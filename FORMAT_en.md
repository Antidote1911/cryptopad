# CryptoPad Encrypted File Formats: CPDF and CPAD

This document describes both binary formats produced by CryptoPad.

| Format | Extension | Arsenic-compatible | Use |
|--------|-----------|--------------------|-----|
| **CPDF** | `.cpdf` | **Yes** — byte-for-byte identical | Arbitrary file encryption |
| **CPAD** | `.cpad` | **No** — different magic, HTML content | Editor documents |

Both formats share the same cryptographic primitives (KEK/DEK, triple AEAD,
Argon2id, HMAC-SHA256) but differ in magic bytes, block structure, and content.

---

## Part I — CPDF format (file encryption)

The conventional file extension is `.cpdf`.
This format is **identical to Arsenic's** — files encrypted by one application
can be decrypted by the other.

### Format version

| Version | Header bytes | Description                                                |
|---------|--------------|------------------------------------------------------------|
| `0x01`  | 257          | KEK/DEK, random per-chunk nonces, encrypted origSize, CHUNK_SIZE padding, global HMAC-SHA256 MAC |

---

### Overview

```
┌─────────────────────────────────────────────────────────────┐
│  HEADER  (257 bytes, fixed)                                 │
├─────────────────────────────────────────────────────────────┤
│  CHUNK 0  (CHUNK_SIZE + 100 bytes)                          │
├─────────────────────────────────────────────────────────────┤
│  CHUNK 1  (CHUNK_SIZE + 100 bytes)                          │
├─────────────────────────────────────────────────────────────┤
│  …                                                          │
├─────────────────────────────────────────────────────────────┤
│  CHUNK N-1  (CHUNK_SIZE + 100 bytes)                        │
├─────────────────────────────────────────────────────────────┤
│  MAC TRAILER  (32 bytes)                                    │
└─────────────────────────────────────────────────────────────┘
```

**Every** encrypted chunk is exactly `CHUNK_SIZE + 100` bytes. The last chunk is
padded with random bytes to reach `CHUNK_SIZE` before encryption. `origSize` is
stored encrypted in the DEK so the receiver can strip the padding; it is never
in the plaintext header.

The disk file size reveals only `⌈origSize / 1 MiB⌉` (the chunk count), not the
exact original size.

Total encrypted file size:

```
257 + ⌈original_size / 1 048 576⌉ × 1 048 676 + 32  bytes
```

(where `1 048 676 = CHUNK_SIZE + OVERHEAD = 1 048 576 + 100`)

---

### Header (257 bytes)

#### Immutable part (21 bytes — used in per-chunk associated data)

| Offset | Length | Content                                                        |
|--------|--------|----------------------------------------------------------------|
| 0      | 4      | ASCII magic: `43 50 44 46` (`CPDF`)                           |
| 4      | 1      | Format version: `0x01`                                        |
| 5      | 16     | **File ID** (random, CSPRNG, never changes)                   |

`origSize` is **not** stored here. It lives inside the encrypted DEK so it cannot
be read without the password.

#### Mutable part (236 bytes — rewritten on password change)

| Offset | Length | Content                                                       |
|--------|--------|---------------------------------------------------------------|
| 21     | 16     | KDF salt (random, CSPRNG)                                     |
| 37     | 4      | `argon_mem`  : Argon2id memory cost (uint32 LE, KiB)          |
| 41     | 4      | `argon_iter` : Argon2id iteration count (uint32 LE)           |
| 45     | 4      | `argon_par`  : Argon2id parallelism (uint32 LE)               |
| 49     | 24     | DEK wrapping nonce (random, CSPRNG)                           |
| 73     | 184    | Encrypted DEK = XChaCha20Poly1305(KEK, nonce, DEK) + 16-byte tag |

---

### KEK / DEK separation

#### Principle

```
Password + KDF salt  →  Argon2id  →  KEK (32 bytes)
                                           │
                                           ▼
Random DEK (168 B)  →  XChaCha20Poly1305(KEK)  →  Encrypted DEK (header)
               │
               ├──→ K1, K2, K3 : per-layer AEAD keys
               ├──→ K4 : HMAC-SHA256 MAC key  (global file authentication)
               └──→ origSize (8 bytes)  ←── encrypted, not visible without password
```

#### Benefits

- **Password change**: re-derive KEK, re-encrypt only the 184-byte DEK in the header.
  The rest of the file (even 50 GB) is untouched.

- **Size privacy**: exact `origSize` is invisible without the password. The disk size
  reveals only the 1 MiB range `[(N−1)×1MiB+1, N×1MiB]`.

#### Argon2id parameters (read from file, never hard-coded)

| Parameter    | Default value        | Source at decryption time          |
|--------------|----------------------|------------------------------------|
| Memory       | 65 536 KiB (64 MiB)  | `argon_mem` field (offset 37)     |
| Iterations   | 3                    | `argon_iter` field (offset 41)    |
| Parallelism  | 4                    | `argon_par` field (offset 45)     |
| Input        | UTF-8 password       | —                                  |
| Salt         | 16 bytes (offset 21) | —                                  |
| Output       | **32 bytes** (KEK)   | —                                  |

#### DEK layout (168 bytes)

```
Offset  Length  Purpose
──────  ──────  ─────────────────────────────────────────────────────────
 0       64      K1 : AES-256/SIV key  (2 × 256 bits)
64       32      K2 : Serpent-256/GCM key
96       32      K3 : XChaCha20Poly1305 key
128      32      K4 : HMAC-SHA256 MAC key  (global file authentication)
160       8      origSize : original file size (uint64 LE) — encrypted here
─────────────────────────────────────────────────────────────────────────
Total : 168 bytes
```

Nonces are **not** stored in the DEK. Each chunk generates three independent
random nonces (16 + 12 + 24 = 52 bytes) stored as a plaintext prefix to that chunk.

---

### Chunk splitting and padding

- Chunk count: `N = ⌈original_size / 1 048 576⌉` (0 if `original_size == 0`)
- Every chunk — including the last — is padded to exactly **1 048 576 bytes**
  before encryption (random padding bytes appended to real content).
- Each encrypted chunk: `52 (nonces) + 1 048 576 (padded plain) + 48 (tags) = 1 048 676 bytes`
- On decryption, `origSize` from the DEK tells the receiver how many bytes of the
  last chunk are real data vs. padding.

---

### Per-chunk nonce

Each chunk stores three independently random nonces as a plaintext prefix:

```
┌──────────────────────────────────────────────────┐
│  N1 : AES-256/SIV nonce        (16 bytes)        │
│  N2 : Serpent-256/GCM nonce    (12 bytes)        │
│  N3 : XChaCha20Poly1305 nonce  (24 bytes)        │
└──────────────────────────────────────────────────┘
     Total: 52 bytes per chunk
```

---

### Per-chunk associated data (AD)

Each AEAD layer receives the same **37 bytes** of associated data:

```
┌──────────────────────────────────────────────────────┐
│  Immutable header part  (21 bytes)                   │
│  Chunk index  (uint64, little-endian, 8 bytes)       │
│  Total chunk count  (uint64, LE, 8 bytes)            │
└──────────────────────────────────────────────────────┘
```

---

### Chunk encryption (application order)

```
Padded plaintext (1 048 576 bytes)
  │
  ▼  1. AES-256/SIV       key K1 (64 B)  nonce N1 (random)  AD 37 B  tag +16
  │
  ▼  2. Serpent-256/GCM   key K2 (32 B)  nonce N2 (random)  AD 37 B  tag +16
  │
  ▼  3. XChaCha20Poly1305 key K3 (32 B)  nonce N3 (random)  AD 37 B  tag +16
  │
Output chunk: N1(16) | N2(12) | N3(24) | ciphertext(1 048 576 + 48 tags)
```

---

### Chunk decryption (reverse order)

```
Input chunk (1 048 676 bytes): N1(16) | N2(12) | N3(24) | ciphertext(1 048 624)
  →  XChaCha20Poly1305  →  Serpent/GCM  →  AES-256/SIV  →  1 048 576 bytes
```

Last chunk: write only `origSize mod 1 048 576` bytes (strip padding).
If `origSize` is a multiple of 1 MiB: write full 1 048 576 bytes (no padding was added).

If any tag fails verification, decryption stops immediately and the partial
output file is deleted.

---

### Global MAC trailer

```
HMAC-SHA256( K4,  header(257 B) || chunk0 || chunk1 || … || chunkN-1 )
```

- Computed during encryption by streaming all written bytes.
- Verified during decryption after all chunks.
  On failure the output file is deleted.

---

### Parallelism

Chunks are processed in **batches** of `N` threads (`QThread::idealThreadCount()`).
Sequential read → parallel encrypt/decrypt → sequential write.
The global MAC is updated sequentially (in file order) on the read data.

---

### File size examples

| Original size        | Chunks | Encrypted size                                     |
|----------------------|--------|----------------------------------------------------|
| 0 B                  | 0      | 257 + 32 = **289 B**                              |
| 1 B                  | 1      | 257 + 1 048 676 + 32 = **1 048 965 B** (~1 MiB)  |
| 1 048 576 B (1 MiB)  | 1      | 257 + 1 048 676 + 32 = **1 048 965 B**            |
| 1 048 577 B          | 2      | 257 + 2 × 1 048 676 + 32 = **2 097 641 B**       |
| 10 485 760 B (10 MiB)| 10     | 257 + 10 × 1 048 676 + 32 = **10 487 049 B**     |

---

## Part II — CPAD format (editor documents)

The conventional file extension is `.cpad`. This format is **specific to CryptoPad**
and is **not** readable by Arsenic (different magic, HTML content).

### Overall structure

```
┌─────────────────────────────────────────────────────────────┐
│  HEADER  (257 bytes) — same layout as a CPDF header        │
├─────────────────────────────────────────────────────────────┤
│  SINGLE BLOCK: nonces(52 B) + ciphertext + 3 tags(48 B)    │
├─────────────────────────────────────────────────────────────┤
│  MAC TRAILER  (32 bytes)                                    │
└─────────────────────────────────────────────────────────────┘
```

Total size = 257 + 52 + html_size + 48 + 32 = **html_size + 389 bytes**.

No chunking, no padding. The HTML document is encrypted as a single block.

### Header (257 bytes)

Same layout as CPDF (see Part I) with two differences:

| Field | CPDF | CPAD |
|-------|------|------|
| Magic (offset 0, 4 B) | `43 50 44 46` (`CPDF`) | `43 50 41 44` (`CPAD`) |
| Version (offset 4, 1 B) | `0x01` | `0x01` |
| `origSize` in DEK | original binary file size | HTML UTF-8 byte length |

### Single block

```
N1 (16 B) | N2 (12 B) | N3 (24 B) | ciphertext | tag×3 (48 B)
```

Nonces are random (CSPRNG) on every encryption.

### Associated data (AD)

```
immutHdr(21 B) | chunkIdx=0 (uint64 LE) | total=1 (uint64 LE)  →  37 bytes
```

Same formula as CPDF, with `chunkIdx = 0` and `total = 1`.

### Global HMAC-SHA256

```
HMAC-SHA256( K4,  header(257 B) || N1 || N2 || N3 || ciphertext )
```

Verified in constant time before AEAD decryption.

### Decrypted content

The plaintext is Qt rich-text HTML encoded as UTF-8
(`QTextEdit::toHtml().toUtf8()`). CryptoPad refuses to open any file whose
decrypted content contains null bytes (binary content guard).
