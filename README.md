# CryptoPad

**A rich-text editor with integrated triple-layer file encryption.**

Developed on Arch Linux. Requires Qt 6 and Botan 3.

---

## Features

- Rich-text editor with syntax highlighting, fonts, colors, and text alignment.
- **Transparent encryption**: open and save `.cpad` editor documents directly.
- **File encryption / decryption**: encrypt or decrypt any external file via the File menu (`.cpdf` format, fully compatible with [Arsenic](https://github.com/Antidote1911/arsenic)).
- Triple-layer AEAD scheme (AES-256/SIV → Serpent-256/GCM → ChaCha20/Poly1305).

---

## Two encryption modes — two formats

### 1. Editor documents (`.cpad`)

Notes and rich text edited in CryptoPad are saved as `.cpad` files.

- Magic bytes: `CPAD`
- Header: 257 bytes (same layout as CPDF — KEK/DEK, Argon2id salt, encrypted DEK)
- Single block: nonces(52 B) + triple-AEAD ciphertext + HMAC-SHA256(32 B)
- Triple-layer AEAD: AES-256/SIV → Serpent-256/GCM → ChaCha20/Poly1305
- Key derivation: Argon2id → 32-byte KEK → wraps a random 168-byte DEK
- Global HMAC-SHA256 trailer (K4 from DEK)
- Content: Qt rich-text HTML (UTF-8)

**Not compatible with Arsenic**: Arsenic expects the `CPDF` magic and does not
handle HTML content. CryptoPad will refuse to open a `.cpdf` file in the editor
and will redirect you to *File → Decrypt file* instead.

### 2. External file encryption (`.cpdf`)

*File → Encrypt file / Decrypt file* encrypts arbitrary files using the **CPDF**
binary format — byte-for-byte identical to Arsenic.

**A file encrypted by CryptoPad can be decrypted by Arsenic and vice versa.**

See [FORMAT_en.md](FORMAT_en.md) (English) or [FORMAT_fr.md](FORMAT_fr.md) (French)
for the complete binary specification.

---

## CPDF / CPAD cryptographic scheme

Both formats share the same primitives:

| Step | Algorithm | Key | Nonce |
|------|-----------|-----|-------|
| 1 | AES-256/SIV | 512 bits (nonce-misuse-resistant) | 128 bits |
| 2 | Serpent-256/GCM | 256 bits | 96 bits |
| 3 | ChaCha20/Poly1305 | 256 bits | 192 bits |

Each layer adds a 16-byte authentication tag (48 bytes total per block).

### Key derivation

The passphrase produces a 32-byte **Key Encryption Key (KEK)** via Argon2id.
The actual cipher keys (K1, K2, K3, K4) live in a randomly-generated
**Data Encryption Key (DEK)** wrapped by the KEK and stored in the file header.

| Parameter | Value |
|-----------|-------|
| Memory | 64 MiB (65 536 KiB) |
| Iterations | 3 |
| Parallelism | 4 |
| Salt | 16 bytes (random, in header) |
| Output | **32 bytes** (KEK) |

### Difference between `.cpad` and `.cpdf`

| Property | `.cpad` (editor) | `.cpdf` (file encryption) |
|----------|-----------------|--------------------------|
| Magic | `CPAD` | `CPDF` |
| Block structure | Single block | 1 MiB chunks with random padding |
| Content | Qt HTML (UTF-8) | Arbitrary binary |
| Arsenic compatible | **No** | **Yes** |

---

## Building from source

Requires **Qt 6** and **Botan 3**. Botan is detected via pkg-config; if not found,
it is downloaded and compiled automatically.

```bash
cmake -B build
cmake --build build -j$(nproc)
```

---

## Security notes

- The password is converted to a `Botan::secure_vector<char>` immediately and
  zeroed after key derivation. It is never stored as `std::string` or `QString`
  beyond the initial conversion.
- All key material (`kek`, `dek`, key slices) is held in
  `Botan::secure_vector<uint8_t>`, which is zeroed on deallocation by Botan's
  secure allocator.
- Argon2 parameters read from a file header are validated against strict bounds
  (memory ≤ 512 MiB, iterations ≤ 16, parallelism ≤ 16) to prevent DoS via
  malformed files.
- The global HMAC-SHA256 trailer is verified with a constant-time comparison
  before any decrypted data is committed.
- Opening a `.cpdf` file in the editor is blocked by magic detection **before**
  any password is requested. Decrypted `.cpad` content containing null bytes is
  also rejected as a secondary guard against malformed files.

---

## Credits

- [Jack Lloyd / randombit.net](https://botan.randombit.net) — [Botan 3](https://github.com/randombit/botan) C++ cryptographic library (BSD 2-Clause license).
- [KeePassXC project](https://github.com/keepassxreboot/keepassxc) — design inspiration for the password dialog.

---

## License

GNU General Public License version 3. See <https://www.gnu.org/licenses/> for details.
