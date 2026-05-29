# CryptoPad

**A rich-text editor with integrated file encryption powered by [Arsenic](https://github.com/Antidote1911/cryptyrust).**

Developed on Arch Linux. Requires Qt 6. The Rust cryptographic library (Arsenic FFI) is downloaded and compiled automatically by CMake — no manual dependency installation needed.

---

## Features

- Rich-text editor with syntax highlighting, fonts, colors, and text alignment.
- **Transparent encryption**: open and save `.cpad` editor documents directly — fully interoperable with the Arsenic application.
- **File encryption / decryption**: encrypt or decrypt any external file via the File menu — same Arsenic V1 format.
- Modern authenticated encryption: Deoxys-II-256 (header) + XChaCha20-Poly1305 (payload), Argon2id key derivation.

---

## Two encryption modes — one format

Both the text editor and the file encryptor use the **Arsenic V1** binary format (`ARSN` magic).  
A file encrypted by CryptoPad can be decrypted by Arsenic and vice versa.

### 1. Editor documents (`.cpad`)

Notes and rich text are saved as Arsenic-encrypted `.cpad` files.

- Content: Qt rich-text HTML (UTF-8), encrypted with Arsenic V1.
- Fully readable by the Arsenic application (pass the decrypted HTML through any browser).

### 2. External file encryption (`.cpdf` / `.arsenic`)

*File → Encrypt file / Decrypt file* encrypts arbitrary binary files using the same Arsenic V1 format.

---

## Arsenic V1 cryptographic scheme

| Role | Algorithm |
|------|-----------|
| Header cipher (wraps DEK) | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 |
| Key derivation | Argon2id (Interactive: 256 MiB, t=3, p=1) |
| Pre-authentication | Argon2id (tiny: 8 MiB, t=1, p=1) + HMAC-SHA256 |

The passphrase derives a **Key Encryption Key (KEK)** via Argon2id.  
A random **Data Encryption Key (DEK)** is wrapped by the KEK and stored in the file header.  
A pre-authentication MAC is computed before the full KDF to reject wrong passwords quickly (~2 ms) without revealing the full plaintext or running the expensive KDF.

---

## Building from source

**Requirements:** Qt 6, CMake ≥ 3.22, a C++20 compiler, and Rust/cargo.

CMake downloads and compiles the Arsenic FFI Rust library automatically on the first build:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The first build fetches the [`cryptyrust`](https://github.com/Antidote1911/cryptyrust) repository at tag `v1.3.2` and compiles the FFI crate with `cargo build --release`. Subsequent builds skip this step.

### Running tests

```bash
cd build && ctest --output-on-failure
```

---

## Security notes

- The password is zeroed immediately after key derivation — never retained as a `std::string` or `QString`.
- Pre-authentication (lightweight Argon2id + HMAC) rejects wrong passwords in ~2 ms before running the expensive KDF, limiting offline brute-force to ~15 000 attempts/s (GPU).
- Opening a binary-encrypted file (`.cpdf`, `.arsenic`) in the text editor is detected by extension and blocked before any password is requested. Decrypted content containing null bytes is also rejected as a secondary guard.
- All authenticated encryption is verified before any plaintext is written to disk.

---

## Credits

- [Antidote1911](https://github.com/Antidote1911) — [cryptyrust / Arsenic](https://github.com/Antidote1911/cryptyrust) Rust cryptographic library (GPL-3.0).
- [KeePassXC project](https://github.com/keepassxreboot/keepassxc) — design inspiration for the password dialog.

---

## License

GNU General Public License version 3. See <https://www.gnu.org/licenses/> for details.
