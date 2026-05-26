#pragma once
#include <QByteArray>
#include <QString>
#include <botan/secmem.h>
#include <cstdint>
#include <vector>

// Format CPAD (binaire) : header(257 B) + nonces(52 B) + ciphertext + HMAC-SHA256(32 B)
//   Triple AEAD : AES-256/SIV → Serpent-256/GCM → ChaCha20/Poly1305
//   Séparation KEK/DEK, Argon2id, HMAC-SHA256 global — mêmes primitives que CPDF.
//   Seul le magic (CPAD vs CPDF) distingue les deux formats.

class CryptoManager {
public:
    static constexpr uint32_t ARGON2_MEM  = 65536;  // 64 MiB
    static constexpr uint32_t ARGON2_ITER = 3;
    static constexpr uint32_t ARGON2_PAR  = 4;

    // Overhead total = header(257) + nonces(52) + 3×tag(16) + HMAC(32) = 389 octets
    static constexpr int ENCRYPT_OVERHEAD = 389;

    static QByteArray encrypt(const QByteArray& plaintext, const QString& password);
    static QByteArray decrypt(const QByteArray& data, const QString& password);
    static QString algoName();

private:
    static constexpr char    MAGIC[4] = {'C','P','A','D'};
    static constexpr uint8_t VERSION  = 1;

    // Tailles des clés et nonces par couche AEAD
    static constexpr size_t K1 = 64; // AES-256/SIV
    static constexpr size_t K2 = 32; // Serpent/GCM
    static constexpr size_t K3 = 32; // ChaCha20Poly1305
    static constexpr size_t K4 = 32; // HMAC-SHA256
    static constexpr size_t N1 = 16;
    static constexpr size_t N2 = 12;
    static constexpr size_t N3 = 24;

    // DEK : K1+K2+K3+K4 (160 B) + origSize (8 B) = 168 B
    static constexpr size_t KEK_LEN      = 32;
    static constexpr size_t DEK_KEYS_LEN = K1+K2+K3+K4;      // 160
    static constexpr size_t DEK_LEN      = DEK_KEYS_LEN + 8;  // 168

    // KEK wrapping (ChaCha20Poly1305, nonce 24 B)
    static constexpr size_t DEK_NONCE_LEN = 24;
    static constexpr size_t ENC_DEK_LEN   = DEK_LEN + 16;     // 184

    // Header : immutable(21) + mutable(236) = 257 B
    static constexpr size_t HDR_IMMUT_SZ = 21;  // magic(4)+ver(1)+file_id(16)
    static constexpr size_t HDR_KDF_SZ   = 16;
    static constexpr size_t HDR_SZ       = 257;

    // Offsets dans le header complet
    static constexpr size_t OFF_KDF_SALT   = 21;
    static constexpr size_t OFF_ARGON_MEM  = 37;
    static constexpr size_t OFF_ARGON_ITER = 41;
    static constexpr size_t OFF_ARGON_PAR  = 45;
    static constexpr size_t OFF_DEK_NONCE  = 49;
    static constexpr size_t OFF_ENC_DEK    = 73;

    static constexpr size_t NONCES_SZ = N1 + N2 + N3;  // 52
    static constexpr size_t MAC_LEN   = 32;
    static constexpr size_t TAG_BYTES = 16;

    static Botan::secure_vector<uint8_t> deriveKEK(const char*                 password,
                                                     size_t                      password_len,
                                                     const std::vector<uint8_t>& kdf_salt,
                                                     uint32_t argon_mem,
                                                     uint32_t argon_iter,
                                                     uint32_t argon_par);
};
