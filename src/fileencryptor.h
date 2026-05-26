#pragma once
#include <QString>
#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>
#include "botan_all.h"

// Chiffrement/déchiffrement de fichiers arbitraires — format CPDF identique à Arsenic.
//
// Format binaire (257 B header + N chunks + 32 B MAC trailer) :
//   Voir FORMAT_fr.md / FORMAT_en.md pour la spécification complète.
//
// Lève std::runtime_error en cas d'erreur ou "Annulé" si cancelled.
// En cas d'erreur, le fichier de sortie partiel est supprimé.

class FileEncryptor {
public:
    static constexpr size_t CHUNK_SIZE      = 1u << 20; // 1 MiB
    static constexpr size_t OVERHEAD        = 52 + 48;  // nonces(52) + 3 tags(48) = 100
    static constexpr size_t HDR_SZ          = 257;
    static constexpr size_t MAC_TRAILER_LEN = 32;

    static void encryptFile(const QString&                  inputPath,
                             const QString&                  outputPath,
                             const QString&                  password,
                             const std::atomic<bool>&        cancelled,
                             const std::function<void(int)>& progressCb = {});

    static void decryptFile(const QString&                  inputPath,
                             const QString&                  outputPath,
                             const QString&                  password,
                             const std::atomic<bool>&        cancelled,
                             const std::function<void(int)>& progressCb = {});

private:
    // Argon2id parameters (same as Arsenic)
    static constexpr uint32_t ARGON2_MEM  = 65536;
    static constexpr uint32_t ARGON2_ITER = 3;
    static constexpr uint32_t ARGON2_PAR  = 4;

    static constexpr char    MAGIC[4] = {'C','P','D','F'};
    static constexpr uint8_t VERSION  = 1;

    // Key and nonce sizes per AEAD layer
    static constexpr size_t K1 = 64; // AES-256/SIV key  (2 × 256 bits)
    static constexpr size_t K2 = 32; // Serpent/GCM key
    static constexpr size_t K3 = 32; // XChaCha20Poly1305 key
    static constexpr size_t K4 = 32; // HMAC-SHA256 MAC key
    static constexpr size_t N1 = 16; // AES-256/SIV nonce
    static constexpr size_t N2 = 12; // Serpent/GCM nonce
    static constexpr size_t N3 = 24; // XChaCha20Poly1305 nonce

    // DEK: K1+K2+K3+K4 (160 B) + origSize (8 B) = 168 B
    static constexpr size_t DEK_KEYS_LEN = K1+K2+K3+K4;      // 160
    static constexpr size_t DEK_LEN      = DEK_KEYS_LEN + 8;  // 168

    // KEK wrapping (XChaCha20Poly1305)
    static constexpr size_t KEK_LEN       = 32;
    static constexpr size_t DEK_NONCE_LEN = 24;
    static constexpr size_t ENC_DEK_LEN   = DEK_LEN + 16;     // 184

    // Header offsets
    static constexpr size_t HDR_IMMUT_SZ   = 21; // magic(4)+ver(1)+file_id(16)
    static constexpr size_t HDR_KDF_SZ     = 16;
    static constexpr size_t OFF_KDF_SALT   = 21;
    static constexpr size_t OFF_ARGON_MEM  = 37;
    static constexpr size_t OFF_ARGON_ITER = 41;
    static constexpr size_t OFF_ARGON_PAR  = 45;
    static constexpr size_t OFF_DEK_NONCE  = 49;
    static constexpr size_t OFF_ENC_DEK    = 73;

    static Botan::secure_vector<uint8_t> deriveKEK(const char*                 password,
                                                     size_t                      password_len,
                                                     const std::vector<uint8_t>& kdf_salt,
                                                     uint32_t argon_mem,
                                                     uint32_t argon_iter,
                                                     uint32_t argon_par);

    static Botan::secure_vector<uint8_t> wrapDEK(const Botan::secure_vector<uint8_t>& kek,
                                                   const std::vector<uint8_t>&          nonce,
                                                   const Botan::secure_vector<uint8_t>& dek);

    static Botan::secure_vector<uint8_t> unwrapDEK(const Botan::secure_vector<uint8_t>& kek,
                                                     const std::vector<uint8_t>&          nonce,
                                                     const std::vector<uint8_t>&          enc_dek);

    static std::vector<uint8_t> encryptChunk(Botan::secure_vector<uint8_t>        plain,
                                              const Botan::secure_vector<uint8_t>& mat,
                                              const std::vector<uint8_t>&          immutHdr,
                                              uint64_t chunkIdx, uint64_t totalChunks);

    static Botan::secure_vector<uint8_t> decryptChunk(std::vector<uint8_t>                 chunk,
                                                        const Botan::secure_vector<uint8_t>& mat,
                                                        const std::vector<uint8_t>&          immutHdr,
                                                        uint64_t chunkIdx, uint64_t totalChunks);
};
