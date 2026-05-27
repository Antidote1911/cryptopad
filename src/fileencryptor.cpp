#include "fileencryptor.h"

#include "botan_all.h"

#include <QFile>
#include <QThread>

#include <concepts>
#include <cstring>
#include <future>
#include <span>
#include <stdexcept>

// ── helpers LE ────────────────────────────────────────────────────────────────

template<std::integral T>
static void pushLE(std::vector<uint8_t>& v, T val) {
    for (size_t b = 0; b < sizeof(T); ++b)
        v.push_back(static_cast<uint8_t>(val >> (8 * b)));
}

template<std::unsigned_integral T>
[[nodiscard]] static T loadLE(const uint8_t* p) noexcept {
    T val{};
    for (size_t b = 0; b < sizeof(T); ++b)
        val |= static_cast<T>(p[b]) << (8 * b);
    return val;
}

template<std::integral T>
static void storeLE(std::span<uint8_t> dst, T val) {
    for (size_t b = 0; b < sizeof(T); ++b)
        dst[b] = static_cast<uint8_t>(val >> (8 * b));
}

// ── KDF ───────────────────────────────────────────────────────────────────────

Botan::secure_vector<uint8_t> FileEncryptor::deriveKEK(const char*              password,
                                                         size_t                   password_len,
                                                         std::span<const uint8_t> kdf_salt,
                                                         uint32_t argon_mem,
                                                         uint32_t argon_iter,
                                                         uint32_t argon_par)
{
    auto fam     = Botan::PasswordHashFamily::create_or_throw("Argon2id");
    auto pwdhash = fam->from_params(argon_mem, argon_iter, argon_par);
    Botan::secure_vector<uint8_t> kek(KEK_LEN);
    pwdhash->derive_key(kek.data(), kek.size(),
                        password, password_len,
                        kdf_salt.data(), kdf_salt.size());
    return kek;
}

Botan::secure_vector<uint8_t> FileEncryptor::wrapDEK(const Botan::secure_vector<uint8_t>& kek,
                                                       std::span<const uint8_t>             nonce,
                                                       const Botan::secure_vector<uint8_t>& dek)
{
    auto aead = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
    aead->set_key(kek);
    aead->start(nonce);
    Botan::secure_vector<uint8_t> enc(dek.begin(), dek.end());
    aead->finish(enc);
    return enc;
}

Botan::secure_vector<uint8_t> FileEncryptor::unwrapDEK(const Botan::secure_vector<uint8_t>& kek,
                                                         std::span<const uint8_t>             nonce,
                                                         std::span<const uint8_t>             enc_dek)
{
    auto aead = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Decryption);
    aead->set_key(kek);
    aead->start(nonce);
    Botan::secure_vector<uint8_t> dec(enc_dek.begin(), enc_dek.end());
    aead->finish(dec);
    return dec;
}

// ── Helpers AD ────────────────────────────────────────────────────────────────

[[nodiscard]] static std::vector<uint8_t> buildChunkAD(std::span<const uint8_t> hdr,
                                                         uint64_t chunkIdx, uint64_t total)
{
    std::vector<uint8_t> ad;
    ad.reserve(hdr.size() + 16);
    ad.assign(hdr.begin(), hdr.end());
    pushLE(ad, chunkIdx);
    pushLE(ad, total);
    return ad;
}

// ── Helpers AEAD ─────────────────────────────────────────────────────────────

[[nodiscard]] static Botan::secure_vector<uint8_t> aeadEncrypt(
    std::string_view                     name,
    const Botan::secure_vector<uint8_t>& key,
    std::span<const uint8_t>             nonce,
    std::span<const uint8_t>             ad,
    Botan::secure_vector<uint8_t>        data)
{
    auto aead = Botan::AEAD_Mode::create_or_throw(name, Botan::Cipher_Dir::Encryption);
    aead->set_key(key);
    aead->set_associated_data(ad);
    aead->start(nonce);
    aead->finish(data);
    return data;
}

[[nodiscard]] static Botan::secure_vector<uint8_t> aeadDecrypt(
    std::string_view                     name,
    const Botan::secure_vector<uint8_t>& key,
    std::span<const uint8_t>             nonce,
    std::span<const uint8_t>             ad,
    Botan::secure_vector<uint8_t>        data)
{
    auto aead = Botan::AEAD_Mode::create_or_throw(name, Botan::Cipher_Dir::Decryption);
    aead->set_key(key);
    aead->set_associated_data(ad);
    aead->start(nonce);
    aead->finish(data);
    return data;
}

// ── Chunk encryption : nonces aléatoires par chunk ───────────────────────────
// Sortie : N1(16) | N2(12) | N3(24) | ciphertext(CHUNK_SIZE + 48 tags)

std::vector<uint8_t> FileEncryptor::encryptChunk(Botan::secure_vector<uint8_t>        plain,
                                                   const Botan::secure_vector<uint8_t>& mat,
                                                   std::span<const uint8_t>             immutHdr,
                                                   uint64_t ci, uint64_t total)
{
    size_t off = 0;
    auto slice = [&](size_t n) {
        Botan::secure_vector<uint8_t> v(mat.begin()+off, mat.begin()+off+n); off += n; return v;
    };
    const auto k1 = slice(K1);
    const auto k2 = slice(K2);
    const auto k3 = slice(K3);

    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> n1(N1), n2(N2), n3(N3);
    rng.randomize(n1.data(), N1);
    rng.randomize(n2.data(), N2);
    rng.randomize(n3.data(), N3);

    const auto ad = buildChunkAD(immutHdr, ci, total);

    plain = aeadEncrypt("AES-256/SIV",      k1, n1, ad, std::move(plain));
    plain = aeadEncrypt("Serpent/GCM",      k2, n2, ad, std::move(plain));
    plain = aeadEncrypt("ChaCha20Poly1305", k3, n3, ad, std::move(plain));

    std::vector<uint8_t> result;
    result.reserve(OVERHEAD + plain.size());
    result.insert(result.end(), n1.begin(), n1.end());
    result.insert(result.end(), n2.begin(), n2.end());
    result.insert(result.end(), n3.begin(), n3.end());
    result.insert(result.end(), plain.begin(), plain.end());
    return result;
}

// ── Chunk decryption : nonces lus depuis le préfixe du bloc ──────────────────
// Entrée : N1(16) | N2(12) | N3(24) | ciphertext

Botan::secure_vector<uint8_t> FileEncryptor::decryptChunk(std::vector<uint8_t>                 chunk,
                                                            const Botan::secure_vector<uint8_t>& mat,
                                                            std::span<const uint8_t>             immutHdr,
                                                            uint64_t ci, uint64_t total)
{
    size_t pos = 0;
    const std::span<const uint8_t> n1(chunk.data()+pos, N1); pos += N1;
    const std::span<const uint8_t> n2(chunk.data()+pos, N2); pos += N2;
    const std::span<const uint8_t> n3(chunk.data()+pos, N3); pos += N3;
    Botan::secure_vector<uint8_t> cipher(chunk.begin()+pos, chunk.end());

    size_t off = 0;
    auto slice = [&](size_t n) {
        Botan::secure_vector<uint8_t> v(mat.begin()+off, mat.begin()+off+n); off += n; return v;
    };
    const auto k1 = slice(K1);
    const auto k2 = slice(K2);
    const auto k3 = slice(K3);

    const auto ad = buildChunkAD(immutHdr, ci, total);

    cipher = aeadDecrypt("ChaCha20Poly1305", k3, n3, ad, std::move(cipher));
    cipher = aeadDecrypt("Serpent/GCM",      k2, n2, ad, std::move(cipher));
    cipher = aeadDecrypt("AES-256/SIV",      k1, n1, ad, std::move(cipher));
    return cipher;
}

// ── writeAll ─────────────────────────────────────────────────────────────────

static void writeAll(QFile& f, const void* data, qint64 n)
{
    if (f.write(static_cast<const char*>(data), n) != n)
        throw std::runtime_error("Erreur d'écriture sur le disque.");
}

// ── encryptFile ───────────────────────────────────────────────────────────────

void FileEncryptor::encryptFile(const QString&                  inputPath,
                                 const QString&                  outputPath,
                                 const QString&                  password,
                                 const std::atomic<bool>&        cancelled,
                                 const std::function<void(int)>& progressCb)
{
    QFile fin(inputPath);
    if (!fin.open(QIODevice::ReadOnly))
        throw std::runtime_error("Impossible d'ouvrir : " + fin.errorString().toStdString());

    const uint64_t origSize    = static_cast<uint64_t>(fin.size());
    const uint64_t totalChunks = (origSize + CHUNK_SIZE - 1) / CHUNK_SIZE;

    Botan::AutoSeeded_RNG rng;

    // file_id : lie les chunks à ce fichier ; ne change pas si le mot de passe change
    std::vector<uint8_t> file_id(16);
    rng.randomize(file_id.data(), file_id.size());

    std::vector<uint8_t> kdf_salt(HDR_KDF_SZ);
    rng.randomize(kdf_salt.data(), kdf_salt.size());

    std::vector<uint8_t> dek_nonce(DEK_NONCE_LEN);
    rng.randomize(dek_nonce.data(), dek_nonce.size());

    // DEK (168 B) : K1+K2+K3+K4 aléatoires + origSize chiffré
    Botan::secure_vector<uint8_t> dek(DEK_LEN);
    rng.randomize(dek.data(), DEK_KEYS_LEN);
    storeLE(std::span<uint8_t>(dek.data() + DEK_KEYS_LEN, sizeof(uint64_t)), origSize);

    const Botan::secure_vector<uint8_t> k4_mac(dek.begin() + K1+K2+K3,
                                                  dek.begin() + K1+K2+K3+K4);

    const QByteArray _pwUtf8 = password.toUtf8();
    Botan::secure_vector<char> _pwd(_pwUtf8.constData(), _pwUtf8.constData() + _pwUtf8.size());
    const auto kek     = deriveKEK(_pwd.data(), _pwd.size(), kdf_salt, ARGON2_MEM, ARGON2_ITER, ARGON2_PAR);
    _pwd = Botan::secure_vector<char>(); // zéroïsé immédiatement après la dérivation
    const auto enc_dek = wrapDEK(kek, dek_nonce, dek);

    // En-tête immutable (21 B) — AD de chaque chunk
    std::vector<uint8_t> immutHdr;
    immutHdr.reserve(HDR_IMMUT_SZ);
    immutHdr.insert(immutHdr.end(), MAGIC.begin(), MAGIC.end());
    immutHdr.push_back(VERSION);
    immutHdr.insert(immutHdr.end(), file_id.begin(), file_id.end());

    // En-tête complet (257 B) = immutable + mutable
    std::vector<uint8_t> fullHdr = immutHdr;
    fullHdr.reserve(HDR_SZ);
    fullHdr.insert(fullHdr.end(), kdf_salt.begin(), kdf_salt.end());
    pushLE(fullHdr, ARGON2_MEM);
    pushLE(fullHdr, ARGON2_ITER);
    pushLE(fullHdr, ARGON2_PAR);
    fullHdr.insert(fullHdr.end(), dek_nonce.begin(), dek_nonce.end());
    fullHdr.insert(fullHdr.end(), enc_dek.begin(), enc_dek.end());

    QFile fout(outputPath);
    if (!fout.open(QIODevice::WriteOnly))
        throw std::runtime_error("Impossible de créer : " + fout.errorString().toStdString());

    struct Guard {
        QFile& f; const QString& path; bool ok{false};
        ~Guard() { f.close(); if (!ok) QFile::remove(path); }
    } guard{.f = fout, .path = outputPath};

    writeAll(fout, fullHdr.data(), static_cast<qint64>(fullHdr.size()));

    // MAC global : HMAC-SHA256(K4, header || chunks chiffrés)
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    mac->set_key(k4_mac);
    mac->update(fullHdr.data(), fullHdr.size());

    const int nThreads = std::max(1, QThread::idealThreadCount());

    for (uint64_t done = 0; done < totalChunks; ) {
        if (cancelled.load()) throw std::runtime_error("Annulé");

        const uint64_t batchEnd  = std::min<uint64_t>(done + nThreads, totalChunks);
        const int      batchSize = static_cast<int>(batchEnd - done);

        std::vector<Botan::secure_vector<uint8_t>> plains(batchSize);
        for (int i = 0; i < batchSize; ++i) {
            const uint64_t ci     = done + static_cast<uint64_t>(i);
            const uint64_t realSz = std::min<uint64_t>(CHUNK_SIZE, origSize - ci * CHUNK_SIZE);
            plains[i].resize(CHUNK_SIZE);
            if (fin.read(reinterpret_cast<char*>(plains[i].data()),
                          static_cast<qint64>(realSz)) != static_cast<qint64>(realSz))
                throw std::runtime_error("Erreur de lecture.");
            if (realSz < CHUNK_SIZE) // padding aléatoire du dernier chunk
                rng.randomize(plains[i].data() + realSz, CHUNK_SIZE - realSz);
        }

        std::vector<std::future<std::vector<uint8_t>>> futures;
        futures.reserve(batchSize);
        for (int i = 0; i < batchSize; ++i) {
            const uint64_t ci = done + i;
            futures.push_back(std::async(std::launch::async,
                [plain = std::move(plains[i]), &dek, &immutHdr, ci, totalChunks]() {
                    return encryptChunk(std::move(plain), dek, immutHdr, ci, totalChunks);
                }));
        }

        for (int i = 0; i < batchSize; ++i) {
            const auto enc = futures[i].get();
            mac->update(enc.data(), enc.size());
            writeAll(fout, enc.data(), static_cast<qint64>(enc.size()));
        }

        done += batchSize;
        if (progressCb) progressCb(static_cast<int>(done * 100 / totalChunks));
    }

    const auto macTag = mac->final();
    writeAll(fout, macTag.data(), static_cast<qint64>(macTag.size()));

    guard.ok = true;
    if (progressCb) progressCb(100);
}

// ── decryptFile ───────────────────────────────────────────────────────────────

void FileEncryptor::decryptFile(const QString&                  inputPath,
                                 const QString&                  outputPath,
                                 const QString&                  password,
                                 const std::atomic<bool>&        cancelled,
                                 const std::function<void(int)>& progressCb)
{
    QFile fin(inputPath);
    if (!fin.open(QIODevice::ReadOnly))
        throw std::runtime_error("Impossible d'ouvrir : " + fin.errorString().toStdString());

    // Lecture et validation du header
    std::vector<uint8_t> fullHdr(HDR_SZ);
    if (fin.read(reinterpret_cast<char*>(fullHdr.data()),
                  static_cast<qint64>(HDR_SZ)) != static_cast<qint64>(HDR_SZ))
        throw std::runtime_error("Fichier trop court ou corrompu.");
    if (std::memcmp(fullHdr.data(), MAGIC.data(), MAGIC.size()) != 0)
        throw std::runtime_error("Format non reconnu — ce fichier n'est pas un fichier CryptoPad chiffré.");
    if (fullHdr[4] != VERSION)
        throw std::runtime_error("Version de format non supportée.");

    // Lire les paramètres Argon2 stockés dans le fichier
    const auto argon_mem  = loadLE<uint32_t>(fullHdr.data() + OFF_ARGON_MEM);
    const auto argon_iter = loadLE<uint32_t>(fullHdr.data() + OFF_ARGON_ITER);
    const auto argon_par  = loadLE<uint32_t>(fullHdr.data() + OFF_ARGON_PAR);

    // Validation : bornes serrées pour éviter un DoS par fichier malveillant.
    // Max mem = 512 MiB (8× la valeur produite), iter/par = 16 — identique à Arsenic.
    if (argon_mem < 8    || argon_mem > 524288 ||
        argon_iter < 1   || argon_iter > 16    ||
        argon_par  < 1   || argon_par  > 16)
        throw std::runtime_error("Paramètres Argon2 invalides dans le fichier.");

    const std::span<const uint8_t> immutHdr(fullHdr.data(), HDR_IMMUT_SZ);
    const std::span<const uint8_t> kdf_salt(fullHdr.data() + OFF_KDF_SALT,  HDR_KDF_SZ);
    const std::span<const uint8_t> dek_nonce(fullHdr.data() + OFF_DEK_NONCE, DEK_NONCE_LEN);
    const std::span<const uint8_t> enc_dek(fullHdr.data() + OFF_ENC_DEK,   ENC_DEK_LEN);

    const QByteArray _pwUtf8 = password.toUtf8();
    Botan::secure_vector<char> _pwd(_pwUtf8.constData(), _pwUtf8.constData() + _pwUtf8.size());
    const auto kek = deriveKEK(_pwd.data(), _pwd.size(), kdf_salt, argon_mem, argon_iter, argon_par);
    _pwd = Botan::secure_vector<char>(); // zéroïsé immédiatement après la dérivation

    Botan::secure_vector<uint8_t> dek;
    try {
        dek = unwrapDEK(kek, dek_nonce, enc_dek);
    } catch (const std::exception&) {
        throw std::runtime_error("Mot de passe incorrect ou données corrompues.");
    }

    // Extraire origSize depuis la DEK (offset DEK_KEYS_LEN = 160)
    const auto origSize    = loadLE<uint64_t>(dek.data() + DEK_KEYS_LEN);
    const uint64_t totalChunks = (origSize + CHUNK_SIZE - 1) / CHUNK_SIZE;

    const Botan::secure_vector<uint8_t> k4_mac(dek.begin() + K1+K2+K3,
                                                  dek.begin() + K1+K2+K3+K4);
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    mac->set_key(k4_mac);
    mac->update(fullHdr.data(), fullHdr.size());

    QFile fout(outputPath);
    if (!fout.open(QIODevice::WriteOnly))
        throw std::runtime_error("Impossible de créer : " + fout.errorString().toStdString());

    struct Guard {
        QFile& f; const QString& path; bool ok{false};
        ~Guard() { f.close(); if (!ok) QFile::remove(path); }
    } guard{.f = fout, .path = outputPath};

    const int nThreads = std::max(1, QThread::idealThreadCount());

    for (uint64_t done = 0; done < totalChunks; ) {
        if (cancelled.load()) throw std::runtime_error("Annulé");

        const uint64_t batchEnd  = std::min<uint64_t>(done + nThreads, totalChunks);
        const int      batchSize = static_cast<int>(batchEnd - done);

        // Tous les chunks font CHUNK_SIZE + OVERHEAD (dernier paddé à CHUNK_SIZE)
        std::vector<std::vector<uint8_t>> ciphers(batchSize);
        for (int i = 0; i < batchSize; ++i) {
            ciphers[i].resize(CHUNK_SIZE + OVERHEAD);
            if (fin.read(reinterpret_cast<char*>(ciphers[i].data()),
                          static_cast<qint64>(CHUNK_SIZE + OVERHEAD)) != static_cast<qint64>(CHUNK_SIZE + OVERHEAD))
                throw std::runtime_error("Fichier tronqué ou corrompu.");
            mac->update(ciphers[i].data(), ciphers[i].size());
        }

        std::vector<std::future<Botan::secure_vector<uint8_t>>> futures;
        futures.reserve(batchSize);
        for (int i = 0; i < batchSize; ++i) {
            const uint64_t ci = done + static_cast<uint64_t>(i);
            futures.push_back(std::async(std::launch::async,
                [cipher = std::move(ciphers[i]), &dek, &immutHdr, ci, totalChunks]() {
                    return decryptChunk(std::move(cipher), dek, immutHdr, ci, totalChunks);
                }));
        }

        for (int i = 0; i < batchSize; ++i) {
            Botan::secure_vector<uint8_t> plain;
            try {
                plain = futures[i].get();
            } catch (const std::exception&) {
                throw std::runtime_error("Mot de passe incorrect ou données corrompues.");
            }
            const uint64_t ci_abs    = done + static_cast<uint64_t>(i);
            const uint64_t writeSize = (ci_abs == totalChunks - 1)
                ? (origSize - ci_abs * CHUNK_SIZE)
                : static_cast<uint64_t>(plain.size());
            writeAll(fout, plain.data(), static_cast<qint64>(writeSize));
        }

        done += batchSize;
        if (progressCb) progressCb(static_cast<int>(done * 100 / totalChunks));
    }

    // Vérifier le trailer MAC — détecte troncature, ajout d'octets, toute altération globale
    std::vector<uint8_t> storedMac(MAC_TRAILER_LEN);
    if (fin.read(reinterpret_cast<char*>(storedMac.data()),
                  static_cast<qint64>(MAC_TRAILER_LEN)) != static_cast<qint64>(MAC_TRAILER_LEN))
        throw std::runtime_error("MAC global manquant — fichier tronqué ou corrompu.");
    const auto computedMac = mac->final();
    if (!Botan::constant_time_compare(computedMac.data(), storedMac.data(), MAC_TRAILER_LEN))
        throw std::runtime_error("Vérification MAC globale échouée — fichier corrompu ou altéré.");

    guard.ok = true;
    if (progressCb) progressCb(100);
}
