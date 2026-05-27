#include "cryptomanager.h"

#include "botan_all.h"

#include <concepts>
#include <cstring>
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

// ── helpers statiques ─────────────────────────────────────────────────────────

[[nodiscard]] static std::vector<uint8_t> buildAD(std::span<const uint8_t> immutHdr,
                                                   uint64_t chunkIdx, uint64_t total)
{
    std::vector<uint8_t> ad;
    ad.reserve(immutHdr.size() + 16);
    ad.assign(immutHdr.begin(), immutHdr.end());
    pushLE(ad, chunkIdx);
    pushLE(ad, total);
    return ad;
}

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

// ── API publique ──────────────────────────────────────────────────────────────

QString CryptoManager::algoName()
{
    return "Triple (AES-256/SIV · Serpent-256/GCM · ChaCha20/Poly1305) + KEK/DEK + HMAC-SHA256";
}

// ── KDF ───────────────────────────────────────────────────────────────────────

Botan::secure_vector<uint8_t> CryptoManager::deriveKEK(const char*              password,
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

// ── encrypt ───────────────────────────────────────────────────────────────────

QByteArray CryptoManager::encrypt(const QByteArray& plaintext, const QString& password)
{
    Botan::AutoSeeded_RNG rng;

    std::vector<uint8_t> file_id(16);
    rng.randomize(file_id.data(), file_id.size());

    std::vector<uint8_t> kdf_salt(HDR_KDF_SZ);
    rng.randomize(kdf_salt.data(), HDR_KDF_SZ);

    std::vector<uint8_t> dek_nonce(DEK_NONCE_LEN);
    rng.randomize(dek_nonce.data(), DEK_NONCE_LEN);

    // DEK : clés aléatoires + origSize encodé en LE sur 8 octets
    Botan::secure_vector<uint8_t> dek(DEK_LEN);
    rng.randomize(dek.data(), DEK_KEYS_LEN);
    const uint64_t origSize = static_cast<uint64_t>(plaintext.size());
    storeLE(std::span<uint8_t>(dek.data() + DEK_KEYS_LEN, sizeof(uint64_t)), origSize);

    const Botan::secure_vector<uint8_t> k4_mac(dek.begin() + K1+K2+K3,
                                                 dek.begin() + K1+K2+K3+K4);

    const QByteArray pwUtf8 = password.toUtf8();
    Botan::secure_vector<char> pwd(pwUtf8.constData(), pwUtf8.constData() + pwUtf8.size());
    const auto kek = deriveKEK(pwd.data(), pwd.size(), kdf_salt, ARGON2_MEM, ARGON2_ITER, ARGON2_PAR);
    pwd = Botan::secure_vector<char>();

    // Enveloppe la DEK avec ChaCha20Poly1305(KEK)
    auto aead_wrap = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
    aead_wrap->set_key(kek);
    aead_wrap->start(std::span{dek_nonce});
    Botan::secure_vector<uint8_t> enc_dek(dek.begin(), dek.end());
    aead_wrap->finish(enc_dek);

    // En-tête immutable (21 B) — AD des trois couches AEAD
    std::vector<uint8_t> immutHdr;
    immutHdr.reserve(HDR_IMMUT_SZ);
    immutHdr.insert(immutHdr.end(), MAGIC.begin(), MAGIC.end());
    immutHdr.push_back(VERSION);
    immutHdr.insert(immutHdr.end(), file_id.begin(), file_id.end());

    // En-tête complet (257 B)
    std::vector<uint8_t> fullHdr = immutHdr;
    fullHdr.reserve(HDR_SZ);
    fullHdr.insert(fullHdr.end(), kdf_salt.begin(), kdf_salt.end());
    pushLE(fullHdr, ARGON2_MEM);
    pushLE(fullHdr, ARGON2_ITER);
    pushLE(fullHdr, ARGON2_PAR);
    fullHdr.insert(fullHdr.end(), dek_nonce.begin(), dek_nonce.end());
    fullHdr.insert(fullHdr.end(), enc_dek.begin(), enc_dek.end());

    // Nonces aléatoires par chiffrement
    std::vector<uint8_t> n1(N1), n2(N2), n3(N3);
    rng.randomize(n1.data(), N1);
    rng.randomize(n2.data(), N2);
    rng.randomize(n3.data(), N3);

    const auto ad = buildAD(immutHdr, 0, 1);

    size_t off = 0;
    auto slice = [&](size_t n) {
        Botan::secure_vector<uint8_t> v(dek.begin()+off, dek.begin()+off+n); off += n; return v;
    };
    const auto k1 = slice(K1);
    const auto k2 = slice(K2);
    const auto k3 = slice(K3);

    Botan::secure_vector<uint8_t> buf(
        reinterpret_cast<const uint8_t*>(plaintext.constData()),
        reinterpret_cast<const uint8_t*>(plaintext.constData()) + plaintext.size());

    buf = aeadEncrypt("AES-256/SIV",      k1, n1, ad, std::move(buf));
    buf = aeadEncrypt("Serpent/GCM",      k2, n2, ad, std::move(buf));
    buf = aeadEncrypt("ChaCha20Poly1305", k3, n3, ad, std::move(buf));

    // MAC global : HMAC-SHA256(K4, header || nonces || ciphertext)
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    mac->set_key(k4_mac);
    mac->update(fullHdr.data(), fullHdr.size());
    mac->update(n1.data(), n1.size());
    mac->update(n2.data(), n2.size());
    mac->update(n3.data(), n3.size());
    mac->update(buf.data(), buf.size());
    const auto macTag = mac->final();

    QByteArray result;
    result.reserve(static_cast<qsizetype>(HDR_SZ + NONCES_SZ + buf.size() + MAC_LEN));
    result.append(reinterpret_cast<const char*>(fullHdr.data()), static_cast<qsizetype>(fullHdr.size()));
    result.append(reinterpret_cast<const char*>(n1.data()),      static_cast<qsizetype>(n1.size()));
    result.append(reinterpret_cast<const char*>(n2.data()),      static_cast<qsizetype>(n2.size()));
    result.append(reinterpret_cast<const char*>(n3.data()),      static_cast<qsizetype>(n3.size()));
    result.append(reinterpret_cast<const char*>(buf.data()),     static_cast<qsizetype>(buf.size()));
    result.append(reinterpret_cast<const char*>(macTag.data()),  static_cast<qsizetype>(macTag.size()));
    return result;
}

// ── decrypt ───────────────────────────────────────────────────────────────────

QByteArray CryptoManager::decrypt(const QByteArray& data, const QString& password)
{
    // ── Détection CPDF : renvoyer vers « Déchiffrer un fichier » ──────────────
    if (data.startsWith(QByteArrayLiteral("CPDF")))
        throw std::runtime_error(
            "Ce fichier est au format CPDF (chiffrement de fichiers).\n"
            "Utilisez « Fichier → Déchiffrer un fichier » pour le déchiffrer.");

    // ── Format CPAD v2 (binaire) ──────────────────────────────────────────────
    const size_t minLen = HDR_SZ + NONCES_SZ + 3 * TAG_BYTES + MAC_LEN;
    if (static_cast<size_t>(data.size()) < minLen)
        throw std::runtime_error("Fichier trop court ou corrompu.");

    const auto* raw = reinterpret_cast<const uint8_t*>(data.constData());

    if (std::memcmp(raw, MAGIC.data(), MAGIC.size()) != 0)
        throw std::runtime_error("Format de fichier invalide (magic CPAD absent).");
    if (raw[4] != VERSION)
        throw std::runtime_error("Version de format non supportée.");

    const auto argon_mem  = loadLE<uint32_t>(raw + OFF_ARGON_MEM);
    const auto argon_iter = loadLE<uint32_t>(raw + OFF_ARGON_ITER);
    const auto argon_par  = loadLE<uint32_t>(raw + OFF_ARGON_PAR);

    if (argon_mem  < 8  || argon_mem  > 524288 ||
        argon_iter < 1  || argon_iter > 16     ||
        argon_par  < 1  || argon_par  > 16)
        throw std::runtime_error("Paramètres Argon2 invalides dans le fichier.");

    const std::span<const uint8_t> immutHdr(raw, HDR_IMMUT_SZ);
    const std::span<const uint8_t> fullHdr(raw, HDR_SZ);
    const std::span<const uint8_t> kdf_salt(raw + OFF_KDF_SALT,  HDR_KDF_SZ);
    const std::span<const uint8_t> dek_nonce(raw + OFF_DEK_NONCE, DEK_NONCE_LEN);
    const std::span<const uint8_t> enc_dek(raw + OFF_ENC_DEK,   ENC_DEK_LEN);

    const QByteArray pwUtf8 = password.toUtf8();
    Botan::secure_vector<char> pwd(pwUtf8.constData(), pwUtf8.constData() + pwUtf8.size());
    const auto kek = deriveKEK(pwd.data(), pwd.size(), kdf_salt, argon_mem, argon_iter, argon_par);
    pwd = Botan::secure_vector<char>();

    Botan::secure_vector<uint8_t> dek;
    try {
        auto aead = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Decryption);
        aead->set_key(kek);
        aead->start(dek_nonce);
        dek.assign(enc_dek.begin(), enc_dek.end());
        aead->finish(dek);
    } catch (const std::exception&) {
        throw std::runtime_error("Mot de passe incorrect ou données corrompues.");
    }

    size_t off = 0;
    auto slice = [&](size_t n) {
        Botan::secure_vector<uint8_t> v(dek.begin()+off, dek.begin()+off+n); off += n; return v;
    };
    const auto k1    = slice(K1);
    const auto k2    = slice(K2);
    const auto k3    = slice(K3);
    const auto k4mac = slice(K4);

    size_t pos = HDR_SZ;
    const std::span<const uint8_t> n1(raw + pos, N1); pos += N1;
    const std::span<const uint8_t> n2(raw + pos, N2); pos += N2;
    const std::span<const uint8_t> n3(raw + pos, N3); pos += N3;

    const size_t ctLen = static_cast<size_t>(data.size()) - HDR_SZ - NONCES_SZ - MAC_LEN;
    Botan::secure_vector<uint8_t> cipher(raw + pos, raw + pos + ctLen);

    // Vérification HMAC avant déchiffrement (encrypt-then-MAC)
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    mac->set_key(k4mac);
    mac->update(fullHdr.data(), fullHdr.size());
    mac->update(n1.data(), n1.size());
    mac->update(n2.data(), n2.size());
    mac->update(n3.data(), n3.size());
    mac->update(cipher.data(), cipher.size());
    const auto computedMac = mac->final();
    const uint8_t* storedMac = raw + HDR_SZ + NONCES_SZ + ctLen;
    if (!Botan::constant_time_compare(computedMac.data(), storedMac, MAC_LEN))
        throw std::runtime_error("Vérification MAC globale échouée — fichier corrompu ou altéré.");

    const auto ad = buildAD(immutHdr, 0, 1);
    try {
        cipher = aeadDecrypt("ChaCha20Poly1305", k3, n3, ad, std::move(cipher));
        cipher = aeadDecrypt("Serpent/GCM",      k2, n2, ad, std::move(cipher));
        cipher = aeadDecrypt("AES-256/SIV",      k1, n1, ad, std::move(cipher));
    } catch (const Botan::Invalid_Authentication_Tag&) {
        throw std::runtime_error("Mot de passe incorrect ou données corrompues.");
    }

    return QByteArray(reinterpret_cast<const char*>(cipher.data()),
                      static_cast<qsizetype>(cipher.size()));
}
