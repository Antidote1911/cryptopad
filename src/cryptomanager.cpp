#include "cryptomanager.h"
#include "cryptyrust.h"
#include <stdexcept>

QString CryptoManager::algoName()
{
    return "Arsenic V1 (Deoxys-II-256 · XChaCha20-Poly1305, Argon2id)";
}

QByteArray CryptoManager::encrypt(const QByteArray& plaintext, const QString& password)
{
    const QByteArray pwUtf8 = password.toUtf8();
    ArsParams params = arsenic_default_params();
    ArsBuffer out = {};

    const int rc = arsenic_encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.constData()),
        static_cast<uintptr_t>(plaintext.size()),
        pwUtf8.constData(),
        &params,
        nullptr, nullptr,
        &out
    );

    if (rc != ARSENIC_OK) {
        const char* err = arsenic_last_error();
        const std::string msg = err ? err : "Erreur de chiffrement inconnue.";
        arsenic_free_buffer(&out);
        throw std::runtime_error(msg);
    }

    QByteArray result(reinterpret_cast<const char*>(out.ptr), static_cast<qsizetype>(out.len));
    arsenic_free_buffer(&out);
    return result;
}

QByteArray CryptoManager::decrypt(const QByteArray& data, const QString& password)
{
    const QByteArray pwUtf8 = password.toUtf8();
    ArsBuffer out = {};

    const int rc = arsenic_decrypt(
        reinterpret_cast<const uint8_t*>(data.constData()),
        static_cast<uintptr_t>(data.size()),
        pwUtf8.constData(),
        nullptr, nullptr,
        &out
    );

    if (rc != ARSENIC_OK) {
        const char* err = arsenic_last_error();
        const std::string msg = (rc == ARSENIC_ERR_BAD_MAGIC)
            ? "Format non reconnu — ce fichier n'est pas un fichier Arsenic."
            : (err ? err : "Mot de passe incorrect ou données corrompues.");
        arsenic_free_buffer(&out);
        throw std::runtime_error(msg);
    }

    QByteArray result(reinterpret_cast<const char*>(out.ptr), static_cast<qsizetype>(out.len));
    arsenic_free_buffer(&out);
    return result;
}
