#include "fileencryptor.h"
#include "cryptyrust.h"

#include <QFile>
#include <stdexcept>

static void arsProgressBridge(int32_t pct, void* user_data)
{
    if (auto* cb = static_cast<const std::function<void(int)>*>(user_data))
        (*cb)(static_cast<int>(pct));
}

void FileEncryptor::encryptFile(const QString&                  inputPath,
                                 const QString&                  outputPath,
                                 const QString&                  password,
                                 const std::atomic<bool>&        cancelled,
                                 const std::function<void(int)>& progressCb)
{
    if (cancelled.load()) throw std::runtime_error("Annulé");

    QFile fin(inputPath);
    if (!fin.open(QIODevice::ReadOnly))
        throw std::runtime_error("Impossible d'ouvrir : " + fin.errorString().toStdString());

    const QByteArray plain = fin.readAll();
    fin.close();

    if (cancelled.load()) throw std::runtime_error("Annulé");

    const QByteArray pwUtf8 = password.toUtf8();
    ArsParams params = arsenic_default_params();
    ArsBuffer out = {};

    const int rc = arsenic_encrypt(
        reinterpret_cast<const uint8_t*>(plain.constData()),
        static_cast<uintptr_t>(plain.size()),
        pwUtf8.constData(),
        &params,
        progressCb ? arsProgressBridge : nullptr,
        progressCb ? const_cast<void*>(static_cast<const void*>(&progressCb)) : nullptr,
        &out
    );

    if (rc != ARSENIC_OK) {
        const char* err = arsenic_last_error();
        const std::string msg = err ? err : "Erreur de chiffrement.";
        arsenic_free_buffer(&out);
        throw std::runtime_error(msg);
    }

    QFile fout(outputPath);
    if (!fout.open(QIODevice::WriteOnly)) {
        arsenic_free_buffer(&out);
        throw std::runtime_error("Impossible de créer : " + fout.errorString().toStdString());
    }

    struct Guard {
        QFile& f; const QString& path; bool ok{false};
        ~Guard() { f.close(); if (!ok) QFile::remove(path); }
    } guard{.f = fout, .path = outputPath};

    fout.write(reinterpret_cast<const char*>(out.ptr), static_cast<qint64>(out.len));
    arsenic_free_buffer(&out);

    guard.ok = true;
    if (progressCb) progressCb(100);
}

void FileEncryptor::decryptFile(const QString&                  inputPath,
                                 const QString&                  outputPath,
                                 const QString&                  password,
                                 const std::atomic<bool>&        cancelled,
                                 const std::function<void(int)>& progressCb)
{
    if (cancelled.load()) throw std::runtime_error("Annulé");

    QFile fin(inputPath);
    if (!fin.open(QIODevice::ReadOnly))
        throw std::runtime_error("Impossible d'ouvrir : " + fin.errorString().toStdString());

    const QByteArray cipher = fin.readAll();
    fin.close();

    if (cancelled.load()) throw std::runtime_error("Annulé");

    const QByteArray pwUtf8 = password.toUtf8();
    ArsBuffer out = {};

    const int rc = arsenic_decrypt(
        reinterpret_cast<const uint8_t*>(cipher.constData()),
        static_cast<uintptr_t>(cipher.size()),
        pwUtf8.constData(),
        progressCb ? arsProgressBridge : nullptr,
        progressCb ? const_cast<void*>(static_cast<const void*>(&progressCb)) : nullptr,
        &out
    );

    if (rc != ARSENIC_OK) {
        const char* err = arsenic_last_error();
        const std::string msg = (rc == ARSENIC_ERR_BAD_MAGIC)
            ? "Format non reconnu — ce fichier n'est pas un fichier Arsenic chiffré."
            : (err ? err : "Mot de passe incorrect ou données corrompues.");
        arsenic_free_buffer(&out);
        throw std::runtime_error(msg);
    }

    QFile fout(outputPath);
    if (!fout.open(QIODevice::WriteOnly)) {
        arsenic_free_buffer(&out);
        throw std::runtime_error("Impossible de créer : " + fout.errorString().toStdString());
    }

    struct Guard {
        QFile& f; const QString& path; bool ok{false};
        ~Guard() { f.close(); if (!ok) QFile::remove(path); }
    } guard{.f = fout, .path = outputPath};

    fout.write(reinterpret_cast<const char*>(out.ptr), static_cast<qint64>(out.len));
    arsenic_free_buffer(&out);

    guard.ok = true;
    if (progressCb) progressCb(100);
}
