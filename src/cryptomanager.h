#pragma once
#include <QByteArray>
#include <QString>

class CryptoManager {
public:
    [[nodiscard]] static QByteArray encrypt(const QByteArray& plaintext, const QString& password);
    [[nodiscard]] static QByteArray decrypt(const QByteArray& data, const QString& password);
    [[nodiscard]] static QString algoName();
};
