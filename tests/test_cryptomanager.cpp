#include <QtTest>
#include <QByteArray>
#include <QString>

#include "cryptomanager.h"

#define QVERIFY_THROWS(expr)                                                      \
    do {                                                                          \
        bool _threw = false;                                                      \
        try { static_cast<void>(expr); } catch (const std::exception&) { _threw = true; } \
        QVERIFY2(_threw, "Exception attendue non levée");                         \
    } while (false)

class TestCryptoManager : public QObject {
    Q_OBJECT

    static QByteArray tamperByte(const QByteArray& data, int byteOffset, uint8_t xorMask = 0xFF)
    {
        QByteArray result = data;
        const int sz  = result.size();
        const int idx = (byteOffset >= 0) ? byteOffset : sz + byteOffset;
        if (idx < 0 || idx >= sz)
            qFatal("tamperByte: offset hors limites (%d, taille %d)", byteOffset, sz);
        result[idx] = static_cast<char>(static_cast<uint8_t>(result[idx]) ^ xorMask);
        return result;
    }

private slots:
    // ── Roundtrip encrypt/decrypt ──────────────────────────────────────────

    void roundtrip_data()
    {
        QTest::addColumn<QByteArray>("plaintext");
        QTest::newRow("ascii")           << QByteArray("Hello, world!");
        QTest::newRow("vide")            << QByteArray();
        QTest::newRow("octets binaires") << QByteArray("\x00\x01\xFE\xFF", 4);
        QTest::newRow("long")            << QByteArray(4096, 'X');
    }

    void roundtrip()
    {
        QFETCH(QByteArray, plaintext);
        const QString pw = "mot_de_passe_test_42!";
        const auto cipher    = CryptoManager::encrypt(plaintext, pw);
        const auto recovered = CryptoManager::decrypt(cipher, pw);
        QVERIFY(!cipher.isEmpty() || plaintext.isEmpty());
        QCOMPARE(recovered, plaintext);
    }

    // ── Mauvais mot de passe ───────────────────────────────────────────────

    void wrongPassword()
    {
        const auto cipher = CryptoManager::encrypt(QByteArray("secret"), "bon_mdp");
        QVERIFY_THROWS(CryptoManager::decrypt(cipher, "mauvais_mdp"));
    }

    // ── Ciphertext altéré (détecté par AEAD ou HMAC) ──────────────────────

    void tamperedCiphertext()
    {
        const auto cipher   = CryptoManager::encrypt(QByteArray("données sensibles"), "pw");
        // Altère le dernier octet — tag ou MAC selon le format
        const auto tampered = tamperByte(cipher, -1);
        QVERIFY_THROWS(CryptoManager::decrypt(tampered, "pw"));
    }

    // ── En-tête altéré ─────────────────────────────────────────────────────
    // Offset 10 : dans la zone des paramètres du header Arsenic

    void tamperedHeader()
    {
        const auto cipher   = CryptoManager::encrypt(QByteArray("test"), "pw");
        const auto tampered = tamperByte(cipher, 10);
        QVERIFY_THROWS(CryptoManager::decrypt(tampered, "pw"));
    }

    // ── Non-déterminisme (sel aléatoire par chiffrement) ──────────────────

    void nonDeterministic()
    {
        const QByteArray pt = "même message";
        const QString    pw = "même_mot_de_passe";
        const auto c1 = CryptoManager::encrypt(pt, pw);
        const auto c2 = CryptoManager::encrypt(pt, pw);
        QVERIFY(c1 != c2);
    }

    // ── Mot de passe Unicode ───────────────────────────────────────────────

    void unicodePassword()
    {
        const QString pw = "пароль_日本語_🔐";
        const auto cipher = CryptoManager::encrypt(QByteArray("données"), pw);
        QVERIFY_THROWS(CryptoManager::decrypt(cipher, "wrong"));
        const auto recovered = CryptoManager::decrypt(cipher, pw);
        QCOMPARE(recovered, QByteArray("données"));
    }

    // ── Format invalide → exception ───────────────────────────────────────

    void rejectInvalidMagic()
    {
        QByteArray fake(200, '\x00');
        fake[0] = 'C'; fake[1] = 'P'; fake[2] = 'A'; fake[3] = 'D'; // ancien format CPAD
        QVERIFY_THROWS(CryptoManager::decrypt(fake, "pw"));
    }
};

QTEST_MAIN(TestCryptoManager)
#include "test_cryptomanager.moc"
