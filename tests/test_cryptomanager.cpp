#include <QtTest>
#include <QByteArray>
#include <QString>

#include "cryptomanager.h"

#define QVERIFY_THROWS(expr)                                                \
    do {                                                                    \
        bool _threw = false;                                                \
        try { (expr); } catch (const std::exception&) { _threw = true; }   \
        QVERIFY2(_threw, "Exception attendue non levée");                   \
    } while (false)

class TestCryptoManager : public QObject {
    Q_OBJECT

private:
    // Copie les données et retourne un XOR d'un octet à byteOffset.
    // Offset négatif : depuis la fin (-1 = dernier octet).
    static QByteArray tamperRaw(const QByteArray& data,
                                 int               byteOffset,
                                 uint8_t           xorMask = 0xFF)
    {
        QByteArray result = data;
        const int sz  = result.size();
        const int idx = (byteOffset >= 0) ? byteOffset : sz + byteOffset;
        if (idx < 0 || idx >= sz)
            qFatal("tamperRaw: offset hors limites (%d, taille %d)", byteOffset, sz);
        result[idx] = static_cast<char>(static_cast<uint8_t>(result[idx]) ^ xorMask);
        return result;
    }

private slots:
    // ── Roundtrip encrypt/decrypt ──────────────────────────────────────────
    // NOTE : chaque cas appelle Argon2id deux fois (encrypt + decrypt) ;
    //        la suite complète prend ~1 min avec les paramètres de prod.

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
        QVERIFY(!cipher.isEmpty());
        QCOMPARE(recovered, plaintext);
    }

    // ── Mauvais mot de passe ───────────────────────────────────────────────

    void wrongPassword()
    {
        const auto cipher = CryptoManager::encrypt(QByteArray("secret"), "bon_mdp");
        QVERIFY_THROWS(CryptoManager::decrypt(cipher, "mauvais_mdp"));
    }

    // ── Dernier octet altéré (HMAC trailer) ───────────────────────────────

    void tamperedCiphertext()
    {
        const auto cipher   = CryptoManager::encrypt(QByteArray("données sensibles"), "pw");
        const auto tampered = tamperRaw(cipher, -1);  // flip le dernier octet du HMAC
        QVERIFY_THROWS(CryptoManager::decrypt(tampered, "pw"));
    }

    // ── Ciphertext altéré (détecté par HMAC) ──────────────────────────────
    // Offset 309 = premier octet du ciphertext (header(257) + nonces(52))

    void tamperedInnerLayer()
    {
        const auto cipher   = CryptoManager::encrypt(QByteArray(64, 'A'), "pw");
        const auto tampered = tamperRaw(cipher, 257 + 52);
        QVERIFY_THROWS(CryptoManager::decrypt(tampered, "pw"));
    }

    // ── Sel altéré → mauvais KEK → échec unwrap DEK ───────────────────────
    // Offset 21 = premier octet du kdf_salt (après immutable header = magic+ver+file_id)

    void tamperedSalt()
    {
        const auto cipher   = CryptoManager::encrypt(QByteArray("test"), "pw");
        const auto tampered = tamperRaw(cipher, 21);
        QVERIFY_THROWS(CryptoManager::decrypt(tampered, "pw"));
    }

    // ── Non-déterminisme (file_id + nonces aléatoires) ────────────────────

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

    // ── Overhead de taille ────────────────────────────────────────────────
    // header(257) + nonces(52) + 3×tag(16) + HMAC(32) = 389 octets fixes

    void ciphertextSize()
    {
        const QByteArray pt(64, 'A');
        const auto cipher = CryptoManager::encrypt(pt, "pw");
        QCOMPARE(cipher.size(), pt.size() + CryptoManager::ENCRYPT_OVERHEAD);
    }

    // ── Détection CPDF ────────────────────────────────────────────────────

    void rejectCpdfMagic()
    {
        // Fabrique un tampon qui commence par le magic CPDF
        QByteArray fake(300, '\x00');
        fake[0] = 'C'; fake[1] = 'P'; fake[2] = 'D'; fake[3] = 'F';
        QVERIFY_THROWS(CryptoManager::decrypt(fake, "pw"));
    }
};

QTEST_MAIN(TestCryptoManager)
#include "test_cryptomanager.moc"
