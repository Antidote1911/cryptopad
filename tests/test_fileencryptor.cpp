#include <QtTest>
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QUuid>
#include <atomic>

#include "fileencryptor.h"

#define QVERIFY_THROWS(expr)                                                \
    do {                                                                    \
        bool _threw = false;                                                \
        try { (expr); } catch (const std::exception&) { _threw = true; }   \
        QVERIFY2(_threw, "Exception attendue non levée");                   \
    } while (false)

class TestFileEncryptor : public QObject {
    Q_OBJECT

    QStringList m_tmpFiles;

    QString tmpPath(const QString& ext = {})
    {
        const QString p = QDir::temp().filePath(
            "test_fe_" + QUuid::createUuid().toString(QUuid::WithoutBraces) + ext);
        m_tmpFiles << p;
        return p;
    }

    QString writeTmp(const QByteArray& data, const QString& ext = {})
    {
        const QString p = tmpPath(ext);
        QFile f(p);
        if (!f.open(QIODevice::WriteOnly))
            qFatal("writeTmp: cannot open %s", qPrintable(p));
        f.write(data);
        return p;
    }

    static void corruptByte(const QString& path, qint64 offset)
    {
        QFile f(path);
        if (!f.open(QIODevice::ReadWrite))
            qFatal("corruptByte: cannot open %s", qPrintable(path));
        if (!f.seek(offset))
            qFatal("corruptByte: seek failed");
        char b = 0;
        f.read(&b, 1);
        b ^= 0xFF;
        if (!f.seek(offset))
            qFatal("corruptByte: seek failed");
        f.write(&b, 1);
    }

private slots:
    void cleanup()
    {
        for (const QString& p : m_tmpFiles)
            QFile::remove(p);
        m_tmpFiles.clear();
    }

    // ── Roundtrip encrypt → decrypt ────────────────────────────────────────

    void roundtrip_data()
    {
        QTest::addColumn<QByteArray>("data");
        QTest::newRow("vide")            << QByteArray();
        QTest::newRow("petit texte")     << QByteArray("Hello, CryptoPad!");
        QTest::newRow("octets binaires") << QByteArray("\x00\x01\xFE\xFF\x80", 5);
        // Dépasse CHUNK_SIZE pour couvrir les fichiers multi-chunks
        QTest::newRow("multi-chunk")     << QByteArray(static_cast<int>(FileEncryptor::CHUNK_SIZE) + 256, '\xAB');
    }

    void roundtrip()
    {
        QFETCH(QByteArray, data);
        const QString pw = "mot_de_passe_42!";
        std::atomic<bool> cancelled{false};

        const QString inPath  = writeTmp(data);
        const QString encPath = tmpPath(".cpdf");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, pw, cancelled);
        QVERIFY(QFile::exists(encPath));

        FileEncryptor::decryptFile(encPath, decPath, pw, cancelled);
        QVERIFY(QFile::exists(decPath));

        QFile dec(decPath);
        QVERIFY(dec.open(QIODevice::ReadOnly));
        QCOMPARE(dec.readAll(), data);
    }

    // ── Mauvais mot de passe ───────────────────────────────────────────────

    void wrongPassword()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath  = writeTmp(QByteArray("données secrètes"));
        const QString encPath = tmpPath(".cpdf");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "bon_mdp", cancelled);
        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "mauvais_mdp", cancelled));
        QVERIFY(!QFile::exists(decPath));
    }

    // ── Payload chiffré altéré (nonce du premier chunk) ───────────────────

    void tamperedPayload()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath  = writeTmp(QByteArray(128, 'X'));
        const QString encPath = tmpPath(".cpdf");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);
        corruptByte(encPath, 257);  // offset 257 = premier octet du premier chunk (N1[0])

        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "pw", cancelled));
        QVERIFY(!QFile::exists(decPath));
    }

    // ── Trailer MAC altéré ────────────────────────────────────────────────

    void tamperedTag()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath  = writeTmp(QByteArray(64, 'T'));
        const QString encPath = tmpPath(".cpdf");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);
        // Dernier octet du fichier = dernier octet du trailer MAC (HMAC-SHA256)
        corruptByte(encPath, QFileInfo(encPath).size() - 1);

        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "pw", cancelled));
        QVERIFY(!QFile::exists(decPath));
    }

    // ── Magic altéré (rejeté avant la dérivation de clé) ─────────────────

    void tamperedMagic()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath  = writeTmp(QByteArray("test"));
        const QString encPath = tmpPath(".cpdf");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);
        corruptByte(encPath, 0);  // premier octet du magic "CPDF"

        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "pw", cancelled));
    }

    // ── Sel KDF altéré (mauvaise clé dérivée) ─────────────────────────────

    void tamperedSalt()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath  = writeTmp(QByteArray("données"));
        const QString encPath = tmpPath(".cpdf");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);
        corruptByte(encPath, 21);  // offset 21 = premier octet du sel KDF (OFF_KDF_SALT)

        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "pw", cancelled));
        QVERIFY(!QFile::exists(decPath));
    }

    // ── Annulation ────────────────────────────────────────────────────────
    // Argon2id s'exécute avant la vérification → délai ~400 ms inévitable.

    void cancellation()
    {
        std::atomic<bool> cancelled{true};
        const QString inPath  = writeTmp(QByteArray("contenu"));
        const QString encPath = tmpPath(".cpdf");

        bool threw = false;
        try {
            FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);
        } catch (const std::exception& e) {
            threw = true;
            QCOMPARE(QString::fromUtf8(e.what()), QString("Annulé"));
        }
        QVERIFY(threw);
        QVERIFY(!QFile::exists(encPath));
    }

    // ── Non-déterminisme (sel aléatoire par chiffrement) ──────────────────

    void nonDeterministic()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath = writeTmp(QByteArray("même contenu"));
        const QString enc1   = tmpPath(".cpdf");
        const QString enc2   = tmpPath(".cpdf");

        FileEncryptor::encryptFile(inPath, enc1, "pw", cancelled);
        FileEncryptor::encryptFile(inPath, enc2, "pw", cancelled);

        QFile f1(enc1), f2(enc2);
        QVERIFY(f1.open(QIODevice::ReadOnly));
        QVERIFY(f2.open(QIODevice::ReadOnly));
        QVERIFY(f1.readAll() != f2.readAll());
    }

    // ── Taille du fichier chiffré ─────────────────────────────────────────
    // Attendu : 257 (header) + N × (CHUNK_SIZE + 100) (chunks paddés) + 32 (MAC trailer)

    void outputSize_data()
    {
        QTest::addColumn<int>("inputSize");
        QTest::newRow("vide")    << 0;
        QTest::newRow("1 octet") << 1;
        QTest::newRow("1 KiB")   << 1024;
        QTest::newRow("CHUNK-1") << static_cast<int>(FileEncryptor::CHUNK_SIZE) - 1;
        QTest::newRow("CHUNK+1") << static_cast<int>(FileEncryptor::CHUNK_SIZE) + 1;
    }

    void outputSize()
    {
        QFETCH(int, inputSize);
        std::atomic<bool> cancelled{false};

        const QString inPath  = writeTmp(QByteArray(inputSize, '\xCC'));
        const QString encPath = tmpPath(".cpdf");

        FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);

        const qint64 cs            = static_cast<qint64>(FileEncryptor::CHUNK_SIZE);
        const qint64 chunkEncrypted = cs + static_cast<qint64>(FileEncryptor::OVERHEAD); // 1 048 676
        const qint64 nChunks       = (inputSize == 0) ? 0 : (inputSize + cs - 1) / cs;
        const qint64 expected      = static_cast<qint64>(FileEncryptor::HDR_SZ)
                                   + nChunks * chunkEncrypted
                                   + static_cast<qint64>(FileEncryptor::MAC_TRAILER_LEN);

        QCOMPARE(QFileInfo(encPath).size(), expected);
    }
};

QTEST_MAIN(TestFileEncryptor)
#include "test_fileencryptor.moc"
