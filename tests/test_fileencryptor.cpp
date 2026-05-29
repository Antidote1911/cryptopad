#include <QtTest>
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QUuid>
#include <atomic>

#include "fileencryptor.h"

#define QVERIFY_THROWS(expr)                                                      \
    do {                                                                          \
        bool _threw = false;                                                      \
        try { static_cast<void>(expr); } catch (const std::exception&) { _threw = true; } \
        QVERIFY2(_threw, "Exception attendue non levée");                         \
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
        QTest::newRow("1 MiB")           << QByteArray(1 << 20, '\xAB');
    }

    void roundtrip()
    {
        QFETCH(QByteArray, data);
        const QString pw = "mot_de_passe_42!";
        std::atomic<bool> cancelled{false};

        const QString inPath  = writeTmp(data);
        const QString encPath = tmpPath(".arsenic");
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
        const QString encPath = tmpPath(".arsenic");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "bon_mdp", cancelled);
        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "mauvais_mdp", cancelled));
        QVERIFY(!QFile::exists(decPath));
    }

    // ── Magic altéré → rejeté avant dérivation de clé ─────────────────────

    void tamperedMagic()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath  = writeTmp(QByteArray("test"));
        const QString encPath = tmpPath(".arsenic");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);
        corruptByte(encPath, 0);  // premier octet du magic "ARSN"

        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "pw", cancelled));
    }

    // ── Dernier octet altéré (tag ou MAC) ────────────────────────────────

    void tamperedLastByte()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath  = writeTmp(QByteArray(64, 'T'));
        const QString encPath = tmpPath(".arsenic");
        const QString decPath = tmpPath(".dec");

        FileEncryptor::encryptFile(inPath, encPath, "pw", cancelled);
        corruptByte(encPath, QFileInfo(encPath).size() - 1);

        QVERIFY_THROWS(FileEncryptor::decryptFile(encPath, decPath, "pw", cancelled));
        QVERIFY(!QFile::exists(decPath));
    }

    // ── Non-déterminisme ──────────────────────────────────────────────────

    void nonDeterministic()
    {
        std::atomic<bool> cancelled{false};
        const QString inPath = writeTmp(QByteArray("même contenu"));
        const QString enc1   = tmpPath(".arsenic");
        const QString enc2   = tmpPath(".arsenic");

        FileEncryptor::encryptFile(inPath, enc1, "pw", cancelled);
        FileEncryptor::encryptFile(inPath, enc2, "pw", cancelled);

        QFile f1(enc1), f2(enc2);
        QVERIFY(f1.open(QIODevice::ReadOnly));
        QVERIFY(f2.open(QIODevice::ReadOnly));
        QVERIFY(f1.readAll() != f2.readAll());
    }

    // ── Annulation avant démarrage ─────────────────────────────────────────

    void cancellation()
    {
        std::atomic<bool> cancelled{true};
        const QString inPath  = writeTmp(QByteArray("contenu"));
        const QString encPath = tmpPath(".arsenic");

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
};

QTEST_MAIN(TestFileEncryptor)
#include "test_fileencryptor.moc"
