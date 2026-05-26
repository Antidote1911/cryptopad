#include "mainwindow.h"
#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("CryptoPad");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("CryptoPad");

    // Dark palette
    QPalette dark;
    dark.setColor(QPalette::Window,          QColor(0x2B, 0x2B, 0x2B));
    dark.setColor(QPalette::WindowText,      Qt::white);
    dark.setColor(QPalette::Base,            QColor(0x1E, 0x1E, 0x1E));
    dark.setColor(QPalette::AlternateBase,   QColor(0x2B, 0x2B, 0x2B));
    dark.setColor(QPalette::ToolTipBase,     Qt::white);
    dark.setColor(QPalette::ToolTipText,     Qt::white);
    dark.setColor(QPalette::Text,            QColor(0xD4, 0xD4, 0xD4));
    dark.setColor(QPalette::Button,          QColor(0x3C, 0x3C, 0x3C));
    dark.setColor(QPalette::ButtonText,      Qt::white);
    dark.setColor(QPalette::BrightText,      Qt::red);
    dark.setColor(QPalette::Highlight,       QColor(0x26, 0x4F, 0x78));
    dark.setColor(QPalette::HighlightedText, Qt::white);
    dark.setColor(QPalette::Link,            QColor(0x56, 0x9C, 0xD6));
    app.setPalette(dark);

    MainWindow w;
    w.show();
    return app.exec();
}
