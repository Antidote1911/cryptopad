#pragma once
#include <QDialog>
#include <QColor>

class QFrame;
class QLineEdit;

class ColorPickerDialog : public QDialog {
    Q_OBJECT
public:
    explicit ColorPickerDialog(const QColor& initial = Qt::white,
                               QWidget* parent = nullptr);
    QColor color() const;
    static QColor getColor(const QColor& initial, QWidget* parent,
                           const QString& title = {});

private:
    void setColor(const QColor& c);
    void updatePreview();

    QWidget*   m_hue;
    QWidget*   m_sv;
    QFrame*    m_preview;
    QLineEdit* m_hex;
    qreal m_h{0}, m_s{1}, m_v{1};
};
