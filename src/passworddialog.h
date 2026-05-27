#pragma once
#include <QDialog>
#include <QString>

class QLineEdit;
class QLabel;

class PasswordDialog : public QDialog {
    Q_OBJECT
public:
    enum class Mode { Encrypt, Decrypt };

    explicit PasswordDialog(Mode mode, QWidget* parent = nullptr);

    [[nodiscard]] QString password() const;
    void    setNote(const QString& text);   // affiche un avertissement en rouge en tête de dialogue

private:
    QLabel*    m_noteLabel{nullptr};
    QLineEdit* m_edit{nullptr};
    QLineEdit* m_confirm{nullptr};  // only shown in Encrypt mode
    Mode       m_mode;

    void validate();
};
