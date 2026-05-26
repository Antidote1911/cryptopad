#include "passworddialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>

PasswordDialog::PasswordDialog(Mode mode, QWidget* parent)
    : QDialog(parent), m_mode(mode)
{
    setWindowTitle(mode == Mode::Encrypt ? tr("Définir le mot de passe") : tr("Entrer le mot de passe"));
    setMinimumWidth(340);

    auto* layout = new QVBoxLayout(this);

    m_noteLabel = new QLabel(this);
    m_noteLabel->setWordWrap(true);
    m_noteLabel->setStyleSheet("color: #c0392b; font-weight: bold; padding-bottom: 4px;");
    m_noteLabel->hide();
    layout->addWidget(m_noteLabel);

    layout->addWidget(new QLabel(tr("Mot de passe :"), this));
    m_edit = new QLineEdit(this);
    m_edit->setEchoMode(QLineEdit::Password);
    m_edit->setPlaceholderText(tr("Mot de passe…"));
    layout->addWidget(m_edit);

    if (mode == Mode::Encrypt) {
        layout->addWidget(new QLabel(tr("Confirmer le mot de passe :"), this));
        m_confirm = new QLineEdit(this);
        m_confirm->setEchoMode(QLineEdit::Password);
        m_confirm->setPlaceholderText(tr("Confirmer…"));
        layout->addWidget(m_confirm);
    }

    auto* btnBox = new QHBoxLayout;
    auto* ok     = new QPushButton(tr("OK"), this);
    auto* cancel = new QPushButton(tr("Annuler"), this);
    ok->setDefault(true);
    btnBox->addStretch();
    btnBox->addWidget(ok);
    btnBox->addWidget(cancel);
    layout->addLayout(btnBox);

    connect(ok,     &QPushButton::clicked, this, &PasswordDialog::validate);
    connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_edit, &QLineEdit::returnPressed, this, &PasswordDialog::validate);
}

void PasswordDialog::setNote(const QString& text)
{
    m_noteLabel->setText(text);
    m_noteLabel->show();
    adjustSize();
}

QString PasswordDialog::password() const
{
    return m_edit->text();
}

void PasswordDialog::validate()
{
    if (m_edit->text().isEmpty()) {
        QMessageBox::warning(this, tr("Erreur"), tr("Le mot de passe ne peut pas être vide."));
        return;
    }
    if (m_mode == Mode::Encrypt && m_confirm && m_edit->text() != m_confirm->text()) {
        QMessageBox::warning(this, tr("Erreur"), tr("Les mots de passe ne correspondent pas."));
        m_confirm->clear();
        m_confirm->setFocus();
        return;
    }
    accept();
}
