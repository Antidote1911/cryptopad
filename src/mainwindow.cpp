#include "mainwindow.h"
#include "codeeditor.h"
#include "cryptomanager.h"
#include "fileencryptor.h"
#include "passworddialog.h"

#include <QTabWidget>
#include <QToolBar>
#include "filteredfontcombobox.h"
#include <QComboBox>
#include <QIntValidator>
#include <QLineEdit>
#include <QApplication>
#include <QAbstractItemView>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QActionGroup>
#include <QIcon>
#include <QToolButton>
#include "colorpickerpopup.h"
#include "colorpickerdialog.h"
#include <QPixmap>
#include <QPainter>
#include <QFileDialog>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QMessageBox>
#include <QProgressDialog>
#include <QtConcurrent>
#include <QCloseEvent>
#include <QFile>
#include <QKeySequence>
#include <QStatusBar>
#include <QLabel>
#include <QRegularExpression>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QTimer>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("CryptoPad");
    resize(1200, 768);

    m_tabs = new QTabWidget(this);
    m_tabs->setTabsClosable(true);
    m_tabs->setMovable(true);
    setCentralWidget(m_tabs);

    connect(m_tabs, &QTabWidget::tabCloseRequested, this, &MainWindow::closeTab);
    connect(m_tabs, &QTabWidget::currentChanged,    this, &MainWindow::onTabChanged);

    setupActions();
    setupMenus();
    setupToolBar();
    setupFontBar();

    m_statsLabel = new QLabel(this);
    m_statsLabel->setContentsMargins(8, 0, 8, 0);
    statusBar()->addPermanentWidget(m_statsLabel);

    updateStatsLabel();
    statusBar()->showMessage(tr("Prêt"));

    newFile();
}

// ── icône couleur ─────────────────────────────────────────────────────────────

QIcon MainWindow::makeColorIcon(const QColor& color)
{
    QPixmap pix(22, 22);
    pix.fill(Qt::transparent);
    QPainter p(&pix);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(color);
    p.setPen(QPen(color.darker(130), 1));
    p.drawRoundedRect(2, 2, 18, 18, 3, 3);
    return QIcon(pix);
}

// ── actions ───────────────────────────────────────────────────────────────────

void MainWindow::setupActions()
{
    // Fichier
    m_actNew    = new QAction(QIcon::fromTheme("document-new"),     tr("&Nouveau"),           this);
    m_actOpen   = new QAction(QIcon::fromTheme("document-open"),    tr("&Ouvrir…"),           this);
    m_actSave   = new QAction(QIcon::fromTheme("document-save"),    tr("&Enregistrer"),       this);
    m_actSaveAs = new QAction(QIcon::fromTheme("document-save-as"), tr("Enregistrer &sous…"), this);
    m_actQuit   = new QAction(QIcon::fromTheme("application-exit"), tr("&Quitter"),           this);

    m_actNew->setShortcut(QKeySequence::New);
    m_actOpen->setShortcut(QKeySequence::Open);
    m_actSave->setShortcut(QKeySequence::Save);
    m_actSaveAs->setShortcut(QKeySequence::SaveAs);
    m_actQuit->setShortcut(QKeySequence::Quit);

    connect(m_actNew,    &QAction::triggered, this, &MainWindow::newFile);
    connect(m_actOpen,   &QAction::triggered, this, &MainWindow::openFile);
    connect(m_actSave,   &QAction::triggered, this, &MainWindow::saveFile);
    connect(m_actSaveAs, &QAction::triggered, this, &MainWindow::saveFileAs);
    connect(m_actQuit,   &QAction::triggered, this, &QWidget::close);

    // Édition
    m_actUndo      = new QAction(QIcon::fromTheme("edit-undo"),       tr("&Annuler"),           this);
    m_actRedo      = new QAction(QIcon::fromTheme("edit-redo"),       tr("&Rétablir"),          this);
    m_actCut       = new QAction(QIcon::fromTheme("edit-cut"),        tr("Co&uper"),            this);
    m_actCopy      = new QAction(QIcon::fromTheme("edit-copy"),       tr("&Copier"),            this);
    m_actPaste     = new QAction(QIcon::fromTheme("edit-paste"),      tr("Co&ller"),            this);
    m_actSelectAll = new QAction(QIcon::fromTheme("edit-select-all"), tr("&Tout sélectionner"), this);

    m_actUndo->setShortcut(QKeySequence::Undo);
    m_actRedo->setShortcut(QKeySequence::Redo);
    m_actCut->setShortcut(QKeySequence::Cut);
    m_actCopy->setShortcut(QKeySequence::Copy);
    m_actPaste->setShortcut(QKeySequence::Paste);
    m_actSelectAll->setShortcut(QKeySequence::SelectAll);

    m_actUndo->setEnabled(false);
    m_actRedo->setEnabled(false);
    m_actCut->setEnabled(false);
    m_actCopy->setEnabled(false);

    connect(m_actUndo,      &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->undo(); });
    connect(m_actRedo,      &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->redo(); });
    connect(m_actCut,       &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->cut(); });
    connect(m_actCopy,      &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->copy(); });
    connect(m_actPaste,     &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->paste(); });
    connect(m_actSelectAll, &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->selectAll(); });

    // Format — caractère
    m_actBold          = new QAction(QIcon::fromTheme("format-text-bold"),          tr("&Gras"),          this);
    m_actItalic        = new QAction(QIcon::fromTheme("format-text-italic"),        tr("&Italique"),      this);
    m_actUnderline     = new QAction(QIcon::fromTheme("format-text-underline"),     tr("&Souligné"),      this);
    m_actStrikethrough = new QAction(QIcon::fromTheme("format-text-strikethrough"), tr("Bar&ré"),         this);

    m_actBold->setShortcut(QKeySequence::Bold);
    m_actItalic->setShortcut(QKeySequence::Italic);
    m_actUnderline->setShortcut(QKeySequence::Underline);

    for (auto* a : {m_actBold, m_actItalic, m_actUnderline, m_actStrikethrough})
        a->setCheckable(true);

    connect(m_actBold,          &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->toggleBold(); });
    connect(m_actItalic,        &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->toggleItalic(); });
    connect(m_actUnderline,     &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->toggleUnderline(); });
    connect(m_actStrikethrough, &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->toggleStrikethrough(); });

    // Format — alignement (groupe exclusif)
    m_actAlignLeft    = new QAction(QIcon::fromTheme("format-justify-left"),   tr("Aligner à &gauche"), this);
    m_actAlignCenter  = new QAction(QIcon::fromTheme("format-justify-center"), tr("&Centrer"),          this);
    m_actAlignRight   = new QAction(QIcon::fromTheme("format-justify-right"),  tr("Aligner à d&roite"), this);
    m_actAlignJustify = new QAction(QIcon::fromTheme("format-justify-fill"),   tr("&Justifier"),        this);

    m_actAlignLeft->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_L));
    m_actAlignCenter->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
    m_actAlignRight->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_R));
    m_actAlignJustify->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_J));

    m_alignGroup = new QActionGroup(this);
    for (auto* a : {m_actAlignLeft, m_actAlignCenter, m_actAlignRight, m_actAlignJustify}) {
        a->setCheckable(true);
        m_alignGroup->addAction(a);
    }
    m_actAlignLeft->setChecked(true);

    connect(m_actAlignLeft,    &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->setAlignment(Qt::AlignLeft); });
    connect(m_actAlignCenter,  &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->setAlignment(Qt::AlignHCenter); });
    connect(m_actAlignRight,   &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->setAlignment(Qt::AlignRight); });
    connect(m_actAlignJustify, &QAction::triggered, this, [this]{ if (auto* e = currentEditor()) e->setAlignment(Qt::AlignJustify); });

    // Format — couleur
    m_actTextColor = new QAction(makeColorIcon(m_lastTextColor), tr("Couleur du &texte…"), this);
    m_actBgColor   = new QAction(makeColorIcon(m_lastBgColor),   tr("Couleur de &fond…"),  this);

    connect(m_actTextColor, &QAction::triggered, this, &MainWindow::applyTextColor);
    connect(m_actBgColor,   &QAction::triggered, this, &MainWindow::applyBgColor);

    // Chiffrement de fichiers arbitraires
    m_actEncryptFile = new QAction(QIcon::fromTheme("document-encrypt"),
                                   tr("Chiffrer un fichier…"), this);
    m_actDecryptFile = new QAction(QIcon::fromTheme("document-decrypt"),
                                   tr("Déchiffrer un fichier…"), this);
    connect(m_actEncryptFile, &QAction::triggered, this, &MainWindow::encryptExternalFile);
    connect(m_actDecryptFile, &QAction::triggered, this, &MainWindow::decryptExternalFile);

    // Aide
    m_actAbout = new QAction(QIcon::fromTheme("help-about"), tr("À &propos…"), this);
    connect(m_actAbout, &QAction::triggered, this, &MainWindow::showAbout);
}

// ── menus ─────────────────────────────────────────────────────────────────────

void MainWindow::setupMenus()
{
    auto* file = menuBar()->addMenu(tr("&Fichier"));
    file->addAction(m_actNew);
    file->addAction(m_actOpen);
    file->addSeparator();
    file->addAction(m_actSave);
    file->addAction(m_actSaveAs);
    file->addSeparator();
    file->addAction(m_actEncryptFile);
    file->addAction(m_actDecryptFile);
    file->addSeparator();
    file->addAction(m_actQuit);

    auto* edit = menuBar()->addMenu(tr("&Édition"));
    edit->addAction(m_actUndo);
    edit->addAction(m_actRedo);
    edit->addSeparator();
    edit->addAction(m_actCut);
    edit->addAction(m_actCopy);
    edit->addAction(m_actPaste);
    edit->addAction(m_actSelectAll);

    auto* fmt = menuBar()->addMenu(tr("&Format"));
    fmt->addAction(m_actBold);
    fmt->addAction(m_actItalic);
    fmt->addAction(m_actUnderline);
    fmt->addAction(m_actStrikethrough);
    fmt->addSeparator();
    fmt->addAction(m_actAlignLeft);
    fmt->addAction(m_actAlignCenter);
    fmt->addAction(m_actAlignRight);
    fmt->addAction(m_actAlignJustify);
    fmt->addSeparator();
    fmt->addAction(m_actTextColor);
    fmt->addAction(m_actBgColor);

    auto* help = menuBar()->addMenu(tr("?"));
    help->addAction(m_actAbout);
}

// ── toolbar ───────────────────────────────────────────────────────────────────

void MainWindow::setupToolBar()
{
    auto* tb = addToolBar(tr("Principal"));
    tb->setMovable(false);
    tb->setIconSize(QSize(22, 22));
    tb->setToolButtonStyle(Qt::ToolButtonIconOnly);

    tb->addAction(m_actNew);
    tb->addAction(m_actOpen);
    tb->addAction(m_actSave);
    tb->addAction(m_actSaveAs);
    tb->addSeparator();
    tb->addAction(m_actUndo);
    tb->addAction(m_actRedo);
    tb->addSeparator();
    tb->addAction(m_actCut);
    tb->addAction(m_actCopy);
    tb->addAction(m_actPaste);
    tb->addAction(m_actSelectAll);
    tb->addSeparator();
    tb->addAction(m_actBold);
    tb->addAction(m_actItalic);
    tb->addAction(m_actUnderline);
    tb->addAction(m_actStrikethrough);
    tb->addSeparator();
    tb->addAction(m_actAlignLeft);
    tb->addAction(m_actAlignCenter);
    tb->addAction(m_actAlignRight);
    tb->addAction(m_actAlignJustify);
    tb->addSeparator();
    tb->addAction(m_actTextColor);
    tb->addAction(m_actBgColor);

    // Stocker les boutons et ajouter "Supprimer la couleur" dans un menu flèche
    auto configColorBtn = [this, tb](QAction* act, QWidget*& btnOut,
                                     void (MainWindow::*removeSlot)()) {
        if (auto* btn = qobject_cast<QToolButton*>(tb->widgetForAction(act))) {
            btnOut = btn;
            auto* menu = new QMenu(btn);
            menu->addAction(tr("Supprimer la couleur"), this, removeSlot);
            btn->setMenu(menu);
            btn->setPopupMode(QToolButton::MenuButtonPopup);
        }
    };
    configColorBtn(m_actTextColor, m_textColorBtn, &MainWindow::removeTextColor);
    configColorBtn(m_actBgColor,   m_bgColorBtn,   &MainWindow::removeBgColor);
}

// ── barre police ──────────────────────────────────────────────────────────────

void MainWindow::setupFontBar()
{
    auto* bar = addToolBar(tr("Police"));
    bar->setMovable(false);
    bar->setIconSize(QSize(22, 22));

    m_fontCombo = new FilteredFontComboBox(this);
    m_fontCombo->setMaximumWidth(220);
    m_fontCombo->setToolTip(tr("Police"));
    bar->addWidget(m_fontCombo);

    m_sizeCombo = new QComboBox(this);
    m_sizeCombo->setEditable(true);
    m_sizeCombo->setFixedWidth(64);
    m_sizeCombo->setToolTip(tr("Taille (points)"));
    m_sizeCombo->setValidator(new QIntValidator(1, 512, m_sizeCombo));
    for (int s : {6,7,8,9,10,11,12,14,16,18,20,22,24,26,28,36,48,72})
        m_sizeCombo->addItem(QString::number(s));
    m_sizeCombo->setCurrentText("11");
    bar->addWidget(m_sizeCombo);

    connect(m_fontCombo, &QFontComboBox::currentFontChanged,
            this, &MainWindow::applyFontFamily);
    connect(m_sizeCombo, &QComboBox::currentTextChanged,
            this, &MainWindow::applyFontSize);

    bar->addSeparator();
    auto* pwLabel = new QLabel(tr(" Mot de passe : "), this);
    bar->addWidget(pwLabel);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText(tr("vide = demander à chaque fois"));
    m_passwordEdit->setFixedWidth(180);
    m_passwordEdit->setToolTip(tr("Mot de passe par défaut utilisé sans dialogue de confirmation"));
    bar->addWidget(m_passwordEdit);
}

// ── signaux éditeur ───────────────────────────────────────────────────────────

void MainWindow::connectEditorSignals(CodeEditor* ed)
{
    if (m_connectedEditor) {
        disconnect(m_connectedEditor, &QTextEdit::undoAvailable,
                   m_actUndo, &QAction::setEnabled);
        disconnect(m_connectedEditor, &QTextEdit::redoAvailable,
                   m_actRedo, &QAction::setEnabled);
        disconnect(m_connectedEditor, &QTextEdit::copyAvailable,
                   m_actCut,  &QAction::setEnabled);
        disconnect(m_connectedEditor, &QTextEdit::copyAvailable,
                   m_actCopy, &QAction::setEnabled);
        disconnect(m_connectedEditor, &QTextEdit::currentCharFormatChanged,
                   this, &MainWindow::onCharFormatChanged);
        disconnect(m_connectedEditor, &QTextEdit::cursorPositionChanged,
                   this, nullptr);
        disconnect(m_connectedEditor->document(), &QTextDocument::contentsChanged,
                   this, &MainWindow::updateStatsLabel);
    }

    m_connectedEditor = ed;

    if (ed) {
        connect(ed, &QTextEdit::undoAvailable, m_actUndo, &QAction::setEnabled);
        connect(ed, &QTextEdit::redoAvailable, m_actRedo, &QAction::setEnabled);
        connect(ed, &QTextEdit::copyAvailable, m_actCut,  &QAction::setEnabled);
        connect(ed, &QTextEdit::copyAvailable, m_actCopy, &QAction::setEnabled);
        connect(ed, &QTextEdit::currentCharFormatChanged,
                this, &MainWindow::onCharFormatChanged);
        connect(ed, &QTextEdit::cursorPositionChanged, this, [this, ed]() {
            onCharFormatChanged(ed->currentCharFormat());
            updateAlignmentActions();
        });
        connect(ed->document(), &QTextDocument::contentsChanged,
                this, &MainWindow::updateStatsLabel);

        m_actUndo->setEnabled(ed->document()->isUndoAvailable());
        m_actRedo->setEnabled(ed->document()->isRedoAvailable());
        bool sel = ed->textCursor().hasSelection();
        m_actCut->setEnabled(sel);
        m_actCopy->setEnabled(sel);
        onCharFormatChanged(ed->currentCharFormat());
        updateAlignmentActions();
    } else {
        m_actUndo->setEnabled(false);
        m_actRedo->setEnabled(false);
        m_actCut->setEnabled(false);
        m_actCopy->setEnabled(false);
        for (auto* a : {m_actBold, m_actItalic, m_actUnderline, m_actStrikethrough})
            a->setChecked(false);
        m_actAlignLeft->setChecked(true);
    }
}

void MainWindow::onCharFormatChanged(const QTextCharFormat& fmt)
{
    m_actBold->setChecked(fmt.fontWeight() == QFont::Bold);
    m_actItalic->setChecked(fmt.fontItalic());
    m_actUnderline->setChecked(fmt.fontUnderline());
    m_actStrikethrough->setChecked(fmt.fontStrikeOut());

    // Synchronisation sans déclencher les slots d'application
    {
        QSignalBlocker b1(m_fontCombo), b2(m_sizeCombo);
        m_fontCombo->setCurrentFont(fmt.font());
        // fontPointSize() vaut 0 si la taille est héritée du document — on se
        // rabat alors sur la taille résolue via font().pointSize().
        int pt = qRound(fmt.fontPointSize());
        if (pt <= 0) pt = fmt.font().pointSize();
        if (pt > 0)
            m_sizeCombo->setCurrentText(QString::number(pt));
    }

    // Icônes couleur reflètent la position du curseur / de la sélection
    auto* ed = currentEditor();

    const QBrush fgBrush = fmt.foreground();
    m_lastTextColor = (fgBrush.style() != Qt::NoBrush)
                      ? fgBrush.color()
                      : (ed ? ed->palette().color(QPalette::Text) : QColor(Qt::white));
    m_actTextColor->setIcon(makeColorIcon(m_lastTextColor));

    const QBrush bgBrush = fmt.background();
    m_lastBgColor = (bgBrush.style() != Qt::NoBrush)
                    ? bgBrush.color()
                    : (ed ? ed->palette().color(QPalette::Base) : QColor(Qt::black));
    m_actBgColor->setIcon(makeColorIcon(m_lastBgColor));
}

void MainWindow::applyFontFamily(const QFont& font)
{
    auto* ed = currentEditor();
    if (!ed) return;
    QTextCharFormat fmt;
    fmt.setFontFamilies({font.family()});
    ed->mergeCurrentCharFormat(fmt);
}

void MainWindow::applyFontSize(const QString& sizeStr)
{
    auto* ed = currentEditor();
    if (!ed) return;
    bool ok;
    const int pt = sizeStr.toInt(&ok);
    if (!ok || pt <= 0) return;
    QTextCharFormat fmt;
    fmt.setFontPointSize(pt);
    ed->mergeCurrentCharFormat(fmt);
}

void MainWindow::updateAlignmentActions()
{
    auto* ed = currentEditor();
    if (!ed) return;
    const Qt::Alignment a = ed->alignment() & Qt::AlignHorizontal_Mask;
    m_actAlignLeft->setChecked(a == Qt::AlignLeft || a == Qt::AlignLeading);
    m_actAlignCenter->setChecked(a == Qt::AlignHCenter);
    m_actAlignRight->setChecked(a == Qt::AlignRight || a == Qt::AlignTrailing);
    m_actAlignJustify->setChecked(a == Qt::AlignJustify);
}

void MainWindow::applyTextColor()
{
    if (!currentEditor()) return;
    if (m_textColorPopup) { m_textColorPopup->close(); return; }
    auto* popup = new ColorPickerPopup(this);
    m_textColorPopup = popup;
    connect(popup, &ColorPickerPopup::colorSelected, this, [this](const QColor& color) {
        if (auto* e = currentEditor()) {
            QTextCharFormat fmt;
            fmt.setForeground(color);
            e->mergeCurrentCharFormat(fmt);
        }
    });
    connect(popup, &ColorPickerPopup::addCustomColorRequested, this, [this]() {
        const QColor color = ColorPickerDialog::getColor(m_lastTextColor, this, tr("Couleur du texte"));
        if (color.isValid()) {
            ColorPickerPopup::addCustomColor(color);
            if (m_textColorPopup) m_textColorPopup->refreshCustomColors();
            if (auto* e = currentEditor()) {
                QTextCharFormat fmt;
                fmt.setForeground(color);
                e->mergeCurrentCharFormat(fmt);
            }
        }
    });
    // Différer : le grab souris du bouton toolbar doit être libéré avant que Qt::Popup en prenne un nouveau
    QPointer<ColorPickerPopup> safePopup = popup;
    QWidget* anchor = m_textColorBtn ? m_textColorBtn : this;
    QTimer::singleShot(0, this, [safePopup, anchor]() {
        if (safePopup) safePopup->showBelow(anchor);
    });
}

void MainWindow::applyBgColor()
{
    if (!currentEditor()) return;
    if (m_bgColorPopup) { m_bgColorPopup->close(); return; }
    auto* popup = new ColorPickerPopup(this);
    m_bgColorPopup = popup;
    connect(popup, &ColorPickerPopup::colorSelected, this, [this](const QColor& color) {
        if (auto* e = currentEditor()) {
            QTextCharFormat fmt;
            fmt.setBackground(color);
            e->mergeCurrentCharFormat(fmt);
        }
    });
    connect(popup, &ColorPickerPopup::addCustomColorRequested, this, [this]() {
        const QColor color = ColorPickerDialog::getColor(m_lastBgColor, this, tr("Couleur de fond du texte"));
        if (color.isValid()) {
            ColorPickerPopup::addCustomColor(color);
            if (m_bgColorPopup) m_bgColorPopup->refreshCustomColors();
            if (auto* e = currentEditor()) {
                QTextCharFormat fmt;
                fmt.setBackground(color);
                e->mergeCurrentCharFormat(fmt);
            }
        }
    });
    // Différer : le grab souris du bouton toolbar doit être libéré avant que Qt::Popup en prenne un nouveau
    QPointer<ColorPickerPopup> safePopup = popup;
    QWidget* anchor = m_bgColorBtn ? m_bgColorBtn : this;
    QTimer::singleShot(0, this, [safePopup, anchor]() {
        if (safePopup) safePopup->showBelow(anchor);
    });
}

void MainWindow::removeTextColor()
{
    auto* ed = currentEditor();
    if (!ed) return;
    QTextCharFormat fmt;
    fmt.setForeground(ed->palette().color(QPalette::Text));
    ed->mergeCurrentCharFormat(fmt);
}

void MainWindow::removeBgColor()
{
    auto* ed = currentEditor();
    if (!ed) return;
    QTextCharFormat fmt;
    fmt.setBackground(ed->palette().color(QPalette::Base));
    ed->mergeCurrentCharFormat(fmt);
}

// ── barre de statut ───────────────────────────────────────────────────────────

void MainWindow::updateStatsLabel()
{
    auto* ed = currentEditor();
    if (!ed) { m_statsLabel->clear(); return; }
    const QString text  = ed->toPlainText();
    const int     chars = text.length();
    const int     words = text.isEmpty() ? 0
        : text.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts).size();
    m_statsLabel->setText(tr("%1 mot%2 · %3 caractère%4")
        .arg(words).arg(words > 1 ? "s" : "")
        .arg(chars).arg(chars > 1 ? "s" : ""));
}

// ── helpers ───────────────────────────────────────────────────────────────────

CodeEditor* MainWindow::currentEditor() const
{
    return qobject_cast<CodeEditor*>(m_tabs->currentWidget());
}

CodeEditor* MainWindow::editorAt(int index) const
{
    return qobject_cast<CodeEditor*>(m_tabs->widget(index));
}

void MainWindow::addEditorTab(const QString& title, const QString& path)
{
    auto* editor = new CodeEditor(this);
    if (!path.isEmpty())
        editor->setFilePath(path);

    connect(editor->document(), &QTextDocument::modificationChanged,
            this, &MainWindow::onModificationChanged);

    int idx = m_tabs->addTab(editor, title);
    m_tabs->setCurrentIndex(idx);
    editor->setFocus();
}

void MainWindow::updateTabTitle(int index)
{
    auto* ed = editorAt(index);
    if (!ed) return;
    QString name = ed->filePath().isEmpty()
        ? tr("Sans titre")
        : QFileInfo(ed->filePath()).fileName();
    m_tabs->setTabText(index, ed->isModified() ? name + "*" : name);
}

void MainWindow::updateWindowTitle()
{
    auto* ed = currentEditor();
    if (!ed) { setWindowTitle("CryptoPad"); return; }
    QString path = ed->filePath().isEmpty() ? tr("Sans titre") : ed->filePath();
    setWindowTitle(QString("CryptoPad — %1%2").arg(path).arg(ed->isModified() ? "*" : ""));
}

void MainWindow::doOpen(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, tr("Erreur"),
                              tr("Impossible d'ouvrir : %1").arg(f.errorString()));
        return;
    }
    const QByteArray cipher = f.readAll();

    // Détection anticipée d'un fichier CPDF ouvert depuis l'éditeur par erreur
    if (cipher.size() >= 4 && cipher.startsWith("CPDF")) {
        QMessageBox::information(this, tr("Format CPDF"),
            tr("Ce fichier est au format CPDF (chiffrement de fichiers).\n"
               "Utilisez « Fichier → Déchiffrer un fichier » pour le déchiffrer."));
        return;
    }

    // Applique le contenu déchiffré à un nouvel onglet
    auto applyPlain = [&](const QByteArray& plain, const QString& pw) {
        // Garde contre les données binaires chiffrées dans un .cpad
        if (plain.contains('\0')) {
            QMessageBox::warning(this, tr("Contenu binaire"),
                tr("Le fichier déchiffré contient des données binaires\n"
                   "et ne peut pas être ouvert dans l'éditeur de texte."));
            return;
        }
        const QString content = QString::fromUtf8(plain);
        addEditorTab(QFileInfo(path).fileName(), path);
        auto* ed = currentEditor();
        ed->setSessionPassword(pw);
        if (content.startsWith("<!DOCTYPE") || content.startsWith("<html"))
            ed->setHtml(content);
        else
            ed->setPlainText(content);
        ed->document()->setModified(false);
        updateTabTitle(m_tabs->currentIndex());
        statusBar()->showMessage(tr("Ouvert : %1").arg(path), 4000);
    };

    const QString defPw = m_passwordEdit->text();

    if (!defPw.isEmpty()) {
        try {
            applyPlain(CryptoManager::decrypt(cipher, defPw), defPw);
            return;
        } catch (...) {}   // mot de passe par défaut incorrect → on tombe dans le dialogue
    }

    PasswordDialog dlg(PasswordDialog::Mode::Decrypt, this);
    if (!defPw.isEmpty())
        dlg.setNote(tr("Le mot de passe par défaut est incorrect pour ce fichier."));
    if (dlg.exec() != QDialog::Accepted) return;

    try {
        applyPlain(CryptoManager::decrypt(cipher, dlg.password()), dlg.password());
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Erreur de déchiffrement"),
                              QString::fromUtf8(e.what()));
    }
}

bool MainWindow::doSave(CodeEditor* ed, const QString& path, const QString& password)
{
    try {
        QByteArray plain  = ed->toHtml().toUtf8();
        QByteArray cipher = CryptoManager::encrypt(plain, password);

        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(this, tr("Erreur"),
                                  tr("Impossible d'écrire : %1").arg(f.errorString()));
            return false;
        }
        f.write(cipher);
        ed->setFilePath(path);
        ed->setSessionPassword(password);
        ed->document()->setModified(false);
        updateTabTitle(m_tabs->currentIndex());
        updateWindowTitle();
        statusBar()->showMessage(
            tr("Enregistré (%1) : %2").arg(CryptoManager::algoName()).arg(path), 5000);
        return true;
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Erreur de chiffrement"),
                              QString::fromUtf8(e.what()));
        return false;
    }
}

bool MainWindow::maybeSave(int index)
{
    auto* ed = editorAt(index);
    if (!ed || !ed->isModified()) return true;

    QString name = ed->filePath().isEmpty()
        ? tr("Sans titre")
        : QFileInfo(ed->filePath()).fileName();

    auto btn = QMessageBox::question(
        this, tr("Enregistrer ?"),
        tr("'%1' a été modifié. Enregistrer les modifications ?").arg(name),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);

    if (btn == QMessageBox::Save) {
        m_tabs->setCurrentIndex(index);
        saveFile();
        return !ed->isModified();
    }
    return btn != QMessageBox::Cancel;
}

// ── slots ─────────────────────────────────────────────────────────────────────

void MainWindow::newFile()
{
    addEditorTab(tr("Sans titre"));
}

void MainWindow::openFile()
{
    QString path = QFileDialog::getOpenFileName(
        this, tr("Ouvrir un fichier chiffré"), {},
        tr("Fichiers CryptoPad (*.cpad);;Tous les fichiers (*)"));
    if (path.isEmpty()) return;
    doOpen(path);
}

void MainWindow::saveFile()
{
    auto* ed = currentEditor();
    if (!ed) return;

    if (ed->filePath().isEmpty()) { saveFileAs(); return; }

    if (!ed->sessionPassword().isEmpty()) {
        doSave(ed, ed->filePath(), ed->sessionPassword());
        return;
    }

    const QString defPw = m_passwordEdit->text();
    if (!defPw.isEmpty()) {
        doSave(ed, ed->filePath(), defPw);
        return;
    }

    PasswordDialog dlg(PasswordDialog::Mode::Encrypt, this);
    if (dlg.exec() != QDialog::Accepted) return;
    doSave(ed, ed->filePath(), dlg.password());
}

void MainWindow::saveFileAs()
{
    auto* ed = currentEditor();
    if (!ed) return;

    QString defaultPath = ed->filePath().isEmpty()
        ? tr("sans_titre.cpad")
        : (ed->filePath().endsWith(".cpad") ? ed->filePath()
                                            : ed->filePath() + ".cpad");

    QString path = QFileDialog::getSaveFileName(
        this, tr("Enregistrer sous"), defaultPath,
        tr("Fichiers CryptoPad (*.cpad);;Tous les fichiers (*)"));
    if (path.isEmpty()) return;

    const QString defPw = m_passwordEdit->text();
    if (!defPw.isEmpty()) {
        doSave(ed, path, defPw);
        return;
    }

    PasswordDialog dlg(PasswordDialog::Mode::Encrypt, this);
    if (dlg.exec() != QDialog::Accepted) return;
    doSave(ed, path, dlg.password());
}

void MainWindow::closeTab(int index)
{
    if (!maybeSave(index)) return;
    m_tabs->removeTab(index);
    if (m_tabs->count() == 0)
        newFile();
}

void MainWindow::onTabChanged(int /*index*/)
{
    connectEditorSignals(currentEditor());
    updateWindowTitle();
    updateStatsLabel();
}

void MainWindow::onModificationChanged(bool /*modified*/)
{
    updateTabTitle(m_tabs->currentIndex());
    updateWindowTitle();
}


void MainWindow::closeEvent(QCloseEvent* event)
{
    for (int i = 0; i < m_tabs->count(); ++i) {
        if (!maybeSave(i)) { event->ignore(); return; }
    }
    event->accept();
}

// ── chiffrement / déchiffrement de fichiers arbitraires ───────────────────────

void MainWindow::encryptExternalFile()
{
    const QString inPath = QFileDialog::getOpenFileName(
        this, tr("Fichier à chiffrer"), {}, tr("Tous les fichiers (*)"));
    if (inPath.isEmpty()) return;

    const QString outPath = QFileDialog::getSaveFileName(
        this, tr("Enregistrer le fichier chiffré"), inPath + ".cpdf",
        tr("Fichiers chiffrés (*.cpdf);;Tous les fichiers (*)"));
    if (outPath.isEmpty()) return;

    QString password = m_passwordEdit->text();
    if (password.isEmpty()) {
        PasswordDialog dlg(PasswordDialog::Mode::Encrypt, this);
        if (dlg.exec() != QDialog::Accepted) return;
        password = dlg.password();
    }

    auto* progress = new QProgressDialog(
        tr("Chiffrement en cours…"), tr("Annuler"), 0, 100, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->setValue(0);

    const auto cancelled = std::make_shared<std::atomic<bool>>(false);
    connect(progress, &QProgressDialog::canceled, this, [cancelled] {
        cancelled->store(true);
    });

    auto* watcher = new QFutureWatcher<QString>(this);
    QPointer<QProgressDialog> safeProgress = progress;
    connect(watcher, &QFutureWatcher<QString>::finished, this,
            [this, watcher, safeProgress, outPath] {
        if (safeProgress) safeProgress->deleteLater();
        const QString err = watcher->result();
        watcher->deleteLater();
        if (err.isEmpty())
            statusBar()->showMessage(tr("Chiffré : %1").arg(outPath), 5000);
        else
            QMessageBox::critical(this, tr("Erreur de chiffrement"), err);
    });

    watcher->setFuture(QtConcurrent::run(
        [inPath, outPath, password, cancelled, safeProgress]() -> QString {
            try {
                FileEncryptor::encryptFile(inPath, outPath, password, *cancelled,
                    [safeProgress](int p) {
                        QMetaObject::invokeMethod(qApp, [safeProgress, p] {
                            if (safeProgress) safeProgress->setValue(p);
                        }, Qt::QueuedConnection);
                    });
                return {};
            } catch (const std::exception& e) {
                return QString::fromUtf8(e.what());
            }
        }));
}

void MainWindow::decryptExternalFile()
{
    const QString inPath = QFileDialog::getOpenFileName(
        this, tr("Fichier à déchiffrer"), {},
        tr("Fichiers chiffrés (*.cpdf);;Tous les fichiers (*)"));
    if (inPath.isEmpty()) return;

    QString suggested = inPath;
    if (suggested.endsWith(".cpdf", Qt::CaseInsensitive))
        suggested.chop(5);
    const QString outPath = QFileDialog::getSaveFileName(
        this, tr("Enregistrer le fichier déchiffré"), suggested,
        tr("Tous les fichiers (*)"));
    if (outPath.isEmpty()) return;

    const QString defPw = m_passwordEdit->text();
    if (!defPw.isEmpty()) {
        launchFileDecrypt(inPath, outPath, defPw, /*isDefault=*/true);
    } else {
        PasswordDialog dlg(PasswordDialog::Mode::Decrypt, this);
        if (dlg.exec() != QDialog::Accepted) return;
        launchFileDecrypt(inPath, outPath, dlg.password(), /*isDefault=*/false);
    }
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, tr("À propos de CryptoPad"),
        tr("<h2>CryptoPad %1</h2>"
           "<p>Éditeur de texte riche avec chiffrement triple couche intégré.</p>"
           "<hr>"
           "<p><b>Documents éditeur (.cpad) — propre à CryptoPad</b><br>"
           "AES-256/SIV → Serpent-256/GCM → ChaCha20/Poly1305<br>"
           "Séparation KEK/DEK · Argon2id (64 Mio · 3 passes · par. 4)<br>"
           "Nonces aléatoires · HMAC-SHA256 global<br>"
           "<i>Non lisible par Arsenic (magic <code>CPAD</code>, contenu HTML).</i></p>"
           "<p><b>Chiffrement de fichiers (.cpdf) — interopérable avec Arsenic</b><br>"
           "Format binaire octet-pour-octet identique à Arsenic.<br>"
           "Découpage en blocs de 1 Mio · séparation KEK/DEK · HMAC-SHA256 global.<br>"
           "<i>Un fichier .cpdf chiffré par CryptoPad peut être déchiffré par Arsenic,<br>"
           "et vice versa.</i></p>"
           "<hr>"
           "<p>Licence : GNU GPL v3 — "
           "Cryptographie : <a href='https://botan.randombit.net'>Botan 3</a></p>")
        .arg(QLatin1String(APP_VERSION)));
}

void MainWindow::launchFileDecrypt(const QString& inPath, const QString& outPath,
                                    const QString& password, bool isDefault)
{
    auto* progress = new QProgressDialog(
        tr("Déchiffrement en cours…"), tr("Annuler"), 0, 100, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(0);
    progress->setValue(0);

    const auto cancelled = std::make_shared<std::atomic<bool>>(false);
    connect(progress, &QProgressDialog::canceled, this, [cancelled] {
        cancelled->store(true);
    });

    auto* watcher = new QFutureWatcher<QString>(this);
    QPointer<QProgressDialog> safeProgress = progress;
    connect(watcher, &QFutureWatcher<QString>::finished, this,
            [this, watcher, safeProgress, inPath, outPath, isDefault] {
        if (safeProgress) safeProgress->deleteLater();
        const QString err = watcher->result();
        watcher->deleteLater();

        if (err.isEmpty()) {
            statusBar()->showMessage(tr("Déchiffré : %1").arg(outPath), 5000);
        } else if (isDefault && err.startsWith("Mot de passe incorrect")) {
            // Le mot de passe par défaut est mauvais : proposer la saisie manuelle
            PasswordDialog dlg(PasswordDialog::Mode::Decrypt, this);
            dlg.setNote(tr("Le mot de passe par défaut est incorrect pour ce fichier."));
            if (dlg.exec() != QDialog::Accepted) return;
            launchFileDecrypt(inPath, outPath, dlg.password(), /*isDefault=*/false);
        } else {
            QMessageBox::critical(this, tr("Erreur de déchiffrement"), err);
        }
    });

    watcher->setFuture(QtConcurrent::run(
        [inPath, outPath, password, cancelled, safeProgress]() -> QString {
            try {
                FileEncryptor::decryptFile(inPath, outPath, password, *cancelled,
                    [safeProgress](int p) {
                        QMetaObject::invokeMethod(qApp, [safeProgress, p] {
                            if (safeProgress) safeProgress->setValue(p);
                        }, Qt::QueuedConnection);
                    });
                return {};
            } catch (const std::exception& e) {
                return QString::fromUtf8(e.what());
            }
        }));
}
