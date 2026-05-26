#pragma once
#include <QMainWindow>
#include <QPointer>
#include <QString>
#include <QColor>
#include <QTextCharFormat>

class QTabWidget;
class QAction;
class QActionGroup;
class QLabel;
class QLineEdit;
class FilteredFontComboBox;
class QComboBox;
class CodeEditor;
class ColorPickerPopup;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void newFile();
    void openFile();
    void saveFile();
    void saveFileAs();
    void encryptExternalFile();
    void decryptExternalFile();
    void closeTab(int index);
    void onTabChanged(int index);
    void onModificationChanged(bool modified);
    void onCharFormatChanged(const QTextCharFormat& fmt);
    void updateAlignmentActions();
    void applyTextColor();
    void applyBgColor();
    void removeTextColor();
    void removeBgColor();
    void showAbout();

private:
    CodeEditor* currentEditor() const;
    CodeEditor* editorAt(int index) const;
    bool        maybeSave(int index);
    void        addEditorTab(const QString& title, const QString& path = {});
    void        doOpen(const QString& path);
    bool        doSave(CodeEditor* ed, const QString& path, const QString& password);
    void        launchFileDecrypt(const QString& inPath, const QString& outPath,
                                  const QString& password, bool isDefault);
    void        updateTabTitle(int index);
    void        updateWindowTitle();
    void        updateStatsLabel();
    void        applyFontFamily(const QFont& font);
    void        applyFontSize(const QString& sizeStr);
    void        connectEditorSignals(CodeEditor* ed);
    void        setupActions();
    void        setupMenus();
    void        setupToolBar();
    void        setupFontBar();
    static QIcon makeColorIcon(const QColor& color);

    QTabWidget*          m_tabs{nullptr};
    QPointer<CodeEditor> m_connectedEditor;
    QLabel*              m_statsLabel{nullptr};

    // Fichier
    QAction* m_actNew{nullptr};
    QAction* m_actEncryptFile{nullptr};
    QAction* m_actDecryptFile{nullptr};
    QAction* m_actOpen{nullptr};
    QAction* m_actSave{nullptr};
    QAction* m_actSaveAs{nullptr};
    QAction* m_actQuit{nullptr};

    // Édition
    QAction* m_actUndo{nullptr};
    QAction* m_actRedo{nullptr};
    QAction* m_actCut{nullptr};
    QAction* m_actCopy{nullptr};
    QAction* m_actPaste{nullptr};
    QAction* m_actSelectAll{nullptr};

    // Format — caractère
    QAction* m_actBold{nullptr};
    QAction* m_actItalic{nullptr};
    QAction* m_actUnderline{nullptr};
    QAction* m_actStrikethrough{nullptr};

    // Format — alignement
    QAction*      m_actAlignLeft{nullptr};
    QAction*      m_actAlignCenter{nullptr};
    QAction*      m_actAlignRight{nullptr};
    QAction*      m_actAlignJustify{nullptr};
    QActionGroup* m_alignGroup{nullptr};

    // Format — couleur
    QAction* m_actTextColor{nullptr};
    QAction* m_actBgColor{nullptr};
    QWidget* m_textColorBtn{nullptr};
    QWidget* m_bgColorBtn{nullptr};
    QColor   m_lastTextColor{Qt::white};
    QColor   m_lastBgColor{QColor(0xFF, 0xFF, 0x00)};   // jaune fluo
    QPointer<ColorPickerPopup> m_textColorPopup;
    QPointer<ColorPickerPopup> m_bgColorPopup;

    // Police
    FilteredFontComboBox* m_fontCombo{nullptr};
    QComboBox*            m_sizeCombo{nullptr};

    // Mot de passe par défaut
    QLineEdit*            m_passwordEdit{nullptr};

    // Aide
    QAction* m_actAbout{nullptr};

};
