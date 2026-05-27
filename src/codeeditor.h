#pragma once
#include <QTextEdit>
#include <QString>

class QPaintEvent;
class QResizeEvent;
class SyntaxHighlighter;

class CodeEditor : public QTextEdit {
    Q_OBJECT
public:
    explicit CodeEditor(QWidget* parent = nullptr);

    void lineNumberAreaPaintEvent(QPaintEvent* event);
    int  lineNumberAreaWidth() const;

    [[nodiscard]] QString filePath() const        { return m_filePath; }
    void                  setFilePath(const QString& path);
    [[nodiscard]] bool    isModified() const;

    [[nodiscard]] QString sessionPassword() const             { return m_sessionPassword; }
    void                  setSessionPassword(const QString& p){ m_sessionPassword = p; }

    void toggleBold();
    void toggleItalic();
    void toggleUnderline();
    void toggleStrikethrough();

protected:
    void resizeEvent(QResizeEvent* event) override;

private slots:
    void updateLineNumberAreaWidth();

private:
    QWidget*           m_lineNumberArea;
    SyntaxHighlighter* m_highlighter;
    QString            m_filePath;
    QString            m_sessionPassword;
};

class LineNumberArea : public QWidget {
public:
    explicit LineNumberArea(CodeEditor* editor) : QWidget(editor), m_editor(editor) {}
    QSize sizeHint() const override { return {m_editor->lineNumberAreaWidth(), 0}; }

protected:
    void paintEvent(QPaintEvent* e) override { m_editor->lineNumberAreaPaintEvent(e); }

private:
    CodeEditor* m_editor;
};
