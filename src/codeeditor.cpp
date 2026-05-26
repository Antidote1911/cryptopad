#include "codeeditor.h"
#include "syntaxhighlighter.h"

#include <QPainter>
#include <QScrollBar>
#include <QFileInfo>
#include <QAbstractTextDocumentLayout>
#include <QTextBlock>

CodeEditor::CodeEditor(QWidget* parent)
    : QTextEdit(parent)
{
    m_lineNumberArea = new LineNumberArea(this);
    m_highlighter    = new SyntaxHighlighter(document());

    connect(document(), &QTextDocument::blockCountChanged,
            this, &CodeEditor::updateLineNumberAreaWidth);
    // Repeindre la gouttière lors du défilement ou d'un changement de disposition.
    connect(verticalScrollBar(), &QScrollBar::valueChanged,
            this, [this](int) { m_lineNumberArea->update(); });
    connect(document()->documentLayout(), &QAbstractTextDocumentLayout::update,
            this, [this](const QRectF&) { m_lineNumberArea->update(); });

    updateLineNumberAreaWidth();

    QFont font("Monospace");
    font.setStyleHint(QFont::Monospace);
    font.setFixedPitch(true);
    font.setPointSize(11);
    setFont(font);

    QFontMetrics fm(font);
    setTabStopDistance(4 * fm.horizontalAdvance(' '));
}

// ── gouttière numéros de ligne ────────────────────────────────────────────────

int CodeEditor::lineNumberAreaWidth() const
{
    int digits = 1;
    int max    = qMax(1, document()->blockCount());
    while (max >= 10) { max /= 10; ++digits; }
    return 6 + fontMetrics().horizontalAdvance('9') * digits;
}

void CodeEditor::updateLineNumberAreaWidth()
{
    setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
    m_lineNumberArea->update();
}

void CodeEditor::resizeEvent(QResizeEvent* e)
{
    QTextEdit::resizeEvent(e);
    QRect cr = contentsRect();
    m_lineNumberArea->setGeometry(cr.left(), cr.top(), lineNumberAreaWidth(), cr.height());
}

void CodeEditor::lineNumberAreaPaintEvent(QPaintEvent* event)
{
    QPainter painter(m_lineNumberArea);
    painter.fillRect(event->rect(), QColor(0x2B, 0x2B, 0x2B));
    painter.setFont(font());
    painter.setPen(QColor(0x85, 0x85, 0x85));

    const int lh = fontMetrics().height();
    const int w  = m_lineNumberArea->width() - 3;

    // cursorRect() retourne les coordonnées dans le viewport — pas besoin
    // de convertir manuellement l'offset de défilement.
    QTextBlock block = document()->begin();
    int num = 1;
    while (block.isValid()) {
        int y = cursorRect(QTextCursor(block)).top();
        if (y > event->rect().bottom()) break;
        if (y + lh >= event->rect().top())
            painter.drawText(0, y, w, lh, Qt::AlignRight, QString::number(num));
        block = block.next();
        ++num;
    }
}

// ── fichier / état ────────────────────────────────────────────────────────────

void CodeEditor::setFilePath(const QString& path)
{
    m_filePath = path;
    m_highlighter->setLanguage(detectLanguage(path));
}

bool CodeEditor::isModified() const
{
    return document()->isModified();
}

// ── mise en forme du caractère ────────────────────────────────────────────────

void CodeEditor::toggleBold()
{
    QTextCharFormat fmt;
    fmt.setFontWeight(currentCharFormat().fontWeight() == QFont::Bold
                      ? QFont::Normal : QFont::Bold);
    mergeCurrentCharFormat(fmt);
}

void CodeEditor::toggleItalic()
{
    QTextCharFormat fmt;
    fmt.setFontItalic(!currentCharFormat().fontItalic());
    mergeCurrentCharFormat(fmt);
}

void CodeEditor::toggleUnderline()
{
    QTextCharFormat fmt;
    fmt.setFontUnderline(!currentCharFormat().fontUnderline());
    mergeCurrentCharFormat(fmt);
}

void CodeEditor::toggleStrikethrough()
{
    QTextCharFormat fmt;
    fmt.setFontStrikeOut(!currentCharFormat().fontStrikeOut());
    mergeCurrentCharFormat(fmt);
}
