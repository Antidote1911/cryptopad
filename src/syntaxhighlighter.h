#pragma once
#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <QRegularExpression>
#include <vector>

enum class Language { None, Cpp, Python, Bash };

Language detectLanguage(const QString& filename);

class SyntaxHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    explicit SyntaxHighlighter(QTextDocument* parent = nullptr);
    void setLanguage(Language lang);

protected:
    void highlightBlock(const QString& text) override;

private:
    struct Rule {
        QRegularExpression pattern;
        QTextCharFormat    format;
    };

    void buildCppRules();
    void buildPythonRules();
    void buildBashRules();

    std::vector<Rule> m_rules;
    Language          m_lang{Language::None};

    // Multi-line comment state for C++
    QTextCharFormat m_multilineCommentFmt;
    QRegularExpression m_commentStart;
    QRegularExpression m_commentEnd;
};
