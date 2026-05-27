#include "syntaxhighlighter.h"
#include <QFileInfo>
#include <array>

Language detectLanguage(const QString& filename)
{
    using enum Language;
    const QString ext = QFileInfo(filename).suffix().toLower();
    if (ext == "cpp" || ext == "cxx" || ext == "cc" || ext == "c" ||
        ext == "hpp" || ext == "hxx" || ext == "h")
        return Cpp;
    if (ext == "py")
        return Python;
    if (ext == "sh" || ext == "bash" || ext == "zsh" || ext == "fish")
        return Bash;
    return None;
}

// ── helpers ──────────────────────────────────────────────────────────────────

static QTextCharFormat mkFmt(const QColor& color, bool bold = false, bool italic = false)
{
    QTextCharFormat f;
    f.setForeground(color);
    if (bold)   f.setFontWeight(QFont::Bold);
    if (italic) f.setFontItalic(true);
    return f;
}

// ── ctor ─────────────────────────────────────────────────────────────────────

SyntaxHighlighter::SyntaxHighlighter(QTextDocument* parent)
    : QSyntaxHighlighter(parent)
{
    m_multilineCommentFmt = mkFmt(QColor(0x80, 0x80, 0x80), false, true);
    m_commentStart = QRegularExpression(R"(/\*)");
    m_commentEnd   = QRegularExpression(R"(\*/)");
}

void SyntaxHighlighter::setLanguage(Language lang)
{
    using enum Language;
    m_lang = lang;
    m_rules.clear();
    switch (lang) {
    case Cpp:    buildCppRules();    break;
    case Python: buildPythonRules(); break;
    case Bash:   buildBashRules();   break;
    default: break;
    }
    rehighlight();
}

// ── C++ rules ────────────────────────────────────────────────────────────────

void SyntaxHighlighter::buildCppRules()
{
    auto kwFmt      = mkFmt(QColor(0x56, 0x9C, 0xD6), true);
    auto typeFmt    = mkFmt(QColor(0x4E, 0xC9, 0xB0), true);
    auto strFmt     = mkFmt(QColor(0xCE, 0x91, 0x78));
    auto numFmt     = mkFmt(QColor(0xB5, 0xCE, 0xA8));
    auto commentFmt = mkFmt(QColor(0x6A, 0x99, 0x55), false, true);
    auto preprocFmt = mkFmt(QColor(0x9B, 0x9B, 0x6A));

    static constexpr auto kw = std::to_array<const char*>({
        "alignas","alignof","and","and_eq","asm","auto","bitand","bitor","bool",
        "break","case","catch","char","char8_t","char16_t","char32_t","class",
        "compl","concept","const","consteval","constexpr","constinit","const_cast",
        "continue","co_await","co_return","co_yield","decltype","default","delete",
        "do","double","dynamic_cast","else","enum","explicit","export","extern",
        "false","float","for","friend","goto","if","inline","int","long","mutable",
        "namespace","new","noexcept","not","not_eq","nullptr","operator","or","or_eq",
        "private","protected","public","register","reinterpret_cast","requires",
        "return","short","signed","sizeof","static","static_assert","static_cast",
        "struct","switch","template","this","thread_local","throw","true","try",
        "typedef","typeid","typename","union","unsigned","using","virtual","void",
        "volatile","wchar_t","while","xor","xor_eq",
    });
    for (const auto* k : kw)
        m_rules.push_back({QRegularExpression(QStringLiteral("\\b") + QLatin1String(k) + QStringLiteral("\\b")), kwFmt});

    // Types from std
    m_rules.push_back({QRegularExpression(R"(\bstd::\w+)"), typeFmt});
    // Preprocessor
    m_rules.push_back({QRegularExpression(R"(^\s*#\s*\w+)"), preprocFmt});
    // String literals (raw strings R"(...)", double-quoted, single-quoted)
    m_rules.push_back({QRegularExpression(R"X(R"[^(]*\(.*?\)"[^)]*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')X"), strFmt});
    // Numbers
    m_rules.push_back({QRegularExpression(R"(\b(0x[\da-fA-F]+|\d+\.?\d*([eE][+-]?\d+)?[uUlLfF]*)\b)"), numFmt});
    // Single-line comment
    m_rules.push_back({QRegularExpression(R"(//[^\n]*)"), commentFmt});
}

// ── Python rules ─────────────────────────────────────────────────────────────

void SyntaxHighlighter::buildPythonRules()
{
    auto kwFmt   = mkFmt(QColor(0x56, 0x9C, 0xD6), true);
    auto builtFmt= mkFmt(QColor(0xDC, 0xDC, 0xAA));
    auto strFmt  = mkFmt(QColor(0xCE, 0x91, 0x78));
    auto numFmt  = mkFmt(QColor(0xB5, 0xCE, 0xA8));
    auto cmtFmt  = mkFmt(QColor(0x6A, 0x99, 0x55), false, true);
    auto selfFmt = mkFmt(QColor(0x9C, 0xDC, 0xFE));
    auto decFmt  = mkFmt(QColor(0xDD, 0xDD, 0x00));

    static constexpr auto kw = std::to_array<const char*>({
        "False","None","True","and","as","assert","async","await","break","class",
        "continue","def","del","elif","else","except","finally","for","from",
        "global","if","import","in","is","lambda","nonlocal","not","or","pass",
        "raise","return","try","while","with","yield",
    });
    for (const auto* k : kw)
        m_rules.push_back({QRegularExpression(QStringLiteral("\\b") + QLatin1String(k) + QStringLiteral("\\b")), kwFmt});

    static constexpr auto builtins = std::to_array<const char*>({
        "abs","all","any","bin","bool","bytes","callable","chr","dict","dir",
        "divmod","enumerate","eval","exec","filter","float","format","frozenset",
        "getattr","globals","hasattr","hash","help","hex","id","input","int",
        "isinstance","issubclass","iter","len","list","locals","map","max","min",
        "next","object","oct","open","ord","pow","print","property","range",
        "repr","reversed","round","set","setattr","slice","sorted","staticmethod",
        "str","sum","super","tuple","type","vars","zip",
    });
    for (const auto* b : builtins)
        m_rules.push_back({QRegularExpression(QStringLiteral("\\b") + QLatin1String(b) + QStringLiteral("\\b")), builtFmt});

    // self / cls
    m_rules.push_back({QRegularExpression(R"(\b(self|cls)\b)"), selfFmt});
    // Decorators
    m_rules.push_back({QRegularExpression(R"(@\w+)"), decFmt});
    // Triple-quoted strings (single-line portion; full multi-line needs state)
    m_rules.push_back({QRegularExpression(R"((\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'))"), strFmt});
    // Normal strings
    m_rules.push_back({QRegularExpression(R"((f|r|b)?\"(?:[^\"\\]|\\.)*\")"), strFmt});
    m_rules.push_back({QRegularExpression(R"((f|r|b)?'(?:[^'\\]|\\.)*')"), strFmt});
    // Numbers
    m_rules.push_back({QRegularExpression(R"(\b\d+\.?\d*([eE][+-]?\d+)?\b)"), numFmt});
    // Comment
    m_rules.push_back({QRegularExpression(R"(#[^\n]*)"), cmtFmt});
}

// ── Bash rules ───────────────────────────────────────────────────────────────

void SyntaxHighlighter::buildBashRules()
{
    auto kwFmt   = mkFmt(QColor(0x56, 0x9C, 0xD6), true);
    auto varFmt  = mkFmt(QColor(0x9C, 0xDC, 0xFE));
    auto strFmt  = mkFmt(QColor(0xCE, 0x91, 0x78));
    auto cmtFmt  = mkFmt(QColor(0x6A, 0x99, 0x55), false, true);
    auto numFmt  = mkFmt(QColor(0xB5, 0xCE, 0xA8));
    auto builtFmt= mkFmt(QColor(0xDC, 0xDC, 0xAA));

    static constexpr auto kw = std::to_array<const char*>({
        "if","then","else","elif","fi","for","while","until","do","done",
        "case","esac","in","function","return","local","export","readonly",
        "declare","typeset","unset","shift","break","continue","exit","trap",
        "source","select","time","coproc",
    });
    for (const auto* k : kw)
        m_rules.push_back({QRegularExpression(QStringLiteral("\\b") + QLatin1String(k) + QStringLiteral("\\b")), kwFmt});

    static constexpr auto builtins = std::to_array<const char*>({
        "echo","printf","read","cd","pwd","ls","cp","mv","rm","mkdir","rmdir",
        "touch","cat","grep","sed","awk","find","sort","uniq","wc","cut","tr",
        "head","tail","test","\\[","true","false","eval","exec","alias","unalias",
        "jobs","fg","bg","kill","wait","sleep","date","basename","dirname",
    });
    for (const auto* b : builtins)
        m_rules.push_back({QRegularExpression(QStringLiteral("\\b") + QLatin1String(b) + QStringLiteral("\\b")), builtFmt});

    // Variables
    m_rules.push_back({QRegularExpression(R"(\$\{?[\w@#\*\?\-\$\!0-9]+\}?)"), varFmt});
    // Shebang
    m_rules.push_back({QRegularExpression(R"(^#!)"), mkFmt(QColor(0xFF, 0xC0, 0x66), true)});
    // Double-quoted strings
    m_rules.push_back({QRegularExpression(R"("(?:[^"\\]|\\.)*")"), strFmt});
    // Single-quoted strings
    m_rules.push_back({QRegularExpression(R"('[^']*')"), strFmt});
    // Numbers
    m_rules.push_back({QRegularExpression(R"(\b\d+\b)"), numFmt});
    // Comment
    m_rules.push_back({QRegularExpression(R"((?<!#)#[^\n]*)"), cmtFmt});
}

// ── highlightBlock ───────────────────────────────────────────────────────────

void SyntaxHighlighter::highlightBlock(const QString& text)
{
    for (const auto& rule : m_rules) {
        auto it = rule.pattern.globalMatch(text);
        while (it.hasNext()) {
            auto m = it.next();
            setFormat(static_cast<int>(m.capturedStart()),
                      static_cast<int>(m.capturedLength()),
                      rule.format);
        }
    }

    // Multi-line C++ block comments
    using enum Language;
    if (m_lang == Cpp) {
        setCurrentBlockState(0);
        int start = 0;
        if (previousBlockState() != 1)
            start = static_cast<int>(m_commentStart.match(text).capturedStart());

        while (start >= 0) {
            auto endMatch = m_commentEnd.match(text, start);
            int end = static_cast<int>(endMatch.capturedStart());
            int len;
            if (end == -1) {
                setCurrentBlockState(1);
                len = text.length() - start;
            } else {
                len = end - start + static_cast<int>(endMatch.capturedLength());
            }
            setFormat(start, len, m_multilineCommentFmt);
            start = static_cast<int>(
                m_commentStart.match(text, start + len).capturedStart());
        }
    }
}
