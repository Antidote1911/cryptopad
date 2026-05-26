#pragma once
#include <QFrame>
#include <QList>
#include <QColor>
#include <array>

class ColorPickerPopup : public QFrame {
    Q_OBJECT
public:
    explicit ColorPickerPopup(QWidget* parent = nullptr);
    void showBelow(QWidget* anchor);
    void refreshCustomColors();

    // Gestion des couleurs personnalisées (stockées en QSettings)
    static void          addCustomColor(const QColor& c);
    static void          removeCustomColor(int index);
    static QList<QColor> customColors();

signals:
    void colorSelected(const QColor& color);
    void addCustomColorRequested();   // l'appelant ouvre QColorDialog puis appelle addCustomColor

protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void leaveEvent(QEvent*) override;
    void contextMenuEvent(QContextMenuEvent*) override;
    void showEvent(QShowEvent*) override;
    void hideEvent(QHideEvent*) override;
    bool eventFilter(QObject*, QEvent*) override;

private:
    static constexpr int COLS       = 8;
    static constexpr int ROWS       = 4;
    static constexpr int CELL       = 24;
    static constexpr int GAP        = 3;
    static constexpr int MARGIN     = 6;
    static constexpr int MAX_CUSTOM = 8;
    static constexpr int SEP_H      = 20;   // hauteur zone séparateur + label

    QRect presetRect(int i) const;
    QRect customRect(int i) const;   // i = 0..MAX_CUSTOM-1 (couleur ou bouton +)
    QRect separatorArea() const;

    int  presetAt(const QPoint& p) const;
    int  customAt(const QPoint& p) const;   // -1 = rien, 0..n-1 = couleur, n = bouton +
    void drawCell(QPainter& p, const QRect& r, const QColor& color, bool hovered) const;

    int           m_hoverPreset{-1};
    int           m_hoverCustom{-1};
    QList<QColor> m_custom;
    QWidget*      m_anchor{nullptr};

    static const std::array<QRgb, COLS * ROWS> s_palette;
};
