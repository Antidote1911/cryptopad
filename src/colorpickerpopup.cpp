#include "colorpickerpopup.h"

#include <QPainter>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QShowEvent>
#include <QHideEvent>
#include <QScreen>
#include <QApplication>
#include <QSettings>

// Palette compacte 8 × 4 :
//   ligne 0 — neutres       ligne 1 — foncés
//   ligne 2 — vifs          ligne 3 — clairs
const std::array<QRgb, ColorPickerPopup::COLS * ColorPickerPopup::ROWS>
ColorPickerPopup::s_palette = {{
    0x000000, 0x2d2d2d, 0x555555, 0x808080, 0xaaaaaa, 0xcccccc, 0xe8e8e8, 0xffffff,
    0x7f1d1d, 0x7c2d12, 0x3f6212, 0x14532d, 0x0c4a6e, 0x1e3a8a, 0x4c1d95, 0x831843,
    0xef4444, 0xf97316, 0xeab308, 0x22c55e, 0x0ea5e9, 0x3b82f6, 0x8b5cf6, 0xec4899,
    0xfecaca, 0xfed7aa, 0xfef08a, 0xbbf7d0, 0xbae6fd, 0xbfdbfe, 0xddd6fe, 0xfbcfe8,
}};

// ── QSettings ────────────────────────────────────────────────────────────────

QList<QColor> ColorPickerPopup::customColors()
{
    QSettings s("CryptoPad", "CryptoPad");
    QList<QColor> list;
    const int n = s.beginReadArray("ui/customColors");
    for (int i = 0; i < n; ++i) {
        s.setArrayIndex(i);
        list << QColor::fromRgba(s.value("rgba").toUInt());
    }
    s.endArray();
    return list;
}

static void saveCustomColors(const QList<QColor>& list)
{
    QSettings s("CryptoPad", "CryptoPad");
    s.remove("ui/customColors");   // supprime toutes les entrées obsolètes
    s.beginWriteArray("ui/customColors", list.size());
    for (int i = 0; i < list.size(); ++i) {
        s.setArrayIndex(i);
        s.setValue("rgba", list[i].rgba());
    }
    s.endArray();
}

void ColorPickerPopup::addCustomColor(const QColor& c)
{
    QList<QColor> list = customColors();
    if (list.size() < MAX_CUSTOM && !list.contains(c))
        list.prepend(c);   // les plus récentes en premier
    saveCustomColors(list);
}

void ColorPickerPopup::removeCustomColor(int index)
{
    QList<QColor> list = customColors();
    if (index >= 0 && index < list.size())
        list.removeAt(index);
    saveCustomColors(list);
}

// ── Géométrie ─────────────────────────────────────────────────────────────────

QRect ColorPickerPopup::presetRect(int i) const
{
    const int row = i / COLS, col = i % COLS;
    return { MARGIN + col * (CELL + GAP), MARGIN + row * (CELL + GAP), CELL, CELL };
}

QRect ColorPickerPopup::separatorArea() const
{
    const int gridH = ROWS * (CELL + GAP) - GAP;
    return { MARGIN, MARGIN + gridH + GAP * 2, width() - 2 * MARGIN, SEP_H };
}

QRect ColorPickerPopup::customRect(int i) const
{
    const int gridH = ROWS * (CELL + GAP) - GAP;
    const int y = MARGIN + gridH + GAP * 2 + SEP_H;
    return { MARGIN + i * (CELL + GAP), y, CELL, CELL };
}

int ColorPickerPopup::presetAt(const QPoint& p) const
{
    for (int i = 0; i < COLS * ROWS; ++i)
        if (presetRect(i).contains(p)) return i;
    return -1;
}

// Retourne : 0..n-1 = couleur perso, n = bouton +, -1 = rien
int ColorPickerPopup::customAt(const QPoint& p) const
{
    const int n = m_custom.size();
    for (int i = 0; i <= qMin(n, MAX_CUSTOM - 1); ++i)
        if (customRect(i).contains(p)) return i;
    return -1;
}

// ── Constructeur ──────────────────────────────────────────────────────────────

ColorPickerPopup::ColorPickerPopup(QWidget* parent)
    : QFrame(parent, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowDoesNotAcceptFocus)
    , m_custom(customColors())
{
    setFrameShape(QFrame::StyledPanel);
    setFrameShadow(QFrame::Plain);
    setMouseTracking(true);
    setAttribute(Qt::WA_DeleteOnClose);

    const int gridW = COLS * (CELL + GAP) - GAP;
    const int gridH = ROWS * (CELL + GAP) - GAP;
    const int w = 2 * MARGIN + gridW;
    const int h = MARGIN + gridH + GAP * 2 + SEP_H + CELL + MARGIN;
    setFixedSize(w, h);
}

// ── Dessin ────────────────────────────────────────────────────────────────────

void ColorPickerPopup::drawCell(QPainter& p, const QRect& r,
                                const QColor& color, bool hovered) const
{
    p.fillRect(r, color);
    if (hovered) {
        p.setPen(QPen(Qt::black, 1));
        p.drawRect(r.adjusted(0, 0, -1, -1));
        p.setPen(QPen(Qt::white, 1));
        p.drawRect(r.adjusted(1, 1, -2, -2));
    } else {
        p.setPen(color.darker(140));
        p.drawRect(r.adjusted(0, 0, -1, -1));
    }
}

void ColorPickerPopup::paintEvent(QPaintEvent* e)
{
    QFrame::paintEvent(e);
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, false);

    // Palette prédéfinie
    for (int i = 0; i < COLS * ROWS; ++i)
        drawCell(p, presetRect(i), QColor(s_palette[i]), i == m_hoverPreset);

    // Séparateur avec label
    const QRect sep = separatorArea();
    const int lineY = sep.top() + sep.height() / 2;
    p.setPen(palette().color(QPalette::Mid));
    p.setFont(QFont(font().family(), font().pointSize() - 1));
    const QRect labelR = p.boundingRect(sep, Qt::AlignCenter, tr("Personnalisées"));
    p.drawLine(sep.left(),       lineY, labelR.left() - 4,  lineY);
    p.drawLine(labelR.right()+4, lineY, sep.right(),         lineY);
    p.setPen(palette().color(QPalette::Text));
    p.drawText(sep, Qt::AlignCenter, tr("Personnalisées"));
    p.setFont(font());

    // Couleurs personnalisées
    const int n = m_custom.size();
    for (int i = 0; i < n; ++i)
        drawCell(p, customRect(i), m_custom[i], i == m_hoverCustom);

    // Bouton « + » si de la place
    if (n < MAX_CUSTOM) {
        const QRect r = customRect(n);
        const bool hov = (m_hoverCustom == n);
        p.fillRect(r, hov ? palette().color(QPalette::Highlight)
                          : palette().color(QPalette::Button));
        p.setPen(hov ? palette().color(QPalette::HighlightedText)
                     : palette().color(QPalette::Mid));
        p.drawRect(r.adjusted(0, 0, -1, -1));
        p.setPen(hov ? palette().color(QPalette::HighlightedText)
                     : palette().color(QPalette::Text));
        p.drawText(r, Qt::AlignCenter, "+");
    }
}

// ── Souris ────────────────────────────────────────────────────────────────────

void ColorPickerPopup::mouseMoveEvent(QMouseEvent* e)
{
    const int hp = presetAt(e->pos());
    const int hc = customAt(e->pos());
    if (hp != m_hoverPreset || hc != m_hoverCustom) {
        m_hoverPreset = hp;
        m_hoverCustom = hc;
        update();
    }
}

void ColorPickerPopup::leaveEvent(QEvent*)
{
    m_hoverPreset = -1;
    m_hoverCustom = -1;
    update();
}

void ColorPickerPopup::showEvent(QShowEvent* e)
{
    QFrame::showEvent(e);
    qApp->installEventFilter(this);
}

void ColorPickerPopup::hideEvent(QHideEvent* e)
{
    qApp->removeEventFilter(this);
    QFrame::hideEvent(e);
}

bool ColorPickerPopup::eventFilter(QObject* watched, QEvent* event)
{
    // Repositionnement : toujours actif, même quand un dialogue modal est ouvert
    if (m_anchor && watched == m_anchor->window()
            && (event->type() == QEvent::Move || event->type() == QEvent::Resize)) {
        showBelow(m_anchor);
        return false;
    }

    // Fermeture sur clic extérieur : ignorée si un dialogue modal est actif
    if (event->type() == QEvent::MouseButtonPress && !QApplication::activeModalWidget()) {
        const auto* me = static_cast<QMouseEvent*>(event);
        if (!rect().contains(mapFromGlobal(me->globalPosition().toPoint())))
            close();
    }
    return false;
}

void ColorPickerPopup::refreshCustomColors()
{
    m_custom = customColors();
    m_hoverCustom = -1;
    update();
}

void ColorPickerPopup::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        const int ip = presetAt(e->pos());
        if (ip >= 0) {
            e->accept();
            emit colorSelected(QColor(s_palette[ip]));
            close();
            return;
        }
        const int ic = customAt(e->pos());
        if (ic >= 0 && ic < m_custom.size()) {
            e->accept();
            emit colorSelected(m_custom[ic]);
            close();
            return;
        }
        if (ic == m_custom.size() && ic < MAX_CUSTOM) {
            e->accept();
            // Pas de close() : le popup reste ouvert pendant que QColorDialog s'ouvre.
            // Sans Qt::Popup (pas de grab X11), aucun conflit possible.
            emit addCustomColorRequested();
            return;
        }
    }

    if (e->button() == Qt::RightButton) {
        const int ic = customAt(e->pos());
        if (ic >= 0 && ic < m_custom.size()) {
            e->accept();
            // Suppression directe sans fermer : pas de grab à libérer, QSettings est safe.
            removeCustomColor(ic);
            refreshCustomColors();
            return;
        }
    }

    e->accept();
    close();
}

void ColorPickerPopup::contextMenuEvent(QContextMenuEvent* e)
{
    // Supprime le menu contextuel natif — le clic droit est géré manuellement
    e->accept();
}

// ── Positionnement ────────────────────────────────────────────────────────────

void ColorPickerPopup::showBelow(QWidget* anchor)
{
    m_anchor = anchor;
    const QPoint below = anchor->mapToGlobal(QPoint(0, anchor->height()));
    const QPoint above = anchor->mapToGlobal(QPoint(0, 0));
    QRect rect(below, size());

    if (auto* screen = QApplication::screenAt(below)) {
        const QRect avail = screen->availableGeometry();
        if (rect.right()  > avail.right())  rect.moveRight(avail.right());
        if (rect.bottom() > avail.bottom()) rect.moveBottom(above.y());
    }
    move(rect.topLeft());
    show();
}
