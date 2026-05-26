#include "colorpickerdialog.h"

#include <QPainter>
#include <QMouseEvent>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLineEdit>
#include <QDialogButtonBox>
#include <QPushButton>

// ── HueSlider ─────────────────────────────────────────────────────────────────
//
// Barre verticale arc-en-ciel + indicateur circulaire. Les constantes BAR_X et
// BAR_W définissent la bande colorée ; IND_R est le rayon de l'indicateur.
// L'indicateur déborde légèrement à gauche de la bande pour ressembler à une
// poignée de curseur.

class HueSlider : public QWidget {
    Q_OBJECT
public:
    explicit HueSlider(QWidget* parent = nullptr) : QWidget(parent) {
        setMouseTracking(true);
        setFixedSize(BAR_X + BAR_W + 2, SQ);
    }
    void setHue(qreal h) { m_h = qBound(0.0, h, 1.0); update(); }
    qreal hue() const    { return m_h; }
signals:
    void hueChanged(qreal);
protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent* e) override { e->accept(); fromY(e->pos().y()); }
    void mouseMoveEvent(QMouseEvent* e) override  { if (e->buttons()) fromY(e->pos().y()); }
private:
    static constexpr int IND_R = 6;
    static constexpr int BAR_X = IND_R + 3;   // x du bord gauche de la bande
    static constexpr int BAR_W = 16;
    static constexpr int SQ    = 280;           // hauteur (= côté du carré SV)
    qreal m_h{0};

    void fromY(int y) {
        const int yTop = IND_R, yBot = height() - IND_R;
        const qreal h = qBound(0.0, qreal(y - yTop) / (yBot - yTop), 1.0);
        if (!qFuzzyCompare(h + 1, m_h + 1)) { m_h = h; update(); emit hueChanged(m_h); }
    }
};

void HueSlider::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    const int yTop = IND_R, yBot = height() - IND_R;
    const QRect bar(BAR_X, yTop, BAR_W, yBot - yTop);

    QLinearGradient g(0, yTop, 0, yBot);
    for (int i = 0; i <= 6; ++i)
        g.setColorAt(i / 6.0, QColor::fromHsvF(i / 6.0, 1.0, 1.0));
    p.fillRect(bar, g);

    // Indicateur
    const int cy = yTop + qRound(m_h * (yBot - yTop));
    p.setPen(QPen(Qt::white, 1.5));
    p.setBrush(QColor::fromHsvF(m_h, 1.0, 1.0));
    p.drawEllipse(QPoint(BAR_X - 1, cy), IND_R, IND_R);
}

// ── SVSquare ──────────────────────────────────────────────────────────────────
//
// Carré saturation × valeur. Le dégradé est rendu par deux QLinearGradient
// superposés (blanc→teinte pure horizontalement, transparent→noir verticalement),
// ce qui donne le résultat mathématiquement exact d'un remplissage pixel par pixel.

class SVSquare : public QWidget {
    Q_OBJECT
public:
    explicit SVSquare(QWidget* parent = nullptr) : QWidget(parent) {
        setMouseTracking(true);
        setFixedSize(280, 280);
    }
    void setHue(qreal h) { m_h = qBound(0.0, h, 1.0); update(); }
    void setSV(qreal s, qreal v) {
        m_s = qBound(0.0, s, 1.0); m_v = qBound(0.0, v, 1.0); update();
    }
    qreal sat() const { return m_s; }
    qreal val() const { return m_v; }
signals:
    void svChanged(qreal s, qreal v);
protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent* e) override { e->accept(); fromPos(e->pos()); }
    void mouseMoveEvent(QMouseEvent* e) override  { if (e->buttons()) fromPos(e->pos()); }
private:
    qreal m_h{0}, m_s{1}, m_v{1};

    void fromPos(const QPoint& pt) {
        const qreal s = qBound(0.0, qreal(pt.x()) / (width()  - 1), 1.0);
        const qreal v = qBound(0.0, 1.0 - qreal(pt.y()) / (height() - 1), 1.0);
        if (!qFuzzyCompare(s + 1, m_s + 1) || !qFuzzyCompare(v + 1, m_v + 1)) {
            m_s = s; m_v = v; update(); emit svChanged(m_s, m_v);
        }
    }
};

void SVSquare::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    const QRect r = rect();

    QLinearGradient hg(r.left(), 0, r.right(), 0);
    hg.setColorAt(0, Qt::white);
    hg.setColorAt(1, QColor::fromHsvF(m_h, 1.0, 1.0));
    p.fillRect(r, hg);

    QLinearGradient vg(0, r.top(), 0, r.bottom());
    vg.setColorAt(0, Qt::transparent);
    vg.setColorAt(1, Qt::black);
    p.fillRect(r, vg);

    // Indicateur — blanc sur fond sombre, noir sur fond clair
    p.setRenderHint(QPainter::Antialiasing);
    const int cx = qRound(m_s * (width()  - 1));
    const int cy = qRound((1.0 - m_v) * (height() - 1));
    const bool useDark = m_v > 0.45 && m_s < 0.85;
    p.setPen(QPen(useDark ? Qt::black : Qt::white, 1.5));
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(QPoint(cx, cy), 6, 6);
}

// ── ColorPickerDialog ─────────────────────────────────────────────────────────

ColorPickerDialog::ColorPickerDialog(const QColor& initial, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Choisir une couleur"));

    auto* hue = new HueSlider(this);
    auto* sv  = new SVSquare(this);
    m_hue = hue;
    m_sv  = sv;

    m_preview = new QFrame(this);
    m_preview->setFixedSize(80, 34);
    m_preview->setFrameShape(QFrame::StyledPanel);
    m_preview->setFrameShadow(QFrame::Plain);

    m_hex = new QLineEdit(this);
    m_hex->setMaxLength(9);
    m_hex->setPlaceholderText("#rrggbb");

    auto* topRow = new QHBoxLayout;
    topRow->setSpacing(8);
    topRow->addWidget(m_preview);
    topRow->addWidget(m_hex);

    auto* midRow = new QHBoxLayout;
    midRow->setSpacing(8);
    midRow->addWidget(m_hue);
    midRow->addWidget(m_sv);

    auto* bbox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    bbox->button(QDialogButtonBox::Ok)->setText(tr("Sélectionner"));
    bbox->button(QDialogButtonBox::Cancel)->setText(tr("Annuler"));

    auto* root = new QVBoxLayout(this);
    root->addLayout(topRow);
    root->addLayout(midRow);
    root->addWidget(bbox);
    root->setSizeConstraint(QLayout::SetFixedSize);

    connect(hue, &HueSlider::hueChanged, this, [this, sv](qreal h) {
        m_h = h;
        sv->setHue(h);
        updatePreview();
    });
    connect(sv, &SVSquare::svChanged, this, [this](qreal s, qreal v) {
        m_s = s; m_v = v;
        updatePreview();
    });
    connect(m_hex, &QLineEdit::editingFinished, this, [this]() {
        QString t = m_hex->text().trimmed();
        if (!t.startsWith('#')) t.prepend('#');
        const QColor c(t);
        if (c.isValid()) setColor(c);
        else updatePreview();   // rétablit le hex valide
    });
    connect(bbox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(bbox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    setColor(initial.isValid() ? initial : Qt::white);
}

void ColorPickerDialog::setColor(const QColor& c)
{
    float h, s, v;
    c.getHsvF(&h, &s, &v);
    m_h = (h < 0.0f) ? 0.0 : qreal(h);  // achromatic: h=-1
    m_s = qreal(s);
    m_v = qreal(v);
    static_cast<HueSlider*>(m_hue)->setHue(m_h);
    static_cast<SVSquare*>(m_sv)->setHue(m_h);
    static_cast<SVSquare*>(m_sv)->setSV(m_s, m_v);
    updatePreview();
}

void ColorPickerDialog::updatePreview()
{
    const QColor c = QColor::fromHsvF(m_h, m_s, m_v);
    m_preview->setStyleSheet(
        QStringLiteral("background:%1; border:1px solid gray; border-radius:2px;").arg(c.name())
    );
    m_hex->blockSignals(true);
    m_hex->setText(c.name().toUpper());
    m_hex->blockSignals(false);
}

QColor ColorPickerDialog::color() const
{
    return QColor::fromHsvF(m_h, m_s, m_v);
}

QColor ColorPickerDialog::getColor(const QColor& initial, QWidget* parent,
                                   const QString& title)
{
    ColorPickerDialog dlg(initial, parent);
    if (!title.isEmpty()) dlg.setWindowTitle(title);
    return dlg.exec() == QDialog::Accepted ? dlg.color() : QColor{};
}

#include "colorpickerdialog.moc"
