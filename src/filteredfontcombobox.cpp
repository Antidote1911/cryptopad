#include "filteredfontcombobox.h"

#include <QApplication>
#include <QFrame>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QListView>
#include <QSortFilterProxyModel>
#include <QPainter>
#include <QKeyEvent>
#include <QScreen>
#include <QScrollBar>
#include <QAbstractItemView>

// ── FontPreviewDelegate ───────────────────────────────────────────────────────

FontPreviewDelegate::FontPreviewDelegate(QObject* parent)
    : QStyledItemDelegate(parent)
    , m_uiPt(QApplication::font().pointSize())
{}

void FontPreviewDelegate::paint(QPainter* painter,
                                const QStyleOptionViewItem& option,
                                const QModelIndex& index) const
{
    QStyleOptionViewItem opt = option;
    initStyleOption(&opt, index);

    // Famille de la fonte tirée du texte de l'item
    const QString family = opt.text;
    const QFont previewFont(family, m_uiPt);
    opt.font        = previewFont;
    opt.fontMetrics = QFontMetrics(previewFont);

    QStyledItemDelegate::paint(painter, opt, index);
}

QSize FontPreviewDelegate::sizeHint(const QStyleOptionViewItem&,
                                    const QModelIndex&) const
{
    // Hauteur uniforme basée sur la police de l'interface
    const QFontMetrics fm(QFont(QApplication::font().family(), m_uiPt));
    return {0, fm.height() + 8};
}

// ── FilteredFontComboBox ──────────────────────────────────────────────────────

FilteredFontComboBox::FilteredFontComboBox(QWidget* parent)
    : QFontComboBox(parent)
{}

void FilteredFontComboBox::buildPopup()
{
    m_popup = new QFrame(nullptr, Qt::Popup);
    m_popup->setFrameShape(QFrame::StyledPanel);
    m_popup->setFrameShadow(QFrame::Plain);

    auto* layout = new QVBoxLayout(m_popup);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(2);

    m_filter = new QLineEdit(m_popup);
    m_filter->setPlaceholderText(tr("Filtrer…"));
    m_filter->setClearButtonEnabled(true);
    layout->addWidget(m_filter);

    m_view = new QListView(m_popup);
    m_view->setFrameShape(QFrame::NoFrame);
    m_view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_view->setUniformItemSizes(true);
    layout->addWidget(m_view);

    m_proxy = new QSortFilterProxyModel(m_popup);
    m_proxy->setSourceModel(model());
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(0);

    m_view->setModel(m_proxy);
    m_view->setItemDelegate(new FontPreviewDelegate(m_view));

    // Sélectionne la police courante dans la liste
    const QString current = currentFont().family();
    for (int i = 0; i < m_proxy->rowCount(); ++i) {
        if (m_proxy->index(i, 0).data().toString() == current) {
            m_view->setCurrentIndex(m_proxy->index(i, 0));
            m_view->scrollTo(m_proxy->index(i, 0), QAbstractItemView::PositionAtCenter);
            break;
        }
    }

    connect(m_filter, &QLineEdit::textChanged, this, [this](const QString& text) {
        m_proxy->setFilterFixedString(text);
    });

    // Sélection via clic ou activation clavier (Entrée / double-clic)
    auto applySelection = [this](const QModelIndex& idx) {
        const QString family = idx.data(Qt::DisplayRole).toString();
        if (!family.isEmpty())
            setCurrentFont(QFont(family));
        hidePopup();
    };
    connect(m_view, &QAbstractItemView::clicked,   this, applySelection);
    connect(m_view, &QAbstractItemView::activated, this, applySelection);

    m_filter->installEventFilter(this);
}

void FilteredFontComboBox::showPopup()
{
    // Détruit l'éventuel popup précédent (ex. auto-masqué par le système)
    if (m_popup) {
        m_popup->hide();
        m_popup->deleteLater();
        m_popup  = nullptr;
        m_filter = nullptr;
        m_view   = nullptr;
        m_proxy  = nullptr;
    }

    buildPopup();

    const QPoint comboTopGlobal    = mapToGlobal(QPoint(0, 0));
    const QPoint comboBottomGlobal = mapToGlobal(QPoint(0, height()));
    const int    popupWidth        = qMax(width(), 260);
    const int    popupHeight       = 320;

    QRect popupRect(comboBottomGlobal, QSize(popupWidth, popupHeight));

    if (auto* screen = QApplication::screenAt(comboBottomGlobal)) {
        const QRect avail = screen->availableGeometry();
        if (popupRect.right()  > avail.right())
            popupRect.moveRight(avail.right());
        if (popupRect.bottom() > avail.bottom())
            popupRect.moveBottom(comboTopGlobal.y());
    }

    m_popup->setGeometry(popupRect);
    m_popup->show();
    m_filter->setFocus();
}

void FilteredFontComboBox::hidePopup()
{
    if (m_popup) {
        m_popup->hide();
        m_popup->deleteLater();  // différé : évite de détruire l'émetteur en plein slot
        m_popup  = nullptr;
        m_filter = nullptr;
        m_view   = nullptr;
        m_proxy  = nullptr;
    }
    // Ne pas appeler QFontComboBox::hidePopup() — on gère notre propre popup.
}

bool FilteredFontComboBox::eventFilter(QObject* obj, QEvent* event)
{
    if (obj == m_filter && event->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(event);
        switch (ke->key()) {
        case Qt::Key_Down:
        case Qt::Key_Up:
        case Qt::Key_PageDown:
        case Qt::Key_PageUp:
            // Délègue la navigation à la liste
            QApplication::sendEvent(m_view, event);
            return true;

        case Qt::Key_Return:
        case Qt::Key_Enter: {
            const QModelIndex idx = m_view->currentIndex();
            if (idx.isValid()) {
                const QString family = idx.data(Qt::DisplayRole).toString();
                if (!family.isEmpty())
                    setCurrentFont(QFont(family));
            }
            hidePopup();
            return true;
        }

        case Qt::Key_Escape:
            hidePopup();
            return true;

        default:
            break;
        }
    }

    return QFontComboBox::eventFilter(obj, event);
}
