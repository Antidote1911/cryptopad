#pragma once
#include <QFontComboBox>
#include <QStyledItemDelegate>

class QLineEdit;
class QListView;
class QFrame;
class QSortFilterProxyModel;

// Affiche chaque police dans sa propre fonte mais à la taille de l'UI.
class FontPreviewDelegate : public QStyledItemDelegate {
public:
    explicit FontPreviewDelegate(QObject* parent = nullptr);
    void  paint(QPainter*, const QStyleOptionViewItem&,
                const QModelIndex&) const override;
    QSize sizeHint(const QStyleOptionViewItem&,
                   const QModelIndex&) const override;
private:
    int m_uiPt;
};

// QFontComboBox avec popup personnalisé : filtre + prévisualisation taille contrôlée.
class FilteredFontComboBox : public QFontComboBox {
    Q_OBJECT
public:
    explicit FilteredFontComboBox(QWidget* parent = nullptr);

    void showPopup() override;
    void hidePopup() override;

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    void buildPopup();

    QFrame*                m_popup{nullptr};
    QLineEdit*             m_filter{nullptr};
    QListView*             m_view{nullptr};
    QSortFilterProxyModel* m_proxy{nullptr};
};
