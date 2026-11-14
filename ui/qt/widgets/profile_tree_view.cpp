/* profile_tree_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/profile_model.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include <ui/qt/widgets/profile_tree_view.h>

#include <QCursor>
#include <QDesktopServices>
#include <QDir>
#include <QDrag>
#include <QDragMoveEvent>
#include <QHeaderView>
#include <QItemDelegate>
#include <QLineEdit>
#include <QPainter>
#include <QStyleOptionViewItem>

#include <algorithm>

ProfileTreeEditDelegate::ProfileTreeEditDelegate(QWidget *parent) : QItemDelegate(parent), editor_(Q_NULLPTR) {}

QWidget *ProfileTreeEditDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                   const QModelIndex &index) const
{
    if (index.column() == ProfileModel::COL_AUTO_SWITCH_FILTER) {
        return new DisplayFilterEdit(parent);
    }
    return QItemDelegate::createEditor(parent, option, index);
}

void ProfileTreeEditDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (qobject_cast<QLineEdit *>(editor))
    {
        QLineEdit * ql = qobject_cast<QLineEdit *>(editor);
        ql->setText(index.data().toString());
    }
}

ProfileTreeView::ProfileTreeView(QWidget *parent) :
    QTreeView (parent)
{
    delegate_ = new ProfileTreeEditDelegate();
    setItemDelegateForColumn(ProfileModel::COL_NAME, delegate_);
    setItemDelegateForColumn(ProfileModel::COL_AUTO_SWITCH_FILTER, delegate_);

    connect(delegate_, &ProfileTreeEditDelegate::commitData, this, &ProfileTreeView::itemUpdated);
}

ProfileTreeView::~ProfileTreeView()
{
    delete delegate_;
}

void ProfileTreeView::selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    QTreeView::selectionChanged(selected, deselected);

    if (model())
    {
        qsizetype offColumn = model()->columnCount();
        qsizetype idxCount = selectedIndexes().count() / offColumn;
        qsizetype dselCount = deselected.count() > 0 ? deselected.at(0).indexes().count() / offColumn : 0;

        /* Ensure, that the last selected row cannot be deselected */
        if (idxCount == 0 && dselCount == 1)
        {
            QModelIndex idx = deselected.at(0).indexes().at(0);
            /* If the last item is no longer valid or the row is out of bounds, select default */
            if (! idx.isValid())
                idx = model()->index(0, ProfileModel::COL_NAME);
            selectIndex(idx);
        }
        else if (selectedIndexes().count() == 0)
            selectIndex(model()->index(0, ProfileModel::COL_NAME));
    }
}

void ProfileTreeView::selectIndex(const QModelIndex &idx)
{
    if (! idx.isValid())
        return;

    setCurrentIndex(idx.siblingAtColumn(0));

    selectionModel()->select(
                QItemSelection(idx.siblingAtColumn(0), idx.siblingAtColumn(model()->columnCount() -1)),
                QItemSelectionModel::ClearAndSelect);

}

void ProfileTreeView::mouseDoubleClickEvent(QMouseEvent *ev)
{
    /* due to the fact, that we allow only row selection, selected rows are always added with all columns */
    if (selectedIndexes().count() <= model()->columnCount())
        QTreeView::mouseDoubleClickEvent(ev);
}

void ProfileTreeView::setDropPath(const QModelIndex &target, bool topLevel)
{
    drop_top_level_ = topLevel;
    drop_path_.clear();
    for (QModelIndex idx = target.siblingAtColumn(0); idx.isValid(); idx = idx.parent())
        drop_path_ << QPersistentModelIndex(idx);

    // Repaint at once, the platform drag loop may delay queued updates
    viewport()->repaint();
}

void ProfileTreeView::startDrag(Qt::DropActions supportedActions)
{
    if (!model())
        return;

    QModelIndexList indexes;
    foreach (QModelIndex idx, selectedIndexes()) {
        if (idx.column() == ProfileModel::COL_NAME && (model()->flags(idx) & Qt::ItemIsDragEnabled))
            indexes << idx;
    }
    if (indexes.isEmpty())
        return;
    std::sort(indexes.begin(), indexes.end(), [this](const QModelIndex &a, const QModelIndex &b) {
        return visualRect(a).top() < visualRect(b).top();
    });

    // Paint the dragged profile names the same on all platforms, each as
    // high as its row and as wide as the name, like selected items.
    QStyleOptionViewItem option;
    initViewItemOption(&option);
    option.state |= QStyle::State_Selected | QStyle::State_Active;
    option.state &= ~(QStyle::State_MouseOver | QStyle::State_HasFocus);
    int width = 0, height = 0;
    foreach (QModelIndex idx, indexes) {
        width = qMax(width, visualRect(idx).width());
        height += visualRect(idx).height();
    }
    qreal ratio = devicePixelRatioF();
    QPixmap pixmap(QSize(width, height) * ratio);
    pixmap.setDevicePixelRatio(ratio);
    pixmap.fill(palette().color(QPalette::Base));
    {
        QPainter painter(&pixmap);
        int y = 0;
        foreach (QModelIndex idx, indexes) {
            option.rect = QRect(0, y, width, visualRect(idx).height());
            itemDelegateForIndex(idx)->paint(&painter, option, idx);
            y += option.rect.height();
        }
        painter.setPen(palette().color(QPalette::Mid));
        painter.drawRect(QRect(0, 0, width, height).adjusted(0, 0, -1, -1));
    }

    QPoint offset = viewport()->mapFromGlobal(QCursor::pos()) - visualRect(indexes.first()).topLeft();
    offset.setX(qBound(0, offset.x(), width - 1));
    offset.setY(qBound(0, offset.y(), height - 1));

    // The platform may not show the drag image, so also paint it in the view
    drag_pixmap_ = pixmap;
    drag_offset_ = offset;

    QDrag *drag = new QDrag(this);
    drag->setMimeData(model()->mimeData(indexes));
    drag->setPixmap(pixmap);
    drag->setHotSpot(offset);
    // The model moves the profiles, so the view must not remove them
    drag->exec(supportedActions & Qt::MoveAction, Qt::MoveAction);

    drag_pixmap_ = QPixmap();
    drag_pos_ = QPoint(-1, -1);
    setDropPath(QModelIndex());
}

void ProfileTreeView::dragMoveEvent(QDragMoveEvent *event)
{
    QTreeView::dragMoveEvent(event);
    drag_pos_ = event->position().toPoint();

    // Between items, or below them, the profile is moved to the parent
    QModelIndex idx = indexAt(event->position().toPoint());
    QModelIndex target = (idx.isValid() && dropIndicatorPosition() == QAbstractItemView::OnItem) ? idx : idx.parent();
    if (model() && model()->canDropMimeData(event->mimeData(), Qt::MoveAction, -1, -1, target))
        setDropPath(target, !target.isValid());
    else
        setDropPath(QModelIndex());
}

void ProfileTreeView::dragLeaveEvent(QDragLeaveEvent *event)
{
    drag_pos_ = QPoint(-1, -1);
    setDropPath(QModelIndex());
    QTreeView::dragLeaveEvent(event);
}

void ProfileTreeView::dropEvent(QDropEvent *event)
{
    setDropPath(QModelIndex());
    QTreeView::dropEvent(event);
}

void ProfileTreeView::drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QTreeView::drawRow(painter, option, index);

    if (drop_path_.contains(index.siblingAtColumn(0)))
    {
        QColor color = palette().color(QPalette::Highlight);
        color.setAlpha(64);
        painter->fillRect(option.rect, color);
    }

    // Frame the profile the dragged profile will be moved into
    if (!drop_path_.isEmpty() && drop_path_.first() == index.siblingAtColumn(0))
    {
        painter->save();
        painter->setPen(palette().color(QPalette::Text));
        painter->drawRect(option.rect.adjusted(0, 0, -1, -1));
        painter->restore();
    }
}

void ProfileTreeView::paintEvent(QPaintEvent *event)
{
    // The drop target is framed in drawRow(), or around all profiles when
    // moving to the top level, so hide the drop indicator while painting.
    // It must stay enabled while dragging to get dropIndicatorPosition().
    setDropIndicatorShown(false);
    QTreeView::paintEvent(event);
    setDropIndicatorShown(true);

    if (drop_top_level_)
    {
        QPainter painter(viewport());
        painter.setPen(palette().color(QPalette::Text));
        painter.drawRect(viewport()->rect().adjusted(0, 0, -1, -1));
    }

    // Dragged profiles, when the platform does not show them
    if (!drag_pixmap_.isNull() && drag_pos_ != QPoint(-1, -1))
    {
        QPainter painter(viewport());
        painter.drawPixmap(drag_pos_ - drag_offset_, drag_pixmap_);
    }
}

bool ProfileTreeView::activeEdit()
{
    return (state() == QAbstractItemView::EditingState);
}

// If our auto switch filters are shorter than the filter column title,
// stretch the name column.
void ProfileTreeView::showEvent(QShowEvent *)
{
    bool have_wide_filter = false;
    int auto_switch_title_width = fontMetrics().horizontalAdvance(model()->headerData(ProfileModel::COL_AUTO_SWITCH_FILTER, Qt::Horizontal).toString());
    for (int row = 0; row < model()->rowCount(); row++) {
        QString filter = model()->data(model()->index(row, ProfileModel::COL_AUTO_SWITCH_FILTER)).toString();
        if (fontMetrics().horizontalAdvance(filter) > auto_switch_title_width) {
            have_wide_filter = true;
            break;
        }
    }

    if (have_wide_filter) {
        return;
    }

    int col_name_size_hint = sizeHintForColumn(ProfileModel::COL_NAME);
    int col_asf_size_hint = qMax(header()->sectionSizeHint(ProfileModel::COL_AUTO_SWITCH_FILTER), sizeHintForColumn(ProfileModel::COL_AUTO_SWITCH_FILTER));
    int extra = columnWidth(ProfileModel::COL_AUTO_SWITCH_FILTER) - col_asf_size_hint;
    if (extra > 0) {
        setColumnWidth(ProfileModel::COL_NAME, col_name_size_hint + extra);
    }

}
