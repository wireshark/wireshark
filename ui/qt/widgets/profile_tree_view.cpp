/* profile_tree_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/url_link_delegate.h>
#include <ui/qt/models/profile_model.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include <ui/qt/widgets/profile_tree_view.h>

#include <QDesktopServices>
#include <QDir>
#include <QHeaderView>
#include <QItemDelegate>
#include <QLineEdit>
#include <QUrl>

ProfileUrlLinkDelegate::ProfileUrlLinkDelegate(QObject *parent) : UrlLinkDelegate (parent) {}

void ProfileUrlLinkDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    /* Only paint links for valid paths */
    if (index.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool())
        UrlLinkDelegate::paint(painter, option, index);
    else
        QStyledItemDelegate::paint(painter, option, index);

}

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

    connect(this, &QAbstractItemView::clicked, this, &ProfileTreeView::itemClicked);
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
            if (! idx.isValid() || idx.row() >= model()->rowCount())
                idx = model()->index(0, ProfileModel::COL_NAME);
            selectRow(idx.row());
        }
        else if (selectedIndexes().count() == 0)
            selectRow(0);
    }
}

void ProfileTreeView::itemClicked(const QModelIndex &index)
{
    if (!index.isValid())
        return;

    /* Only paint links for valid paths */
    if (index.data(ProfileModel::DATA_INDEX_VALUE_IS_URL).toBool())
    {
        QString path = QDir::toNativeSeparators(index.data().toString());
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    }
}

void ProfileTreeView::selectRow(int row)
{
    if (row < 0)
        return;

    setCurrentIndex(model()->index(row, 0));

    selectionModel()->select(
                QItemSelection(model()->index(row, 0), model()->index(row, model()->columnCount() -1)),
                QItemSelectionModel::ClearAndSelect);

}

void ProfileTreeView::mouseDoubleClickEvent(QMouseEvent *ev)
{
    /* due to the fact, that we allow only row selection, selected rows are always added with all columns */
    if (selectedIndexes().count() <= model()->columnCount())
        QTreeView::mouseDoubleClickEvent(ev);
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
