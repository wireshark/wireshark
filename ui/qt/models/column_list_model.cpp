/* column_list_models.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/column_list_model.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/field_filter_edit.h>
#include <ui/qt/widgets/syntax_line_edit.h>
#include <ui/qt/utils/wireshark_mime_data.h>

#include <glib.h>
#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <ui/preference_utils.h>

#include <QLineEdit>
#include <QStringList>
#include <QComboBox>

struct ListElement
{
    QString title;
    QString customFields;
    int nr;
    int type;
    int originalType;
    int occurrence;
    bool displayed;
    bool resolved;
};

static QList<ListElement> store_;

ColumnProxyModel::ColumnProxyModel(QObject * parent) :
    QSortFilterProxyModel(parent),
    showDisplayedOnly_(false)
{}

bool ColumnProxyModel::filterAcceptsRow(int source_row, const QModelIndex &/*source_parent*/) const
{
    bool displayed = false;
    if (sourceModel() &&
         sourceModel()->index(source_row, ColumnListModel::COL_DISPLAYED).data(ColumnListModel::DisplayedState).toBool())
        displayed = true;

    if (showDisplayedOnly_ && ! displayed)
        return false;

    return true;
}

void ColumnProxyModel::setShowDisplayedOnly(bool set)
{
    showDisplayedOnly_ = set;
    invalidateFilter();
}

ColumnTypeDelegate::ColumnTypeDelegate(QObject * parent) :
    QStyledItemDelegate(parent)
{}

QWidget *ColumnTypeDelegate::createEditor(QWidget *parent,
                                       const QStyleOptionViewItem &option,
                                       const QModelIndex &index) const
{
    QWidget *editor = nullptr;

    if (index.column() == ColumnListModel::COL_TYPE)
    {
        QComboBox *cb_editor = new QComboBox(parent);

        for (int i = 0; i < NUM_COL_FMTS; i++)
        {
            cb_editor->addItem(col_format_desc(i), QVariant(i));
            if (i == index.data().toInt())
                cb_editor->setCurrentIndex(i);
        }

        cb_editor->setFrame(false);
        editor = cb_editor;
    }
    else if (index.column() == ColumnListModel::COL_FIELDS)
    {
        FieldFilterEdit * ff_editor = new FieldFilterEdit(parent);
        connect(ff_editor, &FieldFilterEdit::textChanged, ff_editor, &FieldFilterEdit::checkCustomColumn);
        ff_editor->setText(index.data().toString());
        editor = ff_editor;
    }
    else if (index.column() == ColumnListModel::COL_OCCURRENCE)
    {
        SyntaxLineEdit * sl_editor = new SyntaxLineEdit(parent);
        connect(sl_editor, &SyntaxLineEdit::textChanged, sl_editor, &SyntaxLineEdit::checkInteger);
        sl_editor->setText(index.data().toString());
        editor = sl_editor;
    }

    if (!editor) {
        editor = QStyledItemDelegate::createEditor(parent, option, index);
    }
    editor->setAutoFillBackground(true);
    return editor;
}

void ColumnTypeDelegate::setEditorData(QWidget *editor,
                                    const QModelIndex &index) const
{
    QVariant data = index.model()->data(index);
    if (index.column() == ColumnListModel::COL_TYPE)
    {
        QComboBox *comboBox = static_cast<QComboBox*>(editor);
        comboBox->setCurrentText(data.toString());
    }
    else if (index.column() == ColumnListModel::COL_FIELDS)
    {
        if (qobject_cast<FieldFilterEdit *>(editor))
            qobject_cast<FieldFilterEdit *>(editor)->setText(data.toString());
    }
    else if (index.column() == ColumnListModel::COL_OCCURRENCE)
    {
        if (qobject_cast<SyntaxLineEdit *>(editor))
            qobject_cast<SyntaxLineEdit *>(editor)->setText(data.toString());
    }
    else
    {
        if (qobject_cast<QLineEdit *>(editor))
            qobject_cast<QLineEdit *>(editor)->setText(data.toString());
    }
}

void ColumnTypeDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                                   const QModelIndex &index) const
{
    if (index.column() == ColumnListModel::COL_TYPE)
    {
        QComboBox *comboBox = static_cast<QComboBox*>(editor);
        bool ok = false;
        int value = comboBox->currentData().toInt(&ok);

        if (ok)
            model->setData(index, value, Qt::EditRole);
    }
    else if (index.column() == ColumnListModel::COL_FIELDS)
    {
        FieldFilterEdit * ffe = qobject_cast<FieldFilterEdit *>(editor);
        if (ffe)
        {
            if (ffe->syntaxState() == SyntaxLineEdit::Valid) {
                QModelIndex typeIndex = index.sibling(index.row(), ColumnListModel::COL_TYPE);
                model->setData(typeIndex, COL_CUSTOM, Qt::EditRole);
                model->setData(index, ffe->text(), Qt::EditRole);
            }
            else
            {
                ffe->setText(index.data().toString());
            }
        }

        if (index.data().toString().length() == 0)
        {
            QModelIndex typeIndex = index.sibling(index.row(), ColumnListModel::COL_TYPE);
            model->setData(typeIndex, index.data(ColumnListModel::OriginalType).toInt(), Qt::EditRole);

        }
    }
    else if (index.column() == ColumnListModel::COL_OCCURRENCE)
    {
        SyntaxLineEdit * sle = qobject_cast<SyntaxLineEdit *>(editor);
        bool ok = false;
        if (sle)
        {
            sle->checkInteger(index.data().toString());
            if (sle->syntaxState() == SyntaxLineEdit::Valid)
                ok = true;
        }

        if (ok)
        {
            QModelIndex typeIndex = index.sibling(index.row(), ColumnListModel::COL_TYPE);
            model->setData(typeIndex, COL_CUSTOM, Qt::EditRole);
            model->setData(index, sle->text(), Qt::EditRole);
        }
        else if (sle)
        {
            sle->setText(index.data().toString());
        }

        if (index.data().toString().length() == 0)
        {
            QModelIndex typeIndex = index.sibling(index.row(), ColumnListModel::COL_TYPE);
            model->setData(typeIndex, index.data(ColumnListModel::OriginalType).toInt(), Qt::EditRole);

        }
    }
    else
        QStyledItemDelegate::setModelData(editor, model, index);
}

void ColumnTypeDelegate::updateEditorGeometry(QWidget *editor,
                                           const QStyleOptionViewItem &option,
                                           const QModelIndex &/* index */) const
{
    editor->setGeometry(option.rect);
}

ColumnListModel::ColumnListModel(QObject * parent):
    QAbstractTableModel(parent)
{
    populate();
}

QVariant ColumnListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (section > ColumnListModel::COL_RESOLVED || orientation != Qt::Horizontal ||
        role != Qt::DisplayRole)
        return QVariant();

    return headerTitle(section);
}

int ColumnListModel::rowCount(const QModelIndex &/*parent*/) const
{
    return static_cast<int>(store_.count());
}

int ColumnListModel::columnCount(const QModelIndex &/*parent*/) const
{
    return ColumnListModel::COL_RESOLVED + 1;
}

QString ColumnListModel::headerTitle(int section) const
{
    switch (section)
    {
        case ColumnListModel::COL_DISPLAYED:
            return tr("Displayed");
        case ColumnListModel::COL_TITLE:
            return tr("Title");
        case ColumnListModel::COL_TYPE:
            return tr("Type");
        case ColumnListModel::COL_FIELDS:
            return tr("Fields");
        case ColumnListModel::COL_OCCURRENCE:
            return tr("Field Occurrence");
        case ColumnListModel::COL_RESOLVED:
            return tr("Resolved");
    }

    return QString();
}

void ColumnListModel::populate()
{
    store_.clear();

    int nr = 0;

    for (GList *cur = g_list_first(prefs.col_list); cur != NULL && cur->data != NULL; cur = cur->next) {
        fmt_data *cfmt = (fmt_data *) cur->data;
        ListElement ne;
        ne.nr = nr;
        ne.displayed = cfmt->visible;
        ne.title = cfmt->title;
        ne.type = ne.originalType = cfmt->fmt;
        ne.customFields = cfmt->custom_fields;
        ne.occurrence = cfmt->custom_occurrence;
        ne.resolved = cfmt->resolved;

        nr++;
        store_ << ne;
    }
}

QVariant ColumnListModel::data(const QModelIndex &index, int role) const
{
    if (! index.isValid() || index.column() >= store_.count())
        return QVariant();

    ListElement ne = store_.at(index.row());

    if (role == Qt::DisplayRole)
    {
        switch (index.column())
        {
            case COL_DISPLAYED:
            case COL_RESOLVED:
                return QVariant();
            case ColumnListModel::COL_TITLE:
                return ne.title;
            case ColumnListModel::COL_TYPE:
                return col_format_desc(ne.type);
            case ColumnListModel::COL_FIELDS:
                return ne.customFields;
            case ColumnListModel::COL_OCCURRENCE:
                return ne.customFields.length() > 0 ? QVariant::fromValue(ne.occurrence) : QVariant();
        }
    }
    else if (role == Qt::CheckStateRole)
    {
        if (index.column() == COL_DISPLAYED)
        {
            return ne.displayed ? Qt::Checked : Qt::Unchecked;
        }
        else if (index.column() == COL_RESOLVED)
        {
            QModelIndex fieldsIndex = index.sibling(index.row(), ColumnListModel::COL_FIELDS);
            if (column_prefs_custom_resolve(fieldsIndex.data().toString().toUtf8().constData())) {
                return ne.resolved ? Qt::Checked : Qt::Unchecked;
            }
        }
    }
    else if (role == Qt::ToolTipRole)
    {
        if (index.column() == COL_RESOLVED)
        {
            return tr("<html>Show human-readable strings instead of raw values for fields. Only applicable to custom columns with fields that have value strings.</html>");
        }
    }
    else if (role == OriginalType)
        return QVariant::fromValue(ne.originalType);
    else if (role == DisplayedState)
        return QVariant::fromValue(ne.displayed);

    return QVariant();
}

Qt::ItemFlags ColumnListModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags defaultFlags = QAbstractTableModel::flags(index);
    if (index.isValid() && index.row() < store_.count())
    {
        ListElement ne = store_.at(index.row());

        Qt::ItemFlags flags = Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled | defaultFlags;

        if (index.column() == COL_DISPLAYED || index.column() == COL_RESOLVED) {
            flags |= Qt::ItemIsUserCheckable;
        } else {
            flags |= Qt::ItemIsEditable;
        }

        return flags;
    }
    else
        return Qt::ItemIsDropEnabled | defaultFlags;
}

QStringList ColumnListModel::mimeTypes() const
{
    return QStringList() << WiresharkMimeData::ColumnListMimeType;
}

QMimeData *ColumnListModel::mimeData(const QModelIndexList &indexes) const
{
    QMimeData *mimeData = new QMimeData;

    int row = -1;
    if (indexes.count() > 0)
        row = indexes.at(0).row();

    mimeData->setData(WiresharkMimeData::ColumnListMimeType, QString::number(row).toUtf8());
    return mimeData;
}

bool ColumnListModel::canDropMimeData(const QMimeData *data,
    Qt::DropAction /* action */, int /* row */, int /* column */, const QModelIndex &parent) const
{
    if (parent.isValid() || ! data->hasFormat(WiresharkMimeData::ColumnListMimeType))
        return false;

    return true;
}

bool ColumnListModel::dropMimeData(const QMimeData *data,
    Qt::DropAction action, int row, int column, const QModelIndex &parent)
{
    int moveTo;

    if (!canDropMimeData(data, action, row, column, parent))
        return false;

    if (action == Qt::IgnoreAction || parent.isValid())
        return true;

    if (row != -1)
        moveTo = row;
    else
        moveTo = rowCount(QModelIndex());

    bool ok = false;
    int moveFrom = QString(data->data(WiresharkMimeData::ColumnListMimeType)).toInt(&ok);
    if (! ok)
        return false;

    if (moveFrom < moveTo)
        moveTo = moveTo - 1;

    if (moveTo >= store_.count())
        moveTo = static_cast<int>(store_.count()) - 1;

    beginResetModel();
    store_.move(moveFrom, moveTo);
    endResetModel();

    return true;
}

Qt::DropActions ColumnListModel::supportedDropActions() const
{
    return Qt::MoveAction;
}

bool ColumnListModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (!index.isValid() || ! value.isValid())
        return false;

    bool change = false;
    if (role == Qt::CheckStateRole && index.column() == ColumnListModel::COL_DISPLAYED)
    {
        store_[index.row()].displayed = value.toInt() == Qt::Checked ? true : false;
        change = true;
    }
    else if (index.column() == ColumnListModel::COL_TYPE)
    {
        bool ok = false;
        int val = value.toInt(&ok);
        if (ok)
            store_[index.row()].type = val;
    }
    else if (index.column() == ColumnListModel::COL_TITLE)
    {
        store_[index.row()].title = value.toString();
    }
    else if (index.column() == ColumnListModel::COL_FIELDS)
    {
        store_[index.row()].customFields = value.toString();
    }
    else if (index.column() == ColumnListModel::COL_OCCURRENCE)
    {
        bool ok = false;
        int val = value.toInt(&ok);
        if (ok)
            store_[index.row()].occurrence = val;
    }
    else if (role == Qt::CheckStateRole && index.column() == ColumnListModel::COL_RESOLVED)
    {
        store_[index.row()].resolved = value.toInt() == Qt::Checked ? true : false;
    }

    if (change)
        emit dataChanged(index, index);

    return change;
}

void ColumnListModel::saveColumns()
{
    GList *new_col_list = Q_NULLPTR;

    for (int row = 0; row < store_.count(); row++)
    {
        fmt_data * cfmt = g_new0(fmt_data, 1);
        ListElement elem = store_.at(row);

        cfmt->title = qstring_strdup(elem.title);
        cfmt->visible = elem.displayed;
        cfmt->fmt = elem.type;
        cfmt->resolved = TRUE;
        if (cfmt->fmt == COL_CUSTOM)
        {
            cfmt->custom_fields = qstring_strdup(elem.customFields);
            cfmt->custom_occurrence = elem.occurrence;
            cfmt->resolved = elem.resolved;
        }

        new_col_list = g_list_append(new_col_list, cfmt);
    }

    while (prefs.col_list)
        column_prefs_remove_link(prefs.col_list);

    prefs.col_list = new_col_list;
}

void ColumnListModel::addEntry()
{
    beginInsertRows(QModelIndex(), rowCount(), rowCount());
    ListElement elem;
    elem.nr = rowCount();
    elem.title = tr("New Column");
    elem.displayed = true;
    elem.type = elem.originalType = COL_NUMBER;
    elem.occurrence = 0;
    elem.customFields = QString();
    elem.resolved = true;
    store_ << elem;
    endInsertRows();
}

void ColumnListModel::deleteEntry(int row)
{
    beginRemoveRows(QModelIndex(), row, row);
    store_.removeAt(row);
    endRemoveRows();
}

void ColumnListModel::reset()
{
    beginResetModel();
    populate();
    endResetModel();
}
