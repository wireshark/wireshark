/* coloring_rules_model.cpp
 * Data model for coloring rules.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "coloring_rules_model.h"

#include <errno.h>

#include "ui/ws_ui_util.h" //for color_filter_add_cb

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>

#include <QMimeData>


static const QString new_rule_name_ = QObject::tr("New coloring rule");
static const QString color_rule_mime_type_ = "application/x-wireshark-coloring-rules";

ColoringRuleItem::ColoringRuleItem(bool disabled, QString name, QString filter, QColor foreground, QColor background, ColoringRuleItem* parent)
    : ModelHelperTreeItem<ColoringRuleItem>(parent),
    disabled_(disabled),
    name_(name),
    filter_(filter),
    foreground_(foreground),
    background_(background)
{
}

ColoringRuleItem::~ColoringRuleItem()
{

}

ColoringRuleItem::ColoringRuleItem(color_filter_t *colorf, ColoringRuleItem* parent)
    : ModelHelperTreeItem<ColoringRuleItem>(parent),
    disabled_(colorf->disabled),
    name_(colorf->filter_name),
    filter_(colorf->filter_text),
    foreground_(ColorUtils::fromColorT(colorf->fg_color)),
    background_(ColorUtils::fromColorT(colorf->bg_color))
{
}

ColoringRuleItem::ColoringRuleItem(const ColoringRuleItem& item)
    : ModelHelperTreeItem<ColoringRuleItem>(item.parent_),
    disabled_(item.disabled_),
    name_(item.name_),
    filter_(item.filter_),
    foreground_(item.foreground_),
    background_(item.background_)
{
}

// Callback for color_filters_clone.
void
color_filter_add_cb(color_filter_t *colorf, gpointer user_data)
{
    ColoringRulesModel *model = (ColoringRulesModel*)user_data;

    if (model == NULL)
        return;

    model->addColor(colorf);
}

ColoringRulesModel::ColoringRulesModel(QColor defaultForeground, QColor defaultBackground, QObject *parent) :
    QAbstractItemModel(parent),
    root_(new ColoringRuleItem(false, "", "", QColor(), QColor(), NULL)),
    conversation_colors_(NULL),
    defaultForeground_(defaultForeground),
    defaultBackground_(defaultBackground)

{
    color_filters_clone(this, color_filter_add_cb);
}

ColoringRulesModel::~ColoringRulesModel()
{
    delete root_;
    color_filter_list_delete(&conversation_colors_);
}

GSList *ColoringRulesModel::createColorFilterList()
{
    GSList *cfl = NULL;
    for (int row = 0; row < root_->childCount(); row++)
    {
        ColoringRuleItem* rule = root_->child(row);
        if (rule == NULL)
            continue;

        color_t fg = ColorUtils::toColorT(rule->foreground_);
        color_t bg = ColorUtils::toColorT(rule->background_);
        color_filter_t *colorf = color_filter_new(rule->name_.toUtf8().constData(),
                                                  rule->filter_.toUtf8().constData(),
                                                  &bg, &fg, rule->disabled_);
        cfl = g_slist_append(cfl, colorf);
    }

    return cfl;
}

void ColoringRulesModel::addColor(color_filter_t* colorf)
{
    if (!colorf) return;

    if(strstr(colorf->filter_name, CONVERSATION_COLOR_PREFIX) != NULL) {
        conversation_colors_ = g_slist_append(conversation_colors_, colorf);
    } else {
        int count = root_->childCount();

        beginInsertRows(QModelIndex(), count, count);
        ColoringRuleItem* item = new ColoringRuleItem(colorf, root_);
        root_->appendChild(item);
        endInsertRows();
    }
}

void ColoringRulesModel::addColor(bool disabled, QString filter, QColor foreground, QColor background)
{
    //add rule to top of the list
    beginInsertRows(QModelIndex(), 0, 0);
    ColoringRuleItem* item = new ColoringRuleItem(disabled, new_rule_name_, filter, foreground, background, root_);
    root_->prependChild(item);
    endInsertRows();
}


bool ColoringRulesModel::importColors(QString filename, QString& err)
{
    bool success = true;
    gchar* err_msg = NULL;
    if (!color_filters_import(filename.toUtf8().constData(), this, &err_msg, color_filter_add_cb)) {
        err = gchar_free_to_qstring(err_msg);
        success = false;
    }

    return success;
}

bool ColoringRulesModel::exportColors(QString filename, QString& err)
{
    GSList *cfl = createColorFilterList();
    bool success = true;
    gchar* err_msg = NULL;
    if (!color_filters_export(filename.toUtf8().constData(), cfl, FALSE, &err_msg)) {
        err = gchar_free_to_qstring(err_msg);
        success = false;
    }
    color_filter_list_delete(&cfl);

    return success;
}

bool ColoringRulesModel::writeColors(QString& err)
{
    GSList *cfl = createColorFilterList();
    bool success = true;
    gchar* err_msg = NULL;
    if (!color_filters_apply(conversation_colors_, cfl, &err_msg)) {
        err = gchar_free_to_qstring(err_msg);
        success = false;
    }
    if (!color_filters_write(cfl, &err_msg)) {
        err = QString(tr("Unable to save coloring rules: %1").arg(g_strerror(errno)));
        success = false;
        g_free(err_msg);
    }
    color_filter_list_delete(&cfl);

    return success;
}

bool ColoringRulesModel::insertRows(int row, int count, const QModelIndex& parent)
{
    // sanity check insertion
    if (row < 0 )
        return false;

    beginInsertRows(parent, row, row+(count-1));

    for (int i = row; i < row + count; i++)
    {
        ColoringRuleItem* item = new ColoringRuleItem(true, new_rule_name_, "", defaultForeground_, defaultBackground_, root_);
        root_->insertChild(i, item);
    }

    endInsertRows();
    return true;
}

bool ColoringRulesModel::removeRows(int row, int count, const QModelIndex& parent)
{
    if (row < 0 )
        return false;

    beginRemoveRows(parent, row, row+(count-1));
    for (int i = row; i < row + count; i++)
    {
        root_->removeChild(row);
    }
    endRemoveRows();

    return true;
}

bool ColoringRulesModel::copyRow(int dst_row, int src_row)
{
    if (src_row < 0 || src_row >= rowCount() || dst_row < 0 || dst_row >= rowCount()) {
        return false;
    }

    ColoringRuleItem* src_item = root_->child(src_row);
    if (src_item == NULL)
        return false;

    ColoringRuleItem* dst_item = new ColoringRuleItem(*src_item);
    if (dst_item == NULL)
        return false;

    beginInsertRows(QModelIndex(), dst_row, dst_row);
    root_->insertChild(dst_row, dst_item);
    endInsertRows();

    return true;
}

Qt::ItemFlags ColoringRulesModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flags = QAbstractItemModel::flags(index);
    switch (index.column())
    {
    case colName:
        flags |= (Qt::ItemIsUserCheckable|Qt::ItemIsEditable);
        break;
    case colFilter:
        flags |= Qt::ItemIsEditable;
        break;
    }

    if (index.isValid())
        flags |= (Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled);
    else
        flags |= Qt::ItemIsDropEnabled;

    return flags;
}


QVariant ColoringRulesModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    ColoringRuleItem* rule = root_->child(index.row());
    if (rule == NULL)
        return QVariant();

    switch (role)
    {
    case Qt::DisplayRole:
    case Qt::EditRole:
        switch(index.column())
        {
        case colName:
            return rule->name_;
        case colFilter:
            return rule->filter_;
        }
        break;
    case Qt::CheckStateRole:
        switch(index.column())
        {
        case colName:
            return rule->disabled_ ? Qt::Unchecked : Qt::Checked;
        }
        break;
    case Qt::BackgroundRole:
        return rule->background_;
    case Qt::ForegroundRole:
        return rule->foreground_;
    }
    return QVariant();
}

bool ColoringRulesModel::setData(const QModelIndex &dataIndex, const QVariant &value, int role)
{
    if (!dataIndex.isValid())
        return false;

    if (data(dataIndex, role) == value) {
        // Data appears unchanged, do not do additional checks.
        return true;
    }

    ColoringRuleItem* rule = root_->child(dataIndex.row());
    if (rule == NULL)
        return false;

    QModelIndex topLeft = dataIndex,
                bottomRight = dataIndex;

    switch (role)
    {
    case Qt::EditRole:
        switch (dataIndex.column())
        {
        case colName:
            rule->name_ = value.toString();
            break;
        case colFilter:
            rule->filter_ = value.toString();
            break;
        default:
            return false;
        }
        break;
    case Qt::CheckStateRole:
        switch (dataIndex.column())
        {
        case colName:
            rule->disabled_ = (value == Qt::Checked) ? false : true;
            break;
        default:
            return false;
        }
        break;
    case Qt::BackgroundRole:
        if (!value.canConvert(QVariant::Color))
            return false;

        rule->background_ = QColor(value.toString());
        break;
    case Qt::ForegroundRole:
        if (!value.canConvert(QVariant::Color))
            return false;

        rule->foreground_ = QColor(value.toString());
        break;
    case Qt::UserRole:
        {
        ColoringRuleItem* new_rule = VariantPointer<ColoringRuleItem>::asPtr(value);
        *rule = *new_rule;
        topLeft = index(dataIndex.row(), colName);
        bottomRight = index(dataIndex.row(), colFilter);
        break;
        }
    default:
        return false;
    }

    QVector<int> roles;
    roles << role;

    emit dataChanged(topLeft, bottomRight, roles);

    return true;

}

QVariant ColoringRulesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    switch ((ColoringRulesColumn)section) {
    case colName:
        return tr("Name");
    case colFilter:
        return tr("Filter");
    default:
        break;
    }

    return QVariant();
}

Qt::DropActions ColoringRulesModel::supportedDropActions() const
{
    return Qt::MoveAction;
}

QStringList ColoringRulesModel::mimeTypes() const
{
    //Just use plain text to transport data
    QStringList types;
    types << color_rule_mime_type_;
    return types;
}

QMimeData* ColoringRulesModel::mimeData(const QModelIndexList &indexes) const
{
    //if the list is empty, don't return an empty list
    if (indexes.count() == 0)
        return NULL;

    QMimeData *mimeData = new QMimeData();
    QByteArray encodedData;

    QDataStream stream(&encodedData, QIODevice::WriteOnly);

    foreach (const QModelIndex &index, indexes) {
        //use first column as "filter"
        if (index.column() == 0) {
            //Retrieve "native" data to save lots of conversions in the process
            ColoringRuleItem* item = root_->child(index.row());

            stream << item->disabled_ << item->name_ << item->filter_ << item->foreground_ << item->background_;
        }
    }

    mimeData->setData(color_rule_mime_type_, encodedData);
    return mimeData;
}

bool ColoringRulesModel::dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent)
{
    //clear any previous dragDrop information
    dragDropRows_.clear();

    if (action == Qt::IgnoreAction)
        return true;

    if (!data->hasFormat(color_rule_mime_type_))
        return false;

    if (column > 0)
        return false;

    int beginRow;

    if (row != -1)
        beginRow = row;
    else if (parent.isValid())
        beginRow = parent.row();
    else
        beginRow = rowCount();

    bool disabled;
    QString name;
    QString filter;
    QColor foreground;
    QColor background;
    ColoringRuleItem* item;
    QList<QVariant> rules;

    QByteArray encodedData = data->data(color_rule_mime_type_);
    QDataStream stream(&encodedData, QIODevice::ReadOnly);
    int rows = 0;

    while (!stream.atEnd()) {
        stream >> disabled >> name >> filter >> foreground >> background;

        item = new ColoringRuleItem(disabled, name, filter, foreground, background, root_);
        rules.append(VariantPointer<ColoringRuleItem>::asQVariant(item));
        ++rows;
    }

    insertRows(beginRow, rows, QModelIndex());
    for (int i = 0; i < rules.count(); i++) {
        QModelIndex idx = index(beginRow, 0, QModelIndex());
        setData(idx, rules[i], Qt::UserRole);
        beginRow++;
    }

    return true;
}

QModelIndex ColoringRulesModel::index(int row, int column, const QModelIndex &parent) const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    ColoringRuleItem *parent_item, *child_item;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<ColoringRuleItem*>(parent.internalPointer());

    Q_ASSERT(parent_item);

    child_item = parent_item->child(row);
    if (child_item) {
        return createIndex(row, column, child_item);
    }

    return QModelIndex();
}

QModelIndex ColoringRulesModel::parent(const QModelIndex& indexItem) const
{
    if (!indexItem.isValid())
        return QModelIndex();

    ColoringRuleItem* item = static_cast<ColoringRuleItem*>(indexItem.internalPointer());
    if (item != NULL) {
        ColoringRuleItem* parent_item = item->parentItem();
        if (parent_item != NULL) {
            if (parent_item == root_)
                return QModelIndex();

            return createIndex(parent_item->row(), 0, parent_item);
        }
    }

    return QModelIndex();
}

int ColoringRulesModel::rowCount(const QModelIndex& parent) const
{
    ColoringRuleItem *parent_item;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<ColoringRuleItem*>(parent.internalPointer());

    if (parent_item == NULL)
        return 0;

    return parent_item->childCount();
}

int ColoringRulesModel::columnCount(const QModelIndex&) const
{
    return colColoringRulesMax;
}

/* * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
