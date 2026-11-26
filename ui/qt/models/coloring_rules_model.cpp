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

#include <wsutil/filesystem.h>

#include "ui/ws_ui_util.h" //for color_filter_add_cb
#include <app/application_flavor.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/utils/wireshark_mime_data.h>

#include <QApplication>
#include <QMimeData>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

ColoringRuleItem::ColoringRuleItem(bool enabled, QString name, QString filter, QColor foreground, QColor background, ColoringRuleItem* parent)
    : ModelHelperTreeItem<ColoringRuleItem>(parent),
    enabled_(enabled),
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
    enabled_(colorf->enabled),
    name_(colorf->filter_name),
    filter_(colorf->filter_text),
    foreground_(ColorUtils::fromColorT(colorf->fg_color)),
    background_(ColorUtils::fromColorT(colorf->bg_color)),
    source_profile_(colorf->source_profile ? QString::fromUtf8(colorf->source_profile) : QString())
{
}

ColoringRuleItem::ColoringRuleItem(const ColoringRuleItem& item)
    : ModelHelperTreeItem<ColoringRuleItem>(item.parent_),
    enabled_(item.enabled_),
    name_(item.name_),
    filter_(item.filter_),
    foreground_(item.foreground_),
    background_(item.background_),
    source_profile_(item.source_profile_)
{
}

ColoringRuleItem& ColoringRuleItem::operator=(ColoringRuleItem& rhs)
{
    enabled_ = rhs.enabled_;
    name_ = rhs.name_;
    filter_ = rhs.filter_;
    foreground_ = rhs.foreground_;
    background_ = rhs.background_;
    source_profile_ = rhs.source_profile_;
    return *this;
}

// Callback for color_filters_clone.
void
color_filter_add_cb(color_filter_t *colorf, void *user_data)
{
    ColoringRulesModel *model = (ColoringRulesModel*)user_data;

    if (model == NULL)
        return;

    model->addColor(colorf);
}

// Appends a rule to a QList<ColoringRuleItem*>, e.g. when reading the
// inherited, the hidden own or the default rules.
static void
color_filter_append_item_cb(color_filter_t *colorf, void *user_data)
{
    QList<ColoringRuleItem*> *rules = static_cast<QList<ColoringRuleItem*> *>(user_data);

    rules->append(new ColoringRuleItem(colorf, NULL));
    color_filter_delete(colorf);
}

ColoringRulesModel::ColoringRulesModel(QColor defaultForeground, QColor defaultBackground, QObject *parent) :
    InheritedRulesModel<ColoringRuleItem>(COLORING_RULES_FILE_NAME, parent),
    conversation_colors_(NULL),
    defaultForeground_(defaultForeground),
    defaultBackground_(defaultBackground),
    own_from_globals_(false),
    own_file_exists_(false)
{
    root_ = new ColoringRuleItem(true, "", "", QColor(), QColor(), NULL);
    color_filters_clone(this, color_filter_add_cb);

    QByteArray path = ownFilePath().toUtf8();
    own_file_exists_ = file_exists(path.constData());

    // Without a file, a profile using its own rules only uses the default rules
    own_from_globals_ = inherit_mode_ == PROFILE_INHERIT_PROFILE_ONLY && !own_file_exists_;

    if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY) {
        // The own rules are not in use, but are kept and written as they are
        if (own_file_exists_) {
            char *err_msg = NULL;
            if (!color_filters_import(path.constData(), &hidden_own_rules_, &err_msg, color_filter_append_item_cb)) {
                g_free(err_msg);
            }
        }
    }

    initInherited();
    own_edited_ = false;
}

ColoringRulesModel::~ColoringRulesModel()
{
    qDeleteAll(default_rules_);
    color_filter_list_delete(&conversation_colors_);
}

QString ColoringRulesModel::ownFilePath() const
{
    // coloring_rules.jsonc, or else the legacy colorfilters
    const char *prefix = application_configuration_environment_prefix();
    char *path = get_persconffile_path(COLORING_RULES_FILE_NAME, true, prefix);
    if (!file_exists(path)) {
        g_free(path);
        path = get_persconffile_path(COLORFILTERS_FILE_NAME, true, prefix);
    }
    return gchar_free_to_qstring(path);
}

bool ColoringRulesModel::ownFileHasRules() const
{
    QString path = ownFilePath();
    if (!file_exists(path.toUtf8().constData()))
        return false;

    // A file that can't be read has no rules to keep
    QList<ColoringRuleItem*> rules;
    char *err_msg = NULL;
    if (!color_filters_import(path.toUtf8().constData(), &rules, &err_msg, color_filter_append_item_cb))
        g_free(err_msg);
    bool has_rules = !rules.isEmpty();
    qDeleteAll(rules);
    return has_rules;
}

QList<ColoringRuleItem*> ColoringRulesModel::readInherited(profile_inherit_e mode)
{
    QList<ColoringRuleItem*> rules;
    char *err_msg = NULL;
    if (!color_filters_read_inherited(mode, &rules, &err_msg, color_filter_append_item_cb,
                                      application_configuration_environment_prefix())) {
        g_free(err_msg);
    }
    return rules;
}

void ColoringRulesModel::leavingInheritMode(profile_inherit_e mode)
{
    if (mode == PROFILE_INHERIT_PROFILE_ONLY && own_from_globals_ && !own_edited_) {
        // Unchanged default rules are not the profile's own; inherit instead
        default_rules_ << takeOwnRows();
    }
}

void ColoringRulesModel::enteredInheritMode(profile_inherit_e mode)
{
    if (mode == PROFILE_INHERIT_PROFILE_ONLY && ownRowCount() == 0 && !own_file_exists_) {
        // Without own rules or a file, the profile uses the default rules,
        // as when loading them
        if (default_rules_.isEmpty()) {
            char *err_msg = NULL;
            if (!color_filters_read_globals(&default_rules_, &err_msg, color_filter_append_item_cb,
                                            application_configuration_environment_prefix())) {
                g_free(err_msg);
            }
        }
        insertOwnRows(default_rules_);
        own_from_globals_ = true;
        own_edited_ = false;
    }
}

GSList *ColoringRulesModel::createColorFilterList()
{
    QList<ColoringRuleItem*> rules;
    for (int row = 0; row < root_->childCount(); row++)
        rules << root_->child(row);
    return createColorFilterList(rules);
}

GSList *ColoringRulesModel::createColorFilterList(const QList<ColoringRuleItem*> &rules)
{
    GSList *cfl = NULL;
    for (ColoringRuleItem *rule : rules)
    {
        if (rule == NULL)
            continue;

        color_t fg = ColorUtils::toColorT(rule->foreground_);
        color_t bg = ColorUtils::toColorT(rule->background_);
        color_filter_t *colorf = color_filter_new(rule->name_.toUtf8().constData(),
                                                  rule->filter_.toUtf8().constData(),
                                                  &bg, &fg, rule->enabled_);
        if (rule->isInherited())
            colorf->source_profile = g_strdup(rule->source_profile_.toUtf8().constData());
        cfl = g_slist_append(cfl, colorf);
    }

    return cfl;
}

void ColoringRulesModel::addColor(color_filter_t* colorf)
{
    if (!colorf) return;

    if (colorf->source_profile) {
        // Inherited rules are read by loadInherited(), including the ones an own rule hides
        color_filter_delete(colorf);
        return;
    }

    if (strstr(colorf->filter_name, CONVERSATION_COLOR_PREFIX) != NULL) {
        conversation_colors_ = g_slist_append(conversation_colors_, colorf);
    } else {
        // Added rules are own rules, which come before the inherited rules
        int count = ownRowCount();

        beginInsertRows(QModelIndex(), count, count);
        ColoringRuleItem* item = new ColoringRuleItem(colorf, root_);
        color_filter_delete(colorf);
        root_->insertChild(count, item);
        own_edited_ = true;
        endInsertRows();
    }
}

void ColoringRulesModel::addColor(bool enabled, QString filter, QColor foreground, QColor background)
{
    //add rule to top of the list
    own_edited_ = true;
    beginInsertRows(QModelIndex(), 0, 0);
    ColoringRuleItem* item = new ColoringRuleItem(enabled, tr("New coloring rule"), filter, foreground, background, root_);
    root_->prependChild(item);
    endInsertRows();
}


bool ColoringRulesModel::importColors(QString filename, QString& err)
{
    bool success = true;
    char* err_msg = NULL;
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
    char* err_msg = NULL;
    if (!color_filters_export(filename.toUtf8().constData(), cfl, false, application_flavor_name_proper(), &err_msg)) {
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
    char* err_msg = NULL;
    if (!color_filters_apply(conversation_colors_, cfl, &err_msg)) {
        err = gchar_free_to_qstring(err_msg);
        success = false;
    }
    // The profile's own rules are not used, but kept, when only the parent's rules are used
    GSList *write_cfl = cfl;
    GSList *hidden_cfl = NULL;
    if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY) {
        hidden_cfl = createColorFilterList(hidden_own_rules_);
        write_cfl = hidden_cfl;
    }
    // An own file without rules is written only if the rules it replaces
    // had rules: the file, or the default rules used without a file. A
    // profile without a file keeps using the default or inherited rules.
    bool has_own_rules = false;
    for (GSList *item = write_cfl; item; item = g_slist_next(item)) {
        if (((color_filter_t *)item->data)->source_profile == NULL) {
            has_own_rules = true;
            break;
        }
    }
    bool written = true;
    if (has_own_rules || (own_from_globals_ && inherit_mode_ == PROFILE_INHERIT_PROFILE_ONLY) || ownFileHasRules()) {
        written = color_filters_write(write_cfl, application_flavor_name_proper(), application_configuration_environment_prefix(), &err_msg);
    }
    color_filter_list_delete(&hidden_cfl);
    if (!written) {
        err = tr("Unable to save coloring rules: %1").arg(g_strerror(errno));
        success = false;
        g_free(err_msg);
    }
    color_filter_list_delete(&cfl);

    return success;
}

bool ColoringRulesModel::insertRows(int row, int count, const QModelIndex& parent)
{
    // sanity check insertion; new rules go into the own rules, before the inherited rules
    if (row < 0 || inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY)
        return false;
    row = qMin(row, ownRowCount());

    beginInsertRows(parent, row, row+(count-1));

    // Don't touch the inherited rows while inserting
    refreshing_inherited_ = true;
    own_edited_ = true;
    for (int i = row; i < row + count; i++)
    {
        ColoringRuleItem* item = new ColoringRuleItem(true, tr("New coloring rule"), "", defaultForeground_, defaultBackground_, root_);
        root_->insertChild(i, item);
        /* Automatically enable the new coloring rule */
        setData(index(i, colName, parent), Qt::Checked, Qt::CheckStateRole);
    }
    refreshing_inherited_ = false;

    endInsertRows();
    return true;
}

bool ColoringRulesModel::removeRows(int row, int count, const QModelIndex& parent)
{
    // Only own rules can be removed
    int own_count = ownRowCount();
    if (row < 0 || row >= own_count)
        return false;
    count = qMin(count, own_count - row);
    if (count <= 0)
        return false;

    own_edited_ = true;

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

    if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY)
        return false;

    ColoringRuleItem* dst_item = new ColoringRuleItem(*src_item);
    if (dst_item == NULL)
        return false;

    // A copy of an inherited rule is an own rule, which then hides the inherited one
    own_edited_ = true;
    dst_item->source_profile_.clear();
    dst_row = qMin(dst_row, ownRowCount());

    beginInsertRows(QModelIndex(), dst_row, dst_row);
    root_->insertChild(dst_row, dst_item);
    endInsertRows();

    return true;
}

Qt::ItemFlags ColoringRulesModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flags = QAbstractItemModel::flags(index);

    // Inherited rules are read-only
    if (index.isValid() && isInherited(index.row()))
        return inheritedFlags(index, flags);

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

    // The lock, italics and tool tip of an inherited rule
    bool handled;
    QVariant inherited_data = inheritedData(rule, index, role, &handled);
    if (handled)
        return inherited_data;

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
            return rule->enabled_ ? Qt::Checked : Qt::Unchecked;
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
    if (rule == NULL || rule->isInherited())
        return false;
    own_edited_ = true;

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
            rule->enabled_ = (value.toInt() == Qt::Checked) ? true : false;
            break;
        default:
            return false;
        }
        break;
    case Qt::BackgroundRole:
        if (!value.canConvert<QColor>())
            return false;

        rule->background_ = QColor(value.toString());
        break;
    case Qt::ForegroundRole:
        if (!value.canConvert<QColor>())
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
    return Qt::MoveAction | Qt::CopyAction;
}

QStringList ColoringRulesModel::mimeTypes() const
{
    return QStringList() << WiresharkMimeData::ColoringRulesMimeType;
}

QMimeData* ColoringRulesModel::mimeData(const QModelIndexList &indexes) const
{
    //if the list is empty, don't return an empty list
    if (indexes.count() == 0)
        return NULL;

    QMimeData *mimeData = new QMimeData();

    QJsonArray data;
    foreach (const QModelIndex & index, indexes)
    {
        if (index.column() == 0)
        {
            ColoringRuleItem * item = root_->child(index.row());
            if (item != nullptr) {
                QJsonObject entry;
                entry["enabled"] = item->enabled_;
                entry["name"] = item->name_;
                entry["filter"] = item->filter_;
                entry["foreground"] = QVariant::fromValue(item->foreground_).toString();
                entry["background"] = QVariant::fromValue(item->background_).toString();
                data.append(entry);
            }
        }
    }

    QJsonObject dataSet;
    dataSet["coloringrules"] = data;
    QByteArray encodedData = QJsonDocument(dataSet).toJson();

    mimeData->setData(WiresharkMimeData::ColoringRulesMimeType, encodedData);
    return mimeData;
}

bool ColoringRulesModel::dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent)
{
    //clear any previous dragDrop information
    dragDropRows_.clear();

    if (action == Qt::IgnoreAction)
        return true;

    if (!data->hasFormat(WiresharkMimeData::ColoringRulesMimeType) || column > 0)
        return false;

    int beginRow;

    if (row != -1)
        beginRow = row;
    else if (parent.isValid())
        beginRow = parent.row();
    else
        beginRow = rowCount();

    // Dropped rules become own rules, which come before the inherited rules
    beginRow = qMin(beginRow, ownRowCount());

    QList<QVariant> rules;

    QJsonDocument encodedData = QJsonDocument::fromJson(data->data(WiresharkMimeData::ColoringRulesMimeType));
    if (! encodedData.isObject() || ! encodedData.object().contains("coloringrules"))
        return false;

    QJsonArray dataArray = encodedData.object()["coloringrules"].toArray();

    for (int datarow = 0; datarow < dataArray.count(); datarow++)
    {
        QJsonObject entry = dataArray.at(datarow).toObject();

        if (! entry.contains("foreground") || ! entry.contains("background") || ! entry.contains("filter"))
            continue;

        QColor fgColor = entry["foreground"].toVariant().value<QColor>();
        QColor bgColor = entry["background"].toVariant().value<QColor>();

        ColoringRuleItem * item = new ColoringRuleItem(
                entry["enabled"].toVariant().toBool(),
                entry["name"].toString(),
                entry["filter"].toString(),
                fgColor,
                bgColor,
                root_);
        rules.append(VariantPointer<ColoringRuleItem>::asQVariant(item));
    }

    if (!insertRows(beginRow, static_cast<int>(rules.count()), QModelIndex())) {
        // Not while only the parent's rules are used
        for (const QVariant &rule : rules)
            delete VariantPointer<ColoringRuleItem>::asPtr(rule);
        return false;
    }
    for (int i = 0; i < rules.count(); i++) {
        QModelIndex idx = index(beginRow, 0, QModelIndex());
        setData(idx, rules[i], Qt::UserRole);
        beginRow++;
    }

    return true;
}

int ColoringRulesModel::columnCount(const QModelIndex&) const
{
    return colColoringRulesMax;
}
