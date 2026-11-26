/* tagging_rules_model.cpp
 *
 * Model for the Tagging Rules dialog
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "tagging_rules_model.h"

#include <wsutil/filesystem.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/utils/color_utils.h>

#include <QMimeData>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

// ---------------------------------------------------------------------------
// TaggingRuleItem
// ---------------------------------------------------------------------------

TaggingRuleItem::TaggingRuleItem(bool disabled, QString name, QString filter,
                                 QString tag_content, QString tag_url, QString comment,
                                 TaggingRuleItem *parent)
    : ModelHelperTreeItem<TaggingRuleItem>(parent),
      disabled_(disabled),
      name_(name),
      filter_(filter),
      tag_content_(tag_content),
      tag_url_(tag_url),
      comment_(comment)
{
}

TaggingRuleItem::TaggingRuleItem(tag_rule_t *rule, TaggingRuleItem *parent)
    : ModelHelperTreeItem<TaggingRuleItem>(parent),
      disabled_(rule->disabled),
      name_(rule->rule_name),
      filter_(rule->filter_text),
      tag_content_(rule->tag_content ? rule->tag_content : ""),
      tag_url_(rule->tag_url ? rule->tag_url : ""),
      comment_(rule->comment ? rule->comment : ""),
      source_profile_(rule->source_profile ? QString::fromUtf8(rule->source_profile) : QString())
{
}

TaggingRuleItem::TaggingRuleItem(const TaggingRuleItem &item)
    : ModelHelperTreeItem<TaggingRuleItem>(item.parent_),
      disabled_(item.disabled_),
      name_(item.name_),
      filter_(item.filter_),
      tag_content_(item.tag_content_),
      tag_url_(item.tag_url_),
      comment_(item.comment_),
      source_profile_(item.source_profile_)
{
}

TaggingRuleItem::~TaggingRuleItem()
{
}

TaggingRuleItem &TaggingRuleItem::operator=(TaggingRuleItem &rhs)
{
    disabled_    = rhs.disabled_;
    name_        = rhs.name_;
    filter_      = rhs.filter_;
    tag_content_ = rhs.tag_content_;
    tag_url_     = rhs.tag_url_;
    comment_     = rhs.comment_;
    source_profile_ = rhs.source_profile_;
    return *this;
}

// ---------------------------------------------------------------------------
// Clone callback — called by tag_rules_clone() for each rule in the active list
// ---------------------------------------------------------------------------

static void
tag_rule_add_cb(tag_rule_t *rule, void *user_data)
{
    TaggingRulesModel *model = static_cast<TaggingRulesModel *>(user_data);
    if (model == NULL)
        return;

    model->addRule(rule);
}

// ---------------------------------------------------------------------------
// TaggingRulesModel
// ---------------------------------------------------------------------------

TaggingRulesModel::TaggingRulesModel(QObject *parent)
    : InheritedRulesModel<TaggingRuleItem>(TAGRULES_FILE_NAME, parent)
{
    root_ = new TaggingRuleItem(false, QString(), QString(), QString(), QString(), QString(), NULL);
    tag_rules_clone(tag_rule_add_cb, this);
    initInherited();
}

TaggingRulesModel::~TaggingRulesModel()
{
}

QList<TaggingRuleItem*> TaggingRulesModel::readInherited(profile_inherit_e mode)
{
    QList<TaggingRuleItem*> rules;
    GSList *list = tag_rules_read_inherited(mode);
    for (GSList *r = list; r; r = g_slist_next(r)) {
        rules << new TaggingRuleItem((tag_rule_t *)r->data, NULL);
    }
    tag_rule_list_free(list);
    return rules;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

GSList *TaggingRulesModel::createTagRuleList()
{
    QList<TaggingRuleItem *> rules;
    for (int row = 0; row < root_->childCount(); row++)
        rules << root_->child(row);
    return createTagRuleList(rules);
}

GSList *TaggingRulesModel::createTagRuleList(const QList<TaggingRuleItem *> &rules)
{
    GSList *list = NULL;
    for (TaggingRuleItem *rule : rules) {
        if (rule == NULL)
            continue;

        QByteArray name_ba    = rule->name_.toUtf8();
        QByteArray filter_ba  = rule->filter_.toUtf8();
        QByteArray content_ba = rule->tag_content_.toUtf8();
        QByteArray url_ba     = rule->tag_url_.toUtf8();
        QByteArray comment_ba = rule->comment_.toUtf8();
        tag_rule_t *tr = tag_rule_new(
            name_ba.constData(),
            filter_ba.constData(),
            content_ba.constData(),
            rule->tag_url_.isEmpty() ? NULL : url_ba.constData(),
            rule->comment_.isEmpty() ? NULL : comment_ba.constData()
        );
        tr->disabled = rule->disabled_;
        if (rule->isInherited())
            tr->source_profile = g_strdup(rule->source_profile_.toUtf8().constData());
        list = g_slist_append(list, tr);
    }
    return list;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void TaggingRulesModel::addRule(bool disabled, const QString &name,
                                const QString &filter, const QString &tag_content,
                                const QString &tag_url, const QString &comment)
{
    beginInsertRows(QModelIndex(), 0, 0);
    TaggingRuleItem *item = new TaggingRuleItem(disabled, name, filter, tag_content, tag_url, comment, root_);
    root_->prependChild(item);
    endInsertRows();
}

void TaggingRulesModel::addRule(tag_rule_t *rule)
{
    if (!rule)
        return;

    if (rule->source_profile) {
        // Inherited rules are read by loadInherited(), including the ones an own rule hides
        tag_rule_delete(rule);
        return;
    }

    // Added rules are own rules, which come before the inherited rules
    int count = ownRowCount();
    beginInsertRows(QModelIndex(), count, count);
    TaggingRuleItem *item = new TaggingRuleItem(rule, root_);
    tag_rule_delete(rule);
    root_->insertChild(count, item);
    endInsertRows();
}

bool TaggingRulesModel::loadFromPath(const QString &path, QString &err)
{
    char *err_msg = NULL;
    GSList *list = tag_rules_read_path(path.toUtf8().constData(), &err_msg);
    if (!list && err_msg) {
        err = gchar_free_to_qstring(err_msg);
        return false;
    }

    beginResetModel();
    delete root_;
    qDeleteAll(hidden_own_rules_);
    hidden_own_rules_.clear();
    root_ = new TaggingRuleItem(false, QString(), QString(), QString(), QString(), QString(), NULL);
    for (GSList *r = list; r; r = g_slist_next(r)) {
        tag_rule_t *rule = (tag_rule_t *)r->data;
        // The own rules are kept, but not shown, when only the parent's rules are used
        if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY)
            hidden_own_rules_ << new TaggingRuleItem(rule, NULL);
        else
            root_->appendChild(new TaggingRuleItem(rule, root_));
    }
    tag_rule_list_free(list);
    endResetModel();
    return true;
}

bool TaggingRulesModel::writeToPath(const QString &path, const tag_prefs_t *prefs, bool prefs_changed, QString &err)
{
    // The profile's own rules are kept, but not used, when only the parent's
    // rules are used. Without own rules there may be nothing to keep, and
    // then no file is created for no rules.
    bool has_own_rules = ownRowCount() > 0 || !hidden_own_rules_.isEmpty();
    if (!has_own_rules && !prefs_changed && !fileHasRules(path))
        return true;

    GSList *list = createTagRuleList();
    if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY)
        list = g_slist_concat(list, createTagRuleList(hidden_own_rules_));

    char *err_msg = NULL;
    bool ok = tag_rules_write_path(list, path.toUtf8().constData(), prefs, &err_msg);
    tag_rule_list_free(list);
    if (!ok)
        err = gchar_free_to_qstring(err_msg);
    return ok;
}

bool TaggingRulesModel::fileHasRules(const QString &path)
{
    QByteArray path_utf8 = path.toUtf8();
    if (!file_exists(path_utf8.constData()))
        return false;

    // A file that can't be read has no rules to keep
    char *err_msg = NULL;
    GSList *list = tag_rules_read_path(path_utf8.constData(), &err_msg);
    g_free(err_msg);
    bool has_rules = list != NULL;
    tag_rule_list_free(list);
    return has_rules;
}

bool TaggingRulesModel::importRules(const QString &path, QString &err)
{
    // Use read_path so the live active list is not disturbed — the import only
    // affects the dialog model; the live list is updated when the user clicks OK.
    char *err_msg = NULL;
    GSList *imported = tag_rules_read_path(path.toUtf8().constData(), &err_msg);
    if (err_msg) {
        err = gchar_free_to_qstring(err_msg);
        tag_rule_list_free(imported);
        return false;
    }

    // Append imported rules to the current model (don't replace existing rules).
    for (GSList *r = imported; r; r = g_slist_next(r)) {
        tag_rule_t *rule = (tag_rule_t *)r->data;
        addRule(rule); // addRule takes ownership and frees rule
    }
    g_slist_free(imported); // list spine only; items already consumed by addRule
    return true;
}

bool TaggingRulesModel::exportRules(const QString &path, QString &err)
{
    GSList *list = createTagRuleList();
    char *err_msg = NULL;
    bool ok = tag_rules_export_list(list, path.toUtf8().constData(), &err_msg);
    tag_rule_list_free(list);
    if (!ok) {
        err = gchar_free_to_qstring(err_msg);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// QAbstractItemModel overrides
// ---------------------------------------------------------------------------

Qt::ItemFlags TaggingRulesModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags f = QAbstractItemModel::flags(index);

    // Inherited rules are read-only
    if (index.isValid() && isInherited(index.row()))
        return inheritedFlags(index, f);

    switch (index.column()) {
    case colName:
        f |= (Qt::ItemIsUserCheckable | Qt::ItemIsEditable);
        break;
    case colFilter:
    case colTag:
    case colLink:
    case colComment:
        f |= Qt::ItemIsEditable;
        break;
    }

    if (index.isValid())
        f |= (Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled);
    else
        f |= Qt::ItemIsDropEnabled;

    return f;
}

QVariant TaggingRulesModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    TaggingRuleItem *rule = root_->child(index.row());
    if (rule == NULL)
        return QVariant();

    // The lock, italics and tool tip of an inherited rule
    bool handled;
    QVariant inherited_data = inheritedData(rule, index, role, &handled);
    if (handled)
        return inherited_data;

    switch (role) {
    case Qt::DisplayRole:
    case Qt::EditRole:
        switch (index.column()) {
        case colName:    return rule->name_;
        case colFilter:  return rule->filter_;
        case colTag:     return rule->tag_content_;
        case colLink:    return rule->tag_url_;
        case colComment: return rule->comment_;
        }
        break;
    case Qt::CheckStateRole:
        if (index.column() == colName)
            return rule->disabled_ ? Qt::Unchecked : Qt::Checked;
        break;
    case Qt::ForegroundRole:
        // Dim inherited rules
        if (rule->isInherited())
            return ColorUtils::disabledForeground();
        break;
    case TagContentRole:
        return rule->tag_content_;
    case TagUrlRole:
        return rule->tag_url_;
    }
    return QVariant();
}

bool TaggingRulesModel::setData(const QModelIndex &dataIndex, const QVariant &value, int role)
{
    if (!dataIndex.isValid())
        return false;

    if (data(dataIndex, role) == value)
        return true;

    TaggingRuleItem *rule = root_->child(dataIndex.row());
    if (rule == NULL || rule->isInherited())
        return false;

    QModelIndex topLeft     = dataIndex;
    QModelIndex bottomRight = dataIndex;

    switch (role) {
    case Qt::EditRole:
        switch (dataIndex.column()) {
        case colName:    rule->name_        = value.toString(); break;
        case colFilter:  rule->filter_      = value.toString(); break;
        case colTag:     rule->tag_content_ = value.toString(); break;
        case colLink:    rule->tag_url_     = value.toString(); break;
        case colComment: rule->comment_     = value.toString(); break;
        default:         return false;
        }
        break;
    case Qt::CheckStateRole:
        if (dataIndex.column() == colName)
            rule->disabled_ = (value.toInt() == Qt::Checked) ? false : true;
        else
            return false;
        break;
    case TagContentRole:
        rule->tag_content_ = value.toString();
        topLeft    = index(dataIndex.row(), colTag);
        bottomRight = index(dataIndex.row(), colTag);
        break;
    case TagUrlRole:
        rule->tag_url_ = value.toString();
        topLeft    = index(dataIndex.row(), colLink);
        bottomRight = index(dataIndex.row(), colLink);
        break;
    case Qt::UserRole: {
        TaggingRuleItem *new_rule = VariantPointer<TaggingRuleItem>::asPtr(value);
        *rule = *new_rule;
        topLeft    = index(dataIndex.row(), colName);
        bottomRight = index(dataIndex.row(), colComment);
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

QVariant TaggingRulesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    switch (static_cast<TaggingRulesColumn>(section)) {
    case colName:    return tr("Name");
    case colFilter:  return tr("Filter");
    case colTag:     return tr("Tag");
    case colLink:    return tr("Link");
    case colComment: return tr("Comment");
    default:         break;
    }
    return QVariant();
}

int TaggingRulesModel::columnCount(const QModelIndex &) const
{
    return colCount;
}

bool TaggingRulesModel::insertRows(int row, int count, const QModelIndex &parent)
{
    // New rules go into the own rules, before the inherited rules
    if (row < 0 || inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY)
        return false;
    row = qMin(row, ownRowCount());

    beginInsertRows(parent, row, row + (count - 1));
    // Don't touch the inherited rows while inserting
    refreshing_inherited_ = true;
    for (int i = row; i < row + count; i++) {
        TaggingRuleItem *item = new TaggingRuleItem(
            true, tr("New tagging rule"), QString(), QString(), QString(), QString(), root_);
        root_->insertChild(i, item);
        setData(index(i, colName, parent), Qt::Checked, Qt::CheckStateRole);
    }
    refreshing_inherited_ = false;
    endInsertRows();
    return true;
}

bool TaggingRulesModel::removeRows(int row, int count, const QModelIndex &parent)
{
    // Only own rules can be removed
    int own_count = ownRowCount();
    if (row < 0 || row >= own_count)
        return false;
    count = qMin(count, own_count - row);
    if (count <= 0)
        return false;

    beginRemoveRows(parent, row, row + (count - 1));
    for (int i = 0; i < count; i++)
        root_->removeChild(row);
    endRemoveRows();
    return true;
}

// ---------------------------------------------------------------------------
// Drag-and-drop
// ---------------------------------------------------------------------------

Qt::DropActions TaggingRulesModel::supportedDropActions() const
{
    return Qt::MoveAction | Qt::CopyAction;
}

QStringList TaggingRulesModel::mimeTypes() const
{
    return QStringList() << WiresharkMimeData::TaggingRulesMimeType;
}

QMimeData *TaggingRulesModel::mimeData(const QModelIndexList &indexes) const
{
    if (indexes.count() == 0)
        return NULL;

    QMimeData *mimeData = new QMimeData();

    QJsonArray data;
    foreach (const QModelIndex &idx, indexes) {
        if (idx.column() == 0) {
            TaggingRuleItem *item = root_->child(idx.row());
            if (item != nullptr) {
                QJsonObject entry;
                entry["disabled"]    = item->disabled_;
                entry["name"]        = item->name_;
                entry["filter"]      = item->filter_;
                entry["tag_content"] = item->tag_content_;
                entry["tag_url"]     = item->tag_url_;
                entry["comment"]     = item->comment_;
                data.append(entry);
            }
        }
    }

    QJsonObject dataSet;
    dataSet["taggingrules"] = data;
    QByteArray encodedData = QJsonDocument(dataSet).toJson();

    mimeData->setData(WiresharkMimeData::TaggingRulesMimeType, encodedData);
    return mimeData;
}

bool TaggingRulesModel::dropMimeData(const QMimeData *data, Qt::DropAction action,
                                     int row, int column, const QModelIndex &parent)
{
    if (action == Qt::IgnoreAction)
        return true;

    if (!data->hasFormat(WiresharkMimeData::TaggingRulesMimeType) || column > 0)
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

    QJsonDocument encodedData = QJsonDocument::fromJson(
        data->data(WiresharkMimeData::TaggingRulesMimeType));
    if (!encodedData.isObject() || !encodedData.object().contains("taggingrules"))
        return false;

    QJsonArray dataArray = encodedData.object()["taggingrules"].toArray();

    QList<QVariant> rules;
    for (int datarow = 0; datarow < dataArray.count(); datarow++) {
        QJsonObject entry = dataArray.at(datarow).toObject();

        if (!entry.contains("name") || !entry.contains("filter"))
            continue;

        TaggingRuleItem *item = new TaggingRuleItem(
            entry["disabled"].toVariant().toBool(),
            entry["name"].toString(),
            entry["filter"].toString(),
            entry["tag_content"].toString(),
            entry["tag_url"].toString(),
            entry["comment"].toString(),
            root_);
        rules.append(VariantPointer<TaggingRuleItem>::asQVariant(item));
    }

    insertRows(beginRow, static_cast<int>(rules.count()), QModelIndex());
    for (int i = 0; i < rules.count(); i++) {
        QModelIndex idx = index(beginRow, 0, QModelIndex());
        setData(idx, rules[i], Qt::UserRole);
        delete VariantPointer<TaggingRuleItem>::asPtr(rules[i]);
        beginRow++;
    }

    return true;
}
