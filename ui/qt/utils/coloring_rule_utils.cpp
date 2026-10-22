/* coloring_rule_utils.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/coloring_rule_utils.h>

#include <epan/color_filters.h>
#include <epan/ftypes/ftypes.h>

#include <ui/qt/models/coloring_rules_model.h>
#include <ui/qt/models/packet_list_record.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/proto_node.h>

#include <QApplication>
#include <QPalette>

namespace {

struct ColoringRuleGroup {
    const field_info *name = nullptr;
    const field_info *filter = nullptr;
    bool disabled = false;
};

struct ColoringRuleHfIds {
    int name;
    int filter;
    int disabled;
};

// Registered by the Frame dissector. Looked up on first use, which is
// always after epan registration because the model only holds trees then.
const ColoringRuleHfIds &coloringRuleHfIds()
{
    static const ColoringRuleHfIds ids = {
        proto_registrar_get_id_byname("frame.coloring_rule.name"),
        proto_registrar_get_id_byname("frame.coloring_rule.string"),
        proto_registrar_get_id_byname("frame.coloring_rule.disabled"),
    };
    return ids;
}

// Items that belong to an entry besides its name item. An id of -1 (no
// field, or a field not registered) never belongs to an entry.
bool isColoringRuleMember(int id)
{
    const ColoringRuleHfIds &ids = coloringRuleHfIds();
    return id >= 0 && (id == ids.filter || id == ids.disabled);
}

// Reads one entry from its name item and the items that belong to it: the
// children of @p parent from row @p first on, up to the first item that is
// not a string or disabled item. In the nested shape @p parent is the name
// item itself, in the flat one the name item's parent.
void readColoringRuleGroup(const ProtoNode *name_node, const ProtoNode *parent, int first,
                           ColoringRuleGroup *group)
{
    const ColoringRuleHfIds &ids = coloringRuleHfIds();
    group->name = name_node->fieldInfo();
    for (int row = first; parent && row < parent->childrenCount(); row++) {
        const ProtoNode *member = parent->child(row);
        int id = member->hfId();
        if (!isColoringRuleMember(id)) {
            break;
        }
        if (id == ids.filter) {
            group->filter = member->fieldInfo();
        } else {
            group->disabled = true;
        }
    }
}

bool findColoringRuleGroup(const ProtoNode *node, ColoringRuleGroup *group)
{
    const ColoringRuleHfIds &ids = coloringRuleHfIds();
    int id = node ? node->hfId() : -1;
    if (id < 0 || (id != ids.name && !isColoringRuleMember(id))) {
        return false;
    }
    const ProtoNode *parent = node->parentNode();
    if (id == ids.name) {
        if (node->childrenCount() > 0) {
            readColoringRuleGroup(node, node, 0, group);
        } else {
            readColoringRuleGroup(node, parent, parent ? node->row() + 1 : 0, group);
        }
        return true;
    }
    if (!parent) {
        return false;
    }
    if (parent->hfId() == ids.name) {
        readColoringRuleGroup(parent, parent, 0, group);
        return true;
    }
    // Flat shape: the nearest name sibling before the item, with only
    // string or disabled items in between.
    int name_row = -1;
    const int node_row = node->row();
    for (int row = 0; row < node_row; row++) {
        int nid = parent->child(row)->hfId();
        if (nid == ids.name) {
            name_row = row;
        } else if (!isColoringRuleMember(nid)) {
            name_row = -1;
        }
    }
    if (name_row < 0) {
        return false;
    }
    readColoringRuleGroup(parent->child(name_row), parent, name_row + 1, group);
    return true;
}

} // namespace

bool ColoringRuleUtils::entryForNode(const ProtoNode *node, ColoringRuleEntry *entry)
{
    ColoringRuleGroup group;
    if (!entry || !findColoringRuleGroup(node, &group)) {
        return false;
    }
    entry->name = QString::fromUtf8(fvalue_get_string(group.name->value));
    entry->filter = group.filter ? QString::fromUtf8(fvalue_get_string(group.filter->value)) : QString();
    entry->disabled = group.disabled;
    return true;
}

bool ColoringRuleUtils::isDisabledEntryItem(const ProtoNode *node)
{
    ColoringRuleGroup group;
    return findColoringRuleGroup(node, &group) && group.disabled;
}

bool ColoringRuleUtils::setRuleEnabled(const ColoringRuleEntry &entry, bool enabled, QString *err)
{
    // The default colors are only used for rows added to the model, which
    // never happens here.
    ColoringRulesModel model(QApplication::palette().color(QPalette::Text),
                             QApplication::palette().color(QPalette::Base), nullptr);
    bool found = false;
    for (int row = 0; row < model.rowCount(); row++) {
        QModelIndex name_idx = model.index(row, ColoringRulesModel::colName);
        QModelIndex filter_idx = model.index(row, ColoringRulesModel::colFilter);
        if (name_idx.data(Qt::DisplayRole).toString() != entry.name) {
            continue;
        }
        if (!entry.filter.isEmpty() &&
            filter_idx.data(Qt::DisplayRole).toString() != entry.filter) {
            continue;
        }
        model.setData(name_idx, enabled ? Qt::Checked : Qt::Unchecked, Qt::CheckStateRole);
        found = true;
    }
    if (!found) {
        return false;
    }
    QString write_err;
    if (!model.writeColors(write_err) && err) {
        *err = write_err;
    }
    return true;
}

QList<ColoringRuleColors> ColoringRuleUtils::matchColors(const PacketListRecord *record)
{
    QList<ColoringRuleColors> colors;
    const frame_data *fdata = record ? record->frameData() : nullptr;
    if (!fdata) {
        return colors;
    }
    auto append = [&colors](const color_filter_t *colorf) {
        colors.append({ ColorUtils::fromColorT(&colorf->bg_color),
                        ColorUtils::fromColorT(&colorf->fg_color) });
    };
    // The record's matches never include disabled rules, so their head is
    // the rule in fdata->color_filter.
    const GSList *filters = record->matchingColorFilters();
    const color_filter_t *primary = filters ?
        static_cast<const color_filter_t *>(filters->data) : fdata->color_filter;
    if (!primary) {
        return colors;
    }
    append(primary);
    if (!filters || color_filter_is_tmp(primary)) {
        return colors;
    }
    for (const GSList *item = g_slist_next(filters); item != nullptr; item = g_slist_next(item)) {
        append(static_cast<const color_filter_t *>(item->data));
    }
    return colors;
}
