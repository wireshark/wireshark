/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLORING_RULE_UTILS_H
#define COLORING_RULE_UTILS_H

#include <config.h>

#include <QColor>
#include <QList>
#include <QMetaType>
#include <QString>

class PacketListRecord;
class ProtoNode;

/** @brief One coloring rule entry of the Frame tree. */
struct ColoringRuleEntry {
    QString name;           /**< Rule name (value of frame.coloring_rule.name). */
    QString filter;         /**< Rule filter text; empty if the item is missing. */
    bool disabled = false;  /**< The entry has a frame.coloring_rule.disabled item. */
};

/** @brief Colors of one coloring rule a packet matches. */
struct ColoringRuleColors {
    QColor background;  /**< Background color of the rule. */
    QColor foreground;  /**< Foreground (text) color of the rule. */
};

/**
 * @brief Coloring rule lookups for the Qt views.
 *
 * Views and models ask here instead of reading color_filter_t, the Frame
 * dissector's coloring rule fields or the rule list themselves.
 */
class ColoringRuleUtils
{
public:
    /**
     * @brief Resolves the coloring rule entry a Frame tree item belongs to.
     *
     * Handles both shapes the Frame dissector produces: one entry as flat
     * name / string / disabled items, several entries as name items holding
     * their string and disabled items as children.
     * @param node  Tree item of the packet details model; may be nullptr.
     * @param entry Filled when the item belongs to an entry.
     * @return true if @p node is a name, string or disabled item of an entry.
     */
    static bool entryForNode(const ProtoNode *node, ColoringRuleEntry *entry);

    /**
     * @brief Tells whether a Frame tree item belongs to a disabled rule's entry.
     * @param node Tree item of the packet details model; may be nullptr.
     * @return true if the item's entry has a frame.coloring_rule.disabled item.
     */
    static bool isDisabledEntryItem(const ProtoNode *node);

    /**
     * @brief Enables or disables the rule of an entry and saves the rule list.
     *
     * Rules are matched by name, and by filter text when the entry has one,
     * because names are not unique. The state is set, not toggled.
     * @param entry   Entry from entryForNode().
     * @param enabled New state.
     * @param err     Set to the error text when saving fails.
     * @return true if at least one rule matched (and saving was attempted).
     */
    static bool setRuleEnabled(const ColoringRuleEntry &entry, bool enabled, QString *err);

    /**
     * @brief Colors a packet list record is drawn with.
     *
     * One entry per matching rule in match order; the first is the rule that
     * colors the packet. A packet colored by a conversation rule gets that
     * rule alone, because conversation colors take precedence over multiple
     * colors. Without a match list (multi-color mode and multi-color details
     * both off) only the rule that colors the packet is known.
     * @param record Record; may be nullptr.
     * @return The colors; empty if the packet is not colored.
     */
    static QList<ColoringRuleColors> matchColors(const PacketListRecord *record);
};

Q_DECLARE_METATYPE(ColoringRuleEntry)
Q_DECLARE_METATYPE(ColoringRuleColors)

#endif // COLORING_RULE_UTILS_H
