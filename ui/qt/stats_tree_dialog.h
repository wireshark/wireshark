/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STATS_TREE_DIALOG_H
#define STATS_TREE_DIALOG_H

#include "tap_parameter_dialog.h"

#include <config.h>

#include "epan/stats_tree_priv.h"

struct _tree_cfg_pres {
    class StatsTreeDialog* st_dlg;
};

/**
 * @brief A TapParameterDialog that displays a stats_tree-based statistics table.
 */
class StatsTreeDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Construct a StatsTreeDialog for a given stats_tree configuration.
     * @param parent    The parent widget (passed to TapParameterDialog).
     * @param cf        The capture file to tap.
     * @param cfg_abbr  The short name identifying the @c stats_tree_cfg to
     *                  instantiate (e.g. @c "http_tree").
     */
    explicit StatsTreeDialog(QWidget &parent, CaptureFile &cf, const char *cfg_abbr);

    /* Destructor. */
    ~StatsTreeDialog();

    /**
     * @brief Configure the Qt-side presentation fields of a stats_tree node.
     * @param node The stats_tree node whose presentation data should be
     *             initialised.
     */
    static void setupNode(stat_node *node);


private:
    struct _tree_cfg_pres cfg_pr_; /**< Presentation configuration shared with the stats_tree framework. */
    stats_tree     *st_;           /**< The live stats_tree instance being driven by this dialog. */
    stats_tree_cfg *st_cfg_;       /**< The registered configuration record for this stats_tree type. */

    /**
     * @brief Tap reset callback — clears all node data before a retap.
     * @param st_ptr Pointer to the @c stats_tree instance (cast from void*).
     */
    static void resetTap(void *st_ptr);

    /**
     * @brief Tap draw callback — propagates node values into the QTreeWidget.
     * @param st_ptr Pointer to the @c stats_tree instance (cast from void*).
     */
    static void drawTreeItems(void *st_ptr);

    /**
     * @brief Serialise the current tree contents as a formatted string.
     * @param format The output format (@c ST_FORMAT_PLAIN, @c ST_FORMAT_CSV,
     *               or @c ST_FORMAT_XML).
     * @return A @c QByteArray containing the formatted tree data.
     */
    virtual QByteArray getTreeAsString(st_format_type format);


private slots:
    /**
     * @brief (Re-)populate the QTreeWidget from the current stats_tree state.
     */
    virtual void fillTree();
};

#endif // STATS_TREE_DIALOG_H
