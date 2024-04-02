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

class StatsTreeDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    explicit StatsTreeDialog(QWidget &parent, CaptureFile &cf, const char *cfg_abbr);
    ~StatsTreeDialog();
    static void setupNode(stat_node* node);

private:
    struct _tree_cfg_pres cfg_pr_;
    stats_tree *st_;
    stats_tree_cfg *st_cfg_;

    static void resetTap(void *st_ptr);
    static void drawTreeItems(void *st_ptr);
    virtual QByteArray getTreeAsString(st_format_type format);

private slots:
    virtual void fillTree();
};

#endif // STATS_TREE_DIALOG_H
