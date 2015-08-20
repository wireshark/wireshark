/* stats_tree_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef STATS_TREE_DIALOG_H
#define STATS_TREE_DIALOG_H

#include "tap_parameter_dialog.h"

#include <config.h>

#include <glib.h>

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

/*
 * Editor modelines
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
