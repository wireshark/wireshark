/* interface_tree.cpp
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "interface_tree.h"

#include "config.h"

#ifdef HAVE_LIBPCAP
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_opts.h"
#include "capture_ui_utils.h"
#endif

#include <QLabel>
#include <QHeaderView>

InterfaceTree::InterfaceTree(QWidget *parent) :
    QTreeWidget(parent)
{
    GList *if_list;
    QTreeWidgetItem *ti;
    int err;
    gchar *err_str = NULL;

    header()->setVisible(false);
    setRootIsDecorated(false);
    setUniformRowHeights(true);
    setAccessibleName("Welcome screen list");

    setStyleSheet(
            "QTreeWidget {"
            "  border: 0;"
            "}"
            );

    if_list = capture_interface_list(&err, &err_str);
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: move if_list_comparator_alph out of gtk/");
//    if_list = g_list_sort(if_list, if_list_comparator_alph);

    if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
        ti = new QTreeWidgetItem();
        QLabel *label = new QLabel(QString("<h3>No interfaces found</h3>%1").arg(QString().fromUtf8(err_str)));
        label->setWordWrap(true);

        setDisabled(true);
        addTopLevelItem(ti);
        setItemWidget(ti, 0, label);
        return;
    } else if (err_str) {
        g_free(err_str);
    }

    // XXX Do we need to check for this? capture_interface_list returns an error if the length is 0.
    if (g_list_length(if_list) > 0) {
        if_info_t *if_info;
        GList *curr;
        setDisabled(false);

        for (curr = g_list_first(if_list); curr; curr = g_list_next(curr)) {
            if_info = (if_info_t *) curr->data;
            /* Continue if capture device is hidden */
//            if (prefs_is_capture_device_hidden(if_info->name)) {
//                continue;
//            }

            ti = new QTreeWidgetItem();
            ti->setText(0, QString().fromUtf8(if_info->description ? if_info->description : if_info->name));
            addTopLevelItem(ti);
        }
    }
    free_interface_list(if_list);
}
