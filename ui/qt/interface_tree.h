/* interface_tree.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef INTERFACE_TREE_H
#define INTERFACE_TREE_H

#include "config.h"

#include <glib.h>

#ifdef HAVE_LIBPCAP
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_opts.h"
#include "capture_ui_utils.h"
#endif

#include <QTreeWidget>

class InterfaceTree : public QTreeWidget
{
    Q_OBJECT
public:
    explicit InterfaceTree(QWidget *parent = 0);
    ~InterfaceTree();

protected:
    void hideEvent(QHideEvent *evt);
    void showEvent(QShowEvent *evt);
    void resizeEvent(QResizeEvent *evt);

private:
    if_stat_cache_t *stat_cache_;
    QTimer *stat_timer_;

signals:
    void interfaceUpdated(const char *device_name, bool selected);

public slots:
    // add_interface_to_list
    // change_interface_selection
    // change_interface_selection_for_all

private slots:
    void getInterfaceList();
    void updateStatistics(void);
    void updateSelectedInterfaces();
};

#endif // INTERFACE_TREE_H

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
