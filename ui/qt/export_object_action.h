/* export_object_action.h
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

#ifndef EXPORTOBJECTACTION_H
#define EXPORTOBJECTACTION_H

#include "config.h"

#include <glib.h>
#include <epan/packet_info.h>
#include <epan/export_object.h>

#include <QAction>

// Actions for "Export Objects" menu items.

class ExportObjectAction : public QAction
{
    Q_OBJECT
public:
    ExportObjectAction(QObject *parent, register_eo_t *eo = NULL);

    register_eo_t* exportObject() {return eo_;}

public slots:
    void captureFileOpened();
    void captureFileClosed();

private:
    register_eo_t *eo_;
};

#endif // EXPORTOBJECTACTION_H

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
