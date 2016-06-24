/* geometry_state_dialog.cpp
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

#include "geometry_state_dialog.h"
#include "qt_ui_utils.h"
#include "ui/recent.h"
#include "ui/ui_util.h"

GeometryStateDialog::~GeometryStateDialog()
{
    saveGeometry();
}

void GeometryStateDialog::loadGeometry(int width, int height, const QString &dialog_name)
{
    window_geometry_t geom;

    dialog_name_ = dialog_name.isEmpty() ? objectName() : dialog_name;
    if (!dialog_name_.isEmpty() && window_geom_load(dialog_name_.toUtf8().constData(), &geom)) {
        QRect recent_geom(geom.x, geom.y, geom.width, geom.height);

        // Check if the dialog is visible on any screen
        if (rect_on_screen(recent_geom)) {
            move(recent_geom.topLeft());
            resize(recent_geom.size());
        } else {
            // Not visible, move within a reasonable area and try size only
            recent_geom.moveTopLeft(QPoint(50, 50));
            if (rect_on_screen(recent_geom)) {
                resize(recent_geom.size());
            } else if (width > 0 && height > 0) {
                // We're not visible on any screens, use defaults
                resize(width, height);
            }
        }
        if (geom.maximized) {
            showFullScreen();
        }
    } else if (width > 0 && height > 0) {
        // No saved geometry found, use defaults
        resize(width, height);
    }
}

void GeometryStateDialog::saveGeometry()
{
    if (dialog_name_.isEmpty())
        return;

    window_geometry_t geom;

    geom.key = NULL;
    geom.set_pos = TRUE;
    geom.x = pos().x();
    geom.y = pos().y();
    geom.set_size  = TRUE;
    geom.width = size().width();
    geom.height = size().height();
    geom.set_maximized = TRUE;
    geom.maximized = isFullScreen();

    window_geom_save(dialog_name_.toUtf8().constData(), &geom);
}

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
