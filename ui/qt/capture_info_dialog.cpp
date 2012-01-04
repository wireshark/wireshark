/* capture_info_dialog.cpp
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "capture_info_dialog.h"
#include "capture_info.h"

/* create the capture info dialog */
/* will keep pointers to the fields in the counts parameter */
void capture_info_ui_create(
capture_info    *cinfo,
capture_options *capture_opts)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: capture_info_ui_create");
}

/* update the capture info dialog */
/* As this function is a bit time critical while capturing, */
/* prepare everything possible in the capture_info_ui_create() function above! */
void capture_info_ui_update(
capture_info    *cinfo)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: capture_info_ui_update");
}

/* destroy the capture info dialog again */
void capture_info_ui_destroy(
capture_info    *cinfo)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: capture_info_ui_destroy");
}

CaptureInfoDialog::CaptureInfoDialog(QWidget *parent) :
    QDialog(parent)
{
}
