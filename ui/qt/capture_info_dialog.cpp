/* capture_info_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "capture_info_dialog.h"
#include "capture_info.h"

// This is effectively GTK+ only.
// If we implement this here we should modernize the staticstis we show.

/* create the capture info dialog */
/* will keep pointers to the fields in the counts parameter */
void capture_info_ui_create(
capture_info    *,
capture_session *)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: capture_info_ui_create");
}

/* update the capture info dialog */
/* As this function is a bit time critical while capturing, */
/* prepare everything possible in the capture_info_ui_create() function above! */
void capture_info_ui_update(
capture_info    *)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: capture_info_ui_update");
}

/* destroy the capture info dialog again */
void capture_info_ui_destroy(
capture_info    *)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: capture_info_ui_destroy");
}

CaptureInfoDialog::CaptureInfoDialog(QWidget *parent) :
    QDialog(parent)
{
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
