/* main_status_bar.cpp
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

#include "main_status_bar.h"

#include "main_statusbar.h"

/* Temporary message timeouts */
#define TEMPORARY_MSG_TIMEOUT (7 * 1000)
#define TEMPORARY_FLASH_TIMEOUT (1 * 1000)
#define TEMPORARY_FLASH_INTERVAL (TEMPORARY_FLASH_TIMEOUT / 4)

/*
 * Push a formatted temporary message onto the statusbar.
 */
void
statusbar_push_temporary_msg(const gchar *msg_format, ...)
{
    va_list ap;
    gchar *msg;
    guint msg_id;

    va_start(ap, msg_format);
    msg = g_strdup_vprintf(msg_format, ap);
    va_end(ap);

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: statusbar_push_temporary_msg: %s", msg);

//    msg_id = gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, msg);
    g_free(msg);

//    flash_time = TEMPORARY_FLASH_TIMEOUT - 1;
//    g_timeout_add(TEMPORARY_FLASH_INTERVAL, statusbar_flash_temporary_msg, NULL);

//    g_timeout_add(TEMPORARY_MSG_TIMEOUT, statusbar_remove_temporary_msg, GUINT_TO_POINTER(msg_id));
}

/*
 * Update the packets statusbar to the current values
 */
void
packets_bar_update(void)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: packets_bar_update");
//    if(packets_bar) {
//        /* Remove old status */
//        if(packets_str) {
//            gtk_statusbar_pop(GTK_STATUSBAR(packets_bar), packets_ctx);
//        } else {
//            packets_str = g_string_new ("");
//	}

//        /* Do we have any packets? */
//        if(cfile.count) {
//            g_string_printf(packets_str, " Packets: %u Displayed: %u Marked: %u",
//                            cfile.count, cfile.displayed_count, cfile.marked_count);
//            if(cfile.drops_known) {
//                g_string_append_printf(packets_str, " Dropped: %u", cfile.drops);
//            }
//            if(cfile.ignored_count > 0) {
//                g_string_append_printf(packets_str, " Ignored: %u", cfile.ignored_count);
//            }
//            if(!cfile.is_tempfile){
//                /* Loading an existing file */
//                gulong computed_elapsed = cf_get_computed_elapsed();
//                g_string_append_printf(packets_str, " Load time: %lu:%02lu.%03lu",
//                                       computed_elapsed/60000,
//                                       computed_elapsed%60000/1000,
//                                       computed_elapsed%1000);
//            }
//        } else {
//            g_string_printf(packets_str, " No Packets");
//        }
//        gtk_statusbar_push(GTK_STATUSBAR(packets_bar), packets_ctx, packets_str->str);
//    }
}

MainStatusBar::MainStatusBar(QWidget *parent) :
    QStatusBar(parent)
{
}
