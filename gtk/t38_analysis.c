/* t38_analysis.c
 * T.38 fax analysis for Wireshark
 *
 * $Id$
 *
 * Copyright 2005 Verso Technologies Inc.
 * By Alejandro Vaquero <alejandro.vaquero@verso.com>
 *
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation,	Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "graph_analysis.h"

#include "globals.h"

#include <epan/tap.h>
#include <epan/epan_dissect.h>
#include <epan/dissectors/packet-t38.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/conversation.h>
#include <epan/stat_cmd_args.h>
#include "stat_menu.h"

#include "main.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "graph_analysis.h"
#include "gui_stat_menu.h"

void voip_calls_init_tap(const char *);	

/****************************************************************************/
/* user confirmed the info dialog */
/* callback from dialog */
static void t38_analysis_answered_cb(gpointer dialog _U_, gint btn _U_, gpointer data _U_)
{
	voip_calls_init_tap("");
}

/****************************************************************************/
/* entry point from main menu */
static void t38_analysis_cb(GtkWidget *w _U_, gpointer data _U_) 
{
	gpointer dialog;

	/* We have moved this directly to the VoIP Calls */
	dialog = simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
		"This feature has been moved to the \"VoIP Calls\"");
	simple_dialog_set_cb(dialog, t38_analysis_answered_cb, NULL);
}

/****************************************************************************/
static void
t38_analysis_init(const char *dummy _U_, void* userdata _U_)
{
	t38_analysis_cb(NULL, NULL);
}

/****************************************************************************/
void
register_tap_listener_t38_analysis(void)
{
	register_stat_cmd_arg("t38", t38_analysis_init,NULL);


	register_stat_menu_item("Fax T38 Analysis...", REGISTER_STAT_GROUP_TELEPHONY,
	    t38_analysis_cb, NULL, NULL, NULL);
}
