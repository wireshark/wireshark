/* alert_box.c
 * Routines to put up various "standard" alert boxes used in multiple
 * places
 *
 * $Id: alert_box.c,v 1.1 2004/02/11 00:55:26 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <epan/dfilter/dfilter.h>

#include "alert_box.h"

#include "simple_dialog.h"

/*
 * Alert box for an invalid display filter expression.
 * Assumes "dfilter_error_msg" has been set by "dfilter_compile()" to the
 * error message for the filter.
 *
 * XXX - should this have a "Help" button that pops up the display filter
 * help?
 */
void
bad_dfilter_alert_box(const char *dftext)
{
  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, 
                "%s%s%s\n"
                "\n"
                "The filter expression \"%s\" is not a valid display filter.\n"
                "See the help for a description of the display filter syntax.",
                simple_dialog_primary_start(), dfilter_error_msg,
                simple_dialog_primary_end(), dftext);
}
