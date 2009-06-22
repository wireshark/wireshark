/* alert_box.c
 * Routines to put up various "standard" alert boxes used in multiple
 * places
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

#include <string.h>

#include <glib.h>

#include <epan/filesystem.h>
#include <epan/dfilter/dfilter.h>

#include "alert_box.h"

#include "simple_dialog.h"

/*
 * Alert box for general errors.
 */
void
failure_alert_box(const char *msg_format, va_list ap)
{
  vsimple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, msg_format, ap);
}

/*
 * Alert box for a failed attempt to open or create a file.
 * "err" is assumed to be a UNIX-style errno; "for_writing" is TRUE if
 * the file is being opened for writing and FALSE if it's being opened
 * for reading.
 *
 * XXX - add explanatory secondary text for at least some of the errors;
 * various HIGs suggest that you should, for example, suggest that the
 * user remove files if the file system is full.  Perhaps that's because
 * they're providing guidelines for people less sophisticated than the
 * typical Wireshark user is, but....
 */
void
open_failure_alert_box(const char *filename, int err, gboolean for_writing)
{
  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                file_open_error_message(err, for_writing), filename);
}

/*
 * Alert box for a failed attempt to read a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
read_failure_alert_box(const char *filename, int err)
{
  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "An error occurred while reading from the file \"%s\": %s.",
                filename, strerror(err));
}

/*
 * Alert box for a failed attempt to write to a file.
 * "err" is assumed to be a UNIX-style errno.
 *
 * XXX - add explanatory secondary text for at least some of the errors;
 * various HIGs suggest that you should, for example, suggest that the
 * user remove files if the file system is full.  Perhaps that's because
 * they're providing guidelines for people less sophisticated than the
 * typical Wireshark user is, but....
 */
void
write_failure_alert_box(const char *filename, int err)
{
  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                file_write_error_message(err), filename);
}

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
                "The filter expression \"%s\" isn't a valid display filter.\n"
                "See the help for a description of the display filter syntax.",
                simple_dialog_primary_start(), dfilter_error_msg,
                simple_dialog_primary_end(), dftext);
}
