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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/filesystem.h>
#include <epan/dfilter/dfilter.h>

#include "ui/alert_box.h"

#include "ui/simple_dialog.h"

/*
 * Alert box for general errors.
 */
void
failure_alert_box(const char *msg_format, va_list ap)
{
  vsimple_error_message_box(msg_format, ap);
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
  gchar *display_basename;

  display_basename = g_filename_display_basename(filename);
  simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                     file_open_error_message(err, for_writing),
                     display_basename);
  g_free(display_basename);
}

/*
 * Alert box for a failed attempt to read a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
read_failure_alert_box(const char *filename, int err)
{
  gchar *display_basename;

  display_basename = g_filename_display_basename(filename);
  simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                     "An error occurred while reading from the file \"%s\": %s.",
                     display_basename, g_strerror(err));
  g_free(display_basename);
}

/*
 * Alert box for a failed attempt to write to a file.
 * "err" is assumed to be a UNIX-style errno if positive and a
 * Wiretap error if negative.
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
  gchar *display_basename;

  display_basename = g_filename_display_basename(filename);
  if (err < 0) {
    switch (err) {

    case WTAP_ERR_SHORT_WRITE:
      simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                         "A full write couldn't be done to the file \"%s\".",
                         display_basename);
      break;
    
    default:
      simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                         "An error occurred while writing to the file \"%s\": %s.",
                         display_basename, wtap_strerror(err));
      break;
    }
  } else {
    simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                       file_write_error_message(err), display_basename);
  }
  g_free(display_basename);
}
