/* util.c
 * Utility routines
 *
 * $Id: util.c,v 1.23 1999/11/22 06:24:42 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <gtk/gtk.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include "util.h"

#include "image/icon-excl.xpm"
#include "image/icon-ethereal.xpm"

static void simple_dialog_cancel_cb(GtkWidget *, gpointer);

const gchar *bm_key = "button mask";

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 * 
 * Args:
 * type       : One of ESD_TYPE_*.
 * btn_mask   : The address of a gint.  The value passed in determines if
 *              the 'Cancel' button is displayed.  The button pressed by the 
 *              user is passed back.
 * msg_format : Sprintf-style format of the text displayed in the dialog.
 * ...        : Argument list for msg_format
 *
 */
 
#define ESD_MAX_MSG_LEN 2048
void
simple_dialog(gint type, gint *btn_mask, gchar *msg_format, ...) {
  GtkWidget   *win, *main_vb, *top_hb, *type_pm, *msg_label,
              *bbox, *ok_btn, *cancel_btn;
  GdkPixmap   *pixmap;
  GdkBitmap   *mask;
  GtkStyle    *style;
  GdkColormap *cmap;
  va_list      ap;
  gchar        message[ESD_MAX_MSG_LEN];
  gchar      **icon;

  /* Main window */
  win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_container_border_width(GTK_CONTAINER(win), 7);

  switch (type) {
  case ESD_TYPE_WARN :
    gtk_window_set_title(GTK_WINDOW(win), "Ethereal: Warning");
    icon = icon_excl_xpm;
    break;
  case ESD_TYPE_CRIT :
    gtk_window_set_title(GTK_WINDOW(win), "Ethereal: Critical");
    icon = icon_excl_xpm;
    break;
  case ESD_TYPE_INFO :
  default :
    icon = icon_ethereal_xpm;
    gtk_window_set_title(GTK_WINDOW(win), "Ethereal: Information");
    break;
  }

  gtk_object_set_data(GTK_OBJECT(win), bm_key, btn_mask);

  /* Container for our rows */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(win), main_vb);
  gtk_widget_show(main_vb);

  /* Top row: Icon and message text */
  top_hb = gtk_hbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  style = gtk_widget_get_style(win);
  cmap  = gdk_colormap_get_system();
  pixmap = gdk_pixmap_colormap_create_from_xpm_d(NULL, cmap,  &mask,
    &style->bg[GTK_STATE_NORMAL], icon);
  type_pm = gtk_pixmap_new(pixmap, mask);
  gtk_misc_set_alignment (GTK_MISC (type_pm), 0.5, 0.0);
  gtk_container_add(GTK_CONTAINER(top_hb), type_pm);
  gtk_widget_show(type_pm);

  /* Load our vararg list into the message string */
  va_start(ap, msg_format);
  vsnprintf(message, ESD_MAX_MSG_LEN, msg_format, ap);

  msg_label = gtk_label_new(message);
  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
  gtk_container_add(GTK_CONTAINER(top_hb), msg_label);
  gtk_widget_show(msg_label);
  
  /* Button row */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_btn = gtk_button_new_with_label ("OK");
  gtk_signal_connect_object(GTK_OBJECT(ok_btn), "clicked",
    GTK_SIGNAL_FUNC(gtk_widget_destroy), GTK_OBJECT (win)); 
  gtk_container_add(GTK_CONTAINER(bbox), ok_btn);
  GTK_WIDGET_SET_FLAGS(ok_btn, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(ok_btn);
  gtk_widget_show(ok_btn);

  if (btn_mask && *btn_mask == ESD_BTN_CANCEL) {
    cancel_btn = gtk_button_new_with_label("Cancel");
    gtk_signal_connect(GTK_OBJECT(cancel_btn), "clicked",
      GTK_SIGNAL_FUNC(simple_dialog_cancel_cb), (gpointer) win);
    gtk_container_add(GTK_CONTAINER(bbox), cancel_btn);
    GTK_WIDGET_SET_FLAGS(cancel_btn, GTK_CAN_DEFAULT);
    gtk_widget_show(cancel_btn);
  }

  if (btn_mask)
    *btn_mask = ESD_BTN_OK;

  gtk_widget_show(win);
}

static void
simple_dialog_cancel_cb(GtkWidget *w, gpointer win) {
  gint *btn_mask = (gint *) gtk_object_get_data(win, bm_key);
  
  if (btn_mask)
    *btn_mask = ESD_BTN_CANCEL;
  gtk_widget_destroy(GTK_WIDGET(win));
}

static char *
setup_tmpdir(char *dir)
{
	int len = strlen(dir);
	char *newdir;

	/* Append slash if necessary */
	if (dir[len - 1] == '/') {
		newdir = dir;
	}
	else {
		newdir = g_malloc(len + 2);
		strcpy(newdir, dir);
		strcat(newdir, "/");
	}
	return newdir;
}

static int
try_tempfile(char *namebuf, int namebuflen, const char *dir, const char *pfx)
{
	static const char suffix[] = "XXXXXXXXXX";
	int namelen = strlen(dir) + strlen(pfx) + sizeof suffix;
	mode_t old_umask;
	int tmp_fd;

	if (namebuflen < namelen) {
		/* Stick in a truncated name, so that if this error is
		   reported with the file name, you at least get
		   something. */
		snprintf(namebuf, namebuflen, "%s%s%s", dir, pfx, suffix);
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(namebuf, dir);
	strcat(namebuf, pfx);
	strcat(namebuf, suffix);

	/* The Single UNIX Specification doesn't say that "mkstemp()"
	   creates the temporary file with mode rw-------, so we
	   won't assume that all UNIXes will do so; instead, we set
	   the umask to 0077 to take away all group and other
	   permissions, attempt to create the file, and then put
	   the umask back. */
	old_umask = umask(0077);
	tmp_fd = mkstemp(namebuf);
	umask(old_umask);
	return tmp_fd;
}

static char *tmpdir = NULL;
#ifdef WIN32
static char *temp = NULL;
#endif
static char *E_tmpdir;

#ifndef P_tmpdir
#define P_tmpdir "/var/tmp"
#endif

int
create_tempfile(char *namebuf, int namebuflen, const char *pfx)
{
	char *dir;
	int fd;
	static gboolean initialized;

	if (!initialized) {
		if ((dir = getenv("TMPDIR")) != NULL)
			tmpdir = setup_tmpdir(dir);
#ifdef WIN32
		if ((dir = getenv("TEMP")) != NULL)
			temp = setup_tmpdir(dir);
#endif

		E_tmpdir = setup_tmpdir(P_tmpdir);
		initialized = TRUE;
	}

	if (tmpdir != NULL) {
		fd = try_tempfile(namebuf, namebuflen, tmpdir, pfx);
		if (fd != -1)
			return fd;
	}

#ifdef WIN32
	if (temp != NULL) {
		fd = try_tempfile(namebuf, namebuflen, temp, pfx);
		if (fd != -1)
			return fd;
	}
#endif

	fd = try_tempfile(namebuf, namebuflen, E_tmpdir, pfx);
	if (fd != -1)
		return fd;

	return try_tempfile(namebuf, namebuflen, "/tmp", pfx);
}

/* ASCII/EBCDIC conversion tables from
 * http://www.room42.com/store/computer_center/code_tables.shtml
 */
static guint8 ASCII_translate_EBCDIC [ 256 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D, 0x4D,
    0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
    0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
    0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
    0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xAD, 0xE0, 0xBD, 0x5F, 0x6D,
    0x7D, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xC0, 0x6A, 0xD0, 0xA1, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B
};

void
ASCII_to_EBCDIC(guint8 *buf, guint bytes)
{
	guint	i;
	guint8	*bufptr;

	bufptr = buf;

	for (i = 0; i < bytes; i++, bufptr++) {
		*bufptr = ASCII_translate_EBCDIC[*bufptr];
	}
}

guint8
ASCII_to_EBCDIC1(guint8 c)
{
	return ASCII_translate_EBCDIC[c];
}

static guint8 EBCDIC_translate_ASCII [ 256 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x2E, 0x2E, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x2E, 0x3F,
    0x20, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
    0x26, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,
    0x2D, 0x2F, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x7C, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
    0x2E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
    0x72, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x7A, 0x2E, 0x2E, 0x2E, 0x5B, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x5D, 0x2E, 0x2E,
    0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,                                             
    0x52, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x5C, 0x2E, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5A, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,                 
    0x39, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E
};

void
EBCDIC_to_ASCII(guint8 *buf, guint bytes)
{
	guint	i;
	guint8	*bufptr;

	bufptr = buf;

	for (i = 0; i < bytes; i++, bufptr++) {
		*bufptr = EBCDIC_translate_ASCII[*bufptr];
	}
}

guint8
EBCDIC_to_ASCII1(guint8 c)
{
	return EBCDIC_translate_ASCII[c];
}

