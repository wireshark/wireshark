/* simple_dialog.h
 * Definitions for dialog box routines with toolkit-independent APIs but
 * toolkit-dependent implementations.
 *
 * $Id: simple_dialog.h,v 1.6 2004/01/31 02:25:43 ulfl Exp $
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

#ifndef __DIALOG_H__
#define __DIALOG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Dialog type. */
#define ESD_TYPE_INFO	0x00
#define ESD_TYPE_WARN	0x01
#define ESD_TYPE_ERROR	0x02
#define ESD_TYPE_QUEST  0x03

/* Flag to be ORed with the dialog type, to specify that the dialog is
   to be modal. */
#define ESD_TYPE_MODAL	0x10

/* Which buttons to display. */
#define ESD_BTN_OK     0x01
#define ESD_BTN_CANCEL 0x02
#define ESD_BTN_YES    0x04
#define ESD_BTN_NO     0x08

/* show a simple dialog */
#if __GNUC__ >= 2
extern gpointer simple_dialog(gint type, gint btn_mask, gchar *msg_format, ...)
    __attribute__((format (printf, 3, 4)));
#else
extern gpointer simple_dialog(gint type, gint btn_mask, gchar *msg_format, ...);
#endif

/* callback function type */
typedef void (* simple_dialog_cb_t) (gpointer dialog, gint btn, gpointer data);

/* set the callback function, which has to be called when a button was pressed */
extern void simple_dialog_set_cb(gpointer dialog, simple_dialog_cb_t callback_fct, gpointer data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DIALOG_H__ */
