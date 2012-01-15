/* airpcap_dlg.h
 * Declarations of routines for the "Airpcap" dialog
 *
 * $Id$
 *
 * Giorgio Tino <giorgio.tino@cacetech.com>
 * Copyright (c) CACE Technologies, LLC 2006
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

#ifndef __AIRPCAP_DLG_H__
#define __AIRPCAP_DLG_H__

#define AIRPCAP_ADVANCED_FROM_TOOLBAR 0
#define AIRPCAP_ADVANCED_FROM_OPTIONS 1

/*
 * Creates the list of available decryption modes, depending on the adapters found
 */
void update_decryption_mode_list(GtkWidget *w);

/*
 * Selects the current decryption mode in the given combo box
 */
void update_decryption_mode(GtkWidget *w);

/*
 * Turns the decryption on or off
 */
void on_decryption_mode_cb_changed(GtkWidget *w, gpointer data _U_);

/** Create a "Airpcap" dialog box caused by a button click.
 *
 * @param widget parent widget
 * @param construct_args_ptr parameters to construct the dialog (construct_args_t)
 */
void display_airpcap_advanced_cb(GtkWidget *widget, gpointer construct_args_ptr);

/* Called to create the key management window */
void display_airpcap_key_management_cb(GtkWidget *w, gpointer data);

/**/
/*
 * Dialog box that appears whenever keys are not consistent between wieshark and airpcap
 */
void airpcap_keys_check_w(GtkWidget *w, gpointer data);

#endif
