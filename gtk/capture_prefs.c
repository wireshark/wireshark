/* capture_prefs.c
 * Dialog box for capture preferences
 *
 * $Id: capture_prefs.c,v 1.18 2003/09/08 21:44:42 guy Exp $
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
#include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <string.h>
#include <gtk/gtk.h>

#include <pcap.h>

#include "globals.h"
#include "capture_prefs.h"
#include "gtkglobals.h"
#include "prefs.h"
#include "prefs_dlg.h"
#include "ui_util.h"
#include "simple_dialog.h"
#include "pcap-util.h"
#include "main.h"
#include "compat_macros.h"

#define DEVICE_KEY				"device"
#define PROM_MODE_KEY			"prom_mode"
#define CAPTURE_REAL_TIME_KEY	"capture_real_time"
#define AUTO_SCROLL_KEY			"auto_scroll"

#define DEVOPTS_CALLER_PTR_KEY	"devopts_caller_ptr"
#define DEVOPTS_DIALOG_PTR_KEY	"devopts_dialog_ptr"

#define CAPTURE_TABLE_ROWS 5
#define DEVICES_OPTS_ROWS 2
#define IF_OPTS_CLIST_COLS 3
#define IF_OPTS_MAX_DESCR_LEN 128

/* interface options dialog */
static GtkWidget *new_clist, *if_descr_te, *if_hide_cb;
static gint ifrow;						/* last interface row selected */

static void ifopts_edit_cb(GtkWidget *w, gpointer data);
static void ifopts_edit_ok_cb(GtkWidget *w, gpointer parent_w);
static void ifopts_edit_close_cb(GtkWidget *close_bt, gpointer parent_w);
static void ifopts_edit_destroy_cb(GtkWidget *win, gpointer data);
static void ifopts_edit_ifsel_cb(GtkWidget *clist, gint row, gint column,
    GdkEventButton *event, gpointer data);
static void ifopts_edit_ifunsel_cb(GtkWidget *clist, gint row, gint column,
    GdkEventButton *event, gpointer data);
static void ifopts_old_options_add(GtkCList *clist);
static gboolean ifopts_old_options_chk(GtkCList *clist, gchar *ifname);
static void ifopts_new_options_add(GtkCList *clist, gchar *ifname);
static void ifopts_options_free(gchar *text[]);
static void ifopts_if_clist_add(GtkCList *clist);
static void ifopts_write_new_descr(void);
static void ifopts_write_new_hide(void);

GtkWidget*
capture_prefs_show(void)
{
	GtkWidget	*main_tb, *main_vb;
	GtkWidget	*if_cb, *if_lb, *promisc_cb, *sync_cb, *auto_scroll_cb;
	GtkWidget	*ifopts_lb, *ifopts_bt;
	GList		*if_list;
	int		err;
	char		err_str[PCAP_ERRBUF_SIZE];

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 7);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

	/* Main table */
	main_tb = gtk_table_new(CAPTURE_TABLE_ROWS, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
	gtk_widget_show(main_tb);

	/* Default device */
	if_lb = gtk_label_new("Default interface:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_lb, 0, 1, 0, 1);
	gtk_misc_set_alignment(GTK_MISC(if_lb), 1.0, 0.5);
	gtk_widget_show(if_lb);

	if_cb = gtk_combo_new();
	/*
	 * XXX - what if we can't get the list?
	 */
	if_list = get_interface_list(&err, err_str);
	if (if_list != NULL)
		gtk_combo_set_popdown_strings(GTK_COMBO(if_cb), if_list);
	if (prefs.capture_device)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry),
		    prefs.capture_device);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_cb, 1, 2, 0, 1);
	gtk_widget_show(if_cb);
	OBJECT_SET_DATA(main_vb, DEVICE_KEY, if_cb);

	free_interface_list(if_list);

	/* Interface options */
	ifopts_lb = gtk_label_new("Interface options:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), ifopts_lb, 0, 1, 1, 2);
	gtk_misc_set_alignment(GTK_MISC(ifopts_lb), 1.0, 0.5);
	gtk_widget_show(ifopts_lb);

	ifopts_bt = gtk_button_new_with_label("Edit...");
	SIGNAL_CONNECT(ifopts_bt, "clicked", ifopts_edit_cb, NULL);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), ifopts_bt, 1, 2, 1, 2 );

	/* Promiscuous mode */
	promisc_cb = create_preference_check_button(main_tb, 2,
	    "Capture packets in promiscuous mode:", NULL,
	    prefs.capture_prom_mode);
	OBJECT_SET_DATA(main_vb, PROM_MODE_KEY, promisc_cb);

	/* Real-time capture */
	sync_cb = create_preference_check_button(main_tb, 3,
	    "Update list of packets in real time:", NULL,
	    prefs.capture_real_time);
	OBJECT_SET_DATA(main_vb, CAPTURE_REAL_TIME_KEY, sync_cb);

	/* Auto-scroll real-time capture */
	auto_scroll_cb = create_preference_check_button(main_tb, 4,
	    "Automatic scrolling in live capture:", NULL,
	    prefs.capture_auto_scroll);
	OBJECT_SET_DATA(main_vb, AUTO_SCROLL_KEY, auto_scroll_cb);

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}

void
capture_prefs_fetch(GtkWidget *w)
{
	GtkWidget *if_cb, *promisc_cb, *sync_cb, *auto_scroll_cb;
	gchar	*if_text;

	if_cb = (GtkWidget *)OBJECT_GET_DATA(w, DEVICE_KEY);
	promisc_cb = (GtkWidget *)OBJECT_GET_DATA(w, PROM_MODE_KEY);
	sync_cb = (GtkWidget *)OBJECT_GET_DATA(w, CAPTURE_REAL_TIME_KEY);
	auto_scroll_cb = (GtkWidget *)OBJECT_GET_DATA(w, AUTO_SCROLL_KEY);

	if (prefs.capture_device != NULL) {
		g_free(prefs.capture_device);
		prefs.capture_device = NULL;
	}
	if_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry)));
	/* Strip out white space */
	g_strstrip(if_text);
	/* If there was nothing but white space, treat that as an
	   indication that the user doesn't want to wire in a default
	   device, and just wants the first device in the list chosen. */
	if (*if_text == '\0') {
		g_free(if_text);
		if_text = NULL;
	}
	prefs.capture_device = if_text;

	prefs.capture_prom_mode = GTK_TOGGLE_BUTTON (promisc_cb)->active;

	prefs.capture_real_time = GTK_TOGGLE_BUTTON (sync_cb)->active;

	prefs.capture_auto_scroll = GTK_TOGGLE_BUTTON (auto_scroll_cb)->active;
}

void
capture_prefs_apply(GtkWidget *w _U_)
{
}

void
capture_prefs_destroy(GtkWidget *w)
{
	GtkWidget *caller = gtk_widget_get_toplevel(w);
	GtkWidget *dlg;

	/* Is there an interface descriptions dialog associated with this
	   Preferences dialog? */
	dlg = OBJECT_GET_DATA(caller, DEVOPTS_DIALOG_PTR_KEY);

	if (dlg != NULL) {
		/* Yes.  Destroy it. */
		gtk_widget_destroy(dlg);
	}
}

/* Create an edit interface options dialog. */
static void
ifopts_edit_cb(GtkWidget *w, gpointer data _U_)
{
	GtkWidget	*ifopts_edit_dlg, *old_scr_win, *if_scr_win, *main_hb, *main_tb,
				*old_opts_fr, *opts_fr,
				*old_clist, *if_clist, *if_descr_lb, *if_hide_lb,
				*bbox, *ok_bt, *cancel_bt;
	gchar *old_titles[3] = { "Interface", "Description", "Hide?" };
	gchar *if_title[1] = { "Interface" };

	GtkWidget *caller = gtk_widget_get_toplevel(w);
	
	/* Has an edit dialog box already been opened for that top-level
	   widget? */
	ifopts_edit_dlg = OBJECT_GET_DATA(caller, DEVOPTS_DIALOG_PTR_KEY);
	if (ifopts_edit_dlg != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(ifopts_edit_dlg);
		return;
	}
	
	/* create a new dialog */
	ifopts_edit_dlg = gtk_dialog_new();
	gtk_window_set_title(GTK_WINDOW(ifopts_edit_dlg), 
			"Ethereal: Preferences: Interface Options");
	SIGNAL_CONNECT(ifopts_edit_dlg, "destroy", ifopts_edit_destroy_cb, NULL);
	gtk_container_border_width(GTK_CONTAINER(GTK_DIALOG(ifopts_edit_dlg)->vbox),
			5);
	
	/*
	 * XXX - What code can be put here, or somewhere else, to get the Ethereal 
	 *		 icon loaded for this window?
	 */
	
	/* create old options frame */
	old_opts_fr = gtk_frame_new("Previously saved options");
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(ifopts_edit_dlg)->vbox), 
			old_opts_fr);
	gtk_widget_show(old_opts_fr);
	
	/* create a scrolled window to pack the old options CList widget into */
	old_scr_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(old_scr_win),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_container_border_width(GTK_CONTAINER(old_scr_win), 3);
	gtk_container_add(GTK_CONTAINER(old_opts_fr), old_scr_win);
	gtk_widget_show(old_scr_win);
	
	/* create old options CList (previously saved options) */
	old_clist = gtk_clist_new_with_titles(3, old_titles);
	gtk_clist_set_column_width(GTK_CLIST(old_clist), 0, 200);
	gtk_clist_set_column_width(GTK_CLIST(old_clist), 1, 200);
	gtk_clist_set_column_width(GTK_CLIST(old_clist), 2, 40);
	gtk_clist_column_titles_passive(GTK_CLIST(old_clist));
	gtk_container_add(GTK_CONTAINER(old_scr_win), old_clist);
	
	/* add text to old options cells */
	ifopts_old_options_add(GTK_CLIST(old_clist));
	gtk_widget_show(old_clist);
	
	/* create new options CList to hold currently edited values */
	/* XXX - Since this is an "invisible" widget used only as a table
	 * for storing newly edited interface options, do we need to manually
	 * deallocate/free it? (It's never added to a window with 
	 * gtk_container_add().) */
	new_clist = gtk_clist_new(3);
	
	/* create edit options frame */
	opts_fr = gtk_frame_new("Edit interface options");
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(ifopts_edit_dlg)->vbox), 
			opts_fr);
	gtk_widget_show(opts_fr);
	
	main_hb = gtk_hbox_new(TRUE, 5);
	gtk_container_border_width(GTK_CONTAINER(main_hb), 3);
	gtk_container_add(GTK_CONTAINER(opts_fr), main_hb);
	gtk_widget_show(main_hb);
	
	/* create a scrolled window to pack the interface CList widget into */
	if_scr_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(if_scr_win),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_box_pack_start(GTK_BOX(main_hb), if_scr_win, TRUE, TRUE, 0);
	gtk_widget_show(if_scr_win);
	
	/* create interface CList */
	if_clist = gtk_clist_new_with_titles(1, if_title);
	SIGNAL_CONNECT(if_clist, "select_row", ifopts_edit_ifsel_cb, if_clist);
	SIGNAL_CONNECT(if_clist, "unselect_row", ifopts_edit_ifunsel_cb, if_clist);
	gtk_clist_set_column_width(GTK_CLIST(if_clist), 0, 75);
	gtk_clist_column_titles_passive(GTK_CLIST(if_clist));
	gtk_clist_set_selection_mode(GTK_CLIST(if_clist), GTK_SELECTION_SINGLE);
	gtk_container_add(GTK_CONTAINER(if_scr_win), if_clist);
	
	/* initialize variable that saves the last selected row in "if_clist" */
	ifrow = -1;
	
	/* add text to interface cell */
	ifopts_if_clist_add(GTK_CLIST(if_clist));
	gtk_widget_show(if_clist);
	
	/* table to hold description text entry and hide button */
	main_tb = gtk_table_new(DEVICES_OPTS_ROWS, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_hb), main_tb, TRUE, FALSE, 10);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 10);
	gtk_widget_show(main_tb);
	
	/* create interface description label and text entry */
	if_descr_lb = gtk_label_new("Description:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_descr_lb, 0, 1, 0, 1);
	gtk_misc_set_alignment(GTK_MISC(if_descr_lb), 1.0, 0.5);
	gtk_widget_show(if_descr_lb);
	
	if_descr_te = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(if_descr_te), IF_OPTS_MAX_DESCR_LEN);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_descr_te, 1, 2, 0, 1);
	gtk_widget_show(if_descr_te);
	
	/* create hide interface label and button */
	if_hide_lb = gtk_label_new("Hide interface?:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_hide_lb, 0, 1, 1, 2);
	gtk_misc_set_alignment(GTK_MISC(if_hide_lb), 1.0, 0.5);
	gtk_widget_show(if_hide_lb);
	
	if_hide_cb = gtk_check_button_new();
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_hide_cb, 1, 2, 1, 2);
	gtk_widget_show(if_hide_cb);
	
	/* button row: OK and Cancel buttons */
	bbox = gtk_hbutton_box_new();
	gtk_button_box_set_layout(GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 10);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(ifopts_edit_dlg)->action_area), bbox,
			TRUE, FALSE, 0);
	gtk_widget_show(bbox);

#if GTK_MAJOR_VERSION < 2
	ok_bt = gtk_button_new_with_label ("OK");
#else
	ok_bt = gtk_button_new_from_stock(GTK_STOCK_OK);
#endif

	/* Connect the OK button to ifdescr_edit_ok_cb function */
	SIGNAL_CONNECT(ok_bt, "clicked", ifopts_edit_ok_cb, ifopts_edit_dlg);
	GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
	gtk_container_add(GTK_CONTAINER(bbox), ok_bt);
	gtk_widget_grab_default(ok_bt);
	gtk_widget_show(ok_bt);

#if GTK_MAJOR_VERSION < 2
	cancel_bt = gtk_button_new_with_label ("Cancel");
#else
	cancel_bt = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
	/* Connect the Cancel button to destroy the widget */
	SIGNAL_CONNECT(cancel_bt, "clicked", ifopts_edit_close_cb, ifopts_edit_dlg);
	GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
	gtk_container_add(GTK_CONTAINER(bbox), cancel_bt);
	gtk_widget_show(cancel_bt);

	/* Call a handler when we're destroyed, so we can inform
	   our caller, if any, that we've been destroyed. */
	SIGNAL_CONNECT(ifopts_edit_dlg, "destroy", ifopts_edit_destroy_cb, NULL);

	/* Set the DEVOPTS_CALLER_PTR_KEY for the new dialog to point to
	   our caller. */
	OBJECT_SET_DATA(ifopts_edit_dlg, DEVOPTS_CALLER_PTR_KEY, caller);

	/* Set the DEVOPTS_DIALOG_PTR_KEY for the caller to point to us */
	OBJECT_SET_DATA(caller, DEVOPTS_DIALOG_PTR_KEY, ifopts_edit_dlg);
	
	/* Catch the "key_press_event" signal in the window, so that we can
	   catch the ESC key being pressed and act as if the "Cancel" button
	   had been selected. */
	/*dlg_set_cancel(ifopts_edit_dlg, cancel_bt);*/
	
	gtk_widget_show(ifopts_edit_dlg);
}

/*
 * User selected "OK". Create/write preferences strings.
 */
static void
ifopts_edit_ok_cb(GtkWidget *w _U_, gpointer parent_w)
{
	
	/*
	 * Update option values in "new" CList for the last selected interface.
	 * (Is there a function that returns the currently selected row?)
	 */
	if (ifrow != -1)
		ifopts_edit_ifunsel_cb(NULL, ifrow, 0, NULL, NULL);
	
	/* create/write new interfaces description string */
	ifopts_write_new_descr();
	
	/* create/write new "hidden" interfaces string */
	ifopts_write_new_hide();
	
	/* Now nuke this window. */
	gtk_grab_remove(GTK_WIDGET(parent_w));
	gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
ifopts_edit_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
	gtk_grab_remove(GTK_WIDGET(parent_w));
	gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
ifopts_edit_destroy_cb(GtkWidget *win, gpointer data _U_)
{
	GtkWidget *caller;

	/* Get the widget that requested that we be popped up, if any.
	   (It should arrange to destroy us if it's destroyed, so
	   that we don't get a pointer to a non-existent window here.) */
	caller = OBJECT_GET_DATA(win, DEVOPTS_CALLER_PTR_KEY);

	if (caller != NULL) {
		/* Tell it we no longer exist. */
		OBJECT_SET_DATA(caller, DEVOPTS_DIALOG_PTR_KEY, NULL);
	}

	/* Now nuke this window. */
	gtk_grab_remove(GTK_WIDGET(win));
	gtk_widget_destroy(GTK_WIDGET(win));
}

/*
 * Interface selected callback; update displayed widgets.
 */
static void
ifopts_edit_ifsel_cb(GtkWidget		*clist _U_,
					 gint			row,
					 gint			column _U_,
					 GdkEventButton	*event _U_,
					 gpointer		data _U_)
{
	gchar *text;
	
	/* get/display the interface description from "new" CList */
	gtk_clist_get_text(GTK_CLIST(new_clist), row, 1, &text);
	gtk_entry_set_text(GTK_ENTRY(if_descr_te), text);
	
	/* get/display the "hidden" button state from "new" CList */
	gtk_clist_get_text(GTK_CLIST(new_clist), row, 2, &text);
	if (*text == '1')
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_hide_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_hide_cb), FALSE);
	
	/* save currently selected row so we can update its values on "OK". */
	ifrow = row;
}

/*
 * Interface unselected callback; update "new" CList values.
 *
 * NOTE:
 *		This is also called from "ifopts_edit_ok_cb" to update values in 
 *		the "new" CList for the last selected interface; only "row" is passed
 *		as a valid value. Others are "NULL" or "0".
 */
static void
ifopts_edit_ifunsel_cb(GtkWidget		*clist _U_,
						gint			row,
						gint			column _U_,
						GdkEventButton	*event _U_,
						gpointer		data _U_)
{
	gchar *text;
	gchar state[2] = { '\0' };
	
	/* get interface description and set value in "new" CList */
	text = gtk_editable_get_chars(GTK_EDITABLE(if_descr_te), 0, -1);
	/* replace any reserved formatting characters "()," with spaces */
	g_strdelimit(text, "(),", ' ');
	gtk_clist_set_text(GTK_CLIST(new_clist), row, 1, text);
	g_free(text);
	
	/* get "hidden" button state and set value in "new" CList */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(if_hide_cb)) == TRUE)
		state[0] = '1';
	else
		state[0] = '0';
	gtk_clist_set_text(GTK_CLIST(new_clist), row, 2, state);
}

/*
 * Add previously saved options to cells in "old" CList.
 */
static void
ifopts_old_options_add(GtkCList *clist)
{
	gchar	*p;
	gchar	*ifnm;
	gchar	*desc;
	gchar	*pr_descr;
	gchar	*pr_hide;
	gchar	*text[3] = { '\0' };
	gint	row;
	gint	ct;
	
	/* add interface descriptions and "hidden" yes/no text */
	if (prefs.capture_devices_descr != NULL) {
		/* create working copy of device descriptions */
		pr_descr = g_strdup(prefs.capture_devices_descr);
		p = pr_descr;
		ifnm = p;
		
		while (*p != '\0') {
			/* found comma, start of next interface(description) */
			if (*p == ',') {
				/* add existing text */
				if (text[0] != NULL) {
					row = gtk_clist_append(GTK_CLIST(clist), text);
					gtk_clist_set_selectable(GTK_CLIST(clist), row, FALSE);
					ifopts_options_free(text);
				}
				p++;
				/* reset interface name pointer to start of new name */
				ifnm = p;
			}
			/* found left parenthesis, start of description */
			else if (*p == '(') {
				/* terminate and set interface name text */
				*p = '\0';
				text[0] = g_strdup(ifnm);
				/* check if interface is "hidden" */
				if (prefs.capture_devices_hide != NULL) {
					if (strstr(prefs.capture_devices_hide, ifnm) != NULL)
						text[2] = g_strdup("Yes");
					else
						text[2] = g_strdup("No");
				}
				else
					text[2] = g_strdup("No");
				*p = '(';
				p++;
				/* if syntax error */
				if ((*p == '\0') || (*p == ',') || (*p == '(') || (*p == ')')) {
					ifopts_options_free(text);
					break;
				}
				/* save pointer to beginning of description */
				desc = p;
				p++;
				/* if syntax error */
				if ((*p == '\0') || (*p == ',') || (*p == '(') || (*p == ')')) {
					ifopts_options_free(text);
					break;
				}
				/* skip to end of description */
				while (*p != '\0') {
					/* end of description */
					if (*p == ')') {
						/* terminate and set description text */
						*p = '\0';
						text[1] = g_strdup(desc);
						*p = ')';
						p++;
						break;
					}
					p++;
				}
				/* if we reached last interface description, add text */
				if (*p == '\0') {
					if (text[0] != NULL) {
						row = gtk_clist_append(GTK_CLIST(clist), text);
						gtk_clist_set_selectable(GTK_CLIST(clist), row, FALSE);
						ifopts_options_free(text);
					}
				}
			}
			else
				p++;
		}
		
		g_free(pr_descr);
	}
	
	/*
	 * Only add "hidden" interface yes/no text here; since we may not have
	 * any descriptions, but have "hidden" interfaces.
	 */
	if (prefs.capture_devices_hide != NULL) {
		/* create working copy of hidden interfaces */
		pr_hide = g_strdup(prefs.capture_devices_hide);
		p = pr_hide;
		ifnm = p;
		ct = 0;
		
		while (*p != '\0') {
			/* found comma, start of next interface */
			if ((*p == ',') && (ct > 0)) {
				/* terminate and set text */
				*p = '\0';
				text[0] = g_strdup(ifnm);
				/* set empty description */
				text[1] = NULL;
				/* set "hidden" text */
				text[2] = g_strdup("Yes");
				/* add text if not previously added */
				if (!ifopts_old_options_chk(GTK_CLIST(clist), text[0])) {
					row = gtk_clist_append(GTK_CLIST(clist), text);
					gtk_clist_set_selectable(GTK_CLIST(clist), row, FALSE);
				}
				ifopts_options_free(text);
				*p = ',';
				p++;
				ifnm = p;
				ct = 0;
			}
			p++;
			ct++;
		}
		
		/* if we reached last "hidden" interface in list */
		if (ct > 0) {
			/* set text */
			text[0] = g_strdup(ifnm);
			/* set empty description */
			text[1] = NULL;
			/* set "hidden" text */
			text[2] = g_strdup("Yes");
			/* add text if not previously added */
			if (!ifopts_old_options_chk(GTK_CLIST(clist), text[0])) {
				row = gtk_clist_append(GTK_CLIST(clist), text);
				gtk_clist_set_selectable(GTK_CLIST(clist), row, FALSE);
			}
			ifopts_options_free(text);
		}
		
		g_free(pr_hide);
	}
}

/*
 * Check to see if interface has already been added to "old" options CList.
 * Returns TRUE if it has, FALSE if it hasn't.
 */
static gboolean
ifopts_old_options_chk(GtkCList *clist, gchar *ifname)
{
	gint	i;
	gchar	*ifnm;
	
	/* get interface name for each row */
	for (i = 0; ;i++) {
		if (gtk_clist_get_text(GTK_CLIST(clist), i, 0, &ifnm) != 1)
			break;
		if (strcmp(ifnm, ifname) == 0)
			return TRUE;
	}
	
	return FALSE;
}

/*
 * Add any old options that apply to cells in "new" CList. The "new" CList
 * is never displayed. It's used only as a table to store values as they're
 * edited by the user.
 *
 * NOTE: Be careful here since interfaces may have been removed from the 
 * machine or disabled and no longer apply.
 */
static void
ifopts_new_options_add(GtkCList *clist, gchar *ifname)
{
	gchar	*p;
	gchar	*ifnm;
	gchar	*desc;
	gchar	*pr_descr;
	gchar	*text[3] = { '\0' };
	
	/* add interface descriptions and "hidden" flag */
	if (prefs.capture_devices_descr != NULL) {
		/* create working copy of device descriptions */
		pr_descr = g_strdup(prefs.capture_devices_descr);
		
		/* if we find a description for this interface */
		if ((ifnm = strstr(pr_descr, ifname)) != NULL) {
			p = ifnm;
			while (*p != '\0') {
				/* found left parenthesis, start of description */
				if (*p == '(') {
					/* set interface name text */
					text[0] = g_strdup(ifname);
					/* check if interface is "hidden" */
					if (prefs.capture_devices_hide != NULL) {
						if (strstr(prefs.capture_devices_hide, ifname) != NULL)
							text[2] = g_strdup("1");
						else
							text[2] = g_strdup("0");
					}
					else
						text[2] = g_strdup("0");
					p++;
					/* if syntax error */
					if ((*p == '\0') || (*p == ',') || (*p == '(') || (*p == ')')) {
						ifopts_options_free(text);
						break;
					}
					/* save pointer to beginning of description */
					desc = p;
					p++;
					/* if syntax error */
					if ((*p == '\0') || (*p == ',') || (*p == '(') || (*p == ')')) {
						ifopts_options_free(text);
						break;
					}
					/* skip to end of description */
					while (*p != '\0') {
						/* end of description */
						if (*p == ')') {
							/* terminate and set description text */
							*p = '\0';
							text[1] = g_strdup(desc);
							/* add row to CList */
							gtk_clist_append(GTK_CLIST(clist), text);
							ifopts_options_free(text);
							break;
						}
						p++;
					}
					/* get out */
					break;
				}
				else
					p++;
			}
		}
		/* if there's no description for this interface */
		else {
			/* set interface name */
			text[0] = g_strdup(ifname);
			/* set empty description */
			text[1] = NULL;
			/* check if interface is "hidden" */
			if (prefs.capture_devices_hide != NULL) {
				if (strstr(prefs.capture_devices_hide, ifname) != NULL)
					text[2] = g_strdup("1");
				else
					text[2] = g_strdup("0");
			}
			else
				text[2] = g_strdup("0");
			
			/* add row to CList */
			gtk_clist_append(GTK_CLIST(clist), text);
			ifopts_options_free(text);
		}
		
		g_free(pr_descr);
	}
	/*
	 * If we do not have any descriptions, but have "hidden" interfaces.
	 */
	else if (prefs.capture_devices_hide != NULL) {
		/* set interface name */
		text[0] = g_strdup(ifname);
		/* set empty description */
		text[1] = NULL;
		/* check if interface is "hidden" */
		if (strstr(prefs.capture_devices_hide, ifname) != NULL)
			text[2] = g_strdup("1");
		else
			text[2] = g_strdup("0");
		
		/* add row to CList */
		gtk_clist_append(GTK_CLIST(clist), text);
		ifopts_options_free(text);
	}
	/*
	 * If we have no descriptions and no "hidden" interfaces.
	 */
	else {
		/* set interface name */
		text[0] = g_strdup(ifname);
		/* set empty description */
		text[1] = NULL;
		/* interface is not "hidden" */
		text[2] = g_strdup("0");
		
		/* add row to CList */
		gtk_clist_append(GTK_CLIST(clist), text);
		ifopts_options_free(text);
	}
}

static void
ifopts_options_free(gchar *text[])
{
	gint i;
	
	for (i=0; i < IF_OPTS_CLIST_COLS; i++) {
		if (text[i] != NULL) {
			g_free(text[i]);
			text[i] = NULL;
		}
	}
}

/*
 * Add interfaces to displayed interfaces CList. Also, fill "new" options CList.
 */
static void
ifopts_if_clist_add(GtkCList *clist)
{
	GList	*if_list;
	int		err;
	char	err_str[PCAP_ERRBUF_SIZE];
	gchar	*text[1];
	guint	i;
	guint	nitems;
	
	if_list = get_interface_list(&err, err_str);
	if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
		simple_dialog(ESD_TYPE_WARN, NULL, "Can't get list of interfaces: %s",
				err_str);
		return;
	}
	
	/* Seems we need to be at list head for g_list_length()? */
	if_list = g_list_first(if_list);
	nitems = g_list_length(if_list);
	
	/* add interface name text to CList */
	for (i=0; i < nitems; i++) {
		text[0] = g_list_nth_data(if_list, i);
		/* should never happen, but just in case */
		if (text[0] == NULL)
			continue;
		gtk_clist_append(GTK_CLIST(clist), text);
		/* fill "new" options CList with previously saved values */
		ifopts_new_options_add(GTK_CLIST(new_clist), text[0]);
	}
	
	free_interface_list(if_list);
}

/*
 * Create/write new interfaces description string based on "new" CList.
 */
static void
ifopts_write_new_descr(void)
{
	gint	i;
	gint	first_if = 1;				/* flag to check if 1st in list */
	gchar	*ifnm;
	gchar	*desc;
	gchar	*tmp_descr;
	gchar	*new_descr;
	
	/* new preferences interfaces description string */
	new_descr = g_malloc0(MAX_VAL_LEN);
	if (new_descr == NULL) {
		simple_dialog(ESD_TYPE_WARN, NULL, "Error (1) saving interface "
				"descriptions: malloc failure");
		return;
	}
	
	/*
	 * current row's interface description string
	 * (leave space for parens, comma and terminator)
	 */
	/*
	 * XXX - Currently, MAX_WIN_IF_NAME_LEN is 511. This should be large 
	 * enough for *nix. ;o)
	 */
	tmp_descr = g_malloc0(IF_OPTS_MAX_DESCR_LEN + MAX_WIN_IF_NAME_LEN + 4);
	if (tmp_descr == NULL) {
		simple_dialog(ESD_TYPE_WARN, NULL, "Error (2) saving interface "
				"descriptions: malloc failure");
		g_free(new_descr);
		return;
	}
	
	/* get description for each row (interface) */
	for (i = 0; ;i++) {
		/* get description */
		if (gtk_clist_get_text(GTK_CLIST(new_clist), i, 1, &desc) != 1)
			break;
		/* if no description, skip this interface */
		if (strlen(desc) == 0)
			continue;
		/* get interface name */
		gtk_clist_get_text(GTK_CLIST(new_clist), i, 0, &ifnm);
		
		/*
		 * create/cat interface description to new string
		 * (leave space for parens, comma and terminator)
		 */
		if ((strlen(ifnm) + strlen(desc) + 4 + 
				strlen(new_descr)) <  MAX_VAL_LEN) {
			if (first_if == 1)
				snprintf(tmp_descr, IF_OPTS_MAX_DESCR_LEN+MAX_WIN_IF_NAME_LEN+4,
						"%s(%s)", ifnm, desc);
			else
				snprintf(tmp_descr, IF_OPTS_MAX_DESCR_LEN+MAX_WIN_IF_NAME_LEN+4,
						",%s(%s)", ifnm, desc);
			strcat(new_descr, tmp_descr);
			/* set first-in-list flag to false */
			first_if = 0;
		}
		/* interface name + description is too large */
		else {
			simple_dialog(ESD_TYPE_WARN, NULL, "Error saving interface "
					"description for:\n%s\n(too long)", ifnm);
			continue;
		}
	}
	
	/* write new description string to preferences */
	if (strlen(new_descr) > 0) {
		g_free(prefs.capture_devices_descr);
		prefs.capture_devices_descr = new_descr;
	}
	/* no descriptions */
	else {
		g_free(prefs.capture_devices_descr);
		g_free(new_descr);
		prefs.capture_devices_descr = NULL;
	}
}

/*
 * Create/write new "hidden" interfaces string based on "new" CList.
 */
static void
ifopts_write_new_hide(void)
{
	gint	i;
	gint	first_if = 1;				/* flag to check if 1st in list */
	gchar	*ifnm;
	gchar	*hide;
	gchar	*tmp_hide;
	gchar	*new_hide;
	
	/* new preferences "hidden" interfaces string */
	new_hide = g_malloc0(MAX_VAL_LEN);
	if (new_hide == NULL) {
		simple_dialog(ESD_TYPE_WARN, NULL, "Error (1) saving \"hidden\" "
				"interfaces: malloc failure");
		return;
	}
	
	/*
	 * current row's interface name if "hidden"
	 * (leave space for comma and terminator)
	 */
	/*
	 * XXX - Currently, MAX_WIN_IF_NAME_LEN is 511. This should be large 
	 * enough for *nix. ;o)
	 */
	tmp_hide = g_malloc0(MAX_WIN_IF_NAME_LEN + 2);
	if (tmp_hide == NULL) {
		simple_dialog(ESD_TYPE_WARN, NULL, "Error (2) saving \"hidden\" "
				"interfaces: malloc failure");
		g_free(new_hide);
		return;
	}
	
	/* get "hidden" flag for each row (interface) */
	for (i = 0; ;i++) {
		/* get flag */
		if (gtk_clist_get_text(GTK_CLIST(new_clist), i, 2, &hide) != 1)
			break;
		/* if flag is not "1", skip this interface */
		if (*hide == '0')
			continue;
		/* get interface name */
		gtk_clist_get_text(GTK_CLIST(new_clist), i, 0, &ifnm);
		
		/*
		 * create/cat interface to new string
		 * (leave space for comma and terminator)
		 */
		if ((strlen(ifnm) + 2 + strlen(new_hide)) <  MAX_VAL_LEN) {
			if (first_if == 1)
				snprintf(tmp_hide, MAX_WIN_IF_NAME_LEN+2, "%s", ifnm);
			else
				snprintf(tmp_hide, MAX_WIN_IF_NAME_LEN+2, ",%s", ifnm);
			strcat(new_hide, tmp_hide);
			/* set first-in-list flag to false */
			first_if = 0;
		}
		/* interface name is too large */
		else {
			simple_dialog(ESD_TYPE_WARN, NULL, "Error saving \"hidden\" "
					"interface for:\n%s\n(too long)", ifnm);
			continue;
		}
	}
	
	/* write new "hidden" string to preferences */
	if (strlen(new_hide) > 0) {
		g_free(prefs.capture_devices_hide);
		prefs.capture_devices_hide = new_hide;
	}
	/* no "hidden" interfaces */
	else {
		g_free(prefs.capture_devices_hide);
		g_free(new_hide);
		prefs.capture_devices_hide = NULL;
	}
}

#endif /* HAVE_LIBPCAP */
