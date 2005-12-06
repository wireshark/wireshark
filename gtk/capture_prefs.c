/* capture_prefs.c
 * Dialog box for capture preferences
 *
 * $Id$
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

#include <pcap.h>
#include <string.h>
#include <gtk/gtk.h>

#include "globals.h"
#include "capture_prefs.h"
#include "gtkglobals.h"
#include <epan/prefs.h>
#include "prefs_dlg.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "simple_dialog.h"
#include "capture-pcap-util.h"
#include "capture_ui_utils.h"
#include "main.h"
#include "compat_macros.h"

#define DEVICE_KEY				"device"
#define PROM_MODE_KEY			"prom_mode"
#define CAPTURE_REAL_TIME_KEY	"capture_real_time"
#define AUTO_SCROLL_KEY			"auto_scroll"
#define SHOW_INFO_KEY           "show_info"

#define CAPTURE_TABLE_ROWS 6

#define IFOPTS_CALLER_PTR_KEY	"ifopts_caller_ptr"
#define IFOPTS_DIALOG_PTR_KEY	"ifopts_dialog_ptr"
#define IFOPTS_TABLE_ROWS 2
#define IFOPTS_CLIST_COLS 4
#define IFOPTS_MAX_DESCR_LEN 128
#define IFOPTS_IF_NOSEL -1

/* interface options dialog */
static GtkWidget *cur_clist, *if_dev_lb, *if_name_lb, *if_descr_te, *if_hide_cb;
static gint ifrow;						/* current interface row selected */

static void ifopts_edit_cb(GtkWidget *w, gpointer data);
static void ifopts_edit_ok_cb(GtkWidget *w, gpointer parent_w);
static void ifopts_edit_destroy_cb(GtkWidget *win, gpointer data);
static void ifopts_edit_ifsel_cb(GtkWidget *clist, gint row, gint column,
    GdkEventButton *event, gpointer data);
static void ifopts_edit_descr_changed_cb(GtkEditable *ed, gpointer udata);
static void ifopts_edit_hide_changed_cb(GtkToggleButton *tbt, gpointer udata);
static void ifopts_options_add(GtkCList *clist, if_info_t *if_info);
static void ifopts_options_free(gchar *text[]);
static void ifopts_if_clist_add(void);
static void ifopts_write_new_descr(void);
static void ifopts_write_new_hide(void);

GtkWidget*
capture_prefs_show(void)
{
	GtkWidget	*main_tb, *main_vb;
	GtkWidget	*if_cb, *if_lb, *promisc_cb, *sync_cb, *auto_scroll_cb, *show_info_cb;
	GtkWidget	*ifopts_lb, *ifopts_bt;
	GList		*if_list, *combo_list;
	int		err;
	char		err_str[PCAP_ERRBUF_SIZE];
    int         row = 0;
    GtkTooltips *tooltips = gtk_tooltips_new();

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
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_lb, 0, 1, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(if_lb), 1.0, 0.5);
	gtk_widget_show(if_lb);

	if_cb = gtk_combo_new();
	/*
	 * XXX - what if we can't get the list?
	 */
	if_list = get_interface_list(&err, err_str);
	combo_list = build_capture_combo_list(if_list, FALSE);
	free_interface_list(if_list);
	if (combo_list != NULL) {
		gtk_combo_set_popdown_strings(GTK_COMBO(if_cb), combo_list);
		free_capture_combo_list(combo_list);
	}
	if (prefs.capture_device)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry),
		    prefs.capture_device);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_cb, 1, 2, row, row+1);
    gtk_tooltips_set_tip(tooltips, GTK_COMBO(if_cb)->entry, 
        "The default interface to be captured from.", NULL);
	gtk_widget_show(if_cb);
	OBJECT_SET_DATA(main_vb, DEVICE_KEY, if_cb);
    row++;

	/* Interface properties */
	ifopts_lb = gtk_label_new("Interfaces:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), ifopts_lb, 0, 1, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(ifopts_lb), 1.0, 0.5);
	gtk_widget_show(ifopts_lb);

	ifopts_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_EDIT);
    gtk_tooltips_set_tip(tooltips, ifopts_bt, 
        "Open a dialog box to set various interface options.", NULL);
	SIGNAL_CONNECT(ifopts_bt, "clicked", ifopts_edit_cb, NULL);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), ifopts_bt, 1, 2, row, row+1);
    row++;

	/* Promiscuous mode */
	promisc_cb = create_preference_check_button(main_tb, row++,
	    "Capture packets in promiscuous mode:", NULL,
	    prefs.capture_prom_mode);
    gtk_tooltips_set_tip(tooltips, promisc_cb, 
        "Usually a network card will only capture the traffic sent to its own network address. "
        "If you want to capture all traffic that the network card can \"see\", mark this option. "
        "See the FAQ for some more details of capturing packets from a switched network.", NULL);
	OBJECT_SET_DATA(main_vb, PROM_MODE_KEY, promisc_cb);

	/* Real-time capture */
	sync_cb = create_preference_check_button(main_tb, row++,
	    "Update list of packets in real time:", NULL,
	    prefs.capture_real_time);
    gtk_tooltips_set_tip(tooltips, sync_cb,
        "Update the list of packets while capture is in progress. "
        "Don't use this option if you notice packet drops.", NULL);
	OBJECT_SET_DATA(main_vb, CAPTURE_REAL_TIME_KEY, sync_cb);

	/* Auto-scroll real-time capture */
	auto_scroll_cb = create_preference_check_button(main_tb, row++,
	    "Automatic scrolling in live capture:", NULL,
	    prefs.capture_auto_scroll);
    gtk_tooltips_set_tip(tooltips, auto_scroll_cb,
        "Automatic scrolling of the packet list while live capture is in progress. ", NULL);
	OBJECT_SET_DATA(main_vb, AUTO_SCROLL_KEY, auto_scroll_cb);

	/* Show capture info dialog */
	show_info_cb = create_preference_check_button(main_tb, row++,
	    "Hide capture info dialog:", NULL,
	    !prefs.capture_show_info);
    gtk_tooltips_set_tip(tooltips, show_info_cb,
        "Hide the capture info dialog while capturing. "
        "Will only take effect, if the \"Update list of packets in real time\" "
        "option is also used.", NULL);
	OBJECT_SET_DATA(main_vb, SHOW_INFO_KEY, show_info_cb);

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}

void
capture_prefs_fetch(GtkWidget *w)
{
	GtkWidget *if_cb, *promisc_cb, *sync_cb, *auto_scroll_cb, *show_info_cb;
	gchar	*if_text;

	if_cb = (GtkWidget *)OBJECT_GET_DATA(w, DEVICE_KEY);
	promisc_cb = (GtkWidget *)OBJECT_GET_DATA(w, PROM_MODE_KEY);
	sync_cb = (GtkWidget *)OBJECT_GET_DATA(w, CAPTURE_REAL_TIME_KEY);
	auto_scroll_cb = (GtkWidget *)OBJECT_GET_DATA(w, AUTO_SCROLL_KEY);
    show_info_cb = (GtkWidget *)OBJECT_GET_DATA(w, SHOW_INFO_KEY);

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

    prefs.capture_show_info = !(GTK_TOGGLE_BUTTON (show_info_cb)->active);
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
	dlg = OBJECT_GET_DATA(caller, IFOPTS_DIALOG_PTR_KEY);

	if (dlg != NULL) {
		/* Yes.  Destroy it. */
		window_destroy(dlg);
	}
}

/*
 * Create an edit interface options dialog.
 */
static void
ifopts_edit_cb(GtkWidget *w, gpointer data _U_)
{
	GtkWidget	*ifopts_edit_dlg, *cur_scr_win, *main_hb, *main_tb,
				*cur_opts_fr, *ed_opts_fr, *main_vb,
				*if_descr_lb, *if_hide_lb,
				*bbox, *ok_bt, *cancel_bt;
	const gchar *cur_titles[] = { "Device", "Description", "Comment", "Hide?" };
	int row = 0;

	GtkWidget *caller = gtk_widget_get_toplevel(w);
	
	/* Has an edit dialog box already been opened for that top-level
	   widget? */
	ifopts_edit_dlg = OBJECT_GET_DATA(caller, IFOPTS_DIALOG_PTR_KEY);
	if (ifopts_edit_dlg != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(ifopts_edit_dlg);
		return;
	}
	
	/* create a new dialog */
	ifopts_edit_dlg = dlg_window_new("Ethereal: Preferences: Interface Options");
    gtk_window_set_default_size(GTK_WINDOW(ifopts_edit_dlg), DEF_WIDTH, 300);

    main_vb = gtk_vbox_new(FALSE, 1);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
	gtk_container_add(GTK_CONTAINER(ifopts_edit_dlg), main_vb);
	gtk_widget_show(main_vb);
	
	/* create current options frame */
	cur_opts_fr = gtk_frame_new("Interfaces");
	gtk_container_add(GTK_CONTAINER(main_vb), cur_opts_fr);
	gtk_widget_show(cur_opts_fr);
	
	/* create a scrolled window to pack the current options CList widget into */
	cur_scr_win = scrolled_window_new(NULL, NULL);
	gtk_container_border_width(GTK_CONTAINER(cur_scr_win), 3);
	gtk_container_add(GTK_CONTAINER(cur_opts_fr), cur_scr_win);
	gtk_widget_show(cur_scr_win);
	
	/*
	 * Create current options CList.
	 */
	cur_clist = gtk_clist_new_with_titles(IFOPTS_CLIST_COLS, (gchar **) cur_titles);
	gtk_clist_set_column_width(GTK_CLIST(cur_clist), 1, 230);
	gtk_clist_set_column_width(GTK_CLIST(cur_clist), 2, 260);
	gtk_clist_set_column_width(GTK_CLIST(cur_clist), 3, 40);
	gtk_clist_column_titles_passive(GTK_CLIST(cur_clist));
	gtk_container_add(GTK_CONTAINER(cur_scr_win), cur_clist);
	SIGNAL_CONNECT(cur_clist, "select_row", ifopts_edit_ifsel_cb, NULL);
	gtk_widget_show(cur_clist);
	
	/* add interface names to cell */
	ifopts_if_clist_add();
    gtk_clist_columns_autosize(GTK_CLIST(cur_clist));
	
	/* initialize variable that saves currently selected row in "if_clist" */
	ifrow = IFOPTS_IF_NOSEL;
	
	/* create edit options frame */
	ed_opts_fr = gtk_frame_new("Properties");
	gtk_box_pack_start(GTK_BOX(main_vb), ed_opts_fr, FALSE, FALSE, 0);
	gtk_widget_show(ed_opts_fr);
	
	main_hb = gtk_hbox_new(TRUE, 5);
	gtk_container_border_width(GTK_CONTAINER(main_hb), 3);
	gtk_container_add(GTK_CONTAINER(ed_opts_fr), main_hb);
	gtk_widget_show(main_hb);
		
	/* table to hold description text entry and hide button */
	main_tb = gtk_table_new(IFOPTS_TABLE_ROWS, 4, FALSE);
	gtk_box_pack_start(GTK_BOX(main_hb), main_tb, TRUE, FALSE, 10);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 10);
	gtk_widget_show(main_tb);

	if_dev_lb = gtk_label_new("Device:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_dev_lb, 0, 1, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(if_dev_lb), 1.0, 0.5);
	gtk_widget_show(if_dev_lb);
    
	if_dev_lb = gtk_label_new("");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_dev_lb, 1, 2, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(if_dev_lb), 0.0, 0.5);
	gtk_widget_show(if_dev_lb);
    row++;
    
	if_name_lb = gtk_label_new("Description:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_name_lb, 0, 1, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(if_name_lb), 1.0, 0.5);
	gtk_widget_show(if_name_lb);
    
	if_name_lb = gtk_label_new("");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_name_lb, 1, 2, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(if_name_lb), 0.0, 0.5);
	gtk_widget_show(if_name_lb);
    row++;
    
	/* create interface description label and text entry */
	if_descr_lb = gtk_label_new("Comment:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_descr_lb, 0, 1, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(if_descr_lb), 1.0, 0.5);
	gtk_widget_show(if_descr_lb);
	
	if_descr_te = gtk_entry_new();
	SIGNAL_CONNECT(if_descr_te, "changed", ifopts_edit_descr_changed_cb, 
			cur_clist);
	gtk_entry_set_max_length(GTK_ENTRY(if_descr_te), IFOPTS_MAX_DESCR_LEN);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_descr_te, 1, 2, row, row+1);
	gtk_widget_show(if_descr_te);
    row++;
	
	/* create hide interface label and button */
	if_hide_lb = gtk_label_new("Hide interface?:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_hide_lb, 0, 1, row, row+1);
	gtk_misc_set_alignment(GTK_MISC(if_hide_lb), 1.0, 0.5);
	gtk_widget_show(if_hide_lb);
	
	if_hide_cb = gtk_check_button_new();
	SIGNAL_CONNECT(if_hide_cb, "toggled", ifopts_edit_hide_changed_cb, 
			cur_clist);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_hide_cb, 1, 2, row, row+1);
	gtk_widget_show(if_hide_cb);
    row++;
	
	/* button row: OK and Cancel buttons */
	bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
	SIGNAL_CONNECT(ok_bt, "clicked", ifopts_edit_ok_cb, ifopts_edit_dlg);

	cancel_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    window_set_cancel_button(ifopts_edit_dlg, cancel_bt, window_cancel_button_cb);

	gtk_widget_grab_default(ok_bt);

    SIGNAL_CONNECT(ifopts_edit_dlg, "delete_event", window_delete_event_cb,
                 NULL);
	/* Call a handler when we're destroyed, so we can inform
	   our caller, if any, that we've been destroyed. */
	SIGNAL_CONNECT(ifopts_edit_dlg, "destroy", ifopts_edit_destroy_cb, NULL);

	/* Set the key for the new dialog to point to our caller. */
	OBJECT_SET_DATA(ifopts_edit_dlg, IFOPTS_CALLER_PTR_KEY, caller);
	/* Set the key for the caller to point to us */
	OBJECT_SET_DATA(caller, IFOPTS_DIALOG_PTR_KEY, ifopts_edit_dlg);

    /* select the first row in if list, all option fields must exist for this */
	gtk_clist_select_row(GTK_CLIST(cur_clist), 0, -1);
    
	gtk_widget_show(ifopts_edit_dlg);
    window_present(ifopts_edit_dlg);
}

/*
 * User selected "OK". Create/write preferences strings.
 */
static void
ifopts_edit_ok_cb(GtkWidget *w _U_, gpointer parent_w)
{
	if (ifrow != IFOPTS_IF_NOSEL) {
		/* create/write new interfaces description string */
		ifopts_write_new_descr();
		
		/* create/write new "hidden" interfaces string */
		ifopts_write_new_hide();
	}
	
	/* Now nuke this window. */
	gtk_grab_remove(GTK_WIDGET(parent_w));
	window_destroy(GTK_WIDGET(parent_w));
}

static void
ifopts_edit_destroy_cb(GtkWidget *win, gpointer data _U_)
{
	GtkWidget *caller;

	/* Get the widget that requested that we be popped up, if any.
	   (It should arrange to destroy us if it's destroyed, so
	   that we don't get a pointer to a non-existent window here.) */
	caller = OBJECT_GET_DATA(win, IFOPTS_CALLER_PTR_KEY);

	if (caller != NULL) {
		/* Tell it we no longer exist. */
		OBJECT_SET_DATA(caller, IFOPTS_DIALOG_PTR_KEY, NULL);
	}
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
	
	/* save currently selected row */
	ifrow = row;
	
	/* get/display the interface device from current CList */
	gtk_clist_get_text(GTK_CLIST(cur_clist), row, 0, &text);
    /* is needed, as gtk_entry_set_text() will change text again (bug in GTK?) */
    text = strdup(text);
	gtk_label_set_text(GTK_LABEL(if_dev_lb), text);
    g_free(text);
	
	/* get/display the interface name from current CList */
	gtk_clist_get_text(GTK_CLIST(cur_clist), row, 1, &text);
    /* is needed, as gtk_entry_set_text() will change text again (bug in GTK?) */
    text = strdup(text);
	gtk_label_set_text(GTK_LABEL(if_name_lb), text);
    g_free(text);
	
	/* get/display the interface description from current CList */
	gtk_clist_get_text(GTK_CLIST(cur_clist), row, 2, &text);
    /* is needed, as gtk_entry_set_text() will change text again (bug in GTK?) */
    text = strdup(text);
	gtk_entry_set_text(GTK_ENTRY(if_descr_te), text);
    g_free(text);
	
	/* get/display the "hidden" button state from current CList */
	gtk_clist_get_text(GTK_CLIST(cur_clist), row, 3, &text);
	if (strcmp("Yes", text) == 0)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_hide_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_hide_cb), FALSE);
}

/*
 * Comment text entry changed callback; update current CList.
 */
static void
ifopts_edit_descr_changed_cb(GtkEditable *ed, gpointer udata)
{
	gchar *text;
	
	if (ifrow == IFOPTS_IF_NOSEL)
		return;
	
	/* get current description text and set value in current CList */
	text = gtk_editable_get_chars(GTK_EDITABLE(ed), 0, -1);
	/* replace any reserved formatting characters "()," with spaces */
	g_strdelimit(text, "(),", ' ');
	gtk_clist_set_text(GTK_CLIST(udata), ifrow, 2, text);
	g_free(text);
}

/*
 * Hide toggle button changed callback; update current CList.
 */
static void
ifopts_edit_hide_changed_cb(GtkToggleButton *tbt, gpointer udata)
{
	if (ifrow == IFOPTS_IF_NOSEL)
		return;
	
	/* get "hidden" button state and set text in current CList */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tbt)) == TRUE)
		gtk_clist_set_text(GTK_CLIST(udata), ifrow, 3, "Yes");
	else
		gtk_clist_set_text(GTK_CLIST(udata), ifrow, 3, "No");
}

/*
 * Add any saved options that apply to cells in current CList.
 *
 * NOTE:
 *		Interfaces that have been removed from the machine or disabled and 
 *		no longer apply are ignored. Therefore, if the user subsequently 
 *		selects "OK", the options for these interfaces are lost (they're 
 *		lost permanently if "Save" is selected).
 */
static void
ifopts_options_add(GtkCList *clist, if_info_t *if_info)
{
	gint	row;
	gchar	*p;
	gchar	*ifnm;
	gchar	*desc;
	gchar	*pr_descr;
	gchar	*text[] = { NULL, NULL, NULL, NULL };
	
	/* add interface descriptions and "hidden" flag */
	if (prefs.capture_devices_descr != NULL) {
		/* create working copy of device descriptions */
		pr_descr = g_strdup(prefs.capture_devices_descr);
		
		/* if we find a description for this interface */
		if ((ifnm = strstr(pr_descr, if_info->name)) != NULL) {
			p = ifnm;
			while (*p != '\0') {
				/* found left parenthesis, start of description */
				if (*p == '(') {
					/* set device name text */
					text[0] = g_strdup(if_info->name);
					/* set OS description + device name text */
					if (if_info->description != NULL)
						text[1] = g_strdup(if_info->description);
					else
						text[1] = g_strdup("");
					/* check if interface is "hidden" */
					if (prefs.capture_devices_hide != NULL) {
						if (strstr(prefs.capture_devices_hide, if_info->name) != NULL)
							text[3] = g_strdup("Yes");
						else
							text[3] = g_strdup("No");
					}
					else
						text[3] = g_strdup("No");
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
							text[2] = g_strdup(desc);
							/* add row to CList */
							row = gtk_clist_append(GTK_CLIST(clist), text);
							gtk_clist_set_selectable(GTK_CLIST(clist), row, 
									FALSE);
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
			/* set device name text */
			text[0] = g_strdup(if_info->name);
			/* set OS description + device name text */
			if (if_info->description != NULL)
				text[1] = g_strdup(if_info->description);
			else
				text[1] = g_strdup("");
			/* set empty description */
			text[2] = g_strdup("");
			/* check if interface is "hidden" */
			if (prefs.capture_devices_hide != NULL) {
				if (strstr(prefs.capture_devices_hide, if_info->name) != NULL)
					text[3] = g_strdup("Yes");
				else
					text[3] = g_strdup("No");
			}
			else
				text[3] = g_strdup("No");
			
			/* add row to CList */
			row = gtk_clist_append(GTK_CLIST(clist), text);
			gtk_clist_set_selectable(GTK_CLIST(clist), row, FALSE);
			ifopts_options_free(text);
		}
		
		g_free(pr_descr);
	}
	/*
	 * If we do not have any descriptions, but have "hidden" interfaces.
	 */
	else if (prefs.capture_devices_hide != NULL) {
		/* set device name text */
		text[0] = g_strdup(if_info->name);
		/* set OS description + device name text */
		if (if_info->description != NULL)
			text[1] = g_strdup(if_info->description);
		else
			text[1] = g_strdup("");
		/* set empty description */
		text[2] = g_strdup("");
		/* check if interface is "hidden" */
		if (strstr(prefs.capture_devices_hide, if_info->name) != NULL)
			text[3] = g_strdup("Yes");
		else
			text[3] = g_strdup("No");
		
		/* add row to CList */
		row = gtk_clist_append(GTK_CLIST(clist), text);
		gtk_clist_set_selectable(GTK_CLIST(clist), row, FALSE);
		ifopts_options_free(text);
	}
	/*
	 * If we have no descriptions and no "hidden" interfaces.
	 */
	else {
		/* set device name text */
		text[0] = g_strdup(if_info->name);
		/* set OS description + device name text */
		if (if_info->description != NULL)
			text[1] = g_strdup(if_info->description);
		else
			text[1] = g_strdup("");
		/* set empty description */
		text[2] = g_strdup("");
		/* interface is not "hidden" */
		text[3] = g_strdup("No");
		
		/* add row to CList */
		row = gtk_clist_append(GTK_CLIST(clist), text);
		gtk_clist_set_selectable(GTK_CLIST(clist), row, FALSE);
		ifopts_options_free(text);
	}
}

static void
ifopts_options_free(gchar *text[])
{
	gint i;
	
	for (i=0; i < IFOPTS_CLIST_COLS; i++) {
		if (text[i] != NULL) {
			g_free(text[i]);
			text[i] = NULL;
		}
	}
}

/*
 * Add all interfaces to interfaces CList.
 */
static void
ifopts_if_clist_add(void)
{
	GList		*if_list;
	int		err;
	char		err_str[PCAP_ERRBUF_SIZE];
	gchar		*cant_get_if_list_errstr;
	if_info_t	*if_info;
	guint		i;
	guint		nitems;
	
	if_list = get_interface_list(&err, err_str);
	if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
		cant_get_if_list_errstr =
		    cant_get_if_list_error_message(err_str);
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s",
		    cant_get_if_list_errstr);
		g_free(cant_get_if_list_errstr);
		return;
	}
	
	/* Seems we need to be at list head for g_list_length()? */
	if_list = g_list_first(if_list);
	nitems = g_list_length(if_list);
	
	/* add OS description + interface name text to CList */
	for (i=0; i < nitems; i++) {
		if_info = g_list_nth_data(if_list, i);
		/* should never happen, but just in case */
		if (if_info == NULL)
			continue;

        /* fill current options CList with current preference values */
		ifopts_options_add(GTK_CLIST(cur_clist), if_info);
	}
	
	free_interface_list(if_list);
}

/*
 * Create/write new interfaces description string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_descr(void)
{
	gint	i;
	gboolean	first_if = TRUE;				/* flag to check if first in list */
	gchar	*ifnm;
	gchar	*desc;
	gchar	*tmp_descr;
	gchar	*new_descr;
	
	/* new preferences interfaces description string */
	new_descr = g_malloc0(MAX_VAL_LEN);
	
	/* get description for each row (interface) */
	for (i = 0; ;i++) {
		/* get description */
		if (gtk_clist_get_text(GTK_CLIST(cur_clist), i, 2, &desc) != 1)
			break;
		/* if no description, skip this interface */
		if (strlen(desc) == 0)
			continue;
		
		/* get interface name */
		gtk_clist_get_text(GTK_CLIST(cur_clist), i, 0, &ifnm);

		/*
		 * create/cat interface description to new string
		 * (leave space for parens, comma and terminator)
		 */
		if (first_if == TRUE)
			tmp_descr = g_strdup_printf("%s(%s)", ifnm, desc);
		else
			tmp_descr = g_strdup_printf(",%s(%s)", ifnm, desc);
		strcat(new_descr, tmp_descr);
        g_free(tmp_descr);
		/* set first-in-list flag to false */
		first_if = FALSE;
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
 * Create/write new "hidden" interfaces string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_hide(void)
{
	gint	i;
	gint	first_if = TRUE;				/* flag to check if first in list */
	gchar	*ifnm;
	gchar	*hide;
	gchar	*tmp_hide;
	gchar	*new_hide;
	
	/* new preferences "hidden" interfaces string */
	new_hide = g_malloc0(MAX_VAL_LEN);
	
	/* get "hidden" flag text for each row (interface) */
	for (i = 0; ;i++) {
		/* get flag */
		if (gtk_clist_get_text(GTK_CLIST(cur_clist), i, 3, &hide) != 1)
			break;
		/* if flag text is "No", skip this interface */
		if (strcmp("No", hide) == 0)
			continue;

        /* get interface name */
		gtk_clist_get_text(GTK_CLIST(cur_clist), i, 0, &ifnm);
		
		/*
		 * create/cat interface to new string
		 */
		if (first_if == TRUE)
			tmp_hide = g_strdup_printf("%s", ifnm);
		else
			tmp_hide = g_strdup_printf(",%s", ifnm);

		strcat(new_hide, tmp_hide);
        g_free(tmp_hide);
		/* set first-in-list flag to false */
		first_if = FALSE;
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
