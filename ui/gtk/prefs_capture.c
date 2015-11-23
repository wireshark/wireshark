/* prefs_capture.c
 * Dialog box for capture preferences
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

#ifdef HAVE_LIBPCAP

#include <string.h>
#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "capture_opts.h"
#include "caputils/capture_ifinfo.h"
#include "ui/capture_ui_utils.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include "ui/gtk/prefs_capture.h"
#include "ui/gtk/prefs_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/main_welcome.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/old-gtk-compat.h"
#include <epan/strutil.h>

#include <wiretap/wtap.h>

#define DEVICE_KEY		"device"
#define PROM_MODE_KEY		"prom_mode"
#define PCAP_NG_KEY		"pcap_ng"
#define CAPTURE_REAL_TIME_KEY	"capture_real_time"
#define AUTO_SCROLL_KEY		"auto_scroll"
#define SHOW_INFO_KEY           "show_info"

#define IFOPTS_CALLER_PTR_KEY	"ifopts_caller_ptr"
#define IFOPTS_DIALOG_PTR_KEY	"ifopts_dialog_ptr"
#define IFOPTS_LIST_TEXT_COLS   4
#define IFOPTS_MAX_DESCR_LEN  128
#define IFOPTS_IF_NOSEL        -1
#define COLOPTS_CALLER_PTR_KEY	"colopts_caller_ptr"
#define COLOPTS_DIALOG_PTR_KEY	"colopts_dialog_ptr"

static GtkWidget	*capture_window;

/* interface options dialog */
static GtkWidget *cur_list, *if_dev_lb, *if_name_lb, *if_linktype_lb, *if_linktype_cb, *if_descr_te, *if_hide_cb, *if_default_if_lb;
#ifdef HAVE_PCAP_CREATE
static GtkWidget *if_monitor_lb, *if_monitor_cb;
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
static GtkWidget *if_buffersize_lb, *if_buffersize_cb;
#endif
static GtkWidget *if_snaplen_lb, *if_snaplen_cb, *if_snaplen_tg, *if_pmode_lb, *if_pmode_cb;
static GtkTreeSelection *if_selection;	/* current interface row selected */
static int num_linktypes;
static gboolean interfaces_info_nochange;  /* TRUE to ignore Interface Options Properties */
					   /*  widgets "changed" callbacks.               */

static void ifopts_edit_cb(GtkWidget *w, gpointer data);
static void ifopts_edit_ok_cb(GtkWidget *w, gpointer parent_w);
static void ifopts_edit_destroy_cb(GtkWidget *win, gpointer data);
static void ifopts_edit_ifsel_cb(GtkTreeSelection *selection, gpointer data);
#ifdef HAVE_PCAP_CREATE
static void ifopts_edit_monitor_changed_cb(GtkToggleButton *tbt, gpointer udata);
#endif
static void ifopts_edit_linktype_changed_cb(GtkComboBox *ed, gpointer udata);
static void ifopts_edit_descr_changed_cb(GtkEditable *ed, gpointer udata);
static void ifopts_edit_hide_changed_cb(GtkToggleButton *tbt, gpointer udata);
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
static void ifopts_edit_buffersize_changed_cb(GtkSpinButton *ed, gpointer udata);
#endif
static void ifopts_edit_snaplen_changed_cb(GtkSpinButton *ed, gpointer udata);
static void ifopts_edit_hassnap_changed_cb(GtkToggleButton *tbt, gpointer udata);
static void ifopts_edit_pmode_changed_cb(GtkToggleButton *tbt, gpointer udata);
static void ifopts_options_add(GtkListStore *list_store, if_info_t *if_info);
static void ifopts_options_free(gchar *text[]);
static void ifopts_if_liststore_add(void);
#ifdef HAVE_PCAP_CREATE
static void ifopts_write_new_monitor_mode(void);
#endif
static void ifopts_write_new_linklayer(void);
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
static void ifopts_write_new_buffersize(void);
#endif
static void ifopts_write_new_snaplen(void);
static void ifopts_write_new_descr(void);
static void ifopts_write_new_hide(void);
static void ifopts_write_new_pmode(void);
static void prom_mode_cb(GtkToggleButton *tbt, gpointer udata);

/* Columns options dialog */
#ifdef HAVE_PCAP_CREATE
static GtkWidget *col_monitor_cb;
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
static GtkWidget *col_buf_cb;
#endif
static GtkWidget *col_snap_cb;
static GtkWidget *col_link_cb, *col_filter_cb, *col_pmode_cb;
static void colopts_edit_destroy_cb(GtkWidget *win, gpointer data);
static void colopts_edit_cb(GtkWidget *w, gpointer data);
static void colopts_edit_ok_cb(GtkWidget *w, gpointer parent_w);

GtkWidget*
capture_prefs_show(void)
{
	GtkWidget	*main_grid;
	GtkWidget	*if_cbxe, *if_lb, *promisc_cb, *pcap_ng_cb, *sync_cb, *auto_scroll_cb, *show_info_cb;
	GtkWidget	*ifopts_lb, *ifopts_bt, *colopts_lb, *colopts_bt;
	GList		*if_list, *combo_list;
	int		err;
	int		row = 0;
	const gchar     *tooltips_text;

	/* Main vertical box */
	capture_window = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 7, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(capture_window), 5);

	/* Main grid */
	main_grid = ws_gtk_grid_new();
	gtk_box_pack_start(GTK_BOX(capture_window), main_grid, FALSE, FALSE, 0);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_set_vexpand(GTK_WIDGET(main_grid), FALSE); /* Ignore VEXPAND requests from children */
#endif
	ws_gtk_grid_set_row_spacing(GTK_GRID(main_grid), 10);
	ws_gtk_grid_set_column_spacing(GTK_GRID(main_grid), 15);
	gtk_widget_show(main_grid);

	/* Default device */
	if_lb = gtk_label_new("Default interface:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_lb), 1.0f, 0.5f);
	gtk_widget_show(if_lb);

	if_cbxe = gtk_combo_box_text_new_with_entry();
	/*
	 * XXX - what if we can't get the list?
	 */
	if_list = capture_interface_list(&err, NULL, main_window_update);
	combo_list = build_capture_combo_list(if_list, FALSE);
	free_interface_list(if_list);
	if (combo_list != NULL) {
		GList *combo_entry;
		for (combo_entry = combo_list; combo_entry != NULL; combo_entry = g_list_next(combo_entry)) {
			gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(if_cbxe), (const gchar *)combo_entry->data);
		}
	}
	if (prefs.capture_device) {
		gtk_entry_set_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(if_cbxe))),
				   prefs.capture_device);
	}
	else if (combo_list != NULL) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(if_cbxe), 0);
	}
	free_capture_combo_list(combo_list);

	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_cbxe, 1, row, 1, 1);
	tooltips_text = "The default interface to be captured from.";
	gtk_widget_set_tooltip_text(if_lb, tooltips_text);
	gtk_widget_set_tooltip_text(gtk_bin_get_child(GTK_BIN(if_cbxe)), tooltips_text);
	gtk_widget_show(if_cbxe);
	g_object_set_data(G_OBJECT(capture_window), DEVICE_KEY, if_cbxe);
	row++;

	/* Interface properties */
	ifopts_lb = gtk_label_new("Interfaces:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), ifopts_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(ifopts_lb), 1.0f, 0.5f);
	gtk_widget_show(ifopts_lb);

	ifopts_bt = ws_gtk_button_new_from_stock(WIRESHARK_STOCK_EDIT);
	tooltips_text = "Open a dialog box to set various interface options.";
	gtk_widget_set_tooltip_text(ifopts_lb, tooltips_text);
	gtk_widget_set_tooltip_text(ifopts_bt, tooltips_text);
	g_signal_connect(ifopts_bt, "clicked", G_CALLBACK(ifopts_edit_cb), NULL);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), ifopts_bt, 1, row, 1, 1);
	row++;

	/* Promiscuous mode */
	promisc_cb = create_preference_check_button(main_grid, row++,
	    "Capture packets in promiscuous mode on all network cards:",
	    "To set this mode on a per interface basis, select the interface first."
	    "Usually a network card will only capture the traffic sent to its own network address. "
	    "If you want to capture all traffic that the network card can \"see\", mark this option. "
	    "See the FAQ for some more details of capturing packets from a switched network. ",
	    prefs.capture_prom_mode);
	g_signal_connect(promisc_cb, "toggled", G_CALLBACK(prom_mode_cb), NULL);
	g_object_set_data(G_OBJECT(capture_window), PROM_MODE_KEY, promisc_cb);

	/* Pcap-NG format */
	pcap_ng_cb = create_preference_check_button(main_grid, row++,
	    "Capture packets in pcap-ng format:",
	    "Capture packets in the next-generation capture file format.",
	    prefs.capture_pcap_ng);
	g_object_set_data(G_OBJECT(capture_window), PCAP_NG_KEY, pcap_ng_cb);

	/* Real-time capture */
	sync_cb = create_preference_check_button(main_grid, row++,
	    "Update list of packets in real time:",
	    "Update the list of packets while capture is in progress. "
	    "This can result in dropped packets on high-speed networks.",
	    prefs.capture_real_time);
	g_object_set_data(G_OBJECT(capture_window), CAPTURE_REAL_TIME_KEY, sync_cb);

	/* Auto-scroll real-time capture */
	auto_scroll_cb = create_preference_check_button(main_grid, row++,
	    "Automatic scrolling in live capture:",
	    "Keep the packet list scrolled to the bottom while capturing.",
	    prefs.capture_auto_scroll);
	g_object_set_data(G_OBJECT(capture_window), AUTO_SCROLL_KEY, auto_scroll_cb);

	/* Show capture info dialog */
	show_info_cb = create_preference_check_button(main_grid, row++,
	    "Hide capture info dialog:",
	    "Hide the capture info dialog while capturing. ",
	    !prefs.capture_show_info);
	g_object_set_data(G_OBJECT(capture_window), SHOW_INFO_KEY, show_info_cb);

	/* Column properties */
	colopts_lb = gtk_label_new("Columns:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), colopts_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(colopts_lb), 1.0f, 0.5f);
	gtk_widget_show(colopts_lb);

	colopts_bt = ws_gtk_button_new_from_stock(WIRESHARK_STOCK_EDIT);
	tooltips_text = "Open a dialog box to change the visible columns.";
	gtk_widget_set_tooltip_text(colopts_lb, tooltips_text);
	gtk_widget_set_tooltip_text(colopts_bt, tooltips_text);
	g_signal_connect(colopts_bt, "clicked", G_CALLBACK(colopts_edit_cb), NULL);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), colopts_bt, 1, row, 1, 1);
	row++;

	/* Show 'em what we got */
	gtk_widget_show_all(capture_window);

	return(capture_window);
}

void
capture_prefs_fetch(GtkWidget *w)
{
	GtkWidget *if_cbxe, *promisc_cb, *pcap_ng_cb, *sync_cb, *auto_scroll_cb, *show_info_cb;
	gchar	*if_text;

	if_cbxe    = (GtkWidget *)g_object_get_data(G_OBJECT(w), DEVICE_KEY);
	promisc_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), PROM_MODE_KEY);
	pcap_ng_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), PCAP_NG_KEY);
	sync_cb    = (GtkWidget *)g_object_get_data(G_OBJECT(w), CAPTURE_REAL_TIME_KEY);
	auto_scroll_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), AUTO_SCROLL_KEY);
	show_info_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), SHOW_INFO_KEY);

	if (prefs.capture_device != NULL) {
		g_free(prefs.capture_device);
		prefs.capture_device = NULL;
	}
	if_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(if_cbxe)))));
	/* Strip out white space */
	g_strstrip(if_text);
	/* If there was nothing but white space, treat that as an
	   indication that the user doesn't want to wire in a default
	   device, and just wants the first device in the list chosen. */
	if (*if_text == '\0') {
		g_free(if_text);
		if_text = NULL;
	}

	/* Ensure capture device is not NULL */
	if (if_text == NULL)
		if_text = g_strdup("");
	prefs.capture_device = if_text;

	prefs.capture_prom_mode = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(promisc_cb));

	prefs.capture_pcap_ng = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pcap_ng_cb));

	prefs.capture_real_time = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb));

	prefs.capture_auto_scroll = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auto_scroll_cb));

	prefs.capture_show_info = !(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(show_info_cb)));
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
	dlg = (GtkWidget *)g_object_get_data(G_OBJECT(caller), IFOPTS_DIALOG_PTR_KEY);

	if (dlg != NULL) {
		/* Yes.  Destroy it. */
		window_destroy(dlg);
	}

	/* Is there an column descriptions dialog associated with this
	   Preferences dialog? */
	dlg = (GtkWidget *)g_object_get_data(G_OBJECT(caller), COLOPTS_DIALOG_PTR_KEY);

	if (dlg != NULL) {
		/* Yes.  Destroy it. */
		window_destroy(dlg);
	}
}

/*
 * Create an edit interface options dialog.
 */
enum
{
	DEVICE_COLUMN,
	DESC_COLUMN,
#ifdef HAVE_PCAP_CREATE
	DEF_MONITOR_MODE_COLUMN,
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	BUF_COLUMN,
#endif
	HASSNAP_COLUMN,
	SNAPLEN_COLUMN,
	PMODE_COLUMN,
	DEF_LINK_LAYER_COLUMN,
	COMMENT_COLUMN,
	HIDE_COLUMN,
	DLT_COLUMN,
	N_COLUMN /* The number of columns */
};


static void
colopts_edit_cb(GtkWidget *w, gpointer data _U_)
{
	GtkWidget	*colopts_edit_dlg, *main_hb, *main_grid,
						*ed_opts_fr, *main_vb,
						*bbox, *ok_bt, *cancel_bt, *help_bt, *column_lb,
						*col_link_lb,
#ifdef HAVE_PCAP_CREATE
						*col_monitor_lb,
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
						*col_buf_lb,
#endif
						*col_filter_lb, *col_pmode_lb,
			  *col_snap_lb;

	int row = 0;

	GtkWidget   *caller   = gtk_widget_get_toplevel(w);

	/* Has an edit dialog box already been opened for that top-level
	   widget? */
	colopts_edit_dlg = (GtkWidget *)g_object_get_data(G_OBJECT(caller), COLOPTS_DIALOG_PTR_KEY);
	if (colopts_edit_dlg != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(colopts_edit_dlg);
		return;
	}

	/* create a new dialog */
	colopts_edit_dlg = dlg_conf_window_new("Wireshark: Preferences: Capture Options Columns");
	gtk_window_set_default_size(GTK_WINDOW(colopts_edit_dlg), 300, 200);

	main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
	gtk_container_add(GTK_CONTAINER(colopts_edit_dlg), main_vb);
	gtk_widget_show(main_vb);

	/* create edit options frame */
	ed_opts_fr = gtk_frame_new("Columns");
	gtk_box_pack_start(GTK_BOX(main_vb), ed_opts_fr, FALSE, FALSE, 0);
	gtk_widget_show(ed_opts_fr);

	main_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5, TRUE);
	gtk_container_set_border_width(GTK_CONTAINER(main_hb), 3);
	gtk_container_add(GTK_CONTAINER(ed_opts_fr), main_hb);
	gtk_widget_show(main_hb);

	/* grid to hold description text entry and hide button */
	main_grid = ws_gtk_grid_new();
	gtk_box_pack_start(GTK_BOX(main_hb), main_grid, TRUE, FALSE, 10);
	ws_gtk_grid_set_row_spacing(GTK_GRID(main_grid), 10);
	ws_gtk_grid_set_column_spacing(GTK_GRID(main_grid), 10);
	gtk_widget_show(main_grid);

	column_lb = gtk_label_new("Select the columns to be displayed");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), column_lb, 0, row, 2, 1);
	gtk_misc_set_alignment(GTK_MISC(column_lb), 0, 0.5f);
	gtk_widget_show(column_lb);
	row++;

	/* create "Link Layer" label and button */
	col_link_cb = gtk_check_button_new();
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_link_cb, 0, row, 1, 1);
	if (!prefs.capture_columns || prefs_capture_options_dialog_column_is_visible("LINK"))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_link_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_link_cb), FALSE);
	gtk_widget_show(col_link_cb);

	col_link_lb = gtk_label_new("Link layer header");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_link_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(col_link_lb), 0, 0.5f);
	gtk_widget_show(col_link_lb);
	row++;

	/* create "Promiscuous Mode" label and button */
	col_pmode_cb = gtk_check_button_new();
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_pmode_cb, 0, row, 1, 1);
	if (!prefs.capture_columns || prefs_capture_options_dialog_column_is_visible("PMODE"))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_pmode_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_pmode_cb), FALSE);
	gtk_widget_show(col_pmode_cb);

	col_pmode_lb = gtk_label_new("Promiscuous Mode");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_pmode_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(col_pmode_lb), 0, 0.5f);
	gtk_widget_show(col_pmode_lb);
	row++;

	/* create "Snap length in Bytes" label and button */
	col_snap_cb = gtk_check_button_new();
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_snap_cb, 0, row, 1, 1);
	if (!prefs.capture_columns || prefs_capture_options_dialog_column_is_visible("SNAPLEN"))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_snap_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_snap_cb), FALSE);
	gtk_widget_show(col_snap_cb);

	col_snap_lb = gtk_label_new("Snap length in Bytes");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_snap_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(col_snap_lb), 0, 0.5f);
	gtk_widget_show(col_snap_lb);
	row++;

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	/* create "Buffer in Megabytes" label and button */
	col_buf_cb = gtk_check_button_new();
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_buf_cb, 0, row, 1, 1);
	if (!prefs.capture_columns || prefs_capture_options_dialog_column_is_visible("BUFFER"))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_buf_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_buf_cb), FALSE);
	gtk_widget_show(col_buf_cb);

	col_buf_lb = gtk_label_new("Buffer in Megabytes");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_buf_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(col_buf_lb), 0, 0.5f);
	gtk_widget_show(col_buf_lb);
	row++;
#endif

#ifdef HAVE_PCAP_CREATE
	/* create "monitor mode" label and button */
	col_monitor_lb = gtk_label_new("Monitor mode");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_monitor_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(col_monitor_lb), 0, 0.5f);
	gtk_widget_show(col_monitor_lb);

	col_monitor_cb = gtk_check_button_new();
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_monitor_cb, 0, row, 1, 1);
	if (!prefs.capture_columns || prefs_capture_options_dialog_column_is_visible("MONITOR"))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_monitor_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_monitor_cb), FALSE);
	gtk_widget_show(col_monitor_cb);

	row++;
#endif

	/* create "Capture Filter" label and button */
	col_filter_lb = gtk_label_new("Capture filter");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_filter_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(col_filter_lb), 0, 0.5f);
	gtk_widget_show(col_filter_lb);

	col_filter_cb = gtk_check_button_new();
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), col_filter_cb, 0, row, 1, 1);
	if (!prefs.capture_columns || prefs_capture_options_dialog_column_is_visible("FILTER"))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_filter_cb), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(col_filter_cb), FALSE);
	gtk_widget_show(col_filter_cb);

	row++;

	/* button row: OK and Cancel buttons */
	bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	ok_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
	gtk_widget_set_tooltip_text(ok_bt, "Save changes and exit dialog");
	g_signal_connect(ok_bt, "clicked", G_CALLBACK(colopts_edit_ok_cb), colopts_edit_dlg);

	cancel_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	gtk_widget_set_tooltip_text(cancel_bt, "Cancel and exit dialog");
	window_set_cancel_button(colopts_edit_dlg, cancel_bt, window_cancel_button_cb);

	help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
	g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb),
	                 (gpointer)HELP_CAPTURE_INTERFACE_OPTIONS_DIALOG);
	gtk_widget_set_tooltip_text (help_bt, "Show topic specific help");

	gtk_widget_grab_default(ok_bt);

	g_signal_connect(colopts_edit_dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	/* Call a handler when we're destroyed, so we can inform
		 our caller, if any, that we've been destroyed. */
	g_signal_connect(colopts_edit_dlg, "destroy", G_CALLBACK(colopts_edit_destroy_cb), NULL);

	/* Set the key for the new dialog to point to our caller. */
	g_object_set_data(G_OBJECT(colopts_edit_dlg), COLOPTS_CALLER_PTR_KEY, caller);
	/* Set the key for the caller to point to us */
	g_object_set_data(G_OBJECT(caller), COLOPTS_DIALOG_PTR_KEY, colopts_edit_dlg);

	gtk_widget_show(colopts_edit_dlg); /* triggers ifopts_edit_ifsel_cb() with the */
	                                   /* "interfaces" TreeView first row selected */
	window_present(colopts_edit_dlg);
}


static void
ifopts_edit_cb(GtkWidget *w, gpointer data _U_)
{
	GtkWidget	  *ifopts_edit_dlg, *cur_scr_win, *main_hb, *main_grid,
			  *cur_opts_fr, *ed_opts_fr, *main_vb,
			  *if_descr_lb,
			  *if_hide_lb,
			  *bbox, *ok_bt, *cancel_bt, *help_bt;

	GtkListStore      *list_store;
	GtkWidget         *list;
	GtkTreeViewColumn *column;
	GtkCellRenderer   *renderer;
	GtkTreeView       *list_view;
	GtkTreeSelection  *selection;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	GtkAdjustment     *buffer_size_adj;
#endif
	GtkAdjustment     *snaplen_adj;
	int row = 0;

	GtkWidget   *caller   = gtk_widget_get_toplevel(w);

	/* Has an edit dialog box already been opened for that top-level
	   widget? */
	ifopts_edit_dlg = (GtkWidget *)g_object_get_data(G_OBJECT(caller), IFOPTS_DIALOG_PTR_KEY);
	if (ifopts_edit_dlg != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(ifopts_edit_dlg);
		return;
	}

	/* create a new dialog */
	ifopts_edit_dlg = dlg_conf_window_new("Wireshark: Preferences: Interface Options");
	gtk_window_set_default_size(GTK_WINDOW(ifopts_edit_dlg), 1000, 500);

	main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
	gtk_container_add(GTK_CONTAINER(ifopts_edit_dlg), main_vb);
	gtk_widget_show(main_vb);

	/* create current options frame */
	cur_opts_fr = gtk_frame_new("Interfaces");
	gtk_box_pack_start(GTK_BOX(main_vb), cur_opts_fr, TRUE, TRUE, 0);
	gtk_widget_show(cur_opts_fr);

	/* create a scrolled window to pack the current options TreeView widget into */
	cur_scr_win = scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(cur_scr_win), 3);
	gtk_container_add(GTK_CONTAINER(cur_opts_fr), cur_scr_win);
	gtk_widget_show(cur_scr_win);

	/*
	 * Create current options TreeView.
	 */
	list_store = gtk_list_store_new(N_COLUMN,	/* Total number of columns XXX	*/
					G_TYPE_STRING,	/* Device			*/
					G_TYPE_STRING,	/* Description			*/
#ifdef HAVE_PCAP_CREATE
					G_TYPE_BOOLEAN,	/* Monitor mode		*/
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
					G_TYPE_INT,			/* Buffer size				*/
#endif
					G_TYPE_BOOLEAN,	/* Has snap length		*/
					G_TYPE_INT,			/* Snap length				*/
					G_TYPE_BOOLEAN,	/* Promiscuous mode		*/
					G_TYPE_STRING,	/* Default link-layer		*/
					G_TYPE_STRING,	/* Comment			*/
					G_TYPE_BOOLEAN,	/* Hide?			*/
					G_TYPE_INT);	/* Dlt 				*/

	list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

	list_view = GTK_TREE_VIEW(list);

	/* The view now holds a reference.  We can get rid of our own reference */
	g_object_unref (G_OBJECT (list_store));

	/*
	 * Create the first column packet, associating the "text" attribute of the
	 * cell_renderer to the first column of the model
	 */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Device", renderer,
							   "text", DEVICE_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
#ifdef _WIN32
	gtk_tree_view_column_set_min_width(column, 230);
#else
	gtk_tree_view_column_set_min_width(column, 70);
#endif
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Description", renderer,
							   "text", DESC_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 260);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

#ifdef HAVE_PCAP_CREATE
	/*
	 * XXX - for some reason, this doesn't show up.
	 */
	renderer = gtk_cell_renderer_toggle_new ();
	column = gtk_tree_view_column_new_with_attributes ("Default to monitor mode", renderer,
							   "active", DEF_MONITOR_MODE_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);
#endif

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	renderer = gtk_cell_renderer_spin_new ();
	buffer_size_adj = (GtkAdjustment *) gtk_adjustment_new(DEFAULT_CAPTURE_BUFFER_SIZE, 1, 65535, 1.0, 10.0, 0.0);
	g_object_set(G_OBJECT(renderer), "adjustment", buffer_size_adj, NULL);
	column = gtk_tree_view_column_new_with_attributes ("Default buffer size (MiB)", renderer,
							   "text", BUF_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);
#endif
	renderer = gtk_cell_renderer_toggle_new ();
	column = gtk_tree_view_column_new_with_attributes ("Has snap length mode", renderer,
							   "active", HASSNAP_COLUMN,
							   NULL);
	gtk_tree_view_column_set_resizable(column, FALSE);
	/*gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);*/
	renderer = gtk_cell_renderer_spin_new ();
	snaplen_adj = (GtkAdjustment *) gtk_adjustment_new(WTAP_MAX_PACKET_SIZE, 1, WTAP_MAX_PACKET_SIZE, 1.0, 10.0, 0.0);
	g_object_set(G_OBJECT(renderer), "adjustment", snaplen_adj, NULL);
	column = gtk_tree_view_column_new_with_attributes ("Default snap length", renderer,
							   "text", SNAPLEN_COLUMN,
							   NULL);
	gtk_tree_view_column_set_resizable(column, FALSE);

	renderer = gtk_cell_renderer_toggle_new ();
	column = gtk_tree_view_column_new_with_attributes ("Default to promiscuous mode", renderer,
							   "active", PMODE_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Default link-layer", renderer,
							   "text", DEF_LINK_LAYER_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 230);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Comment", renderer,
							   "text", COMMENT_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 100);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

	renderer = gtk_cell_renderer_toggle_new ();
	column = gtk_tree_view_column_new_with_attributes ("Hide?", renderer,
							   "active", HIDE_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, FALSE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);

#if 0
	/* Don't show the DLT column */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("DLT", renderer,
							   "text", DLT_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 40);
	/* Add the column to the view. */
	gtk_tree_view_append_column (list_view, column);
#endif
	/* Setup the selection handler */
	selection = gtk_tree_view_get_selection(list_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

	cur_list = list;
	gtk_container_add(GTK_CONTAINER(cur_scr_win), cur_list);

	if_selection = selection;

	g_signal_connect (G_OBJECT (selection), "changed", /* select_row */
			  G_CALLBACK (ifopts_edit_ifsel_cb),
			  NULL);

	gtk_widget_show(cur_list);

	/* add interface names to cell */
	ifopts_if_liststore_add();

	/* create edit options frame */
	ed_opts_fr = gtk_frame_new("Properties");
	gtk_box_pack_start(GTK_BOX(main_vb), ed_opts_fr, FALSE, FALSE, 0);
	gtk_widget_show(ed_opts_fr);

	main_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5, TRUE);
	gtk_container_set_border_width(GTK_CONTAINER(main_hb), 3);
	gtk_container_add(GTK_CONTAINER(ed_opts_fr), main_hb);
	gtk_widget_show(main_hb);

	/* grid to hold description text entry and hide button */
	main_grid = ws_gtk_grid_new();
	gtk_box_pack_start(GTK_BOX(main_hb), main_grid, TRUE, FALSE, 10);
	ws_gtk_grid_set_row_spacing(GTK_GRID(main_grid), 10);
	ws_gtk_grid_set_column_spacing(GTK_GRID(main_grid), 10);
	gtk_widget_show(main_grid);

	if_dev_lb = gtk_label_new("Device:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_dev_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_dev_lb), 1.0f, 0.5f);
	gtk_widget_show(if_dev_lb);

	if_dev_lb = gtk_label_new("");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_dev_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_dev_lb), 0.0f, 0.5f);
	gtk_widget_show(if_dev_lb);
	row++;

	if_name_lb = gtk_label_new("Description:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_name_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_name_lb), 1.0f, 0.5f);
	gtk_widget_show(if_name_lb);

	if_name_lb = gtk_label_new("");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_name_lb, 1, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_name_lb), 0.0f, 0.5f);
	gtk_widget_show(if_name_lb);
	row++;

#ifdef HAVE_PCAP_CREATE
	/* create "monitor mode" label and button */
	if_monitor_lb = gtk_label_new("Monitor mode:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_monitor_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_monitor_lb), 1.0f, 0.5f);
	gtk_widget_show(if_monitor_lb);

	if_monitor_cb = gtk_check_button_new();
	g_signal_connect(if_monitor_cb, "toggled", G_CALLBACK(ifopts_edit_monitor_changed_cb),
			cur_list);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_monitor_cb, 1, row, 1, 1);
	gtk_widget_show(if_monitor_cb);
	row++;
#endif

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	if_buffersize_lb = gtk_label_new("Default buffer size (MiB):");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_buffersize_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_buffersize_lb), 1.0f, 0.5f);
	gtk_widget_show(if_buffersize_lb);
	buffer_size_adj = (GtkAdjustment *) gtk_adjustment_new(DEFAULT_CAPTURE_BUFFER_SIZE, 1, 65535, 1.0, 10.0, 0.0);
	if_buffersize_cb = gtk_spin_button_new (buffer_size_adj, 0, 0);
	g_signal_connect(if_buffersize_cb, "value-changed", G_CALLBACK(ifopts_edit_buffersize_changed_cb),
			cur_list);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_buffersize_cb, 1, row, 1, 1);
	gtk_widget_show(if_buffersize_cb);
	row++;
#endif

	if_snaplen_lb = gtk_label_new("Limit each packet to:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_snaplen_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_snaplen_lb), 1.0f, 0.5f);
	gtk_widget_show(if_snaplen_lb);
	if_snaplen_tg = gtk_check_button_new();
	g_signal_connect(if_snaplen_tg, "toggled", G_CALLBACK(ifopts_edit_hassnap_changed_cb),
			cur_list);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_snaplen_tg, 2, row, 1, 1);
	gtk_widget_show(if_snaplen_tg);
	snaplen_adj = (GtkAdjustment *) gtk_adjustment_new(65535, 1, 65535, 1.0, 10.0, 0.0);
	if_snaplen_cb = gtk_spin_button_new (snaplen_adj, 0, 0);
	g_signal_connect(if_snaplen_cb, "value-changed", G_CALLBACK(ifopts_edit_snaplen_changed_cb),
			cur_list);
	gtk_spin_button_set_numeric(GTK_SPIN_BUTTON (if_snaplen_cb), TRUE);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_snaplen_cb, 1, row, 1, 1);
	gtk_widget_show(if_snaplen_cb);
	row++;

	/* create "promiscuous mode" label and button */
	if_pmode_lb = gtk_label_new("Promiscuous mode:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_pmode_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_pmode_lb), 1.0f, 0.5f);
	gtk_widget_show(if_pmode_lb);

	if_pmode_cb = gtk_check_button_new();
	g_signal_connect(if_pmode_cb, "toggled", G_CALLBACK(ifopts_edit_pmode_changed_cb),
			cur_list);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_pmode_cb, 1, row, 1, 1);
	gtk_widget_show(if_pmode_cb);
	row++;

	if_linktype_lb = gtk_label_new("Default link-layer header type:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_linktype_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_linktype_lb), 1.0f, 0.5f);
	gtk_widget_show(if_linktype_lb);

	if_linktype_cb = gtk_combo_box_text_new();
	num_linktypes = 0;
	interfaces_info_nochange = FALSE;
	g_signal_connect(if_linktype_cb, "changed", G_CALLBACK(ifopts_edit_linktype_changed_cb),
			cur_list);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_linktype_cb, 1, row, 1, 1);
	gtk_widget_show(if_linktype_cb);
	row++;

	/* create interface description label and text entry */
	if_descr_lb = gtk_label_new("Comment:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_descr_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_descr_lb), 1.0f, 0.5f);
	gtk_widget_show(if_descr_lb);

	if_descr_te = gtk_entry_new();
	g_signal_connect(if_descr_te, "changed", G_CALLBACK(ifopts_edit_descr_changed_cb),
			cur_list);
	gtk_entry_set_max_length(GTK_ENTRY(if_descr_te), IFOPTS_MAX_DESCR_LEN);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_descr_te, 1, row, 1, 1);
	gtk_widget_show(if_descr_te);
	row++;

	/* create "hide interface" label and button */
	if_hide_lb = gtk_label_new("Hide interface?:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_hide_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(if_hide_lb), 1.0f, 0.5f);
	gtk_widget_show(if_hide_lb);

	if_hide_cb = gtk_check_button_new();
	g_signal_connect(if_hide_cb, "toggled", G_CALLBACK(ifopts_edit_hide_changed_cb),
			cur_list);
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_hide_cb, 1, row, 1, 1);
	gtk_widget_show(if_hide_cb);

	if_default_if_lb = gtk_label_new("(Default interface cannot be hidden)");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), if_default_if_lb, 1, row, 2, 1);
	gtk_misc_set_alignment(GTK_MISC(if_default_if_lb), 0.15f, 0.5f);
	row++;

	/* button row: OK and Cancel buttons */
	bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	ok_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
	gtk_widget_set_tooltip_text(ok_bt, "Save changes and exit dialog");
	g_signal_connect(ok_bt, "clicked", G_CALLBACK(ifopts_edit_ok_cb), ifopts_edit_dlg);

	cancel_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	gtk_widget_set_tooltip_text(cancel_bt, "Cancel and exit dialog");
	window_set_cancel_button(ifopts_edit_dlg, cancel_bt, window_cancel_button_cb);

	help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
	g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb),
			 (gpointer)HELP_CAPTURE_INTERFACE_OPTIONS_DIALOG);
	gtk_widget_set_tooltip_text (help_bt, "Show topic specific help");

	gtk_widget_grab_default(ok_bt);

	g_signal_connect(ifopts_edit_dlg, "delete_event", G_CALLBACK(window_delete_event_cb),
			 NULL);
	/* Call a handler when we're destroyed, so we can inform
	   our caller, if any, that we've been destroyed. */
	g_signal_connect(ifopts_edit_dlg, "destroy", G_CALLBACK(ifopts_edit_destroy_cb), NULL);

	/* Set the key for the new dialog to point to our caller. */
	g_object_set_data(G_OBJECT(ifopts_edit_dlg), IFOPTS_CALLER_PTR_KEY, caller);
	/* Set the key for the caller to point to us */
	g_object_set_data(G_OBJECT(caller), IFOPTS_DIALOG_PTR_KEY, ifopts_edit_dlg);

	gtk_widget_show(ifopts_edit_dlg); /* triggers ifopts_edit_ifsel_cb() with the  */
					  /*  "interfaces" TreeView first row selected */
	window_present(ifopts_edit_dlg);
}

/*
 * User selected "OK". Create/write preferences strings.
 */
static void
colopts_edit_ok_cb(GtkWidget *w _U_, gpointer parent_w)
{
	g_list_free(prefs.capture_columns);
	prefs.capture_columns = NULL;
	prefs.capture_columns = g_list_append(prefs.capture_columns, g_strdup("INTERFACE"));
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(col_link_cb))) {
		prefs.capture_columns = g_list_append(prefs.capture_columns, g_strdup("LINK"));
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(col_pmode_cb))) {
		prefs.capture_columns = g_list_append(prefs.capture_columns, g_strdup("PMODE"));
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(col_snap_cb))) {
		prefs.capture_columns = g_list_append(prefs.capture_columns, g_strdup("SNAPLEN"));
	}
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(col_buf_cb))) {
		prefs.capture_columns = g_list_append(prefs.capture_columns, g_strdup("BUFFER"));
	}
#endif
#if defined (HAVE_PCAP_CREATE)
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(col_monitor_cb))) {
		prefs.capture_columns = g_list_append(prefs.capture_columns, g_strdup("MONITOR"));
	}
#endif
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(col_filter_cb))) {
		prefs.capture_columns = g_list_append(prefs.capture_columns, g_strdup("FILTER"));
	}
	/* Now nuke this window. */
	gtk_grab_remove(GTK_WIDGET(parent_w));
	window_destroy(GTK_WIDGET(parent_w));
	if (capture_dlg_window_present()) {
		update_visible_tree_view_columns();
		update_visible_columns_menu ();
	}
}

/*
 * User selected "OK". Create/write preferences strings.
 */
static void
ifopts_edit_ok_cb(GtkWidget *w _U_, gpointer parent_w)
{
	if (if_selection){ /* XXX: Cannot be NULL ?? */
#ifdef HAVE_PCAP_CREATE
		/* create/write new monitor-mode interfaces string */
		ifopts_write_new_monitor_mode();
#endif

		/* create/write new interfaces link-layer string */
		ifopts_write_new_linklayer();

		/* create/write new interfaces description string */
		ifopts_write_new_descr();

		/* create/write new "hidden" interfaces string */
		ifopts_write_new_hide();

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
		/* create/write new "buffersize" interfaces string */
		ifopts_write_new_buffersize();
#endif

		/* create/write new "snaplen" interfaces string */
		ifopts_write_new_snaplen();
		/* create/write new promiscuous mode interfaces string */
		ifopts_write_new_pmode();
	}

	/* Update everything that shows an interface list that includes
	   local interfaces, as we may have changed something that
	   affects how those lists are displayed. */
	refresh_local_interface_lists();

	/* Now nuke this window. */
	gtk_grab_remove(GTK_WIDGET(parent_w));
	window_destroy(GTK_WIDGET(parent_w));
}

static void
colopts_edit_destroy_cb(GtkWidget *win, gpointer data _U_)
{
	GtkWidget *caller;

	/* Get the widget that requested that we be popped up, if any.
	   (It should arrange to destroy us if it's destroyed, so
	   that we don't get a pointer to a non-existent window here.) */
	caller = (GtkWidget *)g_object_get_data(G_OBJECT(win), COLOPTS_CALLER_PTR_KEY);

	if (caller != NULL) {
		/* Tell it we no longer exist. */
		g_object_set_data(G_OBJECT(caller), COLOPTS_DIALOG_PTR_KEY, NULL);
	}
}

static void
ifopts_edit_destroy_cb(GtkWidget *win, gpointer data _U_)
{
	GtkWidget *caller;

	/* Get the widget that requested that we be popped up, if any.
	   (It should arrange to destroy us if it's destroyed, so
	   that we don't get a pointer to a non-existent window here.) */
	caller = (GtkWidget *)g_object_get_data(G_OBJECT(win), IFOPTS_CALLER_PTR_KEY);

	if (caller != NULL) {
		/* Tell it we no longer exist. */
		g_object_set_data(G_OBJECT(caller), IFOPTS_DIALOG_PTR_KEY, NULL);
	}
}

static gint
ifopts_description_to_val (const char *if_name, gboolean monitor_mode, const char *descr)
{
	if_capabilities_t *caps;
	int dlt = -1;

	caps = capture_get_if_capabilities(if_name, monitor_mode, NULL, NULL, main_window_update);
	if (caps != NULL) {
		if (caps->data_link_types != NULL) {
			GList  *lt_entry;
			/* XXX: Code skips first entry because that's the default ??? */
			for (lt_entry = g_list_next(caps->data_link_types);
			    lt_entry != NULL;
			    lt_entry = g_list_next(lt_entry)) {
				data_link_info_t *dli_p = (data_link_info_t *)lt_entry->data;
				if (dli_p->description) {
					if (strcmp(dli_p->description, descr) == 0) {
						dlt = dli_p->dlt;
						break;
					}
				} else {
					if (strcmp(dli_p->name, descr) == 0) {
						dlt = dli_p->dlt;
						break;
					}
				}
			}
		}
		free_if_capabilities(caps);
	}
	return dlt;
}

/*
 * Interface selected callback; update displayed widgets.
 */
static void
ifopts_edit_ifsel_cb(GtkTreeSelection	*selection _U_,
		     gpointer		 data _U_)
{
	GtkTreeIter         iter;
	GtkTreeModel       *model;
	gchar              *desc, *comment, *text;
	gchar              *if_name, *linktype;
#ifdef HAVE_PCAP_CREATE
	gboolean            monitor_mode;
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	gint                buffersize;
#endif
	gint                snaplen;
	gboolean            hide, hide_enabled = TRUE, hassnap = FALSE, pmode;
	gboolean            pmode_pref;
	if_capabilities_t  *caps;
	gint                selected = 0;

	/* Get list_store data for currently selected interface */
	if (!gtk_tree_selection_get_selected (if_selection, &model, &iter)){
		return;
	}
	gtk_tree_model_get(model, &iter,
			   DEVICE_COLUMN,             &if_name,
			   DESC_COLUMN,               &desc,
#ifdef HAVE_PCAP_CREATE
			   DEF_MONITOR_MODE_COLUMN,   &monitor_mode,
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
			   BUF_COLUMN,                &buffersize,
#endif
			   HASSNAP_COLUMN,            &hassnap,
			   SNAPLEN_COLUMN,            &snaplen,
			   PMODE_COLUMN,              &pmode,
			   DEF_LINK_LAYER_COLUMN,     &linktype,
			   COMMENT_COLUMN,            &comment,
			   HIDE_COLUMN,               &hide,
			   -1);

	/* display  the interface device from current interfaces selection */
	gtk_label_set_text(GTK_LABEL(if_dev_lb), if_name);

	/* display the interface name from current interfaces selection */
	gtk_label_set_text(GTK_LABEL(if_name_lb), desc);

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	/* display the buffer size from current interfaces selection */
	gtk_spin_button_set_value(GTK_SPIN_BUTTON (if_buffersize_cb), buffersize);
#endif

	/* display the snap length from current interfaces selection */
	gtk_spin_button_set_value(GTK_SPIN_BUTTON (if_snaplen_cb), snaplen);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_snaplen_tg), hassnap);
	gtk_widget_set_sensitive(GTK_WIDGET(if_snaplen_cb), hassnap);

	if (prefs.capture_prom_mode) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_pmode_cb), TRUE);
	} else if (capture_dev_user_pmode_find(if_name, &pmode_pref)) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_pmode_cb), pmode_pref);
	} else {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_pmode_cb), FALSE);
	}

	/* Ignore "changed" callbacks while we update the Properties widgets */
	interfaces_info_nochange = TRUE;

	/* display the link-layer header type from current interfaces selection */
	/*  -- remove old linktype list (if any) from the ComboBox */
	while (num_linktypes > 0) {
		num_linktypes--;
		gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(if_linktype_cb), num_linktypes);
	}

	/*
	 * -- set the state and sensitivity of the monitor-mode checkbox,
	 * and build and add to the ComboBox a linktype list, corresponding
	 * to the interface capabilities of the selected interface
	 */
#ifdef HAVE_PCAP_CREATE
	caps = capture_get_if_capabilities(if_name, monitor_mode, NULL, NULL, main_window_update);
#else
	caps = capture_get_if_capabilities(if_name, FALSE, NULL, NULL, main_window_update);
#endif
	if (caps != NULL) {
#ifdef HAVE_PCAP_CREATE
		gtk_widget_set_sensitive(if_monitor_lb, caps->can_set_rfmon);
		gtk_widget_set_sensitive(if_monitor_cb, caps->can_set_rfmon);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_monitor_cb), monitor_mode);
#endif
		if (caps->data_link_types != NULL) {
			GList *lt_entry;
			for (lt_entry = caps->data_link_types; lt_entry != NULL;
			    lt_entry = g_list_next(lt_entry)) {
				data_link_info_t *dli_p = (data_link_info_t *)lt_entry->data;
				text = (dli_p->description != NULL) ? dli_p->description : dli_p->name;
				if (strcmp(linktype, text) == 0) {
					selected = num_linktypes;
				}
				 gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(if_linktype_cb), text);
				num_linktypes++;
			}
			gtk_widget_set_sensitive(if_linktype_lb, num_linktypes >= 2);
			gtk_widget_set_sensitive(if_linktype_cb, num_linktypes >= 2);
			gtk_combo_box_set_active(GTK_COMBO_BOX(if_linktype_cb), selected);
		}
		free_if_capabilities(caps);
	}
#ifdef HAVE_PCAP_CREATE
	else {
		gtk_widget_set_sensitive(if_monitor_lb, FALSE);
		gtk_widget_set_sensitive(if_monitor_cb, FALSE);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_monitor_cb), FALSE);
	}
#endif

	/* display the interface description from current interfaces selection */
	gtk_entry_set_text(GTK_ENTRY(if_descr_te), comment);

	/* See if this is the currently selected capturing device */
	if ((prefs.capture_device != NULL) && (*prefs.capture_device != '\0')) {
		guint i;
		interface_t device;
		for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
			device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
			if ((strcmp(device.display_name, prefs.capture_device) == 0) &&
				(strcmp(device.name, if_name) == 0)) {
				/* Don't allow current interface to be hidden */
				hide_enabled = FALSE;
				break;
			}
		}
	}

	/* display the "hide interface" button state from current interfaces selection */
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(if_hide_cb), hide);
	gtk_widget_set_sensitive(if_hide_cb, hide_enabled);
	if (hide_enabled) {
		gtk_widget_hide(if_default_if_lb);
	} else {
		gtk_widget_show(if_default_if_lb);
	}

	interfaces_info_nochange = FALSE;

	g_free(if_name);
	g_free(desc);
	g_free(linktype);
	g_free(comment);
}

#ifdef HAVE_PCAP_CREATE
/*
 * Monitor-mode toggle button changed callback; update displayed widgets
 * (the list of link-layer types might change) and list_store for currently
 * selected interface.
 */
static void
ifopts_edit_monitor_changed_cb(GtkToggleButton *tbt, gpointer udata)
{
	GtkTreeModel      *list_model;
	GtkTreeIter        list_iter;
	GtkListStore      *list_store;
	gchar             *if_name, *text;
	gboolean           monitor_mode;
	if_capabilities_t *caps;

	if (interfaces_info_nochange)
		return;

	if (if_selection == NULL) /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}
	gtk_tree_model_get(list_model, &list_iter,
			   DEVICE_COLUMN,  &if_name,
			   -1);

	/* Ignore "changed" callbacks while we update the Properties widgets */
	interfaces_info_nochange = TRUE;

	/* display the link-layer header type from current interfaces selection */
	/*  -- remove old linktype list (if any) from the ComboBox */
	while (num_linktypes > 0) {
		num_linktypes--;
		gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(if_linktype_cb), num_linktypes);
	}

	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata))); /* Get store */

#ifdef HAVE_PCAP_CREATE
	/* get "monitor mode" button state and set status in list_store for currently selected interface */
	monitor_mode = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tbt));
	gtk_list_store_set  (list_store, &list_iter,
			     DEF_MONITOR_MODE_COLUMN, monitor_mode,
			     -1);
	caps = capture_get_if_capabilities(if_name, monitor_mode, NULL, NULL, main_window_update);
#else
	/* no monitor-mode support */
	caps = capture_get_if_capabilities(if_name, FALSE, NULL, NULL);
#endif

	/*
	 * -- set the sensitivity of the monitor-mode checkbox, and
	 * build and add to the ComboBox a linktype list for the current
	 * interfaces selection, based on the interface capabilities
	 */
	if (caps != NULL) {
#ifdef HAVE_PCAP_CREATE
		gtk_widget_set_sensitive(if_monitor_lb, caps->can_set_rfmon);
		gtk_widget_set_sensitive(if_monitor_cb, caps->can_set_rfmon);
#endif
		if (caps->data_link_types != NULL) {
			GList *lt_entry;
			for (lt_entry = caps->data_link_types; lt_entry != NULL;
			    lt_entry = g_list_next(lt_entry)) {
				data_link_info_t *dli_p = (data_link_info_t *)lt_entry->data;
				text = (dli_p->description != NULL) ? dli_p->description : dli_p->name;
				 gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(if_linktype_cb), text);
				num_linktypes++;
			}
			gtk_widget_set_sensitive(if_linktype_lb, num_linktypes >= 2);
			gtk_widget_set_sensitive(if_linktype_cb, num_linktypes >= 2);
			gtk_combo_box_set_active(GTK_COMBO_BOX(if_linktype_cb), 0);
		}
		free_if_capabilities(caps);
	}
#ifdef HAVE_PCAP_CREATE
	else {
		gtk_widget_set_sensitive(if_monitor_lb, FALSE);
		gtk_widget_set_sensitive(if_monitor_cb, FALSE);
	}
#endif

	interfaces_info_nochange = FALSE;
	g_signal_emit_by_name(if_linktype_cb, "changed");

	g_free(if_name);
}
#endif

/*
 * Link-layer entry changed callback; update list_store for currently selected interface.
 */
static void
ifopts_edit_linktype_changed_cb(GtkComboBox *cb, gpointer udata)
{
	gchar        *ifnm, *text;
#ifdef HAVE_PCAP_CREATE
	gboolean      monitor_mode;
#endif
	gint          linktype;
	GtkTreeModel *list_model;
	GtkTreeIter   list_iter;
	GtkListStore *list_store;

	if (interfaces_info_nochange)
		return;

	if (if_selection == NULL)  /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}

	gtk_tree_model_get(list_model, &list_iter,
		DEVICE_COLUMN,           &ifnm,
#ifdef HAVE_PCAP_CREATE
		DEF_MONITOR_MODE_COLUMN, &monitor_mode,
#endif
		-1);

	/* get current description text and set value in list_store for currently selected interface */
	text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(cb));
	if (text) {
#ifdef HAVE_PCAP_CREATE
		linktype = ifopts_description_to_val(ifnm, monitor_mode, text);
#else
		linktype = ifopts_description_to_val(ifnm, FALSE, text);
#endif
		list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata))); /* Get store */
		gtk_list_store_set  (list_store, &list_iter,
				     DEF_LINK_LAYER_COLUMN, text,
				     DLT_COLUMN, linktype,
				     -1);
		g_free(text);
	}
}

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
/*
 * Buffer size entry changed callback; update list_store for currently selected interface.
 */
static void
ifopts_edit_buffersize_changed_cb(GtkSpinButton *sb, gpointer udata)
{
	gint          buffersize;
	GtkTreeModel *list_model;
	GtkTreeIter   list_iter;
	GtkListStore *list_store;

	if (if_selection == NULL)  /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}


	/* get current description text and set value in list_store for currently selected interface */
	buffersize = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(sb));
	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata))); /* Get store */
	gtk_list_store_set  (list_store, &list_iter,
				     BUF_COLUMN, buffersize,
				     -1);
}
#endif

/*
 * Snap length entry changed callback; update list_store for currently selected interface.
 */
static void
ifopts_edit_snaplen_changed_cb(GtkSpinButton *sb _U_, gpointer udata _U_)
{
	gint          snaplen;
	gboolean      hassnap;
	GtkTreeModel *list_model;
	GtkTreeIter   list_iter;
	GtkListStore *list_store;

	if (if_selection == NULL)  /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}


	/* get current description text and set value in list_store for currently selected interface */
	snaplen = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(sb));
	if (snaplen != WTAP_MAX_PACKET_SIZE) {
		hassnap = TRUE;
	} else {
		hassnap = FALSE;
	}
	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata)));
	gtk_list_store_set  (list_store, &list_iter,
				     SNAPLEN_COLUMN, snaplen,
				     HASSNAP_COLUMN, hassnap,
				     -1);
}

/*
 * Checkbutton for the Snap length changed callback; update list_store for currently selected interface.
 */
static void
ifopts_edit_hassnap_changed_cb(GtkToggleButton *tbt, gpointer udata)
{
	gboolean      hassnap;
	GtkTreeModel *list_model;
	GtkTreeIter   list_iter;
	GtkListStore *list_store;

	if (if_selection == NULL)  /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}
	hassnap = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tbt));

	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata)));
	gtk_list_store_set  (list_store, &list_iter,
				     HASSNAP_COLUMN, hassnap,
				     -1);
	gtk_widget_set_sensitive(GTK_WIDGET(if_snaplen_cb), hassnap);
}

/*
 * Checkbutton for the promiscuous mode changed callback; update list_store for currently selected interface.
 */
static void
ifopts_edit_pmode_changed_cb(GtkToggleButton *tbt, gpointer udata)
{
	gboolean      pmode;
	GtkTreeModel *list_model;
	GtkTreeIter   list_iter;
	GtkListStore *list_store;

	if (if_selection == NULL)  /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}
	pmode = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tbt));

	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata)));
	gtk_list_store_set  (list_store, &list_iter,
				     PMODE_COLUMN, pmode,
				     -1);
}


/*
 * Comment text entry changed callback; update list_store for currently selected interface.
 */
static void
ifopts_edit_descr_changed_cb(GtkEditable *ed, gpointer udata)
{
	gchar        *text;
	GtkTreeModel *list_model;
	GtkTreeIter   list_iter;
	GtkListStore *list_store;

	if (interfaces_info_nochange)
		return;

	if (if_selection == NULL) /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}

	/* get current description text and set value in list_store for currently selected interface */
	text = gtk_editable_get_chars(GTK_EDITABLE(ed), 0, -1);
	/* replace any reserved formatting characters "()," with spaces */
	g_strdelimit(text, "(),", ' ');

	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata))); /* Get store */
	gtk_list_store_set  (list_store, &list_iter,
			     COMMENT_COLUMN, text,
			     -1);

	g_free(text);
}

/*
 * Hide toggle button changed callback; update list_store for currently selected interface .
 */
static void
ifopts_edit_hide_changed_cb(GtkToggleButton *tbt, gpointer udata)
{
	GtkTreeModel *list_model;
	GtkTreeIter   list_iter;
	GtkListStore *list_store;

	if (interfaces_info_nochange)
		return;

	if (if_selection == NULL) /* XXX: Cannot be NULL ?? */
		return;

	if (!gtk_tree_selection_get_selected (if_selection, &list_model, &list_iter)){
		return;
	}

	list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (udata))); /* Get store */
	/* get "hide" button state and set status in list_store for currently selected interface */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tbt)) == TRUE)
		gtk_list_store_set  (list_store, &list_iter,
				     HIDE_COLUMN, TRUE,
				     -1);
	else
		gtk_list_store_set  (list_store, &list_iter,
				     HIDE_COLUMN, FALSE,
				     -1);
}

/*
 * Add any saved interface options that apply to interfaces ListStore.
 *
 * NOTE:
 *		Interfaces that have been removed from the machine or disabled and
 *		no longer apply are ignored. Therefore, if the user subsequently
 *		selects "OK", the options for these interfaces are lost (they're
 *		lost permanently if "Save" is selected).
 */
static void
ifopts_options_add(GtkListStore *list_store, if_info_t *if_info)
{
	gchar	*p;
	gchar	*ifnm;
	gchar	*desc;
	gchar	*pr_descr;
	gchar	*text[] = { NULL, NULL, NULL, NULL };
	if_capabilities_t *caps;
#ifdef HAVE_PCAP_CREATE
	gboolean monitor_mode;
#endif
	gint     linktype;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	gint buffersize;
#endif
	gint snaplen;
	gboolean hide, hassnap = TRUE, pmode;
	GtkTreeIter  iter;

	/* set device name text */
	text[0] = g_strdup(if_info->name);

	/* set vendor description */
	if (if_info->vendor_description != NULL)
		text[1] = g_strdup(if_info->vendor_description);
	else
		text[1] = g_strdup("");

#ifdef HAVE_PCAP_CREATE
	/* get default monitor mode setting */
	monitor_mode = prefs_capture_device_monitor_mode(if_info->name);
	caps = capture_get_if_capabilities(if_info->name, monitor_mode, NULL, NULL, main_window_update);
#else
	/* no monitor-mode support */
	caps = capture_get_if_capabilities(if_info->name, FALSE, NULL, NULL, main_window_update);
#endif

	/* set default link-layer header type */
	linktype = capture_dev_user_linktype_find(if_info->name);
	if (caps != NULL) {
		if (caps->data_link_types != NULL) {
			GList  *lt_entry;
			for (lt_entry = caps->data_link_types; lt_entry != NULL;
			    lt_entry = g_list_next(lt_entry)) {
				data_link_info_t *dli_p = (data_link_info_t *)lt_entry->data;
				/* If we have no previous link-layer header type we use the first one */
				if (linktype == -1 || linktype == dli_p->dlt) {
					if (dli_p->description) {
						text[2] = g_strdup(dli_p->description);
					} else {
						text[2] = g_strdup(dli_p->name);
					}
					break;
				}
			}
		}
		free_if_capabilities(caps);
	}

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
	buffersize = capture_dev_user_buffersize_find(if_info->name);
	if (buffersize == -1) {
		buffersize = DEFAULT_CAPTURE_BUFFER_SIZE;
	}
#endif

        if (!capture_dev_user_snaplen_find(if_info->name, &hassnap, &snaplen)) {
		snaplen = WTAP_MAX_PACKET_SIZE;
		hassnap = FALSE;
	}

	if (prefs.capture_prom_mode) {
		pmode = TRUE;
	} else {
		if (!capture_dev_user_pmode_find(if_info->name, &pmode)) {
			pmode = FALSE;
		}
	}

	/* if we have no link-layer */
	if (text[2] == NULL)
		text[2] = g_strdup("");

	/* add interface descriptions */
	if ((prefs.capture_devices_descr != NULL) &&
	    (*prefs.capture_devices_descr != '\0')) {
		/* create working copy of device descriptions */
		pr_descr = g_strdup(prefs.capture_devices_descr);

		/* if we find a description for this interface */
		if ((ifnm = strstr(pr_descr, if_info->name)) != NULL) {
			p = ifnm;
			while (*p != '\0') {
				/* found left parenthesis, start of description */
				if (*p == '(') {
					p++;
					/* if syntax error */
					if ((*p == '\0') || (*p == ',') || (*p == '(') || (*p == ')'))
						break;

					/* save pointer to beginning of description */
					desc = p;
					p++;
					/* skip to end of description */
					while (*p != '\0') {
						/* if syntax error */
						if ((*p == ',') || (*p == '('))
							break;

						/* end of description */
						else if (*p == ')') {
							/* terminate and set description text */
							*p = '\0';
							text[3] = g_strdup(desc);
							break;
						}
						p++;
					}
					/* get out */
					break;
				} else
					p++;
			}
		}

		g_free(pr_descr);
	}

	/* if we have no description */
	if (text[3] == NULL)
		text[3] = g_strdup("");

	/* check if interface is "hidden" */
	hide = prefs_is_capture_device_hidden(if_info->name);

	/* add row to ListStore */

	gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
			     DEVICE_COLUMN,           text[0],
			     DESC_COLUMN,             text[1],
#ifdef HAVE_PCAP_CREATE
			     DEF_MONITOR_MODE_COLUMN, monitor_mode,
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
			     BUF_COLUMN,              buffersize,
#endif
			     HASSNAP_COLUMN,          hassnap,
			     SNAPLEN_COLUMN,          snaplen,
			     PMODE_COLUMN,            pmode,
			     DEF_LINK_LAYER_COLUMN,   text[2],
			     COMMENT_COLUMN,          text[3],
			     HIDE_COLUMN,             hide,
			     DLT_COLUMN,              linktype,
			     -1);

	ifopts_options_free(text);
}

static void
ifopts_options_free(gchar *text[])
{
	gint i;

	for (i=0; i < IFOPTS_LIST_TEXT_COLS; i++) {
		if (text[i] != NULL) {
			g_free(text[i]);
			text[i] = NULL;
		}
	}
}

/*
 * Add all interfaces to interfaces ListStore.
 */
static void
ifopts_if_liststore_add(void)
{
	GList	*if_list, *ifl_p;
	int	 err;
	gchar	*err_str;

	if_list = capture_interface_list(&err, &err_str, main_window_update);  /* if_list = ptr to first element of list (or NULL) */
	if (if_list == NULL) {
		if (err != 0) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
		}
		g_free(err_str);
		return;
	}

	/* We have an interface list.                            */
	/* add OS description + interface name text to ListStore */
	for (ifl_p = if_list; ifl_p != NULL; ifl_p = g_list_next(ifl_p)) {
		/* should never happen, but just in case */
		if ((ifl_p->data) == NULL)
			continue;
		/* fill current options ListStore with current preference values */
		ifopts_options_add(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (cur_list))),
				   (if_info_t *)ifl_p->data);
	}
	free_interface_list(if_list);
}

#ifdef HAVE_PCAP_CREATE
/*
 * Create/write new "monitor mode" interfaces string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_monitor_mode(void)
{
	GtkListStore 	*store;
	GtkTreeIter 	 iter;
	GtkTreeModel 	*model;
	gboolean	 more_items = TRUE;
	gint		 first_if = TRUE;	/* flag to check if first in list */
	gchar		*ifnm;
	gboolean	 monitor_mode;
	gchar		*new_monitor_mode;

	/* new preferences "monitor mode" interfaces string */
	new_monitor_mode = (gchar*)g_malloc0(MAX_VAL_LEN);

	/* get "monitor mode" flag text for each row (interface) */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(cur_list));
	store = GTK_LIST_STORE(model);
	if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {
		while (more_items) {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					   DEVICE_COLUMN,           &ifnm,
					   DEF_MONITOR_MODE_COLUMN, &monitor_mode,
					   -1);

			/* if flag text is "No", skip this interface */
			if (!monitor_mode){
				more_items = gtk_tree_model_iter_next (model,&iter);
				continue;
			}

			/*
			 * create/cat interface to new string
			 */
			if (first_if != TRUE)
				g_strlcat (new_monitor_mode, ",", MAX_VAL_LEN);
			g_strlcat (new_monitor_mode, ifnm, MAX_VAL_LEN);

			/* set first-in-list flag to false */
			first_if = FALSE;
			more_items = gtk_tree_model_iter_next (model,&iter);
		}

		/* write new "hidden" string to preferences */
		g_free(prefs.capture_devices_monitor_mode);
		prefs.capture_devices_monitor_mode = new_monitor_mode;
	}
}
#endif

/*
 * Create/write new interfaces link-layer string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_linklayer(void)
{
	GtkListStore	*store;
	GtkTreeIter	 iter;
	GtkTreeModel 	*model;

	gboolean	 more_items = TRUE, first_if = TRUE;  /* flag to check if first in list */
	gchar		*ifnm;
	gint		 linktype;
	gchar		*tmp_linklayer;
	gchar		*new_linklayer;

	/* new preferences interfaces link-layer string */
	new_linklayer = (gchar *)g_malloc0(MAX_VAL_LEN);

	/* get link-layer for each row (interface) */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(cur_list));
	store = GTK_LIST_STORE(model);
	if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {

		while (more_items) {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					   DEVICE_COLUMN, &ifnm,
					   DLT_COLUMN,    &linktype,
					   -1);

			if (linktype == -1){
				more_items = gtk_tree_model_iter_next (model,&iter);
				continue;
			}

			if (first_if != TRUE) {
				g_strlcat (new_linklayer, ",", MAX_VAL_LEN);
			}
			/*
			 * create/cat interface link-layer to new string
			 * (leave space for parens, comma and terminator)
			 */
			tmp_linklayer = g_strdup_printf("%s(%d)", ifnm, linktype);
			g_strlcat(new_linklayer, tmp_linklayer, MAX_VAL_LEN);
			g_free(tmp_linklayer);
			g_free(ifnm);
			/* set first-in-list flag to false */
			first_if = FALSE;
			more_items = gtk_tree_model_iter_next (model,&iter);
		}

		/* write new link-layer string to preferences */
		g_free(prefs.capture_devices_linktypes);
		prefs.capture_devices_linktypes = new_linklayer;
	}
}

#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
/*
 * Create/write new interfaces buffer size string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_buffersize(void)
{
	GtkListStore	*store;
	GtkTreeIter	 iter;
	GtkTreeModel 	*model;

	gboolean	 more_items = TRUE, first_if = TRUE;  /* flag to check if first in list */
	gchar		*ifnm;
	gint		 buffersize;
	gchar		*tmp_buffersize;
	gchar		*new_buffersize;

	/* new preferences interfaces buffer size string */
	new_buffersize = (gchar *)g_malloc0(MAX_VAL_LEN);

	/* get buffer size for each row (interface) */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(cur_list));
	store = GTK_LIST_STORE(model);
	if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {

		while (more_items) {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					   DEVICE_COLUMN, &ifnm,
					   BUF_COLUMN,    &buffersize,
					   -1);
			if (buffersize == -1){
				more_items = gtk_tree_model_iter_next (model,&iter);
				continue;
			}

			if (first_if != TRUE) {
				g_strlcat (new_buffersize, ",", MAX_VAL_LEN);
			}
			/*
			 * create/cat interface buffersize to new string
			 * (leave space for parens, comma and terminator)
			 */
			tmp_buffersize = g_strdup_printf("%s(%d)", ifnm, buffersize);
			g_strlcat(new_buffersize, tmp_buffersize, MAX_VAL_LEN);
			g_free(tmp_buffersize);
			g_free(ifnm);
			/* set first-in-list flag to false */
			first_if = FALSE;
			more_items = gtk_tree_model_iter_next (model,&iter);
		}

		/* write new buffersize string to preferences */
		g_free(prefs.capture_devices_buffersize);
		prefs.capture_devices_buffersize = new_buffersize;
	}
}
#endif

/*
 * Create/write new interfaces snap length string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_snaplen(void)
{
	GtkListStore	*store;
	GtkTreeIter	 iter;
	GtkTreeModel 	*model;

	gboolean	 more_items = TRUE, first_if = TRUE;  /* flag to check if first in list */
	gchar		*ifnm;
	gint		 snaplen;
	gboolean hassnap;
	gchar		*tmp_snaplen;
	gchar		*new_snaplen;

	/* new preferences interfaces snap length string */
	new_snaplen = (gchar *)g_malloc0(MAX_VAL_LEN);

	/* get snap length for each row (interface) */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(cur_list));
	store = GTK_LIST_STORE(model);
	if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {

		while (more_items) {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					   DEVICE_COLUMN, &ifnm,
					   SNAPLEN_COLUMN,    &snaplen,
					   HASSNAP_COLUMN,    &hassnap,
					   -1);
			if (snaplen == -1){
				more_items = gtk_tree_model_iter_next (model,&iter);
				continue;
			}
			if (first_if != TRUE) {
				g_strlcat (new_snaplen, ",", MAX_VAL_LEN);
			}
			/*
			 * create/cat interface snap length to new string
			 * (leave space for parens, comma and terminator)
			 */
			tmp_snaplen = g_strdup_printf("%s:%d(%d)", ifnm, hassnap, (hassnap?snaplen:WTAP_MAX_PACKET_SIZE));
			g_strlcat(new_snaplen, tmp_snaplen, MAX_VAL_LEN);
			g_free(tmp_snaplen);
			g_free(ifnm);
			/* set first-in-list flag to false */
			first_if = FALSE;
			more_items = gtk_tree_model_iter_next (model,&iter);
		}

		/* write new snap length string to preferences */
		g_free(prefs.capture_devices_snaplen);
		prefs.capture_devices_snaplen = new_snaplen;
	}
}

/*
 * Create/write new promiscuous mode string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_pmode(void)
{
	GtkListStore	*store;
	GtkTreeIter	 iter;
	GtkTreeModel 	*model;
	GtkWidget *promisc_cb;

	gboolean	 more_items = TRUE, first_if = TRUE;  /* flag to check if first in list */
	gchar		*ifnm;
	gboolean	pmode, off = FALSE;
	gchar		*tmp_pmode;
	gchar		*new_pmode;

	/* new preferences interfaces promiscuous mode string */
	new_pmode = (gchar *)g_malloc0(MAX_VAL_LEN);

	/* get promiscuous mode for each row (interface) */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(cur_list));
	store = GTK_LIST_STORE(model);
	if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {

		while (more_items) {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					   DEVICE_COLUMN, &ifnm,
					   PMODE_COLUMN,    &pmode,
					   -1);
			if (pmode == -1){
				more_items = gtk_tree_model_iter_next (model,&iter);
				continue;
			}

			if (first_if != TRUE) {
				g_strlcat (new_pmode, ",", MAX_VAL_LEN);
			}
			/*
			 * create/cat interface promiscuous mode to new string
			 * (leave space for parens, comma and terminator)
			 */
			if (!pmode) {
				off = TRUE;
			}
			tmp_pmode = g_strdup_printf("%s(%d)", ifnm, pmode);
			g_strlcat(new_pmode, tmp_pmode, MAX_VAL_LEN);
			g_free(tmp_pmode);
			g_free(ifnm);
			/* set first-in-list flag to false */
			first_if = FALSE;
			more_items = gtk_tree_model_iter_next (model,&iter);
		}

		/* write new promiscuous mode string to preferences */
		g_free(prefs.capture_devices_pmode);
		prefs.capture_devices_pmode = new_pmode;
		if (off) {
			prefs.capture_prom_mode = FALSE;
		} else {
			prefs.capture_prom_mode = TRUE;
		}
		promisc_cb = (GtkWidget *)g_object_get_data(G_OBJECT(capture_window), PROM_MODE_KEY);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(promisc_cb), prefs.capture_prom_mode);
	}
}

/*
 * Create/write new interfaces description string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_descr(void)
{
	GtkListStore	*store;
	GtkTreeIter	 iter;
	GtkTreeModel	*model;
	gboolean	 more_items = TRUE;
	gboolean	 first_if = TRUE;	/* flag to check if first in list */
	gchar		*ifnm;
	gchar		*desc;
	gchar		*tmp_descr;
	gchar		*new_descr;

	/* new preferences interfaces description string */
	new_descr = (gchar *)g_malloc0(MAX_VAL_LEN);

	/* get description for each row (interface) */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(cur_list));
	store = GTK_LIST_STORE(model);
	if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {
		while (more_items) {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
				DEVICE_COLUMN, &ifnm,
				COMMENT_COLUMN, &desc,
				-1);

			/* if no description, skip this interface */
			if (strlen(desc) == 0){
				more_items = gtk_tree_model_iter_next (model,&iter);
				continue;
			}
			/*
			 * create/cat interface description to new string
			 * (leave space for parens, comma and terminator)
			 */
			if (first_if != TRUE) {
				g_strlcat (new_descr, ",", MAX_VAL_LEN);
			}

			tmp_descr = g_strdup_printf("%s(%s)", ifnm, desc);
			g_strlcat(new_descr, tmp_descr, MAX_VAL_LEN);
			g_free(tmp_descr);

			/* set first-in-list flag to false */
			first_if = FALSE;
			more_items = gtk_tree_model_iter_next (model,&iter);
		}

		/* write new description string to preferences */
		g_free(prefs.capture_devices_descr);
		prefs.capture_devices_descr = new_descr;
	}
}

/*
 * Create/write new "hidden" interfaces string based on current CList.
 * Put it into the preferences value.
 */
static void
ifopts_write_new_hide(void)
{
	GtkListStore 	*store;
	GtkTreeIter 	 iter;
	GtkTreeModel 	*model;
	gboolean	 more_items = TRUE;
	gint		 first_if = TRUE;	/* flag to check if first in list */
	gchar		*ifnm;
	gboolean	 hide;
	gchar		*new_hide;

	/* get "hide" flag text for each row (interface) */
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(cur_list));
	store = GTK_LIST_STORE(model);
	if( gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter) ) {
		/* new preferences "hidden" interfaces string */
		new_hide = (gchar *)g_malloc0(MAX_VAL_LEN);
		while (more_items) {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					   DEVICE_COLUMN, &ifnm,
					   HIDE_COLUMN,   &hide,
					   -1);

			/* if flag text is "No", skip this interface */
			if (!hide){
				more_items = gtk_tree_model_iter_next (model,&iter);
				continue;
			}

			/*
			 * create/cat interface to new string
			 */
			if (first_if != TRUE)
				g_strlcat (new_hide, ",", MAX_VAL_LEN);
			g_strlcat (new_hide, ifnm, MAX_VAL_LEN);

			/* set first-in-list flag to false */
			first_if = FALSE;
			more_items = gtk_tree_model_iter_next (model,&iter);
		}

		/* write new "hidden" string to preferences */
		g_free(prefs.capture_devices_hide);
		prefs.capture_devices_hide = new_hide;
		hide_interface(g_strdup(new_hide));
	}
}

static void
prom_mode_cb(GtkToggleButton *tbt, gpointer udata _U_) {
	prefs.capture_prom_mode = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tbt));
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
