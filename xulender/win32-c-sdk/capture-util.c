/* capture-util.c
 * UI utility routines
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

/*
 * Much (most?) of this stuff was copied from gtk/ui_util.c and
 * gtk/capture_info_dlg.c, and modified accordingly.
 */

#include "config.h"

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "globals.h"
#include <glib.h>

#include "ringbuffer.h"
#include "pcap-util.h"

#include "win32-globals.h"
#include "win32-c-sdk.h"
#include "ethereal-win32.h"
#include "win32-menu.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include "capture.h"
#include "capture-wpcap.h"
#include "simple_dialog.h"
#include <epan/filesystem.h>

#include "capture-util.h"
#include "capture-dialog.h"
#include "capture-info-dialog.h"

/*
 * These should match the element IDs in capture-info-dialog.xul AND
 * the packet_counts struct in epan/packet.h.
 */
static gchar *info_element_id[] = {
    "sctp",
    "tcp",
    "udp",
    "icmp",
    "arp",
    "ospf",
    "gre",
    "netbios",
    "ipx",
    "vines",
    "other"
    /* We handle "total" elsewhere. */
};

/* Make sure we can perform a capture, and if so open the capture options dialog */
/* XXX - Switch over to value struct iteration, like we're using in the prefs dialog. */
void
capture_start_prep() {
    GList *if_list, *if_entry;
    int   err;
    char  err_str[PCAP_ERRBUF_SIZE];
    win32_element_t *if_el, *cb_el, *sp_el, *tb_el;
    if_info_t *if_info;

    /* Is WPcap loaded? */
    if (!has_wpcap) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Unable to load WinPcap (wpcap.dll); Ethereal will not be able "
	    "to capture packets.\n\n"
	    "In order to capture packets, WinPcap must be installed; see\n"
	    "\n"
	    "        http://winpcap.polito.it/\n"
	    "\n"
	    "or the mirror at\n"
	    "\n"
	    "        http://winpcap.mirror.ethereal.com/\n"
	    "\n"
	    "or the mirror at\n"
	    "\n"
	    "        http://www.mirrors.wiretapped.net/security/packet-capre/winpcap/\n"
	    "\n"
	    "for a downloadable version of WinPcap and for instructions\n"
	    "on how to install WinPcap.");
	return;
    }

    if_list = get_interface_list(&err, err_str);
    if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
	simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Can't get list of interfaces: %s",
	      err_str);
    }

    if (! g_hw_capture_dlg) {
	g_hw_capture_dlg = capture_dialog_dialog_create(g_hw_mainwin);

	if_el = win32_identifier_get_str("capture-dialog.interface-combo");
	win32_element_assert(if_el);

	for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
	    if_info = if_entry->data;
	    SendMessage(if_el->h_wnd, CB_ADDSTRING, 0, (LPARAM) (LPCTSTR) if_info->name);
	}
	SendMessage(if_el->h_wnd, CB_SETCURSEL, 0, 0);
    }

    /* Buffer size */
    sp_el = win32_identifier_get_str("capture-dialog.buffer-size");
    ethereal_spinner_set_range(sp_el, 1, 65535);
    ethereal_spinner_set_pos(sp_el, capture_opts.buffer_size);

    /* Promiscuous mode */
    cb_el = win32_identifier_get_str("capture-dialog.promiscuous");
    win32_checkbox_set_state(cb_el, capture_opts.promisc_mode);

    /* Snaplen */
    cb_el = win32_identifier_get_str("capture-dialog.packet-size-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_snaplen);

    sp_el = win32_identifier_get_str("capture-dialog.packet-size-spinner");
    ethereal_spinner_set_range(sp_el, MIN_PACKET_SIZE, WTAP_MAX_PACKET_SIZE);
    ethereal_spinner_set_pos(sp_el, capture_opts.snaplen);
    win32_element_set_enabled(sp_el, capture_opts.has_snaplen);

    /* Fill in our capture filter, if we have one */
    if (cfile.cfilter) {
	tb_el = win32_identifier_get_str("capture-dialog.capture-filter");
	win32_textbox_set_text(tb_el, cfile.cfilter);
    }

    cb_el = win32_identifier_get_str("capture-dialog.next-file-every-size-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_autostop_filesize);

    /* Capture file options */
    cb_el = win32_identifier_get_str("capture-dialog.use-multiple-files");
    win32_checkbox_set_state(cb_el, capture_opts.multi_files_on);

    /* Ring buffer file size */
    cb_el = win32_identifier_get_str("capture-dialog.next-file-every-size-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_autostop_filesize);

    sp_el = win32_identifier_get_str("capture-dialog.next-file-every-size-spinner");
    ethereal_spinner_set_range(sp_el, 1, INT_MAX);
    ethereal_spinner_set_pos(sp_el, capture_opts.autostop_filesize);

    /* Ring buffer duration */
    cb_el = win32_identifier_get_str("capture-dialog.next-file-every-time-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_file_duration);

    sp_el = win32_identifier_get_str("capture-dialog.next-file-every-time-spinner");
    ethereal_spinner_set_range(sp_el, 1, INT_MAX);
    ethereal_spinner_set_pos(sp_el, capture_opts.file_duration);

    /* Ring buffer files */
    cb_el = win32_identifier_get_str("capture-dialog.ring-buffer-with-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_ring_num_files);

    sp_el = win32_identifier_get_str("capture-dialog.ring-buffer-with-spinner");
    ethereal_spinner_set_range(sp_el, 2, RINGBUFFER_MAX_NUM_FILES);
    ethereal_spinner_set_pos(sp_el, capture_opts.ring_num_files);
    /* XXX - Set wrap and handle onchange */

    /* Stop capture after */
    cb_el = win32_identifier_get_str("capture-dialog.stop-capture-after-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_autostop_files);

    sp_el = win32_identifier_get_str("capture-dialog.stop-capture-after-spinner");
    ethereal_spinner_set_range(sp_el, 1, INT_MAX);
    ethereal_spinner_set_pos(sp_el, capture_opts.autostop_files);

    /* Stop after... (capture limits frame) */
    /* Packet count row */
    cb_el = win32_identifier_get_str("capture-dialog.stop-after-packets-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_autostop_packets);

    sp_el = win32_identifier_get_str("capture-dialog.stop-after-packets-spinner");
    ethereal_spinner_set_range(sp_el, 1, INT_MAX);
    ethereal_spinner_set_pos(sp_el, capture_opts.autostop_packets);

    /* Filesize row */
    cb_el = win32_identifier_get_str("capture-dialog.stop-after-size-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_autostop_filesize);

    sp_el = win32_identifier_get_str("capture-dialog.stop-after-size-spinner");
    ethereal_spinner_set_range(sp_el, 1, INT_MAX);
    ethereal_spinner_set_pos(sp_el, capture_opts.autostop_filesize);

    /* Duration row */
    cb_el = win32_identifier_get_str("capture-dialog.stop-after-time-cb");
    win32_checkbox_set_state(cb_el, capture_opts.has_autostop_duration);

    sp_el = win32_identifier_get_str("capture-dialog.stop-after-time-spinner");
    ethereal_spinner_set_range(sp_el, 1, INT_MAX);
    ethereal_spinner_set_pos(sp_el, capture_opts.autostop_duration);

    /* Set up our display options */
    cb_el = win32_identifier_get_str("capture-dialog.update-real-time");
    win32_checkbox_set_state(cb_el, capture_opts.sync_mode);

    cb_el = win32_identifier_get_str("capture-dialog.auto-scroll-live");
    win32_checkbox_set_state(cb_el, auto_scroll_live);

    cb_el = win32_identifier_get_str("capture-dialog.show_info");
    win32_checkbox_set_state(cb_el, !capture_opts.show_info);

    /* Set up name resolution */
    cb_el = win32_identifier_get_str("capture-mac-resolution");
    win32_checkbox_set_state(cb_el, g_resolv_flags & RESOLV_MAC);

    cb_el = win32_identifier_get_str("capture-network-resolution");
    win32_checkbox_set_state(cb_el, g_resolv_flags & RESOLV_NETWORK);

    cb_el = win32_identifier_get_str("capture-transport-resolution");
    win32_checkbox_set_state(cb_el, g_resolv_flags & RESOLV_TRANSPORT);

    capture_dialog_adjust_sensitivity(cb_el);

    capture_dialog_dialog_show(g_hw_capture_dlg);
}


/* capture_info_counts_t and capture_info_ui_t wer
/* a single capture counter value (with title, pointer to value and GtkWidgets) */
/* as the packet_counts is a struct, not an array, keep a pointer to the */
/* corresponding value packet_counts, to speed up (and simplify) output of values */
typedef struct {
    gint            *value_ptr;
    win32_element_t *value_ds, *percent_pm, *percent_ds;
} capture_info_counts_t;

/* all data we need to know of this dialog, after creation finished */
typedef struct {
    win32_element_t       *cap_info_dlg, *total_el, *running_time_el;
    capture_info_counts_t  counts[CAPTURE_PACKET_COUNTS - 1];
} capture_info_ui_t;

static guint32 time_unit_menulist_get_value(win32_element_t *ml_el, guint32 value);
static guint32 size_unit_menulist_get_value(win32_element_t *ml_el, guint32 value);


/* XXX - Move this to epan/strutil.c */
/* calculate the percentage of the current packet type */
static float
pct(gint num, gint denom) {
    if (denom) {
	return (float) (num * 100.0 / denom);
    } else {
	return 0.0;
    }
}

/* Defined in capture.h */

/* create the capture info dialog */
void
capture_info_create(capture_info *cinfo, gchar *iface) {
    capture_info_ui_t *info;
    gchar id_str[64];
    int i;

    if (! g_hw_capture_info_dlg) {
    	g_hw_capture_info_dlg = capture_info_dialog_dialog_create(g_hw_mainwin);
    }
    SetWindowText(g_hw_capture_info_dlg,
	g_strdup_printf("Ethereal: Capture - Interface %s", iface));

    info = g_malloc0(sizeof(capture_info_ui_t));

    info->cap_info_dlg = (win32_element_t *) GetWindowLong(g_hw_capture_info_dlg, GWL_USERDATA);
    info->total_el = win32_identifier_get_str("capture-count-total");
    win32_element_assert(info->total_el);
    info->running_time_el = win32_identifier_get_str("capture-run-time");
    win32_element_assert(info->running_time_el);

    info->counts[0].value_ptr  = &(cinfo->counts->sctp);
    info->counts[1].value_ptr  = &(cinfo->counts->tcp);
    info->counts[2].value_ptr  = &(cinfo->counts->udp);
    info->counts[3].value_ptr  = &(cinfo->counts->icmp);
    info->counts[4].value_ptr  = &(cinfo->counts->arp);
    info->counts[5].value_ptr  = &(cinfo->counts->ospf);
    info->counts[6].value_ptr  = &(cinfo->counts->gre);
    info->counts[7].value_ptr  = &(cinfo->counts->netbios);
    info->counts[8].value_ptr  = &(cinfo->counts->ipx);
    info->counts[9].value_ptr  = &(cinfo->counts->vines);
    info->counts[10].value_ptr = &(cinfo->counts->other);

    for (i = 0; i < CAPTURE_PACKET_COUNTS - 1; i++) {
	g_snprintf(id_str, sizeof(id_str), "capture-%s-count", info_element_id[i]);
	info->counts[i].value_ds = win32_identifier_get_str(id_str);
	win32_element_assert(info->counts[i].value_ds);
	g_snprintf(id_str, sizeof(id_str), "capture-%s-progress", info_element_id[i]);
	info->counts[i].percent_pm = win32_identifier_get_str(id_str);
	win32_element_assert(info->counts[i].percent_pm);
	g_snprintf(id_str, sizeof(id_str), "capture-%s-percent", info_element_id[i]);
	info->counts[i].percent_ds = win32_identifier_get_str(id_str);
	win32_element_assert(info->counts[i].percent_ds);
    }

    capture_info_dialog_dialog_show(g_hw_capture_info_dlg);

    cinfo->ui = info;
}

/* Update the capture info counters in the dialog */
void
capture_info_update(capture_info *cinfo) {
    int i;
    gchar label_str[64];
    capture_info_ui_t *info = cinfo->ui;

    g_snprintf(label_str, sizeof(label_str), "%02ld:%02ld:%02ld",
	(long)(cinfo->running_time/3600), (long)((cinfo->running_time%3600)/60),
	(long)(cinfo->running_time%60));
    SetWindowText(info->running_time_el->h_wnd, label_str);

    g_snprintf(label_str, sizeof(label_str), "%d", cinfo->counts->total);
    SetWindowText(info->total_el->h_wnd, label_str);

    for (i = 0; i < CAPTURE_PACKET_COUNTS - 1; i++) {
	g_snprintf(label_str, sizeof(label_str), "%d", *info->counts[i].value_ptr);
	SetWindowText(info->counts[i].value_ds->h_wnd, label_str);
	SendMessage(info->counts[i].percent_pm->h_wnd, PBM_SETPOS,
	    (int) (pct(*info->counts[i].value_ptr, cinfo->counts->total)), 0);
	g_snprintf(label_str, sizeof(label_str), "%.1f%%",
	    pct(*info->counts[i].value_ptr, cinfo->counts->total));
	SetWindowText(info->counts[i].percent_ds->h_wnd, label_str);
    }
}

/* destroy the capture info dialog again */
void
capture_info_destroy(capture_info *cinfo) {
    capture_info_dialog_dialog_hide(g_hw_capture_info_dlg);
    g_free(cinfo->ui);
}

/* Defined in capture-util.h */

/* Collect our capture parameters and start capturing.  This is the
   counterpart to gtk/capture_dlg.c:capture_prep_ok_cb(). */

void
capture_dialog_start_capture (win32_element_t *ok_el) {
    gchar           *save_file = NULL, *g_save_file = NULL;
    gchar           *if_name = NULL;
    gchar           *filter_text = NULL;
    win32_element_t *if_el, *cd_el = win32_identifier_get_str("capture-dialog");
    win32_element_t *cb_el, *sp_el, *tb_el, *ml_el;
    int len;
    gchar           *cf_name, *dirname;
    guint32          tmp;

    win32_element_assert(ok_el);
    win32_element_assert(cd_el);

    /* Fetch our interface settings */
    if_el = win32_identifier_get_str("capture-dialog.interface-combo");
    len = SendMessage(if_el->h_wnd, WM_GETTEXTLENGTH, 0, 0);
    if (len > 0) {
	len++;
	if_name = g_malloc(len);
	SendMessage(if_el->h_wnd, WM_GETTEXT, (WPARAM) len, (LPARAM) if_name);
    }

    if (*if_name == '\0' || if_name == NULL) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "You didn't specify an interface on which to capture packets.");
	if (if_name)
	    g_free(if_name);
	return;
    }

    if (cfile.iface)
	g_free(cfile.iface);
    cfile.iface = g_strdup(if_name);
    g_free(if_name);

    /* XXX - We haven't implemented linktype options yet. */
    capture_opts.linktype = -1;

    /* Fetch the capture buffer size */
    sp_el = win32_identifier_get_str("capture-dialog.buffer-size");
    capture_opts.buffer_size = ethereal_spinner_get_pos(sp_el);

    /* Fetch the snapshot length */
    cb_el = win32_identifier_get_str("capture-dialog.packet-size-cb");
    capture_opts.has_snaplen = win32_checkbox_get_state(cb_el);
    if (capture_opts.has_snaplen) {
	sp_el = win32_identifier_get_str("capture-dialog.packet-size-spinner");
	capture_opts.snaplen = ethereal_spinner_get_pos(sp_el);
	if (capture_opts.snaplen < 1)
	    capture_opts.snaplen = WTAP_MAX_PACKET_SIZE;
	else if (capture_opts.snaplen < MIN_PACKET_SIZE)
	    capture_opts.snaplen = MIN_PACKET_SIZE;
    }

    /* Promiscuous mode */
    cb_el = win32_identifier_get_str("capture-dialog.promiscuous");
    capture_opts.promisc_mode = win32_checkbox_get_state(cb_el);

    /* Fetch the capture filter */
    /* XXX - don't try to get clever and set "cfile.filter" to NULL if the
       filter string is empty, as an indication that we don't have a filter
       and thus don't have to set a filter when capturing - the version of
       libpcap in Red Hat Linux 6.1, and versions based on later patches
       in that series, don't bind the AF_PACKET socket to an interface
       until a filter is set, which means they aren't bound at all if
       no filter is set, which means no packets arrive as input on that
       socket, which means Ethereal never sees any packets. */
    tb_el = win32_identifier_get_str("capture-dialog.capture-filter");
    filter_text = win32_textbox_get_text(tb_el);
    g_assert(filter_text != NULL);

    if (cfile.cfilter)
	g_free(cfile.cfilter);

    cfile.cfilter = filter_text;

    /* Fetch the save file */
    tb_el = win32_identifier_get_str("capture-dialog.save-file");
    g_save_file = win32_textbox_get_text(tb_el);
    if (g_save_file && g_save_file[0]) {
	/* User specified a file to which the capture should be written. */
	save_file = g_save_file;
	/* Save the directory name for future file dialogs. */
	cf_name = g_strdup(g_save_file);
	dirname = get_dirname(cf_name);  /* Overwrites cf_name */
	set_last_open_dir(dirname);
	g_free(cf_name);
    } else {
	/* User didn't specify a file; save to a temporary file. */
	if (g_save_file)
	    g_free(g_save_file);
	save_file = NULL;
    }

    /* Fetch our autostop settings */
    cb_el = win32_identifier_get_str("capture-dialog.stop-after-packets-cb");
    capture_opts.has_autostop_packets = win32_checkbox_get_state(cb_el);
    if (capture_opts.has_autostop_packets) {
	sp_el = win32_identifier_get_str("capture-dialog.stop-after-packets-spinner");
	capture_opts.autostop_packets = ethereal_spinner_get_pos(sp_el);
    }

    cb_el = win32_identifier_get_str("capture-dialog.stop-after-time-cb");
    capture_opts.has_autostop_duration = win32_checkbox_get_state(cb_el);
    if (capture_opts.has_autostop_duration) {
	sp_el = win32_identifier_get_str("capture-dialog.stop-after-time-spinner");
	ml_el = win32_identifier_get_str("capture-dialog.stop-after-time-ml");
	capture_opts.autostop_duration = ethereal_spinner_get_pos(sp_el);
	capture_opts.autostop_duration =
	    time_unit_menulist_get_value(ml_el, capture_opts.autostop_duration);
    }

    cb_el = win32_identifier_get_str("capture-dialog.update-real-time");
    capture_opts.sync_mode = win32_checkbox_get_state(cb_el);

    cb_el = win32_identifier_get_str("capture-dialog.auto-scroll-live");
    auto_scroll_live = win32_checkbox_get_state(cb_el);

    cb_el = win32_identifier_get_str("capture-dialog.show_info");
    capture_opts.show_info = ! win32_checkbox_get_state(cb_el);

    /* Fetch our name resolution settings */
    cb_el = win32_identifier_get_str("capture-mac-resolution");
    if (win32_checkbox_get_state(cb_el))
	g_resolv_flags |= RESOLV_MAC;

    cb_el = win32_identifier_get_str("capture-network-resolution");
    if (win32_checkbox_get_state(cb_el))
	g_resolv_flags |= RESOLV_NETWORK;

    cb_el = win32_identifier_get_str("capture-transport-resolution");
    if (win32_checkbox_get_state(cb_el))
	g_resolv_flags |= RESOLV_TRANSPORT;

    menu_name_resolution_changed(g_hw_mainwin);

    cb_el = win32_identifier_get_str("capture-dialog.ring-buffer-with-cb");
    capture_opts.has_ring_num_files = win32_checkbox_get_state(cb_el);

    sp_el = win32_identifier_get_str("capture-dialog.ring-buffer-with-spinner");
    capture_opts.ring_num_files = ethereal_spinner_get_pos(sp_el);
    if (capture_opts.ring_num_files > RINGBUFFER_MAX_NUM_FILES)
	capture_opts.ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
    else if (capture_opts.ring_num_files < RINGBUFFER_MIN_NUM_FILES)
	capture_opts.ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif

    cb_el = win32_identifier_get_str("capture-dialog.use-multiple-files");
    capture_opts.multi_files_on = win32_checkbox_get_state(cb_el);

    if(capture_opts.sync_mode)
	capture_opts.multi_files_on = FALSE;

    if (capture_opts.multi_files_on) {
	cb_el = win32_identifier_get_str("capture-dialog.next-file-every-size-cb");
	capture_opts.has_autostop_filesize = win32_checkbox_get_state(cb_el);
	if (capture_opts.has_autostop_filesize) {
	    sp_el = win32_identifier_get_str("capture-dialog.stop-after-size-spinner");
	    tmp = ethereal_spinner_get_pos(sp_el);
	    tmp = size_unit_menulist_get_value(sp_el, tmp);
	    if(tmp != 0) {
		capture_opts.autostop_filesize = tmp;
	    } else {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Multiple files: Requested filesize too large!\n\n"
		"The setting \"Next file every x byte(s)\" can't be greater than %u bytes (2GB).", G_MAXINT);
		return;
	    }
	}
	/* test if the settings are ok for a ringbuffer */
	if (save_file == NULL) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Multiple files: No capture file name given!\n\n"
		"You must specify a filename if you want to use multiple files.");
	    return;
	} else if (!capture_opts.has_autostop_filesize) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Multiple files: No file limit given!\n\n"
		"You must specify a file size at which is switched to the next capture file\n"
		"if you want to use multiple files.");
	    g_free(save_file);
	    return;
	}
    } else {
	cb_el = win32_identifier_get_str("capture-dialog.next-file-every-size-cb");
	capture_opts.has_autostop_filesize = win32_checkbox_get_state(cb_el);
	if (capture_opts.has_autostop_filesize) {
	    sp_el = win32_identifier_get_str("capture-dialog.stop-after-size-spinner");
	    tmp = ethereal_spinner_get_pos(sp_el);
	    tmp = size_unit_menulist_get_value(sp_el, tmp);
	    if(tmp != 0) {
		capture_opts.autostop_filesize = tmp;
	    } else {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Stop Capture: Requested filesize too large!\n\n"
		    "The setting \"... after x byte(s)\" can't be greater than %u bytes (2GB).", G_MAXINT);
		return;
	    }
	}
    }

    cb_el = win32_identifier_get_str("capture-dialog.next-file-every-time-cb");
    capture_opts.has_file_duration = win32_checkbox_get_state(cb_el);

    if (capture_opts.has_file_duration) {
	sp_el = win32_identifier_get_str("capture-dialog.next-file-every-time-spinner");
	capture_opts.file_duration = ethereal_spinner_get_pos(sp_el);
	capture_opts.file_duration = time_unit_menulist_get_value(sp_el, capture_opts.file_duration);
    }

    cb_el = win32_identifier_get_str("capture-dialog.stop-capture-after-cb");
    capture_opts.has_autostop_files = win32_checkbox_get_state(cb_el);

    if (capture_opts.has_autostop_files) {
	sp_el = win32_identifier_get_str("capture-dialog.stop-capture-after-spinner");
	capture_opts.file_duration = ethereal_spinner_get_pos(sp_el);
    }

    capture_dialog_dialog_hide(cd_el->h_wnd);

    do_capture(save_file);
    if (save_file != NULL)
	g_free(save_file);
}

void
capture_info_dialog_stop_capture(win32_element_t *cid_el) {
    capture_stop();
}

/* Defined in capture-dialog.h */

void
capture_dialog_hide(win32_element_t *cancel_el) {
    win32_element_t *cd_el = win32_identifier_get_str("capture-dialog");

    win32_element_assert(cd_el);

    capture_dialog_dialog_hide(cd_el->h_wnd);
}

void
capture_dialog_limit_packet_size(win32_element_t *cb_el) {
    win32_element_t *sp_el;

    capture_opts.has_snaplen = win32_checkbox_get_state(cb_el);

    sp_el = win32_identifier_get_str("capture-dialog.packet-size-spinner");
    win32_element_set_enabled(sp_el, win32_checkbox_get_state(cb_el));
}

/*
 * This is the counterpart of capture_prep_adjust_sensitivity() in
 * gtk/capture_dlg.c.  We have several controls in the capture dialog
 * that affect the behavior of other controls.  Adjust them all here.
 */
void
capture_dialog_adjust_sensitivity(win32_element_t *cb_el) {
    win32_element_t *sync_cb, *multi_files_on_cb, *auto_scroll_cb,
		    *ring_filesize_cb, *ring_filesize_sp,
		    *ring_filesize_ml, *file_duration_cb,
		    *file_duration_sp, *file_duration_ml,
		    *ringbuffer_nbf_cb, *ringbuffer_nbf_sp,
		    *ringbuffer_nbf_ds, *stop_filesize_cb,
		    *stop_filesize_sp, *stop_filesize_ml,
		    *stop_files_cb, *stop_files_sp, *stop_files_ds,
		    *stop_packets_cb, *stop_packets_sp, *stop_packets_ds,
		    *stop_duration_cb, *stop_duration_sp, *stop_duration_ml,
		    *hide_info_cb;

    sync_cb           = win32_identifier_get_str("capture-dialog.update-real-time");
    multi_files_on_cb = win32_identifier_get_str("capture-dialog.use-multiple-files");
    auto_scroll_cb    = win32_identifier_get_str("capture-dialog.auto-scroll-live");
    hide_info_cb      = win32_identifier_get_str("capture-dialog.show_info");
    ring_filesize_cb  = win32_identifier_get_str("capture-dialog.next-file-every-size-cb");
    ring_filesize_sp  = win32_identifier_get_str("capture-dialog.next-file-every-size-spinner");
    ring_filesize_ml  = win32_identifier_get_str("capture-dialog.next-file-every-size-ml");
    file_duration_cb  = win32_identifier_get_str("capture-dialog.next-file-every-time-cb");
    file_duration_sp  = win32_identifier_get_str("capture-dialog.next-file-every-time-spinner");
    file_duration_ml  = win32_identifier_get_str("capture-dialog.next-file-every-time-ml");
    ringbuffer_nbf_cb = win32_identifier_get_str("capture-dialog.ring-buffer-with-cb");
    ringbuffer_nbf_sp = win32_identifier_get_str("capture-dialog.ring-buffer-with-spinner");
    ringbuffer_nbf_ds = win32_identifier_get_str("capture-dialog.ring-buffer-with-descr");
    stop_filesize_cb  = win32_identifier_get_str("capture-dialog.stop-after-size-cb");
    stop_filesize_sp  = win32_identifier_get_str("capture-dialog.stop-after-size-spinner");
    stop_filesize_ml  = win32_identifier_get_str("capture-dialog.stop-after-size-ml");
    stop_files_cb     = win32_identifier_get_str("capture-dialog.stop-capture-after-cb");
    stop_files_sp     = win32_identifier_get_str("capture-dialog.stop-capture-after-spinner");
    stop_files_ds     = win32_identifier_get_str("capture-dialog.stop-capture-after-descr");
    stop_packets_cb   = win32_identifier_get_str("capture-dialog.stop-after-packets-cb");
    stop_packets_sp   = win32_identifier_get_str("capture-dialog.stop-after-packets-spinner");
    stop_packets_ds   = win32_identifier_get_str("capture-dialog.stop-after-packets-descr");
    stop_duration_cb  = win32_identifier_get_str("capture-dialog.stop-after-time-cb");
    stop_duration_sp  = win32_identifier_get_str("capture-dialog.stop-after-time-spinner");
    stop_duration_ml  = win32_identifier_get_str("capture-dialog.stop-after-time-ml");

    if (win32_checkbox_get_state(sync_cb)) {
	/* "Update list of packets in real time" captures enabled; we don't
	   support ring buffer mode for those captures, so turn ring buffer
	   mode off if it's on, and make its toggle button, and the spin
	   button for the number of ring buffer files (and the spin button's
	   label), insensitive. */
	win32_checkbox_set_state(multi_files_on_cb, FALSE);
	win32_element_set_enabled(multi_files_on_cb, FALSE);

       /* Auto-scroll mode is meaningful only in "Update list of packets
	  in real time" captures, so make its toggle button sensitive. */
	win32_element_set_enabled(auto_scroll_cb, TRUE);
    } else {
	/* "Update list of packets in real time" captures disabled; that
	   means ring buffer mode is OK, so make its toggle button
	   sensitive. */
	win32_element_set_enabled(multi_files_on_cb, TRUE);

	/* Auto-scroll mode is meaningful only in "Update list of packets
	   in real time" captures, so make its toggle button insensitive. */
	win32_element_set_enabled(auto_scroll_cb, FALSE);
    }

    if (win32_checkbox_get_state(multi_files_on_cb)) {
	/* Ring buffer mode enabled. */
	/* Filesize is currently forced */
	win32_element_set_enabled(ring_filesize_cb, TRUE);
	win32_checkbox_set_state(ring_filesize_cb, TRUE);

	win32_element_set_enabled(ringbuffer_nbf_cb, TRUE);
	win32_element_set_enabled(ringbuffer_nbf_sp,
	    win32_checkbox_get_state(ringbuffer_nbf_cb));
	win32_element_set_enabled(ringbuffer_nbf_ds,
	    win32_checkbox_get_state(ringbuffer_nbf_cb));

	/* The ring filesize spinbox is sensitive if the "Next capture file
	   after N kilobytes" checkbox is on. */
	win32_element_set_enabled(ring_filesize_sp,
	    win32_checkbox_get_state(ring_filesize_cb));
	win32_element_set_enabled(ring_filesize_ml,
	    win32_checkbox_get_state(ring_filesize_cb));

        /* The ring duration spinbox is sensitive if the "Next capture file
	   after N seconds" checkbox is on. */
	win32_element_set_enabled(file_duration_cb, TRUE);
	win32_element_set_enabled(file_duration_sp,
	    win32_checkbox_get_state(file_duration_cb));
	win32_element_set_enabled(file_duration_ml,
	    win32_checkbox_get_state(file_duration_cb));

	win32_element_set_enabled(stop_filesize_cb, FALSE);
	win32_element_set_enabled(stop_filesize_sp, FALSE);
	win32_element_set_enabled(stop_filesize_ml, FALSE);

	win32_element_set_enabled(stop_files_cb, TRUE);
	win32_element_set_enabled(stop_files_sp,
	    win32_checkbox_get_state(stop_files_cb));
	win32_element_set_enabled(stop_files_ds,
	    win32_checkbox_get_state(stop_files_cb));
    } else {
	/* Ring buffer mode disabled. */
	win32_element_set_enabled(ringbuffer_nbf_cb, FALSE);
	win32_element_set_enabled(ringbuffer_nbf_sp, FALSE);
	win32_element_set_enabled(ringbuffer_nbf_ds, FALSE);

	win32_element_set_enabled(ring_filesize_cb, FALSE);
	win32_element_set_enabled(ring_filesize_sp, FALSE);
	win32_element_set_enabled(ring_filesize_ml, FALSE);

	win32_element_set_enabled(file_duration_cb, FALSE);
	win32_element_set_enabled(file_duration_sp, FALSE);
	win32_element_set_enabled(file_duration_ml, FALSE);

	/* The maximum file size spinbox is sensitive if the "Stop capture
	   after N kilobytes" checkbox is on. */
	win32_element_set_enabled(stop_filesize_cb, TRUE);
	win32_element_set_enabled(stop_filesize_sp,
	    win32_checkbox_get_state(stop_filesize_cb));
	win32_element_set_enabled(stop_filesize_ml,
	    win32_checkbox_get_state(stop_filesize_cb));

	win32_element_set_enabled(stop_files_cb, FALSE);
	win32_element_set_enabled(stop_files_sp, FALSE);
	win32_element_set_enabled(stop_files_ds, FALSE);
    }
    /* The maximum packet count spinbox is sensitive if the "Stop capture
       after N packets" checkbox is on. */
    win32_element_set_enabled(stop_packets_sp,
	win32_checkbox_get_state(stop_packets_cb));
    win32_element_set_enabled(stop_packets_ds,
	win32_checkbox_get_state(stop_packets_cb));

    /* The capture duration spinbox is sensitive if the "Stop capture
       after N seconds" checkbox is on. */
    win32_element_set_enabled(stop_duration_sp,
	win32_checkbox_get_state(stop_duration_cb));
    win32_element_set_enabled(stop_duration_ml,
	win32_checkbox_get_state(stop_duration_cb));
}

/*
 * Private
 */

#define TIME_UNIT_SECOND 0
#define TIME_UNIT_MINUTE 1
#define TIME_UNIT_HOUR   2
#define TIME_UNIT_DAY    3
#define MAX_TIME_UNITS   4

static guint32
time_unit_menulist_get_value(win32_element_t *ml_el, guint32 value) {
    int unit;

    win32_element_assert(ml_el);
    unit = SendMessage(ml_el->h_wnd, CB_GETCURSEL, 0, 0);

    switch(unit) {
    case(TIME_UNIT_SECOND):
        return value;
        break;
    case(TIME_UNIT_MINUTE):
        return value * 60;
        break;
    case(TIME_UNIT_HOUR):
        return value * 60 * 60;
        break;
    case(TIME_UNIT_DAY):
        return value * 60 * 60 * 24;
        break;
    default:
        g_assert_not_reached();
        return 0;
    }
}

#define SIZE_UNIT_BYTES     0
#define SIZE_UNIT_KILOBYTES 1
#define SIZE_UNIT_MEGABYTES 2
#define SIZE_UNIT_GIGABYTES 3
#define MAX_SIZE_UNITS      4

static guint32
size_unit_menulist_get_value(win32_element_t *ml_el, guint32 value) {
    int unit;

    win32_element_assert(ml_el);
    unit = SendMessage(ml_el->h_wnd, CB_GETCURSEL, 0, 0);


    switch(unit) {
    case(SIZE_UNIT_BYTES):
        return value;
        break;
    case(SIZE_UNIT_KILOBYTES):
        if(value > G_MAXINT / 1024) {
            return 0;
        } else {
            return value * 1024;
        }
        break;
    case(SIZE_UNIT_MEGABYTES):
        if(value > G_MAXINT / (1024 * 1024)) {
            return 0;
        } else {
            return value * 1024 * 1024;
        }
        break;
    case(SIZE_UNIT_GIGABYTES):
        if(value > G_MAXINT / (1024 * 1024 * 1024)) {
            return 0;
        } else {
            return value * 1024 * 1024 * 1024;
        }
        break;
    default:
        g_assert_not_reached();
        return 0;
    }
}
