/* win32-file-dlg.c
 * Native Windows file dialog routines
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2004 Gerald Combs
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

#include "globals.h"

#include <glib.h>

#include <stdio.h>

#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <io.h>

#include "epan/filesystem.h"
#include "epan/resolv.h"
#include "merge.h"
#include "prefs.h"
#include "prefs-recent.h"
#include "simple_dialog.h"
#include "util.h"

#include "win32-file-dlg.h"
#include "win32-main.h"
#include "capture-util.h"
#include "win32-menu.h"

typedef enum {
    merge_append,
    merge_chrono,
    merge_prepend
} merge_action_e;

static UINT CALLBACK open_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT CALLBACK save_as_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT CALLBACK merge_file_hook_proc(HWND mf_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static void file_set_save_marked_sensitive(HWND sf_hwnd);
static void range_update_dynamics(HWND sf_hwnd);

static int            filetype;
static packet_range_t range;
static merge_action_e merge_action;

gboolean
win32_open_file (HWND h_wnd) {
    static        OPENFILENAME ofn;
    gchar         file_name[MAX_PATH] = "";
    read_status_t err;
    gchar        *dirname;

    /* XXX - Check for version and set OPENFILENAME_SIZE_VERSION_400
       where appropriate */
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = h_wnd;
    ofn.hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
    /* XXX - Grab the rest of the extension list from ethereal.nsi. */
    ofn.lpstrFilter =
	"Accellent 5Views (*.5vw)\0"			"*.5vw\0"
	"Ethereal/tcpdump (*.cap, *.pcap)\0"		"*.cap;*.pcap\0"
	"Novell LANalyzer (*.tr1)\0"			"*.tr1\0"
	"NG/NAI Sniffer (*.cap, *.enc, *.trc)\0"	"*.cap;*.enc;*.trc\0"
	"Sun snoop (*.snoop)\0"				"*.snoop\0"
	"WildPackets EtherPeek (*.pkt)\0"		"*.pkt\0"
	"All Files (*.*)\0"				"*.*\0"
	"\0";
    ofn.lpstrCustomFilter = NULL;
    ofn.nMaxCustFilter = 0;
    ofn.nFilterIndex = 2;
    ofn.lpstrFile = file_name;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED && prefs.gui_fileopen_dir[0] != '\0') {
	ofn.lpstrInitialDir = prefs.gui_fileopen_dir;
    } else {
	ofn.lpstrInitialDir = NULL;
    }
    ofn.lpstrTitle = "Ethereal: Select a capture file";
    ofn.Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER |
	    OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_ENABLEHOOK;
    ofn.lpstrDefExt = NULL;
    ofn.lpfnHook = open_file_hook_proc;
    ofn.lpTemplateName = "ETHEREAL_OPENFILENAME_TEMPLATE";

    /* XXX - Get our filter */

    if (GetOpenFileName(&ofn)) {
	err = cf_open(file_name, FALSE, &cfile);
	if (err != 0) {
	    epan_cleanup();
	    exit(2);
	}
	err = cf_read(&cfile);
	if (err == READ_SUCCESS) {
	    dirname = get_dirname(file_name);
	    set_last_open_dir(dirname);
	    menu_name_resolution_changed(h_wnd);
	    return TRUE;
	}
    }
    return FALSE;
}


void
win32_save_as_file(HWND h_wnd, action_after_save_e action_after_save, gpointer action_after_save_data) {
    static OPENFILENAME ofn;
    gchar  file_name[MAX_PATH] = "";
    gchar *dirname;

    /* XXX - Check for version and set OPENFILENAME_SIZE_VERSION_400
       where appropriate */
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = h_wnd;
    ofn.hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
    /* XXX - Grab the rest of the extension list from ethereal.nsi. */
    ofn.lpstrFilter =
	"Accellent 5Views (*.5vw)\0"			"*.5vw\0"
	"Ethereal/tcpdump (*.cap, *.pcap)\0"		"*.cap;*.pcap\0"
	"Novell LANalyzer (*.tr1)\0"			"*.tr1\0"
	"NG/NAI Sniffer (*.cap, *.enc, *.trc)\0"	"*.cap;*.enc;*.trc\0"
	"Sun snoop (*.snoop)\0"				"*.snoop\0"
	"WildPackets EtherPeek (*.pkt)\0"		"*.pkt\0"
	"All Files (*.*)\0"				"*.*\0"
	"\0";
    ofn.lpstrCustomFilter = NULL;
    ofn.nMaxCustFilter = 0;
    ofn.nFilterIndex = 2;
    ofn.lpstrFile = file_name;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED && prefs.gui_fileopen_dir[0] != '\0') {
	ofn.lpstrInitialDir = prefs.gui_fileopen_dir;
    } else {
	ofn.lpstrInitialDir = NULL;
    }
    ofn.lpstrTitle = "Ethereal: Save file as";
    ofn.Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER |
	    OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST |
	    OFN_ENABLEHOOK;
    ofn.lpstrDefExt = NULL;
    ofn.lpfnHook = save_as_file_hook_proc;
    ofn.lpTemplateName = "ETHEREAL_SAVEFILENAME_TEMPLATE";

    if (GetSaveFileName(&ofn)) {
	/* Write out the packets (all, or only the ones from the current
	   range) to the file with the specified name. */
	/* XXX - If we're overwriting a file, GetSaveFileName does the
	   standard windows confirmation.  cf_save() then rejects the overwrite. */
	if (! cf_save(file_name, &cfile, &range, filetype)) {
	    /* The write failed.  Try again. */
	    win32_save_as_file(h_wnd, action_after_save, action_after_save_data);
	    return;
	}

	/* Save the directory name for future file dialogs. */
	dirname = get_dirname(file_name);  /* Overwrites cf_name */
	set_last_open_dir(dirname);

	/* we have finished saving, do we have pending things to do? */
	switch(action_after_save) {
	    case(after_save_no_action):
		break;
	    case(after_save_open_dialog):
		win32_open_file(h_wnd);
		break;
	    case(after_save_open_recent_file):
//		menu_open_recent_file_cmd(action_after_save_data_g);
		break;
	    case(after_save_open_dnd_file):
//		dnd_open_file_cmd(action_after_save_data_g);
		break;
	    case(after_save_merge_dialog):
//		file_merge_cmd(action_after_save_data_g);
		break;
#ifdef HAVE_LIBPCAP
	    case(after_save_capture_dialog):
		capture_start_prep();
		break;
#endif
	    case(after_save_close_file):
		cf_close(&cfile);
		break;
	     case(after_save_exit):
		main_do_quit();
		break;
	    default:
		g_assert_not_reached();
	}
    }
}


void
win32_merge_file (HWND h_wnd) {
    static   OPENFILENAME ofn;
    gchar    file_name[MAX_PATH] = "";
    gchar   *s;
    int      err;
    gboolean merge_ok;
    char    *in_filenames[2];
    int      out_fd;
    char     tmpname[128+1];

    /* XXX - Check for temp file and prompt accordingly */

    /* XXX - Check for version and set OPENFILENAME_SIZE_VERSION_400
       where appropriate */
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = h_wnd;
    ofn.hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
    /* XXX - Grab the rest of the extension list from ethereal.nsi. */
    ofn.lpstrFilter =
	"Accellent 5Views (*.5vw)\0"			"*.5vw\0"
	"Ethereal/tcpdump (*.cap, *.pcap)\0"		"*.cap;*.pcap\0"
	"Novell LANalyzer (*.tr1)\0"			"*.tr1\0"
	"NG/NAI Sniffer (*.cap, *.enc, *.trc)\0"	"*.cap;*.enc;*.trc\0"
	"Sun snoop (*.snoop)\0"				"*.snoop\0"
	"WildPackets EtherPeek (*.pkt)\0"		"*.pkt\0"
	"All Files (*.*)\0"				"*.*\0"
	"\0";
    ofn.lpstrCustomFilter = NULL;
    ofn.nMaxCustFilter = 0;
    ofn.nFilterIndex = 2;
    ofn.lpstrFile = file_name;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED && prefs.gui_fileopen_dir[0] != '\0') {
	ofn.lpstrInitialDir = prefs.gui_fileopen_dir;
    } else {
	ofn.lpstrInitialDir = NULL;
    }
    ofn.lpstrTitle = "Ethereal: Merge with capture file";
    ofn.Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER |
	    OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_ENABLEHOOK;
    ofn.lpstrDefExt = NULL;
    ofn.lpfnHook = merge_file_hook_proc;
    ofn.lpTemplateName = "ETHEREAL_MERGEFILENAME_TEMPLATE";

    if (GetOpenFileName(&ofn)) {
	out_fd = create_tempfile(tmpname, sizeof tmpname, "ether");

	/* merge or append the two files */

	switch (merge_action) {
	    case merge_append:
		/* append file */
		in_filenames[0] = file_name;
		in_filenames[1] = cfile.filename;
		merge_ok = merge_n_files(out_fd, 2, in_filenames, TRUE, &err);
		break;
	    case merge_chrono:
		/* chonological order */
		in_filenames[0] = cfile.filename;
		in_filenames[1] = file_name;
		merge_ok = merge_n_files(out_fd, 2, in_filenames, FALSE, &err);
		break;
	    case merge_prepend:
		/* prepend file */
		in_filenames[0] = cfile.filename;
		in_filenames[1] = file_name;
		merge_ok = merge_n_files(out_fd, 2, in_filenames, TRUE, &err);
		break;
	    default:
		g_assert_not_reached();
	}

	if(!merge_ok) {
	    /* merge failed */
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "An error occurred while merging the files: %s.",
		    wtap_strerror(err));
	    close(out_fd);
//	    if (rfcode != NULL)
//		dfilter_free(rfcode);
//	    return;
	}

	cf_close(&cfile);

	/* Try to open the merged capture file. */
	if ((err = cf_open(tmpname, TRUE /* temporary file */, &cfile)) != 0) {
	    /* We couldn't open it; don't dismiss the open dialog box,
	       just leave it around so that the user can, after they
	       dismiss the alert box popped up for the open error,
	       try again. */
//	    if (rfcode != NULL)
//		dfilter_free(rfcode);
	    return;
	}

	/* Attach the new read filter to "cf" ("cf_open()" succeeded, so
	   it closed the previous capture file, and thus destroyed any
	   previous read filter attached to "cf"). */
//	cfile.rfcode = rfcode;

	switch (cf_read(&cfile)) {
	    case READ_SUCCESS:
	    case READ_ERROR:
		/* Just because we got an error, that doesn't mean we were unable
		   to read any of the file; we handle what we could get from the
		   file. */
		break;
	    case READ_ABORTED:
		/* The user bailed out of re-reading the capture file; the
		   capture file has been closed - just free the capture file name
		   string and return (without changing the last containing
		   directory). */
		return;
	}

	/* Save the name of the containing directory specified in the path name,
	   if any; we can write over cf_merged_name, which is a good thing, given that
	   "get_dirname()" does write over its argument. */
	s = get_dirname(tmpname);
	set_last_open_dir(s);
    }
}


/*
 * Private routines
 */

#define PREVIEW_STR_MAX      200
#define PREVIEW_TIMEOUT_SECS   3

/* XXX - Taken verbatim from gtk/file_dlg.c */
static double
secs_usecs( guint32 s, guint32 us)
{
    return (us / 1000000.0) + (double)s;
}

/* If preview_file is NULL, disable the elements.  If not, enable and
 * show the preview info. */
static gboolean
preview_set_filename(HWND of_hwnd, gchar *preview_file) {
    HWND        cur_ctrl;
    int         i;
    gboolean    enable = FALSE;
    wtap       *wth;
    const struct wtap_pkthdr *phdr;
    int         err = 0;
    gchar      *err_info;
    struct stat cf_stat;
    long        data_offset;
    gchar       string_buff[PREVIEW_STR_MAX];
    guint       packet = 0;
    guint64     filesize;
    time_t      ti_time;
    struct tm  *ti_tm;
    guint       elapsed_time;
    time_t      time_preview;
    time_t      time_current;
    double      start_time = 0;
    double      stop_time = 0;
    double      cur_time;
    gboolean    is_breaked = FALSE;

    if (preview_file != NULL && strlen(preview_file) > 0) {
	enable = TRUE;
    }

    for (i = EWFD_PT_FILENAME; i <= EWFD_PTX_ELAPSED; i++) {
	cur_ctrl = GetDlgItem(of_hwnd, i);
	if (cur_ctrl) {
	    EnableWindow(cur_ctrl, enable);
	}
    }

    for (i = EWFD_PTX_FILENAME; i <= EWFD_PTX_ELAPSED; i++) {
	cur_ctrl = GetDlgItem(of_hwnd, i);
	if (cur_ctrl) {
	    SetWindowText(cur_ctrl, "-");
	}
    }

    if (enable) {
	cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FILENAME);
	SetWindowText(cur_ctrl, get_basename(preview_file));

	cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FORMAT);
	wth = wtap_open_offline(preview_file, &err, &err_info, TRUE);
	if (cur_ctrl && wth == NULL) {
	    if(err == WTAP_ERR_FILE_UNKNOWN_FORMAT) {
		SetWindowText(cur_ctrl, "unknown file format");
	    } else {
		SetWindowText(cur_ctrl, "error opening file");
	    }
	    return FALSE;
	}

	/* Find the size of the file. */
	if (fstat(wtap_fd(wth), &cf_stat) < 0) {
	    wtap_close(wth);
	    return FALSE;
	}

	/* size */
	filesize = cf_stat.st_size;
	g_snprintf(string_buff, PREVIEW_STR_MAX, "%" PRIu64 " bytes", filesize);
	cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_SIZE);
	SetWindowText(cur_ctrl, string_buff);

	/* type */
	g_snprintf(string_buff, PREVIEW_STR_MAX, "%s", wtap_file_type_string(wtap_file_type(wth)));
	cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FORMAT);
	SetWindowText(cur_ctrl, string_buff);

	time(&time_preview);
	while ( (wtap_read(wth, &err, &err_info, &data_offset)) ) {
	    phdr = wtap_phdr(wth);
	    cur_time = secs_usecs(phdr->ts.tv_sec, phdr->ts.tv_usec);
	    if(packet == 0) {
		start_time  = cur_time;
		stop_time = cur_time;
	    }
	    if (cur_time < start_time) {
		start_time = cur_time;
	    }
	    if (cur_time > stop_time){
		stop_time = cur_time;
	    }
	    packet++;
	    if(packet%100) {
		time(&time_current);
		if(time_current-time_preview >= PREVIEW_TIMEOUT_SECS) {
		    is_breaked = TRUE;
		    break;
		}
	    }
	}

	if(err != 0) {
	    g_snprintf(string_buff, PREVIEW_STR_MAX, "error after reading %u packets", packet);
	    cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_PACKETS);
	    SetWindowText(cur_ctrl, string_buff);
	    wtap_close(wth);
	    return TRUE;
	}

	/* packet count */
	if(is_breaked) {
	    g_snprintf(string_buff, PREVIEW_STR_MAX, "more than %u packets (preview timeout)", packet);
	} else {
	    g_snprintf(string_buff, PREVIEW_STR_MAX, "%u", packet);
	}
	cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_PACKETS);
	SetWindowText(cur_ctrl, string_buff);

	/* first packet */
	ti_time = (long)start_time;
	ti_tm = localtime( &ti_time );
	g_snprintf(string_buff, PREVIEW_STR_MAX,
		 "%04d-%02d-%02d %02d:%02d:%02d",
		 ti_tm->tm_year + 1900,
		 ti_tm->tm_mon + 1,
		 ti_tm->tm_mday,
		 ti_tm->tm_hour,
		 ti_tm->tm_min,
		 ti_tm->tm_sec);
	cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FIRST_PKT);
	SetWindowText(cur_ctrl, string_buff);

	/* elapsed time */
	elapsed_time = (unsigned int)(stop_time-start_time);
	if(elapsed_time/86400) {
	    g_snprintf(string_buff, PREVIEW_STR_MAX, "%02u days %02u:%02u:%02u",
	    elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
	} else {
	    g_snprintf(string_buff, PREVIEW_STR_MAX, "%02u:%02u:%02u",
	    elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
	}
	if(is_breaked) {
	    g_snprintf(string_buff, PREVIEW_STR_MAX, "unknown");
	}
	cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_ELAPSED);
	SetWindowText(cur_ctrl, string_buff);

	wtap_close(wth);
    }

    return TRUE;

}

static UINT CALLBACK
open_file_hook_proc(HWND of_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND      cur_ctrl, parent;
    OFNOTIFY *notify = (OFNOTIFY *) l_param;
    gchar     sel_name[MAX_PATH];

    switch(msg) {
	case WM_INITDIALOG:
	    /* XXX - Retain the filter text, and fill it in. */

	    /* Fill in our resolution values */
	    cur_ctrl = GetDlgItem(of_hwnd, EWFD_MAC_NR_CB);
	    SendMessage(cur_ctrl, BM_SETCHECK, g_resolv_flags & RESOLV_MAC, 0);
	    cur_ctrl = GetDlgItem(of_hwnd, EWFD_NET_NR_CB);
	    SendMessage(cur_ctrl, BM_SETCHECK, g_resolv_flags & RESOLV_NETWORK, 0);
	    cur_ctrl = GetDlgItem(of_hwnd, EWFD_TRANS_NR_CB);
	    SendMessage(cur_ctrl, BM_SETCHECK, g_resolv_flags & RESOLV_TRANSPORT, 0);

	    preview_set_filename(of_hwnd, NULL);
	    break;
	case WM_NOTIFY:
	    switch (notify->hdr.code) {
		case CDN_FILEOK:
		    /* XXX - Fetch the read filter */
		    /* Fetch our resolution values */
		    g_resolv_flags = prefs.name_resolve & RESOLV_CONCURRENT;
		    cur_ctrl = GetDlgItem(of_hwnd, EWFD_MAC_NR_CB);
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
			g_resolv_flags |= RESOLV_MAC;
		    cur_ctrl = GetDlgItem(of_hwnd, EWFD_NET_NR_CB);
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
			g_resolv_flags |= RESOLV_NETWORK;
		    cur_ctrl = GetDlgItem(of_hwnd, EWFD_TRANS_NR_CB);
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
			g_resolv_flags |= RESOLV_TRANSPORT;
		    break;
		case CDN_SELCHANGE:
		    /* This _almost_ works correctly.  We need to handle directory
		       selections, etc. */
		    parent = GetParent(of_hwnd);
		    CommDlg_OpenSave_GetSpec(parent, sel_name, MAX_PATH);
		    preview_set_filename(of_hwnd, sel_name);
		    break;
		default:
		    break;
	    }
	    break;
	default:
	    break;
    }
    return 0;
}

/* XXX - Copied verbatim from gtk/file_dlg.c.  Perhaps it
 * should be in wiretap instead?
 */

static gboolean
can_save_with_wiretap(int ft)
{
    /* To save a file with Wiretap, Wiretap has to handle that format,
     and its code to handle that format must be able to write a file
     with this file's encapsulation type. */
    return wtap_dump_can_open(ft) && wtap_dump_can_write_encap(ft, cfile.lnk_t);
}

/* Generate a list of the file types we can save this file as.

   "filetype" is the type it has now.

   "encap" is the encapsulation for its packets (which could be
   "unknown" or "per-packet").

   "filtered" is TRUE if we're to save only the packets that passed
   the display filter (in which case we have to save it using Wiretap)
   and FALSE if we're to save the entire file (in which case, if we're
   saving it in the type it has already, we can just copy it).

   The same applies for sel_curr, sel_all, sel_m_only, sel_m_range and sel_man_range
*/

static void
build_file_format_list(HWND sf_hwnd) {
    HWND  format_cb;
    int   ft;
    guint index;
    guint item_to_select;

    /* Default to the first supported file type, if the file's current
       type isn't supported. */
    item_to_select = 0;

    format_cb = GetDlgItem(sf_hwnd, EWFD_FILE_TYPE_COMBO);
    SendMessage(format_cb, CB_RESETCONTENT, 0, 0);

    /* Check all file types. */
    index = 0;
    for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
	if (!packet_range_process_all(&range) || ft != cfile.cd_t) {
	    /* not all unfiltered packets or a different file type.  We have to use Wiretap. */
	    if (!can_save_with_wiretap(ft))
		continue;       /* We can't. */
	}

	/* OK, we can write it out in this type. */
	SendMessage(format_cb, CB_ADDSTRING, 0, (LPARAM) (LPCTSTR) wtap_file_type_string(ft));
	SendMessage(format_cb, CB_SETITEMDATA, (LPARAM) index, (WPARAM) ft);
	if (ft == filetype) {
	    /* Default to the same format as the file, if it's supported. */
	    item_to_select = index;
	}
	index++;
    }

    SendMessage(format_cb, CB_SETCURSEL, (WPARAM) item_to_select, 0);
}

#define RANGE_TEXT_MAX 128
static UINT CALLBACK
save_as_file_hook_proc(HWND sf_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND           cur_ctrl;
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;
    int            new_filetype, index;
    gchar          range_text[RANGE_TEXT_MAX];

    switch(msg) {
	case WM_INITDIALOG:
	    /* Default to saving all packets, in the file's current format. */
	    filetype = cfile.cd_t;

	    /* init the packet range */
	    packet_range_init(&range);

	    /* Fill in the file format list */
	    build_file_format_list(sf_hwnd);

	    file_set_save_marked_sensitive(sf_hwnd);

	    /* Set the appropriate captured/displayed radio */
	    if (range.process_filtered)
		cur_ctrl = GetDlgItem(sf_hwnd, EWFD_DISPLAYED_BTN);
	    else
		cur_ctrl = GetDlgItem(sf_hwnd, EWFD_CAPTURED_BTN);
	    SendMessage(cur_ctrl, BM_SETCHECK, TRUE, 0);

	    /* dynamic values in the range frame */
	    range_update_dynamics(sf_hwnd);

	    /* Set the appropriate range radio */
	    switch(range.process) {
		case(range_process_all):
		    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_ALL_PKTS_BTN);
		    break;
		case(range_process_selected):
		    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_SEL_PKT_BTN);
		    break;
		case(range_process_marked):
		    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_MARKED_BTN);
		    break;
		case(range_process_marked_range):
		    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_FIRST_LAST_BTN);
		    break;
		case(range_process_user_range):
		    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_RANGE_BTN);
		    break;
		default:
		    g_assert_not_reached();
	    }
	    SendMessage(cur_ctrl, BM_SETCHECK, TRUE, 0);

	    break;
	case WM_COMMAND:
	    cur_ctrl = (HWND) l_param;
	    switch (w_param) {
		case (CBN_SELCHANGE << 16) | EWFD_FILE_TYPE_COMBO:
		    index = SendMessage(cur_ctrl, CB_GETCURSEL, 0, 0);
		    if (index != CB_ERR) {
			new_filetype = SendMessage(cur_ctrl, CB_GETITEMDATA, (WPARAM) index, 0);
			if (new_filetype != CB_ERR) {
			    if (filetype != new_filetype) {
				if (can_save_with_wiretap(new_filetype)) {
				    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_CAPTURED_BTN);
				    EnableWindow(cur_ctrl, TRUE);
				    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_DISPLAYED_BTN);
				    EnableWindow(cur_ctrl, TRUE);
				} else {
				    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_CAPTURED_BTN);
				    SendMessage(cur_ctrl, BM_SETCHECK, 0, 0);
				    EnableWindow(cur_ctrl, FALSE);
				    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_DISPLAYED_BTN);
				    EnableWindow(cur_ctrl, FALSE);
				}
				filetype = new_filetype;
				file_set_save_marked_sensitive(sf_hwnd);
			    }
			}
		    }
		    break;
		case (BN_CLICKED << 16) | EWFD_CAPTURED_BTN:
		case (BN_CLICKED << 16) | EWFD_DISPLAYED_BTN:
		    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_CAPTURED_BTN);
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
			range.process_filtered = FALSE;
		    else
			range.process_filtered = TRUE;
		    range_update_dynamics(sf_hwnd);
		    break;
		    range.process_filtered = TRUE;
		    range_update_dynamics(sf_hwnd);
		    break;
		case (BN_CLICKED << 16) | EWFD_ALL_PKTS_BTN:
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
			range.process = range_process_all;
			range_update_dynamics(sf_hwnd);
		    }
		    break;
		case (BN_CLICKED << 16) | EWFD_SEL_PKT_BTN:
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
			range.process = range_process_selected;
			range_update_dynamics(sf_hwnd);
		    }
		    break;
		case (BN_CLICKED << 16) | EWFD_MARKED_BTN:
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
			range.process = range_process_marked;
			range_update_dynamics(sf_hwnd);
		    }
		    break;
		case (BN_CLICKED << 16) | EWFD_FIRST_LAST_BTN:
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
			range.process = range_process_marked_range;
			range_update_dynamics(sf_hwnd);
		    }
		    break;
		case (BN_CLICKED << 16) | EWFD_RANGE_BTN:
		    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
			range.process = range_process_user_range;
			range_update_dynamics(sf_hwnd);
			cur_ctrl = GetDlgItem(sf_hwnd, EWFD_RANGE_EDIT);
			SetFocus(cur_ctrl);
		    }
		    break;
		case (EN_SETFOCUS << 16) | EWFD_RANGE_EDIT:
		    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_RANGE_BTN);
		    SendMessage(cur_ctrl, BM_CLICK, 0, 0);
		    break;
		case (EN_CHANGE << 16) | EWFD_RANGE_EDIT:
		    SendMessage(cur_ctrl, WM_GETTEXT, (WPARAM) RANGE_TEXT_MAX, (LPARAM) range_text);
		    packet_range_convert_str(&range, range_text);
		    range_update_dynamics(sf_hwnd);
		    break;
		default:
		    break;
	    }
	    break;
	default:
	    break;
    }
    return 0;
}


/*
 * Set the "Save only marked packets" controls as appropriate for
 * the current output file type and count of marked packets.
 *
 * Called when the "Save As..." dialog box is created and when either
 * the file type or the marked count changes.
 */
static void
file_set_save_marked_sensitive(HWND sf_hwnd) {
    HWND     cur_ctrl;
    gboolean enable = TRUE;

    /* We can request that only the marked packets be saved only if we
       can use Wiretap to save the file and if there *are* marked packets. */
    if (!can_save_with_wiretap(filetype) || cfile.marked_count == 0) {
	/* Force the "Save only marked packets" toggle to "false", turn
	   off the flag it controls, and update the list of types we can
	   save the file as. */
	range.process = range_process_all;
	build_file_format_list(sf_hwnd);
	enable = FALSE;
    }
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_MARKED_BTN);
    EnableWindow(cur_ctrl, enable);
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_FIRST_LAST_BTN);
    EnableWindow(cur_ctrl, enable);
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_MARKED_CAP);
    EnableWindow(cur_ctrl, enable);
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_FIRST_LAST_CAP);
    EnableWindow(cur_ctrl, enable);
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_MARKED_DISP);
    EnableWindow(cur_ctrl, enable);
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_FIRST_LAST_DISP);
    EnableWindow(cur_ctrl, enable);
}

/* For each range static control, fill in its value and enable/disable it. */
static void
range_update_dynamics(HWND sf_hwnd) {
    HWND     cur_ctrl;
    gboolean filtered_active = FALSE;
    gchar    static_val[100];
    gint     selected_num;

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_DISPLAYED_BTN);
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
	filtered_active = TRUE;

    /* RANGE_SELECT_ALL */
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_ALL_PKTS_CAP);
    EnableWindow(cur_ctrl, !filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", cfile.count);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_ALL_PKTS_DISP);
    EnableWindow(cur_ctrl, filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", range.displayed_cnt);
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_CURR */
    selected_num = (cfile.current_frame) ? cfile.current_frame->num : 0;
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_SEL_PKT_CAP);
    EnableWindow(cur_ctrl, selected_num && !filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", selected_num ? 1 : 0);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_SEL_PKT_DISP);
    EnableWindow(cur_ctrl, selected_num && filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", selected_num ? 1 : 0);
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_MARKED */
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_MARKED_BTN);
    EnableWindow(cur_ctrl, cfile.marked_count);

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_MARKED_CAP);
    EnableWindow(cur_ctrl, cfile.marked_count && !filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", cfile.marked_count);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_MARKED_DISP);
    EnableWindow(cur_ctrl, cfile.marked_count && filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", range.displayed_marked_cnt);
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_MARKED_RANGE */
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_FIRST_LAST_BTN);
    EnableWindow(cur_ctrl, range.mark_range_cnt);

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_FIRST_LAST_CAP);
    EnableWindow(cur_ctrl, range.mark_range_cnt && !filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", range.mark_range_cnt);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_FIRST_LAST_DISP);
    EnableWindow(cur_ctrl, range.displayed_mark_range_cnt && filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", range.displayed_mark_range_cnt);
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_USER */
    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_RANGE_CAP);
    EnableWindow(cur_ctrl, !filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", range.user_range_cnt);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_RANGE_DISP);
    EnableWindow(cur_ctrl, filtered_active);
    g_snprintf(static_val, sizeof(static_val), "%u", range.displayed_user_range_cnt);
    SetWindowText(cur_ctrl, static_val);
}


static UINT CALLBACK
merge_file_hook_proc(HWND mf_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND      cur_ctrl, parent;
    OFNOTIFY *notify = (OFNOTIFY *) l_param;
    gchar     sel_name[MAX_PATH];

    switch(msg) {
	case WM_INITDIALOG:
	    /* XXX - Retain the filter text, and fill it in. */

	    /* Append by default */
	    cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_PREPEND_BTN);
	    SendMessage(cur_ctrl, BM_SETCHECK, TRUE, 0);
	    merge_action = merge_append;

	    preview_set_filename(mf_hwnd, NULL);
	    break;
	case WM_NOTIFY:
	    switch (notify->hdr.code) {
		case CDN_FILEOK:
		    /* XXX - Fetch the read filter */

		    cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_CHRONO_BTN);
		    if(SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
			merge_action = merge_chrono;
		    } else {
			cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_PREPEND_BTN);
			if(SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
			    merge_action = merge_prepend;
			}
		    }

		    break;
		case CDN_SELCHANGE:
		    /* This _almost_ works correctly.  We need to handle directory
		       selections, etc. */
		    parent = GetParent(mf_hwnd);
		    CommDlg_OpenSave_GetSpec(parent, sel_name, MAX_PATH);
		    preview_set_filename(mf_hwnd, sel_name);
		    break;
		default:
		    break;
	    }
	    break;
	default:
	    break;
    }
    return 0;
}

