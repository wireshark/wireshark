#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"

#include <windows.h>

#include <epan/epan_dissect.h>
#include <epan/addr_resolv.h>

#include <epan/ipproto.h>

#include <epan/prefs.h>
#include "prefs-recent.h"

#include "win32-c-sdk.h"
#include "win32-globals.h"
#include "win32-menu.h"
#include "win32-statusbar.h"
#include "toolbar-util.h"

#include "ethereal-main.h"

#include "menu.h"

static void remove_menu_recent_capture_file(HWND hw_mainwin, gchar *file);
static void normalize_menu_recent(void);

static recent_count = 0;

/*
 * Public routines defined in menu.h
 */

#define MAINWIN_FILE_POS       0
#define MAINWIN_EDIT_POS       1
#define MAINWIN_VIEW_POS       2
#define MAINWIN_GO_POS         3
#define MAINWIN_CAPTURE_POS    4
#define MAINWIN_ANALYZE_POS    5
#define MAINWIN_STATISTICS_POS 6

#define MAINWIN_FILE_OPEN_RECENT_POS 1
#define MAINWIN_EDIT_TIME_REF_POS 4
#define MAINWIN_VIEW_TIMEDF_POS 8
#define MAINWIN_VIEW_NAMERES_POS 9
#define MAINWIN_ANALYZE_AAF_POS 1
#define MAINWIN_ANALYZE_PAF_POS 2

/* Initialize our menus (should be called at program startup) */
void
menus_init(HWND hw_mainwin) {
//    merge_all_tap_menus(tap_menu_tree_root);

    /* Initialize enabled/disabled state of menu items */
    set_menus_for_unsaved_capture_file(FALSE);
    set_menus_for_capture_file(FALSE);
#if 0
    /* Un-#if this when we actually implement Cut/Copy/Paste.
       Then make sure you enable them when they can be done. */
//    set_menu_sensitivity(main_menu_factory, "/Edit/Cut", FALSE);
//    set_menu_sensitivity(main_menu_factory, "/Edit/Copy", FALSE);
//    set_menu_sensitivity(main_menu_factory, "/Edit/Paste", FALSE);
#endif

    set_menus_for_captured_packets(FALSE);
    set_menus_for_selected_packet(&cfile);
    set_menus_for_selected_tree_row(&cfile);

    menu_name_resolution_changed(hw_mainwin);

    /* XXX - Do we need to clear the "open recent" list?  The GTK code does. */
}

/* Add a new recent capture filename to the "Recent Files" submenu
   (duplicates will be ignored) */
void
add_menu_recent_capture_file(gchar *file) {
    HMENU        mainwin_menu, file_menu, or_menu;
    MENUITEMINFO mii;
    int          mi_count, i;
    gboolean     add_item = TRUE;
    gchar        name_buf[MAX_VAL_LEN], *dup_file;

    dup_file = g_strdup(file);
    g_strdelimit(dup_file, "/", '\\');
    if (strlen(file) > MAX_VAL_LEN - 1) return;

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    or_menu = GetSubMenu(file_menu, MAINWIN_FILE_OPEN_RECENT_POS);
    if (or_menu) {
	mi_count = GetMenuItemCount(or_menu) - 2; /* Separator + "Clear" */
	for (i = 0; i < mi_count; i++) {
	    ZeroMemory(&mii, sizeof(mii));
	    mii.cbSize = sizeof(mii);
	    mii.fMask = MIIM_TYPE;
	    mii.fType = MFT_STRING;
	    mii.dwTypeData = name_buf;
	    mii.cch = MAX_VAL_LEN;
	    GetMenuItemInfo(or_menu, i, TRUE, &mii);
	    if (strcmp(dup_file, name_buf) == 0)
		add_item = FALSE;
	}
	if (add_item) {
	    ZeroMemory(&mii, sizeof(mii));
	    mii.cbSize = sizeof(mii);
	    mii.fMask = MIIM_TYPE;
	    mii.fType = MFT_STRING;
	    mii.dwTypeData = dup_file;
	    mii.cch = strlen(dup_file);
	    InsertMenuItem(or_menu, 0, TRUE, &mii);

	    /* Renumber and trim off any excess */
	    normalize_menu_recent();
	}
    }
    g_free(dup_file);
}

/* A recent file menu item has been selected */
void
open_menu_recent_capture_file(HWND hw_mainwin, guint menu_id) {
    HMENU        mainwin_menu, file_menu, or_menu;
    MENUITEMINFO mii;
    gchar        name_buf[MAX_VAL_LEN];
    int          err;

    mainwin_menu = GetMenu(hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    or_menu = GetSubMenu(file_menu, MAINWIN_FILE_OPEN_RECENT_POS);
    if (or_menu) {
	ZeroMemory(&mii, sizeof(mii));
	mii.cbSize = sizeof(mii);
	mii.fMask = MIIM_TYPE;
	mii.fType = MFT_STRING;
	mii.wID = menu_id;
	mii.dwTypeData = name_buf;
	mii.cch = MAX_VAL_LEN;
	if (GetMenuItemInfo(or_menu, menu_id, FALSE, &mii)) {
	    if ((err = cf_open(name_buf, FALSE, &cfile)) == 0) {
		remove_menu_recent_capture_file(hw_mainwin, name_buf);
		add_menu_recent_capture_file(name_buf);
		cf_read(&cfile);
	    } else {
		remove_menu_recent_capture_file(hw_mainwin, name_buf);
	    }
	}
    }
}

/* Clear out the recent files list */
void
clear_menu_recent(HWND hw_mainwin) {
    HMENU mainwin_menu, file_menu, or_menu;

    mainwin_menu = GetMenu(hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    or_menu = GetSubMenu(file_menu, MAINWIN_FILE_OPEN_RECENT_POS);
    if (or_menu) {
	while (GetMenuItemCount(or_menu) > 2) {
	    RemoveMenu(or_menu, 0, MF_BYPOSITION);
	}
    }
}

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading. */
void set_menus_for_capture_file(gboolean have_capture_file) {
    HMENU mainwin_menu, file_menu, view_menu;
    UINT  enable = have_capture_file ? MF_ENABLED : MF_GRAYED;

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);

    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_OPEN, enable | MF_BYCOMMAND);
    EnableMenuItem(file_menu, MAINWIN_FILE_OPEN_RECENT_POS, enable | MF_BYPOSITION);
    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_MERGE, enable | MF_BYCOMMAND);
    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_CLOSE, enable | MF_BYCOMMAND);
    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_SAVE_AS, enable | MF_BYCOMMAND);
    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_EXPORT_FILE, enable | MF_BYCOMMAND);
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_RELOAD, enable | MF_BYCOMMAND);

    set_toolbar_for_capture_file(have_capture_file);
    packets_bar_update();
}

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void set_menus_for_unsaved_capture_file(gboolean have_unsaved_capture_file) {
    HMENU mainwin_menu, file_menu;
    UINT  enable = have_unsaved_capture_file ? MF_ENABLED : MF_GRAYED;

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);

    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_SAVE, enable | MF_BYCOMMAND);
    set_toolbar_for_unsaved_capture_file(have_unsaved_capture_file);
}

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void set_menus_for_capture_in_progress(gboolean capture_in_progress) {
    HMENU mainwin_menu, file_menu, capture_menu;
    UINT  enable = capture_in_progress ? MF_ENABLED : MF_GRAYED;
    UINT  disable = capture_in_progress ? MF_GRAYED : MF_ENABLED;

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    capture_menu = GetSubMenu(mainwin_menu, MAINWIN_CAPTURE_POS);

    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_OPEN, disable | MF_BYCOMMAND);
    EnableMenuItem(file_menu, MAINWIN_FILE_OPEN_RECENT_POS, disable | MF_BYPOSITION);
#ifdef HAVE_LIBPCAP
    EnableMenuItem(capture_menu, IDM_ETHEREAL_MAIN_CAPTURE_START, disable | MF_BYCOMMAND);
    EnableMenuItem(capture_menu, IDM_ETHEREAL_MAIN_CAPTURE_STOP, enable | MF_BYCOMMAND);
#endif /* HAVE_LIBPCAP */

    set_toolbar_for_capture_in_progress(capture_in_progress);

//    set_capture_if_dialog_for_capture_in_progress(capture_in_progress);
}

/* Enable or disable menu items based on whether you have some captured
   packets. */
void set_menus_for_captured_packets(gboolean have_captured_packets) {
    HMENU mainwin_menu, file_menu, edit_menu, view_menu, go_menu, statistics_menu;
    UINT  enable = have_captured_packets ? MF_ENABLED : MF_GRAYED;

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    edit_menu = GetSubMenu(mainwin_menu, MAINWIN_EDIT_POS);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);
    go_menu = GetSubMenu(mainwin_menu, MAINWIN_GO_POS);
    statistics_menu = GetSubMenu(mainwin_menu, MAINWIN_STATISTICS_POS);

    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_PRINT, enable | MF_BYCOMMAND);
    // XXX - Packet list menu "print"
    EnableMenuItem(edit_menu, IDM_ETHEREAL_MAIN_EDIT_FIND_PACKET, enable | MF_BYCOMMAND);
    EnableMenuItem(edit_menu, IDM_ETHEREAL_MAIN_EDIT_FIND_NEXT, enable | MF_BYCOMMAND);
    EnableMenuItem(edit_menu, IDM_ETHEREAL_MAIN_EDIT_FIND_PREVIOUS, enable | MF_BYCOMMAND);
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_ZOOMIN, enable | MF_BYCOMMAND);
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_ZOOMOUT, enable | MF_BYCOMMAND);
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_NORMALSZ, enable | MF_BYCOMMAND);
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_COLORING, enable | MF_BYCOMMAND);
    // XXX - Packet list menu "coloring rules"
    EnableMenuItem(go_menu, IDM_ETHEREAL_MAIN_GO_TOPACKET, enable | MF_BYCOMMAND);
    EnableMenuItem(go_menu, IDM_ETHEREAL_MAIN_GO_FIRST, enable | MF_BYCOMMAND);
    EnableMenuItem(go_menu, IDM_ETHEREAL_MAIN_GO_LAST, enable | MF_BYCOMMAND);
    EnableMenuItem(statistics_menu, IDM_ETHEREAL_MAIN_STATS_SUMMARY, enable | MF_BYCOMMAND);
    EnableMenuItem(statistics_menu, IDM_ETHEREAL_MAIN_STATS_PROTOHIER, enable | MF_BYCOMMAND);

//    walk_menu_tree_for_captured_packets(tap_menu_tree_root,
//	have_captured_packets);
    set_toolbar_for_captured_packets(have_captured_packets);
    packets_bar_update();
}

/*
 * This routine indicates whether we'd actually have any pages in the
 * notebook in a "Decode As" dialog box; if there wouldn't be, we
 * inactivate the menu item for "Decode As".
 */
/* XXX - Copied verbatim from gtk/decode_as_dlg.c */
static gboolean
decode_as_ok(void)
{
    return cfile.edt->pi.ethertype || cfile.edt->pi.ipproto ||
	cfile.edt->pi.ptype == PT_TCP || cfile.edt->pi.ptype == PT_UDP;
}


/* Enable or disable menu items based on whether a packet is selected. */
void set_menus_for_selected_packet(capture_file *cf) {
    HMENU mainwin_menu, edit_menu, view_menu, analyze_menu;
    UINT  enable = (cf->current_frame != NULL) ? MF_ENABLED : MF_GRAYED;

    mainwin_menu = GetMenu(g_hw_mainwin);
    edit_menu = GetSubMenu(mainwin_menu, MAINWIN_EDIT_POS);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);
    analyze_menu = GetSubMenu(mainwin_menu, MAINWIN_ANALYZE_POS);

    EnableMenuItem(edit_menu, IDM_ETHEREAL_MAIN_EDIT_MARK_PACKET, enable | MF_BYCOMMAND);
    // XXX - Packet list menu "mark packet"
    EnableMenuItem(edit_menu, MAINWIN_EDIT_TIME_REF_POS, enable | MF_BYPOSITION);
    // XXX - Packet list menu "time reference"
    EnableMenuItem(edit_menu, IDM_ETHEREAL_MAIN_EDIT_MARK_ALL_PACKETS, enable | MF_BYCOMMAND);
    EnableMenuItem(edit_menu, IDM_ETHEREAL_MAIN_EDIT_UNMARK_ALL_PACKETS, enable | MF_BYCOMMAND);
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_COLLAPSEALL, enable | MF_BYCOMMAND);
    // XXX - Tree view menu "collapse all"
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_EXPANDALL, enable | MF_BYCOMMAND);
    // XXX - Tree view menu "expand all"
    EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_NEWWINDOW, enable | MF_BYCOMMAND);
    // XXX - Packet list menu "new window", "apply as filter", "prepare filter"

    enable = (cf->current_frame != NULL && cf->edt->pi.ipproto == IP_PROTO_TCP) ? MF_ENABLED : MF_GRAYED;
    EnableMenuItem(analyze_menu, IDM_ETHEREAL_MAIN_ANALYZE_FOLLOW, enable | MF_BYCOMMAND);

    enable = (cf->current_frame != NULL && decode_as_ok()) ? MF_ENABLED : MF_GRAYED;
    EnableMenuItem(analyze_menu, IDM_ETHEREAL_MAIN_ANALYZE_DECODEAS, enable | MF_BYCOMMAND);

    enable = (cf->current_frame != NULL && (g_resolv_flags & RESOLV_ALL_ADDRS) != RESOLV_ALL_ADDRS) ? MF_ENABLED : MF_GRAYED;
    EnableMenuItem(analyze_menu, IDM_ETHEREAL_MAIN_VIEW_NAMERES_RESOLVE, enable | MF_BYCOMMAND);

//    walk_menu_tree_for_selected_packet(tap_menu_tree_root, cf->current_frame,
//	cf->edt);
    packets_bar_update();

}

/* Enable or disable menu items based on whether a tree row is selected
   and and on whether a "Match Selected" can be done. */
void set_menus_for_selected_tree_row(capture_file *cf) {
    HMENU              mainwin_menu, file_menu, view_menu, go_menu, analyze_menu;
    UINT               enable = (cf->finfo_selected != NULL) ? MF_ENABLED : MF_GRAYED;
    header_field_info *hfinfo;
    gboolean           properties;

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);
    go_menu = GetSubMenu(mainwin_menu, MAINWIN_GO_POS);
    analyze_menu = GetSubMenu(mainwin_menu, MAINWIN_ANALYZE_POS);

    EnableMenuItem(file_menu, IDM_ETHEREAL_MAIN_EXPORT_SELECTED, enable | MF_BYCOMMAND);
    // XXX - Tree view & hex view "export selected"

    if (cf->finfo_selected != NULL) {
	hfinfo = cf->finfo_selected->hfinfo;
	if (hfinfo->parent == -1) {
	    properties = prefs_is_registered_protocol(hfinfo->abbrev);
	} else {
	    properties = prefs_is_registered_protocol(proto_registrar_get_abbrev(hfinfo->parent));
	}
	enable = (hfinfo->type == FT_FRAMENUM) ? MF_ENABLED : MF_GRAYED;
	EnableMenuItem(go_menu, IDM_ETHEREAL_MAIN_GO_CORRESPONDING, enable | MF_BYCOMMAND);
	// XXX - Tree view "go to corresponding"

	enable = proto_can_match_selected(cf->finfo_selected, cf->edt) ? MF_ENABLED : MF_GRAYED;
	EnableMenuItem(analyze_menu, MAINWIN_ANALYZE_AAF_POS, enable | MF_BYPOSITION);
	EnableMenuItem(analyze_menu, MAINWIN_ANALYZE_PAF_POS, enable | MF_BYPOSITION);
	// XXX - Tree view "Apply as" & "Prepare as"
	// XXX - Tree view "Protocol Prefs"

	enable = (cf->finfo_selected->tree_type != -1) ? MF_ENABLED : MF_GRAYED;
	EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_EXPANDTREE, enable | MF_BYCOMMAND);
	// XXX - Tree view "expand tree"
    } else {
	EnableMenuItem(go_menu, IDM_ETHEREAL_MAIN_GO_CORRESPONDING, MF_GRAYED | MF_BYCOMMAND);
	// XXX - Tree view "go to corresponding"
	EnableMenuItem(analyze_menu, MAINWIN_ANALYZE_AAF_POS, MF_GRAYED | MF_BYPOSITION);
	EnableMenuItem(analyze_menu, MAINWIN_ANALYZE_PAF_POS, MF_GRAYED | MF_BYPOSITION);
	// XXX - Tree view "Apply as" & "Prepare as"
	// XXX - Tree view "Protocol Prefs"
	EnableMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_EXPANDTREE, MF_GRAYED | MF_BYCOMMAND);
	// XXX - Tree view "expand tree"
    }

//    walk_menu_tree_for_selected_tree_row(tap_menu_tree_root, cf->finfo_selected);
}

/* write all capture filenames of the menu to the user's recent file */
void
menu_recent_file_write_all(FILE *rf) {
    HMENU            mainwin_menu, file_menu, or_menu;
    MENUITEMINFO     mii;
    int              mi_count, i;
    gchar            name_buf[MAX_VAL_LEN];

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    or_menu = GetSubMenu(file_menu, MAINWIN_FILE_OPEN_RECENT_POS);
    if (or_menu) {
	mi_count = GetMenuItemCount(or_menu) - 3;
	for (i = mi_count; i >= 0; i--) {
	    ZeroMemory(&mii, sizeof(mii));
	    mii.cbSize = sizeof(mii);
	    mii.fMask = MIIM_TYPE;
	    mii.fType = MFT_STRING;
	    mii.dwTypeData = name_buf;
	    mii.cch = MAX_VAL_LEN;
	    if (GetMenuItemInfo(or_menu, i, TRUE, &mii)) {
		fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", name_buf);
	    }
	}
    }
}

void
menu_name_resolution_changed(HWND hw_mainwin) {
    HMENU        mainwin_menu, view_menu, nr_menu;

    mainwin_menu = GetMenu(hw_mainwin);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);
    nr_menu = GetSubMenu(view_menu, MAINWIN_VIEW_NAMERES_POS);

    if (nr_menu) {
	CheckMenuItem(nr_menu, IDM_ETHEREAL_MAIN_VIEW_NAMERES_MAC,
		g_resolv_flags & RESOLV_MAC ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(nr_menu, IDM_ETHEREAL_MAIN_VIEW_NAMERES_NETWORK,
		g_resolv_flags & RESOLV_NETWORK ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(nr_menu, IDM_ETHEREAL_MAIN_VIEW_NAMERES_TRANSPORT,
		g_resolv_flags & RESOLV_TRANSPORT ? MF_CHECKED : MF_UNCHECKED);
    }
}

void
menu_toggle_name_resolution(HWND hw_mainwin, guint menu_id) {
    guint32 resolv_flag;

    switch (menu_id) {
	case IDM_ETHEREAL_MAIN_VIEW_NAMERES_MAC:
	    resolv_flag = RESOLV_MAC;
	    break;
	case IDM_ETHEREAL_MAIN_VIEW_NAMERES_NETWORK:
	    resolv_flag = RESOLV_NETWORK;
	    break;
	case IDM_ETHEREAL_MAIN_VIEW_NAMERES_TRANSPORT:
	    resolv_flag = RESOLV_TRANSPORT;
	    break;
	default:
	    g_assert_not_reached();
    }

    if (g_resolv_flags & resolv_flag) {
	g_resolv_flags &= ~resolv_flag;
    } else {
	g_resolv_flags |= resolv_flag;
    }
    menu_name_resolution_changed(hw_mainwin);
}

/* The recent file has been read, update the menu correspondingly */
void
menu_update_view_items(void) {
    HMENU mainwin_menu, view_menu, tf_menu;
    UINT  check_item;

    mainwin_menu = GetMenu(g_hw_mainwin);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);
    tf_menu = GetSubMenu(view_menu, MAINWIN_VIEW_TIMEDF_POS);

    if (view_menu) {
	CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_MAIN_TOOLBAR,
		recent.main_toolbar_show ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_FILTER_TOOLBAR,
		recent.filter_toolbar_show ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_STATUSBAR,
		recent.statusbar_show ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_PACKET_LIST,
		recent.packet_list_show ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_PACKET_DETAILS,
		recent.tree_view_show ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_PACKET_BYTES,
		recent.byte_view_show ? MF_CHECKED : MF_UNCHECKED);
    }

    menu_name_resolution_changed(g_hw_mainwin);

#ifdef HAVE_LIBPCAP
    CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_AUTOSCROLL,
	    auto_scroll_live ? MF_CHECKED : MF_UNCHECKED);
#endif

//    main_widgets_rearrange();

    /* don't change the time format, if we had a command line value */
    if (get_timestamp_setting() != TS_NOT_SET) {
	recent.gui_time_format = get_timestamp_setting();
    }

    if (tf_menu) {
	switch(recent.gui_time_format) {
	    case(TS_ABSOLUTE):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_TOD;
		break;
	    case(TS_ABSOLUTE_WITH_DATE):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_DATOD;
		break;
	    case(TS_RELATIVE):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSBEG;
		break;
	    case(TS_DELTA):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSPREV;
		break;
	    default:
		g_assert_not_reached();
	}
	CheckMenuRadioItem(tf_menu, IDM_ETHEREAL_MAIN_VIEW_TIMEDF_TOD,
		IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSPREV, check_item, MF_BYCOMMAND);
	recent.gui_time_format = -1;
    }
}

void
menu_toggle_timestamps(ts_type ts_t) {
    HMENU mainwin_menu, view_menu, tf_menu;
    UINT  check_item;

    mainwin_menu = GetMenu(g_hw_mainwin);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);
    tf_menu = GetSubMenu(view_menu, MAINWIN_VIEW_TIMEDF_POS);

    if (tf_menu) {
	switch(ts_t) {
	    case(TS_ABSOLUTE):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_TOD;
		break;
	    case(TS_ABSOLUTE_WITH_DATE):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_DATOD;
		break;
	    case(TS_RELATIVE):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSBEG;
		break;
	    case(TS_DELTA):
		check_item = IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSPREV;
		break;
	    default:
		g_assert_not_reached();
	}
	CheckMenuRadioItem(tf_menu, IDM_ETHEREAL_MAIN_VIEW_TIMEDF_TOD,
		IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSPREV, check_item, MF_BYCOMMAND);
    }
    if (recent.gui_time_format != ts_t) {
	set_timestamp_setting(ts_t);
	recent.gui_time_format = ts_t;
	change_time_formats(&cfile);
    }
}

/* XXX - We need to synchronize this with the capture and prefs dialogs.
 *       This needs to be done in the GTK+ code as well. */
#ifdef HAVE_LIBPCAP
void
menu_toggle_auto_scroll() {
    HMENU mainwin_menu, view_menu;

    mainwin_menu = GetMenu(g_hw_mainwin);
    view_menu = GetSubMenu(mainwin_menu, MAINWIN_VIEW_POS);

    auto_scroll_live = ! auto_scroll_live;
    if (view_menu) {
	CheckMenuItem(view_menu, IDM_ETHEREAL_MAIN_VIEW_AUTOSCROLL,
		auto_scroll_live ? MF_CHECKED : MF_UNCHECKED);
    }
}
#endif

/*
 * Private routines
 */

/* Remove a capture file from the list */
static void
remove_menu_recent_capture_file(HWND hw_mainwin, gchar *file) {
    HMENU            mainwin_menu, file_menu, or_menu;
    MENUITEMINFO     mii;
    int              mi_count, i;
    gboolean         add_item = TRUE;
    gchar            name_buf[MAX_VAL_LEN], *dup_file;

    dup_file = g_strdup(file);
    g_strdelimit(dup_file, "/", '\\');
    if (strlen(file) > MAX_VAL_LEN - 1) return;

    mainwin_menu = GetMenu(hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    or_menu = GetSubMenu(file_menu, MAINWIN_FILE_OPEN_RECENT_POS);
    if (or_menu) {
	mi_count = GetMenuItemCount(or_menu) - 2; /* Separator + "Clear" */
	for (i = 0; i < mi_count; i++) {
	    ZeroMemory(&mii, sizeof(mii));
	    mii.cbSize = sizeof(mii);
	    mii.fMask = MIIM_TYPE;
	    mii.fType = MFT_STRING;
	    mii.dwTypeData = name_buf;
	    mii.cch = MAX_VAL_LEN;
	    GetMenuItemInfo(or_menu, i, TRUE, &mii);
	    if (strcmp(dup_file, name_buf) == 0) {
		RemoveMenu(or_menu, i, MF_BYPOSITION);
		break;
	    }
	}
    }

    g_free(dup_file);
}

/* Trim off any excess menu items and renumber */
static void
normalize_menu_recent(void) {
    HMENU            mainwin_menu, file_menu, or_menu;
    MENUITEMINFO     mii;
    int              mi_count, i;
    int              max_count = prefs.gui_recent_files_count_max + 2; /* Separator + "Clear" */

    mainwin_menu = GetMenu(g_hw_mainwin);
    file_menu = GetSubMenu(mainwin_menu, MAINWIN_FILE_POS);
    or_menu = GetSubMenu(file_menu, MAINWIN_FILE_OPEN_RECENT_POS);
    if (or_menu) {
	while ((mi_count = GetMenuItemCount(or_menu)) > max_count) {
	    RemoveMenu(or_menu, mi_count - 2, MF_BYPOSITION);
	}
	mi_count = GetMenuItemCount(or_menu) - 2;
	for (i = 0; i < mi_count; i++) {
	    ZeroMemory(&mii, sizeof(mii));
	    mii.cbSize = sizeof(mii);
	    mii.fMask = MIIM_ID;
	    mii.wID = IDM_RECENT_FILE_START + i;
	    SetMenuItemInfo(or_menu, i, TRUE, &mii);
	}
    }
}

