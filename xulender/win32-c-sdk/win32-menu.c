#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"

#include <windows.h>

#include "prefs.h"
#include "prefs-recent.h"

#include "win32-c-sdk.h"
#include "win32-globals.h"
#include "win32-menu.h"

#include "generated/ethereal-main.h"

#include "menu.h"

static void remove_menu_recent_capture_file(HWND hw_mainwin, gchar *file);
static void normalize_menu_recent(void);

static recent_count = 0;

/*
 * Public routines defined in menu.h
 */

#define MAINWIN_FILE_POS 0
#define MAINWIN_FILE_OPEN_RECENT_POS 1

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
}

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void set_menus_for_unsaved_capture_file(gboolean have_unsaved_capture_file) {
}

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void set_menus_for_capture_in_progress(gboolean capture_in_progress) {
}

/* Enable or disable menu items based on whether you have some captured
   packets. */
void set_menus_for_captured_packets(gboolean have_captured_packets) {
}

/* Enable or disable menu items based on whether a packet is selected. */
void set_menus_for_selected_packet(capture_file *cf) {
}

/* Enable or disable menu items based on whether a tree row is selected
   and and on whether a "Match Selected" can be done. */
void set_menus_for_selected_tree_row(capture_file *cf) {
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
