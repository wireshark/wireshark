
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "toolbar-util.h"

#include "ethereal-main.h"

static void toolbar_set_button_image(HWND tb_hw, gint img_off, gint button);

static gboolean toolbar_init = FALSE;

/* Offsets in the bitmap resource ID IDR_MAIN_TOOLBAR */
#define BMP_OFF_START      0
#define BMP_OFF_RELOAD     1
#define BMP_OFF_STOP       2
#define BMP_OFF_FIND_NEXT  3
#define BMP_OFF_FIND_PREV  4
#define BMP_OFF_GOTO_NUM   5
#define BMP_OFF_GOTO_FIRST 6
#define BMP_OFF_GOTO_LAST  7
#define BMP_OFF_ZOOMIN     8
#define BMP_OFF_ZOOMOUT    9
#define BMP_OFF_NORMALSZ  10
#define BMP_OFF_CAP_FILT  11
#define BMP_OFF_DISP_FILT 12
#define BMP_OFF_COLOR_DLG 13
#define BMP_OFF_CLOSE     14
#define TOOLBAR_BMP_COUNT 15

void
toolbar_new() {
    win32_element_t *toolbar = win32_identifier_get_str("main-toolbar");
    TBADDBITMAP      bmap;
    gint             eth_off, std_off;

    win32_element_assert(toolbar);

    ZeroMemory(&bmap, sizeof(bmap));
    bmap.hInst = (HINSTANCE) GetWindowLong(toolbar->h_wnd, GWL_HINSTANCE);
    bmap.nID = IDR_MAIN_TOOLBAR;
    eth_off = SendMessage(toolbar->h_wnd, TB_ADDBITMAP, (WPARAM) TOOLBAR_BMP_COUNT, (LPARAM) &bmap);

    ZeroMemory(&bmap, sizeof(bmap));
    bmap.hInst = HINST_COMMCTRL ;
    bmap.nID = IDB_STD_SMALL_COLOR;
    std_off = SendMessage(toolbar->h_wnd, TB_ADDBITMAP, (WPARAM) TOOLBAR_BMP_COUNT, (LPARAM) &bmap);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_START,
	IDB_MAIN_TOOLBAR_CAPTURE_START);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_STOP,
	IDB_MAIN_TOOLBAR_CAPTURE_STOP);

    toolbar_set_button_image(toolbar->h_wnd, std_off + STD_FILEOPEN,
	IDB_MAIN_TOOLBAR_OPEN);

    toolbar_set_button_image(toolbar->h_wnd, std_off + STD_FILESAVE,
	IDB_MAIN_TOOLBAR_SAVE);

    toolbar_set_button_image(toolbar->h_wnd, std_off + STD_FILESAVE,
	IDB_MAIN_TOOLBAR_SAVE_AS);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_CLOSE,
	IDB_MAIN_TOOLBAR_CLOSE);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_RELOAD,
	IDB_MAIN_TOOLBAR_RELOAD);

    toolbar_set_button_image(toolbar->h_wnd, std_off + STD_PRINT,
	IDB_MAIN_TOOLBAR_PRINT);

    toolbar_set_button_image(toolbar->h_wnd, std_off + STD_FIND,
	IDB_MAIN_TOOLBAR_FIND);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_FIND_NEXT,
	IDB_MAIN_TOOLBAR_FIND_NEXT);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_FIND_PREV,
	IDB_MAIN_TOOLBAR_FIND_PREV);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_GOTO_NUM,
	IDB_MAIN_TOOLBAR_GOTO_NUM);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_GOTO_FIRST,
	IDB_MAIN_TOOLBAR_GOTO_FIRST);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_GOTO_LAST,
	IDB_MAIN_TOOLBAR_GOTO_LAST);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_ZOOMIN,
	IDB_MAIN_TOOLBAR_ZOOMIN);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_ZOOMOUT,
	IDB_MAIN_TOOLBAR_ZOOMOUT);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_NORMALSZ,
	IDB_MAIN_TOOLBAR_NORMALSZ);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_CAP_FILT,
	IDB_MAIN_TOOLBAR_CAP_FILT);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_DISP_FILT,
	IDB_MAIN_TOOLBAR_DISP_FILT);

    toolbar_set_button_image(toolbar->h_wnd, eth_off + BMP_OFF_COLOR_DLG,
	IDB_MAIN_TOOLBAR_COLOR_DLG);

    toolbar_set_button_image(toolbar->h_wnd, std_off + STD_PROPERTIES,
	IDB_MAIN_TOOLBAR_PREFS);

    toolbar_set_button_image(toolbar->h_wnd, std_off + STD_HELP,
	IDB_MAIN_TOOLBAR_HELP);

    /* disable all "sensitive" items by default */
    toolbar_init = TRUE;
    set_toolbar_for_unsaved_capture_file(FALSE);
    set_toolbar_for_captured_packets(FALSE);
    set_toolbar_for_capture_file(FALSE);
#ifdef HAVE_LIBPCAP
    set_toolbar_for_capture_in_progress(FALSE);
#endif /* HAVE_LIBPCAP */
}

/* Enable or disable toolbar items based on whether you have a capture file
   you've finished reading. */
void
set_toolbar_for_capture_file(gboolean have_capture_file) {
    win32_element_t *toolbar = win32_identifier_get_str("main-toolbar");

    win32_element_assert(toolbar);

    if (toolbar_init) {
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_SAVE,
		(LPARAM) have_capture_file);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_CLOSE,
		(LPARAM) have_capture_file);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_RELOAD,
		(LPARAM) have_capture_file);
    }
}


void
set_toolbar_for_unsaved_capture_file(gboolean have_unsaved_capture_file) {
    win32_element_t *toolbar = win32_identifier_get_str("main-toolbar");

    win32_element_assert(toolbar);

    if (toolbar_init) {
	if(have_unsaved_capture_file) {
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_SAVE_AS,
		    (LPARAM) TRUE);
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_SAVE,
		    (LPARAM) FALSE);
	} else {
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_SAVE_AS,
		    (LPARAM) FALSE);
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_SAVE,
		    (LPARAM) TRUE);
	}
    }
}

/* XXX - this is a quick and dirty hack to get the current state of capturing.
 * this has to be improved, and should be reside somewhere in the capture engine. */
/* XXX - Copied from gtk/toolbar.c */
gboolean g_is_capture_in_progress = FALSE;

gboolean
is_capture_in_progress(void)
{
    return g_is_capture_in_progress;
}

/* set toolbar state "have a capture in progress" */
void set_toolbar_for_capture_in_progress(gboolean capture_in_progress) {
    win32_element_t *toolbar = win32_identifier_get_str("main-toolbar");

    win32_element_assert(toolbar);

    g_is_capture_in_progress = capture_in_progress;

    if (toolbar_init) {
#ifdef HAVE_LIBPCAP
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_CAPTURE_START,
		(LPARAM) !capture_in_progress);
	if (capture_in_progress) {
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_CAPTURE_START,
		    (LPARAM) TRUE);
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_CAPTURE_STOP,
		    (LPARAM) FALSE);
	} else {
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_CAPTURE_START,
		    (LPARAM) FALSE);
	    SendMessage(toolbar->h_wnd, TB_HIDEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_CAPTURE_STOP,
		    (LPARAM) TRUE);
	}
#endif /* HAVE_LIBPCAP */
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_OPEN,
		(LPARAM) !capture_in_progress);
    }
}

/* set toolbar state "have packets captured" */
void set_toolbar_for_captured_packets(gboolean have_captured_packets) {
    win32_element_t *toolbar = win32_identifier_get_str("main-toolbar");

    win32_element_assert(toolbar);

    if (toolbar_init) {
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_PRINT,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_FIND,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_FIND_NEXT,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_FIND_PREV,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_GOTO_NUM,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_GOTO_FIRST,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_GOTO_LAST,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_ZOOMIN,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_ZOOMOUT,
		(LPARAM) have_captured_packets);
	SendMessage(toolbar->h_wnd, TB_ENABLEBUTTON, (WPARAM) IDB_MAIN_TOOLBAR_NORMALSZ,
		(LPARAM) have_captured_packets);
    }
}


/*
 * Private routines
 */

static void
toolbar_set_button_image(HWND tb_hw, gint img_off, gint button) {
    TBBUTTONINFO     binf;

    ZeroMemory(&binf, sizeof(binf));
    binf.cbSize = sizeof(binf);
    binf.dwMask = TBIF_IMAGE;
    binf.iImage = img_off;
    SendMessage(tb_hw, TB_SETBUTTONINFO, (WPARAM) button, (LPARAM) &binf);
}