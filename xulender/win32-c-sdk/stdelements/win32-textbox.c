
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <richedit.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"

static void win32_textbox_destroy(win32_element_t *textbox, gboolean destroy_window);
static void win32_textbox_minimum_size(win32_element_t *tree);

typedef struct _textbox_data_t {
    gint rows;
} textbox_data_t;

#define WIN32_TEXTBOX_DATA "_win32_textbox_data"

/*
 * Create a textbox control.
 */

win32_element_t *
win32_textbox_new(HWND hw_parent, gboolean multiline) {
    win32_element_t *textbox;
    textbox_data_t  *td;
    SIZE             sz;
    LONG             extra_style = 0;

    if (multiline) {
	extra_style = ES_MULTILINE;
    }

    g_assert(hw_parent != NULL);

    textbox = win32_element_new(NULL);

    textbox->h_wnd = CreateWindowEx(
	WS_EX_CLIENTEDGE,
	RICHEDIT_CLASS,
	NULL,
	WS_CHILD | WS_VISIBLE |
	ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_WANTRETURN | extra_style,
	0, 0, 0, 0,
	hw_parent,
	(HMENU) ID_TEXTBOX,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(textbox->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    win32_get_text_size(textbox->h_wnd, "ABCabc", &sz);
    sz.cx += 4;
    sz.cy += 4;
    MoveWindow(textbox->h_wnd, 0, 0, sz.cx, sz.cy, TRUE);

    textbox->minwidth = sz.cx;
    textbox->minheight = sz.cy;

    ShowWindow(textbox->h_wnd, SW_SHOW);
    UpdateWindow(textbox->h_wnd);

    /* Attach the textbox address to our HWND. */
    SetWindowLong(textbox->h_wnd, GWL_USERDATA, (LONG) textbox);

    td = g_malloc(sizeof(textbox_data_t));
    td->rows = 1;

    win32_element_set_data(textbox, WIN32_TEXTBOX_DATA, td);

    return textbox;
}

/*
 * Public functions
 */

void
win32_textbox_set_text(win32_element_t *textbox, gchar *text) {
    win32_element_assert(textbox);

    if (text == NULL)
	SetWindowText(textbox->h_wnd, "");

    SetWindowText(textbox->h_wnd, text);
}

gchar *
win32_textbox_get_text(win32_element_t *textbox) {
    int len;
    gchar *text;

    win32_element_assert(textbox);

    len = GetWindowTextLength(textbox->h_wnd) + 1;
    text = g_malloc(len);
    GetWindowText(textbox->h_wnd, text, len);
    return text;
}

/*
 * Set the number of rows displayed.
 */
void win32_textbox_set_row_count(win32_element_t *textbox, gint rows) {
    textbox_data_t *td;

    win32_element_assert(textbox);
    td = (textbox_data_t *) win32_element_get_data(textbox, WIN32_TEXTBOX_DATA);

    td->rows = rows;
    win32_textbox_minimum_size(textbox);
}

/*
 * Get the current character formatting.  If get_sel is TRUE, gets
 * the formatting of the current selection.  Otherwise the default
 * format is used.
 */
void win32_textbox_get_char_format(win32_element_t *textbox, CHARFORMAT *fmt, gboolean get_sel) {
    win32_element_assert(textbox);

    SendMessage(textbox->h_wnd, EM_GETCHARFORMAT, (WPARAM) (BOOL) get_sel,
	(LPARAM) (CHARFORMAT FAR *) fmt);
}

/*
 * Insert text at the specified position.  If pos is -1, the text is appended.
 * If char_fmt is NULL, the default formatting is used.
 */
void win32_textbox_insert(win32_element_t *textbox, gchar *text, gint pos, CHARFORMAT *char_fmt) {

    win32_element_assert(textbox);

    SendMessage(textbox->h_wnd, EM_SETSEL, (WPARAM) (INT) pos, (LPARAM) (INT) pos);
    if (char_fmt) {
	SendMessage(textbox->h_wnd, EM_SETCHARFORMAT, (WPARAM) (UINT) SCF_SELECTION,
	    (LPARAM) (CHARFORMAT FAR *) char_fmt);
    }
    SendMessage(textbox->h_wnd, EM_REPLACESEL, (WPARAM) (BOOL) FALSE, (LPARAM) (LPCTSTR) text);
}

/*
 * Private routines
 */

static void
win32_textbox_destroy(win32_element_t *textbox, gboolean destroy_window) {
    textbox_data_t *td;

    win32_element_assert(textbox);
    td = (textbox_data_t *) win32_element_get_data(textbox, WIN32_TEXTBOX_DATA);

    g_free(td);
}

static void
win32_textbox_minimum_size(win32_element_t *textbox) {
    textbox_data_t *td;
    RECT            tr;
    HDC             hdc;
    TEXTMETRIC      tm;
    int             height;

    win32_element_assert(textbox);
    td = (textbox_data_t *) win32_element_get_data(textbox, WIN32_TEXTBOX_DATA);

    SendMessage(textbox->h_wnd, EM_GETRECT, 0, (LPARAM) &tr);

    hdc = GetDC(textbox->h_wnd);
    GetTextMetrics(hdc, &tm);
    ReleaseDC(textbox->h_wnd, hdc);

    height = (tm.tmHeight + tm.tmExternalLeading) * td->rows;
    if (height > tr.bottom - tr.top) {
	if (height > textbox->minheight) {
	    textbox->minheight = height;
	}
	win32_element_resize(textbox, win32_element_get_width(textbox), height);
    }
}
