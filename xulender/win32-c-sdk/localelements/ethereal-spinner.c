/*
 * Spinner widget/control.
 */

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
#include "win32-util.h"

#include "ethereal-spinner.h"

static void ethereal_spinner_destroy(win32_element_t *spinner, gboolean destroy_window);
static LRESULT CALLBACK ethereal_spinner_wnd_proc(HWND, UINT, WPARAM, LPARAM);

typedef struct _spinner_data_t {
    HWND edit;
    HWND updown;
} spinner_data_t;

#define EWC_SPINNER_PANE "SpinnerPane"
#define ETHEREAL_SPINNER_DATA "_ethereal_spinner_data"

#define DEF_UPDOWN_WIDTH 15

/*
 * Create a spinner (a.k.a. spinbutton, a.k.a. up-down) control.  We create
 * a wrapper window to handle sizing and any events we may need to catch.
 */

win32_element_t *
ethereal_spinner_new(HWND hw_parent) {
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    win32_element_t *spinner;
    spinner_data_t  *sd;
    WNDCLASS         wc;
    SIZE             sz;

    g_assert(hw_parent != NULL);

    spinner = win32_element_new(NULL);

    if (! GetClassInfo(h_instance, EWC_SPINNER_PANE, &wc)) {
	wc.lpszClassName = EWC_SPINNER_PANE;
	wc.lpfnWndProc = ethereal_spinner_wnd_proc;
	wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = h_instance;
	wc.hIcon = NULL;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH) (COLOR_3DFACE+1);
	wc.lpszMenuName = NULL;

	RegisterClass(&wc);
    }

    spinner->h_wnd = CreateWindow(
	EWC_SPINNER_PANE,
	EWC_SPINNER_PANE,
	WS_CHILD | WS_VISIBLE | WS_TABSTOP,
	0, 0, 50, 25,
	hw_parent,
	(HMENU) ID_SPINNER,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(spinner->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    win32_get_text_size(spinner->h_wnd, "12345678", &sz);
    sz.cx += 4;
    sz.cy += 4;
    MoveWindow(spinner->h_wnd, 0, 0, sz.cx, sz.cy, TRUE);

    spinner->minwidth = sz.cx;
    spinner->minheight = sz.cy;
    spinner->destroy = ethereal_spinner_destroy;

    sd = g_malloc(sizeof(spinner_data_t));

    ShowWindow(spinner->h_wnd, SW_SHOW);
    UpdateWindow(spinner->h_wnd);

    /* Attach the spinner address to our HWND. */
    SetWindowLong(spinner->h_wnd, GWL_USERDATA, (LONG) spinner);
    win32_element_set_data(spinner, ETHEREAL_SPINNER_DATA, sd);

    /* Create our text entry and up-down controls */
    sd->edit = CreateWindowEx(
	WS_EX_CLIENTEDGE,
	"EDIT",
	"",
	WS_CHILD | WS_VISIBLE | ES_NUMBER,
	0, 0, sz.cx, sz.cy,
	spinner->h_wnd,
	(HMENU) 0,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);
    sd->updown = CreateUpDownControl(
	WS_VISIBLE | WS_CHILD |
	    UDS_ARROWKEYS | UDS_SETBUDDYINT | UDS_ALIGNRIGHT,
	0, 0, DIALOG2PIXELX(DEF_UPDOWN_WIDTH), sz.cy,
	spinner->h_wnd,
	0,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	sd->edit,
	100, 0, 0);

    SendMessage(sd->edit, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);
    ShowWindow(sd->edit, SW_SHOW);
    UpdateWindow(sd->edit);

    SendMessage(sd->updown, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);
    ShowWindow(sd->updown, SW_SHOW);
    UpdateWindow(sd->updown);

    return spinner;
}

/*
 * Public routines
 */

void
ethereal_spinner_set_range(win32_element_t *spinner, int low, int high) {
    spinner_data_t *sd;

    win32_element_assert(spinner);
    sd = (spinner_data_t *) win32_element_get_data(spinner, ETHEREAL_SPINNER_DATA);

    SendMessage(sd->updown, UDM_SETRANGE32, (WPARAM) low, (LPARAM) high);
}

void
ethereal_spinner_set_pos(win32_element_t *spinner, int pos) {
    spinner_data_t *sd;

    win32_element_assert(spinner);
    sd = (spinner_data_t *) win32_element_get_data(spinner, ETHEREAL_SPINNER_DATA);

    SendMessage(sd->updown, UDM_SETPOS, (WPARAM) 0, (LPARAM) pos);
}

int
ethereal_spinner_get_pos(win32_element_t *spinner) {
    spinner_data_t *sd;

    win32_element_assert(spinner);
    sd = (spinner_data_t *) win32_element_get_data(spinner, ETHEREAL_SPINNER_DATA);

    return (int) SendMessage(sd->updown, UDM_GETPOS, (WPARAM) 0, (LPARAM) 0);
}


/*
 * Private routines
 */

static void
ethereal_spinner_destroy(win32_element_t *spinner, gboolean destroy_window) {
    spinner_data_t *sd;

    win32_element_assert(spinner);

    sd = (spinner_data_t *) win32_element_get_data(spinner, ETHEREAL_SPINNER_DATA);
    g_free(sd);
}

static LRESULT CALLBACK
ethereal_spinner_wnd_proc(HWND hw_spinner, UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t *el;
    spinner_data_t *sd;

    switch (msg) {
	case WM_ENABLE:
	    el = (win32_element_t *) GetWindowLong(hw_spinner, GWL_USERDATA);
	    win32_element_assert(el);
	    sd = (spinner_data_t *) win32_element_get_data(el, ETHEREAL_SPINNER_DATA);
	    EnableWindow(sd->edit, (BOOL) w_param);
	    EnableWindow(sd->updown, (BOOL) w_param);
	    break;

	default:
	    return(DefWindowProc(hw_spinner, msg, w_param, l_param));
    }
    return 0;
}
