/*
 * Combobox widget/control.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"

#include "ethereal-combobox.h"

/* XXX - We need to subclass our own window proc so that we can catch
 * the "return" key.
 * Or maybe we'll just catch it in win32_box_wnd_proc() like everything
 * else.
 */

/*
 * Create a ComboBox control.
 */

win32_element_t *
ethereal_combobox_new(HWND hw_parent) {
    win32_element_t *combobox;
    RECT wr;

    g_assert(hw_parent != NULL);

    combobox = win32_element_new(NULL);

    combobox->h_wnd = CreateWindow(
	"COMBOBOX",
	"ComboBox",
	WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWN |
	    CBS_AUTOHSCROLL,
	0, 0, 50, 50,
	hw_parent,
	(HMENU) ID_COMBOBOX,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(combobox->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    GetWindowRect(combobox->h_wnd, &wr);
    combobox->minwidth = wr.right - wr.left;
    combobox->minheight = wr.bottom - wr.top;

    ShowWindow(combobox->h_wnd, SW_SHOW);
    UpdateWindow(combobox->h_wnd);

    /* Attach the combobox address to our HWND. */
    SetWindowLong(combobox->h_wnd, GWL_USERDATA, (LONG) combobox);

    return combobox;
}
