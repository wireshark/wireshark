
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "win32-c-sdk.h"


static LRESULT CALLBACK win32_toolbox_wnd_proc(HWND hw_toolbox, UINT msg, WPARAM w_param, LPARAM l_param);

#define WIN32_TOOLBOX_PANE "ToolboxPane"

win32_element_t *
win32_toolbox_new(HWND hw_toolbox, HWND hw_parent) {
    win32_element_t *toolbox;
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    WNDCLASS         wc;

    toolbox = win32_element_new(hw_toolbox);

    if (toolbox->h_wnd == NULL) {	/* We have to create our own window */
	g_assert(hw_parent != NULL);

	/* XXX - Should we move this into its own init routine? */
	if (! GetClassInfo(h_instance, WIN32_TOOLBOX_PANE, &wc)) {
	    wc.lpszClassName = WIN32_TOOLBOX_PANE;
	    wc.lpfnWndProc = win32_toolbox_wnd_proc;
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

	toolbox->h_wnd = CreateWindow(
	    WIN32_TOOLBOX_PANE,
	    WIN32_TOOLBOX_PANE,
	    WS_CHILD | WS_VISIBLE,
	    0, 0, 0, 0,
	    hw_parent,
	    NULL,
	    h_instance,
	    (LPSTR) NULL);

	ShowWindow(toolbox->h_wnd, SW_SHOW);
	UpdateWindow(toolbox->h_wnd);
    }

//    toolbox->orient = BOX_ORIENT_VERTICAL;

    /* Attach the box address to our HWND. */
    SetWindowLong(toolbox->h_wnd, GWL_USERDATA, (LONG) toolbox);

    return toolbox;
}


/*
 * Private routines
 */

static LRESULT CALLBACK
win32_toolbox_wnd_proc(HWND hw_toolbox, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND hw_top = hw_toolbox, hw_parent;

    switch (msg) {
	case WM_COMMAND:
	    if (HIWORD(w_param) == 0) {
		/* We have a "menu" notification sent by one of our buttons;
		 * pass it up to the top-level window */
		while (hw_parent = GetParent(hw_top))
		    hw_top = hw_parent;
		SendMessage(hw_top, msg, w_param, l_param);
	    } else {
		win32_element_handle_wm_command(msg, w_param, l_param);
	    }
	    break;
	default:
	    return(DefWindowProc(hw_toolbox, msg, w_param, l_param));
	    break;
    }
    return 0;
}


