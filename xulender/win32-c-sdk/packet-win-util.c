
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "epan/epan_dissect.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "packet-win-util.h"

#include "ethereal-byteview.h"
#include "ethereal-treeview.h"

#include "packet-window.h"


/* Data structure holding information about a packet-detail window. */
/* Copied and modified from gtk/packet_win.c */
typedef struct _packet_win_data {
    frame_data *frame;         /* The frame being displayed */
    union wtap_pseudo_header pseudo_header; /* Pseudo-header for packet */
    guint8     *pd;            /* Data for packet */
    field_info *finfo_selected;
    epan_dissect_t  *edt;
} packet_win_data_t;

static LRESULT CALLBACK packet_window_wnd_proc(HWND hw_pkt, UINT msg, WPARAM w_param, LPARAM l_param);

#define PACKET_WINDOW_DATA "_packet_window_data"

void
packet_window_init(HWND hw_parent) {
    HINSTANCE          h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    WNDCLASS           wc;
    HWND               hw_pkt;
    win32_element_t   *pkt_win, *treeview, *byteview;
    packet_win_data_t *pw_data;
    GString           *title = g_string_new("");
    int                i;

    wc.lpszClassName = "packet_window";
    wc.lpfnWndProc = packet_window_wnd_proc;
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = h_instance;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH) (COLOR_WINDOWFRAME+1);
    wc.lpszMenuName = NULL;

    RegisterClass( &wc );

    hw_pkt = packet_window_window_create(h_instance);

    pkt_win = (win32_element_t *) GetWindowLong(hw_pkt, GWL_USERDATA);
    win32_element_assert(pkt_win);

    treeview = win32_element_find_child(pkt_win, "packet-window.treeview");
    win32_element_assert(treeview);
    byteview = win32_element_find_child(pkt_win, "packet-window.byteview");
    win32_element_assert(byteview);

    pw_data = g_malloc(sizeof(*pw_data));
    pw_data->frame = cfile.current_frame;
    memcpy(&pw_data->pseudo_header, &cfile.pseudo_header, sizeof pw_data->pseudo_header);
    pw_data->pd = g_malloc(pw_data->frame->cap_len);
    memcpy(pw_data->pd, cfile.pd, pw_data->frame->cap_len);
    pw_data->edt = epan_dissect_new(TRUE, TRUE);
    epan_dissect_run(pw_data->edt, &pw_data->pseudo_header, pw_data->pd,
	pw_data->frame, &cfile.cinfo);
    epan_dissect_fill_in_columns(pw_data->edt);

    win32_element_set_data(pkt_win, PACKET_WINDOW_DATA, pw_data);


    /* Use the column data to build our window title */
    for (i = 0; i < cfile.cinfo.num_cols; ++i) {
	g_string_append(title, cfile.cinfo.col_data[i]);
	if (i < cfile.cinfo.num_cols - 1) {
	    g_string_append(title, " ");
	}
    }
    SetWindowText(hw_pkt, title->str);
    g_string_free(title, TRUE);

    ethereal_byteview_add(pw_data->edt, byteview, treeview);

    ethereal_treeview_draw(treeview, pw_data->edt->tree, byteview);

    packet_window_window_show(hw_pkt, SW_SHOW);
}

static LRESULT CALLBACK
packet_window_wnd_proc(HWND hw_pkt, UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t   *pkt_win;
    packet_win_data_t *pw_data;

    switch (msg) {
	case WM_CREATE:
	    packet_window_handle_wm_create(hw_pkt);
	    break;
	case WM_SIZE:
	    packet_window_handle_wm_size(hw_pkt, (int) LOWORD(l_param), (int) HIWORD(l_param));
	    break;
	case WM_NOTIFY:
	    break;
	case WM_CLOSE:
	    pkt_win = (win32_element_t *) GetWindowLong(hw_pkt, GWL_USERDATA);
	    win32_element_assert(pkt_win);
	    pw_data = win32_element_get_data(pkt_win, PACKET_WINDOW_DATA);
	    g_free(pw_data);
	    win32_element_destroy(pkt_win, FALSE);
	    break;
	default:
	    return (DefWindowProc(hw_pkt, msg, w_param, l_param));
    }
    return (DefWindowProc(hw_pkt, msg, w_param, l_param));
}


/*
 * Private functions
 */