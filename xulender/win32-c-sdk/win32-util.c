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


/*
 * The amount of work you have to go through just to get the screen
 * size of a string is amazing.
 */
void win32_get_text_size(HWND hwnd, LPCSTR text, LPSIZE szp) {
    HDC        hdc;
    HFONT      hw_font, hdc_font;
    TEXTMETRIC tm;
    int        width = 0, height = 0, len;
    LPCSTR     cptr = text, next_nl;

    while (cptr) {
	next_nl = strchr(cptr, '\n');
	if (next_nl == NULL) {
	    len = strlen(cptr);
	} else {
	    len = next_nl - cptr;
	}
	hw_font = (HFONT) SendMessage(hwnd, WM_GETFONT, 0, 0);
	hdc = GetWindowDC(hwnd);
	hdc_font = SelectObject(hdc, hw_font);
	GetTextExtentPoint(hdc, cptr, len, szp);
	GetTextMetrics(hdc, &tm);
	SelectObject(hdc, hdc_font);
	ReleaseDC(hwnd, hdc);
	if (szp->cx > width) {
	    width = szp->cx;
	}
	height += tm.tmHeight + tm.tmExternalLeading;
	cptr = strchr(cptr, '\n');
	while (cptr != NULL && cptr[0] == '\n') {
	    cptr++;
	}
    }

    szp->cx = width;
    szp->cy = height;
}

/*
 * Convert a COLORREF to a color_t.
 * XXX - The corresponding COLOR_T2COLORREF lives win win32-util.h, and is a macro.
 * XXX - prefs.c has a set of macros ({RED|GREEN|BLUE}_COMPONENT) that do
 *       similar things using integer math.
 */
void colorref2color_t(COLORREF cr, color_t *ct) {
    guint32 red, green, blue;

    red   = GetRValue(cr);
    green = GetGValue(cr);
    blue  = GetBValue(cr);

    ct->pixel = 0;
    ct->red   = (red   << 8) | red;
    ct->green = (green << 8) | green;
    ct->blue  = (blue  << 8) | blue;
}

/*
 * Initialize a color with R, G, and B values, including any toolkit-dependent
 * work that needs to be done.
 * Returns TRUE if it succeeds, FALSE if it fails.
 */
/* XXX - We always retrun TRUE in Windows */
gboolean
initialize_color(color_t *color, guint16 red, guint16 green, guint16 blue)
{
    color->red = red;
    color->green = green;
    color->blue = blue;
    return TRUE;
}
