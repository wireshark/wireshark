#ifndef __WIN32_UTIL_H__
#define __WIN32_UTIL_H__

#include "color.h"

/* XXX - For some reason, MapDialogRect() and GetDialogBaseUnits() don't work
 * for us.  Instead, we use contrived base units that give us the results we
 * need for DEFAULT_GUI_FONT.
 */
#define DIALOG2PIXELX(x) ((int) (x * 6.0) / 4)
#define DIALOG2PIXELY(y) ((int) (y * 13.25 / 8))

#define COLOR_T2COLORREF(c) RGB((c)->red >> 8, (c)->green >> 8, (c)->blue >> 8)

void win32_get_text_size(HWND hwnd, LPCSTR text, LPSIZE szp);
void colorref2color_t(COLORREF cr, color_t *ct);

#endif /* win32-util.h */
