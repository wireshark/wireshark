/* font_util.c
 * Utilities to use for font manipulation
 *
 * $Id: font_utils.c 11584 2004-08-02 22:37:35Z gerald $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2004 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * XXX - This is a Win32-ified version of gtk/font_utils.h.  FONT_TYPE
 * is hard-coded to "HFONT" and the gtkv1 code has been removed.  We
 * use our own code to convert to and from font string descriptions.
 * Perhaps we should use Pango instead.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>

#include <epan/prefs.h>
#include "prefs-recent.h"

#include "alert_box.h"

#include "simple_dialog.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "font-util.h"

static HFONT win32_hfont_from_string(gchar *font_str);
static HFONT win32_font_boldify(HFONT font);

/* The string values (except for "Thin" and "Regular") are taken from Pango,
 * in the hopes of making it easy to move the gui_font_name2 preference
 * between GTK2 and Windows. */
static value_string style_map[] = {
    { FW_THIN,		"Thin" },
    { FW_ULTRALIGHT,	"Ultra-Light" },
    { FW_LIGHT,		"Light" },
    { FW_NORMAL,	"Normal" },
    { FW_NORMAL,	"Regular" },
    { FW_MEDIUM,	"Medium" },
    { FW_SEMIBOLD,	"Semi-Bold" },
    { FW_BOLD, 		"Bold" },
    { FW_EXTRABOLD,	"Extra-Bold" },
    { FW_HEAVY,		"Heavy" },
    { 0,		NULL }
};

HFONT m_r_font, m_b_font;


/* Get the regular user font.
 *
 * @return the regular user font
 */
HFONT
user_font_get_regular(void) {
    return m_r_font;
}

/* Get the bold user font.
 *
 * @return the bold user font
 */
HFONT
user_font_get_bold(void) {
    return m_b_font;
}


static void
set_fonts(HFONT regular, HFONT bold) {
	/* Yes, assert. The code that loads the font should check
	 * for NULL and provide its own error message. */
	g_assert(m_r_font && m_b_font);
	m_r_font = regular;
	m_b_font = bold;
}

void
view_zoom_in() {
    gint save_gui_zoom_level;

    save_gui_zoom_level = recent.gui_zoom_level;
    recent.gui_zoom_level++;
    switch (user_font_apply()) {
	case FA_SUCCESS:
	    break;
	case FA_FONT_NOT_RESIZEABLE:
	    /* "font_apply()" popped up an alert box. */
	    recent.gui_zoom_level = save_gui_zoom_level;	/* undo zoom */
	    break;
	case FA_FONT_NOT_AVAILABLE:
	    /* We assume this means that the specified size isn't available. */
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Your current font isn't available in the next larger size.\n");
	    recent.gui_zoom_level = save_gui_zoom_level;	/* undo zoom */
	    break;
    }
}

void
view_zoom_out() {
    gint save_gui_zoom_level;

    save_gui_zoom_level = recent.gui_zoom_level;
    recent.gui_zoom_level--;
    switch (user_font_apply()) {
	case FA_SUCCESS:
	    break;
	case FA_FONT_NOT_RESIZEABLE:
	    /* "font_apply()" popped up an alert box. */
	    recent.gui_zoom_level = save_gui_zoom_level;	/* undo zoom */
	    break;
	case FA_FONT_NOT_AVAILABLE:
	    /* We assume this means that the specified size isn't available. */
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Your current font isn't available in the next smaller size.\n");
	    recent.gui_zoom_level = save_gui_zoom_level;	/* undo zoom */
	    break;
    }
}

void
view_zoom_100() {
    gint save_gui_zoom_level;

    save_gui_zoom_level = recent.gui_zoom_level;
    recent.gui_zoom_level = 0;
    switch (user_font_apply()) {
	case FA_SUCCESS:
	    break;
	case FA_FONT_NOT_RESIZEABLE:
	    /* "font_apply()" popped up an alert box. */
	    recent.gui_zoom_level = save_gui_zoom_level;	/* undo zoom */
	    break;
	case FA_FONT_NOT_AVAILABLE:
	    /* We assume this means that the specified size isn't available.
	       XXX - this "shouldn't happen". */
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Your current font couldn't be reloaded at the size you selected.\n");
	    recent.gui_zoom_level = save_gui_zoom_level;	/* undo zoom */
	    break;
    }
}


gboolean
user_font_test(gchar *font_name)
{
    HFONT new_r_font, new_b_font;

    new_r_font = win32_hfont_from_string(font_name);

    if (new_r_font == NULL) {
	/* Oops, that font didn't work.
	   Tell the user, but don't tear down the font selection
	   dialog, so that they can try again. */
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	   "The font you selected cannot be loaded.");

	return FALSE;
    }

    new_b_font = win32_font_boldify(new_r_font);

    if (new_b_font == NULL) {
	/* Oops, that font didn't work.
	   Tell the user, but don't tear down the font selection
	   dialog, so that they can try again. */
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	   "The font you selected doesn't have a boldface version.");

	DeleteObject(new_r_font);
	return FALSE;
    }

    return TRUE;
}



/* Given a font name, construct the name of a version of that font with
   the current zoom factor applied. */
static char *
font_zoom(char *gui_font_name)
{
    char *new_font_name;
    char *font_name_dup;
    char *font_name_p;
    long pointsz;

    if (recent.gui_zoom_level == 0) {
	/* There is no zoom factor - just return the name, so that if
	   this is GTK+ 1.2[.x] and the font name isn't an XLFD font
	   name, we don't fail. */
	return g_strdup(gui_font_name);
    }

    font_name_dup = g_strdup(gui_font_name);
    font_name_p = font_name_dup;

    /* find the start of the font_size string */
    font_name_p = g_strrstr(font_name_dup, " ");
    *font_name_p = '\0';
    font_name_p++;

    /* calculate the new font size */
    pointsz = strtol(font_name_p, NULL, 10);
    pointsz += recent.gui_zoom_level;

    /* build a new font name */
    new_font_name = g_strdup_printf("%s %ld", font_name_dup, pointsz);

    g_free(font_name_dup);

    return new_font_name;
}


fa_ret_t
user_font_apply() {
    win32_element_t *byteview = win32_identifier_get_str("main-byteview");
    HFONT            new_r_font, new_b_font;
    HFONT            old_r_font = NULL, old_b_font = NULL;
    gchar           *gui_font_name;

    win32_element_assert(byteview);

    /* convert font name to reflect the zoom level */
    gui_font_name = font_zoom(prefs.gui_font_name2);
    if (gui_font_name == NULL) {
	/*
	 * This means the font name isn't an XLFD font name.
	 * We just report that for now as a font not available in
	 * multiple sizes.
	 */
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Your current font isn't available in any other sizes.\n");
	return FA_FONT_NOT_RESIZEABLE;
    }

    new_r_font = win32_hfont_from_string(gui_font_name);
    new_b_font = win32_font_boldify(new_r_font);

    if (new_r_font == NULL || new_b_font == NULL) {
        /* We're no longer using the new fonts; unreference them. */
        if (new_r_font != NULL)
            DeleteObject(new_r_font);
        if (new_b_font != NULL)
            DeleteObject(new_b_font);

        g_free(gui_font_name);

        /* We let our caller pop up a dialog box, as the error message
           depends on the context (did they zoom in or out, or did they
           do something else? */
        return FA_FONT_NOT_AVAILABLE;
    }

    /* the font(s) seem to be ok */
    SendMessage(byteview->h_wnd, WM_SETFONT, (WPARAM) new_r_font, TRUE);

//    set_plist_font(new_r_font);
//    set_ptree_font_all(new_r_font);
    old_r_font = m_r_font;
    old_b_font = m_b_font;
    set_fonts(new_r_font, new_b_font);

    /* Redraw the hex dump windows. */
//    redraw_hex_dump_all();

    /* Redraw the "Follow TCP Stream" windows. */
//    follow_redraw_all();

    /* We're no longer using the old fonts; unreference them. */
    if (old_r_font != NULL)
        DeleteObject(old_r_font);
    if (old_b_font != NULL)
        DeleteObject(old_b_font);

    g_free(gui_font_name);

    return FA_SUCCESS;
}

/* Converts a Pango-style font description (e.g. "Courier Bold 12") to an HFONT */
static HFONT
win32_hfont_from_string(gchar *font_str) {
    HFONT    font;
    LOGFONT  lfinfo;
    HDC      hdc;
    gchar   *fdesc, *p, *ps_str = NULL, *style = NULL;
    gint     i, pointsz;

    ZeroMemory(&lfinfo, sizeof(lfinfo));
    lfinfo.lfWeight = FW_NORMAL;
    lfinfo.lfItalic = FALSE;

    fdesc = g_strdup(font_str);
    g_strchug(fdesc);
    g_strchomp(fdesc);

    p = g_strrstr(fdesc, " ");
    if (p) {
	ps_str = p + 1;
	*p = '\0';
	pointsz = atoi(ps_str);
	hdc = GetDC(NULL);
	lfinfo.lfHeight = - MulDiv(pointsz, GetDeviceCaps(hdc, LOGPIXELSY), 72);
	ReleaseDC(NULL, hdc);
    } else {
	g_free(fdesc);
	return NULL;
    }


    /* None of the style_map[] strings can have spaces if this is to work. */

    /* We copy off the face name early in case there are no style parts */
    g_strlcpy(lfinfo.lfFaceName, fdesc, LF_FACESIZE);

    p = g_strrstr(fdesc, " ");
    if (p) {
	style = p + 1;
	*p = '\0';
	if (g_ascii_strcasecmp(style, "italic") == 0 || g_ascii_strcasecmp(style, "oblique") == 0) {
	    g_strlcpy(lfinfo.lfFaceName, fdesc, LF_FACESIZE);
	    style = NULL;
	    lfinfo.lfItalic = TRUE;
	    p = g_strrstr(fdesc, " ");
	    if (p) {
		style = p + 1;
		*p = '\0';
	    }
	}
    }

    if (style) {
	for (i = 0; style_map[i].value != 0; i++) {
	    if (strcasecmp(style, style_map[i].strptr) == 0) {
		lfinfo.lfWeight = style_map[i].value;
		g_strlcpy(lfinfo.lfFaceName, fdesc, LF_FACESIZE);
	    }
	}
    }


    g_free(fdesc);

    font = CreateFontIndirect(&lfinfo);

    return font;
}

gchar *
win32_font_string_from_hfont(HFONT font) {
    LOGFONT lfinfo;
    HDC     hdc;
    gint    pointsz, weight;
    gchar  *italic = "";

    ZeroMemory(&lfinfo, sizeof(lfinfo));

    if (! font) return NULL;

    if (! GetObject(font, sizeof(lfinfo), &lfinfo)) return NULL;

    if (lfinfo.lfWeight <= FW_ULTRALIGHT)
	weight = FW_THIN;
    else if (lfinfo.lfWeight <= FW_LIGHT)
	weight = FW_ULTRALIGHT;
    else if (lfinfo.lfWeight <= FW_NORMAL)
	weight = FW_ULTRALIGHT;
    else if (lfinfo.lfWeight <= FW_MEDIUM)
	weight = FW_NORMAL;
    else if (lfinfo.lfWeight <= FW_SEMIBOLD)
	weight = FW_MEDIUM;
    else if (lfinfo.lfWeight <= FW_BOLD)
	weight = FW_SEMIBOLD;
    else if (lfinfo.lfWeight <= FW_EXTRABOLD)
	weight = FW_BOLD;
    else if (lfinfo.lfWeight <= FW_HEAVY)
	weight = FW_EXTRABOLD;
    else
	weight = FW_HEAVY;

    hdc = GetDC(NULL);
    pointsz = MulDiv(lfinfo.lfHeight, 72, GetDeviceCaps(hdc, LOGPIXELSY));
    ReleaseDC(NULL, hdc);

    if (lfinfo.lfItalic)
	italic = " Italic";

    return g_strdup_printf("%s %s%s %d", lfinfo.lfFaceName,
	    val_to_str(lfinfo.lfWeight, style_map, ""), italic, pointsz);
}

static HFONT
win32_font_boldify(HFONT font) {
    LOGFONT lfinfo;
    HFONT   bold_font;

    ZeroMemory(&lfinfo, sizeof(lfinfo));

    if (! font) return NULL;

    if (! GetObject(font, sizeof(lfinfo), &lfinfo)) return NULL;

    /* Increment the given font's weight by 100 until we find a heavier
     * valid font */
    while (lfinfo.lfWeight < 1000) {
	lfinfo.lfWeight += 100;
	bold_font = CreateFontIndirect(&lfinfo);
	if (bold_font)
	    return bold_font;
    }
    return NULL;
}

void font_init(void) {

    /* Try to load the regular and boldface fixed-width fonts */
    m_r_font = win32_hfont_from_string(prefs.gui_font_name2);
    m_b_font = win32_font_boldify(m_r_font);

    if (m_r_font == NULL || m_b_font == NULL) {
	/* XXX - pop this up as a dialog box? no */
	if (m_r_font == NULL) {
	    fprintf(stderr, "ethereal: Warning: Font %s not found - using system default\n",
		    prefs.gui_font_name2);
	} else {
	    DeleteObject((HGDIOBJ) m_r_font);
	}
	if (m_b_font == NULL) {
	    fprintf(stderr, "ethereal: Warning: Bold font %s not found - using system default\n",
		    prefs.gui_font_name2);
	} else {
	    DeleteObject((HGDIOBJ) m_b_font);
	}

	if ((m_r_font = (HFONT) GetStockObject(ANSI_FIXED_FONT)) == NULL) {
	    fprintf(stderr, "ethereal: Error: Default system font not found\n");
	    exit(1);
	}
	if ((m_b_font = win32_font_boldify(m_r_font)) == NULL) {
	    fprintf(stderr, "ethereal: Error: Bold system font not found\n");
	    exit(1);
	}

	g_free(prefs.gui_font_name2);
	prefs.gui_font_name2 = win32_font_string_from_hfont(m_r_font);
    }

    /* Call this for the side-effects that set_fonts() produces */
    set_fonts(m_r_font, m_b_font);
}



/*
 * Private functions
 */
