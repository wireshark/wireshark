/* font_utils.c
 * Utilities to use for font manipulation
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <epan/packet.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <epan/strutil.h>
#endif

#include "main.h"
#include "recent.h"
#include <epan/prefs.h>

#include "gtkglobals.h"

#include "compat_macros.h"
#include "font_utils.h"
#include "simple_dialog.h"

#include "packet_list.h"
#include "proto_draw.h"
#include "follow_dlg.h"



#if GTK_MAJOR_VERSION < 2
guint	     m_font_height, m_font_width;
#endif
FONT_TYPE *m_r_font, *m_b_font;


/* Get the regular user font.
 *
 * @return the regular user font
 */
FONT_TYPE *user_font_get_regular(void)
{
    return m_r_font;
}

/* Get the bold user font.
 *
 * @return the bold user font
 */
FONT_TYPE *user_font_get_bold(void)
{
    return m_b_font;
}

#if GTK_MAJOR_VERSION < 2
/* Get the regular user font height.
 *
 * @return the regular user font height
 */
guint user_font_get_regular_height(void)
{
    return m_font_height;
}

/* Get the regular user font width.
 *
 * @return the regular user font width
 */
guint user_font_get_regular_width(void)
{
    return m_font_width;
}
#endif


static void
set_fonts(FONT_TYPE *regular, FONT_TYPE *bold)
{
	/* Yes, assert. The code that loads the font should check
	 * for NULL and provide its own error message. */
	g_assert(m_r_font && m_b_font);
	m_r_font = regular;
	m_b_font = bold;

#if GTK_MAJOR_VERSION < 2
	m_font_height = m_r_font->ascent + m_r_font->descent;
	m_font_width = gdk_string_width(m_r_font, "0");
#endif
}

void
view_zoom_in_cb(GtkWidget *w _U_, gpointer d _U_)
{
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
view_zoom_out_cb(GtkWidget *w _U_, gpointer d _U_)
{
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
view_zoom_100_cb(GtkWidget *w _U_, gpointer d _U_)
{
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


#if GTK_MAJOR_VERSION < 2
/* Given a font name, construct the name of the next heavier version of
   that font. */

#define	XLFD_WEIGHT	3	/* index of the "weight" field */

/* Map from a given weight to the appropriate weight for the "bold"
   version of a font.
   XXX - the XLFD says these strings shouldn't be used for font matching;
   can we get the weight, as a number, from GDK, and ask GDK to find us
   a font just like the given font, but with the appropriate higher
   weight? */
static const struct {
	char	*light;
	char	*heavier;
} weight_map[] = {
	{ "ultralight", "light" },
	{ "extralight", "semilight" },
	{ "light",      "medium" },
	{ "semilight",  "semibold" },
	{ "medium",     "bold" },
	{ "normal",     "bold" },
	{ "semibold",   "extrabold" },
	{ "bold",       "ultrabold" }
};
#define	N_WEIGHTS	(sizeof weight_map / sizeof weight_map[0])

/* Try to convert a font name to it's bold version.
 *
 * @param the font to convert
 * @return the bold font
 */
static char *
user_font_boldify(const char *font_name)
{
	char *bold_font_name;
	gchar **xlfd_tokens;
	unsigned int i;

	/* Is this an XLFD font?  If it begins with "-", yes, otherwise no. */
	if (font_name[0] == '-') {
		xlfd_tokens = g_strsplit(font_name, "-", XLFD_WEIGHT+1);

		/*
		 * Make sure we *have* a weight (this might not be a valid
		 * XLFD font name).
		 */
		for (i = 0; i < XLFD_WEIGHT+1; i++) {
			if (xlfd_tokens[i] == NULL) {
				/*
				 * We don't, so treat this as a non-XLFD
				 * font name.
				 */
				goto not_xlfd;
			}
		}
		for (i = 0; i < N_WEIGHTS; i++) {
			if (strcmp(xlfd_tokens[XLFD_WEIGHT],
			    weight_map[i].light) == 0) {
				g_free(xlfd_tokens[XLFD_WEIGHT]);
				xlfd_tokens[XLFD_WEIGHT] =
				    g_strdup(weight_map[i].heavier);
				break;
			}
		}
		bold_font_name = g_strjoinv("-", xlfd_tokens);
		g_strfreev(xlfd_tokens);
		return bold_font_name;
	}

not_xlfd:
	/*
	 * This isn't an XLFD font name; just append "bold" to the name
	 * of the font.
	 */
	bold_font_name = g_strconcat(font_name, "bold", NULL);
	return bold_font_name;
}
#endif


gboolean
user_font_test(gchar *font_name)
{
#if GTK_MAJOR_VERSION < 2
	gchar   *bold_font_name;
#endif
	FONT_TYPE *new_r_font, *new_b_font;

#if GTK_MAJOR_VERSION < 2
	/* Get the name that the boldface version of that font would have. */
	bold_font_name = user_font_boldify(font_name);

	/* Now load those fonts, just to make sure we can. */
	new_r_font = gdk_font_load(font_name);
#else
	new_r_font = pango_font_description_from_string(font_name);
#endif
	if (new_r_font == NULL) {
		/* Oops, that font didn't work.
		   Tell the user, but don't tear down the font selection
		   dialog, so that they can try again. */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		   "The font you selected can't be loaded.");

#if GTK_MAJOR_VERSION < 2
		g_free(bold_font_name);
#endif
		return FALSE;
	}

#if GTK_MAJOR_VERSION < 2
	new_b_font = gdk_font_load(bold_font_name);
#else
	new_b_font = pango_font_description_copy(new_r_font);
	pango_font_description_set_weight(new_b_font, PANGO_WEIGHT_BOLD);
#endif
	if (new_b_font == NULL) {
		/* Oops, that font didn't work.
		   Tell the user, but don't tear down the font selection
		   dialog, so that they can try again. */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		   "The font you selected doesn't have a boldface version.");

#if GTK_MAJOR_VERSION < 2
		g_free(bold_font_name);
		gdk_font_unref(new_r_font);
#else
		pango_font_description_free(new_r_font);
#endif
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
    long font_point_size_l;
#if GTK_MAJOR_VERSION < 2
    int minus_chars;
    char *font_foundry;
    char *font_family;
    char *font_weight;
    char *font_slant;
    char *font_set_width;
    char *font_add_style;
    char *font_pixel_size;
    char *font_point_size;
    char *font_res_x;
    char *font_res_y;
    char *font_spacing;
    char *font_aver_width;
    char *font_charset_reg;
    char *font_charset_encoding;
#endif

    if (recent.gui_zoom_level == 0) {
        /* There is no zoom factor - just return the name, so that if
           this is GTK+ 1.2[.x] and the font name isn't an XLFD font
           name, we don't fail. */
        return g_strdup(gui_font_name);
    }

    font_name_dup = g_strdup(gui_font_name);
    font_name_p = font_name_dup;

#if GTK_MAJOR_VERSION >= 2
    /* find the start of the font_size string */
    font_name_p = strrchr(font_name_dup, ' ');
    *font_name_p = '\0';
    font_name_p++;

    /* calculate the new font size */
    font_point_size_l = strtol(font_name_p, NULL, 10);
    font_point_size_l += recent.gui_zoom_level;

    /* build a new font name */
    new_font_name = g_strdup_printf("%s %ld", font_name_dup, font_point_size_l);
#else
    minus_chars = 0;
    /* replace all '-' chars by NUL and count them */
    while ((font_name_p = strchr(font_name_p, '-')) != NULL) {
        *font_name_p = '\0';
        font_name_p++;
        minus_chars++;
    }

    if (minus_chars != 14) {
        /*
         * Not a valid XLFD font name.
         * XXX - can we try scaling it by looking for a size at the end
         * and tweaking that?  Unfortunately, some fonts have numbers
         * at the end that aren't, as far as I know, sizes, e.g. "nil2".
         */
        return NULL;
    }

    /* first element (font name registry) empty */
    font_name_p = font_name_dup;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    /* get pointers to all font name elements */
    font_foundry = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_family = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_weight = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_slant = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_set_width = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_add_style = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_pixel_size = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_point_size = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_res_x = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_res_y = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_spacing = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_aver_width = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_charset_reg = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_charset_encoding = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    /* calculate the new font size */
    font_point_size_l = strtol(font_point_size, NULL, 10);
    font_point_size_l += recent.gui_zoom_level*10;
    if (font_point_size_l <= 0)
        font_point_size_l = 10;

    /* build a new font name */
    new_font_name = g_strdup_printf("-%s-%s-%s-%s-%s-%s-%s-%ld-%s-%s-%s-%s-%s-%s", 
        font_foundry, font_family, font_weight, font_slant, font_set_width, 
        font_add_style, font_pixel_size, font_point_size_l, font_res_x,
        font_res_y, font_spacing, font_aver_width, font_charset_reg,
        font_charset_encoding);
#endif

    g_free(font_name_dup);

    return new_font_name;
}

fa_ret_t
user_font_apply(void) {
    char *gui_font_name;
#if GTK_MAJOR_VERSION < 2
    char *bold_font_name;
#endif
    FONT_TYPE *new_r_font, *new_b_font;
    FONT_TYPE *old_r_font = NULL, *old_b_font = NULL;

    /* convert font name to reflect the zoom level */
    gui_font_name = font_zoom(prefs.PREFS_GUI_FONT_NAME);
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

    /* load normal and bold font */
#if GTK_MAJOR_VERSION < 2
    new_r_font = gdk_font_load(gui_font_name);
    bold_font_name = user_font_boldify(gui_font_name);
    new_b_font = gdk_font_load(bold_font_name);
#else
    new_r_font = pango_font_description_from_string(gui_font_name);
    new_b_font = pango_font_description_copy(new_r_font);
    pango_font_description_set_weight(new_b_font, PANGO_WEIGHT_BOLD);
#endif

    if (new_r_font == NULL || new_b_font == NULL) {
        /* We're no longer using the new fonts; unreference them. */
#if GTK_MAJOR_VERSION < 2
        if (new_r_font != NULL)
            gdk_font_unref(new_r_font);
        if (new_b_font != NULL)
            gdk_font_unref(new_b_font);
#else
        if (new_r_font != NULL)
            pango_font_description_free(new_r_font);
        if (new_b_font != NULL)
            pango_font_description_free(new_b_font);
#endif
        g_free(gui_font_name);

        /* We let our caller pop up a dialog box, as the error message
           depends on the context (did they zoom in or out, or did they
           do something else? */
        return FA_FONT_NOT_AVAILABLE;
    }

    /* the font(s) seem to be ok */
    packet_list_set_font(new_r_font);
    set_ptree_font_all(new_r_font);
    old_r_font = m_r_font;
    old_b_font = m_b_font;
    set_fonts(new_r_font, new_b_font);
#if GTK_MAJOR_VERSION < 2
    g_free(bold_font_name);
#endif

    /* Redraw the hex dump windows. */
    redraw_hex_dump_all();

    /* Redraw the "Follow TCP Stream" windows. */
    follow_redraw_all();

    /* We're no longer using the old fonts; unreference them. */
#if GTK_MAJOR_VERSION < 2
    if (old_r_font != NULL)
        gdk_font_unref(old_r_font);
    if (old_b_font != NULL)
        gdk_font_unref(old_b_font);
#else
    if (old_r_font != NULL)
        pango_font_description_free(old_r_font);
    if (old_b_font != NULL)
        pango_font_description_free(old_b_font);
#endif
    g_free(gui_font_name);

    return FA_SUCCESS;
}


#ifdef _WIN32

#define NAME_BUFFER_LEN 32

#if GTK_MAJOR_VERSION < 2


/* The setting of the MS default font for system stuff (menus, dialogs, ...),
 * coming from: Allin Cottrell, http://www.ecn.wfu.edu/~cottrell/gtk_win32,
 * Thank you very much for this! */
static int get_windows_font_gtk1(char *fontspec, int fontspec_len)
{
    HDC h_dc;
    HGDIOBJ h_font;
    TEXTMETRIC tm;
    TCHAR name[NAME_BUFFER_LEN];
    int len, pix_height;

    h_dc = CreateDC(_T("DISPLAY"), NULL, NULL, NULL);
    if (h_dc == NULL) return 1;
    h_font = GetStockObject(DEFAULT_GUI_FONT);
    if (h_font == NULL || !SelectObject(h_dc, h_font)) {
        DeleteDC(h_dc);
        return 1;
    }
    len = GetTextFace(h_dc, NAME_BUFFER_LEN, name);
    if (len <= 0) {
        DeleteDC(h_dc);
        return 1;
    }
    if (!GetTextMetrics(h_dc, &tm)) {
        DeleteDC(h_dc);
        return 1;
    }
    pix_height = tm.tmHeight;
    DeleteDC(h_dc);
    g_snprintf(fontspec, fontspec_len, "-*-%s-*-*-*-*-%i-*-*-*-p-*-iso8859-1",
            utf_16to8(name), pix_height);
    return 0;
}

void app_font_gtk1_init(GtkWidget *top_level_w)
{
    GtkStyle *style;
    char winfont[80];
 
    style = gtk_widget_get_style(top_level_w);
    if (get_windows_font_gtk1(winfont, sizeof(winfont)) == 0)
        style->font = gdk_font_load(winfont);
    if (style->font) gtk_widget_set_style(top_level_w, style);
}


#else /* GTK_MAJOR_VERSION */
static char appfontname[128] = "tahoma 8";

static void
set_app_font_gtk2(const char *fontname)
{
    GtkSettings *settings;

    if (fontname != NULL && *fontname == 0) return;

    settings = gtk_settings_get_default();

    if (fontname == NULL) {
	g_object_set(G_OBJECT(settings), "gtk-font-name", appfontname, NULL);
    } else {
	GtkWidget *w;
	PangoFontDescription *pfd;
	PangoContext *pc;
	PangoFont *pfont;

	w = gtk_label_new(NULL);
	pfd = pango_font_description_from_string(fontname);
	pc = gtk_widget_get_pango_context(w);
	pfont = pango_context_load_font(pc, pfd);

	if (pfont != NULL) {
	    strcpy(appfontname, fontname);
	    g_object_set(G_OBJECT(settings), "gtk-font-name", appfontname, NULL);
	}

	gtk_widget_destroy(w);
	pango_font_description_free(pfd);
    }
}

static char *default_windows_menu_fontspec_gtk2(void)
{
    gchar *fontspec = NULL;
    NONCLIENTMETRICS ncm;

    memset(&ncm, 0, sizeof ncm);
    ncm.cbSize = sizeof ncm;

    if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0)) {
	HDC screen = GetDC(0);
	double y_scale = 72.0 / GetDeviceCaps(screen, LOGPIXELSY);
	int point_size = (int) (ncm.lfMenuFont.lfHeight * y_scale);

	if (point_size < 0) point_size = -point_size;
	fontspec = g_strdup_printf("%s %d", ncm.lfMenuFont.lfFaceName,
				   point_size);
	ReleaseDC(0, screen);
    }

    return fontspec;
}

static void try_to_get_windows_font_gtk2(void)
{
    gchar *fontspec;

    fontspec = default_windows_menu_fontspec_gtk2();

    if (fontspec != NULL) {
	int match = 0;
	PangoFontDescription *pfd;
	PangoFont *pfont;
	PangoContext *pc;
	GtkWidget *w;

	pfd = pango_font_description_from_string(fontspec);

	w = gtk_label_new(NULL);
	pc = gtk_widget_get_pango_context(w);
	pfont = pango_context_load_font(pc, pfd);
	match = (pfont != NULL);

	pango_font_description_free(pfd);
	g_object_unref(G_OBJECT(pc));
	gtk_widget_destroy(w);

	if (match) set_app_font_gtk2(fontspec);
	g_free(fontspec);
    }
}
#endif /* GTK_MAJOR_VERSION */

#endif /* _WIN32 */


void font_init(void)
{
#if GTK_MAJOR_VERSION < 2
  gchar *bold_font_name;
#endif

#ifdef _WIN32
#if GTK_MAJOR_VERSION >= 2
  /* try to load the application font for GTK2 */
  try_to_get_windows_font_gtk2();
#endif
#endif
    
  /* Try to load the regular and boldface fixed-width fonts */
#if GTK_MAJOR_VERSION < 2
  bold_font_name = user_font_boldify(prefs.gui_font_name1);
  m_r_font = gdk_font_load(prefs.gui_font_name1);
  m_b_font = gdk_font_load(bold_font_name);
  if (m_r_font == NULL || m_b_font == NULL) {
    /* XXX - pop this up as a dialog box? no */
    if (m_r_font == NULL) {
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
		prefs.gui_font_name1);
    } else {
      gdk_font_unref(m_r_font);
    }
    if (m_b_font == NULL) {
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
		bold_font_name);
    } else {
      gdk_font_unref(m_b_font);
    }
    g_free(bold_font_name);
    if ((m_r_font = gdk_font_load("6x13")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13 not found\n");
      exit(1);
    }
    if ((m_b_font = gdk_font_load("6x13bold")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13bold not found\n");
      exit(1);
    }
    g_free(prefs.gui_font_name1);
    prefs.gui_font_name1 = g_strdup("6x13");
  }
#else /* GTK_MAJOR_VERSION */
  m_r_font = pango_font_description_from_string(prefs.gui_font_name2);
  m_b_font = pango_font_description_copy(m_r_font);
  pango_font_description_set_weight(m_b_font, PANGO_WEIGHT_BOLD);
  if (m_r_font == NULL || m_b_font == NULL) {
    /* XXX - pop this up as a dialog box? no */
    if (m_r_font == NULL) {
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to Monospace 9\n",
		prefs.gui_font_name2);
    } else {
      pango_font_description_free(m_r_font);
    }
    if (m_b_font == NULL) {
        fprintf(stderr, "ethereal: Warning: bold font %s not found - defaulting"
                        " to Monospace 9\n", prefs.gui_font_name2);
    } else {
      pango_font_description_free(m_b_font);
    }
    if ((m_r_font = pango_font_description_from_string("Monospace 9")) == NULL)
    {
      fprintf(stderr, "ethereal: Error: font Monospace 9 not found\n");
      exit(1);
    }
    if ((m_b_font = pango_font_description_copy(m_r_font)) == NULL) {
      fprintf(stderr, "ethereal: Error: font Monospace 9 bold not found\n");
      exit(1);
    }
    g_free(prefs.gui_font_name2);
    pango_font_description_set_weight(m_b_font, PANGO_WEIGHT_BOLD);
    prefs.gui_font_name2 = g_strdup("Monospace 9");
  }
#endif /* GTK_MAJOR_VERSION */

  /* Call this for the side-effects that set_fonts() produces */
  set_fonts(m_r_font, m_b_font);
}
