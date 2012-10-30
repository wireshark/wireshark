/* monospace_font.cpp
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "monospace_font.h"

#include <QFontMetrics>
#include <QString>
#include <QStringList>
#include <QDebug>

//
// XXX We should probably move this to wsApp.
//

//MonospaceFont::MonospaceFont(QObject *parent) :
//    QFont(parent)
//{
//}

QFont mono_regular_font_, mono_bold_font_;

//void MonospaceFont::propagate() {
//    emit(monospaceFontChanged(self));
//}

// http://en.wikipedia.org/wiki/Category:Monospaced_typefaces
#define WIN_DEF_FONT "Consolas"
#define WIN_ALT_FONTS "Lucida Console"
#define OSX_DEF_FONT "Menlo"
#define OSX_ALT_FONTS "Monaco"
#define X11_DEF_FONT "Bitstream Vera Sans Mono"
#define X11_ALT_FONTS "Liberation Mono" << "DejaVu Sans Mono"
#define FALLBACK_FONTS "Lucida Sans Typewriter" << "Inconsolata" << "Droid Sans Mono" << "Andale Mono" << "Courier New" << "monospace"

void
font_init(void) {
    QStringList substitutes;

    // Try to pick the latest, shiniest fixed-width font for our OS.
#if defined(Q_WS_WIN)
#define DEF_FONT WIN_DEF_FONT
#define FONT_SIZE_ADJUST 2
    substitutes = QStringList() << WIN_ALT_FONTS << OSX_DEF_FONT << OSX_ALT_FONTS << X11_DEF_FONT << X11_ALT_FONTS << FALLBACK_FONTS;
#elif defined(Q_WS_MAC)
#define DEF_FONT OSX_DEF_FONT
#define FONT_SIZE_ADJUST 0
    substitutes = QStringList() << OSX_ALT_FONTS << WIN_DEF_FONT << WIN_ALT_FONTS << X11_DEF_FONT << X11_ALT_FONTS << FALLBACK_FONTS;
#else
#define DEF_FONT X11_DEF_FONT
#define FONT_SIZE_ADJUST 0
    substitutes = QStringList() << X11_ALT_FONTS << WIN_DEF_FONT << WIN_ALT_FONTS << OSX_DEF_FONT << OSX_ALT_FONTS << FALLBACK_FONTS;
#endif

    mono_regular_font_.setFamily(DEF_FONT);
    mono_regular_font_.insertSubstitutions(DEF_FONT, substitutes);
    mono_regular_font_.setPointSize(wsApp->font().pointSize() + FONT_SIZE_ADJUST);
#if QT_VERSION >= 0x040700
     mono_bold_font_.setStyleHint(QFont::Monospace);
 #else
     mono_bold_font_.setStyleHint(QFont::TypeWriter);
 #endif

    mono_bold_font_.setFamily(DEF_FONT);
    mono_bold_font_.insertSubstitutions(DEF_FONT, substitutes);
    mono_bold_font_.setPointSize(wsApp->font().pointSize() + FONT_SIZE_ADJUST);
#if QT_VERSION >= 0x040700
     mono_bold_font_.setStyleHint(QFont::Monospace);
 #else
     mono_bold_font_.setStyleHint(QFont::TypeWriter);
 #endif
    mono_bold_font_.setWeight(QFont::Bold);
}

fa_ret_t
user_font_apply(void) {
//    char *gui_font_name;
//    PangoFontDescription *new_r_font, *new_b_font;
//    PangoFontDescription *old_r_font = NULL, *old_b_font = NULL;

    /* convert font name to reflect the zoom level */
//    gui_font_name = font_zoom(prefs.gui_font_name);
//    if (gui_font_name == NULL) {
//        /*
//         * This means the font name isn't an XLFD font name.
//         * We just report that for now as a font not available in
//         * multiple sizes.
//         */
//        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
//            "Your current font isn't available in any other sizes.\n");
//        return FA_FONT_NOT_RESIZEABLE;
//    }

//    /* load normal and bold font */
//    new_r_font = pango_font_description_from_string(gui_font_name);
//    new_b_font = pango_font_description_copy(new_r_font);
//    pango_font_description_set_weight(new_b_font, PANGO_WEIGHT_BOLD);

//    if (new_r_font == NULL || new_b_font == NULL) {
//        /* We're no longer using the new fonts; unreference them. */
//        if (new_r_font != NULL)
//            pango_font_description_free(new_r_font);
//        if (new_b_font != NULL)
//            pango_font_description_free(new_b_font);
//        g_free(gui_font_name);

//        /* We let our caller pop up a dialog box, as the error message
//           depends on the context (did they zoom in or out, or did they
//           do something else? */
//        return FA_FONT_NOT_AVAILABLE;
//    }

//    /* the font(s) seem to be ok */
//    packet_list_set_font(new_r_font);
//    set_ptree_font_all(new_r_font);
//    old_r_font = m_r_font;
//    old_b_font = m_b_font;
//    set_fonts(new_r_font, new_b_font);

//    /* Redraw the packet bytes windows. */
//    redraw_packet_bytes_all();

//    /* Redraw the "Follow TCP Stream" windows. */
//    follow_tcp_redraw_all();

//    /* We're no longer using the old fonts; unreference them. */
//    if (old_r_font != NULL)
//        pango_font_description_free(old_r_font);
//    if (old_b_font != NULL)
//        pango_font_description_free(old_b_font);
//    g_free(gui_font_name);

    return FA_SUCCESS;
}

QFont WiresharkApplication::monospaceFont(bool bold)
{
    return bold ? mono_bold_font_ : mono_regular_font_;
}

int get_monospace_text_size(const char *str, bool regular) {
    QFontMetrics *fm;

    if (regular)
        fm = new QFontMetrics(mono_regular_font_);
    else
        fm = new QFontMetrics(mono_bold_font_);

    return fm->width(str);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
