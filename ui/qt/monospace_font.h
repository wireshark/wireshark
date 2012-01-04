/* monospace_font.h
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

#ifndef MONOSPACE_FONT_H
#define MONOSPACE_FONT_H

#include <QFont>

//class MonospaceFont : public QFont
//{
//    Q_OBJECT
//public:
//    explicit MonospaceFont(QObject *parent = 0);
//    void propagate(void);

//signals:
//    void monospaceFontChanged(QFont);

//public slots:

//};

/** Init the application and user fonts at program start. */
extern void font_init(void);

/** Return value from font_apply() */
typedef enum {
        FA_SUCCESS,             /**< function succeeded */
        FA_FONT_NOT_RESIZEABLE, /**< the chosen font isn't resizable */
        FA_FONT_NOT_AVAILABLE   /**< the chosen font isn't available */
} fa_ret_t;

/** Applies a new user font, corresponding to the preferences font name and recent zoom level.
 *  Will also redraw the screen.
 *
 * @return if the new font could be set or not
 */
extern fa_ret_t user_font_apply(void);

extern QFont get_monospace_font(void);

extern int get_monospace_text_size(const char *str, bool regular);

#endif // MONOSPACE_FONT_H
