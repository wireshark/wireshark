/* bytes_view.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __BYTES_VIEW_H__
#define __BYTES_VIEW_H__

#define BYTES_VIEW_TYPE (bytes_view_get_type())
#define BYTES_VIEW(object)	    (G_TYPE_CHECK_INSTANCE_CAST((object), BYTES_VIEW_TYPE, BytesView))

#define BYTE_VIEW_HIGHLIGHT_APPENDIX 1
#define BYTE_VIEW_HIGHLIGHT_PROTOCOL 2

typedef struct _BytesView BytesView;

GType bytes_view_get_type(void);

GtkWidget *bytes_view_new(void);
void bytes_view_set_font(BytesView *bv, PangoFontDescription *font);

void bytes_view_set_data(BytesView *bv, const guint8 *data, int len);
void bytes_view_set_encoding(BytesView *bv, packet_char_enc enc);
void bytes_view_set_format(BytesView *bv, int format);
void bytes_view_set_highlight_style(BytesView *bv, gboolean bold);

void bytes_view_set_highlight(BytesView *bv, int start, int end, guint64 mask, int maskle);
void bytes_view_set_highlight_extra(BytesView *bv, int id, int start, int end);

void bytes_view_refresh(BytesView *bv);
int bytes_view_byte_from_xy(BytesView *bv, int x, int y);
void bytes_view_scroll_to_byte(BytesView *bv, int byte);

#endif /* __BYTES_VIEW_H__ */
