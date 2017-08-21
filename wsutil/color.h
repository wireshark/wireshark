/* color.h
 * Definitions for colors
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
#ifndef  __COLOR_H__
#define  __COLOR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Data structure holding RGB value for a color, 16 bits per channel.
 */
typedef struct {
    guint16 red;
    guint16 green;
    guint16 blue;
} color_t;

/*
 * Convert a color_t to a 24-bit RGB value, reducing each channel to
 * 8 bits and combining them.
 */
inline static unsigned int
color_t_to_rgb(const color_t *color) {
    return (((color->red >> 8) << 16)
          | ((color->green >> 8) << 8)
          | (color->blue >> 8));
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
