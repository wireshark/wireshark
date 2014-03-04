/* frame_tvbuff.h
 * Implements a tvbuff for frame
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

#ifndef __FRAME_TVBUFF_H__
#define __FRAME_TVBUFF_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <wiretap/wtap.h>

extern tvbuff_t *frame_tvbuff_new(const frame_data *fd, const guint8 *buf);

extern tvbuff_t *frame_tvbuff_new_buffer(const frame_data *fd, Buffer *buf);

extern tvbuff_t *file_tvbuff_new(const frame_data *fd, const guint8 *buf);

extern tvbuff_t *file_tvbuff_new_buffer(const frame_data *fd, Buffer *buf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FRAME_TVBUFF_H__ */
