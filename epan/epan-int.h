/* epan-int.h
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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

#ifndef __EPAN_INT_H__
#define __EPAN_INT_H__

#include <epan/frame_data.h>
#include <wsutil/nstime.h>

/*
 * XXX - this isn't part of libwireshark; using it in the API indicates
 * that perhaps it should be, in some fashion.
 *
 * Whether the structure definition of a capture_file should be part
 * of libwireshark, or part of the code that uses libwireshark, is
 * another matter.
 */
#include "cfile.h"

struct epan_session {
	capture_file *cf;

	const nstime_t *(*get_frame_ts)(capture_file *cf, guint32 frame_num);
	const char *(*get_interface_name)(capture_file *cf, guint32 interface_id);
	const char *(*get_interface_description)(capture_file *cf, guint32 interface_id);
	const char *(*get_user_comment)(capture_file *cf, const frame_data *fd);
};

#endif
