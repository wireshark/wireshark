/* ascend.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 *
 */

#ifndef __ASCENDTEXT_H__
#define __ASCENDTEXT_H__
#include <glib.h>

/*
 * ASCEND_MAX_PKT_LEN is < WTAP_MAX_PACKET_SIZE, so we don't need to
 * check the packet length.
 */
#define ASCEND_MAX_DATA_ROWS 8
#define ASCEND_MAX_DATA_COLS 16
#define ASCEND_MAX_PKT_LEN (ASCEND_MAX_DATA_ROWS * ASCEND_MAX_DATA_COLS)

wtap_open_return_val ascend_open(wtap *wth, int *err, gchar **err_info);

#endif
