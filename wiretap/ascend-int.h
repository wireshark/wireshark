/* ascend-int.h
 * Definitions for routines common to multiple modules in the Lucent/Ascend
 * capture file reading code code, but not used outside that code.
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

#ifndef __ASCEND_INT_H__
#define __ASCEND_INT_H__

#include <glib.h>
#include "ws_symbol_export.h"

typedef struct {
	time_t inittime;
	gboolean adjusted;
	gint64 next_packet_seek_start;
} ascend_t;

typedef struct {
	FILE_T fh;
	const gchar *ascend_parse_error;
	int err;
	gchar *err_info;
	struct ascend_phdr *pseudo_header;
	guint8 *pkt_data;

	gboolean saw_timestamp;
	guint32 timestamp;

	gint64 first_hexbyte;
	guint32 wirelen;
	guint32 caplen;
	time_t secs;
	guint32 usecs;
} ascend_state_t;

extern int
run_ascend_parser(FILE_T fh, struct wtap_pkthdr *phdr, guint8 *pd,
                  ascend_state_t *parser_state, int *err, gchar **err_info);

#endif /* ! __ASCEND_INT_H__ */
