/* ascend-int.h
 * Definitions for routines common to multiple modules in the Lucent/Ascend
 * capture file reading code code, but not used outside that code.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
run_ascend_parser(FILE_T fh, wtap_rec *rec, guint8 *pd,
                  ascend_state_t *parser_state, int *err, gchar **err_info);

#endif /* ! __ASCEND_INT_H__ */
