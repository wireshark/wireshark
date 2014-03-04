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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <glib.h>
#include "ws_symbol_export.h"

extern int at_eof;

extern const gchar *ascend_parse_error;

/*
 * Pointer to the pseudo-header for the current packet.
 */
extern struct ascend_phdr *pseudo_header;

typedef struct {
	time_t inittime;
	gboolean adjusted;
	gint64 next_packet_seek_start;
} ascend_t;

/* Here we provide interfaces to make our scanner act and look like lex */
int ascendlex(void);

void init_parse_ascend(void);
void ascend_init_lexer(FILE_T fh);
gboolean check_ascend(FILE_T fh, struct wtap_pkthdr *phdr);
typedef enum {
    PARSED_RECORD,
    PARSED_NONRECORD,
    PARSE_FAILED
} parse_t;
parse_t parse_ascend(ascend_t *ascend, FILE_T fh, struct wtap_pkthdr *phdr,
		Buffer *buf, guint length);

#endif /* ! __ASCEND_INT_H__ */
