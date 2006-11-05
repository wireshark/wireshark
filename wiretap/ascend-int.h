/* ascend-int.h
 * Definitions for routines common to multiple modules in the Lucent/Ascend
 * capture file reading code code, but not used outside that code.
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

#ifndef __ASCEND_INT_H__
#define __ASCEND_INT_H__

typedef struct {
  time_t start_time;
  time_t secs;
  time_t usecs;
  guint32 caplen;
  guint32 len;
} ascend_pkthdr;

extern int at_eof;

extern const gchar *ascend_parse_error;

/*
 * Pointer to the pseudo-header for the current packet.
 */
extern struct ascend_phdr *pseudo_header;

/* Here we provide interfaces to make our scanner act and look like lex */
int ascendlex(void);

void init_parse_ascend(void);
void ascend_init_lexer(FILE_T fh);
int parse_ascend(FILE_T fh, guint8 *pd, struct ascend_phdr *phdr,
		ascend_pkthdr *hdr, gint64 *start_of_data);

#endif /* ! __ASCEND_INT_H__ */
