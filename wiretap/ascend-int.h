/* ascend-int.h
 * Definitions for routines common to multiple modules in the Lucent/Ascend
 * capture file reading code code, but not used outside that code.
 *
 * $Id: ascend-int.h,v 1.6 2000/05/19 08:18:14 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
  time_t secs;
  time_t usecs;
  guint32 caplen;
  guint32 len;
} ascend_pkthdr;

/*
 * Pointer to the pseudo-header for the current packet.
 */
extern struct ascend_phdr *pseudo_header;

/* Here we provide interfaces to make our scanner act and look like lex */
int ascendlex(void);

void init_parse_ascend(void);
void ascend_init_lexer(FILE_T fh, FILE *nfh);
int parse_ascend(FILE_T fh, void *pd, struct ascend_phdr *phdr,
		ascend_pkthdr *hdr, int len);

#endif /* ! __ASCEND_INT_H__ */
