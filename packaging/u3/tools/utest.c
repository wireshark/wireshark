/* utest.c
 * UUID generation test harness and Wireshark Namespace UUID generation
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

/*
** Copyright (c) 1990- 1993, 1996 Open Software Foundation, Inc.
** Copyright (c) 1989 by Hewlett-Packard Company, Palo Alto, Ca. &
** Digital Equipment Corporation, Maynard, Mass.
** Copyright (c) 1998 Microsoft.
** To anyone who acknowledges that this file is provided "AS IS"
** without any express or implied warranty: permission to use, copy,
** modify, and distribute this file for any purpose is hereby
** granted without fee, provided that the above copyright notices and
** this notice appears in all source code copies, and that none of
** the names of Open Software Foundation, Inc., Hewlett-Packard
** Company, Microsoft, or Digital Equipment Corporation be used in
** advertising or publicity pertaining to distribution of the software
** without specific, written prior permission. Neither Open Software
** Foundation, Inc., Hewlett-Packard Company, Microsoft, nor Digital
** Equipment Corporation makes any representations about the
** suitability of this software for any purpose.
*/

#include "sysdep.h"
#include <stdio.h>
#include "uuid.h"

uuid_t NameSpace_DNS = { /* 6ba7b810-9dad-11d1-80b4-00c04fd430c8 */
    0x6ba7b810,
    0x9dad,
    0x11d1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
};

/* The Wireshark namespace */
uuid_t NameSpace_WS = { /* 94630be0-e031-11db-974d-0002a5d5c51b */
    0x94630be0,
    0xe031,
    0x11db,
    0x97, 0x4d, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b
};


/* puid -- print a UUID */
void puid(uuid_t u)
{
    int i;

    printf("%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", u.time_low, u.time_mid,
    u.time_hi_and_version, u.clock_seq_hi_and_reserved,
    u.clock_seq_low);
    for (i = 0; i < 6; i++)
        printf("%2.2x", u.node[i]);
}

/* Simple driver for UUID generator */
void main(int argc, char **argv)
{
    uuid_t u;
    int f;

    if(argc > 1) { 

      uuid_create_sha1_from_name(&u, NameSpace_WS, argv[1], (int)strlen(argv[1]));
      printf("s/$(UUID)/"); puid(u); printf("/\n");

      exit(0);

    } else {

      uuid_create(&u);
      printf("uuid_create(): "); puid(u); printf("\n");

      f = uuid_compare(&u, &u);
      printf("uuid_compare(u,u): %d\n", f);     /* should be 0 */
      f = uuid_compare(&u, &NameSpace_DNS);
      printf("uuid_compare(u, NameSpace_DNS): %d\n", f); /* s.b. 1 */
      f = uuid_compare(&NameSpace_DNS, &u);
      printf("uuid_compare(NameSpace_DNS, u): %d\n", f); /* s.b. -1 */
      uuid_create_md5_from_name(&u, NameSpace_DNS, "www.widgets.com", 15);
      printf("uuid_create_md5_from_name(): "); puid(u); printf("\n");

    }
}
