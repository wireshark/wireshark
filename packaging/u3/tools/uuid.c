/* uuid.c
 * UUID generation 
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sysdep.h"
#include "uuid.h"

/* various forward declarations */
static int read_state(unsigned16 *clockseq, uuid_time_t *timestamp,
    uuid_node_t *node);
static void write_state(unsigned16 clockseq, uuid_time_t timestamp,
    uuid_node_t node);
static void format_uuid_v1(uuid_t *uuid, unsigned16 clockseq,
    uuid_time_t timestamp, uuid_node_t node);
static void format_uuid_v3or5(uuid_t *uuid, unsigned char hash[16],
    int v);
static void get_current_time(uuid_time_t *timestamp);
static unsigned16 true_random(void);

/* uuid_create -- generator a UUID */
int uuid_create(uuid_t *uuid)
{
     uuid_time_t timestamp, last_time;
     unsigned16 clockseq;
     uuid_node_t node;
     uuid_node_t last_node;
     int f;

     /* acquire system-wide lock so we're alone */
     LOCK;
     /* get time, node ID, saved state from non-volatile storage */
     get_current_time(&timestamp);
     get_ieee_node_identifier(&node);
     f = read_state(&clockseq, &last_time, &last_node);

     /* if no NV state, or if clock went backwards, or node ID
        changed (e.g., new network card) change clockseq */
     if (!f || memcmp(&node, &last_node, sizeof node))
         clockseq = true_random();
     else if (timestamp < last_time)
         clockseq++;

     /* save the state for next time */
     write_state(clockseq, timestamp, node);

     UNLOCK;

     /* stuff fields into the UUID */
     format_uuid_v1(uuid, clockseq, timestamp, node);
     return 1;
}

/* format_uuid_v1 -- make a UUID from the timestamp, clockseq,
                     and node ID */
void format_uuid_v1(uuid_t* uuid, unsigned16 clock_seq,
                    uuid_time_t timestamp, uuid_node_t node)
{
    /* Construct a version 1 uuid with the information we've gathered
       plus a few constants. */
    uuid->time_low = (unsigned long)(timestamp & 0xFFFFFFFF);
    uuid->time_mid = (unsigned short)((timestamp >> 32) & 0xFFFF);
    uuid->time_hi_and_version =
        (unsigned short)((timestamp >> 48) & 0x0FFF);
    uuid->time_hi_and_version |= (1 << 12);
    uuid->clock_seq_low = clock_seq & 0xFF;
    uuid->clock_seq_hi_and_reserved = (clock_seq & 0x3F00) >> 8;
    uuid->clock_seq_hi_and_reserved |= 0x80;
    memcpy(&uuid->node, &node, sizeof uuid->node);
}

/* data type for UUID generator persistent state */
typedef struct {
    uuid_time_t  ts;       /* saved timestamp */
    uuid_node_t  node;     /* saved node ID */
    unsigned16   cs;       /* saved clock sequence */
} uuid_state;

static uuid_state st;

/* read_state -- read UUID generator state from non-volatile store */
int read_state(unsigned16 *clockseq, uuid_time_t *timestamp,
               uuid_node_t *node)
{
    static int inited = 0;
    FILE *fp;

    /* only need to read state once per boot */
    if (!inited) {
        fp = fopen("state", "rb");
        if (fp == NULL)
            return 0;
        fread(&st, sizeof st, 1, fp);
        fclose(fp);
        inited = 1;
    }
    *clockseq = st.cs;
    *timestamp = st.ts;
    *node = st.node;
    return 1;
}

/* write_state -- save UUID generator state back to non-volatile
   storage */
void write_state(unsigned16 clockseq, uuid_time_t timestamp,
                 uuid_node_t node)
{
    static int inited = 0;
    static uuid_time_t next_save;
    FILE* fp;

    if (!inited) {
        next_save = timestamp;
        inited = 1;
    }

    /* always save state to volatile shared state */
    st.cs = clockseq;
    st.ts = timestamp;
    st.node = node;
    if (timestamp >= next_save) {
        fp = fopen("state", "wb");
        fwrite(&st, sizeof st, 1, fp);
        fclose(fp);
        /* schedule next save for 10 seconds from now */
        next_save = timestamp + (10 * 10 * 1000 * 1000);
    }
}

/* get-current_time -- get time as 60-bit 100ns ticks since UUID epoch.
   Compensate for the fact that real clock resolution is
   less than 100ns. */
void get_current_time(uuid_time_t *timestamp)
{
    static int inited = 0;
    static uuid_time_t time_last;
    static unsigned16 uuids_this_tick;
    uuid_time_t time_now;

    if (!inited) {
        get_system_time(&time_now);
        uuids_this_tick = UUIDS_PER_TICK;
        inited = 1;
    }

    for ( ; ; ) {
        get_system_time(&time_now);

        /* if clock reading changed since last UUID generated, */
        if (time_last != time_now) {
            /* reset count of uuids gen'd with this clock reading */
            uuids_this_tick = 0;
            time_last = time_now;
            break;
        }
        if (uuids_this_tick < UUIDS_PER_TICK) {
            uuids_this_tick++;
            break;
        }
        /* going too fast for our clock; spin */
    }
    /* add the count of uuids to low order bits of the clock reading */
    *timestamp = time_now + uuids_this_tick;
}

/* true_random -- generate a crypto-quality random number.
   **This sample doesn't do that.** */
static unsigned16 true_random(void)
{
    static int inited = 0;
    uuid_time_t time_now;

    if (!inited) {
        get_system_time(&time_now);
        time_now = time_now / UUIDS_PER_TICK;
        srand((unsigned int)
               (((time_now >> 32) ^ time_now) & 0xffffffff));
        inited = 1;
    }

    return rand();
}

/* uuid_create_md5_from_name -- create a version 3 (MD5) UUID using a
   "name" from a "name space" */
void uuid_create_md5_from_name(uuid_t *uuid, uuid_t nsid, void *name,
                               int namelen)
{
    MD5_CTX c;
    unsigned char hash[16];
    uuid_t net_nsid;

    /* put name space ID in network byte order so it hashes the same
       no matter what endian machine we're on */
    net_nsid = nsid;
    net_nsid.time_low = htonl(net_nsid.time_low);
    net_nsid.time_mid = htons(net_nsid.time_mid);
    net_nsid.time_hi_and_version = htons(net_nsid.time_hi_and_version);

    MD5Init(&c);
    MD5Update(&c, &net_nsid, sizeof net_nsid);
    MD5Update(&c, name, namelen);
    MD5Final(hash, &c);

    /* the hash is in network byte order at this point */
    format_uuid_v3or5(uuid, hash, 3);
}

void uuid_create_sha1_from_name(uuid_t *uuid, uuid_t nsid, void *name,
                                int namelen)
{
    SHA_CTX c;
    unsigned char hash[20];
    uuid_t net_nsid;

    /* put name space ID in network byte order so it hashes the same
       no matter what endian machine we're on */
    net_nsid = nsid;
    net_nsid.time_low = htonl(net_nsid.time_low);
    net_nsid.time_mid = htons(net_nsid.time_mid);
    net_nsid.time_hi_and_version = htons(net_nsid.time_hi_and_version);

    SHA1_Init(&c);
    SHA1_Update(&c, &net_nsid, sizeof net_nsid);
    SHA1_Update(&c, name, namelen);
    SHA1_Final(hash, &c);

    /* the hash is in network byte order at this point */
    format_uuid_v3or5(uuid, hash, 5);
}

/* format_uuid_v3or5 -- make a UUID from a (pseudo)random 128-bit
   number */
void format_uuid_v3or5(uuid_t *uuid, unsigned char hash[16], int v)
{
    /* convert UUID to local byte order */
    memcpy(uuid, hash, sizeof *uuid);
    uuid->time_low = ntohl(uuid->time_low);
    uuid->time_mid = ntohs(uuid->time_mid);
    uuid->time_hi_and_version = ntohs(uuid->time_hi_and_version);

    /* put in the variant and version bits */
    uuid->time_hi_and_version &= 0x0FFF;
    uuid->time_hi_and_version |= (v << 12);
    uuid->clock_seq_hi_and_reserved &= 0x3F;
    uuid->clock_seq_hi_and_reserved |= 0x80;
}

/* uuid_compare --  Compare two UUID's "lexically" and return */
#define CHECK(f1, f2) if (f1 != f2) return f1 < f2 ? -1 : 1;
int uuid_compare(uuid_t *u1, uuid_t *u2)
{
    int i;

    CHECK(u1->time_low, u2->time_low);
    CHECK(u1->time_mid, u2->time_mid);
    CHECK(u1->time_hi_and_version, u2->time_hi_and_version);
    CHECK(u1->clock_seq_hi_and_reserved, u2->clock_seq_hi_and_reserved);
    CHECK(u1->clock_seq_low, u2->clock_seq_low)
    for (i = 0; i < 6; i++) {
        if (u1->node[i] < u2->node[i])
            return -1;
        if (u1->node[i] > u2->node[i])
            return 1;
    }
    return 0;
}
#undef CHECK

