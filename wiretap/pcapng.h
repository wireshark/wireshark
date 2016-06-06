/* pcapng.h
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
 */

#ifndef __W_PCAPNG_H__
#define __W_PCAPNG_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

/* pcapng: common block header file encoding for every block type */
typedef struct pcapng_block_header_s {
    guint32 block_type;
    guint32 block_total_length;
    /* x bytes block_body */
    /* guint32 block_total_length */
} pcapng_block_header_t;

/* pcapng: section header block file encoding */
typedef struct pcapng_section_header_block_s {
    /* pcapng_block_header_t */
    guint32 magic;
    guint16 version_major;
    guint16 version_minor;
    guint64 section_length; /* might be -1 for unknown */
    /* ... Options ... */
} pcapng_section_header_block_t;

/* pcapng: interface description block file encoding */
typedef struct pcapng_interface_description_block_s {
    guint16 linktype;
    guint16 reserved;
    guint32 snaplen;
    /* ... Options ... */
} pcapng_interface_description_block_t;

/* pcapng: interface statistics block file encoding */
typedef struct pcapng_interface_statistics_block_s {
    guint32 interface_id;
    guint32 timestamp_high;
    guint32 timestamp_low;
    /* ... Options ... */
} pcapng_interface_statistics_block_t;

struct pcapng_option_header {
    guint16 type;
    guint16 value_length;
};

/*
 * Minimum IDB size = minimum block size + size of fixed length portion of IDB.
 */
#define MIN_IDB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_interface_description_block_t)))

wtap_open_return_val pcapng_open(wtap *wth, int *err, gchar **err_info);
gboolean pcapng_dump_open(wtap_dumper *wdh, int *err);
int pcapng_dump_can_write_encap(int encap);

#endif
