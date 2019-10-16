/* pcapng.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_PCAPNG_H__
#define __W_PCAPNG_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

#define PCAPNG_MAGIC         0x1A2B3C4D
#define PCAPNG_SWAPPED_MAGIC 0x4D3C2B1A

#define PCAPNG_MAJOR_VERSION 1
#define PCAPNG_MINOR_VERSION 0

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

/* pcapng: Decryption Secrets Block file encoding */
typedef struct pcapng_decryption_secrets_block_s {
    guint32 secrets_type;   /* Secrets Type, see secrets-types.h */
    guint32 secrets_len;    /* Size of variable-length secrets data. */
    /* x bytes Secrets Data. */
    /* ... Options ... */
} pcapng_decryption_secrets_block_t;

struct pcapng_option_header {
    guint16 type;
    guint16 value_length;
};

/*
 * Minimum IDB size = minimum block size + size of fixed length portion of IDB.
 */
#define MIN_IDB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_interface_description_block_t)))
#define MIN_DSB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_decryption_secrets_block_t)))

wtap_open_return_val pcapng_open(wtap *wth, int *err, gchar **err_info);
gboolean pcapng_dump_open(wtap_dumper *wdh, int *err);
int pcapng_dump_can_write_encap(int encap);

#endif
