/* pcap_module.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PCAP_MODULE_H__
#define __PCAP_MODULE_H__

/*
 * These are the officially registered block types, from the pcapng
 * specification.
 *
 * XXX - Dear Sysdig People: please add your blocks to the spec!
 */
#define BLOCK_TYPE_SHB              0x0A0D0D0A /* Section Header Block */
#define BLOCK_TYPE_IDB              0x00000001 /* Interface Description Block */
#define BLOCK_TYPE_PB               0x00000002 /* Packet Block (obsolete) */
#define BLOCK_TYPE_SPB              0x00000003 /* Simple Packet Block */
#define BLOCK_TYPE_NRB              0x00000004 /* Name Resolution Block */
#define BLOCK_TYPE_ISB              0x00000005 /* Interface Statistics Block */
#define BLOCK_TYPE_EPB              0x00000006 /* Enhanced Packet Block */
#define BLOCK_TYPE_IRIG_TS          0x00000007 /* IRIG Timestamp Block */
#define BLOCK_TYPE_ARINC_429        0x00000008 /* ARINC 429 in AFDX Encapsulation Information Block */
#define BLOCK_TYPE_SYSTEMD_JOURNAL  0x00000009 /* systemd journal entry */
#define BLOCK_TYPE_DSB              0x0000000A /* Decryption Secrets Block */
#define BLOCK_TYPE_SYSDIG_EVENT     0x00000204 /* Sysdig Event Block */
#define BLOCK_TYPE_SYSDIG_EVF       0x00000208 /* Sysdig Event Block with flags */
#define BLOCK_TYPE_SYSDIG_EVENT_V2  0x00000216 /* Sysdig Event Block version 2 */
#define BLOCK_TYPE_SYSDIG_EVF_V2    0x00000217 /* Sysdig Event Block with flags version 2 */

/* TODO: the following are not yet well defined in the draft spec,
 * and do not yet have block type values assigned to them:
 * Compression Block
 * Encryption Block
 * Fixed Length Block
 * Directory Block
 * Traffic Statistics and Monitoring Blocks
 * Event/Security Block
 */

/* Block data to be passed between functions during reading */
typedef struct wtapng_block_s {
    guint32      type;           /* block_type as defined by pcapng */
    gboolean     internal;       /* TRUE if this block type shouldn't be returned from pcapng_read() */
    wtap_block_t block;
    wtap_rec     *rec;
    Buffer       *frame_buffer;
} wtapng_block_t;

/*
 * Reader and writer routines for pcapng block types.
 */
typedef gboolean (*block_reader)(FILE_T fh, guint32 block_read,
                                 gboolean byte_swapped,
                                 wtapng_block_t *wblock,
                                 int *err, gchar **err_info);
typedef gboolean (*block_writer)(wtap_dumper *wdh, const wtap_rec *rec,
                                 const guint8 *pd, int *err);

/*
 * Register a handler for a pcapng block type.
 */
WS_DLL_PUBLIC
void register_pcapng_block_type_handler(guint block_type, block_reader reader,
                                        block_writer writer);

/*
 * Handler routines for pcapng option type.
 */
typedef gboolean (*option_parser)(wtap_block_t block,
                                  gboolean byte_swapped,
                                  guint option_length,
                                  const guint8 *option_content,
                                  int *err, gchar **err_info);
typedef guint32 (*option_sizer)(guint option_id, wtap_optval_t *optval);
typedef gboolean (*option_writer)(wtap_dumper *wdh, guint option_id,
                  wtap_optval_t *optval, int *err);

/*
 * Register a handler for a pcapng option code for a particular block
 * type.
 */
WS_DLL_PUBLIC
void register_pcapng_option_handler(guint block_type, guint option_code,
                                    option_parser parser,
                                    option_sizer sizer,
                                    option_writer writer);

#endif /* __PCAP_MODULE_H__ */
