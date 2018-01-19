/* pcap_module.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __PCAP_MODULE_H__
#define __PCAP_MODULE_H__

/* Block type codes in the file */
#define BLOCK_TYPE_IDB 0x00000001 /* Interface Description Block */
#define BLOCK_TYPE_PB  0x00000002 /* Packet Block (obsolete) */
#define BLOCK_TYPE_SPB 0x00000003 /* Simple Packet Block */
#define BLOCK_TYPE_NRB 0x00000004 /* Name Resolution Block */
#define BLOCK_TYPE_ISB 0x00000005 /* Interface Statistics Block */
#define BLOCK_TYPE_EPB 0x00000006 /* Enhanced Packet Block */
#define BLOCK_TYPE_SYSDIG_EVENT 0x00000204 /* Sysdig Event Block */
#define BLOCK_TYPE_SYSDIG_EVF   0x00000208 /* Sysdig Event Block with flags */
#define BLOCK_TYPE_SHB 0x0A0D0D0A /* Section Header Block */
/* TODO: the following are not yet well defined in the draft spec:
 * Compression Block
 * Encryption Block
 * Fixed Length Block
 * Directory Block
 * Traffic Statistics and Monitoring Blocks
 * Event/Security Block
 */

/*
 * Reader and writer routines for pcapng block types.
 */
typedef gboolean (*block_reader)(FILE_T, guint32, gboolean, struct wtap_pkthdr *,
                                 Buffer *, int *, gchar **);
typedef gboolean (*block_writer)(wtap_dumper *, const struct wtap_pkthdr *,
                                 const guint8 *, int *);

/*
 * Register a handler for a pcapng block type.
 */
WS_DLL_PUBLIC
void register_pcapng_block_type_handler(guint block_type, block_reader read,
                                        block_writer write);

/*
 * Handler routine for pcapng option type.
 */
typedef gboolean (*option_handler_fn)(gboolean, guint, guint8 *, int *, gchar **);

/*
 * Register a handler for a pcapng option code for a particular block
 * type.
 */
WS_DLL_PUBLIC
void register_pcapng_option_handler(guint block_type, guint option_code,
                                    option_handler_fn hfunc);

#endif /* __PCAP_MODULE_H__ */

