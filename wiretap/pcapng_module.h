/** @file
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
#define BLOCK_TYPE_SHB                    0x0A0D0D0A /* Section Header Block */
#define BLOCK_TYPE_IDB                    0x00000001 /* Interface Description Block */
#define BLOCK_TYPE_PB                     0x00000002 /* Packet Block (obsolete) */
#define BLOCK_TYPE_SPB                    0x00000003 /* Simple Packet Block */
#define BLOCK_TYPE_NRB                    0x00000004 /* Name Resolution Block */
#define BLOCK_TYPE_ISB                    0x00000005 /* Interface Statistics Block */
#define BLOCK_TYPE_EPB                    0x00000006 /* Enhanced Packet Block */
#define BLOCK_TYPE_IRIG_TS                0x00000007 /* IRIG Timestamp Block */
#define BLOCK_TYPE_ARINC_429              0x00000008 /* ARINC 429 in AFDX Encapsulation Information Block */
#define BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT 0x00000009 /* systemd journal entry */
#define BLOCK_TYPE_DSB                    0x0000000A /* Decryption Secrets Block */
#define BLOCK_TYPE_SYSDIG_MI              0x00000201 /* Sysdig Machine Info Block */
#define BLOCK_TYPE_SYSDIG_PL_V1           0x00000202 /* Sysdig Process List Block */
#define BLOCK_TYPE_SYSDIG_FDL_V1          0x00000203 /* Sysdig File Descriptor List Block */
#define BLOCK_TYPE_SYSDIG_EVENT           0x00000204 /* Sysdig Event Block */
#define BLOCK_TYPE_SYSDIG_IL_V1           0x00000205 /* Sysdig Interface List Block */
#define BLOCK_TYPE_SYSDIG_UL_V1           0x00000206 /* Sysdig User List Block */
#define BLOCK_TYPE_SYSDIG_PL_V2           0x00000207 /* Sysdig Process List Block version 2 */
#define BLOCK_TYPE_SYSDIG_EVF             0x00000208 /* Sysdig Event Block with flags */
#define BLOCK_TYPE_SYSDIG_PL_V3           0x00000209 /* Sysdig Process List Block version 3 */
#define BLOCK_TYPE_SYSDIG_PL_V4           0x00000210 /* Sysdig Process List Block version 4 */
#define BLOCK_TYPE_SYSDIG_PL_V5           0x00000211 /* Sysdig Process List Block version 5 */
#define BLOCK_TYPE_SYSDIG_PL_V6           0x00000212 /* Sysdig Process List Block version 6 */
#define BLOCK_TYPE_SYSDIG_PL_V7           0x00000213 /* Sysdig Process List Block version 7 */
#define BLOCK_TYPE_SYSDIG_PL_V8           0x00000214 /* Sysdig Process List Block version 8 */
#define BLOCK_TYPE_SYSDIG_PL_V9           0x00000215 /* Sysdig Process List Block version 9 */
#define BLOCK_TYPE_SYSDIG_EVENT_V2        0x00000216 /* Sysdig Event Block version 2 */
#define BLOCK_TYPE_SYSDIG_EVF_V2          0x00000217 /* Sysdig Event Block with flags version 2 */
#define BLOCK_TYPE_SYSDIG_FDL_V2          0x00000218 /* Sysdig File Descriptor List Block */
#define BLOCK_TYPE_SYSDIG_IL_V2           0x00000219 /* Sysdig Interface List Block version 2 */
#define BLOCK_TYPE_SYSDIG_UL_V2           0x00000220 /* Sysdig User List Block version 2 */
#define BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE  0x00000221 /* Sysdig Event Block version 2 with large payload */
#define BLOCK_TYPE_SYSDIG_EVF_V2_LARGE    0x00000222 /* Sysdig Event Block with flags version 2 with large payload */
#define BLOCK_TYPE_CB_COPY                0x00000BAD /* Custom Block which can be copied */
#define BLOCK_TYPE_CB_NO_COPY             0x40000BAD /* Custom Block which should not be copied */

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
    uint32_t     type;           /* block_type as defined by pcapng */
    bool         internal;       /* true if this block type shouldn't be returned from pcapng_read() */
    wtap_block_t block;
    wtap_rec     *rec;
    Buffer       *frame_buffer;
} wtapng_block_t;

/* Section data in private struct */
/*
 * XXX - there needs to be a more general way to implement the Netflix
 * BBLog blocks and options.
 */
typedef struct section_info_t {
    bool byte_swapped;        /**< true if this section is not in our byte order */
    uint16_t version_major;        /**< Major version number of this section */
    uint16_t version_minor;        /**< Minor version number of this section */
    GArray *interfaces;           /**< Interfaces found in this section */
    int64_t shb_off;               /**< File offset of the SHB for this section */
    uint32_t bblog_version;        /**< BBLog: version used */
    uint64_t bblog_offset_tv_sec;  /**< BBLog: UTC offset */
    uint64_t bblog_offset_tv_usec;
} section_info_t;

/*
 * Reader and writer routines for pcapng block types.
 */
typedef bool (*block_reader)(FILE_T fh, uint32_t block_read,
                                 bool byte_swapped,
                                 wtapng_block_t *wblock,
                                 int *err, char **err_info);
typedef bool (*block_writer)(wtap_dumper *wdh, const wtap_rec *rec,
                                 const uint8_t *pd, int *err);

/*
 * Register a handler for a pcapng block type.
 */
WS_DLL_PUBLIC
void register_pcapng_block_type_handler(unsigned block_type, block_reader reader,
                                        block_writer writer);

/*
 * Handler routines for pcapng option type.
 */
typedef bool (*option_parser)(wtap_block_t block,
                                  bool byte_swapped,
                                  unsigned option_length,
                                  const uint8_t *option_content,
                                  int *err, char **err_info);
typedef uint32_t (*option_sizer)(unsigned option_id, wtap_optval_t *optval);
typedef bool (*option_writer)(wtap_dumper *wdh, unsigned option_id,
                  wtap_optval_t *optval, int *err);

/*
 * Register a handler for a pcapng option code for a particular block
 * type.
 */
WS_DLL_PUBLIC
void register_pcapng_option_handler(unsigned block_type, unsigned option_code,
                                    option_parser parser,
                                    option_sizer sizer,
                                    option_writer writer);

/*
 * Byte order of the options within a block.
 *
 * This is usually the byte order of the section, but, for options
 * within a Custom Block, it needs to be a specified byte order,
 * or a byte order indicated by data in the Custom Data (stored in
 * a fashion that doesn't require knowing the byte order of the
 * Custom Data, as it's also the byte order of the Custom Data
 * itself), so that programs ignorant of the format of a given
 * type of Custom Block can still read a block from one file and
 * write it to another, even if the host doing the writing has
 * a byte order different from the host that previously wrote
 * the file.
 */
typedef enum {
    OPT_SECTION_BYTE_ORDER, /* byte order of this section */
    OPT_BIG_ENDIAN,         /* as it says */
    OPT_LITTLE_ENDIAN       /* ditto */
} pcapng_opt_byte_order_e;

/*
 * Process the options section of a block.  process_option points to
 * a routine that processes all the block-specific options, i.e.
 * options other than the end-of-options, comment, and custom
 * options.
 */
WS_DLL_PUBLIC
bool pcapng_process_options(FILE_T fh, wtapng_block_t *wblock,
                                section_info_t *section_info,
                                unsigned opt_cont_buf_len,
                                bool (*process_option)(wtapng_block_t *,
                                                           const section_info_t *,
                                                           uint16_t, uint16_t,
                                                           const uint8_t *,
                                                           int *, char **),
                                pcapng_opt_byte_order_e byte_order,
                                int *err, char **err_info);

/*
 * Helper routines to process options with types used in more than one
 * block type.
 */
WS_DLL_PUBLIC
void pcapng_process_uint8_option(wtapng_block_t *wblock,
                                 uint16_t option_code, uint16_t option_length,
                                 const uint8_t *option_content);

WS_DLL_PUBLIC
void pcapng_process_uint32_option(wtapng_block_t *wblock,
                                  const section_info_t *section_info,
                                  pcapng_opt_byte_order_e byte_order,
                                  uint16_t option_code, uint16_t option_length,
                                  const uint8_t *option_content);

WS_DLL_PUBLIC
void pcapng_process_timestamp_option(wtapng_block_t *wblock,
                                     const section_info_t *section_info,
                                     pcapng_opt_byte_order_e byte_order,
                                     uint16_t option_code, uint16_t option_length,
                                     const uint8_t *option_content);

WS_DLL_PUBLIC
void pcapng_process_uint64_option(wtapng_block_t *wblock,
                                  const section_info_t *section_info,
                                  pcapng_opt_byte_order_e byte_order,
                                  uint16_t option_code, uint16_t option_length,
                                  const uint8_t *option_content);

WS_DLL_PUBLIC
void pcapng_process_int64_option(wtapng_block_t *wblock,
                                 const section_info_t *section_info,
                                 pcapng_opt_byte_order_e byte_order,
                                 uint16_t option_code, uint16_t option_length,
                                 const uint8_t *option_content);

WS_DLL_PUBLIC
void pcapng_process_string_option(wtapng_block_t *wblock, uint16_t option_code,
                                  uint16_t option_length, const uint8_t *option_content);

WS_DLL_PUBLIC
void pcapng_process_bytes_option(wtapng_block_t *wblock, uint16_t option_code,
                                 uint16_t option_length, const uint8_t *option_content);

#endif /* __PCAP_MODULE_H__ */
