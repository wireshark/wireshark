/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PCAP_MODULE_H__
#define __PCAP_MODULE_H__

#include <wiretap/wtap_module.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
#define BLOCK_TYPE_HP_MIB                 0x00000101 /* Hone Project Machine Info Block */
#define BLOCK_TYPE_HP_CEB                 0x00000102 /* Hone Project Connection Event Block */
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
#define BLOCK_TYPE_LEGACY_DPIB            0x80000001 /* Historically, Apple used this code for Darwin Process Info Block. */

/* TODO: the following are not yet well defined in the draft spec,
 * and do not yet have block type values assigned to them:
 * Alternative Packet Blocks
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
} wtapng_block_t;

/* Section data in private struct */
/*
 * XXX - there needs to be a more general way to implement the Netflix
 * BBLog blocks and options.
 */
typedef struct section_info_t {
    bool byte_swapped;             /**< true if this section is not in the reading host's byte order */
    uint16_t version_major;        /**< Major version number of this section */
    uint16_t version_minor;        /**< Minor version number of this section */
    GArray *interfaces;            /**< Interfaces found in this section */
    int64_t shb_off;               /**< File offset of the SHB for this section */
    GHashTable *custom_block_data; /**< Table, indexed by PEN, for custom block data */
    GHashTable *local_block_data;  /**< Table, indexed by block type, for local block data */
} section_info_t;

/*
 * Reader and writer routines for pcapng block types.
 */
typedef bool (*block_reader)(wtap* wth, FILE_T fh, uint32_t block_type,
                             uint32_t block_content_length,
                             section_info_t* section_info,
                             wtapng_block_t *wblock,
                             int *err, char **err_info);
typedef bool (*block_writer)(wtap_dumper *wdh, const wtap_rec *rec,
                             int *err, char **err_info);
typedef bool (*block_processor)(wtap* wth, section_info_t* section_info _U_,
                                wtapng_block_t* wblock);


typedef struct pcapng_block_type_information_t {
    unsigned     type;             /* block_type as defined by pcapng */
    block_reader reader;
    block_processor processor;
    block_writer writer;
    bool         internal;         /* true if this block type shouldn't be returned from pcapng_read() */
    GHashTable   *option_handlers; /* Hash table of option handlers */
} pcapng_block_type_information_t;

/**
 * @brief Register a handler for a pcapng block type.
 *
 * @param handler Pointer to a structure containing the block type information and handler functions.
 */
WS_DLL_PUBLIC
void register_pcapng_block_type_information(pcapng_block_type_information_t* handler);

/*
 * Handler routines for pcapng option type.
 */
typedef bool (*option_parser)(wtap_block_t block, bool byte_swapped,
                              unsigned option_length,
                              const uint8_t *option_content,
                              int *err, char **err_info);
typedef uint32_t (*option_sizer)(unsigned option_id, wtap_optval_t *optval);
typedef bool (*option_writer)(wtap_dumper *wdh, unsigned option_id,
                              wtap_optval_t *optval, int *err);

/**
 * @brief Create a table of handlers for pcapng option codes.
 * @return GHashTable* A hash table of option handlers.
 */
WS_DLL_PUBLIC
GHashTable *pcapng_create_option_handler_table(void);

/**
 * @brief Register a handler for a pcapng option code for a particular block
 * type.
 *
 * @param block_type The block type that this option handler is for.
 * @param option_code The option code that this handler is for.
 * @param parser The function to call to parse this option when reading a file.
 * @param sizer The function to call to determine the size of this option when writing a file.
 * @param writer The function to call to write this option when writing a file.
 */
WS_DLL_PUBLIC
void register_pcapng_option_handler(unsigned block_type, unsigned option_code,
                                    option_parser parser,
                                    option_sizer sizer,
                                    option_writer writer);

/**
 * @brief Byte order of the options within a block.
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
    OPT_SECTION_BYTE_ORDER, /**< byte order of this section */
    OPT_BIG_ENDIAN,         /**< big-endian byte order */
    OPT_LITTLE_ENDIAN       /**< little-endian byte order */
} pcapng_opt_byte_order_e;

/**
 * @brief Process the options section of a block.
 *
 * @param fh File handle.
 * @param wblock Pointer to the pcapng block.
 * @param section_info Pointer to the section information.
 * @param opt_cont_buf_len Length of the option content buffer.
 * @param process_option Function to process each option.
 * @param byte_order Byte order of the option content.
 * @param err Pointer to an integer where any error code will be stored on failure.
 * @param err_info Pointer to a string where error information will be stored on failure.
 * @return true if the options were processed successfully, false otherwise.
 */
WS_DLL_PUBLIC
bool pcapng_process_options(FILE_T fh, wtapng_block_t *wblock,
                            section_info_t *section_info,
                            unsigned opt_cont_buf_len,
                            bool (*process_option)(wtapng_block_t *,
                                                   section_info_t *,
                                                   uint16_t, uint16_t,
                                                   const uint8_t *,
                                                   int *, char **),
                            pcapng_opt_byte_order_e byte_order,
                            int *err, char **err_info);

/**
 * @brief Helper routines to process options with types used in more than one
 * block type.
 *
 * @param wblock Pointer to the pcapng block containing the option.
 * @param option_code Code identifying the option.
 * @param option_length Length of the option content in bytes.
 * @param option_content Pointer to the content of the option.
 */
WS_DLL_PUBLIC
void pcapng_process_uint8_option(wtapng_block_t *wblock,
                                 uint16_t option_code, uint16_t option_length,
                                 const uint8_t *option_content);

/**
 * @brief Process a 32-bit unsigned integer option in a PCAPNG block.
 *
 * @param wblock Pointer to the pcapng block containing the option.
 * @param section_info Pointer to the section information structure.
 * @param byte_order Byte order of the option content.
 * @param option_code Code identifying the option.
 * @param option_length Length of the option content in bytes.
 * @param option_content Pointer to the content of the option.
 */
WS_DLL_PUBLIC
void pcapng_process_uint32_option(wtapng_block_t *wblock,
                                  section_info_t *section_info,
                                  pcapng_opt_byte_order_e byte_order,
                                  uint16_t option_code, uint16_t option_length,
                                  const uint8_t *option_content);

/**
 * @brief Process a timestamp option in a PCAPng block.
 *
 * @param wblock Pointer to the PCAPng block.
 * @param section_info Pointer to the section information.
 * @param byte_order Byte order of the option content.
 * @param option_code Code of the option.
 * @param option_length Length of the option content.
 * @param option_content Content of the option.
 */
WS_DLL_PUBLIC
void pcapng_process_timestamp_option(wtapng_block_t *wblock,
                                     section_info_t *section_info,
                                     pcapng_opt_byte_order_e byte_order,
                                     uint16_t option_code, uint16_t option_length,
                                     const uint8_t *option_content);

/**
 * @brief Process a 64-bit unsigned integer option in a PCAP-NG block.
 *
 * @param wblock Pointer to the current PCAP-NG block.
 * @param section_info Pointer to the section information.
 * @param byte_order Byte order of the option content.
 * @param option_code Code identifying the option.
 * @param option_length Length of the option content in bytes.
 * @param option_content Pointer to the content of the option.
 */
WS_DLL_PUBLIC
void pcapng_process_uint64_option(wtapng_block_t *wblock,
                                  section_info_t *section_info,
                                  pcapng_opt_byte_order_e byte_order,
                                  uint16_t option_code, uint16_t option_length,
                                  const uint8_t *option_content);

/**
 * @brief Process a 64-bit integer option in a PCAPNG block.
 *
 * @param wblock Pointer to the PCAPNG block.
 * @param section_info Pointer to the section information.
 * @param byte_order Byte order of the option content.
 * @param option_code Code of the option.
 * @param option_length Length of the option content.
 * @param option_content Pointer to the option content.
 */
WS_DLL_PUBLIC
void pcapng_process_int64_option(wtapng_block_t *wblock,
                                 section_info_t *section_info,
                                 pcapng_opt_byte_order_e byte_order,
                                 uint16_t option_code, uint16_t option_length,
                                 const uint8_t *option_content);

/**
 * @brief Process a string option in a PCAPNG block.
 *
 * @param wblock Pointer to the wtapng_block_t structure.
 * @param option_code The code of the option.
 * @param option_length The length of the option content.
 * @param option_content The content of the option as bytes.
 */
WS_DLL_PUBLIC
void pcapng_process_string_option(wtapng_block_t *wblock, uint16_t option_code,
                                  uint16_t option_length, const uint8_t *option_content);

/**
 * @brief Processes a bytes option in a PCAPng block.
 *
 * @param wblock Pointer to the PCAPng block.
 * @param option_code The code of the option.
 * @param option_length The length of the option content.
 * @param option_content Pointer to the content of the option.
 */
WS_DLL_PUBLIC
void pcapng_process_bytes_option(wtapng_block_t *wblock, uint16_t option_code,
                                 uint16_t option_length, const uint8_t *option_content);

typedef uint32_t (*compute_option_size_func)(wtap_block_t, unsigned, wtap_opttype_e, wtap_optval_t*);

typedef struct compute_options_size_t
{
    uint32_t size;
    compute_option_size_func compute_option_size;
} compute_options_size_t;

/**
 * @brief Computes the total size of all options in a PCAPNG block.
 *
 * @param block The wtap_block_t containing the options to compute.
 * @param compute_option_size A function pointer to compute the size of each option.
 * @return uint32_t The total size of all options, including the End-of-options tag if applicable.
 */
WS_DLL_PUBLIC
uint32_t pcapng_compute_options_size(wtap_block_t block, compute_option_size_func compute_option_size);

typedef bool (*write_option_func)(wtap_dumper *wdh, wtap_block_t block,
                                  unsigned option_id,
                                  wtap_opttype_e option_type,
                                  wtap_optval_t *optval,
                                  int *err, char **err_info);

/**
 * @brief Writes options to a pcapng file.
 *
 * @param wdh Pointer to the wtap_dumper structure.
 * @param byte_order Byte order of the options.
 * @param block Block containing the options.
 * @param write_option Function pointer to write an option.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC
bool pcapng_write_options(wtap_dumper *wdh, pcapng_opt_byte_order_e byte_order,
                          wtap_block_t block, write_option_func write_option,
                          int *err, char **err_info);

/*
 * Handler routines for pcapng custom blocks with an enterprise number.
 */
typedef bool (*custom_option_parser)(FILE_T fh, section_info_t* section_info,
    wtapng_block_t* wblock,
    int* err, char** err_info);
typedef bool (*custom_option_processor)(wtapng_block_t* wblock,
    section_info_t* section_info, uint16_t option_code,
    const uint8_t* value, uint16_t length);

typedef struct pcapng_custom_block_enterprise_handler_t
{
    custom_option_parser parser;
    custom_option_processor processor;
    block_writer writer;
} pcapng_custom_block_enterprise_handler_t;

/*
 * Register a handler for a pcapng custom block with an enterprise number.
 */
/**
 * @brief Register a handler for a pcapng custom block with an enterprise number.
 *
 * @param enterprise_number The enterprise number associated with the custom block.
 * @param handler Pointer to the custom block enterprise handler structure.
 */
WS_DLL_PUBLIC
void register_pcapng_custom_block_enterprise_handler(unsigned enterprise_number, pcapng_custom_block_enterprise_handler_t const * handler);

/*
 * Helper routines for modules.
 */

/*
 * Write block header.
 */
/**
 * @brief Write a pcapng block header.
 *
 * @param wdh Pointer to the wtap_dumper structure.
 * @param block_type The type of the block.
 * @param block_content_length Length of the block content.
 * @param err Pointer to an integer where an error code will be stored if an error occurs.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC
bool pcapng_write_block_header(wtap_dumper *wdh, uint32_t block_type,
                               uint32_t block_content_length, int *err);

/*
 * Write padding after a chunk of data.
 */
/**
 * @brief Writes padding to a pcapng file.
 *
 * @param wdh Pointer to the wtap_dumper structure.
 * @param pad The amount of padding to write.
 * @param err Pointer to an integer where any error code will be stored.
 * @return true if successful, false otherwise.
 */
static inline bool
pcapng_write_padding(wtap_dumper *wdh, size_t pad, int *err)
{
    if (pad != 0) {
        const uint32_t zero_pad = 0;
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return false;
    }

    return true;
}

/*
 * Write block footer.
 */
/**
 * @brief Writes a block footer for a PCAPNG file.
 *
 * @param wdh Pointer to the wtap_dumper structure.
 * @param block_content_length Length of the block content.
 * @param err Pointer to an integer that will hold any error code.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC
bool pcapng_write_block_footer(wtap_dumper *wdh, uint32_t block_content_length,
                               int *err);

/*
 * Structure holding allocation-and-initialization and free functions
 * for section_info_t-associated custom or local block information.
 */
typedef struct {
    void *(*provision)(void);
    GDestroyNotify free;
} section_info_funcs_t;

/*
 * Find custom block information from a section_info_t; add a
 * newly-created one and return it if none is found.
 */
/**
 * @brief Find local block information from a section_info_t; add a newly-created one and return it if none is found.
 *
 * @param section_info Pointer to the section_info_t structure.
 * @param pen The Pen number for the custom block data.
 * @param funcs Pointer to the section_info_funcs_t structure containing function pointers for freeing custom block data.
 * @return Pointer to the custom block data, or NULL if not found and no new data was created.
 */
WS_DLL_PUBLIC
void *pcapng_get_cb_section_info_data(section_info_t *section_info,
                                      uint32_t pen,
                                      const section_info_funcs_t *funcs);

/**
 * @brief Find local block information from a section_info_t; add a
 * newly-created one and return it if none is found.
 *
 * @param section_info Pointer to the section_info_t structure.
 * @param block_type The block type for the local block data.
 * @param funcs Pointer to the section_info_funcs_t structure containing function pointers for freeing local block data.
 * @return Pointer to the local block data, or NULL if not found and no new data was created.
 */
WS_DLL_PUBLIC
void *pcapng_get_lb_section_info_data(section_info_t *section_info,
                                      uint32_t block_type,
                                      const section_info_funcs_t *funcs);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PCAP_MODULE_H__ */
