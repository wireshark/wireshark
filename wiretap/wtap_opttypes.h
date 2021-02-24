/* wtap_opttypes.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WTAP_OPT_TYPES_H
#define WTAP_OPT_TYPES_H

#include "ws_symbol_export.h"

#include <wsutil/inet_ipv6.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * We use the pcapng option codes for option type values.
 */

/* Options for all blocks */
#define OPT_EOFOPT           0     /**< Appears in pcapng files, but not in blocks. */
#define OPT_COMMENT          1     /**< A UTF-8 string containing a human-readable comment. */

/* Section Header block (SHB) */
#define OPT_SHB_HARDWARE     2     /**< A UTF-8 string containing the description of the
                                     *     hardware used to create this section.
                                     */
#define OPT_SHB_OS           3     /**< A UTF-8 string containing the
                                     *     name of the operating system used to create this section.
                                     */
#define OPT_SHB_USERAPPL     4     /**< A UTF-8 string containing the
                                     *     name of the application used to create this section.
                                     */

/* Interface Description block (IDB) */
#define OPT_IDB_NAME         2     /**< A UTF-8 string containing the name
                                     *     of the device used to capture data.
                                     *     "eth0" / "\Device\NPF_{AD1CE675-96D0-47C5-ADD0-2504B9126B68}"
                                     */
#define OPT_IDB_DESCR        3     /**< A UTF-8 string containing the description
                                     *     of the device used to capture data.
                                     *     "Wi-Fi" / "Local Area Connection" /
                                     *     "Wireless Network Connection" /
                                     *     "First Ethernet Interface"
                                     */
#define OPT_IDB_IP4ADDR      4     /**< XXX: if_IPv4addr Interface network address and netmask.
                                     *     This option can be repeated multiple times within the same Interface Description Block
                                     *     when multiple IPv4 addresses are assigned to the interface.
                                     *     192 168 1 1 255 255 255 0
                                     */
#define OPT_IDB_IP6ADDR      5     /* XXX: if_IPv6addr Interface network address and prefix length (stored in the last byte).
                                     *     This option can be repeated multiple times within the same Interface
                                     *     Description Block when multiple IPv6 addresses are assigned to the interface.
                                     *     2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is written (in hex) as
                                     *     "20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44 40"*/
#define OPT_IDB_MACADDR      6     /* XXX: if_MACaddr  Interface Hardware MAC address (48 bits).                             */
#define OPT_IDB_EUIADDR      7     /* XXX: if_EUIaddr  Interface Hardware EUI address (64 bits)                              */
#define OPT_IDB_SPEED        8     /**< Interface speed (in bps). 100000000 for 100Mbps
                                     */
#define OPT_IDB_TSRESOL      9     /**< Resolution of timestamps. If the Most Significant Bit is equal to zero,
                                     *     the remaining bits indicates the resolution of the timestamp as as a
                                     *     negative power of 10 (e.g. 6 means microsecond resolution, timestamps
                                     *     are the number of microseconds since 1/1/1970). If the Most Significant Bit
                                     *     is equal to one, the remaining bits indicates the resolution has a
                                     *     negative power of 2 (e.g. 10 means 1/1024 of second).
                                     *     If this option is not present, a resolution of 10^-6 is assumed
                                     *     (i.e. timestamps have the same resolution of the standard 'libpcap' timestamps).
                                     */
#define OPT_IDB_TZONE        10    /* XXX: if_tzone    Time zone for GMT support (TODO: specify better). */
#define OPT_IDB_FILTER       11    /**< The filter (e.g. "capture only TCP traffic") used to capture traffic.
                                     *     The first byte of the Option Data keeps a code of the filter used
                                     *     (e.g. if this is a libpcap string, or BPF bytecode, and more).
                                     *     More details about this format will be presented in Appendix XXX (TODO).
                                     *     (TODO: better use different options for different fields?
                                     *     e.g. if_filter_pcap, if_filter_bpf, ...) 00 "tcp port 23 and host 10.0.0.5"
                                     */
#define OPT_IDB_OS           12    /**< A UTF-8 string containing the name of the operating system of the
                                     *     machine in which this interface is installed.
                                     *     This can be different from the same information that can be
                                     *     contained by the Section Header Block
                                     *     (Section 3.1 (Section Header Block (mandatory))) because
                                     *     the capture can have been done on a remote machine.
                                     *     "Windows XP SP2" / "openSUSE 10.2"
                                     */
#define OPT_IDB_FCSLEN       13    /**< An integer value that specified the length of the
                                     *     Frame Check Sequence (in bits) for this interface.
                                     *     For link layers whose FCS length can change during time,
                                     *     the Packet Block Flags Word can be used (see Appendix A (Packet Block Flags Word))
                                     */
#define OPT_IDB_TSOFFSET     14    /**< XXX: A 64 bits integer value that specifies an offset (in seconds)
                                     *     that must be added to the timestamp of each packet to obtain
                                     *     the absolute timestamp of a packet. If the option is missing,
                                     *     the timestamps stored in the packet must be considered absolute
                                     *     timestamps. The time zone of the offset can be specified with the
                                     *     option if_tzone. TODO: won't a if_tsoffset_low for fractional
                                     *     second offsets be useful for highly synchronized capture systems?
                                     */
#define OPT_IDB_HARDWARE     15     /**< A UTF-8 string containing the description
                                     *     of the hardware of the device used
                                     *     to capture data.
                                     *     "Broadcom NetXtreme" /
                                     *     "Intel(R) PRO/1000 MT Network Connection" /
                                     *     "NETGEAR WNA1000Mv2 N150 Wireless USB Micro Adapter"
                                     */


#define OPT_NS_DNSNAME       2
#define OPT_NS_DNSIP4ADDR    3
#define OPT_NS_DNSIP6ADDR    4

#define OPT_ISB_STARTTIME    2
#define OPT_ISB_ENDTIME      3
#define OPT_ISB_IFRECV       4
#define OPT_ISB_IFDROP       5
#define OPT_ISB_FILTERACCEPT 6
#define OPT_ISB_OSDROP       7
#define OPT_ISB_USRDELIV     8

struct wtap_block;
typedef struct wtap_block *wtap_block_t;

/*
 * Currently supported blocks; these are not the pcapng block type values
 * for them, they're identifiers used internally, and more than one
 * pcapng block type may use a given block type.
 *
 * Note that, in a given file format, this information won't necessarily
 * appear in the form of blocks in the file, even though they're presented
 * to the caller of libwiretap as blocks when reading and and are presented
 * by the caller of libwiretap as blocks when writing.  See, for example,
 * the iptrace file format, in which the interface name is given as part
 * of the packet record header; we synthesize those blocks when reading
 * (we don't currently support writing that format, but if we did, we'd
 * get the interface name from the block and put it in the packet record
 * header).
 *
 * WTAP_BLOCK_IF_ID_AND_INFO is a block that not only gives
 * descriptive information about an interface but *also* assigns an
 * ID to the interface, so that every packet has either an explicit
 * or implicit interface ID indicating on which the packet arrived.
 *
 * It does *not* refer to information about interfaces that does not
 * allow identification of the interface on which a packet arrives
 * (I'm looking at *you*, Microsoft Network Monitor...).  Do *not*
 * indicate support for that block if your capture format merely
 * gives a list of interface information without having every packet
 * explicitly or implicitly (as in, for example, the pcapng Simple
 * Packet Block) indicate on which of those interfaces the packet
 * arrived.
 *
 * WTAP_BLOCK_PACKET (which corresponds to the Enhanced Packet Block,
 * the Simple Packet Block, and the deprecated Packet Block) is not
 * currently used; it's reserved for future use.  The same applies
 * to WTAP_BLOCK_SYSTEMD_JOURNAL.
 */
typedef enum {
    WTAP_BLOCK_SECTION = 0,
    WTAP_BLOCK_IF_ID_AND_INFO,
    WTAP_BLOCK_NAME_RESOLUTION,
    WTAP_BLOCK_IF_STATISTICS,
    WTAP_BLOCK_DECRYPTION_SECRETS,
    WTAP_BLOCK_PACKET,
    WTAP_BLOCK_FT_SPECIFIC_REPORT,
    WTAP_BLOCK_FT_SPECIFIC_EVENT,
    WTAP_BLOCK_SYSTEMD_JOURNAL,
    MAX_WTAP_BLOCK_TYPE_VALUE
} wtap_block_type_t;

/**
 * Holds the required data from a WTAP_BLOCK_SECTION.
 */
typedef struct wtapng_section_mandatory_s {
    guint64             section_length; /**< 64-bit value specifying the length in bytes of the
                                         *     following section.
                                         *     Section Length equal -1 (0xFFFFFFFFFFFFFFFF) means
                                         *     that the size of the section is not specified
                                         *   Note: if writing to a new file, this length will
                                         *     be invalid if anything changes, such as the other
                                         *     members of this struct, or the packets written.
                                         */
} wtapng_mandatory_section_t;

/** struct holding the information to build an WTAP_BLOCK_IF_ID_AND_INFO.
 *  the interface_data array holds an array of wtap_block_t
 *  representing interfacs, one per interface.
 */
typedef struct wtapng_iface_descriptions_s {
    GArray *interface_data;
} wtapng_iface_descriptions_t;

/**
 * Holds the required data from a WTAP_BLOCK_IF_ID_AND_INFO.
 */
typedef struct wtapng_if_descr_mandatory_s {
    int                    wtap_encap;            /**< link_type translated to wtap_encap */
    guint64                time_units_per_second;
    int                    tsprecision;           /**< WTAP_TSPREC_ value for this interface */

    guint32                snap_len;

    guint8                 num_stat_entries;
    GArray                *interface_statistics;  /**< An array holding the interface statistics from
                                                   *     pcapng ISB:s or equivalent(?)*/
} wtapng_if_descr_mandatory_t;

/**
 * Holds the required data from a WTAP_BLOCK_IF_STATISTICS.
 */
typedef struct wtapng_if_stats_mandatory_s {
    guint32  interface_id;
    guint32  ts_high;
    guint32  ts_low;
} wtapng_if_stats_mandatory_t;

/**
 * Holds the required data from a WTAP_BLOCK_DECRYPTION_SECRETS.
 */
typedef struct wtapng_dsb_mandatory_s {
    guint32                secrets_type;            /** Type of secrets stored in data (see secrets-types.h) */
    guint32                secrets_len;             /** Length of the secrets data in bytes */
    guint8                *secrets_data;            /** Buffer of secrets (not NUL-terminated) */
} wtapng_dsb_mandatory_t;

/**
 * Holds the required data from a WTAP_BLOCK_FT_SPECIFIC_REPORT.
 */
typedef struct wtapng_ft_specific_mandatory_s {
    guint     record_type;      /* the type of record this is - file type-specific value */
} wtapng_ft_specific_mandatory_t;

/* Currently supported option types */
typedef enum {
    WTAP_OPTTYPE_UINT8,
    WTAP_OPTTYPE_UINT64,
    WTAP_OPTTYPE_STRING,
    WTAP_OPTTYPE_IPv4,
    WTAP_OPTTYPE_IPv6,
    WTAP_OPTTYPE_IF_FILTER
} wtap_opttype_e;

typedef enum {
    WTAP_OPTTYPE_SUCCESS = 0,
    WTAP_OPTTYPE_NO_SUCH_OPTION = -1,
    WTAP_OPTTYPE_NOT_FOUND = -2,
    WTAP_OPTTYPE_TYPE_MISMATCH = -3,
    WTAP_OPTTYPE_NUMBER_MISMATCH = -4,
    WTAP_OPTTYPE_ALREADY_EXISTS = -5
} wtap_opttype_return_val;

/* Interface description data - if_filter option structure */

/* BPF instruction */
typedef struct wtap_bpf_insn_s {
    guint16                code;
    guint8                 jt;
    guint8                 jf;
    guint32                k;
} wtap_bpf_insn_t;

/*
 * Type of filter.
 */
typedef enum {
    if_filter_pcap = 0, /* pcap filter string */
    if_filter_bpf  = 1  /* BPF program */
} if_filter_type_e;

typedef struct if_filter_opt_s {
    if_filter_type_e type;
    union {
        gchar             *filter_str;   /**< pcap filter string */
        struct wtap_bpf_insns {
            guint          bpf_prog_len; /**< number of BPF instructions */
            wtap_bpf_insn_t *bpf_prog;   /**< BPF instructions */
        }                  bpf_prog;     /**< BPF program */
    }                      data;
} if_filter_opt_t;

/*
 * Structure describing a value of an option.
 */
typedef union {
    guint8 uint8val;
    guint64 uint64val;
    guint32 ipv4val;    /* network byte order */
    ws_in6_addr ipv6val;
    char *stringval;
    if_filter_opt_t if_filterval;
} wtap_optval_t;

/*
 * Structure describing an option in a block.
 */
typedef struct {
    guint option_id;     /**< option code for the option */
    wtap_optval_t value; /**< value */
} wtap_option_t;

struct wtap_dumper;

typedef void (*wtap_block_create_func)(wtap_block_t block);
typedef void (*wtap_mand_free_func)(wtap_block_t block);
typedef void (*wtap_mand_copy_func)(wtap_block_t dest_block, wtap_block_t src_block);

/** Initialize block types.
 *
 * This is currently just a placeholder as nothing needs to be
 * initialized yet.  Should handle "registration" when code is
 * refactored to do so.
 */
WS_DLL_PUBLIC void wtap_opttypes_initialize(void);

/** Create a block by type
 *
 * Return a newly allocated block with default options provided
 *
 * @param[in] block_type Block type to be created
 * @return Newly allocated block
 */
WS_DLL_PUBLIC wtap_block_t wtap_block_create(wtap_block_type_t block_type);

/** Free a block
 *
 * Needs to be called to clean up any allocated block
 *
 * @param[in] block Block to be freed
 */
WS_DLL_PUBLIC void wtap_block_free(wtap_block_t block);

/** Free an array of blocks
 *
 * Needs to be called to clean up blocks allocated
 * through GArray (for multiple blocks of same type)
 * Includes freeing the GArray
 *
 * @param[in] block_array Array of blocks to be freed
 */
WS_DLL_PUBLIC void wtap_block_array_free(GArray* block_array);

/** Provide type of a block
 *
 * @param[in] block Block from which to retrieve mandatory data
 * @return Block type.
 */
WS_DLL_PUBLIC wtap_block_type_t wtap_block_get_type(wtap_block_t block);

/** Provide mandatory data of a block
 *
 * @param[in] block Block from which to retrieve mandatory data
 * @return Block mandatory data.  Structure varies based on block type
 */
WS_DLL_PUBLIC void* wtap_block_get_mandatory_data(wtap_block_t block);

/** Add UINT8 option value to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] value Value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_uint8_option(wtap_block_t block, guint option_id, guint8 value);

/** Set UINT8 option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_uint8_option_value(wtap_block_t block, guint option_id, guint8 value);

/** Get UINT8 option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_uint8_option_value(wtap_block_t block, guint option_id, guint8* value) G_GNUC_WARN_UNUSED_RESULT;

/** Add UINT64 option value to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] value Value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_uint64_option(wtap_block_t block, guint option_id, guint64 value);

/** Set UINT64 option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_uint64_option_value(wtap_block_t block, guint option_id, guint64 value);

/** Get UINT64 option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_uint64_option_value(wtap_block_t block, guint option_id, guint64* value) G_GNUC_WARN_UNUSED_RESULT;

/** Add IPv4 address option value to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] value Value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_ipv4_option(wtap_block_t block, guint option_id, guint32 value);

/** Set IPv4 option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_ipv4_option_value(wtap_block_t block, guint option_id, guint32 value);

/** Get IPv4 option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_ipv4_option_value(wtap_block_t block, guint option_id, guint32* value) G_GNUC_WARN_UNUSED_RESULT;

/** Add IPv6 address option value to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] value Value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_ipv6_option(wtap_block_t block, guint option_id, ws_in6_addr *value);

/** Set IPv6 option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_ipv6_option_value(wtap_block_t block, guint option_id, ws_in6_addr *value);

/** Get IPv6 option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_ipv6_option_value(wtap_block_t block, guint option_id, ws_in6_addr* value) G_GNUC_WARN_UNUSED_RESULT;

/** Add a string option to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] value Value of option
 * @param[in] value_length Maximum length of string to copy.
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_string_option(wtap_block_t block, guint option_id, const char *value, gsize value_length);

/** Add a string option to a block with a printf-formatted string as its value
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] format printf-like format string
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_string_option_format(wtap_block_t block, guint option_id, const char *format, ...)
                                    G_GNUC_PRINTF(3,4);

/** Set string option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @param[in] value_length Maximum length of string to copy.
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_string_option_value(wtap_block_t block, guint option_id, const char* value, gsize value_length);

/** Set string option value for nth instance of a particular option in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] idx Instance number of option with that ID
 * @param[in] value New value of option
 * @param[in] value_length Maximum length of string to copy.
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_nth_string_option_value(wtap_block_t block, guint option_id, guint idx, const char* value, gsize value_length);

/** Set string option value in a block to a printf-formatted string
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] format printf-like format string
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_string_option_value_format(wtap_block_t block, guint option_id, const char *format, ...)
                                          G_GNUC_PRINTF(3,4);

/** Set string option value for nth instance of a particular option in a block
 * to a printf-formatted string
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] idx Instance number of option with that ID
 * @param[in] format printf-like format string
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_nth_string_option_value_format(wtap_block_t block, guint option_id, guint idx, const char *format, ...)
                                              G_GNUC_PRINTF(4,5);

/** Get string option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_string_option_value(wtap_block_t block, guint option_id, char** value) G_GNUC_WARN_UNUSED_RESULT;

/** Get string option value for nth instance of a particular option in a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[in] idx Instance number of option with that ID
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_nth_string_option_value(wtap_block_t block, guint option_id, guint idx, char** value) G_GNUC_WARN_UNUSED_RESULT;

/** Add an if_filter option value to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] value Value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_if_filter_option(wtap_block_t block, guint option_id, if_filter_opt_t* value);

/** Set an if_filter option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_if_filter_option_value(wtap_block_t block, guint option_id, if_filter_opt_t* value);

/** Get an if_filter option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option value
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_if_filter_option_value(wtap_block_t block, guint option_id, if_filter_opt_t* value) G_GNUC_WARN_UNUSED_RESULT;

/** Remove an option from a block
 *
 * @param[in] block Block from which to remove the option
 * @param[in] option_id Identifier value for option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_remove_option(wtap_block_t block, guint option_id);

/** Remove the nth instance of an option from a block
 *
 * @param[in] block Block from which to remove the option instance
 * @param[in] option_id Identifier value for option
 * @param[in] idx Instance number of option with that ID
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_remove_nth_option_instance(wtap_block_t block, guint option_id,
                                      guint idx);

/** Copy a block to another.
 *
 * Any options that are in the destination but not the source are not removed.
 * Options that are just in source will be added to destination
 *
 * @param[in] dest_block Block to be copied to
 * @param[in] src_block Block to be copied from
 */
WS_DLL_PUBLIC void wtap_block_copy(wtap_block_t dest_block, wtap_block_t src_block);

/** Make a copy of a block.
 *
 * @param[in] block Block to be copied from
 * @return Newly allocated copy of that block
 */
WS_DLL_PUBLIC wtap_block_t wtap_block_make_copy(wtap_block_t block);

typedef void (*wtap_block_foreach_func)(wtap_block_t block, guint option_id, wtap_opttype_e option_type, wtap_optval_t *option, void *user_data);
WS_DLL_PUBLIC void wtap_block_foreach_option(wtap_block_t block, wtap_block_foreach_func func, void* user_data);

/** Cleanup the internal structures
 */
WS_DLL_PUBLIC void wtap_opttypes_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WTAP_OPT_TYPES_H */
