/* wtap_opttypes.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
                                     *     "Broadcom NetXtreme" / "First Ethernet Interface"
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
                                     *     second offsets be useful for highly syncronized capture systems?
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
 * for them, they're identifiers used internally.
 */
typedef enum {
    WTAP_BLOCK_NG_SECTION = 0,
    WTAP_BLOCK_IF_DESCR,
    WTAP_BLOCK_NG_NRB,
    WTAP_BLOCK_IF_STATS,
    WTAP_BLOCK_END_OF_LIST
} wtap_block_type_t;

/* Currently supported option types */
typedef enum {
    WTAP_OPTTYPE_UINT8,
    WTAP_OPTTYPE_UINT64,
    WTAP_OPTTYPE_STRING,
    WTAP_OPTTYPE_IPv4,
    WTAP_OPTTYPE_IPv6,
    WTAP_OPTTYPE_CUSTOM
} wtap_opttype_e;

typedef enum {
    WTAP_OPTTYPE_SUCCESS = 0,
    WTAP_OPTTYPE_NO_SUCH_OPTION = -1,
    WTAP_OPTTYPE_NOT_FOUND = -2,
    WTAP_OPTTYPE_TYPE_MISMATCH = -3,
    WTAP_OPTTYPE_NUMBER_MISMATCH = -4,
    WTAP_OPTTYPE_ALREADY_EXISTS = -5,
} wtap_opttype_return_val;

struct wtap_opttype_custom
{
    void* data;
    guint size;
};

/*
 * Structure describing a value of an option.
 */
typedef union {
    guint8 uint8val;
    guint64 uint64val;
    guint32 ipv4val;    /* network byte order */
    struct e_in6_addr ipv6val;
    char *stringval;
    struct wtap_opttype_custom customval;
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
wtap_block_add_ipv6_option(wtap_block_t block, guint option_id, struct e_in6_addr *value);

/** Set IPv6 option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_ipv6_option_value(wtap_block_t block, guint option_id, struct e_in6_addr *value);

/** Get IPv6 option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_ipv6_option_value(wtap_block_t block, guint option_id, struct e_in6_addr* value) G_GNUC_WARN_UNUSED_RESULT;

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

/** Add a string option to a block witha printf-formatted string as its value
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

/** Add a "custom" option value to a block
 *
 * @param[in] block Block to which to add the option
 * @param[in] option_id Identifier value for option
 * @param[in] value Value of option
 * @param[in] value_size Size of value
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_add_custom_option(wtap_block_t block, guint option_id, void* value, size_t value_size);

/** Set a "custom" option value in a block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_set_custom_option_value(wtap_block_t block, guint option_id, void* value);

/** Get a "custom" option value from a block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_block_get_custom_option_value(wtap_block_t block, guint option_id, void** value) G_GNUC_WARN_UNUSED_RESULT;

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


typedef void (*wtap_block_foreach_func)(wtap_block_t block, guint option_id, wtap_opttype_e option_type, wtap_optval_t *option, void *user_data);
WS_DLL_PUBLIC void wtap_block_foreach_option(wtap_block_t block, wtap_block_foreach_func func, void* user_data);

WS_DLL_PUBLIC int wtap_opttype_register_custom_block_type(const char* name, const char* description, wtap_block_create_func create,
                                                wtap_mand_free_func free_mand, wtap_mand_copy_func copy_mand);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WTAP_OPT_TYPES_H */

