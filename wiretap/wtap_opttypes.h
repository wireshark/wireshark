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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * We use the pcapng option codes for option type values.
 */
#define OPT_EOFOPT           0x0000 /**< Appears in pcapng files, but not in option blocks. */
#define OPT_COMMENT          0x0001 /**< NULL if not available */

/* Section Header block (SHB) */
#define OPT_SHB_HARDWARE     0x0002 /**< NULL if not available
                                     *     UTF-8 string containing the description of the
                                     *     hardware used to create this section.
                                     */
#define OPT_SHB_OS           0x0003 /**< NULL if not available, UTF-8 string containing the
                                     *     name of the operating system used to create this section.
                                     */
#define OPT_SHB_USERAPPL     0x0004 /**< NULL if not available, UTF-8 string containing the
                                     *     name of the application used to create this section.
                                     */

/* Interface Description block (IDB) */
#define OPT_IDB_NAME         0x0002 /**< NULL if not available, A UTF-8 string containing the name
                                     *     of the device used to capture data.
                                     *     "eth0" / "\Device\NPF_{AD1CE675-96D0-47C5-ADD0-2504B9126B68}"
                                     */
#define OPT_IDB_DESCR        0x0003 /**< NULL if not available, A UTF-8 string containing the description
                                     *     of the device used to capture data.
                                     *     "Broadcom NetXtreme" / "First Ethernet Interface"
                                     */
#define OPT_IDB_IP4ADDR      0x0004 /**< XXX: if_IPv4addr Interface network address and netmask.
                                     *     This option can be repeated multiple times within the same Interface Description Block
                                     *     when multiple IPv4 addresses are assigned to the interface.
                                     *     192 168 1 1 255 255 255 0
                                     */
#define OPT_IDB_IP6ADDR      0x0005 /* XXX: if_IPv6addr Interface network address and prefix length (stored in the last byte).
                                     *     This option can be repeated multiple times within the same Interface
                                     *     Description Block when multiple IPv6 addresses are assigned to the interface.
                                     *     2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is written (in hex) as
                                     *     "20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44 40"*/
#define OPT_IDB_MACADDR      0x0006 /* XXX: if_MACaddr  Interface Hardware MAC address (48 bits).                             */
#define OPT_IDB_EUIADDR      0x0007 /* XXX: if_EUIaddr  Interface Hardware EUI address (64 bits)                              */
#define OPT_IDB_SPEED        0x0008 /**< 0xFFFFFFFF if unknown
                                     *     Interface speed (in bps). 100000000 for 100Mbps
                                     */
#define OPT_IDB_TSRESOL      0x0009 /**< Resolution of timestamps. If the Most Significant Bit is equal to zero,
                                     *     the remaining bits indicates the resolution of the timestamp as as a
                                     *     negative power of 10 (e.g. 6 means microsecond resolution, timestamps
                                     *     are the number of microseconds since 1/1/1970). If the Most Significant Bit
                                     *     is equal to one, the remaining bits indicates the resolution has a
                                     *     negative power of 2 (e.g. 10 means 1/1024 of second).
                                     *     If this option is not present, a resolution of 10^-6 is assumed
                                     *     (i.e. timestamps have the same resolution of the standard 'libpcap' timestamps).
                                     */
#define OPT_IDB_TZONE        0x000A /* XXX: if_tzone    Time zone for GMT support (TODO: specify better). */
#define OPT_IDB_FILTER       0x000B /**< The filter (e.g. "capture only TCP traffic") used to capture traffic.
                                     *     The first byte of the Option Data keeps a code of the filter used
                                     *     (e.g. if this is a libpcap string, or BPF bytecode, and more).
                                     *     More details about this format will be presented in Appendix XXX (TODO).
                                     *     (TODO: better use different options for different fields?
                                     *     e.g. if_filter_pcap, if_filter_bpf, ...) 00 "tcp port 23 and host 10.0.0.5"
                                     */
#define OPT_IDB_OS           0x000C /**< NULL if not available, A UTF-8 string containing the name of the operating system of the
                                     *     machine in which this interface is installed.
                                     *     This can be different from the same information that can be
                                     *     contained by the Section Header Block
                                     *     (Section 3.1 (Section Header Block (mandatory))) because
                                     *     the capture can have been done on a remote machine.
                                     *     "Windows XP SP2" / "openSUSE 10.2"
                                     */
#define OPT_IDB_FCSLEN       0x000D /**< An integer value that specified the length of the
                                     *     Frame Check Sequence (in bits) for this interface.
                                     *     For link layers whose FCS length can change during time,
                                     *     the Packet Block Flags Word can be used (see Appendix A (Packet Block Flags Word))
                                     */
#define OPT_IDB_TSOFFSET     0x000E /**< XXX: A 64 bits integer value that specifies an offset (in seconds)
                                     *                     that must be added to the timestamp of each packet to obtain
                                     *                     the absolute timestamp of a packet. If the option is missing,
                                     *                     the timestamps stored in the packet must be considered absolute
                                     *                     timestamps. The time zone of the offset can be specified with the
                                     *                     option if_tzone. TODO: won't a if_tsoffset_low for fractional
                                     *                     second offsets be useful for highly syncronized capture systems?
                                     */

#define OPT_ISB_STARTTIME    0x0002
#define OPT_ISB_ENDTIME      0x0003
#define OPT_ISB_IFRECV       0x0004
#define OPT_ISB_IFDROP       0x0005
#define OPT_ISB_FILTERACCEPT 0x0006
#define OPT_ISB_OSDROP       0x0007
#define OPT_ISB_USRDELIV     0x0008

struct wtap_optionblock;
typedef struct wtap_optionblock *wtap_optionblock_t;

/* Currently supported option blocks */
typedef enum {
    WTAP_OPTION_BLOCK_IF_DESCR = 0,
    WTAP_OPTION_BLOCK_IF_STATS,
    WTAP_OPTION_BLOCK_NG_SECTION,
    WTAP_OPTION_BLOCK_NG_NRB,
    WTAP_OPTION_BLOCK_END_OF_LIST
} wtap_optionblock_type_t;

/* Currently supported option types */
typedef enum {
    WTAP_OPTTYPE_UINT8,
    WTAP_OPTTYPE_UINT64,
    WTAP_OPTTYPE_STRING,
    WTAP_OPTTYPE_CUSTOM
} wtap_opttype_e;

typedef enum {
    WTAP_OPTTYPE_SUCCESS = 0,
    WTAP_OPTTYPE_NOT_FOUND = -1,
    WTAP_OPTTYPE_TYPE_MISMATCH = -2,
    WTAP_OPTTYPE_ALREADY_EXISTS = -3
} wtap_opttype_return_val;

typedef void (*wtap_opttype_free_custom_func)(void* data);

struct wtap_opttype_custom
{
    void* data;
    guint size;
    wtap_opttype_free_custom_func free_func;
};

typedef union {
    guint8 uint8val;
    guint64 uint64val;
    char *stringval;
    struct wtap_opttype_custom customval;
} wtap_option_type;

struct wtap_dumper;

typedef void (*wtap_block_create_func)(wtap_optionblock_t block);
typedef void (*wtap_mand_free_func)(wtap_optionblock_t block);
typedef void (*wtap_mand_copy_func)(wtap_optionblock_t dest_block, wtap_optionblock_t src_block);

typedef struct wtap_optblock_reg {
    const char *name;                /**< name of option */
    const char *description;         /**< human-readable description of option */
    wtap_opttype_e type;             /**< type of that option */
    wtap_option_type option;         /**< pointer to variable storing the value */
    wtap_option_type default_val;    /**< the default value of the option */
} wtap_optblock_reg_t;

/** Initialize option block types.
 *
 * This is currently just a placeholder as nothing needs to be
 * initialized yet.  Should handle "registration" when code is
 * refactored to do so.
 */
void wtap_opttypes_initialize(void);

/** Create an option block by type
 *
 * Return a newly allocated option block with default options provided
 *
 * @param[in] block_type Option block type to be created
 * @return Newly allocated option block
 */
WS_DLL_PUBLIC wtap_optionblock_t wtap_optionblock_create(int block_type);

/** Free an option block
 *
 * Needs to be called to clean up any allocated option block
 *
 * @param[in] block Block to be freed
 */
WS_DLL_PUBLIC void wtap_optionblock_free(wtap_optionblock_t block);

/** Free an array of option blocks
 *
 * Needs to be called to clean up option blocks allocated
 * through GArray (for multiple blocks of same type)
 * Includes freeing the GArray
 *
 * @param[in] block_array Array of blocks to be freed
 */
WS_DLL_PUBLIC void wtap_optionblock_array_free(GArray* block_array);

/** Provide mandatory data of an option block
 *
 * @param[in] block Block from which to retrieve mandatory data
 * @return Option block mandatory data.  Structure varies based on option block type
 */
WS_DLL_PUBLIC void* wtap_optionblock_get_mandatory_data(wtap_optionblock_t block);

/** Add an option to the option block
 *
 * @param[in] block Block to which to add option
 * @param[in] option_id Identifier value for option
 * @param[in] option structure explaining it
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_add_option(wtap_optionblock_t block, guint option_id, wtap_optblock_reg_t* option);

/** Set string option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @param[in] value_length Maximum length of string to copy.
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_string(wtap_optionblock_t block, guint option_id, char* value, gsize value_length);

/** Set string option value in an option block to a printf-formatted string
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] format printf-like format string
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_string_format(wtap_optionblock_t block, guint option_id, const char *format, ...)
                                          G_GNUC_PRINTF(3,4);

/** Get string option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_string(wtap_optionblock_t block, guint option_id, char** value);

/** Set UINT64 option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_uint64(wtap_optionblock_t block, guint option_id, guint64 value);

/** Get UINT64 option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_uint64(wtap_optionblock_t block, guint option_id, guint64* value);

/** Set UINT8 option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_uint8(wtap_optionblock_t block, guint option_id, guint8 value);

/** Get UINT8 option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_uint8(wtap_optionblock_t block, guint option_id, guint8* value);

/** Set a "custom" option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_custom(wtap_optionblock_t block, guint option_id, void* value);

/** Get a "custom" option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_custom(wtap_optionblock_t block, guint option_id, void** value);

/** Copy an option block to another.
 *
 * Any options that are in the destination but not the source are not removed.
 * Options that are just in source will be added to destination
 *
 * @param[in] dest_block Block to be copied to
 * @param[in] src_block Block to be copied from
 */
void wtap_optionblock_copy_options(wtap_optionblock_t dest_block, wtap_optionblock_t src_block);


typedef void (*wtap_optionblock_foreach_func)(wtap_optionblock_t block, guint option_id, wtap_opttype_e option_type, wtap_option_type* option, void* user_data);
WS_DLL_PUBLIC void wtap_optionblock_foreach_option(wtap_optionblock_t block, wtap_optionblock_foreach_func func, void* user_data);

WS_DLL_PUBLIC int wtap_opttype_register_custom_block_type(const char* name, const char* description, wtap_block_create_func create,
                                                wtap_mand_free_func free_mand, wtap_mand_copy_func copy_mand);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WTAP_OPT_TYPES_H */

