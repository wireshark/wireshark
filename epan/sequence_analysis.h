/** @file
 * Flow sequence analysis
 *
 * Copied from gtk/graph_analysis.h
 *
 * Copyright 2004, Verso Technologies Inc.
 * By Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * based on rtp_analysis.c and io_stat
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EPAN_SEQUENCE_ANALYSIS_H__
#define __EPAN_SEQUENCE_ANALYSIS_H__

#include "ws_symbol_export.h"

#include <glib.h>

#include "packet_info.h"
#include "tap.h"
#include "address.h"
#include "wsutil/file_util.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MAX_NUM_NODES 40

/** defines info types for graph analysis additional information */
typedef enum _ga_info_type {
    GA_INFO_TYPE_NONE=0,
    GA_INFO_TYPE_RTP
} ga_info_type;

/** defines an entry for the graph analysis */
typedef struct _seq_analysis_item {
    uint32_t frame_number;
    address src_addr;
    uint16_t port_src;
    address dst_addr;
    uint16_t port_dst;
    char *frame_label;              /**< the label on top of the arrow */
    char *time_str;                 /**< timestamp */
    char *comment;                  /**< a comment that appears at the right of the graph */
    uint16_t conv_num;              /**< The conversation number. Used for coloring VoIP calls. */
    unsigned fg_color;              /**< Foreground color, 0xRRGGBB. Qt only. */
    unsigned bg_color;              /**< Background color, 0xRRGGBB. Qt only. */
    bool has_color_filter;          /**< Set if packet has color filter. Qt only. */
    bool display;                   /**< indicate if the packet is displayed or not in the graph */
    unsigned src_node;              /**< this is used by graph_analysis.c to identify the node */
    unsigned dst_node;              /**< a node is an IP address that will be displayed in columns */
    uint16_t line_style;            /**< the arrow line width in pixels*/
    ga_info_type info_type;         /**< type of info for item */
    void *info_ptr;                 /**< ptr to info for item */
} seq_analysis_item_t;

/** defines the graph analysis structure */
typedef struct _seq_analysis_info {
    const char* name;                  /**< Name of sequence analysis */
    bool        any_addr;              /**< any addr (DL+net) vs net-only */
    int         nconv;                 /**< number of conversations in the list */
    GQueue*     items;                 /**< list of seq_analysis_info_t */
    GHashTable *ht;                    /**< hash table of seq_analysis_info_t */
    address nodes[MAX_NUM_NODES];      /**< horizontal node list */
    uint8_t occurrence[MAX_NUM_NODES]; /**< horizontal occurrence list 0|1 */
    uint32_t num_nodes;                /**< actual number of nodes */
} seq_analysis_info_t;

/** Structure for information about a registered sequence analysis function */
typedef struct register_analysis register_analysis_t;

WS_DLL_PUBLIC void register_seq_analysis(const char* name, const char* ui_name, const int proto_id, const char* tap_listener, unsigned tap_flags, tap_packet_cb tap_func);

/** Helper function to get sequence analysis name
 *
 * @param analysis Registered sequence analysis
 * @return sequence analysis name string
 */
WS_DLL_PUBLIC const char* sequence_analysis_get_name(register_analysis_t* analysis);

/** Helper function to get tap listener name
 *
 * @param analysis Registered sequence analysis
 * @return sequence analysis tap listener string
 */
WS_DLL_PUBLIC const char* sequence_analysis_get_tap_listener_name(register_analysis_t* analysis);

/** Helper function to get UI name
 *
 * @param analysis Registered sequence analysis
 * @return sequence analysis UI string
 */
WS_DLL_PUBLIC const char* sequence_analysis_get_ui_name(register_analysis_t* analysis);

/** Get tap function handler from sequence analysis
 *
 * @param analysis Registered sequence analysis
 * @return tap function handler of sequence analysis
 */
WS_DLL_PUBLIC tap_packet_cb sequence_analysis_get_packet_func(register_analysis_t* analysis);

/** Helper function to get tap flags
 *
 * @param analysis Registered sequence analysis
 * @return sequence analysis tap flags
 */
WS_DLL_PUBLIC unsigned sequence_analysis_get_tap_flags(register_analysis_t* analysis);

/** Helper function to create a sequence analysis item with address fields populated
 * Allocate a seq_analysis_item_t to return and populate the time_str and src_addr and dst_addr
 * members based on seq_analysis_info_t any_addr member
 *
 * @param pinfo packet info
 * @param sainfo info determining address type
 * @return sequence analysis tap flags
 */
WS_DLL_PUBLIC seq_analysis_item_t* sequence_analysis_create_sai_with_addresses(packet_info *pinfo, seq_analysis_info_t *sainfo);

/** Helper function to set colors for analysis the same as Wireshark display
 *
 * @param pinfo packet info
 * @param sai item to set color
 */
WS_DLL_PUBLIC void sequence_analysis_use_color_filter(packet_info *pinfo, seq_analysis_item_t *sai);

/** Helper function to set frame label and comments to use protocol and info column data
 *
 * @param pinfo packet info
 * @param sai item to set label and comments
 */
WS_DLL_PUBLIC void sequence_analysis_use_col_info_as_label_comment(packet_info *pinfo, seq_analysis_item_t *sai);

/** Find a registered sequence analysis "protocol" by name
 *
 * @param name Registered sequence analysis to find
 * @return registered sequence analysis, NULL if not found
 */
WS_DLL_PUBLIC register_analysis_t* sequence_analysis_find_by_name(const char* name);

/** Interator to walk sequence_analysis tables and execute func
 *
 * @param func action to be performed on all sequence_analysis tables
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void sequence_analysis_table_iterate_tables(wmem_foreach_func func, void *user_data);

/** Create and initialize a seq_analysis_info_t struct
 * @return A pointer to a newly allocated seq_analysis_info_t struct.
 */
WS_DLL_PUBLIC seq_analysis_info_t *sequence_analysis_info_new(void);

/** Free a seq_analysis_info_t struct.
 * @param sainfo A pointer to the seq_analysis_info_t struct to be freed.
 */
WS_DLL_PUBLIC void sequence_analysis_info_free(seq_analysis_info_t * sainfo);

/** Sort a seq_analysis_info_t struct.
 * @param sainfo A pointer to the seq_analysis_info_t struct to be sorted
 */
WS_DLL_PUBLIC void sequence_analysis_list_sort(seq_analysis_info_t *sainfo);

/** Free the segment list
 *
 * @param sainfo Sequence analysis information.
 */
WS_DLL_PUBLIC void sequence_analysis_list_free(seq_analysis_info_t *sainfo);

/** Fill in the node address list
 *
 * @param sainfo Sequence analysis information.
 * @return The number of transaction items (not nodes) processed.
 */
WS_DLL_PUBLIC int sequence_analysis_get_nodes(seq_analysis_info_t *sainfo);

/** Free the node address list
 *
 * @param sainfo Sequence analysis information.
 */
WS_DLL_PUBLIC void sequence_analysis_free_nodes(seq_analysis_info_t *sainfo);


/** Write an ASCII version of the sequence diagram to a file.
 *
 * @param of File to write.
 * @param sainfo Sequence analysis information.
 * @param first_node Start drawing at this node.
 */
WS_DLL_PUBLIC void sequence_analysis_dump_to_file(FILE *of, seq_analysis_info_t *sainfo, unsigned first_node);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EPAN_SEQUENCE_ANALYSIS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
