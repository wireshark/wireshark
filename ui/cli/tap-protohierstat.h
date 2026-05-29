/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_PROTO_HIER_STAT_H__
#define __TAP_PROTO_HIER_STAT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern int pc_proto_id;

/**
 * @brief Node in a protocol hierarchy statistics tree, representing a single
 *        protocol layer with links to related nodes and accumulated traffic counters.
 */
typedef struct _phs_t {
    struct _phs_t *sibling;   /**< Next sibling node at the same level of the hierarchy tree. */
    struct _phs_t *child;     /**< First child node representing a sub-protocol layer. */
    struct _phs_t *parent;    /**< Parent node one level up in the hierarchy tree. */
    char *filter;             /**< Display filter string used to isolate this protocol's traffic. */
    int protocol;             /**< Wireshark protocol ID as registered in the dissector table. */
    const char *proto_name;   /**< Human-readable protocol name string (e.g., "tcp", "http"). */
    uint32_t frames;          /**< Total number of frames captured for this protocol node. */
    uint64_t bytes;           /**< Total number of bytes captured for this protocol node. */
} phs_t;

/**
 * @brief Creates a new Protocol Hierarchy Statistics (PHS) node.
 *
 * @param parent The parent PHS node, or NULL if this is the root node.
 * @param filter A filter string for the PHS node, or NULL if no filter is needed.
 * @return phs_t* Pointer to the newly created PHS node.
 */
extern phs_t * new_phs_t(phs_t *parent, const char *filter);

/**
 * @brief Frees a Protocol Hierarchy Statistics (PHS) structure.
 *
 * This function recursively frees all memory associated with a PHS structure,
 * including its filter, sibling, and child nodes.
 *
 * @param rs Pointer to the PHS structure to be freed.
 */
extern void free_phs(phs_t *rs);

/**
* @brief Processes a packet for Protocol Hierarchy Statistics.
*
* This function updates the internal state of the Protocol Hierarchy Statistics tap data structure based on the provided packet information and dissector context. It checks if the dissector tree is available and iterates through its nodes to update statistics accordingly.
*
* @param prs Pointer to the tap data structure.
* @param pinfo Packet information structure.
* @param edt Dissector tree structure.
* @param dummy Unused parameter.
* @param flags Unused parameter.
* @return TAP_PACKET_REDRAW if the window needs to be redrawn, otherwise TAP_PACKET_DONT_REDRAW.
*/
extern tap_packet_status protohierstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_PROTO_HIER_STAT_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
