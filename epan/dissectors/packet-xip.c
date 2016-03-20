/* packet-xip.c
 * Routines for XIP dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The eXpressive Internet Protocol (XIP) is the network layer protocol for
 * the eXpressive Internet Architecture (XIA), a future Internet architecture
 * project. The addresses in XIP are directed acyclic graphs, so some of the
 * code in this file verifies the correctness of the DAGs and displays them
 * in human-readable form.
 *
 * More information about XIA can be found here:
 *  https://www.cs.cmu.edu/~xia/
 *
 * And here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki
 *
 * More information about the format of the DAG can be found here:
 *  https://github.com/AltraMayor/XIA-for-Linux/wiki/Human-readable-XIP-address-format
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_xip(void);
void proto_reg_handoff_xip(void);

/* Next dissector handles. */
static dissector_handle_t xip_serval_handle;

static gint proto_xip			= -1;

static gint hf_xip_version		= -1;
static gint hf_xip_next_hdr		= -1;
static gint hf_xip_payload_len		= -1;
static gint hf_xip_hop_limit		= -1;
static gint hf_xip_num_dst		= -1;
static gint hf_xip_num_src		= -1;
static gint hf_xip_last_node		= -1;
static gint hf_xip_dst_dag		= -1;
static gint hf_xip_dst_dag_entry	= -1;
static gint hf_xip_src_dag		= -1;
static gint hf_xip_src_dag_entry	= -1;

static gint ett_xip_tree		= -1;
static gint ett_xip_ddag		= -1;
static gint ett_xip_sdag		= -1;

static expert_field ei_xip_invalid_len = EI_INIT;
static expert_field ei_xip_next_header = EI_INIT;
static expert_field ei_xip_bad_num_dst = EI_INIT;
static expert_field ei_xip_bad_num_src = EI_INIT;

static dissector_handle_t xip_handle;

/* XIA principals. */
#define XIDTYPE_NAT		0x00
#define XIDTYPE_AD		0x10
#define XIDTYPE_HID		0x11
#define XIDTYPE_CID		0x12
#define XIDTYPE_SID		0x13
#define XIDTYPE_UNI4ID		0x14
#define XIDTYPE_I4ID		0x15
#define XIDTYPE_U4ID		0x16
#define XIDTYPE_XDP		0x17
#define XIDTYPE_SRVCID		0x18
#define XIDTYPE_FLOWID		0x19
#define XIDTYPE_ZF		0x20

/* Principal string values. */
static const value_string xidtype_vals[] = {
	{ XIDTYPE_AD,		"ad" },
	{ XIDTYPE_HID,		"hid" },
	{ XIDTYPE_CID,		"cid" },
	{ XIDTYPE_SID,		"sid" },
	{ XIDTYPE_UNI4ID,	"uni4id" },
	{ XIDTYPE_I4ID,		"i4id" },
	{ XIDTYPE_U4ID,		"u4id" },
	{ XIDTYPE_XDP,		"xdp" },
	{ XIDTYPE_SRVCID,	"serval" },
	{ XIDTYPE_FLOWID,	"flowid" },
	{ XIDTYPE_ZF,		"zf" },
	{ 0,			NULL }
};

enum xia_addr_error {
	/* There's a non-XIDTYPE_NAT node after an XIDTYPE_NAT node. */
	XIAEADDR_NAT_MISPLACED = 1,
	/* Edge-selected bit is only valid in packets. */
	XIAEADDR_CHOSEN_EDGE,
	/* There's a non-empty edge after an Empty Edge.
	 * This error can also occur if an empty edge is selected. */
	XIAEADDR_EE_MISPLACED,
	/* An edge of a node is out of range. */
	XIAEADDR_EDGE_OUT_RANGE,
	/* The nodes are not in topological order. Notice that being in
	 * topological guarantees that the graph is acyclic, and has a simple,
	 * cheap test. */
	XIAEADDR_NOT_TOPOLOGICAL,
	/* No single component. */
	XIAEADDR_MULTI_COMPONENTS,
	/* Entry node is not present. */
	XIAEADDR_NO_ENTRY
};

/* Maximum number of nodes in a DAG. */
#define XIA_NODES_MAX		9

/* Number of outgoing edges for each node. */
#define XIA_OUTDEGREE_MAX	4

/* Sizes of an XIA node and its components. */
#define XIA_TYPE_SIZE		4
#define XIA_XID_SIZE		20
#define XIA_EDGES_SIZE		4
#define XIA_NODE_SIZE		(XIA_TYPE_SIZE + XIA_XID_SIZE + XIA_EDGES_SIZE)

/* Split XID up into 4 byte chunks. */
#define XIA_XID_CHUNK_SIZE	4

typedef guint32 xid_type_t;

struct xia_xid {
	/* XID type. */
	xid_type_t	xid_type;

	/* XID, represented as 4 byte ints. */
	guint32		xid_id[XIA_XID_SIZE / XIA_XID_CHUNK_SIZE];
};

struct xia_row {
	struct xia_xid	s_xid;
	/* Outgoing edges. */
	union {
		guint8	a[XIA_OUTDEGREE_MAX];
		guint32	i;
	} s_edge;
};

struct xia_addr {
	struct xia_row s_row[XIA_NODES_MAX];
};

/* XIA_MAX_STRADDR_SIZE - The maximum size of an XIA address as a string
 * in bytes. It's the recommended size to call xia_ntop with. It includes space
 * for an invalid sign (i.e. '!'), the type and name of a nodes in
 * hexadecimal, the out-edges, the two separators (i.e. '-') per node,
 * the edge-chosen sign (i.e. '>') for each selected edge,
 * the node separators (i.e. ':' or ":\n"), a string terminator (i.e. '\0'),
 * and an extra '\n' at the end the caller may want to add.
 */
#define MAX_PPAL_NAME_SIZE	32
#define XIA_MAX_STRID_SIZE	(XIA_XID_SIZE * 2 + 1)
#define XIA_MAX_STRXID_SIZE	(MAX_PPAL_NAME_SIZE + XIA_MAX_STRID_SIZE)
#define XIA_MAX_STRADDR_SIZE	(1 + XIA_NODES_MAX * \
	(XIA_MAX_STRXID_SIZE + XIA_OUTDEGREE_MAX * 2 + 2) + 1)

/*
 *	Validating addresses
 */

#define XIA_CHOSEN_EDGE		0x80
#define XIA_EMPTY_EDGE		0x7f
#define XIA_ENTRY_NODE_INDEX	0x7e

#define XIA_EMPTY_EDGES (XIA_EMPTY_EDGE << 24 | XIA_EMPTY_EDGE << 16 |\
			 XIA_EMPTY_EDGE <<  8 | XIA_EMPTY_EDGE)
#define XIA_CHOSEN_EDGES (XIA_CHOSEN_EDGE << 24 | XIA_CHOSEN_EDGE << 16 |\
			 XIA_CHOSEN_EDGE <<  8 | XIA_CHOSEN_EDGE)

static inline gint
is_edge_chosen(guint8 e)
{
	return e & XIA_CHOSEN_EDGE;
}

static inline gint
is_any_edge_chosen(const struct xia_row *row)
{
	return row->s_edge.i & XIA_CHOSEN_EDGES;
}

static inline gint
is_empty_edge(guint8 e)
{
	return (e & XIA_EMPTY_EDGE) == XIA_EMPTY_EDGE;
}

static inline gint
xia_is_nat(xid_type_t ty)
{
	return ty == XIDTYPE_NAT;
}

static gint
xia_are_edges_valid(const struct xia_row *row,
	guint8 node, guint8 num_node, guint32 *pvisited)
{
	const guint8 *edge;
	guint32 all_edges, bits;
	gint i;

	if (is_any_edge_chosen(row)) {
		/* Since at least an edge of last_node has already
		 * been chosen, the address is corrupted.
		 */
		return -XIAEADDR_CHOSEN_EDGE;
	}

	edge = row->s_edge.a;
	all_edges = g_ntohl(row->s_edge.i);
	bits = 0xffffffff;
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++, edge++) {
		guint8 e;
		e = *edge;
		if (e == XIA_EMPTY_EDGE) {
			if ((all_edges & bits) !=
				(XIA_EMPTY_EDGES & bits))
				return -XIAEADDR_EE_MISPLACED;
			else
				break;
		} else if (e >= num_node) {
			return -XIAEADDR_EDGE_OUT_RANGE;
		} else if (node < (num_node - 1) && e <= node) {
			/* Notice that if (node == XIA_ENTRY_NODE_INDEX)
			 * it still works fine because XIA_ENTRY_NODE_INDEX
			 * is greater than (num_node - 1).
			 */
			return -XIAEADDR_NOT_TOPOLOGICAL;
		}
		bits >>= 8;
		*pvisited |= 1 << e;
	}
	return 0;
}

static gint
xia_test_addr(const struct xia_addr *addr)
{
	gint i, n;
	gint saw_nat = 0;
	guint32 visited = 0;

	/* Test that XIDTYPE_NAT is present only on last rows. */
	n = XIA_NODES_MAX;
	for (i = 0; i < XIA_NODES_MAX; i++) {
		xid_type_t ty;
		ty = addr->s_row[i].s_xid.xid_type;
		if (saw_nat) {
			if (!xia_is_nat(ty))
				return -XIAEADDR_NAT_MISPLACED;
		} else if (xia_is_nat(ty)) {
			n = i;
			saw_nat = 1;
		}
	}
	/* n = number of nodes from here. */

	/* Test edges are well formed. */
	for (i = 0; i < n; i++) {
		gint rc;
		rc = xia_are_edges_valid(&addr->s_row[i], i, n, &visited);
		if (rc)
			return rc;
	}

	if (n >= 1) {
		/* Test entry point is present. Notice that it's just a
		 * friendlier error since it's also XIAEADDR_MULTI_COMPONENTS.
		 */
		guint32 all_edges;
		all_edges = addr->s_row[n - 1].s_edge.i;
		if (all_edges == XIA_EMPTY_EDGES)
			return -XIAEADDR_NO_ENTRY;

		if (visited != ((1U << n) - 1))
			return -XIAEADDR_MULTI_COMPONENTS;
	}

	return n;
}

/*
 *	Printing addresses out
 */

#define INDEX_BASE 36

static inline gchar
edge_to_char(guint8 e)
{
	const gchar *ch_edge = "0123456789abcdefghijklmnopqrstuvwxyz";
	e &= ~XIA_CHOSEN_EDGE;
	if (e < INDEX_BASE)
		return ch_edge[e];
	else if (is_empty_edge(e))
		return '*';
	else
		return '+';
}

static void
add_edges_to_buf(gint valid, wmem_strbuf_t *buf, const guint8 *edges)
{
	gint i;
	wmem_strbuf_append_c(buf, '-');
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		if (valid && edges[i] == XIA_EMPTY_EDGE)
			return;

		if (is_edge_chosen(edges[i]))
			wmem_strbuf_append_c(buf, '>');

		wmem_strbuf_append_c(buf, edge_to_char(edges[i]));
	}
}

static void
add_type_to_buf(xid_type_t ty, wmem_strbuf_t *buf)
{
	const gchar *xid_name;
	gsize buflen = wmem_strbuf_get_len(buf);

	if (XIA_MAX_STRADDR_SIZE - buflen - 1 < MAX_PPAL_NAME_SIZE)
		return;

	xid_name = try_val_to_str(ty, xidtype_vals);
	if (xid_name)
		wmem_strbuf_append_printf(buf, "%s-", xid_name);
	else
		wmem_strbuf_append_printf(buf, "0x%x-", ty);
}

static inline void
add_id_to_buf(const struct xia_xid *src, wmem_strbuf_t *buf)
{
	wmem_strbuf_append_printf(buf, "%08x%08x%08x%08x%08x",
		src->xid_id[0],
		src->xid_id[1],
		src->xid_id[2],
		src->xid_id[3],
		src->xid_id[4]);
}

/* xia_ntop - convert an XIA address to a string.
 * @src can be ill-formed, but xia_ntop won't report an error and will return
 * a string that approximates that ill-formed address.
 */
static int
xia_ntop(const struct xia_addr *src, wmem_strbuf_t *buf)
{
	gint valid, i;

	valid = xia_test_addr(src) >= 1;
	if (!valid)
		wmem_strbuf_append_c(buf, '!');

	for (i = 0; i < XIA_NODES_MAX; i++) {
		const struct xia_row *row = &src->s_row[i];

		if (xia_is_nat(row->s_xid.xid_type))
			break;

		if (i > 0)
			wmem_strbuf_append(buf, ":\n");

		/* Add the type, ID, and edges for this node. */
		add_type_to_buf(row->s_xid.xid_type, buf);
		add_id_to_buf(&row->s_xid, buf);
		add_edges_to_buf(valid, buf, row->s_edge.a);
	}

	return 0;
}

/*
 *	Dissection
 */

#define XIPH_MIN_LEN		36
#define ETHERTYPE_XIP		0xC0DE
#define XIA_NEXT_HEADER_DATA	0

/* Offsets of XIP fields in bytes. */
#define XIPH_VERS		0
#define XIPH_NXTH		1
#define XIPH_PLEN		2
#define XIPH_HOPL		4
#define XIPH_NDST		5
#define XIPH_NSRC		6
#define XIPH_LSTN		7
#define XIPH_DSTD		8

static void
construct_dag(tvbuff_t *tvb, proto_tree *xip_tree,
	const gint ett, const gint hf, const gint hf_entry,
	const guint8 num_nodes, guint8 offset)
{
	proto_tree *dag_tree;
	proto_item *ti;
	struct xia_addr dag;
	wmem_strbuf_t *buf;
	const gchar *dag_str;
	guint i, j;
	guint8 dag_offset = offset;

	ti = proto_tree_add_item(xip_tree, hf, tvb, offset,
		num_nodes * XIA_NODE_SIZE, ENC_BIG_ENDIAN);

	buf = wmem_strbuf_sized_new(wmem_packet_scope(),
		XIA_MAX_STRADDR_SIZE, XIA_MAX_STRADDR_SIZE);

	dag_tree = proto_item_add_subtree(ti, ett);

	memset(&dag, 0, sizeof(dag));
	for (i = 0; i < num_nodes; i++) {
		struct xia_row *row = &dag.s_row[i];

		row->s_xid.xid_type = tvb_get_ntohl(tvb, offset);
		offset += XIA_TYPE_SIZE;

		/* Process the ID 32 bits at a time. */
		for (j = 0; j < XIA_XID_SIZE / XIA_XID_CHUNK_SIZE; j++) {
			row->s_xid.xid_id[j] = tvb_get_ntohl(tvb, offset);
			offset += XIA_XID_CHUNK_SIZE;
		}

		/* Need to process the edges byte-by-byte,
		 * so keep the bytes in network order.
		 */
		tvb_memcpy(tvb, row->s_edge.a, offset, XIA_EDGES_SIZE);
		offset += XIA_EDGES_SIZE;
	}

	xia_ntop(&dag, buf);
	dag_str = wmem_strbuf_get_str(buf);
	proto_tree_add_string_format(dag_tree, hf_entry, tvb, dag_offset,
		XIA_NODE_SIZE * num_nodes, dag_str, "%s", dag_str);
}

static gint
dissect_xip_sink_node(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint offset, guint8 sink_node)
{
	tvbuff_t *next_tvb;

	switch (sink_node) {
	/* Serval XID types. */
	case XIDTYPE_FLOWID:
	case XIDTYPE_SRVCID:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		return call_dissector(xip_serval_handle, next_tvb, pinfo, tree);
	/* No special sink processing. */
	default:
		return 0;
	}
}

static gint
dissect_xip_next_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	proto_item *next_ti, gint offset)
{
	tvbuff_t *next_tvb;
	guint8 next_header = tvb_get_guint8(tvb, XIPH_NXTH);

	switch (next_header) {
	case XIA_NEXT_HEADER_DATA:
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		return call_data_dissector(next_tvb, pinfo, tree);
	default:
		expert_add_info_format(pinfo, next_ti, &ei_xip_next_header,
		 "Unrecognized next header type: 0x%02x", next_header);
		return 0;
	}
}

static void
display_xip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *xip_tree = NULL;

	proto_item *ti = NULL;
	proto_item *payload_ti = NULL;
	proto_item *next_ti = NULL;
	proto_item *num_ti = NULL;

	gint offset;
	guint16 xiph_len, payload_len;
	guint8 num_dst_nodes, num_src_nodes, last_node;

	num_dst_nodes = tvb_get_guint8(tvb, XIPH_NDST);
	num_src_nodes = tvb_get_guint8(tvb, XIPH_NSRC);
	xiph_len = 8 + (XIA_NODE_SIZE * num_dst_nodes) +
		(XIA_NODE_SIZE * num_src_nodes);

	/* Construct protocol tree. */
	ti = proto_tree_add_item(tree, proto_xip, tvb, 0, xiph_len, ENC_NA);
	xip_tree = proto_item_add_subtree(ti, ett_xip_tree);

	/* Add XIP version. */
	proto_tree_add_item(xip_tree, hf_xip_version, tvb,
		XIPH_VERS, 1, ENC_BIG_ENDIAN);

	/* Add XIP next header. */
	next_ti = proto_tree_add_item(xip_tree, hf_xip_next_hdr, tvb,
		XIPH_NXTH, 1, ENC_BIG_ENDIAN);

	/* Add XIP payload length. */
	payload_len = tvb_get_ntohs(tvb, XIPH_PLEN);
	payload_ti = proto_tree_add_uint_format(xip_tree, hf_xip_payload_len,
		tvb, XIPH_PLEN, 2, payload_len, "Payload Length: %u bytes",
		payload_len);
	if (tvb_captured_length_remaining(tvb, xiph_len) != payload_len)
		expert_add_info_format(pinfo, payload_ti, &ei_xip_invalid_len,
		"Payload length field (%d bytes) does not match actual payload length (%d bytes)",
		payload_len, tvb_captured_length_remaining(tvb, xiph_len));

	/* Add XIP hop limit. */
	proto_tree_add_item(xip_tree, hf_xip_hop_limit, tvb,
		XIPH_HOPL, 1, ENC_BIG_ENDIAN);

	/* Add XIP number of destination DAG nodes. */
	num_ti = proto_tree_add_item(xip_tree, hf_xip_num_dst, tvb,
		XIPH_NDST, 1, ENC_BIG_ENDIAN);
	if (num_dst_nodes > XIA_NODES_MAX) {
		expert_add_info_format(pinfo, num_ti, &ei_xip_bad_num_dst,
		"The number of destination DAG nodes (%d) must be less than XIA_NODES_MAX (%d)",
		num_dst_nodes, XIA_NODES_MAX);
		num_dst_nodes = XIA_NODES_MAX;
	}

	/* Add XIP number of source DAG nodes. */
	num_ti = proto_tree_add_item(xip_tree, hf_xip_num_src, tvb,
		XIPH_NSRC, 1, ENC_BIG_ENDIAN);
	if (num_src_nodes > XIA_NODES_MAX) {
		expert_add_info_format(pinfo, num_ti, &ei_xip_bad_num_src,
		"The number of source DAG nodes (%d) must be less than XIA_NODES_MAX (%d)",
		num_src_nodes, XIA_NODES_MAX);
		num_src_nodes = XIA_NODES_MAX;
	}

	/* Add XIP last node. */
	last_node = tvb_get_guint8(tvb, XIPH_LSTN);
	proto_tree_add_uint_format_value(xip_tree, hf_xip_last_node, tvb,
		XIPH_LSTN, 1, last_node, "%d%s", last_node,
		last_node == XIA_ENTRY_NODE_INDEX ? " (entry node)" : "");

	/* Construct Destination DAG subtree. */
	if (num_dst_nodes > 0)
		construct_dag(tvb, xip_tree, ett_xip_ddag,
			hf_xip_dst_dag, hf_xip_dst_dag_entry,
			num_dst_nodes, XIPH_DSTD);

	/* Construct Source DAG subtree. */
	if (num_src_nodes > 0)
		construct_dag(tvb, xip_tree, ett_xip_sdag,
			hf_xip_src_dag, hf_xip_src_dag_entry,
			num_src_nodes,
			XIPH_DSTD + num_dst_nodes * XIA_NODE_SIZE);

	/* First byte after XIP header. */
	offset = XIPH_DSTD + XIA_NODE_SIZE * (num_dst_nodes + num_src_nodes);

	/* Dissect other headers according to the sink node, if needed. */
	offset += dissect_xip_sink_node(tvb, pinfo, tree, offset,
			tvb_get_ntohl(tvb, XIPH_DSTD +
			(num_dst_nodes - 1) * XIA_NODE_SIZE));

	dissect_xip_next_header(tvb, pinfo, tree, next_ti, offset);
}

static gint
dissect_xip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data _U_)
{
	/* Not large enough to be valid XIP packet. */
	if (tvb_reported_length(tvb) < XIPH_MIN_LEN)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XIP");
	col_set_str(pinfo->cinfo, COL_INFO, "XIP Packet");

	display_xip(tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}

void
proto_register_xip(void)
{
	static hf_register_info hf[] = {

		/* XIP Header. */

		{ &hf_xip_version,
		{ "Version", "xip.version", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_next_hdr,
		{ "Next Header", "xip.next_hdr", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_payload_len,
		{ "Payload Length", "xip.payload_len", FT_UINT16,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_hop_limit,
		{ "Hop Limit", "xip.hop_limit", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_num_dst,
		{ "Number of Destination Nodes", "xip.num_dst", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_num_src,
		{ "Number of Source Nodes", "xip.num_src", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_last_node,
		{ "Last Node", "xip.last_node", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_dst_dag,
		{ "Destination DAG", "xip.dst_dag", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_dst_dag_entry,
		{ "Destination DAG Entry", "xip.dst_dag_entry", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_src_dag,
		{ "Source DAG", "xip.src_dag", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_src_dag_entry,
		{ "Source DAG Entry", "xip.src_dag_entry", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_xip_tree,
		&ett_xip_ddag,
		&ett_xip_sdag
	};

	static ei_register_info ei[] = {
		{ &ei_xip_invalid_len,
		{ "xip.invalid.len", PI_MALFORMED, PI_ERROR,
		  "Invalid length", EXPFILL }},

		{ &ei_xip_next_header,
		{ "xip.next.header", PI_MALFORMED, PI_ERROR,
		  "Invalid next header", EXPFILL }},

		{ &ei_xip_bad_num_dst,
		{ "xip.bad_num_dst", PI_MALFORMED, PI_ERROR,
		  "Invalid number of destination DAG nodes", EXPFILL }},

		{ &ei_xip_bad_num_src,
		{ "xip.bad_num_src", PI_MALFORMED, PI_ERROR,
		  "Invalid number of source DAG nodes", EXPFILL }}
	};

	expert_module_t* expert_xip;

	proto_xip = proto_register_protocol(
		"eXpressive Internet Protocol",
		"XIP",
		"xip");

	xip_handle = register_dissector("xip", dissect_xip, proto_xip);
	proto_register_field_array(proto_xip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_xip = expert_register_protocol(proto_xip);
	expert_register_field_array(expert_xip, ei, array_length(ei));
}

void
proto_reg_handoff_xip(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_XIP, xip_handle);

	xip_serval_handle = find_dissector_add_dependency("xipserval", proto_xip);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
