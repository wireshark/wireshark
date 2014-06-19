/* packet-isis-hello.c
 * Routines for decoding isis hello packets and their CLVs
 *
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include <epan/addr_resolv.h>


/*
 * Declarations for L1/L2 hello base header.
 */
#define ISIS_HELLO_CTYPE_MASK		0x03
#define ISIS_HELLO_CT_RESERVED_MASK	0xfc
#define ISIS_HELLO_PRIORITY_MASK	0x7f
#define ISIS_HELLO_P_RESERVED_MASK	0x80

#define ISIS_HELLO_TYPE_RESERVED	0
#define ISIS_HELLO_TYPE_LEVEL_1		1
#define ISIS_HELLO_TYPE_LEVEL_2		2
#define ISIS_HELLO_TYPE_LEVEL_12	3

/*
 * misc. bittest macros
 */

#define ISIS_RESTART_RR                 0x01
#define ISIS_RESTART_RA                 0x02
#define ISIS_RESTART_SA                 0x04
#define ISIS_MASK_RESTART_RR(x)            ((x)&ISIS_RESTART_RR)
#define ISIS_MASK_RESTART_RA(x)            ((x)&ISIS_RESTART_RA)
#define ISIS_MASK_RESTART_SA(x)            ((x)&ISIS_RESTART_SA)


#define APPEND_BOOLEAN_FLAG(flag, item, string) \
    if(flag){                            \
        if(item)                        \
            proto_item_append_text(item, string, sep);    \
        sep = cont_sep;                        \
    }

static const char initial_sep[] = " (";
static const char cont_sep[] = ", ";

void proto_register_isis_hello(void);
void proto_reg_handoff_isis_hello(void);

static int proto_isis_hello = -1;

/* hello packets */
static int hf_isis_hello_circuit = -1;
static int hf_isis_hello_circuit_reserved = -1;
static int hf_isis_hello_source_id = -1;
static int hf_isis_hello_holding_timer = -1;
static int hf_isis_hello_pdu_length = -1;
static int hf_isis_hello_priority = -1;
static int hf_isis_hello_priority_reserved = -1;
static int hf_isis_hello_lan_id = -1;
static int hf_isis_hello_local_circuit_id = -1;
static int hf_isis_hello_clv_ipv4_int_addr = -1;
static int hf_isis_hello_clv_ipv6_int_addr = -1;
/* static int hf_isis_hello_clv_ptp_adj = -1; */
static int hf_isis_hello_clv_mt = -1;
static int hf_isis_hello_clv_restart_flags = -1;
static int hf_isis_hello_clv_restart_flags_rr = -1;
static int hf_isis_hello_clv_restart_flags_ra = -1;
static int hf_isis_hello_clv_restart_flags_sa = -1;
static int hf_isis_hello_clv_restart_remain_time = -1;
static int hf_isis_hello_clv_restart_neighbor = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_isis_hello_extended_local_circuit_id = -1;
static int hf_isis_hello_adjacency_state = -1;
static int hf_isis_hello_neighbor_systemid = -1;
static int hf_isis_hello_digest = -1;
static int hf_isis_hello_aux_mcid = -1;
static int hf_isis_hello_mcid = -1;
static int hf_isis_hello_is_neighbor = -1;
static int hf_isis_hello_mtid = -1;
static int hf_isis_hello_checksum = -1;
static int hf_isis_hello_neighbor_extended_local_circuit_id = -1;

static gint ett_isis_hello = -1;
static gint ett_isis_hello_clv_area_addr = -1;
static gint ett_isis_hello_clv_is_neighbors = -1;
static gint ett_isis_hello_clv_padding = -1;
static gint ett_isis_hello_clv_unknown = -1;
static gint ett_isis_hello_clv_nlpid = -1;
static gint ett_isis_hello_clv_authentication = -1;
static gint ett_isis_hello_clv_ip_authentication = -1;
static gint ett_isis_hello_clv_ipv4_int_addr = -1;
static gint ett_isis_hello_clv_ipv6_int_addr = -1;
static gint ett_isis_hello_clv_ptp_adj = -1;
static gint ett_isis_hello_clv_mt = -1;
static gint ett_isis_hello_clv_restart = -1;
static gint ett_isis_hello_clv_restart_flags = -1;
static gint ett_isis_hello_clv_mt_port_cap = -1;
static gint ett_isis_hello_clv_mt_port_cap_spb_mcid = -1;
static gint ett_isis_hello_clv_mt_port_cap_spb_aux_mcid = -1;
static gint ett_isis_hello_clv_mt_port_cap_spb_digest = -1;
static gint ett_isis_hello_clv_mt_port_cap_spb_bvid_tuples = -1;
static gint ett_isis_hello_clv_checksum = -1;

static expert_field ei_isis_hello_short_packet = EI_INIT;
static expert_field ei_isis_hello_long_packet = EI_INIT;
static expert_field ei_isis_hello_subtlv = EI_INIT;
static expert_field ei_isis_hello_authentication = EI_INIT;

static const value_string isis_hello_circuit_type_vals[] = {
	{ ISIS_HELLO_TYPE_RESERVED,	"Reserved 0 (discard PDU)"},
	{ ISIS_HELLO_TYPE_LEVEL_1,	"Level 1 only"},
	{ ISIS_HELLO_TYPE_LEVEL_2,	"Level 2 only"},
	{ ISIS_HELLO_TYPE_LEVEL_12,	"Level 1 and 2"},
	{ 0,		NULL} };


static void
dissect_hello_mt_port_cap_spb_mcid_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    const int MCID_LEN = 51;
    const int SUBLEN   = 2 * MCID_LEN;
    proto_tree *subtree, *ti;

    if (sublen != SUBLEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_packet, tvb, offset, -1,
                                     "Short SPB MCID TLV (%d vs %d)", sublen, SUBLEN);
        return;
    }


    ti = proto_tree_add_text( tree, tvb, offset-2, sublen+2,
                                "SPB MCID: Type: 0x%02x, Length: %d", subtype, sublen);
    subtree = proto_item_add_subtree(ti, ett_isis_hello_clv_mt_port_cap_spb_mcid);

    /* MCID: */
    proto_tree_add_item(subtree, hf_isis_hello_mcid, tvb, offset, MCID_LEN, ENC_NA);
    offset += MCID_LEN;

    /* Aux MCID: */
    proto_tree_add_item(subtree, hf_isis_hello_aux_mcid, tvb, offset, MCID_LEN, ENC_NA);
    /* offset += MCID_LEN; */
}

static void
dissect_hello_mt_port_cap_spb_digest_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    const int DIGEST_LEN = 32;
    const int SUBLEN     = 1 + DIGEST_LEN;
    if (sublen != SUBLEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_packet, tvb, offset, -1,
                              "Short SPB Digest TLV (%d vs %d)", sublen, SUBLEN);
        return;
    }
    else {
        proto_tree *subtree, *ti;
        const guint8 vad     = tvb_get_guint8(tvb, offset);

        ti = proto_tree_add_text( tree, tvb, offset-2, sublen+2,
                                  "SPB Digest: Type: 0x%02x, Length: %d", subtype, sublen);
        subtree = proto_item_add_subtree(ti, ett_isis_hello_clv_mt_port_cap_spb_digest);

        proto_tree_add_text( subtree, tvb, offset, 1,
                             "V: %d, A: %d, D: %d",
                             (vad >> 4) & 0x1,
                             (vad >> 2) & 0x3,
                             (vad >> 0) & 0x3);
        ++offset;

        /* Digest: */
        proto_tree_add_item(subtree, hf_isis_hello_digest, tvb, offset, DIGEST_LEN, ENC_NA);
        /* offset += DIGEST_LEN; */
    }
}

static void
dissect_hello_mt_port_cap_spb_bvid_tuples_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    proto_tree *subtree, *ti;
    int subofs = offset;

    ti = proto_tree_add_text( tree, tvb, offset-2, sublen+2,
                              "SPB Base Vlan Identifiers: Type: 0x%02x, Length: %d", subtype, sublen);
    subtree = proto_item_add_subtree(ti, ett_isis_hello_clv_mt_port_cap_spb_bvid_tuples);

    while (sublen > 0) {
        if (sublen < 6) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_packet, tvb, offset, -1,
                                  "Short SPB BVID header entry (%d vs %d)", sublen, 6);
            return;
        }
        else {
            const guint8 *ect_tlv = tvb_get_ptr(tvb, subofs, 6);
            guint16 word = (ect_tlv[4] << 8) | ect_tlv[5];
            guint16 bvid = (word >> 4) & 0xfff;
            int u_bit = (ect_tlv[5] & 8) ? 1 : 0;
            int m_bit = (ect_tlv[5] & 4) ? 1 : 0;
            proto_tree_add_text( subtree, tvb, subofs, 6,
                                 "ECT: %02x-%02x-%02x-%02x, BVID: 0x%03x (%d),%s U: %d, M: %d",
                                 ect_tlv[0], ect_tlv[1], ect_tlv[2], ect_tlv[3],
                                 bvid, bvid,
                                 (  bvid < 10   ? "   "
                                  : bvid < 100  ? "  "
                                  : bvid < 1000 ? " "
                                  : ""),
                                 u_bit,
                                 m_bit);
        }
        sublen -= 6;
        subofs += 6;
    }
}

static void
dissect_hello_mt_port_cap_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int id_length _U_, int length)
{
    if (length >= 2) {
        /* mtid */
        proto_tree_add_item(tree, hf_isis_hello_mtid, tvb, offset, 2, ENC_BIG_ENDIAN);
        length -= 2;
        offset += 2;
        while (length >= 2) {
            guint8 subtype   = tvb_get_guint8(tvb, offset);
            guint8 subtlvlen = tvb_get_guint8(tvb, offset+1);
            length -= 2;
            offset += 2;
            if (subtlvlen > length) {
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_packet, tvb, offset, -1,
                                      "Short type 0x%02x TLV (%d vs %d)", subtype, subtlvlen, length);
                return;
            }
            if (subtype == 0x04) { /* SPB MCID */
                dissect_hello_mt_port_cap_spb_mcid_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
            }
            else if (subtype == 0x05) { /* SPB Digest */
                dissect_hello_mt_port_cap_spb_digest_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
            }
            else if (subtype == 0x06) { /* SPB BVID Tuples */
                dissect_hello_mt_port_cap_spb_bvid_tuples_clv(tvb, pinfo, tree, offset, subtype, subtlvlen);
            }
            else {
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_subtlv, tvb, offset, -1,
                         "Unknown SubTlv: Type: 0x%02x, Length: %d", subtype, subtlvlen );
            }
            length -= subtlvlen;
            offset += subtlvlen;
        }
    }
}

/*
 * The Restart CLV is documented in RFC 3847 (Restart Signaling for
 * Intermediate System to Intermediate System).  The CLV looks like this
 *
 *  Type   211
 *  Length # of octets in the value field (1 to (3 + ID Length))
 *  Value
 *
 *                                    No. of octets
 *     +-----------------------+
 *     |   Flags               |     1
 *     +-----------------------+
 *     | Remaining Time        |     2
 *     +-----------------------+
 *     | Restarting Neighbor ID|     ID Length
 *     +-----------------------+
 *
 *   Flags (1 octet)
 *
 *      0  1  2  3  4  5  6  7
 *     +--+--+--+--+--+--+--+--+
 *     |  Reserved    |SA|RA|RR|
 *     +--+--+--+--+--+--+--+--+
 *
 *     RR - Restart Request
 *     RA - Restart Acknowledgement
 *     SA - Suppress adjacency advertisement
 *
 * The Remaining Time and Restarting Neighbor ID fields are only required when
 * the RA flag is set.  The Flags field is always required.
 *
 */
/*
 * Name: dissect_hello_restart_clv()
 *
 * Description:
 *	Decode for a restart clv - only found in IIHs
 *      hence no call in the common clv dissector
 *
 */

static void
dissect_hello_restart_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
		proto_tree *tree, int offset, int id_length, int length)
{
	int restart_options=0;
	proto_tree *flags_tree;
	proto_item *restart_flags_item;
	proto_item *hold_time_item;
	const char *sep;

	if (length >= 1) {
	    restart_options = tvb_get_guint8(tvb, offset);
	    restart_flags_item = proto_tree_add_uint ( tree, hf_isis_hello_clv_restart_flags,
		    tvb, offset, 1, restart_options);
	    flags_tree = proto_item_add_subtree(restart_flags_item, ett_isis_hello_clv_restart_flags);
	    proto_tree_add_boolean (flags_tree, hf_isis_hello_clv_restart_flags_sa,
		    tvb, offset, 1, restart_options );
	    proto_tree_add_boolean (flags_tree, hf_isis_hello_clv_restart_flags_ra,
		    tvb, offset, 1, restart_options );
	    proto_tree_add_boolean (flags_tree, hf_isis_hello_clv_restart_flags_rr,
		    tvb, offset, 1, restart_options );

	    /* Append an indication of which flags are set in the restart
	     * options
	     */
	    sep = initial_sep;
	    APPEND_BOOLEAN_FLAG(ISIS_MASK_RESTART_SA(restart_options), restart_flags_item, "%sSA");
	    APPEND_BOOLEAN_FLAG(ISIS_MASK_RESTART_RA(restart_options), restart_flags_item, "%sRA");
	    APPEND_BOOLEAN_FLAG(ISIS_MASK_RESTART_RR(restart_options), restart_flags_item, "%sRR");
	    if (sep != initial_sep)
	    {
		proto_item_append_text (restart_flags_item, ")");
	    }

	}

	/* The Remaining Time field should only be present if the RA flag is
	 * set
	 */
	if (length >= 3 && ISIS_MASK_RESTART_RA(restart_options)) {
	    hold_time_item = proto_tree_add_item( tree, hf_isis_hello_clv_restart_remain_time,
		    tvb, offset+1, 2, ENC_BIG_ENDIAN );
	    proto_item_append_text( hold_time_item, "s" );
	}

	/* The Restarting Neighbor ID should only be present if the RA flag is
	 * set.
	 */
	if (length >= 3 + id_length && ISIS_MASK_RESTART_RA(restart_options)) {
		proto_tree_add_item( tree, hf_isis_hello_clv_restart_neighbor, tvb, offset+3, id_length, ENC_NA);
	}
}

/*
 * Name: dissect_hello_nlpid_clv()
 *
 * Description:
 *	Decode for a hello packets NLPID clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_hello_nlpid_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
	proto_tree *tree, int offset, int id_length _U_, int length)
{
	isis_dissect_nlpid_clv(tvb, tree, offset, length);
}

/*
 * Name: dissect_hello_mt_clv()
 *
 * Description:
 *	Decode for a hello packets Multi Topology clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */

static void
dissect_hello_mt_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
	proto_tree *tree, int offset, int id_length _U_, int length)
{
	isis_dissect_mt_clv(tvb, tree, offset, length,
		hf_isis_hello_clv_mt );
}

/*
 * Name: dissect_hello_ip_int_addr_clv()
 *
 * Description:
 *	Decode for a hello packets ip interface addr clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_hello_ip_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo,
	proto_tree *tree, int offset, int id_length _U_, int length)
{
	isis_dissect_ip_int_clv(tree, pinfo, tvb, &ei_isis_hello_short_packet,
        offset, length, hf_isis_hello_clv_ipv4_int_addr );
}

/*
 * Name: dissect_hello_ipv6_int_addr_clv()
 *
 * Description:
 *	Decode for a hello packets ipv6 interface addr clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_hello_ipv6_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo,
	proto_tree *tree, int offset, int id_length _U_, int length)
{
	isis_dissect_ipv6_int_clv(tree, pinfo, tvb, &ei_isis_hello_short_packet,
        offset, length, hf_isis_hello_clv_ipv6_int_addr );
}

/*
 * Name: dissect_hello_authentication_clv()
 *
 * Description:
 *	Decode for a hello packets authenticaion clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_hello_authentication_clv(tvbuff_t *tvb, packet_info* pinfo,
	proto_tree *tree, int offset, int id_length _U_, int length)
{
	isis_dissect_authentication_clv(tree, pinfo, tvb, &ei_isis_hello_authentication, offset, length);
}

/*
 * Name: dissect_hello_ip_authentication_clv()
 *
 * Description:
 *	Decode for a hello packets IP authenticaion clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_hello_ip_authentication_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
	proto_tree *tree, int offset, int id_length _U_, int length)
{
	isis_dissect_ip_authentication_clv(tvb, tree, offset, length);
}

/*
 * Name: dissect_hello_checksum_clv()
 *
 * Description:
 *      dump and verify the optional checksum in TLV 12
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */

static void
dissect_hello_checksum_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int id_length _U_, int length) {

    guint16 pdu_length,checksum, cacl_checksum=0;

    if (tree) {
        if ( length != 2 ) {
            proto_tree_add_text ( tree, tvb, offset, length,
                                    "incorrect checksum length (%u), should be (2)", length );
            return;
        }

        checksum = tvb_get_ntohs(tvb, offset);

        /* the check_and_get_checksum() function needs to know how big
         * the packet is. we can either pass through the pdu-len through several layers
         * of dissectors and wrappers or extract the PDU length field from the PDU specific header
         * which is offseted 17 bytes in IIHs (relative to the beginning of the IS-IS packet) */
        pdu_length = tvb_get_ntohs(tvb, 17);

        /* unlike the LSP checksum verification which starts at an offset of 12 we start at offset 0*/
        switch (check_and_get_checksum(tvb, 0, pdu_length, checksum, offset, &cacl_checksum))
        {
            case NO_CKSUM :
                proto_tree_add_uint_format_value( tree, hf_isis_hello_checksum, tvb, offset, length, checksum,
                                                "0x%04x [unused]", checksum);
            break;
            case DATA_MISSING :
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_long_packet, tvb, offset, -1,
                        "Packet length %d went beyond packet", tvb_length(tvb) );
            break;
            case CKSUM_NOT_OK :
                proto_tree_add_uint_format_value( tree, hf_isis_hello_checksum, tvb, offset, length, checksum,
                                                "0x%04x [incorrect, should be 0x%04x]",
                                                checksum,
                                                cacl_checksum);
            break;
            case CKSUM_OK :
                proto_tree_add_uint_format_value( tree, hf_isis_hello_checksum, tvb, offset, length, checksum,
                                                "0x%04x [correct]", checksum);
            break;
            default :
                g_message("'check_and_get_checksum' returned an invalid value");
        }
    }
}



/*
 * Name: dissect_hello_area_address_clv()
 *
 * Description:
 *	Decode for a hello packets area address clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_hello_area_address_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
	proto_tree *tree, int offset, int id_length _U_, int length)
{
	isis_dissect_area_address_clv(tree, pinfo, tvb, &ei_isis_hello_short_packet, offset, length);
}

static const value_string adj_state_vals[] = {
    { 0, "Up" },
    { 1, "Initializing" },
    { 2, "Down" },
    { 0, NULL }
};

static void
dissect_hello_ptp_adj_clv(tvbuff_t *tvb, packet_info* pinfo,
		proto_tree *tree, int offset, int id_length, int length)
{
    switch(length)
    {
    case 1:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_NA);
        break;
    case 5:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_isis_hello_extended_local_circuit_id, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        break;
    case 11:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_isis_hello_extended_local_circuit_id, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_hello_neighbor_systemid, tvb, offset+5, id_length, ENC_NA);
    break;
    case 15:
        proto_tree_add_item(tree, hf_isis_hello_adjacency_state, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_isis_hello_extended_local_circuit_id, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_hello_neighbor_systemid, tvb, offset+5, id_length, ENC_NA);
        proto_tree_add_item(tree, hf_isis_hello_neighbor_extended_local_circuit_id, tvb, offset+5+id_length, 4, ENC_BIG_ENDIAN);
    break;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_packet, tvb, offset, -1,
                   "malformed TLV (%d vs 1,5,11,15)", length );
    }
}

/*
 * Name: isis_dissect_is_neighbors_clv()
 *
 * Description:
 *	Take apart a IS neighbor packet.  A neighbor is n 6 byte packets.
 *	(they tend to be an 802.3 MAC address, but it's not required).
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
static void
dissect_hello_is_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	while ( length > 0 ) {
		if (length<6) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_hello_short_packet, tvb, offset, -1,
				"short is neighbor (%d vs 6)", length );
			return;
		}
		/*
		 * Lets turn the area address into "standard" 0000.0000.etc
		 * format string.
		 */
		proto_tree_add_item(tree, hf_isis_hello_is_neighbor, tvb, offset, 6, ENC_NA);
		offset += 6;
		length -= 6;
	}
}

/*
 * Name: dissect_hello_padding_clv()
 *
 * Description:
 *	Decode for a hello packet's padding clv.  Padding does nothing,
 *	so we just return.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void
 */
static void
dissect_hello_padding_clv(tvbuff_t *tvb _U_, packet_info* pinfo _U_, proto_tree *tree _U_, int offset _U_,
	int id_length _U_, int length _U_)
{
	/* nothing to do here! */
}

static const isis_clv_handle_t clv_l1_hello_opts[] = {
	{
		ISIS_CLV_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_hello_clv_is_neighbors,
		dissect_hello_is_neighbors_clv
	},
	{
		ISIS_CLV_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_PROTOCOLS_SUPPORTED,
		"Protocols Supported",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_IP_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_IP6_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_hello_clv_ipv6_int_addr,
		dissect_hello_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_RESTART,
		"Restart Signaling",
		&ett_isis_hello_clv_restart,
		dissect_hello_restart_clv
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_authentication,
		dissect_hello_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_hello_clv_ip_authentication,
		dissect_hello_ip_authentication_clv
	},
	{
		ISIS_CLV_MT_SUPPORTED,
		"Multi Topology",
		&ett_isis_hello_clv_mt,
		dissect_hello_mt_clv
	},
	{
		ISIS_CLV_CHECKSUM,
		"Checksum",
		&ett_isis_hello_clv_checksum,
		dissect_hello_checksum_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_l2_hello_opts[] = {
	{
		ISIS_CLV_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_hello_clv_is_neighbors,
		dissect_hello_is_neighbors_clv
	},
	{
		ISIS_CLV_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_PROTOCOLS_SUPPORTED,
		"Protocols Supported",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_IP_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_IP6_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_hello_clv_ipv6_int_addr,
		dissect_hello_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_authentication,
		dissect_hello_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_hello_clv_ip_authentication,
		dissect_hello_ip_authentication_clv
	},
	{
		ISIS_CLV_RESTART,
		"Restart Signaling",
		&ett_isis_hello_clv_restart,
		dissect_hello_restart_clv
	},
	{
		ISIS_CLV_MT_SUPPORTED,
		"Multi Topology",
		&ett_isis_hello_clv_mt,
		dissect_hello_mt_clv
	},
	{
		ISIS_CLV_CHECKSUM,
		"Checksum",
		&ett_isis_hello_clv_checksum,
		dissect_hello_checksum_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_ptp_hello_opts[] = {
	{
		ISIS_CLV_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_PROTOCOLS_SUPPORTED,
		"Protocols Supported",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_IP_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_IP6_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_hello_clv_ipv6_int_addr,
		dissect_hello_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_authentication,
		dissect_hello_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_hello_clv_ip_authentication,
		dissect_hello_ip_authentication_clv
	},
	{
		ISIS_CLV_MT_PORT_CAP,
		"MT Port Capability",
		&ett_isis_hello_clv_mt_port_cap,
		dissect_hello_mt_port_cap_clv
	},
	{
		ISIS_CLV_RESTART,
		"Restart Option",
		&ett_isis_hello_clv_restart,
		dissect_hello_restart_clv
	},
	{
		ISIS_CLV_PTP_ADJ_STATE,
		"Point-to-point Adjacency State",
		&ett_isis_hello_clv_ptp_adj,
		dissect_hello_ptp_adj_clv
	},
	{
		ISIS_CLV_MT_SUPPORTED,
		"Multi Topology",
		&ett_isis_hello_clv_mt,
		dissect_hello_mt_clv
	},
	{
		ISIS_CLV_CHECKSUM,
		"Checksum",
		&ett_isis_hello_clv_checksum,
		dissect_hello_checksum_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

/*
 * Name: isis_dissect_isis_hello()
 *
 * Description:
 *	This procedure rips apart the various types of ISIS hellos.  L1H and
 *	L2H's are identical for the most part, while the PTP hello has
 *	a shorter header.
 */
static void
dissect_isis_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
	const isis_clv_handle_t *opts, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*hello_tree;
	int				pdu_length;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS HELLO");

	ti = proto_tree_add_item(tree, proto_isis_hello, tvb, offset, -1, ENC_NA);
	hello_tree = proto_item_add_subtree(ti, ett_isis_hello);

	proto_tree_add_item(hello_tree, hf_isis_hello_circuit, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(hello_tree, hf_isis_hello_circuit_reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(hello_tree, hf_isis_hello_source_id, tvb, offset, id_length, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", System-ID: %s", tvb_print_system_id( tvb, offset, id_length ));

	offset += id_length;

	proto_tree_add_item(hello_tree, hf_isis_hello_holding_timer, tvb,
			            offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	pdu_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(hello_tree, hf_isis_hello_pdu_length, tvb,
			            offset, 2, pdu_length);
	offset += 2;

	if (opts == clv_ptp_hello_opts) {
		proto_tree_add_item(hello_tree, hf_isis_hello_local_circuit_id, tvb,
				         offset, 1, ENC_BIG_ENDIAN );
		offset += 1;
	} else {
		proto_tree_add_item(hello_tree, hf_isis_hello_priority, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(hello_tree, hf_isis_hello_priority_reserved, tvb, offset, 1, ENC_NA);
		offset += 1;

		proto_tree_add_item(hello_tree, hf_isis_hello_lan_id, tvb, offset, id_length + 1, ENC_NA);
		offset += id_length + 1;
	}

	pdu_length -= header_length;
	if (pdu_length < 0) {
		expert_add_info_format(pinfo, ti, &ei_isis_hello_long_packet,
			"Packet header length %d went beyond packet", header_length );
		return;
	}
	/*
	 * Now, we need to decode our CLVs.  We need to pass in
	 * our list of valid ones!
	 */
	isis_dissect_clvs(tvb, pinfo, hello_tree, offset,
			opts, &ei_isis_hello_short_packet, pdu_length, id_length,
			ett_isis_hello_clv_unknown);
}


static int
dissect_isis_l1_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_hello(tvb, pinfo, tree, 0,
		clv_l1_hello_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

static int
dissect_isis_l2_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_hello(tvb, pinfo, tree, 0,
		clv_l2_hello_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

static int
dissect_isis_ptp_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_hello(tvb, pinfo, tree, 0,
		clv_ptp_hello_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

/*
 * Name: isis_register_hello()
 *
 * Description:
 *	Register our protocol sub-sets with protocol manager.
 *
 * Input:
 *	int : protocol index for the ISIS protocol
 *
 * Output:
 *	void
 */
void
proto_register_isis_hello(void)
{
	static hf_register_info hf[] = {
		{ &hf_isis_hello_circuit,
		{ "Circuit type", "isis.hello.circuit_type",
			FT_UINT8, BASE_HEX, VALS(isis_hello_circuit_type_vals), ISIS_HELLO_CTYPE_MASK, NULL, HFILL }},

		{ &hf_isis_hello_circuit_reserved,
		{ "Reserved", "isis.hello.reserved",
			FT_UINT8, BASE_HEX, NULL, ISIS_HELLO_CT_RESERVED_MASK, NULL, HFILL }},

		{ &hf_isis_hello_source_id,
		{ "SystemID {Sender of PDU}", "isis.hello.source_id",
			FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_holding_timer,
		{ "Holding timer", "isis.hello.holding_timer",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_pdu_length,
		{ "PDU length", "isis.hello.pdu_length",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_priority,
		 { "Priority", "isis.hello.priority",
			FT_UINT8, BASE_DEC, NULL, ISIS_HELLO_PRIORITY_MASK, NULL, HFILL }},

		{ &hf_isis_hello_priority_reserved,
		 { "Reserved", "isis.hello.reserved",
			FT_UINT8, BASE_DEC, NULL, ISIS_HELLO_P_RESERVED_MASK, NULL, HFILL }},

		{ &hf_isis_hello_lan_id,
		{ "SystemID {Designated IS}", "isis.hello.lan_id",
			FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_local_circuit_id,
		{ "Local circuit ID", "isis.hello.local_circuit_id",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_clv_ipv4_int_addr,
		{ "IPv4 interface address", "isis.hello.clv_ipv4_int_addr",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_clv_ipv6_int_addr,
		{ "IPv6 interface address", "isis.hello.clv_ipv6_int_addr",
			FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},

#if 0
		{ &hf_isis_hello_clv_ptp_adj,
		{ "Point-to-point Adjacency", "isis.hello.clv_ptp_adj",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#endif

		{ &hf_isis_hello_clv_mt,
		{ "MT-ID", "isis.hello.clv_mt",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_clv_restart_flags,
		{ "Restart Signaling Flags", "isis.hello.clv_restart_flags",
			FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_hello_clv_restart_flags_rr,
		{ "Restart Request", "isis.hello.clv_restart_flags.rr",
			FT_BOOLEAN, 8, TFS(&tfs_true_false), ISIS_RESTART_RR,
			"When set, the router is beginning a graceful restart", HFILL }},

		{ &hf_isis_hello_clv_restart_flags_ra,
		{ "Restart Acknowledgment", "isis.hello.clv_restart_flags.ra",
			FT_BOOLEAN, 8, TFS(&tfs_true_false), ISIS_RESTART_RA,
			"When set, the router is willing to enter helper mode", HFILL }},

		{ &hf_isis_hello_clv_restart_flags_sa,
		{ "Suppress Adjacency", "isis.hello.clv_restart_flags.sa",
			FT_BOOLEAN, 8, TFS(&tfs_true_false), ISIS_RESTART_SA,
			"When set, the router is starting as opposed to restarting", HFILL }},

		{ &hf_isis_hello_clv_restart_remain_time,
		{ "Remaining holding time", "isis.hello.clv_restart.remain_time",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"How long the helper router will maintain the existing adjacency", HFILL }},

		{ &hf_isis_hello_clv_restart_neighbor,
		{ "Restarting Neighbor ID", "isis.hello.clv_restart.neighbor",
			FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
			"The System ID of the restarting neighbor", HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_isis_hello_mcid, { "MCID", "isis.hello.mcid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_aux_mcid, { "Aux MCID", "isis.hello.aux_mcid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_digest, { "Digest", "isis.hello.digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_mtid, { "MTID", "isis.hello.mtid", FT_UINT16, BASE_HEX, NULL, 0xfff, NULL, HFILL }},
      { &hf_isis_hello_checksum, { "Checksum", "isis.hello.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_adjacency_state, { "Adjacency State", "isis.hello.adjacency_state", FT_UINT8, BASE_DEC, VALS(adj_state_vals), 0x0, NULL, HFILL }},
      { &hf_isis_hello_extended_local_circuit_id, { "Extended Local circuit ID", "isis.hello.extended_local_circuit_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_neighbor_systemid, { "Neighbor SystemID", "isis.hello.neighbor_systemid", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_neighbor_extended_local_circuit_id, { "Neighbor Extended Local circuit ID", "isis.hello.neighbor_extended_local_circuit_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_hello_is_neighbor, { "IS Neighbor", "isis.hello.is_neighbor", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_isis_hello,
		&ett_isis_hello_clv_area_addr,
		&ett_isis_hello_clv_is_neighbors,
		&ett_isis_hello_clv_padding,
		&ett_isis_hello_clv_unknown,
		&ett_isis_hello_clv_nlpid,
		&ett_isis_hello_clv_authentication,
		&ett_isis_hello_clv_ip_authentication,
		&ett_isis_hello_clv_ipv4_int_addr,
		&ett_isis_hello_clv_ipv6_int_addr,
		&ett_isis_hello_clv_ptp_adj,
		&ett_isis_hello_clv_mt,
		&ett_isis_hello_clv_restart,
		&ett_isis_hello_clv_restart_flags,
		&ett_isis_hello_clv_mt_port_cap,
		&ett_isis_hello_clv_mt_port_cap_spb_mcid,
		&ett_isis_hello_clv_mt_port_cap_spb_aux_mcid,
		&ett_isis_hello_clv_mt_port_cap_spb_digest,
		&ett_isis_hello_clv_mt_port_cap_spb_bvid_tuples,
		&ett_isis_hello_clv_checksum
	};

	static ei_register_info ei[] = {
		{ &ei_isis_hello_short_packet, { "isis.hello.short_packet", PI_MALFORMED, PI_ERROR, "Short packet", EXPFILL }},
		{ &ei_isis_hello_long_packet, { "isis.hello.long_packet", PI_MALFORMED, PI_ERROR, "Long packet", EXPFILL }},
		{ &ei_isis_hello_subtlv, { "isis.hello.subtlv.unknown", PI_PROTOCOL, PI_WARN, "Unknown SubTLV", EXPFILL }},
		{ &ei_isis_hello_authentication, { "isis.hello.authentication.unknown", PI_PROTOCOL, PI_WARN, "Unknown authentication type", EXPFILL }},
	};

	expert_module_t* expert_isis_hello;

	/* Register the protocol name and description */
	proto_isis_hello = proto_register_protocol("ISIS HELLO", "ISIS HELLO", "isis.hello");

	proto_register_field_array(proto_isis_hello, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_isis_hello = expert_register_protocol(proto_isis_hello);
	expert_register_field_array(expert_isis_hello, ei, array_length(ei));
}

void
proto_reg_handoff_isis_hello(void)
{
	dissector_add_uint("isis.type", ISIS_TYPE_L1_HELLO, new_create_dissector_handle(dissect_isis_l1_hello, proto_isis_hello));
	dissector_add_uint("isis.type", ISIS_TYPE_L2_HELLO, new_create_dissector_handle(dissect_isis_l2_hello, proto_isis_hello));
	dissector_add_uint("isis.type", ISIS_TYPE_PTP_HELLO, new_create_dissector_handle(dissect_isis_ptp_hello, proto_isis_hello));
}
