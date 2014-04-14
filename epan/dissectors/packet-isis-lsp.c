/* packet-isis-lsp.c
 * Routines for decoding isis lsp packets and their CLVs
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
/*
 * Copyright 2011, Malgi Nikitha Vivekananda <malgi.nikitha@ipinfusion.com>
 *                 Krishnamurthy Mayya <krishnamurthy.mayya@ipinfusion.com>
 *                    - Decoding for Router Capability TLV and associated subTLVs as per RFC 6326
 *                    - Decoding for Group Address TLV and associated subTLVs as per RFC 6326
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include <epan/addr_resolv.h>
#include <epan/addr_and_mask.h>

/*
 * Declarations for L1/L2 LSP base header.
 */

/* P | ATT | HIPPITY | DS FIELD description */
#define ISIS_LSP_PARTITION_MASK     0x80
#define ISIS_LSP_PARTITION_SHIFT    7
#define ISIS_LSP_PARTITION(info)    (((info) & ISIS_LSP_PARTITION_MASK) >> ISIS_LSP_PARTITION_SHIFT)

#define ISIS_LSP_ATT_MASK     0x78
#define ISIS_LSP_ATT_SHIFT    3
#define ISIS_LSP_ATT(info)    (((info) & ISIS_LSP_ATT_MASK) >> ISIS_LSP_ATT_SHIFT)

#define ISIS_LSP_ATT_ERROR(info)   ((info) >> 3)
#define ISIS_LSP_ATT_EXPENSE(info) (((info) >> 2) & 1)
#define ISIS_LSP_ATT_DELAY(info)   (((info) >> 1) & 1)
#define ISIS_LSP_ATT_DEFAULT(info) ((info) & 1)

#define ISIS_LSP_HIPPITY_MASK     0x04
#define ISIS_LSP_HIPPITY_SHIFT    2
#define ISIS_LSP_HIPPITY(info)    (((info) & ISIS_LSP_HIPPITY_MASK) >> ISIS_LSP_HIPPITY_SHIFT)

#define ISIS_LSP_IS_TYPE_MASK     0x03
#define ISIS_LSP_IS_TYPE(info)    ((info) & ISIS_LSP_IS_TYPE_MASK)

#define ISIS_LSP_MT_MSHIP_RES_MASK   0xF000
#define ISIS_LSP_MT_MSHIP_ID_MASK   0x0FFF


#define ISIS_LSP_TYPE_UNUSED0		0
#define ISIS_LSP_TYPE_LEVEL_1		1
#define ISIS_LSP_TYPE_UNUSED2		2
#define ISIS_LSP_TYPE_LEVEL_2		3

#define ISIS_LSP_ATTACHED_NONE    0
#define ISIS_LSP_ATTACHED_DEFAULT 1
#define ISIS_LSP_ATTACHED_DELAY   2
#define ISIS_LSP_ATTACHED_EXPENSE 4
#define ISIS_LSP_ATTACHED_ERROR   8


#define ISIS_LSP_CLV_METRIC_SUPPORTED(x)	((x)&0x80)
#define ISIS_LSP_CLV_METRIC_IE(x)               ((x)&0x40)
#define ISIS_LSP_CLV_METRIC_RESERVED(x)		((x)&0x40)
#define ISIS_LSP_CLV_METRIC_UPDOWN(x)           ((x)&0x80)
#define ISIS_LSP_CLV_METRIC_VALUE(x)		((x)&0x3f)

/* Sub-TLVs under Router Capability TLV
   As per RFC 6326 section 2.3 */
#define TRILL_VERSION            12
#define NICKNAME                  6
#define TREES                     7
#define TREE_IDENTIFIER           8
#define TREES_USED_IDENTIFIER     9
#define INTERESTED_VLANS         10
#define VLAN_GROUP               13


/*Sub-TLVs under Group Address TLV*/
#define GRP_MAC_ADDRESS 1
#define FP_HMAC_SWID_MASK  G_GINT64_CONSTANT(0xFFFF00000000)
#define FP_HMAC_SSWID_MASK G_GINT64_CONSTANT(0x0000FFFF0000)
#define FP_HMAC_LID_MASK   G_GINT64_CONSTANT(0x00000000FFFF)

void proto_register_isis_lsp(void);
void proto_reg_handoff_isis_lsp(void);

static int proto_isis_lsp = -1;

/* lsp packets */
static int hf_isis_lsp_pdu_length = -1;
static int hf_isis_lsp_remaining_life = -1;
static int hf_isis_lsp_sequence_number = -1;
static int hf_isis_lsp_lsp_id = -1;
static int hf_isis_lsp_hostname = -1;
static int hf_isis_lsp_checksum = -1;
static int hf_isis_lsp_checksum_bad = -1;
static int hf_isis_lsp_checksum_good = -1;
static int hf_isis_lsp_clv_ipv4_int_addr = -1;
static int hf_isis_lsp_clv_ipv6_int_addr = -1;
static int hf_isis_lsp_clv_te_router_id = -1;
static int hf_isis_lsp_clv_mt = -1;
static int hf_isis_lsp_p = -1;
static int hf_isis_lsp_att = -1;
static int hf_isis_lsp_hippity = -1;
static int hf_isis_lsp_is_type = -1;
static int hf_isis_lsp_root_id = -1;
static int hf_isis_lsp_spb_link_metric = -1;
static int hf_isis_lsp_spb_port_count = -1;
static int hf_isis_lsp_spb_port_id = -1;
static int hf_isis_lsp_spb_sr_bit = -1;
static int hf_isis_lsp_spb_spvid = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_isis_lsp_grp_address_length = -1;
static int hf_isis_lsp_mt_cap_spb_instance_v = -1;
static int hf_isis_lsp_mt_cap_spb_instance_cist_external_root_path_cost = -1;
static int hf_isis_lsp_rt_capable_tree_used_id_starting_tree_no = -1;
static int hf_isis_lsp_mt_cap_spb_instance_bridge_priority = -1;
static int hf_isis_lsp_rt_capable_trees_length = -1;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_base_vid = -1;
static int hf_isis_lsp_64_bit_administrative_tag = -1;
static int hf_isis_lsp_grp_address_number_of_sources = -1;
static int hf_isis_lsp_ext_is_reachability_traffic_engineering_default_metric = -1;
static int hf_isis_lsp_grp_address_group_address = -1;
static int hf_isis_lsp_rt_capable_tree_root_id_nickname = -1;
static int hf_isis_lsp_ext_is_reachability_ipv4_interface_address = -1;
static int hf_isis_lsp_ext_ip_reachability_metric = -1;
static int hf_isis_lsp_ext_ip_reachability_ipv4_prefix = -1;
static int hf_isis_lsp_eis_neighbors_es_neighbor_id = -1;
static int hf_isis_lsp_rt_capable_interested_vlans_length = -1;
static int hf_isis_lsp_expense_metric = -1;
static int hf_isis_lsp_ext_is_reachability_link_remote_identifier = -1;
static int hf_isis_lsp_rt_capable_vlan_group_secondary_vlan_id = -1;
static int hf_isis_lsp_grp_address_vlan_id = -1;
static int hf_isis_lsp_rt_capable_trill_length = -1;
static int hf_isis_lsp_rt_capable_tree_root_id_starting_tree_no = -1;
static int hf_isis_lsp_rt_capable_interested_vlans_nickname = -1;
static int hf_isis_lsp_rt_capable_nickname_length = -1;
static int hf_isis_lsp_ip_reachability_ipv4_prefix = -1;
static int hf_isis_lsp_grp_address_topology_id = -1;
static int hf_isis_lsp_ext_is_reachability_ipv4_neighbor_address = -1;
static int hf_isis_lsp_rt_capable_vlan_group_nth_secondary_vlan_id = -1;
static int hf_isis_lsp_ipv6_reachability_reserved_bits = -1;
static int hf_isis_lsp_eis_neighbors_default_metric = -1;
static int hf_isis_lsp_mt_cap_spb_instance_cist_root_identifier = -1;
static int hf_isis_lsp_rt_capable_tree_used_id_nickname = -1;
static int hf_isis_lsp_grp_address_source_address = -1;
static int hf_isis_lsp_delay_metric = -1;
static int hf_isis_lsp_ext_is_reachability_link_local_identifier = -1;
static int hf_isis_lsp_mt_cap_mtid = -1;
static int hf_isis_lsp_32_bit_administrative_tag = -1;
static int hf_isis_lsp_ext_is_reachability_is_neighbor_id = -1;
static int hf_isis_lsp_reservable_link_bandwidth = -1;
static int hf_isis_lsp_rt_capable_vlan_group_primary_vlan_id = -1;
static int hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv4 = -1;
static int hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv6 = -1;
static int hf_isis_lsp_mt_cap_spb_instance_number_of_trees = -1;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_b_mac = -1;
static int hf_isis_lsp_ipv6_reachability_distribution = -1;
static int hf_isis_lsp_ipv6_reachability_distribution_internal = -1;
static int hf_isis_lsp_ipv6_reachability_metric = -1;
static int hf_isis_lsp_rt_capable_trees_maximum_nof_trees_to_compute = -1;
static int hf_isis_lsp_rt_capable_interested_vlans_vlan_start_id = -1;
static int hf_isis_lsp_rt_capable_nickname_nickname_priority = -1;
static int hf_isis_lsp_ext_is_reachability_metric = -1;
static int hf_isis_lsp_default_metric = -1;
static int hf_isis_lsp_ext_ip_reachability_distribution = -1;
static int hf_isis_lsp_maximum_link_bandwidth = -1;
static int hf_isis_lsp_rt_capable_tree_root_id_length = -1;
static int hf_isis_lsp_rt_capable_nickname_tree_root_priority = -1;
static int hf_isis_lsp_eis_neighbors_delay_metric = -1;
static int hf_isis_lsp_rt_capable_trill_maximum_version = -1;
static int hf_isis_lsp_rt_capable_interested_vlans_afs_lost_counter = -1;
static int hf_isis_lsp_ipv6_reachability_ipv6_prefix = -1;
static int hf_isis_lsp_eis_neighbors_error_metric = -1;
static int hf_isis_lsp_rt_capable_interested_vlans_vlan_end_id = -1;
static int hf_isis_lsp_error_metric = -1;
static int hf_isis_lsp_grp_address_number_of_records = -1;
static int hf_isis_lsp_rt_capable_tree_used_id_length = -1;
static int hf_isis_lsp_rt_capable_nickname_nickname = -1;
static int hf_isis_lsp_mt_id_reserved = -1;
static int hf_isis_lsp_eis_neighbors_is_neighbor_id = -1;
static int hf_isis_lsp_mt_id = -1;
static int hf_isis_lsp_eis_neighbors_reserved = -1;
static int hf_isis_lsp_ip_reachability_error_metric = -1;
static int hf_isis_lsp_ip_reachability_delay_metric = -1;
static int hf_isis_lsp_ip_reachability_expense_metric = -1;
static int hf_isis_lsp_rt_capable_trees_nof_trees_to_use = -1;
static int hf_isis_lsp_ip_reachability_default_metric = -1;
static int hf_isis_lsp_rt_capable_trees_nof_trees_to_compute = -1;
static int hf_isis_lsp_eis_neighbors_expense_metric = -1;
static int hf_isis_lsp_rt_capable_vlan_group_length = -1;
static int hf_isis_lsp_partition_designated_l2_is = -1;
static int hf_isis_lsp_ip_reachability_default_metric_ie = -1;
static int hf_isis_lsp_eis_neighbors_default_metric_ie = -1;
static int hf_isis_lsp_eis_neighbors_error_metric_supported = -1;
static int hf_isis_lsp_unrsv_bw_priority_level = -1;
static int hf_isis_lsp_ip_reachability_expense_metric_support = -1;
static int hf_isis_lsp_mt_cap_overload = -1;
static int hf_isis_lsp_eis_neighbors_expense_metric_supported = -1;
static int hf_isis_lsp_ip_reachability_delay_metric_support = -1;
static int hf_isis_lsp_ip_reachability_error_metric_support = -1;
static int hf_isis_lsp_mt_cap_spsourceid = -1;
static int hf_isis_lsp_eis_neighbors_delay_metric_supported = -1;
static int hf_isis_lsp_eis_neighbors_error_metric_ie = -1;
static int hf_isis_lsp_eis_neighbors_expense_metric_ie = -1;
static int hf_isis_lsp_eis_neighbors_delay_metric_ie = -1;
static int hf_isis_lsp_ip_reachability_delay_metric_ie = -1;
static int hf_isis_lsp_ip_reachability_distribution = -1;
static int hf_isis_lsp_ip_reachability_error_metric_ie = -1;
static int hf_isis_lsp_ip_reachability_expense_metric_ie = -1;

static gint ett_isis_lsp = -1;
static gint ett_isis_lsp_info = -1;
static gint ett_isis_lsp_att = -1;
static gint ett_isis_lsp_cksum = -1;
static gint ett_isis_lsp_clv_area_addr = -1;
static gint ett_isis_lsp_clv_is_neighbors = -1;
static gint ett_isis_lsp_clv_ext_is_reachability = -1; /* CLV 22 */
static gint ett_isis_lsp_part_of_clv_ext_is_reachability = -1;
static gint ett_isis_lsp_subclv_admin_group = -1;
static gint ett_isis_lsp_subclv_unrsv_bw = -1;
static gint ett_isis_lsp_subclv_spb_link_metric = -1;
static gint ett_isis_lsp_clv_unknown = -1;
static gint ett_isis_lsp_clv_partition_dis = -1;
static gint ett_isis_lsp_clv_prefix_neighbors = -1;
static gint ett_isis_lsp_clv_nlpid = -1;
static gint ett_isis_lsp_clv_hostname = -1;
static gint ett_isis_lsp_clv_te_router_id = -1;
static gint ett_isis_lsp_clv_authentication = -1;
static gint ett_isis_lsp_clv_ip_authentication = -1;
static gint ett_isis_lsp_clv_ipv4_int_addr = -1;
static gint ett_isis_lsp_clv_ipv6_int_addr = -1; /* CLV 232 */
static gint ett_isis_lsp_clv_mt_cap = -1;
static gint ett_isis_lsp_clv_mt_cap_spb_instance = -1;
static gint ett_isis_lsp_clv_mt_cap_spbm_service_identifier = -1;
static gint ett_isis_lsp_clv_ip_reachability = -1;
static gint ett_isis_lsp_clv_ip_reach_subclv = -1;
static gint ett_isis_lsp_clv_ext_ip_reachability = -1; /* CLV 135 */
static gint ett_isis_lsp_part_of_clv_ext_ip_reachability = -1;
static gint ett_isis_lsp_clv_ipv6_reachability = -1; /* CLV 236 */
static gint ett_isis_lsp_part_of_clv_ipv6_reachability = -1;
static gint ett_isis_lsp_clv_mt = -1;
static gint ett_isis_lsp_clv_mt_is = -1;
static gint ett_isis_lsp_part_of_clv_mt_is = -1;
static gint ett_isis_lsp_clv_mt_reachable_IPv4_prefx = -1;  /* CLV 235 */
static gint ett_isis_lsp_clv_mt_reachable_IPv6_prefx = -1;  /* CLV 237 */
static gint ett_isis_lsp_clv_rt_capable_IPv4_prefx = -1;   /* CLV 242 */
static gint ett_isis_lsp_clv_grp_address_IPv4_prefx = -1;  /* CLV 142 */
static gint ett_isis_lsp_clv_mt_cap_spbv_mac_address = -1;

static expert_field ie_isis_lsp_checksum_bad = EI_INIT;
static expert_field ei_isis_lsp_short_packet = EI_INIT;
static expert_field ei_isis_lsp_long_packet = EI_INIT;
static expert_field ei_isis_lsp_subtlv = EI_INIT;
static expert_field ei_isis_lsp_authentication = EI_INIT;

static const value_string isis_lsp_istype_vals[] = {
	{ ISIS_LSP_TYPE_UNUSED0,	"Unused 0x0 (invalid)"},
	{ ISIS_LSP_TYPE_LEVEL_1,	"Level 1"},
	{ ISIS_LSP_TYPE_UNUSED2,	"Unused 0x2 (invalid)"},
	{ ISIS_LSP_TYPE_LEVEL_2,	"Level 2"},
	{ 0, NULL } };

static const true_false_string tfs_up_down = { "Up", "Down" };
static const true_false_string tfs_notsupported_supported = { "Not Supported", "Supported" };
static const true_false_string tfs_internal_external = { "Internal", "External" };
static const true_false_string tfs_external_internal = { "External", "Internal" };

static void
fp_get_hmac_addr (guint64 hmac, guint16 *swid, guint16 *sswid, guint16 *lid) {

	if (!swid || !sswid || !lid) {
		return;
	}

	*swid  = (guint16) ((hmac & FP_HMAC_SWID_MASK) >> 32);
	*sswid = (guint16) ((hmac & FP_HMAC_SSWID_MASK) >> 16);
	*lid   = (guint16)  (hmac & FP_HMAC_LID_MASK);
}
/*
 * Name: dissect_lsp_mt_id()
 *
 * Description:
 *	dissect and display the multi-topology ID value
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  CAN'T BE NULL
 *	int : offset into packet data where we are.
 *
 * Output:
 *	void, but we will add to proto tree.
 */
static void
dissect_lsp_mt_id(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	int  mt_block, mt_id;
	const char *mt_desc="";

	/* fetch two bytes */
	mt_block = tvb_get_ntohs(tvb, offset);

	proto_tree_add_item(tree, hf_isis_lsp_mt_id_reserved, tvb, offset, 2, ENC_NA);

	mt_id = mt_block & ISIS_LSP_MT_MSHIP_ID_MASK;
	/*mask out the lower 12 bits */
	switch(mt_id) {
	case 0:
		mt_desc="'standard' topology";
		break;
	case 1:
		mt_desc="IPv4 In-Band Management purposes";
		break;
	case 2:
		mt_desc="IPv6 routing topology";
		break;
	case 3:
		mt_desc="IPv4 multicast routing topology";
		break;
	case 4:
		mt_desc="IPv6 multicast routing topology";
		break;
	default:
		mt_desc=((mt_block & 0x0fff) < 3996) ? "Reserved for IETF Consensus" : "Development, Experimental and Proprietary features";
	}

	proto_tree_add_uint_format( tree, hf_isis_lsp_mt_id, tvb, offset, 2,
	                     mt_id, "%s (%d)", mt_desc, mt_id);

}

/*
 * Name: dissect_metric()
 *
 * Description:
 *	Display a metric prefix portion.  ISIS has the concept of multple
 *	metric per prefix (default, delay, expense, and error).  This
 *	routine assists other dissectors by adding a single one of
 *	these to the display tree..
 *
 *	The 8th(msbit) bit in the metric octet is the "supported" bit.  The
 *		"default" support is required, so we support a "force_supported"
 *		flag that tells us that it MUST be zero (zero==supported,
 *		so it really should be a "not supported" in the boolean sense)
 *		and to display a protocol failure accordingly.  Notably,
 *		Cisco IOS 12(6) blows this!
 *	The 7th bit must be zero (reserved).
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	guint8 : value of the metric.
 *	char * : string giving type of the metric.
 *	int : force supported.  True is the supported bit MUST be zero.
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
static void
dissect_metric(tvbuff_t *tvb, proto_tree *tree,	int offset, guint8 value,
	const char *pstr, int force_supported )
{
	int s;

	if ( !tree ) return;

	s = ISIS_LSP_CLV_METRIC_SUPPORTED(value);
	proto_tree_add_text(tree, tvb, offset, 1,
		"%s Metric: %s%s %s%d:%d", pstr,
		s ? "Not supported" : "Supported",
		(s && force_supported) ? "(but is required to be)":"",
		ISIS_LSP_CLV_METRIC_RESERVED(value) ? "(reserved bit != 0)":"",
		ISIS_LSP_CLV_METRIC_VALUE(value), value );
}

/*
 * Name: dissect_lsp_ip_reachability_clv()
 *
 * Description:
 *	Decode an IP reachability CLV.  This can be either internal or
 *	external (the clv format does not change and which type we are
 *	displaying is put there by the dispatcher).  All of these
 *	are a metric block followed by an IP addr and mask.
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
dissect_lsp_ip_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	proto_item 	*ti;
	proto_tree	*ntree = NULL;
	guint32		src, mask, bitmask;
	int		prefix_len;
	gboolean	found_mask = FALSE;

	while ( length > 0 ) {
		if (length<12) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"short IP reachability (%d vs 12)", length );
			return;
		}
		/*
		 * Gotta build a sub-tree for all our pieces
		 */
		if ( tree ) {
			src = tvb_get_ipv4(tvb, offset+4);
			mask = tvb_get_ntohl(tvb, offset+8);

			/* find out if the mask matches one of 33 possible prefix lengths */
			bitmask = 0xffffffff;
			for(prefix_len = 32; prefix_len >= 0; prefix_len--) {
				if (bitmask==mask) {
					found_mask = TRUE;
					break;
				}
				bitmask = bitmask << 1;
			}

			/* If we have a discontiguous netmask, dump the mask, otherwise print the prefix_len */
			/* XXX - We should probably have some sort of netmask_to_str() routine in to_str.c that does this. */

			if(found_mask) {
			  ti = proto_tree_add_ipv4_format_value( tree, hf_isis_lsp_ip_reachability_ipv4_prefix, tvb, offset, 12,
				src, "%s/%d", ip_to_str((guint8*)&src), prefix_len );
			} else {
			  ti = proto_tree_add_ipv4_format_value( tree, hf_isis_lsp_ip_reachability_ipv4_prefix, tvb, offset, 12,
				src, "%s mask %s", ip_to_str((guint8*)&src), tvb_ip_to_str(tvb, offset+8));
			};

			ntree = proto_item_add_subtree(ti, ett_isis_lsp_clv_ip_reachability);

			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_default_metric, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_default_metric_ie, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_distribution, tvb, offset, 1, ENC_NA);

			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_delay_metric, tvb, offset+1, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_delay_metric_support, tvb, offset+1, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_delay_metric_ie, tvb, offset+1, 1, ENC_NA);

			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_expense_metric, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_expense_metric_support, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_expense_metric_ie, tvb, offset+2, 1, ENC_NA);

			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_error_metric, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_error_metric_support, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_error_metric_ie, tvb, offset+3, 1, ENC_NA);
		}
		offset += 12;
		length -= 12;
	}
}

/*
 * Name: dissect_ipreach_subclv ()
 *
 * Description: parses IP reach subTLVs
 *              Called by various IP Reachability dissectors.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_ipreach_subclv(tvbuff_t *tvb, proto_tree *tree, int offset, int clv_code, int clv_len)
{

	switch (clv_code) {
	case 1:
		while (clv_len >= 4) {
			proto_tree_add_item(tree, hf_isis_lsp_32_bit_administrative_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			clv_len-=4;
		}
		break;
	case 2:
		while (clv_len >= 8) {
			proto_tree_add_item(tree, hf_isis_lsp_64_bit_administrative_tag, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset+=8;
			clv_len-=8;
		}
		break;

		default :
			proto_tree_add_text (tree, tvb, offset, clv_len+2,
			                     "Unknown sub-TLV: code %u, length %u",
			                     clv_code, clv_len );
			break;
	}
}


/*
 * Name: dissect_lsp_ext_ip_reachability_clv()
 *
 * Description: Decode an Extended IP Reachability CLV - code 135.
 *
 *   The extended IP reachability TLV is an extended version
 *   of the IP reachability TLVs (codes 128 and 130). It encodes
 *   the metric as a 32-bit unsigned interger and allows to add
 *   sub-CLV(s).
 *
 *   CALLED BY TLV 235 DISSECTOR
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ext_ip_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
	int offset, int id_length _U_, int length)
{
	proto_item *pi = NULL;
	proto_tree *subtree = NULL;
	proto_tree *subtree2 = NULL;
	guint8     ctrl_info;
	guint      bit_length;
	int        byte_length;
	guint8     prefix [4];
	guint      len,i;
	guint      subclvs_len;
	guint      clv_code, clv_len;

	if (!tree) return;

	while (length > 0) {
		ctrl_info = tvb_get_guint8(tvb, offset+4);
		bit_length = ctrl_info & 0x3f;
		byte_length = ipv4_addr_and_mask(tvb, offset+5, prefix, bit_length);
		if (byte_length == -1) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
			 	"IPv4 prefix has an invalid length: %d bits", bit_length );
				return;
			}
		subclvs_len = 0;
		if ((ctrl_info & 0x40) != 0)
			subclvs_len = 1+tvb_get_guint8(tvb, offset+5+byte_length);

		/* open up a new tree per prefix */
		pi = proto_tree_add_text (tree, tvb, offset, 5+byte_length+subclvs_len, "Ext. IP Reachability");
		subtree = proto_item_add_subtree (pi, ett_isis_lsp_part_of_clv_ext_ip_reachability);

		proto_tree_add_ipv4_format_value(subtree, hf_isis_lsp_ext_ip_reachability_ipv4_prefix, tvb, offset+5, byte_length,
                             tvb_get_ntohl(tvb, offset+5), "%s/%u", ip_to_str (prefix), bit_length);
		proto_tree_add_item(subtree, hf_isis_lsp_ext_ip_reachability_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isis_lsp_ext_ip_reachability_distribution, tvb, offset+4, 1, ENC_NA);

		len = 5 + byte_length;
		if ((ctrl_info & 0x40) != 0) {
			subclvs_len = tvb_get_guint8(tvb, offset+len);
			pi = proto_tree_add_text (subtree, tvb, offset+len, 1, "sub-TLVs present, total length: %u bytes",
			                          subclvs_len);
			proto_item_set_len (pi, subclvs_len+1);
			/* open up a new tree for the subTLVs */
			subtree2 = proto_item_add_subtree (pi, ett_isis_lsp_clv_ip_reach_subclv);

			i =0;
			while (i < subclvs_len) {
				clv_code = tvb_get_guint8(tvb, offset+len+1); /* skip the total subtlv len indicator */
				clv_len  = tvb_get_guint8(tvb, offset+len+2);

				/*
				 * we pass on now the raw data to the ipreach_subtlv dissector
				 * therefore we need to skip 3 bytes
				 * (total subtlv len, subtlv type, subtlv len)
				 */
				dissect_ipreach_subclv(tvb, subtree2, offset+len+3, clv_code, clv_len);
				i += clv_len + 2;
			}
			len += 1 + subclvs_len;
		} else {
			proto_tree_add_text (subtree, tvb, offset+4, 1, "no sub-TLVs present");
			                     proto_item_set_len (pi, len);
		}

		offset += len;
		length -= len;
	}
}

/*
 * Name: dissect_isis_grp_address_clv()
 *
 * Description: Decode GROUP ADDRESS subTLVs
 *              The  Group Address  TLV is composed of 1 octet for the type,
 *              1 octet that specifies the number of bytes in the value field, and a
 *              Variable length value field that can have any or all of the subTLVs that are listed in the
 *              - below section
 *
 *Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */

static void
dissect_isis_grp_address_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
	int tree_id,int length)
{
	gint len;
	gint source_num;
	gint k=1;
	guint16 mt_block;
	guint64 hmac_src;
	guint16 swid = 0;
	guint16 sswid = 0;
	guint16 lid = 0;

	proto_item *ti=NULL;
	proto_tree *rt_tree=NULL;

	while (length>0) {
		/* fetch two bytes */
		mt_block=tvb_get_ntohs(tvb, offset);
		/* Mask out the lower 8 bits */
		switch((mt_block&0xff00)>>8) {


			case GRP_MAC_ADDRESS:
				ti = proto_tree_add_text (tree, tvb, offset, (mt_block&0x00ff)+2, "GROUP MAC ADDRESS SUB TLV");
				rt_tree = proto_item_add_subtree(ti,ett_isis_lsp_clv_grp_address_IPv4_prefx);

				length--;
				offset++;

				len=tvb_get_guint8(tvb, offset);/* 1 byte fetched displays the length*/
				proto_tree_add_item(rt_tree, hf_isis_lsp_grp_address_length, tvb, offset, 1, ENC_NA);

				if(len < 5) {
					length -= len;
					offset += len;
					break;
				}

				length--;
				offset++;

				proto_tree_add_item(rt_tree, hf_isis_lsp_grp_address_topology_id, tvb, offset, 2, ENC_BIG_ENDIAN);

				length -= 2;
				offset += 2;
				len -= 2;

				proto_tree_add_item(rt_tree, hf_isis_lsp_grp_address_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

				length -= 2;
				offset += 2;
				len -= 2;

				proto_tree_add_item(rt_tree, hf_isis_lsp_grp_address_number_of_records, tvb, offset, 1, ENC_NA);

				length--;
				offset++;
				len--;

				while(len > 0) {

					source_num=tvb_get_guint8(tvb, offset);
					proto_tree_add_item(rt_tree, hf_isis_lsp_grp_address_number_of_sources, tvb, offset, 1, ENC_NA);

					length--;
					offset++;
					len--;

					hmac_src=tvb_get_ntoh48(tvb, offset);/* Fetch the data in the next two bytes for display*/

					fp_get_hmac_addr (hmac_src, &swid, &sswid, &lid);
					proto_tree_add_bytes_format_value(rt_tree, hf_isis_lsp_grp_address_group_address, tvb, offset, 6,
                                                tvb_get_ptr(tvb, offset, 6), "%04x.%04x.%04x", swid, sswid, lid );

					length -= 6;
					offset += 6;
					len -= 6;

					while((len > 0) && (source_num > 0)) {
						hmac_src = tvb_get_ntoh48 (tvb, offset);
						fp_get_hmac_addr (hmac_src, &swid, &sswid, &lid);
						proto_tree_add_bytes_format(rt_tree, hf_isis_lsp_grp_address_source_address, tvb, offset, 6,
                                                tvb_get_ptr(tvb, offset, 6), "Source Address (%d):%04x.%04x.%04x",
                                                k, swid, sswid, lid);

						k++;
						length -= 6;
						offset += 6;
						len -= 6;
						source_num--;
					}
				}

				break;


			default:
				proto_tree_add_uint_format ( tree, tree_id, tvb, offset,(mt_block&0x00ff)+2,
						mt_block, "INVALID SUB TLV");
				offset++;
				length -= (2+tvb_get_guint8(tvb, offset));
				offset += (1+tvb_get_guint8(tvb, offset));
				break;
		}
	}
}

/*
 * Name: dissect_isis_rt_capable_clv()
 *
 * Description: Decode RouterCapability subTLVs
 *
 *   The Router Capability TLV is composed of 1 octet for the type,
 *   1 octet that specifies the number of bytes in the value field, and a
 *   variable length value field that can have any or all of the subTLVs
 *   that are listed in the below section
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *   len : local variable described to handle the length of the subTLV
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */

/* As per RFC 6326 section 2.3 */
static void
dissect_isis_rt_capable_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, int id_length _U_, int length)
{
	gint len;
	guint16 rt_block;
	proto_item *ti;
	proto_tree *rt_tree;

	gint root_id = 1;       /* To display the root id */
	gint sec_vlan_id = 1;   /* To display the seconadary VLAN id */
	length = length - 5;    /* Ignoring the 5 reserved bytes */
	offset = offset + 5;

	while (length>1) {
		/* fetch two bytes */
		rt_block = tvb_get_ntohs(tvb, offset);

		/* Mask out the lower 8 bits */
		switch ((rt_block&0xff00)>>8) {

		case TRILL_VERSION:
			ti = proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "TRILL version sub tlv");
			rt_tree = proto_item_add_subtree(ti, ett_isis_lsp_clv_rt_capable_IPv4_prefx);

			length--;
			offset++;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trill_length, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trill_maximum_version, tvb, offset+1, 1, ENC_NA);

			length -= 2;
			offset += 2;

			break;

		case TREES:
			ti = proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "Trees sub tlv");
			rt_tree = proto_item_add_subtree(ti, ett_isis_lsp_clv_rt_capable_IPv4_prefx);

			length--;
			offset++;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trees_length, tvb, offset, 1, ENC_NA);

			length--;
			offset++;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trees_nof_trees_to_compute, tvb, offset, 2, ENC_BIG_ENDIAN);

			length -= 2;
			offset += 2;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trees_maximum_nof_trees_to_compute, tvb, offset, 2, ENC_BIG_ENDIAN);

			length -= 2;
			offset += 2;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trees_nof_trees_to_use, tvb, offset, 2, ENC_BIG_ENDIAN);

			length -= 2;
			offset += 2;
			break;

		case TREE_IDENTIFIER:
			ti=proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "Tree root identifier sub tlv");
			rt_tree = proto_item_add_subtree(ti, ett_isis_lsp_clv_rt_capable_IPv4_prefx);

			length--;
			offset++;

			len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_tree_root_id_length, tvb, offset, 1, ENC_NA);

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_tree_root_id_starting_tree_no, tvb, offset+1, 2, ENC_BIG_ENDIAN);

			len -= 2;
			length -= 2;
			offset += 2;

			while (len>1) {
				rt_block = tvb_get_ntohs(tvb, offset);
				proto_tree_add_uint_format(rt_tree, hf_isis_lsp_rt_capable_tree_root_id_nickname, tvb, offset, 2,
                                           rt_block, "Nickname(%dth root): %d", root_id, rt_block);
				root_id++;
				len -= 2;
				length -= 2;
				offset += 2;
			}
			break;

		case NICKNAME:
			ti=proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "The nickname sub tlv");
			rt_tree = proto_item_add_subtree(ti, ett_isis_lsp_clv_rt_capable_IPv4_prefx);

			length--;
			offset++;
			len = tvb_get_guint8(tvb, offset);

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_nickname_length, tvb, offset, 1, ENC_NA);
			length--;
			offset++;

			while (len>0) {
				proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_nickname_nickname_priority, tvb, offset, 1, ENC_NA);
				length--;
				offset++;
				len--;

				proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_nickname_tree_root_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
				len -= 2;
				length -= 2;
				offset += 2;

				proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_nickname_nickname, tvb, offset, 2, ENC_BIG_ENDIAN);
				length = length-2;
				offset = offset+2;
				len = len-2;
			}
			break;

		case INTERESTED_VLANS:
			ti = proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "Interested VLAN and spanning tree root sub tlv");
			rt_tree = proto_item_add_subtree(ti, ett_isis_lsp_clv_rt_capable_IPv4_prefx);

			length--;
			offset++;

			len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_length, tvb, offset, 1, ENC_NA);
			length--;
			offset++;
			len--;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_nickname, tvb, offset, 2, ENC_BIG_ENDIAN);
			len -= 2;
			length -= 2;
			offset += 2;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv4, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv6, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_vlan_start_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			len -= 2;
			length -= 2;
			offset += 2;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_vlan_end_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			len -= 2;
			length -= 2;
			offset += 2;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_afs_lost_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
			length -= 4;
			offset += 4;
			len -= 4;

			while (len>0) {
				proto_tree_add_item(rt_tree, hf_isis_lsp_root_id, tvb, offset, 6, ENC_BIG_ENDIAN);

				length -= 6;
				offset += 6;
				len -= 6;
			}
			break;

		case TREES_USED_IDENTIFIER:
			ti=proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "Trees used identifier sub tlv");
			rt_tree = proto_item_add_subtree(ti, ett_isis_lsp_clv_rt_capable_IPv4_prefx);

			length--;
			offset++;

			len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_tree_used_id_length, tvb, offset, 1, ENC_NA);

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_tree_used_id_starting_tree_no, tvb, offset+1, 2, ENC_BIG_ENDIAN);
			len -= 2;
			length += 2;
			offset += 3;
			root_id = 1;

			while (len>0) {
				rt_block = tvb_get_ntohs(tvb, offset);
				proto_tree_add_uint_format(rt_tree, hf_isis_lsp_rt_capable_tree_used_id_nickname, tvb, offset,2,
                                rt_block, "Nickname(%dth root): %d", root_id, rt_block);
				root_id++;

				len -= 2;
				offset += 2;
				length -= 2;
			}
			break;

		case VLAN_GROUP:
			ti = proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "The VLAN group sub tlv");
			rt_tree = proto_item_add_subtree(ti, ett_isis_lsp_clv_rt_capable_IPv4_prefx);

			length--;
			offset++;

			len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_vlan_group_length, tvb, offset, 1, ENC_NA);

			len--;
			length--;
			offset++;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_vlan_group_primary_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

			len -= 2;
			offset += 2;
			length -= 2;

			proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_vlan_group_secondary_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

			len -= 2;
			offset += 2;
			length -= 2;
			sec_vlan_id = 1;

			while (len>0) {
				rt_block = tvb_get_ntohs(tvb, offset);

				proto_tree_add_uint_format(rt_tree, hf_isis_lsp_rt_capable_vlan_group_nth_secondary_vlan_id, tvb, offset, 2,
                                           rt_block, "%dth secondary vlan id: %x", sec_vlan_id, rt_block);

				length -= 2;
				offset += 2;
				sec_vlan_id++;
				len -= 2;
			}
			break;

		default:
			proto_tree_add_text(tree, tvb, offset, (rt_block&0x00ff)+2, "INVALID sub tlv");

			offset++;
			length -= (2+tvb_get_guint8(tvb, offset));
			offset += (1+tvb_get_guint8(tvb, offset));
			break;
		}
	}
}




/*
 * Name: dissect_lsp_ipv6_reachability_clv()
 *
 * Description: Decode an IPv6 reachability CLV - code 236.
 *
 *   CALLED BY TLV 237 DISSECTOR
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ipv6_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	proto_item        *pi;
	proto_tree        *subtree = NULL;
	proto_tree        *subtree2 = NULL;
	guint8            ctrl_info;
	guint             bit_length;
	int               byte_length;
	struct e_in6_addr prefix;
	guint             len,i;
	guint             subclvs_len;
	guint             clv_code, clv_len;

	if (!tree) return;

	while (length > 0) {
		ctrl_info = tvb_get_guint8(tvb, offset+4);
		bit_length = tvb_get_guint8(tvb, offset+5);
		byte_length = ipv6_addr_and_mask(tvb, offset+6, &prefix, bit_length);
		if (byte_length == -1) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"IPv6 prefix has an invalid length: %d bits", bit_length );
				return;
			}
		subclvs_len = 0;
		if ((ctrl_info & 0x20) != 0)
			subclvs_len = 1+tvb_get_guint8(tvb, offset+6+byte_length);

		pi = proto_tree_add_text (tree, tvb, offset, 6+byte_length+subclvs_len, "IPv6 Reachability");
		subtree = proto_item_add_subtree (pi, ett_isis_lsp_part_of_clv_ipv6_reachability);

		proto_tree_add_ipv6_format_value(subtree, hf_isis_lsp_ipv6_reachability_ipv6_prefix, tvb, offset+6, byte_length,
                             (guint8*)&prefix, "IPv6 prefix: %s/%u", ip6_to_str (&prefix), bit_length);

		proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_distribution, tvb, offset+4, 1, ENC_NA);
		proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_distribution_internal, tvb, offset+4, 1, ENC_NA);

		if ((ctrl_info & 0x1f) != 0) {
			proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_reserved_bits, tvb, offset+4, 1, ENC_NA);
		}

		len = 6 + byte_length;
		if ((ctrl_info & 0x20) != 0) {
			subclvs_len = tvb_get_guint8(tvb, offset+len);
			pi = proto_tree_add_text (subtree, tvb, offset+len, 1, "sub-TLVs present, total length: %u bytes",
			                          subclvs_len);
			proto_item_set_len (pi, subclvs_len+1);
			/* open up a new tree for the subTLVs */
			subtree2 = proto_item_add_subtree (pi, ett_isis_lsp_clv_ip_reach_subclv);

			i =0;
			while (i < subclvs_len) {
				clv_code = tvb_get_guint8(tvb, offset+len+1); /* skip the total subtlv len indicator */
				clv_len  = tvb_get_guint8(tvb, offset+len+2);
				dissect_ipreach_subclv(tvb, subtree2, offset+len+3, clv_code, clv_len);
				i += clv_len + 2;
			}
			len += 1 + subclvs_len;
		} else {
			proto_tree_add_text (subtree, tvb, offset+4, 1, "no sub-TLVs present");
			proto_item_set_len (pi, len);
		}
		offset += len;
		length -= len;
	}
}

/*
 * Name: dissect_lsp_nlpid_clv()
 *
 * Description:
 *	Decode for a lsp packets NLPID clv.  Calls into the
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
dissect_lsp_nlpid_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_nlpid_clv(tvb, tree, offset, length);
}

/*
 * Name: dissect_lsp_mt_clv()
 *
 * Description: - code 229
 *	Decode for a lsp packets Multi Topology clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	guint : length of this clv
 *	int : length of IDs in packet.
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_lsp_mt_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_mt_clv(tvb, tree, offset, length, hf_isis_lsp_clv_mt );
}

/*
 * Name: dissect_lsp_hostname_clv()
 *
 * Description:
 *      Decode for a lsp packets hostname clv.  Calls into the
 *      clv common one.
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : proto tree to build on (may be null)
 *      int : current offset into packet data
 *      int : length of IDs in packet.
 *      int : length of this clv
 *
 * Output:
 *      void, will modify proto_tree if not null.
 */
static void
dissect_lsp_hostname_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_hostname_clv(tvb, tree, offset, length,
		hf_isis_lsp_hostname);
}


/*
 * Name: dissect_lsp_te_router_id_clv()
 *
 * Description:
 *      Decode for a lsp packets Traffic Engineering ID clv.  Calls into the
 *      clv common one.
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : proto tree to build on (may be null)
 *      int : current offset into packet data
 *      int : length of IDs in packet.
 *      int : length of this clv
 *
 * Output:
 *      void, will modify proto_tree if not null.
 */
static void
dissect_lsp_te_router_id_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_te_router_id_clv(tree, pinfo, tvb, &ei_isis_lsp_short_packet, offset, length,
		hf_isis_lsp_clv_te_router_id );
}


/*
 * Name: dissect_lsp_ip_int_addr_clv()
 *
 * Description:
 *	Decode for a lsp packets ip interface addr clv.  Calls into the
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
dissect_lsp_ip_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_ip_int_clv(tree, pinfo, tvb, &ei_isis_lsp_short_packet, offset, length,
		hf_isis_lsp_clv_ipv4_int_addr );
}

/*
 * Name: dissect_lsp_ipv6_int_addr_clv()
 *
 * Description: Decode an IPv6 interface addr CLV - code 232.
 *
 *   Calls into the clv common one.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ipv6_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_ipv6_int_clv(tree, pinfo, tvb, &ei_isis_lsp_short_packet, offset, length,
		hf_isis_lsp_clv_ipv6_int_addr );
}

static void
dissect_isis_lsp_clv_mt_cap_spb_instance(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
	const int CIST_ROOT_ID_LEN            = 8; /* CIST Root Identifier */
	const int CIST_EXT_ROOT_PATH_COST_LEN = 4; /* CIST External Root Path Cost */
	const int BRIDGE_PRI_LEN              = 2; /* Bridge Priority */
	const int V_SPSOURCEID_LEN            = 4; /* v | SPSourceID */
	const int NUM_TREES_LEN               = 1; /* num of trees */

	const int CIST_ROOT_ID_OFFSET = 0;
	const int CIST_EXT_ROOT_PATH_COST_OFFSET = CIST_ROOT_ID_OFFSET            + CIST_ROOT_ID_LEN;
	const int BRIDGE_PRI_OFFSET              = CIST_EXT_ROOT_PATH_COST_OFFSET + CIST_EXT_ROOT_PATH_COST_LEN;
	const int V_SPSOURCEID_OFFSET            = BRIDGE_PRI_OFFSET              + BRIDGE_PRI_LEN;
	const int NUM_TREES_OFFSET               = V_SPSOURCEID_OFFSET            + V_SPSOURCEID_LEN;
	const int FIXED_LEN                      = NUM_TREES_OFFSET               + NUM_TREES_LEN;
	const int VLAN_ID_TUPLE_LEN = 8;

	if (sublen < FIXED_LEN) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
		                      "Short SPB Digest subTLV (%d vs %d)", sublen, FIXED_LEN);
		return;
	}
	else {
		proto_tree *subtree, *ti;
		int subofs = offset;
		const guint8 *cist_root_identifier = tvb_get_ptr   (tvb, subofs + CIST_ROOT_ID_OFFSET, CIST_ROOT_ID_LEN);
		guint8        num_trees            = tvb_get_guint8(tvb, subofs + NUM_TREES_OFFSET);

		/*************************/
		ti = proto_tree_add_text( tree, tvb, offset-2, sublen+2,
		                          "SPB Instance: Type: 0x%02x, Length: %d", subtype, sublen);
		subtree = proto_item_add_subtree(ti, ett_isis_lsp_clv_mt_cap_spb_instance);

		/*************************/
		proto_tree_add_bytes_format_value( subtree, hf_isis_lsp_mt_cap_spb_instance_cist_root_identifier, tvb, subofs + CIST_ROOT_ID_OFFSET, CIST_ROOT_ID_LEN,
		                     cist_root_identifier, "%08x-%08x-%08x-%08x-%08x-%08x-%08x-%08x",
		                     cist_root_identifier[0], cist_root_identifier[1], cist_root_identifier[2],
		                     cist_root_identifier[3], cist_root_identifier[4], cist_root_identifier[5],
		                     cist_root_identifier[6], cist_root_identifier[7]);
		proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_cist_external_root_path_cost, tvb, subofs + CIST_EXT_ROOT_PATH_COST_OFFSET, CIST_EXT_ROOT_PATH_COST_LEN, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_bridge_priority, tvb, subofs + BRIDGE_PRI_OFFSET, BRIDGE_PRI_LEN, ENC_BIG_ENDIAN);

		proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_v, tvb, subofs + V_SPSOURCEID_OFFSET, V_SPSOURCEID_LEN, ENC_BIG_ENDIAN);

		proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spsourceid, tvb, subofs + V_SPSOURCEID_OFFSET, V_SPSOURCEID_LEN, ENC_BIG_ENDIAN);
		ti = proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_number_of_trees, tvb, subofs + NUM_TREES_OFFSET, NUM_TREES_LEN, ENC_BIG_ENDIAN);
		if (num_trees == 0)
			proto_item_append_text(ti, " Invalid subTLV: zero trees");

		subofs += FIXED_LEN;
		sublen -= FIXED_LEN;

		/*************************/
		if (sublen != (num_trees * VLAN_ID_TUPLE_LEN)) {
			proto_tree_add_text( subtree, tvb, subofs, 0,
			                     "SubTLV length doesn't match number of trees");
			return;
		}
		while (sublen > 0 && num_trees > 0) {
			if (sublen < VLAN_ID_TUPLE_LEN) {
				proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				                      "Short VLAN_ID entry (%d vs %d)", sublen, VLAN_ID_TUPLE_LEN);
				return;
			}
			else {
				const guint8 flags       = tvb_get_guint8(tvb, subofs);
				const guint8 *ect_id     = tvb_get_ptr(tvb, subofs + 1, 4);
				const guint8 *bvid_spvid = tvb_get_ptr(tvb, subofs + 1 + 4, 3);
				const guint16 bvid       = (0xff0 & (((guint16)bvid_spvid[0]) << 4)) | (0x0f & (bvid_spvid[1] >> 4));
				const guint16 spvid      = (0xf00 & (((guint16)bvid_spvid[1]) << 8)) | (0xff & (bvid_spvid[2]));
				proto_tree_add_text( subtree, tvb, subofs, VLAN_ID_TUPLE_LEN,
				                     "  U: %u, M: %u, A: %u, ECT: %02x-%02x-%02x-%02x, BVID: 0x%03x (%d),%s SPVID: 0x%03x (%d)",
				                     (flags >> 7) & 1,
				                     (flags >> 6) & 1,
				                     (flags >> 5) & 1,
				                     ect_id[0], ect_id[1], ect_id[2], ect_id[3],
				                     bvid, bvid,
				                     (  bvid < 10   ? "   "
				                      : bvid < 100  ? "  "
				                      : bvid < 1000 ? " "
				                      : ""),
				                     spvid, spvid);
				subofs += VLAN_ID_TUPLE_LEN;
				sublen -= VLAN_ID_TUPLE_LEN;
				--num_trees;
			}
		}
		if (num_trees) {
			proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
			                      "Short subTLV (%d vs %d)", sublen, num_trees * VLAN_ID_TUPLE_LEN);
			return;
		}
	}
}
static void
dissect_isis_lsp_clv_mt_cap_spb_oalg(tvbuff_t   *tvb,
	proto_tree *tree, int offset, int subtype, int sublen)
{
	proto_tree_add_text( tree, tvb, offset, -1,
	                      "MT-Cap SPB Opaque Algorithm: Type: 0x%02x, Length: %d", subtype, sublen);
}
static void
dissect_isis_lsp_clv_mt_cap_spbm_service_identifier(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, int subtype, int sublen)
{
	const int BMAC_LEN = 6; /* B-MAC Address */
	const int BVID_LEN = 2; /* Base-VID */

	const int BMAC_OFFSET = 0;
	const int BVID_OFFSET = BMAC_OFFSET + BMAC_LEN;
	const int FIXED_LEN   = BVID_OFFSET + BVID_LEN;

	const int ISID_LEN = 4;

	if (sublen < FIXED_LEN) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
		                      "Short SPBM Service Identifier and Unicast Address subTLV (%d vs %d)", sublen, FIXED_LEN);
		return;
	}
	else {
		proto_tree *subtree, *ti;
		int subofs = offset;

		/*************************/
		ti = proto_tree_add_text( tree, tvb, offset-2, sublen+2,
		                          "SPB Service ID and Unicast Address: Type: 0x%02x, Length: %d", subtype, sublen);
		subtree = proto_item_add_subtree(ti, ett_isis_lsp_clv_mt_cap_spbm_service_identifier);

		/*************************/
		proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spbm_service_identifier_b_mac, tvb, subofs + BMAC_OFFSET, BMAC_LEN, ENC_NA);
		proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spbm_service_identifier_base_vid, tvb, subofs + BVID_OFFSET, BVID_LEN, ENC_BIG_ENDIAN);

		subofs += FIXED_LEN;
		sublen -= FIXED_LEN;

		/*************************/
		while (sublen > 0) {
			if (sublen < ISID_LEN) {
				proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				                      "Short ISID entry (%d vs %d)", sublen, ISID_LEN);
				return;
			}
			else {
				const guint32 isid = tvb_get_ntohl(tvb, subofs);
				proto_tree_add_text( subtree, tvb, subofs, ISID_LEN,
				                     "  T: %u, R: %u, ISID: 0x%06x (%d)",
				                     (isid >> 31) & 1,
				                     (isid >> 30) & 1,
				                     isid & 0x00ffffff,
				                     isid & 0x00ffffff);
				subofs += ISID_LEN;
				sublen -= ISID_LEN;
			}
		}
	}
}
static void
dissect_isis_lsp_clv_mt_cap_spbv_mac_address(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, int subtype, int sublen)
{
	guint16 fixed_data;
	guint16 spvid;
	guint8 sr_bit;
	const int GMAC_LEN = 6; /* GMAC Address */
	const int SPVID_LEN = 2; /* SPVID */
	const int MAC_TUPLE_LEN = 7;

	const int SPVID_OFFSET = 0;
	const int FIXED_LEN    = SPVID_OFFSET + SPVID_LEN;

	if (sublen < FIXED_LEN) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
		                      "Short SPBV Mac Address subTLV (%d vs %d)", sublen, FIXED_LEN);
		return;
	}
	else {
		proto_tree *subtree, *ti;
		int subofs = offset;
		fixed_data = tvb_get_ntohs(tvb, subofs);
		spvid = (fixed_data & 0x0FFF);
		sr_bit = (fixed_data & 0x3000) >> 12;

		/*************************/
		ti = proto_tree_add_text( tree, tvb, offset-2, sublen+2,
		                          "SPBV Mac Address: Type: 0x%02x, Length: %d", subtype, sublen);
		subtree = proto_item_add_subtree(ti, ett_isis_lsp_clv_mt_cap_spbv_mac_address);

		/*************************/
		proto_tree_add_uint(subtree, hf_isis_lsp_spb_sr_bit,
				            tvb, subofs, 1, sr_bit);
		proto_tree_add_uint(subtree, hf_isis_lsp_spb_spvid,
						            tvb, subofs, 2, spvid);

		subofs += FIXED_LEN;
		sublen -= FIXED_LEN;

		/*************************/
		while (sublen > 0) {
			if (sublen < MAC_TUPLE_LEN) {
				proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				                      "Short MAC Address entry (%d vs %d)", sublen, MAC_TUPLE_LEN);
				return;
			}
			else {
				const guint32 tr_bit = tvb_get_guint8(tvb, subofs);
				const guint8 *gmac   = tvb_get_ptr(tvb, subofs + 1, GMAC_LEN);
				proto_tree_add_text( subtree, tvb, subofs, MAC_TUPLE_LEN,
				                     "  T: %u, R: %u, MAC: %02x-%02x-%02x-%02x-%02x-%02x",
				                     (tr_bit >> 7) & 1,
				                     (tr_bit >> 6) & 1,
									 gmac[0],
									 gmac[1],
									 gmac[2],
									 gmac[3],
									 gmac[4],
									 gmac[5]);
				subofs += MAC_TUPLE_LEN;
				sublen -= MAC_TUPLE_LEN;
			}
		}
	}
}
/*
 * Name: dissect_lsp_clv_mt_cap()
 *
 * Description: Decode an ISIS MT-CAP CLV - code 144.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_isis_lsp_clv_mt_cap(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
                            int id_length _U_, int length)
{
	if (length >= 2) {
		/* mtid */
		proto_tree_add_item( tree, hf_isis_lsp_mt_cap_mtid, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_isis_lsp_mt_cap_overload, tvb, offset, 2, ENC_BIG_ENDIAN);
		length -= 2;
		offset += 2;
		while (length >= 2) {
			guint8 subtype   = tvb_get_guint8(tvb, offset);
			guint8 subtlvlen = tvb_get_guint8(tvb, offset+1);
			length -= 2;
			offset += 2;
			if (subtlvlen > length) {
				proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				                      "Short type 0x%02x TLV (%d vs %d)", subtype, subtlvlen, length);
				return;
			}
			if (subtype == 0x01) { /* SPB Instance */
				dissect_isis_lsp_clv_mt_cap_spb_instance(tvb, pinfo, tree, offset, subtype, subtlvlen);
			}
			else if (subtype == 0x02) { /* OALG */
				dissect_isis_lsp_clv_mt_cap_spb_oalg(tvb, tree, offset, subtype, subtlvlen);
			}
			else if (subtype == 0x03) { /* SPBM Service Identifier */
				dissect_isis_lsp_clv_mt_cap_spbm_service_identifier(tvb, pinfo, tree, offset, subtype, subtlvlen);
			}
			else if (subtype == 0x04) { /* SPBV Mac Address */
				dissect_isis_lsp_clv_mt_cap_spbv_mac_address(tvb, pinfo, tree, offset, subtype, subtlvlen);
			}
			else {
				proto_tree_add_expert_format( tree, pinfo, &ei_isis_lsp_subtlv, tvb, offset, -1,
				                      "Unknown SubTlv: Type: 0x%02x, Length: %d", subtype, subtlvlen);
			}
			length -= subtlvlen;
			offset += subtlvlen;
		}

	}
}

/*
 * Name: dissect_lsp_authentication_clv()
 *
 * Description:
 *	Decode for a lsp packets authenticaion clv.  Calls into the
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
dissect_lsp_authentication_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_authentication_clv(tree, pinfo, tvb, &ei_isis_lsp_authentication, offset, length);
}

/*
 * Name: dissect_lsp_ip_authentication_clv()
 *
 * Description:
 *	Decode for a lsp packets authenticaion clv.  Calls into the
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
dissect_lsp_ip_authentication_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_ip_authentication_clv(tvb, tree, offset, length);
}

/*
 * Name: dissect_lsp_area_address_clv()
 *
 * Description:
 *	Decode for a lsp packet's area address clv.  Call into clv common
 *	one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_area_address_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_area_address_clv(tree, pinfo, tvb, &ei_isis_lsp_short_packet, offset, length);
}

/*
 * Name: dissect_lsp_eis_neighbors_clv_inner()
 *
 * Description:
 *	Real work horse for showing neighbors.  This means we decode the
 *	first octet as either virtual/!virtual (if show_virtual param is
 *	set), or as a must == 0 reserved value.
 *
 *	Once past that, we decode n neighbor elements.  Each neighbor
 *	is comprised of a metric block (is dissect_metric) and the
 *	addresses.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *	int : set to decode first octet as virtual vs reserved == 0
 *	int : set to indicate EIS instead of IS (6 octet per addr instead of 7)
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_eis_neighbors_clv_inner(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int length, int id_length, int show_virtual, int is_eis)
{
	proto_item 	*ti;
	proto_tree	*ntree = NULL;
	int		tlen;

	if (!is_eis) {
		id_length++;	/* IDs are one octet longer in IS neighbours */
		if ( tree ) {
			if ( show_virtual ) {
				/* virtual path flag */
				proto_tree_add_text ( tree, tvb, offset, 1,
				   tvb_get_guint8(tvb, offset) ? "IsVirtual" : "IsNotVirtual" );
			} else {
				proto_tree_add_item(tree, hf_isis_lsp_eis_neighbors_reserved, tvb, offset, 1, ENC_NA);
			}
		}
		offset++;
		length--;
	}
	tlen = 4 + id_length;

	while ( length > 0 ) {
		if (length<tlen) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"short E/IS reachability (%d vs %d)", length, tlen );
			return;
		}
		/*
		 * Gotta build a sub-tree for all our pieces
		 */
		if ( tree ) {
			if ( is_eis ) {
				ti = proto_tree_add_text(tree, tvb, offset, tlen, "ES Neighbor");
			} else {
				ti = proto_tree_add_text(tree, tvb, offset, tlen, "IS Neighbor");
			}
			ntree = proto_item_add_subtree(ti, ett_isis_lsp_clv_is_neighbors);

			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_default_metric, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_default_metric_ie, tvb, offset, 1, ENC_NA);

			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_delay_metric, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_delay_metric_supported, tvb, offset, 1, ENC_NA);

			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_delay_metric_ie, tvb, offset+1, 1, ENC_NA);

			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_expense_metric, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_expense_metric_supported, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_expense_metric_ie, tvb, offset+2, 1, ENC_NA);

			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_error_metric, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_error_metric_supported, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_error_metric_ie, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(ntree, is_eis ? hf_isis_lsp_eis_neighbors_es_neighbor_id : hf_isis_lsp_eis_neighbors_is_neighbor_id,
									tvb, offset+4, id_length, ENC_NA);
			proto_item_append_text(ti, ": %s", tvb_print_system_id(tvb, offset+4, id_length));
		}
		offset += tlen;
		length -= tlen;
	}
}

/*
 * Name: dissect_lsp_l1_is_neighbors_clv()
 *
 * Description:
 *	Dispatch a l1 intermediate system neighbor by calling
 *	the inner function with show virtual set to TRUE and is es set to FALSE.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_l1_is_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length, int length)
{
	dissect_lsp_eis_neighbors_clv_inner(tvb, pinfo, tree, offset,
		length, id_length, TRUE, FALSE);
}

/*
 * Name: dissect_lsp_l1_es_neighbors_clv()
 *
 * Description:
 *	Dispatch a l1 end or intermediate system neighbor by calling
 *	the inner function with show virtual set to TRUE and es set to TRUE.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_l1_es_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length, int length)
{
	dissect_lsp_eis_neighbors_clv_inner(tvb, pinfo, tree, offset,
		length, id_length, TRUE, TRUE);
}

/*
 * Name: dissect_lsp_l2_is_neighbors_clv()
 *
 * Description:
 *	Dispatch a l2 intermediate system neighbor by calling
 *	the inner function with show virtual set to FALSE, and is es set
 *	to FALSE
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_l2_is_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length, int length)
{
	dissect_lsp_eis_neighbors_clv_inner(tvb, pinfo, tree, offset,
		length, id_length, FALSE, FALSE);
}


/*
 * Name: dissect_subclv_admin_group ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the administrive group sub-CLV (code 3).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_admin_group (tvbuff_t *tvb, proto_tree *tree, int offset) {
	proto_item *ti;
	proto_tree *ntree;
	guint32    clv_value;
	guint32    mask;
	int        i;

	ti = proto_tree_add_text(tree, tvb, offset-2, 6, "Administrative group(s):");
	ntree = proto_item_add_subtree (ti, ett_isis_lsp_subclv_admin_group);

	clv_value = tvb_get_ntohl(tvb, offset);
	mask = 1;
	for (i = 0 ; i < 32 ; i++) {
		if ( (clv_value & mask) != 0 ) {
			proto_tree_add_text (ntree, tvb, offset, 4, "group %d", i);
		}
		mask <<= 1;
	}
}

/*
 * Name: dissect_subclv_max_bw ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the maximum link bandwidth sub-CLV (code 9).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_max_bw(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	gfloat  bw;

	bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
	proto_tree_add_float_format_value(tree, hf_isis_lsp_maximum_link_bandwidth, tvb, offset-2, 6,
		bw, "%.2f Mbps", bw);
}

/*
 * Name: dissect_subclv_rsv_bw ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the reservable link bandwidth sub-CLV (code 10).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_rsv_bw(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	gfloat  bw;

	bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
	proto_tree_add_float_format_value (tree, hf_isis_lsp_reservable_link_bandwidth, tvb, offset-2, 6,
		bw, "%.2f Mbps", bw );
}

/*
 * Name: dissect_subclv_unrsv_bw ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the unreserved bandwidth sub-CLV (code 11).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_unrsv_bw(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ntree;
	gfloat     bw;
	int        i;

	ti = proto_tree_add_text (tree, tvb, offset-2, 34, "Unreserved bandwidth:");
	ntree = proto_item_add_subtree (ti, ett_isis_lsp_subclv_unrsv_bw);

	for (i = 0 ; i < 8 ; i++) {
		bw = tvb_get_ntohieee_float(tvb, offset+4*i)*8/1000000;
		proto_tree_add_float_format(ntree, hf_isis_lsp_unrsv_bw_priority_level, tvb, offset+4*i, 4,
			bw, "priority level %d: %.2f Mbps", i, bw );
	}
}

/*
 * Name: dissect_subclv_spb_link_metric ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the SPB link metric sub-CLV (code 29).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *   int : subtlv type
 *   int : subtlv length
 *
 * Output:
 *   void
 */

static void
dissect_subclv_spb_link_metric(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
	const int SUBLEN     = 6;

	if (sublen != SUBLEN) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
		                      "Short SPB Link Metric sub-TLV (%d vs %d)", sublen, SUBLEN);
		return;
	}
	else {
		proto_tree *subtree, *ti;
		ti = proto_tree_add_text( tree, tvb, offset-2, sublen+2,
		                          "SPB Link Metric: Type: 0x%02x (%d), Length: %d", subtype, subtype, sublen);
		subtree = proto_item_add_subtree(ti, ett_isis_lsp_subclv_spb_link_metric);

		proto_tree_add_item(subtree, hf_isis_lsp_spb_link_metric,
		                    tvb, offset, 3, ENC_BIG_ENDIAN);

		proto_tree_add_item(subtree, hf_isis_lsp_spb_port_count,
		                    tvb, offset+3, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(subtree, hf_isis_lsp_spb_port_id,
		                    tvb, offset+4, 2, ENC_BIG_ENDIAN);
    }
}

/*
 * Name: dissect_lsp_ext_is_reachability_clv()
 *
 * Description: Decode a Extended IS Reachability CLV - code 22
 * RFC 3784
 *
 *   The extended IS reachability TLV is an extended version
 *   of the IS reachability TLV (code 2). It encodes the metric
 *   as a 24-bit unsigned integer and allows to add sub-CLV(s).
 *
 *   CALLED BY TLV 222 DISSECTOR
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : length of IDs in packet.
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_ext_is_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
	int offset, int id_length _U_, int length)
{
	proto_item *ti;
	proto_tree *ntree = NULL;
	guint      subclvs_len;
	guint      len, i;
	guint      clv_code, clv_len;

	while (length > 0) {
		ti = proto_tree_add_text(tree, tvb, offset, -1, "IS Neighbor");
		ntree = proto_item_add_subtree (ti, ett_isis_lsp_part_of_clv_ext_is_reachability );

		proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_is_neighbor_id, tvb, offset, 7, ENC_NA);
		proto_item_append_text(ti, ": %s", tvb_print_system_id(tvb, offset, 7));

		proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_metric, tvb, offset+7, 3, ENC_BIG_ENDIAN);

		subclvs_len = tvb_get_guint8(tvb, offset+10);
		if (subclvs_len == 0) {
			proto_tree_add_text (ntree, tvb, offset+10, 1, "no sub-TLVs present");
		}
		else {
			i = 0;
			while (i < subclvs_len) {
				clv_code = tvb_get_guint8(tvb, offset+11+i);
				clv_len  = tvb_get_guint8(tvb, offset+12+i);
				switch (clv_code) {
				case 3 :
					dissect_subclv_admin_group(tvb, ntree, offset+13+i);
					break;
				case 4 :
					proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_link_local_identifier, tvb, offset+13+i, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_link_remote_identifier, tvb, offset+17+i, 4, ENC_BIG_ENDIAN);
					break;
				case 6 :
					proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_ipv4_interface_address, tvb, offset+11+i, 6, ENC_BIG_ENDIAN);
					break;
				case 8 :
					proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_ipv4_neighbor_address, tvb, offset+11+i, 6, ENC_BIG_ENDIAN);
					break;
				case 9 :
					dissect_subclv_max_bw (tvb, ntree, offset+13+i);
					break;
				case 10:
					dissect_subclv_rsv_bw (tvb, ntree, offset+13+i);
					break;
				case 11:
					dissect_subclv_unrsv_bw (tvb, ntree, offset+13+i);
					break;
				case 18:
					proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_traffic_engineering_default_metric, tvb, offset+11+i, 5, ENC_BIG_ENDIAN);
					break;
				case 29:
					dissect_subclv_spb_link_metric(tvb, pinfo, ntree,
						offset+13+i, clv_code, clv_len);
					break;
				case 250:
				case 251:
				case 252:
				case 253:
				case 254:
					proto_tree_add_text (ntree, tvb, offset+11+i, clv_len+2,
						"Unknown Cisco specific extensions: code %d, length %d",
						clv_code, clv_len );
					break;
				default :
					proto_tree_add_text (ntree, tvb, offset+11+i, clv_len+2,
						"Unknown sub-CLV: code %d, length %d", clv_code, clv_len );
					break;
				}
				i += clv_len + 2;
			}
		}

		len = 11 + subclvs_len;
		proto_item_set_len (ti, len);
		offset += len;
		length -= len;
	}
}

/*
 * Name: dissect_lsp_mt_reachable_IPv4_prefx_clv()
 *
 * Description: Decode Multi-Topology IPv4 Prefixes - code 235
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : length of IDs in packet.
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_mt_reachable_IPv4_prefx_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int id_length _U_, int length)
{
	if (length < 2) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"short lsp multi-topology reachable IPv4 prefixes(%d vs %d)", length, 2 );
		return;
	}
	dissect_lsp_mt_id(tvb, tree, offset);
	dissect_lsp_ext_ip_reachability_clv(tvb, pinfo, tree, offset+2, 0, length-2);
}

/*
 * Name: dissect_lsp_mt_reachable_IPv6_prefx_clv()
 *
 * Description: Decode Multi-Topology IPv6 Prefixes - code 237
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : length of IDs in packet.
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_mt_reachable_IPv6_prefx_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int id_length _U_, int length)
{
	if (length < 2) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"short lsp multi-topology reachable IPv6 prefixes(%d vs %d)", length, 2 );
		return;
	}
	dissect_lsp_mt_id(tvb, tree, offset);
	dissect_lsp_ipv6_reachability_clv(tvb, pinfo, tree, offset+2, 0, length-2);
}


/*
 * Name: dissect_lsp_mt_is_reachability_clv()
 *
 * Description: Decode Multi-Topology Intermediate Systems - code 222
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : unused
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */

static void
dissect_lsp_mt_is_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	if (length < 2) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"short lsp reachability(%d vs %d)", length, 2 );
		return;
	}

	/*
	 * the MT ID value dissection is used in other LSPs so we push it
	 * in a function
	 */
	dissect_lsp_mt_id(tvb, tree, offset);
	/*
	 * fix here. No need to parse TLV 22 (with bugs) while it is
	 * already done correctly!!
	 */
	dissect_lsp_ext_is_reachability_clv(tvb, pinfo, tree, offset+2, 0, length-2);
}

/*
 * Name: dissect_lsp_partition_dis_clv()
 *
 * Description:
 *	This CLV is used to indicate which system is the designated
 *	IS for partition repair.  This means just putting out the
 *	"id_length"-octet IS.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_partition_dis_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length, int length)
{
	if ( length < id_length ) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"short lsp partition DIS(%d vs %d)", length, id_length );
		return;
	}
	/*
	 * Gotta build a sub-tree for all our pieces
	 */
	proto_tree_add_item( tree, hf_isis_lsp_partition_designated_l2_is, tvb, offset, id_length, ENC_NA);

	length -= id_length;
	offset += id_length;
	if ( length > 0 ) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_long_packet, tvb, offset, -1,
				"Long lsp partition DIS, %d left over", length );
		return;
	}
}

/*
 * Name: dissect_lsp_prefix_neighbors_clv()
 *
 * Description:
 *	The prefix CLV describes what other (OSI) networks we can reach
 *	and what their cost is.  It is built from a metric block
 *	(see dissect_metric) followed by n addresses.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_prefix_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	char *sbuf;
	int mylen;

	if ( length < 4 ) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
			"Short lsp prefix neighbors (%d vs 4)", length );
		return;
	}
	if ( tree ) {
		dissect_metric (tvb, tree, offset,
			tvb_get_guint8(tvb, offset), "Default", TRUE );
		dissect_metric (tvb, tree, offset+1,
			tvb_get_guint8(tvb, offset+1), "Delay", FALSE );
		dissect_metric (tvb, tree, offset+2,
			tvb_get_guint8(tvb, offset+2), "Expense", FALSE );
		dissect_metric (tvb, tree, offset+3,
			tvb_get_guint8(tvb, offset+3), "Error", FALSE );
	}
	offset += 4;
	length -= 4;
	while ( length > 0 ) {
		mylen = tvb_get_guint8(tvb, offset);
		length--;
		if (length<=0) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_packet, tvb, offset, -1,
				"Zero payload space after length in prefix neighbor" );
			return;
		}
		if ( mylen > length) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_long_packet, tvb, offset, -1,
				"Integral length of prefix neighbor too long (%d vs %d)", mylen, length );
			return;
		}

		/*
		 * Lets turn the area address into "standard" 0000.0000.etc
		 * format string.
		 */
		sbuf =  print_area( tvb_get_ptr(tvb, offset+1, mylen), mylen );
		/* and spit it out */
		if ( tree ) {
			proto_tree_add_text ( tree, tvb, offset, mylen + 1,
				"Area address (%d): %s", mylen, sbuf );
		}
		offset += mylen + 1;
		length -= mylen;	/* length already adjusted for len fld*/
	}
}

static void isis_lsp_checkum_additional_info(tvbuff_t * tvb, packet_info * pinfo,
    proto_item * it_cksum, int offset, gboolean is_cksum_correct)
{
	proto_tree * checksum_tree;
	proto_item * item;

	checksum_tree = proto_item_add_subtree(it_cksum, ett_isis_lsp_cksum);
	item = proto_tree_add_boolean(checksum_tree, hf_isis_lsp_checksum_good, tvb,
	                              offset, 2, is_cksum_correct);
	PROTO_ITEM_SET_GENERATED(item);
	item = proto_tree_add_boolean(checksum_tree, hf_isis_lsp_checksum_bad, tvb,
	                              offset, 2, !is_cksum_correct);
	PROTO_ITEM_SET_GENERATED(item);
	if (!is_cksum_correct) {
		expert_add_info(pinfo, item, &ie_isis_lsp_checksum_bad);
		col_append_str(pinfo->cinfo, COL_INFO, " [ISIS CHECKSUM INCORRECT]");
	}
}

static const isis_clv_handle_t clv_l1_lsp_opts[] = {
	{
		ISIS_CLV_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_lsp_clv_area_addr,
		dissect_lsp_area_address_clv
	},
	{
		ISIS_CLV_IS_REACH,
		"IS Reachability",
		&ett_isis_lsp_clv_is_neighbors,
		dissect_lsp_l1_is_neighbors_clv
	},
	{
		ISIS_CLV_ES_NEIGHBORS,
		"ES Neighbor(s)",
		&ett_isis_lsp_clv_is_neighbors,
		dissect_lsp_l1_es_neighbors_clv
	},
	{
		ISIS_CLV_EXTD_IS_REACH,
		"Extended IS reachability",
		&ett_isis_lsp_clv_ext_is_reachability,
		dissect_lsp_ext_is_reachability_clv
	},
	{
		ISIS_CLV_INT_IP_REACH,
		"IP Internal reachability",
		&ett_isis_lsp_clv_ip_reachability,
		dissect_lsp_ip_reachability_clv
	},
	{
		ISIS_CLV_EXT_IP_REACH,
		"IP External reachability",
		&ett_isis_lsp_clv_ip_reachability,
		dissect_lsp_ip_reachability_clv
	},
	{
		ISIS_CLV_EXTD_IP_REACH,
		"Extended IP Reachability",
		&ett_isis_lsp_clv_ext_ip_reachability,
		dissect_lsp_ext_ip_reachability_clv
	},
	{
		ISIS_CLV_IP6_REACH,
		"IPv6 reachability",
		&ett_isis_lsp_clv_ipv6_reachability,
		dissect_lsp_ipv6_reachability_clv
	},
	{
		ISIS_CLV_PROTOCOLS_SUPPORTED,
		"Protocols supported",
		&ett_isis_lsp_clv_nlpid,
		dissect_lsp_nlpid_clv
	},
	{
		ISIS_CLV_HOSTNAME,
		"Hostname",
		&ett_isis_lsp_clv_hostname,
		dissect_lsp_hostname_clv
	},
	{
		ISIS_CLV_TE_ROUTER_ID,
		"Traffic Engineering Router ID",
		&ett_isis_lsp_clv_te_router_id,
		dissect_lsp_te_router_id_clv
	},
	{
		ISIS_CLV_IP_ADDR,
		"IP Interface address(es)",
		&ett_isis_lsp_clv_ipv4_int_addr,
		dissect_lsp_ip_int_addr_clv
	},
	{
		ISIS_CLV_IP6_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_lsp_clv_ipv6_int_addr,
		dissect_lsp_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_MT_CAP,
		"MT-Capability",
		&ett_isis_lsp_clv_mt_cap,
		dissect_isis_lsp_clv_mt_cap
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_lsp_clv_authentication,
		dissect_lsp_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_lsp_clv_ip_authentication,
		dissect_lsp_ip_authentication_clv
	},
	{
		ISIS_CLV_MT_SUPPORTED,
		"Multi Topology supported",
		&ett_isis_lsp_clv_mt,
		dissect_lsp_mt_clv
	},
	{
		ISIS_CLV_MT_IS_REACH,
		"Multi Topology IS Reachability",
		&ett_isis_lsp_clv_mt_is,
		dissect_lsp_mt_is_reachability_clv
	},
	{
		ISIS_CLV_MT_IP_REACH,
		"Multi Topology Reachable IPv4 Prefixes",
		&ett_isis_lsp_clv_mt_reachable_IPv4_prefx,
		dissect_lsp_mt_reachable_IPv4_prefx_clv
	},
	{
		ISIS_CLV_MT_IP6_REACH,
		"Multi Topology Reachable IPv6 Prefixes",
		&ett_isis_lsp_clv_mt_reachable_IPv6_prefx,
		dissect_lsp_mt_reachable_IPv6_prefx_clv
	},
	{
		ISIS_CLV_RT_CAPABLE,
		"Router Capability",
		&ett_isis_lsp_clv_rt_capable_IPv4_prefx,
		dissect_isis_rt_capable_clv
	},
	{
		ISIS_GRP_ADDR,
		"GROUP ADDRESS TLV",
		&ett_isis_lsp_clv_grp_address_IPv4_prefx,
		dissect_isis_grp_address_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_l2_lsp_opts[] = {
	{
		ISIS_CLV_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_lsp_clv_area_addr,
		dissect_lsp_area_address_clv
	},
	{
		ISIS_CLV_IS_REACH,
		"IS Reachability",
		&ett_isis_lsp_clv_is_neighbors,
		dissect_lsp_l2_is_neighbors_clv
	},
	{
		ISIS_CLV_EXTD_IS_REACH,
		"Extended IS reachability",
		&ett_isis_lsp_clv_ext_is_reachability,
		dissect_lsp_ext_is_reachability_clv
	},
	{
		ISIS_CLV_PARTITION_DIS,
		"Partition Designated Level 2 IS",
		&ett_isis_lsp_clv_partition_dis,
		dissect_lsp_partition_dis_clv
	},
	{
		ISIS_CLV_PREFIX_NEIGHBORS,
		"Prefix neighbors",
		&ett_isis_lsp_clv_prefix_neighbors,
		dissect_lsp_prefix_neighbors_clv
	},
	{
		ISIS_CLV_INT_IP_REACH,
		"IP Internal reachability",
		&ett_isis_lsp_clv_ip_reachability,
		dissect_lsp_ip_reachability_clv
	},
	{
		ISIS_CLV_EXT_IP_REACH,
		"IP External reachability",
		&ett_isis_lsp_clv_ip_reachability,
		dissect_lsp_ip_reachability_clv
	},
	{
		ISIS_CLV_PROTOCOLS_SUPPORTED,
		"Protocols supported",
		&ett_isis_lsp_clv_nlpid,
		dissect_lsp_nlpid_clv
	},
	{
		ISIS_CLV_HOSTNAME,
		"Hostname",
		&ett_isis_lsp_clv_hostname,
		dissect_lsp_hostname_clv
	},
	{
		ISIS_CLV_TE_ROUTER_ID,
		"Traffic Engineering Router ID",
		&ett_isis_lsp_clv_te_router_id,
		dissect_lsp_te_router_id_clv
	},
	{
		ISIS_CLV_EXTD_IP_REACH,
		"Extended IP Reachability",
		&ett_isis_lsp_clv_ext_ip_reachability,
		dissect_lsp_ext_ip_reachability_clv
	},
	{
		ISIS_CLV_IP6_REACH,
		"IPv6 reachability",
		&ett_isis_lsp_clv_ipv6_reachability,
		dissect_lsp_ipv6_reachability_clv
	},
	{
		ISIS_CLV_IP_ADDR,
		"IP Interface address(es)",
		&ett_isis_lsp_clv_ipv4_int_addr,
		dissect_lsp_ip_int_addr_clv
	},
	{
		ISIS_CLV_IP6_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_lsp_clv_ipv6_int_addr,
		dissect_lsp_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_MT_CAP,
		"MT-Capability",
		&ett_isis_lsp_clv_mt_cap,
		dissect_isis_lsp_clv_mt_cap
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_lsp_clv_authentication,
		dissect_lsp_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_lsp_clv_ip_authentication,
		dissect_lsp_ip_authentication_clv
	},
	{
		ISIS_CLV_MT_SUPPORTED,
		"Multi Topology",
		&ett_isis_lsp_clv_mt,
		dissect_lsp_mt_clv
	},
	{
		ISIS_CLV_MT_IS_REACH,
		"Multi Topology IS Reachability",
		&ett_isis_lsp_clv_mt_is,
		dissect_lsp_mt_is_reachability_clv
	},
	{
		ISIS_CLV_MT_IP_REACH,
		"Multi Topology Reachable IPv4 Prefixes",
		&ett_isis_lsp_clv_mt_reachable_IPv4_prefx,
		dissect_lsp_mt_reachable_IPv4_prefx_clv
	},
	{
		ISIS_CLV_MT_IP6_REACH,
		"Multi Topology Reachable IPv6 Prefixes",
		&ett_isis_lsp_clv_mt_reachable_IPv6_prefx,
		dissect_lsp_mt_reachable_IPv6_prefx_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

/*
 * Name: isis_dissect_isis_lsp()
 *
 * Description:
 *	Print out the LSP part of the main header and then call the CLV
 *	de-mangler with the right list of valid CLVs.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int offset : our offset into packet data.
 *	int : LSP type, a la packet-isis.h ISIS_TYPE_* values
 *	int : header length of packet.
 *	int : length of IDs in packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_isis_lsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
	const isis_clv_handle_t *opts, int header_length, int id_length)
{
	proto_item	*ti, *to, *ta;
	proto_tree	*lsp_tree = NULL, *info_tree, *att_tree;
	guint16		pdu_length, lifetime, checksum, cacl_checksum=0;
	guint8		lsp_info;
	int		len, offset_checksum;
	proto_item	*it_cksum;
	char* system_id;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS LSP");

	ti = proto_tree_add_item(tree, proto_isis_lsp, tvb, offset, -1, ENC_NA);
	lsp_tree = proto_item_add_subtree(ti, ett_isis_lsp);

	pdu_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(lsp_tree, hf_isis_lsp_pdu_length, tvb,
			offset, 2, pdu_length);
	offset += 2;

	proto_tree_add_item(lsp_tree, hf_isis_lsp_remaining_life,
			tvb, offset, 2, ENC_BIG_ENDIAN);

	lifetime = tvb_get_ntohs(tvb, offset);
	offset += 2;
	offset_checksum = offset;

	proto_tree_add_item(lsp_tree, hf_isis_lsp_lsp_id, tvb, offset, id_length + 2, ENC_NA);
	system_id = tvb_print_system_id( tvb, offset, id_length+2 );
	col_append_fstr(pinfo->cinfo, COL_INFO, ", LSP-ID: %s", system_id);

	offset += (id_length + 2);

	proto_tree_add_item(lsp_tree, hf_isis_lsp_sequence_number,
			tvb, offset, 4, ENC_BIG_ENDIAN);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", Sequence: 0x%08x, Lifetime: %5us",
			tvb_get_ntohl(tvb, offset),
			tvb_get_ntohs(tvb, offset - (id_length+2+2)));

	offset += 4;

	checksum = lifetime ? tvb_get_ntohs(tvb, offset) : 0;
	switch (check_and_get_checksum(tvb, offset_checksum, pdu_length-12, checksum, offset, &cacl_checksum)) {
		case NO_CKSUM :
			checksum = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint_format_value(lsp_tree, hf_isis_lsp_checksum, tvb, offset, 2, checksum,
					"0x%04x [unused]", checksum);
		break;
		case DATA_MISSING :
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_long_packet, tvb, offset, -1,
					"Packet length %d went beyond packet",
			 		tvb_length_remaining(tvb, offset_checksum));
		break;
		case CKSUM_NOT_OK :
			it_cksum = proto_tree_add_uint_format_value(lsp_tree, hf_isis_lsp_checksum, tvb, offset, 2, checksum,
					"0x%04x [incorrect, should be 0x%04x]",
					checksum, cacl_checksum);
			isis_lsp_checkum_additional_info(tvb, pinfo, it_cksum, offset, FALSE);
		break;
		case CKSUM_OK :
			it_cksum = proto_tree_add_uint_format_value(lsp_tree, hf_isis_lsp_checksum, tvb, offset, 2, checksum,
					"0x%04x [correct]", checksum);
				isis_lsp_checkum_additional_info(tvb, pinfo, it_cksum, offset, TRUE);
		break;
	}
	offset += 2;

	if (tree) {
		/*
		 * P | ATT | HIPPITY | IS TYPE description.
		 */
		lsp_info = tvb_get_guint8(tvb, offset);
		to = proto_tree_add_text(lsp_tree, tvb, offset, 1,
			"Type block(0x%02x): Partition Repair:%d, Attached bits:%d, Overload bit:%d, IS type:%d",
			lsp_info,
			ISIS_LSP_PARTITION(lsp_info),
			ISIS_LSP_ATT(lsp_info),
			ISIS_LSP_HIPPITY(lsp_info),
			ISIS_LSP_IS_TYPE(lsp_info)
			);

		info_tree = proto_item_add_subtree(to, ett_isis_lsp_info);
		proto_tree_add_boolean(info_tree, hf_isis_lsp_p, tvb, offset, 1, lsp_info);
		ta = proto_tree_add_uint(info_tree, hf_isis_lsp_att, tvb, offset, 1, lsp_info);
		att_tree = proto_item_add_subtree(ta, ett_isis_lsp_att);
		proto_tree_add_item(att_tree, hf_isis_lsp_error_metric, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(att_tree, hf_isis_lsp_expense_metric, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(att_tree, hf_isis_lsp_delay_metric, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(att_tree, hf_isis_lsp_default_metric, tvb, offset, 1, ENC_NA);
		proto_tree_add_boolean(info_tree, hf_isis_lsp_hippity, tvb, offset, 1, lsp_info);
		proto_tree_add_uint(info_tree, hf_isis_lsp_is_type, tvb, offset, 1, lsp_info);
	}
	offset += 1;

	len = pdu_length - header_length;
	if (len < 0) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_long_packet, tvb, offset, -1,
			"packet header length %d went beyond packet",
			 header_length );
		return;
	}
	/*
	 * Now, we need to decode our CLVs.  We need to pass in
	 * our list of valid ones!
	 */
	isis_dissect_clvs(tvb, pinfo, lsp_tree, offset,
			opts, &ei_isis_lsp_short_packet, len, id_length, ett_isis_lsp_clv_unknown );
}

static int
dissect_isis_l1_lsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_lsp(tvb, pinfo, tree, 0,
		clv_l1_lsp_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

static int
dissect_isis_l2_lsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_lsp(tvb, pinfo, tree, 0,
		clv_l2_lsp_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

void
proto_register_isis_lsp(void)
{
	static hf_register_info hf[] = {
		{ &hf_isis_lsp_pdu_length,
		{ "PDU length",		"isis.lsp.pdu_length", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_remaining_life,
		{ "Remaining lifetime",	"isis.lsp.remaining_life", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_lsp_id,
		{ "LSP-ID", "isis.lsp.lsp_id", FT_SYSTEM_ID,
		  BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_hostname,
		{ "Hostname", "isis.lsp.hostname", FT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_sequence_number,
		{ "Sequence number",           "isis.lsp.sequence_number",
		  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_checksum,
		{ "Checksum",		"isis.lsp.checksum",FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_checksum_good,
		{ "Good Checksum", "isis.lsp.checksum_good", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "Good IS-IS LSP Checksum", HFILL }},

		{ &hf_isis_lsp_checksum_bad,
		{ "Bad Checksum", "isis.lsp.checksum_bad", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "Bad IS-IS LSP Checksum", HFILL }},

		{ &hf_isis_lsp_clv_ipv4_int_addr,
		{ "IPv4 interface address", "isis.lsp.clv_ipv4_int_addr", FT_IPv4,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_clv_ipv6_int_addr,
		{ "IPv6 interface address", "isis.lsp.clv_ipv6_int_addr", FT_IPv6,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_clv_te_router_id,
		{ "Traffic Engineering Router ID", "isis.lsp.clv_te_router_id", FT_IPv4,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_clv_mt,
		{ "MT-ID", "isis.lsp.clv_mt",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_p,
		{ "Partition Repair",	"isis.lsp.partition_repair", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), ISIS_LSP_PARTITION_MASK,
			"If set, this router supports the optional Partition Repair function", HFILL }},

		{ &hf_isis_lsp_att,
		{ "Attachment",	"isis.lsp.att", FT_UINT8, BASE_DEC,
			NULL, ISIS_LSP_ATT_MASK,
			NULL, HFILL }},

		{ &hf_isis_lsp_hippity,
		{ "Overload bit",	"isis.lsp.overload", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), ISIS_LSP_HIPPITY_MASK,
			"If set, this router will not be used by any decision process to calculate routes", HFILL }},

		{ &hf_isis_lsp_root_id,
		{ "Root Bridge ID",	"isis.lsp.root.id", FT_UINT64, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_isis_lsp_is_type,
		{ "Type of Intermediate System",	"isis.lsp.is_type", FT_UINT8, BASE_DEC,
			VALS(isis_lsp_istype_vals), ISIS_LSP_IS_TYPE_MASK,
			NULL, HFILL }},

		{ &hf_isis_lsp_spb_link_metric,
		{ "SPB Link Metric", "isis.lsp.spb.link_metric",
			FT_UINT24, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_isis_lsp_spb_port_count,
		{ "Number of Ports", "isis.lsp.spb.port_count",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_isis_lsp_spb_port_id,
		{ "Port Id", "isis.lsp.spb.port_id",
			FT_UINT16, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_isis_lsp_spb_sr_bit,
		{ "SR Bit", "isis.lsp.spb.sr_bit",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_isis_lsp_spb_spvid,
		{ "SPVID", "isis.lsp.spb.spvid",
			FT_UINT16, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_isis_lsp_mt_id_reserved, { "Reserved", "isis.lsp.reserved", FT_UINT16, BASE_HEX, NULL, ISIS_LSP_MT_MSHIP_RES_MASK, NULL, HFILL }},
      { &hf_isis_lsp_mt_id, { "MT ID", "isis.lsp.mt_id", FT_UINT16, BASE_DEC, NULL, ISIS_LSP_MT_MSHIP_ID_MASK, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_ipv4_prefix, { "IPv4 prefix", "isis.lsp.ip_reachability.ipv4_prefix", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_default_metric, { "Default Metric", "isis.lsp.ip_reachability.default_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_delay_metric, { "Delay Metric", "isis.lsp.ip_reachability.delay_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_expense_metric, { "Expense Metric", "isis.lsp.ip_reachability.expense_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_error_metric, { "Error Metric", "isis.lsp.ip_reachability.error_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_32_bit_administrative_tag, { "32-Bit Administrative tag", "isis.lsp.32_bit_administrative_tag", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_64_bit_administrative_tag, { "64-Bit Administrative tag", "isis.lsp.64_bit_administrative_tag", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_ip_reachability_ipv4_prefix, { "IPv4 prefix", "isis.lsp.ext_ip_reachability.ipv4_prefix", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_ip_reachability_metric, { "Metric", "isis.lsp.ext_ip_reachability.metric", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_ip_reachability_distribution, { "Distribution", "isis.lsp.ext_ip_reachability.distribution", FT_BOOLEAN, 8, TFS(&tfs_up_down), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_grp_address_length, { "Length", "isis.lsp.grp_address.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_grp_address_topology_id, { "Topology ID", "isis.lsp.grp_address.topology_id", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_lsp_grp_address_vlan_id, { "VLAN ID", "isis.lsp.grp_address.vlan_id", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_lsp_grp_address_number_of_records, { "Number of records", "isis.lsp.grp_address.number_of_records", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_grp_address_number_of_sources, { "Number of sources", "isis.lsp.grp_address.number_of_sources", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_grp_address_group_address, { "Group Address", "isis.lsp.grp_address.group_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_grp_address_source_address, { "Source Address", "isis.lsp.grp_address.source_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_trill_length, { "Length", "isis.lsp.rt_capable.trill.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_trill_maximum_version, { "Maximum version", "isis.lsp.rt_capable.trill.maximum_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_trees_length, { "Length", "isis.lsp.rt_capable.trees.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_trees_nof_trees_to_compute, { "Nof. trees to compute", "isis.lsp.rt_capable.trees.nof_trees_to_compute", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_trees_maximum_nof_trees_to_compute, { "Maximum nof. trees to compute", "isis.lsp.rt_capable.trees.maximum_nof_trees_to_compute", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_trees_nof_trees_to_use, { "Nof. trees to use", "isis.lsp.rt_capable.trees.nof_trees_to_use", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_tree_root_id_length, { "Length", "isis.lsp.rt_capable.tree_root_id.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_tree_root_id_starting_tree_no, { "Starting tree no", "isis.lsp.rt_capable.tree_root_id.starting_tree_no", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_tree_root_id_nickname, { "Nickname", "isis.lsp.rt_capable.tree_root_id.nickname", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_nickname_length, { "Length", "isis.lsp.rt_capable.nickname.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_nickname_nickname_priority, { "Nickname priority", "isis.lsp.rt_capable.nickname.nickname_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_nickname_tree_root_priority, { "Tree root priority", "isis.lsp.rt_capable.nickname.tree_root_priority", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_nickname_nickname, { "Nickname", "isis.lsp.rt_capable.nickname.nickname", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_interested_vlans_length, { "Length", "isis.lsp.rt_capable.interested_vlans.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_interested_vlans_nickname, { "Nickname", "isis.lsp.rt_capable.interested_vlans.nickname", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv4, { "IPv4 multicast router", "isis.lsp.rt_capable.interested_vlans.multicast_ipv4", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv6, { "IPv6 multicast router", "isis.lsp.rt_capable.interested_vlans.multicast_ipv6", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_interested_vlans_vlan_start_id, { "Vlan start id", "isis.lsp.rt_capable.interested_vlans.vlan_start_id", FT_UINT16, BASE_HEX, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_interested_vlans_vlan_end_id, { "Vlan end id", "isis.lsp.rt_capable.interested_vlans.vlan_end_id", FT_UINT16, BASE_HEX, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_interested_vlans_afs_lost_counter, { "Appointed forward state lost counter", "isis.lsp.rt_capable.interested_vlans.afs_lost_counter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_tree_used_id_length, { "Length", "isis.lsp.rt_capable.tree_used_id.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_tree_used_id_starting_tree_no, { "Starting tree no", "isis.lsp.rt_capable.tree_used_id.starting_tree_no", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_tree_used_id_nickname, { "Nickname", "isis.lsp.rt_capable.tree_used_id.nickname", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_vlan_group_length, { "Length", "isis.lsp.rt_capable.vlan_group.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_vlan_group_primary_vlan_id, { "Primary vlan id", "isis.lsp.rt_capable.vlan_group.primary_vlan_id", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_vlan_group_secondary_vlan_id, { "Secondary vlan id", "isis.lsp.rt_capable.vlan_group.secondary_vlan_id", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
      { &hf_isis_lsp_rt_capable_vlan_group_nth_secondary_vlan_id, { "%dth secondary vlan id", "isis.lsp.rt_capable.vlan_group.nth_secondary_vlan_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ipv6_reachability_ipv6_prefix, { "IPv6 prefix", "isis.lsp.ipv6_reachability.ipv6_prefix", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ipv6_reachability_metric, { "Metric", "isis.lsp.ipv6_reachability.metric", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ipv6_reachability_distribution, { "Distribution", "isis.lsp.ipv6_reachability.distribution", FT_BOOLEAN, 8, TFS(&tfs_up_down), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_ipv6_reachability_distribution_internal, { "Distribution", "isis.lsp.ipv6_reachability.distribution_internal", FT_BOOLEAN, 8, TFS(&tfs_internal_external), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_ipv6_reachability_reserved_bits, { "Reserved bits", "isis.lsp.ipv6_reachability.reserved_bits", FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spb_instance_cist_root_identifier, { "CIST Root Identifier", "isis.lsp.mt_cap_spb_instance.cist_root_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spb_instance_cist_external_root_path_cost, { "CIST External Root Path Cost", "isis.lsp.mt_cap_spb_instance.cist_external_root_path_cost", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spb_instance_bridge_priority, { "Bridge Priority", "isis.lsp.mt_cap_spb_instance.bridge_priority", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spb_instance_v, { "V", "isis.lsp.mt_cap_spb_instance.v", FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spb_instance_number_of_trees, { "Number of Trees", "isis.lsp.mt_cap_spb_instance.number_of_trees", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spbm_service_identifier_b_mac, { "B-MAC", "isis.lsp.mt_cap_spbm_service_identifier.b_mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spbm_service_identifier_base_vid, { "Base-VID", "isis.lsp.mt_cap_spbm_service_identifier.base_vid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_mtid, { "MTID", "isis.lsp.mt_cap.mtid", FT_UINT16, BASE_HEX, NULL, 0xfff, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_reserved, { "Reserved", "isis.lsp.eis_neighbors_clv_inner.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_es_neighbor_id, { "ES Neighbor ID", "isis.lsp.eis_neighbors.es_neighbor_id", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_is_neighbor_id, { "IS Neighbor", "isis.lsp.eis_neighbors.is_neighbor", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_default_metric, { "Default Metric", "isis.lsp.eis_neighbors.default_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_delay_metric, { "Delay Metric", "isis.lsp.eis_neighbors.delay_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_expense_metric, { "Expense Metric", "isis.lsp.eis_neighbors.expense_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_error_metric, { "Error Metric", "isis.lsp.eis_neighbors.error_metric", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
      { &hf_isis_lsp_maximum_link_bandwidth, { "Maximum link bandwidth", "isis.lsp.maximum_link_bandwidth", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_reservable_link_bandwidth, { "Reservable link bandwidth", "isis.lsp.reservable_link_bandwidth", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_is_reachability_is_neighbor_id, { "IS neighbor ID", "isis.lsp.ext_is_reachability.is_neighbor_id", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_is_reachability_metric, { "Metric", "isis.lsp.ext_is_reachability.metric", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_is_reachability_link_local_identifier, { "Link Local Identifier", "isis.lsp.ext_is_reachability.link_local_identifier", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_is_reachability_link_remote_identifier, { "Link Remote Identifier", "isis.lsp.ext_is_reachability.link_remote_identifier", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_is_reachability_ipv4_interface_address, { "IPv4 interface address", "isis.lsp.ext_is_reachability.ipv4_interface_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_is_reachability_ipv4_neighbor_address, { "IPv4 neighbor address", "isis.lsp.ext_is_reachability.ipv4_neighbor_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ext_is_reachability_traffic_engineering_default_metric, { "Traffic engineering default metric", "isis.lsp.ext_is_reachability.traffic_engineering_default_metric", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_partition_designated_l2_is, { "Partition designated L2 IS", "isis.lsp.partition_designated_l2_is", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_error_metric, { "Error metric", "isis.lsp.error_metric", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
      { &hf_isis_lsp_expense_metric, { "Expense metric", "isis.lsp.expense_metric", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
      { &hf_isis_lsp_delay_metric, { "Delay metric", "isis.lsp.delay_metric", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }},
      { &hf_isis_lsp_default_metric, { "Default metric", "isis.lsp.default_metric", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_default_metric_ie, { "Default Metric IE", "isis.lsp.ip_reachability.default_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_delay_metric_support, { "Delay Metric", "isis.lsp.ip_reachability.delay_metric_support", FT_BOOLEAN, 8, TFS(&tfs_notsupported_supported), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_expense_metric_support, { "Expense Metric", "isis.lsp.ip_reachability.expense_metric_support", FT_BOOLEAN, 8, TFS(&tfs_notsupported_supported), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_error_metric_support, { "Error Metric", "isis.lsp.ip_reachability.error_metric_support", FT_BOOLEAN, 8, TFS(&tfs_notsupported_supported), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_spsourceid, { "SPSourceId", "isis.lsp.mt_cap.spsourceid", FT_UINT32, BASE_HEX_DEC, NULL, 0xfffff, NULL, HFILL }},
      { &hf_isis_lsp_mt_cap_overload, { "Overload", "isis.lsp.overload", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_default_metric_ie, { "Default Metric", "isis.lsp.eis_neighbors.default_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_delay_metric_supported, { "Delay Metric", "isis.lsp.eis_neighbors_delay_metric.supported", FT_BOOLEAN, 8, TFS(&tfs_notsupported_supported), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_expense_metric_supported, { "Expense Metric", "isis.lsp.eis_neighbors.expense_metric_supported", FT_BOOLEAN, 8, TFS(&tfs_notsupported_supported), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_error_metric_supported, { "Error Metric", "isis.lsp.eis_neighbors.error_metric_supported", FT_BOOLEAN, 8, TFS(&tfs_notsupported_supported), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_unrsv_bw_priority_level, { "priority level", "isis.lsp.unrsv_bw.priority_level", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_distribution, { "Distribution", "isis.lsp.ip_reachability.distribution", FT_BOOLEAN, 8, TFS(&tfs_up_down), 0x80, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_delay_metric_ie, { "Delay Metric", "isis.lsp.ip_reachability.delay_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_expense_metric_ie, { "Expense Metric", "isis.lsp.ip_reachability.expense_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_ip_reachability_error_metric_ie, { "Error Metric", "isis.lsp.ip_reachability.error_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_delay_metric_ie, { "Delay Metric", "isis.lsp.eis_neighbors.delay_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_expense_metric_ie, { "Expense Metric", "isis.lsp.eis_neighbors.expense_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
      { &hf_isis_lsp_eis_neighbors_error_metric_ie, { "Error Metric", "isis.lsp.eis_neighbors.error_metric_ie", FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_isis_lsp,
		&ett_isis_lsp_info,
		&ett_isis_lsp_att,
		&ett_isis_lsp_cksum,
		&ett_isis_lsp_clv_area_addr,
		&ett_isis_lsp_clv_is_neighbors,
		&ett_isis_lsp_clv_ext_is_reachability, /* CLV 22 */
		&ett_isis_lsp_part_of_clv_ext_is_reachability,
		&ett_isis_lsp_subclv_admin_group,
		&ett_isis_lsp_subclv_unrsv_bw,
		&ett_isis_lsp_subclv_spb_link_metric,
		&ett_isis_lsp_clv_unknown,
		&ett_isis_lsp_clv_partition_dis,
		&ett_isis_lsp_clv_prefix_neighbors,
		&ett_isis_lsp_clv_authentication,
		&ett_isis_lsp_clv_ip_authentication,
		&ett_isis_lsp_clv_nlpid,
		&ett_isis_lsp_clv_hostname,
		&ett_isis_lsp_clv_ipv4_int_addr,
		&ett_isis_lsp_clv_ipv6_int_addr, /* CLV 232 */
		&ett_isis_lsp_clv_mt_cap,
		&ett_isis_lsp_clv_mt_cap_spb_instance,
		&ett_isis_lsp_clv_mt_cap_spbm_service_identifier,
		&ett_isis_lsp_clv_te_router_id,
		&ett_isis_lsp_clv_ip_reachability,
		&ett_isis_lsp_clv_ip_reach_subclv,
		&ett_isis_lsp_clv_ext_ip_reachability, /* CLV 135 */
		&ett_isis_lsp_part_of_clv_ext_ip_reachability,
		&ett_isis_lsp_clv_ipv6_reachability, /* CLV 236 */
		&ett_isis_lsp_part_of_clv_ipv6_reachability,
		&ett_isis_lsp_clv_mt,
		&ett_isis_lsp_clv_mt_is,
		&ett_isis_lsp_part_of_clv_mt_is,
		&ett_isis_lsp_clv_rt_capable_IPv4_prefx,
		&ett_isis_lsp_clv_grp_address_IPv4_prefx,    /*CLV 142*/
		&ett_isis_lsp_clv_mt_reachable_IPv4_prefx,
		&ett_isis_lsp_clv_mt_reachable_IPv6_prefx,
		&ett_isis_lsp_clv_mt_cap_spbv_mac_address
	};

	static ei_register_info ei[] = {
		{ &ie_isis_lsp_checksum_bad, { "isis.lsp.checksum_bad.expert", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
		{ &ei_isis_lsp_short_packet, { "isis.lsp.short_packet", PI_MALFORMED, PI_ERROR, "Short packet", EXPFILL }},
		{ &ei_isis_lsp_long_packet, { "isis.lsp.long_packet", PI_MALFORMED, PI_ERROR, "Long packet", EXPFILL }},
		{ &ei_isis_lsp_subtlv, { "isis.lsp.subtlv.unknown", PI_PROTOCOL, PI_WARN, "Unknown SubTLV", EXPFILL }},
		{ &ei_isis_lsp_authentication, { "isis.lsp.authentication.unknown", PI_PROTOCOL, PI_WARN, "Unknown authentication type", EXPFILL }},
	};

	expert_module_t* expert_isis_lsp;

	/* Register the protocol name and description */
	proto_isis_lsp = proto_register_protocol(PROTO_STRING_LSP, "ISIS LSP", "isis.lsp");

	proto_register_field_array(proto_isis_lsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_isis_lsp = expert_register_protocol(proto_isis_lsp);
	expert_register_field_array(expert_isis_lsp, ei, array_length(ei));
}

void
proto_reg_handoff_isis_lsp(void)
{
	dissector_add_uint("isis.type", ISIS_TYPE_L1_LSP, new_create_dissector_handle(dissect_isis_l1_lsp, proto_isis_lsp));
	dissector_add_uint("isis.type", ISIS_TYPE_L2_LSP, new_create_dissector_handle(dissect_isis_l2_lsp, proto_isis_lsp));
}
