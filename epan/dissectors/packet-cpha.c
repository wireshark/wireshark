/* packet-cpha.c
 * Routines for the Check Point High-Availability Protocol (CPHAP)
 * Copyright 2002, Yaniv Kaul <mykaul -at- gmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/ipproto.h>

static int proto_cphap = -1;

static int hf_magic_number = -1;
static int hf_cpha_protocol_ver = -1;
static int hf_cluster_number = -1;
static int hf_opcode = -1;
static int hf_src_if_num = -1;
static int hf_random_id = -1;
static int hf_src_machine_id = -1;
static int hf_dst_machine_id = -1;
static int hf_policy_id = -1;
static int hf_filler = -1;
static int hf_id_num = -1;
static int hf_report_code = -1;
static int hf_ha_mode = -1;
static int hf_ha_time_unit = -1;
/*static int hf_problem = -1;*/
static int hf_num_reported_ifs = -1;
static int hf_ethernet_add = -1;
static int hf_is_if_trusted = -1;
static int hf_ip = -1;
static int hf_slot_num = -1;
static int hf_machine_num = -1;
static int hf_seed = -1;
static int hf_hash_len = -1;
static int hf_status = -1;
static int hf_in_up_num = -1;
static int hf_in_assumed_up_num = -1;
static int hf_out_up_num = -1;
static int hf_out_assumed_up_num = -1;
static int hf_ifn = -1;

static gint ett_cphap = -1;

#define UDP_PORT_CPHA	8116
#define CPHA_MAGIC 0x1A90

struct cpha_hdr {
  guint16	magic_number;
  guint16	ha_protocol_ver;
  guint16	cluster_number;
  guint16	opcode;
  guint16	src_if_num;
  guint16	random_id;
  guint16	src_machine_id;
  guint16	dst_machine_id;
  guint16	policy_id;
  guint16	filler;
  guint32	data;
};

struct fwha_my_state_hdr {
  guint16	id_num;
  guint16	report_code;
  guint16	ha_mode;
  guint16	ha_time_unit;
  /*guint16	problem;*/
};

struct conf_reply_hdr {
  guint32	num_reported_ifs;
  guint8	ethernet_add[6];
  guint16	is_if_trusted;
  guint32 	ip;
};

struct lb_conf_hdr {
  guint16	slot_num;
  guint16	machine_num;
  guint32	seed;
  guint32	hash_list_len;
};

struct fwhap_if_state_s {
  guint8	in_up_num;
  guint8	in_assumed_up_num;
  guint8	out_up_num;
  guint8	out_assumed_up_num;
};

#define NUM_OPCODE_TYPES 10

static const char *opcode_type_str_short[NUM_OPCODE_TYPES+1] = {
  "Unknown",
  "FWHA_MY_STATE",
  "FWHA_QUERY_STATE",
  "FWHA_IF_PROBE_REQ",
  "FWHA_IF_PROBE_REPLY",
  "FWHA_IFCONF_REQ",
  "FWHA_IFCONF_REPLY",
  "FWHA_LB_CONF",
  "FWHA_LB_CONFIRM",
  "FWHA_POLICY_CHANGE",
  "FWHAP_SYNC"
};

static const char *opcode_type_str_long[NUM_OPCODE_TYPES+1] = {
  "Unknown OpCode",
  "Report source machine's state",
  "Query other machine's state",
  "Interface active check request",
  "Interface active check reply",
  "Interface configuration request",
  "Interface configuration reply",
  "LB configuration report request",
  "LB configuration report reply",
  "Policy ID change request/notification",
  "New Sync packet"
};

#define NUM_STATES 5
static const char *state_str[NUM_STATES] = {
  "Down/Dead",
  "Initializing",
  "Standby",
  "Ready",
  "Active/Active-Attention"
};

static const value_string status_vals[] = {
  { 1, "New policy arrived - no need to modify HA configuration" },
  { 2, "New policy arrived - need to modify HA configuration" },
  { 3, "Ready to change configuration" },
  { 0, NULL }
};

#define NUM_HA_MODES 4
static const char *ha_mode_str[NUM_HA_MODES+1] = {
  "FWHA_UNDEF_MODE",
  "FWHA_NOT_ACTIVE_MODE - CPHA is not active",
  "FWHA_BALANCE_MODE - More than one machine active",
  "FWHA_PRIMARY_UP_MODE",
  "FWHA_ONE_UP_MODE"
};

static const char *ha_magic_num2str(guint16 magic);
static const char *version2str(guint16 version);
static const char *opcode2str_short(guint16 opcode);
static const char *opcode2str_long(guint16 opcode);
static void dissect_my_state(tvbuff_t *, int, proto_tree *);
static void dissect_lb_conf(tvbuff_t *, int, proto_tree *);
static void dissect_policy_change(tvbuff_t *, int, proto_tree *);
static void dissect_probe(tvbuff_t *, int, proto_tree *);
static void dissect_conf_reply(tvbuff_t *, int, proto_tree *);
static int is_report_ifs(guint16);
static const char *report_code2str(guint16);
static const char *ha_mode2str(guint16);
static const char *state2str(guint8);

static int
dissect_cpha(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int			offset = 0;
  struct cpha_hdr 	hdr;
  proto_item *		ti;
  proto_item *		nti;
  proto_tree *		cpha_tree = NULL;
  proto_tree *		ntree = NULL;
  guint16		opcode;

  /*
   * If the magic number or protocol version is unknown, don't treat this
   * frame as a CPHA frame.
   */
  if (tvb_length(tvb) < 4) {
    /* Not enough data for the magic number or protocol version */
    return 0;
  }
  hdr.magic_number = tvb_get_ntohs(tvb, 0);
  hdr.ha_protocol_ver = tvb_get_ntohs(tvb, 2);
  if (ha_magic_num2str(hdr.magic_number) == NULL) {
    /* Bad magic number */
    return 0;
  }
  if (version2str(hdr.ha_protocol_ver) == NULL) {
    /* Bad version number */
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CPHA");
  col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&hdr, offset, sizeof(hdr));
  hdr.magic_number = g_ntohs(hdr.magic_number);
  hdr.ha_protocol_ver = g_ntohs(hdr.ha_protocol_ver);
  hdr.random_id = g_ntohs(hdr.random_id);
  hdr.src_if_num = g_ntohs(hdr.src_if_num);
  hdr.src_machine_id = g_ntohs(hdr.src_machine_id);
  hdr.dst_machine_id = g_ntohs(hdr.dst_machine_id);
  hdr.policy_id = g_ntohs(hdr.policy_id);
  hdr.filler = g_ntohs(hdr.filler);
  opcode  = g_ntohs(hdr.opcode);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "CPHAv%d: %s",
        hdr.ha_protocol_ver, opcode2str_short(opcode));

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cphap, tvb, offset, -1, FALSE);
    cpha_tree = proto_item_add_subtree(ti, ett_cphap);
  }
  if (tree) {
    proto_tree_add_uint_format(cpha_tree, hf_magic_number, tvb, offset, sizeof(hdr.magic_number), hdr.magic_number, "Magic Number: 0x%x (%s)", hdr.magic_number, ha_magic_num2str(hdr.magic_number));
    offset += sizeof(hdr.magic_number);

    proto_tree_add_uint_format_value(cpha_tree, hf_cpha_protocol_ver, tvb, offset, sizeof(hdr.ha_protocol_ver), hdr.ha_protocol_ver, "%d (%s)", hdr.ha_protocol_ver,version2str(hdr.ha_protocol_ver));
    offset += sizeof(hdr.ha_protocol_ver);

    proto_tree_add_uint(cpha_tree, hf_cluster_number, tvb, offset, sizeof(hdr.cluster_number), g_ntohs(hdr.cluster_number));
    offset += sizeof(hdr.cluster_number);

    proto_tree_add_uint_format(cpha_tree, hf_opcode, tvb, offset, sizeof(hdr.opcode), opcode,
			"HA OpCode: %d (%s - %s)", opcode, opcode2str_short(opcode), opcode2str_long(opcode));
    offset += sizeof(hdr.opcode);

    proto_tree_add_uint(cpha_tree, hf_src_if_num, tvb, offset, sizeof(hdr.src_if_num),
			hdr.src_if_num);
    offset += sizeof(hdr.src_if_num);

    proto_tree_add_uint(cpha_tree, hf_random_id, tvb, offset, sizeof(hdr.random_id), hdr.random_id);
    offset += sizeof(hdr.random_id);

    proto_tree_add_uint(cpha_tree, hf_src_machine_id, tvb, offset, sizeof(hdr.src_machine_id), hdr.src_machine_id);
    offset += sizeof(hdr.src_machine_id);

    proto_tree_add_uint(cpha_tree, hf_dst_machine_id, tvb, offset, sizeof(hdr.dst_machine_id), hdr.dst_machine_id);
    offset += sizeof(hdr.dst_machine_id);
    if(hdr.ha_protocol_ver != 1) {/* 4.1 - no policy_id and filler*/
    	proto_tree_add_uint(cpha_tree, hf_policy_id, tvb, offset, sizeof(hdr.policy_id), hdr.policy_id);
    	offset += sizeof(hdr.policy_id);

    	proto_tree_add_uint(cpha_tree, hf_filler, tvb, offset, sizeof(hdr.filler), g_ntohs(hdr.filler));
    	offset += sizeof(hdr.filler);
    }
    nti = proto_tree_add_text(cpha_tree, tvb, offset, -1, "%s", opcode2str_short(opcode));
    ntree = proto_item_add_subtree(nti, ett_cphap);

    switch(opcode) {
	case 1: dissect_my_state(tvb, offset, ntree); /* FWHAP_MY_STATE */
		break;
	case 2: break;
	case 3:					     /* FWHAP_IF_PROBE_REQ */
	case 4: dissect_probe(tvb, offset, ntree);   /* FWHAP_IF_PROBE_RPLY */
		break;
	case 5: break;
	case 6: dissect_conf_reply(tvb, offset, ntree); /* FWHAP_IFCONF_RPLY */
		break;
	case 7: dissect_lb_conf(tvb, offset, ntree); /* FWHAP_LB_CONF */
		break;
	case 9: dissect_policy_change(tvb, offset, ntree); /* FWHAP_POLICY_CHANGE */
		break;
	default: break;
    }
  }

  return tvb_length(tvb);
}

static void dissect_my_state(tvbuff_t * tvb, int offset, proto_tree * tree) {
  struct fwha_my_state_hdr hdr;
  struct fwhap_if_state_s  if_hdr;
  int i;
  proto_item *	nti = NULL;
  proto_tree *  ntree = NULL;

  tvb_memcpy(tvb, (guint8 *)&hdr, offset, sizeof(hdr));
  hdr.id_num = g_ntohs(hdr.id_num);
  hdr.report_code = g_ntohs(hdr.report_code);
  hdr.ha_mode = g_ntohs(hdr.ha_mode);
  hdr.ha_time_unit = g_ntohs(hdr.ha_time_unit);

  proto_tree_add_uint(tree, hf_id_num, tvb, offset, sizeof(hdr.id_num), hdr.id_num);
  offset += sizeof(hdr.id_num);

  proto_tree_add_text(tree, tvb, offset, sizeof(hdr.report_code), "Report Code: %s",report_code2str(hdr.report_code));
  offset += sizeof(hdr.report_code);

  proto_tree_add_uint_format_value(tree, hf_ha_mode, tvb, offset, sizeof(hdr.ha_mode), hdr.ha_mode, "%d (%s)", hdr.ha_mode, ha_mode2str(hdr.ha_mode));
  offset += sizeof(hdr.ha_mode);

  proto_tree_add_uint_format_value(tree, hf_ha_time_unit, tvb, offset, sizeof(hdr.ha_time_unit), hdr.ha_time_unit, "%d milliseconds", hdr.ha_time_unit);
  offset += sizeof(hdr.ha_time_unit);

  if (hdr.report_code & 1) {
	/* states */
  	nti = proto_tree_add_text(tree, tvb, offset, hdr.id_num * sizeof(guint8), "Machine states");
	ntree = proto_item_add_subtree(nti, ett_cphap);
	for(i=0; i < hdr.id_num; i++) {
		proto_tree_add_text(ntree, tvb, offset, sizeof(guint8), "State of node %d: %d (%s)", i, tvb_get_guint8(tvb, offset), state2str(tvb_get_guint8(tvb, offset)));
		offset += sizeof(guint8);
	}
  }
  if (hdr.report_code & 2) {
	/* interface information */
	nti = proto_tree_add_text(tree, tvb, offset, sizeof(struct fwhap_if_state_s), "Interface states");
	ntree = proto_item_add_subtree(nti, ett_cphap);
  	tvb_memcpy(tvb, (guint8 *)&if_hdr, offset, sizeof(if_hdr));
	proto_tree_add_int(ntree, hf_in_up_num, tvb, offset, sizeof(if_hdr.in_up_num), if_hdr.in_up_num);
	offset += sizeof(if_hdr.in_up_num);
	proto_tree_add_int(ntree, hf_in_assumed_up_num, tvb, offset, sizeof(if_hdr.in_assumed_up_num), if_hdr.in_assumed_up_num);
	offset += sizeof(if_hdr.in_assumed_up_num);
 	proto_tree_add_int(ntree, hf_out_up_num, tvb, offset, sizeof(if_hdr.out_up_num), if_hdr.out_up_num);
	offset += sizeof(if_hdr.out_up_num);
	proto_tree_add_int(ntree, hf_out_assumed_up_num, tvb, offset, sizeof(if_hdr.out_assumed_up_num), if_hdr.out_assumed_up_num);
	offset += sizeof(if_hdr.out_assumed_up_num);

	for(i=0; i < hdr.id_num; i++) {
		proto_tree_add_text(tree, tvb, offset, sizeof(guint8), "Cluster %d: last packet seen %d time units ago", i, tvb_get_guint8(tvb, offset));
		offset += sizeof(guint8);
	}
  }

}

static void dissect_lb_conf(tvbuff_t * tvb, int offset, proto_tree * tree) {
  struct lb_conf_hdr hdr;

  tvb_memcpy(tvb, (guint8 *)&hdr, offset, sizeof(hdr));
  hdr.slot_num = g_ntohs(hdr.slot_num);
  hdr.machine_num = g_ntohs(hdr.machine_num);
  hdr.seed = g_ntohs(hdr.seed);
  hdr.hash_list_len = g_ntohs(hdr.hash_list_len);

  proto_tree_add_uint(tree, hf_slot_num, tvb, offset, sizeof(hdr.slot_num), hdr.slot_num);
  offset += sizeof(hdr.slot_num);

  proto_tree_add_int(tree, hf_machine_num, tvb, offset, sizeof(hdr.machine_num), hdr.machine_num);
  offset += sizeof(hdr.machine_num);

  proto_tree_add_uint(tree, hf_seed, tvb, offset, sizeof(hdr.seed), hdr.seed);
  offset += sizeof(hdr.seed);

  proto_tree_add_uint(tree, hf_hash_len, tvb, offset, sizeof(hdr.hash_list_len), hdr.hash_list_len);
  offset += sizeof(hdr.hash_list_len);

}

static void dissect_policy_change(tvbuff_t * tvb, int offset, proto_tree * tree) {
  guint32 status;

  status = tvb_get_ntohl(tvb, offset);

  proto_tree_add_uint(tree, hf_status, tvb, offset, sizeof(status), status);
  offset += sizeof(guint32);
}

static void dissect_probe(tvbuff_t * tvb, int offset, proto_tree * tree) {
  guint32 ifn;

  ifn = tvb_get_ntohl(tvb, offset);

  proto_tree_add_uint(tree, hf_ifn, tvb, offset, sizeof(ifn), ifn);
  offset += sizeof(guint32);
}

static void dissect_conf_reply(tvbuff_t * tvb, int offset, proto_tree * tree) {
  struct conf_reply_hdr hdr;

  tvb_memcpy(tvb, (guint8 *)&hdr, offset, sizeof(hdr));
  hdr.num_reported_ifs = g_ntohl(hdr.num_reported_ifs);
  hdr.is_if_trusted = g_ntohs(hdr.is_if_trusted);

  proto_tree_add_uint(tree, hf_num_reported_ifs, tvb, offset, sizeof(hdr.num_reported_ifs), hdr.num_reported_ifs);
  offset += sizeof(hdr.num_reported_ifs);
  proto_tree_add_ether(tree, hf_ethernet_add, tvb, offset, 6, hdr.ethernet_add);
  offset += 6;

  proto_tree_add_boolean(tree, hf_is_if_trusted, tvb, offset, sizeof(hdr.is_if_trusted), hdr.is_if_trusted);
  offset += sizeof(hdr.is_if_trusted);

  proto_tree_add_ipv4(tree, hf_ip, tvb, offset, sizeof(hdr.ip), hdr.ip);
  offset += 4;
}

static int
is_report_ifs(guint16 report_code) {
  if(report_code & 2)
	return 1;
  return 0;
}

static const char *
report_code2str(guint16 report_code) {
  int ret;
  ret = is_report_ifs(report_code);
  if(!(report_code & 1))
	return "Machine information NOT present";
  if(ret == 1)
	return "Interface information included";
  return "Unknown report code!";
}
static const char *
ha_magic_num2str(guint16 magic) {
  if(magic == CPHA_MAGIC)
	return "correct";
  return NULL;
}

static const char *
version2str(guint16 version) {
  switch(version) {
	case 1: return "4.1";
	case 6: return "NG Feature Pack 2";
	case 530: return "NG Feature Pack 3";
	case 540: return "NG with Application Intelligence (Early Availability)";
	case 541: return "NG with Application Intelligence";
	default: break;
  }
  return "Unknown Version";
}
static const char *
opcode2str_short(guint16 opcode) {
  if(opcode <= NUM_OPCODE_TYPES)
	return opcode_type_str_short[opcode];
  return opcode_type_str_short[0];
}

static const char *
ha_mode2str(guint16 hamode) {
  if(hamode <= NUM_HA_MODES)
	return ha_mode_str[hamode];
  return "Unknown HA mode";
}

static const char *
state2str(guint8 state) {
  if(state < NUM_STATES)
	return state_str[state];
  return "Unknown";
}


static const char *
opcode2str_long(guint16 opcode) {
  if(opcode <= NUM_OPCODE_TYPES)
	return opcode_type_str_long[opcode];
  return opcode_type_str_long[0];
}

void
proto_register_cpha(void)
{
  static hf_register_info hf[] = {
    { &hf_magic_number,
    { "CPHAP Magic Number", "cpha.magic_number", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    { &hf_cpha_protocol_ver,
    { "Protocol Version", "cpha.version", FT_UINT16, BASE_DEC, NULL, 0x0, "CPHAP Version", HFILL}},
    { &hf_cluster_number,
    { "Cluster Number", "cpha.cluster_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_opcode,
    { "OpCode", "cpha.opcode", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_src_if_num,
    { "Source Interface", "cpha.src_if", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_random_id,
    { "Random ID", "cpha.random_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_src_machine_id,
    { "Source Machine ID", "cpha.src_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dst_machine_id,
    { "Destination Machine ID", "cpha.dst_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_policy_id,
    { "Policy ID", "cpha.policy_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_filler,
    { "Filler", "cpha.filler", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_id_num,
    { "Number of IDs reported", "cpha.id_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_report_code,
    { "Report code", "cpha.id_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ha_mode,
    { "HA mode", "cpha.ha_mode", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ha_time_unit,
    { "HA Time unit", "cpha.ha_time_unit", FT_UINT16, BASE_DEC, NULL, 0x0, "HA Time unit (ms)", HFILL}},
    { &hf_num_reported_ifs,
    { "Reported Interfaces", "cpha.reported_ifs", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ethernet_add,
    { "Ethernet Address", "cpha.ethernet_addr", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_is_if_trusted,
    { "Interface Trusted", "cpha.if_trusted", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_ip,
    { "IP Address", "cpha.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_slot_num,
    { "Slot Number", "cpha.slot_num", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_machine_num,
    { "Machine Number", "cpha.machine_num", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_seed,
    { "Seed", "cpha.seed", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_hash_len,
    { "Hash list length", "cpha.hash_len", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_in_up_num,
    { "Interfaces up in the Inbound", "cpha.in_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_in_assumed_up_num,
    { "Interfaces assumed up in the Inbound", "cpha.in_assume_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_out_up_num,
    { "Interfaces up in the Outbound", "cpha.out_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_out_assumed_up_num,
    { "Interfaces assumed up in the Outbound", "cpha.out_assume_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_status,
    { "Status", "cpha.status", FT_UINT32, BASE_DEC, VALS(status_vals), 0x0, NULL, HFILL}},
    { &hf_ifn,
    { "Interface Number", "cpha.ifn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  };
  static gint *ett[] = {
    &ett_cphap,
  };

  proto_cphap = proto_register_protocol("Check Point High Availability Protocol",
					       "CPHA", "cpha");
  proto_register_field_array(proto_cphap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cpha(void)
{
  dissector_handle_t cpha_handle;

  cpha_handle = new_create_dissector_handle(dissect_cpha, proto_cphap);
  dissector_add_uint("udp.port", UDP_PORT_CPHA, cpha_handle);
}
