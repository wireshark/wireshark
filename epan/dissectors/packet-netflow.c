/*
 ** packet-netflow.c
 ** 
 *****************************************************************************
 ** (c) 2002 bill fumerola <fumerola@yahoo-inc.com>
 ** All rights reserved.
 ** 
 ** This program is free software; you can redistribute it and/or
 ** modify it under the terms of the GNU General Public License
 ** as published by the Free Software Foundation; either version 2
 ** of the License, or (at your option) any later version.
 ** 
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 ** 
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *****************************************************************************
 **
 ** Previous NetFlow dissector written by Matthew Smart <smart@monkey.org>
 ** NetFlow v9 support added by same.
 **
 ** NetFlow v9 patches by Luca Deri <deri@ntop.org>
 **
 ** See
 **
 ** http://www.cisco.com/warp/public/cc/pd/iosw/prodlit/tflow_wp.htm
 **
 ** for NetFlow v9 information.
 **
 *****************************************************************************
 **
 ** this code was written from the following documentation:
 **
 ** http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_6/iug/format.pdf
 ** http://www.caida.org/tools/measurement/cflowd/configuration/configuration-9.html
 **
 ** some documentation is more accurate then others. in some cases, live data and
 ** information contained in responses from vendors were also used. some fields
 ** are dissected as vendor specific fields.
 **
 ** See also
 **
 ** http://www.cisco.com/univercd/cc/td/doc/cisintwk/intsolns/netflsol/nfwhite.htm
 **
 ** $Yahoo: //depot/fumerola/packet-netflow/packet-netflow.c#14 $
 ** $Id$
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <string.h>

#include <epan/prefs.h>

#define UDP_PORT_NETFLOW	2055

static guint global_netflow_udp_port = UDP_PORT_NETFLOW;
static guint netflow_udp_port = 0;

/*
 * pdu identifiers & sizes 
 */

#define V1PDU_SIZE		(4 * 12)
#define V5PDU_SIZE		(4 * 12)
#define V7PDU_SIZE		(4 * 13)
#define V8PDU_AS_SIZE		(4 * 7)
#define V8PDU_PROTO_SIZE	(4 * 7)
#define V8PDU_SPREFIX_SIZE	(4 * 8)
#define V8PDU_DPREFIX_SIZE	(4 * 8)
#define V8PDU_MATRIX_SIZE	(4 * 10)
#define V8PDU_DESTONLY_SIZE	(4 * 8)
#define V8PDU_SRCDEST_SIZE	(4 * 10)
#define V8PDU_FULL_SIZE		(4 * 11)
#define V8PDU_TOSAS_SIZE	(V8PDU_AS_SIZE + 4)
#define V8PDU_TOSPROTOPORT_SIZE	(V8PDU_PROTO_SIZE + 4)
#define V8PDU_TOSSRCPREFIX_SIZE	V8PDU_SPREFIX_SIZE
#define V8PDU_TOSDSTPREFIX_SIZE	V8PDU_DPREFIX_SIZE
#define V8PDU_TOSMATRIX_SIZE	V8PDU_MATRIX_SIZE
#define V8PDU_PREPORTPROTOCOL_SIZE (4 * 10)

static const value_string v5_sampling_mode[] = {
	{0, "No sampling mode configured"},
	{1, "Packet Interval sampling mode configured"},
	{0, NULL}
};

enum {
	V8PDU_NO_METHOD = 0,
	V8PDU_AS_METHOD,
	V8PDU_PROTO_METHOD,
	V8PDU_SPREFIX_METHOD,
	V8PDU_DPREFIX_METHOD,
	V8PDU_MATRIX_METHOD,
	V8PDU_DESTONLY_METHOD,
	V8PDU_SRCDEST_METHOD,
	V8PDU_FULL_METHOD,
	V8PDU_TOSAS_METHOD,
	V8PDU_TOSPROTOPORT_METHOD,
	V8PDU_TOSSRCPREFIX_METHOD,
	V8PDU_TOSDSTPREFIX_METHOD,
	V8PDU_TOSMATRIX_METHOD,
	V8PDU_PREPORTPROTOCOL_METHOD
};

static const value_string v8_agg[] = {
	{V8PDU_AS_METHOD, "V8 AS aggregation"},
	{V8PDU_PROTO_METHOD, "V8 Proto/Port aggregation"},
	{V8PDU_SPREFIX_METHOD, "V8 Source Prefix aggregation"},
	{V8PDU_DPREFIX_METHOD, "V8 Destination Prefix aggregation"},
	{V8PDU_MATRIX_METHOD, "V8 Network Matrix aggregation"},
	{V8PDU_DESTONLY_METHOD, "V8 Destination aggregation (Cisco Catalyst)"},
	{V8PDU_SRCDEST_METHOD, "V8 Src/Dest aggregation (Cisco Catalyst)"},
	{V8PDU_FULL_METHOD, "V8 Full aggregation (Cisco Catalyst)"},
	{V8PDU_TOSAS_METHOD, "V8 TOS+AS aggregation aggregation"},
	{V8PDU_TOSPROTOPORT_METHOD, "V8 TOS+Protocol aggregation"},
	{V8PDU_TOSSRCPREFIX_METHOD, "V8 TOS+Source Prefix aggregation"},
	{V8PDU_TOSDSTPREFIX_METHOD, "V8 TOS+Destination Prefix aggregation"},
	{V8PDU_TOSMATRIX_METHOD, "V8 TOS+Prefix Matrix aggregation"},
	{V8PDU_PREPORTPROTOCOL_METHOD, "V8 Port+Protocol aggregation"},
	{0, NULL}
};

/* Version 9 template cache structures */
#define V9TEMPLATE_CACHE_MAX_ENTRIES	100

struct v9_template_entry {
	guint16	type;
	guint16	length;
};

struct v9_template {
	guint16	id;
	guint16	count;
	guint32	length;
	guint32 source_id;
	guint32	source_addr;
	guint16 option_template; /* 0=data template, 1=option template */
	struct v9_template_entry *entries;
};

static struct v9_template v9_template_cache[V9TEMPLATE_CACHE_MAX_ENTRIES];

/*
 * ethereal tree identifiers
 */

static int      proto_netflow = -1;
static int      ett_netflow = -1;
static int      ett_unixtime = -1;
static int      ett_flow = -1;
static int      ett_template = -1;
static int      ett_field = -1;
static int      ett_dataflowset = -1;

/*
 * cflow header 
 */

static int      hf_cflow_version = -1;
static int      hf_cflow_count = -1;
static int      hf_cflow_sysuptime = -1;
static int      hf_cflow_unix_secs = -1;
static int      hf_cflow_unix_nsecs = -1;
static int      hf_cflow_timestamp = -1;
static int      hf_cflow_samplingmode = -1;
static int      hf_cflow_samplerate = -1;

/*
 * cflow version specific info 
 */
static int      hf_cflow_sequence = -1;
static int      hf_cflow_engine_type = -1;
static int      hf_cflow_engine_id = -1;
static int      hf_cflow_source_id = -1;

static int      hf_cflow_aggmethod = -1;
static int      hf_cflow_aggversion = -1;

/* Version 9 */

static int	hf_cflow_template_flowset_id = -1;
static int	hf_cflow_data_flowset_id = -1;
static int	hf_cflow_options_flowset_id = -1;
static int	hf_cflow_flowset_id = -1;
static int	hf_cflow_flowset_length = -1;
static int	hf_cflow_template_id = -1;
static int	hf_cflow_template_field_count = -1;
static int	hf_cflow_template_field_type = -1;
static int	hf_cflow_template_field_length = -1;
static int	hf_cflow_option_scope_length = -1;
static int	hf_cflow_option_length = -1;
static int	hf_cflow_template_scope_field_type = -1;
static int	hf_cflow_template_scope_field_length = -1;


/*
 * pdu storage
 */
static int      hf_cflow_srcaddr = -1;
static int      hf_cflow_srcaddr_v6 = -1;
static int      hf_cflow_srcnet = -1;
static int      hf_cflow_dstaddr = -1;
static int      hf_cflow_dstaddr_v6 = -1;
static int      hf_cflow_dstnet = -1;
static int      hf_cflow_nexthop = -1;
static int      hf_cflow_nexthop_v6 = -1;
static int      hf_cflow_bgpnexthop = -1;
static int      hf_cflow_bgpnexthop_v6 = -1;
static int      hf_cflow_inputint = -1;
static int      hf_cflow_outputint = -1;
static int      hf_cflow_flows = -1;
static int      hf_cflow_packets = -1;
static int      hf_cflow_packets64 = -1;
static int      hf_cflow_packetsout = -1;
static int      hf_cflow_octets = -1;
static int      hf_cflow_octets64 = -1;
static int      hf_cflow_timestart = -1;
static int      hf_cflow_timeend = -1;
static int      hf_cflow_srcport = -1;
static int      hf_cflow_dstport = -1;
static int      hf_cflow_prot = -1;
static int      hf_cflow_tos = -1;
static int      hf_cflow_flags = -1;
static int      hf_cflow_tcpflags = -1;
static int      hf_cflow_dstas = -1;
static int      hf_cflow_srcas = -1;
static int      hf_cflow_dstmask = -1;
static int      hf_cflow_srcmask = -1;
static int      hf_cflow_routersc = -1;
static int      hf_cflow_mulpackets = -1;
static int      hf_cflow_muloctets = -1;
static int      hf_cflow_octets_exp = -1;
static int      hf_cflow_packets_exp = -1;
static int      hf_cflow_flows_exp = -1;
static int      hf_cflow_sampling_interval = -1;
static int      hf_cflow_sampling_algorithm = -1;
static int      hf_cflow_flow_active_timeout = -1;
static int      hf_cflow_flow_inactive_timeout = -1;
static int      hf_cflow_mpls_top_label_type = -1;
static int      hf_cflow_mpls_pe_addr = -1;
const value_string special_mpls_top_label_type[] = {
	{0,	"Unknown"},
	{1,	"TE-MIDPT"},
	{2,	"ATOM"},
	{3,	"VPN"},
	{4,	"BGP"},
	{5,	"LDP"},

	{0,	NULL }
};

void
proto_tree_add_mpls_label(proto_tree * pdutree, tvbuff_t * tvb, int offset, int length, int level)
{
	if( length == 3) {
		guint8 b0 = tvb_get_guint8(tvb, offset);
		guint8 b1 = tvb_get_guint8(tvb, offset + 1);
		guint8 b2 = tvb_get_guint8(tvb, offset + 2);
		proto_tree_add_text(pdutree, tvb, offset, length,
			"MPLS-Label%d: %u exp-bits: %u %s", level,
			((b0<<12)+(b1<<4)+(b2>>4)), 
			((b2>>1)&0x7), 
			((b2&0x1)?"top-of-stack":""));
	} else {
		proto_tree_add_text(pdutree, tvb, offset, length,
			"MPLS-Label%d: bad lengh %d", level, length);
	}
}

void		proto_reg_handoff_netflow(void);

typedef int     dissect_pdu_t(proto_tree * pdutree, tvbuff_t * tvb, int offset,
			      int verspec);
static int      dissect_pdu(proto_tree * tree, tvbuff_t * tvb, int offset,
			    int verspec);
static int      dissect_v8_aggpdu(proto_tree * pdutree, tvbuff_t * tvb,
				  int offset, int verspec);
static int      dissect_v8_flowpdu(proto_tree * pdutree, tvbuff_t * tvb,
				   int offset, int verspec);
static int	dissect_v9_flowset(proto_tree * pdutree, tvbuff_t * tvb,
				   int offset, int verspec);
static int	dissect_v9_data(proto_tree * pdutree, tvbuff_t * tvb,
			       int offset, guint16 id, guint length);
static void	dissect_v9_pdu(proto_tree * pdutree, tvbuff_t * tvb,
			       int offset, struct v9_template * template);
static int	dissect_v9_options(proto_tree * pdutree, tvbuff_t * tvb,
			       int offset);
static int	dissect_v9_template(proto_tree * pdutree, tvbuff_t * tvb,
				    int offset, int len);
static void	v9_template_add(struct v9_template * template);
static struct v9_template *v9_template_get(guint16 id, guint32 src_addr,
					   guint32 src_id);

static gchar   *getprefix(const guint32 * address, int prefix);
static void     dissect_netflow(tvbuff_t * tvb, packet_info * pinfo,
				proto_tree * tree);

static int      flow_process_ints(proto_tree * pdutree, tvbuff_t * tvb,
				  int offset);
static int      flow_process_ports(proto_tree * pdutree, tvbuff_t * tvb,
				   int offset);
static int      flow_process_timeperiod(proto_tree * pdutree, tvbuff_t * tvb,
					int offset);
static int      flow_process_aspair(proto_tree * pdutree, tvbuff_t * tvb,
				    int offset);
static int      flow_process_sizecount(proto_tree * pdutree, tvbuff_t * tvb,
				       int offset);
static int      flow_process_textfield(proto_tree * pdutree, tvbuff_t * tvb,
				       int offset, int bytes,
				       const char *text);


static void
dissect_netflow(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	proto_tree     *netflow_tree = NULL;
	proto_tree     *ti;
	proto_item     *timeitem, *pduitem;
	proto_tree     *timetree, *pdutree;
	unsigned int    pduret, ver = 0, pdus = 0, x = 1, vspec;
	size_t          available, pdusize, offset = 0;
	nstime_t        ts;
	dissect_pdu_t  *pduptr;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CFLOW");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_netflow, tvb,
					 offset, -1, FALSE);
		netflow_tree = proto_item_add_subtree(ti, ett_netflow);
	}

	ver = tvb_get_ntohs(tvb, offset);
	vspec = ver;
	switch (ver) {
	case 1:
		pdusize = V1PDU_SIZE;
		pduptr = &dissect_pdu;
		break;
	case 5:
		pdusize = V5PDU_SIZE;
		pduptr = &dissect_pdu;
		break;
	case 7:
		pdusize = V7PDU_SIZE;
		pduptr = &dissect_pdu;
		break;
	case 8:
		pdusize = -1;	/* deferred */
		pduptr = &dissect_v8_aggpdu;
		break;
	case 9:
		pdusize = -1;	/* deferred */
		pduptr = &dissect_v9_flowset;
		break;
	default:
		return;
	}

	if (tree)
		proto_tree_add_uint(netflow_tree, hf_cflow_version, tvb,
				    offset, 2, ver);
	offset += 2;

	pdus = tvb_get_ntohs(tvb, offset);
	if (pdus <= 0)
		return;
	if (tree)
		proto_tree_add_uint(netflow_tree, hf_cflow_count, tvb,
				    offset, 2, pdus);
	offset += 2;

	/*
	 * set something interesting in the display now that we have info 
	 */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (ver == 9) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "total: %u (v%u) record%s", pdus, ver,
                            plurality(pdus, "", "s"));
		} else {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "total: %u (v%u) flow%s", pdus, ver,
                            plurality(pdus, "", "s"));
		}
	}

	/*
	 * the rest is only interesting if we're displaying/searching the
	 * packet 
	 */
	if (!tree)
		return;

	proto_tree_add_item(netflow_tree, hf_cflow_sysuptime, tvb,
			    offset, 4, FALSE);
	offset += 4;

	ts.secs = tvb_get_ntohl(tvb, offset);
	if (ver != 9) {
	  ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
	  timeitem = proto_tree_add_time(netflow_tree,
					 hf_cflow_timestamp, tvb, offset,
					 8, &ts);
        } else {
	  ts.nsecs = 0;
	  timeitem = proto_tree_add_time(netflow_tree,
					 hf_cflow_timestamp, tvb, offset,
					 4, &ts);
        }

	timetree = proto_item_add_subtree(timeitem, ett_unixtime);

	proto_tree_add_item(timetree, hf_cflow_unix_secs, tvb,
			    offset, 4, FALSE);
	offset += 4;

	if (ver != 9) {
		proto_tree_add_item(timetree, hf_cflow_unix_nsecs, tvb,
				    offset, 4, FALSE);
		offset += 4;
	}

	/*
	 * version specific header 
	 */
	if (ver == 5 || ver == 7 || ver == 8 || ver == 9) {
		proto_tree_add_item(netflow_tree, hf_cflow_sequence,
				    tvb, offset, 4, FALSE);
		offset += 4;
	}
	if (ver == 5 || ver == 8) {
		proto_tree_add_item(netflow_tree, hf_cflow_engine_type,
				    tvb, offset++, 1, FALSE);
		proto_tree_add_item(netflow_tree, hf_cflow_engine_id,
				    tvb, offset++, 1, FALSE);
	} else if (ver == 9) {
		proto_tree_add_item(netflow_tree, hf_cflow_source_id,
				    tvb, offset, 4, FALSE);
		offset += 4;
	}
	if (ver == 8) {
		vspec = tvb_get_guint8(tvb, offset);
		switch (vspec) {
		case V8PDU_AS_METHOD:
			pdusize = V8PDU_AS_SIZE;
			break;
		case V8PDU_PROTO_METHOD:
			pdusize = V8PDU_PROTO_SIZE;
			break;
		case V8PDU_SPREFIX_METHOD:
			pdusize = V8PDU_SPREFIX_SIZE;
			break;
		case V8PDU_DPREFIX_METHOD:
			pdusize = V8PDU_DPREFIX_SIZE;
			break;
		case V8PDU_MATRIX_METHOD:
			pdusize = V8PDU_MATRIX_SIZE;
			break;
		case V8PDU_DESTONLY_METHOD:
			pdusize = V8PDU_DESTONLY_SIZE;
			pduptr = &dissect_v8_flowpdu;
			break;
		case V8PDU_SRCDEST_METHOD:
			pdusize = V8PDU_SRCDEST_SIZE;
			pduptr = &dissect_v8_flowpdu;
			break;
		case V8PDU_FULL_METHOD:
			pdusize = V8PDU_FULL_SIZE;
			pduptr = &dissect_v8_flowpdu;
			break;
		case V8PDU_TOSAS_METHOD:
			pdusize = V8PDU_TOSAS_SIZE;
			break;
		case V8PDU_TOSPROTOPORT_METHOD:
			pdusize = V8PDU_TOSPROTOPORT_SIZE;
			break;
		case V8PDU_TOSSRCPREFIX_METHOD:
			pdusize = V8PDU_TOSSRCPREFIX_SIZE;
			break;
		case V8PDU_TOSDSTPREFIX_METHOD:
			pdusize = V8PDU_TOSDSTPREFIX_SIZE;
			break;
		case V8PDU_TOSMATRIX_METHOD:
			pdusize = V8PDU_TOSMATRIX_SIZE;
			break;
		case V8PDU_PREPORTPROTOCOL_METHOD:
			pdusize = V8PDU_PREPORTPROTOCOL_SIZE;
			break;
		default:
			pdusize = -1;
			vspec = 0;
			break;
		}
		proto_tree_add_uint(netflow_tree, hf_cflow_aggmethod,
				    tvb, offset++, 1, vspec);
		proto_tree_add_item(netflow_tree, hf_cflow_aggversion,
				    tvb, offset++, 1, FALSE);
	}
	if (ver == 7 || ver == 8)
		offset = flow_process_textfield(netflow_tree, tvb, offset, 4,
						"reserved");
	else if (ver == 5) {
		proto_tree_add_item(netflow_tree, hf_cflow_samplingmode,
				    tvb, offset, 2, FALSE);
		proto_tree_add_item(netflow_tree, hf_cflow_samplerate,
				    tvb, offset, 2, FALSE);
		offset += 2;
	}

	/*
	 * everything below here should be payload 
	 */
	for (x = 1; x < pdus + 1; x++) {
          	/*
		 * make sure we have a pdu's worth of data 
		 */
		available = tvb_length_remaining(tvb, offset);
		if (ver == 9 && available >= 4) {
			/* pdusize can be different for each v9 flowset */
			pdusize = tvb_get_ntohs(tvb, offset + 2);
		}

		if (available < pdusize)
			break;

		if (ver == 9) {
			pduitem = proto_tree_add_text(netflow_tree, tvb,
			    offset, pdusize, "FlowSet %u", x);
		} else {
			pduitem = proto_tree_add_text(netflow_tree, tvb,
			    offset, pdusize, "pdu %u/%u", x, pdus);
		}
		pdutree = proto_item_add_subtree(pduitem, ett_flow);

		pduret = pduptr(pdutree, tvb, offset, vspec);

		if (pduret < pdusize) pduret = pdusize; /* padding */

		/*
		 * if we came up short, stop processing 
		 */
		if (pduret == pdusize)
			offset += pduret;
		else
			break;
	}
}

/*
 * flow_process_* == common groups of fields, probably could be inline 
 */

static int
flow_process_ints(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_inputint, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(pdutree, hf_cflow_outputint, tvb, offset, 2,
			    FALSE);
	offset += 2;

	return offset;
}

static int
flow_process_ports(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_srcport, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(pdutree, hf_cflow_dstport, tvb, offset, 2, FALSE);
	offset += 2;

	return offset;
}

static int
flow_process_timeperiod(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	nstime_t        ts;
	guint32         msec;

	msec = tvb_get_ntohl(tvb, offset);
	ts.secs = msec / 1000;
	ts.nsecs = (msec % 1000) * 1000000;
	proto_tree_add_time(pdutree, hf_cflow_timestart, tvb, offset, 4, &ts);
	offset += 4;

	msec = tvb_get_ntohl(tvb, offset);
	ts.secs = msec / 1000;
	ts.nsecs = (msec % 1000) * 1000000;
	proto_tree_add_time(pdutree, hf_cflow_timeend, tvb, offset, 4, &ts);
	offset += 4;

	return offset;
}


static int
flow_process_aspair(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_srcas, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(pdutree, hf_cflow_dstas, tvb, offset, 2, FALSE);
	offset += 2;

	return offset;
}

static int
flow_process_sizecount(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_packets, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(pdutree, hf_cflow_octets, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
flow_process_textfield(proto_tree * pdutree, tvbuff_t * tvb, int offset,
		       int bytes, const char *text)
{
	proto_tree_add_text(pdutree, tvb, offset, bytes, text);
	offset += bytes;

	return offset;
}

static int
dissect_v8_flowpdu(proto_tree * pdutree, tvbuff_t * tvb, int offset,
		   int verspec)
{
	int             startoffset = offset;

	proto_tree_add_item(pdutree, hf_cflow_dstaddr, tvb, offset, 4, FALSE);
	offset += 4;

	if (verspec != V8PDU_DESTONLY_METHOD) {
		proto_tree_add_item(pdutree, hf_cflow_srcaddr, tvb, offset, 4,
				    FALSE);
		offset += 4;
	}
	if (verspec == V8PDU_FULL_METHOD) {
		proto_tree_add_item(pdutree, hf_cflow_dstport, tvb, offset, 2,
				    FALSE);
		offset += 2;
		proto_tree_add_item(pdutree, hf_cflow_srcport, tvb, offset, 2,
				    FALSE);
		offset += 2;
	}

	offset = flow_process_sizecount(pdutree, tvb, offset);
	offset = flow_process_timeperiod(pdutree, tvb, offset);

	proto_tree_add_item(pdutree, hf_cflow_outputint, tvb, offset, 2,
			    FALSE);
	offset += 2;

	if (verspec != V8PDU_DESTONLY_METHOD) {
		proto_tree_add_item(pdutree, hf_cflow_inputint, tvb, offset, 2,
				    FALSE);
		offset += 2;
	}

	proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, FALSE);
	if (verspec == V8PDU_FULL_METHOD)
		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);
	offset = flow_process_textfield(pdutree, tvb, offset, 1, "marked tos");

	if (verspec == V8PDU_SRCDEST_METHOD)
		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2,
					   "reserved");
	else if (verspec == V8PDU_FULL_METHOD)
		offset =
		    flow_process_textfield(pdutree, tvb, offset, 1, "padding");

	offset =
	    flow_process_textfield(pdutree, tvb, offset, 4, "extra packets");

	proto_tree_add_item(pdutree, hf_cflow_routersc, tvb, offset, 4, FALSE);
	offset += 4;

	return (offset - startoffset);
}

/*
 * dissect a version 8 pdu, returning the length of the pdu processed 
 */

static int
dissect_v8_aggpdu(proto_tree * pdutree, tvbuff_t * tvb, int offset,
		  int verspec)
{
	int             startoffset = offset;

	proto_tree_add_item(pdutree, hf_cflow_flows, tvb, offset, 4, FALSE);
	offset += 4;

	offset = flow_process_sizecount(pdutree, tvb, offset);
	offset = flow_process_timeperiod(pdutree, tvb, offset);

	switch (verspec) {
	case V8PDU_AS_METHOD:
	case V8PDU_TOSAS_METHOD:
		offset = flow_process_aspair(pdutree, tvb, offset);

		if (verspec == V8PDU_TOSAS_METHOD) {
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 2,
						   "reserved");
		}
		break;
	case V8PDU_PROTO_METHOD:
	case V8PDU_TOSPROTOPORT_METHOD:
		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);

		if (verspec == V8PDU_PROTO_METHOD)
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
		else if (verspec == V8PDU_TOSPROTOPORT_METHOD)
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2,
					   "reserved");
		offset = flow_process_ports(pdutree, tvb, offset);

		if (verspec == V8PDU_TOSPROTOPORT_METHOD)
			offset = flow_process_ints(pdutree, tvb, offset);
		break;
	case V8PDU_SPREFIX_METHOD:
	case V8PDU_DPREFIX_METHOD:
	case V8PDU_TOSSRCPREFIX_METHOD:
	case V8PDU_TOSDSTPREFIX_METHOD:
		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ?
				    hf_cflow_srcnet : hf_cflow_dstnet, tvb,
				    offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ?
				    hf_cflow_srcmask : hf_cflow_dstmask, tvb,
				    offset++, 1, FALSE);

		if (verspec == V8PDU_SPREFIX_METHOD
		    || verspec == V8PDU_DPREFIX_METHOD)
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
		else if (verspec == V8PDU_TOSSRCPREFIX_METHOD
			 || verspec == V8PDU_TOSDSTPREFIX_METHOD)
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);

		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ? hf_cflow_srcas
				    : hf_cflow_dstas, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ?
				    hf_cflow_inputint : hf_cflow_outputint,
				    tvb, offset, 2, FALSE);
		offset += 2;

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2,
					   "reserved");
		break;
	case V8PDU_MATRIX_METHOD:
	case V8PDU_TOSMATRIX_METHOD:
	case V8PDU_PREPORTPROTOCOL_METHOD:
		proto_tree_add_item(pdutree, hf_cflow_srcnet, tvb, offset, 4,
				    FALSE);
		offset += 4;

		proto_tree_add_item(pdutree, hf_cflow_dstnet, tvb, offset, 4,
				    FALSE);
		offset += 4;

		proto_tree_add_item(pdutree, hf_cflow_srcmask, tvb, offset++,
				    1, FALSE);

		proto_tree_add_item(pdutree, hf_cflow_dstmask, tvb, offset++,
				    1, FALSE);

		if (verspec == V8PDU_TOSMATRIX_METHOD ||
		    verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);
			if (verspec == V8PDU_TOSMATRIX_METHOD) {
				offset =
				    flow_process_textfield(pdutree, tvb,
							   offset, 1,
							   "padding");
			} else if (verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
				proto_tree_add_item(pdutree, hf_cflow_prot,
						    tvb, offset++, 1, FALSE);
			}
		} else {
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 2,
						   "reserved");
		}

		if (verspec == V8PDU_MATRIX_METHOD
		    || verspec == V8PDU_TOSMATRIX_METHOD) {
			offset = flow_process_aspair(pdutree, tvb, offset);
		} else if (verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
			offset = flow_process_ports(pdutree, tvb, offset);
		}

		offset = flow_process_ints(pdutree, tvb, offset);
		break;
	}


	return (offset - startoffset);
}

/* Dissect a version 9 FlowSet and return the length we processed. */

static int
dissect_v9_flowset(proto_tree * pdutree, tvbuff_t * tvb, int offset, int ver)
{
	int length;
	guint16	flowset_id;

	if (ver != 9)
		return (0);

	flowset_id = tvb_get_ntohs(tvb, offset);
	if (flowset_id == 0) {
		/* Template */
		proto_tree_add_item(pdutree, hf_cflow_template_flowset_id, tvb,
		    offset, 2, FALSE);
		offset += 2;

		length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb,
		    offset, 2, FALSE);
		offset += 2;

		dissect_v9_template(pdutree, tvb, offset, length - 4);
	} else if (flowset_id == 1) {
		/* Options */
		proto_tree_add_item(pdutree, hf_cflow_options_flowset_id, tvb,
		    offset, 2, FALSE);
		offset += 2;

		length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb,
		    offset, 2, FALSE);
		offset += 2;

		dissect_v9_options(pdutree, tvb, offset);
	} else if (flowset_id >= 2 && flowset_id <= 255) {
		/* Reserved */
		proto_tree_add_item(pdutree, hf_cflow_flowset_id, tvb,
		    offset, 2, FALSE);
		offset += 2;

		length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb,
		    offset, 2, FALSE);
		offset += 2;
	} else {
		/* Data */
		proto_tree_add_item(pdutree, hf_cflow_data_flowset_id, tvb,
		    offset, 2, FALSE);
		offset += 2;

		length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb,
		    offset, 2, FALSE);
		offset += 2;

		/*
		 * The length includes the length of the FlowSet ID and
		 * the length field itself.
		 */
		length -= 4;
		if (length > 0) {
			dissect_v9_data(pdutree, tvb, offset, flowset_id,
			    (guint)length);
		}
	}

	return (length);
}

static int
dissect_v9_data(proto_tree * pdutree, tvbuff_t * tvb, int offset,
    guint16 id, guint length)
{
	struct v9_template *template;
	proto_tree *data_tree;
	proto_item *data_item;

	template = v9_template_get(id, 0, 0);
	if (template != NULL && template->length != 0) {
		int count;

		count = 1;
		while (length >= template->length) {
			data_item = proto_tree_add_text(pdutree, tvb,
			    offset, template->length, "pdu %d", count++);
			data_tree = proto_item_add_subtree(data_item,
			    ett_dataflowset);

			dissect_v9_pdu(data_tree, tvb, offset, template);

			offset += template->length;
			length -= template->length;
		}
		if (length != 0) {
			proto_tree_add_text(pdutree, tvb, offset, length,
			    "Padding (%u byte%s)",
			    length, plurality(length, "", "s"));
		}
	} else {
		proto_tree_add_text(pdutree, tvb, offset, length,
		    "Data (%u byte%s), no template found",
		    length, plurality(length, "", "s"));
	}

	return (0);
}

static void
dissect_v9_pdu(proto_tree * pdutree, tvbuff_t * tvb, int offset,
    struct v9_template * template)
{
	int i;

	for (i = 0; i < template->count; i++) {
		guint16 type, length;
		nstime_t ts;
		guint32 msec;

		type = template->entries[i].type;
		length = template->entries[i].length;

		switch (type) {
		case 1: /* bytes */
			if (length == 4) {
				proto_tree_add_item(pdutree, hf_cflow_octets,
				    tvb, offset, length, FALSE);
			} else if (length == 8) {
				proto_tree_add_item(pdutree, hf_cflow_octets64,
				    tvb, offset, length, FALSE);
			} else {
				proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Octets: length %u", length);
			}
		  break;

		case 2: /* packets */
			if (length == 4) {
				proto_tree_add_item(pdutree, hf_cflow_packets,
				    tvb, offset, length, FALSE);
			} else if (length == 8) {
				proto_tree_add_item(pdutree, hf_cflow_packets64,
				    tvb, offset, length, FALSE);
			} else {
				proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Packets: length %u", length);
			}
			break;

		case 3: /* flows */
			if (length == 4) {
				proto_tree_add_item(pdutree, hf_cflow_flows,
				    tvb, offset, length, FALSE);
			} else {
				proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Flows: length %u", length);
			}
			break;

		case 4: /* proto */
			proto_tree_add_item(pdutree, hf_cflow_prot,
			    tvb, offset, length, FALSE);
			break;

		case 5: /* TOS */
			proto_tree_add_item(pdutree, hf_cflow_tos,
			    tvb, offset, length, FALSE);
			break;

		case 6: /* TCP flags */
			proto_tree_add_item(pdutree, hf_cflow_tcpflags,
			    tvb, offset, length, FALSE);
			break;

		case 7: /* source port */
			proto_tree_add_item(pdutree, hf_cflow_srcport,
			    tvb, offset, length, FALSE);
			break;

		case 8: /* source IP */
			if (length == 4) {
				proto_tree_add_item(pdutree, hf_cflow_srcaddr,
				    tvb, offset, length, FALSE);
			} else if (length == 16) {
				proto_tree_add_item(pdutree, hf_cflow_srcaddr_v6,
				    tvb, offset, length, FALSE);
			} else {
				proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "SrcAddr: length %u", length);
			}
			break;

		case 9: /* source mask */
			proto_tree_add_item(pdutree, hf_cflow_srcmask,
			    tvb, offset, length, FALSE);
			break;

		case 10: /* input SNMP */
			proto_tree_add_item(pdutree, hf_cflow_inputint,
			    tvb, offset, length, FALSE);
			break;

		case 11: /* dest port */
			proto_tree_add_item(pdutree, hf_cflow_dstport,
			    tvb, offset, length, FALSE);
			break;

		case 12: /* dest IP */
			if (length == 4) {
				proto_tree_add_item(pdutree, hf_cflow_dstaddr,
				    tvb, offset, length, FALSE);
			} else if (length == 16) {
				proto_tree_add_item(pdutree, hf_cflow_dstaddr_v6,
				    tvb, offset, length, FALSE);
			} else {
				proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "DstAddr: length %u", length);
			}
			break;

		case 13: /* dest mask */
			proto_tree_add_item(pdutree, hf_cflow_dstmask,
			    tvb, offset, length, FALSE);
			break;

		case 14: /* output SNMP */
			proto_tree_add_item(pdutree, hf_cflow_outputint,
			    tvb, offset, length, FALSE);
			break;

		case 15: /* nexthop IP */
			if (length == 4) {
				proto_tree_add_item(pdutree, hf_cflow_nexthop,
				    tvb, offset, length, FALSE);
			} else if (length == 16) {
				proto_tree_add_item(pdutree, hf_cflow_nexthop_v6,
				    tvb, offset, length, FALSE);
			} else {
				proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "NextHop: length %u", length);
			}
			break;

		case 16: /* source AS */
			proto_tree_add_item(pdutree, hf_cflow_srcas,
			    tvb, offset, length, FALSE);
			break;

		case 17: /* dest AS */
			proto_tree_add_item(pdutree, hf_cflow_dstas,
			    tvb, offset, length, FALSE);
			break;

		case 18: /* BGP nexthop IP */
			if (length == 4) {
				proto_tree_add_item(pdutree, hf_cflow_bgpnexthop,
				    tvb, offset, length, FALSE);
			} else if (length == 16) {
				proto_tree_add_item(pdutree, hf_cflow_bgpnexthop_v6,
				    tvb, offset, length, FALSE);
			} else {
				proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "BGPNextHop: length %u", length);
			}
			break;

		case 19: /* multicast packets */
			proto_tree_add_item(pdutree, hf_cflow_mulpackets,
			    tvb, offset, length, FALSE);
			break;

		case 20: /* multicast octets */
			proto_tree_add_item(pdutree, hf_cflow_muloctets,
			    tvb, offset, length, FALSE);
			break;

		case 21: /* last switched */
		        msec = tvb_get_ntohl(tvb, offset);
			ts.secs = msec / 1000;
			ts.nsecs = (msec % 1000) * 1000000;
			proto_tree_add_time(pdutree, hf_cflow_timeend,
			    tvb, offset, length, &ts);
			break;

		case 22: /* first switched */
		        msec = tvb_get_ntohl(tvb, offset);
			ts.secs = msec / 1000;
			ts.nsecs = (msec % 1000) * 1000000;
			proto_tree_add_time(pdutree, hf_cflow_timestart,
			    tvb, offset, length, &ts);
			break;
			
		case 34: /* sampling interval */
		  proto_tree_add_item(pdutree, hf_cflow_sampling_interval,
				      tvb, offset, length, FALSE);
		  break;

		case 35: /* sampling algorithm */
		  proto_tree_add_item(pdutree, hf_cflow_sampling_algorithm,
				      tvb, offset, length, FALSE);
		  break;

		case 36: /* flow active timeout */
		   proto_tree_add_item(pdutree, hf_cflow_flow_active_timeout,
				      tvb, offset, length, FALSE);
		  break;

		case 37: /* flow inactive timeout */
		   proto_tree_add_item(pdutree, hf_cflow_flow_inactive_timeout,
				      tvb, offset, length, FALSE);
		  break;

		case 40: /* bytes exported */
			proto_tree_add_item(pdutree, hf_cflow_octets_exp,
			    tvb, offset, length, FALSE);
			break;

		case 41: /* packets exported */
			proto_tree_add_item(pdutree, hf_cflow_packets_exp,
			    tvb, offset, length, FALSE);
			break;

		case 42: /* flows exported */
			proto_tree_add_item(pdutree, hf_cflow_flows_exp,
			    tvb, offset, length, FALSE);
			break;

		case 46: /* top MPLS label type*/ 
			proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_type,
			    tvb, offset, length, FALSE);
			break;
		case 47: /* top MPLS label PE address*/ 
			proto_tree_add_item(pdutree, hf_cflow_mpls_pe_addr,
			    tvb, offset, length, FALSE);
			break;
		case 70: /* MPLS label1*/ 
			proto_tree_add_mpls_label(pdutree, tvb, offset, length, 1);
			break;
		case 71: /* MPLS label2*/ 
			proto_tree_add_mpls_label(pdutree, tvb, offset, length, 2);
			break;
		case 72: /* MPLS label3*/ 
			proto_tree_add_mpls_label(pdutree, tvb, offset, length, 3);
			break;
		case 73: /* MPLS label4*/ 
			proto_tree_add_mpls_label(pdutree, tvb, offset, length, 4);
			break;
		default:
			proto_tree_add_text(pdutree, tvb, offset, length,
			    "Type %u", type);
			break;
		}

		offset += length;
	}
}

static int
dissect_v9_options(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
  guint16 length, option_scope_len, option_len, i, id, size;
  struct v9_template template;
  int template_offset;

  id = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(pdutree, hf_cflow_template_id, tvb,
		      offset, 2, FALSE);
  offset += 2;

  option_scope_len = length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(pdutree, hf_cflow_option_scope_length, tvb,
		      offset, 2, FALSE);
  offset += 2;

  option_len = length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(pdutree, hf_cflow_option_length, tvb,
		      offset, 2, FALSE);
  offset += 2;

  for(i=0; i<option_scope_len; i++) {
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pdutree, hf_cflow_template_scope_field_type, tvb,
			offset, 2, FALSE);
    offset += 2; i += 2;

    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pdutree, hf_cflow_template_scope_field_length, tvb,
			offset, 2, FALSE);
    offset += 2; i += 2;
  }

  template_offset = offset;

  for(i=0; i<option_len;) {
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pdutree, hf_cflow_template_field_type, tvb,
			offset, 2, FALSE);
    offset += 2; i += 2;

    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(pdutree, hf_cflow_template_field_length, tvb,
			offset, 2, FALSE);
    offset += 2; i += 2;
  }

  /* Cache template */
  memset(&template, 0, sizeof(template));
  template.id = id;
  template.count = option_len/4;
  template.source_addr = 0;	/* XXX */
  template.source_id = 0;	/* XXX */
  template.option_template = 1; /* Option template */
  size = template.count * sizeof(struct v9_template_entry);
  template.entries = g_malloc(size);
  tvb_memcpy(tvb, (guint8 *)template.entries, template_offset, size);

  v9_template_add(&template);
  
  return (0);
}

static int
dissect_v9_template(proto_tree * pdutree, tvbuff_t * tvb, int offset, int len)
{
	struct v9_template template;
	proto_tree *template_tree;
	proto_item *template_item;
	proto_tree *field_tree;
	proto_item *field_item;
	guint16 id, count;
	int remaining = len;
	gint32 i;

	while (remaining > 0) {

	  id = tvb_get_ntohs(tvb, offset);
	  count = tvb_get_ntohs(tvb, offset + 2);

	  template_item = proto_tree_add_text(pdutree, tvb, offset, 
	      4 + sizeof(struct v9_template_entry) * count, 
	      "Template (Id = %u, Count = %u)", id, count);
	  template_tree = proto_item_add_subtree(template_item, ett_template);

	  proto_tree_add_item(template_tree, hf_cflow_template_id, tvb,
	      offset, 2, FALSE);
	  offset += 2;

	  proto_tree_add_item(template_tree, hf_cflow_template_field_count, 
	      tvb, offset, 2, FALSE);
	  offset += 2;

	  /* Cache template */
	  memset(&template, 0, sizeof(template));
	  template.id = id;
	  template.count = count;
	  template.source_addr = 0;	/* XXX */
	  template.source_id = 0;		/* XXX */
	  template.option_template = 0;   /* Data template */
	  template.entries = g_malloc(count * sizeof(struct v9_template_entry));
	  tvb_memcpy(tvb, (guint8 *)template.entries, offset,
	      count * sizeof(struct v9_template_entry));
	  v9_template_add(&template);

	  for (i = 1; i <= count; i++) {
	    guint16 type, length;

	    type = tvb_get_ntohs(tvb, offset);
	    length = tvb_get_ntohs(tvb, offset + 2);

	    field_item = proto_tree_add_text(template_tree, tvb,
		offset, 4, "Field (%u/%u)", i, count);
	    field_tree = proto_item_add_subtree(field_item, ett_field);

	    proto_tree_add_item(field_tree,
		hf_cflow_template_field_type, tvb, offset, 2, FALSE);
	    offset += 2;

	    proto_tree_add_item(field_tree,
		hf_cflow_template_field_length, tvb, offset, 2, FALSE);
	    offset += 2;
	  }
	  remaining -= 4 + sizeof(struct v9_template_entry) * count;
	}

	return (0);
}

static value_string v9_template_types[] = {
	{ 1, "BYTES" },
	{ 2, "PKTS" },
	{ 3, "FLOWS" },
	{ 4, "PROT" },
	{ 5, "TOS" },
	{ 6, "TCP_FLAGS" },
	{ 7, "L4_SRC_PORT" },
	{ 8, "IP_SRC_ADDR" },
	{ 9, "SRC_MASK" },
	{ 10, "INPUT_SNMP" },
	{ 11, "L4_DST_PORT" },
	{ 12, "IP_DST_ADDR" },
	{ 13, "DST_MASK" },
	{ 14, "OUTPUT_SNMP" },
	{ 15, "IP_NEXT_HOP" },
	{ 16, "SRC_AS" },
	{ 17, "DST_AS" },
	{ 18, "BGP_NEXT_HOP" },
	{ 19, "MUL_DPKTS" },
	{ 20, "MUL_DOCTETS" },
	{ 21, "LAST_SWITCHED" },
	{ 22, "FIRST_SWITCHED" },
	{ 23, "OUT_BYTES" },
	{ 24, "OUT_PKTS" },
	{ 27, "IPV6_SRC_ADDR" },
	{ 28, "IPV6_DST_ADDR" },
	{ 29, "IPV6_SRC_MASK" },
	{ 30, "IPV6_DST_MASK" },
	{ 31, "FLOW_LABEL" },
	{ 32, "ICMP_TYPE" },
	{ 33, "IGMP_TYPE" },
	{ 34, "SAMPLING_INTERVAL" },
	{ 35, "SAMPLING_ALGORITHM" },
	{ 36, "FLOW_ACTIVE_TIMEOUT" },
	{ 37, "FLOW_INACTIVE_TIMEOUT" },
	{ 38, "ENGINE_TYPE" },
	{ 39, "ENGINE_ID" },
	{ 40, "TOTAL_BYTES_EXP" },
	{ 41, "TOTAL_PKTS_EXP" },
	{ 42, "TOTAL_FLOWS_EXP" },
	{ 46, "MPLS_TOP_LABEL_TYPE" },
	{ 47, "MPLS_TOP_LABEL_ADDR" },
	{ 48, "FLOW_SAMPLER_ID" },
	{ 49, "FLOW_SAMPLER_MODE" },
	{ 50, "FLOW_SAMPLER_RANDOM_INTERVAL" },
	{ 55, "DST_TOS" },
	{ 56, "SRC_MAC" },
	{ 57, "DST_MAC" },
	{ 58, "SRC_VLAN" },
	{ 59, "DST_VLAN" },
	{ 60, "IP_PROTOCOL_VERSION" },
	{ 61, "DIRECTION" },
	{ 62, "IPV6_NEXT_HOP" },
	{ 63, "BPG_IPV6_NEXT_HOP" },
	{ 64, "IPV6_OPTION_HEADERS" },
	{ 70, "MPLS_LABEL_1" },
	{ 71, "MPLS_LABEL_2" },
	{ 72, "MPLS_LABEL_3" },
	{ 73, "MPLS_LABEL_4" },
	{ 74, "MPLS_LABEL_5" },
	{ 75, "MPLS_LABEL_6" },
	{ 76, "MPLS_LABEL_7" },
	{ 77, "MPLS_LABEL_8" },
	{ 78, "MPLS_LABEL_9" },
	{ 79, "MPLS_LABEL_10" },
	{ 0, NULL },
};

static value_string v9_scope_field_types[] = {
	{ 1, "System" },
	{ 2, "Interface" },
	{ 3, "Line Card" },
	{ 4, "NetFlow Cache" },
	{ 5, "Template" },
	{ 0, NULL },
};

static void
v9_template_add(struct v9_template *template)
{
	int i;

	/* Add up the actual length of the data and store in proper byte order */
	template->length = 0;
	for (i = 0; i < template->count; i++) {
		template->entries[i].type = g_ntohs(template->entries[i].type);
		template->entries[i].length = g_ntohs(template->entries[i].length);
		template->length += template->entries[i].length;
	}

	memmove(&v9_template_cache[template->id % V9TEMPLATE_CACHE_MAX_ENTRIES],
	    template, sizeof(*template));
}

static struct v9_template *
v9_template_get(guint16 id, guint32 src_addr, guint32 src_id)
{
	struct v9_template *template;

	src_addr = 0;
	template = &v9_template_cache[id % V9TEMPLATE_CACHE_MAX_ENTRIES];

	if (template->id != id ||
	    template->source_addr != src_addr ||
	    template->source_id != src_id) {
		template = NULL;
	}

	return (template);
}

/*
 * dissect a version 1, 5, or 7 pdu and return the length of the pdu we
 * processed
 */

static int
dissect_pdu(proto_tree * pdutree, tvbuff_t * tvb, int offset, int ver)
{
	int             startoffset = offset;
	guint32         srcaddr, dstaddr;
	guint8          mask;
	nstime_t        ts;

	memset(&ts, '\0', sizeof(ts));

	/*
	 * memcpy so we can use the values later to calculate a prefix 
	 */
	srcaddr = tvb_get_ipv4(tvb, offset);
	proto_tree_add_ipv4(pdutree, hf_cflow_srcaddr, tvb, offset, 4,
			    srcaddr);
	offset += 4;

	dstaddr = tvb_get_ipv4(tvb, offset);
	proto_tree_add_ipv4(pdutree, hf_cflow_dstaddr, tvb, offset, 4,
			    dstaddr);
	offset += 4;

	proto_tree_add_item(pdutree, hf_cflow_nexthop, tvb, offset, 4, FALSE);
	offset += 4;

	offset = flow_process_ints(pdutree, tvb, offset);
	offset = flow_process_sizecount(pdutree, tvb, offset);
	offset = flow_process_timeperiod(pdutree, tvb, offset);
	offset = flow_process_ports(pdutree, tvb, offset);

	/*
	 * and the similarities end here 
	 */
	if (ver == 1) {
		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2, "padding");

		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);

		proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1,
				    FALSE);

		proto_tree_add_item(pdutree, hf_cflow_tcpflags, tvb, offset++,
				    1, FALSE);

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 3, "padding");

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 4,
					   "reserved");
	} else {
		if (ver == 5)
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
		else {
			proto_tree_add_item(pdutree, hf_cflow_flags, tvb,
					    offset++, 1, FALSE);
		}

		proto_tree_add_item(pdutree, hf_cflow_tcpflags, tvb, offset++,
				    1, FALSE);

		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);

		proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1,
				    FALSE);

		offset = flow_process_aspair(pdutree, tvb, offset);

		mask = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(pdutree, tvb, offset, 1,
				    "SrcMask: %u (prefix: %s/%u)",
				    mask, getprefix(&srcaddr, mask),
				    mask != 0 ? mask : 32);
		proto_tree_add_uint_hidden(pdutree, hf_cflow_srcmask, tvb,
					   offset++, 1, mask);

		mask = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(pdutree, tvb, offset, 1,
				    "DstMask: %u (prefix: %s/%u)",
				    mask, getprefix(&dstaddr, mask),
				    mask != 0 ? mask : 32);
		proto_tree_add_uint_hidden(pdutree, hf_cflow_dstmask, tvb,
					   offset++, 1, mask);

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2, "padding");

		if (ver == 7) {
			proto_tree_add_item(pdutree, hf_cflow_routersc, tvb,
					    offset, 4, FALSE);
			offset += 4;
		}
	}

	return (offset - startoffset);
}

static gchar   *
getprefix(const guint32 * address, int prefix)
{
	guint32         gprefix;

	gprefix = *address & g_htonl((0xffffffff << (32 - prefix)));

	return (ip_to_str((const guint8 *)&gprefix));
}


static void
netflow_reinit(void)
{
	int i;

	/*
	 * Clear out the template cache.
	 * Free the table of fields for each entry, and then zero out
	 * the cache.
	 */
	for (i = 0; i < V9TEMPLATE_CACHE_MAX_ENTRIES; i++)
		g_free(v9_template_cache[i].entries);
	memset(v9_template_cache, 0, sizeof v9_template_cache);
}

void
proto_register_netflow(void)
{
	static hf_register_info hf[] = {
		/*
		 * flow header 
		 */
		{&hf_cflow_version,
		 {"Version", "cflow.version",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "NetFlow Version", HFILL}
		 },
		{&hf_cflow_count,
		 {"Count", "cflow.count",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Count of PDUs", HFILL}
		 },
		{&hf_cflow_sysuptime,
		 {"SysUptime", "cflow.sysuptime",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Time since router booted (in milliseconds)", HFILL}
		 },

		{&hf_cflow_timestamp,
		 {"Timestamp", "cflow.timestamp",
		  FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
		  "Current seconds since epoch", HFILL}
		 },
		{&hf_cflow_unix_secs,
		 {"CurrentSecs", "cflow.unix_secs",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Current seconds since epoch", HFILL}
		 },
		{&hf_cflow_unix_nsecs,
		 {"CurrentNSecs", "cflow.unix_nsecs",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Residual nanoseconds since epoch", HFILL}
		 },
		{&hf_cflow_samplingmode,
		 {"SamplingMode", "cflow.samplingmode",
		  FT_UINT16, BASE_DEC, VALS(v5_sampling_mode), 0xC000,
		  "Sampling Mode of exporter", HFILL}
		 },
		{&hf_cflow_samplerate,
		 {"SampleRate", "cflow.samplerate",
		  FT_UINT16, BASE_DEC, NULL, 0x3FFF,
		  "Sample Frequency of exporter", HFILL}
		 },

		/*
		 * end version-agnostic header
		 * version-specific flow header 
		 */
		{&hf_cflow_sequence,
		 {"FlowSequence", "cflow.sequence",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Sequence number of flows seen", HFILL}
		 },
		{&hf_cflow_engine_type,
		 {"EngineType", "cflow.engine_type",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Flow switching engine type", HFILL}
		 },
		{&hf_cflow_engine_id,
		 {"EngineId", "cflow.engine_id",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Slot number of switching engine", HFILL}
		 },
		{&hf_cflow_source_id,
		 {"SourceId", "cflow.source_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Identifier for export device", HFILL}
		 },
		{&hf_cflow_aggmethod,
		 {"AggMethod", "cflow.aggmethod",
		  FT_UINT8, BASE_DEC, VALS(v8_agg), 0x0,
		  "CFlow V8 Aggregation Method", HFILL}
		 },
		{&hf_cflow_aggversion,
		 {"AggVersion", "cflow.aggversion",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "CFlow V8 Aggregation Version", HFILL}
		 },
		/*
		 * end version specific header storage 
		 */
		/*
		 * Version 9
		 */
		{&hf_cflow_flowset_id,
		 {"FlowSet Id", "cflow.flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "FlowSet Id", HFILL}
		 },
		{&hf_cflow_data_flowset_id,
		 {"Data FlowSet (Template Id)", "cflow.data_flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Data FlowSet with corresponding to a template Id", HFILL}
		 },
		{&hf_cflow_options_flowset_id,
		 {"Options FlowSet", "cflow.options_flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Options FlowSet", HFILL}
		 },
		{&hf_cflow_template_flowset_id,
		 {"Template FlowSet", "cflow.template_flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Template FlowSet", HFILL}
		 },
		{&hf_cflow_flowset_length,
		 {"FlowSet Length", "cflow.flowset_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "FlowSet length", HFILL}
		 },
		{&hf_cflow_template_id,
		 {"Template Id", "cflow.template_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Template Id", HFILL}
		 },
		{&hf_cflow_template_field_count,
		 {"Field Count", "cflow.template_field_count",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Template field count", HFILL}
		 },
		{&hf_cflow_template_field_type,
		 {"Type", "cflow.template_field_type",
		  FT_UINT16, BASE_DEC, VALS(v9_template_types), 0x0,
		  "Template field type", HFILL}
		 },
		{&hf_cflow_template_field_length,
		 {"Length", "cflow.template_field_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Template field length", HFILL}
		 },

		/* options */
		{&hf_cflow_option_scope_length,
		 {"Option Scope Length", "cflow.option_scope_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Option scope length", HFILL}
		 },
		{&hf_cflow_option_length,
		 {"Option Length", "cflow.option_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Option length", HFILL}
		 },
		{&hf_cflow_template_scope_field_type,
		 {"Scope Type", "cflow.scope_field_type",
		  FT_UINT16, BASE_DEC, VALS(v9_scope_field_types), 0x0,
		  "Scope field type", HFILL}
		 },		
		{&hf_cflow_template_scope_field_length,
		 {"Scope Field Length", "cflow.scope_field_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Scope field length", HFILL}
		 },
		{&hf_cflow_sampling_interval,
		 {"Sampling interval", "cflow.sampling_interval",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Sampling interval", HFILL}
		},
		{&hf_cflow_sampling_algorithm,
		 {"Sampling algorithm", "cflow.sampling_algorithm",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Sampling algorithm", HFILL}
		},
		{&hf_cflow_flow_active_timeout,
		 {"Flow active timeout", "cflow.flow_active_timeout",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow active timeout", HFILL}
		},
		{&hf_cflow_flow_inactive_timeout,
		 {"Flow inactive timeout", "cflow.flow_inactive_timeout",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow inactive timeout", HFILL}
		},

		/*
		 * begin pdu content storage 
		 */
		{&hf_cflow_srcaddr,
		 {"SrcAddr", "cflow.srcaddr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Source Address", HFILL}
		 },
		{&hf_cflow_srcaddr_v6,
		 {"SrcAddr", "cflow.srcaddrv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Source Address", HFILL}
		 },
		{&hf_cflow_srcnet,
		 {"SrcNet", "cflow.srcnet",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Source Network", HFILL}
		 },
		{&hf_cflow_dstaddr,
		 {"DstAddr", "cflow.dstaddr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Destination Address", HFILL}
		 },
		{&hf_cflow_dstaddr_v6,
		 {"DstAddr", "cflow.dstaddrv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Destination Address", HFILL}
		 },
		{&hf_cflow_dstnet,
		 {"DstNet", "cflow.dstaddr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Destination Network", HFILL}
		 },
		{&hf_cflow_nexthop,
		 {"NextHop", "cflow.nexthop",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Router nexthop", HFILL}
		 },
		{&hf_cflow_nexthop_v6,
		 {"NextHop", "cflow.nexthopv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Router nexthop", HFILL}
		 },
		{&hf_cflow_bgpnexthop,
		 {"BGPNextHop", "cflow.bgpnexthop",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "BGP Router Nexthop", HFILL}
		 },
		{&hf_cflow_bgpnexthop_v6,
		 {"BGPNextHop", "cflow.bgpnexthopv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "BGP Router Nexthop", HFILL}
		 },
		{&hf_cflow_inputint,
		 {"InputInt", "cflow.inputint",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Input Interface", HFILL}
		 },
		{&hf_cflow_outputint,
		 {"OutputInt", "cflow.outputint",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Output Interface", HFILL}
		 },
		{&hf_cflow_flows,
		 {"Flows", "cflow.flows",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Flows Aggregated in PDU", HFILL}
		 },
		{&hf_cflow_packets,
		 {"Packets", "cflow.packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of packets", HFILL}
		 },
		{&hf_cflow_packets64,
		 {"Packets", "cflow.packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of packets", HFILL}
		 },
		{&hf_cflow_packetsout,
		 {"PacketsOut", "cflow.packetsout",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of packets going out", HFILL}
		 },
		{&hf_cflow_octets,
		 {"Octets", "cflow.octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of bytes", HFILL}
		 },
		{&hf_cflow_octets64,
		 {"Octets", "cflow.octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of bytes", HFILL}
		 },
		{&hf_cflow_timestart,
		 {"StartTime", "cflow.timestart",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		  "Uptime at start of flow", HFILL}
		 },
		{&hf_cflow_timeend,
		 {"EndTime", "cflow.timeend",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		  "Uptime at end of flow", HFILL}
		 },
		{&hf_cflow_srcport,
		 {"SrcPort", "cflow.srcport",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Source Port", HFILL}
		 },
		{&hf_cflow_dstport,
		 {"DstPort", "cflow.dstport",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Destination Port", HFILL}
		 },
		{&hf_cflow_prot,
		 {"Protocol", "cflow.protocol",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IP Protocol", HFILL}
		 },
		{&hf_cflow_tos,
		 {"IP ToS", "cflow.tos",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "IP Type of Service", HFILL}
		 },
		{&hf_cflow_flags,
		 {"Export Flags", "cflow.flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "CFlow Flags", HFILL}
		 },
		{&hf_cflow_tcpflags,
		 {"TCP Flags", "cflow.tcpflags",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "TCP Flags", HFILL}
		 },
		{&hf_cflow_srcas,
		 {"SrcAS", "cflow.srcas",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Source AS", HFILL}
		 },
		{&hf_cflow_dstas,
		 {"DstAS", "cflow.dstas",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Destination AS", HFILL}
		 },
		{&hf_cflow_srcmask,
		 {"SrcMask", "cflow.srcmask",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Source Prefix Mask", HFILL}
		 },
		{&hf_cflow_dstmask,
		 {"DstMask", "cflow.dstmask",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Destination Prefix Mask", HFILL}
		 },
		{&hf_cflow_routersc,
		 {"Router Shortcut", "cflow.routersc",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Router shortcut by switch", HFILL}
		 },
		{&hf_cflow_mulpackets,
		 {"MulticastPackets", "cflow.mulpackets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of multicast packets", HFILL}
		 },
		{&hf_cflow_muloctets,
		 {"MulticastOctets", "cflow.muloctets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of multicast octets", HFILL}
		 },
		{&hf_cflow_octets_exp,
		 {"OctetsExp", "cflow.octetsexp",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Octets exported", HFILL}
		 },
		{&hf_cflow_packets_exp,
		 {"PacketsExp", "cflow.packetsexp",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Packets exported", HFILL}
		 },
		{&hf_cflow_mpls_top_label_type, 
		 {"TopLabelType", "cflow.toplabeltype",
		  FT_UINT8, BASE_DEC, VALS(special_mpls_top_label_type), 0x0,
		  "Top MPLS label Type", HFILL}
		 },
		{&hf_cflow_mpls_pe_addr, 
		 {"TopLabelAddr", "cflow.toplabeladdr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Top MPLS label PE address", HFILL}
		 },
		{&hf_cflow_flows_exp,
		 {"FlowsExp", "cflow.flowsexp",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Flows exported", HFILL}
		 }
		/*
		 * end pdu content storage 
		 */
	};

	static gint    *ett[] = {
		&ett_netflow,
		&ett_unixtime,
		&ett_flow,
		&ett_template,
		&ett_field,
		&ett_dataflowset
	};

	module_t *netflow_module;

	proto_netflow = proto_register_protocol("Cisco NetFlow", "CFLOW",
						"cflow");

	proto_register_field_array(proto_netflow, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register our configuration options for NetFlow */
	netflow_module = prefs_register_protocol(proto_netflow,
	    proto_reg_handoff_netflow);

	prefs_register_uint_preference(netflow_module, "udp.port",
	    "NetFlow UDP Port", "Set the port for NetFlow messages",
	    10, &global_netflow_udp_port);

	register_init_routine(&netflow_reinit);
}


/*
 * protocol/port association 
 */
void
proto_reg_handoff_netflow(void)
{
	static int netflow_prefs_initialized = FALSE;
	static dissector_handle_t netflow_handle;

	if (!netflow_prefs_initialized) {
		netflow_handle = create_dissector_handle(dissect_netflow,
		    proto_netflow);
		netflow_prefs_initialized = TRUE;
	} else {
		dissector_delete("udp.port", netflow_udp_port, netflow_handle);
	}

	/* Set out port number for future use */
	netflow_udp_port = global_netflow_udp_port;

	dissector_add("udp.port", netflow_udp_port, netflow_handle);
}
