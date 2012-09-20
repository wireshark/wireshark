/* packet-sndcp-xid.c
 * Routines for Subnetwork Dependent Convergence Protocol (SNDCP) XID dissection
 * Used to dissect XID compression parameters negotiated in GSM (TS44.065)
 * Copyright 2008, Vincent Helfre <vincent.helfre [AT] ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>


/* Parameter types: TS 44.065 8
*/
#define SNDCP_VERSION_PAR_TYPE 0
#define DATA_COMPRESSION_PAR_TYPE 1
#define PROTOCOL_COMPRESSION_PAR_TYPE 2

/* Algorithm identifiers: TS 44.065 6.6.1.1.4 and 6.5.1.1.4
*/
#define ALGO_V42BIS 0
#define ALGO_V44 1
#define ALGO_RFC1144 0
#define ALGO_RFC2507 1
#define ALGO_ROHC 2

static const value_string sndcp_xid_dcomp_algo_str[] = {
	{0x0, "V.42 bis"},
	{0x1, "V.44"},
	{0, NULL}
};

static const value_string sndcp_xid_pcomp_algo_str[] = {
	{0x0, "RFC 1144"},
	{0x1, "RFC 2507"},
	{0x2, "ROHC (RFC 3095)"},
	{0, NULL}
};

typedef struct
{
	guint8 nb_of_dcomp_pcomp; /* note that a DCOMP or a PCOMP is 4 bit wide */
	guint16 (**func_array_ptr) (tvbuff_t *, proto_tree *, guint16);
} algo_parameters_t;

/* Initialize the protocol and registered fields
*/
static int proto_sndcp_xid   = -1;

/* These fields are used to store store the algorithm ID
* When the P bit is not set, try to decode the algo based on what whas stored.
* Entity ranges from 0 to 31 (6.5.1.1.3)
*/
static guint8 dcomp_entity_algo_id[32]={-1, -1, -1, -1, -1, -1, -1, -1,
										-1, -1, -1, -1, -1, -1, -1, -1,
										-1, -1, -1, -1, -1, -1, -1, -1,
										-1, -1, -1, -1, -1, -1, -1, -1};
static guint8 pcomp_entity_algo_id[32]={-1, -1, -1, -1, -1, -1, -1, -1,
										-1, -1, -1, -1, -1, -1, -1, -1,
										-1, -1, -1, -1, -1, -1, -1, -1,
										-1, -1, -1, -1, -1, -1, -1, -1};



/* L3 XID parsing */
static int hf_sndcp_xid_type = -1;
static int hf_sndcp_xid_len = -1;
static int hf_sndcp_xid_value = -1;
static int hf_sndcp_xid_comp_pbit = -1;
static int hf_sndcp_xid_comp_spare_byte1 = -1;
static int hf_sndcp_xid_comp_entity = -1;
static int hf_sndcp_xid_comp_spare_byte2 = -1;
static int hf_sndcp_xid_comp_algo_id = -1;
static int hf_sndcp_xid_comp_len = -1;
/* There is currently a maximum of 15 DCOMP/PCOMP: 6.5.1.1.5 */
static int hf_sndcp_xid_comp[15] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_sndcp_xid_comp_spare = -1;

static int hf_element_applicable_nsapi_15 = -1;
static int hf_element_applicable_nsapi_14 = -1;
static int hf_element_applicable_nsapi_13 = -1;
static int hf_element_applicable_nsapi_12 = -1;
static int hf_element_applicable_nsapi_11 = -1;
static int hf_element_applicable_nsapi_10 = -1;
static int hf_element_applicable_nsapi_9 = -1;
static int hf_element_applicable_nsapi_8 = -1;
static int hf_element_applicable_nsapi_7 = -1;
static int hf_element_applicable_nsapi_6 = -1;
static int hf_element_applicable_nsapi_5 = -1;
static int hf_element_applicable_nsapi_spare = -1;

static int hf_sndcp_xid_rfc1144_s0 = -1;
static int hf_sndcp_xid_rfc2507_f_max_period_msb = -1;
static int hf_sndcp_xid_rfc2507_f_max_period_lsb = -1;
static int hf_sndcp_xid_rfc2507_f_max_time = -1;
static int hf_sndcp_xid_rfc2507_max_header = -1;
static int hf_sndcp_xid_rfc2507_tcp_space = -1;
static int hf_sndcp_xid_rfc2507_non_tcp_space_msb = -1;
static int hf_sndcp_xid_rfc2507_non_tcp_space_lsb = -1;
static int hf_sndcp_xid_rohc_max_cid_spare = -1;
static int hf_sndcp_xid_rohc_max_cid_msb = -1;
static int hf_sndcp_xid_rohc_max_cid_lsb = -1;
static int hf_sndcp_xid_rohc_max_header = -1;
static int hf_sndcp_xid_rohc_profile_msb = -1;
static int hf_sndcp_xid_rohc_profile_lsb = -1;

static int hf_sndcp_xid_V42bis_p0_spare = -1;
static int hf_sndcp_xid_V42bis_p0 = -1;
static int hf_sndcp_xid_V42bis_p1_msb = -1;
static int hf_sndcp_xid_V42bis_p1_lsb = -1;
static int hf_sndcp_xid_V42bis_p2 = -1;
static int hf_sndcp_xid_V44_c0 = -1;
static int hf_sndcp_xid_V44_c0_spare = -1;
static int hf_sndcp_xid_V44_p0_spare = -1;
static int hf_sndcp_xid_V44_p0 = -1;
static int hf_sndcp_xid_V44_p1t_msb = -1;
static int hf_sndcp_xid_V44_p1t_lsb = -1;
static int hf_sndcp_xid_V44_p1r_msb = -1;
static int hf_sndcp_xid_V44_p1r_lsb = -1;
static int hf_sndcp_xid_V44_p3t_msb = -1;
static int hf_sndcp_xid_V44_p3t_lsb = -1;
static int hf_sndcp_xid_V44_p3r_msb = -1;
static int hf_sndcp_xid_V44_p3r_lsb = -1;


/* Initialize the subtree pointers
*/
static gint ett_sndcp_xid                = -1;
static gint ett_sndcp_xid_version_field  = -1;
static gint ett_sndcp_comp_field        = -1;

static void parse_compression_parameters(tvbuff_t *tvb, proto_tree *tree, gboolean dcomp);
/******************************************************/
/* Compression algorithms element dissector functions */
/******************************************************/
static guint16 parse_applicable_nsapi(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 nsapi_byte1, nsapi_byte2;
	nsapi_byte1 = tvb_get_guint8(tvb, offset);
	nsapi_byte2 = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_element_applicable_nsapi_15, tvb, offset, 1, nsapi_byte1);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_14, tvb, offset, 1, nsapi_byte1);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_13, tvb, offset, 1, nsapi_byte1);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_12, tvb, offset, 1, nsapi_byte1);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_11, tvb, offset, 1, nsapi_byte1);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_10, tvb, offset, 1, nsapi_byte1);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_9, tvb, offset, 1, nsapi_byte1);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_8, tvb, offset, 1, nsapi_byte1);

	proto_tree_add_uint(tree, hf_element_applicable_nsapi_7, tvb, offset+1, 1, nsapi_byte2);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_6, tvb, offset+1, 1, nsapi_byte2);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_5, tvb, offset+1, 1, nsapi_byte2);
	proto_tree_add_uint(tree, hf_element_applicable_nsapi_spare, tvb, offset+1, 1, nsapi_byte2);

	return 2U;
}

static guint16 parse_rfc1144_s0(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 s0;
	s0 = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(tree, hf_sndcp_xid_rfc1144_s0, tvb, offset, 1, s0);

	return 1U;
}

static guint16 parse_rfc2507_f_max_period(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 f_max_period_byte1, f_max_period_byte2;
	f_max_period_byte1 = tvb_get_guint8(tvb, offset);
	f_max_period_byte2 = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_rfc2507_f_max_period_msb, tvb, offset, 1, f_max_period_byte1);
	proto_tree_add_uint(tree, hf_sndcp_xid_rfc2507_f_max_period_lsb, tvb, offset, 1, f_max_period_byte2);

	return 2U;
}

static guint16 parse_rfc2507_f_max_time(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 f_max_time;
	f_max_time = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(tree, hf_sndcp_xid_rfc2507_f_max_time, tvb, offset, 1, f_max_time);

	return 1U;
}

static guint16 parse_rfc2507_max_header(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 max_header;
	max_header = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(tree, hf_sndcp_xid_rfc2507_max_header, tvb, offset, 1, max_header);

	return 1U;
}

static guint16 parse_rfc2507_tcp_space(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 tcp_space;
	tcp_space = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(tree, hf_sndcp_xid_rfc2507_tcp_space, tvb, offset, 1, tcp_space);

	return 1U;
}

static guint16 parse_rfc2507_non_tcp_space(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 tcp_space_msb, tcp_space_lsb;
	tcp_space_msb = tvb_get_guint8(tvb, offset);
	tcp_space_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_rfc2507_non_tcp_space_msb, tvb, offset, 1, tcp_space_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_rfc2507_non_tcp_space_lsb, tvb, offset, 1, tcp_space_lsb);

	return 2U;
}

static guint16 parse_rohc_max_cid(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 max_cid_msb, max_cid_lsb;
	max_cid_msb = tvb_get_guint8(tvb, offset);
	max_cid_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_rohc_max_cid_spare, tvb, offset, 1, max_cid_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_rohc_max_cid_msb, tvb, offset, 1, max_cid_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_rohc_max_cid_lsb, tvb, offset+1, 1, max_cid_lsb);

	return 2U;
}
static guint16 parse_rohc_max_header(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 max_header;

	max_header = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_rohc_max_header, tvb, offset+1, 1, max_header);

	return 2U;
}

static guint16 parse_rohc_profile(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 profile_msb, profile_lsb;
	profile_msb = tvb_get_guint8(tvb, offset);
	profile_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_rohc_profile_msb, tvb, offset, 1, profile_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_rohc_profile_lsb, tvb, offset+1, 1, profile_lsb);

	return 2U;
}

static guint16 parse_V42bis_p0(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p0;

	p0 = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(tree, hf_sndcp_xid_V42bis_p0_spare, tvb, offset, 1, p0);
	proto_tree_add_uint(tree, hf_sndcp_xid_V42bis_p0, tvb, offset, 1, p0);

	return 1U;
}

static guint16 parse_V42bis_p1(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p1_msb, p1_lsb;

	p1_msb = tvb_get_guint8(tvb, offset);
	p1_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_V42bis_p1_msb, tvb, offset, 1, p1_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_V42bis_p1_lsb, tvb, offset+1, 1, p1_lsb);

	return 2U;
}

static guint16 parse_V42bis_p2(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p2;

	p2 = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(tree, hf_sndcp_xid_V42bis_p2, tvb, offset, 1, p2);

	return 1U;
}

static guint16 parse_V44_c0(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 c0;

	c0 = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_sndcp_xid_V44_c0_spare, tvb, offset, 1, c0);
	proto_tree_add_uint(tree, hf_sndcp_xid_V44_c0, tvb, offset, 1, c0);

	return 1U;
}

static guint16 parse_V44_p0(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p0;

	p0 = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p0_spare, tvb, offset, 1, p0);
	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p0, tvb, offset, 1, p0);

	return 1U;
}


static guint16 parse_V44_p1t(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p1t_msb, p1t_lsb;

	p1t_msb = tvb_get_guint8(tvb, offset);
	p1t_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p1t_msb, tvb, offset, 1, p1t_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p1t_lsb, tvb, offset+1, 1, p1t_lsb);

	return 2U;
}

static guint16 parse_V44_p1r(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p1r_msb, p1r_lsb;

	p1r_msb = tvb_get_guint8(tvb, offset);
	p1r_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p1r_msb, tvb, offset, 1, p1r_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p1r_lsb, tvb, offset+1, 1, p1r_lsb);

	return 2U;
}

static guint16 parse_V44_p3t(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p3t_msb, p3t_lsb;

	p3t_msb = tvb_get_guint8(tvb, offset);
	p3t_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p3t_msb, tvb, offset, 1, p3t_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p3t_lsb, tvb, offset+1, 1, p3t_lsb);

	return 2U;
}

static guint16 parse_V44_p3r(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
	guint8 p3r_msb, p3r_lsb;

	p3r_msb = tvb_get_guint8(tvb, offset);
	p3r_lsb = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p3r_msb, tvb, offset, 1, p3r_msb);
	proto_tree_add_uint(tree, hf_sndcp_xid_V44_p3r_lsb, tvb, offset+1, 1, p3r_lsb);

	return 2U;
}


/***************************************************/
/* Compression algorithms element dissector arrays */
/***************************************************/
static guint16 (*rfc1144_elem_fcn[])(tvbuff_t *, proto_tree *, guint16) = {
    parse_applicable_nsapi,
	parse_rfc1144_s0,
	NULL
};


static guint16 (*rfc2507_elem_fcn[])(tvbuff_t *, proto_tree *, guint16) = {
	parse_applicable_nsapi,
	parse_rfc2507_f_max_period,
	parse_rfc2507_f_max_time,
	parse_rfc2507_max_header,
	parse_rfc2507_tcp_space,
	parse_rfc2507_non_tcp_space,
	NULL
};

static guint16 (*rohc_elem_fcn[])(tvbuff_t *, proto_tree *, guint16) = {
	parse_applicable_nsapi,
	parse_rohc_max_cid,
	parse_rohc_max_header,
	parse_rohc_profile, /* Profile 1 */
	parse_rohc_profile, /* Profile 2 */
	parse_rohc_profile, /* Profile 3 */
	parse_rohc_profile, /* Profile 4 */
	parse_rohc_profile, /* Profile 5 */
	parse_rohc_profile, /* Profile 6 */
	parse_rohc_profile, /* Profile 7 */
	parse_rohc_profile, /* Profile 8 */
	parse_rohc_profile, /* Profile 9 */
	parse_rohc_profile, /* Profile 10 */
	parse_rohc_profile, /* Profile 11 */
	parse_rohc_profile, /* Profile 12 */
	parse_rohc_profile, /* Profile 13 */
	parse_rohc_profile, /* Profile 14 */
	parse_rohc_profile, /* Profile 15 */
	parse_rohc_profile, /* Profile 16 */
	NULL
};

/* Array containing the number of pcomp and the function array pointer */
static algo_parameters_t pcomp_algo_pars[] = {
	{2, rfc1144_elem_fcn},
	{5, rfc2507_elem_fcn},
	{2, rohc_elem_fcn}
};

/* Data compression algorithms */

static guint16 (*v42bis_elem_fcn[])(tvbuff_t *, proto_tree *, guint16) = {
	parse_applicable_nsapi,
	parse_V42bis_p0,
	parse_V42bis_p1,
	parse_V42bis_p2,
	NULL
};

static guint16 (*v44_elem_fcn[])(tvbuff_t *, proto_tree *, guint16) = {
	parse_applicable_nsapi,
	parse_V44_c0,
	parse_V44_p0,
	parse_V44_p1t,
	parse_V44_p1r,
	parse_V44_p3t,
	parse_V44_p3r,
	NULL
};

/* Array containing the number of dcomp and the function array pointer */
static algo_parameters_t dcomp_algo_pars[] = {
	{1, v42bis_elem_fcn},
	{2, v44_elem_fcn},

};

/* Code to actually dissect the packets
*/
static void
dissect_sndcp_xid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it
	*/
	proto_item *ti, *version_item, *dcomp_item, *pcomp_item;
	proto_tree *sndcp_tree, *version_tree, *dcomp_tree, *pcomp_tree;
	guint16 offset = 0, l3_param_len;
	guint8 parameter_type, parameter_len;

	/* create display subtree for the protocol
	*/
	ti = proto_tree_add_item(tree, proto_sndcp_xid, tvb, 0, -1, ENC_NA);
	sndcp_tree = proto_item_add_subtree(ti, ett_sndcp_xid);
	l3_param_len = tvb_reported_length(tvb);

	while (offset < l3_param_len-1)
	{
		parameter_type = tvb_get_guint8(tvb, offset);
		parameter_len = tvb_get_guint8(tvb, offset+1);

		if (parameter_type == SNDCP_VERSION_PAR_TYPE)
		{
			guint8 value = tvb_get_guint8(tvb, offset+2);
			version_item = proto_tree_add_text(sndcp_tree, tvb, offset, parameter_len+2,
					"Version (SNDCP version number) - Value %d", value);

			version_tree = proto_item_add_subtree(version_item, ett_sndcp_xid_version_field);
			proto_tree_add_uint(version_tree, hf_sndcp_xid_type, tvb, offset,
			1, parameter_type);
			proto_tree_add_uint(version_tree, hf_sndcp_xid_len, tvb, offset+1,
			1, parameter_len);
			proto_tree_add_uint(version_tree, hf_sndcp_xid_value, tvb, offset+2,
			1, value);
			offset += 3;
		}

		else if (parameter_type == DATA_COMPRESSION_PAR_TYPE)
		{
			tvbuff_t * dcomp_tvb;

			dcomp_item = proto_tree_add_text(sndcp_tree, tvb, offset, parameter_len+2,
				"Data Compression");
			dcomp_tree = proto_item_add_subtree(dcomp_item, ett_sndcp_comp_field);
			proto_tree_add_uint(dcomp_tree, hf_sndcp_xid_type, tvb, offset,
			1, parameter_type);
			proto_tree_add_uint(dcomp_tree, hf_sndcp_xid_len, tvb, offset+1,
			1, parameter_len);
			offset += 2;

			dcomp_tvb = tvb_new_subset(tvb, offset, parameter_len, parameter_len);
			parse_compression_parameters(dcomp_tvb, dcomp_tree, TRUE);
			offset += parameter_len;


		}
		else if (parameter_type == PROTOCOL_COMPRESSION_PAR_TYPE)
		{
			tvbuff_t * pcomp_tvb;

			pcomp_item = proto_tree_add_text(sndcp_tree, tvb, offset, parameter_len+2,
				"Protocol Control Information Compression");
			pcomp_tree = proto_item_add_subtree(pcomp_item, ett_sndcp_comp_field);
			proto_tree_add_uint(pcomp_tree, hf_sndcp_xid_type, tvb, offset,
			1, parameter_type);
			proto_tree_add_uint(pcomp_tree, hf_sndcp_xid_len, tvb, offset+1,
			1, parameter_len);
			offset += 2;

			pcomp_tvb = tvb_new_subset(tvb, offset, parameter_len, parameter_len);
			parse_compression_parameters(pcomp_tvb, pcomp_tree, FALSE);
			offset += parameter_len;

		}
		else
		{
			break; /* error: exit */
		}
	}
}


static void parse_compression_parameters(tvbuff_t *tvb, proto_tree *tree, gboolean dcomp)
{
	guint8 entity, len, algo_id;
	guint8 number_of_comp, i;
	gboolean p_bit_set;
	algo_parameters_t * algo_pars;
	guint8 function_index;
	proto_item *comp_entity_field = NULL;
	proto_tree *comp_entity_tree = NULL;
	guint16 tvb_len, offset=0 , new_offset, entity_offset;
	value_string const * comp_algo_str;

	tvb_len = tvb_reported_length(tvb);
	if (tvb_len < 3) return; /* entity, algo and length bytes should always be present 6.5.1.1 and 6.6.1.1 */

	/* Loop to decode each entity (cf Figure 10) */
	while (offset < tvb_len)
	{
		/* Read the entity byte */
		entity = tvb_get_guint8(tvb, offset);
		p_bit_set = ((entity & 0x80) == 0x80) ? 1 : 0;
		entity = entity & 0x1F;

		/* P bit is set: means that algo identifier and dcomp are present */
		if (p_bit_set)
		{
			/* Read the algorithm id. TODO: store the algo in a different variable for each different entity */
			algo_id = tvb_get_guint8(tvb, offset+1) & 0x1F;

			/* sanity check: check that the algo id that will be used inside the array has a valid range */
			if (dcomp)
			{
				if(algo_id <= ALGO_V44)
				{
					algo_pars = dcomp_algo_pars;
					dcomp_entity_algo_id[entity] = algo_id;
					comp_algo_str = sndcp_xid_dcomp_algo_str;
				}
				else return;
			}
			else
			{
				if (algo_id <= ALGO_ROHC)
				{
					algo_pars = pcomp_algo_pars;
					pcomp_entity_algo_id[entity] = algo_id;
					comp_algo_str = sndcp_xid_pcomp_algo_str;
				}
				else return;
			}

			/* Read the length */
			len = tvb_get_guint8(tvb, offset+2);

			comp_entity_field = proto_tree_add_text(tree, tvb, offset, len + 3,
				"Entity %d, Algorithm %s",
				entity & 0x1F, val_to_str(algo_id & 0x1F, comp_algo_str,"Undefined Algorithm Identifier:%X"));
			comp_entity_tree = proto_item_add_subtree(comp_entity_field, ett_sndcp_comp_field);

			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_pbit, tvb, offset, 1, p_bit_set << 7);
			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_spare_byte1, tvb, offset, 1, entity);
			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_entity, tvb, offset, 1, entity);

			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_spare_byte2, tvb, offset+1, 1, algo_id);
			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_algo_id, tvb, offset+1, 1, algo_id);
			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_len, tvb, offset+2, 1, len);

			/* Read the dcomp/pcomp field */
			offset += 3; /* entity_offset will be used as the offset from length byte */
			number_of_comp = algo_pars[algo_id].nb_of_dcomp_pcomp;

			for (i=0; i < (number_of_comp+1) / 2; i++)
			{
				guint8 byte;

				byte = tvb_get_guint8(tvb, offset+i);
				proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp[2*i], tvb, offset+i, 1, byte);

				/* if there is an even number of dcomp/pcomp */
				if (2*i+1 < number_of_comp)
				{
					proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp[2*i+1], tvb, offset+i, 1, byte);
				}
				/* else there is padding in the end */
				else
				{
					proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_spare, tvb, offset+i, 1, byte);
				}

			}
			entity_offset = i;
			function_index = 0;

			/* Process the elements byte per byte */
			while ((entity_offset < len) && (algo_pars[algo_id].func_array_ptr[function_index] != NULL))
			{
				new_offset = offset+entity_offset;
				entity_offset += algo_pars[algo_id].func_array_ptr[function_index](tvb, comp_entity_tree, new_offset);
				function_index++;
			}
			offset += entity_offset;

		}
		else /* P bit not set */
		{
			len = tvb_get_guint8(tvb, offset+1);

			if (dcomp)
			{
				algo_pars = dcomp_algo_pars;
				algo_id = dcomp_entity_algo_id[entity];
				comp_algo_str = sndcp_xid_dcomp_algo_str;
			}
			else
			{
				algo_pars = pcomp_algo_pars;
				algo_id = pcomp_entity_algo_id[entity];
				comp_algo_str = sndcp_xid_pcomp_algo_str;
			}
			comp_entity_field = proto_tree_add_text(tree, tvb, offset, len + 2,
				"Entity %d decoded as Algorithm %s",
				entity & 0x1F, val_to_str(algo_id & 0x1F, comp_algo_str,"Undefined Algorithm Identifier:%X"));

			comp_entity_tree = proto_item_add_subtree(comp_entity_field, ett_sndcp_comp_field);

			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_pbit, tvb, offset, 1, p_bit_set << 7);
			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_spare_byte1, tvb, offset, 1, entity);
			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_entity, tvb, offset, 1, entity);
			proto_tree_add_uint(comp_entity_tree, hf_sndcp_xid_comp_len, tvb, offset+2, 1, len);

			offset += 2;
			entity_offset = 0;
			function_index = 0;

			if (dcomp)
			{
				if (algo_id > ALGO_V44) return;
			}
			else
			{
				if (algo_id > ALGO_ROHC) return;
			}

			/* Process the elements byte per byte */
			while ((entity_offset < len) && (algo_pars[algo_id].func_array_ptr[function_index] != NULL))
			{
				new_offset = offset+entity_offset;
				entity_offset += algo_pars[algo_id].func_array_ptr[function_index](tvb, comp_entity_tree, new_offset);
				function_index++;
			}
			offset += entity_offset;
		}
	}

	/* Else if length is lower than 3, the packet is not correctly formatted */
}

/* Register the protocol with Wireshark
   this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_sndcp_xid(void)
{
  /* Setup list of header fields
   */
	static hf_register_info hf[] = {
		/* L3 XID Parameter Parsing Info */
		{&hf_sndcp_xid_type,
				{ "Parameter type","llcgprs.l3xidpartype", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
		{&hf_sndcp_xid_len,
				{ "Length","llcgprs.l3xidparlen", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
		{&hf_sndcp_xid_value,
				{ "Value","llcgprs.l3xidparvalue", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
		{&hf_sndcp_xid_comp_pbit,
				{ "P bit","llcgprs.l3xiddcomppbit", FT_UINT8, BASE_DEC, NULL, 0x80, "Data", HFILL}},
		{&hf_sndcp_xid_comp_spare_byte1,
				{ "Spare","llcgprs.l3xidspare", FT_UINT8, BASE_HEX, NULL, 0x60, "Ignore", HFILL}},
		{&hf_sndcp_xid_comp_entity,
				{ "Entity","llcgprs.l3xidentity", FT_UINT8, BASE_DEC, NULL, 0x1F, "Data", HFILL}},
		{&hf_sndcp_xid_comp_spare_byte2,
				{ "Spare","llcgprs.l3xidspare", FT_UINT8, BASE_HEX, NULL, 0xE0, "Ignore", HFILL}},
		{&hf_sndcp_xid_comp_algo_id,
				{ "Algorithm identifier","llcgprs.l3xidalgoid", FT_UINT8, BASE_DEC, NULL, 0x1F, "Data", HFILL}},
		{&hf_sndcp_xid_comp_len,
				{ "Length","llcgprs.l3xidcomplen", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
		{&hf_sndcp_xid_comp[0],
				{ "DCOMP1","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp[1],
				{ "DCOMP2","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0x0F, "Data", HFILL}},
		{&hf_sndcp_xid_comp[2],
				{ "DCOMP3","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp[3],
				{ "DCOMP4","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0x0F, "Data", HFILL}},
		{&hf_sndcp_xid_comp[4],
				{ "DCOMP5","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp[5],
				{ "DCOMP6","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0x0F, "Data", HFILL}},
		{&hf_sndcp_xid_comp[6],
				{ "DCOMP7","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp[7],
				{ "DCOMP8","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0x0F, "Data", HFILL}},
		{&hf_sndcp_xid_comp[8],
				{ "DCOMP9","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp[9],
				{ "DCOMP10","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0x0F, "Data", HFILL}},
		{&hf_sndcp_xid_comp[10],
				{ "DCOMP11","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp[11],
				{ "DCOMP12","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0x0F, "Data", HFILL}},
		{&hf_sndcp_xid_comp[12],
				{ "DCOMP13","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp[13],
				{ "DCOMP14","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0x0F, "Data", HFILL}},
		{&hf_sndcp_xid_comp[14],
				{ "DCOMP15","llcgprs.l3xiddcomp", FT_UINT8, BASE_DEC, NULL, 0xF0, "Data", HFILL}},
		{&hf_sndcp_xid_comp_spare,
				{ "Spare","llcgprs.l3xidspare", FT_UINT8, BASE_HEX, NULL, 0x0F, "Ignore", HFILL}},
 		{&hf_element_applicable_nsapi_15,
				{ "NSAPI 15","sndcpxid.nsapi15", FT_UINT8, BASE_DEC, NULL, 0x80, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_14,
				{ "NSAPI 14","sndcpxid.nsapi14", FT_UINT8, BASE_DEC, NULL, 0x40, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_13,
				{ "NSAPI 13","sndcpxid.nsapi13", FT_UINT8, BASE_DEC, NULL, 0x20, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_12,
				{ "NSAPI 12","sndcpxid.nsapi12", FT_UINT8, BASE_DEC, NULL, 0x10, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_11,
				{ "NSAPI 11","sndcpxid.nsapi11", FT_UINT8, BASE_DEC, NULL, 0x08, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_10,
				{ "NSAPI 10","sndcpxid.nsapi10", FT_UINT8, BASE_DEC, NULL, 0x04, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_9,
				{ "NSAPI 9","sndcpxid.nsapi9", FT_UINT8, BASE_DEC, NULL, 0x02, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_8,
				{ "NSAPI 8","sndcpxid.nsapi8", FT_UINT8, BASE_DEC, NULL, 0x01, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_7,
				{ "NSAPI 7","sndcpxid.nsapi7", FT_UINT8, BASE_DEC, NULL, 0x80, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_6,
				{ "NSAPI 6","sndcpxid.nsapi6", FT_UINT8, BASE_DEC, NULL, 0x40, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_5,
				{ "NSAPI 5","sndcpxid.nsapi5", FT_UINT8, BASE_DEC, NULL, 0x20, "Data", HFILL}},
 		{&hf_element_applicable_nsapi_spare,
				{ "Spare","sndcpxid.spare", FT_UINT8, BASE_DEC, NULL, 0x1F, "Ignore", HFILL}},
 		{&hf_sndcp_xid_rfc1144_s0,
				{ "S0 - 1","sndcpxid.rfc1144_s0", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rfc2507_f_max_period_msb,
				{ "F Max Period MSB","sndcpxid.rfc2507_f_max_period_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rfc2507_f_max_period_lsb,
				{ "F Max Period LSB","sndcpxid.rfc2507_f_max_period_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rfc2507_f_max_time,
				{ "F Max Time","sndcpxid.rfc2507_f_max_time", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rfc2507_max_header,
				{ "Max Header","sndcpxid.rfc2507_max_header", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rfc2507_tcp_space,
				{ "TCP Space","sndcpxid.rfc2507_max_tcp_space", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rfc2507_non_tcp_space_msb,
				{ "TCP non space MSB","sndcpxid.rfc2507_max_non_tcp_space_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rfc2507_non_tcp_space_lsb,
				{ "TCP non space LSB","sndcpxid.rfc2507_max_non_tcp_space_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rohc_max_cid_spare,
				{ "Spare","sndcpxid.rohc_max_cid_spare", FT_UINT8, BASE_DEC, NULL, 0xC0, "Ignore", HFILL}},
 		{&hf_sndcp_xid_rohc_max_cid_msb,
				{ "Max CID MSB","sndcpxid.rohc_max_cid_msb", FT_UINT8, BASE_HEX, NULL, 0x3F, "Data", HFILL}},
 		{&hf_sndcp_xid_rohc_max_cid_lsb,
				{ "Max CID LSB","sndcpxid.rohc_max_cid_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rohc_max_header,
				{ "Max header","sndcpxid.rohc_max_header", FT_UINT8, BASE_DEC, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rohc_profile_msb,
				{ "Profile MSB","sndcpxid.rohc_profile_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_rohc_profile_lsb,
				{ "Profile LSB","sndcpxid.rohc_profile_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V42bis_p0_spare,
				{ "Spare","sndcpxid.V42bis_p0spare", FT_UINT8, BASE_DEC, NULL, 0xFC, "Ignore", HFILL}},
 		{&hf_sndcp_xid_V42bis_p0,
				{ "P0","sndcpxid.V42bis_p0", FT_UINT8, BASE_HEX, NULL, 0x03, "Data", HFILL}},
 		{&hf_sndcp_xid_V42bis_p1_msb,
				{ "P1 MSB","sndcpxid.V42bis_p1_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V42bis_p1_lsb,
				{ "P1 LSB","sndcpxid.V42bis_p1_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V42bis_p2,
				{ "P2","sndcpxid.V42bis_p2", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_c0_spare,
				{ "P2","sndcpxid.V44_c0_spare", FT_UINT8, BASE_HEX, NULL, 0x3F, "Ignore", HFILL}},
 		{&hf_sndcp_xid_V44_c0,
				{ "P2","sndcpxid.V44_c0", FT_UINT8, BASE_HEX, NULL, 0xC0, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p0_spare,
				{ "Spare","sndcpxid.V44_p0spare", FT_UINT8, BASE_DEC, NULL, 0xFC, "Ignore", HFILL}},
 		{&hf_sndcp_xid_V44_p0,
				{ "P0","sndcpxid.V44_p0", FT_UINT8, BASE_HEX, NULL, 0x03, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p1t_msb,
				{ "P1t MSB","sndcpxid.V44_p1t_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p1t_lsb,
				{ "P1t LSB","sndcpxid.V44_p1t_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p1r_msb,
				{ "P1r MSB","sndcpxid.V44_p1r_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p1r_lsb,
				{ "P1r LSB","sndcpxid.V44_p1r_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p3t_msb,
				{ "P3t MSB","sndcpxid.V44_p3t_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p3t_lsb,
				{ "P3t LSB","sndcpxid.V44_p3t_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p3r_msb,
				{ "P3r MSB","sndcpxid.V44_p3r_msb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
 		{&hf_sndcp_xid_V44_p3r_lsb,
				{ "P3r LSB","sndcpxid.V44_p3r_lsb", FT_UINT8, BASE_HEX, NULL, 0xFF, "Data", HFILL}},
	};

   /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sndcp_xid,
    &ett_sndcp_xid_version_field,
    &ett_sndcp_comp_field
  };

  /* Register the protocol name and description */
  proto_sndcp_xid = proto_register_protocol("Subnetwork Dependent Convergence Protocol XID",
					"SNDCP XID", "sndcpxid");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sndcp_xid, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("sndcpxid", dissect_sndcp_xid, proto_sndcp_xid);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_sndcp_xid(void)
{
}
