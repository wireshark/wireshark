/* packet-ipv6.c
 * Routines for IPv6 packet disassembly
 *
 * $Id: packet-ipv6.c,v 1.79 2002/03/27 04:27:03 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_h
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-ip.h"
#include "packet-ipsec.h"
#include "packet-ipv6.h"
#include <epan/resolv.h>
#include "prefs.h"
#include "reassemble.h"
#include "ipproto.h"
#include "etypes.h"
#include "ppptypes.h"
#include "aftypes.h"
#include "nlpid.h"

/*
 * NOTE: ipv6.nxt is not very useful as we will have chained header.
 * now testing ipv6.final, but it raises SEGV.
#define TEST_FINALHDR
 */

static int proto_ipv6 = -1;
static int hf_ipv6_version = -1;
static int hf_ipv6_class = -1;
static int hf_ipv6_flow = -1;
static int hf_ipv6_plen = -1;
static int hf_ipv6_nxt = -1;
static int hf_ipv6_hlim = -1;
static int hf_ipv6_src = -1;
static int hf_ipv6_dst = -1;
static int hf_ipv6_addr = -1;
#ifdef TEST_FINALHDR
static int hf_ipv6_final = -1;
#endif
static int hf_ipv6_fragments = -1;
static int hf_ipv6_fragment = -1;
static int hf_ipv6_fragment_overlap = -1;
static int hf_ipv6_fragment_overlap_conflict = -1;
static int hf_ipv6_fragment_multiple_tails = -1;
static int hf_ipv6_fragment_too_long_fragment = -1;
static int hf_ipv6_fragment_error = -1;

static int hf_ipv6_mipv6_type = -1;
static int hf_ipv6_mipv6_length = -1;
static int hf_ipv6_mipv6_a_flag = -1;
static int hf_ipv6_mipv6_h_flag = -1;
static int hf_ipv6_mipv6_r_flag = -1;
static int hf_ipv6_mipv6_d_flag = -1;
static int hf_ipv6_mipv6_m_flag = -1;
static int hf_ipv6_mipv6_b_flag = -1;
static int hf_ipv6_mipv6_prefix_length = -1;
static int hf_ipv6_mipv6_sequence_number = -1;
static int hf_ipv6_mipv6_life_time = -1;
static int hf_ipv6_mipv6_status = -1;
static int hf_ipv6_mipv6_refresh = -1;
static int hf_ipv6_mipv6_home_address = -1;
static int hf_ipv6_mipv6_sub_type = -1;
static int hf_ipv6_mipv6_sub_length = -1;
static int hf_ipv6_mipv6_sub_unique_ID = -1;
static int hf_ipv6_mipv6_sub_alternative_COA = -1;

static gint ett_ipv6 = -1;
static gint ett_ipv6_fragments = -1;
static gint ett_ipv6_fragment  = -1;

static dissector_handle_t data_handle;

/* Reassemble fragmented datagrams */
static gboolean ipv6_reassemble = FALSE;

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

/*
 * defragmentation of IPv6
 */
static GHashTable *ipv6_fragment_table = NULL;

static void
ipv6_reassemble_init(void)
{
  fragment_table_init(&ipv6_fragment_table);
}

static int
dissect_routing6(tvbuff_t *tvb, int offset, proto_tree *tree) {
    struct ip6_rthdr rt;
    guint len;
    proto_tree *rthdr_tree;
	proto_item *ti;
    char buf[sizeof(struct ip6_rthdr0) + sizeof(struct e_in6_addr) * 23];

    tvb_memcpy(tvb, (guint8 *)&rt, offset, sizeof(rt));
    len = (rt.ip6r_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, tvb, offset, len,
	    "Routing Header, Type %u", rt.ip6r_type);
	rthdr_tree = proto_item_add_subtree(ti, ett_ipv6);

	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_nxt), 1,
	    "Next header: %s (0x%02x)", ipprotostr(rt.ip6r_nxt), rt.ip6r_nxt);
	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_len), 1,
	    "Length: %u (%d bytes)", rt.ip6r_len, len);
	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_type), 1,
	    "Type: %u", rt.ip6r_type);
	proto_tree_add_text(rthdr_tree, tvb,
	    offset + offsetof(struct ip6_rthdr, ip6r_segleft), 1,
	    "Segments left: %u", rt.ip6r_segleft);

	if (rt.ip6r_type == 0 && len <= sizeof(buf)) {
	    struct e_in6_addr *a;
	    int n;
	    struct ip6_rthdr0 *rt0;

	    tvb_memcpy(tvb, buf, offset, len);
	    rt0 = (struct ip6_rthdr0 *)buf;
	    for (a = rt0->ip6r0_addr, n = 0;
		 a < (struct e_in6_addr *)(buf + len);
		 a++, n++) {
		proto_tree_add_text(rthdr_tree, tvb,
		    offset + offsetof(struct ip6_rthdr0, ip6r0_addr) + n * sizeof(struct e_in6_addr),
		    sizeof(struct e_in6_addr),
#ifdef INET6
		    "address %d: %s (%s)",
		    n, get_hostname6(a), ip6_to_str(a)
#else
		    "address %d: %s", n, ip6_to_str(a)
#endif
		    );
	    }
	}

	/* decode... */
    }

    return len;
}

static int
dissect_frag6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    guint16 *offlg, guint32 *ident) {
    struct ip6_frag frag;
    int len;
    proto_item *ti;
    proto_tree *rthdr_tree;

    tvb_memcpy(tvb, (guint8 *)&frag, offset, sizeof(frag));
    len = sizeof(frag);
    frag.ip6f_offlg = ntohs(frag.ip6f_offlg);
    *offlg = frag.ip6f_offlg;
    *ident = frag.ip6f_ident;
    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO,
	    "IPv6 fragment (nxt=%s (0x%02x) off=%u id=0x%x)",
	    ipprotostr(frag.ip6f_nxt), frag.ip6f_nxt,
	    frag.ip6f_offlg & IP6F_OFF_MASK, frag.ip6f_ident);
    }
    if (tree) {
	   ti = proto_tree_add_text(tree, tvb, offset, len,
			   "Fragmention Header");
	   rthdr_tree = proto_item_add_subtree(ti, ett_ipv6);

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_nxt), 1,
			 "Next header: %s (0x%02x)",
			 ipprotostr(frag.ip6f_nxt), frag.ip6f_nxt);

#if 0
	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_reserved), 1,
			 "Reserved: %u",
			 frag.ip6f_reserved);
#endif

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_offlg), 2,
			 "Offset: %u",
			 frag.ip6f_offlg & IP6F_OFF_MASK);

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_offlg), 2,
			 "More fragments: %s",
				frag.ip6f_offlg & IP6F_MORE_FRAG ?
				"Yes" : "No");

	   proto_tree_add_text(rthdr_tree, tvb,
			 offset + offsetof(struct ip6_frag, ip6f_ident), 4,
			 "Identification: 0x%08x",
			 frag.ip6f_ident);
    }
    return len;
}

/* Binding Update flag description */
static const true_false_string ipv6_mipv6_bu_a_flag_value = {
    "Binding Acknowledgement requested",
    "Binding Acknowledgement not requested"
};
static const true_false_string ipv6_mipv6_bu_h_flag_value = {
    "Home Registration",
    "No Home Registration"
};
static const true_false_string ipv6_mipv6_bu_r_flag_value = {
    "Router",
    "Not a Router"
};
static const true_false_string ipv6_mipv6_bu_d_flag_value = {
    "Perform Duplicate Address Detection",
    "Do not perform Duplicate Address Detection"
};
static const true_false_string ipv6_mipv6_bu_m_flag_value = {
    "MAP Registration",
    "No MAP Registration"
};
static const true_false_string ipv6_mipv6_bu_b_flag_value = {
    "Request for bicasting",
    "Do not request for bicasting"
};

static int
dissect_mipv6_ba(tvbuff_t *tvb, proto_tree *dstopt_tree, int offset)
{
    guint8 status, len = 0;
    const char *status_text;
    gboolean sub_options = FALSE;

    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_type, tvb,
	offset + len, IP6_MIPv6_OPTION_TYPE_LENGTH,
	tvb_get_guint8(tvb, offset + len),
	"Option Type: %u (0x%02x) - Binding Acknowledgement",
	tvb_get_guint8(tvb, offset + len),
    tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_OPTION_TYPE_LENGTH;
    if (tvb_get_guint8(tvb, offset + len) > 11)
	sub_options = TRUE;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_length, tvb, offset + len,
	IP6_MIPv6_OPTION_LENGTH_LENGTH, tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_OPTION_LENGTH_LENGTH;
    status = tvb_get_guint8(tvb, offset + len);
    switch (status) {
    case BA_OK:
	status_text = "- Binding Update accepted";
	break;
    case BA_REAS_UNSPEC:
	status_text = "- Binding Update was rejected - Reason unspecified";
	break;
    case BA_ADMIN_PROH:
	status_text = "- Binding Update was rejected - Administratively prohibited";
	break;
    case BA_INSUF_RES:
	status_text = "- Binding Update was rejected - Insufficient resources";
	break;
    case BA_NO_HR:
	status_text = "- Binding Update was rejected - Home registration not supported";
	break;
    case BA_NO_SUBNET:
	status_text = "- Binding Update was rejected - Not home subnet";
	break;
    case BA_ERR_ID_LEN:
	status_text = "- Binding Update was rejected - Incorrect interface identifier length";
	break;
    case BA_NO_HA:
	status_text = "- Binding Update was rejected - Not home agent for this mobile node";
	break;
    case BA_DUPL_ADDR:
	status_text = "- Binding Update was rejected - Duplicate Address Detection failed";
	break;
    default:
	status_text = NULL;
	break;
    }
    if (!status_text) {
	if (status > 128)
	    status_text = "- Binding Update was rejected";
	else
	    status_text = "";
    }
    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_status,
	tvb, offset + len, IP6_MIPv6_STATUS_LENGTH,
	tvb_get_guint8(tvb, offset + len),
	"Status: %u %s", tvb_get_guint8(tvb, offset + len), status_text);
    len += IP6_MIPv6_STATUS_LENGTH;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_sequence_number,
	tvb, offset + len, IP6_MIPv6_SEQUENCE_NUMBER_LENGTH,
	tvb_get_ntohs(tvb, offset + len));
    len += IP6_MIPv6_SEQUENCE_NUMBER_LENGTH;
    if (tvb_get_ntohl(tvb, offset + len) == 0xffffffff) {
	proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_life_time,
	    tvb, offset + len, IP6_MIPv6_LIFE_TIME_LENGTH,
	    tvb_get_ntohl(tvb, offset + len),
	    "Life Time: %u - Infinity", tvb_get_ntohl(tvb, offset + len));
    } else {
	proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_life_time,
	    tvb, offset + len, IP6_MIPv6_LIFE_TIME_LENGTH,
	    tvb_get_ntohl(tvb, offset + len));
    }
    len += IP6_MIPv6_LIFE_TIME_LENGTH;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_refresh, tvb,
	offset + len, IP6_MIPv6_REFRESH_LENGTH,
	tvb_get_ntohl(tvb, offset + len));
    len += IP6_MIPv6_REFRESH_LENGTH;
    /* sub - options */
    if (sub_options)
	proto_tree_add_text(dstopt_tree, tvb, offset + len, 1, "Sub-Options");
    return len;
}

static int
dissect_mipv6_bu(tvbuff_t *tvb, proto_tree *dstopt_tree, int offset)
{
    int len = 0;
    gboolean sub_options = FALSE;

    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_type, tvb, offset,
	IP6_MIPv6_OPTION_TYPE_LENGTH, tvb_get_guint8(tvb, offset),
	"Option Type: %u (0x%02x) - Binding Update",
	tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset));
    len += IP6_MIPv6_OPTION_TYPE_LENGTH;
    if (tvb_get_guint8(tvb, offset + len) > 8)
	sub_options = TRUE;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_length, tvb, offset + len,
	IP6_MIPv6_OPTION_LENGTH_LENGTH, tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_OPTION_LENGTH_LENGTH;
    proto_tree_add_boolean(dstopt_tree, hf_ipv6_mipv6_a_flag, tvb, offset + len,
	IP6_MIPv6_FLAGS_LENGTH, tvb_get_guint8(tvb, offset + len));
    proto_tree_add_boolean(dstopt_tree, hf_ipv6_mipv6_h_flag, tvb, offset + len,
	IP6_MIPv6_FLAGS_LENGTH, tvb_get_guint8(tvb, offset + len));
    proto_tree_add_boolean(dstopt_tree, hf_ipv6_mipv6_r_flag, tvb, offset + len,
	IP6_MIPv6_FLAGS_LENGTH, tvb_get_guint8(tvb, offset + len));
    proto_tree_add_boolean(dstopt_tree, hf_ipv6_mipv6_d_flag, tvb, offset + len,
	IP6_MIPv6_FLAGS_LENGTH, tvb_get_guint8(tvb, offset + len));
    proto_tree_add_boolean(dstopt_tree, hf_ipv6_mipv6_m_flag, tvb, offset + len,
	IP6_MIPv6_FLAGS_LENGTH, tvb_get_guint8(tvb, offset + len));
    proto_tree_add_boolean(dstopt_tree, hf_ipv6_mipv6_b_flag, tvb, offset + len,
	IP6_MIPv6_FLAGS_LENGTH, tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_FLAGS_LENGTH;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_prefix_length, tvb,
	offset + len,
	IP6_MIPv6_PREFIX_LENGTH_LENGTH, tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_PREFIX_LENGTH_LENGTH;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_sequence_number, tvb,
	offset + len, IP6_MIPv6_SEQUENCE_NUMBER_LENGTH,
	tvb_get_ntohs(tvb, offset + len));
    len += IP6_MIPv6_SEQUENCE_NUMBER_LENGTH;
    if (tvb_get_ntohl(tvb, offset + len) == 0xffffffff) {
    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_life_time, tvb,
	offset + len, IP6_MIPv6_LIFE_TIME_LENGTH,
	tvb_get_ntohl(tvb, offset + len), "Life Time: %u - Infinity",
	tvb_get_ntohl(tvb, offset + len));
    } else {
	proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_life_time, tvb,
	    offset + len, IP6_MIPv6_LIFE_TIME_LENGTH, tvb_get_ntohl(tvb,
	    offset + len));
    }
    len += IP6_MIPv6_LIFE_TIME_LENGTH;
    /* sub - options */
    if (sub_options)
	proto_tree_add_text(dstopt_tree, tvb, offset + len, 1, "Sub-Options");
    return len;
}

static int
dissect_mipv6_ha(tvbuff_t *tvb, proto_tree *dstopt_tree, int offset)
{
    int len = 0;
    gboolean sub_options = FALSE;

    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_type, tvb,
	offset + len, IP6_MIPv6_OPTION_TYPE_LENGTH,
	tvb_get_guint8(tvb, offset + len),
	"Option Type: %u (0x%02x) - Home Address",
	tvb_get_guint8(tvb, offset + len), tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_OPTION_TYPE_LENGTH;
    if (tvb_get_guint8(tvb, offset + len) > 16)
	sub_options = TRUE;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_length, tvb, offset + len,
	IP6_MIPv6_OPTION_LENGTH_LENGTH, tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_OPTION_LENGTH_LENGTH;
    proto_tree_add_ipv6(dstopt_tree, hf_ipv6_mipv6_home_address, tvb,
	offset + len, IP6_MIPv6_HOME_ADDRESS_LENGTH,
	tvb_get_ptr(tvb, offset + len, IP6_MIPv6_HOME_ADDRESS_LENGTH));
    len += IP6_MIPv6_HOME_ADDRESS_LENGTH;
    /* sub - options */
    if (sub_options)
	proto_tree_add_text(dstopt_tree, tvb, offset + len, 1, "Sub-Options");
    return len;
}

static int
dissect_mipv6_br(tvbuff_t *tvb, proto_tree *dstopt_tree, int offset)
{
    int len = 0;
    gboolean sub_options = FALSE;

    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_type, tvb,
	offset + len, IP6_MIPv6_OPTION_TYPE_LENGTH,
	tvb_get_guint8(tvb, offset + len),
	"Option Type: %u (0x%02x) - Binding Request",
	tvb_get_guint8(tvb, offset + len), tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_OPTION_TYPE_LENGTH;
    if (tvb_get_guint8(tvb, offset + len) > 0)
	sub_options = TRUE;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_length, tvb, offset + len,
	IP6_MIPv6_OPTION_LENGTH_LENGTH, tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_OPTION_LENGTH_LENGTH;
    /* sub - options */
    if (sub_options)
	proto_tree_add_text(dstopt_tree, tvb, offset + len, 1, "Sub-Options");
    return len;
}

static int
dissect_mipv6_sub_u(tvbuff_t *tvb, proto_tree *dstopt_tree, int offset)
{
    int len = 0;
			
    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_sub_length, tvb,
	offset + len, IP6_MIPv6_SUB_TYPE_LENGTH,
	tvb_get_guint8(tvb, offset + len),
	"Sub-Option Type: %u (0x%02x) - Unique Identifier Sub-Option",
	tvb_get_guint8(tvb, offset + len), tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_SUB_TYPE_LENGTH;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_sub_length, tvb,
	offset + len, IP6_MIPv6_SUB_LENGTH_LENGTH,
	tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_SUB_LENGTH_LENGTH;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_sub_unique_ID, tvb,
	offset + len, IP6_MIPv6_SUB_UNIQUE_ID_LENGTH,
	tvb_get_ntohs(tvb, offset + len));
    len += IP6_MIPv6_SUB_UNIQUE_ID_LENGTH;
    return len;
}

static int
dissect_mipv6_sub_a_coa(tvbuff_t *tvb, proto_tree *dstopt_tree, int offset)
{
    int len = 0;

    proto_tree_add_uint_format(dstopt_tree, hf_ipv6_mipv6_sub_type, tvb,
	offset + len, IP6_MIPv6_SUB_TYPE_LENGTH,
	tvb_get_guint8(tvb, offset + len),
	"Sub-Option Type: %u (0x%02x) - Alternative Care Of Address",
	tvb_get_guint8(tvb, offset + len),
    tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_SUB_TYPE_LENGTH;
    proto_tree_add_uint(dstopt_tree, hf_ipv6_mipv6_sub_length, tvb,
	offset + len, IP6_MIPv6_SUB_LENGTH_LENGTH,
	tvb_get_guint8(tvb, offset + len));
    len += IP6_MIPv6_SUB_LENGTH_LENGTH;
    proto_tree_add_ipv6(dstopt_tree, hf_ipv6_mipv6_sub_alternative_COA, tvb,
	offset + len, IP6_MIPv6_SUB_ALTERNATIVE_COA_LENGTH,
	tvb_get_ptr(tvb, offset + len, IP6_MIPv6_SUB_ALTERNATIVE_COA_LENGTH));
    len += IP6_MIPv6_SUB_ALTERNATIVE_COA_LENGTH;
    return len;
}

static const value_string rtalertvals[] = {
    { IP6OPT_RTALERT_MLD, "MLD" },
    { IP6OPT_RTALERT_RSVP, "RSVP" },
    { 0, NULL },
};

static int
dissect_opts(tvbuff_t *tvb, int offset, proto_tree *tree, char *optname)
{
    struct ip6_ext ext;
    int len;
    proto_tree *dstopt_tree;
    proto_item *ti;
    gint p;
    guint8 tmp;
    int mip_offset = 0, delta = 0;

    tvb_memcpy(tvb, (guint8 *)&ext, offset, sizeof(ext));
    len = (ext.ip6e_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, tvb, offset, len, "%s Header ", optname);

	dstopt_tree = proto_item_add_subtree(ti, ett_ipv6);

	proto_tree_add_text(dstopt_tree, tvb,
	    offset + offsetof(struct ip6_ext, ip6e_nxt), 1,
	    "Next header: %s (0x%02x)", ipprotostr(ext.ip6e_nxt), ext.ip6e_nxt);
	proto_tree_add_text(dstopt_tree, tvb,
	    offset + offsetof(struct ip6_ext, ip6e_len), 1,
	    "Length: %u (%d bytes)", ext.ip6e_len, len);

	mip_offset = offset;
	mip_offset += 2;

	p = offset + 2;

	while (p < offset + len) {
	    switch (tvb_get_guint8(tvb, p)) {
	    case IP6OPT_PAD1:
		proto_tree_add_text(dstopt_tree, tvb, p, 1, "Pad1");
		p++;
		mip_offset++;
		break;
	    case IP6OPT_PADN:
		tmp = tvb_get_guint8(tvb, p + 1);
		proto_tree_add_text(dstopt_tree, tvb, p, tmp + 2,
		    "PadN: %u bytes", tmp + 2);
		p += tmp;
		p += 2;
		mip_offset += tvb_get_guint8(tvb, mip_offset + 1) + 2;
		break;
	    case IP6OPT_JUMBO:
		tmp = tvb_get_guint8(tvb, p + 1);
		if (tmp == 4) {
		    proto_tree_add_text(dstopt_tree, tvb, p, tmp + 2,
			"Jumbo payload: %u (%u bytes)",
			tvb_get_ntohl(tvb, p + 2), tmp + 2);
		} else {
		    proto_tree_add_text(dstopt_tree, tvb, p, tmp + 2,
			"Jumbo payload: Invalid length (%u bytes)",
			tmp + 2);
		}
		p += tmp;
		p += 2;
		mip_offset += tvb_get_guint8(tvb, mip_offset+1)+2;
		break;
	    case IP6OPT_RTALERT:
	      {
		char *rta;

		tmp = tvb_get_guint8(tvb, p + 1);
		if (tmp == 2) {
		    rta = val_to_str(tvb_get_ntohs(tvb, p + 2), rtalertvals,
			"Unknown");
		} else
		    rta = "Invalid length";
		ti = proto_tree_add_text(dstopt_tree, tvb, p , tmp + 2,
		    "Router alert: %s (%u bytes)", rta, tmp + 2);
		p += tmp;
		p += 2;
		mip_offset += tvb_get_guint8(tvb, mip_offset + 1) + 2;
		break;
	      }
	    case IP6OPT_BINDING_UPDATE :
		delta = dissect_mipv6_bu(tvb, dstopt_tree, mip_offset);
		p += delta;
		mip_offset += delta;
		break;
	    case IP6OPT_BINDING_ACK :
		delta = dissect_mipv6_ba(tvb, dstopt_tree, mip_offset);
		p += delta;
		mip_offset += delta;
		break;
	    case IP6OPT_HOME_ADDRESS :
		delta = dissect_mipv6_ha(tvb, dstopt_tree, mip_offset);
		p += delta;
		mip_offset += delta;
		break;
	    case IP6OPT_BINDING_REQUEST :
		delta = dissect_mipv6_br(tvb, dstopt_tree, mip_offset);
		p += delta;
		mip_offset += delta;
		break;
	    case IP6OPT_MIPv6_UNIQUE_ID_SUB :
		delta = dissect_mipv6_sub_u(tvb, dstopt_tree, mip_offset);
		p += delta;
		mip_offset += delta;
		break;
	    case IP6OPT_MIPv6_ALTERNATIVE_COA_SUB :
		delta = dissect_mipv6_sub_a_coa(tvb, dstopt_tree, mip_offset);
		p += delta;
		mip_offset += delta;
		break;
	    default:
		p = offset + len;
		break;
	    }
	}

	/* decode... */
    }
    return len;
}

static int
dissect_hopopts(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    return dissect_opts(tvb, offset, tree, "Hop-by-hop Option");
}

static int
dissect_dstopts(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    return dissect_opts(tvb, offset, tree, "Destination Option");
}

static void
dissect_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ipv6_tree = NULL;
  proto_item *ti;
  guint8 nxt;
  int advance;
  int poffset;
  guint16 plen;
  gboolean frag;
  guint16 offlg;
  guint32 ident;
  int offset;
  fragment_data *ipfd_head;
  tvbuff_t   *next_tvb;
  gboolean update_col_info = TRUE;
  gboolean save_fragmented;

  struct ip6_hdr ipv6;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPv6");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  offset = 0;
  tvb_memcpy(tvb, (guint8 *)&ipv6, offset, sizeof(ipv6));

  pinfo->ipproto = ipv6.ip6_nxt; /* XXX make work TCP follow (ipproto = 6) */

  /* Get the payload length */
  plen = ntohs(ipv6.ip6_plen);

  /* Adjust the length of this tvbuff to include only the IPv6 datagram. */
  set_actual_length(tvb, plen + sizeof (struct ip6_hdr));

  SET_ADDRESS(&pinfo->net_src, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_SRC, 16));
  SET_ADDRESS(&pinfo->src, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_SRC, 16));
  SET_ADDRESS(&pinfo->net_dst, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_DST, 16));
  SET_ADDRESS(&pinfo->dst, AT_IPv6, 16, tvb_get_ptr(tvb, offset + IP6H_DST, 16));

  if (tree) {
    /* !!! specify length */
    ti = proto_tree_add_item(tree, proto_ipv6, tvb, offset, 40, FALSE);
    ipv6_tree = proto_item_add_subtree(ti, ett_ipv6);

    /* !!! warning: version also contains 4 Bit priority */
    proto_tree_add_uint(ipv6_tree, hf_ipv6_version, tvb,
		offset + offsetof(struct ip6_hdr, ip6_vfc), 1,
		(ipv6.ip6_vfc >> 4) & 0x0f);

    proto_tree_add_uint(ipv6_tree, hf_ipv6_class, tvb,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		(guint8)((ntohl(ipv6.ip6_flow) >> 20) & 0xff));

    /*
     * there should be no alignment problems for ip6_flow, since it's the first
     * guint32 in the ipv6 struct
     */
    proto_tree_add_uint_format(ipv6_tree, hf_ipv6_flow, tvb,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		(unsigned long)(ntohl(ipv6.ip6_flow) & IPV6_FLOWLABEL_MASK),
		"Flowlabel: 0x%05lx",
		(unsigned long)(ntohl(ipv6.ip6_flow) & IPV6_FLOWLABEL_MASK));

    proto_tree_add_uint(ipv6_tree, hf_ipv6_plen, tvb,
		offset + offsetof(struct ip6_hdr, ip6_plen), 2,
		plen);

    proto_tree_add_uint_format(ipv6_tree, hf_ipv6_nxt, tvb,
		offset + offsetof(struct ip6_hdr, ip6_nxt), 1,
		ipv6.ip6_nxt,
		"Next header: %s (0x%02x)",
		ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);

    proto_tree_add_uint(ipv6_tree, hf_ipv6_hlim, tvb,
		offset + offsetof(struct ip6_hdr, ip6_hlim), 1,
		ipv6.ip6_hlim);

    proto_tree_add_ipv6_hidden(ipv6_tree, hf_ipv6_addr, tvb,
			       offset + offsetof(struct ip6_hdr, ip6_src), 16,
			       ipv6.ip6_src.s6_addr8);
    proto_tree_add_ipv6_hidden(ipv6_tree, hf_ipv6_addr, tvb,
			       offset + offsetof(struct ip6_hdr, ip6_dst), 16,
			       ipv6.ip6_dst.s6_addr8);

    proto_tree_add_ipv6_format(ipv6_tree, hf_ipv6_src, tvb,
		offset + offsetof(struct ip6_hdr, ip6_src), 16,
		(guint8 *)&ipv6.ip6_src,
#ifdef INET6
		"Source address: %s (%s)",
		get_hostname6(&ipv6.ip6_src),
#else
		"Source address: %s",
#endif
		ip6_to_str(&ipv6.ip6_src));

    proto_tree_add_ipv6_format(ipv6_tree, hf_ipv6_dst, tvb,
		offset + offsetof(struct ip6_hdr, ip6_dst), 16,
		(guint8 *)&ipv6.ip6_dst,
#ifdef INET6
		"Destination address: %s (%s)",
		get_hostname6(&ipv6.ip6_dst),
#else
		"Destination address: %s",
#endif
		ip6_to_str(&ipv6.ip6_dst));
  }

  /* start of the new header (could be a extension header) */
  poffset = offset + offsetof(struct ip6_hdr, ip6_nxt);
  nxt = tvb_get_guint8(tvb, poffset);
  offset += sizeof(struct ip6_hdr);
  offlg = 0;
  ident = 0;

/* start out assuming this isn't fragmented */
  frag = FALSE;

again:
   switch (nxt) {
   case IP_PROTO_HOPOPTS:
			advance = dissect_hopopts(tvb, offset, tree);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_ROUTING:
			advance = dissect_routing6(tvb, offset, tree);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_FRAGMENT:
			frag = TRUE;
			advance = dissect_frag6(tvb, offset, pinfo, tree,
			    &offlg, &ident);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_AH:
			advance = dissect_ah_header(
				  tvb_new_subset(tvb, offset, -1, -1),
				  pinfo, tree, NULL, NULL);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    case IP_PROTO_DSTOPTS:
			advance = dissect_dstopts(tvb, offset, tree);
			nxt = tvb_get_guint8(tvb, offset);
			poffset = offset;
			offset += advance;
			plen -= advance;
			goto again;
    }

#ifdef TEST_FINALHDR
  proto_tree_add_uint_hidden(ipv6_tree, hf_ipv6_final, tvb, poffset, 1, nxt);
#endif

  /* If ipv6_reassemble is on, this is a fragment, and we have all the data
   * in the fragment, then just add the fragment to the hashtable.
   */
  save_fragmented = pinfo->fragmented;
  if (ipv6_reassemble && frag && tvb_reported_length(tvb) <= tvb_length(tvb)) {
    ipfd_head = fragment_add(tvb, offset, pinfo, ident,
			     ipv6_fragment_table,
			     offlg & IP6F_OFF_MASK,
			     plen,
			     offlg & IP6F_MORE_FRAG);

    if (ipfd_head != NULL) {
      fragment_data *ipfd;
      proto_tree *ft = NULL;
      proto_item *fi = NULL;

      /* OK, we have the complete reassembled payload.
         Allocate a new tvbuff, referring to the reassembled payload. */
      next_tvb = tvb_new_real_data(ipfd_head->data, ipfd_head->datalen,
	ipfd_head->datalen);

      /* Add the tvbuff to the list of tvbuffs to which the tvbuff we
         were handed refers, so it'll get cleaned up when that tvbuff
         is cleaned up. */
      tvb_set_child_real_data_tvbuff(tvb, next_tvb);

      /* Add the defragmented data to the data source list. */
      add_new_data_source(pinfo->fd, next_tvb, "Reassembled IPv6");

      /* It's not fragmented. */
      pinfo->fragmented = FALSE;

      /* show all fragments */
      fi = proto_tree_add_item(ipv6_tree, hf_ipv6_fragments,
                next_tvb, 0, -1, FALSE);
      ft = proto_item_add_subtree(fi, ett_ipv6_fragments);
      for (ipfd = ipfd_head->next; ipfd; ipfd = ipfd->next){
        if (ipfd->flags & (FD_OVERLAP|FD_OVERLAPCONFLICT
                          |FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
          /* this fragment has some flags set, create a subtree
           * for it and display the flags.
           */
          proto_tree *fet = NULL;
          proto_item *fei = NULL;
          int hf;

          if (ipfd->flags & (FD_OVERLAPCONFLICT
                      |FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
            hf = hf_ipv6_fragment_error;
          } else {
            hf = hf_ipv6_fragment;
          }
          fei = proto_tree_add_none_format(ft, hf,
                   next_tvb, ipfd->offset, ipfd->len,
                   "Frame:%u payload:%u-%u",
                   ipfd->frame,
                   ipfd->offset,
                   ipfd->offset+ipfd->len-1
          );
          fet = proto_item_add_subtree(fei, ett_ipv6_fragment);
          if (ipfd->flags&FD_OVERLAP) {
            proto_tree_add_boolean(fet,
                 hf_ipv6_fragment_overlap, next_tvb, 0, 0,
                 TRUE);
          }
          if (ipfd->flags&FD_OVERLAPCONFLICT) {
            proto_tree_add_boolean(fet,
                 hf_ipv6_fragment_overlap_conflict, next_tvb, 0, 0,
                 TRUE);
          }
          if (ipfd->flags&FD_MULTIPLETAILS) {
            proto_tree_add_boolean(fet,
                 hf_ipv6_fragment_multiple_tails, next_tvb, 0, 0,
                 TRUE);
          }
          if (ipfd->flags&FD_TOOLONGFRAGMENT) {
            proto_tree_add_boolean(fet,
                 hf_ipv6_fragment_too_long_fragment, next_tvb, 0, 0,
                 TRUE);
          }
        } else {
          /* nothing of interest for this fragment */
          proto_tree_add_none_format(ft, hf_ipv6_fragment,
                   next_tvb, ipfd->offset, ipfd->len,
                   "Frame:%u payload:%u-%u",
                   ipfd->frame,
                   ipfd->offset,
                   ipfd->offset+ipfd->len-1
          );
        }
      }
      if (ipfd_head->flags & (FD_OVERLAPCONFLICT
                        |FD_MULTIPLETAILS|FD_TOOLONGFRAGMENT) ) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
          col_set_str(pinfo->cinfo, COL_INFO, "[Illegal fragments]");
          update_col_info = FALSE;
        }
      }
    } else {
      /* We don't have the complete reassembled payload. */
      next_tvb = NULL;
    }
  } else {
    /* If this is the first fragment, dissect its contents, otherwise
       just show it as a fragment.

       XXX - if we eventually don't save the reassembled contents of all
       fragmented datagrams, we may want to always reassemble. */
    if (offlg & IP6F_OFF_MASK) {
      /* Not the first fragment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First fragment, or not fragmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset(tvb, offset, -1, -1);

      /*
       * If this is the first fragment, but not the only fragment,
       * tell the next protocol that.
       */
      if (offlg & IP6F_MORE_FRAG)
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as a fragment. */
    /* COL_INFO was filled in by "dissect_frag6()" */
    call_dissector(data_handle,tvb_new_subset(tvb, offset, -1,tvb_reported_length_remaining(tvb,offset)),pinfo, tree);

    /* As we haven't reassembled anything, we haven't changed "pi", so
       we don't have to restore it. */
    pinfo->fragmented = save_fragmented;
    return;
  }

  /* do lookup with the subdissector table */
  if (!dissector_try_port(ip_dissector_table, nxt, next_tvb, pinfo, tree)) {
    /* Unknown protocol */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%02x)", ipprotostr(nxt),nxt);
    call_dissector(data_handle,next_tvb, pinfo, tree);
  }
  pinfo->fragmented = save_fragmented;
}

static void
dissect_ipv6_none(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (hf_ipv6_mipv6_length != -1) {
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Mobile IPv6 Destination Option");
    } else {
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "IPv6 no next header");
    }
    /* XXX - dissect the payload as padding? */
}

void
proto_register_ipv6(void)
{
  static hf_register_info hf[] = {
    { &hf_ipv6_version,
      { "Version",		"ipv6.version",
				FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_class,
      { "Traffic class",	"ipv6.class",
				FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_flow,
      { "Flowlabel",		"ipv6.flow",
				FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_plen,
      { "Payload length",	"ipv6.plen",
				FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_nxt,
      { "Next header",		"ipv6.nxt",
				FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_hlim,
      { "Hop limit",		"ipv6.hlim",
				FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ipv6_src,
      { "Source",		"ipv6.src",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Source IPv6 Address", HFILL }},
    { &hf_ipv6_dst,
      { "Destination",		"ipv6.dst",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Destination IPv6 Address", HFILL }},
    { &hf_ipv6_addr,
      { "Address",		"ipv6.addr",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Source or Destination IPv6 Address", HFILL }},

    { &hf_ipv6_fragment_overlap,
      { "Fragment overlap",	"ipv6.fragment.overlap",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Fragment overlaps with other fragments", HFILL }},

    { &hf_ipv6_fragment_overlap_conflict,
      { "Conflicting data in fragment overlap",	"ipv6.fragment.overlap.conflict",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Overlapping fragments contained conflicting data", HFILL }},

    { &hf_ipv6_fragment_multiple_tails,
      { "Multiple tail fragments found", "ipv6.fragment.multipletails",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Several tails were found when defragmenting the packet", HFILL }},

    { &hf_ipv6_fragment_too_long_fragment,
      { "Fragment too long",	"ipv6.fragment.toolongfragment",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Fragment contained data past end of packet", HFILL }},

    { &hf_ipv6_fragment_error,
      { "Defragmentation error", "ipv6.fragment.error",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"Defragmentation error due to illegal fragments", HFILL }},

    { &hf_ipv6_fragment,
      { "IPv6 Fragment",	"ipv6.fragment",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"IPv6 Fragment", HFILL }},

    { &hf_ipv6_fragments,
      { "IPv6 Fragments",	"ipv6.fragments",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"IPv6 Fragments", HFILL }},

    /* BT INSERT BEGIN */
    { &hf_ipv6_mipv6_type,
      { "Option Type ",		"ipv6.mipv6_type",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_length,
      { "Option Length ",		"ipv6.mipv6_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_a_flag,
      { "Acknowledge (A) ",		"ipv6.mipv6_a_flag",
				FT_BOOLEAN, 8, TFS(&ipv6_mipv6_bu_a_flag_value),
				IP6_MIPv6_BU_A_FLAG,
				"", HFILL }},
    { &hf_ipv6_mipv6_h_flag,
      { "Home Registration (H) ",		"ipv6.mipv6_h_flag",
				FT_BOOLEAN, 8, TFS(&ipv6_mipv6_bu_h_flag_value),
				IP6_MIPv6_BU_H_FLAG,
				"", HFILL }},
    { &hf_ipv6_mipv6_r_flag,
      { "Router (R) ",		"ipv6.mipv6_r_flag",
				FT_BOOLEAN, 8, TFS(&ipv6_mipv6_bu_r_flag_value),
				IP6_MIPv6_BU_R_FLAG,
				"", HFILL }},
    { &hf_ipv6_mipv6_d_flag,
      { "Duplicate Address Detection (D) ",		"ipv6.mipv6_d_flag",
				FT_BOOLEAN, 8, TFS(&ipv6_mipv6_bu_d_flag_value),
				IP6_MIPv6_BU_D_FLAG,
				"", HFILL }},
    { &hf_ipv6_mipv6_m_flag,
      { "MAP Registration (M) ",		"ipv6.mipv6_m_flag",
				FT_BOOLEAN, 8, TFS(&ipv6_mipv6_bu_m_flag_value),
				IP6_MIPv6_BU_M_FLAG,
				"", HFILL }},
    { &hf_ipv6_mipv6_b_flag,
      { "Bicasting all (B) ",		"ipv6.mipv6_b_flag",
				FT_BOOLEAN, 8, TFS(&ipv6_mipv6_bu_b_flag_value),
				IP6_MIPv6_BU_B_FLAG,
				"", HFILL }},
    { &hf_ipv6_mipv6_prefix_length,
      { "Prefix Length ",		"ipv6.mipv6_prefix_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_sequence_number,
      { "Sequence Number ",		"ipv6.mipv6_sequence_number",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_life_time,
      { "Life Time ",		"ipv6.mipv6_life_time",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_status,
      { "Status ",		"ipv6.mipv6_status",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_refresh,
      { "Refresh ",		"ipv6.mipv6_refresh",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_home_address,
      { "Home Address ",		"ipv6.mipv6_home_address",
				FT_IPv6, BASE_HEX, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_sub_type,
      { "Sub-Option Type ",		"ipv6.mipv6_sub_type",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_sub_length,
      { "Sub-Option Length ",		"ipv6.mipv6_sub_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_sub_unique_ID,
      { "Unique Identifier ",		"ipv6.mipv6_sub_unique_ID",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"", HFILL }},
    { &hf_ipv6_mipv6_sub_alternative_COA,
      { "Alternative Care of Address ",		"ipv6.mipv6_sub_alternative_COA",
				FT_IPv6, BASE_HEX, NULL, 0x0,
				"", HFILL }},

    /* BT INSERT END */
#ifdef TEST_FINALHDR
    { &hf_ipv6_final,
      { "Final next header",	"ipv6.final",
				FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
#endif
  };
  static gint *ett[] = {
    &ett_ipv6,
    &ett_ipv6_fragments,
    &ett_ipv6_fragment,
  };
  module_t *ipv6_module;

  proto_ipv6 = proto_register_protocol("Internet Protocol Version 6", "IPv6", "ipv6");
  proto_register_field_array(proto_ipv6, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register configuration options */
  ipv6_module = prefs_register_protocol(proto_ipv6, NULL);
  prefs_register_bool_preference(ipv6_module, "defragment",
	"Reassemble fragmented IPv6 datagrams",
	"Whether fragmented IPv6 datagrams should be reassembled",
	&ipv6_reassemble);

  register_dissector("ipv6", dissect_ipv6, proto_ipv6);
  register_init_routine(ipv6_reassemble_init);
}

void
proto_reg_handoff_ipv6(void)
{
  dissector_handle_t ipv6_handle, ipv6_none_handle;

  data_handle = find_dissector("data");
  ipv6_handle = find_dissector("ipv6");
  dissector_add("ethertype", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("ppp.protocol", PPP_IPV6, ipv6_handle);
  dissector_add("ppp.protocol", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("gre.proto", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("ip.proto", IP_PROTO_IPV6, ipv6_handle);
  ipv6_none_handle = create_dissector_handle(dissect_ipv6_none, proto_ipv6);
  dissector_add("ip.proto", IP_PROTO_NONE, ipv6_none_handle);
  dissector_add("null.type", BSD_AF_INET6_BSD, ipv6_handle);
  dissector_add("null.type", BSD_AF_INET6_FREEBSD, ipv6_handle);
  dissector_add("chdlctype", ETHERTYPE_IPv6, ipv6_handle);
  dissector_add("fr.ietf", NLPID_IP6, ipv6_handle);
  dissector_add("x.25.spi", NLPID_IP6, ipv6_handle);
}
