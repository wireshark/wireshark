/* packet-rsvp.c
 * Routines for RSVP packet disassembly
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-rsvp.c,v 1.39 2001/04/23 17:51:33 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
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

/*
 * NOTES
 *
 * This module defines routines to disassemble RSVP packets, as defined in
 * RFC 2205. All objects from RC2205 are supported, in IPv4 and IPv6 mode.
 * In addition, the Integrated Services traffic specification objects
 * defined in RFC2210 are also supported. 
 *
 * IPv6 support is not completely tested
 *
 * Mar 3, 2000: Added support for MPLS/TE objects, as defined in 
 * <draft-ietf-mpls-rsvp-lsp-tunnel-04.txt>
 */

 
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "in_cksum.h"
#include "packet-ipv6.h"
#include "ieee-float.h"
#include "etypes.h"
#include "ipproto.h"

static int proto_rsvp = -1;

static gint ett_rsvp = -1;
static gint ett_rsvp_hdr = -1;
static gint ett_rsvp_session = -1;
static gint ett_rsvp_hop = -1;
static gint ett_rsvp_time_values = -1;
static gint ett_rsvp_error = -1;
static gint ett_rsvp_scope = -1;
static gint ett_rsvp_style = -1;
static gint ett_rsvp_confirm = -1;
static gint ett_rsvp_sender_template = -1;
static gint ett_rsvp_filter_spec = -1;
static gint ett_rsvp_sender_tspec = -1;
static gint ett_rsvp_flowspec = -1;
static gint ett_rsvp_adspec = -1;
static gint ett_rsvp_adspec_subtree = -1;
static gint ett_rsvp_integrity = -1;
static gint ett_rsvp_policy = -1;
static gint ett_rsvp_label = -1;
static gint ett_rsvp_label_request = -1;
static gint ett_rsvp_session_attribute = -1;
static gint ett_rsvp_session_attribute_flags = -1;
static gint ett_rsvp_explicit_route = -1;
static gint ett_rsvp_explicit_route_subobj = -1;
static gint ett_rsvp_record_route = -1;
static gint ett_rsvp_record_route_subobj = -1;
static gint ett_rsvp_unknown_class = -1;


/*
 * RSVP message types
 */
typedef enum {
    RSVP_MSG_PATH=1, RSVP_MSG_RESV, RSVP_MSG_PERR, RSVP_MSG_RERR,
    RSVP_MSG_PTEAR, RSVP_MSG_RTEAR, RSVP_MSG_CONFIRM, 
    RSVP_MSG_RTEAR_CONFIRM=10
} rsvp_message_types;

static value_string message_type_vals[] = { 
    {RSVP_MSG_PATH, "PATH Message"},
    {RSVP_MSG_RESV, "RESV Message"},
    {RSVP_MSG_PERR, "PATH ERROR Message"},
    {RSVP_MSG_RERR, "RESV ERROR Message"},
    {RSVP_MSG_PTEAR, "PATH TEAR Message"},
    {RSVP_MSG_RTEAR, "RESV TEAR Message"},
    {RSVP_MSG_CONFIRM, "CONFIRM Message"},
    {RSVP_MSG_RTEAR_CONFIRM, "RESV TEAR CONFIRM Message"},
    {0, NULL}
};

/* 
 * RSVP classes
 */
#define MAX_RSVP_CLASS 15

enum rsvp_classes {
    RSVP_CLASS_NULL=0,
    RSVP_CLASS_SESSION,

    RSVP_CLASS_HOP=3,
    RSVP_CLASS_INTEGRITY,
    RSVP_CLASS_TIME_VALUES,
    RSVP_CLASS_ERROR,
    RSVP_CLASS_SCOPE,
    RSVP_CLASS_STYLE,
    RSVP_CLASS_FLOWSPEC,
    RSVP_CLASS_FILTER_SPEC,
    RSVP_CLASS_SENDER_TEMPLATE,
    RSVP_CLASS_SENDER_TSPEC,
    RSVP_CLASS_ADSPEC,
    RSVP_CLASS_POLICY,
    RSVP_CLASS_CONFIRM,
    RSVP_CLASS_LABEL,

    RSVP_CLASS_LABEL_REQUEST=19,
    RSVP_CLASS_EXPLICIT_ROUTE,
    RSVP_CLASS_RECORD_ROUTE,

    RSVP_CLASS_SESSION_ATTRIBUTE=207,
};

static value_string rsvp_class_vals[] = { 
    {RSVP_CLASS_NULL, "NULL object"},
    {RSVP_CLASS_SESSION, "SESSION object"},
    {RSVP_CLASS_HOP, "HOP object"},
    {RSVP_CLASS_INTEGRITY, "INTEGRITY object"},
    {RSVP_CLASS_TIME_VALUES, "TIME VALUES object"},
    {RSVP_CLASS_ERROR, "ERROR object"},
    {RSVP_CLASS_SCOPE, "SCOPE object"},
    {RSVP_CLASS_STYLE, "STYLE object"},
    {RSVP_CLASS_FLOWSPEC, "FLOWSPEC object"},
    {RSVP_CLASS_FILTER_SPEC, "FILTER SPEC object"},
    {RSVP_CLASS_SENDER_TEMPLATE, "SENDER TEMPLATE object"},
    {RSVP_CLASS_SENDER_TSPEC, "SENDER TSPEC object"},
    {RSVP_CLASS_ADSPEC, "ADSPEC object"},
    {RSVP_CLASS_POLICY, "POLICY object"},
    {RSVP_CLASS_CONFIRM, "CONFIRM object"},
    {RSVP_CLASS_LABEL, "LABEL object"},
    {RSVP_CLASS_LABEL_REQUEST, "LABEL REQUEST object"},
    {RSVP_CLASS_EXPLICIT_ROUTE, "EXPLICIT ROUTE object"},
    {RSVP_CLASS_RECORD_ROUTE, "RECORD ROUTE object"},
    {RSVP_CLASS_SESSION_ATTRIBUTE, "SESSION ATTRIBUTE object"},
    {0, NULL}
};

/*
 * RSVP error values
 */
enum rsvp_error_types {
    RSVP_ERROR_CONFIRM = 0,
    RSVP_ERROR_ADMISSION,
    RSVP_ERROR_POLICY,
    RSVP_ERROR_NO_PATH,
    RSVP_ERROR_NO_SENDER,
    RSVP_ERROR_CONFLICT_RESV_STYLE,
    RSVP_ERROR_UNKNOWN_RESV_STYLE,
    RSVP_ERROR_CONFLICT_DEST_PORTS,
    RSVP_ERROR_CONFLICT_SRC_PORTS,
    RSVP_ERROR_PREEMPTED=12,
    RSVP_ERROR_UNKNOWN_CLASS,
    RSVP_ERROR_UNKNOWN_C_TYPE,
    RSVP_ERROR_TRAFFIC = 21,
    RSVP_ERROR_TRAFFIC_SYSTEM,
    RSVP_ERROR_SYSTEM
};

static value_string rsvp_error_vals[] = {
    {RSVP_ERROR_CONFIRM, "Confirmation"},
    {RSVP_ERROR_ADMISSION, "Admission Control Failure "},
    {RSVP_ERROR_POLICY, "Policy Control Failure"},
    {RSVP_ERROR_NO_PATH, "No PATH information for this RESV message"},
    {RSVP_ERROR_NO_SENDER, "No sender information for this RESV message"},
    {RSVP_ERROR_CONFLICT_RESV_STYLE, "Conflicting reservation styles"},
    {RSVP_ERROR_UNKNOWN_RESV_STYLE, "Unknown reservation style"},
    {RSVP_ERROR_CONFLICT_DEST_PORTS, "Conflicting destination ports"},
    {RSVP_ERROR_CONFLICT_SRC_PORTS, "Conflicting source ports"},
    {RSVP_ERROR_PREEMPTED, "Service preempted"},
    {RSVP_ERROR_UNKNOWN_CLASS, "Unknown object class"},
    {RSVP_ERROR_UNKNOWN_C_TYPE, "Unknown object C-type"},
    {RSVP_ERROR_TRAFFIC, "Traffic Control Error"},
    {RSVP_ERROR_TRAFFIC_SYSTEM, "Traffic Control System Error"},
    {0, NULL}
};

/*
 * Defines the reservation style plus style-specific information that
 * is not a FLOWSPEC or FILTER_SPEC object, in a RESV message.
 */
#define RSVP_DISTINCT (1 << 3)
#define RSVP_SHARED (2 << 3)
#define RSVP_SHARING_MASK (RSVP_DISTINCT | RSVP_SHARED)

#define RSVP_SCOPE_WILD 1
#define RSVP_SCOPE_EXPLICIT 2
#define RSVP_SCOPE_MASK 0x07

#define RSVP_WF (RSVP_SHARED | RSVP_SCOPE_WILD)
#define RSVP_FF (RSVP_DISTINCT | RSVP_SCOPE_EXPLICIT)
#define RSVP_SE (RSVP_SHARED | RSVP_SCOPE_EXPLICIT)

static value_string style_vals[] = {
    { RSVP_WF, "Wildcard Filter" },
    { RSVP_FF, "Fixed Filter" },
    { RSVP_SE, "Shared-Explicit" },
    { 0,       NULL }
};

/*
 * Defines a desired QoS, in a RESV message.
 */
enum    qos_service_type {
    QOS_QUALITATIVE =     128,          /* Qualitative service */
    QOS_CONTROLLED_LOAD=    5,		/* Controlled Load Service */
    QOS_GUARANTEED =        2,		/* Guaranteed service */
    QOS_TSPEC =             1		/* Traffic specification */
    };

static value_string qos_vals[] = {
    { QOS_QUALITATIVE, "Qualitative QoS" },
    { QOS_CONTROLLED_LOAD, "Controlled-load QoS" },
    { QOS_GUARANTEED, "Guaranteed rate QoS" },
    { QOS_TSPEC, "Traffic specification" },
    { 0, NULL }
};

static value_string svc_vals[] = {
    { 127, "Token bucket TSpec" },
    { 128, "Qualitative TSpec" },
    { 130, "Guaranteed-rate RSpec" },
    { 0, NULL }
};

enum rsvp_spec_types { INTSRV = 2 };

enum intsrv_services {
	INTSRV_GENERAL = 1,
	INTSRV_GTD = 2,
	INTSRV_CLOAD = 5,
	INTSRV_QUALITATIVE = 128
};

static value_string intsrv_services_str[] = { 
    {INTSRV_GENERAL, "Default General Parameters"},
    {INTSRV_GTD, "Guaranteed"},
    {INTSRV_CLOAD, "Controlled Load"},
    {INTSRV_QUALITATIVE, "Qualitative"},
    { 0, NULL }
};

enum intsrv_field_name {
	INTSRV_NON_IS_HOPS = 1, INTSRV_COMPOSED_NON_IS_HOPS,
	INTSRV_IS_HOPS, INTSRV_COMPOSED_IS_HOPS,
	INTSRV_PATH_BANDWIDTH, INTSRV_MIN_PATH_BANDWIDTH,
	INTSRV_IF_LATENCY, INTSRV_PATH_LATENCY,
	INTSRV_MTU, INTSRV_COMPOSED_MTU,

	INTSRV_TOKEN_BUCKET_TSPEC = 127,
	INTSRV_QUALITATIVE_TSPEC = 128,
	INTSRV_GTD_RSPEC = 130,

    	INTSRV_DELAY = 131,	/* Gtd Parameter C - Max Delay Bound - bytes */
	INTSRV_MAX_JITTER,	/* Gtd Parameter D - Max Jitter */
    	INTSRV_E2E_DELAY,	/* Gtd Parameter Ctot */
	INTSRV_E2E_MAX_JITTER,	/* Gtd Parameter Dtot */
    	INTSRV_SHP_DELAY,	/* Gtd Parameter Csum */
	INTSRV_SHP_MAX_JITTER	/* Gtd Parameter Dsum */
};

static value_string adspec_params[] = { 
    {4, "IS Hop Count"},
    {6, "Path b/w estimate"},
    {8, "Minimum path latency"},
    {10, "Composed MTU"},
    {133, "End-to-end composed value for C"},
    {134, "End-to-end composed value for D"},
    {135, "Since-last-reshaping point composed C"},
    {136, "Since-last-reshaping point composed D"},
    { 0, NULL }
};

/* -------------------- Stuff for MPLS/TE objects -------------------- */

static const value_string proto_vals[] = { {IP_PROTO_ICMP, "ICMP"},
                                           {IP_PROTO_IGMP, "IGMP"},
                                           {IP_PROTO_TCP,  "TCP" },
                                           {IP_PROTO_UDP,  "UDP" },
                                           {IP_PROTO_OSPF, "OSPF"},
                                           {0,             NULL  } };

/* Filter keys */
enum rsvp_filter_keys {

    /* Message types */
    RSVPF_MSG,          /* Message type */
    /* Shorthand for message types */
    RSVPF_PATH,
    RSVPF_RESV,
    RSVPF_PATHERR,
    RSVPF_RESVERR,
    RSVPF_PATHTEAR,
    RSVPF_RESVTEAR,
    RSVPF_RCONFIRM,
    RSVPF_JUNK_MSG8,
    RSVPF_JUNK_MSG9,
    RSVPF_RTEARCONFIRM,

    /* Does the message contain an object of this type? */
    RSVPF_OBJECT,
    /* Object present shorthands */
    RSVPF_SESSION,
    RSVPF_DUMMY_1,
    RSVPF_HOP,
    RSVPF_INTEGRITY,
    RSVPF_TIME_VALUES,
    RSVPF_ERROR,
    RSVPF_SCOPE,
    RSVPF_STYLE,
    RSVPF_FLOWSPEC,
    RSVPF_FILTER_SPEC,
    RSVPF_SENDER,
    RSVPF_TSPEC,
    RSVPF_ADSPEC,
    RSVPF_POLICY,
    RSVPF_CONFIRM,
    RSVPF_LABEL,
    RSVPF_DUMMY_2,
    RSVPF_DUMMY_3,
    RSVPF_LABEL_REQUEST,
    RSVPF_EXPLICIT_ROUTE,
    RSVPF_RECORD_ROUTE,

    RSVPF_SESSION_ATTRIBUTE,

    RSVPF_UNKNOWN_OBJ, 

    /* Session object */
    RSVPF_SESSION_IP,
    RSVPF_SESSION_PROTO,
    RSVPF_SESSION_PORT,
    RSVPF_SESSION_TUNNEL_ID,
    RSVPF_SESSION_EXT_TUNNEL_ID,

    /* Sender template */
    RSVPF_SENDER_IP,
    RSVPF_SENDER_PORT,
    RSVPF_SENDER_LSP_ID,

    /* Sentinel */
    RSVPF_MAX
};

static int rsvp_filter[RSVPF_MAX];

static hf_register_info rsvpf_info[] = {

    /* Message type number */
    {&rsvp_filter[RSVPF_MSG], 
     { "Message Type", "rsvp.msg", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x0,
     	"" }},

    /* Message type shorthands */
    {&rsvp_filter[RSVPF_PATH], 
     { "Path Message", "rsvp.path", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RESV], 
     { "Resv Message", "rsvp.resv", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_PATHERR], 
     { "Path Error Message", "rsvp.perr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RESVERR], 
     { "Resv Error Message", "rsvp.rerr", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_PATHTEAR], 
     { "Path Tear Message", "rsvp.ptear", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RESVTEAR], 
     { "Resv Tear Message", "rsvp.rtear", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RCONFIRM], 
     { "Resv Confirm Message", "rsvp.resvconf", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RTEARCONFIRM], 
     { "Resv Tear Confirm Message", "rsvp.rtearconf", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
     	"" }},

    /* Object class */
    {&rsvp_filter[RSVPF_OBJECT], 
     { "Object class", "rsvp.object", FT_UINT8, BASE_DEC, VALS(rsvp_class_vals), 0x0,
     	"" }},

    /* Object present shorthands */
    {&rsvp_filter[RSVPF_SESSION], 
     { "SESSION", "rsvp.session", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_HOP], 
     { "HOP", "rsvp.hop", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_INTEGRITY], 
     { "INTEGRITY", "rsvp.integrity", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_TIME_VALUES], 
     { "TIME VALUES", "rsvp.time", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_ERROR], 
     { "ERROR", "rsvp.error", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SCOPE], 
     { "SCOPE", "rsvp.scope", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_STYLE], 
     { "STYLE", "rsvp.style", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_FLOWSPEC], 
     { "FLOWSPEC", "rsvp.flowspec", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_FILTER_SPEC], 
     { "FILTERSPEC", "rsvp.filter", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SENDER], 
     { "SENDER TEMPLATE", "rsvp.sender", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_TSPEC], 
     { "SENDER TSPEC", "rsvp.tspec", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_ADSPEC], 
     { "ADSPEC", "rsvp.adspec", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_POLICY], 
     { "POLICY", "rsvp.policy", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_CONFIRM], 
     { "CONFIRM", "rsvp.confirm", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_LABEL], 
     { "LABEL", "rsvp.label", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_LABEL_REQUEST], 
     { "LABEL REQUEST", "rsvp.label_request", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_ATTRIBUTE], 
     { "SESSION ATTRIBUTE", "rsvp.session_attribute", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_EXPLICIT_ROUTE], 
     { "EXPLICIT ROUTE", "rsvp.explicit_route", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RECORD_ROUTE], 
     { "RECORD ROUTE", "rsvp.record_route", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_UNKNOWN_OBJ], 
     { "Unknown object", "rsvp.obj_unknown", FT_NONE, BASE_NONE, NULL, 0x0,
     	"" }},

    /* Session fields */
    {&rsvp_filter[RSVPF_SESSION_IP], 
     { "Destination address", "rsvp.session.ip", FT_IPv4, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_PORT], 
     { "Port number", "rsvp.session.port", FT_UINT16, BASE_DEC, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_PROTO], 
     { "Protocol", "rsvp.session.proto", FT_UINT8, BASE_DEC, VALS(proto_vals), 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_TUNNEL_ID], 
     { "Tunnel ID", "rsvp.session.tunnel_id", FT_UINT16, BASE_DEC, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID], 
     { "Extended tunnel ID", "rsvp.session.ext_tunnel_id", FT_UINT32, BASE_DEC, NULL, 0x0,
     	"" }},

    /* Sender template/Filterspec fields */
    {&rsvp_filter[RSVPF_SENDER_IP], 
     { "Sender IPv4 address", "rsvp.sender.ip", FT_IPv4, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SENDER_PORT], 
     { "Sender port number", "rsvp.sender.port", FT_UINT16, BASE_DEC, NULL, 0x0,
       "" }},

    {&rsvp_filter[RSVPF_SENDER_LSP_ID], 
     { "Sender LSP ID", "rsvp.sender.lsp_id", FT_UINT16, BASE_DEC, NULL, 0x0,
     	"" }}
};

static inline int rsvp_class_to_filter_num(int classnum)
{
    switch(classnum) {
    case RSVP_CLASS_SESSION :
    case RSVP_CLASS_HOP :
    case RSVP_CLASS_INTEGRITY :
    case RSVP_CLASS_TIME_VALUES :
    case RSVP_CLASS_ERROR :
    case RSVP_CLASS_SCOPE :
    case RSVP_CLASS_STYLE :
    case RSVP_CLASS_FLOWSPEC :
    case RSVP_CLASS_FILTER_SPEC :
    case RSVP_CLASS_SENDER_TEMPLATE :
    case RSVP_CLASS_SENDER_TSPEC :
    case RSVP_CLASS_ADSPEC :
    case RSVP_CLASS_POLICY :
    case RSVP_CLASS_CONFIRM :
    case RSVP_CLASS_LABEL :
    case RSVP_CLASS_LABEL_REQUEST :
    case RSVP_CLASS_EXPLICIT_ROUTE :
    case RSVP_CLASS_RECORD_ROUTE :
	return classnum + RSVPF_OBJECT;
	break;

    case RSVP_CLASS_SESSION_ATTRIBUTE :
	return RSVPF_SESSION_ATTRIBUTE;
	
    default:
	return RSVPF_UNKNOWN_OBJ;
    }
}

static void 
dissect_rsvp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
    int offset = 0;
    proto_tree *rsvp_tree = NULL, *ti, *ti2; 
    proto_tree *rsvp_header_tree;
    proto_tree *rsvp_object_tree;
    proto_tree *rsvp_sa_flags_tree;
    proto_tree *rsvp_ero_subtree;
    guint8 ver_flags;
    guint8 message_type;
    guint16 cksum, computed_cksum;
    vec_t cksum_vec[1];
    int i, j, k, l, len;
    int msg_length;
    int obj_length;
    int mylen;
    int offset2;

    if (check_col(pinfo->fd, COL_PROTOCOL))
        col_set_str(pinfo->fd, COL_PROTOCOL, "RSVP");
    if (check_col(pinfo->fd, COL_INFO))
        col_clear(pinfo->fd, COL_INFO);

    ver_flags = tvb_get_guint8(tvb, offset+0);
    message_type = tvb_get_guint8(tvb, offset+1);
    if (check_col(pinfo->fd, COL_INFO)) {
        col_add_str(pinfo->fd, COL_INFO,
            val_to_str(message_type, message_type_vals, "Unknown (%u)")); 
    }

    if (tree) {
	msg_length = tvb_get_ntohs(tvb, offset+6);
	ti = proto_tree_add_item(tree, proto_rsvp, tvb, offset, msg_length,
	    FALSE);
	rsvp_tree = proto_item_add_subtree(ti, ett_rsvp);

	ti = proto_tree_add_text(rsvp_tree, tvb, offset, 8, "RSVP Header"); 
	rsvp_header_tree = proto_item_add_subtree(ti, ett_rsvp_hdr);

        proto_tree_add_text(rsvp_header_tree, tvb, offset, 1, "RSVP Version: %u", 
			    (ver_flags & 0xf0)>>4);  
	proto_tree_add_text(rsvp_header_tree, tvb, offset, 1, "Flags: %02x",
			    ver_flags & 0xf);
	proto_tree_add_uint(rsvp_header_tree, rsvp_filter[RSVPF_MSG], tvb, 
			    offset+1, 1, message_type);
	if (message_type <= RSVPF_RTEARCONFIRM &&
			message_type != RSVPF_JUNK_MSG8 &&
			message_type != RSVPF_JUNK_MSG9 ) {
	       proto_tree_add_boolean_hidden(rsvp_header_tree, rsvp_filter[RSVPF_MSG + message_type], tvb, 
				   offset+1, 1, 1);
	}
	cksum = tvb_get_ntohs(tvb, offset+2);
	if (!pinfo->fragmented && tvb_length(tvb) >= msg_length) {
	    /* The packet isn't part of a fragmented datagram and isn't
	       truncated, so we can checksum it. */
	    cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, msg_length);
	    cksum_vec[0].len = msg_length;
	    computed_cksum = in_cksum(&cksum_vec[0], 1);
	    if (computed_cksum == 0) {
		proto_tree_add_text(rsvp_header_tree, tvb, offset+2, 2,
				    "Message Checksum: 0x%04x (correct)",
				    cksum);
	    } else {
		proto_tree_add_text(rsvp_header_tree, tvb, offset+2, 2,
				    "Message Checksum: 0x%04x (incorrect, should be 0x%04x)",
				    cksum,
				    in_cksum_shouldbe(cksum, computed_cksum));
	    }
	} else {
	    proto_tree_add_text(rsvp_header_tree, tvb, offset+2, 2,
				"Message Checksum: 0x%04x",
				cksum);
	}
	proto_tree_add_text(rsvp_header_tree, tvb, offset+4, 1,
			    "Sending TTL: %u",
			    tvb_get_guint8(tvb, offset+4));
	proto_tree_add_text(rsvp_header_tree, tvb, offset+6, 2,
			    "Message length: %u", msg_length);

	offset += 8;
	len = 8;
	while (len < msg_length) {
	    guint8 class;	
	    guint8 type;
	    char *object_type;

	    obj_length = tvb_get_ntohs(tvb, offset);
	    class = tvb_get_guint8(tvb, offset+2);
	    type = tvb_get_guint8(tvb, offset+3);
	    object_type = val_to_str(class, rsvp_class_vals, "Unknown");
	    proto_tree_add_uint_hidden(rsvp_tree, rsvp_filter[RSVPF_OBJECT], tvb, 
					    offset, obj_length, class);
	    ti = proto_tree_add_item(rsvp_tree, rsvp_filter[rsvp_class_to_filter_num(class)],
	    			     tvb, offset, obj_length, FALSE);

	    offset2 = offset+4;

	    switch(class) {

	    case RSVP_CLASS_SESSION : 		
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_session);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
					"C-type: 1 - IPv4");
		    proto_tree_add_item(rsvp_object_tree,
		    			rsvp_filter[RSVPF_SESSION_IP],
		    			tvb, offset2, 4, FALSE);

		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SESSION_PROTO], tvb, 
					offset2+4, 1, FALSE);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+5, 1,
					"Flags: %x",
					tvb_get_ntohs(tvb, offset2+5));
		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SESSION_PORT], tvb, 
					offset2+6, 2, FALSE);
		    break;
		}

		case 2: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
					"Destination address: %s", 
					ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2, 16)));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, 1,
					"Protocol: %u",
					tvb_get_guint8(tvb, offset2+16));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+17, 1,
					"Flags: %x",
					tvb_get_guint8(tvb, offset2+17));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+18, 2,
					"Destination port: %u", 
					tvb_get_ntohs(tvb, offset2+18));
		    break;
		}
		
		case 7: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 7 - IPv4 LSP");
		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SESSION_IP],
					tvb, offset2, 4, FALSE);

		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
					tvb, offset2+6, 2, FALSE);

		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4, 
					"Extended Tunnel ID: %u (%s)",
					tvb_get_ntohl(tvb, offset2+8),
					ip_to_str(tvb_get_ptr(tvb, offset2+8, 4)));
		    proto_tree_add_item_hidden(rsvp_object_tree,
		    			rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
		    			tvb, offset2+8, 4, FALSE);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		}
		}
		break;
		
	    case RSVP_CLASS_HOP :		
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_hop);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4, 
					"Neighbor address: %s", 
					ip_to_str(tvb_get_ptr(tvb, offset2, 4)));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
					"Logical interface: %u", 
					tvb_get_ntohl(tvb, offset2+4));
		    break;
		}

		case 2: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
					"Neighbor address: %s", 
					ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2, 16)));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, 4,
					"Logical interface: 0x%08x", 
					tvb_get_ntohl(tvb, offset2+16));
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		}
		}
		break;
		
	    case RSVP_CLASS_TIME_VALUES : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_time_values);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4, 
					"Refresh interval: %u ms (%u seconds)",
					tvb_get_ntohl(tvb, offset2),
					tvb_get_ntohl(tvb, offset2)/1000);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		    break;
		}
		}
		break;

	    case RSVP_CLASS_ERROR :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_error);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    guint8 error_code;

		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4, 
					"Error node: %s",
					ip_to_str(tvb_get_ptr(tvb, offset2, 4)));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 1,
					"Flags: 0x%02x",
					tvb_get_guint8(tvb, offset2+4));
		    error_code = tvb_get_guint8(tvb, offset2+5);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+5, 1,
					"Error code: %u - %s", error_code,
					val_to_str(error_code, rsvp_error_vals, "Unknown"));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+6, 2,
					"Error value: %u",
					tvb_get_ntohs(tvb, offset2+6));
		    break;
		}

		case 2: {
		    guint8 error_code;

		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
					"Error node: %s",
					ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2, 16)));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, 1,
					"Flags: 0x%02x",
					tvb_get_guint8(tvb, offset2+16));
		    error_code = tvb_get_guint8(tvb, offset2+17);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+17, 1,
					"Error code: %u - %s", error_code,
					val_to_str(error_code, rsvp_error_vals, "Unknown"));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+18, 2,
					"Error value: %u",
					tvb_get_ntohs(tvb, offset2+18));
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		}
		}
		break;
		

	    case RSVP_CLASS_SCOPE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_scope);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1 - IPv4");
		    while (mylen > 0) {
			proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4, 
					    "IPv4 Address: %s",
					    ip_to_str(tvb_get_ptr(tvb, offset2, 4)));
			offset2 += 4;
			mylen -= 4;
		    }
		    break;
		}

		case 2: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 2 - IPv6");
		    while (mylen > 0) {
			proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16, 
					    "IPv6 Address: %s",
					    ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2, 16)));
			offset2 += 16;
			mylen -= 16;
		    }
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		}
		}
		break;
		
	    case RSVP_CLASS_STYLE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_style);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    guint32 style;

		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
					"Flags: 0x%02x",
					tvb_get_guint8(tvb, offset2));
		    style = tvb_get_ntoh24(tvb, offset2+1);
		    ti = proto_tree_add_text(rsvp_object_tree, tvb, offset2+1,
			3, "Style: 0x%06X - %s",
			style,
			val_to_str(style, style_vals, "Unknown"));
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		    break;
		}
		}
		break;
	    
	    case RSVP_CLASS_CONFIRM :		
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_confirm);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4, 
					"Receiver address: %s", 
					ip_to_str(tvb_get_ptr(tvb, offset2, 4)));
		    break;
		}

		case 2: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16, 
					"Receiver address: %s", 
					ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2, 16)));
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		}
		}
		break;

	    case RSVP_CLASS_SENDER_TEMPLATE :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_sender_template);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		goto common_template;
	    case RSVP_CLASS_FILTER_SPEC :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_filter_spec);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
	    common_template:
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SENDER_IP],
					tvb, offset2, 4, FALSE);
		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SENDER_PORT],
					tvb, offset2+6, 2, FALSE);
		    break;
		}

		case 2: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16, 
					"Source address: %s", 
					ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2, 16)));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+18, 2,
					"Source port: %u",
					tvb_get_ntohs(tvb, offset2+18));
		    break;
		}
		
		case 7: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 7 - IPv4 LSP");
		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SENDER_IP],
					tvb, offset2, 4, FALSE);
		    proto_tree_add_item(rsvp_object_tree,
					rsvp_filter[RSVPF_SENDER_LSP_ID],
		    			tvb, offset2+6, 2, FALSE);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		}
		}
		break;

	    case RSVP_CLASS_SENDER_TSPEC : {
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_sender_tspec);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;

		proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
				    "Message format version: %u", 
				    tvb_get_guint8(tvb, offset2)>>4);
		proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2, 
				    "Data length: %u words, not including header", 
				    tvb_get_ntohs(tvb, offset2+2));

		mylen -= 4;
		offset2 += 4;
		while (mylen > 0) {
		    guint8 service_num;
		    guint8 param_id;
		    guint16 length;

		    service_num = tvb_get_guint8(tvb, offset2);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
					"Service header: %u - %s", 
					service_num,
					val_to_str(service_num, qos_vals, "Unknown"));
		    length = tvb_get_ntohs(tvb, offset2+2);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2, 
					"Length of service %u data: %u words, " 
					"not including header", 
					service_num, length);

		    mylen -= 4;
		    offset2 += 4;

		    switch(service_num) {
			
		    case QOS_TSPEC :
			/* Token bucket TSPEC */
			param_id = tvb_get_guint8(tvb, offset2);
			proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
					    "Parameter %u - %s", 
					    param_id,
					    val_to_str(param_id, svc_vals, "Unknown"));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
					    "Parameter %u flags: 0x%02x",
					    param_id,
					    tvb_get_guint8(tvb, offset2+1));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    param_id,
					    tvb_get_ntohs(tvb, offset2+2));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
					    "Token bucket rate: %ld", 
					    tvb_ieee_to_long(tvb, offset2+4));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
					    "Token bucket size: %ld", 
					    tvb_ieee_to_long(tvb, offset2+8));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+12, 4,
					    "Peak data rate: %ld", 
					    tvb_ieee_to_long(tvb, offset2+12));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, 4,
					    "Minimum policed unit: %u", 
					    tvb_get_ntohl(tvb, offset2+16));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+20, 4,
					    "Maximum policed unit: %u", 
					    tvb_get_ntohl(tvb, offset2+20));
			break;

		    case QOS_QUALITATIVE :
			/* Token bucket TSPEC */
			param_id = tvb_get_guint8(tvb, offset2);
			proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
					    "Parameter %u - %s", 
					    param_id,
					    val_to_str(param_id, svc_vals, "Unknown"));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
					    "Parameter %u flags: %x", 
					    param_id,
					    tvb_get_guint8(tvb, offset2+1));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    param_id,
					    tvb_get_ntohs(tvb, offset2+2));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
					    "Maximum policed unit: %u", 
					    tvb_get_ntohl(tvb, offset2+4));
			break;

		    }
		    offset2 += length*4; 
		    mylen -= length*4;
		}
		break;
	    }

	    case RSVP_CLASS_FLOWSPEC : {
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_flowspec);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;

		proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
				    "Message format version: %u", 
				    tvb_get_guint8(tvb, offset2)>>4);
		proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2, 
				    "Data length: %u words, not including header", 
				    tvb_get_ntohs(tvb, offset2+2));

		mylen -= 4;
		offset2+= 4;
		while (mylen > 0) {
		    guint8 service_num;
		    guint16 length;
		    guint8 param_id;

		    service_num = tvb_get_guint8(tvb, offset2);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
					"Service header: %u - %s", 
					service_num,
					val_to_str(service_num, intsrv_services_str, "Unknown"));
		    length = tvb_get_ntohs(tvb, offset2+2);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2, 
					"Length of service %u data: %u words, " 
					"not including header", 
					service_num,
					length);

		    mylen -= 4;
		    offset2 += 4;

		    switch(service_num) {

		    case QOS_CONTROLLED_LOAD :
		    case QOS_GUARANTEED :
			/* Treat both these the same for now */
			param_id = tvb_get_guint8(tvb, offset2);
			proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
					    "Parameter %u - %s", 
					    param_id,
					    val_to_str(param_id, svc_vals, "Unknown"));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
					    "Parameter %u flags: %x", 
					    param_id,
					    tvb_get_guint8(tvb, offset2+1));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    param_id,
					    tvb_get_ntohs(tvb, offset2+2));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
					    "Token bucket rate: %ld", 
					    tvb_ieee_to_long(tvb, offset2+4));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
					    "Token bucket size: %ld", 
					    tvb_ieee_to_long(tvb, offset2+8));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+12, 4,
					    "Peak data rate: %ld", 
					    tvb_ieee_to_long(tvb, offset2+12));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, 4,
					    "Minimum policed unit: %u", 
					    tvb_get_ntohl(tvb, offset2+16));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+20, 4,
					    "Maximum policed unit: %u", 
					    tvb_get_ntohl(tvb, offset2+20));
			if (service_num != QOS_GUARANTEED)
			    break;
			
			/* Guaranteed-rate RSpec */
			param_id = tvb_get_guint8(tvb, offset2+24);
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+24, 1,
					    "Parameter %u - %s", 
					    param_id,
					    val_to_str(param_id, svc_vals, "Unknown"));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+25, 1, 
					    "Parameter %u flags: %x", 
					    param_id,
					    tvb_get_guint8(tvb, offset2+25));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+26, 2,
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    param_id,
					    tvb_get_ntohs(tvb, offset2+26));

			proto_tree_add_text(rsvp_object_tree, tvb, offset2+28, 4,
					    "Rate: %ld", 
					    tvb_ieee_to_long(tvb, offset2+28));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+32, 4,
					    "Slack term: %u", 
					    tvb_get_ntohl(tvb, offset2+32));
			break;

		    case QOS_QUALITATIVE :
			param_id = tvb_get_guint8(tvb, offset2);
			proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, 
					    "Parameter %u - %s", 
					    param_id,
					    val_to_str(param_id, svc_vals, "Unknown"));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
					    "Parameter %u flags: %x", 
					    param_id,
					    tvb_get_guint8(tvb, offset2+1));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    param_id,
					    tvb_get_ntohs(tvb, offset2+2));
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
					    "Maximum policed unit: %u", 
					    tvb_get_ntohl(tvb, offset2+4));
			
			break;
		    }
		    offset2 += length*4;
		    mylen -= length*4;
		}
		break;
	    }

	    case RSVP_CLASS_ADSPEC : {
		proto_tree *adspec_tree;

		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_adspec);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;

		proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
				    "Message format version: %u", 
				    tvb_get_guint8(tvb, offset2)>>4);
		proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
				    "Data length: %u words, not including header", 
				    tvb_get_ntohs(tvb, offset2+2));
		mylen -= 4;
		offset2 += 4;
		while (mylen > 0) {
		    guint8 service_num;
		    guint8 break_bit;
		    guint16 length;
		    char *str;

		    service_num = tvb_get_guint8(tvb, offset2);
		    str = val_to_str(service_num, intsrv_services_str, "Unknown");
		    break_bit = tvb_get_guint8(tvb, offset2+1);
		    length = tvb_get_ntohs(tvb, offset2+2);
		    ti = proto_tree_add_text(rsvp_object_tree, tvb, offset2, 
					     (length+1)*4,
					     str);
		    adspec_tree = proto_item_add_subtree(ti,
							 ett_rsvp_adspec_subtree);
		    proto_tree_add_text(adspec_tree, tvb, offset2, 1,
					"Service header %u - %s",
					service_num, str);
		    proto_tree_add_text(adspec_tree, tvb, offset2+1, 1,
					(break_bit&0x80)?
					"Break bit set":"Break bit not set");
		    proto_tree_add_text(adspec_tree, tvb, offset2+2, 2, 
					"Data length: %u words, not including header", 
					length);
		    mylen -= 4;
		    offset2 += 4;
		    i = length*4;
		    while (i > 0) {
		    	guint8 id;
		    	guint16 phdr_length;

			id = tvb_get_guint8(tvb, offset2);
			phdr_length = tvb_get_ntohs(tvb, offset2+2);
			str = match_strval(id, adspec_params);
			if (str) {
			    switch(id) {
			    case 4:
			    case 8:
			    case 10:
			    case 133:
			    case 134:
			    case 135:
			    case 136:
				/* 32-bit unsigned integer */
				proto_tree_add_text(adspec_tree, tvb, offset2,
						    (phdr_length+1)<<2,
						    "%s - %u (type %u, length %u)",
						    str,
						    tvb_get_ntohl(tvb, offset2+4),
						    id, phdr_length);
				break;
				
			    case 6:
				/* IEEE float */
				proto_tree_add_text(adspec_tree, tvb, offset2,
						    (phdr_length+1)<<2,
						    "%s - %lu (type %u, length %u)",
						    str,
						    tvb_ieee_to_long(tvb, offset2+4),
						    id, phdr_length);
				break;
			    default: 
				proto_tree_add_text(adspec_tree, tvb, offset2, 
						    (phdr_length+1)<<2,
						    "%s (type %u, length %u)",
						    str,
						    id, phdr_length);
			    }
			} else {
			    proto_tree_add_text(adspec_tree, tvb, offset2, 
						(phdr_length+1)<<2,
						"Unknown (type %u, length %u)",
						id, phdr_length);
			}
			offset2 += (phdr_length+1)<<2;
			i -= (phdr_length+1)<<2;
			mylen -= (phdr_length+1)<<2;
		    }
		}
		break;
	    }

	    case RSVP_CLASS_INTEGRITY :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_integrity);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		goto default_class;

	    case RSVP_CLASS_POLICY :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_policy);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		goto default_class;

	    case RSVP_CLASS_LABEL_REQUEST : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_label_request);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    unsigned short l3pid = tvb_get_ntohs(tvb, offset2+2);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
					"L3PID: %s (0x%04x)",
					val_to_str(l3pid, etype_vals, "Unknown"),
					l3pid);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		    break;
		}
		}
		break;
	    
	    case RSVP_CLASS_LABEL : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_label);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1");
		    for (i=1, l = 0; l < mylen; l+=4, i++)
			proto_tree_add_text(rsvp_object_tree, tvb, offset2+l, 4,
					    "Label %d: %u %s", 
					    i, tvb_get_ntohl(tvb, offset2+l), 
					    l == mylen - 4 ? 
					    "(Top label)" : "");
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		    break;
		}
		}
		break;
	    
	    case RSVP_CLASS_SESSION_ATTRIBUTE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_session_attribute);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 7: {
		    guint8 flags;
		    guint8 name_len;

		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 7 - IPv4 LSP");
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
					"Setup priority: %u",
					tvb_get_guint8(tvb, offset2));
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
					"Hold priority: %u",
					tvb_get_guint8(tvb, offset2+1));
		    flags = tvb_get_guint8(tvb, offset2+2);
		    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 1,
					      "Flags: 0x%02x", flags);
		    rsvp_sa_flags_tree = proto_item_add_subtree(ti2, 
								ett_rsvp_session_attribute_flags);
		    proto_tree_add_text(rsvp_sa_flags_tree, tvb, offset2+2, 1,
					decode_boolean_bitfield(flags, 0x01, 8,
					    "Local protection desired",
					    "Local protection not desired"));
		    proto_tree_add_text(rsvp_sa_flags_tree, tvb, offset2+2, 1,
					decode_boolean_bitfield(flags, 0x02, 8,
					    "Merging permitted",
					    "Merging not permitted"));
		    proto_tree_add_text(rsvp_sa_flags_tree, tvb, offset2+2, 1,
					decode_boolean_bitfield(flags, 0x04, 8,
					    "Ingress node may reroute",
					    "Ingress node may not reroute"));
		    
		    name_len = tvb_get_guint8(tvb, offset2+3);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+3, 1,
					"Name length: %u", name_len);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, name_len,
					"Name: %.*s",
					name_len,
					tvb_get_ptr(tvb, offset2+4, name_len));
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		    break;
		}
		}
		break;

	    case RSVP_CLASS_EXPLICIT_ROUTE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_explicit_route);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1");
		    for (i=1, l = 0; l < mylen; i++) {
			j = tvb_get_guint8(tvb, offset2+l) & 0x7f;
			switch(j) {
			case 1: /* IPv4 */
			    k = tvb_get_guint8(tvb, offset2+l) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, 
						      offset2+l, 8,
						      "IPv4 Subobject - %s, %s",
						      ip_to_str(tvb_get_ptr(tvb, offset2+l+2, 4)),
						      k ? "Loose" : "Strict");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: 1 (IPv4)");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+2, 4,
						"IPv4 hop: %s",
						ip_to_str(tvb_get_ptr(tvb, offset2+l+2, 4)));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+6, 1, 
						"Prefix length: %u",
						tvb_get_guint8(tvb, offset2+l+6));
			    break;

			case 2: /* IPv6 */
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, 
						      offset2+l, 20,
						      "IPv6 Subobject");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    k = tvb_get_guint8(tvb, offset2+l) & 0x80;
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: 2 (IPv6)");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+2, 16,
						"IPv6 hop: %s",
						ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2+l+2, 16)));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+18, 1,
						"Prefix length: %u",
						tvb_get_guint8(tvb, offset2+l+6));
			    break;

			case 32: /* AS */
			    k = tvb_get_ntohs(tvb, offset2+l+2);
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, 
						      offset2+l, 4,
						      "Autonomous System %u",
						      k);
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: 32 (Autonomous System Number)");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+2, 2,
						"Autonomous System %u", k);
			    break;

			case 64: /* Path Term */
			    k = tvb_get_guint8(tvb, offset2+l) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
						      offset2+l, 4,
						      "LSP Path Termination");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: 64 (MPLS LSP Path Termination)");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));
			    break;

			default: /* Unknown subobject */
			    k = tvb_get_guint8(tvb, offset2+l) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, 
						      offset2+l,
						      tvb_get_guint8(tvb, offset2+l+1),
						      "Unknown subobject: %d", j);
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: %u (Unknown)", j);
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));

			}

			l += tvb_get_guint8(tvb, offset2+l+1);
		    }
		    break;
		}
		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		    break;
		}
		}
		break;
	    

	    case RSVP_CLASS_RECORD_ROUTE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_record_route);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
		mylen = obj_length - 4;
		switch(type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: 1");
		    for (i=1, l = 0; l < mylen; i++) {
			j = tvb_get_guint8(tvb, offset2+l);
			switch(j) {
			case 1: /* IPv4 */
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, 
						      offset2+l, 8,
						      "IPv4 Subobject - %s",
						      ip_to_str(tvb_get_ptr(tvb, offset2+l+2, 4)));
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_record_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: 1 (IPv4)");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+2, 4,
						"IPv4 hop: %s",
						ip_to_str(tvb_get_ptr(tvb, offset2+l+2, 4)));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+6, 1,
						"Prefix length: %u",
						tvb_get_guint8(tvb, offset2+l+6));
			    break;

			case 2: /* IPv6 */
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, 
						      offset2+l, 20,
						      "IPv6 Subobject");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_record_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: 2 (IPv6)");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+2, 16,
						"IPv6 hop: %s",
						ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset2+l+2, 16)));
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+18, 1,
						"Prefix length: %u",
						tvb_get_guint8(tvb, offset2+l+6));
			    break;

			default: /* Unknown subobject */
			    k = tvb_get_guint8(tvb, offset2+l) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, 
						      offset2+l,
						      tvb_get_guint8(tvb, offset2+l+1),
						      "Unknown subobject: %u",
						      j);
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_record_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l, 1,
						"Type: %u (Unknown)", j);
			    proto_tree_add_text(rsvp_ero_subtree, tvb, offset2+l+1, 1,
						"Length: %u",
						tvb_get_guint8(tvb, offset2+l+1));

			}

			l += tvb_get_guint8(tvb, offset2+l+1);
		    }
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, 
					"C-type: Unknown (%u)",
					type);
		    proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
					"Data (%d bytes)", mylen);
		    break;
		}
		}
		break;
	    
	    default :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_unknown_class);
		proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
				    "Length: %u", obj_length);
		proto_tree_add_text(rsvp_object_tree, tvb, offset+2, 1, 
				    "Class number: %u - %s", 
				    class, object_type);
	    default_class:
		mylen = obj_length - 4;
		proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
				    "Data (%d bytes)", mylen);
		break;

	    case RSVP_CLASS_NULL :
		break;

	    }  
	    
	    offset += obj_length;
	    len += obj_length;
	}
    }
}

void
proto_register_rsvp(void)
{
	static gint *ett[] = {
		&ett_rsvp,
		&ett_rsvp_hdr,
		&ett_rsvp_session,
		&ett_rsvp_hop,
		&ett_rsvp_time_values,
		&ett_rsvp_error,
		&ett_rsvp_scope,
		&ett_rsvp_style,
		&ett_rsvp_confirm,
		&ett_rsvp_sender_template,
		&ett_rsvp_filter_spec,
		&ett_rsvp_sender_tspec,
		&ett_rsvp_flowspec,
		&ett_rsvp_adspec,
		&ett_rsvp_adspec_subtree,
		&ett_rsvp_integrity,
		&ett_rsvp_policy,
		&ett_rsvp_label,
		&ett_rsvp_label_request,
		&ett_rsvp_session_attribute,
		&ett_rsvp_session_attribute_flags,
		&ett_rsvp_explicit_route,
		&ett_rsvp_explicit_route_subobj,
		&ett_rsvp_record_route,
		&ett_rsvp_record_route_subobj,
		&ett_rsvp_unknown_class,
	};

        proto_rsvp = proto_register_protocol("Resource ReserVation Protocol (RSVP)",
	    "RSVP", "rsvp");
        proto_register_field_array(proto_rsvp, rsvpf_info, array_length(rsvpf_info));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rsvp(void)
{
	dissector_add("ip.proto", IP_PROTO_RSVP, dissect_rsvp, proto_rsvp);
}
