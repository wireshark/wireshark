/* packet-rsvp.c
 * Routines for RSVP packet disassembly
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-rsvp.c,v 1.18 2000/03/14 06:03:24 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <glib.h>
#include "packet.h"
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "packet-rsvp.h"
#include "ieee-float.h"

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
    {RSVP_MSG_RTEAR_CONFIRM, "RESV TEAR CONFIRM Message"}
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
    {RSVP_ERROR_TRAFFIC_SYSTEM, "Traffic Control System Error"}
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
    { RSVP_SE, "Shared-Explicit" }
};

/*------------------------------*
 * Object definitions
 *------------------------------*/

/*
 * Base RSVP object
 */
typedef struct {
    guint16 length;
    guint8 class;	
    guint8 type;
    /* Data follows, as a sequence of bytes */
} rsvp_object;

/*
 * RSVP message header
 */

typedef struct {
    guint8    ver_flags;		/* RSVP Version & flags */
    guint8    message_type;		/* type of message */
    guint16   cksum;			/* IP Checksum */
    guint8    sending_ttl;		/* ttl of message */
    guint8    reserved_byte;		/* reserved */
    guint16   rsvp_length;		/* length of RSVP data */
    /* Objects follow, as a sequence of "rsvp_object"s */
} rsvp_header;

/*
 * NULL object 
*/
typedef struct {
    rsvp_object base;
} rsvp_null;

/*
 * SESSION object
 */
typedef struct {
    rsvp_object base;
    guint32 destination;
    guint8 protocol;
    guint8 flags;
    guint16 port;
} rsvp_session_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr destination;
    guint8 protocol;
    guint8 flags;
    guint16 port;
} rsvp_session_ipv6;

/*
 * HOP object
 * Can be a PHOP or a NHOP
 */
typedef struct {
    rsvp_object base;
    guint32 neighbor;
    guint32 lif_handle;
} rsvp_hop_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr neighbor;
    guint32 lif_handle;
} rsvp_hop_ipv6;

/*
 * TIME_VALUES object
 */
typedef struct {
    rsvp_object base;
    gint32 refresh_ms;
} rsvp_time_values;

/*
 * ERROR object
 */
typedef struct {
    rsvp_object base;
    guint32 error_node;
    guint8 flags;
    guint8 error_code;
    guint16 error_value;
} rsvp_error_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr error_node;
    guint8 flags;
    guint8 error_code;
    guint16 error_value;
} rsvp_error_ipv6;

/*
 * CONFIRM object
 */
typedef struct {
    rsvp_object base;
    guint32 receiver;
} rsvp_confirm_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr receiver;
} rsvp_confirm_ipv6;

/*
 * SCOPE object
 */
typedef struct {
    rsvp_object base;
    /* Source follows, as a sequence of 32-bit integers */
} rsvp_scope;

/*
 * STYLE object
 */
typedef struct {
    rsvp_object base;
    guint32 reservation_type;
} rsvp_style;

/*
 * Defines a subset of session data packets that should receive the
 * desired QoS (specified by an FLOWSPEC object), in a RESV message.
 */
typedef struct {
    rsvp_object base;
    guint32 source;			/* source sending data */
    guint16 unused;
    guint16 udp_source_port;		/* port number */
} rsvp_filter_ipv4;

/*
 * Contains a sender IP address and perhaps some additional
 * demultiplexing information to identify a sender, in a PATH
 * message.
 */
typedef struct {
    rsvp_object base;
    guint32 source;			/* source sending data */
    guint16 __reserved;
    guint16 source_port;		/* port number */
} rsvp_template_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr source;		/* source sending data */
    guint16 __reserved;
    guint16 source_port;		/* port number */
} rsvp_template_ipv6;

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
};

static value_string svc_vals[] = {
    { 127, "Token bucket TSpec" },
    { 128, "Qualitative TSpec" },
    { 130, "Guaranteed-rate RSpec" }
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

/*
 * Subobjects for Integrated Services
 */

typedef struct {
    guint8 service_num;
    guint8 break_bit;
    guint16 length;
} service_hdr;

typedef struct {					
    service_hdr svchdr;

    guint8	param_id;
    guint8	flags_tspec;
    guint16	parameter_length;

    guint32	rate;
    guint32	depth;
    guint32	peak;
    guint32	min_unit;
    guint32	max_unit;
} IS_tspec; /* RFC2210 */

typedef struct {
    service_hdr svchdr;
    
    guint8	param_id;
    guint8	flags_tspec;
    guint16	parameter_length;

    guint32	max_unit;
} QUAL_tspec; /* Qualitative */

typedef struct {
    rsvp_object base;
    guint8	version;	
    guint8 	__reserved_;
    guint16	length_in_words;

    /* Data follows, as a sequence of bytes */
} rsvp_tspec;

typedef struct {
    guint8	param_id;
    guint8	flags_rspec;
    guint16	param2_length;
    guint32	requested_rate;
    guint32	slack;
} IS_rspec;

typedef struct {
    IS_tspec tspec;
    IS_rspec rspec;
} IS_flowspec; /* RFC 2210 */

typedef struct {
    service_hdr svchdr;
    
    guint8	param_id;
    guint8	flags_tspec;
    guint16	parameter_length;

    guint32	max_unit;
} QUAL_flowspec; /* Qualitative */


typedef struct {
    rsvp_object base;
    guint8	version;	
    guint8 	__reserved_;
    guint16	length_in_words;

    /* Data follows, as a sequence of bytes */
} rsvp_flowspec;
					

typedef struct {
    guint8 id;
    guint8 flags;
    guint16 length;
    guint32 dataval;
} param_hdr;
    
static value_string adspec_params[] = { 
    {4, "IS Hop Count"},
    {6, "Path b/w estimate"},
    {8, "Minimum path latency"},
    {10, "Composed MTU"},
    {133, "End-to-end composed value for C"},
    {134, "End-to-end composed value for D"},
    {135, "Since-last-reshaping point composed C"},
    {136, "Since-last-reshaping point composed D"},
};

/* -------------------- Stuff for MPLS/TE objects -------------------- */

typedef struct {
    rsvp_object base;
    guint32 labels[0];
} label;

typedef struct {
    rsvp_object base;
    guint16 _reserved;
    guint16 l3pid;
} label_request;

typedef struct {
    rsvp_object base;
    guint8 setup_prio;
    guint8 hold_prio;
    guint8 flags;
    guint8 name_len;
    guint8 name[0];
} session_attribute;

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
     { "Message Type", "rsvp.msg", FT_UINT8, BASE_NONE, message_type_vals, 0x0,
     	"" }},

    /* Message type shorthands */
    {&rsvp_filter[RSVPF_PATH], 
     { "Path Message", "rsvp.path", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RESV], 
     { "Resv Message", "rsvp.resv", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_PATHERR], 
     { "Path Error Message", "rsvp.perr", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RESVERR], 
     { "Resv Error Message", "rsvp.rerr", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_PATHTEAR], 
     { "Path Tear Message", "rsvp.ptear", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RESVTEAR], 
     { "Resv Tear Message", "rsvp.rtear", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RCONFIRM], 
     { "Resv Confirm Message", "rsvp.resvconf", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    /* Object present */
    {&rsvp_filter[RSVPF_OBJECT], 
     { "", "rsvp.object", FT_UINT8, BASE_NONE, rsvp_class_vals, 0x0,
     	"" }},

    /* Object present shorthands */
    {&rsvp_filter[RSVPF_SESSION], 
     { "SESSION", "rsvp.session", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_HOP], 
     { "HOP", "rsvp.hop", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_INTEGRITY], 
     { "INTEGRITY", "rsvp.integrity", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_TIME_VALUES], 
     { "TIME VALUES", "rsvp.time", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_ERROR], 
     { "ERROR", "rsvp.error", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SCOPE], 
     { "SCOPE", "rsvp.scope", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_STYLE], 
     { "STYLE", "rsvp.style", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_FLOWSPEC], 
     { "FLOWSPEC", "rsvp.flowspec", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_FILTER_SPEC], 
     { "FILTERSPEC", "rsvp.filter", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SENDER], 
     { "SENDER TEMPLATE", "rsvp.sender", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_TSPEC], 
     { "SENDER TSPEC", "rsvp.tspec", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_ADSPEC], 
     { "ADSPEC", "rsvp.adspec", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_POLICY], 
     { "POLICY", "rsvp.policy", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_CONFIRM], 
     { "CONFIRM", "rsvp.confirm", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_LABEL], 
     { "LABEL", "rsvp.label", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_LABEL_REQUEST], 
     { "LABEL REQUEST", "rsvp.label_request", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_ATTRIBUTE], 
     { "SESSION ATTRIBUTE", "rsvp.session_attribute", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_EXPLICIT_ROUTE], 
     { "EXPLICIT ROUTE", "rsvp.explicit_route", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_RECORD_ROUTE], 
     { "RECORD ROUTE", "rsvp.record_route", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_UNKNOWN_OBJ], 
     { "Unknown object", "rsvp.obj_unknown", FT_UINT8, BASE_NONE, NULL, 0x0,
     	"" }},

    /* Session fields */
    {&rsvp_filter[RSVPF_SESSION_IP], 
     { "Destination address", "rsvp.session.ip", FT_IPv4, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_PORT], 
     { "Port number", "rsvp.session.port", FT_UINT16, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_PROTO], 
     { "Protocol", "rsvp.session.proto", FT_UINT8, BASE_NONE, VALS(proto_vals), 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_TUNNEL_ID], 
     { "Tunnel ID", "rsvp.session.tunnel_id", FT_UINT16, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID], 
     { "Extended tunnel ID", "rsvp.session.ext_tunnel_id", FT_UINT32, BASE_NONE, NULL, 0x0,
     	"" }},

    /* Sender template/Filterspec fields */
    {&rsvp_filter[RSVPF_SENDER_IP], 
     { "Sender IPv4 address", "rsvp.sender.ip", FT_IPv4, BASE_NONE, NULL, 0x0,
     	"" }},

    {&rsvp_filter[RSVPF_SENDER_PORT], 
     { "Sender port number", "rsvp.sender.port", FT_UINT16, BASE_NONE, NULL, 0x0,
       "" }},

    {&rsvp_filter[RSVPF_SENDER_LSP_ID], 
     { "Sender LSP ID", "rsvp.sender.lsp_id", FT_UINT16, BASE_NONE, NULL, 0x0,
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

void 
dissect_rsvp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
    proto_tree *rsvp_tree = NULL, *ti, *ti2; 
    proto_tree *rsvp_header_tree;
    proto_tree *rsvp_object_tree;
    proto_tree *rsvp_sa_flags_tree;
    proto_tree *rsvp_ero_subtree;
    char *packet_type, *object_type;
    rsvp_header *hdr;
    rsvp_object *obj;
    int i, j, k, l, len, mylen;
    int msg_length;
    int obj_length;
    int offset2;
    struct e_in6_addr *ip6a;
    guint32 ip_addr;

    hdr = (rsvp_header *)&pd[offset];
    packet_type = match_strval(hdr->message_type, message_type_vals);
    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "RSVP");
    if (check_col(fd, COL_INFO)) {
        if (packet_type != NULL)
            col_add_str(fd, COL_INFO, packet_type); 
        else
            col_add_fstr(fd, COL_INFO, "Unknown (%u)", hdr->message_type); 
    }

    if (tree) {
	msg_length = pntohs(pd+offset+6);
	ti = proto_tree_add_item(tree, proto_rsvp, offset, msg_length, NULL);
	rsvp_tree = proto_item_add_subtree(ti, ett_rsvp);

	ti = proto_tree_add_text(rsvp_tree, offset, 
				 sizeof(rsvp_header), "RSVP Header"); 
	rsvp_header_tree = proto_item_add_subtree(ti, ett_rsvp_hdr);

        proto_tree_add_text(rsvp_header_tree, offset, 1, "RSVP Version: %u", 
			    (hdr->ver_flags & 0xf0)>>4);  
	proto_tree_add_text(rsvp_header_tree, offset, 1, "Flags: %02X",
			    hdr->ver_flags & 0xf);  
	proto_tree_add_item(rsvp_header_tree, rsvp_filter[RSVPF_MSG], 
			    offset+1, 1, hdr->message_type);
	if (hdr->message_type >= RSVPF_MAX) {
	    proto_tree_add_text(rsvp_header_tree, offset+1, 1, "Message Type: %u - Unknown",
				hdr->message_type);
	    return;
	}
	proto_tree_add_item_hidden(rsvp_header_tree, rsvp_filter[RSVPF_MSG + hdr->message_type], 
				   offset+1, 1, 1);
	proto_tree_add_text(rsvp_header_tree, offset + 2 , 2, "Message Checksum");
	proto_tree_add_text(rsvp_header_tree, offset + 4 , 1, "Sending TTL: %u",
			    hdr->sending_ttl);
	proto_tree_add_text(rsvp_header_tree, offset + 6 , 2, "Message length: %d",
			    msg_length);

	offset += sizeof(rsvp_header);
	len = 0;
	while (len + sizeof(rsvp_header) < msg_length) {
	    obj = (rsvp_object *)&pd[offset];
	    obj_length = pntohs(pd+offset);
	    if (!BYTES_ARE_IN_FRAME(offset, obj_length)) {
		proto_tree_add_text(rsvp_tree, offset, 1, 
				    "Further data not captured");
		break;
	    }
	    
	    object_type = match_strval(obj->class, rsvp_class_vals);
	    if (!object_type) object_type = "Unknown";
	    ti = proto_tree_add_item_hidden(rsvp_tree, rsvp_filter[RSVPF_OBJECT], 
					    offset, obj_length, obj->class);
	    ti = proto_tree_add_item(rsvp_tree, rsvp_filter[rsvp_class_to_filter_num(obj->class)], 
				     offset, obj_length, obj->class);

	    offset2 = offset + sizeof(rsvp_object);

	    switch(obj->class) {

	    case RSVP_CLASS_SESSION : 		
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_session);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    memcpy(&ip_addr, pd+offset2, 4);
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_IP], 
					offset2, 4, ip_addr);

		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_PROTO], 
					offset2+4, 1, *(pd+offset2+4));
		    proto_tree_add_text(rsvp_object_tree, offset2+5, 1,
					"Flags: %x", pntohs(pd+offset2+5));
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_PORT], 
					offset2+6, 2, pntohs(pd+offset2+6));
		    break;
		}

		case 2: {
		    rsvp_session_ipv6 *sess = (rsvp_session_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Destination address: %s", 
					ip6_to_str(&(sess->destination)));
		    proto_tree_add_text(rsvp_object_tree, offset2+16, 1,
					"Protocol: %u", sess->protocol);
		    proto_tree_add_text(rsvp_object_tree, offset2+17, 1,
					"Flags: %x", sess->flags);
		    proto_tree_add_text(rsvp_object_tree, offset2+18, 2,
					"Destination port: %u", 
					pntohs(pd+offset2+18));
		    break;
		}
		
		case 7: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 7 - IPv4 LSP");
		    memcpy(&ip_addr, pd+offset2, 4);
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_IP], 
					offset2, 4, ip_addr);

		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_TUNNEL_ID], 
					offset2+6, 2, pntohs(pd+offset2+6));

		    memcpy(&ip_addr, pd+offset2+8, 4);
		    proto_tree_add_text(rsvp_object_tree, offset2+8, 4, 
					"Extended Tunnel ID: %lu (%s)", 
					(unsigned long)ntohl(ip_addr),
					ip_to_str(pd+offset2+8));
		    proto_tree_add_item_hidden(rsvp_object_tree, rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID], 
					offset2+8, 4, ip_addr);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		
	    case RSVP_CLASS_HOP :		
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_hop);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    rsvp_hop_ipv4 *hop = (rsvp_hop_ipv4 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Neighbor address: %s", 
					ip_to_str((guint8 *) &(hop->neighbor)));
		    proto_tree_add_text(rsvp_object_tree, offset2+4, 4,
					"Logical interface: %0x", 
					pntohl(pd+offset2+4));
		    break;
		}

		case 2: {
		    rsvp_hop_ipv6 *hop = (rsvp_hop_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Neighbor address: %s", 
					ip6_to_str(&(hop->neighbor)));
		    proto_tree_add_text(rsvp_object_tree, offset2+16, 4,
					"Logical interface: %0x", 
					pntohl(pd+offset2+16));
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		
	    case RSVP_CLASS_TIME_VALUES : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_time_values);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Refresh interval: %u ms (%u seconds)",
					pntohl(pd+offset2),
					pntohl(pd+offset2)/1000);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;

	    case RSVP_CLASS_ERROR :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_error);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    rsvp_error_ipv4 *err = (rsvp_error_ipv4 *)obj;
		    char *err_str = match_strval(err->error_code, rsvp_error_vals);
		    if (!err_str) err_str = "Unknown";

		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Error node: %s",
					ip_to_str((guint8 *) &(err->error_node)));
		    proto_tree_add_text(rsvp_object_tree, offset2+4, 1,
					"Flags: %02x", err->flags);
		    proto_tree_add_text(rsvp_object_tree, offset2+5, 1,
					"Error code: %u - %s", err->error_code,
					err_str);
		    proto_tree_add_text(rsvp_object_tree, offset2+6, 2,
					"Error value: %u", pntohs(pd+offset2+6));
		    
		    break;
		}

		case 2: {
		    rsvp_error_ipv6 *err = (rsvp_error_ipv6 *)obj;
		    char *err_str = match_strval(err->error_code, rsvp_error_vals);
		    if (!err_str) err_str = "Unknown";
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Error node: %s",
					ip6_to_str(&(err->error_node)));
		    proto_tree_add_text(rsvp_object_tree, offset2+16, 1,
					"Flags: %02x", err->flags);
		    proto_tree_add_text(rsvp_object_tree, offset2+17, 1,
					"Error code: %u - %s", err->error_code,
					err_str);
		    proto_tree_add_text(rsvp_object_tree, offset2+18, 2,
					"Error value: %u", pntohs(pd+offset2+18));
		    
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		

	    case RSVP_CLASS_SCOPE : 
		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_scope);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    unsigned long ip;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    while (mylen > sizeof(rsvp_object)) {
			ip = pntohl(pd+offset2);
			proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					    "IPv4 Address: %s",
					    ip_to_str((guint8 *) &ip));
			offset2 += 4;
			mylen -= 4;
		    }
		    break;
		}

		case 2: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    while (mylen>sizeof(rsvp_object)) {
			ip6a = (struct e_in6_addr *)pd+offset2;
			proto_tree_add_text(rsvp_object_tree, offset2, 16, 
					    "IPv6 Address: %s",
					    ip6_to_str(ip6a));
			offset2 += 16;
			mylen -= 16;
		    }
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;
		
	    case RSVP_CLASS_STYLE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_style);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    unsigned long ip = pntohl(pd+offset2);
		    char *style_str = match_strval(ip, style_vals);
		    if (!style_str) style_str = "Unknown";
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, offset2+5, 1,
					"Style: %lu - %s", ip, style_str);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;
	    
	    case RSVP_CLASS_CONFIRM :		
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_confirm);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    rsvp_confirm_ipv4 *confirm = (rsvp_confirm_ipv4 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    proto_tree_add_text(rsvp_object_tree, offset2, 4, 
					"Receiver address: %s", 
					ip_to_str((guint8 *) &(confirm->receiver)));
		    break;
		}

		case 2: {
		    rsvp_confirm_ipv6 *confirm = (rsvp_confirm_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 16, 
					"Receiver address: %s", 
					ip6_to_str(&(confirm->receiver)));
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;

	    case RSVP_CLASS_SENDER_TEMPLATE :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_sender_template);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		goto common_template;
	    case RSVP_CLASS_FILTER_SPEC :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_filter_spec);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
	    common_template:
		switch(obj->type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1 - IPv4");
		    memcpy(&ip_addr, pd+offset2, 4);
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SENDER_IP], 
					offset2, 4, ip_addr);

		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SENDER_PORT], 
					offset2+6, 2, pntohs(pd+offset2+6));
		    break;
		}

		case 2: {
		    rsvp_template_ipv6 *tem = (rsvp_template_ipv6 *)obj;
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 2 - IPv6");
		    proto_tree_add_text(rsvp_object_tree, offset2, 16, 
					"Source address: %s", 
					ip6_to_str(&(tem->source)));
		    proto_tree_add_text(rsvp_object_tree, offset2+18, 2,
					"Source port: %u", pntohs(pd+offset2+18));
		    break;
		}
		
		case 7: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 7 - IPv4 LSP");
		    memcpy(&ip_addr, pd+offset2, 4);
		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SENDER_IP], 
					offset2, 4, ip_addr);

		    proto_tree_add_item(rsvp_object_tree, rsvp_filter[RSVPF_SENDER_LSP_ID], 
					offset2+6, 2, pntohs(pd+offset2+6));
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%u)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		}
		}
		break;

	    case RSVP_CLASS_SENDER_TSPEC : {
		rsvp_tspec *tspec = (rsvp_tspec *)obj;
		IS_tspec *ist;
		QUAL_tspec *qt;
		service_hdr  *sh;
		char *str;

		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_sender_tspec);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);

		proto_tree_add_text(rsvp_object_tree, offset2, 1, 
				    "Message format version: %u", 
				    tspec->version>>4);
		proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				    "Data length: %u words, not including header", 
				    pntohs(pd+offset2+2));

		mylen -=4;
		offset2 +=4;
		while (mylen > 4) {
		    sh = (service_hdr *)(pd+offset2);
		    str = match_strval(sh->service_num, qos_vals);
		    if (!str) str = "Unknown";

		    proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					"Service header: %u - %s", 
					sh->service_num, str);
		    proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					"Length of service %u data: %u words, " 
					"not including header", 
					sh->service_num,
					ntohs(sh->length));

		    offset2+=4; mylen -=4; 

		    switch(sh->service_num) {
			
		    case QOS_TSPEC :
			ist = (IS_tspec *)sh;

			/* Token bucket TSPEC */
			str = match_strval(ist->param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %u - %s", 
					    ist->param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %u flags: %x", 
					    ist->param_id, ist->flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    ist->param_id,
					    /* pntohs(pd+offset2+10)); */
					    ntohs(ist->parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Token bucket rate: %ld", 
					    pieee_to_long(pd+offset2+4));
			proto_tree_add_text(rsvp_object_tree, offset2+8, 4, 
					    "Token bucket size: %ld", 
					    pieee_to_long(pd+offset2+8));
			proto_tree_add_text(rsvp_object_tree, offset2+12, 4, 
					    "Peak data rate: %ld", 
					    pieee_to_long(pd+offset2+12));
			proto_tree_add_text(rsvp_object_tree, offset2+16, 4, 
					    "Minimum policed unit: %u", 
					    pntohl(pd+offset2+16));
			proto_tree_add_text(rsvp_object_tree, offset2+20, 4, 
					    "Maximum policed unit: %u", 
					    pntohl(pd+offset2+20));

			break;

		    case QOS_QUALITATIVE :
			qt = (QUAL_tspec *)sh;

			/* Token bucket TSPEC */
			str = match_strval(qt->param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %u - %s", 
					    qt->param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %u flags: %x", 
					    qt->param_id, qt->flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    qt->param_id,
					    /* pntohs(pd+offset2+10)); */
					    ntohs(qt->parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Maximum policed unit: %u", 
					    pntohl(pd+offset2+4));

			break;

		    }
		    offset2 += ntohs(sh->length)*4; 
		    mylen -= ntohs(sh->length)*4;
		}
		    
		break;
	    }

	    case RSVP_CLASS_FLOWSPEC : {
		rsvp_flowspec *flowspec = (rsvp_flowspec *)obj;
		IS_flowspec *isf;
		QUAL_flowspec *qf;
		service_hdr *sh;
		int mylen;

		char *str;

		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_flowspec);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);

		proto_tree_add_text(rsvp_object_tree, offset2, 1, 
				    "Message format version: %u", 
				    flowspec->version>>4);
		proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				    "Data length: %u words, not including header", 
				    pntohs(pd+offset2+2));

		mylen -=4;
		offset2+=4;
		while (mylen > 4) {
		    sh = (service_hdr *)(pd+offset2);
		    str = match_strval(sh->service_num, intsrv_services_str);
		    if (!str) str = "Unknown";

		    proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					"Service header: %u - %s", 
					sh->service_num, str);
		    proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					"Length of service %u data: %u words, " 
					"not including header", 
					sh->service_num,
					ntohs(sh->length));

		    offset2+=4; mylen -=4; 

		    switch(sh->service_num) {

		    case QOS_CONTROLLED_LOAD :
		    case QOS_GUARANTEED :
			/* Treat both these the same for now */
			isf = (IS_flowspec *)sh;

			str = match_strval(isf->tspec.param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %u - %s", 
					    isf->tspec.param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %u flags: %x", 
					    isf->tspec.param_id, isf->tspec.flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    isf->tspec.param_id,
					    ntohs(isf->tspec.parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Token bucket rate: %ld", 
					    pieee_to_long(pd+offset2+4));
			proto_tree_add_text(rsvp_object_tree, offset2+8, 4, 
					    "Token bucket size: %ld", 
					    pieee_to_long(pd+offset2+8));
			proto_tree_add_text(rsvp_object_tree, offset2+12, 4, 
					    "Peak data rate: %ld", 
					    pieee_to_long(pd+offset2+12));
			proto_tree_add_text(rsvp_object_tree, offset2+16, 4, 
					    "Minimum policed unit: %u", 
					    pntohl(pd+offset2+16));
			proto_tree_add_text(rsvp_object_tree, offset2+20, 4, 
					    "Maximum policed unit: %u", 
					    pntohl(pd+offset2+20));
			if (sh->service_num!=QOS_GUARANTEED)
			    break;
			
			/* Guaranteed-rate RSpec */
			str = match_strval(isf->rspec.param_id, svc_vals);
			if (!str) str="Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2+24, 1, 
					    "Parameter %u - %s", 
					    isf->rspec.param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+25, 1, 
					    "Parameter %u flags: %x", 
					    isf->rspec.param_id, isf->rspec.flags_rspec);
			proto_tree_add_text(rsvp_object_tree, offset2+26, 2, 
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    isf->rspec.param_id,
					    ntohs(isf->rspec.param2_length));

			proto_tree_add_text(rsvp_object_tree, offset2+28, 4, 
					    "Rate: %ld", 
					    pieee_to_long(pd+offset2+28));
			proto_tree_add_text(rsvp_object_tree, offset2+32, 4, 
					    "Slack term: %u", 
					    pntohl(pd+offset2+32));
			break;

		    case QOS_QUALITATIVE :
			qf = (QUAL_flowspec *)sh;

			str = match_strval(qf->param_id, svc_vals);
			if (!str) str = "Unknown";
			proto_tree_add_text(rsvp_object_tree, offset2, 1, 
					    "Parameter %u - %s", 
					    qf->param_id, str);
			proto_tree_add_text(rsvp_object_tree, offset2+1, 1, 
					    "Parameter %u flags: %x", 
					    qf->param_id, qf->flags_tspec);
			proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
					    "Parameter %u data length: %u words, " 
					    "not including header",
					    qf->param_id,
					    ntohs(qf->parameter_length));
			proto_tree_add_text(rsvp_object_tree, offset2+4, 4, 
					    "Maximum policed unit: %u", 
					    pntohl(pd+offset2+4));
			
			break;
		    }
		    offset2 += ntohs(sh->length)*4;
		    mylen -= ntohs(sh->length)*4;
		}

		break;
	    }

	    case RSVP_CLASS_ADSPEC : {
		proto_tree *adspec_tree;
		service_hdr *shdr;
		param_hdr *phdr; 

		char *str;

		mylen = obj_length;
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_adspec);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		
		proto_tree_add_text(rsvp_object_tree, offset2, 1, 
				    "Message format version: %u", 
				    (*((unsigned char *)pd+offset2))>>4);
		proto_tree_add_text(rsvp_object_tree, offset2+2, 2, 
				    "Data length: %u words, not including header", 
				    pntohs(pd+offset2+2));
		offset2+=4;
		mylen -= 4;
		while (mylen > 4) {
		    shdr = (service_hdr *)(pd + offset2);
		    str = match_strval(shdr->service_num, intsrv_services_str);

		    ti = proto_tree_add_text(rsvp_object_tree, offset2, 
					     (pntohs(&shdr->length)+1)<<2,
					     str?str:"Unknown");
		    adspec_tree = proto_item_add_subtree(ti,
							 ett_rsvp_adspec_subtree);
		    proto_tree_add_text(adspec_tree, offset2, 1,
					"Service header %u - %s",
					shdr->service_num, str);
		    proto_tree_add_text(adspec_tree, offset2+1, 1,
					(shdr->break_bit&0x80)?
					"Break bit set":"Break bit not set");
		    proto_tree_add_text(adspec_tree, offset2+2, 2, 
					"Data length: %u words, not including header", 
					pntohs(&shdr->length));
		    offset2+=4; i=(pntohs(&shdr->length)+1)<<2; mylen-=4;
		    while (i>4) {
			phdr = (param_hdr *)(pd + offset2);
			str = match_strval(phdr->id, adspec_params);
			if (str) {
			    switch(phdr->id) {
			    case 4:
			    case 8:
			    case 10:
			    case 133:
			    case 134:
			    case 135:
			    case 136:
				/* 32-bit unsigned integer */
				proto_tree_add_text(adspec_tree, offset2, 
						    (pntohs(&phdr->length)+1)<<2,
						    "%s - %lu (type %u, length %u)",
						    str, 
						    (unsigned long)pntohl(&phdr->dataval), 
						    phdr->id, pntohs(&phdr->length));
				break;
				
			    case 6:
				/* IEEE float */
				proto_tree_add_text(adspec_tree, offset2, 
						    (pntohs(&phdr->length)+1)<<2,
						    "%s - %lu (type %u, length %u)",
						    str, 
						    pieee_to_long(&phdr->dataval), 
						    phdr->id, pntohs(&phdr->length));
				break;
			    default: 
				proto_tree_add_text(adspec_tree, offset2, 
						    (pntohs(&phdr->length)+1)<<2,
						    "%s (type %u, length %u)",
						    str, 
						    phdr->id, pntohs(&phdr->length));
			    }
			} else {
			    proto_tree_add_text(adspec_tree, offset2, 
						(pntohs(&phdr->length)+1)<<2,
						"Unknown (type %u, length %u)",
						phdr->id, pntohs(&phdr->length));
			}
			offset2+=(pntohs(&phdr->length)+1)<<2;
			i-=(pntohs(&phdr->length)+1)<<2;
			mylen-=(pntohs(&phdr->length)+1)<<2;
		    }
		}
		break;
	    }

	    case RSVP_CLASS_INTEGRITY :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_integrity);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		goto default_class;

	    case RSVP_CLASS_POLICY :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_policy);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
		goto default_class;

	    case RSVP_CLASS_LABEL_REQUEST : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_label_request);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    unsigned short l3pid = pntohs(pd+offset2+2);
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    proto_tree_add_text(rsvp_object_tree, offset2+2, 2,
					"L3PID: 0x%04x", l3pid);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;
	    
	    case RSVP_CLASS_LABEL : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_label);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    for (i=1, l = 0; l < obj_length - 4; l+=4, i++)
			proto_tree_add_text(rsvp_object_tree, offset2+l, 4, 
					    "Label %d: %d %s", 
					    i, pntohl(pd+offset2+l), 
					    l == obj_length - 8 ? 
					    "(Top label)" : "");
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;
	    
	    case RSVP_CLASS_SESSION_ATTRIBUTE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_session_attribute);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 7: {
		    char s_name[64];
		    session_attribute *s_attr = (session_attribute *)&pd[offset];
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 7 - IPv4 LSP");
		    proto_tree_add_text(rsvp_object_tree, offset2, 1,
					"Setup priority: %d", s_attr->setup_prio);
		    proto_tree_add_text(rsvp_object_tree, offset2+1, 1,
					"Hold priority: %d", s_attr->hold_prio);
		    ti2 = proto_tree_add_text(rsvp_object_tree, offset2+2, 1,
					      "Flags: %0x", s_attr->flags);
		    rsvp_sa_flags_tree = proto_item_add_subtree(ti2, 
								ett_rsvp_session_attribute_flags);
		    proto_tree_add_text(rsvp_sa_flags_tree, offset2+2, 1, 
					".......%d: Local protection: %s", 
					s_attr->flags & 0x1 ? 1 : 0,
					s_attr->flags & 0x1 ? "Set" : "Not set");
		    proto_tree_add_text(rsvp_sa_flags_tree, offset2+2, 1, 
					"......%d.: Merging permitted: %s", 
					s_attr->flags & 0x2 ? 1 : 0,
					s_attr->flags & 0x2 ? "Set" : "Not set");
		    proto_tree_add_text(rsvp_sa_flags_tree, offset2+2, 1, 
					".....%d..: Ingress note may reroute: %s", 
					s_attr->flags & 0x4 ? 1 : 0,
					s_attr->flags & 0x4 ? "Set" : "Not set");
		    
		    proto_tree_add_text(rsvp_object_tree, offset2+3, 1,
					"Name length: %d", s_attr->name_len);
		    memset(s_name, 0, 64);
		    strncpy(s_name, s_attr->name, 60); 
		    if (s_attr->name_len>60) sprintf(&(s_name[60]), "...");
		    proto_tree_add_text(rsvp_object_tree, offset2+4, s_attr->name_len,
					"Name: %s", s_name);
		    break;
		}

		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;

	    case RSVP_CLASS_EXPLICIT_ROUTE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_explicit_route);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    for (i=1, l = 0; l < obj_length - 4; i++) {
			j = ((unsigned char)pd[offset2+l]) & 0x7f;
			switch(j) {
			case 1: /* IPv4 */
			    k = ((unsigned char)pd[offset2+l]) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, 8,
						      "IPv4 Subobject - %s, %s",
						      ip_to_str(&pd[offset2+l+2]), 
						      k ? "Loose" : "Strict");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: 1 (IPv4)");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+2, 4, 
						"IPv4 hop: %s", ip_to_str(&pd[offset2+l+2]));
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+6, 1, 
						"Prefix length: %d", pd[offset2+l+6]);
			    break;

			case 2: /* IPv6 */
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, 20,
						      "IPv6 Subobject");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    k = ((unsigned char)pd[offset2+l]) & 0x80;
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: 2 (IPv6)");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);
			    ip6a = (struct e_in6_addr *)pd+offset2+l+2;
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+2, 16, 
						"IPv6 hop: %s", ip6_to_str(ip6a));
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+18, 1, 
						"Prefix length: %d", pd[offset2+l+6]);
			    break;

			case 32: /* AS */
			    k = pntohs(offset2+l+2);
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, 4,
						      "Autonomous System %d", k);
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: 32 (Autonomous System Number)");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+2, 2, 
						"Autonomous System %d", k);
			    break;

			case 64: /* Path Term */
			    k = ((unsigned char)pd[offset2+l]) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, 4,
						      "LSP Path Termination");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: 64 (MPLS LSP Path Termination)");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);
			    break;

			default: /* Unknown subobject */
			    k = ((unsigned char)pd[offset2+l]) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, pd[offset2+l+1],
						      "Unknown subobject: %d", j);
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_explicit_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: %d (Unknown)", j);
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);

			}

			l += ((unsigned char)pd[offset2+l+1]);
		    }
		    break;
		}
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;
	    

	    case RSVP_CLASS_RECORD_ROUTE : 
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_record_route);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %d - %s", 
				    obj->class, object_type);
		switch(obj->type) {
		case 1: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: 1");
		    for (i=1, l = 0; l < obj_length - 4; i++) {
			j = (unsigned char)pd[offset2+l];
			switch(j) {
			case 1: /* IPv4 */
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, 8,
						      "IPv4 Subobject - %s",
						      ip_to_str(&pd[offset2+l+2]));
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_record_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: 1 (IPv4)");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+2, 4, 
						"IPv4 hop: %s", ip_to_str(&pd[offset2+l+2]));
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+6, 1, 
						"Prefix length: %d", pd[offset2+l+6]);
			    break;

			case 2: /* IPv6 */
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, 20,
						      "IPv6 Subobject");
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_record_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: 2 (IPv6)");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);
			    ip6a = (struct e_in6_addr *)pd+offset2+l+2;
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+2, 16, 
						"IPv6 hop: %s", ip6_to_str(ip6a));
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+18, 1, 
						"Prefix length: %d", pd[offset2+l+6]);
			    break;

			default: /* Unknown subobject */
			    k = ((unsigned char)pd[offset2+l]) & 0x80;
			    ti2 = proto_tree_add_text(rsvp_object_tree, 
						      offset2+l, pd[offset2+l+1],
						      "Unknown subobject: %d", j);
			    rsvp_ero_subtree = 
				proto_item_add_subtree(ti2, ett_rsvp_record_route_subobj); 
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						k ? "Loose Hop " : "Strict Hop");
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l, 1, 
						"Type: %d (Unknown)", j);
			    proto_tree_add_text(rsvp_ero_subtree, offset2+l+1, 1, 
						"Length: %d", pd[offset2+l+1]);

			}

			l += ((unsigned char)pd[offset2+l+1]);
		    }
		    break;
		}
		
		default: {
		    proto_tree_add_text(rsvp_object_tree, offset+3, 1, 
					"C-type: Unknown (%d)",
					obj->type);
		    i = obj_length - sizeof(rsvp_object);
		    proto_tree_add_text(rsvp_object_tree, offset2, i,
					"Data (%d bytes)", i);
		    break;
		}
		}
		break;
	    
	    default :
		rsvp_object_tree = proto_item_add_subtree(ti, ett_rsvp_unknown_class);
		proto_tree_add_text(rsvp_object_tree, offset, 2, "Length: %d", 
				    obj_length);
		proto_tree_add_text(rsvp_object_tree, offset+2, 1, 
				    "Class number: %u - %s", 
				    obj->class, object_type);
	    default_class:
		i = obj_length - sizeof(rsvp_object);
		proto_tree_add_text(rsvp_object_tree, offset2, i,
				    "Data (%d bytes)", i);
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

        proto_rsvp = proto_register_protocol("Resource ReserVation Protocol (RSVP)", "rsvp");
        proto_register_field_array(proto_rsvp, rsvpf_info, array_length(rsvpf_info));
	proto_register_subtree_array(ett, array_length(ett));
}
