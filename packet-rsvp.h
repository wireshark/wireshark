/**********************************************************************
 *
 * packet-rsvp.h
 *
 * (C) Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-rsvp.h,v 1.1 1999/06/11 16:44:51 gram Exp $
 *
 * For license details, see the COPYING file with this distribution
 *
 **********************************************************************/

#ifndef PACKET_RSVP_H
#define PACKET_RSVP_H

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
    RSVP_CLASS_CONFIRM
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
    {RSVP_CLASS_CONFIRM, "CONFIRM object"}
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

/*
 * Defines a desired QoS, in a RESV message.
 */
enum    qos_service_type {
    QOS_CONTROLLED_LOAD=    5,		/* Controlled Load Service */
    QOS_GUARANTEED =        2,		/* Guaranteed service */
    QOS_DEFAULT		 =  1,		/* Default general parameters */
    QOS_TSPEC =             0,		/* Traffic specification */
    QOS_UNSPECIFIED =	    -1		/* unspecified */
    };

static value_string qos_vals[] = {
    { QOS_CONTROLLED_LOAD, "Controlled-load QoS" },
    { QOS_GUARANTEED, "Guaranteed rate QoS" },
    { QOS_DEFAULT, "Default general parameters" },
    { QOS_UNSPECIFIED, "Unspecified QoS" },
    { QOS_TSPEC, "Traffic specification" },
};

static value_string svc_vals[] = {
    { 127, "Token bucket TSpec" },
    { 130, "Guaranteed-rate RSpec" }
};

enum rsvp_spec_types { INTSRV = 2 };

enum intsrv_services {
	INTSRV_GENERAL = 1,
	INTSRV_GTD = 2,
	INTSRV_CLOAD = 5
};

enum intsrv_field_name {
	INTSRV_NON_IS_HOPS = 1, INTSRV_COMPOSED_NON_IS_HOPS,
	INTSRV_IS_HOPS, INTSRV_COMPOSED_IS_HOPS,
	INTSRV_PATH_BANDWIDTH, INTSRV_MIN_PATH_BANDWIDTH,
	INTSRV_IF_LATENCY, INTSRV_PATH_LATENCY,
	INTSRV_MTU, INTSRV_COMPOSED_MTU,

	INTSRV_TOKEN_BUCKET_TSPEC = 127,
	INTSRV_GTD_RSPEC = 130,

    	INTSRV_DELAY = 131,	/* Gtd Parameter C - Max Delay Bound - bytes */
	INTSRV_MAX_JITTER,	/* Gtd Parameter D - Max Jitter */
    	INTSRV_E2E_DELAY,	/* Gtd Parameter Ctot */
	INTSRV_E2E_MAX_JITTER,	/* Gtd Parameter Dtot */
    	INTSRV_SHP_DELAY,	/* Gtd Parameter Csum */
	INTSRV_SHP_MAX_JITTER	/* Gtd Parameter Dsum */
};

/*------------------------------*
 * Object definitions
 *------------------------------*/

/*
 * Base RSVP object
 */
typedef struct {
    unsigned short length;
    unsigned char class;	
    unsigned char type;
    unsigned char data[0];
} rsvp_object;

/*
 * RSVP message header
 */

typedef struct {
    unsigned char    ver_flags;			/* RSVP Version & flags */
    unsigned char    message_type;		/* type of message */
    unsigned short   cksum;			/* IP Checksum */
    unsigned char    sending_ttl;		/* ttl of message */
    unsigned char    reserved_byte;		/* reserved */
    unsigned short   rsvp_length;		/* length of RSVP data */
    rsvp_object rsvp_first_object[0];
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
    unsigned long destination;
    unsigned char protocol;
    unsigned char flags;
    unsigned short port;
} rsvp_session_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr destination;
    unsigned char protocol;
    unsigned char flags;
    unsigned short port;
} rsvp_session_ipv6;

/*
 * HOP object
 * Can be a PHOP or a NHOP
 */
typedef struct {
    rsvp_object base;
    unsigned long neighbor;
    unsigned long lif_handle;
} rsvp_hop_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr neighbor;
    unsigned long lif_handle;
} rsvp_hop_ipv6;

/*
 * TIME_VALUES object
 */
typedef struct {
    rsvp_object base;
    long refresh_ms;
} rsvp_time_values;

/*
 * ERROR object
 */
typedef struct {
    rsvp_object base;
    unsigned long error_node;
    unsigned char flags;
    unsigned char error_code;
    unsigned short error_value;
} rsvp_error_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr error_node;
    unsigned char flags;
    unsigned char error_code;
    unsigned short error_value;
} rsvp_error_ipv6;

/*
 * CONFIRM object
 */
typedef struct {
    rsvp_object base;
    unsigned long receiver;
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
    unsigned long source[0];
} rsvp_scope;

/*
 * STYLE object
 */
typedef struct {
    rsvp_object base;
    unsigned long reservation_type;
} rsvp_style;

/*
 * Defines a subset of session data packets that should receive the
 * desired QoS (specified by an FLOWSPEC object), in a RESV message.
 */
typedef struct {
    rsvp_object base;
    unsigned long source;			/* source sending data */
    unsigned short unused;
    unsigned short udp_source_port;		/* port number */
} rsvp_filter_ipv4;

/*
 * Contains a sender IP address and perhaps some additional
 * demultiplexing information to identify a sender, in a PATH
 * message.
 */
typedef struct {
    rsvp_object base;
    unsigned long source;			/* source sending data */
    unsigned short __reserved;
    unsigned short source_port;		/* port number */
} rsvp_template_ipv4;

typedef struct {
    rsvp_object base;
    struct e_in6_addr source;			/* source sending data */
    unsigned short __reserved;
    unsigned short source_port;		/* port number */
} rsvp_template_ipv6;

/*
 * Subobjects for Integrated Services
 */

typedef struct {
    rsvp_object base;
    unsigned char	version;	
    unsigned char 	__reserved_;
    unsigned short	length_in_words;
					
    unsigned char	service_header;
    unsigned char	_reserved;
    unsigned short	service_length;	
    unsigned char	param_id;
    unsigned char	flags_tspec;
    unsigned short	parameter_length;

    unsigned long	rate;
    unsigned long	depth;
    unsigned long	peak;
    unsigned long	min_unit;
    unsigned long	max_unit;
} IS_tspec; /* RFC2210 */

typedef struct {
    rsvp_object base;
    unsigned char	version;	
    unsigned char 	__reserved_;
    unsigned short	length_in_words;
					
    unsigned char	service_header;
    unsigned char	_reserved;
    unsigned short	service_length;	
    unsigned char	param_id;
    unsigned char	flags_tspec;
    unsigned short	parameter_length;

    unsigned long	rate;
    unsigned long	depth;
    unsigned long	peak;
    unsigned long	min_unit;
    unsigned long	max_unit;

    unsigned char	param_id_rspec;
    unsigned char	flags_rspec;
    unsigned short	param2_length;
    unsigned long	requested_rate;
    unsigned long	slack;
} IS_flowspec; /* RFC 2210 */

/*
 * ADSPEC objects */

typedef struct {
    unsigned char service_num;
    unsigned char break_bit;
    unsigned short length;
} service_hdr;

static value_string adspec_services[] = { 
    {1, "Default General Parameters"},
    {2, "Guaranteed"},
    {5, "Controlled Load"},
};

typedef struct {
    unsigned char id;
    unsigned char flags;
    unsigned short length;
    unsigned long dataval;
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



#endif
