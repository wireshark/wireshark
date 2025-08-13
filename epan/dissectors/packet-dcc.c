/* packet-dcc.c
 * Routines for Distributed Checksum Clearinghouse packet dissection
 * DCC Home: http://www.rhyolite.com/anti-spam/dcc/
 *
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-udp.h"

void proto_register_dcc(void);
void proto_reg_handoff_dcc(void);

static int proto_dcc;
static int hf_dcc_len;
static int hf_dcc_pkt_vers;
static int hf_dcc_op;
static int hf_dcc_clientid;
static int hf_dcc_opnums_host;
static int hf_dcc_opnums_pid;
static int hf_dcc_opnums_report;
static int hf_dcc_opnums_retrans;

static int hf_dcc_signature;
static int hf_dcc_max_pkt_vers;
static int hf_dcc_qdelay_ms;
static int hf_dcc_brand;

static int hf_dcc_ck_type;
static int hf_dcc_ck_len;
static int hf_dcc_ck_sum;

static int hf_dcc_date;

static int hf_dcc_target;
static int hf_dcc_response_text;

static int hf_dcc_adminop;
static int hf_dcc_adminval;
static int hf_dcc_floodop;
static int hf_dcc_trace;
static int hf_dcc_trace_admin;
static int hf_dcc_trace_anon;
static int hf_dcc_trace_client;
static int hf_dcc_trace_rlim;
static int hf_dcc_trace_query;
static int hf_dcc_trace_ridc;
static int hf_dcc_trace_flood;

static int hf_dcc_addr;
static int hf_dcc_id;
static int hf_dcc_last_used;
static int hf_dcc_requests;
static int hf_dcc_pad;
static int hf_dcc_unused;

static int ett_dcc;
static int ett_dcc_opnums;
static int ett_dcc_op;
static int ett_dcc_ck;
static int ett_dcc_trace;


/* Inserted below is dcc_proto.h from the dcc source distribution, with the
	following changes made:

:%s/u_in*t16_t/uint16_t/g
:%s/u_in*t32_t/uint32_t/g
:%s/u_ch*ar/unsigned char/g
:%s/in*t32_t/int32_t/g

This includes more than is really necessary, but easier to just include whole
header.

*/


/* Distributed Checksum Clearinghouse protocol
 *
 * Copyright (c) 2002 by Rhyolite Software
 *
 * SPDX-License-Identifier: ISC
 *
 * Rhyolite Software DCC 1.0.53-1.45 $Revision: 1.3 $
 */

#ifndef DCC_PROTO_H
#define DCC_PROTO_H


#define DCC_PORT    6277		/* default UDP port #, MAPS in DTMF */


/* No client's retransmission can be delayed by more than this
 * This matters for how long a DCC server must remember old requests
 * to recognize retransmissions */
#define DCC_MAX_DELAY_SEC   30

typedef uint16_t DCC_MS;

/* anonymous client delay */
#define DCC_MAX_QDELAY_MS   (DCC_MAX_DELAY_SEC*1000)
#define DCC_DEF_QDELAY_MS   0


/* types of checksums */
typedef enum {
    DCC_CK_INVALID  =0,			/* deleted from database when seen */
    DCC_CK_IP	    =1,			/* MD5 of binary source IPv6 address */
    DCC_CK_ENV_FROM =2,			/*  "  "  envelope Mail From value */
    DCC_CK_FROM	    =3,			/*  "  "  header From: line */
    DCC_CK_SUB	    =4,			/*  "  "  substitute header line */
    DCC_CK_MESSAGE_ID=5,		/*  "  "  header Message-ID: line */
    DCC_CK_RECEIVED =6,			/*  "  "  last header Received: line */
    DCC_CK_BODY	    =7,			/*  "  "  body */
    DCC_CK_FUZ1	    =8,			/*  "  "  filtered body */
    DCC_CK_FUZ2	    =9,			/*  "  "     "      "   */
    DCC_CK_FUZ3	    =10,		/*  "  "     "      "   */
    DCC_CK_FUZ4	    =11,		/*  "  "     "      "   */
    DCC_CK_SRVR_ID  =12,		/* hostname for server-ID check */
    DCC_CK_ENV_TO   =13			/* MD5 of envelope Rcpt To value */
#   define DCC_CK_FLOD_PATH DCC_CK_ENV_TO   /* flooding path in server-IDs */
} DCC_CK_TYPES;
#define DCC_CK_TYPE_FIRST   DCC_CK_IP
#define DCC_CK_TYPE_LAST    DCC_CK_ENV_TO
#define DCC_NUM_CKS	    DCC_CK_TYPE_LAST    /* # of valid types */

/* DCC_DIM_CKS dimensions arrays of checksum types including DCC_CK_INVALID
 * Beware that DCC_DIM_CKS is used in the database header. */
#define DCC_DIM_CKS	    (DCC_CK_TYPE_LAST+1)

/* Ensure that arrays of DCC_CKs contain an even number so that structures
 * containing them will have no extra structure packing */
#define DCC_COMP_DIM_CKS    ((((DCC_NUM_CKS+1)+1)/2)*2)	/* == DCC_DIM_CKS */

/* keep in the database longer than others */
#define DCC_CK_LONG_TERM(t) ((t) >= DCC_CK_FUZ1 && (t) <= DCC_CK_FUZ4)

#define DCC_CK_IS_BODY(t) ((t) >= DCC_CK_BODY && (t) <= DCC_CK_FUZ4)

/* ok for users to talk about */
#define DCC_CK_OK_USER(t) ((t) > DCC_CK_INVALID && (t) <= DCC_CK_FUZ4)
/* ok in the database */
#define DCC_CK_OK_DB(t) ((t) > DCC_CK_INVALID && (t) <= DCC_CK_TYPE_LAST)
#define DCC_CK_OK_PROTO(t) DCC_CK_OK_USER(t)	/* ok from clients */
#define DCC_CK_OK_FLOD(t) DCC_CK_OK_DB(t)   /* ok in floods */

typedef unsigned char DCC_CK_TYPE;


typedef enum {
    DCC_OP_INVALID=0,
    DCC_OP_NOP,				/* see if the server is alive */
    DCC_OP_REPORT,			/* client reporting and querying */
    DCC_OP_QUERY,			/* client querying */
    DCC_OP_QUERY_RESP,			/* server responding */
    DCC_OP_ADMN,			/* local control of the server */
    DCC_OP_OK,				/* administrative operation ok */
    DCC_OP_ERROR,			/* server failing or complaining */
    DCC_OP_DELETE			/* delete some checksums */
} DCC_OPS;

typedef uint32_t DCC_CLNT_ID;
#define DCC_ID_INVALID	    0
#define DCC_ID_ANON	    1		/* anonymous (non-paying) client */
#define DCC_ID_WHITE	    2		/* white-listed */
#define DCC_ID_COMP	    3		/* compressed */
#define DCC_SRVR_ID_MIN	    100		/* below reserved for special uses */
#define	DCC_SRVR_ID_MAX	    32767	/* below are servers--must be 2**n-1 */
#define DCC_CLNT_ID_MIN	    (DCC_SRVR_ID_MAX+1)
#define DCC_CLNT_ID_MAX	    16777215
typedef uint16_t DCC_SRVR_ID;
#define	DCC_SRVR_ID_AUTH (DCC_SRVR_ID_MAX+1)	/* client was authenticated */

/* client's identification of its transaction */
typedef struct {
    uint32_t	h;			/* client host ID, e.g. IP address */
    uint32_t	p;			/* process ID, serial #, timestamp */
    uint32_t	r;			/* report ID */
    uint32_t	t;			/* client (re)transmission # */
} DCC_OP_NUMS;

/* The inter-DCC server flooding algorithm depends on unique-per-server
 * timestamps to detect duplicates.  That imposes a requirement on
 * timestamps that they have resolution enough to separate reports
 * from clients arriving at any single server.
 * The timestamps are 48 bits consisting of 17 bits of 8's of microseconds
 * and 31 bits of seconds.  That's sufficient for the UNIX epoch.
 * If the DCC is still around in the 2030's (and in the unlikely case that
 * 8 microseconds are still fine enough), we can make the 31 bits be
 * an offset in a bigger window.
 */
#define DCC_TS_USEC_RSHIFT  3
#define DCC_TS_USEC_MULT    (1<<DCC_TS_USEC_RSHIFT)
#define DCC_TS_SEC_LSHIFT   17
#define DCC_TS_USEC_MASK    ((1<<DCC_TS_SEC_LSHIFT) - 1)
typedef unsigned char DCC_TS[6];

/* The start of any DCC packet.
 *	The length and version are early, since they are they only fields
 *	that are constrained in future versions. */
typedef struct {
    uint16_t	len;			/* total DCC packet length (for TCP) */
    unsigned char	pkt_vers;		/* packet protocol version */
#    define	 DCC_PKT_VERSION	4
#    define	 DCC_PKT_VERSION_MIN	DCC_PKT_VERSION
#    define	 DCC_PKT_VERSION_MAX    DCC_PKT_VERSION
    unsigned char	op;			/* one of DCC_OPS */
    /* Identify the transaction.
     *	    Each client can have many hosts, each host can be multi-homed,
     *	    and each host can be running many processes talking to the
     *	    server.  Each packet needs to be uniquely numbered, so that the
     *	    server can recognize as interchangeable all of the (re)transmissions
     *	    of a single report (rid) from a client process (pid) on a single
     *	    host (hid), and the client can know which transmission (tid)
     *	    produced a given server response to maintain the client's RTT
     *	    value for the server. */
    DCC_CLNT_ID	sender;			/* official DCC client-ID */
    DCC_OP_NUMS	op_nums;		/* op_num.t must be last */
} DCC_HDR;

typedef unsigned char DCC_SIGNATURE[16];

typedef struct {
    DCC_HDR	hdr;
    DCC_SIGNATURE signature;
} DCC_NOP;


/* administrative requests from localhost
 *	These can be freely changed, because the administrative tools
 *	should match the daemon. */
typedef enum {
    DCC_AOP_OK=-1,			/* never really sent */
    DCC_AOP_STOP=1,			/* stop gracefully */
    DCC_AOP_NEW_IDS,			/* load keys and client-IDs */
    DCC_AOP_FLOD,			/* start or stop flooding */
    DCC_AOP_DB_UNLOCK,			/* start switch to new database */
    DCC_AOP_DB_NEW,			/* finish switch to new database */
    DCC_AOP_STATS,			/* return counters--val=buffer size */
    DCC_AOP_STATS_CLEAR,		/* return and zero counters */
    DCC_AOP_TRACE_ON,
    DCC_AOP_TRACE_OFF,
    DCC_AOP_CUR_CLIENTS			/* some client IP addresses */
} DCC_AOPS;

/* for DCC_AOP_FLOD */
typedef enum {
    DCC_AOP_FLOD_CHECK=0,
    DCC_AOP_FLOD_SHUTDOWN,
    DCC_AOP_FLOD_HALT,
    DCC_AOP_FLOD_RESUME,
    DCC_AOP_FLOD_REWIND,
    DCC_AOP_FLOD_LIST,
    DCC_AOP_FLOD_STATS,
    DCC_AOP_FLOD_STATS_CLEAR
} DCC_AOP_FLODS;

typedef struct {			/* with operation DCC_OP_ADMN */
    DCC_HDR	hdr;
    int32_t	date;			/* seconds since epoch on caller */
    uint32_t	val;			/* request type, buffer size, etc. */
    unsigned char	aop;			/* one of DCC_AOPS */
    unsigned char	pad[3];
    DCC_SIGNATURE signature;
} DCC_ADMN_REQ;

/* noisy response to some DCC_AOPS with operation DCC_OP_ADMN */
typedef struct {
    unsigned char	addr[16];
    DCC_CLNT_ID	id;
    uint32_t	last_used;
    uint32_t	requests;
} DCC_ADMN_RESP_CLIENTS;
typedef union {
    char	string[80*22];
    DCC_ADMN_RESP_CLIENTS clients[1];
} DCC_ADMN_RESP_VAL;
typedef struct {
    DCC_HDR	hdr;
    DCC_ADMN_RESP_VAL val;
    DCC_SIGNATURE signature;
} DCC_ADMN_RESP;


#define DCC_TRACE_ADMN_BIT  0x0001	/* administrative requests */
#define DCC_TRACE_ANON_BIT  0x0002	/* anonymous client errors */
#define DCC_TRACE_CLNT_BIT  0x0004	/* authenticated client errors */
#define DCC_TRACE_RLIM_BIT  0x0008	/* rate limited messages */
#define DCC_TRACE_QUERY_BIT 0x0010	/* all queries and reports */
#define DCC_TRACE_RIDC_BIT  0x0020	/* RID cache messages */
#define DCC_TRACE_FLOD_BIT  0x0040	/* input and output flooding */
/* INFO must always be on */
#define DCC_TRACE_ALL_BITS  (DCC_TRACE_ADMN_BIT | DCC_TRACE_ANON_BIT	\
			     | DCC_TRACE_CLNT_BIT | DCC_TRACE_RLIM_BIT	\
			     | DCC_TRACE_QUERY_BIT | DCC_TRACE_RIDC_BIT \
			     | DCC_TRACE_FLOD_BIT)


typedef char DCC_BRAND[64];

/* administrative or NOP ok */
typedef struct {
    DCC_HDR	hdr;
    unsigned char	max_pkt_vers;		/* can handle this version */
    unsigned char	unused;
    DCC_MS	qdelay_ms;
    DCC_BRAND	brand;			/* identity or brandname of sender */
    DCC_SIGNATURE signature;
} DCC_OK;


/* a reported checksum from a client */
typedef unsigned char DCC_SUM[16];		/* for now all have 16 bytes */
typedef struct {
    DCC_CK_TYPE	type;
    unsigned char	len;			/* total length of this checksum */
    DCC_SUM	sum;
} DCC_CK;

typedef uint32_t DCC_TGTS;		/* database is limited to 24 bits */
#define	DCC_TGTS_TOO_MANY   0x00fffff0	/* >= 16777200 targets */
#define	DCC_TGTS_OK	    0x00fffff1	/* certified not spam */
#define	DCC_TGTS_OK2	    0x00fffff2	/* half certified not spam */
#define	DCC_TGTS_DEL	    0x00fffff3	/* a deleted checksum */
#define DCC_TGTS_INVALID    0x01000000

/* query or query/report packet from client to server */
typedef struct {
    DCC_HDR	hdr;
    DCC_TGTS	tgts;			/* # of addressees */
#    define	 DCC_QUERY_MAX DCC_DIM_CKS
    DCC_CK	cks[DCC_QUERY_MAX];	/* even to prevent structure padding */
    DCC_SIGNATURE signature;
} DCC_QUERY_REPORT;


typedef struct {
    DCC_TGTS	tgts[DCC_QUERY_MAX];	/* individual answers */
} DCC_QUERY_RESP_BODY;

/* response to a query or query/report */
typedef struct {
    DCC_HDR	hdr;
    DCC_QUERY_RESP_BODY body;
    DCC_SIGNATURE signature;
} DCC_QUERY_RESP;


/* DCC_OP_DELETE request to delete checksums */
typedef struct {
    DCC_HDR	hdr;
    int32_t	date;			/* seconds since epoch on caller */
    DCC_CK	ck;
    unsigned char	pad[2];			/* structure padding */
    DCC_SIGNATURE signature;
} DCC_DELETE;


/* error response from server to client */
typedef struct {
    DCC_HDR	hdr;
#    define	 DCC_ERROR_MSG_LEN  128
    char	msg[DCC_ERROR_MSG_LEN];
    DCC_SIGNATURE signature;
} DCC_ERROR;


/* sender's position or serial number
 *	Only the sender understands sender positions except for these
 *	special values.  However, the special values imply that the position
 *	must be big endian. */
typedef unsigned char DCC_FLOD_POS[8];
/* special cases sent by the receiver back to the sender */
#define DCC_FLOD_POS_END	0	/* receiver closing with message */
#define DCC_FLOD_POS_END_REQ	1	/* receiver wants to stop */
#define DCC_FLOD_POS_NOTE	2	/* receiver has a tracing message */
#define DCC_FLOD_POS_COMPLAINT	3	/* receiver has a problem message */
#define DCC_FLOD_POS_REWIND	4	/* receiver's database emptied */
#define DCC_FLOD_POS_MIN	10

#define DCC_FLOD_OK_STR	    "DCC flod ok: "
#define DCC_FLOD_MAX_RESP   200

/* report forwarded among servers */
typedef struct {
    DCC_FLOD_POS pos;
    unsigned char	tgts[sizeof(DCC_TGTS)];
    unsigned char	srvr_id_auth[sizeof(DCC_SRVR_ID)];  /* receiving server */
    DCC_TS	ts;			/* date reported */
    unsigned char	num_cks;
    DCC_CK	cks[DCC_QUERY_MAX];
} DCC_FLOD;

/* record of path taken by a report */
#define DCC_NUM_FLOD_PATH ((int)(sizeof(DCC_SUM)/sizeof(DCC_SRVR_ID)))
typedef struct {
    unsigned char	hi, lo;
} DCC_FLOD_PATH_ID;

typedef struct {
    DCC_FLOD_POS z;
    char    msg[DCC_FLOD_MAX_RESP];
    char    null;
} FLOD_END;
typedef struct {
    DCC_FLOD_POS    op;
    unsigned char	    len;
    char	    str[DCC_FLOD_MAX_RESP];
} FLOD_NOTE;
#define FLOD_NOTE_OVHD ((int)sizeof(FLOD_NOTE)-DCC_FLOD_MAX_RESP)

#define DCC_FLOD_VERSION_STR_BASE   "DCC flod version "
#define DCC_FLOD_VERSION5_STR	    DCC_FLOD_VERSION_STR_BASE"5"
#define DCC_FLOD_VERSION5	    5
#define DCC_FLOD_VERSION6_STR	    DCC_FLOD_VERSION_STR_BASE"6"
#define DCC_FLOD_VERSION6	    6
#define DCC_FLOD_VERSION7_STR	    DCC_FLOD_VERSION_STR_BASE"7"
#define DCC_FLOD_VERSION7	    7
#define DCC_FLOD_VERSION_DEF	    0
#define DCC_FLOD_VERSION_CUR_STR    DCC_FLOD_VERSION7_STR
#define DCC_FLOD_VERSION_CUR	    DCC_FLOD_VERSION7
typedef struct {
#    define DCC_FLOD_VERSION_STR_LEN 64
    char	str[DCC_FLOD_VERSION_STR_LEN];
    DCC_SRVR_ID	sender_srvr_id;
    unsigned char	turn;
    unsigned char	unused[3];
} DCC_FLOD_VERSION_BODY;
typedef struct {
    DCC_FLOD_VERSION_BODY body;
    char	pad[256-sizeof(DCC_FLOD_VERSION_BODY)-sizeof(DCC_SIGNATURE)];
    DCC_SIGNATURE signature;
} DCC_FLOD_VERSION_HDR;


#endif /* DCC_PROTO_H	*/








/* Lookup string tables */
static const value_string dcc_op_vals[] = {
	{DCC_OP_INVALID,    "Invalid Op"},
	{DCC_OP_NOP,	    "No-Op"},
	{DCC_OP_REPORT,	    "Report and Query"},
	{DCC_OP_QUERY,	    "Query"},
	{DCC_OP_QUERY_RESP, "Server Response"},
	{DCC_OP_ADMN,	    "Admin"},
	{DCC_OP_OK,	    "Ok"},
	{DCC_OP_ERROR,	    "Server Failing"},
	{DCC_OP_DELETE,	    "Delete Checksum(s)"},
	{0, NULL}
};

static const value_string dcc_cktype_vals[] = {
	{DCC_CK_INVALID,    "Invalid/Deleted from DB when seen"},
	{DCC_CK_IP,	    "MD5 of binary source IPv6 address"},
	{DCC_CK_ENV_FROM,   "MD5 of envelope Mail From value"},
	{DCC_CK_FROM,	    "MD5 of header From: line"},
	{DCC_CK_SUB,	    "MD5 of substitute header line"},
	{DCC_CK_MESSAGE_ID, "MD5 of header Message-ID: line"},
	{DCC_CK_RECEIVED,   "MD5 of last header Received: line"},
	{DCC_CK_BODY,	    "MD5 of body"},
	{DCC_CK_FUZ1,	    "MD5 of filtered body - FUZ1"},
	{DCC_CK_FUZ2,	    "MD5 of filtered body - FUZ2"},
	{DCC_CK_FUZ3,	    "MD5 of filtered body - FUZ3"},
	{DCC_CK_FUZ4,	    "MD5 of filtered body - FUZ4"},
	{DCC_CK_SRVR_ID,    "hostname for server-ID check "},
	{DCC_CK_ENV_TO,	    "MD5 of envelope Rcpt To value"},
	{0, NULL},
};

static const value_string dcc_adminop_vals[] = {
	{DCC_AOP_OK,	      "Never sent"},
	{DCC_AOP_STOP,	      "Stop Gracefully"},
	{DCC_AOP_NEW_IDS,     "Load keys and client IDs"},
	{DCC_AOP_FLOD,	      "Flood control"},
	{DCC_AOP_DB_UNLOCK,   "Start Switch to new database"},
	{DCC_AOP_DB_NEW,      "Finish Switch to new database"},
	{DCC_AOP_STATS,	      "Return counters"},
	{DCC_AOP_STATS_CLEAR, "Return and zero counters"},
	{DCC_AOP_TRACE_ON,    "Enable tracing"},
	{DCC_AOP_TRACE_OFF,   "Disable tracing"},
	{DCC_AOP_CUR_CLIENTS, "List clients"},
	{0, NULL},
};

static const value_string dcc_target_vals[] = {
	{DCC_TGTS_TOO_MANY, "Targets (>= 16777200)"},
	{DCC_TGTS_OK,	    "Certified not spam"},
	{DCC_TGTS_OK2,	    "Half certified not spam"},
	{DCC_TGTS_DEL,	    "Deleted checksum"},
	{DCC_TGTS_INVALID,  "Invalid"},
	{0, NULL},
};

static const value_string dcc_floodop_vals[] = {
	{DCC_AOP_FLOD_CHECK,	   "Check"},
	{DCC_AOP_FLOD_SHUTDOWN,	   "Shutdown"},
	{DCC_AOP_FLOD_HALT,	   "Halt"},
	{DCC_AOP_FLOD_RESUME,	   "Resume"},
	{DCC_AOP_FLOD_REWIND,	   "Rewind"},
	{DCC_AOP_FLOD_LIST,	   "List"},
	{DCC_AOP_FLOD_STATS,	   "Stats"},
	{DCC_AOP_FLOD_STATS_CLEAR, "Clear Stats"},
	{0,NULL},
};

static int* const trace_flags[] = {
    &hf_dcc_trace_admin,
    &hf_dcc_trace_anon,
    &hf_dcc_trace_client,
    &hf_dcc_trace_rlim,
    &hf_dcc_trace_query,
    &hf_dcc_trace_ridc,
    &hf_dcc_trace_flood,
    NULL
};

static int
dissect_dcc_pdu(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	proto_tree *dcc_tree, *dcc_optree, *dcc_opnumtree, *ti;
	uint32_t packet_length, op;
	int offset = 0;
	int client_is_le = 0;
	int i;
	bool is_response = (pinfo->srcport == DCC_PORT);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCC");

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
		is_response ? "Response" : "Request",
		val_to_str_wmem(pinfo->pool, tvb_get_uint8(tvb, offset+3),
			 dcc_op_vals, "Unknown Op: %u"));

	ti = proto_tree_add_item(tree, proto_dcc, tvb, offset, -1, ENC_NA);
	dcc_tree = proto_item_add_subtree(ti, ett_dcc);

	proto_tree_add_item_ret_uint(dcc_tree, hf_dcc_len, tvb, offset, 2, ENC_BIG_ENDIAN, &packet_length);
	offset += 2;

	proto_tree_add_item(dcc_tree, hf_dcc_pkt_vers, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item_ret_uint(dcc_tree, hf_dcc_op, tvb, offset, 1, ENC_BIG_ENDIAN, &op);
	offset += 1;

	proto_tree_add_item(dcc_tree, hf_dcc_clientid, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	dcc_opnumtree = proto_tree_add_subtree(dcc_tree, tvb, offset, -1, ett_dcc_opnums, NULL, "Operation Numbers (Opaque to Server)");

	/* Note - these are indeterminate - they are sortof considered opaque to the client */
	/* Make some attempt to figure out if this data is little endian, not guaranteed to be
	correct if connection went through a firewall or similar. */

	/* Very hokey check - if all three of pid/report/retrans look like little-endian
		numbers, host is probably little endian. Probably innacurate on super-heavily-used
		DCC clients though. This should be good enough for now. */
	client_is_le = (( (tvb_get_uint8(tvb, offset+4) | tvb_get_uint8(tvb, offset+5)) &&
						(tvb_get_uint8(tvb, offset+8) | tvb_get_uint8(tvb, offset+9)) &&
						(tvb_get_uint8(tvb, offset+12) | tvb_get_uint8(tvb, offset+13)) )) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

	proto_tree_add_item(dcc_opnumtree, hf_dcc_opnums_host, tvb, offset, 4, client_is_le);
	offset += 4;

	proto_tree_add_item(dcc_opnumtree, hf_dcc_opnums_pid, tvb, offset, 4, client_is_le);
	offset += 4;

	proto_tree_add_item(dcc_opnumtree, hf_dcc_opnums_report, tvb, offset, 4, client_is_le);
	offset += 4;

	proto_tree_add_item(dcc_opnumtree, hf_dcc_opnums_retrans, tvb, offset, 4, client_is_le);
	offset += 4;

	dcc_optree = proto_tree_add_subtree_format(dcc_tree, tvb, offset, -1, ett_dcc_op, NULL,
		"Operation: %s", val_to_str_wmem(pinfo->pool, op, dcc_op_vals, "Unknown Op: %u"));

	switch(op) {
		case DCC_OP_NOP:
			proto_tree_add_item(dcc_optree, hf_dcc_signature, tvb, offset, (int)sizeof(DCC_SIGNATURE), ENC_NA);
			break;

		case DCC_OP_REPORT:
			proto_tree_add_item(dcc_optree, hf_dcc_target, tvb, offset, (int)sizeof(DCC_TGTS), ENC_BIG_ENDIAN);
			offset += (int)sizeof(DCC_TGTS);

			for (i = 0; i <= DCC_QUERY_MAX && (tvb_reported_length_remaining(tvb, offset + sizeof(DCC_SIGNATURE)) > 0); i++)
			{
				proto_tree* cktree;
				cktree = proto_tree_add_subtree_format(dcc_optree, tvb, offset, (int)sizeof(DCC_CK),
					ett_dcc_ck, NULL, "Checksum - %s",
					val_to_str_wmem(pinfo->pool, tvb_get_uint8(tvb, offset), dcc_cktype_vals, "Unknown Type: %u"));
				proto_tree_add_item(cktree, hf_dcc_ck_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(cktree, hf_dcc_ck_len, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(cktree, hf_dcc_ck_sum, tvb, offset, (int)sizeof(DCC_SUM), ENC_NA);
				offset += (int)sizeof(DCC_SUM);
			}
			proto_tree_add_item(dcc_optree, hf_dcc_signature, tvb, offset, (int)sizeof(DCC_SIGNATURE), ENC_NA);
			break;

		case DCC_OP_QUERY_RESP:
			for (i=0; i<=DCC_QUERY_MAX && (tvb_reported_length_remaining(tvb, offset+sizeof(DCC_SIGNATURE)) > 0); i++)
			{
				proto_tree_add_item(dcc_optree, hf_dcc_target, tvb, offset, (int)sizeof(DCC_TGTS), ENC_BIG_ENDIAN);
				offset += (int)sizeof(DCC_TGTS);
			}
			proto_tree_add_item(dcc_optree, hf_dcc_signature, tvb, offset, (int)sizeof(DCC_SIGNATURE), ENC_NA);
			break;

		case DCC_OP_ADMN:
			if ( is_response )
			{
				int left_local = tvb_reported_length_remaining(tvb, offset) - (int)sizeof(DCC_SIGNATURE);
				if ( left_local == sizeof(DCC_ADMN_RESP_CLIENTS) )
				{
					proto_tree_add_item(dcc_optree, hf_dcc_addr, tvb, offset, 16, ENC_NA);
					offset += 16;
					proto_tree_add_item(dcc_optree, hf_dcc_id, tvb, offset, (int)sizeof(DCC_CLNT_ID), ENC_BIG_ENDIAN);
					offset += (int)sizeof(DCC_CLNT_ID);
					proto_tree_add_item(dcc_optree, hf_dcc_last_used, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(dcc_optree, hf_dcc_requests, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
				}
				else
				{
					int next_offset, left;
					while (tvb_reported_length_remaining(tvb, offset+(int)sizeof(DCC_SIGNATURE)) > 0) {
						left = tvb_reported_length_remaining(tvb,offset) - (int)sizeof(DCC_SIGNATURE);
						tvb_find_line_end(tvb, offset, left, &next_offset, false);
						proto_tree_add_item(dcc_optree, hf_dcc_response_text, tvb, offset,
							next_offset - offset, ENC_ASCII);
						offset = next_offset;
					}
				}
				proto_tree_add_item(dcc_optree, hf_dcc_signature, tvb, offset, (int)sizeof(DCC_SIGNATURE), ENC_NA);
			}
			else
			{
				uint32_t aop;

				proto_tree_add_item(dcc_optree, hf_dcc_date, tvb, offset, 4, ENC_TIME_SECS | ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item_ret_uint(dcc_optree, hf_dcc_adminop, tvb, offset+4, 1, ENC_BIG_ENDIAN, &aop);
				col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
					val_to_str_wmem(pinfo->pool, aop, dcc_adminop_vals, "Unknown (%u)"));

				if (aop == DCC_AOP_TRACE_ON || aop == DCC_AOP_TRACE_OFF )
				{
					proto_tree_add_bitmask(dcc_optree, tvb, offset, hf_dcc_trace, ett_dcc_trace, trace_flags, ENC_BIG_ENDIAN);
				}
				else if ( aop == DCC_AOP_FLOD )
				{
					uint32_t floodop;
					proto_tree_add_item_ret_uint(dcc_optree, hf_dcc_floodop, tvb, offset, 4, ENC_BIG_ENDIAN, &floodop);
					col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
						val_to_str_wmem(pinfo->pool, floodop, dcc_floodop_vals, "Unknown (%u)"));
				}
				else
				{
					proto_tree_add_item(dcc_optree, hf_dcc_adminval, tvb, offset, 4, ENC_BIG_ENDIAN);
				}
				offset += 4;

				offset += 1; /* admin op we did in reverse order */

				proto_tree_add_item(dcc_optree, hf_dcc_pad, tvb, offset, 3, ENC_NA);
				offset += 3;
				proto_tree_add_item(dcc_optree, hf_dcc_signature, tvb, offset, (int)sizeof(DCC_SIGNATURE), ENC_NA);
			}
			break;

		case DCC_OP_OK:
			proto_tree_add_item(dcc_optree, hf_dcc_max_pkt_vers, tvb,
				offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(dcc_optree, hf_dcc_unused, tvb, offset, 1, ENC_NA);
			offset += 1;

			proto_tree_add_item(dcc_optree, hf_dcc_qdelay_ms, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(dcc_optree, hf_dcc_brand, tvb, offset, (int)sizeof(DCC_BRAND), ENC_ASCII);
			offset += (int)sizeof(DCC_BRAND);

			proto_tree_add_item(dcc_optree, hf_dcc_signature, tvb, offset, (int)sizeof(DCC_SIGNATURE), ENC_NA);
			break;

		default:
			/* do nothing */
			break;
	}

	return tvb_captured_length(tvb);
}

static unsigned
dissect_dcc_pdu_len(packet_info* pinfo _U_, tvbuff_t* tvb,
	int offset, void* data _U_)
{
	return tvb_get_ntohs(tvb, offset);
}

static int
dissect_dcc_udp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	udp_dissect_pdus(tvb, pinfo, tree, sizeof(DCC_HDR), NULL,
		dissect_dcc_pdu_len, dissect_dcc_pdu, data);
	return tvb_captured_length(tvb);
}

void
proto_register_dcc(void)
{
	static hf_register_info hf[] = {
			{ &hf_dcc_len, {
				"Packet Length", "dcc.len", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_pkt_vers, {
				"Packet Version", "dcc.pkt_vers", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_op, {
				"Operation Type", "dcc.op", FT_UINT8, BASE_DEC,
				VALS(dcc_op_vals), 0, NULL, HFILL }},

			{ &hf_dcc_clientid, {
				"Client ID", "dcc.clientid", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_opnums_host, {
				"Host", "dcc.opnums.host", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_opnums_pid, {
				"Process ID", "dcc.opnums.pid", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_opnums_report, {
				"Report", "dcc.opnums.report", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_opnums_retrans, {
				"Retransmission", "dcc.opnums.retrans", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_signature, {
				"Signature", "dcc.signature", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_max_pkt_vers, {
				"Maximum Packet Version", "dcc.max_pkt_vers", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_qdelay_ms, {
				"Client Delay", "dcc.qdelay_ms", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_brand, {
				"Server Brand", "dcc.brand", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_ck_type, {
				"Type", "dcc.checksum.type", FT_UINT8, BASE_DEC,
				VALS(dcc_cktype_vals), 0, "Checksum Type", HFILL }},

			{ &hf_dcc_ck_len, {
				"Length", "dcc.checksum.length", FT_UINT8, BASE_DEC,
				NULL, 0, "Checksum Length", HFILL }},

			{ &hf_dcc_ck_sum, {
				"Sum", "dcc.checksum.sum", FT_BYTES, BASE_NONE,
				NULL, 0, "Checksum", HFILL }},

			{ &hf_dcc_target, {
				"Target", "dcc.target", FT_UINT32, BASE_HEX,
				VALS(dcc_target_vals), 0, NULL, HFILL }},

			{ &hf_dcc_response_text, {
				"Response Text", "dcc.response_text", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_date, {
				"Date", "dcc.date", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_adminop, {
				"Admin Op", "dcc.adminop", FT_UINT8, BASE_DEC,
				VALS(dcc_adminop_vals), 0, NULL, HFILL }},

			{ &hf_dcc_adminval, {
				"Admin Value", "dcc.adminval", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_trace, {
				"Trace Bits", "dcc.trace", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_trace_admin, {
				"Admin Requests", "dcc.trace.admin", FT_BOOLEAN, 32,
				NULL, 0x00000001, NULL, HFILL }},

			{ &hf_dcc_trace_anon, {
				"Anonymous Requests", "dcc.trace.anon", FT_BOOLEAN, 32,
				NULL, 0x00000002, NULL, HFILL }},

			{ &hf_dcc_trace_client, {
				"Authenticated Client Requests", "dcc.trace.client", FT_BOOLEAN, 32,
				NULL, 0x00000004, NULL, HFILL }},

			{ &hf_dcc_trace_rlim, {
				"Rate-Limited Requests", "dcc.trace.rlim", FT_BOOLEAN, 32,
				NULL, 0x00000008, NULL, HFILL }},

			{ &hf_dcc_trace_query, {
				"Queries and Reports", "dcc.trace.query", FT_BOOLEAN, 32,
				NULL, 0x00000010, NULL, HFILL }},

			{ &hf_dcc_trace_ridc, {
				"RID Cache Messages", "dcc.trace.ridc", FT_BOOLEAN, 32,
				NULL, 0x00000020, NULL, HFILL }},

			{ &hf_dcc_trace_flood, {
				"Input/Output Flooding", "dcc.trace.flood", FT_BOOLEAN, 32,
				NULL, 0x00000040, NULL, HFILL }},

			{ &hf_dcc_floodop, {
				"Flood Control Operation", "dcc.floodop", FT_UINT32, BASE_DEC,
				VALS(dcc_floodop_vals), 0, NULL, HFILL }},

			{ &hf_dcc_id, {
				"Id", "dcc.id", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_last_used, {
				"Last Used", "dcc.last_used", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_requests, {
				"Requests", "dcc.requests", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_addr, {
				"Addr", "dcc.addr", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_pad, {
				"Pad", "dcc.pad", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }},

			{ &hf_dcc_unused, {
				"Unused", "dcc.unused", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }},
		};

	static int *ett[] = {
		&ett_dcc,
		&ett_dcc_op,
		&ett_dcc_ck,
		&ett_dcc_opnums,
		&ett_dcc_trace,
	};

	proto_dcc = proto_register_protocol("Distributed Checksum Clearinghouse protocol", "DCC", "dcc");

	proto_register_field_array(proto_dcc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcc(void)
{
	dissector_handle_t udp_handle = register_dissector("dcc_udp", dissect_dcc_udp, proto_dcc);
	dissector_add_uint_with_preference("udp.port", DCC_PORT, udp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
