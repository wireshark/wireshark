/* packet-dcc.c
 * Protocol defs for Distributed Checksum Clearinghouse protocol
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


/* Inserted below is dcc_proto.h from the dcc source distribution, with the
	following changes made:

:%s/u_in*t16_t/guint16/g
:%s/u_in*t32_t/guint32/g
:%s/u_ch*ar/guchar/g
:%s/in*t32_t/gint32/g

This includes more than is really necessary, but easier to just include whole
header.

*/


/* Distributed Checksum Clearinghouse protocol
 *
 * Copyright (c) 2002 by Rhyolite Software
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND RHYOLITE SOFTWARE DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RHYOLITE SOFTWARE
 * BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
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

typedef guint16 DCC_MS;

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

typedef guchar DCC_CK_TYPE;


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

typedef guint32 DCC_CLNT_ID;
#define DCC_ID_INVALID	    0
#define DCC_ID_ANON	    1		/* anonymous (non-paying) client */
#define DCC_ID_WHITE	    2		/* white-listed */
#define DCC_ID_COMP	    3		/* compressed */
#define DCC_SRVR_ID_MIN	    100		/* below reserved for special uses */
#define	DCC_SRVR_ID_MAX	    32767	/* below are servers--must be 2**n-1 */
#define DCC_CLNT_ID_MIN	    (DCC_SRVR_ID_MAX+1)
#define DCC_CLNT_ID_MAX	    16777215
typedef guint16 DCC_SRVR_ID;
#define	DCC_SRVR_ID_AUTH (DCC_SRVR_ID_MAX+1)	/* client was authenticated */

/* client's identification of its transaction */
typedef struct {
    guint32	h;			/* client host ID, e.g. IP address */
    guint32	p;			/* process ID, serial #, timestamp */
    guint32	r;			/* report ID */
    guint32	t;			/* client (re)transmission # */
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
typedef guchar DCC_TS[6];

/* The start of any DCC packet.
 *	The length and version are early, since they are they only fields
 *	that are constrained in future versions. */
typedef struct {
    guint16	len;			/* total DCC packet length (for TCP) */
    guchar	pkt_vers;		/* packet protocol version */
#    define	 DCC_PKT_VERSION	4
#    define	 DCC_PKT_VERSION_MIN	DCC_PKT_VERSION
#    define	 DCC_PKT_VERSION_MAX    DCC_PKT_VERSION
    guchar	op;			/* one of DCC_OPS */
    /* Identify the transaction.
     *	    Each client can have many hosts, each host can be multi-homed,
     *	    and each host can be running many processes talking to the
     *	    server.  Each packet needs to be uniquely numbered, so that the
     *	    server can recognize as interchangable all of the (re)transmissions
     *	    of a single report (rid) from a client process (pid) on a single
     *	    host (hid), and the client can know which transmission (tid)
     *	    produced a given server response to maintain the client's RTT
     *	    value for the server. */
    DCC_CLNT_ID	sender;			/* official DCC client-ID */
    DCC_OP_NUMS	op_nums;		/* op_num.t must be last */
} DCC_HDR;

typedef guchar DCC_SIGNATURE[16];

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
    gint32	date;			/* seconds since epoch on caller */
    guint32	val;			/* request type, buffer size, etc. */
    guchar	aop;			/* one of DCC_AOPS */
    guchar	pad[3];
    DCC_SIGNATURE signature;
} DCC_ADMN_REQ;

/* noisy response to some DCC_AOPS with operation DCC_OP_ADMN */
typedef struct {
    guchar	addr[16];
    DCC_CLNT_ID	id;
    guint32	last_used;
    guint32	requests;
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
    guchar	max_pkt_vers;		/* can handle this version */
    guchar	unused;
    DCC_MS	qdelay_ms;
    DCC_BRAND	brand;			/* identity or brandname of sender */
    DCC_SIGNATURE signature;
} DCC_OK;


/* a reported checksum from a client */
typedef guchar DCC_SUM[16];		/* for now all have 16 bytes */
typedef struct {
    DCC_CK_TYPE	type;
    guchar	len;			/* total length of this checksum */
    DCC_SUM	sum;
} DCC_CK;

typedef guint32 DCC_TGTS;		/* database is limited to 24 bits */
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
    gint32	date;			/* seconds since epoch on caller */
    DCC_CK	ck;
    guchar	pad[2];			/* structure padding */
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
typedef guchar DCC_FLOD_POS[8];
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
    guchar	tgts[sizeof(DCC_TGTS)];
    guchar	srvr_id_auth[sizeof(DCC_SRVR_ID)];  /* receiving server */
    DCC_TS	ts;			/* date reported */
    guchar	num_cks;
    DCC_CK	cks[DCC_QUERY_MAX];
} DCC_FLOD;

/* record of path taken by a report */
#define DCC_NUM_FLOD_PATH ((int)(sizeof(DCC_SUM)/sizeof(DCC_SRVR_ID)))
typedef struct {
    guchar	hi, lo;
} DCC_FLOD_PATH_ID;

typedef struct {
    DCC_FLOD_POS z;
    char    msg[DCC_FLOD_MAX_RESP];
    char    null;
} FLOD_END;
typedef struct {
    DCC_FLOD_POS    op;
    guchar	    len;
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
    guchar	turn;
    guchar	unused[3];
} DCC_FLOD_VERSION_BODY;
typedef struct {
    DCC_FLOD_VERSION_BODY body;
    char	pad[256-sizeof(DCC_FLOD_VERSION_BODY)-sizeof(DCC_SIGNATURE)];
    DCC_SIGNATURE signature;
} DCC_FLOD_VERSION_HDR;


#endif /* DCC_PROTO_H	*/
