/* packet-tacacs.h
 * Routines for cisco tacplus packet dissection
 * Copyright 2000, Emanuele Caratti <wiz@iol.it>
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

#ifndef __PACKET_TACACS_H__
#define __PACKET_TACACS_H__

#define TAC_PLUS_HDR_SIZE 12

#define MD5_LEN           16
#define MSCHAP_DIGEST_LEN 49
enum
{
	FLAGS_UNENCRYPTED = 0x01,
	FLAGS_SINGLE = 0x04
};

/* Tacacs+ packet type */
enum
{
	TAC_PLUS_AUTHEN = 0x01,		/* Authentication */
	TAC_PLUS_AUTHOR = 0x02,		/* Authorization  */
	TAC_PLUS_ACCT = 0x03		/* Accounting     */
};

/* Flags */
#define TAC_PLUS_ENCRYPTED 0x0 
#define TAC_PLUS_CLEAR     0x1

/* Authentication action to perform */
enum
{
	TAC_PLUS_AUTHEN_LOGIN = 0x01,
	TAC_PLUS_AUTHEN_CHPASS = 0x02,
	TAC_PLUS_AUTHEN_SENDPASS = 0x03,	/* deprecated */
	TAC_PLUS_AUTHEN_SENDAUTH = 0x04
};

/* Authentication priv_levels */
enum
{
	TAC_PLUS_PRIV_LVL_MAX	= 0x0f,
	TAC_PLUS_PRIV_LVL_ROOT	= 0x0f,
	TAC_PLUS_PRIV_LVL_USER	= 0x01,
	TAC_PLUS_PRIV_LVL_MIN	= 0x00
};

/* authen types */
enum
{
	TAC_PLUS_AUTHEN_TYPE_ASCII 		= 0x01,	/*  ascii  */
	TAC_PLUS_AUTHEN_TYPE_PAP 		= 0x02,	/*  pap    */
	TAC_PLUS_AUTHEN_TYPE_CHAP 		= 0x03,	/*  chap   */
	TAC_PLUS_AUTHEN_TYPE_ARAP 		= 0x04,	/*  arap   */
	TAC_PLUS_AUTHEN_TYPE_MSCHAP 	= 0x05	/*  mschap */
};

/* authen services */
enum
{
	TAC_PLUS_AUTHEN_SVC_NONE	= 0x00,
	TAC_PLUS_AUTHEN_SVC_LOGIN	= 0x01,
	TAC_PLUS_AUTHEN_SVC_ENABLE	= 0x02,
	TAC_PLUS_AUTHEN_SVC_PPP		= 0x03,
	TAC_PLUS_AUTHEN_SVC_ARAP	= 0x04,
	TAC_PLUS_AUTHEN_SVC_PT		= 0x05,
	TAC_PLUS_AUTHEN_SVC_RCMD	= 0x06,
	TAC_PLUS_AUTHEN_SVC_X25		= 0x07,
	TAC_PLUS_AUTHEN_SVC_NASI	= 0x08,
	TAC_PLUS_AUTHEN_SVC_FWPROXY	= 0x09
};

/* status of reply packet, that client get from server in authen */
enum
{
	TAC_PLUS_AUTHEN_STATUS_PASS		= 0x01,
	TAC_PLUS_AUTHEN_STATUS_FAIL		= 0x02,
	TAC_PLUS_AUTHEN_STATUS_GETDATA	= 0x03,
	TAC_PLUS_AUTHEN_STATUS_GETUSER	= 0x04,
	TAC_PLUS_AUTHEN_STATUS_GETPASS	= 0x05,
	TAC_PLUS_AUTHEN_STATUS_RESTART	= 0x06,
	TAC_PLUS_AUTHEN_STATUS_ERROR	= 0x07,
	TAC_PLUS_AUTHEN_STATUS_FOLLOW	= 0x21
};

/* Authen reply Flags */
#define TAC_PLUS_REPLY_FLAG_NOECHO		0x01
/* Authen continue Flags */
#define TAC_PLUS_CONTINUE_FLAG_ABORT    0x01

/* methods of authentication */
enum {
	TAC_PLUS_AUTHEN_METH_NOT_SET	= 0x00,
	TAC_PLUS_AUTHEN_METH_NONE		= 0x01,
	TAC_PLUS_AUTHEN_METH_KRB5		= 0x03,
	TAC_PLUS_AUTHEN_METH_LINE		= 0x03,
	TAC_PLUS_AUTHEN_METH_ENABLE		= 0x04,
	TAC_PLUS_AUTHEN_METH_LOCAL		= 0x05,
	TAC_PLUS_AUTHEN_METH_TACACSPLUS	= 0x06,
	TAC_PLUS_AUTHEN_METH_GUEST		= 0x08,
	TAC_PLUS_AUTHEN_METH_RADIUS		= 0x10,
	TAC_PLUS_AUTHEN_METH_KRB4		= 0x11,
	TAC_PLUS_AUTHEN_METH_RCMD		= 0x20
};

/* authorization status */
enum
{
	TAC_PLUS_AUTHOR_STATUS_PASS_ADD		= 0x01,
	TAC_PLUS_AUTHOR_STATUS_PASS_REPL	= 0x02,
	TAC_PLUS_AUTHOR_STATUS_FAIL			= 0x10,
	TAC_PLUS_AUTHOR_STATUS_ERROR		= 0x11,
	TAC_PLUS_AUTHOR_STATUS_FOLLOW		= 0x21
};

/* accounting flag */

enum
{
	TAC_PLUS_ACCT_FLAG_MORE		= 0x1, /* deprecated */
	TAC_PLUS_ACCT_FLAG_START	= 0x2,
	TAC_PLUS_ACCT_FLAG_STOP		= 0x4,
	TAC_PLUS_ACCT_FLAG_WATCHDOG	= 0x8
};
/* accounting status */
enum {
	TAC_PLUS_ACCT_STATUS_SUCCESS	= 0x01,
	TAC_PLUS_ACCT_STATUS_ERROR		= 0x02,
	TAC_PLUS_ACCT_STATUS_FOLLOW		= 0x21
};

/* Header offsets */
#define H_VER_OFF			(0)
#define H_TYPE_OFF			(H_VER_OFF+1)
#define H_SEQ_NO_OFF		(H_TYPE_OFF+1)
#define H_FLAGS_OFF			(H_SEQ_NO_OFF+1)
#define H_SESSION_ID_OFF	(H_FLAGS_OFF+1)
#define H_LENGTH_OFF		(H_SESSION_ID_OFF+4)

#define TACPLUS_BODY_OFF		0
/* authen START offsets */
#define AUTHEN_S_ACTION_OFF			(TACPLUS_BODY_OFF)
#define AUTHEN_S_PRIV_LVL_OFF		(AUTHEN_S_ACTION_OFF+1)
#define AUTHEN_S_AUTHEN_TYPE_OFF	(AUTHEN_S_PRIV_LVL_OFF+1)
#define AUTHEN_S_SERVICE_OFF		(AUTHEN_S_AUTHEN_TYPE_OFF+1)
#define AUTHEN_S_USER_LEN_OFF		(AUTHEN_S_SERVICE_OFF+1)
#define AUTHEN_S_PORT_LEN_OFF		(AUTHEN_S_USER_LEN_OFF+1)
#define AUTHEN_S_REM_ADDR_LEN_OFF	(AUTHEN_S_PORT_LEN_OFF+1)
#define AUTHEN_S_DATA_LEN_OFF		(AUTHEN_S_REM_ADDR_LEN_OFF+1)
#define AUTHEN_S_VARDATA_OFF		(AUTHEN_S_DATA_LEN_OFF+1) /* variable data offset (user, port, etc ) */

/* authen REPLY fields offset */
#define AUTHEN_R_STATUS_OFF			(TACPLUS_BODY_OFF)
#define AUTHEN_R_FLAGS_OFF			(AUTHEN_R_STATUS_OFF+1)
#define AUTHEN_R_SRV_MSG_LEN_OFF	(AUTHEN_R_FLAGS_OFF+1)
#define AUTHEN_R_DATA_LEN_OFF		(AUTHEN_R_SRV_MSG_LEN_OFF+2)
#define AUTHEN_R_VARDATA_OFF		(AUTHEN_R_DATA_LEN_OFF+2)

/* authen CONTINUE fields offset */
#define AUTHEN_C_USER_LEN_OFF		(TACPLUS_BODY_OFF)
#define AUTHEN_C_DATA_LEN_OFF		(AUTHEN_C_USER_LEN_OFF+2)
#define AUTHEN_C_FLAGS_OFF			(AUTHEN_C_DATA_LEN_OFF+2)
#define AUTHEN_C_VARDATA_OFF		(AUTHEN_C_FLAGS_OFF+1)

/* acct REQUEST fields offsets */
#define ACCT_Q_FLAGS_OFF			(TACPLUS_BODY_OFF)
#define ACCT_Q_METHOD_OFF			(ACCT_Q_FLAGS_OFF+1)
#define ACCT_Q_PRIV_LVL_OFF			(ACCT_Q_METHOD_OFF+1)
#define ACCT_Q_AUTHEN_TYPE_OFF		(ACCT_Q_PRIV_LVL_OFF+1)
#define ACCT_Q_SERVICE_OFF			(ACCT_Q_AUTHEN_TYPE_OFF+1)
#define ACCT_Q_USER_LEN_OFF			(ACCT_Q_SERVICE_OFF+1)
#define ACCT_Q_PORT_LEN_OFF			(ACCT_Q_USER_LEN_OFF+1)
#define ACCT_Q_REM_ADDR_LEN_OFF		(ACCT_Q_PORT_LEN_OFF+1)
#define ACCT_Q_ARG_CNT_OFF			(ACCT_Q_REM_ADDR_LEN_OFF+1)
#define ACCT_Q_VARDATA_OFF			(ACCT_Q_ARG_CNT_OFF+1)

/* acct REPLY fields offsets */
#define ACCT_R_SRV_MSG_LEN_OFF		(TACPLUS_BODY_OFF)
#define ACCT_R_DATA_LEN_OFF			(ACCT_R_SRV_MSG_LEN_OFF+2)
#define ACCT_R_STATUS_OFF			(ACCT_R_DATA_LEN_OFF+2)
#define ACCT_R_VARDATA_OFF			(ACCT_R_STATUS_OFF+1)

/* AUTHORIZATION */
/* Request */
#define AUTHOR_Q_AUTH_METH_OFF		(TACPLUS_BODY_OFF)
#define AUTHOR_Q_PRIV_LVL_OFF		(AUTHOR_Q_AUTH_METH_OFF+1)
#define AUTHOR_Q_AUTHEN_TYPE_OFF	(AUTHOR_Q_PRIV_LVL_OFF+1)
#define AUTHOR_Q_SERVICE_OFF		(AUTHOR_Q_AUTHEN_TYPE_OFF+1)
#define AUTHOR_Q_USER_LEN_OFF		(AUTHOR_Q_SERVICE_OFF+1)
#define AUTHOR_Q_PORT_LEN_OFF		(AUTHOR_Q_USER_LEN_OFF+1)
#define AUTHOR_Q_REM_ADDR_LEN_OFF	(AUTHOR_Q_PORT_LEN_OFF+1)
#define AUTHOR_Q_ARGC_OFF			(AUTHOR_Q_REM_ADDR_LEN_OFF+1)
#define AUTHOR_Q_VARDATA_OFF		(AUTHOR_Q_ARGC_OFF+1)

/* Reply */
#define AUTHOR_R_STATUS_OFF			(TACPLUS_BODY_OFF)
#define AUTHOR_R_ARGC_OFF			(AUTHOR_R_STATUS_OFF+1)
#define AUTHOR_R_SRV_MSG_LEN_OFF	(AUTHOR_R_ARGC_OFF+1)
#define AUTHOR_R_DATA_LEN_OFF		(AUTHOR_R_SRV_MSG_LEN_OFF+2)
#define AUTHOR_R_VARDATA_OFF		(AUTHOR_R_DATA_LEN_OFF+2)


#if 0
/* Packet structures */
typedef struct  {
	u_char version;
	u_char type;
	u_char seq_no;
	u_char flags;
	guint32 session_id;     
	guint32 length; 
} tacplus_pkt_hdr; 

/* Authentication START packet */
typedef	struct {
	u_char	action;
	u_char	priv_lvl;
	u_char	authen_type;
	u_char	service;
	u_char	user_len;
	u_char	port_len;
	u_char	rem_addr_len;
	u_char	data_len;
	u_char	vardata[1];
} tacplus_authen_start ;

/* Authentication CONTINUE packet */
typedef struct {
	guint16	user_len;
	guint16 data_len;
	u_char	flags;
	u_char	vardata[1];
} tacplus_authen_continue ;

/* Authentication REPLY packet */
typedef struct {
	u_char	status;
	u_char	flags;
	guint16	srv_msg_len;
	guint16	data_len;
	u_char	vardata[1];
} tacplus_authen_reply;


/* Authentication sub-PACKET */
typedef union {
	tacplus_authen_start 	s; /* start */
	tacplus_authen_continue c; /* continue */
	tacplus_authen_reply	r; /* reply (from srv) */
} tacplus_authen_pkt;

/* AUTHORIZATION request */

typedef struct {
	u_char	authen_method;
	u_char	priv_lvl;
	u_char	authen_type;
	u_char	authen_service;
	u_char	user_len;
	u_char	port_len;
	u_char	rem_addr_len;
	u_char	arg_cnt;
	u_char	vardata[1];
} tacplus_author_request;

typedef struct {
	u_char	status;
	u_char	arg_cnt;
	guint16	srv_msg_len;
	guint16	data_len;
	u_char	vardata[1];
} tacplus_author_reply;

typedef union {
	tacplus_author_request	q;
	tacplus_author_reply	r;
} tacplus_author_pkt;

/* ACCOUNTING request */
typedef struct {
	u_char	flags;
	u_char	authen_method;
	u_char	priv_lvl;
	u_char	authen_type;
	u_char	authen_service;
	u_char	user_len;
	u_char	port_len;
	u_char	rem_addr_len;
	u_char	arg_cnt;
	u_char	vardata[1];
} tacplus_account_request;

typedef struct {
	guint16	srv_msg_len;
	guint16 data_len;
	u_char	status;
	u_char	vardata[1];
} tacplus_account_reply;

typedef union {
	tacplus_account_request q; /* Request */
	tacplus_account_reply	r; /* Reply */
} tacplus_account_pkt;

/* TACACS+ Packet */
typedef struct {
	tacplus_pkt_hdr hdr;
	union {
		tacplus_authen_pkt authen;
		tacplus_author_pkt author;
		tacplus_account_pkt acct;
	} body;
} tacplus_pkt;

#endif

/* From my old tacacs dissector */
static value_string tacplus_type_vals[] = {
	{TAC_PLUS_AUTHEN,	"Authentication"},
	{TAC_PLUS_AUTHOR,	"Authorization"	},
	{TAC_PLUS_ACCT,		"Accounting"	},
	{0, NULL}};

static value_string tacplus_authen_action_vals[] = {
	{TAC_PLUS_AUTHEN_LOGIN, 		"Inbound Login"},
	{TAC_PLUS_AUTHEN_CHPASS, 		"Change password request"},
	{TAC_PLUS_AUTHEN_SENDPASS, 		"Send password request"},
	{TAC_PLUS_AUTHEN_SENDAUTH, 		"Outbound Request (SENDAUTH)"},
	{0, NULL}};

#if 0
static value_string tacplus_authen_priv_lvl_vals[] = {
	{TAC_PLUS_PRIV_LVL_MAX, 		"LVL_MAX"},
	{TAC_PLUS_PRIV_LVL_ROOT, 		"LVL_ROOT"},
	{TAC_PLUS_PRIV_LVL_USER,		"LVL_USER"},
	{TAC_PLUS_PRIV_LVL_MIN,			"LVL_MIN"},
	{0, NULL}};
#endif

static value_string tacplus_authen_type_vals[] = {
	{TAC_PLUS_AUTHEN_TYPE_ASCII,	"ASCII"},
	{TAC_PLUS_AUTHEN_TYPE_PAP,		"PAP"},
	{TAC_PLUS_AUTHEN_TYPE_CHAP,		"CHAP"},
	{TAC_PLUS_AUTHEN_TYPE_ARAP,		"ARAP"},
	{TAC_PLUS_AUTHEN_TYPE_MSCHAP,	"MS-CHAP"},
	{0, NULL}};

static value_string tacplus_authen_service_vals[] = {
	{TAC_PLUS_AUTHEN_SVC_NONE,		"TAC_PLUS_AUTHEN_SVC_NONE"},
	{TAC_PLUS_AUTHEN_SVC_LOGIN,		"Login"	},
	{TAC_PLUS_AUTHEN_SVC_ENABLE,	"ENABLE"},
	{TAC_PLUS_AUTHEN_SVC_PPP,		"PPP"	},
	{TAC_PLUS_AUTHEN_SVC_ARAP,		"ARAP"	},
	{TAC_PLUS_AUTHEN_SVC_PT,		"TAC_PLUS_AUTHEN_SVC_PT"},
	{TAC_PLUS_AUTHEN_SVC_RCMD,		"TAC_PLUS_AUTHEN_SVC_RCMD"},
	{TAC_PLUS_AUTHEN_SVC_X25,		"TAC_PLUS_AUTHEN_SVC_X25"},
	{TAC_PLUS_AUTHEN_SVC_NASI,		"TAC_PLUS_AUTHEN_SVC_NASI"},
	{TAC_PLUS_AUTHEN_SVC_FWPROXY,	"TAC_PLUS_AUTHEN_SVC_FWPROXY"},
	{0, NULL}};

static value_string tacplus_reply_status_vals[] = {
	{TAC_PLUS_AUTHEN_STATUS_PASS, 		"Authentication Passed"},
	{TAC_PLUS_AUTHEN_STATUS_FAIL, 		"Authentication Failed"},
	{TAC_PLUS_AUTHEN_STATUS_GETDATA,	"Send Data"},
	{TAC_PLUS_AUTHEN_STATUS_GETUSER,	"Send Username"},
	{TAC_PLUS_AUTHEN_STATUS_GETPASS,	"Send Password"},
	{TAC_PLUS_AUTHEN_STATUS_RESTART,	"Restart Authentication Sequence"},
	{TAC_PLUS_AUTHEN_STATUS_ERROR,		"Unrecoverable Error"},
	{TAC_PLUS_AUTHEN_STATUS_FOLLOW,		"Use Alternate Server"},
	{0, NULL}};


static value_string tacplus_authen_method[] = {
	{TAC_PLUS_AUTHEN_METH_NOT_SET,		"NOT_SET"},
	{TAC_PLUS_AUTHEN_METH_NONE,			"NONE"},
	{TAC_PLUS_AUTHEN_METH_KRB5,			"KRB5"},
	{TAC_PLUS_AUTHEN_METH_LINE,			"LINE"},
	{TAC_PLUS_AUTHEN_METH_ENABLE,		"ENABLE"},
	{TAC_PLUS_AUTHEN_METH_LOCAL,		"LOCAL"},
	{TAC_PLUS_AUTHEN_METH_TACACSPLUS,	"TACACSPLUS"},
	{TAC_PLUS_AUTHEN_METH_GUEST,		"GUEST"},
	{TAC_PLUS_AUTHEN_METH_RADIUS,		"RADIUS"},
	{TAC_PLUS_AUTHEN_METH_KRB4,			"KRB4"},
	{TAC_PLUS_AUTHEN_METH_RCMD,			"RCMD"},
	{0, NULL}};

static value_string tacplus_author_status[] = {
	{TAC_PLUS_AUTHOR_STATUS_PASS_ADD,		"PASS_ADD"},
	{TAC_PLUS_AUTHOR_STATUS_PASS_REPL,		"PASS_REPL"},
	{TAC_PLUS_AUTHOR_STATUS_FAIL,		"FAIL"},
	{TAC_PLUS_AUTHOR_STATUS_ERROR,		"ERROR"},
	{TAC_PLUS_AUTHOR_STATUS_FOLLOW,		"FOLLOW"},
	{0, NULL}};

static value_string tacplus_acct_status[] = {
	{TAC_PLUS_ACCT_STATUS_SUCCESS,	"Success"},
	{TAC_PLUS_ACCT_STATUS_ERROR,	"Error"},
	{TAC_PLUS_ACCT_STATUS_FOLLOW,	"Follow"},
	{0, NULL}};

#ifdef __TAC_ACCOUNTING__
static value_string tacplus_acct_flags[] = {
	{TAC_PLUS_ACCT_FLAG_MORE,	"More (deprecated)"},
	{TAC_PLUS_ACCT_FLAG_START,	"Start"},
	{TAC_PLUS_ACCT_FLAG_STOP,	"Stop"},
	{TAC_PLUS_ACCT_FLAG_WATCHDOG,"Update"},
	{0, NULL}};
#endif

#endif   /* __PACKET_TACACS_H__ */
