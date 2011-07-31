/* packet-tds.c
 * Routines for TDS NetLib dissection
 * Copyright 2000-2002, Brian Bruns <camber@ais.org>
 * Copyright 2002, Steve Langasek <vorlon@netexpress.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * The NETLIB protocol is a small blocking protocol designed to allow TDS
 * to be placed within different transports (TCP, DECNet, IPX/SPX).  A
 * NETLIB packet starts with an eight byte header containing:
 *
 *      a one-byte packet type field;
 *
 *      a one-byte status field;
 *
 *      a two-byte big-endian size field giving the size of the packet,
 *      including the header;
 *
 *      a two-byte big-endian channel number, used when multiple sessions
 *      are being multiplexed on a single connection;
 *
 *      a one-byte packet number, giving "the frame number of a multiplexed
 *      message, modulo 256";
 *
 *      a one-byte window, which is the number of frames to be sent
 *      before an acknowledgment message is received.
 *
 * followed by payload whose size is the value in the size field minus
 * 8.
 *
 * Microsoft Network Monitor 2.x dissects the 4 byte field (and indicates
 * that the one-byte last packet indicator also contains other bits).
 *
 * The TDS protocol consists of a number of protocol data units (PDUs) that
 * appear to be assembled from NETLIB packets, in the form of zero or more
 * NETLIB packets with the last packet indicator clear and a final NETLIB
 * packet with the last packet indicator set.  The type of the TDS PDU is
 * specified by the packet type field of the NETLIB header (presumably that
 * field has the same value for all NETLIB packets that make up a TDS PDU).
 *
 * The "server response" PDU consists of a sequence of multiple items, each
 * one beginning with a one byte type field at the start of the PDU.  Some
 * items are fixed length, some are variable length with a two byte size
 * field following the item type, and then there is TDS_ROW_TOKEN in which
 * size is determined by analyzing the result set returned from the server.
 * This in effect means that we are hopelessly lost if we haven't seen the
 * result set.  Also, TDS 4/5 is byte order negotiable, which is specified
 * in the login packet.  We can attempt to determine it later on, but not
 * with 100% accuracy.
 *
 * Some preliminary documentation on the packet format can be found at
 * http://www.freetds.org/tds.html
 *
 * Some more information can be found in
 * http://download.nai.com/products/media/sniffer/support/sdos/sybase.pdf
 *
 * Much of this code was originally developed for the FreeTDS project.
 * http://www.freetds.org
 */

/*
 * Excerpts from Brian's posting to wireshark-dev:
 *
 * The TDS Protocol is actually a protocol within a protocol.  On the outside
 * there is netlib which is not so much a encapsulation as a blocking of the
 * data, typically to 512 or 4096 bytes.  Between this are the protocol data
 * units for TDS.  Netlib packets may be split over real packets, multiple
 * netlib packets may appear in single real packets.  TDS PDUs may be split
 * over netlib packets (and real packets) and most certainly can appear
 * multiple times within a netlib packet.
 *
 * Because of this, I abandoned my earlier attempt at making two dissectors,
 * one for netlib and one for TDS. Counterintuitively, a single dissector
 * turned out to be simpler than splitting it up.
 *
 * Here are some of the (hefty) limitations of the current code
 *
 * . We currently do not handle netlib headers that cross packet boundaries.
 *   This should be an easy fix.
 * . I probably could have used the packet reassembly stuff, but I started
 *   this at version 0.8.20, so c'est la vie. It wouldn't have covered the
 *   netlib stuff anyway, so no big loss.
 * . The older two layer version of the code dissected the PDU's, but the new
 *   version does not yet, it only labels the names. I need an elegant way to
 *   deal with dissecting data crossing (netlib and tcp) packet boundries.  I
 *   think I have one, but ran out of time to do it.
 * . It will only work on little endian platforms.  Or rather I should say,
 *   the client that was captured must be little endian.  TDS 7.0/8.0 is
 *   always LE; for TDS 4.2/5.0 look in the code for tvb_get_le*() functions,
 *   there are fields in the login packet which determine byte order.
 * . result sets that span netlib packets are not working
 * . TDS 7 and 4.2 result sets are not working yet
 *
 * All that said, the code does deal gracefully with different boudary
 * conditions and what remains are the easier bits, IMHO.
 *
 * XXX - "real packets" means "TCP segments", for TCP.
 *
 * XXX - is it *REALLY* true that you can have more than one TDS PDU (as
 * opposed to more than one server response item) per NETLIB packet?  Or is
 * all the data in a NETLIB packet put into a single TDS PDU?  If so, then
 * we can reassemble NETLIB packets using the standard TCP desegmentation
 * code, and can reassemble TDS PDUs using "fragment_add_seq_check()",
 * and more cleanly separate the NETLIB and TDS dissectors (although the
 * "is this NETLIB" heuristic would have to look at TDS information past
 * the NETLIB header, in order to make the heuristic strong enough not
 * to get too many false positives; note that the heuristic should reject
 * any putative NETLIB packet with a length field with a value < 8).
 *
 * That would substantially clean the dissector up, eliminating most of
 * the per-packet data (we might still need information to handle
 * TDS_ROW_TOKEN), getting rid of the stuff to handle data split across
 * TCP segment boundaries in favor of simple reassembly code, and
 * fixing some otherwise nasty-looking crashing bugs.
 *
 * NOTE: we assume that all the data in a NETLIB packet *can* be put into
 * a single TDS PTU, so that we have separate reassembly of NETLIB
 * packets and TDS PDUs; it seems to work, and it really did clean stuff
 * up and fix crashes.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "isprint.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>

#include "packet-frame.h"
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/expert.h>

#define TDS_QUERY_PKT        1
#define TDS_LOGIN_PKT        2
#define TDS_RPC_PKT          3
#define TDS_RESP_PKT         4
#define TDS_RAW_PKT          5
#define TDS_ATTENTION_PKT    6
#define TDS_BULK_DATA_PKT    7
#define TDS_OPEN_CHN_PKT     8
#define TDS_CLOSE_CHN_PKT    9
#define TDS_RES_ERROR_PKT   10
#define TDS_LOG_CHN_ACK_PKT 11
#define TDS_ECHO_PKT        12
#define TDS_LOGOUT_CHN_PKT  13
#define TDS_TRANS_MGR_PKT   14
#define TDS_QUERY5_PKT      15  /* or "Normal tokenized request or response */
#define TDS_LOGIN7_PKT      16  /* or "Urgent tokenized request or response */
#define TDS_SSPI_PKT        17
#define TDS_PRELOGIN_PKT    18
#define TDS_INVALID_PKT     19

#define is_valid_tds_type(x) ((x) >= TDS_QUERY_PKT && (x) < TDS_INVALID_PKT)

/* The following constants are imported more or less directly from FreeTDS */
/*      Updated from FreeTDS v0.63 tds.h                                   */
/*         "$Id: tds.h,v 1.192 2004/10/28 12:42:12 freddy77]"              */
/* Note: [###] below means 'not defined in FreeTDS tds.h'                  */

#define TDS5_PARAMFMT2_TOKEN       32  /* 0x20    TDS 5.0 only              */
#define TDS_LANG_TOKEN             33  /* 0x21    TDS 5.0 only              */
#define TDS5_ORDERBY2_TOKEN        34  /* 0x22    TDS 5.0 only              */
#define TDS5_CURDECLARE2_TOKEN     35  /* 0x23    TDS 5.0 only        [###] */
#define TDS5_ROWFMT2_TOKEN         97  /* 0x61    TDS 5.0 only              */
#define TDS5_MSG_TOKEN            101  /* 0x65    TDS 5.0 only        [###] */
#define TDS_LOGOUT_TOKEN          113  /* 0x71    TDS 5.0 only? ct_close()  */
#define TDS_RET_STAT_TOKEN        121  /* 0x79                              */
#define TDS_PROCID_TOKEN          124  /* 0x7C    TDS 4.2 only - TDS_PROCID */
#define TDS_CURCLOSE_TOKEN        128  /* 0x80    TDS 5.0 only              */
#define TDS7_RESULT_TOKEN         129  /* 0x81    TDS 7.0 only              */
#define TDS_CURFETCH_TOKEN        130  /* 0x82    TDS 5.0 only              */
#define TDS_CURINFO_TOKEN         131  /* 0x83    TDS 5.0 only              */
#define TDS_CUROPEN_TOKEN         132  /* 0x84    TDS 5.0 only              */
#define TDS_CURDECLARE_TOKEN      134  /* 0x86    TDS 5.0 only              */
#define TDS7_COMPUTE_RESULT_TOKEN 136  /* 0x88    TDS 7.0 only              */
#define TDS_COL_NAME_TOKEN        160  /* 0xA0    TDS 4.2 only              */
#define TDS_COL_INFO_TOKEN        161  /* 0xA1    TDS 4.2 only - TDS_COLFMT */
#define TDS5_DYNAMIC2_TOKEN       163  /* 0xA3    TDS 5.0 only              */
#if 0 /* XX: Why commented out ? These are 'live' in FreeTDS tds.h */
#define TDS_TABNAME               164  /* 0xA4                              */
#define TDS_COL_INFO              165  /* 0xA5                              */
#endif
#define TDS_OPTIONCMD_TOKEN       166  /* 0xA6 */
#define TDS_COMPUTE_NAMES_TOKEN   167  /* 0xA7 */
#define TDS_COMPUTE_RESULT_TOKEN  168  /* 0xA8 */
#define TDS_ORDER_BY_TOKEN        169  /* 0xA9    TDS_ORDER                 */
#define TDS_ERR_TOKEN             170  /* 0xAA                              */
#define TDS_MSG_TOKEN             171  /* 0xAB                              */
#define TDS_PARAM_TOKEN           172  /* 0xAC    RETURNVALUE?              */
#define TDS_LOGIN_ACK_TOKEN       173  /* 0xAD                              */
#define TDS_CONTROL_TOKEN         174  /* 0xAE    TDS_CONTROL               */
#define TDS_KEY_TOKEN             202  /* 0xCA                        [###] */
#define TDS_ROW_TOKEN             209  /* 0xD1                              */
#define TDS_CMP_ROW_TOKEN         211  /* 0xD3                              */
#define TDS5_PARAMS_TOKEN         215  /* 0xD7    TDS 5.0 only              */
#define TDS_CAP_TOKEN             226  /* 0xE2                              */
#define TDS_ENV_CHG_TOKEN         227  /* 0xE3                              */
#define TDS_EED_TOKEN             229  /* 0xE5                              */
#define TDS_DBRPC_TOKEN           230  /* 0xE6                              */
#define TDS5_DYNAMIC_TOKEN        231  /* 0xE7    TDS 5.0 only              */
#define TDS5_PARAMFMT_TOKEN       236  /* 0xEC    TDS 5.0 only              */
#define TDS_AUTH_TOKEN            237  /* 0xED                              */
#define TDS_RESULT_TOKEN          238  /* 0xEE                              */
#define TDS_DONE_TOKEN            253  /* 0xFD    TDS_DONE                  */
#define TDS_DONEPROC_TOKEN        254  /* 0xFE    TDS_DONEPROC              */
#define TDS_DONEINPROC_TOKEN      255  /* 0xFF    TDS_DONEINPROC            */

/* Microsoft internal stored procedure id's */

#define TDS_SP_CURSOR           1
#define TDS_SP_CURSOROPEN       2
#define TDS_SP_CURSORPREPARE    3
#define TDS_SP_CURSOREXECUTE    4
#define TDS_SP_CURSORPREPEXEC   5
#define TDS_SP_CURSORUNPREPARE  6
#define TDS_SP_CURSORFETCH      7
#define TDS_SP_CURSOROPTION     8
#define TDS_SP_CURSORCLOSE      9
#define TDS_SP_EXECUTESQL      10
#define TDS_SP_PREPARE         11
#define TDS_SP_EXECUTE         12
#define TDS_SP_PREPEXEC        13
#define TDS_SP_PREPEXECRPC     14
#define TDS_SP_UNPREPARE       15


#define TDS_RPC_OPT_WITH_RECOMP    0x01
#define TDS_RPC_OPT_NO_METADATA    0x02
#define TDS_RPC_OPT_REUSE_METADATA 0x04

#define TDS_RPC_PARAMETER_STATUS_BY_REF  0x01
#define TDS_RPC_PARAMETER_STATUS_DEFAULT 0x02

/* Sybase Data Types */

#define SYBCHAR        47  /* 0x2F */
#define SYBVARCHAR     39  /* 0x27 */
#define SYBINTN        38  /* 0x26 */
#define SYBINT1        48  /* 0x30 */
#define SYBINT2        52  /* 0x34 */
#define SYBINT4        56  /* 0x38 */
#define SYBINT8       127  /* 0x7F */
#define SYBFLT8        62  /* 0x3E */
#define SYBDATETIME    61  /* 0x3D */
#define SYBBIT         50  /* 0x32 */
#define SYBTEXT        35  /* 0x23 */
#define SYBNTEXT       99  /* 0x63 */
#define SYBIMAGE       34  /* 0x22 */
#define SYBMONEY4     122  /* 0x7A */
#define SYBMONEY       60  /* 0x3C */
#define SYBDATETIME4   58  /* 0x3A */
#define SYBREAL        59  /* 0x3B */
#define SYBBINARY      45  /* 0x2D */
#define SYBVOID        31  /* 0x1F */
#define SYBVARBINARY   37  /* 0x25 */
#define SYBNVARCHAR   103  /* 0x67 */
#define SYBBITN       104  /* 0x68 */
#define SYBNUMERIC    108  /* 0x6C */
#define SYBDECIMAL    106  /* 0x6A */
#define SYBFLTN       109  /* 0x6D */
#define SYBMONEYN     110  /* 0x6E */
#define SYBDATETIMN   111  /* 0x6F */
#define XSYBCHAR      175  /* 0xA7 */
#define XSYBVARCHAR   167  /* 0xAF */
#define XSYBNVARCHAR  231  /* 0xE7 */
#define XSYBNCHAR     239  /* 0xEF */
#define XSYBVARBINARY 165  /* 0xA5 */
#define XSYBBINARY    173  /* 0xAD */
#define SYBLONGBINARY 225  /* 0xE1 */
#define SYBSINT1       64  /* 0x40 */
#define SYBUINT2       65  /* 0x41 */
#define SYBUINT4       66  /* 0x42 */
#define SYBUINT8       67  /* 0x43 */
#define SYBUNIQUE      36  /* 0x24 */
#define SYBVARIANT     98  /* 0x62 */

#define is_fixed_coltype(x) (x==SYBINT1    ||           \
                             x==SYBINT2      ||         \
                             x==SYBINT4      ||         \
                             x==SYBINT8      ||         \
                             x==SYBREAL       ||        \
                             x==SYBFLT8      ||         \
                             x==SYBDATETIME  ||         \
                             x==SYBDATETIME4 ||         \
                             x==SYBBIT       ||         \
                             x==SYBMONEY     ||         \
                             x==SYBMONEY4    ||         \
                             x==SYBUNIQUE)

/* FIXEDLENTYPE */
#define TDS_DATA_TYPE_NULL            0x1F  /* Null (no data associated with this type) */
#define TDS_DATA_TYPE_INT1            0x30  /* TinyInt (1 byte data representation) */
#define TDS_DATA_TYPE_BIT             0x32  /* Bit (1 byte data representation) */
#define TDS_DATA_TYPE_INT2            0x34  /* SmallInt (2 byte data representation) */
#define TDS_DATA_TYPE_INT4            0x38  /* Int (4 byte data representation) */
#define TDS_DATA_TYPE_DATETIM4        0x3A  /* SmallDateTime (4 byte data representation) */
#define TDS_DATA_TYPE_FLT4            0x3B  /* Real (4 byte data representation) */
#define TDS_DATA_TYPE_MONEY           0x3C  /* Money (8 byte data representation) */
#define TDS_DATA_TYPE_DATETIME        0x3D  /* DateTime (8 byte data representation) */
#define TDS_DATA_TYPE_FLT8            0x3E  /* Float (8 byte data representation) */
#define TDS_DATA_TYPE_MONEY4          0x7A  /* SmallMoney (4 byte data representation) */
#define TDS_DATA_TYPE_INT8            0x7F  /* BigInt (8 byte data representation) */
/* BYTELEN_TYPE */
#define TDS_DATA_TYPE_GUID            0x24  /* UniqueIdentifier */
#define TDS_DATA_TYPE_INTN            0x26
#define TDS_DATA_TYPE_DECIMAL         0x37  /* Decimal (legacy support) */
#define TDS_DATA_TYPE_NUMERIC         0x3F  /* Numeric (legacy support) */
#define TDS_DATA_TYPE_BITN            0x68
#define TDS_DATA_TYPE_DECIMALN        0x6A  /* Decimal */
#define TDS_DATA_TYPE_NUMERICN        0x6C  /* Numeric */
#define TDS_DATA_TYPE_FLTN            0x6D
#define TDS_DATA_TYPE_MONEYN          0x6E
#define TDS_DATA_TYPE_DATETIMN        0x6F
#define TDS_DATA_TYPE_DATEN           0x28  /* (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_TIMEN           0x29  /* (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_DATETIME2N      0x2A  /* (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_DATETIMEOFFSETN 0x2B  /* (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_CHAR            0x2F  /* Char (legacy support) */
#define TDS_DATA_TYPE_VARCHAR         0x27  /* VarChar (legacy support) */
#define TDS_DATA_TYPE_BINARY          0x2D  /* Binary (legacy support) */
#define TDS_DATA_TYPE_VARBINARY       0x25  /* VarBinary (legacy support) */
/* USHORTLEN_TYPE */
#define TDS_DATA_TYPE_BIGVARBIN       0xA5  /* VarBinary */
#define TDS_DATA_TYPE_BIGVARCHR       0xA7  /* VarChar */
#define TDS_DATA_TYPE_BIGBINARY       0xAD  /* Binary */
#define TDS_DATA_TYPE_BIGCHAR         0xAF  /* Char */
#define TDS_DATA_TYPE_NVARCHAR        0xE7  /* NVarChar */
#define TDS_DATA_TYPE_NCHAR           0xEF  /* NChar */
/* LONGLEN_TYPE */
#define TDS_DATA_TYPE_XML             0xF1  /* XML (introduced in TDS 7.2) */
#define TDS_DATA_TYPE_UDT             0xF0  /* CLR-UDT (introduced in TDS 7.2) */
#define TDS_DATA_TYPE_TEXT            0x23  /* Text */
#define TDS_DATA_TYPE_IMAGE           0x22  /* Image */
#define TDS_DATA_TYPE_NTEXT           0x63  /* NText */
#define TDS_DATA_TYPE_SSVARIANT       0x62  /* Sql_Variant (introduced in TDS 7.2) */

static const value_string tds_data_type_names[] = {
    /* FIXEDLENTYPE */
    {TDS_DATA_TYPE_NULL,            "NULLTYPE - Null (no data associated with this type)"},
    {TDS_DATA_TYPE_INT1,            "INT1TYPE - TinyInt (1 byte data representation)"},
    {TDS_DATA_TYPE_BIT,             "BITTYPE - Bit (1 byte data representation)"},
    {TDS_DATA_TYPE_INT2,            "INT2TYPE - SmallInt (2 byte data representation)"},
    {TDS_DATA_TYPE_INT4,            "INT4TYPE - Int (4 byte data representation)"},
    {TDS_DATA_TYPE_DATETIM4,        "DATETIM4TYPE - SmallDateTime (4 byte data representation)"},
    {TDS_DATA_TYPE_FLT4,            "FLT4TYPE - Real (4 byte data representation)"},
    {TDS_DATA_TYPE_MONEY,           "MONEYTYPE - Money (8 byte data representation)"},
    {TDS_DATA_TYPE_DATETIME,        "DATETIMETYPE - DateTime (8 byte data representation)"},
    {TDS_DATA_TYPE_FLT8,            "FLT8TYPE - Float (8 byte data representation)"},
    {TDS_DATA_TYPE_MONEY4,          "MONEY4TYPE - SmallMoney (4 byte data representation)"},
    {TDS_DATA_TYPE_INT8,            "INT8TYPE - BigInt (8 byte data representation)"},
    /* BYTELEN_TYPE */
    {TDS_DATA_TYPE_GUID,            "GUIDTYPE - UniqueIdentifier"},
    {TDS_DATA_TYPE_INTN,            "INTNTYPE"},
    {TDS_DATA_TYPE_DECIMAL,         "DECIMALTYPE - Decimal (legacy support)"},
    {TDS_DATA_TYPE_NUMERIC,         "NUMERICTYPE - Numeric (legacy support)"},
    {TDS_DATA_TYPE_BITN,            "BITNTYPE"},
    {TDS_DATA_TYPE_DECIMALN,        "DECIMALNTYPE - Decimal"},
    {TDS_DATA_TYPE_NUMERICN,        "NUMERICNTYPE - Numeric"},
    {TDS_DATA_TYPE_FLTN,            "FLTNTYPE"},
    {TDS_DATA_TYPE_MONEYN,          "MONEYNTYPE"},
    {TDS_DATA_TYPE_DATETIMN,        "DATETIMNTYPE"},
    {TDS_DATA_TYPE_DATEN,           "DATENTYPE - (introduced in TDS 7.3)"},
    {TDS_DATA_TYPE_TIMEN,           "TIMENTYPE - (introduced in TDS 7.3)"},
    {TDS_DATA_TYPE_DATETIME2N,      "DATETIME2NTYPE - (introduced in TDS 7.3)"},
    {TDS_DATA_TYPE_DATETIMEOFFSETN, "DATETIMEOFFSETNTYPE - (introduced in TDS 7.3)"},
    {TDS_DATA_TYPE_CHAR,            "CHARTYPE - Char (legacy support)"},
    {TDS_DATA_TYPE_VARCHAR,         "VARCHARTYPE - VarChar (legacy support)"},
    {TDS_DATA_TYPE_BINARY,          "BINARYTYPE - Binary (legacy support)"},
    {TDS_DATA_TYPE_VARBINARY,       "VARBINARYTYPE - VarBinary (legacy support)"},
    /* USHORTLEN_TYPE */
    {TDS_DATA_TYPE_BIGVARBIN,       "BIGVARBINTYPE - VarBinary"},
    {TDS_DATA_TYPE_BIGVARCHR,       "BIGVARCHRTYPE - VarChar"},
    {TDS_DATA_TYPE_BIGBINARY,       "BIGBINARYTYPE - Binary"},
    {TDS_DATA_TYPE_BIGCHAR,         "BIGCHARTYPE - Char"},
    {TDS_DATA_TYPE_NVARCHAR,        "NVARCHARTYPE - NVarChar"},
    {TDS_DATA_TYPE_NCHAR,           "NCHARTYPE - NChar"},
    /* LONGLEN_TYPE */
    {TDS_DATA_TYPE_XML,             "XMLTYPE - XML (introduced in TDS 7.2)"},
    {TDS_DATA_TYPE_UDT,             "UDTTYPE - CLR-UDT (introduced in TDS 7.2)"},
    {TDS_DATA_TYPE_TEXT,            "TEXTTYPE - Text"},
    {TDS_DATA_TYPE_IMAGE,           "IMAGETYPE - Image"},
    {TDS_DATA_TYPE_NTEXT,           "NTEXTTYPE - NText"},
    {TDS_DATA_TYPE_SSVARIANT,       "SSVARIANTTYPE - Sql_Variant (introduced in TDS 7.2)"},
    {0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_tds = -1;
static int hf_tds_type = -1;
static int hf_tds_status = -1;
static int hf_tds_status_eom = -1;
static int hf_tds_status_ignore = -1;
static int hf_tds_status_event_notif = -1;
static int hf_tds_status_reset_conn = -1;
static int hf_tds_status_reset_conn_skip_tran = -1;
static int hf_tds_length = -1;
static int hf_tds_channel = -1;
static int hf_tds_packet_number = -1;
static int hf_tds_window = -1;
static int hf_tds_reassembled_in = -1;
static int hf_tds_reassembled_length = -1;
static int hf_tds_fragments = -1;
static int hf_tds_fragment = -1;
static int hf_tds_fragment_overlap = -1;
static int hf_tds_fragment_overlap_conflict = -1;
static int hf_tds_fragment_multiple_tails = -1;
static int hf_tds_fragment_too_long_fragment = -1;
static int hf_tds_fragment_error = -1;
static int hf_tds_fragment_count = -1;

static int hf_tds7_login_total_size = -1;
static int hf_tds7_version = -1;
static int hf_tds7_packet_size = -1;
static int hf_tds7_client_version = -1;
static int hf_tds7_client_pid = -1;
static int hf_tds7_connection_id = -1;
static int hf_tds7_option_flags1 = -1;
static int hf_tds7_option_flags2 = -1;
static int hf_tds7_sql_type_flags = -1;
static int hf_tds7_reserved_flags = -1;
static int hf_tds7_time_zone = -1;
static int hf_tds7_collation = -1;

static int hf_tds_all_headers = -1;
static int hf_tds_all_headers_total_length = -1;
static int hf_tds_all_headers_header_length = -1;
static int hf_tds_all_headers_header_type = -1;
static int hf_tds_all_headers_trans_descr = -1;
static int hf_tds_all_headers_request_cnt = -1;

static int hf_tds_type_info = -1;
static int hf_tds_type_info_type = -1;
static int hf_tds_type_info_varlen = -1;
static int hf_tds_type_info_precision = -1;
static int hf_tds_type_info_scale = -1;
static int hf_tds_type_info_collation = -1;
static int hf_tds_type_info_collation_lcid = -1;
static int hf_tds_type_info_collation_ign_case = -1;
static int hf_tds_type_info_collation_ign_accent = -1;
static int hf_tds_type_info_collation_ign_kana = -1;
static int hf_tds_type_info_collation_ign_width = -1;
static int hf_tds_type_info_collation_binary = -1;
static int hf_tds_type_info_collation_version = -1;
static int hf_tds_type_info_collation_sortid = -1;
static int hf_tds_type_varbyte_length = -1;
static int hf_tds_type_varbyte_data_null = -1;
static int hf_tds_type_varbyte_data_boolean = -1;
static int hf_tds_type_varbyte_data_int1 = -1;
static int hf_tds_type_varbyte_data_int2 = -1;
static int hf_tds_type_varbyte_data_int4 = -1;
static int hf_tds_type_varbyte_data_int8 = -1;
static int hf_tds_type_varbyte_data_float = -1;
static int hf_tds_type_varbyte_data_double = -1;
static int hf_tds_type_varbyte_data_bytes = -1;
static int hf_tds_type_varbyte_data_guid = -1;
static int hf_tds_type_varbyte_data_string = -1;
static int hf_tds_type_varbyte_plp_len = -1;
static int hf_tds_type_varbyte_plp_chunk_len = -1;

static int hf_tds_rpc = -1;
static int hf_tds_rpc_name_length8 = -1;
static int hf_tds_rpc_name_length = -1;
static int hf_tds_rpc_name = -1;
static int hf_tds_rpc_proc_id = -1;
static int hf_tds_rpc_options = -1;
static int hf_tds_rpc_options_with_recomp = -1;
static int hf_tds_rpc_options_no_metadata = -1;
static int hf_tds_rpc_options_reuse_metadata = -1;
static int hf_tds_rpc_separator = -1;
static int hf_tds_rpc_parameter = -1;
static int hf_tds_rpc_parameter_name_length = -1;
static int hf_tds_rpc_parameter_name = -1;
static int hf_tds_rpc_parameter_status = -1;
static int hf_tds_rpc_parameter_status_by_ref = -1;
static int hf_tds_rpc_parameter_status_default = -1;
static int hf_tds_rpc_parameter_value = -1;

/* Initialize the subtree pointers */
static gint ett_tds = -1;
static gint ett_tds_status = -1;
static gint ett_tds_fragments = -1;
static gint ett_tds_fragment = -1;
static gint ett_tds_token = -1;
static gint ett_tds_all_headers = -1;
static gint ett_tds_all_headers_header = -1;
static gint ett_tds_type_info = -1;
static gint ett_tds_type_info_collation = -1;
static gint ett_tds_type_varbyte = -1;
static gint ett_tds_message = -1;
static gint ett_tds_rpc_options = -1;
static gint ett_tds_rpc_parameter = -1;
static gint ett_tds_rpc_parameter_status = -1;
static gint ett_tds7_query = -1;
static gint ett_tds7_login = -1;
static gint ett_tds7_hdr = -1;

/* Desegmentation of Netlib buffers crossing TCP segment boundaries. */
static gboolean tds_desegment = TRUE;

static const fragment_items tds_frag_items = {
    &ett_tds_fragment,
    &ett_tds_fragments,
    &hf_tds_fragments,
    &hf_tds_fragment,
    &hf_tds_fragment_overlap,
    &hf_tds_fragment_overlap_conflict,
    &hf_tds_fragment_multiple_tails,
    &hf_tds_fragment_too_long_fragment,
    &hf_tds_fragment_error,
    &hf_tds_fragment_count,
    &hf_tds_reassembled_in,
    &hf_tds_reassembled_length,
    "fragments"
};

/* Tables for reassembly of fragments. */
static GHashTable *tds_fragment_table = NULL;
static GHashTable *tds_reassembled_table = NULL;

/* defragmentation of multi-buffer TDS PDUs */
static gboolean tds_defragment = TRUE;

static dissector_handle_t tds_tcp_handle;
static dissector_handle_t ntlmssp_handle;
static dissector_handle_t gssapi_handle;
static dissector_handle_t data_handle;

/* TDS protocol type preference */
/*   XXX: This preference is used as a 'hint' for cases where interpretation is ambiguous */
/*        Currently the hint is global                                                    */
/*   TODO: Consider storing protocol type with each conversation                          */
/*        (when type is determined and using the preference as a default) ??              */

#define TDS_PROTOCOL_NOT_SPECIFIED   0
#define TDS_PROTOCOL_4      0x40
#define TDS_PROTOCOL_5      0x50
#define TDS_PROTOCOL_7_0    0x70
#define TDS_PROTOCOL_7_1    0x71
#define TDS_PROTOCOL_7_2    0x72
#define TDS_PROTOCOL_7_3    0x73

static gint tds_protocol_type = TDS_PROTOCOL_NOT_SPECIFIED;

static const enum_val_t tds_protocol_type_options[] = {
    {"not_specified", "Not Specified", TDS_PROTOCOL_NOT_SPECIFIED},
    {"tds4", "TDS 4", TDS_PROTOCOL_4},  /* TDS 4.2 and TDS 4.6 */
    {"tds5", "TDS 5", TDS_PROTOCOL_5},
    {"tds70", "TDS 7.0", TDS_PROTOCOL_7_0},
    {"tds71", "TDS 7.1", TDS_PROTOCOL_7_1},
    {"tds72", "TDS 7.2", TDS_PROTOCOL_7_2},
    {"tds73", "TDS 7.3", TDS_PROTOCOL_7_3},
    {NULL, NULL, -1}
};

#define TDS_PROTO_PREF_NOT_SPECIFIED (tds_protocol_type == TDS_NOT_SPECIFIED)
#define TDS_PROTO_PREF_TDS4 (tds_protocol_type == TDS_PROTOCOL_4)
#define TDS_PROTO_PREF_TDS5 (tds_protocol_type == TDS_PROTOCOL_5)
#define TDS_PROTO_PREF_TDS7_0 (tds_protocol_type == TDS_PROTOCOL_7_0)
#define TDS_PROTO_PREF_TDS7_1 (tds_protocol_type == TDS_PROTOCOL_7_1)
#define TDS_PROTO_PREF_TDS7_2 (tds_protocol_type == TDS_PROTOCOL_7_2)
#define TDS_PROTO_PREF_TDS7_3 (tds_protocol_type == TDS_PROTOCOL_7_3)
#define TDS_PROTO_PREF_TDS7 (tds_protocol_type >= TDS_PROTOCOL_7_0 && tds_protocol_type <= TDS_PROTOCOL_7_3)

/* TDS "endian type" */
/*   XXX: Assumption is that all TDS conversations being decoded in a particular capture */
/*        have the same endian type                                                      */
/*   TODO: consider storing endian type with each conversation                           */
/*         (using pref as the default)                                                   */

static gboolean tds_little_endian = TRUE;

static const enum_val_t tds_endian_type_options[] = {
    {"little_endian", "Little Endian", TRUE},
    {"big_endian"   , "Big Endian"   , FALSE},
    {NULL, NULL, -1}
};


/* TCP port preferences for TDS decode */

static range_t *tds_tcp_ports = NULL;

/* These correspond to the netlib packet type field */
static const value_string packet_type_names[] = {
    {TDS_QUERY_PKT,     "SQL batch"},
    {TDS_LOGIN_PKT,     "Pre-TDS7 login"},
    {TDS_RPC_PKT,       "Remote Procedure Call"},
    {TDS_RESP_PKT,      "Response"},
    {TDS_RAW_PKT,       "Unused"},
    {TDS_ATTENTION_PKT, "Attention"},
    {TDS_BULK_DATA_PKT, "Bulk load data"},
    {TDS_QUERY5_PKT,    "TDS5 query"},
    {TDS_LOGIN7_PKT,    "TDS7 login"},
    {TDS_SSPI_PKT,      "SSPI message"},
    {TDS_PRELOGIN_PKT,  "TDS7 pre-login message"},
    {0, NULL}
};

enum {
    TDS_HEADER_QUERY_NOTIF = 0x0001,
    TDS_HEADER_TRANS_DESCR = 0x0002
};

static const value_string header_type_names[] = {
    {TDS_HEADER_QUERY_NOTIF, "Query notifications"},
    {TDS_HEADER_TRANS_DESCR, "Transaction descriptor"},
    {0, NULL}
};

/* The status field */

#define is_valid_tds_status(x) ((x) <= STATUS_EVENT_NOTIFICATION)

#define STATUS_LAST_BUFFER              0x01
#define STATUS_IGNORE_EVENT             0x02
#define STATUS_EVENT_NOTIFICATION       0x04
#define STATUS_RESETCONNECTION          0x08
#define STATUS_RESETCONNECTIONSKIPTRAN  0x10

/* The one byte token at the start of each TDS PDU */
static const value_string token_names[] = {
    {TDS5_DYNAMIC_TOKEN,        "TDS5 Dynamic SQL"},
    {TDS5_PARAMFMT_TOKEN,       "TDS5 Parameter Format"},
    {TDS5_PARAMFMT2_TOKEN,      "TDS5 Parameter2 Format"},
    {TDS5_PARAMS_TOKEN,         "TDS5 Parameters"},
    {TDS_LANG_TOKEN,            "Language"},
    {TDS_LOGOUT_TOKEN,          "Logout"},
    {TDS_RET_STAT_TOKEN,        "Return Status"},
    {TDS_PROCID_TOKEN,          "Proc ID"},
    {TDS7_RESULT_TOKEN,         "TDS7+ Results"},
    {TDS_COL_NAME_TOKEN,        "Column Names"},
    {TDS_COL_INFO_TOKEN,        "Column Info"},
    {TDS_COMPUTE_NAMES_TOKEN,   "Compute Names"},
    {TDS_COMPUTE_RESULT_TOKEN,  "Compute Results"},
    {TDS_ORDER_BY_TOKEN,        "Order By"},
    {TDS_ERR_TOKEN,             "Error Message"},
    {TDS_MSG_TOKEN,             "Info Message"},
    {TDS_PARAM_TOKEN,           "Parameter"},
    {TDS_LOGIN_ACK_TOKEN,       "Login Acknowledgement"},
    {TDS_CONTROL_TOKEN,         "TDS Control"},
    {TDS_KEY_TOKEN,             "TDS Key"},
    {TDS_ROW_TOKEN,             "Row"},
    {TDS_CMP_ROW_TOKEN,         "Compute Row"},
    {TDS_CAP_TOKEN,             "Capabilities"},
    {TDS_ENV_CHG_TOKEN,         "Environment Change"},
    {TDS_EED_TOKEN,             "Extended Error"},
    {TDS_AUTH_TOKEN,            "Authentication"},
    {TDS_RESULT_TOKEN,          "Results"},
    {TDS_DONE_TOKEN,            "Done"},
    {TDS_DONEPROC_TOKEN,        "Done Proc"},
    {TDS_DONEINPROC_TOKEN,      "Done In Proc"},
    {TDS5_DYNAMIC2_TOKEN,       "TDS5 Dynamic2"},
    {TDS5_ORDERBY2_TOKEN,       "TDS5 OrderBy2"},
    {TDS5_CURDECLARE2_TOKEN,    "TDS5 CurDeclare2"},
    {TDS5_ROWFMT2_TOKEN,        "TDS5 RowFmt2"},
    {TDS5_MSG_TOKEN,            "TDS5 Msg"},
    {0, NULL}
};

#define TDS_RPC_SEPARATOR_BATCH_FLAG            0x80
#define TDS_RPC_SEPARATOR_BATCH_FLAG_7_2        0xFF
#define TDS_RPC_SEPARATOR_NO_EXEC_FLAG          0xFE

static const value_string tds_rpc_separators[] = {
    {TDS_RPC_SEPARATOR_BATCH_FLAG,     "Batch flag"},
    {TDS_RPC_SEPARATOR_BATCH_FLAG_7_2, "Batch flag 7.2"},
    {TDS_RPC_SEPARATOR_NO_EXEC_FLAG,   "No exec flag"},
    {0, NULL }
};

static const value_string internal_stored_proc_id_names[] = {
    {TDS_SP_CURSOR,          "sp_cursor"         },
    {TDS_SP_CURSOROPEN,      "sp_cursoropen"     },
    {TDS_SP_CURSORPREPARE,   "sp_cursorprepare"  },
    {TDS_SP_CURSOREXECUTE,   "sp_cursorexecute"  },
    {TDS_SP_CURSORPREPEXEC,  "sp_cursorprepexec" },
    {TDS_SP_CURSORUNPREPARE, "sp_cursorunprepare"},
    {TDS_SP_CURSORFETCH,     "sp_cursorfetch"    },
    {TDS_SP_CURSOROPTION,    "sp_cursoroption"   },
    {TDS_SP_CURSORCLOSE,     "sp_cursorclose"    },
    {TDS_SP_EXECUTESQL,      "sp_executesql"     },
    {TDS_SP_PREPARE,         "sp_prepare"        },
    {TDS_SP_EXECUTE,         "sp_execute"        },
    {TDS_SP_PREPEXEC,        "sp_prepexec"       },
    {TDS_SP_PREPEXECRPC,     "sp_prepexecrpc"    },
    {TDS_SP_UNPREPARE,       "sp_unprepare"      },
    {0,                      NULL                },
};

static const value_string env_chg_names[] = {
    {1, "Database"},
    {2, "Language"},
    {3, "Sort Order"},
    {4, "Blocksize"},
    {5, "Unicode Locale ID"},
    {6, "Unicode Comparison Style"},
    {7, "Collation Info"},
    {0, NULL},
};

static const value_string login_field_names[] = {
    {0, "Client Name"},
    {1, "Username"},
    {2, "Password"},
    {3, "App Name"},
    {4, "Server Name"},
    {5, "Unknown1"},
    {6, "Library Name"},
    {7, "Locale"},
    {8, "Database Name"},
    {0, NULL},
};


#define MAX_COLUMNS 256

/*
 * This is where we store the column information to be used in decoding the
 * TDS_ROW_TOKEN tokens.
 */
struct _tds_col {
    gchar name[256];
    guint16 utype;
    guint8 ctype;
    guint csize;
};

struct _netlib_data {
    guint num_cols;
    struct _tds_col *columns[MAX_COLUMNS];
};

struct tds7_login_packet_hdr {
    guint32 total_packet_size;
    guint32 tds_version;
    guint32 packet_size;
    guint32 client_version;
    guint32 client_pid;
    guint32 connection_id;
    guint8  option_flags1;
    guint8  option_flags2;
    guint8  sql_type_flags;
    guint8  reserved_flags;
    guint32 time_zone;
    guint32 collation;
};

/* support routines */

static void
dissect_tds_nt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               guint offset, guint length)
{
    tvbuff_t *nt_tvb;

    nt_tvb = tvb_new_subset(tvb, offset, -1, length);
    if(tvb_strneql(tvb, offset, "NTLMSSP", 7) == 0)
        call_dissector(ntlmssp_handle, nt_tvb, pinfo, tree);
    else
        call_dissector(gssapi_handle, nt_tvb, pinfo, tree);
}

/*  */

static guint16
tds_tvb_get_xxtohs(tvbuff_t *tvb, gint offset, gboolean tds_little_endian_flag) {
    if (tds_little_endian_flag)
        return tvb_get_letohs(tvb, offset);
    else
        return tvb_get_ntohs(tvb, offset);
}

static guint32
tds_tvb_get_xxtohl(tvbuff_t *tvb, gint offset, gboolean tds_little_endian_flag) {
    if (tds_little_endian_flag)
        return tvb_get_letohl(tvb, offset);
    else
        return tvb_get_ntohl(tvb, offset);
}


static int
tds_token_is_fixed_size(guint8 token)
{
    switch (token) {
        case TDS_DONE_TOKEN:
        case TDS_DONEPROC_TOKEN:
        case TDS_DONEINPROC_TOKEN:
        case TDS_RET_STAT_TOKEN:
        case TDS7_RESULT_TOKEN:
        case TDS_PROCID_TOKEN:
        case TDS_LOGOUT_TOKEN:
            return 1;
        default:
            return 0;
    }
}


static int
tds_get_fixed_token_size(guint8 token)
{
    switch(token) {
        case TDS_DONE_TOKEN:
        case TDS_DONEPROC_TOKEN:
        case TDS_DONEINPROC_TOKEN:
        case TDS_PROCID_TOKEN:
            return 8;
        case TDS_RET_STAT_TOKEN:
            return 4;
        case TDS_LOGOUT_TOKEN:
            return 1;
        case TDS7_RESULT_TOKEN:
        default:
            return 0;
    }
}

static guint
tds_get_variable_token_size(tvbuff_t *tvb, gint offset, guint8 token,
                            guint *len_field_size_p, guint *len_field_val_p)
{
    switch(token) {
        /* some tokens have a 4 byte length field */
        case TDS5_PARAMFMT2_TOKEN:
        case TDS_LANG_TOKEN:
        case TDS5_ORDERBY2_TOKEN:
        case TDS5_CURDECLARE2_TOKEN:
        case TDS5_ROWFMT2_TOKEN:
        case TDS5_DYNAMIC2_TOKEN:
            *len_field_size_p = 4;
            *len_field_val_p = tds_tvb_get_xxtohl(tvb, offset, tds_little_endian);
            break;
            /* some have a 1 byte length field */
        case TDS5_MSG_TOKEN:
            *len_field_size_p = 1;
            *len_field_val_p = tvb_get_guint8(tvb, offset);
            break;
            /* and most have a 2 byte length field */
        default:
            *len_field_size_p = 2;
            *len_field_val_p = tds_tvb_get_xxtohs(tvb, offset, tds_little_endian);
            break;
    }
    return *len_field_val_p + *len_field_size_p + 1;
}


static void
dissect_tds_all_headers(tvbuff_t *tvb, guint *offset, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item = NULL, *total_length_item = NULL;
    proto_tree *sub_tree = NULL;
    guint32 total_length;
    guint final_offset;

    total_length = tvb_get_letohl(tvb, *offset);
    /* Try to find out heuristically whether the ALL_HEADERS rule is actually present.
     * In practice total_length is a single byte value, so if the extracted value exceeds 1 byte,
     * then the headers are most likely absent. */
    if(total_length >= 0x100)
        return;
    item = proto_tree_add_item(tree, hf_tds_all_headers, tvb, *offset, total_length, TRUE);
    sub_tree = proto_item_add_subtree(item, ett_tds_all_headers);
    total_length_item = proto_tree_add_item(sub_tree, hf_tds_all_headers_total_length, tvb, *offset, 4, TRUE);

    final_offset = *offset + total_length;
    *offset += 4;
    do {
        /* dissect a stream header */
        proto_tree *header_sub_tree = NULL;
        proto_item *length_item = NULL, *type_item = NULL;
        guint32 header_length;
        guint16 header_type;

        header_length = tvb_get_letohl(tvb, *offset);
        item = proto_tree_add_text(sub_tree, tvb, *offset, header_length, "Header");
        header_sub_tree = proto_item_add_subtree(item, ett_tds_all_headers_header);
        length_item = proto_tree_add_item(header_sub_tree, hf_tds_all_headers_header_length, tvb, *offset, 4, TRUE);
        if(header_length == 0 ) {
            expert_add_info_format(pinfo, length_item, PI_MALFORMED, PI_ERROR, "Empty header");
            break;
        }

        header_type = tvb_get_letohs(tvb, *offset + 4);
        type_item = proto_tree_add_item(header_sub_tree, hf_tds_all_headers_header_type, tvb, *offset + 4, 2, TRUE);

        switch(header_type) {
            case TDS_HEADER_QUERY_NOTIF:
                break;
            case TDS_HEADER_TRANS_DESCR:
                if(header_length != 18)
                    expert_add_info_format(pinfo, length_item, PI_MALFORMED, PI_ERROR, "Length should equal 18");
                proto_tree_add_item(header_sub_tree, hf_tds_all_headers_trans_descr, tvb, *offset + 6, 8, TRUE);
                proto_tree_add_item(header_sub_tree, hf_tds_all_headers_request_cnt, tvb, *offset + 14, 4, TRUE);
                break;
            default:
                expert_add_info_format(pinfo, type_item, PI_MALFORMED, PI_ERROR, "Invalid header type");
        }

        *offset += header_length;
    } while(*offset < final_offset);
    if(*offset != final_offset) {
        expert_add_info_format(pinfo, total_length_item, PI_MALFORMED, PI_ERROR,
                               "Sum of headers' lengths (%d) differs from total headers length (%d)",
                               total_length + *offset - final_offset, total_length);
        return;
    }
}


static void
dissect_tds_query_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset, len;
    gboolean is_unicode = TRUE;
    char *msg;

    proto_item *query_hdr;
    proto_tree *query_tree;

    offset = 0;
    query_hdr = proto_tree_add_text(tree, tvb, offset, -1, "TDS Query Packet");
    query_tree = proto_item_add_subtree(query_hdr, ett_tds7_query);
    dissect_tds_all_headers(tvb, &offset, pinfo, query_tree);
    len = tvb_reported_length_remaining(tvb, offset);

    if (TDS_PROTO_PREF_TDS4 ||
        (!TDS_PROTO_PREF_TDS7 &&
         ((len < 2) || tvb_get_guint8(tvb, offset+1) != 0)))
        is_unicode = FALSE;

    if (is_unicode)
        msg = tvb_get_ephemeral_faked_unicode(tvb, offset, len/2, TRUE);
    else
        msg = (gchar*)tvb_get_ephemeral_string(tvb, offset, len);

    proto_tree_add_text(query_tree, tvb, offset, len, "Query: %s", msg);
    offset += len;
}


static void
dissect_tds5_lang_token(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree) {
    gboolean is_unicode = FALSE;
    char *msg;

    proto_tree_add_text(tree, tvb, offset, 1 , "Status: %u", tvb_get_guint8(tvb, offset));
    offset += 1;
    len    -= 1;

    if (is_unicode)
        msg = tvb_get_ephemeral_faked_unicode(tvb, offset, (len)/2, TRUE);
    else
        msg = (gchar*)tvb_get_ephemeral_string(tvb, offset, len);

    proto_tree_add_text(tree, tvb, offset, len, "Language text: %s", msg);
}

static void
dissect_tds_query5_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    guint offset;
    guint pos;
    guint token_len_field_size = 2;
    guint token_len_field_val = 0;
    guint8 token;
    guint token_sz;
    proto_item *query_hdr;
    proto_tree *query_tree;
    proto_item *token_item;
    proto_tree *token_tree;

    offset = 0;
    query_hdr = proto_tree_add_text(tree, tvb, offset, -1, "TDS5 Query Packet");
    query_tree = proto_item_add_subtree(query_hdr, ett_tds7_query);

    /*
     * Until we reach the end of the packet, read tokens.
     */
    pos = offset;
    while (tvb_reported_length_remaining(tvb, pos) > 0) {

        /* our token */
        token = tvb_get_guint8(tvb, pos);
        if (tds_token_is_fixed_size(token))
            token_sz = tds_get_fixed_token_size(token) + 1;
        else
            token_sz = tds_get_variable_token_size(tvb, pos+1, token, &token_len_field_size,
                                                   &token_len_field_val);

        /* XXX - Should this check be done in tds_get_variable_token_size()
         * instead? */
        if ((int) token_sz < 0) {
            proto_tree_add_text(query_tree, tvb, 0, 0, "Bogus token size: %u",
                                token_sz);
            break;
        }

        token_item = proto_tree_add_text(query_tree, tvb, pos, token_sz,
                                         "Token 0x%02x %s", token,
                                         val_to_str(token, token_names, "Unknown Token Type"));
        token_tree = proto_item_add_subtree(token_item, ett_tds_token);

        /*
         * If it's a variable token, put the length field in here
         * instead of replicating this for each token subdissector.
         */
        if (!tds_token_is_fixed_size(token))
            proto_tree_add_text(token_tree, tvb, pos+1, token_len_field_size, "Length: %u", token_len_field_val);

        switch (token) {
            case TDS_LANG_TOKEN:
                dissect_tds5_lang_token(tvb, pos + 5, token_sz -5, token_tree);
                break;
            default:
                break;
        }

        pos += token_sz;

    }  /* while */
}


static void
dissect_tds7_login(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset, i, j, k, offset2, len;
    char *val, *val2;

    proto_item *login_hdr;
    proto_tree *login_tree;
    proto_item *header_hdr;
    proto_tree *header_tree;
    proto_item *length_hdr;
    proto_tree *length_tree;

    struct tds7_login_packet_hdr td7hdr;
    gint length_remaining;


    /* create display subtree for the protocol */
    offset = 0;
    login_hdr = proto_tree_add_text(tree, tvb, offset, -1, "TDS7 Login Packet");
    login_tree = proto_item_add_subtree(login_hdr, ett_tds7_login);
    header_hdr = proto_tree_add_text(login_tree, tvb, offset, 36, "Login Packet Header");
    header_tree = proto_item_add_subtree(header_hdr, ett_tds7_hdr);

    td7hdr.total_packet_size = tvb_get_letohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_login_total_size, tvb, offset,
                        sizeof(td7hdr.total_packet_size), td7hdr.total_packet_size);
    offset += sizeof(td7hdr.total_packet_size);

    td7hdr.tds_version = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_version, tvb, offset, sizeof(td7hdr.tds_version), td7hdr.tds_version);
    offset += sizeof(td7hdr.tds_version);

    td7hdr.packet_size = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_packet_size, tvb, offset, sizeof(td7hdr.packet_size), td7hdr.packet_size);
    offset += sizeof(td7hdr.packet_size);

    td7hdr.client_version = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_client_version, tvb, offset, sizeof(td7hdr.client_version), td7hdr.client_version);
    offset += sizeof(td7hdr.client_version);

    td7hdr.client_pid = tvb_get_letohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_client_pid, tvb, offset, sizeof(td7hdr.client_pid), td7hdr.client_pid);
    offset += sizeof(td7hdr.client_pid);

    td7hdr.connection_id= tvb_get_letohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_connection_id, tvb, offset, sizeof(td7hdr.connection_id), td7hdr.connection_id);
    offset += sizeof(td7hdr.connection_id);

    td7hdr.option_flags1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_option_flags1, tvb, offset, sizeof(td7hdr.option_flags1), td7hdr.option_flags1);
    offset += sizeof(td7hdr.option_flags1);

    td7hdr.option_flags2 = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_option_flags2, tvb, offset, sizeof(td7hdr.option_flags2), td7hdr.option_flags2);
    offset += sizeof(td7hdr.option_flags2);

    td7hdr.sql_type_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_sql_type_flags, tvb, offset, sizeof(td7hdr.sql_type_flags), td7hdr.sql_type_flags);
    offset += sizeof(td7hdr.sql_type_flags);

    td7hdr.reserved_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_reserved_flags, tvb, offset, sizeof(td7hdr.reserved_flags), td7hdr.reserved_flags);
    offset += sizeof(td7hdr.reserved_flags);

    td7hdr.time_zone = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_time_zone, tvb, offset, sizeof(td7hdr.time_zone), td7hdr.time_zone);
    offset += sizeof(td7hdr.time_zone);

    td7hdr.collation = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7_collation, tvb, offset, sizeof(td7hdr.collation), td7hdr.collation);
    offset += sizeof(td7hdr.collation);

    length_hdr = proto_tree_add_text(login_tree, tvb, offset, 50, "Lengths and offsets");
    length_tree = proto_item_add_subtree(length_hdr, ett_tds7_hdr);

    for (i = 0; i < 9; i++) {
        offset2 = tvb_get_letohs(tvb, offset + i*4);
        len = tvb_get_letohs(tvb, offset + i*4 + 2);
        proto_tree_add_text(length_tree, tvb, offset + i*4, 2,
                            "%s offset: %u",
                            val_to_str(i, login_field_names, "Unknown"),
                            offset2);
        proto_tree_add_text(length_tree, tvb, offset + i*4 + 2, 2,
                            "%s length: %u",
                            val_to_str(i, login_field_names, "Unknown"),
                            len);
        if (len != 0) {
            if( i != 2) {
                /* tds 7 is always unicode */
                val = tvb_get_ephemeral_faked_unicode(tvb, offset2, len, TRUE);
                len *= 2;
                proto_tree_add_text(login_tree, tvb, offset2, len, "%s: %s", val_to_str(i, login_field_names, "Unknown"), val);
            } else {
                /* This field is the password.  We retrieve it from the packet
                 * as a non-unicode string and then perform two operations on it
                 * to "decrypt" it.  Finally, we create a new string that consists
                 * of ASCII characters instead of unicode by skipping every other
                 * byte in the original string.
                 */

                len *= 2;
                val = (gchar*)tvb_get_ephemeral_string(tvb, offset2, len);
                val2 = g_malloc((len/2)+1);

                for(j = 0, k = 0; j < len; j += 2, k++) {
                    val[j] ^= 0xA5;

                    /* Swap the most and least significant bits */
                    val[j] = ((val[j] & 0x0F) << 4) | ((val[j] & 0xF0) >> 4);

                    val2[k] = val[j];
                }
                val2[k] = '\0'; /* Null terminate our new string */

                proto_tree_add_text(login_tree, tvb, offset2, len, "%s: %s", val_to_str(i, login_field_names, "Unknown"), val2);
                g_free(val2);
            }
        }
    }

    /*
     * XXX - what about the client MAC address, etc.?
     */
    length_remaining = tvb_reported_length_remaining(tvb, offset2 + len);
    if (length_remaining > 0) {
        dissect_tds_nt(tvb, pinfo, login_tree, offset2 + len,
                       length_remaining);
    }
}

static int
get_size_by_coltype(int servertype)
{
    switch(servertype)
    {
        case SYBINT1:        return 1;
        case SYBINT2:        return 2;
        case SYBINT4:        return 4;
        case SYBINT8:        return 8;
        case SYBREAL:        return 4;
        case SYBFLT8:        return 8;
        case SYBDATETIME:    return 8;
        case SYBDATETIME4:   return 4;
        case SYBBIT:         return 1;
        case SYBBITN:        return 1;
        case SYBMONEY:       return 8;
        case SYBMONEY4:      return 4;
        case SYBUNIQUE:      return 16;
        default:             return -1;
    }
}
# if 0
/*
 * data_to_string should take column data and turn it into something we can
 * display on the tree.
 */
static char *data_to_string(void *data, guint col_type, guint col_size)
{
    char *result;
    guint i;

    result=ep_alloc(256);
    switch(col_type) {
        case SYBVARCHAR:
            /* strncpy(result, (char *)data, col_size); */
            for (i=0;i<col_size && i<(256-1);i++)
                if (!isprint(((char *)data)[i])) result[i]='.';
                else result[i]=((char *)data)[i];
            result[i] = '\0';
            break;
        case SYBINT2:
            g_snprintf(result, 256, "%d", *(short *)data);
            break;
        case SYBINT4:
            g_snprintf(result, 256, "%d", *(int *)data);
            break;
        default:
            g_snprintf(result, 256, "Unexpected column_type %d", col_type);
            break;
    }
    return result;
}
#endif

/*
 * Since rows are special PDUs in that they are not fixed and lack a size field,
 * the length must be computed using the column information seen in the result
 * PDU. This function does just that.
 */
static guint
tds_get_row_size(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset)
{
    guint cur, i, csize;

    cur = offset;
    for (i = 0; i < nl_data->num_cols; i++) {
        if (!is_fixed_coltype(nl_data->columns[i]->ctype)) {
            csize = tvb_get_guint8(tvb, cur);
            cur++;
        } else
            csize = get_size_by_coltype(nl_data->columns[i]->ctype);
        cur += csize;
    }

    return (cur - offset + 1);
}

/*
 * Process TDS 4 "COL_INFO" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 * XXX Can TDS 4 be "big-endian" ? we'll assume yes.
 *
 */
static gboolean
dissect_tds_col_info_token(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset)
{
    guint next, cur;
    guint col;

    next = offset + tds_tvb_get_xxtohs(tvb, offset+1, tds_little_endian) + 3;
    cur = offset + 3;

    col = 0;
    while (cur < next) {

        if (col >= MAX_COLUMNS) {
            nl_data->num_cols = 0;
            return FALSE;
        }

        nl_data->columns[col] = ep_alloc(sizeof(struct _tds_col));

        nl_data->columns[col]->name[0] ='\0';

        nl_data->columns[col]->utype = tds_tvb_get_xxtohs(tvb, cur, tds_little_endian);
        cur += 2;

        cur += 2; /* unknown */

        nl_data->columns[col]->ctype = tvb_get_guint8(tvb,cur);
        cur++;

        if (!is_fixed_coltype(nl_data->columns[col]->ctype)) {
            nl_data->columns[col]->csize = tvb_get_guint8(tvb,cur);
            cur ++;
        } else {
            nl_data->columns[col]->csize =
                get_size_by_coltype(nl_data->columns[col]->ctype);
        }

        col += 1;

    } /* while */

    nl_data->num_cols = col;
    return TRUE;
}


/*
 * Read the results token and store the relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size).
 *
 * TODO: check we don't go past end of the token
 */
static gboolean
read_results_tds5(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset, guint len _U_)
{
    guint name_len;
    guint cur;
    guint i;

    cur = offset;

    /*
     * This would be the logical place to check for little/big endianess
     * if we didn't see the login packet.
     * XXX: We'll take a hint
     */
    nl_data->num_cols = tds_tvb_get_xxtohs(tvb, cur, tds_little_endian);
    if (nl_data->num_cols > MAX_COLUMNS) {
        nl_data->num_cols = 0;
        return FALSE;
    }

    cur += 2;

    for (i = 0; i < nl_data->num_cols; i++) {
        nl_data->columns[i] = ep_alloc(sizeof(struct _tds_col));
        name_len = tvb_get_guint8(tvb,cur);
        cur ++;
        cur += name_len;

        cur++; /* unknown */

        nl_data->columns[i]->utype = tds_tvb_get_xxtohs(tvb, cur, tds_little_endian);
        cur += 2;

        cur += 2; /* unknown */

        nl_data->columns[i]->ctype = tvb_get_guint8(tvb,cur);
        cur++;

        if (!is_fixed_coltype(nl_data->columns[i]->ctype)) {
            nl_data->columns[i]->csize = tvb_get_guint8(tvb,cur);
            cur ++;
        } else {
            nl_data->columns[i]->csize =
                get_size_by_coltype(nl_data->columns[i]->ctype);
        }
        cur++; /* unknown */
    }
    return TRUE;
}

/*
 * If the packet type from the netlib header is a login packet, then dig into
 * the packet to see if this is a supported TDS version and verify the otherwise
 * weak heuristics of the netlib check.
 */
static gboolean
netlib_check_login_pkt(tvbuff_t *tvb, guint offset, packet_info *pinfo, guint8 type)
{
    guint tds_major, bytes_avail;

    bytes_avail = tvb_length(tvb) - offset;
    /*
     * we have two login packet styles, one for TDS 4.2 and 5.0
     */
    if (type==TDS_LOGIN_PKT) {
        /* Use major version number to validate TDS 4/5 login
         * packet */

        /* Login packet is first in stream and should not be fragmented...
         * if it is we are screwed */
        if (bytes_avail < 467) return FALSE;
        tds_major = tvb_get_guint8(tvb, 466);
        if (tds_major != 4 && tds_major != 5) {
            return FALSE;
        }
        /*
         * and one added by Microsoft in SQL Server 7
         */
    } else if (type==TDS_LOGIN7_PKT) {
        if (bytes_avail < 16) return FALSE;
        tds_major = tvb_get_guint8(tvb, 15);
        if (tds_major != 0x70 && tds_major != 0x80) {
            return FALSE;
        }
    } else if (type==TDS_QUERY5_PKT) {
        if (bytes_avail < 9) return FALSE;
        /* if this is a TDS 5.0 query check the token */
        if (tvb_get_guint8(tvb, 8) != TDS_LANG_TOKEN) {
            return FALSE;
        }
    }
    /*
     * See if either tcp.destport or tcp.srcport is specified
     * in the preferences as being a TDS port.
     */
    else if (!value_is_in_range(tds_tcp_ports, pinfo->srcport) &&
             !value_is_in_range(tds_tcp_ports, pinfo->destport)) {
        return FALSE;
    }

    return TRUE;
}

static void
dissect_tds_env_chg(tvbuff_t *tvb, guint offset, guint token_sz,
                    proto_tree *tree)
{
    guint8 env_type;
    guint old_len, new_len, old_len_offset;
    char *new_val = NULL, *old_val = NULL;
    guint32 string_offset;
    gboolean is_unicode = FALSE;
    guint16 collate_codepage, collate_flags;
    guint8 collate_charset_id;

    env_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "Type: %u (%s)", env_type,
                        val_to_str(env_type, env_chg_names, "Unknown"));

    new_len = tvb_get_guint8(tvb, offset+1);
    old_len_offset = offset + new_len + 2;
    old_len = tvb_get_guint8(tvb, old_len_offset);

    /*
     * If our lengths plus the lengths of the type and the lengths
     * don't add up to the token size, it must be UCS2.
     */
    if (old_len + new_len + 3 != token_sz) {
        is_unicode = TRUE;
        old_len_offset = offset + (new_len * 2) + 2;
        old_len = tvb_get_guint8(tvb, old_len_offset);
    }

    proto_tree_add_text(tree, tvb, offset + 1, 1, "New Value Length: %u",
                        new_len);
    if (new_len) {
        if (env_type != 7) { /* if it's not 'Collation Info - which is not textual! */
            string_offset = offset + 2;
            if (is_unicode == TRUE) {
                new_val = tvb_get_ephemeral_faked_unicode(tvb, string_offset,
                                                          new_len, TRUE);
                new_len *= 2;
            } else
                new_val = (gchar*)tvb_get_ephemeral_string(tvb, string_offset, new_len);
            proto_tree_add_text(tree, tvb, string_offset, new_len,
                                "New Value: %s", new_val);
        }
        else { /* parse collation info structure. From http://www.freetds.org/tds.html#collate */
            offset +=2;
            collate_codepage = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Codepage: %u" , collate_codepage);
            offset += 2;
            collate_flags = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Flags: 0x%x", collate_flags);
            offset += 2;
            collate_charset_id = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1, "Charset ID: %u", collate_charset_id);
            offset +=1;
        }
    }

    proto_tree_add_text(tree, tvb, old_len_offset, 1, "Old Value Length: %u",
                        old_len);
    if (old_len) {
        string_offset = old_len_offset + 1;
        if (is_unicode == TRUE) {
            old_val = tvb_get_ephemeral_faked_unicode(tvb, string_offset,
                                                      old_len, TRUE);
            old_len *= 2;
        } else
            old_val = (gchar*)tvb_get_ephemeral_string(tvb, string_offset, old_len);
        proto_tree_add_text(tree, tvb, string_offset, old_len,
                            "Old Value: %s", old_val);
    }
}

static void
dissect_tds_err_token(tvbuff_t *tvb, guint offset, guint token_sz _U_, proto_tree *tree)
{
    guint16 msg_len;
    guint8 srvr_len, proc_len;
    char *msg;
    gboolean is_unicode = FALSE;

    proto_tree_add_text(tree, tvb, offset, 4, "SQL Error Number: %d", tds_tvb_get_xxtohl(tvb, offset, tds_little_endian));
    offset += 4;
    proto_tree_add_text(tree, tvb, offset, 1, "State: %u", tvb_get_guint8(tvb, offset));
    offset +=1;
    proto_tree_add_text(tree, tvb, offset, 1, "Severity Level: %u", tvb_get_guint8(tvb, offset));
    offset +=1;

    msg_len = tds_tvb_get_xxtohs(tvb, offset, tds_little_endian);
    proto_tree_add_text(tree, tvb, offset, 1, "Error message length: %u characters", msg_len);
    offset +=2;

    if(tvb_get_guint8(tvb, offset+1) == 0) /* FIXME: It's probably unicode, if the 2nd byte of the message is zero. It's not a good detection method, but it works */
        is_unicode = TRUE;

    if(is_unicode) {
        msg = tvb_get_ephemeral_faked_unicode(tvb, offset, msg_len, TRUE);
        msg_len *= 2;
    } else {
        msg = (gchar*)tvb_get_ephemeral_string(tvb, offset, msg_len);
    }
    proto_tree_add_text(tree, tvb, offset, msg_len, "Error: %s", format_text((guchar*)msg, strlen(msg)));
    offset += msg_len;

    srvr_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree, tvb, offset, 1, "Server name length: %u characters", srvr_len);
    offset +=1;
    if(srvr_len) {
        if (is_unicode) {
            msg = tvb_get_ephemeral_faked_unicode(tvb, offset, srvr_len, TRUE);
            srvr_len *=2;
        } else {
            msg = (gchar*)tvb_get_ephemeral_string(tvb, offset, srvr_len);
        }
        proto_tree_add_text(tree, tvb, offset, srvr_len, "Server name: %s", msg);
        offset += srvr_len;
    }

    proc_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree, tvb, offset, 1, "Process name length: %u characters", proc_len);
    offset +=1;
    if(proc_len) {
        if (is_unicode) {
            msg = tvb_get_ephemeral_faked_unicode(tvb, offset, proc_len, TRUE);
            proc_len *=2;
        } else {
            msg = (gchar*)tvb_get_ephemeral_string(tvb, offset, proc_len);
        }
        proto_tree_add_text(tree, tvb, offset, proc_len, "Process name: %s", msg);
        offset += proc_len;
    }

    proto_tree_add_text(tree, tvb, offset, 2, "line number: %d", tds_tvb_get_xxtohs(tvb, offset, tds_little_endian));
}

static void
dissect_tds_login_ack_token(tvbuff_t *tvb, guint offset, guint token_sz, proto_tree *tree)
{
    guint8 msg_len;
    char *msg;
    gboolean is_unicode = FALSE;

    proto_tree_add_text(tree, tvb, offset, 1, "Ack: %u", tvb_get_guint8(tvb, offset));
    offset +=1;
    proto_tree_add_text(tree, tvb, offset, 1, "Major version (may be incorrect): %d", tvb_get_guint8(tvb, offset));
    offset +=1;
    proto_tree_add_text(tree, tvb, offset, 1, "Minor version (may be incorrect): %d", tvb_get_guint8(tvb, offset));
    offset +=1;
    proto_tree_add_text(tree, tvb, offset, 2, "zero usually");
    offset +=2;

    msg_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "Text length: %u characters", msg_len);
    offset +=1;

    if(msg_len + 6U + 3U != token_sz - 1) /* 6 is the length of ack(1), version (4), text length (1) fields */
        is_unicode = TRUE;
    proto_tree_add_text(tree, tvb, offset, 0, "msg_len: %d, token_sz: %d, total: %d",msg_len, token_sz, msg_len + 6U + 3U);
    if(is_unicode) {
        msg = tvb_get_ephemeral_faked_unicode(tvb, offset, msg_len, TRUE);
        msg_len *= 2;
    } else {
        msg = (gchar*)tvb_get_ephemeral_string(tvb, offset, msg_len);
    }
    proto_tree_add_text(tree, tvb, offset, msg_len, "Text: %s", format_text((guchar*)msg, strlen(msg)));
    offset += msg_len;

    proto_tree_add_text(tree, tvb, offset, 4, "Server Version");
    offset += 4;
}

static int
dissect_tds7_results_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint16 num_columns, table_len;
    guint8 type, msg_len;
    int i;
    char *msg;
    guint16 collate_codepage, collate_flags;
    guint8 collate_charset_id;

    num_columns = tvb_get_letohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Columns: %u", tvb_get_letohs(tvb, offset));
    offset +=2;
    for(i=0; i != num_columns; i++) {
        proto_tree_add_text(tree, tvb, offset, 0, "Column %d", i + 1);
        proto_tree_add_text(tree, tvb, offset, 2, "usertype: %d", tvb_get_letohs(tvb, offset));
        offset +=2;
        proto_tree_add_text(tree, tvb, offset, 2, "flags: %d", tvb_get_letohs(tvb, offset));
        offset +=2;
        type  = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "Type: %d", type);
        offset +=1;
        if(type == 38 || type == 104 || type == 109 || type == 111) { /* ugly, ugly hack. Wish I knew what it really means!*/
            proto_tree_add_text(tree, tvb, offset, 1, "unknown 1 byte (%x)", tvb_get_guint8(tvb, offset));
            offset +=1;
        }
        else if (type == 35) {
            proto_tree_add_text(tree, tvb, offset, 4, "unknown 4 bytes (%x)", tvb_get_letohl(tvb, offset));
            offset += 4;
            collate_codepage = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Codepage: %u" , collate_codepage);
            offset += 2;
            collate_flags = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Flags: 0x%x", collate_flags);
            offset += 2;
            collate_charset_id = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1, "Charset ID: %u", collate_charset_id);
            offset +=1;
            table_len = tvb_get_letohs(tvb, offset);
            offset +=2;
            if(table_len != 0) {
                msg = tvb_get_ephemeral_faked_unicode(tvb, offset, table_len, TRUE);
                proto_tree_add_text(tree, tvb, offset, table_len*2, "Table name: %s", msg);
                offset += table_len*2;
            }
        }
        else if (type == 106 || type == 108) {
            proto_tree_add_text(tree, tvb, offset, 3, "unknown 3 bytes");
            offset +=3;
        }
        else if(type > 128) {
            proto_tree_add_text(tree, tvb, offset, 2, "Large type size: 0x%x", tvb_get_letohs(tvb, offset));
            offset += 2;
            if (type != 165) {
                collate_codepage = tvb_get_letohs(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 2, "Codepage: %u" , collate_codepage);
                offset += 2;
                collate_flags = tvb_get_letohs(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 2, "Flags: 0x%x", collate_flags);
                offset += 2;
                collate_charset_id = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 1, "Charset ID: %u", collate_charset_id);
                offset +=1;
            }
        }
        msg_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "message length: %d",msg_len);
        offset += 1;
        if(msg_len != 0) {
            msg = tvb_get_ephemeral_faked_unicode(tvb, offset, msg_len, TRUE);
            proto_tree_add_text(tree, tvb, offset, msg_len*2, "Text: %s", msg);
            offset += msg_len*2;
        }
    }
    return offset;
}

static void
dissect_tds_done_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_text(tree, tvb, offset, 2, "Status flags");
    offset += 2;
    proto_tree_add_text(tree, tvb, offset, 2, "Operation");
    offset += 2;
    proto_tree_add_text(tree, tvb, offset, 4, "row count: %u", tds_tvb_get_xxtohl(tvb, offset, tds_little_endian));
    offset += 2;
}

static guint8
dissect_tds_type_info(tvbuff_t *tvb, guint *offset, packet_info *pinfo, proto_tree *tree, gboolean *plp)
{
    proto_item *item = NULL, *item1 = NULL, *data_type_item = NULL;
    proto_tree *sub_tree = NULL, *collation_tree;
    guint32 varlen, varlen_len = 0;
    guint8 data_type;

    *plp = FALSE; /* most types are not Partially Length-Prefixed */
    item = proto_tree_add_item(tree, hf_tds_type_info, tvb, *offset, 0, TRUE);
    data_type = tvb_get_guint8(tvb, *offset);
    proto_item_append_text(item, " (%s)", val_to_str(data_type, tds_data_type_names, "Invalid data type: %02X"));
    sub_tree = proto_item_add_subtree(item, ett_tds_type_info);
    data_type_item = proto_tree_add_item(sub_tree, hf_tds_type_info_type, tvb, *offset, 1, TRUE);
    *offset += 1;

    /* optional TYPE_VARLEN for variable length types */
    switch(data_type) {
        /* FIXEDLENTYPE */
        case TDS_DATA_TYPE_NULL:            /* Null (no data associated with this type) */
        case TDS_DATA_TYPE_INT1:            /* TinyInt (1 byte data representation) */
        case TDS_DATA_TYPE_BIT:             /* Bit (1 byte data representation) */
        case TDS_DATA_TYPE_INT2:            /* SmallInt (2 byte data representation) */
        case TDS_DATA_TYPE_INT4:            /* Int (4 byte data representation) */
        case TDS_DATA_TYPE_FLT4:            /* Real (4 byte data representation) */
        case TDS_DATA_TYPE_DATETIM4:        /* SmallDateTime (4 byte data representation) */
        case TDS_DATA_TYPE_MONEY4:          /* SmallMoney (4 byte data representation) */
        case TDS_DATA_TYPE_INT8:            /* BigInt (8 byte data representation) */
        case TDS_DATA_TYPE_FLT8:            /* Float (8 byte data representation) */
        case TDS_DATA_TYPE_MONEY:           /* Money (8 byte data representation) */
        case TDS_DATA_TYPE_DATETIME:        /* DateTime (8 byte data representation) */
        /* BYTELEN_TYPE with length determined by SCALE */
        case TDS_DATA_TYPE_TIMEN:           /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIME2N:      /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIMEOFFSETN: /* (introduced in TDS 7.3) */
            varlen_len = 0;
            break;
        /* BYTELEN_TYPE */
        case TDS_DATA_TYPE_GUID:            /* UniqueIdentifier */
        case TDS_DATA_TYPE_INTN:
        case TDS_DATA_TYPE_DECIMAL:         /* Decimal (legacy support) */
        case TDS_DATA_TYPE_NUMERIC:         /* Numeric (legacy support) */
        case TDS_DATA_TYPE_BITN:
        case TDS_DATA_TYPE_DECIMALN:        /* Decimal */
        case TDS_DATA_TYPE_NUMERICN:        /* Numeric */
        case TDS_DATA_TYPE_FLTN:
        case TDS_DATA_TYPE_MONEYN:
        case TDS_DATA_TYPE_DATETIMN:
        case TDS_DATA_TYPE_DATEN:           /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_CHAR:            /* Char (legacy support) */
        case TDS_DATA_TYPE_VARCHAR:         /* VarChar (legacy support) */
        case TDS_DATA_TYPE_BINARY:          /* Binary (legacy support) */
        case TDS_DATA_TYPE_VARBINARY:       /* VarBinary (legacy support) */
            varlen_len = 1;
            varlen = tvb_get_guint8(tvb, *offset);
            break;
        /* USHORTLEN_TYPE */
        case TDS_DATA_TYPE_BIGVARCHR:       /* VarChar */
        case TDS_DATA_TYPE_BIGVARBIN:       /* VarBinary */
        case TDS_DATA_TYPE_NVARCHAR:        /* NVarChar */
            varlen_len = 2;
            varlen = tvb_get_letohs(tvb, *offset);
            /* A type with unlimited max size, known as varchar(max), varbinary(max) and nvarchar(max),
               which has a max size of 0xFFFF, defined by PARTLENTYPE. This class of types was introduced in TDS 7.2. */
            if(varlen == 0xFFFF)
                *plp = TRUE;
            break;
        case TDS_DATA_TYPE_BIGBINARY:       /* Binary */
        case TDS_DATA_TYPE_BIGCHAR:         /* Char */
        case TDS_DATA_TYPE_NCHAR:           /* NChar */
            varlen_len = 2;
            varlen = tvb_get_letohs(tvb, *offset);
            break;
        /* LONGLEN_TYPE */
        case TDS_DATA_TYPE_XML:             /* XML (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_UDT:             /* CLR-UDT (introduced in TDS 7.2) */
            *plp = TRUE;
        case TDS_DATA_TYPE_TEXT:            /* Text */
        case TDS_DATA_TYPE_IMAGE:           /* Image */
        case TDS_DATA_TYPE_NTEXT:           /* NText */
        case TDS_DATA_TYPE_SSVARIANT:       /* Sql_Variant (introduced in TDS 7.2) */
            varlen_len = 4;
            varlen = tvb_get_letohl(tvb, *offset);
            break;
        default:
            expert_add_info_format(pinfo, data_type_item, PI_MALFORMED, PI_ERROR, "Invalid data type");
            THROW(ReportedBoundsError); /* No point in continuing */
    }

    if(varlen_len)
        item1 = proto_tree_add_uint(sub_tree, hf_tds_type_info_varlen, tvb, *offset, varlen_len, varlen);
    if(*plp)
        proto_item_append_text(item1, " (PLP - Partially Length-Prefixed data type)");
    *offset += varlen_len;

    /* Optional data dependent on type */
    switch(data_type) {
        /* PRECISION and SCALE */
        case TDS_DATA_TYPE_DECIMAL:         /* Decimal (legacy support) */
        case TDS_DATA_TYPE_NUMERIC:         /* Numeric (legacy support) */
        case TDS_DATA_TYPE_DECIMALN:        /* Decimal */
        case TDS_DATA_TYPE_NUMERICN:        /* Numeric */
            proto_tree_add_item(sub_tree, hf_tds_type_info_precision, tvb, *offset, 1, TRUE);
            *offset += 1;
        /* SCALE */
        case TDS_DATA_TYPE_TIMEN:           /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIME2N:      /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIMEOFFSETN: /* (introduced in TDS 7.3) */
            proto_tree_add_item(sub_tree, hf_tds_type_info_scale, tvb, *offset, 1, TRUE);
            *offset += 1;
            break;
        /* COLLATION */
        case TDS_DATA_TYPE_BIGCHAR:         /* Char */
        case TDS_DATA_TYPE_BIGVARCHR:       /* VarChar */
        case TDS_DATA_TYPE_TEXT:            /* Text */
        case TDS_DATA_TYPE_NTEXT:           /* NText */
        case TDS_DATA_TYPE_NCHAR:           /* NChar */
        case TDS_DATA_TYPE_NVARCHAR:        /* NVarChar */
            item1 = proto_tree_add_item(sub_tree, hf_tds_type_info_collation, tvb, *offset, 5, TRUE);
            collation_tree = proto_item_add_subtree(item1, ett_tds_type_info_collation);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_lcid, tvb, *offset, 4, TRUE);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_case, tvb, *offset, 4, TRUE);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_accent, tvb, *offset, 4, TRUE);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_kana, tvb, *offset, 4, TRUE);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_width, tvb, *offset, 4, TRUE);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_binary, tvb, *offset, 4, TRUE);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_version, tvb, *offset, 4, TRUE);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_sortid, tvb, *offset + 4, 1, TRUE);
            *offset += 5;
            break;
    }

    proto_item_set_end(item, tvb, *offset);
    return data_type;
}

static void
dissect_tds_type_varbyte(tvbuff_t *tvb, guint *offset, packet_info *pinfo, proto_tree *tree, int hf, guint8 data_type, gboolean plp)
{
    enum { GEN_NULL = 0x00U, CHARBIN_NULL = 0xFFFFU, CHARBIN_NULL32 = 0xFFFFFFFFUL };
    guint32 length;
    char *string_value;
    proto_tree *sub_tree = NULL;
    proto_item *item = NULL, *length_item = NULL;

    item = proto_tree_add_item(tree, hf, tvb, *offset, 0, TRUE);
    sub_tree = proto_item_add_subtree(item, ett_tds_type_varbyte);

    if(plp) {
        enum { PLP_TERMINATOR = 0x00000000UL, UNKNOWN_PLP_LEN = 0xFFFFFFFFFFFFFFFEULL, PLP_NULL = 0xFFFFFFFFFFFFFFFFULL };
        guint64 plp_length = tvb_get_letoh64(tvb, *offset);
        length_item = proto_tree_add_item(sub_tree, hf_tds_type_varbyte_plp_len, tvb, *offset, 8, TRUE);
        *offset += 8;
        if(plp_length == PLP_NULL)
            proto_item_append_text(length_item, " (PLP_NULL)");
        else {
            if(plp_length == UNKNOWN_PLP_LEN)
                proto_item_append_text(length_item, " (UNKNOWN_PLP_LEN)");
            while(TRUE) {
                length = tvb_get_letohl(tvb, *offset);
                length_item = proto_tree_add_item(sub_tree, hf_tds_type_varbyte_plp_chunk_len, tvb, *offset, 4, TRUE);
                *offset += 4;
                if(length == PLP_TERMINATOR) {
                    proto_item_append_text(length_item, " (PLP_TERMINATOR)");
                    break;
                }
                switch(data_type) {
                    case TDS_DATA_TYPE_BIGVARBIN: /* VarBinary */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, TRUE);
                        break;
                    case TDS_DATA_TYPE_BIGVARCHR: /* VarChar */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, TRUE);
                        break;
                    case TDS_DATA_TYPE_NVARCHAR:  /* NVarChar */
                        string_value = tvb_get_ephemeral_faked_unicode(tvb, *offset, length / 2, TRUE);
                        proto_tree_add_string(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, string_value);
                        break;
                    case TDS_DATA_TYPE_XML:       /* XML (introduced in TDS 7.2) */
                    case TDS_DATA_TYPE_UDT:       /* CLR-UDT (introduced in TDS 7.2) */
                        expert_add_info_format(pinfo, length_item, PI_UNDECODED, PI_ERROR, "Data type %d not supported yet", data_type);
                        /* No point in continuing: we need to parse the full data_type to know where it ends */
                        THROW(ReportedBoundsError);
                    default:
                        /* no other data type sets plp = TRUE */
                        DISSECTOR_ASSERT_NOT_REACHED();
                }
                *offset += length;
            }
        }
    }
    else switch(data_type) {
        /* FIXEDLENTYPE */
        case TDS_DATA_TYPE_NULL:            /* Null (no data associated with this type) */
            break;
        case TDS_DATA_TYPE_BIT:             /* Bit (1 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_boolean, tvb, *offset, 1, TRUE);
            *offset += 1;
            break;
        case TDS_DATA_TYPE_INT1:            /* TinyInt (1 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int1, tvb, *offset, 1, TRUE);
            *offset += 1;
            break;
        case TDS_DATA_TYPE_INT2:            /* SmallInt (2 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int2, tvb, *offset, 2, TRUE);
            *offset += 2;
            break;
        case TDS_DATA_TYPE_INT4:            /* Int (4 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int4, tvb, *offset, 4, TRUE);
            *offset += 4;
            break;
        case TDS_DATA_TYPE_INT8:            /* BigInt (8 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int8, tvb, *offset, 8, TRUE);
            *offset += 8;
            break;
        case TDS_DATA_TYPE_FLT4:            /* Real (4 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_float, tvb, *offset, 4, TRUE);
            *offset += 4;
            break;
        case TDS_DATA_TYPE_FLT8:            /* Float (8 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_double, tvb, *offset, 8, TRUE);
            *offset += 8;
            break;
        case TDS_DATA_TYPE_MONEY4:          /* SmallMoney (4 byte data representation) */
        case TDS_DATA_TYPE_DATETIM4:        /* SmallDateTime (4 byte data representation) */
            /*TODO*/
            *offset += 4;
            break;
        case TDS_DATA_TYPE_MONEY:           /* Money (8 byte data representation) */
        case TDS_DATA_TYPE_DATETIME:        /* DateTime (8 byte data representation) */
            /*TODO*/
            *offset += 8;
            break;


        /* BYTELEN_TYPE - types prefixed with 1-byte length */
        case TDS_DATA_TYPE_GUID:            /* UniqueIdentifier */
            length = tvb_get_guint8(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            switch(length) {
                case GEN_NULL: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, TRUE); break;
                case 16: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_guid, tvb, *offset + 1, length, TRUE); break;
                default: expert_add_info_format(pinfo, length_item, PI_MALFORMED, PI_ERROR, "Invalid length");
            }
            *offset += 1 + length;
            break;
        case TDS_DATA_TYPE_BITN:
            length = tvb_get_guint8(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            switch(length) {
                case GEN_NULL: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, TRUE); break;
                case 1: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_boolean, tvb, *offset + 1, 1, TRUE); break;
                default: expert_add_info_format(pinfo, length_item, PI_MALFORMED, PI_ERROR, "Invalid length");
            }
            *offset += 1 + length;
            break;
        case TDS_DATA_TYPE_INTN:
            length = tvb_get_guint8(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            switch(length) {
                case GEN_NULL: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, TRUE); break;
                case 1: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int1, tvb, *offset + 1, 1, TRUE); break;
                case 2: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int2, tvb, *offset + 1, 2, TRUE); break;
                case 4: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int4, tvb, *offset + 1, 4, TRUE); break;
                case 8: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int8, tvb, *offset + 1, 8, TRUE); break;
                default: expert_add_info_format(pinfo, length_item, PI_MALFORMED, PI_ERROR, "Invalid length");
            }
            *offset += 1 + length;
            break;
        case TDS_DATA_TYPE_FLTN:
            length = tvb_get_guint8(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            switch(length) {
                case GEN_NULL: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, TRUE); break;
                case 4: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_float, tvb, *offset + 1, 4, TRUE); break;
                case 8: proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_double, tvb, *offset + 1, 8, TRUE); break;
                default: expert_add_info_format(pinfo, length_item, PI_MALFORMED, PI_ERROR, "Invalid length");
            }
            *offset += 1 + length;
            break;
        case TDS_DATA_TYPE_DECIMAL:         /* Decimal (legacy support) */
        case TDS_DATA_TYPE_NUMERIC:         /* Numeric (legacy support) */
        case TDS_DATA_TYPE_DECIMALN:        /* Decimal */
        case TDS_DATA_TYPE_NUMERICN:        /* Numeric */
        case TDS_DATA_TYPE_MONEYN:
        case TDS_DATA_TYPE_DATETIMN:
        case TDS_DATA_TYPE_DATEN:           /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_TIMEN:           /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIME2N:      /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIMEOFFSETN: /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_CHAR:            /* Char (legacy support) */
        case TDS_DATA_TYPE_VARCHAR:         /* VarChar (legacy support) */
        case TDS_DATA_TYPE_BINARY:          /* Binary (legacy support) */
        case TDS_DATA_TYPE_VARBINARY:       /* VarBinary (legacy support) */
            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length > 0) {
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, TRUE);
                *offset += length;
            }
            break;

        /* USHORTLEN_TYPE - types prefixed with 2-byte length */
        case TDS_DATA_TYPE_BIGVARBIN:       /* VarBinary */
        case TDS_DATA_TYPE_BIGBINARY:       /* Binary */
        case TDS_DATA_TYPE_BIGVARCHR:       /* VarChar */
        case TDS_DATA_TYPE_BIGCHAR:         /* Char */
        case TDS_DATA_TYPE_NVARCHAR:        /* NVarChar */
        case TDS_DATA_TYPE_NCHAR:           /* NChar */
            length = tvb_get_letohs(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 2, length);
            *offset += 2;
            if(length == CHARBIN_NULL) {
                proto_item_append_text(length_item, " (CHARBIN_NULL)");
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, TRUE);
            }
            else {
                switch(data_type) {
                    case TDS_DATA_TYPE_BIGVARBIN: /* VarBinary */
                    case TDS_DATA_TYPE_BIGBINARY: /* Binary */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, TRUE);
                        break;
                    case TDS_DATA_TYPE_BIGVARCHR: /* VarChar */
                    case TDS_DATA_TYPE_BIGCHAR:   /* Char */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, TRUE);
                        break;
                    case TDS_DATA_TYPE_NVARCHAR:  /* NVarChar */
                    case TDS_DATA_TYPE_NCHAR:     /* NChar */
                        string_value = tvb_get_ephemeral_faked_unicode(tvb, *offset, length / 2, TRUE);
                        proto_tree_add_string(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, string_value);
                        break;
                    default:
                        DISSECTOR_ASSERT_NOT_REACHED();
                }
                *offset += length;
            }
            break;

        /* LONGLEN_TYPE - types prefixed with 2-byte length */
        case TDS_DATA_TYPE_NTEXT:           /* NText */
        case TDS_DATA_TYPE_XML:             /* XML (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_UDT:             /* CLR-UDT (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_TEXT:            /* Text */
        case TDS_DATA_TYPE_IMAGE:           /* Image */
        case TDS_DATA_TYPE_SSVARIANT:       /* Sql_Variant (introduced in TDS 7.2) */
            length = tvb_get_letohl(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 4, length);
            *offset += 4;
            if(length == CHARBIN_NULL32) {
                proto_item_append_text(length_item, " (CHARBIN_NULL)");
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, TRUE);
            }
            else {
                switch(data_type) {
                    case TDS_DATA_TYPE_NTEXT: /* NText */
                        string_value = tvb_get_ephemeral_faked_unicode(tvb, *offset, length / 2, TRUE);
                        proto_tree_add_string(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, string_value);
                        break;
                    default: /*TODO*/
                        expert_add_info_format(pinfo, length_item, PI_UNDECODED, PI_ERROR, "Data type %d not supported yet", data_type);
                        /* No point in continuing: we need to parse the full data_type to know where it ends */
                        THROW(ReportedBoundsError);
                }
                *offset += length;
            }
            break;
    }
    proto_item_set_end(item, tvb, *offset);
}

static void
dissect_tds_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item = NULL, *param_item = NULL;
    proto_tree *sub_tree = NULL, *status_sub_tree = NULL;
    int offset = 0;
    guint len;
    char *val;
    guint8 data_type;

    item = proto_tree_add_item(tree, hf_tds_rpc, tvb, 0, -1, TRUE);
    tree = proto_item_add_subtree(item, ett_tds_message);

    dissect_tds_all_headers(tvb, &offset, pinfo, tree);
    while(tvb_length_remaining(tvb, offset) > 0) {
        /*
         * RPC name.
         */
        switch(tds_protocol_type) {
            case TDS_PROTOCOL_4:
                len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_tds_rpc_name_length8, tvb, offset, 1, TRUE);
                proto_tree_add_item(tree, hf_tds_rpc_name, tvb, offset + 1, len, TRUE);
                offset += 1 + len;
                break;

            case TDS_PROTOCOL_7_0:
            case TDS_PROTOCOL_7_1:
            case TDS_PROTOCOL_7_2:
            case TDS_PROTOCOL_7_3:
            default: /* unspecified: try as if TDS7 */
                len = tvb_get_letohs(tvb, offset);
                proto_tree_add_item(tree, hf_tds_rpc_name_length, tvb, offset, 2, TRUE);
                offset += 2;
                if (len == 0xFFFF) {
                    proto_tree_add_item(tree, hf_tds_rpc_proc_id, tvb, offset, 2, TRUE);
                    offset += 2;
                }
                else if (len != 0) {
                    val = tvb_get_ephemeral_faked_unicode(tvb, offset, len, TRUE);
                    proto_tree_add_string(tree, hf_tds_rpc_name, tvb, offset, len * 2, val);
                    offset += len * 2;
                }
                break;
        }
        item = proto_tree_add_item(tree, hf_tds_rpc_options, tvb, offset, 2, TRUE);
        sub_tree = proto_item_add_subtree(item, ett_tds_rpc_options);
        proto_tree_add_item(sub_tree, hf_tds_rpc_options_with_recomp, tvb, offset, 2, TRUE);
        proto_tree_add_item(sub_tree, hf_tds_rpc_options_no_metadata, tvb, offset, 2, TRUE);
        proto_tree_add_item(sub_tree, hf_tds_rpc_options_reuse_metadata, tvb, offset, 2, TRUE);
        offset += 2;

        /* dissect parameters */
        while(tvb_length_remaining(tvb, offset) > 0) {
            gboolean plp;

            len = tvb_get_guint8(tvb, offset);
            /* check for BatchFlag or NoExecFlag */
            if((gint8)len < 0) {
                proto_tree_add_item(tree, hf_tds_rpc_separator, tvb, offset, 1, TRUE);
                ++offset;
                break;
            }
            param_item = proto_tree_add_item(tree, hf_tds_rpc_parameter, tvb, offset, 0, TRUE);
            sub_tree = proto_item_add_subtree(param_item, ett_tds_rpc_parameter);
            proto_tree_add_item(sub_tree, hf_tds_rpc_parameter_name_length, tvb, offset, 1, TRUE);
            ++offset;
            if(len) {
                val = tvb_get_ephemeral_faked_unicode(tvb, offset, len, TRUE);
                proto_tree_add_string(sub_tree, hf_tds_rpc_parameter_name, tvb, offset, len * 2, val);
                offset += len * 2;
            }
            item = proto_tree_add_item(sub_tree, hf_tds_rpc_parameter_status, tvb, offset, 1, TRUE);
            status_sub_tree = proto_item_add_subtree(item, ett_tds_rpc_parameter_status);
            proto_tree_add_item(status_sub_tree, hf_tds_rpc_parameter_status_by_ref, tvb, offset, 1, TRUE);
            proto_tree_add_item(status_sub_tree, hf_tds_rpc_parameter_status_default, tvb, offset, 1, TRUE);
            ++offset;
            data_type = dissect_tds_type_info(tvb, &offset, pinfo, sub_tree, &plp);
            dissect_tds_type_varbyte(tvb, &offset, pinfo, sub_tree, hf_tds_rpc_parameter_value, data_type, plp);
            proto_item_set_end(param_item, tvb, offset);
        }
    }
}

static void
dissect_tds_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *token_item;
    proto_tree *token_tree;
    guint pos, token_sz = 0;
    guint token_len_field_size = 2;
    guint token_len_field_val = 0;
    guint8 token;
    struct _netlib_data nl_data;
    gint length_remaining;

    memset(&nl_data, '\0', sizeof nl_data);

    /*
     * Until we reach the end of the packet, read tokens.
     */
    pos = offset;
    while (tvb_reported_length_remaining(tvb, pos) > 0) {
        /* our token */
        token = tvb_get_guint8(tvb, pos);

        /* TODO Handle TDS_PARAMFMT, TDS_PARAMS [similar to TDS_RESULTS, TDS_ROW] */
        if (tds_token_is_fixed_size(token)) {
            token_sz = tds_get_fixed_token_size(token) + 1;
        } else if (token == TDS_ROW_TOKEN) {
            /*
             * Rows are special; they have no size field and
             * aren't fixed length.
             */
            token_sz = tds_get_row_size(tvb, &nl_data, pos + 1);
        } else
            token_sz = tds_get_variable_token_size(tvb, pos + 1,
                                                   token, &token_len_field_size, &token_len_field_val);

        length_remaining = tvb_ensure_length_remaining(tvb, pos);

        if ((int) token_sz < 0) {
            proto_tree_add_text(tree, tvb, pos, 0, "Bogus token size: %u",
                                token_sz);
            break;
        }
        if ((int) token_len_field_size < 0) {
            proto_tree_add_text(tree, tvb, pos, 0, "Bogus token length field size: %u",
                                token_len_field_size);
            break;
        }
        token_item = proto_tree_add_text(tree, tvb, pos, token_sz,
                                         "Token 0x%02x %s", token,
                                         val_to_str(token, token_names, "Unknown Token Type"));
        token_tree = proto_item_add_subtree(token_item, ett_tds_token);

        /*
         * If it's a variable token, put the length field in here
         * instead of replicating this for each token subdissector.
         */
        if (!tds_token_is_fixed_size(token) && token != TDS_ROW_TOKEN) {
            proto_tree_add_text(token_tree, tvb, pos + 1,
                                token_len_field_size, "Length: %u",
                                token_len_field_val);
        }

        if (token_sz > (guint)length_remaining)
            token_sz = (guint)length_remaining;

        switch (token) {

            case TDS_COL_NAME_TOKEN:
                /*
                 * TDS 4.2
                 * TODO dissect token to get "column names" to fill in _netlib_data
                 */
                break;

            case TDS_COL_INFO_TOKEN:
                /*
                 * TDS 4.2: get the column info
                 */
                dissect_tds_col_info_token(tvb, &nl_data, pos);
                break;

            case TDS_RESULT_TOKEN:
                /*
                 * If it's a result token, we need to stash the
                 * column info.
                 */
                read_results_tds5(tvb, &nl_data, pos + 3, token_sz - 3);
                break;

            case TDS_ENV_CHG_TOKEN:
                dissect_tds_env_chg(tvb, pos + 3, token_sz - 3, token_tree);
                break;

            case TDS_AUTH_TOKEN:
                dissect_tds_nt(tvb, pinfo, token_tree, pos + 3, token_sz - 3);
                break;
            case TDS_ERR_TOKEN:
            case TDS_MSG_TOKEN:
                dissect_tds_err_token(tvb, pos + 3, token_sz - 3, token_tree);
                break;

            case TDS_DONE_TOKEN:
            case TDS_DONEPROC_TOKEN:
            case TDS_DONEINPROC_TOKEN:
                dissect_tds_done_token(tvb, pos + 1, token_tree);
                break;
            case TDS_LOGIN_ACK_TOKEN:
                dissect_tds_login_ack_token(tvb, pos + 3, token_sz - 3, token_tree);
                break;
            case TDS7_RESULT_TOKEN:
                pos = (dissect_tds7_results_token(tvb, pos + 1, token_tree)-1);
                break;
        }

        /* and step to the end of the token, rinse, lather, repeat */
        pos += token_sz;
    }
}

static void
dissect_netlib_buffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *tds_item = NULL;
    proto_tree *tds_tree = NULL;
    proto_tree *tds_status_tree = NULL;
    guint8 type;
    guint8 status;
    guint16 channel;
    guint8 packet_number;
    gboolean save_fragmented;
    int len;
    fragment_data *fd_head;
    tvbuff_t *next_tvb;

    type = tvb_get_guint8(tvb, offset);
    status = tvb_get_guint8(tvb, offset + 1);
    channel = tvb_get_ntohs(tvb, offset + 4);
    packet_number = tvb_get_guint8(tvb, offset + 6);

    /* create display subtree for the protocol */
    tds_item = proto_tree_add_item(tree, proto_tds, tvb, offset, -1, FALSE);
    tds_tree = proto_item_add_subtree(tds_item, ett_tds);
    proto_tree_add_item(tds_tree, hf_tds_type, tvb, offset, 1, TRUE);
    tds_item = proto_tree_add_item(tds_tree, hf_tds_status, tvb, offset + 1, 1, TRUE);
    tds_status_tree = proto_item_add_subtree(tds_item, ett_tds_status);
    proto_tree_add_item(tds_status_tree, hf_tds_status_eom, tvb, offset + 1, 1, FALSE);
    proto_tree_add_item(tds_status_tree, hf_tds_status_ignore, tvb, offset + 1, 1, FALSE);
    proto_tree_add_item(tds_status_tree, hf_tds_status_event_notif, tvb, offset + 1, 1, FALSE);
    proto_tree_add_item(tds_status_tree, hf_tds_status_reset_conn, tvb, offset + 1, 1, FALSE);
    proto_tree_add_item(tds_status_tree, hf_tds_status_reset_conn_skip_tran,tvb, offset + 1, 1, FALSE);
    proto_tree_add_item(tds_tree, hf_tds_length, tvb, offset + 2, 2, FALSE);
    proto_tree_add_item(tds_tree, hf_tds_channel, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(tds_tree, hf_tds_packet_number, tvb, offset + 6, 1, TRUE);
    proto_tree_add_item(tds_tree, hf_tds_window, tvb, offset + 7, 1, TRUE);
    offset += 8;        /* skip Netlib header */

    /*
     * Deal with fragmentation.
     *
     * TODO: handle case where netlib headers 'packet-number'.is always 0
     *       use fragment_add_seq_next in this case ?
     *
     */
    save_fragmented = pinfo->fragmented;
    if (tds_defragment &&
        (packet_number > 1 || (status & STATUS_LAST_BUFFER) == 0)) {
        if ((status & STATUS_LAST_BUFFER) == 0) {
            col_append_str(pinfo->cinfo, COL_INFO,
                           " (Not last buffer)");
        }
        len = tvb_reported_length_remaining(tvb, offset);
        /*
         * XXX - I've seen captures that start with a login
         * packet with a sequence number of 2.
         */
        fd_head = fragment_add_seq_check(tvb, offset, pinfo, channel,
                                         tds_fragment_table, tds_reassembled_table,
                                         packet_number - 1, len, (status & STATUS_LAST_BUFFER) == 0);
        next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                            "Reassembled TDS", fd_head, &tds_frag_items, NULL,
                                            tds_tree);
    } else {
        /*
         * If this isn't the last buffer, just show it as a fragment.
         * (XXX - it'd be nice to dissect it if it's the first
         * buffer, but we'd need to do reassembly in order to
         * discover that.)
         *
         * If this is the last buffer, dissect it.
         * (XXX - it'd be nice to show it as a fragment if it's part
         * of a fragmented message, but we'd need to do reassembly
         * in order to discover that.)
         */
        if ((status & STATUS_LAST_BUFFER) == 0)
            next_tvb = NULL;
        else {
            next_tvb = tvb_new_subset_remaining(tvb, offset);
        }
    }

    if (next_tvb != NULL) {

        switch (type) {

            case TDS_RPC_PKT:
                dissect_tds_rpc(next_tvb, pinfo, tds_tree);
                break;

            case TDS_RESP_PKT:
                dissect_tds_resp(next_tvb, pinfo, tds_tree);
                break;

            case TDS_LOGIN7_PKT:
                dissect_tds7_login(next_tvb, pinfo, tds_tree);
                break;
            case TDS_QUERY_PKT:
                dissect_tds_query_packet(next_tvb, pinfo, tds_tree);
                break;
            case TDS_QUERY5_PKT:
                dissect_tds_query5_packet(next_tvb, pinfo, tds_tree);
                break;
            case TDS_SSPI_PKT:
                dissect_tds_nt(next_tvb, pinfo, tds_tree, offset - 8, -1);
                break;
            default:
                proto_tree_add_text(tds_tree, next_tvb, 0, -1,
                                    "TDS Packet");
                break;
        }
    } else {
        next_tvb = tvb_new_subset_remaining (tvb, offset);
        call_dissector(data_handle, next_tvb, pinfo, tds_tree);
    }
    pinfo->fragmented = save_fragmented;
}

static void
dissect_tds_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    volatile gboolean first_time = TRUE;
    volatile int offset = 0;
    guint length_remaining;
    guint8 type;
    guint16 plen;
    guint length;
    tvbuff_t *volatile next_tvb;
    proto_item *tds_item = NULL;
    proto_tree *tds_tree = NULL;
    void *pd_save;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        length_remaining = tvb_ensure_length_remaining(tvb, offset);

        /*
         * Can we do reassembly?
         */
        if (tds_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the fixed-length part of the PDU
             * split across segment boundaries?
             */
            if (length_remaining < 8) {
		/*
		 * Yes.  Tell the TCP dissector where the data for this message
		 * starts in the data it handed us and that we need "some more
		 * data."  Don't tell it exactly how many bytes we need because
		 * if/when we ask for even more (after the header) that will
		 * break reassembly.
		 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return;
            }
        }

        type = tvb_get_guint8(tvb, offset);

        /*
         * Get the length of the PDU.
         */
        plen = tvb_get_ntohs(tvb, offset + 2);
        if (plen < 8) {
            /*
             * The length is less than the header length.
             * Put in the type, status, and length, and
             * report the length as bogus.
             */
            if (tree) {
                /* create display subtree for the protocol */
                tds_item = proto_tree_add_item(tree, proto_tds,
                                               tvb, offset, -1, FALSE);

                tds_tree = proto_item_add_subtree(tds_item,
                                                  ett_tds);
                proto_tree_add_uint(tds_tree, hf_tds_type, tvb,
                                    offset, 1, type);
                proto_tree_add_item(tds_tree, hf_tds_status,
                                    tvb, offset + 1, 1, FALSE);
                proto_tree_add_uint_format(tds_tree,
                                           hf_tds_length, tvb, offset + 2, 2, plen,
                                           "Size: %u (bogus, should be >= 8)", plen);
            }

            /*
             * Give up - we can't dissect any more of this
             * data.
             */
            break;
        }

        /*
         * Can we do reassembly?
         */
        if (tds_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the PDU split across segment boundaries?
             */
            if (length_remaining < plen) {
                /*
                 * Yes.  Tell the TCP dissector where the
                 * data for this message starts in the data
                 * it handed us, and how many more bytes we
                 * need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = plen - length_remaining;
                return;
            }
        }

        if (first_time) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "TDS");

            /*
             * Set the packet description based on its TDS packet
             * type.
             */
            col_add_str(pinfo->cinfo, COL_INFO,
                        val_to_str(type, packet_type_names,
                                   "Unknown Packet Type: %u"));
            first_time = FALSE;
        }

        /*
         * Construct a tvbuff containing the amount of the payload
         * we have available.  Make its reported length the amount
         * of data in the PDU.
         *
         * XXX - if reassembly isn't enabled. the subdissector will
         * throw a BoundsError exception, rather than a
         * ReportedBoundsError exception.  We really want a tvbuff
         * where the length is "length", the reported length is
         * "plen", and the "if the snapshot length were infinite"
         * length is the minimum of the reported length of the tvbuff
         * handed to us and "plen", with a new type of exception
         * thrown if the offset is within the reported length but
         * beyond that third length, with that exception getting the
         * "Unreassembled Packet" error.
         */
        length = length_remaining;
        if (length > plen)
            length = plen;
        next_tvb = tvb_new_subset(tvb, offset, length, plen);

        /*
         * Dissect the Netlib buffer.
         *
         * Catch the ReportedBoundsError exception; if this
         * particular Netlib buffer happens to get a
         * ReportedBoundsError exception, that doesn't mean
         * that we should stop dissecting PDUs within this frame
         * or chunk of reassembled data.
         *
         * If it gets a BoundsError, we can stop, as there's nothing
         * more to see, so we just re-throw it.
         */
        pd_save = pinfo->private_data;
        TRY {
            dissect_netlib_buffer(next_tvb, pinfo, tree);
        }
        CATCH(BoundsError) {
            RETHROW;
        }
        CATCH(ReportedBoundsError) {
            /*  Restore the private_data structure in case one of the
             *  called dissectors modified it (and, due to the exception,
             *  was unable to restore it).
             */
            pinfo->private_data = pd_save;

            show_reported_bounds_error(tvb, pinfo, tree);
        }
        ENDTRY;

        /*
         * Step to the next Netlib buffer.
         */
        offset += plen;
    }
}

static gboolean
dissect_tds_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint8 type;
    guint8 status;
    guint16 plen;
    conversation_t *conv;

    /*
     * If we don't have even enough data for a Netlib header,
     * just say it's not TDS.
     */
    if (tvb_length(tvb) < 8)
        return FALSE;

    /*
     * Quickly scan all the data we have in order to see if
     * everything in it looks like Netlib traffic.
     */
    while (tvb_bytes_exist(tvb, offset, 1)) {
        /*
         * Check the type field.
         */
        type = tvb_get_guint8(tvb, offset);
        if (!is_valid_tds_type(type))
            return FALSE;

        /*
         * Check the status field, if it's present.
         */
        if (!tvb_bytes_exist(tvb, offset + 1, 1))
            break;
        status = tvb_get_guint8(tvb, offset + 1);
        if (!is_valid_tds_status(status))
            return FALSE;

        /*
         * Get the length of the PDU.
         */
        if (!tvb_bytes_exist(tvb, offset + 2, 2))
            break;
        plen = tvb_get_ntohs(tvb, offset + 2);
        if (plen < 8) {
            /*
             * The length is less than the header length.
             * That's bogus.
             */
            return FALSE;
        }

        /*
         * If we're at the beginning of the segment, check the
         * payload if it's a login packet.
         */
        if (offset == 0) {
            if (!netlib_check_login_pkt(tvb, offset, pinfo, type))
                return FALSE;
        }

        /*
         * Step to the next Netlib buffer.
         */
        offset += plen;
    }

    /*
     * OK, it passes the test; assume the rest of this conversation
     * is TDS.
     */
    conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, tds_tcp_handle);

    /*
     * Now dissect it as TDS.
     */
    dissect_tds_tcp(tvb, pinfo, tree);
    return TRUE;
}

static void
tds_init(void)
{
    /*
     * Initialize the fragment and reassembly tables.
     */
    fragment_table_init(&tds_fragment_table);
    reassembled_table_init(&tds_reassembled_table);

}

/* Register the protocol with Wireshark */

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_tds(void)
{
    static hf_register_info hf[] = {
        { &hf_tds_type,
          { "Type",             "tds.type",
            FT_UINT8, BASE_DEC, VALS(packet_type_names), 0x0,
            "Packet type", HFILL }
        },
        { &hf_tds_status,
          { "Status",           "tds.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Packet status", HFILL }
        },
        { &hf_tds_status_eom,
          { "End of message",   "tds.status.eom",
            FT_BOOLEAN, 8, NULL, STATUS_LAST_BUFFER,
            "The packet is the last packet in the whole request", HFILL }
        },
        { &hf_tds_status_ignore,
          { "Ignore this event", "tds.status.ignore",
            FT_BOOLEAN, 8, NULL, STATUS_IGNORE_EVENT,
            "(From client to server) Ignore this event (EOM MUST also be set)", HFILL }
        },
        { &hf_tds_status_event_notif,
          { "Event notification", "tds.status.event_notif",
            FT_BOOLEAN, 8, NULL, STATUS_EVENT_NOTIFICATION,
            NULL, HFILL }
        },
        { &hf_tds_status_reset_conn,
          { "Reset connection", "tds.status.reset_conn",
            FT_BOOLEAN, 8, NULL, STATUS_RESETCONNECTION,
            "(From client to server) Reset this connection before processing event", HFILL }
        },
        { &hf_tds_status_reset_conn_skip_tran,
          { "Reset connection keeping transaction state", "tds.status.reset_conn_skip_tran",
            FT_BOOLEAN, 8, NULL, STATUS_RESETCONNECTIONSKIPTRAN,
            "(From client to server) Reset the connection before processing event but do not modify the transaction state", HFILL }
        },
        { &hf_tds_length,
          { "Length",           "tds.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Packet length", HFILL }
        },
        { &hf_tds_channel,
          { "Channel",          "tds.channel",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Channel Number", HFILL }
        },
        { &hf_tds_packet_number,
          { "Packet Number",    "tds.packet_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_window,
          { "Window",           "tds.window",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_fragment_overlap,
          { "Segment overlap",  "tds.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_tds_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap", "tds.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_tds_fragment_multiple_tails,
          { "Multiple tail fragments found", "tds.fragment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_tds_fragment_too_long_fragment,
          { "Segment too long", "tds.fragment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of packet", HFILL }
        },
        { &hf_tds_fragment_error,
          { "Defragmentation error",    "tds.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_tds_fragment_count,
          { "Segment count", "tds.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_fragment,
          { "TDS Fragment",     "tds.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_fragments,
          { "TDS Fragments",    "tds.fragments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_reassembled_in,
          { "Reassembled TDS in frame", "tds.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This TDS packet is reassembled in this frame", HFILL }
        },
        { &hf_tds_reassembled_length,
          { "Reassembled TDS length", "tds.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }
        },
        { &hf_tds7_login_total_size,
          { "Total Packet Length", "tds7login.total_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "TDS7 Login Packet total packet length", HFILL }
        },
        { &hf_tds7_version,
          { "TDS version", "tds7login.version",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_packet_size,
          { "Packet Size", "tds7login.packet_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_client_version,
          { "Client version", "tds7login.client_version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_client_pid,
          { "Client PID", "tds7login.client_pid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_connection_id,
          { "Connection ID", "tds7login.connection_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_option_flags1,
          { "Option Flags 1", "tds7login.option_flags1",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_option_flags2,
          { "Option Flags 2", "tds7login.option_flags2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_sql_type_flags,
          { "SQL Type Flags", "tds7login.sql_type_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_reserved_flags,
          { "Reserved Flags", "tds7login.reserved_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_time_zone,
          { "Time Zone", "tds7login.time_zone",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7_collation,
          { "Collation", "tds7login.collation",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_all_headers,
          { "Packet data stream headers", "tds.all_headers",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "The ALL_HEADERS rule", HFILL }
        },
        { &hf_tds_all_headers_total_length,
          { "Total length",     "tds.all_headers.total_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Total length of ALL_HEADERS stream", HFILL }
        },
        { &hf_tds_all_headers_header_length,
          { "Length",           "tds.all_headers.header.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Total length of an individual header", HFILL }
        },
        { &hf_tds_all_headers_header_type,
          { "Type",             "tds.all_headers.header.type",
            FT_UINT16, BASE_HEX, VALS(header_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_all_headers_trans_descr,
          { "Transaction descriptor", "tds.all_headers.header.trans_descr",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "For each connection, a number that uniquely identifies the transaction the request is associated with. Initially generated by the server when a new transaction is created and returned to the client as part of the ENVCHANGE token stream.", HFILL }
        },
        { &hf_tds_all_headers_request_cnt,
          { "Outstanding request count", "tds.all_headers.header.request_cnt",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of requests currently active on the connection", HFILL }
        },
        { &hf_tds_type_info,
          { "Type info",        "tds.type_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "The TYPE_INFO rule applies to several messages used to describe column information", HFILL }
        },
        { &hf_tds_type_info_type,
          { "Type",             "tds.type_info.type",
            FT_UINT8, BASE_HEX, VALS(tds_data_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_info_varlen,
          { "Maximal length",   "tds.type_info.varlen",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Defines the length of the data contained within the column", HFILL }
        },
        { &hf_tds_type_info_precision,
          { "Precision",        "tds.type_info.precision",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_info_scale,
          { "Scale",            "tds.type_info.scale",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation,
          { "Collation",        "tds.type_info.collation",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Specifies collation information for character data or metadata describing character data", HFILL }
        },
        { &hf_tds_type_info_collation_lcid,
          { "LCID",             "tds.type_info.collation.lcid",
            FT_UINT32, BASE_HEX, NULL, 0x000FFFFF,
            "For a SortId==0 collation, the LCID bits correspond to a LocaleId as defined by the National Language Support (NLS) functions", HFILL }
        },
        { &hf_tds_type_info_collation_ign_case,
          { "Ignore case",      "tds.type_info.collation.ignore_case",
            FT_BOOLEAN, 32, NULL, 0x00100000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_ign_accent,
          { "Ignore accent",    "tds.type_info.collation.ignore_accent",
            FT_BOOLEAN, 32, NULL, 0x00200000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_ign_kana,
          { "Ignore kana",      "tds.type_info.collation.ignore_kana",
            FT_BOOLEAN, 32, NULL, 0x00400000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_ign_width,
          { "Ignore width",     "tds.type_info.collation.ignore_width",
            FT_BOOLEAN, 32, NULL, 0x00800000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_binary,
          { "Binary",           "tds.type_info.collation.binary",
            FT_BOOLEAN, 32, NULL, 0x01000000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_version,
          { "Version",          "tds.type_info.collation.version",
            FT_UINT32, BASE_DEC, NULL, 0xF0000000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_sortid,
          { "SortId",           "tds.type_info.collation.sortid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_length,
          { "Length",           "tds.type_varbyte.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_null,
          { "Data: NULL",       "tds.type_varbyte.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_boolean,
          { "Data",             "tds.type_varbyte.data",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int1,
          { "Data",             "tds.type_varbyte.data",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int2,
          { "Data",             "tds.type_varbyte.data",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int4,
          { "Data",             "tds.type_varbyte.data",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int8,
          { "Data",             "tds.type_varbyte.data",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_float,
          { "Data",             "tds.type_varbyte.data",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_double,
          { "Data",             "tds.type_varbyte.data",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_bytes,
          { "Data",             "tds.type_varbyte.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_guid,
          { "Data",             "tds.type_varbyte.data",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_string,
          { "Data",             "tds.type_varbyte.data",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_plp_len,
          { "PLP length",       "tds.type_varbyte.plp_len",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_plp_chunk_len,
          { "PLP chunk length", "tds.type_varbyte.plp_chunk_len",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc,
          { "Remote Procedure Call", "tds.rpc",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_name_length8,
          { "Procedure name length", "tds.rpc.name_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_name_length,
          { "Procedure name length", "tds.rpc.name_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_name,
          { "Procedure name",   "tds.rpc.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_proc_id,
          { "Stored procedure ID", "tds.rpc.proc_id",
            FT_UINT16, BASE_DEC, VALS(internal_stored_proc_id_names), 0x0,
            "The number identifying the special stored procedure to be executed", HFILL }
        },
        { &hf_tds_rpc_options,
          { "Option flags",     "tds.rpc.options",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "The number identifying the special stored procedure to be executed", HFILL }
        },
        { &hf_tds_rpc_options_with_recomp,
          { "With recompile",   "tds.rpc.options.with_recomp",
            FT_BOOLEAN, 16, NULL, TDS_RPC_OPT_WITH_RECOMP,
            "The number identifying the special stored procedure to be executed", HFILL }
        },
        { &hf_tds_rpc_options_no_metadata,
          { "No metadata",      "tds.rpc.options.no_metadata",
            FT_BOOLEAN, 16, NULL, TDS_RPC_OPT_NO_METADATA,
            "The number identifying the special stored procedure to be executed", HFILL }
        },
        { &hf_tds_rpc_options_reuse_metadata,
          { "Reuse metadata",   "tds.rpc.options.reuse_metadata",
            FT_BOOLEAN, 16, NULL, TDS_RPC_OPT_REUSE_METADATA,
            "The number identifying the special stored procedure to be executed", HFILL }
        },
        { &hf_tds_rpc_separator,
          { "RPC batch separator", "tds.rpc.separator",
            FT_UINT8, BASE_DEC, VALS(tds_rpc_separators), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_parameter,
          { "Parameter",        "tds.rpc.parameter",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_parameter_name_length,
          { "Name length",      "tds.rpc.parameter.name_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_parameter_name,
          { "Name",             "tds.rpc.parameter.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rpc_parameter_status,
          { "Status flags",     "tds.rpc.parameter.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Information on how the parameter is passed", HFILL }
        },
        { &hf_tds_rpc_parameter_status_by_ref,
          { "By reference",     "tds.rpc.parameter.status.by_ref",
            FT_BOOLEAN, 16, NULL, TDS_RPC_PARAMETER_STATUS_BY_REF,
            NULL, HFILL }
        },
        { &hf_tds_rpc_parameter_status_default,
          { "Default value",    "tds.rpc.parameter.status.default",
            FT_BOOLEAN, 16, NULL, TDS_RPC_PARAMETER_STATUS_DEFAULT,
            NULL, HFILL }
        },
        { &hf_tds_rpc_parameter_value,
          { "Value",            "tds.rpc.parameter.value",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_tds,
        &ett_tds_status,
        &ett_tds_fragments,
        &ett_tds_fragment,
        &ett_tds_all_headers,
        &ett_tds_all_headers_header,
        &ett_tds_type_info,
        &ett_tds_type_info_collation,
        &ett_tds_type_varbyte,
        &ett_tds_message,
        &ett_tds_rpc_options,
        &ett_tds_rpc_parameter,
        &ett_tds_rpc_parameter_status,
        &ett_tds_token,
        &ett_tds7_query,
        &ett_tds7_login,
        &ett_tds7_hdr,
    };
    module_t *tds_module;

/* Register the protocol name and description */
    proto_tds = proto_register_protocol("Tabular Data Stream",
                                        "TDS", "tds");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_tds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

/* Allow dissector to be found by name. */
    register_dissector("tds", dissect_tds_tcp, proto_tds);

    tds_module = prefs_register_protocol(proto_tds, NULL);
    prefs_register_bool_preference(tds_module, "desegment_buffers",
                                   "Reassemble TDS buffers spanning multiple TCP segments",
                                   "Whether the TDS dissector should reassemble TDS buffers spanning multiple TCP segments. "
                                   "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &tds_desegment);
    prefs_register_bool_preference(tds_module, "defragment",
                                   "Reassemble fragmented TDS messages with multiple buffers",
                                   "Whether the TDS dissector should defragment messages spanning multiple Netlib buffers",
                                   &tds_defragment);
    prefs_register_enum_preference(tds_module, "protocol_type",
                                   "TDS Protocol Type",
                                   "Hint as to version of TDS protocol being decoded",
                                   &tds_protocol_type, tds_protocol_type_options, FALSE);
    prefs_register_enum_preference(tds_module, "endian_type",
                                   "TDS decode as",
                                   "Hint as to whether to decode TDS protocol as little-endian or big-endian. (TDS7/8 always decoded as little-endian)",
                                   &tds_little_endian, tds_endian_type_options, FALSE);
    prefs_register_range_preference(tds_module, "tcp_ports",
                                    "TDS TCP ports",
                                    "Additional TCP ports to decode as TDS",
                                    &tds_tcp_ports, 0xFFFF);

    register_init_routine(tds_init);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_tds(void)
{
    tds_tcp_handle = create_dissector_handle(dissect_tds_tcp, proto_tds);

    /* Initial TDS ports: MS SQL default ports */
    dissector_add_uint("tcp.port", 1433, tds_tcp_handle);
    dissector_add_uint("tcp.port", 2433, tds_tcp_handle);

    heur_dissector_add("tcp", dissect_tds_tcp_heur, proto_tds);

    ntlmssp_handle = find_dissector("ntlmssp");
    gssapi_handle = find_dissector("gssapi");
    data_handle = find_dissector("data");
}
