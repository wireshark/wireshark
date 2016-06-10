/* packet-tds.c
 * Routines for TDS NetLib dissection
 * Copyright 2000-2002, Brian Bruns <camber@ais.org>
 * Copyright 2002, Steve Langasek <vorlon@netexpress.net>
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
 * http://www.sybase.com/content/1013412/tds34.pdf
 * http://www.sybase.com/content/1040983/Sybase-tds38-102306.pdf
 * Microsoft's [MS-TDS] protocol specification
 *
 * This document is no longer available here:
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
 *   deal with dissecting data crossing (netlib and tcp) packet boundaries.  I
 *   think I have one, but ran out of time to do it.
 * . It will only work on little endian platforms.  Or rather I should say,
 *   the client that was captured must be little endian.  TDS 7.0/8.0 is
 *   always LE; for TDS 4.2/5.0 look in the code for tvb_get_le*() functions,
 *   there are fields in the login packet which determine byte order.
 * . result sets that span netlib packets are not working
 * . TDS 7 and 4.2 result sets are not working yet
 *
 * All that said, the code does deal gracefully with different boundary
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

#include "config.h"


#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/show_exception.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-tcp.h"

#define TDS_QUERY_PKT        1 /* SQLBatch in MS-TDS revision 18.0 */
#define TDS_LOGIN_PKT        2
#define TDS_RPC_PKT          3
#define TDS_RESP_PKT         4
#define TDS_RAW_PKT          5
#define TDS_ATTENTION_PKT    6
#define TDS_BULK_DATA_PKT    7 /* Bulk Load BCP in MS-TDS revision 18.0 */
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
#define TDS_TLS_PKT         23

#define is_valid_tds_type(x) (((x) >= TDS_QUERY_PKT && (x) < TDS_INVALID_PKT) || x == TDS_TLS_PKT)

/* The following constants are imported more or less directly from FreeTDS */
/*      Updated from FreeTDS v0.63 tds.h                                   */
/*         "$Id: tds.h,v 1.192 2004/10/28 12:42:12 freddy77]"              */
/* Note: [###] below means 'not defined in FreeTDS tds.h'                  */

#define TDS_TVPROW_TOKEN           1   /* 0x01 */
#define TDS5_PARAMFMT2_TOKEN       32  /* 0x20    TDS 5.0 only              */
#define TDS_LANG_TOKEN             33  /* 0x21    TDS 5.0 only              */
#define TDS5_ORDERBY2_TOKEN        34  /* 0x22    TDS 5.0 only              */
#define TDS5_CURDECLARE2_TOKEN     35  /* 0x23    TDS 5.0 only        [###] */
#define TDS5_ROWFMT2_TOKEN         97  /* 0x61    TDS 5.0 only              */
#define TDS5_MSG_TOKEN            101  /* 0x65    TDS 5.0 only        [###] */
#define TDS_LOGOUT_TOKEN          113  /* 0x71    TDS 5.0 only? ct_close()  */
#define TDS_OFFSET_TOKEN          120  /* 0x78    Removed in TDS 7.2        */
#define TDS_RET_STAT_TOKEN        121  /* 0x79                              */
#define TDS_PROCID_TOKEN          124  /* 0x7C    TDS 4.2 only - TDS_PROCID */
#define TDS_CURCLOSE_TOKEN        128  /* 0x80    TDS 5.0 only              */
#define TDS7_COL_METADATA_TOKEN   129  /* 0x81                              */
#define TDS_CURFETCH_TOKEN        130  /* 0x82    TDS 5.0 only              */
#define TDS_CURINFO_TOKEN         131  /* 0x83    TDS 5.0 only              */
#define TDS_CUROPEN_TOKEN         132  /* 0x84    TDS 5.0 only              */
#define TDS_CURDECLARE_TOKEN      134  /* 0x86    TDS 5.0 only              */
#define TDS7_ALTMETADATA_TOKEN    136  /* 0x88                              */
#define TDS_COL_NAME_TOKEN        160  /* 0xA0    TDS 4.2 only              */
#define TDS_COL_INFO_TOKEN        161  /* 0xA1    TDS 4.2 only - TDS_COLFMT */
#define TDS5_DYNAMIC2_TOKEN       163  /* 0xA3    TDS 5.0 only              */
#define TDS_TABNAME_TOKEN         164  /* 0xA4                              */
#define TDS7_COL_INFO_TOKEN       165  /* 0xA5                              */
#define TDS_OPTIONCMD_TOKEN       166  /* 0xA6 */
#define TDS_COMPUTE_NAMES_TOKEN   167  /* 0xA7 */
#define TDS_COMPUTE_RESULT_TOKEN  168  /* 0xA8 */
#define TDS_ORDER_TOKEN           169  /* 0xA9    TDS_ORDER                 */
#define TDS_ERR_TOKEN             170  /* 0xAA                              */
#define TDS_INFO_TOKEN            171  /* 0xAB                              */
#define TDS_RETURNVAL_TOKEN       172  /* 0xAC                              */
#define TDS_LOGIN_ACK_TOKEN       173  /* 0xAD                              */
#define TDS_FEATUREEXTACK_TOKEN   174  /* 0xAE    Introduced TDS 7.4        */
#define TDS_KEY_TOKEN             202  /* 0xCA                        [###] */
#define TDS_ROW_TOKEN             209  /* 0xD1                              */
#define TDS_NBCROW_TOKEN          210  /* 0xD2    Introduced TDS 7.3        */
#define TDS_ALTROW_TOKEN          211  /* 0xD3                              */
#define TDS5_PARAMS_TOKEN         215  /* 0xD7    TDS 5.0 only              */
#define TDS_CAP_TOKEN             226  /* 0xE2                              */
#define TDS_ENVCHG_TOKEN          227  /* 0xE3                              */
#define TDS_SESSIONSTATE_TOKEN    228  /* 0xE4    Introduced TDS 7.4        */
#define TDS_EED_TOKEN             229  /* 0xE5                              */
#define TDS_DBRPC_TOKEN           230  /* 0xE6                              */
#define TDS5_DYNAMIC_TOKEN        231  /* 0xE7    TDS 5.0 only              */
#define TDS5_PARAMFMT_TOKEN       236  /* 0xEC    TDS 5.0 only              */
#define TDS_AUTH_TOKEN            237  /* 0xED                              */  /* DUPLICATE! */
#define TDS_SSPI_TOKEN            237  /* 0xED                              */  /* DUPLICATE! */
#define TDS_RESULT_TOKEN          238  /* 0xEE                              */  /* DUPLICATE! */
#define TDS_FEDAUTHINFO_TOKEN     238  /* 0xEE    Introduced TDS 7.4        */  /* DUPLICATE! */
#define TDS_DONE_TOKEN            253  /* 0xFD                              */
#define TDS_DONEPROC_TOKEN        254  /* 0xFE                              */
#define TDS_DONEINPROC_TOKEN      255  /* 0xFF                              */

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

/* FIXEDLENTYPE */
#define TDS_DATA_TYPE_NULL            0x1F  /* 31 = Null (no data associated with this type) */
#define TDS_DATA_TYPE_INT1            0x30  /* 48 = TinyInt (1 byte data representation) */
#define TDS_DATA_TYPE_BIT             0x32  /* 50 = Bit (1 byte data representation) */
#define TDS_DATA_TYPE_INT2            0x34  /* 52 = SmallInt (2 byte data representation) */
#define TDS_DATA_TYPE_INT4            0x38  /* 56 = Int (4 byte data representation) */
#define TDS_DATA_TYPE_DATETIME4       0x3A  /* 58 = SmallDateTime (4 byte data representation) */
#define TDS_DATA_TYPE_FLT4            0x3B  /* 59 = Real (4 byte data representation) */
#define TDS_DATA_TYPE_MONEY           0x3C  /* 60 = Money (8 byte data representation) */
#define TDS_DATA_TYPE_DATETIME        0x3D  /* 61 = DateTime (8 byte data representation) */
#define TDS_DATA_TYPE_FLT8            0x3E  /* 62 = Float (8 byte data representation) */
#define TDS_DATA_TYPE_MONEY4          0x7A  /* 122 = SmallMoney (4 byte data representation) */
#define TDS_DATA_TYPE_INT8            0x7F  /* 127 = BigInt (8 byte data representation) */
/* BYTELEN_TYPE */
#define TDS_DATA_TYPE_GUID            0x24  /* 36 = UniqueIdentifier */
#define TDS_DATA_TYPE_INTN            0x26  /* 38 */
#define TDS_DATA_TYPE_DECIMAL         0x37  /* 55 = Decimal (legacy support) */
#define TDS_DATA_TYPE_NUMERIC         0x3F  /* 63 = Numeric (legacy support) */
#define TDS_DATA_TYPE_BITN            0x68  /* 104 */
#define TDS_DATA_TYPE_DECIMALN        0x6A  /* 106 = Decimal */
#define TDS_DATA_TYPE_NUMERICN        0x6C  /* 108 = Numeric */
#define TDS_DATA_TYPE_FLTN            0x6D  /* 109 */
#define TDS_DATA_TYPE_MONEYN          0x6E  /* 110 */
#define TDS_DATA_TYPE_DATETIMN        0x6F  /* 111 */
#define TDS_DATA_TYPE_DATEN           0x28  /* 40 (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_TIMEN           0x29  /* 41 (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_DATETIME2N      0x2A  /* 42 (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_DATETIMEOFFSETN 0x2B  /* 43 (introduced in TDS 7.3) */
#define TDS_DATA_TYPE_CHAR            0x2F  /* 47 = Char (legacy support) */
#define TDS_DATA_TYPE_VARCHAR         0x27  /* 39 = VarChar (legacy support) */
#define TDS_DATA_TYPE_BINARY          0x2D  /* 45 = Binary (legacy support) */
#define TDS_DATA_TYPE_VARBINARY       0x25  /* 37 = VarBinary (legacy support) */
/* USHORTLEN_TYPE */
#define TDS_DATA_TYPE_BIGVARBIN       0xA5  /* 165 = VarBinary */
#define TDS_DATA_TYPE_BIGVARCHR       0xA7  /* 167 = VarChar */
#define TDS_DATA_TYPE_BIGBINARY       0xAD  /* 173 = Binary */
#define TDS_DATA_TYPE_BIGCHAR         0xAF  /* 175 = Char */
#define TDS_DATA_TYPE_NVARCHAR        0xE7  /* 231 = NVarChar */
#define TDS_DATA_TYPE_NCHAR           0xEF  /* 239 = NChar */
/* LONGLEN_TYPE */
#define TDS_DATA_TYPE_XML             0xF1  /* 241 = XML (introduced in TDS 7.2) */
#define TDS_DATA_TYPE_UDT             0xF0  /* 240 = CLR-UDT (introduced in TDS 7.2) */
#define TDS_DATA_TYPE_TEXT            0x23  /* 35 = Text */
#define TDS_DATA_TYPE_IMAGE           0x22  /* 34 = Image */
#define TDS_DATA_TYPE_NTEXT           0x63  /* 99 = NText */
#define TDS_DATA_TYPE_SSVARIANT       0x62  /* 98 = Sql_Variant (introduced in TDS 7.2) */
/* no official data type, used only as error indication */
#define TDS_DATA_TYPE_INVALID         G_MAXUINT8

#define is_fixedlen_type_sybase(x) (x==SYBINT1      ||            \
                                    x==SYBINT2      ||            \
                                    x==SYBINT4      ||            \
                                    x==SYBINT8      ||            \
                                    x==SYBREAL      ||            \
                                    x==SYBFLT8      ||            \
                                    x==SYBDATETIME  ||            \
                                    x==SYBDATETIME4 ||            \
                                    x==SYBBIT       ||            \
                                    x==SYBMONEY     ||            \
                                    x==SYBMONEY4    ||            \
                                    x==SYBUNIQUE                  \
                                   )

#define is_fixedlen_type_tds(x)    (x==TDS_DATA_TYPE_NULL ||      \
                                    x==TDS_DATA_TYPE_INT1 ||      \
                                    x==TDS_DATA_TYPE_BIT  ||      \
                                    x==TDS_DATA_TYPE_INT2 ||      \
                                    x==TDS_DATA_TYPE_INT4 ||      \
                                    x==TDS_DATA_TYPE_DATETIME4 || \
                                    x==TDS_DATA_TYPE_FLT4 ||      \
                                    x==TDS_DATA_TYPE_MONEY ||     \
                                    x==TDS_DATA_TYPE_DATETIME ||  \
                                    x==TDS_DATA_TYPE_FLT8 ||      \
                                    x==TDS_DATA_TYPE_MONEY4 ||    \
                                    x==TDS_DATA_TYPE_INT8         \
                                   )

#define is_varlen_type_tds(x)     (x==TDS_DATA_TYPE_GUID            ||  \
                                   x==TDS_DATA_TYPE_INTN            ||  \
                                   x==TDS_DATA_TYPE_DECIMAL         ||  \
                                   x==TDS_DATA_TYPE_NUMERIC         ||  \
                                   x==TDS_DATA_TYPE_BITN            ||  \
                                   x==TDS_DATA_TYPE_DECIMALN        ||  \
                                   x==TDS_DATA_TYPE_NUMERICN        ||  \
                                   x==TDS_DATA_TYPE_FLTN            ||  \
                                   x==TDS_DATA_TYPE_MONEYN          ||  \
                                   x==TDS_DATA_TYPE_DATETIMN        ||  \
                                   x==TDS_DATA_TYPE_DATEN           ||  \
                                   x==TDS_DATA_TYPE_TIMEN           ||  \
                                   x==TDS_DATA_TYPE_DATETIME2N      ||  \
                                   x==TDS_DATA_TYPE_DATETIMEOFFSETN ||  \
                                   x==TDS_DATA_TYPE_CHAR            ||  \
                                   x==TDS_DATA_TYPE_VARCHAR         ||  \
                                   x==TDS_DATA_TYPE_BINARY          ||  \
                                   x==TDS_DATA_TYPE_VARBINARY       ||  \
                                   x==TDS_DATA_TYPE_BIGVARBIN       ||  \
                                   x==TDS_DATA_TYPE_BIGVARCHR       ||  \
                                   x==TDS_DATA_TYPE_BIGBINARY       ||  \
                                   x==TDS_DATA_TYPE_BIGCHAR         ||  \
                                   x==TDS_DATA_TYPE_NVARCHAR        ||  \
                                   x==TDS_DATA_TYPE_NCHAR           ||  \
                                   x==TDS_DATA_TYPE_XML             ||  \
                                   x==TDS_DATA_TYPE_UDT             ||  \
                                   x==TDS_DATA_TYPE_TEXT            ||  \
                                   x==TDS_DATA_TYPE_IMAGE           ||  \
                                   x==TDS_DATA_TYPE_NTEXT           ||  \
                                   x==TDS_DATA_TYPE_SSVARIANT           \
                                  )

#define TDS_GEN_NULL        0x00U
#define TDS_CHARBIN_NULL    0xFFFFU
#define TDS_CHARBIN_NULL32  0xFFFFFFFFU

#define TDS_PLP_TERMINATOR  G_GUINT64_CONSTANT(0x0000000000000000)
#define TDS_UNKNOWN_PLP_LEN G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFE)
#define TDS_PLP_NULL        G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)

static const value_string tds_data_type_names[] = {
    /* FIXEDLENTYPE */
    {TDS_DATA_TYPE_NULL,            "NULLTYPE - Null (no data associated with this type)"},
    {TDS_DATA_TYPE_INT1,            "INT1TYPE - TinyInt (1 byte data representation)"},
    {TDS_DATA_TYPE_BIT,             "BITTYPE - Bit (1 byte data representation)"},
    {TDS_DATA_TYPE_INT2,            "INT2TYPE - SmallInt (2 byte data representation)"},
    {TDS_DATA_TYPE_INT4,            "INT4TYPE - Int (4 byte data representation)"},
    {TDS_DATA_TYPE_DATETIME4,       "DATETIME4TYPE - SmallDateTime (4 byte data representation)"},
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

void proto_reg_handoff_tds(void);
void proto_register_tds(void);

/************************ Message definitions ***********************/

/* Bulk Load BCP stream */

/* Bulk Load Update Text/Write Text */

/* Federated Authentication Token */

/* LOGIN7 Token */
static int hf_tds7login_total_size = -1;
static int hf_tds7login_version = -1;
static int hf_tds7login_packet_size = -1;
static int hf_tds7login_client_version = -1;
static int hf_tds7login_client_pid = -1;
static int hf_tds7login_connection_id = -1;
static int hf_tds7login_option_flags1 = -1;
static int hf_tds7login_option_flags2 = -1;
static int hf_tds7login_sql_type_flags = -1;
static int hf_tds7login_reserved_flags = -1;
static int hf_tds7login_time_zone = -1;
static int hf_tds7login_collation = -1;
static int hf_tds7login_offset = -1;
static int hf_tds7login_length = -1;
static int hf_tds7login_password = -1;
static int hf_tds7login_clientname = -1;
static int hf_tds7login_username = -1;
static int hf_tds7login_appname = -1;
static int hf_tds7login_servername = -1;
static int hf_tds7login_libraryname = -1;
static int hf_tds7login_locale = -1;
static int hf_tds7login_databasename = -1;

/* PRELOGIN stream */
static int hf_tds_prelogin = -1;
static int hf_tds_prelogin_option_token = -1;
static int hf_tds_prelogin_option_offset = -1;
static int hf_tds_prelogin_option_length = -1;
static int hf_tds_prelogin_option_version = -1;
static int hf_tds_prelogin_option_subbuild = -1;
static int hf_tds_prelogin_option_encryption = -1;
static int hf_tds_prelogin_option_instopt = -1;
static int hf_tds_prelogin_option_threadid = -1;
static int hf_tds_prelogin_option_mars = -1;
static int hf_tds_prelogin_option_traceid = -1;
static int hf_tds_prelogin_option_fedauthrequired = -1;
static int hf_tds_prelogin_option_nonceopt = -1;

/* RPC Request Stream */
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

/* SQLBatch Stream */
static int hf_tds_query = -1;

/* SSPI Message Stream */

/* Transaction Manager Request Stream */
static int hf_tds_transmgr = -1;
static int hf_tds_transmgr_payload = -1;

/************************ Token definitions ************************/

/* ALTMETADATA token */

/* ALTROW token */

/* COLINFO token (TDS_COL_INFO_TOKEN) */
static int hf_tds_colinfo = -1;

/* COLMETADATA token (TDS7_COL_METADATA_TOKEN) */
static int hf_tds_colmetadata = -1;
static int hf_tds_colmetadata_results_token_flags = -1;
static int hf_tds_colmetadata_columns = -1;
static int hf_tds_colmetadata_large_type_size = -1;
static int hf_tds_colmetadata_usertype32 = -1;
static int hf_tds_colmetadata_usertype16 = -1;
static int hf_tds_colmetadata_results_token_type = -1;
static int hf_tds_colmetadata_collate_codepage = -1;
static int hf_tds_colmetadata_collate_flags = -1;
static int hf_tds_colmetadata_collate_charset_id = -1;
static int hf_tds_colmetadata_colname = -1;
static int hf_tds_colmetadata_colname_length = -1;
static int hf_tds_colmetadata_table_name_parts = -1;
static int hf_tds_colmetadata_table_name = -1;
static int hf_tds_colmetadata_table_name_length = -1;
static int hf_tds_colmetadata_csize = -1;
static int hf_tds_colmetadata_precision = -1;
static int hf_tds_colmetadata_scale = -1;
static int hf_tds_colmetadata_field = -1;
static int hf_tds_colmetadata_flags_nullable = -1;
static int hf_tds_colmetadata_flags_updateable = -1;
static int hf_tds_colmetadata_flags_casesen = -1;
static int hf_tds_colmetadata_flags_identity = -1;
static int hf_tds_colmetadata_flags_computed = -1;
static int hf_tds_colmetadata_flags_reservedodbc = -1;
static int hf_tds_colmetadata_flags_sparsecolumnset = -1;
static int hf_tds_colmetadata_flags_encrypted = -1;
static int hf_tds_colmetadata_flags_fixedlenclrtype = -1;
static int hf_tds_colmetadata_flags_hidden = -1;
static int hf_tds_colmetadata_flags_key = -1;
static int hf_tds_colmetadata_flags_nullableunknown = -1;
static int hf_tds_colmetadata_maxbytesize = -1;
static int hf_tds_colmetadata_dbname_length = -1;
static int hf_tds_colmetadata_dbname = -1;
static int hf_tds_colmetadata_schemaname_length = -1;
static int hf_tds_colmetadata_schemaname = -1;
static int hf_tds_colmetadata_typename_length = -1;
static int hf_tds_colmetadata_typename = -1;
static int hf_tds_colmetadata_assemblyqualifiedname_length = -1;
static int hf_tds_colmetadata_assemblyqualifiedname = -1;
static int hf_tds_colmetadata_owningschema_length = -1;
static int hf_tds_colmetadata_owningschema = -1;
static int hf_tds_colmetadata_xmlschemacollection_length = -1;
static int hf_tds_colmetadata_xmlschemacollection = -1;

/* DONE token (TDS_DONE_TOKEN) */
static int hf_tds_done = -1;
static int hf_tds_done_curcmd = -1;
static int hf_tds_done_status = -1;
static int hf_tds_done_donerowcount_32 = -1;
static int hf_tds_done_donerowcount_64 = -1;

/* DONEPROC token (TDS_DONEPROC_TOKEN) */
static int hf_tds_doneproc = -1;
static int hf_tds_doneproc_curcmd = -1;
static int hf_tds_doneproc_status = -1;
static int hf_tds_doneproc_donerowcount_32 = -1;
static int hf_tds_doneproc_donerowcount_64 = -1;

/* DONEINPROC token () */
static int hf_tds_doneinproc = -1;
static int hf_tds_doneinproc_curcmd = -1;
static int hf_tds_doneinproc_status = -1;
static int hf_tds_doneinproc_donerowcount_32 = -1;
static int hf_tds_doneinproc_donerowcount_64 = -1;

/* ENVCHANGE token (TDS_ENVCHG_TOKEN) */
static int hf_tds_envchg = -1;
static int hf_tds_envchg_length = -1;
static int hf_tds_envchg_type = -1;
static int hf_tds_envchg_oldvalue_length = -1;
static int hf_tds_envchg_newvalue_length = -1;
static int hf_tds_envchg_oldvalue_string = -1;
static int hf_tds_envchg_newvalue_string = -1;
static int hf_tds_envchg_oldvalue_bytes = -1;
static int hf_tds_envchg_newvalue_bytes = -1;
static int hf_tds_envchg_collate_codepage = -1;
static int hf_tds_envchg_collate_flags = -1;
static int hf_tds_envchg_collate_charset_id = -1;

/* ERROR token (TDS_ERR_TOKEN) */
static int hf_tds_error = -1;
static int hf_tds_error_length = -1;
static int hf_tds_error_number = -1;
static int hf_tds_error_state = -1;
static int hf_tds_error_class = -1;
static int hf_tds_error_msgtext_length = -1;
static int hf_tds_error_msgtext = -1;
static int hf_tds_error_servername_length = -1;
static int hf_tds_error_servername = -1;
static int hf_tds_error_procname_length = -1;
static int hf_tds_error_procname = -1;
static int hf_tds_error_linenumber_32 = -1;
static int hf_tds_error_linenumber_16 = -1;

/* FEATUREEXTACK token (TDS_FEATUREEXTACK_TOKEN) */
static int hf_tds_featureextack = -1;
static int hf_tds_featureextack_feature = -1;
static int hf_tds_featureextack_featureid = -1;
static int hf_tds_featureextack_featureackdata = -1;
static int hf_tds_featureextack_featureackdatalen = -1;

/* FEDAUTHINFO token */

/* INFO token */
static int hf_tds_info = -1;
static int hf_tds_info_length = -1;
static int hf_tds_info_number = -1;
static int hf_tds_info_state = -1;
static int hf_tds_info_class = -1;
static int hf_tds_info_msgtext_length = -1;
static int hf_tds_info_msgtext = -1;
static int hf_tds_info_servername_length = -1;
static int hf_tds_info_servername = -1;
static int hf_tds_info_procname_length = -1;
static int hf_tds_info_procname = -1;
static int hf_tds_info_linenumber_32 = -1;
static int hf_tds_info_linenumber_16 = -1;

/* LOGINACK token (TDS_LOGIN_ACK_TOKEN) */
static int hf_tds_loginack = -1;
static int hf_tds_loginack_length = -1;
static int hf_tds_loginack_interface = -1;
static int hf_tds_loginack_tdsversion = -1;
static int hf_tds_loginack_progversion = -1;
static int hf_tds_loginack_progname = -1;

/* NBCROW token (TDS_NBCROW_TOKEN) */
static int hf_tds_nbcrow = -1;

/* OFFSET token */
static int hf_tds_offset = -1;
static int hf_tds_offset_id = -1;
static int hf_tds_offset_len = -1;

/* ORDER token (TDS_ORDER_TOKEN) */
static int hf_tds_order = -1;
static int hf_tds_order_length = -1;
static int hf_tds_order_colnum = -1;

/* RETURNSTATUS token (TDS_RET_STAT_TOKEN) */
static int hf_tds_returnstatus = -1;
static int hf_tds_returnstatus_value = -1;

/* RETURNVALUE token (TDS_RETURNVAL_TOKEN) */

/* ROW token (TDS_ROW_TOKEN) */
static int hf_tds_row = -1;
static int hf_tds_row_field = -1;

/* SESSIONSTATE token (TDS_SESSIONSTATE_TOKEN) */
static int hf_tds_sessionstate = -1;
static int hf_tds_sessionstate_length = -1;
static int hf_tds_sessionstate_seqno = -1;
static int hf_tds_sessionstate_status = -1;
static int hf_tds_sessionstate_stateid = -1;
static int hf_tds_sessionstate_statelen = -1;
static int hf_tds_sessionstate_statevalue = -1;

/* SSPI token */
static int hf_tds_sspi = -1;
static int hf_tds_sspi_buffer = -1;

/* TABNAME token */

/* TVPROW Token */

/* TDS5 Lang Token */
static int hf_tds_lang_language_text = -1;
static int hf_tds_lang_token_status = -1;

/* Unknown token */
static int hf_tds_unknown_tds_token = -1;

/*********************** Basic types *******************************/

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
static int hf_tds_type_varbyte_data_absdatetime = -1;
static int hf_tds_type_varbyte_data_reltime = -1;
static int hf_tds_type_varbyte_data_sign = -1;
static int hf_tds_type_varbyte_plp_len = -1;
static int hf_tds_type_varbyte_plp_chunk_len = -1;

/****************************** Top level TDS ******************************/

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
static int hf_tds_all_headers = -1;
static int hf_tds_all_headers_total_length = -1;
static int hf_tds_all_headers_header_length = -1;
static int hf_tds_all_headers_header_type = -1;
static int hf_tds_all_headers_trans_descr = -1;
static int hf_tds_all_headers_request_cnt = -1;
static int hf_tds_unknown_tds_packet = -1;
static int hf_tds_token_len = -1;

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
static gint ett_tds7_prelogin = -1;
static gint ett_tds7_login = -1;
static gint ett_tds7_hdr = -1;
static gint ett_tds_col = -1;
static gint ett_tds_flags = -1;
static gint ett_tds_prelogin_option = -1;
static gint ett_tds7_featureextack = -1;
static gint ett_tds7_featureextack_feature = -1;

/* static expert_field ei_tds_type_info_type_undecoded = EI_INIT; */
static expert_field ei_tds_invalid_length = EI_INIT;
static expert_field ei_tds_token_length_invalid = EI_INIT;
static expert_field ei_tds_type_info_type = EI_INIT;
static expert_field ei_tds_all_headers_header_type = EI_INIT;
/* static expert_field ei_tds_token_stats = EI_INIT; */
static expert_field ei_tds_invalid_plp_type = EI_INIT;

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
    /* Reassembled data field */
    NULL,
    "fragments"
};

/* Tables for reassembly of fragments. */
static reassembly_table tds_reassembly_table;

/* defragmentation of multi-buffer TDS PDUs */
static gboolean tds_defragment = TRUE;

static dissector_handle_t tds_tcp_handle;
static dissector_handle_t ntlmssp_handle;
static dissector_handle_t gssapi_handle;

typedef struct {
    gint tds7_version;
} tds_conv_info_t;

/* TDS protocol type preference */
/*   XXX: This preference is used as a 'hint' for cases where interpretation is ambiguous */
/*        Currently the hint is global                                                    */
/*   TODO: Consider storing protocol type with each conversation                          */
/*        (when type is determined and using the preference as a default) ??              */

#define TDS_PROTOCOL_NOT_SPECIFIED   0xFFFF
#define TDS_PROTOCOL_4      0x4000
#define TDS_PROTOCOL_5      0x5000
#define TDS_PROTOCOL_7_0    0x7000
#define TDS_PROTOCOL_7_1    0x7100
#define TDS_PROTOCOL_7_2    0x7200
#define TDS_PROTOCOL_7_3    0x7300
#define TDS_PROTOCOL_7_3A   0x730a
#define TDS_PROTOCOL_7_3B   0x730b
#define TDS_PROTOCOL_7_4    0x7400

static gint tds_protocol_type = TDS_PROTOCOL_NOT_SPECIFIED;

static const enum_val_t tds_protocol_type_options[] = {
    {"not_specified", "Not Specified", TDS_PROTOCOL_NOT_SPECIFIED},
    {"tds4", "TDS 4", TDS_PROTOCOL_4},  /* TDS 4.2 and TDS 4.6 */
    {"tds5", "TDS 5", TDS_PROTOCOL_5},
    {"tds70", "TDS 7.0", TDS_PROTOCOL_7_0},
    {"tds71", "TDS 7.1", TDS_PROTOCOL_7_1},
    {"tds72", "TDS 7.2", TDS_PROTOCOL_7_2},
    {"tds73", "TDS 7.3", TDS_PROTOCOL_7_3},
    {"tds73a", "TDS 7.3A", TDS_PROTOCOL_7_3A},
    {"tds73b", "TDS 7.3B", TDS_PROTOCOL_7_3B},
    {"tds74", "TDS 7.4", TDS_PROTOCOL_7_4},
    {NULL, NULL, -1}
};

#define TDS_PROTO_PREF_NOT_SPECIFIED (tds_protocol_type == TDS_PROTOCOL_NOT_SPECIFIED)
#define TDS_PROTO_PREF_TDS4 (tds_protocol_type == TDS_PROTOCOL_4)
#define TDS_PROTO_PREF_TDS5 (tds_protocol_type == TDS_PROTOCOL_5)
#define TDS_PROTO_PREF_TDS7_0 (tds_protocol_type == TDS_PROTOCOL_7_0)
#define TDS_PROTO_PREF_TDS7_1 (tds_protocol_type == TDS_PROTOCOL_7_1)
#define TDS_PROTO_PREF_TDS7_2 (tds_protocol_type == TDS_PROTOCOL_7_2)
#define TDS_PROTO_PREF_TDS7_3 (tds_protocol_type == TDS_PROTOCOL_7_3)
#define TDS_PROTO_PREF_TDS7_3A (tds_protocol_type == TDS_PROTOCOL_7_3A)
#define TDS_PROTO_PREF_TDS7_3B (tds_protocol_type == TDS_PROTOCOL_7_3B)
#define TDS_PROTO_PREF_TDS7_4 (tds_protocol_type == TDS_PROTOCOL_7_4)
#define TDS_PROTO_PREF_TDS7 (tds_protocol_type >= TDS_PROTOCOL_7_0 && tds_protocol_type <= TDS_PROTOCOL_7_4)

#define TDS_PROTO_TDS4 TDS_PROTO_PREF_TDS4
#define TDS_PROTO_TDS7 (TDS_PROTO_PREF_TDS7 || \
                        (TDS_PROTO_PREF_NOT_SPECIFIED && (tds_info->tds7_version != TDS_PROTOCOL_NOT_SPECIFIED)))
#define TDS_PROTO_TDS7_1_OR_LESS ((tds_protocol_type <= TDS_PROTOCOL_7_1) || \
                                     (TDS_PROTO_PREF_NOT_SPECIFIED && (tds_info->tds7_version <= TDS_PROTOCOL_7_1)))
#define TDS_PROTO_TDS7_2_OR_GREATER ((tds_protocol_type >= TDS_PROTOCOL_7_2) || \
                                     (TDS_PROTO_PREF_NOT_SPECIFIED && (tds_info->tds7_version >= TDS_PROTOCOL_7_2)))
#define TDS_PROTO_TDS7_3A_OR_LESS ((tds_protocol_type <= TDS_PROTOCOL_7_3A) || \
                                     (TDS_PROTO_PREF_NOT_SPECIFIED && (tds_info->tds7_version <= TDS_PROTOCOL_7_3A)))
#define TDS_PROTO_TDS7_3B_OR_GREATER ((tds_protocol_type >= TDS_PROTOCOL_7_3B) || \
                                     (TDS_PROTO_PREF_NOT_SPECIFIED && (tds_info->tds7_version >= TDS_PROTOCOL_7_3B)))
#define TDS_PROTO_TDS7_4_OR_GREATER ((tds_protocol_type >= TDS_PROTOCOL_7_4) || \
                                     (TDS_PROTO_PREF_NOT_SPECIFIED && (tds_info->tds7_version >= TDS_PROTOCOL_7_4)))

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
    {TDS_QUERY_PKT,       "SQL batch"},
    {TDS_LOGIN_PKT,       "Pre-TDS7 login"},
    {TDS_RPC_PKT,         "Remote Procedure Call"},
    {TDS_RESP_PKT,        "Response"},
    {TDS_RAW_PKT,         "Unused"},
    {TDS_ATTENTION_PKT,   "Attention"},
    {TDS_BULK_DATA_PKT,   "Bulk load data"},
    {TDS_OPEN_CHN_PKT,    "Unused"},
    {TDS_CLOSE_CHN_PKT,   "Unused"},
    {TDS_RES_ERROR_PKT,   "Unused"},
    {TDS_LOG_CHN_ACK_PKT, "Unused"},
    {TDS_ECHO_PKT,        "Unused"},
    {TDS_LOGOUT_CHN_PKT,  "Unused"},
    {TDS_TRANS_MGR_PKT,   "Transaction Manager Request"},
    {TDS_QUERY5_PKT,      "TDS5 query"},
    {TDS_LOGIN7_PKT,      "TDS7 login"},
    {TDS_SSPI_PKT,        "SSPI message"},
    {TDS_PRELOGIN_PKT,    "TDS7 pre-login message"},
    {TDS_TLS_PKT,         "TLS exchange"},
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
    {TDS_COL_NAME_TOKEN,        "Column Names"},
    {TDS_COL_INFO_TOKEN,        "Column Info"},
    {TDS_COMPUTE_NAMES_TOKEN,   "Compute Names"},
    {TDS_COMPUTE_RESULT_TOKEN,  "Compute Results"},
    {TDS_ORDER_TOKEN,           "Order"},
    {TDS_ERR_TOKEN,             "Error Message"},
    {TDS_INFO_TOKEN,            "Info Message"},
    {TDS_LOGIN_ACK_TOKEN,       "Login Acknowledgement"},
    {TDS_KEY_TOKEN,             "TDS Key"},
    {TDS_ROW_TOKEN,             "Row"},
    {TDS_CAP_TOKEN,             "Capabilities"},
    {TDS_ENVCHG_TOKEN,         "Environment Change"},
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
    {TDS_OFFSET_TOKEN,          "Offset"},
    {TDS_CURCLOSE_TOKEN,        "CurClose"},
    {TDS7_COL_METADATA_TOKEN,   "Column Metadata"},
    {TDS_CURFETCH_TOKEN,        "CurFetch"},
    {TDS_CURINFO_TOKEN,         "CurInfo"},
    {TDS_CUROPEN_TOKEN,         "CurOpen"},
    {TDS_CURDECLARE_TOKEN,      "CurDeclare"},
    {TDS7_ALTMETADATA_TOKEN,    "AltMetaData"},
    {TDS_TABNAME_TOKEN,         "Table Name"},
    {TDS7_COL_INFO_TOKEN,       "Column Info"},
    {TDS_OPTIONCMD_TOKEN,       "OptionCmd"},
    {TDS_RETURNVAL_TOKEN,       "Return Value"},
    {TDS_FEATUREEXTACK_TOKEN,   "FeatureExt Acknowledgement"},
    {TDS_NBCROW_TOKEN,          "Row (with Null Bitmap Compression)"},
    {TDS_ALTROW_TOKEN,          "ALTROW"},
    {TDS_SESSIONSTATE_TOKEN,    "Session State"},
    {TDS_DBRPC_TOKEN,           "DBRPC"},
    {TDS_SSPI_TOKEN,            "SSPI"},
    {TDS_FEDAUTHINFO_TOKEN,     "FEDAUTHINFO"},
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
    {0,                      NULL                }
};

static const value_string envchg_names[] = {
    {1, "Database"},
    {2, "Language"},
    {3, "Character set"},
    {4, "Packet size"},
    {5, "Unicode data sorting local id"},
    {6, "Unicode data sorting comparison flags"},
    {7, "SQL Collation"},
    {8, "Begin Transaction"},
    {9, "Commit Transaction"},
    {10, "Rollback Transaction"},
    {11, "Enlist DTC Transaction"},
    {12, "Defect Transaction"},
    {13, "Real Time Log Shipping"},
    {15, "Promote Transaction"},
    {16, "Transaction Manager Address"},
    {17, "Transaction ended"},
    {18, "RESETCONNECTION/RESETCONNECTIONSKIPTRAN Completion Acknowledgement"},
    {19, "Sends back name of user instance started per login request"},
    {20, "Sends routing information to client"},
    {0, NULL}
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
    {0, NULL}
};

static const value_string prelogin_token_names[] = {
    {0, "Version"},
    {1, "Encryption"},
    {2, "InstOpt"},
    {3, "ThreadID"},
    {4, "MARS"},
    {5, "TraceID"},
    {6, "FedAuthRequired"},
    {7, "NonceOpt"},
    {255, "Terminator"},
    {0, NULL}
};

static const value_string featureextack_feature_names[] = {
    {0, "Reserved"},
    {1, "SessionRecovery"},
    {2, "FedAuth"},
    {255, "Terminator"},
    {0, NULL}
};

static const value_string transmgr_types[] = {
    {0, "TM_GET_DTC_ADDRESS"},
    {1, "TM_PROPAGATE_XACT"},
    {5, "TM_BEGIN_XACT"},
    {6, "TM_PROMOTE_XACT"},
    {7, "TM_COMMIT_XACT"},
    {8, "TM_ROLLBACK_XACT"},
    {9, "TM_SAVE_XACT"},
    {0, NULL}
};

static const value_string prelogin_encryption_options[] = {
    {0, "Encryption is available but off"},
    {1, "Encryption is available and on"},
    {2, "Encryption is not available"},
    {3, "Encryption is required"},
    {0, NULL}
};

#define TDS_MAX_COLUMNS 256

/*
 * This is where we store the column information to be used in decoding the
 * TDS_ROW_TOKEN tokens.
 */
struct _tds_col {
    gchar name[256];
    guint32 utype;
    guint8 ctype;
    guint8 precision;
    guint8 scale;
    guint csize;
};

struct _netlib_data {
    guint num_cols;
    struct _tds_col *columns[TDS_MAX_COLUMNS];
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

static int
tds_token_is_fixed_size(guint8 token)
{
    switch (token) {
        case TDS_DONE_TOKEN:
        case TDS_DONEPROC_TOKEN:
        case TDS_DONEINPROC_TOKEN:
        case TDS_RET_STAT_TOKEN:
        case TDS_PROCID_TOKEN:
        case TDS_LOGOUT_TOKEN:
        case TDS_OFFSET_TOKEN:
            return 1;
        default:
            return 0;
    }
}

static int
tds_get_fixed_token_size(guint8 token, tds_conv_info_t *tds_info)
{
    switch(token) {
        case TDS_DONE_TOKEN:
        case TDS_DONEPROC_TOKEN:
        case TDS_DONEINPROC_TOKEN:
            if (TDS_PROTO_TDS7_1_OR_LESS) {
                return 8;
            } else {
                return 12;
            }
        case TDS_PROCID_TOKEN:
            return 8;
        case TDS_RET_STAT_TOKEN:
            return 4;
        case TDS_LOGOUT_TOKEN:
            return 1;
        case TDS_OFFSET_TOKEN:
            return 4;
        default:
            return 0;
    }
}

static guint
tds_get_variable_token_size(tvbuff_t *tvb, gint offset, guint8 token,
                            guint *len_field_size_p, guint *len_field_val_p)
{
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    switch(token) {
        /* some tokens have a 4 byte length field */
        case TDS5_PARAMFMT2_TOKEN:
        case TDS_LANG_TOKEN:
        case TDS5_ORDERBY2_TOKEN:
        case TDS5_CURDECLARE2_TOKEN:
        case TDS5_ROWFMT2_TOKEN:
        case TDS5_DYNAMIC2_TOKEN:
        case TDS_SESSIONSTATE_TOKEN:
            *len_field_size_p = 4;
            *len_field_val_p = tvb_get_guint32(tvb, offset, encoding);
            break;
            /* some have a 1 byte length field */
        case TDS5_MSG_TOKEN:
            *len_field_size_p = 1;
            *len_field_val_p = tvb_get_guint8(tvb, offset);
            break;
            /* and most have a 2 byte length field */
        default:
            *len_field_size_p = 2;
            *len_field_val_p = tvb_get_guint16(tvb, offset, encoding);
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
    item = proto_tree_add_item(tree, hf_tds_all_headers, tvb, *offset, total_length, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_tds_all_headers);
    total_length_item = proto_tree_add_item(sub_tree, hf_tds_all_headers_total_length, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

    final_offset = *offset + total_length;
    *offset += 4;
    do {
        /* dissect a stream header */
        proto_tree *header_sub_tree = NULL;
        proto_item *header_item, *length_item = NULL, *type_item = NULL;
        guint32 header_length = 0;
        guint16 header_type;

        header_sub_tree = proto_tree_add_subtree(sub_tree, tvb, *offset, header_length, ett_tds_all_headers_header, &header_item, "Header");
        length_item = proto_tree_add_item_ret_uint(header_sub_tree, hf_tds_all_headers_header_length, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &header_length);
        proto_item_set_len(header_item, header_length);
        if(header_length == 0 ) {
            expert_add_info_format(pinfo, length_item, &ei_tds_invalid_length, "Empty header");
            break;
        }

        header_type = tvb_get_letohs(tvb, *offset + 4);
        type_item = proto_tree_add_item(header_sub_tree, hf_tds_all_headers_header_type, tvb, *offset + 4, 2, ENC_LITTLE_ENDIAN);

        switch(header_type) {
            case TDS_HEADER_QUERY_NOTIF:
                break;
            case TDS_HEADER_TRANS_DESCR:
                if(header_length != 18)
                    expert_add_info_format(pinfo, length_item, &ei_tds_invalid_length, "Length should equal 18");
                proto_tree_add_item(header_sub_tree, hf_tds_all_headers_trans_descr, tvb, *offset + 6, 8, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(header_sub_tree, hf_tds_all_headers_request_cnt, tvb, *offset + 14, 4, ENC_LITTLE_ENDIAN);
                break;
            default:
                expert_add_info(pinfo, type_item, &ei_tds_all_headers_header_type);
        }

        *offset += header_length;
    } while(*offset < final_offset);
    if(*offset != final_offset) {
        expert_add_info_format(pinfo, total_length_item, &ei_tds_invalid_length, "Sum of headers' lengths (%d) differs from total headers length (%d)", total_length + *offset - final_offset, total_length);
        return;
    }
}

static void
dissect_tds_query_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint offset, len;
    guint string_encoding = ENC_UTF_16|ENC_LITTLE_ENDIAN;
    proto_tree *query_tree;

    offset = 0;
    query_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_tds7_query, NULL, "TDS Query Packet");
    dissect_tds_all_headers(tvb, &offset, pinfo, query_tree);
    len = tvb_reported_length_remaining(tvb, offset);

    if (TDS_PROTO_TDS4 ||
        (!TDS_PROTO_TDS7 &&
         ((len < 2) || tvb_get_guint8(tvb, offset+1) != 0)))
        string_encoding = ENC_ASCII|ENC_NA;

    proto_tree_add_item(query_tree, hf_tds_query, tvb, offset, len, string_encoding);
    /* offset += len; */
}

static void
dissect_tds5_lang_token(tvbuff_t *tvb, guint offset, guint len, proto_tree *tree) {

    proto_tree_add_item(tree, hf_tds_lang_token_status, tvb, offset, 1, ENC_NA);
    offset += 1;
    len    -= 1;

    proto_tree_add_item(tree, hf_tds_lang_language_text, tvb, offset, len, ENC_ASCII|ENC_NA);
}

static void
dissect_tds_transmgr_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *request_tree;
    guint offset = 0, len;

    request_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_tds7_query, NULL, "Transaction Manager Request Packet");
    dissect_tds_all_headers(tvb, &offset, pinfo, request_tree);
    len = tvb_reported_length_remaining(tvb, offset);

    if(len >= 2)
    {
        proto_tree_add_item(request_tree, hf_tds_transmgr, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        if(len > 2)
        {
            proto_tree_add_item(request_tree, hf_tds_transmgr_payload, tvb, offset + 2, len - 2, ENC_NA);
        }
    }
}

static void
dissect_tds_query5_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint offset;
    guint pos;
    guint token_len_field_size = 2;
    guint token_len_field_val = 0;
    guint8 token;
    guint token_sz;
    proto_tree *query_tree;
    proto_tree *token_tree;
    proto_item *token_item;

    offset = 0;
    query_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_tds7_query, NULL, "TDS5 Query Packet");

    /*
     * Until we reach the end of the packet, read tokens.
     */
    pos = offset;
    while (tvb_reported_length_remaining(tvb, pos) > 0) {

        /* our token */
        token = tvb_get_guint8(tvb, pos);
        if (tds_token_is_fixed_size(token))
            token_sz = tds_get_fixed_token_size(token, tds_info) + 1;
        else
            token_sz = tds_get_variable_token_size(tvb, pos+1, token, &token_len_field_size,
                                                   &token_len_field_val);

        token_tree = proto_tree_add_subtree_format(query_tree, tvb, pos, token_sz,
                                         ett_tds_token, &token_item, "Token 0x%02x %s", token,
                                         val_to_str_const(token, token_names, "Unknown Token Type"));

        if ((int) token_sz < 0) {
            expert_add_info_format(pinfo, token_item, &ei_tds_token_length_invalid, "Bogus token size: %u", token_sz);
            break;
        }

        /*
         * If it's a variable token, put the length field in here
         * instead of replicating this for each token subdissector.
         */
        if (!tds_token_is_fixed_size(token))
        {
            token_item = proto_tree_add_uint(token_tree, hf_tds_token_len, tvb, pos + 1, 1, token_len_field_val);
            proto_item_set_len(token_item, token_len_field_size);
        }

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

static int detect_tls(tvbuff_t *tvb)
{
    guint8 tls_type, tls_maj_ver, tls_min_ver;
    gint offset = 0, tls_len;

    tls_type = tvb_get_guint8(tvb, offset);
    tls_maj_ver = tvb_get_guint8(tvb, offset + 1);
    tls_min_ver = tvb_get_guint8(tvb, offset + 2);
    tls_len = tvb_get_ntohs(tvb, offset + 3);

    if( (tls_type >= 0x14) && (tls_type <= 0x18) &&
        (tls_maj_ver == 3) && (tls_min_ver <= 3) &&
        ((tls_len + 5 <= tvb_reported_length_remaining(tvb, offset)))
      )
    {
        return 1;
    }

    return 0;
}

static void
dissect_tds7_prelogin_packet(tvbuff_t *tvb, proto_tree *tree)
{
    guint8 token;
    gint offset = 0;
    guint16 tokenoffset, tokenlen;
    proto_tree *prelogin_tree = NULL, *option_tree;
    proto_item *item;

    item = proto_tree_add_item(tree, hf_tds_prelogin, tvb, 0, -1, ENC_NA);

    if(detect_tls(tvb))
    {
        proto_item_append_text(item, " - TLS exchange");
        return;
    }

    prelogin_tree = proto_item_add_subtree(item, ett_tds_message);
    while(tvb_reported_length_remaining(tvb, offset) > 0)
    {
        token = tvb_get_guint8(tvb, offset);
        option_tree = proto_tree_add_subtree(prelogin_tree, tvb, offset, token == 0xff ? 1 : 5, ett_tds_prelogin_option, NULL, "Option");
        proto_tree_add_item(option_tree, hf_tds_prelogin_option_token, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        if(token == 0xff)
            break;

        tokenoffset = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(option_tree, hf_tds_prelogin_option_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        tokenlen = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(option_tree, hf_tds_prelogin_option_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if(tokenlen != 0)
        {
            switch(token)
            {
                case 0: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_version, tvb, tokenoffset, 4, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_subbuild, tvb, tokenoffset + 4, 2, ENC_LITTLE_ENDIAN);
                    break;
                }
                case 1: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_encryption, tvb, tokenoffset, 1, ENC_LITTLE_ENDIAN);
                    break;
                }
                case 2: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_instopt, tvb, tokenoffset, tokenlen, ENC_ASCII | ENC_NA);
                    break;
                }
                case 3: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_threadid, tvb, tokenoffset, 4, ENC_BIG_ENDIAN);
                    break;
                }
                case 4: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_mars, tvb, tokenoffset, 1, ENC_LITTLE_ENDIAN);
                    break;
                }
                case 5: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_traceid, tvb, tokenoffset, tokenlen, ENC_NA);
                    break;
                }
                case 6: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_fedauthrequired, tvb, tokenoffset, 1, ENC_LITTLE_ENDIAN);
                    break;
                }
                case 7: {
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_nonceopt, tvb, tokenoffset, tokenlen, ENC_NA);
                    break;
                }
            }
        }
    }
}

static void
dissect_tds7_login(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset, i, j, k, offset2, len, login_hf = 0;
    char *val, *val2;

    proto_tree *login_tree;
    proto_tree *header_tree;
    proto_tree *length_tree;

    struct tds7_login_packet_hdr td7hdr;
    gint length_remaining;

    /* create display subtree for the protocol */
    offset = 0;
    login_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_tds7_login, NULL, "TDS7 Login Packet");
    header_tree = proto_tree_add_subtree(login_tree, tvb, offset, 36, ett_tds7_hdr, NULL, "Login Packet Header");

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_total_size, tvb, offset, sizeof(td7hdr.total_packet_size), ENC_LITTLE_ENDIAN, &(td7hdr.total_packet_size));
    offset += (int)sizeof(td7hdr.total_packet_size);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_version, tvb, offset, sizeof(td7hdr.tds_version), ENC_LITTLE_ENDIAN, &(td7hdr.tds_version));
    offset += (int)sizeof(td7hdr.tds_version);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_packet_size, tvb, offset, sizeof(td7hdr.packet_size), ENC_LITTLE_ENDIAN, &(td7hdr.packet_size));
    offset += (int)sizeof(td7hdr.packet_size);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_client_version, tvb, offset, sizeof(td7hdr.client_version), ENC_LITTLE_ENDIAN, &(td7hdr.client_version));
    offset += (int)sizeof(td7hdr.client_version);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_client_pid, tvb, offset, sizeof(td7hdr.client_pid), ENC_LITTLE_ENDIAN, &(td7hdr.client_pid));
    offset += (int)sizeof(td7hdr.client_pid);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_connection_id, tvb, offset, sizeof(td7hdr.connection_id), ENC_LITTLE_ENDIAN, &(td7hdr.connection_id));
    offset += (int)sizeof(td7hdr.connection_id);

    td7hdr.option_flags1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7login_option_flags1, tvb, offset, sizeof(td7hdr.option_flags1), td7hdr.option_flags1);
    offset += (int)sizeof(td7hdr.option_flags1);

    td7hdr.option_flags2 = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7login_option_flags2, tvb, offset, sizeof(td7hdr.option_flags2), td7hdr.option_flags2);
    offset += (int)sizeof(td7hdr.option_flags2);

    td7hdr.sql_type_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7login_sql_type_flags, tvb, offset, sizeof(td7hdr.sql_type_flags), td7hdr.sql_type_flags);
    offset += (int)sizeof(td7hdr.sql_type_flags);

    td7hdr.reserved_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(header_tree, hf_tds7login_reserved_flags, tvb, offset, sizeof(td7hdr.reserved_flags), td7hdr.reserved_flags);
    offset += (int)sizeof(td7hdr.reserved_flags);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_time_zone, tvb, offset, sizeof(td7hdr.time_zone), ENC_LITTLE_ENDIAN, &(td7hdr.time_zone));
    offset += (int)sizeof(td7hdr.time_zone);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_collation, tvb, offset, sizeof(td7hdr.collation), ENC_LITTLE_ENDIAN, &(td7hdr.collation));
    offset += (int)sizeof(td7hdr.collation);

    length_tree = proto_tree_add_subtree(login_tree, tvb, offset, 50, ett_tds7_hdr, NULL, "Lengths and offsets");

    for (i = 0; i < 9; i++) {
        offset2 = tvb_get_letohs(tvb, offset + i*4);
        len = tvb_get_letohs(tvb, offset + i*4 + 2);
        proto_tree_add_uint_format(length_tree, hf_tds7login_offset, tvb, offset + i*4, 2,
                            offset2, "%s offset: %u",
                            val_to_str_const(i, login_field_names, "Unknown"),
                            offset2);
        proto_tree_add_uint_format(length_tree, hf_tds7login_length, tvb, offset + i*4 + 2, 2,
                            len, "%s length: %u",
                            val_to_str_const(i, login_field_names, "Unknown"),
                            len);

        switch(i) {
            case 0:
                login_hf = hf_tds7login_clientname;
                break;
            case 1:
                login_hf = hf_tds7login_username;
                break;
            case 2:
                login_hf = hf_tds7login_password;
                break;
            case 3:
                login_hf = hf_tds7login_appname;
                break;
            case 4:
                login_hf = hf_tds7login_servername;
                break;
            case 6:
                login_hf = hf_tds7login_libraryname;
                break;
            case 7:
                login_hf = hf_tds7login_locale;
                break;
            case 8:
                login_hf = hf_tds7login_databasename;
                break;
        }

        if (len != 0) {
            if( i != 2) {
                /* tds 7 is always unicode */
                len *= 2;
                proto_tree_add_item(login_tree, login_hf, tvb, offset2, len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            } else {
                /* This field is the password.  We retrieve it from the packet
                 * as a non-unicode string and then perform two operations on it
                 * to "decrypt" it.  Finally, we create a new string that consists
                 * of ASCII characters instead of unicode by skipping every other
                 * byte in the original string.
                 */

                len *= 2;
                val = (gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset2, len, ENC_ASCII);
                val2 = (char *)wmem_alloc(wmem_packet_scope(), len/2+1);

                for(j = 0, k = 0; j < len; j += 2, k++) {
                    val[j] ^= 0xA5;

                    /* Swap the most and least significant bits */
                    val[j] = ((val[j] & 0x0F) << 4) | ((val[j] & 0xF0) >> 4);

                    val2[k] = val[j];
                }
                val2[k] = '\0'; /* Null terminate our new string */

                proto_tree_add_string_format_value(login_tree, login_hf, tvb, offset2, len, val2, "%s", val2);
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

static guint8 variant_propbytes(guint8 type)
{
    switch (type)
    {
    /* FIXEDLENTYPE */
    case TDS_DATA_TYPE_BIT: return 0;
    case TDS_DATA_TYPE_INT1: return 0;
    case TDS_DATA_TYPE_INT2: return 0;
    case TDS_DATA_TYPE_INT4: return 0;
    case TDS_DATA_TYPE_INT8: return 0;
    case TDS_DATA_TYPE_DATETIME: return 0;
    case TDS_DATA_TYPE_DATETIME4: return 0;
    case TDS_DATA_TYPE_FLT4: return 0;
    case TDS_DATA_TYPE_FLT8: return 0;
    case TDS_DATA_TYPE_MONEY: return 0;
    case TDS_DATA_TYPE_MONEY4: return 0;

    /* BYTELEN_TYPE */
    case TDS_DATA_TYPE_DATEN: return 0;
    case TDS_DATA_TYPE_GUID: return 0;
    case TDS_DATA_TYPE_TIMEN: return 1;
    case TDS_DATA_TYPE_DATETIME2N: return 1;
    case TDS_DATA_TYPE_DATETIMEOFFSETN: return 1;
    case TDS_DATA_TYPE_DECIMALN: return 2;
    case TDS_DATA_TYPE_NUMERICN: return 2;

    /* USHORTLEN_TYPE */
    case TDS_DATA_TYPE_BIGVARBIN: return 2;
    case TDS_DATA_TYPE_BIGVARCHR: return 7;
    case TDS_DATA_TYPE_BIGBINARY: return 2;
    case TDS_DATA_TYPE_BIGCHAR: return 7;
    case TDS_DATA_TYPE_NVARCHAR: return 7;
    case TDS_DATA_TYPE_NCHAR: return 7;

    default: return 0;
    }
}

static void
dissect_tds_type_varbyte(tvbuff_t *tvb, guint *offset, packet_info *pinfo, proto_tree *tree, int hf, guint8 data_type, guint8 scale, gboolean plp, gint fieldnum)
{
    guint32 length;
    proto_tree *sub_tree = NULL;
    proto_item *item = NULL, *length_item = NULL;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    item = proto_tree_add_item(tree, hf, tvb, *offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_tds_type_varbyte);

    if(fieldnum != -1)
        proto_item_append_text(item, " %i", fieldnum);

    proto_item_append_text(item, " (%s)", val_to_str(data_type, tds_data_type_names, "Invalid data type: %02X"));

    if(plp) {
        guint64 plp_length = tvb_get_letoh64(tvb, *offset);
        length_item = proto_tree_add_item(sub_tree, hf_tds_type_varbyte_plp_len, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
        if(plp_length == TDS_PLP_NULL)
            proto_item_append_text(length_item, " (PLP_NULL)");
        else {
            if(plp_length == TDS_UNKNOWN_PLP_LEN)
                proto_item_append_text(length_item, " (UNKNOWN_PLP_LEN)");
            while(TRUE) {
                length_item = proto_tree_add_item_ret_uint(sub_tree, hf_tds_type_varbyte_plp_chunk_len, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &length);
                *offset += 4;
                if(length == TDS_PLP_TERMINATOR) {
                    proto_item_append_text(length_item, " (PLP_TERMINATOR)");
                    break;
                }
                switch(data_type) {
                    case TDS_DATA_TYPE_BIGVARBIN: /* VarBinary */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, ENC_NA);
                        break;
                    case TDS_DATA_TYPE_BIGVARCHR: /* VarChar */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, ENC_ASCII|ENC_NA);
                        break;
                    case TDS_DATA_TYPE_NVARCHAR:  /* NVarChar */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        break;
                    case TDS_DATA_TYPE_XML:       /* XML (introduced in TDS 7.2) */
                    case TDS_DATA_TYPE_UDT:       /* CLR-UDT (introduced in TDS 7.2) */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, ENC_NA);
                        break;
                    default:
                        /* no other data type sets plp = TRUE */
                        expert_add_info_format(pinfo, length_item, &ei_tds_invalid_plp_type, "This type should not use PLP");
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
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_boolean, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case TDS_DATA_TYPE_INT1:            /* TinyInt (1 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int1, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        case TDS_DATA_TYPE_INT2:            /* SmallInt (2 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int2, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;
        case TDS_DATA_TYPE_INT4:            /* Int (4 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int4, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
            break;
        case TDS_DATA_TYPE_INT8:            /* BigInt (8 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int8, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            *offset += 8;
            break;
        case TDS_DATA_TYPE_FLT4:            /* Real (4 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_float, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
            break;
        case TDS_DATA_TYPE_FLT8:            /* Float (8 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_double, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            *offset += 8;
            break;
        case TDS_DATA_TYPE_MONEY4:          /* SmallMoney (4 byte data representation) */
        case TDS_DATA_TYPE_DATETIME4:       /* SmallDateTime (4 byte data representation) */
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
                case TDS_GEN_NULL:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, ENC_NA);
                    break;
                case 16:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_guid, tvb, *offset + 1, length, ENC_LITTLE_ENDIAN);
                    break;
                default:
                    expert_add_info(pinfo, length_item, &ei_tds_invalid_length);
            }
            *offset += 1 + length;
            break;

        case TDS_DATA_TYPE_BITN:
            length = tvb_get_guint8(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            switch(length) {
                case TDS_GEN_NULL:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, ENC_NA);
                    break;
                case 1:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_boolean, tvb, *offset + 1, 1, ENC_LITTLE_ENDIAN);
                    break;
                default:
                    expert_add_info(pinfo, length_item, &ei_tds_invalid_length);
            }
            *offset += 1 + length;
            break;

        case TDS_DATA_TYPE_INTN:
            length = tvb_get_guint8(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            switch(length) {
                case TDS_GEN_NULL:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, ENC_NA);
                    break;
                case 1:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int1, tvb, *offset + 1, 1, ENC_LITTLE_ENDIAN);
                    break;
                case 2:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int2, tvb, *offset + 1, 2, ENC_LITTLE_ENDIAN);
                    break;
                case 4:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int4, tvb, *offset + 1, 4, ENC_LITTLE_ENDIAN);
                    break;
                case 8:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int8, tvb, *offset + 1, 8, ENC_LITTLE_ENDIAN);
                    break;
                default:
                    expert_add_info(pinfo, length_item, &ei_tds_invalid_length);
            }
            *offset += 1 + length;
            break;

        case TDS_DATA_TYPE_FLTN:
            length = tvb_get_guint8(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            switch(length) {
                case TDS_GEN_NULL:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, ENC_NA);
                    break;
                case 4:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_float, tvb, *offset + 1, 4, ENC_LITTLE_ENDIAN);
                    break;
                case 8:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_double, tvb, *offset + 1, 8, ENC_LITTLE_ENDIAN);
                    break;
                default:
                    expert_add_info(pinfo, length_item, &ei_tds_invalid_length);
            }
            *offset += 1 + length;
            break;

        case TDS_DATA_TYPE_MONEYN:
            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length > 0) {
                if(length == 4)
                {
                    gdouble dblvalue = (gfloat)tvb_get_guint32(tvb, *offset, encoding);
                    proto_tree_add_double_format_value(sub_tree, hf_tds_type_varbyte_data_double, tvb, *offset, 4, dblvalue, "%.4f", dblvalue/10000);
                }
                if(length == 8)
                {
                    gdouble dblvalue;
                    guint64 moneyval;

                    moneyval = tvb_get_guint32(tvb, *offset, encoding);
                    dblvalue = (gdouble)((moneyval << 32) + tvb_get_guint32(tvb, *offset + 4, encoding));
                    proto_tree_add_double_format_value(sub_tree, hf_tds_type_varbyte_data_double, tvb, *offset, 8, dblvalue, "%.4f", dblvalue/10000);
                }
                *offset += length;
            }
            break;

        case TDS_DATA_TYPE_DATEN:           /* (introduced in TDS 7.3) */
            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length == 3) {
                guint days = 0;
                nstime_t tv;

                days += tvb_get_guint8(tvb, *offset + 2) << 16;
                days += tvb_get_guint8(tvb, *offset + 1) << 8;
                days += tvb_get_guint8(tvb, *offset);

                tv.secs = (time_t)((days * G_GUINT64_CONSTANT(86400)) - G_GUINT64_CONSTANT(62135596800)); /* 62135596800 - seconds between Jan 1, 1 and Jan 1, 1970 */
                tv.nsecs = 0;
                proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_absdatetime, tvb, *offset, length, &tv);
            }
            *offset += length;
            break;

        case TDS_DATA_TYPE_TIMEN:           /* (introduced in TDS 7.3) */
            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length > 0) {

                int i;
                guint64 value = 0;
                gdouble dblvalue;
                nstime_t tv;

                for(i = length - 1; i > 0; i--)
                {
                    value = value + tvb_get_guint8(tvb, *offset + i);
                    value = value << 8;
                }
                value = value + tvb_get_guint8(tvb, *offset);

                dblvalue = (gdouble)value;
                for(i = 0; i < scale; i++)
                {
                    dblvalue = dblvalue / 10;
                }

                tv.secs = (time_t)dblvalue;
                tv.nsecs = (guint)(dblvalue - tv.secs) * 1000000000;
                proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_reltime, tvb, *offset, length, &tv);

                *offset += length;
            }
            break;

        case TDS_DATA_TYPE_DATETIMN:

            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length > 0) {
                if(length == 4)
                {
                    /* SQL smalldatetime */
                    nstime_t tv;
                    guint days = tvb_get_guint16(tvb, *offset, encoding);
                    guint minutes = tvb_get_guint16(tvb, *offset + 2, encoding);

                    tv.secs = (time_t)((days * G_GUINT64_CONSTANT(86400)) + (minutes * 60) - G_GUINT64_CONSTANT(2208988800)); /* 2208988800 - seconds between Jan 1, 1900 and Jan 1, 1970 */
                    tv.nsecs = 0;
                    proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_absdatetime, tvb, *offset, length, &tv);
                }
                if(length == 8)
                {
                    /* SQL datetime */
                    nstime_t tv;
                    guint days = tvb_get_guint32(tvb, *offset, encoding);
                    guint threehndths = tvb_get_guint32(tvb, *offset + 4, encoding);

                    tv.secs = (time_t)((days * G_GUINT64_CONSTANT(86400)) + (threehndths/300) - G_GUINT64_CONSTANT(2208988800)); /* 2208988800 - seconds between Jan 1, 1900 and Jan 1, 1970 */
                    tv.nsecs = (threehndths%300) * 10000000 / 3;
                    proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_absdatetime, tvb, *offset, length, &tv);
                }
                *offset += length;
            }
            break;

        case TDS_DATA_TYPE_DATETIME2N:      /* (introduced in TDS 7.3) */
            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length > 0) {

                int i, bytestoread = 0;
                guint64 value = 0;
                gdouble dblvalue;
                guint days = 0;
                guint64 secs;
                nstime_t tv;

                if(scale <= 2) bytestoread = 3;
                if((scale >= 3) && (scale <= 4)) bytestoread = 4;
                if((scale >= 5) && (scale <= 7)) bytestoread = 5;

                for(i = bytestoread - 1; i > 0; i--)
                {
                    value = value + tvb_get_guint8(tvb, *offset + i);
                    value = value << 8;
                }
                value = value + tvb_get_guint8(tvb, *offset);

                dblvalue = (gdouble)value;
                for(i = 0; i < scale; i++)
                {
                     dblvalue = dblvalue / 10;
                }

                days += tvb_get_guint8(tvb, *offset + bytestoread + 2) << 16;
                days += tvb_get_guint8(tvb, *offset + bytestoread + 1) << 8;
                days += tvb_get_guint8(tvb, *offset + bytestoread);

                secs = (days * G_GUINT64_CONSTANT(86400)) - G_GUINT64_CONSTANT(62135596800); /* 62135596800 - seconds between Jan 1, 1 and Jan 1, 1970 */

                value = (guint64)dblvalue;
                tv.secs = (time_t)(secs + value);
                dblvalue = dblvalue - value;
                tv.nsecs = (guint)dblvalue * 1000000000;
                proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_absdatetime, tvb, *offset, length, &tv);

                *offset += bytestoread + 3;
            }
            break;

        case TDS_DATA_TYPE_DATETIMEOFFSETN: /* (introduced in TDS 7.3) */
            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length > 0) {

                int i, bytestoread = 0;
                guint64 value = 0;
                gdouble dblvalue;
                guint days = 0;
                gshort timeoffset = 0;
                guint64 secs;
                nstime_t tv;
                proto_item *timeitem = NULL;

                if(scale <= 2) bytestoread = 3;
                if((scale >= 3) && (scale <= 4)) bytestoread = 4;
                if((scale >= 5) && (scale <= 7)) bytestoread = 5;

                for(i = bytestoread - 1; i > 0; i--)
                {
                    value = value + tvb_get_guint8(tvb, *offset + i);
                    value = value << 8;
                }
                value = value + tvb_get_guint8(tvb, *offset);

                dblvalue = (gdouble)value;
                for(i = 0; i < scale; i++)
                {
                    dblvalue = dblvalue / 10;
                }

                days += tvb_get_guint8(tvb, *offset + bytestoread + 2) << 16;
                days += tvb_get_guint8(tvb, *offset + bytestoread + 1) << 8;
                days += tvb_get_guint8(tvb, *offset + bytestoread);

                secs = (days * G_GUINT64_CONSTANT(86400)) - G_GUINT64_CONSTANT(62135596800); /* 62135596800 - seconds between Jan 1, 1 and Jan 1, 1970 */

                value = (guint64)dblvalue;
                tv.secs = (time_t)(secs + value);
                dblvalue = dblvalue - value;
                tv.nsecs = (guint)dblvalue * 1000000000;
                timeitem = proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_absdatetime, tvb, *offset, length, &tv);

                timeoffset = tvb_get_letohs(tvb, *offset + bytestoread + 3);

                /* TODO: Need to find a way to convey the time and the offset in a single item, rather than appending text */
                proto_item_append_text(timeitem, " %c%02i:%02i", timeoffset > 0 ? '+':'-', timeoffset / 60, timeoffset % 60);
                *offset += bytestoread + 5;
            }
            break;

        case TDS_DATA_TYPE_DECIMAL:         /* Decimal (legacy support) */
        case TDS_DATA_TYPE_NUMERIC:         /* Numeric (legacy support) */
        case TDS_DATA_TYPE_DECIMALN:        /* Decimal */
        case TDS_DATA_TYPE_NUMERICN:        /* Numeric */
        {
            proto_item *numericitem = NULL;

            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;

            if(length > 0) {

                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_sign, tvb, *offset, 1, ENC_NA);

                switch(length - 1)
                {
                    case 4:
                    {
                        numericitem = proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int4, tvb, *offset + 1, 4, ENC_LITTLE_ENDIAN);

                        if(scale != 0)
                            proto_item_append_text(numericitem, " x 10^%u", scale);
                        break;
                    }
                    case 8:
                    {
                        numericitem = proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int8, tvb, *offset + 1, 8, ENC_LITTLE_ENDIAN);

                        if(scale != 0)
                            proto_item_append_text(numericitem, " x 10^%u", scale);
                        break;
                    }
                    case 12:
                    case 16:
                    {
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset + 1, length, ENC_NA);
                        break;
                    }
                }
                *offset += length;
            }
            break;
        }
        case TDS_DATA_TYPE_CHAR:            /* Char (legacy support) */
        case TDS_DATA_TYPE_VARCHAR:         /* VarChar (legacy support) */
        case TDS_DATA_TYPE_BINARY:          /* Binary (legacy support) */
        case TDS_DATA_TYPE_VARBINARY:       /* VarBinary (legacy support) */
            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;
            if(length > 0) {
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, ENC_NA);
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
            if(length == TDS_CHARBIN_NULL) {
                proto_item_append_text(length_item, " (CHARBIN_NULL)");
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, ENC_NA);
            }
            else {
                switch(data_type) {
                    case TDS_DATA_TYPE_BIGVARBIN: /* VarBinary */
                    case TDS_DATA_TYPE_BIGBINARY: /* Binary */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, ENC_NA);
                        break;
                    case TDS_DATA_TYPE_BIGVARCHR: /* VarChar */
                    case TDS_DATA_TYPE_BIGCHAR:   /* Char */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, ENC_ASCII|ENC_NA);
                        break;
                    case TDS_DATA_TYPE_NVARCHAR:  /* NVarChar */
                    case TDS_DATA_TYPE_NCHAR:     /* NChar */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        break;
                }
                *offset += length;
            }
            break;

        /* LONGLEN_TYPE - types prefixed with 4-byte length */
        case TDS_DATA_TYPE_NTEXT:           /* NText */
        case TDS_DATA_TYPE_TEXT:            /* Text */
        case TDS_DATA_TYPE_IMAGE:           /* Image */
        case TDS_DATA_TYPE_XML:             /* XML (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_UDT:             /* CLR-UDT (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_SSVARIANT:       /* Sql_Variant (introduced in TDS 7.2) */
            length_item = proto_tree_add_item_ret_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &length);
            *offset += 4;
            if(length == TDS_CHARBIN_NULL32) {
                proto_item_append_text(length_item, " (CHARBIN_NULL)");
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, ENC_NA);
            }
            else {
                switch(data_type) {
                    case TDS_DATA_TYPE_NTEXT: /* NText */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        break;
                    case TDS_DATA_TYPE_TEXT:
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_string, tvb, *offset, length, ENC_ASCII|ENC_NA);
                        break;
                    default: /*TODO*/
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, ENC_NA);
                }
                *offset += length;
            }
            break;
    }
    proto_item_set_end(item, tvb, *offset);
}

static void
dissect_tds_type_info_minimal(guint8 data_type, guint size, gboolean *plp)
{
    *plp = FALSE; /* most types are not Partially Length-Prefixed */

    /* optional TYPE_VARLEN for variable length types */
    switch(data_type) {
        /* USHORTLEN_TYPE */
        case TDS_DATA_TYPE_BIGVARCHR:       /* VarChar */
        case TDS_DATA_TYPE_BIGVARBIN:       /* VarBinary */
        case TDS_DATA_TYPE_NVARCHAR:        /* NVarChar */
            /* A type with unlimited max size, known as varchar(max), varbinary(max) and nvarchar(max),
               which has a max size of 0xFFFF, defined by PARTLENTYPE. This class of types was introduced in TDS 7.2. */
            if(size == 0xFFFF)
                *plp = TRUE;
            break;
        /* LONGLEN_TYPE */
        case TDS_DATA_TYPE_XML:             /* XML (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_UDT:             /* CLR-UDT (introduced in TDS 7.2) */
            *plp = TRUE;
            break;
    }
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
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    next = offset + tvb_get_guint16(tvb, offset+1, encoding) + 3;
    cur = offset + 3;

    col = 0;
    while (cur < next) {

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = 0;
            return FALSE;
        }

        nl_data->columns[col] = wmem_new(wmem_packet_scope(), struct _tds_col);
        nl_data->columns[col]->name[0] ='\0';
        nl_data->columns[col]->utype = tvb_get_guint16(tvb, cur, encoding);
        cur += 2;

        cur += 2; /* unknown */

        nl_data->columns[col]->ctype = tvb_get_guint8(tvb,cur);
        cur++;

        if (!is_fixedlen_type_tds(nl_data->columns[col]->ctype)) {
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
read_results_tds5_token(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset)
{
    guint name_len;
    guint cur;
    guint i;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    cur = offset;

    /*
     * This would be the logical place to check for little/big endianess
     * if we didn't see the login packet.
     * XXX: We'll take a hint
     */
    nl_data->num_cols = tvb_get_guint16(tvb, cur, encoding);
    if (nl_data->num_cols > TDS_MAX_COLUMNS) {
        nl_data->num_cols = 0;
        return FALSE;
    }

    cur += 2;

    for (i = 0; i < nl_data->num_cols; i++) {
        nl_data->columns[i] = wmem_new(wmem_packet_scope(), struct _tds_col);
        name_len = tvb_get_guint8(tvb,cur);
        cur ++;
        cur += name_len;

        cur++; /* unknown */

        nl_data->columns[i]->utype = tvb_get_guint16(tvb, cur, encoding);
        cur += 2;

        cur += 2; /* unknown */

        nl_data->columns[i]->ctype = tvb_get_guint8(tvb,cur);
        cur++;

        if (!is_fixedlen_type_tds(nl_data->columns[i]->ctype)) {
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

    bytes_avail = tvb_captured_length(tvb) - offset;
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

static int
dissect_tds_prelogin_response(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint8 token = 0;
    gint tokenoffset, tokenlen, cur = offset, valid = 0;

    /* Test for prelogin format compliance */
    while(tvb_reported_length_remaining(tvb, cur) > 0)
    {
        token = tvb_get_guint8(tvb, cur);
        cur += 1;

           if((token <= 8) || (token == 0xff))
           {
               valid = 1;
           } else {
               valid = 0;
               break;
           }

        if(token == 0xff)
            break;

           tokenoffset = tvb_get_ntohs(tvb, cur);
           if(tokenoffset > tvb_captured_length_remaining(tvb, 0))
           {
               valid = 0;
               break;
           }
           cur += 2;

           tokenlen = tvb_get_ntohs(tvb, cur);
           if(tokenlen > tvb_captured_length_remaining(tvb, 0))
           {
               valid = 0;
               break;
           }
           cur += 2;
    }

    if(token != 0xff)
    {
        valid = 0;
    }


    if(valid)
    {
        dissect_tds7_prelogin_packet(tvb, tree);
    }

    return valid;
}

static int
dissect_tds_order_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint cur = offset;
    guint16 i, length;

    length = tvb_get_letohs(tvb, cur);
    proto_tree_add_item(tree, hf_tds_order_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;

    for (i = 0; i < length / 2; i++) {
        proto_tree_add_item(tree, hf_tds_order_colnum, tvb, cur, 2, ENC_LITTLE_ENDIAN);
        cur += 2;
    }

    return cur - offset;
}

static int
dissect_tds_offset_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint cur = offset;

    proto_tree_add_item(tree, hf_tds_offset_id, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_tds_offset_len, tvb, cur + 2, 2, ENC_LITTLE_ENDIAN);
    cur += 4;

    return cur - offset;
}

static int
dissect_tds_row_token(tvbuff_t *tvb, packet_info *pinfo, struct _netlib_data *nl_data, guint offset, proto_tree *tree)
{
    guint cur = offset, i, type;
    gboolean plp = FALSE;

    for (i = 0; i < nl_data->num_cols; i++) {
        type = nl_data->columns[i]->ctype;
        dissect_tds_type_info_minimal(type, nl_data->columns[i]->csize, &plp);

        if(nl_data->columns[i]->ctype == TDS_DATA_TYPE_NTEXT ||
            nl_data->columns[i]->ctype == TDS_DATA_TYPE_TEXT ||
            nl_data->columns[i]->ctype == TDS_DATA_TYPE_IMAGE)
        {
            /* TextPointer */
            cur += 1 + tvb_get_guint8(tvb, cur);

            /* Timestamp */
            cur += 8;
        }

        dissect_tds_type_varbyte(tvb, &cur, pinfo, tree, hf_tds_row_field, type, nl_data->columns[i]->scale, plp, i+1);
    }

    return cur - offset;
}

static int
dissect_tds_nbc_row_token(tvbuff_t *tvb, packet_info *pinfo, struct _netlib_data *nl_data, guint offset, proto_tree *tree)
{
    guint relbyte, relbit, i, cur;
    gboolean plp = FALSE;

    cur = offset + nl_data->num_cols/8;
    if((nl_data->num_cols%8) != 0) cur++;

    for (i = 0; i < nl_data->num_cols; i++) {

        relbyte = tvb_get_guint8(tvb, offset + i/8);
        relbit = relbyte & (1 << (i%8));

        if(relbit == 0)
        {
            dissect_tds_type_info_minimal(nl_data->columns[i]->ctype, nl_data->columns[i]->csize, &plp);

            if(nl_data->columns[i]->ctype == TDS_DATA_TYPE_NTEXT ||
                nl_data->columns[i]->ctype == TDS_DATA_TYPE_TEXT ||
                nl_data->columns[i]->ctype == TDS_DATA_TYPE_IMAGE)
            {
                /* TextPointer */
                cur += 1 + tvb_get_guint8(tvb, cur);

                /* Timestamp */
                cur += 8;
            }

            dissect_tds_type_varbyte(tvb, &cur, pinfo, tree, hf_tds_row_field, nl_data->columns[i]->ctype, nl_data->columns[i]->scale, plp, i+1);
        }
    }

    return cur - offset;
}

static int
dissect_tds_returnstatus_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint cur = offset;

    proto_tree_add_item(tree, hf_tds_returnstatus_value, tvb, cur, 4, ENC_LITTLE_ENDIAN);
    cur += 4;

    return cur - offset;
}

static int
dissect_tds_sspi_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint cur = offset, len_field_val;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    len_field_val = tvb_get_guint16(tvb, cur, encoding) * 2;
    cur += 2;

    if (len_field_val) {
        proto_tree_add_item(tree, hf_tds_sspi_buffer, tvb, cur, len_field_val, ENC_NA);
        cur += len_field_val;
    }

    return cur - offset;
}

static int
dissect_tds_envchg_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint cur = offset;
    guint8 env_type;
    guint new_len, old_len;

    proto_tree_add_item(tree, hf_tds_envchg_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;

    env_type = tvb_get_guint8(tvb, cur);
    proto_tree_add_item(tree, hf_tds_envchg_type, tvb, cur, 1, ENC_NA);
    cur += 1;

    /* Read new value */
    switch(env_type)
    {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 13:
    case 19:
        /* B_VARCHAR, Unicode strings */
        new_len = tvb_get_guint8(tvb, cur) * 2;
        proto_tree_add_item(tree, hf_tds_envchg_newvalue_length, tvb, cur, 1, ENC_NA);
        cur += 1;
        if(new_len > 0)
        {
            proto_tree_add_item(tree, hf_tds_envchg_newvalue_string, tvb, cur, new_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            cur += new_len;
        }

        break;

    case 7:
        /* parse collation info structure. From http://www.freetds.org/tds.html#collate */
        new_len = tvb_get_guint8(tvb, cur);
        proto_tree_add_item(tree, hf_tds_envchg_newvalue_length, tvb, cur, 1, ENC_NA);
        cur +=1;

        proto_tree_add_item(tree, hf_tds_envchg_collate_codepage, tvb, cur, 2, ENC_LITTLE_ENDIAN );
        proto_tree_add_item(tree, hf_tds_envchg_collate_flags, tvb, cur + 2, 2, ENC_LITTLE_ENDIAN );
        proto_tree_add_item(tree, hf_tds_envchg_collate_charset_id, tvb, cur + 4, 1, ENC_LITTLE_ENDIAN );
        cur += new_len;

        break;

    case 8:
    case 12:
    case 16:
        /* B_VARBYTE */
        new_len = tvb_get_guint8(tvb, cur);
        proto_tree_add_item(tree, hf_tds_envchg_newvalue_length, tvb, cur, 1, ENC_NA);
        cur += 1;
        if(new_len > 0)
        {
            proto_tree_add_item(tree, hf_tds_envchg_newvalue_bytes, tvb, cur, new_len, ENC_NA);
            cur += new_len;
        }
        break;

    case 9:
    case 10:
    case 11:
    case 17:
    case 18:
        /* %x00 */
        proto_tree_add_item(tree, hf_tds_envchg_newvalue_length, tvb, cur, 1, ENC_NA);
        cur += 1;
        break;

    case 15:
        /* L_VARBYTE */
        break;

    case 20:
        break;

    }

    /* Read old value */
    switch(env_type)
    {
    case 1:
    case 2:
    case 3:
    case 4:
        /* B_VARCHAR, Unicode strings */
        old_len = tvb_get_guint8(tvb, cur) * 2;
        proto_tree_add_item(tree, hf_tds_envchg_oldvalue_length, tvb, cur, 1, ENC_NA);
        cur += 1;
        if(old_len > 0)
        {
            proto_tree_add_item(tree, hf_tds_envchg_oldvalue_string, tvb, cur, old_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            cur += old_len;
        }
        break;

    case 5:
    case 6:
    case 8:
    case 12:
    case 13:
    case 15:
    case 16:
    case 18:
    case 19:
        /* %x00 */
        proto_tree_add_item(tree, hf_tds_envchg_oldvalue_length, tvb, cur, 1, ENC_NA);
        cur += 1;
        break;

    case 7:
    case 9:
    case 10:
    case 11:
    case 17:
        /* B_VARBYTE */
        old_len = tvb_get_guint8(tvb, cur);
        proto_tree_add_item(tree, hf_tds_envchg_oldvalue_length, tvb, cur, 1, ENC_NA);
        cur += 1;
        if(old_len > 0)
        {
            proto_tree_add_item(tree, hf_tds_envchg_oldvalue_bytes, tvb, cur, old_len, ENC_NA);
            cur += old_len;
        }
        break;

    case 20:
        break;
    }

    return cur - offset;
}

static int
dissect_tds_error_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint16 msg_len;
    guint8 srvr_len, proc_len;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    proto_tree_add_item(tree, hf_tds_error_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;

    proto_tree_add_item(tree, hf_tds_error_number, tvb, cur, 4, encoding);
    cur += 4;
    proto_tree_add_item(tree, hf_tds_error_state, tvb, cur, 1, ENC_NA);
    cur +=1;
    proto_tree_add_item(tree, hf_tds_error_class, tvb, cur, 1, ENC_NA);
    cur +=1;

    msg_len = tvb_get_guint16(tvb, cur, encoding);
    proto_tree_add_uint_format_value(tree, hf_tds_error_msgtext_length, tvb, cur, 2, msg_len, "%u characters", msg_len);
    cur +=2;

    msg_len *= 2;
    proto_tree_add_item(tree, hf_tds_error_msgtext, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
    cur += msg_len;

    srvr_len = tvb_get_guint8(tvb, cur);

    proto_tree_add_uint_format_value(tree, hf_tds_error_servername_length, tvb, cur, 1, srvr_len, "%u characters", srvr_len);
    cur +=1;
    if(srvr_len) {
        srvr_len *=2;
        proto_tree_add_item(tree, hf_tds_error_servername, tvb, cur, srvr_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        cur += srvr_len;
    }

    proc_len = tvb_get_guint8(tvb, cur);

    proto_tree_add_uint_format_value(tree, hf_tds_error_procname_length, tvb, cur, 1, proc_len, "%u characters", proc_len);
    cur +=1;
    if(proc_len) {
        proc_len *=2;
        proto_tree_add_item(tree, hf_tds_error_procname, tvb, cur, proc_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        cur += proc_len;
    }

    if (TDS_PROTO_TDS7_1_OR_LESS) {
        proto_tree_add_item(tree, hf_tds_error_linenumber_16, tvb, cur, 2, encoding);
        cur += 2;
    } else {
        proto_tree_add_item(tree, hf_tds_error_linenumber_32, tvb, cur, 4, encoding);
        cur += 4;
    }

    return cur - offset;
}

static int
dissect_tds_info_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint16 msg_len;
    guint8 srvr_len, proc_len;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    proto_tree_add_item(tree, hf_tds_info_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;

    proto_tree_add_item(tree, hf_tds_info_number, tvb, cur, 4, encoding);
    cur += 4;
    proto_tree_add_item(tree, hf_tds_info_state, tvb, cur, 1, ENC_NA);
    cur +=1;
    proto_tree_add_item(tree, hf_tds_info_class, tvb, cur, 1, ENC_NA);
    cur +=1;

    msg_len = tvb_get_guint16(tvb, cur, encoding);
    proto_tree_add_uint_format_value(tree, hf_tds_info_msgtext_length, tvb, cur, 2, msg_len, "%u characters", msg_len);
    cur +=2;

    msg_len *= 2;
    proto_tree_add_item(tree, hf_tds_info_msgtext, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
    cur += msg_len;

    srvr_len = tvb_get_guint8(tvb, cur);

    proto_tree_add_uint_format_value(tree, hf_tds_info_servername_length, tvb, cur, 1, srvr_len, "%u characters", srvr_len);
    cur +=1;
    if(srvr_len) {
        srvr_len *=2;
        proto_tree_add_item(tree, hf_tds_info_servername, tvb, cur, srvr_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        cur += srvr_len;
    }

    proc_len = tvb_get_guint8(tvb, cur);

    proto_tree_add_uint_format_value(tree, hf_tds_info_procname_length, tvb, cur, 1, proc_len, "%u characters", proc_len);
    cur +=1;
    if(proc_len) {
        proc_len *=2;
        proto_tree_add_item(tree, hf_tds_info_procname, tvb, cur, proc_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        cur += proc_len;
    }

    if (TDS_PROTO_TDS7_1_OR_LESS) {
        proto_tree_add_item(tree, hf_tds_info_linenumber_16, tvb, cur, 2, encoding);
        cur += 2;
    } else {
        proto_tree_add_item(tree, hf_tds_info_linenumber_32, tvb, cur, 4, encoding);
        cur += 4;
    }

    return cur - offset;
}

static int
dissect_tds_login_ack_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint8 msg_len;
    guint32 tds_version;
    guint cur = offset;

    proto_tree_add_item(tree, hf_tds_loginack_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;

    proto_tree_add_item(tree, hf_tds_loginack_interface, tvb, cur, 1, ENC_NA);
    cur +=1;
    proto_tree_add_item_ret_uint(tree, hf_tds_loginack_tdsversion, tvb, cur, 4, ENC_BIG_ENDIAN, &tds_version);
    switch (tds_version) {
        case 0x07000000:
            tds_info->tds7_version = TDS_PROTOCOL_7_0;
            break;
        case 0x07010000:
        case 0x71000001:
            tds_info->tds7_version = TDS_PROTOCOL_7_1;
            break;
        case 0x72090002:
            tds_info->tds7_version = TDS_PROTOCOL_7_2;
            break;
        case 0x730A0003:
            tds_info->tds7_version = TDS_PROTOCOL_7_3A;
            break;
        case 0x730B0003:
            tds_info->tds7_version = TDS_PROTOCOL_7_3B;
            break;
        case 0x74000004:
            tds_info->tds7_version = TDS_PROTOCOL_7_4;
            break;
        default:
            tds_info->tds7_version = TDS_PROTOCOL_7_4;
            break;
    }
    cur += 4;

    msg_len = tvb_get_guint8(tvb, cur);
    cur +=1;

    msg_len *= 2;
    proto_tree_add_item(tree, hf_tds_loginack_progname, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
    cur += msg_len;

    proto_tree_add_item(tree, hf_tds_loginack_progversion, tvb, cur, 4, ENC_NA);

    cur += 4;

    return cur - offset;
}

static int
dissect_tds7_colmetadata_token(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint16 num_columns, flags, numparts, parti, partlen, msg_len;
    guint8 type;
    int i, col_offset;
    proto_tree* col_tree, *flags_tree;
    proto_item* flags_item, * type_item, *col_item;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    num_columns = tvb_get_letohs(tvb, cur);
    nl_data->num_cols = num_columns;
    proto_tree_add_item(tree, hf_tds_colmetadata_columns, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    if (nl_data->num_cols > TDS_MAX_COLUMNS) {
        nl_data->num_cols = 0;
        return 0;
    }
    cur +=2;

    for(i=0; i != num_columns; i++) {

        col_offset = cur;

        col_item = proto_tree_add_item(tree, hf_tds_colmetadata_field, tvb, cur, 0, ENC_NA);
        col_tree = proto_item_add_subtree(col_item, ett_tds_col);
        proto_item_set_text(col_item, "Column %d", i + 1);

        nl_data->columns[i] = wmem_new(wmem_packet_scope(), struct _tds_col);
        nl_data->columns[i]->name[0] ='\0';

        if (TDS_PROTO_TDS7_1_OR_LESS) {
            proto_tree_add_item(col_tree, hf_tds_colmetadata_usertype16, tvb, cur, 2, ENC_LITTLE_ENDIAN);
            nl_data->columns[i]->utype = tvb_get_guint16(tvb, cur, encoding);
            cur +=2;
        } else {
            proto_tree_add_item_ret_uint(col_tree, hf_tds_colmetadata_usertype32, tvb, cur, 4, ENC_LITTLE_ENDIAN, &(nl_data->columns[i]->utype));
            cur +=4;
        }

        flags = tvb_get_letohs(tvb, cur);
        flags_item = proto_tree_add_uint(col_tree, hf_tds_colmetadata_results_token_flags, tvb, cur, 2, flags);
        if(flags_item)
        {
            flags_tree = proto_item_add_subtree(flags_item, ett_tds_flags);
            if(flags_tree)
            {
                proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_nullable, tvb, cur, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_casesen, tvb, cur, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_updateable, tvb, cur, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_identity, tvb, cur, 2, ENC_BIG_ENDIAN);
                if(TDS_PROTO_TDS7_2_OR_GREATER) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_computed, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_3A_OR_LESS) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_reservedodbc, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_2_OR_GREATER) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_fixedlenclrtype, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_3B_OR_GREATER) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_sparsecolumnset, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_4_OR_GREATER) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_encrypted, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_2_OR_GREATER) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_hidden, tvb, cur, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_key, tvb, cur, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_nullableunknown, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
            }
        }
        cur +=2;

        /* TYPE_INFO */
        type  = tvb_get_guint8(tvb, cur);
        type_item = proto_tree_add_item(col_tree, hf_tds_colmetadata_results_token_type, tvb, cur, 1, ENC_NA);
        proto_item_append_text(type_item, " (%s)", val_to_str(type, tds_data_type_names, "Invalid data type: %02X"));
        nl_data->columns[i]->ctype = type;
        cur++;

        if(is_fixedlen_type_tds(type))
        {
            nl_data->columns[i]->csize = get_size_by_coltype(type);
        }
        else if(is_varlen_type_tds(type))
        {
            switch(type)
            {
                case TDS_DATA_TYPE_GUID:
                case TDS_DATA_TYPE_INTN:
                case TDS_DATA_TYPE_BITN:
                case TDS_DATA_TYPE_FLTN:
                case TDS_DATA_TYPE_MONEYN:
                case TDS_DATA_TYPE_DATETIMN:
                case TDS_DATA_TYPE_CHAR:
                case TDS_DATA_TYPE_VARCHAR:
                case TDS_DATA_TYPE_BINARY:
                case TDS_DATA_TYPE_VARBINARY:
                {
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_csize, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    nl_data->columns[i]->csize = tvb_get_guint8(tvb, cur);
                    cur++;
                    break;
                }
                case TDS_DATA_TYPE_DATEN:
                {
                    break;
                }
                case TDS_DATA_TYPE_DECIMAL:
                case TDS_DATA_TYPE_NUMERIC:
                case TDS_DATA_TYPE_DECIMALN:
                case TDS_DATA_TYPE_NUMERICN:
                {
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_csize, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    nl_data->columns[i]->csize = tvb_get_guint8(tvb,cur);
                    cur++;

                    proto_tree_add_item(col_tree, hf_tds_colmetadata_precision, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    nl_data->columns[i]->precision = tvb_get_guint8(tvb,cur);
                    cur++;

                    proto_tree_add_item(col_tree, hf_tds_colmetadata_scale, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    nl_data->columns[i]->scale = tvb_get_guint8(tvb,cur);
                    cur++;
                    break;
                }
                case TDS_DATA_TYPE_TIMEN:
                case TDS_DATA_TYPE_DATETIME2N:
                case TDS_DATA_TYPE_DATETIMEOFFSETN:
                {
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_scale, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    nl_data->columns[i]->scale = tvb_get_guint8(tvb,cur);
                    cur++;
                    break;
                }
                case TDS_DATA_TYPE_BIGVARBIN:
                {
                    nl_data->columns[i]->csize = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;
                    break;
                }
                case TDS_DATA_TYPE_BIGVARCHR:
                {
                    nl_data->columns[i]->csize = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;

                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_codepage, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_flags, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_charset_id, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    cur +=1;
                    break;
                }
                case TDS_DATA_TYPE_BIGBINARY:
                {
                    nl_data->columns[i]->csize = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;
                    break;
                }
                case TDS_DATA_TYPE_BIGCHAR:
                case TDS_DATA_TYPE_NVARCHAR:
                case TDS_DATA_TYPE_NCHAR:
                {
                    nl_data->columns[i]->csize = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;

                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_codepage, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_flags, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_charset_id, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    cur +=1;
                    break;
                }
                case TDS_DATA_TYPE_XML:
                {
                    guint8 schema_present;
                    schema_present = tvb_get_guint8(tvb, cur);
                    cur += 1;

                    if(schema_present)
                    {
                        msg_len = tvb_get_guint8(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_dbname_length, tvb, cur, 1, ENC_NA);
                        cur += 1;
                        if(msg_len != 0) {
                            msg_len *= 2;
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_dbname, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                            cur += msg_len;
                        }

                        msg_len = tvb_get_guint8(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_owningschema_length, tvb, cur, 1, ENC_NA);
                        cur += 1;
                        if(msg_len != 0) {
                            msg_len *= 2;
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_owningschema, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                            cur += msg_len;
                        }

                        msg_len = tvb_get_guint8(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_typename_length, tvb, cur, 1, ENC_NA);
                        cur += 1;
                        if(msg_len != 0) {
                            msg_len *= 2;
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_typename, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                            cur += msg_len;
                        }

                        msg_len = tvb_get_guint8(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_xmlschemacollection_length, tvb, cur, 1, ENC_NA);
                        cur += 1;
                        if(msg_len != 0) {
                            msg_len *= 2;
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_xmlschemacollection, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                            cur += msg_len;
                        }
                    }

                    break;
                }
                case TDS_DATA_TYPE_UDT:
                {
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_maxbytesize, tvb, cur, 2, ENC_NA|ENC_LITTLE_ENDIAN);
                    cur += 2;

                    msg_len = tvb_get_guint8(tvb, cur);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_dbname_length, tvb, cur, 1, ENC_NA);
                    cur += 1;
                    if(msg_len != 0) {
                        msg_len *= 2;
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_dbname, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += msg_len;
                    }

                    msg_len = tvb_get_guint8(tvb, cur);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_schemaname_length, tvb, cur, 1, ENC_NA);
                    cur += 1;
                    if(msg_len != 0) {
                        msg_len *= 2;
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_schemaname, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += msg_len;
                    }

                    msg_len = tvb_get_guint8(tvb, cur);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_typename_length, tvb, cur, 1, ENC_NA);
                    cur += 1;
                    if(msg_len != 0) {
                        msg_len *= 2;
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_typename, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += msg_len;
                    }

                    msg_len = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_assemblyqualifiedname_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;
                    if(msg_len != 0) {
                        msg_len *= 2;
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_assemblyqualifiedname, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += msg_len;
                    }

                    break;
                }
                case TDS_DATA_TYPE_IMAGE:
                {
                    cur += 4;

                    /* Table name */
                    numparts = tvb_get_guint8(tvb, cur);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_parts, tvb, cur, 1, ENC_LITTLE_ENDIAN);
                    cur += 1;

                    for(parti = 0; parti < numparts; parti++)
                    {
                        partlen = tvb_get_letohs(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name, tvb, cur + 2, partlen * 2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += 2 + (partlen * 2);
                    }
                    break;
                }
                case TDS_DATA_TYPE_TEXT:
                case TDS_DATA_TYPE_NTEXT:
                {
                    /* Not sure what we are stepping over here */
                    cur += 2;

                    nl_data->columns[i]->csize = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;

                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_codepage, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_flags, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_charset_id, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    cur +=1;

                    /* Table name */
                    numparts = tvb_get_guint8(tvb, cur);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_parts, tvb, cur, 1, ENC_LITTLE_ENDIAN);
                    cur += 1;

                    for(parti = 0; parti < numparts; parti++)
                    {
                        partlen = tvb_get_letohs(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name, tvb, cur + 2, partlen * 2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += 2 + (partlen * 2);
                    }

                    break;
                }
                case TDS_DATA_TYPE_SSVARIANT:
                {
                    cur += 4;
                    break;
                }
            }
        }

        /* ColName */
        msg_len = tvb_get_guint8(tvb, cur);
        proto_tree_add_item(col_tree, hf_tds_colmetadata_colname_length, tvb, cur, 1, ENC_NA);
        cur += 1;
        if(msg_len != 0) {
            msg_len *= 2;
            proto_tree_add_item(col_tree, hf_tds_colmetadata_colname, tvb, cur, msg_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            cur += msg_len;
        }

        proto_item_set_len(col_item, cur - col_offset);
    }

    return cur - offset;
}

static int
dissect_tds_done_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;

    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    proto_tree_add_item(tree, hf_tds_done_status, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;
    proto_tree_add_item(tree, hf_tds_done_curcmd, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;
    if (TDS_PROTO_TDS7_1_OR_LESS) {
        proto_tree_add_item(tree, hf_tds_done_donerowcount_32, tvb, cur, 4, encoding);
        cur += 4;
    } else {
        proto_tree_add_item(tree, hf_tds_done_donerowcount_64, tvb, cur, 8, encoding);
        cur += 8;
    }

    return cur - offset;
}

static int
dissect_tds_doneproc_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    proto_tree_add_item(tree, hf_tds_doneproc_status, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;
    proto_tree_add_item(tree, hf_tds_doneproc_curcmd, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;
    if (TDS_PROTO_TDS7_1_OR_LESS) {
        proto_tree_add_item(tree, hf_tds_doneproc_donerowcount_32, tvb, cur, 4, encoding);
        cur += 4;
    } else {
        proto_tree_add_item(tree, hf_tds_doneproc_donerowcount_64, tvb, cur, 8, encoding);
        cur += 8;
    }

    return cur - offset;
}

static int
dissect_tds_doneinproc_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    int encoding = tds_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    proto_tree_add_item(tree, hf_tds_doneinproc_status, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;
    proto_tree_add_item(tree, hf_tds_doneinproc_curcmd, tvb, cur, 2, ENC_LITTLE_ENDIAN);
    cur += 2;
    if (TDS_PROTO_TDS7_1_OR_LESS) {
        proto_tree_add_item(tree, hf_tds_doneinproc_donerowcount_32, tvb, cur, 4, encoding);
        cur += 4;
    } else {
        proto_tree_add_item(tree, hf_tds_doneinproc_donerowcount_64, tvb, cur, 8, encoding);
        cur += 8;
    }

    return cur - offset;
}

static guint8
dissect_tds_type_info(tvbuff_t *tvb, guint *offset, packet_info *pinfo, proto_tree *tree, gboolean *plp, gboolean variantprop)
{
    proto_item *item = NULL, *item1 = NULL, *data_type_item = NULL;
    proto_tree *sub_tree = NULL, *collation_tree;
    guint32 varlen, varlen_len = 0;
    guint8 data_type;

    *plp = FALSE; /* most types are not Partially Length-Prefixed */
    item = proto_tree_add_item(tree, hf_tds_type_info, tvb, *offset, 0, ENC_NA);
    data_type = tvb_get_guint8(tvb, *offset);
    proto_item_append_text(item, " (%s)", val_to_str(data_type, tds_data_type_names, "Invalid data type: %02X"));
    sub_tree = proto_item_add_subtree(item, ett_tds_type_info);
    data_type_item = proto_tree_add_item(sub_tree, hf_tds_type_info_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
    *offset += 1;

    if(variantprop)
    {
        guint8 prop_bytes = variant_propbytes(data_type);
        *offset += prop_bytes;
    }

    /* optional TYPE_VARLEN for variable length types */
    switch(data_type) {
        /* FIXEDLENTYPE */
        case TDS_DATA_TYPE_NULL:            /* Null (no data associated with this type) */
        case TDS_DATA_TYPE_INT1:            /* TinyInt (1 byte data representation) */
        case TDS_DATA_TYPE_BIT:             /* Bit (1 byte data representation) */
        case TDS_DATA_TYPE_INT2:            /* SmallInt (2 byte data representation) */
        case TDS_DATA_TYPE_INT4:            /* Int (4 byte data representation) */
        case TDS_DATA_TYPE_FLT4:            /* Real (4 byte data representation) */
        case TDS_DATA_TYPE_DATETIME4:       /* SmallDateTime (4 byte data representation) */
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
            /* Fall through */
        case TDS_DATA_TYPE_TEXT:            /* Text */
        case TDS_DATA_TYPE_IMAGE:           /* Image */
        case TDS_DATA_TYPE_NTEXT:           /* NText */
        case TDS_DATA_TYPE_SSVARIANT:       /* Sql_Variant (introduced in TDS 7.2) */
            varlen_len = 4;
            varlen = tvb_get_letohl(tvb, *offset);
            break;
        default:
            expert_add_info(pinfo, data_type_item, &ei_tds_type_info_type);
            varlen_len = 0;
            data_type = TDS_DATA_TYPE_INVALID;
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
            proto_tree_add_item(sub_tree, hf_tds_type_info_precision, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            /* fallthrough */

        /* SCALE */
        case TDS_DATA_TYPE_TIMEN:           /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIME2N:      /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_DATETIMEOFFSETN: /* (introduced in TDS 7.3) */
            proto_tree_add_item(sub_tree, hf_tds_type_info_scale, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
            break;
        /* COLLATION */
        case TDS_DATA_TYPE_BIGCHAR:         /* Char */
        case TDS_DATA_TYPE_BIGVARCHR:       /* VarChar */
        case TDS_DATA_TYPE_TEXT:            /* Text */
        case TDS_DATA_TYPE_NTEXT:           /* NText */
        case TDS_DATA_TYPE_NCHAR:           /* NChar */
        case TDS_DATA_TYPE_NVARCHAR:        /* NVarChar */
            item1 = proto_tree_add_item(sub_tree, hf_tds_type_info_collation, tvb, *offset, 5, ENC_NA);
            collation_tree = proto_item_add_subtree(item1, ett_tds_type_info_collation);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_lcid, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_case, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_accent, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_kana, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_ign_width, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_binary, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_version, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(collation_tree, hf_tds_type_info_collation_sortid, tvb, *offset + 4, 1, ENC_LITTLE_ENDIAN);
            *offset += 5;
            break;
    }

    proto_item_set_end(item, tvb, *offset);
    return data_type;
}

static void
dissect_tds_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item = NULL, *param_item = NULL;
    proto_tree *sub_tree = NULL, *status_sub_tree = NULL;
    int offset = 0;
    guint len;
    guint8 data_type;

    item = proto_tree_add_item(tree, hf_tds_rpc, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_tds_message);

    dissect_tds_all_headers(tvb, &offset, pinfo, tree);
    while(tvb_reported_length_remaining(tvb, offset) > 0) {
        /*
         * RPC name.
         */
        switch(tds_protocol_type) {
            case TDS_PROTOCOL_4:
                len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_tds_rpc_name_length8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, hf_tds_rpc_name, tvb, offset + 1, len, ENC_ASCII|ENC_NA);
                offset += 1 + len;
                break;

            case TDS_PROTOCOL_7_0:
            case TDS_PROTOCOL_7_1:
            case TDS_PROTOCOL_7_2:
            case TDS_PROTOCOL_7_3:
            case TDS_PROTOCOL_7_4:
            default: /* unspecified: try as if TDS7 */
                len = tvb_get_letohs(tvb, offset);
                proto_tree_add_item(tree, hf_tds_rpc_name_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                if (len == 0xFFFF) {
                    proto_tree_add_item(tree, hf_tds_rpc_proc_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                else if (len != 0) {
                    len *= 2;
                    proto_tree_add_item(tree, hf_tds_rpc_name, tvb, offset, len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                    offset += len;
                }
                break;
        }
        item = proto_tree_add_item(tree, hf_tds_rpc_options, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        sub_tree = proto_item_add_subtree(item, ett_tds_rpc_options);
        proto_tree_add_item(sub_tree, hf_tds_rpc_options_with_recomp, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_tds_rpc_options_no_metadata, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_tds_rpc_options_reuse_metadata, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* dissect parameters */
        while(tvb_reported_length_remaining(tvb, offset) > 0) {
            gboolean plp;

            len = tvb_get_guint8(tvb, offset);
            /* check for BatchFlag or NoExecFlag */
            if((gint8)len < 0) {
                proto_tree_add_item(tree, hf_tds_rpc_separator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                ++offset;
                break;
            }
            param_item = proto_tree_add_item(tree, hf_tds_rpc_parameter, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(param_item, ett_tds_rpc_parameter);
            proto_tree_add_item(sub_tree, hf_tds_rpc_parameter_name_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            if(len) {
                len *= 2;
                proto_tree_add_item(sub_tree, hf_tds_rpc_parameter_name, tvb, offset, len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                offset += len;
            }
            item = proto_tree_add_item(sub_tree, hf_tds_rpc_parameter_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            status_sub_tree = proto_item_add_subtree(item, ett_tds_rpc_parameter_status);
            proto_tree_add_item(status_sub_tree, hf_tds_rpc_parameter_status_by_ref, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(status_sub_tree, hf_tds_rpc_parameter_status_default, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ++offset;
            data_type = dissect_tds_type_info(tvb, &offset, pinfo, sub_tree, &plp, FALSE);
            if (data_type == TDS_DATA_TYPE_INVALID)
                break;
            dissect_tds_type_varbyte(tvb, &offset, pinfo, sub_tree, hf_tds_rpc_parameter_value, data_type, 0, plp, -1); /* TODO: Precision needs setting? */
            proto_item_set_end(param_item, tvb, offset);
        }
    }
}

static int
dissect_tds_featureextack_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint8 featureid;
    gint featureackdatalen;
    proto_tree *feature_tree = NULL;
    proto_item * feature_item;
    guint cur = offset;

    while(tvb_reported_length_remaining(tvb, cur) > 0)
    {
        featureid = tvb_get_guint8(tvb, cur);
        featureackdatalen = tvb_get_guint32(tvb, cur + 1, ENC_LITTLE_ENDIAN);

        feature_item = proto_tree_add_item(tree, hf_tds_featureextack_feature, tvb, cur, featureid == 0xff ? 1 : 5 + featureackdatalen, ENC_NA);
        feature_tree = proto_item_add_subtree(feature_item, ett_tds_col);

        proto_tree_add_item(feature_tree, hf_tds_featureextack_featureid, tvb, cur, 1, ENC_LITTLE_ENDIAN);
        cur += 1;

        if(featureid == 0xff)
            break;

        proto_tree_add_item(feature_tree, hf_tds_featureextack_featureackdatalen, tvb, cur, 4, ENC_LITTLE_ENDIAN);
        cur += 4;

        proto_tree_add_item(feature_tree, hf_tds_featureextack_featureackdata, tvb, cur, featureackdatalen, ENC_NA);
        cur += featureackdatalen;
    }

    return cur - offset;
}

static int
dissect_tds_sessionstate_token(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint16 statelen;
    guint cur = offset, len;

    proto_tree_add_item_ret_uint(tree, hf_tds_sessionstate_length, tvb, cur, 4, ENC_LITTLE_ENDIAN, &len);
    cur += 4;

    proto_tree_add_item(tree, hf_tds_sessionstate_seqno, tvb, cur, 4, ENC_LITTLE_ENDIAN);
    cur += 4;

    proto_tree_add_item(tree, hf_tds_sessionstate_status, tvb, cur, 1, ENC_LITTLE_ENDIAN);
    cur += 1;

    while((cur - offset - 3) < len)
    {
        proto_tree_add_item(tree, hf_tds_sessionstate_stateid, tvb, cur, 1, ENC_LITTLE_ENDIAN);
        cur += 1;

        if(tvb_get_guint8(tvb, cur) == 0xFF)
        {
            cur += 1;
            statelen = tvb_get_ntohs(tvb, cur + 2);
            proto_tree_add_item(tree, hf_tds_sessionstate_statelen, tvb, cur, 2, ENC_LITTLE_ENDIAN);
            cur += 2;
        } else {
            statelen = tvb_get_guint8(tvb, cur);
            proto_tree_add_item(tree, hf_tds_sessionstate_statelen, tvb, cur, 1, ENC_LITTLE_ENDIAN);
            cur += 1;
        }

        proto_tree_add_item(tree, hf_tds_sessionstate_statevalue, tvb, cur, statelen, ENC_NA);
        cur += statelen;
    }

    return cur - offset;
}

static gint
token_to_idx(guint8 token)
{
    /* TODO: Commented out entries are token types which are not currently dissected
     * Although they are known values, we cannot step over the bytes as token length is unknown
     * Better therefore to return unknown token type and highlight to user
    */

    switch(token)
    {
    /*case TDS7_ALTMETADATA_TOKEN: return hf_tds_altmetadata;*/
    /*case TDS_ALTROW_TOKEN: return hf_tds_altrow;*/
    /*case TDS_COL_NAME_TOKEN: return hf_tds_colname;*/
    case TDS_COL_INFO_TOKEN: return hf_tds_colinfo;
    case TDS7_COL_METADATA_TOKEN: return hf_tds_colmetadata;
    case TDS_DONE_TOKEN: return hf_tds_done;
    case TDS_DONEPROC_TOKEN: return hf_tds_doneproc;
    case TDS_DONEINPROC_TOKEN: return hf_tds_doneinproc;
    case TDS_ENVCHG_TOKEN: return hf_tds_envchg;
    case TDS_ERR_TOKEN: return hf_tds_error;
    case TDS_FEATUREEXTACK_TOKEN: return hf_tds_featureextack;
    /*case TDS_FEDAUTHINFO_TOKEN: return hf_tds_fedauthinfo;*/
    case TDS_INFO_TOKEN: return hf_tds_info;
    case TDS_LOGIN_ACK_TOKEN: return hf_tds_loginack;
    case TDS_NBCROW_TOKEN: return hf_tds_nbcrow;
    case TDS_OFFSET_TOKEN: return hf_tds_offset;
    case TDS_ORDER_TOKEN: return hf_tds_order;
    case TDS_RET_STAT_TOKEN: return hf_tds_returnstatus;
    /*case TDS_RETURNVAL_TOKEN: return hf_tds_returnvalue;*/
    case TDS_ROW_TOKEN: return hf_tds_row;
    case TDS_SESSIONSTATE_TOKEN: return hf_tds_sessionstate;
    case TDS_SSPI_TOKEN: return hf_tds_sspi;
    /*case TDS_TABNAME_TOKEN: return hf_tds_tabname;*/
    /*case TDS_TVPROW_TOKEN: return hf_tds_tvprow;*/
    }

    return hf_tds_unknown_tds_token;
}

static void
dissect_tds_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tds_conv_info_t *tds_info)
{
    proto_item *token_item;
    proto_tree *token_tree;
    guint pos = 0, token_sz = 0;
    guint8 token;
    struct _netlib_data nl_data;

    memset(&nl_data, '\0', sizeof nl_data);

    /* Test for pre-login response in case this response is not a token stream */
    if(dissect_tds_prelogin_response(tvb, pos, tree) == 1)
    {
        return;
    }

    /*
     * Until we reach the end of the packet, read tokens.
     */
    while (tvb_reported_length_remaining(tvb, pos) > 0) {
        /* our token */
        token = tvb_get_guint8(tvb, pos);

        token_item = proto_tree_add_item(tree, token_to_idx(token), tvb, pos, tvb_reported_length_remaining(tvb, pos), ENC_NA);
        token_tree = proto_item_add_subtree(token_item, ett_tds_type_varbyte);

        if(TDS_PROTO_TDS4)
        {
            guint8 nomatch = 0;

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
                    read_results_tds5_token(tvb, &nl_data, pos + 3);
                    break;

                case TDS_AUTH_TOKEN:
                    dissect_tds_nt(tvb, pinfo, token_tree, pos + 3, token_sz - 3);
                    break;

                default:
                    nomatch = 1;
                    break;
            }

            if(nomatch)
            {
                break;
            }

        } else {

            /* Tokens from MS-TDS specification, revision 18.0 (up to TDS 7.4) */
            switch (token) {
                case TDS7_COL_METADATA_TOKEN:
                    token_sz = dissect_tds7_colmetadata_token(tvb, &nl_data, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_DONE_TOKEN:
                    token_sz = dissect_tds_done_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_DONEPROC_TOKEN:
                    token_sz = dissect_tds_doneproc_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_DONEINPROC_TOKEN:
                    token_sz = dissect_tds_doneinproc_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_ENVCHG_TOKEN:
                    token_sz = dissect_tds_envchg_token(tvb, pos + 1, token_tree) + 1;
                    break;
                case TDS_ERR_TOKEN:
                    token_sz = dissect_tds_error_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_INFO_TOKEN:
                    token_sz = dissect_tds_info_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_FEATUREEXTACK_TOKEN:
                    token_sz = dissect_tds_featureextack_token(tvb, pos + 1, token_tree) + 1;
                    break;
                case TDS_LOGIN_ACK_TOKEN:
                    token_sz = dissect_tds_login_ack_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_NBCROW_TOKEN:
                    token_sz = dissect_tds_nbc_row_token(tvb, pinfo, &nl_data, pos + 1, token_tree) + 1;
                    break;
                case TDS_OFFSET_TOKEN:
                    token_sz = dissect_tds_offset_token(tvb, pos + 1, token_tree) + 1;
                    break;
                case TDS_ORDER_TOKEN:
                    token_sz = dissect_tds_order_token(tvb, pos + 1, token_tree) + 1;
                    break;
                case TDS_RET_STAT_TOKEN:
                    token_sz = dissect_tds_returnstatus_token(tvb, pos + 1, token_tree) + 1;
                    break;
                case TDS_ROW_TOKEN:
                    token_sz = dissect_tds_row_token(tvb, pinfo, &nl_data, pos + 1, token_tree) + 1;
                    break;
                case TDS_SESSIONSTATE_TOKEN:
                    token_sz = dissect_tds_sessionstate_token(tvb, pos + 1, token_tree) + 1;
                    break;
                case TDS_SSPI_TOKEN:
                    token_sz = dissect_tds_sspi_token(tvb, pos + 1, token_tree) + 1;
                    break;
                default:
                    token_sz = 0;
                    break;
            }

            /* Move on if nothing identifiable found */
            if(token_sz == 0)
                break;

            proto_item_set_len(token_item, token_sz);

            /* and step to the end of the token, rinse, lather, repeat */
            pos += token_sz;
        }
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
    gboolean save_fragmented, last_buffer;
    int len;
    fragment_head *fd_head;
    tvbuff_t *next_tvb;
    conversation_t *conv;
    tds_conv_info_t *tds_info;

    if(detect_tls(tvb))
    {
        tds_item = proto_tree_add_item(tree, hf_tds_prelogin, tvb, 0, -1, ENC_NA);
        proto_item_append_text(tds_item, " - TLS exchange");
        return;
    }

    conv = find_or_create_conversation(pinfo);
    tds_info = (tds_conv_info_t*)conversation_get_proto_data(conv, proto_tds);
    if (!tds_info) {
        tds_info = wmem_new(wmem_file_scope(), tds_conv_info_t);
        tds_info->tds7_version = TDS_PROTOCOL_NOT_SPECIFIED;
        conversation_add_proto_data(conv, proto_tds, tds_info);
    }

    type = tvb_get_guint8(tvb, offset);
    status = tvb_get_guint8(tvb, offset + 1);
    channel = tvb_get_ntohs(tvb, offset + 4);
    packet_number = tvb_get_guint8(tvb, offset + 6);

    /* create display subtree for the protocol */
    tds_item = proto_tree_add_item(tree, proto_tds, tvb, offset, -1, ENC_NA);
    tds_tree = proto_item_add_subtree(tds_item, ett_tds);
    proto_tree_add_item(tds_tree, hf_tds_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    tds_item = proto_tree_add_item(tds_tree, hf_tds_status, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    tds_status_tree = proto_item_add_subtree(tds_item, ett_tds_status);
    proto_tree_add_item(tds_status_tree, hf_tds_status_eom, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tds_status_tree, hf_tds_status_ignore, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tds_status_tree, hf_tds_status_event_notif, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tds_status_tree, hf_tds_status_reset_conn, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tds_status_tree, hf_tds_status_reset_conn_skip_tran,tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tds_tree, hf_tds_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tds_tree, hf_tds_channel, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tds_tree, hf_tds_packet_number, tvb, offset + 6, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tds_tree, hf_tds_window, tvb, offset + 7, 1, ENC_LITTLE_ENDIAN);
    offset += 8;        /* skip Netlib header */

    /*
     * Deal with fragmentation.
     *
     * TODO: handle case where netlib headers 'packet-number'.is always 0
     *       use fragment_add_seq_next in this case ?
     *
     */
    save_fragmented = pinfo->fragmented;

    if (tds_defragment && (packet_number > 1 || (status & STATUS_LAST_BUFFER) == 0)) {

        if (((status & STATUS_LAST_BUFFER) == 0)) {
            col_append_str(pinfo->cinfo, COL_INFO, " (Not last buffer)");
        }
        len = tvb_reported_length_remaining(tvb, offset);
        /*
         * XXX - I've seen captures that start with a login
         * packet with a sequence number of 2.
         */

        last_buffer = ((status & STATUS_LAST_BUFFER) == 1);
        /*
        if(tvb_reported_length(tvb) == tvb_captured_length(tvb))
        {
            last_buffer = TRUE;
        }
        */

        fd_head = fragment_add_seq_check(&tds_reassembly_table, tvb, offset,
                                         pinfo, channel, NULL,
                                         packet_number - 1, len, !last_buffer);
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
        if (((status & STATUS_LAST_BUFFER) == 0))
        {
            next_tvb = NULL;
        }
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
                dissect_tds_resp(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS_LOGIN7_PKT:
                dissect_tds7_login(next_tvb, pinfo, tds_tree);
                break;
            case TDS_QUERY_PKT:
                dissect_tds_query_packet(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS_QUERY5_PKT:
                dissect_tds_query5_packet(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS_SSPI_PKT:
                dissect_tds_nt(next_tvb, pinfo, tds_tree, offset - 8, -1);
                break;
            case TDS_TRANS_MGR_PKT:
                dissect_tds_transmgr_packet(next_tvb, pinfo, tds_tree);
                break;
            case TDS_ATTENTION_PKT:
                break;
            case TDS_PRELOGIN_PKT:
                dissect_tds7_prelogin_packet(next_tvb, tds_tree);
                break;

            default:
                proto_tree_add_item(tds_tree, hf_tds_unknown_tds_packet, next_tvb, 0, -1, ENC_NA);
                break;
        }
    } else {
        next_tvb = tvb_new_subset_remaining (tvb, offset);
        call_data_dissector(next_tvb, pinfo, tds_tree);
    }
    pinfo->fragmented = save_fragmented;
}

static int
dissect_tds_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    volatile gboolean first_time = TRUE;
    volatile int offset = 0;
    guint length_remaining;
    guint8 type;
    volatile guint16 plen;
    guint length;
    tvbuff_t *volatile next_tvb;
    proto_item *tds_item = NULL;
    proto_tree *tds_tree = NULL;

    while ((length_remaining = tvb_reported_length_remaining(tvb, offset)) > 0) {

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
                return tvb_captured_length(tvb);
            }
        }

        type = tvb_get_guint8(tvb, offset);

        /* Special test for TLS to that we don't have lots of incorrect reports of malformed packets */
        if(type == TDS_TLS_PKT)
        {
            plen = tvb_get_ntohs(tvb, offset + 3) + 5;
        } else
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
                                               tvb, offset, -1, ENC_NA);

                tds_tree = proto_item_add_subtree(tds_item,
                                                  ett_tds);
                proto_tree_add_uint(tds_tree, hf_tds_type, tvb,
                                    offset, 1, type);

                if(type != TDS_TLS_PKT)
                {
                    proto_tree_add_item(tds_tree, hf_tds_status,
                                    tvb, offset + 1, 1, ENC_BIG_ENDIAN);
                    tds_item = proto_tree_add_uint(tds_tree, hf_tds_length, tvb, offset + 2, 2, plen);
                    expert_add_info_format(pinfo, tds_item, &ei_tds_invalid_length, "bogus, should be >= 8");
                }
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
                return tvb_captured_length(tvb);
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
         * If it gets an error that means there's no point in
         * dissecting any more Netlib buffers, rethrow the
         * exception in question.
         *
         * If it gets any other error, report it and continue, as that
         * means that Netlib buffer got an error, but that doesn't mean
         * we should stop dissecting Netlib buffers within this frame
         * or chunk of reassembled data.
         */
        TRY {
            dissect_netlib_buffer(next_tvb, pinfo, tree);
        }
        CATCH_NONFATAL_ERRORS {

            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;

        /*
         * Step to the next Netlib buffer.
         */
        offset += plen;
    }

    return tvb_captured_length(tvb);
}

static gboolean
dissect_tds_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
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
    if (tvb_captured_length(tvb) < 8)
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
    dissect_tds_message(tvb, pinfo, tree, data);

    return TRUE;
}

static void
tds_init(void)
{
    /*
     * Initialize the reassembly table.
     *
     * XXX - should fragments be reassembled across multiple TCP
     * connections?
     */

    reassembly_table_init(&tds_reassembly_table,
                          &addresses_ports_reassembly_table_functions);
}

static void
tds_cleanup(void)
{
    reassembly_table_destroy(&tds_reassembly_table);
}

static void
version_convert( gchar *result, guint32 hexver )
{
    g_snprintf( result, ITEM_LABEL_LENGTH, "%d.%d.%d.%d",
        (hexver >> 24) & 0xFF, (hexver >> 16) & 0xFF, (hexver >> 8) & 0xFF, hexver & 0xFF);
}

/* Register the protocol with Wireshark */

/* this format is required because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_tds(void)
{
    static hf_register_info hf[] = {

        /************************ Token definitions ************************/

        /* ALTMETADATA token */

        /* ALTROW token */

        /* COLINFO token (TDS_COL_INFO_TOKEN) */
        { &hf_tds_colinfo,
          { "Token - ColInfo", "tds.colinfo",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* COLMETADATA token (TDS7_COL_METADATA_TOKEN) */
        { &hf_tds_colmetadata,
          { "Token - ColumnMetaData", "tds.colmetadata",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_columns,
          { "Columns", "tds.colmetadata.columns",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_usertype32,
          { "Usertype", "tds.colmetadata.usertype",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_usertype16,
          { "Usertype", "tds.colmetadata.usertype",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_results_token_flags,
          { "Flags", "tds.colmetadata.results_token_flags",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_results_token_type,
          { "Type", "tds.colmetadata.results_token_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_csize,
          { "Type size", "tds.colmetadata.type_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_large_type_size,
          { "Large type size", "tds.colmetadata.large_type_size",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_collate_codepage,
          { "Collate codepage", "tds.colmetadata.collate_codepage",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_collate_flags,
          { "Collate flags", "tds.colmetadata.collate_flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_collate_charset_id,
          { "Collate charset ID", "tds.colmetadata.collate_charset_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_precision,
          { "Precision", "tds.colmetadata.precision",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_scale,
          { "Scale", "tds.colmetadata.scale",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_colname_length,
          { "Column name length", "tds.colmetadata.colname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_colname,
          { "Column Name", "tds.colmetadata.colname",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_table_name_parts,
          { "Table name parts", "tds.colmetadata.table_name_parts",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_table_name,
          { "Table name", "tds.colmetadata.table_name",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_table_name_length,
          { "Table name length", "tds.colmetadata.table_name_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_field,
          { "Field", "tds.colmetadata.field",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_nullable,
          { "Nullable", "tds.colmetadata.flags.nullable",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_casesen,
          { "Case sensitive", "tds.colmetadata.flags.casesen",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_updateable,
          { "Updateable", "tds.colmetadata.flags.updateable",
            FT_BOOLEAN, 16, NULL, 0x3000,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_identity,
          { "Identity", "tds.colmetadata.flags.identity",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_computed,
          { "Computed", "tds.colmetadata.flags.computed",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_reservedodbc,
          { "Reserved ODBC", "tds.colmetadata.flags.reservedodbc",
            FT_BOOLEAN, 16, NULL, 0x0300,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_fixedlenclrtype,
          { "Fixed length CLR type", "tds.colmetadata.flags.fixedlenclrtype",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_sparsecolumnset,
          { "Sparse column set", "tds.colmetadata.flags.sparsecolumnset",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_encrypted,
          { "Encrypted", "tds.colmetadata.flags.encrypted",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_hidden,
          { "Hidden", "tds.colmetadata.flags.hidden",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_key,
          { "Flags", "tds.colmetadata.flags.key",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_flags_nullableunknown,
          { "Nullable unknown", "tds.colmetadata.flags.nullableunknown",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_maxbytesize,
          { "Max byte size", "tds.colmetadata.maxbytesize",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_dbname_length,
          { "Database name length", "tds.colmetadata.dbname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_dbname,
          { "Database name length", "tds.colmetadata.dbname",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_schemaname_length,
          { "Schema name length", "tds.colmetadata.schemaname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_schemaname,
          { "Schema name", "tds.colmetadata.schemaname",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_typename_length,
          { "Type name length", "tds.colmetadata.typename_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_typename,
          { "Type name", "tds.colmetadata.typename",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_assemblyqualifiedname_length,
          { "Assembly qualified name length", "tds.colmetadata.assemblyqualifiedname_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_assemblyqualifiedname,
          { "Assembly qualified name", "tds.colmetadata.assemblyqualifiedname",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_owningschema_length,
          { "Owning schema name length", "tds.colmetadata.owningschema_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_owningschema,
          { "Owning schema name", "tds.colmetadata.owningschema",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_xmlschemacollection_length,
          { "XML schema collection length", "tds.colmetadata.xmlschemacollection_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_xmlschemacollection,
          { "XML schema collection", "tds.colmetadata.xmlschemacollection",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },

        /* DONE token (TDS_DONE_TOKEN) */
        { &hf_tds_done,
          { "Token - Done", "tds.done",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_done_donerowcount_64,
          { "Row count", "tds.done.donerowcount64",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_done_donerowcount_32,
          { "Row count", "tds.done.donerowcount",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_done_status,
          { "Status flags", "tds.done.status",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_done_curcmd,
          { "Operation", "tds.done.curcmd",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        /* DONEPROC token (TDS_DONEPROC_TOKEN - implemented the same as TDS_DONE_TOKEN) */
        { &hf_tds_doneproc,
          { "Token - DoneProc", "tds.doneproc",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneproc_donerowcount_64,
          { "Row count", "tds.doneproc.donerowcount64",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneproc_donerowcount_32,
          { "Row count", "tds.doneproc.donerowcount",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneproc_status,
          { "Status flags", "tds.doneproc.status",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneproc_curcmd,
          { "Operation", "tds.doneproc.curcmd",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
          },

        /* DONEINPROC token (TDS_DONEINPROC_TOKEN - implemented the same as TDS_DONE_TOKEN) */
        { &hf_tds_doneinproc,
          { "Token - DoneInProc", "tds.doneinproc",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneinproc_donerowcount_64,
          { "Row count", "tds.doneinproc.donerowcount64",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneinproc_donerowcount_32,
          { "Row count", "tds.doneinproc.donerowcount",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneinproc_status,
          { "Status flags", "tds.doneinproc.status",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_doneinproc_curcmd,
          { "Operation", "tds.doneinproc.curcmd",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
          },

        /* ENVCHANGE token (TDS_ENVCHG_TOKEN) */
        { &hf_tds_envchg,
          { "Token - EnvChange", "tds.envchange",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_length,
          { "Token length", "tds.envchange.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_type,
          { "Type", "tds.envchange.type",
            FT_UINT8, BASE_DEC, VALS(envchg_names), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_newvalue_length,
          { "New Value Length", "tds.envchange.newvalue_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_newvalue_string,
          { "New Value", "tds.envchange.newvalue_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_newvalue_bytes,
          { "New Value", "tds.envchange.newvalue",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_oldvalue_length,
          { "Old Value Length", "tds.envchange.oldvalue_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_oldvalue_string,
          { "Old Value", "tds.envchange.oldvalue_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_oldvalue_bytes,
          { "Old Value", "tds.envchange.oldvalue",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_collate_codepage,
          { "Collate codepage", "tds.envchange.collate_codepage",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_collate_flags,
          { "Collate flags", "tds.envchange.collate_flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_envchg_collate_charset_id,
          { "Collate charset ID", "tds.envchange.collate_charset_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /* ERROR token (TDS_ERR_TOKEN) */
        { &hf_tds_error,
          { "Token - Error", "tds.error",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_length,
          { "Token length", "tds.error.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_number,
          { "SQL Error Number", "tds.error.number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_state,
          { "State", "tds.error.state",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_class,
          { "Class (Severity)", "tds.error.class",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_msgtext_length,
          { "Error message length", "tds.error.msgtext_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_msgtext,
          { "Error message", "tds.error.msgtext",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_servername_length,
          { "Server name length", "tds.error.servername_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_error_servername,
          { "Server name", "tds.error.servername",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_error_procname_length,
          { "Process name length", "tds.error.procname_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_error_procname,
          { "Process name", "tds.error.procname",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_error_linenumber_16,
          { "Line number", "tds.error.linenumber",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_error_linenumber_32,
          { "Line number", "tds.error.linenumber",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },

        /* FEATUREEXTACK token (TDS_FEATUREEXTACK_TOKEN) */
        { &hf_tds_featureextack,
          { "Token - FeatureExtAct", "tds.featureextack",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_featureextack_feature,
            { "Feature", "tds.featureextack.feature",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_featureextack_featureid,
          { "Feature ID", "tds.featureextack.featureid",
            FT_UINT8, BASE_DEC, VALS(featureextack_feature_names), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_featureextack_featureackdatalen,
          { "Feature length", "tds.featureextack.featureackdatalen",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_featureextack_featureackdata,
          { "Feature data", "tds.featureextack.featureackdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* FEDAUTHINFO token */

        /* INFO token */
        { &hf_tds_info,
          { "Token - Info", "tds.info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_length,
          { "Token length", "tds.info.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_number,
          { "SQL Error Number", "tds.info.number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_state,
          { "State", "tds.info.state",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_class,
          { "Class (Severity)", "tds.info.class",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_msgtext_length,
          { "Error message length", "tds.info.msgtext_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_msgtext,
          { "Error message", "tds.info.msgtext",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_servername_length,
          { "Server name length", "tds.info.servername_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_info_servername,
          { "Server name", "tds.info.servername",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_info_procname_length,
          { "Process name length", "tds.info.procname_length",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_info_procname,
          { "Process name", "tds.info.procname",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_info_linenumber_16,
          { "Line number", "tds.info.linenumber",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_info_linenumber_32,
          { "Line number", "tds.info.linenumber",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },

        /* LOGINACK token (TDS_LOGIN_ACK_TOKEN) */
        { &hf_tds_loginack,
          { "Token - LoginAck", "tds.loginack",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_loginack_length,
          { "Token length", "tds.loginack.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_loginack_interface,
          { "Interface", "tds.loginack.interface",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_loginack_tdsversion,
          { "TDS version", "tds.loginack.tdsversion",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_loginack_progversion,
          { "Server Version", "tds.loginack.progversion",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(version_convert), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_loginack_progname,
          { "Server name", "tds.loginack.progname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* NBCROW token (TDS_NBCROW_TOKEN) */
        { &hf_tds_nbcrow,
          { "Token - NBCRow", "tds.nbcrow",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* OFFSET token */
        { &hf_tds_offset,
          { "Token - Offset", "tds.offset",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_tds_offset_id,
          { "Offset ID", "tds.offset.id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_tds_offset_len,
          { "Offset length", "tds.offset.len",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        /* ORDER token (TDS_ORDER_TOKEN) */
        { &hf_tds_order,
          { "Token - Order", "tds.order",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_tds_order_length,
          { "Token length", "tds.order.length",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_tds_order_colnum,
          { "Order column", "tds.order.colnum",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        /* RETURNSTATUS token (TDS_RET_STAT_TOKEN) */
        { &hf_tds_returnstatus,
          { "Token - ReturnStatus", "tds.returnstatus",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_returnstatus_value,
          { "Value", "tds.returnstatus.value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /* RETURNVALUE token (TDS_RETURNVAL_TOKEN) */

        /* ROW token (TDS_ROW_TOKEN) */
        { &hf_tds_row,
          { "Token - Row", "tds.row",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_row_field,
          { "Field", "tds.row.field",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* SESSIONSTATE token (TDS_SESSIONSTATE_TOKEN) */
        { &hf_tds_sessionstate,
          { "Token - Session state", "tds.sessionstate",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_sessionstate_length,
          { "Token length", "tds.sessionstate.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_sessionstate_seqno,
          { "Sequence number", "tds.sessionstate.seqno",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_sessionstate_status,
          { "Status", "tds.sessionstate.status",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_sessionstate_stateid,
          { "State ID", "tds.sessionstate.stateid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_sessionstate_statelen,
          { "State Length", "tds.sessionstate.statelen",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_sessionstate_statevalue,
          { "State Value", "tds.sessionstate.statevalue",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* SSPI token */
        { &hf_tds_sspi,
          { "Token - SSPI", "tds.sspi",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_sspi_buffer,
          { "State Value", "tds.sspi.buffer",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* TABNAME token */

        /* TVPROW Token */

        /* TDS5 Lang Token */
        { &hf_tds_lang_token_status,
          { "Status", "tds.lang.token_status",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_lang_language_text,
          { "Language text", "tds.lang.language_text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* Unknown token type */
        { &hf_tds_unknown_tds_token,
          { "Token - Unknown", "tds.unknown_tds_token",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /************************ Message definitions ***********************/

        /* Bulk Load BCP stream */

        /* Bulk Load Update Text/Write Text */

        /* Federated Authentication Token */

        /* LOGIN7 Token */
        { &hf_tds7login_total_size,
          { "Total Packet Length", "tds.7login.total_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "TDS7 Login Packet total packet length", HFILL }
        },
        { &hf_tds7login_version,
          { "TDS version", "tds.7login.version",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_packet_size,
          { "Packet Size", "tds.7login.packet_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_client_version,
          { "Client version", "tds.7login.client_version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_client_pid,
          { "Client PID", "tds.7login.client_pid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_connection_id,
          { "Connection ID", "tds.7login.connection_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_option_flags1,
          { "Option Flags 1", "tds.7login.option_flags1",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_option_flags2,
          { "Option Flags 2", "tds.7login.option_flags2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_sql_type_flags,
          { "SQL Type Flags", "tds.7login.sql_type_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_reserved_flags,
          { "Reserved Flags", "tds.7login.reserved_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_time_zone,
          { "Time Zone", "tds.7login.time_zone",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_collation,
          { "Collation", "tds.7login.collation",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_offset,
          { "Offset", "tds.7login.offset",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_length,
          { "Length", "tds.7login.length",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_password,
          { "Password", "tds.7login.password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_clientname,
          { "Client name", "tds.7login.clientname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_username,
          { "Username", "tds.7login.username",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_appname,
          { "App name", "tds.7login.appname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_servername,
          { "Server name", "tds.7login.servername",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_libraryname,
          { "Library name", "tds.7login.libraryname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_locale,
          { "Locale", "tds.7login.locale",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds7login_databasename,
          { "Database name", "tds.7login.databasename",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* PRELOGIN stream */

        { &hf_tds_prelogin,
          { "Pre-Login Message", "tds.prelogin",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_token,
          { "Option Token", "tds.prelogin.option.token",
            FT_UINT8, BASE_DEC, VALS(prelogin_token_names), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_offset,
          { "Option offset", "tds.prelogin.option.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_length,
          { "Option length", "tds.prelogin.option.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_version,
          { "Version", "tds.prelogin.option.version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_subbuild,
          { "Sub-build", "tds.prelogin.option.subbuild",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_encryption,
          { "Encryption", "tds.prelogin.option.encryption",
            FT_UINT8, BASE_DEC, VALS(prelogin_encryption_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_instopt,
          { "InstOpt", "tds.prelogin.option.instopt",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_threadid,
          { "ThreadID", "tds.prelogin.option.threadid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_mars,
          { "MARS", "tds.prelogin.option.mars",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_traceid,
          { "TraceID", "tds.prelogin.option.traceid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_fedauthrequired,
          { "FedAuthRequired", "tds.prelogin.option.fedauthrequired",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_nonceopt,
          { "NonceOpt", "tds.prelogin.option.nonceopt",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* RPC Request Stream */

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

        /* SQLBatch Stream */
        { &hf_tds_query,
          { "Query", "tds.query",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* SSPI Message Stream */

        /* Transaction Manager Request Stream */
        { &hf_tds_transmgr,
          { "Transaction Manager Request", "tds.transmgr",
            FT_UINT16, BASE_DEC, VALS(transmgr_types), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_transmgr_payload,
          { "Payload", "tds.transmgr.payload",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /****************************** Basic types **********************************/

        { &hf_tds_type_info,
          { "Type info", "tds.type_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "The TYPE_INFO rule applies to several messages used to describe column information", HFILL }
        },
        { &hf_tds_type_info_type,
          { "Type", "tds.type_info.type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_info_varlen,
          { "Maximal length", "tds.type_info.varlen",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Defines the length of the data contained within the column", HFILL }
        },
        { &hf_tds_type_info_precision,
          { "Precision", "tds.type_info.precision",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_info_scale,
          { "Scale", "tds.type_info.scale",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation,
          { "Collation", "tds.type_info.collation",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Specifies collation information for character data or metadata describing character data", HFILL }
        },
        { &hf_tds_type_info_collation_lcid,
          { "LCID", "tds.type_info.collation.lcid",
            FT_UINT32, BASE_HEX, NULL, 0x000FFFFF,
            "For a SortId==0 collation, the LCID bits correspond to a LocaleId as defined by the National Language Support (NLS) functions", HFILL }
        },
        { &hf_tds_type_info_collation_ign_case,
          { "Ignore case", "tds.type_info.collation.ignore_case",
            FT_BOOLEAN, 32, NULL, 0x00100000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_ign_accent,
          { "Ignore accent", "tds.type_info.collation.ignore_accent",
            FT_BOOLEAN, 32, NULL, 0x00200000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_ign_kana,
          { "Ignore kana", "tds.type_info.collation.ignore_kana",
            FT_BOOLEAN, 32, NULL, 0x00400000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_ign_width,
          { "Ignore width", "tds.type_info.collation.ignore_width",
            FT_BOOLEAN, 32, NULL, 0x00800000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_binary,
          { "Binary", "tds.type_info.collation.binary",
            FT_BOOLEAN, 32, NULL, 0x01000000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_version,
          { "Version", "tds.type_info.collation.version",
            FT_UINT32, BASE_DEC, NULL, 0xF0000000,
            NULL, HFILL }
        },
        { &hf_tds_type_info_collation_sortid,
          { "SortId", "tds.type_info.collation.sortid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_length,
          { "Length", "tds.type_varbyte.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_null,
          { "Data: NULL", "tds.type_varbyte.data.null",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_boolean,
          { "Data", "tds.type_varbyte.data.bool",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int1,
          { "Data", "tds.type_varbyte.data.int",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int2,
          { "Data", "tds.type_varbyte.data.int",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int4,
          { "Data", "tds.type_varbyte.data.int",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_int8,
          { "Data", "tds.type_varbyte.data.int64",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_float,
          { "Data", "tds.type_varbyte.data.float",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_double,
          { "Data", "tds.type_varbyte.data.float",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_bytes,
          { "Data", "tds.type_varbyte.data.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_guid,
          { "Data", "tds.type_varbyte.data.guid",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_string,
          { "Data", "tds.type_varbyte.data.string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_absdatetime,
          { "Data", "tds.type_varbyte.data.datetime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_reltime,
          { "Time", "tds.type_varbyte.data.time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_sign,
          { "Sign", "tds.type_varbyte.data.sign",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_plp_len,
          { "PLP length", "tds.type_varbyte.plp_len",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_plp_chunk_len,
          { "PLP chunk length", "tds.type_varbyte.plp_chunk_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /***************************** Top level TDS *******************************/

        { &hf_tds_type,
          { "Type", "tds.type",
            FT_UINT8, BASE_DEC, VALS(packet_type_names), 0x0,
            "Packet type", HFILL }
        },
        { &hf_tds_status,
          { "Status", "tds.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Packet status", HFILL }
        },
        { &hf_tds_status_eom,
          { "End of message", "tds.status.eom",
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
          { "Length", "tds.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Packet length", HFILL }
        },
        { &hf_tds_channel,
          { "Channel", "tds.channel",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Channel Number", HFILL }
        },
        { &hf_tds_packet_number,
          { "Packet Number", "tds.packet_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_window,
          { "Window", "tds.window",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_fragment_overlap,
          { "Segment overlap", "tds.fragment.overlap",
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
          { "Defragmentation error", "tds.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_tds_fragment_count,
          { "Segment count", "tds.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_fragment,
          { "TDS Fragment", "tds.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_fragments,
          { "TDS Fragments", "tds.fragments",
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
        { &hf_tds_all_headers,
          { "Packet data stream headers", "tds.all_headers",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "The ALL_HEADERS rule", HFILL }
        },
        { &hf_tds_all_headers_total_length,
          { "Total length", "tds.all_headers.total_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Total length of ALL_HEADERS stream", HFILL }
        },
        { &hf_tds_all_headers_header_length,
          { "Length", "tds.all_headers.header.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Total length of an individual header", HFILL }
        },
        { &hf_tds_all_headers_header_type,
          { "Type", "tds.all_headers.header.type",
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
        { &hf_tds_unknown_tds_packet,
          { "TDS Packet", "tds.unknown_tds_packet",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_token_len,
          { "Length", "tds.token_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
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
        &ett_tds_prelogin_option,
        &ett_tds_token,
        &ett_tds7_query,
        &ett_tds7_prelogin,
        &ett_tds7_login,
        &ett_tds7_hdr,
        &ett_tds_col,
        &ett_tds_flags,
        &ett_tds7_featureextack,
        &ett_tds7_featureextack_feature
    };

    static ei_register_info ei[] = {
        { &ei_tds_all_headers_header_type, { "tds.all_headers.header.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid header type", EXPFILL }},
        { &ei_tds_type_info_type, { "tds.type_info.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid data type", EXPFILL }},
#if 0
        { &ei_tds_type_info_type_undecoded, { "tds.type_info.type.undecoded", PI_UNDECODED, PI_ERROR, "Data type not supported yet", EXPFILL }},
#endif
        { &ei_tds_invalid_length, { "tds.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
        { &ei_tds_token_length_invalid, { "tds.token.length.invalid", PI_PROTOCOL, PI_WARN, "Bogus token size", EXPFILL }},
#if 0
        { &ei_tds_token_stats, { "tds.token.stats", PI_PROTOCOL, PI_NOTE, "Token stats", EXPFILL }},
#endif
        { &ei_tds_invalid_plp_type, { "tds.type_info.type.invalidplp", PI_PROTOCOL, PI_NOTE, "Invalid PLP type", EXPFILL }}
    };

    module_t *tds_module;
    expert_module_t* expert_tds;

/* Register the protocol name and description */
    proto_tds = proto_register_protocol("Tabular Data Stream", "TDS", "tds");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_tds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_tds = expert_register_protocol(proto_tds);
    expert_register_field_array(expert_tds, ei, array_length(ei));

/* Allow dissector to be found by name. */
    tds_tcp_handle = register_dissector("tds", dissect_tds_message, proto_tds);

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
    register_cleanup_routine(tds_cleanup);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_tds(void)
{
    /* Initial TDS ports: MS SQL default ports */
    dissector_add_uint("tcp.port", 1433, tds_tcp_handle);
    dissector_add_uint("tcp.port", 2433, tds_tcp_handle);

    heur_dissector_add("tcp", dissect_tds_tcp_heur, "Tabular Data Stream over TCP", "tds_tcp", proto_tds, HEURISTIC_ENABLE);

    ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_tds);
    gssapi_handle = find_dissector_add_dependency("gssapi", proto_tds);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
