/* packet-tds.c
 * Routines for TDS NetLib dissection
 * Copyright 2000-2002, Brian Bruns <camber@ais.org>
 * Copyright 2002, Steve Langasek <vorlon@netexpress.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * https://web.archive.org/web/20140611233513/http://www.sybase.com/content/1013412/tds34.pdf
 * https://web.archive.org/web/20140611233501/http://www.sybase.com/content/1040983/Sybase-tds38-102306.pdf
 * Microsoft's [MS-TDS] protocol specification
 *     https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
 * Microsoft's TDS 4.2 [MS-SSTDS] protocol specification
 *     https://docs.microsoft.com/en-us/openspecs/sql_server_protocols/ms-sstds/
 *
 * This document is no longer available here, and does not appear to
 *   have been archived by the Wayback Machine:
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
#include <epan/proto_data.h>

#include <wsutil/epochs.h>

#include <math.h>

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
#define TDS5_QUERY_PKT      15  /* or "Normal tokenized request or response */
#define TDS_LOGIN7_PKT      16  /* or "Urgent tokenized request or response */
#define TDS_SSPI_PKT        17
#define TDS_PRELOGIN_PKT    18
#define TDS_INVALID_PKT     19
#define TDS_TLS_PKT         23
#define TDS_SMP_PKT         83  /* Session Multiplex Protocol; MARS option */

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
#define TDS5_LOGOUT_TOKEN         113  /* 0x71    TDS 5.0 only? ct_close()  */
#define TDS_OFFSET_TOKEN          120  /* 0x78    Removed in TDS 7.2        */
#define TDS_RET_STAT_TOKEN        121  /* 0x79                              */
#define TDS_PROCID_TOKEN          124  /* 0x7C    TDS 4.x only - TDS_PROCID */
#define TDS_CURCLOSE_TOKEN        128  /* 0x80    TDS 5.0 only              */
#define TDS7_COL_METADATA_TOKEN   129  /* 0x81                              */
#define TDS_CURFETCH_TOKEN        130  /* 0x82    TDS 5.0 only              */
#define TDS_CURINFO_TOKEN         131  /* 0x83    TDS 5.0 only              */
#define TDS_CUROPEN_TOKEN         132  /* 0x84    TDS 5.0 only              */
#define TDS_CURDECLARE_TOKEN      134  /* 0x86    TDS 5.0 only              */
#define TDS7_ALTMETADATA_TOKEN    136  /* 0x88                              */
#define TDS_COL_NAME_TOKEN        160  /* 0xA0    TDS 4.x only              */
#define TDS_COLFMT_TOKEN          161  /* 0xA1    TDS 4.2 only - TDS_COLFMT */
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
#define TDS_CONTROL_TOKEN         174  /* 0xAE    TDS 4.x only              */
#define TDS_FEATUREEXTACK_TOKEN   174  /* 0xAE    Introduced TDS 7.4        */
#define TDS_KEY_TOKEN             202  /* 0xCA                        [###] */
#define TDS_ROW_TOKEN             209  /* 0xD1                              */
#define TDS_NBCROW_TOKEN          210  /* 0xD2    Introduced TDS 7.3        */
#define TDS_ALTROW_TOKEN          211  /* 0xD3                              */
#define TDS5_PARAMS_TOKEN         215  /* 0xD7    TDS 5.0 only              */
#define TDS_CAPABILITY_TOKEN      226  /* 0xE2                              */
#define TDS_ENVCHG_TOKEN          227  /* 0xE3                              */
#define TDS_SESSIONSTATE_TOKEN    228  /* 0xE4    Introduced TDS 7.4        */
#define TDS5_EED_TOKEN            229  /* 0xE5    TDS 5.0 only              */
#define TDS5_DBRPC_TOKEN          230  /* 0xE6                              */
#define TDS5_DYNAMIC_TOKEN        231  /* 0xE7    TDS 5.0 only              */
#define TDS5_PARAMFMT_TOKEN       236  /* 0xEC    TDS 5.0 only              */
#define TDS_AUTH_TOKEN            237  /* 0xED                              */  /* DUPLICATE! */
#define TDS_SSPI_TOKEN            237  /* 0xED                              */  /* DUPLICATE! */
#define TDS5_ROWFMT_TOKEN         238  /* 0xEE    TDS 5.0 only              */  /* DUPLICATE! */
#define TDS_FEDAUTHINFO_TOKEN     238  /* 0xEE    Introduced TDS 7.4        */  /* DUPLICATE! */
#define TDS_DONE_TOKEN            253  /* 0xFD                              */
#define TDS_DONEPROC_TOKEN        254  /* 0xFE                              */
#define TDS_DONEINPROC_TOKEN      255  /* 0xFF                              */

/* Capabilty token fields (TDS5) */
#define TDS_CAP_REQUEST                      1
#define TDS_CAP_RESPONSE                     2

/* TDS 5 Cursor fetch options */
#define TDS_CUR_NEXT                         1
#define TDS_CUR_PREV                         2
#define TDS_CUR_FIRST                        3
#define TDS_CUR_LAST                         4
#define TDS_CUR_ABS                          5
#define TDS_CUR_REL                          6

/* TDS 5 Cursor Info Commands */
#define TDS_CURINFO_SET_FETCH_COUNT          1
#define TDS_CURINFO_INQUIRE                  2
#define TDS_CURINFO_INFORM                   3
#define TDS_CURINFO_LISTALL                  4

/* TDS 7 Prelogin options */
#define TDS7_PRELOGIN_OPTION_VERSION         0x00
#define TDS7_PRELOGIN_OPTION_ENCRYPTION      0x01
#define TDS7_PRELOGIN_OPTION_INSTOPT         0x02
#define TDS7_PRELOGIN_OPTION_THREADID        0x03
#define TDS7_PRELOGIN_OPTION_MARS            0x04
#define TDS7_PRELOGIN_OPTION_TRACEID         0x05
#define TDS7_PRELOGIN_OPTION_FEDAUTHREQUIRED 0x06
#define TDS7_PRELOGIN_OPTION_NONCEOPT        0x07
#define TDS7_PRELOGIN_OPTION_TERMINATOR      0xff

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
#define SYBLONGCHAR   175  /* 0xAF */
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
#define TDS_DATA_TYPE_DECIMAL         0x37  /* 55 = Decimal (TDS 4/5) */
#define TDS_DATA_TYPE_NUMERIC         0x3F  /* 63 = Numeric (TDS 4/5) */
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
#define TDS_DATA_TYPE_CHAR            0x2F  /* 47 = Char (TDS 4/5) */
#define TDS_DATA_TYPE_VARCHAR         0x27  /* 39 = VarChar (TDS 4/5) */
#define TDS_DATA_TYPE_BINARY          0x2D  /* 45 = Binary (TDS 4/5) */
#define TDS_DATA_TYPE_VARBINARY       0x25  /* 37 = VarBinary (TDS 4/5) */
/* USHORTLEN_TYPE */
#define TDS_DATA_TYPE_BIGVARBIN       0xA5  /* 165 = VarBinary */
#define TDS_DATA_TYPE_BIGVARCHR       0xA7  /* 167 = VarChar */
#define TDS_DATA_TYPE_BIGBINARY       0xAD  /* 173 = Binary */
#define TDS_DATA_TYPE_BIGCHAR         0xAF  /* 175 = Char, AKA SYBLONGCHAR (TDS 5) */
#define TDS_DATA_TYPE_NVARCHAR        0xE7  /* 231 = NVarChar */
#define TDS_DATA_TYPE_NCHAR           0xEF  /* 239 = NChar */
/* LONGLEN_TYPE */
#define TDS_DATA_TYPE_XML             0xF1  /* 241 = XML (introduced in TDS 7.2) */
#define TDS_DATA_TYPE_UDT             0xF0  /* 240 = CLR-UDT (introduced in TDS 7.2) */
#define TDS_DATA_TYPE_TEXT            0x23  /* 35 = Text */
#define TDS_DATA_TYPE_IMAGE           0x22  /* 34 = Image */
#define TDS_DATA_TYPE_LONGBINARY      0xE1  /* 225 = Long Binary (TDS 5.0) */
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

#define is_longlen_type_sybase(x)  ((x)==SYBLONGCHAR ||             \
                                    (x)==SYBLONGBINARY              \
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

#define is_numeric_type_tds(x)     ((x)==TDS_DATA_TYPE_NUMERIC ||   \
                                    (x)==TDS_DATA_TYPE_NUMERICN ||  \
                                    (x)==TDS_DATA_TYPE_DECIMAL ||   \
                                    (x)==TDS_DATA_TYPE_DECIMALN     \
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

#define is_image_type_tds(x)      ((x)==TDS_DATA_TYPE_TEXT            ||  \
                                   (x)==TDS_DATA_TYPE_IMAGE           ||  \
                                   (x)==TDS_DATA_TYPE_NTEXT               \
                                  )

#define TDS_GEN_NULL        0x00U
#define TDS_CHARBIN_NULL    0xFFFFU
#define TDS_CHARBIN_NULL32  0xFFFFFFFFU

#define TDS_PLP_TERMINATOR  G_GUINT64_CONSTANT(0x0000000000000000)
#define TDS_UNKNOWN_PLP_LEN G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFE)
#define TDS_PLP_NULL        G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)

/* Fixed field lengths */

#define TDS_MAXNAME         30
#define TDS_RPLEN           255
#define TDS_PROGNLEN        10
#define TDS_PKTLEN          6

/* Encodings */

#define TDS_INT2_BIG_ENDIAN     2
#define TDS_INT2_LITTLE_ENDIAN  3
#define TDS_INT4_BIG_ENDIAN     0
#define TDS_INT4_LITTLE_ENDIAN  1
#define TDS_FLT8_BIG_ENDIAN     4
#define TDS_FLT8_VAX_D          5
#define TDS_FLT8_LITTLE_ENDIAN  10
#define TDS_FLT8_ND5000         11
#define TDS_CHAR_ASCII          6
#define TDS_CHAR_EBCDIC         7
#define TDS_DATE4_TIME_FIRST    16
#define TDS_DATE4_DATE_FIRST    17
#define TDS_DATE8_TIME_FIRST    8
#define TDS_DATE8_DATE_FIRST    9
/* Artificial, for TDS 7 */
#define TDS_CHAR_UTF16         120

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
    {TDS_DATA_TYPE_DECIMAL,         "DECIMALTYPE - Decimal (TDS 4/5)"},
    {TDS_DATA_TYPE_NUMERIC,         "NUMERICTYPE - Numeric (TDS 4/5)"},
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
    {TDS_DATA_TYPE_CHAR,            "CHARTYPE - Char (TDS 4/5)"},
    {TDS_DATA_TYPE_VARCHAR,         "VARCHARTYPE - VarChar (TDS 4/5)"},
    {TDS_DATA_TYPE_BINARY,          "BINARYTYPE - Binary (TDS 4/5)"},
    {TDS_DATA_TYPE_VARBINARY,       "VARBINARYTYPE - VarBinary (TDS 4/5)"},
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
    {TDS_DATA_TYPE_LONGBINARY,      "LONGBINARY - Binary"},
    {TDS_DATA_TYPE_NTEXT,           "NTEXTTYPE - NText"},
    {TDS_DATA_TYPE_SSVARIANT,       "SSVARIANTTYPE - Sql_Variant (introduced in TDS 7.2)"},
    {0, NULL }
};

void proto_reg_handoff_tds(void);
void proto_register_tds(void);

#define TDS_PORT_RANGE "1433,2433" /* Not IANA registered */

/************************ Message definitions ***********************/

/* Bulk Load BCP stream */

/* Bulk Load Update Text/Write Text */

/* Federated Authentication Token */

/* LOGIN fields */

static int hf_tdslogin = -1;
static int hf_tdslogin_hostname_length = -1;
static int hf_tdslogin_hostname = -1;
static int hf_tdslogin_username_length = -1;
static int hf_tdslogin_username = -1;
static int hf_tdslogin_password_length = -1;
static int hf_tdslogin_password = -1;
static int hf_tdslogin_hostprocess_length = -1;
static int hf_tdslogin_hostprocess = -1;
static int hf_tdslogin_appname_length = -1;
static int hf_tdslogin_appname = -1;
static int hf_tdslogin_servername_length = -1;
static int hf_tdslogin_servername = -1;
static int hf_tdslogin_remotepassword_length = -1;
static int hf_tdslogin_rempw_servername_length = -1;
static int hf_tdslogin_rempw_servername = -1;
static int hf_tdslogin_rempw_password_length = -1;
static int hf_tdslogin_rempw_password = -1;
static int hf_tdslogin_option_int2 = -1;
static int hf_tdslogin_option_int4 = -1;
static int hf_tdslogin_option_char = -1;
static int hf_tdslogin_option_float = -1;
static int hf_tdslogin_option_date8 = -1;
static int hf_tdslogin_option_usedb = -1;
static int hf_tdslogin_option_bulk = -1;
static int hf_tdslogin_option_server_to_server = -1;
static int hf_tdslogin_option_server_to_server_loginack = -1;
static int hf_tdslogin_option_conversation_type = -1;
static int hf_tdslogin_proto_version = -1;
static int hf_tdslogin_progname_length = -1;
static int hf_tdslogin_progname = -1;
static int hf_tdslogin_progvers = -1;
static int hf_tdslogin_option2_noshort = -1;
static int hf_tdslogin_option2_flt4 = -1;
static int hf_tdslogin_option2_date4 = -1;
static int hf_tdslogin_language = -1;
static int hf_tdslogin_language_length = -1;
static int hf_tdslogin_setlang = -1;
static int hf_tdslogin_seclogin = -1;
static int hf_tdslogin_secbulk = -1;
static int hf_tdslogin_halogin = -1;
static int hf_tdslogin_hasessionid = -1;
static int hf_tdslogin_charset = -1;
static int hf_tdslogin_charset_length = -1;
static int hf_tdslogin_setcharset = -1;
static int hf_tdslogin_packetsize = -1;
static int hf_tdslogin_packetsize_length = -1;

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

/* CAPABILITY token */
static int hf_tds_capability = -1;
static int hf_tds_capability_length = -1;
static int hf_tds_capability_captype = -1;
static int hf_tds_capability_caplen = -1;
static int hf_tds_capability_req_lang = -1;
static int hf_tds_capability_req_rpc = -1;
static int hf_tds_capability_req_evt = -1;
static int hf_tds_capability_req_mstmt = -1;
static int hf_tds_capability_req_bcp = -1;
static int hf_tds_capability_req_cursor = -1;
static int hf_tds_capability_req_dynf = -1;
static int hf_tds_capability_req_msg = -1;
static int hf_tds_capability_req_param = -1;
static int hf_tds_capability_data_int1 = -1;
static int hf_tds_capability_data_int2 = -1;
static int hf_tds_capability_data_int4 = -1;
static int hf_tds_capability_data_bit = -1;
static int hf_tds_capability_data_char = -1;
static int hf_tds_capability_data_vchar = -1;
static int hf_tds_capability_data_bin = -1;
static int hf_tds_capability_data_vbin = -1;
static int hf_tds_capability_data_mny8 = -1;
static int hf_tds_capability_data_mny4 = -1;
static int hf_tds_capability_data_date8 = -1;
static int hf_tds_capability_data_date4 = -1;
static int hf_tds_capability_data_flt4 = -1;
static int hf_tds_capability_data_flt8 = -1;
static int hf_tds_capability_data_num = -1;
static int hf_tds_capability_data_text = -1;
static int hf_tds_capability_data_image = -1;
static int hf_tds_capability_data_dec = -1;
static int hf_tds_capability_data_lchar = -1;
static int hf_tds_capability_data_lbin = -1;
static int hf_tds_capability_data_intn = -1;
static int hf_tds_capability_data_datetimen = -1;
static int hf_tds_capability_data_moneyn = -1;
static int hf_tds_capability_csr_prev = -1;
static int hf_tds_capability_csr_first = -1;
static int hf_tds_capability_csr_last = -1;
static int hf_tds_capability_csr_abs = -1;
static int hf_tds_capability_csr_rel = -1;
static int hf_tds_capability_csr_multi = -1;
static int hf_tds_capability_con_oob = -1;
static int hf_tds_capability_con_inband = -1;
static int hf_tds_capability_con_logical = -1;
static int hf_tds_capability_proto_text = -1;
static int hf_tds_capability_proto_bulk = -1;
static int hf_tds_capability_req_urgevt = -1;
static int hf_tds_capability_data_sensitivity = -1;
static int hf_tds_capability_data_boundary = -1;
static int hf_tds_capability_proto_dynamic = -1;
static int hf_tds_capability_proto_dynproc = -1;
static int hf_tds_capability_data_fltn = -1;
static int hf_tds_capability_data_bitn = -1;
static int hf_tds_capability_data_int8 = -1;
static int hf_tds_capability_data_void = -1;
static int hf_tds_capability_dol_bulk = -1;
static int hf_tds_capability_object_java1 = -1;
static int hf_tds_capability_object_char = -1;
static int hf_tds_capability_data_columnstatus = -1;
static int hf_tds_capability_object_binary = -1;
static int hf_tds_capability_widetable = -1;
static int hf_tds_capability_data_uint2 = -1;
static int hf_tds_capability_data_uint4 = -1;
static int hf_tds_capability_data_uint8 = -1;
static int hf_tds_capability_data_uintn = -1;
static int hf_tds_capability_cur_implicit = -1;
static int hf_tds_capability_data_nlbin = -1;
static int hf_tds_capability_image_nchar = -1;
static int hf_tds_capability_blob_nchar_16 = -1;
static int hf_tds_capability_blob_nchar_8 = -1;
static int hf_tds_capability_blob_nchar_scsu = -1;
static int hf_tds_capability_data_date = -1;
static int hf_tds_capability_data_time = -1;
static int hf_tds_capability_data_interval = -1;
static int hf_tds_capability_csr_scroll = -1;
static int hf_tds_capability_csr_sensitive = -1;
static int hf_tds_capability_csr_insensitive = -1;
static int hf_tds_capability_csr_semisensitive = -1;
static int hf_tds_capability_csr_keysetdriven = -1;
static int hf_tds_capability_req_srvpktsize = -1;
static int hf_tds_capability_data_unitext = -1;
static int hf_tds_capability_cap_clusterfailover = -1;
static int hf_tds_capability_data_sint1 = -1;
static int hf_tds_capability_req_largeident = -1;
static int hf_tds_capability_req_blob_nchar_16 = -1;
static int hf_tds_capability_data_xml = -1;
static int hf_tds_capability_req_curinfo3 = -1;
static int hf_tds_capability_req_dbrpc2 = -1;
static int hf_tds_capability_res_nomsg = -1;
static int hf_tds_capability_res_noeed = -1;
static int hf_tds_capability_res_noparam = -1;
static int hf_tds_capability_data_noint1 = -1;
static int hf_tds_capability_data_noint2 = -1;
static int hf_tds_capability_data_noint4 = -1;
static int hf_tds_capability_data_nobit = -1;
static int hf_tds_capability_data_nochar = -1;
static int hf_tds_capability_data_novchar = -1;
static int hf_tds_capability_data_nobin = -1;
static int hf_tds_capability_data_novbin = -1;
static int hf_tds_capability_data_nomny8 = -1;
static int hf_tds_capability_data_nomny4 = -1;
static int hf_tds_capability_data_nodate8 = -1;
static int hf_tds_capability_data_nodate4 = -1;
static int hf_tds_capability_data_noflt4 = -1;
static int hf_tds_capability_data_noflt8 = -1;
static int hf_tds_capability_data_nonum = -1;
static int hf_tds_capability_data_notext = -1;
static int hf_tds_capability_data_noimage = -1;
static int hf_tds_capability_data_nodec = -1;
static int hf_tds_capability_data_nolchar = -1;
static int hf_tds_capability_data_nolbin = -1;
static int hf_tds_capability_data_nointn = -1;
static int hf_tds_capability_data_nodatetimen = -1;
static int hf_tds_capability_data_nomoneyn = -1;
static int hf_tds_capability_con_nooob = -1;
static int hf_tds_capability_con_noinband = -1;
static int hf_tds_capability_proto_notext = -1;
static int hf_tds_capability_proto_nobulk = -1;
static int hf_tds_capability_data_nosensitivity = -1;
static int hf_tds_capability_data_noboundary = -1;
static int hf_tds_capability_res_notdsdebug = -1;
static int hf_tds_capability_res_nostripblanks = -1;
static int hf_tds_capability_data_noint8 = -1;
static int hf_tds_capability_object_nojava1 = -1;
static int hf_tds_capability_object_nochar = -1;
static int hf_tds_capability_data_nocolumnstatus = -1;
static int hf_tds_capability_object_nobinary = -1;
static int hf_tds_capability_data_nouint2 = -1;
static int hf_tds_capability_data_nouint4 = -1;
static int hf_tds_capability_data_nouint8 = -1;
static int hf_tds_capability_data_nouintn = -1;
static int hf_tds_capability_no_widetables = -1;
static int hf_tds_capability_data_nonlbin = -1;
static int hf_tds_capability_image_nonchar = -1;
static int hf_tds_capability_blob_nonchar_16 = -1;
static int hf_tds_capability_blob_nonchar_8 = -1;
static int hf_tds_capability_blob_nonchar_scsu = -1;
static int hf_tds_capability_data_nodate = -1;
static int hf_tds_capability_data_notime = -1;
static int hf_tds_capability_data_nointerval = -1;
static int hf_tds_capability_data_nounitext = -1;
static int hf_tds_capability_data_nosint1 = -1;
static int hf_tds_capability_no_largeident = -1;
static int hf_tds_capability_no_blob_nchar_16 = -1;
static int hf_tds_capability_no_srvpktsize = -1;
static int hf_tds_capability_data_noxml = -1;
static int hf_tds_capability_no_nint_return_value = -1;
static int hf_tds_capability_res_noxnldata = -1;
static int hf_tds_capability_res_suppress_fmt = -1;
static int hf_tds_capability_res_suppress_doneinproc = -1;
static int hf_tds_capability_res_force_rowfmt2 = -1;

/* COLINFO token (TDS_COLFMT_TOKEN) */
static int hf_tds_colfmt = -1;
static int hf_tds_colfmt_length = -1;
static int hf_tds_colfmt_column = -1;
static int hf_tds_colfmt_utype = -1;
static int hf_tds_colfmt_ctype = -1;
static int hf_tds_colfmt_csize = -1;
static int hf_tds_colfmt_csize_long = -1;
static int hf_tds_colfmt_text_tablename = -1;

/* COLNAME token (TDS_COL_NAME_TOKEN) */
static int hf_tds_colname = -1;
static int hf_tds_colname_length = -1;
static int hf_tds_colname_column = -1;
static int hf_tds_colname_name = -1;

/* COLMETADATA token (TDS7_COL_METADATA_TOKEN) */
static int hf_tds_colmetadata = -1;
static int hf_tds_colmetadata_results_token_flags = -1;
static int hf_tds_colmetadata_columns = -1;
static int hf_tds_colmetadata_large2_type_size = -1;
static int hf_tds_colmetadata_large4_type_size = -1;
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

/* CONTROL token (TDS_CONTROL_TOKEN) */
static int hf_tds_control = -1;
static int hf_tds_control_length = -1;
static int hf_tds_control_fmt = -1;

/* CURCLOSE token (TDS_CURCLOSE_TOKEN) */
static int hf_tds_curclose = -1;
static int hf_tds_curclose_length = -1;
static int hf_tds_curclose_cursorid = -1;
static int hf_tds_curclose_cursor_name = -1;
static int hf_tds_curclose_option_deallocate = -1;

/* CURDECLARE token (TDS_CURDECLARE_TOKEN) */
static int hf_tds_curdeclare = -1;
static int hf_tds_curdeclare_length = -1;
static int hf_tds_curdeclare_cursor_name = -1;
static int hf_tds_curdeclare_options = -1;
static int hf_tds_curdeclare_options_rdonly = -1;
static int hf_tds_curdeclare_options_updatable = -1;
static int hf_tds_curdeclare_options_sensitive = -1;
static int hf_tds_curdeclare_options_dynamic = -1;
static int hf_tds_curdeclare_options_implicit = -1;
static int hf_tds_curdeclare_status_parameterized = -1;
static int hf_tds_curdeclare_statement = -1;
static int hf_tds_curdeclare_update_columns_num = -1;
static int hf_tds_curdeclare_update_columns_name = -1;

/* CURFETCH token (TDS_CURFETCH_TOKEN) */
static int hf_tds_curfetch = -1;
static int hf_tds_curfetch_length = -1;
static int hf_tds_curfetch_cursorid = -1;
static int hf_tds_curfetch_cursor_name = -1;
static int hf_tds_curfetch_type = -1;
static int hf_tds_curfetch_rowcnt = -1;

/* CURINFO token (TDS_CURINFO_TOKEN) */
static int hf_tds_curinfo = -1;
static int hf_tds_curinfo_length = -1;
static int hf_tds_curinfo_cursorid = -1;
static int hf_tds_curinfo_cursor_name = -1;
static int hf_tds_curinfo_cursor_command = -1;
static int hf_tds_curinfo_cursor_status = -1;
static int hf_tds_curinfo_cursor_status_declared = -1;
static int hf_tds_curinfo_cursor_status_open = -1;
static int hf_tds_curinfo_cursor_status_closed = -1;
static int hf_tds_curinfo_cursor_status_rdonly = -1;
static int hf_tds_curinfo_cursor_status_updatable = -1;
static int hf_tds_curinfo_cursor_status_rowcnt = -1;
static int hf_tds_curinfo_cursor_status_dealloc = -1;
static int hf_tds_curinfo_cursor_rowcnt = -1;

/* CUROPEN token (TDS_CUROPEN_TOKEN) */
static int hf_tds_curopen = -1;
static int hf_tds_curopen_length = -1;
static int hf_tds_curopen_cursorid = -1;
static int hf_tds_curopen_cursor_name = -1;
static int hf_tds_curopen_status_parameterized = -1;

/* TDS5 DBRPC Token (TDS5_DBRPC_TOKEN) */
static int hf_tds_dbrpc = -1;
static int hf_tds_dbrpc_length = -1;
static int hf_tds_dbrpc_rpcname_len = -1;
static int hf_tds_dbrpc_rpcname = -1;
static int hf_tds_dbrpc_options = -1;
static int hf_tds_dbrpc_options_recompile = -1;
static int hf_tds_dbrpc_options_params = -1;

/* DONE token (TDS_DONE_TOKEN) */
static int hf_tds_done = -1;
static int hf_tds_done_curcmd = -1;
static int hf_tds_done_status = -1;
static int hf_tds_done_status_more = -1;
static int hf_tds_done_status_error = -1;
static int hf_tds_done_status_inxact = -1;
static int hf_tds_done_status_proc = -1;
static int hf_tds_done_status_count = -1;
static int hf_tds_done_status_attn = -1;
static int hf_tds_done_status_event = -1;
static int hf_tds_done_status_rpcinbatch = -1;
static int hf_tds_done_status_srverror = -1;
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

/* EED token (TDS5_EED_TOKEN) */
static int hf_tds_eed = -1;
static int hf_tds_eed_length = -1;
static int hf_tds_eed_number = -1;
static int hf_tds_eed_state = -1;
static int hf_tds_eed_class = -1;
static int hf_tds_eed_sql_state = -1;
static int hf_tds_eed_status = -1;
static int hf_tds_eed_transtate = -1;
static int hf_tds_eed_msgtext = -1;
static int hf_tds_eed_servername = -1;
static int hf_tds_eed_procname = -1;
static int hf_tds_eed_linenumber = -1;

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

/* LOGOUT token (TDS5_LOGOUT_TOKEN) */
static int hf_tds_logout = -1;
static int hf_tds_logout_options = -1;

/* MSG token (TDS5_MSG_TOKEN) */
static int hf_tds_msg = -1;
static int hf_tds_msg_length = -1;
static int hf_tds_msg_status = -1;
static int hf_tds_msg_msgid = -1;

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

/* PARAMFMT token (TDS5_PARAMFMT_TOKEN) */
static int hf_tds_paramfmt = -1;
static int hf_tds_paramfmt_length = -1;
static int hf_tds_paramfmt_numparams = -1;
static int hf_tds_paramfmt_colname = -1;
static int hf_tds_paramfmt_status = -1;
static int hf_tds_paramfmt_utype = -1;
static int hf_tds_paramfmt_ctype = -1;
static int hf_tds_paramfmt_csize = -1;
static int hf_tds_paramfmt_locale_info = -1;

/* PARAMFMT2 token (TDS5_PARAM_TOKEN) */
static int hf_tds_paramfmt2 = -1;
static int hf_tds_paramfmt2_length = -1;
static int hf_tds_paramfmt2_numparams = -1;
static int hf_tds_paramfmt2_colname = -1;
static int hf_tds_paramfmt2_status = -1;
static int hf_tds_paramfmt2_utype = -1;
static int hf_tds_paramfmt2_ctype = -1;
static int hf_tds_paramfmt2_csize = -1;
static int hf_tds_paramfmt2_locale_info = -1;

/* PARAMS token (TDS5_PARAMS_TOKEN) */
static int hf_tds_params = -1;
static int hf_tds_params_field = -1;

/* PROCID token (TDS_PROCID_TOKEN) */
static int hf_tds_procid = -1;
static int hf_tds_procid_value = -1;

/* RETURNSTATUS token (TDS_RET_STAT_TOKEN) */
static int hf_tds_returnstatus = -1;
static int hf_tds_returnstatus_value = -1;

/* RETURNVALUE token (TDS_RETURNVAL_TOKEN) */

/* ROW token (TDS_ROW_TOKEN) */
static int hf_tds_row = -1;
static int hf_tds_row_field = -1;

/* ROWFMT token (TDS5_ROWFMT_TOKEN) */
static int hf_tds_rowfmt = -1;
static int hf_tds_rowfmt_length = -1;
static int hf_tds_rowfmt_numcols = -1;
static int hf_tds_rowfmt_colname = -1;
static int hf_tds_rowfmt_status = -1;
static int hf_tds_rowfmt_utype = -1;
static int hf_tds_rowfmt_ctype = -1;
static int hf_tds_rowfmt_csize = -1;
static int hf_tds_rowfmt_text_tablename = -1;
static int hf_tds_rowfmt_precision = -1;
static int hf_tds_rowfmt_scale = -1;
static int hf_tds_rowfmt_locale_info = -1;

/* ROWFMT2 token (TDS5_ROW_TOKEN) */
static int hf_tds_rowfmt2 = -1;
static int hf_tds_rowfmt2_length = -1;
static int hf_tds_rowfmt2_numcols = -1;
static int hf_tds_rowfmt2_labelname = -1;
static int hf_tds_rowfmt2_catalogname = -1;
static int hf_tds_rowfmt2_schemaname = -1;
static int hf_tds_rowfmt2_tablename = -1;
static int hf_tds_rowfmt2_colname = -1;
static int hf_tds_rowfmt2_status = -1;
static int hf_tds_rowfmt2_utype = -1;
static int hf_tds_rowfmt2_ctype = -1;
static int hf_tds_rowfmt2_csize = -1;
static int hf_tds_rowfmt2_text_tablename = -1;
static int hf_tds_rowfmt2_precision = -1;
static int hf_tds_rowfmt2_scale = -1;
static int hf_tds_rowfmt2_locale_info = -1;

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

/* TDS5 LANG Token */
static int hf_tds_lang_length = -1;
static int hf_tds_lang_language_text = -1;
static int hf_tds_lang_token_status = -1;
static int hf_tds_lang_status_parameterized = -1;

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
static int hf_tds_type_varbyte_data_uint_bytes = -1;
static int hf_tds_type_varbyte_data_guid = -1;
static int hf_tds_type_varbyte_data_string = -1;
static int hf_tds_type_varbyte_data_uint_string = -1;
static int hf_tds_type_varbyte_data_absdatetime = -1;
static int hf_tds_type_varbyte_data_reltime = -1;
static int hf_tds_type_varbyte_data_sign = -1;
static int hf_tds_type_varbyte_data_textptr_len = -1;
static int hf_tds_type_varbyte_data_textptr = -1;
static int hf_tds_type_varbyte_data_text_ts = -1;
static int hf_tds_type_varbyte_plp_len = -1;
static int hf_tds_type_varbyte_plp_chunk_len = -1;
static int hf_tds_type_varbyte_plp_chunk = -1;
static int hf_tds_type_varbyte_column_name = -1;

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

/* Initialize the subtree pointers */
static gint ett_tds = -1;
static gint ett_tds_status = -1;
static gint ett_tds_fragments = -1;
static gint ett_tds_fragment = -1;
static gint ett_tds_token = -1;
static gint ett_tds_capability_req = -1;
static gint ett_tds_capability_resp = -1;
static gint ett_tds_done_status = -1;
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
static gint ett_tds_login = -1;
static gint ett_tds_login_options = -1;
static gint ett_tds_login_options2= -1;
static gint ett_tds_login_rempw = -1;
static gint ett_tds7_login = -1;
static gint ett_tds7_hdr = -1;
static gint ett_tds_col = -1;
static gint ett_tds_flags = -1;
static gint ett_tds_prelogin_option = -1;
static gint ett_tds7_featureextack = -1;
static gint ett_tds7_featureextack_feature = -1;
static gint ett_tds5_dbrpc_options = -1;
static gint ett_tds5_curdeclare_options = -1;
static gint ett_tds5_curinfo_status = -1;

/* static expert_field ei_tds_type_info_type_undecoded = EI_INIT; */
static expert_field ei_tds_invalid_length = EI_INIT;
static expert_field ei_tds_token_length_invalid = EI_INIT;
static expert_field ei_tds_invalid_plp_length = EI_INIT;
static expert_field ei_tds_type_info_type = EI_INIT;
static expert_field ei_tds_all_headers_header_type = EI_INIT;
/* static expert_field ei_tds_token_stats = EI_INIT; */
static expert_field ei_tds_invalid_plp_type = EI_INIT;
static expert_field ei_tds_cursor_name_mismatch = EI_INIT;

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
static dissector_handle_t smp_handle;

#define TDS_CURSOR_NAME_VALID           0x01
#define TDS_CURSOR_ID_VALID             0x02
#define TDS_CURSOR_ROWINFO_VALID        0x04
#define TDS_CURSOR_IN_CONV_TABLE        0x08
#define TDS_CURSOR_FETCH_PENDING        0x10

typedef struct {
    const char          *tds_cursor_name;
    guint                tds_cursor_id;
    struct _netlib_data *tds_cursor_rowinfo;
    guint                tds_cursor_flags;
} tds_cursor_info_t;

typedef struct {
    tds_cursor_info_t *tds_conv_cursor_current;
    wmem_tree_t       *tds_conv_cursor_table;
} tds_conv_cursor_info_t;

typedef struct {
    tds_conv_cursor_info_t *tds_conv_cursor_info;
    gint tds_version;
    guint tds_encoding_int2;
    guint tds_encoding_int4;
    guint tds_encoding_char;
    guint tds_encoding_date8;
    guint tds_encoding_date4;
    gboolean tds_packets_in_order;
} tds_conv_info_t;

/* The actual TDS protocol values used on the wire. */
#define TDS_PROTOCOL_VALUE_4_2   0x04020000
#define TDS_PROTOCOL_VALUE_4_6   0x04060000
#define TDS_PROTOCOL_VALUE_5     0x05000000
#define TDS_PROTOCOL_VALUE_7_0   0x07000000
#define TDS_PROTOCOL_VALUE_7_1   0x07010000
#define TDS_PROTOCOL_VALUE_7_1_1 0x71000001
#define TDS_PROTOCOL_VALUE_7_2   0x72090002
#define TDS_PROTOCOL_VALUE_7_3A  0x730A0003
#define TDS_PROTOCOL_VALUE_7_3B  0x730B0003
#define TDS_PROTOCOL_VALUE_7_4   0x74000004

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
    {"tds4", "TDS 4.x", TDS_PROTOCOL_4},
    {"tds5", "TDS 5.0", TDS_PROTOCOL_5},
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

#define TDS_PROTO_LESS_THAN_TDS7(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ? ((tds_info)->tds_version <= TDS_PROTOCOL_7_0) \
                                          : (tds_protocol_type <= TDS_PROTOCOL_7_0))
#define TDS_PROTO_TDS5(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ? ((tds_info)->tds_version == TDS_PROTOCOL_5) \
                                          : (tds_protocol_type == TDS_PROTOCOL_5))
#define TDS_PROTO_TDS7(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ? ((tds_info)->tds_version >= TDS_PROTOCOL_7_0) && \
                                            ((tds_info)->tds_version <= TDS_PROTOCOL_7_4) \
                                          : (tds_protocol_type >= TDS_PROTOCOL_7_0 && \
                                             tds_protocol_type <= TDS_PROTOCOL_7_4))
#define TDS_PROTO_TDS7_1_OR_LESS(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ?  ((tds_info)->tds_version <= TDS_PROTOCOL_7_1) \
                                          :  (tds_protocol_type <= TDS_PROTOCOL_7_1))
#define TDS_PROTO_TDS7_2_OR_GREATER(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ? ((tds_info)->tds_version >= TDS_PROTOCOL_7_2) \
                                          : (tds_protocol_type >= TDS_PROTOCOL_7_2))
#define TDS_PROTO_TDS7_3A_OR_LESS(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ? ((tds_info)->tds_version <= TDS_PROTOCOL_7_3A) \
                                          : (tds_protocol_type <= TDS_PROTOCOL_7_3A))
#define TDS_PROTO_TDS7_3B_OR_GREATER(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ? (tds_info->tds_version >= TDS_PROTOCOL_7_3B) \
                                          : (tds_protocol_type >= TDS_PROTOCOL_7_3B))
#define TDS_PROTO_TDS7_4_OR_GREATER(tds_info) \
            (TDS_PROTO_PREF_NOT_SPECIFIED ? ((tds_info)->tds_version >= TDS_PROTOCOL_7_4) \
                                          : (tds_protocol_type >= TDS_PROTOCOL_7_4))

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
    {TDS_LOGIN_PKT,       "TDS4/5 login"},
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
    {TDS5_QUERY_PKT,      "TDS5 query"},
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
#define is_valid_tds_status(x) ((x) == 0x00 || /* Normal, not last buffer */ \
                                (x) == 0x01 || /* Normal, last buffer */     \
                                (x) == 0x02 || /* TDS7: Attention ack, but not last buffer. TDS45 invalid. */ \
                                (x) == 0x03 || /* TDS7: Attention Ack, last buffer. */ \
                                (x) == 0x05 || /* TDS45: Attention, last buffer */ \
                                (x) == 0x09 || /* TDS45: Event, last buffer. TDS7: Reset connection, last buffer */ \
                                (x) == 0x11 || /* TDS45: Seal, last buffer. TDS7: Reset connection skip tran, last buffer */ \
                                (x) == 0x21)   /* TDS45: Encrypt, last buffer. */

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
    {TDS5_LOGOUT_TOKEN,         "Logout"},
    {TDS_RET_STAT_TOKEN,        "Return Status"},
    {TDS_PROCID_TOKEN,          "Proc ID"},
    {TDS_COL_NAME_TOKEN,        "Column Names"},
    {TDS_COLFMT_TOKEN,          "Column Format"},
    {TDS_COMPUTE_NAMES_TOKEN,   "Compute Names"},
    {TDS_COMPUTE_RESULT_TOKEN,  "Compute Results"},
    {TDS_ORDER_TOKEN,           "Order"},
    {TDS_ERR_TOKEN,             "Error Message"},
    {TDS_INFO_TOKEN,            "Info Message"},
    {TDS_LOGIN_ACK_TOKEN,       "Login Acknowledgement"},
    {TDS_KEY_TOKEN,             "TDS Key"},
    {TDS_ROW_TOKEN,             "Row"},
    {TDS_CAPABILITY_TOKEN,      "Capabilities"},
    {TDS_ENVCHG_TOKEN,          "Environment Change"},
    {TDS5_EED_TOKEN,             "Extended Error"},
    {TDS_AUTH_TOKEN,            "Authentication"},
    {TDS5_ROWFMT_TOKEN,         "Rowfmt"},
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
    {TDS5_DBRPC_TOKEN,           "DBRPC"},
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

static const value_string login_options[] = {
    {TDS_INT4_BIG_ENDIAN, "Big-endian"},
    {TDS_INT4_LITTLE_ENDIAN, "Little-endian"},
    {TDS_INT2_BIG_ENDIAN, "Big-endian"},
    {TDS_INT2_LITTLE_ENDIAN, "Little-endian"},
    {TDS_FLT8_BIG_ENDIAN, "IEEE Big-endian"},
    {TDS_FLT8_VAX_D, "VAX D"},
    {TDS_CHAR_ASCII, "ASCII"},
    {TDS_CHAR_EBCDIC, "EBCDIC"},
    {TDS_DATE8_TIME_FIRST, "Time first"},
    {TDS_DATE8_DATE_FIRST, "Date first"},
    {TDS_FLT8_LITTLE_ENDIAN, "IEEE Little-endian"},
    {TDS_FLT8_ND5000, "ND5000"},
    {12, "IEEE Big-endian"},
    {13, "IEEE Little-endian"},
    {14, "VAX F"},
    {15, "ND5000 4"},
    {TDS_DATE4_TIME_FIRST, "Time first"},
    {TDS_DATE4_DATE_FIRST, "Date first"},
    {0, NULL}
};

static const value_string login_conversation_type[] = {
    {0, "Client to server"},
    {1, "Server to server"},
    {2, "Server remote login"},
    {4, "Internal RPC"},
    {0, NULL}
};

static const value_string login_server_to_server[] = {
    {0, "Server's Default SQL"},
    {1, "Transact-SQL"},
    {2, "ANSI SQL, version 1"},
    {3, "ANSI SQL, version 2, level 1"},
    {4, "ANSI SQL, version 2, level 2"},
    {5, "Log in succeeded"},
    {6, "Log in failed"},
    {7, "Negotiate further"},
    {0, NULL}
};

static const value_string tds_capability_type[] = {
    {TDS_CAP_REQUEST, "Request capabilities"},
    {TDS_CAP_RESPONSE, "Response capabilities"},
    {0, NULL}
};

static const value_string tds_curfetch_types[] = {
    {TDS_CUR_NEXT,    "Next"},
    {TDS_CUR_PREV,    "Previous"},
    {TDS_CUR_FIRST,   "First"},
    {TDS_CUR_LAST,    "Last"},
    {TDS_CUR_ABS,     "Absolute"},
    {TDS_CUR_REL,     "Relative"},
    {0, NULL}
};

static const value_string tds_curinfo_commands[] = {
    {TDS_CURINFO_SET_FETCH_COUNT, "Set fetch count"},
    {TDS_CURINFO_INQUIRE,         "Inquire cursor state"},
    {TDS_CURINFO_INFORM,          "Report information about a cursor"},
    {TDS_CURINFO_LISTALL,         "List all open cursors"},
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
    {4, "ColumnEncryption"},
    {5, "GlobalTransactions"},
    {8, "AzureSQLSupport"},
    {9, "DataClassification"},
    {10, "UTF8Support"},
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

static const true_false_string tds_tfs_more_final = {"More tokens follow", "Final done token"};

static const unit_name_string units_characters = { " character", " characters" };

static const value_string tds_mars_type[] = {
    {0, "Off"},
    {1, "On"},
    {0, NULL}
};

#define TDS_MAX_COLUMNS 256

/*
 * This is where we store the column information to be used in decoding the
 * TDS_ROW_TOKEN tokens.
 */
struct _tds_col {
    const char *name;
    guint csize;
    guint32 utype;
    guint8 ctype;
    guint8 precision;
    guint8 scale;
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
               guint offset)
{
    tvbuff_t *nt_tvb;

    nt_tvb = tvb_new_subset_remaining(tvb, offset);
    if(tvb_strneql(tvb, offset, "NTLMSSP", 7) == 0)
        call_dissector(ntlmssp_handle, nt_tvb, pinfo, tree);
    else
        call_dissector(gssapi_handle, nt_tvb, pinfo, tree);
}

static guint
tds_get_int2_encoding(tds_conv_info_t *tds_info)
{
    return (tds_info->tds_encoding_int2 == TDS_INT2_BIG_ENDIAN) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;
}

static guint
tds_get_int4_encoding(tds_conv_info_t *tds_info)
{
    return (tds_info->tds_encoding_int4 == TDS_INT4_BIG_ENDIAN) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;
}
static guint
tds_get_char_encoding(tds_conv_info_t *tds_info)
{
    switch (tds_info->tds_encoding_char) {
        case TDS_CHAR_ASCII:
            return ENC_ASCII;

        case TDS_CHAR_EBCDIC:
            return ENC_EBCDIC;

        case TDS_CHAR_UTF16:
            return (ENC_UTF_16|ENC_LITTLE_ENDIAN);
    }
    return 0;
}

static guint
tds_char_encoding_is_two_byte(tds_conv_info_t *tds_info)
{
    return (tds_info->tds_encoding_char == TDS_CHAR_UTF16);
}

static int
tds_token_is_fixed_size_sybase(guint8 token)
{
    switch (token) {
        case TDS_DONE_TOKEN:
        case TDS_DONEPROC_TOKEN:
        case TDS_DONEINPROC_TOKEN:
        case TDS_RET_STAT_TOKEN:
        case TDS_PROCID_TOKEN:
        case TDS5_LOGOUT_TOKEN:
        case TDS_OFFSET_TOKEN:
            return 1;
        default:
            return 0;
    }
}

static int
tds_get_fixed_token_size_sybase(guint8 token, tds_conv_info_t *tds_info _U_)
{
    switch(token) {
        case TDS_DONE_TOKEN:
        case TDS_DONEPROC_TOKEN:
        case TDS_DONEINPROC_TOKEN:
            return 8;
        case TDS_PROCID_TOKEN:
            return 8;
        case TDS_RET_STAT_TOKEN:
            return 4;
        case TDS5_LOGOUT_TOKEN:
            return 1;
        case TDS_OFFSET_TOKEN:
            return 4;
        default:
            return 0;
    }
}

static guint
tds_get_variable_token_size_sybase(tvbuff_t *tvb, gint offset, guint8 token,
                                   tds_conv_info_t *tds_info,
                                   guint *len_field_size_p,
                                   guint *len_field_val_p)
{
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
            *len_field_val_p = tvb_get_guint32(tvb, offset,
                                               tds_get_int4_encoding(tds_info));
            break;
        /* some have a 1 byte length field */
        case TDS5_MSG_TOKEN:
            *len_field_size_p = 1;
            *len_field_val_p = tvb_get_guint8(tvb, offset);
            break;
        /* Some have no length field at all. */
        case TDS5_PARAMS_TOKEN:
        case TDS_ROW_TOKEN:
            *len_field_size_p = 0;
            *len_field_val_p = 0;
            break;
        /* and most have a 2 byte length field */
        default:
            *len_field_size_p = 2;
            *len_field_val_p = tvb_get_guint16(tvb, offset,
                                               tds_get_int2_encoding(tds_info));
            break;
    }
    return *len_field_val_p + *len_field_size_p + 1;
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

static struct _netlib_data *
copy_nl_data(wmem_allocator_t *allocator, struct _netlib_data *nl_data)
{
    struct _netlib_data *new_nl_data;
    guint col;


    new_nl_data = wmem_new0(allocator, struct _netlib_data);
    new_nl_data->num_cols = nl_data->num_cols;
    for (col=0; col < nl_data->num_cols; col++) {
        struct _tds_col *old_column = nl_data->columns[col];
        struct _tds_col *new_column = wmem_new0(allocator, struct _tds_col);
        new_nl_data->columns[col] = new_column;
        if (old_column->name) {
            new_column->name = wmem_strdup(allocator, old_column->name);
        }
        new_column->csize     = old_column->csize;
        new_column->utype     = old_column->utype;
        new_column->ctype     = old_column->ctype;
        new_column->precision = old_column->precision;
        new_column->scale     = old_column->scale;
    }

    return new_nl_data;
}

static void
dissect_tds_all_headers(tvbuff_t *tvb, gint *offset, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item = NULL, *total_length_item = NULL;
    proto_tree *sub_tree = NULL;
    guint32 total_length;
    gint final_offset;

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
handle_tds_sql_datetime(tvbuff_t *tvb, guint offset, proto_tree *sub_tree, tds_conv_info_t *tds_info)
{
    /* SQL datetime */
    nstime_t tv = NSTIME_INIT_ZERO;
    gint64 days; /* Note that days is signed, allowing dates back to 1753. */
    guint64 threehndths;

    if (tds_info->tds_encoding_date8 == TDS_DATE8_DATE_FIRST) {
        days = tvb_get_gint32(tvb, offset, tds_get_int4_encoding(tds_info));
        threehndths = tvb_get_guint32(tvb, offset + 4, tds_get_int4_encoding(tds_info));
    }
    else if (tds_info->tds_encoding_date8 == TDS_DATE8_TIME_FIRST) {
        threehndths = tvb_get_guint32(tvb, offset, tds_get_int4_encoding(tds_info));
        days = tvb_get_gint32(tvb, offset + 4, tds_get_int4_encoding(tds_info));
    }
    else {
        /* TODO Check these values in the login packet and offer expert information.
         * Here just make sure they're initialized.
         */
        days = threehndths = 0;
    }

    tv.secs = (time_t)((days * G_GUINT64_CONSTANT(86400)) + (threehndths/300) - EPOCH_DELTA_1900_01_01_00_00_00_UTC); /* seconds between Jan 1, 1900 and Jan 1, 1970 */
    tv.nsecs = (int)((threehndths%300) * 10000000 / 3);
    proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_absdatetime, tvb, offset, 8, &tv);
}

static void
handle_tds_sql_smalldatetime(tvbuff_t *tvb, guint offset, proto_tree *sub_tree, tds_conv_info_t *tds_info)
{
    /* SQL smalldatetime */
    nstime_t tv = NSTIME_INIT_ZERO;
    guint64 days, minutes;

    if (tds_info->tds_encoding_date4 == TDS_DATE4_DATE_FIRST) {
        days = tvb_get_guint16(tvb, offset, tds_get_int2_encoding(tds_info));
        minutes = tvb_get_guint16(tvb, offset + 2, tds_get_int2_encoding(tds_info));
    }
    else if (tds_info->tds_encoding_date4 == TDS_DATE4_TIME_FIRST) {
        minutes = tvb_get_guint16(tvb, offset, tds_get_int2_encoding(tds_info));
        days = tvb_get_guint16(tvb, offset + 2, tds_get_int2_encoding(tds_info));
    }
    else {
        /* TODO Check these values in the login packet and offer expert information.
         * Here just make sure they're initialized.
         */
        days = minutes = 0;
    }


    tv.secs = (time_t)((days * G_GUINT64_CONSTANT(86400)) + (minutes * 60) - EPOCH_DELTA_1900_01_01_00_00_00_UTC); /* seconds between Jan 1, 1900 and Jan 1, 1970 */
    tv.nsecs = 0;
    proto_tree_add_time(sub_tree, hf_tds_type_varbyte_data_absdatetime, tvb, offset, 8, &tv);
}

static void
handle_tds_sql_smallmoney(tvbuff_t *tvb, guint offset, proto_tree *sub_tree, tds_conv_info_t *tds_info)
{
    gdouble dblvalue = (gfloat)tvb_get_guint32(tvb, offset, tds_get_int4_encoding(tds_info));
    proto_tree_add_double_format_value(sub_tree, hf_tds_type_varbyte_data_double,
        tvb, offset, 4, dblvalue, "%.4f", dblvalue/10000);
}

static void
handle_tds_sql_money(tvbuff_t *tvb, guint offset, proto_tree *sub_tree, tds_conv_info_t *tds_info)
{
    guint64 moneyval = tvb_get_guint32(tvb, offset, tds_get_int4_encoding(tds_info));
    gdouble dblvalue = (gdouble)((moneyval << 32) + tvb_get_guint32(tvb, offset + 4,
                            tds_get_int4_encoding(tds_info)));

    proto_tree_add_double_format_value(sub_tree, hf_tds_type_varbyte_data_double,
        tvb, offset, 8, dblvalue, "%.4f", dblvalue/10000);
}

static void
dissect_tds_type_varbyte(tvbuff_t *tvb, guint *offset, packet_info *pinfo, proto_tree *tree, int hf, tds_conv_info_t *tds_info,
                         guint8 data_type, guint8 scale, gboolean plp, gint fieldnum, const char *name)
{
    guint length, textptrlen;
    proto_tree *sub_tree = NULL;
    proto_item *item = NULL, *length_item = NULL;
    gint32 data_value;

    item = proto_tree_add_item(tree, hf, tvb, *offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_tds_type_varbyte);

    if(fieldnum != -1)
        proto_item_append_text(item, " %i", fieldnum);

    if (name && strlen(name) > 0) {
        proto_item *pi;
        pi = proto_tree_add_string(sub_tree, hf_tds_type_varbyte_column_name, tvb, 0, (gint) strlen(name),
                                   (const char *)name);
        proto_item_set_generated(pi);
    }

    if(plp) {
        guint64 plp_length = tvb_get_letoh64(tvb, *offset);
        length_item = proto_tree_add_item(sub_tree, hf_tds_type_varbyte_plp_len, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        *offset += 8;
        if(plp_length == TDS_PLP_NULL)
            proto_item_append_text(length_item, " (PLP_NULL)");
        else {
            tvbuff_t *combined_chunks_tvb;
            guint combined_length;

            if(plp_length == TDS_UNKNOWN_PLP_LEN) {
                proto_item_append_text(length_item, " (UNKNOWN_PLP_LEN)");
            }
            /*
             * XXX - composite tvbuffs with no compontents aren't supported,
             * so we create the tvbuff when the first non-terminator chunk
             * is found.
             */
            combined_chunks_tvb = NULL;
            while(TRUE) {
                length_item = proto_tree_add_item_ret_uint(sub_tree, hf_tds_type_varbyte_plp_chunk_len, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &length);
                *offset += 4;
                if(length == TDS_PLP_TERMINATOR) {
                    proto_item_append_text(length_item, " (PLP_TERMINATOR)");
                    break;
                }

                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_plp_chunk, tvb, *offset, length, ENC_NA);
                if (combined_chunks_tvb == NULL)
                    combined_chunks_tvb = tvb_new_composite();
		/* Add this chunk to the composite tvbuff */
		tvbuff_t *chunk_tvb = tvb_new_subset_length(tvb, *offset, length);
		tvb_composite_append(combined_chunks_tvb, chunk_tvb);
                *offset += length;
            }
            if (combined_chunks_tvb != NULL) {
                tvb_composite_finalize(combined_chunks_tvb);

                /*
                 * If a length was specified, report an error if it's not
                 * the same as the reassembled length.
                 */
                combined_length = tvb_reported_length(combined_chunks_tvb);
                if(plp_length != TDS_UNKNOWN_PLP_LEN) {
                    if(plp_length != combined_length) {
                        expert_add_info(pinfo, length_item, &ei_tds_invalid_plp_length);
                    }
                }

                /*
                 * Now dissect the reassembled data.
                 *
                 * XXX - can we make this item cover multiple ranges?
                 * If so, do so.
                 */
                const guint8 *strval = NULL;
                switch(data_type) {
                    case TDS_DATA_TYPE_BIGVARBIN: /* VarBinary */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, combined_chunks_tvb, 0, combined_length, ENC_NA);
                        break;
                    case TDS_DATA_TYPE_BIGVARCHR: /* VarChar */
                        proto_tree_add_item_ret_string(sub_tree,
                            hf_tds_type_varbyte_data_string,
                            combined_chunks_tvb, 0, combined_length, ENC_ASCII|ENC_NA,
                            wmem_packet_scope(), &strval);
                        if (strval) {
                            proto_item_append_text(item, " (%s)", strval);
                        }
                        break;
                    case TDS_DATA_TYPE_NVARCHAR:  /* NVarChar */
                        proto_tree_add_item_ret_string(sub_tree,
                            hf_tds_type_varbyte_data_string,
                            combined_chunks_tvb, 0, combined_length, ENC_UTF_16|ENC_LITTLE_ENDIAN,
                            wmem_packet_scope(), &strval);
                        if (strval) {
                            proto_item_append_text(item, " (%s)", strval);
                        }
                        break;
                    case TDS_DATA_TYPE_XML:       /* XML (introduced in TDS 7.2) */
                    case TDS_DATA_TYPE_UDT:       /* CLR-UDT (introduced in TDS 7.2) */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, combined_chunks_tvb, 0, combined_length, ENC_NA);
                        break;
                    default:
                        /* no other data type sets plp = TRUE */
                        expert_add_info_format(pinfo, length_item, &ei_tds_invalid_plp_type, "This type should not use PLP");
                }
            } else {
                /*
                 * If a length was specified, report an error if it's not
                 * zero.
                 */
                if(plp_length != TDS_UNKNOWN_PLP_LEN) {
                    if(plp_length != 0) {
                        expert_add_info(pinfo, length_item, &ei_tds_invalid_plp_length);
                    }
                }

                /*
                 * The data is empty.
                 */
                switch(data_type) {
                    case TDS_DATA_TYPE_BIGVARBIN: /* VarBinary */
                        proto_tree_add_bytes(sub_tree, hf_tds_type_varbyte_data_bytes, NULL, 0, 0, NULL);
                        break;
                    case TDS_DATA_TYPE_BIGVARCHR: /* VarChar */
                        proto_tree_add_string(sub_tree, hf_tds_type_varbyte_data_string, NULL, 0, 0, "");
                        break;
                    case TDS_DATA_TYPE_NVARCHAR:  /* NVarChar */
                        proto_tree_add_string(sub_tree, hf_tds_type_varbyte_data_string, NULL, 0, 0, "");
                        break;
                    case TDS_DATA_TYPE_XML:       /* XML (introduced in TDS 7.2) */
                    case TDS_DATA_TYPE_UDT:       /* CLR-UDT (introduced in TDS 7.2) */
                        proto_tree_add_bytes(sub_tree, hf_tds_type_varbyte_data_bytes, NULL, 0, 0, NULL);
                        break;
                    default:
                        /* no other data type sets plp = TRUE */
                        expert_add_info_format(pinfo, length_item, &ei_tds_invalid_plp_type, "This type should not use PLP");
                }
            }
        }
    }
    else switch(data_type) {
        /* FIXEDLENTYPE */
        case TDS_DATA_TYPE_NULL:            /* Null (no data associated with this type) */
            break;
        case TDS_DATA_TYPE_BIT:             /* Bit (1 byte data representation) */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_boolean, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;
        case TDS_DATA_TYPE_INT1:            /* TinyInt (1 byte data representation) */
            proto_tree_add_item_ret_int(sub_tree, hf_tds_type_varbyte_data_int1, tvb, *offset, 1, ENC_NA, &data_value);
            proto_item_append_text(item, " (%d)", data_value);
            *offset += 1;
            break;
        case TDS_DATA_TYPE_INT2:            /* SmallInt (2 byte data representation) */
            proto_tree_add_item_ret_int(sub_tree, hf_tds_type_varbyte_data_int2, tvb, *offset, 2, tds_get_int2_encoding(tds_info), &data_value);
            proto_item_append_text(item, " (%d)", data_value);
            *offset += 2;
            break;
        case TDS_DATA_TYPE_INT4:            /* Int (4 byte data representation) */
            proto_tree_add_item_ret_int(sub_tree, hf_tds_type_varbyte_data_int4, tvb, *offset, 4, tds_get_int4_encoding(tds_info), &data_value);
            proto_item_append_text(item, " (%d)", data_value);
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
        case TDS_DATA_TYPE_DATETIME4:       /* SmallDateTime (4 byte data representation) */
            handle_tds_sql_smalldatetime(tvb, *offset, sub_tree, tds_info);
            *offset += 4;
            break;
        case TDS_DATA_TYPE_MONEY4:          /* SmallMoney (4 byte data representation) */
            handle_tds_sql_smallmoney(tvb, *offset, sub_tree, tds_info);
            *offset += 4;
            break;
        case TDS_DATA_TYPE_DATETIME:        /* DateTime (8 byte data representation) */
            handle_tds_sql_datetime(tvb, *offset, sub_tree, tds_info);
            *offset += 8;
            break;
        case TDS_DATA_TYPE_MONEY:           /* Money (8 byte data representation) */
            handle_tds_sql_money(tvb, *offset, sub_tree, tds_info);
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
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_boolean, tvb, *offset + 1, 1, ENC_NA);
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
                    proto_tree_add_item_ret_int(sub_tree, hf_tds_type_varbyte_data_int1, tvb, *offset + 1, 1, ENC_NA, &data_value);
                    proto_item_append_text(item, " (%d)", data_value);
                    break;
                case 2:
                    proto_tree_add_item_ret_int(sub_tree, hf_tds_type_varbyte_data_int2, tvb, *offset + 1, 2, tds_get_int2_encoding(tds_info), &data_value);
                    proto_item_append_text(item, " (%d)", data_value);
                    break;
                case 4:
                    proto_tree_add_item_ret_int(sub_tree, hf_tds_type_varbyte_data_int4, tvb, *offset + 1, 4, tds_get_int4_encoding(tds_info), &data_value);
                    proto_item_append_text(item, " (%d)", data_value);
                    break;
                case 8:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_int8, tvb, *offset + 1, 8, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%"G_GINT64_MODIFIER"d)", tvb_get_letoh64(tvb, *offset));
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
                    proto_item_append_text(item, " (%f)", tvb_get_letohieee_float(tvb, *offset));
                    break;
                case 8:
                    proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_double, tvb, *offset + 1, 8, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(item, " (%f)", tvb_get_letohieee_double(tvb, *offset));
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
                    handle_tds_sql_smallmoney(tvb, *offset, sub_tree, tds_info);
                }
                if(length == 8)
                {
                    handle_tds_sql_money(tvb, *offset, sub_tree, tds_info);
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
                    handle_tds_sql_smalldatetime(tvb, *offset, sub_tree, tds_info);
                }
                else if(length == 8)
                {
                    handle_tds_sql_datetime(tvb, *offset, sub_tree, tds_info);
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

        case TDS_DATA_TYPE_DECIMAL:         /* Decimal (TDS 4/5) */
        case TDS_DATA_TYPE_NUMERIC:         /* Numeric (TDS 4/5) */
        case TDS_DATA_TYPE_DECIMALN:        /* Decimal */
        case TDS_DATA_TYPE_NUMERICN:        /* Numeric */
        {
            proto_item *numericitem = NULL;

            length = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 1, length);
            *offset += 1;

            if(length > 0) {

                if (TDS_PROTO_TDS5(tds_info)) {
                    /* Sybase rules:
                     * Data are big-endian.
                     * The size appears to be variable governed on the Precision specification.
                     * Sign of TRUE indicates negative.
                     */
                    gboolean sign = FALSE;

                    proto_tree_add_item_ret_boolean(sub_tree, hf_tds_type_varbyte_data_sign, tvb, *offset, 1, ENC_NA, &sign);
                    *offset += 1;
                    length -= 1;

                    numericitem = proto_tree_add_item(sub_tree,
                        hf_tds_type_varbyte_data_bytes, tvb, *offset, length,
                        ENC_NA);
                    if (length <= 8) {
                        guint8 data_array[8];
                        guint j;
                        gint64 int64_value = 0;
                        /*
                         * XXX - this actually falls down if we have more than
                         * 53 bits of significance. (Assuming IEEE 754 floating-piont.)
                         * This isn't likely to happen in practice.
                         * Decimal/numeric fields are intended to be used
                         * for precise integers/scaled integers. They would not
                         * be typically be used for high dynamic range quantities.
                         */

                        (void) tvb_memcpy(tvb, data_array, *offset, length);
                        for (j = 0; j < length; j++) {
                            int64_value = (int64_value << 8) | data_array[j];
                        }
                        if(scale == 0) {
                            proto_item_append_text(numericitem,
                                " (%" G_GINT64_MODIFIER "d)",
                                (sign ? -int64_value : int64_value));
                        }
                        else {
                            proto_item_append_text(numericitem,
                                " (%.*f)", scale,
                                (double)(sign ? -int64_value
                                              : int64_value)/pow(10.0, (double)(scale)));
                        }
                    }
                    *offset += length;
                }
                else {
                    /*
                     *  Microsoft apparently allowed NUMERIC/DECIMAL while they
                     *  still were negotiating TDS 4.x. Sybase did not, so
                     *  assume any NUMERIC that's not TDS 5.0 is Microsoft's.
                     *
                     * Microsoft rules:
                     * Data are little-endian.
                     * The data size is documented as being 4, 8, 12, or 16 bytes,
                     * but this code does not rely on that.
                     * Sign of TRUE indicates positive.
                     */
                    gboolean sign = TRUE;

                    proto_tree_add_item_ret_boolean(sub_tree,
                        hf_tds_type_varbyte_data_sign, tvb, *offset, 1,
                        ENC_NA, &sign);
                    length -= 1;
                    *offset += 1;

                    numericitem = proto_tree_add_item(sub_tree,
                        hf_tds_type_varbyte_data_bytes, tvb, *offset, length,
                        ENC_NA);
                    if (length <= 8) {
                        guint8 data_array[8];
                        gint j;
                        gint64 int64_value = 0;
                        /*
                         * XXX - this actually falls down if we have more than
                         * 53 bits of significance. (Assuming IEEE 754 floating-piont.)
                         * This isn't likely to happen in practice.
                         * Decimal/numeric fields are intended to be used
                         * for precise integers/scaled integers. They would not
                         * be typically be used for high dynamic range quantities.
                         *
                         * We could change the "length <= 8" criterion above,
                         * but Microsoft appears to only use length values which
                         * are multiples of 4. Any numeric/decimal with a
                         * precision between 9 and 19 will be stored as an
                         * 8-byte integer.
                         */

                        (void) tvb_memcpy(tvb, data_array, *offset, length);
                        for (j = length - 1; j >= 0; j--) {
                            int64_value = (int64_value << 8) | data_array[j];
                        }
                        if(scale == 0) {
                            proto_item_append_text(numericitem,
                                " (%" G_GINT64_MODIFIER "d)",
                                (sign ? -int64_value : int64_value));
                        }
                        else {
                            proto_item_append_text(numericitem,
                                " (%.*f)", scale,
                                (double)(sign ? int64_value
                                              : -int64_value)/pow(10.0, (double)(scale)));
                        }
                    }
                    *offset += length;
                }
            }
            else {
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset,
                    0, ENC_NA);
            }
            break;
        }
        case TDS_DATA_TYPE_CHAR:            /* Char (TDS 4/5) */
        case TDS_DATA_TYPE_VARCHAR:         /* VarChar (TDS 4/5) */
        {
            gint len;
            proto_tree_add_item_ret_length(sub_tree, hf_tds_type_varbyte_data_uint_string,
                tvb, *offset, 1, tds_get_char_encoding(tds_info), &len);
            *offset += len;
            break;
        }
        case TDS_DATA_TYPE_BINARY:          /* Binary (TDS 4/5) */
        case TDS_DATA_TYPE_VARBINARY:       /* VarBinary (TDS 4/5) */
        {
            gint len;
            proto_tree_add_item_ret_length(sub_tree, hf_tds_type_varbyte_data_uint_bytes,
                tvb, *offset, 1, ENC_NA, &len);
            *offset += len;
            break;
        }
        /* USHORTLEN_TYPE - types prefixed with 2-byte length */
        case TDS_DATA_TYPE_BIGVARBIN:       /* VarBinary */
        case TDS_DATA_TYPE_BIGBINARY:       /* Binary */
        case TDS_DATA_TYPE_BIGVARCHR:       /* VarChar */
        case TDS_DATA_TYPE_BIGCHAR:         /* Char */
        case TDS_DATA_TYPE_NVARCHAR:        /* NVarChar */
        case TDS_DATA_TYPE_NCHAR:           /* NChar */
            /* Special case where MS and Sybase independently assigned a data type of 0xaf. */
            if ((data_type == SYBLONGCHAR) && TDS_PROTO_LESS_THAN_TDS7(tds_info)) {
                gint len;
                proto_tree_add_item_ret_length(sub_tree, hf_tds_type_varbyte_data_uint_string, tvb, *offset, 4,
                    tds_get_char_encoding(tds_info)|tds_get_int4_encoding(tds_info), &len);
                *offset += len;
                break;
            }
            length = tvb_get_letohs(tvb, *offset);
            length_item = proto_tree_add_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 2, length);
            *offset += 2;
            if(length == TDS_CHARBIN_NULL) {
                proto_item_append_text(length_item, " (CHARBIN_NULL)");
                proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_null, tvb, *offset, 0, ENC_NA);
            }
            else {
                const guint8 *strval = NULL;
                switch(data_type) {
                    case TDS_DATA_TYPE_BIGVARBIN: /* VarBinary */
                    case TDS_DATA_TYPE_BIGBINARY: /* Binary */
                        proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_bytes, tvb, *offset, length, ENC_NA);
                        break;
                    case TDS_DATA_TYPE_BIGVARCHR: /* VarChar */
                    case TDS_DATA_TYPE_BIGCHAR:   /* Char */
                        proto_tree_add_item_ret_string(sub_tree, hf_tds_type_varbyte_data_string,
                            tvb, *offset, length, ENC_ASCII|ENC_NA,
                            wmem_packet_scope(), &strval);
                        if (strval) {
                            proto_item_append_text(item, " (%s)", strval);
                        }
                        break;
                    case TDS_DATA_TYPE_NVARCHAR:  /* NVarChar */
                    case TDS_DATA_TYPE_NCHAR:     /* NChar */
                        proto_tree_add_item_ret_string(sub_tree, hf_tds_type_varbyte_data_string,
                            tvb, *offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN,
                            wmem_packet_scope(), &strval);
                        if (strval) {
                            proto_item_append_text(item, " (%s)", strval);
                        }
                        break;
                }
                *offset += length;
            }
            break;

        /* LONGLEN_TYPE - types prefixed with 4-byte length */
        /* SYBLONGCHAR would be similar, but there is an ambiguity with TDS 7.x.
         * It is handled under TDS_DATA_TYPE_BIGCHAR above. */
        case TDS_DATA_TYPE_LONGBINARY:      /* Long Binary (TDS 5.0) */
        {
            gint len;
            proto_tree_add_item_ret_length(sub_tree, hf_tds_type_varbyte_data_uint_bytes, tvb, *offset, 4,
                tds_get_int4_encoding(tds_info), &len);
            *offset += len;
            break;
        }
        /* LONGLEN_TYPE - types prefixed with 4-byte length using a text pointer*/
        case TDS_DATA_TYPE_NTEXT:           /* NText */
        case TDS_DATA_TYPE_TEXT:            /* Text */
        case TDS_DATA_TYPE_IMAGE:           /* Image */
        case TDS_DATA_TYPE_XML:             /* XML (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_UDT:             /* CLR-UDT (introduced in TDS 7.2) */
        case TDS_DATA_TYPE_SSVARIANT:       /* Sql_Variant (introduced in TDS 7.2) */
            /* TextPointer */
            length_item =proto_tree_add_item_ret_uint(sub_tree, hf_tds_type_varbyte_data_textptr_len,
                             tvb, *offset, 1, ENC_NA, &textptrlen);
            if (TDS_PROTO_LESS_THAN_TDS7(tds_info) && textptrlen == 0) {
                proto_item_append_text(length_item, " (NULL)");
                *offset += 1;
                break;
            }
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_textptr, tvb,
                                *offset + 1, textptrlen, ENC_NA);
            *offset += 1 + textptrlen;

            /* Timestamp */
            proto_tree_add_item(sub_tree, hf_tds_type_varbyte_data_text_ts, tvb,
                                *offset, 8, ENC_NA);
            *offset += 8;

            length_item = proto_tree_add_item_ret_uint(sub_tree, hf_tds_type_varbyte_length, tvb, *offset, 4,
                                                       tds_get_int4_encoding(tds_info), &length);
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
dissect_tds_query_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tds_conv_info_t *tds_info)
{
    gint offset, len;
    guint string_encoding = ENC_UTF_16|ENC_LITTLE_ENDIAN;
    proto_tree *query_tree;

    offset = 0;
    query_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_tds7_query, NULL, "TDS Query Packet");
    dissect_tds_all_headers(tvb, &offset, pinfo, query_tree);
    len = tvb_reported_length_remaining(tvb, offset);

    if (TDS_PROTO_LESS_THAN_TDS7(tds_info) ||
        (!TDS_PROTO_TDS7(tds_info) &&
         ((len < 2) || tvb_get_guint8(tvb, offset+1) != 0)))
        string_encoding = ENC_ASCII|ENC_NA;

    proto_tree_add_item(query_tree, hf_tds_query, tvb, offset, len, string_encoding);
    /* offset += len; */
}

static int * const dbrpc_options_hf_fields[] = {
    &hf_tds_dbrpc_options_recompile,
    &hf_tds_dbrpc_options_params,
    NULL
};

static guint
dissect_tds5_dbrpc_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info) {

    guint rpcnamelen, cur=offset;

    proto_tree_add_item(tree, hf_tds_dbrpc_length, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
    cur += 2;

    proto_tree_add_item_ret_uint(tree, hf_tds_dbrpc_rpcname_len, tvb, cur, 1,
                                 ENC_NA, &rpcnamelen);
    if (rpcnamelen > 0) {
        proto_tree_add_item(tree, hf_tds_dbrpc_rpcname, tvb, cur + 1, rpcnamelen,
                            tds_get_char_encoding(tds_info));
    }
    cur += (rpcnamelen + 1);

    proto_tree_add_bitmask(tree, tvb, cur, hf_tds_dbrpc_options, ett_tds5_dbrpc_options,
                           dbrpc_options_hf_fields, tds_get_int2_encoding(tds_info));
    cur += 2;

    return cur - offset;
}

static guint
dissect_tds5_lang_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info) {

    guint len, cur=offset;

    proto_tree_add_item_ret_uint(tree, hf_tds_lang_length, tvb, cur, 4,
                                 tds_get_int4_encoding(tds_info), &len);
    cur += 4;

    /* Both of these calls are retained for backwards compatibility. */
    proto_tree_add_item(tree, hf_tds_lang_token_status, tvb, cur, 1, ENC_NA);
    proto_tree_add_item(tree, hf_tds_lang_status_parameterized, tvb, cur, 1, ENC_NA);

    cur += 1;
    len -= 1;

    proto_tree_add_item(tree, hf_tds_lang_language_text, tvb, cur, len, ENC_ASCII|ENC_NA);
    cur += len;

    return cur - offset;
}

static void
tds5_check_cursor_name(packet_info *pinfo, proto_item *pi,
                       tds_cursor_info_t *cursor_current, const guint8 *cursorname)
{
    if (cursorname && cursor_current &&
        ( cursor_current->tds_cursor_flags & TDS_CURSOR_NAME_VALID)) {
        if (g_strcmp0((const char *)cursorname,
            cursor_current->tds_cursor_name) != 0) {
            expert_add_info_format(pinfo, pi, &ei_tds_cursor_name_mismatch,
                    "Cursor name %s does not match current cursor name %s",
                    cursorname, cursor_current->tds_cursor_name);
        }
    }
}

static void
tds_cursor_info_init(tds_conv_info_t *tds_info)
{
    tds_conv_cursor_info_t *conv_cursor_info = tds_info->tds_conv_cursor_info;

    if (!conv_cursor_info) {
        conv_cursor_info =
            wmem_new0(wmem_file_scope(), tds_conv_cursor_info_t);
        conv_cursor_info->tds_conv_cursor_table =
            wmem_tree_new(wmem_file_scope());
        tds_info->tds_conv_cursor_info = conv_cursor_info;
    }
}

static guint
dissect_tds5_curclose_token(tvbuff_t *tvb, packet_info *pinfo, guint offset,
                              proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint len, cur = offset;
    guint cursorid;
    proto_item *cursor_id_pi;
    tds_cursor_info_t *packet_cursor =
        (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);

    proto_tree_add_item_ret_uint(tree, hf_tds_curclose_length, tvb, cur, 2, tds_get_int2_encoding(tds_info), &len);
    cur += 2;

    cursor_id_pi = proto_tree_add_item_ret_uint(tree, hf_tds_curclose_cursorid,
        tvb, cur, 4, tds_get_int4_encoding(tds_info), &cursorid);
    cur += 4;

    if (cursorid == 0) {
        gint cursorname_len;
        const guint8 *cursorname;
        proto_item *cursor_name_pi;

        cursor_name_pi = proto_tree_add_item_ret_string_and_length(tree,
            hf_tds_curclose_cursor_name,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &cursorname, &cursorname_len);
        cur += cursorname_len;
        tds5_check_cursor_name(pinfo, cursor_name_pi, packet_cursor, cursorname);
    }
    else if (packet_cursor && cursor_id_pi &&
            (packet_cursor->tds_cursor_flags & TDS_CURSOR_NAME_VALID)) {
        proto_item_append_text(cursor_id_pi, " (%s)",
            packet_cursor->tds_cursor_name);
    }

    proto_tree_add_item(tree, hf_tds_curclose_option_deallocate, tvb, cur, 1, ENC_NA);
    cur += 1;

    if (!PINFO_FD_VISITED(pinfo) && !packet_cursor) {
        tds_conv_cursor_info_t *conv_cursor_info;

        tds_cursor_info_init(tds_info);
        conv_cursor_info = tds_info->tds_conv_cursor_info;
        if (cursorid) {
            tds_cursor_info_t *cursor_current;
            cursor_current =
                (tds_cursor_info_t *) wmem_tree_lookup32(conv_cursor_info->tds_conv_cursor_table,
                                 cursorid);
            if (cursor_current) {
                p_add_proto_data(wmem_file_scope(),
                    pinfo, proto_tds, 0, cursor_current);
            }
        }
    }

    return cur - offset;
}

static int * const tds_curdeclare_hf_fields[] = {
    &hf_tds_curdeclare_options_rdonly,
    &hf_tds_curdeclare_options_updatable,
    &hf_tds_curdeclare_options_sensitive,
    &hf_tds_curdeclare_options_dynamic,
    &hf_tds_curdeclare_options_implicit,
    NULL
};

static guint
dissect_tds5_curdeclare_token(tvbuff_t *tvb, packet_info *pinfo, guint offset,
                              proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint len, cur = offset, num_updatable_columns;
    gint cursorname_len, stmtlen;
    const guint8 *cursorname;
    tds_cursor_info_t *packet_cursor =
        (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);

    proto_tree_add_item_ret_uint(tree, hf_tds_curdeclare_length, tvb, cur, 2,
        tds_get_int2_encoding(tds_info), &len);
    cur += 2;

    proto_tree_add_item_ret_string_and_length(tree, hf_tds_curdeclare_cursor_name,
        tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
        wmem_packet_scope(), &cursorname, &cursorname_len);
    cur += cursorname_len;

    /* Options is one byte, as is status. */
    proto_tree_add_bitmask(tree, tvb, cur, hf_tds_curdeclare_options,
        ett_tds5_curdeclare_options, tds_curdeclare_hf_fields, ENC_NA);
    proto_tree_add_item(tree, hf_tds_curdeclare_status_parameterized, tvb,
        cur + 1, 1, ENC_NA);
    cur += 2;

    proto_tree_add_item_ret_length(tree, hf_tds_curdeclare_statement, tvb, cur, 2,
        tds_get_char_encoding(tds_info)|tds_get_int2_encoding(tds_info), &stmtlen);
    cur += stmtlen;

    proto_tree_add_item_ret_uint(tree, hf_tds_curdeclare_update_columns_num, tvb, cur, 1,
                                 ENC_NA, &num_updatable_columns);
    cur += 1;

    if (num_updatable_columns > 0) {
        gint column_name_len;

        proto_tree_add_item_ret_length(tree, hf_tds_curdeclare_update_columns_name,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA, &column_name_len);
        cur += column_name_len;
    }

    /*
     * If being processed in order (first time through) prepare to correlate the
     * curdeclare with the curinfo response.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
        tds_conv_cursor_info_t *conv_cursor_info;
        tds_cursor_info_t *cursor_current;

        tds_cursor_info_init(tds_info);
        conv_cursor_info = tds_info->tds_conv_cursor_info;

        cursor_current = conv_cursor_info->tds_conv_cursor_current;
        if (!cursor_current) {
            cursor_current = wmem_new0(wmem_file_scope(), tds_cursor_info_t);
            conv_cursor_info->tds_conv_cursor_current = cursor_current;
        }
        else if (!(cursor_current->tds_cursor_flags & TDS_CURSOR_IN_CONV_TABLE)) {
            /*
             * The cursor was allocated, but never entered into the table.
             * This won't happen normally, but it could happen if the client were
             * coded unusually and pending activity were to be aborted mid-sequence.
             * Free possible existing values to avoid a file-level leak.
             */
            wmem_free(wmem_file_scope(), (void *) cursor_current->tds_cursor_name);
            wmem_free(wmem_file_scope(), (void *) cursor_current->tds_cursor_rowinfo);
            (void) memset(cursor_current, 0, sizeof (tds_cursor_info_t));
        }

        cursor_current->tds_cursor_name = wmem_strdup(wmem_file_scope(), (const char* )cursorname);
        cursor_current->tds_cursor_flags |= TDS_CURSOR_NAME_VALID;

        if (packet_cursor && packet_cursor != cursor_current) {
            p_remove_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);
            packet_cursor = NULL;
        }
        if (!packet_cursor) {
            p_add_proto_data(wmem_file_scope(), pinfo, proto_tds, 0, cursor_current);
        }

    }
    return cur - offset;
}

static guint
dissect_tds5_curfetch_token(tvbuff_t *tvb, packet_info *pinfo, guint offset,
                              proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint len, cur = offset;
    guint cursorid;
    guint curfetch_type;
    const guint8 *cursorname;
    proto_item *cursor_id_pi;
    tds_cursor_info_t *packet_cursor =
        (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);

    proto_tree_add_item_ret_uint(tree, hf_tds_curfetch_length, tvb, cur, 2, tds_get_int2_encoding(tds_info), &len);
    cur += 2;

    cursor_id_pi = proto_tree_add_item_ret_uint(tree, hf_tds_curfetch_cursorid,
        tvb, cur, 4, tds_get_int4_encoding(tds_info), &cursorid);
    cur += 4;

    if (cursorid == 0) {
        gint cursorname_len;
        proto_item *cursor_name_pi;

        cursor_name_pi = proto_tree_add_item_ret_string_and_length(tree, hf_tds_curfetch_cursor_name,
                 tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
                 wmem_packet_scope(), &cursorname, &cursorname_len);
        tds5_check_cursor_name(pinfo, cursor_name_pi, packet_cursor, cursorname);
        cur += cursorname_len;
    }
    else if (packet_cursor && cursor_id_pi &&
            (packet_cursor->tds_cursor_flags & TDS_CURSOR_NAME_VALID)) {
        proto_item_append_text(cursor_id_pi, " (%s)",
            packet_cursor->tds_cursor_name);
    }

    proto_tree_add_item_ret_uint(tree, hf_tds_curfetch_type, tvb, cur, 1,
                                 ENC_NA, &curfetch_type);
    cur += 1;

    if (curfetch_type >= TDS_CUR_ABS) {
        proto_tree_add_item(tree, hf_tds_curfetch_rowcnt, tvb, cur, 4,
                            tds_get_int4_encoding(tds_info));
        cur += 4;
    }

    if (!PINFO_FD_VISITED(pinfo) && !packet_cursor) {
        tds_conv_cursor_info_t *conv_cursor_info = tds_info->tds_conv_cursor_info;
        tds_cursor_info_t *cursor_current;

        if (!conv_cursor_info) {
            conv_cursor_info =
                wmem_new0(wmem_file_scope(), tds_conv_cursor_info_t);
            conv_cursor_info->tds_conv_cursor_table =
                wmem_tree_new(wmem_file_scope());
            tds_info->tds_conv_cursor_info = conv_cursor_info;
        }
        if (cursorid) {
            cursor_current =
                (tds_cursor_info_t *) wmem_tree_lookup32(conv_cursor_info->tds_conv_cursor_table,
                                 cursorid);
            if (cursor_current) {
                p_add_proto_data(wmem_file_scope(),
                    pinfo, proto_tds, 0, cursor_current);
                cursor_current->tds_cursor_flags |= TDS_CURSOR_FETCH_PENDING;
                conv_cursor_info->tds_conv_cursor_current = cursor_current;
            }
        }
    }

    return cur - offset;
}

static int * const tds_curinfo_hf_fields[] = {
    &hf_tds_curinfo_cursor_status_declared,
    &hf_tds_curinfo_cursor_status_open,
    &hf_tds_curinfo_cursor_status_closed,
    &hf_tds_curinfo_cursor_status_rdonly,
    &hf_tds_curinfo_cursor_status_updatable,
    &hf_tds_curinfo_cursor_status_rowcnt,
    &hf_tds_curinfo_cursor_status_dealloc,
    NULL
};

static guint
dissect_tds5_curinfo_token(tvbuff_t *tvb, packet_info *pinfo, guint offset,
                           proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint len, cur = offset;
    const guint8 *cursorname = NULL;
    guint cursorid;
    guint cursor_command;
    tds_cursor_info_t *packet_cursor =
        (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);
    proto_item *cursor_id_pi;

    proto_tree_add_item_ret_uint(tree, hf_tds_curinfo_length, tvb, cur, 2,
        tds_get_int2_encoding(tds_info), &len);
    cur += 2;

    cursor_id_pi = proto_tree_add_item_ret_uint(tree, hf_tds_curinfo_cursorid,
        tvb, cur, 4, tds_get_int4_encoding(tds_info), &cursorid);
    cur += 4;

    if (cursorid == 0) {
        gint cursorname_len;
        proto_item *cursor_name_pi;
        cursor_name_pi = proto_tree_add_item_ret_string_and_length(tree,
            hf_tds_curinfo_cursor_name, tvb, cur, 1,
            tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &cursorname, &cursorname_len);
        cur += cursorname_len;
        tds5_check_cursor_name(pinfo, cursor_name_pi, packet_cursor, cursorname);
    }
    else if (packet_cursor && cursor_id_pi &&
            (packet_cursor->tds_cursor_flags & TDS_CURSOR_NAME_VALID)) {
        proto_item_append_text(cursor_id_pi, " (%s)",
            packet_cursor->tds_cursor_name);
    }


    proto_tree_add_item_ret_uint(tree, hf_tds_curinfo_cursor_command,
        tvb, cur, 1, ENC_NA, &cursor_command);
    cur += 1;

    proto_tree_add_bitmask(tree, tvb, cur, hf_tds_curinfo_cursor_status,
        ett_tds5_curinfo_status, tds_curinfo_hf_fields,
        tds_get_int2_encoding(tds_info));
    cur += 2;

    /* offset + 2 to skip past the length, which does not include itself. */
    if (len - (cur - (offset + 2)) == 4) {
        proto_tree_add_item(tree, hf_tds_curinfo_cursor_rowcnt, tvb, cur, 4,
            tds_get_int4_encoding(tds_info));
        cur += 4;
    }

    /*
     * If we're going through sequentially, and it's an INFORM response,
     * try to correlate cursor names with cursor ids.
     */
    if (!PINFO_FD_VISITED(pinfo) &&
            cursor_command == TDS_CURINFO_INFORM &&
            !packet_cursor) {
        tds_conv_cursor_info_t *conv_cursor_info = tds_info->tds_conv_cursor_info;
        tds_cursor_info_t *cursor_current;

        if (!conv_cursor_info) {
            conv_cursor_info =
                wmem_new0(wmem_file_scope(), tds_conv_cursor_info_t);
            conv_cursor_info->tds_conv_cursor_table =
                wmem_tree_new(wmem_file_scope());
            tds_info->tds_conv_cursor_info = conv_cursor_info;
        }
        cursor_current = conv_cursor_info->tds_conv_cursor_current;
        if (!cursor_current) {
            cursor_current = wmem_new0(wmem_file_scope(), tds_cursor_info_t);
            conv_cursor_info->tds_conv_cursor_current = cursor_current;
        }
        p_add_proto_data(wmem_file_scope(), pinfo, proto_tds, 0, cursor_current);
        if (cursorid != 0) {
            if (!(cursor_current->tds_cursor_flags & TDS_CURSOR_ID_VALID)) {
                cursor_current->tds_cursor_id = cursorid;
                cursor_current->tds_cursor_flags |= TDS_CURSOR_ID_VALID;
                wmem_tree_insert32(conv_cursor_info->tds_conv_cursor_table,
                    cursorid, cursor_current);
                cursor_current->tds_cursor_flags |= TDS_CURSOR_IN_CONV_TABLE;
            } else if (cursor_current->tds_cursor_id != cursorid) {
                tds_cursor_info_t *temp_cursor =
                    (tds_cursor_info_t *) wmem_tree_lookup32(conv_cursor_info->tds_conv_cursor_table,
                                  cursorid);
                if (temp_cursor != cursor_current) {
                    cursor_current = temp_cursor;
                    conv_cursor_info->tds_conv_cursor_current = cursor_current;
                    p_remove_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_tds, 0, cursor_current);

                }
            }
        }
    }
    return cur - offset;
}

static guint
dissect_tds5_curopen_token(tvbuff_t *tvb, packet_info *pinfo, guint offset,
                           proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint len, cur = offset;
    guint cursorid;
    proto_item *cursor_id_pi;
    tds_cursor_info_t *packet_cursor =
        (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);

    proto_tree_add_item_ret_uint(tree, hf_tds_curopen_length, tvb, cur, 2, tds_get_int2_encoding(tds_info), &len);
    cur += 2;

    cursor_id_pi = proto_tree_add_item_ret_uint(tree, hf_tds_curopen_cursorid,
                       tvb, cur, 4, tds_get_int4_encoding(tds_info), &cursorid);
    cur += 4;

    if (cursorid == 0) {
        gint cursorname_len;
        const guint8 *cursorname;
        proto_item *pi;

        pi = proto_tree_add_item_ret_string_and_length(tree, hf_tds_curopen_cursor_name,
                 tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
                 wmem_packet_scope(), &cursorname, &cursorname_len);
        cur += cursorname_len;
        tds5_check_cursor_name(pinfo, pi, packet_cursor, cursorname);
    }
    else if (packet_cursor && cursor_id_pi &&
            (packet_cursor->tds_cursor_flags & TDS_CURSOR_NAME_VALID)) {
        proto_item_append_text(cursor_id_pi, " (%s)",
            packet_cursor->tds_cursor_name);
    }

    proto_tree_add_item(tree, hf_tds_curopen_status_parameterized, tvb, cur, 1, ENC_NA);
    cur += 1;

    return cur - offset;
}

/*
 * Each of these covers the 8 bits of a byte, so they have
 * 9 elements - one for each bit, plus the terminating NULL.
 *
 * Some have early NULLs as placeholders.
 */
static int * const hf_req_0[9] = {
    &hf_tds_capability_req_lang,
    &hf_tds_capability_req_rpc,
    &hf_tds_capability_req_evt,
    &hf_tds_capability_req_mstmt,
    &hf_tds_capability_req_bcp,
    &hf_tds_capability_req_cursor,
    &hf_tds_capability_req_dynf,
    NULL, NULL}; /* Two nulls until I can figure out the types. */

static int * const hf_req_1[9] = {
    &hf_tds_capability_req_msg,
    &hf_tds_capability_req_param,
    &hf_tds_capability_data_int1,
    &hf_tds_capability_data_int2,
    &hf_tds_capability_data_int4,
    &hf_tds_capability_data_bit,
    &hf_tds_capability_data_char,
    &hf_tds_capability_data_vchar,
    NULL};

static int * const hf_req_2[9] = {
    &hf_tds_capability_data_bin,
    &hf_tds_capability_data_vbin,
    &hf_tds_capability_data_mny8,
    &hf_tds_capability_data_mny4,
    &hf_tds_capability_data_date8,
    &hf_tds_capability_data_date4,
    &hf_tds_capability_data_flt4,
    &hf_tds_capability_data_flt8,
    NULL};

static int * const hf_req_3[9] = {
    &hf_tds_capability_data_num,
    &hf_tds_capability_data_text,
    &hf_tds_capability_data_image,
    &hf_tds_capability_data_dec,
    &hf_tds_capability_data_lchar,
    &hf_tds_capability_data_lbin,
    &hf_tds_capability_data_intn,
    &hf_tds_capability_data_datetimen,
    NULL};

static int * const hf_req_4[9] = {
    &hf_tds_capability_data_moneyn,
    &hf_tds_capability_csr_prev,
    &hf_tds_capability_csr_first,
    &hf_tds_capability_csr_last,
    &hf_tds_capability_csr_abs,
    &hf_tds_capability_csr_rel,
    &hf_tds_capability_csr_multi,
    &hf_tds_capability_con_oob,
    NULL};

static int * const hf_req_5[9] = {
    &hf_tds_capability_con_inband,
    &hf_tds_capability_con_logical,
    &hf_tds_capability_proto_text,
    &hf_tds_capability_proto_bulk,
    &hf_tds_capability_req_urgevt,
    &hf_tds_capability_data_sensitivity,
    &hf_tds_capability_data_boundary,
    &hf_tds_capability_proto_dynamic,
    NULL};

static int * const hf_req_6[9] = {
    &hf_tds_capability_proto_dynproc,
    &hf_tds_capability_data_fltn,
    &hf_tds_capability_data_bitn,
    &hf_tds_capability_data_int8,
    &hf_tds_capability_data_void,
    &hf_tds_capability_dol_bulk,
    &hf_tds_capability_object_java1,
    &hf_tds_capability_object_char,
    NULL};

static int * const hf_req_7[9] = {
    &hf_tds_capability_object_binary,
    &hf_tds_capability_data_columnstatus,
    &hf_tds_capability_widetable,
    &hf_tds_capability_data_uint2,
    &hf_tds_capability_data_uint4,
    &hf_tds_capability_data_uint8,
    NULL,NULL, /* 56 and 60 reserved */
    NULL};

static int * const hf_req_8[9] = {
    &hf_tds_capability_data_uintn,
    &hf_tds_capability_cur_implicit,
    &hf_tds_capability_data_nlbin,
    &hf_tds_capability_image_nchar,
    &hf_tds_capability_blob_nchar_16,
    &hf_tds_capability_blob_nchar_8,
    &hf_tds_capability_blob_nchar_scsu,
    &hf_tds_capability_data_date,
    NULL};

static int * const hf_req_9[9] = {
    &hf_tds_capability_data_time,
    &hf_tds_capability_data_interval,
    &hf_tds_capability_csr_scroll,
    &hf_tds_capability_csr_sensitive,
    &hf_tds_capability_csr_insensitive,
    &hf_tds_capability_csr_semisensitive,
    &hf_tds_capability_csr_keysetdriven,
    &hf_tds_capability_req_srvpktsize,
    NULL};

static int * const hf_req_10[9] = {
    &hf_tds_capability_data_unitext,
    &hf_tds_capability_cap_clusterfailover,
    &hf_tds_capability_data_sint1,
    &hf_tds_capability_req_largeident,
    &hf_tds_capability_req_blob_nchar_16,
    &hf_tds_capability_data_xml,
    &hf_tds_capability_req_curinfo3,
    &hf_tds_capability_req_dbrpc2,
    NULL};

static int * const hf_resp_0[9] = {
    &hf_tds_capability_res_nomsg,
    &hf_tds_capability_res_noeed,
    &hf_tds_capability_res_noparam,
    &hf_tds_capability_data_noint1,
    &hf_tds_capability_data_noint2,
    &hf_tds_capability_data_noint4,
    &hf_tds_capability_data_nobit,
    NULL, /* 0 unused */
    NULL};

static int * const hf_resp_1[9] = {
    &hf_tds_capability_data_nochar,
    &hf_tds_capability_data_novchar,
    &hf_tds_capability_data_nobin,
    &hf_tds_capability_data_novbin,
    &hf_tds_capability_data_nomny8,
    &hf_tds_capability_data_nomny4,
    &hf_tds_capability_data_nodate8,
    &hf_tds_capability_data_nodate4,
    NULL};

static int * const hf_resp_2[9] = {
    &hf_tds_capability_data_noflt4,
    &hf_tds_capability_data_noflt8,
    &hf_tds_capability_data_nonum,
    &hf_tds_capability_data_notext,
    &hf_tds_capability_data_noimage,
    &hf_tds_capability_data_nodec,
    &hf_tds_capability_data_nolchar,
    &hf_tds_capability_data_nolbin,
    NULL};

static int * const hf_resp_3[9] = {
    &hf_tds_capability_data_nointn,
    &hf_tds_capability_data_nodatetimen,
    &hf_tds_capability_data_nomoneyn,
    &hf_tds_capability_con_nooob,
    &hf_tds_capability_con_noinband,
    &hf_tds_capability_proto_notext,
    &hf_tds_capability_proto_nobulk,
    &hf_tds_capability_data_nosensitivity,
    NULL};

static int * const hf_resp_4[9] = {
    &hf_tds_capability_data_noboundary,
    &hf_tds_capability_res_notdsdebug,
    &hf_tds_capability_res_nostripblanks,
    &hf_tds_capability_data_noint8,
    &hf_tds_capability_object_nojava1,
    &hf_tds_capability_object_nochar,
    &hf_tds_capability_data_nocolumnstatus,
    &hf_tds_capability_object_nobinary,
    NULL};

static int * const hf_resp_5[9] = {
    &hf_tds_capability_data_nouint2,
    &hf_tds_capability_data_nouint4,
    &hf_tds_capability_data_nouint8,
    &hf_tds_capability_data_nouintn,
    &hf_tds_capability_no_widetables,
    &hf_tds_capability_data_nonlbin,
    &hf_tds_capability_image_nonchar,
    NULL, /* 40 unused */
    NULL};

static int * const hf_resp_6[9] = {
    &hf_tds_capability_blob_nonchar_16,
    &hf_tds_capability_blob_nonchar_8,
    &hf_tds_capability_blob_nonchar_scsu,
    &hf_tds_capability_data_nodate,
    &hf_tds_capability_data_notime,
    &hf_tds_capability_data_nointerval,
    &hf_tds_capability_data_nounitext,
    &hf_tds_capability_data_nosint1,
    NULL};

static int * const hf_resp_7[9] = {
    &hf_tds_capability_no_largeident,
    &hf_tds_capability_no_blob_nchar_16,
    &hf_tds_capability_no_srvpktsize,
    &hf_tds_capability_data_noxml,
    &hf_tds_capability_no_nint_return_value,
    &hf_tds_capability_res_noxnldata,
    &hf_tds_capability_res_suppress_fmt,
    &hf_tds_capability_res_suppress_doneinproc,
    NULL};

static int * const hf_resp_8[9] = {
    &hf_tds_capability_res_force_rowfmt2,
    NULL, NULL, NULL, /* 65-67 reserved */
    NULL, NULL, NULL, NULL, /* 68-71 reserved */
    NULL};

static int * const *hf_req_array[] = {
    hf_req_0,
    hf_req_1,
    hf_req_2,
    hf_req_3,
    hf_req_4,
    hf_req_5,
    hf_req_6,
    hf_req_7,
    hf_req_8,
    hf_req_9,
    hf_req_10
   };

static int * const *hf_resp_array[] = {
    hf_resp_0,
    hf_resp_1,
    hf_resp_2,
    hf_resp_3,
    hf_resp_4,
    hf_resp_5,
    hf_resp_6,
    hf_resp_7,
    hf_resp_8
   };

static guint
dissect_tds5_capability_token(tvbuff_t *tvb, packet_info *pinfo, guint offset,
                              proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint len, cur;

    proto_tree_add_item_ret_uint(tree, hf_tds_capability_length, tvb, offset, 2, tds_get_int2_encoding(tds_info), &len);
    cur = 2;

    while (cur < len) {
        guint captype, caplen, cap;
        proto_item *length_item;

        proto_tree_add_item_ret_uint(tree, hf_tds_capability_captype, tvb,
                                     offset + cur, 1, ENC_NA, &captype);
        length_item = proto_tree_add_item_ret_uint(tree, hf_tds_capability_caplen, tvb,
                                     offset + cur +1 , 1, ENC_NA, &caplen);
        cur += 2;

        if (caplen > (cur - len)) {
            expert_add_info_format(pinfo, length_item, &ei_tds_token_length_invalid,
                                   " Capability length %d", caplen);
            caplen = cur - len;
        }

        for (cap=0; cap < caplen; cap++) {
            int * const *hf_array = NULL;
            char name[ITEM_LABEL_LENGTH];
            int ett;

            switch (captype) {
                case TDS_CAP_REQUEST:
                    if (cap < array_length(hf_req_array)) {
                        hf_array = hf_req_array[cap];
                        g_snprintf(name, ITEM_LABEL_LENGTH, "Req caps %d-%d: ",
                                   cap*8, (cap + 1)*8 - 1);
                        ett = ett_tds_capability_req;
                    }
                    break;
                case TDS_CAP_RESPONSE:
                    if (cap < array_length(hf_resp_array)) {
                        hf_array = hf_resp_array[cap];
                        g_snprintf(name, ITEM_LABEL_LENGTH, "Resp caps %d-%d: ",
                                   cap*8, (cap + 1)*8 - 1);
                        ett = ett_tds_capability_resp;
                    }
                    break;
                default:
                    ;
            }
            if (hf_array) {
                /* Using add_bitmask_text to allow the name to be specified.
                 * The flags are the same as the add_bitmask defaults. */
                proto_tree_add_bitmask_text(tree, tvb,
                                            offset + cur + (caplen - cap - 1), 1,
                                            name, NULL,
                                            ett, hf_array,
                                            ENC_NA, BMT_NO_INT|BMT_NO_TFS);
            }

        }
        cur += caplen;
    }

    return cur;

}

static void
dissect_tds_transmgr_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *request_tree;
    gint offset = 0, len;

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

static guint
dissect_tds5_logout_token(proto_tree *tree, tvbuff_t *tvb, guint offset, tds_conv_info_t *tds_info _U_)
{
    guint cur = offset;

    proto_tree_add_item(tree, hf_tds_logout_options, tvb, cur, 1, ENC_NA);
    cur += 1;

    return cur - offset;
}

static guint
dissect_tds5_msg_token(proto_tree *tree, tvbuff_t *tvb, guint offset, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    proto_tree_add_item(tree, hf_tds_msg_length, tvb, cur, 1, ENC_NA);
    cur += 1;
    proto_tree_add_item(tree, hf_tds_msg_status, tvb, cur, 1, ENC_NA);
    cur += 1;
    proto_tree_add_item(tree, hf_tds_msg_msgid, tvb, cur, 2, tds_get_int2_encoding(tds_info));
    cur += 2;

    return cur - offset;
}

/*
 * Process TDS 5 "PARAMFMT" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 */
static guint
dissect_tds_paramfmt_token(proto_tree *tree, tvbuff_t *tvb, guint offset, tds_conv_info_t *tds_info,
                           struct _netlib_data *nl_data)
{
    guint next, cur;
    guint col, len, numcols;

    proto_tree_add_item_ret_uint(tree, hf_tds_paramfmt_length, tvb, offset, 2,
                                 tds_get_int4_encoding(tds_info), &len);
    proto_tree_add_item_ret_uint(tree, hf_tds_paramfmt_numparams, tvb, offset + 2, 2,
                                 tds_get_int2_encoding(tds_info), &numcols);
    next = offset + len + 2; /* Only skip the length field. */
    cur = offset + 4; /* Skip the length and numcols field. */

    col = 0;
    while (cur < next) {
        const guint8 *colname = NULL;
        gint colnamelen, localelen;

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = TDS_MAX_COLUMNS;
            return 0;
        }

        if (!(nl_data->columns[col])) {
            nl_data->columns[col] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }

        proto_tree_add_item_ret_string_and_length(tree, hf_tds_paramfmt_colname,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &colname, &colnamelen);
        cur += colnamelen;
        nl_data->columns[col]->name = (const char*)colname;

        proto_tree_add_item(tree, hf_tds_paramfmt_status, tvb, cur, 1, ENC_NA);
        cur += 1;

        nl_data->columns[col]->utype = tvb_get_guint32(tvb, cur,
                                                       tds_get_int4_encoding(tds_info));
        proto_tree_add_item(tree, hf_tds_paramfmt_utype, tvb, cur, 4,
                            tds_get_int4_encoding(tds_info));
        cur += 4;

        nl_data->columns[col]->ctype = tvb_get_guint8(tvb,cur);
        proto_tree_add_item(tree, hf_tds_paramfmt_ctype, tvb, cur, 1, ENC_NA);
        cur++;

        if (!is_fixedlen_type_tds(nl_data->columns[col]->ctype)) {
            if (is_longlen_type_sybase(nl_data->columns[col]->ctype)) {
                proto_tree_add_item_ret_uint(tree, hf_tds_paramfmt_csize, tvb, cur, 4,
                    tds_get_int4_encoding(tds_info),
                    &nl_data->columns[col]->csize);
                cur += 4;
            }
            else {
                nl_data->columns[col]->csize = tvb_get_guint8(tvb,cur);
                proto_tree_add_item(tree, hf_tds_paramfmt_csize, tvb, cur, 1, ENC_NA);
                cur ++;
            }
        } else {
            nl_data->columns[col]->csize =
                get_size_by_coltype(nl_data->columns[col]->ctype);
        }

        proto_tree_add_item_ret_length(tree, hf_tds_paramfmt_locale_info,
            tvb, cur, 1, ENC_NA, &localelen);
        cur += localelen;

        col += 1;

    } /* while */

    nl_data->num_cols = col;
    return cur - offset;
}

/*
 * Process TDS 5 "PARAMFMT2" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 */
static guint
dissect_tds_paramfmt2_token(proto_tree *tree, tvbuff_t *tvb, guint offset, tds_conv_info_t *tds_info,
                           struct _netlib_data *nl_data)
{
    guint next, cur;
    guint col, len, numcols;

    proto_tree_add_item_ret_uint(tree, hf_tds_paramfmt2_length, tvb, offset, 4,
                                 tds_get_int4_encoding(tds_info), &len);
    proto_tree_add_item_ret_uint(tree, hf_tds_paramfmt2_numparams, tvb, offset + 4, 2,
                                 tds_get_int2_encoding(tds_info), &numcols);
    next = offset + len + 4; /* Only skip the length field. */
    cur = offset + 6; /* Skip the length and numcols field. */

    col = 0;
    while (cur < next) {
        const guint8 *colname = NULL;
        gint colnamelen, localelen;

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = TDS_MAX_COLUMNS;
            return 0;
        }

        if (!(nl_data->columns[col])) {
            nl_data->columns[col] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }

        proto_tree_add_item_ret_string_and_length(tree, hf_tds_paramfmt2_colname,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &colname, &colnamelen);
        cur += colnamelen;
        nl_data->columns[col]->name = (const char*)colname;

        proto_tree_add_item(tree, hf_tds_paramfmt2_status, tvb, cur, 4, tds_get_int4_encoding(tds_info));
        cur += 4;

        nl_data->columns[col]->utype = tvb_get_guint32(tvb, cur,
                                                       tds_get_int4_encoding(tds_info));
        proto_tree_add_item(tree, hf_tds_paramfmt2_utype, tvb, cur, 4,
                            tds_get_int4_encoding(tds_info));
        cur += 4;

        nl_data->columns[col]->ctype = tvb_get_guint8(tvb,cur);
        proto_tree_add_item(tree, hf_tds_paramfmt2_ctype, tvb, cur, 1, ENC_NA);
        cur++;

        if (!is_fixedlen_type_tds(nl_data->columns[col]->ctype)) {
            if (is_longlen_type_sybase(nl_data->columns[col]->ctype)) {
                proto_tree_add_item_ret_uint(tree, hf_tds_paramfmt2_csize, tvb, cur, 4,
                    tds_get_int4_encoding(tds_info),
                    &nl_data->columns[col]->csize);
                cur += 4;
            }
            else {
                nl_data->columns[col]->csize = tvb_get_guint8(tvb,cur);
                proto_tree_add_item(tree, hf_tds_paramfmt2_csize, tvb, cur, 1, ENC_NA);
                cur ++;
            }
        } else {
            nl_data->columns[col]->csize =
                get_size_by_coltype(nl_data->columns[col]->ctype);
        }

        proto_tree_add_item_ret_length(tree, hf_tds_paramfmt2_locale_info,
            tvb, cur, 1, ENC_NA, &localelen);
        cur += localelen;

        col += 1;

    } /* while */

    nl_data->num_cols = col;
    return cur - offset;
}

static int
dissect_tds5_params_token(tvbuff_t *tvb, packet_info *pinfo,
                          struct _netlib_data *nl_data, guint offset,
                          proto_tree *tree, proto_item *token_item,
                          tds_conv_info_t *tds_info)
{
    guint cur = offset, i;

    /* TDS5 does not have the Partially Length-Prefixed concept, so the "plp"
     * parameter is always FALSE. */
    for (i = 0; i < nl_data->num_cols; i++) {
        dissect_tds_type_varbyte(tvb, &cur, pinfo, tree, hf_tds_params_field, tds_info,
                                 nl_data->columns[i]->ctype, nl_data->columns[i]->scale,
                                 FALSE, i+1, nl_data->columns[i]->name);
    }

    proto_item_set_len(token_item, cur - offset);
    return cur - offset;
}

static gint
tds45_token_to_idx(guint8 token)
{
    /* TODO: Commented out entries are token types which are not currently dissected
     * Although they are known values, we cannot step over the bytes as token length is unknown
     * Better therefore to return unknown token type and highlight to user
    */

    /*
     * Token values for TDS4 and TDS5.
     * Microsoft and Sybase have separately expanded the protocol and have
     * each used numbers differently.
     */

    switch(token)
    {
        /*case TDS_ALTROW_TOKEN: return hf_tds_altrow;*/
        case TDS_CAPABILITY_TOKEN: return hf_tds_capability;
        case TDS_COLFMT_TOKEN: return hf_tds_colfmt;
        case TDS_COL_NAME_TOKEN: return hf_tds_colname;
        case TDS_CONTROL_TOKEN: return hf_tds_control;
        case TDS_CURCLOSE_TOKEN: return hf_tds_curclose;
        case TDS_CURDECLARE_TOKEN: return hf_tds_curdeclare;
        case TDS_CURFETCH_TOKEN: return hf_tds_curfetch;
        case TDS_CURINFO_TOKEN: return hf_tds_curinfo;
        case TDS_CUROPEN_TOKEN: return hf_tds_curopen;
        case TDS5_DBRPC_TOKEN: return hf_tds_dbrpc;
        case TDS_DONE_TOKEN: return hf_tds_done;
        case TDS_DONEPROC_TOKEN: return hf_tds_doneproc;
        case TDS_DONEINPROC_TOKEN: return hf_tds_doneinproc;
        case TDS5_EED_TOKEN: return hf_tds_eed;
        case TDS_ENVCHG_TOKEN: return hf_tds_envchg;
        case TDS_ERR_TOKEN: return hf_tds_error;
        case TDS_INFO_TOKEN: return hf_tds_info;
        case TDS_LOGIN_ACK_TOKEN: return hf_tds_loginack;
        case TDS5_LOGOUT_TOKEN: return hf_tds_logout;
        case TDS5_MSG_TOKEN: return hf_tds_msg;
        case TDS_OFFSET_TOKEN: return hf_tds_offset;
        case TDS_ORDER_TOKEN: return hf_tds_order;
        case TDS5_PARAMFMT_TOKEN: return hf_tds_paramfmt;
        case TDS5_PARAMFMT2_TOKEN: return hf_tds_paramfmt2;
        case TDS5_PARAMS_TOKEN: return hf_tds_params;
        case TDS_PROCID_TOKEN: return hf_tds_procid;
        case TDS_RET_STAT_TOKEN: return hf_tds_returnstatus;
        /*case TDS_RETURNVAL_TOKEN: return hf_tds_returnvalue;*/
        case TDS_ROW_TOKEN: return hf_tds_row;
        case TDS5_ROWFMT_TOKEN: return hf_tds_rowfmt;
        case TDS5_ROWFMT2_TOKEN: return hf_tds_rowfmt2;
        /*case TDS_TABNAME_TOKEN: return hf_tds_tabname;*/
    }

    return hf_tds_unknown_tds_token;
}

static void
dissect_tds5_tokenized_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      tds_conv_info_t *tds_info)
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
    struct _netlib_data nl_data;

    (void) memset(&nl_data, '\0', sizeof nl_data);

    offset = 0;
    query_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_tds7_query, NULL, "TDS5 Query Packet");

    /*
     * Until we reach the end of the packet, read tokens.
     */
    pos = offset;
    while (tvb_reported_length_remaining(tvb, pos) > 0) {

        /* our token */
        token = tvb_get_guint8(tvb, pos);
        if (tds_token_is_fixed_size_sybase(token))
            token_sz = tds_get_fixed_token_size_sybase(token, tds_info) + 1;
        else
            token_sz = tds_get_variable_token_size_sybase(tvb, pos+1, token, tds_info,
                                                          &token_len_field_size,
                                                          &token_len_field_val);
        token_tree = proto_tree_add_subtree_format(query_tree, tvb, pos, token_sz,
                                         ett_tds_token, &token_item, "Token 0x%02x %s", token,
                                         val_to_str_const(token, token_names, "Unknown Token Type"));

        if ((int) token_sz < 0) {
            expert_add_info_format(pinfo, token_item, &ei_tds_token_length_invalid, "Bogus token size: %u", token_sz);
            break;
        }

        switch (token) {
            case TDS_LANG_TOKEN:
                token_sz = dissect_tds5_lang_token(tvb, pos + 1, token_tree, tds_info) + 1;
                break;
            case TDS_CURCLOSE_TOKEN:
                token_sz = dissect_tds5_curclose_token(tvb, pinfo, pos + 1, token_tree, tds_info) + 1;
                break;
            case TDS_CURDECLARE_TOKEN:
                token_sz = dissect_tds5_curdeclare_token(tvb, pinfo, pos + 1, token_tree, tds_info) + 1;
                break;
            case TDS_CURFETCH_TOKEN:
                token_sz = dissect_tds5_curfetch_token(tvb, pinfo, pos + 1, token_tree, tds_info) + 1;
                break;
            case TDS_CURINFO_TOKEN:
                token_sz = dissect_tds5_curinfo_token(tvb, pinfo, pos + 1, token_tree, tds_info) + 1;
                break;
            case TDS_CUROPEN_TOKEN:
                token_sz = dissect_tds5_curopen_token(tvb, pinfo, pos + 1, token_tree, tds_info) + 1;
                break;
            case TDS5_LOGOUT_TOKEN:
                token_sz = dissect_tds5_logout_token(token_tree, tvb, pos + 1, tds_info) + 1;
                break;
            case TDS5_DBRPC_TOKEN:
                token_sz = dissect_tds5_dbrpc_token(tvb, pos + 1, token_tree, tds_info) + 1;
                break;
            case TDS5_PARAMFMT_TOKEN:
                token_sz = dissect_tds_paramfmt_token(token_tree, tvb, pos + 1, tds_info, &nl_data) + 1;
                break;
            case TDS5_PARAMFMT2_TOKEN:
                token_sz = dissect_tds_paramfmt2_token(token_tree, tvb, pos + 1, tds_info, &nl_data) + 1;
                break;
            case TDS5_PARAMS_TOKEN:
                token_sz = dissect_tds5_params_token(tvb, pinfo, &nl_data, pos + 1,
                                                     token_tree, token_item, tds_info) + 1;
                break;
            default:
                break;
        }

        pos += token_sz;

    }  /* while */
}

static void
set_tds7_encodings(tds_conv_info_t *tds_info)
{
    tds_info->tds_encoding_int4 = TDS_INT4_LITTLE_ENDIAN;
    tds_info->tds_encoding_int2 = TDS_INT2_LITTLE_ENDIAN;
    tds_info->tds_encoding_char = TDS_CHAR_UTF16;
}

static void
set_tds_version(tds_conv_info_t *tds_info, guint32 tds_version)
{
    switch (tds_version) {
        case TDS_PROTOCOL_VALUE_4_2:
            tds_info->tds_version = TDS_PROTOCOL_4;
            break;
        case TDS_PROTOCOL_VALUE_4_6:
            tds_info->tds_version = TDS_PROTOCOL_4;
            break;
        case TDS_PROTOCOL_VALUE_5:
            tds_info->tds_version = TDS_PROTOCOL_5;
            break;
        case 0x0700026f: /* SQL Server 7.0 */
        case 0x070002bb: /* SQL Server 7.0 SP1 */
        case 0x0700034a: /* SQL Server 7.0 SP2 */
        case 0x070003c1: /* SQL Server 7.0 SP3 */
        case 0x07000427: /* SQL Server 7.0 SP4 */
        case TDS_PROTOCOL_VALUE_7_0:
            tds_info->tds_version = TDS_PROTOCOL_7_0;
            set_tds7_encodings(tds_info);
            break;
        case 0x080000c2: /* SQL Server 2000 */
        case 0x08000180: /* SQL Server 2000 SP1 */
        case 0x08000214: /* SQL Server 2000 SP2 */
        case 0x080002f8: /* SQL Server 2000 SP3 */
        case 0x080007f7: /* SQL Server 2000 SP4 */
        case TDS_PROTOCOL_VALUE_7_1:
        case TDS_PROTOCOL_VALUE_7_1_1:
            tds_info->tds_version = TDS_PROTOCOL_7_1;
            set_tds7_encodings(tds_info);
            break;
        case 0x09000577: /* SQL Server 2005 */
        case 0x090007ff: /* SQL Server 2005 SP1 */
        case 0x09000be2: /* SQL Server 2005 SP2 */
        case 0x09000fc3: /* SQL Server 2005 SP3 */
        case 0x09001388: /* SQL Server 2005 SP4 */
        case TDS_PROTOCOL_VALUE_7_2:
            tds_info->tds_version = TDS_PROTOCOL_7_2;
            set_tds7_encodings(tds_info);
            break;
        case 0x0a000640: /* SQL Server 2008 */
        case 0x0a0009e3: /* SQL Server 2008 SP1 */
        case 0x0a0109e3: /* SQL Server 2008 SP1 */
        case 0x0a000fa0: /* SQL Server 2008 SP2 */
        case 0x0a020fa0: /* SQL Server 2008 SP2 */
        case 0x0a00157c: /* SQL Server 2008 SP3 */
        case 0x0a03157c: /* SQL Server 2008 SP3 */
        case 0x0a001770: /* SQL Server 2008 SP4 */
        case 0x0a041770: /* SQL Server 2008 SP4 */
        case TDS_PROTOCOL_VALUE_7_3A:
            tds_info->tds_version = TDS_PROTOCOL_7_3A;
            set_tds7_encodings(tds_info);
            break;
        case 0x0a320640: /* SQL Server 2008 R2 */
        case 0x0a3209c4: /* SQL Server 2008 R2 SP1 */
        case 0x0a3309c4: /* SQL Server 2008 R2 SP1 */
        case 0x0a320fa0: /* SQL Server 2008 R2 SP2 */
        case 0x0a340fa0: /* SQL Server 2008 R2 SP2 */
        case 0x0a321770: /* SQL Server 2008 R2 SP3 */
        case 0x0a351770: /* SQL Server 2008 R2 SP3 */
        case TDS_PROTOCOL_VALUE_7_3B:
            tds_info->tds_version = TDS_PROTOCOL_7_3B;
            set_tds7_encodings(tds_info);
            break;
        case 0x0b000834: /* SQL Server 2012 */
        case 0x0b000bb8: /* SQL Server 2012 SP1 */
        case 0x0b010bb8: /* SQL Server 2012 SP1 */
        case 0x0b0013c2: /* SQL Server 2012 SP2 */
        case 0x0b0213c2: /* SQL Server 2012 SP2 */
        case 0x0b001784: /* SQL Server 2012 SP3 */
        case 0x0b031784: /* SQL Server 2012 SP3 */
        case 0x0b001b59: /* SQL Server 2012 SP4 */
        case 0x0b041b59: /* SQL Server 2012 SP4 */
        case 0x0c0007d0: /* SQL Server 2014 */
        case 0x0c001004: /* SQL Server 2014 SP1 */
        case 0x0c011004: /* SQL Server 2014 SP1 */
        case 0x0c001388: /* SQL Server 2014 SP2 */
        case 0x0c021388: /* SQL Server 2014 SP2 */
        case 0x0d000641: /* SQL Server 2016 */
        case 0x0d000fa1: /* SQL Server 2016 SP1 */
        case 0x0d010fa1: /* SQL Server 2016 SP1 */
        case 0x030003e8: /* SQL Server 2017 */
        case TDS_PROTOCOL_VALUE_7_4:
            tds_info->tds_version = TDS_PROTOCOL_7_4;
            set_tds7_encodings(tds_info);
            break;
        default:
            tds_info->tds_version = TDS_PROTOCOL_7_4;
            break;
    }
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
dissect_tds7_prelogin_packet(tvbuff_t *tvb, proto_tree *tree, tds_conv_info_t *tds_info,
                             gboolean is_response)
{
    guint8 token;
    gint offset = 0;
    guint16 tokenoffset, tokenlen;
    proto_tree *prelogin_tree = NULL, *option_tree;
    proto_item *item, *option_item;

    item = proto_tree_add_item(tree, hf_tds_prelogin, tvb, 0, -1, ENC_NA);

    if(detect_tls(tvb))
    {
        proto_item_append_text(item, " - TLS exchange");
        return;
    }

    /*
     * If we get here, we know we're at least TDS 7.0. The actual TDS 7 version
     * will be set from the LOGINACK token, which should come after all of
     * the prelogin packets. That instance will overwrite the value set here.
     */

    set_tds_version(tds_info, TDS_PROTOCOL_VALUE_7_0);

    prelogin_tree = proto_item_add_subtree(item, ett_tds_message);
    while(tvb_reported_length_remaining(tvb, offset) > 0)
    {
        token = tvb_get_guint8(tvb, offset);
        option_tree = proto_tree_add_subtree(prelogin_tree, tvb, offset, token == 0xff ? 1 : 5,
                                             ett_tds_prelogin_option, &option_item, "Option");
        proto_tree_add_item(option_tree, hf_tds_prelogin_option_token, tvb, offset, 1, ENC_NA);
        offset += 1;

        if(token == TDS7_PRELOGIN_OPTION_TERMINATOR)
        {
            proto_item_append_text(option_item, ": Terminator");
            break;
        }

        tokenoffset = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(option_tree, hf_tds_prelogin_option_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        tokenlen = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(option_tree, hf_tds_prelogin_option_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        switch(token)
        {
            case TDS7_PRELOGIN_OPTION_VERSION: {
                guint32 version;
                proto_item_append_text(option_item, ": Version");
                proto_tree_add_item_ret_uint(option_tree, hf_tds_prelogin_option_version,
                                                tvb, tokenoffset, 4, ENC_BIG_ENDIAN,
                                                &version);
                proto_tree_add_item(option_tree, hf_tds_prelogin_option_subbuild, tvb, tokenoffset + 4, 2, ENC_LITTLE_ENDIAN);
                /* This gives us a better idea of what protocol we'll see. */
                if (is_response) {
                    set_tds_version(tds_info, version);
                }
                break;
            }
            case TDS7_PRELOGIN_OPTION_ENCRYPTION: {
                proto_item_append_text(option_item, ": Encryption");
                proto_tree_add_item(option_tree, hf_tds_prelogin_option_encryption, tvb, tokenoffset, tokenlen, ENC_NA);
                break;
            }
            case TDS7_PRELOGIN_OPTION_INSTOPT: {
                proto_item_append_text(option_item, ": InstOpt");
                proto_tree_add_item(option_tree, hf_tds_prelogin_option_instopt, tvb, tokenoffset, tokenlen, ENC_ASCII | ENC_NA);
                break;
            }
            case TDS7_PRELOGIN_OPTION_THREADID: {
                proto_item_append_text(option_item, ": ThreadID");
                if (tokenlen > 0)
                    proto_tree_add_item(option_tree, hf_tds_prelogin_option_threadid, tvb, tokenoffset, tokenlen, ENC_BIG_ENDIAN);
                break;
            }
            case TDS7_PRELOGIN_OPTION_MARS: {
                proto_item_append_text(option_item, ": MARS");
                proto_tree_add_item(option_tree, hf_tds_prelogin_option_mars, tvb, tokenoffset, tokenlen, ENC_NA);
                break;
            }
            case TDS7_PRELOGIN_OPTION_TRACEID: {
                proto_item_append_text(option_item, ": TraceID");
                proto_tree_add_item(option_tree, hf_tds_prelogin_option_traceid, tvb, tokenoffset, tokenlen, ENC_NA);
                break;
            }
            case TDS7_PRELOGIN_OPTION_FEDAUTHREQUIRED: {
                proto_item_append_text(option_item, ": FedAuthRequired");
                proto_tree_add_item(option_tree, hf_tds_prelogin_option_fedauthrequired, tvb, tokenoffset, tokenlen, ENC_NA);
                break;
            }
            case TDS7_PRELOGIN_OPTION_NONCEOPT: {
                proto_item_append_text(option_item, ": NonceOpt");
                proto_tree_add_item(option_tree, hf_tds_prelogin_option_nonceopt, tvb, tokenoffset, tokenlen, ENC_NA);
                break;
            }
        }
    }
}

static guint
dissect_tds45_login_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         int hf, int hf_length, guint offset, const guint namesize,
                         const char *name)
{
    guint len;
    proto_item *length_item;

    len = tvb_get_guint8(tvb,offset + namesize);
    length_item = proto_tree_add_item(tree, hf_length,
                                      tvb, offset+namesize, 1, ENC_NA);
    if (len > namesize) {
        expert_add_info_format(pinfo, length_item, &ei_tds_invalid_length,
                               "Invalid %s length (%d)", name, len);
        len = namesize;
    }
    if (len > 0) {
        proto_tree_add_item(tree, hf, tvb, offset, len, ENC_ASCII);
    }
    return offset + namesize + 1;

}

static guint
dissect_tds45_remotepassword(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
{
    guint rplen, cur, server_len, password_len;
    proto_item *length_item;
    proto_tree *rempw_tree;

    rempw_tree = proto_tree_add_subtree(tree, tvb, offset, TDS_RPLEN + 1, ett_tds_login_rempw, NULL, "Remote password");

    length_item = proto_tree_add_item_ret_uint(rempw_tree, hf_tdslogin_remotepassword_length, tvb,
                                               offset + TDS_RPLEN, 1, ENC_NA, &rplen);
    if (rplen > TDS_RPLEN) {
        expert_add_info_format(pinfo, length_item, &ei_tds_invalid_length,
                               "Invalid %s length (%d)", "remote password field", rplen);
        rplen = TDS_RPLEN;
    }

    cur = 0;
    while (cur < rplen) {
        length_item = proto_tree_add_item_ret_uint(rempw_tree, hf_tdslogin_rempw_servername_length, tvb,
                                                   offset + cur, 1, ENC_NA, &server_len);
        if (server_len > (rplen - cur) - 1) {
            expert_add_info_format(pinfo, length_item, &ei_tds_invalid_length,
                                   "Invalid %s length (%d)", "remote password servername", server_len);
            server_len = (rplen - cur) - 1;
        }
        if (server_len > 0) {
            proto_tree_add_item(rempw_tree, hf_tdslogin_rempw_servername, tvb,
                                offset + cur + 1, server_len, ENC_ASCII|ENC_NA);
        }
        length_item = proto_tree_add_item_ret_uint(rempw_tree, hf_tdslogin_rempw_password_length, tvb,
                                                   offset + cur + 1 + server_len, 1, ENC_NA, &password_len);
        if (password_len > (rplen - cur) - 1 - server_len - 1) {
            expert_add_info_format(pinfo, length_item, &ei_tds_invalid_length,
                                   "Invalid %s length (%d)", "remote password password", password_len);
            password_len = (rplen - cur) - 1 - server_len - 1;
        }
        if (password_len > 0) {
            proto_tree_add_item(rempw_tree, hf_tdslogin_rempw_password, tvb,
                                offset + cur + 1 + server_len + 1, password_len, ENC_ASCII|ENC_NA);
        }
        cur += (1 + server_len + 1 + password_len);
    }

    return offset + (TDS_RPLEN + 1);
}

static void
dissect_tds45_login(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint offset, len;

    proto_item *login_item;
    proto_tree *login_tree, *login_options_tree, *login_options2_tree;
    guint lval;
    guint32 tds_version;

    /* create display subtree for the protocol */
    offset = 0;
    len = tvb_reported_length(tvb);
    login_item = proto_tree_add_item(tree, hf_tdslogin, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
    login_tree = proto_item_add_subtree(login_item, ett_tds_login);
    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_hostname, hf_tdslogin_hostname_length,
                                      offset, TDS_MAXNAME, "hostname");

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_username, hf_tdslogin_username_length,
                                      offset, TDS_MAXNAME, "username");

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_password, hf_tdslogin_password_length,
                                      offset, TDS_MAXNAME, "password");

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_hostprocess, hf_tdslogin_hostprocess_length,
                                      offset, TDS_MAXNAME, "host process id");

    login_options_tree = proto_tree_add_subtree(login_tree, tvb, offset, 9,
                                                ett_tds_login_options, NULL, "Login Options");

    tds_info->tds_encoding_int2 = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(login_options_tree, hf_tdslogin_option_int2, tvb, offset, 1,
                        tds_info->tds_encoding_int2 );
    offset++;
    tds_info->tds_encoding_int4 = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(login_options_tree, hf_tdslogin_option_int4, tvb, offset, 1,
                        tds_info->tds_encoding_int2);
    offset++;
    tds_info->tds_encoding_char = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(login_options_tree, hf_tdslogin_option_char, tvb, offset, 1,
                        tds_info->tds_encoding_char);
    offset++;
    proto_tree_add_item(login_options_tree, hf_tdslogin_option_float, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item_ret_uint(login_options_tree, hf_tdslogin_option_date8, tvb,
        offset, 1, ENC_NA, &tds_info->tds_encoding_date8);
    offset++;
    proto_tree_add_item(login_options_tree, hf_tdslogin_option_usedb, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(login_options_tree, hf_tdslogin_option_bulk, tvb, offset, 1, ENC_NA);
    offset++;
    lval = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(login_options_tree, hf_tdslogin_option_server_to_server, tvb, offset, 1, lval & 0x7f);
    proto_tree_add_boolean(login_options_tree, hf_tdslogin_option_server_to_server_loginack, tvb, offset, 1, lval);
    offset++;
    proto_tree_add_item(login_options_tree, hf_tdslogin_option_conversation_type, tvb, offset, 1, ENC_NA);
    offset++;
    /* TDS 4 packet size */
    offset += 4;
    /* Spare */
    offset += 3;

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_appname, hf_tdslogin_appname_length,
                                      offset, TDS_MAXNAME, "appname");

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_servername, hf_tdslogin_servername_length,
                                      offset, TDS_MAXNAME, "server name");

    offset = dissect_tds45_remotepassword(tvb, pinfo, login_tree, offset);

    proto_tree_add_item_ret_uint(login_tree, hf_tdslogin_proto_version, tvb,
                                 offset, 4, ENC_BIG_ENDIAN,
                                 &tds_version);
    offset += 4;
    set_tds_version(tds_info, tds_version);
    proto_item_set_text(login_item, (tds_version == TDS_PROTOCOL_5 ? "TDS 5 Login Packet" : "TDS 4 Login Packet"));

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_progname, hf_tdslogin_progname_length,
                                      offset, TDS_PROGNLEN, "program name");

    proto_tree_add_item(login_tree, hf_tdslogin_progvers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    login_options2_tree = proto_tree_add_subtree(login_tree, tvb, offset, 3, ett_tds_login_options2, NULL, "Login Options 2");

    proto_tree_add_item(login_options2_tree, hf_tdslogin_option2_noshort, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(login_options2_tree, hf_tdslogin_option2_flt4, tvb, offset, 1, ENC_NA );
    offset++;
    proto_tree_add_item_ret_uint(login_options2_tree, hf_tdslogin_option2_date4,
        tvb, offset, 1, ENC_NA, &tds_info->tds_encoding_date4);
    offset++;

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_language, hf_tdslogin_language_length,
                                      offset, TDS_MAXNAME, "language");

    proto_tree_add_item(login_tree, hf_tdslogin_setlang, tvb, offset, 1, ENC_NA);
    offset++;

    /* Two bytes of oldsecure unused, must be zero. */
    offset += 2;

    proto_tree_add_item(login_tree, hf_tdslogin_seclogin, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(login_tree, hf_tdslogin_secbulk, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(login_tree, hf_tdslogin_halogin, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(login_tree, hf_tdslogin_hasessionid, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* secspare */
    offset += 2;

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_charset, hf_tdslogin_charset_length,
                                      offset, TDS_MAXNAME, "charset");

    proto_tree_add_item(login_tree, hf_tdslogin_setcharset, tvb, offset, 1, ENC_NA);
    offset++;

    offset = dissect_tds45_login_name(tvb, pinfo, login_tree,
                                      hf_tdslogin_packetsize, hf_tdslogin_packetsize_length,
                                      offset, TDS_PKTLEN, "packetsize");
    /* Unused */
    offset += 4;

    if (len > offset) {
        /* Check for capabilities token */
        if (tvb_get_guint8(tvb, offset) == TDS_CAPABILITY_TOKEN) {
            proto_item *token_item;
            proto_tree *token_tree;
            token_item = proto_tree_add_item(login_tree, hf_tds_capability, tvb, offset,
                                             tvb_reported_length_remaining(tvb, offset), ENC_NA);
            token_tree = proto_item_add_subtree(token_item, ett_tds_token);

            dissect_tds5_capability_token(tvb, pinfo, offset + 1, token_tree, tds_info);
        }
    }

}

static void
dissect_tds7_login(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint offset, i, j, k, offset2, len, login_hf = 0;
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
    set_tds_version(tds_info, td7hdr.tds_version);
    offset += (int)sizeof(td7hdr.tds_version);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_packet_size, tvb, offset, sizeof(td7hdr.packet_size), ENC_LITTLE_ENDIAN, &(td7hdr.packet_size));
    offset += (int)sizeof(td7hdr.packet_size);

    proto_tree_add_item_ret_uint(header_tree, hf_tds7login_client_version, tvb, offset, sizeof(td7hdr.client_version), ENC_BIG_ENDIAN, &(td7hdr.client_version));
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
                proto_tree_add_item(login_tree, login_hf, tvb, offset2, len,
                    ENC_UTF_16|ENC_LITTLE_ENDIAN);
            } else {
                /* This field is the password.  It is an obfusticated Unicode
                 * string. This code assumes that the password is composed of
                 * the 8-bit subset of UCS-16. Retrieve it from the packet
                 * as a non-unicode string and then perform two operations on it
                 * to "decrypt" it.  Finally, we create a new string that consists
                 * of ASCII characters instead of unicode by skipping every other
                 * byte in the original string.
                 *
                 * Optionally, we could make an expert item to warn of non-ASCII
                 * characters in the string.
                 */

                gchar *val, *val2;
                len *= 2;
                val  = (gchar *)tvb_memdup(wmem_packet_scope(), tvb, offset2, len);
                val2 = (gchar *)wmem_alloc(wmem_packet_scope(), len/2+1);

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
        dissect_tds_nt(tvb, pinfo, login_tree, offset2 + len);
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
 * Process TDS 4 "COL_NAME" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 */
static guint
dissect_tds_col_name_token(proto_tree *tree, tvbuff_t *tvb, guint offset, tds_conv_info_t *tds_info,
                           struct _netlib_data *nl_data)
{
    guint next, cur, col=0;
    guint32 len;

    proto_tree_add_item_ret_uint(tree, hf_tds_colname_length, tvb, offset, 2,
                                 tds_get_int2_encoding(tds_info), &len);
    cur = offset + 2;
    next = cur + len;

    while (cur < next) {
        proto_item *col_item;
        proto_tree *col_tree;
        const guint8 *colname;

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = TDS_MAX_COLUMNS;
            return 0;
        }

        col_item = proto_tree_add_item(tree, hf_tds_colname_column, tvb, cur, 0, ENC_NA);
        col_tree = proto_item_add_subtree(col_item, ett_tds_col);

        if (!(nl_data->columns[col])) {
            nl_data->columns[col] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }
        proto_tree_add_item_ret_string_and_length(col_tree, hf_tds_colname_name,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &colname, &len);

        nl_data->columns[col]->name = (const char*)colname;

        if (len > 1) {
            proto_item_set_text(col_item, "Column %d (%s)", col + 1, colname);
        }
        else {
            proto_item_set_text(col_item, "Column %d", col + 1);
        }
        proto_item_set_len(col_item, len);

        col++;
        cur += len;
    }

    nl_data->num_cols = col;
    return cur - offset;
}

/*
 * Process TDS 4 "COLFMT" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 */
static guint
dissect_tds_colfmt_token(proto_tree *tree, tvbuff_t *tvb, guint offset, tds_conv_info_t *tds_info,
                         struct _netlib_data *nl_data)
{
    guint next, cur;
    guint col = 0, len;

    proto_tree_add_item_ret_uint(tree, hf_tds_colfmt_length, tvb, offset, 2,
                                 tds_get_int2_encoding(tds_info), &len);
    cur = offset + 2;
    next = cur + len;

    while (cur < next) {
        proto_item *col_item;
        proto_tree *col_tree;
        guint colstart = cur;
        gboolean first = TRUE;

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = TDS_MAX_COLUMNS;
            return 0;
        }

        col_item = proto_tree_add_item(tree, hf_tds_colfmt_column, tvb, cur, 0, ENC_NA);
        col_tree = proto_item_add_subtree(col_item, ett_tds_col);

        proto_item_set_text(col_item, "Column %d", col + 1);

        if (!(nl_data->columns[col])) {
            nl_data->columns[col] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }
        else {
            if (nl_data->columns[col]->name) {
                proto_item_append_text(col_item, " (%s", nl_data->columns[col]->name);
                first = FALSE;
            }
        }
        /* This only is correct for Sybase.
         * MS says that it's a 2-byte user type and a 2-byte flag field.
         * I don't know exactly how MSSQL is distinguished. */
        nl_data->columns[col]->utype = tvb_get_guint32(tvb, cur,
                                                       tds_get_int4_encoding(tds_info));
        proto_tree_add_item(col_tree, hf_tds_colfmt_utype, tvb, cur, 4,
                            tds_get_int4_encoding(tds_info));
        cur += 4;

        nl_data->columns[col]->ctype = tvb_get_guint8(tvb,cur);
        proto_tree_add_item(col_tree, hf_tds_colfmt_ctype, tvb, cur, 1, ENC_NA);
        cur++;

        if (first) {
            proto_item_append_text(col_item, " (%s)",
                                   val_to_str_const(nl_data->columns[col]->ctype,
                                                    tds_data_type_names, "Unknown type"));
            }
        else {
            proto_item_append_text(col_item, ", %s)",
                                   val_to_str_const(nl_data->columns[col]->ctype,
                                                    tds_data_type_names, "Unknown type"));
        }

        if (!is_fixedlen_type_tds(nl_data->columns[col]->ctype)) {
            if (is_image_type_tds(nl_data->columns[col]->ctype)) {
                gint tnamelen;
                proto_tree_add_item_ret_uint(col_tree, hf_tds_colfmt_csize_long, tvb, cur, 4,
                                             tds_get_int4_encoding(tds_info),
                                             &nl_data->columns[col]->csize);
                cur += 4;
                proto_tree_add_item_ret_length(col_tree, hf_tds_colfmt_text_tablename,
                    tvb, cur, 2,
                    tds_get_char_encoding(tds_info)|tds_get_int2_encoding(tds_info),
                    &tnamelen);
                cur += tnamelen;

            }
            else {
                nl_data->columns[col]->csize = tvb_get_guint8(tvb,cur);
                proto_tree_add_item(col_tree, hf_tds_colfmt_csize, tvb, cur, 1, ENC_NA);
                cur += 1;
            }
        } else {
            nl_data->columns[col]->csize =
                get_size_by_coltype(nl_data->columns[col]->ctype);
        }

        proto_item_set_len(col_item, cur - colstart);

        col += 1;

    } /* while */

    nl_data->num_cols = col;
    return cur - offset;
}

/*
 * Process TDS 5 "ROWFMT" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 */
static guint
dissect_tds_rowfmt_token(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
    guint offset, tds_conv_info_t *tds_info, struct _netlib_data *nl_data)
{
    guint next, cur;
    guint col, len, numcols;
    tds_cursor_info_t *packet_cursor =
        (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);

    proto_tree_add_item_ret_uint(tree, hf_tds_rowfmt_length, tvb, offset, 2,
        tds_get_int4_encoding(tds_info), &len);
    proto_tree_add_item_ret_uint(tree, hf_tds_rowfmt_numcols, tvb, offset + 2, 2,
        tds_get_int2_encoding(tds_info), &numcols);
    next = offset + len + 2; /* Only skip the length field. */
    cur = offset + 4; /* Skip the length and numcols field. */

    col = 0;
    while (cur < next) {
        proto_item *col_item;
        proto_tree *col_tree;
        guint colstart = cur;
        gboolean first = TRUE;
        gint colnamelen;
        gint localelen;
        const guint8 *colname = NULL;

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = TDS_MAX_COLUMNS;
            return 0;
        }

        col_tree = proto_tree_add_subtree_format(tree, tvb, cur, 0,
                       ett_tds_col, &col_item,
                       "Column %d", col + 1);

        if (!(nl_data->columns[col])) {
            nl_data->columns[col] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }

        proto_tree_add_item_ret_string_and_length(col_tree, hf_tds_rowfmt_colname,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &colname, &colnamelen);

        if (colnamelen > 1) {
            proto_item_append_text(col_item, " (%s", colname);
            first = FALSE;
        }
        cur += colnamelen;

        proto_tree_add_item(col_tree, hf_tds_rowfmt_status, tvb, cur, 1, ENC_NA);
        cur += 1;

        nl_data->columns[col]->utype = tvb_get_guint32(tvb, cur,
                                                       tds_get_int4_encoding(tds_info));
        proto_tree_add_item(col_tree, hf_tds_rowfmt_utype, tvb, cur, 4,
            tds_get_int4_encoding(tds_info));
        cur += 4;

        nl_data->columns[col]->ctype = tvb_get_guint8(tvb,cur);
        proto_tree_add_item(col_tree, hf_tds_rowfmt_ctype, tvb, cur, 1, ENC_NA);
        cur++;

        if (first) {
            proto_item_append_text(col_item, " (%s)",
                val_to_str_const(nl_data->columns[col]->ctype,
                    tds_data_type_names, "Unknown type"));
            }
        else {
            proto_item_append_text(col_item, ", %s)",
                val_to_str_const(nl_data->columns[col]->ctype,
                    tds_data_type_names, "Unknown type"));
        }

        if (!is_fixedlen_type_tds(nl_data->columns[col]->ctype)) {
            if (is_image_type_tds(nl_data->columns[col]->ctype)) {
                gint tnamelen;
                proto_tree_add_item_ret_uint(col_tree, hf_tds_rowfmt_csize, tvb, cur, 4,
                    tds_get_int4_encoding(tds_info),
                    &nl_data->columns[col]->csize);
                cur += 4;
                proto_tree_add_item_ret_length(col_tree, hf_tds_rowfmt_text_tablename,
                    tvb, cur, 2,
                    tds_get_char_encoding(tds_info)|tds_get_int2_encoding(tds_info),
                    &tnamelen);
                cur += tnamelen;
            }
            else if (is_longlen_type_sybase(nl_data->columns[col]->ctype)) {
                proto_tree_add_item_ret_uint(col_tree, hf_tds_rowfmt_csize, tvb, cur, 4,
                    tds_get_int4_encoding(tds_info),
                    &nl_data->columns[col]->csize);
                cur += 4;
            }
            else {
                nl_data->columns[col]->csize = tvb_get_guint8(tvb,cur);
                proto_tree_add_item(col_tree, hf_tds_rowfmt_csize, tvb, cur, 1, ENC_NA);
                cur ++;
            }
        } else {
            nl_data->columns[col]->csize =
                get_size_by_coltype(nl_data->columns[col]->ctype);
        }

        if (is_numeric_type_tds(nl_data->columns[col]->ctype)) {
            guint col_precision, col_scale;
            proto_tree_add_item_ret_uint(col_tree, hf_tds_rowfmt_precision,
                tvb, cur, 1, ENC_NA, &col_precision);
            proto_tree_add_item_ret_uint(col_tree, hf_tds_rowfmt_scale,
                tvb, cur + 1, 1, ENC_NA, &col_scale);
            nl_data->columns[col]->precision = col_precision;
            nl_data->columns[col]->scale     = col_scale;
            cur += 2;
        }

        proto_tree_add_item_ret_length(col_tree, hf_tds_rowfmt_locale_info,
            tvb, cur, 1, ENC_NA, &localelen);
        cur += localelen;

        proto_item_set_len(col_item, cur - colstart);

        col += 1;

    } /* while */

    nl_data->num_cols = col;

    /*
     * If there is a packet cursor, we need to copy the struct _netlib_data into it
     * for use by later packets referencing the same cursor.
     */

    if (packet_cursor && !(packet_cursor->tds_cursor_flags & TDS_CURSOR_ROWINFO_VALID)) {
        packet_cursor->tds_cursor_rowinfo = copy_nl_data(wmem_file_scope(), nl_data);
        packet_cursor->tds_cursor_flags |= TDS_CURSOR_ROWINFO_VALID;
    }

    return cur - offset;
}

/*
 * Process TDS 5 "ROWFMT2" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 */
static guint
dissect_tds_rowfmt2_token(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        guint offset, tds_conv_info_t *tds_info, struct _netlib_data *nl_data)
{
    guint next, cur;
    guint col, len, numcols;
    tds_cursor_info_t *packet_cursor =
        (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);

    proto_tree_add_item_ret_uint(tree, hf_tds_rowfmt2_length, tvb, offset, 4,
        tds_get_int4_encoding(tds_info), &len);
    proto_tree_add_item_ret_uint(tree, hf_tds_rowfmt2_numcols, tvb, offset + 4, 2,
        tds_get_int2_encoding(tds_info), &numcols);
    next = offset + len + 4; /* Only skip the length field. */
    cur = offset + 6; /* Skip the length and numcols field. */

    col = 0;
    while (cur < next) {
        proto_item *col_item;
        proto_tree *col_tree;
        guint colstart = cur;
        guint ctype;
        gint labelnamelen, catalognamelen, schemanamelen, tablenamelen, colnamelen, localelen;
        const guint8 *labelname = NULL, *catalogname = (const guint8 * )"", *schemaname = (const guint8 * )"",
                     *tablename = (const guint8*)"", *colname = (const guint8*)"";
        const char *name;

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = TDS_MAX_COLUMNS;
            return 0;
        }

        col_tree = proto_tree_add_subtree_format(tree, tvb, cur, 0,
                       ett_tds_col, &col_item,
                       "Column %d", col + 1);

        if (!(nl_data->columns[col])) {
            nl_data->columns[col] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }
        proto_tree_add_item_ret_string_and_length(col_tree, hf_tds_rowfmt2_labelname,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &labelname, &labelnamelen);
        cur += labelnamelen;

        proto_tree_add_item_ret_string_and_length(col_tree, hf_tds_rowfmt2_catalogname,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &catalogname, &catalognamelen);
        cur += catalognamelen;

        proto_tree_add_item_ret_string_and_length(col_tree, hf_tds_rowfmt2_schemaname,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &schemaname, &schemanamelen);
        cur += schemanamelen;

        proto_tree_add_item_ret_string_and_length(col_tree, hf_tds_rowfmt2_tablename,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &tablename, &tablenamelen);
        cur += tablenamelen;

        proto_tree_add_item_ret_string_and_length(col_tree, hf_tds_rowfmt2_colname,
            tvb, cur, 1, tds_get_char_encoding(tds_info)|ENC_NA,
            wmem_packet_scope(), &colname, &colnamelen);
        cur += colnamelen;

        if (catalognamelen > 1) {
            name = wmem_strjoin(wmem_packet_scope(), ".",
                       catalogname, schemaname, tablename, (const gchar*)colname, NULL);
        }
        else if (schemanamelen > 1) {
            name = wmem_strjoin(wmem_packet_scope(), ".",
                       schemaname, tablename, (const gchar*)colname, NULL);
        }
        else if (tablenamelen > 1) {
            name = wmem_strjoin(wmem_packet_scope(), ".",
                       tablename, (const gchar*)colname, NULL);
        }
        else {
            name = (const gchar*)colname;
        }

        if (labelnamelen > 1) {
            if (strlen(name) > 0) {
                name = wmem_strjoin(wmem_packet_scope(), " AS ",
                           name, (const gchar*)labelname, NULL);
            }
            else {
                name = (const gchar*)labelname;
            }
        }

        nl_data->columns[col]->name = name;

        proto_tree_add_item(col_tree, hf_tds_rowfmt2_status, tvb, cur, 4, tds_get_int4_encoding(tds_info));
        cur += 4;

        nl_data->columns[col]->utype = tvb_get_guint32(tvb, cur,
                                                       tds_get_int4_encoding(tds_info));
        proto_tree_add_item(col_tree, hf_tds_rowfmt2_utype, tvb, cur, 4,
            tds_get_int4_encoding(tds_info));
        cur += 4;

        proto_tree_add_item_ret_uint(col_tree, hf_tds_rowfmt2_ctype, tvb, cur, 1, ENC_NA, &ctype);
        cur++;

        nl_data->columns[col]->ctype = ctype;

        if (!is_fixedlen_type_tds(ctype)) {
            if (is_image_type_tds(ctype)) {
                gint tnamelen;
                proto_tree_add_item_ret_uint(col_tree, hf_tds_rowfmt2_csize, tvb, cur, 4,
                    tds_get_int4_encoding(tds_info),
                    &nl_data->columns[col]->csize);
                cur += 4;
                proto_tree_add_item_ret_length(col_tree, hf_tds_rowfmt2_text_tablename,
                    tvb, cur, 2,
                    tds_get_char_encoding(tds_info)|tds_get_int2_encoding(tds_info),
                    &tnamelen);
                cur += tnamelen;
            }
            else if (is_longlen_type_sybase(ctype)) {
                proto_tree_add_item_ret_uint(col_tree, hf_tds_rowfmt2_csize, tvb, cur, 4,
                    tds_get_int4_encoding(tds_info),
                    &nl_data->columns[col]->csize);
                cur += 4;
            }
            else {
                nl_data->columns[col]->csize = tvb_get_guint8(tvb,cur);
                proto_tree_add_item(col_tree, hf_tds_rowfmt2_csize, tvb, cur, 1, ENC_NA);
                cur ++;
            }
        } else {
            nl_data->columns[col]->csize = get_size_by_coltype(ctype);
        }

        if (is_numeric_type_tds(nl_data->columns[col]->ctype)) {
            proto_tree_add_item(col_tree, hf_tds_rowfmt2_precision, tvb, cur, 1, ENC_NA);
            proto_tree_add_item(col_tree, hf_tds_rowfmt2_scale, tvb, cur + 1, 1, ENC_NA);
            cur += 2;
        }

        proto_tree_add_item_ret_length(col_tree, hf_tds_rowfmt2_locale_info,
            tvb, cur, 1, ENC_NA, &localelen);
        cur += localelen;

        proto_item_set_len(col_item, cur - colstart);

        col += 1;

    } /* while */

    nl_data->num_cols = col;

    /*
     * If there is a packet cursor, we need to copy the struct _netlib_data into it
     * for use by later packets referencing the same cursor.
     */

    if (packet_cursor && !(packet_cursor->tds_cursor_flags & TDS_CURSOR_ROWINFO_VALID)) {
        packet_cursor->tds_cursor_rowinfo = copy_nl_data(wmem_file_scope(), nl_data);
        packet_cursor->tds_cursor_flags |= TDS_CURSOR_ROWINFO_VALID;
    }

    return cur - offset;
}

/*
 * Process TDS "CONTROL" token and store relevant information in the
 * _netlib_data structure for later use (see tds_get_row_size)
 *
 */
static guint
dissect_tds_control_token(proto_tree *tree, tvbuff_t *tvb, guint offset, tds_conv_info_t *tds_info,
                          struct _netlib_data *nl_data)
{
    guint next, cur, col=0;
    guint32 len;
    cur = offset;

    /* TODO: fill in nl_data as necessary. */

    proto_tree_add_item_ret_uint(tree, hf_tds_control_length, tvb, cur, 2,
                                 tds_get_int2_encoding(tds_info), &len);
    cur += 2;

    next = cur + len;
    while (cur < next) {

        if (col >= TDS_MAX_COLUMNS) {
            nl_data->num_cols = TDS_MAX_COLUMNS;
            return 0;
        }

        if (!(nl_data->columns[col])) {
            nl_data->columns[col] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }
        proto_tree_add_item_ret_length(tree, hf_tds_control_fmt, tvb, cur, 1, ENC_NA, &len);

        cur += len;
        col += 1;
    }

    return cur - offset;
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
         * if it is we are screwed
         *
         * Note that all of these offsets include the 8-byte netlib
         * header. Therefore, they are 8 bytes larger than the ones that
         * would be seen in dissect_tds45_login.
         */
        if (bytes_avail < 467) return FALSE;
        tds_major = tvb_get_guint8(tvb, 466);
        if (tds_major != 4 && tds_major != 5) {
            return FALSE;
        }

        /*
         * Ensure that the strings at the front of the login packet
         * have valid lengths.
         */

        /* Hostname */
        if (tvb_get_guint8(tvb, 8 + TDS_MAXNAME) > TDS_MAXNAME)
            return FALSE;
        /* Username */
        if (tvb_get_guint8(tvb, 39 + TDS_MAXNAME) > TDS_MAXNAME)
            return FALSE;
        /* Password */
        if (tvb_get_guint8(tvb, 70 + TDS_MAXNAME) > TDS_MAXNAME)
            return FALSE;
        /* Client process id */
        if (tvb_get_guint8(tvb, 101 + TDS_MAXNAME) > TDS_MAXNAME)
            return FALSE;
    }
    /*
     * and one added by Microsoft in SQL Server 7
     */
    else if (type==TDS_LOGIN7_PKT) {
        if (bytes_avail < 16) return FALSE;
        tds_major = tvb_get_guint8(tvb, 15);
        if (tds_major != 0x70 && tds_major != 0x80) {
            return FALSE;
        }
    } else if (type==TDS5_QUERY_PKT) {
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
dissect_tds_prelogin_response(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint8 token = 0;
    gint tokenoffset, tokenlen, cur = offset, valid = 0;

    /*
     * Test for prelogin format compliance
     * A prelogin response consists solely of "tokens" from 0 to 7, followed by
     * a terminator.
     */

    while(tvb_reported_length_remaining(tvb, cur) > 0)
    {
        token = tvb_get_guint8(tvb, cur);
        cur += 1;

        if(token == TDS7_PRELOGIN_OPTION_TERMINATOR)
            break;

        if(token <= TDS7_PRELOGIN_OPTION_NONCEOPT) {
            valid = 1;
        }
        else {
            valid = 0;
            break;
        }

       tokenoffset = tvb_get_ntohs(tvb, cur);
       if(tokenoffset > tvb_reported_length_remaining(tvb, 0)) {
           valid = 0;
           break;
       }
       cur += 2;

       tokenlen = tvb_get_ntohs(tvb, cur);
       if(tokenlen > tvb_reported_length_remaining(tvb, 0)) {
           valid = 0;
           break;
       }
       cur += 2;
    }

    if(token != TDS7_PRELOGIN_OPTION_TERMINATOR) {
        valid = 0;
    }


    if(valid) {
        /* The prelogin response has the same form as the prelogin request. */
        dissect_tds7_prelogin_packet(tvb, tree, tds_info, TRUE);
    }

    return valid;
}

static int
dissect_tds_order_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint i, length;

    proto_tree_add_item_ret_uint(tree, hf_tds_order_length, tvb, cur, 2,
                                 tds_get_int2_encoding(tds_info), &length);
    cur += 2;

    if (TDS_PROTO_LESS_THAN_TDS7(tds_info)) {
        for (i = 0; i < length; i++) {
            proto_tree_add_item(tree, hf_tds_order_colnum, tvb, cur, 1, ENC_NA);
            cur += 1;
        }
    }
    else {
        for (i = 0; i < length / 2; i++) {
            proto_tree_add_item(tree, hf_tds_order_colnum, tvb, cur, 2, ENC_LITTLE_ENDIAN);
            cur += 2;
        }
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
dissect_tds_row_token(tvbuff_t *tvb, packet_info *pinfo, struct _netlib_data *nl_data, guint offset,
                      proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset, i, type;
    gboolean plp = FALSE;
    tds_cursor_info_t *packet_cursor;

    if (!PINFO_FD_VISITED(pinfo)) {
        if (tds_info->tds_conv_cursor_info && tds_info->tds_conv_cursor_info->tds_conv_cursor_current) {
            tds_cursor_info_t *cursor_current = tds_info->tds_conv_cursor_info->tds_conv_cursor_current;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_tds, 0,
                             cursor_current);
        }
    }

    packet_cursor = (tds_cursor_info_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_tds, 0);

    if (packet_cursor && (packet_cursor->tds_cursor_flags & TDS_CURSOR_ROWINFO_VALID)) {
        nl_data = packet_cursor->tds_cursor_rowinfo;
    }

    for (i = 0; i < nl_data->num_cols; i++) {
        type = nl_data->columns[i]->ctype;
        dissect_tds_type_info_minimal(type, nl_data->columns[i]->csize, &plp);

        dissect_tds_type_varbyte(tvb, &cur, pinfo, tree, hf_tds_row_field, tds_info,
                                 type, nl_data->columns[i]->scale, plp, i+1,
                                 nl_data->columns[i]->name);
    }

    return cur - offset;
}

static int
dissect_tds_nbc_row_token(tvbuff_t *tvb, packet_info *pinfo, struct _netlib_data *nl_data,
                          guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
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

            dissect_tds_type_varbyte(tvb, &cur, pinfo, tree, hf_tds_row_field, tds_info,
                                     nl_data->columns[i]->ctype, nl_data->columns[i]->scale, plp, i+1,
                                     nl_data->columns[i]->name);
        }
    }

    return cur - offset;
}

static int
dissect_tds_returnstatus_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;

    proto_tree_add_item(tree, hf_tds_returnstatus_value, tvb, cur, 4, tds_get_int4_encoding(tds_info));
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
dissect_tds_envchg_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint8 env_type;
    guint new_len, old_len;

    proto_tree_add_item(tree, hf_tds_envchg_length, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
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
        /* B_VARCHAR, Strings */
        proto_tree_add_item_ret_uint(tree, hf_tds_envchg_newvalue_length, tvb, cur, 1, ENC_NA, &new_len);
        cur += 1;
        if(new_len > 0)
        {
            if (tds_char_encoding_is_two_byte(tds_info)) {
                new_len *= 2;
            }
            proto_tree_add_item(tree, hf_tds_envchg_newvalue_string, tvb, cur, new_len,
                                tds_get_char_encoding(tds_info));
            cur += new_len;
        }

        break;

    case 7:
        /* parse collation info structure. From http://www.freetds.org/tds.html#collate */
        proto_tree_add_item_ret_uint(tree, hf_tds_envchg_newvalue_length, tvb, cur, 1, ENC_NA, &new_len);
        cur +=1;
        proto_tree_add_item(tree, hf_tds_envchg_collate_codepage, tvb, cur, 2, tds_get_int2_encoding(tds_info));
        proto_tree_add_item(tree, hf_tds_envchg_collate_flags, tvb, cur + 2, 2, tds_get_int2_encoding(tds_info));

        proto_tree_add_item(tree, hf_tds_envchg_collate_charset_id, tvb, cur + 4, 1, ENC_NA);
        cur += new_len;

        break;

    case 8:
    case 12:
    case 16:
        /* B_VARBYTE */
        proto_tree_add_item_ret_uint(tree, hf_tds_envchg_newvalue_length, tvb, cur, 1, ENC_NA, &new_len);
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
        /* B_VARCHAR, Strings */
        proto_tree_add_item_ret_uint(tree, hf_tds_envchg_oldvalue_length, tvb, cur, 1, ENC_NA, &old_len);
        cur += 1;
        if(old_len > 0) {
            if (tds_char_encoding_is_two_byte(tds_info)) {
                old_len *= 2;
            }
            proto_tree_add_item(tree, hf_tds_envchg_oldvalue_string, tvb, cur, old_len,
                                tds_get_char_encoding(tds_info));
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
        proto_tree_add_item_ret_uint(tree, hf_tds_envchg_oldvalue_length, tvb, cur, 1, ENC_NA, &old_len);
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
dissect_tds_eed_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    gint32 msg_len, len;

    proto_tree_add_item(tree, hf_tds_eed_length, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
    cur += 2;

    proto_tree_add_item(tree, hf_tds_eed_number, tvb, cur, 4,
                              tds_get_int4_encoding(tds_info));
    cur += 4;
    proto_tree_add_item(tree, hf_tds_eed_state, tvb, cur, 1, ENC_NA);
    cur += 1;
    proto_tree_add_item(tree, hf_tds_eed_class, tvb, cur, 1, ENC_NA);
    cur += 1;

    proto_tree_add_item_ret_length(tree, hf_tds_eed_sql_state, tvb, cur, 1,
        ENC_NA, &len);
    cur += len;

    proto_tree_add_item(tree, hf_tds_eed_status, tvb, cur, 1, ENC_NA);
    cur += 1;

    proto_tree_add_item(tree, hf_tds_eed_transtate, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
    cur += 2;

    proto_tree_add_item_ret_length(tree, hf_tds_eed_msgtext, tvb, cur, 2,
         tds_get_char_encoding(tds_info)|tds_get_int2_encoding(tds_info),
         &msg_len);
    cur += msg_len;

    proto_tree_add_item_ret_length(tree, hf_tds_eed_servername, tvb, cur, 1,
         tds_get_char_encoding(tds_info)|ENC_NA, &msg_len);
    cur += msg_len;

    proto_tree_add_item_ret_length(tree, hf_tds_eed_procname, tvb, cur, 1,
         tds_get_char_encoding(tds_info)|ENC_NA, &msg_len);
    cur += msg_len;

    proto_tree_add_item(tree, hf_tds_eed_linenumber, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
    cur += 2;

    /* TODO Handle EED follows? Maybe handled as separate tokens. */

    return cur - offset;
}

static int
dissect_tds_error_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint32 msg_len;
    guint32 srvr_len, proc_len;

    proto_tree_add_item(tree, hf_tds_error_length, tvb, cur, 2, tds_get_int2_encoding(tds_info));
    cur += 2;

    proto_tree_add_item(tree, hf_tds_error_number, tvb, cur, 4, tds_get_int4_encoding(tds_info));
    cur += 4;
    proto_tree_add_item(tree, hf_tds_error_state, tvb, cur, 1, ENC_NA);
    cur +=1;
    proto_tree_add_item(tree, hf_tds_error_class, tvb, cur, 1, ENC_NA);
    cur +=1;

    proto_tree_add_item_ret_uint(tree, hf_tds_error_msgtext_length, tvb, cur, 2,
        tds_get_int2_encoding(tds_info), &msg_len);
    cur +=2;

    if (tds_char_encoding_is_two_byte(tds_info)) {
        msg_len *= 2;
    }
    proto_tree_add_item(tree, hf_tds_error_msgtext, tvb, cur, msg_len, tds_get_char_encoding(tds_info));
    cur += msg_len;

    proto_tree_add_item_ret_uint(tree, hf_tds_error_servername_length, tvb, cur, 1, ENC_NA, &srvr_len);
    cur +=1;
    if(srvr_len) {
        if (tds_char_encoding_is_two_byte(tds_info)) {
            srvr_len *=2;
        }
        proto_tree_add_item(tree, hf_tds_error_servername, tvb, cur, srvr_len, tds_get_char_encoding(tds_info));
        cur += srvr_len;
    }

    proto_tree_add_item_ret_uint(tree, hf_tds_error_procname_length, tvb, cur, 1, ENC_NA, &proc_len);
    cur +=1;
    if(proc_len) {
        if (tds_char_encoding_is_two_byte(tds_info)) {
            proc_len *=2;
        }
        proto_tree_add_item(tree, hf_tds_error_procname, tvb, cur, proc_len, tds_get_char_encoding(tds_info));
        cur += proc_len;
    }

    if (TDS_PROTO_TDS7_1_OR_LESS(tds_info)) {
        proto_tree_add_item(tree, hf_tds_error_linenumber_16, tvb, cur, 2, tds_get_int2_encoding(tds_info));
        cur += 2;
    } else {
        proto_tree_add_item(tree, hf_tds_error_linenumber_32, tvb, cur, 4, tds_get_int4_encoding(tds_info));
        cur += 4;
    }

    return cur - offset;
}

static int
dissect_tds_info_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint32 msg_len;
    guint32 srvr_len, proc_len;

    proto_tree_add_item(tree, hf_tds_info_length, tvb, cur, 2, tds_get_int2_encoding(tds_info));
    cur += 2;

    proto_tree_add_item(tree, hf_tds_info_number, tvb, cur, 4, tds_get_int4_encoding(tds_info));
    cur += 4;
    proto_tree_add_item(tree, hf_tds_info_state, tvb, cur, 1, ENC_NA);
    cur +=1;
    proto_tree_add_item(tree, hf_tds_info_class, tvb, cur, 1, ENC_NA);
    cur +=1;

    proto_tree_add_item_ret_uint(tree, hf_tds_info_msgtext_length, tvb, cur, 2,
                                 tds_get_int2_encoding(tds_info), &msg_len);
    cur +=2;

    if (tds_char_encoding_is_two_byte(tds_info)) {
        msg_len *= 2;
    }
    proto_tree_add_item(tree, hf_tds_info_msgtext, tvb, cur, msg_len, tds_get_char_encoding(tds_info));

    cur += msg_len;

    proto_tree_add_item_ret_uint(tree, hf_tds_info_servername_length, tvb, cur, 1, ENC_NA, &srvr_len);
    cur +=1;
    if(srvr_len) {
        if (tds_char_encoding_is_two_byte(tds_info)) {
            srvr_len *=2;
        }
        proto_tree_add_item(tree, hf_tds_info_servername, tvb, cur, srvr_len, tds_get_char_encoding(tds_info));
        cur += srvr_len;
    }

    proto_tree_add_item_ret_uint(tree, hf_tds_info_procname_length, tvb, cur, 1, ENC_NA, &proc_len);
    cur +=1;
    if(proc_len) {
        if (tds_char_encoding_is_two_byte(tds_info)) {
            proc_len *=2;
        }
        proto_tree_add_item(tree, hf_tds_info_procname, tvb, cur, proc_len, tds_get_char_encoding(tds_info));
        cur += proc_len;
    }

    if (TDS_PROTO_TDS7_1_OR_LESS(tds_info)) {
        proto_tree_add_item(tree, hf_tds_info_linenumber_16, tvb, cur, 2, tds_get_int2_encoding(tds_info));
        cur += 2;
    } else {
        proto_tree_add_item(tree, hf_tds_info_linenumber_32, tvb, cur, 4, tds_get_int4_encoding(tds_info));
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

    proto_tree_add_item(tree, hf_tds_loginack_length, tvb, cur, 2, tds_get_int2_encoding(tds_info));
    cur += 2;

    proto_tree_add_item(tree, hf_tds_loginack_interface, tvb, cur, 1, ENC_NA);
    cur +=1;
    proto_tree_add_item_ret_uint(tree, hf_tds_loginack_tdsversion, tvb, cur, 4, ENC_BIG_ENDIAN, &tds_version);
    set_tds_version(tds_info, tds_version);

    cur += 4;

    msg_len = tvb_get_guint8(tvb, cur);
    cur +=1;

    if (tds_char_encoding_is_two_byte(tds_info)) {
        msg_len *= 2;
    }
    proto_tree_add_item(tree, hf_tds_loginack_progname, tvb, cur, msg_len,
                        tds_get_char_encoding(tds_info));
    cur += msg_len;

    proto_tree_add_item(tree, hf_tds_loginack_progversion, tvb, cur, 4, ENC_BIG_ENDIAN);

    cur += 4;

    return cur - offset;
}

static int
dissect_tds7_colmetadata_token(tvbuff_t *tvb, struct _netlib_data *nl_data, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;
    guint16 num_columns, flags, msg_len;
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
        return 2;
    }
    cur +=2;

    for(i=0; i != num_columns; i++) {

        col_offset = cur;

        col_item = proto_tree_add_item(tree, hf_tds_colmetadata_field, tvb, cur, 0, ENC_NA);
        col_tree = proto_item_add_subtree(col_item, ett_tds_col);
        proto_item_set_text(col_item, "Column %d", i + 1);

        if (!(nl_data->columns[i])) {
            nl_data->columns[i] = wmem_new0(wmem_packet_scope(), struct _tds_col);
        }

        if (TDS_PROTO_TDS7_1_OR_LESS(tds_info)) {
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
                if(TDS_PROTO_TDS7_2_OR_GREATER(tds_info)) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_computed, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_3A_OR_LESS(tds_info)) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_reservedodbc, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_2_OR_GREATER(tds_info)) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_fixedlenclrtype, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_3B_OR_GREATER(tds_info)) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_sparsecolumnset, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_4_OR_GREATER(tds_info)) {
                    proto_tree_add_item(flags_tree, hf_tds_colmetadata_flags_encrypted, tvb, cur, 2, ENC_BIG_ENDIAN);
                }
                if(TDS_PROTO_TDS7_2_OR_GREATER(tds_info)) {
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
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large2_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;
                    break;
                }
                case TDS_DATA_TYPE_BIGVARCHR:
                {
                    nl_data->columns[i]->csize = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large2_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
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
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large2_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                    cur += 2;
                    break;
                }
                case TDS_DATA_TYPE_BIGCHAR:
                case TDS_DATA_TYPE_NVARCHAR:
                case TDS_DATA_TYPE_NCHAR:
                {
                    nl_data->columns[i]->csize = tvb_get_guint16(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large2_type_size, tvb, cur, 2, ENC_LITTLE_ENDIAN);
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
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_maxbytesize, tvb, cur, 2, ENC_LITTLE_ENDIAN);
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
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large4_type_size, tvb, cur, 4, ENC_LITTLE_ENDIAN);
                    cur += 4;

                    /* Table name */
                    if (TDS_PROTO_TDS7_2_OR_GREATER(tds_info)) {
                        guint numparts = tvb_get_guint8(tvb, cur);
                        guint parti;
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_parts, tvb, cur, 1, ENC_LITTLE_ENDIAN);
                        cur += 1;

                        for(parti = 0; parti < numparts; parti++)
                        {
                            guint partlen = tvb_get_letohs(tvb, cur);
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name, tvb, cur + 2, partlen * 2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                            cur += 2 + (partlen * 2);
                        }
                    }
                    else {
                        guint tablenamelen = tvb_get_letohs(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name, tvb, cur + 2, tablenamelen * 2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += 2 + (tablenamelen * 2);
                    }
                    break;
                }
                case TDS_DATA_TYPE_TEXT:
                case TDS_DATA_TYPE_NTEXT:
                {
                    nl_data->columns[i]->csize = tvb_get_guint32(tvb, cur, encoding);
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large4_type_size, tvb, cur, 4, ENC_LITTLE_ENDIAN);
                    cur += 4;

                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_codepage, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_flags, tvb, cur, 2, ENC_LITTLE_ENDIAN );
                    cur += 2;
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_collate_charset_id, tvb, cur, 1, ENC_LITTLE_ENDIAN );
                    cur +=1;

                    /* Table name */
                    if (TDS_PROTO_TDS7_2_OR_GREATER(tds_info)) {
                        guint numparts = tvb_get_guint8(tvb, cur);
                        guint parti;
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_parts, tvb, cur, 1, ENC_LITTLE_ENDIAN);
                        cur += 1;

                        for(parti = 0; parti < numparts; parti++)
                        {
                            guint partlen = tvb_get_letohs(tvb, cur);
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name, tvb, cur + 2, partlen * 2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                            cur += 2 + (partlen * 2);
                        }
                    }
                    else {
                        guint tablenamelen = tvb_get_letohs(tvb, cur);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name_length, tvb, cur, 2, ENC_LITTLE_ENDIAN);
                        proto_tree_add_item(col_tree, hf_tds_colmetadata_table_name, tvb, cur + 2, tablenamelen * 2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
                        cur += 2 + (tablenamelen * 2);
                    }

                    break;
                }
                case TDS_DATA_TYPE_SSVARIANT:
                {
                    proto_tree_add_item(col_tree, hf_tds_colmetadata_large4_type_size, tvb, cur, 4, ENC_LITTLE_ENDIAN);
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

/* Valid status fields for TDS_DONEINPROC_TOKEN
 * One  field is not valid in this token.
 */

static int * const done_status_flags[] = {
    &hf_tds_done_status_more,
    &hf_tds_done_status_error,
    &hf_tds_done_status_inxact,
    &hf_tds_done_status_proc,
    &hf_tds_done_status_count,
    &hf_tds_done_status_attn,
    &hf_tds_done_status_event,
    &hf_tds_done_status_srverror,
    NULL
};

static int
dissect_tds_done_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;

    proto_tree_add_bitmask(tree, tvb, cur, hf_tds_done_status, ett_tds_done_status,
                           done_status_flags, tds_get_int2_encoding(tds_info));
    cur += 2;
    proto_tree_add_item(tree, hf_tds_done_curcmd, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
    cur += 2;
    if (TDS_PROTO_TDS7_1_OR_LESS(tds_info)) {
        proto_tree_add_item(tree, hf_tds_done_donerowcount_32, tvb, cur, 4,
                            tds_get_int4_encoding(tds_info));
        cur += 4;
    } else {
        /* TDS 7 is always little-endian. */
        proto_tree_add_item(tree, hf_tds_done_donerowcount_64, tvb, cur, 8, ENC_LITTLE_ENDIAN);
        cur += 8;
    }

    return cur - offset;
}

/* Valid status fields for TDS_DONEINPROC_TOKEN
 * All fields are valid in this token.
 */

static int * const doneproc_status_flags[] = {
    &hf_tds_done_status_more,
    &hf_tds_done_status_error,
    &hf_tds_done_status_inxact,
    &hf_tds_done_status_proc,
    &hf_tds_done_status_count,
    &hf_tds_done_status_attn,
    &hf_tds_done_status_event,
    &hf_tds_done_status_rpcinbatch,
    &hf_tds_done_status_srverror,
    NULL
};

static int
dissect_tds_doneproc_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;

    proto_tree_add_bitmask(tree, tvb, cur, hf_tds_doneproc_status, ett_tds_done_status,
                           doneproc_status_flags, tds_get_int2_encoding(tds_info));
    cur += 2;
    proto_tree_add_item(tree, hf_tds_doneproc_curcmd, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
    cur += 2;
    if (TDS_PROTO_TDS7_1_OR_LESS(tds_info)) {
        proto_tree_add_item(tree, hf_tds_doneproc_donerowcount_32, tvb, cur, 4,
                            tds_get_int4_encoding(tds_info));
        cur += 4;
    } else {
        /* TDS 7 is always little-endian. */
        proto_tree_add_item(tree, hf_tds_doneproc_donerowcount_64, tvb, cur, 8, ENC_LITTLE_ENDIAN);
        cur += 8;
    }

    return cur - offset;
}

/* Valid status fields for TDS_DONEINPROC_TOKEN
 * A few fields are not valid in this token.
 *
 * This token occurs much more frequently when stored procedures are used, so
 * it's worthwhile to make a separate list.
 */
static int * const doneinproc_status_flags[] = {
    &hf_tds_done_status_more,
    &hf_tds_done_status_error,
    &hf_tds_done_status_inxact,
    &hf_tds_done_status_count,
    &hf_tds_done_status_attn,
    &hf_tds_done_status_event,
    &hf_tds_done_status_srverror,
    NULL
};

static int
dissect_tds_doneinproc_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info)
{
    guint cur = offset;

    proto_tree_add_bitmask(tree, tvb, cur, hf_tds_doneinproc_status, ett_tds_done_status,
                           doneinproc_status_flags, tds_get_int2_encoding(tds_info));
    cur += 2;
    proto_tree_add_item(tree, hf_tds_doneinproc_curcmd, tvb, cur, 2,
                        tds_get_int2_encoding(tds_info));
    cur += 2;
    if (TDS_PROTO_TDS7_1_OR_LESS(tds_info)) {
        proto_tree_add_item(tree, hf_tds_doneinproc_donerowcount_32, tvb, cur, 4,
                            tds_get_int4_encoding(tds_info));
        cur += 4;
    } else {
        /* TDS 7 is always little-endian. */
        proto_tree_add_item(tree, hf_tds_doneinproc_donerowcount_64, tvb, cur, 8, ENC_LITTLE_ENDIAN);
        cur += 8;
    }

    return cur - offset;
}

static int
dissect_tds_procid_token(tvbuff_t *tvb, guint offset, proto_tree *tree, tds_conv_info_t *tds_info _U_ )
{
    guint cur = offset;

    proto_tree_add_item(tree, hf_tds_procid_value, tvb, cur, 8, ENC_NA);
    cur += 8;

    return cur - offset;
}

static guint8
dissect_tds_type_info(tvbuff_t *tvb, gint *offset, packet_info *pinfo, proto_tree *tree, gboolean *plp, gboolean variantprop)
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
        case TDS_DATA_TYPE_DECIMAL:         /* Decimal (TDS 4/5) */
        case TDS_DATA_TYPE_NUMERIC:         /* Numeric (TDS 4/5) */
        case TDS_DATA_TYPE_BITN:
        case TDS_DATA_TYPE_DECIMALN:        /* Decimal */
        case TDS_DATA_TYPE_NUMERICN:        /* Numeric */
        case TDS_DATA_TYPE_FLTN:
        case TDS_DATA_TYPE_MONEYN:
        case TDS_DATA_TYPE_DATETIMN:
        case TDS_DATA_TYPE_DATEN:           /* (introduced in TDS 7.3) */
        case TDS_DATA_TYPE_CHAR:            /* Char (TDS 4/5) */
        case TDS_DATA_TYPE_VARCHAR:         /* VarChar (TDS 4/5) */
        case TDS_DATA_TYPE_BINARY:          /* Binary (TDS 4/5) */
        case TDS_DATA_TYPE_VARBINARY:       /* VarBinary (TDS 4/5) */
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
        case TDS_DATA_TYPE_DECIMAL:         /* Decimal (TDS 4/5) */
        case TDS_DATA_TYPE_NUMERIC:         /* Numeric (TDS 4/5) */
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
dissect_tds_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, tds_conv_info_t *tds_info)
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
            case TDS_PROTOCOL_5:
                len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_tds_rpc_name_length8, tvb, offset, 1, ENC_NA);
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
            dissect_tds_type_varbyte(tvb, &offset, pinfo, sub_tree, hf_tds_rpc_parameter_value, tds_info,
                                     data_type, 0, plp, -1, NULL); /* TODO: Precision needs setting? */
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
tds7_token_to_idx(guint8 token)
{
    /* TODO: Commented out entries are token types which are not currently dissected
     * Although they are known values, we cannot step over the bytes as token length is unknown
     * Better therefore to return unknown token type and highlight to user
    */

    /*
     * Token values for TDS7.
     * Microsoft and Sybase have separately expanded the protocol and have
     * each used numbers differently.
     */

    switch(token)
    {
    /*case TDS7_ALTMETADATA_TOKEN: return hf_tds_altmetadata;*/
    /*case TDS_ALTROW_TOKEN: return hf_tds_altrow;*/
    /*case TDS_COL_NAME_TOKEN: return hf_tds_colname;*/
    case TDS_CAPABILITY_TOKEN: return hf_tds_capability;
    case TDS_COLFMT_TOKEN: return hf_tds_colfmt;
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

    (void) memset(&nl_data, '\0', sizeof nl_data);

    /* Test for pre-login response in case this response is not a token stream */
    if(dissect_tds_prelogin_response(tvb, pos, tree, tds_info) == 1)
    {
        return;
    }

    /*
     * Until we reach the end of the packet, read tokens.
     */
    while (tvb_reported_length_remaining(tvb, pos) > 0) {
        /* our token */
        token = tvb_get_guint8(tvb, pos);

        if(TDS_PROTO_LESS_THAN_TDS7(tds_info))
        {

            token_item = proto_tree_add_item(tree, tds45_token_to_idx(token), tvb,
                                             pos, tvb_reported_length_remaining(tvb, pos), ENC_NA);
            token_tree = proto_item_add_subtree(token_item, ett_tds_token);

            token_sz = 0;
            switch (token) {
                case TDS_CAPABILITY_TOKEN:
                    token_sz = dissect_tds5_capability_token(tvb, pinfo, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_CURINFO_TOKEN:
                    token_sz = dissect_tds5_curinfo_token(tvb, pinfo, pos + 1, token_tree, tds_info) + 1;
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
                case TDS5_EED_TOKEN:
                    token_sz = dissect_tds_eed_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_ENVCHG_TOKEN:
                    token_sz = dissect_tds_envchg_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_COL_NAME_TOKEN:
                    token_sz = dissect_tds_col_name_token(token_tree, tvb, pos + 1, tds_info, &nl_data) + 1;
                    break;
                case TDS_COLFMT_TOKEN:
                    token_sz = dissect_tds_colfmt_token(token_tree, tvb, pos + 1, tds_info, &nl_data) + 1;
                    break;
                case TDS_CONTROL_TOKEN:
                    token_sz = dissect_tds_control_token(token_tree, tvb, pos + 1, tds_info, &nl_data) + 1;
                    break;
                case TDS_ERR_TOKEN:
                    token_sz = dissect_tds_error_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_INFO_TOKEN:
                    token_sz = dissect_tds_info_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_LOGIN_ACK_TOKEN:
                    token_sz = dissect_tds_login_ack_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS5_MSG_TOKEN:
                    token_sz = dissect_tds5_msg_token(token_tree, tvb, pos + 1, tds_info) + 1;
                    break;
                case TDS_ORDER_TOKEN:
                    token_sz = dissect_tds_order_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS5_PARAMFMT_TOKEN:
                    token_sz = dissect_tds_paramfmt_token(token_tree, tvb, pos + 1, tds_info, &nl_data) + 1;
                    break;
                case TDS5_PARAMFMT2_TOKEN:
                    token_sz = dissect_tds_paramfmt2_token(token_tree, tvb, pos + 1, tds_info, &nl_data) + 1;
                    break;
                case TDS5_PARAMS_TOKEN:
                    token_sz = dissect_tds5_params_token(tvb, pinfo, &nl_data, pos + 1,
                                                         token_tree, token_item, tds_info) + 1;
                    break;
                case TDS_PROCID_TOKEN:
                    token_sz = dissect_tds_procid_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_RET_STAT_TOKEN:
                    token_sz = dissect_tds_returnstatus_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_ROW_TOKEN:
                    token_sz = dissect_tds_row_token(tvb, pinfo, &nl_data, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS5_ROWFMT_TOKEN:
                    token_sz = dissect_tds_rowfmt_token(token_tree, tvb, pinfo, pos + 1, tds_info, &nl_data) + 1;
                    break;
                case TDS5_ROWFMT2_TOKEN:
                    token_sz = dissect_tds_rowfmt2_token(token_tree, tvb, pinfo, pos + 1, tds_info, &nl_data) + 1;
                    break;

                default:
                    break;
            }
            if (token_sz == 0) {
                expert_add_info_format(pinfo, token_item, &ei_tds_token_length_invalid,
                                       "Bogus token size: %u", token_sz);
                break;
            }
            else {
                proto_item_set_len(token_item, token_sz);
            }

            pos += token_sz;

        } else {

            token_item = proto_tree_add_item(tree, tds7_token_to_idx(token), tvb, pos,
                                             tvb_reported_length_remaining(tvb, pos), ENC_NA);
            token_tree = proto_item_add_subtree(token_item, ett_tds_token);

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
                    token_sz = dissect_tds_envchg_token(tvb, pos + 1, token_tree, tds_info) + 1;
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
                    token_sz = dissect_tds_nbc_row_token(tvb, pinfo, &nl_data, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_OFFSET_TOKEN:
                    token_sz = dissect_tds_offset_token(tvb, pos + 1, token_tree) + 1;
                    break;
                case TDS_ORDER_TOKEN:
                    token_sz = dissect_tds_order_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_RET_STAT_TOKEN:
                    token_sz = dissect_tds_returnstatus_token(tvb, pos + 1, token_tree, tds_info) + 1;
                    break;
                case TDS_ROW_TOKEN:
                    token_sz = dissect_tds_row_token(tvb, pinfo, &nl_data, pos + 1, token_tree, tds_info) + 1;
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
fill_tds_info_defaults(tds_conv_info_t *tds_info)
{
    tds_info->tds_conv_cursor_info = NULL;
    if (tds_little_endian) {
        tds_info->tds_encoding_int4 = TDS_INT4_LITTLE_ENDIAN;
        tds_info->tds_encoding_int2 = TDS_INT2_LITTLE_ENDIAN;
    }
    else {
        tds_info->tds_encoding_int4 = TDS_INT4_BIG_ENDIAN;
        tds_info->tds_encoding_int2 = TDS_INT2_BIG_ENDIAN;
    }

    switch (tds_protocol_type) {
        case TDS_PROTOCOL_4:
        case TDS_PROTOCOL_5:
            tds_info->tds_encoding_char = TDS_CHAR_ASCII;
            break;

        case TDS_PROTOCOL_7_0:
        case TDS_PROTOCOL_7_1:
        case TDS_PROTOCOL_7_2:
        case TDS_PROTOCOL_7_3:
        case TDS_PROTOCOL_7_3A:
        case TDS_PROTOCOL_7_3B:
        case TDS_PROTOCOL_7_4:
        case TDS_PROTOCOL_NOT_SPECIFIED:
        default:
            tds_info->tds_encoding_int4  = TDS_INT4_LITTLE_ENDIAN;
            tds_info->tds_encoding_int2  = TDS_INT2_LITTLE_ENDIAN;
            tds_info->tds_encoding_char  = TDS_CHAR_UTF16;
            tds_info->tds_encoding_date8 = TDS_DATE8_DATE_FIRST ;
            tds_info->tds_encoding_date4 = TDS_DATE4_DATE_FIRST ;
            break;
    }
}

static void
dissect_netlib_buffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *tds_item;
    proto_tree *tds_tree;
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

    static int * const status_flags[] = {
        &hf_tds_status_eom,
        &hf_tds_status_ignore,
        &hf_tds_status_event_notif,
        &hf_tds_status_reset_conn,
        &hf_tds_status_reset_conn_skip_tran,
        NULL
    };

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
        tds_info->tds_version = TDS_PROTOCOL_NOT_SPECIFIED;
        tds_info->tds_packets_in_order = 0;
        fill_tds_info_defaults(tds_info);
        conversation_add_proto_data(conv, proto_tds, tds_info);
    }

    /* create display subtree for the protocol */
    tds_item = proto_tree_add_item(tree, proto_tds, tvb, offset, -1, ENC_NA);
    tds_tree = proto_item_add_subtree(tds_item, ett_tds);

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tds_tree, hf_tds_type, tvb, offset, 1, ENC_NA);

    status = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_bitmask(tds_tree, tvb, offset+1, hf_tds_status, ett_tds_status, status_flags, ENC_NA);
    proto_tree_add_item(tds_tree, hf_tds_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    channel = tvb_get_ntohs(tvb, offset + 4);
    proto_tree_add_item(tds_tree, hf_tds_channel, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    packet_number = tvb_get_guint8(tvb, offset + 6);
    proto_tree_add_item(tds_tree, hf_tds_packet_number, tvb, offset + 6, 1, ENC_NA);
    proto_tree_add_item(tds_tree, hf_tds_window, tvb, offset + 7, 1, ENC_NA);

    offset += 8;        /* skip Netlib header */

    /*
     * Deal with fragmentation.
     *
     */
    save_fragmented = pinfo->fragmented;

    /*
     * Don't even try to defragment if it's not a valid TDS type, because we're probably
     * not looking at a valid Netlib header. This can occur for partial captures.
     */
    if (tds_defragment && is_valid_tds_type(type) && is_valid_tds_status(status)) {
         if (((!(status & STATUS_LAST_BUFFER)) &&
                (packet_number == 0) &&
                (channel == 0)) ||
             tds_info->tds_packets_in_order) {
            /*
             * Assumptions:
             * Packet number of zero on a fragment typically will occur only when
             * they are going to appear in order. This will happen with DB-Library
             * or CT-Library.
             * Exception:
             * When a more modern stream has a large number of fragments and the packet
             * number wraps back to zero.
             * Heuristic:
             * In the exception case, the channel number will be non-zero. This is what
             * has been observed, but it's probably not guaranteed.
             */

            tds_info->tds_packets_in_order = 1;

            if (!(status & STATUS_LAST_BUFFER)) {
                col_append_str(pinfo->cinfo, COL_INFO, " (Not last buffer)");
            }
            len = tvb_reported_length_remaining(tvb, offset);

            last_buffer = ((status & STATUS_LAST_BUFFER) == STATUS_LAST_BUFFER);
            fd_head = fragment_add_seq_next(&tds_reassembly_table, tvb, offset,
                                             pinfo, channel, NULL,
                                             len, !last_buffer);
            next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                "Reassembled TDS", fd_head, &tds_frag_items, NULL,
                                                tds_tree);
        }
        else if (packet_number > 1 || !(status & STATUS_LAST_BUFFER)) {
            /*
             * Assumptions:
             * This is TDS7, and the packets are correctly numbered from 1.
             * This is either a first fragment, or one of a group of fragments.
             *
             * XXX - This might not work if the packet number wraps to zero on
             * the very last buffer of a sequence.
             */

            if (!(status & STATUS_LAST_BUFFER)) {
                col_append_str(pinfo->cinfo, COL_INFO, " (Not last buffer)");
            }
            len = tvb_reported_length_remaining(tvb, offset);
            /*
             * XXX - I've seen captures that start with a login
             * packet with a sequence number of 2.  In one, there's
             * a TDS7 pre-login message with a packet number of 0,
             * to which the response has a packet number of 1, and
             * then a TDS4/5 login message with a packet number of 2
             * and "end of message" not set, followed by a TDS4/5 login
             * message with a packet number of 3 and "end of message",
             * to which there's a response with a packet number of 1.
             *
             * The TCP sequence numbers do *not* indicate that any
             * data is missing, so the TDS4/5 login was sent with a
             * packet number of 2, immediately after the TDS7 pre-login
             * message with a packet number of 0.
             *
             * Given that we are running atop a reliable transport,
             * we could try doing some form of reassembly that just
             * accumulates packets until we get an EOM, just checking
             * to make sure that each packet added to the reassembly
             * process has a sequence number that - modulo 256! - has
             * is one greater than the sequence number of the previous
             * packet added to the reassembly.
             */

            last_buffer = ((status & STATUS_LAST_BUFFER) == STATUS_LAST_BUFFER);
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
        }
        else {
            /* We're defragmenting, but this isn't a fragment. */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
        }

    }
    else {
        /*
         * We're not defragmenting, or this is an invalid Netlib header.
         *
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
                dissect_tds_rpc(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS_RESP_PKT:
                dissect_tds_resp(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS_LOGIN_PKT:
                dissect_tds45_login(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS_LOGIN7_PKT:
                dissect_tds7_login(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS_QUERY_PKT:
                dissect_tds_query_packet(next_tvb, pinfo, tds_tree, tds_info);
                break;
            case TDS5_QUERY_PKT:
                dissect_tds5_tokenized_request_packet(next_tvb, pinfo, tds_tree,
                                                      tds_info);
                break;
            case TDS_SSPI_PKT:
                dissect_tds_nt(next_tvb, pinfo, tds_tree, offset - 8);
                break;
            case TDS_TRANS_MGR_PKT:
                dissect_tds_transmgr_packet(next_tvb, pinfo, tds_tree);
                break;
            case TDS_ATTENTION_PKT:
                break;
            case TDS_PRELOGIN_PKT:
                dissect_tds7_prelogin_packet(next_tvb, tds_tree, tds_info, FALSE);
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
dissect_tds_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint32 type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TDS");
    col_clear(pinfo->cinfo, COL_INFO);

    type = tvb_get_guint8(tvb, 0);
    if (type == TDS_SMP_PKT)
    {
        /* if the type is SMP, it's shimmed in between TDS and lower layer */
        call_dissector(smp_handle, tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s", val_to_str(type, packet_type_names, "Unknown Packet Type: %u"));

    dissect_netlib_buffer(tvb, pinfo, tree);

    col_set_fence(pinfo->cinfo, COL_INFO);

    return tvb_captured_length(tvb);
}

static guint
get_tds_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint  plen;
    guint8 type;

    type = tvb_get_guint8(tvb, offset);

    switch (type)
    {
        case TDS_SMP_PKT:
            /* Special case for SMP dissector */
            plen = tvb_get_letohl(tvb, offset + 4);
            break;
        case TDS_TLS_PKT:
            /* Special test for TLS to that we don't have lots of incorrect reports of malformed packets */
            plen = tvb_get_ntohs(tvb, offset + 3) + 5;
            break;
        default:
            plen = tvb_get_ntohs(tvb, offset + 2);
            break;
    }

   return plen;
}

static int
dissect_tds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
   tcp_dissect_pdus(tvb, pinfo, tree, tds_desegment, 8, get_tds_pdu_len, dissect_tds_pdu, data);
   return tvb_captured_length(tvb);
}

static gboolean
dissect_tds_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    guint8 type;
    guint8 status;
    guint16 plen;

    /*
     * If we don't have even enough data for a Netlib header,
     * just say it's not TDS.
     */
    if (tvb_reported_length(tvb) < 8)
        return FALSE;

    /*
     * Quickly scan all the data we have in order to see if
     * everything in it looks like Netlib traffic.
     */

    /*
     * Check the type field.
     */
    type = tvb_get_guint8(tvb, offset);
    if (!is_valid_tds_type(type))
        return FALSE;

    /*
     * Check the status field
     */
    status = tvb_get_guint8(tvb, offset + 1);
    if (!is_valid_tds_status(status))
        return FALSE;

    /*
     * Get the length of the PDU.
     */
    plen = tvb_get_ntohs(tvb, offset + 2);
    if (plen < 8) {
        /*
         * The length is less than the header length.
         * That's bogus.
         */
        return FALSE;
    }

    if (!netlib_check_login_pkt(tvb, offset, pinfo, type))
        return FALSE;

    /*
     * Now dissect it as TDS.
     */
    dissect_tds(tvb, pinfo, tree, data);

    return TRUE;
}

static void
version_convert( gchar *result, guint32 hexver )
{
    /* Version string is major(8).minor(8).build(16) in big-endian order.
     * By specifying ENC_BIG_ENDIAN, the bytes have been swapped before we
     * see them.
     */
    g_snprintf( result, ITEM_LABEL_LENGTH, "%d.%d.%d",
        (hexver >> 24) & 0xFF, (hexver >> 16) & 0xFF, (hexver & 0xFFFF));
}

static void
apply_tds_prefs(void) {
    tds_tcp_ports = prefs_get_range_value("tds", "tcp.port");
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

        /* CAPABILITY token */
        { &hf_tds_capability,
          { "Token - Capability", "tds.capabilty",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_capability_length,
          { "Token length", "tds.capability.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_capability_captype,
          { "Capability type", "tds.capability.captype",
            FT_UINT8, BASE_DEC, VALS(tds_capability_type), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_capability_caplen,
          { "Capability len", "tds.capability.caplen",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_lang,
          { "Language requests", "tds.capability.req.lang",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_rpc,
          { "RPC requests", "tds.capability.req.rpc",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_evt,
          { "RPC event notifications", "tds.capability.req.evt",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_mstmt,
          { "Multiple commands per request", "tds.capability.req.mstmt",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_bcp,
          { "Bulk copy requests", "tds.capability.req.bcp",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_cursor,
          { "Cursor command requests", "tds.capability.req.cursor",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_dynf,
          { "Dynamic SQL requests", "tds.capability.req.dynf",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_msg,
          { "TDS_MSG requests", "tds.capability.req.msg",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_param,
          { "TDS_DBRPC/TDS_PARAM requests", "tds.capability.req.param",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_int1,
          { "Support 1-byte unsigned ints", "tds.capability.data.int1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_int2,
          { "Support 2-byte ints", "tds.capability.data.int2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_int4,
          { "Support 4-byte ints", "tds.capability.data.int4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_bit,
          { "Support bits", "tds.capability.data.bit",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_char,
          { "Support fixed-length character types", "tds.capability.data.char",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_vchar,
          { "Support variable-length character types", "tds.capability.data.vchar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_bin,
          { "Support fixed-length binary", "tds.capability.data.bin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_vbin,
          { "Support variable-length binary", "tds.capability.data.vbin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_mny8,
          { "Support 8-byte money", "tds.capability.data.mny8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_mny4,
          { "Support 4-byte money", "tds.capability.data.mny4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_date8,
          { "Support 8-byte datetime", "tds.capability.data.date8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_date4,
          { "Support 4-byte datetime", "tds.capability.data.date4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_flt4,
          { "Support 4-byte float", "tds.capability.data.flt4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_flt8,
          { "Support 8-byte float", "tds.capability.data.flt8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_num,
          { "Support numeric", "tds.capability.data.num",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_text,
          { "Support text data", "tds.capability.data.text",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_image,
          { "Support image data", "tds.capability.data.image",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_dec,
          { "Support decimal", "tds.capability.data.dec",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_lchar,
          { "Support long varible-length character types", "tds.capability.data.lchar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_lbin,
          { "Support long varible-length binary types", "tds.capability.data.lbin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_intn,
          { "Support nullable ints", "tds.capability.data.intn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_datetimen,
          { "Support nullable datetime", "tds.capability.data.datetimen",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_moneyn,
          { "Support nullable money", "tds.capability.data.moneyn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_prev,
          { "Support fetch previous cursor", "tds.capability.csr.prev",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_first,
          { "Support fetch first cursor", "tds.capability.csr.first",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_last,
          { "Support fetch last cursor", "tds.capability.csr.last",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_abs,
          { "Support fetch absolute cursor", "tds.capability.csr.abs",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_rel,
          { "Support fetch relative cursor", "tds.capability.csr.rel",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_multi,
          { "Support fetch multi-row cursor", "tds.capability.csr.multi",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_con_oob,
          { "Support expedited attention", "tds.capability.con.oob",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_con_inband,
          { "Support non-expedited attention", "tds.capability.con.inband",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_con_logical,
          { "Support logical logout", "tds.capability.con.logout",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_proto_text,
          { "Support tokenized text/image", "tds.capability.proto.text",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_proto_bulk,
          { "Support tokenized bcp", "tds.capability.proto.bulk",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_urgevt,
          { "Use new event notification", "tds.capability.req.urgevt",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_sensitivity,
          { "Support sensitivity data", "tds.capability.data.sensitivity",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_boundary,
          { "Support boundary data", "tds.capability.data.boundary",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_proto_dynamic,
          { "Use DESCIN/DESCOUT dynamic protocol", "tds.capability.proto.dynamic",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_proto_dynproc,
          { "Prepend \"create proc\" to dynamic prepares", "tds.capability.proto.dynproc",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_fltn,
          { "Support nullable floats", "tds.capability.data.fltn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_bitn,
          { "Support nullable bits", "tds.capability.data.bitn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_int8,
          { "Support 8-byte ints", "tds.capability.data.int8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_void,
          { "Undocumented TDS_DATA_VOID", "tds.capability.data.void",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_dol_bulk,
          { "Undocumented TDS_DOL_VOID", "tds.capability.dol.bulk",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_object_java1,
          { "Support serialized java objects", "tds.capability.object.java1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_object_char,
          { "Support streaming char data", "tds.capability.object.char",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_object_binary,
          { "Support streaming binary data", "tds.capability.object.binary",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_columnstatus,
          { "Add status field to ROW/PARAMS", "tds.capability.data.columnstatus",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_widetable,
          { "Allow wide-table tokens", "tds.capability.widetable",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_uint2,
          { "Support 2-byte unsigned ints", "tds.capability.data.uint2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_uint4,
          { "Support 4-byte unsigned ints", "tds.capability.data.uint4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_uint8,
          { "Support 8-byte unsigned ints", "tds.capability.data.uint8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_uintn,
          { "Support nullable unsigned ints", "tds.capability.data.uintn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_cur_implicit,
          { "Support TDS_CUR_DOPT_IMPLICIT", "tds.capability.cur.implicit",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nlbin,
          { "Support UTF-16 LONGBINARY", "tds.capability.data.nlbin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_image_nchar,
          { "Support UTF-16 IMAGE", "tds.capability.image.nchar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_blob_nchar_16,
          { "Support BLOB serialization 0", "tds.capability.blob.nchar_16",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_blob_nchar_8,
          { "Support BLOB serialization 1", "tds.capability.blob.nchar_8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_blob_nchar_scsu,
          { "Support BLOB serialization 2", "tds.capability.blob.nchar_scsu",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_date,
          { "Support DATE", "tds.capability.data.date",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_time,
          { "Support TIME", "tds.capability.data.time",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_interval,
          { "Support INTERVAL", "tds.capability.data.interval",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_scroll,
          { "Support scrollable cursor", "tds.capability.csr.scroll",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_sensitive,
          { "Support sens. scr csr", "tds.capability.csr.sensitive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_insensitive,
          { "Support insens. scr csr", "tds.capability.csr.insensitive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_semisensitive,
          { "Support semisens. scr csr", "tds.capability.csr.semisensitive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_csr_keysetdriven,
          { "Support scr keyset driven csr", "tds.capability.csr.keysetdriven",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_srvpktsize,
          { "Support server-spec. packet size", "tds.capability.req.srvpktsize",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_unitext,
          { "Support UTF-16 text", "tds.capability.data.unitext",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_cap_clusterfailover,
          { "Support cluster failover", "tds.capability.cap.clusterfailover",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_sint1,
          { "Support signed 1-byte ints", "tds.capability.data.sint1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_largeident,
          { "Support large identifiers", "tds.capability.req.largeident",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_blob_nchar_16,
          { "Support BLOB serialization 0 (new)", "tds.capability.req.blob_nchar_16",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_xml,
          { "Support XML type", "tds.capability.data.xml",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_curinfo3,
          { "Support TDS_CURINFO3 token", "tds.capability.req.curinfo3",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_req_dbrpc2,
          { "Support TDS_DBRPC2 token", "tds.capability.req.dbrpc2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_nomsg,
          { "No sup. for TDS_MSG result", "tds.capability.res.nomsg",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_noeed,
          { "No sup. for TDS_EED token", "tds.capability.res.noeed",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_noparam,
          { "No sup. for TDS_PARAM return param", "tds.capability.res.noparam",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noint1,
          { "No sup. for unsigned 1-byte ints", "tds.capability.data.noint1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noint2,
          { "No sup. for 2-byte ints", "tds.capability.data.noint2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noint4,
          { "No sup. for 4-byte ints", "tds.capability.data.noint4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nobit,
          { "No sup. for BIT type", "tds.capability.data.nobit",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nochar,
          { "No sup. for fixed-length char", "tds.capability.data.nochar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_novchar,
          { "No sup. for variable-length char", "tds.capability.data.novchar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nobin,
          { "No sup. for fixed-length binary", "tds.capability.data.nobin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_novbin,
          { "No sup. for variable-length binary", "tds.capability.data.novbin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nomny8,
          { "No sup. for 8-byte money", "tds.capability.data.nomny8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nomny4,
          { "No sup. for 4-byte money", "tds.capability.data.nomny4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nodate8,
          { "No sup. for 8-byte datetime", "tds.capability.data.nodate8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nodate4,
          { "No sup. for 4-byte datetime", "tds.capability.data.nodate4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noflt4,
          { "No sup. for 4-byte floats", "tds.capability.data.noflt4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noflt8,
          { "No sup. for 8-byte floats", "tds.capability.data.noflt8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nonum,
          { "No sup. for NUMERIC", "tds.capability.data.nonum",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_notext,
          { "No sup. for TEXT", "tds.capability.data.notext",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noimage,
          { "No sup. for IMAGE", "tds.capability.data.noimage",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nodec,
          { "No sup. for DECIMAL", "tds.capability.data.nodec",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nolchar,
          { "No sup. for long character types", "tds.capability.data.nolchar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nolbin,
          { "No sup. for long binary types", "tds.capability.data.nolbin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nointn,
          { "No sup. for nullable ints", "tds.capability.data.nointn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nodatetimen,
          { "No sup. for nullable datetime", "tds.capability.data.nodatetimen",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nomoneyn,
          { "No sup. for nullable money", "tds.capability.data.nomoneyn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_con_nooob,
          { "No sup. for expedited attentions", "tds.capability.con.nooob",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_con_noinband,
          { "No sup. for non-expedited attentions", "tds.capability.con.noinband",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_proto_notext,
          { "No sup. for tokenized text/image", "tds.capability.proto.notext",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_proto_nobulk,
          { "No sup. for tokenized BCP", "tds.capability.proto.nobulk",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nosensitivity,
          { "No sup. for sensitivity", "tds.capability.data.nosensitivity",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noboundary,
          { "No sup. for BOUNDARY", "tds.capability.data.noboundary",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_notdsdebug,
          { "No sup. for TDS_DEBUG token", "tds.capability.res.notdsdebug",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_nostripblanks,
          { "Do not strip blanks from CHAR", "tds.capability.res.nostripblanks",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noint8,
          { "No sup. for 8-byte ints", "tds.capability.data.noint8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_object_nojava1,
          { "No sup. for serialized Java objects", "tds.capability.object.nojava1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_object_nochar,
          { "No sup. for streaming char data", "tds.capability.object.nochar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nocolumnstatus,
          { "No sup. for columnstatus byte", "tds.capability.data.nocolumnstatus",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_object_nobinary,
          { "No sup. for streaming binary data", "tds.capability.object.nobinary",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nouint2,
          { "No sup. for 2-byte unsigned ints", "tds.capability.data.nouint2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nouint4,
          { "No sup. for 4-byte unsigned ints", "tds.capability.data.nouint4",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nouint8,
          { "No sup. for 8-byte unsigned ints", "tds.capability.data.nouint8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nouintn,
          { "No sup. for nullable unsigned ints", "tds.capability.data.nouintn",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_no_widetables,
          { "No sup. for wide-table tokens", "tds.capability.no_widetables",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nonlbin,
          { "No sup. for LONGBINARY with UTF-16", "tds.capability.data.nonlbin",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_image_nonchar,
          { "No sup. for IMAGE with UTF-16", "tds.capability.image.nonchar",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_blob_nonchar_16,
          { "No sup. for BLOB subtype 0", "tds.capability.blob.nonchar_16",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_blob_nonchar_8,
          { "No sup. for BLOB subtype 1", "tds.capability.blob.nonchar_8",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_blob_nonchar_scsu,
          { "No sup. for BLOB subtype 2", "tds.capability.blob.nonchar_scsu",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nodate,
          { "No sup. for DATE", "tds.capability.data.nodate",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_notime,
          { "No sup. for TIME", "tds.capability.data.notime",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nointerval,
          { "No sup. for INTERVAL", "tds.capability.data.nointerval",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nounitext,
          { "No sup. for TEXT with UTF-16", "tds.capability.data.nounitext",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_nosint1,
          { "No sup. for 1-byte signed ints", "tds.capability.data.nosint1",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_no_largeident,
          { "No sup. for large identifiers", "tds.capability.no_largeident",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },
        { &hf_tds_capability_no_blob_nchar_16,
          { "No sup. for BLOB type 0 (replacement)", "tds.capability.no_blob_nchar_16",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_tds_capability_no_srvpktsize,
          { "No sup. for server spec pkt size", "tds.capability.no_srvpktsize",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            NULL, HFILL }
        },
        { &hf_tds_capability_data_noxml,
          { "No sup. for XML data", "tds.capability.data.noxml",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            NULL, HFILL }
        },
        { &hf_tds_capability_no_nint_return_value,
          { "No sup. for non-int return value", "tds.capability.no_nint_return_value",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_noxnldata,
          { "No req. for ROWFMT2 data", "tds.capability.res.noxnldata",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_suppress_fmt,
          { "Srvr can suppress ROWFMT for DYNAMIC", "tds.capability.res.suppress_fmt",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_suppress_doneinproc,
          { "Srvr can suppress DONEINPROC", "tds.capability.res.suppress_doneinproc",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
            NULL, HFILL }
        },
        { &hf_tds_capability_res_force_rowfmt2,
          { "Force use of ROWFMT2", "tds.capability.res.force_rowfmt2",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            NULL, HFILL }
        },

        /* COLINFO token (TDS_COLFMT_TOKEN) */
        { &hf_tds_colfmt,
          { "Token - ColFormat", "tds.colfmt",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colfmt_length,
          { "Token length - ColFormat", "tds.colfmt.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colfmt_column,
          { "Column", "tds.colfmt.column",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colfmt_utype,
          { "ColFormat - Column Usertype", "tds.colfmt.utype",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colfmt_ctype,
          { "ColFormat - Column Datatype", "tds.colfmt.ctype",
            FT_UINT8, BASE_DEC, &tds_data_type_names, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colfmt_csize,
          { "ColFormat - Column size", "tds.colfmt.csize",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colfmt_csize_long,
          { "ColFormat - Column size - long", "tds.colfmt.csize_long",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colfmt_text_tablename,
          { "ColFormat - Text Tablename", "tds.colfmt.text_tablename",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* COLNAME token (TDS_COL_NAME_TOKEN) */
        { &hf_tds_colname,
          { "Token - ColName", "tds.colname",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colname_length,
          { "Token length - ColName", "tds.colname.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colname_column,
          { "Column", "tds.colname.column",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colname_name,
          { "Column name", "tds.colname.name",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
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
        { &hf_tds_colmetadata_large2_type_size,
          { "Large type size", "tds.colmetadata.large_type_size",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_colmetadata_large4_type_size,
          { "Large type size", "tds.colmetadata.large_type_size",
            FT_UINT32, BASE_HEX, NULL, 0x0,
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

        /* CONTROL token (TDS_CONTROL_TOKEN) */
        { &hf_tds_control,
          { "Token - Control", "tds.control",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_control_length,
          { "Token Length - Control", "tds.control.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_control_fmt,
          { "Control - Fmt", "tds.control.fmt",
            FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
            NULL, HFILL }
        },

        /* CURCLOSE token (TDS_CURCLOSE_TOKEN) */
        { &hf_tds_curclose,
          { "Token - CurClose", "tds.curclose",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curclose_length,
          { "Token Length - CurClose", "tds.curclose.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curclose_cursorid,
          { "CursorId", "tds.curclose.cursorid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curclose_cursor_name,
          { "Cursorname", "tds.curclose.cursor.name_len",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curclose_option_deallocate,
          { "Deallocate", "tds.curclose.option.deallocate",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        /* CURDECLARE token (TDS_CURDECLARE_TOKEN) */
        { &hf_tds_curdeclare,
          { "Token - CurDeclare", "tds.curdeclare",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_length,
          { "Token Length - CurDeclare", "tds.curdeclare.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_cursor_name,
          { "Cursorname", "tds.curdeclare.cursor.name_len",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_options,
          { "Options", "tds.curdeclare.options",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_options_rdonly,
          { "Read Only", "tds.curdeclare.options.rdonly",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_options_updatable,
          { "Updatable", "tds.curdeclare.options.updatable",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_options_sensitive,
          { "Sensitive", "tds.curdeclare.options.sensitive",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_options_dynamic,
          { "Dynamic", "tds.curdeclare.options.dynamic",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_options_implicit,
          { "Implict", "tds.curdeclare.options.implicit",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_status_parameterized,
          { "Status Parameterized", "tds.curdeclare.status.parameterized",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_statement,
          { "Statement", "tds.curdeclare.statement",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_update_columns_num,
          { "Number of updatable columns", "tds.curdeclare.update_columns_num",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curdeclare_update_columns_name,
          { "Updatable Column Name", "tds.curdeclare.update_columns_name",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* CURFETCH token (TDS_CURFETCH_TOKEN) */
        { &hf_tds_curfetch,
          { "Token - CurFetch", "tds.curfetch",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curfetch_length,
          { "Token Length - CurFetch", "tds.curfetch.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curfetch_cursorid,
          { "CursorId", "tds.curfetch.cursorid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curfetch_cursor_name,
          { "CurFetch - Cursorname", "tds.curfetch.cursor.name_len",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curfetch_type,
          { "CurFetch - Type", "tds.curinfo.type",
            FT_UINT8, BASE_DEC, VALS(tds_curfetch_types), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curfetch_rowcnt,
          { "CurFetch - Rowcnt", "tds.curfetch.rowcnt",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /* CURINFO token (TDS_CURINFO_TOKEN) */
        { &hf_tds_curinfo,
          { "Token - CurInfo", "tds.curinfo",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_length,
          { "Token Length - Curinfo", "tds.curinfo.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursorid,
          { "CursorId", "tds.curinfo.cursorid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_name,
          { "Cursorname", "tds.curinfo.cursor.name_len",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_command,
          { "Cursor Command", "tds.curinfo.cursor.command",
            FT_UINT8, BASE_DEC, VALS(tds_curinfo_commands), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status,
          { "Cursor Status", "tds.curinfo.cursor.status",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status_declared,
          { "Declared", "tds.curinfo.cursor.status.declared",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status_open,
          { "Open", "tds.curinfo.cursor.status.open",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status_closed,
          { "Closed", "tds.curinfo.cursor.status.closed",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status_rdonly,
          { "Read only", "tds.curinfo.cursor.status.rdonly",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status_updatable,
          { "Updatable", "tds.curinfo.cursor.status.updatable",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status_rowcnt,
          { "Rowcount valid", "tds.curinfo.cursor.status.rowcnt",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_status_dealloc,
          { "Deallocated", "tds.curinfo.cursor.status.dealloc",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_tds_curinfo_cursor_rowcnt,
          { "Cursor Rowcnt", "tds.curinfo.cursor.rowcnt",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /* CUROPEN token (TDS_CUROPEN_TOKEN) */
        { &hf_tds_curopen,
          { "Token - CurOpen", "tds.curopen",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curopen_length,
          { "Token Length - CurOpen", "tds.curopen.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curopen_cursorid,
          { "CursorId", "tds.curopen.cursorid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curopen_cursor_name,
          { "Cursorname", "tds.curopen.cursor.name_len",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_curopen_status_parameterized,
          { "Status Parameterized", "tds.curopen.status.parameterized",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        /* DBRPC token (TDS5_DBRPC_TOKEN) */
        { &hf_tds_dbrpc,
          { "Token - DBRPC", "tds.dbrpc",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_dbrpc_length,
          { "Token Length - DBRPC", "tds.dbrpc.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_dbrpc_rpcname_len,
          { "DBRPC - RPC Name Length", "tds.dbrpc.rpcname_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_dbrpc_rpcname,
          { "DBRPC - RPC Name", "tds.dbrpc.rpcname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_dbrpc_options,
          { "DBRPC - Options", "tds.dbrpc.options",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_dbrpc_options_recompile,
          { "Recompile", "tds.dbrpc.options.recompile",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_tds_dbrpc_options_params,
          { "Has parameters", "tds.dbrpc.options.params",
            FT_BOOLEAN, 16, NULL, 0x0002,
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
            FT_UINT16, BASE_HEX, NULL, 0x017f,
            NULL, HFILL }
        },
        { &hf_tds_done_status_more,
          { "More",   "tds.done.status.more",
            FT_BOOLEAN, 16, TFS(&tds_tfs_more_final), 0x0001,
            NULL, HFILL }
        },
        { &hf_tds_done_status_error,
          { "Error",   "tds.done.status.error",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002,
            NULL, HFILL }
        },
        { &hf_tds_done_status_inxact,
          { "In Transaction",   "tds.done.status.inxact",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004,
            NULL, HFILL }
        },
        { &hf_tds_done_status_proc,
          { "Procedure",   "tds.done.status.proc",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008,
            NULL, HFILL }
        },
        { &hf_tds_done_status_count,
          { "Row count valid",   "tds.done.status.count",
            FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0010,
            NULL, HFILL }
        },
        { &hf_tds_done_status_attn,
          { "Acknowledge ATTN",   "tds.done.status.attn",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0020,
            NULL, HFILL }
        },
        { &hf_tds_done_status_event,
          { "Event",   "tds.done.status.event",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040,
            NULL, HFILL }
        },
        { &hf_tds_done_status_rpcinbatch,
          { "RPC in batch",   "tds.done.status.rpcinbatch",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
            NULL, HFILL }
        },
        { &hf_tds_done_status_srverror,
          { "Server Error",   "tds.done.status.srverror",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
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
            FT_UINT16, BASE_HEX, NULL, 0x01ff,
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
            FT_UINT16, BASE_HEX, NULL, 0x0177,
            NULL, HFILL }
        },
        { &hf_tds_doneinproc_curcmd,
          { "Operation", "tds.doneinproc.curcmd",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
          },

        /* EED token (TDS5_EED_TOKEN) */
        { &hf_tds_eed,
          { "Token - ExtendedErrorDiagnostic", "tds.eed",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_length,
          { "Token length", "tds.eed.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_number,
          { "SQL Error Number", "tds.eed.number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_state,
          { "State", "tds.eed.state",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_class,
          { "Class (Severity)", "tds.eed.class",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_sql_state,
          { "SQL State", "tds.eed.sql_state",
            FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_status,
          { "EED Following", "tds.eed.status",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_transtate,
          { "Transaction state", "tds.eed.transtate",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_msgtext,
          { "Error message", "tds.eed.msgtext",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_servername,
          { "Server name", "tds.eed.servername",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_procname,
          { "Procedure name", "tds.eed.procname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_eed_linenumber,
          { "Line number", "tds.eed.linenumber",
          FT_UINT16, BASE_DEC, NULL, 0x0,
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
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_characters, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_msgtext,
          { "Error message", "tds.error.msgtext",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_error_servername_length,
          { "Server name length", "tds.error.servername_length",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_characters, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_error_servername,
          { "Server name", "tds.error.servername",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_error_procname_length,
          { "Process name length", "tds.error.procname_length",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_characters, 0x0,
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
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_characters, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_msgtext,
          { "Error message", "tds.info.msgtext",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_info_servername_length,
          { "Server name length", "tds.info.servername_length",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_characters, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_info_servername,
          { "Server name", "tds.info.servername",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_tds_info_procname_length,
          { "Process name length", "tds.info.procname_length",
          FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_characters, 0x0,
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

        /* LOGOUT token (TDS5_LOGOUT_TOKEN) */
        { &hf_tds_logout,
          { "Token - Logout", "tds.logout",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_logout_options,
          { "Logout Options", "tds.logout.options",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        /* MSG token (TDS5_MSG_TOKEN) */
        { &hf_tds_msg,
          { "Token - Msg", "tds.msg",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_msg_length,
          { "Token length - Msg", "tds.msg.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_msg_status,
          { "Status", "tds.msg.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_msg_msgid,
          { "Message Id", "tds.msg.msgid",
            FT_UINT16, BASE_DEC, NULL, 0x0,
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

        /* PARAMFMT token (TDS5_PARAMFMT_TOKEN) */
        { &hf_tds_paramfmt,
          { "Token - Paramfmt", "tds.paramfmt",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_length,
          { "Token length - Paramfmt", "tds.paramfmt.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_numparams,
          { "Number of Parameters", "tds.paramfmt.numparams",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_colname,
          { "Parameter name", "tds.paramfmt.colname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_status,
          { "Column Status", "tds.paramfmt.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_utype,
          { "Parameter Usertype", "tds.paramfmt.utype",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_ctype,
          { "Parameter Datatype", "tds.paramfmt.ctype",
            FT_UINT8, BASE_DEC, &tds_data_type_names, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_csize,
          { "Parameter size", "tds.paramfmt.csize",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt_locale_info,
          { "Locale info", "tds.paramfmt.locale_info",
            FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
            NULL, HFILL }
        },

        /* PARAMFMT2 token (TDS5_PARAMFMT2_TOKEN) */
        { &hf_tds_paramfmt2,
          { "Token - Paramfmt2", "tds.paramfmt2",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_length,
          { "Token length - Paramfmt2", "tds.paramfmt2.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_numparams,
          { "Number of Parameters", "tds.paramfmt2.numparams",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_colname,
          { "Parameter name", "tds.paramfmt2.paramname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_status,
          { "Parameter Status", "tds.paramfmt2.status",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_utype,
          { "Parameter Usertype", "tds.paramfmt2.utype",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_ctype,
          { "Parameter Datatype", "tds.paramfmt2.ctype",
            FT_UINT8, BASE_DEC, &tds_data_type_names, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_csize,
          { "Parameter size", "tds.paramfmt2.csize",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_paramfmt2_locale_info,
          { "Locale info", "tds.paramfmt2.locale_info",
            FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
            NULL, HFILL }
        },

        /* PARAMS token (TDS5_PARAMS_TOKEN) */
        { &hf_tds_params,
          { "Token - Params", "tds.params",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_params_field,
          { "Parameter", "tds.params.parameter",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* PROCID token (TDS_PROCID_TOKEN) */
        { &hf_tds_procid,
          { "Token - Procid", "tds.procid",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_tds_procid_value,
          { "Procid Value", "tds.procid.value",
           FT_BYTES, BASE_NONE, NULL, 0x0,
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

        /* ROWFMT token (TDS5_ROWFMT_TOKEN) */
        { &hf_tds_rowfmt,
          { "Token - Rowfmt", "tds.rowfmt",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_length,
          { "Token length - Rowfmt", "tds.rowfmt.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_numcols,
          { "Number of Columns", "tds.rowfmt.numcols",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_colname,
          { "Column name", "tds.rowfmt.colname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_status,
          { "Column Status", "tds.rowfmt.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_utype,
          { "Column Usertype", "tds.rowfmt.utype",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_ctype,
          { "Column Datatype", "tds.rowfmt.ctype",
            FT_UINT8, BASE_DEC, &tds_data_type_names, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_csize,
          { "Column size", "tds.rowfmt.csize",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_text_tablename,
          { "Text Tablename", "tds.rowfmt.text_tablename",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_precision,
          { "Precision", "tds.rowfmt.precision",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_scale,
          { "Scale", "tds.rowfmt.scale",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt_locale_info,
          { "Locale info", "tds.rowfmt.locale_info",
            FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
            NULL, HFILL }
        },

        /* ROWFMT2 token (TDS5_ROWFMT2_TOKEN) */
        { &hf_tds_rowfmt2,
          { "Token - Rowfmt2", "tds.rowfmt2",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_length,
          { "Token length - Rowfmt2", "tds.rowfmt2.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_numcols,
          { "Number of Columns", "tds.rowfmt2.numcols",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_labelname,
          { "Label name", "tds.rowfmt2.labelname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_catalogname,
          { "Catalog name", "tds.rowfmt2.catalogname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_schemaname,
          { "Schema name", "tds.rowfmt2.schemaname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_tablename,
          { "Table name", "tds.rowfmt2.tablename",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_colname,
          { "Column name", "tds.rowfmt2.colname",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_status,
          { "Column Status", "tds.rowfmt2.status",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_utype,
          { "Column Usertype", "tds.rowfmt2.utype",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_ctype,
          { "Column Datatype", "tds.rowfmt2.ctype",
            FT_UINT8, BASE_DEC, &tds_data_type_names, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_csize,
          { "Column size", "tds.rowfmt2.csize",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_text_tablename,
          { "Text Tablename", "tds.rowfmt2.text_tablename",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_precision,
          { "Precision", "tds.rowfmt2.precision",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_scale,
          { "Scale", "tds.rowfmt2.scale",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_rowfmt2_locale_info,
          { "Locale info", "tds.rowfmt2.locale_info",
            FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
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
        { &hf_tds_lang_length,
          { "Token Length - Language", "tds.lang.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_lang_token_status,
          { "Status", "tds.lang.token_status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_lang_status_parameterized,
          { "Parameters follow", "tds.lang.token_status.parameterized",
            FT_BOOLEAN, 8, NULL, 0x01,
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

        /* LOGIN Token */
        { &hf_tdslogin,
          { "Hostname length", "tds.login",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_hostname_length,
          { "Hostname length", "tds.login.hostname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_hostname,
          { "Hostname", "tds.login.hostname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_username_length,
          { "Username length", "tds.login.username_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_username,
          { "Username", "tds.login.username",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_password_length,
          { "Password length", "tds.login.password_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_password,
          { "Password", "tds.login.password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_hostprocess_length,
          { "Host Process Id length", "tds.login.hostprocess_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_hostprocess,
          { "Host Process Id", "tds.login.pid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_int2,
          { "Short (2-byte) integer format", "tds.login.option.int2",
            FT_UINT8, BASE_DEC, VALS(login_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_int4,
          { "Long (4-byte) integer format", "tds.login.option.int4",
            FT_UINT8, BASE_DEC, VALS(login_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_char,
          { "Character set", "tds.login.option.char",
            FT_UINT8, BASE_DEC, VALS(login_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_float,
          { "Double (8 byte) float format", "tds.login.option.float",
            FT_UINT8, BASE_DEC, VALS(login_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_date8,
          { "Long (8 byte) date format", "tds.login.option.date",
            FT_UINT8, BASE_DEC, VALS(login_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_usedb,
          { "Use DB", "tds.login.option.usedb",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_no_yes), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_bulk,
          { "Bulk Copy", "tds.login.option.bulk",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_no_yes), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_server_to_server,
          { "Server to server options", "tds.login.option.server_to_server",
            FT_UINT8, BASE_DEC, VALS(login_server_to_server), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_server_to_server_loginack,
          { "Server to server loginack", "tds.login.option.server_to_server_loginack",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option_conversation_type,
          { "Conversation type", "tds.login.option.type",
            FT_UINT8, BASE_DEC, VALS(login_conversation_type), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_appname_length,
          { "Application name length", "tds.login.appname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_appname,
          { "Application name", "tds.login.appname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_servername_length,
          { "Server name length", "tds.login.servername_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_servername,
          { "Server name", "tds.login.servname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_remotepassword_length,
          { "Remote password length", "tds.login.rempw_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_rempw_servername_length,
          { "Remote password servername length", "tds.login.rempw_servername_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_rempw_servername,
          { "Remote password server name", "tds.login.rempw_servername",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_rempw_password_length,
          { "Remote password password length", "tds.login.rempw_password_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_rempw_password,
          { "Remote password password", "tds.login.rempw_password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_proto_version,
          { "Protocol version", "tds.login.protoversion",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_progname_length,
          { "Program name length", "tds.login.progname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_progname,
          { "Program name", "tds.login.progname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_progvers,
          { "Program version", "tds.login.progversion",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option2_noshort,
          { "Convert shorts to longs", "tds.login.option.noshort",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option2_flt4,
          { "Single (4 byte) float format", "tds.login.option.flt4",
            FT_UINT8, BASE_DEC, VALS(login_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_option2_date4,
          { "Short (4 byte) date format", "tds.login.option.date4",
            FT_UINT8, BASE_DEC, VALS(login_options), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_language,
          { "Language", "tds.login.language",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_language_length,
          { "Language name length", "tds.login.language_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_setlang,
          { "Notify client of language changes", "tds.login.setlang",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_seclogin,
          { "Secure login", "tds.login.seclogin",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_secbulk,
          { "Secure bulk copy", "tds.login.secbulk",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_halogin,
          { "High Availability login", "tds.login.halogin",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_hasessionid,
          { "High Availability session id", "tds.login.hasessionid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_charset,
          { "Character set", "tds.login.charset",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_charset_length,
          { "Character set name length", "tds.login.charset_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_setcharset,
          { "Notify client of character set changes", "tds.login.setcharset",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_packetsize,
          { "Packet size", "tds.login.packetsize",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tdslogin_packetsize_length,
          { "Packet size length", "tds.login.packetsize_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

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
            FT_UINT32, BASE_CUSTOM, CF_FUNC(version_convert), 0x0,
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
            FT_UINT32, BASE_CUSTOM, CF_FUNC(version_convert), 0x0,
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
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_threadid,
          { "ThreadID", "tds.prelogin.option.threadid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_prelogin_option_mars,
          { "MARS", "tds.prelogin.option.mars",
            FT_UINT8, BASE_DEC, VALS(tds_mars_type), 0x0,
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
        { &hf_tds_type_varbyte_data_uint_bytes,
          { "Data", "tds.type_varbyte.data.uint_bytes",
            FT_UINT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
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
        { &hf_tds_type_varbyte_data_uint_string,
          { "Data", "tds.type_varbyte.data.uint_string",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
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
        { &hf_tds_type_varbyte_data_textptr_len,
          { "Data Textptr Len", "tds.type_varbyte.textptr_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_textptr,
          { "Data Textptr", "tds.type_varbyte.data.textptr",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_data_text_ts,
          { "Data Text timestamp", "tds.type_varbyte.data.text_ts",
            FT_BYTES, BASE_NONE, NULL, 0x0,
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
        { &hf_tds_type_varbyte_plp_chunk,
          { "PLP chunk", "tds.type_varbyte.plp_chunk",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tds_type_varbyte_column_name,
          { "Column name", "tds.type_varbyte.column.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
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
        &ett_tds_capability_req,
        &ett_tds_capability_resp,
        &ett_tds_done_status,
        &ett_tds7_query,
        &ett_tds7_prelogin,
        &ett_tds_login,
        &ett_tds_login_options,
        &ett_tds_login_options2,
        &ett_tds_login_rempw,
        &ett_tds7_login,
        &ett_tds7_hdr,
        &ett_tds_col,
        &ett_tds_flags,
        &ett_tds7_featureextack,
        &ett_tds7_featureextack_feature,
        &ett_tds5_dbrpc_options,
        &ett_tds5_curdeclare_options,
        &ett_tds5_curinfo_status
    };

    static ei_register_info ei[] = {
        { &ei_tds_all_headers_header_type, { "tds.all_headers.header.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid header type", EXPFILL }},
        { &ei_tds_type_info_type, { "tds.type_info.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid data type", EXPFILL }},
#if 0
        { &ei_tds_type_info_type_undecoded, { "tds.type_info.type.undecoded", PI_UNDECODED, PI_ERROR, "Data type not supported yet", EXPFILL }},
#endif
        { &ei_tds_invalid_length, { "tds.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
        { &ei_tds_token_length_invalid, { "tds.token.length.invalid", PI_PROTOCOL, PI_WARN, "Bogus token size", EXPFILL }},
        { &ei_tds_invalid_plp_length, { "tds.invalid_plp_length", PI_PROTOCOL, PI_NOTE, "PLP length doesn't equal the sum of the lengths of the chunks", EXPFILL }},
#if 0
        { &ei_tds_token_stats, { "tds.token.stats", PI_PROTOCOL, PI_NOTE, "Token stats", EXPFILL }},
#endif
        { &ei_tds_invalid_plp_type, { "tds.type_info.type.invalidplp", PI_PROTOCOL, PI_NOTE, "Invalid PLP type", EXPFILL }},
        { &ei_tds_cursor_name_mismatch, { "tds.cursor.name_mismatch", PI_PROTOCOL, PI_WARN, "Cursor name mismatch", EXPFILL }}
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
    tds_tcp_handle = register_dissector("tds", dissect_tds, proto_tds);

    tds_module = prefs_register_protocol(proto_tds, apply_tds_prefs);
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

    /*
     * Initialize the reassembly table.
     *
     * XXX - should fragments be reassembled across multiple TCP
     * connections?
     */

    reassembly_table_register(&tds_reassembly_table,
                          &addresses_ports_reassembly_table_functions);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_tds(void)
{
    /* Initial TDS ports: MS SQL default ports */
    dissector_add_uint_range_with_preference("tcp.port", TDS_PORT_RANGE, tds_tcp_handle);
    apply_tds_prefs();
    heur_dissector_add("tcp", dissect_tds_tcp_heur, "Tabular Data Stream over TCP", "tds_tcp", proto_tds, HEURISTIC_ENABLE);

    ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_tds);
    gssapi_handle = find_dissector_add_dependency("gssapi", proto_tds);
    smp_handle = find_dissector_add_dependency("smp_tds", proto_tds);

    /* Isn't required, but allows user to override current payload */
    dissector_add_for_decode_as("smp.payload", create_dissector_handle(dissect_tds_pdu, proto_tds));
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
