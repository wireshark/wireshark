/* packet-drda.c
 * Routines for Distributed Relational Database Architecture packet dissection
 *
 * metatech <metatech@flashmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*  DRDA in a nutshell
*
*   DRDA stands for Distributed Relational Database Architecture.
*   It is a protocol between database client and database server published by
*   the Open Group (www.opengroup.org) DDM (Distributed Data Management) is an
*   data management interface which allows to exchange structured data between
*   systems.  DRDA is specific to relational databases and uses a subset of DDM
*   to transport its data.  The IBM DB2 product uses the DRDA protocol from
*   version V8.  Unless negotiated differently during the handshake, the fields
*   of the DDM commands and reply messages are in EBCDIC.
*
*   Documentation:
*   DRDA Version 3 Vol. 3: Distributed Relational Database Architecture,
*   Open Group.
*   Version 3 is no longer available; for the latest version, see
*
*       http://www.opengroup.org/dbiop/
*
*   Reference for Remote DRDA Requesters and Servers, IBM.
*
*       https://www-304.ibm.com/support/docview.wss?uid=pub1sc18985301
*/

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-tcp.h"

static int proto_drda = -1;
static int hf_drda_ddm_length = -1;
static int hf_drda_ddm_magic = -1;
static int hf_drda_ddm_format = -1;
static int hf_drda_ddm_fmt_reserved = -1;
static int hf_drda_ddm_fmt_chained = -1;
static int hf_drda_ddm_fmt_errcont = -1;
static int hf_drda_ddm_fmt_samecorr = -1;
static int hf_drda_ddm_fmt_dsstyp = -1;
static int hf_drda_ddm_rc = -1;
static int hf_drda_ddm_length2 = -1;
static int hf_drda_ddm_codepoint = -1;
static int hf_drda_param_length = -1;
static int hf_drda_param_codepoint = -1;
static int hf_drda_param_data = -1;
static int hf_drda_param_data_ebcdic = -1;
static int hf_drda_sqlstatement = -1;
static int hf_drda_sqlstatement_ebcdic = -1;

static gint ett_drda = -1;
static gint ett_drda_ddm = -1;
static gint ett_drda_ddm_format = -1;
static gint ett_drda_param = -1;

static dissector_handle_t drda_tcp_handle;

static gboolean drda_desegment = TRUE;

#define DRDA_MAGIC  0xD0

#define DRDA_CP_DATA          0x0000
#define DRDA_CP_CODPNT        0x000C
#define DRDA_CP_FDODSC        0x0010
#define DRDA_CP_TYPDEFNAM     0x002F
#define DRDA_CP_TYPDEFOVR     0x0035
#define DRDA_CP_CODPNTDR      0x0064
#define DRDA_CP_EXCSAT        0x1041
#define DRDA_CP_SYNCCTL       0x1055
#define DRDA_CP_SYNCRSY       0x1069
#define DRDA_CP_ACCSEC        0x106D
#define DRDA_CP_SECCHK        0x106E
#define DRDA_CP_SYNCLOG       0x106F
#define DRDA_CP_RSCTYP        0x111F
#define DRDA_CP_RSNCOD        0x1127
#define DRDA_CP_RSCNAM        0x112D
#define DRDA_CP_PRDID         0x112E
#define DRDA_CP_PRCCNVCD      0x113F
#define DRDA_CP_VRSNAM        0x1144
#define DRDA_CP_SRVCLSNM      0x1147
#define DRDA_CP_SVRCOD        0x1149
#define DRDA_CP_SYNERRCD      0x114A
#define DRDA_CP_SRVDGN        0x1153
#define DRDA_CP_SRVRLSLV      0x115A
#define DRDA_CP_SPVNAM        0x115D
#define DRDA_CP_EXTNAM        0x115E
#define DRDA_CP_SRVNAM        0x116D
#define DRDA_CP_SECMGRNM      0x1196
#define DRDA_CP_DEPERRCD      0x119B
#define DRDA_CP_CCSIDSBC      0x119C
#define DRDA_CP_CCSIDDBC      0x119D
#define DRDA_CP_CCSIDMBC      0x119E
#define DRDA_CP_USRID         0x11A0
#define DRDA_CP_PASSWORD      0x11A1
#define DRDA_CP_SECMEC        0x11A2
#define DRDA_CP_SECCHKCD      0x11A4
#define DRDA_CP_SVCERRNO      0x11B4
#define DRDA_CP_SECTKN        0x11DC
#define DRDA_CP_NEWPASSWORD   0x11DE
#define DRDA_CP_MGRLVLRM      0x1210
#define DRDA_CP_MGRDEPRM      0x1218
#define DRDA_CP_SECCHKRM      0x1219
#define DRDA_CP_CMDATHRM      0x121C
#define DRDA_CP_AGNPRMRM      0x1232
#define DRDA_CP_RSCLMTRM      0x1233
#define DRDA_CP_PRCCNVRM      0x1245
#define DRDA_CP_CMDCMPRM      0x124B
#define DRDA_CP_SYNTAXRM      0x124C
#define DRDA_CP_CMDNSPRM      0x1250
#define DRDA_CP_PRMNSPRM      0x1251
#define DRDA_CP_VALNSPRM      0x1252
#define DRDA_CP_OBJNSPRM      0x1253
#define DRDA_CP_CMDCHKRM      0x1254
#define DRDA_CP_TRGNSPRM      0x125F
#define DRDA_CP_AGENT         0x1403
#define DRDA_CP_MGRLVLLS      0x1404
#define DRDA_CP_SUPERVISOR    0x143C
#define DRDA_CP_SECMGR        0x1440
#define DRDA_CP_EXCSATRD      0x1443
#define DRDA_CP_CMNAPPC       0x1444
#define DRDA_CP_DICTIONARY    0x1458
#define DRDA_CP_MGRLVLN       0x1473
#define DRDA_CP_CMNTCPIP      0x1474
#define DRDA_CP_FDODTA        0x147A
#define DRDA_CP_CMNSYNCPT     0x147C
#define DRDA_CP_ACCSECRD      0x14AC
#define DRDA_CP_SYNCPTMGR     0x14C0
#define DRDA_CP_RSYNCMGR      0x14C1
#define DRDA_CP_CCSIDMGR      0x14CC
#define DRDA_CP_MONITOR       0x1900
#define DRDA_CP_MONITORRD     0x1C00
#define DRDA_CP_XAMGR         0x1C01
#define DRDA_CP_ACCRDB        0x2001
#define DRDA_CP_BGNBND        0x2002
#define DRDA_CP_BNDSQLSTT     0x2004
#define DRDA_CP_CLSQRY        0x2005
#define DRDA_CP_CNTQRY        0x2006
#define DRDA_CP_DRPPKG        0x2007
#define DRDA_CP_DSCSQLSTT     0x2008
#define DRDA_CP_ENDBND        0x2009
#define DRDA_CP_EXCSQLIMM     0x200A
#define DRDA_CP_EXCSQLSTT     0x200B
#define DRDA_CP_OPNQRY        0x200C
#define DRDA_CP_PRPSQLSTT     0x200D
#define DRDA_CP_RDBCMM        0x200E
#define DRDA_CP_RDBRLLBCK     0x200F
#define DRDA_CP_REBIND        0x2010
#define DRDA_CP_DSCRDBTBL     0x2012
#define DRDA_CP_EXCSQLSET     0x2014
#define DRDA_CP_DSCERRCD      0x2101
#define DRDA_CP_QRYPRCTYP     0x2102
#define DRDA_CP_RDBINTTKN     0x2103
#define DRDA_CP_PRDDTA        0x2104
#define DRDA_CP_RDBCMTOK      0x2105
#define DRDA_CP_RDBCOLID      0x2108
#define DRDA_CP_PKGID         0x2109
#define DRDA_CP_PKGCNSTKN     0x210D
#define DRDA_CP_RTNSETSTT     0x210E
#define DRDA_CP_RDBACCCL      0x210F
#define DRDA_CP_RDBNAM        0x2110
#define DRDA_CP_OUTEXP        0x2111
#define DRDA_CP_PKGNAMCT      0x2112
#define DRDA_CP_PKGNAMCSN     0x2113
#define DRDA_CP_QRYBLKSZ      0x2114
#define DRDA_CP_UOWDSP        0x2115
#define DRDA_CP_RTNSQLDA      0x2116
#define DRDA_CP_RDBALWUPD     0x211A
#define DRDA_CP_SQLCSRHLD     0x211F
#define DRDA_CP_STTSTRDEL     0x2120
#define DRDA_CP_STTDECDEL     0x2121
#define DRDA_CP_PKGDFTCST     0x2125
#define DRDA_CP_QRYBLKCTL     0x2132
#define DRDA_CP_CRRTKN        0x2135
#define DRDA_CP_PRCNAM        0x2138
#define DRDA_CP_PKGSNLST      0x2139
#define DRDA_CP_NBRROW        0x213A
#define DRDA_CP_TRGDFTRT      0x213B
#define DRDA_CP_QRYRELSCR     0x213C
#define DRDA_CP_QRYROWNBR     0x213D
#define DRDA_CP_QRYRFRTBL     0x213E
#define DRDA_CP_MAXRSLCNT     0x2140
#define DRDA_CP_MAXBLKEXT     0x2141
#define DRDA_CP_RSLSETFLG     0x2142
#define DRDA_CP_TYPSQLDA      0x2146
#define DRDA_CP_OUTOVROPT     0x2147
#define DRDA_CP_RTNEXTDTA     0x2148
#define DRDA_CP_QRYATTSCR     0x2149
#define DRDA_CP_QRYATTUPD     0x2150
#define DRDA_CP_QRYSCRORN     0x2152
#define DRDA_CP_QRYROWSNS     0x2153
#define DRDA_CP_QRYBLKRST     0x2154
#define DRDA_CP_QRYRTNDTA     0x2155
#define DRDA_CP_QRYROWSET     0x2156
#define DRDA_CP_QRYATTSNS     0x2157
#define DRDA_CP_QRYINSID      0x215B
#define DRDA_CP_QRYCLSIMP     0x215D
#define DRDA_CP_QRYCLSRLS     0x215E
#define DRDA_CP_QRYOPTVAL     0x215F
#define DRDA_CP_DIAGLVL       0x2160
#define DRDA_CP_ACCRDBRM      0x2201
#define DRDA_CP_QRYNOPRM      0x2202
#define DRDA_CP_RDBNACRM      0x2204
#define DRDA_CP_OPNQRYRM      0x2205
#define DRDA_CP_PKGBNARM      0x2206
#define DRDA_CP_RDBACCRM      0x2207
#define DRDA_CP_BGNBNDRM      0x2208
#define DRDA_CP_PKGBPARM      0x2209
#define DRDA_CP_DSCINVRM      0x220A
#define DRDA_CP_ENDQRYRM      0x220B
#define DRDA_CP_ENDUOWRM      0x220C
#define DRDA_CP_ABNUOWRM      0x220D
#define DRDA_CP_DTAMCHRM      0x220E
#define DRDA_CP_QRYPOPRM      0x220F
#define DRDA_CP_RDBNFNRM      0x2211
#define DRDA_CP_OPNQFLRM      0x2212
#define DRDA_CP_SQLERRRM      0x2213
#define DRDA_CP_RDBUPDRM      0x2218
#define DRDA_CP_RSLSETRM      0x2219
#define DRDA_CP_RDBAFLRM      0x221A
#define DRDA_CP_CMDVLTRM      0x221D
#define DRDA_CP_CMMRQSRM      0x2225
#define DRDA_CP_RDBATHRM      0x22CB
#define DRDA_CP_SQLAM         0x2407
#define DRDA_CP_SQLCARD       0x2408
#define DRDA_CP_SQLCINRD      0x240B
#define DRDA_CP_SQLRSLRD      0x240E
#define DRDA_CP_RDB           0x240F
#define DRDA_CP_FRCFIXROW     0x2410
#define DRDA_CP_SQLDARD       0x2411
#define DRDA_CP_SQLDTA        0x2412
#define DRDA_CP_SQLDTARD      0x2413
#define DRDA_CP_SQLSTT        0x2414
#define DRDA_CP_OUTOVR        0x2415
#define DRDA_CP_LMTBLKPRC     0x2417
#define DRDA_CP_FIXROWPRC     0x2418
#define DRDA_CP_SQLSTTVRB     0x2419
#define DRDA_CP_QRYDSC        0x241A
#define DRDA_CP_QRYDTA        0x241B
#define DRDA_CP_CSTMBCS       0x2435
#define DRDA_CP_SRVLST        0x244E
#define DRDA_CP_SQLATTR       0x2450

#define DRDA_DSSFMT_SAME_CORR 0x01
#define DRDA_DSSFMT_CONTINUE  0x02
#define DRDA_DSSFMT_CHAINED   0x04
#define DRDA_DSSFMT_RESERVED  0x08

#define DRDA_DSSFMT_RQSDSS    0x01
#define DRDA_DSSFMT_RPYDSS    0x02
#define DRDA_DSSFMT_OBJDSS    0x03
#define DRDA_DSSFMT_CMNDSS    0x04
#define DRDA_DSSFMT_NORPYDSS  0x05

#define DRDA_TEXT_DDM   "DDM"
#define DRDA_TEXT_PARAM "Parameter"

static const value_string drda_opcode_vals[] = {
    { DRDA_CP_DATA,         "Data" },
    { DRDA_CP_CODPNT,       "Code Point" },
    { DRDA_CP_FDODSC,       "FD:OCA Data Descriptor" },
    { DRDA_CP_TYPDEFNAM,    "Data Type Definition Name" },
    { DRDA_CP_TYPDEFOVR,    "TYPDEF Overrides" },
    { DRDA_CP_CODPNTDR,     "Code Point Data Representation" },
    { DRDA_CP_EXCSAT,       "Exchange Server Attributes" },
    { DRDA_CP_SYNCCTL,      "Sync Point Control Request" },
    { DRDA_CP_SYNCRSY,      "Sync Point Resync Command" },
    { DRDA_CP_ACCSEC,       "Access Security" },
    { DRDA_CP_SECCHK,       "Security Check" },
    { DRDA_CP_SYNCLOG,      "Sync Point Log" },
    { DRDA_CP_RSCTYP,       "Resource Type Information" },
    { DRDA_CP_RSNCOD,       "Reason Code Information" },
    { DRDA_CP_RSCNAM,       "Resource Name Information" },
    { DRDA_CP_PRDID,        "Product-Specific Identifier" },
    { DRDA_CP_PRCCNVCD,     "Conversation Protocol Error Code" },
    { DRDA_CP_VRSNAM,       "Version Name" },
    { DRDA_CP_SRVCLSNM,     "Server Class Name" },
    { DRDA_CP_SVRCOD,       "Severity Code" },
    { DRDA_CP_SYNERRCD,     "Syntax Error Code" },
    { DRDA_CP_SRVDGN,       "Server Diagnostic Information" },
    { DRDA_CP_SRVRLSLV,     "Server Product Release Level" },
    { DRDA_CP_SPVNAM,       "Supervisor Name" },
    { DRDA_CP_EXTNAM,       "External Name" },
    { DRDA_CP_SRVNAM,       "Server Name" },
    { DRDA_CP_SECMGRNM,     "Security Manager Name" },
    { DRDA_CP_DEPERRCD,     "Manager Dependency Error Code" },
    { DRDA_CP_CCSIDSBC,     "CCSID for Single-Byte Characters" },
    { DRDA_CP_CCSIDDBC,     "CCSID for Double-byte Characters" },
    { DRDA_CP_CCSIDMBC,     "CCSID for Mixed-byte Characters" },
    { DRDA_CP_USRID,        "User ID at the Target System" },
    { DRDA_CP_PASSWORD,     "Password" },
    { DRDA_CP_SECMEC,       "Security Mechanism" },
    { DRDA_CP_SECCHKCD,     "Security Check Code" },
    { DRDA_CP_SVCERRNO,     "Security Service ErrorNumber" },
    { DRDA_CP_SECTKN,       "Security Token" },
    { DRDA_CP_NEWPASSWORD,  "New Password" },
    { DRDA_CP_MGRLVLRM,     "Manager-Level Conflict" },
    { DRDA_CP_MGRDEPRM,     "Manager Dependency Error" },
    { DRDA_CP_SECCHKRM,     "Security Check" },
    { DRDA_CP_CMDATHRM,     "Not Authorized to Command" },
    { DRDA_CP_AGNPRMRM,     "Permanent Agent Error" },
    { DRDA_CP_RSCLMTRM,     "Resource Limits Reached" },
    { DRDA_CP_PRCCNVRM,     "Conversational Protocol Error" },
    { DRDA_CP_CMDCMPRM,     "Command Processing Completed" },
    { DRDA_CP_SYNTAXRM,     "Data Stream Syntax Error" },
    { DRDA_CP_CMDNSPRM,     "Command Not Supported" },
    { DRDA_CP_PRMNSPRM,     "Parameter Not Supported" },
    { DRDA_CP_VALNSPRM,     "Parameter Value Not Supported" },
    { DRDA_CP_OBJNSPRM,     "Object Not Supported" },
    { DRDA_CP_CMDCHKRM,     "Command Check" },
    { DRDA_CP_TRGNSPRM,     "Target Not Supported" },
    { DRDA_CP_AGENT,        "Agent" },
    { DRDA_CP_MGRLVLLS,     "Manager-Level List" },
    { DRDA_CP_SUPERVISOR,   "Supervisor" },
    { DRDA_CP_SECMGR,       "Security Manager" },
    { DRDA_CP_EXCSATRD,     "Server Attributes Reply Data" },
    { DRDA_CP_CMNAPPC,      "LU 6.2 Conversational Communications Manager" },
    { DRDA_CP_DICTIONARY,   "Dictionary" },
    { DRDA_CP_MGRLVLN,      "Manager-Level Number Attribute" },
    { DRDA_CP_CMNTCPIP,     "TCP/IP CommunicationManager" },
    { DRDA_CP_FDODTA,       "FD:OCA Data" },
    { DRDA_CP_CMNSYNCPT,
      "SNA LU 6.2 Sync Point Conversational Communications Manager" },
    { DRDA_CP_ACCSECRD,     "Access Security Reply Data" },
    { DRDA_CP_SYNCPTMGR,    "Sync Point Manager" },
    { DRDA_CP_RSYNCMGR,     "ResynchronizationManager" },
    { DRDA_CP_CCSIDMGR,     "CCSID Manager" },
    { DRDA_CP_MONITOR,      "Monitor Events" },
    { DRDA_CP_MONITORRD,    "Monitor Reply Data" },
    { DRDA_CP_XAMGR,        "XAManager" },
    { DRDA_CP_ACCRDB,       "Access RDB" },
    { DRDA_CP_BGNBND,       "Begin Binding a Package to an RDB" },
    { DRDA_CP_BNDSQLSTT,    "Bind SQL Statement to an RDB Package" },
    { DRDA_CP_CLSQRY,       "Close Query" },
    { DRDA_CP_CNTQRY,       "Continue Query" },
    { DRDA_CP_DRPPKG,       "Drop RDB Package" },
    { DRDA_CP_DSCSQLSTT,    "Describe SQL Statement" },
    { DRDA_CP_ENDBND,       "End Binding a Package to an RDB" },
    { DRDA_CP_EXCSQLIMM,    "Execute Immediate SQL Statement" },
    { DRDA_CP_EXCSQLSTT,    "Execute SQL Statement" },
    { DRDA_CP_OPNQRY,       "Open Query" },
    { DRDA_CP_PRPSQLSTT,    "Prepare SQL Statement" },
    { DRDA_CP_RDBCMM,       "RDB Commit Unit of Work" },
    { DRDA_CP_RDBRLLBCK,    "RDB Rollback Unit of Work" },
    { DRDA_CP_REBIND,       "Rebind an Existing RDB Package" },
    { DRDA_CP_DSCRDBTBL,    "Describe RDB Table" },
    { DRDA_CP_EXCSQLSET,    "Set SQL Environment" },
    { DRDA_CP_DSCERRCD,     "Description Error Code" },
    { DRDA_CP_QRYPRCTYP,    "Query Protocol Type" },
    { DRDA_CP_RDBINTTKN,    "RDB Interrupt Token" },
    { DRDA_CP_PRDDTA,       "Product-Specific Data" },
    { DRDA_CP_RDBCMTOK,     "RDB Commit Allowed" },
    { DRDA_CP_RDBCOLID,     "RDB Collection Identifier" },
    { DRDA_CP_PKGID,        "RDB Package Identifier" },
    { DRDA_CP_PKGCNSTKN,    "RDB Package Consistency Token" },
    { DRDA_CP_RTNSETSTT,    "Return SET Statement" },
    { DRDA_CP_RDBACCCL,     "RDB Access Manager Class" },
    { DRDA_CP_RDBNAM,       "Relational Database Name" },
    { DRDA_CP_OUTEXP,       "Output Expected" },
    { DRDA_CP_PKGNAMCT,     "RDB Package Name and Consistency Token" },
    { DRDA_CP_PKGNAMCSN,
      "RDB Package Name, Consistency Token, and Section Number" },
    { DRDA_CP_QRYBLKSZ,     "Query Block Size" },
    { DRDA_CP_UOWDSP,       "Unit of Work Disposition" },
    { DRDA_CP_RTNSQLDA,     "Maximum Result Set Count" },
    { DRDA_CP_RDBALWUPD,    "RDB Allow Updates" },
    { DRDA_CP_SQLCSRHLD,    "Hold Cursor Position" },
    { DRDA_CP_STTSTRDEL,    "Statement String Delimiter" },
    { DRDA_CP_STTDECDEL,    "Statement Decimal Delimiter" },
    { DRDA_CP_PKGDFTCST,    "Package Default Character Subtype" },
    { DRDA_CP_QRYBLKCTL,    "Query Block Protocol Control" },
    { DRDA_CP_CRRTKN,       "Correlation Token" },
    { DRDA_CP_PRCNAM,       "Procedure Name" },
    { DRDA_CP_PKGSNLST,     "RDB Result Set Reply Message" },
    { DRDA_CP_NBRROW,       "Number of Fetch or Insert Rows" },
    { DRDA_CP_TRGDFTRT,     "Target Default Value Return" },
    { DRDA_CP_QRYRELSCR,    "Query Relative Scrolling Action" },
    { DRDA_CP_QRYROWNBR,    "Query Row Number" },
    { DRDA_CP_QRYRFRTBL,    "Query Refresh Answer Set Table" },
    { DRDA_CP_MAXRSLCNT,    "Maximum Result Set Count" },
    { DRDA_CP_MAXBLKEXT,    "Maximum Number of Extra Blocks" },
    { DRDA_CP_RSLSETFLG,    "Result Set Flags" },
    { DRDA_CP_TYPSQLDA,     "Type of SQL Descriptor Area" },
    { DRDA_CP_OUTOVROPT,    "Output Override Option" },
    { DRDA_CP_RTNEXTDTA,    "Return of EXTDTA Option" },
    { DRDA_CP_QRYATTSCR,    "Query Attribute for Scrollability" },
    { DRDA_CP_QRYATTUPD,    "Query Attribute for Updatability" },
    { DRDA_CP_QRYSCRORN,    "Query Scroll Orientation" },
    { DRDA_CP_QRYROWSNS,    "Query Row Sensitivity" },
    { DRDA_CP_QRYBLKRST,    "Query Block Reset" },
    { DRDA_CP_QRYRTNDTA,    "Query Returns Datat" },
    { DRDA_CP_QRYROWSET,    "Query Rowset Size" },
    { DRDA_CP_QRYATTSNS,    "Query Attribute for Sensitivity" },
    { DRDA_CP_QRYINSID,     "Query Instance Identifier" },
    { DRDA_CP_QRYCLSIMP,    "Query Close Implicit" },
    { DRDA_CP_QRYCLSRLS,    "Query Close Lock Release" },
    { DRDA_CP_QRYOPTVAL,    "QRYOPTVAL" },
    { DRDA_CP_DIAGLVL,      "SQL Error Diagnostic Level" },
    { DRDA_CP_ACCRDBRM,     "Access to RDB Completed" },
    { DRDA_CP_QRYNOPRM,     "Query Not Open" },
    { DRDA_CP_RDBNACRM,     "RDB Not Accessed" },
    { DRDA_CP_OPNQRYRM,     "Open Query Complete" },
    { DRDA_CP_PKGBNARM,     "RDB Package Binding Not Active" },
    { DRDA_CP_RDBACCRM,     "RDB Currently Accessed" },
    { DRDA_CP_BGNBNDRM,     "Begin Bind Error" },
    { DRDA_CP_PKGBPARM,     "RDB Package Binding Process Active" },
    { DRDA_CP_DSCINVRM,     "Invalid Description" },
    { DRDA_CP_ENDQRYRM,     "End of Query" },
    { DRDA_CP_ENDUOWRM,     "End Unit of Work Condition" },
    { DRDA_CP_ABNUOWRM,     "Abnormal End Unit ofWork Condition" },
    { DRDA_CP_DTAMCHRM,     "Data Descriptor Mismatch" },
    { DRDA_CP_QRYPOPRM,     "Query Previously Opened" },
    { DRDA_CP_RDBNFNRM,     "RDB Not Found" },
    { DRDA_CP_OPNQFLRM,     "Open Query Failure" },
    { DRDA_CP_SQLERRRM,     "SQL Error Condition" },
    { DRDA_CP_RDBUPDRM,     "RDB Update Reply Message" },
    { DRDA_CP_RSLSETRM,     "RDB Result Set Reply Message" },
    { DRDA_CP_RDBAFLRM,     "RDB Access Failed Reply Message" },
    { DRDA_CP_CMDVLTRM,     "Command Violation" },
    { DRDA_CP_CMMRQSRM,     "Commitment Request" },
    { DRDA_CP_RDBATHRM,     "Not Authorized to RDB" },
    { DRDA_CP_SQLAM,        "SQL Application Manager" },
    { DRDA_CP_SQLCARD,      "SQL Communications Area Reply Data" },
    { DRDA_CP_SQLCINRD,     "SQL Result Set Column Information Reply Data" },
    { DRDA_CP_SQLRSLRD,     "SQL Result Set Reply Data" },
    { DRDA_CP_RDB,          "Relational Database" },
    { DRDA_CP_FRCFIXROW,    "Force Fixed Row Query Protocol" },
    { DRDA_CP_SQLDARD,      "SQLDA Reply Data" },
    { DRDA_CP_SQLDTA,       "SQL Program Variable Data" },
    { DRDA_CP_SQLDTARD,     "SQL Data Reply Data" },
    { DRDA_CP_SQLSTT,       "SQL Statement" },
    { DRDA_CP_OUTOVR,       "Output Override Descriptor" },
    { DRDA_CP_LMTBLKPRC,    "Limited Block Protocol" },
    { DRDA_CP_FIXROWPRC,    "Fixed Row Query Protocol" },
    { DRDA_CP_SQLSTTVRB,    "SQL Statement Variable Descriptions" },
    { DRDA_CP_QRYDSC,       "Query Answer Set Description" },
    { DRDA_CP_QRYDTA,       "Query Answer Set Data" },
    { DRDA_CP_SQLATTR,      "SQL Statement Attributes" },
    { 0,          NULL }
};
static value_string_ext drda_opcode_vals_ext = VALUE_STRING_EXT_INIT(drda_opcode_vals);

static const value_string drda_opcode_abbr[] = {
    { DRDA_CP_DATA,         "DATA" },
    { DRDA_CP_CODPNT,       "CODPNT" },
    { DRDA_CP_FDODSC,       "FDODSC" },
    { DRDA_CP_TYPDEFNAM,    "TYPDEFNAM" },
    { DRDA_CP_TYPDEFOVR,    "TYPDEFOVR" },
    { DRDA_CP_CODPNTDR,     "CODPNTDR" },
    { DRDA_CP_EXCSAT,       "EXCSAT" },
    { DRDA_CP_SYNCCTL,      "SYNCCTL" },
    { DRDA_CP_SYNCRSY,      "SYNCRSY" },
    { DRDA_CP_ACCSEC,       "ACCSEC" },
    { DRDA_CP_SECCHK,       "SECCHK" },
    { DRDA_CP_SYNCLOG,      "SYNCLOG" },
    { DRDA_CP_RSCTYP,       "RSCTYP" },
    { DRDA_CP_RSNCOD,       "RSNCOD" },
    { DRDA_CP_RSCNAM,       "RSCNAM" },
    { DRDA_CP_PRDID,        "PRDID" },
    { DRDA_CP_PRCCNVCD,     "PRCCNVCD" },
    { DRDA_CP_VRSNAM,       "VRSNAM" },
    { DRDA_CP_SRVCLSNM,     "SRVCLSNM" },
    { DRDA_CP_SVRCOD,       "SVRCOD" },
    { DRDA_CP_SYNERRCD,     "SYNERRCD" },
    { DRDA_CP_SRVDGN,       "SRVDGN" },
    { DRDA_CP_SRVRLSLV,     "SRVRLSLV" },
    { DRDA_CP_SPVNAM,       "SPVNAM" },
    { DRDA_CP_EXTNAM,       "EXTNAM" },
    { DRDA_CP_SRVNAM,       "SRVNAM" },
    { DRDA_CP_SECMGRNM,     "SECMGRNM" },
    { DRDA_CP_DEPERRCD,     "DEPERRCD" },
    { DRDA_CP_CCSIDSBC,     "CCSIDSBC" },
    { DRDA_CP_CCSIDDBC,     "CCSIDDBC" },
    { DRDA_CP_CCSIDMBC,     "CCSIDMBC" },
    { DRDA_CP_USRID,        "USRID" },
    { DRDA_CP_PASSWORD,     "PASSWORD" },
    { DRDA_CP_SECMEC,       "SECMEC" },
    { DRDA_CP_SECCHKCD,     "SECCHKCD" },
    { DRDA_CP_SVCERRNO,     "SVCERRNO" },
    { DRDA_CP_SECTKN,       "SECTKN" },
    { DRDA_CP_NEWPASSWORD,  "NEWPASSWORD" },
    { DRDA_CP_MGRLVLRM,     "MGRLVLRM" },
    { DRDA_CP_MGRDEPRM,     "MGRDEPRM" },
    { DRDA_CP_SECCHKRM,     "SECCHKRM" },
    { DRDA_CP_CMDATHRM,     "CMDATHRM" },
    { DRDA_CP_AGNPRMRM,     "AGNPRMRM" },
    { DRDA_CP_RSCLMTRM,     "RSCLMTRM" },
    { DRDA_CP_PRCCNVRM,     "PRCCNVRM" },
    { DRDA_CP_CMDCMPRM,     "CMDCMPRM" },
    { DRDA_CP_SYNTAXRM,     "SYNTAXRM" },
    { DRDA_CP_CMDNSPRM,     "CMDNSPRM" },
    { DRDA_CP_PRMNSPRM,     "PRMNSPRM" },
    { DRDA_CP_VALNSPRM,     "VALNSPRM" },
    { DRDA_CP_OBJNSPRM,     "OBJNSPRM" },
    { DRDA_CP_CMDCHKRM,     "CMDCHKRM" },
    { DRDA_CP_TRGNSPRM,     "TRGNSPRM" },
    { DRDA_CP_AGENT,        "AGENT" },
    { DRDA_CP_MGRLVLLS,     "MGRLVLLS" },
    { DRDA_CP_SUPERVISOR,   "SUPERVISOR" },
    { DRDA_CP_SECMGR,       "SECMGR" },
    { DRDA_CP_EXCSATRD,     "EXCSATRD" },
    { DRDA_CP_CMNAPPC,      "CMNAPPC" },
    { DRDA_CP_DICTIONARY,   "DICTIONARY" },
    { DRDA_CP_MGRLVLN,      "MGRLVLN" },
    { DRDA_CP_CMNTCPIP,     "CMNTCPIP" },
    { DRDA_CP_FDODTA,       "FDODTA" },
    { DRDA_CP_CMNSYNCPT,    "CMNSYNCPT" },
    { DRDA_CP_ACCSECRD,     "ACCSECRD" },
    { DRDA_CP_SYNCPTMGR,    "SYNCPTMGR" },
    { DRDA_CP_RSYNCMGR,     "RSYNCMGR" },
    { DRDA_CP_CCSIDMGR,     "CCSIDMGR" },
    { DRDA_CP_MONITOR,      "MONITOR" },
    { DRDA_CP_MONITORRD,    "MONITORRD" },
    { DRDA_CP_XAMGR,        "XAMGR" },
    { DRDA_CP_ACCRDB,       "ACCRDB" },
    { DRDA_CP_BGNBND,       "BGNBND" },
    { DRDA_CP_BNDSQLSTT,    "BNDSQLSTT" },
    { DRDA_CP_CLSQRY,       "CLSQRY" },
    { DRDA_CP_CNTQRY,       "CNTQRY" },
    { DRDA_CP_DRPPKG,       "DRPPKG" },
    { DRDA_CP_DSCSQLSTT,    "DSCSQLSTT" },
    { DRDA_CP_ENDBND,       "ENDBND" },
    { DRDA_CP_EXCSQLIMM,    "EXCSQLIMM" },
    { DRDA_CP_EXCSQLSTT,    "EXCSQLSTT" },
    { DRDA_CP_OPNQRY,       "OPNQRY" },
    { DRDA_CP_PRPSQLSTT,    "PRPSQLSTT" },
    { DRDA_CP_RDBCMM,       "RDBCMM" },
    { DRDA_CP_RDBRLLBCK,    "RDBRLLBCK" },
    { DRDA_CP_REBIND,       "REBIND" },
    { DRDA_CP_DSCRDBTBL,    "DSCRDBTBL" },
    { DRDA_CP_EXCSQLSET,    "EXCSQLSET" },
    { DRDA_CP_DSCERRCD,     "DSCERRCD" },
    { DRDA_CP_QRYPRCTYP,    "QRYPRCTYP" },
    { DRDA_CP_RDBINTTKN,    "RDBINTTKN" },
    { DRDA_CP_PRDDTA,       "PRDDTA" },
    { DRDA_CP_RDBCMTOK,     "RDBCMTOK" },
    { DRDA_CP_RDBCOLID,     "RDBCOLID" },
    { DRDA_CP_PKGID,        "PKGID" },
    { DRDA_CP_PKGCNSTKN,    "PKGCNSTKN" },
    { DRDA_CP_RTNSETSTT,    "RTNSETSTT" },
    { DRDA_CP_RDBACCCL,     "RDBACCCL" },
    { DRDA_CP_RDBNAM,       "RDBNAM" },
    { DRDA_CP_OUTEXP,       "OUTEXP" },
    { DRDA_CP_PKGNAMCT,     "PKGNAMCT" },
    { DRDA_CP_PKGNAMCSN,    "PKGNAMCSN" },
    { DRDA_CP_QRYBLKSZ,     "QRYBLKSZ" },
    { DRDA_CP_UOWDSP,       "UOWDSP" },
    { DRDA_CP_RTNSQLDA,     "RTNSQLDA" },
    { DRDA_CP_RDBALWUPD,    "RDBALWUPD" },
    { DRDA_CP_SQLCSRHLD,    "SQLCSRHLD" },
    { DRDA_CP_STTSTRDEL,    "STTSTRDEL" },
    { DRDA_CP_STTDECDEL,    "STTDECDEL" },
    { DRDA_CP_PKGDFTCST,    "PKGDFTCST" },
    { DRDA_CP_QRYBLKCTL,    "QRYBLKCTL" },
    { DRDA_CP_CRRTKN,       "CRRTKN" },
    { DRDA_CP_PRCNAM,       "PRCNAM" },
    { DRDA_CP_PKGSNLST,     "PKGSNLST" },
    { DRDA_CP_NBRROW,       "NBRROW" },
    { DRDA_CP_TRGDFTRT,     "TRGDFTRT" },
    { DRDA_CP_QRYRELSCR,    "QRYRELSCR" },
    { DRDA_CP_QRYROWNBR,    "QRYROWNBR" },
    { DRDA_CP_QRYRFRTBL,    "QRYRFRTBL" },
    { DRDA_CP_MAXRSLCNT,    "MAXRSLCNT" },
    { DRDA_CP_MAXBLKEXT,    "MAXBLKEXT" },
    { DRDA_CP_RSLSETFLG,    "RSLSETFLG" },
    { DRDA_CP_TYPSQLDA,     "TYPSQLDA" },
    { DRDA_CP_OUTOVROPT,    "OUTOVROPT" },
    { DRDA_CP_RTNEXTDTA,    "RTNEXTDTA" },
    { DRDA_CP_QRYATTSCR,    "QRYATTSCR" },
    { DRDA_CP_QRYATTUPD,    "QRYATTUPD" },
    { DRDA_CP_QRYSCRORN,    "QRYSCRORN" },
    { DRDA_CP_QRYROWSNS,    "QRYROWSNS" },
    { DRDA_CP_QRYBLKRST,    "QRYBLKRST" },
    { DRDA_CP_QRYRTNDTA,    "QRYRTNDTA" },
    { DRDA_CP_QRYROWSET,    "QRYROWSET" },
    { DRDA_CP_QRYATTSNS,    "QRYATTSNS" },
    { DRDA_CP_QRYINSID,     "QRYINSID" },
    { DRDA_CP_QRYCLSIMP,    "QRYCLSIMP" },
    { DRDA_CP_QRYCLSRLS,    "QRYCLSRLS" },
    { DRDA_CP_QRYOPTVAL,    "QRYOPTVAL" },
    { DRDA_CP_DIAGLVL,      "DIAGLVL" },
    { DRDA_CP_ACCRDBRM,     "ACCRDBRM" },
    { DRDA_CP_QRYNOPRM,     "QRYNOPRM" },
    { DRDA_CP_RDBNACRM,     "RDBNACRM" },
    { DRDA_CP_OPNQRYRM,     "OPNQRYRM" },
    { DRDA_CP_PKGBNARM,     "PKGBNARM" },
    { DRDA_CP_RDBACCRM,     "RDBACCRM" },
    { DRDA_CP_BGNBNDRM,     "BGNBNDRM" },
    { DRDA_CP_PKGBPARM,     "PKGBPARM" },
    { DRDA_CP_DSCINVRM,     "DSCINVRM" },
    { DRDA_CP_ENDQRYRM,     "ENDQRYRM" },
    { DRDA_CP_ENDUOWRM,     "ENDUOWRM" },
    { DRDA_CP_ABNUOWRM,     "ABNUOWRM" },
    { DRDA_CP_DTAMCHRM,     "DTAMCHRM" },
    { DRDA_CP_QRYPOPRM,     "QRYPOPRM" },
    { DRDA_CP_RDBNFNRM,     "RDBNFNRM" },
    { DRDA_CP_OPNQFLRM,     "OPNQFLRM" },
    { DRDA_CP_SQLERRRM,     "SQLERRRM" },
    { DRDA_CP_RDBUPDRM,     "RDBUPDRM" },
    { DRDA_CP_RSLSETRM,     "RSLSETRM" },
    { DRDA_CP_RDBAFLRM,     "RDBAFLRM" },
    { DRDA_CP_CMDVLTRM,     "CMDVLTRM" },
    { DRDA_CP_CMMRQSRM,     "CMMRQSRM" },
    { DRDA_CP_RDBATHRM,     "RDBATHRM" },
    { DRDA_CP_SQLAM,        "SQLAM" },
    { DRDA_CP_SQLCARD,      "SQLCARD" },
    { DRDA_CP_SQLCINRD,     "SQLCINRD" },
    { DRDA_CP_SQLRSLRD,     "SQLRSLRD" },
    { DRDA_CP_RDB,          "RDB" },
    { DRDA_CP_FRCFIXROW,    "FRCFIXROW" },
    { DRDA_CP_SQLDARD,      "SQLDARD" },
    { DRDA_CP_SQLDTA,       "SQLDTA" },
    { DRDA_CP_SQLDTARD,     "SQLDTARD" },
    { DRDA_CP_SQLSTT,       "SQLSTT" },
    { DRDA_CP_OUTOVR,       "OUTOVR" },
    { DRDA_CP_LMTBLKPRC,    "LMTBLKPRC" },
    { DRDA_CP_FIXROWPRC,    "FIXROWPRC" },
    { DRDA_CP_SQLSTTVRB,    "SQLSTTVRB" },
    { DRDA_CP_QRYDSC,       "QRYDSC" },
    { DRDA_CP_QRYDTA,       "QRYDTA" },
    { DRDA_CP_SQLATTR,      "SQLATTR" },
    { 0,          NULL }
};
static value_string_ext drda_opcode_abbr_ext = VALUE_STRING_EXT_INIT(drda_opcode_abbr);

static const value_string drda_dsstyp_abbr[] = {
    { DRDA_DSSFMT_RQSDSS,     "RQSDSS" },
    { DRDA_DSSFMT_RPYDSS,     "RPYDSS" },
    { DRDA_DSSFMT_OBJDSS,     "OBJDSS" },
    { DRDA_DSSFMT_CMNDSS,     "CMNDSS" },
    { DRDA_DSSFMT_NORPYDSS,   "NORPYDSS" },
    { 0,          NULL }
};

static guint iPreviousFrameNumber = 0;

static void
drda_init(void)
{
    iPreviousFrameNumber = 0;
}

static void
dissect_drda(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;

    guint16 iCommand;
    guint16 iLength;
    guint16 iCommandEnd = 0;

    guint8 iFormatFlags;
    guint8 iDSSType;
    guint8 iDSSFlags;

    guint16 iParameterCP;
    gint iLengthParam;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRDA");
    /* This is a trick to know whether this is the first PDU in this packet or not */
    if (iPreviousFrameNumber != pinfo->fd->num)
        col_clear(pinfo->cinfo, COL_INFO);
    else
        col_append_str(pinfo->cinfo, COL_INFO, " | ");

    iPreviousFrameNumber = pinfo->fd->num;
    /* There may be multiple DRDA commands in one frame */
    while ((guint) (offset + 10) <= tvb_length(tvb))
    {
        iCommand = tvb_get_ntohs(tvb, offset + 8);
        iLength = tvb_get_ntohs(tvb, offset + 0);
        if (iLength < 10) {
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Invalid length detected (%u): should be at least 10 bytes long", iLength);
            break;
        }
        /* iCommandEnd is the length of the packet up to the end of the current command */
        iCommandEnd += iLength;

        if (offset > 0)
            col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(iCommand, &drda_opcode_abbr_ext, "Unknown (0x%02x)"));

        if (tree)
        {
            proto_tree  *drda_tree;
            proto_tree  *drdaroot_tree;
            proto_tree  *drda_tree_sub;
            proto_item  *ti;

            ti = proto_tree_add_item(tree, proto_drda, tvb, offset, -1, ENC_NA);
            proto_item_append_text(ti, " (%s)", val_to_str_ext(iCommand, &drda_opcode_vals_ext, "Unknown (0x%02x)"));
            drdaroot_tree = proto_item_add_subtree(ti, ett_drda);

            ti = proto_tree_add_text(drdaroot_tree, tvb, offset, 10, DRDA_TEXT_DDM);
            proto_item_append_text(ti, " (%s)", val_to_str_ext(iCommand, &drda_opcode_abbr_ext, "Unknown (0x%02x)"));
            drda_tree = proto_item_add_subtree(ti, ett_drda_ddm);

            proto_tree_add_item(drda_tree, hf_drda_ddm_length, tvb, offset + 0, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(drda_tree, hf_drda_ddm_magic, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

            iFormatFlags = tvb_get_guint8(tvb, offset + 3);
            iDSSType = iFormatFlags & 0x0F;
            iDSSFlags = iFormatFlags >> 4;

            ti = proto_tree_add_item(drda_tree, hf_drda_ddm_format, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
            drda_tree_sub = proto_item_add_subtree(ti, ett_drda_ddm_format);

            proto_tree_add_boolean(drda_tree_sub, hf_drda_ddm_fmt_reserved, tvb, offset + 3, 1, iDSSFlags);
            proto_tree_add_boolean(drda_tree_sub, hf_drda_ddm_fmt_chained, tvb, offset + 3, 1, iDSSFlags);
            proto_tree_add_boolean(drda_tree_sub, hf_drda_ddm_fmt_errcont, tvb, offset + 3, 1, iDSSFlags);
            proto_tree_add_boolean(drda_tree_sub, hf_drda_ddm_fmt_samecorr, tvb, offset + 3, 1, iDSSFlags);
            proto_tree_add_uint(drda_tree_sub, hf_drda_ddm_fmt_dsstyp, tvb, offset + 3, 1, iDSSType);

            proto_tree_add_item(drda_tree, hf_drda_ddm_rc, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(drda_tree, hf_drda_ddm_length2, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(drda_tree, hf_drda_ddm_codepoint, tvb, offset + 8, 2, ENC_BIG_ENDIAN);

            /* The number of attributes is variable */
            for (offset += 10; offset < iCommandEnd; )
            {
                if (tvb_length_remaining(tvb, offset) >= 2)
                {
                    iLengthParam = tvb_get_ntohs(tvb, offset + 0);
                    if (iLengthParam == 0 || iLengthParam == 1) iLengthParam = iLength - 10;
                    if (tvb_length_remaining(tvb, offset) >= iLengthParam)
                    {
                        iParameterCP = tvb_get_ntohs(tvb, offset + 2);
                        ti = proto_tree_add_text(drdaroot_tree, tvb, offset, iLengthParam,
                                     DRDA_TEXT_PARAM);
                        proto_item_append_text(ti, " (%s)", val_to_str_ext(iParameterCP, &drda_opcode_vals_ext, "Unknown (0x%02x)"));
                        drda_tree_sub = proto_item_add_subtree(ti, ett_drda_param);
                        proto_tree_add_item(drda_tree_sub, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(drda_tree_sub, hf_drda_param_codepoint, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(drda_tree_sub, hf_drda_param_data, tvb, offset + 4, iLengthParam - 4, ENC_UTF_8|ENC_NA);
                        proto_tree_add_item(drda_tree_sub, hf_drda_param_data_ebcdic, tvb, offset + 4, iLengthParam - 4, ENC_EBCDIC|ENC_NA);
                        if (iCommand == DRDA_CP_SQLSTT)
                        {
                            /* Extract SQL statement from packet */
                            tvbuff_t* next_tvb = NULL;
                            next_tvb = tvb_new_subset(tvb, offset + 4, iLengthParam - 4, iLengthParam - 4);
                            add_new_data_source(pinfo, next_tvb, "SQL statement");
                            proto_tree_add_item(drdaroot_tree, hf_drda_sqlstatement, next_tvb, 0, iLengthParam - 5, ENC_UTF_8|ENC_NA);
                            proto_tree_add_item(drdaroot_tree, hf_drda_sqlstatement_ebcdic, next_tvb, 0, iLengthParam - 4, ENC_EBCDIC|ENC_NA);
                        }
                    }
                    offset += iLengthParam;
                }
                else
                {
                    break;
                }
            }
        }
        else
        {
            /* No tree, advance directly to next command */
            offset += iLength;
        }
    }
}

static guint
get_drda_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    if (tvb_length_remaining(tvb, offset) >= 10)
    {
        return (tvb_get_ntohs(tvb, offset));
    }
    return 0;
}

static void
dissect_drda_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, drda_desegment, 10, get_drda_pdu_len, dissect_drda);
}


static gboolean
dissect_drda_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t * conversation;
    if (tvb_length(tvb) >= 10)
    {
        /* The first header is 6 bytes long, so the length in the second header should 6 bytes less */
        guint16 cOuterLength, cInnerLength;
        cOuterLength = tvb_get_ntohs(tvb, 0);
        cInnerLength = tvb_get_ntohs(tvb, 6);
        if ((tvb_get_guint8(tvb, 2) == DRDA_MAGIC) && ((cOuterLength - cInnerLength) == 6))
        {
            /* Register this dissector for this conversation */
            conversation = find_or_create_conversation(pinfo);
            conversation_set_dissector(conversation, drda_tcp_handle);

            /* Dissect the packet */
            dissect_drda(tvb, pinfo, tree);
            return TRUE;
        }
    }
    return FALSE;
}

void
proto_register_drda(void)
{
    static hf_register_info hf[] = {
        { &hf_drda_ddm_length,
          { "Length", "drda.ddm.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "DDM length", HFILL }},

        { &hf_drda_ddm_magic,
          { "Magic", "drda.ddm.ddmid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "DDM magic", HFILL }},

        { &hf_drda_ddm_format,
          { "Format", "drda.ddm.format",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "DDM format", HFILL }},

        { &hf_drda_ddm_fmt_reserved,
          { "Reserved", "drda.ddm.fmt.bit0",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), DRDA_DSSFMT_RESERVED,
            "DSSFMT reserved", HFILL }},

        { &hf_drda_ddm_fmt_chained,
          { "Chained", "drda.ddm.fmt.bit1",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), DRDA_DSSFMT_CHAINED,
            "DSSFMT chained", HFILL }},

        { &hf_drda_ddm_fmt_errcont,
          { "Continue", "drda.ddm.fmt.bit2",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), DRDA_DSSFMT_CONTINUE,
            "DSSFMT continue on error", HFILL }},

        { &hf_drda_ddm_fmt_samecorr,
          { "Same correlation", "drda.ddm.fmt.bit3",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), DRDA_DSSFMT_SAME_CORR,
            "DSSFMT same correlation", HFILL }},

        { &hf_drda_ddm_fmt_dsstyp,
          { "DSS type", "drda.ddm.fmt.dsstyp",
            FT_UINT8, BASE_DEC, VALS(drda_dsstyp_abbr), 0x0,
            "DSSFMT type", HFILL }},

        { &hf_drda_ddm_rc,
          { "CorrelId", "drda.ddm.rqscrr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "DDM correlation identifier", HFILL }},

        { &hf_drda_ddm_length2,
          { "Length2", "drda.ddm.length2",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "DDM length2", HFILL }},

        { &hf_drda_ddm_codepoint,
          { "Code point", "drda.ddm.codepoint",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &drda_opcode_abbr_ext, 0x0,
            "DDM code point", HFILL }},

        { &hf_drda_param_length,
          { "Length", "drda.param.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Param length", HFILL }},

        { &hf_drda_param_codepoint,
          { "Code point", "drda.param.codepoint",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &drda_opcode_abbr_ext, 0x0,
            "Param code point", HFILL }},

        { &hf_drda_param_data,
          { "Data (ASCII)", "drda.param.data",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Param data left as ASCII for display", HFILL }},

        { &hf_drda_param_data_ebcdic,
          { "Data (EBCDIC)", "drda.param.data.ebcdic",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Param data converted from EBCDIC to ASCII for display", HFILL }},

        { &hf_drda_sqlstatement,
          { "SQL statement (ASCII)", "drda.sqlstatement",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "SQL statement left as ASCII for display", HFILL }},

        { &hf_drda_sqlstatement_ebcdic,
          { "SQL statement (EBCDIC)", "drda.sqlstatement.ebcdic",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "SQL statement converted from EBCDIC to ASCII for display", HFILL }}

    };
    static gint *ett[] = {
        &ett_drda,
        &ett_drda_ddm,
        &ett_drda_ddm_format,
        &ett_drda_param
    };

    module_t *drda_module;

    proto_drda = proto_register_protocol("DRDA", "DRDA", "drda");
    proto_register_field_array(proto_drda, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    drda_module = prefs_register_protocol(proto_drda, NULL);
    prefs_register_bool_preference(drda_module, "desegment",
                       "Reassemble DRDA messages spanning multiple TCP segments",
                       "Whether the DRDA dissector should reassemble messages spanning"
                       " multiple TCP segments."
                       " To use this option, you must also enable"
                       " \"Allow subdissectors to reassemble TCP streams\""
                       " in the TCP protocol settings.",
                       &drda_desegment);
    register_init_routine(&drda_init);
}

void
proto_reg_handoff_drda(void)
{
    heur_dissector_add("tcp", dissect_drda_heur, proto_drda);
    drda_tcp_handle = create_dissector_handle(dissect_drda_tcp, proto_drda);
}
