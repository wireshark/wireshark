/* packet-drda.c
 * Routines for Distributed Relational Database Architecture packet dissection
 *
 * metatech <metatech@flashmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
*
*   DRDA Version 2, Volume 3: Distributed Data Management (DDM)
*     Architecture, Open Group.
*
*       https://pubs.opengroup.org/onlinepubs/009608699/toc.pdf
*
*   DRDA Version 3, Volume 3: Distributed Data Management (DDM)
*     Architecture Open Group.
*   Version 3 is no longer available.
*
*   DRDA Version 4, Volume 3: Distributed Data Management (DDM)
*     Architecture, Open Group.
*
*       https://pubs.opengroup.org/onlinepubs/9699939199/toc.pdf
*
*   DRDA Version 5, Volume 3: Distributed Data Management (DDM)
*     Architecture, Open Group.
*
*       https://publications.opengroup.org/c114
*
*   Reference for Remote DRDA Requesters and Servers, IBM.
*
*       https://www-304.ibm.com/support/docview.wss?uid=pub1sc18985301
*         (now dead)
*       https://publibfp.boulder.ibm.com/epubs/pdf/dsnudh10.pdf
*
*   Microsoft has some references that can be useful as well:
*
*       https://learn.microsoft.com/en-us/dotnet/api/microsoft.hostintegration.drda.common?view=his-dotnet
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/iana_charsets.h>
#include <epan/proto_data.h>
#include "packet-tcp.h"

void proto_register_drda(void);
void proto_reg_handoff_drda(void);

static int proto_drda;
static int hf_drda_ddm_length;
static int hf_drda_ddm_magic;
static int hf_drda_ddm_format;
static int hf_drda_ddm_fmt_reserved;
static int hf_drda_ddm_fmt_chained;
static int hf_drda_ddm_fmt_errcont;
static int hf_drda_ddm_fmt_samecorr;
static int hf_drda_ddm_fmt_dsstyp;
static int hf_drda_ddm_rc;
static int hf_drda_ddm_length2;
static int hf_drda_ddm_codepoint;
static int hf_drda_param_length;
static int hf_drda_param_codepoint;
static int hf_drda_param_data;
static int hf_drda_param_data_ebcdic;
static int hf_drda_null_ind;
static int hf_drda_typdefnam;
static int hf_drda_clob_length;
static int hf_drda_sqlstatement;
static int hf_drda_sqlcagrp;
static int hf_drda_sqlcode;
static int hf_drda_sqlstate;
static int hf_drda_sqlerrproc;
static int hf_drda_sqlcaxgrp;
static int hf_drda_sqlerrd1;
static int hf_drda_sqlerrd2;
static int hf_drda_sqlerrd3;
static int hf_drda_sqlerrd4;
static int hf_drda_sqlerrd5;
static int hf_drda_sqlerrd6;
static int hf_drda_sqlwarn0;
static int hf_drda_sqlwarn1;
static int hf_drda_sqlwarn2;
static int hf_drda_sqlwarn3;
static int hf_drda_sqlwarn4;
static int hf_drda_sqlwarn5;
static int hf_drda_sqlwarn6;
static int hf_drda_sqlwarn7;
static int hf_drda_sqlwarn8;
static int hf_drda_sqlwarn9;
static int hf_drda_sqlwarna;
static int hf_drda_sqlerrmsg;
static int hf_drda_sqldhgrp;
static int hf_drda_sqldhold;
static int hf_drda_sqldreturn;
static int hf_drda_sqldscroll;
static int hf_drda_sqldsensitive;
static int hf_drda_sqldfcode;
static int hf_drda_sqldkeytype;
static int hf_drda_sqldoptlck;
static int hf_drda_sqldschema;
static int hf_drda_sqldmodule;
static int hf_drda_sqldagrp;
static int hf_drda_sqlprecision;
static int hf_drda_sqlscale;
static int hf_drda_sqllength;
static int hf_drda_sqllength32;
static int hf_drda_sqltype;
static int hf_drda_sqlarrextent;
static int hf_drda_sqldoptgrp;
static int hf_drda_sqlunnamed;
static int hf_drda_sqlname;
static int hf_drda_sqllabel;
static int hf_drda_sqlcomments;
static int hf_drda_sqludtgrp;
static int hf_drda_sqludtxtype;
static int hf_drda_sqludtschema;
static int hf_drda_sqludtname;
static int hf_drda_sqludtmodule;
static int hf_drda_sqldxgrp;
static int hf_drda_sqlxkeymem;
static int hf_drda_sqlxupdateable;
static int hf_drda_sqlxgenerated;
static int hf_drda_sqlxparmmode;
static int hf_drda_sqlxoptlck;
static int hf_drda_sqlxhidden;
static int hf_drda_sqlxcorname;
static int hf_drda_sqlxbasename;
static int hf_drda_sqlxschema;
static int hf_drda_sqlxname;
static int hf_drda_sqlxmodule;
static int hf_drda_sqldiaggrp;
static int hf_drda_sqlnum;
static int hf_drda_rlsconv;
static int hf_drda_secmec;
static int hf_drda_sectkn;
static int hf_drda_svrcod;
static int hf_drda_secchkcd;
static int hf_drda_ccsid;
static int hf_drda_mgrlvln;
static int hf_drda_monitor;
static int hf_drda_monitor_etime;
static int hf_drda_monitor_reserved;
static int hf_drda_etime;
static int hf_drda_respktsz;
static int hf_drda_rdbinttkn;
static int hf_drda_rdbcmtok;
static int hf_drda_rdbcolid;
static int hf_drda_rdbcolid_ebcdic;
static int hf_drda_pkgid;
static int hf_drda_pkgid_ebcdic;
static int hf_drda_pkgsn;
static int hf_drda_pkgcnstkn;
static int hf_drda_rtnsetstt;
static int hf_drda_rdbnam;
static int hf_drda_rdbnam_ebcdic;
static int hf_drda_outexp;
static int hf_drda_qryblksz;
static int hf_drda_uowdsp;
static int hf_drda_rdbalwupd;
static int hf_drda_sqlcsrhld;
static int hf_drda_qryextdtasz;
static int hf_drda_smldtasz;
static int hf_drda_meddtasz;
static int hf_drda_trgdftrt;
static int hf_drda_rtnsqlda;
static int hf_drda_qryattupd;
static int hf_drda_qryrowset;
static int hf_drda_qryinsid;
static int hf_drda_qryclsimp;
static int hf_drda_qryblkfct;
static int hf_drda_maxrslcnt;
static int hf_drda_maxblkext;
static int hf_drda_rslsetflg;
static int hf_drda_rslsetflg_unused;
static int hf_drda_rslsetflg_dsconly;
static int hf_drda_rslsetflg_extended;
static int hf_drda_rslsetflg_reserved;
static int hf_drda_typsqlda;
static int hf_drda_outovropt;
static int hf_drda_dyndtafmt;
static int hf_drda_pktobj;

static int ett_drda;
static int ett_drda_ddm;
static int ett_drda_ddm_format;
static int ett_drda_param;
static int ett_drda_monitor;
static int ett_drda_rslsetflg;
static int ett_drda_sqlcagrp;
static int ett_drda_sqlcaxgrp;
static int ett_drda_sqldhgrp;
static int ett_drda_sqldagrp;
static int ett_drda_sqldoptgrp;
static int ett_drda_sqludtgrp;
static int ett_drda_sqldxgrp;
static int ett_drda_sqldiaggrp;

static expert_field ei_drda_opcode_invalid_length;
static expert_field ei_drda_undecoded;

static dissector_handle_t drda_tcp_handle;

static dissector_table_t drda_opcode_table;

#define typdefnam_vals_ENUM_VAL_T_LIST(XXX) \
    XXX(TYPDEFNAM_370, 1, "QTDSQL370", "System/390 SQL type definition") \
    XXX(TYPDEFNAM_400, 2, "QTDSQL400", "AS/400 SQL type definition") \
    XXX(TYPDEFNAM_X86, 3, "QTDSQLX86", "Intel 80x86 SQL type definition") \
    XXX(TYPDEFNAM_ASC, 4, "QTDSQLASC", "General ASCII Big Endian SQL type definition") \
    XXX(TYPDEFNAM_VAX, 5, "QTDSQLVAX", "DEC VAX SQL type definition")

typedef ENUM_VAL_T_ENUM(typdefnam_vals) enum_typdefnam_t;

ENUM_VAL_T_ARRAY_STATIC(typdefnam_vals);

/* Preferences */
static bool drda_desegment = true;
static unsigned drda_default_sqlam = 7;
static int drda_default_typdefnam = TYPDEFNAM_X86;
static int drda_default_ccsidsbc = IANA_CS_UTF_8;
static int drda_default_ccsidmbc = IANA_CS_UTF_8;

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
#define DRDA_CP_RLSCONV       0x119F
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
#define DRDA_CP_SNDPKT        0x1805
#define DRDA_CP_MONITOR       0x1900
#define DRDA_CP_ETIME         0x1901
#define DRDA_CP_RESPKTSZ      0x1908
#define DRDA_CP_CCSIDXML      0x1913
#define DRDA_CP_MONITORRD     0x1C00
#define DRDA_CP_XAMGR         0x1C01
#define DRDA_CP_PKTOBJ        0x1C04
#define DRDA_CP_UNICODEMGR    0x1C08
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
#define DRDA_CP_PKGNAM        0x210A
#define DRDA_CP_PKGSN         0x210C
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
#define DRDA_CP_QRYEXTDTASZ   0x2134
#define DRDA_CP_CRRTKN        0x2135
#define DRDA_CP_SMLDTASZ      0x2136
#define DRDA_CP_MEDDTASZ      0x2137
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
#define DRDA_CP_DYNDTAFMT     0x214B
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
#define DRDA_CP_QRYBLKFCT     0x215F
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
#define DRDA_CP_CSTSYSDFT     0x2432
#define DRDA_CP_CSTBITS       0x2433
#define DRDA_CP_CSTSBCS       0x2434
#define DRDA_CP_CSTMBCS       0x2435
#define DRDA_CP_ISOLVLCHG     0x2441
#define DRDA_CP_ISOLVLCS      0x2442
#define DRDA_CP_ISOLVLALL     0x2443
#define DRDA_CP_ISOLVLRR      0x2444
#define DRDA_CP_ISOLVLNC      0x2445
#define DRDA_CP_SRVLST        0x244E
#define DRDA_CP_SQLATTR       0x2450

#define DRDA_DSSFMT_SAME_CORR 0x10
#define DRDA_DSSFMT_CONTINUE  0x20
#define DRDA_DSSFMT_CHAINED   0x40
#define DRDA_DSSFMT_RESERVED  0x80

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
    { DRDA_CP_RLSCONV,      "Release Conversation" },
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
    { DRDA_CP_SNDPKT,       "Send Packet" },
    { DRDA_CP_MONITOR,      "Monitor Events" },
    { DRDA_CP_ETIME,        "Elapsed Time" },
    { DRDA_CP_RESPKTSZ,     "Response Packet Size" },
    { DRDA_CP_CCSIDXML,     "CCSID for External Encoded XML Strings" },
    { DRDA_CP_MONITORRD,    "Monitor Reply Data" },
    { DRDA_CP_XAMGR,        "XAManager" },
    { DRDA_CP_PKTOBJ,       "Packet Object" },
    { DRDA_CP_UNICODEMGR,   "Unicode Manager" },
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
    { DRDA_CP_PKGNAM,       "RDB Package Name" },
    { DRDA_CP_PKGSN,        "RDB Package Section Number" },
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
    { DRDA_CP_QRYEXTDTASZ,  "Query Externalized Data Size" },
    { DRDA_CP_CRRTKN,       "Correlation Token" },
    { DRDA_CP_SMLDTASZ,     "Maximum Size of Small Data" },
    { DRDA_CP_MEDDTASZ,     "Maximum Size of Medium Data" },
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
    { DRDA_CP_DYNDTAFMT,    "Dynamic Data Format" },
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
    { DRDA_CP_QRYBLKFCT,    "Query Blocking Factor" },
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
    { DRDA_CP_CSTSYSDFT,    "Character Subtype System Default" },
    { DRDA_CP_CSTBITS,      "Character Subtype Bits" },
    { DRDA_CP_CSTSBCS,      "Character Subtype SBCS" },
    { DRDA_CP_CSTMBCS,      "Character Subtype MBCS" },
    { DRDA_CP_ISOLVLCHG,    "Isolation Level Change" },
    { DRDA_CP_ISOLVLCS,     "Isolation Level Cursor Stability" },
    { DRDA_CP_ISOLVLALL,    "Isolation Level All" },
    { DRDA_CP_ISOLVLRR,     "Isolation Level Repeatable Read" },
    { DRDA_CP_ISOLVLNC,     "Isolation Level No Commit" },
    { DRDA_CP_SRVLST,       "Server List" },
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
    { DRDA_CP_RLSCONV,      "RLSCONV" },
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
    { DRDA_CP_SNDPKT,       "SNDPKT" },
    { DRDA_CP_MONITOR,      "MONITOR" },
    { DRDA_CP_ETIME,        "ETIME" },
    { DRDA_CP_RESPKTSZ,     "RESPKTSZ" },
    { DRDA_CP_CCSIDXML,     "CCSIDXML" },
    { DRDA_CP_MONITORRD,    "MONITORRD" },
    { DRDA_CP_XAMGR,        "XAMGR" },
    { DRDA_CP_PKTOBJ,       "PKTOBJ" },
    { DRDA_CP_UNICODEMGR,   "UNICODEMGR" },
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
    { DRDA_CP_PKGNAM,       "PKGNAM" },
    { DRDA_CP_PKGSN,        "PKGSN" },
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
    { DRDA_CP_QRYEXTDTASZ,  "QRYEXTDTASZ" },
    { DRDA_CP_CRRTKN,       "CRRTKN" },
    { DRDA_CP_SMLDTASZ,     "SMLDTASZ" },
    { DRDA_CP_MEDDTASZ,     "MEDDTASZ" },
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
    { DRDA_CP_DYNDTAFMT,    "DYNDTAFMT" },
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
    { DRDA_CP_QRYBLKFCT,    "QRYBLKFCT" },
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
    { DRDA_CP_CSTSYSDFT,    "CSTSYSDFT" },
    { DRDA_CP_CSTBITS,      "CSTBITS" },
    { DRDA_CP_CSTSBCS,      "CSTSBCS" },
    { DRDA_CP_CSTMBCS,      "CSTMBCS" },
    { DRDA_CP_ISOLVLCHG,    "ISOLVLCHG" },
    { DRDA_CP_ISOLVLCS,     "ISOLVLCS" },
    { DRDA_CP_ISOLVLALL,    "ISOLVLALL" },
    { DRDA_CP_ISOLVLRR,     "ISOLVLRR" },
    { DRDA_CP_ISOLVLNC,     "ISOLVLNC" },
    { DRDA_CP_SRVLST,       "SRVLST" },
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

static const value_string drda_boolean_vals[] = {
    { 0xF0, "FALSE" }, /* \xf0 - EBCDIC '0' */
    { 0xF1, "TRUE" },  /* \xf1 - EBCDIC '1' */
    { 0, NULL }
};

static const value_string drda_max_vals[] =
{
    { -1, "Unlimited"},
    {  0, NULL }
};

static const range_string drda_null_ind_rvals[] =
{
    { 0x00, 0x00, "Complete data value follows" },
    { 0x01, 0x7F, "Truncation has occurred (should not occur in DRDA)" },
    { 0x80, 0xFD, "Reserved; no data value follows" },
    { 0xFE, 0xFE, "Undefined result; no data value follows" },
    { 0xFF, 0xFF, "NULL; no data value follows" },
    { 0, 0, NULL },
};

typedef struct _drda_encoding_t {
    enum_typdefnam_t typdefnam;
    unsigned sbc;
    unsigned mbc;
} drda_encoding_t;

typedef struct _drda_flow_t {
    wmem_tree_t* encoding_tree;
    wmem_tree_t* sqlam_tree;
} drda_flow_t;

typedef struct _drda_conv_info_t {
    drda_flow_t *client; /* AKA source system */
    drda_flow_t *server; /* AKA target system */

    address srv_addr;
    port_type srv_ptype;
    unsigned srv_port;
} drda_conv_info_t;

typedef struct _drda_pdu_info_t {
    unsigned sqlam;
    enum_typdefnam_t typdefnam;
    unsigned sbc;
    unsigned mbc;
} drda_pdu_info_t;

static drda_flow_t*
drda_new_flow(wmem_allocator_t *alloc, packet_info *pinfo)
{
    drda_flow_t *new_flow = wmem_new(alloc, drda_flow_t);

    new_flow->encoding_tree = wmem_tree_new(alloc);
    new_flow->sqlam_tree = wmem_tree_new(alloc);
    wmem_tree_insert32(new_flow->sqlam_tree, pinfo->num, GUINT_TO_POINTER(drda_default_sqlam));

    return new_flow;
}

static void
drda_update_flow_encoding(packet_info *pinfo, drda_flow_t *flow, const drda_pdu_info_t *pdu_info)
{
    drda_encoding_t *encoding = wmem_tree_lookup32_le(flow->encoding_tree, pinfo->num);
    if (encoding) {
        if (encoding->typdefnam == pdu_info->typdefnam && encoding->sbc == pdu_info->sbc && encoding->mbc == pdu_info->mbc) {
            return;
        }
    }
    encoding = wmem_new(wmem_file_scope(), drda_encoding_t);
    encoding->mbc = pdu_info->mbc;
    encoding->sbc = pdu_info->sbc;
    encoding->typdefnam = pdu_info->typdefnam;
    wmem_tree_insert32(flow->encoding_tree, pinfo->num, encoding);
}

static drda_conv_info_t*
drda_get_conv_info(packet_info *pinfo)
{
    conversation_t *conv = find_or_create_conversation(pinfo);
    drda_conv_info_t *conv_info = conversation_get_proto_data(conv, proto_drda);

    if (conv_info == NULL) {
        conv_info = wmem_new0(wmem_file_scope(), drda_conv_info_t);

        conv_info->client = drda_new_flow(wmem_file_scope(), pinfo);
        conv_info->server = drda_new_flow(wmem_file_scope(), pinfo);

        conversation_add_proto_data(conv, proto_drda, conv_info);
    }
    return conv_info;
}

static drda_pdu_info_t*
drda_get_pdu_info(packet_info *pinfo, uint32_t correl, bool is_server)
{
    drda_pdu_info_t *pdu_info;

    /* "When the TYPDEFNAM object is specified as a command/reply data object,
     * the value specified applies to the following command data objects and
     * reply data objects for that command, respectively. When TYPDEFNAM is
     * repeatable, the value of one TYPDEFNAM object is applicable only to
     * those objects (command data or reply data) that are sent before another
     * TYPDEFNAM object is sent. The value of TYPDEFNAM that a command
     * specifies is in effect only for that command. This rule applies to all
     * commands, unless specified otherwise." Similar for TYPDEFOVR.
     *
     * This means that encoding values are initialized to those set for the
     * given direction for entire conversation by ACCRDB[RM] for each
     * frame, or for each time the correlation ID changes (representing
     * a different command; shared correlation IDs in a frame (after
     * desegmentation, if needed) are data objects for the same command.)
     */
    pdu_info = p_get_proto_data(pinfo->pool, pinfo, proto_drda, correl);

    if (!pdu_info) {
        pdu_info = wmem_new(pinfo->pool, drda_pdu_info_t);
        drda_conv_info_t *conv_info = drda_get_conv_info(pinfo);
        drda_flow_t *flow = is_server ? conv_info->server : conv_info->client;
        pdu_info->sqlam = GPOINTER_TO_UINT(wmem_tree_lookup32_le(flow->sqlam_tree, pinfo->num));
        drda_encoding_t *encoding = wmem_tree_lookup32_le(flow->encoding_tree, pinfo->num);
        if (encoding) {
            pdu_info->typdefnam = encoding->typdefnam;
            pdu_info->sbc = encoding->sbc;
            pdu_info->mbc = encoding->mbc;
        } else {
            pdu_info->typdefnam = drda_default_typdefnam;
            pdu_info->sbc = mibenum_charset_to_encoding((unsigned)drda_default_ccsidsbc);
            pdu_info->mbc = mibenum_charset_to_encoding((unsigned)drda_default_ccsidmbc);
        }

        p_set_proto_data(pinfo->pool, pinfo, proto_drda, correl, pdu_info);
    }


    return pdu_info;
}

static void
drda_set_server(drda_conv_info_t *conv_info, address *addr, port_type ptype, uint32_t port)
{
    copy_address_wmem(wmem_file_scope(), &conv_info->srv_addr, addr);
    conv_info->srv_ptype = ptype;
    conv_info->srv_port = port;
}

static bool
drda_packet_from_server(packet_info *pinfo, uint32_t command, uint8_t dsstyp)
{
    drda_conv_info_t *conv_info = drda_get_conv_info(pinfo);
    if (conv_info->srv_addr.type != AT_NONE) {
        return (conv_info->srv_ptype == pinfo->ptype) &&
               (conv_info->srv_port == pinfo->srcport) &&
               addresses_equal(&conv_info->srv_addr, &pinfo->src);
    }
    switch (command) {
    case DRDA_CP_EXCSAT:
    case DRDA_CP_ACCRDB:
        /* Client */
        drda_set_server(conv_info, &pinfo->dst, pinfo->ptype, pinfo->destport);
        return false;

    case DRDA_CP_EXCSATRD:
    case DRDA_CP_ACCRDBRM:
        /* Server (EXCSATRD is OBJDSS, which itself is inconclusive.) */
        drda_set_server(conv_info, &pinfo->src, pinfo->ptype, pinfo->srcport);
        return true;

    }
    /* The above commands are the ones that matter the most for determining
     * direction.
     */
    switch (dsstyp) {
    case DRDA_DSSFMT_RQSDSS:
    case DRDA_DSSFMT_NORPYDSS:
        drda_set_server(conv_info, &pinfo->dst, pinfo->ptype, pinfo->destport);
        return false;

    case DRDA_DSSFMT_RPYDSS:
        drda_set_server(conv_info, &pinfo->src, pinfo->ptype, pinfo->srcport);
        return true;

    default:
        /* We will be using the default values from the prefs anyway, since
         * this means we won't have received ACCRDB[RM] yet.
         */
        break;
    }

    return false;
}

static int
dissect_fdoca_integer(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset,int length, const drda_pdu_info_t *pdu_info, uint32_t *value)
{
    unsigned endian;
    switch (pdu_info->typdefnam) {
    case TYPDEFNAM_370:
    case TYPDEFNAM_400:
    case TYPDEFNAM_ASC:
        endian = ENC_BIG_ENDIAN;
        break;
    case TYPDEFNAM_X86:
    case TYPDEFNAM_VAX:
    default:
        endian = ENC_LITTLE_ENDIAN;
        break;
    }
    proto_tree_add_item_ret_int(tree, hf_index, tvb, offset, length, endian, value);
    return offset + length;
}

static int
dissect_fdoca_integer64(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset,int length, const drda_pdu_info_t *pdu_info, uint64_t *value)
{
    unsigned endian;
    switch (pdu_info->typdefnam) {
    case TYPDEFNAM_370:
    case TYPDEFNAM_400:
    case TYPDEFNAM_ASC:
        endian = ENC_BIG_ENDIAN;
        break;
    case TYPDEFNAM_X86:
    case TYPDEFNAM_VAX:
    default:
        endian = ENC_LITTLE_ENDIAN;
        break;
    }
    proto_tree_add_item_ret_int64(tree, hf_index, tvb, offset, length, endian, value);
    return offset + length;
}

static int
dissect_fdoca_fcs(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset, int length, const drda_pdu_info_t *pdu_info)
{
    proto_tree_add_item(tree, hf_index, tvb, offset, length, pdu_info->sbc);
    return offset + length;
}

static int
dissect_fdoca_vcs(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset, const drda_pdu_info_t *pdu_info)
{
    uint32_t item_len;
    proto_tree_add_item_ret_uint(tree, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &item_len);
    offset += 2;
    proto_tree_add_item(tree, hf_index, tvb, offset, item_len, pdu_info->sbc);
    return offset + (int)item_len;
}

static int
dissect_fdoca_vcm(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset, const drda_pdu_info_t *pdu_info)
{
    uint32_t item_len;
    proto_tree_add_item_ret_uint(tree, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &item_len);
    offset += 2;
    proto_tree_add_item(tree, hf_index, tvb, offset, item_len, pdu_info->mbc);
    return offset + (int)item_len;
}

static int
dissect_fdoca_nocs(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset, const drda_pdu_info_t *pdu_info)
{
    uint32_t null_ind, item_length;
    proto_tree_add_item_ret_uint(tree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        proto_tree_add_item_ret_uint(tree, hf_drda_clob_length, tvb, offset, 4, ENC_BIG_ENDIAN, &item_length);
        offset += 4;
        proto_tree_add_item(tree, hf_index, tvb, offset, item_length, pdu_info->sbc);
        offset += item_length;
    }
    return offset;
}

static int
dissect_fdoca_nocm(proto_tree *tree, int hf_index, tvbuff_t *tvb, int offset, const drda_pdu_info_t *pdu_info)
{
    uint32_t null_ind, item_length;
    proto_tree_add_item_ret_uint(tree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        proto_tree_add_item_ret_uint(tree, hf_drda_clob_length, tvb, offset, 4, ENC_BIG_ENDIAN, &item_length);
        offset += 4;
        proto_tree_add_item(tree, hf_index, tvb, offset, item_length, pdu_info->mbc);
        offset += item_length;
    }
    return offset;
}

static int
dissect_drda_typdefnam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;
    const uint8_t *typdefnam;

    proto_tree_add_item_ret_string(tree, hf_drda_typdefnam, tvb, 0, tvb_reported_length(tvb), ENC_UTF_8, pinfo->pool, &typdefnam);
    for (int i = 0; typdefnam_vals[i].name != NULL; i++) {
        if (strcmp(typdefnam_vals[i].name, typdefnam) == 0) {
            pdu_info->typdefnam = typdefnam_vals[i].value;
            break;
        }
    }
    proto_tree_add_item_ret_string(tree, hf_drda_typdefnam, tvb, 0, tvb_reported_length(tvb), ENC_EBCDIC_CP500, pinfo->pool, &typdefnam);
    for (int i = 0; typdefnam_vals[i].name != NULL; i++) {
        if (strcmp(typdefnam_vals[i].name, typdefnam) == 0) {
            pdu_info->typdefnam = typdefnam_vals[i].value;
            break;
        }
    }
    return tvb_reported_length(tvb);
}

static int
dissect_drda_sqlstt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;

    int offset = 0;

    uint32_t sqlstt_length;

    /* If SECMGR is Level 6 and higher, it's possible to select a SECMEC
     * that means that the security-sensitive DDM/FD:OCA objects are encrypted.
     * They are SQLDTA, SQLDTARD, SQLSTT, SQLDARD, SQLATTR, SQLCINRD,
     * SQLRSLRD, SQLSTTVRB, QRYDTA, EXTDTA, and SECTKNOVR.
     * XXX: We don't handle the encryption, and we don't handle looking at
     * the SECMEC to see if they are encrypted.
     */

    /* From the DRDA Specification Volume 1, 1.1 The DRDA Reference
     * (Version 4 and later):
     * Greater than 32,767 Byte SQL Statements
     * "Existing early descriptor character fields are mapped to a Variable
     * Character Mixed or a Variable Character SBCS which allow a maximum of
     * 32,767 bytes. SQL Statements described by the SQL Statement Group use
     * these character fields. To allow SQL Statements to extend beyond the 32K
     * limit, SQL statements are changed to map to nullable Large Character
     * Objects Mixed and nullable Large Character Objects SBCS to allow for
     * very large SQL Statements."
     *
     * In other words, it changed from a pair of non nullable LONG VARCHARs
     * to a pair of nullable CLOBs, meaning that each string gained a
     * null indicator byte and the length field grew from 2 to 4 bytes.
     *
     * This requires SQLAM Level 7 on both client & server, as sent in the
     * MGRLVLLS in the EXCSATRD.
     *
     * We can cheat a bit because we can tell which one it is by
     * inspection (assuming valid data), so we don't have to check
     * pdu_info->sqlam
     */

    sqlstt_length = tvb_get_ntohs(tvb, offset);
    if (sqlstt_length == 0) {
        sqlstt_length = tvb_get_ntohs(tvb, offset + 2);
    }
    if (sqlstt_length + 4 == tvb_reported_length(tvb)) {
        /* pdu_info->sqlam < 7 */
        offset = dissect_fdoca_vcm(tree, hf_drda_sqlstatement, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(tree, hf_drda_sqlstatement, tvb, offset, pdu_info);
    } else {
        offset = dissect_fdoca_nocm(tree, hf_drda_sqlstatement, tvb, offset, pdu_info);
        offset = dissect_fdoca_nocs(tree, hf_drda_sqlstatement, tvb, offset, pdu_info);
    }
    return offset;
}

static int
dissect_drda_sqldiaggrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    int offset = 0;

    uint32_t null_ind;

    ti = proto_tree_add_item(tree, hf_drda_sqldiaggrp, tvb, offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_drda_sqldiaggrp);
    proto_tree_add_item_ret_uint(subtree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        proto_tree_add_expert(subtree, pinfo, &ei_drda_undecoded, tvb, offset, 2);
    }
    proto_item_set_end(ti, tvb, offset);
    return offset;
}

static const value_string drda_udtxtype_vals[] = {

    { 0, "Not a UDT" },
    { 1, "Distinct type" },
    { 2, "Structured type" },
    { 3, "Reference type" },
    { 0, NULL },
};

static int
dissect_drda_sqludtgrp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *subtree;
    int offset = 0;

    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;
    uint32_t null_ind;

    ti = proto_tree_add_item(tree, hf_drda_sqludtgrp, tvb, offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_drda_sqludtgrp);
    proto_tree_add_item_ret_uint(subtree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        if (pdu_info->sqlam > 6) {
            offset = dissect_fdoca_integer(subtree, hf_drda_sqludtxtype, tvb, offset, 4, pdu_info, NULL);
            offset = dissect_fdoca_vcs(subtree, hf_drda_rdbnam, tvb, offset, pdu_info);
            offset = dissect_fdoca_vcm(subtree, hf_drda_sqludtschema, tvb, offset, pdu_info);
            offset = dissect_fdoca_vcs(subtree, hf_drda_sqludtschema, tvb, offset, pdu_info);
        }
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqludtname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqludtname, tvb, offset, pdu_info);
        if (pdu_info->sqlam >= 10) {
            offset = dissect_fdoca_vcm(subtree, hf_drda_sqludtmodule, tvb, offset, pdu_info);
            offset = dissect_fdoca_vcs(subtree, hf_drda_sqludtmodule, tvb, offset, pdu_info);
        }
    }
    proto_item_set_end(ti, tvb, offset);
    return offset;
}

static const value_string drda_keymem_vals[] = {
    { 0, "Not a member of the primary key or of a unique index" },
    { 1, "Member of the primary key or of a unique index" },
    { 0, NULL }
};

static const value_string drda_updateable_vals[] = {
    { 0, "Not updateable" },
    { 1, "Updateable" },
    { 0, NULL }
};

static const value_string drda_generated_vals[] = {
    { 0, "None of the other values of this field apply" },
    { 1, "Data for this column is always generated using an expression" },
    { 2, "Data for this identity column is always generated" },
    { 3, "Data for this ROWID column is always generated" },
    { 4, "Data for this identity column is generated by default" },
    { 5, "Data for this ROWID column is generated by default" },
    { 6, "Data for this row change timestamp column is always generated" },
    { 7, "Data for this row change timestamp column is generated by default" },
    { 0, NULL }
};

static const value_string drda_parmmode_vals[] = {
    { 0, "Not for use with a CALL statement" },
    { 1, "Input-only parameter" },
    { 2, "Input and output parameter" },
    { 4, "Output-only parameter" },
    { 0, NULL }
};

static const value_string drda_xoptlck_vals[] = {
    { 0, "Column not injected because of optimistic locking" },
    { 1, "Row change token column was injected because optimistic locking was requested" },
    { 2, "RID column was injected because optimistic locking was requested" },
    { 0, NULL }
};

static const value_string drda_hidden_vals[] = {
    { 0, "Not a hidden column" },
    { 1, "Hidden column" },
    { 0, NULL }
};

static int
dissect_drda_sqldxgrp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *subtree;
    int offset = 0;

    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;
    uint32_t null_ind;

    ti = proto_tree_add_item(tree, hf_drda_sqldxgrp, tvb, offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_drda_sqldxgrp);
    proto_tree_add_item_ret_uint(subtree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        offset = dissect_fdoca_integer(subtree, hf_drda_sqlxkeymem, tvb, offset, 2, pdu_info, NULL);
        offset = dissect_fdoca_integer(subtree, hf_drda_sqlxupdateable, tvb, offset, 2, pdu_info, NULL);
        offset = dissect_fdoca_integer(subtree, hf_drda_sqlxgenerated, tvb, offset, 2, pdu_info, NULL);
        offset = dissect_fdoca_integer(subtree, hf_drda_sqlxparmmode, tvb, offset, 2, pdu_info, NULL);
        if (pdu_info->sqlam >= 9) {
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlxoptlck, tvb, offset, 2, pdu_info, NULL);
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlxhidden, tvb, offset, 2, pdu_info, NULL);
        }
        offset = dissect_fdoca_vcs(subtree, hf_drda_rdbnam, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlxcorname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlxcorname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlxbasename, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlxbasename, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlxschema, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlxschema, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlxname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlxname, tvb, offset, pdu_info);
        if (pdu_info->sqlam >= 10) {
            offset = dissect_fdoca_vcm(subtree, hf_drda_sqlxmodule, tvb, offset, pdu_info);
            offset = dissect_fdoca_vcs(subtree, hf_drda_sqlxmodule, tvb, offset, pdu_info);
        }
    }
    proto_item_set_end(ti, tvb, offset);
    return offset;
}

/* Appendix D of C112. Note that some strings have multiple codes that
 * map to them.
 */
static const value_string drda_fcode_vals[] = {

    {  1, "ALLOCATE CURSOR" },
    {  2, "ALLOCATE DESCRIPTOR" },
    {  3, "ALTER DOMAIN" },
    {  4, "ALTER TABLE" },
    {  6, "CREATE ASSERTION" },
    {  7, "CALL" },
    {  8, "CREATE CHARACTER SET" },
    {  9, "CLOSE CURSOR" },
    { 11, "CREATE COLLATION" },
    { 12, "COMMIT WORK" },
    { 13, "CONNECT" },
    { 15, "DEALLOCATE DESCRIPTOR" },
    { 16, "DEALLOCATE PREPARE" },
    { 17, "ALTER ROUTINE" },
    { 18, "DELETE CURSOR" },
    { 19, "DELETE WHERE" },
    { 20, "DESCRIBE" },
    { 21, "SELECT" },
    { 22, "DISCONNECT" },
    { 23, "CREATE DOMAIN" },
    { 24, "DROP ASSERTION" },
    { 25, "DROP CHARACTER SET" },
    { 26, "DROP COLLATION" },
    { 27, "DROP DOMAIN" },
    { 29, "DROP ROLE" },
    { 30, "DROP ROUTINE" },
    { 31, "DROP SCHEMA" },
    { 32, "DROP TABLE" },
    { 33, "DROP TRANSLATION" },
    { 34, "DROP TRIGGER" },
    { 35, "DROP TYPE" },
    { 36, "DROP VIEW" },
    { 37, "DYNAMIC CLOSE" },
    { 38, "DYNAMIC DELETE CURSOR" },
    { 39, "DYNAMIC FETCH" },
    { 40, "DYNAMIC OPEN" },
    { 41, "SELECT" },
    { 42, "DYNAMIC UPDATE CURSOR" },
    { 43, "EXECUTE IMMEDIATE" },
    { 44, "EXECUTE" },
    { 45, "FETCH" },
    { 47, "GET DESCRIPTOR" },
    { 48, "GRANT" },
    { 49, "GRANT ROLE" },
    { 50, "INSERT" },
    { 53, "OPEN" },
    { 54, "DYNAMIC DELETE CURSOR" },
    { 55, "DYNAMIC UPDATE CURSOR" },
    { 56, "PREPARE" },
    { 57, "RELEASE SAVEPOINT" },
    { 58, "RETURN" },
    { 59, "REVOKE" },
    { 60, "ALTER TYPE" },
    { 66, "SET CATALOG" },
    { 69, "SET CURRENT_PATH" },
    { 70, "SET DESCRIPTOR" },
    { 72, "SET NAMES" },
    { 74, "SET SCHEMA" },
    { 85, "SELECT CURSOR" },
    { 98, "FREE LOCATOR" },
    { 99, "HOLD LOCATOR" },
    {101, "DECLARE CURSOR" },
    {115, "DROP ORDERING" },
    {116, "DROP TRANSFORM" },
    {118, "SET TRANSFORM GROUP" },
    { 0, NULL }
};

static const value_string drda_hold_vals[] = {

    { 0, "No cursor exists, or cursor defined without WITH HOLD clause" },
    { 1, "Cursor defined using WITH HOLD clause" },
    {-1, "Unknown if cursor was defined using WITH HOLD clause" },
    { 0, NULL }
};

static const value_string drda_return_vals[] = {

    { 0, "Statement is not a query" },
    { 1, "Cursor defined using the WITH RETURN CLIENT clause" },
    { 2, "Cursor defined using the WITH RETURN CALLER clause" },
    {-1, "Unknown if cursor is intended to be used as a result set that will be returned from a procedure" },
    { 0, NULL }
};

static const value_string drda_scroll_vals[] = {

    { 0, "No cursor exists, or not scrollable" },
    { 1, "Cursor defined using SCROLL clause" },
    {-1, "Cursor exists, but scrollability unknown" },
    { 0, NULL }
};

static const value_string drda_sensitive_vals[] = {

    { 0, "No cursor exists" },
    { 1, "Cursor defined as SENSITIVE DYNAMIC" },
    { 2, "Cursor defined as SENSITIVE STATIC" },
    { 3, "Cursor defined as INSENSITIVE" },
    { 4, "Cursor defined with PARTIAL SENSITIVITY and STATIC size and ordering" },
    { 5, "Cursor defined with PARTIAL SENSITIVITY and DYNAMIC size and ordering" },
    {-1, "Cursor exists, but sensitivity unknown" },
    { 0, NULL }
};

static const value_string drda_keytype_vals[] = {

    { 0, "Statement is not a query, or no columns are members of a key" },
    { 1, "Select list includes all columns of the primary key of the base table referenced by the query" },
    { 2, "Table reference by the query does not have a primary key, but the select list includes a set of columns that are defined as the preferred candidate key" },
    { 0, NULL }
};

static const value_string drda_doptlck_vals[] = {

    { 0, "Optimistic locking columns not injected" },
    { 1, "Optimistic locking columns injected, but might not have the granularity to guarantee no false negatives" },
    { 2, "Optimistic locking columns injected, guaranteeing no false negatives" },
    { 0, NULL }
};

static int
dissect_drda_sqldhgrp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *sqldhgrp_ti;
    proto_tree *sqldhgrp_tree;
    int offset = 0, len;

    uint32_t null_ind;

    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;

    sqldhgrp_ti = proto_tree_add_item(tree, hf_drda_sqldhgrp, tvb, offset, 1, ENC_NA);
    sqldhgrp_tree = proto_item_add_subtree(sqldhgrp_ti, ett_drda_sqldhgrp);
    proto_tree_add_item_ret_uint(sqldhgrp_tree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        len = 2;
        offset = dissect_fdoca_integer(sqldhgrp_tree, hf_drda_sqldhold, tvb, offset, len, pdu_info, NULL);
        offset = dissect_fdoca_integer(sqldhgrp_tree, hf_drda_sqldreturn, tvb, offset, len, pdu_info, NULL);
        offset = dissect_fdoca_integer(sqldhgrp_tree, hf_drda_sqldscroll, tvb, offset, len, pdu_info, NULL);
        offset = dissect_fdoca_integer(sqldhgrp_tree, hf_drda_sqldsensitive, tvb, offset, len, pdu_info, NULL);
        offset = dissect_fdoca_integer(sqldhgrp_tree, hf_drda_sqldfcode, tvb, offset, len, pdu_info, NULL);
        offset = dissect_fdoca_integer(sqldhgrp_tree, hf_drda_sqldkeytype, tvb, offset, len, pdu_info, NULL);
        if (pdu_info->sqlam >= 9) {
            offset = dissect_fdoca_integer(sqldhgrp_tree, hf_drda_sqldoptlck, tvb, offset, len, pdu_info, NULL);
        }
        offset = dissect_fdoca_vcs(sqldhgrp_tree, hf_drda_rdbnam, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(sqldhgrp_tree, hf_drda_sqldschema, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(sqldhgrp_tree, hf_drda_sqldschema, tvb, offset, pdu_info);
        if (pdu_info->sqlam >= 10) {
            offset = dissect_fdoca_vcm(sqldhgrp_tree, hf_drda_sqldmodule, tvb, offset, pdu_info);
            offset = dissect_fdoca_vcs(sqldhgrp_tree, hf_drda_sqldmodule, tvb, offset, pdu_info);
        }
    }
    proto_item_set_end(sqldhgrp_ti, tvb, offset);

    return offset;
}

static const value_string drda_unnamed_vals[] = {

    { 0, "Column name not generated by the RDB" },
    { 1, "Column name generated by the RDB" },
    { 0, NULL }
};

static int
dissect_drda_sqldoptgrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *sqldoptgrp_ti, *expert_ti;
    proto_tree *subtree;
    int offset = 0;

    uint32_t null_ind;

    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;

    sqldoptgrp_ti = proto_tree_add_item(tree, hf_drda_sqldoptgrp, tvb, offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(sqldoptgrp_ti, ett_drda_sqldoptgrp);
    proto_tree_add_item_ret_uint(subtree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        offset = dissect_fdoca_integer(subtree, hf_drda_sqlunnamed, tvb, offset, 2, pdu_info, NULL);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqllabel, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqllabel, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlcomments, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlcomments, tvb, offset, pdu_info);

        offset += dissect_drda_sqludtgrp(tvb_new_subset_remaining(tvb, offset), pinfo, subtree, data);
        offset += dissect_drda_sqldxgrp(tvb_new_subset_remaining(tvb, offset), pinfo, subtree, data);
        if (pdu_info->sqlam >= 10) {
            expert_ti = proto_tree_add_item_ret_uint(subtree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
            offset++;
            if ((int8_t)null_ind >= 0) {
                expert_add_info(pinfo, expert_ti, &ei_drda_undecoded);
                /* XXX: What is this? It's not in Version 5 of the spec. */
            }
        }
    }
    proto_item_set_end(sqldoptgrp_ti, tvb, offset);
    return offset;
}

static const value_string drda_sqltype_vals[] = {

    { 384, "DATE" },
    { 385, "DATE (NULLABLE)" },
    { 388, "TIME" },
    { 389, "TIME (NULLABLE)" },
    { 392, "TIMESTAMP" },
    { 393, "TIMESTAMP (NULLABLE)" },
    { 396, "DATALINK" },
    { 397, "DATALINK (NULLABLE)" },
    { 404, "BLOB" },
    { 405, "BLOB (NULLABLE)" },
    { 408, "CLOB" },
    { 409, "CLOB (NULLABLE)" },
    { 412, "DBCLOB" },
    { 413, "DBCLOB (NULLABLE)" },
    { 448, "VARCHAR" },
    { 449, "VARCHAR (NULLABLE)" },
    { 452, "CHAR" },
    { 453, "CHAR (NULLABLE)" },
    { 456, "LONG VARCHAR" },
    { 457, "LONG VARCHAR (NULLABLE)" },
    { 460, "NULL-TERMINATED CHAR" },
    { 461, "NULL-TERMINATED CHAR (NULLABLE)" },
    { 464, "VARGRAPHIC" },
    { 465, "VARGRAPHIC (NULLABLE)" },
    { 468, "GRAPHIC" },
    { 469, "GRAPHIC (NULLABLE)" },
    { 472, "LONG VARGRAPHIC" },
    { 473, "LONG VARGRAPHIC (NULLABLE)" },
    { 476, "PASCAL L STRING" },
    { 477, "PASCAL L STRING (NULLABLE)" },
    { 480, "FLOAT" },
    { 481, "FLOAT (NULLABLE)" },
    { 484, "FIXED DECIMAL" },
    { 485, "FIXED DECIMAL (NULLABLE)" },
    { 488, "ZONED DECIMAL" },
    { 489, "ZONED DECIMAL (NULLABLE)" },
    { 492, "BIGINT" },
    { 493, "BIGINT (NULLABLE)" },
    { 496, "INTEGER" },
    { 497, "INTEGER (NULLABLE)" },
    { 500, "SMALLINT" },
    { 501, "SMALLINT (NULLABLE)" },
    { 504, "NUMERIC CHAR" },
    { 505, "NUMERIC CHAR (NULLABLE)" },
    { 904, "ROWID" },
    { 905, "ROWID (NULLABLE)" },
    { 908, "VARBINARY" },
    { 909, "VARBINARY (NULLABLE)" },
    { 912, "BINARY" },
    { 913, "BINARY (NULLABLE)" },
    { 960, "BLOB LOCATOR" },
    { 961, "BLOB LOCATOR (NULLABLE)" },
    { 964, "CLOB LOCATOR" },
    { 965, "CLOB LOCATOR (NULLABLE)" },
    { 968, "DBCLOB LOCATOR" },
    { 969, "DBCLOB LOCATOR (NULLABLE)" },
    { 972, "RESULT SET LOCATOR" },
    { 973, "RESULT SET LOCATOR (NULLABLE)" },
    { 988, "XML" },
    { 989, "XML (NULLABLE)" },
    { 996, "DECFLOAT" },
    { 997, "DECFLOAT (NULLABLE)" },
    {2436, "BOOLEAN" },
    {2437, "BOOLEAN (NULLABLE)" },
    {2444, "CURSOR TYPE" },
    {2445, "CURSOR TYPE (NULLABLE)" },
    {2448, "TIMESTAMP WITH TIME ZONE" },
    {2449, "TIMESTAMP WITH TIME ZONE (NULLABLE)" },
    { 0, NULL }
};

static int
dissect_drda_sqldagrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *sqldagrp_ti;
    proto_tree *subtree;
    int offset = 0;

    //uint32_t null_ind;

    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;

    sqldagrp_ti = proto_tree_add_item(tree, hf_drda_sqldagrp, tvb, offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(sqldagrp_ti, ett_drda_sqldagrp);

    offset = dissect_fdoca_integer(subtree, hf_drda_sqlprecision, tvb, offset, 2, pdu_info, NULL);
    offset = dissect_fdoca_integer(subtree, hf_drda_sqlscale, tvb, offset, 2, pdu_info, NULL);
    if (pdu_info->sqlam >= 6) {
        offset = dissect_fdoca_integer64(subtree, hf_drda_sqllength, tvb, offset, 8, pdu_info, NULL);
    } else {
        offset = dissect_fdoca_integer(subtree, hf_drda_sqllength32, tvb, offset, 4, pdu_info, NULL);
    }
    offset = dissect_fdoca_integer(subtree, hf_drda_sqltype, tvb, offset, 2, pdu_info, NULL);
    proto_tree_add_item(subtree, hf_drda_ccsid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (pdu_info->sqlam >= 9) {
        offset = dissect_fdoca_integer64(subtree, hf_drda_sqlarrextent, tvb, offset, 8, pdu_info, NULL);

        if (pdu_info->sqlam >= 10) {
            proto_tree_add_expert(subtree, pinfo, &ei_drda_undecoded, tvb, offset, 2);
            /* XXX: What is this? It's not in Version 5 of the spec. */
            offset += 2;
        }
    }

    if (pdu_info->sqlam >= 7) {
        offset += dissect_drda_sqldoptgrp(tvb_new_subset_remaining(tvb, offset), pinfo, subtree, data);
    } else {
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlname, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqllabel, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqllabel, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcm(subtree, hf_drda_sqlcomments, tvb, offset, pdu_info);
        offset = dissect_fdoca_vcs(subtree, hf_drda_sqlcomments, tvb, offset, pdu_info);
        if (pdu_info->sqlam == 6) {
            offset += dissect_drda_sqludtgrp(tvb_new_subset_remaining(tvb, offset), pinfo, subtree, data);
        }
    }
    proto_item_set_end(sqldagrp_ti, tvb, offset);
    return offset;
}

static int
dissect_drda_sqlcard(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* For a description of these fields (at least on DB2), see:
     *  https://www.ibm.com/docs/en/db2-for-zos/12?topic=sqlca-description-fields
     */

    proto_item *ti, *sqlcard_ti;
    proto_tree *subtree, *sqlcard_tree;
    int offset = 0, len = 4;

    uint32_t null_ind, length;

    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;

    sqlcard_ti = proto_tree_add_item(tree, hf_drda_sqlcagrp, tvb, offset, 1, ENC_NA);
    sqlcard_tree = proto_item_add_subtree(sqlcard_ti, ett_drda_sqlcagrp);
    proto_tree_add_item_ret_uint(sqlcard_tree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
    offset++;
    if ((int8_t)null_ind >= 0) {
        len = 4;
        offset = dissect_fdoca_integer(sqlcard_tree, hf_drda_sqlcode, tvb, offset, len, pdu_info, NULL);
        len = 5;
        offset = dissect_fdoca_fcs(sqlcard_tree, hf_drda_sqlstate, tvb, offset, len, pdu_info);
        len = 8;
        offset = dissect_fdoca_fcs(sqlcard_tree, hf_drda_sqlerrproc, tvb, offset, len, pdu_info);

        /* SQLCAXGRP (nullable) */
        proto_tree_add_item_ret_uint(sqlcard_tree, hf_drda_null_ind, tvb, offset, 1, ENC_NA, &null_ind);
        offset++;
        if ((int8_t)null_ind >= 0) {
            ti = proto_tree_add_item(sqlcard_tree, hf_drda_sqlcaxgrp, tvb, offset, 35, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_drda_sqlcaxgrp);
            /* Earlier than SQLAM Level 7, the RDBName follows here, and is
             * a fixed string field of length 18. At SQLAM Level 7 and
             * higher, the SQLRDBNAME is a variable character field and
             * comes later, after the SQLWARN fields.
             */
            if (pdu_info->sqlam < 7) {
                offset = dissect_fdoca_fcs(subtree, hf_drda_rdbnam, tvb, offset, 18, pdu_info);
            }
            len = 4;
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlerrd1, tvb, offset, len, pdu_info, NULL);
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlerrd2, tvb, offset, len, pdu_info, NULL);
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlerrd3, tvb, offset, len, pdu_info, NULL);
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlerrd4, tvb, offset, len, pdu_info, NULL);
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlerrd5, tvb, offset, len, pdu_info, NULL);
            offset = dissect_fdoca_integer(subtree, hf_drda_sqlerrd6, tvb, offset, len, pdu_info, NULL);
            len = 1;
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn0, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn1, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn2, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn3, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn4, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn5, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn6, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn7, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn8, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarn9, tvb, offset, len, pdu_info);
            offset = dissect_fdoca_fcs(subtree, hf_drda_sqlwarna, tvb, offset, len, pdu_info);
            if (pdu_info->sqlam >= 7) {
                offset = dissect_fdoca_vcs(subtree, hf_drda_rdbnam, tvb, offset, pdu_info);
            }
            /* SQLERRMSG_m, a variable character string using the mixed
             * character CCSID. On DB2, contains one or more tokens,
             * separated by X'FF', that are substituted for variables
             * in the descriptions of error conditions.
             */
            proto_tree_add_item_ret_uint(subtree, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
            offset += 2;
            int end_offset;
            while ((end_offset = tvb_find_guint8(tvb, offset, length, 0xFF)) != -1) {
                proto_tree_add_item(subtree, hf_drda_sqlerrmsg, tvb, offset, end_offset - offset, pdu_info->mbc);
                length -= (end_offset + 1 - offset);
                offset = end_offset + 1;
            }
            proto_tree_add_item(subtree, hf_drda_sqlerrmsg, tvb, offset, length, pdu_info->mbc);
            offset += length;

            /* SQLERRMSG_s - same but using the single byte CCSID. Only one
             * of these should have nonzero length.
             */
            proto_tree_add_item_ret_uint(subtree, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
            offset += 2;
            while ((end_offset = tvb_find_guint8(tvb, offset, length, 0xFF)) != -1) {
                proto_tree_add_item(subtree, hf_drda_sqlerrmsg, tvb, offset, end_offset - offset, pdu_info->sbc);
                length -= (end_offset + 1 - offset);
                offset = end_offset + 1;
            }
            proto_tree_add_item(subtree, hf_drda_sqlerrmsg, tvb, offset, length, pdu_info->sbc);
            offset += length;
            proto_item_set_end(ti, tvb, offset);
        }

        if (pdu_info->sqlam >= 7) {
            offset += dissect_drda_sqldiaggrp(tvb_new_subset_remaining(tvb, offset), pinfo, sqlcard_tree, data);
        }
    } else {
        /* DRDA, Version 4, Volume 1: 5.6.4.6 SQLCAGRP:
         * "A null SQLCA indicates everything is fine: SQLSTATE='00000'"
         */
        ti = proto_tree_add_int(sqlcard_tree, hf_drda_sqlcode, tvb, offset, 0, 0);
        proto_item_set_generated(ti);
        ti = proto_tree_add_string(sqlcard_tree, hf_drda_sqlstate, tvb, offset, 0, "00000");
        proto_item_set_generated(ti);
    }
    proto_item_set_end(sqlcard_ti, tvb, offset);

    return offset;
}

static int
dissect_drda_sqldard(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    int offset = 0;
    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;

    uint32_t numrows;

    offset = dissect_drda_sqlcard(tvb, pinfo, tree, data);

    if (pdu_info->sqlam >= 7) {
        offset += dissect_drda_sqldhgrp(tvb_new_subset_remaining(tvb, offset), pinfo, tree, data);
    }
    offset = dissect_fdoca_integer(tree, hf_drda_sqlnum, tvb, offset, 2, pdu_info, &numrows);
    for (uint32_t i = 0; i < numrows; ++i) {
        offset += dissect_drda_sqldagrp(tvb_new_subset_remaining(tvb, offset), pinfo, tree, data);
    }
    return offset;
}

static int
dissect_drda_undecoded(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_drda_undecoded, tvb, 0, -1);
    return tvb_captured_length(tvb);
}

static const value_string drda_rlsconv_vals[] = {
    { 0xF0, "NO" }, /* EBCDIC '0' */
    { 0xF1, "TERMINATE" },  /* EBCDIC '1' */
    { 0xF2, "REUSE" },  /* EBCDIC '2' */
    { 0xF3, "NO_KDO - Presence of keep dynamic sections" },  /* EBCDIC '3' */
    { 0, NULL }
};

static int
dissect_drda_rlsconv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_rlsconv, tvb, 0, 1, ENC_NA);
    return 1;
}

static const value_string drda_secmec_vals[] = {
    { 1, "DCESEC - Distributed Computing Environment" },
    { 3, "USRIDPWD - User ID and Password" },
    { 4, "UDRIDONL - User ID Only" },
    { 5, "USRIDNWPWD - User ID, Password, and New Password" },
    { 6, "USRSBSPWD - User ID with Substitute Password" },
    { 7, "USRENCPWD - User ID with Encrypted Password" },
    { 8, "USRSSBPWD - User ID with Strong Password Substitute" },
    { 9, "EUSRIDPWD - Encrypted User ID and Password" },
    {10, "EUSRIDNWPWD - Encrypted User ID, Password, New Password" },
    {11, "KERSEC - Kerberos Security" },
    {12, "EUSRIDDTA - Encrypted User ID and Security-Sensitive Data" },
    {13, "EUSRPWDDTA - Encrypted User ID, Password, and Security-Sensitive Data" },
    {14, "EUSRNPWDDTA - Encrypted User ID, Password, New Password, and Security-Sensitive Data" },
    {15, "PLGIN - Plug-in Security" },
    {16, "EUSRIDONL - Encrypted User ID Only" },
    { 0, NULL }
};

static int
dissect_drda_secmec(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* REPEATABLE */
    int offset = 0;
    while (tvb_reported_length_remaining(tvb, offset) >= 2) {
        proto_tree_add_item(tree, hf_drda_secmec, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    return offset;
}

static const value_string drda_svrcod_vals[] = {
    {  0, "INFO - Information Only" },
    {  4, "WARNING - Warning" },
    {  8, "ERROR - Error" },
    { 16, "SEVERE - Severe Error" },
    { 32, "ACCDMG - Access Damage" },
    { 64, "PRMDMG - Permanent Damage" },
    {128, "SESDMG - Session Damage" },
    { 0, NULL }
};

static int
dissect_drda_sectkn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_sectkn, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    return tvb_reported_length(tvb);
}

static int
dissect_drda_svrcod(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_svrcod, tvb, 0, 2, ENC_BIG_ENDIAN);
    return 2;
}

static const value_string drda_secchkcd_vals[] = {
    {0x00, "The security information is correct and acceptable." },
    {0x01, "SECMEC value not supported." },
    {0x02, "DCE information status issued." },
    {0x03, "DCE retryable error." },
    {0x04, "DCE non-retryable error." },
    {0x05, "GSSAPI informational status issued." },
    {0x06, "GSSAPI retryable error." },
    {0x07, "GSSAPI non-retryable error." },
    {0x08, "Local Security Service informational status issued." },
    {0x09, "Local Security Service retryable error." },
    {0x0A, "Local Security Service non-retryable error." },
    {0x0B, "SECTKN missing when it is required or it is invalid." },
    {0x0E, "Password expired." },
    {0x0F, "Password invalid." },
    {0x10, "Password missing." },
    {0x12, "User ID missing." },
    {0x13, "User ID invalid." },
    {0x14, "User ID revoked." },
    {0x15, "New Password invalid." },
    {0x16, "Authentication failed because of connectivity restrictions enforced by the security plug-in." },
    {0x17, "Invalid GSS-API server credential." },
    {0x18, "GSS-API server credential expired on the database server." },
    {0x19, "Continue - require more security context information for authentication." },
    { 0, NULL }
};

static int
dissect_drda_secchkcd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_secchkcd, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

/* A few common CCSIDs, many more are at:
 * https://www.ibm.com/docs/en/i/7.3?topic=information-ccsid-values-defined-i
 * https://web.archive.org/web/20160304082631/http://www-01.ibm.com/software/globalization/g11n-res.html
 */
static const value_string drda_ccsid_vals[] = {
    {    0, "Use default value" },
    {   37, "IBM037" }, /* EBCDIC US Latin-1 */
    {  367, "US-ASCII" },
    {  500, "IBM500" }, /* EBCDIC International Latin-1 */
    {  819, "ISO-8859-1" },
    {  850, "IBM850" }, /* DOS Latin-1 */
    { 1200, "UTF-16" }, /* UTF-16BE; UTF-16LE is 1202 */
    { 1202, "UTF-16LE" },
    { 1208, "UTF-8" },
    { 65535, "Requested CCSID unsupported" },
    { 0, NULL }
};

static unsigned
ccsid_to_encoding(uint32_t ccsid)
{
    switch (ccsid) {

    case 0:
    case 500:
    case 65535:
        return ENC_EBCDIC_CP500;
    case 37:
        return ENC_EBCDIC_CP037;
    case 367:
        return ENC_ASCII;
    case 819:
        return ENC_ISO_8859_1;
    case 850:
        return ENC_ASCII; /* XXX: CP 850 not yet supported; CP 437 is closer, but ASCII safer */
    case 1200:
        return ENC_UTF_16|ENC_BIG_ENDIAN;
    case 1202:
        return ENC_UTF_16|ENC_LITTLE_ENDIAN;
    case 1208:
        return ENC_UTF_8;
    default:
        return ENC_UTF_8;
    }
}

static int
dissect_drda_ccsid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;
    uint32_t ccsid;

    proto_tree_add_item_ret_uint(tree, hf_drda_ccsid, tvb, 0, 2, ENC_BIG_ENDIAN, &ccsid);
    switch (pinfo->match_uint) {
    case DRDA_CP_CCSIDSBC:
        pdu_info->sbc = ccsid_to_encoding(ccsid);
        break;
    case DRDA_CP_CCSIDMBC:
        pdu_info->mbc = ccsid_to_encoding(ccsid);
        break;
    default:
        break;
    }
    return 2;
}

static int
dissect_drda_monitor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static int * const monitor_fields[] = {
        &hf_drda_monitor_etime,
        &hf_drda_monitor_reserved,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, 0, hf_drda_monitor, ett_drda_monitor,
        monitor_fields, ENC_BIG_ENDIAN);
    return 4;
}

static int
dissect_drda_etime(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_etime, tvb, 0, 8, ENC_TIME_USECS);
    return 8;
}

static int
dissect_drda_respktsz(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_respktsz, tvb, 0, 4, ENC_BIG_ENDIAN);
    return 4;
}

static int
dissect_drda_rdbinttkn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* The contents of the token are unarchitected and can differe for each
     * target SQLAM.
     */
    proto_tree_add_item(tree, hf_drda_rdbinttkn, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    return tvb_reported_length(tvb);
}

static int
dissect_drda_rdbcmtok(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_rdbcmtok, tvb, 0, 1, ENC_NA);
    return 1;
}

static int
dissect_drda_pkgnam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti_length;
    int offset = 0;
    uint32_t length;

    /* The PKGNAMCSN can have one of the following two formats depending on the
     * length of the RDBNAM, RDBCOLID, and PKGID contained therein:
     * * RDBNAM, RDBCOLID, and PKGID all have a length of 18.
     *   [Possibly right padded with blank spaces.]
     *   This format of the PKGNAMCSN is identical to the sole format used prior
     *   to DDM Level 7 where the length is fixed at 58. The use of the SCLDTALEN
     *   is disallowed with this format.
     * * At least one of RDBNAM, RDBCOLID, and PKGID has a length > 18.
     *   This format of the PKGNAMCSN mandates the SCLDTALEN to precede each of
     *   the RDBNAM, RDBCOLID, and PKGID. With this format, the PKGNAMCSN has a
     *   minimum length of 65 and a maximum length of 775.
     */
    if (tvb_reported_length(tvb) == 54) {
        /* 58 - 4 bytes for the code point and length already removed. */
        proto_tree_add_item(tree, hf_drda_rdbnam, tvb, offset, 18, ENC_UTF_8);
        proto_tree_add_item(tree, hf_drda_rdbnam_ebcdic, tvb, offset, 18, ENC_EBCDIC_CP500);
        offset += 18;
        proto_tree_add_item(tree, hf_drda_rdbcolid, tvb, offset, 18, ENC_UTF_8);
        proto_tree_add_item(tree, hf_drda_rdbcolid_ebcdic, tvb, offset, 18, ENC_EBCDIC_CP500);
        offset += 18;
        proto_tree_add_item(tree, hf_drda_pkgid, tvb, offset, 18, ENC_UTF_8);
        proto_tree_add_item(tree, hf_drda_pkgid_ebcdic, tvb, offset, 18, ENC_EBCDIC_CP500);
        offset += 18;
    } else if (tvb_reported_length(tvb) > 64) {
        ti_length = proto_tree_add_item_ret_uint(tree, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
        if (length < 18 || length > 255) {
            expert_add_info_format(pinfo, ti_length, &ei_drda_opcode_invalid_length, "Invalid length detected (%u): should be 18-255 bytes long", length);
        }
        offset += 2;
        proto_tree_add_item(tree, hf_drda_rdbnam, tvb, offset, length, ENC_UTF_8);
        proto_tree_add_item(tree, hf_drda_rdbnam_ebcdic, tvb, offset, length, ENC_EBCDIC_CP500);
        offset += length;
        ti_length = proto_tree_add_item_ret_uint(tree, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
        if (length < 18 || length > 255) {
            expert_add_info_format(pinfo, ti_length, &ei_drda_opcode_invalid_length, "Invalid length detected (%u): should be 18-255 bytes long", length);
        }
        offset += 2;
        proto_tree_add_item(tree, hf_drda_rdbcolid, tvb, offset, length, ENC_UTF_8);
        proto_tree_add_item(tree, hf_drda_rdbcolid_ebcdic, tvb, offset, length, ENC_EBCDIC_CP500);
        offset += length;
        ti_length = proto_tree_add_item_ret_uint(tree, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
        if (length < 18 || length > 255) {
            expert_add_info_format(pinfo, ti_length, &ei_drda_opcode_invalid_length, "Invalid length detected (%u): should be 18-255 bytes long", length);
        }
        offset += 2;
        proto_tree_add_item(tree, hf_drda_pkgid, tvb, offset, length, ENC_UTF_8);
        proto_tree_add_item(tree, hf_drda_pkgid_ebcdic, tvb, offset, length, ENC_EBCDIC_CP500);
        offset += length;
    } else {
        proto_tree_add_expert_format(tree, pinfo, &ei_drda_opcode_invalid_length, tvb, 0, tvb_reported_length(tvb), "Invalid length; RDBNAM, RDBCOLID, and PKGID should all be length 18 or larger.");
    }

    return offset;
}

static int
dissect_drda_rtnsetstt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_rtnsetstt, tvb, 0, 1, ENC_NA);
    return 1;
}

static int
dissect_drda_outexp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_outexp, tvb, 0, 1, ENC_NA);
    return 1;
}

static int
dissect_drda_pkgnamct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset;

    offset = dissect_drda_pkgnam(tvb_new_subset_length(tvb, 0, tvb_reported_length_remaining(tvb, 8)), pinfo, tree, data);

    proto_tree_add_item(tree, hf_drda_pkgcnstkn, tvb, offset, 8, ENC_UTF_8);
    offset += 8;

    return offset;
}

static int
dissect_drda_pkgnamcsn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset;

    offset = dissect_drda_pkgnamct(tvb_new_subset_length(tvb, 0, tvb_reported_length_remaining(tvb, 2)), pinfo, tree, data);

    proto_tree_add_item(tree, hf_drda_pkgsn, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_drda_qryblksz(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_qryblksz, tvb, 0, 4, ENC_BIG_ENDIAN);
    return 4;
}

static const value_string drda_uowdsp_vals[] =
{
    { 1, "Committed"},
    { 2, "Rolled back"},
    { 0, NULL }
};

static int
dissect_drda_uowdsp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_uowdsp, tvb, 0, 1, ENC_NA);
    return 1;
}

static int
dissect_drda_rdbalwupd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_rdbalwupd, tvb, 0, 1, ENC_NA);
    return 1;
}

static int
dissect_drda_sqlcsrhld(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_sqlcsrhld, tvb, 0, 1, ENC_NA);
    return 1;
}

static const val64_string drda_qryextdtasz_vals[] =
{
    { -1, "Not limited by this parameter"},
    {  0, NULL }
};

static int
dissect_drda_qryextdtasz(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_qryextdtasz, tvb, 0, 8, ENC_BIG_ENDIAN);
    return 8;
}

static int
dissect_drda_smldtasz(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_smldtasz, tvb, 0, 8, ENC_BIG_ENDIAN);
    return 8;
}

static int
dissect_drda_meddtasz(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_meddtasz, tvb, 0, 8, ENC_BIG_ENDIAN);
    return 8;
}

static int
dissect_drda_trgdftrt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_trgdftrt, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
dissect_drda_rtnsqlda(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_rtnsqlda, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

static const value_string drda_qryattupd_vals[] = {
    { 0, "QRYUNK - Unknown or undefined for this cursor" },
    { 1, "QRYRDO - The cursor is read-only" },
    { 2, "QRYDEL - The cursor allows read and delete" },
    { 4, "QRYUPD - The cursor allows read, delete, and update" },
    { 0, NULL }
};

static int
dissect_drda_qryattupd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_qryattupd, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
dissect_drda_qryrowset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_qryrowset, tvb, 0, 4, ENC_BIG_ENDIAN);
    return 4;
}

static int
dissect_drda_qryinsid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* Query Instance Identifier (QRYINSID) uniquely identifies the instance of
     * a query. Its contents are implementation-specific and are unarchitected
     * by DDM.
     */
    proto_tree_add_item(tree, hf_drda_qryinsid, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    return tvb_reported_length(tvb);
}

static const value_string drda_qryclsimp_vals[] = {
    { 0, "Target server determines whether to implicitly close the cursor or not upon SQLSTATE 02000 based on the cursor type" },
    { 1, "Target server must implicitly close the cursor upon SQLSTATE 02000" },
    { 2, "Target server must not implicitly close the cursor upon SQLSTATE 02000" },
    { 0, NULL }
};

static int
dissect_drda_qryclsimp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_qryclsimp, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
dissect_drda_qryblkfct(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_qryblkfct, tvb, 0, 4, ENC_BIG_ENDIAN);
    return 4;
}

static int
dissect_drda_maxrslcnt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_maxrslcnt, tvb, 0, 2, ENC_BIG_ENDIAN);
    return 2;
}

static int
dissect_drda_maxblkext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_maxblkext, tvb, 0, 2, ENC_BIG_ENDIAN);
    return 2;
}

static const value_string drda_rslsetflg_extended_vals[] =
{
    { 0, "Standard SQLDA" },
    { 1, "Extended SQLDA" },
    { 2, "Light SQLDA" },
    { 0, NULL }
};

static int
dissect_drda_rslsetflg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static int * const rslsetflg_fields[] = {
        &hf_drda_rslsetflg_unused,
        &hf_drda_rslsetflg_dsconly,
        &hf_drda_rslsetflg_extended,
        &hf_drda_rslsetflg_reserved,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, 0, hf_drda_rslsetflg, ett_drda_rslsetflg,
        rslsetflg_fields, ENC_BIG_ENDIAN);
    return 4;
}

static const value_string drda_typsqlda_vals[] = {
    { 0, "Standard output SQLDA" },
    { 1, "Standard input SQLDA" },
    { 2, "Light output SQLDA" },
    { 3, "Light input SQLDA" },
    { 4, "Extended output SQLDA" },
    { 5, "Extended input SQLDA" },
    { 0, NULL }
};

static int
dissect_drda_typsqlda(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_typsqlda, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

static const value_string drda_outovropt_vals[] = {
    { 1, "OUTOVRFRS - Output Override Allowed on First CNTQRY" },
    { 2, "OUTOVRANY - Output Override Allowed on Any CNTQRY" },
    { 3, "OUTOVRNON - Output Override Not Allowed, and MINLVL is 8" },
    { 0, NULL }
};

static int
dissect_drda_outovropt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_outovropt, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
dissect_drda_dyndtafmt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_dyndtafmt, tvb, 0, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
dissect_drda_pktobj(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_drda_pktobj, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    return tvb_reported_length(tvb);
}

static int
dissect_drda_mgrlvlls(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_tree *drda_tree_sub;
    proto_item *ti;

    drda_pdu_info_t *pdu_info = (drda_pdu_info_t*)data;

    int offset = 0;
    uint32_t mgrlvln;
    uint16_t iParameterCP;
    int iLengthParam = 4;

    while (tvb_reported_length_remaining(tvb, offset) >= 2)
    {
        iParameterCP = tvb_get_ntohs(tvb, offset);
        drda_tree_sub = proto_tree_add_subtree(tree, tvb, offset, iLengthParam,
                        ett_drda_param, &ti, DRDA_TEXT_PARAM);
        proto_item_append_text(ti, " (%s)", val_to_str_ext(iParameterCP, &drda_opcode_vals_ext, "Unknown (0x%02x)"));
        proto_tree_add_item(drda_tree_sub, hf_drda_param_codepoint, tvb, offset, 2, ENC_BIG_ENDIAN);
        switch (iParameterCP) {

        case DRDA_CP_CCSIDMGR:
        case DRDA_CP_UNICODEMGR:
            /* The default CCSID for DRDA is 500 (EBCDIC Latin-1).
             * These two code points are used to propose (in an EXCSAT
             * command's MGRLVLLS parameter) and accept (in an EXCSATRD
             * command's MGRLVLLS parameter) a CSSID to be used for all
             * character data for DDM parameters. (*Not*, note, for the
             * FD:OCA (SQL statements and the like), which are governed
             * by TYPDEFNAM and TYPDEFOVR as contained in ACCRDB and ACCRDBRM
             * - note that they can be different in the two directions.)
             *
             * A 0 reply in an EXCSATRD means rejection of the request, and
             * EBCDIC code page 500 (Latin-1) must be used. A 0xFFFF reply
             * in an EXCSATRD means "I do support CCSIDMGR, but not the code
             * page you requested, try again."
             *
             * UNICODEMGR and CCSIDMGR are mutually exclusive.
             * UNICODEMGR should only use 1208 (UTF-8) or 0. CCSIDMGR must
             * support 500 (EBCDIC Latin-1), 819 (ISO 8859-1), and 850
             * (IBM PC-DOS ASCII Latin-1), and can support others.
             * If the server replies with a 0 to UNICODEMGR, the client can
             * try again with a CCSIDMGR.
             */
            proto_tree_add_item(drda_tree_sub, hf_drda_ccsid, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            break;

        case DRDA_CP_SQLAM:
            proto_tree_add_item_ret_uint(drda_tree_sub, hf_drda_mgrlvln, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &mgrlvln);
            pdu_info->sqlam = mgrlvln;
            break;

        default:
            proto_tree_add_item(drda_tree_sub, hf_drda_mgrlvln, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        }
        offset += iLengthParam;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_drda_collection(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_tree *drda_tree_sub;
    proto_item *ti;
    int offset = 0;

    uint16_t iParameterCP;
    int iLengthParam;

    /* All objects in DDM are modeled as either scalars or collections.
     * A collection has the length before each element.
     * There are also lists of repeatable scalars, which don't have
     * the length.
     */

    while (tvb_reported_length_remaining(tvb, offset) >= 2)
    {
        iLengthParam = tvb_get_ntohs(tvb, offset + 0);
        if (tvb_reported_length_remaining(tvb, offset) >= iLengthParam)
        {
            iParameterCP = tvb_get_ntohs(tvb, offset + 2);
            drda_tree_sub = proto_tree_add_subtree(tree, tvb, offset, iLengthParam,
                            ett_drda_param, &ti, DRDA_TEXT_PARAM);
            proto_item_append_text(ti, " (%s)", val_to_str_ext(iParameterCP, &drda_opcode_vals_ext, "Unknown (0x%02x)"));
            proto_tree_add_item(drda_tree_sub, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(drda_tree_sub, hf_drda_param_codepoint, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if (!dissector_try_uint_new(drda_opcode_table, iParameterCP, tvb_new_subset_length(tvb, offset + 4, iLengthParam - 4), pinfo, drda_tree_sub, false, data)) {
                proto_tree_add_item(drda_tree_sub, hf_drda_param_data, tvb, offset + 4, iLengthParam - 4, ENC_UTF_8);
                proto_tree_add_item(drda_tree_sub, hf_drda_param_data_ebcdic, tvb, offset + 4, iLengthParam - 4, ENC_EBCDIC_CP500);
            }
        }
        offset += iLengthParam;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_drda_codpntdr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    uint32_t codpnt;

    ti = proto_tree_add_item_ret_uint(tree, hf_drda_param_codepoint, tvb, 0, 2, ENC_BIG_ENDIAN, &codpnt);
    proto_item_append_text(ti, " - %s", val_to_str_ext(codpnt, &drda_opcode_vals_ext, "Unknown (0x%02x)"));
    return 2;
}

static int
dissect_drda_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree  *drda_tree;
    proto_tree  *drdaroot_tree;
    proto_tree  *drda_tree_sub;
    proto_item  *ti, *ddm_ti, *ti_length;
    int offset = 0;

    drda_conv_info_t *conv_info;
    drda_flow_t      *flow;
    drda_pdu_info_t  *pdu_info;
    uint64_t flags;
    uint32_t iLength, iCommand, correl;

    uint16_t iParameterCP;
    uint8_t dsstyp;
    bool is_server = false;
    int iLengthParam;

    static int * const format_flags[] = {
        &hf_drda_ddm_fmt_reserved,
        &hf_drda_ddm_fmt_chained,
        &hf_drda_ddm_fmt_errcont,
        &hf_drda_ddm_fmt_samecorr,
        &hf_drda_ddm_fmt_dsstyp,
        NULL
    };

    ti = proto_tree_add_item(tree, proto_drda, tvb, 0, -1, ENC_NA);
    drdaroot_tree = proto_item_add_subtree(ti, ett_drda);

    drda_tree = proto_tree_add_subtree(drdaroot_tree, tvb, 0, 10, ett_drda_ddm, &ddm_ti, DRDA_TEXT_DDM);

    ti_length = proto_tree_add_item_ret_uint(drda_tree, hf_drda_ddm_length, tvb, 0, 2, ENC_BIG_ENDIAN, &iLength);
    if (iLength < 10) {
        expert_add_info_format(pinfo, ti_length, &ei_drda_opcode_invalid_length, "Invalid length detected (%u): should be at least 10 bytes long", iLength);
        return 2;
    }

    proto_tree_add_item(drda_tree, hf_drda_ddm_magic, tvb, 2, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bitmask_ret_uint64(drda_tree, tvb, 3, hf_drda_ddm_format, ett_drda_ddm_format, format_flags, ENC_BIG_ENDIAN, &flags);
    dsstyp = flags & 0xF;

    proto_tree_add_item_ret_uint(drda_tree, hf_drda_ddm_rc, tvb, 4, 2, ENC_BIG_ENDIAN, &correl);
    proto_tree_add_item(drda_tree, hf_drda_ddm_length2, tvb, 6, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item_ret_uint(drda_tree, hf_drda_ddm_codepoint, tvb, 8, 2, ENC_BIG_ENDIAN, &iCommand);
    is_server = drda_packet_from_server(pinfo, iCommand, dsstyp);
    proto_item_append_text(ti, " (%s)", val_to_str_ext(iCommand, &drda_opcode_vals_ext, "Unknown (0x%02x)"));
    proto_item_append_text(ddm_ti, " (%s)", val_to_str_ext(iCommand, &drda_opcode_abbr_ext, "Unknown (0x%02x)"));
    col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", val_to_str_ext(iCommand, &drda_opcode_abbr_ext, "Unknown (0x%02x)"));
    col_set_fence(pinfo->cinfo, COL_INFO);

    pdu_info = drda_get_pdu_info(pinfo, correl, is_server);

    /* There are a few command objects treated differently, like SNDPKT */
    if (!dissector_try_uint_new(drda_opcode_table, iCommand, tvb_new_subset_length(tvb, 10, iLength - 10), pinfo, drda_tree, false, pdu_info)) {
        /* The number of attributes is variable */
        offset = 10;
        while (tvb_reported_length_remaining(tvb, offset) >= 2)
        {
            iLengthParam = tvb_get_ntohs(tvb, offset + 0);
            if (iLengthParam == 0 || iLengthParam == 1)
                iLengthParam = iLength - 10;
            if (tvb_reported_length_remaining(tvb, offset) >= iLengthParam)
            {
                iParameterCP = tvb_get_ntohs(tvb, offset + 2);
                drda_tree_sub = proto_tree_add_subtree(drdaroot_tree, tvb, offset, iLengthParam,
                                ett_drda_param, &ti, DRDA_TEXT_PARAM);
                proto_item_append_text(ti, " (%s)", val_to_str_ext(iParameterCP, &drda_opcode_vals_ext, "Unknown (0x%02x)"));
                proto_tree_add_item(drda_tree_sub, hf_drda_param_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(drda_tree_sub, hf_drda_param_codepoint, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                if (!dissector_try_uint_new(drda_opcode_table, iParameterCP, tvb_new_subset_length(tvb, offset + 4, iLengthParam - 4), pinfo, drda_tree_sub, false, pdu_info)) {
                    proto_tree_add_item(drda_tree_sub, hf_drda_param_data, tvb, offset + 4, iLengthParam - 4, ENC_UTF_8);
                    proto_tree_add_item(drda_tree_sub, hf_drda_param_data_ebcdic, tvb, offset + 4, iLengthParam - 4, ENC_EBCDIC_CP500);
                }
            }
            offset += iLengthParam;
        }
    }
    conv_info = drda_get_conv_info(pinfo);
    if (iCommand == DRDA_CP_EXCSATRD) {
        /* EXCSATRD should be from the server, it confirms the negotiated
         * values for the MGRLVLLS that both directions will use. */
        flow = conv_info->server;
        if (GPOINTER_TO_UINT(wmem_tree_lookup32_le(flow->sqlam_tree, pinfo->num)) != pdu_info->sqlam) {
            wmem_tree_insert32(flow->sqlam_tree, pinfo->num, GUINT_TO_POINTER(pdu_info->sqlam));
        }
        flow = conv_info->client;
        if (GPOINTER_TO_UINT(wmem_tree_lookup32_le(flow->sqlam_tree, pinfo->num)) != pdu_info->sqlam) {
            wmem_tree_insert32(flow->sqlam_tree, pinfo->num, GUINT_TO_POINTER(pdu_info->sqlam));
        }
    } else if (iCommand == DRDA_CP_ACCRDB || iCommand == DRDA_CP_ACCRDBRM) {
        /* The parameters configured by ACCRDB and ACCRDBRM, OTOH, are
          * separate per-direction. */
        flow = (iCommand == DRDA_CP_ACCRDB) ? conv_info->client : conv_info->server;
        drda_update_flow_encoding(pinfo, flow, pdu_info);
    }

    return tvb_captured_length(tvb);
}

static unsigned
get_drda_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (tvb_get_ntohs(tvb, offset));
}

static int
dissect_drda_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRDA");
    col_clear(pinfo->cinfo, COL_INFO);

    /* There may be multiple DRDA commands in one frame */
    tcp_dissect_pdus(tvb, pinfo, tree, drda_desegment, 10, get_drda_pdu_len, dissect_drda_pdu, data);
    return tvb_captured_length(tvb);
}


static bool
dissect_drda_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t * conversation;
    if (tvb_captured_length(tvb) >= 10)
    {
        /* The first header is 6 bytes long, so the length in the second header should 6 bytes less */
        uint16_t cOuterLength, cInnerLength;
        cOuterLength = tvb_get_ntohs(tvb, 0);
        cInnerLength = tvb_get_ntohs(tvb, 6);
        if ((tvb_get_uint8(tvb, 2) == DRDA_MAGIC) && ((cOuterLength - cInnerLength) == 6))
        {
            /* Register this dissector for this conversation */
            conversation = find_or_create_conversation(pinfo);
            conversation_set_dissector(conversation, drda_tcp_handle);

            /* Dissect the packet */
            dissect_drda_tcp(tvb, pinfo, tree, data);
            return true;
        }
    }
    return false;
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
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), DRDA_DSSFMT_RESERVED,
            "DSSFMT reserved", HFILL }},

        { &hf_drda_ddm_fmt_chained,
          { "Chained", "drda.ddm.fmt.bit1",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), DRDA_DSSFMT_CHAINED,
            "DSSFMT chained", HFILL }},

        { &hf_drda_ddm_fmt_errcont,
          { "Continue", "drda.ddm.fmt.bit2",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), DRDA_DSSFMT_CONTINUE,
            "DSSFMT continue on error", HFILL }},

        { &hf_drda_ddm_fmt_samecorr,
          { "Same correlation", "drda.ddm.fmt.bit3",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), DRDA_DSSFMT_SAME_CORR,
            "DSSFMT same correlation", HFILL }},

        { &hf_drda_ddm_fmt_dsstyp,
          { "DSS type", "drda.ddm.fmt.dsstyp",
            FT_UINT8, BASE_DEC, VALS(drda_dsstyp_abbr), 0x0F,
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

        /* The DRDA spec really treats the NULL indicator as a FT_INT8, but
         * range_strings with negative values are a little annoying.
         */
        { &hf_drda_null_ind,
          { "SQL NULL Indicator", "drda.null_ind",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(drda_null_ind_rvals),
            0x0, NULL, HFILL }},

        { &hf_drda_typdefnam,
          { "Data Type Definition Name", "drda.typdefnam",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_clob_length,
          { "CLOB Length", "drda.clob.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlstatement,
          { "SQL statement", "drda.sqlstatement",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlcagrp,
          { "SQL Communications Area Group Description", "drda.sqlcagrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlcode,
          { "SQL code", "drda.sqlcode",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlstate,
          { "SQL state", "drda.sqlstate",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrproc,
          { "SQLERRPROC", "drda.sqlerrproc",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlcaxgrp,
          { "SQL Communications Area Exceptions Group", "drda.sqlcaxgrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrd1,
          { "SQLERRD1", "drda.sqlerrd1",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrd2,
          { "SQLERRD2", "drda.sqlerrd2",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrd3,
          { "SQLERRD3", "drda.sqlerrd3",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrd4,
          { "SQLERRD4", "drda.sqlerrd4",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrd5,
          { "SQLERRD5", "drda.sqlerrd5",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrd6,
          { "SQLERRD6", "drda.sqlerrd6",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn0,
          { "SQLWARN0", "drda.sqlwarn0",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn1,
          { "SQLWARN1", "drda.sqlwarn1",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn2,
          { "SQLWARN2", "drda.sqlwarn2",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn3,
          { "SQLWARN3", "drda.sqlwarn3",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn4,
          { "SQLWARN4", "drda.sqlwarn4",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn5,
          { "SQLWARN5", "drda.sqlwarn5",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn6,
          { "SQLWARN6", "drda.sqlwarn6",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn7,
          { "SQLWARN7", "drda.sqlwarn7",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn8,
          { "SQLWARN8", "drda.sqlwarn8",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarn9,
          { "SQLWARN9", "drda.sqlwarn9",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlwarna,
          { "SQLWARNA", "drda.sqlwarna",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlerrmsg,
          { "SQL Error Message Token", "drda.sqlerrmsg",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldhgrp,
          { "SQL Descriptor Header Group Description", "drda.sqldhgrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldhold,
          { "SQLDHOLD", "drda.sqldhold",
            FT_INT16, BASE_DEC, VALS(drda_hold_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldreturn,
          { "SQLDRETURN", "drda.sqldreturn",
            FT_INT16, BASE_DEC, VALS(drda_return_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldscroll,
          { "SQLDSCROLL", "drda.sqldscroll",
            FT_INT16, BASE_DEC, VALS(drda_scroll_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldsensitive,
          { "SQLDSENSITIVE", "drda.sqldsensitive",
            FT_INT16, BASE_DEC, VALS(drda_sensitive_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldfcode,
          { "SQLDFCODE", "drda.sqldfcode",
            FT_INT16, BASE_DEC, VALS(drda_fcode_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldkeytype,
          { "SQLDKEYTYPE", "drda.sqldkeytype",
            FT_INT16, BASE_DEC, VALS(drda_keytype_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldoptlck,
          { "SQLDOPTLCK", "drda.sqldoptlck",
            FT_INT16, BASE_DEC, VALS(drda_doptlck_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldschema,
          { "SQLDSCHEMA", "drda.sqldschema",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldmodule,
          { "SQLDMODULE", "drda.sqldmodule",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldagrp,
          { "SQL Descriptor Area Group Description", "drda.sqldagrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlprecision,
          { "SQLPRECISION", "drda.sqlprecision",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlscale,
          { "SQLSCALE", "drda.sqlscale",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqllength,
          { "SQLLENGTH", "drda.sqllength",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqllength32,
          { "SQLLENGTH", "drda.sqllength",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqltype,
          { "SQLTYPE", "drda.sqltype",
            FT_INT16, BASE_DEC, VALS(drda_sqltype_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlarrextent,
          { "SQLARREXTENT", "drda.sqlarrextent",
            FT_INT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldoptgrp,
          { "SQL Descriptor Optional Group Description", "drda.sqldoptgrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlunnamed,
          { "SQLUNNAMED", "drda.sqlunnamed",
            FT_INT16, BASE_DEC, VALS(drda_unnamed_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlname,
          { "SQLNAME", "drda.sqlname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqllabel,
          { "SQLLABEL", "drda.sqllabel",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlcomments,
          { "SQLCOMMENTS", "drda.sqlcomments",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqludtgrp,
          { "SQL Descriptor User-Defined Type Group Description",
            "drda.sqludtgrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqludtxtype,
          { "SQLUDTXTYPE", "drda.sqludtxtype",
            FT_INT32, BASE_DEC, VALS(drda_udtxtype_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqludtschema,
          { "SQLUDTSCHEMA", "drda.sqludtschema",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqludtname,
          { "SQLUDTNAME", "drda.sqludtname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqludtmodule,
          { "SQLUDTMODULE", "drda.sqludtmodule",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldxgrp,
          { "SQL Descriptor Extended Type Group Description", "drda.sqldxgrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxkeymem,
          { "SQLXKEYMEM", "drda.sqlxkeymem",
            FT_INT16, BASE_DEC, VALS(drda_keymem_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxupdateable,
          { "SQLXUPDATEABLE", "drda.sqlxupdateable",
            FT_INT16, BASE_DEC, VALS(drda_updateable_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxgenerated,
          { "SQLXGENERATED", "drda.sqlxgenerated",
            FT_INT16, BASE_DEC, VALS(drda_generated_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxparmmode,
          { "SQLXPARMMODE", "drda.sqlxparmmode",
            FT_INT16, BASE_DEC, VALS(drda_parmmode_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxoptlck,
          { "SQLXOPTLCK", "drda.sqlxoptlck",
            FT_INT16, BASE_DEC, VALS(drda_xoptlck_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxhidden,
          { "SQLXHIDDEN", "drda.sqlxhidden",
            FT_INT16, BASE_DEC, VALS(drda_hidden_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxcorname,
          { "SQLXCORNAME", "drda.sqlxcorname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxbasename,
          { "SQLXBASENAME", "drda.sqlxbasename",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxschema,
          { "SQLXSCHEMA", "drda.sqlxschema",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxname,
          { "SQLXNAME", "drda.sqlxname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlxmodule,
          { "SQLXMODULE", "drda.sqlxmodule",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqldiaggrp,
          { "SQL Diagnostics Group Description", "drda.sqldiaggrp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlnum,
          { "SQLNUM", "drda.sqlnum",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_rlsconv,
          { "Release Conversation", "drda.rlsconv", FT_UINT8, BASE_NONE,
            VALS(drda_rlsconv_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_secmec,
          { "Security Mechanism", "drda.secmec", FT_UINT16, BASE_DEC,
            VALS(drda_secmec_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sectkn,
          { "Security Token", "drda.sectkn", FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_svrcod,
          { "Severity Code", "drda.svrcod", FT_UINT16, BASE_DEC,
            VALS(drda_svrcod_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_secchkcd,
          { "Security Check Code", "drda.secchkcd", FT_UINT8, BASE_HEX,
            VALS(drda_secchkcd_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_ccsid,
          { "CCSID", "drda.ccsid", FT_UINT16, BASE_DEC,
            VALS(drda_ccsid_vals), 0x0,
            "Coded Character Set Identifier", HFILL }},

        { &hf_drda_mgrlvln,
          { "Manager-level Number", "drda.mgrlvln", FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_monitor,
          { "Monitor", "drda.monitor", FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_monitor_etime,
          { "Elapsed Time", "drda.monitor.etime", FT_BOOLEAN, 32,
            NULL, 0x80000000,
            NULL, HFILL }},

        { &hf_drda_monitor_reserved,
          { "Reserved", "drda.monitor.reserved", FT_UINT32, BASE_HEX,
            NULL, 0x7FFFFFFF,
            NULL, HFILL }},

        { &hf_drda_etime,
          { "Elapsed Time", "drda.etime", FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_respktsz,
          { "Response Packet Size", "drda.respktsz", FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_rdbinttkn,
          { "RDB Interrupt Token", "drda.rdbinttkn", FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_rdbcmtok,
          { "RDB Commit Allowed", "drda.rdbcmtok", FT_UINT8, BASE_NONE,
            VALS(drda_boolean_vals), 0x0,
            NULL, HFILL }},

        /* This one is a 0x00 0x01 boolean, not a EBCDIC 0xf0 0xf1 boolean */
        { &hf_drda_rtnsetstt,
          { "Return SET Statement", "drda.rtnsetstt", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_outexp,
          { "Output Expected", "drda.outexp", FT_UINT8, BASE_NONE,
            VALS(drda_boolean_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_rdbnam,
          { "Relational Database Name (ASCII)", "drda.rdbnam", FT_STRING,
            BASE_NONE, NULL, 0x0,
            "RDBNAM assuming ASCII/UTF-8", HFILL }},

        { &hf_drda_rdbnam_ebcdic,
          { "Relational Database Name (EBCDIC)", "drda.rdbnam.ebcdic", FT_STRING,
            BASE_NONE, NULL, 0x0,
            "RBDNAM assuming EBCDIC", HFILL }},

        { &hf_drda_rdbcolid,
          { "RDB Collection Identifier (ASCII)", "drda.rdbcoldid", FT_STRING,
            BASE_NONE, NULL, 0x0,
            "RDBCOLID assuming ASCII/UTF-8", HFILL }},

        { &hf_drda_rdbcolid_ebcdic,
          { "RDB Collection Identifier (EBCDIC)", "drda.rdbcolid.ebcdic",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "RBDCOLID assuming EBCDIC", HFILL }},

        { &hf_drda_pkgid,
          { "RDB Package Identifier (ASCII)", "drda.pkgid", FT_STRING, BASE_NONE,
            NULL, 0x0,
            "PKGID assuming ASCII/UTF-8", HFILL }},

        { &hf_drda_pkgid_ebcdic,
          { "RDB Package Identifier (EBCDIC)", "drda.pkgid.ebcdic", FT_STRING,
            BASE_NONE, NULL, 0x0,
            "PKGID assuming EBCDIC", HFILL }},

        { &hf_drda_pkgsn,
          { "RDB Package Section Number", "drda.pkgsn", FT_INT16,
            BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_pkgcnstkn,
          { "RDB Package Consistency Token", "drda.pkgcnstkn", FT_BYTES,
            BASE_NONE|BASE_SHOW_ASCII_PRINTABLE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_qryblksz,
          { "Query Block Size", "drda.qryblksz", FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_uowdsp,
          { "Unit of Work Disposition", "drda.uowdsp", FT_UINT8, BASE_HEX,
            VALS(drda_uowdsp_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_rdbalwupd,
          { "RDB Allow Updates", "drda.rdbalwupd", FT_UINT8, BASE_HEX,
            VALS(drda_boolean_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_sqlcsrhld,
          { "Hold Cursor Position", "drda.sqlcsrhld", FT_UINT8, BASE_HEX,
            VALS(drda_boolean_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_qryextdtasz,
          { "Query Externalized Data Size", "drda.qryextdtasz", FT_INT64,
            BASE_DEC|BASE_VAL64_STRING|BASE_SPECIAL_VALS,
            VALS64(drda_qryextdtasz_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_smldtasz,
          { "Maximum Size of Small Data", "drda.smldtasz", FT_INT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_meddtasz,
          { "Maximum Size of Medium Data", "drda.meddtasz", FT_INT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_trgdftrt,
          { "Target Default Value Return", "drda.trgdftrt", FT_UINT8, BASE_HEX,
            VALS(drda_boolean_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_rtnsqlda,
          { "Return the SQLDA", "drda.rtnsqlda", FT_UINT8, BASE_HEX,
            VALS(drda_boolean_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_qryattupd,
          { "Query Attribute for Updatability", "drda.qryattupd", FT_INT8,
            BASE_DEC, VALS(drda_qryattupd_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_qryrowset,
          { "Query Rowset Size", "drda.qryrowset", FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_qryinsid,
          { "Query Instance Identifier", "drda.qryinsid", FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_qryclsimp,
          { "Query Close Implicit", "drda.qryclsimp", FT_INT8, BASE_DEC,
            VALS(drda_qryclsimp_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_qryblkfct,
          { "Query Blocking Factor", "drda.qryblkfct", FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_maxrslcnt,
          { "Maximum Result Set Count", "drda.maxrslcnt", FT_INT32,
            BASE_DEC|BASE_SPECIAL_VALS, VALS(drda_max_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_maxblkext,
          { "Maximum Number of Extra Blocks", "drda.maxblkext", FT_INT32,
            BASE_DEC|BASE_SPECIAL_VALS, VALS(drda_max_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_rslsetflg,
          { "Result Set Flags", "drda.rslsetflg", FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_drda_rslsetflg_unused,
          { "Unused", "drda.rslsetflg.unused", FT_UINT8, BASE_HEX,
            NULL, 0xE0,
            "Flags are no longer used and value should be zero", HFILL }},

        { &hf_drda_rslsetflg_dsconly,
          { "Description Only", "drda.rslsetflg.dsconly", FT_BOOLEAN, 8,
            NULL, 0x10,
            "Requires the target SQLAM to return an FD:OCA description but not any answer set data", HFILL }},

        { &hf_drda_rslsetflg_extended,
          { "Extended", "drda.rslsetflg.extended", FT_UINT8, BASE_HEX,
            VALS(drda_rslsetflg_extended_vals), 0x0C,
            "Identifies the type of FD:OCA SQLDA descriptor returned", HFILL }},

        { &hf_drda_rslsetflg_reserved,
          { "Reserved", "drda.rslsetflg.reserved", FT_UINT8, BASE_HEX,
            NULL, 0x03,
            NULL, HFILL }},

        { &hf_drda_typsqlda,
          { "Type of SQL Descriptor Area", "drda.typsqlda", FT_INT8, BASE_DEC,
            VALS(drda_typsqlda_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_outovropt,
          { "Output Override Option", "drda.outovropt", FT_INT8, BASE_DEC,
            VALS(drda_outovropt_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_dyndtafmt,
          { "Dynamic Data Format", "drda.dyndtafmt", FT_UINT8, BASE_HEX,
            VALS(drda_boolean_vals), 0x0,
            NULL, HFILL }},

        { &hf_drda_pktobj,
          { "Packet Object", "drda.pktobj", FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_drda,
        &ett_drda_ddm,
        &ett_drda_ddm_format,
        &ett_drda_param,
        &ett_drda_monitor,
        &ett_drda_rslsetflg,
        &ett_drda_sqlcagrp,
        &ett_drda_sqlcaxgrp,
        &ett_drda_sqldhgrp,
        &ett_drda_sqldagrp,
        &ett_drda_sqldoptgrp,
        &ett_drda_sqludtgrp,
        &ett_drda_sqldxgrp,
        &ett_drda_sqldiaggrp,
    };

    static ei_register_info ei[] = {
        { &ei_drda_opcode_invalid_length, { "drda.opcode.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length detected", EXPFILL }},
        { &ei_drda_undecoded, { "drda.undecoded", PI_UNDECODED, PI_NOTE, "[Not decoded yet]", EXPFILL }},
    };

    module_t *drda_module;
    expert_module_t* expert_drda;

    proto_drda = proto_register_protocol("DRDA", "DRDA", "drda");
    proto_register_field_array(proto_drda, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_drda = expert_register_protocol(proto_drda);
    expert_register_field_array(expert_drda, ei, array_length(ei));

    drda_opcode_table = register_dissector_table("drda.opcode", "DRDA opcode",
        proto_drda, FT_UINT16, BASE_HEX);

    drda_module = prefs_register_protocol(proto_drda, NULL);
    prefs_register_bool_preference(drda_module, "desegment",
                       "Reassemble DRDA messages spanning multiple TCP segments",
                       "Whether the DRDA dissector should reassemble messages spanning"
                       " multiple TCP segments."
                       " To use this option, you must also enable"
                       " \"Allow subdissectors to reassemble TCP streams\""
                       " in the TCP protocol settings.",
                       &drda_desegment);

    prefs_register_uint_preference(drda_module, "sqlam",
                        "Default SQLAM Level",
                        "Default SQL Application Manager Level in the absence"
                        " of EXSATRD command. (Currently the only difference"
                        " in handling is between values < 7 and >= 7.)",
                        10, &drda_default_sqlam);

    prefs_register_enum_preference(drda_module, "typdefnam",
                        "Default TYPDEFNAM",
                        "Data Type Definition to use in the absence of"
                        " ACCRDB and ACCRDBRM commands.",
                        &drda_default_typdefnam,
                        typdefnam_vals, false);

    prefs_register_enum_preference(drda_module, "ccsidsbc",
                        "Default Single-byte encoding for FD:OCA data",
                        "Single-byte encoding to use for FD:OCA character data"
                        " in the absence of CCSIDSBC TYPDEFOVR parameter.",
                        &drda_default_ccsidsbc,
                        ws_supported_mibenum_vals_character_sets_ev_array,
                        false);

    prefs_register_enum_preference(drda_module, "ccsidmbc",
                        "Default Mixed-byte encoding for FD:OCA data",
                        "Mixed-byte encoding to use for FD:OCA character data"
                        " in the absence of CCSIDMBC TYPDEFOVR parameter.",
                        &drda_default_ccsidmbc,
                        ws_supported_mibenum_vals_character_sets_ev_array,
                        false);

    drda_tcp_handle = register_dissector("drda", dissect_drda_tcp, proto_drda);
}

void
proto_reg_handoff_drda(void)
{
    heur_dissector_add("tcp", dissect_drda_heur, "DRDA over TCP", "drda_tcp", proto_drda, HEURISTIC_ENABLE);

    dissector_handle_t ccsid_handle;
    dissector_handle_t codpntdr_handle;
    dissector_handle_t collection_handle;
    dissector_handle_t sqlstt_handle;
    dissector_handle_t undecoded_handle;

    ccsid_handle = create_dissector_handle(dissect_drda_ccsid, proto_drda);
    codpntdr_handle = create_dissector_handle(dissect_drda_codpntdr, proto_drda);
    collection_handle = create_dissector_handle(dissect_drda_collection, proto_drda);
    sqlstt_handle = create_dissector_handle(dissect_drda_sqlstt, proto_drda);
    undecoded_handle = create_dissector_handle(dissect_drda_undecoded, proto_drda);

    dissector_add_uint("drda.opcode", DRDA_CP_TYPDEFNAM, create_dissector_handle(dissect_drda_typdefnam, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_MGRLVLLS, create_dissector_handle(dissect_drda_mgrlvlls, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_TYPDEFOVR, collection_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_PKGSNLST, collection_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_RLSCONV, create_dissector_handle(dissect_drda_rlsconv, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SECMEC, create_dissector_handle(dissect_drda_secmec, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SECTKN, create_dissector_handle(dissect_drda_sectkn, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SVRCOD, create_dissector_handle(dissect_drda_svrcod, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SECCHKCD, create_dissector_handle(dissect_drda_secchkcd, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_CCSIDSBC, ccsid_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_CCSIDDBC, ccsid_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_CCSIDMBC, ccsid_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_CCSIDXML, ccsid_handle);

    dissector_add_uint("drda.opcode", DRDA_CP_RDBACCCL, codpntdr_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_QRYPRCTYP, codpntdr_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_PKGDFTCST, codpntdr_handle);
    dissector_add_uint("drda.opcode", 0x2460, codpntdr_handle); /* Not in DRDA, Version 5 */

    dissector_add_uint("drda.opcode", DRDA_CP_MONITOR, create_dissector_handle(dissect_drda_monitor, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_ETIME, create_dissector_handle(dissect_drda_etime, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_RESPKTSZ, create_dissector_handle(dissect_drda_respktsz, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_RDBINTTKN, create_dissector_handle(dissect_drda_rdbinttkn, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_RDBCMTOK, create_dissector_handle(dissect_drda_rdbcmtok, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_RTNSETSTT, create_dissector_handle(dissect_drda_rtnsetstt, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_OUTEXP, create_dissector_handle(dissect_drda_outexp, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_PKGNAM, create_dissector_handle(dissect_drda_pkgnam, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_PKGNAMCT, create_dissector_handle(dissect_drda_pkgnamct, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_PKGNAMCSN, create_dissector_handle(dissect_drda_pkgnamcsn, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_UOWDSP, create_dissector_handle(dissect_drda_uowdsp, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_RDBALWUPD, create_dissector_handle(dissect_drda_rdbalwupd, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_QRYBLKSZ, create_dissector_handle(dissect_drda_qryblksz, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_RTNSQLDA, create_dissector_handle(dissect_drda_rtnsqlda, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SQLCSRHLD, create_dissector_handle(dissect_drda_sqlcsrhld, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_QRYEXTDTASZ, create_dissector_handle(dissect_drda_qryextdtasz, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SMLDTASZ, create_dissector_handle(dissect_drda_smldtasz, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_MEDDTASZ, create_dissector_handle(dissect_drda_meddtasz, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_TRGDFTRT, create_dissector_handle(dissect_drda_trgdftrt, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_QRYATTUPD, create_dissector_handle(dissect_drda_qryattupd, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_QRYROWSET, create_dissector_handle(dissect_drda_qryrowset, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_QRYINSID, create_dissector_handle(dissect_drda_qryinsid, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_QRYCLSIMP, create_dissector_handle(dissect_drda_qryclsimp, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_QRYBLKFCT, create_dissector_handle(dissect_drda_qryblkfct, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_MAXRSLCNT, create_dissector_handle(dissect_drda_maxrslcnt, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_MAXBLKEXT, create_dissector_handle(dissect_drda_maxblkext, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_RSLSETFLG, create_dissector_handle(dissect_drda_rslsetflg, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_TYPSQLDA, create_dissector_handle(dissect_drda_typsqlda, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_OUTOVROPT, create_dissector_handle(dissect_drda_outovropt, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_DYNDTAFMT, create_dissector_handle(dissect_drda_dyndtafmt, proto_drda));

    dissector_add_uint("drda.opcode", DRDA_CP_PKTOBJ, create_dissector_handle(dissect_drda_pktobj, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SQLSTT, sqlstt_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_SQLATTR, sqlstt_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_SQLCARD, create_dissector_handle(dissect_drda_sqlcard, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_SQLDARD, create_dissector_handle(dissect_drda_sqldard, proto_drda));
    dissector_add_uint("drda.opcode", DRDA_CP_FDODSC, undecoded_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_FDODTA, undecoded_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_QRYDSC, undecoded_handle);
    dissector_add_uint("drda.opcode", DRDA_CP_QRYDTA, undecoded_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
