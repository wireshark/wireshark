/* packet-sqloracle.h
 * Abstract: this file contains Net8 related definiton and structure
 *           gathered from jdbc thin driver
 *
 * $Id$
 *
 * Copyright (C) 2002 - 2002 AppDancer Networks, Inc. All rights reserved.
 * Author:      Charles Tai 01/28/2003
 *
 * The initial Ethereal version of this file was imported from the
 * ClearSight source code package.
 *
 * Ethereal - Network traffic analyzer
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



typedef unsigned char UI8_T, BYTE,*UI8_P;
typedef unsigned short UI16_T, *UI16_P;
typedef unsigned int UI32_T, *UI32_P;
typedef int		I32_T, *I32_P;
typedef short		I16_T, *I16_P;
typedef char	I8_T,  *I8_P;

/*+-------------------------------
 *	NET8 protocol definition
 *--------------------------------
-*/


/*+-------------------------------
 *	NET8 Command Header 
 *--------------------------------
-*/
#define NET8_TYPE_SETPROP		1		/* Set PROtocol */
#define NET8_TYPE_SETDATAREP	2		/* Set Data Representation */
#define NET8_TYPE_USERTOSERVER	3		/* User to Server request */
#define NET8_TYPE_ERRORSTATUS	4		/* Error return status */
#define NET8_TYPE_AUAS	5		/* Access User Address space */
#define NET8_TYPE_ROWTRANSFER	6		/* Row Transfer Header */
#define NET8_TYPE_ROWDATA		7		/* I made this to handle spanning data rows */
#define NET8_TYPE_OPIPARAM		8		/* return OPI parameter */
#define NET8_TYPE_FUNCCOMPLETE	9		/* return Function Complete */
#define NET8_TYPE_TTINOER  10 /* for msdos/os2  N oerdefs follow */
#define NET8_TYPE_TTIIOV  11 /* Sending IO vec only for fast UPI */
#define NET8_TYPE_TTISLG  12 /* Send LonG for fast UPI*/
#define NET8_TYPE_TTIICA  13 /* Invoke user CAllback*/
#define NET8_TYPE_TTILOBD 14 /* LOB/FILE data follows */
#define NET8_TYPE_TTIWRN  15 /* warning messages - may be a set of them */


#define NET8_TYPE_DESCINFO		16		/* Describe Information */
#define NET8_TYPE_PIGGYBACKFUNC	17		/* piggy back funtion follow */
#define NET8_TYPE_TTI3GL  18			/* signals special action for untrusted callout support */
#define NET8_TYPE_TTIFOB  19			 /* Flush Out Bind data in DML/w RETURN when error */
#define NET8_TYPE_SECURENEG		0xde		/* Secure Network Services Negotiation */
#define MAX_QUERY_STRING_LEN	256

/*+--------------------------------------
 *	User to Server request function types 
 *  NET8_TYPE_USERTOSERVER	0x03
 *  look in ttc7\FunCodes.java
 *---------------------------------------
-*/
#define NET8_USER_FUNC_OLOGON		1   /* logon to Oracle */ 
#define NET8_USER_FUNC_OPENCURSOR	2	/* Open Cursor */
#define NET8_USER_FUNC_PARSE		3	/* Parse */
#define NET8_USER_FUNC_EXECUTE		4	/* Execute */
#define NET8_USER_FUNC_OFETCH  5   /* fetch a row */ 

#define NET8_USER_FUNC_CLOSECURSOR	8	/* Close Cursor */

     
#define NET8_USER_FUNC_OLOGOFF 9   /* logoff of ORACLE */ 
#define NET8_USER_FUNC_ODSCRIBE 10   /* describe a select list column */ 
#define NET8_USER_FUNC_ODEFIN  11   /* define[] where the column goes */ 
#define NET8_USER_FUNC_OCOMON  12   /* auto[] commit on */ 
#define NET8_USER_FUNC_OCOMOFF    13   /* auto commit off */ 
#define NET8_USER_FUNC_OCOMMIT    14   /* commit */ 
#define NET8_USER_FUNC_OROLLBACK      15   /* rollback */ 
#define NET8_USER_FUNC_OSFE       16   /* set fatal error options */ 
#define NET8_USER_FUNC_ORESUME    17   /* resume current operation */ 
#define NET8_USER_FUNC_OVERSN     18   /* get ORACLE version-date string */ 
#define NET8_USER_FUNC_OTEMP      19   /* until we get rid of OASQL */ 
#define NET8_USER_FUNC_CANCEL    20   /* cancel the current operation */ 
#define NET8_USER_FUNC_OGEM       21   /* get error message */ 
#define NET8_USER_FUNC_OEXIT      22   /* Exit oracle command */ 
#define NET8_USER_FUNC_OSPECIAL   23   /* special function */ 
#define NET8_USER_FUNC_OABORT     24   /* abort */ 
#define NET8_USER_FUNC_ODQRID     25   /* deq by rowid */ 
#define NET8_USER_FUNC_OLNGF6     26   /* fetch a long column value */ 
#define NET8_USER_FUNC_OCAM       27   /* Create Access Module */ 
#define NET8_USER_FUNC_OSAMS      28   /* Save Access Module Statement */ 
#define NET8_USER_FUNC_OSAM       29   /* Save Access Module */ 
#define NET8_USER_FUNC_OPAMS      30   /* Parse Access Module Statement */ 
#define NET8_USER_FUNC_OHOWMANY   31   /* How Many Items? */ 
#define NET8_USER_FUNC_OINIT      32   /* Initialize Oracle */ 
#define NET8_USER_FUNC_OCHANGEU   33   /* change user id */ 
#define NET8_USER_FUNC_OBINDRP    34   /* Bind by reference positional */ 
#define NET8_USER_FUNC_OGETBV     35   /* Get n'th Bind Variable */ 
#define NET8_USER_FUNC_OGETIV     36   /* Get n'th Into Variable */ 
#define NET8_USER_FUNC_OBINDRV    37   /* Bind by reference */ 
#define NET8_USER_FUNC_OBINDRN    38   /* Bind by reference numeric */ 
#define NET8_USER_FUNC_OPARSEX    39   /* Parse And Execute */ 
#define NET8_USER_FUNC_OPARSYN    40   /* Parse for Syntax only */ 
#define NET8_USER_FUNC_OPARSDI    41   /* Parse for Syntax & SQL Dictionary lookup */ 
#define NET8_USER_FUNC_OCONTINUE  42   /* continue serving after eof */ 
#define NET8_USER_FUNC_ODSCRARR   43   /* array describe */ 
#define NET8_USER_FUNC_OLCCINI    44   /* init sys pars command table */ 
#define NET8_USER_FUNC_OLCCFIN    45   /* finalize sys pars command table */ 
#define NET8_USER_FUNC_OLCCPUT    46   /* put sys par in command table */ 
#define NET8_USER_FUNC_OLCCGPI    47   /* get sys pars info from command table */ 
#define NET8_USER_FUNC_OV6STRT    48   /* start Oracle (V6) */ 
#define NET8_USER_FUNC_OV6STOP    49   /* [poll for] shut down Oracle (V6) */ 
#define NET8_USER_FUNC_ORIP       50   /* run independent process (V6) */ 
#define NET8_USER_FUNC_OTRAM      51   /* test RAM (V6) */ 
#define NET8_USER_FUNC_OARCHIVE   52   /* archive op (V6) */ 
#define NET8_USER_FUNC_OMRSTART   53   /* media recovery - start (V6) */ 
#define NET8_USER_FUNC_OMRRECTS   54   /* media recovery - record tablespace to recover (V6) */
     
#define NET8_USER_FUNC_OMRGSLSQ   55   /* media recovery - get starting log seq # (V6) */ 
#define NET8_USER_FUNC_OMRREC     56   /* media recovery - recover using offline log (V6) */ 
#define NET8_USER_FUNC_OMRCAN     57   /* media recovery - cancel media recovery (V6) */ 
#define NET8_USER_FUNC_O2LOGON    58   /* logon to ORACLE (V6) (supercedes OLOGON) */ 
#define NET8_USER_FUNC_OVERSION   59   /* get ORACLE version-date string in new format */ 
#define NET8_USER_FUNC_OINIT2     60   /* new init call (supersedes OINIT) */ 
#define NET8_USER_FUNC_OCLOALL    61   /* reserved for MAC; close all cursors */ 
#define NET8_USER_FUNC_OALL       62   /* bundled execution call */ 
#define NET8_USER_FUNC_OTEX       63   /* reserved for os2/msdos; transaction execute call */ 
#define NET8_USER_FUNC_OSDAUTH    64   /* reserved for os2/msdos; set DBA authorization call */
     
#define NET8_USER_FUNC_OUDLFUN    65   /* for direct loader: functions */ 
#define NET8_USER_FUNC_OUDLBUF    66   /* for direct loader: buffer transfer */ 
#define NET8_USER_FUNC_OK2RPC     67   /* distrib. trans. mgr. RPC */ 
#define NET8_USER_FUNC_ODSCIDX    68   /* describe indexes for distributed query */ 
#define NET8_USER_FUNC_OSESOPN    69   /* session operations */ 
#define NET8_USER_FUNC_OEXECSCN   70   /* execute using synchronized system commit numbers */ 
#define NET8_USER_FUNC_OALL7      71   /* fast upi calls to opial7 */ 
#define NET8_USER_FUNC_OLONGF     72   /* Long fetch version 7 */ 
#define NET8_USER_FUNC_OEXECA     73   /* call opiexe from opiall; no two-task access */ 
#define NET8_USER_FUNC_OSQL7      74   /* New ver 7 parse call to deal with various flavours*/ 
#define NET8_USER_FUNC_OOBS       75   /* Please DO Not REUSE THIS CODE */ 
#define NET8_USER_FUNC_ORPC       76   /* RPC Call from pl/sql */ 
#define NET8_USER_FUNC_OKGL_OLD   77   /* do a KGL operation */ 
#define NET8_USER_FUNC_OEXFEN     78   
#define NET8_USER_FUNC_OXAOPN     79   /* X/Open XA operation */ 
#define NET8_USER_FUNC_OKGL  80   /* New OKGL call */ 
#define NET8_USER_FUNC_03LOGON    81 /* 2nd Half of Logon */ 
#define NET8_USER_FUNC_03LOGA     82   /* 1st Half of Logon */ 
#define NET8_USER_FUNC_OFNSTM     83   /* Do Streaming Operation */ 
#define NET8_USER_FUNC_OPENSESS  84   /* Open Session */  
#define NET8_USER_FUNC_O71XAOPN   85   /* X/Open XA operations (71 interface */ 
#define NET8_USER_FUNC_ODEBUG  86 /* debugging operation */
#define NET8_USER_FUNC_ODEBUGS 87 /* special debugging operation */ 
#define NET8_USER_FUNC_OXAST  88 /* XA start */
#define NET8_USER_FUNC_OXACM  89 /* XA Switch and Commit */ 
#define NET8_USER_FUNC_OXAPR  90 /* XA Switch and Prepare */
#define NET8_USER_FUNC_OXDP  91 /* direct copy from db buffers to client addr */ 

/* in Oracle 7 and lower, this used to be OCONNECT */
#define NET8_USER_FUNC_OKOD       92  /* New OKOD call */

/* Oracle 8 changes follow */
#define NET8_USER_FUNC_OCBK       93	/* OCBK call (kernel side only) */
#define NET8_USER_FUNC_OALL8      94	/* new v8 bundled call */
#define NET8_USER_FUNC_OFNSTM2    95	/* OFNSTM without the begintxn */
#define NET8_USER_FUNC_OLOBOPS    96	/* LOB and FILE related calls */
#define NET8_USER_FUNC_OFILECRT   97	/* FILE create call */
#define NET8_USER_FUNC_ODNY       98	/* new describe query call */
#define NET8_USER_FUNC_OCONNECT   99	/* code for non blocking attach host */
#define NET8_USER_FUNC_OOPENRCS  100	/* Open a recursive cursor */
#define NET8_USER_FUNC_OKPRALL   101	/* Bundled KPR execution */
#define NET8_USER_FUNC_OPLS      102	/* Bundled PL/SQL execution */
#define NET8_USER_FUNC_OTXSE	  103	/* transaction start, attach, detach */
#define NET8_USER_FUNC_OTXEN	  104	/* transaction commit, rollback, recover */
#define NET8_USER_FUNC_OCCA      105	/* Cursor Close All */
#define NET8_USER_FUNC_OFOI      106	/* Failover info piggyback */
#define NET8_USER_FUNC_O80SES    107	/* V8 session switching piggyback */
#define NET8_USER_FUNC_ODDF      108	/* Do Dummy Defines */
#define NET8_USER_FUNC_OLRMINI   109	/* init sys pars */
#define NET8_USER_FUNC_OLRMFIN   110	/* finalize sys pars */
#define NET8_USER_FUNC_OLRMPUT   111	/* put sys par in par space */
#define NET8_USER_FUNC_OLRMTRM   112	/* terminate sys pars */
#define NET8_USER_FUNC_OEXFENA   113	/* execute but don't unmap (used from opiall0) */
#define NET8_USER_FUNC_OINIUCB   114	/* OINIT for Untrusted CallBacks */
#define NET8_USER_FUNC_AUTH     115	/* Generic authentication call */
#define NET8_USER_FUNC_OFGI      116	/* FailOver Get Instance Info */
#define NET8_USER_FUNC_OOTCO	  117	/* Oracle Transaction service COmmit remote sites */
#define NET8_USER_FUNC_GETSESSKEY  118	/* Get the session key */
#define NET8_USER_FUNC_ODSY      119	/* V8 Describe Any */
#define NET8_USER_FUNC_OCANA     120	/* Cancel All */
#define NET8_USER_FUNC_OAQEQ	  121	/* AQ EnQueue */
#define NET8_USER_FUNC_OAQDQ	  122	/* AQ Dequeue */
#define NET8_USER_FUNC_ORFS	  123	/* RFS call */
#define NET8_USER_FUNC_OKPN      124	/* Kernel Programmatic Notification */
#define NET8_USER_FUNC_MAX_OFCN  124	/* last item allocated */
/*+--------------------------------------------------
 * query results db types in the describe pkt
 * for NET8_TYPE_OPIPARAM		0x08
 * & for NET8_TYPE_DESCINFO		0x10
 *---------------------------------------------------
-*/
#define NET8_DATATYPE_VARCHAR			0x01
#define NET8_DATATYPE_NUMBER			0x02
#define NET8_DATATYPE_VARNUM			0x06
#define NET8_DATATYPE_LONG				0x08
#define NET8_DATATYPE_DATE				0x0C
#define NET8_DATATYPE_RAW				0x17
#define NET8_DATATYPE_LONG_RAW			0x18
#define NET8_DATATYPE_CHAR				0x60
#define NET8_DATATYPE_RESULT_SET		0x66
#define NET8_DATATYPE_ROWID				0x68
#define NET8_DATATYPE_NAMED_TYPE		0x6D
#define NET8_DATATYPE_REF_TYPE			0x6F
#define NET8_DATATYPE_CLOB				0x70
#define NET8_DATATYPE_BLOB				0x71
#define NET8_DATATYPE_BFILE				0x72
#define NET8_DATATYPE_TIMESTAMP			0xB4
#define NET8_DATATYPE_TIMESTAMPTZ		0xB5
#define NET8_DATATYPE_INTERVALYM		0xB6
#define NET8_DATATYPE_INTERVALDS		0xB7
#define NET8_DATATYPE_TIMESTAMPLTZ		0xE7
#define NET8_DATATYPE_PLSQL_INDEX_TABLE	0x3E6
#define NET8_DATATYPE_FIXED_CHAR		0x3E7

/*+--------------------------------------------------
 * datatype sizes
 *---------------------------------------------------
-*/
#define NET8_DATATYPE_SIZE_TIMESTAMP		11
#define NET8_DATATYPE_SIZE_TIMESTAMPNOFRAC	7
#define NET8_DATATYPE_SIZE_DATE				7
#define NET8_DATATYPE_SIZE_TIMESTAMPZ		13
#define NET8_TIMESTAMPZ_REGIONIDBIT			0x80 /*-128*/
#define NET8_DATATYPE_SIZE_TIMESTAMPLTZ		11
#define NET8_DATATYPE_SIZE_TIMESTAMPLTZNOFRAC	7




void proto_register_sqloracle(void);
void proto_reg_handoff_sqloracle(void);

