/* packet-sqloracle.c
 * Routines for SQL ORcle packet dissection
 *
 * The initial Ethereal version of this file was imported from the
 * ClearSight source code package.
 * No author/copyright given in the original file.
 *
 * $Id$
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
#define TCP_PORT_TNS 1522 /* XXX 1521 collides with packet-tns.c */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <ctype.h>
#include <string.h>
#include <epan/packet.h>
#include "packet-sqloracle.h"
#define SWAP_UI16(ui16)	(((ui16)>>8 & 0xff) | ((ui16)<<8 & 0xff00))

/* option flag 1 */
#define OPTION_CANCEL 0x80
#define OPTION_FETCH  0x40
#define OPTION_EXCUTE  0x20
#define OPTION_DEFINE  0x10
#define OPTION_BIND  0x08
#define OPTION_DESC_BIND  0x04
#define OPTION_PARSE  0x02

/* option flag 2 */
#define OPTION_PLSQL 0x80
#define OPTION_PARSE2  0x40
#define OPTION_VECTOR  0x04
#define OPTION_FETCH2  0x02
#define OPTION_COMMIT  0x01



/* protocol */
static gint proto_sqloracle = -1;
static gint ett_sqloracle = -1;
static gint ett_sqloracle_operation = -1;

static int hf_sqloracle_operation = -1;
static int hf_sqloracle_func_type = -1;
/* static int hf_sqloracle_stmt_length = -1; */
static int hf_sqloracle_stmt = -1;
/* static int hf_sqloracle_v8ttluds_tname = -1;
static int hf_sqloracle_v8ttluds_sname = -1;
static int hf_sqloracle_v8ttluds_columnname = -1;
static int hf_sqloracle_v8ttluds_scrlength = -1;
static int hf_sqloracle_v8ttluds_nullallow = -1;
static int hf_sqloracle_v8ttluds_header= -1;
static int hf_sqloracle_v8ttloac_formuse = -1;
static int hf_sqloracle_v8ttloac_ncs = -1;
static int hf_sqloracle_v8ttloac_oid = -1;
static int hf_sqloracle_v8ttloac_header =-1;
static int hf_sqloracle_ttloac_flag2 = -1;
static int hf_sqloracle_ttloac_mal = -1;
static int hf_sqloracle_ttloac_varcharlen = -1;
static int hf_sqloracle_ttloac_dummy = -1;
static int hf_sqloracle_ttloac_scalesize = -1;
static int hf_sqloracle_ttloac_prefix = -1;
static int hf_sqloracle_ttloac_flag1 = -1;
static int hf_sqloracle_ttloac_type = -1;
static int hf_sqloracle_ttloac_header = -1;
*/
static int hf_sqloracle_flag = -1;
static int hf_sqloracle_num_column = -1;
/* static int hf_sqloracle_v8ttloac_vsn = -1; */
static int hf_sqloracle_itemNum = -1;
static int hf_sqloracle_numItersThisTime = -1;
static int hf_sqloracle_uacBufLength = -1;

static dissector_handle_t data_handle;
static	dissector_handle_t sqloracle_handle;
static char m_pCurQuery[2025];

static int m_numOfUpdate =0;
/* static int m_tnsErrors = 0; */
static int m_numOfSelect = 0;
static int m_numOfInsert = 0;
static int m_numOfDelete = 0;
static int m_numOfRollback = 0;
static int m_numOfSet = 0;
static int m_numOfStart = 0;
static int m_numOfCommit = 0;
static int m_numOfOtherStatement = 0;
static int m_numOfTransaction = 0;
/* static int m_bReAssembling = 0; */
/* SQLORACLE flags */
/*static const true_false_string flags_set_truth =
{
  " ",
  "No "
}; */
static const value_string sqloracle_operation_type[] = {
	{NET8_TYPE_SETPROP,   "Set protocol" },
	{NET8_TYPE_SETDATAREP,    "Set data representations" },
	{NET8_TYPE_USERTOSERVER,       "User request" },
	{NET8_TYPE_ERRORSTATUS,    "Error: No data found" },
	{NET8_TYPE_AUAS,  "Access user address space" },
	{NET8_TYPE_ROWTRANSFER,      "Row transfer header" },
	{NET8_TYPE_ROWDATA,      "Row transfer data follows" },
	{NET8_TYPE_OPIPARAM,     "Return OPI parameter" },
	{NET8_TYPE_FUNCCOMPLETE,    "Oracle function complete"},
	{NET8_TYPE_TTINOER,    "N Error return definitions follow"},
	{NET8_TYPE_TTIIOV, "Sending I/O Vec only for fast UPI"},
	{NET8_TYPE_TTISLG,   "Send long for fast UPI"},
	{NET8_TYPE_TTIICA,   "Invoke user callback"},
	{NET8_TYPE_TTILOBD,   "LOB/FILE data follows"},
	{NET8_TYPE_TTIWRN,   "Warning messages - may be a set of them"},
	{NET8_TYPE_DESCINFO,   "Describe information"},
	{NET8_TYPE_PIGGYBACKFUNC,   "Piggyback function follows"},
	{NET8_TYPE_TTI3GL,   "signals special action for untrusted callout support"},
	{NET8_TYPE_TTIFOB,   "Flush Out Bind data in DML/w RETURN when error"},
	{NET8_TYPE_SECURENEG,   "Secure Network Services Negotiation"},
	{0,     "Unknown"},
	{0, NULL}
};
static const value_string sql_func_type[] = {
    {NET8_USER_FUNC_OLOGON,   " Logon to Oracle"},
    {NET8_USER_FUNC_OPENCURSOR,    "Open cursor" },              
    {NET8_USER_FUNC_PARSE,     "Parse statement" },                
    {NET8_USER_FUNC_EXECUTE,    "Execute statement" },               
    {NET8_USER_FUNC_OFETCH,   " Fetch row" },              
    {NET8_USER_FUNC_CLOSECURSOR,   "Close cursor" },              
    {NET8_USER_FUNC_OLOGOFF,  "Logoff" },             
    {NET8_USER_FUNC_ODSCRIBE, "Describe select list column" },            
    {NET8_USER_FUNC_ODEFIN,   "Define where column goes" },              
    {NET8_USER_FUNC_OCOMON,   "Autocommit On" },              
    {NET8_USER_FUNC_OCOMOFF,  "Autocommit Off" },             
    {NET8_USER_FUNC_OCOMMIT,  "Commit" },             
    {NET8_USER_FUNC_OROLLBACK,    "Rollback" },               
    {NET8_USER_FUNC_OSFE,     "Set fatal error options" },                
    {NET8_USER_FUNC_ORESUME,  "Resume current operation" },             
    {NET8_USER_FUNC_OVERSN,   "Get version-date string" },              
    {NET8_USER_FUNC_OTEMP,    "(Obsolete)" },               
    {NET8_USER_FUNC_CANCEL,  "Cancel Operation" },             
    {NET8_USER_FUNC_OGEM,     "Get error message" },                
    {NET8_USER_FUNC_OSPECIAL, "Special function" },            
    {NET8_USER_FUNC_OABORT,   "Abort" },              
    {NET8_USER_FUNC_ODQRID,   "Dequeue by rowid" },              
    {NET8_USER_FUNC_OLNGF6,   "Fetch long value" },              
    {NET8_USER_FUNC_OHOWMANY, "How Many Items?" },            
    {NET8_USER_FUNC_OINIT,    "Initialize Database" },               
    {NET8_USER_FUNC_OCHANGEU, "Change user_id" },            
    {NET8_USER_FUNC_OBINDRP,  "Bind by reference positional" },             
    {NET8_USER_FUNC_OGETBV,   "Get n'th Bind Variable" },              
    {NET8_USER_FUNC_OGETIV,   "Get n'th Into Variable" },              
    {NET8_USER_FUNC_OBINDRV,  "Bind by reference" },             
    {NET8_USER_FUNC_OBINDRN,  "Bind by reference numeric" },             
    {NET8_USER_FUNC_OPARSEX,  "Parse And Execute" },             
    {NET8_USER_FUNC_OPARSYN,  "Parse for Syntax only" },             
    {NET8_USER_FUNC_OPARSDI,  "Parse for Syntax & SQL Dictionary lookup" },
    {NET8_USER_FUNC_OCONTINUE, "Continue serving after eof" },            
    {NET8_USER_FUNC_ODSCRARR, "Describe Columns" },            
    {NET8_USER_FUNC_OLCCINI,  "Init sys pars command table" },             
    {NET8_USER_FUNC_OLCCFIN,  "Finalize sys pars command table" },             
    {NET8_USER_FUNC_OLCCPUT,  "Put sys par in command table" },             
    {NET8_USER_FUNC_OV6STRT,  "Start Oracle (V6)" },             
    {NET8_USER_FUNC_OV6STOP,  "Poll for shut down Oracle (V6)" },             
    {NET8_USER_FUNC_ORIP,     "Run independent process (V6)" },                
    {NET8_USER_FUNC_OARCHIVE, "Archive op (V6)" },            
    {NET8_USER_FUNC_OMRSTART, "Media recovery - start (V6)" },            
    {NET8_USER_FUNC_OMRRECTS, "Media recovery - record tablespace to recover (V6)"},          
    {NET8_USER_FUNC_OMRGSLSQ, "Media recovery - get starting log seq # (V6)" },
    {NET8_USER_FUNC_OMRREC,   "Media recovery - recover using offline log (V6)" },
    {NET8_USER_FUNC_OMRCAN,   "Media recovery - cancel media recovery (V6)" },
    {NET8_USER_FUNC_O2LOGON,  "Logon to ORACLE" },             
    {NET8_USER_FUNC_OVERSION, "Get Version/Date String" },
    {NET8_USER_FUNC_OINIT2,   "New init call (supersedes OINIT)" },              
    {NET8_USER_FUNC_OCLOALL,  "Reserved for MAC; close all cursors" },             
    {NET8_USER_FUNC_OALL,     "Bundled execution call" },                
    {NET8_USER_FUNC_OTEX,     "Transaction execute call (OS/2)" },                
    {NET8_USER_FUNC_OSDAUTH,  "Set DBA authorization call (OS/2)" },             
    {NET8_USER_FUNC_OUDLFUN,  "Direct loader: functions" },             
    {NET8_USER_FUNC_OUDLBUF,  "Direct loader: buffer transfer" },             
    {NET8_USER_FUNC_OK2RPC,   "Distrib. trans. mgr. RPC" },              
    {NET8_USER_FUNC_ODSCIDX,  "Describe indexes for distributed query" },
    {NET8_USER_FUNC_OSESOPN,  "Session operations" },             
    {NET8_USER_FUNC_OEXECSCN, "Execute using synchronized system commit numbers" },
    {NET8_USER_FUNC_OALL7,    "New V8 Bundle call" },               
    {NET8_USER_FUNC_OLONGF,   "Long fetch version 7" },              
    {NET8_USER_FUNC_OEXECA,   "Call opiexe from opiall" },             
    {NET8_USER_FUNC_OSQL7,    "Parse call" },               
    {NET8_USER_FUNC_OOBS,     "(Obsolete)" },
    {NET8_USER_FUNC_ORPC,     "RPC Call from pl" },                
    {NET8_USER_FUNC_OEXFEN,   "OEXFEN" },
    {NET8_USER_FUNC_OXAOPN,   "XA operation" },              
    {NET8_USER_FUNC_OKGL,     "KGL call" },
    {NET8_USER_FUNC_03LOGON,  "LogonB"},
    {NET8_USER_FUNC_03LOGA,   "LogonA"},
    {NET8_USER_FUNC_OFNSTM,   "Do Streaming Operation"},
    {NET8_USER_FUNC_OPENSESS, "Open Session"},  
    {NET8_USER_FUNC_O71XAOPN,  "X/Open XA operations"},
    {NET8_USER_FUNC_ODEBUG,   "Debug"},
    {NET8_USER_FUNC_ODEBUGS,  "Special Debug"},
    {NET8_USER_FUNC_OXAST,    "XA Start"},
    {NET8_USER_FUNC_OXACM,    "XA Commit"},
    {NET8_USER_FUNC_OXAPR,    "XA Prepare"},
    {NET8_USER_FUNC_OXDP,     "XA Import"},
    {NET8_USER_FUNC_OKOD,     "Get Object Value From Reference"},
    {NET8_USER_FUNC_OCONNECT, "Connect"},
	{NET8_USER_FUNC_OCBK,		"call (kernel side only)"},
	{NET8_USER_FUNC_OALL8,     "OALL8"},
	{NET8_USER_FUNC_OFNSTM2,   "OFNSTM without the begintxn"},
	{NET8_USER_FUNC_OLOBOPS,   "LOB Operation"},
	{NET8_USER_FUNC_OFILECRT,  "FILE create call"},
	{NET8_USER_FUNC_ODNY,      "New Describe"},
	{NET8_USER_FUNC_OCONNECT,  "code for non blocking attach host"},
	{NET8_USER_FUNC_OOPENRCS,  "Open a recursive cursor"},
	{NET8_USER_FUNC_OKPRALL,   "Bundled KPR execution"},
	{NET8_USER_FUNC_OPLS,      "Bundled PL/SQL execution"},
	{NET8_USER_FUNC_OTXSE,	    "transaction start, attach, detach"},
	{NET8_USER_FUNC_OTXEN,	    "transaction commit, rollback, recover"},
	{NET8_USER_FUNC_OCCA,      "Cursor Close All"},
	{NET8_USER_FUNC_OFOI,      "Failover info piggyback"},
	{NET8_USER_FUNC_O80SES,    "V8 session switching piggyback"},
	{NET8_USER_FUNC_ODDF,      "Do Dummy Defines"},
	{NET8_USER_FUNC_OLRMINI,   "init sys pars"},
	{NET8_USER_FUNC_OLRMFIN,   "finalize sys pars"},
	{NET8_USER_FUNC_OLRMPUT,   "put sys par in par space"},
	{NET8_USER_FUNC_OLRMTRM,   "terminate sys pars"},
	{NET8_USER_FUNC_OEXFENA,   "execute but don't unmap (used from opiall0)"},
	{NET8_USER_FUNC_OINIUCB,   "OINIT for Untrusted CallBacks"},
	{NET8_USER_FUNC_AUTH,     "Authentication Call"},
	{NET8_USER_FUNC_OFGI,      "FailOver Get Instance Info"},
	{NET8_USER_FUNC_OOTCO,	    "Oracle Transaction service COmmit remote sites"},
	{NET8_USER_FUNC_GETSESSKEY,  "Get the session key"},
	{NET8_USER_FUNC_ODSY,      "V8 Describe Any"},
	{NET8_USER_FUNC_OCANA,     "Cancel All"},
	{NET8_USER_FUNC_OAQEQ,	    "AQ EnQueue"},
	{NET8_USER_FUNC_OAQDQ,	    "AQ Dequeue"},
	{NET8_USER_FUNC_ORFS,	    "RFS call"},
	{NET8_USER_FUNC_OKPN,      "Kernel Programmatic Notification"},
    {0,       "Unknown type"},
	{0, NULL}
};


#if 0
/* jtse */
/*+------------------------------------------------------
 * 
 * Convert hex data to character string
 *--------------------------------------------------------
-*/
char * convertHexToString(BYTE *pSrc, UI16_T length)
{
    char buf[150];
	char * hexString;
	char hex[17] = "0123456789ABCDEF";
	int i;
    int limit = 2*length;
    if (limit >= sizeof(buf) - 3)
        limit = sizeof(buf) - 3;


    for( i=0; i<limit; i+=2)
    {
        buf[i] = hex[*pSrc>>4];
        buf[i+1] = hex[*pSrc&0x0F];
		pSrc++;
    }
	buf[i] = '\0';

    /*
	for(int i=0; i<length*2; i++)
	{
		buf[i]   = hex[*pSrc>>4];
		buf[++i] = hex[*pSrc&0x0F];
		pSrc++;
	}
	buf[length*2] = '\0';
    */

    /* hexString = buf; */
	strcpy (hexString, buf);
	return hexString;
}
#endif

static void ParseSqlStatement(/*char  *appMsg,*/ UI8_P pSqlData, UI16_T dataLen)
{
	char  *pSqlModifyData = (I8_P)m_pCurQuery;
	int   i = 0;

	while (*pSqlData != '\1' && *pSqlData != '\0' && i < dataLen)
	{
		if (*pSqlData < ' ')
		{
			*pSqlModifyData = ' ';
		}
		else
		{
			*pSqlModifyData = *pSqlData;
		}

		pSqlModifyData++;
		pSqlData++;
		i++;
	}

	*pSqlModifyData = '\0';

#if 0
	appMsg = (I8_P)m_pCurQuery;
#endif

	if (strncasecmp((I8_P)m_pCurQuery, "update", 6) == 0)
	{
		m_numOfUpdate++;
#if 0
		pSummaryStat->m_numOfUpdate++;
		if (m_pServerNode != NULL)
		    m_pServerNode->m_numOfUpdate++;
#endif
	}
	else if (strncasecmp((I8_P)m_pCurQuery, "select", 6) == 0)
	{
		m_numOfSelect++;
#if 0
		pSummaryStat->m_numOfSelect++;
	        if (m_pServerNode != NULL)
		    m_pServerNode->m_numOfSelect++;
#endif
	}
	else if (strncasecmp((I8_P)m_pCurQuery, "insert", 6) == 0)
	{
		m_numOfInsert++;
#if 0
		pSummaryStat->m_numOfInsert++;
	        if (m_pServerNode != NULL)
			m_pServerNode->m_numOfInsert++;
#endif
	}
	else if (strncasecmp((I8_P)m_pCurQuery, "delete", 6) == 0)
	{
		m_numOfDelete++;
#if 0
		pSummaryStat->m_numOfDelete++;
	        if (m_pServerNode != NULL)
			m_pServerNode->m_numOfDelete++;
#endif
	}
	else if (strncasecmp((I8_P)m_pCurQuery, "rollback", 8) == 0)
	{
		m_numOfRollback++;
#if 0
		pSummaryStat->m_numOfRollback++;
	        if (m_pServerNode != NULL)
			m_pServerNode->m_numOfRollback++;
#endif
	}
	else if (strncasecmp((I8_P)m_pCurQuery, "set", 3) == 0)
	{
		m_numOfSet++;
#if 0
		pSummaryStat->m_numOfSet++;
	        if (m_pServerNode != NULL)
			m_pServerNode->m_numOfSet++;
#endif
	}
	else if (strncasecmp((I8_P)m_pCurQuery, "start", 5) == 0)
	{
		m_numOfStart++;
#if 0
		pSummaryStat->m_numOfStart++;
	        if (m_pServerNode != NULL)
			m_pServerNode->m_numOfStart++;
#endif
	}
	else if (strncasecmp((I8_P)m_pCurQuery, "commit", 6) == 0)
	{
		m_numOfCommit++;
#if 0
		pSummaryStat->m_numOfCommit++;
	        if (m_pServerNode != NULL)
			m_pServerNode->m_numOfCommit++;
#endif
	}
	else 
	{
		m_numOfOtherStatement++;
#if 0
		pSummaryStat->m_numOfOtherStatement++;
		if (m_pServerNode != NULL)
			m_pServerNode->m_numOfOtherStatement++;
#endif
	}

	m_numOfTransaction++;
#if 0
	m_pSummaryStat->m_numOfTransaction++;
        if (m_pServerNode != NULL)
		m_pServerNode->m_numOfTransaction++;
#endif
}


static gboolean FindBeginningSQLString(UI8_P *pBuf, UI16_T *pDataLen, int lookSize)
{
	/* the position could still be off by x bytes, check if it happened to be landing on an address */
/*	int i = 31;	/+ allow upto 8 bad bytes */
	UI8_P pString = *pBuf;
	gboolean bAlpha1 = isalpha(pString[0]) != 0;
	gboolean bAlpha2 = isalpha(pString[1]) != 0;
	gboolean bAlpha3 = isalpha(pString[2]) != 0;
	gboolean bAlpha4 = isalpha(pString[3]) != 0;
	gboolean bComment = FALSE;
	UI16_T dataLen = *pDataLen;
	while ( (dataLen > 2) && (lookSize > 0) && ((bAlpha1 == FALSE) || (bAlpha2 == FALSE) || (bAlpha3 == FALSE) || (bAlpha4 == FALSE)))
	{
		/* check if we need to find the ending comment */
		if (bComment)
		{
			if (*((UI16_P)pString) == 0x2F2A)	/* ending comment */
			{
				bComment = FALSE;
				pString ++;	/* skip the comment */
				dataLen --;
			}
			pString ++;
			dataLen --;
		}
		else
		{
			/* check if there is a comment string prepended to the statement */
			if (*((UI16_P)pString) == 0x2A2F)	/* beginning of comment */
			{
				bComment = TRUE;
				dataLen -= 2;
				pString += 2;
				bAlpha2 = isalpha(pString[1]) != 0;
				bAlpha3 = isalpha(pString[2]) != 0;
				bAlpha4 = isalpha(pString[3]) != 0;
				continue;
			}
			pString++;
			bAlpha1 = bAlpha2;
			bAlpha2 = isalpha(pString[1]) != 0;
			bAlpha3 = isalpha(pString[2]) != 0;
			bAlpha4 = isalpha(pString[3]) != 0;
			dataLen --;
            /* don't count the zeros */
            if (*((UI8_P)pString) != 0x0)
			    lookSize--;
		}
	}
	if (bAlpha1 && bAlpha2 && bAlpha3 && bAlpha4)
	{
		*pBuf = pString;
		*pDataLen = dataLen;
		return TRUE;
	}
	else
		return FALSE;
}

static gboolean ParseCommand(proto_tree *tree,tvbuff_t *tvb, int offset, packet_info *pinfo,UI16_T dataLen)
{
	UI8_T pAddress[1024];
	UI16_T SQLDataLen = dataLen;
	int i;
	UI8_P pAddr;
	for (i=0; i<1024;i++)
	{
		pAddress[i] = '\0';
	}
	tvb_memcpy (tvb, pAddress,offset, dataLen);
	pAddr = (UI8_P)pAddress;
	/* see if SQL statement is there */
	if (FindBeginningSQLString((UI8_P*)&pAddr, &SQLDataLen, 0x30) == TRUE)
	{
		ParseSqlStatement( pAddr, dataLen);
		if (tree)
			proto_tree_add_text(tree, tvb, offset+dataLen-SQLDataLen, SQLDataLen,
			    "SQL statement = %s",m_pCurQuery);
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);
	    if (check_col(pinfo->cinfo, COL_INFO))
		   col_add_fstr(pinfo->cinfo, COL_INFO, "%s",m_pCurQuery );
		return TRUE;
	}
	return FALSE;
}

#if 0
static gboolean ParseNewCommand( proto_tree *tree,tvbuff_t *tvb, int offset, packet_info *pinfo, UI16_T dataLen)
{
	UI8_T pAddress[1024];
	/* find the first sequence of zeros */
	int amount = dataLen - 12;
	int i = 0, sqlamount;
	UI8_P pAddr;
	tvb_memcpy (tvb, pAddress,offset, dataLen);
	pAddr = (UI8_P)&pAddress;
	for (; i < amount; i++)
	{
		if (*((UI32_P)((UI8_P)pAddr++)) == 0x0000)
			break;
	}
	/* was there a sequence of 4 zeros */
	if (i >= amount)
	{
	/*	free(pAddr); */
		return FALSE;		/* went past, can not be a sql command */
	}
	/* look for the end of the zeros */
	amount = dataLen - i - 4;	/* rest of the data */
	pAddr += 3;
	for (i = 0; *pAddr++ == 0 && i < amount; i++);
	if (i >= amount)
	{
		/* free (pAddr); */
		return FALSE;	/* no values after zeros */
	}

	amount -= i + 1;	/* rest of the data */

	/* see if SQL statement is there */
	sqlamount = amount;
	if (FindBeginningSQLString((UI8_P*)&pAddr, (UI16_P)&sqlamount, 13) == TRUE)
	{
		ParseSqlStatement( pAddr, amount);
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);
	    if (check_col(pinfo->cinfo, COL_INFO))
		   col_add_fstr(pinfo->cinfo, COL_INFO, "%s",m_pCurQuery );
		proto_tree_add_text(tree, tvb, offset+amount-sqlamount, sqlamount,
			    "SQL statement = %s",m_pCurQuery);
		return TRUE;
	}
	return FALSE;
}
#endif




static void
dissect_sqloracle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
	proto_item	*ti = NULL;
	proto_tree	*sqloracle_tree = NULL;
	int offset = 0,dataLen,nocol,numItersThisTime,flag,iterNum,uacBufLength;
	guint8	header_operation,func_type=0;
	m_pCurQuery[0] = '0';


	pinfo->current_proto = "SQLORACLE";
	if ( check_col( pinfo->cinfo, COL_PROTOCOL ))
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "SQL" );
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

	header_operation = tvb_get_guint8(tvb, offset);
	dataLen = tvb_reported_length_remaining(tvb, offset);
	if (header_operation != NET8_TYPE_FUNCCOMPLETE)
		func_type = tvb_get_guint8(tvb, offset+1);

	if ( check_col(pinfo->cinfo, COL_INFO))
	{
	   col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(header_operation, sqloracle_operation_type, ""));
	}

	if ( tree ) 
	{ 
		ti = proto_tree_add_item(tree, proto_sqloracle, tvb, 0, -1, FALSE);
		sqloracle_tree = proto_item_add_subtree(ti, ett_sqloracle);
	    proto_tree_add_uint(sqloracle_tree, hf_sqloracle_operation, tvb, offset, 1,header_operation);
		if (func_type && header_operation !=NET8_TYPE_ROWTRANSFER)
			proto_tree_add_uint(sqloracle_tree, hf_sqloracle_func_type, tvb, offset+1, 1,func_type);
	}

	switch (header_operation)
	{
		case NET8_TYPE_USERTOSERVER: /* 0x3 */
			if ( check_col(pinfo->cinfo, COL_INFO))
			{
                col_append_fstr(pinfo->cinfo, COL_INFO, ":%s ", val_to_str(func_type, sql_func_type, ""));
			}
			switch (func_type)
			{
				case NET8_USER_FUNC_PARSE:
					ParseCommand(sqloracle_tree,tvb,offset+0x0B,pinfo,dataLen-0x0B);
					break;
				case NET8_USER_FUNC_OALL:
				case NET8_USER_FUNC_OALL8:
					/* command could be embedded in this packet
					 * filtered_for_hh02_and_hh05.enc has commands that are not 0x2f offset
					 * try to detect the difference by looking at the offset 0x12 for 6 zeros
					 */
					if (dataLen > (0x19 + 8))	/* assume minimum of 8 chars for the command */
					{
						/* piggybacked functions will recursive call this routine to process the command */
						if (ParseCommand(sqloracle_tree,tvb, offset+0x12, pinfo,dataLen - 0x12) == TRUE)
							break;
					}
					break;
				case NET8_USER_FUNC_OSQL7:			/* 0x4A */
					/* command could be embedded in this packet */
					/* aig oracle.enc has smaller data */
					if (dataLen > (0x2A /*0x30/0x14*/ + 8))	/* minimum of 8 chars */
					{
						if (ParseCommand(sqloracle_tree,tvb, offset + 0x2A /*0x30/0x14*/, pinfo,dataLen - 0x2A /*0x30/0x14*/) == TRUE)
								break;
					}
					break;

				case NET8_USER_FUNC_OALL7:			/* 0x47 */
					/* command could be embedded in this packet */
					if (dataLen > (0x2A /*0x30/0x14*/ + 8))	/* minimum of 8 chars */
					{
						if (ParseCommand(sqloracle_tree,tvb, offset + 0x14, pinfo,dataLen - 0x14) == TRUE)
						{
							if (check_col(pinfo->cinfo, COL_INFO))
								col_add_fstr(pinfo->cinfo, COL_INFO, "%s",m_pCurQuery );
							break;
						}
						else
							/* appdncr.enc has this smaller command */
						if (ParseCommand(sqloracle_tree,tvb, offset + 0x30, pinfo,dataLen - 0x30) == TRUE)
							break;
					}
					break;
			}
			break;
		case NET8_TYPE_ROWTRANSFER:		/* 0x06 */
			flag = func_type;
			proto_tree_add_uint(sqloracle_tree, hf_sqloracle_flag, tvb, offset+1, 1,flag);
			nocol = tvb_get_guint8(tvb, offset+2);
			iterNum = tvb_get_guint8(tvb, offset+3);
			numItersThisTime = tvb_get_ntohs(tvb, offset+5);
			uacBufLength = tvb_get_ntohs(tvb, offset+7);
			proto_tree_add_uint(sqloracle_tree, hf_sqloracle_num_column, tvb, offset+2, 1,nocol);
			proto_tree_add_uint(sqloracle_tree, hf_sqloracle_itemNum, tvb, offset+3, 1,iterNum);
			proto_tree_add_uint(sqloracle_tree, hf_sqloracle_numItersThisTime, tvb, offset+5, 2,numItersThisTime);
			proto_tree_add_uint(sqloracle_tree, hf_sqloracle_uacBufLength, tvb, offset+7, 2,uacBufLength);

			break;
		default:
			return;
			break;
	}

} /* dissect_sqloracle */

void
proto_register_sqloracle(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_sqloracle_operation,
		  { "Basic Operation", "sqloracle.operation", FT_UINT8, BASE_DEC, VALS(sqloracle_operation_type), 0x0, "", HFILL }
		},
		{ &hf_sqloracle_func_type,
		  { "Function Type", "sqloracle.type", FT_UINT8, BASE_DEC, VALS(sql_func_type), 0x0, "", HFILL }
		},
		{ &hf_sqloracle_flag,
		  { "flag", "sqloracle.flag", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_num_column,
			{ "Number of Columns", "sqloracle.nocolumn", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_itemNum,
		  { "Iteration Number", "sqloracle.itemNum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_numItersThisTime,
		  { "# of iterations this time", "sqloracle.numItersThisTime", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_uacBufLength,
		  { "user access buffer length", "sqloracle.uacBufLength", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
		},
/*		{ &hf_sqloracle_ttloac_header,
			{ "TTLOAC Header", "sqloracle.ttloac_header", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},

		{ &hf_sqloracle_ttloac_type,
			{ "type", "sqloracle.ttloac_type", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_ttloac_flag1,
		  { "flag1", "sqloracle.ttloac_flag1", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_ttloac_prefix,
		{ "prefix",		"sqloracle.ttloac_prefix", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_ttloac_scalesize,
		{ "scale size",		"sqloracle.ttloac_scalesize", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_ttloac_dummy,
		{ "dummy",		"sqloracle.ottloac_dummy", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_ttloac_varcharlen,
		{ "varcharlen",		"sqloracle.ttloac_varcharlen", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_ttloac_mal,
		{ "mal",		"sqloracle.ttloac_mal", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_ttloac_flag2,
		{ "flag2",		"sqloracle.ttloac_flag2", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttloac_header,
			{ "V8TTLOAC Header", "sqloracle.v8ttloac_header", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},

		{ &hf_sqloracle_v8ttloac_oid,
			{ "oid", "sqloracle.v8ttloac_oid", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttloac_vsn,
		  { "vsn", "sqloracle.v8ttloac_vsn", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttloac_ncs,
		{ "ncs",		"sqloracle.v8ttloac_ncs", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttloac_formuse,
		{ "FormUse",		"sqloracle.v8ttloac_formuse", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttluds_header,
			{ "V8TTLUDS Header", "sqloracle.v8ttluds_header", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},

		{ &hf_sqloracle_v8ttluds_nullallow,
			{ "null allowed", "sqloracle.v8ttluds_nullallow", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttluds_scrlength,
		  { "screen length", "sqloracle.v8ttluds_scrlength", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttluds_columnname,
		  { "column name", "sqloracle.v8ttluds_columnname", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttluds_sname,
		  { "sName", "sqloracle.v8ttluds_snname", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_v8ttluds_tname,
		  { "tName", "sqloracle.v8ttluds_tname", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
		},
		{ &hf_sqloracle_stmt_length,
		{ "SQL Statement Length",	"sqloracle.stmtlength", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},
*/		{ &hf_sqloracle_stmt,
			{ "SQL statement", "sqloracle.stmt", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }
		},
		};

	static gint *ett[] =
	{
		&ett_sqloracle,
		&ett_sqloracle_operation,
	};

	proto_sqloracle = proto_register_protocol("SQL -Net8 Data", "SQL", "sqloracle");
	proto_register_field_array(proto_sqloracle, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	
	register_dissector("sqloracle", dissect_sqloracle, proto_sqloracle);
}

void
proto_reg_handoff_sqloracle(void)
{

	sqloracle_handle = create_dissector_handle(dissect_sqloracle, proto_sqloracle);
	dissector_add("tns.port", TCP_PORT_TNS, sqloracle_handle);
	data_handle = find_dissector("data");
}

