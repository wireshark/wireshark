/* packet-mq-pcf.c
 * Routines for IBM WebSphere MQ PCF packet dissection
 *
 * metatech <metatech@flashmail.com>
 * robionekenobi <robionekenobi@bluewin.ch>
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

/*  MQ PCF in a nutshell
*
*   The MQ Programmable Command Formats API allows remotely configuring a queue manager.
*
*   MQ PCF documentation is called "WebSphere MQ Programmable Command Formats and Administration Interface"
*/

#include "config.h"

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/value_string.h>
#include "packet-mq.h"
#include "wmem/wmem.h"

#define PCF_MAX_PARM 999
#define PCF_MAX_LIST 20000

guint mq_pcf_maxprm = PCF_MAX_PARM;
guint mq_pcf_maxlst = PCF_MAX_LIST;

static int proto_mqpcf = -1;

static int hf_mqpcf_cfh_type = -1;
static int hf_mqpcf_cfh_length = -1;
static int hf_mqpcf_cfh_version = -1;
static int hf_mqpcf_cfh_command = -1;
static int hf_mqpcf_cfh_msgseqnumber = -1;
static int hf_mqpcf_cfh_control = -1;
static int hf_mqpcf_cfh_compcode = -1;
static int hf_mqpcf_cfh_reason = -1;
static int hf_mqpcf_cfh_paramcount = -1;

static int hf_mq_pcf_prmtyp = -1;
static int hf_mq_pcf_prmlen = -1;
static int hf_mq_pcf_prmid = -1;
static int hf_mq_pcf_prmccsid = -1;
static int hf_mq_pcf_prmstrlen = -1;
static int hf_mq_pcf_prmcount = -1;
static int hf_mq_pcf_prmunused = -1;

static int hf_mq_pcf_string = -1;
static int hf_mq_pcf_stringlist = -1;
static int hf_mq_pcf_int = -1;
static int hf_mq_pcf_intlist = -1;
static int hf_mq_pcf_bytestring = -1;
static int hf_mq_pcf_int64 = -1;
static int hf_mq_pcf_int64list = -1;

static expert_field ei_mq_pcf_prmln0 = EI_INIT;
static expert_field ei_mq_pcf_MaxInt = EI_INIT;
static expert_field ei_mq_pcf_MaxStr = EI_INIT;
static expert_field ei_mq_pcf_MaxI64 = EI_INIT;
static expert_field ei_mq_pcf_MaxPrm = EI_INIT;

static gint ett_mqpcf_prm = -1;
static gint ett_mqpcf = -1;
static gint ett_mqpcf_cfh = -1;

#define MQ_TEXT_CFH   "MQ Command Format Header"

guint8 *dissect_mqpcf_parm_getintval(guint uPrm,guint uVal)
{
	value_string *pVs=NULL;
	pVs=(value_string *)try_val_to_str(uPrm,GET_VALSV(MQCFINT_Parse));

	if (pVs)
	{
		return (guint8 *)try_val_to_str(uVal,pVs);
	}
	return NULL;
}

void dissect_mqpcf_parm_int(tvbuff_t *tvb, proto_tree *tree, guint offset,guint uPrm,guint uVal,int hfindex)
{
	header_field_info *hfinfo;
	guint8 *pVal;

	pVal=dissect_mqpcf_parm_getintval(uPrm,uVal);
	hfinfo=proto_registrar_get_nth(hfindex);

	if (pVal)
	{
		proto_tree_add_none_format(tree, hfindex, tvb, offset , 4, "%s:%d-%s",
			hfinfo->name, uVal, pVal);
	}
	else
	{
		proto_tree_add_none_format(tree, hfindex, tvb, offset , 4, "%s:%8x-%d",
			hfinfo->name, uVal, uVal);
	}
}

static void dissect_mqpcf_parm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mq_tree, guint offset,guint32 uCount,guint bLittleEndian)
{
	guint32 u=0;
	guint32 tOfs=0;
	guint32 uLenF;
	char strPrm[256];
	guint32 uTyp;
	guint32 uLen = 0;
	guint32 uPrm;
	guint32 uCnt;
	guint32 uCCS;
	guint32 uSLn;
	guint32 uVal;
	guint64 uVal64;

	const char sMaxLst[] = " Max # of List reached. DECODE interrupted   (actual %u of %u)";
	const char sPrmLn0[] = " MQPrm[%3u] has a zero length. DECODE Failed (MQPrm Count: %u)";
	const char sMaxPrm[] = " Max # of Parm reached. DECODE interrupted   (actual %u of %u)";

	proto_item *ti=NULL;
	proto_tree *tree=NULL;

	for (u=0;u<uCount && u<mq_pcf_maxprm;u++)
	{
		tOfs=offset;
		uTyp=tvb_get_guint32_endian(tvb, offset, bLittleEndian);
		uLen=tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
		if (uLen==0)
		{
			ti = proto_tree_add_text(mq_tree, tvb, offset, 12, sPrmLn0, u+1, uCount);
			expert_add_info(pinfo, ti, &ei_mq_pcf_prmln0);
			u=uCount;
			break;
		}
		uPrm=tvb_get_guint32_endian(tvb, offset + 8, bLittleEndian);
		uLenF=12;

		g_snprintf(strPrm,(gulong)sizeof(strPrm)-1," %-s[%3u] {%1d-%-15.15s} %8x/%5d-%-30.30s",
			"MQPrm",u+1,
			uTyp,val_to_str_const(uTyp,GET_VALSV(PrmTyp),"      Unknown")+6,
			uPrm,uPrm,val_to_str_const(uPrm,GET_VALSV(PrmId),"Unknown"));

		switch (uTyp)
		{
		case MQ_MQCFT_NONE:
			break;
		case MQ_MQCFT_COMMAND:
			break;
		case MQ_MQCFT_RESPONSE:
			break;
		case MQ_MQCFT_INTEGER:
			{
				guint8 *pVal;
				uVal=tvb_get_guint32_endian(tvb, offset+uLenF, bLittleEndian);
				pVal=dissect_mqpcf_parm_getintval(uPrm,uVal);
				if (pVal)
				{
					ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %d-%s",
						strPrm,uVal,pVal);
				}
				else
				{
					ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %8x-%d",
						strPrm,uVal,uVal);
				}
				tree = proto_item_add_subtree(ti, ett_mqpcf_prm);
				proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmid, tvb, offset + 8, 4, bLittleEndian);

				dissect_mqpcf_parm_int(tvb, tree, offset+uLenF, uPrm, uVal, hf_mq_pcf_int);

				offset+=uLenF+4;
			}
			break;
		case MQ_MQCFT_STRING:
			{
				guint8 *sStr;

				uCCS=tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
				uSLn=tvb_get_guint32_endian(tvb, offset + uLenF + 4, bLittleEndian);
				sStr=tvb_get_ephemeral_string_enc(tvb, offset + uLenF + 8,uSLn,(uCCS!=500)?ENC_ASCII:ENC_EBCDIC);
				strip_trailing_blanks(sStr,uSLn);

				ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %s", strPrm, sStr);
				tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

				proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmid, tvb, offset + 8, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmccsid, tvb, offset + 12, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 16, 4, bLittleEndian);

				proto_tree_add_item(tree, hf_mq_pcf_string, tvb, offset + uLenF + 8, uSLn, (uCCS!=500)?ENC_ASCII:ENC_EBCDIC);

				offset+=uLenF+8+uSLn;
			}
			break;
		case MQ_MQCFT_INTEGER_LIST:
			{
				guint32 u2;

				uCnt=tvb_get_guint32_endian(tvb, offset+uLenF, bLittleEndian);
				ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s Cnt(%d)",strPrm,uCnt);
				tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

				proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmid, tvb, offset + 8, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 12, 4, bLittleEndian);

				offset+=uLenF+4;
				for (u2=0;u2<uCnt && u2<mq_pcf_maxlst;u2++)
				{
					uVal=tvb_get_guint32_endian(tvb, offset, bLittleEndian);
					dissect_mqpcf_parm_int(tvb, tree, offset, uPrm, uVal, hf_mq_pcf_intlist);
					offset+=4;
				}
				if (u2!=uCnt)
				{
					ti = proto_tree_add_text(tree, tvb, offset, uLen, sMaxLst, u2, uCnt);
					expert_add_info(pinfo, ti, &ei_mq_pcf_MaxInt);
				}
			}
			break;
		case MQ_MQCFT_STRING_LIST:
			{
				guint32 u2;

				uCCS=tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
				uCnt=tvb_get_guint32_endian(tvb, offset + uLenF + 4, bLittleEndian);
				uSLn=tvb_get_guint32_endian(tvb, offset + uLenF + 8, bLittleEndian);

				ti = proto_tree_add_text(mq_tree, tvb, offset, uLen,"%s Cnt(%d)",strPrm,uCnt);

				tree = proto_item_add_subtree(ti, ett_mqpcf_prm);
				proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmid, tvb, offset + 8, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmccsid, tvb, offset + 12, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 16, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 20, 4, bLittleEndian);

				offset+=uLenF+12;
				for (u2=0;u2<uCnt && u2<mq_pcf_maxlst;u2++)
				{
					proto_tree_add_item(tree, hf_mq_pcf_stringlist, tvb, offset , uSLn, (uCCS!=500)?ENC_ASCII:ENC_EBCDIC);
					offset+=uSLn;
				}
				if (u2!=uCnt)
				{
					ti = proto_tree_add_text(tree, tvb, offset, uLen, sMaxLst, u2, uCnt);
					expert_add_info(pinfo, ti, &ei_mq_pcf_MaxStr);
				}
			}
			break;
		case MQ_MQCFT_EVENT:
			break;
		case MQ_MQCFT_USER:
			break;
		case MQ_MQCFT_BYTE_STRING:
			{
				uSLn=tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
				if (uSLn)
				{
					guint8 *sStrA=tvb_get_ephemeral_string_enc(tvb, offset + uLenF + 4,uSLn,ENC_ASCII);
					guint8 *sStrE=tvb_get_ephemeral_string_enc(tvb, offset + uLenF + 4,uSLn,ENC_EBCDIC);
					ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s A(%s) E(%s)", strPrm, sStrA,sStrE);
				}
				else
				{
					ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s <MISSING>", strPrm);
				}
				tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

				proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmid, tvb, offset + 8, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 12, 4, bLittleEndian);

				proto_tree_add_item(tree, hf_mq_pcf_bytestring, tvb, offset + uLenF + 4 , uSLn,bLittleEndian);

				offset+=uLenF+4+uSLn;
			}
			break;
		case MQ_MQCFT_TRACE_ROUTE:
			break;
		case MQ_MQCFT_REPORT:
			break;
		case MQ_MQCFT_INTEGER_FILTER:
			break;
		case MQ_MQCFT_STRING_FILTER:
			break;
		case MQ_MQCFT_BYTE_STRING_FILTER:
			break;
		case MQ_MQCFT_COMMAND_XR:
			break;
		case MQ_MQCFT_XR_MSG:
			break;
		case MQ_MQCFT_XR_ITEM:
			break;
		case MQ_MQCFT_XR_SUMMARY:
			break;
		case MQ_MQCFT_GROUP:
			break;
		case MQ_MQCFT_STATISTICS:
			break;
		case MQ_MQCFT_ACCOUNTING:
			break;
		case MQ_MQCFT_INTEGER64:
			{
				uVal64=tvb_get_guint64_endian(tvb, offset+4, bLittleEndian);
				ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "d)",
					strPrm, uVal64, uVal64);
				tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

				proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmid, tvb, offset + 8, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmunused, tvb, offset + 12, 4, bLittleEndian);

				proto_tree_add_item(tree, hf_mq_pcf_int64, tvb, offset + uLenF + 4, 8, bLittleEndian);

				offset+=uLenF+4+8;
			}
			break;
		case MQ_MQCFT_INTEGER64_LIST:
			{
				guint32 u2;
				uCnt=tvb_get_guint32_endian(tvb, offset, bLittleEndian);
				ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s Cnt(%d)",strPrm,uCnt);
				tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

				proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmid, tvb, offset + 8, 4, bLittleEndian);
				proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 12, 4, bLittleEndian);

				offset+=uLenF+4;
				for (u2=0;u2<uCnt && u2<mq_pcf_maxlst;u2++)
				{
					proto_tree_add_item(tree, hf_mq_pcf_int64list, tvb, offset, 8, bLittleEndian);
					offset+=8;
				}
				if (u2!=uCnt)
				{
					ti = proto_tree_add_text(tree, tvb, offset, uLen, sMaxLst, u2, uCnt);
					expert_add_info(pinfo, ti, &ei_mq_pcf_MaxI64);
				}
			}
			break;
		}
		offset=tOfs+uLen;
	}
	if (u!=uCount)
	{
		ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, sMaxPrm, u, uCount);
		expert_add_info(pinfo, ti, &ei_mq_pcf_MaxPrm);
	}
}
static void dissect_mqpcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	struct mqinfo* mqinfo = (struct mqinfo *)pinfo->private_data;
	gboolean bLittleEndian;

	bLittleEndian = ((mqinfo->encoding & MQ_MQENC_INTEGER_MASK)==MQ_MQENC_INTEGER_REVERSED)?ENC_LITTLE_ENDIAN:ENC_BIG_ENDIAN;

	if (tvb_length(tvb) >= 36)
	{
		gint iSizeMQCFH = 36;
		guint32 iCommand = tvb_get_guint32_endian(tvb, offset + 12, bLittleEndian);

		if (tree)
		{
			proto_item	*ti = NULL;
			proto_tree	*mq_tree = NULL;
			proto_tree	*mqroot_tree = NULL;
			guint32 uCount;

			ti = proto_tree_add_item(tree, proto_mqpcf, tvb, offset, -1, ENC_NA);
			proto_item_append_text(ti, " (%s)", val_to_str(iCommand, mq_mqcmd_vals, "Unknown (0x%02x)"));
			mqroot_tree = proto_item_add_subtree(ti, ett_mqpcf);

			ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeMQCFH, MQ_TEXT_CFH);
			mq_tree = proto_item_add_subtree(ti, ett_mqpcf_cfh);

			uCount=tvb_get_guint32_endian(tvb, offset+32, bLittleEndian);     /* Count of parameter structures */

			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_type, tvb, offset + 0, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_length, tvb, offset + 4, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_version, tvb, offset + 8, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_command, tvb, offset + 12, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_msgseqnumber, tvb, offset + 16, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_control, tvb, offset + 20, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_compcode, tvb, offset + 24, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_reason, tvb, offset + 28, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_paramcount, tvb, offset + 32, 4, bLittleEndian);
			dissect_mqpcf_parm(tvb, pinfo, mqroot_tree, offset + iSizeMQCFH, uCount, bLittleEndian);
		}
	}
}

static gboolean dissect_mqpcf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if (tvb_length(tvb) >= 36)
	{
		struct mqinfo* mqinfo = (struct mqinfo *)pinfo->private_data;
		if (strncmp((const char*)mqinfo->format, MQ_MQFMT_ADMIN, 8) == 0
			|| strncmp((const char*)mqinfo->format, MQ_MQFMT_EVENT, 8) == 0
			|| strncmp((const char*)mqinfo->format, MQ_MQFMT_PCF, 8) == 0)
		{
			/* Dissect the packet */
			dissect_mqpcf(tvb, pinfo, tree);
			return TRUE;
		}
	}
	return FALSE;
}

void proto_register_mqpcf(void)
{
	expert_module_t* expert_mqpcf;

	static hf_register_info hf[] = {
		{ &hf_mqpcf_cfh_type    , { "Type....", "mqpcf.cfh.type", FT_UINT32, BASE_DEC, VALS(&GET_VALSV(mqcft)), 0x0, "CFH type", HFILL }},
		{ &hf_mqpcf_cfh_length  , { "Length..", "mqpcf.cfh.length", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH length", HFILL }},
		{ &hf_mqpcf_cfh_version , { "Version.", "mqpcf.cfh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH version", HFILL }},
		{ &hf_mqpcf_cfh_command , { "Command.", "mqpcf.cfh.command", FT_UINT32, BASE_DEC, VALS(&GET_VALSV(mqcmd)), 0x0, "CFH command", HFILL }},
		{ &hf_mqpcf_cfh_msgseqnumber, { "MsgSeqNr", "mqpcf.cfh.msgseqnumber", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH message sequence number", HFILL }},
		{ &hf_mqpcf_cfh_control , { "Control.", "mqpcf.cfh.control", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH control", HFILL }},
		{ &hf_mqpcf_cfh_compcode, { "CompCode", "mqpcf.cfh.compcode", FT_UINT32, BASE_DEC, VALS(&GET_VALSV(mqcc)), 0x0, "CFH completion code", HFILL }},
		{ &hf_mqpcf_cfh_reason  , { "ReasCode", "mqpcf.cfh.reasoncode", FT_UINT32, BASE_DEC, VALS(&GET_VALSV(mqrc)), 0x0, "CFH reason code", HFILL }},
		{ &hf_mqpcf_cfh_paramcount, { "ParmCnt.", "mqpcf.cfh.paramcount", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH parameter count", HFILL }},
		{ &hf_mq_pcf_prmtyp     , { "PrmTyp..", "mqpcf.parm.type", FT_UINT32, BASE_DEC, VALS(&GET_VALSV(PrmTyp)), 0x0, "MQPCF parameter type", HFILL }},
		{ &hf_mq_pcf_prmlen     , { "PrmLen..", "mqpcf.parm.len", FT_UINT32, BASE_DEC, NULL, 0x0, "MQPCF parameter length", HFILL }},
		{ &hf_mq_pcf_prmid      , { "PrmID...", "mqpcf.parm.id", FT_UINT32, BASE_DEC, VALS(&GET_VALSV(PrmId)), 0x0, "MQPCF parameter id", HFILL }},
		{ &hf_mq_pcf_prmccsid   , { "PrmCCSID", "mqpcf.parm.ccsid", FT_UINT32, BASE_DEC, NULL, 0x0, "MQPCF parameter ccsid", HFILL }},
		{ &hf_mq_pcf_prmstrlen  , { "PrmStrLn", "mqpcf.parm.strlen", FT_UINT32, BASE_DEC, NULL, 0x0, "MQPCF parameter strlen", HFILL }},
		{ &hf_mq_pcf_prmcount   , { "PrmCount", "mqpcf.parm.count", FT_UINT32, BASE_DEC, NULL, 0x0, "MQPCF parameter count", HFILL }},
		{ &hf_mq_pcf_prmunused  , { "PrmUnuse", "mqpcf.parm.unused", FT_UINT32, BASE_DEC, NULL, 0x0, "MQPCF parameter unused", HFILL }},
		{ &hf_mq_pcf_string     , { "String..", "mqpcf.parm.string", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MQPCF parameter string", HFILL }},
		{ &hf_mq_pcf_stringlist , { "StrList..", "mqpcf.parm.stringlist", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MQPCF parameter string list", HFILL }},
		{ &hf_mq_pcf_int        , { "Integer.", "mqpcf.parm.int", FT_NONE, BASE_NONE, NULL, 0x0, "MQPCF parameter int", HFILL }},
		{ &hf_mq_pcf_intlist    , { "IntList.", "mqpcf.parm.intlist", FT_NONE, BASE_NONE, NULL, 0x0, "MQPCF parameter int list", HFILL }},
		{ &hf_mq_pcf_bytestring , { "ByteStr..", "mqpcf.parm.bytestring", FT_BYTES, BASE_NONE, NULL, 0x0, "MQPCF parameter byte string", HFILL }},
		{ &hf_mq_pcf_int64      , { "Int64...", "mqpcf.parm.int64", FT_UINT64, BASE_HEX | BASE_DEC, NULL, 0x0, "MQPCF parameter int64", HFILL }},
		{ &hf_mq_pcf_int64list  , { "Int64Lst", "mqpcf.parm.int64list", FT_UINT64, BASE_HEX | BASE_DEC, NULL, 0x0, "MQPCF parameter int64 list", HFILL }},
	};
	static gint *ett[] = {
		&ett_mqpcf,
		&ett_mqpcf_prm,
		&ett_mqpcf_cfh,
	};
	static ei_register_info ei[] = 
	{
        { &ei_mq_pcf_prmln0, { "mqpcf.parm.len0", PI_MALFORMED, PI_ERROR, "MQPCF Parameter length is 0", EXPFILL }},
		{ &ei_mq_pcf_MaxInt, { "mqpcf.parm.IntList", PI_UNDECODED, PI_WARN, "MQPCF Parameter Integer list exhausted", EXPFILL }},
		{ &ei_mq_pcf_MaxStr, { "mqpcf.parm.StrList", PI_UNDECODED, PI_WARN, "MQPCF Parameter String list exhausted", EXPFILL }},
		{ &ei_mq_pcf_MaxI64, { "mqpcf.parm.Int64List", PI_UNDECODED, PI_WARN, "MQPCF Parameter Int64 list exhausted", EXPFILL }},
		{ &ei_mq_pcf_MaxPrm, { "mqpcf.parm.MaxPrm", PI_UNDECODED, PI_WARN, "MQPCF Max number of parameter exhausted", EXPFILL }},
    };

	module_t *mq_pcf_module;

	proto_mqpcf = proto_register_protocol("WebSphere MQ Programmable Command Formats", "MQ PCF", "mqpcf");
	proto_register_field_array(proto_mqpcf, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_mqpcf = expert_register_protocol(proto_mqpcf);
    expert_register_field_array(expert_mqpcf, ei, array_length(ei));

	mq_pcf_module = prefs_register_protocol(proto_mqpcf, NULL);
	prefs_register_uint_preference(mq_pcf_module,"maxprm",
		"Set the maximun number of parameter in the PCF to decode",
		"When dissecting PCF there can be a lot of parameters."
		" You can limit the number of parameter decoded, before it continue with the next PCF.",
		10, &mq_pcf_maxprm);
	prefs_register_uint_preference(mq_pcf_module,"maxlst",
		"Set the maximun number of Parameter List that are displayed",
		"When dissecting a parameter of a PCFm, if it is a StringList, IntegerList or Integer64 List, "
		" You can limit the number of element displayed, before it continue with the next Parameter.",
		10, &mq_pcf_maxlst);

}

void proto_reg_handoff_mqpcf(void)
{
	heur_dissector_add("mq", dissect_mqpcf_heur, proto_mqpcf);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
