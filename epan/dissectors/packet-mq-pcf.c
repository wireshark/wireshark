/* packet-mq-pcf.c
 * Routines for IBM WebSphere MQ PCF packet dissection
 *
 * metatech <metatech@flashmail.com>
 * robionekenobi <robionekenobi@bluewin.ch>
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
#include <math.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/value_string.h>
#include <epan/strutil.h>
#include "packet-mq.h"
#include "wmem/wmem.h"

void proto_register_mqpcf(void);
void proto_reg_handoff_mqpcf(void);

#define PCF_MAX_PARM 999
#define PCF_MAX_LIST 20000

guint mq_pcf_maxprm = PCF_MAX_PARM;
guint mq_pcf_maxlst = PCF_MAX_LIST;

static int proto_mqpcf = -1;

static int hf_mqpcf_cfh_type = -1;
static int hf_mqpcf_cfh_length = -1;
static int hf_mqpcf_cfh_version = -1;
static int hf_mqpcf_cfh_command = -1;
static int hf_mqpcf_cfh_MsgSeqNbr = -1;
static int hf_mqpcf_cfh_control = -1;
static int hf_mqpcf_cfh_compcode = -1;
static int hf_mqpcf_cfh_reason = -1;
static int hf_mqpcf_cfh_ParmCount = -1;

static int hf_mq_pcf_prmtyp = -1;
static int hf_mq_pcf_prmlen = -1;
static int hf_mq_pcf_prmid = -1;
static int hf_mq_pcf_prmidnovals = -1;
static int hf_mq_pcf_filterop = -1;
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
static expert_field ei_mq_pcf_PrmCnt = EI_INIT;

static gint ett_mqpcf_prm = -1;
static gint ett_mqpcf = -1;
static gint ett_mqpcf_cfh = -1;

#define MQ_TEXT_CFH   "MQ Command Format Header"

static guint32 dissect_mqpcf_getDigits(guint uCnt)
{
    return (guint) log10(uCnt) + 1;
}
/*
* Here we get a special value_string, that return another value_string
* pointer instead of string value. This let us use the try_val_to_str
* to get val_to_str value from the value of a parameter on a more
* easier way than using switch cases
*/
static const guint8 *dissect_mqpcf_parm_getintval(guint uPrm, guint uVal)
{
    const value_string *pVs;
    pVs = (const value_string *)try_val_to_str(uPrm, GET_VALSV(MQCFINT_Parse));

    if (pVs)
    {
        return (const guint8 *)try_val_to_str(uVal, pVs);
    }
    return NULL;
}

static void dissect_mqpcf_parm_int(tvbuff_t *tvb, proto_tree *tree, guint offset, guint uPrm,
                            guint uVal, int hfindex, guint iCnt, guint iMaxCnt, guint iDigit, gboolean bParse)
{
    header_field_info *hfinfo;
    const guint8 *pVal = NULL;

    if (bParse)
        pVal = dissect_mqpcf_parm_getintval(uPrm, uVal);

    hfinfo = proto_registrar_get_nth(hfindex);

    if (iMaxCnt > 1)
    {
        if (pVal)
        {
            proto_tree_add_int_format(tree, hfindex, tvb, offset, 4, uVal,
                "%s[%*d]: %8d-%s", hfinfo->name, iDigit, iCnt, uVal, pVal);
        }
        else
        {
            proto_tree_add_int_format(tree, hfindex, tvb, offset, 4, uVal,
                "%s[%*d]: %8x-%d", hfinfo->name, iDigit, iCnt, uVal, uVal);
        }
    }
    else
    {
        if (pVal)
        {
            proto_tree_add_int_format_value(tree, hfindex, tvb, offset, 4, uVal,
                "%8d-%s", uVal, pVal);
        }
        else
        {
            proto_tree_add_int_format_value(tree, hfindex, tvb, offset, 4, uVal,
                "%8x-%d", uVal, uVal);
        }
    }
}

static void dissect_mqpcf_parm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mq_tree,
                               guint offset, guint32 uCount, guint bLittleEndian, gboolean bParse)
{
    guint32 u    = 0;
    guint32 tOfs = 0;
    guint32 uLenF;
    char    strPrm[256];
    guint32 uTyp;
    guint32 uLen = 0;
    guint32 uPrm;
    guint32 uCnt;
    guint32 uCCS;
    guint32 uSLn;
    guint32 uVal;
    guint64 uVal64;
    guint32 uDig;

    const char sMaxLst[] = " Max # of List reached. DECODE interrupted   (actual %u of %u)";
    const char sPrmLn0[] = " MQPrm[%3u] has a zero length. DECODE Failed (MQPrm Count: %u)";
    const char sMaxPrm[] = " Max # of Parm reached. DECODE interrupted   (actual %u of %u)";
    const char sPrmCnt[] = " Cnt=-1 and Length(%u) < 16. DECODE interrupted for elem %u";

    proto_item *ti   = NULL;
    proto_tree *tree = NULL;

    if (uCount == (guint32)-1)
    {
        guint32 xOfs = offset;

        uCnt = 0;
        while (tvb_length_remaining(tvb, xOfs) >= 16)
        {
            uLen = tvb_get_guint32_endian(tvb, xOfs + 4, bLittleEndian);
            if (uLen < 16)
            {
                ti = proto_tree_add_text(mq_tree, tvb, xOfs, 16, sPrmCnt, uLen, uCnt);
                expert_add_info(pinfo, ti, &ei_mq_pcf_PrmCnt);
                break;
            }
            uCnt++;
            xOfs += uLen;
        }
        uCount = uCnt;
    }

    uDig = dissect_mqpcf_getDigits(uCount);

    for (u = 0; u < uCount && u < mq_pcf_maxprm; u++)
    {
        tOfs = offset;
        uTyp = tvb_get_guint32_endian(tvb, offset    , bLittleEndian);
        uLen = tvb_get_guint32_endian(tvb, offset + 4, bLittleEndian);
        if (uLen == 0)
        {
            ti = proto_tree_add_text(mq_tree, tvb, offset, 12, sPrmLn0, u+1, uCount);
            expert_add_info(pinfo, ti, &ei_mq_pcf_prmln0);
            u = uCount;
            break;
        }
        uPrm = tvb_get_guint32_endian(tvb, offset + 8, bLittleEndian);
        uLenF = 12;

        if (bParse)
            g_snprintf(strPrm, (gulong)sizeof(strPrm) - 1, " %-s[%*u] {%2d-%-15.15s} %8x/%5d-%-30.30s",
                "MQPrm", uDig, u+1,
                uTyp, val_to_str_const(uTyp, GET_VALSV(PrmTyp), "      Unknown") + 6,
                uPrm, uPrm, val_to_str_const(uPrm, GET_VALSV(PrmId), "Unknown"));
        else
            g_snprintf(strPrm, (gulong)sizeof(strPrm) - 1, " %-s[%*u] {%2d-%-15.15s} %8x/%5d",
                "XtraD", uDig, u+1,
                uTyp, val_to_str_const(uTyp, GET_VALSV(PrmTyp), "      Unknown") + 6,
                uPrm, uPrm);

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
                const guint8 *pVal = NULL;
                uVal = tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
                if (bParse)
                    pVal = dissect_mqpcf_parm_getintval(uPrm, uVal);
                if (pVal)
                {
                    ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %d-%s",
                        strPrm, uVal, pVal);
                }
                else
                {
                    ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %8x-%d",
                        strPrm, uVal, uVal);
                }
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);
                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset    , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);

                dissect_mqpcf_parm_int(tvb, tree, offset+uLenF, uPrm, uVal, hf_mq_pcf_int, 0, 0, 0, bParse);
            }
            break;
        case MQ_MQCFT_STRING:
            {
                guint8 *sStr;

                uCCS = tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
                uSLn = tvb_get_guint32_endian(tvb, offset + uLenF + 4, bLittleEndian);
                sStr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + uLenF + 8,
                    uSLn, (uCCS != 500) ? ENC_ASCII : ENC_EBCDIC);
                if (*sStr)
                    strip_trailing_blanks(sStr, uSLn);
                if (*sStr)
                    format_text_chr(sStr, strlen(sStr), '.');

                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %s", strPrm, sStr);
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmccsid , tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 16, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_string, tvb, offset + uLenF + 8, uSLn, (uCCS != 500) ? ENC_ASCII : ENC_EBCDIC);
            }
            break;
        case MQ_MQCFT_INTEGER_LIST:
            {
                guint32 u2;
                guint32 uDigit = 0;

                uCnt = tvb_get_guint32_endian(tvb, offset+uLenF, bLittleEndian);
                uDigit = dissect_mqpcf_getDigits(uCnt);

                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s Cnt(%d)", strPrm, uCnt);
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp  , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen  , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 12, 4, bLittleEndian);

                offset += uLenF+4;
                for (u2 = 0; u2 < uCnt && u2 < mq_pcf_maxlst; u2++)
                {
                    uVal = tvb_get_guint32_endian(tvb, offset, bLittleEndian);
                    dissect_mqpcf_parm_int(tvb, tree, offset, uPrm, uVal, hf_mq_pcf_intlist, u2+1, uCnt, uDigit, bParse);
                    offset += 4;
                }
                if (u2 != uCnt)
                {
                    ti = proto_tree_add_text(tree, tvb, offset, uLen, sMaxLst, u2, uCnt);
                    expert_add_info(pinfo, ti, &ei_mq_pcf_MaxInt);
                }
            }
            break;
        case MQ_MQCFT_STRING_LIST:
            {
                guint32  u2;
                guint32  uDigit;
                guint8  *sStr;
                header_field_info *hfinfo;

                hfinfo = proto_registrar_get_nth(hf_mq_pcf_stringlist);

                uCCS = tvb_get_guint32_endian(tvb, offset + uLenF    , bLittleEndian);
                uCnt = tvb_get_guint32_endian(tvb, offset + uLenF + 4, bLittleEndian);
                uSLn = tvb_get_guint32_endian(tvb, offset + uLenF + 8, bLittleEndian);

                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s Cnt(%d)", strPrm, uCnt);

                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);
                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmccsid , tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmcount , tvb, offset + 16, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 20, 4, bLittleEndian);

                uDigit = dissect_mqpcf_getDigits(uCnt);

                offset += uLenF+12;
                for (u2 = 0; u2 < uCnt && u2 < mq_pcf_maxlst; u2++)
                {
                    sStr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset,
                        uSLn, (uCCS != 500) ? ENC_ASCII : ENC_EBCDIC);
                    if (*sStr)
                        strip_trailing_blanks(sStr, uSLn);
                    if (*sStr)
                        format_text_chr(sStr, strlen(sStr),  '.');

                    proto_tree_add_string_format(tree, hf_mq_pcf_stringlist, tvb, offset, uSLn, sStr,
                        "%s[%*d]: %s", hfinfo->name, uDigit, u2+1, sStr);
                    offset += uSLn;
                }
                if (u2 != uCnt)
                {
                    ti = proto_tree_add_text(tree, tvb, offset, uLen, sMaxLst, u2, uCnt);
                    expert_add_info(pinfo, ti, &ei_mq_pcf_MaxStr);
                }
            }
            break;
        case MQ_MQCFT_EVENT:
            break;
        case MQ_MQCFT_USER:
            {
                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s", strPrm);
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_bytestring, tvb, offset + 8, uLen - 8, bLittleEndian);
            }
            break;
        case MQ_MQCFT_BYTE_STRING:
            {
                uSLn = tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
                if (uSLn)
                {
                    guint8 *sStrA = format_text_chr(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + uLenF + 4, uSLn, ENC_ASCII) , uSLn, '.');
                    guint8 *sStrE = format_text_chr(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + uLenF + 4, uSLn, ENC_EBCDIC), uSLn, '.');
                    if (uSLn > 35)
                    {
                        ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s [Truncated] A(%-.35s) E(%-.35s)", strPrm, sStrA, sStrE);
                    }
                    else
                    {
                        ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s A(%s) E(%s)", strPrm, sStrA, sStrE);
                    }
                }
                else
                {
                    ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s <MISSING>", strPrm);
                }
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 12, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_bytestring, tvb, offset + uLenF + 4 , uSLn, bLittleEndian);
            }
            break;
        case MQ_MQCFT_TRACE_ROUTE:
            break;
        case MQ_MQCFT_REPORT:
            break;
        case MQ_MQCFT_INTEGER_FILTER:
            {
                guint32 uOpe;

                uOpe = tvb_get_guint32_endian(tvb, offset + uLenF    , bLittleEndian);
                uVal = tvb_get_guint32_endian(tvb, offset + uLenF + 4, bLittleEndian);

                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %s %d",
                    strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)")+7, uVal);
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_filterop , tvb, offset + 12, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_int, tvb, offset + uLenF + 4, 4, bLittleEndian);
            }
            break;
        case MQ_MQCFT_STRING_FILTER:
            {
                guint8 *sStr;
                guint32 uOpe;

                uOpe = tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
                uCCS = tvb_get_guint32_endian(tvb, offset + uLenF + 4, bLittleEndian);
                uSLn = tvb_get_guint32_endian(tvb, offset + uLenF + 8, bLittleEndian);
                sStr = format_text_chr(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + uLenF + 12, uSLn, (uCCS != 500) ? ENC_ASCII : ENC_EBCDIC), uSLn, '.');
                strip_trailing_blanks(sStr, uSLn);

                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %s %s",
                    strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)")+7, sStr);
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_filterop , tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmccsid , tvb, offset + 16, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 20, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_string, tvb, offset + uLenF + 12, uSLn, (uCCS != 500) ? ENC_ASCII : ENC_EBCDIC);
            }
            break;
        case MQ_MQCFT_BYTE_STRING_FILTER:
            {
                guint32 uOpe;
                uOpe = tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
                uSLn = tvb_get_guint32_endian(tvb, offset + uLenF + 4, bLittleEndian);
                if (uSLn)
                {
                    guint8 *sStrA = format_text_chr(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + uLenF + 8, uSLn, ENC_ASCII), uSLn, '.');
                    guint8 *sStrE = format_text_chr(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + uLenF + 8, uSLn, ENC_EBCDIC), uSLn, '.');
                    ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %s A(%s) E(%s)",
                        strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)")+7, sStrA, sStrE);
                }
                else
                {
                    ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %s <MISSING>",
                        strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)")+7);
                }
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_filterop , tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 16, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_bytestring, tvb, offset + uLenF + 8 , uSLn, bLittleEndian);
            }
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
                uVal64 = tvb_get_guint64_endian(tvb, offset + uLenF + 4, bLittleEndian);
                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s %" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "d)",
                    strPrm, uVal64, uVal64);
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp   , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen   , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmunused, tvb, offset + 12, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_int64, tvb, offset + uLenF + 4, 8, bLittleEndian);
            }
            break;
        case MQ_MQCFT_INTEGER64_LIST:
            {
                guint32 u2;
                guint32 uDigit;
                header_field_info *hfinfo;

                hfinfo = proto_registrar_get_nth(hf_mq_pcf_int64list);

                uCnt = tvb_get_guint32_endian(tvb, offset + uLenF, bLittleEndian);
                ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, "%s Cnt(%d)", strPrm, uCnt);
                tree = proto_item_add_subtree(ti, ett_mqpcf_prm);
                uDigit = dissect_mqpcf_getDigits(uCnt);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp  , tvb, offset     , 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen  , tvb, offset +  4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset +  8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 12, 4, bLittleEndian);

                offset += uLenF + 4;
                for (u2 = 0; u2 < uCnt && u2 < mq_pcf_maxlst; u2++)
                {
                    uVal64 = tvb_get_guint64_endian(tvb, offset, bLittleEndian);
                    proto_tree_add_int64_format(tree, hf_mq_pcf_int64list, tvb, offset, 8, uVal64,
                        "%s[%*d]: %" G_GINT64_MODIFIER "d", hfinfo->name, uDigit, u2+1, uVal64);
                    offset += 8;
                }
                if (u2 != uCnt)
                {
                    ti = proto_tree_add_text(tree, tvb, offset, uLen, sMaxLst, u2, uCnt);
                    expert_add_info(pinfo, ti, &ei_mq_pcf_MaxI64);
                }
            }
            break;
        }
        offset = tOfs+uLen;
    }
    if (u != uCount)
    {
        ti = proto_tree_add_text(mq_tree, tvb, offset, uLen, sMaxPrm, u, uCount);
        expert_add_info(pinfo, ti, &ei_mq_pcf_MaxPrm);
    }
}

static void dissect_mqpcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mq_parm_t* p_mq_parm)
{
    gint offset = 0;
    gboolean bLittleEndian;

    bLittleEndian = ((p_mq_parm->mq_cur_ccsid.encod & MQ_MQENC_INTEGER_MASK) == MQ_MQENC_INTEGER_REVERSED) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    if (tvb_length(tvb) >= 36)
    {
        gint iSizeMQCFH = 36;
        guint32 iCommand = tvb_get_guint32_endian(tvb, offset + 12, bLittleEndian);

        if (tree)
        {
            proto_item *ti;
            proto_tree *mq_tree;
            proto_tree *mqroot_tree;
            char        sTmp[256];
            guint32     uCnt;
            guint32     uTyp;
            guint32     uCmd;
            guint32     uCC;
            guint32     uRC;

            uTyp = tvb_get_guint32_endian(tvb, offset     , bLittleEndian);
            uCmd = tvb_get_guint32_endian(tvb, offset + 12, bLittleEndian);
            uCC  = tvb_get_guint32_endian(tvb, offset + 24, bLittleEndian);
            uRC  = tvb_get_guint32_endian(tvb, offset + 28, bLittleEndian);
            uCnt = tvb_get_guint32_endian(tvb, offset + 32, bLittleEndian);

            if (uCC || uRC)
            {
                g_snprintf(sTmp, (gulong)sizeof(sTmp)-1, " %-s [%d-%s] {%d-%s} PrmCnt(%d) CC(%d-%s) RC(%d-%s)",
                    MQ_TEXT_CFH,
                    uTyp, val_to_str_const(uTyp, GET_VALSV(mqcft), "Unknown"),
                    uCmd, val_to_str_const(uCmd, GET_VALSV(mqcmd), "Unknown"),
                    uCnt,
                    uCC, val_to_str_const(uCC, GET_VALSV(mqcc), "Unknown"),
                    uRC, val_to_str_const(uRC, GET_VALSV(mqrc), "Unknown"));
            }
            else
            {
                g_snprintf(sTmp, (gulong)sizeof(sTmp)-1, " %-s [%d-%s] {%d-%s} PrmCnt(%d)",
                    MQ_TEXT_CFH,
                    uTyp, val_to_str_const(uTyp, GET_VALSV(mqcft), "Unknown"),
                    uCmd, val_to_str_const(uCmd, GET_VALSV(mqcmd), "Unknown"),
                    uCnt);
            }

            ti = proto_tree_add_item(tree, proto_mqpcf, tvb, offset, -1, ENC_NA);

            proto_item_append_text(ti, " (%s)", val_to_str(iCommand, GET_VALSV(mqcmd), "Unknown (0x%02x)"));
            mqroot_tree = proto_item_add_subtree(ti, ett_mqpcf);

            ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeMQCFH, "%s", sTmp);
            mq_tree = proto_item_add_subtree(ti, ett_mqpcf_cfh);

            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_type     , tvb, offset +  0, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_length   , tvb, offset +  4, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_version  , tvb, offset +  8, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_command  , tvb, offset + 12, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_MsgSeqNbr, tvb, offset + 16, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_control  , tvb, offset + 20, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_compcode , tvb, offset + 24, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_reason   , tvb, offset + 28, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_ParmCount, tvb, offset + 32, 4, bLittleEndian);
            dissect_mqpcf_parm(tvb, pinfo, mqroot_tree, offset + iSizeMQCFH, uCnt, bLittleEndian, TRUE);
        }
    }
}

static gboolean dissect_mqpcf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (data && tvb_length(tvb) >= 36)
    {
        mq_parm_t *p_mq_parm = (mq_parm_t *)data;
        if (strncmp((const char*)p_mq_parm->mq_format, MQ_MQFMT_ADMIN, 8) == 0
            || strncmp((const char*)p_mq_parm->mq_format, MQ_MQFMT_EVENT, 8) == 0
            || strncmp((const char*)p_mq_parm->mq_format, MQ_MQFMT_PCF, 8) == 0)
        {
            /* Dissect the packet */
            dissect_mqpcf(tvb, pinfo, tree, p_mq_parm);
            return TRUE;
        }
        if (strncmp((const char *)p_mq_parm->mq_format, "LPOO", 4) == 0)
        {
            gboolean bLittleEndian;
            bLittleEndian = ((p_mq_parm->mq_cur_ccsid.encod & MQ_MQENC_INTEGER_MASK) == MQ_MQENC_INTEGER_REVERSED) ? ENC_LITTLE_ENDIAN:ENC_BIG_ENDIAN;
            dissect_mqpcf_parm(tvb, pinfo, tree, 0, (guint32)-1, bLittleEndian, FALSE);
            return TRUE;
        }
    }
    return FALSE;
}

void proto_register_mqpcf(void)
{
    expert_module_t *expert_mqpcf;

    static hf_register_info hf[] =
    {
        { &hf_mqpcf_cfh_type     , { "Type.....", "mqpcf.cfh.type"      , FT_UINT32, BASE_DEC, VALS(mq_mqcft_vals), 0x0, "CFH type", HFILL }},
        { &hf_mqpcf_cfh_length   , { "Length...", "mqpcf.cfh.length"    , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH length", HFILL }},
        { &hf_mqpcf_cfh_version  , { "Version..", "mqpcf.cfh.version"   , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH version", HFILL }},
        { &hf_mqpcf_cfh_command  , { "Command..", "mqpcf.cfh.command"   , FT_UINT32, BASE_DEC, VALS(mq_mqcmd_vals), 0x0, "CFH command", HFILL }},
        { &hf_mqpcf_cfh_MsgSeqNbr, { "MsgSeqNbr", "mqpcf.cfh.MsgSeqNbr" , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH message sequence number", HFILL }},
        { &hf_mqpcf_cfh_control  , { "Control..", "mqpcf.cfh.control"   , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH control", HFILL }},
        { &hf_mqpcf_cfh_compcode , { "CompCode.", "mqpcf.cfh.compcode"  , FT_UINT32, BASE_DEC, VALS(mq_mqcc_vals), 0x0, "CFH completion code", HFILL }},
        { &hf_mqpcf_cfh_reason   , { "ReasCode.", "mqpcf.cfh.reasoncode", FT_UINT32, BASE_DEC, VALS(mq_mqrc_vals), 0x0, "CFH reason code", HFILL }},
        { &hf_mqpcf_cfh_ParmCount, { "ParmCount", "mqpcf.cfh.ParmCount" , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH parameter count", HFILL }},

        { &hf_mq_pcf_prmtyp      , { "ParmTyp..", "mqpcf.parm.type"      , FT_UINT32 , BASE_DEC, VALS(mq_PrmTyp_vals), 0x0, "MQPCF parameter type", HFILL }},
        { &hf_mq_pcf_prmlen      , { "ParmLen..", "mqpcf.parm.len"       , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter length", HFILL }},
        { &hf_mq_pcf_prmid       , { "ParmID...", "mqpcf.parm.id"        , FT_UINT32 , BASE_DEC, VALS(mq_PrmId_vals), 0x0, "MQPCF parameter id", HFILL }},
        { &hf_mq_pcf_prmidnovals , { "ParmID...", "mqpcf.parm.idNoVals"  , FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "MQPCF parameter id No Vals", HFILL }},
        { &hf_mq_pcf_filterop    , { "FilterOP.", "mqpcf.filter.op"      , FT_UINT32 , BASE_DEC, VALS(mq_FilterOP_vals), 0x0, "MQPCF Filter operator", HFILL }},
        { &hf_mq_pcf_prmccsid    , { "ParmCCSID", "mqpcf.parm.ccsid"     , FT_UINT32 , BASE_DEC | BASE_RANGE_STRING, RVALS(mq_ccsid_rvals), 0x0, "MQPCF parameter ccsid", HFILL }},
        { &hf_mq_pcf_prmstrlen   , { "ParmStrLn", "mqpcf.parm.strlen"    , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter strlen", HFILL }},
        { &hf_mq_pcf_prmcount    , { "ParmCount", "mqpcf.parm.count"     , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter count", HFILL }},
        { &hf_mq_pcf_prmunused   , { "ParmUnuse", "mqpcf.parm.unused"    , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter unused", HFILL }},
        { &hf_mq_pcf_string      , { "String...", "mqpcf.parm.string"    , FT_STRINGZ, BASE_NONE, NULL, 0x0, "MQPCF parameter string", HFILL }},
        { &hf_mq_pcf_stringlist  , { "StrList..", "mqpcf.parm.stringlist", FT_STRINGZ, BASE_NONE, NULL, 0x0, "MQPCF parameter string list", HFILL }},
        { &hf_mq_pcf_int         , { "Integer..", "mqpcf.parm.int"       , FT_INT32  , BASE_DEC, NULL, 0x0, "MQPCF parameter int", HFILL }},
        { &hf_mq_pcf_intlist     , { "IntList..", "mqpcf.parm.intlist"   , FT_INT32  , BASE_DEC, NULL, 0x0, "MQPCF parameter int list", HFILL }},
        { &hf_mq_pcf_bytestring  , { "ByteStr..", "mqpcf.parm.bytestring", FT_BYTES  , BASE_NONE, NULL, 0x0, "MQPCF parameter byte string", HFILL }},
        { &hf_mq_pcf_int64       , { "Int64....", "mqpcf.parm.int64"     , FT_INT64  , BASE_DEC, NULL, 0x0, "MQPCF parameter int64", HFILL }},
        { &hf_mq_pcf_int64list   , { "Int64List", "mqpcf.parm.int64list" , FT_INT64  , BASE_DEC, NULL, 0x0, "MQPCF parameter int64 list", HFILL }},
    };
    static gint *ett[] =
    {
        &ett_mqpcf,
        &ett_mqpcf_prm,
        &ett_mqpcf_cfh,
    };
    static ei_register_info ei[] =
    {
        { &ei_mq_pcf_prmln0, { "mqpcf.parm.len0"     , PI_MALFORMED, PI_ERROR, "MQPCF Parameter length is 0", EXPFILL }},
        { &ei_mq_pcf_MaxInt, { "mqpcf.parm.IntList"  , PI_UNDECODED, PI_WARN , "MQPCF Parameter Integer list exhausted", EXPFILL }},
        { &ei_mq_pcf_MaxStr, { "mqpcf.parm.StrList"  , PI_UNDECODED, PI_WARN , "MQPCF Parameter String list exhausted", EXPFILL }},
        { &ei_mq_pcf_MaxI64, { "mqpcf.parm.Int64List", PI_UNDECODED, PI_WARN , "MQPCF Parameter Int64 list exhausted", EXPFILL }},
        { &ei_mq_pcf_MaxPrm, { "mqpcf.parm.MaxPrm"   , PI_UNDECODED, PI_WARN , "MQPCF Max number of parameter exhausted", EXPFILL }},
        { &ei_mq_pcf_PrmCnt, { "mqpcf.parm.PrmCnt"   , PI_UNDECODED, PI_WARN , "MQPCF Unkn Parm Cnt Length invalid", EXPFILL }},
    };

    module_t *mq_pcf_module;

    proto_mqpcf = proto_register_protocol("WebSphere MQ Programmable Command Formats", "MQ PCF", "mqpcf");
    proto_register_field_array(proto_mqpcf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_mqpcf = expert_register_protocol(proto_mqpcf);
    expert_register_field_array(expert_mqpcf, ei, array_length(ei));

    mq_pcf_module = prefs_register_protocol(proto_mqpcf, NULL);
    prefs_register_uint_preference(mq_pcf_module, "maxprm",
        "Set the maximun number of parameter in the PCF to decode",
        "When dissecting PCF there can be a lot of parameters."
        " You can limit the number of parameter decoded, before it continue with the next PCF.",
        10, &mq_pcf_maxprm);
    prefs_register_uint_preference(mq_pcf_module, "maxlst",
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
 * Editor modelines - http://www.wireshark.org/tools/modelines.html
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
