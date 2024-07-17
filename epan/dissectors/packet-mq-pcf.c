/* packet-mq-pcf.c
 * Routines for IBM WebSphere MQ PCF packet dissection
 *
 * metatech <metatech@flashmail.com>
 * Robert Grange <robionekenobi@bluewin.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*  MQ PCF in a nutshell
  *
  *   The MQ Programmable Command Formats API allows remotely configuring a queue manager.
  *
  *   MQ PCF documentation is called "WebSphere MQ Programmable Command Formats and Administration Interface"
  *   Formats and Administration Interface"
  *
  *   See:
  *
  *       ftp://public.dhe.ibm.com/software/integration/wmq/docs/V7.0/PDFs/V7.0_2008/csqzak11.pdf
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

#include "packet-mq.h"

void proto_register_mqpcf(void);
void proto_reg_handoff_mqpcf(void);

#define PCF_MAX_PARM 999
#define PCF_MAX_LIST 20000

static unsigned mq_pcf_maxprm = PCF_MAX_PARM;
static unsigned mq_pcf_maxlst = PCF_MAX_LIST;

static int proto_mqpcf;

static int hf_mqpcf_cfh_type;
static int hf_mqpcf_cfh_length;
static int hf_mqpcf_cfh_version;
static int hf_mqpcf_cfh_command;
static int hf_mqpcf_cfh_MsgSeqNbr;
static int hf_mqpcf_cfh_control;
static int hf_mqpcf_cfh_compcode;
static int hf_mqpcf_cfh_reason;
static int hf_mqpcf_cfh_ParmCount;

static int hf_mq_pcf_prmtyp;
static int hf_mq_pcf_prmlen;
static int hf_mq_pcf_prmid;
static int hf_mq_pcf_prmidnovals;
static int hf_mq_pcf_filterop;
static int hf_mq_pcf_prmccsid;
static int hf_mq_pcf_prmstrlen;
static int hf_mq_pcf_prmcount;
static int hf_mq_pcf_prmunused;

static int hf_mq_pcf_string;
static int hf_mq_pcf_stringlist;
static int hf_mq_pcf_int;
static int hf_mq_pcf_intlist;
static int hf_mq_pcf_bytestring;
static int hf_mq_pcf_int64;
static int hf_mq_pcf_int64list;

static expert_field ei_mq_pcf_hdrlne;
static expert_field ei_mq_pcf_prmln0;
static expert_field ei_mq_pcf_MaxInt;
static expert_field ei_mq_pcf_MaxStr;
static expert_field ei_mq_pcf_MaxI64;
static expert_field ei_mq_pcf_MaxPrm;
static expert_field ei_mq_pcf_PrmCnt;

static int ett_mqpcf_prm;
static int ett_mqpcf_grp;
static int ett_mqpcf;
static int ett_mqpcf_cfh;

#define MQ_TEXT_CFH   "MQ Command Format Header"

static uint32_t dissect_mqpcf_getDigits(unsigned uCnt)
{
    return (uint32_t)(log10((double)uCnt) + 1);
}
/*
* Here we get a special value_string, that return another value_string
* pointer instead of string value. This let us use the try_val_to_str
* to get val_to_str value from the value of a parameter on a more
* easier way than using switch cases.
*/
const uint8_t *dissect_mqpcf_parm_getintval(unsigned uPrm, unsigned uVal)
{
    const value_string *pVs;
    pVs = (const value_string *)try_val_to_str_ext(uPrm, GET_VALS_EXTP(MQCFINT_Parse));

    if (pVs)
    {
        return (const uint8_t *)try_val_to_str(uVal, pVs);
    }
    return NULL;
}

static void dissect_mqpcf_parm_int(tvbuff_t *tvb, proto_tree *tree, unsigned offset, unsigned uPrm,
                                   unsigned uVal, int hfindex, unsigned iCnt, unsigned iMaxCnt,
                                   unsigned iDigit, bool bParse)
{
    header_field_info *hfinfo;
    const uint8_t *pVal = NULL;

    if (bParse)
        pVal = dissect_mqpcf_parm_getintval(uPrm, uVal);

    hfinfo = proto_registrar_get_nth(hfindex);

    if (iMaxCnt > 1)
    {
        if (pVal)
        {
            proto_tree_add_int_format(tree, hfindex, tvb, offset, 4, uVal,
                                      "%s[%*d]: %s (%d)", hfinfo->name, iDigit, iCnt, pVal, uVal);
        }
        else
        {
            proto_tree_add_int_format(tree, hfindex, tvb, offset, 4, uVal,
                                      "%s[%*d]: 0x%08x (%d)", hfinfo->name, iDigit, iCnt, uVal, uVal);
        }
    }
    else
    {
        if (pVal)
        {
            proto_tree_add_int_format_value(tree, hfindex, tvb, offset, 4, uVal,
                                            "%s (%d) ", pVal, uVal);
        }
        else
        {
            proto_tree_add_int_format_value(tree, hfindex, tvb, offset, 4, uVal,
                                            "0x%08x (%d)", uVal, uVal);
        }
    }
}

// NOLINTNEXTLINE(misc-no-recursion)
int dissect_mqpcf_parm_grp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* mq_tree,
    unsigned offset, unsigned bLittleEndian, bool bParse)
{
    uint32_t uLen = 0;
    uint32_t uCnt = 0;

    uLen = tvb_get_uint32(tvb, offset + 4, bLittleEndian);
    uCnt = tvb_get_uint32(tvb, offset + 12, bLittleEndian);

    dissect_mqpcf_parm(tvb, pinfo, mq_tree, offset + uLen, uCnt, bLittleEndian, bParse);
    offset += uLen;
    for (uint32_t u = 0; u < uCnt; u++)
    {
        offset += tvb_get_uint32(tvb, offset + 4, bLittleEndian);
    }
    offset -= uLen;

    return offset;
}

// NOLINTNEXTLINE(misc-no-recursion)
uint32_t dissect_mqpcf_parm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mq_tree,
    unsigned offset, uint32_t uCount, unsigned bLittleEndian, bool bParse)
{
    uint32_t u = 0;
    uint32_t tOfs = 0;
    uint32_t uLenF;
    char    strPrm[256];
    uint32_t uTyp;
    uint32_t uLen = 0;
    uint32_t uMax = 0;
    uint32_t uPrm;
    uint32_t uCnt;
    uint32_t uCCS;
    uint32_t uSLn;
    uint32_t uVal;
    uint64_t uVal64;
    uint32_t uDig;
    uint32_t _offset = offset;

    static const char *sMaxLst = " Max # of List reached. DECODE interrupted   (actual %u of %u)";
    static const char *sPrmLn0 = " MQPrm[%3u] has a zero length. DECODE Failed (MQPrm Count: %u)";
    static const char *sHdrLne = " MQPrm[%3u] PCF Header not enough remaining bytes in pdu. DECODE Failed (MQPrm Count: %u)";
    static const char *sMaxPrm = " Max # of Parm reached. DECODE interrupted   (actual %u of %u)";
    static const char *sPrmCnt = " Cnt=-1 and Length(%u) < 16. DECODE interrupted for elem %u";

    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    if (uCount == (uint32_t)-1)
    {
        uint32_t xOfs = offset;

        uCnt = 0;
        while (tvb_reported_length_remaining(tvb, xOfs) >= 16)
        {
            uLen = tvb_get_uint32(tvb, xOfs + 4, bLittleEndian);
            if (uLen < 16)
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_mq_pcf_PrmCnt, tvb, xOfs, 16, sPrmCnt, uLen, uCnt);
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
        uMax = (unsigned)tvb_reported_length_remaining(tvb, tOfs);
        if (uMax < 12)
        {
            proto_tree_add_expert_format(tree, pinfo, &ei_mq_pcf_hdrlne, tvb, offset, 12, sHdrLne, u + 1, uCount);
            u = uCount;
            break;
        }
        uTyp = tvb_get_uint32(tvb, offset, bLittleEndian);
        uLen = tvb_get_uint32(tvb, offset + 4, bLittleEndian);
        if (uLen == 0)
        {
            proto_tree_add_expert_format(tree, pinfo, &ei_mq_pcf_prmln0, tvb, offset, 12, sPrmLn0, u + 1, uCount);
            u = uCount;
            break;
        }
        /* Try to decode as much as possible value */
        uLen = MIN(uLen, uMax);

        uPrm = tvb_get_uint32(tvb, offset + 8, bLittleEndian);
        uLenF = 12;

        if (bParse)
            snprintf(strPrm, sizeof(strPrm) - 1, " %-s[%*u] {%2d-%-4.4s} 0x%08x (%4d) %-30.30s",
                       "MQPrm", uDig, u + 1,
                       uTyp, val_to_str_ext_const(uTyp, GET_VALS_EXTP(PrmTyp2), "      Unkn") + 6,
                       uPrm, uPrm, val_to_str_ext_const(uPrm, GET_VALS_EXTP(PrmId), "Unknown"));
        else
            snprintf(strPrm, sizeof(strPrm) - 1, " %-s[%*u] {%2d-%-4.4s} 0x%08x (%4d)",
                       "XtraD", uDig, u + 1,
                       uTyp, val_to_str_ext_const(uTyp, GET_VALS_EXTP(PrmTyp2), "      Unkn") + 6,
                       uPrm, uPrm);

        increment_dissection_depth(pinfo);
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
                const uint8_t *pVal = NULL;
                uVal = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                if (bParse)
                    pVal = dissect_mqpcf_parm_getintval(uPrm, uVal);

                if (pVal)
                {
                    tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL,
                                                         "%s: %s (%d)", strPrm, pVal, uVal);
                }
                else
                {
                    tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL,
                                                         "%s: 0x%08x (%d)", strPrm, uVal, uVal);
                }

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);

                dissect_mqpcf_parm_int(tvb, tree, offset + uLenF, uPrm, uVal, hf_mq_pcf_int, 0, 0, 0, bParse);
            }
            break;
            case MQ_MQCFT_STRING:
            {
                uint8_t *sStr;

                uCCS = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                uSLn = tvb_get_uint32(tvb, offset + uLenF + 4, bLittleEndian);
                sStr = tvb_get_string_enc(pinfo->pool, tvb, offset + uLenF + 8,
                                          uSLn, IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII);
                if (*sStr)
                    strip_trailing_blanks(sStr, uSLn);
                if (*sStr)
                    sStr = (uint8_t*)format_text_chr(pinfo->pool, sStr, strlen((const char *)sStr), '.');

                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s: %s", strPrm, sStr);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmccsid, tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 16, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_string, tvb, offset + uLenF + 8, uSLn, IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII);
            }
            break;
            case MQ_MQCFT_INTEGER_LIST:
            {
                uint32_t u2;
                uint32_t uDigit = 0;

                uCnt = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                uDigit = dissect_mqpcf_getDigits(uCnt);

                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, &ti, "%s-> contain %d Element(s)", strPrm, uCnt);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 12, 4, bLittleEndian);

                offset += uLenF + 4;
                for (u2 = 0; u2 < uCnt && u2 < mq_pcf_maxlst; u2++)
                {
                    uVal = tvb_get_uint32(tvb, offset, bLittleEndian);
                    dissect_mqpcf_parm_int(tvb, tree, offset, uPrm, uVal, hf_mq_pcf_intlist, u2 + 1, uCnt, uDigit, bParse);
                    offset += 4;
                }
                if (u2 != uCnt)
                {
                    proto_tree_add_expert_format(tree, pinfo, &ei_mq_pcf_MaxInt, tvb, offset, (uCnt - u2) * 4, sMaxLst, u2, uCnt);
                }
            }
            break;
            case MQ_MQCFT_STRING_LIST:
            {
                uint32_t u2;
                uint32_t uDigit;
                uint8_t *sStr;
                header_field_info *hfinfo;

                hfinfo = proto_registrar_get_nth(hf_mq_pcf_stringlist);

                uCCS = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                uCnt = tvb_get_uint32(tvb, offset + uLenF + 4, bLittleEndian);
                uSLn = tvb_get_uint32(tvb, offset + uLenF + 8, bLittleEndian);

                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s-> contain %d Element(s)", strPrm, uCnt);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmccsid, tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 16, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 20, 4, bLittleEndian);

                uDigit = dissect_mqpcf_getDigits(uCnt);

                offset += uLenF + 12;
                for (u2 = 0; u2 < uCnt && u2 < mq_pcf_maxlst; u2++)
                {
                    sStr = tvb_get_string_enc(pinfo->pool, tvb, offset,
                                              uSLn, IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII);
                    if (*sStr)
                        strip_trailing_blanks(sStr, uSLn);
                    if (*sStr)
                        sStr = (uint8_t*)format_text_chr(pinfo->pool, sStr, strlen((const char *)sStr), '.');

                    proto_tree_add_string_format(tree, hf_mq_pcf_stringlist, tvb, offset, uSLn, (const char *)sStr,
                                                 "%s[%*d]: %s", hfinfo->name, uDigit, u2 + 1, sStr);
                    offset += uSLn;
                }
                if (u2 != uCnt)
                {
                    proto_tree_add_expert_format(tree, pinfo, &ei_mq_pcf_MaxStr, tvb, offset, (uCnt - u2) * uSLn, sMaxLst, u2, uCnt);
                }
            }
            break;
            case MQ_MQCFT_GROUP:
            {
                uCnt = tvb_get_uint32(tvb, offset + 12, bLittleEndian);

                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, &ti, "%s-> contain %d Element(s)", strPrm, uCnt);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 12, 4, bLittleEndian);

                tOfs = dissect_mqpcf_parm_grp(tvb, pinfo, tree, offset, bLittleEndian, bParse);
            }
            break;
            case MQ_MQCFT_EVENT:
                break;
            case MQ_MQCFT_USER:
            {
                tree = proto_tree_add_subtree(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, strPrm);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_bytestring, tvb, offset + 8, uLen - 8, bLittleEndian);
            }
            break;
            case MQ_MQCFT_BYTE_STRING:
            {
                uSLn = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                if (uSLn)
                {
                    uint8_t *sStrA = (uint8_t *)format_text_chr(pinfo->pool, tvb_get_string_enc(pinfo->pool, tvb, offset + uLenF + 4, uSLn, ENC_ASCII), uSLn, '.');
                    uint8_t *sStrE = (uint8_t *)format_text_chr(pinfo->pool, tvb_get_string_enc(pinfo->pool, tvb, offset + uLenF + 4, uSLn, ENC_EBCDIC), uSLn, '.');
                    if (uSLn > 35)
                    {
                        tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL,
                                                             "%s: [Truncated] A(%-.35s) E(%-.35s)", strPrm, sStrA, sStrE);
                    }
                    else
                    {
                        tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL,
                                                             "%s: A(%s) E(%s)", strPrm, sStrA, sStrE);
                    }
                }
                else
                {
                    tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s <MISSING>", strPrm);
                }

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 12, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_bytestring, tvb, offset + uLenF + 4, uSLn, bLittleEndian);
            }
            break;
            case MQ_MQCFT_TRACE_ROUTE:
                break;
            case MQ_MQCFT_REPORT:
                break;
            case MQ_MQCFT_INTEGER_FILTER:
            {
                uint32_t uOpe;

                uOpe = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                uVal = tvb_get_uint32(tvb, offset + uLenF + 4, bLittleEndian);

                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s: %s 0x%08x (%d)",
                                                     strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)") + 7, uVal, uVal);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_filterop, tvb, offset + 12, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_int, tvb, offset + uLenF + 4, 4, bLittleEndian);
            }
            break;
            case MQ_MQCFT_STRING_FILTER:
            {
                uint8_t *sStr;
                uint32_t uOpe;

                uOpe = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                uCCS = tvb_get_uint32(tvb, offset + uLenF + 4, bLittleEndian);
                uSLn = tvb_get_uint32(tvb, offset + uLenF + 8, bLittleEndian);
                sStr = (uint8_t *)format_text_chr(pinfo->pool,
                                                 tvb_get_string_enc(pinfo->pool, tvb, offset + uLenF + 12, uSLn, IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII),
                                                 uSLn, '.');
                strip_trailing_blanks(sStr, uSLn);

                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s: %s %s",
                                                     strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)") + 7, sStr);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_filterop, tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmccsid, tvb, offset + 16, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 20, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_string, tvb, offset + uLenF + 12, uSLn, IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII);
            }
            break;
            case MQ_MQCFT_BYTE_STRING_FILTER:
            {
                uint32_t uOpe;
                uOpe = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                uSLn = tvb_get_uint32(tvb, offset + uLenF + 4, bLittleEndian);
                if (uSLn)
                {
                    uint8_t *sStrA = (uint8_t *)format_text_chr(pinfo->pool, tvb_get_string_enc(pinfo->pool, tvb, offset + uLenF + 8, uSLn, ENC_ASCII), uSLn, '.');
                    uint8_t *sStrE = (uint8_t *)format_text_chr(pinfo->pool, tvb_get_string_enc(pinfo->pool, tvb, offset + uLenF + 8, uSLn, ENC_EBCDIC), uSLn, '.');
                    tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s: %s A(%s) E(%s)",
                                                         strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)") + 7, sStrA, sStrE);
                }
                else
                {
                    tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s: %s <MISSING>",
                                                         strPrm, val_to_str(uOpe, GET_VALSV(FilterOP), "       Unknown (0x%02x)") + 7);
                }

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_filterop, tvb, offset + 12, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmstrlen, tvb, offset + 16, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_bytestring, tvb, offset + uLenF + 8, uSLn, bLittleEndian);
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
            case MQ_MQCFT_STATISTICS:
                break;
            case MQ_MQCFT_ACCOUNTING:
                break;
            case MQ_MQCFT_INTEGER64:
            {
                uVal64 = tvb_get_uint64(tvb, offset + uLenF + 4, bLittleEndian);
                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL,
                                                     "%s: 0x%" PRIx64 " (%" PRId64 ")", strPrm, uVal64, uVal64);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmunused, tvb, offset + 12, 4, bLittleEndian);

                proto_tree_add_item(tree, hf_mq_pcf_int64, tvb, offset + uLenF + 4, 8, bLittleEndian);
            }
            break;
            case MQ_MQCFT_INTEGER64_LIST:
            {
                uint32_t u2;
                uint32_t uDigit;
                header_field_info *hfinfo;

                hfinfo = proto_registrar_get_nth(hf_mq_pcf_int64list);

                uCnt = tvb_get_uint32(tvb, offset + uLenF, bLittleEndian);
                tree = proto_tree_add_subtree_format(mq_tree, tvb, offset, uLen, ett_mqpcf_prm, NULL, "%s-> contain %d Element(s)", strPrm, uCnt);
                uDigit = dissect_mqpcf_getDigits(uCnt);

                proto_tree_add_item(tree, hf_mq_pcf_prmtyp, tvb, offset, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmlen, tvb, offset + 4, 4, bLittleEndian);
                proto_tree_add_item(tree, (bParse) ? hf_mq_pcf_prmid : hf_mq_pcf_prmidnovals, tvb, offset + 8, 4, bLittleEndian);
                proto_tree_add_item(tree, hf_mq_pcf_prmcount, tvb, offset + 12, 4, bLittleEndian);

                offset += uLenF + 4;
                for (u2 = 0; u2 < uCnt && u2 < mq_pcf_maxlst; u2++)
                {
                    uVal64 = tvb_get_uint64(tvb, offset, bLittleEndian);
                    proto_tree_add_int64_format(tree, hf_mq_pcf_int64list, tvb, offset, 8, uVal64,
                                                "%s[%*d]: 0x%" PRIx64 " (%" PRId64 ")",
                                                hfinfo->name, uDigit, u2 + 1, uVal64, uVal64);
                    offset += 8;
                }
                if (u2 != uCnt)
                {
                    proto_tree_add_expert_format(tree, pinfo, &ei_mq_pcf_MaxI64, tvb, offset, (uCnt - u2) * 8, sMaxLst, u2, uCnt);
                }
            }
            break;
        }
        decrement_dissection_depth(pinfo);
        offset = tOfs + uLen;
    }
    if (u != uCount)
    {
        proto_tree_add_expert_format(mq_tree, pinfo, &ei_mq_pcf_MaxPrm, tvb, offset, tvb_reported_length_remaining(tvb, offset), sMaxPrm, u, uCount);
    }
    return offset - _offset;
}

static void dissect_mqpcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mq_parm_t* p_mq_parm)
{
    int offset = 0;
    unsigned bLittleEndian;

    bLittleEndian = ((p_mq_parm->mq_cur_ccsid.encod & MQ_MQENC_INTEGER_MASK) == MQ_MQENC_INTEGER_REVERSED) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    if (tvb_reported_length(tvb) >= 36)
    {
        int iSizeMQCFH = 36;
        uint32_t iCommand = tvb_get_uint32(tvb, offset + 12, bLittleEndian);

        if (tree)
        {
            proto_item *ti;
            proto_tree *mq_tree;
            proto_tree *mqroot_tree;
            char        sTmp[256];
            uint32_t    uCnt;
            uint32_t    uTyp;
            uint32_t    uCmd;
            uint32_t    uCC;
            uint32_t    uRC;

            uTyp = tvb_get_uint32(tvb, offset, bLittleEndian);
            uCmd = tvb_get_uint32(tvb, offset + 12, bLittleEndian);
            uCC = tvb_get_uint32(tvb, offset + 24, bLittleEndian);
            uRC = tvb_get_uint32(tvb, offset + 28, bLittleEndian);
            uCnt = tvb_get_uint32(tvb, offset + 32, bLittleEndian);

            if (uCC || uRC)
            {
                snprintf(sTmp, sizeof(sTmp) - 1, " %-s [%d-%s] {%d-%s} PrmCnt(%d) CC(%d-%s) RC(%d-%s)",
                           MQ_TEXT_CFH,
                           uTyp, val_to_str_const(uTyp, GET_VALSV(mqcft), "Unknown"),
                           uCmd, val_to_str_ext_const(uCmd, GET_VALS_EXTP(MQCMD), "Unknown"),
                           uCnt,
                           uCC, val_to_str_const(uCC, GET_VALSV(mqcc), "Unknown"),
                           uRC, val_to_str_ext_const(uRC, GET_VALS_EXTP(MQRC), "Unknown"));
            }
            else
            {
                snprintf(sTmp, sizeof(sTmp) - 1, " %-s [%d-%s] {%d-%s} PrmCnt(%d)",
                           MQ_TEXT_CFH,
                           uTyp, val_to_str_const(uTyp, GET_VALSV(mqcft), "Unknown"),
                           uCmd, val_to_str_ext_const(uCmd, GET_VALS_EXTP(MQCMD), "Unknown"),
                           uCnt);
            }

            ti = proto_tree_add_item(tree, proto_mqpcf, tvb, offset, -1, ENC_NA);

            proto_item_append_text(ti, " (%s)", val_to_str_ext(iCommand, GET_VALS_EXTP(MQCMD), "Unknown (0x%02x)"));
            mqroot_tree = proto_item_add_subtree(ti, ett_mqpcf);

            mq_tree = proto_tree_add_subtree(mqroot_tree, tvb, offset, iSizeMQCFH, ett_mqpcf_cfh, NULL, sTmp);

            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_type, tvb, offset + 0, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_length, tvb, offset + 4, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_version, tvb, offset + 8, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_command, tvb, offset + 12, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_MsgSeqNbr, tvb, offset + 16, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_control, tvb, offset + 20, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_compcode, tvb, offset + 24, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_reason, tvb, offset + 28, 4, bLittleEndian);
            proto_tree_add_item(mq_tree, hf_mqpcf_cfh_ParmCount, tvb, offset + 32, 4, bLittleEndian);
            dissect_mqpcf_parm(tvb, pinfo, mqroot_tree, offset + iSizeMQCFH, uCnt, bLittleEndian, true);
        }
    }
}

static bool dissect_mqpcf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (data && tvb_reported_length(tvb) >= 36)
    {
        mq_parm_t *p_mq_parm = (mq_parm_t *)data;
        if (strncmp((const char*)p_mq_parm->mq_format, MQ_MQFMT_ADMIN, 8) == 0
            || strncmp((const char*)p_mq_parm->mq_format, MQ_MQFMT_EVENT, 8) == 0
            || strncmp((const char*)p_mq_parm->mq_format, MQ_MQFMT_PCF, 8) == 0)
        {
            /* Dissect the packet */
            dissect_mqpcf(tvb, pinfo, tree, p_mq_parm);
            return true;
        }
        if (strncmp((const char *)p_mq_parm->mq_format, "LPOO", 4) == 0)
        {
            unsigned bLittleEndian;
            bLittleEndian = ((p_mq_parm->mq_cur_ccsid.encod & MQ_MQENC_INTEGER_MASK) == MQ_MQENC_INTEGER_REVERSED) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;
            dissect_mqpcf_parm(tvb, pinfo, tree, 0, (uint32_t)-1, bLittleEndian, false);
            return true;
        }
    }
    return false;
}

void proto_register_mqpcf(void)
{
    expert_module_t *expert_mqpcf;

    static hf_register_info hf[] =
    {
        { &hf_mqpcf_cfh_type     , { "Type.....", "mqpcf.cfh.type"      , FT_UINT32, BASE_DEC, VALS(mq_mqcft_vals), 0x0, "CFH type", HFILL }},
        { &hf_mqpcf_cfh_length   , { "Length...", "mqpcf.cfh.length"    , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH length", HFILL }},
        { &hf_mqpcf_cfh_version  , { "Version..", "mqpcf.cfh.version"   , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH version", HFILL }},
        { &hf_mqpcf_cfh_command  , { "Command..", "mqpcf.cfh.command"   , FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQCMD), 0x0, "CFH command", HFILL }},
        { &hf_mqpcf_cfh_MsgSeqNbr, { "MsgSeqNbr", "mqpcf.cfh.MsgSeqNbr" , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH message sequence number", HFILL }},
        { &hf_mqpcf_cfh_control  , { "Control..", "mqpcf.cfh.control"   , FT_UINT32, BASE_DEC, VALS(mq_CtlOpt_vals), 0x0, "CFH control", HFILL }},
        { &hf_mqpcf_cfh_compcode , { "CompCode.", "mqpcf.cfh.compcode"  , FT_UINT32, BASE_DEC, VALS(mq_mqcc_vals), 0x0, "CFH completion code", HFILL }},
        { &hf_mqpcf_cfh_reason   , { "ReasCode.", "mqpcf.cfh.reasoncode", FT_UINT32, BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(MQRC), 0x0, "CFH reason code", HFILL }},
        { &hf_mqpcf_cfh_ParmCount, { "ParmCount", "mqpcf.cfh.ParmCount" , FT_UINT32, BASE_DEC, NULL, 0x0, "CFH parameter count", HFILL }},

        { &hf_mq_pcf_prmtyp      , { "ParmTyp..", "mqpcf.parm.type"      , FT_UINT32 , BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(PrmTyp), 0x0, "MQPCF parameter type", HFILL }},
        { &hf_mq_pcf_prmlen      , { "ParmLen..", "mqpcf.parm.len"       , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter length", HFILL }},
        { &hf_mq_pcf_prmid       , { "ParmID...", "mqpcf.parm.id"        , FT_UINT32 , BASE_DEC | BASE_EXT_STRING, GET_VALS_EXTP(PrmId), 0x0, "MQPCF parameter id", HFILL }},
        { &hf_mq_pcf_prmidnovals , { "ParmID...", "mqpcf.parm.idNoVals"  , FT_UINT32 , BASE_HEX_DEC, NULL, 0x0, "MQPCF parameter id No Vals", HFILL }},
        { &hf_mq_pcf_filterop    , { "FilterOP.", "mqpcf.filter.op"      , FT_UINT32 , BASE_DEC, VALS(mq_FilterOP_vals), 0x0, "MQPCF Filter operator", HFILL }},
        { &hf_mq_pcf_prmccsid    , { "ParmCCSID", "mqpcf.parm.ccsid"     , FT_UINT32 , BASE_DEC | BASE_RANGE_STRING, RVALS(mq_ccsid_rvals), 0x0, "MQPCF parameter ccsid", HFILL }},
        { &hf_mq_pcf_prmstrlen   , { "ParmStrLn", "mqpcf.parm.strlen"    , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter strlen", HFILL }},
        { &hf_mq_pcf_prmcount    , { "ParmCount", "mqpcf.parm.count"     , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter count", HFILL }},
        { &hf_mq_pcf_prmunused   , { "ParmUnuse", "mqpcf.parm.unused"    , FT_UINT32 , BASE_DEC, NULL, 0x0, "MQPCF parameter unused", HFILL }},
        { &hf_mq_pcf_string      , { "String...", "mqpcf.parm.string"    , FT_STRING, BASE_NONE, NULL, 0x0, "MQPCF parameter string", HFILL }},
        { &hf_mq_pcf_stringlist  , { "StrList..", "mqpcf.parm.stringlist", FT_STRING, BASE_NONE, NULL, 0x0, "MQPCF parameter string list", HFILL }},
        { &hf_mq_pcf_int         , { "Integer..", "mqpcf.parm.int"       , FT_INT32  , BASE_DEC, NULL, 0x0, "MQPCF parameter int", HFILL }},
        { &hf_mq_pcf_intlist     , { "IntList..", "mqpcf.parm.intlist"   , FT_INT32  , BASE_DEC, NULL, 0x0, "MQPCF parameter int list", HFILL }},
        { &hf_mq_pcf_bytestring  , { "ByteStr..", "mqpcf.parm.bytestring", FT_BYTES  , BASE_NONE, NULL, 0x0, "MQPCF parameter byte string", HFILL }},
        { &hf_mq_pcf_int64       , { "Int64....", "mqpcf.parm.int64"     , FT_INT64  , BASE_DEC, NULL, 0x0, "MQPCF parameter int64", HFILL }},
        { &hf_mq_pcf_int64list   , { "Int64List", "mqpcf.parm.int64list" , FT_INT64  , BASE_DEC, NULL, 0x0, "MQPCF parameter int64 list", HFILL }},
    };
    static int *ett[] =
    {
        &ett_mqpcf,
        &ett_mqpcf_prm,
        &ett_mqpcf_grp,
        &ett_mqpcf_cfh,
    };
    static ei_register_info ei[] =
    {
        { &ei_mq_pcf_prmln0, { "mqpcf.parm.len0"     , PI_MALFORMED, PI_ERROR, "MQPCF Parameter length is 0", EXPFILL }},
        { &ei_mq_pcf_hdrlne, { "mqpcf.parm.hdrlenerr", PI_MALFORMED, PI_ERROR, "MQPCF Header not enough bytes in pdu", EXPFILL}},
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
                                   "Set the maximum number of parameters in the PCF to decode",
                                   "When dissecting PCF there can be a lot of parameters."
                                   " You can limit the number of parameter decoded, before it continue with the next PCF.",
                                   10, &mq_pcf_maxprm);
    prefs_register_uint_preference(mq_pcf_module, "maxlst",
                                   "Set the maximum number of Parameter List that are displayed",
                                   "When dissecting a parameter of a PCFm, if it is a StringList, IntegerList or Integer64 List, "
                                   " You can limit the number of elements displayed, before it continues with the next Parameter.",
                                   10, &mq_pcf_maxlst);

}

void proto_reg_handoff_mqpcf(void)
{
    heur_dissector_add("mq", dissect_mqpcf_heur, "WebSphere MQ PCF", "mqpcf_mq", proto_mqpcf, HEURISTIC_ENABLE);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
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
