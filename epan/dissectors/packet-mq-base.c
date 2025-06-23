/* packet-mq-base.c
 * Routines for IBM WebSphere MQ packet dissection base
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

#include "config.h"
#include <epan/packet.h>

#include "packet-mq.h"

wmem_strbuf_t* mqpcf_get_encoding(wmem_allocator_t* allocator, const unsigned uEnc)
{
    wmem_strbuf_t* pEnc = wmem_strbuf_new(allocator, "");
    switch(uEnc & MQ_MQENC_FLOAT_MASK)
    {
    case MQ_MQENC_FLOAT_UNDEFINED:
        wmem_strbuf_append(pEnc, "FLT_UNDEFINED");
        break;
    case MQ_MQENC_FLOAT_IEEE_NORMAL:
        wmem_strbuf_append(pEnc, "FLT_IEEE_NORMAL");
        break;
    case MQ_MQENC_FLOAT_IEEE_REVERSED:
        wmem_strbuf_append(pEnc, "FLT_IEEE_REVERSED");
        break;
    case MQ_MQENC_FLOAT_S390:
        wmem_strbuf_append(pEnc, "FLT_S390");
        break;
    case MQ_MQENC_FLOAT_TNS:
        wmem_strbuf_append(pEnc, "FLT_TNS");
        break;
    default:
        wmem_strbuf_append(pEnc, "FLT_UNKNOWN");
        break;
    }

    wmem_strbuf_append(pEnc, "/");
    switch(uEnc & MQ_MQENC_DECIMAL_MASK)
    {
    case MQ_MQENC_DECIMAL_UNDEFINED:
        wmem_strbuf_append(pEnc, "DEC_UNDEFINED");
        break;
    case MQ_MQENC_DECIMAL_NORMAL:
        wmem_strbuf_append(pEnc, "DEC_NORMAL");
        break;
    case MQ_MQENC_DECIMAL_REVERSED:
        wmem_strbuf_append(pEnc, "DEC_REVERSED");
        break;
    default:
        wmem_strbuf_append(pEnc, "DEC_UNKNOWN");
        break;
    }

    wmem_strbuf_append(pEnc, "/");
    switch (uEnc & MQ_MQENC_INTEGER_MASK)
    {
    case MQ_MQENC_INTEGER_UNDEFINED:
        wmem_strbuf_append(pEnc, "INT_UNDEFINED");
        break;
    case MQ_MQENC_INTEGER_NORMAL:
        wmem_strbuf_append(pEnc, "INT_NORMAL");
        break;
    case MQ_MQENC_INTEGER_REVERSED:
        wmem_strbuf_append(pEnc, "INT_REVERSED");
        break;
    default:
        wmem_strbuf_append(pEnc, "INT_UNKNOWN");
        break;
    }

    return pEnc;
}

 /* This routine truncates the string at the first blank space */
int32_t strip_trailing_blanks(uint8_t* a_str, uint32_t a_size)
{
    int32_t i = 0;
    if (a_str != NULL)
    {
        for (i = a_size - 1; i >= 0; i--)
        {
            if (a_str[i] != ' ' && a_str[i] != '\0')
                break;
            else
                a_str[i] = '\0';
        }
    }
    return i;
}

const range_string mq_MQWI_rvals[] =
{
/*  -2*/ { MQ_MQCGWI_DEFAULT, MQ_MQCGWI_DEFAULT, "MQCGWI_DEFAULT" },
/*  -1*/ { MQ_MQWI_UNLIMITED, MQ_MQWI_UNLIMITED, "MQWI_UNLIMITED" },
/* >=0*/ { MQ_MQWI_0, MQ_MQWI_7FFFFFFF, "" },
    { 0, 0, NULL }
};

const range_string mq_MQCODL_rvals[] =
{
/*  -1*/ { MQ_MQCODL_AS_INPUT, MQ_MQCODL_AS_INPUT, "MQCODL_AS_INPUT" },
/* >=0*/ { MQ_MQCODL_0, MQ_MQCODL_7FFFFFFF, "" },
    { 0, 0, NULL }
};

const range_string mq_MQCCSI_rvals[] =
{
/*  -4*/ { MQ_MQCCSI_AS_PUBLISHED, MQ_MQCCSI_AS_PUBLISHED, "MQCCSI_AS_PUBLISHED" },
/*  -3*/ { MQ_MQCCSI_APPL, MQ_MQCCSI_APPL, "MQCCSI_APPL" },
/*  -2*/ { MQ_MQCCSI_INHERIT, MQ_MQCCSI_INHERIT, "MQCCSI_INHERIT" },
/*  -1*/ { MQ_MQCCSI_EMBEDDED, MQ_MQCCSI_EMBEDDED, "MQCCSI_EMBEDDED" },
/*   0*/ { MQ_MQCCSI_UNDEFINED, MQ_MQCCSI_UNDEFINED, "UNDEFINED/DEFAULT/Q_MGR" },
/* >=1*/ { MQ_MQCCSI_1, MQ_MQCCSI_65535, "" },
    { 0, 0, NULL }
};

static const value_string mq_MQKEY_vals[] =
{
/*  0 */ { MQ_MQKEY_REUSE_DISABLED, "MQKEY_REUSE_DISABLED" },
/* -1 */ { MQ_MQKEY_REUSE_UNLIMITED, "MQKEY_REUSE_UNLIMITED" },
    { 0, NULL }
};

value_string mq_MQCC_vals[] =
{
/* -1*/ { MQ_MQCC_UNKNOWN, "MQCC_UNKNOWN" },
/*  0*/ { MQ_MQCC_OK, "MQCC_OK" },
/*  1*/ { MQ_MQCC_WARNING, "MQCC_WARNING" },
/*  2*/ { MQ_MQCC_FAILED, "MQCC_FAILED" },
    { 0, NULL }
};

/* Types of Structure */
value_string mq_MQCFT_vals[] =
{
/*  0*/ { MQ_MQCFT_NONE, "MQCFT_NONE" },
/*  1*/ { MQ_MQCFT_COMMAND, "MQCFT_COMMAND" },
/*  2*/ { MQ_MQCFT_RESPONSE, "MQCFT_RESPONSE" },
/*  3*/ { MQ_MQCFT_INTEGER, "MQCFT_INTEGER" },
/*  4*/ { MQ_MQCFT_STRING, "MQCFT_STRING" },
/*  5*/ { MQ_MQCFT_INTEGER_LIST, "MQCFT_INTEGER_LIST" },
/*  6*/ { MQ_MQCFT_STRING_LIST, "MQCFT_STRING_LIST" },
/*  7*/ { MQ_MQCFT_EVENT, "MQCFT_EVENT" },
/*  8*/ { MQ_MQCFT_USER, "MQCFT_USER" },
/*  9*/ { MQ_MQCFT_BYTE_STRING, "MQCFT_BYTE_STRING" },
/* 10*/ { MQ_MQCFT_TRACE_ROUTE, "MQCFT_TRACE_ROUTE" },
/* 12*/ { MQ_MQCFT_REPORT, "MQCFT_REPORT" },
/* 13*/ { MQ_MQCFT_INTEGER_FILTER, "MQCFT_INTEGER_FILTER" },
/* 14*/ { MQ_MQCFT_STRING_FILTER, "MQCFT_STRING_FILTER" },
/* 15*/ { MQ_MQCFT_BYTE_STRING_FILTER, "MQCFT_BYTE_STRING_FILTER" },
/* 16*/ { MQ_MQCFT_COMMAND_XR, "MQCFT_COMMAND_XR" },
/* 17*/ { MQ_MQCFT_XR_MSG, "MQCFT_XR_MSG" },
/* 18*/ { MQ_MQCFT_XR_ITEM, "MQCFT_XR_ITEM" },
/* 19*/ { MQ_MQCFT_XR_SUMMARY, "MQCFT_XR_SUMMARY" },
/* 20*/ { MQ_MQCFT_GROUP, "MQCFT_GROUP" },
/* 21*/ { MQ_MQCFT_STATISTICS, "MQCFT_STATISTICS" },
/* 22*/ { MQ_MQCFT_ACCOUNTING, "MQCFT_ACCOUNTING" },
/* 23*/ { MQ_MQCFT_INTEGER64, "MQCFT_INTEGER64" },
/* 25*/ { MQ_MQCFT_INTEGER64_LIST, "MQCFT_INTEGER64_LIST" },
/* 26*/ { MQ_MQCFT_APP_ACTIVITY, "MQCFT_APP_ACTIVITY" },
    { 0, NULL }
};

static const value_string mq_MQAIT_vals[] =
{
/* 0*/ { MQ_MQAIT_ALL, "MQAIT_ALL" },
/* 1*/ { MQ_MQAIT_CRL_LDAP, "MQAIT_CRL_LDAP" },
/* 2*/ { MQ_MQAIT_OCSP, "MQAIT_OCSP" },
/* 3*/ { MQ_MQAIT_IDPW_OS, "MQAIT_IDPW_OS" },
/* 4*/ { MQ_MQAIT_IDPW_LDAP, "MQAIT_IDPW_LDAP" },
    { 0, NULL }
};

value_string mq_MQCFOP_vals[] =
{
/*  1*/ { MQ_MQCFOP_LESS, "MQCFOP_LESS" },
/*  2*/ { MQ_MQCFOP_EQUAL, "MQCFOP_EQUAL" },
/*  3*/ { MQ_MQCFOP_NOT_GREATER, "MQCFOP_NOT_GREATER" },
/*  4*/ { MQ_MQCFOP_GREATER, "MQCFOP_GREATER" },
/*  5*/ { MQ_MQCFOP_NOT_EQUAL, "MQCFOP_NOT_EQUAL" },
/*  6*/ { MQ_MQCFOP_NOT_LESS, "MQCFOP_NOT_LESS" },
/* 10*/ { MQ_MQCFOP_CONTAINS, "MQCFOP_CONTAINS" },
/* 13*/ { MQ_MQCFOP_EXCLUDES, "MQCFOP_EXCLUDES" },
/* 18*/ { MQ_MQCFOP_LIKE, "MQCFOP_LIKE" },
/* 21*/ { MQ_MQCFOP_NOT_LIKE, "MQCFOP_NOT_LIKE" },
/* 26*/ { MQ_MQCFOP_CONTAINS_GEN, "MQCFOP_CONTAINS_GEN" },
/* 29*/ { MQ_MQCFOP_EXCLUDES_GEN, "MQCFOP_EXCLUDES_GEN" },
    { 0, NULL }
};

value_string mq_MQPRT_vals[] =
{
/* 0*/ { MQ_MQPRT_RESPONSE_AS_PARENT, "MQPRT_RESPONSE_AS_PARENT" },
/* 1*/ { MQ_MQPRT_SYNC_RESPONSE, "MQPRT_SYNC_RESPONSE" },
/* 2*/ { MQ_MQPRT_ASYNC_RESPONSE, "MQPRT_ASYNC_RESPONSE" },
    { 0, NULL }
};

static const value_string mq_MQRECORDING_vals[] =
{
/* 0*/ { MQ_MQRECORDING_DISABLED, "MQRECORDING_DISABLED" },
/* 1*/ { MQ_MQRECORDING_Q, "MQRECORDING_Q" },
/* 2*/ { MQ_MQRECORDING_MSG, "MQRECORDING_MSG" },
    { 0, NULL }
};

static const value_string mq_MQTCPSTACK_vals[] =
{
/* 0*/ { MQ_MQTCPSTACK_SINGLE, "MQTCPSTACK_SINGLE" },
/* 1*/ { MQ_MQTCPSTACK_MULTIPLE, "MQTCPSTACK_MULTIPLE" },
    { 0, NULL }
};

static const value_string mq_MQTCPKEEP_vals[] =
{
/* 0*/ { MQ_MQTCPKEEP_NO, "MQTCPKEEP_NO" },
/* 1*/ { MQ_MQTCPKEEP_YES, "MQTCPKEEP_YES" },
    { 0, NULL }
};

static const value_string mq_MQSQQM_vals[] =
{
/* 0*/ { MQ_MQSQQM_USE, "MQSQQM_USE" },
/* 1*/ { MQ_MQSQQM_IGNORE, "MQSQQM_IGNORE" },
    { 0, NULL }
};

static const value_string mq_MQRCVTIME_vals[] =
{
/* 0*/ { MQ_MQRCVTIME_MULTIPLY, "MQRCVTIME_MULTIPLY" },
/* 1*/ { MQ_MQRCVTIME_ADD, "MQRCVTIME_ADD" },
/* 2*/ { MQ_MQRCVTIME_EQUAL, "MQRCVTIME_EQUAL" },
    { 0, NULL }
};

static const value_string mq_MQIPADDR_vals[] =
{
/* 0*/ { MQ_MQIPADDR_IPV4, "MQIPADDR_IPV4" },
/* 1*/ { MQ_MQIPADDR_IPV6, "MQIPADDR_IPV6" },
    { 0, NULL }
};

static const value_string mq_MQGUR_vals[] =
{
/* 0*/ { MQ_MQGUR_DISABLED, "MQGUR_DISABLED" },
/* 1*/ { MQ_MQGUR_ENABLED, "MQGUR_ENABLED" },
    { 0, NULL }
};

static const value_string mq_DNSWLM_vals[] =
{
/* 0*/ { MQ_MQDNSWLM_NO, "MQDNSWLM_NO" },
/* 1*/ { MQ_MQDNSWLM_YES, "MQDNSWLM_YES" },
    { 0, NULL }
};

static const value_string mq_MQADOPT_TYPE_vals[] =
{
/*  0*/ { MQ_MQADOPT_TYPE_NO, "MQADOPT_TYPE_NO" },
/*  1*/ { MQ_MQADOPT_TYPE_ALL, "MQADOPT_TYPE_ALL" },
/*  2*/ { MQ_MQADOPT_TYPE_SVR, "MQADOPT_TYPE_SVR" },
/*  4*/ { MQ_MQADOPT_TYPE_SDR, "MQADOPT_TYPE_SDR" },
/*  8*/ { MQ_MQADOPT_TYPE_RCVR, "MQADOPT_TYPE_RCVR" },
/* 16*/ { MQ_MQADOPT_TYPE_CLUSRCVR, "MQADOPT_TYPE_CLUSRCVR" },
    { 0, NULL }
};

static const value_string mq_MQADOPT_CHECK_vals[] =
{
/* 0*/ { MQ_MQADOPT_CHECK_NONE, "MQADOPT_CHECK_NONE" },
/* 1*/ { MQ_MQADOPT_CHECK_ALL, "MQADOPT_CHECK_ALL" },
/* 2*/ { MQ_MQADOPT_CHECK_Q_MGR_NAME, "MQADOPT_CHECK_Q_MGR_NAME" },
/* 4*/ { MQ_MQADOPT_CHECK_NET_ADDR, "MQADOPT_CHECK_NET_ADDR" },
/* 8*/ { MQ_MQADOPT_CHECK_CHANNEL_NAME, "MQADOPT_CHECK_CHANNEL_NAME" },
    { 0, NULL }
};

static const value_string mq_MQXPT_vals[] =
{
/* -1*/ { MQ_MQXPT_ALL, "MQXPT_ALL" },
/*  0*/ { MQ_MQXPT_LOCAL, "MQXPT_LOCAL" },
/*  1*/ { MQ_MQXPT_LU62, "MQXPT_LU62" },
/*  2*/ { MQ_MQXPT_TCP, "MQXPT_TCP" },
/*  3*/ { MQ_MQXPT_NETBIOS, "MQXPT_NETBIOS" },
/*  4*/ { MQ_MQXPT_SPX, "MQXPT_SPX" },
/*  5*/ { MQ_MQXPT_DECNET, "MQXPT_DECNET" },
/*  6*/ { MQ_MQXPT_UDP, "MQXPT_UDP" },
    { 0, NULL }
};

static const value_string mq_MQSCA_vals[] =
{
/* 0*/ { MQ_MQSCA_REQUIRED, "MQSCA_REQUIRED" },
/* 1*/ { MQ_MQSCA_OPTIONAL, "MQSCA_OPTIONAL" },
    { 0, NULL }
};

static const value_string mq_MQPA_vals[] =
{
/* 1*/ { MQ_MQPA_DEFAULT, "MQPA_DEFAULT" },
/* 2*/ { MQ_MQPA_CONTEXT, "MQPA_CONTEXT" },
/* 3*/ { MQ_MQPA_ONLY_MCA, "MQPA_ONLY_MCA" },
/* 4*/ { MQ_MQPA_ALTERNATE_OR_MCA, "MQPA_ALTERNATE_OR_MCA" },
    { 0, NULL }
};

static const value_string mq_MQNPMS_vals[] =
{
/* 1*/ { MQ_MQNPMS_NORMAL, "MQNPMS_NORMAL" },
/* 2*/ { MQ_MQNPMS_FAST, "MQNPMS_FAST" },
    { 0, NULL }
};

static const value_string mq_MQCOMPRESS_vals[] =
{
/*         -1*/ { MQ_MQCOMPRESS_NOT_AVAILABLE, "MQCOMPRESS_NOT_AVAILABLE" },
/*          0*/ { MQ_MQCOMPRESS_NONE, "MQCOMPRESS_NONE" },
/*          1*/ { MQ_MQCOMPRESS_RLE, "MQCOMPRESS_RLE" },
/*          2*/ { MQ_MQCOMPRESS_ZLIBFAST, "MQCOMPRESS_ZLIBFAST" },
/*          4*/ { MQ_MQCOMPRESS_ZLIBHIGH, "MQCOMPRESS_ZLIBHIGH" },
/*          8*/ { MQ_MQCOMPRESS_SYSTEM, "MQCOMPRESS_SYSTEM" },
/* 0x0FFFFFFF*/ { MQ_MQCOMPRESS_ANY, "MQCOMPRESS_ANY" },
    { 0, NULL }
};

#if 0
static const value_string mq_MCAStatus_vals[] =
{
/* 0*/ { MQ_MQMCAS_STOPPED, "MQMCAS_STOPPED" },
/* 3*/ { MQ_MQMCAS_RUNNING, "MQMCAS_RUNNING" },
    { 0, NULL }
};
#endif

static const value_string mq_MQCAT_vals[] =
{
/* 1*/ { MQ_MQMCAT_PROCESS, "MQMCAT_PROCESS" },
/* 2*/ { MQ_MQMCAT_THREAD, "MQMCAT_THREAD" },
    { 0, NULL }
};

static const value_string mq_MQCDC_vals[] =
{
/* 0*/ { MQ_MQCDC_NO_SENDER_CONVERSION, "MQCDC_NO_SENDER_CONVERSION" },
/* 1*/ { MQ_MQCDC_SENDER_CONVERSION, "MQCDC_SENDER_CONVERSION" },
    { 0, NULL }
};

static const value_string mq_MQUS_vals[] =
{
/* 0*/ { MQ_MQUS_NORMAL, "MQUS_NORMAL" },
/* 1*/ { MQ_MQUS_TRANSMISSION, "MQUS_TRANSMISSION" },
{ 0, NULL }
};

static const value_string mq_MQCHT_vals[] =
{
/*  1*/ { MQ_MQCHT_SENDER, "MQCHT_SENDER" },
/*  2*/ { MQ_MQCHT_SERVER, "MQCHT_SERVER" },
/*  3*/ { MQ_MQCHT_RECEIVER, "MQCHT_RECEIVER" },
/*  4*/ { MQ_MQCHT_REQUESTER, "MQCHT_REQUESTER" },
/*  5*/ { MQ_MQCHT_ALL, "MQCHT_ALL" },
/*  6*/ { MQ_MQCHT_SVRCONN, "MQCHT_SVRCONN" },
/*  7*/ { MQ_MQCHT_CLNTCONN, "MQCHT_CLNTCONN" },
/*  8*/ { MQ_MQCHT_CLUSRCVR, "MQCHT_CLUSRCVR" },
/*  9*/ { MQ_MQCHT_CLUSSDR, "MQCHT_CLUSSDR" },
/* 10*/ { MQ_MQCHT_MQTT, "MQCHT_MQTT" },
/* 11*/ { MQ_MQCHT_AMQP, "MQCHT_AMQP" },
    { 0, NULL }
};

static const value_string mq_MQQSIE_vals[] =
{
/* 0*/ { MQ_MQQSIE_NONE, "MQQSIE_NONE" },
/* 1*/ { MQ_MQQSIE_HIGH, "MQQSIE_HIGH" },
/* 2*/ { MQ_MQQSIE_OK, "MQQSIE_OK" },
    { 0, NULL }
};

static const value_string mq_MQMON_vals[] =
{
/* -3*/ { MQ_MQMON_Q_MGR, "MQMON_Q_MGR" },
/* -1*/ { MQ_MQMON_NONE, "NONE/NOTAVAIL" },
/*  0*/ { MQ_MQMON_OFF, "OFF/DISABLED" },
/*  1*/ { MQ_MQMON_ON, "ON/ENABLED" },
/* 17*/ { MQ_MQMON_LOW, "MQMON_LOW" },
/* 33*/ { MQ_MQMON_MEDIUM, "MQMON_MEDIUM" },
/* 65*/ { MQ_MQMON_HIGH, "MQMON_HIGH" },
    { 0, NULL }
};

static const value_string mq_MQQT_vals[] =
{
/*    1*/ { MQ_MQQT_LOCAL, "MQQT_LOCAL" },
/*    2*/ { MQ_MQQT_MODEL, "MQQT_MODEL" },
/*    3*/ { MQ_MQQT_ALIAS, "MQQT_ALIAS" },
/*    6*/ { MQ_MQQT_REMOTE, "MQQT_REMOTE" },
/*    7*/ { MQ_MQQT_CLUSTER, "MQQT_CLUSTER" },
/* 1001*/ { MQ_MQQT_ALL, "MQQT_ALL" },
    { 0, NULL }
};

static const value_string mq_MQEVR_vals[] =
{
/* 0*/ { MQ_MQEVR_DISABLED, "MQEVR_DISABLED" },
/* 1*/ { MQ_MQEVR_ENABLED, "MQEVR_ENABLED" },
/* 2*/ { MQ_MQEVR_EXCEPTION, "MQEVR_EXCEPTION" },
/* 3*/ { MQ_MQEVR_NO_DISPLAY, "MQEVR_NO_DISPLAY" },
/* 4*/ { MQ_MQEVR_API_ONLY, "MQEVR_API_ONLY" },
/* 5*/ { MQ_MQEVR_ADMIN_ONLY, "MQEVR_ADMIN_ONLY" },
/* 6*/ { MQ_MQEVR_USER_ONLY, "MQEVR_USER_ONLY" },
    { 0, NULL }
};

static const value_string mq_MQOO_vals[] =
{
/* 0x00000002*/ { MQ_MQOO_INPUT_SHARED, "MQOO_INPUT_SHARED" },
/* 0x00000004*/ { MQ_MQOO_INPUT_EXCLUSIVE, "MQOO_INPUT_EXCLUSIVE" },
    { 0, NULL }
};

static const value_string mq_MQCLWL_USEQ_vals[] =
{
/* -3*/ { MQ_MQCLWL_USEQ_AS_Q_MGR, "MQCLWL_USEQ_AS_Q_MGR" },
/*  0*/ { MQ_MQCLWL_USEQ_LOCAL, "MQCLWL_USEQ_LOCAL" },
/*  1*/ { MQ_MQCLWL_USEQ_ANY, "MQCLWL_USEQ_ANY" },
    { 0, NULL }
};

static const value_string mq_MQQDT_vals[] =
{
/* 1*/ { MQ_MQQDT_PREDEFINED, "MQQDT_PREDEFINED" },
/* 2*/ { MQ_MQQDT_PERMANENT_DYNAMIC, "MQQDT_PERMANENT_DYNAMIC" },
/* 3*/ { MQ_MQQDT_TEMPORARY_DYNAMIC, "MQQDT_TEMPORARY_DYNAMIC" },
/* 4*/ { MQ_MQQDT_SHARED_DYNAMIC, "MQQDT_SHARED_DYNAMIC" },
    { 0, NULL }
};

static const value_string mq_MQQA_GET_vals[] =
{
/* 0*/ { MQ_MQQA_GET_ALLOWED, "MQQA_GET_ALLOWED" },
/* 1*/ { MQ_MQQA_GET_INHIBITED, "MQQA_GET_INHIBITED" },
    { 0, NULL }
};

static const value_string mq_MQIGQ_vals[] =
{
/* 0*/ { MQ_MQIGQ_DISABLED, "MQIGQ_DISABLED" },
/* 1*/ { MQ_MQIGQ_ENABLED, "MQIGQ_ENABLED" },
    { 0, NULL }
};

static const value_string mq_MQQA_PUT_vals[] =
{
/* 0*/ { MQ_MQQA_PUT_ALLOWED, "MQQA_PUT_ALLOWED" },
/* 1*/ { MQ_MQQA_PUT_INHIBITED, "MQQA_PUT_INHIBITED" },
    { 0, NULL }
};

static const value_string mq_MQQA_vals[] =
{
/* 0*/ { MQ_MQQA_NOT_SHAREABLE, "MQQA_NOT_SHAREABLE" },
/* 1*/ { MQ_MQQA_SHAREABLE, "MQQA_SHAREABLE" },
    { 0, NULL }
};

static const value_string mq_MQQA_BACKOUT_vals[] =
{
/* 0*/ { MQ_MQQA_BACKOUT_NOT_HARDENED, "MQQA_BACKOUT_NOT_HARDENED" },
/* 1*/ { MQ_MQQA_BACKOUT_HARDENED, "MQQA_BACKOUT_HARDENED" },
    { 0, NULL }
};

static const value_string mq_MQMDS_vals[] =
{
/* 0*/ { MQ_MQMDS_PRIORITY, "MQMDS_PRIORITY" },
/* 1*/ { MQ_MQMDS_FIFO, "MQMDS_FIFO" },
    { 0, NULL }
};

static const value_string mq_MQNPM_vals[] =
{
/*  0*/ { MQ_MQNPM_CLASS_NORMAL, "MQNPM_CLASS_NORMAL" },
/* 10*/ { MQ_MQNPM_CLASS_HIGH, "MQNPM_CLASS_HIGH" },
    { 0, NULL }
};

static const value_string mq_MQTC_vals[] =
{
/* 0*/ { MQ_MQTC_OFF, "MQTC_OFF" },
/* 1*/ { MQ_MQTC_ON, "MQTC_ON" },
    { 0, NULL }
};

static const value_string mq_MQTT_vals[] =
{
/* 0*/ { MQ_MQTT_NONE, "MQTT_NONE" },
/* 1*/ { MQ_MQTT_FIRST, "MQTT_FIRST" },
/* 2*/ { MQ_MQTT_EVERY, "MQTT_EVERY" },
/* 3*/ { MQ_MQTT_DEPTH, "MQTT_DEPTH" },
    { 0, NULL }
};

#if 0
static const value_string mq_TriggerRestart_vals[] =
{
/* 0*/ { MQ_MQTRIGGER_RESTART_NO, "MQTRIGGER_RESTART_NO" },
/* 1*/ { MQ_MQTRIGGER_RESTART_YES, "MQTRIGGER_RESTART_YES" },
    { 0, NULL }
};
#endif

static const value_string mq_MQDL_vals[] =
{
/* 0*/ { MQ_MQDL_NOT_SUPPORTED, "MQDL_NOT_SUPPORTED" },
/* 1*/ { MQ_MQDL_SUPPORTED, "MQDL_SUPPORTED" },
    { 0, NULL }
};

static const value_string mq_MQIT_vals[] =
{
/* 0*/ { MQ_MQIT_NONE, "MQIT_NONE" },
/* 1*/ { MQ_MQIT_MSG_ID, "MQIT_MSG_ID" },
/* 2*/ { MQ_MQIT_CORREL_ID, "MQIT_CORREL_ID" },
/* 4*/ { MQ_MQIT_MSG_TOKEN, "MQIT_MSG_TOKEN" },
/* 5*/ { MQ_MQIT_GROUP_ID, "MQIT_GROUP_ID" },
    { 0, NULL }
};

static const value_string mq_MQBND_vals[] =
{
/* 0*/ { MQ_MQBND_BIND_ON_OPEN, "MQBND_BIND_ON_OPEN" },
/* 1*/ { MQ_MQBND_BIND_NOT_FIXED, "MQBND_BIND_NOT_FIXED" },
/* 2*/ { MQ_MQBND_BIND_ON_GROUP, "MQBND_BIND_ON_GROUP" },
    { 0, NULL }
};

static const value_string m_MQQSGD_vals[] =
{
/* -1*/ { MQ_MQQSGD_ALL, "MQQSGD_ALL" },
/*  0*/ { MQ_MQQSGD_Q_MGR, "MQQSGD_Q_MGR" },
/*  1*/ { MQ_MQQSGD_COPY, "MQQSGD_COPY" },
/*  2*/ { MQ_MQQSGD_SHARED, "MQQSGD_SHARED" },
/*  3*/ { MQ_MQQSGD_GROUP, "MQQSGD_GROUP" },
/*  4*/ { MQ_MQQSGD_PRIVATE, "MQQSGD_PRIVATE" },
/*  6*/ { MQ_MQQSGD_LIVE, "MQQSGD_LIVE" },
    { 0, NULL }
};

#if 0
static const value_string mq_ReorgCtls_vals[] =
{
/* 0*/ { MQ_MQREORG_DISABLED, "MQREORG_DISABLED" },
/* 1*/ { MQ_MQREORG_ENABLED, "MQREORG_ENABLED" },
    { 0, NULL }
};
#endif

value_string mq_MQREADA_vals[] =
{
/* 0*/ { MQ_MQREADA_NO, "MQREADA_NO" },
/* 1*/ { MQ_MQREADA_YES, "MQREADA_YES" },
/* 2*/ { MQ_MQREADA_DISABLED, "MQREADA_DISABLED" },
/* 3*/ { MQ_MQREADA_INHIBITED, "MQREADA_INHIBITED" },
/* 4*/ { MQ_MQREADA_BACKLOG, "MQREADA_BACKLOG" },
    { 0, NULL }
};

value_string mq_MQPROP_vals[] =
{
/* 0*/ { MQ_MQPROP_COMPATIBILITY, "MQPROP_COMPATIBILITY" },
/* 1*/ { MQ_MQPROP_NONE, "MQPROP_NONE" },
/* 2*/ { MQ_MQPROP_ALL, "MQPROP_ALL" },
/* 3*/ { MQ_MQPROP_FORCE_MQRFH2, "MQPROP_FORCE_MQRFH2" },
/* 4*/ { MQ_MQPROP_V6COMPAT, "MQPROP_V6COMPAT" },
    { 0, NULL }
};

static const value_string mq_MQEVO_vals[] =
{
/* 0*/ { MQ_MQEVO_OTHER, "MQEVO_OTHER" },
/* 1*/ { MQ_MQEVO_CONSOLE, "MQEVO_CONSOLE" },
/* 2*/ { MQ_MQEVO_INIT, "MQEVO_INIT" },
/* 3*/ { MQ_MQEVO_MSG, "MQEVO_MSG" },
/* 4*/ { MQ_MQEVO_MQSET, "MQEVO_MQSET" },
/* 5*/ { MQ_MQEVO_INTERNAL, "MQEVO_INTERNAL" },
/* 6*/ { MQ_MQEVO_MQSUB, "MQEVO_MQSUB" },
/* 7*/ { MQ_MQEVO_CTLMSG, "MQEVO_CTLMSG" },
/* 8*/ { MQ_MQEVO_REST, "MQEVO_REST" },
    { 0, NULL }
};

value_string mq_MQPER_vals[] =
{
/* -1*/ { MQ_MQPER_PERSISTENCE_AS_PARENT, "MQPER_PERSISTENCE_AS_PARENT" },
/*  0*/ { MQ_MQPER_NOT_PERSISTENT, "MQPER_NOT_PERSISTENT" },
/*  1*/ { MQ_MQPER_PERSISTENT, "MQPER_PERSISTENT" },
/*  2*/ { MQ_MQPER_PERSISTENCE_AS_Q_DEF, "MQPER_PERSISTENCE_AS_Q_DEF" },
    { 0, NULL }
};

static const value_string mq_MQUCI_vals[] =
{
/* 0*/ { MQ_MQUCI_NO, "MQUCI_NO" },
/* 1*/ { MQ_MQUCI_YES, "MQUCI_YES" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQLR_vals[] =
{
/*  -2*/ { MQ_MQLR_MAX, "MQLR_MAX" },
/*   1*/ { MQ_MQLR_ONE, "MQLR_ONE" },
/*  -1*/ { MQ_MQLR_AUTO, "MQLR_AUTO" },
    { 0, NULL }
};
static const value_string mq_MQMEDIMGSCHED_vals[] =
{
/*   0*/ { MQ_MQMEDIMGSCHED_MANUAL, "MQMEDIMGSCHED_MANUAL" },
/*   1*/ { MQ_MQMEDIMGSCHED_AUTO, "MQMEDIMGSCHED_AUTO" },
    { 0, NULL }
};
static const value_string mq_MQMEDIMGINTVL_vals[] =
{
/*   0*/ { MQ_MQMEDIMGINTVL_OFF, "MQMEDIMGINTVL_OFF" },
    { 0, NULL }
};
static const value_string mq_MQMEDIMGLOGLN_vals[] =
{
/*   0*/ { MQ_MQMEDIMGLOGLN_OFF, "MQMEDIMGLOGLN_OFF" },
    { 0, NULL }
};
static const value_string mq_MQIMGRCOV_vals[] =
{
/*   0*/ { MQ_MQIMGRCOV_NO, "MQIMGRCOV_NO" },
/*   1*/ { MQ_MQIMGRCOV_YES, "MQIMGRCOV_YES" },
/*   2*/ { MQ_MQIMGRCOV_AS_Q_MGR, "MQIMGRCOV_AS_Q_MGR" },
    { 0, NULL }
};
#endif

value_string mq_MQMT_vals[] =
{
/*   1*/ { MQ_MQMT_REQUEST, "MQMT_REQUEST" },
/*   2*/ { MQ_MQMT_REPLY, "MQMT_REPLY" },
/*   3*/ { MQ_MQMT_DATAGRAM, "MQMT_DATAGRAM" },
/*   4*/ { MQ_MQMT_REPORT, "MQMT_REPORT" },
/* 112*/ { MQ_MQMT_MQE_FIELDS_FROM_MQE, "MQMT_MQE_FIELDS_FROM_MQE" },
/* 113*/ { MQ_MQMT_MQE_FIELDS, "MQMT_MQE_FIELDS" },
    { 0, NULL }
};

static const value_string mq_MQPL_vals[] =
{
/*  1*/ { MQ_MQPL_ZOS, "ZOS/MVS/OS390" },
/*  2*/ { MQ_MQPL_OS2, "MQPL_OS2" },
/*  3*/ { MQ_MQPL_UNIX, "UNIX/AIX" },
/*  4*/ { MQ_MQPL_OS400, "MQPL_OS400" },
/*  5*/ { MQ_MQPL_WINDOWS, "MQPL_WINDOWS" },
/* 11*/ { MQ_MQPL_WINDOWS_NT, "MQPL_WINDOWS_NT" },
/* 12*/ { MQ_MQPL_VMS, "MQPL_VMS" },
/* 13*/ { MQ_MQPL_NSK, "NSK/NSS" },
/* 15*/ { MQ_MQPL_OPEN_TP1, "MQPL_OPEN_TP1" },
/* 18*/ { MQ_MQPL_VM, "MQPL_VM" },
/* 23*/ { MQ_MQPL_TPF, "MQPL_TPF" },
/* 27*/ { MQ_MQPL_VSE, "MQPL_VSE" },
/* 28*/ { MQ_MQPL_APPLIANCE, "MQPL_APPLIANCE" },
    { 0, NULL }
};

static const value_string mq_MQCMDI_vals[] =
{
/*  1*/ { MQ_MQCMDI_CMDSCOPE_ACCEPTED, "MQCMDI_CMDSCOPE_ACCEPTED" },
/*  2*/ { MQ_MQCMDI_CMDSCOPE_GENERATED, "MQCMDI_CMDSCOPE_GENERATED" },
/*  3*/ { MQ_MQCMDI_CMDSCOPE_COMPLETED, "MQCMDI_CMDSCOPE_COMPLETED" },
/*  4*/ { MQ_MQCMDI_QSG_DISP_COMPLETED, "MQCMDI_QSG_DISP_COMPLETED" },
/*  5*/ { MQ_MQCMDI_COMMAND_ACCEPTED, "MQCMDI_COMMAND_ACCEPTED" },
/*  6*/ { MQ_MQCMDI_CLUSTER_REQUEST_QUEUED, "MQCMDI_CLUSTER_REQUEST_QUEUED" },
/*  7*/ { MQ_MQCMDI_CHANNEL_INIT_STARTED, "MQCMDI_CHANNEL_INIT_STARTED" },
/* 11*/ { MQ_MQCMDI_RECOVER_STARTED, "MQCMDI_RECOVER_STARTED" },
/* 12*/ { MQ_MQCMDI_BACKUP_STARTED, "MQCMDI_BACKUP_STARTED" },
/* 13*/ { MQ_MQCMDI_RECOVER_COMPLETED, "MQCMDI_RECOVER_COMPLETED" },
/* 14*/ { MQ_MQCMDI_SEC_TIMER_ZERO, "MQCMDI_SEC_TIMER_ZERO" },
/* 16*/ { MQ_MQCMDI_REFRESH_CONFIGURATION, "MQCMDI_REFRESH_CONFIGURATION" },
/* 17*/ { MQ_MQCMDI_SEC_SIGNOFF_ERROR, "MQCMDI_SEC_SIGNOFF_ERROR" },
/* 18*/ { MQ_MQCMDI_IMS_BRIDGE_SUSPENDED, "MQCMDI_IMS_BRIDGE_SUSPENDED" },
/* 19*/ { MQ_MQCMDI_DB2_SUSPENDED, "MQCMDI_DB2_SUSPENDED" },
/* 20*/ { MQ_MQCMDI_DB2_OBSOLETE_MSGS, "MQCMDI_DB2_OBSOLETE_MSGS" },
/* 21*/ { MQ_MQCMDI_SEC_UPPERCASE, "MQCMDI_SEC_UPPERCASE" },
/* 22*/ { MQ_MQCMDI_SEC_MIXEDCASE, "MQCMDI_SEC_MIXEDCASE" },
{ 0, NULL }
};

value_string mq_MQCFC_vals[] =
{
/* 0*/ { MQ_MQCFC_NOT_LAST, "MQCFC_NOT_LAST" },
/* 1*/ { MQ_MQCFC_LAST, "MQCFC_LAST" },
    { 0, NULL }
};

#if 0
static const value_string mq_ActionOptions_vals[] =
{
/* 1*/ { MQ_MQACT_FORCE_REMOVE, "MQACT_FORCE_REMOVE" },
/* 2*/ { MQ_MQACT_ADVANCE_LOG, "MQACT_ADVANCE_LOG" },
/* 3*/ { MQ_MQACT_COLLECT_STATISTICS, "MQACT_COLLECT_STATISTICS" },
/* 4*/ { MQ_MQACT_PUBSUB, "MQACT_PUBSUB" },
/* 5*/ { MQ_MQACT_ADD, "MQACT_ADD" },
/* 6*/ { MQ_MQACT_REPLACE, "MQACT_REPLACE" },
/* 7*/ { MQ_MQACT_REMOVE, "MQACT_REMOVE" },
/* 8*/ { MQ_MQACT_REMOVEALL, "MQACT_REMOVEALL" },
/* 9*/ { MQ_MQACT_FAIL, "MQACT_FAIL" },
/*10*/ { MQ_MQACT_REDUCE_LOG, "MQACT_REDUCE_LOG" },
/*11*/ { MQ_MQACT_ARCHIVE_LOG, "MQACT_ARCHIVE_LOG" },
    { 0, NULL }
};
#endif

static const value_string mq_MQAS_vals[] =
{
/* 0*/ { MQ_MQAS_NONE, "MQAS_NONE" },
/* 1*/ { MQ_MQAS_STARTED, "MQAS_STARTED" },
/* 2*/ { MQ_MQAS_START_WAIT, "MQAS_START_WAIT" },
/* 3*/ { MQ_MQAS_STOPPED, "MQAS_STOPPED" },
/* 4*/ { MQ_MQAS_SUSPENDED, "MQAS_SUSPENDED" },
/* 5*/ { MQ_MQAS_SUSPENDED_TEMPORARY, "MQAS_SUSPENDED_TEMPORARY" },
/* 6*/ { MQ_MQAS_ACTIVE, "MQAS_ACTIVE" },
/* 7*/ { MQ_MQAS_INACTIVE, "MQAS_INACTIVE" },
    { 0, NULL }
};

static const value_string mq_MQAUTH_vals[] =
{
/* -3*/ { MQ_MQAUTH_ALL_MQI, "MQAUTH_ALL_MQI" },
/* -2*/ { MQ_MQAUTH_ALL_ADMIN, "MQAUTH_ALL_ADMIN" },
/* -1*/ { MQ_MQAUTH_ALL, "MQAUTH_ALL" },
/*  0*/ { MQ_MQAUTH_NONE, "MQAUTH_NONE" },
/*  1*/ { MQ_MQAUTH_ALT_USER_AUTHORITY, "MQAUTH_ALT_USER_AUTHORITY" },
/*  2*/ { MQ_MQAUTH_BROWSE, "MQAUTH_BROWSE" },
/*  3*/ { MQ_MQAUTH_CHANGE, "MQAUTH_CHANGE" },
/*  4*/ { MQ_MQAUTH_CLEAR, "MQAUTH_CLEAR" },
/*  5*/ { MQ_MQAUTH_CONNECT, "MQAUTH_CONNECT" },
/*  6*/ { MQ_MQAUTH_CREATE, "MQAUTH_CREATE" },
/*  7*/ { MQ_MQAUTH_DELETE, "MQAUTH_DELETE" },
/*  8*/ { MQ_MQAUTH_DISPLAY, "MQAUTH_DISPLAY" },
/*  9*/ { MQ_MQAUTH_INPUT, "MQAUTH_INPUT" },
/* 10*/ { MQ_MQAUTH_INQUIRE, "MQAUTH_INQUIRE" },
/* 11*/ { MQ_MQAUTH_OUTPUT, "MQAUTH_OUTPUT" },
/* 12*/ { MQ_MQAUTH_PASS_ALL_CONTEXT, "MQAUTH_PASS_ALL_CONTEXT" },
/* 13*/ { MQ_MQAUTH_PASS_IDENTITY_CONTEXT, "MQAUTH_PASS_IDENTITY_CONTEXT" },
/* 14*/ { MQ_MQAUTH_SET, "MQAUTH_SET" },
/* 15*/ { MQ_MQAUTH_SET_ALL_CONTEXT, "MQAUTH_SET_ALL_CONTEXT" },
/* 16*/ { MQ_MQAUTH_SET_IDENTITY_CONTEXT, "MQAUTH_SET_IDENTITY_CONTEXT" },
/* 17*/ { MQ_MQAUTH_CONTROL, "MQAUTH_CONTROL" },
/* 18*/ { MQ_MQAUTH_CONTROL_EXTENDED, "MQAUTH_CONTROL_EXTENDED" },
/* 19*/ { MQ_MQAUTH_PUBLISH, "MQAUTH_PUBLISH" },
/* 20*/ { MQ_MQAUTH_SUBSCRIBE, "MQAUTH_SUBSCRIBE" },
/* 21*/ { MQ_MQAUTH_RESUME, "MQAUTH_RESUME" },
/* 22*/ { MQ_MQAUTH_SYSTEM, "MQAUTH_SYSTEM" },
    { 0, NULL }
};

#if 0
static const value_string mq_BridgeTypes_vals[] =
{
/* 1*/ { MQ_MQBT_OTMA, "MQBT_OTMA" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_RefreshRepositoryOptions_vals[] =
{
/* 0*/ { MQ_MQCFO_REFRESH_REPOSITORY_NO, "MQCFO_REFRESH_REPOSITORY_NO" },
/* 1*/ { MQ_MQCFO_REFRESH_REPOSITORY_YES, "MQCFO_REFRESH_REPOSITORY_YES" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_RemoveQueuesOptions_vals[] =
{
/* 0*/ { MQ_MQCFO_REMOVE_QUEUES_NO, "MQCFO_REMOVE_QUEUES_NO" },
/* 1*/ { MQ_MQCFO_REMOVE_QUEUES_YES, "MQCFO_REMOVE_QUEUES_YES" },
    { 0, NULL }
};
#endif

static const value_string mq_MQCHIDS_vals[] =
{
/* 0*/ { MQ_MQCHIDS_NOT_INDOUBT, "MQCHIDS_NOT_INDOUBT" },
/* 1*/ { MQ_MQCHIDS_INDOUBT, "MQCHIDS_INDOUBT" },
    { 0, NULL }
};

static const value_string mq_MQCHLD_vals[] =
{
/* -1*/ { MQ_MQCHLD_ALL, "MQCHLD_ALL" },
/*  1*/ { MQ_MQCHLD_DEFAULT, "MQCHLD_DEFAULT" },
/*  2*/ { MQ_MQCHLD_SHARED, "MQCHLD_SHARED" },
/*  4*/ { MQ_MQCHLD_PRIVATE, "MQCHLD_PRIVATE" },
/* 5 */ { MQ_MQCHLD_FIXSHARED, "MQCHLD_FIXSHARED" },
    { 0, NULL }
};

static const value_string mq_MQCHS_vals[] =
{
/*  0*/ { MQ_MQCHS_INACTIVE, "MQCHS_INACTIVE" },
/*  1*/ { MQ_MQCHS_BINDING, "MQCHS_BINDING" },
/*  2*/ { MQ_MQCHS_STARTING, "MQCHS_STARTING" },
/*  3*/ { MQ_MQCHS_RUNNING, "MQCHS_RUNNING" },
/*  4*/ { MQ_MQCHS_STOPPING, "MQCHS_STOPPING" },
/*  5*/ { MQ_MQCHS_RETRYING, "MQCHS_RETRYING" },
/*  6*/ { MQ_MQCHS_STOPPED, "MQCHS_STOPPED" },
/*  7*/ { MQ_MQCHS_REQUESTING, "MQCHS_REQUESTING" },
/*  8*/ { MQ_MQCHS_PAUSED, "MQCHS_PAUSED" },
/*  9*/ { MQ_MQCHS_DISCONNECTED, "MQCHS_DISCONNECTED" },
/* 13*/ { MQ_MQCHS_INITIALIZING, "MQCHS_INITIALIZING" },
/* 14*/ { MQ_MQCHS_SWITCHING, "MQCHS_SWITCHING" },
    { 0, NULL }
};

static const value_string mq_MQCHSSTATE_vals[] =
{
/*    0*/ { MQ_MQCHSSTATE_OTHER, "MQCHSSTATE_OTHER" },
/*  100*/ { MQ_MQCHSSTATE_END_OF_BATCH, "MQCHSSTATE_END_OF_BATCH" },
/*  200*/ { MQ_MQCHSSTATE_SENDING, "MQCHSSTATE_SENDING" },
/*  300*/ { MQ_MQCHSSTATE_RECEIVING, "MQCHSSTATE_RECEIVING" },
/*  400*/ { MQ_MQCHSSTATE_SERIALIZING, "MQCHSSTATE_SERIALIZING" },
/*  500*/ { MQ_MQCHSSTATE_RESYNCHING, "MQCHSSTATE_RESYNCHING" },
/*  600*/ { MQ_MQCHSSTATE_HEARTBEATING, "MQCHSSTATE_HEARTBEATING" },
/*  700*/ { MQ_MQCHSSTATE_IN_SCYEXIT, "MQCHSSTATE_IN_SCYEXIT" },
/*  800*/ { MQ_MQCHSSTATE_IN_RCVEXIT, "MQCHSSTATE_IN_RCVEXIT" },
/*  900*/ { MQ_MQCHSSTATE_IN_SENDEXIT, "MQCHSSTATE_IN_SENDEXIT" },
/* 1000*/ { MQ_MQCHSSTATE_IN_MSGEXIT, "MQCHSSTATE_IN_MSGEXIT" },
/* 1100*/ { MQ_MQCHSSTATE_IN_MREXIT, "MQCHSSTATE_IN_MREXIT" },
/* 1200*/ { MQ_MQCHSSTATE_IN_CHADEXIT, "MQCHSSTATE_IN_CHADEXIT" },
/* 1250*/ { MQ_MQCHSSTATE_NET_CONNECTING, "MQCHSSTATE_NET_CONNECTING" },
/* 1300*/ { MQ_MQCHSSTATE_SSL_HANDSHAKING, "MQCHSSTATE_SSL_HANDSHAKING" },
/* 1400*/ { MQ_MQCHSSTATE_NAME_SERVER, "MQCHSSTATE_NAME_SERVER" },
/* 1500*/ { MQ_MQCHSSTATE_IN_MQPUT, "MQCHSSTATE_IN_MQPUT" },
/* 1600*/ { MQ_MQCHSSTATE_IN_MQGET, "MQCHSSTATE_IN_MQGET" },
/* 1700*/ { MQ_MQCHSSTATE_IN_MQI_CALL, "MQCHSSTATE_IN_MQI_CALL" },
/* 1800*/ { MQ_MQCHSSTATE_COMPRESSING, "MQCHSSTATE_COMPRESSING" },
    { 0, NULL }
};

#if 0
static const value_string mq_ChannelSharedRestartOptions_vals[] =
{
/* 0*/ { MQ_MQCHSH_RESTART_NO, "MQCHSH_RESTART_NO" },
/* 1*/ { MQ_MQCHSH_RESTART_YES, "MQCHSH_RESTART_YES" },
    { 0, NULL }
};
#endif

static const value_string mq_MQCHSR_STOP_vals[] =
{
/* 0*/ { MQ_MQCHSR_STOP_NOT_REQUESTED, "MQCHSR_STOP_NOT_REQUESTED" },
/* 1*/ { MQ_MQCHSR_STOP_REQUESTED, "MQCHSR_STOP_REQUESTED" },
    { 0, NULL }
};

#if 0
static const value_string mq_ChannelTableTypes_vals[] =
{
/* 1*/ { MQ_MQCHTAB_Q_MGR, "MQCHTAB_Q_MGR" },
/* 2*/ { MQ_MQCHTAB_CLNTCONN, "MQCHTAB_CLNTCONN" },
    { 0, NULL }
};
#endif

static const value_string mq_MQINBD_vals[] =
{
/* 0*/ { MQ_MQINBD_Q_MGR, "MQINBD_Q_MGR" },
/* 3*/ { MQ_MQINBD_GROUP, "MQINBD_GROUP" },
    { 0, NULL }
};

static const value_string mq_MQTRAXSTR_vals[] =
{
/* 0*/ { MQ_MQTRAXSTR_NO, "MQTRAXSTR_NO" },
/* 1*/ { MQ_MQTRAXSTR_YES, "MQTRAXSTR_YES" },
    { 0, NULL }
};

#if 0
static const value_string mq_ClearTopicStringScope_vals[] =
{
/* 1*/ { MQ_MQCLRS_LOCAL, "MQCLRS_LOCAL" },
/* 2*/ { MQ_MQCLRS_GLOBAL, "MQCLRS_GLOBAL" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_ClearTopicStringType_vals[] =
{
/* 1*/ { MQ_MQCLRT_RETAINED, "MQCLRT_RETAINED" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_DisconnectTypes_vals[] =
{
/* 0*/ { MQ_MQDISCONNECT_NORMAL, "MQDISCONNECT_NORMAL" },
/* 1*/ { MQ_MQDISCONNECT_IMPLICIT, "MQDISCONNECT_IMPLICIT" },
/* 2*/ { MQ_MQDISCONNECT_Q_MGR, "MQDISCONNECT_Q_MGR" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_EscapeTypes_vals[] =
{
/* 1*/ { MQ_MQET_MQSC, "MQET_MQSC" },
    { 0, NULL }
};
#endif

static const value_string mq_MQFC_vals[] =
{
/* 0*/ { MQ_MQFC_NO, "MQFC_NO" },
/* 1*/ { MQ_MQFC_YES, "MQFC_YES" },
    { 0, NULL }
};

static const value_string mq_MQHSTATE_vals[] =
{
/* 0*/ { MQ_MQHSTATE_INACTIVE, "MQHSTATE_INACTIVE" },
/* 1*/ { MQ_MQHSTATE_ACTIVE, "MQHSTATE_ACTIVE" },
    { 0, NULL }
};

#if 0
static const value_string mq_InboundDispositions_vals[] =
{
/* 0*/ { MQ_MQINBD_Q_MGR, "MQINBD_Q_MGR" },
/* 3*/ { MQ_MQINBD_GROUP, "MQINBD_GROUP" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_IndoubtOptions_vals[] =
{
/* 1*/ { MQ_MQIDO_COMMIT, "MQIDO_COMMIT" },
/* 2*/ { MQ_MQIDO_BACKOUT, "MQIDO_BACKOUT" },
    { 0, NULL }
};
#endif

static const value_string mq_MQMCAS_vals[] =
{
/* 0*/ { MQ_MQMCAS_STOPPED, "MQMCAS_STOPPED" },
/* 3*/ { MQ_MQMCAS_RUNNING, "MQMCAS_RUNNING" },
    { 0, NULL }
};

#if 0
static const value_string mq_ModeOptions_vals[] =
{
/* 0*/ { MQ_MQMODE_FORCE, "MQMODE_FORCE" },
/* 1*/ { MQ_MQMODE_QUIESCE, "MQMODE_QUIESCE" },
/* 2*/ { MQ_MQMODE_TERMINATE, "MQMODE_TERMINATE" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_PurgeOptions_vals[] =
{
/* 0*/ { MQ_MQPO_NO, "MQPO_NO" },
/* 1*/ { MQ_MQPO_YES, "MQPO_YES" },
    { 0, NULL }
};
#endif

static const value_string mq_MQPSCLUS_vals[] =
{
/* 0*/ { MQ_MQPSCLUS_DISABLED, "MQPSCLUS_DISABLED" },
/* 1*/ { MQ_MQPSCLUS_ENABLED, "MQPSCLUS_ENABLED" },
    { 0, NULL }
};

static const value_string mq_PubSubMode_vals[] =
{
/* 0*/ { MQ_MQPSM_DISABLED, "MQPSM_DISABLED" },
/* 1*/ { MQ_MQPSM_COMPAT, "MQPSM_COMPAT" },
/* 2*/ { MQ_MQPSM_ENABLED, "MQPSM_ENABLED" },
    { 0, NULL }
};

static const value_string mq_PubSubSync_vals[] =
{
/* 0*/ { MQ_MQSYNCPOINT_YES, "MQSYNCPOINT_YES" },
/* 1*/ { MQ_MQSYNCPOINT_IFPER, "MQSYNCPOINT_IFPER" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQPSST_vals[] =
{
/* 0*/ { MQ_MQPSST_ALL, "MQPSST_ALL" },
/* 1*/ { MQ_MQPSST_LOCAL, "MQPSST_LOCAL" },
/* 2*/ { MQ_MQPSST_PARENT, "MQPSST_PARENT" },
/* 3*/ { MQ_MQPSST_CHILD, "MQPSST_CHILD" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQPS_STATUS_vals[] =
{
/* 0*/ { MQ_MQPS_STATUS_INACTIVE, "MQPS_STATUS_INACTIVE" },
/* 1*/ { MQ_MQPS_STATUS_STARTING, "MQPS_STATUS_STARTING" },
/* 2*/ { MQ_MQPS_STATUS_STOPPING, "MQPS_STATUS_STOPPING" },
/* 3*/ { MQ_MQPS_STATUS_ACTIVE, "MQPS_STATUS_ACTIVE" },
/* 4*/ { MQ_MQPS_STATUS_COMPAT, "MQPS_STATUS_COMPAT" },
/* 5*/ { MQ_MQPS_STATUS_ERROR, "MQPS_STATUS_ERROR" },
/* 6*/ { MQ_MQPS_STATUS_REFUSED, "MQPS_STATUS_REFUSED" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQQMDT_vals[] =
{
/* 1*/ { MQ_MQQMDT_EXPLICIT_CLUSTER_SENDER, "MQQMDT_EXPLICIT_CLUSTER_SENDER" },
/* 2*/ { MQ_MQQMDT_AUTO_CLUSTER_SENDER, "MQQMDT_AUTO_CLUSTER_SENDER" },
/* 3*/ { MQ_MQQMDT_CLUSTER_RECEIVER, "MQQMDT_CLUSTER_RECEIVER" },
/* 4*/ { MQ_MQQMDT_AUTO_EXP_CLUSTER_SENDER, "MQQMDT_AUTO_EXP_CLUSTER_SENDER" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQQMFAC_vals[] =
{
/* 1*/ { MQ_MQQMFAC_IMS_BRIDGE, "MQQMFAC_IMS_BRIDGE" },
/* 2*/ { MQ_MQQMFAC_DB2, "MQQMFAC_DB2" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQQMSTA_vals[] =
{
/* 1*/ { MQ_MQQMSTA_STARTING, "MQQMSTA_STARTING" },
/* 2*/ { MQ_MQQMSTA_RUNNING, "MQQMSTA_RUNNING" },
/* 3*/ { MQ_MQQMSTA_QUIESCING, "MQQMSTA_QUIESCING" },
/* 4*/ { MQ_MQQMSTA_STANDBY, "MQQMSTA_STANDBY" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQQMT_vals[] =
{
/* 0*/ { MQ_MQQMT_NORMAL, "MQQMT_NORMAL" },
/* 1*/ { MQ_MQQMT_REPOSITORY, "MQQMT_REPOSITORY" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQQO_vals[] =
{
/* 0*/ { MQ_MQQO_NO, "MQQO_NO" },
/* 1*/ { MQ_MQQO_YES, "MQQO_YES" },
    { 0, NULL }
};
#endif

static const value_string mq_MQQSOT_vals[] =
{
/* 1*/ { MQ_MQQSOT_ALL, "MQQSOT_ALL" },
/* 2*/ { MQ_MQQSOT_INPUT, "MQQSOT_INPUT" },
/* 3*/ { MQ_MQQSOT_OUTPUT, "MQQSOT_OUTPUT" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQNT_vals[] =
{
/*    0*/ { MQ_MQNT_NONE, "MQNT_NONE" },
/*    1*/ { MQ_MQNT_Q, "MQNT_Q" },
/*    2*/ { MQ_MQNT_CLUSTER, "MQNT_CLUSTER" },
/*    4*/ { MQ_MQNT_AUTH_INFO, "MQNT_AUTH_INFO" },
/* 1001*/ { MQ_MQNT_ALL, "MQNT_ALL" },
    { 0, NULL }
};
#endif

static const value_string mq_MQQSGS_vals[] =
{
/* 0*/ { MQ_MQQSGS_UNKNOWN, "MQQSGS_UNKNOWN" },
/* 1*/ { MQ_MQQSGS_CREATED, "MQQSGS_CREATED" },
/* 2*/ { MQ_MQQSGS_ACTIVE, "MQQSGS_ACTIVE" },
/* 3*/ { MQ_MQQSGS_INACTIVE, "MQQSGS_INACTIVE" },
/* 4*/ { MQ_MQQSGS_FAILED, "MQQSGS_FAILED" },
/* 5*/ { MQ_MQQSGS_PENDING, "MQQSGS_PENDING" },
    { 0, NULL }
};

#if 0
static const value_string mq_QueueStatusType_vals[] =
{
/* 1104*/ { MQ_MQIACF_Q_HANDLE, "MQIACF_Q_HANDLE" },
/* 1105*/ { MQ_MQIACF_Q_STATUS, "MQIACF_Q_STATUS" },
    { 0, NULL }
};
#endif

static const value_string mq_MQQSO_vals[] =
{
/* 0*/ { MQ_MQQSO_NO, "MQQSO_NO" },
/* 1*/ { MQ_MQQSO_SHARED, "MQQSO_YES/MQQSO_SHARED" },
/* 2*/ { MQ_MQQSO_EXCLUSIVE, "MQQSO_EXCLUSIVE" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQQSUM_vals[] =
{
/* 0*/ { MQ_MQQSUM_NO, "MQQSUM_NO" },
/* 1*/ { MQ_MQQSUM_YES, "MQQSUM_YES" },
    { 0, NULL }
};
#endif

static const value_string mq_MQRP_vals[] =
{
/* 0*/ { MQ_MQRP_NO, "MQRP_NO" },
/* 1*/ { MQ_MQRP_YES, "MQRP_YES" },
    { 0, NULL }
};

static const value_string mq_MQRQ_vals[] =
{
/*  1*/ { MQ_MQRQ_CONN_NOT_AUTHORIZED, "MQRQ_CONN_NOT_AUTHORIZED" },
/*  2*/ { MQ_MQRQ_OPEN_NOT_AUTHORIZED, "MQRQ_OPEN_NOT_AUTHORIZED" },
/*  3*/ { MQ_MQRQ_CLOSE_NOT_AUTHORIZED, "MQRQ_CLOSE_NOT_AUTHORIZED" },
/*  4*/ { MQ_MQRQ_CMD_NOT_AUTHORIZED, "MQRQ_CMD_NOT_AUTHORIZED" },
/*  5*/ { MQ_MQRQ_Q_MGR_STOPPING, "MQRQ_Q_MGR_STOPPING" },
/*  6*/ { MQ_MQRQ_Q_MGR_QUIESCING, "MQRQ_Q_MGR_QUIESCING" },
/*  7*/ { MQ_MQRQ_CHANNEL_STOPPED_OK, "MQRQ_CHANNEL_STOPPED_OK" },
/*  8*/ { MQ_MQRQ_CHANNEL_STOPPED_ERROR, "MQRQ_CHANNEL_STOPPED_ERROR" },
/*  9*/ { MQ_MQRQ_CHANNEL_STOPPED_RETRY, "MQRQ_CHANNEL_STOPPED_RETRY" },
/* 10*/ { MQ_MQRQ_CHANNEL_STOPPED_DISABLED, "MQRQ_CHANNEL_STOPPED_DISABLED" },
/* 11*/ { MQ_MQRQ_BRIDGE_STOPPED_OK, "MQRQ_BRIDGE_STOPPED_OK" },
/* 12*/ { MQ_MQRQ_BRIDGE_STOPPED_ERROR, "MQRQ_BRIDGE_STOPPED_ERROR" },
/* 13*/ { MQ_MQRQ_SSL_HANDSHAKE_ERROR, "MQRQ_SSL_HANDSHAKE_ERROR" },
/* 14*/ { MQ_MQRQ_SSL_CIPHER_SPEC_ERROR, "MQRQ_SSL_CIPHER_SPEC_ERROR" },
/* 15*/ { MQ_MQRQ_SSL_CLIENT_AUTH_ERROR, "MQRQ_SSL_CLIENT_AUTH_ERROR" },
/* 16*/ { MQ_MQRQ_SSL_PEER_NAME_ERROR, "MQRQ_SSL_PEER_NAME_ERROR" },
/* 17*/ { MQ_MQRQ_SUB_NOT_AUTHORIZED, "MQRQ_SUB_NOT_AUTHORIZED" },
/* 18*/ { MQ_MQRQ_SUB_DEST_NOT_AUTHORIZED, "MQRQ_SUB_DEST_NOT_AUTHORIZED" },
/* 19*/ { MQ_MQRQ_SSL_UNKNOWN_REVOCATION, "MQRQ_SSL_UNKNOWN_REVOCATION" },
/* 20*/ { MQ_MQRQ_SYS_CONN_NOT_AUTHORIZED, "MQRQ_SYS_CONN_NOT_AUTHORIZED" },
/* 21*/ { MQ_MQRQ_CHANNEL_BLOCKED_ADDRESS, "MQRQ_CHANNEL_BLOCKED_ADDRESS" },
/* 22*/ { MQ_MQRQ_CHANNEL_BLOCKED_USERID, "MQRQ_CHANNEL_BLOCKED_USERID" },
/* 23*/ { MQ_MQRQ_CHANNEL_BLOCKED_NOACCESS, "MQRQ_CHANNEL_BLOCKED_NOACCESS" },
/* 24*/ { MQ_MQRQ_MAX_ACTIVE_CHANNELS, "MQRQ_MAX_ACTIVE_CHANNELS" },
/* 25*/ { MQ_MQRQ_MAX_CHANNELS, "MQRQ_MAX_CHANNELS" },
/* 26*/ { MQ_MQRQ_SVRCONN_INST_LIMIT, "MQRQ_SVRCONN_INST_LIMIT" },
/* 27*/ { MQ_MQRQ_CLIENT_INST_LIMIT, "MQRQ_CLIENT_INST_LIMIT" },
/* 28*/ { MQ_MQRQ_CAF_NOT_INSTALLED, "MQRQ_CAF_NOT_INSTALLED" },
/* 29*/ { MQ_MQRQ_CSP_NOT_AUTHORIZED, "MQRQ_CSP_NOT_AUTHORIZED" },
/* 30*/ { MQ_MQRQ_FAILOVER_PERMITTED, "MQRQ_FAILOVER_PERMITTED" },
/* 31*/ { MQ_MQRQ_FAILOVER_NOT_PERMITTED, "MQRQ_FAILOVER_NOT_PERMITTED" },
/* 32*/ { MQ_MQRQ_STANDBY_ACTIVATED, "MQRQ_STANDBY_ACTIVATED" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQRT_vals[] =
{
/* 1*/ { MQ_MQRT_CONFIGURATION, "MQRT_CONFIGURATION" },
/* 2*/ { MQ_MQRT_EXPIRY, "MQRT_EXPIRY" },
/* 3*/ { MQ_MQRT_NSPROC, "MQRT_NSPROC" },
/* 4*/ { MQ_MQRT_PROXYSUB, "MQRT_PROXYSUB" },
/* 5*/ { MQ_MQRT_SUB_CONFIGURATION, "MQRT_SUB_CONFIGURATION" },
    { 0, NULL }
};
#endif

static const value_string mq_MQSCO_vals[] =
{
/* 1*/ { MQ_MQSCO_Q_MGR, "MQSCO_Q_MGR" },
/* 2*/ { MQ_MQSCO_CELL, "MQSCO_CELL" },
    { 0, NULL }
};

static const value_string mq_MQSECITEM_vals[] =
{
/*  0*/ { MQ_MQSECITEM_ALL, "MQSECITEM_ALL" },
/*  1*/ { MQ_MQSECITEM_MQADMIN, "MQSECITEM_MQADMIN" },
/*  2*/ { MQ_MQSECITEM_MQNLIST, "MQSECITEM_MQNLIST" },
/*  3*/ { MQ_MQSECITEM_MQPROC, "MQSECITEM_MQPROC" },
/*  4*/ { MQ_MQSECITEM_MQQUEUE, "MQSECITEM_MQQUEUE" },
/*  5*/ { MQ_MQSECITEM_MQCONN, "MQSECITEM_MQCONN" },
/*  6*/ { MQ_MQSECITEM_MQCMDS, "MQSECITEM_MQCMDS" },
/*  7*/ { MQ_MQSECITEM_MXADMIN, "MQSECITEM_MXADMIN" },
/*  8*/ { MQ_MQSECITEM_MXNLIST, "MQSECITEM_MXNLIST" },
/*  9*/ { MQ_MQSECITEM_MXPROC, "MQSECITEM_MXPROC" },
/* 10*/ { MQ_MQSECITEM_MXQUEUE, "MQSECITEM_MXQUEUE" },
/* */ { MQ_MQSECITEM_MXTOPIC, "MQSECITEM_MXTOPIC" },
    { 0, NULL }
};

static const value_string mq_MQSECSW_vals[] =
{
/*  1*/ { MQ_MQSECSW_PROCESS, "MQSECSW_PROCESS" },
/*  2*/ { MQ_MQSECSW_NAMELIST, "MQSECSW_NAMELIST" },
/*  3*/ { MQ_MQSECSW_Q, "MQSECSW_Q" },
/*  4*/ { MQ_MQSECSW_TOPIC, "MQSECSW_TOPIC" },
/*  6*/ { MQ_MQSECSW_CONTEXT, "MQSECSW_CONTEXT" },
/*  7*/ { MQ_MQSECSW_ALTERNATE_USER, "MQSECSW_ALTERNATE_USER" },
/*  8*/ { MQ_MQSECSW_COMMAND, "MQSECSW_COMMAND" },
/*  9*/ { MQ_MQSECSW_CONNECTION, "MQSECSW_CONNECTION" },
/* 10*/ { MQ_MQSECSW_SUBSYSTEM, "MQSECSW_SUBSYSTEM" },
/* 11*/ { MQ_MQSECSW_COMMAND_RESOURCES, "MQSECSW_COMMAND_RESOURCES" },
/* 15*/ { MQ_MQSECSW_Q_MGR, "MQSECSW_Q_MGR" },
/* 16*/ { MQ_MQSECSW_QSG, "MQSECSW_QSG" },
/* 21*/ { MQ_MQSECSW_OFF_FOUND, "MQSECSW_OFF_FOUND" },
/* 22*/ { MQ_MQSECSW_ON_FOUND, "MQSECSW_ON_FOUND" },
/* 23*/ { MQ_MQSECSW_OFF_NOT_FOUND, "MQSECSW_OFF_NOT_FOUND" },
/* 24*/ { MQ_MQSECSW_ON_NOT_FOUND, "MQSECSW_ON_NOT_FOUND" },
/* 25*/ { MQ_MQSECSW_OFF_ERROR, "MQSECSW_OFF_ERROR" },
/* 26*/ { MQ_MQSECSW_ON_OVERRIDDEN, "MQSECSW_ON_OVERRIDDEN" },
    { 0, NULL }
};

static const value_string mq_MQSECTYPE_vals[] =
{
/* 1*/ { MQ_MQSECTYPE_AUTHSERV, "MQSECTYPE_AUTHSERV" },
/* 2*/ { MQ_MQSECTYPE_SSL, "MQSECTYPE_SSL" },
/* 3*/ { MQ_MQSECTYPE_CLASSES, "MQSECTYPE_CLASSES" },
/* 4*/ { MQ_MQSECTYPE_CONNAUTH, "MQSECTYPE_CONNAUTH" },
    { 0, NULL }
};

static const value_string mq_MQCHK_vals[] =
{
/* 0*/ { MQ_MQCHK_OPTIONAL, "MQCHK_OPTIONAL" },
/* 1*/ { MQ_MQCHK_NONE, "MQCHK_NONE" },
/* 2*/ { MQ_MQCHK_REQUIRED_ADMIN, "MQCHK_REQUIRED_ADMIN" },
/* 3*/ { MQ_MQCHK_REQUIRED, "MQCHK_REQUIRED" },
/* 4*/ { MQ_MQCHK_AS_Q_MGR, "MQCHK_AS_Q_MGR" },
    { 0, NULL }
};


static const value_string mq_MQADPCTX_vals[] =
{
/* 0*/ { MQ_MQADPCTX_NO, "MQADPCTX_NO" },
/* 1*/ { MQ_MQADPCTX_YES, "MQADPCTX_YES" },
    { 0, NULL }
};

static const value_string mq_MQSECCOMM_vals[] =
{
/* 0*/ { MQ_MQSECCOMM_NO, "MQSECCOMM_NO" },
/* 1*/ { MQ_MQSECCOMM_YES, "MQSECCOMM_YES" },
/* 2*/ { MQ_MQSECCOMM_ANON, "MQSECCOMM_ANON" },
    { 0, NULL }
};

static const value_string mq_MQLDAP_AUTHORMD_vals[] =
{
/* 0*/ { MQ_MQLDAP_AUTHORMD_OS, "MQLDAP_AUTHORMD_OS" },
/* 1*/ { MQ_MQLDAP_AUTHORMD_SEARCHGRP, "MQLDAP_AUTHORMD_SEARCHGRP" },
/* 2*/ { MQ_MQLDAP_AUTHORMD_SEARCHUSR, "MQLDAP_AUTHORMD_SEARCHUSR" },
/* 3*/ { MQ_MQLDAP_AUTHORMD_SRCHGRPSN, "MQLDAP_AUTHORMD_SRCHGRPSN" },
    { 0, NULL }
};

static const value_string mq_MQLDAP_NESTGRP_vals[] =
{
/* 0*/ { MQ_MQLDAP_NESTGRP_NO, "MQLDAP_NESTGRP_NO" },
/* 1*/ { MQ_MQLDAP_NESTGRP_YES, "MQLDAP_NESTGRP_YES" },
    { 0, NULL }
};

static const value_string mq_MQAUTHENTICATE_vals[] =
{
/* 0*/ { MQ_MQAUTHENTICATE_OS, "MQAUTHENTICATE_OS" },
/* 1*/ { MQ_MQAUTHENTICATE_PAM, "MQAUTHENTICATE_PAM" },
    { 0, NULL }
};

static const value_string mq_MQLDAPC_vals[] =
{
/* 0*/ { MQ_MQLDAPC_INACTIVE, "MQLDAPC_INACTIVE" },
/* 1*/ { MQ_MQLDAPC_CONNECTED, "MQLDAPC_CONNECTED" },
/* 2*/ { MQ_MQLDAPC_ERROR, "MQLDAPC_ERROR" },
    { 0, NULL }
};

static const value_string mq_MQZAET_vals[] =
{
/* 0*/ { MQ_MQZAET_NONE, "MQZAET_NONE" },
/* 1*/ { MQ_MQZAET_PRINCIPAL, "MQZAET_PRINCIPAL" },
/* 2*/ { MQ_MQZAET_GROUP, "MQZAET_GROUP" },
/* 3*/ { MQ_MQZAET_UNKNOWN, "MQZAET_UNKNOWN" },
    { 0, NULL }
};

static const value_string mq_MQTA_PUB_vals[] =
{
/* 0*/ { MQ_MQTA_PUB_AS_PARENT, "MQTA_PUB_AS_PARENT" },
/* 1*/ { MQ_MQTA_PUB_INHIBITED, "MQTA_PUB_INHIBITED" },
/* 2*/ { MQ_MQTA_PUB_ALLOWED, "MQTA_PUB_ALLOWED" },
    { 0, NULL }
};

static const value_string mq_MQDLV_vals[] =
{
/* 0*/ { MQ_MQDLV_AS_PARENT, "MQDLV_AS_PARENT" },
/* 1*/ { MQ_MQDLV_ALL, "MQDLV_ALL" },
/* 2*/ { MQ_MQDLV_ALL_DUR, "MQDLV_ALL_DUR" },
/* 3*/ { MQ_MQDLV_ALL_AVAIL, "MQDLV_ALL_AVAIL" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQCLCT_vals[] =
{
/* 0*/ { MQ_MQCLCT_STATIC, "MQCLCT_STATIC" },
/* 1*/ { MQ_MQCLCT_DYNAMIC, "MQCLCT_DYNAMIC" },
    { 0, NULL }
};
#endif

static const value_string mq_MQTA_SUB_vals[] =
{
/* 0*/ { MQ_MQTA_SUB_AS_PARENT, "MQTA_SUB_AS_PARENT" },
/* 1*/ { MQ_MQTA_SUB_INHIBITED, "MQTA_SUB_INHIBITED" },
/* 2*/ { MQ_MQTA_SUB_ALLOWED, "MQTA_SUB_ALLOWED" },
    { 0, NULL }
};

static const value_string mq_MQTA_PROXY_vals[] =
{
/* 1*/ { MQ_MQTA_PROXY_SUB_FORCE, "MQTA_PROXY_SUB_FORCE" },
/* 2*/ { MQ_MQTA_PROXY_SUB_FIRSTUSE, "MQTA_PROXY_SUB_FIRSTUSE" },
    { 0, NULL }
};

static const value_string mq_MQTA_vals[] =
{
/* 1*/ { MQ_MQTA_BLOCK, "MQTA_BLOCK" },
/* 2*/ { MQ_MQTA_PASSTHRU, "MQTA_PASSTHRU" },
    { 0, NULL }
};

static const value_string mq_MQTOPT_vals[] =
{
/* 0*/ { MQ_MQTOPT_LOCAL, "MQTOPT_LOCAL" },
/* 1*/ { MQ_MQTOPT_CLUSTER, "MQTOPT_CLUSTER" },
/* 2*/ { MQ_MQTOPT_ALL, "MQTOPT_ALL" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQSELTYPE_vals[] =
{
/* 0*/ { MQ_MQSELTYPE_NONE, "MQSELTYPE_NONE" },
/* 1*/ { MQ_MQSELTYPE_STANDARD, "MQSELTYPE_STANDARD" },
/* 2*/ { MQ_MQSELTYPE_EXTENDED, "MQSELTYPE_EXTENDED" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQSUS_vals[] =
{
/* 0*/ { MQ_MQSUS_NO, "MQSUS_NO" },
/* 1*/ { MQ_MQSUS_YES, "MQSUS_YES" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQSYNCPOINT_vals[] =
{
/* 0*/ { MQ_MQSYNCPOINT_YES, "MQSYNCPOINT_YES" },
/* 1*/ { MQ_MQSYNCPOINT_IFPER, "MQSYNCPOINT_IFPER" },
    { 0, NULL }
};
#endif

static const value_string mq_MQSYSP_vals[] =
{
/*  0*/ { MQ_MQSYSP_NO, "MQSYSP_NO" },
/*  1*/ { MQ_MQSYSP_YES, "MQSYSP_YES" },
/*  2*/ { MQ_MQSYSP_EXTENDED, "MQSYSP_EXTENDED" },
/* 10*/ { MQ_MQSYSP_TYPE_INITIAL, "MQSYSP_TYPE_INITIAL" },
/* 11*/ { MQ_MQSYSP_TYPE_SET, "MQSYSP_TYPE_SET" },
/* 12*/ { MQ_MQSYSP_TYPE_LOG_COPY, "MQSYSP_TYPE_LOG_COPY" },
/* 13*/ { MQ_MQSYSP_TYPE_LOG_STATUS, "MQSYSP_TYPE_LOG_STATUS" },
/* 14*/ { MQ_MQSYSP_TYPE_ARCHIVE_TAPE, "MQSYSP_TYPE_ARCHIVE_TAPE" },
/* 20*/ { MQ_MQSYSP_ALLOC_BLK, "MQSYSP_ALLOC_BLK" },
/* 21*/ { MQ_MQSYSP_ALLOC_TRK, "MQSYSP_ALLOC_TRK" },
/* 22*/ { MQ_MQSYSP_ALLOC_CYL, "MQSYSP_ALLOC_CYL" },
/* 30*/ { MQ_MQSYSP_STATUS_BUSY, "MQSYSP_STATUS_BUSY" },
/* 31*/ { MQ_MQSYSP_STATUS_PREMOUNT, "MQSYSP_STATUS_PREMOUNT" },
/* 32*/ { MQ_MQSYSP_STATUS_AVAILABLE, "MQSYSP_STATUS_AVAILABLE" },
/* 33*/ { MQ_MQSYSP_STATUS_UNKNOWN, "MQSYSP_STATUS_UNKNOWN" },
/* 34*/ { MQ_MQSYSP_STATUS_ALLOC_ARCHIVE, "MQSYSP_STATUS_ALLOC_ARCHIVE" },
/* 35*/ { MQ_MQSYSP_STATUS_COPYING_BSDS, "MQSYSP_STATUS_COPYING_BSDS" },
/* 36*/ { MQ_MQSYSP_STATUS_COPYING_LOG, "MQSYSP_STATUS_COPYING_LOG" },
    { 0, NULL }
};

static const value_string mq_MQSUB_DURABLE_vals[] =
{
/*-1*/ { MQ_MQSUB_DURABLE_ALL, "MQSUB_DURABLE_ALL" },
/* 0*/ { MQ_MQSUB_DURABLE_AS_PARENT, "MQSUB_DURABLE_AS_PARENT" },
/* 1*/ { MQ_MQSUB_DURABLE_ALLOWED, "ALLOWED/YES" },
/* 2*/ { MQ_MQSUB_DURABLE_INHIBITED, "INHIBITED/NO" },
    { 0, NULL }
};

static const value_string mq_MQSUBTYPE_vals[] =
{
/* -2*/ { MQ_MQSUBTYPE_USER, "MQSUBTYPE_USER" },
/* -1*/ { MQ_MQSUBTYPE_ALL, "MQSUBTYPE_ALL" },
/*  1*/ { MQ_MQSUBTYPE_API, "MQSUBTYPE_API" },
/*  2*/ { MQ_MQSUBTYPE_ADMIN, "MQSUBTYPE_ADMIN" },
/*  3*/ { MQ_MQSUBTYPE_PROXY, "MQSUBTYPE_PROXY" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQDC_vals[] =
{
/* 1*/ { MQ_MQDC_MANAGED, "MQDC_MANAGED" },
/* 2*/ { MQ_MQDC_PROVIDED, "MQDC_PROVIDED" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQRU_PUBLISH_vals[] =
{
/* 1*/ { MQ_MQRU_PUBLISH_ON_REQUEST, "MQRU_PUBLISH_ON_REQUEST" },
/* 2*/ { MQ_MQRU_PUBLISH_ALL, "MQRU_PUBLISH_ALL" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQTIME_vals[] =
{
/* 0*/ { MQ_MQTIME_UNIT_MINS, "MQTIME_UNIT_MINS" },
/* 1*/ { MQ_MQTIME_UNIT_SECS, "MQTIME_UNIT_SECS" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQVU_vals[] =
{
/* 1*/ { MQ_MQVU_FIXED_USER, "MQVU_FIXED_USER" },
/* 2*/ { MQ_MQVU_ANY_USER, "MQVU_ANY_USER" },
    { 0, NULL }
};
#endif

#if 0
static const value_string mq_MQWS_vals[] =
{
/* 0*/ { MQ_MQWS_DEFAULT, "MQWS_DEFAULT" },
/* 1*/ { MQ_MQWS_CHAR, "MQWS_CHAR" },
/* 2*/ { MQ_MQWS_TOPIC, "MQWS_TOPIC" },
    { 0, NULL }
};
#endif

static const value_string mq_MQUIDSUPP_vals[] =
{
/* 0*/ { MQ_MQUIDSUPP_NO, "MQUIDSUPP_NO" },
/* 1*/ { MQ_MQUIDSUPP_YES, "MQUIDSUPP_YES" },
    { 0, NULL }
};

static const value_string mq_MQUNDELIVERED_vals[] =
{
/* 0*/ { MQ_MQUNDELIVERED_NORMAL, "MQUNDELIVERED_NORMAL" },
/* 1*/ { MQ_MQUNDELIVERED_SAFE, "MQUNDELIVERED_SAFE" },
/* 2*/ { MQ_MQUNDELIVERED_DISCARD, "MQUNDELIVERED_DISCARD" },
/* 3*/ { MQ_MQUNDELIVERED_KEEP, "MQUNDELIVERED_KEEP" },
    { 0, NULL }
};

static const value_string mq_MQUOWST_vals[] =
{
/* 0*/ { MQ_MQUOWST_NONE, "MQUOWST_NONE" },
/* 1*/ { MQ_MQUOWST_ACTIVE, "MQUOWST_ACTIVE" },
/* 2*/ { MQ_MQUOWST_PREPARED, "MQUOWST_PREPARED" },
/* 3*/ { MQ_MQUOWST_UNRESOLVED, "MQUOWST_UNRESOLVED" },
    { 0, NULL }
};

static const value_string mq_MQUOWT_vals[] =
{
/* 0*/ { MQ_MQUOWT_Q_MGR, "MQUOWT_Q_MGR" },
/* 1*/ { MQ_MQUOWT_CICS, "MQUOWT_CICS" },
/* 2*/ { MQ_MQUOWT_RRS, "MQUOWT_RRS" },
/* 3*/ { MQ_MQUOWT_IMS, "MQUOWT_IMS" },
/* 4*/ { MQ_MQUOWT_XA, "MQUOWT_XA" },
    { 0, NULL }
};

static const value_string mq_MQUSAGE_PS_vals[] =
{
/* 0*/ { MQ_MQUSAGE_PS_AVAILABLE, "MQUSAGE_PS_AVAILABLE" },
/* 1*/ { MQ_MQUSAGE_PS_DEFINED, "MQUSAGE_PS_DEFINED" },
/* 2*/ { MQ_MQUSAGE_PS_OFFLINE, "MQUSAGE_PS_OFFLINE" },
/* 3*/ { MQ_MQUSAGE_PS_NOT_DEFINED, "MQUSAGE_PS_NOT_DEFINED" },
    { 0, NULL }
};

static const value_string mq_MQUSAGE_EXPAND_vals[] =
{
/* 1*/ { MQ_MQUSAGE_EXPAND_USER, "MQUSAGE_EXPAND_USER" },
/* 2*/ { MQ_MQUSAGE_EXPAND_SYSTEM, "MQUSAGE_EXPAND_SYSTEM" },
/* 3*/ { MQ_MQUSAGE_EXPAND_NONE, "MQUSAGE_EXPAND_NONE" },
    { 0, NULL }
};

static const value_string mq_MQUSAGE_DS_vals[] =
{
/* 10*/ { MQ_MQUSAGE_DS_OLDEST_ACTIVE_UOW, "MQUSAGE_DS_OLDEST_ACTIVE_UOW" },
/* 11*/ { MQ_MQUSAGE_DS_OLDEST_PS_RECOVERY, "MQUSAGE_DS_OLDEST_PS_RECOVERY" },
/* 12*/ { MQ_MQUSAGE_DS_OLDEST_CF_RECOVERY, "MQUSAGE_DS_OLDEST_CF_RECOVERY" },
    { 0, NULL }
};

#if 0
static const value_string mq_MQOPER_vals[] =
{
/*  0*/ { MQ_MQOPER_UNKNOWN, "MQOPER_UNKNOWN" },
/*  1*/ { MQ_MQOPER_BROWSE, "MQOPER_BROWSE" },
/*  2*/ { MQ_MQOPER_DISCARD, "MQOPER_DISCARD" },
/*  3*/ { MQ_MQOPER_GET, "MQOPER_GET" },
/*  4*/ { MQ_MQOPER_PUT, "MQOPER_PUT" },
/*  5*/ { MQ_MQOPER_PUT_REPLY, "MQOPER_PUT_REPLY" },
/*  6*/ { MQ_MQOPER_PUT_REPORT, "MQOPER_PUT_REPORT" },
/*  7*/ { MQ_MQOPER_RECEIVE, "MQOPER_RECEIVE" },
/*  8*/ { MQ_MQOPER_SEND, "MQOPER_SEND" },
/*  9*/ { MQ_MQOPER_TRANSFORM, "MQOPER_TRANSFORM" },
/* 10*/ { MQ_MQOPER_PUBLISH, "MQOPER_PUBLISH" },
/* 11*/ { MQ_MQOPER_EXCLUDED_PUBLISH, "MQOPER_EXCLUDED_PUBLISH" },
/* 12*/ { MQ_MQOPER_DISCARDED_PUBLISH, "MQOPER_DISCARDED_PUBLISH" },
    { 0, NULL }
};
#endif

static const value_string mq_MQIACF_CONN_INFO_vals[] =
{
/* 1111*/ { MQ_MQIACF_CONN_INFO_CONN, "MQIACF_CONN_INFO_CONN" },
/* 1112*/ { MQ_MQIACF_CONN_INFO_HANDLE, "MQIACF_CONN_INFO_HANDLE" },
/* 1113*/ { MQ_MQIACF_CONN_INFO_ALL, "MQIACF_CONN_INFO_ALL" },
    { 0, NULL }
};

static const value_string mq_MQPRI_vals[] =
{
/* -3*/ { MQ_MQPRI_PRIORITY_AS_PUBLISHED, "MQPRI_PRIORITY_AS_PUBLISHED" },
/* -2*/ { MQ_MQPRI_PRIORITY_AS_PARENT, "MQPRI_PRIORITY_AS_PARENT" },
/* -1*/ { MQ_MQPRI_PRIORITY_AS_Q_DEF, "MQPRI_PRIORITY_AS_Q_DEF" },
/*  0*/ { MQ_0, "0" },
/*  1*/ { MQ_1, "1" },
/*  2*/ { MQ_2, "2" },
/*  3*/ { MQ_3, "3" },
/*  4*/ { MQ_4, "4" },
/*  5*/ { MQ_5, "5" },
/*  6*/ { MQ_6, "6" },
/*  7*/ { MQ_7, "7" },
/*  8*/ { MQ_8, "8" },
/*  9*/ { MQ_9, "9" },
    { 0, NULL }
};

static const value_string mq_MQPSPROP_vals[] =
{
/* 0*/ { MQ_MQPSPROP_NONE, "MQPSPROP_NONE" },
/* 1*/ { MQ_MQPSPROP_COMPAT, "MQPSPROP_COMPAT" },
/* 2*/ { MQ_MQPSPROP_RFH2, "MQPSPROP_RFH2" },
/* 3*/ { MQ_MQPSPROP_MSGPROP, "MQPSPROP_MSGPROP" },
    { 0, NULL }
};

static const value_string mq_MQSCOPE_vals[] =
{
/* 0*/ { MQ_MQSCOPE_ALL, "MQSCOPE_ALL" },
/* 1*/ { MQ_MQSCOPE_AS_PARENT, "MQSCOPE_AS_PARENT" },
/* 4*/ { MQ_MQSCOPE_QMGR, "MQSCOPE_QMGR" },
    { 0, NULL }
};

static const value_string mq_MQ_SUITE_B_vals[] =
{
/* 0*/ { MQ_MQ_SUITE_B_NOT_AVAILABLE, "MQ_SUITE_B_NOT_AVAILABLE" },
/* 1*/ { MQ_MQ_SUITE_B_NONE, "MQ_SUITE_B_NONE" },
/* 2*/ { MQ_MQ_SUITE_B_128_BIT, "MQ_SUITE_B_128_BIT" },
/* 4*/ { MQ_MQ_SUITE_B_192_BIT, "MQ_SUITE_B_192_BIT" },
    { 0, NULL }
};

static const value_string mq_MQMC_vals[] =
{
/* 0*/ { MQ_MQMC_AS_PARENT, "MQMC_AS_PARENT" },
/* 1*/ { MQ_MQMC_ENABLED, "MQMC_ENABLED" },
/* 2*/ { MQ_MQMC_DISABLED, "MQMC_DISABLED" },
/* 3*/ { MQ_MQMC_ONLY, "MQMC_ONLY" },
    { 0, NULL }
};

static const value_string mq_MQUSEDLQ_vals[] =
{
/* 0*/ { MQ_MQUSEDLQ_AS_PARENT, "MQUSEDLQ_AS_PARENT" },
/* 1*/ { MQ_MQUSEDLQ_NO, "MQUSEDLQ_NO" },
/* 2*/ { MQ_MQUSEDLQ_YES, "MQUSEDLQ_YES" },
    { 0, NULL }
};

static const value_string mq_MQCLROUTE_vals[] =
{
/* 0*/ { MQ_MQCLROUTE_DIRECT, "MQCLROUTE_DIRECT" },
/* 1*/ { MQ_MQCLROUTE_TOPIC_HOST, "MQCLROUTE_TOPIC_HOST" },
/* 2*/ { MQ_MQCLROUTE_NONE, "MQCLROUTE_NONE" },
    { 0, NULL }
};

static const value_string mq_MQCLST_vals[] =
{
/* 0*/ { MQ_MQCLST_ACTIVE, "MQCLST_ACTIVE" },
/* 1*/ { MQ_MQCLST_PENDING, "MQCLST_PENDING" },
/* 2*/ { MQ_MQCLST_INVALID, "MQCLST_INVALID" },
/* 3*/ { MQ_MQCLST_ERROR, "MQCLST_ERROR" },
    { 0, NULL }
};

static const value_string mq_MQMULC_vals[] =
{
/* 0*/ { MQ_MQMULC_STANDARD, "MQMULC_STANDARD" },
/* 1*/ { MQ_MQMULC_REFINED, "MQMULC_REFINED" },
    { 0, NULL }
};

static const value_string mq_MQIGQPA_vals[] =
{
/* 1*/ { MQ_MQIGQPA_DEFAULT, "MQIGQPA_DEFAULT" },
/* 2*/ { MQ_MQIGQPA_CONTEXT, "MQIGQPA_CONTEXT" },
/* 3*/ { MQ_MQIGQPA_ONLY_IGQ, "MQIGQPA_ONLY_IGQ" },
/* 4*/ { MQ_MQIGQPA_ALTERNATE_OR_IGQ, "MQIGQPA_ALTERNATE_OR_IGQ" },
    { 0, NULL }
};

static const value_string mq_MQSCYC_vals[] =
{
/* 0*/ { MQ_MQSCYC_UPPER, "MQSCYC_UPPER" },
/* 1*/ { MQ_MQSCYC_MIXED, "MQSCYC_MIXED" },
    { 0, NULL }
};

static const value_string mq_MQCAUT_vals[] =
{
/* 0*/ { MQ_MQCAUT_ALL, "MQCAUT_ALL" },
/* 1*/ { MQ_MQCAUT_BLOCKUSER, "MQCAUT_BLOCKUSER" },
/* 2*/ { MQ_MQCAUT_BLOCKADDR, "MQCAUT_BLOCKADDR" },
/* 3*/ { MQ_MQCAUT_SSLPEERMAP, "MQCAUT_SSLPEERMAP" },
/* 4*/ { MQ_MQCAUT_ADDRESSMAP, "MQCAUT_ADDRESSMAP" },
/* 5*/ { MQ_MQCAUT_USERMAP, "MQCAUT_USERMAP" },
/* 6*/ { MQ_MQCAUT_QMGRMAP, "MQCAUT_QMGRMAP" },
    { 0, NULL }
};

static const value_string mq_MQUSRC_vals[] =
{
/* 0*/ { MQ_MQUSRC_MAP, "MQUSRC_MAP" },
/* 1*/ { MQ_MQUSRC_NOACCESS, "MQUSRC_NOACCESS" },
/* 2*/ { MQ_MQUSRC_CHANNEL, "MQUSRC_CHANNEL" },
    { 0, NULL }
};

static const value_string mq_MQWARN_vals[] =
{
/* 0*/ { MQ_MQWARN_NO, "MQWARN_NO" },
/* 1*/ { MQ_MQWARN_YES, "MQWARN_YES" },
    { 0, NULL }
};

static const value_string mq_MQ_CERT_vals[] =
{
/* 0*/ { MQ_MQ_CERT_VAL_POLICY_ANY, "MQ_CERT_VAL_POLICY_ANY" },
/* 1*/ { MQ_MQ_CERT_VAL_POLICY_RFC5280, "MQ_CERT_VAL_POLICY_RFC5280" },
    { 0, NULL }
};

static const value_string mq_MQCHAD_vals[] =
{
/* 0*/ { MQ_MQCHAD_DISABLED, "MQCHAD_DISABLED" },
/* 1*/ { MQ_MQCHAD_ENABLED, "MQCHAD_ENABLED" },
    { 0, NULL }
};

static const value_string mq_MQCHLA_vals[] =
{
/* 0*/ { MQ_MQCHLA_DISABLED, "MQCHLA_DISABLED" },
/* 1*/ { MQ_MQCHLA_ENABLED, "MQCHLA_ENABLED" },
    { 0, NULL }
};

static const value_string mq_MQCLXQ_vals[] =
{
/* 0*/ { MQ_MQCLXQ_SCTQ, "MQCLXQ_SCTQ" },
/* 1*/ { MQ_MQCLXQ_CHANNEL, "MQCLXQ_CHANNEL" },
    { 0, NULL }
};

static const value_string mq_MQSVC_CONTROL_vals[] =
{
/* 0*/ { MQ_MQSVC_CONTROL_Q_MGR, "MQSVC_CONTROL_Q_MGR" },
/* 1*/ { MQ_MQSVC_CONTROL_Q_MGR_START, "MQSVC_CONTROL_Q_MGR_START" },
/* 2*/ { MQ_MQSVC_CONTROL_MANUAL, "MQSVC_CONTROL_MANUAL" },
    { 0, NULL }
};

static const value_string mq_MQSVC_STATUS_vals[] =
{
/* 0*/ { MQ_MQSVC_STATUS_STOPPED, "MQSVC_STATUS_STOPPED" },
/* 1*/ { MQ_MQSVC_STATUS_STARTING, "MQSVC_STATUS_STARTING" },
/* 2*/ { MQ_MQSVC_STATUS_RUNNING, "MQSVC_STATUS_RUNNING" },
/* 3*/ { MQ_MQSVC_STATUS_STOPPING, "MQSVC_STATUS_STOPPING" },
/* 4*/ { MQ_MQSVC_STATUS_RETRYING, "MQSVC_STATUS_RETRYING" },
    { 0, NULL }
};

static const value_string mq_MQCAP_vals[] =
{
/* 0*/ { MQ_MQCAP_NOT_SUPPORTED, "MQCAP_NOT_SUPPORTED" },
/* 1*/ { MQ_MQCAP_SUPPORTED, "MQCAP_SUPPORTED" },
/* 2*/ { MQ_MQCAP_EXPIRED, "MQCAP_EXPIRED" },
    { 0, NULL }
};

static const value_string mq_MQSSL_vals[] =
{
/* 0*/ { MQ_MQSSL_FIPS_NO, "MQSSL_FIPS_NO" },
/* 1*/ { MQ_MQSSL_FIPS_YES, "MQSSL_FIPS_YES" },
    { 0, NULL }
};

static const value_string mq_MQSP_vals[] =
{
/* 0*/ { MQ_MQSP_NOT_AVAILABLE, "MQSP_NOT_AVAILABLE" },
/* 1*/ { MQ_MQSP_AVAILABLE, "MQSP_AVAILABLE" },
    { 0, NULL }
};

value_string mq_MQCUOWC_vals[] =
{
/* 0x00000111*/ { MQ_MQCUOWC_ONLY, "MQCUOWC_ONLY" },
/* 0x00010000*/ { MQ_MQCUOWC_CONTINUE, "MQCUOWC_CONTINUE" },
/* 0x00000011*/ { MQ_MQCUOWC_FIRST, "MQCUOWC_FIRST" },
/* 0x00000010*/ { MQ_MQCUOWC_MIDDLE, "MQCUOWC_MIDDLE" },
/* 0x00000110*/ { MQ_MQCUOWC_LAST, "MQCUOWC_LAST" },
/* 0x00000100*/ { MQ_MQCUOWC_COMMIT, "MQCUOWC_COMMIT" },
/* 0x00001100*/ { MQ_MQCUOWC_BACKOUT, "MQCUOWC_BACKOUT" },
    { 0, NULL }
};

value_string mq_MQCLT_vals[] =
{
/* 1*/ { MQ_MQCLT_PROGRAM, "MQCLT_PROGRAM" },
/* 2*/ { MQ_MQCLT_TRANSACTION, "MQCLT_TRANSACTION" },
    { 0, NULL }
};

value_string mq_MQCADSD_vals[] =
{
/* 0x00000000*/ { MQ_MQCADSD_NONE, "MQCADSD_NONE" },
/* 0x00000001*/ { MQ_MQCADSD_SEND, "MQCADSD_SEND" },
/* 0x00000010*/ { MQ_MQCADSD_RECV, "MQCADSD_RECV" },
/* 0x00000100*/ { MQ_MQCADSD_MSGFORMAT, "MQCADSD_MSGFORMAT" },
    { 0, NULL }
};

value_string mq_MQCCT_vals[] =
{
/* 0x00000000*/ { MQ_MQCCT_NO, "MQCCT_NO" },
/* 0x00000001*/ { MQ_MQCCT_YES, "MQCCT_YES" },
    { 0, NULL }
};

value_string mq_MQCTES_vals[] =
{
/* 0x00000000*/ { MQ_MQCTES_NOSYNC, "MQCTES_NOSYNC" },
/* 0x00000100*/ { MQ_MQCTES_COMMIT, "MQCTES_COMMIT" },
/* 0x00001100*/ { MQ_MQCTES_BACKOUT, "MQCTES_BACKOUT" },
/* 0x00010000*/ { MQ_MQCTES_ENDTASK, "MQCTES_ENDTASK" },
    { 0, NULL }
};

static const value_string mq_MQCFR_vals[] =
{
/* 0*/ { MQ_MQCFR_NO, "MQCFR_NO" },
/* 1*/ { MQ_MQCFR_YES, "MQCFR_YES" },
    { 0, NULL }
};

static const value_string mq_MQDSB_vals[] =
{
/* 0*/ { MQ_MQDSB_DEFAULT, "MQDSB_DEFAULT" },
/* 1*/ { MQ_MQDSB_8K, "MQDSB_8K" },
/* 2*/ { MQ_MQDSB_16K, "MQDSB_16K" },
/* 3*/ { MQ_MQDSB_32K, "MQDSB_32K" },
/* 4*/ { MQ_MQDSB_64K, "MQDSB_64K" },
/* 5*/ { MQ_MQDSB_128K, "MQDSB_128K" },
/* 6*/ { MQ_MQDSB_256K, "MQDSB_256K" },
/* 7*/ { MQ_MQDSB_512K, "MQDSB_512K" },
/* 8*/ { MQ_MQDSB_1024K, "MQDSB_1024K" },
/* 9*/ { MQ_MQDSB_1M, "MQDSB_1M" },
    { 0, NULL }
};

static const value_string mq_MQDSE_vals[] =
{
/* 0*/ { MQ_MQDSE_DEFAULT, "MQDSE_DEFAULT" },
/* 1*/ { MQ_MQDSE_YES, "MQDSE_YES" },
/* 2*/ { MQ_MQDSE_NO, "MQDSE_NO" },
    { 0, NULL }
};

static const value_string mq_MQCFOFFLD_vals[] =
{
/* 0*/ { MQ_MQCFOFFLD_NONE, "MQCFOFFLD_NONE" },
/* 1*/ { MQ_MQCFOFFLD_SMDS, "MQCFOFFLD_SMDS" },
/* 2*/ { MQ_MQCFOFFLD_DB2, "MQCFOFFLD_DB2" },
/* 3*/ { MQ_MQCFOFFLD_BOTH, "MQCFOFFLD_BOTH" },
    { 0, NULL }
};

static const value_string mq_MQRECAUTO_vals[] =
{
/* 0*/ { MQ_MQRECAUTO_NO, "MQRECAUTO_NO" },
/* 1*/ { MQ_MQRECAUTO_YES, "MQRECAUTO_YES" },
    { 0, NULL }
};

static const value_string mq_MQCFCONLOS_vals[] =
{
/* 0*/ { MQ_MQCFCONLOS_TERMINATE, "MQCFCONLOS_TERMINATE" },
/* 1*/ { MQ_MQCFCONLOS_TOLERATE, "MQCFCONLOS_TOLERATE" },
/* 2*/ { MQ_MQCFCONLOS_ASQMGR, "MQCFCONLOS_ASQMGR" },
    { 0, NULL }
};

static const value_string mq_MQCFSTATUS_vals[] =
{
/*  0*/ { MQ_MQCFSTATUS_NOT_FOUND, "MQCFSTATUS_NOT_FOUND" },
/*  1*/ { MQ_MQCFSTATUS_ACTIVE, "MQCFSTATUS_ACTIVE" },
/*  2*/ { MQ_MQCFSTATUS_IN_RECOVER, "MQCFSTATUS_IN_RECOVER" },
/*  3*/ { MQ_MQCFSTATUS_IN_BACKUP, "MQCFSTATUS_IN_BACKUP" },
/*  4*/ { MQ_MQCFSTATUS_FAILED, "MQCFSTATUS_FAILED" },
/*  5*/ { MQ_MQCFSTATUS_NONE, "MQCFSTATUS_NONE" },
/*  6*/ { MQ_MQCFSTATUS_UNKNOWN, "MQCFSTATUS_UNKNOWN" },
/*  7*/ { MQ_MQCFSTATUS_RECOVERED, "MQCFSTATUS_RECOVERED" },
/*  8*/ { MQ_MQCFSTATUS_EMPTY, "MQCFSTATUS_EMPTY" },
/*  9*/ { MQ_MQCFSTATUS_NEW, "MQCFSTATUS_NEW" },
/* 20*/ { MQ_MQCFSTATUS_ADMIN_INCOMPLETE, "MQCFSTATUS_ADMIN_INCOMPLETE" },
/* 21*/ { MQ_MQCFSTATUS_NEVER_USED, "MQCFSTATUS_NEVER_USED" },
/* 22*/ { MQ_MQCFSTATUS_NO_BACKUP, "MQCFSTATUS_NO_BACKUP" },
/* 23*/ { MQ_MQCFSTATUS_NOT_FAILED, "MQCFSTATUS_NOT_FAILED" },
/* 24*/ { MQ_MQCFSTATUS_NOT_RECOVERABLE, "MQCFSTATUS_NOT_RECOVERABLE" },
/* 25*/ { MQ_MQCFSTATUS_XES_ERROR, "MQCFSTATUS_XES_ERROR" },
    { 0, NULL }
};

static const value_string mq_MQIACF_CF_STATUS_vals[] =
{
/* 1136*/ { MQ_MQIACF_CF_STATUS_SUMMARY, "MQIACF_CF_STATUS_SUMMARY" },
/* 1137*/ { MQ_MQIACF_CF_STATUS_CONNECT, "MQIACF_CF_STATUS_CONNECT" },
/* 1138*/ { MQ_MQIACF_CF_STATUS_BACKUP, "MQIACF_CF_STATUS_BACKUP" },
/* 1333*/ { MQ_MQIACF_CF_STATUS_SMDS, "MQIACF_CF_STATUS_SMDS" },
    { 0, NULL }
};

static const value_string mq_MQCFTYPE_vals[] =
{
/* 0*/ { MQ_MQCFTYPE_APPL, "MQCFTYPE_APPL" },
/* 1*/ { MQ_MQCFTYPE_ADMIN, "MQCFTYPE_ADMIN" },
    { 0, NULL }
};

static const value_string mq_MQCFACCESS_vals[] =
{
/* 0*/ { MQ_MQCFACCESS_ENABLED, "MQCFACCESS_ENABLED" },
/* 1*/ { MQ_MQCFACCESS_SUSPENDED, "MQCFACCESS_SUSPENDED" },
/* 2*/ { MQ_MQCFACCESS_DISABLED, "MQCFACCESS_DISABLED" },
    { 0, NULL }
};

static const value_string mq_MQS_OPENMODE_vals[] =
{
/* 0*/ { MQ_MQS_OPENMODE_NONE, "MQS_OPENMODE_NONE" },
/* 1*/ { MQ_MQS_OPENMODE_READONLY, "MQS_OPENMODE_READONLY" },
/* 2*/ { MQ_MQS_OPENMODE_UPDATE, "MQS_OPENMODE_UPDATE" },
/* 3*/ { MQ_MQS_OPENMODE_RECOVERY, "MQS_OPENMODE_RECOVERY" },
    { 0, NULL }
};

static const value_string mq_MQS_STATUS_vals[] =
{
/* 0*/ { MQ_MQS_STATUS_CLOSED, "MQS_STATUS_CLOSED" },
/* 1*/ { MQ_MQS_STATUS_CLOSING, "MQS_STATUS_CLOSING" },
/* 2*/ { MQ_MQS_STATUS_OPENING, "MQS_STATUS_OPENING" },
/* 3*/ { MQ_MQS_STATUS_OPEN, "MQS_STATUS_OPEN" },
/* 4*/ { MQ_MQS_STATUS_NOTENABLED, "MQS_STATUS_NOTENABLED" },
/* 5*/ { MQ_MQS_STATUS_ALLOCFAIL, "MQS_STATUS_ALLOCFAIL" },
/* 6*/ { MQ_MQS_STATUS_OPENFAIL, "MQS_STATUS_OPENFAIL" },
/* 7*/ { MQ_MQS_STATUS_STGFAIL, "MQS_STATUS_STGFAIL" },
/* 8*/ { MQ_MQS_STATUS_DATAFAIL, "MQS_STATUS_DATAFAIL" },
    { 0, NULL }
};

static const value_string mq_MQS_AVAIL_vals[] =
{
/* 0*/ { MQ_MQS_AVAIL_NORMAL, "MQS_AVAIL_NORMAL" },
/* 1*/ { MQ_MQS_AVAIL_ERROR, "MQS_AVAIL_ERROR" },
/* 2*/ { MQ_MQS_AVAIL_STOPPED, "MQS_AVAIL_STOPPED" },
    { 0, NULL }
};

static const value_string mq_MQS_EXPANDST_vals[] =
{
/* 0*/ { MQ_MQS_EXPANDST_NORMAL, "MQS_EXPANDST_NORMAL" },
/* 1*/ { MQ_MQS_EXPANDST_FAILED, "MQS_EXPANDST_FAILED" },
/* 2*/ { MQ_MQS_EXPANDST_MAXIMUM, "MQS_EXPANDST_MAXIMUM" },
    { 0, NULL }
};

static const value_string mq_MQRDNS_vals[] =
{
/* 0*/ { MQ_MQRDNS_ENABLED, "MQRDNS_ENABLED" },
/* 1*/ { MQ_MQRDNS_DISABLED, "MQRDNS_DISABLED" },
    { 0, NULL }
};

static const value_string mq_MQCIT_vals[] =
{
/* 1*/ { MQ_MQCIT_MULTICAST, "MQCIT_MULTICAST" },
    { 0, NULL }
};

static const value_string mq_MQMCB_vals[] =
{
/* 0*/ { MQ_MQMCB_DISABLED, "MQMCB_DISABLED" },
/* 1*/ { MQ_MQMCB_ENABLED, "MQMCB_ENABLED" },
    { 0, NULL }
};

static const value_string mq_MQNSH_vals[] =
{
/*-1*/ { MQ_MQNSH_ALL, "MQNSH_ALL" },
/* 0*/ { MQ_MQNSH_NONE, "MQNSH_NONE" },
    { 0, NULL }
};

static const value_string mq_MQPSST_vals[] =
{
/* 0*/ { MQ_MQPSST_ALL, "MQPSST_ALL" },
/* 1*/ { MQ_MQPSST_LOCAL, "MQPSST_LOCAL" },
/* 2*/ { MQ_MQPSST_PARENT, "MQPSST_PARENT" },
/* 3*/ { MQ_MQPSST_CHILD, "MQPSST_CHILD" },
    { 0, NULL }
};

static const value_string mq_MQUSAGE_SMDS_vals[] =
{
/* 0*/ { MQ_MQUSAGE_SMDS_AVAILABLE, "MQUSAGE_SMDS_AVAILABLE" },
/* 1*/ { MQ_MQUSAGE_SMDS_NO_DATA, "MQUSAGE_SMDS_NO_DATA" },
    { 0, NULL }
};

static const value_string mq_MQSTDBY_vals[] =
{
/* 0*/ { MQ_MQSTDBY_NOT_PERMITTED, "MQSTDBY_NOT_PERMITTED" },
/* 1*/ { MQ_MQSTDBY_PERMITTED, "MQSTDBY_PERMITTED" },
    { 0, NULL }
};

static const value_string mq_MQAT_vals[] =
{
/*    0*/ { MQ_MQAT_NO_CONTEXT, "MQAT_NO_CONTEXT" },
/*    1*/ { MQ_MQAT_CICS, "MQAT_CICS" },
/*    2*/ { MQ_MQAT_ZOS, "MQAT_ZOS" },
/*    3*/ { MQ_MQAT_IMS, "MQAT_IMS" },
/*    4*/ { MQ_MQAT_OS2, "MQAT_OS2" },
/*    5*/ { MQ_MQAT_DOS, "MQAT_DOS" },
/*    6*/ { MQ_MQAT_UNIX, "MQAT_UNIX" },
/*    7*/ { MQ_MQAT_QMGR, "MQAT_QMGR" },
/*    8*/ { MQ_MQAT_OS400, "MQAT_OS400" },
/*    9*/ { MQ_MQAT_WINDOWS, "MQAT_WINDOWS" },
/*   10*/ { MQ_MQAT_CICS_VSE, "MQAT_CICS_VSE" },
/*   11*/ { MQ_MQAT_WINDOWS_NT, "MQAT_WINDOWS_NT" },
/*   12*/ { MQ_MQAT_VMS, "MQAT_VMS" },
/*   13*/ { MQ_MQAT_NSK, "MQAT_NSK" },
/*   14*/ { MQ_MQAT_VOS, "MQAT_VOS" },
/*   15*/ { MQ_MQAT_OPEN_TP1, "MQAT_OPEN_TP1" },
/*   18*/ { MQ_MQAT_VM, "MQAT_VM" },
/*   19*/ { MQ_MQAT_IMS_BRIDGE, "MQAT_IMS_BRIDGE" },
/*   20*/ { MQ_MQAT_XCF, "MQAT_XCF" },
/*   21*/ { MQ_MQAT_CICS_BRIDGE, "MQAT_CICS_BRIDGE" },
/*   22*/ { MQ_MQAT_NOTES_AGENT, "MQAT_NOTES_AGENT" },
/*   23*/ { MQ_MQAT_TPF, "MQAT_TPF" },
/*   25*/ { MQ_MQAT_USER, "MQAT_USER" },
/*   26*/ { MQ_MQAT_QMGR_PUBLISH, "MQAT_QMGR_PUBLISH" },
/*   28*/ { MQ_MQAT_JAVA, "MQAT_JAVA" },
/*   29*/ { MQ_MQAT_DQM, "MQAT_DQM" },
/*   30*/ { MQ_MQAT_CHANNEL_INITIATOR, "MQAT_CHANNEL_INITIATOR" },
/*   31*/ { MQ_MQAT_WLM, "MQAT_WLM" },
/*   32*/ { MQ_MQAT_BATCH, "MQAT_BATCH" },
/*   33*/ { MQ_MQAT_RRS_BATCH, "MQAT_RRS_BATCH" },
/*   34*/ { MQ_MQAT_SIB, "MQAT_SIB" },
/*   35*/ { MQ_MQAT_SYSTEM_EXTENSION, "MQAT_SYSTEM_EXTENSION" },
/*   36*/ { MQ_MQAT_MCAST_PUBLISH, "MQAT_MCAST_PUBLISH" },
/*   37*/ { MQ_MQAT_AMQP, "MQAT_AMQP" },
/*   -1*/ { MQ_MQAT_UNKNOWN, "MQAT_UNKNOWN" },
    { 0, NULL }
};
value_string_ext mq_MQAT_xvals = VALUE_STRING_EXT_INIT(mq_MQAT_vals);

static const value_string mq_MQCMD_vals[] =
{
/*    0*/ { MQ_MQCMD_NONE, "MQCMD_NONE" },
/*    1*/ { MQ_MQCMD_CHANGE_Q_MGR, "MQCMD_CHANGE_Q_MGR" },
/*    2*/ { MQ_MQCMD_INQUIRE_Q_MGR, "MQCMD_INQUIRE_Q_MGR" },
/*    3*/ { MQ_MQCMD_CHANGE_PROCESS, "MQCMD_CHANGE_PROCESS" },
/*    4*/ { MQ_MQCMD_COPY_PROCESS, "MQCMD_COPY_PROCESS" },
/*    5*/ { MQ_MQCMD_CREATE_PROCESS, "MQCMD_CREATE_PROCESS" },
/*    6*/ { MQ_MQCMD_DELETE_PROCESS, "MQCMD_DELETE_PROCESS" },
/*    7*/ { MQ_MQCMD_INQUIRE_PROCESS, "MQCMD_INQUIRE_PROCESS" },
/*    8*/ { MQ_MQCMD_CHANGE_Q, "MQCMD_CHANGE_Q" },
/*    9*/ { MQ_MQCMD_CLEAR_Q, "MQCMD_CLEAR_Q" },
/*   10*/ { MQ_MQCMD_COPY_Q, "MQCMD_COPY_Q" },
/*   11*/ { MQ_MQCMD_CREATE_Q, "MQCMD_CREATE_Q" },
/*   12*/ { MQ_MQCMD_DELETE_Q, "MQCMD_DELETE_Q" },
/*   13*/ { MQ_MQCMD_INQUIRE_Q, "MQCMD_INQUIRE_Q" },
/*   16*/ { MQ_MQCMD_REFRESH_Q_MGR, "MQCMD_REFRESH_Q_MGR" },
/*   17*/ { MQ_MQCMD_RESET_Q_STATS, "MQCMD_RESET_Q_STATS" },
/*   18*/ { MQ_MQCMD_INQUIRE_Q_NAMES, "MQCMD_INQUIRE_Q_NAMES" },
/*   19*/ { MQ_MQCMD_INQUIRE_PROCESS_NAMES, "MQCMD_INQUIRE_PROCESS_NAMES" },
/*   20*/ { MQ_MQCMD_INQUIRE_CHANNEL_NAMES, "MQCMD_INQUIRE_CHANNEL_NAMES" },
/*   21*/ { MQ_MQCMD_CHANGE_CHANNEL, "MQCMD_CHANGE_CHANNEL" },
/*   22*/ { MQ_MQCMD_COPY_CHANNEL, "MQCMD_COPY_CHANNEL" },
/*   23*/ { MQ_MQCMD_CREATE_CHANNEL, "MQCMD_CREATE_CHANNEL" },
/*   24*/ { MQ_MQCMD_DELETE_CHANNEL, "MQCMD_DELETE_CHANNEL" },
/*   25*/ { MQ_MQCMD_INQUIRE_CHANNEL, "MQCMD_INQUIRE_CHANNEL" },
/*   26*/ { MQ_MQCMD_PING_CHANNEL, "MQCMD_PING_CHANNEL" },
/*   27*/ { MQ_MQCMD_RESET_CHANNEL, "MQCMD_RESET_CHANNEL" },
/*   28*/ { MQ_MQCMD_START_CHANNEL, "MQCMD_START_CHANNEL" },
/*   29*/ { MQ_MQCMD_STOP_CHANNEL, "MQCMD_STOP_CHANNEL" },
/*   30*/ { MQ_MQCMD_START_CHANNEL_INIT, "MQCMD_START_CHANNEL_INIT" },
/*   31*/ { MQ_MQCMD_START_CHANNEL_LISTENER, "MQCMD_START_CHANNEL_LISTENER" },
/*   32*/ { MQ_MQCMD_CHANGE_NAMELIST, "MQCMD_CHANGE_NAMELIST" },
/*   33*/ { MQ_MQCMD_COPY_NAMELIST, "MQCMD_COPY_NAMELIST" },
/*   34*/ { MQ_MQCMD_CREATE_NAMELIST, "MQCMD_CREATE_NAMELIST" },
/*   35*/ { MQ_MQCMD_DELETE_NAMELIST, "MQCMD_DELETE_NAMELIST" },
/*   36*/ { MQ_MQCMD_INQUIRE_NAMELIST, "MQCMD_INQUIRE_NAMELIST" },
/*   37*/ { MQ_MQCMD_INQUIRE_NAMELIST_NAMES, "MQCMD_INQUIRE_NAMELIST_NAMES" },
/*   38*/ { MQ_MQCMD_ESCAPE, "MQCMD_ESCAPE" },
/*   39*/ { MQ_MQCMD_RESOLVE_CHANNEL, "MQCMD_RESOLVE_CHANNEL" },
/*   40*/ { MQ_MQCMD_PING_Q_MGR, "MQCMD_PING_Q_MGR" },
/*   41*/ { MQ_MQCMD_INQUIRE_Q_STATUS, "MQCMD_INQUIRE_Q_STATUS" },
/*   42*/ { MQ_MQCMD_INQUIRE_CHANNEL_STATUS, "MQCMD_INQUIRE_CHANNEL_STATUS" },
/*   43*/ { MQ_MQCMD_CONFIG_EVENT, "MQCMD_CONFIG_EVENT" },
/*   44*/ { MQ_MQCMD_Q_MGR_EVENT, "MQCMD_Q_MGR_EVENT" },
/*   45*/ { MQ_MQCMD_PERFM_EVENT, "MQCMD_PERFM_EVENT" },
/*   46*/ { MQ_MQCMD_CHANNEL_EVENT, "MQCMD_CHANNEL_EVENT" },
/*   60*/ { MQ_MQCMD_DELETE_PUBLICATION, "MQCMD_DELETE_PUBLICATION" },
/*   61*/ { MQ_MQCMD_DEREGISTER_PUBLISHER, "MQCMD_DEREGISTER_PUBLISHER" },
/*   62*/ { MQ_MQCMD_DEREGISTER_SUBSCRIBER, "MQCMD_DEREGISTER_SUBSCRIBER" },
/*   63*/ { MQ_MQCMD_PUBLISH, "MQCMD_PUBLISH" },
/*   64*/ { MQ_MQCMD_REGISTER_PUBLISHER, "MQCMD_REGISTER_PUBLISHER" },
/*   65*/ { MQ_MQCMD_REGISTER_SUBSCRIBER, "MQCMD_REGISTER_SUBSCRIBER" },
/*   66*/ { MQ_MQCMD_REQUEST_UPDATE, "MQCMD_REQUEST_UPDATE" },
/*   67*/ { MQ_MQCMD_BROKER_INTERNAL, "MQCMD_BROKER_INTERNAL" },
/*   69*/ { MQ_MQCMD_ACTIVITY_MSG, "MQCMD_ACTIVITY_MSG" },
/*   70*/ { MQ_MQCMD_INQUIRE_CLUSTER_Q_MGR, "MQCMD_INQUIRE_CLUSTER_Q_MGR" },
/*   71*/ { MQ_MQCMD_RESUME_Q_MGR_CLUSTER, "MQCMD_RESUME_Q_MGR_CLUSTER" },
/*   72*/ { MQ_MQCMD_SUSPEND_Q_MGR_CLUSTER, "MQCMD_SUSPEND_Q_MGR_CLUSTER" },
/*   73*/ { MQ_MQCMD_REFRESH_CLUSTER, "MQCMD_REFRESH_CLUSTER" },
/*   74*/ { MQ_MQCMD_RESET_CLUSTER, "MQCMD_RESET_CLUSTER" },
/*   75*/ { MQ_MQCMD_TRACE_ROUTE, "MQCMD_TRACE_ROUTE" },
/*   78*/ { MQ_MQCMD_REFRESH_SECURITY, "MQCMD_REFRESH_SECURITY" },
/*   79*/ { MQ_MQCMD_CHANGE_AUTH_INFO, "MQCMD_CHANGE_AUTH_INFO" },
/*   80*/ { MQ_MQCMD_COPY_AUTH_INFO, "MQCMD_COPY_AUTH_INFO" },
/*   81*/ { MQ_MQCMD_CREATE_AUTH_INFO, "MQCMD_CREATE_AUTH_INFO" },
/*   82*/ { MQ_MQCMD_DELETE_AUTH_INFO, "MQCMD_DELETE_AUTH_INFO" },
/*   83*/ { MQ_MQCMD_INQUIRE_AUTH_INFO, "MQCMD_INQUIRE_AUTH_INFO" },
/*   84*/ { MQ_MQCMD_INQUIRE_AUTH_INFO_NAMES, "MQCMD_INQUIRE_AUTH_INFO_NAMES" },
/*   85*/ { MQ_MQCMD_INQUIRE_CONNECTION, "MQCMD_INQUIRE_CONNECTION" },
/*   86*/ { MQ_MQCMD_STOP_CONNECTION, "MQCMD_STOP_CONNECTION" },
/*   87*/ { MQ_MQCMD_INQUIRE_AUTH_RECS, "MQCMD_INQUIRE_AUTH_RECS" },
/*   88*/ { MQ_MQCMD_INQUIRE_ENTITY_AUTH, "MQCMD_INQUIRE_ENTITY_AUTH" },
/*   89*/ { MQ_MQCMD_DELETE_AUTH_REC, "MQCMD_DELETE_AUTH_REC" },
/*   90*/ { MQ_MQCMD_SET_AUTH_REC, "MQCMD_SET_AUTH_REC" },
/*   91*/ { MQ_MQCMD_LOGGER_EVENT, "MQCMD_LOGGER_EVENT" },
/*   92*/ { MQ_MQCMD_RESET_Q_MGR, "MQCMD_RESET_Q_MGR" },
/*   93*/ { MQ_MQCMD_CHANGE_LISTENER, "MQCMD_CHANGE_LISTENER" },
/*   94*/ { MQ_MQCMD_COPY_LISTENER, "MQCMD_COPY_LISTENER" },
/*   95*/ { MQ_MQCMD_CREATE_LISTENER, "MQCMD_CREATE_LISTENER" },
/*   96*/ { MQ_MQCMD_DELETE_LISTENER, "MQCMD_DELETE_LISTENER" },
/*   97*/ { MQ_MQCMD_INQUIRE_LISTENER, "MQCMD_INQUIRE_LISTENER" },
/*   98*/ { MQ_MQCMD_INQUIRE_LISTENER_STATUS, "MQCMD_INQUIRE_LISTENER_STATUS" },
/*   99*/ { MQ_MQCMD_COMMAND_EVENT, "MQCMD_COMMAND_EVENT" },
/*  100*/ { MQ_MQCMD_CHANGE_SECURITY, "MQCMD_CHANGE_SECURITY" },
/*  101*/ { MQ_MQCMD_CHANGE_CF_STRUC, "MQCMD_CHANGE_CF_STRUC" },
/*  102*/ { MQ_MQCMD_CHANGE_STG_CLASS, "MQCMD_CHANGE_STG_CLASS" },
/*  103*/ { MQ_MQCMD_CHANGE_TRACE, "MQCMD_CHANGE_TRACE" },
/*  104*/ { MQ_MQCMD_ARCHIVE_LOG, "MQCMD_ARCHIVE_LOG" },
/*  105*/ { MQ_MQCMD_BACKUP_CF_STRUC, "MQCMD_BACKUP_CF_STRUC" },
/*  106*/ { MQ_MQCMD_CREATE_BUFFER_POOL, "MQCMD_CREATE_BUFFER_POOL" },
/*  107*/ { MQ_MQCMD_CREATE_PAGE_SET, "MQCMD_CREATE_PAGE_SET" },
/*  108*/ { MQ_MQCMD_CREATE_CF_STRUC, "MQCMD_CREATE_CF_STRUC" },
/*  109*/ { MQ_MQCMD_CREATE_STG_CLASS, "MQCMD_CREATE_STG_CLASS" },
/*  110*/ { MQ_MQCMD_COPY_CF_STRUC, "MQCMD_COPY_CF_STRUC" },
/*  111*/ { MQ_MQCMD_COPY_STG_CLASS, "MQCMD_COPY_STG_CLASS" },
/*  112*/ { MQ_MQCMD_DELETE_CF_STRUC, "MQCMD_DELETE_CF_STRUC" },
/*  113*/ { MQ_MQCMD_DELETE_STG_CLASS, "MQCMD_DELETE_STG_CLASS" },
/*  114*/ { MQ_MQCMD_INQUIRE_ARCHIVE, "MQCMD_INQUIRE_ARCHIVE" },
/*  115*/ { MQ_MQCMD_INQUIRE_CF_STRUC, "MQCMD_INQUIRE_CF_STRUC" },
/*  116*/ { MQ_MQCMD_INQUIRE_CF_STRUC_STATUS, "MQCMD_INQUIRE_CF_STRUC_STATUS" },
/*  117*/ { MQ_MQCMD_INQUIRE_CMD_SERVER, "MQCMD_INQUIRE_CMD_SERVER" },
/*  118*/ { MQ_MQCMD_INQUIRE_CHANNEL_INIT, "MQCMD_INQUIRE_CHANNEL_INIT" },
/*  119*/ { MQ_MQCMD_INQUIRE_QSG, "MQCMD_INQUIRE_QSG" },
/*  120*/ { MQ_MQCMD_INQUIRE_LOG, "MQCMD_INQUIRE_LOG" },
/*  121*/ { MQ_MQCMD_INQUIRE_SECURITY, "MQCMD_INQUIRE_SECURITY" },
/*  122*/ { MQ_MQCMD_INQUIRE_STG_CLASS, "MQCMD_INQUIRE_STG_CLASS" },
/*  123*/ { MQ_MQCMD_INQUIRE_SYSTEM, "MQCMD_INQUIRE_SYSTEM" },
/*  124*/ { MQ_MQCMD_INQUIRE_THREAD, "MQCMD_INQUIRE_THREAD" },
/*  125*/ { MQ_MQCMD_INQUIRE_TRACE, "MQCMD_INQUIRE_TRACE" },
/*  126*/ { MQ_MQCMD_INQUIRE_USAGE, "MQCMD_INQUIRE_USAGE" },
/*  127*/ { MQ_MQCMD_MOVE_Q, "MQCMD_MOVE_Q" },
/*  128*/ { MQ_MQCMD_RECOVER_BSDS, "MQCMD_RECOVER_BSDS" },
/*  129*/ { MQ_MQCMD_RECOVER_CF_STRUC, "MQCMD_RECOVER_CF_STRUC" },
/*  130*/ { MQ_MQCMD_RESET_TPIPE, "MQCMD_RESET_TPIPE" },
/*  131*/ { MQ_MQCMD_RESOLVE_INDOUBT, "MQCMD_RESOLVE_INDOUBT" },
/*  132*/ { MQ_MQCMD_RESUME_Q_MGR, "MQCMD_RESUME_Q_MGR" },
/*  133*/ { MQ_MQCMD_REVERIFY_SECURITY, "MQCMD_REVERIFY_SECURITY" },
/*  134*/ { MQ_MQCMD_SET_ARCHIVE, "MQCMD_SET_ARCHIVE" },
/*  136*/ { MQ_MQCMD_SET_LOG, "MQCMD_SET_LOG" },
/*  137*/ { MQ_MQCMD_SET_SYSTEM, "MQCMD_SET_SYSTEM" },
/*  138*/ { MQ_MQCMD_START_CMD_SERVER, "MQCMD_START_CMD_SERVER" },
/*  139*/ { MQ_MQCMD_START_Q_MGR, "MQCMD_START_Q_MGR" },
/*  140*/ { MQ_MQCMD_START_TRACE, "MQCMD_START_TRACE" },
/*  141*/ { MQ_MQCMD_STOP_CHANNEL_INIT, "MQCMD_STOP_CHANNEL_INIT" },
/*  142*/ { MQ_MQCMD_STOP_CHANNEL_LISTENER, "MQCMD_STOP_CHANNEL_LISTENER" },
/*  143*/ { MQ_MQCMD_STOP_CMD_SERVER, "MQCMD_STOP_CMD_SERVER" },
/*  144*/ { MQ_MQCMD_STOP_Q_MGR, "MQCMD_STOP_Q_MGR" },
/*  145*/ { MQ_MQCMD_STOP_TRACE, "MQCMD_STOP_TRACE" },
/*  146*/ { MQ_MQCMD_SUSPEND_Q_MGR, "MQCMD_SUSPEND_Q_MGR" },
/*  147*/ { MQ_MQCMD_INQUIRE_CF_STRUC_NAMES, "MQCMD_INQUIRE_CF_STRUC_NAMES" },
/*  148*/ { MQ_MQCMD_INQUIRE_STG_CLASS_NAMES, "MQCMD_INQUIRE_STG_CLASS_NAMES" },
/*  149*/ { MQ_MQCMD_CHANGE_SERVICE, "MQCMD_CHANGE_SERVICE" },
/*  150*/ { MQ_MQCMD_COPY_SERVICE, "MQCMD_COPY_SERVICE" },
/*  151*/ { MQ_MQCMD_CREATE_SERVICE, "MQCMD_CREATE_SERVICE" },
/*  152*/ { MQ_MQCMD_DELETE_SERVICE, "MQCMD_DELETE_SERVICE" },
/*  153*/ { MQ_MQCMD_INQUIRE_SERVICE, "MQCMD_INQUIRE_SERVICE" },
/*  154*/ { MQ_MQCMD_INQUIRE_SERVICE_STATUS, "MQCMD_INQUIRE_SERVICE_STATUS" },
/*  155*/ { MQ_MQCMD_START_SERVICE, "MQCMD_START_SERVICE" },
/*  156*/ { MQ_MQCMD_STOP_SERVICE, "MQCMD_STOP_SERVICE" },
/*  157*/ { MQ_MQCMD_DELETE_BUFFER_POOL, "MQCMD_DELETE_BUFFER_POOL" },
/*  158*/ { MQ_MQCMD_DELETE_PAGE_SET, "MQCMD_DELETE_PAGE_SET" },
/*  159*/ { MQ_MQCMD_CHANGE_BUFFER_POOL, "MQCMD_CHANGE_BUFFER_POOL" },
/*  160*/ { MQ_MQCMD_CHANGE_PAGE_SET, "MQCMD_CHANGE_PAGE_SET" },
/*  161*/ { MQ_MQCMD_INQUIRE_Q_MGR_STATUS, "MQCMD_INQUIRE_Q_MGR_STATUS" },
/*  162*/ { MQ_MQCMD_CREATE_LOG, "MQCMD_CREATE_LOG" },
/*  164*/ { MQ_MQCMD_STATISTICS_MQI, "MQCMD_STATISTICS_MQI" },
/*  165*/ { MQ_MQCMD_STATISTICS_Q, "MQCMD_STATISTICS_Q" },
/*  166*/ { MQ_MQCMD_STATISTICS_CHANNEL, "MQCMD_STATISTICS_CHANNEL" },
/*  167*/ { MQ_MQCMD_ACCOUNTING_MQI, "MQCMD_ACCOUNTING_MQI" },
/*  168*/ { MQ_MQCMD_ACCOUNTING_Q, "MQCMD_ACCOUNTING_Q" },
/*  169*/ { MQ_MQCMD_INQUIRE_AUTH_SERVICE, "MQCMD_INQUIRE_AUTH_SERVICE" },
/*  170*/ { MQ_MQCMD_CHANGE_TOPIC, "MQCMD_CHANGE_TOPIC" },
/*  171*/ { MQ_MQCMD_COPY_TOPIC, "MQCMD_COPY_TOPIC" },
/*  172*/ { MQ_MQCMD_CREATE_TOPIC, "MQCMD_CREATE_TOPIC" },
/*  173*/ { MQ_MQCMD_DELETE_TOPIC, "MQCMD_DELETE_TOPIC" },
/*  174*/ { MQ_MQCMD_INQUIRE_TOPIC, "MQCMD_INQUIRE_TOPIC" },
/*  175*/ { MQ_MQCMD_INQUIRE_TOPIC_NAMES, "MQCMD_INQUIRE_TOPIC_NAMES" },
/*  176*/ { MQ_MQCMD_INQUIRE_SUBSCRIPTION, "MQCMD_INQUIRE_SUBSCRIPTION" },
/*  177*/ { MQ_MQCMD_CREATE_SUBSCRIPTION, "MQCMD_CREATE_SUBSCRIPTION" },
/*  178*/ { MQ_MQCMD_CHANGE_SUBSCRIPTION, "MQCMD_CHANGE_SUBSCRIPTION" },
/*  179*/ { MQ_MQCMD_DELETE_SUBSCRIPTION, "MQCMD_DELETE_SUBSCRIPTION" },
/*  181*/ { MQ_MQCMD_COPY_SUBSCRIPTION, "MQCMD_COPY_SUBSCRIPTION" },
/*  182*/ { MQ_MQCMD_INQUIRE_SUB_STATUS, "MQCMD_INQUIRE_SUB_STATUS" },
/*  183*/ { MQ_MQCMD_INQUIRE_TOPIC_STATUS, "MQCMD_INQUIRE_TOPIC_STATUS" },
/*  184*/ { MQ_MQCMD_CLEAR_TOPIC_STRING, "MQCMD_CLEAR_TOPIC_STRING" },
/*  185*/ { MQ_MQCMD_INQUIRE_PUBSUB_STATUS, "MQCMD_INQUIRE_PUBSUB_STATUS" },
/*  186*/ { MQ_MQCMD_INQUIRE_SMDS, "MQCMD_INQUIRE_SMDS" },
/*  187*/ { MQ_MQCMD_CHANGE_SMDS, "MQCMD_CHANGE_SMDS" },
/*  188*/ { MQ_MQCMD_RESET_SMDS, "MQCMD_RESET_SMDS" },
/*  190*/ { MQ_MQCMD_CREATE_COMM_INFO, "MQCMD_CREATE_COMM_INFO" },
/*  191*/ { MQ_MQCMD_INQUIRE_COMM_INFO, "MQCMD_INQUIRE_COMM_INFO" },
/*  192*/ { MQ_MQCMD_CHANGE_COMM_INFO, "MQCMD_CHANGE_COMM_INFO" },
/*  193*/ { MQ_MQCMD_COPY_COMM_INFO, "MQCMD_COPY_COMM_INFO" },
/*  194*/ { MQ_MQCMD_DELETE_COMM_INFO, "MQCMD_DELETE_COMM_INFO" },
/*  195*/ { MQ_MQCMD_PURGE_CHANNEL, "MQCMD_PURGE_CHANNEL" },
/*  196*/ { MQ_MQCMD_MQXR_DIAGNOSTICS, "MQCMD_MQXR_DIAGNOSTICS" },
/*  197*/ { MQ_MQCMD_START_SMDSCONN, "MQCMD_START_SMDSCONN" },
/*  198*/ { MQ_MQCMD_STOP_SMDSCONN, "MQCMD_STOP_SMDSCONN" },
/*  199*/ { MQ_MQCMD_INQUIRE_SMDSCONN, "MQCMD_INQUIRE_SMDSCONN" },
/*  200*/ { MQ_MQCMD_INQUIRE_MQXR_STATUS, "MQCMD_INQUIRE_MQXR_STATUS" },
/*  201*/ { MQ_MQCMD_START_CLIENT_TRACE, "MQCMD_START_CLIENT_TRACE" },
/*  202*/ { MQ_MQCMD_STOP_CLIENT_TRACE, "MQCMD_STOP_CLIENT_TRACE" },
/*  203*/ { MQ_MQCMD_SET_CHLAUTH_REC, "MQCMD_SET_CHLAUTH_REC" },
/*  204*/ { MQ_MQCMD_INQUIRE_CHLAUTH_RECS, "MQCMD_INQUIRE_CHLAUTH_RECS" },
/*  205*/ { MQ_MQCMD_INQUIRE_PROT_POLICY, "MQCMD_INQUIRE_PROT_POLICY" },
/*  206*/ { MQ_MQCMD_CREATE_PROT_POLICY, "MQCMD_CREATE_PROT_POLICY" },
/*  207*/ { MQ_MQCMD_DELETE_PROT_POLICY, "MQCMD_DELETE_PROT_POLICY" },
/*  208*/ { MQ_MQCMD_CHANGE_PROT_POLICY, "MQCMD_CHANGE_PROT_POLICY" },
/*  209*/ { MQ_MQCMD_ACTIVITY_TRACE, "MQCMD_ACTIVITY_TRACE" },
/*  213*/ { MQ_MQCMD_RESET_CF_STRUC, "MQCMD_RESET_CF_STRUC" },
/*  214*/ { MQ_MQCMD_INQUIRE_XR_CAPABILITY, "MQCMD_INQUIRE_XR_CAPABILITY" },
/*  216*/ { MQ_MQCMD_INQUIRE_AMQP_CAPABILITY, "MQCMD_INQUIRE_AMQP_CAPABILITY" },
/*  217*/ { MQ_MQCMD_AMQP_DIAGNOSTICS, "MQCMD_AMQP_DIAGNOSTICS" },

    { 0, NULL }
};
value_string_ext mq_MQCMD_xvals = VALUE_STRING_EXT_INIT(mq_MQCMD_vals);

static const value_string mq_MQRC_vals[] =
{
/*    0*/ { MQ_MQRC_NONE, "MQRC_NONE" },
/*  900*/ { MQ_MQRC_APPL_FIRST, "MQRC_APPL_FIRST" },
/*  999*/ { MQ_MQRC_APPL_LAST, "MQRC_APPL_LAST" },
/* 2001*/ { MQ_MQRC_ALIAS_BASE_Q_TYPE_ERROR, "MQRC_ALIAS_BASE_Q_TYPE_ERROR" },
/* 2002*/ { MQ_MQRC_ALREADY_CONNECTED, "MQRC_ALREADY_CONNECTED" },
/* 2003*/ { MQ_MQRC_BACKED_OUT, "MQRC_BACKED_OUT" },
/* 2004*/ { MQ_MQRC_BUFFER_ERROR, "MQRC_BUFFER_ERROR" },
/* 2005*/ { MQ_MQRC_BUFFER_LENGTH_ERROR, "MQRC_BUFFER_LENGTH_ERROR" },
/* 2006*/ { MQ_MQRC_CHAR_ATTR_LENGTH_ERROR, "MQRC_CHAR_ATTR_LENGTH_ERROR" },
/* 2007*/ { MQ_MQRC_CHAR_ATTRS_ERROR, "MQRC_CHAR_ATTRS_ERROR" },
/* 2008*/ { MQ_MQRC_CHAR_ATTRS_TOO_SHORT, "MQRC_CHAR_ATTRS_TOO_SHORT" },
/* 2009*/ { MQ_MQRC_CONNECTION_BROKEN, "MQRC_CONNECTION_BROKEN" },
/* 2010*/ { MQ_MQRC_DATA_LENGTH_ERROR, "MQRC_DATA_LENGTH_ERROR" },
/* 2011*/ { MQ_MQRC_DYNAMIC_Q_NAME_ERROR, "MQRC_DYNAMIC_Q_NAME_ERROR" },
/* 2012*/ { MQ_MQRC_ENVIRONMENT_ERROR, "MQRC_ENVIRONMENT_ERROR" },
/* 2013*/ { MQ_MQRC_EXPIRY_ERROR, "MQRC_EXPIRY_ERROR" },
/* 2014*/ { MQ_MQRC_FEEDBACK_ERROR, "MQRC_FEEDBACK_ERROR" },
/* 2016*/ { MQ_MQRC_GET_INHIBITED, "MQRC_GET_INHIBITED" },
/* 2017*/ { MQ_MQRC_HANDLE_NOT_AVAILABLE, "MQRC_HANDLE_NOT_AVAILABLE" },
/* 2018*/ { MQ_MQRC_HCONN_ERROR, "MQRC_HCONN_ERROR" },
/* 2019*/ { MQ_MQRC_HOBJ_ERROR, "MQRC_HOBJ_ERROR" },
/* 2020*/ { MQ_MQRC_INHIBIT_VALUE_ERROR, "MQRC_INHIBIT_VALUE_ERROR" },
/* 2021*/ { MQ_MQRC_INT_ATTR_COUNT_ERROR, "MQRC_INT_ATTR_COUNT_ERROR" },
/* 2022*/ { MQ_MQRC_INT_ATTR_COUNT_TOO_SMALL, "MQRC_INT_ATTR_COUNT_TOO_SMALL" },
/* 2023*/ { MQ_MQRC_INT_ATTRS_ARRAY_ERROR, "MQRC_INT_ATTRS_ARRAY_ERROR" },
/* 2024*/ { MQ_MQRC_SYNCPOINT_LIMIT_REACHED, "MQRC_SYNCPOINT_LIMIT_REACHED" },
/* 2025*/ { MQ_MQRC_MAX_CONNS_LIMIT_REACHED, "MQRC_MAX_CONNS_LIMIT_REACHED" },
/* 2026*/ { MQ_MQRC_MD_ERROR, "MQRC_MD_ERROR" },
/* 2027*/ { MQ_MQRC_MISSING_REPLY_TO_Q, "MQRC_MISSING_REPLY_TO_Q" },
/* 2029*/ { MQ_MQRC_MSG_TYPE_ERROR, "MQRC_MSG_TYPE_ERROR" },
/* 2030*/ { MQ_MQRC_MSG_TOO_BIG_FOR_Q, "MQRC_MSG_TOO_BIG_FOR_Q" },
/* 2031*/ { MQ_MQRC_MSG_TOO_BIG_FOR_Q_MGR, "MQRC_MSG_TOO_BIG_FOR_Q_MGR" },
/* 2033*/ { MQ_MQRC_NO_MSG_AVAILABLE, "MQRC_NO_MSG_AVAILABLE" },
/* 2034*/ { MQ_MQRC_NO_MSG_UNDER_CURSOR, "MQRC_NO_MSG_UNDER_CURSOR" },
/* 2035*/ { MQ_MQRC_NOT_AUTHORIZED, "MQRC_NOT_AUTHORIZED" },
/* 2036*/ { MQ_MQRC_NOT_OPEN_FOR_BROWSE, "MQRC_NOT_OPEN_FOR_BROWSE" },
/* 2037*/ { MQ_MQRC_NOT_OPEN_FOR_INPUT, "MQRC_NOT_OPEN_FOR_INPUT" },
/* 2038*/ { MQ_MQRC_NOT_OPEN_FOR_INQUIRE, "MQRC_NOT_OPEN_FOR_INQUIRE" },
/* 2039*/ { MQ_MQRC_NOT_OPEN_FOR_OUTPUT, "MQRC_NOT_OPEN_FOR_OUTPUT" },
/* 2040*/ { MQ_MQRC_NOT_OPEN_FOR_SET, "MQRC_NOT_OPEN_FOR_SET" },
/* 2041*/ { MQ_MQRC_OBJECT_CHANGED, "MQRC_OBJECT_CHANGED" },
/* 2042*/ { MQ_MQRC_OBJECT_IN_USE, "MQRC_OBJECT_IN_USE" },
/* 2043*/ { MQ_MQRC_OBJECT_TYPE_ERROR, "MQRC_OBJECT_TYPE_ERROR" },
/* 2044*/ { MQ_MQRC_OD_ERROR, "MQRC_OD_ERROR" },
/* 2045*/ { MQ_MQRC_OPTION_NOT_VALID_FOR_TYPE, "MQRC_OPTION_NOT_VALID_FOR_TYPE" },
/* 2046*/ { MQ_MQRC_OPTIONS_ERROR, "MQRC_OPTIONS_ERROR" },
/* 2047*/ { MQ_MQRC_PERSISTENCE_ERROR, "MQRC_PERSISTENCE_ERROR" },
/* 2048*/ { MQ_MQRC_PERSISTENT_NOT_ALLOWED, "MQRC_PERSISTENT_NOT_ALLOWED" },
/* 2049*/ { MQ_MQRC_PRIORITY_EXCEEDS_MAXIMUM, "MQRC_PRIORITY_EXCEEDS_MAXIMUM" },
/* 2050*/ { MQ_MQRC_PRIORITY_ERROR, "MQRC_PRIORITY_ERROR" },
/* 2051*/ { MQ_MQRC_PUT_INHIBITED, "MQRC_PUT_INHIBITED" },
/* 2052*/ { MQ_MQRC_Q_DELETED, "MQRC_Q_DELETED" },
/* 2053*/ { MQ_MQRC_Q_FULL, "MQRC_Q_FULL" },
/* 2055*/ { MQ_MQRC_Q_NOT_EMPTY, "MQRC_Q_NOT_EMPTY" },
/* 2056*/ { MQ_MQRC_Q_SPACE_NOT_AVAILABLE, "MQRC_Q_SPACE_NOT_AVAILABLE" },
/* 2057*/ { MQ_MQRC_Q_TYPE_ERROR, "MQRC_Q_TYPE_ERROR" },
/* 2058*/ { MQ_MQRC_Q_MGR_NAME_ERROR, "MQRC_Q_MGR_NAME_ERROR" },
/* 2059*/ { MQ_MQRC_Q_MGR_NOT_AVAILABLE, "MQRC_Q_MGR_NOT_AVAILABLE" },
/* 2061*/ { MQ_MQRC_REPORT_OPTIONS_ERROR, "MQRC_REPORT_OPTIONS_ERROR" },
/* 2062*/ { MQ_MQRC_SECOND_MARK_NOT_ALLOWED, "MQRC_SECOND_MARK_NOT_ALLOWED" },
/* 2063*/ { MQ_MQRC_SECURITY_ERROR, "MQRC_SECURITY_ERROR" },
/* 2065*/ { MQ_MQRC_SELECTOR_COUNT_ERROR, "MQRC_SELECTOR_COUNT_ERROR" },
/* 2066*/ { MQ_MQRC_SELECTOR_LIMIT_EXCEEDED, "MQRC_SELECTOR_LIMIT_EXCEEDED" },
/* 2067*/ { MQ_MQRC_SELECTOR_ERROR, "MQRC_SELECTOR_ERROR" },
/* 2068*/ { MQ_MQRC_SELECTOR_NOT_FOR_TYPE, "MQRC_SELECTOR_NOT_FOR_TYPE" },
/* 2069*/ { MQ_MQRC_SIGNAL_OUTSTANDING, "MQRC_SIGNAL_OUTSTANDING" },
/* 2070*/ { MQ_MQRC_SIGNAL_REQUEST_ACCEPTED, "MQRC_SIGNAL_REQUEST_ACCEPTED" },
/* 2071*/ { MQ_MQRC_STORAGE_NOT_AVAILABLE, "MQRC_STORAGE_NOT_AVAILABLE" },
/* 2072*/ { MQ_MQRC_SYNCPOINT_NOT_AVAILABLE, "MQRC_SYNCPOINT_NOT_AVAILABLE" },
/* 2075*/ { MQ_MQRC_TRIGGER_CONTROL_ERROR, "MQRC_TRIGGER_CONTROL_ERROR" },
/* 2076*/ { MQ_MQRC_TRIGGER_DEPTH_ERROR, "MQRC_TRIGGER_DEPTH_ERROR" },
/* 2077*/ { MQ_MQRC_TRIGGER_MSG_PRIORITY_ERR, "MQRC_TRIGGER_MSG_PRIORITY_ERR" },
/* 2078*/ { MQ_MQRC_TRIGGER_TYPE_ERROR, "MQRC_TRIGGER_TYPE_ERROR" },
/* 2079*/ { MQ_MQRC_TRUNCATED_MSG_ACCEPTED, "MQRC_TRUNCATED_MSG_ACCEPTED" },
/* 2080*/ { MQ_MQRC_TRUNCATED_MSG_FAILED, "MQRC_TRUNCATED_MSG_FAILED" },
/* 2082*/ { MQ_MQRC_UNKNOWN_ALIAS_BASE_Q, "MQRC_UNKNOWN_ALIAS_BASE_Q" },
/* 2085*/ { MQ_MQRC_UNKNOWN_OBJECT_NAME, "MQRC_UNKNOWN_OBJECT_NAME" },
/* 2086*/ { MQ_MQRC_UNKNOWN_OBJECT_Q_MGR, "MQRC_UNKNOWN_OBJECT_Q_MGR" },
/* 2087*/ { MQ_MQRC_UNKNOWN_REMOTE_Q_MGR, "MQRC_UNKNOWN_REMOTE_Q_MGR" },
/* 2090*/ { MQ_MQRC_WAIT_INTERVAL_ERROR, "MQRC_WAIT_INTERVAL_ERROR" },
/* 2091*/ { MQ_MQRC_XMIT_Q_TYPE_ERROR, "MQRC_XMIT_Q_TYPE_ERROR" },
/* 2092*/ { MQ_MQRC_XMIT_Q_USAGE_ERROR, "MQRC_XMIT_Q_USAGE_ERROR" },
/* 2093*/ { MQ_MQRC_NOT_OPEN_FOR_PASS_ALL, "MQRC_NOT_OPEN_FOR_PASS_ALL" },
/* 2094*/ { MQ_MQRC_NOT_OPEN_FOR_PASS_IDENT, "MQRC_NOT_OPEN_FOR_PASS_IDENT" },
/* 2095*/ { MQ_MQRC_NOT_OPEN_FOR_SET_ALL, "MQRC_NOT_OPEN_FOR_SET_ALL" },
/* 2096*/ { MQ_MQRC_NOT_OPEN_FOR_SET_IDENT, "MQRC_NOT_OPEN_FOR_SET_IDENT" },
/* 2097*/ { MQ_MQRC_CONTEXT_HANDLE_ERROR, "MQRC_CONTEXT_HANDLE_ERROR" },
/* 2098*/ { MQ_MQRC_CONTEXT_NOT_AVAILABLE, "MQRC_CONTEXT_NOT_AVAILABLE" },
/* 2099*/ { MQ_MQRC_SIGNAL1_ERROR, "MQRC_SIGNAL1_ERROR" },
/* 2100*/ { MQ_MQRC_OBJECT_ALREADY_EXISTS, "MQRC_OBJECT_ALREADY_EXISTS" },
/* 2101*/ { MQ_MQRC_OBJECT_DAMAGED, "MQRC_OBJECT_DAMAGED" },
/* 2102*/ { MQ_MQRC_RESOURCE_PROBLEM, "MQRC_RESOURCE_PROBLEM" },
/* 2103*/ { MQ_MQRC_ANOTHER_Q_MGR_CONNECTED, "MQRC_ANOTHER_Q_MGR_CONNECTED" },
/* 2104*/ { MQ_MQRC_UNKNOWN_REPORT_OPTION, "MQRC_UNKNOWN_REPORT_OPTION" },
/* 2105*/ { MQ_MQRC_STORAGE_CLASS_ERROR, "MQRC_STORAGE_CLASS_ERROR" },
/* 2106*/ { MQ_MQRC_COD_NOT_VALID_FOR_XCF_Q, "MQRC_COD_NOT_VALID_FOR_XCF_Q" },
/* 2107*/ { MQ_MQRC_XWAIT_CANCELED, "MQRC_XWAIT_CANCELED" },
/* 2108*/ { MQ_MQRC_XWAIT_ERROR, "MQRC_XWAIT_ERROR" },
/* 2109*/ { MQ_MQRC_SUPPRESSED_BY_EXIT, "MQRC_SUPPRESSED_BY_EXIT" },
/* 2110*/ { MQ_MQRC_FORMAT_ERROR, "MQRC_FORMAT_ERROR" },
/* 2111*/ { MQ_MQRC_SOURCE_CCSID_ERROR, "MQRC_SOURCE_CCSID_ERROR" },
/* 2112*/ { MQ_MQRC_SOURCE_INTEGER_ENC_ERROR, "MQRC_SOURCE_INTEGER_ENC_ERROR" },
/* 2113*/ { MQ_MQRC_SOURCE_DECIMAL_ENC_ERROR, "MQRC_SOURCE_DECIMAL_ENC_ERROR" },
/* 2114*/ { MQ_MQRC_SOURCE_FLOAT_ENC_ERROR, "MQRC_SOURCE_FLOAT_ENC_ERROR" },
/* 2115*/ { MQ_MQRC_TARGET_CCSID_ERROR, "MQRC_TARGET_CCSID_ERROR" },
/* 2116*/ { MQ_MQRC_TARGET_INTEGER_ENC_ERROR, "MQRC_TARGET_INTEGER_ENC_ERROR" },
/* 2117*/ { MQ_MQRC_TARGET_DECIMAL_ENC_ERROR, "MQRC_TARGET_DECIMAL_ENC_ERROR" },
/* 2118*/ { MQ_MQRC_TARGET_FLOAT_ENC_ERROR, "MQRC_TARGET_FLOAT_ENC_ERROR" },
/* 2119*/ { MQ_MQRC_NOT_CONVERTED, "MQRC_NOT_CONVERTED" },
/* 2120*/ { MQ_MQRC_CONVERTED_MSG_TOO_BIG, "MQRC_CONVERTED_MSG_TOO_BIG" },
/* 2120   { MQ_MQRC_TRUNCATED, "MQRC_TRUNCATED" }, */
/* 2121*/ { MQ_MQRC_NO_EXTERNAL_PARTICIPANTS, "MQRC_NO_EXTERNAL_PARTICIPANTS" },
/* 2122*/ { MQ_MQRC_PARTICIPANT_NOT_AVAILABLE, "MQRC_PARTICIPANT_NOT_AVAILABLE" },
/* 2123*/ { MQ_MQRC_OUTCOME_MIXED, "MQRC_OUTCOME_MIXED" },
/* 2124*/ { MQ_MQRC_OUTCOME_PENDING, "MQRC_OUTCOME_PENDING" },
/* 2125*/ { MQ_MQRC_BRIDGE_STARTED, "MQRC_BRIDGE_STARTED" },
/* 2126*/ { MQ_MQRC_BRIDGE_STOPPED, "MQRC_BRIDGE_STOPPED" },
/* 2127*/ { MQ_MQRC_ADAPTER_STORAGE_SHORTAGE, "MQRC_ADAPTER_STORAGE_SHORTAGE" },
/* 2128*/ { MQ_MQRC_UOW_IN_PROGRESS, "MQRC_UOW_IN_PROGRESS" },
/* 2129*/ { MQ_MQRC_ADAPTER_CONN_LOAD_ERROR, "MQRC_ADAPTER_CONN_LOAD_ERROR" },
/* 2130*/ { MQ_MQRC_ADAPTER_SERV_LOAD_ERROR, "MQRC_ADAPTER_SERV_LOAD_ERROR" },
/* 2131*/ { MQ_MQRC_ADAPTER_DEFS_ERROR, "MQRC_ADAPTER_DEFS_ERROR" },
/* 2132*/ { MQ_MQRC_ADAPTER_DEFS_LOAD_ERROR, "MQRC_ADAPTER_DEFS_LOAD_ERROR" },
/* 2133*/ { MQ_MQRC_ADAPTER_CONV_LOAD_ERROR, "MQRC_ADAPTER_CONV_LOAD_ERROR" },
/* 2134*/ { MQ_MQRC_BO_ERROR, "MQRC_BO_ERROR" },
/* 2135*/ { MQ_MQRC_DH_ERROR, "MQRC_DH_ERROR" },
/* 2136*/ { MQ_MQRC_MULTIPLE_REASONS, "MQRC_MULTIPLE_REASONS" },
/* 2137*/ { MQ_MQRC_OPEN_FAILED, "MQRC_OPEN_FAILED" },
/* 2138*/ { MQ_MQRC_ADAPTER_DISC_LOAD_ERROR, "MQRC_ADAPTER_DISC_LOAD_ERROR" },
/* 2139*/ { MQ_MQRC_CNO_ERROR, "MQRC_CNO_ERROR" },
/* 2140*/ { MQ_MQRC_CICS_WAIT_FAILED, "MQRC_CICS_WAIT_FAILED" },
/* 2141*/ { MQ_MQRC_DLH_ERROR, "MQRC_DLH_ERROR" },
/* 2142*/ { MQ_MQRC_HEADER_ERROR, "MQRC_HEADER_ERROR" },
/* 2143*/ { MQ_MQRC_SOURCE_LENGTH_ERROR, "MQRC_SOURCE_LENGTH_ERROR" },
/* 2144*/ { MQ_MQRC_TARGET_LENGTH_ERROR, "MQRC_TARGET_LENGTH_ERROR" },
/* 2145*/ { MQ_MQRC_SOURCE_BUFFER_ERROR, "MQRC_SOURCE_BUFFER_ERROR" },
/* 2146*/ { MQ_MQRC_TARGET_BUFFER_ERROR, "MQRC_TARGET_BUFFER_ERROR" },
/* 2148*/ { MQ_MQRC_IIH_ERROR, "MQRC_IIH_ERROR" },
/* 2149*/ { MQ_MQRC_PCF_ERROR, "MQRC_PCF_ERROR" },
/* 2150*/ { MQ_MQRC_DBCS_ERROR, "MQRC_DBCS_ERROR" },
/* 2152*/ { MQ_MQRC_OBJECT_NAME_ERROR, "MQRC_OBJECT_NAME_ERROR" },
/* 2153*/ { MQ_MQRC_OBJECT_Q_MGR_NAME_ERROR, "MQRC_OBJECT_Q_MGR_NAME_ERROR" },
/* 2154*/ { MQ_MQRC_RECS_PRESENT_ERROR, "MQRC_RECS_PRESENT_ERROR" },
/* 2155*/ { MQ_MQRC_OBJECT_RECORDS_ERROR, "MQRC_OBJECT_RECORDS_ERROR" },
/* 2156*/ { MQ_MQRC_RESPONSE_RECORDS_ERROR, "MQRC_RESPONSE_RECORDS_ERROR" },
/* 2157*/ { MQ_MQRC_ASID_MISMATCH, "MQRC_ASID_MISMATCH" },
/* 2158*/ { MQ_MQRC_PMO_RECORD_FLAGS_ERROR, "MQRC_PMO_RECORD_FLAGS_ERROR" },
/* 2159*/ { MQ_MQRC_PUT_MSG_RECORDS_ERROR, "MQRC_PUT_MSG_RECORDS_ERROR" },
/* 2160*/ { MQ_MQRC_CONN_ID_IN_USE, "MQRC_CONN_ID_IN_USE" },
/* 2161*/ { MQ_MQRC_Q_MGR_QUIESCING, "MQRC_Q_MGR_QUIESCING" },
/* 2162*/ { MQ_MQRC_Q_MGR_STOPPING, "MQRC_Q_MGR_STOPPING" },
/* 2163*/ { MQ_MQRC_DUPLICATE_RECOV_COORD, "MQRC_DUPLICATE_RECOV_COORD" },
/* 2173*/ { MQ_MQRC_PMO_ERROR, "MQRC_PMO_ERROR" },
/* 2182*/ { MQ_MQRC_API_EXIT_NOT_FOUND, "MQRC_API_EXIT_NOT_FOUND" },
/* 2183*/ { MQ_MQRC_API_EXIT_LOAD_ERROR, "MQRC_API_EXIT_LOAD_ERROR" },
/* 2184*/ { MQ_MQRC_REMOTE_Q_NAME_ERROR, "MQRC_REMOTE_Q_NAME_ERROR" },
/* 2185*/ { MQ_MQRC_INCONSISTENT_PERSISTENCE, "MQRC_INCONSISTENT_PERSISTENCE" },
/* 2186*/ { MQ_MQRC_GMO_ERROR, "MQRC_GMO_ERROR" },
/* 2187*/ { MQ_MQRC_CICS_BRIDGE_RESTRICTION, "MQRC_CICS_BRIDGE_RESTRICTION" },
/* 2188*/ { MQ_MQRC_STOPPED_BY_CLUSTER_EXIT, "MQRC_STOPPED_BY_CLUSTER_EXIT" },
/* 2189*/ { MQ_MQRC_CLUSTER_RESOLUTION_ERROR, "MQRC_CLUSTER_RESOLUTION_ERROR" },
/* 2190*/ { MQ_MQRC_CONVERTED_STRING_TOO_BIG, "MQRC_CONVERTED_STRING_TOO_BIG" },
/* 2191*/ { MQ_MQRC_TMC_ERROR, "MQRC_TMC_ERROR" },
/* 2192*/ { MQ_MQRC_STORAGE_MEDIUM_FULL, "MQRC_STORAGE_MEDIUM_FULL" },
/* 2192   { MQ_MQRC_PAGESET_FULL, "MQRC_PAGESET_FULL" }, */
/* 2193*/ { MQ_MQRC_PAGESET_ERROR, "MQRC_PAGESET_ERROR" },
/* 2194*/ { MQ_MQRC_NAME_NOT_VALID_FOR_TYPE, "MQRC_NAME_NOT_VALID_FOR_TYPE" },
/* 2195*/ { MQ_MQRC_UNEXPECTED_ERROR, "MQRC_UNEXPECTED_ERROR" },
/* 2196*/ { MQ_MQRC_UNKNOWN_XMIT_Q, "MQRC_UNKNOWN_XMIT_Q" },
/* 2197*/ { MQ_MQRC_UNKNOWN_DEF_XMIT_Q, "MQRC_UNKNOWN_DEF_XMIT_Q" },
/* 2198*/ { MQ_MQRC_DEF_XMIT_Q_TYPE_ERROR, "MQRC_DEF_XMIT_Q_TYPE_ERROR" },
/* 2199*/ { MQ_MQRC_DEF_XMIT_Q_USAGE_ERROR, "MQRC_DEF_XMIT_Q_USAGE_ERROR" },
/* 2200*/ { MQ_MQRC_MSG_MARKED_BROWSE_CO_OP, "MQRC_MSG_MARKED_BROWSE_CO_OP" },
/* 2201*/ { MQ_MQRC_NAME_IN_USE, "MQRC_NAME_IN_USE" },
/* 2202*/ { MQ_MQRC_CONNECTION_QUIESCING, "MQRC_CONNECTION_QUIESCING" },
/* 2203*/ { MQ_MQRC_CONNECTION_STOPPING, "MQRC_CONNECTION_STOPPING" },
/* 2204*/ { MQ_MQRC_ADAPTER_NOT_AVAILABLE, "MQRC_ADAPTER_NOT_AVAILABLE" },
/* 2206*/ { MQ_MQRC_MSG_ID_ERROR, "MQRC_MSG_ID_ERROR" },
/* 2207*/ { MQ_MQRC_CORREL_ID_ERROR, "MQRC_CORREL_ID_ERROR" },
/* 2208*/ { MQ_MQRC_FILE_SYSTEM_ERROR, "MQRC_FILE_SYSTEM_ERROR" },
/* 2209*/ { MQ_MQRC_NO_MSG_LOCKED, "MQRC_NO_MSG_LOCKED" },
/* 2210*/ { MQ_MQRC_SOAP_DOTNET_ERROR, "MQRC_SOAP_DOTNET_ERROR" },
/* 2211*/ { MQ_MQRC_SOAP_AXIS_ERROR, "MQRC_SOAP_AXIS_ERROR" },
/* 2212*/ { MQ_MQRC_SOAP_URL_ERROR, "MQRC_SOAP_URL_ERROR" },
/* 2216*/ { MQ_MQRC_FILE_NOT_AUDITED, "MQRC_FILE_NOT_AUDITED" },
/* 2217*/ { MQ_MQRC_CONNECTION_NOT_AUTHORIZED, "MQRC_CONNECTION_NOT_AUTHORIZED" },
/* 2218*/ { MQ_MQRC_MSG_TOO_BIG_FOR_CHANNEL, "MQRC_MSG_TOO_BIG_FOR_CHANNEL" },
/* 2219*/ { MQ_MQRC_CALL_IN_PROGRESS, "MQRC_CALL_IN_PROGRESS" },
/* 2220*/ { MQ_MQRC_RMH_ERROR, "MQRC_RMH_ERROR" },
/* 2222*/ { MQ_MQRC_Q_MGR_ACTIVE, "MQRC_Q_MGR_ACTIVE" },
/* 2223*/ { MQ_MQRC_Q_MGR_NOT_ACTIVE, "MQRC_Q_MGR_NOT_ACTIVE" },
/* 2224*/ { MQ_MQRC_Q_DEPTH_HIGH, "MQRC_Q_DEPTH_HIGH" },
/* 2225*/ { MQ_MQRC_Q_DEPTH_LOW, "MQRC_Q_DEPTH_LOW" },
/* 2226*/ { MQ_MQRC_Q_SERVICE_INTERVAL_HIGH, "MQRC_Q_SERVICE_INTERVAL_HIGH" },
/* 2227*/ { MQ_MQRC_Q_SERVICE_INTERVAL_OK, "MQRC_Q_SERVICE_INTERVAL_OK" },
/* 2228*/ { MQ_MQRC_RFH_HEADER_FIELD_ERROR, "MQRC_RFH_HEADER_FIELD_ERROR" },
/* 2229*/ { MQ_MQRC_RAS_PROPERTY_ERROR, "MQRC_RAS_PROPERTY_ERROR" },
/* 2232*/ { MQ_MQRC_UNIT_OF_WORK_NOT_STARTED, "MQRC_UNIT_OF_WORK_NOT_STARTED" },
/* 2233*/ { MQ_MQRC_CHANNEL_AUTO_DEF_OK, "MQRC_CHANNEL_AUTO_DEF_OK" },
/* 2234*/ { MQ_MQRC_CHANNEL_AUTO_DEF_ERROR, "MQRC_CHANNEL_AUTO_DEF_ERROR" },
/* 2235*/ { MQ_MQRC_CFH_ERROR, "MQRC_CFH_ERROR" },
/* 2236*/ { MQ_MQRC_CFIL_ERROR, "MQRC_CFIL_ERROR" },
/* 2237*/ { MQ_MQRC_CFIN_ERROR, "MQRC_CFIN_ERROR" },
/* 2238*/ { MQ_MQRC_CFSL_ERROR, "MQRC_CFSL_ERROR" },
/* 2239*/ { MQ_MQRC_CFST_ERROR, "MQRC_CFST_ERROR" },
/* 2241*/ { MQ_MQRC_INCOMPLETE_GROUP, "MQRC_INCOMPLETE_GROUP" },
/* 2242*/ { MQ_MQRC_INCOMPLETE_MSG, "MQRC_INCOMPLETE_MSG" },
/* 2243*/ { MQ_MQRC_INCONSISTENT_CCSIDS, "MQRC_INCONSISTENT_CCSIDS" },
/* 2244*/ { MQ_MQRC_INCONSISTENT_ENCODINGS, "MQRC_INCONSISTENT_ENCODINGS" },
/* 2245*/ { MQ_MQRC_INCONSISTENT_UOW, "MQRC_INCONSISTENT_UOW" },
/* 2246*/ { MQ_MQRC_INVALID_MSG_UNDER_CURSOR, "MQRC_INVALID_MSG_UNDER_CURSOR" },
/* 2247*/ { MQ_MQRC_MATCH_OPTIONS_ERROR, "MQRC_MATCH_OPTIONS_ERROR" },
/* 2248*/ { MQ_MQRC_MDE_ERROR, "MQRC_MDE_ERROR" },
/* 2249*/ { MQ_MQRC_MSG_FLAGS_ERROR, "MQRC_MSG_FLAGS_ERROR" },
/* 2250*/ { MQ_MQRC_MSG_SEQ_NUMBER_ERROR, "MQRC_MSG_SEQ_NUMBER_ERROR" },
/* 2251*/ { MQ_MQRC_OFFSET_ERROR, "MQRC_OFFSET_ERROR" },
/* 2252*/ { MQ_MQRC_ORIGINAL_LENGTH_ERROR, "MQRC_ORIGINAL_LENGTH_ERROR" },
/* 2253*/ { MQ_MQRC_SEGMENT_LENGTH_ZERO, "MQRC_SEGMENT_LENGTH_ZERO" },
/* 2255*/ { MQ_MQRC_UOW_NOT_AVAILABLE, "MQRC_UOW_NOT_AVAILABLE" },
/* 2256*/ { MQ_MQRC_WRONG_GMO_VERSION, "MQRC_WRONG_GMO_VERSION" },
/* 2257*/ { MQ_MQRC_WRONG_MD_VERSION, "MQRC_WRONG_MD_VERSION" },
/* 2258*/ { MQ_MQRC_GROUP_ID_ERROR, "MQRC_GROUP_ID_ERROR" },
/* 2259*/ { MQ_MQRC_INCONSISTENT_BROWSE, "MQRC_INCONSISTENT_BROWSE" },
/* 2260*/ { MQ_MQRC_XQH_ERROR, "MQRC_XQH_ERROR" },
/* 2261*/ { MQ_MQRC_SRC_ENV_ERROR, "MQRC_SRC_ENV_ERROR" },
/* 2262*/ { MQ_MQRC_SRC_NAME_ERROR, "MQRC_SRC_NAME_ERROR" },
/* 2263*/ { MQ_MQRC_DEST_ENV_ERROR, "MQRC_DEST_ENV_ERROR" },
/* 2264*/ { MQ_MQRC_DEST_NAME_ERROR, "MQRC_DEST_NAME_ERROR" },
/* 2265*/ { MQ_MQRC_TM_ERROR, "MQRC_TM_ERROR" },
/* 2266*/ { MQ_MQRC_CLUSTER_EXIT_ERROR, "MQRC_CLUSTER_EXIT_ERROR" },
/* 2267*/ { MQ_MQRC_CLUSTER_EXIT_LOAD_ERROR, "MQRC_CLUSTER_EXIT_LOAD_ERROR" },
/* 2268*/ { MQ_MQRC_CLUSTER_PUT_INHIBITED, "MQRC_CLUSTER_PUT_INHIBITED" },
/* 2269*/ { MQ_MQRC_CLUSTER_RESOURCE_ERROR, "MQRC_CLUSTER_RESOURCE_ERROR" },
/* 2270*/ { MQ_MQRC_NO_DESTINATIONS_AVAILABLE, "MQRC_NO_DESTINATIONS_AVAILABLE" },
/* 2271*/ { MQ_MQRC_CONN_TAG_IN_USE, "MQRC_CONN_TAG_IN_USE" },
/* 2272*/ { MQ_MQRC_PARTIALLY_CONVERTED, "MQRC_PARTIALLY_CONVERTED" },
/* 2273*/ { MQ_MQRC_CONNECTION_ERROR, "MQRC_CONNECTION_ERROR" },
/* 2274*/ { MQ_MQRC_OPTION_ENVIRONMENT_ERROR, "MQRC_OPTION_ENVIRONMENT_ERROR" },
/* 2277*/ { MQ_MQRC_CD_ERROR, "MQRC_CD_ERROR" },
/* 2278*/ { MQ_MQRC_CLIENT_CONN_ERROR, "MQRC_CLIENT_CONN_ERROR" },
/* 2279*/ { MQ_MQRC_CHANNEL_STOPPED_BY_USER, "MQRC_CHANNEL_STOPPED_BY_USER" },
/* 2280*/ { MQ_MQRC_HCONFIG_ERROR, "MQRC_HCONFIG_ERROR" },
/* 2281*/ { MQ_MQRC_FUNCTION_ERROR, "MQRC_FUNCTION_ERROR" },
/* 2282*/ { MQ_MQRC_CHANNEL_STARTED, "MQRC_CHANNEL_STARTED" },
/* 2283*/ { MQ_MQRC_CHANNEL_STOPPED, "MQRC_CHANNEL_STOPPED" },
/* 2284*/ { MQ_MQRC_CHANNEL_CONV_ERROR, "MQRC_CHANNEL_CONV_ERROR" },
/* 2285*/ { MQ_MQRC_SERVICE_NOT_AVAILABLE, "MQRC_SERVICE_NOT_AVAILABLE" },
/* 2286*/ { MQ_MQRC_INITIALIZATION_FAILED, "MQRC_INITIALIZATION_FAILED" },
/* 2287*/ { MQ_MQRC_TERMINATION_FAILED, "MQRC_TERMINATION_FAILED" },
/* 2288*/ { MQ_MQRC_UNKNOWN_Q_NAME, "MQRC_UNKNOWN_Q_NAME" },
/* 2289*/ { MQ_MQRC_SERVICE_ERROR, "MQRC_SERVICE_ERROR" },
/* 2290*/ { MQ_MQRC_Q_ALREADY_EXISTS, "MQRC_Q_ALREADY_EXISTS" },
/* 2291*/ { MQ_MQRC_USER_ID_NOT_AVAILABLE, "MQRC_USER_ID_NOT_AVAILABLE" },
/* 2292*/ { MQ_MQRC_UNKNOWN_ENTITY, "MQRC_UNKNOWN_ENTITY" },
/* 2293*/ { MQ_MQRC_UNKNOWN_AUTH_ENTITY, "MQRC_UNKNOWN_AUTH_ENTITY" },
/* 2294*/ { MQ_MQRC_UNKNOWN_REF_OBJECT, "MQRC_UNKNOWN_REF_OBJECT" },
/* 2295*/ { MQ_MQRC_CHANNEL_ACTIVATED, "MQRC_CHANNEL_ACTIVATED" },
/* 2296*/ { MQ_MQRC_CHANNEL_NOT_ACTIVATED, "MQRC_CHANNEL_NOT_ACTIVATED" },
/* 2297*/ { MQ_MQRC_UOW_CANCELED, "MQRC_UOW_CANCELED" },
/* 2298*/ { MQ_MQRC_FUNCTION_NOT_SUPPORTED, "MQRC_FUNCTION_NOT_SUPPORTED" },
/* 2299*/ { MQ_MQRC_SELECTOR_TYPE_ERROR, "MQRC_SELECTOR_TYPE_ERROR" },
/* 2300*/ { MQ_MQRC_COMMAND_TYPE_ERROR, "MQRC_COMMAND_TYPE_ERROR" },
/* 2301*/ { MQ_MQRC_MULTIPLE_INSTANCE_ERROR, "MQRC_MULTIPLE_INSTANCE_ERROR" },
/* 2302*/ { MQ_MQRC_SYSTEM_ITEM_NOT_ALTERABLE, "MQRC_SYSTEM_ITEM_NOT_ALTERABLE" },
/* 2303*/ { MQ_MQRC_BAG_CONVERSION_ERROR, "MQRC_BAG_CONVERSION_ERROR" },
/* 2304*/ { MQ_MQRC_SELECTOR_OUT_OF_RANGE, "MQRC_SELECTOR_OUT_OF_RANGE" },
/* 2305*/ { MQ_MQRC_SELECTOR_NOT_UNIQUE, "MQRC_SELECTOR_NOT_UNIQUE" },
/* 2306*/ { MQ_MQRC_INDEX_NOT_PRESENT, "MQRC_INDEX_NOT_PRESENT" },
/* 2307*/ { MQ_MQRC_STRING_ERROR, "MQRC_STRING_ERROR" },
/* 2308*/ { MQ_MQRC_ENCODING_NOT_SUPPORTED, "MQRC_ENCODING_NOT_SUPPORTED" },
/* 2309*/ { MQ_MQRC_SELECTOR_NOT_PRESENT, "MQRC_SELECTOR_NOT_PRESENT" },
/* 2310*/ { MQ_MQRC_OUT_SELECTOR_ERROR, "MQRC_OUT_SELECTOR_ERROR" },
/* 2311*/ { MQ_MQRC_STRING_TRUNCATED, "MQRC_STRING_TRUNCATED" },
/* 2312*/ { MQ_MQRC_SELECTOR_WRONG_TYPE, "MQRC_SELECTOR_WRONG_TYPE" },
/* 2313*/ { MQ_MQRC_INCONSISTENT_ITEM_TYPE, "MQRC_INCONSISTENT_ITEM_TYPE" },
/* 2314*/ { MQ_MQRC_INDEX_ERROR, "MQRC_INDEX_ERROR" },
/* 2315*/ { MQ_MQRC_SYSTEM_BAG_NOT_ALTERABLE, "MQRC_SYSTEM_BAG_NOT_ALTERABLE" },
/* 2316*/ { MQ_MQRC_ITEM_COUNT_ERROR, "MQRC_ITEM_COUNT_ERROR" },
/* 2317*/ { MQ_MQRC_FORMAT_NOT_SUPPORTED, "MQRC_FORMAT_NOT_SUPPORTED" },
/* 2318*/ { MQ_MQRC_SELECTOR_NOT_SUPPORTED, "MQRC_SELECTOR_NOT_SUPPORTED" },
/* 2319*/ { MQ_MQRC_ITEM_VALUE_ERROR, "MQRC_ITEM_VALUE_ERROR" },
/* 2320*/ { MQ_MQRC_HBAG_ERROR, "MQRC_HBAG_ERROR" },
/* 2321*/ { MQ_MQRC_PARAMETER_MISSING, "MQRC_PARAMETER_MISSING" },
/* 2322*/ { MQ_MQRC_CMD_SERVER_NOT_AVAILABLE, "MQRC_CMD_SERVER_NOT_AVAILABLE" },
/* 2323*/ { MQ_MQRC_STRING_LENGTH_ERROR, "MQRC_STRING_LENGTH_ERROR" },
/* 2324*/ { MQ_MQRC_INQUIRY_COMMAND_ERROR, "MQRC_INQUIRY_COMMAND_ERROR" },
/* 2325*/ { MQ_MQRC_NESTED_BAG_NOT_SUPPORTED, "MQRC_NESTED_BAG_NOT_SUPPORTED" },
/* 2326*/ { MQ_MQRC_BAG_WRONG_TYPE, "MQRC_BAG_WRONG_TYPE" },
/* 2327*/ { MQ_MQRC_ITEM_TYPE_ERROR, "MQRC_ITEM_TYPE_ERROR" },
/* 2328*/ { MQ_MQRC_SYSTEM_BAG_NOT_DELETABLE, "MQRC_SYSTEM_BAG_NOT_DELETABLE" },
/* 2329*/ { MQ_MQRC_SYSTEM_ITEM_NOT_DELETABLE, "MQRC_SYSTEM_ITEM_NOT_DELETABLE" },
/* 2330*/ { MQ_MQRC_CODED_CHAR_SET_ID_ERROR, "MQRC_CODED_CHAR_SET_ID_ERROR" },
/* 2331*/ { MQ_MQRC_MSG_TOKEN_ERROR, "MQRC_MSG_TOKEN_ERROR" },
/* 2332*/ { MQ_MQRC_MISSING_WIH, "MQRC_MISSING_WIH" },
/* 2333*/ { MQ_MQRC_WIH_ERROR, "MQRC_WIH_ERROR" },
/* 2334*/ { MQ_MQRC_RFH_ERROR, "MQRC_RFH_ERROR" },
/* 2335*/ { MQ_MQRC_RFH_STRING_ERROR, "MQRC_RFH_STRING_ERROR" },
/* 2336*/ { MQ_MQRC_RFH_COMMAND_ERROR, "MQRC_RFH_COMMAND_ERROR" },
/* 2337*/ { MQ_MQRC_RFH_PARM_ERROR, "MQRC_RFH_PARM_ERROR" },
/* 2338*/ { MQ_MQRC_RFH_DUPLICATE_PARM, "MQRC_RFH_DUPLICATE_PARM" },
/* 2339*/ { MQ_MQRC_RFH_PARM_MISSING, "MQRC_RFH_PARM_MISSING" },
/* 2340*/ { MQ_MQRC_CHAR_CONVERSION_ERROR, "MQRC_CHAR_CONVERSION_ERROR" },
/* 2341*/ { MQ_MQRC_UCS2_CONVERSION_ERROR, "MQRC_UCS2_CONVERSION_ERROR" },
/* 2342*/ { MQ_MQRC_DB2_NOT_AVAILABLE, "MQRC_DB2_NOT_AVAILABLE" },
/* 2343*/ { MQ_MQRC_OBJECT_NOT_UNIQUE, "MQRC_OBJECT_NOT_UNIQUE" },
/* 2344*/ { MQ_MQRC_CONN_TAG_NOT_RELEASED, "MQRC_CONN_TAG_NOT_RELEASED" },
/* 2345*/ { MQ_MQRC_CF_NOT_AVAILABLE, "MQRC_CF_NOT_AVAILABLE" },
/* 2346*/ { MQ_MQRC_CF_STRUC_IN_USE, "MQRC_CF_STRUC_IN_USE" },
/* 2347*/ { MQ_MQRC_CF_STRUC_LIST_HDR_IN_USE, "MQRC_CF_STRUC_LIST_HDR_IN_USE" },
/* 2348*/ { MQ_MQRC_CF_STRUC_AUTH_FAILED, "MQRC_CF_STRUC_AUTH_FAILED" },
/* 2349*/ { MQ_MQRC_CF_STRUC_ERROR, "MQRC_CF_STRUC_ERROR" },
/* 2350*/ { MQ_MQRC_CONN_TAG_NOT_USABLE, "MQRC_CONN_TAG_NOT_USABLE" },
/* 2351*/ { MQ_MQRC_GLOBAL_UOW_CONFLICT, "MQRC_GLOBAL_UOW_CONFLICT" },
/* 2352*/ { MQ_MQRC_LOCAL_UOW_CONFLICT, "MQRC_LOCAL_UOW_CONFLICT" },
/* 2353*/ { MQ_MQRC_HANDLE_IN_USE_FOR_UOW, "MQRC_HANDLE_IN_USE_FOR_UOW" },
/* 2354*/ { MQ_MQRC_UOW_ENLISTMENT_ERROR, "MQRC_UOW_ENLISTMENT_ERROR" },
/* 2355*/ { MQ_MQRC_UOW_MIX_NOT_SUPPORTED, "MQRC_UOW_MIX_NOT_SUPPORTED" },
/* 2356*/ { MQ_MQRC_WXP_ERROR, "MQRC_WXP_ERROR" },
/* 2357*/ { MQ_MQRC_CURRENT_RECORD_ERROR, "MQRC_CURRENT_RECORD_ERROR" },
/* 2358*/ { MQ_MQRC_NEXT_OFFSET_ERROR, "MQRC_NEXT_OFFSET_ERROR" },
/* 2359*/ { MQ_MQRC_NO_RECORD_AVAILABLE, "MQRC_NO_RECORD_AVAILABLE" },
/* 2360*/ { MQ_MQRC_OBJECT_LEVEL_INCOMPATIBLE, "MQRC_OBJECT_LEVEL_INCOMPATIBLE" },
/* 2361*/ { MQ_MQRC_NEXT_RECORD_ERROR, "MQRC_NEXT_RECORD_ERROR" },
/* 2362*/ { MQ_MQRC_BACKOUT_THRESHOLD_REACHED, "MQRC_BACKOUT_THRESHOLD_REACHED" },
/* 2363*/ { MQ_MQRC_MSG_NOT_MATCHED, "MQRC_MSG_NOT_MATCHED" },
/* 2364*/ { MQ_MQRC_JMS_FORMAT_ERROR, "MQRC_JMS_FORMAT_ERROR" },
/* 2365*/ { MQ_MQRC_SEGMENTS_NOT_SUPPORTED, "MQRC_SEGMENTS_NOT_SUPPORTED" },
/* 2366*/ { MQ_MQRC_WRONG_CF_LEVEL, "MQRC_WRONG_CF_LEVEL" },
/* 2367*/ { MQ_MQRC_CONFIG_CREATE_OBJECT, "MQRC_CONFIG_CREATE_OBJECT" },
/* 2368*/ { MQ_MQRC_CONFIG_CHANGE_OBJECT, "MQRC_CONFIG_CHANGE_OBJECT" },
/* 2369*/ { MQ_MQRC_CONFIG_DELETE_OBJECT, "MQRC_CONFIG_DELETE_OBJECT" },
/* 2370*/ { MQ_MQRC_CONFIG_REFRESH_OBJECT, "MQRC_CONFIG_REFRESH_OBJECT" },
/* 2371*/ { MQ_MQRC_CHANNEL_SSL_ERROR, "MQRC_CHANNEL_SSL_ERROR" },
/* 2372*/ { MQ_MQRC_PARTICIPANT_NOT_DEFINED, "MQRC_PARTICIPANT_NOT_DEFINED" },
/* 2373*/ { MQ_MQRC_CF_STRUC_FAILED, "MQRC_CF_STRUC_FAILED" },
/* 2374*/ { MQ_MQRC_API_EXIT_ERROR, "MQRC_API_EXIT_ERROR" },
/* 2375*/ { MQ_MQRC_API_EXIT_INIT_ERROR, "MQRC_API_EXIT_INIT_ERROR" },
/* 2376*/ { MQ_MQRC_API_EXIT_TERM_ERROR, "MQRC_API_EXIT_TERM_ERROR" },
/* 2377*/ { MQ_MQRC_EXIT_REASON_ERROR, "MQRC_EXIT_REASON_ERROR" },
/* 2378*/ { MQ_MQRC_RESERVED_VALUE_ERROR, "MQRC_RESERVED_VALUE_ERROR" },
/* 2379*/ { MQ_MQRC_NO_DATA_AVAILABLE, "MQRC_NO_DATA_AVAILABLE" },
/* 2380*/ { MQ_MQRC_SCO_ERROR, "MQRC_SCO_ERROR" },
/* 2381*/ { MQ_MQRC_KEY_REPOSITORY_ERROR, "MQRC_KEY_REPOSITORY_ERROR" },
/* 2382*/ { MQ_MQRC_CRYPTO_HARDWARE_ERROR, "MQRC_CRYPTO_HARDWARE_ERROR" },
/* 2383*/ { MQ_MQRC_AUTH_INFO_REC_COUNT_ERROR, "MQRC_AUTH_INFO_REC_COUNT_ERROR" },
/* 2384*/ { MQ_MQRC_AUTH_INFO_REC_ERROR, "MQRC_AUTH_INFO_REC_ERROR" },
/* 2385*/ { MQ_MQRC_AIR_ERROR, "MQRC_AIR_ERROR" },
/* 2386*/ { MQ_MQRC_AUTH_INFO_TYPE_ERROR, "MQRC_AUTH_INFO_TYPE_ERROR" },
/* 2387*/ { MQ_MQRC_AUTH_INFO_CONN_NAME_ERROR, "MQRC_AUTH_INFO_CONN_NAME_ERROR" },
/* 2388*/ { MQ_MQRC_LDAP_USER_NAME_ERROR, "MQRC_LDAP_USER_NAME_ERROR" },
/* 2389*/ { MQ_MQRC_LDAP_USER_NAME_LENGTH_ERR, "MQRC_LDAP_USER_NAME_LENGTH_ERR" },
/* 2390*/ { MQ_MQRC_LDAP_PASSWORD_ERROR, "MQRC_LDAP_PASSWORD_ERROR" },
/* 2391*/ { MQ_MQRC_SSL_ALREADY_INITIALIZED, "MQRC_SSL_ALREADY_INITIALIZED" },
/* 2392*/ { MQ_MQRC_SSL_CONFIG_ERROR, "MQRC_SSL_CONFIG_ERROR" },
/* 2393*/ { MQ_MQRC_SSL_INITIALIZATION_ERROR, "MQRC_SSL_INITIALIZATION_ERROR" },
/* 2394*/ { MQ_MQRC_Q_INDEX_TYPE_ERROR, "MQRC_Q_INDEX_TYPE_ERROR" },
/* 2395*/ { MQ_MQRC_CFBS_ERROR, "MQRC_CFBS_ERROR" },
/* 2396*/ { MQ_MQRC_SSL_NOT_ALLOWED, "MQRC_SSL_NOT_ALLOWED" },
/* 2397*/ { MQ_MQRC_JSSE_ERROR, "MQRC_JSSE_ERROR" },
/* 2398*/ { MQ_MQRC_SSL_PEER_NAME_MISMATCH, "MQRC_SSL_PEER_NAME_MISMATCH" },
/* 2399*/ { MQ_MQRC_SSL_PEER_NAME_ERROR, "MQRC_SSL_PEER_NAME_ERROR" },
/* 2400*/ { MQ_MQRC_UNSUPPORTED_CIPHER_SUITE, "MQRC_UNSUPPORTED_CIPHER_SUITE" },
/* 2401*/ { MQ_MQRC_SSL_CERTIFICATE_REVOKED, "MQRC_SSL_CERTIFICATE_REVOKED" },
/* 2402*/ { MQ_MQRC_SSL_CERT_STORE_ERROR, "MQRC_SSL_CERT_STORE_ERROR" },
/* 2406*/ { MQ_MQRC_CLIENT_EXIT_LOAD_ERROR, "MQRC_CLIENT_EXIT_LOAD_ERROR" },
/* 2407*/ { MQ_MQRC_CLIENT_EXIT_ERROR, "MQRC_CLIENT_EXIT_ERROR" },
/* 2408*/ { MQ_MQRC_UOW_COMMITTED, "MQRC_UOW_COMMITTED" },
/* 2409*/ { MQ_MQRC_SSL_KEY_RESET_ERROR, "MQRC_SSL_KEY_RESET_ERROR" },
/* 2410*/ { MQ_MQRC_UNKNOWN_COMPONENT_NAME, "MQRC_UNKNOWN_COMPONENT_NAME" },
/* 2411*/ { MQ_MQRC_LOGGER_STATUS, "MQRC_LOGGER_STATUS" },
/* 2412*/ { MQ_MQRC_COMMAND_MQSC, "MQRC_COMMAND_MQSC" },
/* 2413*/ { MQ_MQRC_COMMAND_PCF, "MQRC_COMMAND_PCF" },
/* 2414*/ { MQ_MQRC_CFIF_ERROR, "MQRC_CFIF_ERROR" },
/* 2415*/ { MQ_MQRC_CFSF_ERROR, "MQRC_CFSF_ERROR" },
/* 2416*/ { MQ_MQRC_CFGR_ERROR, "MQRC_CFGR_ERROR" },
/* 2417*/ { MQ_MQRC_MSG_NOT_ALLOWED_IN_GROUP, "MQRC_MSG_NOT_ALLOWED_IN_GROUP" },
/* 2418*/ { MQ_MQRC_FILTER_OPERATOR_ERROR, "MQRC_FILTER_OPERATOR_ERROR" },
/* 2419*/ { MQ_MQRC_NESTED_SELECTOR_ERROR, "MQRC_NESTED_SELECTOR_ERROR" },
/* 2420*/ { MQ_MQRC_EPH_ERROR, "MQRC_EPH_ERROR" },
/* 2421*/ { MQ_MQRC_RFH_FORMAT_ERROR, "MQRC_RFH_FORMAT_ERROR" },
/* 2422*/ { MQ_MQRC_CFBF_ERROR, "MQRC_CFBF_ERROR" },
/* 2423*/ { MQ_MQRC_CLIENT_CHANNEL_CONFLICT, "MQRC_CLIENT_CHANNEL_CONFLICT" },
/* 2424*/ { MQ_MQRC_SD_ERROR, "MQRC_SD_ERROR" },
/* 2425*/ { MQ_MQRC_TOPIC_STRING_ERROR, "MQRC_TOPIC_STRING_ERROR" },
/* 2426*/ { MQ_MQRC_STS_ERROR, "MQRC_STS_ERROR" },
/* 2428*/ { MQ_MQRC_NO_SUBSCRIPTION, "MQRC_NO_SUBSCRIPTION" },
/* 2429*/ { MQ_MQRC_SUBSCRIPTION_IN_USE, "MQRC_SUBSCRIPTION_IN_USE" },
/* 2430*/ { MQ_MQRC_STAT_TYPE_ERROR, "MQRC_STAT_TYPE_ERROR" },
/* 2431*/ { MQ_MQRC_SUB_USER_DATA_ERROR, "MQRC_SUB_USER_DATA_ERROR" },
/* 2432*/ { MQ_MQRC_SUB_ALREADY_EXISTS, "MQRC_SUB_ALREADY_EXISTS" },
/* 2434*/ { MQ_MQRC_IDENTITY_MISMATCH, "MQRC_IDENTITY_MISMATCH" },
/* 2435*/ { MQ_MQRC_ALTER_SUB_ERROR, "MQRC_ALTER_SUB_ERROR" },
/* 2436*/ { MQ_MQRC_DURABILITY_NOT_ALLOWED, "MQRC_DURABILITY_NOT_ALLOWED" },
/* 2437*/ { MQ_MQRC_NO_RETAINED_MSG, "MQRC_NO_RETAINED_MSG" },
/* 2438*/ { MQ_MQRC_SRO_ERROR, "MQRC_SRO_ERROR" },
/* 2440*/ { MQ_MQRC_SUB_NAME_ERROR, "MQRC_SUB_NAME_ERROR" },
/* 2441*/ { MQ_MQRC_OBJECT_STRING_ERROR, "MQRC_OBJECT_STRING_ERROR" },
/* 2442*/ { MQ_MQRC_PROPERTY_NAME_ERROR, "MQRC_PROPERTY_NAME_ERROR" },
/* 2443*/ { MQ_MQRC_SEGMENTATION_NOT_ALLOWED, "MQRC_SEGMENTATION_NOT_ALLOWED" },
/* 2444*/ { MQ_MQRC_CBD_ERROR, "MQRC_CBD_ERROR" },
/* 2445*/ { MQ_MQRC_CTLO_ERROR, "MQRC_CTLO_ERROR" },
/* 2446*/ { MQ_MQRC_NO_CALLBACKS_ACTIVE, "MQRC_NO_CALLBACKS_ACTIVE" },
/* 2448*/ { MQ_MQRC_CALLBACK_NOT_REGISTERED, "MQRC_CALLBACK_NOT_REGISTERED" },
/* 2457*/ { MQ_MQRC_OPTIONS_CHANGED, "MQRC_OPTIONS_CHANGED" },
/* 2458*/ { MQ_MQRC_READ_AHEAD_MSGS, "MQRC_READ_AHEAD_MSGS" },
/* 2459*/ { MQ_MQRC_SELECTOR_SYNTAX_ERROR, "MQRC_SELECTOR_SYNTAX_ERROR" },
/* 2460*/ { MQ_MQRC_HMSG_ERROR, "MQRC_HMSG_ERROR" },
/* 2461*/ { MQ_MQRC_CMHO_ERROR, "MQRC_CMHO_ERROR" },
/* 2462*/ { MQ_MQRC_DMHO_ERROR, "MQRC_DMHO_ERROR" },
/* 2463*/ { MQ_MQRC_SMPO_ERROR, "MQRC_SMPO_ERROR" },
/* 2464*/ { MQ_MQRC_IMPO_ERROR, "MQRC_IMPO_ERROR" },
/* 2465*/ { MQ_MQRC_PROPERTY_NAME_TOO_BIG, "MQRC_PROPERTY_NAME_TOO_BIG" },
/* 2466*/ { MQ_MQRC_PROP_VALUE_NOT_CONVERTED, "MQRC_PROP_VALUE_NOT_CONVERTED" },
/* 2467*/ { MQ_MQRC_PROP_TYPE_NOT_SUPPORTED, "MQRC_PROP_TYPE_NOT_SUPPORTED" },
/* 2469*/ { MQ_MQRC_PROPERTY_VALUE_TOO_BIG, "MQRC_PROPERTY_VALUE_TOO_BIG" },
/* 2470*/ { MQ_MQRC_PROP_CONV_NOT_SUPPORTED, "MQRC_PROP_CONV_NOT_SUPPORTED" },
/* 2471*/ { MQ_MQRC_PROPERTY_NOT_AVAILABLE, "MQRC_PROPERTY_NOT_AVAILABLE" },
/* 2472*/ { MQ_MQRC_PROP_NUMBER_FORMAT_ERROR, "MQRC_PROP_NUMBER_FORMAT_ERROR" },
/* 2473*/ { MQ_MQRC_PROPERTY_TYPE_ERROR, "MQRC_PROPERTY_TYPE_ERROR" },
/* 2478*/ { MQ_MQRC_PROPERTIES_TOO_BIG, "MQRC_PROPERTIES_TOO_BIG" },
/* 2479*/ { MQ_MQRC_PUT_NOT_RETAINED, "MQRC_PUT_NOT_RETAINED" },
/* 2480*/ { MQ_MQRC_ALIAS_TARGTYPE_CHANGED, "MQRC_ALIAS_TARGTYPE_CHANGED" },
/* 2481*/ { MQ_MQRC_DMPO_ERROR, "MQRC_DMPO_ERROR" },
/* 2482*/ { MQ_MQRC_PD_ERROR, "MQRC_PD_ERROR" },
/* 2483*/ { MQ_MQRC_CALLBACK_TYPE_ERROR, "MQRC_CALLBACK_TYPE_ERROR" },
/* 2484*/ { MQ_MQRC_CBD_OPTIONS_ERROR, "MQRC_CBD_OPTIONS_ERROR" },
/* 2485*/ { MQ_MQRC_MAX_MSG_LENGTH_ERROR, "MQRC_MAX_MSG_LENGTH_ERROR" },
/* 2486*/ { MQ_MQRC_CALLBACK_ROUTINE_ERROR, "MQRC_CALLBACK_ROUTINE_ERROR" },
/* 2487*/ { MQ_MQRC_CALLBACK_LINK_ERROR, "MQRC_CALLBACK_LINK_ERROR" },
/* 2488*/ { MQ_MQRC_OPERATION_ERROR, "MQRC_OPERATION_ERROR" },
/* 2489*/ { MQ_MQRC_BMHO_ERROR, "MQRC_BMHO_ERROR" },
/* 2490*/ { MQ_MQRC_UNSUPPORTED_PROPERTY, "MQRC_UNSUPPORTED_PROPERTY" },
/* 2492*/ { MQ_MQRC_PROP_NAME_NOT_CONVERTED, "MQRC_PROP_NAME_NOT_CONVERTED" },
/* 2494*/ { MQ_MQRC_GET_ENABLED, "MQRC_GET_ENABLED" },
/* 2495*/ { MQ_MQRC_MODULE_NOT_FOUND, "MQRC_MODULE_NOT_FOUND" },
/* 2496*/ { MQ_MQRC_MODULE_INVALID, "MQRC_MODULE_INVALID" },
/* 2497*/ { MQ_MQRC_MODULE_ENTRY_NOT_FOUND, "MQRC_MODULE_ENTRY_NOT_FOUND" },
/* 2498*/ { MQ_MQRC_MIXED_CONTENT_NOT_ALLOWED, "MQRC_MIXED_CONTENT_NOT_ALLOWED" },
/* 2499*/ { MQ_MQRC_MSG_HANDLE_IN_USE, "MQRC_MSG_HANDLE_IN_USE" },
/* 2500*/ { MQ_MQRC_HCONN_ASYNC_ACTIVE, "MQRC_HCONN_ASYNC_ACTIVE" },
/* 2501*/ { MQ_MQRC_MHBO_ERROR, "MQRC_MHBO_ERROR" },
/* 2502*/ { MQ_MQRC_PUBLICATION_FAILURE, "MQRC_PUBLICATION_FAILURE" },
/* 2503*/ { MQ_MQRC_SUB_INHIBITED, "MQRC_SUB_INHIBITED" },
/* 2504*/ { MQ_MQRC_SELECTOR_ALWAYS_FALSE, "MQRC_SELECTOR_ALWAYS_FALSE" },
/* 2507*/ { MQ_MQRC_XEPO_ERROR, "MQRC_XEPO_ERROR" },
/* 2509*/ { MQ_MQRC_DURABILITY_NOT_ALTERABLE, "MQRC_DURABILITY_NOT_ALTERABLE" },
/* 2510*/ { MQ_MQRC_TOPIC_NOT_ALTERABLE, "MQRC_TOPIC_NOT_ALTERABLE" },
/* 2512*/ { MQ_MQRC_SUBLEVEL_NOT_ALTERABLE, "MQRC_SUBLEVEL_NOT_ALTERABLE" },
/* 2513*/ { MQ_MQRC_PROPERTY_NAME_LENGTH_ERR, "MQRC_PROPERTY_NAME_LENGTH_ERR" },
/* 2514*/ { MQ_MQRC_DUPLICATE_GROUP_SUB, "MQRC_DUPLICATE_GROUP_SUB" },
/* 2515*/ { MQ_MQRC_GROUPING_NOT_ALTERABLE, "MQRC_GROUPING_NOT_ALTERABLE" },
/* 2516*/ { MQ_MQRC_SELECTOR_INVALID_FOR_TYPE, "MQRC_SELECTOR_INVALID_FOR_TYPE" },
/* 2517*/ { MQ_MQRC_HOBJ_QUIESCED, "MQRC_HOBJ_QUIESCED" },
/* 2518*/ { MQ_MQRC_HOBJ_QUIESCED_NO_MSGS, "MQRC_HOBJ_QUIESCED_NO_MSGS" },
/* 2519*/ { MQ_MQRC_SELECTION_STRING_ERROR, "MQRC_SELECTION_STRING_ERROR" },
/* 2520*/ { MQ_MQRC_RES_OBJECT_STRING_ERROR, "MQRC_RES_OBJECT_STRING_ERROR" },
/* 2521*/ { MQ_MQRC_CONNECTION_SUSPENDED, "MQRC_CONNECTION_SUSPENDED" },
/* 2522*/ { MQ_MQRC_INVALID_DESTINATION, "MQRC_INVALID_DESTINATION" },
/* 2523*/ { MQ_MQRC_INVALID_SUBSCRIPTION, "MQRC_INVALID_SUBSCRIPTION" },
/* 2524*/ { MQ_MQRC_SELECTOR_NOT_ALTERABLE, "MQRC_SELECTOR_NOT_ALTERABLE" },
/* 2525*/ { MQ_MQRC_RETAINED_MSG_Q_ERROR, "MQRC_RETAINED_MSG_Q_ERROR" },
/* 2526*/ { MQ_MQRC_RETAINED_NOT_DELIVERED, "MQRC_RETAINED_NOT_DELIVERED" },
/* 2527*/ { MQ_MQRC_RFH_RESTRICTED_FORMAT_ERR, "MQRC_RFH_RESTRICTED_FORMAT_ERR" },
/* 2528*/ { MQ_MQRC_CONNECTION_STOPPED, "MQRC_CONNECTION_STOPPED" },
/* 2529*/ { MQ_MQRC_ASYNC_UOW_CONFLICT, "MQRC_ASYNC_UOW_CONFLICT" },
/* 2530*/ { MQ_MQRC_ASYNC_XA_CONFLICT, "MQRC_ASYNC_XA_CONFLICT" },
/* 2531*/ { MQ_MQRC_PUBSUB_INHIBITED, "MQRC_PUBSUB_INHIBITED" },
/* 2532*/ { MQ_MQRC_MSG_HANDLE_COPY_FAILURE, "MQRC_MSG_HANDLE_COPY_FAILURE" },
/* 2533*/ { MQ_MQRC_DEST_CLASS_NOT_ALTERABLE, "MQRC_DEST_CLASS_NOT_ALTERABLE" },
/* 2534*/ { MQ_MQRC_OPERATION_NOT_ALLOWED, "MQRC_OPERATION_NOT_ALLOWED" },
/* 2535*/ { MQ_MQRC_ACTION_ERROR, "MQRC_ACTION_ERROR" },
/* 2537*/ { MQ_MQRC_CHANNEL_NOT_AVAILABLE, "MQRC_CHANNEL_NOT_AVAILABLE" },
/* 2538*/ { MQ_MQRC_HOST_NOT_AVAILABLE, "MQRC_HOST_NOT_AVAILABLE" },
/* 2539*/ { MQ_MQRC_CHANNEL_CONFIG_ERROR, "MQRC_CHANNEL_CONFIG_ERROR" },
/* 2540*/ { MQ_MQRC_UNKNOWN_CHANNEL_NAME, "MQRC_UNKNOWN_CHANNEL_NAME" },
/* 2541*/ { MQ_MQRC_LOOPING_PUBLICATION, "MQRC_LOOPING_PUBLICATION" },
/* 2542*/ { MQ_MQRC_ALREADY_JOINED, "MQRC_ALREADY_JOINED" },
/* 2543*/ { MQ_MQRC_STANDBY_Q_MGR, "MQRC_STANDBY_Q_MGR" },
/* 2544*/ { MQ_MQRC_RECONNECTING, "MQRC_RECONNECTING" },
/* 2545*/ { MQ_MQRC_RECONNECTED, "MQRC_RECONNECTED" },
/* 2546*/ { MQ_MQRC_RECONNECT_QMID_MISMATCH, "MQRC_RECONNECT_QMID_MISMATCH" },
/* 2547*/ { MQ_MQRC_RECONNECT_INCOMPATIBLE, "MQRC_RECONNECT_INCOMPATIBLE" },
/* 2548*/ { MQ_MQRC_RECONNECT_FAILED, "MQRC_RECONNECT_FAILED" },
/* 2549*/ { MQ_MQRC_CALL_INTERRUPTED, "MQRC_CALL_INTERRUPTED" },
/* 2550*/ { MQ_MQRC_NO_SUBS_MATCHED, "MQRC_NO_SUBS_MATCHED" },
/* 2551*/ { MQ_MQRC_SELECTION_NOT_AVAILABLE, "MQRC_SELECTION_NOT_AVAILABLE" },
/* 2552*/ { MQ_MQRC_CHANNEL_SSL_WARNING, "MQRC_CHANNEL_SSL_WARNING" },
/* 2553*/ { MQ_MQRC_OCSP_URL_ERROR, "MQRC_OCSP_URL_ERROR" },
/* 2554*/ { MQ_MQRC_CONTENT_ERROR, "MQRC_CONTENT_ERROR" },
/* 2555*/ { MQ_MQRC_RECONNECT_Q_MGR_REQD, "MQRC_RECONNECT_Q_MGR_REQD" },
/* 2556*/ { MQ_MQRC_RECONNECT_TIMED_OUT, "MQRC_RECONNECT_TIMED_OUT" },
/* 2557*/ { MQ_MQRC_PUBLISH_EXIT_ERROR, "MQRC_PUBLISH_EXIT_ERROR" },
/* 2558*/ { MQ_MQRC_COMMINFO_ERROR, "MQRC_COMMINFO_ERROR" },
/* 2559*/ { MQ_MQRC_DEF_SYNCPOINT_INHIBITED, "MQRC_DEF_SYNCPOINT_INHIBITED" },
/* 2560*/ { MQ_MQRC_MULTICAST_ONLY, "MQRC_MULTICAST_ONLY" },
/* 2561*/ { MQ_MQRC_DATA_SET_NOT_AVAILABLE, "MQRC_DATA_SET_NOT_AVAILABLE" },
/* 2562*/ { MQ_MQRC_GROUPING_NOT_ALLOWED, "MQRC_GROUPING_NOT_ALLOWED" },
/* 2563*/ { MQ_MQRC_GROUP_ADDRESS_ERROR, "MQRC_GROUP_ADDRESS_ERROR" },
/* 2564*/ { MQ_MQRC_MULTICAST_CONFIG_ERROR, "MQRC_MULTICAST_CONFIG_ERROR" },
/* 2565*/ { MQ_MQRC_MULTICAST_INTERFACE_ERROR, "MQRC_MULTICAST_INTERFACE_ERROR" },
/* 2566*/ { MQ_MQRC_MULTICAST_SEND_ERROR, "MQRC_MULTICAST_SEND_ERROR" },
/* 2567*/ { MQ_MQRC_MULTICAST_INTERNAL_ERROR, "MQRC_MULTICAST_INTERNAL_ERROR" },
/* 2568*/ { MQ_MQRC_CONNECTION_NOT_AVAILABLE, "MQRC_CONNECTION_NOT_AVAILABLE" },
/* 2569*/ { MQ_MQRC_SYNCPOINT_NOT_ALLOWED, "MQRC_SYNCPOINT_NOT_ALLOWED" },
/* 2570*/ { MQ_MQRC_SSL_ALT_PROVIDER_REQUIRED, "MQRC_SSL_ALT_PROVIDER_REQUIRED" },
/* 2571*/ { MQ_MQRC_MCAST_PUB_STATUS, "MQRC_MCAST_PUB_STATUS" },
/* 2572*/ { MQ_MQRC_MCAST_SUB_STATUS, "MQRC_MCAST_SUB_STATUS" },
/* 2573*/ { MQ_MQRC_PRECONN_EXIT_LOAD_ERROR, "MQRC_PRECONN_EXIT_LOAD_ERROR" },
/* 2574*/ { MQ_MQRC_PRECONN_EXIT_NOT_FOUND, "MQRC_PRECONN_EXIT_NOT_FOUND" },
/* 2575*/ { MQ_MQRC_PRECONN_EXIT_ERROR, "MQRC_PRECONN_EXIT_ERROR" },
/* 2576*/ { MQ_MQRC_CD_ARRAY_ERROR, "MQRC_CD_ARRAY_ERROR" },
/* 2577*/ { MQ_MQRC_CHANNEL_BLOCKED, "MQRC_CHANNEL_BLOCKED" },
/* 2578*/ { MQ_MQRC_CHANNEL_BLOCKED_WARNING, "MQRC_CHANNEL_BLOCKED_WARNING" },
/* 2579*/ { MQ_MQRC_SUBSCRIPTION_CREATE, "MQRC_SUBSCRIPTION_CREATE" },
/* 2580*/ { MQ_MQRC_SUBSCRIPTION_DELETE, "MQRC_SUBSCRIPTION_DELETE" },
/* 2581*/ { MQ_MQRC_SUBSCRIPTION_CHANGE, "MQRC_SUBSCRIPTION_CHANGE" },
/* 2582*/ { MQ_MQRC_SUBSCRIPTION_REFRESH, "MQRC_SUBSCRIPTION_REFRESH" },
/* 2583*/ { MQ_MQRC_INSTALLATION_MISMATCH, "MQRC_INSTALLATION_MISMATCH" },
/* 2584*/ { MQ_MQRC_NOT_PRIVILEGED, "MQRC_NOT_PRIVILEGED" },
/* 2586*/ { MQ_MQRC_PROPERTIES_DISABLED, "MQRC_PROPERTIES_DISABLED" },
/* 2587*/ { MQ_MQRC_HMSG_NOT_AVAILABLE, "MQRC_HMSG_NOT_AVAILABLE" },
/* 2588*/ { MQ_MQRC_EXIT_PROPS_NOT_SUPPORTED, "MQRC_EXIT_PROPS_NOT_SUPPORTED" },
/* 2589*/ { MQ_MQRC_INSTALLATION_MISSING, "MQRC_INSTALLATION_MISSING" },
/* 2590*/ { MQ_MQRC_FASTPATH_NOT_AVAILABLE, "MQRC_FASTPATH_NOT_AVAILABLE" },
/* 2591*/ { MQ_MQRC_CIPHER_SPEC_NOT_SUITE_B, "MQRC_CIPHER_SPEC_NOT_SUITE_B" },
/* 2592*/ { MQ_MQRC_SUITE_B_ERROR, "MQRC_SUITE_B_ERROR" },
/* 2593*/ { MQ_MQRC_CERT_VAL_POLICY_ERROR, "MQRC_CERT_VAL_POLICY_ERROR" },
/* 2594*/ { MQ_MQRC_PASSWORD_PROTECTION_ERROR, "MQRC_PASSWORD_PROTECTION_ERROR" },
/* 2595*/ { MQ_MQRC_CSP_ERROR, "MQRC_CSP_ERROR" },
/* 2596*/ { MQ_MQRC_CERT_LABEL_NOT_ALLOWED, "MQRC_CERT_LABEL_NOT_ALLOWED" },
/* 2598*/ { MQ_MQRC_ADMIN_TOPIC_STRING_ERROR, "MQRC_ADMIN_TOPIC_STRING_ERROR" },
/* 2599*/ { MQ_MQRC_AMQP_NOT_AVAILABLE, "MQRC_AMQP_NOT_AVAILABLE" },
/* 2600*/ { MQ_MQRC_CCDT_URL_ERROR, "MQRC_CCDT_URL_ERROR" },
/* 3001*/ { MQ_MQRCCF_CFH_TYPE_ERROR, "MQRCCF_CFH_TYPE_ERROR" },
/* 3002*/ { MQ_MQRCCF_CFH_LENGTH_ERROR, "MQRCCF_CFH_LENGTH_ERROR" },
/* 3003*/ { MQ_MQRCCF_CFH_VERSION_ERROR, "MQRCCF_CFH_VERSION_ERROR" },
/* 3004*/ { MQ_MQRCCF_CFH_MSG_SEQ_NUMBER_ERR, "MQRCCF_CFH_MSG_SEQ_NUMBER_ERR" },
/* 3005*/ { MQ_MQRCCF_CFH_CONTROL_ERROR, "MQRCCF_CFH_CONTROL_ERROR" },
/* 3006*/ { MQ_MQRCCF_CFH_PARM_COUNT_ERROR, "MQRCCF_CFH_PARM_COUNT_ERROR" },
/* 3007*/ { MQ_MQRCCF_CFH_COMMAND_ERROR, "MQRCCF_CFH_COMMAND_ERROR" },
/* 3008*/ { MQ_MQRCCF_COMMAND_FAILED, "MQRCCF_COMMAND_FAILED" },
/* 3009*/ { MQ_MQRCCF_CFIN_LENGTH_ERROR, "MQRCCF_CFIN_LENGTH_ERROR" },
/* 3010*/ { MQ_MQRCCF_CFST_LENGTH_ERROR, "MQRCCF_CFST_LENGTH_ERROR" },
/* 3011*/ { MQ_MQRCCF_CFST_STRING_LENGTH_ERR, "MQRCCF_CFST_STRING_LENGTH_ERR" },
/* 3012*/ { MQ_MQRCCF_FORCE_VALUE_ERROR, "MQRCCF_FORCE_VALUE_ERROR" },
/* 3013*/ { MQ_MQRCCF_STRUCTURE_TYPE_ERROR, "MQRCCF_STRUCTURE_TYPE_ERROR" },
/* 3014*/ { MQ_MQRCCF_CFIN_PARM_ID_ERROR, "MQRCCF_CFIN_PARM_ID_ERROR" },
/* 3015*/ { MQ_MQRCCF_CFST_PARM_ID_ERROR, "MQRCCF_CFST_PARM_ID_ERROR" },
/* 3016*/ { MQ_MQRCCF_MSG_LENGTH_ERROR, "MQRCCF_MSG_LENGTH_ERROR" },
/* 3017*/ { MQ_MQRCCF_CFIN_DUPLICATE_PARM, "MQRCCF_CFIN_DUPLICATE_PARM" },
/* 3018*/ { MQ_MQRCCF_CFST_DUPLICATE_PARM, "MQRCCF_CFST_DUPLICATE_PARM" },
/* 3019*/ { MQ_MQRCCF_PARM_COUNT_TOO_SMALL, "MQRCCF_PARM_COUNT_TOO_SMALL" },
/* 3020*/ { MQ_MQRCCF_PARM_COUNT_TOO_BIG, "MQRCCF_PARM_COUNT_TOO_BIG" },
/* 3021*/ { MQ_MQRCCF_Q_ALREADY_IN_CELL, "MQRCCF_Q_ALREADY_IN_CELL" },
/* 3022*/ { MQ_MQRCCF_Q_TYPE_ERROR, "MQRCCF_Q_TYPE_ERROR" },
/* 3023*/ { MQ_MQRCCF_MD_FORMAT_ERROR, "MQRCCF_MD_FORMAT_ERROR" },
/* 3024*/ { MQ_MQRCCF_CFSL_LENGTH_ERROR, "MQRCCF_CFSL_LENGTH_ERROR" },
/* 3025*/ { MQ_MQRCCF_REPLACE_VALUE_ERROR, "MQRCCF_REPLACE_VALUE_ERROR" },
/* 3026*/ { MQ_MQRCCF_CFIL_DUPLICATE_VALUE, "MQRCCF_CFIL_DUPLICATE_VALUE" },
/* 3027*/ { MQ_MQRCCF_CFIL_COUNT_ERROR, "MQRCCF_CFIL_COUNT_ERROR" },
/* 3028*/ { MQ_MQRCCF_CFIL_LENGTH_ERROR, "MQRCCF_CFIL_LENGTH_ERROR" },
/* 3029*/ { MQ_MQRCCF_QUIESCE_VALUE_ERROR, "MQRCCF_QUIESCE_VALUE_ERROR" },
/* 3029   { MQ_MQRCCF_MODE_VALUE_ERROR, "MQRCCF_MODE_VALUE_ERROR" }, */
/* 3030*/ { MQ_MQRCCF_MSG_SEQ_NUMBER_ERROR, "MQRCCF_MSG_SEQ_NUMBER_ERROR" },
/* 3031*/ { MQ_MQRCCF_PING_DATA_COUNT_ERROR, "MQRCCF_PING_DATA_COUNT_ERROR" },
/* 3032*/ { MQ_MQRCCF_PING_DATA_COMPARE_ERROR, "MQRCCF_PING_DATA_COMPARE_ERROR" },
/* 3033*/ { MQ_MQRCCF_CFSL_PARM_ID_ERROR, "MQRCCF_CFSL_PARM_ID_ERROR" },
/* 3034*/ { MQ_MQRCCF_CHANNEL_TYPE_ERROR, "MQRCCF_CHANNEL_TYPE_ERROR" },
/* 3035*/ { MQ_MQRCCF_PARM_SEQUENCE_ERROR, "MQRCCF_PARM_SEQUENCE_ERROR" },
/* 3036*/ { MQ_MQRCCF_XMIT_PROTOCOL_TYPE_ERR, "MQRCCF_XMIT_PROTOCOL_TYPE_ERR" },
/* 3037*/ { MQ_MQRCCF_BATCH_SIZE_ERROR, "MQRCCF_BATCH_SIZE_ERROR" },
/* 3038*/ { MQ_MQRCCF_DISC_INT_ERROR, "MQRCCF_DISC_INT_ERROR" },
/* 3039*/ { MQ_MQRCCF_SHORT_RETRY_ERROR, "MQRCCF_SHORT_RETRY_ERROR" },
/* 3040*/ { MQ_MQRCCF_SHORT_TIMER_ERROR, "MQRCCF_SHORT_TIMER_ERROR" },
/* 3041*/ { MQ_MQRCCF_LONG_RETRY_ERROR, "MQRCCF_LONG_RETRY_ERROR" },
/* 3042*/ { MQ_MQRCCF_LONG_TIMER_ERROR, "MQRCCF_LONG_TIMER_ERROR" },
/* 3043*/ { MQ_MQRCCF_SEQ_NUMBER_WRAP_ERROR, "MQRCCF_SEQ_NUMBER_WRAP_ERROR" },
/* 3044*/ { MQ_MQRCCF_MAX_MSG_LENGTH_ERROR, "MQRCCF_MAX_MSG_LENGTH_ERROR" },
/* 3045*/ { MQ_MQRCCF_PUT_AUTH_ERROR, "MQRCCF_PUT_AUTH_ERROR" },
/* 3046*/ { MQ_MQRCCF_PURGE_VALUE_ERROR, "MQRCCF_PURGE_VALUE_ERROR" },
/* 3047*/ { MQ_MQRCCF_CFIL_PARM_ID_ERROR, "MQRCCF_CFIL_PARM_ID_ERROR" },
/* 3048*/ { MQ_MQRCCF_MSG_TRUNCATED, "MQRCCF_MSG_TRUNCATED" },
/* 3049*/ { MQ_MQRCCF_CCSID_ERROR, "MQRCCF_CCSID_ERROR" },
/* 3050*/ { MQ_MQRCCF_ENCODING_ERROR, "MQRCCF_ENCODING_ERROR" },
/* 3051*/ { MQ_MQRCCF_QUEUES_VALUE_ERROR, "MQRCCF_QUEUES_VALUE_ERROR" },
/* 3052*/ { MQ_MQRCCF_DATA_CONV_VALUE_ERROR, "MQRCCF_DATA_CONV_VALUE_ERROR" },
/* 3053*/ { MQ_MQRCCF_INDOUBT_VALUE_ERROR, "MQRCCF_INDOUBT_VALUE_ERROR" },
/* 3054*/ { MQ_MQRCCF_ESCAPE_TYPE_ERROR, "MQRCCF_ESCAPE_TYPE_ERROR" },
/* 3055*/ { MQ_MQRCCF_REPOS_VALUE_ERROR, "MQRCCF_REPOS_VALUE_ERROR" },
/* 3062*/ { MQ_MQRCCF_CHANNEL_TABLE_ERROR, "MQRCCF_CHANNEL_TABLE_ERROR" },
/* 3063*/ { MQ_MQRCCF_MCA_TYPE_ERROR, "MQRCCF_MCA_TYPE_ERROR" },
/* 3064*/ { MQ_MQRCCF_CHL_INST_TYPE_ERROR, "MQRCCF_CHL_INST_TYPE_ERROR" },
/* 3065*/ { MQ_MQRCCF_CHL_STATUS_NOT_FOUND, "MQRCCF_CHL_STATUS_NOT_FOUND" },
/* 3066*/ { MQ_MQRCCF_CFSL_DUPLICATE_PARM, "MQRCCF_CFSL_DUPLICATE_PARM" },
/* 3067*/ { MQ_MQRCCF_CFSL_TOTAL_LENGTH_ERROR, "MQRCCF_CFSL_TOTAL_LENGTH_ERROR" },
/* 3068*/ { MQ_MQRCCF_CFSL_COUNT_ERROR, "MQRCCF_CFSL_COUNT_ERROR" },
/* 3069*/ { MQ_MQRCCF_CFSL_STRING_LENGTH_ERR, "MQRCCF_CFSL_STRING_LENGTH_ERR" },
/* 3070*/ { MQ_MQRCCF_BROKER_DELETED, "MQRCCF_BROKER_DELETED" },
/* 3071*/ { MQ_MQRCCF_STREAM_ERROR, "MQRCCF_STREAM_ERROR" },
/* 3072*/ { MQ_MQRCCF_TOPIC_ERROR, "MQRCCF_TOPIC_ERROR" },
/* 3073*/ { MQ_MQRCCF_NOT_REGISTERED, "MQRCCF_NOT_REGISTERED" },
/* 3074*/ { MQ_MQRCCF_Q_MGR_NAME_ERROR, "MQRCCF_Q_MGR_NAME_ERROR" },
/* 3075*/ { MQ_MQRCCF_INCORRECT_STREAM, "MQRCCF_INCORRECT_STREAM" },
/* 3076*/ { MQ_MQRCCF_Q_NAME_ERROR, "MQRCCF_Q_NAME_ERROR" },
/* 3077*/ { MQ_MQRCCF_NO_RETAINED_MSG, "MQRCCF_NO_RETAINED_MSG" },
/* 3078*/ { MQ_MQRCCF_DUPLICATE_IDENTITY, "MQRCCF_DUPLICATE_IDENTITY" },
/* 3079*/ { MQ_MQRCCF_INCORRECT_Q, "MQRCCF_INCORRECT_Q" },
/* 3080*/ { MQ_MQRCCF_CORREL_ID_ERROR, "MQRCCF_CORREL_ID_ERROR" },
/* 3081*/ { MQ_MQRCCF_NOT_AUTHORIZED, "MQRCCF_NOT_AUTHORIZED" },
/* 3082*/ { MQ_MQRCCF_UNKNOWN_STREAM, "MQRCCF_UNKNOWN_STREAM" },
/* 3083*/ { MQ_MQRCCF_REG_OPTIONS_ERROR, "MQRCCF_REG_OPTIONS_ERROR" },
/* 3084*/ { MQ_MQRCCF_PUB_OPTIONS_ERROR, "MQRCCF_PUB_OPTIONS_ERROR" },
/* 3085*/ { MQ_MQRCCF_UNKNOWN_BROKER, "MQRCCF_UNKNOWN_BROKER" },
/* 3086*/ { MQ_MQRCCF_Q_MGR_CCSID_ERROR, "MQRCCF_Q_MGR_CCSID_ERROR" },
/* 3087*/ { MQ_MQRCCF_DEL_OPTIONS_ERROR, "MQRCCF_DEL_OPTIONS_ERROR" },
/* 3088*/ { MQ_MQRCCF_CLUSTER_NAME_CONFLICT, "MQRCCF_CLUSTER_NAME_CONFLICT" },
/* 3089*/ { MQ_MQRCCF_REPOS_NAME_CONFLICT, "MQRCCF_REPOS_NAME_CONFLICT" },
/* 3090*/ { MQ_MQRCCF_CLUSTER_Q_USAGE_ERROR, "MQRCCF_CLUSTER_Q_USAGE_ERROR" },
/* 3091*/ { MQ_MQRCCF_ACTION_VALUE_ERROR, "MQRCCF_ACTION_VALUE_ERROR" },
/* 3092*/ { MQ_MQRCCF_COMMS_LIBRARY_ERROR, "MQRCCF_COMMS_LIBRARY_ERROR" },
/* 3093*/ { MQ_MQRCCF_NETBIOS_NAME_ERROR, "MQRCCF_NETBIOS_NAME_ERROR" },
/* 3094*/ { MQ_MQRCCF_BROKER_COMMAND_FAILED, "MQRCCF_BROKER_COMMAND_FAILED" },
/* 3095*/ { MQ_MQRCCF_CFST_CONFLICTING_PARM, "MQRCCF_CFST_CONFLICTING_PARM" },
/* 3096*/ { MQ_MQRCCF_PATH_NOT_VALID, "MQRCCF_PATH_NOT_VALID" },
/* 3097*/ { MQ_MQRCCF_PARM_SYNTAX_ERROR, "MQRCCF_PARM_SYNTAX_ERROR" },
/* 3098*/ { MQ_MQRCCF_PWD_LENGTH_ERROR, "MQRCCF_PWD_LENGTH_ERROR" },
/* 3150*/ { MQ_MQRCCF_FILTER_ERROR, "MQRCCF_FILTER_ERROR" },
/* 3151*/ { MQ_MQRCCF_WRONG_USER, "MQRCCF_WRONG_USER" },
/* 3152*/ { MQ_MQRCCF_DUPLICATE_SUBSCRIPTION, "MQRCCF_DUPLICATE_SUBSCRIPTION" },
/* 3153*/ { MQ_MQRCCF_SUB_NAME_ERROR, "MQRCCF_SUB_NAME_ERROR" },
/* 3154*/ { MQ_MQRCCF_SUB_IDENTITY_ERROR, "MQRCCF_SUB_IDENTITY_ERROR" },
/* 3155*/ { MQ_MQRCCF_SUBSCRIPTION_IN_USE, "MQRCCF_SUBSCRIPTION_IN_USE" },
/* 3156*/ { MQ_MQRCCF_SUBSCRIPTION_LOCKED, "MQRCCF_SUBSCRIPTION_LOCKED" },
/* 3157*/ { MQ_MQRCCF_ALREADY_JOINED, "MQRCCF_ALREADY_JOINED" },
/* 3160*/ { MQ_MQRCCF_OBJECT_IN_USE, "MQRCCF_OBJECT_IN_USE" },
/* 3161*/ { MQ_MQRCCF_UNKNOWN_FILE_NAME, "MQRCCF_UNKNOWN_FILE_NAME" },
/* 3162*/ { MQ_MQRCCF_FILE_NOT_AVAILABLE, "MQRCCF_FILE_NOT_AVAILABLE" },
/* 3163*/ { MQ_MQRCCF_DISC_RETRY_ERROR, "MQRCCF_DISC_RETRY_ERROR" },
/* 3164*/ { MQ_MQRCCF_ALLOC_RETRY_ERROR, "MQRCCF_ALLOC_RETRY_ERROR" },
/* 3165*/ { MQ_MQRCCF_ALLOC_SLOW_TIMER_ERROR, "MQRCCF_ALLOC_SLOW_TIMER_ERROR" },
/* 3166*/ { MQ_MQRCCF_ALLOC_FAST_TIMER_ERROR, "MQRCCF_ALLOC_FAST_TIMER_ERROR" },
/* 3167*/ { MQ_MQRCCF_PORT_NUMBER_ERROR, "MQRCCF_PORT_NUMBER_ERROR" },
/* 3168*/ { MQ_MQRCCF_CHL_SYSTEM_NOT_ACTIVE, "MQRCCF_CHL_SYSTEM_NOT_ACTIVE" },
/* 3169*/ { MQ_MQRCCF_ENTITY_NAME_MISSING, "MQRCCF_ENTITY_NAME_MISSING" },
/* 3170*/ { MQ_MQRCCF_PROFILE_NAME_ERROR, "MQRCCF_PROFILE_NAME_ERROR" },
/* 3171*/ { MQ_MQRCCF_AUTH_VALUE_ERROR, "MQRCCF_AUTH_VALUE_ERROR" },
/* 3172*/ { MQ_MQRCCF_AUTH_VALUE_MISSING, "MQRCCF_AUTH_VALUE_MISSING" },
/* 3173*/ { MQ_MQRCCF_OBJECT_TYPE_MISSING, "MQRCCF_OBJECT_TYPE_MISSING" },
/* 3174*/ { MQ_MQRCCF_CONNECTION_ID_ERROR, "MQRCCF_CONNECTION_ID_ERROR" },
/* 3175*/ { MQ_MQRCCF_LOG_TYPE_ERROR, "MQRCCF_LOG_TYPE_ERROR" },
/* 3176*/ { MQ_MQRCCF_PROGRAM_NOT_AVAILABLE, "MQRCCF_PROGRAM_NOT_AVAILABLE" },
/* 3177*/ { MQ_MQRCCF_PROGRAM_AUTH_FAILED, "MQRCCF_PROGRAM_AUTH_FAILED" },
/* 3200*/ { MQ_MQRCCF_NONE_FOUND, "MQRCCF_NONE_FOUND" },
/* 3201*/ { MQ_MQRCCF_SECURITY_SWITCH_OFF, "MQRCCF_SECURITY_SWITCH_OFF" },
/* 3202*/ { MQ_MQRCCF_SECURITY_REFRESH_FAILED, "MQRCCF_SECURITY_REFRESH_FAILED" },
/* 3203*/ { MQ_MQRCCF_PARM_CONFLICT, "MQRCCF_PARM_CONFLICT" },
/* 3204*/ { MQ_MQRCCF_COMMAND_INHIBITED, "MQRCCF_COMMAND_INHIBITED" },
/* 3205*/ { MQ_MQRCCF_OBJECT_BEING_DELETED, "MQRCCF_OBJECT_BEING_DELETED" },
/* 3207*/ { MQ_MQRCCF_STORAGE_CLASS_IN_USE, "MQRCCF_STORAGE_CLASS_IN_USE" },
/* 3208*/ { MQ_MQRCCF_OBJECT_NAME_RESTRICTED, "MQRCCF_OBJECT_NAME_RESTRICTED" },
/* 3209*/ { MQ_MQRCCF_OBJECT_LIMIT_EXCEEDED, "MQRCCF_OBJECT_LIMIT_EXCEEDED" },
/* 3210*/ { MQ_MQRCCF_OBJECT_OPEN_FORCE, "MQRCCF_OBJECT_OPEN_FORCE" },
/* 3211*/ { MQ_MQRCCF_DISPOSITION_CONFLICT, "MQRCCF_DISPOSITION_CONFLICT" },
/* 3212*/ { MQ_MQRCCF_Q_MGR_NOT_IN_QSG, "MQRCCF_Q_MGR_NOT_IN_QSG" },
/* 3213*/ { MQ_MQRCCF_ATTR_VALUE_FIXED, "MQRCCF_ATTR_VALUE_FIXED" },
/* 3215*/ { MQ_MQRCCF_NAMELIST_ERROR, "MQRCCF_NAMELIST_ERROR" },
/* 3217*/ { MQ_MQRCCF_NO_CHANNEL_INITIATOR, "MQRCCF_NO_CHANNEL_INITIATOR" },
/* 3218*/ { MQ_MQRCCF_CHANNEL_INITIATOR_ERROR, "MQRCCF_CHANNEL_INITIATOR_ERROR" },
/* 3222*/ { MQ_MQRCCF_COMMAND_LEVEL_CONFLICT, "MQRCCF_COMMAND_LEVEL_CONFLICT" },
/* 3223*/ { MQ_MQRCCF_Q_ATTR_CONFLICT, "MQRCCF_Q_ATTR_CONFLICT" },
/* 3224*/ { MQ_MQRCCF_EVENTS_DISABLED, "MQRCCF_EVENTS_DISABLED" },
/* 3225*/ { MQ_MQRCCF_COMMAND_SCOPE_ERROR, "MQRCCF_COMMAND_SCOPE_ERROR" },
/* 3226*/ { MQ_MQRCCF_COMMAND_REPLY_ERROR, "MQRCCF_COMMAND_REPLY_ERROR" },
/* 3227*/ { MQ_MQRCCF_FUNCTION_RESTRICTED, "MQRCCF_FUNCTION_RESTRICTED" },
/* 3228*/ { MQ_MQRCCF_PARM_MISSING, "MQRCCF_PARM_MISSING" },
/* 3229*/ { MQ_MQRCCF_PARM_VALUE_ERROR, "MQRCCF_PARM_VALUE_ERROR" },
/* 3230*/ { MQ_MQRCCF_COMMAND_LENGTH_ERROR, "MQRCCF_COMMAND_LENGTH_ERROR" },
/* 3231*/ { MQ_MQRCCF_COMMAND_ORIGIN_ERROR, "MQRCCF_COMMAND_ORIGIN_ERROR" },
/* 3232*/ { MQ_MQRCCF_LISTENER_CONFLICT, "MQRCCF_LISTENER_CONFLICT" },
/* 3233*/ { MQ_MQRCCF_LISTENER_STARTED, "MQRCCF_LISTENER_STARTED" },
/* 3234*/ { MQ_MQRCCF_LISTENER_STOPPED, "MQRCCF_LISTENER_STOPPED" },
/* 3235*/ { MQ_MQRCCF_CHANNEL_ERROR, "MQRCCF_CHANNEL_ERROR" },
/* 3236*/ { MQ_MQRCCF_CF_STRUC_ERROR, "MQRCCF_CF_STRUC_ERROR" },
/* 3237*/ { MQ_MQRCCF_UNKNOWN_USER_ID, "MQRCCF_UNKNOWN_USER_ID" },
/* 3238*/ { MQ_MQRCCF_UNEXPECTED_ERROR, "MQRCCF_UNEXPECTED_ERROR" },
/* 3239*/ { MQ_MQRCCF_NO_XCF_PARTNER, "MQRCCF_NO_XCF_PARTNER" },
/* 3240*/ { MQ_MQRCCF_CFGR_PARM_ID_ERROR, "MQRCCF_CFGR_PARM_ID_ERROR" },
/* 3241*/ { MQ_MQRCCF_CFIF_LENGTH_ERROR, "MQRCCF_CFIF_LENGTH_ERROR" },
/* 3242*/ { MQ_MQRCCF_CFIF_OPERATOR_ERROR, "MQRCCF_CFIF_OPERATOR_ERROR" },
/* 3243*/ { MQ_MQRCCF_CFIF_PARM_ID_ERROR, "MQRCCF_CFIF_PARM_ID_ERROR" },
/* 3244*/ { MQ_MQRCCF_CFSF_FILTER_VAL_LEN_ERR, "MQRCCF_CFSF_FILTER_VAL_LEN_ERR" },
/* 3245*/ { MQ_MQRCCF_CFSF_LENGTH_ERROR, "MQRCCF_CFSF_LENGTH_ERROR" },
/* 3246*/ { MQ_MQRCCF_CFSF_OPERATOR_ERROR, "MQRCCF_CFSF_OPERATOR_ERROR" },
/* 3247*/ { MQ_MQRCCF_CFSF_PARM_ID_ERROR, "MQRCCF_CFSF_PARM_ID_ERROR" },
/* 3248*/ { MQ_MQRCCF_TOO_MANY_FILTERS, "MQRCCF_TOO_MANY_FILTERS" },
/* 3249*/ { MQ_MQRCCF_LISTENER_RUNNING, "MQRCCF_LISTENER_RUNNING" },
/* 3250*/ { MQ_MQRCCF_LSTR_STATUS_NOT_FOUND, "MQRCCF_LSTR_STATUS_NOT_FOUND" },
/* 3251*/ { MQ_MQRCCF_SERVICE_RUNNING, "MQRCCF_SERVICE_RUNNING" },
/* 3252*/ { MQ_MQRCCF_SERV_STATUS_NOT_FOUND, "MQRCCF_SERV_STATUS_NOT_FOUND" },
/* 3253*/ { MQ_MQRCCF_SERVICE_STOPPED, "MQRCCF_SERVICE_STOPPED" },
/* 3254*/ { MQ_MQRCCF_CFBS_DUPLICATE_PARM, "MQRCCF_CFBS_DUPLICATE_PARM" },
/* 3255*/ { MQ_MQRCCF_CFBS_LENGTH_ERROR, "MQRCCF_CFBS_LENGTH_ERROR" },
/* 3256*/ { MQ_MQRCCF_CFBS_PARM_ID_ERROR, "MQRCCF_CFBS_PARM_ID_ERROR" },
/* 3257*/ { MQ_MQRCCF_CFBS_STRING_LENGTH_ERR, "MQRCCF_CFBS_STRING_LENGTH_ERR" },
/* 3258*/ { MQ_MQRCCF_CFGR_LENGTH_ERROR, "MQRCCF_CFGR_LENGTH_ERROR" },
/* 3259*/ { MQ_MQRCCF_CFGR_PARM_COUNT_ERROR, "MQRCCF_CFGR_PARM_COUNT_ERROR" },
/* 3260*/ { MQ_MQRCCF_CONN_NOT_STOPPED, "MQRCCF_CONN_NOT_STOPPED" },
/* 3261*/ { MQ_MQRCCF_SERVICE_REQUEST_PENDING, "MQRCCF_SERVICE_REQUEST_PENDING" },
/* 3262*/ { MQ_MQRCCF_NO_START_CMD, "MQRCCF_NO_START_CMD" },
/* 3263*/ { MQ_MQRCCF_NO_STOP_CMD, "MQRCCF_NO_STOP_CMD" },
/* 3264*/ { MQ_MQRCCF_CFBF_LENGTH_ERROR, "MQRCCF_CFBF_LENGTH_ERROR" },
/* 3265*/ { MQ_MQRCCF_CFBF_PARM_ID_ERROR, "MQRCCF_CFBF_PARM_ID_ERROR" },
/* 3266*/ { MQ_MQRCCF_CFBF_OPERATOR_ERROR, "MQRCCF_CFBF_OPERATOR_ERROR" },
/* 3267*/ { MQ_MQRCCF_CFBF_FILTER_VAL_LEN_ERR, "MQRCCF_CFBF_FILTER_VAL_LEN_ERR" },
/* 3268*/ { MQ_MQRCCF_LISTENER_STILL_ACTIVE, "MQRCCF_LISTENER_STILL_ACTIVE" },
/* 3269*/ { MQ_MQRCCF_DEF_XMIT_Q_CLUS_ERROR, "MQRCCF_DEF_XMIT_Q_CLUS_ERROR" },
/* 3300*/ { MQ_MQRCCF_TOPICSTR_ALREADY_EXISTS, "MQRCCF_TOPICSTR_ALREADY_EXISTS" },
/* 3301*/ { MQ_MQRCCF_SHARING_CONVS_ERROR, "MQRCCF_SHARING_CONVS_ERROR" },
/* 3302*/ { MQ_MQRCCF_SHARING_CONVS_TYPE, "MQRCCF_SHARING_CONVS_TYPE" },
/* 3303*/ { MQ_MQRCCF_SECURITY_CASE_CONFLICT, "MQRCCF_SECURITY_CASE_CONFLICT" },
/* 3305*/ { MQ_MQRCCF_TOPIC_TYPE_ERROR, "MQRCCF_TOPIC_TYPE_ERROR" },
/* 3306*/ { MQ_MQRCCF_MAX_INSTANCES_ERROR, "MQRCCF_MAX_INSTANCES_ERROR" },
/* 3307*/ { MQ_MQRCCF_MAX_INSTS_PER_CLNT_ERR, "MQRCCF_MAX_INSTS_PER_CLNT_ERR" },
/* 3308*/ { MQ_MQRCCF_TOPIC_STRING_NOT_FOUND, "MQRCCF_TOPIC_STRING_NOT_FOUND" },
/* 3309*/ { MQ_MQRCCF_SUBSCRIPTION_POINT_ERR, "MQRCCF_SUBSCRIPTION_POINT_ERR" },
/* 3311*/ { MQ_MQRCCF_SUB_ALREADY_EXISTS, "MQRCCF_SUB_ALREADY_EXISTS" },
/* 3312*/ { MQ_MQRCCF_UNKNOWN_OBJECT_NAME, "MQRCCF_UNKNOWN_OBJECT_NAME" },
/* 3313*/ { MQ_MQRCCF_REMOTE_Q_NAME_ERROR, "MQRCCF_REMOTE_Q_NAME_ERROR" },
/* 3314*/ { MQ_MQRCCF_DURABILITY_NOT_ALLOWED, "MQRCCF_DURABILITY_NOT_ALLOWED" },
/* 3315*/ { MQ_MQRCCF_HOBJ_ERROR, "MQRCCF_HOBJ_ERROR" },
/* 3316*/ { MQ_MQRCCF_DEST_NAME_ERROR, "MQRCCF_DEST_NAME_ERROR" },
/* 3317*/ { MQ_MQRCCF_INVALID_DESTINATION, "MQRCCF_INVALID_DESTINATION" },
/* 3318*/ { MQ_MQRCCF_PUBSUB_INHIBITED, "MQRCCF_PUBSUB_INHIBITED" },
/* 3319*/ { MQ_MQRCCF_GROUPUR_CHECKS_FAILED, "MQRCCF_GROUPUR_CHECKS_FAILED" },
/* 3320*/ { MQ_MQRCCF_COMM_INFO_TYPE_ERROR, "MQRCCF_COMM_INFO_TYPE_ERROR" },
/* 3321*/ { MQ_MQRCCF_USE_CLIENT_ID_ERROR, "MQRCCF_USE_CLIENT_ID_ERROR" },
/* 3322*/ { MQ_MQRCCF_CLIENT_ID_NOT_FOUND, "MQRCCF_CLIENT_ID_NOT_FOUND" },
/* 3323*/ { MQ_MQRCCF_CLIENT_ID_ERROR, "MQRCCF_CLIENT_ID_ERROR" },
/* 3324*/ { MQ_MQRCCF_PORT_IN_USE, "MQRCCF_PORT_IN_USE" },
/* 3325*/ { MQ_MQRCCF_SSL_ALT_PROVIDER_REQD, "MQRCCF_SSL_ALT_PROVIDER_REQD" },
/* 3326*/ { MQ_MQRCCF_CHLAUTH_TYPE_ERROR, "MQRCCF_CHLAUTH_TYPE_ERROR" },
/* 3327*/ { MQ_MQRCCF_CHLAUTH_ACTION_ERROR, "MQRCCF_CHLAUTH_ACTION_ERROR" },
/* 3328*/ { MQ_MQRCCF_POLICY_NOT_FOUND, "MQRCCF_POLICY_NOT_FOUND" },
/* 3329*/ { MQ_MQRCCF_ENCRYPTION_ALG_ERROR, "MQRCCF_ENCRYPTION_ALG_ERROR" },
/* 3330*/ { MQ_MQRCCF_SIGNATURE_ALG_ERROR, "MQRCCF_SIGNATURE_ALG_ERROR" },
/* 3331*/ { MQ_MQRCCF_TOLERATION_POL_ERROR, "MQRCCF_TOLERATION_POL_ERROR" },
/* 3332*/ { MQ_MQRCCF_POLICY_VERSION_ERROR, "MQRCCF_POLICY_VERSION_ERROR" },
/* 3333*/ { MQ_MQRCCF_RECIPIENT_DN_MISSING, "MQRCCF_RECIPIENT_DN_MISSING" },
/* 3334*/ { MQ_MQRCCF_POLICY_NAME_MISSING, "MQRCCF_POLICY_NAME_MISSING" },
/* 3335*/ { MQ_MQRCCF_CHLAUTH_USERSRC_ERROR, "MQRCCF_CHLAUTH_USERSRC_ERROR" },
/* 3336*/ { MQ_MQRCCF_WRONG_CHLAUTH_TYPE, "MQRCCF_WRONG_CHLAUTH_TYPE" },
/* 3337*/ { MQ_MQRCCF_CHLAUTH_ALREADY_EXISTS, "MQRCCF_CHLAUTH_ALREADY_EXISTS" },
/* 3338*/ { MQ_MQRCCF_CHLAUTH_NOT_FOUND, "MQRCCF_CHLAUTH_NOT_FOUND" },
/* 3339*/ { MQ_MQRCCF_WRONG_CHLAUTH_ACTION, "MQRCCF_WRONG_CHLAUTH_ACTION" },
/* 3340*/ { MQ_MQRCCF_WRONG_CHLAUTH_USERSRC, "MQRCCF_WRONG_CHLAUTH_USERSRC" },
/* 3341*/ { MQ_MQRCCF_CHLAUTH_WARN_ERROR, "MQRCCF_CHLAUTH_WARN_ERROR" },
/* 3342*/ { MQ_MQRCCF_WRONG_CHLAUTH_MATCH, "MQRCCF_WRONG_CHLAUTH_MATCH" },
/* 3343*/ { MQ_MQRCCF_IPADDR_RANGE_CONFLICT, "MQRCCF_IPADDR_RANGE_CONFLICT" },
/* 3344*/ { MQ_MQRCCF_CHLAUTH_MAX_EXCEEDED, "MQRCCF_CHLAUTH_MAX_EXCEEDED" },
/* 3345   { MQ_MQRCCF_IPADDR_ERROR, "MQRCCF_IPADDR_ERROR" }, */
/* 3345*/ { MQ_MQRCCF_ADDRESS_ERROR, "MQRCCF_ADDRESS_ERROR" },
/* 3346*/ { MQ_MQRCCF_IPADDR_RANGE_ERROR, "MQRCCF_IPADDR_RANGE_ERROR" },
/* 3347*/ { MQ_MQRCCF_PROFILE_NAME_MISSING, "MQRCCF_PROFILE_NAME_MISSING" },
/* 3348*/ { MQ_MQRCCF_CHLAUTH_CLNTUSER_ERROR, "MQRCCF_CHLAUTH_CLNTUSER_ERROR" },
/* 3349*/ { MQ_MQRCCF_CHLAUTH_NAME_ERROR, "MQRCCF_CHLAUTH_NAME_ERROR" },
/* 3350*/ { MQ_MQRCCF_CHLAUTH_RUNCHECK_ERROR, "MQRCCF_CHLAUTH_RUNCHECK_ERROR" },
/* 3351*/ { MQ_MQRCCF_CF_STRUC_ALREADY_FAILED, "MQRCCF_CF_STRUC_ALREADY_FAILED" },
/* 3352*/ { MQ_MQRCCF_CFCONLOS_CHECKS_FAILED, "MQRCCF_CFCONLOS_CHECKS_FAILED" },
/* 3353*/ { MQ_MQRCCF_SUITE_B_ERROR, "MQRCCF_SUITE_B_ERROR" },
/* 3354*/ { MQ_MQRCCF_CHANNEL_NOT_STARTED, "MQRCCF_CHANNEL_NOT_STARTED" },
/* 3355*/ { MQ_MQRCCF_CUSTOM_ERROR, "MQRCCF_CUSTOM_ERROR" },
/* 3356*/ { MQ_MQRCCF_BACKLOG_OUT_OF_RANGE, "MQRCCF_BACKLOG_OUT_OF_RANGE" },
/* 3357*/ { MQ_MQRCCF_CHLAUTH_DISABLED, "MQRCCF_CHLAUTH_DISABLED" },
/* 3358*/ { MQ_MQRCCF_SMDS_REQUIRES_DSGROUP, "MQRCCF_SMDS_REQUIRES_DSGROUP" },
/* 3359*/ { MQ_MQRCCF_PSCLUS_DISABLED_TOPDEF, "MQRCCF_PSCLUS_DISABLED_TOPDEF" },
/* 3360*/ { MQ_MQRCCF_PSCLUS_TOPIC_EXISTS, "MQRCCF_PSCLUS_TOPIC_EXISTS" },
/* 3361*/ { MQ_MQRCCF_SSL_CIPHER_SUITE_ERROR, "MQRCCF_SSL_CIPHER_SUITE_ERROR" },
/* 3362*/ { MQ_MQRCCF_SOCKET_ERROR, "MQRCCF_SOCKET_ERROR" },
/* 3363*/ { MQ_MQRCCF_CLUS_XMIT_Q_USAGE_ERROR, "MQRCCF_CLUS_XMIT_Q_USAGE_ERROR" },
/* 3364*/ { MQ_MQRCCF_CERT_VAL_POLICY_ERROR, "MQRCCF_CERT_VAL_POLICY_ERROR" },
/* 3365*/ { MQ_MQRCCF_INVALID_PROTOCOL, "MQRCCF_INVALID_PROTOCOL" },
/* 3366*/ { MQ_MQRCCF_REVDNS_DISABLED, "MQRCCF_REVDNS_DISABLED" },
/* 3367*/ { MQ_MQRCCF_CLROUTE_NOT_ALTERABLE, "MQRCCF_CLROUTE_NOT_ALTERABLE" },
/* 3368*/ { MQ_MQRCCF_CLUSTER_TOPIC_CONFLICT, "MQRCCF_CLUSTER_TOPIC_CONFLICT" },
/* 3369*/ { MQ_MQRCCF_DEFCLXQ_MODEL_Q_ERROR, "MQRCCF_DEFCLXQ_MODEL_Q_ERROR" },
/* 3370*/ { MQ_MQRCCF_CHLAUTH_CHKCLI_ERROR, "MQRCCF_CHLAUTH_CHKCLI_ERROR" },
/* 3371*/ { MQ_MQRCCF_CERT_LABEL_NOT_ALLOWED, "MQRCCF_CERT_LABEL_NOT_ALLOWED" },
/* 3372*/ { MQ_MQRCCF_Q_MGR_ATTR_CONFLICT, "MQRCCF_Q_MGR_ATTR_CONFLICT" },
/* 3373*/ { MQ_MQRCCF_ENTITY_TYPE_MISSING, "MQRCCF_ENTITY_TYPE_MISSING" },
/* 3374*/ { MQ_MQRCCF_CLWL_EXIT_NAME_ERROR, "MQRCCF_CLWL_EXIT_NAME_ERROR" },
/* 3375*/ { MQ_MQRCCF_SERVICE_NAME_ERROR, "MQRCCF_SERVICE_NAME_ERROR" },
/* 3376*/ { MQ_MQRCCF_REMOTE_CHL_TYPE_ERROR, "MQRCCF_REMOTE_CHL_TYPE_ERROR" },
/* 3377*/ { MQ_MQRCCF_TOPIC_RESTRICTED, "MQRCCF_TOPIC_RESTRICTED" },
/* 3378*/ { MQ_MQRCCF_CURRENT_LOG_EXTENT, "MQRCCF_CURRENT_LOG_EXTENT" },
/* 3379*/ { MQ_MQRCCF_LOG_EXTENT_NOT_FOUND, "MQRCCF_LOG_EXTENT_NOT_FOUND" },
/* 3380*/ { MQ_MQRCCF_LOG_NOT_REDUCED, "MQRCCF_LOG_NOT_REDUCED" },
/* 3381*/ { MQ_MQRCCF_LOG_EXTENT_ERROR, "MQRCCF_LOG_EXTENT_ERROR" },
/* 3382*/ { MQ_MQRCCF_ACCESS_BLOCKED, "MQRCCF_ACCESS_BLOCKED" },
/* 4001*/ { MQ_MQRCCF_OBJECT_ALREADY_EXISTS, "MQRCCF_OBJECT_ALREADY_EXISTS" },
/* 4002*/ { MQ_MQRCCF_OBJECT_WRONG_TYPE, "MQRCCF_OBJECT_WRONG_TYPE" },
/* 4003*/ { MQ_MQRCCF_LIKE_OBJECT_WRONG_TYPE, "MQRCCF_LIKE_OBJECT_WRONG_TYPE" },
/* 4004*/ { MQ_MQRCCF_OBJECT_OPEN, "MQRCCF_OBJECT_OPEN" },
/* 4005*/ { MQ_MQRCCF_ATTR_VALUE_ERROR, "MQRCCF_ATTR_VALUE_ERROR" },
/* 4006*/ { MQ_MQRCCF_UNKNOWN_Q_MGR, "MQRCCF_UNKNOWN_Q_MGR" },
/* 4007*/ { MQ_MQRCCF_Q_WRONG_TYPE, "MQRCCF_Q_WRONG_TYPE" },
/* 4008*/ { MQ_MQRCCF_OBJECT_NAME_ERROR, "MQRCCF_OBJECT_NAME_ERROR" },
/* 4009*/ { MQ_MQRCCF_ALLOCATE_FAILED, "MQRCCF_ALLOCATE_FAILED" },
/* 4010*/ { MQ_MQRCCF_HOST_NOT_AVAILABLE, "MQRCCF_HOST_NOT_AVAILABLE" },
/* 4011*/ { MQ_MQRCCF_CONFIGURATION_ERROR, "MQRCCF_CONFIGURATION_ERROR" },
/* 4012*/ { MQ_MQRCCF_CONNECTION_REFUSED, "MQRCCF_CONNECTION_REFUSED" },
/* 4013*/ { MQ_MQRCCF_ENTRY_ERROR, "MQRCCF_ENTRY_ERROR" },
/* 4014*/ { MQ_MQRCCF_SEND_FAILED, "MQRCCF_SEND_FAILED" },
/* 4015*/ { MQ_MQRCCF_RECEIVED_DATA_ERROR, "MQRCCF_RECEIVED_DATA_ERROR" },
/* 4016*/ { MQ_MQRCCF_RECEIVE_FAILED, "MQRCCF_RECEIVE_FAILED" },
/* 4017*/ { MQ_MQRCCF_CONNECTION_CLOSED, "MQRCCF_CONNECTION_CLOSED" },
/* 4018*/ { MQ_MQRCCF_NO_STORAGE, "MQRCCF_NO_STORAGE" },
/* 4019*/ { MQ_MQRCCF_NO_COMMS_MANAGER, "MQRCCF_NO_COMMS_MANAGER" },
/* 4020*/ { MQ_MQRCCF_LISTENER_NOT_STARTED, "MQRCCF_LISTENER_NOT_STARTED" },
/* 4024*/ { MQ_MQRCCF_BIND_FAILED, "MQRCCF_BIND_FAILED" },
/* 4025*/ { MQ_MQRCCF_CHANNEL_INDOUBT, "MQRCCF_CHANNEL_INDOUBT" },
/* 4026*/ { MQ_MQRCCF_MQCONN_FAILED, "MQRCCF_MQCONN_FAILED" },
/* 4027*/ { MQ_MQRCCF_MQOPEN_FAILED, "MQRCCF_MQOPEN_FAILED" },
/* 4028*/ { MQ_MQRCCF_MQGET_FAILED, "MQRCCF_MQGET_FAILED" },
/* 4029*/ { MQ_MQRCCF_MQPUT_FAILED, "MQRCCF_MQPUT_FAILED" },
/* 4030*/ { MQ_MQRCCF_PING_ERROR, "MQRCCF_PING_ERROR" },
/* 4031*/ { MQ_MQRCCF_CHANNEL_IN_USE, "MQRCCF_CHANNEL_IN_USE" },
/* 4032*/ { MQ_MQRCCF_CHANNEL_NOT_FOUND, "MQRCCF_CHANNEL_NOT_FOUND" },
/* 4033*/ { MQ_MQRCCF_UNKNOWN_REMOTE_CHANNEL, "MQRCCF_UNKNOWN_REMOTE_CHANNEL" },
/* 4034*/ { MQ_MQRCCF_REMOTE_QM_UNAVAILABLE, "MQRCCF_REMOTE_QM_UNAVAILABLE" },
/* 4035*/ { MQ_MQRCCF_REMOTE_QM_TERMINATING, "MQRCCF_REMOTE_QM_TERMINATING" },
/* 4036*/ { MQ_MQRCCF_MQINQ_FAILED, "MQRCCF_MQINQ_FAILED" },
/* 4037*/ { MQ_MQRCCF_NOT_XMIT_Q, "MQRCCF_NOT_XMIT_Q" },
/* 4038*/ { MQ_MQRCCF_CHANNEL_DISABLED, "MQRCCF_CHANNEL_DISABLED" },
/* 4039*/ { MQ_MQRCCF_USER_EXIT_NOT_AVAILABLE, "MQRCCF_USER_EXIT_NOT_AVAILABLE" },
/* 4040*/ { MQ_MQRCCF_COMMIT_FAILED, "MQRCCF_COMMIT_FAILED" },
/* 4041*/ { MQ_MQRCCF_WRONG_CHANNEL_TYPE, "MQRCCF_WRONG_CHANNEL_TYPE" },
/* 4042*/ { MQ_MQRCCF_CHANNEL_ALREADY_EXISTS, "MQRCCF_CHANNEL_ALREADY_EXISTS" },
/* 4043*/ { MQ_MQRCCF_DATA_TOO_LARGE, "MQRCCF_DATA_TOO_LARGE" },
/* 4044*/ { MQ_MQRCCF_CHANNEL_NAME_ERROR, "MQRCCF_CHANNEL_NAME_ERROR" },
/* 4045*/ { MQ_MQRCCF_XMIT_Q_NAME_ERROR, "MQRCCF_XMIT_Q_NAME_ERROR" },
/* 4047*/ { MQ_MQRCCF_MCA_NAME_ERROR, "MQRCCF_MCA_NAME_ERROR" },
/* 4048*/ { MQ_MQRCCF_SEND_EXIT_NAME_ERROR, "MQRCCF_SEND_EXIT_NAME_ERROR" },
/* 4049*/ { MQ_MQRCCF_SEC_EXIT_NAME_ERROR, "MQRCCF_SEC_EXIT_NAME_ERROR" },
/* 4050*/ { MQ_MQRCCF_MSG_EXIT_NAME_ERROR, "MQRCCF_MSG_EXIT_NAME_ERROR" },
/* 4051*/ { MQ_MQRCCF_RCV_EXIT_NAME_ERROR, "MQRCCF_RCV_EXIT_NAME_ERROR" },
/* 4052*/ { MQ_MQRCCF_XMIT_Q_NAME_WRONG_TYPE, "MQRCCF_XMIT_Q_NAME_WRONG_TYPE" },
/* 4053*/ { MQ_MQRCCF_MCA_NAME_WRONG_TYPE, "MQRCCF_MCA_NAME_WRONG_TYPE" },
/* 4054*/ { MQ_MQRCCF_DISC_INT_WRONG_TYPE, "MQRCCF_DISC_INT_WRONG_TYPE" },
/* 4055*/ { MQ_MQRCCF_SHORT_RETRY_WRONG_TYPE, "MQRCCF_SHORT_RETRY_WRONG_TYPE" },
/* 4056*/ { MQ_MQRCCF_SHORT_TIMER_WRONG_TYPE, "MQRCCF_SHORT_TIMER_WRONG_TYPE" },
/* 4057*/ { MQ_MQRCCF_LONG_RETRY_WRONG_TYPE, "MQRCCF_LONG_RETRY_WRONG_TYPE" },
/* 4058*/ { MQ_MQRCCF_LONG_TIMER_WRONG_TYPE, "MQRCCF_LONG_TIMER_WRONG_TYPE" },
/* 4059*/ { MQ_MQRCCF_PUT_AUTH_WRONG_TYPE, "MQRCCF_PUT_AUTH_WRONG_TYPE" },
/* 4060*/ { MQ_MQRCCF_KEEP_ALIVE_INT_ERROR, "MQRCCF_KEEP_ALIVE_INT_ERROR" },
/* 4061*/ { MQ_MQRCCF_MISSING_CONN_NAME, "MQRCCF_MISSING_CONN_NAME" },
/* 4062*/ { MQ_MQRCCF_CONN_NAME_ERROR, "MQRCCF_CONN_NAME_ERROR" },
/* 4063*/ { MQ_MQRCCF_MQSET_FAILED, "MQRCCF_MQSET_FAILED" },
/* 4064*/ { MQ_MQRCCF_CHANNEL_NOT_ACTIVE, "MQRCCF_CHANNEL_NOT_ACTIVE" },
/* 4065*/ { MQ_MQRCCF_TERMINATED_BY_SEC_EXIT, "MQRCCF_TERMINATED_BY_SEC_EXIT" },
/* 4067*/ { MQ_MQRCCF_DYNAMIC_Q_SCOPE_ERROR, "MQRCCF_DYNAMIC_Q_SCOPE_ERROR" },
/* 4068*/ { MQ_MQRCCF_CELL_DIR_NOT_AVAILABLE, "MQRCCF_CELL_DIR_NOT_AVAILABLE" },
/* 4069*/ { MQ_MQRCCF_MR_COUNT_ERROR, "MQRCCF_MR_COUNT_ERROR" },
/* 4070*/ { MQ_MQRCCF_MR_COUNT_WRONG_TYPE, "MQRCCF_MR_COUNT_WRONG_TYPE" },
/* 4071*/ { MQ_MQRCCF_MR_EXIT_NAME_ERROR, "MQRCCF_MR_EXIT_NAME_ERROR" },
/* 4072*/ { MQ_MQRCCF_MR_EXIT_NAME_WRONG_TYPE, "MQRCCF_MR_EXIT_NAME_WRONG_TYPE" },
/* 4073*/ { MQ_MQRCCF_MR_INTERVAL_ERROR, "MQRCCF_MR_INTERVAL_ERROR" },
/* 4074*/ { MQ_MQRCCF_MR_INTERVAL_WRONG_TYPE, "MQRCCF_MR_INTERVAL_WRONG_TYPE" },
/* 4075*/ { MQ_MQRCCF_NPM_SPEED_ERROR, "MQRCCF_NPM_SPEED_ERROR" },
/* 4076*/ { MQ_MQRCCF_NPM_SPEED_WRONG_TYPE, "MQRCCF_NPM_SPEED_WRONG_TYPE" },
/* 4077*/ { MQ_MQRCCF_HB_INTERVAL_ERROR, "MQRCCF_HB_INTERVAL_ERROR" },
/* 4078*/ { MQ_MQRCCF_HB_INTERVAL_WRONG_TYPE, "MQRCCF_HB_INTERVAL_WRONG_TYPE" },
/* 4079*/ { MQ_MQRCCF_CHAD_ERROR, "MQRCCF_CHAD_ERROR" },
/* 4080*/ { MQ_MQRCCF_CHAD_WRONG_TYPE, "MQRCCF_CHAD_WRONG_TYPE" },
/* 4081*/ { MQ_MQRCCF_CHAD_EVENT_ERROR, "MQRCCF_CHAD_EVENT_ERROR" },
/* 4082*/ { MQ_MQRCCF_CHAD_EVENT_WRONG_TYPE, "MQRCCF_CHAD_EVENT_WRONG_TYPE" },
/* 4083*/ { MQ_MQRCCF_CHAD_EXIT_ERROR, "MQRCCF_CHAD_EXIT_ERROR" },
/* 4084*/ { MQ_MQRCCF_CHAD_EXIT_WRONG_TYPE, "MQRCCF_CHAD_EXIT_WRONG_TYPE" },
/* 4085*/ { MQ_MQRCCF_SUPPRESSED_BY_EXIT, "MQRCCF_SUPPRESSED_BY_EXIT" },
/* 4086*/ { MQ_MQRCCF_BATCH_INT_ERROR, "MQRCCF_BATCH_INT_ERROR" },
/* 4087*/ { MQ_MQRCCF_BATCH_INT_WRONG_TYPE, "MQRCCF_BATCH_INT_WRONG_TYPE" },
/* 4088*/ { MQ_MQRCCF_NET_PRIORITY_ERROR, "MQRCCF_NET_PRIORITY_ERROR" },
/* 4089*/ { MQ_MQRCCF_NET_PRIORITY_WRONG_TYPE, "MQRCCF_NET_PRIORITY_WRONG_TYPE" },
/* 4090*/ { MQ_MQRCCF_CHANNEL_CLOSED, "MQRCCF_CHANNEL_CLOSED" },
/* 4091*/ { MQ_MQRCCF_Q_STATUS_NOT_FOUND, "MQRCCF_Q_STATUS_NOT_FOUND" },
/* 4092*/ { MQ_MQRCCF_SSL_CIPHER_SPEC_ERROR, "MQRCCF_SSL_CIPHER_SPEC_ERROR" },
/* 4093*/ { MQ_MQRCCF_SSL_PEER_NAME_ERROR, "MQRCCF_SSL_PEER_NAME_ERROR" },
/* 4094*/ { MQ_MQRCCF_SSL_CLIENT_AUTH_ERROR, "MQRCCF_SSL_CLIENT_AUTH_ERROR" },
/* 4095*/ { MQ_MQRCCF_RETAINED_NOT_SUPPORTED, "MQRCCF_RETAINED_NOT_SUPPORTED" },
/* 6000*/ { MQ_MQRC_LIBRARY_LOAD_ERROR, "MQRC_LIBRARY_LOAD_ERROR" },
/* 6001*/ { MQ_MQRC_CLASS_LIBRARY_ERROR, "MQRC_CLASS_LIBRARY_ERROR" },
/* 6002*/ { MQ_MQRC_STRING_LENGTH_TOO_BIG, "MQRC_STRING_LENGTH_TOO_BIG" },
/* 6003*/ { MQ_MQRC_WRITE_VALUE_ERROR, "MQRC_WRITE_VALUE_ERROR" },
/* 6004*/ { MQ_MQRC_PACKED_DECIMAL_ERROR, "MQRC_PACKED_DECIMAL_ERROR" },
/* 6005*/ { MQ_MQRC_FLOAT_CONVERSION_ERROR, "MQRC_FLOAT_CONVERSION_ERROR" },
/* 6100*/ { MQ_MQRC_REOPEN_EXCL_INPUT_ERROR, "MQRC_REOPEN_EXCL_INPUT_ERROR" },
/* 6101*/ { MQ_MQRC_REOPEN_INQUIRE_ERROR, "MQRC_REOPEN_INQUIRE_ERROR" },
/* 6102*/ { MQ_MQRC_REOPEN_SAVED_CONTEXT_ERR, "MQRC_REOPEN_SAVED_CONTEXT_ERR" },
/* 6103*/ { MQ_MQRC_REOPEN_TEMPORARY_Q_ERROR, "MQRC_REOPEN_TEMPORARY_Q_ERROR" },
/* 6104*/ { MQ_MQRC_ATTRIBUTE_LOCKED, "MQRC_ATTRIBUTE_LOCKED" },
/* 6105*/ { MQ_MQRC_CURSOR_NOT_VALID, "MQRC_CURSOR_NOT_VALID" },
/* 6106*/ { MQ_MQRC_ENCODING_ERROR, "MQRC_ENCODING_ERROR" },
/* 6107*/ { MQ_MQRC_STRUC_ID_ERROR, "MQRC_STRUC_ID_ERROR" },
/* 6108*/ { MQ_MQRC_NULL_POINTER, "MQRC_NULL_POINTER" },
/* 6109*/ { MQ_MQRC_NO_CONNECTION_REFERENCE, "MQRC_NO_CONNECTION_REFERENCE" },
/* 6110*/ { MQ_MQRC_NO_BUFFER, "MQRC_NO_BUFFER" },
/* 6111*/ { MQ_MQRC_BINARY_DATA_LENGTH_ERROR, "MQRC_BINARY_DATA_LENGTH_ERROR" },
/* 6112*/ { MQ_MQRC_BUFFER_NOT_AUTOMATIC, "MQRC_BUFFER_NOT_AUTOMATIC" },
/* 6113*/ { MQ_MQRC_INSUFFICIENT_BUFFER, "MQRC_INSUFFICIENT_BUFFER" },
/* 6114*/ { MQ_MQRC_INSUFFICIENT_DATA, "MQRC_INSUFFICIENT_DATA" },
/* 6115*/ { MQ_MQRC_DATA_TRUNCATED, "MQRC_DATA_TRUNCATED" },
/* 6116*/ { MQ_MQRC_ZERO_LENGTH, "MQRC_ZERO_LENGTH" },
/* 6117*/ { MQ_MQRC_NEGATIVE_LENGTH, "MQRC_NEGATIVE_LENGTH" },
/* 6118*/ { MQ_MQRC_NEGATIVE_OFFSET, "MQRC_NEGATIVE_OFFSET" },
/* 6119*/ { MQ_MQRC_INCONSISTENT_FORMAT, "MQRC_INCONSISTENT_FORMAT" },
/* 6120*/ { MQ_MQRC_INCONSISTENT_OBJECT_STATE, "MQRC_INCONSISTENT_OBJECT_STATE" },
/* 6121*/ { MQ_MQRC_CONTEXT_OBJECT_NOT_VALID, "MQRC_CONTEXT_OBJECT_NOT_VALID" },
/* 6122*/ { MQ_MQRC_CONTEXT_OPEN_ERROR, "MQRC_CONTEXT_OPEN_ERROR" },
/* 6123*/ { MQ_MQRC_STRUC_LENGTH_ERROR, "MQRC_STRUC_LENGTH_ERROR" },
/* 6124*/ { MQ_MQRC_NOT_CONNECTED, "MQRC_NOT_CONNECTED" },
/* 6125*/ { MQ_MQRC_NOT_OPEN, "MQRC_NOT_OPEN" },
/* 6126*/ { MQ_MQRC_DISTRIBUTION_LIST_EMPTY, "MQRC_DISTRIBUTION_LIST_EMPTY" },
/* 6127*/ { MQ_MQRC_INCONSISTENT_OPEN_OPTIONS, "MQRC_INCONSISTENT_OPEN_OPTIONS" },
/* 6128*/ { MQ_MQRC_WRONG_VERSION, "MQRC_WRONG_VERSION" },
/* 6129*/ { MQ_MQRC_REFERENCE_ERROR, "MQRC_REFERENCE_ERROR" },
/* 6130*/ { MQ_MQRC_XR_NOT_AVAILABLE, "MQRC_XR_NOT_AVAILABLE" },
/*29440*/ { MQ_MQRC_SUB_JOIN_NOT_ALTERABLE, "MQRC_SUB_JOIN_NOT_ALTERABLE" },
    { 0, NULL }
};
value_string_ext mq_MQRC_xvals = VALUE_STRING_EXT_INIT(mq_MQRC_vals);

static const value_string mq_MQOT_vals[] =
{
/*    0*/ { MQ_MQOT_NONE, "MQOT_NONE" },
/*    1*/ { MQ_MQOT_Q, "MQOT_Q" },
/*    2*/ { MQ_MQOT_NAMELIST, "MQOT_NAMELIST" },
/*    3*/ { MQ_MQOT_PROCESS, "MQOT_PROCESS" },
/*    4*/ { MQ_MQOT_STORAGE_CLASS, "MQOT_STORAGE_CLASS" },
/*    5*/ { MQ_MQOT_Q_MGR, "MQOT_Q_MGR" },
/*    6*/ { MQ_MQOT_CHANNEL, "MQOT_CHANNEL" },
/*    7*/ { MQ_MQOT_AUTH_INFO, "MQOT_AUTH_INFO" },
/*    8*/ { MQ_MQOT_TOPIC, "MQOT_TOPIC" },
/*    9*/ { MQ_MQOT_COMM_INFO, "MQOT_COMM_INFO" },
/*   10*/ { MQ_MQOT_CF_STRUC, "MQOT_CF_STRUC" },
/*   11*/ { MQ_MQOT_LISTENER, "MQOT_LISTENER" },
/*   12*/ { MQ_MQOT_SERVICE, "MQOT_SERVICE" },
/*  999*/ { MQ_MQOT_RESERVED_1, "MQOT_RESERVED_1" },
/* 1001*/ { MQ_MQOT_ALL, "MQOT_ALL" },
/* 1002*/ { MQ_MQOT_ALIAS_Q, "MQOT_ALIAS_Q" },
/* 1003*/ { MQ_MQOT_MODEL_Q, "MQOT_MODEL_Q" },
/* 1004*/ { MQ_MQOT_LOCAL_Q, "MQOT_LOCAL_Q" },
/* 1005*/ { MQ_MQOT_REMOTE_Q, "MQOT_REMOTE_Q" },
/* 1007*/ { MQ_MQOT_SENDER_CHANNEL, "MQOT_SENDER_CHANNEL" },
/* 1008*/ { MQ_MQOT_SERVER_CHANNEL, "MQOT_SERVER_CHANNEL" },
/* 1009*/ { MQ_MQOT_REQUESTER_CHANNEL, "MQOT_REQUESTER_CHANNEL" },
/* 1010*/ { MQ_MQOT_RECEIVER_CHANNEL, "MQOT_RECEIVER_CHANNEL" },
/* 1011*/ { MQ_MQOT_CURRENT_CHANNEL, "MQOT_CURRENT_CHANNEL" },
/* 1012*/ { MQ_MQOT_SAVED_CHANNEL, "MQOT_SAVED_CHANNEL" },
/* 1013*/ { MQ_MQOT_SVRCONN_CHANNEL, "MQOT_SVRCONN_CHANNEL" },
/* 1014*/ { MQ_MQOT_CLNTCONN_CHANNEL, "MQOT_CLNTCONN_CHANNEL" },
/* 1015*/ { MQ_MQOT_SHORT_CHANNEL, "MQOT_SHORT_CHANNEL" },
/* 1016*/ { MQ_MQOT_CHLAUTH, "MQOT_CHLAUTH" },
/* 1017*/ { MQ_MQOT_REMOTE_Q_MGR_NAME, "MQOT_REMOTE_Q_MGR_NAME" },
/* 1019*/ { MQ_MQOT_PROT_POLICY, "MQOT_PROT_POLICY" },
/* 1020*/ { MQ_MQOT_TT_CHANNEL, "MQOT_TT_CHANNEL" },
/* 1021*/ { MQ_MQOT_AMQP_CHANNEL, "MQOT_AMQP_CHANNEL" },
/* 1022*/ { MQ_MQOT_AUTH_REC, "MQOT_AUTH_REC" },
    { 0, NULL }
};
value_string_ext mq_MQOT_xvals = VALUE_STRING_EXT_INIT(mq_MQOT_vals);

static const value_string mq_PrmId_vals[] =
{
/*    1*/ { MQ_MQIA_APPL_TYPE, "MQIA_APPL_TYPE" },
/*    2*/ { MQ_MQIA_CODED_CHAR_SET_ID, "MQIA_CODED_CHAR_SET_ID" },
/*    3*/ { MQ_MQIA_CURRENT_Q_DEPTH, "MQIA_CURRENT_Q_DEPTH" },
/*    4*/ { MQ_MQIA_DEF_INPUT_OPEN_OPTION, "MQIA_DEF_INPUT_OPEN_OPTION" },
/*    5*/ { MQ_MQIA_DEF_PERSISTENCE, "MQIA_DEF_PERSISTENCE" },
/*    6*/ { MQ_MQIA_DEF_PRIORITY, "MQIA_DEF_PRIORITY" },
/*    7*/ { MQ_MQIA_DEFINITION_TYPE, "MQIA_DEFINITION_TYPE" },
/*    8*/ { MQ_MQIA_HARDEN_GET_BACKOUT, "MQIA_HARDEN_GET_BACKOUT" },
/*    9*/ { MQ_MQIA_INHIBIT_GET, "MQIA_INHIBIT_GET" },
/*   10*/ { MQ_MQIA_INHIBIT_PUT, "MQIA_INHIBIT_PUT" },
/*   11*/ { MQ_MQIA_MAX_HANDLES, "MQIA_MAX_HANDLES" },
/*   12*/ { MQ_MQIA_USAGE, "MQIA_USAGE" },
/*   13*/ { MQ_MQIA_MAX_MSG_LENGTH, "MQIA_MAX_MSG_LENGTH" },
/*   14*/ { MQ_MQIA_MAX_PRIORITY, "MQIA_MAX_PRIORITY" },
/*   15*/ { MQ_MQIA_MAX_Q_DEPTH, "MQIA_MAX_Q_DEPTH" },
/*   16*/ { MQ_MQIA_MSG_DELIVERY_SEQUENCE, "MQIA_MSG_DELIVERY_SEQUENCE" },
/*   17*/ { MQ_MQIA_OPEN_INPUT_COUNT, "MQIA_OPEN_INPUT_COUNT" },
/*   18*/ { MQ_MQIA_OPEN_OUTPUT_COUNT, "MQIA_OPEN_OUTPUT_COUNT" },
/*   19*/ { MQ_MQIA_NAME_COUNT, "MQIA_NAME_COUNT" },
/*   20*/ { MQ_MQIA_Q_TYPE, "MQIA_Q_TYPE" },
/*   21*/ { MQ_MQIA_RETENTION_INTERVAL, "MQIA_RETENTION_INTERVAL" },
/*   22*/ { MQ_MQIA_BACKOUT_THRESHOLD, "MQIA_BACKOUT_THRESHOLD" },
/*   23*/ { MQ_MQIA_SHAREABILITY, "MQIA_SHAREABILITY" },
/*   24*/ { MQ_MQIA_TRIGGER_CONTROL, "MQIA_TRIGGER_CONTROL" },
/*   25*/ { MQ_MQIA_TRIGGER_INTERVAL, "MQIA_TRIGGER_INTERVAL" },
/*   26*/ { MQ_MQIA_TRIGGER_MSG_PRIORITY, "MQIA_TRIGGER_MSG_PRIORITY" },
/*   27*/ { MQ_MQIA_CPI_LEVEL, "MQIA_CPI_LEVEL" },
/*   28*/ { MQ_MQIA_TRIGGER_TYPE, "MQIA_TRIGGER_TYPE" },
/*   29*/ { MQ_MQIA_TRIGGER_DEPTH, "MQIA_TRIGGER_DEPTH" },
/*   30*/ { MQ_MQIA_SYNCPOINT, "MQIA_SYNCPOINT" },
/*   31*/ { MQ_MQIA_COMMAND_LEVEL, "MQIA_COMMAND_LEVEL" },
/*   32*/ { MQ_MQIA_PLATFORM, "MQIA_PLATFORM" },
/*   33*/ { MQ_MQIA_MAX_UNCOMMITTED_MSGS, "MQIA_MAX_UNCOMMITTED_MSGS" },
/*   34*/ { MQ_MQIA_DIST_LISTS, "MQIA_DIST_LISTS" },
/*   35*/ { MQ_MQIA_TIME_SINCE_RESET, "MQIA_TIME_SINCE_RESET" },
/*   36*/ { MQ_MQIA_HIGH_Q_DEPTH, "MQIA_HIGH_Q_DEPTH" },
/*   37*/ { MQ_MQIA_MSG_ENQ_COUNT, "MQIA_MSG_ENQ_COUNT" },
/*   38*/ { MQ_MQIA_MSG_DEQ_COUNT, "MQIA_MSG_DEQ_COUNT" },
/*   39*/ { MQ_MQIA_EXPIRY_INTERVAL, "MQIA_EXPIRY_INTERVAL" },
/*   40*/ { MQ_MQIA_Q_DEPTH_HIGH_LIMIT, "MQIA_Q_DEPTH_HIGH_LIMIT" },
/*   41*/ { MQ_MQIA_Q_DEPTH_LOW_LIMIT, "MQIA_Q_DEPTH_LOW_LIMIT" },
/*   42*/ { MQ_MQIA_Q_DEPTH_MAX_EVENT, "MQIA_Q_DEPTH_MAX_EVENT" },
/*   43*/ { MQ_MQIA_Q_DEPTH_HIGH_EVENT, "MQIA_Q_DEPTH_HIGH_EVENT" },
/*   44*/ { MQ_MQIA_Q_DEPTH_LOW_EVENT, "MQIA_Q_DEPTH_LOW_EVENT" },
/*   45*/ { MQ_MQIA_SCOPE, "MQIA_SCOPE" },
/*   46*/ { MQ_MQIA_Q_SERVICE_INTERVAL_EVENT, "MQIA_Q_SERVICE_INTERVAL_EVENT" },
/*   47*/ { MQ_MQIA_AUTHORITY_EVENT, "MQIA_AUTHORITY_EVENT" },
/*   48*/ { MQ_MQIA_INHIBIT_EVENT, "MQIA_INHIBIT_EVENT" },
/*   49*/ { MQ_MQIA_LOCAL_EVENT, "MQIA_LOCAL_EVENT" },
/*   50*/ { MQ_MQIA_REMOTE_EVENT, "MQIA_REMOTE_EVENT" },
/*   51*/ { MQ_MQIA_CONFIGURATION_EVENT, "MQIA_CONFIGURATION_EVENT" },
/*   52*/ { MQ_MQIA_START_STOP_EVENT, "MQIA_START_STOP_EVENT" },
/*   53*/ { MQ_MQIA_PERFORMANCE_EVENT, "MQIA_PERFORMANCE_EVENT" },
/*   54*/ { MQ_MQIA_Q_SERVICE_INTERVAL, "MQIA_Q_SERVICE_INTERVAL" },
/*   55*/ { MQ_MQIA_CHANNEL_AUTO_DEF, "MQIA_CHANNEL_AUTO_DEF" },
/*   56*/ { MQ_MQIA_CHANNEL_AUTO_DEF_EVENT, "MQIA_CHANNEL_AUTO_DEF_EVENT" },
/*   57*/ { MQ_MQIA_INDEX_TYPE, "MQIA_INDEX_TYPE" },
/*   58*/ { MQ_MQIA_CLUSTER_WORKLOAD_LENGTH, "MQIA_CLUSTER_WORKLOAD_LENGTH" },
/*   59*/ { MQ_MQIA_CLUSTER_Q_TYPE, "MQIA_CLUSTER_Q_TYPE" },
/*   60*/ { MQ_MQIA_ARCHIVE, "MQIA_ARCHIVE" },
/*   61*/ { MQ_MQIA_DEF_BIND, "MQIA_DEF_BIND" },
/*   62*/ { MQ_MQIA_PAGESET_ID, "MQIA_PAGESET_ID" },
/*   63*/ { MQ_MQIA_QSG_DISP, "MQIA_QSG_DISP" },
/*   64*/ { MQ_MQIA_INTRA_GROUP_QUEUING, "MQIA_INTRA_GROUP_QUEUING" },
/*   65*/ { MQ_MQIA_IGQ_PUT_AUTHORITY, "MQIA_IGQ_PUT_AUTHORITY" },
/*   66*/ { MQ_MQIA_AUTH_INFO_TYPE, "MQIA_AUTH_INFO_TYPE" },
/*   68*/ { MQ_MQIA_MSG_MARK_BROWSE_INTERVAL, "MQIA_MSG_MARK_BROWSE_INTERVAL" },
/*   69*/ { MQ_MQIA_SSL_TASKS, "MQIA_SSL_TASKS" },
/*   70*/ { MQ_MQIA_CF_LEVEL, "MQIA_CF_LEVEL" },
/*   71*/ { MQ_MQIA_CF_RECOVER, "MQIA_CF_RECOVER" },
/*   72*/ { MQ_MQIA_NAMELIST_TYPE, "MQIA_NAMELIST_TYPE" },
/*   73*/ { MQ_MQIA_CHANNEL_EVENT, "MQIA_CHANNEL_EVENT" },
/*   74*/ { MQ_MQIA_BRIDGE_EVENT, "MQIA_BRIDGE_EVENT" },
/*   75*/ { MQ_MQIA_SSL_EVENT, "MQIA_SSL_EVENT" },
/*   76*/ { MQ_MQIA_SSL_RESET_COUNT, "MQIA_SSL_RESET_COUNT" },
/*   77*/ { MQ_MQIA_SHARED_Q_Q_MGR_NAME, "MQIA_SHARED_Q_Q_MGR_NAME" },
/*   78*/ { MQ_MQIA_NPM_CLASS, "MQIA_NPM_CLASS" },
/*   80*/ { MQ_MQIA_MAX_OPEN_Q, "MQIA_MAX_OPEN_Q" },
/*   81*/ { MQ_MQIA_MONITOR_INTERVAL, "MQIA_MONITOR_INTERVAL" },
/*   82*/ { MQ_MQIA_Q_USERS, "MQIA_Q_USERS" },
/*   83*/ { MQ_MQIA_MAX_GLOBAL_LOCKS, "MQIA_MAX_GLOBAL_LOCKS" },
/*   84*/ { MQ_MQIA_MAX_LOCAL_LOCKS, "MQIA_MAX_LOCAL_LOCKS" },
/*   85*/ { MQ_MQIA_LISTENER_PORT_NUMBER, "MQIA_LISTENER_PORT_NUMBER" },
/*   86*/ { MQ_MQIA_BATCH_INTERFACE_AUTO, "MQIA_BATCH_INTERFACE_AUTO" },
/*   87*/ { MQ_MQIA_CMD_SERVER_AUTO, "MQIA_CMD_SERVER_AUTO" },
/*   88*/ { MQ_MQIA_CMD_SERVER_CONVERT_MSG, "MQIA_CMD_SERVER_CONVERT_MSG" },
/*   89*/ { MQ_MQIA_CMD_SERVER_DLQ_MSG, "MQIA_CMD_SERVER_DLQ_MSG" },
/*   90*/ { MQ_MQIA_MAX_Q_TRIGGERS, "MQIA_MAX_Q_TRIGGERS" },
/*   91*/ { MQ_MQIA_TRIGGER_RESTART, "MQIA_TRIGGER_RESTART" },
/*   92*/ { MQ_MQIA_SSL_FIPS_REQUIRED, "MQIA_SSL_FIPS_REQUIRED" },
/*   93*/ { MQ_MQIA_IP_ADDRESS_VERSION, "MQIA_IP_ADDRESS_VERSION" },
/*   94*/ { MQ_MQIA_LOGGER_EVENT, "MQIA_LOGGER_EVENT" },
/*   95*/ { MQ_MQIA_CLWL_Q_RANK, "MQIA_CLWL_Q_RANK" },
/*   96*/ { MQ_MQIA_CLWL_Q_PRIORITY, "MQIA_CLWL_Q_PRIORITY" },
/*   97*/ { MQ_MQIA_CLWL_MRU_CHANNELS, "MQIA_CLWL_MRU_CHANNELS" },
/*   98*/ { MQ_MQIA_CLWL_USEQ, "MQIA_CLWL_USEQ" },
/*   99*/ { MQ_MQIA_COMMAND_EVENT, "MQIA_COMMAND_EVENT" },
/*  100*/ { MQ_MQIA_ACTIVE_CHANNELS, "MQIA_ACTIVE_CHANNELS" },
/*  101*/ { MQ_MQIA_CHINIT_ADAPTERS, "MQIA_CHINIT_ADAPTERS" },
/*  102*/ { MQ_MQIA_ADOPTNEWMCA_CHECK, "MQIA_ADOPTNEWMCA_CHECK" },
/*  103*/ { MQ_MQIA_ADOPTNEWMCA_TYPE, "MQIA_ADOPTNEWMCA_TYPE" },
/*  104*/ { MQ_MQIA_ADOPTNEWMCA_INTERVAL, "MQIA_ADOPTNEWMCA_INTERVAL" },
/*  105*/ { MQ_MQIA_CHINIT_DISPATCHERS, "MQIA_CHINIT_DISPATCHERS" },
/*  106*/ { MQ_MQIA_DNS_WLM, "MQIA_DNS_WLM" },
/*  107*/ { MQ_MQIA_LISTENER_TIMER, "MQIA_LISTENER_TIMER" },
/*  108*/ { MQ_MQIA_LU62_CHANNELS, "MQIA_LU62_CHANNELS" },
/*  109*/ { MQ_MQIA_MAX_CHANNELS, "MQIA_MAX_CHANNELS" },
/*  110*/ { MQ_MQIA_OUTBOUND_PORT_MIN, "MQIA_OUTBOUND_PORT_MIN" },
/*  111*/ { MQ_MQIA_RECEIVE_TIMEOUT, "MQIA_RECEIVE_TIMEOUT" },
/*  112*/ { MQ_MQIA_RECEIVE_TIMEOUT_TYPE, "MQIA_RECEIVE_TIMEOUT_TYPE" },
/*  113*/ { MQ_MQIA_RECEIVE_TIMEOUT_MIN, "MQIA_RECEIVE_TIMEOUT_MIN" },
/*  114*/ { MQ_MQIA_TCP_CHANNELS, "MQIA_TCP_CHANNELS" },
/*  115*/ { MQ_MQIA_TCP_KEEP_ALIVE, "MQIA_TCP_KEEP_ALIVE" },
/*  116*/ { MQ_MQIA_TCP_STACK_TYPE, "MQIA_TCP_STACK_TYPE" },
/*  117*/ { MQ_MQIA_CHINIT_TRACE_AUTO_START, "MQIA_CHINIT_TRACE_AUTO_START" },
/*  118*/ { MQ_MQIA_CHINIT_TRACE_TABLE_SIZE, "MQIA_CHINIT_TRACE_TABLE_SIZE" },
/*  119*/ { MQ_MQIA_CHINIT_CONTROL, "MQIA_CHINIT_CONTROL" },
/*  120*/ { MQ_MQIA_CMD_SERVER_CONTROL, "MQIA_CMD_SERVER_CONTROL" },
/*  121*/ { MQ_MQIA_SERVICE_TYPE, "MQIA_SERVICE_TYPE" },
/*  122*/ { MQ_MQIA_MONITORING_CHANNEL, "MQIA_MONITORING_CHANNEL" },
/*  123*/ { MQ_MQIA_MONITORING_Q, "MQIA_MONITORING_Q" },
/*  124*/ { MQ_MQIA_MONITORING_AUTO_CLUSSDR, "MQIA_MONITORING_AUTO_CLUSSDR" },
/*  127*/ { MQ_MQIA_STATISTICS_MQI, "MQIA_STATISTICS_MQI" },
/*  128*/ { MQ_MQIA_STATISTICS_Q, "MQIA_STATISTICS_Q" },
/*  129*/ { MQ_MQIA_STATISTICS_CHANNEL, "MQIA_STATISTICS_CHANNEL" },
/*  130*/ { MQ_MQIA_STATISTICS_AUTO_CLUSSDR, "MQIA_STATISTICS_AUTO_CLUSSDR" },
/*  131*/ { MQ_MQIA_STATISTICS_INTERVAL, "MQIA_STATISTICS_INTERVAL" },
/*  133*/ { MQ_MQIA_ACCOUNTING_MQI, "MQIA_ACCOUNTING_MQI" },
/*  134*/ { MQ_MQIA_ACCOUNTING_Q, "MQIA_ACCOUNTING_Q" },
/*  135*/ { MQ_MQIA_ACCOUNTING_INTERVAL, "MQIA_ACCOUNTING_INTERVAL" },
/*  136*/ { MQ_MQIA_ACCOUNTING_CONN_OVERRIDE, "MQIA_ACCOUNTING_CONN_OVERRIDE" },
/*  137*/ { MQ_MQIA_TRACE_ROUTE_RECORDING, "MQIA_TRACE_ROUTE_RECORDING" },
/*  138*/ { MQ_MQIA_ACTIVITY_RECORDING, "MQIA_ACTIVITY_RECORDING" },
/*  139*/ { MQ_MQIA_SERVICE_CONTROL, "MQIA_SERVICE_CONTROL" },
/*  140*/ { MQ_MQIA_OUTBOUND_PORT_MAX, "MQIA_OUTBOUND_PORT_MAX" },
/*  141*/ { MQ_MQIA_SECURITY_CASE, "MQIA_SECURITY_CASE" },
/*  150*/ { MQ_MQIA_QMOPT_CSMT_ON_ERROR, "MQIA_QMOPT_CSMT_ON_ERROR" },
/*  151*/ { MQ_MQIA_QMOPT_CONS_INFO_MSGS, "MQIA_QMOPT_CONS_INFO_MSGS" },
/*  152*/ { MQ_MQIA_QMOPT_CONS_WARNING_MSGS, "MQIA_QMOPT_CONS_WARNING_MSGS" },
/*  153*/ { MQ_MQIA_QMOPT_CONS_ERROR_MSGS, "MQIA_QMOPT_CONS_ERROR_MSGS" },
/*  154*/ { MQ_MQIA_QMOPT_CONS_CRITICAL_MSGS, "MQIA_QMOPT_CONS_CRITICAL_MSGS" },
/*  155*/ { MQ_MQIA_QMOPT_CONS_COMMS_MSGS, "MQIA_QMOPT_CONS_COMMS_MSGS" },
/*  156*/ { MQ_MQIA_QMOPT_CONS_REORG_MSGS, "MQIA_QMOPT_CONS_REORG_MSGS" },
/*  157*/ { MQ_MQIA_QMOPT_CONS_SYSTEM_MSGS, "MQIA_QMOPT_CONS_SYSTEM_MSGS" },
/*  158*/ { MQ_MQIA_QMOPT_LOG_INFO_MSGS, "MQIA_QMOPT_LOG_INFO_MSGS" },
/*  159*/ { MQ_MQIA_QMOPT_LOG_WARNING_MSGS, "MQIA_QMOPT_LOG_WARNING_MSGS" },
/*  160*/ { MQ_MQIA_QMOPT_LOG_ERROR_MSGS, "MQIA_QMOPT_LOG_ERROR_MSGS" },
/*  161*/ { MQ_MQIA_QMOPT_LOG_CRITICAL_MSGS, "MQIA_QMOPT_LOG_CRITICAL_MSGS" },
/*  162*/ { MQ_MQIA_QMOPT_LOG_COMMS_MSGS, "MQIA_QMOPT_LOG_COMMS_MSGS" },
/*  163*/ { MQ_MQIA_QMOPT_LOG_REORG_MSGS, "MQIA_QMOPT_LOG_REORG_MSGS" },
/*  164*/ { MQ_MQIA_QMOPT_LOG_SYSTEM_MSGS, "MQIA_QMOPT_LOG_SYSTEM_MSGS" },
/*  165*/ { MQ_MQIA_QMOPT_TRACE_MQI_CALLS, "MQIA_QMOPT_TRACE_MQI_CALLS" },
/*  166*/ { MQ_MQIA_QMOPT_TRACE_COMMS, "MQIA_QMOPT_TRACE_COMMS" },
/*  167*/ { MQ_MQIA_QMOPT_TRACE_REORG, "MQIA_QMOPT_TRACE_REORG" },
/*  168*/ { MQ_MQIA_QMOPT_TRACE_CONVERSION, "MQIA_QMOPT_TRACE_CONVERSION" },
/*  169*/ { MQ_MQIA_QMOPT_TRACE_SYSTEM, "MQIA_QMOPT_TRACE_SYSTEM" },
/*  170*/ { MQ_MQIA_QMOPT_INTERNAL_DUMP, "MQIA_QMOPT_INTERNAL_DUMP" },
/*  171*/ { MQ_MQIA_MAX_RECOVERY_TASKS, "MQIA_MAX_RECOVERY_TASKS" },
/*  172*/ { MQ_MQIA_MAX_CLIENTS, "MQIA_MAX_CLIENTS" },
/*  173*/ { MQ_MQIA_AUTO_REORGANIZATION, "MQIA_AUTO_REORGANIZATION" },
/*  174*/ { MQ_MQIA_AUTO_REORG_INTERVAL, "MQIA_AUTO_REORG_INTERVAL" },
/*  175*/ { MQ_MQIA_DURABLE_SUB, "MQIA_DURABLE_SUB" },
/*  176*/ { MQ_MQIA_MULTICAST, "MQIA_MULTICAST" },
/*  181*/ { MQ_MQIA_INHIBIT_PUB, "MQIA_INHIBIT_PUB" },
/*  182*/ { MQ_MQIA_INHIBIT_SUB, "MQIA_INHIBIT_SUB" },
/*  183*/ { MQ_MQIA_TREE_LIFE_TIME, "MQIA_TREE_LIFE_TIME" },
/*  184*/ { MQ_MQIA_DEF_PUT_RESPONSE_TYPE, "MQIA_DEF_PUT_RESPONSE_TYPE" },
/*  185*/ { MQ_MQIA_TOPIC_DEF_PERSISTENCE, "MQIA_TOPIC_DEF_PERSISTENCE" },
/*  186*/ { MQ_MQIA_MASTER_ADMIN, "MQIA_MASTER_ADMIN" },
/*  187*/ { MQ_MQIA_PUBSUB_MODE, "MQIA_PUBSUB_MODE" },
/*  188*/ { MQ_MQIA_DEF_READ_AHEAD, "MQIA_DEF_READ_AHEAD" },
/*  189*/ { MQ_MQIA_READ_AHEAD, "MQIA_READ_AHEAD" },
/*  190*/ { MQ_MQIA_PROPERTY_CONTROL, "MQIA_PROPERTY_CONTROL" },
/*  192*/ { MQ_MQIA_MAX_PROPERTIES_LENGTH, "MQIA_MAX_PROPERTIES_LENGTH" },
/*  193*/ { MQ_MQIA_BASE_TYPE, "MQIA_BASE_TYPE" },
/*  195*/ { MQ_MQIA_PM_DELIVERY, "MQIA_PM_DELIVERY" },
/*  196*/ { MQ_MQIA_NPM_DELIVERY, "MQIA_NPM_DELIVERY" },
/*  199*/ { MQ_MQIA_PROXY_SUB, "MQIA_PROXY_SUB" },
/*  203*/ { MQ_MQIA_PUBSUB_NP_MSG, "MQIA_PUBSUB_NP_MSG" },
/*  204*/ { MQ_MQIA_SUB_COUNT, "MQIA_SUB_COUNT" },
/*  205*/ { MQ_MQIA_PUBSUB_NP_RESP, "MQIA_PUBSUB_NP_RESP" },
/*  206*/ { MQ_MQIA_PUBSUB_MAXMSG_RETRY_COUNT, "MQIA_PUBSUB_MAXMSG_RETRY_COUNT" },
/*  207*/ { MQ_MQIA_PUBSUB_SYNC_PT, "MQIA_PUBSUB_SYNC_PT" },
/*  208*/ { MQ_MQIA_TOPIC_TYPE, "MQIA_TOPIC_TYPE" },
/*  215*/ { MQ_MQIA_PUB_COUNT, "MQIA_PUB_COUNT" },
/*  216*/ { MQ_MQIA_WILDCARD_OPERATION, "MQIA_WILDCARD_OPERATION" },
/*  218*/ { MQ_MQIA_SUB_SCOPE, "MQIA_SUB_SCOPE" },
/*  219*/ { MQ_MQIA_PUB_SCOPE, "MQIA_PUB_SCOPE" },
/*  221*/ { MQ_MQIA_GROUP_UR, "MQIA_GROUP_UR" },
/*  222*/ { MQ_MQIA_UR_DISP, "MQIA_UR_DISP" },
/*  223*/ { MQ_MQIA_COMM_INFO_TYPE, "MQIA_COMM_INFO_TYPE" },
/*  224*/ { MQ_MQIA_CF_OFFLOAD, "MQIA_CF_OFFLOAD" },
/*  225*/ { MQ_MQIA_CF_OFFLOAD_THRESHOLD1, "MQIA_CF_OFFLOAD_THRESHOLD1" },
/*  226*/ { MQ_MQIA_CF_OFFLOAD_THRESHOLD2, "MQIA_CF_OFFLOAD_THRESHOLD2" },
/*  227*/ { MQ_MQIA_CF_OFFLOAD_THRESHOLD3, "MQIA_CF_OFFLOAD_THRESHOLD3" },
/*  228*/ { MQ_MQIA_CF_SMDS_BUFFERS, "MQIA_CF_SMDS_BUFFERS" },
/*  229*/ { MQ_MQIA_CF_OFFLDUSE, "MQIA_CF_OFFLDUSE" },
/*  230*/ { MQ_MQIA_MAX_RESPONSES, "MQIA_MAX_RESPONSES" },
/*  231*/ { MQ_MQIA_RESPONSE_RESTART_POINT, "MQIA_RESPONSE_RESTART_POINT" },
/*  232*/ { MQ_MQIA_COMM_EVENT, "MQIA_COMM_EVENT" },
/*  233*/ { MQ_MQIA_MCAST_BRIDGE, "MQIA_MCAST_BRIDGE" },
/*  234*/ { MQ_MQIA_USE_DEAD_LETTER_Q, "MQIA_USE_DEAD_LETTER_Q" },
/*  235*/ { MQ_MQIA_TOLERATE_UNPROTECTED, "MQIA_TOLERATE_UNPROTECTED" },
/*  236*/ { MQ_MQIA_SIGNATURE_ALGORITHM, "MQIA_SIGNATURE_ALGORITHM" },
/*  237*/ { MQ_MQIA_ENCRYPTION_ALGORITHM, "MQIA_ENCRYPTION_ALGORITHM" },
/*  238*/ { MQ_MQIA_POLICY_VERSION, "MQIA_POLICY_VERSION" },
/*  239*/ { MQ_MQIA_ACTIVITY_CONN_OVERRIDE, "MQIA_ACTIVITY_CONN_OVERRIDE" },
/*  240*/ { MQ_MQIA_ACTIVITY_TRACE, "MQIA_ACTIVITY_TRACE" },
/*  242*/ { MQ_MQIA_SUB_CONFIGURATION_EVENT, "MQIA_SUB_CONFIGURATION_EVENT" },
/*  243*/ { MQ_MQIA_XR_CAPABILITY, "MQIA_XR_CAPABILITY" },
/*  244*/ { MQ_MQIA_CF_RECAUTO, "MQIA_CF_RECAUTO" },
/*  245*/ { MQ_MQIA_QMGR_CFCONLOS, "MQIA_QMGR_CFCONLOS" },
/*  246*/ { MQ_MQIA_CF_CFCONLOS, "MQIA_CF_CFCONLOS" },
/*  247*/ { MQ_MQIA_SUITE_B_STRENGTH, "MQIA_SUITE_B_STRENGTH" },
/*  248*/ { MQ_MQIA_CHLAUTH_RECORDS, "MQIA_CHLAUTH_RECORDS" },
/*  249*/ { MQ_MQIA_PUBSUB_CLUSTER, "MQIA_PUBSUB_CLUSTER" },
/*  250*/ { MQ_MQIA_DEF_CLUSTER_XMIT_Q_TYPE, "MQIA_DEF_CLUSTER_XMIT_Q_TYPE" },
/*  251*/ { MQ_MQIA_PROT_POLICY_CAPABILITY, "MQIA_PROT_POLICY_CAPABILITY" },
/*  252*/ { MQ_MQIA_CERT_VAL_POLICY, "MQIA_CERT_VAL_POLICY" },
/*  253*/ { MQ_MQIA_TOPIC_NODE_COUNT, "MQIA_TOPIC_NODE_COUNT" },
/*  254*/ { MQ_MQIA_REVERSE_DNS_LOOKUP, "MQIA_REVERSE_DNS_LOOKUP" },
/*  255*/ { MQ_MQIA_CLUSTER_PUB_ROUTE, "MQIA_CLUSTER_PUB_ROUTE" },
/*  256*/ { MQ_MQIA_CLUSTER_OBJECT_STATE, "MQIA_CLUSTER_OBJECT_STATE" },
/*  257*/ { MQ_MQIA_CHECK_LOCAL_BINDING, "MQIA_CHECK_LOCAL_BINDING" },
/*  258*/ { MQ_MQIA_CHECK_CLIENT_BINDING, "MQIA_CHECK_CLIENT_BINDING" },
/*  259*/ { MQ_MQIA_AUTHENTICATION_FAIL_DELAY, "MQIA_AUTHENTICATION_FAIL_DELAY" },
/*  260*/ { MQ_MQIA_ADOPT_CONTEXT, "MQIA_ADOPT_CONTEXT" },
/*  261*/ { MQ_MQIA_LDAP_SECURE_COMM, "MQIA_LDAP_SECURE_COMM" },
/*  262*/ { MQ_MQIA_DISPLAY_TYPE, "MQIA_DISPLAY_TYPE" },
/*  263*/ { MQ_MQIA_LDAP_AUTHORMD, "MQIA_LDAP_AUTHORMD" },
/*  264*/ { MQ_MQIA_LDAP_NESTGRP, "MQIA_LDAP_NESTGRP" },
/*  265*/ { MQ_MQIA_AMQP_CAPABILITY, "MQIA_AMQP_CAPABILITY" },
/*  266*/ { MQ_MQIA_AUTHENTICATION_METHOD, "MQIA_AUTHENTICATION_METHOD" },
/*  267*/ { MQ_MQIA_KEY_REUSE_COUNT, "MQIA_KEY_REUSE_COUNT" },
/*  268*/ { MQ_MQIA_MEDIA_IMAGE_SCHEDULING, "MQIA_MEDIA_IMAGE_SCHEDULING" },
/*  269*/ { MQ_MQIA_MEDIA_IMAGE_INTERVAL, "MQIA_MEDIA_IMAGE_INTERVAL" },
/*  270*/ { MQ_MQIA_MEDIA_IMAGE_LOG_LENGTH, "MQIA_MEDIA_IMAGE_LOG_LENGTH" },
/*  271*/ { MQ_MQIA_MEDIA_IMAGE_RECOVER_OBJ, "MQIA_MEDIA_IMAGE_RECOVER_OBJ" },
/*  272*/ { MQ_MQIA_MEDIA_IMAGE_RECOVER_Q, "MQIA_MEDIA_IMAGE_RECOVER_Q" },
/*  273*/ { MQ_MQIA_ADVANCED_CAPABILITY, "MQIA_ADVANCED_CAPABILITY" },
/*  702*/ { MQ_MQIAMO_AVG_BATCH_SIZE, "MQIAMO_AVG_BATCH_SIZE" },
/*  703*/ { MQ_MQIAMO_AVG_Q_TIME, "MQIAMO_AVG_Q_TIME" },
/*  703   { MQ_MQIAMO64_AVG_Q_TIME, "MQIAMO64_AVG_Q_TIME" }, */
/*  704*/ { MQ_MQIAMO_BACKOUTS, "MQIAMO_BACKOUTS" },
/*  705*/ { MQ_MQIAMO_BROWSES, "MQIAMO_BROWSES" },
/*  706*/ { MQ_MQIAMO_BROWSE_MAX_BYTES, "MQIAMO_BROWSE_MAX_BYTES" },
/*  707*/ { MQ_MQIAMO_BROWSE_MIN_BYTES, "MQIAMO_BROWSE_MIN_BYTES" },
/*  708*/ { MQ_MQIAMO_BROWSES_FAILED, "MQIAMO_BROWSES_FAILED" },
/*  709*/ { MQ_MQIAMO_CLOSES, "MQIAMO_CLOSES" },
/*  710*/ { MQ_MQIAMO_COMMITS, "MQIAMO_COMMITS" },
/*  711*/ { MQ_MQIAMO_COMMITS_FAILED, "MQIAMO_COMMITS_FAILED" },
/*  712*/ { MQ_MQIAMO_CONNS, "MQIAMO_CONNS" },
/*  713*/ { MQ_MQIAMO_CONNS_MAX, "MQIAMO_CONNS_MAX" },
/*  714*/ { MQ_MQIAMO_DISCS, "MQIAMO_DISCS" },
/*  715*/ { MQ_MQIAMO_DISCS_IMPLICIT, "MQIAMO_DISCS_IMPLICIT" },
/*  716*/ { MQ_MQIAMO_DISC_TYPE, "MQIAMO_DISC_TYPE" },
/*  717*/ { MQ_MQIAMO_EXIT_TIME_AVG, "MQIAMO_EXIT_TIME_AVG" },
/*  718*/ { MQ_MQIAMO_EXIT_TIME_MAX, "MQIAMO_EXIT_TIME_MAX" },
/*  719*/ { MQ_MQIAMO_EXIT_TIME_MIN, "MQIAMO_EXIT_TIME_MIN" },
/*  720*/ { MQ_MQIAMO_FULL_BATCHES, "MQIAMO_FULL_BATCHES" },
/*  721*/ { MQ_MQIAMO_GENERATED_MSGS, "MQIAMO_GENERATED_MSGS" },
/*  722*/ { MQ_MQIAMO_GETS, "MQIAMO_GETS" },
/*  723*/ { MQ_MQIAMO_GET_MAX_BYTES, "MQIAMO_GET_MAX_BYTES" },
/*  724*/ { MQ_MQIAMO_GET_MIN_BYTES, "MQIAMO_GET_MIN_BYTES" },
/*  725*/ { MQ_MQIAMO_GETS_FAILED, "MQIAMO_GETS_FAILED" },
/*  726*/ { MQ_MQIAMO_INCOMPLETE_BATCHES, "MQIAMO_INCOMPLETE_BATCHES" },
/*  727*/ { MQ_MQIAMO_INQS, "MQIAMO_INQS" },
/*  728*/ { MQ_MQIAMO_MSGS, "MQIAMO_MSGS" },
/*  729*/ { MQ_MQIAMO_NET_TIME_AVG, "MQIAMO_NET_TIME_AVG" },
/*  730*/ { MQ_MQIAMO_NET_TIME_MAX, "MQIAMO_NET_TIME_MAX" },
/*  731*/ { MQ_MQIAMO_NET_TIME_MIN, "MQIAMO_NET_TIME_MIN" },
/*  732*/ { MQ_MQIAMO_OBJECT_COUNT, "MQIAMO_OBJECT_COUNT" },
/*  733*/ { MQ_MQIAMO_OPENS, "MQIAMO_OPENS" },
/*  734*/ { MQ_MQIAMO_PUT1S, "MQIAMO_PUT1S" },
/*  735*/ { MQ_MQIAMO_PUTS, "MQIAMO_PUTS" },
/*  736*/ { MQ_MQIAMO_PUT_MAX_BYTES, "MQIAMO_PUT_MAX_BYTES" },
/*  737*/ { MQ_MQIAMO_PUT_MIN_BYTES, "MQIAMO_PUT_MIN_BYTES" },
/*  738*/ { MQ_MQIAMO_PUT_RETRIES, "MQIAMO_PUT_RETRIES" },
/*  739*/ { MQ_MQIAMO_Q_MAX_DEPTH, "MQIAMO_Q_MAX_DEPTH" },
/*  740*/ { MQ_MQIAMO_Q_MIN_DEPTH, "MQIAMO_Q_MIN_DEPTH" },
/*  741*/ { MQ_MQIAMO_Q_TIME_AVG, "MQIAMO_Q_TIME_AVG" },
/*  741   { MQ_MQIAMO64_Q_TIME_AVG, "MQIAMO64_Q_TIME_AVG" }, */
/*  742*/ { MQ_MQIAMO_Q_TIME_MAX, "MQIAMO_Q_TIME_MAX" },
/*  742   { MQ_MQIAMO64_Q_TIME_MAX, "MQIAMO64_Q_TIME_MAX" }, */
/*  743*/ { MQ_MQIAMO_Q_TIME_MIN, "MQIAMO_Q_TIME_MIN" },
/*  743   { MQ_MQIAMO64_Q_TIME_MIN, "MQIAMO64_Q_TIME_MIN" }, */
/*  744*/ { MQ_MQIAMO_SETS, "MQIAMO_SETS" },
/*  745*/ { MQ_MQIAMO64_BROWSE_BYTES, "MQIAMO64_BROWSE_BYTES" },
/*  746*/ { MQ_MQIAMO64_BYTES, "MQIAMO64_BYTES" },
/*  747*/ { MQ_MQIAMO64_GET_BYTES, "MQIAMO64_GET_BYTES" },
/*  748*/ { MQ_MQIAMO64_PUT_BYTES, "MQIAMO64_PUT_BYTES" },
/*  749*/ { MQ_MQIAMO_CONNS_FAILED, "MQIAMO_CONNS_FAILED" },
/*  751*/ { MQ_MQIAMO_OPENS_FAILED, "MQIAMO_OPENS_FAILED" },
/*  752*/ { MQ_MQIAMO_INQS_FAILED, "MQIAMO_INQS_FAILED" },
/*  753*/ { MQ_MQIAMO_SETS_FAILED, "MQIAMO_SETS_FAILED" },
/*  754*/ { MQ_MQIAMO_PUTS_FAILED, "MQIAMO_PUTS_FAILED" },
/*  755*/ { MQ_MQIAMO_PUT1S_FAILED, "MQIAMO_PUT1S_FAILED" },
/*  757*/ { MQ_MQIAMO_CLOSES_FAILED, "MQIAMO_CLOSES_FAILED" },
/*  758*/ { MQ_MQIAMO_MSGS_EXPIRED, "MQIAMO_MSGS_EXPIRED" },
/*  759*/ { MQ_MQIAMO_MSGS_NOT_QUEUED, "MQIAMO_MSGS_NOT_QUEUED" },
/*  760*/ { MQ_MQIAMO_MSGS_PURGED, "MQIAMO_MSGS_PURGED" },
/*  764*/ { MQ_MQIAMO_SUBS_DUR, "MQIAMO_SUBS_DUR" },
/*  765*/ { MQ_MQIAMO_SUBS_NDUR, "MQIAMO_SUBS_NDUR" },
/*  766*/ { MQ_MQIAMO_SUBS_FAILED, "MQIAMO_SUBS_FAILED" },
/*  767*/ { MQ_MQIAMO_SUBRQS, "MQIAMO_SUBRQS" },
/*  768*/ { MQ_MQIAMO_SUBRQS_FAILED, "MQIAMO_SUBRQS_FAILED" },
/*  769*/ { MQ_MQIAMO_CBS, "MQIAMO_CBS" },
/*  770*/ { MQ_MQIAMO_CBS_FAILED, "MQIAMO_CBS_FAILED" },
/*  771*/ { MQ_MQIAMO_CTLS, "MQIAMO_CTLS" },
/*  772*/ { MQ_MQIAMO_CTLS_FAILED, "MQIAMO_CTLS_FAILED" },
/*  773*/ { MQ_MQIAMO_STATS, "MQIAMO_STATS" },
/*  774*/ { MQ_MQIAMO_STATS_FAILED, "MQIAMO_STATS_FAILED" },
/*  775*/ { MQ_MQIAMO_SUB_DUR_HIGHWATER, "MQIAMO_SUB_DUR_HIGHWATER" },
/*  776*/ { MQ_MQIAMO_SUB_DUR_LOWWATER, "MQIAMO_SUB_DUR_LOWWATER" },
/*  777*/ { MQ_MQIAMO_SUB_NDUR_HIGHWATER, "MQIAMO_SUB_NDUR_HIGHWATER" },
/*  778*/ { MQ_MQIAMO_SUB_NDUR_LOWWATER, "MQIAMO_SUB_NDUR_LOWWATER" },
/*  779*/ { MQ_MQIAMO_TOPIC_PUTS, "MQIAMO_TOPIC_PUTS" },
/*  780*/ { MQ_MQIAMO_TOPIC_PUTS_FAILED, "MQIAMO_TOPIC_PUTS_FAILED" },
/*  781*/ { MQ_MQIAMO_TOPIC_PUT1S, "MQIAMO_TOPIC_PUT1S" },
/*  782*/ { MQ_MQIAMO_TOPIC_PUT1S_FAILED, "MQIAMO_TOPIC_PUT1S_FAILED" },
/*  783*/ { MQ_MQIAMO64_TOPIC_PUT_BYTES, "MQIAMO64_TOPIC_PUT_BYTES" },
/*  784*/ { MQ_MQIAMO_PUBLISH_MSG_COUNT, "MQIAMO_PUBLISH_MSG_COUNT" },
/*  785*/ { MQ_MQIAMO64_PUBLISH_MSG_BYTES, "MQIAMO64_PUBLISH_MSG_BYTES" },
/*  786*/ { MQ_MQIAMO_UNSUBS_DUR, "MQIAMO_UNSUBS_DUR" },
/*  787*/ { MQ_MQIAMO_UNSUBS_NDUR, "MQIAMO_UNSUBS_NDUR" },
/*  788*/ { MQ_MQIAMO_UNSUBS_FAILED, "MQIAMO_UNSUBS_FAILED" },
/*  789*/ { MQ_MQIAMO_INTERVAL, "MQIAMO_INTERVAL" },
/*  790*/ { MQ_MQIAMO_MSGS_SENT, "MQIAMO_MSGS_SENT" },
/*  791*/ { MQ_MQIAMO_BYTES_SENT, "MQIAMO_BYTES_SENT" },
/*  792*/ { MQ_MQIAMO_REPAIR_BYTES, "MQIAMO_REPAIR_BYTES" },
/*  793*/ { MQ_MQIAMO_FEEDBACK_MODE, "MQIAMO_FEEDBACK_MODE" },
/*  794*/ { MQ_MQIAMO_RELIABILITY_TYPE, "MQIAMO_RELIABILITY_TYPE" },
/*  795*/ { MQ_MQIAMO_LATE_JOIN_MARK, "MQIAMO_LATE_JOIN_MARK" },
/*  796*/ { MQ_MQIAMO_NACKS_RCVD, "MQIAMO_NACKS_RCVD" },
/*  797*/ { MQ_MQIAMO_REPAIR_PKTS, "MQIAMO_REPAIR_PKTS" },
/*  798*/ { MQ_MQIAMO_HISTORY_PKTS, "MQIAMO_HISTORY_PKTS" },
/*  799*/ { MQ_MQIAMO_PENDING_PKTS, "MQIAMO_PENDING_PKTS" },
/*  800*/ { MQ_MQIAMO_PKT_RATE, "MQIAMO_PKT_RATE" },
/*  801*/ { MQ_MQIAMO_MCAST_XMIT_RATE, "MQIAMO_MCAST_XMIT_RATE" },
/*  802*/ { MQ_MQIAMO_MCAST_BATCH_TIME, "MQIAMO_MCAST_BATCH_TIME" },
/*  803*/ { MQ_MQIAMO_MCAST_HEARTBEAT, "MQIAMO_MCAST_HEARTBEAT" },
/*  804*/ { MQ_MQIAMO_DEST_DATA_PORT, "MQIAMO_DEST_DATA_PORT" },
/*  805*/ { MQ_MQIAMO_DEST_REPAIR_PORT, "MQIAMO_DEST_REPAIR_PORT" },
/*  806*/ { MQ_MQIAMO_ACKS_RCVD, "MQIAMO_ACKS_RCVD" },
/*  807*/ { MQ_MQIAMO_ACTIVE_ACKERS, "MQIAMO_ACTIVE_ACKERS" },
/*  808*/ { MQ_MQIAMO_PKTS_SENT, "MQIAMO_PKTS_SENT" },
/*  809*/ { MQ_MQIAMO_TOTAL_REPAIR_PKTS, "MQIAMO_TOTAL_REPAIR_PKTS" },
/*  810*/ { MQ_MQIAMO_TOTAL_PKTS_SENT, "MQIAMO_TOTAL_PKTS_SENT" },
/*  811*/ { MQ_MQIAMO_TOTAL_MSGS_SENT, "MQIAMO_TOTAL_MSGS_SENT" },
/*  812*/ { MQ_MQIAMO_TOTAL_BYTES_SENT, "MQIAMO_TOTAL_BYTES_SENT" },
/*  813*/ { MQ_MQIAMO_NUM_STREAMS, "MQIAMO_NUM_STREAMS" },
/*  814*/ { MQ_MQIAMO_ACK_FEEDBACK, "MQIAMO_ACK_FEEDBACK" },
/*  815*/ { MQ_MQIAMO_NACK_FEEDBACK, "MQIAMO_NACK_FEEDBACK" },
/*  816*/ { MQ_MQIAMO_PKTS_LOST, "MQIAMO_PKTS_LOST" },
/*  817*/ { MQ_MQIAMO_MSGS_RCVD, "MQIAMO_MSGS_RCVD" },
/*  818*/ { MQ_MQIAMO_MSG_BYTES_RCVD, "MQIAMO_MSG_BYTES_RCVD" },
/*  819*/ { MQ_MQIAMO_MSGS_DELIVERED, "MQIAMO_MSGS_DELIVERED" },
/*  820*/ { MQ_MQIAMO_PKTS_PROCESSED, "MQIAMO_PKTS_PROCESSED" },
/*  821*/ { MQ_MQIAMO_PKTS_DELIVERED, "MQIAMO_PKTS_DELIVERED" },
/*  822*/ { MQ_MQIAMO_PKTS_DROPPED, "MQIAMO_PKTS_DROPPED" },
/*  823*/ { MQ_MQIAMO_PKTS_DUPLICATED, "MQIAMO_PKTS_DUPLICATED" },
/*  824*/ { MQ_MQIAMO_NACKS_CREATED, "MQIAMO_NACKS_CREATED" },
/*  825*/ { MQ_MQIAMO_NACK_PKTS_SENT, "MQIAMO_NACK_PKTS_SENT" },
/*  826*/ { MQ_MQIAMO_REPAIR_PKTS_RQSTD, "MQIAMO_REPAIR_PKTS_RQSTD" },
/*  827*/ { MQ_MQIAMO_REPAIR_PKTS_RCVD, "MQIAMO_REPAIR_PKTS_RCVD" },
/*  828*/ { MQ_MQIAMO_PKTS_REPAIRED, "MQIAMO_PKTS_REPAIRED" },
/*  829*/ { MQ_MQIAMO_TOTAL_MSGS_RCVD, "MQIAMO_TOTAL_MSGS_RCVD" },
/*  830*/ { MQ_MQIAMO_TOTAL_MSG_BYTES_RCVD, "MQIAMO_TOTAL_MSG_BYTES_RCVD" },
/*  831*/ { MQ_MQIAMO_TOTAL_REPAIR_PKTS_RCVD, "MQIAMO_TOTAL_REPAIR_PKTS_RCVD" },
/*  832*/ { MQ_MQIAMO_TOTAL_REPAIR_PKTS_RQSTD, "MQIAMO_TOTAL_REPAIR_PKTS_RQSTD" },
/*  833*/ { MQ_MQIAMO_TOTAL_MSGS_PROCESSED, "MQIAMO_TOTAL_MSGS_PROCESSED" },
/*  834*/ { MQ_MQIAMO_TOTAL_MSGS_SELECTED, "MQIAMO_TOTAL_MSGS_SELECTED" },
/*  835*/ { MQ_MQIAMO_TOTAL_MSGS_EXPIRED, "MQIAMO_TOTAL_MSGS_EXPIRED" },
/*  836*/ { MQ_MQIAMO_TOTAL_MSGS_DELIVERED, "MQIAMO_TOTAL_MSGS_DELIVERED" },
/*  837*/ { MQ_MQIAMO_TOTAL_MSGS_RETURNED, "MQIAMO_TOTAL_MSGS_RETURNED" },
/*  838*/ { MQ_MQIAMO64_HIGHRES_TIME, "MQIAMO64_HIGHRES_TIME" },
/*  839*/ { MQ_MQIAMO_MONITOR_CLASS, "MQIAMO_MONITOR_CLASS" },
/*  840*/ { MQ_MQIAMO_MONITOR_TYPE, "MQIAMO_MONITOR_TYPE" },
/*  841*/ { MQ_MQIAMO_MONITOR_ELEMENT, "MQIAMO_MONITOR_ELEMENT" },
/*  842*/ { MQ_MQIAMO_MONITOR_DATATYPE, "MQIAMO_MONITOR_DATATYPE" },
/*  843*/ { MQ_MQIAMO_MONITOR_FLAGS, "MQIAMO_MONITOR_FLAGS" },
/*  844*/ { MQ_MQIAMO64_QMGR_OP_DURATION, "MQIAMO64_QMGR_OP_DURATION" },
/*  845*/ { MQ_MQIAMO64_MONITOR_INTERVAL, "MQIAMO64_MONITOR_INTERVAL" },
/* 1001*/ { MQ_MQIACF_Q_MGR_ATTRS, "MQIACF_Q_MGR_ATTRS" },
/* 1002*/ { MQ_MQIACF_Q_ATTRS, "MQIACF_Q_ATTRS" },
/* 1003*/ { MQ_MQIACF_PROCESS_ATTRS, "MQIACF_PROCESS_ATTRS" },
/* 1004*/ { MQ_MQIACF_NAMELIST_ATTRS, "MQIACF_NAMELIST_ATTRS" },
/* 1005*/ { MQ_MQIACF_FORCE, "MQIACF_FORCE" },
/* 1006*/ { MQ_MQIACF_REPLACE, "MQIACF_REPLACE" },
/* 1007*/ { MQ_MQIACF_PURGE, "MQIACF_PURGE" },
/* 1008 { MQ_MQIACF_MODE, "MQIACF_MODE" }, */
/* 1008*/ { MQ_MQIACF_QUIESCE, "MQIACF_QUIESCE" },
/* 1009*/ { MQ_MQIACF_ALL, "MQIACF_ALL" },
/* 1010*/ { MQ_MQIACF_EVENT_APPL_TYPE, "MQIACF_EVENT_APPL_TYPE" },
/* 1011*/ { MQ_MQIACF_EVENT_ORIGIN, "MQIACF_EVENT_ORIGIN" },
/* 1012*/ { MQ_MQIACF_PARAMETER_ID, "MQIACF_PARAMETER_ID" },
/* 1013*/ { MQ_MQIACF_ERROR_ID, "MQIACF_ERROR_ID" },
/* 1013   { MQ_MQIACF_ERROR_IDENTIFIER, "MQIACF_ERROR_IDENTIFIER" }, */
/* 1014*/ { MQ_MQIACF_SELECTOR, "MQIACF_SELECTOR" },
/* 1015*/ { MQ_MQIACF_CHANNEL_ATTRS, "MQIACF_CHANNEL_ATTRS" },
/* 1016*/ { MQ_MQIACF_OBJECT_TYPE, "MQIACF_OBJECT_TYPE" },
/* 1017*/ { MQ_MQIACF_ESCAPE_TYPE, "MQIACF_ESCAPE_TYPE" },
/* 1018*/ { MQ_MQIACF_ERROR_OFFSET, "MQIACF_ERROR_OFFSET" },
/* 1019*/ { MQ_MQIACF_AUTH_INFO_ATTRS, "MQIACF_AUTH_INFO_ATTRS" },
/* 1020*/ { MQ_MQIACF_REASON_QUALIFIER, "MQIACF_REASON_QUALIFIER" },
/* 1021*/ { MQ_MQIACF_COMMAND, "MQIACF_COMMAND" },
/* 1022*/ { MQ_MQIACF_OPEN_OPTIONS, "MQIACF_OPEN_OPTIONS" },
/* 1023*/ { MQ_MQIACF_OPEN_TYPE, "MQIACF_OPEN_TYPE" },
/* 1024*/ { MQ_MQIACF_PROCESS_ID, "MQIACF_PROCESS_ID" },
/* 1025*/ { MQ_MQIACF_THREAD_ID, "MQIACF_THREAD_ID" },
/* 1026*/ { MQ_MQIACF_Q_STATUS_ATTRS, "MQIACF_Q_STATUS_ATTRS" },
/* 1027*/ { MQ_MQIACF_UNCOMMITTED_MSGS, "MQIACF_UNCOMMITTED_MSGS" },
/* 1028*/ { MQ_MQIACF_HANDLE_STATE, "MQIACF_HANDLE_STATE" },
/* 1070*/ { MQ_MQIACF_AUX_ERROR_DATA_INT_1, "MQIACF_AUX_ERROR_DATA_INT_1" },
/* 1071*/ { MQ_MQIACF_AUX_ERROR_DATA_INT_2, "MQIACF_AUX_ERROR_DATA_INT_2" },
/* 1072*/ { MQ_MQIACF_CONV_REASON_CODE, "MQIACF_CONV_REASON_CODE" },
/* 1073*/ { MQ_MQIACF_BRIDGE_TYPE, "MQIACF_BRIDGE_TYPE" },
/* 1074*/ { MQ_MQIACF_INQUIRY, "MQIACF_INQUIRY" },
/* 1075*/ { MQ_MQIACF_WAIT_INTERVAL, "MQIACF_WAIT_INTERVAL" },
/* 1076*/ { MQ_MQIACF_OPTIONS, "MQIACF_OPTIONS" },
/* 1077*/ { MQ_MQIACF_BROKER_OPTIONS, "MQIACF_BROKER_OPTIONS" },
/* 1078*/ { MQ_MQIACF_REFRESH_TYPE, "MQIACF_REFRESH_TYPE" },
/* 1079*/ { MQ_MQIACF_SEQUENCE_NUMBER, "MQIACF_SEQUENCE_NUMBER" },
/* 1080*/ { MQ_MQIACF_INTEGER_DATA, "MQIACF_INTEGER_DATA" },
/* 1081*/ { MQ_MQIACF_REGISTRATION_OPTIONS, "MQIACF_REGISTRATION_OPTIONS" },
/* 1082*/ { MQ_MQIACF_PUBLICATION_OPTIONS, "MQIACF_PUBLICATION_OPTIONS" },
/* 1083*/ { MQ_MQIACF_CLUSTER_INFO, "MQIACF_CLUSTER_INFO" },
/* 1084*/ { MQ_MQIACF_Q_MGR_DEFINITION_TYPE, "MQIACF_Q_MGR_DEFINITION_TYPE" },
/* 1085*/ { MQ_MQIACF_Q_MGR_TYPE, "MQIACF_Q_MGR_TYPE" },
/* 1086*/ { MQ_MQIACF_ACTION, "MQIACF_ACTION" },
/* 1087*/ { MQ_MQIACF_SUSPEND, "MQIACF_SUSPEND" },
/* 1088*/ { MQ_MQIACF_BROKER_COUNT, "MQIACF_BROKER_COUNT" },
/* 1089*/ { MQ_MQIACF_APPL_COUNT, "MQIACF_APPL_COUNT" },
/* 1090*/ { MQ_MQIACF_ANONYMOUS_COUNT, "MQIACF_ANONYMOUS_COUNT" },
/* 1091*/ { MQ_MQIACF_REG_REG_OPTIONS, "MQIACF_REG_REG_OPTIONS" },
/* 1092*/ { MQ_MQIACF_DELETE_OPTIONS, "MQIACF_DELETE_OPTIONS" },
/* 1093*/ { MQ_MQIACF_CLUSTER_Q_MGR_ATTRS, "MQIACF_CLUSTER_Q_MGR_ATTRS" },
/* 1094*/ { MQ_MQIACF_REFRESH_INTERVAL, "MQIACF_REFRESH_INTERVAL" },
/* 1095*/ { MQ_MQIACF_REFRESH_REPOSITORY, "MQIACF_REFRESH_REPOSITORY" },
/* 1096*/ { MQ_MQIACF_REMOVE_QUEUES, "MQIACF_REMOVE_QUEUES" },
/* 1098*/ { MQ_MQIACF_OPEN_INPUT_TYPE, "MQIACF_OPEN_INPUT_TYPE" },
/* 1099*/ { MQ_MQIACF_OPEN_OUTPUT, "MQIACF_OPEN_OUTPUT" },
/* 1100*/ { MQ_MQIACF_OPEN_SET, "MQIACF_OPEN_SET" },
/* 1101*/ { MQ_MQIACF_OPEN_INQUIRE, "MQIACF_OPEN_INQUIRE" },
/* 1102*/ { MQ_MQIACF_OPEN_BROWSE, "MQIACF_OPEN_BROWSE" },
/* 1103*/ { MQ_MQIACF_Q_STATUS_TYPE, "MQIACF_Q_STATUS_TYPE" },
/* 1104*/ { MQ_MQIACF_Q_HANDLE, "MQIACF_Q_HANDLE" },
/* 1105*/ { MQ_MQIACF_Q_STATUS, "MQIACF_Q_STATUS" },
/* 1106*/ { MQ_MQIACF_SECURITY_TYPE, "MQIACF_SECURITY_TYPE" },
/* 1107*/ { MQ_MQIACF_CONNECTION_ATTRS, "MQIACF_CONNECTION_ATTRS" },
/* 1108*/ { MQ_MQIACF_CONNECT_OPTIONS, "MQIACF_CONNECT_OPTIONS" },
/* 1110*/ { MQ_MQIACF_CONN_INFO_TYPE, "MQIACF_CONN_INFO_TYPE" },
/* 1111*/ { MQ_MQIACF_CONN_INFO_CONN, "MQIACF_CONN_INFO_CONN" },
/* 1112*/ { MQ_MQIACF_CONN_INFO_HANDLE, "MQIACF_CONN_INFO_HANDLE" },
/* 1113*/ { MQ_MQIACF_CONN_INFO_ALL, "MQIACF_CONN_INFO_ALL" },
/* 1114*/ { MQ_MQIACF_AUTH_PROFILE_ATTRS, "MQIACF_AUTH_PROFILE_ATTRS" },
/* 1115*/ { MQ_MQIACF_AUTHORIZATION_LIST, "MQIACF_AUTHORIZATION_LIST" },
/* 1116*/ { MQ_MQIACF_AUTH_ADD_AUTHS, "MQIACF_AUTH_ADD_AUTHS" },
/* 1117*/ { MQ_MQIACF_AUTH_REMOVE_AUTHS, "MQIACF_AUTH_REMOVE_AUTHS" },
/* 1118*/ { MQ_MQIACF_ENTITY_TYPE, "MQIACF_ENTITY_TYPE" },
/* 1120*/ { MQ_MQIACF_COMMAND_INFO, "MQIACF_COMMAND_INFO" },
/* 1121*/ { MQ_MQIACF_CMDSCOPE_Q_MGR_COUNT, "MQIACF_CMDSCOPE_Q_MGR_COUNT" },
/* 1122*/ { MQ_MQIACF_Q_MGR_SYSTEM, "MQIACF_Q_MGR_SYSTEM" },
/* 1123*/ { MQ_MQIACF_Q_MGR_EVENT, "MQIACF_Q_MGR_EVENT" },
/* 1124*/ { MQ_MQIACF_Q_MGR_DQM, "MQIACF_Q_MGR_DQM" },
/* 1125*/ { MQ_MQIACF_Q_MGR_CLUSTER, "MQIACF_Q_MGR_CLUSTER" },
/* 1126*/ { MQ_MQIACF_QSG_DISPS, "MQIACF_QSG_DISPS" },
/* 1128*/ { MQ_MQIACF_UOW_STATE, "MQIACF_UOW_STATE" },
/* 1129*/ { MQ_MQIACF_SECURITY_ITEM, "MQIACF_SECURITY_ITEM" },
/* 1130*/ { MQ_MQIACF_CF_STRUC_STATUS, "MQIACF_CF_STRUC_STATUS" },
/* 1132*/ { MQ_MQIACF_UOW_TYPE, "MQIACF_UOW_TYPE" },
/* 1133*/ { MQ_MQIACF_CF_STRUC_ATTRS, "MQIACF_CF_STRUC_ATTRS" },
/* 1134*/ { MQ_MQIACF_EXCLUDE_INTERVAL, "MQIACF_EXCLUDE_INTERVAL" },
/* 1135*/ { MQ_MQIACF_CF_STATUS_TYPE, "MQIACF_CF_STATUS_TYPE" },
/* 1136*/ { MQ_MQIACF_CF_STATUS_SUMMARY, "MQIACF_CF_STATUS_SUMMARY" },
/* 1137*/ { MQ_MQIACF_CF_STATUS_CONNECT, "MQIACF_CF_STATUS_CONNECT" },
/* 1138*/ { MQ_MQIACF_CF_STATUS_BACKUP, "MQIACF_CF_STATUS_BACKUP" },
/* 1139*/ { MQ_MQIACF_CF_STRUC_TYPE, "MQIACF_CF_STRUC_TYPE" },
/* 1140*/ { MQ_MQIACF_CF_STRUC_SIZE_MAX, "MQIACF_CF_STRUC_SIZE_MAX" },
/* 1141*/ { MQ_MQIACF_CF_STRUC_SIZE_USED, "MQIACF_CF_STRUC_SIZE_USED" },
/* 1142*/ { MQ_MQIACF_CF_STRUC_ENTRIES_MAX, "MQIACF_CF_STRUC_ENTRIES_MAX" },
/* 1143*/ { MQ_MQIACF_CF_STRUC_ENTRIES_USED, "MQIACF_CF_STRUC_ENTRIES_USED" },
/* 1144*/ { MQ_MQIACF_CF_STRUC_BACKUP_SIZE, "MQIACF_CF_STRUC_BACKUP_SIZE" },
/* 1145*/ { MQ_MQIACF_MOVE_TYPE, "MQIACF_MOVE_TYPE" },
/* 1146*/ { MQ_MQIACF_MOVE_TYPE_MOVE, "MQIACF_MOVE_TYPE_MOVE" },
/* 1147*/ { MQ_MQIACF_MOVE_TYPE_ADD, "MQIACF_MOVE_TYPE_ADD" },
/* 1148*/ { MQ_MQIACF_Q_MGR_NUMBER, "MQIACF_Q_MGR_NUMBER" },
/* 1149*/ { MQ_MQIACF_Q_MGR_STATUS, "MQIACF_Q_MGR_STATUS" },
/* 1150*/ { MQ_MQIACF_DB2_CONN_STATUS, "MQIACF_DB2_CONN_STATUS" },
/* 1151*/ { MQ_MQIACF_SECURITY_ATTRS, "MQIACF_SECURITY_ATTRS" },
/* 1152*/ { MQ_MQIACF_SECURITY_TIMEOUT, "MQIACF_SECURITY_TIMEOUT" },
/* 1153*/ { MQ_MQIACF_SECURITY_INTERVAL, "MQIACF_SECURITY_INTERVAL" },
/* 1154*/ { MQ_MQIACF_SECURITY_SWITCH, "MQIACF_SECURITY_SWITCH" },
/* 1155*/ { MQ_MQIACF_SECURITY_SETTING, "MQIACF_SECURITY_SETTING" },
/* 1156*/ { MQ_MQIACF_STORAGE_CLASS_ATTRS, "MQIACF_STORAGE_CLASS_ATTRS" },
/* 1157*/ { MQ_MQIACF_USAGE_TYPE, "MQIACF_USAGE_TYPE" },
/* 1158*/ { MQ_MQIACF_BUFFER_POOL_ID, "MQIACF_BUFFER_POOL_ID" },
/* 1159*/ { MQ_MQIACF_USAGE_TOTAL_PAGES, "MQIACF_USAGE_TOTAL_PAGES" },
/* 1160*/ { MQ_MQIACF_USAGE_UNUSED_PAGES, "MQIACF_USAGE_UNUSED_PAGES" },
/* 1161*/ { MQ_MQIACF_USAGE_PERSIST_PAGES, "MQIACF_USAGE_PERSIST_PAGES" },
/* 1162*/ { MQ_MQIACF_USAGE_NONPERSIST_PAGES, "MQIACF_USAGE_NONPERSIST_PAGES" },
/* 1163*/ { MQ_MQIACF_USAGE_RESTART_EXTENTS, "MQIACF_USAGE_RESTART_EXTENTS" },
/* 1164*/ { MQ_MQIACF_USAGE_EXPAND_COUNT, "MQIACF_USAGE_EXPAND_COUNT" },
/* 1165*/ { MQ_MQIACF_PAGESET_STATUS, "MQIACF_PAGESET_STATUS" },
/* 1166*/ { MQ_MQIACF_USAGE_TOTAL_BUFFERS, "MQIACF_USAGE_TOTAL_BUFFERS" },
/* 1167*/ { MQ_MQIACF_USAGE_DATA_SET_TYPE, "MQIACF_USAGE_DATA_SET_TYPE" },
/* 1168*/ { MQ_MQIACF_USAGE_PAGESET, "MQIACF_USAGE_PAGESET" },
/* 1169*/ { MQ_MQIACF_USAGE_DATA_SET, "MQIACF_USAGE_DATA_SET" },
/* 1170*/ { MQ_MQIACF_USAGE_BUFFER_POOL, "MQIACF_USAGE_BUFFER_POOL" },
/* 1171*/ { MQ_MQIACF_MOVE_COUNT, "MQIACF_MOVE_COUNT" },
/* 1172*/ { MQ_MQIACF_EXPIRY_Q_COUNT, "MQIACF_EXPIRY_Q_COUNT" },
/* 1173*/ { MQ_MQIACF_CONFIGURATION_OBJECTS, "MQIACF_CONFIGURATION_OBJECTS" },
/* 1174*/ { MQ_MQIACF_CONFIGURATION_EVENTS, "MQIACF_CONFIGURATION_EVENTS" },
/* 1175*/ { MQ_MQIACF_SYSP_TYPE, "MQIACF_SYSP_TYPE" },
/* 1176*/ { MQ_MQIACF_SYSP_DEALLOC_INTERVAL, "MQIACF_SYSP_DEALLOC_INTERVAL" },
/* 1177*/ { MQ_MQIACF_SYSP_MAX_ARCHIVE, "MQIACF_SYSP_MAX_ARCHIVE" },
/* 1178*/ { MQ_MQIACF_SYSP_MAX_READ_TAPES, "MQIACF_SYSP_MAX_READ_TAPES" },
/* 1179*/ { MQ_MQIACF_SYSP_IN_BUFFER_SIZE, "MQIACF_SYSP_IN_BUFFER_SIZE" },
/* 1180*/ { MQ_MQIACF_SYSP_OUT_BUFFER_SIZE, "MQIACF_SYSP_OUT_BUFFER_SIZE" },
/* 1181*/ { MQ_MQIACF_SYSP_OUT_BUFFER_COUNT, "MQIACF_SYSP_OUT_BUFFER_COUNT" },
/* 1182*/ { MQ_MQIACF_SYSP_ARCHIVE, "MQIACF_SYSP_ARCHIVE" },
/* 1183*/ { MQ_MQIACF_SYSP_DUAL_ACTIVE, "MQIACF_SYSP_DUAL_ACTIVE" },
/* 1184*/ { MQ_MQIACF_SYSP_DUAL_ARCHIVE, "MQIACF_SYSP_DUAL_ARCHIVE" },
/* 1185*/ { MQ_MQIACF_SYSP_DUAL_BSDS, "MQIACF_SYSP_DUAL_BSDS" },
/* 1186*/ { MQ_MQIACF_SYSP_MAX_CONNS, "MQIACF_SYSP_MAX_CONNS" },
/* 1187*/ { MQ_MQIACF_SYSP_MAX_CONNS_FORE, "MQIACF_SYSP_MAX_CONNS_FORE" },
/* 1188*/ { MQ_MQIACF_SYSP_MAX_CONNS_BACK, "MQIACF_SYSP_MAX_CONNS_BACK" },
/* 1189*/ { MQ_MQIACF_SYSP_EXIT_INTERVAL, "MQIACF_SYSP_EXIT_INTERVAL" },
/* 1190*/ { MQ_MQIACF_SYSP_EXIT_TASKS, "MQIACF_SYSP_EXIT_TASKS" },
/* 1191*/ { MQ_MQIACF_SYSP_CHKPOINT_COUNT, "MQIACF_SYSP_CHKPOINT_COUNT" },
/* 1192*/ { MQ_MQIACF_SYSP_OTMA_INTERVAL, "MQIACF_SYSP_OTMA_INTERVAL" },
/* 1193*/ { MQ_MQIACF_SYSP_Q_INDEX_DEFER, "MQIACF_SYSP_Q_INDEX_DEFER" },
/* 1194*/ { MQ_MQIACF_SYSP_DB2_TASKS, "MQIACF_SYSP_DB2_TASKS" },
/* 1195*/ { MQ_MQIACF_SYSP_RESLEVEL_AUDIT, "MQIACF_SYSP_RESLEVEL_AUDIT" },
/* 1196*/ { MQ_MQIACF_SYSP_ROUTING_CODE, "MQIACF_SYSP_ROUTING_CODE" },
/* 1197*/ { MQ_MQIACF_SYSP_SMF_ACCOUNTING, "MQIACF_SYSP_SMF_ACCOUNTING" },
/* 1198*/ { MQ_MQIACF_SYSP_SMF_STATS, "MQIACF_SYSP_SMF_STATS" },
/* 1199*/ { MQ_MQIACF_SYSP_SMF_STAT_TIME_MINS, "MQIACF_SYSP_SMF_STAT_TIME_MINS" },
/* 1200*/ { MQ_MQIACF_SYSP_TRACE_CLASS, "MQIACF_SYSP_TRACE_CLASS" },
/* 1201*/ { MQ_MQIACF_SYSP_TRACE_SIZE, "MQIACF_SYSP_TRACE_SIZE" },
/* 1202*/ { MQ_MQIACF_SYSP_WLM_INTERVAL, "MQIACF_SYSP_WLM_INTERVAL" },
/* 1203*/ { MQ_MQIACF_SYSP_ALLOC_UNIT, "MQIACF_SYSP_ALLOC_UNIT" },
/* 1204*/ { MQ_MQIACF_SYSP_ARCHIVE_RETAIN, "MQIACF_SYSP_ARCHIVE_RETAIN" },
/* 1205*/ { MQ_MQIACF_SYSP_ARCHIVE_WTOR, "MQIACF_SYSP_ARCHIVE_WTOR" },
/* 1206*/ { MQ_MQIACF_SYSP_BLOCK_SIZE, "MQIACF_SYSP_BLOCK_SIZE" },
/* 1207*/ { MQ_MQIACF_SYSP_CATALOG, "MQIACF_SYSP_CATALOG" },
/* 1208*/ { MQ_MQIACF_SYSP_COMPACT, "MQIACF_SYSP_COMPACT" },
/* 1209*/ { MQ_MQIACF_SYSP_ALLOC_PRIMARY, "MQIACF_SYSP_ALLOC_PRIMARY" },
/* 1210*/ { MQ_MQIACF_SYSP_ALLOC_SECONDARY, "MQIACF_SYSP_ALLOC_SECONDARY" },
/* 1211*/ { MQ_MQIACF_SYSP_PROTECT, "MQIACF_SYSP_PROTECT" },
/* 1212*/ { MQ_MQIACF_SYSP_QUIESCE_INTERVAL, "MQIACF_SYSP_QUIESCE_INTERVAL" },
/* 1213*/ { MQ_MQIACF_SYSP_TIMESTAMP, "MQIACF_SYSP_TIMESTAMP" },
/* 1214*/ { MQ_MQIACF_SYSP_UNIT_ADDRESS, "MQIACF_SYSP_UNIT_ADDRESS" },
/* 1215*/ { MQ_MQIACF_SYSP_UNIT_STATUS, "MQIACF_SYSP_UNIT_STATUS" },
/* 1216*/ { MQ_MQIACF_SYSP_LOG_COPY, "MQIACF_SYSP_LOG_COPY" },
/* 1217*/ { MQ_MQIACF_SYSP_LOG_USED, "MQIACF_SYSP_LOG_USED" },
/* 1218*/ { MQ_MQIACF_SYSP_LOG_SUSPEND, "MQIACF_SYSP_LOG_SUSPEND" },
/* 1219*/ { MQ_MQIACF_SYSP_OFFLOAD_STATUS, "MQIACF_SYSP_OFFLOAD_STATUS" },
/* 1220*/ { MQ_MQIACF_SYSP_TOTAL_LOGS, "MQIACF_SYSP_TOTAL_LOGS" },
/* 1221*/ { MQ_MQIACF_SYSP_FULL_LOGS, "MQIACF_SYSP_FULL_LOGS" },
/* 1222*/ { MQ_MQIACF_LISTENER_ATTRS, "MQIACF_LISTENER_ATTRS" },
/* 1223*/ { MQ_MQIACF_LISTENER_STATUS_ATTRS, "MQIACF_LISTENER_STATUS_ATTRS" },
/* 1224*/ { MQ_MQIACF_SERVICE_ATTRS, "MQIACF_SERVICE_ATTRS" },
/* 1225*/ { MQ_MQIACF_SERVICE_STATUS_ATTRS, "MQIACF_SERVICE_STATUS_ATTRS" },
/* 1226*/ { MQ_MQIACF_Q_TIME_INDICATOR, "MQIACF_Q_TIME_INDICATOR" },
/* 1227*/ { MQ_MQIACF_OLDEST_MSG_AGE, "MQIACF_OLDEST_MSG_AGE" },
/* 1228*/ { MQ_MQIACF_AUTH_OPTIONS, "MQIACF_AUTH_OPTIONS" },
/* 1229*/ { MQ_MQIACF_Q_MGR_STATUS_ATTRS, "MQIACF_Q_MGR_STATUS_ATTRS" },
/* 1230*/ { MQ_MQIACF_CONNECTION_COUNT, "MQIACF_CONNECTION_COUNT" },
/* 1231*/ { MQ_MQIACF_Q_MGR_FACILITY, "MQIACF_Q_MGR_FACILITY" },
/* 1232*/ { MQ_MQIACF_CHINIT_STATUS, "MQIACF_CHINIT_STATUS" },
/* 1233*/ { MQ_MQIACF_CMD_SERVER_STATUS, "MQIACF_CMD_SERVER_STATUS" },
/* 1234*/ { MQ_MQIACF_ROUTE_DETAIL, "MQIACF_ROUTE_DETAIL" },
/* 1235*/ { MQ_MQIACF_RECORDED_ACTIVITIES, "MQIACF_RECORDED_ACTIVITIES" },
/* 1236*/ { MQ_MQIACF_MAX_ACTIVITIES, "MQIACF_MAX_ACTIVITIES" },
/* 1237*/ { MQ_MQIACF_DISCONTINUITY_COUNT, "MQIACF_DISCONTINUITY_COUNT" },
/* 1238*/ { MQ_MQIACF_ROUTE_ACCUMULATION, "MQIACF_ROUTE_ACCUMULATION" },
/* 1239*/ { MQ_MQIACF_ROUTE_DELIVERY, "MQIACF_ROUTE_DELIVERY" },
/* 1240*/ { MQ_MQIACF_OPERATION_TYPE, "MQIACF_OPERATION_TYPE" },
/* 1241*/ { MQ_MQIACF_BACKOUT_COUNT, "MQIACF_BACKOUT_COUNT" },
/* 1242*/ { MQ_MQIACF_COMP_CODE, "MQIACF_COMP_CODE" },
/* 1243*/ { MQ_MQIACF_ENCODING, "MQIACF_ENCODING" },
/* 1244*/ { MQ_MQIACF_EXPIRY, "MQIACF_EXPIRY" },
/* 1245*/ { MQ_MQIACF_FEEDBACK, "MQIACF_FEEDBACK" },
/* 1247*/ { MQ_MQIACF_MSG_FLAGS, "MQIACF_MSG_FLAGS" },
/* 1248*/ { MQ_MQIACF_MSG_LENGTH, "MQIACF_MSG_LENGTH" },
/* 1249*/ { MQ_MQIACF_MSG_TYPE, "MQIACF_MSG_TYPE" },
/* 1250*/ { MQ_MQIACF_OFFSET, "MQIACF_OFFSET" },
/* 1251*/ { MQ_MQIACF_ORIGINAL_LENGTH, "MQIACF_ORIGINAL_LENGTH" },
/* 1252*/ { MQ_MQIACF_PERSISTENCE, "MQIACF_PERSISTENCE" },
/* 1253*/ { MQ_MQIACF_PRIORITY, "MQIACF_PRIORITY" },
/* 1254*/ { MQ_MQIACF_REASON_CODE, "MQIACF_REASON_CODE" },
/* 1255*/ { MQ_MQIACF_REPORT, "MQIACF_REPORT" },
/* 1256*/ { MQ_MQIACF_VERSION, "MQIACF_VERSION" },
/* 1257*/ { MQ_MQIACF_UNRECORDED_ACTIVITIES, "MQIACF_UNRECORDED_ACTIVITIES" },
/* 1258*/ { MQ_MQIACF_MONITORING, "MQIACF_MONITORING" },
/* 1259*/ { MQ_MQIACF_ROUTE_FORWARDING, "MQIACF_ROUTE_FORWARDING" },
/* 1260*/ { MQ_MQIACF_SERVICE_STATUS, "MQIACF_SERVICE_STATUS" },
/* 1261*/ { MQ_MQIACF_Q_TYPES, "MQIACF_Q_TYPES" },
/* 1262*/ { MQ_MQIACF_USER_ID_SUPPORT, "MQIACF_USER_ID_SUPPORT" },
/* 1263*/ { MQ_MQIACF_INTERFACE_VERSION, "MQIACF_INTERFACE_VERSION" },
/* 1264*/ { MQ_MQIACF_AUTH_SERVICE_ATTRS, "MQIACF_AUTH_SERVICE_ATTRS" },
/* 1265*/ { MQ_MQIACF_USAGE_EXPAND_TYPE, "MQIACF_USAGE_EXPAND_TYPE" },
/* 1266*/ { MQ_MQIACF_SYSP_CLUSTER_CACHE, "MQIACF_SYSP_CLUSTER_CACHE" },
/* 1267*/ { MQ_MQIACF_SYSP_DB2_BLOB_TASKS, "MQIACF_SYSP_DB2_BLOB_TASKS" },
/* 1268*/ { MQ_MQIACF_SYSP_WLM_INT_UNITS, "MQIACF_SYSP_WLM_INT_UNITS" },
/* 1269*/ { MQ_MQIACF_TOPIC_ATTRS, "MQIACF_TOPIC_ATTRS" },
/* 1271*/ { MQ_MQIACF_PUBSUB_PROPERTIES, "MQIACF_PUBSUB_PROPERTIES" },
/* 1273*/ { MQ_MQIACF_DESTINATION_CLASS, "MQIACF_DESTINATION_CLASS" },
/* 1274*/ { MQ_MQIACF_DURABLE_SUBSCRIPTION, "MQIACF_DURABLE_SUBSCRIPTION" },
/* 1275*/ { MQ_MQIACF_SUBSCRIPTION_SCOPE, "MQIACF_SUBSCRIPTION_SCOPE" },
/* 1277*/ { MQ_MQIACF_VARIABLE_USER_ID, "MQIACF_VARIABLE_USER_ID" },
/* 1280*/ { MQ_MQIACF_REQUEST_ONLY, "MQIACF_REQUEST_ONLY" },
/* 1283*/ { MQ_MQIACF_PUB_PRIORITY, "MQIACF_PUB_PRIORITY" },
/* 1287*/ { MQ_MQIACF_SUB_ATTRS, "MQIACF_SUB_ATTRS" },
/* 1288*/ { MQ_MQIACF_WILDCARD_SCHEMA, "MQIACF_WILDCARD_SCHEMA" },
/* 1289*/ { MQ_MQIACF_SUB_TYPE, "MQIACF_SUB_TYPE" },
/* 1290*/ { MQ_MQIACF_MESSAGE_COUNT, "MQIACF_MESSAGE_COUNT" },
/* 1291*/ { MQ_MQIACF_Q_MGR_PUBSUB, "MQIACF_Q_MGR_PUBSUB" },
/* 1292*/ { MQ_MQIACF_Q_MGR_VERSION, "MQIACF_Q_MGR_VERSION" },
/* 1294*/ { MQ_MQIACF_SUB_STATUS_ATTRS, "MQIACF_SUB_STATUS_ATTRS" },
/* 1295*/ { MQ_MQIACF_TOPIC_STATUS, "MQIACF_TOPIC_STATUS" },
/* 1296*/ { MQ_MQIACF_TOPIC_SUB, "MQIACF_TOPIC_SUB" },
/* 1297*/ { MQ_MQIACF_TOPIC_PUB, "MQIACF_TOPIC_PUB" },
/* 1300*/ { MQ_MQIACF_RETAINED_PUBLICATION, "MQIACF_RETAINED_PUBLICATION" },
/* 1301*/ { MQ_MQIACF_TOPIC_STATUS_ATTRS, "MQIACF_TOPIC_STATUS_ATTRS" },
/* 1302*/ { MQ_MQIACF_TOPIC_STATUS_TYPE, "MQIACF_TOPIC_STATUS_TYPE" },
/* 1303*/ { MQ_MQIACF_SUB_OPTIONS, "MQIACF_SUB_OPTIONS" },
/* 1304*/ { MQ_MQIACF_PUBLISH_COUNT, "MQIACF_PUBLISH_COUNT" },
/* 1305*/ { MQ_MQIACF_CLEAR_TYPE, "MQIACF_CLEAR_TYPE" },
/* 1306*/ { MQ_MQIACF_CLEAR_SCOPE, "MQIACF_CLEAR_SCOPE" },
/* 1307*/ { MQ_MQIACF_SUB_LEVEL, "MQIACF_SUB_LEVEL" },
/* 1308*/ { MQ_MQIACF_ASYNC_STATE, "MQIACF_ASYNC_STATE" },
/* 1309*/ { MQ_MQIACF_SUB_SUMMARY, "MQIACF_SUB_SUMMARY" },
/* 1310*/ { MQ_MQIACF_OBSOLETE_MSGS, "MQIACF_OBSOLETE_MSGS" },
/* 1311*/ { MQ_MQIACF_PUBSUB_STATUS, "MQIACF_PUBSUB_STATUS" },
/* 1314*/ { MQ_MQIACF_PS_STATUS_TYPE, "MQIACF_PS_STATUS_TYPE" },
/* 1318*/ { MQ_MQIACF_PUBSUB_STATUS_ATTRS, "MQIACF_PUBSUB_STATUS_ATTRS" },
/* 1321*/ { MQ_MQIACF_SELECTOR_TYPE, "MQIACF_SELECTOR_TYPE" },
/* 1322*/ { MQ_MQIACF_LOG_COMPRESSION, "MQIACF_LOG_COMPRESSION" },
/* 1323*/ { MQ_MQIACF_GROUPUR_CHECK_ID, "MQIACF_GROUPUR_CHECK_ID" },
/* 1324*/ { MQ_MQIACF_MULC_CAPTURE, "MQIACF_MULC_CAPTURE" },
/* 1325*/ { MQ_MQIACF_PERMIT_STANDBY, "MQIACF_PERMIT_STANDBY" },
/* 1326*/ { MQ_MQIACF_OPERATION_MODE, "MQIACF_OPERATION_MODE" },
/* 1327*/ { MQ_MQIACF_COMM_INFO_ATTRS, "MQIACF_COMM_INFO_ATTRS" },
/* 1328*/ { MQ_MQIACF_CF_SMDS_BLOCK_SIZE, "MQIACF_CF_SMDS_BLOCK_SIZE" },
/* 1329*/ { MQ_MQIACF_CF_SMDS_EXPAND, "MQIACF_CF_SMDS_EXPAND" },
/* 1330*/ { MQ_MQIACF_USAGE_FREE_BUFF, "MQIACF_USAGE_FREE_BUFF" },
/* 1331*/ { MQ_MQIACF_USAGE_FREE_BUFF_PERC, "MQIACF_USAGE_FREE_BUFF_PERC" },
/* 1332*/ { MQ_MQIACF_CF_STRUC_ACCESS, "MQIACF_CF_STRUC_ACCESS" },
/* 1333*/ { MQ_MQIACF_CF_STATUS_SMDS, "MQIACF_CF_STATUS_SMDS" },
/* 1334*/ { MQ_MQIACF_SMDS_ATTRS, "MQIACF_SMDS_ATTRS" },
/* 1335*/ { MQ_MQIACF_USAGE_SMDS, "MQIACF_USAGE_SMDS" },
/* 1336*/ { MQ_MQIACF_USAGE_BLOCK_SIZE, "MQIACF_USAGE_BLOCK_SIZE" },
/* 1337*/ { MQ_MQIACF_USAGE_DATA_BLOCKS, "MQIACF_USAGE_DATA_BLOCKS" },
/* 1338*/ { MQ_MQIACF_USAGE_EMPTY_BUFFERS, "MQIACF_USAGE_EMPTY_BUFFERS" },
/* 1339*/ { MQ_MQIACF_USAGE_INUSE_BUFFERS, "MQIACF_USAGE_INUSE_BUFFERS" },
/* 1340*/ { MQ_MQIACF_USAGE_LOWEST_FREE, "MQIACF_USAGE_LOWEST_FREE" },
/* 1341*/ { MQ_MQIACF_USAGE_OFFLOAD_MSGS, "MQIACF_USAGE_OFFLOAD_MSGS" },
/* 1342*/ { MQ_MQIACF_USAGE_READS_SAVED, "MQIACF_USAGE_READS_SAVED" },
/* 1343*/ { MQ_MQIACF_USAGE_SAVED_BUFFERS, "MQIACF_USAGE_SAVED_BUFFERS" },
/* 1344*/ { MQ_MQIACF_USAGE_TOTAL_BLOCKS, "MQIACF_USAGE_TOTAL_BLOCKS" },
/* 1345*/ { MQ_MQIACF_USAGE_USED_BLOCKS, "MQIACF_USAGE_USED_BLOCKS" },
/* 1346*/ { MQ_MQIACF_USAGE_USED_RATE, "MQIACF_USAGE_USED_RATE" },
/* 1347*/ { MQ_MQIACF_USAGE_WAIT_RATE, "MQIACF_USAGE_WAIT_RATE" },
/* 1348*/ { MQ_MQIACF_SMDS_OPENMODE, "MQIACF_SMDS_OPENMODE" },
/* 1349*/ { MQ_MQIACF_SMDS_STATUS, "MQIACF_SMDS_STATUS" },
/* 1350*/ { MQ_MQIACF_SMDS_AVAIL, "MQIACF_SMDS_AVAIL" },
/* 1351*/ { MQ_MQIACF_MCAST_REL_INDICATOR, "MQIACF_MCAST_REL_INDICATOR" },
/* 1352*/ { MQ_MQIACF_CHLAUTH_TYPE, "MQIACF_CHLAUTH_TYPE" },
/* 1354*/ { MQ_MQIACF_MQXR_DIAGNOSTICS_TYPE, "MQIACF_MQXR_DIAGNOSTICS_TYPE" },
/* 1355*/ { MQ_MQIACF_CHLAUTH_ATTRS, "MQIACF_CHLAUTH_ATTRS" },
/* 1356*/ { MQ_MQIACF_OPERATION_ID, "MQIACF_OPERATION_ID" },
/* 1357*/ { MQ_MQIACF_API_CALLER_TYPE, "MQIACF_API_CALLER_TYPE" },
/* 1358*/ { MQ_MQIACF_API_ENVIRONMENT, "MQIACF_API_ENVIRONMENT" },
/* 1359*/ { MQ_MQIACF_TRACE_DETAIL, "MQIACF_TRACE_DETAIL" },
/* 1360*/ { MQ_MQIACF_HOBJ, "MQIACF_HOBJ" },
/* 1361*/ { MQ_MQIACF_CALL_TYPE, "MQIACF_CALL_TYPE" },
/* 1362*/ { MQ_MQIACF_MQCB_OPERATION, "MQIACF_MQCB_OPERATION" },
/* 1363*/ { MQ_MQIACF_MQCB_TYPE, "MQIACF_MQCB_TYPE" },
/* 1364*/ { MQ_MQIACF_MQCB_OPTIONS, "MQIACF_MQCB_OPTIONS" },
/* 1365*/ { MQ_MQIACF_CLOSE_OPTIONS, "MQIACF_CLOSE_OPTIONS" },
/* 1366*/ { MQ_MQIACF_CTL_OPERATION, "MQIACF_CTL_OPERATION" },
/* 1367*/ { MQ_MQIACF_GET_OPTIONS, "MQIACF_GET_OPTIONS" },
/* 1368*/ { MQ_MQIACF_RECS_PRESENT, "MQIACF_RECS_PRESENT" },
/* 1369*/ { MQ_MQIACF_KNOWN_DEST_COUNT, "MQIACF_KNOWN_DEST_COUNT" },
/* 1370*/ { MQ_MQIACF_UNKNOWN_DEST_COUNT, "MQIACF_UNKNOWN_DEST_COUNT" },
/* 1371*/ { MQ_MQIACF_INVALID_DEST_COUNT, "MQIACF_INVALID_DEST_COUNT" },
/* 1372*/ { MQ_MQIACF_RESOLVED_TYPE, "MQIACF_RESOLVED_TYPE" },
/* 1373*/ { MQ_MQIACF_PUT_OPTIONS, "MQIACF_PUT_OPTIONS" },
/* 1374*/ { MQ_MQIACF_BUFFER_LENGTH, "MQIACF_BUFFER_LENGTH" },
/* 1375*/ { MQ_MQIACF_TRACE_DATA_LENGTH, "MQIACF_TRACE_DATA_LENGTH" },
/* 1376*/ { MQ_MQIACF_SMDS_EXPANDST, "MQIACF_SMDS_EXPANDST" },
/* 1377*/ { MQ_MQIACF_STRUC_LENGTH, "MQIACF_STRUC_LENGTH" },
/* 1378*/ { MQ_MQIACF_ITEM_COUNT, "MQIACF_ITEM_COUNT" },
/* 1379*/ { MQ_MQIACF_EXPIRY_TIME, "MQIACF_EXPIRY_TIME" },
/* 1380*/ { MQ_MQIACF_CONNECT_TIME, "MQIACF_CONNECT_TIME" },
/* 1381*/ { MQ_MQIACF_DISCONNECT_TIME, "MQIACF_DISCONNECT_TIME" },
/* 1382*/ { MQ_MQIACF_HSUB, "MQIACF_HSUB" },
/* 1383*/ { MQ_MQIACF_SUBRQ_OPTIONS, "MQIACF_SUBRQ_OPTIONS" },
/* 1384*/ { MQ_MQIACF_XA_RMID, "MQIACF_XA_RMID" },
/* 1385*/ { MQ_MQIACF_XA_FLAGS, "MQIACF_XA_FLAGS" },
/* 1386*/ { MQ_MQIACF_XA_RETCODE, "MQIACF_XA_RETCODE" },
/* 1387*/ { MQ_MQIACF_XA_HANDLE, "MQIACF_XA_HANDLE" },
/* 1388*/ { MQ_MQIACF_XA_RETVAL, "MQIACF_XA_RETVAL" },
/* 1389*/ { MQ_MQIACF_STATUS_TYPE, "MQIACF_STATUS_TYPE" },
/* 1390*/ { MQ_MQIACF_XA_COUNT, "MQIACF_XA_COUNT" },
/* 1391*/ { MQ_MQIACF_SELECTOR_COUNT, "MQIACF_SELECTOR_COUNT" },
/* 1392*/ { MQ_MQIACF_SELECTORS, "MQIACF_SELECTORS" },
/* 1393*/ { MQ_MQIACF_INTATTR_COUNT, "MQIACF_INTATTR_COUNT" },
/* 1394*/ { MQ_MQIACF_INT_ATTRS, "MQIACF_INT_ATTRS" },
/* 1395*/ { MQ_MQIACF_SUBRQ_ACTION, "MQIACF_SUBRQ_ACTION" },
/* 1396*/ { MQ_MQIACF_NUM_PUBS, "MQIACF_NUM_PUBS" },
/* 1397*/ { MQ_MQIACF_POINTER_SIZE, "MQIACF_POINTER_SIZE" },
/* 1398*/ { MQ_MQIACF_REMOVE_AUTHREC, "MQIACF_REMOVE_AUTHREC" },
/* 1399*/ { MQ_MQIACF_XR_ATTRS, "MQIACF_XR_ATTRS" },
/* 1400*/ { MQ_MQIACF_APPL_FUNCTION_TYPE, "MQIACF_APPL_FUNCTION_TYPE" },
/* 1401*/ { MQ_MQIACF_AMQP_ATTRS, "MQIACF_AMQP_ATTRS" },
/* 1402*/ { MQ_MQIACF_EXPORT_TYPE, "MQIACF_EXPORT_TYPE" },
/* 1403*/ { MQ_MQIACF_EXPORT_ATTRS, "MQIACF_EXPORT_ATTRS" },
/* 1404*/ { MQ_MQIACF_SYSTEM_OBJECTS, "MQIACF_SYSTEM_OBJECTS" },
/* 1405*/ { MQ_MQIACF_CONNECTION_SWAP, "MQIACF_CONNECTION_SWAP" },
/* 1406*/ { MQ_MQIACF_AMQP_DIAGNOSTICS_TYPE, "MQIACF_AMQP_DIAGNOSTICS_TYPE" },
/* 1408*/ { MQ_MQIACF_BUFFER_POOL_LOCATION, "MQIACF_BUFFER_POOL_LOCATION" },
/* 1409*/ { MQ_MQIACF_LDAP_CONNECTION_STATUS, "MQIACF_LDAP_CONNECTION_STATUS" },
/* 1410*/ { MQ_MQIACF_SYSP_MAX_ACE_POOL, "MQIACF_SYSP_MAX_ACE_POOL" },
/* 1411*/ { MQ_MQIACF_PAGECLAS, "MQIACF_PAGECLAS" },
/* 1412*/ { MQ_MQIACF_AUTH_REC_TYPE, "MQIACF_AUTH_REC_TYPE" },
/* 1413*/ { MQ_MQIACF_SYSP_MAX_CONC_OFFLOADS, "MQIACF_SYSP_MAX_CONC_OFFLOADS" },
/* 1414*/ { MQ_MQIACF_SYSP_ZHYPERWRITE, "MQIACF_SYSP_ZHYPERWRITE" },
/* 1415*/ { MQ_MQIACF_Q_MGR_STATUS_LOG, "MQIACF_Q_MGR_STATUS_LOG" },
/* 1416*/ { MQ_MQIACF_ARCHIVE_LOG_SIZE, "MQIACF_ARCHIVE_LOG_SIZE" },
/* 1417*/ { MQ_MQIACF_MEDIA_LOG_SIZE, "MQIACF_MEDIA_LOG_SIZE" },
/* 1418*/ { MQ_MQIACF_RESTART_LOG_SIZE, "MQIACF_RESTART_LOG_SIZE" },
/* 1419*/ { MQ_MQIACF_REUSABLE_LOG_SIZE, "MQIACF_REUSABLE_LOG_SIZE" },
/* 1420*/ { MQ_MQIACF_LOG_IN_USE, "MQIACF_LOG_IN_USE" },
/* 1421*/ { MQ_MQIACF_LOG_UTILIZATION, "MQIACF_LOG_UTILIZATION" },
/* 1422*/ { MQ_MQIACF_LOG_REDUCTION, "MQIACF_LOG_REDUCTION" },
/* 1501*/ { MQ_MQIACH_XMIT_PROTOCOL_TYPE, "MQIACH_XMIT_PROTOCOL_TYPE" },
/* 1502*/ { MQ_MQIACH_BATCH_SIZE, "MQIACH_BATCH_SIZE" },
/* 1503*/ { MQ_MQIACH_DISC_INTERVAL, "MQIACH_DISC_INTERVAL" },
/* 1504*/ { MQ_MQIACH_SHORT_TIMER, "MQIACH_SHORT_TIMER" },
/* 1505*/ { MQ_MQIACH_SHORT_RETRY, "MQIACH_SHORT_RETRY" },
/* 1506*/ { MQ_MQIACH_LONG_TIMER, "MQIACH_LONG_TIMER" },
/* 1507*/ { MQ_MQIACH_LONG_RETRY, "MQIACH_LONG_RETRY" },
/* 1508*/ { MQ_MQIACH_PUT_AUTHORITY, "MQIACH_PUT_AUTHORITY" },
/* 1509*/ { MQ_MQIACH_SEQUENCE_NUMBER_WRAP, "MQIACH_SEQUENCE_NUMBER_WRAP" },
/* 1510*/ { MQ_MQIACH_MAX_MSG_LENGTH, "MQIACH_MAX_MSG_LENGTH" },
/* 1511*/ { MQ_MQIACH_CHANNEL_TYPE, "MQIACH_CHANNEL_TYPE" },
/* 1512*/ { MQ_MQIACH_DATA_COUNT, "MQIACH_DATA_COUNT" },
/* 1513*/ { MQ_MQIACH_NAME_COUNT, "MQIACH_NAME_COUNT" },
/* 1514*/ { MQ_MQIACH_MSG_SEQUENCE_NUMBER, "MQIACH_MSG_SEQUENCE_NUMBER" },
/* 1515*/ { MQ_MQIACH_DATA_CONVERSION, "MQIACH_DATA_CONVERSION" },
/* 1516*/ { MQ_MQIACH_IN_DOUBT, "MQIACH_IN_DOUBT" },
/* 1517*/ { MQ_MQIACH_MCA_TYPE, "MQIACH_MCA_TYPE" },
/* 1518*/ { MQ_MQIACH_SESSION_COUNT, "MQIACH_SESSION_COUNT" },
/* 1519*/ { MQ_MQIACH_ADAPTER, "MQIACH_ADAPTER" },
/* 1520*/ { MQ_MQIACH_COMMAND_COUNT, "MQIACH_COMMAND_COUNT" },
/* 1521*/ { MQ_MQIACH_SOCKET, "MQIACH_SOCKET" },
/* 1522*/ { MQ_MQIACH_PORT, "MQIACH_PORT" },
/* 1523*/ { MQ_MQIACH_CHANNEL_INSTANCE_TYPE, "MQIACH_CHANNEL_INSTANCE_TYPE" },
/* 1524*/ { MQ_MQIACH_CHANNEL_INSTANCE_ATTRS, "MQIACH_CHANNEL_INSTANCE_ATTRS" },
/* 1525*/ { MQ_MQIACH_CHANNEL_ERROR_DATA, "MQIACH_CHANNEL_ERROR_DATA" },
/* 1526*/ { MQ_MQIACH_CHANNEL_TABLE, "MQIACH_CHANNEL_TABLE" },
/* 1527*/ { MQ_MQIACH_CHANNEL_STATUS, "MQIACH_CHANNEL_STATUS" },
/* 1528*/ { MQ_MQIACH_INDOUBT_STATUS, "MQIACH_INDOUBT_STATUS" },
/* 1529*/ { MQ_MQIACH_LAST_SEQ_NUMBER, "MQIACH_LAST_SEQ_NUMBER" },
/* 1529 { MQ_MQIACH_LAST_SEQUENCE_NUMBER, "MQIACH_LAST_SEQUENCE_NUMBER" }, */
/* 1531*/ { MQ_MQIACH_CURRENT_MSGS, "MQIACH_CURRENT_MSGS" },
/* 1532*/ { MQ_MQIACH_CURRENT_SEQ_NUMBER, "MQIACH_CURRENT_SEQ_NUMBER" },
/* 1532 { MQ_MQIACH_CURRENT_SEQUENCE_NUMBER, "MQIACH_CURRENT_SEQUENCE_NUMBER" }, */
/* 1533*/ { MQ_MQIACH_SSL_RETURN_CODE, "MQIACH_SSL_RETURN_CODE" },
/* 1534*/ { MQ_MQIACH_MSGS, "MQIACH_MSGS" },
/* 1535*/ { MQ_MQIACH_BYTES_SENT, "MQIACH_BYTES_SENT" },
/* 1536 { MQ_MQIACH_BYTES_RCVD, "MQIACH_BYTES_RCVD" }, */
/* 1536*/ { MQ_MQIACH_BYTES_RECEIVED, "MQIACH_BYTES_RECEIVED" },
/* 1537*/ { MQ_MQIACH_BATCHES, "MQIACH_BATCHES" },
/* 1538*/ { MQ_MQIACH_BUFFERS_SENT, "MQIACH_BUFFERS_SENT" },
/* 1539 { MQ_MQIACH_BUFFERS_RCVD, "MQIACH_BUFFERS_RCVD" }, */
/* 1539*/ { MQ_MQIACH_BUFFERS_RECEIVED, "MQIACH_BUFFERS_RECEIVED" },
/* 1540*/ { MQ_MQIACH_LONG_RETRIES_LEFT, "MQIACH_LONG_RETRIES_LEFT" },
/* 1541*/ { MQ_MQIACH_SHORT_RETRIES_LEFT, "MQIACH_SHORT_RETRIES_LEFT" },
/* 1542*/ { MQ_MQIACH_MCA_STATUS, "MQIACH_MCA_STATUS" },
/* 1543*/ { MQ_MQIACH_STOP_REQUESTED, "MQIACH_STOP_REQUESTED" },
/* 1544*/ { MQ_MQIACH_MR_COUNT, "MQIACH_MR_COUNT" },
/* 1545*/ { MQ_MQIACH_MR_INTERVAL, "MQIACH_MR_INTERVAL" },
/* 1562*/ { MQ_MQIACH_NPM_SPEED, "MQIACH_NPM_SPEED" },
/* 1563*/ { MQ_MQIACH_HB_INTERVAL, "MQIACH_HB_INTERVAL" },
/* 1564*/ { MQ_MQIACH_BATCH_INTERVAL, "MQIACH_BATCH_INTERVAL" },
/* 1565*/ { MQ_MQIACH_NETWORK_PRIORITY, "MQIACH_NETWORK_PRIORITY" },
/* 1566*/ { MQ_MQIACH_KEEP_ALIVE_INTERVAL, "MQIACH_KEEP_ALIVE_INTERVAL" },
/* 1567*/ { MQ_MQIACH_BATCH_HB, "MQIACH_BATCH_HB" },
/* 1568*/ { MQ_MQIACH_SSL_CLIENT_AUTH, "MQIACH_SSL_CLIENT_AUTH" },
/* 1570*/ { MQ_MQIACH_ALLOC_RETRY, "MQIACH_ALLOC_RETRY" },
/* 1571*/ { MQ_MQIACH_ALLOC_FAST_TIMER, "MQIACH_ALLOC_FAST_TIMER" },
/* 1572*/ { MQ_MQIACH_ALLOC_SLOW_TIMER, "MQIACH_ALLOC_SLOW_TIMER" },
/* 1573*/ { MQ_MQIACH_DISC_RETRY, "MQIACH_DISC_RETRY" },
/* 1574*/ { MQ_MQIACH_PORT_NUMBER, "MQIACH_PORT_NUMBER" },
/* 1575*/ { MQ_MQIACH_HDR_COMPRESSION, "MQIACH_HDR_COMPRESSION" },
/* 1576*/ { MQ_MQIACH_MSG_COMPRESSION, "MQIACH_MSG_COMPRESSION" },
/* 1577*/ { MQ_MQIACH_CLWL_CHANNEL_RANK, "MQIACH_CLWL_CHANNEL_RANK" },
/* 1578*/ { MQ_MQIACH_CLWL_CHANNEL_PRIORITY, "MQIACH_CLWL_CHANNEL_PRIORITY" },
/* 1579*/ { MQ_MQIACH_CLWL_CHANNEL_WEIGHT, "MQIACH_CLWL_CHANNEL_WEIGHT" },
/* 1580*/ { MQ_MQIACH_CHANNEL_DISP, "MQIACH_CHANNEL_DISP" },
/* 1581*/ { MQ_MQIACH_INBOUND_DISP, "MQIACH_INBOUND_DISP" },
/* 1582*/ { MQ_MQIACH_CHANNEL_TYPES, "MQIACH_CHANNEL_TYPES" },
/* 1583*/ { MQ_MQIACH_ADAPS_STARTED, "MQIACH_ADAPS_STARTED" },
/* 1584*/ { MQ_MQIACH_ADAPS_MAX, "MQIACH_ADAPS_MAX" },
/* 1585*/ { MQ_MQIACH_DISPS_STARTED, "MQIACH_DISPS_STARTED" },
/* 1586*/ { MQ_MQIACH_DISPS_MAX, "MQIACH_DISPS_MAX" },
/* 1587*/ { MQ_MQIACH_SSLTASKS_STARTED, "MQIACH_SSLTASKS_STARTED" },
/* 1588*/ { MQ_MQIACH_SSLTASKS_MAX, "MQIACH_SSLTASKS_MAX" },
/* 1589*/ { MQ_MQIACH_CURRENT_CHL, "MQIACH_CURRENT_CHL" },
/* 1590*/ { MQ_MQIACH_CURRENT_CHL_MAX, "MQIACH_CURRENT_CHL_MAX" },
/* 1591*/ { MQ_MQIACH_CURRENT_CHL_TCP, "MQIACH_CURRENT_CHL_TCP" },
/* 1592*/ { MQ_MQIACH_CURRENT_CHL_LU62, "MQIACH_CURRENT_CHL_LU62" },
/* 1593*/ { MQ_MQIACH_ACTIVE_CHL, "MQIACH_ACTIVE_CHL" },
/* 1594*/ { MQ_MQIACH_ACTIVE_CHL_MAX, "MQIACH_ACTIVE_CHL_MAX" },
/* 1595*/ { MQ_MQIACH_ACTIVE_CHL_PAUSED, "MQIACH_ACTIVE_CHL_PAUSED" },
/* 1596*/ { MQ_MQIACH_ACTIVE_CHL_STARTED, "MQIACH_ACTIVE_CHL_STARTED" },
/* 1597*/ { MQ_MQIACH_ACTIVE_CHL_STOPPED, "MQIACH_ACTIVE_CHL_STOPPED" },
/* 1598*/ { MQ_MQIACH_ACTIVE_CHL_RETRY, "MQIACH_ACTIVE_CHL_RETRY" },
/* 1599*/ { MQ_MQIACH_LISTENER_STATUS, "MQIACH_LISTENER_STATUS" },
/* 1600*/ { MQ_MQIACH_SHARED_CHL_RESTART, "MQIACH_SHARED_CHL_RESTART" },
/* 1601*/ { MQ_MQIACH_LISTENER_CONTROL, "MQIACH_LISTENER_CONTROL" },
/* 1602*/ { MQ_MQIACH_BACKLOG, "MQIACH_BACKLOG" },
/* 1604*/ { MQ_MQIACH_XMITQ_TIME_INDICATOR, "MQIACH_XMITQ_TIME_INDICATOR" },
/* 1605*/ { MQ_MQIACH_NETWORK_TIME_INDICATOR, "MQIACH_NETWORK_TIME_INDICATOR" },
/* 1606*/ { MQ_MQIACH_EXIT_TIME_INDICATOR, "MQIACH_EXIT_TIME_INDICATOR" },
/* 1607*/ { MQ_MQIACH_BATCH_SIZE_INDICATOR, "MQIACH_BATCH_SIZE_INDICATOR" },
/* 1608*/ { MQ_MQIACH_XMITQ_MSGS_AVAILABLE, "MQIACH_XMITQ_MSGS_AVAILABLE" },
/* 1609*/ { MQ_MQIACH_CHANNEL_SUBSTATE, "MQIACH_CHANNEL_SUBSTATE" },
/* 1610*/ { MQ_MQIACH_SSL_KEY_RESETS, "MQIACH_SSL_KEY_RESETS" },
/* 1611*/ { MQ_MQIACH_COMPRESSION_RATE, "MQIACH_COMPRESSION_RATE" },
/* 1612*/ { MQ_MQIACH_COMPRESSION_TIME, "MQIACH_COMPRESSION_TIME" },
/* 1613*/ { MQ_MQIACH_MAX_XMIT_SIZE, "MQIACH_MAX_XMIT_SIZE" },
/* 1614*/ { MQ_MQIACH_DEF_CHANNEL_DISP, "MQIACH_DEF_CHANNEL_DISP" },
/* 1615*/ { MQ_MQIACH_SHARING_CONVERSATIONS, "MQIACH_SHARING_CONVERSATIONS" },
/* 1616*/ { MQ_MQIACH_MAX_SHARING_CONVS, "MQIACH_MAX_SHARING_CONVS" },
/* 1617*/ { MQ_MQIACH_CURRENT_SHARING_CONVS, "MQIACH_CURRENT_SHARING_CONVS" },
/* 1618*/ { MQ_MQIACH_MAX_INSTANCES, "MQIACH_MAX_INSTANCES" },
/* 1619*/ { MQ_MQIACH_MAX_INSTS_PER_CLIENT, "MQIACH_MAX_INSTS_PER_CLIENT" },
/* 1620*/ { MQ_MQIACH_CLIENT_CHANNEL_WEIGHT, "MQIACH_CLIENT_CHANNEL_WEIGHT" },
/* 1621*/ { MQ_MQIACH_CONNECTION_AFFINITY, "MQIACH_CONNECTION_AFFINITY" },
/* 1622*/ { MQ_MQIACH_AUTH_INFO_TYPES, "MQIACH_AUTH_INFO_TYPES" },
/* 1623*/ { MQ_MQIACH_RESET_REQUESTED, "MQIACH_RESET_REQUESTED" },
/* 1624*/ { MQ_MQIACH_BATCH_DATA_LIMIT, "MQIACH_BATCH_DATA_LIMIT" },
/* 1625*/ { MQ_MQIACH_MSG_HISTORY, "MQIACH_MSG_HISTORY" },
/* 1626*/ { MQ_MQIACH_MULTICAST_PROPERTIES, "MQIACH_MULTICAST_PROPERTIES" },
/* 1627*/ { MQ_MQIACH_NEW_SUBSCRIBER_HISTORY, "MQIACH_NEW_SUBSCRIBER_HISTORY" },
/* 1628*/ { MQ_MQIACH_MC_HB_INTERVAL, "MQIACH_MC_HB_INTERVAL" },
/* 1629*/ { MQ_MQIACH_USE_CLIENT_ID, "MQIACH_USE_CLIENT_ID" },
/* 1630*/ { MQ_MQIACH_MQTT_KEEP_ALIVE, "MQIACH_MQTT_KEEP_ALIVE" },
/* 1631*/ { MQ_MQIACH_IN_DOUBT_IN, "MQIACH_IN_DOUBT_IN" },
/* 1632*/ { MQ_MQIACH_IN_DOUBT_OUT, "MQIACH_IN_DOUBT_OUT" },
/* 1633*/ { MQ_MQIACH_MSGS_SENT, "MQIACH_MSGS_SENT" },
/* 1634*/ { MQ_MQIACH_MSGS_RCVD, "MQIACH_MSGS_RCVD" },
/* 1634   { MQ_MQIACH_MSGS_RECEIVED, "MQIACH_MSGS_RECEIVED" }, */
/* 1635*/ { MQ_MQIACH_PENDING_OUT, "MQIACH_PENDING_OUT" },
/* 1636*/ { MQ_MQIACH_AVAILABLE_CIPHERSPECS, "MQIACH_AVAILABLE_CIPHERSPECS" },
/* 1637*/ { MQ_MQIACH_MATCH, "MQIACH_MATCH" },
/* 1638*/ { MQ_MQIACH_USER_SOURCE, "MQIACH_USER_SOURCE" },
/* 1639*/ { MQ_MQIACH_WARNING, "MQIACH_WARNING" },
/* 1640*/ { MQ_MQIACH_DEF_RECONNECT, "MQIACH_DEF_RECONNECT" },
/* 1642*/ { MQ_MQIACH_CHANNEL_SUMMARY_ATTRS, "MQIACH_CHANNEL_SUMMARY_ATTRS" },
/* 1643*/ { MQ_MQIACH_PROTOCOL, "MQIACH_PROTOCOL" },
/* 1644*/ { MQ_MQIACH_AMQP_KEEP_ALIVE, "MQIACH_AMQP_KEEP_ALIVE" },
/* 1645*/ { MQ_MQIACH_SECURITY_PROTOCOL, "MQIACH_SECURITY_PROTOCOL" },
/* 2000*/ { MQ_MQIA_USER_LIST, "MQIA_USER_LIST" },
/* 2001*/ { MQ_MQCA_APPL_ID, "MQCA_APPL_ID" },
/* 2002*/ { MQ_MQCA_BASE_OBJECT_NAME, "MQCA_BASE_OBJECT_NAME" },
/* 2002   { MQ_MQCA_BASE_Q_NAME, "MQCA_BASE_Q_NAME" }, */
/* 2003*/ { MQ_MQCA_COMMAND_INPUT_Q_NAME, "MQCA_COMMAND_INPUT_Q_NAME" },
/* 2004*/ { MQ_MQCA_CREATION_DATE, "MQCA_CREATION_DATE" },
/* 2005*/ { MQ_MQCA_CREATION_TIME, "MQCA_CREATION_TIME" },
/* 2006*/ { MQ_MQCA_DEAD_LETTER_Q_NAME, "MQCA_DEAD_LETTER_Q_NAME" },
/* 2007*/ { MQ_MQCA_ENV_DATA, "MQCA_ENV_DATA" },
/* 2008*/ { MQ_MQCA_INITIATION_Q_NAME, "MQCA_INITIATION_Q_NAME" },
/* 2009*/ { MQ_MQCA_NAMELIST_DESC, "MQCA_NAMELIST_DESC" },
/* 2010*/ { MQ_MQCA_NAMELIST_NAME, "MQCA_NAMELIST_NAME" },
/* 2011*/ { MQ_MQCA_PROCESS_DESC, "MQCA_PROCESS_DESC" },
/* 2012*/ { MQ_MQCA_PROCESS_NAME, "MQCA_PROCESS_NAME" },
/* 2013*/ { MQ_MQCA_Q_DESC, "MQCA_Q_DESC" },
/* 2014*/ { MQ_MQCA_Q_MGR_DESC, "MQCA_Q_MGR_DESC" },
/* 2015*/ { MQ_MQCA_Q_MGR_NAME, "MQCA_Q_MGR_NAME" },
/* 2016*/ { MQ_MQCA_Q_NAME, "MQCA_Q_NAME" },
/* 2017*/ { MQ_MQCA_REMOTE_Q_MGR_NAME, "MQCA_REMOTE_Q_MGR_NAME" },
/* 2018*/ { MQ_MQCA_REMOTE_Q_NAME, "MQCA_REMOTE_Q_NAME" },
/* 2019*/ { MQ_MQCA_BACKOUT_REQ_Q_NAME, "MQCA_BACKOUT_REQ_Q_NAME" },
/* 2020*/ { MQ_MQCA_NAMES, "MQCA_NAMES" },
/* 2021*/ { MQ_MQCA_USER_DATA, "MQCA_USER_DATA" },
/* 2022*/ { MQ_MQCA_STORAGE_CLASS, "MQCA_STORAGE_CLASS" },
/* 2023*/ { MQ_MQCA_TRIGGER_DATA, "MQCA_TRIGGER_DATA" },
/* 2024*/ { MQ_MQCA_XMIT_Q_NAME, "MQCA_XMIT_Q_NAME" },
/* 2025*/ { MQ_MQCA_DEF_XMIT_Q_NAME, "MQCA_DEF_XMIT_Q_NAME" },
/* 2026*/ { MQ_MQCA_CHANNEL_AUTO_DEF_EXIT, "MQCA_CHANNEL_AUTO_DEF_EXIT" },
/* 2027*/ { MQ_MQCA_ALTERATION_DATE, "MQCA_ALTERATION_DATE" },
/* 2028*/ { MQ_MQCA_ALTERATION_TIME, "MQCA_ALTERATION_TIME" },
/* 2029*/ { MQ_MQCA_CLUSTER_NAME, "MQCA_CLUSTER_NAME" },
/* 2030*/ { MQ_MQCA_CLUSTER_NAMELIST, "MQCA_CLUSTER_NAMELIST" },
/* 2031*/ { MQ_MQCA_CLUSTER_Q_MGR_NAME, "MQCA_CLUSTER_Q_MGR_NAME" },
/* 2032*/ { MQ_MQCA_Q_MGR_IDENTIFIER, "MQCA_Q_MGR_IDENTIFIER" },
/* 2033*/ { MQ_MQCA_CLUSTER_WORKLOAD_EXIT, "MQCA_CLUSTER_WORKLOAD_EXIT" },
/* 2034*/ { MQ_MQCA_CLUSTER_WORKLOAD_DATA, "MQCA_CLUSTER_WORKLOAD_DATA" },
/* 2035*/ { MQ_MQCA_REPOSITORY_NAME, "MQCA_REPOSITORY_NAME" },
/* 2036*/ { MQ_MQCA_REPOSITORY_NAMELIST, "MQCA_REPOSITORY_NAMELIST" },
/* 2037*/ { MQ_MQCA_CLUSTER_DATE, "MQCA_CLUSTER_DATE" },
/* 2038*/ { MQ_MQCA_CLUSTER_TIME, "MQCA_CLUSTER_TIME" },
/* 2039*/ { MQ_MQCA_CF_STRUC_NAME, "MQCA_CF_STRUC_NAME" },
/* 2040*/ { MQ_MQCA_QSG_NAME, "MQCA_QSG_NAME" },
/* 2041*/ { MQ_MQCA_IGQ_USER_ID, "MQCA_IGQ_USER_ID" },
/* 2042*/ { MQ_MQCA_STORAGE_CLASS_DESC, "MQCA_STORAGE_CLASS_DESC" },
/* 2043*/ { MQ_MQCA_XCF_GROUP_NAME, "MQCA_XCF_GROUP_NAME" },
/* 2044*/ { MQ_MQCA_XCF_MEMBER_NAME, "MQCA_XCF_MEMBER_NAME" },
/* 2045*/ { MQ_MQCA_AUTH_INFO_NAME, "MQCA_AUTH_INFO_NAME" },
/* 2046*/ { MQ_MQCA_AUTH_INFO_DESC, "MQCA_AUTH_INFO_DESC" },
/* 2047*/ { MQ_MQCA_LDAP_USER_NAME, "MQCA_LDAP_USER_NAME" },
/* 2048*/ { MQ_MQCA_LDAP_PASSWORD, "MQCA_LDAP_PASSWORD" },
/* 2049*/ { MQ_MQCA_SSL_KEY_REPOSITORY, "MQCA_SSL_KEY_REPOSITORY" },
/* 2050*/ { MQ_MQCA_SSL_CRL_NAMELIST, "MQCA_SSL_CRL_NAMELIST" },
/* 2051*/ { MQ_MQCA_SSL_CRYPTO_HARDWARE, "MQCA_SSL_CRYPTO_HARDWARE" },
/* 2052*/ { MQ_MQCA_CF_STRUC_DESC, "MQCA_CF_STRUC_DESC" },
/* 2053*/ { MQ_MQCA_AUTH_INFO_CONN_NAME, "MQCA_AUTH_INFO_CONN_NAME" },
/* 2060*/ { MQ_MQCA_CICS_FILE_NAME, "MQCA_CICS_FILE_NAME" },
/* 2061*/ { MQ_MQCA_TRIGGER_TRANS_ID, "MQCA_TRIGGER_TRANS_ID" },
/* 2062*/ { MQ_MQCA_TRIGGER_PROGRAM_NAME, "MQCA_TRIGGER_PROGRAM_NAME" },
/* 2063*/ { MQ_MQCA_TRIGGER_TERM_ID, "MQCA_TRIGGER_TERM_ID" },
/* 2064*/ { MQ_MQCA_TRIGGER_CHANNEL_NAME, "MQCA_TRIGGER_CHANNEL_NAME" },
/* 2065*/ { MQ_MQCA_SYSTEM_LOG_Q_NAME, "MQCA_SYSTEM_LOG_Q_NAME" },
/* 2066*/ { MQ_MQCA_MONITOR_Q_NAME, "MQCA_MONITOR_Q_NAME" },
/* 2067*/ { MQ_MQCA_COMMAND_REPLY_Q_NAME, "MQCA_COMMAND_REPLY_Q_NAME" },
/* 2068*/ { MQ_MQCA_BATCH_INTERFACE_ID, "MQCA_BATCH_INTERFACE_ID" },
/* 2069*/ { MQ_MQCA_SSL_KEY_LIBRARY, "MQCA_SSL_KEY_LIBRARY" },
/* 2070*/ { MQ_MQCA_SSL_KEY_MEMBER, "MQCA_SSL_KEY_MEMBER" },
/* 2071*/ { MQ_MQCA_DNS_GROUP, "MQCA_DNS_GROUP" },
/* 2072*/ { MQ_MQCA_LU_GROUP_NAME, "MQCA_LU_GROUP_NAME" },
/* 2073*/ { MQ_MQCA_LU_NAME, "MQCA_LU_NAME" },
/* 2074*/ { MQ_MQCA_LU62_ARM_SUFFIX, "MQCA_LU62_ARM_SUFFIX" },
/* 2075*/ { MQ_MQCA_TCP_NAME, "MQCA_TCP_NAME" },
/* 2076*/ { MQ_MQCA_CHINIT_SERVICE_PARM, "MQCA_CHINIT_SERVICE_PARM" },
/* 2077*/ { MQ_MQCA_SERVICE_NAME, "MQCA_SERVICE_NAME" },
/* 2078*/ { MQ_MQCA_SERVICE_DESC, "MQCA_SERVICE_DESC" },
/* 2079*/ { MQ_MQCA_SERVICE_START_COMMAND, "MQCA_SERVICE_START_COMMAND" },
/* 2080*/ { MQ_MQCA_SERVICE_START_ARGS, "MQCA_SERVICE_START_ARGS" },
/* 2081*/ { MQ_MQCA_SERVICE_STOP_COMMAND, "MQCA_SERVICE_STOP_COMMAND" },
/* 2082*/ { MQ_MQCA_SERVICE_STOP_ARGS, "MQCA_SERVICE_STOP_ARGS" },
/* 2083*/ { MQ_MQCA_STDOUT_DESTINATION, "MQCA_STDOUT_DESTINATION" },
/* 2084*/ { MQ_MQCA_STDERR_DESTINATION, "MQCA_STDERR_DESTINATION" },
/* 2085*/ { MQ_MQCA_TPIPE_NAME, "MQCA_TPIPE_NAME" },
/* 2086*/ { MQ_MQCA_PASS_TICKET_APPL, "MQCA_PASS_TICKET_APPL" },
/* 2090*/ { MQ_MQCA_AUTO_REORG_START_TIME, "MQCA_AUTO_REORG_START_TIME" },
/* 2091*/ { MQ_MQCA_AUTO_REORG_CATALOG, "MQCA_AUTO_REORG_CATALOG" },
/* 2092*/ { MQ_MQCA_TOPIC_NAME, "MQCA_TOPIC_NAME" },
/* 2093*/ { MQ_MQCA_TOPIC_DESC, "MQCA_TOPIC_DESC" },
/* 2094*/ { MQ_MQCA_TOPIC_STRING, "MQCA_TOPIC_STRING" },
/* 2096*/ { MQ_MQCA_MODEL_DURABLE_Q, "MQCA_MODEL_DURABLE_Q" },
/* 2097*/ { MQ_MQCA_MODEL_NON_DURABLE_Q, "MQCA_MODEL_NON_DURABLE_Q" },
/* 2098*/ { MQ_MQCA_RESUME_DATE, "MQCA_RESUME_DATE" },
/* 2099*/ { MQ_MQCA_RESUME_TIME, "MQCA_RESUME_TIME" },
/* 2101*/ { MQ_MQCA_CHILD, "MQCA_CHILD" },
/* 2102*/ { MQ_MQCA_PARENT, "MQCA_PARENT" },
/* 2105*/ { MQ_MQCA_ADMIN_TOPIC_NAME, "MQCA_ADMIN_TOPIC_NAME" },
/* 2108*/ { MQ_MQCA_TOPIC_STRING_FILTER, "MQCA_TOPIC_STRING_FILTER" },
/* 2109*/ { MQ_MQCA_AUTH_INFO_OCSP_URL, "MQCA_AUTH_INFO_OCSP_URL" },
/* 2110*/ { MQ_MQCA_COMM_INFO_NAME, "MQCA_COMM_INFO_NAME" },
/* 2111*/ { MQ_MQCA_COMM_INFO_DESC, "MQCA_COMM_INFO_DESC" },
/* 2112*/ { MQ_MQCA_POLICY_NAME, "MQCA_POLICY_NAME" },
/* 2113*/ { MQ_MQCA_SIGNER_DN, "MQCA_SIGNER_DN" },
/* 2114*/ { MQ_MQCA_RECIPIENT_DN, "MQCA_RECIPIENT_DN" },
/* 2115*/ { MQ_MQCA_INSTALLATION_DESC, "MQCA_INSTALLATION_DESC" },
/* 2116*/ { MQ_MQCA_INSTALLATION_NAME, "MQCA_INSTALLATION_NAME" },
/* 2117*/ { MQ_MQCA_INSTALLATION_PATH, "MQCA_INSTALLATION_PATH" },
/* 2118*/ { MQ_MQCA_CHLAUTH_DESC, "MQCA_CHLAUTH_DESC" },
/* 2119*/ { MQ_MQCA_CUSTOM, "MQCA_CUSTOM" },
/* 2120*/ { MQ_MQCA_VERSION, "MQCA_VERSION" },
/* 2121*/ { MQ_MQCA_CERT_LABEL, "MQCA_CERT_LABEL" },
/* 2122*/ { MQ_MQCA_XR_VERSION, "MQCA_XR_VERSION" },
/* 2123*/ { MQ_MQCA_XR_SSL_CIPHER_SUITES, "MQCA_XR_SSL_CIPHER_SUITES" },
/* 2124*/ { MQ_MQCA_CLUS_CHL_NAME, "MQCA_CLUS_CHL_NAME" },
/* 2125*/ { MQ_MQCA_CONN_AUTH, "MQCA_CONN_AUTH" },
/* 2126*/ { MQ_MQCA_LDAP_BASE_DN_USERS, "MQCA_LDAP_BASE_DN_USERS" },
/* 2127*/ { MQ_MQCA_LDAP_SHORT_USER_FIELD, "MQCA_LDAP_SHORT_USER_FIELD" },
/* 2128*/ { MQ_MQCA_LDAP_USER_OBJECT_CLASS, "MQCA_LDAP_USER_OBJECT_CLASS" },
/* 2129*/ { MQ_MQCA_LDAP_USER_ATTR_FIELD, "MQCA_LDAP_USER_ATTR_FIELD" },
/* 2130*/ { MQ_MQCA_SSL_CERT_ISSUER_NAME, "MQCA_SSL_CERT_ISSUER_NAME" },
/* 2131*/ { MQ_MQCA_QSG_CERT_LABEL, "MQCA_QSG_CERT_LABEL" },
/* 2132*/ { MQ_MQCA_LDAP_BASE_DN_GROUPS, "MQCA_LDAP_BASE_DN_GROUPS" },
/* 2133*/ { MQ_MQCA_LDAP_GROUP_OBJECT_CLASS, "MQCA_LDAP_GROUP_OBJECT_CLASS" },
/* 2134*/ { MQ_MQCA_LDAP_GROUP_ATTR_FIELD, "MQCA_LDAP_GROUP_ATTR_FIELD" },
/* 2135*/ { MQ_MQCA_LDAP_FIND_GROUP_FIELD, "MQCA_LDAP_FIND_GROUP_FIELD" },
/* 2136*/ { MQ_MQCA_AMQP_VERSION, "MQCA_AMQP_VERSION" },
/* 2137*/ { MQ_MQCA_AMQP_SSL_CIPHER_SUITES, "MQCA_AMQP_SSL_CIPHER_SUITES" },
/* 2701*/ { MQ_MQCAMO_CLOSE_DATE, "MQCAMO_CLOSE_DATE" },
/* 2702*/ { MQ_MQCAMO_CLOSE_TIME, "MQCAMO_CLOSE_TIME" },
/* 2703*/ { MQ_MQCAMO_CONN_DATE, "MQCAMO_CONN_DATE" },
/* 2704*/ { MQ_MQCAMO_CONN_TIME, "MQCAMO_CONN_TIME" },
/* 2705*/ { MQ_MQCAMO_DISC_DATE, "MQCAMO_DISC_DATE" },
/* 2706*/ { MQ_MQCAMO_DISC_TIME, "MQCAMO_DISC_TIME" },
/* 2707*/ { MQ_MQCAMO_END_DATE, "MQCAMO_END_DATE" },
/* 2708*/ { MQ_MQCAMO_END_TIME, "MQCAMO_END_TIME" },
/* 2709*/ { MQ_MQCAMO_OPEN_DATE, "MQCAMO_OPEN_DATE" },
/* 2710*/ { MQ_MQCAMO_OPEN_TIME, "MQCAMO_OPEN_TIME" },
/* 2711*/ { MQ_MQCAMO_START_DATE, "MQCAMO_START_DATE" },
/* 2712*/ { MQ_MQCAMO_START_TIME, "MQCAMO_START_TIME" },
/* 2713*/ { MQ_MQCAMO_MONITOR_CLASS, "MQCAMO_MONITOR_CLASS" },
/* 2714*/ { MQ_MQCAMO_MONITOR_TYPE, "MQCAMO_MONITOR_TYPE" },
/* 2715*/ { MQ_MQCAMO_MONITOR_DESC, "MQCAMO_MONITOR_DESC" },
/* 3001*/ { MQ_MQCACF_FROM_Q_NAME, "MQCACF_FROM_Q_NAME" },
/* 3002*/ { MQ_MQCACF_TO_Q_NAME, "MQCACF_TO_Q_NAME" },
/* 3003*/ { MQ_MQCACF_FROM_PROCESS_NAME, "MQCACF_FROM_PROCESS_NAME" },
/* 3004*/ { MQ_MQCACF_TO_PROCESS_NAME, "MQCACF_TO_PROCESS_NAME" },
/* 3005*/ { MQ_MQCACF_FROM_NAMELIST_NAME, "MQCACF_FROM_NAMELIST_NAME" },
/* 3006*/ { MQ_MQCACF_TO_NAMELIST_NAME, "MQCACF_TO_NAMELIST_NAME" },
/* 3007*/ { MQ_MQCACF_FROM_CHANNEL_NAME, "MQCACF_FROM_CHANNEL_NAME" },
/* 3008*/ { MQ_MQCACF_TO_CHANNEL_NAME, "MQCACF_TO_CHANNEL_NAME" },
/* 3009*/ { MQ_MQCACF_FROM_AUTH_INFO_NAME, "MQCACF_FROM_AUTH_INFO_NAME" },
/* 3010*/ { MQ_MQCACF_TO_AUTH_INFO_NAME, "MQCACF_TO_AUTH_INFO_NAME" },
/* 3011*/ { MQ_MQCACF_Q_NAMES, "MQCACF_Q_NAMES" },
/* 3012*/ { MQ_MQCACF_PROCESS_NAMES, "MQCACF_PROCESS_NAMES" },
/* 3013*/ { MQ_MQCACF_NAMELIST_NAMES, "MQCACF_NAMELIST_NAMES" },
/* 3014*/ { MQ_MQCACF_ESCAPE_TEXT, "MQCACF_ESCAPE_TEXT" },
/* 3015*/ { MQ_MQCACF_LOCAL_Q_NAMES, "MQCACF_LOCAL_Q_NAMES" },
/* 3016*/ { MQ_MQCACF_MODEL_Q_NAMES, "MQCACF_MODEL_Q_NAMES" },
/* 3017*/ { MQ_MQCACF_ALIAS_Q_NAMES, "MQCACF_ALIAS_Q_NAMES" },
/* 3018*/ { MQ_MQCACF_REMOTE_Q_NAMES, "MQCACF_REMOTE_Q_NAMES" },
/* 3019*/ { MQ_MQCACF_SENDER_CHANNEL_NAMES, "MQCACF_SENDER_CHANNEL_NAMES" },
/* 3020*/ { MQ_MQCACF_SERVER_CHANNEL_NAMES, "MQCACF_SERVER_CHANNEL_NAMES" },
/* 3021*/ { MQ_MQCACF_REQUESTER_CHANNEL_NAMES, "MQCACF_REQUESTER_CHANNEL_NAMES" },
/* 3022*/ { MQ_MQCACF_RECEIVER_CHANNEL_NAMES, "MQCACF_RECEIVER_CHANNEL_NAMES" },
/* 3023*/ { MQ_MQCACF_OBJECT_Q_MGR_NAME, "MQCACF_OBJECT_Q_MGR_NAME" },
/* 3024*/ { MQ_MQCACF_APPL_NAME, "MQCACF_APPL_NAME" },
/* 3025*/ { MQ_MQCACF_USER_IDENTIFIER, "MQCACF_USER_IDENTIFIER" },
/* 3026*/ { MQ_MQCACF_AUX_ERROR_DATA_STR_1, "MQCACF_AUX_ERROR_DATA_STR_1" },
/* 3027*/ { MQ_MQCACF_AUX_ERROR_DATA_STR_2, "MQCACF_AUX_ERROR_DATA_STR_2" },
/* 3028*/ { MQ_MQCACF_AUX_ERROR_DATA_STR_3, "MQCACF_AUX_ERROR_DATA_STR_3" },
/* 3029*/ { MQ_MQCACF_BRIDGE_NAME, "MQCACF_BRIDGE_NAME" },
/* 3030*/ { MQ_MQCACF_STREAM_NAME, "MQCACF_STREAM_NAME" },
/* 3031*/ { MQ_MQCACF_TOPIC, "MQCACF_TOPIC" },
/* 3032*/ { MQ_MQCACF_PARENT_Q_MGR_NAME, "MQCACF_PARENT_Q_MGR_NAME" },
/* 3033*/ { MQ_MQCACF_CORREL_ID, "MQCACF_CORREL_ID" },
/* 3034*/ { MQ_MQCACF_PUBLISH_TIMESTAMP, "MQCACF_PUBLISH_TIMESTAMP" },
/* 3035*/ { MQ_MQCACF_STRING_DATA, "MQCACF_STRING_DATA" },
/* 3036*/ { MQ_MQCACF_SUPPORTED_STREAM_NAME, "MQCACF_SUPPORTED_STREAM_NAME" },
/* 3037*/ { MQ_MQCACF_REG_TOPIC, "MQCACF_REG_TOPIC" },
/* 3038*/ { MQ_MQCACF_REG_TIME, "MQCACF_REG_TIME" },
/* 3039*/ { MQ_MQCACF_REG_USER_ID, "MQCACF_REG_USER_ID" },
/* 3040*/ { MQ_MQCACF_CHILD_Q_MGR_NAME, "MQCACF_CHILD_Q_MGR_NAME" },
/* 3041*/ { MQ_MQCACF_REG_STREAM_NAME, "MQCACF_REG_STREAM_NAME" },
/* 3042*/ { MQ_MQCACF_REG_Q_MGR_NAME, "MQCACF_REG_Q_MGR_NAME" },
/* 3043*/ { MQ_MQCACF_REG_Q_NAME, "MQCACF_REG_Q_NAME" },
/* 3044*/ { MQ_MQCACF_REG_CORREL_ID, "MQCACF_REG_CORREL_ID" },
/* 3045*/ { MQ_MQCACF_EVENT_USER_ID, "MQCACF_EVENT_USER_ID" },
/* 3046*/ { MQ_MQCACF_OBJECT_NAME, "MQCACF_OBJECT_NAME" },
/* 3047*/ { MQ_MQCACF_EVENT_Q_MGR, "MQCACF_EVENT_Q_MGR" },
/* 3048*/ { MQ_MQCACF_AUTH_INFO_NAMES, "MQCACF_AUTH_INFO_NAMES" },
/* 3049*/ { MQ_MQCACF_EVENT_APPL_IDENTITY, "MQCACF_EVENT_APPL_IDENTITY" },
/* 3050*/ { MQ_MQCACF_EVENT_APPL_NAME, "MQCACF_EVENT_APPL_NAME" },
/* 3051*/ { MQ_MQCACF_EVENT_APPL_ORIGIN, "MQCACF_EVENT_APPL_ORIGIN" },
/* 3052*/ { MQ_MQCACF_SUBSCRIPTION_NAME, "MQCACF_SUBSCRIPTION_NAME" },
/* 3053*/ { MQ_MQCACF_REG_SUB_NAME, "MQCACF_REG_SUB_NAME" },
/* 3054*/ { MQ_MQCACF_SUBSCRIPTION_IDENTITY, "MQCACF_SUBSCRIPTION_IDENTITY" },
/* 3055*/ { MQ_MQCACF_REG_SUB_IDENTITY, "MQCACF_REG_SUB_IDENTITY" },
/* 3056*/ { MQ_MQCACF_SUBSCRIPTION_USER_DATA, "MQCACF_SUBSCRIPTION_USER_DATA" },
/* 3057*/ { MQ_MQCACF_REG_SUB_USER_DATA, "MQCACF_REG_SUB_USER_DATA" },
/* 3058*/ { MQ_MQCACF_APPL_TAG, "MQCACF_APPL_TAG" },
/* 3059*/ { MQ_MQCACF_DATA_SET_NAME, "MQCACF_DATA_SET_NAME" },
/* 3060*/ { MQ_MQCACF_UOW_START_DATE, "MQCACF_UOW_START_DATE" },
/* 3061*/ { MQ_MQCACF_UOW_START_TIME, "MQCACF_UOW_START_TIME" },
/* 3062*/ { MQ_MQCACF_UOW_LOG_START_DATE, "MQCACF_UOW_LOG_START_DATE" },
/* 3063*/ { MQ_MQCACF_UOW_LOG_START_TIME, "MQCACF_UOW_LOG_START_TIME" },
/* 3064*/ { MQ_MQCACF_UOW_LOG_EXTENT_NAME, "MQCACF_UOW_LOG_EXTENT_NAME" },
/* 3065*/ { MQ_MQCACF_PRINCIPAL_ENTITY_NAMES, "MQCACF_PRINCIPAL_ENTITY_NAMES" },
/* 3066*/ { MQ_MQCACF_GROUP_ENTITY_NAMES, "MQCACF_GROUP_ENTITY_NAMES" },
/* 3067*/ { MQ_MQCACF_AUTH_PROFILE_NAME, "MQCACF_AUTH_PROFILE_NAME" },
/* 3068*/ { MQ_MQCACF_ENTITY_NAME, "MQCACF_ENTITY_NAME" },
/* 3069*/ { MQ_MQCACF_SERVICE_COMPONENT, "MQCACF_SERVICE_COMPONENT" },
/* 3070*/ { MQ_MQCACF_RESPONSE_Q_MGR_NAME, "MQCACF_RESPONSE_Q_MGR_NAME" },
/* 3071*/ { MQ_MQCACF_CURRENT_LOG_EXTENT_NAME, "MQCACF_CURRENT_LOG_EXTENT_NAME" },
/* 3072*/ { MQ_MQCACF_RESTART_LOG_EXTENT_NAME, "MQCACF_RESTART_LOG_EXTENT_NAME" },
/* 3073*/ { MQ_MQCACF_MEDIA_LOG_EXTENT_NAME, "MQCACF_MEDIA_LOG_EXTENT_NAME" },
/* 3074*/ { MQ_MQCACF_LOG_PATH, "MQCACF_LOG_PATH" },
/* 3075*/ { MQ_MQCACF_COMMAND_MQSC, "MQCACF_COMMAND_MQSC" },
/* 3076*/ { MQ_MQCACF_Q_MGR_CPF, "MQCACF_Q_MGR_CPF" },
/* 3078*/ { MQ_MQCACF_USAGE_LOG_RBA, "MQCACF_USAGE_LOG_RBA" },
/* 3079*/ { MQ_MQCACF_USAGE_LOG_LRSN, "MQCACF_USAGE_LOG_LRSN" },
/* 3080*/ { MQ_MQCACF_COMMAND_SCOPE, "MQCACF_COMMAND_SCOPE" },
/* 3081*/ { MQ_MQCACF_ASID, "MQCACF_ASID" },
/* 3082*/ { MQ_MQCACF_PSB_NAME, "MQCACF_PSB_NAME" },
/* 3083*/ { MQ_MQCACF_PST_ID, "MQCACF_PST_ID" },
/* 3084*/ { MQ_MQCACF_TASK_NUMBER, "MQCACF_TASK_NUMBER" },
/* 3085*/ { MQ_MQCACF_TRANSACTION_ID, "MQCACF_TRANSACTION_ID" },
/* 3086*/ { MQ_MQCACF_Q_MGR_UOW_ID, "MQCACF_Q_MGR_UOW_ID" },
/* 3088*/ { MQ_MQCACF_ORIGIN_NAME, "MQCACF_ORIGIN_NAME" },
/* 3089*/ { MQ_MQCACF_ENV_INFO, "MQCACF_ENV_INFO" },
/* 3090*/ { MQ_MQCACF_SECURITY_PROFILE, "MQCACF_SECURITY_PROFILE" },
/* 3091*/ { MQ_MQCACF_CONFIGURATION_DATE, "MQCACF_CONFIGURATION_DATE" },
/* 3092*/ { MQ_MQCACF_CONFIGURATION_TIME, "MQCACF_CONFIGURATION_TIME" },
/* 3093*/ { MQ_MQCACF_FROM_CF_STRUC_NAME, "MQCACF_FROM_CF_STRUC_NAME" },
/* 3094*/ { MQ_MQCACF_TO_CF_STRUC_NAME, "MQCACF_TO_CF_STRUC_NAME" },
/* 3095*/ { MQ_MQCACF_CF_STRUC_NAMES, "MQCACF_CF_STRUC_NAMES" },
/* 3096*/ { MQ_MQCACF_FAIL_DATE, "MQCACF_FAIL_DATE" },
/* 3097*/ { MQ_MQCACF_FAIL_TIME, "MQCACF_FAIL_TIME" },
/* 3098*/ { MQ_MQCACF_BACKUP_DATE, "MQCACF_BACKUP_DATE" },
/* 3099*/ { MQ_MQCACF_BACKUP_TIME, "MQCACF_BACKUP_TIME" },
/* 3100*/ { MQ_MQCACF_SYSTEM_NAME, "MQCACF_SYSTEM_NAME" },
/* 3101*/ { MQ_MQCACF_CF_STRUC_BACKUP_START, "MQCACF_CF_STRUC_BACKUP_START" },
/* 3102*/ { MQ_MQCACF_CF_STRUC_BACKUP_END, "MQCACF_CF_STRUC_BACKUP_END" },
/* 3103*/ { MQ_MQCACF_CF_STRUC_LOG_Q_MGRS, "MQCACF_CF_STRUC_LOG_Q_MGRS" },
/* 3104*/ { MQ_MQCACF_FROM_STORAGE_CLASS, "MQCACF_FROM_STORAGE_CLASS" },
/* 3105*/ { MQ_MQCACF_TO_STORAGE_CLASS, "MQCACF_TO_STORAGE_CLASS" },
/* 3106*/ { MQ_MQCACF_STORAGE_CLASS_NAMES, "MQCACF_STORAGE_CLASS_NAMES" },
/* 3108*/ { MQ_MQCACF_DSG_NAME, "MQCACF_DSG_NAME" },
/* 3109*/ { MQ_MQCACF_DB2_NAME, "MQCACF_DB2_NAME" },
/* 3110*/ { MQ_MQCACF_SYSP_CMD_USER_ID, "MQCACF_SYSP_CMD_USER_ID" },
/* 3111*/ { MQ_MQCACF_SYSP_OTMA_GROUP, "MQCACF_SYSP_OTMA_GROUP" },
/* 3112*/ { MQ_MQCACF_SYSP_OTMA_MEMBER, "MQCACF_SYSP_OTMA_MEMBER" },
/* 3113*/ { MQ_MQCACF_SYSP_OTMA_DRU_EXIT, "MQCACF_SYSP_OTMA_DRU_EXIT" },
/* 3114*/ { MQ_MQCACF_SYSP_OTMA_TPIPE_PFX, "MQCACF_SYSP_OTMA_TPIPE_PFX" },
/* 3115*/ { MQ_MQCACF_SYSP_ARCHIVE_PFX1, "MQCACF_SYSP_ARCHIVE_PFX1" },
/* 3116*/ { MQ_MQCACF_SYSP_ARCHIVE_UNIT1, "MQCACF_SYSP_ARCHIVE_UNIT1" },
/* 3117*/ { MQ_MQCACF_SYSP_LOG_CORREL_ID, "MQCACF_SYSP_LOG_CORREL_ID" },
/* 3118*/ { MQ_MQCACF_SYSP_UNIT_VOLSER, "MQCACF_SYSP_UNIT_VOLSER" },
/* 3119*/ { MQ_MQCACF_SYSP_Q_MGR_TIME, "MQCACF_SYSP_Q_MGR_TIME" },
/* 3120*/ { MQ_MQCACF_SYSP_Q_MGR_DATE, "MQCACF_SYSP_Q_MGR_DATE" },
/* 3121*/ { MQ_MQCACF_SYSP_Q_MGR_RBA, "MQCACF_SYSP_Q_MGR_RBA" },
/* 3122*/ { MQ_MQCACF_SYSP_LOG_RBA, "MQCACF_SYSP_LOG_RBA" },
/* 3123*/ { MQ_MQCACF_SYSP_SERVICE, "MQCACF_SYSP_SERVICE" },
/* 3124*/ { MQ_MQCACF_FROM_LISTENER_NAME, "MQCACF_FROM_LISTENER_NAME" },
/* 3125*/ { MQ_MQCACF_TO_LISTENER_NAME, "MQCACF_TO_LISTENER_NAME" },
/* 3126*/ { MQ_MQCACF_FROM_SERVICE_NAME, "MQCACF_FROM_SERVICE_NAME" },
/* 3127*/ { MQ_MQCACF_TO_SERVICE_NAME, "MQCACF_TO_SERVICE_NAME" },
/* 3128*/ { MQ_MQCACF_LAST_PUT_DATE, "MQCACF_LAST_PUT_DATE" },
/* 3129*/ { MQ_MQCACF_LAST_PUT_TIME, "MQCACF_LAST_PUT_TIME" },
/* 3130*/ { MQ_MQCACF_LAST_GET_DATE, "MQCACF_LAST_GET_DATE" },
/* 3131*/ { MQ_MQCACF_LAST_GET_TIME, "MQCACF_LAST_GET_TIME" },
/* 3132*/ { MQ_MQCACF_OPERATION_DATE, "MQCACF_OPERATION_DATE" },
/* 3133*/ { MQ_MQCACF_OPERATION_TIME, "MQCACF_OPERATION_TIME" },
/* 3134*/ { MQ_MQCACF_ACTIVITY_DESC, "MQCACF_ACTIVITY_DESC" },
/* 3135*/ { MQ_MQCACF_APPL_IDENTITY_DATA, "MQCACF_APPL_IDENTITY_DATA" },
/* 3136*/ { MQ_MQCACF_APPL_ORIGIN_DATA, "MQCACF_APPL_ORIGIN_DATA" },
/* 3137*/ { MQ_MQCACF_PUT_DATE, "MQCACF_PUT_DATE" },
/* 3138*/ { MQ_MQCACF_PUT_TIME, "MQCACF_PUT_TIME" },
/* 3139*/ { MQ_MQCACF_REPLY_TO_Q, "MQCACF_REPLY_TO_Q" },
/* 3140*/ { MQ_MQCACF_REPLY_TO_Q_MGR, "MQCACF_REPLY_TO_Q_MGR" },
/* 3141*/ { MQ_MQCACF_RESOLVED_Q_NAME, "MQCACF_RESOLVED_Q_NAME" },
/* 3142*/ { MQ_MQCACF_STRUC_ID, "MQCACF_STRUC_ID" },
/* 3143*/ { MQ_MQCACF_VALUE_NAME, "MQCACF_VALUE_NAME" },
/* 3144*/ { MQ_MQCACF_SERVICE_START_DATE, "MQCACF_SERVICE_START_DATE" },
/* 3145*/ { MQ_MQCACF_SERVICE_START_TIME, "MQCACF_SERVICE_START_TIME" },
/* 3146*/ { MQ_MQCACF_SYSP_OFFLINE_RBA, "MQCACF_SYSP_OFFLINE_RBA" },
/* 3147*/ { MQ_MQCACF_SYSP_ARCHIVE_PFX2, "MQCACF_SYSP_ARCHIVE_PFX2" },
/* 3148*/ { MQ_MQCACF_SYSP_ARCHIVE_UNIT2, "MQCACF_SYSP_ARCHIVE_UNIT2" },
/* 3149*/ { MQ_MQCACF_TO_TOPIC_NAME, "MQCACF_TO_TOPIC_NAME" },
/* 3150*/ { MQ_MQCACF_FROM_TOPIC_NAME, "MQCACF_FROM_TOPIC_NAME" },
/* 3151*/ { MQ_MQCACF_TOPIC_NAMES, "MQCACF_TOPIC_NAMES" },
/* 3152*/ { MQ_MQCACF_SUB_NAME, "MQCACF_SUB_NAME" },
/* 3153*/ { MQ_MQCACF_DESTINATION_Q_MGR, "MQCACF_DESTINATION_Q_MGR" },
/* 3154*/ { MQ_MQCACF_DESTINATION, "MQCACF_DESTINATION" },
/* 3156*/ { MQ_MQCACF_SUB_USER_ID, "MQCACF_SUB_USER_ID" },
/* 3159*/ { MQ_MQCACF_SUB_USER_DATA, "MQCACF_SUB_USER_DATA" },
/* 3160*/ { MQ_MQCACF_SUB_SELECTOR, "MQCACF_SUB_SELECTOR" },
/* 3161*/ { MQ_MQCACF_LAST_PUB_DATE, "MQCACF_LAST_PUB_DATE" },
/* 3162*/ { MQ_MQCACF_LAST_PUB_TIME, "MQCACF_LAST_PUB_TIME" },
/* 3163*/ { MQ_MQCACF_FROM_SUB_NAME, "MQCACF_FROM_SUB_NAME" },
/* 3164*/ { MQ_MQCACF_TO_SUB_NAME, "MQCACF_TO_SUB_NAME" },
/* 3167*/ { MQ_MQCACF_LAST_MSG_TIME, "MQCACF_LAST_MSG_TIME" },
/* 3168*/ { MQ_MQCACF_LAST_MSG_DATE, "MQCACF_LAST_MSG_DATE" },
/* 3169*/ { MQ_MQCACF_SUBSCRIPTION_POINT, "MQCACF_SUBSCRIPTION_POINT" },
/* 3170*/ { MQ_MQCACF_FILTER, "MQCACF_FILTER" },
/* 3171*/ { MQ_MQCACF_NONE, "MQCACF_NONE" },
/* 3172*/ { MQ_MQCACF_ADMIN_TOPIC_NAMES, "MQCACF_ADMIN_TOPIC_NAMES" },
/* 3172*/ { MQ_MQCACF_ADMIN_TOPIC_NAMES, "MQCACF_ADMIN_TOPIC_NAMES" },
/* 3173*/ { MQ_MQCACF_ROUTING_FINGER_PRINT, "MQCACF_ROUTING_FINGER_PRINT" },
/* 3173*/ { MQ_MQCACF_ROUTING_FINGER_PRINT, "MQCACF_ROUTING_FINGER_PRINT" },
/* 3174*/ { MQ_MQCACF_APPL_DESC, "MQCACF_APPL_DESC" },
/* 3174*/ { MQ_MQCACF_APPL_DESC, "MQCACF_APPL_DESC" },
/* 3175*/ { MQ_MQCACF_Q_MGR_START_DATE, "MQCACF_Q_MGR_START_DATE" },
/* 3176*/ { MQ_MQCACF_Q_MGR_START_TIME, "MQCACF_Q_MGR_START_TIME" },
/* 3177*/ { MQ_MQCACF_FROM_COMM_INFO_NAME, "MQCACF_FROM_COMM_INFO_NAME" },
/* 3178*/ { MQ_MQCACF_TO_COMM_INFO_NAME, "MQCACF_TO_COMM_INFO_NAME" },
/* 3179*/ { MQ_MQCACF_CF_OFFLOAD_SIZE1, "MQCACF_CF_OFFLOAD_SIZE1" },
/* 3180*/ { MQ_MQCACF_CF_OFFLOAD_SIZE2, "MQCACF_CF_OFFLOAD_SIZE2" },
/* 3181*/ { MQ_MQCACF_CF_OFFLOAD_SIZE3, "MQCACF_CF_OFFLOAD_SIZE3" },
/* 3182*/ { MQ_MQCACF_CF_SMDS_GENERIC_NAME, "MQCACF_CF_SMDS_GENERIC_NAME" },
/* 3183*/ { MQ_MQCACF_CF_SMDS, "MQCACF_CF_SMDS" },
/* 3184*/ { MQ_MQCACF_RECOVERY_DATE, "MQCACF_RECOVERY_DATE" },
/* 3185*/ { MQ_MQCACF_RECOVERY_TIME, "MQCACF_RECOVERY_TIME" },
/* 3186*/ { MQ_MQCACF_CF_SMDSCONN, "MQCACF_CF_SMDSCONN" },
/* 3187*/ { MQ_MQCACF_CF_STRUC_NAME, "MQCACF_CF_STRUC_NAME" },
/* 3188*/ { MQ_MQCACF_ALTERNATE_USERID, "MQCACF_ALTERNATE_USERID" },
/* 3189*/ { MQ_MQCACF_CHAR_ATTRS, "MQCACF_CHAR_ATTRS" },
/* 3190*/ { MQ_MQCACF_DYNAMIC_Q_NAME, "MQCACF_DYNAMIC_Q_NAME" },
/* 3191*/ { MQ_MQCACF_HOST_NAME, "MQCACF_HOST_NAME" },
/* 3192*/ { MQ_MQCACF_MQCB_NAME, "MQCACF_MQCB_NAME" },
/* 3193*/ { MQ_MQCACF_OBJECT_STRING, "MQCACF_OBJECT_STRING" },
/* 3194*/ { MQ_MQCACF_RESOLVED_LOCAL_Q_MGR, "MQCACF_RESOLVED_LOCAL_Q_MGR" },
/* 3195*/ { MQ_MQCACF_RESOLVED_LOCAL_Q_NAME, "MQCACF_RESOLVED_LOCAL_Q_NAME" },
/* 3196*/ { MQ_MQCACF_RESOLVED_OBJECT_STRING, "MQCACF_RESOLVED_OBJECT_STRING" },
/* 3197*/ { MQ_MQCACF_RESOLVED_Q_MGR, "MQCACF_RESOLVED_Q_MGR" },
/* 3198*/ { MQ_MQCACF_SELECTION_STRING, "MQCACF_SELECTION_STRING" },
/* 3199*/ { MQ_MQCACF_XA_INFO, "MQCACF_XA_INFO" },
/* 3200*/ { MQ_MQCACF_APPL_FUNCTION, "MQCACF_APPL_FUNCTION" },
/* 3201*/ { MQ_MQCACF_XQH_REMOTE_Q_NAME, "MQCACF_XQH_REMOTE_Q_NAME" },
/* 3202*/ { MQ_MQCACF_XQH_REMOTE_Q_MGR, "MQCACF_XQH_REMOTE_Q_MGR" },
/* 3203*/ { MQ_MQCACF_XQH_PUT_TIME, "MQCACF_XQH_PUT_TIME" },
/* 3204*/ { MQ_MQCACF_XQH_PUT_DATE, "MQCACF_XQH_PUT_DATE" },
/* 3205*/ { MQ_MQCACF_EXCL_OPERATOR_MESSAGES, "MQCACF_EXCL_OPERATOR_MESSAGES" },
/* 3206*/ { MQ_MQCACF_CSP_USER_IDENTIFIER, "MQCACF_CSP_USER_IDENTIFIER" },
/* 3207*/ { MQ_MQCACF_AMQP_CLIENT_ID, "MQCACF_AMQP_CLIENT_ID" },
/* 3208*/ { MQ_MQCACF_ARCHIVE_LOG_EXTENT_NAME, "MQCACF_ARCHIVE_LOG_EXTENT_NAME" },
/* 3501*/ { MQ_MQCACH_CHANNEL_NAME, "MQCACH_CHANNEL_NAME" },
/* 3502*/ { MQ_MQCACH_DESC, "MQCACH_DESC" },
/* 3503*/ { MQ_MQCACH_MODE_NAME, "MQCACH_MODE_NAME" },
/* 3504*/ { MQ_MQCACH_TP_NAME, "MQCACH_TP_NAME" },
/* 3505*/ { MQ_MQCACH_XMIT_Q_NAME, "MQCACH_XMIT_Q_NAME" },
/* 3506*/ { MQ_MQCACH_CONNECTION_NAME, "MQCACH_CONNECTION_NAME" },
/* 3507*/ { MQ_MQCACH_MCA_NAME, "MQCACH_MCA_NAME" },
/* 3508*/ { MQ_MQCACH_SEC_EXIT_NAME, "MQCACH_SEC_EXIT_NAME" },
/* 3509*/ { MQ_MQCACH_MSG_EXIT_NAME, "MQCACH_MSG_EXIT_NAME" },
/* 3510*/ { MQ_MQCACH_SEND_EXIT_NAME, "MQCACH_SEND_EXIT_NAME" },
/* 3511*/ { MQ_MQCACH_RCV_EXIT_NAME, "MQCACH_RCV_EXIT_NAME" },
/* 3512*/ { MQ_MQCACH_CHANNEL_NAMES, "MQCACH_CHANNEL_NAMES" },
/* 3513*/ { MQ_MQCACH_SEC_EXIT_USER_DATA, "MQCACH_SEC_EXIT_USER_DATA" },
/* 3514*/ { MQ_MQCACH_MSG_EXIT_USER_DATA, "MQCACH_MSG_EXIT_USER_DATA" },
/* 3515*/ { MQ_MQCACH_SEND_EXIT_USER_DATA, "MQCACH_SEND_EXIT_USER_DATA" },
/* 3516*/ { MQ_MQCACH_RCV_EXIT_USER_DATA, "MQCACH_RCV_EXIT_USER_DATA" },
/* 3517*/ { MQ_MQCACH_USER_ID, "MQCACH_USER_ID" },
/* 3518*/ { MQ_MQCACH_PASSWORD, "MQCACH_PASSWORD" },
/* 3520*/ { MQ_MQCACH_LOCAL_ADDRESS, "MQCACH_LOCAL_ADDRESS" },
/* 3521*/ { MQ_MQCACH_LOCAL_NAME, "MQCACH_LOCAL_NAME" },
/* 3524*/ { MQ_MQCACH_LAST_MSG_TIME, "MQCACH_LAST_MSG_TIME" },
/* 3525*/ { MQ_MQCACH_LAST_MSG_DATE, "MQCACH_LAST_MSG_DATE" },
/* 3527*/ { MQ_MQCACH_MCA_USER_ID, "MQCACH_MCA_USER_ID" },
/* 3528*/ { MQ_MQCACH_CHANNEL_START_TIME, "MQCACH_CHANNEL_START_TIME" },
/* 3529*/ { MQ_MQCACH_CHANNEL_START_DATE, "MQCACH_CHANNEL_START_DATE" },
/* 3530*/ { MQ_MQCACH_MCA_JOB_NAME, "MQCACH_MCA_JOB_NAME" },
/* 3531*/ { MQ_MQCACH_LAST_LUWID, "MQCACH_LAST_LUWID" },
/* 3532*/ { MQ_MQCACH_CURRENT_LUWID, "MQCACH_CURRENT_LUWID" },
/* 3533*/ { MQ_MQCACH_FORMAT_NAME, "MQCACH_FORMAT_NAME" },
/* 3534*/ { MQ_MQCACH_MR_EXIT_NAME, "MQCACH_MR_EXIT_NAME" },
/* 3535*/ { MQ_MQCACH_MR_EXIT_USER_DATA, "MQCACH_MR_EXIT_USER_DATA" },
/* 3544*/ { MQ_MQCACH_SSL_CIPHER_SPEC, "MQCACH_SSL_CIPHER_SPEC" },
/* 3545*/ { MQ_MQCACH_SSL_PEER_NAME, "MQCACH_SSL_PEER_NAME" },
/* 3546*/ { MQ_MQCACH_SSL_HANDSHAKE_STAGE, "MQCACH_SSL_HANDSHAKE_STAGE" },
/* 3547*/ { MQ_MQCACH_SSL_SHORT_PEER_NAME, "MQCACH_SSL_SHORT_PEER_NAME" },
/* 3548*/ { MQ_MQCACH_REMOTE_APPL_TAG, "MQCACH_REMOTE_APPL_TAG" },
/* 3549*/ { MQ_MQCACH_SSL_CERT_USER_ID, "MQCACH_SSL_CERT_USER_ID" },
/* 3550*/ { MQ_MQCACH_SSL_CERT_ISSUER_NAME, "MQCACH_SSL_CERT_ISSUER_NAME" },
/* 3551*/ { MQ_MQCACH_LU_NAME, "MQCACH_LU_NAME" },
/* 3552*/ { MQ_MQCACH_IP_ADDRESS, "MQCACH_IP_ADDRESS" },
/* 3553*/ { MQ_MQCACH_TCP_NAME, "MQCACH_TCP_NAME" },
/* 3554*/ { MQ_MQCACH_LISTENER_NAME, "MQCACH_LISTENER_NAME" },
/* 3555*/ { MQ_MQCACH_LISTENER_DESC, "MQCACH_LISTENER_DESC" },
/* 3556*/ { MQ_MQCACH_LISTENER_START_DATE, "MQCACH_LISTENER_START_DATE" },
/* 3557*/ { MQ_MQCACH_LISTENER_START_TIME, "MQCACH_LISTENER_START_TIME" },
/* 3558*/ { MQ_MQCACH_SSL_KEY_RESET_DATE, "MQCACH_SSL_KEY_RESET_DATE" },
/* 3559*/ { MQ_MQCACH_SSL_KEY_RESET_TIME, "MQCACH_SSL_KEY_RESET_TIME" },
/* 3560*/ { MQ_MQCACH_REMOTE_VERSION, "MQCACH_REMOTE_VERSION" },
/* 3561*/ { MQ_MQCACH_REMOTE_PRODUCT, "MQCACH_REMOTE_PRODUCT" },
/* 3562*/ { MQ_MQCACH_GROUP_ADDRESS, "MQCACH_GROUP_ADDRESS" },
/* 3563*/ { MQ_MQCACH_JAAS_CONFIG, "MQCACH_JAAS_CONFIG" },
/* 3564*/ { MQ_MQCACH_CLIENT_ID, "MQCACH_CLIENT_ID" },
/* 3565*/ { MQ_MQCACH_SSL_KEY_PASSPHRASE, "MQCACH_SSL_KEY_PASSPHRASE" },
/* 3566*/ { MQ_MQCACH_CONNECTION_NAME_LIST, "MQCACH_CONNECTION_NAME_LIST" },
/* 3567*/ { MQ_MQCACH_CLIENT_USER_ID, "MQCACH_CLIENT_USER_ID" },
/* 3568*/ { MQ_MQCACH_MCA_USER_ID_LIST, "MQCACH_MCA_USER_ID_LIST" },
/* 3569*/ { MQ_MQCACH_SSL_CIPHER_SUITE, "MQCACH_SSL_CIPHER_SUITE" },
/* 3570*/ { MQ_MQCACH_WEBCONTENT_PATH, "MQCACH_WEBCONTENT_PATH" },
/* 3571*/ { MQ_MQCACH_TOPIC_ROOT, "MQCACH_TOPIC_ROOT" },
/* 4000*/ { MQ_MQCA_USER_LIST, "MQCA_USER_LIST" },
/* 7001*/ { MQ_MQBACF_EVENT_ACCOUNTING_TOKEN, "MQBACF_EVENT_ACCOUNTING_TOKEN" },
/* 7002*/ { MQ_MQBACF_EVENT_SECURITY_ID, "MQBACF_EVENT_SECURITY_ID" },
/* 7003*/ { MQ_MQBACF_RESPONSE_SET, "MQBACF_RESPONSE_SET" },
/* 7004*/ { MQ_MQBACF_RESPONSE_ID, "MQBACF_RESPONSE_ID" },
/* 7005*/ { MQ_MQBACF_EXTERNAL_UOW_ID, "MQBACF_EXTERNAL_UOW_ID" },
/* 7006*/ { MQ_MQBACF_CONNECTION_ID, "MQBACF_CONNECTION_ID" },
/* 7007*/ { MQ_MQBACF_GENERIC_CONNECTION_ID, "MQBACF_GENERIC_CONNECTION_ID" },
/* 7008*/ { MQ_MQBACF_ORIGIN_UOW_ID, "MQBACF_ORIGIN_UOW_ID" },
/* 7009*/ { MQ_MQBACF_Q_MGR_UOW_ID, "MQBACF_Q_MGR_UOW_ID" },
/* 7010*/ { MQ_MQBACF_ACCOUNTING_TOKEN, "MQBACF_ACCOUNTING_TOKEN" },
/* 7011*/ { MQ_MQBACF_CORREL_ID, "MQBACF_CORREL_ID" },
/* 7012*/ { MQ_MQBACF_GROUP_ID, "MQBACF_GROUP_ID" },
/* 7013*/ { MQ_MQBACF_MSG_ID, "MQBACF_MSG_ID" },
/* 7014*/ { MQ_MQBACF_CF_LEID, "MQBACF_CF_LEID" },
/* 7015*/ { MQ_MQBACF_DESTINATION_CORREL_ID, "MQBACF_DESTINATION_CORREL_ID" },
/* 7016*/ { MQ_MQBACF_SUB_ID, "MQBACF_SUB_ID" },
/* 7019*/ { MQ_MQBACF_ALTERNATE_SECURITYID, "MQBACF_ALTERNATE_SECURITYID" },
/* 7020*/ { MQ_MQBACF_MESSAGE_DATA, "MQBACF_MESSAGE_DATA" },
/* 7021*/ { MQ_MQBACF_MQBO_STRUCT, "MQBACF_MQBO_STRUCT" },
/* 7022*/ { MQ_MQBACF_MQCB_FUNCTION, "MQBACF_MQCB_FUNCTION" },
/* 7023*/ { MQ_MQBACF_MQCBC_STRUCT, "MQBACF_MQCBC_STRUCT" },
/* 7024*/ { MQ_MQBACF_MQCBD_STRUCT, "MQBACF_MQCBD_STRUCT" },
/* 7025*/ { MQ_MQBACF_MQCD_STRUCT, "MQBACF_MQCD_STRUCT" },
/* 7026*/ { MQ_MQBACF_MQCNO_STRUCT, "MQBACF_MQCNO_STRUCT" },
/* 7027*/ { MQ_MQBACF_MQGMO_STRUCT, "MQBACF_MQGMO_STRUCT" },
/* 7028*/ { MQ_MQBACF_MQMD_STRUCT, "MQBACF_MQMD_STRUCT" },
/* 7029*/ { MQ_MQBACF_MQPMO_STRUCT, "MQBACF_MQPMO_STRUCT" },
/* 7030*/ { MQ_MQBACF_MQSD_STRUCT, "MQBACF_MQSD_STRUCT" },
/* 7031*/ { MQ_MQBACF_MQSTS_STRUCT, "MQBACF_MQSTS_STRUCT" },
/* 7032*/ { MQ_MQBACF_SUB_CORREL_ID, "MQBACF_SUB_CORREL_ID" },
/* 7033*/ { MQ_MQBACF_XA_XID, "MQBACF_XA_XID" },
/* 7034*/ { MQ_MQBACF_XQH_CORREL_ID, "MQBACF_XQH_CORREL_ID" },
/* 7035*/ { MQ_MQBACF_XQH_MSG_ID, "MQBACF_XQH_MSG_ID" },
/* 7036*/ { MQ_MQBACF_REQUEST_ID, "MQBACF_REQUEST_ID" },
/* 7037*/ { MQ_MQBACF_PROPERTIES_DATA, "MQBACF_PROPERTIES_DATA" },
/* 7038*/ { MQ_MQBACF_CONN_TAG, "MQBACF_CONN_TAG" },
/* 8001*/ { MQ_MQGACF_COMMAND_CONTEXT, "MQGACF_COMMAND_CONTEXT" },
/* 8002*/ { MQ_MQGACF_COMMAND_DATA, "MQGACF_COMMAND_DATA" },
/* 8003*/ { MQ_MQGACF_TRACE_ROUTE, "MQGACF_TRACE_ROUTE" },
/* 8004*/ { MQ_MQGACF_OPERATION, "MQGACF_OPERATION" },
/* 8005*/ { MQ_MQGACF_ACTIVITY, "MQGACF_ACTIVITY" },
/* 8006*/ { MQ_MQGACF_EMBEDDED_MQMD, "MQGACF_EMBEDDED_MQMD" },
/* 8007*/ { MQ_MQGACF_MESSAGE, "MQGACF_MESSAGE" },
/* 8008*/ { MQ_MQGACF_MQMD, "MQGACF_MQMD" },
/* 8009*/ { MQ_MQGACF_VALUE_NAMING, "MQGACF_VALUE_NAMING" },
/* 8010*/ { MQ_MQGACF_Q_ACCOUNTING_DATA, "MQGACF_Q_ACCOUNTING_DATA" },
/* 8011*/ { MQ_MQGACF_Q_STATISTICS_DATA, "MQGACF_Q_STATISTICS_DATA" },
/* 8012*/ { MQ_MQGACF_CHL_STATISTICS_DATA, "MQGACF_CHL_STATISTICS_DATA" },
/* 8013*/ { MQ_MQGACF_ACTIVITY_TRACE, "MQGACF_ACTIVITY_TRACE" },
/* 8014*/ { MQ_MQGACF_APP_DIST_LIST, "MQGACF_APP_DIST_LIST" },
/* 8015*/ { MQ_MQGACF_MONITOR_CLASS, "MQGACF_MONITOR_CLASS" },
/* 8016*/ { MQ_MQGACF_MONITOR_TYPE, "MQGACF_MONITOR_TYPE" },
/* 8017*/ { MQ_MQGACF_MONITOR_ELEMENT, "MQGACF_MONITOR_ELEMENT" },
    { 0, NULL }
};
value_string_ext mq_PrmId_xvals = VALUE_STRING_EXT_INIT(mq_PrmId_vals);

static const value_string mq_PrmTyp_vals[] =
{
/*    0*/ { MQ_MQCFT_NONE, "MQCFT_NONE" },
/*    1*/ { MQ_MQCFT_COMMAND, "MQCFT_COMMAND" },
/*    2*/ { MQ_MQCFT_RESPONSE, "MQCFT_RESPONSE" },
/*    3*/ { MQ_MQCFT_INTEGER, "MQCFT_INTEGER" },
/*    4*/ { MQ_MQCFT_STRING, "MQCFT_STRING" },
/*    5*/ { MQ_MQCFT_INTEGER_LIST, "MQCFT_INTEGER_LIST" },
/*    6*/ { MQ_MQCFT_STRING_LIST, "MQCFT_STRING_LIST" },
/*    7*/ { MQ_MQCFT_EVENT, "MQCFT_EVENT" },
/*    8*/ { MQ_MQCFT_USER, "MQCFT_USER" },
/*    9*/ { MQ_MQCFT_BYTE_STRING, "MQCFT_BYTE_STRING" },
/*   10*/ { MQ_MQCFT_TRACE_ROUTE, "MQCFT_TRACE_ROUTE" },
/*   12*/ { MQ_MQCFT_REPORT, "MQCFT_REPORT" },
/*   13*/ { MQ_MQCFT_INTEGER_FILTER, "MQCFT_INTEGER_FILTER" },
/*   14*/ { MQ_MQCFT_STRING_FILTER, "MQCFT_STRING_FILTER" },
/*   15*/ { MQ_MQCFT_BYTE_STRING_FILTER, "MQCFT_BYTE_STRING_FILTER" },
/*   16*/ { MQ_MQCFT_COMMAND_XR, "MQCFT_COMMAND_XR" },
/*   17*/ { MQ_MQCFT_XR_MSG, "MQCFT_XR_MSG" },
/*   18*/ { MQ_MQCFT_XR_ITEM, "MQCFT_XR_ITEM" },
/*   19*/ { MQ_MQCFT_XR_SUMMARY, "MQCFT_XR_SUMMARY" },
/*   20*/ { MQ_MQCFT_GROUP, "MQCFT_GROUP" },
/*   21*/ { MQ_MQCFT_STATISTICS, "MQCFT_STATISTICS" },
/*   22*/ { MQ_MQCFT_ACCOUNTING, "MQCFT_ACCOUNTING" },
/*   23*/ { MQ_MQCFT_INTEGER64, "MQCFT_INTEGER64" },
/*   25*/ { MQ_MQCFT_INTEGER64_LIST, "MQCFT_INTEGER64_LIST" },
    { 0, NULL }
};
value_string_ext mq_PrmTyp_xvals = VALUE_STRING_EXT_INIT(mq_PrmTyp_vals);

static const value_string mq_PrmTyp2_vals[] =
{
/*    0*/ { MQ_MQCFT_NONE, "MQCFT_NONE" },
/*    1*/ { MQ_MQCFT_CMD, "MQCFT_CMD" },
/*    2*/ { MQ_MQCFT_RSP, "MQCFT_RSP" },
/*    3*/ { MQ_MQCFT_INT, "MQCFT_INT" },
/*    4*/ { MQ_MQCFT_STR, "MQCFT_STR" },
/*    5*/ { MQ_MQCFT_INTL, "MQCFT_INTL" },
/*    6*/ { MQ_MQCFT_STRL, "MQCFT_STRL" },
/*    7*/ { MQ_MQCFT_EVT, "MQCFT_EVT" },
/*    8*/ { MQ_MQCFT_USR, "MQCFT_USR" },
/*    9*/ { MQ_MQCFT_BSTR, "MQCFT_BSTR" },
/*   10*/ { MQ_MQCFT_TRC, "MQCFT_TRC" },
/*   12*/ { MQ_MQCFT_RPT, "MQCFT_RPT" },
/*   13*/ { MQ_MQCFT_INTF, "MQCFT_INTF" },
/*   14*/ { MQ_MQCFT_STRF, "MQCFT_STRF" },
/*   15*/ { MQ_MQCFT_BSTF, "MQCFT_BSTF" },
/*   16*/ { MQ_MQCFT_CMDX, "MQCFT_CMDX" },
/*   17*/ { MQ_MQCFT_XMSG, "MQCFT_XMSG" },
/*   18*/ { MQ_MQCFT_XITM, "MQCFT_XITM" },
/*   19*/ { MQ_MQCFT_XSUM, "MQCFT_XSUM" },
/*   20*/ { MQ_MQCFT_GRP, "MQCFT_GRP" },
/*   21*/ { MQ_MQCFT_STAT, "MQCFT_STAT" },
/*   22*/ { MQ_MQCFT_ACNT, "MQCFT_ACNT" },
/*   23*/ { MQ_MQCFT_I64, "MQCFT_I64" },
/*   25*/ { MQ_MQCFT_I64L, "MQCFT_I64L" },
    { 0, NULL }
};
value_string_ext mq_PrmTyp2_xvals = VALUE_STRING_EXT_INIT(mq_PrmTyp2_vals);

static const value_string mq_selector_vals[] =
{
/*    1*/ { MQ_MQIA_APPL_TYPE, "MQIA_APPL_TYPE" },
/*    2*/ { MQ_MQIA_CODED_CHAR_SET_ID, "MQIA_CODED_CHAR_SET_ID" },
/*    3*/ { MQ_MQIA_CURRENT_Q_DEPTH, "MQIA_CURRENT_Q_DEPTH" },
/*    4*/ { MQ_MQIA_DEF_INPUT_OPEN_OPTION, "MQIA_DEF_INPUT_OPEN_OPTION" },
/*    5*/ { MQ_MQIA_DEF_PERSISTENCE, "MQIA_DEF_PERSISTENCE" },
/*    6*/ { MQ_MQIA_DEF_PRIORITY, "MQIA_DEF_PRIORITY" },
/*    7*/ { MQ_MQIA_DEFINITION_TYPE, "MQIA_DEFINITION_TYPE" },
/*    8*/ { MQ_MQIA_HARDEN_GET_BACKOUT, "MQIA_HARDEN_GET_BACKOUT" },
/*    9*/ { MQ_MQIA_INHIBIT_GET, "MQIA_INHIBIT_GET" },
/*   10*/ { MQ_MQIA_INHIBIT_PUT, "MQIA_INHIBIT_PUT" },
/*   11*/ { MQ_MQIA_MAX_HANDLES, "MQIA_MAX_HANDLES" },
/*   12*/ { MQ_MQIA_USAGE, "MQIA_USAGE" },
/*   13*/ { MQ_MQIA_MAX_MSG_LENGTH, "MQIA_MAX_MSG_LENGTH" },
/*   14*/ { MQ_MQIA_MAX_PRIORITY, "MQIA_MAX_PRIORITY" },
/*   15*/ { MQ_MQIA_MAX_Q_DEPTH, "MQIA_MAX_Q_DEPTH" },
/*   16*/ { MQ_MQIA_MSG_DELIVERY_SEQUENCE, "MQIA_MSG_DELIVERY_SEQUENCE" },
/*   17*/ { MQ_MQIA_OPEN_INPUT_COUNT, "MQIA_OPEN_INPUT_COUNT" },
/*   18*/ { MQ_MQIA_OPEN_OUTPUT_COUNT, "MQIA_OPEN_OUTPUT_COUNT" },
/*   19*/ { MQ_MQIA_NAME_COUNT, "MQIA_NAME_COUNT" },
/*   20*/ { MQ_MQIA_Q_TYPE, "MQIA_Q_TYPE" },
/*   21*/ { MQ_MQIA_RETENTION_INTERVAL, "MQIA_RETENTION_INTERVAL" },
/*   22*/ { MQ_MQIA_BACKOUT_THRESHOLD, "MQIA_BACKOUT_THRESHOLD" },
/*   23*/ { MQ_MQIA_SHAREABILITY, "MQIA_SHAREABILITY" },
/*   24*/ { MQ_MQIA_TRIGGER_CONTROL, "MQIA_TRIGGER_CONTROL" },
/*   25*/ { MQ_MQIA_TRIGGER_INTERVAL, "MQIA_TRIGGER_INTERVAL" },
/*   26*/ { MQ_MQIA_TRIGGER_MSG_PRIORITY, "MQIA_TRIGGER_MSG_PRIORITY" },
/*   27*/ { MQ_MQIA_CPI_LEVEL, "MQIA_CPI_LEVEL" },
/*   28*/ { MQ_MQIA_TRIGGER_TYPE, "MQIA_TRIGGER_TYPE" },
/*   29*/ { MQ_MQIA_TRIGGER_DEPTH, "MQIA_TRIGGER_DEPTH" },
/*   30*/ { MQ_MQIA_SYNCPOINT, "MQIA_SYNCPOINT" },
/*   31*/ { MQ_MQIA_COMMAND_LEVEL, "MQIA_COMMAND_LEVEL" },
/*   32*/ { MQ_MQIA_PLATFORM, "MQIA_PLATFORM" },
/*   33*/ { MQ_MQIA_MAX_UNCOMMITTED_MSGS, "MQIA_MAX_UNCOMMITTED_MSGS" },
/*   34*/ { MQ_MQIA_DIST_LISTS, "MQIA_DIST_LISTS" },
/*   35*/ { MQ_MQIA_TIME_SINCE_RESET, "MQIA_TIME_SINCE_RESET" },
/*   36*/ { MQ_MQIA_HIGH_Q_DEPTH, "MQIA_HIGH_Q_DEPTH" },
/*   37*/ { MQ_MQIA_MSG_ENQ_COUNT, "MQIA_MSG_ENQ_COUNT" },
/*   38*/ { MQ_MQIA_MSG_DEQ_COUNT, "MQIA_MSG_DEQ_COUNT" },
/*   39*/ { MQ_MQIA_EXPIRY_INTERVAL, "MQIA_EXPIRY_INTERVAL" },
/*   40*/ { MQ_MQIA_Q_DEPTH_HIGH_LIMIT, "MQIA_Q_DEPTH_HIGH_LIMIT" },
/*   41*/ { MQ_MQIA_Q_DEPTH_LOW_LIMIT, "MQIA_Q_DEPTH_LOW_LIMIT" },
/*   42*/ { MQ_MQIA_Q_DEPTH_MAX_EVENT, "MQIA_Q_DEPTH_MAX_EVENT" },
/*   43*/ { MQ_MQIA_Q_DEPTH_HIGH_EVENT, "MQIA_Q_DEPTH_HIGH_EVENT" },
/*   44*/ { MQ_MQIA_Q_DEPTH_LOW_EVENT, "MQIA_Q_DEPTH_LOW_EVENT" },
/*   45*/ { MQ_MQIA_SCOPE, "MQIA_SCOPE" },
/*   46*/ { MQ_MQIA_Q_SERVICE_INTERVAL_EVENT, "MQIA_Q_SERVICE_INTERVAL_EVENT" },
/*   47*/ { MQ_MQIA_AUTHORITY_EVENT, "MQIA_AUTHORITY_EVENT" },
/*   48*/ { MQ_MQIA_INHIBIT_EVENT, "MQIA_INHIBIT_EVENT" },
/*   49*/ { MQ_MQIA_LOCAL_EVENT, "MQIA_LOCAL_EVENT" },
/*   50*/ { MQ_MQIA_REMOTE_EVENT, "MQIA_REMOTE_EVENT" },
/*   51*/ { MQ_MQIA_CONFIGURATION_EVENT, "MQIA_CONFIGURATION_EVENT" },
/*   52*/ { MQ_MQIA_START_STOP_EVENT, "MQIA_START_STOP_EVENT" },
/*   53*/ { MQ_MQIA_PERFORMANCE_EVENT, "MQIA_PERFORMANCE_EVENT" },
/*   54*/ { MQ_MQIA_Q_SERVICE_INTERVAL, "MQIA_Q_SERVICE_INTERVAL" },
/*   55*/ { MQ_MQIA_CHANNEL_AUTO_DEF, "MQIA_CHANNEL_AUTO_DEF" },
/*   56*/ { MQ_MQIA_CHANNEL_AUTO_DEF_EVENT, "MQIA_CHANNEL_AUTO_DEF_EVENT" },
/*   57*/ { MQ_MQIA_INDEX_TYPE, "MQIA_INDEX_TYPE" },
/*   58*/ { MQ_MQIA_CLUSTER_WORKLOAD_LENGTH, "MQIA_CLUSTER_WORKLOAD_LENGTH" },
/*   59*/ { MQ_MQIA_CLUSTER_Q_TYPE, "MQIA_CLUSTER_Q_TYPE" },
/*   60*/ { MQ_MQIA_ARCHIVE, "MQIA_ARCHIVE" },
/*   61*/ { MQ_MQIA_DEF_BIND, "MQIA_DEF_BIND" },
/*   62*/ { MQ_MQIA_PAGESET_ID, "MQIA_PAGESET_ID" },
/*   63*/ { MQ_MQIA_QSG_DISP, "MQIA_QSG_DISP" },
/*   64*/ { MQ_MQIA_INTRA_GROUP_QUEUING, "MQIA_INTRA_GROUP_QUEUING" },
/*   65*/ { MQ_MQIA_IGQ_PUT_AUTHORITY, "MQIA_IGQ_PUT_AUTHORITY" },
/*   66*/ { MQ_MQIA_AUTH_INFO_TYPE, "MQIA_AUTH_INFO_TYPE" },
/*   68*/ { MQ_MQIA_MSG_MARK_BROWSE_INTERVAL, "MQIA_MSG_MARK_BROWSE_INTERVAL" },
/*   69*/ { MQ_MQIA_SSL_TASKS, "MQIA_SSL_TASKS" },
/*   70*/ { MQ_MQIA_CF_LEVEL, "MQIA_CF_LEVEL" },
/*   71*/ { MQ_MQIA_CF_RECOVER, "MQIA_CF_RECOVER" },
/*   72*/ { MQ_MQIA_NAMELIST_TYPE, "MQIA_NAMELIST_TYPE" },
/*   73*/ { MQ_MQIA_CHANNEL_EVENT, "MQIA_CHANNEL_EVENT" },
/*   74*/ { MQ_MQIA_BRIDGE_EVENT, "MQIA_BRIDGE_EVENT" },
/*   75*/ { MQ_MQIA_SSL_EVENT, "MQIA_SSL_EVENT" },
/*   76*/ { MQ_MQIA_SSL_RESET_COUNT, "MQIA_SSL_RESET_COUNT" },
/*   77*/ { MQ_MQIA_SHARED_Q_Q_MGR_NAME, "MQIA_SHARED_Q_Q_MGR_NAME" },
/*   78*/ { MQ_MQIA_NPM_CLASS, "MQIA_NPM_CLASS" },
/*   80*/ { MQ_MQIA_MAX_OPEN_Q, "MQIA_MAX_OPEN_Q" },
/*   81*/ { MQ_MQIA_MONITOR_INTERVAL, "MQIA_MONITOR_INTERVAL" },
/*   82*/ { MQ_MQIA_Q_USERS, "MQIA_Q_USERS" },
/*   83*/ { MQ_MQIA_MAX_GLOBAL_LOCKS, "MQIA_MAX_GLOBAL_LOCKS" },
/*   84*/ { MQ_MQIA_MAX_LOCAL_LOCKS, "MQIA_MAX_LOCAL_LOCKS" },
/*   85*/ { MQ_MQIA_LISTENER_PORT_NUMBER, "MQIA_LISTENER_PORT_NUMBER" },
/*   86*/ { MQ_MQIA_BATCH_INTERFACE_AUTO, "MQIA_BATCH_INTERFACE_AUTO" },
/*   87*/ { MQ_MQIA_CMD_SERVER_AUTO, "MQIA_CMD_SERVER_AUTO" },
/*   88*/ { MQ_MQIA_CMD_SERVER_CONVERT_MSG, "MQIA_CMD_SERVER_CONVERT_MSG" },
/*   89*/ { MQ_MQIA_CMD_SERVER_DLQ_MSG, "MQIA_CMD_SERVER_DLQ_MSG" },
/*   90*/ { MQ_MQIA_MAX_Q_TRIGGERS, "MQIA_MAX_Q_TRIGGERS" },
/*   91*/ { MQ_MQIA_TRIGGER_RESTART, "MQIA_TRIGGER_RESTART" },
/*   92*/ { MQ_MQIA_SSL_FIPS_REQUIRED, "MQIA_SSL_FIPS_REQUIRED" },
/*   93*/ { MQ_MQIA_IP_ADDRESS_VERSION, "MQIA_IP_ADDRESS_VERSION" },
/*   94*/ { MQ_MQIA_LOGGER_EVENT, "MQIA_LOGGER_EVENT" },
/*   95*/ { MQ_MQIA_CLWL_Q_RANK, "MQIA_CLWL_Q_RANK" },
/*   96*/ { MQ_MQIA_CLWL_Q_PRIORITY, "MQIA_CLWL_Q_PRIORITY" },
/*   97*/ { MQ_MQIA_CLWL_MRU_CHANNELS, "MQIA_CLWL_MRU_CHANNELS" },
/*   98*/ { MQ_MQIA_CLWL_USEQ, "MQIA_CLWL_USEQ" },
/*   99*/ { MQ_MQIA_COMMAND_EVENT, "MQIA_COMMAND_EVENT" },
/*  100*/ { MQ_MQIA_ACTIVE_CHANNELS, "MQIA_ACTIVE_CHANNELS" },
/*  101*/ { MQ_MQIA_CHINIT_ADAPTERS, "MQIA_CHINIT_ADAPTERS" },
/*  102*/ { MQ_MQIA_ADOPTNEWMCA_CHECK, "MQIA_ADOPTNEWMCA_CHECK" },
/*  103*/ { MQ_MQIA_ADOPTNEWMCA_TYPE, "MQIA_ADOPTNEWMCA_TYPE" },
/*  104*/ { MQ_MQIA_ADOPTNEWMCA_INTERVAL, "MQIA_ADOPTNEWMCA_INTERVAL" },
/*  105*/ { MQ_MQIA_CHINIT_DISPATCHERS, "MQIA_CHINIT_DISPATCHERS" },
/*  106*/ { MQ_MQIA_DNS_WLM, "MQIA_DNS_WLM" },
/*  107*/ { MQ_MQIA_LISTENER_TIMER, "MQIA_LISTENER_TIMER" },
/*  108*/ { MQ_MQIA_LU62_CHANNELS, "MQIA_LU62_CHANNELS" },
/*  109*/ { MQ_MQIA_MAX_CHANNELS, "MQIA_MAX_CHANNELS" },
/*  110*/ { MQ_MQIA_OUTBOUND_PORT_MIN, "MQIA_OUTBOUND_PORT_MIN" },
/*  111*/ { MQ_MQIA_RECEIVE_TIMEOUT, "MQIA_RECEIVE_TIMEOUT" },
/*  112*/ { MQ_MQIA_RECEIVE_TIMEOUT_TYPE, "MQIA_RECEIVE_TIMEOUT_TYPE" },
/*  113*/ { MQ_MQIA_RECEIVE_TIMEOUT_MIN, "MQIA_RECEIVE_TIMEOUT_MIN" },
/*  114*/ { MQ_MQIA_TCP_CHANNELS, "MQIA_TCP_CHANNELS" },
/*  115*/ { MQ_MQIA_TCP_KEEP_ALIVE, "MQIA_TCP_KEEP_ALIVE" },
/*  116*/ { MQ_MQIA_TCP_STACK_TYPE, "MQIA_TCP_STACK_TYPE" },
/*  117*/ { MQ_MQIA_CHINIT_TRACE_AUTO_START, "MQIA_CHINIT_TRACE_AUTO_START" },
/*  118*/ { MQ_MQIA_CHINIT_TRACE_TABLE_SIZE, "MQIA_CHINIT_TRACE_TABLE_SIZE" },
/*  119*/ { MQ_MQIA_CHINIT_CONTROL, "MQIA_CHINIT_CONTROL" },
/*  120*/ { MQ_MQIA_CMD_SERVER_CONTROL, "MQIA_CMD_SERVER_CONTROL" },
/*  121*/ { MQ_MQIA_SERVICE_TYPE, "MQIA_SERVICE_TYPE" },
/*  122*/ { MQ_MQIA_MONITORING_CHANNEL, "MQIA_MONITORING_CHANNEL" },
/*  123*/ { MQ_MQIA_MONITORING_Q, "MQIA_MONITORING_Q" },
/*  124*/ { MQ_MQIA_MONITORING_AUTO_CLUSSDR, "MQIA_MONITORING_AUTO_CLUSSDR" },
/*  127*/ { MQ_MQIA_STATISTICS_MQI, "MQIA_STATISTICS_MQI" },
/*  128*/ { MQ_MQIA_STATISTICS_Q, "MQIA_STATISTICS_Q" },
/*  129*/ { MQ_MQIA_STATISTICS_CHANNEL, "MQIA_STATISTICS_CHANNEL" },
/*  130*/ { MQ_MQIA_STATISTICS_AUTO_CLUSSDR, "MQIA_STATISTICS_AUTO_CLUSSDR" },
/*  131*/ { MQ_MQIA_STATISTICS_INTERVAL, "MQIA_STATISTICS_INTERVAL" },
/*  133*/ { MQ_MQIA_ACCOUNTING_MQI, "MQIA_ACCOUNTING_MQI" },
/*  134*/ { MQ_MQIA_ACCOUNTING_Q, "MQIA_ACCOUNTING_Q" },
/*  135*/ { MQ_MQIA_ACCOUNTING_INTERVAL, "MQIA_ACCOUNTING_INTERVAL" },
/*  136*/ { MQ_MQIA_ACCOUNTING_CONN_OVERRIDE, "MQIA_ACCOUNTING_CONN_OVERRIDE" },
/*  137*/ { MQ_MQIA_TRACE_ROUTE_RECORDING, "MQIA_TRACE_ROUTE_RECORDING" },
/*  138*/ { MQ_MQIA_ACTIVITY_RECORDING, "MQIA_ACTIVITY_RECORDING" },
/*  139*/ { MQ_MQIA_SERVICE_CONTROL, "MQIA_SERVICE_CONTROL" },
/*  140*/ { MQ_MQIA_OUTBOUND_PORT_MAX, "MQIA_OUTBOUND_PORT_MAX" },
/*  141*/ { MQ_MQIA_SECURITY_CASE, "MQIA_SECURITY_CASE" },
/*  150*/ { MQ_MQIA_QMOPT_CSMT_ON_ERROR, "MQIA_QMOPT_CSMT_ON_ERROR" },
/*  151*/ { MQ_MQIA_QMOPT_CONS_INFO_MSGS, "MQIA_QMOPT_CONS_INFO_MSGS" },
/*  152*/ { MQ_MQIA_QMOPT_CONS_WARNING_MSGS, "MQIA_QMOPT_CONS_WARNING_MSGS" },
/*  153*/ { MQ_MQIA_QMOPT_CONS_ERROR_MSGS, "MQIA_QMOPT_CONS_ERROR_MSGS" },
/*  154*/ { MQ_MQIA_QMOPT_CONS_CRITICAL_MSGS, "MQIA_QMOPT_CONS_CRITICAL_MSGS" },
/*  155*/ { MQ_MQIA_QMOPT_CONS_COMMS_MSGS, "MQIA_QMOPT_CONS_COMMS_MSGS" },
/*  156*/ { MQ_MQIA_QMOPT_CONS_REORG_MSGS, "MQIA_QMOPT_CONS_REORG_MSGS" },
/*  157*/ { MQ_MQIA_QMOPT_CONS_SYSTEM_MSGS, "MQIA_QMOPT_CONS_SYSTEM_MSGS" },
/*  158*/ { MQ_MQIA_QMOPT_LOG_INFO_MSGS, "MQIA_QMOPT_LOG_INFO_MSGS" },
/*  159*/ { MQ_MQIA_QMOPT_LOG_WARNING_MSGS, "MQIA_QMOPT_LOG_WARNING_MSGS" },
/*  160*/ { MQ_MQIA_QMOPT_LOG_ERROR_MSGS, "MQIA_QMOPT_LOG_ERROR_MSGS" },
/*  161*/ { MQ_MQIA_QMOPT_LOG_CRITICAL_MSGS, "MQIA_QMOPT_LOG_CRITICAL_MSGS" },
/*  162*/ { MQ_MQIA_QMOPT_LOG_COMMS_MSGS, "MQIA_QMOPT_LOG_COMMS_MSGS" },
/*  163*/ { MQ_MQIA_QMOPT_LOG_REORG_MSGS, "MQIA_QMOPT_LOG_REORG_MSGS" },
/*  164*/ { MQ_MQIA_QMOPT_LOG_SYSTEM_MSGS, "MQIA_QMOPT_LOG_SYSTEM_MSGS" },
/*  165*/ { MQ_MQIA_QMOPT_TRACE_MQI_CALLS, "MQIA_QMOPT_TRACE_MQI_CALLS" },
/*  166*/ { MQ_MQIA_QMOPT_TRACE_COMMS, "MQIA_QMOPT_TRACE_COMMS" },
/*  167*/ { MQ_MQIA_QMOPT_TRACE_REORG, "MQIA_QMOPT_TRACE_REORG" },
/*  168*/ { MQ_MQIA_QMOPT_TRACE_CONVERSION, "MQIA_QMOPT_TRACE_CONVERSION" },
/*  169*/ { MQ_MQIA_QMOPT_TRACE_SYSTEM, "MQIA_QMOPT_TRACE_SYSTEM" },
/*  170*/ { MQ_MQIA_QMOPT_INTERNAL_DUMP, "MQIA_QMOPT_INTERNAL_DUMP" },
/*  171*/ { MQ_MQIA_MAX_RECOVERY_TASKS, "MQIA_MAX_RECOVERY_TASKS" },
/*  172*/ { MQ_MQIA_MAX_CLIENTS, "MQIA_MAX_CLIENTS" },
/*  173*/ { MQ_MQIA_AUTO_REORGANIZATION, "MQIA_AUTO_REORGANIZATION" },
/*  174*/ { MQ_MQIA_AUTO_REORG_INTERVAL, "MQIA_AUTO_REORG_INTERVAL" },
/*  175*/ { MQ_MQIA_DURABLE_SUB, "MQIA_DURABLE_SUB" },
/*  176*/ { MQ_MQIA_MULTICAST, "MQIA_MULTICAST" },
/*  181*/ { MQ_MQIA_INHIBIT_PUB, "MQIA_INHIBIT_PUB" },
/*  182*/ { MQ_MQIA_INHIBIT_SUB, "MQIA_INHIBIT_SUB" },
/*  183*/ { MQ_MQIA_TREE_LIFE_TIME, "MQIA_TREE_LIFE_TIME" },
/*  184*/ { MQ_MQIA_DEF_PUT_RESPONSE_TYPE, "MQIA_DEF_PUT_RESPONSE_TYPE" },
/*  185*/ { MQ_MQIA_TOPIC_DEF_PERSISTENCE, "MQIA_TOPIC_DEF_PERSISTENCE" },
/*  186*/ { MQ_MQIA_MASTER_ADMIN, "MQIA_MASTER_ADMIN" },
/*  187*/ { MQ_MQIA_PUBSUB_MODE, "MQIA_PUBSUB_MODE" },
/*  188*/ { MQ_MQIA_DEF_READ_AHEAD, "MQIA_DEF_READ_AHEAD" },
/*  189*/ { MQ_MQIA_READ_AHEAD, "MQIA_READ_AHEAD" },
/*  190*/ { MQ_MQIA_PROPERTY_CONTROL, "MQIA_PROPERTY_CONTROL" },
/*  192*/ { MQ_MQIA_MAX_PROPERTIES_LENGTH, "MQIA_MAX_PROPERTIES_LENGTH" },
/*  193*/ { MQ_MQIA_BASE_TYPE, "MQIA_BASE_TYPE" },
/*  195*/ { MQ_MQIA_PM_DELIVERY, "MQIA_PM_DELIVERY" },
/*  196*/ { MQ_MQIA_NPM_DELIVERY, "MQIA_NPM_DELIVERY" },
/*  199*/ { MQ_MQIA_PROXY_SUB, "MQIA_PROXY_SUB" },
/*  203*/ { MQ_MQIA_PUBSUB_NP_MSG, "MQIA_PUBSUB_NP_MSG" },
/*  204*/ { MQ_MQIA_SUB_COUNT, "MQIA_SUB_COUNT" },
/*  205*/ { MQ_MQIA_PUBSUB_NP_RESP, "MQIA_PUBSUB_NP_RESP" },
/*  206*/ { MQ_MQIA_PUBSUB_MAXMSG_RETRY_COUNT, "MQIA_PUBSUB_MAXMSG_RETRY_COUNT" },
/*  207*/ { MQ_MQIA_PUBSUB_SYNC_PT, "MQIA_PUBSUB_SYNC_PT" },
/*  208*/ { MQ_MQIA_TOPIC_TYPE, "MQIA_TOPIC_TYPE" },
/*  215*/ { MQ_MQIA_PUB_COUNT, "MQIA_PUB_COUNT" },
/*  216*/ { MQ_MQIA_WILDCARD_OPERATION, "MQIA_WILDCARD_OPERATION" },
/*  218*/ { MQ_MQIA_SUB_SCOPE, "MQIA_SUB_SCOPE" },
/*  219*/ { MQ_MQIA_PUB_SCOPE, "MQIA_PUB_SCOPE" },
/*  221*/ { MQ_MQIA_GROUP_UR, "MQIA_GROUP_UR" },
/*  222*/ { MQ_MQIA_UR_DISP, "MQIA_UR_DISP" },
/*  223*/ { MQ_MQIA_COMM_INFO_TYPE, "MQIA_COMM_INFO_TYPE" },
/*  224*/ { MQ_MQIA_CF_OFFLOAD, "MQIA_CF_OFFLOAD" },
/*  225*/ { MQ_MQIA_CF_OFFLOAD_THRESHOLD1, "MQIA_CF_OFFLOAD_THRESHOLD1" },
/*  226*/ { MQ_MQIA_CF_OFFLOAD_THRESHOLD2, "MQIA_CF_OFFLOAD_THRESHOLD2" },
/*  227*/ { MQ_MQIA_CF_OFFLOAD_THRESHOLD3, "MQIA_CF_OFFLOAD_THRESHOLD3" },
/*  228*/ { MQ_MQIA_CF_SMDS_BUFFERS, "MQIA_CF_SMDS_BUFFERS" },
/*  229*/ { MQ_MQIA_CF_OFFLDUSE, "MQIA_CF_OFFLDUSE" },
/*  230*/ { MQ_MQIA_MAX_RESPONSES, "MQIA_MAX_RESPONSES" },
/*  231*/ { MQ_MQIA_RESPONSE_RESTART_POINT, "MQIA_RESPONSE_RESTART_POINT" },
/*  232*/ { MQ_MQIA_COMM_EVENT, "MQIA_COMM_EVENT" },
/*  233*/ { MQ_MQIA_MCAST_BRIDGE, "MQIA_MCAST_BRIDGE" },
/*  234*/ { MQ_MQIA_USE_DEAD_LETTER_Q, "MQIA_USE_DEAD_LETTER_Q" },
/*  235*/ { MQ_MQIA_TOLERATE_UNPROTECTED, "MQIA_TOLERATE_UNPROTECTED" },
/*  236*/ { MQ_MQIA_SIGNATURE_ALGORITHM, "MQIA_SIGNATURE_ALGORITHM" },
/*  237*/ { MQ_MQIA_ENCRYPTION_ALGORITHM, "MQIA_ENCRYPTION_ALGORITHM" },
/*  238*/ { MQ_MQIA_POLICY_VERSION, "MQIA_POLICY_VERSION" },
/*  239*/ { MQ_MQIA_ACTIVITY_CONN_OVERRIDE, "MQIA_ACTIVITY_CONN_OVERRIDE" },
/*  240*/ { MQ_MQIA_ACTIVITY_TRACE, "MQIA_ACTIVITY_TRACE" },
/*  242*/ { MQ_MQIA_SUB_CONFIGURATION_EVENT, "MQIA_SUB_CONFIGURATION_EVENT" },
/*  243*/ { MQ_MQIA_XR_CAPABILITY, "MQIA_XR_CAPABILITY" },
/*  244*/ { MQ_MQIA_CF_RECAUTO, "MQIA_CF_RECAUTO" },
/*  245*/ { MQ_MQIA_QMGR_CFCONLOS, "MQIA_QMGR_CFCONLOS" },
/*  246*/ { MQ_MQIA_CF_CFCONLOS, "MQIA_CF_CFCONLOS" },
/*  247*/ { MQ_MQIA_SUITE_B_STRENGTH, "MQIA_SUITE_B_STRENGTH" },
/*  248*/ { MQ_MQIA_CHLAUTH_RECORDS, "MQIA_CHLAUTH_RECORDS" },
/*  249*/ { MQ_MQIA_PUBSUB_CLUSTER, "MQIA_PUBSUB_CLUSTER" },
/*  250*/ { MQ_MQIA_DEF_CLUSTER_XMIT_Q_TYPE, "MQIA_DEF_CLUSTER_XMIT_Q_TYPE" },
/*  251*/ { MQ_MQIA_PROT_POLICY_CAPABILITY, "MQIA_PROT_POLICY_CAPABILITY" },
/*  252*/ { MQ_MQIA_CERT_VAL_POLICY, "MQIA_CERT_VAL_POLICY" },
/*  253*/ { MQ_MQIA_TOPIC_NODE_COUNT, "MQIA_TOPIC_NODE_COUNT" },
/*  254*/ { MQ_MQIA_REVERSE_DNS_LOOKUP, "MQIA_REVERSE_DNS_LOOKUP" },
/*  255*/ { MQ_MQIA_CLUSTER_PUB_ROUTE, "MQIA_CLUSTER_PUB_ROUTE" },
/*  256*/ { MQ_MQIA_CLUSTER_OBJECT_STATE, "MQIA_CLUSTER_OBJECT_STATE" },
/*  257*/ { MQ_MQIA_CHECK_LOCAL_BINDING, "MQIA_CHECK_LOCAL_BINDING" },
/*  258*/ { MQ_MQIA_CHECK_CLIENT_BINDING, "MQIA_CHECK_CLIENT_BINDING" },
/*  259*/ { MQ_MQIA_AUTHENTICATION_FAIL_DELAY, "MQIA_AUTHENTICATION_FAIL_DELAY" },
/*  260*/ { MQ_MQIA_ADOPT_CONTEXT, "MQIA_ADOPT_CONTEXT" },
/*  261*/ { MQ_MQIA_LDAP_SECURE_COMM, "MQIA_LDAP_SECURE_COMM" },
/*  262*/ { MQ_MQIA_DISPLAY_TYPE, "MQIA_DISPLAY_TYPE" },
/*  263*/ { MQ_MQIA_LDAP_AUTHORMD, "MQIA_LDAP_AUTHORMD" },
/*  264*/ { MQ_MQIA_LDAP_NESTGRP, "MQIA_LDAP_NESTGRP" },
/*  265*/ { MQ_MQIA_AMQP_CAPABILITY, "MQIA_AMQP_CAPABILITY" },
/*  266*/ { MQ_MQIA_AUTHENTICATION_METHOD, "MQIA_AUTHENTICATION_METHOD" },
/*  267*/ { MQ_MQIA_KEY_REUSE_COUNT, "MQIA_KEY_REUSE_COUNT" },
/*  268*/ { MQ_MQIA_MEDIA_IMAGE_SCHEDULING, "MQIA_MEDIA_IMAGE_SCHEDULING" },
/*  269*/ { MQ_MQIA_MEDIA_IMAGE_INTERVAL, "MQIA_MEDIA_IMAGE_INTERVAL" },
/*  270*/ { MQ_MQIA_MEDIA_IMAGE_LOG_LENGTH, "MQIA_MEDIA_IMAGE_LOG_LENGTH" },
/*  271*/ { MQ_MQIA_MEDIA_IMAGE_RECOVER_OBJ, "MQIA_MEDIA_IMAGE_RECOVER_OBJ" },
/*  272*/ { MQ_MQIA_MEDIA_IMAGE_RECOVER_Q, "MQIA_MEDIA_IMAGE_RECOVER_Q" },
/*  273*/ { MQ_MQIA_ADVANCED_CAPABILITY, "MQIA_ADVANCED_CAPABILITY" },
/* 2001*/ { MQ_MQCA_APPL_ID, "MQCA_APPL_ID" },
/* 2001 { MQ_MQCA_FIRST, "MQCA_FIRST" }, */
/* 2002*/ { MQ_MQCA_BASE_OBJECT_NAME, "MQCA_BASE_OBJECT_NAME" },
/* 2002 { MQ_MQCA_BASE_Q_NAME, "MQCA_BASE_Q_NAME" },*/
/* 2003*/ { MQ_MQCA_COMMAND_INPUT_Q_NAME, "MQCA_COMMAND_INPUT_Q_NAME" },
/* 2004*/ { MQ_MQCA_CREATION_DATE, "MQCA_CREATION_DATE" },
/* 2005*/ { MQ_MQCA_CREATION_TIME, "MQCA_CREATION_TIME" },
/* 2006*/ { MQ_MQCA_DEAD_LETTER_Q_NAME, "MQCA_DEAD_LETTER_Q_NAME" },
/* 2007*/ { MQ_MQCA_ENV_DATA, "MQCA_ENV_DATA" },
/* 2008*/ { MQ_MQCA_INITIATION_Q_NAME, "MQCA_INITIATION_Q_NAME" },
/* 2009*/ { MQ_MQCA_NAMELIST_DESC, "MQCA_NAMELIST_DESC" },
/* 2010*/ { MQ_MQCA_NAMELIST_NAME, "MQCA_NAMELIST_NAME" },
/* 2011*/ { MQ_MQCA_PROCESS_DESC, "MQCA_PROCESS_DESC" },
/* 2012*/ { MQ_MQCA_PROCESS_NAME, "MQCA_PROCESS_NAME" },
/* 2013*/ { MQ_MQCA_Q_DESC, "MQCA_Q_DESC" },
/* 2014*/ { MQ_MQCA_Q_MGR_DESC, "MQCA_Q_MGR_DESC" },
/* 2015*/ { MQ_MQCA_Q_MGR_NAME, "MQCA_Q_MGR_NAME" },
/* 2016*/ { MQ_MQCA_Q_NAME, "MQCA_Q_NAME" },
/* 2017*/ { MQ_MQCA_REMOTE_Q_MGR_NAME, "MQCA_REMOTE_Q_MGR_NAME" },
/* 2018*/ { MQ_MQCA_REMOTE_Q_NAME, "MQCA_REMOTE_Q_NAME" },
/* 2019*/ { MQ_MQCA_BACKOUT_REQ_Q_NAME, "MQCA_BACKOUT_REQ_Q_NAME" },
/* 2020*/ { MQ_MQCA_NAMES, "MQCA_NAMES" },
/* 2021*/ { MQ_MQCA_USER_DATA, "MQCA_USER_DATA" },
/* 2022*/ { MQ_MQCA_STORAGE_CLASS, "MQCA_STORAGE_CLASS" },
/* 2023*/ { MQ_MQCA_TRIGGER_DATA, "MQCA_TRIGGER_DATA" },
/* 2024*/ { MQ_MQCA_XMIT_Q_NAME, "MQCA_XMIT_Q_NAME" },
/* 2025*/ { MQ_MQCA_DEF_XMIT_Q_NAME, "MQCA_DEF_XMIT_Q_NAME" },
/* 2026*/ { MQ_MQCA_CHANNEL_AUTO_DEF_EXIT, "MQCA_CHANNEL_AUTO_DEF_EXIT" },
/* 2027*/ { MQ_MQCA_ALTERATION_DATE, "MQCA_ALTERATION_DATE" },
/* 2028*/ { MQ_MQCA_ALTERATION_TIME, "MQCA_ALTERATION_TIME" },
/* 2029*/ { MQ_MQCA_CLUSTER_NAME, "MQCA_CLUSTER_NAME" },
/* 2030*/ { MQ_MQCA_CLUSTER_NAMELIST, "MQCA_CLUSTER_NAMELIST" },
/* 2031*/ { MQ_MQCA_CLUSTER_Q_MGR_NAME, "MQCA_CLUSTER_Q_MGR_NAME" },
/* 2032*/ { MQ_MQCA_Q_MGR_IDENTIFIER, "MQCA_Q_MGR_IDENTIFIER" },
/* 2033*/ { MQ_MQCA_CLUSTER_WORKLOAD_EXIT, "MQCA_CLUSTER_WORKLOAD_EXIT" },
/* 2034*/ { MQ_MQCA_CLUSTER_WORKLOAD_DATA, "MQCA_CLUSTER_WORKLOAD_DATA" },
/* 2035*/ { MQ_MQCA_REPOSITORY_NAME, "MQCA_REPOSITORY_NAME" },
/* 2036*/ { MQ_MQCA_REPOSITORY_NAMELIST, "MQCA_REPOSITORY_NAMELIST" },
/* 2037*/ { MQ_MQCA_CLUSTER_DATE, "MQCA_CLUSTER_DATE" },
/* 2038*/ { MQ_MQCA_CLUSTER_TIME, "MQCA_CLUSTER_TIME" },
/* 2039*/ { MQ_MQCA_CF_STRUC_NAME, "MQCA_CF_STRUC_NAME" },
/* 2040*/ { MQ_MQCA_QSG_NAME, "MQCA_QSG_NAME" },
/* 2041*/ { MQ_MQCA_IGQ_USER_ID, "MQCA_IGQ_USER_ID" },
/* 2042*/ { MQ_MQCA_STORAGE_CLASS_DESC, "MQCA_STORAGE_CLASS_DESC" },
/* 2043*/ { MQ_MQCA_XCF_GROUP_NAME, "MQCA_XCF_GROUP_NAME" },
/* 2044*/ { MQ_MQCA_XCF_MEMBER_NAME, "MQCA_XCF_MEMBER_NAME" },
/* 2045*/ { MQ_MQCA_AUTH_INFO_NAME, "MQCA_AUTH_INFO_NAME" },
/* 2046*/ { MQ_MQCA_AUTH_INFO_DESC, "MQCA_AUTH_INFO_DESC" },
/* 2047*/ { MQ_MQCA_LDAP_USER_NAME, "MQCA_LDAP_USER_NAME" },
/* 2048*/ { MQ_MQCA_LDAP_PASSWORD, "MQCA_LDAP_PASSWORD" },
/* 2049*/ { MQ_MQCA_SSL_KEY_REPOSITORY, "MQCA_SSL_KEY_REPOSITORY" },
/* 2050*/ { MQ_MQCA_SSL_CRL_NAMELIST, "MQCA_SSL_CRL_NAMELIST" },
/* 2051*/ { MQ_MQCA_SSL_CRYPTO_HARDWARE, "MQCA_SSL_CRYPTO_HARDWARE" },
/* 2052*/ { MQ_MQCA_CF_STRUC_DESC, "MQCA_CF_STRUC_DESC" },
/* 2053*/ { MQ_MQCA_AUTH_INFO_CONN_NAME, "MQCA_AUTH_INFO_CONN_NAME" },
/* 2060*/ { MQ_MQCA_CICS_FILE_NAME, "MQCA_CICS_FILE_NAME" },
/* 2061*/ { MQ_MQCA_TRIGGER_TRANS_ID, "MQCA_TRIGGER_TRANS_ID" },
/* 2062*/ { MQ_MQCA_TRIGGER_PROGRAM_NAME, "MQCA_TRIGGER_PROGRAM_NAME" },
/* 2063*/ { MQ_MQCA_TRIGGER_TERM_ID, "MQCA_TRIGGER_TERM_ID" },
/* 2064*/ { MQ_MQCA_TRIGGER_CHANNEL_NAME, "MQCA_TRIGGER_CHANNEL_NAME" },
/* 2065*/ { MQ_MQCA_SYSTEM_LOG_Q_NAME, "MQCA_SYSTEM_LOG_Q_NAME" },
/* 2066*/ { MQ_MQCA_MONITOR_Q_NAME, "MQCA_MONITOR_Q_NAME" },
/* 2067*/ { MQ_MQCA_COMMAND_REPLY_Q_NAME, "MQCA_COMMAND_REPLY_Q_NAME" },
/* 2068*/ { MQ_MQCA_BATCH_INTERFACE_ID, "MQCA_BATCH_INTERFACE_ID" },
/* 2069*/ { MQ_MQCA_SSL_KEY_LIBRARY, "MQCA_SSL_KEY_LIBRARY" },
/* 2070*/ { MQ_MQCA_SSL_KEY_MEMBER, "MQCA_SSL_KEY_MEMBER" },
/* 2071*/ { MQ_MQCA_DNS_GROUP, "MQCA_DNS_GROUP" },
/* 2072*/ { MQ_MQCA_LU_GROUP_NAME, "MQCA_LU_GROUP_NAME" },
/* 2073*/ { MQ_MQCA_LU_NAME, "MQCA_LU_NAME" },
/* 2074*/ { MQ_MQCA_LU62_ARM_SUFFIX, "MQCA_LU62_ARM_SUFFIX" },
/* 2075*/ { MQ_MQCA_TCP_NAME, "MQCA_TCP_NAME" },
/* 2076*/ { MQ_MQCA_CHINIT_SERVICE_PARM, "MQCA_CHINIT_SERVICE_PARM" },
/* 2077*/ { MQ_MQCA_SERVICE_NAME, "MQCA_SERVICE_NAME" },
/* 2078*/ { MQ_MQCA_SERVICE_DESC, "MQCA_SERVICE_DESC" },
/* 2079*/ { MQ_MQCA_SERVICE_START_COMMAND, "MQCA_SERVICE_START_COMMAND" },
/* 2080*/ { MQ_MQCA_SERVICE_START_ARGS, "MQCA_SERVICE_START_ARGS" },
/* 2081*/ { MQ_MQCA_SERVICE_STOP_COMMAND, "MQCA_SERVICE_STOP_COMMAND" },
/* 2082*/ { MQ_MQCA_SERVICE_STOP_ARGS, "MQCA_SERVICE_STOP_ARGS" },
/* 2083*/ { MQ_MQCA_STDOUT_DESTINATION, "MQCA_STDOUT_DESTINATION" },
/* 2084*/ { MQ_MQCA_STDERR_DESTINATION, "MQCA_STDERR_DESTINATION" },
/* 2085*/ { MQ_MQCA_TPIPE_NAME, "MQCA_TPIPE_NAME" },
/* 2086*/ { MQ_MQCA_PASS_TICKET_APPL, "MQCA_PASS_TICKET_APPL" },
/* 2090*/ { MQ_MQCA_AUTO_REORG_START_TIME, "MQCA_AUTO_REORG_START_TIME" },
/* 2091*/ { MQ_MQCA_AUTO_REORG_CATALOG, "MQCA_AUTO_REORG_CATALOG" },
/* 2092*/ { MQ_MQCA_TOPIC_NAME, "MQCA_TOPIC_NAME" },
/* 2093*/ { MQ_MQCA_TOPIC_DESC, "MQCA_TOPIC_DESC" },
/* 2094*/ { MQ_MQCA_TOPIC_STRING, "MQCA_TOPIC_STRING" },
/* 2096*/ { MQ_MQCA_MODEL_DURABLE_Q, "MQCA_MODEL_DURABLE_Q" },
/* 2097*/ { MQ_MQCA_MODEL_NON_DURABLE_Q, "MQCA_MODEL_NON_DURABLE_Q" },
/* 2098*/ { MQ_MQCA_RESUME_DATE, "MQCA_RESUME_DATE" },
/* 2099*/ { MQ_MQCA_RESUME_TIME, "MQCA_RESUME_TIME" },
/* 2101*/ { MQ_MQCA_CHILD, "MQCA_CHILD" },
/* 2102*/ { MQ_MQCA_PARENT, "MQCA_PARENT" },
/* 2105*/ { MQ_MQCA_ADMIN_TOPIC_NAME, "MQCA_ADMIN_TOPIC_NAME" },
/* 2108*/ { MQ_MQCA_TOPIC_STRING_FILTER, "MQCA_TOPIC_STRING_FILTER" },
/* 2109*/ { MQ_MQCA_AUTH_INFO_OCSP_URL, "MQCA_AUTH_INFO_OCSP_URL" },
/* 2110*/ { MQ_MQCA_COMM_INFO_NAME, "MQCA_COMM_INFO_NAME" },
/* 2111*/ { MQ_MQCA_COMM_INFO_DESC, "MQCA_COMM_INFO_DESC" },
/* 2112*/ { MQ_MQCA_POLICY_NAME, "MQCA_POLICY_NAME" },
/* 2113*/ { MQ_MQCA_SIGNER_DN, "MQCA_SIGNER_DN" },
/* 2114*/ { MQ_MQCA_RECIPIENT_DN, "MQCA_RECIPIENT_DN" },
/* 2115*/ { MQ_MQCA_INSTALLATION_DESC, "MQCA_INSTALLATION_DESC" },
/* 2116*/ { MQ_MQCA_INSTALLATION_NAME, "MQCA_INSTALLATION_NAME" },
/* 2117*/ { MQ_MQCA_INSTALLATION_PATH, "MQCA_INSTALLATION_PATH" },
/* 2118*/ { MQ_MQCA_CHLAUTH_DESC, "MQCA_CHLAUTH_DESC" },
/* 2119*/ { MQ_MQCA_CUSTOM, "MQCA_CUSTOM" },
/* 2120*/ { MQ_MQCA_VERSION, "MQCA_VERSION" },
/* 2121*/ { MQ_MQCA_CERT_LABEL, "MQCA_CERT_LABEL" },
/* 2122*/ { MQ_MQCA_XR_VERSION, "MQCA_XR_VERSION" },
/* 2123*/ { MQ_MQCA_XR_SSL_CIPHER_SUITES, "MQCA_XR_SSL_CIPHER_SUITES" },
/* 2124*/ { MQ_MQCA_CLUS_CHL_NAME, "MQCA_CLUS_CHL_NAME" },
/* 2125*/ { MQ_MQCA_CONN_AUTH, "MQCA_CONN_AUTH" },
/* 2126*/ { MQ_MQCA_LDAP_BASE_DN_USERS, "MQCA_LDAP_BASE_DN_USERS" },
/* 2127*/ { MQ_MQCA_LDAP_SHORT_USER_FIELD, "MQCA_LDAP_SHORT_USER_FIELD" },
/* 2128*/ { MQ_MQCA_LDAP_USER_OBJECT_CLASS, "MQCA_LDAP_USER_OBJECT_CLASS" },
/* 2129*/ { MQ_MQCA_LDAP_USER_ATTR_FIELD, "MQCA_LDAP_USER_ATTR_FIELD" },
/* 2130*/ { MQ_MQCA_SSL_CERT_ISSUER_NAME, "MQCA_SSL_CERT_ISSUER_NAME" },
/* 2131*/ { MQ_MQCA_QSG_CERT_LABEL, "MQCA_QSG_CERT_LABEL" },
/* 2132*/ { MQ_MQCA_LDAP_BASE_DN_GROUPS, "MQCA_LDAP_BASE_DN_GROUPS" },
/* 2133*/ { MQ_MQCA_LDAP_GROUP_OBJECT_CLASS, "MQCA_LDAP_GROUP_OBJECT_CLASS" },
/* 2134*/ { MQ_MQCA_LDAP_GROUP_ATTR_FIELD, "MQCA_LDAP_GROUP_ATTR_FIELD" },
/* 2135*/ { MQ_MQCA_LDAP_FIND_GROUP_FIELD, "MQCA_LDAP_FIND_GROUP_FIELD" },
/* 2136*/ { MQ_MQCA_AMQP_VERSION, "MQCA_AMQP_VERSION" },
/* 2137*/ { MQ_MQCA_AMQP_SSL_CIPHER_SUITES, "MQCA_AMQP_SSL_CIPHER_SUITES" },
    { 0, NULL }
};
value_string_ext mq_selector_xvals = VALUE_STRING_EXT_INIT(mq_selector_vals);

void mq_setup_MQCFINT_Parse_data(GHashTable* table)
{
/*    1*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_APPL_TYPE), (void*)(&mq_MQAT_vals));
/*    4*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEF_INPUT_OPEN_OPTION), (void*)(&mq_MQOO_vals));
/*    5*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEF_PERSISTENCE), (void*)(&mq_MQPER_vals));
/*    6*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEF_PRIORITY), (void*)(&mq_MQPRI_vals));
/*    7*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEFINITION_TYPE), (void*)(&mq_MQQDT_vals));
/*    8*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_HARDEN_GET_BACKOUT), (void*)(&mq_MQQA_BACKOUT_vals));
/*    9*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_INHIBIT_GET), (void*)(&mq_MQQA_GET_vals));
/*   10*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_INHIBIT_PUT), (void*)(&mq_MQQA_PUT_vals));
/*   12*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_USAGE), (void*)(&mq_MQUS_vals));
/*   16*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_MSG_DELIVERY_SEQUENCE), (void*)(&mq_MQMDS_vals));
/*   20*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_Q_TYPE), (void*)(&mq_MQQT_vals));
/*   23*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SHAREABILITY), (void*)(&mq_MQQA_vals));
/*   24*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_TRIGGER_CONTROL), (void*)(&mq_MQTC_vals));
/*   28*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_TRIGGER_TYPE), (void*)(&mq_MQTT_vals));
/*   30*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SYNCPOINT), (void*)(&mq_MQSP_vals));
/*   32*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PLATFORM), (void*)(&mq_MQPL_vals));
/*   34*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DIST_LISTS), (void*)(&mq_MQDL_vals));
/*   42*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_Q_DEPTH_MAX_EVENT), (void*)(&mq_MQEVR_vals));
/*   43*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_Q_DEPTH_HIGH_EVENT), (void*)(&mq_MQEVR_vals));
/*   44*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_Q_DEPTH_LOW_EVENT), (void*)(&mq_MQEVR_vals));
/*   45*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SCOPE), (void*)(&mq_MQSCO_vals));
/*   46*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_Q_SERVICE_INTERVAL_EVENT), (void*)(&mq_MQQSIE_vals));
/*   47*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_AUTHORITY_EVENT), (void*)(&mq_MQEVR_vals));
/*   48*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_INHIBIT_EVENT), (void*)(&mq_MQEVR_vals));
/*   49*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_LOCAL_EVENT), (void*)(&mq_MQEVR_vals));
/*   50*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_REMOTE_EVENT), (void*)(&mq_MQEVR_vals));
/*   51*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CONFIGURATION_EVENT), (void*)(&mq_MQEVR_vals));
/*   52*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_START_STOP_EVENT), (void*)(&mq_MQEVR_vals));
/*   53*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PERFORMANCE_EVENT), (void*)(&mq_MQEVR_vals));
/*   55*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHANNEL_AUTO_DEF), (void*)(&mq_MQCHAD_vals));
/*   56*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHANNEL_AUTO_DEF_EVENT), (void*)(&mq_MQEVR_vals));
/*   57*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_INDEX_TYPE), (void*)(&mq_MQIT_vals));
/*   61*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEF_BIND), (void*)(&mq_MQBND_vals));
/*   63*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_QSG_DISP), (void*)(&m_MQQSGD_vals));
/*   64*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_INTRA_GROUP_QUEUING), (void*)(&mq_MQIGQ_vals));
/*   65*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_IGQ_PUT_AUTHORITY), (void*)(&mq_MQIGQPA_vals));
/*   66*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_AUTH_INFO_TYPE), (void*)(&mq_MQAIT_vals));
/*   71*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CF_RECOVER), (void*)(&mq_MQCFR_vals));
/*   73*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHANNEL_EVENT), (void*)(&mq_MQEVR_vals));
/*   74*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_BRIDGE_EVENT), (void*)(&mq_MQEVR_vals));
/*   75*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SSL_EVENT), (void*)(&mq_MQEVR_vals));
/*   77*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SHARED_Q_Q_MGR_NAME), (void*)(&mq_MQSQQM_vals));
/*   78*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_NPM_CLASS), (void*)(&mq_MQNPM_vals));
/*   92*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SSL_FIPS_REQUIRED), (void*)(&mq_MQSSL_vals));
/*   93*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_IP_ADDRESS_VERSION), (void*)(&mq_MQIPADDR_vals));
/*   94*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_LOGGER_EVENT), (void*)(&mq_MQEVR_vals));
/*   98*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CLWL_USEQ), (void*)(&mq_MQCLWL_USEQ_vals));
/*   99*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_COMMAND_EVENT), (void*)(&mq_MQEVR_vals));
/*  102*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ADOPTNEWMCA_CHECK), (void*)(&mq_MQADOPT_CHECK_vals));
/*  103*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ADOPTNEWMCA_TYPE), (void*)(&mq_MQADOPT_TYPE_vals));
/*  106*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DNS_WLM), (void*)(&mq_DNSWLM_vals));
/*  112*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_RECEIVE_TIMEOUT_TYPE), (void*)(&mq_MQRCVTIME_vals));
/*  115*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_TCP_KEEP_ALIVE), (void*)(&mq_MQTCPKEEP_vals));
/*  116*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_TCP_STACK_TYPE), (void*)(&mq_MQTCPSTACK_vals));
/*  117*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHINIT_TRACE_AUTO_START), (void*)(&mq_MQTRAXSTR_vals));
/*  119*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHINIT_CONTROL), (void*)(&mq_MQSVC_CONTROL_vals));
/*  120*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CMD_SERVER_CONTROL), (void*)(&mq_MQSVC_CONTROL_vals));
/*  122*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_MONITORING_CHANNEL), (void*)(&mq_MQMON_vals));
/*  123*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_MONITORING_Q), (void*)(&mq_MQMON_vals));
/*  124*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_MONITORING_AUTO_CLUSSDR), (void*)(&mq_MQMON_vals));
/*  124*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_MONITORING_AUTO_CLUSSDR), (void*)(&mq_MQMON_vals));
/*  127*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_STATISTICS_MQI), (void*)(&mq_MQMON_vals));
/*  128*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_STATISTICS_Q), (void*)(&mq_MQMON_vals));
/*  129*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_STATISTICS_CHANNEL), (void*)(&mq_MQMON_vals));
/*  130*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_STATISTICS_AUTO_CLUSSDR), (void*)(&mq_MQMON_vals));
/*  131*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_STATISTICS_INTERVAL), (void*)(&mq_MQMON_vals));
/*  133*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ACCOUNTING_MQI), (void*)(&mq_MQMON_vals));
/*  134*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ACCOUNTING_Q), (void*)(&mq_MQMON_vals));
/*  136*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ACCOUNTING_CONN_OVERRIDE), (void*)(&mq_MQMON_vals));
/*  137*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_TRACE_ROUTE_RECORDING), (void*)(&mq_MQRECORDING_vals));
/*  138*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ACTIVITY_RECORDING), (void*)(&mq_MQRECORDING_vals));
/*  141*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SECURITY_CASE), (void*)(&mq_MQSCYC_vals));
/*  175*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DURABLE_SUB), (void*)(&mq_MQSUB_DURABLE_vals));
/*  176*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_MULTICAST), (void*)(&mq_MQMC_vals));
/*  181*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_INHIBIT_PUB), (void*)(&mq_MQTA_PUB_vals));
/*  182*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_INHIBIT_SUB), (void*)(&mq_MQTA_SUB_vals));
/*  184*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEF_PUT_RESPONSE_TYPE), (void*)(&mq_MQPRT_vals));
/*  185*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_TOPIC_DEF_PERSISTENCE), (void*)(&mq_MQPER_vals));
/*  187*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PUBSUB_MODE), (void*)(&mq_PubSubMode_vals));
/*  188*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEF_READ_AHEAD), (void*)(&mq_MQREADA_vals));
/*  189*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_READ_AHEAD), (void*)(&mq_MQREADA_vals));
/*  190*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PROPERTY_CONTROL), (void*)(&mq_MQPROP_vals));
/*  193*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_BASE_TYPE), (void*)(&mq_MQOT_vals));
/*  195*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PM_DELIVERY), (void*)(&mq_MQDLV_vals));
/*  196*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_NPM_DELIVERY), (void*)(&mq_MQDLV_vals));
/*  199*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PROXY_SUB), (void*)(&mq_MQTA_PROXY_vals));
/*  203*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PUBSUB_NP_MSG), (void*)(&mq_MQUNDELIVERED_vals));
/*  205*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PUBSUB_NP_RESP), (void*)(&mq_MQUNDELIVERED_vals));
/*  207*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PUBSUB_SYNC_PT), (void*)(&mq_PubSubSync_vals));
/*  208*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_TOPIC_TYPE), (void*)(&mq_MQTOPT_vals));
/*  216*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_WILDCARD_OPERATION), (void*)(&mq_MQTA_vals));
/*  218*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SUB_SCOPE), (void*)(&mq_MQSCOPE_vals));
/*  219*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PUB_SCOPE), (void*)(&mq_MQSCOPE_vals));
/*  221*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_GROUP_UR), (void*)(&mq_MQGUR_vals));
/*  222*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_UR_DISP), (void*)(&m_MQQSGD_vals));
/*  223*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_COMM_INFO_TYPE), (void*)(&mq_MQCIT_vals));
/*  224*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CF_OFFLOAD), (void*)(&mq_MQCFOFFLD_vals));
/*  229*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CF_OFFLDUSE), (void*)(&mq_MQCFOFFLD_vals));
/*  232*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_COMM_EVENT), (void*)(&mq_MQEVR_vals));
/*  233*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_MCAST_BRIDGE), (void*)(&mq_MQMCB_vals));
/*  234*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_USE_DEAD_LETTER_Q), (void*)(&mq_MQUSEDLQ_vals));
/*  239*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ACTIVITY_CONN_OVERRIDE), (void*)(&mq_MQMON_vals));
/*  240*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ACTIVITY_TRACE), (void*)(&mq_MQMON_vals));
/*  243*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_XR_CAPABILITY), (void*)(&mq_MQCAP_vals));
/*  244*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CF_RECAUTO), (void*)(&mq_MQRECAUTO_vals));
/*  245*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_QMGR_CFCONLOS), (void*)(&mq_MQCFCONLOS_vals));
/*  246*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CF_CFCONLOS), (void*)(&mq_MQCFCONLOS_vals));
/*  247*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_SUITE_B_STRENGTH), (void*)(&mq_MQ_SUITE_B_vals));
/*  248*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHLAUTH_RECORDS), (void*)(&mq_MQCHLA_vals));
/*  249*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PUBSUB_CLUSTER), (void*)(&mq_MQPSCLUS_vals));
/*  250*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_DEF_CLUSTER_XMIT_Q_TYPE), (void*)(&mq_MQCLXQ_vals));
/*  251*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_PROT_POLICY_CAPABILITY), (void*)(&mq_MQCAP_vals));
/*  252*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CERT_VAL_POLICY), (void*)(&mq_MQ_CERT_vals));
/*  254*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_REVERSE_DNS_LOOKUP), (void*)(&mq_MQRDNS_vals));
/*  255*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CLUSTER_PUB_ROUTE), (void*)(&mq_MQCLROUTE_vals));
/*  256*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CLUSTER_OBJECT_STATE), (void*)(&mq_MQCLST_vals));
/*  257*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHECK_LOCAL_BINDING), (void*)(&mq_MQCHK_vals));
/*  258*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_CHECK_CLIENT_BINDING), (void*)(&mq_MQCHK_vals));
/*  260*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_ADOPT_CONTEXT), (void*)(&mq_MQADPCTX_vals));
/*  261*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_LDAP_SECURE_COMM), (void*)(&mq_MQSECCOMM_vals));
/*  263*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_LDAP_AUTHORMD), (void*)(&mq_MQLDAP_AUTHORMD_vals));
/*  264*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_LDAP_NESTGRP), (void*)(&mq_MQLDAP_NESTGRP_vals));
/*  265*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_AMQP_CAPABILITY), (void*)(&mq_MQCAP_vals));
/*  266*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_AUTHENTICATION_METHOD), (void*)(&mq_MQAUTHENTICATE_vals));
/*  267*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIA_KEY_REUSE_COUNT), (void*)(&mq_MQKEY_vals));
/* 1001*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_Q_MGR_ATTRS), (void*)(&mq_PrmId_vals));
/* 1002*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_Q_ATTRS), (void*)(&mq_PrmId_vals));
/* 1005*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_FORCE), (void*)(&mq_MQFC_vals));
/* 1006*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_REPLACE), (void*)(&mq_MQRP_vals));
/* 1010*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_EVENT_APPL_TYPE), (void*)(&mq_MQAT_vals));
/* 1011*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_EVENT_ORIGIN), (void*)(&mq_MQEVO_vals));
/* 1012*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_PARAMETER_ID), (void*)(&mq_PrmId_vals));
/* 1016*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_OBJECT_TYPE), (void*)(&mq_MQOT_vals));
/* 1020*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_REASON_QUALIFIER), (void*)(&mq_MQRQ_vals));
/* 1021*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_COMMAND), (void*)(&mq_MQCMD_vals));
/* 1023*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_OPEN_TYPE), (void*)(&mq_MQQSOT_vals));
/* 1026*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_Q_STATUS_ATTRS), (void*)(&mq_PrmId_vals));
/* 1028*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_HANDLE_STATE), (void*)(&mq_MQHSTATE_vals));
/* 1093*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CLUSTER_Q_MGR_ATTRS), (void*)(&mq_PrmId_vals));
/* 1098*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_OPEN_INPUT_TYPE), (void*)(&mq_MQQSO_vals));
/* 1099*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_OPEN_OUTPUT), (void*)(&mq_MQQSO_vals));
/* 1100*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_OPEN_SET), (void*)(&mq_MQQSO_vals));
/* 1101*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_OPEN_INQUIRE), (void*)(&mq_MQQSO_vals));
/* 1102*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_OPEN_BROWSE), (void*)(&mq_MQQSO_vals));
/* 1103*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_Q_STATUS_TYPE), (void*)(&mq_PrmId_vals));
/* 1106*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SECURITY_TYPE), (void*)(&mq_MQSECTYPE_vals));
/* 1107*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CONNECTION_ATTRS), (void*)(&mq_PrmId_vals));
/* 1110*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CONN_INFO_TYPE), (void*)(&mq_MQIACF_CONN_INFO_vals));
/* 1115*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_AUTHORIZATION_LIST), (void*)(&mq_MQAUTH_vals));
/* 1118*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_ENTITY_TYPE), (void*)(&mq_MQZAET_vals));
/* 1120*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_COMMAND_INFO), (void*)(&mq_MQCMDI_vals));
/* 1126*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_QSG_DISPS), (void*)(&m_MQQSGD_vals));
/* 1128*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_UOW_STATE), (void*)(&mq_MQUOWST_vals));
/* 1129*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SECURITY_ITEM), (void*)(&mq_MQSECITEM_vals));
/* 1130*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CF_STRUC_STATUS), (void*)(&mq_MQCFSTATUS_vals));
/* 1132*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_UOW_TYPE), (void*)(&mq_MQUOWT_vals));
/* 1133*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CF_STRUC_ATTRS), (void*)(&mq_PrmId_vals));
/* 1135*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CF_STATUS_TYPE), (void*)(&mq_MQIACF_CF_STATUS_vals));
/* 1139*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CF_STRUC_TYPE), (void*)(&mq_MQCFTYPE_vals));
/* 1149*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_Q_MGR_STATUS), (void*)(&mq_MQQSGS_vals));
/* 1150*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_DB2_CONN_STATUS), (void*)(&mq_MQQSGS_vals));
/* 1154*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SECURITY_SWITCH), (void*)(&mq_MQSECSW_vals));
/* 1155*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SECURITY_SETTING), (void*)(&mq_MQSECSW_vals));
/* 1157*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_USAGE_TYPE), (void*)(&mq_PrmId_vals));
/* 1165*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_PAGESET_STATUS), (void*)(&mq_MQUSAGE_PS_vals));
/* 1167*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_USAGE_DATA_SET_TYPE), (void*)(&mq_MQUSAGE_DS_vals));
/* 1175*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_TYPE), (void*)(&mq_MQSYSP_vals));
/* 1182*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_ARCHIVE), (void*)(&mq_MQSYSP_vals));
/* 1183*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_DUAL_ACTIVE), (void*)(&mq_MQSYSP_vals));
/* 1184*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_DUAL_ARCHIVE), (void*)(&mq_MQSYSP_vals));
/* 1185*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_DUAL_BSDS), (void*)(&mq_MQSYSP_vals));
/* 1197*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_SMF_ACCOUNTING), (void*)(&mq_MQSYSP_vals));
/* 1198*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_SMF_STATS), (void*)(&mq_MQSYSP_vals));
/* 1203*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_ALLOC_UNIT), (void*)(&mq_MQSYSP_vals));
/* 1205*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_ARCHIVE_WTOR), (void*)(&mq_MQSYSP_vals));
/* 1207*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_CATALOG), (void*)(&mq_MQSYSP_vals));
/* 1208*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_COMPACT), (void*)(&mq_MQSYSP_vals));
/* 1211*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_PROTECT), (void*)(&mq_MQSYSP_vals));
/* 1218*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_LOG_SUSPEND), (void*)(&mq_MQSYSP_vals));
/* 1219*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_OFFLOAD_STATUS), (void*)(&mq_MQSYSP_vals));
/* 1229*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_Q_MGR_STATUS_ATTRS), (void*)(&mq_PrmId_vals));
/* 1232*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CHINIT_STATUS), (void*)(&mq_MQSVC_STATUS_vals));
/* 1233*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CMD_SERVER_STATUS), (void*)(&mq_MQSVC_STATUS_vals));
/* 1261*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_Q_TYPES), (void*)(&mq_MQQT_vals));
/* 1262*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_USER_ID_SUPPORT), (void*)(&mq_MQUIDSUPP_vals));
/* 1264*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_AUTH_SERVICE_ATTRS), (void*)(&mq_PrmId_vals));
/* 1265*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_USAGE_EXPAND_TYPE), (void*)(&mq_MQUSAGE_EXPAND_vals));
/* 1271*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_PUBSUB_PROPERTIES), (void*)(&mq_MQPSPROP_vals));
/* 1274*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_DURABLE_SUBSCRIPTION), (void*)(&mq_MQSUB_DURABLE_vals));
/* 1280*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_REQUEST_ONLY), (void*)(&mq_MQSUB_DURABLE_vals));
/* 1283*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_PUB_PRIORITY), (void*)(&mq_MQPRI_vals));
/* 1289*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SUB_TYPE), (void*)(&mq_MQSUBTYPE_vals));
/* 1300*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_RETAINED_PUBLICATION), (void*)(&mq_MQQSO_vals));
/* 1302*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_TOPIC_STATUS_TYPE), (void*)(&mq_PrmId_vals));
/* 1308*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_ASYNC_STATE), (void*)(&mq_MQAS_vals));
/* 1308*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_PS_STATUS_TYPE), (void*)(&mq_MQPSST_vals));
/* 1322*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_LOG_COMPRESSION), (void*)(&mq_MQCOMPRESS_vals));
/* 1324*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_MULC_CAPTURE), (void*)(&mq_MQMULC_vals));
/* 1325*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_PERMIT_STANDBY), (void*)(&mq_MQSTDBY_vals));
/* 1328*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CF_SMDS_BLOCK_SIZE), (void*)(&mq_MQDSB_vals));
/* 1329*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CF_SMDS_EXPAND), (void*)(&mq_MQDSE_vals));
/* 1332*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CF_STRUC_ACCESS), (void*)(&mq_MQCFACCESS_vals));
/* 1335*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_USAGE_SMDS), (void*)(&mq_MQUSAGE_SMDS_vals));
/* 1341*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_USAGE_OFFLOAD_MSGS), (void*)(&mq_MQCFOFFLD_vals));
/* 1348*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SMDS_OPENMODE), (void*)(&mq_MQS_OPENMODE_vals));
/* 1349*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SMDS_STATUS), (void*)(&mq_MQS_STATUS_vals));
/* 1350*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SMDS_AVAIL), (void*)(&mq_MQS_AVAIL_vals));
/* 1352*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_CHLAUTH_TYPE), (void*)(&mq_MQCAUT_vals));
/* 1376*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SMDS_EXPANDST), (void*)(&mq_MQS_EXPANDST_vals));
/* 1409*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_LDAP_CONNECTION_STATUS), (void*)(&mq_MQLDAPC_vals));
/* 1414*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACF_SYSP_ZHYPERWRITE), (void*)(&mq_MQSYSP_vals));
/* 1501*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_XMIT_PROTOCOL_TYPE), (void*)(&mq_MQXPT_vals));
/* 1508*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_PUT_AUTHORITY), (void*)(&mq_MQPA_vals));
/* 1511*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_CHANNEL_TYPE), (void*)(&mq_MQCHT_vals));
/* 1515*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_DATA_CONVERSION), (void*)(&mq_MQCDC_vals));
/* 1517*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_MCA_TYPE), (void*)(&mq_MQCAT_vals));
/* 1523*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_CHANNEL_INSTANCE_TYPE), (void*)(&mq_MQOT_vals));
/* 1527*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_CHANNEL_STATUS), (void*)(&mq_MQCHS_vals));
/* 1528*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_INDOUBT_STATUS), (void*)(&mq_MQCHIDS_vals));
/* 1542*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_MCA_STATUS), (void*)(&mq_MQMCAS_vals));
/* 1543*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_STOP_REQUESTED), (void*)(&mq_MQCHSR_STOP_vals));
/* 1562*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_NPM_SPEED), (void*)(&mq_MQNPMS_vals));
/* 1568*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_SSL_CLIENT_AUTH), (void*)(&mq_MQSCA_vals));
/* 1575*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_HDR_COMPRESSION), (void*)(&mq_MQCOMPRESS_vals));
/* 1576*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_MSG_COMPRESSION), (void*)(&mq_MQCOMPRESS_vals));
/* 1580*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_CHANNEL_DISP), (void*)(&mq_MQCHLD_vals));
/* 1581*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_INBOUND_DISP), (void*)(&mq_MQINBD_vals));
/* 1582*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_CHANNEL_TYPES), (void*)(&mq_MQCHT_vals));
/* 1599*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_LISTENER_STATUS), (void*)(&mq_MQSVC_STATUS_vals));
/* 1601*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_LISTENER_CONTROL), (void*)(&mq_MQSVC_CONTROL_vals));
/* 1609*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_CHANNEL_SUBSTATE), (void*)(&mq_MQCHSSTATE_vals));
/* 1614*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_DEF_CHANNEL_DISP), (void*)(&mq_MQCHLD_vals));
/* 1622*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_AUTH_INFO_TYPES), (void*)(&mq_MQAIT_vals));
/* 1627*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_NEW_SUBSCRIBER_HISTORY), (void*)(&mq_MQNSH_vals));
/* 1629*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_USE_CLIENT_ID), (void*)(&mq_MQUCI_vals));
/* 1638*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_USER_SOURCE), (void*)(&mq_MQUSRC_vals));
/* 1639*/ g_hash_table_insert(table, GUINT_TO_POINTER(MQ_MQIACH_WARNING), (void*)(&mq_MQWARN_vals));
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
