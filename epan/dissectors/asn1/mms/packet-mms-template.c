/* packet-mms_asn1.c
 *
 * Ronnie Sahlberg 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-mms.h"

#define PNAME  "MMS"
#define PSNAME "MMS"
#define PFNAME "mms"

void proto_register_mms(void);
void proto_reg_handoff_mms(void);

static bool use_iec61850_mapping = true;

/* Initialize the protocol and registered fields */
static int proto_mms;

/* Conversation */
static int hf_mms_response_in;
static int hf_mms_response_to;
static int hf_mms_response_time;

/* IEC 61850-8-1 filters */
static int hf_mms_iec61850_rptid;
static int hf_mms_iec61850_reported_optflds;
static int hf_mms_iec61850_seqnum;
static int hf_mms_iec61850_timeofentry;
static int hf_mms_iec61850_datset;
static int hf_mms_iec61850_bufovfl;
static int hf_mms_iec61850_confrev;
static int hf_mms_iec61850_inclusion_bitstring;
static int hf_mms_iec61850_ctlModel;

static int hf_mms_iec61850_QualityC0;
static int hf_mms_iec61850_Quality20;
static int hf_mms_iec61850_Quality10;
static int hf_mms_iec61850_Quality8;
static int hf_mms_iec61850_Quality4;
static int hf_mms_iec61850_Quality2;
static int hf_mms_iec61850_Quality1;
static int hf_mms_iec61850_Quality0080;
static int hf_mms_iec61850_Quality0040;
static int hf_mms_iec61850_Quality0020;
static int hf_mms_iec61850_Quality0010;
static int hf_mms_iec61850_Quality0008;
static int hf_mms_iec61850_quality_bitstring;
static int hf_mms_iec61850_timequality80;
static int hf_mms_iec61850_timequality40;
static int hf_mms_iec61850_timequality20;
static int hf_mms_iec61850_timequality1F;
static int hf_mms_iec61850_check_bitstring;
static int hf_mms_iec61850_check_b1;
static int hf_mms_iec61850_check_b0;
static int hf_mms_iec61850_orcategory;
static int hf_mms_iec61850_beh$stval;
static int hf_mms_iec61850_mod$stval;
static int hf_mms_iec61850_health$stval;
static int hf_mms_iec61850_ctlval;
static int hf_mms_iec61850_origin;
static int hf_mms_iec61850_origin_orcat;
static int hf_mms_iec61850_origin_orident;
static int hf_mms_iec61850_ctlNum;
static int hf_mms_iec61850_T;
static int hf_mms_iec61850_test;

#include "packet-mms-hf.c"

/* Initialize the subtree pointers */
static int ett_mms;
static int ett_mms_iec61850_quality_bitstring;
static int ett_mms_iec61850_check_bitstring;
#include "packet-mms-ett.c"

static expert_field ei_mms_mal_timeofday_encoding;
static expert_field ei_mms_mal_utctime_encoding;
static expert_field ei_mms_zero_pdu;

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/

#define BUFFER_SIZE_PRE 10
#define BUFFER_SIZE_MORE 1024

typedef enum _iec61850_8_1_vmd_specific {
    IEC61850_8_1_NOT_SET = 0,
    IEC61850_8_1_RPT
} iec61850_8_1_vmd_specific;

typedef enum _itemid_type {
    IEC61850_ITEM_ID_NOT_SET = 0,
    IEC61850_ITEM_ID_CTLMODEL,
    IEC61850_ITEM_ID_Q,
    IEC61850_ITEM_ID_OPER,
    IEC61850_ITEM_ID_CHECK,
    IEC61850_ITEM_ID_OR_CAT,
    IEC61850_ITEM_ID_BEH$STVAL,
    IEC61850_ITEM_ID_MOD$STVAL,
    IEC61850_ITEM_ID_HEALTH$STVAL,
    IEC61850_ITEM_ID_$BR$_OR_$RP$,
    IEC61850_ITEM_ID_$SBOW
} itemid_type;

typedef struct _mms_transaction_t {
    uint32_t req_frame;
    uint32_t rep_frame;
    nstime_t req_time;
    /* Request info*/
    itemid_type itemid;    /* Numeric representation of ItemId substring */
    int conf_serv_pdu_type_req;
} mms_transaction_t;

typedef struct _mms_conv_info_t {
    wmem_map_t* pdus;
} mms_conv_info_t;

typedef struct mms_private_data_t
{
    char preCinfo[BUFFER_SIZE_PRE];
    char moreCinfo[BUFFER_SIZE_MORE];
} mms_private_data_t;

#define MMS_CONFIRMED_REQUEST_PDU        0
#define MMS_CONFIRMED_RESPONSE_PDU       1
#define MMS_CONFIRMED_ERROR_PDU          2
#define MMS_UNCONFIRMED_PDU              3
#define MMS_REJECT_PDU                   4
#define MMS_CANCEL_REQUEST_PDU           5
#define MMS_CANCEL_RESPONSE_PDU          6
#define MMS_CANCEL_ERROR_PDU             7
#define MMS_INITIATE_REQUEST_PDU         8
#define MMS_INITIATE_RESPONSE_PDU        9
#define MMS_INITIATE_ERROR_PDU          10
#define MMS_CONCLUDE_REQUEST_PDU        11
#define MMS_CONCLUDE_RESPONSE_PDU       12
#define MMS_CONCLUDE_ERROR_PDU          13

#define MMS_CONFIRMEDSERVICE_STATUS    0
#define MMS_CONFIRMEDSERVICE_GETNAMELIST    1
#define MMS_CONFIRMEDSERVICE_IDENTIFY    2
#define MMS_CONFIRMEDSERVICE_RENAME    3
#define MMS_CONFIRMEDSERVICE_READ    4
#define MMS_CONFIRMEDSERVICE_WRITE    5
#define MMS_CONFIRMEDSERVICE_GETVARIABLEACCESSATTRIBUTES    6
#define MMS_CONFIRMEDSERVICE_DEFINENAMEDVARIABLE    7
#define MMS_CONFIRMEDSERVICE_DEFINESCATTEREDACCESS    8
#define MMS_CONFIRMEDSERVICE_GETSCATTEREDACCESSATTRIBUTES    9
#define MMS_CONFIRMEDSERVICE_DELETEVARIABLEACCESS    10
#define MMS_CONFIRMEDSERVICE_DEFINENAMEDVARIABLELIST    11
#define MMS_CONFIRMEDSERVICE_GETNAMEDVARIABLELISTATTRIBUTES    12
#define MMS_CONFIRMEDSERVICE_DELETENAMEDVARIABLELIST    13
#define MMS_CONFIRMEDSERVICE_DEFINENAMEDTYPE    14
#define MMS_CONFIRMEDSERVICE_GETNAMEDTYPEATTRIBUTES    15
#define MMS_CONFIRMEDSERVICE_DELETENAMEDTYPE    16
#define MMS_CONFIRMEDSERVICE_INPUT    17
#define MMS_CONFIRMEDSERVICE_OUTPUT    18
#define MMS_CONFIRMEDSERVICE_TAKECONTROL    19
#define MMS_CONFIRMEDSERVICE_RELINQUISHCONTROL    20
#define MMS_CONFIRMEDSERVICE_DEFINESEMAPHORE    21
#define MMS_CONFIRMEDSERVICE_DELETESEMAPHORE    22
#define MMS_CONFIRMEDSERVICE_REPORTSEMAPHORESTATUS    23
#define MMS_CONFIRMEDSERVICE_REPORTPOOLSEMAPHORESTATUS    24
#define MMS_CONFIRMEDSERVICE_REPORTSEMAPHOREENTRYSTATUS    25
#define MMS_CONFIRMEDSERVICE_INITIATEDOWNLOADSEQUENCE    26
#define MMS_CONFIRMEDSERVICE_DOWNLOADSEGMENT    27
#define MMS_CONFIRMEDSERVICE_TERMINATEDOWNLOADSEQUENCE    28
#define MMS_CONFIRMEDSERVICE_INITIATEUPLOADSEQUENCE    29
#define MMS_CONFIRMEDSERVICE_UPLOADSEGMENT    30
#define MMS_CONFIRMEDSERVICE_TERMINATEUPLOADSEQUENCE    31
#define MMS_CONFIRMEDSERVICE_REQUESTDOMAINDOWNLOAD    32
#define MMS_CONFIRMEDSERVICE_REQUESTDOMAINUPLOAD    33
#define MMS_CONFIRMEDSERVICE_LOADDOMAINCONTENT    34
#define MMS_CONFIRMEDSERVICE_STOREDOMAINCONTENT    35
#define MMS_CONFIRMEDSERVICE_DELETEDOMAIN    36
#define MMS_CONFIRMEDSERVICE_GETDOMAINATTRIBUTES    37
#define MMS_CONFIRMEDSERVICE_CREATEPROGRAMINVOCATION    38
#define MMS_CONFIRMEDSERVICE_DELETEPROGRAMINVOCATION    39
#define MMS_CONFIRMEDSERVICE_START    40
#define MMS_CONFIRMEDSERVICE_STOP    41
#define MMS_CONFIRMEDSERVICE_RESUME    42
#define MMS_CONFIRMEDSERVICE_RESET    43
#define MMS_CONFIRMEDSERVICE_KILL    44
#define MMS_CONFIRMEDSERVICE_GETPROGRAMINVOCATIONATTRIBUTES    45
#define MMS_CONFIRMEDSERVICE_OBTAINFILE    46
#define MMS_CONFIRMEDSERVICE_DEFINEEVENTCONDITION    47
#define MMS_CONFIRMEDSERVICE_DELETEEVENTCONDITION    48
#define MMS_CONFIRMEDSERVICE_GETEVENTCONDITIONATTRIBUTES    49
#define MMS_CONFIRMEDSERVICE_REPORTEVENTCONDITIONSTATUS    50
#define MMS_CONFIRMEDSERVICE_ALTEREVENTCONDITIONMONITORING    51
#define MMS_CONFIRMEDSERVICE_TRIGGEREVENT    52
#define MMS_CONFIRMEDSERVICE_DEFINEEVENTACTION    53
#define MMS_CONFIRMEDSERVICE_DELETEEVENTACTION    54
#define MMS_CONFIRMEDSERVICE_GETEVENTACTIONATTRIBUTES    55
#define MMS_CONFIRMEDSERVICE_REPORTEVENTACTIONSTATUS    56
#define MMS_CONFIRMEDSERVICE_DEFINEEVENTENROLLMENT    57
#define MMS_CONFIRMEDSERVICE_DELETEEVENTENROLLMENT    58
#define MMS_CONFIRMEDSERVICE_ALTEREVENTENROLLMENT    59
#define MMS_CONFIRMEDSERVICE_REPORTEVENTENROLLMENTSTATUS    60
#define MMS_CONFIRMEDSERVICE_GETEVENTENROLLMENTATTRIBUTES    61
#define MMS_CONFIRMEDSERVICE_ACKNOWLEDGEEVENTNOTIFICATION    62
#define MMS_CONFIRMEDSERVICE_GETALARMSUMMARY    63
#define MMS_CONFIRMEDSERVICE_GETALARMENROLLMENTSUMMARY    64
#define MMS_CONFIRMEDSERVICE_READJOURNAL    65
#define MMS_CONFIRMEDSERVICE_WRITEJOURNAL    66
#define MMS_CONFIRMEDSERVICE_INITIALIZEJOURNAL    67
#define MMS_CONFIRMEDSERVICE_REPORTJOURNALSTATUS    68
#define MMS_CONFIRMEDSERVICE_CREATEJOURNAL    69
#define MMS_CONFIRMEDSERVICE_DELETEJOURNAL    70
#define MMS_CONFIRMEDSERVICE_GETCAPABILITYLIST    71
#define MMS_CONFIRMEDSERVICE_FILEOPEN    72
#define MMS_FILEREAD    73
#define MMS_FILECLOSE    74
#define MMS_FILERENAME    75
#define MMS_FILEDELETE    76
#define MMS_FILEDIRECTORY    77

#define MMS_OBJECTCLASS_NAMMEDVARIABLE 0
#define MMS_OBJECTCLASS_NAMEDVARIABLELIST 2
#define MMS_OBJECTCLASS_DOMAIN 9

#define MMS_OBJECTSCOPE_VMDSPECIFIC 0
#define MMS_OBJECTSCOPE_DOMAINSPECIFIC 1

#define MMS_IEC_61850_CONF_SERV_PDU_NOT_SET 0
#define MMS_IEC_61850_CONF_SERV_PDU_GET_SERV_DIR 1
#define MMS_IEC_61850_CONF_SERV_PDU_GETLOGICALDEVICEDIRECTORY 2
#define MMS_IEC_61850_CONF_SERV_PDU_GETDATASETDIRECTORY 3
#define MMS_IEC_61850_CONF_SERV_PDU_GETDATADIRECTORY 4
#define MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE 5
#define MMS_IEC_61850_CONF_SERV_PDU_READ 6
#define MMS_IEC_61850_CONF_SERV_PDU_WRITE 7

typedef struct mms_actx_private_data_t
{
    int mms_pdu_type;                               /* MMSpdu type taken from MMSpdu CHOICE branch_taken */
    int invokeid;
    iec61850_8_1_vmd_specific vmd_specific;         /* Numeric representation of decode vmd_specific strings */
    int listOfAccessResult_cnt;                     /* Position in the list, 1 count */
    int data_cnt;                                   /* Number of times data occurred(depth)*/
    uint16_t reported_optflds;                       /* Bitmap over included fields */
    proto_item* pdu_item;                           /* The item to append PDU info to */
    int confirmedservice_type;                      /* Requested service */
    int objectclass;
    int objectscope;
    mms_transaction_t* mms_trans_p;                 /* Pointer to the transaction record */
    char* itemid_str;
    int success;                                    /* If variable access succeeded or not */
} mms_actx_private_data_t;


static const value_string mms_iec6150_cntmodel_vals[] = {
    {0, "status-only"},
    {1, "direct-with-normal-security"},
    {2, "sbo-with-normal-security"},
    {3, "direct-with-enhanced-security"},
    {4, "sbo-with-enhanced-security"},
    {0, NULL}
};

static const value_string mms_iec6150_validity_vals[] = {
    {0, "Good"},
    {1, "Invalid"},
    {2, "Reserved"},
    {3, "Questionable"},
    {0, NULL}
};

static const value_string mms_iec6150_source_vals[] = {
    {0, "Process"},
    {1, "Substituted"},
    {0, NULL}
};

static const value_string mms_iec6150_timeaccuracy_vals[] = {
    {0,  "0 bits accuracy"},
    {1,  "1 bits accuracy"},
    {2,  "2 bits accuracy"},
    {3,  "3 bits accuracy"},
    {4,  "4 bits accuracy"},
    {5,  "5 bits accuracy"},
    {6,  "6 bits accuracy"},
    {7,  "7 bits accuracy"},
    {8,  "8 bits accuracy"},
    {9,  "9 bits accuracy"},
    {10, "10 bits accuracy"},
    {11, "11 bits accuracy"},
    {12, "12 bits accuracy"},
    {13, "13 bits accuracy"},
    {14, "14 bits accuracy"},
    {15, "15 bits accuracy"},
    {16, "16 bits accuracy"},
    {17, "17 bits accuracy"},
    {18, "18 bits accuracy"},
    {19, "19 bits accuracy"},
    {20, "20 bits accuracy"},
    {21, "21 bits accuracy"},
    {22, "22 bits accuracy"},
    {23, "23 bits accuracy"},
    {24, "24 bits accuracy"},
    {25, "25 bits accuracy"},
    {26, "26 bits accuracy"},
    {27, "27 bits accuracy"},
    {28, "28 bits accuracy"},
    {29, "29 bits accuracy"},
    {30, "Invalid"},
    {31, "Unspecified"},
    {0, NULL}
};

static const value_string mms_iec6150_orcategory_vals[] = {
    {0, "not-supported"},
    {1, "bay-control"},
    {2, "station-control"},
    {3, "remote-control"},
    {4, "automatic-bay"},
    {5, "automatic-station"},
    {6, "automatic-station"},
    {7, "maintenance"},
    {8, "process"},
    {0, NULL}
};

static const value_string mms_iec6150_beh_vals[] = {
    {0,"Uninitialised"},
    {1, "on"},
    {2, "blocked"},
    {3, "test"},
    {4, "test/blocked"},
    {5, "off"},
    {0, NULL}
};

static const value_string mms_iec6150_health_vals[] = {
    {0,"Uninitialised"},
    {1,"Ok"},
    {2,"Warning"},
    {3,"Alarm"},
    {0, NULL}
};

/* Helper function to get or create the private data struct */
static
mms_private_data_t* mms_get_private_data(asn1_ctx_t* actx)
{
    packet_info* pinfo = actx->pinfo;
    mms_private_data_t* private_data = (mms_private_data_t*)p_get_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num);
    if (private_data != NULL) {
        return private_data;
    } else {
        private_data = wmem_new0(pinfo->pool, mms_private_data_t);
        p_add_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num, private_data);
        return private_data;
    }
}

/* Helper function to test presence of private data struct */
static bool
mms_has_private_data(asn1_ctx_t* actx)
{
    packet_info* pinfo = actx->pinfo;
    return (p_get_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num) != NULL);
}

static void
private_data_add_preCinfo(asn1_ctx_t* actx, uint32_t val)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    snprintf(private_data->preCinfo, BUFFER_SIZE_PRE, "%02d ", val);
}

static char*
private_data_get_preCinfo(asn1_ctx_t* actx)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    return private_data->preCinfo;
}

static void
private_data_add_moreCinfo_id(asn1_ctx_t* actx, tvbuff_t* tvb)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    (void)g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
    (void)g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool, tvb,
        0, tvb_reported_length(tvb), ENC_ASCII | ENC_NA), BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_float(asn1_ctx_t* actx, tvbuff_t* tvb)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    snprintf(private_data->moreCinfo, BUFFER_SIZE_MORE,
        " %f", tvb_get_ieee_float(tvb, 1, ENC_BIG_ENDIAN));
}

static char*
private_data_get_moreCinfo(asn1_ctx_t* actx)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    return private_data->moreCinfo;
}

/*****************************************************************************/


#include "packet-mms-fn.c"

/*
* Dissect MMS PDUs inside a PPDU.
*/
static int
dissect_mms(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent_tree, void* data _U_)
{
    int offset = 0;
    int old_offset;
    proto_item* item = NULL;
    proto_tree* tree = NULL;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
        tree = proto_item_add_subtree(item, ett_mms);
        asn1_ctx.subtree.top_tree = parent_tree;
    }
    if (use_iec61850_mapping) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS/IEC61850");
    }
    else {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
    }
    col_clear(pinfo->cinfo, COL_INFO);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        old_offset = offset;
        if (use_iec61850_mapping) {
            asn1_ctx.private_data = (void*)wmem_new0(pinfo->pool, mms_actx_private_data_t);
        }
        offset = dissect_mms_MMSpdu(false, tvb, offset, &asn1_ctx, tree, -1);
        if (asn1_ctx.private_data) {
            wmem_free(pinfo->pool, asn1_ctx.private_data);
        }
        if (offset == old_offset) {
            proto_tree_add_expert(tree, pinfo, &ei_mms_zero_pdu, tvb, offset, -1);
            break;
        }
    }
    return tvb_captured_length(tvb);
}


/*--- proto_register_mms -------------------------------------------*/
void proto_register_mms(void) {

    /* List of fields */
    static hf_register_info hf[] =
    {
        { &hf_mms_response_in,
                { "Response In", "mms.response_in",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
                "The response to this mms request is in this frame", HFILL }
        },
        { &hf_mms_response_to,
                { "Request In", "mms.response_to",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
                "This is a response to the mms request in this frame", HFILL }
        },
        { &hf_mms_response_time,
                { "Response Time", "mms.response_time",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                "The time between the Call and the Reply", HFILL }
        },
        { &hf_mms_iec61850_rptid,
          { "RptID", "mms.iec61850.rptid",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_reported_optflds,
          { "Reported OptFlds", "mms.iec61850.reported_optfld",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_seqnum,
          { "SeqNum", "mms.iec61850.seqnum",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_timeofentry,
          { "TimeOfEntry", "mms.iec61850.timeofentry",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_datset,
          { "DatSet", "mms.iec61850.datset",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_bufovfl,
          { "BufOvfl", "mms.iec61850.bufovfl",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_confrev,
          { "ConfRev", "mms.iec61850.confrev",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_inclusion_bitstring,
          { "Inclusion-bitstring", "mms.iec61850.inclusion_bitstring",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_ctlModel,
        { "ctlModel", "mms.iec61850.ctlmodel",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_cntmodel_vals), 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_QualityC0,
        { "Validity", "mms.iec61850.validity",
            FT_UINT8, BASE_HEX, VALS(mms_iec6150_validity_vals), 0xC0,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality20,
        { "Overflow", "mms.iec61850.overflow",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality10,
        { "OutofRange", "mms.iec61850.outofrange",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality8,
        { "BadReference", "mms.iec61850.badreference",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality4,
        { "Oscillatory", "mms.iec61850.oscillatory",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality2,
        { "Failure", "mms.iec61850.failure",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality1,
        { "OldData", "mms.iec61850.oldData",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0080,
        { "Inconsistent", "mms.iec61850.inconsistent",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0040,
        { "Inaccurate", "mms.iec61850.inaccurate",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0020,
        { "Source", "mms.iec61850.source",
            FT_UINT8, BASE_HEX, VALS(mms_iec6150_source_vals), 0x20,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0010,
        { "Test", "mms.iec61850.test",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0008,
        { "OperatorBlocked", "mms.iec61850.operatorblocked",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }},
        { &hf_mms_iec61850_quality_bitstring,
          { "Quality", "mms.iec61850.quality_bitstring",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality80,
        { "Leap Second Known", "mms.iec61850.leapsecondknown",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality40,
        { "ClockFailure", "mms.iec61850.clockfailure",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality20,
        { "Clock not synchronized", "mms.iec61850.clocknotsynchronized",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality1F,
        { "Time Accuracy", "mms.iec61850.timeaccuracy",
            FT_UINT8, BASE_HEX, VALS(mms_iec6150_timeaccuracy_vals), 0x1F,
            NULL, HFILL } },
        { &hf_mms_iec61850_check_bitstring,
          { "Check", "mms.iec61850.check_bitstring",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_check_b1,
        { "Synchrocheck", "mms.iec61850.synchrocheck",
            FT_BOOLEAN, 2, NULL, 0x2,
            NULL, HFILL } },
        { &hf_mms_iec61850_check_b0,
        { "Interlock-check", "mms.iec61850.interlockcheck",
            FT_BOOLEAN, 2, NULL, 0x1,
            NULL, HFILL } },
        { &hf_mms_iec61850_orcategory,
        { "orCategory", "mms.iec61850.orcategory",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_orcategory_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_beh$stval,
        { "beh", "mms.iec61850.beh",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_beh_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_mod$stval,
        { "mod", "mms.iec61850.mod",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_beh_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_health$stval,
        { "health", "mms.iec61850.health",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_health_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_ctlval,
        { "ctlVal", "mms.iec61850.ctlval",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_origin,
          { "Origin", "mms.iec61850.origin",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_origin_orcat,
        { "Origin Category", "mms.iec61850.orcat",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_origin_orident,
        { "Origin Identifier", "mms.iec61850.orident",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_ctlNum,
        { "ctlNum", "mms.iec61850.ctlnum",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_T,
        { "T(Timestamp)", "mms.iec61850.timestamp",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_test,
        { "Test", "mms.iec61850.test",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }},
#include "packet-mms-hfarr.c"
    };

    /* List of subtrees */
    static int* ett[] = {
            &ett_mms,
            &ett_mms_iec61850_quality_bitstring,
            &ett_mms_iec61850_check_bitstring,
#include "packet-mms-ettarr.c"
    };

    static ei_register_info ei[] = {
            { &ei_mms_mal_timeofday_encoding, { "mms.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
            { &ei_mms_mal_utctime_encoding, { "mms.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
            { &ei_mms_zero_pdu, { "mms.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte MMS PDU", EXPFILL }},
    };

    expert_module_t* expert_mms;

    /* Register protocol */
    proto_mms = proto_register_protocol(PNAME, PSNAME, PFNAME);
    register_dissector("mms", dissect_mms, proto_mms);
    /* Register fields and subtrees */
    proto_register_field_array(proto_mms, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mms = expert_register_protocol(proto_mms);
    expert_register_field_array(expert_mms, ei, array_length(ei));

    /* Setting to enable/disable the IEC-61850 mapping on MMS */
    module_t* mms_module = prefs_register_protocol(proto_mms, proto_reg_handoff_mms);

    prefs_register_bool_preference(mms_module, "use_iec61850_mapping",
        "Dissect MMS as IEC-61850",
        "Enables or disables dissection as IEC-61850 on top of MMS",
        &use_iec61850_mapping);
}


static bool
dissect_mms_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent_tree, void* data)
{
    /* must check that this really is an mms packet */
    int offset = 0;
    uint32_t length = 0;
    uint32_t oct;
    int idx = 0;

    int8_t tmp_class;
    bool tmp_pc;
    int32_t tmp_tag;

    /* first, check do we have at least 2 bytes (pdu) */
    if (!tvb_bytes_exist(tvb, 0, 2))
        return false;	/* no */

    /* can we recognize MMS PDU ? Return false if  not */
    /*   get MMS PDU type */
    offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

    /* check MMS type */

    /* Class should be constructed */
    if (tmp_class != BER_CLASS_CON)
        return false;

    /* see if the tag is a valid MMS PDU */
    try_val_to_str_idx(tmp_tag, mms_MMSpdu_vals, &idx);
    if (idx == -1) {
        return false;  /* no, it isn't an MMS PDU */
    }

    /* check MMS length  */
    oct = tvb_get_uint8(tvb, offset) & 0x7F;
    if (oct == 0)
        /* MMS requires length after tag so not MMS if indefinite length*/
        return false;

    offset = get_ber_length(tvb, offset, &length, NULL);
    /* do we have enough bytes? */
    if (!tvb_bytes_exist(tvb, offset, length))
        return false;

    dissect_mms(tvb, pinfo, parent_tree, data);
    return true;
}

/*--- proto_reg_handoff_mms --- */
void proto_reg_handoff_mms(void) {
    register_ber_oid_dissector("1.0.9506.2.3", dissect_mms, proto_mms, "MMS");
    register_ber_oid_dissector("1.0.9506.2.1", dissect_mms, proto_mms, "mms-abstract-syntax-version1(1)");
    heur_dissector_add("cotp", dissect_mms_heur, "MMS over COTP", "mms_cotp", proto_mms, HEURISTIC_ENABLE);
    heur_dissector_add("cotp_is", dissect_mms_heur, "MMS over COTP (inactive subset)", "mms_cotp_is", proto_mms, HEURISTIC_ENABLE);
}

