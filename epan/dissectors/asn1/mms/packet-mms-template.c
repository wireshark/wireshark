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

static bool use_iec61850_mapping = TRUE;

/* Initialize the protocol and registered fields */
static int proto_mms;

/* Converstaion */
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
#include "packet-mms-hf.c"

/* Initialize the subtree pointers */
static int ett_mms;
static int ett_mms_iec61850_quality_bitstring;
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
    IEC61850_ITEM_ID_Q
} itemid_type;

typedef struct _mms_transaction_t {
    uint32_t req_frame;
    uint32_t rep_frame;
    nstime_t req_time;
    /* Rquest info*/
    itemid_type itemid;    /* Numeric representation of ItemId substring */
} mms_transaction_t;

typedef struct _mms_conv_info_t {
    wmem_map_t* pdus;
} mms_conv_info_t;

typedef struct mms_private_data_t
{
    char preCinfo[BUFFER_SIZE_PRE];
    char moreCinfo[BUFFER_SIZE_MORE];
} mms_private_data_t;


typedef struct mms_actx_private_data_t
{
    int mms_pdu_type;                               /* MMSpdu type taken from MMSpdu CHOISE branch_taken */
    int invokeid;
    iec61850_8_1_vmd_specific vmd_specific;    /* Numeric representation of decode vmd_specific strings */
    int listOfAccessResult_cnt;                     /* Posision  in the list, 1 count*/
    guint16 reported_optflds;                       /* Bitmap over included fields*/
    mms_transaction_t* mms_trans;
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
static gboolean
mms_has_private_data(asn1_ctx_t* actx)
{
    packet_info* pinfo = actx->pinfo;
    return (p_get_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num) != NULL);
}

static void
private_data_add_preCinfo(asn1_ctx_t* actx, guint32 val)
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
    (void)g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool,
        tvb, 2, tvb_get_guint8(tvb, 1), ENC_STRING), BUFFER_SIZE_MORE);
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
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
        tree = proto_item_add_subtree(item, ett_mms);
        asn1_ctx.subtree.top_tree = parent_tree;
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
    col_clear(pinfo->cinfo, COL_INFO);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        old_offset = offset;
        if (use_iec61850_mapping) {
            asn1_ctx.private_data = (void*)wmem_new0(pinfo->pool, mms_actx_private_data_t);
        }
        offset = dissect_mms_MMSpdu(FALSE, tvb, offset, &asn1_ctx, tree, -1);
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
#include "packet-mms-hfarr.c"
    };

    /* List of subtrees */
    static gint* ett[] = {
            &ett_mms,
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
        "Enables or disables dsissection as IEC-61850 on top of MMS",
        &use_iec61850_mapping);
}


static gboolean
dissect_mms_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent_tree, void* data _U_)
{
    /* must check that this really is an mms packet */
    int offset = 0;
    guint32 length = 0;
    guint32 oct;
    gint idx = 0;

    gint8 tmp_class;
    bool tmp_pc;
    gint32 tmp_tag;

    /* first, check do we have at least 2 bytes (pdu) */
    if (!tvb_bytes_exist(tvb, 0, 2))
        return FALSE;	/* no */

    /* can we recognize MMS PDU ? Return FALSE if  not */
    /*   get MMS PDU type */
    offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

    /* check MMS type */

    /* Class should be constructed */
    if (tmp_class != BER_CLASS_CON)
        return FALSE;

    /* see if the tag is a valid MMS PDU */
    try_val_to_str_idx(tmp_tag, mms_MMSpdu_vals, &idx);
    if (idx == -1) {
        return FALSE;  /* no, it isn't an MMS PDU */
    }

    /* check MMS length  */
    oct = tvb_get_guint8(tvb, offset) & 0x7F;
    if (oct == 0)
        /* MMS requires length after tag so not MMS if indefinite length*/
        return FALSE;

    offset = get_ber_length(tvb, offset, &length, NULL);
    /* do we have enough bytes? */
    if (!tvb_bytes_exist(tvb, offset, length))
        return FALSE;

    dissect_mms(tvb, pinfo, parent_tree, data);
    return TRUE;
}

/*--- proto_reg_handoff_mms --- */
void proto_reg_handoff_mms(void) {
    register_ber_oid_dissector("1.0.9506.2.3", dissect_mms, proto_mms, "MMS");
    register_ber_oid_dissector("1.0.9506.2.1", dissect_mms, proto_mms, "mms-abstract-syntax-version1(1)");
    heur_dissector_add("cotp", dissect_mms_heur, "MMS over COTP", "mms_cotp", proto_mms, HEURISTIC_ENABLE);
    heur_dissector_add("cotp_is", dissect_mms_heur, "MMS over COTP (inactive subset)", "mms_cotp_is", proto_mms, HEURISTIC_ENABLE);
}

