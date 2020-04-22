/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lnpdqp.c                                                            */
/* asn2wrs.py -b -p lnpdqp -c ./lnpdqp.cnf -s ./packet-lnpdqp-template -D . -O ../.. LNPDQP.asn */

/* Input file: packet-lnpdqp-template.c */

#line 1 "./asn1/lnpdqp/packet-lnpdqp-template.c"
/* packet-lnpdqp-template.c
 * Routines for Local Number Portability Database Query Protocol dissection
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref GR-533 i2 2001
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include "packet-ber.h"

#define PNAME  "Local Number Portability Database Query"
#define PSNAME "LNPDQP"
#define PFNAME "lnpdqp"

/*
 * Operation Code is partitioned into:
 * Operation Family = ConnectionControl, no Reply Required (4)
 * Operation Specifier = Connect (1)
 */
#define LNPDQP_ANSI_TCAP_OPCODE_CC 0x0401
/*
 * Operation Code is partitioned into:
 * Operation Family = ProvideInstruction, Reply Required (131) 0x83
 * Operation Specifier = Start (1)
 */
/* Exluding H bit */
#define LNPDQP_ANSI_TCAP_OPCODE_PI 0x0301

void proto_reg_handoff_lnpdqp(void);
void proto_register_lnpdqp(void);

/* Initialize the protocol and registered fields */
static int proto_lnpdqp = -1;


static int hf_lnpdqp_type_of_digits = -1;
static int hf_lnpdqp_nature_of_number = -1;
static int hf_lnpdqp_digits_enc = -1;
static int hf_lnpdqp_np = -1;
static int hf_lnpdqp_nr_digits = -1;
static int hf_lnpdqp_bcd_digits = -1;
static int hf_lnpdqp_ia5_digits = -1;

/* asn2wrs/the ber dissector does not handle the same tag used multiple times
 * in asn1 description, do some magic to handle.
 */
static int hf_lnpdqp_networkRoutingNumber = -1;   /* Digits */
static int hf_lnpdqp_callingPartyANI = -1;        /* Digits */
static int hf_lnpdqp_originatingLATA = -1;        /* Digits */
static int hf_lnpdqp_carrierID = -1;              /* Digits */


/*--- Included file: packet-lnpdqp-hf.c ---*/
#line 1 "./asn1/lnpdqp/packet-lnpdqp-hf.c"
static int hf_lnpdqp_ConnectionControlArg_PDU = -1;  /* ConnectionControlArg */
static int hf_lnpdqp_ProvideInstructionArg_PDU = -1;  /* ProvideInstructionArg */
static int hf_lnpdqp_digits = -1;                 /* Digits */
static int hf_lnpdqp_billingIndicators = -1;      /* BillingIndicators */
static int hf_lnpdqp_calledPartyNumber = -1;      /* ServiceKey */
static int hf_lnpdqp_oli = -1;                    /* OriginatingStationType */

/*--- End of included file: packet-lnpdqp-hf.c ---*/
#line 58 "./asn1/lnpdqp/packet-lnpdqp-template.c"

static int ett_lnpdqp = -1;
static int ett_lnpdqp_digitstype = -1;
static int ett_lnpdqp_digits = -1;

/*--- Included file: packet-lnpdqp-ett.c ---*/
#line 1 "./asn1/lnpdqp/packet-lnpdqp-ett.c"
static gint ett_lnpdqp_ConnectionControlArg_U = -1;
static gint ett_lnpdqp_ProvideInstructionArg_U = -1;
static gint ett_lnpdqp_ServiceKey = -1;

/*--- End of included file: packet-lnpdqp-ett.c ---*/
#line 63 "./asn1/lnpdqp/packet-lnpdqp-template.c"


/* Type of Digits (octet 1, bits A-H) */
static const value_string lnpdqp_type_of_digits_vals[] = {
    {   0, "Not Used" },
    {   1, "Dialed Number or Called Party Number" },
    {   2, "Calling Party Number" },
    {   3, "Caller Interaction" },
    {   4, "Routing Number" },
    {   5, "Billing Number" },
    {   6, "Destination Number" },
    {   7, "LATA" },
    {   8, "Carrier" },
    {   9, "Last Calling Party" },
    {   10, "Last Party Called" },
    {   11, "Calling Directory Number" },
    {   12, "VMSR Identifier" },
    {   13, "Original Called Number" },
    {   14, "Redirecting Number" },
    {   15, "Connected Number" },
    {   0, NULL }
};

#if 0
XXXX Currently unused
/* Nature of Number (octet 2, bits A-H )*/
static const true_false_string lnpdqp_na_bool_val  = {
    "International",
    "National"
};
static const true_false_string lnpdqp_pi_bool_val  = {
    "Presentation Restricted",
    "Presentation Allowed"
};
static const true_false_string lnpdqp_navail_bool_val  = {
    "Number is not available",
    "Number is available"
};
static const true_false_string lnpdqp_si_bool_val  = {
    "User provided, screening passed",
    "User provided, not screened"
};
#endif
static const value_string lnpdqp_na_vals[]  = {
    {   0, "National, No Presentation Restricted"},
    {   1, "International, No Presentation Restricted"},
    {   2, "National, Presentation Restricted"},
    {   3, "International, Presentation Restricted"},
    {   0, NULL }
};
/* Encoding (octet 3, bits A-D) */
static const value_string lnpdqp_digits_enc_vals[]  = {
    {   0, "Not used"},
    {   1, "BCD"},
    {   2, "IA5"},
    {   3, "Octet string"},
    {   0, NULL }
};
/* Numbering Plan (octet 3, bits E-H) */
static const value_string lnpdqp_np_vals[]  = {
    {   0, "Unknown or not applicable"},
    {   1, "ISDN Numbering Plan (ITU Rec. E.164)"},
    {   2, "Telephony Numbering (ITU-T Rec. E.164,E.163)"},
    {   3, "Data Numbering (ITU-T Rec. X.121)"},
    {   4, "Telex Numbering (ITU-T Rec. F.69)"},
    {   5, "Maritime Mobile Numbering"},
    {   6, "Land Mobile Numbering (ITU-T Rec. E.212)"},
    {   7, "Private Numbering Plan"},
    {   0, NULL }
};

/*
 * OriginatingStationType ::= OCTET STRING (SIZE(1))
 * The following codes are used in the originating line information field:
 * 00000010 } Binary values administered by the North
 * to } American Numbering Administration
 * 01100011 }
 * Ref http://www.nanpa.com/number_resource_info/ani_ii_assignments.html
 */

static const value_string lnpdqp_OriginatingStationType_vals[]  = {
    {   0, "Plain Old Telephone Service (POTS) - non-coin service requiring no special treatment"},
    {   1, "Multiparty line (more than 2) - ANI cannot be provided on 4 or 8 party lines. "},
    {   2, "ANI Failure "},
    /* 03-05 Unassigned */
    {   6, "Station Level Rating "},
    {   7, "Special Operator Handling Required"},
    /* 08-09 Unassigned */
    {   10, "Not assignable - conflict with 10X test code"},
    /* 11 Unassigned */
    /* 12-19 Not assignable - conflict with international outpulsing code */
    {   20, "Automatic Identified Outward Dialing (AIOD)"},
    /* 21-22 Unassigned */
    /* To lasy to do these */
    {   61, "Cellular/Wireless PCS (Type 1) "},
    {   62, "Cellular/Wireless PCS (Type 2) "},
    {   63, "Cellular/Wireless PCS (Roaming)"},
    {   0, NULL }
};

static void
dissect_lnpdqp_digits_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, asn1_ctx_t *actx _U_){

    guint8 octet , no_of_digits;
    int    offset = 0;
    char *digit_str;

    proto_tree *subtree;


    subtree = proto_item_add_subtree(actx->created_item, ett_lnpdqp_digitstype);

    /* Octet 1  Type of Digits*/
    proto_tree_add_item(subtree, hf_lnpdqp_type_of_digits, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 2 Nature of Number*/
    proto_tree_add_item(subtree, hf_lnpdqp_nature_of_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 3 Numbering Plan |Encoding Scheme| */
    octet = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(subtree, hf_lnpdqp_np, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_lnpdqp_digits_enc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 4 Number of Digits */
    switch ((octet&0xf)){
    case 1:
        /* BCD Coding */
        no_of_digits = tvb_get_guint8(tvb,offset);
        proto_tree_add_item(subtree, hf_lnpdqp_nr_digits, tvb, offset, 1, ENC_BIG_ENDIAN);
        if(no_of_digits == 0)
            return;
        offset++;
        proto_tree_add_item_ret_display_string(subtree, hf_lnpdqp_bcd_digits, tvb, offset, -1, ENC_KEYPAD_BC_TBCD, wmem_packet_scope(), &digit_str);
        proto_item_append_text(actx->created_item, " - %s", digit_str);
        break;
    case 2:
        /* IA5 Coding */
        no_of_digits = tvb_get_guint8(tvb,offset);
        proto_tree_add_item(subtree, hf_lnpdqp_nr_digits, tvb, offset, 1, ENC_BIG_ENDIAN);
        if(no_of_digits == 0)
            return;
        offset++;
        proto_tree_add_item(subtree, hf_lnpdqp_ia5_digits, tvb, offset, -1, ENC_ASCII|ENC_NA);
        proto_item_append_text(actx->created_item, " - %s", tvb_get_string_enc(wmem_packet_scope(),tvb,offset,tvb_reported_length_remaining(tvb,offset), ENC_ASCII | ENC_NA));
        break;
    default:
        break;
    }

}



/*--- Included file: packet-lnpdqp-fn.c ---*/
#line 1 "./asn1/lnpdqp/packet-lnpdqp-fn.c"


static int
dissect_lnpdqp_Digits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 13 "./asn1/lnpdqp/lnpdqp.cnf"
    tvbuff_t *parameter_tvb = NULL;
    guint8 type_of_dgt;
    proto_tree *subtree;

    type_of_dgt = tvb_get_guint8(tvb,offset);
    switch(type_of_dgt){
        case 2:
            /* Calling Party Number */
            hf_index = hf_lnpdqp_callingPartyANI;
            break;
        case 4:
            /* Routing Number */
            hf_index = hf_lnpdqp_networkRoutingNumber;
            break;
        case 7:
            /* Local Access and Transport Area */
            hf_index = hf_lnpdqp_originatingLATA;
            break;
        case 8:
            /* Carrier */
            hf_index = hf_lnpdqp_carrierID;
            break;
        default:
            break;
    }
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

    if (parameter_tvb){
        subtree = proto_item_add_subtree(actx->created_item, ett_lnpdqp_digits);
        dissect_lnpdqp_digits_type(parameter_tvb,actx->pinfo,subtree, actx);
    }



  return offset;
}



static int
dissect_lnpdqp_BillingIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ConnectionControlArg_U_set[] = {
  { &hf_lnpdqp_digits       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lnpdqp_Digits },
  { &hf_lnpdqp_billingIndicators, BER_CLASS_PRI, 65, BER_FLAGS_IMPLTAG, dissect_lnpdqp_BillingIndicators },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lnpdqp_ConnectionControlArg_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ConnectionControlArg_U_set, hf_index, ett_lnpdqp_ConnectionControlArg_U);

  return offset;
}



static int
dissect_lnpdqp_ConnectionControlArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 18, TRUE, dissect_lnpdqp_ConnectionControlArg_U);

  return offset;
}


static const value_string lnpdqp_ServiceKey_vals[] = {
  {   4, "digits" },
  { 0, NULL }
};

static const ber_choice_t ServiceKey_choice[] = {
  {   4, &hf_lnpdqp_digits       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lnpdqp_Digits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_lnpdqp_ServiceKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ServiceKey_choice, hf_index, ett_lnpdqp_ServiceKey,
                                 NULL);

  return offset;
}



static int
dissect_lnpdqp_OriginatingStationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ProvideInstructionArg_U_set[] = {
  { &hf_lnpdqp_calledPartyNumber, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lnpdqp_ServiceKey },
  { &hf_lnpdqp_digits       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lnpdqp_Digits },
  { &hf_lnpdqp_oli          , BER_CLASS_PRI, 69, BER_FLAGS_IMPLTAG, dissect_lnpdqp_OriginatingStationType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_lnpdqp_ProvideInstructionArg_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ProvideInstructionArg_U_set, hf_index, ett_lnpdqp_ProvideInstructionArg_U);

  return offset;
}



static int
dissect_lnpdqp_ProvideInstructionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 18, TRUE, dissect_lnpdqp_ProvideInstructionArg_U);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ConnectionControlArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_lnpdqp_ConnectionControlArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_lnpdqp_ConnectionControlArg_PDU);
  return offset;
}
static int dissect_ProvideInstructionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_lnpdqp_ProvideInstructionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_lnpdqp_ProvideInstructionArg_PDU);
  return offset;
}


/*--- End of included file: packet-lnpdqp-fn.c ---*/
#line 216 "./asn1/lnpdqp/packet-lnpdqp-template.c"

static int
dissect_lnpdqp_cc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    asn1_ctx_t asn1_ctx;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    col_set_str(pinfo->cinfo, COL_INFO, "ConnectionControl");


    /* create display subtree for the protocol */
    item = proto_tree_add_item(parent_tree, proto_lnpdqp, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lnpdqp);

    return dissect_ConnectionControlArg_PDU(tvb, pinfo, tree, NULL);
}

static int
dissect_lnpdqp_pi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    asn1_ctx_t asn1_ctx;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    col_set_str(pinfo->cinfo, COL_INFO, "ProvideInstruction");


    /* create display subtree for the protocol */
    item = proto_tree_add_item(parent_tree, proto_lnpdqp, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_lnpdqp);

    return dissect_ProvideInstructionArg_PDU(tvb, pinfo, tree, NULL);

}


void proto_register_lnpdqp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
        { &hf_lnpdqp_type_of_digits,
          { "Type of Digits", "lnpdqp.type_of_digits",
            FT_UINT8, BASE_DEC, VALS(lnpdqp_type_of_digits_vals), 0x0,
            NULL, HFILL }},
        { &hf_lnpdqp_nature_of_number,
          { "Nature of Number", "lnpdqp.na",
            FT_UINT8, BASE_DEC, VALS(lnpdqp_na_vals), 0x0,
            NULL, HFILL }},
        { &hf_lnpdqp_digits_enc,
          { "Encoding", "lnpdqp.enc",
            FT_UINT8, BASE_DEC, VALS(lnpdqp_digits_enc_vals), 0x0f,
            NULL, HFILL }},
        { &hf_lnpdqp_np,
          { "Numbering Plan", "lnpdqp.np",
            FT_UINT8, BASE_DEC, VALS(lnpdqp_np_vals), 0xf0,
            NULL, HFILL }},
        { &hf_lnpdqp_nr_digits,
          { "Number of Digits", "lnpdqp.nr_digits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_lnpdqp_bcd_digits,
          { "BCD digits", "lnpdqp.bcd_digits",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_lnpdqp_ia5_digits,
          { "IA5 digits", "lnpdqp.ia5_digits",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

/* asn2wrs/the ber dissector does not handle the same tag used multiple times
 * in asn1 description, do some magic to handle.
 */
    { &hf_lnpdqp_networkRoutingNumber,
      { "networkRoutingNumber", "lnpdqp.networkRoutingNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},

    { &hf_lnpdqp_callingPartyANI,
      { "callingPartyANI", "lnpdqp.callingPartyANI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_lnpdqp_originatingLATA,
      { "originatingLATA", "lnpdqp.originatingLATA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},
    { &hf_lnpdqp_carrierID,
      { "carrierID", "lnpdqp.carrierID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Digits", HFILL }},


/*--- Included file: packet-lnpdqp-hfarr.c ---*/
#line 1 "./asn1/lnpdqp/packet-lnpdqp-hfarr.c"
    { &hf_lnpdqp_ConnectionControlArg_PDU,
      { "ConnectionControlArg", "lnpdqp.ConnectionControlArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lnpdqp_ProvideInstructionArg_PDU,
      { "ProvideInstructionArg", "lnpdqp.ProvideInstructionArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lnpdqp_digits,
      { "digits", "lnpdqp.digits",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lnpdqp_billingIndicators,
      { "billingIndicators", "lnpdqp.billingIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lnpdqp_calledPartyNumber,
      { "calledPartyNumber", "lnpdqp.calledPartyNumber",
        FT_UINT32, BASE_DEC, VALS(lnpdqp_ServiceKey_vals), 0,
        "ServiceKey", HFILL }},
    { &hf_lnpdqp_oli,
      { "oli", "lnpdqp.oli",
        FT_UINT8, BASE_DEC, VALS(lnpdqp_OriginatingStationType_vals), 0,
        "OriginatingStationType", HFILL }},

/*--- End of included file: packet-lnpdqp-hfarr.c ---*/
#line 314 "./asn1/lnpdqp/packet-lnpdqp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_lnpdqp,
    &ett_lnpdqp_digitstype,
    &ett_lnpdqp_digits,


/*--- Included file: packet-lnpdqp-ettarr.c ---*/
#line 1 "./asn1/lnpdqp/packet-lnpdqp-ettarr.c"
    &ett_lnpdqp_ConnectionControlArg_U,
    &ett_lnpdqp_ProvideInstructionArg_U,
    &ett_lnpdqp_ServiceKey,

/*--- End of included file: packet-lnpdqp-ettarr.c ---*/
#line 323 "./asn1/lnpdqp/packet-lnpdqp-template.c"
  };

  /* Register protocol */
  proto_lnpdqp = proto_register_protocol(PNAME, PSNAME, PFNAME);


  register_dissector("lnpdqp_cc", dissect_lnpdqp_cc, proto_lnpdqp);
  register_dissector("lnpdqp_pi", dissect_lnpdqp_pi, proto_lnpdqp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lnpdqp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}
void proto_reg_handoff_lnpdqp(void) {

    static dissector_handle_t lnpdqp_cc_handle, lnpdqp_pi_handle;

    lnpdqp_cc_handle = find_dissector("lnpdqp_cc");
    lnpdqp_pi_handle = find_dissector("lnpdqp_pi");

    dissector_add_uint("ansi_tcap.nat.opcode", LNPDQP_ANSI_TCAP_OPCODE_CC, lnpdqp_cc_handle);
    dissector_add_uint("ansi_tcap.nat.opcode", LNPDQP_ANSI_TCAP_OPCODE_PI, lnpdqp_pi_handle);

}
/*
* Editor modelines
*
* Local Variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
