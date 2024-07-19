/* packet-synergy.c
 * Routines for synergy dissection
 * Copyright 2005, Vasanth Manickam <vasanthm@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-tcp.h"

void proto_register_synergy(void);
void proto_reg_handoff_synergy(void);

#define SYNERGY_PORT        24800 /* Not IANA registered */

static int proto_synergy;

static int hf_synergy_packet_len;
static int hf_synergy_packet_type;

static int hf_synergy_unknown;
static int hf_synergy_handshake;
static int hf_synergy_handshake_majorversion;
static int hf_synergy_handshake_minorversion;
static int hf_synergy_handshake_clientname;

static int hf_synergy_cbye;

static int hf_synergy_cinn;
static int hf_synergy_cinn_x;
static int hf_synergy_cinn_y;
static int hf_synergy_cinn_sequence;
static int hf_synergy_cinn_modifiermask;

static int hf_synergy_cout;

static int hf_synergy_cclp;
static int hf_synergy_cclp_clipboardidentifier;
static int hf_synergy_cclp_sequencenumber;

static int hf_synergy_csec;

static int hf_synergy_crop;

static int hf_synergy_ciak;

static int hf_synergy_dkdn;
static int hf_synergy_dkdn_keyid;
static int hf_synergy_dkdn_keymodifiermask;
static int hf_synergy_dkdn_keybutton;

static int hf_synergy_dkrp;
static int hf_synergy_dkrp_keyid;
static int hf_synergy_dkrp_keymodifiermask;
static int hf_synergy_dkrp_numberofrepeats;
static int hf_synergy_dkrp_keybutton;

static int hf_synergy_dkup;
static int hf_synergy_dkup_keyid;
static int hf_synergy_dkup_keymodifiermask;
static int hf_synergy_dkup_keybutton;

static int hf_synergy_dmdn;
static int hf_synergy_dmup;

static int hf_synergy_dmmv;
static int hf_synergy_dmmv_x;
static int hf_synergy_dmmv_y;

static int hf_synergy_dmrm;
static int hf_synergy_dmrm_x;
static int hf_synergy_dmrm_y;

static int hf_synergy_dmwm;

static int hf_synergy_dclp;
static int hf_synergy_dclp_clipboardidentifier;
static int hf_synergy_dclp_sequencenumber;
static int hf_synergy_dclp_clipboarddata;

static int hf_synergy_dinf;
static int hf_synergy_dinf_clp;
static int hf_synergy_dinf_ctp;
static int hf_synergy_dinf_wsp;
static int hf_synergy_dinf_hsp;
static int hf_synergy_dinf_swz;
static int hf_synergy_dinf_x;
static int hf_synergy_dinf_y;

static int hf_synergy_dsop;

static int hf_synergy_qinf;

static int hf_synergy_eicv;
static int hf_synergy_eicv_majorversion;
static int hf_synergy_eicv_minorversion;

static int hf_synergy_ebsy;

static int hf_synergy_eunk;

static int hf_synergy_ebad;

/* Initialize the subtree pointers */
static int ett_synergy;

static dissector_handle_t synergy_handle;

static const string_string packet_type_vals[] = {

    { "CNOP", "No Operation" },
    { "CALV", "Keep Alive" },
    { "CBYE", "Close Connection" },
    { "CINN", "Enter Screen" },
    { "COUT", "Leave Screen" },
    { "CCLP", "Grab Clipboard" },
    { "CSEC", "Screen Saver Change" },
    { "CROP", "Reset Options" },
    { "CIAK", "Resolution Change Acknowledgment" },
    { "DKDN", "Key Pressed" },
    { "DKRP", "Key Auto-Repeat" },
    { "DKUP", "Key Released" },
    { "DMDN", "Mouse Button Pressed" },
    { "DMUP", "Mouse Button Released" },
    { "DMMV", "Mouse Moved" },
    { "DMRM", "Relative Mouse Move" },
    { "DMWM", "Mouse Button Pressed" },
    { "DCLP", "Clipboard Data" },
    { "DINF", "Client Data" },
    { "DSOP", "Set Options" },
    { "QINF", "Query Screen Info" },
    { "EICV", "Incompatible Versions" },
    { "EBSY", "Connection Already in Use" },
    { "EUNK", "Unknown Client" },
    { "EBAD", "Protocol Violation" },
    { NULL  , NULL }
};

static void dissect_synergy_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_cinn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_cclp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_dkdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_dkrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_dkup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_dmmv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_dmrm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_dclp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_dinf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);
static void dissect_synergy_eicv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,int offset);


/* Code to dissect a single Synergy packet */
static int
dissect_synergy_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "synergy");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        int offset=0;
        const uint8_t* packet_type;
        proto_item *ti = NULL;
        proto_tree *synergy_tree = NULL;
        ti = proto_tree_add_protocol_format(tree, proto_synergy, tvb, 0, -1,"Synergy Protocol");
        synergy_tree = proto_item_add_subtree(ti, ett_synergy);

        proto_tree_add_item(synergy_tree,hf_synergy_packet_len,tvb,offset,4,ENC_BIG_ENDIAN);

        /* Are the first 7 bytes of the payload "Synergy"?
         * (Note this never throws an exception)
         */
        if (tvb_strneql(tvb, offset+4, "Synergy", 7) == 0) {
            /* Yes - dissect as a handshake. */
            dissect_synergy_handshake(tvb,pinfo,synergy_tree,offset+11);

            return tvb_captured_length(tvb);
        }

        /* No, so the first 4 bytes of the payload should be a packet type */
        packet_type = tvb_get_string_enc(pinfo->pool, tvb, offset+4, 4, ENC_ASCII);
        proto_tree_add_string_format_value(synergy_tree,hf_synergy_packet_type,tvb,offset+4,4, packet_type, "%s (%s)", str_to_str(packet_type, packet_type_vals, "Unknown"), packet_type);

        if(strncmp(packet_type,"CNOP",4)==0) {
        } else if(strncmp(packet_type,"CALV",4)==0) {
        } else if(strncmp(packet_type,"CBYE",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_cbye,tvb,offset+8,-1,ENC_NA);
        } else if(strncmp(packet_type,"CINN",4)==0) {
            dissect_synergy_cinn(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"COUT",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_cout,tvb,offset+8,-1,ENC_NA);
        } else if(strncmp(packet_type,"CCLP",4)==0) {
            dissect_synergy_cclp(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"CSEC",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_csec,tvb,offset+8,1,ENC_BIG_ENDIAN);
        } else if(strncmp(packet_type,"CROP",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_crop,tvb,offset+8,-1,ENC_NA);
        } else if(strncmp(packet_type,"CIAK",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_ciak,tvb,offset+8,-1,ENC_NA);
        } else if(strncmp(packet_type,"DKDN",4)==0) {
            dissect_synergy_dkdn(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"DKRP",4)==0) {
            dissect_synergy_dkrp(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"DKUP",4)==0) {
            dissect_synergy_dkup(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"DMDN",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_dmdn,tvb,offset+8,1,ENC_BIG_ENDIAN);
        } else if(strncmp(packet_type,"DMUP",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_dmup,tvb,offset+8,1,ENC_BIG_ENDIAN);
        } else if(strncmp(packet_type,"DMMV",4)==0) {
            dissect_synergy_dmmv(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"DMRM",4)==0) {
            dissect_synergy_dmrm(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"DMWM",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_dmwm,tvb,offset+8,2,ENC_BIG_ENDIAN);
        } else if(strncmp(packet_type,"DCLP",4)==0) {
            dissect_synergy_dclp(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"DINF",4)==0) {
            dissect_synergy_dinf(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"DSOP",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_dsop,tvb,offset+8,4,ENC_BIG_ENDIAN);
        } else if(strncmp(packet_type,"QINF",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_qinf,tvb,offset+8,-1,ENC_NA);
        } else if(strncmp(packet_type,"EICV",4)==0) {
            dissect_synergy_eicv(tvb,pinfo,synergy_tree,offset+8);
        } else if(strncmp(packet_type,"EBSY",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_ebsy,tvb,offset+8,-1,ENC_NA);
        } else if(strncmp(packet_type,"EUNK",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_eunk,tvb,offset+8,-1,ENC_NA);
        } else if(strncmp(packet_type,"EBAD",4)==0) {
            proto_tree_add_item(synergy_tree,hf_synergy_ebad,tvb,offset+8,-1,ENC_NA);
        } else {
            proto_tree_add_item(synergy_tree,hf_synergy_unknown,tvb,offset+8,-1,ENC_NA);
        }
    }

    return tvb_captured_length(tvb);
}

static void dissect_synergy_handshake( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_handshake, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_handshake_majorversion, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_handshake_minorversion, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    if (tvb_reported_length_remaining(tvb, offset + 4) != 0)
    {
        proto_tree_add_item(sub_tree, hf_synergy_unknown, tvb, offset + 4, 4, ENC_NA);
        proto_tree_add_item(sub_tree, hf_synergy_handshake_clientname, tvb, offset + 8, -1, ENC_ASCII);
    }
}

static void dissect_synergy_cinn( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_cinn, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_cinn_x, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_cinn_y, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_cinn_sequence, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_cinn_modifiermask, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
}

static void dissect_synergy_cclp( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_cclp, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_cclp_clipboardidentifier, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_cclp_sequencenumber, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
}

static void dissect_synergy_dkdn( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dkdn, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_dkdn_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dkdn_keymodifiermask, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    if (tvb_reported_length_remaining(tvb, offset + 4) != 0)
        proto_tree_add_item(sub_tree, hf_synergy_dkdn_keybutton, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
}

static void dissect_synergy_dkrp( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dkrp, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_dkrp_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dkrp_keymodifiermask, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dkrp_numberofrepeats, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

    if (tvb_reported_length_remaining(tvb, offset + 6) != 0)
        proto_tree_add_item(sub_tree, hf_synergy_dkrp_keybutton, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
}

static void dissect_synergy_dkup( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dkup, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_dkup_keyid, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dkup_keymodifiermask, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    if (tvb_reported_length_remaining(tvb, offset + 4) != 0)
        proto_tree_add_item(sub_tree, hf_synergy_dkup_keybutton, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
}

static void dissect_synergy_dmmv( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dmmv, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_dmmv_x, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dmmv_y, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
}

static void dissect_synergy_dmrm( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dmrm, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_dmrm_x, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dmrm_y, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
}

static void dissect_synergy_dclp( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dclp, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_dclp_clipboardidentifier, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dclp_sequencenumber, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dclp_clipboarddata, tvb, offset + 5, -1, ENC_ASCII);
}

static void dissect_synergy_dinf( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dinf, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_dinf_clp, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_ctp, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_wsp, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_hsp, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_swz, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_x, tvb, offset + 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_y, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
}

static void dissect_synergy_eicv( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_eicv, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);

    proto_tree_add_item(sub_tree, hf_synergy_eicv_majorversion, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_synergy_eicv_minorversion, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
}

static unsigned
synergy_get_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	return tvb_get_ntohl(tvb, offset) + 4;
}

static int
dissect_synergy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 4, synergy_get_pdu_len,
                     dissect_synergy_pdu, NULL);
    return tvb_captured_length(tvb);
}

void
proto_register_synergy(void)
{
    static hf_register_info hf[] = {

        { &hf_synergy_packet_len,
            { "Packet Length","synergy.packet_len",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_packet_type,
            { "Packet Type","synergy.packet_type",FT_STRING, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_unknown,
            { "unknown","synergy.unknown",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_handshake,
            { "Handshake","synergy.handshake",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_handshake_majorversion,
            { "Major Version","synergy.handshake.majorversion",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_handshake_minorversion,
            { "Minor Version","synergy.handshake.minorversion",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_handshake_clientname,
            { "Client Name","synergy.handshake.client",FT_STRING, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cbye,
            { "Close Connection","synergy.cbye",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cinn,
            { "Enter Screen","synergy.cinn",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cinn_x,
            { "Screen X","synergy.cinn.x",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cinn_y,
            { "Screen Y","synergy.cinn.y",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cinn_sequence,
            { "Sequence Number","synergy.cinn.sequence",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cinn_modifiermask,
            { "Modifier Key Mask","synergy.cinn.mask",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cout,
            { "Leave Screen","synergy.cout",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cclp,
            { "Grab Clipboard","synergy.clipboard",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cclp_clipboardidentifier,
            { "Identifier","synergy.clipboard.identifier",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_cclp_sequencenumber,
            { "Sequence Number","synergy.clipboard.sequence",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_csec,
            { "Screen Saver Change","synergy.screensaver",FT_BOOLEAN, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_crop,
            { "Reset Options","synergy.resetoptions",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_ciak,
            { "Resolution Change Acknowledgment","synergy.ack",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkdn,
            { "Key Pressed","synergy.keypressed",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkdn_keyid,
            { "Key Id","synergy.keypressed.keyid",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkdn_keymodifiermask,
            { "Key Modifier Mask","synergy.keypressed.mask",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkdn_keybutton,
            { "Key Button","synergy.keypressed.key",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkrp,
            { "Key Auto-Repeat","synergy.keyautorepeat",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkrp_keyid,
            { "Key ID","synergy.keyautorepeat.keyid",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkrp_keymodifiermask,
            { "Key modifier Mask","synergy.keyautorepeat.mask",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkrp_numberofrepeats,
            { "Number of Repeats","synergy.keyautorepeat.repeat",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkrp_keybutton,
            { "Key Button","synergy.keyautorepeat.key",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkup,
            { "Key Released","synergy.keyreleased",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkup_keyid,
            { "Key Id","synergy.keyreleased.keyid",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkup_keymodifiermask,
            { "Key Modifier Mask","synergy.keyreleased.mask",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dkup_keybutton,
            { "Key Button","synergy.keyreleased.key",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmdn,
            { "Mouse Button Pressed","synergy.mousebuttonpressed",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmup,
            { "Mouse Button Released","synergy.mousebuttonreleased",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmmv,
            { "Mouse Moved","synergy.mousemoved",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmmv_x,
            { "X Axis","synergy.mousemoved.x",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmmv_y,
            { "Y Axis","synergy.mousemoved.y",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmrm,
            { "Relative Mouse Move","synergy.relativemousemove",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmrm_x,
            { "X Axis","synergy.relativemousemove.x",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmrm_y,
            { "Y Axis","synergy.relativemousemove.y",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dmwm,
            { "Mouse Button Pressed","synergy.mousebuttonpressed",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dclp,
            { "Clipboard Data","synergy.clipboarddata",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dclp_clipboardidentifier,
            { "Clipboard Identifier","synergy.clipboarddata.identifier",FT_UINT8, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dclp_sequencenumber,
            { "Sequence Number","synergy.clipboarddata.sequence",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dclp_clipboarddata,
            { "Clipboard Data","synergy.clipboarddata.data",FT_STRING, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf,
            { "Client Data","synergy.clientdata",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf_clp,
            { "coordinate of leftmost pixel on secondary screen","synergy.clps",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf_ctp,
            { "coordinate of topmost pixel on secondary screen","synergy.clps.ctp",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf_wsp,
            { "width of secondary screen in pixels","synergy.clps.wsp",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf_hsp,
            { "height of secondary screen in pixels","synergy.clps.hsp",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf_swz,
            { "size of warp zone","synergy.clps.swz",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf_x,
            { "x position of the mouse on the secondary screen","synergy.clps.x",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dinf_y,
            { "y position of the mouse on the secondary screen","synergy.clps.y",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_dsop,
            { "Set Options","synergy.setoptions",FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_qinf,
            { "Query Screen Info","synergy.qinf",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_eicv,
            { "Incompatible Versions","synergy.eicv",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_eicv_majorversion,
            { "Major Version Number","synergy.eicv.major",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_eicv_minorversion,
            { "Minor Version Number","synergy.eicv.minor",FT_UINT16, BASE_DEC, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_ebsy,
            { "Connection Already in Use","synergy.ebsy",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_eunk,
            { "Unknown Client","synergy.unknown",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
        { &hf_synergy_ebad,
            { "Protocol Violation","synergy.violation",FT_NONE, BASE_NONE, NULL, 0x0,NULL, HFILL }
        },
    };


/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_synergy,
    };

/* Register the protocol name and description */
    proto_synergy = proto_register_protocol("Synergy", "Synergy", "synergy");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_synergy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    synergy_handle = register_dissector("synergy", dissect_synergy, proto_synergy);
}

void
proto_reg_handoff_synergy(void)
{
    dissector_add_uint_with_preference("tcp.port", SYNERGY_PORT, synergy_handle);
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
