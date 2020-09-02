/* packet-wsmp.c
 * Routines for WAVE Short Message  dissection (WSMP)
 * Copyright 2013, Savari Networks (http://www.savarinetworks.com) (email: smooney@savarinetworks.com)
 *  Based on packet-wsmp.c implemented by
 *  Arada Systems (http://www.aradasystems.com) (email: siva@aradasystems.com)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Ref IEEE 1609.3
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include "packet-ieee1609dot2.h"

/* elemenID Types */
#define TRANSMITPW 0x04
#define CHANNUM    0x0F
#define DATARATE   0x10
#define WSMP       0x80
#define WSMP_S     0x81
#define WSMP_I     0x82

void proto_register_wsmp(void);
void proto_reg_handoff_wsmp(void);

static const value_string wsmp_elemenid_names[] = {
    { 0x80, "WSMP" },
    { 0x81, "WSMP-S" },
    { 0x82, "WSMP-I" },
    { 0, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_wsmp = -1;
static int hf_wsmp_version = -1;
static int hf_wsmp_var_len_det = -1;
static int hf_wsmp_psid = -1;
static int hf_wsmp_rate = -1;
static int hf_wsmp_channel = -1;
static int hf_wsmp_txpower = -1;
static int hf_wsmp_WAVEid = -1;
static int hf_wsmp_wsmlength = -1;
static int hf_wsmp_WSMP_S_data = -1;

static int hf_wsmp_subtype = -1;
static int hf_wsmp_N_header_opt_ind = -1;
static int hf_wsmp_version_v3 = -1;
static int hf_wsmp_no_elements = -1;
static int hf_wsmp_wave_ie = -1;
static int hf_wsmp_wave_ie_len = -1;
static int hf_wsmp_wave_ie_data = -1;
static int hf_wsmp_tpid = -1;

/* Initialize the subtree pointers */
static int ett_wsmp = -1;
static int ett_wsmdata = -1;
static int ett_wsmp_n_hdr = -1;
static int ett_wsmp_t_hdr = -1;
static int ett_wsmp_ie_ext = -1;
static int ett_wsmp_ie = -1;

static expert_field ei_wsmp_length_field_err = EI_INIT;
static expert_field ei_wsmp_psid_invalid = EI_INIT;

dissector_handle_t IEEE1609dot2_handle;


static const value_string wsmp_subtype_vals[] = {
    { 0x0, "Null-networking protocol" },
    { 0x1, "ITS station-internal forwarding" },
    { 0x2, "N-hop forwarding" },
    { 0x3, "Enables the features of GeoNetworking" },
    { 0, NULL }
};

static const value_string wsmp_wave_information_elements_vals[] = {
    { 0, "Reserved" },
    { 1, "Reserved" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 4, "Transmit Power Used" },                   /* WSMP - N - Header 8.3.4.4 */
    { 5, "2D Location" },                           /* WSA header 8.2.2.6 */
    { 6, "3D Location" },                           /* WSA header 8.2.2.6 */
    { 7, "Advertiser Identifier" },                 /* WSA header 8.2.2.6 */
    { 8, "Provider Service Context" },              /* WSA Service Info 8.2.3.5 */
    { 9, "IPv6 Address" },                          /* WSA Service Info 8.2.3.5 */
    { 10, "Service Por" },                          /* WSA Service Info 8.2.3.5 */
    { 11, "Provider MAC Address" },                 /* WSA Service Info 8.2.3.5 */
    { 12, "EDCA Parameter Set" },                   /* WSA Channel Info 8.2.4.8 */
    { 13, "Secondary DNS" },                        /* WSA WRA 8.2.5.7 */
    { 14, "Gateway MAC Address" },                  /* WSA WRA 8.2.5.7 */
    { 15, "Channel Number" },                       /* WSMP - N - Header 8.3.4.2 */
    { 16, "Data Rate" },                            /* WSMP - N - Header 8.3.4.3 */
    { 17, "Repeat Rate" },                          /* WSA header 8.2.2.6 */
    { 18, "Reserved" },
    { 19, "RCPI Threshold" },                       /* WSA Service Info 8.2.3.5 */
    { 20, "WSA Count Threshold" },                  /* WSA Service Info 8.2.3.5 */
    { 21, "Channel Access" },                       /* WSA Channel Info 8.2.4.8 */
    { 22, "WSA Count Threshold Interval" },         /* WSA Service Info 8.2.3.5 */
    { 23, "Channel Load" },                         /* WSMP-N-Header 8.3.4.5 */
    { 0, NULL }
};

static const value_string wsmp_tpid_vals[] = {
    { 0, "The Address Info field contains a PSID and a WAVE Information Element Extension field is not present" },
    { 1, "The Address Info field contains a PSID and a WAVE Information Element Extension field is present" },
    { 2, "The Address Info field contains source and destination ITS port numbers and a WAVE Information Element Extension field is not present" },
    { 3, "The Address Info field contains source and destination ITS port numbers and a WAVE Information Element Extension field is present" },
    { 4, "LPP mode and a WAVE Information Element Extension field is not present" },
    { 5, "LPP mode and a WAVE Information Element Extension field is present" },
    { 0, NULL }
};

/*
4.1.2 P-encoding of PSIDs
    This standard defines a compact encoding for PSID referred to as p-encoding. Octets are numbered from the
    left starting at zero (Octet 0). The length of the PSID is indicated by Octet 0, where the position of the first
    zero-value bit in descending order of bit significance in the octet indicates the length in octets of the p?encoded
    PSID. Using p-encoding, a binary "0" in the most-significant bit indicates a one-octet PSID; a binary "10"
    in the two most-significant bits indicates a two-octet PSID; a binary "110" in the three most-significant bits
    indicates a three-octet PSID; and a binary "1110" in the four most-significant bits indicates a four-octet PSID.
*/
static int
dissect_wsmp_psid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint32 *psid)
{
    guint8 oct;
    guint32 psidLen = 0;

    oct = tvb_get_guint8(tvb, offset);
    *psid = 0;

    if ((oct & 0xF0) == 0xF0) {
        proto_tree_add_expert(tree, pinfo, &ei_wsmp_psid_invalid, tvb, offset, 1);
        return offset + 1;
    } else if ((oct & 0xF0) == 0xE0) {
        psidLen = 4;
    } else if ((oct & 0xE0) == 0xC0) {
        psidLen = 3;
    } else if ((oct & 0xC0) == 0x80) {
        psidLen = 2;
    } else if ((oct & 0x80) == 0x00) {
        psidLen = 1;
    }

    if (psidLen == 1)
        *psid = oct;
    else if (psidLen == 2)
        *psid = (tvb_get_ntohs(tvb, offset) & ~0x8000) + 0x80;
    else if (psidLen == 3)
        *psid = (tvb_get_ntoh24(tvb, offset) & ~0xc00000) + 0x4080;
    else if (psidLen == 4)
        *psid = (tvb_get_ntohl(tvb, offset) & ~0xe0000000) + 0x204080;

    proto_tree_add_bits_item(tree, hf_wsmp_var_len_det, tvb, offset << 3, psidLen, ENC_NA);
    proto_tree_add_uint_bits_format_value(tree, hf_wsmp_psid, tvb, (offset << 3) + psidLen,
            (psidLen << 3) - psidLen,*psid,"%s(%u)", val64_to_str_const(*psid, ieee1609dot2_Psid_vals, "Unknown"), *psid);
    offset += psidLen;

    return offset;
}

/* 8.1.3 Length and Count field encoding*/
static int
dissect_wsmp_length_and_count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf_id, guint16* value)
{
    guint8 oct, len;
    guint16 val;
    /* For values in the range of 0 through 127, Length and Count values
     * are represented in a single-octet encoded as an unsigned integer. For values in the range 128 through 16
     * 383, values are represented as two octets encoded as follows. If the most significant bit of the field is 0b0,
     * then this indicates a one-octet Length or Count field. If the two most significant bits of the field are 0b10,
     * the Length or Count field is a two-octet field, with the remaining 14 bits representing the value encoded as
     * an unsigned integer.*/

    oct = tvb_get_guint8(tvb, offset);
    if ((oct & 0x80) == 0x80) {
        if ((oct & 0xc0) == 0x80) {
            /* Two bytes */
            val = tvb_get_ntohs(tvb, offset) & 0x3fff;
            len = 2;
        } else {
            /* Error */
            proto_tree_add_expert(tree, pinfo, &ei_wsmp_length_field_err, tvb, offset, 1);
            val = tvb_get_ntohs(tvb, offset) & 0x3fff;
            len = 2;
        }
    }else{
        /* One byte */
        val = oct;
        len = 1;
    }

    proto_tree_add_uint(tree, hf_id, tvb, offset, len, val);
    offset += len;

    if (value){
        *value = val;
    }

    return offset;
}

static int
dissect_wsmp_v3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 oct)
{
    proto_tree *sub_tree, *n_tree, *t_tree, *data_tree;
    proto_item *item;
    int offset = 0, ie_start, len_to_set;
    guint8 header_opt_ind = (oct & 0x08) >> 3;
    guint8 ie;
    guint16 count, ie_len, wsm_len;
    guint32 tpid, psid = 0;

    static int * const flags[] = {
        &hf_wsmp_subtype,
        &hf_wsmp_N_header_opt_ind,
        &hf_wsmp_version_v3,
        NULL
    };

    /* 8.3.2 WSMP Network Header (WSMP-N-Header) */

    n_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_wsmp_n_hdr, &item, "WSMP-N-Header");
    /* In Version 3
    * B7     B4          B3            B2   B0     | Variable                            | 1 octet
    * Subtype    |WSMP-NHeader      | WSMP Version |  WAVE Information Element Extension | TPID
    *            | Option Indicator |              |                                     |
    */

    proto_tree_add_bitmask_list(n_tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);
    offset++;

    /* WAVE Information Element Extension */
    if (header_opt_ind) {
        sub_tree = proto_tree_add_subtree(n_tree, tvb, offset, -1, ett_wsmp_ie_ext, &item, "WAVE Information Element Extension");
        /* Figure 14 WAVE Information Element Extension */
        /* 8.1.3 Length and Count field encoding*/
        /* Count( Number of WAVE Information Elements )*/
        offset = dissect_wsmp_length_and_count(tvb, pinfo, sub_tree, offset, hf_wsmp_no_elements, &count);

        while (count) {
            proto_tree* ie_tree;
            ie_start = offset;
            /* WAVE Element ID 1 octet*/
            ie = tvb_get_guint8(tvb, offset);
            ie_tree = proto_tree_add_subtree_format(sub_tree, tvb, offset, -1, ett_wsmp_ie, &item, "%s",
                val_to_str_const(ie, wsmp_wave_information_elements_vals, "Unknown"));

            proto_tree_add_item(ie_tree, hf_wsmp_wave_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Length */
            offset = dissect_wsmp_length_and_count(tvb, pinfo, ie_tree, offset, hf_wsmp_wave_ie_len, &ie_len);

            proto_tree_add_item(ie_tree, hf_wsmp_wave_ie_data, tvb, offset, ie_len, ENC_NA);
            offset += ie_len;

            len_to_set = offset - ie_start;
            proto_item_set_len(item, len_to_set);

            count--;
        }
    }

    /* TPID */
    proto_tree_add_item_ret_uint(n_tree, hf_wsmp_tpid, tvb, offset, 1, ENC_BIG_ENDIAN, &tpid);
    offset++;

    /* WSMP-T-Header */
    t_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_wsmp_t_hdr, &item, "WSMP-T-Header");
    switch (tpid) {
        case 0:
            /* The Address Info field contains a PSID and a WAVE Information Element Extension field is not present.*/
            offset = dissect_wsmp_psid(tvb, pinfo, t_tree, offset, &psid);
            break;
        default:
            break;
    }

    /* WSM Length */
    offset = dissect_wsmp_length_and_count(tvb, pinfo, t_tree, offset, hf_wsmp_wave_ie_len, &wsm_len);

    /* WSM Data */
    data_tree = proto_tree_add_subtree(tree, tvb, offset, wsm_len, ett_wsmdata, NULL, "Wave Short Message");

    if((psid == (guint32)psid_vehicle_to_vehicle_safety_and_awarenesss) && (IEEE1609dot2_handle)){
        ieee1609dot2_set_next_default_psid(pinfo, psid);
        tvbuff_t * tvb_new = tvb_new_subset_remaining(tvb, offset);
        call_dissector(IEEE1609dot2_handle, tvb_new, pinfo, data_tree);
    } else if ((psid == (guint32)psid_intersection_safety_and_awareness) && (IEEE1609dot2_handle)) {
        ieee1609dot2_set_next_default_psid(pinfo, psid);
        tvbuff_t * tvb_new = tvb_new_subset_remaining(tvb, offset);
        call_dissector(IEEE1609dot2_handle, tvb_new, pinfo, data_tree);
    }

    return tvb_captured_length(tvb);
}
static int
dissect_wsmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *wsmp_tree, *wsmdata_tree;
    tvbuff_t   *wsmdata_tvb;
    guint16     wsmlength, offset = 0;
    guint32     psid, supLen;
    guint8      elemenId, elemenLen, msb, oct, version;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WSMP");

    col_set_str(pinfo->cinfo, COL_INFO, "WAVE Short Message Protocol IEEE P1609.3");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_wsmp, tvb, 0, -1, ENC_NA);
    wsmp_tree = proto_item_add_subtree(ti, ett_wsmp);

    /* In Version 3
     * B7     B4          B3            B2   B0
     * Subtype    |WSMP-NHeader      | WSMP Version
     *            | Option Indicator
     */
    oct = tvb_get_guint8(tvb, offset);
    version = oct & 0x07;
    if (version == 3) {
        /* Version 3 */
        return dissect_wsmp_v3(tvb, pinfo, wsmp_tree, oct);
    }

    proto_tree_add_item(wsmp_tree, hf_wsmp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    offset = dissect_wsmp_psid(tvb, pinfo, wsmp_tree, offset, &psid);

    /* TLV decoder that does not display the T and L elements */
    elemenId = tvb_get_guint8(tvb, offset);
    while ((elemenId != WSMP) && (elemenId != WSMP_S) && (elemenId != WSMP_I))
    {
        offset++;
        if (elemenId == CHANNUM)
        {
            elemenLen = tvb_get_guint8(tvb, offset);
            offset++;
            proto_tree_add_item(wsmp_tree,
                                hf_wsmp_channel, tvb, offset, elemenLen, ENC_BIG_ENDIAN);
            offset += elemenLen;
        }
        else if (elemenId == DATARATE)
        {
            elemenLen = tvb_get_guint8(tvb, offset);
            offset++;
            proto_tree_add_item(wsmp_tree,
                                hf_wsmp_rate, tvb, offset, elemenLen, ENC_BIG_ENDIAN);
            offset += elemenLen;
        }
        else if (elemenId == TRANSMITPW)
        {
            elemenLen = tvb_get_guint8(tvb, offset);
            offset++;
            proto_tree_add_item(wsmp_tree,
                                hf_wsmp_txpower, tvb, offset, elemenLen, ENC_BIG_ENDIAN);
            offset += elemenLen;
        }
        elemenId  = tvb_get_guint8(tvb, offset);
    }

    proto_tree_add_item(wsmp_tree,
                        hf_wsmp_WAVEid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    wsmlength = tvb_get_ntohs( tvb, offset);
    proto_tree_add_item(wsmp_tree,
                        hf_wsmp_wsmlength, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (elemenId == WSMP_S)
    {
        msb    = 1;
        supLen = 0;
        while (msb)
        {
            msb = tvb_get_guint8(tvb, offset + supLen);
            msb = msb & 0x80;
            supLen++;
        }
        proto_tree_add_item(wsmp_tree,
                            hf_wsmp_WSMP_S_data, tvb, offset, supLen, ENC_BIG_ENDIAN);
        wsmlength -= supLen;
        offset    += supLen;
    }

    wsmdata_tree = proto_tree_add_subtree(wsmp_tree, tvb, offset, wsmlength,
                                        ett_wsmdata, NULL, "Wave Short Message");

    wsmdata_tvb  = tvb_new_subset_length_caplen(tvb, offset, -1, wsmlength);

    /* TODO: Branch on the application context and display accordingly
     * Default: call the data dissector
     */
    if (psid == 0x4070)
    {
        call_data_dissector(wsmdata_tvb, pinfo, wsmdata_tree);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_wsmp(void)
{
    static hf_register_info hf[] = {
        { &hf_wsmp_version,
          { "Version", "wsmp.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_var_len_det,
          { "Length", "wsmp.len.det",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_psid,
          { "PSID", "wsmp.psid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_channel,
          { "Channel", "wsmp.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_rate,
          { "Data Rate", "wsmp.rate", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_txpower,
          { "Transmit Power", "wsmp.txpower", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_WAVEid,
          { "WAVE element id", "wsmp.WAVEid", FT_UINT8, BASE_DEC, VALS(wsmp_elemenid_names), 0x0,
            NULL, HFILL }},

        { &hf_wsmp_wsmlength,
          { "WSM Length", "wsmp.wsmlength", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_WSMP_S_data,
          { "WAVE Supplement Data", "wsmp.supplement", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_subtype,
          { "Subtype", "wsmp.subtype", FT_UINT8, BASE_DEC, VALS(wsmp_subtype_vals), 0xF0,
            NULL, HFILL }},

        { &hf_wsmp_N_header_opt_ind,
          { "WSMP-NHeader Option Indicator(WAVE Information Element Extension)", "wsmp.N_header_opt_ind", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
            NULL, HFILL }},

        { &hf_wsmp_version_v3,
          { "Version", "wsmp.version_v3", FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }},

        { &hf_wsmp_no_elements,
          { "Count", "wsmp.no_elements", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_wave_ie,
          { "WAVE IE", "wsmp.wave_ie", FT_UINT8, BASE_DEC, VALS(wsmp_wave_information_elements_vals), 0x0,
            NULL, HFILL }},

        { &hf_wsmp_wave_ie_len,
          { "Length", "wsmp.wave_ie_len", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_wave_ie_data,
          { "Data", "wsmp.wave_ie_data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_tpid,
          { "TPID", "wsmp.wave_ie", FT_UINT8, BASE_DEC, VALS(wsmp_tpid_vals), 0x0,
            NULL, HFILL }},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_wsmp,
        &ett_wsmdata,
        &ett_wsmp_n_hdr,
        &ett_wsmp_t_hdr,
        &ett_wsmp_ie_ext,
        &ett_wsmp_ie,
    };

    static ei_register_info ei[] = {
    { &ei_wsmp_length_field_err, { "wsmp.length_field_err", PI_PROTOCOL, PI_ERROR,
        "Length field wrongly encoded, b6 not 0. The rest of the dissection is suspect", EXPFILL }},
    { &ei_wsmp_psid_invalid, { "wsmp.psid.invalid", PI_PROTOCOL, PI_ERROR, "Invalid PSID", EXPFILL }},
    };

    expert_module_t* expert_wsmp;

    /* Register the protocol name and description */
    proto_wsmp = proto_register_protocol("Wave Short Message Protocol(IEEE P1609.3)",
                                         "WSMP", "wsmp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_wsmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_wsmp = expert_register_protocol(proto_wsmp);
    expert_register_field_array(expert_wsmp, ei, array_length(ei));

}

void
proto_reg_handoff_wsmp(void)
{
    dissector_handle_t wsmp_handle;

    wsmp_handle = create_dissector_handle(dissect_wsmp, proto_wsmp);
    dissector_add_uint("ethertype", ETHERTYPE_WSMP, wsmp_handle);

    IEEE1609dot2_handle = find_dissector_add_dependency("ieee1609dot2.data", proto_wsmp);
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
