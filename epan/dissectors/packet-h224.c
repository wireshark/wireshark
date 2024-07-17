/* packet-h224.c
 * Routines for H.224 dissection
 * Copyright 2022, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
    RFC description H.224 in SDP: RFC4573                  https://www.rfc-editor.org/rfc/rfc4573.html
    H.281 - FECC protocol H.281                            https://www.itu.int/rec/T-REC-H.281/en
    H.224 - transport encapsulation for FECC H.224         https://www.itu.int/rec/T-REC-H.224-200501-I/en
    H.323 Annex Q - packing description H.224 in RTP H.323 https://www.itu.int/rec/T-REC-H.323-202203-I
 */

#include <config.h>


#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/t35.h>
#include <epan/tfs.h>
//#include <epan/expert.h>
//#include <epan/prefs.h>

/* Prototypes */
void proto_reg_handoff_h224(void);
void proto_register_h224(void);

/* Initialize the protocol and registered fields */
static int proto_h224;
static int hf_h224_q922_dlci_priority;
static int hf_h224_q922_ctl;
static int hf_h224_dta;
static int hf_h224_sta;
static int hf_h224_reserved;
static int hf_h224_standard_client_id;
static int hf_h224_extended_client_id_list;
static int hf_h224_non_standard_client;
static int hf_h224_extended_client_id;
static int hf_h224_country_code;
static int hf_h224_extension;
static int hf_h224_manufacturer_code;
static int hf_h224_client_id_manufacturer;

static int hf_h224_es_b7;
static int hf_h224_bs_b6;
static int hf_h224_c1_b5;
static int hf_h224_c2_b4;
static int hf_h224_seg_b3b0;
static int hf_h224_other_client_data;

static int hf_h224_client_list_code;
static int hf_h224_extra_caps_code;
static int hf_h224_response_code;
static int hf_h224_number_of_clients;
static int hf_h224_ex_caps_bit;
static int hf_h224_caps_reserved;
static int hf_h224_brd_svs;
static int hf_h224_number_of_presets;
static int hf_h224_vs_id;
static int hf_h224_vs_reserved_b3;
static int hf_h224_vs_reserved_b3b0;
static int hf_h224_motion_video;
static int hf_h224_norm_res_si;
static int hf_h224_dbl_res_si;
static int hf_h224_pan_cap;
static int hf_h224_tilt_cap;
static int hf_h224_zoom_cap;
static int hf_h224_focus_cap;
static int hf_h224_encoded_characters;
static int hf_h224_end_octet;
static int hf_h224_command_code;
static int hf_h224_message_pan;
static int hf_h224_message_pan_dir;
static int hf_h224_message_tilt;
static int hf_h224_message_tilt_dir;
static int hf_h224_message_zoom;
static int hf_h224_message_zoom_dir;
static int hf_h224_message_focus;
static int hf_h224_message_focus_dir;
static int hf_h224_message_reserved_b7b4;
static int hf_h224_message_reserved_b3b2;
static int hf_h224_message_reserved_b3b0;
static int hf_h224_message_vs_m1;
static int hf_h224_message_vs_m0;
static int hf_h224_message_timeout;
static int hf_h224_message_preset_number;

//static expert_field ei_h224_EXPERTABBREV;

static dissector_handle_t h224_handle;

/* Initialize the subtree pointers */
static int ett_h224;

/* Definition of DLCI data priority's masks */
#define H224_DATA_PRI_MASK      0xFCF0

#define FECC_MAX_LENGTH_ASCII_STR       16
#define TIMEOUT_INTERVALS               50
#define MAX_TIMEOUT_VALUE               800

/* Definition of Standard Client IDs */
#define H224_CME_CLIENT_ID                      0x00
#define H224_FECC_CLIENT_ID                     0x01
#define H224_EXTENED_CLIENT_ID                  0x7E
#define H224_NON_STANDARD_CLIENT_ID             0x7F

/* definitions of CME messages type */
#define CME_MSG_Client_List_Message             0x0100
#define CME_MSG_Client_List_Command             0x01FF
#define CME_MSG_Extra_Capabilities_Message      0x0200
#define CME_MSG_Extra_Capabilities_Command      0x02FF

/* definitions of FECC messages type */
#define FECC_MSG_START_ACTION_REQ               0x01
#define FECC_MSG_CONTINUE_ACTION_REQ            0x02
#define FECC_MSG_STOP_ACTION_REQ                0x03
#define FECC_MSG_SELECT_VIDEO_SOURCE_REQ        0x04
#define FECC_MSG_VIDEO_SOURCE_SWITCHED_IND      0x05
#define FECC_MSG_STORE_AS_PRESET_REQ            0x06
#define FECC_MSG_ACTIVATE_PRESET_REQ            0x07

static unsigned dissect_h224_cme_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset);
static unsigned dissect_h224_fecc_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset);
static unsigned dissect_h224_extended_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset);
static unsigned dissect_h224_non_standard_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset);

typedef struct {
    int optcode;
    unsigned (*decode) (tvbuff_t*, proto_tree*, unsigned);
} h224_opt_t;

static const h224_opt_t h224opt[] = {
/* CME */           {H224_CME_CLIENT_ID, dissect_h224_cme_client_data},
/* FECC */          {H224_FECC_CLIENT_ID, dissect_h224_fecc_client_data},
/* EXTENED */       {H224_EXTENED_CLIENT_ID, dissect_h224_extended_client_data},
/* NON_STANDARD */  {H224_NON_STANDARD_CLIENT_ID, dissect_h224_non_standard_client_data},
                    {0, NULL}
};

/* DLCI address for data priority */
static const value_string h224_data_priority[] =
        {
                { 6, "Low Priority Data" },
                { 7, "High Priority Data" },
                { 0, NULL },
        };

static const value_string h224_client_data_type[] =
        {
                { H224_CME_CLIENT_ID, "Client Data For CME(Client Management Entity)" },
                { H224_FECC_CLIENT_ID, "Client Data For FECC(Far-End Camera Control)" },
                { H224_EXTENED_CLIENT_ID, "Client Data For Extended Client ID list" },
                { H224_NON_STANDARD_CLIENT_ID, "Client Data For Non-standard client" },
                { 0, NULL}
        };

static const value_string h224_fecc_message_type[] =
        {
                { FECC_MSG_START_ACTION_REQ, "START ACTION Request" },
                { FECC_MSG_CONTINUE_ACTION_REQ, "CONTINUE ACTION Request" },
                { FECC_MSG_STOP_ACTION_REQ, "STOP ACTION Request" },
                { FECC_MSG_SELECT_VIDEO_SOURCE_REQ, "SELECT VIDEO SOURCE Request" },
                { FECC_MSG_VIDEO_SOURCE_SWITCHED_IND, "VIDEO SOURCE SWITCHED indication" },
                { FECC_MSG_STORE_AS_PRESET_REQ, "STORE AS PRESET Request" },
                { FECC_MSG_ACTIVATE_PRESET_REQ, "ACTIVATE PRESET Request" },
                { 0, NULL },
        };

static const true_false_string tfs_right_left = { "Right", "Left" };
static const true_false_string tfs_in_out = { "In", "Out" };

static value_string_ext h224_client_data_ext = VALUE_STRING_EXT_INIT(h224_client_data_type);

static unsigned
dissect_h224_standard_clients_ids(tvbuff_t* tvb, proto_tree* tree, unsigned offset, uint8_t client_id)
{
    uint32_t manufacturer_code;

    if (client_id == H224_EXTENED_CLIENT_ID) {
        proto_tree_add_item(tree, hf_h224_extended_client_id_list, tvb, offset, 1, ENC_NA);
        offset++;
        proto_tree_add_item(tree, hf_h224_extended_client_id, tvb, offset, 1, ENC_NA);
        offset++;
    } else if (client_id == H224_NON_STANDARD_CLIENT_ID){
        proto_tree_add_item(tree, hf_h224_non_standard_client, tvb, offset, 1, ENC_NA);
        offset++;
        manufacturer_code = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_h224_country_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_h224_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_uint(tree, hf_h224_manufacturer_code, tvb, offset - 2, 4, manufacturer_code);
        offset += 2;
        proto_tree_add_item(tree, hf_h224_client_id_manufacturer, tvb, offset, 1, ENC_NA);
        offset++;
    } else {
        proto_tree_add_item(tree, hf_h224_standard_client_id, tvb, offset, 1, ENC_NA);
        offset++;
    }
    return offset;
}

static unsigned
dissect_h224_cme_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset)
{
    uint16_t type;
    uint8_t num;
    uint8_t oct;
    uint8_t source_id;
    uint8_t zero_offset;
    proto_tree *ext_tree;

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_h224, NULL,
                                      val_to_str_ext_const(H224_CME_CLIENT_ID, &h224_client_data_ext, "Unknown field"));
    type = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    switch (type) {
        case CME_MSG_Client_List_Message:
            proto_tree_add_item(ext_tree, hf_h224_client_list_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_response_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_number_of_clients, tvb, offset, 1, ENC_BIG_ENDIAN);
            num = tvb_get_uint8(tvb, offset);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_ex_caps_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            for (int i = 0; i < num; i++) {
                oct = tvb_get_uint8(tvb, offset);
                offset = dissect_h224_standard_clients_ids(tvb, ext_tree, offset, (oct & 0x7f));
            }
            break;
        case CME_MSG_Client_List_Command:
            proto_tree_add_item(ext_tree, hf_h224_client_list_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_response_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case CME_MSG_Extra_Capabilities_Message:
            proto_tree_add_item(ext_tree, hf_h224_extra_caps_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_response_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_ex_caps_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            oct = tvb_get_uint8(tvb, offset);
            offset = dissect_h224_standard_clients_ids(tvb, ext_tree, offset, oct);
            if ((oct & 0x7f) == 0x01) {
                static int* const fecc_number_of_presets[] = {
                        &hf_h224_caps_reserved,
                        &hf_h224_brd_svs,
                        &hf_h224_number_of_presets,
                        NULL
                };
                proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, fecc_number_of_presets, ENC_BIG_ENDIAN);
                offset++;
                oct = tvb_get_uint8(tvb, offset);
                static int* const fecc_vrs_capabilities[] = {
                        &hf_h224_vs_id,
                        &hf_h224_vs_reserved_b3,
                        &hf_h224_motion_video,
                        &hf_h224_norm_res_si,
                        &hf_h224_dbl_res_si,
                        NULL
                };
                proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, fecc_vrs_capabilities, ENC_BIG_ENDIAN);
                offset++;
                source_id = (oct & 0xf0) >> 4;
                if (source_id > 5) {
                    zero_offset = tvb_find_guint8(tvb, offset, FECC_MAX_LENGTH_ASCII_STR, 0);
                    if (zero_offset > offset) {
                        proto_tree_add_item(ext_tree, hf_h224_encoded_characters, tvb, offset, zero_offset - offset, ENC_ASCII);
                        offset = zero_offset;
                        proto_tree_add_item(ext_tree, hf_h224_end_octet, tvb, offset, 1, ENC_NA);
                        offset++;
                    }
                }
                static int* const fecc_caps_ability[] = {
                        &hf_h224_pan_cap,
                        &hf_h224_tilt_cap,
                        &hf_h224_zoom_cap,
                        &hf_h224_focus_cap,
                        &hf_h224_vs_reserved_b3b0,
                        NULL
                };
                proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, fecc_caps_ability, ENC_BIG_ENDIAN);
                offset++;
            }
            break;
        case CME_MSG_Extra_Capabilities_Command:
            proto_tree_add_item(ext_tree, hf_h224_extra_caps_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_response_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_ex_caps_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            oct = tvb_get_uint8(tvb, offset);
            offset = dissect_h224_standard_clients_ids(tvb, ext_tree, offset, oct);
            break;
        default:
            break;
    }
    return offset;
}

static unsigned
dissect_h224_fecc_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset)
{
    uint8_t oct;
    proto_tree *ext_tree;

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_h224, NULL,
                                      val_to_str_ext_const(H224_FECC_CLIENT_ID, &h224_client_data_ext, "Unknown field"));
    oct = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ext_tree, hf_h224_command_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    static int* const fecc_message_action[] = {
            &hf_h224_message_pan,
            &hf_h224_message_pan_dir,
            &hf_h224_message_tilt,
            &hf_h224_message_tilt_dir,
            &hf_h224_message_zoom,
            &hf_h224_message_zoom_dir,
            &hf_h224_message_focus,
            &hf_h224_message_focus_dir,
            NULL
    };
    switch(oct) {
        case FECC_MSG_START_ACTION_REQ:
        {
            uint16_t timeout;
            proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, fecc_message_action, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(ext_tree, hf_h224_message_reserved_b7b4, tvb, offset, 1, ENC_BIG_ENDIAN);
            oct = tvb_get_uint8(tvb, offset);
            timeout = (oct & 0x0f) ? (oct * TIMEOUT_INTERVALS) : MAX_TIMEOUT_VALUE;
            proto_tree_add_uint_format(ext_tree, hf_h224_message_timeout, tvb, offset, 1, oct,"%u (%u milliseconds)", oct, timeout);
            offset++;
            break;
        }
        case FECC_MSG_CONTINUE_ACTION_REQ:
        case FECC_MSG_STOP_ACTION_REQ:
            proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, fecc_message_action, ENC_BIG_ENDIAN);
            offset++;
            break;
        case FECC_MSG_SELECT_VIDEO_SOURCE_REQ:
        case FECC_MSG_VIDEO_SOURCE_SWITCHED_IND:
        {
            static int* const fecc_message_m1m0[] = {
                    &hf_h224_vs_id,
                    &hf_h224_message_reserved_b3b2,
                    &hf_h224_message_vs_m1,
                    &hf_h224_message_vs_m0,
                    NULL
            };
            proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, fecc_message_m1m0, ENC_BIG_ENDIAN);
            offset++;
            break;
        }
        case FECC_MSG_STORE_AS_PRESET_REQ:
        case FECC_MSG_ACTIVATE_PRESET_REQ:
        {
            static int* const fecc_message_preset_num[] = {
                    &hf_h224_message_preset_number,
                    &hf_h224_message_reserved_b3b0,
                    NULL
            };
            proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, fecc_message_preset_num, ENC_BIG_ENDIAN);
            offset++;
            break;
        }
        default:
            break;
    }
    return offset;
}

static unsigned dissect_h224_extended_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset) {
    proto_tree *ext_tree;

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_h224, NULL,
                                      val_to_str_ext_const(H224_EXTENED_CLIENT_ID, &h224_client_data_ext, "Unknown field"));
    proto_tree_add_item(ext_tree, hf_h224_other_client_data, tvb, offset, -1, ENC_NA);
    offset++;
    return offset;
}

static unsigned dissect_h224_non_standard_client_data(tvbuff_t* tvb, proto_tree* tree, unsigned offset) {
    proto_tree *ext_tree;

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_h224, NULL,
                                      val_to_str_ext_const(H224_NON_STANDARD_CLIENT_ID, &h224_client_data_ext, "Unknown field"));
    proto_tree_add_item(ext_tree, hf_h224_other_client_data, tvb, offset, -1, ENC_NA);
    offset++;
    return offset;
}
/* Code to actually dissect the packets */
static int
dissect_h224(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* h224_tree;
    unsigned    offset = 0;
    uint8_t oct;


    /* Set the Protocol column in the summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.224");

    ti = proto_tree_add_item(tree, proto_h224, tvb, offset, -1, ENC_NA);
    h224_tree = proto_item_add_subtree(ti, ett_h224);

    /* On IP transport networks, the H.224 protocol octet structure shall be the same as Figure 2/H.224
     * except that the HDLC bit stuffing, HDLC flags and HDLC Frame Check Sequence shall be omitted.
     */
     /* The 10-bit DLCI address for data priority */
    proto_tree_add_item(h224_tree, hf_h224_q922_dlci_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
     /* Q.922 UI-Mode format 1 octets */
    proto_tree_add_item(h224_tree, hf_h224_q922_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
     /* Destination terminal address 2 octets */
    proto_tree_add_item(h224_tree, hf_h224_dta, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
     /* Source terminal address 2 octets */
    proto_tree_add_item(h224_tree, hf_h224_sta, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(h224_tree, hf_h224_reserved, tvb, offset, 1, ENC_NA);

    /*
    * CLIENT ID: The client to receive the contents of the datagram. The Client ID may be any
    * of the following formats:
    * - Standard Client ID – Single octet.
    * - Extended Client ID – Two octets (0x7E, extended Client ID).
    * - Non-standard Client ID – Six octets (0x7F, country, manufacturer code, ID)
    */
    oct = tvb_get_uint8(tvb, offset);
    offset = dissect_h224_standard_clients_ids(tvb, h224_tree, offset, oct);

    static int* const h224_flags[] = {
    &hf_h224_es_b7,
    &hf_h224_bs_b6,
    &hf_h224_c1_b5,
    &hf_h224_c2_b4,
    &hf_h224_seg_b3b0,
    NULL
    };

    proto_tree_add_bitmask_list(h224_tree, tvb, offset, 1, h224_flags, ENC_BIG_ENDIAN);
    offset++;

    /* Data */
    int i = -1;
    while (h224opt[++i].decode) {
        if (h224opt[i].optcode == oct) {
            h224opt[i].decode(tvb, h224_tree, offset);
            break;
        }
    }
    return tvb_reported_length(tvb);
}

/* Register the protocol with Wireshark. */
void
proto_register_h224(void)
{
    //module_t        *h224_module;
    //expert_module_t *expert_h224;

    static hf_register_info hf[] = {
        { &hf_h224_q922_dlci_priority,
          { "Q.922 DLCI Priority", "h224.q922_dlci_pri",
            FT_UINT16, BASE_HEX, VALS(h224_data_priority), H224_DATA_PRI_MASK,
            NULL, HFILL }
        },
        { &hf_h224_q922_ctl,
          { "Q.922 Control Octet", "h224.q922_ctl",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_dta,
          { "Destination Terminal Address", "h224.dta",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_sta,
          { "Source Terminal Address", "h224.sta",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_reserved,
          { "Reserved", "h224.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_h224_standard_client_id,
          { "Standard Client ID", "h224.standard_client_id",
            FT_UINT8, BASE_HEX, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_h224_extended_client_id_list,
          { "Extended Client ID List", "h224.extended_client_id_list",
            FT_UINT8, BASE_HEX, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_h224_non_standard_client,
          { "Non-standard Client", "h224.non_standard_client",
            FT_UINT8, BASE_HEX, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_h224_extended_client_id,
          { "Extended Client ID", "h224.extended_client_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_country_code,
          { "Country code", "h224.country_code",
            FT_UINT8, BASE_HEX, VALS(T35CountryCode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_h224_extension,
          { "Extension", "h224.Extension",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_manufacturer_code,
          { "Manufacturer code", "h224.manufacturer_code",
            FT_UINT32, BASE_HEX, VALS(H221ManufacturerCode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_h224_client_id_manufacturer,
          { "Manufacturer Client ID", "h224.manufacturer_client_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_es_b7,
        { "Ending Segment(ES)",   "h224.flag.es",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_h224_bs_b6,
        { "Beginning Segment(BS)",   "h224.flag.bs",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_h224_c1_b5,
        { "C1",   "h224.flag.c1",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_h224_c2_b4,
        { "C0",   "h224.flag.c0",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_h224_seg_b3b0,
          { "Segment number", "h224.flags_seg",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_h224_client_list_code,
          { "Client List code", "h224.client_list_code",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_extra_caps_code,
          { "Extra Capabilities code", "h224.ex_caps_code",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_response_code,
          { "Response Code", "h224.response_code",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_number_of_clients,
          { "Number of clients", "h224.number_of_clients",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_h224_ex_caps_bit,
          { "Extra Capabilities bit", "h224.ex_caps_bit",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_h224_caps_reserved,
          { "Preset reserved", "h224.preset_reserved",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_h224_brd_svs,
          { "Broadcast switch video sources", "h224.brd_svs",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_h224_number_of_presets,
          { "Number of presets", "h224.number_of_presets",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_h224_vs_id,
          { "Video source id", "h224.vs_id",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_h224_vs_reserved_b3,
          { "Reserved type", "h224.reserved_type",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_h224_vs_reserved_b3b0,
          { "Reserved Capabilities", "h224.reserved_caps",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_h224_motion_video,
          { "Motion video", "h224.motion_video",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_h224_norm_res_si,
          { "Normal resolution still image", "h224.norm_res_si",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_h224_dbl_res_si,
          { "Double resolution still image", "h224.dbl_res_si",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_h224_pan_cap,
          { "Pan Capability", "h224.pan_cap",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_h224_tilt_cap,
          { "Tilt Capability", "h224.tilt_cap",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_h224_zoom_cap,
          { "Zoom Capability", "h224.zoom_cap",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_h224_focus_cap,
          { "Focus Capability", "h224.focus_cap",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_h224_encoded_characters,
          { "Ascii String", "h224.ascii_str",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_h224_end_octet,
          { "End octet", "h224.end_oct",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_h224_command_code,
          { "FECC Message Code", "h224.fecc_message_code",
            FT_UINT8, BASE_HEX, VALS(h224_fecc_message_type), 0,
            NULL, HFILL }
        },
        { &hf_h224_message_pan,
          { "Pan action", "h224.pan_action",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_h224_message_pan_dir,
          { "Pan direction", "h224.pan_dir",
            FT_BOOLEAN, 8, TFS(&tfs_right_left), 0x40,
            NULL, HFILL }
        },
        { &hf_h224_message_tilt,
          { "Tilt action", "h224.tilt_action",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_h224_message_tilt_dir,
          { "Tilt direction", "h224.tilt_dir",
            FT_BOOLEAN, 8, TFS(&tfs_up_down), 0x10,
            NULL, HFILL }
        },
        { &hf_h224_message_zoom,
          { "Zoom action", "h224.zoom_action",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_h224_message_zoom_dir,
          { "Zoom direction", "h224.zoom_dir",
            FT_BOOLEAN, 8, TFS(&tfs_in_out), 0x04,
            NULL, HFILL }
        },
        { &hf_h224_message_focus,
          { "Focus action", "h224.focus_action",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_h224_message_focus_dir,
          { "Focus direction", "h224.focus_dir",
            FT_BOOLEAN, 8, TFS(&tfs_in_out), 0x01,
            NULL, HFILL }
        },
        { &hf_h224_message_reserved_b7b4,
          { "Action Reserved", "h224.act_reserved",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_h224_message_reserved_b3b2,
          { "Mode Reserved", "h224.mode_reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0c,
            NULL, HFILL }
        },
        { &hf_h224_message_reserved_b3b0,
          { "Activate Preset Reserved", "h224.ap_reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_h224_message_vs_m1,
          { "M1", "h224.vs_m1",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_h224_message_vs_m0,
          { "M0", "h224.vs_m0",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_h224_message_timeout,
          { "Timeout", "h224.timeout",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_h224_message_preset_number,
          { "Preset Number", "h224.preset_number",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_h224_other_client_data,
          { "Client data", "h224.client_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };
    static int *ett[] = {
        &ett_h224
    };

    /* Setup protocol expert items */
    //static ei_register_info ei[] = {
    //    { &ei_h224_EXPERTABBREV,
    //      { "h224.EXPERTABBREV", PI_GROUP, PI_SEVERITY,
    //        "EXPERTDESCR", EXPFILL }
    //    }
    //};

    /* Register the protocol name and description */
    proto_h224 = proto_register_protocol("H.224", "H.224", "h224");

    /* Register the header fields and subtrees */
    proto_register_field_array(proto_h224, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register expert items */
//    expert_h224 = expert_register_protocol(proto_h224);
//    expert_register_field_array(expert_h224, ei, array_length(ei));

    h224_handle = register_dissector("h224", dissect_h224, proto_h224);


}

void
proto_reg_handoff_h224(void)
{
    dissector_add_string("rtp_dyn_payload_type", "H224", h224_handle);
    dissector_add_for_decode_as("rtp.pt", h224_handle);
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
