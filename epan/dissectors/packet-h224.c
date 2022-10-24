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
//#include <epan/expert.h>
//#include <epan/prefs.h>

/* Prototypes */
void proto_reg_handoff_h224(void);
void proto_register_h224(void);

/* Initialize the protocol and registered fields */
static int proto_h224 = -1;
static int hf_h224_dta = -1;
static int hf_h224_sta = -1;
static int hf_h224_reserved = -1;
static int hf_h224_standard_client_id = -1;
static int hf_h224_extended_client_id = -1;
static int hf_h224_client_id_country = -1;
static int hf_h224_client_id_manufacturer = -1;

static int hf_h224_es_b7 = -1;
static int hf_h224_bs_b6 = -1;
static int hf_h224_c1_b5 = -1;
static int hf_h224_c2_b4 = -1;
static int hf_h224_seg_b3b0 = -1;

static int hf_h224_client_data = -1;

//static expert_field ei_h224_EXPERTABBREV = EI_INIT;

static dissector_handle_t h224_handle;

/* Initialize the subtree pointers */
static gint ett_h224 = -1;

/* Code to actually dissect the packets */
static int
dissect_h224(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* ti;
    proto_tree* h224_tree;
    guint       offset = 0;
    guint8 oct;


    /* Set the Protocol column in the summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.224");

    ti = proto_tree_add_item(tree, proto_h224, tvb, offset, -1, ENC_NA);
    h224_tree = proto_item_add_subtree(ti, ett_h224);

    /* On IP transport networks, the H.224 protocol octet structure shall be the same as Figure 2/H.224
     * except that the HDLC bit stuffing, HDLC flags and HDLC Frame Check Sequence shall be omitted.
     */
     /* Destination terminal address 2 octets */
    proto_tree_add_item(h224_tree, hf_h224_dta, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
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
    oct = tvb_get_guint8(tvb, offset);
    if (oct == 0x7e) {
        proto_tree_add_item(h224_tree, hf_h224_extended_client_id, tvb, offset, 2, ENC_NA);
        offset += 2;
    } else if (oct == 0x7f){
        proto_tree_add_item(h224_tree, hf_h224_client_id_country, tvb, offset, 2, ENC_NA);
        offset += 2;
        proto_tree_add_item(h224_tree, hf_h224_client_id_manufacturer, tvb, offset, 2, ENC_NA);
        offset += 2;
        proto_tree_add_item(h224_tree, hf_h224_extended_client_id, tvb, offset, 2, ENC_NA);
        offset += 2;
    } else {
        proto_tree_add_item(h224_tree, hf_h224_standard_client_id, tvb, offset, 1, ENC_NA);
        offset++;
    }

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
    proto_tree_add_item(h224_tree, hf_h224_client_data, tvb, offset, -1, ENC_NA);

    return tvb_reported_length(tvb);
}

/* Register the protocol with Wireshark. */
void
proto_register_h224(void)
{
    //module_t        *h224_module;
    //expert_module_t *expert_h224;

    static hf_register_info hf[] = {
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
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_h224_extended_client_id,
          { "Extended Client ID", "h224.standard_client_id",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_h224_client_id_country,
          { "Client ID country", "h224.standard_client_id_country",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_h224_client_id_manufacturer,
          { "Manufacturer Client ID", "h224.manufacturer_client_id",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
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
        { &hf_h224_client_data,
            { "Client data",           "h224.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };
    static gint *ett[] = {
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
