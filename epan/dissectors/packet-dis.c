/* packet-dis.c
 * Routines for Distributed Interactive Simulation packet
 * disassembly (IEEE-1278).
 * Copyright 2005, Scientific Research Corporation
 * Initial implementation by Jeremy Ouellette <jouellet@scires.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* TODO / NOTES:
 * Field handling isn't ideal; this dissector should probably register
 * each individual field via the proto_register_field_array mechanism.
 * This would lead to better PDML output (instead of requiring the end user
 * to manually parse out the key/value pairs) and better searchability in
 * interactive mode.
 *
 * Lots more PDUs to implement.  Only the basic engagement events are currently
 * handled (Fire, Detonation, Entity State).  Most of the basic field types are
 * complete, however, so declaring new PDUs should be fairly simple.
 *
 * Lots more enumerations to implement.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-dis-enums.h"
#include "packet-dis-pdus.h"
#include "packet-dis-fields.h"

#define DEFAULT_DIS_UDP_PORT 3000

/* Encoding type the last 14 bits */
#define DIS_ENCODING_TYPE(word) ((word) & 0x3FFF)


static gint proto_dis = -1;
int hf_dis_proto_ver = -1;
int hf_dis_exercise_id = -1;
int hf_dis_pdu_type = -1;
int hf_dis_proto_fam = -1;
int hf_dis_pdu_length = -1;
int hf_dis_entity_id_site = -1;
int hf_dis_entity_id_application = -1;
int hf_dis_entity_id_entity = -1;
int hf_dis_num_art_params = -1;
int hf_dis_entityKind = -1;
int hf_dis_entityDomain = -1;
int hf_dis_category_land = -1;
int hf_dis_category_air = -1;
int hf_dis_category_surface = -1;
int hf_dis_category_subsurface = -1;
int hf_dis_category_space = -1;
int hf_dis_category_radio = -1;
int hf_dis_num_electromagnetic_emission_systems = -1;
int hf_dis_emitter_name = -1;
int hf_dis_emission_function = -1;
int hf_dis_beam_function = -1;
int hf_dis_radio_id = -1;
int hf_dis_ens = -1;
int hf_dis_ens_class = -1;
int hf_dis_ens_type = -1;
int hf_dis_tdl_type = -1;
int hf_dis_sample_rate = -1;
int hf_dis_data_length = -1;
int hf_dis_num_of_samples = -1;
int hf_dis_signal_data = -1;
int hf_dis_radio_category = -1;
int hf_dis_nomenclature_version = -1;
int hf_dis_nomenclature = -1;
int hf_dis_radio_transmit_state = -1;
int hf_dis_radio_input_source = -1;
int hf_dis_antenna_pattern_type = -1;
int hf_dis_antenna_pattern_length = -1;
int hf_dis_transmit_frequency = -1;
int hf_dis_spread_spectrum_usage = -1;
int hf_dis_frequency_hopping = -1;
int hf_dis_pseudo_noise_modulation = -1;
int hf_dis_time_hopping = -1;
int hf_dis_modulation_major = -1;
int hf_dis_modulation_system = -1;
int hf_dis_crypto_system = -1;
int hf_dis_crypto_key = -1;
int hf_dis_encryption_mode = -1;
int hf_dis_key_identifier = -1;
int hf_dis_modulation_parameter_length = -1;
int hf_dis_mod_param_fh_net_id = -1;
int hf_dis_mod_param_fh_set_id = -1;
int hf_dis_mod_param_fh_lo_set_id = -1;
int hf_dis_mod_param_fh_msg_start = -1;
int hf_dis_mod_param_fh_reserved = -1;
int hf_dis_mod_param_fh_sync_time_offset = -1;
int hf_dis_mod_param_fh_security_key = -1;
int hf_dis_mod_param_fh_clear_channel = -1;
int hf_dis_mod_param_dump = -1;
int hf_dis_mod_param_ts_allocation_mode = -1;
int hf_dis_mod_param_transmitter_prim_mode = -1;
int hf_dis_mod_param_transmitter_second_mode = -1;
int hf_dis_mod_param_sync_state = -1;
int hf_dis_mod_param_network_sync_id = -1;
int hf_dis_antenna_pattern_parameter_dump = -1;

/* Initialize the subtree pointers */
static gint ett_dis = -1;
static gint ett_dis_header = -1;
static gint ett_dis_po_header = -1;
static gint ett_dis_payload = -1;
int ett_dis_ens = -1;
int ett_dis_crypto_key = -1;

static const true_false_string dis_modulation_spread_spectrum = {
    "Spread Spectrum modulation in use",
    "Spread Spectrum modulation not in use"
};

static const true_false_string dis_frequency_hopping_value = {
    "Frequency hopping modulation used",
    "Frequency hopping modulation not used"
};

static const true_false_string dis_encryption_mode_value = {
    "diphase encryption mode",
    "baseband encryption mode"
};

static const true_false_string dis_pseudo_noise_value = {
    "Pseudo Noise modulation used",
    "Pseudo Noise modulation not used"
};

static const true_false_string dis_time_hopping_value = {
    "Time hopping modulation used",
    "Time hopping modulation not used"
};

static guint dis_udp_port = DEFAULT_DIS_UDP_PORT;

static const char* dis_proto_name = "Distributed Interactive Simulation";
static const char* dis_proto_name_short = "DIS";

/* Main dissector routine to be invoked for a DIS PDU.
 */
static gint dissect_dis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *dis_tree = 0;
    proto_item *dis_node = 0;
    proto_item *dis_header_tree = 0;
    proto_item *dis_header_node = 0;
    proto_item *dis_payload_tree = 0;
    proto_item *dis_payload_node = 0;
    gint offset = 0;
    const gchar *pduString = 0;
    DIS_ParserNode *pduParser = 0;

    /* DIS packets must be at least 12 bytes long.  DIS uses port 3000, by
     * default, but the Cisco Redundant Link Management protocol can also use
     * that port; RLM packets are 8 bytes long, so we use this to distinguish
     * between them.
     */
    if (tvb_reported_length(tvb) < 12)
    {
        return 0;
    }

    /* Reset the global PDU type variable -- this will be parsed as part of
     * the DIS header.
     */
    pduType = DIS_PDUTYPE_OTHER;
    protocolFamily = DIS_PROTOCOLFAMILY_OTHER;
    persistentObjectPduType = DIS_PERSISTENT_OBJECT_TYPE_OTHER;

    /* set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, dis_proto_name_short);

    /* Add the top-level DIS node under which the rest of the fields will be
     * displayed.
     */
    dis_node = proto_tree_add_protocol_format(tree, proto_dis, tvb, offset,
        -1, "Distributed Interactive Simulation");
    dis_tree = proto_item_add_subtree(dis_node, ett_dis);

    /* Add a node to contain the DIS header fields.
     */
    dis_header_node = proto_tree_add_text(dis_tree, tvb, offset, -1, "Header");
    dis_header_tree = proto_item_add_subtree(dis_header_node, ett_dis_header);
    offset = parseFields(tvb, dis_header_tree, offset, DIS_FIELDS_PDU_HEADER);

    proto_item_set_end(dis_header_node, tvb, offset);

    /* Locate the string name for the PDU type enumeration,
     * or default to "Unknown".
    */
    pduString = val_to_str(pduType, DIS_PDU_Type_Strings, "Unknown");

    /* Locate the appropriate PDU parser, if type is known.
     */
    switch (protocolFamily)
    {
    case DIS_PROTOCOLFAMILY_PERSISTENT_OBJECT:
        {
            proto_item *dis_po_header_tree = 0;
            proto_item *dis_po_header_node = 0;

            dis_po_header_node = proto_tree_add_text
                (dis_header_tree, tvb, offset, -1, "PO Header");
            dis_po_header_tree = proto_item_add_subtree
                (dis_po_header_node, ett_dis_po_header);
            offset = parseFields
                (tvb, dis_po_header_tree, offset,
                 DIS_FIELDS_PERSISTENT_OBJECT_HEADER);
            proto_item_set_end(dis_po_header_node, tvb, offset);

            /* Locate the appropriate PO PDU parser, if type is known.
             */
            switch (persistentObjectPduType)
            {
            case DIS_PERSISTENT_OBJECT_TYPE_SIMULATOR_PRESENT:
                pduParser = DIS_PARSER_SIMULATOR_PRESENT_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_DESCRIBE_OBJECT:
                pduParser = DIS_PARSER_DESCRIBE_OBJECT_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_OBJECTS_PRESENT:
                pduParser = DIS_PARSER_OBJECTS_PRESENT_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_OBJECT_REQUEST:
                pduParser = DIS_PARSER_OBJECT_REQUEST_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_DELETE_OBJECTS:
                pduParser = DIS_PARSER_DELETE_OBJECTS_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_SET_WORLD_STATE:
                pduParser = DIS_PARSER_SET_WORLD_STATE_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_NOMINATION:
                pduParser = DIS_PARSER_NOMINATION_PO_PDU;
                break;
            default:
                pduParser = 0;
                break;
            }

            /* Locate the string name for the PO PDU type enumeration,
             * or default to "Unknown".
             */
            pduString = val_to_str
                (persistentObjectPduType,
                 DIS_PDU_PersistentObjectType_Strings, "Unknown");

            /* Add a node to contain the DIS PDU fields.
             */
            dis_payload_node = proto_tree_add_text(dis_tree, tvb, offset, -1,
                "%s PO PDU", pduString);

        }
        break;
    default:

        /* Add a node to contain the DIS PDU fields.
         */
        dis_payload_node = proto_tree_add_text(dis_tree, tvb, offset, -1,
            "%s PDU", pduString);

        switch (pduType)
        {
        /* DIS Entity Information / Interaction PDUs */
        case DIS_PDUTYPE_ENTITY_STATE:
            pduParser = DIS_PARSER_ENTITY_STATE_PDU;
            break;

        /* DIS Distributed Emission Regeneration PDUs */
        case DIS_PDUTYPE_ELECTROMAGNETIC_EMISSION:
            pduParser = DIS_PARSER_ELECTROMAGNETIC_EMISSION_PDU;
            break;

        /* DIS Radio Communications protocol (RCP) family PDUs */
        case DIS_PDUTYPE_TRANSMITTER:
            pduParser = DIS_PARSER_TRANSMITTER_PDU;
            break;
        case DIS_PDUTYPE_SIGNAL:
            pduParser = DIS_PARSER_SIGNAL_PDU;
            break;

        /* DIS Warfare PDUs */
        case DIS_PDUTYPE_FIRE:
            pduParser = DIS_PARSER_FIRE_PDU;
            break;
        case DIS_PDUTYPE_DETONATION:
            if ( disProtocolVersion < DIS_VERSION_IEEE_1278_1_200X )
            {
                pduParser = DIS_PARSER_DETONATION_PDU;
            }
            else
            {
                /* TODO: Version 7 changed the Detonation PDU format
                 *       Need a different parser
                 */
                pduParser = DIS_PARSER_DETONATION_PDU;
            }
            break;

        /* DIS Simulation Management PDUs */
        case DIS_PDUTYPE_START_RESUME:
            pduParser = DIS_PARSER_START_RESUME_PDU;
            break;
        case DIS_PDUTYPE_STOP_FREEZE:
            pduParser = DIS_PARSER_STOP_FREEZE_PDU;
            break;
        case DIS_PDUTYPE_ACKNOWLEDGE:
            pduParser = DIS_PARSER_ACKNOWLEDGE_PDU;
            break;
        case DIS_PDUTYPE_ACTION_REQUEST:
            pduParser = DIS_PARSER_ACTION_REQUEST_PDU;
            break;
        case DIS_PDUTYPE_ACTION_RESPONSE:
            pduParser = DIS_PARSER_ACTION_RESPONSE_PDU;
            break;
        case DIS_PDUTYPE_DATA:
        case DIS_PDUTYPE_SET_DATA:
            pduParser = DIS_PARSER_DATA_PDU;
            break;
        case DIS_PDUTYPE_DATA_QUERY:
            pduParser = DIS_PARSER_DATA_QUERY_PDU;
            break;
        case DIS_PDUTYPE_COMMENT:
            pduParser = DIS_PARSER_COMMENT_PDU;
            break;
        case DIS_PDUTYPE_CREATE_ENTITY:
        case DIS_PDUTYPE_REMOVE_ENTITY:
            pduParser = DIS_PARSER_SIMAN_ENTITY_PDU;
            break;

        /* DIS Simulation Management with Reliability PDUs */
        case DIS_PDUTYPE_START_RESUME_R:
            pduParser = DIS_PARSER_START_RESUME_R_PDU;
            break;
        case DIS_PDUTYPE_STOP_FREEZE_R:
            pduParser = DIS_PARSER_STOP_FREEZE_R_PDU;
            break;
        case DIS_PDUTYPE_ACKNOWLEDGE_R:
            pduParser = DIS_PARSER_ACKNOWLEDGE_PDU;
            break;
        case DIS_PDUTYPE_ACTION_REQUEST_R:
            pduParser = DIS_PARSER_ACTION_REQUEST_R_PDU;
            break;
        case DIS_PDUTYPE_ACTION_RESPONSE_R:
            pduParser = DIS_PARSER_ACTION_RESPONSE_PDU;
            break;
        case DIS_PDUTYPE_DATA_R:
        case DIS_PDUTYPE_SET_DATA_R:
            pduParser = DIS_PARSER_DATA_R_PDU;
            break;
        case DIS_PDUTYPE_DATA_QUERY_R:
            pduParser = DIS_PARSER_DATA_QUERY_R_PDU;
            break;
        case DIS_PDUTYPE_COMMENT_R:
            pduParser = DIS_PARSER_COMMENT_PDU;
            break;
        case DIS_PDUTYPE_CREATE_ENTITY_R:
        case DIS_PDUTYPE_REMOVE_ENTITY_R:
            pduParser = DIS_PARSER_SIMAN_ENTITY_R_PDU;
            break;

        /* DIS Experimental V-DIS PDUs */
        case DIS_PDUTYPE_APPLICATION_CONTROL:
            pduParser = DIS_PARSER_APPLICATION_CONTROL_PDU;
            break;

        default:
            pduParser = 0;
            break;
        }
        break;
    }

    /* If a parser was located, invoke it on the data packet.
     */
    if (pduParser != 0)
    {
        dis_payload_tree = proto_item_add_subtree(dis_payload_node,
            ett_dis_payload);
        offset = parseFields(tvb, dis_payload_tree, offset, pduParser);

        proto_item_set_end(dis_payload_node, tvb, offset);
    }

    /* Add detail to the INFO column */
    switch (pduType)
    {
    /* DIS Entity Information / Interaction PDUs */
    case DIS_PDUTYPE_ENTITY_STATE:
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "PDUType: %s, %s, %s",
                      pduString,
                      val_to_str(entityKind, DIS_PDU_EntityKind_Strings, "Unknown Entity Kind"),
                      val_to_str(entityDomain, DIS_PDU_Domain_Strings, "Unknown Entity Domain")
                     );
        break;

    case DIS_PDUTYPE_SIGNAL:
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "PDUType: %s, RadioID=%u, Encoding Type=%s, Number of Samples=%u",
                      pduString,
                      radioID,
                      val_to_str(DIS_ENCODING_TYPE(encodingScheme), DIS_PDU_Encoding_Type_Strings, "Unknown Encoding Type"),
                      numSamples
                      );
        break;
    case DIS_PDUTYPE_TRANSMITTER:
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "PDUType: %s, RadioID=%u, Transmit State=%s",
                      pduString,
                      radioID,
                      val_to_str(disRadioTransmitState, DIS_PDU_RadioTransmitState_Strings, "Unknown Transmit State")
                      );
        break;
    default:
        /* set the basic info column (pdu type) */
        col_add_fstr( pinfo->cinfo, COL_INFO,
                     "PDUType: %s",
                      pduString);
        break;
    }

    return tvb_length(tvb);
}

/* Registration routine for the DIS protocol.
 */
void proto_reg_handoff_dis(void);

void proto_register_dis(void)
{

/* registration with the filtering engine */
    static hf_register_info hf[] =
        {
            { &hf_dis_proto_ver,
              { "Proto version",      "dis.proto_ver",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ProtocolVersion_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_exercise_id,
              { "Excercise ID",       "dis.exer_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_pdu_type,
              { "PDU type",           "dis.pdu_type",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Type_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_proto_fam,
              { "Proto Family",       "dis.proto_fam",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ProtocolFamily_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_pdu_length,
              { "PDU Length",         "dis.pdu_length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entity_id_site,
              { "Entity ID Site",     "dis.entity_id_site",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entity_id_application,
              { "Entity ID Application", "dis.entity_id_application",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entity_id_entity,
              { "Entity ID Entity",       "dis.entity_id_entity",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_art_params,
              { "Number of Articulation Parameters",  "dis.num_articulation_params",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entityKind,
              { "Kind",       "dis.entityKind",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_EntityKind_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entityDomain,
              { "Domain",       "dis.entityDomain",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Domain_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_land,
              { "Category / Land",       "dis.category.land",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_LandPlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_air,
              { "Category / Air",       "dis.category.air",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_AirPlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_surface,
              { "Category / Surface",       "dis.category.surface",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_SurfacePlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_subsurface,
              { "Category / Subsurface",       "dis.category.subsurface",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_SubsurfacePlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_space,
              { "Category / Space",       "dis.category.space",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_SpacePlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_radio,
              { "Category / Radio",       "dis.category.radio",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioCategory_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_emitter_name,
              { "Emitter Name", "dis.electromagnetic.emitter.name",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_EmitterName_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_emission_function,
              { "Emission Function", "dis.electromagnetic.emission.function",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_EmissionFunction_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_beam_function,
              { "Beam Function", "dis.electromagnetic.emission.beam.function",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_BeamFunction_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_electromagnetic_emission_systems,
              { "Number of Electromagnetic Emission Systems",  "dis.electromagnetic.num_emission_systems",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_radio_id,
              { "Radio ID",  "dis.radio.radio_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_ens,
              { "Encoding Scheme",  "dis.radio.encoding_scheme",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_ens_class,
              { "Encoding Class",  "dis.radio.encoding_class",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_Encoding_Class_Strings), 0xc000,
                NULL, HFILL }
            },
            { &hf_dis_ens_type,
              { "Encoding Type", "dis.radio.encoding_type",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_Encoding_Type_Strings), 0x3fff,
                NULL, HFILL }
            },
            { &hf_dis_tdl_type,
              { "TDL Type", "dis.radio.tdl_type",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_TDL_Type_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_sample_rate,
              { "Sample Rate", "dis.radio.sample_rate",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_data_length,
              { "Data Length", "dis.radio.data_length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_of_samples,
              { "Number of Samples", "dis.radio.num_of_samples",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_signal_data,
              {"Data", "dis.radio.signal_data",
               FT_BYTES,        BASE_NONE, NULL, 0x0,
               NULL, HFILL}
            },
            { &hf_dis_radio_category,
              { "Radio Category", "dis.radio.radio_category",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioCategory_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_nomenclature_version,
              { "Nomenclature Version", "dis.radio.nomenclature_version",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_NomenclatureVersion_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_nomenclature,
              { "Nomenclature", "dis.radio.nomenclature",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_Nomenclature_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_radio_transmit_state,
              { "Radio Transmit State", "dis.radio.transmit_state",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioTransmitState_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_radio_input_source,
              { "Radio Input Source", "dis.radio.input_source",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioInputSource_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_antenna_pattern_type,
              { "Antenna Pattern Type", "dis.radio.antenna_pattern_type",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_AntennaPatternType_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_antenna_pattern_length,
              { "Antenna Pattern Length", "dis.radio.antenna_pattern_length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_transmit_frequency,
              { "Transmit Frequency (Hz)", "dis.radio.frequency",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_spread_spectrum_usage,
              { "Spread Spectrum", "dis.radio.mod_type.spread_spectrum_usage",
                FT_BOOLEAN, 16, TFS(&dis_modulation_spread_spectrum),0xFFFF,
                NULL, HFILL }
            },
            { &hf_dis_frequency_hopping,
              { "Frequency Hopping modulation", "dis.radio.mod_type.frequency_hopping",
                FT_BOOLEAN, 16, TFS(&dis_frequency_hopping_value),0x0001,
                NULL, HFILL }
            },
            { &hf_dis_pseudo_noise_modulation,
              { "Psuedo noise modulation",  "dis.radio.mod_type.pseudo_noise_modulation",
                FT_BOOLEAN, 16, TFS(&dis_pseudo_noise_value),0x0002,
                NULL, HFILL }
            },
            { &hf_dis_time_hopping,
              { "Time Hopping modulation",  "dis.radio.mod_type.time_hopping",
                FT_BOOLEAN, 16, TFS(&dis_time_hopping_value),0x0004,
                NULL, HFILL }
            },
            { &hf_dis_modulation_major,
              { "Major Modulation", "dis.radio.mod_type.major",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_MajorModulation_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_modulation_system,
              { "System Modulation", "dis.radio.mod_type.system",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_SystemModulation_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_crypto_system,
              { "Crypto System", "dis.radio.crypto_system",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_CryptoSystem_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_crypto_key,
              { "Encryption Key",  "dis.radio.encryption_key",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_encryption_mode,
              { "Encryption Mode",  "dis.radio.encryption_key.mode",
                FT_BOOLEAN, 16, TFS(&dis_encryption_mode_value),0x8000,
                NULL, HFILL }
            },
            { &hf_dis_key_identifier,
              { "Encryption Key ID",  "dis.radio.encryption_key.id",
                FT_UINT16, BASE_DEC, NULL,0x7FFF,
                NULL, HFILL }
            },
            { &hf_dis_modulation_parameter_length,
              { "Modulation Parameter Length", "dis.radio.mod_param.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_net_id,
              { "Frequency Hopping Network ID", "dis.radio.mod_param.cctt_cingars.fh_nw_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_set_id,
              { "Frequency Set ID", "dis.radio.mod_param.cctt_cingars.fh_set_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_lo_set_id,
              { "Frequency Lockout Set ID", "dis.radio.mod_param.cctt_cingars.fh_lo_set_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_msg_start,
              { "Start of Message", "dis.radio.mod_param.cctt_cingars.fh_msg_start",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ModParamMsgStart_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_reserved,
              { "Reserved", "dis.radio.mod_param.cctt_cingars.fh_reserved",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_sync_time_offset,
              { "Sync Time Offset (Seconds)", "dis.radio.mod_param.cctt_cingars.fh_sync_offset",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_security_key,
              { "Transmission Security Key", "dis.radio.mod_param.cctt_cingars.fh_securit_key",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_clear_channel,
              { "Clear Channel", "dis.radio.mod_param.cctt_cingars.fh_clr_channel",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ModParamClrChannel_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_dump,
              {"Modulation Parameter All", "dis.radio.mod_param.all",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL}
            },
            { &hf_dis_mod_param_ts_allocation_mode,
              { "Time Slot Allocaton Mode", "dis.radio.mod_param.jtids.ts_alloc_mode",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_TSAllocationFidelity_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_transmitter_prim_mode,
              { "Transmitter Primary Mode", "dis.radio.mod_param.jtids.transmitter_primary_mode",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_TerminalPrimaryMode_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_transmitter_second_mode,
              { "Transmitter Primary Mode", "dis.radio.mod_param.jtids.transmitter_secondary_mode",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_TerminalSecondaryMode_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_sync_state,
              { "Synchronization State", "dis.radio.mod_param.jtids.sync_state",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ModParamSyncState_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_network_sync_id,
              { "Network Sync ID", "dis.radio.mod_param.jtids.network_sync_id",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_antenna_pattern_parameter_dump,
              {"Antenna Pattern Parameter", "dis.radio.antenna_parameter",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL}
            },
        };

    /* Setup protocol subtree array */
    static gint *ett[] =
    {
        &ett_dis,
        &ett_dis_header,
        &ett_dis_po_header,
        &ett_dis_ens,
        &ett_dis_crypto_key,
        &ett_dis_payload
    };

    module_t *dis_module;

    proto_dis = proto_register_protocol(dis_proto_name, dis_proto_name_short, "dis");
    proto_register_field_array(proto_dis, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dis_module = prefs_register_protocol(proto_dis, proto_reg_handoff_dis);

    /* Create an unsigned integer preference to allow the user to specify the
     * UDP port on which to capture DIS packets.
     */
    prefs_register_uint_preference(dis_module, "udp.port",
        "DIS UDP Port",
        "Set the UDP port for DIS messages",
        10, &dis_udp_port);

    /* Perform the one-time initialization of the DIS parsers.
     */
    initializeParsers();
    initializeFieldParsers();
}

/* Register handoff routine for DIS dissector.  This will be invoked initially
 * and when the preferences are changed, to handle changing the UDP port for
 * which this dissector is registered.
 */
void proto_reg_handoff_dis(void)
{
    static gboolean dis_prefs_initialized = FALSE;
    static dissector_handle_t dis_dissector_handle;
    static guint saved_dis_udp_port;

    if (!dis_prefs_initialized)
    {
        dis_dissector_handle = new_create_dissector_handle(dissect_dis, proto_dis);
        dis_prefs_initialized = TRUE;
    }
    else
    {
        dissector_delete_uint("udp.port", saved_dis_udp_port, dis_dissector_handle);
    }

    dissector_add_uint("udp.port", dis_udp_port, dis_dissector_handle);
    saved_dis_udp_port = dis_udp_port;
}

