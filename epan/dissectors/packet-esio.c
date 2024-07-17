/* packet-esio.c
 * Routines for Ether-S-I/O dissection (from Saia Burgess Controls AG )
 * Copyright 2010, Christian Durrer <christian.durrer@sensemail.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

/* Telegram types*/
#define ESIO_TRANSFER                  0x01
#define ESIO_STATUS                    0x02

void proto_register_esio(void);
void proto_reg_handoff_esio(void);

static dissector_handle_t esio_handle;

#define ESIO_UDP_PORT       6060 /* Not IANA registered */

/* Initialize the protocol and registered fields */
static int proto_esio;
static int hf_esio_type;
static int hf_esio_version;
static int hf_esio_length;
static int hf_esio_transaction_id;
static int hf_esio_tlg_id;
static int hf_esio_src_stn_id;
static int hf_esio_data_nbr;
static int hf_esio_data_flags;
static int hf_esio_data_transfer_id;
static int hf_esio_data_dest_id;
static int hf_esio_data_length;
static int hf_esio_data;
static int hf_esio_sts_type;
static int hf_esio_sts_size;
static int hf_esio_rio_sts;
static int hf_esio_rio_tlgs_lost;
static int hf_esio_rio_diag;
static int hf_esio_rio_flags;

/* Initialize the subtree pointers */
static int ett_esio;
static int ett_esio_header;
static int ett_esio_transfer_header;
static int ett_esio_transfer_data;
static int ett_esio_data;

static expert_field ei_esio_telegram_lost;

/* value to string definitions*/
/* Ether-S-I/O telegram types*/
static const value_string esio_tlg_types[] = {
       {0, "Reserved"},
       {1, "Data transfer telegram"},
       {2, "Status/Diag telegram"},
       {0, NULL}
};

/* Status telegram types*/
static const value_string esio_sts_types[] = {
       {0, "None"},
       {1, "RIO status"},
       {0, NULL}
};

/* check whether the packet looks like SBUS or not */
static bool
is_esio_pdu(tvbuff_t *tvb)
{
       /* we need at least 8 bytes to determine whether this is
          Ether-S-I/O or not*/
       /* minimal length is 20 bytes*/
       if (tvb_captured_length(tvb) < 20) {
              return false;
       }
       /* First four bytes must be "ESIO"*/
       if (tvb_strneql(tvb, 0, "ESIO", 4) != 0) {
              return false;
       }
       /* fifth byte must be 0*/
       if (tvb_get_uint8(tvb, 4) > 0x00) {
              return false;
       }
       /* sixth byte indicates telegram type and must be 0, 1 or 2*/
       if (tvb_get_uint8(tvb, 5) > 0x02) {
              return false;
       }
       /* seventh byte must be 0*/
       if (tvb_get_uint8(tvb, 6) > 0x00) {
              return false;
       }
       /* eight byte indicates telegram version and must be 0 (up to now)*/
       if (tvb_get_uint8(tvb, 7) > 0x00) {
              return false;
       }
       /*header seems to be Ether-S-I/O*/
       return true;
}

/*Dissect the telegram*/
static int
dissect_esio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
       proto_item *ti;
       proto_tree *esio_tree, *esio_header_tree, *esio_transfer_header_tree,
                  *esio_data_tansfer_tree, *esio_data_tree;

       int         i;
       int         offset;
       uint8_t     esio_nbr_data_transfers;
       uint16_t    esio_telegram_type;
       uint16_t    esio_tlg_type;
       uint16_t    esio_transfer_length;
       uint32_t    esio_transfer_dest_id;
       uint32_t    esio_src_id;
       uint32_t    esio_dst_id;

/* does this look like an sbus pdu? */
       if (!is_esio_pdu(tvb)) {
              return 0;
       }

/* Make entries in Protocol column and Info column on summary display */
       col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESIO");
       col_clear(pinfo->cinfo, COL_INFO);
       esio_telegram_type = tvb_get_uint8(tvb,5);

       switch (esio_telegram_type) {
       case ESIO_TRANSFER:
                esio_src_id = tvb_get_ntohl(tvb,16);
                esio_nbr_data_transfers = tvb_get_uint8(tvb, 20);
                esio_dst_id = tvb_get_ntohl(tvb,26);
                col_add_fstr( pinfo->cinfo, COL_INFO,
                            "Data transfer: Src ID: %d, Dst ID(s): %d",
                            esio_src_id, esio_dst_id);
                if (esio_nbr_data_transfers > 1) {
                    col_append_str( pinfo->cinfo, COL_INFO,
                                        " ...");
                }
                break;
       case ESIO_STATUS:
                esio_src_id = tvb_get_ntohl(tvb,16);
                col_add_fstr( pinfo->cinfo, COL_INFO,
                            "Status/diag telegram: Src ID: %d",
                            esio_src_id);
                break;
       default:
                /* All other telegrams */
                col_set_str( pinfo->cinfo, COL_INFO,
                            "Unknown telegram");
                break;
       }

/* create display subtree for the protocol */
       offset = 0;
       ti = proto_tree_add_item(tree, proto_esio, tvb, offset, -1, ENC_NA);
       esio_tree = proto_item_add_subtree(ti, ett_esio);
/*Add subtree for Ether-S-I/O header*/
       esio_header_tree = proto_tree_add_subtree(esio_tree, tvb, offset, 12, ett_esio_header, NULL, "Ether-S-I/O header");
       offset += 4; /*first four bytes are "ESIO"*/
/* add items to the Ether-S-I/O header subtree*/
       esio_tlg_type = tvb_get_ntohs(tvb,offset);
       proto_tree_add_item(esio_header_tree,
                           hf_esio_type, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       proto_tree_add_item(esio_header_tree,
                           hf_esio_version, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       proto_tree_add_item(esio_header_tree,
                           hf_esio_length, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       proto_tree_add_item(esio_header_tree,
                           hf_esio_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;
       switch (esio_tlg_type) {
       case ESIO_TRANSFER:
              if (tree) {
                     /*Add subtree for Ether-S-I/O header*/
                     esio_transfer_header_tree = proto_tree_add_subtree(esio_tree, tvb, offset, 12,
                                                        ett_esio_transfer_header, NULL, "Transfer header");
                     proto_tree_add_item(esio_transfer_header_tree,
                                         hf_esio_tlg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                     offset += 4;
                     proto_tree_add_item(esio_transfer_header_tree,
                                         hf_esio_src_stn_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                     offset += 4;
                     esio_nbr_data_transfers = tvb_get_uint8(tvb,offset);
                     proto_tree_add_item(esio_transfer_header_tree,
                                         hf_esio_data_nbr, tvb, offset, 1, ENC_BIG_ENDIAN);
                     offset += 1;
                     proto_tree_add_item(esio_transfer_header_tree,
                                         hf_esio_data_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                     offset += 1;
                     for (i=((esio_nbr_data_transfers)); i>0; i--) {
                            /*Add subtree(s) for Ether-S-I/O data transfers*/
                            esio_transfer_dest_id = tvb_get_ntohl(tvb,(offset+4));
                            esio_transfer_length = tvb_get_ntohs(tvb,(offset+8));
                            esio_data_tansfer_tree = proto_tree_add_subtree_format(esio_tree, tvb, offset,
                                                     (esio_transfer_length + 10), ett_esio_transfer_data, NULL,
                                                     "Data transfer to ID: %d ", esio_transfer_dest_id);

                            proto_tree_add_item(esio_data_tansfer_tree,
                                                hf_esio_data_transfer_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(esio_data_tansfer_tree,
                                                hf_esio_data_dest_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(esio_data_tansfer_tree,
                                                hf_esio_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                            /*here comes the data*/
                            esio_data_tree = proto_tree_add_subtree(esio_data_tansfer_tree, tvb, offset,
                                                     esio_transfer_length, ett_esio_data, NULL, "Data bytes ");
                            for (i=((esio_transfer_length)); i>0; i--) {
                                   proto_tree_add_item(esio_data_tree,
                                                       hf_esio_data, tvb, offset,
                                                       1, ENC_BIG_ENDIAN);
                                   offset += 1;
                            }
                     }
              } /* if (tree) */
              break;
       case ESIO_STATUS: {
              proto_item *hi = NULL;
              if (tree) {
                     proto_tree_add_item(esio_tree,
                                         hf_esio_sts_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                     proto_tree_add_item(esio_tree,
                                         hf_esio_sts_size, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                     proto_tree_add_item(esio_tree,
                                         hf_esio_src_stn_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                     proto_tree_add_item(esio_tree,
                                         hf_esio_rio_sts, tvb, offset+8,
                                         1, ENC_BIG_ENDIAN);
                     hi = proto_tree_add_item(esio_tree,
                                              hf_esio_rio_tlgs_lost, tvb, offset+9,
                                              1, ENC_BIG_ENDIAN);
                     proto_tree_add_item(esio_tree,
                                         hf_esio_rio_diag, tvb, offset+10,
                                         1, ENC_BIG_ENDIAN);
                     proto_tree_add_item(esio_tree,
                                         hf_esio_rio_flags, tvb, offset+11, 1, ENC_BIG_ENDIAN);
              } /* if (tree) */
              if (tvb_get_uint8(tvb, offset + 9) > 0) {
                     expert_add_info(pinfo, hi, &ei_esio_telegram_lost);
              }
              break;
       }
       default:
              break;
       } /* switch() */

       return tvb_captured_length(tvb);
/*End of dissect_sbus*/
}

/* Register the protocol with Wireshark */
void
proto_register_esio(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
       static hf_register_info hf[] = {
              { &hf_esio_type,
                     { "Telegram type", "esio.type",
                     FT_UINT16, BASE_HEX, VALS(esio_tlg_types), 0,
                     NULL, HFILL }
              },

              { &hf_esio_version,
                     { "Version", "esio.vers",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_length,
                     { "Length (bytes)", "esio.len",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_transaction_id,
                     { "Transaction ID", "esio.transaction_id",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_src_stn_id,
                     { "Source station ID", "esio.src_stn_id",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_tlg_id,
                     { "Telegram ID", "esio.transfer.tlg_id",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_data_nbr,
                     { "Nbr. of data transfers", "esio.data.nbr",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_data_flags,
                     { "Transfer header flags", "esio.data.flags",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_data_transfer_id,
                     { "Data transfer ID", "esio.data.transfer_id",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_data_dest_id,
                     { "Data destination ID", "esio.data.destination_id",
                     FT_UINT32, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_data_length,
                     { "Data transfer length", "esio.data.length",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_data,
                     { "Data", "esio.data",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_sts_type,
                     { "Status type", "esio.sts.type",
                     FT_UINT16, BASE_HEX, VALS(esio_sts_types), 0,
                     NULL, HFILL }
              },

              { &hf_esio_sts_size,
                     { "Status length (bytes)", "esio.sts.length",
                     FT_UINT16, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_rio_sts,
                     { "RIO status", "esio.sts.rio_sts",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_rio_tlgs_lost,
                     { "Lost telegrams to RIO", "esio.sts.rio_lost_tlg",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_rio_diag,
                     { "RIO diagnostics", "esio.sts.rio_diag",
                     FT_UINT8, BASE_DEC, NULL, 0,
                     NULL, HFILL }
              },

              { &hf_esio_rio_flags,
                     { "RIO flags", "esio.sts.rio_flags",
                     FT_UINT8, BASE_HEX, NULL, 0,
                     NULL, HFILL }
              }
       };


/* Setup protocol subtree array */
       static int *ett[] = {
              &ett_esio,
              &ett_esio_header,
              &ett_esio_transfer_header,
              &ett_esio_transfer_data,
              &ett_esio_data
       };

        static ei_register_info ei[] = {
            { &ei_esio_telegram_lost, { "esio.telegram_lost", PI_SEQUENCE, PI_NOTE, "Telegram(s) lost", EXPFILL }},
        };

       expert_module_t* expert_esio;

/* Register the protocol name and description */
       proto_esio = proto_register_protocol("SAIA Ether-S-I/O protocol", "ESIO", "esio");

/* Required function calls to register the header fields and subtrees used */
       proto_register_field_array(proto_esio, hf, array_length(hf));
       proto_register_subtree_array(ett, array_length(ett));
       expert_esio = expert_register_protocol(proto_esio);
       expert_register_field_array(expert_esio, ei, array_length(ei));

/* Register the dissector by name and save its handle */
       esio_handle = register_dissector("esio", dissect_esio, proto_esio);
}

void
proto_reg_handoff_esio(void)
{
       dissector_add_uint_with_preference("udp.port", ESIO_UDP_PORT, esio_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 7
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=7 tabstop=8 expandtab:
 * :indentSize=7:tabSize=8:noTabs=true:
 */
