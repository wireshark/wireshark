/* packet-oipf.c
 * Dissector for Open IPTV Forum protocols
 * Copyright 2012, Martin Kaiser <martin@kaiser.cx>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* This dissector supports the CI+ Content and Service Protection Gateway
   (CSPG-CI+) as defined in in Open IPTV Forum Specification Volume 7 V2.1
   http://www.openiptvforum.org/release_2.html */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

static int proto_oipf_ciplus = -1;

static gint ett_oipf_ciplus = -1;

static int hf_oipf_ciplus_cmd_id = -1;
static int hf_oipf_ciplus_ca_sys_id = -1;
static int hf_oipf_ciplus_trx_id = -1;
static int hf_oipf_ciplus_send_datatype_nbr = -1;
static int hf_oipf_ciplus_dat_id = -1;
static int hf_oipf_ciplus_dat_len = -1;
static int hf_oipf_ciplus_data = -1;

/* the application id for this protocol in the CI+ SAS resource
   this is actually a 64bit hex number, we can't use a 64bit number as a key
   for the dissector table directly, we have to process it as a string
   (the string must not be a local variable as glib stores a pointer to
   it in the hash table) */
static gchar *sas_app_id_str_oipf = "0x0108113101190000";

static const value_string oipf_ciplus_cmd_id[] = {
    { 0x01, "send_msg" },
    { 0x02, "reply_msg" },
    { 0x03, "parental_control_info" },
    { 0x04, "rights_info" },
    { 0x05, "system_info" },
    { 0, NULL }
};

static const value_string oipf_ciplus_dat_id[] = {
    { 0x01, "oipf_ca_vendor_specific_information" },
    { 0x02, "oipf_country_code" },
    { 0x03, "oipf_parental_control_url" },
    { 0x04, "oipf_rating_type" },
    { 0x05, "oipf_rating_value" },
    { 0x06, "oipf_rights_issuer_url" },
    { 0x07, "oipf_access_status" },
    { 0x08, "oipf_status" },
    { 0, NULL }
};


static int
dissect_oipf_ciplus(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    gint        msg_len;
    proto_item *ti;
    proto_tree *oipf_ciplus_tree = NULL;
    guint       offset           = 0;
    guint8      i, send_datatype_nbr;
    guint16     dat_len;

    /* an OIPF CI+ message minimally contains command_id (1 byte),
       ca sys id (2 bytes), transaction id (4 bytes) and
       number of sent datatypes (1 byte) */
    msg_len = tvb_reported_length(tvb);
    if (msg_len < 8)
        return 0;

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, msg_len, "Open IPTV Forum CSPG-CI+");
        oipf_ciplus_tree = proto_item_add_subtree(ti, ett_oipf_ciplus);
    }

    proto_tree_add_item(oipf_ciplus_tree, hf_oipf_ciplus_cmd_id,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(oipf_ciplus_tree, hf_oipf_ciplus_ca_sys_id,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(oipf_ciplus_tree, hf_oipf_ciplus_trx_id,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    send_datatype_nbr = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(oipf_ciplus_tree, hf_oipf_ciplus_send_datatype_nbr,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    for (i=0; i<send_datatype_nbr; i++) {
        proto_tree_add_item(oipf_ciplus_tree, hf_oipf_ciplus_dat_id,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        dat_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(oipf_ciplus_tree, hf_oipf_ciplus_dat_len,
                tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(oipf_ciplus_tree, hf_oipf_ciplus_data,
                tvb, offset, dat_len, ENC_BIG_ENDIAN);
        offset += dat_len;
    }

    return offset;
}

void
proto_register_oipf(void)
{
    static gint *ett[] = {
        &ett_oipf_ciplus
    };

    static hf_register_info hf[] = {
        { &hf_oipf_ciplus_cmd_id,
            { "Command ID", "oipf.ciplus.cmd_id", FT_UINT8, BASE_HEX,
               VALS(oipf_ciplus_cmd_id), 0, NULL, HFILL } },
        { &hf_oipf_ciplus_ca_sys_id,
            { "CA system ID", "oipf.ciplus.ca_system_id", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_oipf_ciplus_trx_id,
            { "Transaction ID", "oipf.ciplus.transaction_id",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_oipf_ciplus_send_datatype_nbr,
            { "Number of data items", "oipf.ciplus.num_items", FT_UINT8,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_oipf_ciplus_dat_id,
            { "Datatype ID", "oipf.ciplus.datatype_id", FT_UINT8, BASE_HEX,
                VALS(oipf_ciplus_dat_id), 0, NULL, HFILL } },
        { &hf_oipf_ciplus_dat_len,
            { "Datatype length", "oipf.ciplus.datatype_len", FT_UINT16,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_oipf_ciplus_data,
            { "Data", "oipf.ciplus.data", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } }
    };

    proto_oipf_ciplus = proto_register_protocol(
            "Open IPTV Forum CSPG-CI+", "OIPF CI+", "oipf.ciplus");
    proto_register_field_array(proto_oipf_ciplus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_oipf(void)
{
    dissector_handle_t oipf_ciplus_handle;

    oipf_ciplus_handle =
        new_create_dissector_handle(dissect_oipf_ciplus, proto_oipf_ciplus);

    dissector_add_string("dvb-ci.sas.app_id_str",
            sas_app_id_str_oipf, oipf_ciplus_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
