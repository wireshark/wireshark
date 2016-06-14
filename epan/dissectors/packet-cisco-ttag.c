/* packet-cisco-ttag.c
 * Routines for dissection of Cisco's ttag protocol.
 * Based on packet-cisco-metadata.c
 *
 * Copyright 2016 by Jaap Keuter (jkeuter[AT]xs4all.nl)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_register_ttag(void);
void proto_reg_handoff_ttag(void);

static dissector_handle_t ethertype_handle;

static int proto_ttag = -1;

static int hf_ttag_time_stamp = -1;
static int hf_ttag_eth_type = -1;

static gint ett_ttag = -1;

static int
dissect_ttag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint64 timestamp_value;
    nstime_t timestamp;
    guint16 encap_proto;
    ethertype_data_t ethertype_data;

    proto_tree *ttag_tree;
    proto_item *ti;
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TTAG");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_ttag, tvb, 0, 8, ENC_NA);
    ttag_tree = proto_item_add_subtree(ti, ett_ttag);

    timestamp_value = tvb_get_guint48(tvb, offset, ENC_BIG_ENDIAN);
    timestamp.secs = timestamp_value / G_GUINT64_CONSTANT(1000000000);
    timestamp.nsecs = (guint32)(timestamp_value - (timestamp.secs * G_GUINT64_CONSTANT(1000000000)));

    proto_item_append_text(ti, ", Timestamp: %lu.%d seconds", timestamp.secs, timestamp.nsecs);

    proto_tree_add_time(ttag_tree, hf_ttag_time_stamp, tvb, offset, 6, &timestamp);
    offset += 6;

    encap_proto = tvb_get_ntohs(tvb, offset);
    offset += 2;

    ethertype_data.etype = encap_proto;
    ethertype_data.offset_after_ethertype = offset;
    ethertype_data.fh_tree = ttag_tree;
    ethertype_data.etype_id = hf_ttag_eth_type;
    /* ttag doesn't define a trailer, but there's no way to tell Ethertype dissector that.
     * At least use the correct header field to reflect that and allow proper filter expression,
     * although it will still be attached to our tree instead of Ethernet II.
     */
    ethertype_data.trailer_id = proto_registrar_get_id_byname("eth.trailer");
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);

    return tvb_captured_length(tvb);
}

void
proto_register_ttag(void)
{
    static hf_register_info hf[] = {
        { &hf_ttag_time_stamp,
            { "Time stamp", "ttag.time_stamp", FT_RELATIVE_TIME, 0, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ttag_eth_type,
            { "Type", "ttag.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_ttag
    };

    proto_ttag = proto_register_protocol("Cisco ttag", "Cisco ttag", "ttag");
    proto_register_field_array(proto_ttag, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ttag(void)
{
    dissector_handle_t ttag_handle;

    ethertype_handle = find_dissector_add_dependency("ethertype", proto_ttag);

    ttag_handle = create_dissector_handle(dissect_ttag, proto_ttag);
    dissector_add_for_decode_as("ethertype", ttag_handle);
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
