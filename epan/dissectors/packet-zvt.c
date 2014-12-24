/* packet-zvt.c
 * Routines for ZVT dissection
 * Copyright 2014-2015, Martin Kaiser <martin@kaiser.cx>
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

/* ZVT is a manufacturer-independent protocol between payment terminals and
 * electronic cash-register systems / vending machines
 *
 * the specifications are available from http://www.zvt-kassenschnittstelle.de
 *
 * ZVT defines a "serial transport protocol" and a "TCP/IP transport
 * protocol"
 *
 * ZVT can sit on top of USB, either the serial or the TCP/IP protocol
 * can be used in this case - this is not supported for now
 *
 * a dump of ZVT data can be converted to pcap, using a user-defined DLT
 * we register the dissector by name and try to auto-detect the serial
 * or TCP/IP protocol
 *
 * finally, ZVT can run on top of TCP, the default port is 20007, only
 * the TCP/IP protocol can be used here
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>

/* special characters of the serial transport protocol */
#define ACK 0x06
#define NAK 0x15
#define DLE 0x10  /* data line escape */
#define STX 0x02  /* start of text */

/* an APDU needs at least a 2-byte control-field and one byte length */
#define ZVT_APDU_MIN_LEN 3

void proto_register_zvt(void);
void proto_reg_handoff_zvt(void);

/* the specification mentions tcp port 20007
   this port is not officially registered with IANA */
static guint pref_zvt_tcp_port = 0;

static int proto_zvt = -1;

static int ett_zvt = -1;
static int ett_zvt_apdu = -1;

static int hf_zvt_ctrl = -1;
static int hf_zvt_len = -1;

static const value_string ctrl_field[] = {
    { 0x040F, "Status Information" },
    { 0x04FF, "Intermediate Status Information" },
    { 0x0600, "Registration" },
    { 0x0601, "Authorisation" },
    { 0x060F, "Completion" },
    { 0x061E, "Abort" },
    { 0x0650, "End Of Day" },
    { 0x0670, "Diagnosis" },
    { 0x0693, "Initialisation" },
    { 0x06D1, "Print Line" },
    { 0x06D3, "Print Text Block" },
    { 0, NULL }
};
static value_string_ext ctrl_field_ext = VALUE_STRING_EXT_INIT(ctrl_field);


/* dissect a ZVT APDU
   return -1 if we don't have a complete APDU, 0 if the packet is no ZVT APDU
   or the length of the ZVT APDU if all goes well */
static int
dissect_zvt_apdu(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    gint        offset_start;
    guint8      len_bytes = 1; /* number of bytes for the len field */
    guint16     len;
    proto_item *apdu_it;
    proto_tree *apdu_tree;

    offset_start = offset;

    if (tvb_captured_length_remaining(tvb, offset) < ZVT_APDU_MIN_LEN)
        return -1;

    len = tvb_get_guint8(tvb, offset+2);
    if (len == 0xFF) {
        len_bytes = 3;
        len = tvb_get_ntohs(tvb, offset+3);
    }

    /* ZVT_APDU_MIN_LEN already includes one length byte */
    if (tvb_captured_length_remaining(tvb, offset) <
            ZVT_APDU_MIN_LEN + (len_bytes-1) + len) {
        return -1;
    }

    apdu_tree = proto_tree_add_subtree(tree,
            tvb, offset, -1, ett_zvt_apdu, &apdu_it, "ZVT APDU");

    if (tvb_get_guint8(tvb, offset) == 0x80 ||
        tvb_get_guint8(tvb, offset) == 0x84) {
        offset += 2;
    }
    else {
        proto_tree_add_item(apdu_tree, hf_zvt_ctrl, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    proto_tree_add_uint(apdu_tree, hf_zvt_len, tvb, offset, len_bytes, len);
    offset += len_bytes;

    offset += len;

    proto_item_set_len(apdu_it, offset - offset_start);
    return offset - offset_start;
}


static gint
dissect_zvt_serial(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    gint  offset_start;
    int   apdu_len;

    offset_start = offset;

    if (tvb_reported_length_remaining(tvb, offset) == 1) {
        offset++; /* ACK or NAK byte */
        return offset - offset_start;
    }

    offset ++; /* DLE byte */
    offset ++; /* STX byte */

    apdu_len = dissect_zvt_apdu(tvb, offset, pinfo, tree);
    if (apdu_len < 0)
        return apdu_len;

    offset += apdu_len;

    offset ++; /* DLE byte */
    offset ++; /* ETX byte */
    offset += 2; /* CRC bytes */

    return offset - offset_start;
}


static gboolean
valid_ctrl_field(tvbuff_t *tvb, gint offset)
{
    if (tvb_get_guint8(tvb, offset) == 0x80 ||
        tvb_get_guint8(tvb, offset) == 0x84 ||
        try_val_to_str_ext(tvb_get_ntohs(tvb, offset), &ctrl_field_ext)) {
            return TRUE;
    }

    return FALSE;
}


static int
dissect_zvt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        zvt_len = 0;
    proto_item *zvt_ti;
    proto_tree *zvt_tree;
    gboolean    is_serial; /* serial or TCP/IP protocol? */

    if (tvb_captured_length(tvb) == 1 &&
            (tvb_get_guint8(tvb, 0) == ACK ||
             tvb_get_guint8(tvb, 0) == NAK)) {
        is_serial = TRUE;
    }
    else if (tvb_captured_length(tvb) >= 2 &&
            tvb_get_guint8(tvb, 0) == DLE &&
            tvb_get_guint8(tvb, 1) == STX) {
        is_serial = TRUE;
    }
    else if (tvb_captured_length(tvb) >= ZVT_APDU_MIN_LEN &&
            valid_ctrl_field(tvb, 0)) {
        is_serial = FALSE;
    }
    else
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZVT");
    col_clear(pinfo->cinfo, COL_INFO);
    zvt_ti = proto_tree_add_protocol_format(tree, proto_zvt,
            tvb, 0, -1,
            "ZVT Kassenschnittstelle: %s", is_serial ?
            "Serial Transport Protocol" : "Transport Protocol TCP/IP");
    zvt_tree = proto_item_add_subtree(zvt_ti, ett_zvt);

    if (is_serial)
        zvt_len = dissect_zvt_serial(tvb, 0, pinfo, zvt_tree);
    else
        zvt_len = dissect_zvt_apdu(tvb, 0, pinfo, zvt_tree);

    /* zvt_len < 0 means that we have an incomplete APDU
       we can't do any reassembly here, so let's consume all bytes */
    if (zvt_len < 0)
        zvt_len = tvb_captured_length(tvb);

    proto_item_set_len(zvt_ti, zvt_len);
    return zvt_len;
}


static int
dissect_zvt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        offset = 0, zvt_len = 0, ret;
    proto_item *zvt_ti;
    proto_tree *zvt_tree;

    if (tvb_captured_length(tvb) < ZVT_APDU_MIN_LEN) {
        if (pinfo->can_desegment) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        }
        return zvt_len;
    }

    if (!valid_ctrl_field(tvb, 0))
        return 0; /* reject the packet */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZVT");
    col_clear(pinfo->cinfo, COL_INFO);
    zvt_ti = proto_tree_add_protocol_format(tree, proto_zvt,
            tvb, 0, -1,
            "ZVT Kassenschnittstelle: Transport Protocol TCP/IP");
    zvt_tree = proto_item_add_subtree(zvt_ti, ett_zvt);

    while (tvb_captured_length_remaining(tvb, offset) > 0) {
        ret = dissect_zvt_apdu(tvb, offset, pinfo, zvt_tree);
        if (ret == 0) {
            /* not a valid APDU
               mark the bytes that we consumed and exit, give
               other dissectors a chance to try the remaining
               bytes */
            break;
        }
        else if (ret < 0) {
            /* not enough data - ask the TCP layer for more */

            if (pinfo->can_desegment) {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            }
            break;
        }
        else {
            offset += ret;
            zvt_len += ret;
        }
    }

    proto_item_set_len(zvt_ti, zvt_len);
    return zvt_len;
}


void
proto_register_zvt(void)
{
    static hf_register_info hf[] = {
        { &hf_zvt_ctrl,
            { "Control-field", "zvt.control_field", FT_UINT16,
                BASE_HEX|BASE_EXT_STRING, &ctrl_field_ext, 0, NULL, HFILL } },
        { &hf_zvt_len,
            { "Length-field", "zvt.length_field",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } }
    };
    static gint *ett[] = {
        &ett_zvt,
        &ett_zvt_apdu
    };

    module_t *zvt_module;

    proto_zvt = proto_register_protocol(
            "ZVT Kassenschnittstelle", "ZVT", "zvt");
    proto_register_field_array(proto_zvt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    zvt_module = prefs_register_protocol(proto_zvt, proto_reg_handoff_zvt);
    prefs_register_uint_preference(zvt_module, "tcp.port",
                   "ZVT TCP Port",
                   "Set the TCP port for ZVT messages (port 20007 according to the spec)",
                   10,
                   &pref_zvt_tcp_port);
}


void
proto_reg_handoff_zvt(void)
{
    static gboolean            registered_dissector = FALSE;
    static int                 zvt_tcp_port;
    static dissector_handle_t  zvt_tcp_handle;

    if (!registered_dissector) {
        /* register by name to allow mapping to a user DLT */
        new_register_dissector("zvt", dissect_zvt, proto_zvt);

        zvt_tcp_handle = new_create_dissector_handle(dissect_zvt_tcp, proto_zvt);

        registered_dissector = TRUE;
    }
    else
        dissector_delete_uint("tcp.port", zvt_tcp_port, zvt_tcp_handle);

    zvt_tcp_port = pref_zvt_tcp_port;
    dissector_add_uint("tcp.port", zvt_tcp_port, zvt_tcp_handle);
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
