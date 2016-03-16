/* packet-hdmi.c
 * Routines for HDMI dissection
 * Copyright 2014 Martin Kaiser <martin@kaiser.cx>
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

/* this dissector handles I2C messages on the HDMI Display Data Channel (DDC)
 *
 * EDID (Extended Display Identification Data) messages are dissected here,
 * HDCP messages are passed on to the HDCP dissector
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_hdmi(void);
void proto_reg_handoff_hdmi(void);

static int proto_hdmi  = -1;

static dissector_handle_t hdcp_handle;

static gint ett_hdmi = -1;
static gint ett_hdmi_edid = -1;

static int hf_hdmi_addr = -1;
static int hf_hdmi_edid_offset = -1;
static int hf_hdmi_edid_hdr = -1;
static int hf_hdmi_edid_manf_id = -1;
static int hf_hdmi_edid_manf_prod_code = -1;
static int hf_hdmi_edid_manf_serial = -1;
static int hf_hdmi_edid_manf_week = -1;
static int hf_hdmi_edid_mod_year = -1;
static int hf_hdmi_edid_manf_year = -1;
static int hf_hdmi_edid_version = -1;


/* also called Source and Sink in the HDMI spec */
#define ADDR_TRX "Transmitter"
#define ADDR_RCV "Receiver"

/* we use 8bit I2C addresses, including the direction bit */
#define ADDR8_HDCP_WRITE 0x74  /* transmitter->receiver */
#define ADDR8_HDCP_READ  0x75  /* r->t */
#define ADDR8_EDID_WRITE 0xA0  /* t->r */
#define ADDR8_EDID_READ  0xA1  /* r->t */

#define HDCP_ADDR8(x)   (x == ADDR8_HDCP_WRITE || x == ADDR8_HDCP_READ)

static const value_string hdmi_addr[] = {
    { ADDR8_HDCP_WRITE, "transmitter writes HDCP data for receiver" },
    { ADDR8_HDCP_READ,  "transmitter reads HDCP data from receiver" },

    { ADDR8_EDID_WRITE, "EDID request" },
    { ADDR8_EDID_READ,  "EDID read" },
    { 0, NULL }
};

#define EDID_HDR_VALUE G_GUINT64_CONSTANT(0x00ffffffffffff00)

/* grab 5 bits, from bit n to n+4, from a big-endian number x
   map those bits to a capital letter such that A == 1, B == 2, ... */
#define CAPITAL_LETTER(x, n) ('A'-1 + (((x) & (0x1F<<n)) >> n))


/* dissect EDID data from the receiver
   return the offset after the dissected data */
static gint
dissect_hdmi_edid(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    proto_item *yi;
    proto_tree *edid_tree;
    guint64     edid_hdr;
    guint16     manf_id;
    gchar       manf_id_str[4]; /* 3 letters + 0-termination */
    guint8      week, year;
    int         year_hf;

    edid_tree = proto_tree_add_subtree(tree, tvb,
            offset, -1, ett_hdmi_edid, NULL,
            "Extended Display Identification Data (EDID)");

    edid_hdr = tvb_get_ntoh64(tvb, offset);
    if (edid_hdr != EDID_HDR_VALUE)
        return offset; /* XXX handle fragmented EDID messages */

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "EDID");

    proto_tree_add_item(edid_tree, hf_hdmi_edid_hdr,
            tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    /* read as big endian for easier splitting */
    manf_id = tvb_get_ntohs(tvb, offset);
    /* XXX check that MSB is 0 */
    manf_id_str[0] = CAPITAL_LETTER(manf_id, 10);
    manf_id_str[1] = CAPITAL_LETTER(manf_id,  5);
    manf_id_str[2] = CAPITAL_LETTER(manf_id,  0);
    manf_id_str[3] = 0;
    proto_tree_add_string(edid_tree, hf_hdmi_edid_manf_id,
            tvb, offset, 2, manf_id_str);
    offset += 2;

    proto_tree_add_item(edid_tree, hf_hdmi_edid_manf_prod_code,
            tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(edid_tree, hf_hdmi_edid_manf_serial,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    week = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(edid_tree, hf_hdmi_edid_manf_week,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    year_hf = week == 255 ? hf_hdmi_edid_mod_year : hf_hdmi_edid_manf_year;
    year = tvb_get_guint8(tvb, offset);
    yi = proto_tree_add_item(edid_tree, year_hf,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(yi, " (year %d)", 1990+year);
    offset += 1;

    proto_tree_add_item(edid_tree, hf_hdmi_edid_version, tvb, offset, 2, ENC_BIG_ENDIAN);

    /* XXX dissect the parts following the EDID header */

    return tvb_reported_length(tvb);
}


static int
dissect_hdmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8      addr;
    gint        offset=0;
    proto_item *pi;
    proto_tree *hdmi_tree;

    /* the I2C address in the first byte is always handled by the HDMI
       dissector, even if the packet contains HDCP data */
    addr = tvb_get_guint8(tvb, 0);
    if (!try_val_to_str(addr, hdmi_addr))
        return 0; /* no HDMI packet */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDMI");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_item(tree, proto_hdmi, tvb, 0, -1, ENC_NA);
    hdmi_tree = proto_item_add_subtree(pi, ett_hdmi);

    if (addr&0x01) {
        set_address(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR_RCV)+1, ADDR_RCV);
        set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR_TRX)+1, ADDR_TRX);
        pinfo->p2p_dir = P2P_DIR_RECV;
    }
    else {
        set_address(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR_TRX)+1, ADDR_TRX);
        set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR_RCV)+1, ADDR_RCV);
        pinfo->p2p_dir = P2P_DIR_SENT;
    }

    /* there's no explicit statement in the spec saying that the protocol is
        big or little endian
       there's three cases: one byte values, symmetrical values or values
        that are explicitly marked as little endian
       for the sake of simplicity, we use little endian everywhere */
    proto_tree_add_item(hdmi_tree, hf_hdmi_addr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    if (HDCP_ADDR8(addr)) {
        tvbuff_t *hdcp_tvb;

        hdcp_tvb = tvb_new_subset_remaining(tvb, offset);

        return call_dissector(hdcp_handle, hdcp_tvb, pinfo, hdmi_tree);
    }

    if (addr == ADDR8_EDID_WRITE) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "EDID request");
        proto_tree_add_item(hdmi_tree, hf_hdmi_edid_offset,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        return offset;
    }

    return dissect_hdmi_edid(tvb, offset, pinfo, hdmi_tree);
}

static void
hdmi_fmt_edid_version( gchar *result, guint32 revision )
{
   g_snprintf( result, ITEM_LABEL_LENGTH, "%d.%02d", (guint8)(( revision & 0xFF00 ) >> 8), (guint8)(revision & 0xFF) );
}

void
proto_register_hdmi(void)
{
    static hf_register_info hf[] = {
        { &hf_hdmi_addr,
            { "8bit I2C address", "hdmi.addr", FT_UINT8, BASE_HEX,
                VALS(hdmi_addr), 0, NULL, HFILL } },
        { &hf_hdmi_edid_offset,
            { "Offset", "hdmi.edid.offset",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_hdr,
            { "EDID header", "hdmi.edid.hdr",
                FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_manf_id,
            { "Manufacturer ID", "hdmi.edid.manf_id",
                FT_STRING, STR_ASCII, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_manf_prod_code,
            { "Manufacturer product code", "hdmi.edid.manf_prod_code",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_manf_serial,
            { "Serial number", "hdmi.edid.serial_num",
                FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_manf_week,
            { "Week of manufacture", "hdmi.edid.manf_week",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_mod_year,
            { "Model year", "hdmi.edid.model_year",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_manf_year,
            { "Year of manufacture", "hdmi.edid.manf_year",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_hdmi_edid_version,
            { "EDID Version", "hdmi.edid.version",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(hdmi_fmt_edid_version), 0, NULL, HFILL } }

    };

    static gint *ett[] = {
        &ett_hdmi,
        &ett_hdmi_edid
    };

    proto_hdmi = proto_register_protocol(
            "High-Definition Multimedia Interface", "HDMI", "hdmi");

    proto_register_field_array(proto_hdmi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_hdmi(void)
{
    dissector_handle_t hdmi_handle;

    hdcp_handle = find_dissector_add_dependency("hdcp", proto_hdmi);

    hdmi_handle = create_dissector_handle( dissect_hdmi, proto_hdmi );
    dissector_add_for_decode_as("i2c.message", hdmi_handle );
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
