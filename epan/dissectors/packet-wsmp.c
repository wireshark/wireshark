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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>

#define WSMP       0x80
#define WSMP_S     0x81
#define WSMP_I     0x82
#define CHANNUM    0x0F
#define DATARATE   0x10
#define TRANSMITPW 0x04

void proto_register_wsmp(void);
void proto_reg_handoff_wsmp(void);

static const value_string wsmp_elemenid_names[] = {
    { 0x80, "WSMP" },
    { 0x81, "WSMP-S" },
    { 0x82, "WSMP-I" },
    { 0, NULL }
};


static dissector_handle_t data_handle;

/* Initialize the protocol and registered fields */
static int proto_wsmp = -1;
static int hf_wsmp_version = -1;
static int hf_wsmp_psid = -1;
static int hf_wsmp_rate = -1;
static int hf_wsmp_channel = -1;
static int hf_wsmp_txpower = -1;
static int hf_wsmp_WAVEid = -1;
static int hf_wsmp_wsmlength = -1;
static int hf_wsmp_WSMP_S_data = -1;

/* Savari function to get the length of a psid based on the number of
    successive 1s in the most sig bits of the most sig octet. Taken
    from libwme
*/
static int wme_getpsidlen (guint8 *psid)
{
    int length = 0;
    if ((psid[0] & 0xF0) == 0xF0) {
        length = 255;
    } else if ( (psid[0] & 0xE0) == 0xE0) {
        length = 4;
    } else if ( (psid[0] & 0xE0) == 0xC0) {
        length = 3;
    } else if ( (psid[0] & 0xC0) == 0x80) {
        length = 2;
    } else if ((psid[0] & 0x80) == 0x00) {
        length = 1;
    }
    return length;
}

/* Initialize the subtree pointers */
static gint ett_wsmp = -1;
static gint ett_wsmdata = -1;

static void
dissect_wsmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *wsmdata_item;
    proto_tree *wsmp_tree, *wsmdata_tree;
    tvbuff_t   *wsmdata_tvb;
    guint16     wsmlength, offset;
    guint32     psidLen, psid, supLen;
    guint8      elemenId, elemenLen, msb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WSMP");

    col_set_str(pinfo->cinfo, COL_INFO, "WAVE Short Message Protocol IEEE P1609.3");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_wsmp, tvb, 0, -1, ENC_NA);

    wsmp_tree = proto_item_add_subtree(ti, ett_wsmp);

    offset = 0;
    proto_tree_add_item(wsmp_tree,
                        hf_wsmp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    psid    = tvb_get_guint8(tvb, offset);
    psidLen = (guint32)wme_getpsidlen((guint8*)&psid);


    if (psidLen == 2)
        psid = tvb_get_ntohs(tvb, offset);
    else if (psidLen == 3)
    {
        psid = tvb_get_ntohl(tvb, offset);
        psid = psid & 0x00FFFF; /* three bytes */

    }
    else if (psidLen == 4)
        psid = tvb_get_ntohl(tvb, offset);

    proto_tree_add_item(wsmp_tree,
                        hf_wsmp_psid, tvb, offset, psidLen, ENC_BIG_ENDIAN);
    offset += psidLen;


    elemenId = tvb_get_guint8(tvb, offset);
    while ((elemenId != WSMP) && (elemenId != WSMP_S) && (elemenId != WSMP_I))
    {
        offset++;
        if (elemenId == CHANNUM)
        {
            /* channel number */
            elemenLen = tvb_get_guint8(tvb, offset);
            offset++;
            proto_tree_add_item(wsmp_tree,
                                hf_wsmp_channel, tvb, offset, elemenLen, ENC_BIG_ENDIAN);
            offset += elemenLen;
        }
        else if (elemenId == DATARATE)
        {
            /* Data rate  */
            elemenLen = tvb_get_guint8(tvb, offset);
            offset++;
            proto_tree_add_item(wsmp_tree,
                                hf_wsmp_rate, tvb, offset, elemenLen, ENC_BIG_ENDIAN);
            offset += elemenLen;
        }
        else if (elemenId == TRANSMITPW)
        {
            /* Transmit power */
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

    wsmlength = tvb_get_letohs( tvb, offset);
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

    wsmdata_item = proto_tree_add_text (wsmp_tree, tvb, offset, wsmlength,
                                        "Wave Short Message");
    wsmdata_tree = proto_item_add_subtree(wsmdata_item, ett_wsmdata);

    wsmdata_tvb  = tvb_new_subset(tvb, offset, -1, wsmlength);

    /* TODO: Branch on the application context and display accordingly
     * Default: call the data dissector
     */
    if (psid == 0xbff0)
    {
        call_dissector(data_handle, wsmdata_tvb, pinfo, wsmdata_tree);
    }
}

void
proto_register_wsmp(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_wsmp_version,
          { "Version",           "wsmp.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_wsmp_psid,
          { "PSID",           "wsmp.psid", FT_UINT32, BASE_HEX, NULL, 0x0,
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
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_wsmp,
        &ett_wsmdata,
    };

    /* Register the protocol name and description */
    proto_wsmp = proto_register_protocol("Wave Short Message Protocol(IEEE P1609.3)",
                                         "WSMP", "wsmp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_wsmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_wsmp(void)
{
    dissector_handle_t wsmp_handle;

    wsmp_handle = create_dissector_handle(dissect_wsmp, proto_wsmp);
    dissector_add_uint("ethertype", ETHERTYPE_WSMP, wsmp_handle);
    data_handle = find_dissector("data");
    return;
}
