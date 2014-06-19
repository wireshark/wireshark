/* packet-rtacser.c
 * Routines for Schweitzer Engineering Laboratories "Real-Time Automation Controller" (RTAC) Serial Line Dissection
 * By Chris Bontje (cbontje[AT]gmail.com)
 * Copyright May 2013
 *
 ************************************************************************************************
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
 *
 ************************************************************************************************
 * Dissector Notes:
 *
 * The RTAC product family (SEL-3530, SEL-2241, SEL-3505) is a Linux-based Automation Controller
 * product that is capable of interfacing with SEL and 3rd-party equipment using a variety of
 * standard industrial protocols such as SEL FM, DNP3, Modbus, C37.118, Telegyr 8979 and others.
 * Each protocol instance (master/client or slave/server) is configured to utilize either Ethernet
 * or EIA-232/485 serial connectivity with protocol variations for each medium taken into account.
 *
 * The configuration software for the RTAC platform is named AcSELerator RTAC (SEL-5033) and
 * is used to set up all communications and user logic for the controller as well as provide
 * downloading and online debugging facilities.  One particularly useful aspect of the online
 * debugging capabilities is a robust Communication Monitor tool that can show raw data streams
 * from either serial or Ethernet interfaces.  Many similar products have this same capability
 * but the RTAC software goes a step beyond by providing a "save-as" function to save all captured
 * data into pcap format for further analysis in Wireshark.
 *
 * All Ethernet-style capture files will have a packets with a "Linux Cooked Capture" header
 * including the "source" MAC address of the device responsible for the generation of the message
 * and the TCP/IP header(s) maintained from the original conversation.  The application data from the
 * message will follow as per a standard Wireshark packet.
 *
 * Serial-based pcap capture files were orignally stored using "User 0" DLT type 147 to specify a
 * user-defined dissector for pcap data but this format was later modified to specify a custom DLT type
 * known as LINKTYPE_RTAC_SERIAL (DLT 250). The pcap file data portion contains a standard 12-byte serial
 * header followed by the application payload data from actual rx/tx activity on the line.  Some useful
 * information can be retrieved from the 12-byte header information, such as conversation time-stamps,
 * UART function and EIA-232 serial control line states at the time of the message.
 *
 * This dissector will automatically be used for any newer-style DLT 250 files, and the payload protocol
 * can be configured via built-in preferences to use whatever standardized industrial protocol is present
 * on the line for attempted dissection (selfm, mbrtu, dnp3.udp, synphasor).  Older pcap files of DLT type 147
 * can be used by setting the DLT_USER preferences configuration of User 0 (DLT=147) with a 'Header Size'
 * of '12' and a 'Header Protocol' of 'rtacser'.  The payload protocol should be set to use the protocol
 * dissector for the data that is present on the line (again, selfm, mbrtu, dnp3.udp or synphasor). */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>

void proto_register_rtacser(void);

/* Initialize the protocol and registered fields */
static int proto_rtacser                    = -1;
static int hf_rtacser_timestamp             = -1;
static int hf_rtacser_event_type            = -1;
static int hf_rtacser_ctrl_cts              = -1;
static int hf_rtacser_ctrl_dcd              = -1;
static int hf_rtacser_ctrl_dsr              = -1;
static int hf_rtacser_ctrl_rts              = -1;
static int hf_rtacser_ctrl_dtr              = -1;
static int hf_rtacser_ctrl_ring             = -1;
static int hf_rtacser_ctrl_mbok             = -1;
static int hf_rtacser_footer                = -1;
static int hf_rtacser_data                  = -1;

/* Initialize the subtree pointers */
static gint ett_rtacser                   = -1;
static gint ett_rtacser_cl                = -1;

/* Globals for RTAC Serial Preferences */
static guint global_rtacser_payload_proto = 0; /* No Payload, by default */

/* Handles for Payload Protocols */
static dissector_handle_t selfm_handle;
static dissector_handle_t dnp3_handle;
static dissector_handle_t modbus_handle;
static dissector_handle_t synphasor_handle;
static dissector_handle_t lg8979_handle;

#define RTACSER_HEADER_LEN    12

/* Bit-masks for EIA-232 serial control lines */
#define RTACSER_CTRL_CTS      0x01
#define RTACSER_CTRL_DCD      0x02
#define RTACSER_CTRL_DSR      0x04
#define RTACSER_CTRL_RTS      0x08
#define RTACSER_CTRL_DTR      0x10
#define RTACSER_CTRL_RING     0x20
#define RTACSER_CTRL_MBOK     0x40

/* Payload Protocol Types from Preferences */
#define RTACSER_PAYLOAD_NONE        0
#define RTACSER_PAYLOAD_SELFM       1
#define RTACSER_PAYLOAD_DNP3        2
#define RTACSER_PAYLOAD_MODBUS      3
#define RTACSER_PAYLOAD_SYNPHASOR   4
#define RTACSER_PAYLOAD_LG8979      5

/* Event Types */
static const value_string rtacser_eventtype_vals[] = {
    { 0x00,       "STATUS_CHANGE"         },
    { 0x01,       "DATA_TX_START"         },
    { 0x02,       "DATA_RX_START"         },
    { 0x03,       "DATA_TX_END"           },
    { 0x04,       "DATA_RX_END"           },
    { 0x05,       "CAPTURE_DATA_LOST"     },
    { 0x06,       "CAPTURE_COMPLETE"      },
    { 0x07,       "FRAMING_ERROR"         },
    { 0x08,       "PARITY_ERROR"          },
    { 0x09,       "SERIAL_BREAK_EVENT"    },
    { 0x0A,       "SERIAL_OVERFLOW_EVENT" },
    { 0,          NULL }
};

static const enum_val_t rtacser_payload_proto_type[] = {
  { "NONE      ", "NONE      ",  RTACSER_PAYLOAD_NONE       },
  { "SEL FM    ", "SEL FM    ",  RTACSER_PAYLOAD_SELFM      },
  { "DNP3      ", "DNP3      ",  RTACSER_PAYLOAD_DNP3       },
  { "MODBUS RTU", "MODBUS RTU",  RTACSER_PAYLOAD_MODBUS     },
  { "SYNPHASOR ", "SYNPHASOR ",  RTACSER_PAYLOAD_SYNPHASOR  },
  { "L&G 8979  ", "L&G 8979  ",  RTACSER_PAYLOAD_LG8979     },
  { NULL, NULL, 0 }
};


/******************************************************************************************************/
/* Code to dissect RTAC Serial-Line Protocol packets */
/******************************************************************************************************/
static void
dissect_rtacser_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *rtacser_item, *ts_item, *cl_item, *data_payload;
    proto_tree    *rtacser_tree, *cl_tree;
    int           offset = 0, len;
    guint         event_type;
    guint32       timestamp1, timestamp2;
    gboolean      cts, dcd, dsr, rts, dtr, ring, mbok;
    tvbuff_t      *payload_tvb;

    len = RTACSER_HEADER_LEN;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTAC Serial");
    col_clear(pinfo->cinfo, COL_INFO);

    rtacser_item = proto_tree_add_protocol_format(tree, proto_rtacser, tvb, 0, len, "RTAC Serial Line");
    rtacser_tree = proto_item_add_subtree(rtacser_item, ett_rtacser);

    /* Time-stamp is stored as 2 x 32-bit unsigned integers, the left and right-hand side of the decimal point respectively */
    /* The format mirrors the timeval struct - absolute Epoch time (seconds since 1/1/1970) with an added microsecond component */
    timestamp1 = tvb_get_ntohl(tvb, offset);
    timestamp2 = tvb_get_ntohl(tvb, offset+4);
    ts_item = proto_tree_add_item(rtacser_tree, hf_rtacser_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
    proto_item_set_text(ts_item, "Arrived At Time: %u.%u" , timestamp1, timestamp2);
    offset += 8;

    /* Set INFO column with RTAC Serial Event Type */
    event_type = tvb_get_guint8(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%-21s", val_to_str_const(event_type, rtacser_eventtype_vals, "Unknown Type"));

    /* Add event type to tree */
    proto_tree_add_item(rtacser_tree, hf_rtacser_event_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Retrieve EIA-232 serial control line states */
    cts  = tvb_get_guint8(tvb, offset) & RTACSER_CTRL_CTS;
    dcd  = tvb_get_guint8(tvb, offset) & RTACSER_CTRL_DCD;
    dsr  = tvb_get_guint8(tvb, offset) & RTACSER_CTRL_DSR;
    rts  = tvb_get_guint8(tvb, offset) & RTACSER_CTRL_RTS;
    dtr  = tvb_get_guint8(tvb, offset) & RTACSER_CTRL_DTR;
    ring = tvb_get_guint8(tvb, offset) & RTACSER_CTRL_RING;
    mbok = tvb_get_guint8(tvb, offset) & RTACSER_CTRL_MBOK;

    cl_item = proto_tree_add_text(rtacser_tree, tvb, offset, 1, "Control Lines");
    cl_tree = proto_item_add_subtree(cl_item, ett_rtacser_cl);

    /* Add UART Control Line information to INFO column */
    col_append_str(pinfo->cinfo, COL_INFO, " ( ");
    (cts)  ? col_append_str(pinfo->cinfo, COL_INFO, "CTS") : col_append_str(pinfo->cinfo, COL_INFO, "/CTS");
    (dcd)  ? col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DCD")  : col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "/DCD");
    (dsr)  ? col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DSR")  : col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "/DSR");
    (rts)  ? col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "RTS")  : col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "/RTS");
    (dtr)  ? col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DTR")  : col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "/DTR");
    (ring) ? col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "RING") : col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "/RING");
    (mbok) ? col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "MBOK") : col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "/MBOK");
    col_append_str(pinfo->cinfo, COL_INFO, " )");

    /* Add UART Control Line information to tree */
    proto_item_append_text(cl_item, " (");
    (cts)  ? proto_item_append_text(cl_item, "CTS, ") : proto_item_append_text(cl_item, "/CTS, ");
    (dcd)  ? proto_item_append_text(cl_item, "DCD, ") : proto_item_append_text(cl_item, "/DCD, ");
    (dsr)  ? proto_item_append_text(cl_item, "DSR, ") : proto_item_append_text(cl_item, "/DSR, ");
    (rts)  ? proto_item_append_text(cl_item, "RTS, ") : proto_item_append_text(cl_item, "/RTS, ");
    (dtr)  ? proto_item_append_text(cl_item, "DTR, ") : proto_item_append_text(cl_item, "/DTR, ");
    (ring) ? proto_item_append_text(cl_item, "RING, ") : proto_item_append_text(cl_item, "/RING, ");
    (mbok) ? proto_item_append_text(cl_item, "MBOK") : proto_item_append_text(cl_item, "/MBOK");
    proto_item_append_text(cl_item, ")");

    proto_tree_add_item(cl_tree, hf_rtacser_ctrl_cts,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cl_tree, hf_rtacser_ctrl_dcd,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cl_tree, hf_rtacser_ctrl_dsr,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cl_tree, hf_rtacser_ctrl_rts,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cl_tree, hf_rtacser_ctrl_dtr,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cl_tree, hf_rtacser_ctrl_ring, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(cl_tree, hf_rtacser_ctrl_mbok, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 2-byte footer */
    proto_tree_add_item(rtacser_tree, hf_rtacser_footer, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* If no payload dissector has been selected, indicate to the user the preferences options */
    if ((tvb_reported_length_remaining(tvb, offset) > 0) && (global_rtacser_payload_proto == RTACSER_PAYLOAD_NONE)) {
        data_payload = proto_tree_add_item(tree, hf_rtacser_data, tvb, offset, -1, ENC_NA);
        proto_item_set_text(data_payload,"Payload Protocol not selected.  Check 'Preferences-> Protocols-> RTAC Serial' for options");
        return;
    }


    /* Determine correct message type and call appropriate dissector */
    if (tvb_reported_length_remaining(tvb, RTACSER_HEADER_LEN) > 0) {

        switch (global_rtacser_payload_proto) {
            case RTACSER_PAYLOAD_SELFM:
                payload_tvb = tvb_new_subset_remaining(tvb, RTACSER_HEADER_LEN);
                call_dissector(selfm_handle, payload_tvb, pinfo, tree);
                break;
            case RTACSER_PAYLOAD_DNP3:
                payload_tvb = tvb_new_subset_remaining(tvb, RTACSER_HEADER_LEN);
                call_dissector(dnp3_handle, payload_tvb, pinfo, tree);
                break;
            case RTACSER_PAYLOAD_MODBUS:
                payload_tvb = tvb_new_subset_remaining(tvb, RTACSER_HEADER_LEN);
                call_dissector(modbus_handle, payload_tvb, pinfo, tree);
                break;
            case RTACSER_PAYLOAD_SYNPHASOR:
                payload_tvb = tvb_new_subset_remaining(tvb, RTACSER_HEADER_LEN);
                call_dissector(synphasor_handle, payload_tvb, pinfo, tree);
                break;
            case RTACSER_PAYLOAD_LG8979:
                payload_tvb = tvb_new_subset_remaining(tvb, RTACSER_HEADER_LEN);
                call_dissector(lg8979_handle, payload_tvb, pinfo, tree);
                break;
            default:
                break;
        }
    }

}



/******************************************************************************************************/
/* Dissect RTAC Serial-line protocol payload */
/******************************************************************************************************/
static int
dissect_rtacser(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint length = tvb_length(tvb);

    /* Check for a RTAC Serial packet.  It should be at least 12 bytes */
    if(length < 12) {

        return 0;
    }

    dissect_rtacser_data(tvb, pinfo, tree);

    return tvb_length(tvb);
}

/******************************************************************************************************/
/* Register the protocol with Wireshark */
/******************************************************************************************************/
void proto_reg_handoff_rtacser(void);

void
proto_register_rtacser(void)
{
    /* RTAC Serial Protocol header fields */
    static hf_register_info rtacser_hf[] = {
        { &hf_rtacser_timestamp,
        { "Timestamp", "rtacser.timestamp", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_rtacser_event_type,
        { "Event Type", "rtacser.eventtype", FT_UINT8, BASE_HEX, VALS(rtacser_eventtype_vals), 0x0, NULL, HFILL }},
        { &hf_rtacser_ctrl_cts,
        { "CTS", "rtacser.cts", FT_UINT8, BASE_DEC, NULL, RTACSER_CTRL_CTS, NULL, HFILL }},
        { &hf_rtacser_ctrl_dcd,
        { "DCD", "rtacser.dcd", FT_UINT8, BASE_DEC, NULL, RTACSER_CTRL_DCD, NULL, HFILL }},
        { &hf_rtacser_ctrl_dsr,
        { "DSR", "rtacser.dsr", FT_UINT8, BASE_DEC, NULL, RTACSER_CTRL_DSR, NULL, HFILL }},
        { &hf_rtacser_ctrl_rts,
        { "RTS", "rtacser.rts", FT_UINT8, BASE_DEC, NULL, RTACSER_CTRL_RTS, NULL, HFILL }},
        { &hf_rtacser_ctrl_dtr,
        { "DTR", "rtacser.dtr", FT_UINT8, BASE_DEC, NULL, RTACSER_CTRL_DTR, NULL, HFILL }},
        { &hf_rtacser_ctrl_ring,
        { "RING", "rtacser.ring", FT_UINT8, BASE_DEC, NULL, RTACSER_CTRL_RING, NULL, HFILL }},
        { &hf_rtacser_ctrl_mbok,
        { "MBOK", "rtacser.mbok", FT_UINT8, BASE_DEC, NULL, RTACSER_CTRL_MBOK, NULL, HFILL }},
        { &hf_rtacser_footer,
        { "Footer", "rtacser.footer", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_rtacser_data,
        { "Payload data", "rtacser.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_rtacser,
        &ett_rtacser_cl,
   };

    module_t *rtacser_module;

    /* Register the protocol name and description */
    proto_rtacser = proto_register_protocol("RTAC Serial", "RTAC Serial", "rtacser");

    /* Registering protocol to be called by another dissector */
    new_register_dissector("rtacser", dissect_rtacser, proto_rtacser);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_rtacser, rtacser_hf, array_length(rtacser_hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register required preferences for RTAC Serial Payload Protocol */
    rtacser_module = prefs_register_protocol(proto_rtacser, proto_reg_handoff_rtacser);

    /* RTAC Serial Preference - Payload Protocol in use */
    prefs_register_enum_preference(rtacser_module, "rtacserial_payload_proto",
                                    "Payload Protocol Type",
                                    "Payload Protocol Type",
                                    &global_rtacser_payload_proto,
                                    rtacser_payload_proto_type,
                                    TRUE);


}

/******************************************************************************************************/
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
 */
/******************************************************************************************************/
void
proto_reg_handoff_rtacser(void)
{
    static int rtacser_prefs_initialized = FALSE;
    static dissector_handle_t rtacser_handle;

    /* Make sure to use RTAC Serial Protocol Preferences field to determine payload protocol to use for decoding */
    if (! rtacser_prefs_initialized) {
        rtacser_handle = new_create_dissector_handle(dissect_rtacser, proto_rtacser);
        rtacser_prefs_initialized = TRUE;
    }

    /* Create a handle for each expected payload protocol that can be called via the Preferences */
    selfm_handle = find_dissector("selfm");
    dnp3_handle = find_dissector("dnp3.udp");
    modbus_handle = find_dissector("mbrtu");
    synphasor_handle = find_dissector("synphasor");
    lg8979_handle = find_dissector("lg8979");

    dissector_add_uint("wtap_encap", WTAP_ENCAP_RTAC_SERIAL, rtacser_handle);
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
