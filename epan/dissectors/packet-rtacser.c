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
#include <epan/decode_as.h>
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

/* Initialize the subtree pointers */
static gint ett_rtacser                   = -1;
static gint ett_rtacser_cl                = -1;

static dissector_handle_t rtacser_handle;
static dissector_table_t  subdissector_table;

#define RTACSER_HEADER_LEN    12

/* Bit-masks for EIA-232 serial control lines */
#define RTACSER_CTRL_CTS      0x01
#define RTACSER_CTRL_DCD      0x02
#define RTACSER_CTRL_DSR      0x04
#define RTACSER_CTRL_RTS      0x08
#define RTACSER_CTRL_DTR      0x10
#define RTACSER_CTRL_RING     0x20
#define RTACSER_CTRL_MBOK     0x40

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

static void
rtacser_ppi_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Payload as");
}

static gpointer
rtacser_ppi_value(packet_info *pinfo _U_)
{
    return 0;
}

/******************************************************************************************************/
/* Code to dissect RTAC Serial-Line Protocol packets */
/******************************************************************************************************/
static void
dissect_rtacser_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *rtacser_item, *cl_item;
    proto_tree    *rtacser_tree, *cl_tree;
    int           offset = 0, len;
    guint         event_type;
    nstime_t      tv;
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
    tv.secs = tvb_get_ntohl(tvb, offset);
    tv.nsecs = tvb_get_ntohl(tvb, offset+4)*1000;
    proto_tree_add_time(rtacser_tree, hf_rtacser_timestamp, tvb, offset, 8, &tv);
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

    cl_tree = proto_tree_add_subtree(rtacser_tree, tvb, offset, 1, ett_rtacser_cl, &cl_item, "Control Lines");

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

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        payload_tvb = tvb_new_subset_remaining(tvb, RTACSER_HEADER_LEN);
        /* Functionality for choosing subdissector is controlled through Decode As as CAN doesn't
           have a unique identifier to determine subdissector */
        if (!dissector_try_uint(subdissector_table, 0, payload_tvb, pinfo, tree)){
            call_data_dissector(payload_tvb, pinfo, tree);
        }
    }
}



/******************************************************************************************************/
/* Dissect RTAC Serial-line protocol payload */
/******************************************************************************************************/
static int
dissect_rtacser(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint length = tvb_captured_length(tvb);

    /* Check for a RTAC Serial packet.  It should be at least 12 bytes */
    if(length < 12) {

        return 0;
    }

    dissect_rtacser_data(tvb, pinfo, tree);

    return tvb_captured_length(tvb);
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
        { "Arrived At Time", "rtacser.timestamp", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }},
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
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_rtacser,
        &ett_rtacser_cl,
    };

    static build_valid_func rtacser_da_ppi_build_value[1] = {rtacser_ppi_value};
    static decode_as_value_t rtacser_da_ppi_values[1] = {{rtacser_ppi_prompt, 1, rtacser_da_ppi_build_value}};
    static decode_as_t rtacser_da_ppi = {"rtacser", "RTAC Serial", "rtacser.data", 1, 0, rtacser_da_ppi_values, "RTAC Serial", NULL,
                                    decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    module_t *rtacser_module;

    /* Register the protocol name and description */
    proto_rtacser = proto_register_protocol("RTAC Serial", "RTAC Serial", "rtacser");

    /* Registering protocol to be called by another dissector */
    rtacser_handle = register_dissector("rtacser", dissect_rtacser, proto_rtacser);

    subdissector_table = register_dissector_table("rtacser.data", "RTAC Serial Data Subdissector", proto_rtacser, FT_UINT32, BASE_HEX);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_rtacser, rtacser_hf, array_length(rtacser_hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register required preferences for RTAC Serial Payload Protocol */
    rtacser_module = prefs_register_protocol(proto_rtacser, proto_reg_handoff_rtacser);

    /* RTAC Serial Preference - Payload Protocol in use */
    prefs_register_obsolete_preference(rtacser_module, "rtacserial_payload_proto");

    register_decode_as(&rtacser_da_ppi);
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
