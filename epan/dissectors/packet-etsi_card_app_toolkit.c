/* packet-card_app_toolkit
 * Routines for packet dissection of
 *	ETSI TS 102 223 v10.0.0  (Release 10 / 2010-10)
 *	3GPP TS 11.14 v8.17.0 (Release 1999 / 2004-09)
 *	3GPP TS 31.111
 * Copyright 2010-2011 by Harald Welte <laforge@gnumonks.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/lapd_sapi.h>
#include <epan/prefs.h>

#include "packet-e212.h"

static int proto_cat = -1;

static int hf_cat_tlv = -1;

static int hf_ctlv_devid_src = -1;
static int hf_ctlv_devid_dst = -1;
static int hf_ctlv_cmd_nr = -1;
static int hf_ctlv_cmd_type = -1;
static int hf_ctlv_cmd_qual = -1;
static int hf_ctlv_dur_time_intv = -1;
static int hf_ctlv_dur_time_unit = -1;
static int hf_ctlv_result_gen = -1;
static int hf_ctlv_text_string_enc = -1;
static int hf_ctlv_event = -1;
static int hf_ctlv_tone = -1;
static int hf_ctlv_loc_status = -1;
static int hf_ctlv_bearer = -1;
static int hf_ctlv_bearer_descr = -1;
static int hf_ctlv_transport_ptype = -1;
static int hf_ctlv_transport_port = -1;
static int hf_ctlv_access_tech = -1;
static int hf_ctlv_loci_lac = -1;
static int hf_ctlv_loci_cell_id = -1;

static int ett_cat = -1;
static int ett_elem = -1;


/* According to Section 7.2 of ETSI TS 101 220 / Chapter 7.2 */

#if 0
/* BER-TLV tag - Remote Management application Data templates */
static const value_string ber_tlv_rmad_tag_vals[] = {
	{ 0x01, "OMA SCWS" },
	{ 0x81, "OMA SCWS and GP 2.2 Amd. B" },
	{ 0xaa, "Command Scripting template for definite length coding" },
	{ 0xab, "Response Scripting Template for definite length coding" },
	{ 0xae, "Command Scripting template for indefinite length coding" },
	{ 0xaf, "Response Scripting Template for indefinite length coding" },
	{ 0, NULL }
};
#endif

/* Comprehension-TLV tag */
static const value_string comp_tlv_tag_vals[] = {
	{ 0x01, "Command details" },
	{ 0x02, "Device identity" },
	{ 0x03, "Result" },
	{ 0x04, "Duration" },
	{ 0x05, "Alpha identifier" },
	{ 0x06, "Address" },
	{ 0x07, "Capability configuration parameters" },
	{ 0x08, "Subaddress" },
	{ 0x09, "GSM/3G SS string" },
	{ 0x0a, "GSM/3G USSD string" },
	{ 0x0b, "GSM/3G SMS TPDU" },
	{ 0x0c, "GSM/3G Cell Broadcast page" },
	{ 0x0d, "Text string" },
	{ 0x0e, "Tone" },
	{ 0x0f, "Item" },
	{ 0x10, "Item identifier" },
	{ 0x11, "Response length" },
	{ 0x12, "File List" },
	{ 0x13, "Location Information" },
	{ 0x14, "IMEI" },
	{ 0x15, "Help request" },
	{ 0x16, "Network Measurement Results" },
	{ 0x17, "Default Text" },
	{ 0x18, "Items Next Action Indicator" },
	{ 0x19, "Event list" },
	{ 0x1a, "GSM/3G Cause" },
	{ 0x1b, "Location status" },
	{ 0x1c, "transaction identifier" },
	{ 0x1d, "GSM/3G BCCH channel list" },
	{ 0x1e, "Icon identifier" },
	{ 0x1f, "Item Icon identifier list" },
	{ 0x20, "Card reader status" },
	{ 0x21, "Card ATR" },
	{ 0x22, "C-APDU" },
	{ 0x23, "R-APDU" },
	{ 0x24, "Timer identifier" },
	{ 0x25, "Timer value" },
	{ 0x26, "Date-Time and Time zone" },
	{ 0x27, "Call control requested action" },
	{ 0x28, "AT Command" },
	{ 0x29, "AT Response" },
	{ 0x2a, "GSM/3G BC Repeat Indicator" },
	{ 0x2b, "Immedaite response" },
	{ 0x2c, "DTMF string" },
	{ 0x2d, "Language" },
	{ 0x2e, "GSM/3G Timing Advance" },
	{ 0x2f, "AID" },
	{ 0x30, "Browser Identity" },
	{ 0x31, "URL" },
	{ 0x32, "Bearer" },
	{ 0x33, "Provisioning Reference File" },
	{ 0x34, "Browser Termination Cause" },
	{ 0x35, "Bearer description" },
	{ 0x36, "Channel data" },
	{ 0x37, "Channel data length" },
	{ 0x38, "Channel status" },
	{ 0x39, "Buffer size" },
	{ 0x3a, "Card reader identifier" },
	{ 0x3b, "File Update Information" },
	{ 0x3c, "UICC/terminal interface transport level" },
	{ 0x3e, "Other address (data destination address)" },
	{ 0x3f, "Access Technology" },
	{ 0x40, "Display parameters" },
	{ 0x41, "Service Record" },
	{ 0x42, "Device Filter" },
	{ 0x43, "Service Search" },
	{ 0x44, "Attribute information" },
	{ 0x45, "Service Availability" },
	{ 0x46, "3GPP2 ESN" },
	{ 0x47, "Network Access Name" },
	{ 0x48, "3GPP2 CDMA-SMS-TPDU" },
	{ 0x49, "remote Entity Address" },
	{ 0x4a, "3GPP I-WLAN Identifier" },
	{ 0x4b, "3GPP I-WLAN Access Status" },
	{ 0x50, "Text attribute" },
	{ 0x51, "Item text attribute list" },
	{ 0x52, "3GPP PDP Context Activation parameter" },
	{ 0x53, "Contactless state request" },
	{ 0x54, "Conactless functionality state" },
	{ 0x55, "3GPP CSG cell selection status" },
	{ 0x56, "3GPP CSG ID" },
	{ 0x57, "3GPP HNB name" },
	{ 0x62, "IMEISV tag" },
	{ 0x63, "Battery state" },
	{ 0x64, "Browsing status" },
	{ 0x65, "Network Search Mode" },
	{ 0x66, "Frame Layout" },
	{ 0x67, "Frames Information" },
	{ 0x68, "Frame identifier" },
	{ 0x69, "3GPP UTRAN Measurement qualifier" },
	{ 0x6a, "Multimedia Messsage Reference" },
	{ 0x6b, "Multimedia Message Identifier" },
	{ 0x6c, "Multimedia Message Transfer Status" },
	{ 0x6d, "MEID" },
	{ 0x6e, "Multimedia Message Content Identifier" },
	{ 0x6f, "Multimedia Message Notification" },
	{ 0x70, "Last Envelope" },
	{ 0x71, "Registry application data" },
	{ 0x72, "3GPP PLMNwAcT List" },
	{ 0x73, "3GPP Routing Area Information" },
	{ 0x74, "3GPP Update/Attach Type" },
	{ 0x75, "3GPP Rejection Cause Code" },
	{ 0x76, "3GPP Geographical Location Parameters" },
	{ 0x77, "3GPP GAD Shapes" },
	{ 0x78, "3GPP NMEA sentence" },
	{ 0x79, "3GPP PLMN list" },
	{ 0x7a, "Broadcast Network Information" },
	{ 0x7b, "ACTIVATE descriptor" },
	{ 0x7c, "3GPP EPS PDN connection activation parameters" },
	{ 0x7d, "3GPP Tracking Area Identification" },
	{ 0x7e, "3GPP CSG ID list" },
	{ 0, NULL }
};

/* TS 102 223 Chapter 8.7 */
static const value_string dev_id_vals[] = {
	{ 0x01,	"Keypad" },
	{ 0x02, "Display" },
	{ 0x03, "Earpiece" },
	{ 0x10, "Additional Card Reader 0" },
	{ 0x11, "Additional Card Reader 1" },
	{ 0x12, "Additional Card Reader 2" },
	{ 0x13, "Additional Card Reader 3" },
	{ 0x14, "Additional Card Reader 4" },
	{ 0x15, "Additional Card Reader 5" },
	{ 0x16, "Additional Card Reader 6" },
	{ 0x17, "Additional Card Reader 7" },
	{ 0x21, "Channel ID 1" },
	{ 0x22, "Channel ID 2" },
	{ 0x23, "Channel ID 3" },
	{ 0x24, "Channel ID 4" },
	{ 0x25, "Channel ID 5" },
	{ 0x26, "Channel ID 6" },
	{ 0x27, "Channel ID 7" },
	{ 0x81, "SIM / USIM / UICC" },
	{ 0x82, "Terminal (Card Reader)" },
	{ 0x83, "Network" },
	{ 0, NULL }
};

/* TS 102 223 Chapter 9.4 */
static const value_string cmd_type_vals[] = {
	{ 0x01, "REFRESH" },
	{ 0x02, "MORE TIME" },
	{ 0x03, "POLL INTERVAL" },
	{ 0x04, "POLLING OFF" },
	{ 0x05, "SET UP EVENT LIST" },
	{ 0x10, "SET UP CALL" },
	{ 0x11, "GSM/3G SEND SS" },
	{ 0x12, "GSM/3G SEND USSD" },
	{ 0x13, "SEND SHORT MESSAGE" },
	{ 0x14, "SEND DTMF" },
	{ 0x15, "LAUNCH BROWSER" },
	{ 0x16, "3GPP GEOGRAPHICAL LOCATION REQUEST" },
	{ 0x20, "PLAY TONE" },
	{ 0x21, "DISPLAY TEXT" },
	{ 0x22, "GET INKEY" },
	{ 0X23, "GET INPUT" },
	{ 0x24, "SELECT ITEM" },
	{ 0X25, "SET UP MENU" },
	{ 0x26, "PROVIDE LOCAL INFORMATION" },
	{ 0x27, "TIMER MANAGEMENT" },
	{ 0x28, "SET UP IDLE MODE TEXT" },
	{ 0x30, "PERFORM CARD APDU" },
	{ 0x31, "POWER ON CARD" },
	{ 0x32, "POWER OFF CARD" },
	{ 0x33, "GET READER STATUS" },
	{ 0x34, "RUN AT COMMAND" },
	{ 0x35, "LANGUAGE NOTIFICATION" },
	{ 0x40, "OPEN CHANNEL" },
	{ 0x41, "CLOSE CHANNEL" },
	{ 0x42, "RECEIVE DATA" },
	{ 0x43, "SEND DATA" },
	{ 0x44, "GET CHANNEL STATUS" },
	{ 0x45, "SERVICE SEARCH" },
	{ 0x46, "GET SERVICE INFORMATION" },
	{ 0x47, "DECLARE SERVICE" },
	{ 0x50, "SET FRAMES" },
	{ 0x51, "GET FRAMES STATUS" },
	{ 0x60, "RETRIEVE MULTIMEDIA MESSAGE" },
	{ 0x61, "SUBMIT MULTIMEDIA MESSAGE" },
	{ 0x62, "DISPLAY MULTIMEDIA MESSAGE" },
	{ 0x70, "ACTIVATE" },
	{ 0x71, "CONTACTLESS STATE CHANGED" },
	{ 0x81, "End of the proactive session" },
	{ 0, NULL }
};

/* TS 102 223 Chapter 8.8 */
static const value_string time_unit_vals[] = {
	{ 0x00, "minutes" },
	{ 0x01, "seconds" },
	{ 0x02, "tenths of seconds" },
	{ 0, NULL }
};

/* TS 102 223 Chapter 7.12 */
static const value_string result_vals[] = {
	{ 0x00, "Command performed successfully" },
	{ 0x01, "Command performed with partial comprehension" },
	{ 0x02, "Command performed with missing information" },
	{ 0x03, "REFRESH performed with additional EFs read" },
	{ 0x04, "Command performed successfully, but requested icon could not be displayed" },
	{ 0x05, "Command performed, but modified by call control by NAA" },
	{ 0x06, "Command performed successfully, limited service" },
	{ 0x07, "Command performed with modifications" },
	{ 0x08, "REFRESH performed by indicated NAA was not active" },
	{ 0x09, "Command performed successfully, tone not played" },
	{ 0x10, "Proactive UICC session terminated by the user" },
	{ 0x11, "Backward move in the proactive UICC session requested by user" },
	{ 0x12, "No response from user" },
	{ 0x13, "Help information required by the user" },
	{ 0x20, "Terminal currently unable to process command" },
	{ 0x21, "Network currently unable to process command" },
	{ 0x22, "User did not accept the proactive command" },
	{ 0x23, "User cleared down call before connection or network refuse" },
	{ 0x24, "Action in contradiction with the current timer state" },
	{ 0x25, "Interaction with call control by NAA temporary problem" },
	{ 0x26, "Launch browser generic error code" },
	{ 0x27, "MMS temporary problem" },
	{ 0x30, "Command beyond terminal's capabilities" },
	{ 0x31, "Command type not understood by terminal" },
	{ 0x32, "Command data not understood by terminal" },
	{ 0x33, "Command number not known by terminal" },
	{ 0x36, "Error, required values are missing" },
	{ 0x38, "MultipleCard commands error" },
	{ 0x39, "Interaction with call control by NAA, permanent problem" },
	{ 0x3a, "Bearer Independent Protocol error" },
	{ 0x3b, "Access Technology unable to process command" },
	{ 0x3c, "Frames error" },
	{ 0x3d, "MMS error" },
	{ 0, NULL }
};

static const value_string text_encoding_vals[] = {
	{ 0x00, "GSM default alphabet, 7 bits packed" },
	{ 0x01, "GSM default alphabet, 8 bits" },
	{ 0x08, "UCS2" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.16 */
static const value_string tone_vals[] = {
	/* Standard supervisory tones */
	{ 0x01, "Dial tone" },
	{ 0x02, "Called subscriber busy" },
	{ 0x03, "Congestion" },
	{ 0x04, "Radio path acknowledge" },
	{ 0x05, "Radio path not available / Call dropped" },
	{ 0x06, "Error / Special information" },
	{ 0x07, "Call waiting tone" },
	{ 0x08, "Ringing tone" },
	/* Terminal proprietary tones */
	{ 0x10, "General beep" },
	{ 0x11, "Positive acknowledgement tone" },
	{ 0x12, "Negative acknowledgement or error tone" },
	{ 0x13, "Ringing tone as selected by the oser for incoming speech call" },
	{ 0x14, "Alert tone as selected by the user for incoming SMS" },
	{ 0x15, "Critical alert" },
	{ 0x20, "Vibrate only, if available" },
	/* Themed tones */
	{ 0x30, "happy tone" },
	{ 0x31, "sad tone" },
	{ 0x32, "urgent action tone" },
	{ 0x33, "question tone" },
	{ 0x34, "message received tone" },
	/* Melody tones */
	{ 0x40, "Melody 1" },
	{ 0x41, "Melody 2" },
	{ 0x42, "Melody 3" },
	{ 0x43, "Melody 4" },
	{ 0x44, "Melody 5" },
	{ 0x45, "Melody 6" },
	{ 0x46, "Melody 7" },
	{ 0x47, "Melody 8" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.25 */
static const value_string event_list_vals[] = {
	{ 0x00, "MT call" },
	{ 0x01, "Call connected" },
	{ 0x02, "Call disconnected" },
	{ 0x03, "Location status" },
	{ 0x04, "User activity" },
	{ 0x05, "Idle screen available" },
	{ 0x06, "Card reader status" },
	{ 0x07, "Language selection" },
	{ 0x08, "Browser termination" },
	{ 0x09, "Data available" },
	{ 0x0a, "Channel status" },
	{ 0x0b, "Access Technology Change (single access technology)" },
	{ 0x0c, "Display parameters changed" },
	{ 0x0d, "Local connection" },
	{ 0x0e, "Network Search Mode Change" },
	{ 0x0f, "Browsing status" },
	{ 0x10, "Frames Informations Change" },
	{ 0x11, "3GPP I-WLAN Access Status" },
	{ 0x12, "3GPP Network Rejection" },
	{ 0x13, "HCI connectivity event" },
	{ 0x14, "Access Technology Change (multiple access technologies)" },
	{ 0x15, "3GPP CSG cell selection" },
	{ 0x16, "Contactless state request" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.27 */
static const value_string loc_status_vals[] = {
	{ 0x00, "Normal service" },
	{ 0x01, "Limited service" },
	{ 0x02, "No service" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.49 + TS 11.14 Chapter 12.49 */
static const value_string bearer_vals[] = {
	{ 0x00, "SMS" },
	{ 0x01, "CSD" },
	{ 0x02, "USSD" },
	{ 0x03, "GPRS / packet switched" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.52 + TS 11.14 Chapter 12.52 */
static const value_string bearer_descr_vals[] = {
	{ 0x01, "CSD" },
	{ 0x02, "GPRS" },
	{ 0x03, "default bearer for requested transport layer" },
	{ 0x04, "local link techonlogy independent" },
	{ 0x05, "Bluetooth" },
	{ 0x06, "IrDA" },
	{ 0x07, "RS232" },
	{ 0x08, "TIA/EIA/IS-820 packet data service" },
	{ 0x09, "GSM/3GPP ???" },
	{ 0x0a, "3GPP I-WLAN" },
	{ 0x0b, "3GPP E-UTRAN / Mapped UTRAN packet service" },
	{ 0x10, "USB" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.59 + TS 11.14 Chapter 12.59 */
static const value_string transport_ptype_vals[] = {
	{ 0x01, "UDP, UICC in client mode, remote connection" },
	{ 0x02, "TCP, UICC in client mode, remote connection" },
	{ 0x03, "TCP, UICC in server mode" },
	{ 0x04, "UDP, UICC in client mode, local connection" },
	{ 0x05, "TCP, UICC in client mode, locel connection" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.61 */
static const value_string access_tech_vals[] = {
	{ 0x00, "GSM" },
	{ 0x01, "TIA/EIA-553" },
	{ 0x02, "TIA/EIA-136-C" },
	{ 0x03, "UTRAN" },
	{ 0x04, "TETRA" },
	{ 0x05, "TIE/EIA-95" },
	{ 0x06, "cdma2000 1x (TIA/EIA/IS-2000)" },
	{ 0x07, "cdma2000 HRPD (TIA/EIA/IS-856)" },
	{ 0x08, "E-UTRAN" },
	{ 0, NULL }
};

static void
dissect_cat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *cat_ti;
	proto_tree *cat_tree, *elem_tree;
	unsigned int pos = 0;

	cat_ti = proto_tree_add_item(tree, proto_cat, tvb, 0, -1, ENC_NA);
	cat_tree = proto_item_add_subtree(cat_ti, ett_cat);
	while (pos < tvb_length(tvb)) {
		proto_item *ti;
		guint8 tag, len, g8;
		void *ptr = NULL;
		unsigned int i;

		tag = tvb_get_guint8(tvb, pos++);
		len = tvb_get_guint8(tvb, pos++);

#if 1
		ti = proto_tree_add_bytes_format(cat_tree, hf_cat_tlv, tvb, pos,
					    len, ptr, "%s: %s",
					    val_to_str(tag&0x7f, comp_tlv_tag_vals, "%02x"),
					    tvb_bytes_to_str(tvb, pos, len));
#else
		ti = proto_tree_add_bytes_format(cat_tree, hf_cat_tlv, tvb, pos,
					    len, ptr, "%s:   ",
					    val_to_str(tag&0x7f, comp_tlv_tag_vals, "%02x"));
#endif
		elem_tree = proto_item_add_subtree(ti, ett_elem);

		switch (tag & 0x7f) {
		case 0x01:	/* command details */
			if (len < 3)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_cmd_nr, tvb, pos, 1, ENC_NA);
			proto_tree_add_item(elem_tree, hf_ctlv_cmd_type, tvb, pos+1, 1, ENC_NA);
			proto_tree_add_item(elem_tree, hf_ctlv_cmd_qual, tvb, pos+2, 1, ENC_NA);
			/* append command type to INFO column */
			g8 = tvb_get_guint8(tvb, pos+1);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
					val_to_str(g8, cmd_type_vals, "%02x "));
			break;
		case 0x02:	/* device identity */
			if (len < 2)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_devid_src, tvb, pos, 1, ENC_NA);
			proto_tree_add_item(elem_tree, hf_ctlv_devid_dst, tvb, pos+1, 1, ENC_NA);
			break;
		case 0x03:	/* Result */
			proto_tree_add_item(elem_tree, hf_ctlv_result_gen, tvb, pos, 1, ENC_NA);
			break;
		case 0x04:	/* Duration */
			if (len < 2)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_dur_time_intv, tvb, pos+1, 1, ENC_NA);
			proto_tree_add_item(elem_tree, hf_ctlv_dur_time_unit, tvb, pos, 1, ENC_NA);
			break;
		case 0x05:	/* alpha identifier */
			break;
		case 0x0d:	/* text string */
			/* 1st byte: encoding */
			proto_tree_add_item(elem_tree, hf_ctlv_text_string_enc, tvb, pos, 1, ENC_NA);
			g8 = tvb_get_guint8(tvb, pos);
			switch (g8) {
			case 0x04: /* 8bit */
				proto_tree_add_text(elem_tree, tvb, pos+1, len-1, "Text payload");
				break;
			case 0x00: /* 7bit */
			case 0x08: /* UCS2 */
				/* FIXME: 7bit and UCS-2 */
				break;
			}
			break;
		case 0x0e:	/* tone */
			if (len < 1)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_tone, tvb, pos, 1, ENC_NA);
			break;
		case 0x13:	/* location information */
			if (len < 7)
				break;
			/* MCC/MNC / LAC / CellID */
			dissect_e212_mcc_mnc(tvb, pinfo, elem_tree, pos, TRUE);
			proto_tree_add_item(elem_tree, hf_ctlv_loci_lac, tvb, pos+3, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(elem_tree, hf_ctlv_loci_cell_id, tvb, pos+5, 2, ENC_BIG_ENDIAN);
			break;
		case 0x19:	/* event list */
			for (i = 0; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_event, tvb, pos+i, 1, ENC_NA);
			break;
		case 0x1b:	/* location status */
			for (i = 0; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_loc_status, tvb, pos+i, 1, ENC_NA);
			break;
		case 0x32:	/* bearer */
			for (i = 0; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_bearer, tvb, pos+i, 1, ENC_NA);
			break;
		case 0x35:	/* bearer description */
			proto_tree_add_item(elem_tree, hf_ctlv_bearer, tvb, pos, 1, ENC_NA);
			for (i = 1; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_descr, tvb, pos+i, 1, ENC_NA);
			break;
		case 0x3c:	/* UICC/terminal interface transport level */
			if (len < 3)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_transport_ptype, tvb, pos, 1, ENC_NA);
			proto_tree_add_item(elem_tree, hf_ctlv_transport_port, tvb, pos+1, 2, ENC_BIG_ENDIAN);
			break;
		case 0x3f:	/* access technology */
			for (i = 1; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_access_tech, tvb, pos+i, 1, ENC_NA);
			break;
		}

		pos += len;
	}
}


void
proto_reg_handoff_card_app_toolkit(void);

void
proto_register_card_app_toolkit(void)
{
	static hf_register_info hf[] = {
		{ &hf_cat_tlv,
			{ "COMPREHENSIVE-TLV", "etsi_cat.comp_tlv",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_devid_src,
			{ "Source Device ID", "etsi_cat.comp_tlv.src_dev",
			  FT_UINT8, BASE_HEX, VALS(dev_id_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_devid_dst,
			{ "Destination Device ID", "etsi_cat.comp_tlv.dst_dev",
			  FT_UINT8, BASE_HEX, VALS(dev_id_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_nr,
			{ "Command Number", "etsi_cat.comp_tlv.cmd_nr",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_type,
			{ "Command Type", "etsi_cat.comp_tlv.cmd_type",
			  FT_UINT8, BASE_HEX, VALS(cmd_type_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_qual,
			{ "Command Qualifier", "etsi_cat.comp_tlv.cmd_qual",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dur_time_intv,
			{ "Time Interval", "etsi_cat.comp_tlv.time_interval",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dur_time_unit,
			{ "Time Unit", "etsi_cat.comp_tlv.time_unit",
			  FT_UINT8, BASE_HEX, VALS(time_unit_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_gen,
			{ "Result", "etsi_cat.comp_tlv.result",
			  FT_UINT8, BASE_HEX, VALS(result_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_text_string_enc,
			{ "Text String Encoding", "etsi_cat.comp_tlv.text_encoding",
			  FT_UINT8, BASE_HEX, VALS(text_encoding_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_event,
			{ "Event", "etsi_cat.comp_tlv.event",
			  FT_UINT8, BASE_HEX, VALS(event_list_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_tone,
			{ "Tone", "etsi_cat.comp_tlv.tone",
			  FT_UINT8, BASE_HEX, VALS(tone_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_loc_status,
			{ "Location Status", "etsi_cat.comp_tlv.loc_status",
			  FT_UINT8, BASE_HEX, VALS(loc_status_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer,
			{ "Bearer", "etsi_cat.comp_tlv.bearer",
			  FT_UINT8, BASE_HEX, VALS(bearer_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_descr,
			{ "Bearer Description", "etsi_cat.comp_tlv.bearer_descr",
			  FT_UINT8, BASE_HEX, VALS(bearer_descr_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_transport_ptype,
			{ "Transport protocol type", "etsi_cat.comp_tlv.transport.ptype",
			  FT_UINT8, BASE_HEX, VALS(transport_ptype_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_transport_port,
			{ "Transport port", "etsi_cat.comp_tlv.transport.port",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_access_tech,
			{ "Access technology", "etsi_cat.comp_tlv.access_tech",
			  FT_UINT8, BASE_HEX, VALS(access_tech_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_loci_lac,
			{ "Location Area Code", "etsi_cat.comp_tlv.loci.lac",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_loci_cell_id,
			{ "Cell ID", "etsi_cat.comp_tlv.loci.cell_id",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
	};
	static gint *ett[] = {
		&ett_cat,
		&ett_elem,
	};

	proto_cat = proto_register_protocol("Card Application Tookit ETSI TS 102.223", "ETSI CAT",
						 "etsi_cat");

	proto_register_field_array(proto_cat, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("etsi_cat", dissect_cat, proto_cat);
}

/* This function is called once at startup and every time the user hits
 * 'apply' in the preferences dialogue */
void
proto_reg_handoff_card_app_toolkit(void)
{
}
