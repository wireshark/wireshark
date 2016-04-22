/* packet-card_app_toolkit
 * Routines for packet dissection of
 *	ETSI TS 102 223 v12.2.0  (Release 12 / 2015-03)
 *	3GPP TS 11.14 v8.17.0 (Release 1999 / 2004-09)
 *	3GPP TS 31.111 v9.7.0 (Release 9 / 2012-03)
 * Copyright 2010-2011 by Harald Welte <laforge@gnumonks.org>
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
#include <epan/charsets.h>

#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-gsm_sms.h"

void proto_register_card_app_toolkit(void);
void proto_reg_handoff_card_app_toolkit(void);

static int proto_cat = -1;

static dissector_handle_t gsm_sms_handle;	/* SMS TPDU */

static int hf_cat_tlv = -1;

static int hf_ctlv_devid_src = -1;
static int hf_ctlv_devid_dst = -1;
static int hf_ctlv_cmd_nr = -1;
static int hf_ctlv_cmd_type = -1;
static int hf_ctlv_cmd_qual_refresh = -1;
static int hf_ctlv_cmd_qual_send_short_msg = -1;
static int hf_ctlv_cmd_qual_loci = -1;
static int hf_ctlv_cmd_qual_timer_mgmt = -1;
static int hf_ctlv_cmd_qual_send_data = -1;
static int hf_ctlv_cmd_qual = -1;
static int hf_ctlv_dur_time_unit = -1;
static int hf_ctlv_dur_time_intv = -1;
static int hf_ctlv_alpha_id_string = -1;
static int hf_ctlv_address_ton = -1;
static int hf_ctlv_address_npi = -1;
static int hf_ctlv_address_string = -1;
static int hf_ctlv_subaddress_string = -1;
static int hf_ctlv_result_gen = -1;
static int hf_ctlv_result_term = -1;
static int hf_ctlv_result_launch_browser = -1;
static int hf_ctlv_result_multiplecard = -1;
static int hf_ctlv_result_cc_ctrl_mo_sm_ctrl = -1;
static int hf_ctlv_result_bip = -1;
static int hf_ctlv_result_frames_cmd = -1;
static int hf_ctlv_text_string_enc = -1;
static int hf_ctlv_text_string = -1;
static int hf_ctlv_event = -1;
static int hf_ctlv_tone = -1;
static int hf_ctlv_item_id = -1;
static int hf_ctlv_item_string = -1;
static int hf_ctlv_loc_status = -1;
static int hf_ctlv_timer_val_hr = -1;
static int hf_ctlv_timer_val_min = -1;
static int hf_ctlv_timer_val_sec = -1;
static int hf_ctlv_date_time_yr = -1;
static int hf_ctlv_date_time_mo = -1;
static int hf_ctlv_date_time_day = -1;
static int hf_ctlv_date_time_hr = -1;
static int hf_ctlv_date_time_min = -1;
static int hf_ctlv_date_time_sec = -1;
static int hf_ctlv_date_time_tz = -1;
static int hf_ctlv_at_cmd = -1;
static int hf_ctlv_at_rsp = -1;
static int hf_ctlv_dtmf_string = -1;
static int hf_ctlv_language = -1;
static int hf_ctlv_me_status = -1;
static int hf_ctlv_timing_adv = -1;
static int hf_ctlv_aid_rid = -1;
static int hf_ctlv_aid_pix_app_code_etsi = -1;
static int hf_ctlv_aid_pix_app_code_3gpp = -1;
static int hf_ctlv_aid_pix_app_code_3gpp2 = -1;
static int hf_ctlv_aid_pix_app_code = -1;
static int hf_ctlv_aid_pix_country_code = -1;
static int hf_ctlv_aid_pix_app_prov_code = -1;
static int hf_ctlv_aid_pix_app_prov_field = -1;
static int hf_ctlv_bearer = -1;
static int hf_ctlv_bearer_descr = -1;
static int hf_ctlv_bearer_csd_data_rate = -1;
static int hf_ctlv_bearer_csd_bearer_serv = -1;
static int hf_ctlv_bearer_csd_conn_elem = -1;
static int hf_ctlv_bearer_gprs_precedence = -1;
static int hf_ctlv_bearer_gprs_delay = -1;
static int hf_ctlv_bearer_gprs_reliability = -1;
static int hf_ctlv_bearer_gprs_peak = -1;
static int hf_ctlv_bearer_gprs_mean = -1;
static int hf_ctlv_bearer_gprs_prot_type = -1;
static int hf_ctlv_bearer_utran_traffic_class = -1;
static int hf_ctlv_bearer_utran_max_bitrate_ul = -1;
static int hf_ctlv_bearer_utran_max_bitrate_dl = -1;
static int hf_ctlv_bearer_utran_guaranteed_bitrate_ul = -1;
static int hf_ctlv_bearer_utran_guaranteed_bitrate_dl = -1;
static int hf_ctlv_bearer_utran_delivery_order = -1;
static int hf_ctlv_bearer_utran_max_sdu_size = -1;
static int hf_ctlv_bearer_utran_sdu_error_ratio = -1;
static int hf_ctlv_bearer_utran_residual_bit_error_ratio = -1;
static int hf_ctlv_bearer_utran_delivery_erroneous_sdus = -1;
static int hf_ctlv_bearer_utran_transfer_delay = -1;
static int hf_ctlv_bearer_utran_traffic_handling_prio = -1;
static int hf_ctlv_bearer_utran_pdp_type = -1;
static int hf_ctlv_bearer_params = -1;
static int hf_ctlv_buffers_size = -1;
static int hf_ctlv_transport_ptype = -1;
static int hf_ctlv_transport_port = -1;
static int hf_ctlv_other_address_coding = -1;
static int hf_ctlv_other_address_ipv4 = -1;
static int hf_ctlv_other_address_ipv6 = -1;
static int hf_ctlv_access_tech = -1;
static int hf_ctlv_dns_server_address_coding = -1;
static int hf_ctlv_dns_server_address_ipv4 = -1;
static int hf_ctlv_dns_server_address_ipv6 = -1;
static int hf_ctlv_utran_eutran_meas_qual = -1;
static int hf_ctlv_upd_attach_type = -1;
static int hf_ctlv_loci_lac = -1;
static int hf_ctlv_loci_cell_id = -1;
static int hf_ctlv_loci_ext_cell_id = -1;
static int hf_ctlv_iari = -1;
static int hf_ctlv_impu = -1;
static int hf_ctlv_ims_status_code = -1;
static int hf_ctlv_broadcast_nw_tech = -1;
static int hf_ctlv_broadcast_nw_loc_info = -1;

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
	{ 0x09, "3GPP SS string" },
	{ 0x0a, "3GPP USSD string" },
	{ 0x0b, "3GPP SMS TPDU" },
	{ 0x0c, "3GPP Cell Broadcast page" },
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
	{ 0x21, "Card ATR / eCAT sequence number" },
	{ 0x22, "C-APDU / Encrypted TLV list" },
	{ 0x23, "R-APDU / SA template" },
	{ 0x24, "Timer identifier" },
	{ 0x25, "Timer value" },
	{ 0x26, "Date-Time and Time zone" },
	{ 0x27, "Call control requested action" },
	{ 0x28, "AT Command" },
	{ 0x29, "AT Response" },
	{ 0x2a, "GSM/3G BC Repeat Indicator" },
	{ 0x2b, "Immediate response" },
	{ 0x2c, "DTMF string" },
	{ 0x2d, "Language" },
	{ 0x2e, "GSM Timing Advance" },
	{ 0x2f, "AID" },
	{ 0x30, "Browser Identity" },
	{ 0x31, "URL / URI" },
	{ 0x32, "Bearer" },
	{ 0x33, "Provisioning Reference File" },
	{ 0x34, "Browser Termination Cause" },
	{ 0x35, "Bearer description" },
	{ 0x36, "Channel data" },
	{ 0x37, "Channel data length" },
	{ 0x38, "Channel status" },
	{ 0x39, "Buffer size" },
	{ 0x3a, "Card reader identifier / REFRESH Enforcement Policy" },
	{ 0x3b, "File Update Information" },
	{ 0x3c, "UICC/terminal interface transport level" },
	{ 0x3e, "Other address (data destination address)" },
	{ 0x3f, "Access Technology" },
	{ 0x40, "Display parameters / DNS server address" },
	{ 0x41, "Service Record" },
	{ 0x42, "Device Filter" },
	{ 0x43, "Service Search" },
	{ 0x44, "Attribute information" },
	{ 0x45, "Service Availability" },
	{ 0x46, "3GPP2 ESN" },
	{ 0x47, "Network Access Name" },
	{ 0x48, "3GPP2 CDMA-SMS-TPDU" },
	{ 0x49, "Remote Entity Address" },
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
	{ 0x60, "MAC" },
	{ 0x61, "Emergency Call Object" },
	{ 0x62, "IMEISV" },
	{ 0x63, "Battery state" },
	{ 0x64, "Browsing status" },
	{ 0x65, "Network Search Mode" },
	{ 0x66, "Frame Layout" },
	{ 0x67, "Frames Information" },
	{ 0x68, "Frame identifier" },
	{ 0x69, "3GPP UTRAN/E-UTRAN Measurement qualifier" },
	{ 0x6a, "Multimedia Message Reference" },
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
	{ 0x76, "3GPP Geographical Location Parameters / IARI" },
	{ 0x77, "3GPP GAD Shapes / IMPU list" },
	{ 0x78, "3GPP NMEA sentence / IMS Status-Code" },
	{ 0x79, "3GPP PLMN list" },
	{ 0x7a, "Broadcast Network Information" },
	{ 0x7b, "ACTIVATE descriptor" },
	{ 0x7c, "3GPP EPS PDN connection activation parameters" },
	{ 0x7d, "3GPP Tracking Area Identification" },
	{ 0x7e, "3GPP CSG ID list" },
	{ 0xaa, "IP address list" },
	{ 0xbb, "Surrounding macrocells" },
	{ 0, NULL }
};
static value_string_ext comp_tlv_tag_vals_ext = VALUE_STRING_EXT_INIT(comp_tlv_tag_vals);

/* TS 102 223 Chapter 8.6 */
static const value_string cmd_qual_refresh_vals[] = {
	{ 0x00,	"NAA Initialization and Full File Change Notification" },
	{ 0x01,	"File Change Notification" },
	{ 0x02, "NAA Initialization and File Change Notification" },
	{ 0x03, "NAA Initialization" },
	{ 0x04, "UICC Reset" },
	{ 0x05, "NAA Application Reset, only applicable for a 3G platform" },
	{ 0x06, "NAA Session Reset, only applicable for a 3G platform" },
	{ 0x07, "Steering of Roaming" },
	{ 0x08, "Steering of Roaming for I-WLAN" },
	{ 0, NULL }
};

static const true_false_string cmd_qual_send_short_msg_value = {
	"SMS packing by the terminal required",
	"Packing not required"
};

static const value_string cmd_qual_loci_vals[] = {
	{ 0x00,	"Location Information (MCC, MNC, LAC/TAC, Cell Identity and Extended Cell Identity)" },
	{ 0x01,	"IMEI of the terminal" },
	{ 0x02, "Network Measurement results" },
	{ 0x03, "Date, time and time zone" },
	{ 0x04, "Language setting" },
	{ 0x05, "Timing Advance" },
	{ 0x06, "Access Technology (single access technology)" },
	{ 0x07, "ESN of the terminal" },
	{ 0x08, "IMEISV of the terminal" },
	{ 0x09, "Search Mode" },
	{ 0x0a, "Charge State of the Battery" },
	{ 0x0b, "MEID of the terminal" },
	{ 0x0c, "Current WSID" },
	{ 0x0d, "Broadcast Network information according to current Broadcast Network Technology used" },
	{ 0x0e, "Multiple Access Technologies" },
	{ 0x0f, "Location Information for multiple access technologies" },
	{ 0x10, "Network Measurement results for multiple access technologies" },
	{ 0x11, "CSG ID list and corresponding HNB name" },
	{ 0x12, "H(e)NB IP address" },
	{ 0x13, "H(e)NB surrounding macrocells" },
	{ 0, NULL }
};
static value_string_ext cmd_qual_loci_vals_ext = VALUE_STRING_EXT_INIT(cmd_qual_loci_vals);

static const value_string cmd_qual_timer_mgmt_vals[] = {
	{ 0x00, "Start" },
	{ 0x01, "Deactivate" },
	{ 0x02, "Get current value" },
	{ 0, NULL }
};

static const true_false_string cmd_qual_send_data_value = {
	"Send data immediately",
	"Store data in Tx buffer"
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
	{ 0x31, "eCAT ID 1" },
	{ 0x32, "eCAT ID 2" },
	{ 0x33, "eCAT ID 3" },
	{ 0x34, "eCAT ID 4" },
	{ 0x35, "eCAT ID 5" },
	{ 0x36, "eCAT ID 6" },
	{ 0x37, "eCAT ID 7" },
	{ 0x38, "eCAT ID 8" },
	{ 0x39, "eCAT ID 9" },
	{ 0x3a, "eCAT ID 10" },
	{ 0x3b, "eCAT ID 11" },
	{ 0x3c, "eCAT ID 12" },
	{ 0x3d, "eCAT ID 13" },
	{ 0x3e, "eCAT ID 14" },
	{ 0x3f, "eCAT ID 15" },
	{ 0x81, "SIM / USIM / UICC" },
	{ 0x82, "Terminal (Card Reader)" },
	{ 0x83, "Network" },
	{ 0, NULL }
};
static value_string_ext dev_id_vals_ext = VALUE_STRING_EXT_INIT(dev_id_vals);

/* TS 102 223 Chapter 9.4 */
static const value_string cmd_type_vals[] = {
	{ 0x01, "REFRESH" },
	{ 0x02, "MORE TIME" },
	{ 0x03, "POLL INTERVAL" },
	{ 0x04, "POLLING OFF" },
	{ 0x05, "SET UP EVENT LIST" },
	{ 0x10, "SET UP CALL" },
	{ 0x11, "SEND SS" },
	{ 0x12, "SEND USSD" },
	{ 0x13, "SEND SHORT MESSAGE" },
	{ 0x14, "SEND DTMF" },
	{ 0x15, "LAUNCH BROWSER" },
	{ 0x16, "3GPP GEOGRAPHICAL LOCATION REQUEST" },
	{ 0x20, "PLAY TONE" },
	{ 0x21, "DISPLAY TEXT" },
	{ 0x22, "GET INKEY" },
	{ 0X23, "GET INPUT" },
	{ 0x24, "SELECT ITEM" },
	{ 0x25, "SET UP MENU" },
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
	{ 0x72, "COMMAND CONTAINER" },
	{ 0x73, "ENCAPSULATED SESSION CONTROL" },
	{ 0x81, "End of the proactive session" },
	{ 0, NULL }
};
static value_string_ext cmd_type_vals_ext = VALUE_STRING_EXT_INIT(cmd_type_vals);

/* TS 102 223 Chapter 8.8 */
static const value_string time_unit_vals[] = {
	{ 0x00, "minutes" },
	{ 0x01, "seconds" },
	{ 0x02, "tenths of seconds" },
	{ 0, NULL }
};

/* TS 102 223 Chapter 8.1 */
static const value_string ton_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "International Number" },
	{ 0x02, "National Number" },
	{ 0x03, "Network Specific Number" },
	{ 0, NULL }
};

/* TS 102 223 Chapter 8.1 */
static const value_string npi_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "ISDN/telephony numbering plan (Recommendation ITU-Ts E.164 and E.163" },
	{ 0x03, "Data numbering plan (Recommendation ITU-T X.121)" },
	{ 0x04, "Telex numbering plan (Recommendation ITU-T F.69)" },
	{ 0x09, "Private numbering plan" },
	{ 0x0f, "Reserved for extension" },
	{ 0, NULL }
};

/* TS 102 223 Chapter 8.12 */
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
	{ 0x14, "USSD or SS transaction terminated by the user" },
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
	{ 0x34, "SS Return Error" },
	{ 0x35, "SMS RP-ERROR" },
	{ 0x36, "Error, required values are missing" },
	{ 0x37, "USSD Return Error" },
	{ 0x38, "MultipleCard commands error" },
	{ 0x39, "Interaction with call control by USIM or MO short message control by USIM, permanent problem" },
	{ 0x3a, "Bearer Independent Protocol error" },
	{ 0x3b, "Access Technology unable to process command" },
	{ 0x3c, "Frames error" },
	{ 0x3d, "MMS error" },
	{ 0, NULL }
};
static value_string_ext result_vals_ext = VALUE_STRING_EXT_INIT(result_vals);

static const value_string result_term_vals[] = {
	{ 0x00, "No specific cause can be given" },
	{ 0x01, "Screen is busy" },
	{ 0x02, "Terminal currently busy on call" },
	{ 0x03, "ME currently busy on SS transaction" },
	{ 0x04, "No service" },
	{ 0x05, "Access control class bar" },
	{ 0x06, "Radio resource not granted" },
	{ 0x07, "Not in speech call" },
	{ 0x08, "ME currently busy on USSD transaction" },
	{ 0x09, "Terminal currently busy on SEND DTMF command" },
	{ 0x0a, "No NAA active" },
	{ 0, NULL }
};
static value_string_ext result_term_vals_ext = VALUE_STRING_EXT_INIT(result_term_vals);

static const value_string result_launch_browser_vals[] = {
	{ 0x00, "No specific cause can be given" },
	{ 0x01, "Bearer unavailable" },
	{ 0x02, "Browser unavailable" },
	{ 0x03, "Terminal unable to read the provisioning data" },
	{ 0x04, "Default URL unavailable" },
	{ 0, NULL }
};

static const value_string result_multiplecard_vals[] = {
	{ 0x00, "No specific cause can be given" },
	{ 0x01, "Card reader removed or not present" },
	{ 0x02, "Card removed or not present" },
	{ 0x03, "Card reader busy" },
	{ 0x04, "Card powered off" },
	{ 0x05, "C-APDU format error" },
	{ 0x06, "Mute card" },
	{ 0x07, "Transmission error" },
	{ 0x08, "Protocol not supported" },
	{ 0x09, "Specified reader not valid" },
	{ 0, NULL }
};
static value_string_ext result_multiplecard_vals_ext = VALUE_STRING_EXT_INIT(result_multiplecard_vals);

static const value_string result_cc_ctrl_mo_sm_ctrl_vals[] = {
	{ 0x00, "No specific cause can be given" },
	{ 0x01, "Action not allowed" },
	{ 0x02, "The type of request has changed" },
	{ 0, NULL }
};

static const value_string result_bip_vals[] = {
	{ 0x00, "No specific cause can be given" },
	{ 0x01, "No channel available" },
	{ 0x02, "Channel closed" },
	{ 0x03, "Channel identifier not valid" },
	{ 0x04, "Requested buffer size not available" },
	{ 0x05, "Security error (unsuccessful authentication)" },
	{ 0x06, "Requested UICC/terminal interface transport level not available" },
	{ 0x07, "Remote device is not reachable" },
	{ 0x08, "Service error" },
	{ 0x09, "Service identifier unknown" },
	{ 0x10, "Port not available" },
	{ 0x11, "Launch parameters missing or incorrect" },
	{ 0x12, "Application launch failed" },
	{ 0, NULL }
};
static value_string_ext result_bip_vals_ext = VALUE_STRING_EXT_INIT(result_bip_vals);

static const value_string result_frames_cmd_vals[] = {
	{ 0x00, "No specific cause can be given" },
	{ 0x01, "Frame identifier is not valid" },
	{ 0x02, "Number of frames beyond the terminal's capabilities" },
	{ 0x03, "No Frame defined" },
	{ 0x04, "Requested size not supported" },
	{ 0x05, "Default Active Frame is not valid" },
	{ 0, NULL }
};


static const range_string text_encoding_vals[] = {
	{ 0x00, 0x03, "GSM default alphabet, 7 bits packed" },
	{ 0x04, 0x07, "GSM default alphabet, 8 bits" },
	{ 0x08, 0x0b, "UCS2" },
	{ 0xf0, 0xf3, "GSM default alphabet, 7 bits packed" },
	{ 0xf4, 0xf7, "GSM default alphabet, 8 bits" },
	{ 0, 0, NULL }
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
static value_string_ext tone_vals_ext = VALUE_STRING_EXT_INIT(tone_vals);

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
	{ 0x10, "Frames Information Change" },
	{ 0x11, "I-WLAN Access Status" },
	{ 0x12, "Network Rejection" },
	{ 0x13, "HCI connectivity event" },
	{ 0x14, "Access Technology Change (multiple access technologies)" },
	{ 0x15, "CSG cell selection" },
	{ 0x16, "Contactless state request" },
	{ 0x17, "IMS Registration" },
	{ 0x18, "Incoming IMS data" },
	{ 0x19, "Profile Container" },
	{ 0x1a, "Void" },
	{ 0x1b, "Secured Profile Container" },
	{ 0x1c, "Poll Interval Negotiation" },
	{ 0, NULL }
};
static value_string_ext event_list_vals_ext = VALUE_STRING_EXT_INIT(event_list_vals);

/* TS 102 223 - Chapter 8.27 */
static const value_string loc_status_vals[] = {
	{ 0x00, "Normal service" },
	{ 0x01, "Limited service" },
	{ 0x02, "No service" },
	{ 0, NULL }
};

/* 31.111 - Chapter 8.46 */
static const value_string me_status_vals[] = {
	{ 0x00, "ME is in the idle state" },
	{ 0x01, "ME is not in idle state" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.49 + TS 11.14 Chapter 12.49 */
static const value_string bearer_vals[] = {
	{ 0x00, "SMS" },
	{ 0x01, "CSD" },
	{ 0x02, "USSD" },
	{ 0x03, "GPRS/UTRAN packet service/E-UTRAN" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.52 + TS 11.14 Chapter 12.52 */
static const value_string bearer_descr_vals[] = {
	{ 0x01, "CSD" },
	{ 0x02, "GPRS / UTRAN packet service / E-UTRAN" },
	{ 0x03, "default bearer for requested transport layer" },
	{ 0x04, "local link technology independent" },
	{ 0x05, "Bluetooth" },
	{ 0x06, "IrDA" },
	{ 0x07, "RS232" },
	{ 0x08, "TIA/EIA/IS-820 packet data service" },
	{ 0x09, "UTRAN packet service with extended parameters / HSDPA / E-UTRAN" },
	{ 0x0a, "I-WLAN" },
	{ 0x0b, "E-UTRAN / Mapped UTRAN packet service" },
	{ 0x10, "USB" },
	{ 0, NULL }
};
static value_string_ext bearer_descr_vals_ext = VALUE_STRING_EXT_INIT(bearer_descr_vals);

/* 3GPP 31.111 - Chapter 8.52 */
static const value_string csd_data_rate_vals[] = {
	{   0, "autobauding" },
	{   1, "300 bps (V.21)" },
	{   2, "1200 bps (V.22)" },
	{   3, "1200/75 bps (V.23)" },
	{   4, "2400 bps (V.22bis)" },
	{   5, "2400 bps (V.26ter)" },
	{   6, "4800 bps (V.32)" },
	{   7, "9600 bps (V.32)" },
	{  12, "9600 bps (V.34)" },
	{  14, "14400 bps (V.34)" },
	{  15, "19200 bps (V.34)" },
	{  16, "28800 bps (V.34)" },
	{  17, "33600 bps (V.34)" },
	{  34, "1200 bps (V.120)" },
	{  36, "2400 bps (V.120)" },
	{  38, "4800 bps (V.120)" },
	{  39, "9600 bps (V.120)" },
	{  43, "14400 bps (V.120)" },
	{  47, "19200 bps (V.120)" },
	{  48, "28800 bps (V.120)" },
	{  49, "38400 bps (V.120)" },
	{  50, "48000 bps (V.120)" },
	{  51, "56000 bps (V.120)" },
	{  65, "300 bps (V.110)" },
	{  66, "1200 bps (V.110)" },
	{  68, "2400 bps (V.110 or X.31 flag stuffing)" },
	{  70, "4800 bps (V.110 or X.31 flag stuffing)" },
	{  71, "9600 bps (V.110 or X.31 flag stuffing)" },
	{  75, "14400 bps (V.110 or X.31 flag stuffing)" },
	{  79, "19200 bps (V.110 or X.31 flag stuffing)" },
	{  80, "28800 bps (V.110 or X.31 flag stuffing)" },
	{  81, "38400 bps (V.110 or X.31 flag stuffing)" },
	{  82, "48000 bps (V.110 or X.31 flag stuffing)" },
	{  83, "56000 bps (V.110 or X.31 flag stuffing)" },
	{  84, "64000 bps (X.31 flag stuffing)" },
	{ 115, "56000 bps (bit transparent)" },
	{ 116, "64000 bps (bit transparent)" },
	{ 120, "32000 bps (PIAFS32k)" },
	{ 121, "64000 bps (PIAFS64k)" },
	{ 130, "28800 bps (multimedia)" },
	{ 131, "32000 bps (multimedia)" },
	{ 132, "33600 bps (multimedia)" },
	{ 133, "56000 bps (multimedia)" },
	{ 134, "64000 bps (multimedia)" },
	{   0, NULL }
};
value_string_ext csd_data_rate_vals_ext = VALUE_STRING_EXT_INIT(csd_data_rate_vals);

static const value_string csd_bearer_serv_vals[] = {
	{ 0, "Data circuit asynchronous (UDI or 3.1 kHz modem)" },
	{ 1, "Data circuit synchronous (UDI or 3.1 kHz modem)" },
	{ 2, "PAD Access (asynchronous) (UDI)" },
	{ 3, "Packet Access (synchronous) (UDI)" },
	{ 4, "Data circuit asynchronous (RDI)" },
	{ 5, "Data circuit synchronous (RDI)" },
	{ 6, "PAD Access (asynchronous) (RDI)" },
	{ 7, "Packet Access (synchronous) (RDI)" },
	{ 0, NULL }
};
static const value_string csd_conn_elem_vals[] = {
	{ 0, "Transparent" },
	{ 1, "Non-transparent" },
	{ 2, "Both, transparent preferred" },
	{ 3, "Both, non-transparent preferred" },
	{ 0, NULL }
};
static const value_string gprs_prot_type_vals[] = {
	{ 2, "IP (Internet Protocol, IETF STD 5)" },
	{ 0, NULL }
};
static const value_string utran_traffic_class_vals[] = {
	{ 0, "Conversational" },
	{ 1, "Streaming" },
	{ 2, "Interactive" },
	{ 3, "Background" },
	{ 4, "Subscribed value" },
	{ 0, NULL }
};
static const value_string utran_delivery_order_vals[] = {
	{ 0, "No" },
	{ 1, "Yes" },
	{ 2, "Subscribed value" },
	{ 0, NULL }
};
static const value_string utran_delivery_erroneous_sdus_vals[] = {
	{ 0, "No" },
	{ 1, "Yes" },
	{ 2, "No detect" },
	{ 3, "Subscribed value" },
	{ 0, NULL }
};
static const value_string pdp_type_vals[] = {
	{ 1, "X.25" },
	{ 2, "IP" },
	{ 3, "IPV6" },
	{ 4, "IPV4V6" },
	{ 5, "OSPIH" },
	{ 6, "PPP" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.58 */
static const value_string other_address_coding_vals[] = {
	{ 0x21, "IPv4 address" },
	{ 0x57, "IPv6 address" },
	{ 0, NULL }
};

/* TS 102 223 - Chapter 8.59 + TS 11.14 Chapter 12.59 */
static const value_string transport_ptype_vals[] = {
	{ 0x01, "UDP, UICC in client mode, remote connection" },
	{ 0x02, "TCP, UICC in client mode, remote connection" },
	{ 0x03, "TCP, UICC in server mode" },
	{ 0x04, "UDP, UICC in client mode, local connection" },
	{ 0x05, "TCP, UICC in client mode, local connection" },
	{ 0x06, "direct communication channel" },
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
	{ 0x09, "eHRPD" },
	{ 0, NULL }
};

/* 3GPP 31.111 - Chapter 8.73 */
static const value_string utran_eutran_meas_qual_vals[] = {
	{ 0x01, "UTRAN Intra-frequency measurements" },
	{ 0x02, "UTRAN Inter-frequency measurements" },
	{ 0x03, "UTRAN Inter-RAT (GERAN) measurements" },
	{ 0x04, "UTRAN Inter-RAT (E-UTRAN) measurements" },
	{ 0x05, "E-UTRAN Intra-frequency measurements" },
	{ 0x06, "E-UTRAN Inter-frequency measurements" },
	{ 0x07, "E-UTRAN Inter-RAT (GERAN) measurements" },
	{ 0x08, "E-UTRAN Inter-RAT (UTRAN) measurements" },
	{ 0, NULL }
};

/* ETSI 102.223 - Chapter 8.90 */
static const value_string broadcast_nw_tech_vals[] = {
	{ 0x00, "DVB-H" },
	{ 0x01, "DVB-T" },
	{ 0x02, "DVB-SH" },
	{ 0x03, "T-DMB" },
	{ 0x04, "FLO" },
	{ 0x05, "WiMAX" },
	{ 0x06, "DVB-NGH" },
	{ 0x07, "DVB-T2" },
	{ 0, NULL }
};

/* 3GPP 31.111 - Chapter 8.92 */
static const value_string upd_attach_type_vals[] = {
	{ 0x00, "\"Normal Location Updating\" in the case of a Location Updating Request message" },
	{ 0x01, "\"Periodic Updating\" in the case of a Location Updating Request message" },
	{ 0x02, "\"IMSI Attach\" in the case of a Location Updating Request message" },
	{ 0x03, "\"GPRS Attach\" in the case of a GPRS Attach Request message" },
	{ 0x04, "\"Combined GPRS/IMSI Attach\" in the case of a GPRS Attach Request message" },
	{ 0x05, "\"RA Updating\" in the case of a Routing Area Update Request message" },
	{ 0x06, "\"Combined RA/LA Updating\" in the case of a Routing Area Update Request message" },
	{ 0x07, "\"Combined RA/LA Updating with IMSI Attach\" in the case of a Routing Area Update Request message" },
	{ 0x08, "\"Periodic Updating\" in the case of a Routing Area Update Request message" },
	{ 0x09, "\"EPS Attach\" in the case of an EMM ATTACH REQUEST message" },
	{ 0x0A, "\"Combined EPS/IMSI Attach\" in the case of an EMM ATTACH REQUEST message" },
	{ 0x0B, "\"TA updating\" in the case of an EMM TRACKING AREA UPDATE REQUEST message" },
	{ 0x0C, "\"Combined TA/LA updating\" in the case of an EMM TRACKING AREA UPDATE REQUEST message" },
	{ 0x0D, "\"Combined TA/LA updating with IMSI attach\" in the case of an EMM TRACKING AREA UPDATE REQUEST message" },
	{ 0x0E, "\"Periodic updating\" in the case of an EMM TRACKING AREA UPDATE REQUEST message" },
	{ 0, NULL }
};
static value_string_ext upd_attach_type_vals_ext = VALUE_STRING_EXT_INIT(upd_attach_type_vals);

/* 3GPP 31.111 - Chapter 8.112 */
static const string_string ims_status_code[] = {
	{ "100", "Trying" },
	{ "180", "Ringing" },
	{ "181", "Call Is Being Forwarded" },
	{ "182", "Queued" },
	{ "183", "Session Progress" },
	{ "200", "OK" },
	{ "300", "Multiple Choices" },
	{ "301", "Moved Permanently" },
	{ "302", "Moved Temporarily" },
	{ "305", "Use Proxy" },
	{ "380", "Alternative Service" },
	{ "400", "Bad Request" },
	{ "401", "Unauthorized" },
	{ "402", "Payment Required" },
	{ "403", "Forbidden" },
	{ "404", "Not Found" },
	{ "405", "Method Not Allowed" },
	{ "406", "Not Acceptable" },
	{ "407", "Proxy Authentication Required" },
	{ "408", "Request Timeout" },
	{ "410", "Gone" },
	{ "413", "Request Entity Too Large" },
	{ "414", "Request-URI Too Long" },
	{ "415", "Unsupported Media Type" },
	{ "416", "Unsupported URI Scheme" },
	{ "420", "Bad Extension" },
	{ "421", "Extension Required" },
	{ "423", "Interval Too Brief" },
	{ "480", "Temporarily Unavailable" },
	{ "481", "Call/Transaction Does Not Exist" },
	{ "482", "Loop Detected" },
	{ "483", "Too Many Hops" },
	{ "484", "Address Incomplete" },
	{ "485", "Ambiguous" },
	{ "486", "Busy Here" },
	{ "487", "Request Terminated" },
	{ "488", "Not Acceptable Here" },
	{ "491", "Request Pending" },
	{ "493", "Undecipherable" },
	{ "500", "Server Internal Error" },
	{ "501", "Not Implemented" },
	{ "502", "Bad Gateway" },
	{ "503", "Service Unavailable" },
	{ "504", "Server Time-out" },
	{ "505", "Version Not Supported" },
	{ "513", "Message Too Large" },
	{ "600", "Busy Everywhere" },
	{ "603", "Decline" },
	{ "604", "Does Not Exist Anywhere" },
	{ "606", "Not Acceptable" },
	{ 0, NULL }
};

#define AID_RID_ETSI   G_GINT64_CONSTANT(0xA000000009)
#define AID_RID_3GPP   G_GINT64_CONSTANT(0xA000000087)
#define AID_RID_3GPP2  G_GINT64_CONSTANT(0xA000000343)
#define AID_RID_OMA    G_GINT64_CONSTANT(0xA000000412)
#define AID_RID_WIMAX  G_GINT64_CONSTANT(0xA000000424)

static const val64_string aid_rid_vals[] = {
	{ AID_RID_ETSI, "ETSI"},
	{ AID_RID_3GPP, "3GPP"},
	{ AID_RID_3GPP2, "3GPP2"},
	{ AID_RID_OMA, "OMA"},
	{ AID_RID_WIMAX, "WiMAX Forum"},
	{ 0, NULL}
};

static const value_string aid_pix_app_code_etsi_vals[] = {
	{ 0x0001, "GSM"},
	{ 0x0002, "GSM SIM toolkit"},
	{ 0x0003, "GSM SIM API for Java Card"},
	{ 0x0004, "TETRA"},
	{ 0x0005, "UICC API for Java Card"},
	{ 0x0101, "DVB CBMS KMS"},
	{ 0x0201, "M2MSM"},
	{ 0, NULL}
};

static const value_string aid_pix_app_code_3gpp_vals[] = {
	{ 0x1001, "3GPP UICC"},
	{ 0x1002, "3GPP USIM"},
	{ 0x1003, "3GPP USIM toolkit"},
	{ 0x1004, "3GPP ISIM"},
	{ 0x1005, "3GPP (U)SIM API for Java Card"},
	{ 0x1006, "3GPP ISIM API for Java Card"},
	{ 0x1007, "3GPP Contact Manager API for Java Card"},
	{ 0x1008, "3GPP USIM-INI"},
	{ 0x1009, "3GPP USIM-RN"},
	{ 0, NULL}
};

static const value_string aid_pix_app_code_3gpp2_vals[] = {
	{ 0x1002, "3GPP2 CSIM"},
	{ 0, NULL}
};

static void
dissect_cat_efadn_coding(tvbuff_t *tvb, proto_tree *tree, guint32 pos, guint32 len, int hf_entry)
{
	if (len) {
		guint32 i;

		guint8 first_byte = tvb_get_guint8(tvb, pos);
		if ((first_byte & 0x80) == 0) {
			wmem_strbuf_t *strbuf = wmem_strbuf_sized_new(wmem_packet_scope(), len+1, 0);
			for (i = 0; i < len; i++) {
				guint8 gsm_chars[2];
				gsm_chars[0] = tvb_get_guint8(tvb, pos+i);
				if (gsm_chars[0] == 0x1b) {
					/* Escape character */
					guint8 second_byte;
					i++;
					second_byte = tvb_get_guint8(tvb, pos+i);
					gsm_chars[0] |= second_byte << 7;
					gsm_chars[1] = second_byte >> 1;
					wmem_strbuf_append(strbuf, get_ts_23_038_7bits_string(wmem_packet_scope(), gsm_chars, 0, 2));
				} else {
					wmem_strbuf_append(strbuf, get_ts_23_038_7bits_string(wmem_packet_scope(), gsm_chars, 0, 1));
				}
			}
			proto_tree_add_string(tree, hf_entry, tvb, pos, len, wmem_strbuf_finalize(strbuf));
		} else if (first_byte == 0x80) {
			proto_tree_add_item(tree, hf_entry, tvb, pos+1, len-1, ENC_UCS_2|ENC_BIG_ENDIAN);
		} else if (first_byte == 0x81) {
			guint8 string_len = tvb_get_guint8(tvb, pos+1);
			guint16 ucs2_base = tvb_get_guint8(tvb, pos+2) << 7;
			wmem_strbuf_t *strbuf = wmem_strbuf_sized_new(wmem_packet_scope(), 2*string_len+1, 0);
			for (i = 0; i < string_len; i++) {
				guint8 byte = tvb_get_guint8(tvb, pos+3+i);
				if ((byte & 0x80) == 0) {
					guint8 gsm_chars[2];
					gsm_chars[0] = byte;
					if (gsm_chars[0] == 0x1b) {
						/* Escape character */
						guint8 second_byte;
						i++;
						second_byte = tvb_get_guint8(tvb, pos+3+i);
						gsm_chars[0] |= second_byte << 7;
						gsm_chars[1] = second_byte >> 1;
						wmem_strbuf_append(strbuf, get_ts_23_038_7bits_string(wmem_packet_scope(), gsm_chars, 0, 2));
					} else {
						wmem_strbuf_append(strbuf, get_ts_23_038_7bits_string(wmem_packet_scope(), gsm_chars, 0, 1));
					}
				} else {
					guint8 ucs2_char[2];
					ucs2_char[0] = ucs2_base >> 8;
					ucs2_char[1] = (ucs2_base & 0xff) + (byte & 0x7f);
					wmem_strbuf_append(strbuf, get_ucs_2_string(wmem_packet_scope(), ucs2_char, 2, ENC_BIG_ENDIAN));
				}
			}
			proto_tree_add_string(tree, hf_entry, tvb, pos, len, wmem_strbuf_finalize(strbuf));
		} else if (first_byte == 0x82) {
			guint8 string_len = tvb_get_guint8(tvb, pos+1);
			guint16 ucs2_base = tvb_get_ntohs(tvb, pos+2);
			wmem_strbuf_t *strbuf = wmem_strbuf_sized_new(wmem_packet_scope(), 2*string_len+1, 0);
			for (i = 0; i < string_len; i++) {
				guint8 byte = tvb_get_guint8(tvb, pos+4+i);
				if ((byte & 0x80) == 0) {
					guint8 gsm_chars[2];
					gsm_chars[0] = byte;
					if (gsm_chars[0] == 0x1b) {
						/* Escape character */
						guint8 second_byte;
						i++;
						second_byte = tvb_get_guint8(tvb, pos+4+i);
						gsm_chars[0] |= second_byte << 7;
						gsm_chars[1] = second_byte >> 1;
						wmem_strbuf_append(strbuf, get_ts_23_038_7bits_string(wmem_packet_scope(), gsm_chars, 0, 2));
					} else {
						wmem_strbuf_append(strbuf, get_ts_23_038_7bits_string(wmem_packet_scope(), gsm_chars, 0, 1));
					}
				} else {
					guint8 ucs2_char[2];
					ucs2_char[0] = ucs2_base >> 8;
					ucs2_char[1] = (ucs2_base & 0xff) + (byte & 0x7f);
					wmem_strbuf_append(strbuf, get_ucs_2_string(wmem_packet_scope(), ucs2_char, 2, ENC_BIG_ENDIAN));
				}
			}
			proto_tree_add_string(tree, hf_entry, tvb, pos, len, wmem_strbuf_finalize(strbuf));
		}
	}
}

static int
dissect_cat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_item *cat_ti;
	proto_tree *cat_tree, *elem_tree;
	unsigned int pos = 0;
	tvbuff_t *new_tvb;
	gboolean ims_event = FALSE, dns_server = FALSE;
	guint length = tvb_reported_length(tvb);
	gsm_sms_data_t sms_data = {0};

	cat_ti = proto_tree_add_item(tree, proto_cat, tvb, 0, -1, ENC_NA);
	cat_tree = proto_item_add_subtree(cat_ti, ett_cat);
	while (pos < length) {
		proto_item *ti;
		guint8 g8;
		guint16 tag;
		guint32 len, i;
		guint8 *ptr = NULL;

		tag = tvb_get_guint8(tvb, pos++) & 0x7f;
		if (tag == 0x7f) {
			tag = tvb_get_ntohs(tvb, pos) & 0x7fff;
			pos += 2;
		}
		len = tvb_get_guint8(tvb, pos++);
		switch (len) {
		case 0x81:
			len = tvb_get_guint8(tvb, pos++);
			break;
		case 0x82:
			len = tvb_get_ntohs(tvb, pos);
			pos += 2;
			break;
		case 0x83:
			len = tvb_get_ntoh24(tvb, pos);
			pos += 3;
			break;
		default:
			break;
		}

#if 1
		ti = proto_tree_add_bytes_format(cat_tree, hf_cat_tlv, tvb, pos,
					    len, ptr, "%s: %s",
					    val_to_str_ext(tag, &comp_tlv_tag_vals_ext, "%02x"),
					    (const guint8 *)tvb_bytes_to_str(wmem_packet_scope(), tvb, pos, len));
#else
		ti = proto_tree_add_bytes_format(cat_tree, hf_cat_tlv, tvb, pos,
					    len, ptr, "%s:   ",
					    val_to_str_ext(tag, &comp_tlv_tag_vals_ext, "%02x"));
#endif
		elem_tree = proto_item_add_subtree(ti, ett_elem);

		switch (tag) {
		case 0x01:	/* command details */
			if (len < 3)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_cmd_nr, tvb, pos, 1, ENC_BIG_ENDIAN);
			if (tvb_get_guint8(tvb, pos) == 0x40) {
				ims_event = TRUE;
				dns_server = TRUE;
			}
			proto_tree_add_item(elem_tree, hf_ctlv_cmd_type, tvb, pos+1, 1, ENC_BIG_ENDIAN);
			/* append command type to INFO column */
			g8 = tvb_get_guint8(tvb, pos+1);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
					val_to_str_ext(g8, &cmd_type_vals_ext, "%02x "));
			switch (g8) {
			case 0x01:
				proto_tree_add_item(elem_tree, hf_ctlv_cmd_qual_refresh, tvb, pos+2, 1, ENC_BIG_ENDIAN);
				break;
			case 0x13:
				proto_tree_add_item(elem_tree, hf_ctlv_cmd_qual_send_short_msg, tvb, pos+2, 1, ENC_NA);
				sms_data.stk_packing_required = tvb_get_guint8(tvb, pos+2) & 0x01 ? TRUE : FALSE;
				break;
			case 0x26:
				proto_tree_add_item(elem_tree, hf_ctlv_cmd_qual_loci, tvb, pos+2, 1, ENC_BIG_ENDIAN);
				break;
			case 0x27:
				proto_tree_add_item(elem_tree, hf_ctlv_cmd_qual_timer_mgmt, tvb, pos+2, 1, ENC_BIG_ENDIAN);
				break;
			case 0x43:
				proto_tree_add_item(elem_tree, hf_ctlv_cmd_qual_send_data, tvb, pos+2, 1, ENC_NA);
				break;
			default:
				proto_tree_add_item(elem_tree, hf_ctlv_cmd_qual, tvb, pos+2, 1, ENC_BIG_ENDIAN);
				break;
			}
			break;
		case 0x02:	/* device identity */
			if (len < 2)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_devid_src, tvb, pos, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(elem_tree, hf_ctlv_devid_dst, tvb, pos+1, 1, ENC_BIG_ENDIAN);
			break;
		case 0x03:	/* Result */
			g8 = tvb_get_guint8(tvb, pos);
			proto_tree_add_item(elem_tree, hf_ctlv_result_gen, tvb, pos, 1, ENC_BIG_ENDIAN);
			switch (g8) {
			case 0x20:
				proto_tree_add_item(elem_tree, hf_ctlv_result_term, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				break;
			case 0x26:
				proto_tree_add_item(elem_tree, hf_ctlv_result_launch_browser, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				break;
			case 0x38:
				proto_tree_add_item(elem_tree, hf_ctlv_result_multiplecard, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				break;
			case 0x39:
				proto_tree_add_item(elem_tree, hf_ctlv_result_cc_ctrl_mo_sm_ctrl, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				break;
			case 0x3a:
				proto_tree_add_item(elem_tree, hf_ctlv_result_bip, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				break;
			case 0x3c:
				proto_tree_add_item(elem_tree, hf_ctlv_result_frames_cmd, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				break;
			default:
				break;
			}
			break;
		case 0x04:	/* Duration */
			if (len < 2)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_dur_time_unit, tvb, pos, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(elem_tree, hf_ctlv_dur_time_intv, tvb, pos+1, 1, ENC_BIG_ENDIAN);
			break;
		case 0x05:	/* alpha identifier */
			dissect_cat_efadn_coding(tvb, elem_tree, pos, len, hf_ctlv_alpha_id_string);
			break;
		case 0x06:	/* address */
			proto_tree_add_item(elem_tree, hf_ctlv_address_ton, tvb, pos, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(elem_tree, hf_ctlv_address_npi, tvb, pos, 1, ENC_BIG_ENDIAN);
			dissect_cat_efadn_coding(tvb, elem_tree, pos+1, len-1, hf_ctlv_address_string);
			break;
		case 0x08:	/* subaddress */
			dissect_cat_efadn_coding(tvb, elem_tree, pos, len, hf_ctlv_subaddress_string);
			break;
		case 0x0b:	/* sms tpdu */
			new_tvb = tvb_new_subset_length(tvb, pos, len);
			if (new_tvb) {
				int p2p_dir_save = pinfo->p2p_dir;
				if (data) {
					if (GPOINTER_TO_INT(data) == 0xd0) {
						/* Proactive command */
						pinfo->p2p_dir = P2P_DIR_RECV;
					} else {
						pinfo->p2p_dir = P2P_DIR_SENT;
					}
				}
				call_dissector_only(gsm_sms_handle, new_tvb, pinfo, elem_tree, &sms_data);
				pinfo->p2p_dir = p2p_dir_save;
			}
			break;
		case 0x0d:	/* text string */
			if (len == 0)
				break;
			/* 1st byte: encoding */
			proto_tree_add_item(elem_tree, hf_ctlv_text_string_enc, tvb, pos, 1, ENC_BIG_ENDIAN);
			g8 = tvb_get_guint8(tvb, pos);
			switch (g8 & 0xf0) {
			case 0x00:
				g8 &= 0x0c;
				break;
			case 0xf0:
				g8 &= 0x04;
				break;
			default:
				break;
			}
			switch (g8) {
			case 0x00: /* 7bit */
				proto_tree_add_item(elem_tree, hf_ctlv_text_string, tvb, pos+1, len-1, ENC_3GPP_TS_23_038_7BITS|ENC_NA);
				break;
			case 0x04: /* 8bit */
				/* XXX - ASCII, or some extended ASCII? */
				proto_tree_add_item(elem_tree, hf_ctlv_text_string, tvb, pos+1, len-1, ENC_ASCII|ENC_NA);
				break;
			case 0x08: /* UCS2 */
				proto_tree_add_item(elem_tree, hf_ctlv_text_string, tvb, pos+1, len-1, ENC_UCS_2|ENC_BIG_ENDIAN);
				break;
			default:
				break;
			}
			break;
		case 0x0e:	/* tone */
			if (len < 1)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_tone, tvb, pos, 1, ENC_BIG_ENDIAN);
			break;
		case 0x0f:	/* item */
			if (len) {
				proto_tree_add_item(elem_tree, hf_ctlv_item_id, tvb, pos, 1, ENC_BIG_ENDIAN);
				dissect_cat_efadn_coding(tvb, elem_tree, pos+1, len-1, hf_ctlv_item_string);
			}
			break;
		case 0x13:	/* location information */
			if (len == 0)
				break;
			/* MCC/MNC / LAC / CellID */
			dissect_e212_mcc_mnc(tvb, pinfo, elem_tree, pos, E212_NONE, TRUE);
			proto_tree_add_item(elem_tree, hf_ctlv_loci_lac, tvb, pos+3, 2, ENC_BIG_ENDIAN);
			if (len == 5)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_loci_cell_id, tvb, pos+5, 2, ENC_BIG_ENDIAN);
			if (len == 7)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_loci_ext_cell_id, tvb, pos+7, 2, ENC_BIG_ENDIAN);
			break;
		case 0x14:	/* IMEI */
		case 0x62:	/* IMEISV */
			de_mid(tvb, elem_tree, pinfo, pos, len, NULL, 0);
			break;
		case 0x19:	/* event list */
			for (i = 0; i < len; i++) {
				guint8 event = tvb_get_guint8(tvb, pos+i);
				if ((event == 0x17) || (event == 0x18)) {
					ims_event = TRUE;
				}
				proto_tree_add_uint(elem_tree, hf_ctlv_event, tvb, pos+i, 1, event);
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
						val_to_str_ext(event, &event_list_vals_ext, "%02x "));
			}
			break;
		case 0x1b:	/* location status */
			for (i = 0; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_loc_status, tvb, pos+i, 1, ENC_BIG_ENDIAN);
			break;
		case 0x25:	/* timer value */
			{
				guint8 oct;
				oct = tvb_get_guint8(tvb, pos);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_timer_val_hr, tvb, pos, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+1);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_timer_val_min, tvb, pos+1, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+2);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_timer_val_sec, tvb, pos+2, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
			}
			break;
		case 0x26:	/* date-time and time zone */
			{
				guint8 oct, tz;
				oct = tvb_get_guint8(tvb, pos);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_yr, tvb, pos, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+1);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_mo, tvb, pos+1, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+2);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_day, tvb, pos+2, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+3);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_hr, tvb, pos+3, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+4);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_min, tvb, pos+4, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+5);
				proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_sec, tvb, pos+5, 1, oct, "%u (0x%02x)", 10*(oct&0x0f)+(oct>>4), oct);
				oct = tvb_get_guint8(tvb, pos+6);
				if (oct == 0xff) {
					proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_tz, tvb, pos+6, 1, oct, "Unknown (0x%02x)", oct);
				} else {
					tz = (oct >> 4) + (oct & 0x07) * 10;
					proto_tree_add_uint_format_value(elem_tree, hf_ctlv_date_time_tz, tvb, pos+6, 1, oct, "GMT %c %d hr %d min (0x%02x)",
					(oct & 0x08)?'-':'+', tz/4, (tz%4)*15, oct);
				}
			}
			break;
		case 0x28:	/* AT Command */
			proto_tree_add_item(elem_tree, hf_ctlv_at_cmd, tvb, pos, len, ENC_ASCII|ENC_NA);
			break;
		case 0x29:	/* AT Response */
			proto_tree_add_item(elem_tree, hf_ctlv_at_rsp, tvb, pos, len, ENC_ASCII|ENC_NA);
			break;
		case 0x2c:	/* DTMF string */
			dissect_cat_efadn_coding(tvb, elem_tree, pos, len, hf_ctlv_dtmf_string);
			break;
		case 0x2d:	/* language */
			proto_tree_add_item(elem_tree, hf_ctlv_language, tvb, pos, len, ENC_ASCII|ENC_NA);
			break;
		case 0x2e:	/* Timing Advance */
			proto_tree_add_item(elem_tree, hf_ctlv_me_status, tvb, pos, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(elem_tree, hf_ctlv_timing_adv, tvb, pos+1, 1, ENC_BIG_ENDIAN);
			break;
		case 0x2f:	/* AID */
			{
				guint64 rid = tvb_get_ntoh40(tvb, pos);

				proto_tree_add_uint64(elem_tree, hf_ctlv_aid_rid, tvb, pos, 5, rid);
				if (rid == AID_RID_ETSI) {
					proto_tree_add_item(elem_tree, hf_ctlv_aid_pix_app_code_etsi, tvb, pos+5, 2, ENC_BIG_ENDIAN);
				} else if (rid == AID_RID_3GPP) {
					proto_tree_add_item(elem_tree, hf_ctlv_aid_pix_app_code_3gpp, tvb, pos+5, 2, ENC_BIG_ENDIAN);
				} else if (rid == AID_RID_3GPP2) {
					proto_tree_add_item(elem_tree, hf_ctlv_aid_pix_app_code_3gpp2, tvb, pos+5, 2, ENC_BIG_ENDIAN);
				} else {
					proto_tree_add_item(elem_tree, hf_ctlv_aid_pix_app_code, tvb, pos+5, 2, ENC_BIG_ENDIAN);
				}
				proto_tree_add_item(elem_tree, hf_ctlv_aid_pix_country_code, tvb, pos+7, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_aid_pix_app_prov_code, tvb, pos+9, 3, ENC_BIG_ENDIAN);
				if (len > 12) {
					proto_tree_add_item(elem_tree, hf_ctlv_aid_pix_app_prov_field, tvb, pos+12, len-12, ENC_NA);
				}
			}
			break;
		case 0x32:	/* bearer */
			for (i = 0; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_bearer, tvb, pos+i, 1, ENC_BIG_ENDIAN);
			break;
		case 0x35:	/* bearer description */
			g8 = tvb_get_guint8(tvb, pos);
			proto_tree_add_uint(elem_tree, hf_ctlv_bearer_descr, tvb, pos, 1, g8);
			switch (g8) {
			case 0x01:
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_csd_data_rate, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_csd_bearer_serv, tvb, pos+2, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_csd_conn_elem, tvb, pos+3, 1, ENC_BIG_ENDIAN);
				break;
			case 0x02:
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_gprs_precedence, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_gprs_delay, tvb, pos+2, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_gprs_reliability, tvb, pos+3, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_gprs_peak, tvb, pos+4, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_gprs_mean, tvb, pos+5, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_gprs_prot_type, tvb, pos+6, 1, ENC_BIG_ENDIAN);
				break;
			case 0x09:
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_traffic_class, tvb, pos+1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_max_bitrate_ul, tvb, pos+2, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_max_bitrate_dl, tvb, pos+4, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_guaranteed_bitrate_ul, tvb, pos+6, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_guaranteed_bitrate_dl, tvb, pos+8, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_delivery_order, tvb, pos+10, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_max_sdu_size, tvb, pos+11, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_sdu_error_ratio, tvb, pos+12, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_residual_bit_error_ratio, tvb, pos+13, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_delivery_erroneous_sdus, tvb, pos+14, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_transfer_delay, tvb, pos+15, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_traffic_handling_prio, tvb, pos+16, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_pdp_type, tvb, pos+1, 17, ENC_BIG_ENDIAN);
				break;
			case 0x0a:
				break;
			case 0x0b:
				de_esm_qos(tvb, elem_tree, pinfo, pos+1, len-2, NULL, 0);
				proto_tree_add_item(elem_tree, hf_ctlv_bearer_utran_pdp_type, tvb, pos+len-1, 1, ENC_BIG_ENDIAN);
				break;
			default:
				if (len > 1) {
					proto_tree_add_item(elem_tree, hf_ctlv_bearer_params, tvb, pos+1, len-1, ENC_NA);
				}
				break;
			}
			break;
		case 0x39:	/* buffer size */
			proto_tree_add_item(elem_tree, hf_ctlv_buffers_size, tvb, pos, 2, ENC_BIG_ENDIAN);
			break;
		case 0x3c:	/* UICC/terminal interface transport level */
			if (len < 3)
				break;
			proto_tree_add_item(elem_tree, hf_ctlv_transport_ptype, tvb, pos, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(elem_tree, hf_ctlv_transport_port, tvb, pos+1, 2, ENC_BIG_ENDIAN);
			break;
		case 0x3e:	/* other address */
			g8 = tvb_get_guint8(tvb, pos);
			proto_tree_add_uint(elem_tree, hf_ctlv_other_address_coding, tvb, pos, 1, g8);
			switch (g8) {
			case 0x21:
				proto_tree_add_item(elem_tree, hf_ctlv_other_address_ipv4, tvb, pos+1, 4, ENC_NA);
				break;
			case 0x57:
				proto_tree_add_item(elem_tree, hf_ctlv_other_address_ipv6, tvb, pos+1, 16, ENC_NA);
				break;
			default:
				break;
			}
			break;
		case 0x3f:	/* access technology */
			for (i = 0; i < len; i++)
				proto_tree_add_item(elem_tree, hf_ctlv_access_tech, tvb, pos+i, 1, ENC_BIG_ENDIAN);
			break;
		case 0x40:	/* Display parameters / DNS server address */
			if (dns_server) {
				g8 = tvb_get_guint8(tvb, pos);
				proto_tree_add_uint(elem_tree, hf_ctlv_dns_server_address_coding, tvb, pos, 1, g8);
				switch (g8) {
				case 0x21:
					proto_tree_add_item(elem_tree, hf_ctlv_dns_server_address_ipv4, tvb, pos+1, 4, ENC_NA);
					break;
				case 0x57:
					proto_tree_add_item(elem_tree, hf_ctlv_dns_server_address_ipv6, tvb, pos+1, 16, ENC_NA);
					break;
				default:
					break;
				}
			}
			break;
		case 0x47:	/* network access name */
			de_sm_apn(tvb, elem_tree, pinfo, pos, len, NULL, 0);
			break;
		case 0x69:	/* UTRAN EUTRAN measurement qualifier */
			proto_tree_add_item(elem_tree, hf_ctlv_utran_eutran_meas_qual, tvb, pos, 1, ENC_BIG_ENDIAN);
			break;
		case 0x73:	/* Routing Area Information */
			de_gmm_rai(tvb, elem_tree, pinfo, pos, len, NULL, 0);
			break;
		case 0x74:	/* Update/Attach Type */
			proto_tree_add_item(elem_tree, hf_ctlv_upd_attach_type, tvb, pos, 1, ENC_BIG_ENDIAN);
			break;
		case 0x76:	/* Geographical Location Parameters / IARI */
			if (ims_event) {
				proto_tree_add_item(elem_tree, hf_ctlv_iari, tvb, pos, len, ENC_UTF_8 | ENC_NA);
			}
			break;
		case 0x77:	/* GAD Shapes / IMPU list */
			if (ims_event) {
				i = 0;
				while (i < len) {
					if (tvb_get_guint8(tvb, pos+i) == 0x80) {
						g8 = tvb_get_guint8(tvb, pos+i+1);
						proto_tree_add_item(elem_tree, hf_ctlv_impu, tvb, pos+i+2, g8, ENC_UTF_8 | ENC_NA);
						i += 2+g8;
					} else {
						break;
					}
				}
			}
			break;
		case 0x78:	/* NMEA sentence / IMS Status-Code */
			if (ims_event) {
				guint8 *status_code = tvb_get_string_enc(wmem_packet_scope(), tvb, pos, len, ENC_ASCII);
				proto_tree_add_string_format_value(elem_tree, hf_ctlv_ims_status_code, tvb, pos, len,
					status_code, "%s (%s)", status_code, str_to_str(status_code, ims_status_code, "Unknown"));
			}
			break;
		case 0x79:	/* PLMN list */
			for (i = 0; i < len; i+=3) {
				dissect_e212_mcc_mnc(tvb, pinfo, elem_tree, pos+3*i, E212_NONE, TRUE);
			}
			break;
		case 0x7a:/* Broadcast Network Information */
			proto_tree_add_item(elem_tree, hf_ctlv_broadcast_nw_tech, tvb, pos, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(elem_tree, hf_ctlv_broadcast_nw_loc_info, tvb, pos+1, len-1, ENC_NA);
			break;
		case 0x7c:	/* EPS PDN connection activation parameters */
			nas_esm_pdn_con_req(tvb, elem_tree, pinfo, pos, len);
			break;
		case 0x7d:	/* Tracking Area Identification */
			de_emm_trac_area_id(tvb, elem_tree, pinfo, pos, 5, NULL, 0);
			break;
		default:
			break;
		}
		pos += len;
	}
	return length;
}

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
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dev_id_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_devid_dst,
			{ "Destination Device ID", "etsi_cat.comp_tlv.dst_dev",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dev_id_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_nr,
			{ "Command Number", "etsi_cat.comp_tlv.cmd_nr",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_type,
			{ "Command Type", "etsi_cat.comp_tlv.cmd_type",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &cmd_type_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_qual_refresh,
			{ "Command Qualifier", "etsi_cat.comp_tlv.cmd_qual.refresh",
			  FT_UINT8, BASE_HEX, VALS(cmd_qual_refresh_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_qual_send_short_msg,
			{ "Command Qualifier", "etsi_cat.comp_tlv.cmd_qual.send_short_msg",
			  FT_BOOLEAN, 8, TFS(&cmd_qual_send_short_msg_value), 0x01,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_qual_loci,
			{ "Command Qualifier", "etsi_cat.comp_tlv.cmd_qual.loci",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &cmd_qual_loci_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_qual_timer_mgmt,
			{ "Command Qualifier", "etsi_cat.comp_tlv.cmd_qual.timer_mgmt",
			  FT_UINT8, BASE_HEX, VALS(cmd_qual_timer_mgmt_vals), 0x03,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_qual_send_data,
			{ "Command Qualifier", "etsi_cat.comp_tlv.cmd_qual.send_data",
			  FT_BOOLEAN, 8, TFS(&cmd_qual_send_data_value), 0x01,
			  NULL, HFILL },
		},
		{ &hf_ctlv_cmd_qual,
			{ "Command Qualifier", "etsi_cat.comp_tlv.cmd_qual",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dur_time_unit,
			{ "Time Unit", "etsi_cat.comp_tlv.time_unit",
			  FT_UINT8, BASE_HEX, VALS(time_unit_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dur_time_intv,
			{ "Time Interval", "etsi_cat.comp_tlv.time_interval",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_alpha_id_string,
			{ "Alpha Identifier String", "etsi_cat.comp_tlv.alpha_id.string",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_address_ton,
			{ "TON", "etsi_cat.comp_tlv.address.ton",
			  FT_UINT8,  BASE_HEX, VALS(ton_vals), 0x70,
			  NULL, HFILL },
		},
		{ &hf_ctlv_address_npi,
			{ "NPI", "etsi_cat.comp_tlv.address.npi",
			  FT_UINT8,  BASE_HEX, VALS(npi_vals), 0x0f,
			  NULL, HFILL },
		},
		{ &hf_ctlv_address_string,
			{ "Address String", "etsi_cat.comp_tlv.address.string",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_subaddress_string,
			{ "Subaddress String", "etsi_cat.comp_tlv.subaddress.string",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_gen,
			{ "Result", "etsi_cat.comp_tlv.result",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &result_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_term,
			{ "Additional information", "etsi_cat.comp_tlv.result.term",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &result_term_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_launch_browser,
			{ "Additional information", "etsi_cat.comp_tlv.result.launch_browser",
			  FT_UINT8, BASE_HEX, VALS(result_launch_browser_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_multiplecard,
			{ "Additional information", "etsi_cat.comp_tlv.result.multiplecard",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &result_multiplecard_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_cc_ctrl_mo_sm_ctrl,
			{ "Additional information", "etsi_cat.comp_tlv.result.cc_ctrl_mo_sm_ctrl",
			  FT_UINT8, BASE_HEX, VALS(result_cc_ctrl_mo_sm_ctrl_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_bip,
			{ "Additional information", "etsi_cat.comp_tlv.result.bip",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &result_bip_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_result_frames_cmd,
			{ "Additional information", "etsi_cat.comp_tlv.result.frames_cmd",
			  FT_UINT8, BASE_HEX, VALS(result_frames_cmd_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_text_string_enc,
			{ "Text String Encoding", "etsi_cat.comp_tlv.text_encoding",
			  FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(text_encoding_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_text_string,
			{ "Text String", "etsi_cat.comp_tlv.text",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_event,
			{ "Event", "etsi_cat.comp_tlv.event",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &event_list_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_tone,
			{ "Tone", "etsi_cat.comp_tlv.tone",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &tone_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_item_id,
			{ "Item Identifier", "etsi_cat.comp_tlv.item.id",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_item_string,
			{ "Item String", "etsi_cat.comp_tlv.item.string",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_loc_status,
			{ "Location Status", "etsi_cat.comp_tlv.loc_status",
			  FT_UINT8, BASE_HEX, VALS(loc_status_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_timer_val_hr,
			{ "Hours", "etsi_cat.comp_tlv.timer_val.hr",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_timer_val_min,
			{ "Minutes", "etsi_cat.comp_tlv.timer_val.min",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_timer_val_sec,
			{ "Seconds", "etsi_cat.comp_tlv.timer_val.sec",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_date_time_yr,
			{ "Year", "etsi_cat.comp_tlv.date_time.yr",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_date_time_mo,
			{ "Month", "etsi_cat.comp_tlv.date_time.mo",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_date_time_day,
			{ "Day", "etsi_cat.comp_tlv.date_time.day",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_date_time_hr,
			{ "Hours", "etsi_cat.comp_tlv.date_time.hr",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_date_time_min,
			{ "Minutes", "etsi_cat.comp_tlv.date_time.min",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_date_time_sec,
			{ "Seconds", "etsi_cat.comp_tlv.date_time.sec",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_date_time_tz,
			{ "Time Zone", "etsi_cat.comp_tlv.date_time.tz",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_at_cmd,
			{ "AT Command", "etsi_cat.comp_tlv.at_cmd",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_at_rsp,
			{ "AT Response", "etsi_cat.comp_tlv.at_rsp",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dtmf_string,
			{ "DMTF String", "etsi_cat.comp_tlv.dtmf.string",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_language,
			{ "Language", "etsi_cat.comp_tlv.language",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_me_status,
			{ "ME Status", "etsi_cat.comp_tlv.me_status",
			  FT_UINT8, BASE_DEC, VALS(me_status_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_timing_adv,
			{ "Timing Advance", "etsi_cat.comp_tlv.timing_adv",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_rid,
			{ "RID", "etsi_cat.comp_tlv.aid.rid",
			  FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(aid_rid_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_pix_app_code_etsi,
			{ "PIX Application Code", "etsi_cat.comp_tlv.aid.pix.app_code",
			  FT_UINT16, BASE_HEX, VALS(aid_pix_app_code_etsi_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_pix_app_code_3gpp,
			{ "PIX Application Code", "etsi_cat.comp_tlv.aid.pix.app_code",
			  FT_UINT16, BASE_HEX, VALS(aid_pix_app_code_3gpp_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_pix_app_code_3gpp2,
			{ "PIX Application Code", "etsi_cat.comp_tlv.aid.pix.app_code",
			  FT_UINT16, BASE_HEX, VALS(aid_pix_app_code_3gpp2_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_pix_app_code,
			{ "PIX Application Code", "etsi_cat.comp_tlv.aid.pix.app_code",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_pix_country_code,
			{ "PIX Country Code", "etsi_cat.comp_tlv.aid.pix.country_code",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_pix_app_prov_code,
			{ "PIX Application Provider Code", "etsi_cat.comp_tlv.aid.pix.app_prov_code",
			  FT_UINT24, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_aid_pix_app_prov_field,
			{ "PIX Application Provider Field", "etsi_cat.comp_tlv.aid.pix.app_prov_field",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer,
			{ "Bearer", "etsi_cat.comp_tlv.bearer",
			  FT_UINT8, BASE_HEX, VALS(bearer_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_descr,
			{ "Bearer Description", "etsi_cat.comp_tlv.bearer.descr",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bearer_descr_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_csd_data_rate,
			{ "Data Rate", "etsi_cat.comp_tlv.bearer.csd.data_rate",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &csd_data_rate_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_csd_bearer_serv,
			{ "Bearer Service", "etsi_cat.comp_tlv.bearer.csd.bearer_serv",
			  FT_UINT8, BASE_DEC, VALS(csd_bearer_serv_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_csd_conn_elem,
			{ "Connection Element", "etsi_cat.comp_tlv.bearer.csd.conn_elem",
			  FT_UINT8, BASE_DEC, VALS(csd_conn_elem_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_gprs_precedence,
			{ "Precedence Class", "etsi_cat.comp_tlv.bearer.gprs.precedence",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_gprs_delay,
			{ "Delay Class", "etsi_cat.comp_tlv.bearer.gprs.delay",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_gprs_reliability,
			{ "Reliability Class", "etsi_cat.comp_tlv.bearer.gprs.reliability",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_gprs_peak,
			{ "Peak Throughput Class", "etsi_cat.comp_tlv.bearer.gprs.peak",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_gprs_mean,
			{ "Mean Throughput Class", "etsi_cat.comp_tlv.bearer.gprs.mean",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_gprs_prot_type,
			{ "Packet Data Protocol Type", "etsi_cat.comp_tlv.bearer.gprs.prot_type",
			  FT_UINT8, BASE_DEC, VALS(gprs_prot_type_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_traffic_class,
			{ "Traffic Class", "etsi_cat.comp_tlv.bearer.utran.traffic_class",
			  FT_UINT8, BASE_DEC, VALS(utran_traffic_class_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_max_bitrate_ul,
			{ "Maximum Bitrate UL", "etsi_cat.comp_tlv.bearer.utran.max_bitrate_ul",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_max_bitrate_dl,
			{ "Maximum Bitrate DL", "etsi_cat.comp_tlv.bearer.utran.max_bitrate_dl",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_guaranteed_bitrate_ul,
			{ "Guaranteed Bitrate DL", "etsi_cat.comp_tlv.bearer.utran.guaranteed_bitrate_ul",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_guaranteed_bitrate_dl,
			{ "Guaranteed Bitrate DL", "etsi_cat.comp_tlv.bearer.utran.guaranteed_bitrate_dl",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_delivery_order,
			{ "Delivery Order", "etsi_cat.comp_tlv.bearer.utran.delivery_order",
			  FT_UINT8, BASE_DEC, VALS(utran_delivery_order_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_max_sdu_size,
			{ "Maximum SDU Size", "etsi_cat.comp_tlv.bearer.utran.max_sdu_size",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_sdu_error_ratio,
			{ "SDU Error Ratio", "etsi_cat.comp_tlv.bearer.utran.sdu_error_ratio",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_residual_bit_error_ratio,
			{ "Residual Bit Error Ratio", "etsi_cat.comp_tlv.bearer.utran.residual_bit_error_ratio",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_delivery_erroneous_sdus,
			{ "Delivery of Erroneous SDUs", "etsi_cat.comp_tlv.bearer.utran.delivery_erroneous_sdus",
			  FT_UINT8, BASE_DEC, VALS(utran_delivery_erroneous_sdus_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_transfer_delay,
			{ "Transfer Delay", "etsi_cat.comp_tlv.bearer.utran.transfer_delay",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_traffic_handling_prio,
			{ "Traffic Handling Priority", "etsi_cat.comp_tlv.bearer.utran.traffic_handling_prio",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_utran_pdp_type,
			{ "PDP Type", "etsi_cat.comp_tlv.bearer.utran.pdp_type",
			  FT_UINT8, BASE_DEC, VALS(pdp_type_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_bearer_params,
			{ "Bearer Parameters", "etsi_cat.comp_tlv.bearer.params",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_buffers_size,
			{ "Buffer Size", "etsi_cat.comp_tlv.buffer_size",
			  FT_UINT16, BASE_DEC, NULL, 0,
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
		{ &hf_ctlv_other_address_coding,
			{ "Coding of Type of address", "etsi_cat.comp_tlv.other_address.coding",
			  FT_UINT8, BASE_HEX, VALS(other_address_coding_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_other_address_ipv4,
			{ "IPv4 address", "etsi_cat.comp_tlv.other_address.ipv4",
			  FT_IPv4, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_other_address_ipv6,
			{ "IPv6 address", "etsi_cat.comp_tlv.other_address.ipv6",
			  FT_IPv6, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_access_tech,
			{ "Access technology", "etsi_cat.comp_tlv.access_tech",
			  FT_UINT8, BASE_HEX, VALS(access_tech_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dns_server_address_coding,
			{ "Type of address", "etsi_cat.comp_tlv.dns_server_address.coding",
			  FT_UINT8, BASE_HEX, VALS(other_address_coding_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dns_server_address_ipv4,
			{ "IPv4 address", "etsi_cat.comp_tlv.dns_server_address.ipv4",
			  FT_IPv4, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_dns_server_address_ipv6,
			{ "IPv6 address", "etsi_cat.comp_tlv.dns_server_address.ipv6",
			  FT_IPv6, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_utran_eutran_meas_qual,
			{ "UTRAN/E-UTRAN Measurement Qualifier", "etsi_cat.comp_tlv.utran_eutran_meas_qual",
			  FT_UINT8, BASE_HEX, VALS(utran_eutran_meas_qual_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_upd_attach_type,
			{ "UTRAN/E-UTRAN Measurement Qualifier", "etsi_cat.comp_tlv.upd_attach_type",
			  FT_UINT8, BASE_HEX | BASE_EXT_STRING, &upd_attach_type_vals_ext, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_loci_lac,
			{ "Location Area Code / Tracking Area Code", "etsi_cat.comp_tlv.loci.lac",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_loci_cell_id,
			{ "Cell ID", "etsi_cat.comp_tlv.loci.cell_id",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_loci_ext_cell_id,
			{ "Extended Cell ID", "etsi_cat.comp_tlv.loci.ext_cell_id",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_iari,
			{ "IARI", "etsi_cat.comp_tlv.iari",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_impu,
			{ "IMPU", "etsi_cat.comp_tlv.impu",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_ims_status_code,
			{ "IMS Status-Code", "etsi_cat.comp_tlv.ims_status_code",
			  FT_STRING, STR_UNICODE, NULL, 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_broadcast_nw_tech,
			{ "Broadcast Network Technology", "etsi_cat.comp_tlv.broadcast_nw.tech",
			  FT_UINT8, BASE_HEX, VALS(broadcast_nw_tech_vals), 0,
			  NULL, HFILL },
		},
		{ &hf_ctlv_broadcast_nw_loc_info,
			{ "Broadcast Network Location Information", "etsi_cat.comp_tlv.broadcast_nw.loc_info",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL },
		}
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

void
proto_reg_handoff_card_app_toolkit(void)
{
	gsm_sms_handle = find_dissector_add_dependency("gsm_sms", proto_cat);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
