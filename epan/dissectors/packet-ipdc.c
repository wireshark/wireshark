/* packet-ipdc.c
 * Routines for IP Device Control (SS7 over IP) dissection
 * Copyright Lucent Technologies 2004
 * Josh Bailey <joshbailey@lucent.com> and Ruud Linders <ruud@lucent.com>
 *
 * Using IPDC spec 0.20.2
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * I couldn't find the IPDC spec in question, but, for reference,
 * there are some Internet-Drafts for a protocol that looks like a
 * descendant or other variant of this:
 *
 *	http://tools.ietf.org/html/draft-taylor-ipdc-00
 *	http://tools.ietf.org/html/draft-dugan-ipdc-connection-00
 *	http://tools.ietf.org/html/draft-elliott-ipdc-media-00
 *	http://tools.ietf.org/html/draft-bell-ipdc-signaling-00
 *	http://tools.ietf.org/html/draft-pickett-ipdc-management-00
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <math.h>

#include <epan/packet.h>
#include "packet-tcp.h"
#include <epan/prefs.h>

#define	TCP_PORT_IPDC	6668
#define	TRANS_ID_SIZE_IPDC	4

#define	TEXT_UNDEFINED	"UNDEFINED"

#define	IPDC_STR_LEN	255

typedef enum {
	IPDC_UNKNOWN,
	IPDC_UINT,
	IPDC_ASCII,
	IPDC_BYTE,
	IPDC_OCTET,
	IPDC_IPA,
	IPDC_LINESTATUS,
	IPDC_CHANNELSTATUS,
	IPDC_Q931,
	IPDC_ENCTYPE
} ipdc_tag_type;

static const value_string encoding_type_vals[] = {
	{ 0x00, "PCMU (G.711 mu-law)" },
	{ 0x04, "G.723.1" },
	{ 0x08, "PCMA (G.711 A-law)" },
	{ 0x12, "G.729A" },
	{ 0x60, "Transparent data encoding" },
	{ 0x61, "T.38 fax over UPD" },
	{ 0, NULL }
};

static const value_string line_status_vals[] = {
	{ 0x00, "Not present" },
	{ 0x01, "Disabled" },
	{ 0x02, "Red alarm (loss of sync)" },
	{ 0x03, "Yellow alarm" },
	{ 0x04, "Other alarm or error" },
	{ 0x05, "Up" },
	{ 0x06, "Loopback" },
	{ 0, NULL }
};

static const value_string channel_status_vals[] = {
	{ 0x00, "Not present" },
	{ 0x01, "Out of service" },
	{ 0x03, "Maintenance (continuity test pending/in progress)" },
	{ 0x04, "Blocked" },
	{ 0x05, "Loopback" },
	{ 0x06, "Idle" },
	{ 0x07, "In use (dialing, ringing, etc.)" },
	{ 0x08, "Connected" },
	{ 0x50, "On hook" },
	{ 0x51, "Off hook" },
	{ 0, NULL }
};

/* XXX: Note duplicate values in the following ?? */
static const value_string message_code_vals[] = {
	{ 0x0082, "SS -> GW: ASUP: Acknowledgment to NSUP" },
	{ 0x0084, "SS -> GW: LNK: Link Active" },
	{ 0x0087, "SS -> GW: RCGST: Request Congestion Status" },
	{ 0x00FF, "SS -> GW: MRJ: Message reject." },
	{ 0x0041, "SS -> GW: RMS: Request module status" },
	{ 0x0043, "SS -> GW: RLS: Request line status" },
	{ 0x0045, "SS -> GW: RCS: Request channel status" },
	{ 0x0051, "SS -> GW: SMS: Set a module to a given state" },
	{ 0x0053, "SS -> GW: SLS: Set a line to a given state" },
	{ 0x0055, "SS -> GW: SCS: Set a group of channels to a given state" },
	{ 0x0047, "SS -> GW: RRS: Request RTP port Status" },
	{ 0x0048, "SS -> GW: RARS: Request All RTP port Status" },
	{ 0x0091, "SS -> GW: RSI: Request system information" },
	{ 0x0001, "SS -> GW: RCSI: Request inbound call setup" },
	{ 0x0009, "SS -> GW: RCST: Request pass-through call setup (TDM connection between two channels)" },
	{ 0x0013, "SS -> GW: RCCP: Request packet call setup" },
	{ 0x0015, "SS -> GW: RMPC: Modify/Query request packet call" },
	{ 0x0011, "SS -> GW: RCR: Release channel request" },
	{ 0x0012, "SS -> GW: ACR: Release channel complete" },
	{ 0x0061, "SS -> GW: PCT: Prepare channel for continuity test" },
	{ 0x0063, "SS -> GW: SCT: Start continuity test procedure with far end as loopback (Generate tone and check for received tone)" },
	{ 0x0073, "SS -> GW: STN: Send tones" },
	{ 0x0071, "SS -> GW: LTN: Listen for tones" },
	{ 0x007D, "SS -> GW: RTE: Request Test Echo" },
	{ 0x007E, "SS -> GW: ARTE: Response to Request Test Echo" },
	{ 0x0079, "SS -> GW: NATV: Native Mode Q.931 Signaling Transport" },
	{ 0x007A, "SS -> GW: TUNL: Tunneled Transport of signaling protocol data units" },
	{ 0x0081, "GW -> SS: NSUP: Notify the soft switch that the GW is coming up" },
	{ 0x0083, "GW -> SS: NSDN: Indication that the GW is going down" },
	{ 0x0085, "GW -> SS: ALNK: Acknowledgement to Link Active" },
	{ 0x0086, "GW -> SS: SLNK: Link Status" },
	{ 0x0088, "GW -> SS: CGST: Congestion Status" },
	{ 0x00FF, "GW -> SS: MRJ: Message reject." },
	{ 0x0042, "GW -> SS: NMS: Notify module status" },
	{ 0x0044, "GW -> SS: NLS: Notify line status" },
	{ 0x0046, "GW -> SS: NCS: Notify channel status" },
	{ 0x0056, "GW -> SS: RSCS: Response to SCS" },
	{ 0x0049, "GW -> SS: NRS: Notify RTP port Status" },
	{ 0x004A, "GW -> SS: NARS: Notify All RTP port Status" },
	{ 0x0092, "GW -> SS: NSI: Notify System Information" },
	{ 0x0002, "GW -> SS: ACSI: Accept inbound call setup" },
	{ 0x0003, "GW -> SS: CONI: Connect inbound call (answer)" },
	{ 0x0014, "GW -> SS: ACCP: Accept packet call setup" },
	{ 0x0016, "GW -> SS: AMPC: Accept modify to packet call" },
	{ 0x000A, "GW -> SS: ACST: Accept pass-through call" },
	{ 0x0011, "GW -> SS: RCR: Release channel request" },
	{ 0x0012, "GW -> SS: ACR: Release channel complete" },
	{ 0x0062, "GW -> SS: APCT: Response to PCT" },
	{ 0x0064, "GW -> SS: ASCT: Continuity test result" },
	{ 0x0074, "GW -> SS: ASTN: Completion result of STN command" },
	{ 0x0072, "GW -> SS: ALTN: Response to Listen for tones" },
	{ 0x00F0, "GW -> SS: NTN: Notify ToNe" },
	{ 0x007D, "GW -> SS: RTE: Request Test Echo" },
	{ 0x007E, "GW -> SS: ARTE: Response to Request Test Echo" },
	{ 0x0079, "GW -> SS: NATV: Native Mode Q.931 Signaling Transport" },
	{ 0x007A, "GW -> SS: TUNL: Tunneled Transport of signaling protocol data units" },
	{ 0x0005, "TD -> SS: RCSO: Request outbound call setup" },
	{ 0x0006, "SS -> TD: ACSO: Accept outbound call setup" },
	{ 0x0007, "SS -> TD: CONO: Outbound call connected" },
	{ 0, NULL }
};

static const value_string tag_description[] = {
	{ 0x01, "Protocol version" },
	{ 0x02, "System ID/ Serial Number" },
	{ 0x03, "System type" },
	{ 0x04, "Maximum number of modules (slot cards) supported" },
	{ 0x05, "Bay number" },
	{ 0x07, "Module number" },
	{ 0x0A, "Module type" },
	{ 0x0C, "Module status" },
	{ 0x0D, "Line number" },
	{ 0x14, "Line status" },
	{ 0x15, "Channel number" },
	{ 0x17, "Bearer capability" },
	{ 0x18, "Calling party number" },
	{ 0x19, "Dialed number" },
	{ 0x1B, "Primary SS IP address" },
	{ 0x1C, "Primary SS TCP port" },
	{ 0x20, "Number of lines in the Line status array" },
	{ 0x21, "Line status array" },
	{ 0x22, "Number of channels in the Channel status array" },
	{ 0x23, "Channel status array" },
	{ 0x24, "Requested module state" },
	{ 0x25, "Requested line state" },
	{ 0x26, "Requested channel status action" },
	{ 0x27, "Set channel status option" },
	{ 0x28, "Channel number first (for grouping)" },
	{ 0x29, "End Channel Number (for grouping)" },
	{ 0x2A, "Set channel status result" },
	{ 0x2B, "Prepare for continuity check result" },
	{ 0x2C, "Continuity timeout (ms)" },
	{ 0x2D, "Continuity test result" },
	{ 0x31, "Maximum time between digits in digits recognition/ tone" \
		"detection (inter-digit time-out) (ms)" },
	{ 0x32, "Tone string length" },
	{ 0x33, "Tone string" },
	{ 0x34, "Tone to complete collection" },
	{ 0x35, "Tone listen completion status" },
	{ 0x36, "Tone send completion status" },
	{ 0x37, "TDM destination Module" },
	{ 0x38, "TDM destination Line" },
	{ 0x39, "TDM destination channel" },
	{ 0x3A, "DTMF send IP address" },
	{ 0x3B, "DTMF send RTP port number" },
	{ 0x3C, "DTMF send format" },
	{ 0x3D, "DTMF Named Events to Expect" },
	{ 0x3E, "DTMF Payload Indicator" },
	{ 0x40, "Access server Call identifier" },
	{ 0x46, "Maximum time for digit collection (ms)" },
	{ 0x49, "Tone Type" },
	{ 0x4A, "Apply/Cancel Tone" },
	{ 0x5D, "Destination listen IP address" },
	{ 0x5E, "Destination listen RTP port number" },
	{ 0x5F, "Destination send IP address" },
	{ 0x60, "Destination send RTP port number" },
	{ 0x65, "Source port type" },
	{ 0x66, "Destination port type" },
	{ 0x67, "Start RTP Port Number" },
	{ 0x68, "End RTP Port Number" },
	{ 0x69, "Rogue Session Addresses" },
	{ 0x6A, "RTP Port Status" },
	{ 0x6F, "Receive Encoding Type" },
	{ 0x70, "Send Encoding Type" },
	{ 0x71, "Silence Suppression Activation Timer (ms)" },
	{ 0x72, "Comfort Noise Generation" },
	{ 0x73, "Packet Loading (ms)" },
	{ 0x74, "Echo Cancellation" },
	{ 0x75, "Constant DTMF Tone Detection on/off" },
	{ 0x76, "Constant MF Tone Detection on/off" },
	{ 0x77, "Constant Fax tone detection on/off" },
	{ 0x78, "Constant Modem tone detection on/off" },
	{ 0x7B, "Constant Packet Loss Detection on/off" },
	{ 0x7C, "Packet Loss Threshold" },
	{ 0x7D, "Constant Latency Threshold Detection on/off" },
	{ 0x7E, "Latency Threshold (ms)" },
	{ 0x86, "Announcement treatment" },
	{ 0x90, "Packet Statistics Reset Indicator" },
	{ 0x91, "Number of audio packets sent" },
	{ 0x92, "Number of audio packets dropped" },
	{ 0x93, "Number of audio bytes sent" },
	{ 0x94, "Number of audio bytes dropped" },
	{ 0x95, "Number of signaling packets sent" },
	{ 0x96, "Number of signaling packets dropped" },
	{ 0x97, "Number of signaling bytes sent" },
	{ 0x98, "Number of signaling bytes dropped" },
	{ 0x99, "Estimated average latency (ms)" },
	{ 0x9D, "Number of audio packets received" },
	{ 0x9E, "Number of audio bytes received" },
	{ 0x9F, "Number of signaling packets received" },
	{ 0xA0, "Number of signaling bytes received" },
	{ 0xA1, "Protocol Type" },
	{ 0xA2, "PDU Data Block" },
	{ 0xA3, "Jitter estimated (m ticks)" },
	{ 0xA4, "Global call ID" },
	{ 0xA5, "User information line 1 proto" },
	{ 0xA6, "Congestion level indicator" },
	{ 0xA7, "RADIUS Ascend-auth-type" },
	{ 0xB0, "Link status" },
	{ 0xB1, "Action request" },
	{ 0xB2, "Calling Party Info1" },
	{ 0xB3, "Called Party Info2" },
	{ 0xC1, "Country Code" },
	{ 0xC2, "Number of Operational Universal Ports" },
	{ 0xC3, "Number of Operational HDLC-only (digital) ports" },
	{ 0xFE, "Q.850 Cause code" },
	{ 0, NULL }
};
static value_string_ext tag_description_ext = VALUE_STRING_EXT_INIT(tag_description);

typedef struct _ipdc_tag_type_val {
	gint	tag;
	ipdc_tag_type	type;
} ipdc_tag_type_val;

static const ipdc_tag_type_val ipdc_tag_types[] = {
	{ 0x01, IPDC_UINT },
	{ 0x02, IPDC_ASCII },
	{ 0x03, IPDC_ASCII },
	{ 0x04, IPDC_UINT },
	{ 0x05, IPDC_ASCII },
	{ 0x07, IPDC_UINT },
	{ 0x0A, IPDC_BYTE },
	{ 0x0C, IPDC_BYTE },
	{ 0x0D, IPDC_UINT },
	{ 0x14, IPDC_BYTE },
	{ 0x15, IPDC_UINT },
	{ 0x17, IPDC_BYTE },
	{ 0x18, IPDC_ASCII },
	{ 0x19, IPDC_ASCII },
	{ 0x1B, IPDC_IPA },
	{ 0x1C, IPDC_UINT },
	{ 0x20, IPDC_UINT },
	{ 0x21, IPDC_LINESTATUS },
	{ 0x22, IPDC_UINT },
	{ 0x23, IPDC_CHANNELSTATUS },
	{ 0x24, IPDC_BYTE },
	{ 0x25, IPDC_OCTET }, /* TBD */
	{ 0x26, IPDC_BYTE },
	{ 0x27, IPDC_BYTE },
	{ 0x28, IPDC_UINT },
	{ 0x29, IPDC_UINT },
	{ 0x2A, IPDC_BYTE },
	{ 0x2B, IPDC_BYTE },
	{ 0x2C, IPDC_UINT },
	{ 0x2D, IPDC_BYTE },
	{ 0x31, IPDC_UINT },
	{ 0x32, IPDC_UINT },
	{ 0x33, IPDC_ASCII },
	{ 0x34, IPDC_ASCII },
	{ 0x35, IPDC_BYTE },
	{ 0x36, IPDC_UINT },
	{ 0x37, IPDC_UINT },
	{ 0x38, IPDC_UINT },
	{ 0x39, IPDC_UINT },
	{ 0x3A, IPDC_IPA },
	{ 0x3B, IPDC_UINT },
	{ 0x3C, IPDC_BYTE },
	{ 0x3D, IPDC_ASCII },
	{ 0x3E, IPDC_UINT },
	{ 0x40, IPDC_UINT },
	{ 0x46, IPDC_UINT },
	{ 0x49, IPDC_BYTE },
	{ 0x4A, IPDC_BYTE },
	{ 0x5D, IPDC_IPA },
	{ 0x5E, IPDC_UINT },
	{ 0x5F, IPDC_IPA },
	{ 0x60, IPDC_UINT },
	{ 0x65, IPDC_BYTE },
	{ 0x66, IPDC_BYTE },
	{ 0x67, IPDC_UINT },
	{ 0x68, IPDC_UINT },
	{ 0x69, IPDC_IPA },
	{ 0x6A, IPDC_BYTE },
	{ 0x6F, IPDC_ENCTYPE },
	{ 0x70, IPDC_ENCTYPE },
	{ 0x71, IPDC_UINT },
	{ 0x72, IPDC_BYTE },
	{ 0x73, IPDC_UINT },
	{ 0x74, IPDC_BYTE },
	{ 0x75, IPDC_BYTE },
	{ 0x76, IPDC_BYTE },
	{ 0x77, IPDC_BYTE },
	{ 0x78, IPDC_BYTE },
	{ 0x7B, IPDC_BYTE },
	{ 0x7C, IPDC_UINT },
	{ 0x7D, IPDC_BYTE },
	{ 0x7E, IPDC_UINT },
	{ 0x86, IPDC_BYTE },
	{ 0x90, IPDC_BYTE },
	{ 0x91, IPDC_UINT },
	{ 0x92, IPDC_UINT },
	{ 0x93, IPDC_UINT },
	{ 0x94, IPDC_UINT },
	{ 0x95, IPDC_UINT },
	{ 0x96, IPDC_UINT },
	{ 0x97, IPDC_UINT },
	{ 0x98, IPDC_UINT },
	{ 0x99, IPDC_UINT },
	{ 0x9D, IPDC_UINT },
	{ 0x9E, IPDC_UINT },
	{ 0x9F, IPDC_UINT },
	{ 0xA0, IPDC_UINT },
	{ 0xA1, IPDC_UINT },
	{ 0xA2, IPDC_Q931 },
	{ 0xA3, IPDC_BYTE },
	{ 0xA4, IPDC_BYTE },
	{ 0xA5, IPDC_BYTE },
	{ 0xA6, IPDC_UINT },
	{ 0xA7, IPDC_UINT },
	{ 0xB0, IPDC_BYTE },
	{ 0xB1, IPDC_BYTE },
	{ 0xB2, IPDC_OCTET },
	{ 0xB3, IPDC_OCTET },
	{ 0xC1, IPDC_BYTE },
	{ 0xC2, IPDC_UINT },
	{ 0xC3, IPDC_UINT },
	{ 0xFE, IPDC_UINT },
	{ 0xFFFF, IPDC_UNKNOWN }
};

#define	IPDC_TAG(x)	(256 * (x))

static const value_string tag_enum_type[] = {
	/* Protocol Version */
	{ IPDC_TAG(0x01) + 0x00, "Version 0 (Xcom NMI 5.0)" },
	{ IPDC_TAG(0x01) + 0x01, "IPDC Version 0.12" },
	{ IPDC_TAG(0x01) + 0x02, "IPDC Version 0.15" },
	{ IPDC_TAG(0x01) + 0x03, "IPDC Version 0.17" },
	{ IPDC_TAG(0x01) + 0x04, "IPDC Version 0.18" },
	{ IPDC_TAG(0x01) + 0x05, "IPDC Version 0.19" },
	{ IPDC_TAG(0x01) + 0x06, "IPDC Version 0.20" },
	/* Module type, from Annex B. */
	{ IPDC_TAG(0x0a) + 0x01, "Unknown" },
	{ IPDC_TAG(0x0a) + 0x02, "Shelf" },
	{ IPDC_TAG(0x0a) + 0x03, "Router Card" },
	{ IPDC_TAG(0x0a) + 0x04, "8-line Channelized T1" },
	{ IPDC_TAG(0x0a) + 0x05, "8-line Channelized E1" },
	{ IPDC_TAG(0x0a) + 0x06, "48-modem Card" },
	{ IPDC_TAG(0x0a) + 0x07, "192 HDLC Card" },
	{ IPDC_TAG(0x0a) + 0x08, "4-port Ethernet Card" },
	{ IPDC_TAG(0x0a) + 0x09, "Serial WAN Card" },
	{ IPDC_TAG(0x0a) + 0x0A, "HSSI Card" },
	{ IPDC_TAG(0x0a) + 0x0B, "10-line Unchannelized T1" },
	{ IPDC_TAG(0x0a) + 0x0C, "36-modem (Analog) Card" },
	{ IPDC_TAG(0x0a) + 0x0D, "T3 Card" },
	{ IPDC_TAG(0x0a) + 0x0E, "48-modem 56K Card" },
	{ IPDC_TAG(0x0a) + 0x0F, "Forward" },
	{ IPDC_TAG(0x0a) + 0x10, "SDSL Card" },
	{ IPDC_TAG(0x0a) + 0x11, "CAP ADSL Card" },
	{ IPDC_TAG(0x0a) + 0x12, "DMT ADSL Card" },
	{ IPDC_TAG(0x0a) + 0x13, "Standalone Modem Controller" },
	{ IPDC_TAG(0x0a) + 0x14, "32-port IDSL Card" },
	{ IPDC_TAG(0x0a) + 0x15, "10-line Unchannelized E1" },
	{ IPDC_TAG(0x0a) + 0x16, "36-modem (Analog) 2 Card" },
	{ IPDC_TAG(0x0a) + 0x17, "CSMX Modem Card" },
	{ IPDC_TAG(0x0a) + 0x18, "UDS3 Card" },
	{ IPDC_TAG(0x0a) + 0x19, "DS3 ATM Card" },
	{ IPDC_TAG(0x0a) + 0x1A, "4-port Ethernet 2 Card" },
	{ IPDC_TAG(0x0a) + 0x1B, "192 HDLC 2 Card" },
	{ IPDC_TAG(0x0a) + 0x1C, "SDSL 70 Data Card" },
	{ IPDC_TAG(0x0a) + 0x1D, "MADD Card" },
	{ IPDC_TAG(0x0a) + 0x1E, "SDSL 70 Voice Card" },
	{ IPDC_TAG(0x0a) + 0x1F, "OC3 Daughter Card" },
	{ IPDC_TAG(0x0a) + 0x20, "OC3 ATM Card" },
	{ IPDC_TAG(0x0a) + 0x21, "4-port Ethernet 3 Card" },
	{ IPDC_TAG(0x0a) + 0x22, "SRS Ethernet Card" },
	{ IPDC_TAG(0x0a) + 0x23, "SDSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x24, "AL DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x25, "CSM3V Modem Card" },
	{ IPDC_TAG(0x0a) + 0x26, "HDLC2EC Card" },
	{ IPDC_TAG(0x0a) + 0x27, "DS3 Daughter Card" },
	{ IPDC_TAG(0x0a) + 0x28, "2-port Ethernet Card" },
	{ IPDC_TAG(0x0a) + 0x2A, "STM0 Card" },
	{ IPDC_TAG(0x0a) + 0x2B, "SDSL Ripper Card" },
	{ IPDC_TAG(0x0a) + 0x2F, "Stinger Terminator Card" },
	{ IPDC_TAG(0x0a) + 0x30, "GS DADSL Ripper Card" },
	{ IPDC_TAG(0x0a) + 0x31, "PCTFIT Card" },
	{ IPDC_TAG(0x0a) + 0x32, "PCTFIE Card" },
	{ IPDC_TAG(0x0a) + 0x33, "CT DADSL GLITE Card" },
	{ IPDC_TAG(0x0a) + 0x34, "DS3 ATM 2 Card" },
	{ IPDC_TAG(0x0a) + 0x35, "E3 ATM Card" },
	{ IPDC_TAG(0x0a) + 0x36, "24-line Stinger IMA T1 Card" },
	{ IPDC_TAG(0x0a) + 0x37, "MADD 2 Card" },
	{ IPDC_TAG(0x0a) + 0x38, "GS HDSL 2 Card" },
	{ IPDC_TAG(0x0a) + 0x39, "32-line Stinger IDSL Card" },
	{ IPDC_TAG(0x0a) + 0x3A, "ANNEXB DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x3B, "24-line Stinger IMA E1 Card" },
	{ IPDC_TAG(0x0a) + 0x3C, "40C CT DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x3D, "4-port Ethernet 3+ Card" },
	{ IPDC_TAG(0x0a) + 0x3E, "CLPMT Card" },
	{ IPDC_TAG(0x0a) + 0x3F, "CLPME Card" },
	{ IPDC_TAG(0x0a) + 0x40, "E3 Daughter Card" },
	{ IPDC_TAG(0x0a) + 0x41, "8-line Stinger IMA T1 Card" },
	{ IPDC_TAG(0x0a) + 0x42, "8-line Stinger IMA E1 Card" },
	{ IPDC_TAG(0x0a) + 0x43, "48A GS DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x44, "48B GS DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x45, "48C GS DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x46, "40A CT DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x47, "OC3 ATM 2 Card" },
	{ IPDC_TAG(0x0a) + 0x48, "4-port Serial WAN 2 Card" },
	{ IPDC_TAG(0x0a) + 0x49, "CDS3 LIM Card" },
	{ IPDC_TAG(0x0a) + 0x4A, "R7000 Card" },
	{ IPDC_TAG(0x0a) + 0x4B, "VPN Card" },
	{ IPDC_TAG(0x0a) + 0x4C, "HSE Card" },
	{ IPDC_TAG(0x0a) + 0x4D, "MADD 3 Card" },
	{ IPDC_TAG(0x0a) + 0x4E, "Stinger CM V2 Card" },
	{ IPDC_TAG(0x0a) + 0x4F, "COC3 LIM Card" },
	{ IPDC_TAG(0x0a) + 0x50, "Stinger SHDSL Card" },
	{ IPDC_TAG(0x0a) + 0x51, "2-port OC34-port DS3 Daughter Card" },
	{ IPDC_TAG(0x0a) + 0x52, "72-line DADSL ATM Card" },
	{ IPDC_TAG(0x0a) + 0x53, "36-line DMT MRT Card" },
	{ IPDC_TAG(0x0a) + 0x54, "24-line T1 Card" },
	{ IPDC_TAG(0x0a) + 0x55, "24-line E1 Card" },
	{ IPDC_TAG(0x0a) + 0x56, "Stinger MRT CM Card" },
	{ IPDC_TAG(0x0a) + 0x57, "CSTM1 LIM Card" },
	/* Module status */
	{ IPDC_TAG(0x0c) + 0x00, "Not present (empty)" },
	{ IPDC_TAG(0x0c) + 0x01, "Out of service (down)" },
	{ IPDC_TAG(0x0c) + 0x02, "Up" },
	{ IPDC_TAG(0x0c) + 0x03, "Error" },
	{ IPDC_TAG(0x0c) + 0x04, "Does not exist" },
	/* Line status */
	{ IPDC_TAG(0x14) + 0x00, "Not present" },
	{ IPDC_TAG(0x14) + 0x01, "Disabled" },
	{ IPDC_TAG(0x14) + 0x02, "Red alarm (loss of sync)" },
	{ IPDC_TAG(0x14) + 0x03, "Yellow alarm" },
	{ IPDC_TAG(0x14) + 0x04, "Other alarms or errors" },
	{ IPDC_TAG(0x14) + 0x05, "Up" },
	{ IPDC_TAG(0x14) + 0x06, "Loopback" },
	/* Bearer capability */
	{ IPDC_TAG(0x17) + 0x00, "Voice call" },
	{ IPDC_TAG(0x17) + 0x08, "64K data call" },
	{ IPDC_TAG(0x17) + 0x09, "56K data call" },
	{ IPDC_TAG(0x17) + 0x10,
	"Modem call (3.1K Audio call) (applies to RCSI for modem call only)" },
	/* Line status array */
	/* { IPDC_TAG(0x21) + 0x0, "" }, */
	/* Channel status array */
	/* { IPDC_TAG(0x23) + 0x0, "" }, */
	/* Requested module state */
	{ IPDC_TAG(0x24) + 0x00, "Out of service" },
	{ IPDC_TAG(0x24) + 0x01, "Initialize (bring up)" },
	/* Requested line state */
	{ IPDC_TAG(0x25) + 0x00, "Disable" },
	{ IPDC_TAG(0x25) + 0x01, "Enable" },
	{ IPDC_TAG(0x25) + 0x02, "Start loopback" },
	{ IPDC_TAG(0x25) + 0x03, "Terminate loopback" },
	/* Requested channel status action */
	{ IPDC_TAG(0x26) + 0x00, "Reset to idle" },
	{ IPDC_TAG(0x26) + 0x01, "Reset to out of service" },
	{ IPDC_TAG(0x26) + 0x02, "Start loopback" },
	{ IPDC_TAG(0x26) + 0x03, "Terminate loopback" },
	/* Set channel status option */
	{ IPDC_TAG(0x27) + 0x00,
	"Do not perform the indicated action if any of the" \
	"channels is not in the valid initial state" },
	{ IPDC_TAG(0x27) + 0x01,
	"Perform the indicated action on channels that are on" \
	"the valid initial state. Other channels are not affected" },
	/* Set channel status result */
	{ IPDC_TAG(0x2a) + 0x00,
		"action successfully performed in all channels" },
	{ IPDC_TAG(0x2a) + 0x01, "at least one channel failed" },
	/* Prepare for continuity check result */
	{ IPDC_TAG(0x2b) + 0x00, "Resources reserved successfully" },
	{ IPDC_TAG(0x2b) + 0x01, "Resource not available" },
	/* Continuity test result */
	{ IPDC_TAG(0x2d) + 0x00, "Test completed successfully" },
	{ IPDC_TAG(0x2d) + 0x01, "Test failed" },
	/* Tone listen completion status */
	{ IPDC_TAG(0x35) + 0x00, "Timeout" },
	{ IPDC_TAG(0x35) + 0x01, "No resources available for this operation" },
	{ IPDC_TAG(0x35) + 0x02, "Operation terminated by the SS" },
	{ IPDC_TAG(0x35) + 0x03, "Tone-to-complete-collection received" },
	{ IPDC_TAG(0x35) + 0x04,
		"The specified maximum number of tones received" },
	{ IPDC_TAG(0x35) + 0x05, "Wait between successive tones too long" },
	/* Tone send completion status */
	{ IPDC_TAG(0x36) + 0x00, "Operation succeeded" },
	{ IPDC_TAG(0x36) + 0x01, "Operation failed" },
	{ IPDC_TAG(0x36) + 0x02, "Operation terminated by SS" },
	{ IPDC_TAG(0x36) + 0x03, "Operation started" },
	{ IPDC_TAG(0x36) + 0x04,
		"Operation terminated by administrative action" },
	/* DTMF send format */
	{ IPDC_TAG(0x3c) + 0x00, "Tone" },
	{ IPDC_TAG(0x3c) + 0x01, "Event" },
	{ IPDC_TAG(0x3c) + 0x02, "Both (default)" },
	/* Tone Type */
	{ IPDC_TAG(0x49) + 0x00, "MF Tone" },
	{ IPDC_TAG(0x49) + 0x01, "DTMF Tone" },
	{ IPDC_TAG(0x49) + 0x02, "Analog Test Tone" },
	{ IPDC_TAG(0x49) + 0x03, "Announcement" },
	{ IPDC_TAG(0x49) + 0x04, "Digital Milli-watt tone" },
	{ IPDC_TAG(0x49) + 0x05, "Supplemental tones" },
	{ IPDC_TAG(0x49) + 0x06,
		"Fax tone (CED, no phase reversal, or V.21 flags)" },
	{ IPDC_TAG(0x49) + 0x07, "Modem tone (CED, phase reversal)" },
	{ IPDC_TAG(0x49) + 0x41, "Ringback tone" },
	/* Apply/Cancel Tone */
	{ IPDC_TAG(0x4a) + 0x00, "Apply tone" },
	{ IPDC_TAG(0x4a) + 0x01, "Cancel tone" },
	{ IPDC_TAG(0x4a) + 0x02, "Listen for tone" },
	/* Source port type */
	{ IPDC_TAG(0x65) + 0x00, "SCN channel" },
	/* Destination port type */
	{ IPDC_TAG(0x66) + 0x01, "RTP port" },
	/* RTP Port Status */
	{ IPDC_TAG(0x6a) + 0x00, "Idle", },
	{ IPDC_TAG(0x6a) + 0x01, "Active" },
	/* Receive Encoding Type */
	{ IPDC_TAG(0x6f) + 0x00, "PCMU (G.711 mu-law)" },
	{ IPDC_TAG(0x6f) + 0x04, "G723.1" },
	{ IPDC_TAG(0x6f) + 0x08, "PCMA (G.711 A-law)" },
	{ IPDC_TAG(0x6f) + 0x12, "G729A" },
	{ IPDC_TAG(0x6f) + 0x60, "Transparent data encoding" },
	{ IPDC_TAG(0x6f) + 0x61, "T.38 fax over UPD" },
	/* Send Encoding Type */
	{ IPDC_TAG(0x70) + 0x00, "PCMU (G.711 mu-law)" },
	{ IPDC_TAG(0x70) + 0x04, "G723.1" },
	{ IPDC_TAG(0x70) + 0x08, "PCMA (G.711 A-law)" },
	{ IPDC_TAG(0x70) + 0x12, "G729A" },
	{ IPDC_TAG(0x70) + 0x60, "Transparent data encoding" },
	{ IPDC_TAG(0x70) + 0x61, "T.38 fax over UPD" },
	/* Comfort Noise Generation */
	{ IPDC_TAG(0x72) + 0x00, "off" },
	{ IPDC_TAG(0x72) + 0x01, "on" },
	/* Echo Cancellation */
	{ IPDC_TAG(0x74) + 0x00, "Off" },
	{ IPDC_TAG(0x74) + 0x01, "On, 16 ms tail" },
	{ IPDC_TAG(0x74) + 0x02, "On, 32 ms tail (default)" },
	{ IPDC_TAG(0x74) + 0x03, "On, 64ms tail" },
	/* Constant DTMF Tone Detection on/off */
	{ IPDC_TAG(0x75) + 0x00, "Off" },
	{ IPDC_TAG(0x75) + 0x01, "On (Default)" },
	/* Constant MF Tone Detection on/off" */
	{ IPDC_TAG(0x76) + 0x00, "Off (Default)" },
	{ IPDC_TAG(0x76) + 0x01, "On" },
	/* Constant Fax tone detection on/off */
	{ IPDC_TAG(0x77) + 0x00, "Off" },
	{ IPDC_TAG(0x77) + 0x00, "On (Default)" },
	/* Constant Modem tone detection on/off */
	{ IPDC_TAG(0x78) + 0x00, "Off" },
	{ IPDC_TAG(0x78) + 0x01, "On (Default)" },
	/* Constant Packet Loss Detection on/off */
	{ IPDC_TAG(0x7b) + 0x00, "Off" },
	{ IPDC_TAG(0x7b) + 0x01, "On (Default)" },
	/* Constant Latency Threshold Detection on/off */
	{ IPDC_TAG(0x7d) + 0x00, "Off" },
	{ IPDC_TAG(0x7d) + 0x01, "On (Default)" },
	/* Announcement treatment */
	{ IPDC_TAG(0x86) + 0x00, "Continuous play" },
	{ IPDC_TAG(0x86) + 0x01, "Play 1 time and terminate the call" },
	{ IPDC_TAG(0x86) + 0x02, "Play 2 times and terminate the call" },
	{ IPDC_TAG(0x86) + 0x03, "Play 3 times and terminate the call" },
	{ IPDC_TAG(0x86) + 0x04, "Play 4 times and terminate the call" },
	{ IPDC_TAG(0x86) + 0x05, "Play 5 times and terminate the call" },
	/* Packet Statistics Reset Indicator */
	{ IPDC_TAG(0x90) + 0x00, "Do not reset" },
	{ IPDC_TAG(0x90) + 0x01, "Reset (default)" },
	/* Protocol Type */
	{ IPDC_TAG(0xa1) + 0x01, "ITU-T Q931" },
	{ IPDC_TAG(0xa1) + 0x02, "Nortel-ISDN" },
	{ IPDC_TAG(0xa1) + 0x03, "5ESS-ISDN" },
	{ IPDC_TAG(0xa1) + 0x04, "Euro-ISDN" },
	/* Global call ID  Refer Annex A */
	/* IPDC_TAG(0xa4) .... */
	/* User information line 1 proto */
	/* IPDC_TAG(0xa5) .... */
	/* Congestion level indicator */
	{ IPDC_TAG(0xa6) + 0x00, "No Congestion" },
	{ IPDC_TAG(0xa6) + 0x01, "Congestion Level 1" },
	{ IPDC_TAG(0xa6) + 0x02, "Congestion Level 2" },
	/* RADIUS Ascend-auth-type */
	{ IPDC_TAG(0xa7) + 0x00, "None" },
	{ IPDC_TAG(0xa7) + 0x01, "Any" },
	{ IPDC_TAG(0xa7) + 0x02, "PAP (Default)" },
	{ IPDC_TAG(0xa7) + 0x03, "CHAP" },
	{ IPDC_TAG(0xa7) + 0x03, "MS-CHAP" },
	/* Link status */
	{ IPDC_TAG(0xb0) + 0x00, "Successfully connected" },
	{ IPDC_TAG(0xb0) + 0x01, "Not connected" },
	/* Action request */
	{ IPDC_TAG(0xb1) + 0x00, "Registration request" },
	/* Calling Party Info */
	/* Called Party Info */
	/* Country Code */
	{ IPDC_TAG(0xc1) + 0x00, "Argentina" },
	{ IPDC_TAG(0xc1) + 0x02, "Australia" },
	{ IPDC_TAG(0xc1) + 0x03, "Belgium" },
	{ IPDC_TAG(0xc1) + 0x04, "China" },
	{ IPDC_TAG(0xc1) + 0x05, "Costa Rica" },
	{ IPDC_TAG(0xc1) + 0x06, "Finland" },
	{ IPDC_TAG(0xc1) + 0x07, "France" },
	{ IPDC_TAG(0xc1) + 0x08, "Germany" },
	{ IPDC_TAG(0xc1) + 0x09, "Hong Kong" },
	{ IPDC_TAG(0xc1) + 0x0a, "Italy" },
	{ IPDC_TAG(0xc1) + 0x0b, "Japan" },
	{ IPDC_TAG(0xc1) + 0x0c, "Korea" },
	{ IPDC_TAG(0xc1) + 0x0d, "Mexico" },
	{ IPDC_TAG(0xc1) + 0x0e, "Netherlands" },
	{ IPDC_TAG(0xc1) + 0x0f, "New Zealand" },
	{ IPDC_TAG(0xc1) + 0x10, "Singapore" },
	{ IPDC_TAG(0xc1) + 0x11, "Spain" },
	{ IPDC_TAG(0xc1) + 0x12, "Sweden" },
	{ IPDC_TAG(0xc1) + 0x13, "Switzerland" },
	{ IPDC_TAG(0xc1) + 0x14, "UK" },
	{ IPDC_TAG(0xc1) + 0x15, "US" },
	{ IPDC_TAG(0xc1) + 0x15, "Brazil" },
	{ 0, NULL }
};

static value_string_ext tag_enum_type_ext = VALUE_STRING_EXT_INIT(tag_enum_type);
static int proto_ipdc = -1;
static int hf_ipdc_nr = -1;
static int hf_ipdc_ns = -1;
static int hf_ipdc_payload_len = -1;
static int hf_ipdc_protocol_id = -1;
static int hf_ipdc_trans_id_size = -1;
static int hf_ipdc_trans_id = -1;
static int hf_ipdc_message_code = -1;

static gint ett_ipdc = -1;
static gint ett_ipdc_tag = -1;

static gboolean ipdc_desegment = TRUE;
static guint ipdc_port_pref = TCP_PORT_IPDC;
static gboolean new_packet = FALSE;

static dissector_handle_t q931_handle;

void proto_reg_handoff_ipdc(void);


static guint
get_ipdc_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	/* lower 10 bits only */
	guint raw_len = (tvb_get_ntohs(tvb,offset+2) & 0x03FF);

	return raw_len + 4;
}

static void
dissect_ipdc_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *ipdc_tree;
	proto_item *ipdc_tag;
	proto_tree *tag_tree;
	tvbuff_t *q931_tvb;

	const char *des;
	const char *enum_val = "";
	char tmp_tag_text[IPDC_STR_LEN + 1];
	const value_string *val_ptr;
	guint32	type;
	guint len;
	guint i;
	guint status;
	gshort tag;
	guint32 tmp_tag;

	gshort nr = tvb_get_guint8(tvb,0);
	gshort ns = tvb_get_guint8(tvb,1);
	guint payload_len = get_ipdc_pdu_len(pinfo,tvb,0);

	gshort trans_id_size;
	guint32 trans_id;
	guint16 message_code;
	guint16 offset;

	/* display IPDC protocol ID */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPDC");

	/* short frame... */
	if (payload_len < 4)
		return;

	/* clear info column and display send/receive sequence numbers */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (new_packet == TRUE) {
			col_clear(pinfo->cinfo, COL_INFO);
			new_packet = FALSE;
		}
		col_append_fstr(pinfo->cinfo, COL_INFO, "r=%u s=%u ",
		nr, ns);
	}

	if (payload_len == 4) {
		if (!tree)
			return;

		ti = proto_tree_add_item(tree, proto_ipdc, tvb, 0, -1, ENC_NA);
		ipdc_tree = proto_item_add_subtree(ti, ett_ipdc);
		proto_tree_add_item(ipdc_tree, hf_ipdc_nr, tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ipdc_tree, hf_ipdc_ns, tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ipdc_tree, hf_ipdc_payload_len, tvb, 2, 2,
				    payload_len);

		return;
	}

	/* IPDC tags present - display message code and trans. ID */
	trans_id_size = TRANS_ID_SIZE_IPDC; /* tvb_get_guint8(tvb,5); */
	trans_id = tvb_get_ntohl(tvb,6);
	message_code = tvb_get_ntohs(tvb,6+trans_id_size);
	offset = 6 + trans_id_size + 2; /* past message_code */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO,
				"TID=%x %s ",
				trans_id,
				val_to_str_const(message_code, message_code_vals,
					   TEXT_UNDEFINED));


	ti = proto_tree_add_item(tree, proto_ipdc, tvb, 0, -1, ENC_NA);
	ipdc_tree = proto_item_add_subtree(ti, ett_ipdc);

	proto_tree_add_item(ipdc_tree, hf_ipdc_nr, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ipdc_tree, hf_ipdc_ns, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_uint(ipdc_tree, hf_ipdc_payload_len, tvb,
		2, 2, payload_len);

	proto_tree_add_item(ipdc_tree, hf_ipdc_protocol_id, tvb,
			    4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ipdc_tree, hf_ipdc_trans_id_size, tvb,
			    5, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ipdc_tree, hf_ipdc_trans_id, tvb,
			    6, trans_id_size, ENC_NA);
	proto_tree_add_item(ipdc_tree, hf_ipdc_message_code, tvb,
			    6 + trans_id_size, 2, ENC_BIG_ENDIAN);

	ipdc_tag = proto_tree_add_text(ipdc_tree, tvb, offset,
				       payload_len - offset, "IPDC tags");
	tag_tree = proto_item_add_subtree(ipdc_tag, ett_ipdc_tag);

	/* iterate through tags. first byte is tag, second is length,
	   in bytes, following is tag data. tag of 0x0 should be
	   end of tags. */
	for (;;) {
		tag = tvb_get_guint8(tvb, offset);

		if (tag == 0x0) {
			if (offset == payload_len - 1) {
				proto_tree_add_text(tag_tree, tvb,
						    offset, 1, "end of tags");
			} else {
				proto_tree_add_text(tag_tree, tvb,
						    offset, 1, "data trailing end of tags");
			}

			break;
		}

		len = tvb_get_guint8(tvb,offset+1);
		des = val_to_str_ext_const(tag, &tag_description_ext, TEXT_UNDEFINED);
		/* lookup tag type */
		for (i = 0; (ipdc_tag_types[i].tag != tag &&
			     ipdc_tag_types[i].type != IPDC_UNKNOWN); i++)
		;
		type = ipdc_tag_types[i].type;

		tmp_tag = 0;

		switch (type) {
			/* simple IPDC_ASCII strings */
			case IPDC_ASCII:
				DISSECTOR_ASSERT(len<=IPDC_STR_LEN);
				tvb_memcpy(tvb, tmp_tag_text, offset+2, len);
				tmp_tag_text[len] = 0;
				proto_tree_add_text(tag_tree, tvb, offset,
						    len + 2, "0x%2.2x: %s: %s", tag, des,
						    tmp_tag_text);
			break;

			/* unsigned integers, or bytes */
			case IPDC_UINT:
			case IPDC_BYTE:
				for (i = 0; i < len; i++)
					tmp_tag += tvb_get_guint8(tvb,
						offset + 2 + i) * (guint32)pow(256, len - (i + 1));

				if (len == 1)
					enum_val =
						val_to_str_ext_const(IPDC_TAG(tag) + tmp_tag,
								     &tag_enum_type_ext, TEXT_UNDEFINED);

				if (len == 1 && strcmp(enum_val, TEXT_UNDEFINED) != 0) {
					proto_tree_add_text(tag_tree, tvb,
							    offset, len + 2,
							    "0x%2.2x: %s: %s",
							    tag, des, enum_val);
				} else {
					proto_tree_add_text(tag_tree, tvb,
							    offset, len + 2,
							    "0x%2.2x: %s: %u",
							    tag, des, tmp_tag);
				}
			break;

			/* IP addresses */
			case IPDC_IPA:
				switch (len) {
					case 4:
						g_snprintf(tmp_tag_text,
							   IPDC_STR_LEN,
							   "%u.%u.%u.%u",
							   tvb_get_guint8(tvb, offset + 2),
							   tvb_get_guint8(tvb, offset + 3),
							   tvb_get_guint8(tvb, offset + 4),
							   tvb_get_guint8(tvb, offset + 5)
							);
						break;
					case 6:
						g_snprintf(tmp_tag_text,
							   IPDC_STR_LEN,
							   "%u.%u.%u.%u:%u",
							   tvb_get_guint8(tvb, offset + 2),
							   tvb_get_guint8(tvb, offset + 3),
							   tvb_get_guint8(tvb, offset + 4),
							   tvb_get_guint8(tvb, offset + 5),
							   tvb_get_ntohs(tvb, offset + 6));
						break;
					default:
						g_snprintf(tmp_tag_text,
							   IPDC_STR_LEN,
							   "Invalid IP address length %u",
							   len);
				}
				proto_tree_add_text(tag_tree, tvb,
						    offset, len + 2,
						    "0x%2.2x: %s: %s",
						    tag, des, tmp_tag_text);
				break;
			/* Line status arrays */
			case IPDC_LINESTATUS:
			case IPDC_CHANNELSTATUS:
				proto_tree_add_text(tag_tree, tvb, offset,
						    len + 2, "0x%2.2x: %s", tag, des);
				val_ptr = (type == IPDC_LINESTATUS) ? line_status_vals : channel_status_vals;
				for (i = 0; i < len; i++) {
					status = tvb_get_guint8(tvb,offset+2+i);
					proto_tree_add_text(tag_tree, tvb,
							    offset + 2 + i, 1,
							    " %.2u: %.2x (%s)",
							    i + 1, status,
							    val_to_str_const(status,
									     val_ptr,
									     TEXT_UNDEFINED));
				}
				break;
			case IPDC_Q931:
				q931_tvb =
					tvb_new_subset(tvb, offset+2, len, len);
				call_dissector(q931_handle,q931_tvb,pinfo,tree);
				break;
			case IPDC_ENCTYPE:
				proto_tree_add_text(tag_tree, tvb,
						    offset, len + 2,
						    "0x%2.2x: %s: %s",
						    tag, des, val_to_str_const(
							    tvb_get_guint8(tvb,offset+2),
							    encoding_type_vals,
							    TEXT_UNDEFINED));
				if (len == 2) {
					proto_tree_add_text(tag_tree, tvb,
							    offset, len + 2,
							    "0x%2.2x: %s: %u",
							    tag, des,
							    tvb_get_guint8(tvb,offset+3));
				}
				break;
				/* default */
			default:
				proto_tree_add_text(tag_tree, tvb, offset,
						    len + 2, "0x%2.2x: %s", tag, des);
		} /* switch */
		offset += len + 2;
	}
}

static void
dissect_ipdc_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ipdc_common(tvb, pinfo, tree);
}

static void
dissect_ipdc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	new_packet = TRUE;
	tcp_dissect_pdus(tvb, pinfo, tree, ipdc_desegment, 4,
			 get_ipdc_pdu_len, dissect_ipdc_tcp_pdu);
}

void
proto_register_ipdc(void)
{

	static hf_register_info hf[] = {
		{ &hf_ipdc_nr,
		  { "N(r)",	"ipdc.nr",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Receive sequence number", HFILL }
		},

		{ &hf_ipdc_ns,
		  { "N(s)",	"ipdc.ns",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Transmit sequence number", HFILL }
		},

		{ &hf_ipdc_payload_len,
		  { "Payload length",	"ipdc.length",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ipdc_protocol_id,
		  { "Protocol ID",	"ipdc.protocol_id",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ipdc_trans_id_size,
		  { "Transaction ID size",	"ipdc.trans_id_size",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ipdc_trans_id,
		  { "Transaction ID",	"ipdc.trans_id",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},

		{ &hf_ipdc_message_code,
		  { "Message code",	"ipdc.message_code",
		    FT_UINT16, BASE_HEX, VALS(message_code_vals), 0x0,
		    NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_ipdc,
		&ett_ipdc_tag,
	};

	module_t *ipdc_module;

	proto_ipdc = proto_register_protocol("IP Device Control (SS7 over IP)",
					     "IPDC", "ipdc");
	proto_register_field_array(proto_ipdc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ipdc_module = prefs_register_protocol(proto_ipdc, proto_reg_handoff_ipdc);
	prefs_register_bool_preference(ipdc_module, "desegment_ipdc_messages",
				       "Reassemble IPDC messages spanning multiple TCP segments",
				       "Whether the IPDC dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &ipdc_desegment);
	prefs_register_uint_preference(ipdc_module, "tcp.port",
				       "IPDC monitoring port",
				       "Set the IPDC monitoring port", 10,
				       &ipdc_port_pref);
}

void
proto_reg_handoff_ipdc(void)
{
	static guint last_ipdc_port_pref = 0;
	static dissector_handle_t ipdc_tcp_handle = NULL;

	if (ipdc_tcp_handle) {
		dissector_delete_uint("tcp.port", last_ipdc_port_pref,
			ipdc_tcp_handle);
	} else {
		ipdc_tcp_handle =
			create_dissector_handle(dissect_ipdc_tcp, proto_ipdc);
		q931_handle = find_dissector("q931");
	}

	last_ipdc_port_pref = ipdc_port_pref;
	dissector_add_uint("tcp.port", ipdc_port_pref, ipdc_tcp_handle);
}
