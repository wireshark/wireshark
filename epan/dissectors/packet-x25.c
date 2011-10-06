/* packet-x25.c
 * Routines for X.25 packet disassembly
 * Olivier Abad <oabad@noos.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <epan/llcsaps.h>
#include <epan/packet.h>
#include <epan/circuit.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/nlpid.h>
#include <epan/x264_prt_id.h>

/*
 * Direction of packet.
 */
typedef enum {
	X25_FROM_DCE,		/* DCE->DTE */
	X25_FROM_DTE,		/* DTE->DCE */
	X25_UNKNOWN		/* direction unknown */
} x25_dir_t;

/*
 * 0 for data packets, 1 for non-data packets.
 */
#define	X25_NONDATA_BIT			0x01

#define	X25_CALL_REQUEST		0x0B
#define	X25_CALL_ACCEPTED		0x0F
#define	X25_CLEAR_REQUEST		0x13
#define	X25_CLEAR_CONFIRMATION		0x17
#define	X25_INTERRUPT			0x23
#define	X25_INTERRUPT_CONFIRMATION	0x27
#define	X25_RESET_REQUEST		0x1B
#define	X25_RESET_CONFIRMATION		0x1F
#define	X25_RESTART_REQUEST		0xFB
#define	X25_RESTART_CONFIRMATION	0xFF
#define	X25_REGISTRATION_REQUEST	0xF3
#define	X25_REGISTRATION_CONFIRMATION	0xF7
#define	X25_DIAGNOSTIC			0xF1
#define	X25_RR				0x01
#define	X25_RNR				0x05
#define	X25_REJ				0x09
#define	X25_DATA			0x00

#define PACKET_IS_DATA(type)		(!(type & X25_NONDATA_BIT))
#define PACKET_TYPE_FC(type)		(type & 0x1F)

#define X25_MBIT_MOD8			0x10
#define X25_MBIT_MOD128			0x01

#define X25_ABIT			0x8000

#define X25_QBIT			0x8000
#define X25_DBIT			0x4000

#define X25_FAC_CLASS_MASK		0xC0

#define X25_FAC_CLASS_A			0x00
#define X25_FAC_CLASS_B			0x40
#define X25_FAC_CLASS_C			0x80
#define X25_FAC_CLASS_D			0xC0

#define X25_FAC_COMP_MARK		0x00
#define X25_FAC_REVERSE			0x01
#define X25_FAC_THROUGHPUT		0x02
#define X25_FAC_CUG			0x03
#define X25_FAC_CHARGING_INFO		0x04
#define X25_FAC_CALLED_MODIF		0x08
#define X25_FAC_CUG_OUTGOING_ACC	0x09
#define X25_FAC_THROUGHPUT_MIN		0x0A
#define X25_FAC_EXPRESS_DATA		0x0B
#define X25_FAC_BILATERAL_CUG		0x41
#define X25_FAC_PACKET_SIZE		0x42
#define X25_FAC_WINDOW_SIZE		0x43
#define X25_FAC_RPOA_SELECTION		0x44
#define X25_FAC_CUG_EXT			0x47
#define X25_FAC_CUG_OUTGOING_ACC_EXT	0x48
#define X25_FAC_TRANSIT_DELAY		0x49
#define X25_FAC_CALL_DURATION		0xC1
#define X25_FAC_SEGMENT_COUNT		0xC2
#define X25_FAC_CALL_TRANSFER		0xC3
#define X25_FAC_RPOA_SELECTION_EXT	0xC4
#define X25_FAC_MONETARY_UNIT		0xC5
#define X25_FAC_NUI			0xC6
#define X25_FAC_CALLED_ADDR_EXT		0xC9
#define X25_FAC_ETE_TRANSIT_DELAY	0xCA
#define X25_FAC_CALLING_ADDR_EXT	0xCB
#define X25_FAC_CALL_DEFLECT		0xD1
#define X25_FAC_PRIORITY		0xD2

static int proto_x25 = -1;
static int hf_x25_gfi = -1;
static int hf_x25_abit = -1;
static int hf_x25_qbit = -1;
static int hf_x25_dbit = -1;
static int hf_x25_mod = -1;
static int hf_x25_lcn = -1;
static int hf_x25_type = -1;
static int hf_x25_type_fc_mod8 = -1;
static int hf_x25_type_data = -1;
static int hf_x25_p_r_mod8 = -1;
static int hf_x25_p_r_mod128 = -1;
static int hf_x25_mbit_mod8 = -1;
static int hf_x25_mbit_mod128 = -1;
static int hf_x25_p_s_mod8 = -1;
static int hf_x25_p_s_mod128 = -1;

static gint ett_x25 = -1;
static gint ett_x25_gfi = -1;
static gint ett_x25_fac = -1;
static gint ett_x25_fac_unknown = -1;
static gint ett_x25_fac_mark = -1;
static gint ett_x25_fac_reverse = -1;
static gint ett_x25_fac_charging_info = -1;
static gint ett_x25_fac_throughput = -1;
static gint ett_x25_fac_cug = -1;
static gint ett_x25_fac_called_modif = -1;
static gint ett_x25_fac_cug_outgoing_acc = -1;
static gint ett_x25_fac_throughput_min = -1;
static gint ett_x25_fac_express_data = -1;
static gint ett_x25_fac_bilateral_cug = -1;
static gint ett_x25_fac_packet_size = -1;
static gint ett_x25_fac_window_size = -1;
static gint ett_x25_fac_rpoa_selection = -1;
static gint ett_x25_fac_cug_ext = -1;
static gint ett_x25_fac_cug_outgoing_acc_ext = -1;
static gint ett_x25_fac_transit_delay = -1;
static gint ett_x25_fac_call_duration = -1;
static gint ett_x25_fac_segment_count = -1;
static gint ett_x25_fac_call_transfer = -1;
static gint ett_x25_fac_rpoa_selection_ext = -1;
static gint ett_x25_fac_monetary_unit = -1;
static gint ett_x25_fac_nui = -1;
static gint ett_x25_fac_called_addr_ext = -1;
static gint ett_x25_fac_ete_transit_delay = -1;
static gint ett_x25_fac_calling_addr_ext = -1;
static gint ett_x25_fac_call_deflect = -1;
static gint ett_x25_fac_priority = -1;
static gint ett_x25_user_data = -1;

static gint ett_x25_segment = -1;
static gint ett_x25_segments = -1;
static gint hf_x25_segments = -1;
static gint hf_x25_segment = -1;
static gint hf_x25_segment_overlap = -1;
static gint hf_x25_segment_overlap_conflict = -1;
static gint hf_x25_segment_multiple_tails = -1;
static gint hf_x25_segment_too_long_segment = -1;
static gint hf_x25_segment_error = -1;
static gint hf_x25_segment_count = -1;
static gint hf_x25_reassembled_length = -1;

static const value_string vals_modulo[] = {
	{ 1, "8" },
	{ 2, "128" },
	{ 0, NULL}
};

static const value_string vals_x25_type[] = {
	{ X25_CALL_REQUEST, "Call" },
	{ X25_CALL_ACCEPTED, "Call Accepted" },
	{ X25_CLEAR_REQUEST, "Clear" },
	{ X25_CLEAR_CONFIRMATION, "Clear Confirmation" },
	{ X25_INTERRUPT, "Interrupt" },
	{ X25_INTERRUPT_CONFIRMATION, "Interrupt Confirmation" },
	{ X25_RESET_REQUEST, "Reset" },
	{ X25_RESET_CONFIRMATION, "Reset Confirmation" },
	{ X25_RESTART_REQUEST, "Restart" },
	{ X25_RESTART_CONFIRMATION, "Restart Confirmation" },
	{ X25_REGISTRATION_REQUEST, "Registration" },
	{ X25_REGISTRATION_CONFIRMATION, "Registration Confirmation" },
	{ X25_DIAGNOSTIC, "Diagnostic" },
	{ X25_RR, "RR" },
	{ X25_RNR, "RNR" },
	{ X25_REJ, "REJ" },
	{ X25_DATA, "Data" },
	{ 0,   NULL}
};

static struct true_false_string m_bit_tfs = {
	"More data follows",
	"End of data"
};

static const fragment_items x25_frag_items = {
	&ett_x25_segment,
	&ett_x25_segments,
	&hf_x25_segments,
	&hf_x25_segment,
	&hf_x25_segment_overlap,
	&hf_x25_segment_overlap_conflict,
	&hf_x25_segment_multiple_tails,
	&hf_x25_segment_too_long_segment,
	&hf_x25_segment_error,
	&hf_x25_segment_count,
	NULL,
	&hf_x25_reassembled_length,
	"segments"
};

static dissector_handle_t ip_handle;
static dissector_handle_t clnp_handle;
static dissector_handle_t ositp_handle;
static dissector_handle_t qllc_handle;
static dissector_handle_t data_handle;

/* Preferences */
static gboolean payload_is_qllc_sna = FALSE;
static gboolean call_request_nodata_is_cotp = FALSE;
static gboolean payload_check_data = FALSE;
static gboolean reassemble_x25 = TRUE;

/* Reassembly of X.25 */

static GHashTable *x25_segment_table = NULL;
static GHashTable *x25_reassembled_table = NULL;

static dissector_table_t x25_subdissector_table;
static heur_dissector_list_t x25_heur_subdissector_list;

static void
x25_hash_add_proto_start(guint16 vc, guint32 frame, dissector_handle_t dissect)
{
  circuit_t *circuit;

  /*
   * Is there already a circuit with this VC number?
   */
  circuit = find_circuit(CT_X25, vc, frame);
  if (circuit != NULL) {
    /*
     * Yes - close it, as we're creating a new one.
     */
    close_circuit(circuit, frame - 1);
  }

  /*
   * Set up a new circuit.
   */
  circuit = circuit_new(CT_X25, vc, frame);

  /*
   * Set its dissector.
   */
  circuit_set_dissector(circuit, dissect);
}

static void
x25_hash_add_proto_end(guint16 vc, guint32 frame)
{
  circuit_t *circuit;

  /*
   * Try to find the circuit.
   */
  circuit = find_circuit(CT_X25, vc, frame);

  /*
   * If we succeeded, close it.
   */
  if (circuit != NULL)
    close_circuit(circuit, frame);
}

static const char *clear_code(unsigned char code)
{
    if (code == 0x00 || (code & 0x80) == 0x80)
	return "DTE Originated";
    if (code == 0x01)
	return "Number Busy";
    if (code == 0x03)
	return "Invalid Facility Requested";
    if (code == 0x05)
	return "Network Congestion";
    if (code == 0x09)
	return "Out Of Order";
    if (code == 0x0B)
	return "Access Barred";
    if (code == 0x0D)
	return "Not Obtainable";
    if (code == 0x11)
	return "Remote Procedure Error";
    if (code == 0x13)
	return "Local Procedure Error";
    if (code == 0x15)
	return "RPOA Out Of Order";
    if (code == 0x19)
	return "Reverse Charging Acceptance Not Subscribed";
    if (code == 0x21)
	return "Incompatible Destination";
    if (code == 0x29)
	return "Fast Select Acceptance Not Subscribed";
    if (code == 0x39)
	return "Destination Absent";

    return ep_strdup_printf("Unknown %02X", code);
}

static const char *clear_diag(unsigned char code)
{
    if (code == 0)
	return "No additional information";
    if (code == 1)
	return "Invalid P(S)";
    if (code == 2)
	return "Invalid P(R)";
    if (code == 16)
	return "Packet type invalid";
    if (code == 17)
	return "Packet type invalid for state r1";
    if (code == 18)
	return "Packet type invalid for state r2";
    if (code == 19)
	return "Packet type invalid for state r3";
    if (code == 20)
	return "Packet type invalid for state p1";
    if (code == 21)
	return "Packet type invalid for state p2";
    if (code == 22)
	return "Packet type invalid for state p3";
    if (code == 23)
	return "Packet type invalid for state p4";
    if (code == 24)
	return "Packet type invalid for state p5";
    if (code == 25)
	return "Packet type invalid for state p6";
    if (code == 26)
	return "Packet type invalid for state p7";
    if (code == 27)
	return "Packet type invalid for state d1";
    if (code == 28)
	return "Packet type invalid for state d2";
    if (code == 29)
	return "Packet type invalid for state d3";
    if (code == 32)
	return "Packet not allowed";
    if (code == 33)
	return "Unidentifiable packet";
    if (code == 34)
	return "Call on one-way logical channel";
    if (code == 35)
	return "Invalid packet type on a PVC";
    if (code == 36)
	return "Packet on unassigned LC";
    if (code == 37)
	return "Reject not subscribed to";
    if (code == 38)
	return "Packet too short";
    if (code == 39)
	return "Packet too long";
    if (code == 40)
	return "Invalid general format identifier";
    if (code == 41)
	return "Restart/registration packet with nonzero bits";
    if (code == 42)
	return "Packet type not compatible with facility";
    if (code == 43)
	return "Unauthorised interrupt confirmation";
    if (code == 44)
	return "Unauthorised interrupt";
    if (code == 45)
	return "Unauthorised reject";
    if (code == 48)
	return "Time expired";
    if (code == 49)
	return "Time expired for incoming call";
    if (code == 50)
	return "Time expired for clear indication";
    if (code == 51)
	return "Time expired for reset indication";
    if (code == 52)
	return "Time expired for restart indication";
    if (code == 53)
	return "Time expired for call deflection";
    if (code == 64)
	return "Call set-up/clearing or registration pb.";
    if (code == 65)
	return "Facility/registration code not allowed";
    if (code == 66)
	return "Facility parameter not allowed";
    if (code == 67)
	return "Invalid called DTE address";
    if (code == 68)
	return "Invalid calling DTE address";
    if (code == 69)
	return "Invalid facility/registration length";
    if (code == 70)
	return "Incoming call barred";
    if (code == 71)
	return "No logical channel available";
    if (code == 72)
	return "Call collision";
    if (code == 73)
	return "Duplicate facility requested";
    if (code == 74)
	return "Non zero address length";
    if (code == 75)
	return "Non zero facility length";
    if (code == 76)
	return "Facility not provided when expected";
    if (code == 77)
	return "Invalid CCITT-specified DTE facility";
    if (code == 78)
	return "Max. nb of call redir/defl. exceeded";
    if (code == 80)
	return "Miscellaneous";
    if (code == 81)
	return "Improper cause code from DTE";
    if (code == 82)
	return "Not aligned octet";
    if (code == 83)
	return "Inconsistent Q bit setting";
    if (code == 84)
	return "NUI problem";
    if (code == 112)
	return "International problem";
    if (code == 113)
	return "Remote network problem";
    if (code == 114)
	return "International protocol problem";
    if (code == 115)
	return "International link out of order";
    if (code == 116)
	return "International link busy";
    if (code == 117)
	return "Transit network facility problem";
    if (code == 118)
	return "Remote network facility problem";
    if (code == 119)
	return "International routing problem";
    if (code == 120)
	return "Temporary routing problem";
    if (code == 121)
	return "Unknown called DNIC";
    if (code == 122)
	return "Maintenance action";
    if (code == 144)
	return "Timer expired or retransmission count surpassed";
    if (code == 145)
	return "Timer expired or retransmission count surpassed for INTERRUPT";
    if (code == 146)
	return "Timer expired or retransmission count surpassed for DATA "
	       "packet transmission";
    if (code == 147)
	return "Timer expired or retransmission count surpassed for REJECT";
    if (code == 160)
	return "DTE-specific signals";
    if (code == 161)
	return "DTE operational";
    if (code == 162)
	return "DTE not operational";
    if (code == 163)
	return "DTE resource constraint";
    if (code == 164)
	return "Fast select not subscribed";
    if (code == 165)
	return "Invalid partially full DATA packet";
    if (code == 166)
	return "D-bit procedure not supported";
    if (code == 167)
	return "Registration/Cancellation confirmed";
    if (code == 224)
	return "OSI network service problem";
    if (code == 225)
	return "Disconnection (transient condition)";
    if (code == 226)
	return "Disconnection (permanent condition)";
    if (code == 227)
	return "Connection rejection - reason unspecified (transient "
	       "condition)";
    if (code == 228)
	return "Connection rejection - reason unspecified (permanent "
	       "condition)";
    if (code == 229)
	return "Connection rejection - quality of service not available "
               "transient condition)";
    if (code == 230)
	return "Connection rejection - quality of service not available "
               "permanent condition)";
    if (code == 231)
	return "Connection rejection - NSAP unreachable (transient condition)";
    if (code == 232)
	return "Connection rejection - NSAP unreachable (permanent condition)";
    if (code == 233)
	return "reset - reason unspecified";
    if (code == 234)
	return "reset - congestion";
    if (code == 235)
	return "Connection rejection - NSAP address unknown (permanent "
               "condition)";
    if (code == 240)
	return "Higher layer initiated";
    if (code == 241)
	return "Disconnection - normal";
    if (code == 242)
	return "Disconnection - abnormal";
    if (code == 243)
	return "Disconnection - incompatible information in user data";
    if (code == 244)
	return "Connection rejection - reason unspecified (transient "
               "condition)";
    if (code == 245)
	return "Connection rejection - reason unspecified (permanent "
               "condition)";
    if (code == 246)
	return "Connection rejection - quality of service not available "
               "(transient condition)";
    if (code == 247)
	return "Connection rejection - quality of service not available "
               "(permanent condition)";
    if (code == 248)
	return "Connection rejection - incompatible information in user data";
    if (code == 249)
	return "Connection rejection - unrecognizable protocol identifier "
               "in user data";
    if (code == 250)
	return "Reset - user resynchronization";

    return ep_strdup_printf("Unknown %d", code);
}

static const char *reset_code(unsigned char code)
{
    if (code == 0x00 || (code & 0x80) == 0x80)
	return "DTE Originated";
    if (code == 0x01)
	return "Out of order";
    if (code == 0x03)
	return "Remote Procedure Error";
    if (code == 0x05)
	return "Local Procedure Error";
    if (code == 0x07)
	return "Network Congestion";
    if (code == 0x09)
	return "Remote DTE operational";
    if (code == 0x0F)
	return "Network operational";
    if (code == 0x11)
	return "Incompatible Destination";
    if (code == 0x1D)
	return "Network out of order";

    return ep_strdup_printf("Unknown %02X", code);
}

static const char *restart_code(unsigned char code)
{
    if (code == 0x00 || (code & 0x80) == 0x80)
	return "DTE Originated";
    if (code == 0x01)
	return "Local Procedure Error";
    if (code == 0x03)
	return "Network Congestion";
    if (code == 0x07)
	return "Network Operational";
    if (code == 0x7F)
	return "Registration/cancellation confirmed";

    return ep_strdup_printf("Unknown %02X", code);
}

static const char *registration_code(unsigned char code)
{
    if (code == 0x03)
	return "Invalid facility request";
    if (code == 0x05)
	return "Network congestion";
    if (code == 0x13)
	return "Local procedure error";
    if (code == 0x7F)
	return "Registration/cancellation confirmed";

    return ep_strdup_printf("Unknown %02X", code);
}

static void
dump_facilities(proto_tree *tree, int *offset, tvbuff_t *tvb)
{
    guint8 fac, byte1, byte2, byte3;
    guint32 len;      /* facilities length */
    proto_item *ti=0;
    proto_tree *fac_tree = 0;
    proto_tree *fac_subtree;

    len = tvb_get_guint8(tvb, *offset);
    if (len && tree) {
	ti = proto_tree_add_text(tree, tvb, *offset, len + 1,
		                 "Facilities");
	fac_tree = proto_item_add_subtree(ti, ett_x25_fac);
	proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Facilities length: %d", len);
    }
    (*offset)++;

    while (len > 0) {
	fac = tvb_get_guint8(tvb, *offset);
	switch(fac & X25_FAC_CLASS_MASK) {
	case X25_FAC_CLASS_A:
	    switch (fac) {
	    case X25_FAC_COMP_MARK:
		if (fac_tree)
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : 00 (Marker)");
		switch (tvb_get_guint8(tvb, *offset + 1)) {
		case 0x00:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : 00 (Network complementary "
					    "services - calling DTE)");
		    }
		    break;
		case 0xFF:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : FF (Network complementary "
					    "services - called DTE)");
		    }
		    break;
		case 0x0F:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : 0F (DTE complementary "
					    "services)");
		    }
		    break;
		default:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : %02X (Unknown marker)",
					    tvb_get_guint8(tvb, *offset+1));
		    }
		    break;
		}
		break;
	    case X25_FAC_REVERSE:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Reverse charging / Fast select)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_reverse);
		    byte1 = tvb_get_guint8(tvb, *offset + 1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter : %02X", byte1);
		    if (byte1 & 0xC0)
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"11.. .... = Fast select with restriction");
		    else if (byte1 & 0x80)
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"10.. .... = Fast select - no restriction");
		    else
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"00.. .... = Fast select not requested");
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1, "%s",
			    decode_boolean_bitfield(byte1, 0x01, 1*8,
				"Reverse charging requested",
				"Reverse charging not requested"));
		}
		break;
	    case X25_FAC_CHARGING_INFO:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Charging information)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_charging_info);
		    byte1 = tvb_get_guint8(tvb, *offset + 1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter : %02X", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1, "%s",
			    decode_boolean_bitfield(byte1, 0x01, 1*8,
				"Charging information requested",
				"Charging information not requested"));
		}
		break;
	    case X25_FAC_THROUGHPUT:
		if (fac_tree) {
		    char *tmpbuf;

		    tmpbuf=ep_alloc(80);
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Throughput class negotiation)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_throughput);
		    byte1 = tvb_get_guint8(tvb, *offset + 1);
		    switch (byte1 >> 4)
		    {
		    case 3:
		    case 4:
		    case 5:
		    case 6:
		    case 7:
		    case 8:
		    case 9:
		    case 10:
		    case 11:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (%d bps)",
				75*(1<<((byte1 >> 4)-3)));
			break;
		    case 12:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (48000 bps)");
			break;
		    case 13:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (64000 bps)");
			break;
		    default:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (Reserved)");
		    }
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1, "%s",
			    decode_numeric_bitfield(byte1, 0xF0, 1*8, tmpbuf));
		    switch (byte1 & 0x0F)
		    {
		    case 3:
		    case 4:
		    case 5:
		    case 6:
		    case 7:
		    case 8:
		    case 9:
		    case 10:
		    case 11:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (%d bps)",
				75*(1<<((byte1 & 0x0F)-3)));
			break;
		    case 12:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (48000 bps)");
			break;
		    case 13:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (64000 bps)");
			break;
		    default:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (Reserved)");
		    }
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1, "%s",
			    decode_numeric_bitfield(byte1, 0x0F, 1*8, tmpbuf));
		}
		break;
	    case X25_FAC_CUG:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Closed user group selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_cug);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Closed user group: %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_CALLED_MODIF:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Called address modified)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_called_modif);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_CUG_OUTGOING_ACC:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Closed user group with outgoing access selection)",
			    fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_cug_outgoing_acc);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Closed user group: %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_THROUGHPUT_MIN:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Minimum throughput class)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_throughput_min);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_EXPRESS_DATA:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Negotiation of express data)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_express_data);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Unknown class A)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    }
	    (*offset) += 2;
	    len -= 2;
	    break;
	case X25_FAC_CLASS_B:
	    switch (fac) {
	    case X25_FAC_BILATERAL_CUG:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Bilateral closed user group selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_bilateral_cug);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
					"Bilateral CUG: %04X",
					tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    case X25_FAC_PACKET_SIZE:
		if (fac_tree)
		{
		    char *tmpbuf;

		    tmpbuf=ep_alloc(80);
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Packet size)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_packet_size);
		    byte1 = tvb_get_guint8(tvb, *offset + 1);
		    switch (byte1)
		    {
		    case 0x04:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (16)");
			break;
		    case 0x05:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (32)");
			break;
		    case 0x06:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (64)");
			break;
		    case 0x07:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (128)");
			break;
		    case 0x08:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (256)");
			break;
		    case 0x09:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (512)");
			break;
		    case 0x0A:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (1024)");
			break;
		    case 0x0B:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (2048)");
			break;
		    case 0x0C:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (4096)");
			break;
		    default:
			g_snprintf(tmpbuf, 80, "From the called DTE : %%u (Unknown)");
			break;
		    }
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1, "%s",
			    decode_numeric_bitfield(byte1, 0x0F, 1*8, tmpbuf));

		    byte2 = tvb_get_guint8(tvb, *offset + 2);
		    switch (byte2)
		    {
		    case 0x04:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (16)");
			break;
		    case 0x05:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (32)");
			break;
		    case 0x06:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (64)");
			break;
		    case 0x07:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (128)");
			break;
		    case 0x08:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (256)");
			break;
		    case 0x09:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (512)");
			break;
		    case 0x0A:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (1024)");
			break;
		    case 0x0B:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (2048)");
			break;
		    case 0x0C:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (4096)");
			break;
		    default:
			g_snprintf(tmpbuf, 80, "From the calling DTE : %%u (Unknown)");
			break;
		    }
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1, "%s",
			    decode_numeric_bitfield(byte2, 0x0F, 1*8, tmpbuf));
		}
		break;
	    case X25_FAC_WINDOW_SIZE:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Window size)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_window_size);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1, "%s",
			    decode_numeric_bitfield(tvb_get_guint8(tvb, *offset+1),
				0x7F, 1*8, "From the called DTE: %u"));
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1, "%s",
			    decode_numeric_bitfield(tvb_get_guint8(tvb, *offset+2),
				0x7F, 1*8, "From the calling DTE: %u"));
		}
		break;
	    case X25_FAC_RPOA_SELECTION:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(RPOA selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_rpoa_selection);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
					"Data network identification code : %04X",
					tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    case X25_FAC_CUG_EXT:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Extended closed user group selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_cug_ext);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
			    "Closed user group: %04X", tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    case X25_FAC_CUG_OUTGOING_ACC_EXT:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Extended closed user group with outgoing access selection)",
			    fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_cug_outgoing_acc_ext);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
			    "Closed user group: %04X", tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    case X25_FAC_TRANSIT_DELAY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Transit delay selection and indication)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_transit_delay);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
					"Transit delay: %d ms",
					tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Unknown class B)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
			    "Parameter %04X", tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    }
	    (*offset) += 3;
	    len -= 3;
	    break;
	case X25_FAC_CLASS_C:
	    if (fac_tree) {
		ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			"Code : %02X (Unknown class C)", fac);
		fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		proto_tree_add_text(fac_subtree, tvb, *offset+1, 3,
			"Parameter %06X",
			tvb_get_ntoh24(tvb, *offset+1));
	    }
	    (*offset) += 4;
	    len -= 4;
	    break;
	case X25_FAC_CLASS_D:
	    switch (fac) {
	    case X25_FAC_CALL_DURATION:
		if (fac_tree) {
		    int i;

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Call duration)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_call_duration);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    if ((byte1 < 4) || (byte1 % 4)) {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Bogus length : %d", byte1);
			return;
		    } else {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Length : %u", byte1);
		    }
		    for (i = 0; (i<byte1); i+=4) {
			    proto_tree_add_text(fac_subtree, tvb, *offset+2+i, 4,
				"Call duration : %u Day(s) %02X:%02X:%02X Hour(s)",
				tvb_get_guint8(tvb, *offset+2+i),
				tvb_get_guint8(tvb, *offset+3+i),
				tvb_get_guint8(tvb, *offset+4+i),
				tvb_get_guint8(tvb, *offset+5+i));
			}
		}
		break;
	    case X25_FAC_SEGMENT_COUNT:
		if (fac_tree) {
			int i;
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Segment count)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_segment_count);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    if ((byte1 < 8) || (byte1 % 8)) {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Bogus length : %d", byte1);
			return;
		    } else {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Length : %u", byte1);
		    }
		    for (i = 0; (i<byte1); i+=8) {
			    proto_tree_add_text(fac_subtree, tvb, *offset+2+i, 4,
				"Segments sent to DTE : %02X%02X%02X%02X",
				tvb_get_guint8(tvb, *offset+2+i),
				tvb_get_guint8(tvb, *offset+3+i),
				tvb_get_guint8(tvb, *offset+4+i),
				tvb_get_guint8(tvb, *offset+5+i));
			    proto_tree_add_text(fac_subtree, tvb, *offset+6+i, 4,
				"Segments received from DTE : %02X%02X%02X%02X",
				tvb_get_guint8(tvb, *offset+6+i),
				tvb_get_guint8(tvb, *offset+7+i),
				tvb_get_guint8(tvb, *offset+8+i),
				tvb_get_guint8(tvb, *offset+9+i));
			}
		}
		break;
	    case X25_FAC_CALL_TRANSFER:
		if (fac_tree) {
		    int i;
		    char *tmpbuf;

		    tmpbuf=ep_alloc(258);
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Call redirection or deflection notification)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_call_transfer);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    if (byte1 < 2) {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Bogus length : %d", byte1);
			return;
		    } else {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Length : %u", byte1);
		    }
		    byte2 = tvb_get_guint8(tvb, *offset+2);
		    if ((byte2 & 0xC0) == 0xC0) {
			proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				"Reason : call deflection by the originally "
				"called DTE address");
		    }
		    else {
			switch (byte2) {
			case 0x01:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : originally called DTE busy");
			    break;
			case 0x07:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : call dist. within a hunt group");
			    break;
			case 0x09:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : originally called DTE out of order");
			    break;
			case 0x0F:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : systematic call redirection");
			    break;
			default:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : unknown");
			    break;
			}
		    }
		    byte3 = tvb_get_guint8(tvb, *offset+3);
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, 1,
			    "Number of semi-octets in DTE address : %u",
			    byte3);
		    for (i = 0; (i<byte3)&&(i<256); i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+4+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+4+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+4, byte1 - 2,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_RPOA_SELECTION_EXT:
		if (fac_tree) {
		    int i;

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Extended RPOA selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_rpoa_selection_ext);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    if ((byte1 < 2) || (byte1 % 2)) {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Bogus length : %d", byte1);
			return;
		    } else {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Length : %u", byte1);
		    }
		    for (i = 0; (i<byte1); i+=2) {
			    proto_tree_add_text(fac_subtree, tvb, *offset+2+i, 2,
				"Data network identification code : %04X",
				tvb_get_ntohs(tvb, *offset+2+i));
			}
		}
		break;
	    case X25_FAC_CALLING_ADDR_EXT:
		if (fac_tree) {
		    int i;
		    char *tmpbuf;

		    tmpbuf=ep_alloc(258);
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Calling address extension)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_calling_addr_ext);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    if (byte1 < 1) {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Bogus length : %d", byte1);
			return;
		    } else {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Length : %u", byte1);
		    }
		    byte2 = tvb_get_guint8(tvb, *offset+2) & 0x3F;
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
			    "Number of semi-octets in DTE address : %u", byte2);
		    for (i = 0; (i<byte2)&&(i<256) ; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+3+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+3+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, byte1 - 1,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_MONETARY_UNIT:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Monetary Unit)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_monetary_unit);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "Value");
		}
		break;
	    case X25_FAC_NUI:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Network User Identification selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_nui);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "NUI");
		}
		break;
	    case X25_FAC_CALLED_ADDR_EXT:
		if (fac_tree) {
		    int i;
		    char *tmpbuf;

		    tmpbuf=ep_alloc(258);
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Called address extension)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_called_addr_ext);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    if (byte1 < 1) {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Bogus length : %d", byte1);
			return;
		    } else {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Length : %u", byte1);
		    }
		    byte2 = tvb_get_guint8(tvb, *offset+2) & 0x3F;
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
			    "Number of semi-octets in DTE address : %u", byte2);
		    for (i = 0; (i<byte2)&&(i<256) ; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+3+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+3+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, byte1 - 1,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_ETE_TRANSIT_DELAY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(End to end transit delay)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_ete_transit_delay);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "Value");
		}
		break;
	    case X25_FAC_CALL_DEFLECT:
		if (fac_tree) {
		    int i;
		    char *tmpbuf;

		    tmpbuf=ep_alloc(258);
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Call deflection selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_call_deflect);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    if (byte1 < 2) {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Bogus length : %d", byte1);
			return;
		    } else {
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"Length : %u", byte1);
		    }
		    byte2 = tvb_get_guint8(tvb, *offset+2);
		    if ((byte2 & 0xC0) == 0xC0)
			proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				"Reason : call DTE originated");
		    else
			proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				"Reason : unknown");
		    byte3 = tvb_get_guint8(tvb, *offset+3);
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, 1,
			    "Number of semi-octets in the alternative DTE address : %u",
			    byte3);
		    for (i = 0; (i<byte3)&&(i<256) ; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+4+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+4+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+4, byte1 - 2,
			    "Alternative DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_PRIORITY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Priority)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_priority);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "Value");
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Unknown class D)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "Value");
		}
	    }
	    byte1 = tvb_get_guint8(tvb, *offset+1);
	    (*offset) += byte1+2;
	    len -= byte1+2;
	    break;
	}
    }
}

static void
x25_ntoa(proto_tree *tree, int *offset, tvbuff_t *tvb,
	 packet_info *pinfo, gboolean is_registration)
{
    int len1, len2;
    int i;
    char *addr1, *addr2;
    char *first, *second;
    guint8 byte;
    int localoffset;

    addr1=ep_alloc(16);
    addr2=ep_alloc(16);

    byte = tvb_get_guint8(tvb, *offset);
    len1 = (byte >> 0) & 0x0F;
    len2 = (byte >> 4) & 0x0F;

    if (tree) {
	proto_tree_add_text(tree, tvb, *offset, 1, "%s",
		decode_numeric_bitfield(byte, 0xF0, 1*8,
			is_registration ?
		          "DTE address length : %u" :
		          "Calling address length : %u"));
	proto_tree_add_text(tree, tvb, *offset, 1, "%s",
		decode_numeric_bitfield(byte, 0x0F, 1*8,
			is_registration ?
		          "DCE address length : %u" :
		          "Called address length : %u"));
    }
    (*offset)++;

    localoffset = *offset;
    byte = tvb_get_guint8(tvb, localoffset);

    first=addr1;
    second=addr2;
    for (i = 0; i < (len1 + len2); i++) {
	if (i < len1) {
	    if (i % 2 != 0) {
		*first++ = ((byte >> 0) & 0x0F) + '0';
		localoffset++;
		byte = tvb_get_guint8(tvb, localoffset);
	    } else {
		*first++ = ((byte >> 4) & 0x0F) + '0';
	    }
	} else {
	    if (i % 2 != 0) {
		*second++ = ((byte >> 0) & 0x0F) + '0';
		localoffset++;
		byte = tvb_get_guint8(tvb, localoffset);
	    } else {
		*second++ = ((byte >> 4) & 0x0F) + '0';
	    }
	}
    }

    *first  = '\0';
    *second = '\0';

    if (len1) {
        col_add_str(pinfo->cinfo, COL_RES_DL_DST, addr1);
	if (tree)
	    proto_tree_add_text(tree, tvb, *offset,
				(len1 + 1) / 2,
				is_registration ?
				  "DCE address : %s" :
				  "Called address : %s",
				addr1);
    }
    if (len2) {
        col_add_str(pinfo->cinfo, COL_RES_DL_SRC, addr2);
	if (tree)
	    proto_tree_add_text(tree, tvb, *offset + len1/2,
				(len2+1)/2+(len1%2+(len2+1)%2)/2,
				is_registration ?
				  "DTE address : %s" :
				  "Calling address : %s",
				addr2);
    }
    (*offset) += ((len1 + len2 + 1) / 2);
}

static void
x25_toa(proto_tree *tree, int *offset, tvbuff_t *tvb,
	packet_info *pinfo)
{
    int len1, len2;
    int i;
    char *addr1, *addr2;
    char *first, *second;
    guint8 byte;
    int localoffset;

    addr1=ep_alloc(256);
    addr2=ep_alloc(256);

    len1 = tvb_get_guint8(tvb, *offset);
    if (tree) {
	proto_tree_add_text(tree, tvb, *offset, 1,
		    "Called address length : %u",
		    len1);
    }
    (*offset)++;

    len2 = tvb_get_guint8(tvb, *offset);
    if (tree) {
	proto_tree_add_text(tree, tvb, *offset, 1,
		    "Calling address length : %u",
		    len2);
    }
    (*offset)++;

    localoffset = *offset;
    byte = tvb_get_guint8(tvb, localoffset);

    /*
     * XXX - the first two half-octets of the address are the TOA and
     * NPI; process them as such and, if the TOA says an address is
     * an alternative address, process it correctly (i.e., not as a
     * sequence of half-octets containing digit values).
     */
    first=addr1;
    second=addr2;
    for (i = 0; i < (len1 + len2); i++) {
	if (i < len1) {
	    if (i % 2 != 0) {
		*first++ = ((byte >> 0) & 0x0F) + '0';
		localoffset++;
		byte = tvb_get_guint8(tvb, localoffset);
	    } else {
		*first++ = ((byte >> 4) & 0x0F) + '0';
	    }
	} else {
	    if (i % 2 != 0) {
		*second++ = ((byte >> 0) & 0x0F) + '0';
		localoffset++;
		byte = tvb_get_guint8(tvb, localoffset);
	    } else {
		*second++ = ((byte >> 4) & 0x0F) + '0';
	    }
	}
    }

    *first  = '\0';
    *second = '\0';

    if (len1) {
        col_add_str(pinfo->cinfo, COL_RES_DL_DST, addr1);
	if (tree)
	    proto_tree_add_text(tree, tvb, *offset,
				(len1 + 1) / 2,
				"Called address : %s",
				addr1);
    }
    if (len2) {
        col_add_str(pinfo->cinfo, COL_RES_DL_SRC, addr2);
	if (tree)
	    proto_tree_add_text(tree, tvb, *offset + len1/2,
				(len2+1)/2+(len1%2+(len2+1)%2)/2,
				"Calling address : %s",
				addr2);
    }
    (*offset) += ((len1 + len2 + 1) / 2);
}

static int
get_x25_pkt_len(tvbuff_t *tvb)
{
    guint length, called_len, calling_len, dte_len, dce_len;
    guint8 byte2, bytex;

    byte2 = tvb_get_guint8(tvb, 2);
    switch (byte2)
    {
    case X25_CALL_REQUEST:
	bytex = tvb_get_guint8(tvb, 3);
	called_len  = (bytex >> 0) & 0x0F;
	calling_len = (bytex >> 4) & 0x0F;
	length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* facilities */

	return MIN(tvb_reported_length(tvb),length);

    case X25_CALL_ACCEPTED:
	/* The calling/called address length byte (following the packet type)
	 * is not mandatory, so we must check the packet length before trying
	 * to read it */
	if (tvb_reported_length(tvb) == 3)
	    return(3);
	bytex = tvb_get_guint8(tvb, 3);
	called_len  = (bytex >> 0) & 0x0F;
	calling_len = (bytex >> 4) & 0x0F;
	length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* facilities */

	return MIN(tvb_reported_length(tvb),length);

    case X25_CLEAR_REQUEST:
    case X25_RESET_REQUEST:
    case X25_RESTART_REQUEST:
	return MIN(tvb_reported_length(tvb),5);

    case X25_DIAGNOSTIC:
	return MIN(tvb_reported_length(tvb),4);

    case X25_CLEAR_CONFIRMATION:
    case X25_INTERRUPT:
    case X25_INTERRUPT_CONFIRMATION:
    case X25_RESET_CONFIRMATION:
    case X25_RESTART_CONFIRMATION:
	return MIN(tvb_reported_length(tvb),3);

    case X25_REGISTRATION_REQUEST:
	bytex = tvb_get_guint8(tvb, 3);
	dce_len = (bytex >> 0) & 0x0F;
	dte_len = (bytex >> 4) & 0x0F;
	length = 4 + (dte_len + dce_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* registration */

	return MIN(tvb_reported_length(tvb),length);

    case X25_REGISTRATION_CONFIRMATION:
	bytex = tvb_get_guint8(tvb, 5);
	dce_len = (bytex >> 0) & 0x0F;
	dte_len = (bytex >> 4) & 0x0F;
	length = 6 + (dte_len + dce_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* registration */

	return MIN(tvb_reported_length(tvb),length);
    }

    if (PACKET_IS_DATA(byte2))
	return MIN(tvb_reported_length(tvb),3);

    switch (PACKET_TYPE_FC(byte2))
    {
    case X25_RR:
	return MIN(tvb_reported_length(tvb),3);

    case X25_RNR:
	return MIN(tvb_reported_length(tvb),3);

    case X25_REJ:
	return MIN(tvb_reported_length(tvb),3);
    }

    return 0;
}

static const value_string prt_id_vals[] = {
        {PRT_ID_ISO_8073,           "ISO 8073 COTP"},
        {PRT_ID_ISO_8602,           "ISO 8602 CLTP"},
        {PRT_ID_ISO_10736_ISO_8073, "ISO 10736 in conjunction with ISO 8073 COTP"},
        {PRT_ID_ISO_10736_ISO_8602, "ISO 10736 in conjunction with ISO 8602 CLTP"},
        {0x00,                      NULL}
};

static const value_string sharing_strategy_vals[] = {
        {0x00,            "No sharing"},
        {0x00,            NULL}
};

static void
dissect_x25_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    x25_dir_t dir, gboolean side)
{
    proto_tree *x25_tree=0, *gfi_tree=0, *userdata_tree=0;
    proto_item *ti;
    guint localoffset=0;
    guint x25_pkt_len;
    int modulo;
    guint16 vc;
    dissector_handle_t dissect = NULL;
    gboolean toa;         /* TOA/NPI address format */
    guint16 bytes0_1;
    guint8 pkt_type;
    const char *short_name = NULL, *long_name = NULL;
    tvbuff_t *next_tvb = NULL;
    gboolean q_bit_set = FALSE;
    gboolean m_bit_set;
    gint payload_len;
    guint32 frag_key;
    void *saved_private_data;
    fragment_data *fd_head;


    guint8 spi;
    int is_x_264;
    guint8 prt_id;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "X.25");

    bytes0_1 = tvb_get_ntohs(tvb, 0);

    modulo = ((bytes0_1 & 0x2000) ? 128 : 8);
    vc     = (int)(bytes0_1 & 0x0FFF);

    pinfo->ctype = CT_X25;
    pinfo->circuit_id = vc;

    if (bytes0_1 & X25_ABIT) toa = TRUE;
    else toa = FALSE;

    x25_pkt_len = get_x25_pkt_len(tvb);
    if (x25_pkt_len < 3) /* packet too short */
    {
	col_set_str(pinfo->cinfo, COL_INFO, "Invalid/short X.25 packet");
	if (tree)
	    proto_tree_add_protocol_format(tree, proto_x25, tvb, 0, -1,
		    "Invalid/short X.25 packet");
	return;
    }

    pkt_type = tvb_get_guint8(tvb, 2);
    if (PACKET_IS_DATA(pkt_type)) {
	if (bytes0_1 & X25_QBIT)
	    q_bit_set = TRUE;
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_x25, tvb, 0, x25_pkt_len, FALSE);
        x25_tree = proto_item_add_subtree(ti, ett_x25);
        ti = proto_tree_add_item(x25_tree, hf_x25_gfi, tvb, 0, 2, ENC_BIG_ENDIAN);
        gfi_tree = proto_item_add_subtree(ti, ett_x25_gfi);

        if (PACKET_IS_DATA(pkt_type)) {
            proto_tree_add_boolean(gfi_tree, hf_x25_qbit, tvb, 0, 2,
                bytes0_1);
        }
        else if (pkt_type == X25_CALL_REQUEST ||
            pkt_type == X25_CALL_ACCEPTED ||
            pkt_type == X25_CLEAR_REQUEST ||
            pkt_type == X25_CLEAR_CONFIRMATION) {
            proto_tree_add_boolean(gfi_tree, hf_x25_abit, tvb, 0, 2,
                bytes0_1);
        }

        if (pkt_type == X25_CALL_REQUEST || pkt_type == X25_CALL_ACCEPTED ||
            PACKET_IS_DATA(pkt_type)) {
            proto_tree_add_boolean(gfi_tree, hf_x25_dbit, tvb, 0, 2,
                bytes0_1);
        }
        proto_tree_add_uint(gfi_tree, hf_x25_mod, tvb, 0, 2, bytes0_1);
    }

    switch (pkt_type) {
    case X25_CALL_REQUEST:
        switch (dir) {

	case X25_FROM_DCE:
	    short_name = "Inc. call";
	    long_name = "Incoming call";
	    break;

	case X25_FROM_DTE:
	    short_name = "Call req.";
	    long_name = "Call request";
	    break;

	case X25_UNKNOWN:
	    short_name = "Inc. call/Call req.";
	    long_name = "Incoming call/Call request";
	    break;
	}
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d", short_name, vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb,
		    0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_CALL_REQUEST, "Packet Type: %s", long_name);
	}
	localoffset = 3;
	if (localoffset < x25_pkt_len) { /* calling/called addresses */
	    if (toa)
		x25_toa(x25_tree, (gint*)&localoffset, tvb, pinfo);
	    else
		x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, FALSE);
	}

	if (localoffset < x25_pkt_len) /* facilities */
	    dump_facilities(x25_tree, (gint*)&localoffset, tvb);

	if (localoffset < tvb_reported_length(tvb)) /* user data */
	{

	    if (x25_tree) {
		ti = proto_tree_add_text(x25_tree, tvb, localoffset, -1,
			"User data");
		userdata_tree = proto_item_add_subtree(ti, ett_x25_user_data);
	    }

	    /* X.263/ISO 9577 says that:

		    When CLNP or ESIS are run over X.25, the SPI
		    is 0x81 or 0x82, respectively; those are the
		    NLPIDs for those protocol.

		    When X.224/ISO 8073 COTP is run over X.25, and
		    when ISO 11570 explicit identification is being
		    used, the first octet of the user data field is
		    a TPDU length field, and the rest is "as defined
		    in ITU-T Rec. X.225 | ISO/IEC 8073, Annex B,
		    or ITU-T Rec. X.264 and ISO/IEC 11570".

		    When X.264/ISO 11570 default identification is
		    being used, there is no user data field in the
		    CALL REQUEST packet.  This is for X.225/ISO 8073
		    COTP.

	       It also says that SPI values from 0x03 through 0x3f are
	       reserved and are in use by X.224/ISO 8073 Annex B and
	       X.264/ISO 11570.  The note says that those values are
	       not NLPIDs, they're "used by the respective higher layer
	       protocol" and "not used for higher layer protocol
	       identification".  I infer from this and from what
	       X.264/ISO 11570 says that this means that values in those
	       range are valid values for the first octet of an
	       X.224/ISO 8073 packet or for X.264/ISO 11570.

	       Annex B of X.225/ISO 8073 mentions some additional TPDU
	       types that can be put in what I presume is the user
	       data of connect requests.  It says that:

		    The sending transport entity shall:

			a) either not transmit any TPDU in the NS-user data
			   parameter of the N-CONNECT request primitive; or

			b) transmit the UN-TPDU (see ITU-T Rec. X.264 and
			   ISO/IEC 11570) followed by the NCM-TPDU in the
			   NS-user data parameter of the N-CONNECT request
			   primitive.

	       I don't know if this means that the user data field
	       will contain a UN TPDU followed by an NCM TPDU or not.

	       X.264/ISO 11570 says that:

		    When default identification is being used,
		    X.225/ISO 8073 COTP is identified.  No user data
		    is sent in the network-layer connection request.

		    When explicit identification is being used,
		    the user data is a UN TPDU ("Use of network
		    connection TPDU"), which specifies the transport
		    protocol to use over this network connection.
		    It also says that the length of a UN TPDU shall
		    not exceed 32 octets, i.e. shall not exceed 0x20;
		    it says this is "due to the desire not to conflict
		    with the protocol identifier field carried by X.25
		    CALL REQUEST/INCOMING CALL packets", and says that
		    field has values specified in X.244.  X.244 has been
		    superseded by X.263/ISO 9577, so that presumably
		    means the goal is to allow a UN TPDU's length
		    field to be distinguished from an NLPID, allowing
		    you to tell whether X.264/ISO 11570 explicit
		    identification is being used or an NLPID is
		    being used as the SPI.

	       I read this as meaning that, if the ISO mechanisms are
	       used to identify the protocol being carried over X.25:

		    if there's no user data in the CALL REQUEST/
		    INCOMING CALL packet, it's COTP;

		    if there is user data, then:

			if the first octet is less than or equal to
			32, it might be a UN TPDU, and that identifies
			the transport protocol being used, and
			it may be followed by more data, such
			as a COTP NCM TPDU if it's COTP;

			if the first octet is greater than 32, it's
			an NLPID, *not* a TPDU length, and the
			stuff following it is *not* a TPDU.

	       Figure A.2 of X.263/ISO 9577 seems to say that the
	       first octet of the user data is a TPDU length field,
	       in the range 0x03 through 0x82, and says they are
	       for X.225/ISO 8073 Annex B or X.264/ISO 11570.

	       However, X.264/ISO 11570 seems to imply that the length
	       field would be that of a UN TPDU, which must be less
	       than or equal to 0x20, and X.225/ISO 8073 Annex B seems
	       to indicate that the user data must begin with
	       an X.264/ISO 11570 UN TPDU, so I'd say that A.2 should
	       have said "in the range 0x03 through 0x20", instead
	       (the length value doesn't include the length field,
	       and the minimum UN TPDU has length, type, PRT-ID,
	       and SHARE, so that's 3 bytes without the length). */
	    spi = tvb_get_guint8(tvb, localoffset);
	    if (spi > 32 || spi < 3) {
		/* First octet is > 32, or < 3, so the user data isn't an
		   X.264/ISO 11570 UN TPDU */
		is_x_264 = FALSE;
	    } else {
		/* First octet is >= 3 and <= 32, so the user data *might*
		   be an X.264/ISO 11570 UN TPDU.  Check whether we have
		   enough data to see if it is. */
		if (tvb_bytes_exist(tvb, localoffset+1, 1)) {
		    /* We do; check whether the second octet is 1. */
		    if (tvb_get_guint8(tvb, localoffset+1) == 0x01) {
			/* Yes, the second byte is 1, so it looks like
			   a UN TPDU. */
			is_x_264 = TRUE;
		    } else {
			/* No, the second byte is not 1, so it's not a
			   UN TPDU. */
			is_x_264 = FALSE;
		    }
		} else {
		    /* We can't see the second byte of the putative UN
		       TPDU, so we don't know if that's what it is. */
		    is_x_264 = -1;
		}
	    }
	    if (is_x_264 == -1) {
		/*
		 * We don't know what it is; just skip it.
		 */
		localoffset = tvb_length(tvb);
	    } else if (is_x_264) {
		/* It looks like an X.264 UN TPDU, so show it as such. */
		if (userdata_tree) {
		    proto_tree_add_text(userdata_tree, tvb, localoffset, 1,
					"X.264 length indicator: %u",
					spi);
		    proto_tree_add_text(userdata_tree, tvb, localoffset+1, 1,
					"X.264 UN TPDU identifier: 0x%02X",
					tvb_get_guint8(tvb, localoffset+1));
		}
		prt_id = tvb_get_guint8(tvb, localoffset+2);
		if (userdata_tree) {
		    proto_tree_add_text(userdata_tree, tvb, localoffset+2, 1,
					"X.264 protocol identifier: %s",
					val_to_str(prt_id, prt_id_vals,
					       "Unknown (0x%02X)"));
		    proto_tree_add_text(userdata_tree, tvb, localoffset+3, 1,
					"X.264 sharing strategy: %s",
					val_to_str(tvb_get_guint8(tvb, localoffset+3),
					sharing_strategy_vals, "Unknown (0x%02X)"));
		}

		/* XXX - dissect the variable part? */

		/* The length doesn't include the length octet itself. */
		localoffset += spi + 1;

		switch (prt_id) {

		case PRT_ID_ISO_8073:
		    /* ISO 8073 COTP */
		    if (!pinfo->fd->flags.visited)
			x25_hash_add_proto_start(vc, pinfo->fd->num, ositp_handle);
		    /* XXX - dissect the rest of the user data as COTP?
		       That needs support for NCM TPDUs, etc. */
		    break;

		case PRT_ID_ISO_8602:
		    /* ISO 8602 CLTP */
		    if (!pinfo->fd->flags.visited)
			x25_hash_add_proto_start(vc, pinfo->fd->num, ositp_handle);
		    break;
		}
	    } else if (is_x_264 == 0) {
		/* It doesn't look like a UN TPDU, so compare the first
		   octet of the CALL REQUEST packet with various X.263/
		   ISO 9577 NLPIDs, as per Annex A of X.263/ISO 9577. */

		if (userdata_tree) {
		    proto_tree_add_text(userdata_tree, tvb, localoffset, 1,
					"X.263 secondary protocol ID: %s",
					val_to_str(spi, nlpid_vals, "Unknown (0x%02x)"));
		}

		if (!pinfo->fd->flags.visited) {
		    /*
		     * Is there a dissector handle for this SPI?
		     * If so, assign it to this virtual circuit.
		     */
		    dissect = dissector_get_uint_handle(x25_subdissector_table, spi);
		    if (dissect != NULL)
			x25_hash_add_proto_start(vc, pinfo->fd->num, dissect);
		}

		/*
		 * If there's only one octet of user data, it's just
		 * an NLPID; don't try to dissect it.
		 */
		if (localoffset + 1 == tvb_reported_length(tvb))
		    return;

		/*
		 * There's more than one octet of user data, so we'll
		 * dissect it; for some protocols, the NLPID is considered
		 * to be part of the PDU, so, for those cases, we don't
		 * skip past it.  For other protocols, we skip the NLPID.
		 */
		switch (spi) {

		case NLPID_ISO8473_CLNP:
		case NLPID_ISO9542_ESIS:
		case NLPID_ISO10589_ISIS:
		case NLPID_ISO10747_IDRP:
		case NLPID_SNDCF:
		    /*
		     * The NLPID is part of the PDU.  Don't skip it.
		     * But if it's all there is to the PDU, don't
		     * bother dissecting it.
		     */
		    break;

		case NLPID_SPI_X_29:
		    /*
		     * The first 4 bytes of the call user data are
		     * the SPI plus 3 reserved bytes; they are not
		     * part of the data to be dissected as X.29 data.
		     */
		    localoffset += 4;
		    break;

		default:
		    /*
		     * The NLPID isn't part of the PDU - skip it.
		     * If that means there's nothing to dissect
		     */
		    localoffset++;
		}
	    }
	} else {
	  /* if there's no user data in the CALL REQUEST/
	     INCOMING CALL packet, it's COTP; */

           if (call_request_nodata_is_cotp){
              x25_hash_add_proto_start(vc, pinfo->fd->num, ositp_handle);
           }
	}
	break;
    case X25_CALL_ACCEPTED:
        switch (dir) {

	case X25_FROM_DCE:
	    short_name = "Call conn.";
	    long_name = "Call connected";
	    break;

	case X25_FROM_DTE:
	    short_name = "Call acc.";
	    long_name = "Call accepted";
	    break;

	case X25_UNKNOWN:
	    short_name = "Call conn./Call acc.";
	    long_name = "Call connected/Call accepted";
	    break;
	}
	if(check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d", short_name, vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
	    	    X25_CALL_ACCEPTED, "Packet Type: %s", long_name);
	}
	localoffset = 3;
        if (localoffset < x25_pkt_len) { /* calling/called addresses */
	    if (toa)
		x25_toa(x25_tree, (gint*)&localoffset, tvb, pinfo);
	    else
		x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, FALSE);
	}

	if (localoffset < x25_pkt_len) /* facilities */
	    dump_facilities(x25_tree, (gint*)&localoffset, tvb);
	break;
    case X25_CLEAR_REQUEST:
        switch (dir) {

	case X25_FROM_DCE:
	    short_name = "Clear ind.";
	    long_name = "Clear indication";
	    break;

	case X25_FROM_DTE:
	    short_name = "Clear req.";
	    long_name = "Clear request";
	    break;

	case X25_UNKNOWN:
	    short_name = "Clear ind./Clear req.";
	    long_name = "Clear indication/Clear request";
	    break;
	}
	if(check_col(pinfo->cinfo, COL_INFO)) {
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d %s - %s", short_name,
		    vc, clear_code(tvb_get_guint8(tvb, 3)),
		    clear_diag(tvb_get_guint8(tvb, 4)));
	}
	x25_hash_add_proto_end(vc, pinfo->fd->num);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb,
	    	    localoffset+2, 1, X25_CLEAR_REQUEST, "Packet Type: %s",
	    	    long_name);
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause : %s", clear_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic : %s", clear_diag(tvb_get_guint8(tvb, 4)));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_CLEAR_CONFIRMATION:
	if(check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Clear Conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_CLEAR_CONFIRMATION);
	}
	localoffset = x25_pkt_len;

	if (localoffset < tvb_reported_length(tvb)) { /* extended clear conf format */
	    if (toa)
		x25_toa(x25_tree, (gint*)&localoffset, tvb, pinfo);
	    else
		x25_ntoa(x25_tree,(gint*)&localoffset, tvb, pinfo, FALSE);
	}

	if (localoffset < tvb_reported_length(tvb)) /* facilities */
	    dump_facilities(x25_tree, (gint*)&localoffset, tvb);
	break;
    case X25_DIAGNOSTIC:
	if(check_col(pinfo->cinfo, COL_INFO)) {
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Diag. %d",
		    (int)tvb_get_guint8(tvb, 3));
	}
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_DIAGNOSTIC);
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Diagnostic : %d", (int)tvb_get_guint8(tvb, 3));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_INTERRUPT:
	if(check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Interrupt VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_INTERRUPT);
	}
	localoffset = x25_pkt_len;
	break;
    case X25_INTERRUPT_CONFIRMATION:
	if(check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Interrupt Conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_INTERRUPT_CONFIRMATION);
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESET_REQUEST:
        switch (dir) {

	case X25_FROM_DCE:
	    short_name = "Reset ind.";
	    long_name = "Reset indication";
	    break;

	case X25_FROM_DTE:
	    short_name = "Reset req.";
	    long_name = "Reset request";
	    break;

	case X25_UNKNOWN:
	    short_name = "Reset ind./Reset req.";
	    long_name = "Reset indication/Reset request";
	    break;
	}
	if(check_col(pinfo->cinfo, COL_INFO)) {
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s VC:%d %s - Diag.:%d",
		    short_name, vc, reset_code(tvb_get_guint8(tvb, 3)),
		    (int)tvb_get_guint8(tvb, 4));
	}
	x25_hash_add_proto_end(vc, pinfo->fd->num);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESET_REQUEST, "Packet Type: %s", long_name);
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause : %s", reset_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic : %d", (int)tvb_get_guint8(tvb, 4));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESET_CONFIRMATION:
	if(check_col(pinfo->cinfo, COL_INFO))
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Reset conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESET_CONFIRMATION);
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESTART_REQUEST:
        switch (dir) {

	case X25_FROM_DCE:
	    short_name = "Restart ind.";
	    long_name = "Restart indication";
	    break;

	case X25_FROM_DTE:
	    short_name = "Restart req.";
	    long_name = "Restart request";
	    break;

	case X25_UNKNOWN:
	    short_name = "Restart ind./Restart req.";
	    long_name = "Restart indication/Restart request";
	    break;
	}
	if(check_col(pinfo->cinfo, COL_INFO)) {
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s - Diag.:%d",
		    short_name,
		    restart_code(tvb_get_guint8(tvb, 3)),
		    (int)tvb_get_guint8(tvb, 4));
	}
	if (x25_tree) {
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESTART_REQUEST, "Packet Type: %s", long_name);
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause : %s", restart_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic : %d", (int)tvb_get_guint8(tvb, 4));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESTART_CONFIRMATION:
	col_set_str(pinfo->cinfo, COL_INFO, "Restart conf.");
	if (x25_tree)
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESTART_CONFIRMATION);
	localoffset = x25_pkt_len;
	break;
    case X25_REGISTRATION_REQUEST:
	col_set_str(pinfo->cinfo, COL_INFO, "Registration req.");
	if (x25_tree)
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_REGISTRATION_REQUEST);
	localoffset = 3;
	if (localoffset < x25_pkt_len)
	    x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, TRUE);

	if (x25_tree) {
	    if (localoffset < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset, 1,
			"Registration length: %d",
			tvb_get_guint8(tvb, localoffset) & 0x7F);
	    if (localoffset+1 < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset+1,
			tvb_get_guint8(tvb, localoffset) & 0x7F,
			"Registration");
	}
	localoffset = tvb_reported_length(tvb);
	break;
    case X25_REGISTRATION_CONFIRMATION:
	col_set_str(pinfo->cinfo, COL_INFO, "Registration conf.");
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_REGISTRATION_CONFIRMATION);
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause: %s", registration_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic: %s", registration_code(tvb_get_guint8(tvb, 4)));
	}
	localoffset = 5;
	if (localoffset < x25_pkt_len)
	    x25_ntoa(x25_tree, (gint*)&localoffset, tvb, pinfo, TRUE);

	if (x25_tree) {
	    if (localoffset < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset, 1,
			"Registration length: %d",
			tvb_get_guint8(tvb, localoffset) & 0x7F);
	    if (localoffset+1 < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset+1,
			tvb_get_guint8(tvb, localoffset) & 0x7F,
			"Registration");
	}
	localoffset = tvb_reported_length(tvb);
	break;
    default :
	localoffset = 2;
	if (PACKET_IS_DATA(pkt_type))
	{
	    if(check_col(pinfo->cinfo, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->cinfo, COL_INFO,
			    "Data VC:%d P(S):%d P(R):%d %s", vc,
			    (pkt_type >> 1) & 0x07,
			    (pkt_type >> 5) & 0x07,
			    (pkt_type & X25_MBIT_MOD8) ? " M" : "");
		else
		    col_add_fstr(pinfo->cinfo, COL_INFO,
			    "Data VC:%d P(S):%d P(R):%d %s", vc,
			    tvb_get_guint8(tvb, localoffset+1) >> 1,
			    pkt_type >> 1,
			    (tvb_get_guint8(tvb, localoffset+1) & X25_MBIT_MOD128) ? " M" : "");
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_boolean(x25_tree, hf_x25_mbit_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_p_s_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type_data, tvb,
			    localoffset, 1, pkt_type);
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type_data, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_p_s_mod128, tvb,
			    localoffset+1, 1,
			    tvb_get_guint8(tvb, localoffset+1));
		    proto_tree_add_boolean(x25_tree, hf_x25_mbit_mod128, tvb,
			    localoffset+1, 1,
			    tvb_get_guint8(tvb, localoffset+1));
		}
	    }
	    if (modulo == 8) {
		m_bit_set = pkt_type & X25_MBIT_MOD8;
		localoffset += 1;
	    } else {
		m_bit_set = tvb_get_guint8(tvb, localoffset+1) & X25_MBIT_MOD128;
		localoffset += 2;
	    }
	    payload_len = tvb_reported_length_remaining(tvb, localoffset);
	    if (reassemble_x25) {
		/*
		 * Reassemble received and sent traffic separately.
		 * We don't reassemble traffic with an unknown direction
		 * at all.
		 */
		frag_key = vc;
		if (side) {
		    /*
		     * OR in an extra bit to distinguish from traffic
		     * in the other direction.
		     */
		    frag_key |= 0x10000;
		}
		fd_head = fragment_add_seq_next(tvb, localoffset, 
						pinfo, frag_key,
						x25_segment_table,
						x25_reassembled_table,
						payload_len, m_bit_set);
		pinfo->fragmented = m_bit_set;

                /* Fragment handling is not adapted to handle several x25
                 * packets in the same frame. This is common with XOT and
                 * shorter packet sizes.
                 * Therefore, fragment_add_seq_next seem to always return fd_head
                 * A fix to use m_bit_set to only show fragments for last pkt
                 */
		if (!m_bit_set && fd_head) {
		    if (fd_head->next) {
		        proto_item *frag_tree_item;

		        /* This is the last packet */
			next_tvb = tvb_new_child_real_data(tvb, fd_head->data, 
						     fd_head->len,
						     fd_head->len);
			add_new_data_source(pinfo, next_tvb, "Reassembled X.25");
                        if (x25_tree) {
                           show_fragment_seq_tree(fd_head, 
                                                  &x25_frag_items, 
                                                  x25_tree, 
                                                  pinfo, next_tvb, &frag_tree_item);
                        }
		    }
	        }

		if (m_bit_set && next_tvb == NULL) {
		    /*
		     * This isn't the last packet, so just
		     * show it as X.25 user data.
		     */
		    proto_tree_add_text(x25_tree, tvb, localoffset, -1,
		        "User data (%u byte%s)", payload_len,
		        plurality(payload_len, "", "s"));
		    return;
		}
	    }
	    break;
	}

	/*
	 * Non-data packets (RR, RNR, REJ).
	 */
	switch (PACKET_TYPE_FC(pkt_type))
	{
	case X25_RR:
	    if(check_col(pinfo->cinfo, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->cinfo, COL_INFO, "RR VC:%d P(R):%d",
			    vc, (pkt_type >> 5) & 0x07);
		else
		    col_add_fstr(pinfo->cinfo, COL_INFO, "RR VC:%d P(R):%d",
			    vc, tvb_get_guint8(tvb, localoffset+1) >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type_fc_mod8, tvb,
			    localoffset, 1, X25_RR);
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_RR);
		    proto_tree_add_item(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset+1, 1, ENC_BIG_ENDIAN);
		}
	    }
	    break;

	case X25_RNR:
	    if(check_col(pinfo->cinfo, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->cinfo, COL_INFO, "RNR VC:%d P(R):%d",
			    vc, (pkt_type >> 5) & 0x07);
		else
		    col_add_fstr(pinfo->cinfo, COL_INFO, "RNR VC:%d P(R):%d",
			    vc, tvb_get_guint8(tvb, localoffset+1) >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type_fc_mod8, tvb,
			    localoffset, 1, X25_RNR);
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_RNR);
		    proto_tree_add_item(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset+1, 1, ENC_BIG_ENDIAN);
		}
	    }
	    break;

	case X25_REJ:
	    if(check_col(pinfo->cinfo, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->cinfo, COL_INFO, "REJ VC:%d P(R):%d",
			    vc, (pkt_type >> 5) & 0x07);
		else
		    col_add_fstr(pinfo->cinfo, COL_INFO, "REJ VC:%d P(R):%d",
			    vc, tvb_get_guint8(tvb, localoffset+1) >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type_fc_mod8, tvb,
			    localoffset, 1, X25_REJ);
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_REJ);
		    proto_tree_add_item(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset+1, 1, ENC_BIG_ENDIAN);
		}
	    }
	}
	localoffset += (modulo == 8) ? 1 : 2;
    }

    if (localoffset >= tvb_reported_length(tvb))
      return;
    if (pinfo->fragmented)
      return;

    if (!next_tvb)
      next_tvb = tvb_new_subset_remaining(tvb, localoffset);

    saved_private_data = pinfo->private_data;
    pinfo->private_data = &q_bit_set;

    /* See if there's already a dissector for this circuit. */
    if (try_circuit_dissector(CT_X25, vc, pinfo->fd->num, next_tvb, pinfo,
			      tree)) {
	pinfo->private_data = saved_private_data;
	return;	/* found it and dissected it */
    }

    /* Did the user suggest QLLC/SNA? */
    if (payload_is_qllc_sna) {
	/* Yes - dissect it as QLLC/SNA. */
	if (!pinfo->fd->flags.visited)
	    x25_hash_add_proto_start(vc, pinfo->fd->num, qllc_handle);
	call_dissector(qllc_handle, next_tvb, pinfo, tree);
	pinfo->private_data = saved_private_data;
	return;
    }

    if (payload_check_data){
    /* If the Call Req. has not been captured, let's look at the first
       two bytes of the payload to see if this looks like COTP. */
    if (tvb_get_guint8(tvb, localoffset) == tvb_length(next_tvb)-1) {
      /* First byte contains the length of the remaining buffer */
      if ((tvb_get_guint8(tvb, localoffset+1) & 0x0F) == 0) {
	/* Second byte contains a valid COTP TPDU */
	if (!pinfo->fd->flags.visited)
	    x25_hash_add_proto_start(vc, pinfo->fd->num, ositp_handle);
	call_dissector(ositp_handle, next_tvb, pinfo, tree);
	pinfo->private_data = saved_private_data;
	return;
      }
    }

    /* Then let's look at the first byte of the payload to see if this
       looks like IP or CLNP. */
    switch (tvb_get_guint8(tvb, localoffset)) {

    case 0x45:
	/* Looks like an IP header */
	if (!pinfo->fd->flags.visited)
	    x25_hash_add_proto_start(vc, pinfo->fd->num, ip_handle);
	call_dissector(ip_handle, next_tvb, pinfo, tree);
	pinfo->private_data = saved_private_data;
	return;

    case NLPID_ISO8473_CLNP:
	if (!pinfo->fd->flags.visited)
	    x25_hash_add_proto_start(vc, pinfo->fd->num, clnp_handle);
	call_dissector(clnp_handle, next_tvb, pinfo, tree);
	pinfo->private_data = saved_private_data;
	return;
    }
    }

    /* Try the heuristic dissectors. */
    if (dissector_try_heuristic(x25_heur_subdissector_list, next_tvb, pinfo,
				tree)) {
	pinfo->private_data = saved_private_data;
	return;
    }

    /* All else failed; dissect it as raw data */
    call_dissector(data_handle, next_tvb, pinfo, tree);
    pinfo->private_data = saved_private_data;
}

/*
 * X.25 dissector for use when "pinfo->pseudo_header" points to a
 * "struct x25_phdr".
 */
static void
dissect_x25_dir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_x25_common(tvb, pinfo, tree,
	(pinfo->pseudo_header->x25.flags & FROM_DCE) ? X25_FROM_DCE :
						       X25_FROM_DTE,
	pinfo->pseudo_header->x25.flags & FROM_DCE);
}

/*
 * X.25 dissector for use when "pinfo->pseudo_header" doesn't point to a
 * "struct x25_phdr".
 */
static void
dissect_x25(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int direction;

    /*
     * We don't know if this packet is DTE->DCE or DCE->DCE.
     * However, we can, at least, distinguish between the two
     * sides of the conversation, based on the addresses and
     * ports.
     */
    direction = CMP_ADDRESS(&pinfo->src, &pinfo->dst);
    if (direction == 0)
	direction = (pinfo->srcport > pinfo->destport)*2 - 1;
    dissect_x25_common(tvb, pinfo, tree, X25_UNKNOWN, direction > 0);
}

static void
x25_reassemble_init(void)
{
  fragment_table_init(&x25_segment_table);
  reassembled_table_init(&x25_reassembled_table);
}

void
proto_register_x25(void)
{
    static hf_register_info hf[] = {
	{ &hf_x25_gfi,
	  { "GFI", "x25.gfi", FT_UINT16, BASE_DEC, NULL, 0xF000,
	  	"General format identifier", HFILL }},
	{ &hf_x25_abit,
	  { "A Bit", "x25.a", FT_BOOLEAN, 16, NULL, X25_ABIT,
	  	"Address Bit", HFILL }},
	{ &hf_x25_qbit,
	  { "Q Bit", "x25.q", FT_BOOLEAN, 16, NULL, X25_QBIT,
	  	"Qualifier Bit", HFILL }},
	{ &hf_x25_dbit,
	  { "D Bit", "x25.d", FT_BOOLEAN, 16, NULL, X25_DBIT,
	  	"Delivery Confirmation Bit", HFILL }},
	{ &hf_x25_mod,
	  { "Modulo", "x25.mod", FT_UINT16, BASE_DEC, VALS(vals_modulo), 0x3000,
	  	"Specifies whether the frame is modulo 8 or 128", HFILL }},
	{ &hf_x25_lcn,
	  { "Logical Channel", "x25.lcn", FT_UINT16, BASE_DEC, NULL, 0x0FFF,
	  	"Logical Channel Number", HFILL }},
	{ &hf_x25_type,
	  { "Packet Type", "x25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x0,
	  	NULL, HFILL }},
	{ &hf_x25_type_fc_mod8,
	  { "Packet Type", "x25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x1F,
	  	NULL, HFILL }},
	{ &hf_x25_type_data,
	  { "Packet Type", "x25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x01,
	  	NULL, HFILL }},
	{ &hf_x25_p_r_mod8,
	  { "P(R)", "x25.p_r", FT_UINT8, BASE_DEC, NULL, 0xE0,
	  	"Packet Receive Sequence Number", HFILL }},
	{ &hf_x25_p_r_mod128,
	  { "P(R)", "x25.p_r", FT_UINT8, BASE_DEC, NULL, 0xFE,
	  	"Packet Receive Sequence Number", HFILL }},
	{ &hf_x25_mbit_mod8,
	  { "M Bit", "x25.m", FT_BOOLEAN, 8, TFS(&m_bit_tfs), X25_MBIT_MOD8,
	  	"More Bit", HFILL }},
	{ &hf_x25_mbit_mod128,
	  { "M Bit", "x25.m", FT_BOOLEAN, 8, TFS(&m_bit_tfs), X25_MBIT_MOD128,
	  	"More Bit", HFILL }},
	{ &hf_x25_p_s_mod8,
	  { "P(S)", "x25.p_s", FT_UINT8, BASE_DEC, NULL, 0x0E,
	  	"Packet Send Sequence Number", HFILL }},
	{ &hf_x25_p_s_mod128,
	  { "P(S)", "x25.p_s", FT_UINT8, BASE_DEC, NULL, 0xFE,
	  	"Packet Send Sequence Number", HFILL }},
	{ &hf_x25_segment_overlap,
	  { "Fragment overlap",	"x25.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment overlaps with other fragments", HFILL }},
	
	{ &hf_x25_segment_overlap_conflict,
	  { "Conflicting data in fragment overlap",	"x25.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Overlapping fragments contained conflicting data", HFILL }},
	
	{ &hf_x25_segment_multiple_tails,
	  { "Multiple tail fragments found",	"x25.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Several tails were found when defragmenting the packet", HFILL }},
	
	{ &hf_x25_segment_too_long_segment,
	  { "Fragment too long",	"x25.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment contained data past end of packet", HFILL }},
	
	{ &hf_x25_segment_error,
	  { "Defragmentation error", "x25.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "Defragmentation error due to illegal fragments", HFILL }},
	
	{ &hf_x25_segment_count,
	  { "Fragment count", "x25.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }},
	
	{ &hf_x25_reassembled_length,
	  { "Reassembled X.25 length", "x25.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
	    "The total length of the reassembled payload", HFILL }},
	
	{ &hf_x25_segment,
	  { "X.25 Fragment", "x25.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "X25 Fragment", HFILL }},
	
	{ &hf_x25_segments,
	  { "X.25 Fragments", "x25.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_x25,
	&ett_x25_gfi,
	&ett_x25_fac,
	&ett_x25_fac_unknown,
	&ett_x25_fac_mark,
	&ett_x25_fac_reverse,
	&ett_x25_fac_charging_info,
	&ett_x25_fac_throughput,
	&ett_x25_fac_cug,
	&ett_x25_fac_called_modif,
	&ett_x25_fac_cug_outgoing_acc,
	&ett_x25_fac_throughput_min,
	&ett_x25_fac_express_data,
	&ett_x25_fac_bilateral_cug,
	&ett_x25_fac_packet_size,
	&ett_x25_fac_window_size,
	&ett_x25_fac_rpoa_selection,
	&ett_x25_fac_cug_ext,
	&ett_x25_fac_cug_outgoing_acc_ext,
	&ett_x25_fac_transit_delay,
	&ett_x25_fac_call_duration,
	&ett_x25_fac_segment_count,
	&ett_x25_fac_call_transfer,
	&ett_x25_fac_rpoa_selection_ext,
	&ett_x25_fac_monetary_unit,
	&ett_x25_fac_nui,
	&ett_x25_fac_called_addr_ext,
	&ett_x25_fac_ete_transit_delay,
	&ett_x25_fac_calling_addr_ext,
	&ett_x25_fac_call_deflect,
	&ett_x25_fac_priority,
	&ett_x25_user_data,
	&ett_x25_segment,
	&ett_x25_segments
    };
    module_t *x25_module;

    proto_x25 = proto_register_protocol ("X.25", "X.25", "x25");
    proto_register_field_array (proto_x25, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    x25_subdissector_table = register_dissector_table("x.25.spi",
	"X.25 secondary protocol identifier", FT_UINT8, BASE_HEX);
    register_heur_dissector_list("x.25", &x25_heur_subdissector_list);

    register_dissector("x.25_dir", dissect_x25_dir, proto_x25);
    register_dissector("x.25", dissect_x25, proto_x25);

    /* Preferences */
    x25_module = prefs_register_protocol(proto_x25, NULL);
    prefs_register_obsolete_preference(x25_module, "non_q_bit_is_sna");
    prefs_register_bool_preference(x25_module, "payload_is_qllc_sna",
            "Default to QLLC/SNA",
            "If CALL REQUEST not seen or didn't specify protocol, dissect as QLLC/SNA",
            &payload_is_qllc_sna);
    prefs_register_bool_preference(x25_module, "call_request_nodata_is_cotp",
            "Assume COTP for Call Request without data",
            "If CALL REQUEST has no data, assume the protocol handled is COTP",
            &call_request_nodata_is_cotp);
    prefs_register_bool_preference(x25_module, "payload_check_data",
            "Check data for COTP/IP/CLNP",
            "If CALL REQUEST not seen or didn't specify protocol, check user data before checking heuristic dissectors",
            &payload_check_data);
    prefs_register_bool_preference(x25_module, "reassemble",
				   "Reassemble fragmented X.25 packets",
				   "Reassemble fragmented X.25 packets",
				   &reassemble_x25);
    register_init_routine(&x25_reassemble_init);
}

void
proto_reg_handoff_x25(void)
{
    dissector_handle_t x25_handle;

    /*
     * Get handles for various dissectors.
     */
    ip_handle = find_dissector("ip");
    clnp_handle = find_dissector("clnp");
    ositp_handle = find_dissector("ositp");
    qllc_handle = find_dissector("qllc");
    data_handle = find_dissector("data");

    x25_handle = find_dissector("x.25");
    dissector_add_uint("llc.dsap", SAP_X25, x25_handle);
}
