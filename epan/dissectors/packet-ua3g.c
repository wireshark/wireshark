/* packet-ua3g.c
 * Routines for UA/UDP (Universal Alcatel over UDP) packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include "epan/packet.h"
#include "epan/prefs.h"
#include "epan/tap.h"
#include "epan/value_string.h"
#include "epan/emem.h"
#include "packet-uaudp.h"

extern int isprint( int ch );

/*-----------------------------------------------------------------------------
    Globals
    ---------------------------------------------------------------------------*/
static int  proto_ua3g			= -1;
static gint ett_ua3g			= -1;
static gint ett_ua3g_body		= -1;
static gint ett_ua3g_param		= -1;
static gint ett_ua3g_option		= -1;
static int  hf_ua3g_length		= -1;
static int  hf_ua3g_opcode		= -1;
static int  hf_ua3g_ip			= -1;
static int  hf_ua3g_command		= -1;

extern e_ua_direction message_direction;

/* Definition of opcodes */
/* System To Terminal */
#define NOP				0x00
#define PRODUCTION_TEST			0x01	/* IP Phone */
#define SUBDEVICE_ESCAPE		0x02	/* IP Phone */
#define SOFT_RESET			0x03
#define IP_PHONE_WARMSTART		0x04	/* IP Phone */
#define HE_ROUTING			0x05	/* IP Phone - NOT EXPECTED */
#define SUBDEVICE_RESET			0x06
#define LOOPBACK_ON			0x07	/* IP Phone & UA NOE */
#define LOOPBACK_OFF			0x08	/* IP Phone & UA NOE */
#define VIDEO_ROUTING			0x09	/* IP Phone - NOT EXPECTED */
#define SUPER_MSG			0x0B
#define SEGMENT_MSG			0x0C
#define REMOTE_UA_ROUTING		0x0D	/* IP Phone - NOT EXPECTED */
#define VERY_REMOTE_UA_ROUTING		0x0E	/* IP Phone - NOT EXPECTED */
#define OSI_ROUTING			0x0F	/* IP Phone - NOT EXPECTED */
#define ABC_A_ROUTING			0x11	/* IP Phone - NOT EXPECTED */
#define IBS_ROUTING			0x12	/* IP Phone - NOT EXPECTED */
#define IP_DEVICE_ROUTING		0x13
#define M_REFLEX_HUB_ROUTING		0x14	/* IP Phone - NOT EXPECTED */
/*#define NOE_CS_ROUTING		0x15	// Decoded by packet-noe.c */
/*#define NOE_PS_ROUTING		0x16	// Decoded by packet-noe.c */
#define SUPER_MSG_2			0x17
#define DEBUG_IN_LINE			0x18
#define LED_COMMAND			0x21	/* IP Phone */
#define START_BUZZER			0x22	/* VTA */
#define STOP_BUZZER			0x23	/* VTA */
#define ENABLE_DTMF			0x24	/* Only IP NOE */
#define DISABLE_DTMF			0x25	/* Only IP NOE */
#define CLEAR_LCD_DISP			0x26	/* IP Phone */
#define LCD_LINE_1_CMD			0x27	/* IP Phone */
#define LCD_LINE_2_CMD			0x28	/* IP Phone */
#define MAIN_VOICE_MODE			0x29
#define VERSION_INQUIRY			0x2A
#define ARE_YOU_THERE			0x2B	/* IP Phone & UA NOE */
#define SUBDEVICE_METASTATE		0x2C
#define VTA_STATUS_INQUIRY		0x2D	/* IP Phone */
#define SUBDEVICE_STATE			0x2E
#define DWL_DTMF_CLCK_FORMAT		0x30	/* IP Phone */
#define SET_CLCK			0x31	/* IP Phone */
#define VOICE_CHANNEL			0x32	/* IP Phone & UA NOE */
#define EXTERNAL_RINGING		0x33
#define LCD_CURSOR			0x35	/* IP Phone */
#define DWL_SPECIAL_CHAR		0x36	/* IP Phone */
#define SET_CLCK_TIMER_POS		0x38	/* IP Phone */
#define SET_LCD_CONTRAST		0x39	/* IP Phone */
#define AUDIO_IDLE			0x3A
#define SET_SPEAKER_VOL			0x3B	/* IP Phone */
#define BEEP				0x3C
#define SIDETONE			0x3D
#define RINGING_CADENCE			0x3E
#define	MUTE				0x3F
#define FEEDBACK			0x40
#define KEY_RELEASE			0x41	/* IP Phone */
#define TRACE_ON			0x42	/* IP Phone - NOT EXPECTED */
#define TRACE_OFF			0x43	/* IP Phone - NOT EXPECTED */
#define READ_PERIPHERAL			0x44	/* IP Phone - NOT EXPECTED */
#define WRITE_PERIPHERAL		0x45	/* IP Phone - NOT EXPECTED */
#define ALL_ICONS_OFF			0x46	/* IP Phone */
#define ICON_CMD			0x47	/* IP Phone */
#define AMPLIFIED_HANDSET		0x48	/* IP Phone */
#define AUDIO_CONFIG			0x49
#define AUDIO_PADDED_PATH		0x4A	/* IP Phone */
#define RELEASE_RADIO_LINK		0x4B	/* IP Phone - NOT EXPECTED */
#define DECT_HANDOVER			0x4C	/* IP Phone - NOT EXPECTED */
#define LOUDSPEAKER			0x4D
#define ANNOUNCE			0x4E
#define RING				0x4F
#define UA_DWL_PROTOCOL			0x50	/* Only UA NOE */
/* Terminal To System */
#define CS_NOP_ACK			0x00
#define CS_HANDSET_OFFHOOK		0x01	/* IP Phone */
#define CS_HANDSET_ONHOOK		0x02	/* IP Phone */
#define CS_DIGIT_DIALED			0x03	/* IP Phone */
#define CS_SUBDEVICE_MSG		0x04
#define CS_HE_ROUTING			0x05	/* IP Phone - NOT EXPECTED */
#define CS_LOOPBACK_ON			0x06	/* IP Phone & UA NOE */
#define CS_LOOPBACK_OFF			0x07	/* IP Phone & UA NOE */
#define CS_VIDEO_ROUTING		0x09	/* IP Phone - NOT EXPECTED */
#define CS_WARMSTART_ACK		0x0A	/* IP Phone */
#define CS_SUPER_MSG			0x0B	/* IP Phone - NOT EXPECTED */
#define CS_SEGMENT_MSG			0x0C
#define CS_REMOTE_UA_ROUTING		0x0D	/* IP Phone - NOT EXPECTED */
#define CS_VERY_REMOTE_UA_R		0x0E	/* IP Phone - NOT EXPECTED */
#define CS_OSI_ROUTING			0x0F	/* IP Phone - NOT EXPECTED */
#define CS_ABC_A_ROUTING		0x11	/* IP Phone - NOT EXPECTED */
#define CS_IBS_ROUTING			0x12	/* IP Phone - NOT EXPECTED */
#define CS_IP_DEVICE_ROUTING		0x13
/*#define CS_NOE_CS_ROUTING		0x15	// Decoded by packet-noe.c */
/*#define CS_NOE_PS_ROUTING		0x16	// Decoded by packet-noe.c */
#define CS_SUPER_MSG_2			0x17
#define CS_DEBUG_IN_LINE		0x18
#define CS_UNSOLICITED_MSG		0x9F
#define CS_NON_DIGIT_KEY_PUSHED		0x20	/* IP Phone */
#define CS_VERSION_RESPONSE		0x21
#define CS_I_M_HERE			0x22
#define CS_RSP_STATUS_INQUIRY		0x23	/* IP Phone */
#define CS_SUBDEVICE_STATE		0x24
#define CS_DIGIT_KEY_RELEASED		0x26	/* IP Phone */
#define CS_TRACE_ON_ACK			0x27	/* IP Phone */
#define CS_TRACE_OFF_ACK		0x28	/* IP Phone */
#define CS_SPECIAL_KEY_STATUS		0x29	/* IP Phone */
#define CS_KEY_RELEASED			0x2A	/* IP Phone */
#define CS_PERIPHERAL_CONTENT		0x2B	/* IP Phone */
#define CS_TM_KEY_PUSHED		0x2D	/* IP Phone */
#define CS_UA_DWL_PROTOCOL		0x50	/* Only UA NOE */


static const value_string *opcodes_vals;

/* System To Terminal Opcodes */
static const value_string opcodes_vals_sys[] =
{
	{NOP				, "NOP"},
	{PRODUCTION_TEST		, "Production Test"},	/* IP Phone */
	{SUBDEVICE_ESCAPE		, "Subdevice Escape To Subdevice"},	/* IP Phone */
	{SOFT_RESET			, "Software Reset"},
	{IP_PHONE_WARMSTART		, "IP-Phone Warmstart"},	/* IP Phone */
	{HE_ROUTING			, "HE Routing Code"},	/* IP Phone - NOT EXPECTED */
	{SUBDEVICE_RESET		, "Subdevice Reset"},
	{LOOPBACK_ON			, "Loopback On"},
	{LOOPBACK_OFF			, "Loopback Off"},
	{VIDEO_ROUTING			, "Video Routing Code"},	/* IP Phone - NOT EXPECTED */
	{SUPER_MSG			, "Super Message"},
	{SEGMENT_MSG			, "Segment Message"},
	{REMOTE_UA_ROUTING		, "Remote UA Routing Code"},	/* IP Phone - NOT EXPECTED */
	{VERY_REMOTE_UA_ROUTING		, "Very Remote UA Routing Code"},	/* IP Phone - NOT EXPECTED */
	{OSI_ROUTING			, "OSI Routing Code"},	/* IP Phone - NOT EXPECTED */
	{ABC_A_ROUTING			, "ABC-A Routing Code"},	/* IP Phone - NOT EXPECTED */
	{IBS_ROUTING			, "IBS Routing Code"},	/* IP Phone - NOT EXPECTED */
	{IP_DEVICE_ROUTING		, "IP Device Routing"},
	{M_REFLEX_HUB_ROUTING		, "Mutli-Reflex Hub Routing Code"},	/* IP Phone - NOT EXPECTED */
	{SUPER_MSG_2			, "Super Message 2"},
	{DEBUG_IN_LINE			, "Debug In Line"},
	{LED_COMMAND			, "Led Command"},	/* IP Phone */
	{START_BUZZER			, "Start Buzzer"},	/* VTA */
	{STOP_BUZZER			, "Stop Buzzer"},	/* VTA */
	{ENABLE_DTMF			, "Enable DTMF"},
	{DISABLE_DTMF			, "Disable DTMF"},
	{CLEAR_LCD_DISP			, "Clear LCD Display"},	/* IP Phone */
	{LCD_LINE_1_CMD			, "LCD Line 1 Commands"},	/* IP Phone */
	{LCD_LINE_2_CMD			, "LCD Line 2 Commands"},	/* IP Phone */
	{MAIN_VOICE_MODE		, "Main Voice Mode"},
	{VERSION_INQUIRY		, "Version Inquiry"},
	{ARE_YOU_THERE			, "Are You There?"},
	{SUBDEVICE_METASTATE		, "Subdevice Metastate"},
	{VTA_STATUS_INQUIRY		, "VTA Status Inquiry"},	/* IP Phone */
	{SUBDEVICE_STATE		, "Subdevice State?"},
	{DWL_DTMF_CLCK_FORMAT		, "Download DTMF & Clock Format"},	/* IP Phone */
	{SET_CLCK			, "Set Clock"},	/* IP Phone */
	{VOICE_CHANNEL			, "Voice Channel"},	/* IP Phone & UA NOE */
	{EXTERNAL_RINGING		, "External Ringing"},
	{LCD_CURSOR			, "LCD Cursor"},	/* IP Phone */
	{DWL_SPECIAL_CHAR		, "Download Special Character"},	/* IP Phone */
	{SET_CLCK_TIMER_POS		, "Set Clock/Timer Position"},	/* IP Phone */
	{SET_LCD_CONTRAST		, "Set LCD Contrast"},	/* IP Phone */
	{AUDIO_IDLE			, "Audio Idle"},
	{SET_SPEAKER_VOL		, "Set Speaker Volume"},	/* IP Phone */
	{BEEP				, "Beep"},
	{SIDETONE			, "Sidetone"},
	{RINGING_CADENCE		, "Set Programmable Ringing Cadence"},
	{MUTE				, "Mute"},
	{FEEDBACK			, "Feedback"},
	{KEY_RELEASE			, "Key Release"},	/* IP Phone */
	{TRACE_ON			, "Trace On"},	/* IP Phone - NOT EXPECTED */
	{TRACE_OFF			, "Trace Off"},	/* IP Phone - NOT EXPECTED */
	{READ_PERIPHERAL		, "Read Peripheral"},	/* IP Phone - NOT EXPECTED */
	{WRITE_PERIPHERAL		, "Write Peripheral"},	/* IP Phone - NOT EXPECTED */
	{ALL_ICONS_OFF			, "All Icons Off"},	/* IP Phone */
	{ICON_CMD			, "Icon Command"},	/* IP Phone */
	{AMPLIFIED_HANDSET		, "Amplified Handset (Boost)"},	/* IP Phone */
	{AUDIO_CONFIG			, "Audio Config"},
	{AUDIO_PADDED_PATH		, "Audio Padded Path"},	/* IP Phone */
	{RELEASE_RADIO_LINK		, "Release Radio Link"},	/* IP Phone - NOT EXPECTED */
	{DECT_HANDOVER			, "DECT External Handover Routing Code"},	/* IP Phone - NOT EXPECTED */
	{LOUDSPEAKER			, "Loudspeaker"},
	{ANNOUNCE			, "Announce"},
	{RING				, "Ring"},
	{UA_DWL_PROTOCOL		, "UA Download Protocol"},
	{0, NULL}
};

/* Terminal To System Opcodes */
static const value_string opcodes_vals_term[] =
{
	{CS_NOP_ACK			, "NOP Acknowledge"},
	{CS_HANDSET_OFFHOOK		, "Handset Offhook"},	/* IP Phone */
	{CS_HANDSET_ONHOOK		, "Hansdet Onhook"},	/* IP Phone */
	{CS_DIGIT_DIALED		, "Digital Dialed"},	/* IP Phone */
	{CS_SUBDEVICE_MSG		, "Subdevice Message"},
	{CS_HE_ROUTING			, "HE Routing Response Code"},	/* IP Phone - NOT EXPECTED */
	{CS_LOOPBACK_ON			, "Loopback On Acknowledge"},	/* Same as CS To Terminal */
	{CS_LOOPBACK_OFF		, "Loopback Off Acknowledge"},	/* Same as CS To Terminal */
	{CS_VIDEO_ROUTING		, "Video Routing Response Code"},	/* IP Phone - NOT EXPECTED */
	{CS_WARMSTART_ACK		, "Warmstart Acknowledge"},	/* IP Phone */
	{CS_SUPER_MSG			, "Super Message"},	/* IP Phone - NOT EXPECTED */
	{CS_SEGMENT_MSG			, "Segment Message"},	/* Same as CS To Terminal */
	{CS_REMOTE_UA_ROUTING		, "Remote UA Routing Response Code"},	/* IP Phone - NOT EXPECTED */
	{CS_VERY_REMOTE_UA_R		, "Very Remote UA Routing Response Code"},	/* IP Phone - NOT EXPECTED */
	{CS_OSI_ROUTING			, "OSI Response Code"},	/* IP Phone - NOT EXPECTED */
	{CS_ABC_A_ROUTING		, "ABC-A Routing Response Code"},	/* IP Phone - NOT EXPECTED */
	{CS_IBS_ROUTING			, "IBS Routing Response Code"},	/* IP Phone - NOT EXPECTED */
	{CS_IP_DEVICE_ROUTING		, "IP Device Routing"},
	{CS_SUPER_MSG_2			, "Super Message 2"},	/* Same as CS To Terminal */
	{CS_DEBUG_IN_LINE		, "Debug Message"},
	{CS_UNSOLICITED_MSG		, "Unsolicited Message"},
	{CS_NON_DIGIT_KEY_PUSHED	, "Non-Digit Key Pushed"},	/* IP Phone */
	{CS_VERSION_RESPONSE		, "Version Information"},
	{CS_I_M_HERE			, "I'm Here Response"},
	{CS_RSP_STATUS_INQUIRY		, "Response To Status Inquiry"},	/* IP Phone */
	{CS_SUBDEVICE_STATE		, "Subdevice State Response"},
	{CS_DIGIT_KEY_RELEASED		, "Digit Key Released"},	/* IP Phone */
	{CS_TRACE_ON_ACK		, "Trace On Acknowledge"},	/* IP Phone - NOT EXPECTED */
	{CS_TRACE_OFF_ACK		, "Trace Off Acknowledge"},	/* IP Phone - NOT EXPECTED */
	{CS_SPECIAL_KEY_STATUS		, "Special Key Status"},	/* IP Phone */
	{CS_KEY_RELEASED		, "Key Released"},	/* IP Phone */
	{CS_PERIPHERAL_CONTENT		, "Peripheral Content"},	/* IP Phone - NOT EXPECTED */
	{CS_TM_KEY_PUSHED		, "TM Key Pushed"},	/* IP Phone - NOT EXPECTED */
	{CS_UA_DWL_PROTOCOL		, "Download Protocol"},
	{0, NULL}
};

static const value_string str_on_off[] = {
	{0x00, "Off"},
	{0x01, "On"},
	{0, NULL}
};
static const value_string str_yes_no[] = {
	{0x00, "No"},
	{0x01, "Yes"},
	{0, NULL}
};
static const value_string str_device_type[] = {
	{0x00, "Voice Terminal Adaptor"},
	{0, NULL}
};


/*-----------------------------------------------------------------------------
    VERSION NUMBER COMPUTER - This function computes a version number (S.SZ.AB) from a 16 bits number
    ---------------------------------------------------------------------------*/
static char *
version_number_computer(int hexa_version)
{
	static char version[10];
	int release, vers, fix;

	release = (int)(hexa_version / 10000);
	vers = (int)((hexa_version % 10000) / 100);
	fix = (hexa_version % 10000) % 100;
	g_snprintf(version, 10, "%d.%02d.%02d", release, vers, fix);
	return version;
}


/*-----------------------------------------------------------------------------
    Function for UA3G message with opcode and one parameter

    PRODUCTION TEST - 01h (MESSAGE FROM THE SYSTEM)
    SUBDEVICE RESET - 06h (MESSAGE FROM THE SYSTEM)
    ARE YOU THERE - 2Bh - IPhone & UA NOE (MESSAGE FROM THE SYSTEM)
    SET SPEAKER VOLUME - 3Bh (MESSAGE FROM THE SYSTEM)
    TRACE ON - 42h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_with_one_parameter(proto_tree *tree _U_, tvbuff_t *tvb,
			  packet_info *pinfo _U_, guint offset, guint length,
			  guint8 opcode, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_first_parameter[] = {
		{0x01, "Production Test Command"},
		{0x06, "Reserved For Compatibility"},
		{0x2B, "Temporization"},
		{0x3B, "Volmue"},
		{0x42, "Subdevice Address"},
		{0, NULL}
	};

	if(length > 0) {
		ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
		proto_tree_add_text(ua3g_body_tree, tvb, offset, length, "%s: %d",
			val_to_str(opcode, str_first_parameter, "Unknown"), tvb_get_guint8(tvb, offset));
		length--;
	}
}


/*-----------------------------------------------------------------------------
    SUBDEVICE ESCAPE TO SUBDEVICE - 02h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_subdevice_escape(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
			guint offset, guint length, guint8 opcode _U_,
			proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int j = 0;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Subdevice Address: %d", (tvb_get_guint8(tvb, offset) & 0x0F));
	offset++;
	length--;

	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Subdevice Opcode: 0x%02x", (tvb_get_guint8(tvb, offset) & 0x7F));
	offset++;
	length--;

	while(length > 0) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Parameter Byte %2d: %d", j++,
			tvb_get_guint8(tvb, offset));
		offset++;
		length--;
	}
}


/*-----------------------------------------------------------------------------
    SOFTWARE RESET - 03h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_software_reset(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		      guint offset, guint length, guint8 opcode _U_,
		      proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_verswitch[] = {
		{0x00, "Reset Without Version Switch"},
		{0x01, "Reset With Version Switch"},
		{0, NULL}
	};

	if(length > 0) {
		ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s",
			val_to_str(tvb_get_guint8(tvb, offset), str_verswitch, "Unknown"));
		offset++;
		length--;
	}
}


/*-----------------------------------------------------------------------------
    IP-PHONE WARMSTART - 04h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_ip_phone_warmstart(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
			  guint offset, guint length, guint8 opcode _U_,
			  proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_command[] = {
		{0x00, "Run In UA2G Emulation Mode"},
		{0x01, "Run In Full UA3G Mode"},
		{0, NULL}
	};

	if(length > 0) {
		ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
		proto_tree_add_text(ua3g_body_tree,
			tvb,
			offset,
			1,
			"Command: %s",
			val_to_str(tvb_get_guint8(tvb, offset), str_command, "Unknown"));
		offset++;
		length--;
	}
}


/*-----------------------------------------------------------------------------
    SUPER MESSAGE - 0Bh (MESSAGE FROM THE SYSTEM)
    SUPER MESSAGE 2 - 17h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_super_msg(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		 guint offset, guint length, guint8 opcode,
		 proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int i, parameter_length;
	int j = 0;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	while(length > 0) {
		if(opcode == 0x17) {
			parameter_length = tvb_get_ntohs(tvb, offset);
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
				"Length %d: %d", j++, parameter_length);
			offset += 2;
			length -= 2;
		} else {
			parameter_length = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Length %d: %d", j++, parameter_length);
			offset++;
			length--;
		}

		for(i = 1; i <= parameter_length; i++) {
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"L%d Byte %2d: %d",
				j, i, tvb_get_guint8(tvb, offset));
			offset++;
			length--;
		}
	}
}


/*-----------------------------------------------------------------------------
    SEGMENT MESSAGE - 0Ch (MESSAGE FROM THE TERMINAL AND FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_segment_msg(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		   guint offset, guint length, guint8 opcode _U_,
		   proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int first_sub_segment;
	int j = 0;
	static const value_string str_first_sub_segment[] = {
		{0x00, "Subsequent Segment"},
		{0x80, "Fisrt Segment"},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	first_sub_segment = (tvb_get_guint8(tvb, offset) & 0x80);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "F/S: %s (%d)",
		val_to_str(first_sub_segment, str_first_sub_segment, "Unknown"),
		first_sub_segment);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Number Of Remaining Segments: %d",
		(tvb_get_guint8(tvb, offset) & 0x7F));
	offset++;
	length--;

	if(first_sub_segment == 0x80) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 2, "Length: %d",
			tvb_get_ntohs(tvb, offset));
		offset += 2;
		length -= 2;
	}

	while(length > 0) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Segment Message byte %d: %d",
			j++, tvb_get_guint8(tvb, offset));
		offset++;
		length--;
	}
}


/*-----------------------------------------------------------------------------
    IP DEVICE ROUTING - 13h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_ip_device_routing(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
			 guint offset, guint length, guint8 opcode _U_,
			 proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	gint *lengthp = 0;
	proto_tree *ua3g_body_tree;
	proto_item *ua3g_param_item;
	proto_tree *ua3g_param_tree;
	static const value_string str_command[] = {
		{0x00, "Reset"},
		{0x01, "Start RTP"},
		{0x02, "Stop RTP"},
		{0x03, "Redirect"},
		{0x04, "Tone Definition"},
		{0x05, "Start Tone"},
		{0x06, "Stop Tone"},
		{0x07, "Start Listen RTP"},
		{0x08, "Stop Listen RTP"},
		{0x09, "Get Parameters Value"},
		{0x0A, "Set Parameters Value"},
		{0x0B, "Send Digit"},
		{0x0C, "Pause RTP"},
		{0x0D, "Restart RTP"},
		{0x0E, "Start Record RTP"},
		{0x0F, "Stop Record RTP"},
		{0, NULL}
	};

	emem_strbuf_t *strbuf = ep_strbuf_new_label("");

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_command, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_command, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
		val_to_str(command, str_command, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip, tvb, offset, 1,
		command, "Command: %s",
		val_to_str(command, str_command, "Unknown"));
	offset++;
	length--;

	switch(command) {
	case 0x00: /* RESET */
		{
			int i, parameter_id, parameter_length;
			static const value_string str_parameter_id[] = {
				{0x00, "Update Mode"},
				{0x01, "Bad Sec Mode"},
				{0x02, "Customization Name"},
				{0x03, "Localization Name"},
				{0, NULL}
			};

			if(length > 0) {
				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					switch(parameter_id) {
					case 0x00: /* Update Mode */
						{
							static const value_string str_update_mode[] = {
								{0x00, "NOE Update Mode"},
								{0x01, "Bootloader"},
								{0x02, "Data"},
								{0x04, "Customization"},
								{0x08, "Localization"},
								{0x10, "Code"},
								{0x20, "SIP"},
								{0, NULL}
							};
							static const value_string str_disable_enable[] = {
								{0, "Disable"},
								{1, "Enable"},
								{0, NULL}
							};

							if((tvb_get_guint8(tvb, offset + 2) & 0x80) == 0x00) {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%s: ",
									val_to_str(tvb_get_guint8(tvb, offset + 2) & 0x80, str_update_mode, "Unknown"));

								for(i = 0; i < 6; i++) {
									ep_strbuf_append_printf(strbuf, "%s: %s, ",
										val_to_str(0x01 << i, str_update_mode, "Unknown"),
										val_to_str((tvb_get_guint8(tvb, offset + 2) >> i) & 0x01, str_disable_enable, ""));
								}
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%s",
									val_to_str(tvb_get_guint8(tvb, offset + 2) & 0x80, str_update_mode, "Unknown"));
							}

							break;
						}
					case 0x01: /* Bad_Sec_Mode */
						{
							static const value_string str_bad_sec_mode[] = {
								{0x01, "Binary is full, CS is secured, but terminal running in clear mode"},
								{0, NULL}
							};

							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf,
								val_to_str(tvb_get_guint8(tvb, offset + 2), str_bad_sec_mode, "Unknown"));
							break;
						}
					case 0x02: /* Cust_Name */
						{
							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf, "\"");
							for(i = 1; i <= parameter_length; i++) {
								if(isprint(tvb_get_guint8(tvb, offset + 1 + i)))
									ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+1+i, lengthp));
								else
									ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+1+i, lengthp));
							}

							ep_strbuf_append(strbuf, "\"");
							break;
						}
					case 0x03: /* L10N_Name */
						{
							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf, "\"");
							for(i = 1; i <= parameter_length; i++) {
								if(isprint(tvb_get_guint8(tvb, offset + 1 + i)))
									ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+1+i, lengthp));
								else
									ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+1+i, lengthp));
							}

							ep_strbuf_append(strbuf, "\"");
							break;
						}
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s: %s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				} else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
					"Parameter: %s", val_to_str(parameter_id, str_parameter_id, "Unknown"));
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					/*Fix Clang Warning*/
					/*offset += parameter_length;*/
					/*length -= parameter_length;*/
				}
			}
			break;
		}
	case 0x01: /* START RTP */
		{
			int i, parameter_length, parameter_id;
			static const value_string str_direction[] = {
				{0x00, "Terminal Input"},
				{0x01, "Terminal Output"},
				{0x02, "Terminal Input/Output (Both Directions)"},
				{0, NULL}
			};
			static const value_string str_parameter_id[] = {
				{0x00, "Local UDP Port"},
				{0x01, "Remote IP Address"},
				{0x02, "Remote UDP Port"},
				{0x03, "Type Of Service"},
				{0x04, "Compressor"},
				{0x05, "Payload Concatenation (ms)"},
				{0x06, "Echo Cancelation Enabler"},
				{0x07, "Silence Suppression Enabler"},
				{0x08, "802.1 Q User Priority"},
				{0x09, "Reserved"},
				{0x0a, "Post Filtering Enabler"},
				{0x0b, "High Pass Filtering Enabler"},
				{0x0c, "Remote SSRC"},
				{0x0d, "Must Send QOS Tickets"},
				{0x0e, "Local Identifier"},
				{0x0f, "Distant Identifier"},
				{0x10, "Destination For RTCP Sender Reports - Port Number"},
				{0x11, "Destination For RTCP Sender Reports - IP Address"},
				{0x12, "Destination For RTCP Receiver Reports - Port Number"},
				{0x13, "Destination For RTCP Receiver Reports - IP Address"},
				{0x14, "Channel Number"},
				{0x15, "DTMF Sending"},
				{0x16, "Payload Type Of Redundancy"},
				{0x17, "Payload Type Of DTMF Events"},
				{0x18, "Enable / Disable RFC 2198"},
				{0x31, "SRTP Encryption Enable For This Communication"},
				{0x32, "Master Key For SRTP Session"},
				{0x33, "Master Salt Key For SRTP Session"},
				{0x34, "Master key for output stream of SRTP session"},
				{0x35, "Master salt key for output stream of SRTP session"},
				{0x36, "Integrity checking enabled for this communication"},
				{0x37, "MKI value for SRTP packets in input stream"},
				{0x38, "MKI value for SRTP packets in output stream"},
				{0x50, "MD5 Authentication"},
				{0, NULL}
			};

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Direction: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_direction, "Unknown"));
			offset++;
			length--;

			while(length > 0) {
				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					switch(parameter_id) {
					case 0x01: /* Remote IP Address */
					case 0x11: /* Destination For RTCP Sender Reports - IP Address */
					case 0x13: /* Destination For RTCP Receiver Reports - IP Address */
						{
							if(parameter_length > 0) {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", tvb_get_guint8(tvb, offset + 2));
							}

							for(i = 2; i <= parameter_length; i++) {
								ep_strbuf_append(strbuf, ".");
								ep_strbuf_append_printf(strbuf, "%u", tvb_get_guint8(tvb, offset+1+i));
							}
							break;
						}
					case 0x04: /* Compressor */
						{
							static const value_string str_compressor[] = {
								{0x00, "G.711 A-law"},
								{0x01, "G.711 mu-law"},
								{0x0F, "G.723.1 5.3kbps"},
								{0x10, "G.723.1 6.3kbps"},
								{0x11, "G.729A 8 kbps"},
								{0, NULL}
							};

							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;
								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append(strbuf, val_to_str((guint8)(param_value), str_compressor, "Default Codec"));
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					case 0x06: /* Echo Cancelation Enabler */
					case 0x07: /* Silence Suppression Enabler */
					case 0x0A: /* Post Filtering Enabler */
					case 0x0B: /* High Pass Filtering Enabler */
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append(strbuf, val_to_str((guint8)(param_value), str_on_off, "On"));
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					case 0x0D: /* Must Send QOS Tickets */
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append(strbuf, val_to_str((guint8)(param_value), str_yes_no, "No"));
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					case 0x0E: /* Local Identifier */
					case 0x0F: /* Distant Identifier */
						{
							break;
						}
					case 0x15: /* DTMF Sending */
						{
							static const value_string str_dtmf_sending[] = {
								{0x00, "Don't Send DTMF"},
								{0, NULL}
							};
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--)
								{
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append(strbuf, val_to_str((guint8)(param_value), str_dtmf_sending, "Send DTMF"));
							}
							else
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					case 0x18: /* Enable / Disable RFC 2198 */
						{
							static const value_string str_enable_00[] = {
								{0x00, "Enable"},
								{0, NULL}
							};

							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append(strbuf, val_to_str((guint8)(param_value), str_enable_00, "Disable"));
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					case 0x31: /* SRTP Encryption Enable For This Communication */
						{
							static const value_string str_enable_10[] = {
								{0x10, "Enable"},
								{0, NULL}
							};

							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--)
								{
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append(strbuf, val_to_str((guint8)(param_value), str_enable_10, "Disable"));
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					case 0x00: /* Local UDP Port */
					case 0x02: /* Remote UDP Port */
					case 0x03: /* Type Of Service */
					case 0x05: /* Payload Concatenation */
					case 0x08: /* 802.1 Q User Priority */
					case 0x09: /* Reserved */
					case 0x0C: /* Remote SSRC */
					case 0x10: /* Destination For RTCP Sender Reports - Port Number */
					case 0x12: /* Destination For RTCP Receiver Reports - Port Number */
					case 0x14: /* Channel Number */
					case 0x16: /* Payload Type For Redundancy */
					case 0x17: /* Payload Type For DTMF Events */
					case 0x32: /* Master Key For SRTP Session */
					case 0x33: /* Master Salt Key For SRTP Session */
					case 0x34: /* Master key for output stream of SRTP session */
					case 0x35: /* Master salt key for output stream of SRTP session */
					case 0x36: /* Integrity checking enabled for this communication */
					case 0x37: /* MKI value for SRTP packets in input stream */
					case 0x38: /* MKI value for SRTP packets in output stream */
					case 0x50: /* MD5 Authentication */
					default:
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--)
								{
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s: %s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				} else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Parameter: %s (0x%02x)",
					val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					offset += parameter_length;
					length -= parameter_length;
				}
			}
			break;
		}
	case 0x02: /* STOP_RTP */
		{
			int i, parameter_id, parameter_length;
			static const value_string str_parameter_id[] = {
				{0x0E, "Local Identifier"},
				{0x0F, "Distant Identifier"},
				{0x14, "Canal Identifier"},
				{0, NULL}
			};

			while(length > 0) {
				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					switch(parameter_id) {
					case 0x0E: /* Local Identifier */
					case 0x0F: /* Distant Identifier */
						{
							break;
						}
					case 0x14: /* Canal Identifier */
					default:
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--)
								{
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s: %s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				} else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
					"Parameter: %s (0x%02x)",
					val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					offset += parameter_length;
					length -= parameter_length;
				}
			}
			break;
		}
	case 0x03: /* REDIRECT */
		{
			int i, parameter_length, parameter_id;
			static const value_string str_parameter_id[] = {
				{0x00, "Remote MainCPU Server IP Adress"},
				{0x01, "Remote MainCPU Server Port"},
				{0, NULL}
			};

			while(length > 0) {
				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					switch(parameter_id) {
					case 0x00: /* Remote MainCPU Server IP Adress */
						{
							if(parameter_length > 0) {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", tvb_get_guint8(tvb, offset + 2));
							}

							for(i = 2; i <= parameter_length; i++) {
								ep_strbuf_append(strbuf, ".");
								ep_strbuf_append_printf(strbuf, "%u", tvb_get_guint8(tvb, offset+1+i));
							}
							break;
						}
					case 0x01: /* Remote MainCPU Server Port */
					default:
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
						}
						break;
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, parameter_length + 2,
						"%s: %s", val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				} else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, parameter_length + 2,
						"%s", val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
					"Parameter: %s (0x%02x)",
					val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					offset += parameter_length;
					length -= parameter_length;
				}
			}
			break;
		}
	case 0x04: /* DEF_TONES */
		{
			int i, tone_nb_entries;
			guint16 frequency_1, frequency_2;
			signed char level_1, level_2;

			tone_nb_entries = tvb_get_guint8(tvb, offset);

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Nomber Of Entries: %d", tone_nb_entries);
			offset++;
			length--;

			while(length > 0) {
				for(i = 1; i <= tone_nb_entries; i++) {
					frequency_1 = tvb_get_ntohs(tvb, offset);
					level_1 = (signed char)(tvb_get_guint8(tvb, offset + 2)) / 2;
					frequency_2 = tvb_get_ntohs(tvb, offset + 3);
					level_2 = (signed char)(tvb_get_guint8(tvb, offset + 5)) / 2;

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 6,
						"Tone Pair %d: %d Hz at %d dB / %d Hz at %d dB",
						i, frequency_1, level_1, frequency_2, level_2);
					ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 2,
						"Frequency 1: %d Hz", frequency_1);
					offset += 2;
					length -= 2;

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Level: %d dB", level_1);
					offset++;
					length--;

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 2, "Frequency 2: %d Hz", frequency_2);
					offset += 2;
					length -= 2;

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Level: %d dB", level_2);
					offset++;
					length--;
				}
			}
			break;
		}
	case 0x05: /* START TONE */
		{
			guint8 i, tone_nb_entries, tone_direction, tone_id;
/*			guint8 i, tone_nb_entries, tone_direction, tone_id, tone_duration tone_silence; */
			int tone_duration;
			static const value_string str_tone_direction[] = {
				{0x00, "On The Phone"},
				{0x40, "To The Network"},
				{0x80, "On The Phone and To The Network"},
				{0, NULL}
			};

			tone_direction = tvb_get_guint8(tvb, offset) & 0xC0;
			tone_nb_entries = tvb_get_guint8(tvb, offset);

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Direction: %s - Nomber Of Entries: %d",
				val_to_str(tone_direction, str_tone_direction, "Unknown"), tone_nb_entries);
			offset++;
			length--;

			while(length > 0 && tone_nb_entries) {
				for(i = 1; i <= tone_nb_entries; i++) {
					tone_id = tvb_get_guint8(tvb, offset);
					tone_duration = tvb_get_ntohs(tvb, offset + 1);
					/*tone_duration = tvb_get_guint8(tvb, offset + 1);
					tone_silence = tvb_get_guint8(tvb, offset + 2);*/

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 6,
						"Tone Pair %d: Id: %d, Duration: %d ms",
/*						"Tone Pair %d: Id: %d, Duration: %d ms, Silence: %d ms", */
						i, tone_id, tone_duration);
/*						i, tone_id, tone_duration, tone_silence); */
					ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
						"Identification: %d", tone_id);
					offset++;
					length--;

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 2,
						"Duration: %d ms", tone_duration);
					offset += 2;
					length -= 2;

					/*proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
						"Duration: %d ms", tone_duration);
					offset++;
					length--;

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
						"Silence: %d ms", tone_silence);
					offset++;
					length--;*/
				}
			}
			break;
		}
	case 0x07: /* START LISTEN RTP */
	case 0x08: /* STOP LISTEN RTP */
		{
			int i, parameter_length, parameter_id;
			static const value_string str_parameter_id[] = {
				{0x00, "Remote IP Adress     "},
				{0x01, "Remote UDP Port In   "},
				{0x02, "Remote UDP Port Out  "},
				{0x03, "Remote IP Address Out"},
				{0x04, "Canal Number"},
				{0, NULL}
			};

			while(length > 0) {
				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					switch(parameter_id) {
					case 0x00: /* Remote IP Adress - Not for start listening rtp */
					case 0x03: /* Remote IP Adress Out - Not for start listening rtp */
						{
							if(parameter_length > 0) {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", tvb_get_guint8(tvb, offset + 2));
							}

							for(i = 2; i <= parameter_length; i++) {
								ep_strbuf_append(strbuf, ".");
								ep_strbuf_append_printf(strbuf, "%u", tvb_get_guint8(tvb, offset+1+i));
							}
							break;
						}
					case 0x01: /* Remote UDP Port In - Not for start listening rtp */
					case 0x02: /* Remote UDP Port Out - Not for start listening rtp */
					case 0x04: /* Canal Number */
					default:
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
						}
						break;
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s: %s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				}
				else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
					"Parameter: %s (0x%02x)",
					val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					offset += parameter_length;
					length -= parameter_length;
				}
			}
			break;
		}
	case 0x09: /* GET_PARAM_REQ */
		{
			guint8 parameter;
			static const value_string str_parameter[] = {
				{0x00	, "Firmware Version"},
				{0x01	, "Firmware Version"},
				{0x02	, "DHCP IP Address"},
				{0x03	, "Local IP Address"},
				{0x04	, "Subnetwork Mask"},
				{0x05	, "Router IP Address"},
				{0x06	, "TFTP IP Address"},
				{0x07	, "MainCPU IP Address"},
				{0x08	, "Default Codec"},
				{0x09	, "Ethernet Drivers Config"},
				{0x0A	, "MAC Address"},
				{0, NULL}
			};

			while(length > 0) {
				parameter = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s",
					val_to_str(parameter, str_parameter, "Unknown"));
				offset++;
				length--;
			}
			break;
		}
	case 0x0A: /* SET_PARAM_REQ */
		{
			int i, parameter_id, parameter_length;
			static const value_string str_parameter_id[] = {
				{0x00	, "QOS IP TOS"},
				{0x01	, "QOS 8021 VLID"},
				{0x02	, "QOS 8021 PRI"},
				{0x03	, "SNMP MIB2 SysContact"},
				{0x04	, "SNMP MIB2 SysName"},
				{0x05	, "SNMP MIB2 SysLocation"},
				{0x06	, "Default Compressor"},
				{0x07	, "Error String Net Down"},
				{0x08	, "Error String Cable PB"},
				{0x09	, "Error String Try Connect"},
				{0x0A	, "Error String Connected"},
				{0x0B	, "Error String Reset"},
				{0x0C	, "Error String Duplicate IP Address"},
				{0x0D	, "SNMP MIB Community"},
				{0x0E	, "TFTP Backup Sec Mode"},
				{0x0F	, "TFTP Backup IP Address"},
				{0x10	, "Set MMI Password"},
				{0x11	, "Set PC Port Status"},
				{0x12	, "Record RTP Authorization"},
				{0x13	, "Security Flags"},
				{0x14	, "ARP Spoofing"},
				{0x15	, "Session Param"},
				{0x30	, "MD5 Authentication"},
				{0, NULL}
			};

			while(length > 0) {
				guint64 param_value = 0;

				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					switch(parameter_id) {
					case 0x06: /* Compressor */
						{
							static const value_string str_compressor[] = {
								{0x00, "G.711 A-law"},
								{0x01, "G.711 mu-law"},
								{0x0F, "G.723.1 5.3kbps"},
								{0x10, "G.723.1 6.3kbps"},
								{0x11, "G.729A 8 kbps"},
								{0, NULL}
							};

							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf, val_to_str(tvb_get_guint8(tvb, offset + 2),
								str_compressor, "Default Codec"));
							break;
						}
					case 0x07: /* ERR STRING NET DOWN */
					case 0x08: /* ERR STRING CABLE PB */
					case 0x09: /* ERR STRING TRY CONNECT */
					case 0x0A: /* ERR STRING CONNECTED */
					case 0x0B: /* ERR STRING RESET */
					case 0x0C: /* ERR STRING DUPLICATE IP ADDRESS */
						{
							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf, "\"");
							for(i = 1; i <= parameter_length; i++) {
								if(isprint(tvb_get_guint8(tvb, offset + 1 + i)))
									ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+1+i, lengthp));
								else
									ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+1+i, lengthp));
							}
							ep_strbuf_append(strbuf, "\"");
							break;
						}
					case 0x0F: /* TFTP BACKUP IP ADDR */
						{
							if(parameter_length > 0) {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", tvb_get_guint8(tvb, offset + 2));
							}

							for(i = 2; i <= parameter_length; i++) {
								ep_strbuf_append(strbuf, ".");
								ep_strbuf_append_printf(strbuf, "%u", tvb_get_guint8(tvb, offset+1+i));
							}
							break;
						}
					case 0x11: /* Set PC Port status */
						{
							static const value_string str_set_pc_port_status[] = {
								{0x00, "No PC Port Security"},
								{0x01, "Block PC Port"},
								{0x02, "Filter VLAN"},
								{0, NULL}
							};
							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf, val_to_str(tvb_get_guint8(tvb, offset + 2),
								str_set_pc_port_status, "Unknown"));
							break;
						}
					case 0x12: /* Record RTP Authorization */
						{
							static const value_string str_enable_feature[] = {
								{0x00, "Disable Feature"},
								{0x01, "Enable Feature"},
								{0, NULL}
							};

							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf, val_to_str(tvb_get_guint8(tvb, offset + 2),
								str_enable_feature, "Unknown"));
							break;
						}
					case 0x13: /* Security Flags */
						{
							static const value_string str_set_pc_port_status[] = {
								{0x00, "Filtering Not Active"},
								{0x01, "Filtering Activated"},
								{0, NULL}
							};
							ep_strbuf_truncate(strbuf, 0);
							ep_strbuf_append(strbuf, val_to_str((tvb_get_guint8(tvb, offset + 2) & 0x01),
								str_set_pc_port_status, "Unknown"));
							break;
						}
					case 0x00: /* QOS IP TOS */
					case 0x01: /* QOS 8021 VLID */
					case 0x02: /* QOS 8021 PRI */
					case 0x03: /* SNMP MIB2 SYSCONTACT */
					case 0x04: /* SNMP MIB2 SYSNAME */
					case 0x05: /* SNMP MIB2 SYSLOCATION */
					case 0x0D: /* SNMP MIB COMMUNITY */
					case 0x0E: /* TFTP BACKUP SEC MODE */
					case 0x10: /* SET MMI PASSWORD */
					case 0x14: /* ARP Spoofing */
					case 0x15: /* Session Param */
					case 0x30: /* MD5 Authentication */
					default:
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
							} else if(parameter_length > 8) {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
							break;
						}
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s: %s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				} else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Parameter: %s (0x%02x)",
					val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					offset += parameter_length;
					length -= parameter_length;
				}
			}
			break;
		}
	case 0x0B: /* SEND_DIGIT */
		{
			static const value_string str_digit[] = {
				{0, "0"},
				{1, "1"},
				{2, "2"},
				{3, "3"},
				{4, "4"},
				{5, "5"},
				{6, "6"},
				{7, "7"},
				{8, "8"},
				{9, "9"},
				{10, "*"},
				{11, "#"},
				{12, "A"},
				{13, "B"},
				{14, "C"},
				{15, "D"},
				{16, "Flash"},
				{0, NULL}
			};
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Digit Value: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_digit, "Unknown"));
		break;
		}
	case 0x0C: /* PAUSE_RTP */
	case 0x0D: /* RESTART_RTP */
		{
			int i, parameter_length, parameter_id;
			static const value_string str_parameter_id[] = {
				{0x14, "Canal Identifier"},
				{0, NULL}
			};

			while(length > 0) {
				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					if((parameter_length > 0) && (parameter_length <= 8)) {
						guint64 param_value = 0;

						for(i = parameter_length; i > 0; i--) {
							param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
						}
						ep_strbuf_truncate(strbuf, 0);
						ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
					} else {
						ep_strbuf_truncate(strbuf, 0);
						ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
							tvb_get_guint8(tvb, offset + 2),
							tvb_get_guint8(tvb, offset + 3),
							tvb_get_guint8(tvb, offset + parameter_length),
							tvb_get_guint8(tvb, offset + 1 + parameter_length));
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s: %s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				}
				else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
					"Parameter: %s (0x%02x)",
					val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					offset += parameter_length;
					length -= parameter_length;
				}
			}
			break;
		}
	case 0x0E: /* START_RECORD_RTP */
	case 0x0F: /* STOP RECORD RTP */
		{
			int i, parameter_length, parameter_id;
			static const value_string str_parameter_id[] = {
				{0x00	, "Recorder Index"},
				{0x01	, "Remote IP Address"},
				{0x02	, "Remote UDP Port In"},
				{0x03	, "Remote UDP Port Out"},
				{0x04	, "Remote IP Address Out"},
				{0x05	, "Local UDP Port In"},
				{0x06	, "Local UDP Port Out"},
				{0x07	, "Type Of Service"},
				{0x08	, "Master Key For SRTP Session"},
				{0x09	, "Master Salt Key For SRTP Session"},
				{0x30	, "MD5 Authentication"},
				{0, NULL}
			};

			while(length > 0) {
				parameter_id = tvb_get_guint8(tvb, offset);
				parameter_length = tvb_get_guint8(tvb, offset + 1);

				if(parameter_length > 0) {
					switch(parameter_id) {
					case 0x01: /* Remote IP Address */
					case 0x04: /* Remote IP Address Out */
						{
							if(parameter_length > 0) {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", tvb_get_guint8(tvb, offset + 2));
							}

							for(i = 2; i <= parameter_length; i++) {
								ep_strbuf_append(strbuf, ".");
								ep_strbuf_append_printf(strbuf, "%u", tvb_get_guint8(tvb, offset+1+i));
							}
							break;
						}
					case 0x00: /* Recorder Index */
					case 0x02: /* Remote UDP Port In */
					case 0x03: /* Remote UDP Port Out */
					case 0x05: /* Local UDP Port In */
					case 0x06: /* Local UDP Port Out */
					case 0x07: /* Type Of Service */
					case 0x08: /* Master Key For SRTP Session */
					case 0x09: /* Master Salt Key For SRTP Session */
					case 0x30: /* MD5 Authentication */
					default:
						{
							if((parameter_length > 0) && (parameter_length <= 8)) {
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
							} else {
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
									tvb_get_guint8(tvb, offset + 2),
									tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + parameter_length),
									tvb_get_guint8(tvb, offset + 1 + parameter_length));
							}
						}
						break;
					}

					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s: %s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
				} else
					ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
						parameter_length + 2, "%s",
						val_to_str(parameter_id, str_parameter_id, "Unknown"));

				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
					"Parameter: %s (0x%02x)",
					val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
				offset++;
				length--;

				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
					"Length: %d", parameter_length);
				offset++;
				length--;

				if(parameter_length > 0) {
					proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
						"Value: %s", strbuf->str);
					offset += parameter_length;
					length -= parameter_length;
				}
			}
			break;
		}
	case 0x06: /* STOP TONE */
	default:
		{
			break;
		}
	}
}


/*-----------------------------------------------------------------------------
    DEBUG IN LINE - 18h (MESSAGE FROM THE TERMINAL AND FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_debug_in_line(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		     guint offset, guint length, guint8 opcode _U_,
		     proto_item *ua3g_body_item)
{
	gint *lengthp = 0;
	proto_tree *ua3g_body_tree;
	int i, parameter_length;
	emem_strbuf_t *strbuf = ep_strbuf_new_label("");

	parameter_length = length;
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	ep_strbuf_truncate(strbuf, 0);
	ep_strbuf_append(strbuf, "\"");
	for(i = 0; i < parameter_length; i++) {
		if(isprint(tvb_get_guint8(tvb, offset + i)))
			ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+i, lengthp));
		else
			ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+i, lengthp));
	}
	ep_strbuf_append(strbuf, "\"");

	proto_tree_add_text(ua3g_body_tree, tvb, offset, length,
		"Text String With Debug: %s", strbuf->str);
}


/*-----------------------------------------------------------------------------
    LED COMMAND - 21h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_led_command(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		   guint offset, guint length, guint8 opcode _U_,
		   proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int command = tvb_get_guint8(tvb, offset);
	static const value_string str_command[] = {
		{0x00, "Led Off"},
		{0x01, "Led On"},
		{0x02, "Red Led Fast Flash"},
		{0x03, "Red Led Slow Flash"},
		{0x04, "Green Led On"},
		{0x05, "Green Led Fast Flash"},
		{0x06, "Green Led Slow Flash"},
		{0x07, "All Led Off"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_command, "Unknown"));
	proto_item_append_text(ua3g_body_item, "s - %s",
		val_to_str(command, str_command, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_command, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_command, "Unknown"));
	offset++;
	length--;

	if(command != 0x07) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Led Number: %d", tvb_get_guint8(tvb, offset));
	}
}


/*-----------------------------------------------------------------------------
    LCD LINE 1 COMMANDS - 27h (MESSAGE FROM THE SYSTEM)
    LCD LINE 2 COMMANDS - 28h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_lcd_line_cmd(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		    guint offset, guint length, guint8 opcode _U_,
		    proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 lcd_options, command, column_n;
	guint i;
	proto_tree *ua3g_body_tree;
	proto_item *ua3g_param_item;
	proto_tree *ua3g_param_tree;
	proto_item *ua3g_option_item;
	proto_tree *ua3g_option_tree;
	static char str_ascii[40];
/*	static char lcd_options_tab[6];*/
	static const value_string str_command[] = {
		{0, "Clear Line & Write From Column"},
		{1, "Write From Column"},
		{2, "Append To Current Line"},
		{0, NULL}
	};
	static const value_string str_enable_disable[] = {
		{0, "Disable"},
		{0, NULL}
	};
	static const value_string str_lcd_option[] = {
		{7, "Suspend Display Refresh"},
		{6, "Time Of Day Display    "},
		{5, "Call Timer Display     "},
		{4, "Call Timer Control     "},
		{2, "Blink                  "},
		{0, NULL}
	};
	static const value_string str_call_timer_ctrl[] = {
		{0x00, "Call Timer Status Not Changed"},
		{0x08, "Stop Call Timer"},
		{0x10, "Start Call Timer From Current Value"},
		{0x18, "Initialize And Call Timer"},
		{0, NULL}
	};
	emem_strbuf_t *strbuf = ep_strbuf_new_label("");

	lcd_options = tvb_get_guint8(tvb, offset) & 0xFC;
	command = tvb_get_guint8(tvb, offset) & 0x03;
	column_n = tvb_get_guint8(tvb, offset + 1);

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s %d",
		val_to_str(command, str_command, "Unknown"),
		column_n);
	proto_item_append_text(ua3g_body_item, " %s %d",
		val_to_str(command, str_command, "Unknown"),
		column_n);
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s %d",
			val_to_str(command, str_command, "Unknown"),
			column_n);

	ep_strbuf_truncate(strbuf, 0);
	ep_strbuf_append(strbuf, "\"");
	for(i = 0; i < length - 2; i++) {
		if(isprint(tvb_get_guint8(tvb, offset + 2 + i)))
			ep_strbuf_append_printf(strbuf, "%c", tvb_get_guint8(tvb, offset + 2 + i));
		else
			ep_strbuf_append_printf(strbuf, "'0x%02x'", tvb_get_guint8(tvb, offset + 2 + i));
	}
	ep_strbuf_append(strbuf, "\"");

	ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
		length, "%s %d: %s",
		val_to_str(command, str_command, "Unknown"), column_n, str_ascii);
	ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_command, "Unknown"));
	ua3g_option_item = proto_tree_add_text(ua3g_param_tree, tvb, offset,
		1, "LCD Options: 0x%x", lcd_options);
	ua3g_option_tree = proto_item_add_subtree(ua3g_option_item, ett_ua3g_option);

	for(i = 2; i <= 7; i++) {
		int shift_value = 1 << i;
		if(i != 3) {
			proto_tree_add_text(ua3g_option_tree, tvb, offset, 1, "%s: %s",
				val_to_str(i, str_lcd_option, "Unknown"),
				val_to_str((tvb_get_guint8(tvb, offset) & shift_value), str_enable_disable, "Enable"));
		} else {
			i++;
			proto_tree_add_text(ua3g_option_tree, tvb, offset, 1, "%s: %s",
				val_to_str(i, str_lcd_option, "Unknown"),
				val_to_str((tvb_get_guint8(tvb, offset) & 0x18), str_call_timer_ctrl, "Unknown"));
		}
	}
	offset++;
	length--;

	if(command != 3)
		proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Starting Column: %d", column_n);
	else
		proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Unused");

	offset++;
	length--;
	proto_tree_add_text(ua3g_param_tree, tvb, offset, length, "ASCII Char: %s", str_ascii);
}


/*-----------------------------------------------------------------------------
    MAIN VOICE MODE - 29h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_main_voice_mode(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		       guint offset, guint length, guint8 opcode _U_,
		       proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 mode = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;
	static const value_string str_voice_mode[] = {
		{0x00, "Idle"},
		{0x01, "Handset"},
		{0x02, "Group Listening"},
		{0x03, "On Hook Dial"},
		{0x04, "Handsfree"},
		{0x05, "Announce Loudspeaker"},
		{0x06, "Ringing"},
		{0x10, "Idle"},
		{0x11, "Handset"},
		{0x12, "Headset"},
		{0x13, "Handsfree"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(mode, str_voice_mode, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(mode, str_voice_mode, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(mode, str_voice_mode, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, mode, "Voice Mode: %s",
		val_to_str(mode, str_voice_mode, "Unknown"));
	offset++;
	length--;

	switch(mode) {
	case 0x06: /* Ringing */
		{
			static const value_string str_cadence[] = {
				{0x00, "Standard Ringing"},
				{0x01, "Double Burst"},
				{0x02, "Triple Burst"},
				{0x03, "Continuous Ringing"},
				{0x04, "Priority Attendant Ringing"},
				{0x05, "Regular Attendant Ringing"},
				{0x06, "Programmable Cadence"},
				{0x07, "Programmable Cadence"},
				{0, NULL}
			};

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Tune: %d", tvb_get_guint8(tvb, offset));
			offset++;
			length--;

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Cadence: %s (%d)",
				val_to_str(tvb_get_guint8(tvb, offset), str_cadence, "Unknown"),
				tvb_get_guint8(tvb, offset));
			offset++;
			length--;
		}
	case 0x02: /* Group Listening */
	case 0x03: /* On Hook Dial */
	case 0x04: /* Handsfree */
	case 0x05: /* Announce Loudspeaker */
		{
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Speaker Volume: %d",
				tvb_get_guint8(tvb, offset));
			offset++;
			length--;

			if(length > 0) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset,
					1, "Microphone Volume: %d",
					tvb_get_guint8(tvb, offset));
			}
			break;
		}
	case 0x11: /* Handset */
	case 0x12: /* Headset */
	case 0x13: /* Handsfree */
		{
			signed char level;
			static const value_string str_receiving_level[] = {
				{0x11, "Receiving Level "},
				{0x12, "Receiving Level "},
				{0x13, "Speaker Level   "},
				{0, NULL}
			};

			level = (signed char)(tvb_get_guint8(tvb, offset)) / 2;
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"%s: %d dB",
				val_to_str(mode, str_receiving_level, "Unknown"), level);
			offset++;
			length--;

			level = (signed char)(tvb_get_guint8(tvb, offset)) / 2;
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Sending Level	: %d dB", level);
			break;
		}
	case 0x00: /* Idle */
	case 0x01: /* Handset */
	case 0x10: /* Idle */
	default:
		{
			break;
		}
	}
}


/*-----------------------------------------------------------------------------
    SUBDEVICE METASTATE - 2Ch (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_subdevice_metastate(proto_tree *tree _U_, tvbuff_t *tvb,
			   packet_info *pinfo _U_, guint offset, guint length,
			   guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_new_metastate[] = {
		{0x00, "Disable"},
		{0x01, "Active"},
		{0x02, "Wake Up"},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Subchannel Address: %d", tvb_get_guint8(tvb, offset));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "New Metastate: %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_new_metastate, "Unknown"));
}


/*-----------------------------------------------------------------------------
    Download DTMF & CLOCK FORMAT - 30h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_dwl_dtmf_clck_format(proto_tree *tree _U_, tvbuff_t *tvb,
			    packet_info *pinfo _U_, guint offset, guint length,
			    guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_clock_format[] = {
		{0, "Europe"},
		{1, "US"},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Minimum 'ON' Time: %d ms", (tvb_get_guint8(tvb, offset) * 10));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Inter-Digit Pause Time: %d ms",
		(tvb_get_guint8(tvb, offset) * 10));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Clock Time Format: %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_clock_format, "Unknown"));
	offset++;
	length--;

	if(length > 0)
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"DTMF Country Adaptation: %d", tvb_get_guint8(tvb, offset));
}


/*-----------------------------------------------------------------------------
    SET CLOCK - 31h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_set_clck(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		guint offset, guint length, guint8 opcode _U_,
		proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;
	proto_item *ua3g_param_item;
	proto_tree *ua3g_param_tree;
	int hour, minute, second, call_timer;
	static const value_string str_command[] = {
		{0x00, "Set Current Time/Call Timer"},
		{0x01, "Set Current Time"},
		{0x02, "Set Call Timer"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_command, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_command, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_command, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_command, "Unknown"));
	offset++;
	length--;
	call_timer = 0;

	switch(command) {
	case 0x02: /* Timer Form */
		{
			call_timer = 1;
		}
	case 0x00: /* Set Current Time/Call Timer */
	case 0x01: /* Set Current Time */
		{
			static const value_string str_call_timer[] = {
				{1, "Call Timer "},
				{0, NULL}
			};

			while(length > 0) {
				hour = tvb_get_guint8(tvb, offset);
				minute = tvb_get_guint8(tvb, offset + 1);
				second = tvb_get_guint8(tvb, offset + 2);

				ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset, 3,
					"%s: %d:%d:%d",
					val_to_str(call_timer, str_call_timer, "Current Time"), hour, minute, second);
				ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "%sHour: %d",
					val_to_str(call_timer, str_call_timer, ""), hour);
				offset++;
				length--;
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "%sMinute: %d",
					val_to_str(call_timer, str_call_timer, ""), minute);
				offset++;
				length--;
				proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "%sSecond: %d",
					val_to_str(call_timer, str_call_timer, ""), second);
				offset++;
				length--;

				call_timer = 1;
			}
		}
	default:
		{
			break;
		}
	}

}


/*-----------------------------------------------------------------------------
    VOICE CHANNEL - 32h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_voice_channel(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		     guint offset, guint length, guint8 opcode _U_,
		     proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_v[] = {
		{0x00, "Normal Voice Channel Mode"},
		{0x01, "Write 00 to Voice Channel"},
		{0, NULL}
	};
	static const value_string str_c[] = {
		{0x00, "Normal Codec Operation"},
		{0x02, "Write Quiet To Codec"},
		{0, NULL}
	};
	static const value_string str_b[] = {
		{0x00, "Use B1 As Voice Channel"},
		{0x04, "Use B3 As Voice Channel"},
		{0, NULL}
	};
	static const value_string str_voice_channel[] = {
		{0x00, "No"},
		{0x01, "B1"},
		{0x02, "B2"},
		{0x03, "B3"},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	if(length == 1) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s",
			val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_v, "Unknown"));
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s",
			val_to_str((tvb_get_guint8(tvb, offset) & 0x02), str_c, "Unknown"));
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s",
			val_to_str((tvb_get_guint8(tvb, offset) & 0x04), str_b, "Unknown"));
		offset++;
		length--;
	} else if(length == 2) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Main Voice: %s",
			val_to_str(tvb_get_guint8(tvb, offset), str_voice_channel, "Unknown"));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Announce: %s",
			val_to_str(tvb_get_guint8(tvb, offset), str_voice_channel, "Unknown"));
		offset++;
		length--;
	} else if(length == 4) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "B General: %d",
			tvb_get_guint8(tvb, offset));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "B Loud Speaker: %d",
			tvb_get_guint8(tvb, offset));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "B Ear Piece: %d",
			tvb_get_guint8(tvb, offset));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "B Microphones: %d",
			tvb_get_guint8(tvb, offset));
		offset++;
		length--;
	}
}


/*-----------------------------------------------------------------------------
    EXTERNAL RINGING - 33h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_external_ringing(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
			guint offset, guint length _U_, guint8 opcode _U_,
			proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_ext_ring_cmd[] = {
		{0x00, "Turn Off"},
		{0x01, "Turn On"},
		{0x02, "Follow The Normal Ringing"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_ext_ring_cmd, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_ext_ring_cmd, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(tvb_get_guint8(tvb, offset), str_ext_ring_cmd, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset, 1,
		tvb_get_guint8(tvb, offset), "External Ringing Command: %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_ext_ring_cmd, "Unknown"));
}


/*-----------------------------------------------------------------------------
    LCD CURSOR - 35h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_lcd_cursor(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		  guint offset, guint length, guint8 opcode _U_,
		  proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str((tvb_get_guint8(tvb, offset + 1) & 0x02), str_on_off, "On"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str((tvb_get_guint8(tvb, offset + 1) & 0x02), str_on_off, "On"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str((tvb_get_guint8(tvb, offset + 1) & 0x02), str_on_off, "On"));

	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Line Number: %d", tvb_get_guint8(tvb, offset));
	offset++;
	length--;

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset, 1,
		tvb_get_guint8(tvb, offset), "Cursor %s",
		val_to_str((tvb_get_guint8(tvb, offset) & 0x02), str_on_off, "On"));
}


/*-----------------------------------------------------------------------------
    DOWNLOAD SPECIAL CHARACTER - 36h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_dwl_special_char(proto_tree *tree _U_, tvbuff_t *tvb,
			packet_info *pinfo _U_, guint offset, guint length,
			guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int i, j;
	emem_strbuf_t *strbuf = ep_strbuf_new_label("");

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	while(length > 0) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Character Number: %d", tvb_get_guint8(tvb, offset));
		offset++;
		length--;
		for(i = 1; i <= 8; i++) {
			int byte = tvb_get_guint8(tvb, offset);
			char byte_char[20] = "  ";

			/* The following loop will draw a picture of the character with "spaces" and "o" */
			for(j = 7; j >= 0; j--) {
				if(((byte >> j) & 0x01) == 0)
					ep_strbuf_append_printf(strbuf, "  ");
				else
					ep_strbuf_append_printf(strbuf, "o ");
			}

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Byte %d: 0x%02x   %s", i, byte, byte_char);
			offset++;
			length--;
		}
	}
}


/*-----------------------------------------------------------------------------
    SET CLOCK/TIMER POSITION - 38h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_set_clck_timer_pos(proto_tree *tree _U_, tvbuff_t *tvb,
			  packet_info *pinfo _U_, guint offset, guint length,
			  guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Clock Line Number: %d", tvb_get_guint8(tvb, offset));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Clock Column Number: %d", tvb_get_guint8(tvb, offset));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Call Timer Line Number: %d", tvb_get_guint8(tvb, offset));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Call Timer Column Number: %d", tvb_get_guint8(tvb, offset));
}


/*-----------------------------------------------------------------------------
    SET LCD CONTRAST - 39h - (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_set_lcd_contrast(proto_tree *tree _U_, tvbuff_t *tvb,
			packet_info *pinfo _U_, guint offset, guint length,
			guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_driver_number[] = {
		{0x00, "Display"},
		{0x01, "Icon"},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Driver Number: %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_driver_number, "Unknown"));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Contrast Value: %d", tvb_get_guint8(tvb, offset));
}


/*-----------------------------------------------------------------------------
    BEEP - 3Ch (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_beep(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
	    guint offset, guint length, guint8 opcode _U_,
	    proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	emem_strbuf_t *strbuf = ep_strbuf_new_label("");
	if(length > 0) { /* All cases except classical beep */
		guint8 command = tvb_get_guint8(tvb, offset);
		proto_tree *ua3g_body_tree;
		static const value_string str_command[] = {
			{0x01, "Beep Once"},
			{0x02, "Beep Start"},
			{0x03, "Stop Beep"},
			{0x04, "Start Beep"},
			{0x05, "Define Beep"},
			{0, NULL}
		};

		/* add text to the frame tree */
		proto_item_append_text(ua3g_item, ", %s",
			val_to_str(command, str_command, "Unknown"));
		proto_item_append_text(ua3g_body_item, " - %s",
			val_to_str(command, str_command, "Unknown"));
		ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

		/* add text to the frame "INFO" column */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
				val_to_str(command, str_command, "Unknown"));

		proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb,
			offset, 1, command, "Beep: %s",
			val_to_str(command, str_command, "Unknown"));
		offset++;
		length--;

		switch(command) {
		case 0x01: /* Beep Once */
		case 0x02: /* Beep Start */
			{
				int i =  0;
				static const value_string str_destination[] = {
					{0x01, "Ear-Piece"},
					{0x02, "Loudspeaker"},
					{0x02, "Ear-Piece and Loudspeaker"},
					{0, NULL}
				};
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Destination: %s",
					val_to_str(tvb_get_guint8(tvb, offset), str_destination, "Unknown"));
				offset++;
				length--;

				while(length > 0) {
					i++;
					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "On / Off: %s",
						val_to_str((tvb_get_guint8(tvb, offset) & 0x80), str_on_off, "On"));
					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Cadence T%d: %d ms",
						i, ((tvb_get_guint8(tvb, offset) & 0x7F) * 10));
					offset++;
					length--;
				}
				break;
			}
		case 0x04: /* Start Beep */
			{
				int i;
				static const value_string str_destination[] = {
					{0x01, "Handset"},
					{0x02, "Headset"},
					{0x04, "Loudspeaker"},
					{0x08, "Announce Loudspeaker"},
					{0x10, "Handsfree"},
					{0, NULL}
				};

				ep_strbuf_append_printf(strbuf, "%s",
					val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_destination, ""));
				for(i = 1; i < 5; i++) {
					ep_strbuf_append(strbuf,
						val_to_str((tvb_get_guint8(tvb, offset) & (0x01 << i)), str_destination, ""));
				}

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Destination: %s", strbuf->str);
				offset++;

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Beep Number: %x", tvb_get_guint8(tvb, offset));
				break;
			}
		case 0x05:
			{
				int i, nb_of_notes, beep_number;
				static const value_string str_freq_sample_nb[] = {
					{0x00, "Frequency"},
					{0xFF, "Audio Sample Number"},
					{0, NULL}
				};
				static const value_string str_duration[] = {
					{0x00, "Duration "},
					{0xFF, "Duration (Ignored)"},
					{0, NULL}
				};
				static const value_string str_terminator[] = {
					{0xFD, "Stop"},
					{0xFE, "Loop"},
					{0xFF, "Infinite"},
					{0, NULL}
				};

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Beep Number: %x", beep_number = tvb_get_guint8(tvb, offset));
				offset++;
				length--;

				if(beep_number <= 0x44)
					beep_number = 0x00;
				else beep_number = 0xFF;

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Number Of Notes: %x", nb_of_notes = tvb_get_guint8(tvb, offset));
				offset++;
				length--;

				while(length > 0) {
					for(i = 1; i <= nb_of_notes; i++) {
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s %d: %d",
							val_to_str(beep_number, str_freq_sample_nb, "Unknown"),
							i, tvb_get_guint8(tvb, offset));
						offset++;
						length--;
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Level %d: %d",
							i, tvb_get_guint8(tvb, offset));
						offset++;
						length--;
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s %d: %x",
							val_to_str(beep_number, str_duration, "Unknown"),
							i, tvb_get_guint8(tvb, offset));
						offset++;
						length--;
					}
					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Terminator: %d (%s)",
						tvb_get_guint8(tvb, offset),
						val_to_str(tvb_get_guint8(tvb, offset), str_terminator, "Unknown"));
					offset++;
					length--;
				}
				break;
			}
		case 0x03: /* Stop Beep */
		default:
			{
				break;
			}
		}
	} else { /* Classical Beep */
		/* add text to the frame tree */
		proto_item_append_text(ua3g_item, ", Classical Beep");
		proto_item_append_text(ua3g_body_item, " - Classical Beep");

		/* add text to the frame "INFO" column */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ": Classical Beep");
	}
}


/*-----------------------------------------------------------------------------
    SIDETONE ON / OFF - 3Dh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_sidetone(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		guint offset, guint length _U_, guint8 opcode _U_,
		proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_on_off, "On"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_on_off, "On"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_on_off, "On"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_on_off, "On"));
	offset++;

	if(command == 0x01) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Level: %d dB",
			(signed char)(tvb_get_guint8(tvb, offset) / 2));
	}
}


/*-----------------------------------------------------------------------------
    SET PROGRAMMABLE RINGING CADENCE - 3Eh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_ringing_cadence(proto_tree *tree _U_, tvbuff_t *tvb,
		       packet_info *pinfo _U_, guint offset, guint length,
		       guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int i = 0;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Cadence: %d",
		tvb_get_guint8(tvb, offset));
	offset++;
	length--;

	while(length > 0) {
		i++;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "On / Off	: %s",
			val_to_str((tvb_get_guint8(tvb, offset) & 0x80), str_on_off, "On"));
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Length %d	: %d ms",
			i, ((tvb_get_guint8(tvb, offset) & 0x7F) * 10));
		offset++;
		length--;
	}
}


/*-----------------------------------------------------------------------------
    MUTE ON / OFF - 3Fh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_mute(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
	    guint offset, guint length _U_, guint8 opcode _U_,
	    proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;
	static const value_string str_mute[] = {
		{0x00, "Microphone Disable"},
		{0x01, "Microphone Enable"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_mute, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_mute, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_mute, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "%s",
		val_to_str(command, str_mute, "Unknown"));
}


/*-----------------------------------------------------------------------------
	FEEDBACK ON / OFF - 40h (MESSAGE FROM THE SYSTEM)
	---------------------------------------------------------------------------*/
static void
decode_feedback(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		guint offset, guint length, guint8 opcode _U_,
		proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_on_off, "On"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_on_off, "On"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_on_off, "On"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_on_off, "On"));
	offset++;
	length--;

	if(command == 0x01) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Level: %d dB",
			(signed char)(tvb_get_guint8(tvb, offset) / 2));
		offset++;
		length--;

		if(length > 0) {
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Duration: %d ms",
				(tvb_get_guint8(tvb, offset) * 10));
		}
	}
}


/*-----------------------------------------------------------------------------
    READ PERIPHERAL - 44h (MESSAGE FROM THE SYSTEM)
    WRITE PERIPHERAL - 45h (MESSAGE FROM THE SYSTEM)
    PERIPHERAL CONTENT - 2Bh (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_r_w_peripheral(proto_tree *tree _U_, tvbuff_t *tvb,
		      packet_info *pinfo _U_, guint offset, guint length,
		      guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 2, "Address: %d",
		tvb_get_ntohs(tvb, offset));
	offset += 2;
	length -= 2;

	if(length > 0) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Content: %d", tvb_get_guint8(tvb, offset));
	}
}


/*-----------------------------------------------------------------------------
    ICON COMMAND - 47h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_icon_cmd(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		guint offset, guint length, guint8 opcode _U_,
		proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int i;
	static const value_string str_state[] = {
		{0x00, "Off"},
		{0x01, "Slow Flash"},
		{0x02, "Not Used"},
		{0x03, "Steady On"},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Icon Number: %d", tvb_get_guint8(tvb, offset));
	offset++;
	length--;

	for(i = 0; i < 8; i++) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
			"Segment %d: %s (%d)", i,
			val_to_str((((tvb_get_guint8(tvb, offset) << 1) >> i) & 0x02) + ((tvb_get_guint8(tvb, offset + 1) >> i) & 0x01),str_state, "Unknwon"),
			(((tvb_get_guint8(tvb, offset) << 1) >> i) & 0x02) + ((tvb_get_guint8(tvb, offset + 1) >> i) & 0x01));
	}
}


/*-----------------------------------------------------------------------------
    AUDIO CONFIGURATION - 49h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_audio_config(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		    guint offset, guint length, guint8 opcode _U_,
		    proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;
	static const value_string str_command[] = {
		{0x00, "Audio Coding"},
		{0x01, "DPI Channel Allocations"},
		{0x02, "Loudspeaker Volume Adjust"},
		{0x03, "Audio Circuit Configuration"},
		{0x04, "Handsfree Parameters"},
		{0x05, "Loudspeaker Acoustic Parameters"},
		{0x06, "Device Congiguration"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_command, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_command, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_command, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb,
		offset, 1, command, "Command	: %s (%d)",
		val_to_str(command, str_command, "Unknown"), command);
	offset++;
	length--;

	switch(command) {
	case 0x00: /* Audio Coding */
		{
			static const value_string str_law[] = {
				{0x00, "A Law"},
				{0x01, "m Law"},
				{0, NULL}
			};
			proto_tree_add_text(ua3g_body_tree, tvb, offset,
				1, "Ignored	: %d",
				tvb_get_guint8(tvb, offset));
			offset++;
			length--;

			proto_tree_add_text(ua3g_body_tree, tvb, offset,
				1, "Law	: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_law, "Unknown"));
			break;
		}
	case 0x01: /* DPI Channel Allocations */
		{
			int i;
			static const value_string str_body[] = {
				{0, "UA Channel UA-TX1   "},
				{1, "UA Channel UA-TX2   "},
				{2, "GCI Channel GCI-TX1 "},
				{3, "GCI Channel GCI-TX2 "},
				{4, "Codec Channel COD-TX"},
				{0, NULL}
			};
			for(i = 0; i < 5; i++) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset,
					1, "%s: %d",
					val_to_str(i, str_body, "Unknown"), tvb_get_guint8(tvb, offset));
				offset++;
				length--;
			}
			break;
		}
	case 0x02: /* Loudspeaker Volume Adjust */
		{
			int i;
			for(i = 1; i < 8; i++) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset,
					1, "Volume Level %d: %d",
					i, tvb_get_guint8(tvb, offset));
				offset++;
				length--;
			}
			break;
		}
	case 0x03: /* Audio Circuit Configuration */
		{
			int i;
			static const value_string str_body[] = {
				{0, "Anti-Distortion Coeff 1(DTH)"},
				{1, "Anti-Distortion Coeff 2(DTR)"},
				{2, "Anti-Distortion Coeff 3(DTF)"},
				{3, "Sidetone Attenuation (STR)  "},
				{4, "Anti-Larsen Coeff 1 (AHP1)  "},
				{5, "Anti-Larsen Coeff 2 (AHP2)  "},
				{6, "Anti-Larsen Coeff 3 (ATH)   "},
				{7, "Anti-Larsen Coeff 4 (ATR)   "},
				{8, "Anti-Larsen Coeff 5 (ATF)   "},
				{9, "Anti-Larsen Coeff 6 (ALM)   "},
				{0, NULL}
			};

			for(i = 0; i < 10; i++) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset,
					1, "%s: %d",
					val_to_str(i, str_body, "Unknown"), tvb_get_guint8(tvb, offset));
				offset++;
				length--;
			}
			break;
		}
	case 0x04: /* Handsfree Parameters */
		{
			static const value_string str_return_loss[] = {
				{0x00, "Return Loss Normal"},
				{0x01, "Return Loss Active"},
				{0, NULL}
			};
			static const value_string str_full_duplex[] = {
				{0x00, "Handsfree Normal"},
				{0x02, "More Full Duplex"},
				{0, NULL}
			};

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s",
				val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_return_loss, "Unknown"));
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s",
				val_to_str((tvb_get_guint8(tvb, offset) & 0x02), str_full_duplex, "Unknown"));
			break;
		}
	case 0x05: /* Loudspeaker Acoustic Parameters */
		{
			int i;
			static const value_string str_body[] = {
				{0, "Group Listening Attenuation Constant                                      "},
				{1, "Handsfree Attenuation Constant                                            "},
				{2, "Handsfree Number Of ms To Stay In Send State Before Going To Another State"},
				{3, "Handsfree Number Of Positions To Shift Right MTx                          "},
				{4, "Handsfree Number Of Positions To Shift Right MRc                          "},
				{5, "Handsfree Idle Transmission Threshold                                     "},
				{6, "Handsfree Low Transmission Threshold                                      "},
				{7, "Handsfree Idle Reception Threshold                                        "},
				{8, "Handsfree Low Reception Threshold                                         "},
				{9, "Handsfree Medium Reception Threshold                                      "},
				{10, "Handsfree High Reception Threshold                                        "},
				{0, NULL}
			};

			for(i = 0; i < 11; i++) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s: %d",
					val_to_str(i, str_body, "Unknown"), tvb_get_guint8(tvb, offset));
				offset++;
				length--;
			}
			break;
		}
	case 0x06: /* Device Configuration */
		{
			static const value_string str_device[] = {
				{0, "Handset Device             "},
				{1, "Headset Device             "},
				{2, "Loudspeaker Device         "},
				{3, "Announce Loudspeaker Device"},
				{4, "Handsfree Device           "},
				{0, NULL}
			};
			static const value_string str_device_values[] = {
				{0x01, " Internal"},
				{0x02, " Rj9 Plug"},
				{0x04, " Jack Plug"},
				{0x08, " Bluetooth Link"},
				{0x10, " USB Link"},
				{0, NULL}
			};
			emem_strbuf_t *strbuf = ep_strbuf_new_label("");
			int j;
			int i = 0;

			while(length > 0) {
				ep_strbuf_truncate(strbuf, 0);
				ep_strbuf_append_printf(strbuf, "%s",
					val_to_str(tvb_get_guint8(tvb, offset) & 0x01, str_device_values, ""));

				for(j = 1; j < 4; j++) {
					ep_strbuf_append_printf(strbuf, "%s",
						val_to_str((tvb_get_guint8(tvb, offset) & (0x01 << j)), str_device_values, ""));
				}
				if(strcmp(strbuf->str, "") <= 0) {
					ep_strbuf_truncate(strbuf, 0);
					ep_strbuf_append(strbuf, " None");
				}

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s:%s",
					val_to_str(i, str_device, "Unknown"), strbuf->str);
				offset++;
				length--;
				i++;
			}
			break;
		}
	default:
		{
			break;
		}
	}
}


/*-----------------------------------------------------------------------------
    AUDIO PADDED PATH - 4Ah (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_audio_padded_path(proto_tree *tree _U_, tvbuff_t *tvb,
			 packet_info *pinfo _U_, guint offset, guint length,
			 guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Emission Padded Level: %d", tvb_get_guint8(tvb, offset));
	offset++;
	length--;
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Reception Padded Level: %d", tvb_get_guint8(tvb, offset));
}


/*-----------------------------------------------------------------------------
    KEY RELEASE ON / OFF - 41h (MESSAGE FROM THE SYSTEM)
    AMPLIFIED HANDSET (BOOST) - 48h (MESSAGE FROM THE SYSTEM)
    LOUDSPEAKER ON / OFF - 4Dh (MESSAGE FROM THE SYSTEM)
    ANNOUNCE ON / OFF - 4Eh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_on_off_level(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		    guint offset, guint length, guint8 opcode _U_,
		    proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_on_off, "On"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_on_off, "On"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_on_off, "On"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_on_off, "On"));
	offset++;
	length--;

	if(length > 0) {
		if(command == 0x01) {
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Level on Loudspeaker: %d dB",
				(signed char)(tvb_get_guint8(tvb, offset)));
		}
	}
}


/*-----------------------------------------------------------------------------
    RING ON / OFF - 4Fh (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_ring(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
	    guint offset, guint length, guint8 opcode _U_,
	    proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;
	static const value_string str_cadence[] = {
		{0x00, "Standard Ringing"},
		{0x01, "Double Burst"},
		{0x02, "Triple Burst"},
		{0x03, "Continuous"},
		{0x04, "Priority Attendant Ringing"},
		{0x05, "Regular Attendant Ringing"},
		{0x06, "Programmable Cadence"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_on_off, "On"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_on_off, "On"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_on_off, "On"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_on_off, "On"));
	offset++;
	length--;

	if(command == 0x01) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Melody: %d", tvb_get_guint8(tvb, offset));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Cadence: %s",
			val_to_str(tvb_get_guint8(tvb, offset), str_cadence, "Unknown"));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Speaker level: %d dB",
			(signed char)(tvb_get_guint8(tvb, offset)));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Beep number: %d", tvb_get_guint8(tvb, offset));
		offset++;
		length--;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Silent: %s",
			val_to_str((tvb_get_guint8(tvb, offset) & 0x80), str_on_off, "On"));
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Progressive: %d",
			(tvb_get_guint8(tvb, offset) & 0x03));
	}
}


/*-----------------------------------------------------------------------------
    UA DOWNLOAD PROTOCOL - 50h - Only for UA NOE (MESSAGE FROM THE TERMINAL AND FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_ua_dwl_protocol(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		       guint offset, guint length, guint8 opcode _U_,
		       proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;
	static const value_string str_command[] = {
		{0x00, "Downloading Suggest"},
		{0x01, "Downloading Request"},
		{0x02, "Downloading Acknowledge"},
		{0x03, "Downloading Data"},
		{0x04, "Downloading End"},
		{0x05, "Downloading End Acknowledge"},
		{0x06, "Downloading ISO Checksum"},
		{0x07, "Downloading ISO Checksum Acknowledge"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_command, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_command, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_command, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb,
		offset, 1, command, "Command	: %s",
		val_to_str(command, str_command, "Unknown"));
	offset++;
	length--;

	switch(command) {
	case 0x00:	/* Downloading Suggest (MESSAGE FROM THE TERMINAL) */
		{
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Item Identifier: %d", tvb_get_guint8(tvb, offset));
			offset++;
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Item Version: %s",
				version_number_computer(tvb_get_letohs(tvb, offset)));
			offset += 2;
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Cause: %d", tvb_get_guint8(tvb, offset));
			break;
		}
	case 0x01:	/* Downloading Request (MESSAGE FROM THE SYSTEM) */
		{
			static const value_string str_force_mode[] = {
				{0x00, "System Accept All Refusals"},
				{0x01, "Force Software Lock"},
				{0, NULL}
			};
			static const value_string str_item_id[] = {
				{0x00, "Patches File"},
				{0x01, "Application Binary"},
				{0x02, "Datas Binary"},
				{0, NULL}
			};
			static const value_string str_mode_selection_country[] = {
				{0x00, "No Check"},
				{0x01, "For All Countries Except Chinese"},
				{0x02, "For Chinese"},
				{0, NULL}
			};
			static const value_string str_mem_size[] = {
				{0x00, "No Check"},
				{0x01, "128 Kbytes"},
				{0x02, "256 Kbytes"},
				{0x03, "512 Kbytes"},
				{0x04, "1 Mbytes"},
				{0x05, "2 Mbytes"},
				{0x06, "4 Mbytes"},
				{0x07, "8 Mbytes"},
				{0, NULL}
			};
			static const value_string str_bin_info[] = {
				{0x00, "Uncompressed Binary"},
				{0x01, "LZO Compressed Binary"},
				{0, NULL}
			};

			if(length > 7) { /* Not R1 */
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Force Mode: %s",
					val_to_str(tvb_get_guint8(tvb, offset), str_force_mode, "Unknown"));
				offset++;
				length--;
			}

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Item Identifier: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_item_id, "Unknown"));
			offset++;
			length--;

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
				"Item Version: %d", tvb_get_ntohs(tvb, offset));
			offset += 2;
			length -= 2;

			if(length > 2) { /* Not R1 */
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Files Included: %s Boot Binary Included, %s Loader Binary Included, %s Appli Binary Included, %s Datas Binary Included",
					val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_yes_no, ""),
					val_to_str((tvb_get_guint8(tvb, offset) & 0x02), str_yes_no, ""),
					val_to_str((tvb_get_guint8(tvb, offset) & 0x04), str_yes_no, ""),
					val_to_str((tvb_get_guint8(tvb, offset) & 0x08), str_yes_no, ""));
				offset++;
				length--;

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Model Selection: For A Model: %s, For B Model: %s, For C Model %s, Country Version: %s",
					val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_yes_no, "Yes"),
					val_to_str((tvb_get_guint8(tvb, offset) & 0x02), str_yes_no, "Yes"),
					val_to_str((tvb_get_guint8(tvb, offset) & 0x04), str_yes_no, "Yes"),
					val_to_str(((tvb_get_guint8(tvb, offset) & 0xE0) >> 5), str_mode_selection_country, "Unknown"));
				offset++;
				length--;

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Hardware Selection: For Ivanoe 1: %s, For Ivanoe 2: %s",
					val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_yes_no, "Yes"),
					val_to_str((tvb_get_guint8(tvb, offset) & 0x02), str_yes_no, "Yes"));
				offset++;
				length--;

				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Memory Sizes Required: Flash Min Size: %s, External Ram Min Size: %s",
					val_to_str((tvb_get_guint8(tvb, offset) & 0x07), str_mem_size, "Unknown"),
					val_to_str(((tvb_get_guint8(tvb, offset) & 0x38) >> 3), str_mem_size, "Unknown"));
				offset++;
				length--;
			} else { /* R1 */
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Binary Information: %s, Country/Operator/CLient Identifier ?",
					val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_bin_info, ""));
				offset++;
				length--;
			}

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 3,
				"Binary Length: %d", tvb_get_ntoh24(tvb, offset));
			break;
		}
	case 0x02:	/* Downloading Acknowledge (MESSAGE FROM THE TERMINAL) */
		{
			static const value_string str_status[] = {
				{0x00, "Ok (Binary Item Downloading In \"Normal\" Progress)"},
				{0x01, "Hardware Failure: Flash Failure"},
				{0x02, "Not Enough Place To Store The Downloaded Binary"},
				{0x03, "Wrong Seq Number On Latest Received Download_Data Message"},
				{0x04, "Wrong Packet Number On Latest Received Download_Data Message"},
				{0x05, "Download Refusal Terminal (Validation Purpose)"},
				{0x06, "Download Refusal Terminal (Development Purpose)"},
				{0x10, "Download Refusal: Hardware Cause (Unknown Flash Device, Incompatible Hardware)"},
				{0x11, "Download Refusal: No Loader Available Into The Terminal"},
				{0x12, "Download Refusal: Software Lock"},
				{0x13, "Download Refusal: Wrong Parameter Into Download Request"},
				{0x20, "Wrong Packet Number On Latest Received Downloading_Data Message"},
				{0x21, "Compress Header Invalid"},
				{0x22, "Decompress Error"},
				{0x23, "Binary Header Invalid"},
				{0x24, "Binary Check Error: Flash Write Error Or Binary Is Invalid"},
				{0x25, "Error Already Signaled - No More Data Accepted"},
				{0x26, "No Downloading In Progress"},
				{0x27, "Too Many Bytes Received (More Than Size Given Into The Download_Req Message)"},
				{0xFF, "Undefined Error"},
				{0, NULL}
			};

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
				"Packet Number: %d", tvb_get_ntohs(tvb, offset));
			offset += 2;

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Status: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_status, "Unknown"));
			break;
		}
	case 0x03:	/* Downloading Data (MESSAGE FROM THE SYSTEM) */
		{
			int i = 1;

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
				"Packet Number: %d", tvb_get_ntohs(tvb, offset));
			offset += 2;
			length -= 2;

			while(length > 0) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Packet Number %3d: %d", i, tvb_get_guint8(tvb, offset));
				offset++;
				length--;
				i++;
			}
			break;
		}
	case 0x05:	/* Downloading End Acknowledge (MESSAGE FROM THE TERMINAL) */
		{
			static const value_string str_ok[] = {
				{0x00, "Ok"},
				{0x01, "Hardware Failure: Flash Problems"},
				{0x02, "Not Enough Place To Store The Downloaded Binary"},
				{0, NULL}
			};

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Status: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_ok, "Not Ok"));
			break;
		}
	case 0x06:	/* Downloading Iso Checksum (MESSAGE FROM THE SYSTEM) */
		{
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 4,
				"Checksum: %d", tvb_get_ntohl(tvb, offset));
			/*Fix Clang Warning*/
			/*offset += 4;*/
			/*length -= 4;*/
			break;
		}
	case 0x07:	/* Downloading ISO Checksum Acknowledge (MESSAGE FROM THE TERMINAL) */
		{
			static const value_string str_ack_status[] = {
				{0x00, "The Checksum Matches"},
				{0x25, "Error Detected And Already Signaled"},
				{0x30, "Checksum Error (All Bytes Received)"},
				{0x31, "Checksum Error (Bytes Missing)"},
				{0, NULL}
			};

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Acknowledge: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_ack_status, "Unknown"));
			break;
		}
	case 0x04:	/* Downloading End (MESSAGE FROM THE SYSTEM) */
	default:
		{
			break;
		}
	}
}


/*-----------------------------------------------------------------------------
    DIGIT DIALED - 03h (MESSAGE FROM THE SYSTEM)
    ---------------------------------------------------------------------------*/
static void
decode_digit_dialed(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		    guint offset, guint length _U_, guint8 opcode _U_,
		    proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	static const value_string str_digit[] = {
		{0, "0"},
		{1, "1"},
		{2, "2"},
		{3, "3"},
		{4, "4"},
		{5, "5"},
		{6, "6"},
		{7, "7"},
		{8, "8"},
		{9, "9"},
		{10, "*"},
		{11, "#"},
		{12, "A"},
		{13, "B"},
		{14, "C"},
		{15, "D"},
		{16, "Flash"},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Digit Value: %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_digit, "Unknown"));
}


/*-----------------------------------------------------------------------------
    SUBDEVICE_MSG - 04h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_subdevice_msg(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		     guint offset, guint length, guint8 opcode _U_,
		     proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int i = 0;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Subdev Type: %d", (tvb_get_guint8(tvb, offset) & 0xF0));
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Subdev Address: %d", (tvb_get_guint8(tvb, offset) & 0x0F));
	offset++;
	length--;

	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
		"Subdevice Opcode: %d", (tvb_get_guint8(tvb, offset) & 0x7F));
	offset++;
	length--;

	while(length > 0) {
		i++;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Parameter Byte %2d: %d", i, tvb_get_guint8(tvb, offset));
		offset++;
		length--;
	}
}


/*-----------------------------------------------------------------------------
    IP DEVICE ROUTING - 13h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_cs_ip_device_routing(proto_tree *tree _U_, tvbuff_t *tvb,
			    packet_info *pinfo, guint offset, guint length,
			    guint8 opcode _U_, proto_item *ua3g_item,
			    proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	gint *lengthp = 0;
	proto_tree *ua3g_body_tree;
	proto_item *ua3g_param_item;
	proto_tree *ua3g_param_tree;
	emem_strbuf_t *strbuf = ep_strbuf_new_label("");
	static const value_string str_command[] = {
		{0x00, "Init"},
		{0x01, "Incident"},
		{0x02, "Get Parameters Value Response"},
		{0x03, "QOS Ticket RSP"},
		{0, NULL}
	};

	/* add text to the frame tree */
	proto_item_append_text(ua3g_item, ", %s",
		val_to_str(command, str_command, "Unknown"));
	proto_item_append_text(ua3g_body_item, " - %s",
		val_to_str(command, str_command, "Unknown"));
	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	/* add text to the frame "INFO" column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
			val_to_str(command, str_command, "Unknown"));

	proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_ip, tvb, offset,
		1, command, "Command: %s",
		val_to_str(command, str_command, "Unknown"));
	offset++;
	length--;

	switch(command) {
		case 0x00:
			{
				static const value_string str_vta_type[] = {
					{0x20, "NOE A"},
					{0x21, "NOE B"},
					{0x22, "NOE C"},
					{0x23, "NOE D"},
					{0, NULL}
				};
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "VTA Type: %s",
					val_to_str(tvb_get_guint8(tvb, offset), str_vta_type, "Unknown"));
				offset++;
				length--;

				proto_tree_add_text(ua3g_body_tree, tvb, offset,
					1, "Characteristic Number: %d", tvb_get_guint8(tvb, offset));
				break;
			}
		case 0x01:
			{
				int i=0;
				if(length == 1) {
					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
						"Incident 0: %d", tvb_get_guint8(tvb, offset));
				} else {
					while(length >0) {
						i++;
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
							"Parameter %d Identifier: %d",
							i, tvb_get_guint8(tvb, offset));
						offset++;
						length--;
					}
				}
				break;
			}
		case 0x02:
			{
				int i, parameter_id, parameter_length;
				static const value_string str_parameter_id[] = {
					{0x00, "Firmware Version"},
					{0x01, "Firmware Version"},
					{0x02, "DHCP IP Address"},
					{0x03, "Local IP Address"},
					{0x04, "Subnetwork Mask"},
					{0x05, "Router IP Address"},
					{0x06, "TFTP IP Address"},
					{0x07, "Main CPU Address"},
					{0x08, "Default Codec"},
					{0x09, "Ethernet Drivers Config"},
					{0x0A, "MAC Address"},
					{0, NULL}
				};

				while(length > 0) {
					parameter_id = tvb_get_guint8(tvb, offset);
					parameter_length = tvb_get_guint8(tvb, offset + 1);

					if(parameter_length > 0) {
						switch(parameter_id) {
						case 0x00: /* Firmware Version */
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%s",
									version_number_computer(tvb_get_ntohs(tvb, offset + 2)));
								break;
							}
						case 0x01: /* Firmware Version */
						case 0x02: /* DHCP IP Address */
						case 0x03: /* Local IP Address */
						case 0x04: /* Subnetwork Mask */
						case 0x05: /* Router IP Address */
						case 0x06: /* TFTP IP Address */
						case 0x07: /* Main CPU Address */
							{
								if(parameter_length > 0) {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf, "%d", tvb_get_guint8(tvb, offset + 2));
								}

								for(i = 2; i <= parameter_length; i++) {
									ep_strbuf_append(strbuf, ".");
									ep_strbuf_append_printf(strbuf, "%u", tvb_get_guint8(tvb, offset+1+i));
								}
								break;
							}
						case 0x08: /* Default Codec */
							{
								static const value_string str_compressor[] = {
									{0x00, "G.711 A-law"},
									{0x01, "G.711 mu-law"},
									{0x0F, "G.723.1 5.3kbps"},
									{0x10, "G.723.1 6.3kbps"},
									{0x11, "G.729A 8 kbps"},
									{0, NULL}
								};

								if((parameter_length > 0) && (parameter_length <= 8)) {
									guint64 param_value = 0;

									for(i = parameter_length; i > 0; i--) {
										param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
									}
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append(strbuf,
										val_to_str((guint8)(param_value), str_compressor, "Default Codec"));
								} else {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
										tvb_get_guint8(tvb, offset + 2),
										tvb_get_guint8(tvb, offset + 3),
										tvb_get_guint8(tvb, offset + parameter_length),
										tvb_get_guint8(tvb, offset + 1 + parameter_length));
								}
								break;
							}
						case 0x09: /* Ethernet Drivers Config */
							{
								if(parameter_length == 2) {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf,
										"Port Lan Speed: %d - Port Lan Duplex: %d",
										tvb_get_guint8(tvb, offset + 2),
										tvb_get_guint8(tvb, offset + 3));
								} else if(parameter_length == 4) {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf,
										"Port Lan Speed: %d - Port Lan Duplex: %d - Port PC Speed: %d - Port PC Duplex: %d",
										tvb_get_guint8(tvb, offset + 2),
										tvb_get_guint8(tvb, offset + 3),
										tvb_get_guint8(tvb, offset + 4),
										tvb_get_guint8(tvb, offset + 5));
								} else {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
										tvb_get_guint8(tvb, offset + 2),
										tvb_get_guint8(tvb, offset + 3),
										tvb_get_guint8(tvb, offset + parameter_length),
										tvb_get_guint8(tvb, offset + 1 + parameter_length));
								}
								break;
							}
						case 0x0A: /* MAC Address */
							{
								if(parameter_length > 0) {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf, "%02x", tvb_get_guint8(tvb, offset + 2));
								}

								for(i = 2; i <= parameter_length; i++) {
									ep_strbuf_append(strbuf, ":");
									ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+1+i, lengthp));
								}
								break;
							}
						default:
							{
								if((parameter_length > 0) && (parameter_length <= 8)) {
									guint64 param_value = 0;

									for(i = parameter_length; i > 0; i--) {
										param_value += (tvb_get_guint8(tvb, offset + 1 + i) << (8 * (parameter_length - i)));
									}
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
								} else {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append_printf(strbuf, "0x%02x 0x%02x ... 0x%02x 0x%02x",
										tvb_get_guint8(tvb, offset + 2),
										tvb_get_guint8(tvb, offset + 3),
										tvb_get_guint8(tvb, offset + parameter_length),
										tvb_get_guint8(tvb, offset + 1 + parameter_length));
								}
							}
							break;
						}

						ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
							parameter_length + 2, "%s: %s",
							val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
					} else
						ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
							parameter_length + 2, "%s",
							val_to_str(parameter_id, str_parameter_id, "Unknown"));

					ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);
					proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Parameter: %s (0x%02x)",
						val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
					offset++;
					length--;

					proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
						"Length: %d", parameter_length);
					offset++;
					length--;

					if(parameter_length > 0) {
						proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
							"Value: %s", strbuf->str);
						offset += parameter_length;
						length -= parameter_length;
					}
				}
				break;
			}
		case 0x03:
			{
				int i, parameter_id, parameter_length;
				int element_length = 1;
				int framing_rtp = 0;
				char parameter_value_tab[15][50];
				static const value_string str_parameter_id[] = {
					{0x01, "Date Of End Of Communication"},
					{0x02, "Node Number"},
					{0x03, "Ticket Protocol Version"},
					{0x06, "Equiment Type"},
					{0x08, "Local IP Address"},
					{0x09, "Distant IP Address"},
					{0x0A, "Local ID"},
					{0x0B, "Distant ID"},
					{0x0C, "Call Duration (second)"},
					{0x0D, "Local SSRC"},
					{0x0E, "Distant SSRC"},
					{0x0F, "Codec"},
					{0x10, "VAD"},
					{0x11, "ECE"},
					{0x12, "Voice Mode"},
					{0x13, "Transmitted Framing (ms)"},
					{0x14, "Received Framing (ms)"},
					{0x15, "Framing Changes"},
					{0x16, "Number Of RTP Packets Received"},
					{0x17, "Number Of RTP Packets Sent"},
					{0x18, "Number Of RTP Packets Lost"},
					{0x19, "Total Silence Detected (second)"},
					{0x1A, "Number Of SID Received"},
					{0x1B, "Delay Distribution"},
					{0x1C, "Maximum Delay (ms)"},
					{0x1D, "Number Of DTMF Received"},
					{0x1E, "Consecutive BFI"},
					{0x1F, "BFI Distribution"},
					{0x20, "Jitter Depth Distribution"},
					{0x21, "Number Of ICMP Host Unreachable"},
					{0x26, "Firmware Version"},
					{0x29, "DSP Framing (ms)"},
					{0x2A, "Transmitter SID"},
					{0x2D, "Minimum Delay (ms)"},
					{0x2E, "802.1 Q Used"},
					{0x2F, "802.1p Priority"},
					{0x30, "VLAN Id"},
					{0x31, "DiffServ"},
					{0x3D, "200 ms BFI Distribution"},
					{0x3E, "Consecutive RTP Lost"},
					{0, NULL}
				};
				static const value_string str_parameter_id_tab[] = {
					{0x1B, "Range: Value"},
					{0x1F, "Range: Value"},
					{0x20, "Jitter: Value"},
					{0x3D, "Contents: Value"},
					{0x3E, "Contents: Value"},
					{0, NULL}
				};

				while(length > 0) {
					parameter_id = tvb_get_guint8(tvb, offset);
					parameter_length = tvb_get_ntohs(tvb, offset + 1);

					if(parameter_length > 0) {
						switch(parameter_id) {
						case 0x06: /* Type Of Equipment */
							{
								static const value_string str_first_byte[] = {
									{0x01, "IP-Phone"},
									{0x02, "Appli-PC"},
									{0x03, "Coupler OmniPCX Enterprise"},
									{0x04, "Coupler OmniPCX Office"},
									{0, NULL}
								};
								static const value_string str_second_byte[] = {
									{0x0101, "IP-Phone V2"},
									{0x0102, "NOE-IP"},
									{0x0200, "4980 Softphone (PCMM2)"},
									{0x0201, "WebSoftphoneIP"},
									{0x0300, "INTIP"},
									{0x0301, "GD"},
									{0x0302, "eVA"},
									{0, NULL}
								};
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%s, %s",
									val_to_str(tvb_get_guint8(tvb, offset + 3), str_first_byte, "Unknown"),
									val_to_str(tvb_get_ntohs(tvb, offset + 3), str_second_byte, "Unknown"));
								break;
							}
						case 0x08: /* Local IP Address */
						case 0x09: /* Distant IP Address */
						case 0x26: /* Firmware Version */
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", tvb_get_guint8(tvb, offset + 3));
								for(i = 2; i <= parameter_length; i++) {
									ep_strbuf_append(strbuf, ".");
									ep_strbuf_append_printf(strbuf, "%u", tvb_get_guint8(tvb, offset+2+i));
								}
								break;
							}
						case 0x0A:
						case 0x0B:
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append(strbuf, "\"");
								for(i = 1; i <= parameter_length; i++) {
									if(isprint(tvb_get_guint8(tvb, offset + 2 + i)))
										ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+2+i, lengthp));
									else
										ep_strbuf_append(strbuf, tvb_get_const_stringz(tvb, offset+2+i, lengthp));
								}
								ep_strbuf_append(strbuf, "\"");
								break;
							}
						case 0x0F: /* Default Codec */
							{
								static const value_string str_compressor[] = {
									{0x00, "G.711 A-law"},
									{0x01, "G.711 mu-law"},
									{0x02, "G.723.1 6.3kbps"},
									{0x03, "G.729"},
									{0x04, "G.723.1 5.3kbps"},
									{0, NULL}
								};

								if((parameter_length > 0) && (parameter_length <= 8)) {
									guint64 param_value = 0;

									for(i = parameter_length; i > 0; i--) {
										param_value += (tvb_get_guint8(tvb, offset + 2 + i) << (8 * (parameter_length - i)));
									}
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append(strbuf,
										val_to_str((guint8)(param_value), str_compressor, "Default Codec"));
								} else {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append(strbuf, "Parameter Value Too Long (more than 64 bits)");
								}

								break;
							}
						case 0x10: /* VAD */
						case 0x11: /* ECE */
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%s",
									val_to_str(tvb_get_guint8(tvb, offset + 3), str_on_off, "On"));
								break;
							}
						case 0x12: /* Voice Mode */
							{
								static const value_string str_voice_mode[] = {
									{0x50, "Idle"},
									{0x51, "Handset"},
									{0x52, "Group Listening"},
									{0x53, "On Hook Dial"},
									{0x54, "Handsfree"},
									{0x55, "Headset"},
									{0, NULL}
								};

								if((parameter_length > 0) && (parameter_length <= 8)) {
									guint64 param_value = 0;

									for(i = parameter_length; i > 0; i--) {
										param_value += (tvb_get_guint8(tvb, offset + 2 + i) << (8 * (parameter_length - i)));
									}
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append(strbuf,
										val_to_str((guint8)(param_value), str_voice_mode, "Unknown"));
								} else {
									ep_strbuf_truncate(strbuf, 0);
									ep_strbuf_append(strbuf, "Parameter Value Too Long (more than 64 bits)");
								}

								break;
							}
						case 0x1B: /* Delay Distribution */
							{
								static const value_string str_range[] = {
									{0, "0-40     "},
									{1, "40-80    "},
									{2, "80-150   "},
									{3, "150-250  "},
									{4, "250 and +"},
									{0, NULL}
								};
								element_length = 2;
								for(i = 0; i < (parameter_length / element_length); i++) {
									g_snprintf(parameter_value_tab[i], 50, "%s: %d",
										val_to_str(i, str_range, "Unknown"),
										tvb_get_ntohs(tvb, offset + 3 + element_length * i));
								}
								break;
							}
						case 0x1E: /* Consecutive BFI */
							{
								static const value_string str_range[] = {
									{0, "0"},
									{1, "1"},
									{2, "2"},
									{3, "3"},
									{4, "4"},
									{5, "5"},
									{6, "5"},
									{7, "7"},
									{8, "8"},
									{9, "9"},
									{0, NULL}
								};
								element_length = 2;
								for(i = 0; i < (parameter_length / element_length); i++) {
									g_snprintf(parameter_value_tab[i], 50, "%s: %d",
										val_to_str(i, str_range, "Unknown"),
										tvb_get_ntohs(tvb, offset + 3 + element_length * i));
								}
								break;
							}
						case 0x1F: /* BFI Distribution */
							{
								static const value_string str_range[] = {
									{0, "0      "},
									{1, "0-1    "},
									{2, "1-2    "},
									{3, "2-3    "},
									{4, "3 and +"},
									{0, NULL}
								};
								element_length = 2;
								for(i = 0; i < (parameter_length / element_length); i++) {
									g_snprintf(parameter_value_tab[i], 50, "%s: %d",
										val_to_str(i, str_range, "Unknown"),
										tvb_get_ntohs(tvb, offset + 3 + element_length * i));
								}
								break;
							}
						case 0x20: /* Jitter Depth Distribution */
							{
								element_length = 4;
								for(i = 0; i < (parameter_length / element_length); i++) {
									g_snprintf(parameter_value_tab[i], 50, "+/- %3d ms: %d",
										((2 * i) + 1) * framing_rtp / 2,
										tvb_get_ntohl(tvb, offset + 3 + 4 * i));
								}
								break;
							}
						case 0x2E: /* 802.1 Q Used */
							{
								static const value_string str_bool[] = {
									{0x00, "False"},
									{0, NULL}
								};
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%s", val_to_str(tvb_get_guint8(tvb, offset + 3), str_bool, "True"));
								break;
							}
						case 0x2F: /* 802.1p Priority */
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", (tvb_get_guint8(tvb, offset + 3) & 0x07));
								break;
							}
						case 0x30: /* VLAN Id */
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d", (tvb_get_ntohs(tvb, offset + 3) & 0x0FFF));
								break;
							}
						case 0x31: /* DiffServ */
							{
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%d (%d)", tvb_get_guint8(tvb, offset + 3),
									tvb_get_guint8(tvb, offset + 3)>>2);
								break;
							}
						case 0x3D: /* 200 ms BFI Distribution */
							{
								static const value_string str_range[] = {
									{0, "< 10 %  "},
									{1, "< 20 %  "},
									{2, "< 40 %  "},
									{3, "< 60 %  "},
									{4, ">= 60 % "},
									{0, NULL}
								};
								element_length = 2;
								for(i = 0; i < (parameter_length / element_length); i++) {
									g_snprintf(parameter_value_tab[i], 50, "%s: %d",
										val_to_str(i, str_range, "Unknown"),
										tvb_get_ntohs(tvb, offset + 3 + element_length * i));
								}
								break;
							}
						case 0x3E: /* Consecutive RTP Lost */
							{
								static const value_string str_range[] = {
									{0, "1         "},
									{1, "2         "},
									{2, "3         "},
									{3, "4         "},
									{4, "5 and more"},
									{0, NULL}
								};
								element_length = 2;
								for(i = 0; i < (parameter_length / element_length); i++) {
									g_snprintf(parameter_value_tab[i], 50, "%s: %d",
										val_to_str(i, str_range, "Unknown"),
										tvb_get_ntohs(tvb, offset + 3 + element_length * i));
								}
								break;
							}
						case 0x14: /* Received Framing (ms) */
							{
								framing_rtp = tvb_get_guint8(tvb, offset + 3);
							}
						case 0x01: /* Date Of End Of Communication */
						case 0x02: /* Node Number */
						case 0x03: /* Ticket Protocol Version */
						case 0x0C: /* Call Duration (second) */
						case 0x0D: /* Local SSRC */
						case 0x0E: /* Distant SSRC */
						case 0x13: /* Transmitted Framing (ms) */
						case 0x15: /* Framing Changes */
						case 0x16: /* Number Of RTP Packets Received */
						case 0x17: /* Number Of RTP Packets Sent */
						case 0x18: /* Number Of RTP Packets Lost */
						case 0x19: /* Total Silence Detected (second) */
						case 0x1A: /* Number Of SID Received */
						case 0x1C: /* Maximum Delay (ms) */
						case 0x1D: /* Number Of DTMF Received */
						case 0x21: /* Number Of ICMP Host Unreachable */
						case 0x29: /* DSP Framing (ms) */
						case 0x2A: /* Transmitter SID */
						case 0x2D: /* Minimum Delay (ms) */
						default:
							{
								guint64 param_value = 0;

								for(i = parameter_length; i > 0; i--) {
									param_value += (tvb_get_guint8(tvb, offset + 2 + i) << (8 * (parameter_length - i)));
								}
								ep_strbuf_truncate(strbuf, 0);
								ep_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", param_value);
								break;
							}
						}
					}

					switch(parameter_id)
					{
					/* Case of values in table */
					case 0x1B:
					case 0x1E:
					case 0x1F:
					case 0x20:
					case 0x3D:
					case 0x3E:
						{
							ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
								parameter_length + 3, "%s:",
								val_to_str(parameter_id, str_parameter_id, "Unknown"));
							proto_tree_add_text(ua3g_body_tree, tvb, offset + 3,
								parameter_length, "          %s",
								val_to_str(parameter_id, str_parameter_id_tab, "Unknown"));
							ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

							proto_tree_add_text(ua3g_param_tree, tvb, offset, 1,
								"Parameter: %s (0x%02x)",
								val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
							offset++;
							length--;

							proto_tree_add_text(ua3g_param_tree, tvb, offset, 2,
								"Length: %d", parameter_length);
							offset += 2;
							length -= 2;

							for(i = 0; i < (parameter_length / element_length); i++) {
								proto_tree_add_text(ua3g_body_tree, tvb, offset,
									element_length, "          %s", parameter_value_tab[i]);
								offset += element_length;
								length -= element_length;
							}
							break;
						}
					default:
						{
							if(parameter_length > 0)
								ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
									parameter_length + 3, "%s: %s",
									val_to_str(parameter_id, str_parameter_id, "Unknown"), strbuf->str);
							else
								ua3g_param_item = proto_tree_add_text(ua3g_body_tree, tvb, offset,
									parameter_length + 3, "%s",
									val_to_str(parameter_id, str_parameter_id, "Unknown"));

							ua3g_param_tree = proto_item_add_subtree(ua3g_param_item, ett_ua3g_param);

							proto_tree_add_text(ua3g_param_tree, tvb, offset, 1, "Parameter: %s (0x%02x)",
								val_to_str(parameter_id, str_parameter_id, "Unknown"), parameter_id);
							offset++;
							length--;

							proto_tree_add_text(ua3g_param_tree, tvb, offset, 2, "Length: %d", parameter_length);
							offset += 2;
							length -= 2;

							if(parameter_length > 0) {
								proto_tree_add_text(ua3g_param_tree, tvb, offset, parameter_length,
									"Value: %s", strbuf->str);
								offset += parameter_length;
								length -= parameter_length;
							}
							break;
						}
					}

				}
				break;
			}
		default:
		{
			break;
		}
	}
}


/*-----------------------------------------------------------------------------
    UNSOLICITED MESSAGE - 9Fh/1Fh (MESSAGE FROM THE TERMINAL)
    VERSION RESPONSE - 21h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_unsolicited_msg(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo,
		       guint offset, guint length, guint8 opcode,
		       proto_item *ua3g_item, proto_item *ua3g_body_item)
{
	guint8 command = tvb_get_guint8(tvb, offset);
	proto_tree *ua3g_body_tree;
	static const value_string str_command[] = {
		{0x00, "Hardware Reset Acknowledge"},
		{0x01, "Software Reset Acknowledge"},
		{0x02, "Illegal Command Received"},
		{0x05, "Subdevice Down"},
		{0x06, "Segment Failure"},
		{0x07, "UA Device Event"},
		{0, NULL}
	};

	if(opcode != 0x21) {
		/* add text to the frame tree */
		proto_item_append_text(ua3g_item, ", %s",
			val_to_str(command, str_command, "Unknown"));
		proto_item_append_text(ua3g_body_item, " - %s",
			val_to_str(command, str_command, "Unknown"));
		ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

		/* add text to the frame "INFO" column */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
				val_to_str(command, str_command, "Unknown"));

		proto_tree_add_uint_format(ua3g_body_tree, hf_ua3g_command, tvb,
			offset, 1, command, "Command: %s",
			val_to_str(command, str_command, "Unknown"));
		offset++;
		length--;
	} else {
		ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
		command = 0xFF; /* Opcode = 0x21 */
	}

	switch(command)
	{
	case 0x00: /* Hardware Reset Acknowledge */
	case 0x01: /* Software Reset Acknowledge */
	case 0xFF: /* Opcode = 0x21 : Version Response */
		{
			int link, vta_type;
			static const value_string str_vta_type[] = {
				{0x03, "4035"},
				{0x04, "4020"},
				{0x05, "4010"},
				{0x20, "NOE A"},
				{0x21, "NOE B"},
				{0x22, "NOE C"},
				{0x23, "NOE D"},
				{0, NULL}
			};
			static const value_string str_other_info_1[] = {
				{0x00, "Link Is TDM"},
				{0x01, "Link Is IP"},
				{0, NULL}
			};
			static const value_string str_other_info_2[] = {
				{0x00, "Download Allowed"},
				{0x01, "Download Refused"},
				{0, NULL}
			};
			static const value_string str_hard_config_ip[] = {
				{0x00, "Export Binary (No Thales)"},
				{0x01, "Full Binary (Thales)"},
				{0, NULL}
			};
			static const value_string str_hard_config_chip[] = {
				{0x00, "Chip Id: Unknown"},
				{0x01, "Chip Id: Ivanoe 1"},
				{0x02, "Chip Id: Ivanoe 2"},
				{0x03, "Chip Id: Reserved"},
				{0, NULL}
			};
			static const value_string str_hard_config_flash[] = {
				{0x00, "Flash Size: No Flash"},
				{0x01, "Flash Size: 128 Kbytes"},
				{0x02, "Flash Size: 256 Kbytes"},
				{0x03, "Flash Size: 512 Kbytes"},
				{0x04, "Flash Size: 1 Mbytes"},
				{0x05, "Flash Size: 2 Mbytes"},
				{0x06, "Flash Size: 4 Mbytes"},
				{0x07, "Flash Size: 8 Mbytes"},
				{0, NULL}
			};
			static const value_string str_hard_config_ram[] = {
				{0x00, "External RAM Size: No External RAM"},
				{0x01, "External RAM Size: 128 Kbytes"},
				{0x02, "External RAM Size: 256 Kbytes"},
				{0x03, "External RAM Size: 512 Kbytes"},
				{0x04, "External RAM Size: 1 Mbytes"},
				{0x05, "External RAM Size: 2 Mbytes"},
				{0x06, "External RAM Size: 4 Mbytes"},
				{0x07, "External RAM Size: 8 Mbytes"},
				{0, NULL}
			};

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Device Type: %s",
				val_to_str(tvb_get_guint8(tvb, offset), str_device_type, "Unknown"));
			offset++;
			length--;

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 2, "Firmware Version: %s",
				version_number_computer(tvb_get_ntohs(tvb, offset)));
			offset += 2;
			length -= 2;

			if(opcode != 0x21) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Self-Test Result: %d", tvb_get_guint8(tvb, offset));
				offset++;
				length--;
			}

			vta_type = tvb_get_guint8(tvb, offset);

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "VTA Type: %s",
				val_to_str(vta_type, str_vta_type, "Unknown"));
			offset++;
			length--;

			switch(vta_type)
			{
			case 0x03:
			case 0x04:
			case 0x05:
				{
					static const value_string str_subtype[] = {
						{0x03, "2x40"},
						{0x04, "1x20"},
						{0x05, "1x20"},
						{0, NULL}
					};
					static const value_string str_generation[] = {
						{0x02, "3"},
						{0, NULL}
					};
					static const value_string str_design[] = {
						{0x00, "Alpha"},
						{0, NULL}
					};
					static const value_string str_hard_vta_type[] = {
						{0x03, "MR2 (4035)"},
						{0x05, "VLE (4010)"},
						{0x07, "LE (4020)"},
						{0, NULL}
					};
					static const value_string str_hard_design[] = {
						{0x06, "Alpha"},
						{0, NULL}
					};
					static const value_string str_hard_subtype[] = {
						{0x06, "2x40"},
						{0x07, "1x20"},
						{0x08, "1x20"},
						{0, NULL}
					};

					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
						"Characteristic Number: VTA SubType: %s, Generation: %s, Design: %s",
						val_to_str((((tvb_get_guint8(tvb, offset) & 0xC0) >> 6) + vta_type), str_subtype, "Unknown"),
						val_to_str(((tvb_get_guint8(tvb, offset) & 0x38) >> 3), str_generation, "Unknown"),
						val_to_str((tvb_get_guint8(tvb, offset) & 0x07), str_design, "Unknown"));
					offset++;
					length--;
					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
						"Other Information: %s",
						val_to_str(tvb_get_guint8(tvb, offset), str_other_info_2, "Unknown"));
					offset++;
					length--;

					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
						"Hardware Configuration: VTA Type: %s, Design: %s, VTA SubType: %s",
						val_to_str((((tvb_get_guint8(tvb, offset) & 0xE0) >> 5) + vta_type), str_hard_vta_type, "Unknown"),
						val_to_str(((tvb_get_guint8(tvb, offset) & 0x1C) >> 2), str_hard_design, "Unknown"),
						val_to_str((tvb_get_guint8(tvb, offset) & 0x03), str_hard_subtype, "Unknown"));
					offset++;
					length--;

					if(opcode != 0x21) {
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
							"Hook Status/BCM Version: %s Hook",
							val_to_str(tvb_get_guint8(tvb, offset), str_on_off, "On"));
						offset++;
						length--;

					}
					break;
				}
			case 0x20:
			case 0x21:
			case 0x22:
			case 0x23:
			default:
				{
					link = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
						"Other Information 1: %s",
						val_to_str(link, str_other_info_1, "Unknown"));
					offset++;
					length--;

					if(link == 0x00) {
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
							"Hardware Version: %d", tvb_get_guint8(tvb, offset));
						offset++;
						length--;

						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
							"Hardware Configuration: %s, %s, %s",
							val_to_str((tvb_get_guint8(tvb, offset) & 0x03), str_hard_config_chip, "Unknown"),
							val_to_str(((tvb_get_guint8(tvb, offset) & 0x1C) >> 2), str_hard_config_flash, "Unknown"),
							val_to_str(((tvb_get_guint8(tvb, offset) & 0xE0) >> 5), str_hard_config_ram, "Unknown"));
						offset++;
						length--;
					} else {
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Other Information 2: %s",
							val_to_str(tvb_get_guint8(tvb, offset), str_other_info_2, "Unknown"));
						offset++;
						length--;

						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Hardware Configuration: %s",
							val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_hard_config_ip, "Unknown"));
						offset++;
						length--;
					}

					if(opcode != 0x21) {
						proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Hook Status: %s Hook",
							val_to_str(tvb_get_guint8(tvb, offset), str_on_off, "On"));
						offset++;
						length--;

						if(length > 0) {
							if(link == 0x00) {
								proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
									"Firmware Datas Patch Version: %s",
									version_number_computer(tvb_get_ntohs(tvb, offset)));
								offset += 2;
								length -= 2;

								if(length > 0) {
									proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
										"Firmware Version (Loader): %s",
										version_number_computer(tvb_get_ntohs(tvb, offset)));
								}
							} else {
								proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
									"Datas Version: %s",
									version_number_computer(tvb_get_ntohs(tvb, offset)));
								offset += 2;
								length -= 2;

								if(length > 0) {
									proto_tree_add_text(ua3g_body_tree, tvb, offset, 2,
										"Firmware Version (Bootloader): %s",
										version_number_computer(tvb_get_ntohs(tvb, offset)));
								}
							}
						}
					}
					break;
				}
			}
			break;
		}
	case 0x02: /* Illegal Command Received */
		{
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Opcode Of Bad  Command: %d", tvb_get_guint8(tvb, offset));
			offset++;
			length--;

			while(length >0) {
				proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
					"Next Byte Of Bad Command: %d", tvb_get_guint8(tvb, offset));
				offset++;
				length--;
			}
			break;
		}
	case 0x05: /* Subdevice Down */
		{
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Subdevice Address: %d", tvb_get_guint8(tvb, offset));
			break;
		}
	case 0x06: /* Segment Failure */
		{
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "T: %d",
				(tvb_get_guint8(tvb, offset) & 0x01));
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Num: %d",
				(tvb_get_guint8(tvb, offset) & 0x02));
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "/S: %d",
				(tvb_get_guint8(tvb, offset) & 0x04));
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "L: %d",
				(tvb_get_guint8(tvb, offset) & 0x08));
			offset++;

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Opcode Bad Segment: %d", tvb_get_guint8(tvb, offset));
			offset++;

			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Next Byte Of Bad Segment: %d",
				tvb_get_guint8(tvb, offset));
			break;
		}
	case 0x07: /* UA Device Event */
		{
			proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
				"Device Event: %d", tvb_get_guint8(tvb, offset));
			break;
		}
	default:
		{
			break;
		}
	}
}


/*-----------------------------------------------------------------------------
    NON-DIGIT KEY PUSHED - 20h (MESSAGE FROM THE TERMINAL)
    DIGIT KEY RELEASED - 26h (MESSAGE FROM THE TERMINAL)
    KEY RELEASED - 2Ah (MESSAGE FROM THE TERMINAL)
    TM KEY PUSHED - 2Dh (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_key_number(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
		  guint offset, guint length, guint8 opcode _U_,
		  proto_item *ua3g_body_item _U_)
{
/*    proto_tree *ua3g_body_tree;*/
/*
	static const value_string str_first_parameter[] = {
		{0x01, "Production Test Command"},
		{0x06, "Reserved For Compatibility"},
		{0x3B, "Volmue"},
		{0x42, "Subdevice Address"},
		{0, NULL}
	};
*/
	if(length > 0) {
/*		ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);*/
		proto_tree_add_text(tree, tvb, offset, length,
			"Key Number: Row %d, Column %d",
			(tvb_get_guint8(tvb, offset) & 0xF0), (tvb_get_guint8(tvb, offset) & 0x0F));
	}
}


/*-----------------------------------------------------------------------------
    I'M HERE - 22h - Only for UA NOE (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_i_m_here(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		guint offset, guint length _U_, guint8 opcode _U_,
		proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "Id Code: %s",
		val_to_str(tvb_get_guint8(tvb, offset), str_device_type, "Unknown"));
}


/*-----------------------------------------------------------------------------
    RESPONSE STATUS INQUIRY - 23h (MESSAGE FROM THE TERMINAL)
    SPECIAL KEY STATUS - 29h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_special_key(proto_tree *tree _U_, tvbuff_t *tvb, packet_info *pinfo _U_,
		   guint offset, guint length, guint8 opcode,
		   proto_item *ua3g_body_item)
{
/*	guint8 command = tvb_get_guint8(tvb, offset);*/
	proto_tree *ua3g_body_tree;
	int i;
	static const value_string str_parameters[] = {
		{0x00, "Not Received Default In Effect"},
		{0x02, "Downloaded Values In Effect"},
		{0, NULL}
	};
	static const value_string str_special_key_status[] = {
		{0x00, "Released"},
		{0, NULL}
	};
	static const value_string str_special_key[] = {
		{0, "Shift "},
		{1, "Ctrl  "},
		{2, "Alt   "},
		{3, "Cmd   "},
		{4, "Shift'"},
		{5, "Ctrl' "},
		{6, "Alt'  "},
		{7, "Cmd'  "},
		{0, NULL}
	};

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);
	if(opcode == 0x23) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Parameters Received for DTMF: %s",
			val_to_str((tvb_get_guint8(tvb, offset) & 0x02), str_parameters, "Unknown"));
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Hookswitch Status: %shook",
			val_to_str((tvb_get_guint8(tvb, offset) & 0x01), str_on_off, "On"));
		offset++;
		length--;
	}

	for(i = 0; i < 8; i++) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1, "%s: %s",
			val_to_str(i, str_special_key, "Unknown"),
			val_to_str((tvb_get_guint8(tvb, offset) & (0x01 << i)),
			str_special_key_status, "Pressed"));
	}
}


/*-----------------------------------------------------------------------------
    SUBDEVICE STATE ENQUIRY - 24h (MESSAGE FROM THE TERMINAL)
    ---------------------------------------------------------------------------*/
static void
decode_subdevice_state(proto_tree *tree _U_, tvbuff_t *tvb,
		       packet_info *pinfo _U_, guint offset, guint length _U_,
		       guint8 opcode _U_, proto_item *ua3g_body_item)
{
	proto_tree *ua3g_body_tree;
	int i;

	ua3g_body_tree = proto_item_add_subtree(ua3g_body_item, ett_ua3g_body);

	for(i = 0; i <= 7; i++) {
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Subdevice %d State: %d",
			i, (tvb_get_guint8(tvb, offset) & 0x0F));
		i++;
		proto_tree_add_text(ua3g_body_tree, tvb, offset, 1,
			"Subdevice %d State: %d",
			i, ((tvb_get_guint8(tvb, offset) & 0xF0) >> 4));
		offset++;
	}
}


/*-----------------------------------------------------------------------------
    UA3G DISSECTOR
    ---------------------------------------------------------------------------*/
static void
dissect_ua3g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ua3g_item = NULL;
	proto_tree *ua3g_tree = NULL;
	proto_item *ua3g_body_item = NULL;
	gint length = 0;
	gint offset = 0;
	guint8 opcode = 0x00;

	if(tree) {
		ua3g_item = proto_tree_add_item(tree, proto_ua3g, tvb, 0, -1, ENC_NA);
		ua3g_tree = proto_item_add_subtree(ua3g_item, ett_ua3g);

		if(message_direction == SYS_TO_TERM) {
			opcodes_vals = opcodes_vals_sys;
		} else
			opcodes_vals = opcodes_vals_term;

		/* Length of the UA Message */
		length = tvb_get_letohs(tvb, offset);

		/* add text to the frame "INFO" column */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " - UA3G Message:");

		proto_tree_add_uint(ua3g_tree, hf_ua3g_length, tvb, offset, 2, length);
		offset += 2;

		/* Opcode of the UA Message */
		opcode = tvb_get_guint8(tvb, offset);
		if(opcode != 0x9f)
			opcode = (opcode & 0x7f);

		/* Usefull for a research in wireshark */
		proto_tree_add_uint_format(ua3g_tree, hf_ua3g_opcode, tvb, offset,
			1, opcode, "Opcode: %s (0x%02x)",
			val_to_str(opcode, opcodes_vals, "Unknown"), opcode);
		offset++;
		length--;

		/* add text to the frame "INFO" column */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
				val_to_str(opcode, opcodes_vals, "Unknown"));

		proto_item_append_text(ua3g_item, ", %s", val_to_str(opcode, opcodes_vals, "Unknown"));

		if(length > 0)
			ua3g_body_item = proto_tree_add_text(ua3g_tree, tvb, offset,
				length, "UA3G Body - %s",
				val_to_str(opcode, opcodes_vals, "Unknown"));

		if(message_direction == SYS_TO_TERM) {
			switch(opcode) {
			case PRODUCTION_TEST: /* 0x01 */
			case SUBDEVICE_RESET: /* 0x06 */
			case ARE_YOU_THERE: /* 0x2B */
			case SET_SPEAKER_VOL: /* 0x3B */
			case TRACE_ON: /* 0x42 */
				{
					decode_with_one_parameter(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case SUBDEVICE_ESCAPE: /* 0x02 */
				{
					decode_subdevice_escape(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case SOFT_RESET: /* 0x03 */
				{
					decode_software_reset(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case IP_PHONE_WARMSTART: /* 0x04 */
				{
					decode_ip_phone_warmstart(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case SUPER_MSG: /* 0x0B */
			case SUPER_MSG_2: /* 0x17 */
				{
					decode_super_msg(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case SEGMENT_MSG: /* 0x0C */
				{
					decode_segment_msg(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case IP_DEVICE_ROUTING: /* 0x13 */
				{
					decode_ip_device_routing(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case DEBUG_IN_LINE: /* 0x18 */
				{
					decode_debug_in_line(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case LED_COMMAND: /* 0x21 */
				{
					decode_led_command(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case LCD_LINE_1_CMD: /* 0x27 */
			case LCD_LINE_2_CMD: /* 0x28 */
				{
					decode_lcd_line_cmd(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case MAIN_VOICE_MODE: /* 0x29 */
				{
					decode_main_voice_mode(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case SUBDEVICE_METASTATE: /* 0x2C */
				{
					decode_subdevice_metastate(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case DWL_DTMF_CLCK_FORMAT: /* 0x30 */
				{
					decode_dwl_dtmf_clck_format(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case SET_CLCK: /* 0x31 */
				{
					decode_set_clck(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case VOICE_CHANNEL: /* 0x32 */
				{
					decode_voice_channel(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case EXTERNAL_RINGING: /* 0x33 */
				{
					decode_external_ringing(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case LCD_CURSOR: /* 0x35 */
				{
					decode_lcd_cursor(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case DWL_SPECIAL_CHAR: /* 0x36 */
				{
					decode_dwl_special_char(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case SET_CLCK_TIMER_POS: /* 0x38 */
				{
					decode_set_clck_timer_pos(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case SET_LCD_CONTRAST: /* 0x39 */
				{
					decode_set_lcd_contrast(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case BEEP: /* 0x3C */
				{
					decode_beep(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case SIDETONE: /* 0x3D */
				{
					decode_sidetone(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case RINGING_CADENCE: /* 0x3E */
				{
					decode_ringing_cadence(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case MUTE: /* 0x3F */
				{
					decode_mute(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case FEEDBACK: /* 0x40 */
				{
					decode_feedback(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case READ_PERIPHERAL: /* 0x44 */
			case WRITE_PERIPHERAL: /* 0x45 */
				{
					decode_r_w_peripheral(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case ICON_CMD: /* 0x47 */
				{
					decode_icon_cmd(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case AUDIO_CONFIG: /* 0x49 */
				{
					decode_audio_config(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case AUDIO_PADDED_PATH: /* 0x4A */
				{
					decode_audio_padded_path(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case KEY_RELEASE: /* 0x41 */
			case AMPLIFIED_HANDSET: /* 0x48 */
			case LOUDSPEAKER: /* 0x4D */
			case ANNOUNCE: /* 0x4E */
				{
					decode_on_off_level(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case RING: /* 0x4F */
				{
					decode_ring(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case UA_DWL_PROTOCOL: /* 0x50 */
				{
					decode_ua_dwl_protocol(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			/* Case for UA3G message with only opcode (No body) */
			case NOP: /* 0x00 */
			case HE_ROUTING:	/* 0x05 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case LOOPBACK_ON: /* 0x07 */
			case LOOPBACK_OFF: /* 0x08 */
			case VIDEO_ROUTING:	/* 0x09 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case REMOTE_UA_ROUTING:	/* 0x0D NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case VERY_REMOTE_UA_ROUTING:	/* 0x0E NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case OSI_ROUTING:	/* 0x0F NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case ABC_A_ROUTING:	/* 0x11 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case IBS_ROUTING:	/* 0x12 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case M_REFLEX_HUB_ROUTING:	/* 0x14 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case START_BUZZER: /* 0x22 */
			case STOP_BUZZER: /* 0x23 */
			case ENABLE_DTMF: /* 0x24 */
			case DISABLE_DTMF: /* 0x25 */
			case CLEAR_LCD_DISP: /* 0x26 */
			case VERSION_INQUIRY: /* 0x2A */
			case VTA_STATUS_INQUIRY: /* 0x2D */
			case SUBDEVICE_STATE: /* 0x2E */
			case AUDIO_IDLE: /* 0x3A */
			case TRACE_OFF: /* 0x43 */
			case ALL_ICONS_OFF: /* 0x46 */
			case RELEASE_RADIO_LINK: /* 0x4B */
			case DECT_HANDOVER:	/* 0x4C NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			default:
				{
					break;
				}
			}
		}
		if(message_direction == TERM_TO_SYS) {
			switch(opcode) {
			case CS_DIGIT_DIALED: /* 0x03 */
				{
					decode_digit_dialed(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_SUBDEVICE_MSG: /* 0x04 */
				{
					decode_subdevice_msg(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_SUPER_MSG: /* 0x0B */
			case CS_SUPER_MSG_2: /* 0x17 */
				{
					decode_super_msg(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_SEGMENT_MSG: /* 0x0C */
				{
					decode_segment_msg(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_IP_DEVICE_ROUTING: /* 0x13 */
				{
					decode_cs_ip_device_routing(ua3g_tree, tvb, pinfo, offset, length, opcode,ua3g_item, ua3g_body_item);
					break;
				}
			case CS_DEBUG_IN_LINE: /* 0x18 */
				{
					decode_debug_in_line(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_NON_DIGIT_KEY_PUSHED:	/* 0x20 Key translation not sure */
			case CS_DIGIT_KEY_RELEASED:	/* 0x26 Key translation not sure */
			case CS_KEY_RELEASED: /* 0x2A */
			case CS_TM_KEY_PUSHED:	/* 0x2D Key translation not sure */
				{
					decode_key_number(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_UNSOLICITED_MSG: /* 0x9F (0x1F) */
			case CS_VERSION_RESPONSE: /* 0x21 */
				{
					decode_unsolicited_msg(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			case CS_I_M_HERE: /* 0x22 */
				{
					decode_i_m_here(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_RSP_STATUS_INQUIRY: /* 0x23 */
			case CS_SPECIAL_KEY_STATUS: /* 0x29 */
				{
					decode_special_key(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_SUBDEVICE_STATE: /* 0x24 */
				{
					decode_subdevice_state(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_PERIPHERAL_CONTENT: /* 0x2B */
				{
					decode_r_w_peripheral(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_body_item);
					break;
				}
			case CS_UA_DWL_PROTOCOL: /* 0x50 */
				{
					decode_ua_dwl_protocol(ua3g_tree, tvb, pinfo, offset, length, opcode, ua3g_item, ua3g_body_item);
					break;
				}
			/* Case for UA3G message with only opcode (No body) */
			case CS_NOP_ACK: /* 0x00 */
			case CS_HANDSET_OFFHOOK: /* 0x01 */
			case CS_HANDSET_ONHOOK: /* 0x02 */
			case CS_HE_ROUTING:	/* 0x05 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case CS_LOOPBACK_ON: /* 0x06 */
			case CS_LOOPBACK_OFF: /* 0x07 */
			case CS_VIDEO_ROUTING:	/* 0x09 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case CS_WARMSTART_ACK: /* 0x0A */
			case CS_REMOTE_UA_ROUTING:	/* 0x0D NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case CS_VERY_REMOTE_UA_R:	/* 0x0E NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case CS_OSI_ROUTING:	/* 0x0F NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case CS_ABC_A_ROUTING:	/* 0x11 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case CS_IBS_ROUTING:	/* 0x12 NOT DECODED - No description in 3AK 29000 0556 DSZZA */
			case CS_TRACE_ON_ACK: /* 0x27 */
			case CS_TRACE_OFF_ACK: /* 0x28 */
			default:
				{
					break;
				}
			}
		}
	}
}


/*-----------------------------------------------------------------------------
    DISSECTORS REGISTRATION FUNCTIONS
    ---------------------------------------------------------------------------*/
void proto_register_ua3g(void)
{
	static hf_register_info hf_ua3g[] =
		{
			{ &hf_ua3g_length,
			  { "Length", "ua3g.length", FT_UINT16, BASE_DEC,
			    NULL, 0x00, "Decimal Value", HFILL }
			},
			{ &hf_ua3g_opcode,
			  { "Opcode", "ua3g.opcode", FT_UINT8, BASE_HEX,
			    NULL, 0x00, "Hexa Value", HFILL }
			},
			{ &hf_ua3g_ip,
			  { "IP Device Routing", "ua3g.ip", FT_UINT8, BASE_HEX,
			    NULL, 0x00, "Hexa Value - 2nd Command For IP Device Routing Opcode", HFILL }
			},
			{ &hf_ua3g_command,
			  { "Command", "ua3g.command", FT_UINT8, BASE_HEX,
				NULL, 0x00, "Hexa Value - 2nd Command (Excepted IP Device Routing Opcode)", HFILL }
			},
		};

	static gint *ett[] =
	{
		&ett_ua3g,
		&ett_ua3g_body,
		&ett_ua3g_param,
		&ett_ua3g_option,
	};

	/* UA3G dissector registration */
	proto_ua3g = proto_register_protocol("UA3G Message", "UA3G", "ua3g");

	proto_register_field_array(proto_ua3g, hf_ua3g, array_length(hf_ua3g));

	register_dissector("ua3g", dissect_ua3g, proto_ua3g);

	/* Common subtree array registration */
	proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_ua3g(void)
{
	dissector_handle_t handle_ua3g = find_dissector("ua3g");

	/* hooking of UA3G on UDP */
	register_dissector_table("ua3g.opcode", "ua3g.opcode",
		FT_UINT8, BASE_HEX);

	dissector_add_uint("ua3g.opcode", 0x15, handle_ua3g);
}
