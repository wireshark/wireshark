/* packet-adwin-config.c
 * Routines for ADwin configuration protocol dissection
 * Copyright 2010, Thomas Boehne <TBoehne[AT]ADwin.de>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/ipproto.h>

/* This is registered to a different protocol */
#define ADWIN_CONFIGURATION_PORT 7000

#define UDPStatusLENGTH             52
#define UDPExtStatusLENGTH         432
#define UDPMessageLENGTH           100
#define UDPMessageLENGTH_wrong     104
#define UDPInitAckLENGTH            96
#define UDPIXP425FlashUpdateLENGTH  92
#define UDPOutLENGTH                22

#define STATUS_WITH_BOOTLOADER                  0x0001
#define STATUS_REPROGRAMMABLE                   0x0002
#define STATUS_CONFIGURABLE                     0x0004
#define STATUS_BOOTLOADER_BOOTS                 0x0008
#define STATUS_BOOTLOADER_REPROGRAMMABLE        0x0010
#define STATUS_BOOTLOADER_RECEIVES_DATA         0x0020
#define STATUS_BOOTLOADER_REPROGRAMMING_DONE    0x0040
#define STATUS_WITH_EEPROM_SUPPORT              0x0080

static const value_string pattern_mapping[] = {
	{ 0x12343210, "Reset reset/socket counters"},
	{ 0x73241291, "Scan Netarm + IXP"},
	{ 0x37241291, "Scan IXP"},
	{ 0, NULL },
};

static const value_string config_command_mapping[] = {
	{ 100, "Apply all config values except MAC if MAC matches."},
	{ 105, "Apply all config values including MAC if current MAC is 00:50:C2:0A:22:EE."},
	{ 110, "Apply all config values including MAC."},
	{ 120, "Enable/Disable bootloader if MAC matches."},
	{ 130, "Write extended hardware info to EEPROM."},
	{ 0, NULL },
};

static const string_string system_type_mapping[] = {
	{ "01", "Light 16"},
	{ "02", "Gold"},
	{ "03", "Pro I"},
	{ "04", "Pro II"},
	{ "05", "Gold II"},
	{ 0, NULL },
};

static const string_string processor_type_mapping[] = {
	{ "09", "T9"},
	{ "10", "T10"},
	{ "11", "T11"},
	{ 0, NULL },
};


/* add little endian number (incorrect byte-order) value to a tree */
#define ADWIN_ADD_LE(tree, field, offset, length)                       \
        proto_tree_add_item(tree, hf_adwin_config_##field, tvb, offset, \
                            length, ENC_LITTLE_ENDIAN);

/* add big endian number (correct byte-order) value to a tree */
#define ADWIN_ADD_BE(tree, field, offset, length)                       \
        proto_tree_add_item(tree, hf_adwin_config_##field, tvb, offset, \
                            length, ENC_BIG_ENDIAN);

/* Initialize the protocol and registered fields */
static int proto_adwin_config                     = -1;

static int hf_adwin_config_bootloader             = -1;
static int hf_adwin_config_command                = -1;
static int hf_adwin_config_data                   = -1;
static int hf_adwin_config_date                   = -1;
static int hf_adwin_config_description            = -1;
static int hf_adwin_config_dhcp                   = -1;
static int hf_adwin_config_filename               = -1;
static int hf_adwin_config_filesize               = -1;
static int hf_adwin_config_gateway                = -1;
static int hf_adwin_config_mac                    = -1;
static int hf_adwin_config_netmask_count          = -1;
static int hf_adwin_config_netmask                = -1;
static int hf_adwin_config_password               = -1;
static int hf_adwin_config_path                   = -1;
static int hf_adwin_config_pattern                = -1;
static int hf_adwin_config_port16                 = -1;
static int hf_adwin_config_port32                 = -1;
static int hf_adwin_config_reboot                 = -1;
static int hf_adwin_config_scan_id                = -1;
static int hf_adwin_config_reply_broadcast        = -1;
static int hf_adwin_config_revision               = -1;
static int hf_adwin_config_processor_type         = -1;
static int hf_adwin_config_system_type            = -1;
static int hf_adwin_config_server_ip              = -1;
static int hf_adwin_config_server_version         = -1;
static int hf_adwin_config_server_version_beta    = -1;
static int hf_adwin_config_socketshutdowns        = -1;
static int hf_adwin_config_status                 = -1;
static int hf_adwin_config_status_bootloader      = -1;
static int hf_adwin_config_status_reprogrammable  = -1;
static int hf_adwin_config_status_configurable    = -1;
static int hf_adwin_config_status_bootloader_boots = -1;
static int hf_adwin_config_status_bootloader_reprogrammable  = -1;
static int hf_adwin_config_status_bootloader_receive = -1;
static int hf_adwin_config_status_bootloader_reprogramming_done  = -1;
static int hf_adwin_config_status_eeprom_support  = -1;
static int hf_adwin_config_stream_length          = -1;
static int hf_adwin_config_timeout                = -1;
static int hf_adwin_config_timerresets            = -1;
static int hf_adwin_config_disk_free              = -1;
static int hf_adwin_config_disk_size              = -1;
static int hf_adwin_config_unused                 = -1;
static int hf_adwin_config_version                = -1;
static int hf_adwin_config_xilinx_version         = -1;

/* Initialize the subtree pointers */
static gint ett_adwin_config          = -1;
static gint ett_adwin_config_status   = -1;
static gint ett_adwin_config_debug    = -1;

static void
dissect_UDPStatus(tvbuff_t *tvb, proto_tree *adwin_tree)
{
	proto_tree *status_tree;
	proto_tree *debug_tree;
	proto_item *st, *dt;

	if (! adwin_tree)
		return;

	dt = proto_tree_add_item(adwin_tree, proto_adwin_config, tvb, 0, -1, ENC_NA);
	debug_tree = proto_item_add_subtree(dt, ett_adwin_config_debug);
	proto_item_set_text(dt, "ADwin Debug information");

	ADWIN_ADD_BE(adwin_tree, pattern,             0,  4);
	ADWIN_ADD_BE(adwin_tree, version,             4,  4);

	st = ADWIN_ADD_BE(adwin_tree, status,         8,  4);
	status_tree = proto_item_add_subtree(st, ett_adwin_config_status);
	ADWIN_ADD_BE(status_tree, status_bootloader,               8,  4);
	ADWIN_ADD_BE(status_tree, status_reprogrammable,           8,  4);
	ADWIN_ADD_BE(status_tree, status_configurable,             8,  4);
	ADWIN_ADD_BE(status_tree, status_bootloader_boots,         8,  4);
	ADWIN_ADD_BE(status_tree, status_bootloader_reprogrammable,8,  4);
	ADWIN_ADD_BE(status_tree, status_bootloader_receive,       8,  4);
	ADWIN_ADD_BE(status_tree, status_bootloader_reprogramming_done, 8,  4);
	ADWIN_ADD_BE(status_tree, status_eeprom_support,           8,  4);

	ADWIN_ADD_BE(adwin_tree, server_version_beta,12,  2);
	ADWIN_ADD_BE(adwin_tree, server_version,     14,  2);
	ADWIN_ADD_BE(adwin_tree, xilinx_version,     16,  4);
	ADWIN_ADD_BE(adwin_tree, mac,                20,  6);
	ADWIN_ADD_LE(debug_tree, unused,             26,  2);
	ADWIN_ADD_BE(adwin_tree, port16,             28,  2);
	ADWIN_ADD_LE(adwin_tree, dhcp,               30,  1);
	ADWIN_ADD_LE(adwin_tree, netmask_count,      31,  1);
	ADWIN_ADD_BE(adwin_tree, gateway,            32,  4);
	ADWIN_ADD_LE(debug_tree, unused,             36, 11);
	ADWIN_ADD_LE(adwin_tree, reply_broadcast,    47,  1);
	ADWIN_ADD_LE(adwin_tree, scan_id,            48,  4);
}

static void
dissect_UDPExtStatus(tvbuff_t *tvb, proto_tree *adwin_tree)
{
	const gchar *processor_type, *system_type;

	if (! adwin_tree)
		return;

	ADWIN_ADD_BE(adwin_tree, mac,                 0,  6);
	ADWIN_ADD_LE(adwin_tree, unused,              6,  2);
	ADWIN_ADD_BE(adwin_tree, pattern,             8,  4);
	ADWIN_ADD_BE(adwin_tree, version,            12,  4);
	ADWIN_ADD_LE(adwin_tree, description,        16, 16);
	ADWIN_ADD_BE(adwin_tree, timerresets,        32,  4);
	ADWIN_ADD_BE(adwin_tree, socketshutdowns,    36,  4);
	ADWIN_ADD_BE(adwin_tree, disk_free,          40,  4);
	ADWIN_ADD_BE(adwin_tree, disk_size,          44,  4);
	ADWIN_ADD_LE(adwin_tree, date,               48,  8);
	ADWIN_ADD_LE(adwin_tree, revision,           56,  8);

	/* add the processor type raw values to the tree, to allow filtering */
	ADWIN_ADD_LE(adwin_tree, processor_type,     64,  2);
	/* add the processor type as a pretty printed string */
	processor_type = tvb_get_ephemeral_string(tvb, 64, 2);
	processor_type = str_to_str(processor_type, processor_type_mapping, "Unknown (%s)");
	proto_tree_add_text(adwin_tree, tvb, 64, 2, "Processor Type: %s", processor_type);

	/* add system type as raw value and pretty printed string */
	ADWIN_ADD_LE(adwin_tree, system_type,        66,  2);
	system_type = tvb_get_ephemeral_string(tvb, 66, 2);
	system_type = str_to_str(system_type, system_type_mapping, "Unknown (%s)");
	proto_tree_add_text(adwin_tree, tvb, 66, 2, "System Type: %s", system_type);

	ADWIN_ADD_LE(adwin_tree, unused,             68,364);
}

static void
dissect_UDPMessage(tvbuff_t *tvb, proto_tree *adwin_tree)
{
	const gchar *processor_type, *system_type;

	if (! adwin_tree)
		return;

	ADWIN_ADD_LE(adwin_tree, command,             0,  4);
	ADWIN_ADD_LE(adwin_tree, version,             4,  4);
	ADWIN_ADD_LE(adwin_tree, mac,                 8,  6);
	ADWIN_ADD_LE(adwin_tree, unused,             14,  2);
	ADWIN_ADD_LE(adwin_tree, server_ip,          16,  4);
	ADWIN_ADD_LE(adwin_tree, unused,             20,  4);
	ADWIN_ADD_LE(adwin_tree, netmask,            24,  4);
	ADWIN_ADD_LE(adwin_tree, unused,             28,  4);
	ADWIN_ADD_LE(adwin_tree, gateway,            32,  4);
	ADWIN_ADD_LE(adwin_tree, unused,             36,  4);
	ADWIN_ADD_LE(adwin_tree, dhcp,               40,  4);
	ADWIN_ADD_LE(adwin_tree, port32,             44,  4);
	ADWIN_ADD_LE(adwin_tree, password,           48, 10);
	ADWIN_ADD_LE(adwin_tree, bootloader,         58,  1);
	ADWIN_ADD_LE(adwin_tree, unused,             59,  5);
	ADWIN_ADD_LE(adwin_tree, description,        64, 16);
	ADWIN_ADD_LE(adwin_tree, date,               80,  8);
	ADWIN_ADD_LE(adwin_tree, revision,           88,  8);

	/* add the processor type raw values to the tree, to allow filtering */
	ADWIN_ADD_LE(adwin_tree, processor_type,     96,  2);
	/* add the processor type as a pretty printed string */
	processor_type = tvb_get_ephemeral_string(tvb, 96, 2);
	processor_type = str_to_str(processor_type, processor_type_mapping, "Unknown");
	proto_tree_add_text(adwin_tree, tvb, 96, 2, "Processor Type: %s", processor_type);

	/* add system type as raw value and pretty printed string */
	ADWIN_ADD_LE(adwin_tree, system_type,        98,  2);
	system_type = tvb_get_ephemeral_string(tvb, 98, 2);
	system_type = str_to_str(system_type, system_type_mapping, "Unknown");
	proto_tree_add_text(adwin_tree, tvb, 98, 2, "System Type: %s", system_type);
}

static void
dissect_UDPInitAck(tvbuff_t *tvb, proto_tree *adwin_tree)
{

	if (! adwin_tree)
		return;

	ADWIN_ADD_BE(adwin_tree, pattern,             0,  4);
	ADWIN_ADD_LE(adwin_tree, reboot,              4,  4);
	ADWIN_ADD_BE(adwin_tree, mac,                 8,  6);
	ADWIN_ADD_LE(adwin_tree, unused,             14,  2);
	ADWIN_ADD_LE(adwin_tree, unused,             16, 80);
}

static void
dissect_UDPIXP425FlashUpdate(tvbuff_t *tvb, proto_tree *adwin_tree)
{

	if (! adwin_tree)
		return;

	ADWIN_ADD_BE(adwin_tree, pattern,             0,  4);
	ADWIN_ADD_BE(adwin_tree, version,             4,  4);
	ADWIN_ADD_BE(adwin_tree, scan_id,             8,  4);
	ADWIN_ADD_BE(adwin_tree, status,             12,  4);
	ADWIN_ADD_BE(adwin_tree, timeout,            16,  4);
	ADWIN_ADD_BE(adwin_tree, filename,           20, 24);
	ADWIN_ADD_BE(adwin_tree, mac,                44,  6);
	ADWIN_ADD_BE(adwin_tree, unused,             50, 42);
}

static void
dissect_UDPOut(tvbuff_t *tvb, proto_tree *adwin_tree)
{

	if (! adwin_tree)
		return;

	ADWIN_ADD_LE(adwin_tree, status,              0,  4);
	ADWIN_ADD_BE(adwin_tree, mac,                 4,  6);
	ADWIN_ADD_LE(adwin_tree, netmask,            10,  4);
	ADWIN_ADD_BE(adwin_tree, gateway,            14,  4);
	ADWIN_ADD_LE(adwin_tree, dhcp,               18,  2);
	ADWIN_ADD_BE(adwin_tree, port16,             20,  2);
}

static guint
get_adwin_TCPUpdate_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	/*
	 * Return the length of the packet. (Doesn't include the length field itself)
	 */
	return tvb_get_ntohl(tvb, offset);
}

static void
dissect_TCPFlashUpdate(tvbuff_t *tvb,  packet_info *pinfo _U_, proto_tree *adwin_tree)
{
	gint length, offset;
	guint8 *filename;
	nstime_t tmp_time;
	tmp_time.nsecs = 0;

	if (! adwin_tree)
		return;

	ADWIN_ADD_BE(adwin_tree, stream_length,        0,    4);
	offset = 4;
	length = tvb_strnlen(tvb, offset, -1) + 1;
	filename = tvb_get_ephemeral_string(tvb, offset, length);
	if (strncmp(filename, "eeprom_on", length) == 0) {
		proto_tree_add_text(adwin_tree, tvb, offset, length,
				    "Enable EEPROM Support");
		return;
	}
	if (strncmp(filename, "eeprom_off", length) == 0) {
		proto_tree_add_text(adwin_tree, tvb, offset, length,
				    "Disable EEPROM Support");
		return;
	}
	ADWIN_ADD_BE(adwin_tree, filename,       4,  length);
	offset += length;
	length = tvb_strnlen(tvb, 4 + length, -1) + 1;
	ADWIN_ADD_BE(adwin_tree, path,           offset,  length);
	offset += length;
	ADWIN_ADD_BE(adwin_tree, filesize,       offset,  4);
	offset += 4;
	tmp_time.secs = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(adwin_tree, tvb, offset, 4,
			    "File time: %s", abs_time_to_str(&tmp_time, ABSOLUTE_TIME_LOCAL, TRUE));
	offset += 4;
	tmp_time.secs = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(adwin_tree, tvb, offset, 4,
			    "Update time: %s", abs_time_to_str(&tmp_time, ABSOLUTE_TIME_LOCAL, TRUE));
	offset += 4;
	ADWIN_ADD_BE(adwin_tree, unused,         offset, 128);
	offset += 128;
	length = tvb_length(tvb) - offset;
	ADWIN_ADD_BE(adwin_tree, data,             offset,  length);
}

/* 00:50:c2:0a:2*:** */
static char mac_iab_start[] = { 0x00, 0x50, 0xc2, 0x0a, 0x20, 0x00 };
static char mac_iab_end[]   = { 0x00, 0x50, 0xc2, 0x0a, 0x2f, 0xff };

/* 00:22:71:**:**:** */
static char mac_oui_start[] = { 0x00, 0x22, 0x71, 0x00, 0x00, 0x00 };
static char mac_oui_end[]   = { 0x00, 0x22, 0x71, 0xff, 0xff, 0xff };

/* ff:ff:ff:ff:ff:ff */
static char mac_broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* return TRUE if mac is in mac address range assigned to ADwin or if
 * mac is broadcast */
static gboolean
is_adwin_mac_or_broadcast(address mac)
{
	if (mac.type != AT_ETHER)
		return FALSE;

	if (mac.len != 6) /* length of MAC address */
		return FALSE;

	if ((memcmp(mac.data, mac_iab_start, mac.len) >= 0) &&
	    (memcmp(mac.data, mac_iab_end  , mac.len) <= 0))
		return TRUE;

	if ((memcmp(mac.data, mac_oui_start, mac.len) >= 0) &&
	    (memcmp(mac.data, mac_oui_end, mac.len) <= 0))
		return TRUE;

	/* adwin configuration protocol uses MAC broadcasts for
	   device discovery */
	if (memcmp(mac.data, mac_broadcast, mac.len) == 0)
		return TRUE;

	return FALSE;
}


/* Here we determine which type of packet is sent by looking at its
   size. Let's hope that future ADwin packets always differ in size.
   They probably will, since the server classifies the packets
   according to their sizes, too. */

static const value_string length_mapping[] = {
	{ UDPStatusLENGTH,		"UDPStatus" },
	{ UDPExtStatusLENGTH,		"UDPExtStatus" },
	{ UDPMessageLENGTH,		"UDPMessage" },
	{ UDPMessageLENGTH_wrong,	"UDPMessage (broken - upgrade ADConfig!)" },
	{ UDPInitAckLENGTH,		"UDPInitAck" },
	{ UDPIXP425FlashUpdateLENGTH,	"UDPIXP425FlashUpdate" },
	{ UDPOutLENGTH,			"UDPOut" },
	{ 0, NULL },
};

/*  Depending on the packet type, the appropriate dissector is called. */
static int
dissect_adwin_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *adwin_config_tree;
	guint32 length;

	length = tvb_reported_length(tvb);

	if (pinfo->ipproto == IP_PROTO_UDP &&
	    ! (length == UDPStatusLENGTH
	       || length == UDPExtStatusLENGTH
	       || length == UDPMessageLENGTH
	       || length == UDPMessageLENGTH_wrong
	       || length == UDPInitAckLENGTH
	       || length == UDPIXP425FlashUpdateLENGTH
	       || length == UDPOutLENGTH))
		return 0;

	if(pinfo->ipproto == IP_PROTO_TCP &&
	   !(pinfo->srcport == ADWIN_CONFIGURATION_PORT
	     || pinfo->destport == ADWIN_CONFIGURATION_PORT))
		return 0;

	if (pinfo->ipproto != IP_PROTO_UDP && pinfo->ipproto != IP_PROTO_TCP)
		return 0;

	if (! (is_adwin_mac_or_broadcast(pinfo->dl_src) || is_adwin_mac_or_broadcast(pinfo->dl_dst)))
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADwin Config");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_adwin_config, tvb, 0, -1, ENC_NA);
		adwin_config_tree = proto_item_add_subtree(ti, ett_adwin_config);
	} else {
		adwin_config_tree = NULL;
	}

	switch (pinfo->ipproto) {
	case IP_PROTO_TCP:
		tcp_dissect_pdus(tvb, pinfo, tree, 1, 4, get_adwin_TCPUpdate_len, dissect_TCPFlashUpdate);
		col_set_str(pinfo->cinfo, COL_INFO, "TCPFlashUpdate");
		break;
	case IP_PROTO_UDP:
		switch (length) {
		case UDPStatusLENGTH:
			dissect_UDPStatus(tvb, adwin_config_tree);
			break;
		case UDPExtStatusLENGTH:
			dissect_UDPExtStatus(tvb, adwin_config_tree);
			break;
		case UDPMessageLENGTH:
			dissect_UDPMessage(tvb, adwin_config_tree);
			break;
		case UDPMessageLENGTH_wrong: /* incorrect packet length */
			/* formerly used by adconfig */
			dissect_UDPMessage(tvb, adwin_config_tree);
			break;
		case UDPInitAckLENGTH:
			dissect_UDPInitAck(tvb, adwin_config_tree);
			break;
		case UDPIXP425FlashUpdateLENGTH:
			dissect_UDPIXP425FlashUpdate(tvb, adwin_config_tree);
			break;
		case UDPOutLENGTH:
			dissect_UDPOut(tvb, adwin_config_tree);
			break;
		default:
			/* Heuristics above should mean we never get here */
			DISSECTOR_ASSERT_NOT_REACHED();
		}

		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(length, length_mapping,
				"Unknown ADwin Configuration packet, length: %d"));
	}

	return (tvb_reported_length(tvb));
}

void
proto_register_adwin_config(void)
{
	static hf_register_info hf[] = {
		{ &hf_adwin_config_bootloader,
		  { "Enable Bootloader", "adwin_config.bootloader",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_command,
		  { "Command", "adwin_config.command",
		    FT_UINT32, BASE_DEC, config_command_mapping, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_data,
		  { "Data", "adwin_config.data",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_date,
		  { "Date", "adwin_config.date",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_description,
		  { "Description", "adwin_config.description",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_dhcp,
		  { "DHCP enabled", "adwin_config.dhcp",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_filename,
		  { "File name", "adwin_config.filename",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_filesize,
		  { "File size", "adwin_config.filesize",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_gateway,
		  { "Gateway IP", "adwin_config.gateway",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_mac,
		  { "MAC address", "adwin_config.mac",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_netmask,
		  { "Netmask", "adwin_config.netmask",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_netmask_count,
		  { "Netmask count", "adwin_config.netmask_count",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "The number of binary ones in the netmask.", HFILL }
		},
		{ &hf_adwin_config_password,
		  { "Password", "adwin_config.password",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Password to set for ADwin system.", HFILL }
		},
		{ &hf_adwin_config_pattern,
		  { "Pattern", "adwin_config.pattern",
		    FT_UINT32, BASE_HEX, pattern_mapping, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_path,
		  { "Path", "adwin_config.path",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_port16,
		  { "Port (16bit)", "adwin_config.port",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "The server port on which the ADwin system is listening on (16bit).", HFILL }
		},
		{ &hf_adwin_config_port32,
		  { "Port (32bit)", "adwin_config.port",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "The server port on which the ADwin system is listening on (32bit).", HFILL }
		},
		{ &hf_adwin_config_reboot,
		  { "Reboot", "adwin_config.reboot",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Number of system reboots.", HFILL }
		},
		{ &hf_adwin_config_scan_id,
		  { "Scan ID", "adwin_config.scan_id",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_reply_broadcast, /* send_normal in UDPStatus */
		  { "Reply with broadcast", "adwin_config.reply_broadcast",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "If this bit is set, the scanned system should reply with a broadcast.", HFILL }
		},
		{ &hf_adwin_config_revision,
		  { "Revision", "adwin_config.revision",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_processor_type,
		  { "Processor Type (Raw value)", "adwin_config.processor_type",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The DSP processor type of the ADwin system, e.g. T9, T10 or T11.", HFILL }
		},
		{ &hf_adwin_config_system_type,
		  { "System Type (Raw value)", "adwin_config.system_type",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The system type of the ADwin system, e.g. Gold, Pro or Light.", HFILL }
		},
		{ &hf_adwin_config_server_ip,
		  { "Server IP", "adwin_config.server_ip",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "In scan replies, this is the current IP address of the ADwin system. In configuration packets, this is the new IP to be used by the ADwin system.", HFILL }
		},
		{ &hf_adwin_config_server_version,
		  { "Server version", "adwin_config.server_version",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "The version number of the server program. This number represents the complete firmware version, e.g. 2.74.", HFILL }
		},
		{ &hf_adwin_config_server_version_beta,
		  { "server version (beta part)", "adwin_config.server_version_beta",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "A non-zero value of this field indicates a beta firmware version, where this number represents the current revision.", HFILL }
		},
		{ &hf_adwin_config_socketshutdowns,
		  { "Socket shutdowns", "adwin_config.socketshutdowns",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of socket errors that lead to a recreation of the socket (ethernet interface version 1 only).", HFILL }
		},
		{ &hf_adwin_config_status,
		  { "Status", "adwin_config.status",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_status_bootloader,
		  { "Status Bootloader", "adwin_config.status_bootloader",
		    FT_BOOLEAN, 32, NULL, STATUS_WITH_BOOTLOADER,
		    "Indicates if the ADwin system has bootloader capabilities.", HFILL }
		},
		{ &hf_adwin_config_status_reprogrammable,
		  { "Status Reprogrammable",
		    "adwin_config.status_reprogrammable",
		    FT_BOOLEAN, 32, NULL, STATUS_REPROGRAMMABLE,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_status_configurable,
		  { "Status Configurable", "adwin_config.status_configurable",
		    FT_BOOLEAN, 32, NULL, STATUS_CONFIGURABLE,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_status_bootloader_boots,
		  { "Status Bootloader boots",
		    "adwin_config.status_bootloader_boots",
		    FT_BOOLEAN, 32, NULL, STATUS_BOOTLOADER_BOOTS,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_status_bootloader_reprogrammable,
		  { "Status Bootloader reprogrammable",
		    "adwin_config.status_bootloader_reprogrammable",
		    FT_BOOLEAN, 32, NULL, STATUS_BOOTLOADER_REPROGRAMMABLE,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_status_bootloader_receive,
		  { "Status Bootloader receive",
		    "adwin_config.status_bootloader_receive",
		    FT_BOOLEAN, 32, NULL, STATUS_BOOTLOADER_RECEIVES_DATA,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_status_bootloader_reprogramming_done,
		  { "Status Bootloader reprogramming done",
		    "adwin_config.status_bootloader_reprogramming_done",
		    FT_BOOLEAN, 32, NULL, STATUS_BOOTLOADER_REPROGRAMMING_DONE,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_status_eeprom_support,
		  { "Status EEPROM Support",
		    "adwin_config.status_eeprom_support",
		    FT_BOOLEAN, 32, NULL, STATUS_WITH_EEPROM_SUPPORT,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_stream_length,
		  { "Stream length", "adwin_config.stream_length",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_timeout,
		  { "Timeout", "adwin_config.timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_timerresets,
		  { "Timer resets", "adwin_config.timerresets",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Counter for resets of the timer (ethernet interface version 1 only).", HFILL }
		},
		{ &hf_adwin_config_disk_free,
		  { "Free disk space (kb)", "adwin_config.disk_free",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Free disk space in kb on flash (ethernet interface version 2 only).", HFILL }
		},
		{ &hf_adwin_config_disk_size,
		  { "Disk size (kb)", "adwin_config.disk_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Flash disk size in kb (ethernet interface version 2 only).", HFILL }
		},
		{ &hf_adwin_config_unused,
		  { "Unused", "adwin_config.unused",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_version,
		  { "Version", "adwin_config.version",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_xilinx_version,
		  { "XILINX Version", "adwin_config.xilinx_version",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Version of XILINX program", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_adwin_config,
		&ett_adwin_config_status,
		&ett_adwin_config_debug,
	};

	/* Register the protocol name and description */
	proto_adwin_config =
		proto_register_protocol("ADwin configuration protocol",
					"ADwin-Config", "adwin_config");

	/* Required function calls to register the header fields and
	   subtrees used */
	proto_register_field_array(proto_adwin_config, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_adwin_config(void)
{
	static int adwin_config_prefs_initialized = FALSE;

	if ( ! adwin_config_prefs_initialized ) {
		heur_dissector_add("udp", dissect_adwin_config, proto_adwin_config);
		heur_dissector_add("tcp", dissect_adwin_config, proto_adwin_config);
		adwin_config_prefs_initialized = TRUE;
	}
}
