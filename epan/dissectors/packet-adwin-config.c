/* packet-adwin-config.c
 * Routines for ADwin configuration protocol dissection
 * Copyright 2010, Thomas Boehne <TBoehne[AT]ADwin.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include "packet-tcp.h"

/* Forward declarations */
void proto_register_adwin_config(void);
void proto_reg_handoff_adwin_config(void);

/* This is registered to a different protocol */
#define ADWIN_CONFIGURATION_PORT 7000

#define UDPStatusLENGTH             52
#define UDPExtStatusLENGTH         432
#define UDPMessageLENGTH           100
#define UDPMessageLENGTH_wrong     104
#define UDPInitAckLENGTH            96
#define UDPIXP425FlashUpdateLENGTH  92
#define UDPOutLENGTH                22

#define STATUS_WITH_BOOTLOADER                  0x00000001
#define STATUS_REPROGRAMMABLE                   0x00000002
#define STATUS_CONFIGURABLE                     0x00000004
#define STATUS_BOOTLOADER_BOOTS                 0x00000008
#define STATUS_BOOTLOADER_REPROGRAMMABLE        0x00000010
#define STATUS_BOOTLOADER_RECEIVES_DATA         0x00000020
#define STATUS_BOOTLOADER_REPROGRAMMING_DONE    0x00000040
#define STATUS_WITH_EEPROM_SUPPORT              0x00000080

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
	{ NULL, NULL },
};

static const string_string processor_type_mapping[] = {
	{ "09", "T9"},
	{ "10", "T10"},
	{ "11", "T11"},
	{ NULL, NULL },
};

/* Initialize the protocol and registered fields */
static int proto_adwin_config;

static int hf_adwin_config_bootloader;
static int hf_adwin_config_command;
static int hf_adwin_config_data;
static int hf_adwin_config_date;
static int hf_adwin_config_description;
static int hf_adwin_config_dhcp;
static int hf_adwin_config_filename;
static int hf_adwin_config_filesize;
static int hf_adwin_config_filetime;
static int hf_adwin_config_updatetime;
static int hf_adwin_config_gateway;
static int hf_adwin_config_mac;
static int hf_adwin_config_netmask_count;
static int hf_adwin_config_netmask;
static int hf_adwin_config_password;
static int hf_adwin_config_path;
static int hf_adwin_config_pattern;
static int hf_adwin_config_port16;
static int hf_adwin_config_port32;
static int hf_adwin_config_reboot;
static int hf_adwin_config_scan_id;
static int hf_adwin_config_reply_broadcast;
static int hf_adwin_config_revision;
static int hf_adwin_config_processor_type_raw;
static int hf_adwin_config_system_type_raw;
static int hf_adwin_config_processor_type;
static int hf_adwin_config_system_type;
static int hf_adwin_config_server_ip;
static int hf_adwin_config_server_version;
static int hf_adwin_config_server_version_beta;
static int hf_adwin_config_socketshutdowns;
static int hf_adwin_config_status;
static int hf_adwin_config_status_bootloader;
static int hf_adwin_config_status_reprogrammable;
static int hf_adwin_config_status_configurable;
static int hf_adwin_config_status_bootloader_boots;
static int hf_adwin_config_status_bootloader_reprogrammable;
static int hf_adwin_config_status_bootloader_receive;
static int hf_adwin_config_status_bootloader_reprogramming_done;
static int hf_adwin_config_status_eeprom_support;
static int hf_adwin_config_stream_length;
static int hf_adwin_config_eeprom_support;
static int hf_adwin_config_timeout;
static int hf_adwin_config_timerresets;
static int hf_adwin_config_disk_free;
static int hf_adwin_config_disk_size;
static int hf_adwin_config_unused;
static int hf_adwin_config_version;
static int hf_adwin_config_xilinx_version;

/* Initialize the subtree pointers */
static int ett_adwin_config;
static int ett_adwin_config_status;
static int ett_adwin_config_debug;

static void
dissect_UDPStatus(tvbuff_t *tvb, proto_tree *adwin_tree)
{
	proto_tree *debug_tree;
	proto_item *dt;

	static int * const status_flags[] = {
		&hf_adwin_config_status_bootloader,
		&hf_adwin_config_status_reprogrammable,
		&hf_adwin_config_status_configurable,
		&hf_adwin_config_status_bootloader_boots,
		&hf_adwin_config_status_bootloader_reprogrammable,
		&hf_adwin_config_status_bootloader_receive,
		&hf_adwin_config_status_bootloader_reprogramming_done,
		&hf_adwin_config_status_eeprom_support,
		NULL
	};

	if (! adwin_tree)
		return;

	dt = proto_tree_add_item(adwin_tree, proto_adwin_config, tvb, 0, -1, ENC_NA);
	debug_tree = proto_item_add_subtree(dt, ett_adwin_config_debug);
	proto_item_set_text(dt, "ADwin Debug information");

	proto_tree_add_item(adwin_tree, hf_adwin_config_pattern, tvb, 0,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_version, tvb, 4,  4, ENC_BIG_ENDIAN);

	proto_tree_add_bitmask(adwin_tree, tvb, 8, hf_adwin_config_status, ett_adwin_config_status, status_flags, ENC_BIG_ENDIAN);

	proto_tree_add_item(adwin_tree, hf_adwin_config_server_version_beta, tvb, 12,  2, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_server_version, tvb, 14,  2, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_xilinx_version, tvb, 16,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_mac, tvb, 20,  6, ENC_NA);
	proto_tree_add_item(debug_tree, hf_adwin_config_unused, tvb, 26, 2, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_port16, tvb, 28,  2, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_dhcp, tvb, 30, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_netmask_count, tvb, 31,  1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_gateway, tvb, 32,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(debug_tree, hf_adwin_config_unused, tvb, 36, 11, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_reply_broadcast, tvb, 47, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_scan_id, tvb, 48, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_UDPExtStatus(packet_info *pinfo, tvbuff_t *tvb, proto_tree *adwin_tree)
{
	const char *processor_type, *system_type;

	if (! adwin_tree)
		return;

	proto_tree_add_item(adwin_tree, hf_adwin_config_mac, tvb, 0,  6, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 6,  2, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_pattern, tvb, 8,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_version, tvb, 12,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_description, tvb, 16, 16, ENC_ASCII);
	proto_tree_add_item(adwin_tree, hf_adwin_config_timerresets, tvb, 32, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_socketshutdowns, tvb, 36, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_disk_free, tvb, 40, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_disk_size, tvb, 44, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_date, tvb, 48,  8, ENC_ASCII);
	proto_tree_add_item(adwin_tree, hf_adwin_config_revision, tvb, 56,  8, ENC_ASCII);

	/* add the processor type raw values to the tree, to allow filtering */
	proto_tree_add_item(adwin_tree, hf_adwin_config_processor_type_raw, tvb, 64, 2, ENC_ASCII);
	/* add the processor type as a pretty printed string */
	processor_type = tvb_get_string_enc(pinfo->pool, tvb, 64, 2, ENC_ASCII|ENC_NA);
	processor_type = str_to_str(processor_type, processor_type_mapping, "Unknown (%s)");
	proto_tree_add_string(adwin_tree, hf_adwin_config_processor_type, tvb, 64, 2, processor_type);

	/* add system type as raw value and pretty printed string */
	proto_tree_add_item(adwin_tree, hf_adwin_config_system_type_raw, tvb, 66, 2, ENC_ASCII);
	system_type = tvb_get_string_enc(pinfo->pool, tvb, 66, 2, ENC_ASCII|ENC_NA);
	system_type = str_to_str(system_type, system_type_mapping, "Unknown (%s)");
	proto_tree_add_string(adwin_tree, hf_adwin_config_system_type, tvb, 66, 2, system_type);

	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 68, 364, ENC_NA);
}

static void
dissect_UDPMessage(packet_info *pinfo, tvbuff_t *tvb, proto_tree *adwin_tree)
{
	const char *processor_type, *system_type;

	if (! adwin_tree)
		return;

	proto_tree_add_item(adwin_tree, hf_adwin_config_command, tvb, 0,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_version, tvb, 4,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_mac, tvb, 8,  6, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 14,  2, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_server_ip, tvb, 16,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 20,  4, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_netmask, tvb, 24,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 28,  4, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_gateway, tvb, 32,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 36,  4, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_dhcp, tvb, 40,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_port32, tvb, 44,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_password, tvb, 48, 10, ENC_ASCII);
	proto_tree_add_item(adwin_tree, hf_adwin_config_bootloader, tvb, 58,  1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 59,  5, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_description, tvb, 64, 16, ENC_ASCII);
	proto_tree_add_item(adwin_tree, hf_adwin_config_date, tvb, 80,  8, ENC_ASCII);
	proto_tree_add_item(adwin_tree, hf_adwin_config_revision, tvb, 88,  8, ENC_ASCII);

	/* add the processor type raw values to the tree, to allow filtering */
	proto_tree_add_item(adwin_tree, hf_adwin_config_processor_type_raw, tvb, 96,  2, ENC_ASCII);
	/* add the processor type as a pretty printed string */
	processor_type = tvb_get_string_enc(pinfo->pool, tvb, 96, 2, ENC_ASCII|ENC_NA);
	processor_type = str_to_str(processor_type, processor_type_mapping, "Unknown");
	proto_tree_add_string(adwin_tree, hf_adwin_config_processor_type, tvb, 96, 2, processor_type);

	/* add system type as raw value and pretty printed string */
	proto_tree_add_item(adwin_tree, hf_adwin_config_system_type_raw, tvb, 98,  2, ENC_ASCII);
	system_type = tvb_get_string_enc(pinfo->pool, tvb, 98, 2, ENC_ASCII|ENC_NA);
	system_type = str_to_str(system_type, system_type_mapping, "Unknown");
	proto_tree_add_string(adwin_tree, hf_adwin_config_system_type, tvb, 98, 2, system_type);
}

static void
dissect_UDPInitAck(tvbuff_t *tvb, proto_tree *adwin_tree)
{

	if (! adwin_tree)
		return;

	proto_tree_add_item(adwin_tree, hf_adwin_config_pattern, tvb, 0,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_reboot, tvb, 4, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_mac, tvb, 8,  6, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 14, 2, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 16, 80, ENC_NA);
}

static void
dissect_UDPIXP425FlashUpdate(tvbuff_t *tvb, proto_tree *adwin_tree)
{

	if (! adwin_tree)
		return;

	proto_tree_add_item(adwin_tree, hf_adwin_config_pattern, tvb, 0,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_version, tvb, 4,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_scan_id, tvb, 8,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_status, tvb, 12,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_timeout, tvb, 16,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_filename, tvb, 20, 24, ENC_ASCII);
	proto_tree_add_item(adwin_tree, hf_adwin_config_mac, tvb, 44,  6, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, 50, 42, ENC_NA);
}

static void
dissect_UDPOut(tvbuff_t *tvb, proto_tree *adwin_tree)
{

	if (! adwin_tree)
		return;

	proto_tree_add_item(adwin_tree, hf_adwin_config_status, tvb, 0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_mac, tvb, 4,  6, ENC_NA);
	proto_tree_add_item(adwin_tree, hf_adwin_config_netmask, tvb, 10, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_gateway, tvb, 14,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_dhcp, tvb, 18, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_config_port16, tvb, 20,  2, ENC_BIG_ENDIAN);
}

static unsigned
get_adwin_TCPUpdate_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                        int offset, void *data _U_)
{
	/*
	 * Return the length of the packet. (Doesn't include the length field itself)
	 */
	return tvb_get_ntohl(tvb, offset);
}

static int
dissect_TCPFlashUpdate(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *adwin_tree;
	proto_item *ti;
	int length, offset;
	uint8_t *filename;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADwin Config");
	col_set_str(pinfo->cinfo, COL_INFO, "TCPFlashUpdate");

	ti = proto_tree_add_item(tree, proto_adwin_config, tvb, 0, -1, ENC_NA);
	adwin_tree = proto_item_add_subtree(ti, ett_adwin_config);

	proto_tree_add_item(adwin_tree, hf_adwin_config_stream_length, tvb, 0, 4, ENC_BIG_ENDIAN);
	offset = 4;
	length = tvb_strnlen(tvb, offset, -1) + 1;
	filename = tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII|ENC_NA);
	if (strncmp(filename, "eeprom_on", length) == 0) {
		proto_tree_add_boolean(adwin_tree, hf_adwin_config_eeprom_support, tvb, offset, length, true);
		return offset+length;
	}
	if (strncmp(filename, "eeprom_off", length) == 0) {
		proto_tree_add_boolean(adwin_tree, hf_adwin_config_eeprom_support, tvb, offset, length, false);
		return offset+length;
	}
	proto_tree_add_item(adwin_tree, hf_adwin_config_filename, tvb, 4, length, ENC_ASCII);
	offset += length;
	length = tvb_strnlen(tvb, 4 + length, -1) + 1;
	proto_tree_add_item(adwin_tree, hf_adwin_config_path, tvb, offset, length, ENC_ASCII);
	offset += length;
	proto_tree_add_item(adwin_tree, hf_adwin_config_filesize, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(adwin_tree, hf_adwin_config_filetime, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(adwin_tree, hf_adwin_config_updatetime, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(adwin_tree, hf_adwin_config_unused, tvb, offset, 128, ENC_NA);
	offset += 128;
	length = tvb_captured_length_remaining(tvb, offset);
	proto_tree_add_item(adwin_tree, hf_adwin_config_data, tvb, offset, length, ENC_NA);

	return tvb_captured_length(tvb);
}

/* 00:50:c2:0a:2*:** */
static const unsigned char mac_iab_start[] = { 0x00, 0x50, 0xc2, 0x0a, 0x20, 0x00 };
static const unsigned char mac_iab_end[]   = { 0x00, 0x50, 0xc2, 0x0a, 0x2f, 0xff };

/* 00:22:71:**:**:** */
static const unsigned char mac_oui_start[] = { 0x00, 0x22, 0x71, 0x00, 0x00, 0x00 };
static const unsigned char mac_oui_end[]   = { 0x00, 0x22, 0x71, 0xff, 0xff, 0xff };

/* ff:ff:ff:ff:ff:ff */
static const unsigned char mac_broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* return true if mac is in mac address range assigned to ADwin or if
 * mac is broadcast */
static bool
is_adwin_mac_or_broadcast(address mac)
{
	if (mac.type != AT_ETHER)
		return false;

	if (mac.len != 6) /* length of MAC address */
		return false;

	if ((memcmp(mac.data, mac_iab_start, mac.len) >= 0) &&
	    (memcmp(mac.data, mac_iab_end  , mac.len) <= 0))
		return true;

	if ((memcmp(mac.data, mac_oui_start, mac.len) >= 0) &&
	    (memcmp(mac.data, mac_oui_end, mac.len) <= 0))
		return true;

	/* adwin configuration protocol uses MAC broadcasts for
	   device discovery */
	if (memcmp(mac.data, mac_broadcast, mac.len) == 0)
		return true;

	return false;
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

static bool
dissect_adwin_config_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *adwin_config_tree;
	uint32_t length;

	length = tvb_reported_length(tvb);

	if(!(pinfo->srcport == ADWIN_CONFIGURATION_PORT
		|| pinfo->destport == ADWIN_CONFIGURATION_PORT))
		return false;

	if (!(length == UDPStatusLENGTH
	       || length == UDPExtStatusLENGTH
	       || length == UDPMessageLENGTH
	       || length == UDPMessageLENGTH_wrong
	       || length == UDPInitAckLENGTH
	       || length == UDPIXP425FlashUpdateLENGTH
	       || length == UDPOutLENGTH))
		return false;

	if (! (is_adwin_mac_or_broadcast(pinfo->dl_src) || is_adwin_mac_or_broadcast(pinfo->dl_dst)))
		return false;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADwin Config");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_adwin_config, tvb, 0, -1, ENC_NA);
	adwin_config_tree = proto_item_add_subtree(ti, ett_adwin_config);

	switch (length) {
	case UDPStatusLENGTH:
		dissect_UDPStatus(tvb, adwin_config_tree);
		break;
	case UDPExtStatusLENGTH:
		dissect_UDPExtStatus(pinfo, tvb, adwin_config_tree);
		break;
	case UDPMessageLENGTH:
		dissect_UDPMessage(pinfo, tvb, adwin_config_tree);
		break;
	case UDPMessageLENGTH_wrong: /* incorrect packet length */
		/* formerly used by adconfig */
		dissect_UDPMessage(pinfo, tvb, adwin_config_tree);
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
		col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(length, length_mapping,
			"Unknown ADwin Configuration packet, length: %d"));
	}

	return true;
}

static bool
dissect_adwin_config_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if(!(pinfo->srcport == ADWIN_CONFIGURATION_PORT
		|| pinfo->destport == ADWIN_CONFIGURATION_PORT))
		return false;

	/* XXX - Is this possible for TCP? */
	if (! (is_adwin_mac_or_broadcast(pinfo->dl_src) || is_adwin_mac_or_broadcast(pinfo->dl_dst)))
		return false;

	tcp_dissect_pdus(tvb, pinfo, tree, 1, 4, get_adwin_TCPUpdate_len, dissect_TCPFlashUpdate, NULL);

	return true;
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
		    FT_UINT32, BASE_DEC, VALS(config_command_mapping), 0x0,
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
		{ &hf_adwin_config_filetime,
		  { "File time", "adwin_config.filetime",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_updatetime,
		  { "Update time", "adwin_config.updatetime",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
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
		    FT_IPv4, BASE_NETMASK, NULL, 0x0,
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
		    FT_UINT32, BASE_HEX, VALS(pattern_mapping), 0x0,
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
		{ &hf_adwin_config_processor_type_raw,
		  { "Processor Type (Raw value)", "adwin_config.processor_type_raw",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The DSP processor type of the ADwin system, e.g. T9, T10 or T11.", HFILL }
		},
		{ &hf_adwin_config_system_type_raw,
		  { "System Type (Raw value)", "adwin_config.system_type_raw",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The system type of the ADwin system, e.g. Gold, Pro or Light.", HFILL }
		},
		{ &hf_adwin_config_processor_type,
		  { "Processor Type", "adwin_config.processor_type",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_config_system_type,
		  { "System Type", "adwin_config.system_type",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
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
		{ &hf_adwin_config_eeprom_support,
		  { "EEPROM Support", "adwin_config.eeprom_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x0,
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
	static int *ett[] = {
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
	heur_dissector_add("udp", dissect_adwin_config_udp, "ADwin-Config over UDP", "adwin_config_udp", proto_adwin_config, HEURISTIC_ENABLE);
	heur_dissector_add("tcp", dissect_adwin_config_tcp, "ADwin-Config over TCP", "adwin_config_tcp", proto_adwin_config, HEURISTIC_ENABLE);
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
