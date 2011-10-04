/* packet-3com-njack.c
 * Routines for the disassembly of the 3com NetworkJack management protocol
 *
 * $Id$
 *
 * Copyright 2005 Joerg Mayer (see AUTHORS file)
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

/*
  TODO:
  - Find out lots more values :-)
  - Support for other 3com devices that use the same protocol
  - Do any devices use TCP or different ports?
  - Sanity checks for tlv_length depending on tlv_type
  - Search and fix XXX comments in the code
  - Proper descriptions in hf_ fields

Specs:
	No specs available. All knowledge gained by looking at traffic dumps
	Packets to Managementstation: PORT_NJACK_PC (5264)
	Packets to Switch: PORT_NJACK_SWITCH (5265)

	Type 0x00? (localquery):	  M -> BC, Magic, type, 'LOCALQUERY'?
	Type 0x01 (query):                M -> S, Magic, type, 'QUERY'
	Type 0x02 (query resp):		  S -> M, Magic, type, tlv-list (end: ffxx)
	Type 0x04 ??? (after query resp): M -> S, Magic, type, 0x43AAD406
	Type 0x07 (set):                  M -> S, Magic, type, length (16 bit be)
	Type 0x08 (set resp):             S -> M, Magic, type, net length (8 bit), result status
	Type 0x0b (get):                  M -> S, Magic, type, 00 00 63 ff
	Type 0x0c (get resp):             S -> M, Magic, type, T(8 bit) L(8 bit) V(L bytes)
	Type 0x0d (dhcpinfo):             S -> M, Magic, type, tlv, t=00 = last (no length)
	Type 0x10 (clear counters):       M -> S, Magic, type, 0400
	Type 0x10 (clear counters resp):  M -> S, Magic, type, 00
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>


/* protocol handles */
static int proto_njack = -1;

/* ett handles */
static int ett_njack = -1;
static int ett_njack_tlv_header = -1;

/* hf elements */
static int hf_njack_magic = -1;
static int hf_njack_type = -1;
/* type set/get response */
static int hf_njack_tlv_length = -1;
static int hf_njack_tlv_data = -1;
static int hf_njack_tlv_version = -1;
static int hf_njack_tlv_type = -1;
static int hf_njack_tlv_typeip = -1;
static int hf_njack_tlv_devicemac = -1;
static int hf_njack_tlv_snmpwrite = -1;
static int hf_njack_tlv_dhcpcontrol = -1;
static int hf_njack_tlv_typestring = -1;
/* 1st TAB */
static int hf_njack_tlv_countermode = -1;
static int hf_njack_tlv_scheduling = -1;
static int hf_njack_tlv_addtagscheme = -1;
static int hf_njack_tlv_portingressmode = -1;
static int hf_njack_tlv_maxframesize = -1;
static int hf_njack_tlv_powerforwarding = -1;
/* type 07: set */
static int hf_njack_set_length = -1;
static int hf_njack_set_salt = -1;
static int hf_njack_set_authdata = -1;
/* type 08: set result */
static int hf_njack_setresult = -1;
/* type 0b: get */
/* type 0c: get response */
static int hf_njack_getresp_unknown1 = -1;

#define PROTO_SHORT_NAME "NJACK"
#define PROTO_LONG_NAME "3com Network Jack"

#define PORT_NJACK_PC	5264
#define PORT_NJACK_SWITCH	5265

typedef enum {
	NJACK_TYPE_QUERY	= 0x01,
	NJACK_TYPE_QUERYRESP	= 0x02,
	/* type 0x04 exists - see specs sections */
	NJACK_TYPE_SET		= 0x07,
	NJACK_TYPE_SETRESULT	= 0x08,

	NJACK_TYPE_GET		= 0x0b,
	NJACK_TYPE_GETRESP	= 0x0c,

	NJACK_TYPE_DHCPINFO	= 0x0d,

	NJACK_TYPE_CLEARCOUNTER	= 0x10,
	NJACK_TYPE_COUNTERRESP	= 0x11
} njack_type_t;

static const value_string njack_type_vals[] = {
	{ NJACK_TYPE_SET,		"Set"},
	{ NJACK_TYPE_SETRESULT,		"Set result"},
	{ NJACK_TYPE_QUERY,		"Query (discovery)"},
	{ NJACK_TYPE_QUERYRESP,		"Query response"},
	{ NJACK_TYPE_GET,		"Get"},
	{ NJACK_TYPE_GETRESP,		"Get response"},
	{ NJACK_TYPE_DHCPINFO,		"DHCP info\?\?"},
	{ NJACK_TYPE_CLEARCOUNTER,	"Clear counters\?\?"},
	{ NJACK_TYPE_COUNTERRESP,	"Clear counters response\?\?"},

	{ 0,	NULL }
};

typedef enum {
	NJACK_CMD_STARTOFPARAMS		= 0x00,
	NJACK_CMD_MACADDRESS		= 0x01,
	NJACK_CMD_IPADDRESS		= 0x02,
	NJACK_CMD_NETWORK		= 0x03,
	NJACK_CMD_MASK			= 0x04,
	NJACK_CMD_MAXFRAMESIZE		= 0x05,
	NJACK_CMD_COUNTERMODE		= 0x06,
	NJACK_CMD_QUEUEING		= 0x0a,
	NJACK_CMD_ADDTAGSCHEME		= 0x0b,
	NJACK_CMD_REMOVETAG		= 0x0c,
	NJACK_CMD_GROUP			= 0x0d,
	NJACK_CMD_LOCATION		= 0x0e,
	NJACK_CMD_VERSION		= 0x0f,
	NJACK_CMD_PORT1			= 0x13,
	NJACK_CMD_PORT2			= 0x14,
	NJACK_CMD_PORT3			= 0x15,
	NJACK_CMD_PORT4			= 0x16,
	NJACK_CMD_PASSWORD		= 0x19,
	NJACK_CMD_ENABLESNMPWRITE	= 0x1a,
	NJACK_CMD_ROCOMMUNITY		= 0x1b,
	NJACK_CMD_RWCOMMUNITY		= 0x1c,
	NJACK_CMD_POWERFORWARDING	= 0x1e,
	NJACK_CMD_DHCPCONTROL		= 0x1f,
	NJACK_CMD_IPGATEWAY		= 0x20,
	NJACK_CMD_SNMPTRAP		= 0x23,
	NJACK_CMD_COLDSTARTTRAP		= 0x26,
	NJACK_CMD_LINKDOWNTRAP		= 0x27,
	NJACK_CMD_LINKUPTRAP		= 0x28,
	NJACK_CMD_AUTHFAILTRAP		= 0x29,
	NJACK_CMD_PRODUCTNAME		= 0x2a,
	NJACK_CMD_SERIALNO		= 0x2b,
	NJACK_CMD_GETALLPARMAMS		= 0x63,
	NJACK_CMD_ENDOFPACKET		= 0xff
} njack_cmd_type_t;

static const value_string njack_cmd_vals[] = {
	{ NJACK_CMD_STARTOFPARAMS,	"Start of Parameters" },
	{ NJACK_CMD_MACADDRESS,		"MAC address" },
	{ NJACK_CMD_IPADDRESS,		"IP address" },
	{ NJACK_CMD_NETWORK,		"IP network" },
	{ NJACK_CMD_MASK,		"IP netmask" },
	{ NJACK_CMD_MAXFRAMESIZE,	"Max frame size" },
	{ NJACK_CMD_COUNTERMODE,	"Countermode" },
	{ NJACK_CMD_QUEUEING,		"Priority scheduling policy" },
	{ NJACK_CMD_ADDTAGSCHEME,	"Add tag scheme" },
	{ NJACK_CMD_REMOVETAG,		"Remove tag" },
	{ NJACK_CMD_GROUP,		"Device group" },
	{ NJACK_CMD_LOCATION,		"Location" },
	{ NJACK_CMD_VERSION,		"Firmware version" },
	{ NJACK_CMD_PORT1,		"Port 1" },
	{ NJACK_CMD_PORT2,		"Port 2" },
	{ NJACK_CMD_PORT3,		"Port 3" },
	{ NJACK_CMD_PORT4,		"Port 4" },
	{ NJACK_CMD_PASSWORD,		"Device password" },
	{ NJACK_CMD_ENABLESNMPWRITE,	"SNMP write enable" },
	{ NJACK_CMD_ROCOMMUNITY,	"RO community" },
	{ NJACK_CMD_RWCOMMUNITY,	"RW community" },
	{ NJACK_CMD_POWERFORWARDING,	"Port power forwarding" },
	{ NJACK_CMD_DHCPCONTROL,	"DHCP control" },
	{ NJACK_CMD_IPGATEWAY,		"IP gateway" },
	{ NJACK_CMD_SNMPTRAP,		"SNMP trap" },
	{ NJACK_CMD_COLDSTARTTRAP,	"Coldstart trap" },
	{ NJACK_CMD_LINKDOWNTRAP,	"Linkdown trap" },
	{ NJACK_CMD_LINKUPTRAP,		"Linkup trap" },
	{ NJACK_CMD_AUTHFAILTRAP,	"Auth fail trap" },
	{ NJACK_CMD_PRODUCTNAME,	"Product name" },
	{ NJACK_CMD_SERIALNO,		"Serial no" },
	{ NJACK_CMD_GETALLPARMAMS,	"Get all parameters" },
	{ NJACK_CMD_ENDOFPACKET,	"End of packet" },

	{ 0,	NULL }
};

typedef enum {
	NJACK_SETRESULT_SUCCESS		= 0x01,
	NJACK_SETRESULT_FAILAUTH	= 0xFD
} njack_setresult_t;

static const value_string njack_setresult_vals[] = {
	{ NJACK_SETRESULT_SUCCESS,	"Success" },
	{ NJACK_SETRESULT_FAILAUTH,	"Failauth" },

	{ 0,	NULL }
};

/* General settings TAB */
static const value_string njack_dhcpcontrol[] = {
	{ 0,	"Disable" },
	{ 1,	"Enable" },

	{ 0,	NULL }
};
/* End General settings TAB */

/* Port settings TAB */
#if 0
static const true_false_string tfs_port_state = {
	"Disable",
	"Enable"
};

static const true_false_string tfs_port_autoneg = {
	"Manual",
	"Auto negotiation"
};

static const true_false_string tfs_port_speed = {
	"10Mbps",
	"100Mbps"
};

static const true_false_string tfs_port_duplex = {
	"halfduplex",
	"duplex"
};

#endif
/* End Port settings TAB */

/* Hardware Settings TAB */
static const value_string njack_scheduling[] = {
	{ 0,	"Weighted fair" },
	{ 1,	"Strict priority" },

	{ 0,	NULL }
};

static const value_string njack_addtagscheme[] = {
	{ 0,	"Frames transmitted unmodified" },
	{ 1,	"Add tag to untagged frame" },

	{ 0,	NULL }
};

static const value_string njack_portingressmode[] = {
	{ 0,	"Receive unmodified" },
	{ 1,	"Remove tag if present" },

	{ 0,	NULL }
};

static const value_string njack_maxframesize[] = {
	{ 0,	"1522 tagged, 1518 untagged" },
	{ 1,	"1535" },

	{ 0,	NULL }
};

static const value_string njack_countermode[] = {
	{ 0,	"Count Rx, Tx Good frames" },
	{ 1,	"RX errors, TX collisions" },

	{ 0,	NULL }
};

static const value_string njack_powerforwarding[] = {
	{ 1,	"OFF" },
	{ 2,	"ON" },
	/* XXX find out correct value */
	{ 3,	"802.3af" },

	{ 0,	NULL }
};
/* End Hardware Settings TAB */

/* SNMP TAB */
static const value_string njack_snmpwrite[] = {
	{ 0,	"Disable" },
	{ 1,	"Enable" },

	{ 0,	NULL }
};

#if 0
static const value_string njack_snmptrap[] = {
	{ 0,	"Disable" },
	{ 1,	"Enable" },

	{ 0,	NULL }
};

static const value_string njack_coldstarttrap[] = {
	{ 0,	"Disable" },
	{ 1,	"Enable" },

	{ 0,	NULL }
};

static const value_string njack_linkdowntrap[] = {
	{ 0,	"Disable" },
	{ 1,	"Enable" },

	{ 0,	NULL }
};

static const value_string njack_linkuptrap[] = {
	{ 0,	"Disable" },
	{ 1,	"Enable" },

	{ 0,	NULL }
};

static const value_string njack_authfailtrap[] = {
	{ 0,	"Disable" },
	{ 1,	"Enable" },

	{ 0,	NULL }
};
#endif
/* End SNMP TAB */

static int
dissect_portsettings(tvbuff_t *tvb, proto_tree *port_tree, guint32 offset)
{
	/* XXX This is still work in progress, the information here
	 *     may be wrong and is obviously incomplete
	 *  Structure: 8 bytes, total 64 bits.
	 *
	 * Bytes 0-1: select feature
	 *       2-7: feature values
	 *  Feature		Indicator	Valuebit(s)
	 *  ------------------------------------------------------------
	 *  Port Vlan		0x8000		0x0000 0078 0000 (bits: port 4 ... 1)
	 *  Prio (hw queue)	0x4000		0x0000 0006 0000
	 *  MC rate limit	0x1000		0x0000 6000 0000 (0:3, 1:6, 2:12, 3:100%)
	 *  Speed/Duplex	0x0c00		XXX don't know which bit is speed / duplex
	 *					0x0000 0800 0000 (duplex 0 half, 1 full)
	 * 					0x0000 1000 0000 (speed 0 10M, 1 100M)
	 *  Port Ena		0x0100		0x0000 0300 0000 (1 dis, 3 ena)
	 *  Auto neg 	 	0x0008 		0x0000 0000 0800 (0 man, 1 auto)
	 *  Vlan number 	0x0004 		0xff0f 0000 0000 (le)
	 * XXX evaluate the following stuff:
	 *  Flowcontrol		0x0001		0x0000 0000 0200 ???
	 *  Flowcontrol		0x0001		0x0100 83f1 0a00 <- recorded
	 *  Auto Mdi		0x0002		0x0000 0000 0300 (1 man, 2 auto)
	 *  Manual MDI		0x0002		0x0100 8371 0900 <- recorded
	 *  Manual MDI-X	0x0002		0x0100 8371 0800 <- recorded
	 *  Auto MDI-X
	 */
	proto_tree_add_item(port_tree, hf_njack_tlv_data,
		tvb, offset, 8, ENC_NA);
	return offset;
}

static int
dissect_tlvs(tvbuff_t *tvb, proto_tree *njack_tree, guint32 offset)
{
	guint8 tlv_type;
	guint8 tlv_length;
	proto_item *tlv_item;
	proto_item *tlv_tree;

	for (;;) {
		tlv_type = tvb_get_guint8(tvb, offset);
		/* Special cases that don't have a length field */
		if (tlv_type == NJACK_CMD_ENDOFPACKET) {
			proto_tree_add_item(njack_tree, hf_njack_tlv_type,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		}
		if (tlv_type == NJACK_CMD_GETALLPARMAMS) {
			proto_tree_add_item(njack_tree, hf_njack_tlv_type,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			continue;
		}
		tlv_length = tvb_get_guint8(tvb, offset + 1);
		tlv_item = proto_tree_add_text(njack_tree, tvb,
			offset, tlv_length + 2,
			"T %02x, L %02x: %s",
			tlv_type,
			tlv_length,
			val_to_str(tlv_type, njack_cmd_vals, "Unknown"));
		tlv_tree = proto_item_add_subtree(tlv_item,
			ett_njack_tlv_header);
		proto_tree_add_item(tlv_tree, hf_njack_tlv_type,
			tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tlv_tree, hf_njack_tlv_length,
			tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		switch (tlv_type) {
		case NJACK_CMD_STARTOFPARAMS:
			break;
		case NJACK_CMD_COUNTERMODE:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_countermode,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_QUEUEING:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_scheduling,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_ADDTAGSCHEME:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_addtagscheme,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_REMOVETAG:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_portingressmode,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_MAXFRAMESIZE:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_maxframesize,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_ENABLESNMPWRITE:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_snmpwrite,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_POWERFORWARDING:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_powerforwarding,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_DHCPCONTROL:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_dhcpcontrol,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_CMD_MACADDRESS:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_devicemac,
				tvb, offset, 6, ENC_BIG_ENDIAN);
			offset += 6;
			break;
		case NJACK_CMD_VERSION:
			/* XXX Don't misuse ip address printing here */
			proto_tree_add_item(tlv_tree, hf_njack_tlv_version,
				tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		case NJACK_CMD_IPADDRESS:
		case NJACK_CMD_NETWORK:
		case NJACK_CMD_MASK:
		case NJACK_CMD_IPGATEWAY:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typeip,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case NJACK_CMD_GROUP:
		case NJACK_CMD_LOCATION:
		case NJACK_CMD_PASSWORD:
		case NJACK_CMD_ROCOMMUNITY:
		case NJACK_CMD_RWCOMMUNITY:
		case 0x25: /* ? */
		case NJACK_CMD_PRODUCTNAME:
		case NJACK_CMD_SERIALNO:
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typestring,
				tvb, offset, tlv_length, ENC_BIG_ENDIAN);
			offset += tlv_length;
			break;
		case NJACK_CMD_PORT1:
		case NJACK_CMD_PORT2:
		case NJACK_CMD_PORT3:
		case NJACK_CMD_PORT4:
			if (tlv_length == 8) {
				dissect_portsettings(tvb, tlv_tree, offset);
			}
			offset += tlv_length;
			break;
		default:
			if (tlv_length != 0) {
				proto_tree_add_item(tlv_tree, hf_njack_tlv_data,
					tvb, offset, tlv_length, ENC_NA);
				offset += tlv_length;
			}
			break;
		}
	}
	return offset;
}

#if 0
#include <epan/crypt/crypt-md5.h>

static gboolean
verify_password(tvbuff_t *tvb, const char *password)
{
	/* 1. pad non-terminated password-string to a length of 32 bytes
	 *    (padding: 0x01, 0x02, 0x03...)
         * 2. Calculate MD5 of padded password and write it to offset 12 of packet
         * 3. Calculate MD5 of resulting packet and write it to offset 12 of packet
	 */

	gboolean is_valid = TRUE;
	const guint8	*packetdata;
	guint32 length;
	guint8	*workbuffer;
	guint	i;
	guint8	byte;
	md5_state_t md_ctx;
	md5_byte_t *digest;

	workbuffer=ep_alloc(32);
	digest=ep_alloc(16);

	length = tvb_get_ntohs(tvb, 6);
	packetdata = tvb_get_ptr(tvb, 0, length);
	for (i = 0; i<32 && *password; i++, password++) {
		workbuffer[i] = *password;
	}
	for (byte = 1; i<32; i++, byte++) {
		workbuffer[i] = byte;
	}
	md5_init(&md_ctx);
	md5_append(&md_ctx, workbuffer, 32);
	md5_finish(&md_ctx, digest);
	md5_init(&md_ctx);
	md5_append(&md_ctx, packetdata, 12);
	md5_append(&md_ctx, digest, 16);
	md5_append(&md_ctx, packetdata + 28, length - 28);
	md5_finish(&md_ctx, digest);
	fprintf(stderr, "Calculated digest: "); /* debugging */
	for (i = 0; i < 16; i++) {
		fprintf(stderr, "%02X", digest[i]); /* debugging */
		if (digest[i] != *(packetdata + 12 + i)) {
			is_valid = FALSE;
			break;
		}
	}
	fprintf(stderr, " (%d)\n", is_valid); /* debugging */

	return is_valid;
}
#endif

static int
dissect_njack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *njack_tree = NULL;
	guint32 offset = 0;
	guint8 packet_type;
	guint8 setresult;
	gint remaining;

	packet_type = tvb_get_guint8(tvb, 5);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
 	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(packet_type, njack_type_vals, "Type 0x%02x"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_njack, tvb, offset, -1,
		    ENC_BIG_ENDIAN);
		njack_tree = proto_item_add_subtree(ti, ett_njack);

		proto_tree_add_item(njack_tree, hf_njack_magic, tvb, offset, 5,
			ENC_BIG_ENDIAN);
		offset += 5;

		proto_tree_add_item(njack_tree, hf_njack_type, tvb, offset, 1,
			ENC_BIG_ENDIAN);
		offset += 1;
		switch (packet_type) {
		case NJACK_TYPE_SET:
			/* Type 0x07: S -> M, Magic, type, length (16 bit be) */
			proto_tree_add_item(njack_tree, hf_njack_set_length, tvb, offset,
				2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(njack_tree, hf_njack_set_salt, tvb, offset,
				4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(njack_tree, hf_njack_set_authdata, tvb, offset,
				16, ENC_NA);
			offset += 16;
			offset = dissect_tlvs(tvb, njack_tree, offset);
			break;
		case NJACK_TYPE_SETRESULT:
			/* Type 0x08: M -> S, Magic, type, setresult (8 bit) */
			setresult = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(njack_tree, hf_njack_setresult, tvb, offset,
				1, ENC_BIG_ENDIAN);
			offset += 1;
			col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(setresult, njack_setresult_vals, "[0x%02x]"));
			break;
		case NJACK_TYPE_GET:
			/* Type 0x0b: S -> M, Magic, type, 00 00 63 ff */
			offset = dissect_tlvs(tvb, njack_tree, offset);
			break;
		case NJACK_TYPE_QUERYRESP:
			/* Type 0x02: M -> S, Magic, type, T(8 bit) L(8 bit) V(L bytes) */
		case NJACK_TYPE_GETRESP:
			/* Type 0x0c: M -> S, Magic, type, T(8 bit) L(8 bit) V(L bytes) */
			offset = dissect_tlvs(tvb, njack_tree, offset);
			proto_tree_add_item(njack_tree, hf_njack_getresp_unknown1, tvb, offset,
				1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		case NJACK_TYPE_DHCPINFO: /* not completely understood */
		default:
			/* Unknown type */
			remaining = tvb_reported_length_remaining(tvb, offset);
			if (remaining > 0) {
				proto_tree_add_item(njack_tree, hf_njack_tlv_data,
					tvb, offset, remaining, ENC_NA);
				offset += remaining;
			}
			break;
		}
	}
	return offset;
}

static gboolean
test_njack(tvbuff_t *tvb)
{
	/* We need at least 'NJ200' + 1 Byte packet type */
	if ( (tvb_length(tvb) < 6) ||
	     (tvb_strncaseeql(tvb, 0, "NJ200", 5) != 0) ) {
		return FALSE;
	}
	return TRUE;
}

static gboolean
dissect_njack_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_njack(tvb) ) {
		return FALSE;
	}
	dissect_njack(tvb, pinfo, tree);
	return TRUE;
}

static int
dissect_njack_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_njack(tvb) ) {
		return 0;
	}
	return dissect_njack(tvb, pinfo, tree);
}

void
proto_register_njack(void)
{
	static hf_register_info hf[] = {

	/* NJACK header */
		{ &hf_njack_magic,
		{ "Magic",	"njack.magic", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_njack_type,
		{ "Type",	"njack.type", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

	/* TLV fields */
		{ &hf_njack_tlv_type,
		{ "TlvType",	"njack.tlv.type", FT_UINT8, BASE_HEX, VALS(njack_cmd_vals),
			0x0, NULL, HFILL }},

		{ &hf_njack_tlv_length,
		{ "TlvLength",	"njack.tlv.length", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

                { &hf_njack_tlv_data,
                { "TlvData",   "njack.tlv.data", FT_BYTES, BASE_NONE, NULL,
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_version,
                { "TlvFwVersion",   "njack.tlv.version", FT_IPv4, BASE_NONE, NULL,
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_snmpwrite,
                { "TlvTypeSnmpwrite",   "njack.tlv.snmpwrite", FT_UINT8, BASE_DEC, VALS(njack_snmpwrite),
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_dhcpcontrol,
                { "TlvTypeDhcpControl",   "njack.tlv.dhcpcontrol", FT_UINT8, BASE_DEC, VALS(njack_dhcpcontrol),
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_devicemac,
                { "TlvTypeDeviceMAC",   "njack.tlv.devicemac", FT_ETHER, BASE_NONE, NULL,
                        0x0, NULL, HFILL }},

		/* XXX dummy entries, to be replaced */
                { &hf_njack_tlv_typeip,
                { "TlvTypeIP",   "njack.tlv.typeip", FT_IPv4, BASE_NONE, NULL,
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_typestring,
                { "TlvTypeString",   "njack.tlv.typestring", FT_STRING, BASE_NONE, NULL,
                        0x0, NULL, HFILL }},

		/* 1st tab */
                { &hf_njack_tlv_scheduling,
                { "TlvTypeScheduling",   "njack.tlv.scheduling", FT_UINT8, BASE_DEC, VALS(njack_scheduling),
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_addtagscheme,
                { "TlvAddTagScheme",   "njack.tlv.addtagscheme", FT_UINT8, BASE_DEC, VALS(njack_addtagscheme),
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_portingressmode,
                { "TlvTypePortingressmode",   "njack.tlv.portingressmode", FT_UINT8, BASE_DEC, VALS(njack_portingressmode),
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_maxframesize,
                { "TlvTypeMaxframesize",   "njack.tlv.maxframesize", FT_UINT8, BASE_DEC, VALS(njack_maxframesize),
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_countermode,
                { "TlvTypeCountermode",   "njack.tlv.countermode", FT_UINT8, BASE_DEC, VALS(njack_countermode),
                        0x0, NULL, HFILL }},

                { &hf_njack_tlv_powerforwarding,
                { "TlvTypePowerforwarding",   "njack.tlv.powerforwarding", FT_UINT8, BASE_DEC, VALS(njack_powerforwarding),
                        0x0, NULL, HFILL }},

	/* Type 0x07: set */
		{ &hf_njack_set_length,
		{ "SetLength",	"njack.set.length", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_njack_set_salt,
		{ "Salt",	"njack.set.salt", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

                { &hf_njack_set_authdata,
                { "Authdata",   "njack.tlv.authdata", FT_BYTES, BASE_NONE, NULL,
                        0x0, NULL, HFILL }},

	/* Type 0x08: set result */
                { &hf_njack_setresult,
                { "SetResult",   "njack.setresult", FT_UINT8, BASE_HEX, VALS(njack_setresult_vals),
                        0x0, NULL, HFILL }},

	/* Type 0x0b get */

	/* Type 0x0c get response */
		{ &hf_njack_getresp_unknown1,
		{ "Unknown1",	"njack.getresp.unknown1", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

        };
	static gint *ett[] = {
		&ett_njack,
		&ett_njack_tlv_header,
	};

        proto_njack = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "njack");
        proto_register_field_array(proto_njack, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_njack(void)
{
	dissector_handle_t njack_handle;

	njack_handle = new_create_dissector_handle(dissect_njack_static, proto_njack);
	dissector_add_uint("udp.port", PORT_NJACK_PC, njack_handle);
	/* dissector_add_uint("tcp.port", PORT_NJACK_PC, njack_handle); */
	dissector_add_uint("udp.port", PORT_NJACK_SWITCH, njack_handle);
	/* dissector_add_uint("tcp.port", PORT_NJACK_SWITCH, njack_handle); */

        heur_dissector_add("udp", dissect_njack_heur, proto_njack);
        /* heur_dissector_add("tcp", dissect_njack_heur, proto_njack); */
}

