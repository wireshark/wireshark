/* Packet-rdp_rail.c
 * Routines for the RAIL RDP channel
 * Copyright 2023, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See: "[MS-RDPERP] "
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/value_string.h>

#include "packet-rdpudp.h"

#define PNAME  "RDP Program virtual channel Protocol"
#define PSNAME "RAIL"
#define PFNAME "rdp_rail"

void proto_register_rdp_rail(void);
void proto_reg_handoff_rdp_rail(void);


static int proto_rdp_rail;

static int hf_rail_orderType;
static int hf_rail_pduLength;

static int hf_rail_caps_handshake_buildNumber;

static int hf_rail_windowId;
static int hf_rail_windowmove_left;
static int hf_rail_windowmove_top;
static int hf_rail_windowmove_right;
static int hf_rail_windowmove_bottom;

static int hf_rail_notify_iconId;
static int hf_rail_notify_message;

static int hf_rail_localmovesize_isMoveSizeStart;
static int hf_rail_localmovesize_moveSizeType;
static int hf_rail_localmovesize_posX;
static int hf_rail_localmovesize_posY;

static int hf_rail_minmaxinfo_maxwidth;
static int hf_rail_minmaxinfo_maxheight;
static int hf_rail_minmaxinfo_maxPosX;
static int hf_rail_minmaxinfo_maxPosY;
static int hf_rail_minmaxinfo_minTrackWidth;
static int hf_rail_minmaxinfo_minTrackHeight;
static int hf_rail_minmaxinfo_maxTrackWidth;
static int hf_rail_minmaxinfo_maxTrackHeight;

static int hf_rail_cloak_cloaked;

static int hf_rail_handshake_flags;
static int hf_rail_handshake_flags_hidef;
static int hf_rail_handshake_flags_ex_spi;
static int hf_rail_handshake_flags_snap;
static int hf_rail_handshake_flags_textscale;
static int hf_rail_handshake_flags_caretblink;
static int hf_rail_handshake_flags_ex_spi2;

static int hf_rail_cstatus_flags;
static int hf_rail_cstatus_flags_allowlocalmove;
static int hf_rail_cstatus_autoreconnect;
static int hf_rail_cstatus_zorder_sync;
static int hf_rail_cstatus_resize_margin;
static int hf_rail_cstatus_hidpi_icons;
static int hf_rail_cstatus_appbar_remoting;
static int hf_rail_cstatus_powerdisplay;
static int hf_rail_cstatus_bidir_cloak;
static int hf_rail_cstatus_suppress_icon_border;

static int hf_rail_activate_enabled;

static int hf_rail_sysparam_server_params;
static int hf_rail_sysparam_client_params;

static int ett_rdp_rail;
static int ett_rdp_rail_handshake_flags;
static int ett_rdp_rail_clientstatus_flags;

enum {
	TS_RAIL_ORDER_EXEC = 0x01,
	TS_RAIL_ORDER_ACTIVATE = 0x02,
	TS_RAIL_ORDER_SYSPARAM = 0x03,
	TS_RAIL_ORDER_SYSCOMMAND = 0x04,
	TS_RAIL_ORDER_HANDSHAKE = 0x05,
	TS_RAIL_ORDER_NOTIFY_EVENT = 0x06,
	TS_RAIL_ORDER_WINDOWMOVE = 0x08,
	TS_RAIL_ORDER_LOCALMOVESIZE = 0x09,
	TS_RAIL_ORDER_MINMAXINFO = 0x0a,
	TS_RAIL_ORDER_CLIENTSTATUS = 0x0b,
	TS_RAIL_ORDER_SYSMENU = 0x0c,
	TS_RAIL_ORDER_LANGBARINFO = 0x0d,
	TS_RAIL_ORDER_EXEC_RESULT = 0x80,
	TS_RAIL_ORDER_GET_APPID_REQ = 0x0e,
	TS_RAIL_ORDER_GET_APPID_RESP = 0x0f,
	TS_RAIL_ORDER_TASKBARINFO = 0x10,
	TS_RAIL_ORDER_LANGUAGEIMEINFO = 0x11,
	TS_RAIL_ORDER_COMPARTMENTINFO = 0x12,
	TS_RAIL_ORDER_HANDSHAKE_EX = 0X13,
	TS_RAIL_ORDER_ZORDER_SYNC = 0x14,
	TS_RAIL_ORDER_CLOAK = 0x15,
	TS_RAIL_ORDER_POWER_DISPLAY_REQUEST = 0x16,
	TS_RAIL_ORDER_SNAP_ARRANGE = 0x17,
	TS_RAIL_ORDER_GET_APPID_RESP_EX = 0x18,
	TS_RAIL_ORDER_TEXTSCALEINFO = 0x19,
	TS_RAIL_ORDER_CARETBLINKINFO = 0x1a
};

enum {
	SPI_SETSCREENSAVEACTIVE = 0x00000011,
	SPI_SETSCREENSAVESECURE = 0x00000077,

	SPI_SETDRAGFULLWINDOWS = 0x00000025,
	SPI_SETKEYBOARDCUES = 0x0000100B,
	SPI_SETKEYBOARDPREF = 0x00000045,
	SPI_SETWORKAREA = 0x0000002F,
	RAIL_SPI_DISPLAYCHANGE = 0x0000F001,
	SPI_SETMOUSEBUTTONSWAP = 0x00000021,
	RAIL_SPI_TASKBARPOS = 0x0000F000,
	SPI_SETHIGHCONTRAST = 0x00000043,
	SPI_SETCARETWIDTH = 0x00002007,
	SPI_SETSTICKYKEYS = 0x0000003B,
	SPI_SETTOGGLEKEYS = 0x00000035,
	SPI_SETFILTERKEYS = 0x00000033,
	RAIL_SPI_DISPLAY_ANIMATIONS_ENABLED = 0x0000F002,
	RAIL_SPI_DISPLAY_ADVANCED_EFFECTS_ENABLED = 0x0000F003,
	RAIL_SPI_DISPLAY_AUTO_HIDE_SCROLLBARS = 0x0000F004,
	RAIL_SPI_DISPLAY_MESSAGE_DURATION = 0x0000F005,
	RAIL_SPI_CLOSED_CAPTION_FONT_COLOR = 0x0000F006,
	RAIL_SPI_CLOSED_CAPTION_FONT_OPACITY = 0x0000F007,
	RAIL_SPI_CLOSED_CAPTION_FONT_SIZE = 0x0000F008,
	RAIL_SPI_CLOSED_CAPTION_FONT_STYLE = 0x0000F009,
	RAIL_SPI_CLOSED_CAPTION_FONT_EDGE_EFFECT = 0x0000F00A,
	RAIL_SPI_CLOSED_CAPTION_BACKGROUND_COLOR = 0x0000F00B,
	RAIL_SPI_CLOSED_CAPTION_BACKGROUND_OPACITY = 0x0000F00C,
	RAIL_SPI_CLOSED_CAPTION_REGION_COLOR = 0x0000F00D,
	RAIL_SPI_CLOSED_CAPTION_REGION_OPACITY = 0x0000F00E,
};

static const value_string rdp_rail_order_vals[] = {
	{ TS_RAIL_ORDER_EXEC, "Execute"},
	{ TS_RAIL_ORDER_ACTIVATE, "Activate"},
	{ TS_RAIL_ORDER_SYSPARAM, "Client system parameters"},
	{ TS_RAIL_ORDER_SYSCOMMAND, "System command"},
	{ TS_RAIL_ORDER_HANDSHAKE, "Handshake"},
	{ TS_RAIL_ORDER_NOTIFY_EVENT, "Notify event"},
	{ TS_RAIL_ORDER_WINDOWMOVE, "Window move"},
	{ TS_RAIL_ORDER_LOCALMOVESIZE, "Local move size"},
	{ TS_RAIL_ORDER_MINMAXINFO, "MinMax info"},
	{ TS_RAIL_ORDER_CLIENTSTATUS, "Client status"},
	{ TS_RAIL_ORDER_SYSMENU, "System menu"},
	{ TS_RAIL_ORDER_LANGBARINFO, "Language bar info"},
	{ TS_RAIL_ORDER_EXEC_RESULT, "Exec result"},
	{ TS_RAIL_ORDER_GET_APPID_REQ, "Get appId request"},
	{ TS_RAIL_ORDER_GET_APPID_RESP, "Get appId response"},
	{ TS_RAIL_ORDER_TASKBARINFO, "Taskbar info"},
	{ TS_RAIL_ORDER_LANGUAGEIMEINFO, "Language IME info"},
	{ TS_RAIL_ORDER_COMPARTMENTINFO, "Compartment info"},
	{ TS_RAIL_ORDER_HANDSHAKE_EX, "HandshakeEx"},
	{ TS_RAIL_ORDER_ZORDER_SYNC, "Z-order sync"},
	{ TS_RAIL_ORDER_CLOAK, "Cloak"},
	{ TS_RAIL_ORDER_POWER_DISPLAY_REQUEST, "Power display requet"},
	{ TS_RAIL_ORDER_SNAP_ARRANGE, "Snap arrange"},
	{ TS_RAIL_ORDER_GET_APPID_RESP_EX, "Get appId response"},
	{ TS_RAIL_ORDER_TEXTSCALEINFO, "Text scale info"},
	{ TS_RAIL_ORDER_CARETBLINKINFO, "Caret blink info"},
	{ 0x0, NULL},
};

static const value_string moveSizeStart_vals[] = {
	{ 0x0001, "RAIL_WMSZ_LEFT" },
	{ 0x0002, "RAIL_WMSZ_RIGHT" },
	{ 0x0003, "RAIL_WMSZ_TOP" },
	{ 0x0004, "RAIL_WMSZ_TOPLEFT" },
	{ 0x0005, "RAIL_WMSZ_TOPRIGHT" },
	{ 0x0006, "RAIL_WMSZ_BOTTOM" },
	{ 0x0007, "RAIL_WMSZ_BOTTOMLEFT" },
	{ 0x0008, "RAIL_WMSZ_BOTTOMRIGHT" },
	{ 0x0009, "RAIL_WMSZ_MOVE" },
	{ 0x000A, "RAIL_WMSZ_KEYMOVE" },
	{ 0x000B, "RAIL_WMSZ_KEYSIZE" },
	{ 0x0, NULL},
};

static const value_string rdp_rail_notify_vals[] = {
	{ 0x00000201, "WM_LBUTTONDOWN" },
	{ 0x00000202, "WM_LBUTTONUP" },
	{ 0x00000204, "WM_RBUTTONDOWN" },
	{ 0x00000205, "WM_RBUTTONUP" },
	{ 0x0000007B, "WM_CONTEXTMENU" },
	{ 0x00000203, "WM_LBUTTONDBLCLK" },
	{ 0x00000206, "WM_RBUTTONDBLCLK" },
	{ 0x00000400, "NIN_SELECT" },
	{ 0x00000401, "NIN_KEYSELECT" },
	{ 0x00000402, "NIN_BALLOONSHOW" },
	{ 0x00000403, "NIN_BALLOONHIDE" },
	{ 0x00000404, "NIN_BALLOONTIMEOUT" },
	{ 0x00000405, "NIN_BALLOONUSERCLICK" },
	{ 0x0, NULL},
};

static const value_string rdp_rail_server_system_params_vals[] = {
	{ SPI_SETSCREENSAVEACTIVE, "SPI_SETSCREENSAVEACTIVE" },
	{ SPI_SETSCREENSAVESECURE, "SPI_SETSCREENSAVESECURE" },
	{ 0x0, NULL},
};

static const value_string rdp_rail_client_system_params_vals[] = {
	{ SPI_SETDRAGFULLWINDOWS, "SPI_SETDRAGFULLWINDOWS" },
	{ SPI_SETKEYBOARDCUES, "SPI_SETKEYBOARDCUES" },
	{ SPI_SETKEYBOARDPREF, "SPI_SETKEYBOARDPREF" },
	{ SPI_SETWORKAREA, "SPI_SETWORKAREA" },
	{ RAIL_SPI_DISPLAYCHANGE, "RAIL_SPI_DISPLAYCHANGE" },
	{ SPI_SETMOUSEBUTTONSWAP, "SPI_SETMOUSEBUTTONSWAP" },
	{ RAIL_SPI_TASKBARPOS, "RAIL_SPI_TASKBARPOS" },
	{ SPI_SETHIGHCONTRAST, "SPI_SETHIGHCONTRAST" },
	{ SPI_SETCARETWIDTH, "SPI_SETCARETWIDTH" },
	{ SPI_SETSTICKYKEYS, "SPI_SETSTICKYKEYS" },
	{ SPI_SETTOGGLEKEYS, "SPI_SETTOGGLEKEYS" },
	{ SPI_SETFILTERKEYS, "SPI_SETFILTERKEYS" },
	{ RAIL_SPI_DISPLAY_ANIMATIONS_ENABLED, "RAIL_SPI_DISPLAY_ANIMATIONS_ENABLED" },
	{ RAIL_SPI_DISPLAY_ADVANCED_EFFECTS_ENABLED, "RAIL_SPI_DISPLAY_ADVANCED_EFFECTS_ENABLED" },
	{ RAIL_SPI_DISPLAY_AUTO_HIDE_SCROLLBARS, "RAIL_SPI_DISPLAY_AUTO_HIDE_SCROLLBARS" },
	{ RAIL_SPI_DISPLAY_MESSAGE_DURATION, "RAIL_SPI_DISPLAY_MESSAGE_DURATION" },
	{ RAIL_SPI_CLOSED_CAPTION_FONT_COLOR, "RAIL_SPI_CLOSED_CAPTION_FONT_COLOR" },
	{ RAIL_SPI_CLOSED_CAPTION_FONT_OPACITY, "RAIL_SPI_CLOSED_CAPTION_FONT_OPACITY" },
	{ RAIL_SPI_CLOSED_CAPTION_FONT_SIZE, "RAIL_SPI_CLOSED_CAPTION_FONT_SIZE" },
	{ RAIL_SPI_CLOSED_CAPTION_FONT_STYLE, "RAIL_SPI_CLOSED_CAPTION_FONT_STYLE" },
	{ RAIL_SPI_CLOSED_CAPTION_FONT_EDGE_EFFECT, "RAIL_SPI_CLOSED_CAPTION_FONT_EDGE_EFFECT" },
	{ RAIL_SPI_CLOSED_CAPTION_BACKGROUND_COLOR, "RAIL_SPI_CLOSED_CAPTION_BACKGROUND_COLOR" },
	{ RAIL_SPI_CLOSED_CAPTION_BACKGROUND_OPACITY, "RAIL_SPI_CLOSED_CAPTION_BACKGROUND_OPACITY" },
	{ RAIL_SPI_CLOSED_CAPTION_REGION_COLOR, "RAIL_SPI_CLOSED_CAPTION_REGION_COLOR" },
	{ RAIL_SPI_CLOSED_CAPTION_REGION_OPACITY, "RAIL_SPI_CLOSED_CAPTION_REGION_OPACITY" },
	{ 0x0, NULL},
};


static int
dissect_rdp_rail(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *parent_tree _U_, void *data _U_)
{
	proto_item *item;
	int nextOffset, offset = 0;
	uint32_t cmdId = 0;
	uint32_t pduLength;
	proto_tree *tree;
	uint32_t windowId;
	bool packetToServer = rdp_isServerAddressTarget(pinfo);

	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RAIL");
	col_clear(pinfo->cinfo, COL_INFO);

	pduLength = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
	item = proto_tree_add_item(parent_tree, proto_rdp_rail, tvb, offset, pduLength, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdp_rail);

	proto_tree_add_item_ret_uint(tree, hf_rail_orderType, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cmdId);
	offset += 2;

	proto_tree_add_item(tree, hf_rail_pduLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	nextOffset = offset + (pduLength - 4);

	/* packets that start with a windowId */
	switch (cmdId) {
	case TS_RAIL_ORDER_ACTIVATE:
	case TS_RAIL_ORDER_SYSMENU:
	case TS_RAIL_ORDER_SYSCOMMAND:
	case TS_RAIL_ORDER_NOTIFY_EVENT:
	case TS_RAIL_ORDER_GET_APPID_REQ:
	case TS_RAIL_ORDER_MINMAXINFO:
	case TS_RAIL_ORDER_WINDOWMOVE:
	case TS_RAIL_ORDER_LOCALMOVESIZE:
	case TS_RAIL_ORDER_CLOAK:
	case TS_RAIL_ORDER_SNAP_ARRANGE:
	case TS_RAIL_ORDER_GET_APPID_RESP:
	case TS_RAIL_ORDER_GET_APPID_RESP_EX:
	case TS_RAIL_ORDER_ZORDER_SYNC:
		proto_tree_add_item_ret_uint(tree, hf_rail_windowId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &windowId);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s|windowId=0x%x", val_to_str_const(cmdId, rdp_rail_order_vals, "Unknown RAIL command"),
				windowId);
		offset += 4;
		break;
	default:
		col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmdId, rdp_rail_order_vals, "Unknown RAIL command"));
		break;
	}


	/* do the rest of the parsing */
	switch (cmdId) {
	case TS_RAIL_ORDER_EXEC:
		break;
	case TS_RAIL_ORDER_ACTIVATE:
		proto_tree_add_item(tree, hf_rail_activate_enabled, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;
	case TS_RAIL_ORDER_SYSPARAM:
		if (!packetToServer) {
			uint32_t serverParam;

			col_set_str(pinfo->cinfo, COL_INFO, "Server system parameters");

			proto_tree_add_item_ret_uint(tree, hf_rail_sysparam_server_params, tvb, offset, 4, ENC_LITTLE_ENDIAN, &serverParam);

			col_append_fstr(pinfo->cinfo, COL_INFO, "|%s", val_to_str_const(serverParam, rdp_rail_server_system_params_vals, "<unknown server param>"));
			switch(serverParam) {
			case SPI_SETSCREENSAVEACTIVE:
			case SPI_SETSCREENSAVESECURE:
				/* TODO */
				break;
			}
		} else {
			uint32_t clientParam;

			proto_tree_add_item_ret_uint(tree, hf_rail_sysparam_client_params, tvb, offset, 4, ENC_LITTLE_ENDIAN, &clientParam);
			col_append_fstr(pinfo->cinfo, COL_INFO, "|%s", val_to_str_const(clientParam, rdp_rail_client_system_params_vals, "<unknown client param>"));

			switch(clientParam) {
			case SPI_SETDRAGFULLWINDOWS:
			case SPI_SETKEYBOARDCUES:
			case SPI_SETKEYBOARDPREF:
			case SPI_SETWORKAREA:
			case RAIL_SPI_DISPLAYCHANGE:
			case SPI_SETMOUSEBUTTONSWAP:
			case RAIL_SPI_TASKBARPOS:
			case SPI_SETHIGHCONTRAST:
			case SPI_SETCARETWIDTH:
			case SPI_SETSTICKYKEYS:
			case SPI_SETTOGGLEKEYS:
			case SPI_SETFILTERKEYS:
			case RAIL_SPI_DISPLAY_ANIMATIONS_ENABLED:
			case RAIL_SPI_DISPLAY_ADVANCED_EFFECTS_ENABLED:
			case RAIL_SPI_DISPLAY_AUTO_HIDE_SCROLLBARS:
			case RAIL_SPI_DISPLAY_MESSAGE_DURATION:
			case RAIL_SPI_CLOSED_CAPTION_FONT_COLOR:
			case RAIL_SPI_CLOSED_CAPTION_FONT_OPACITY:
			case RAIL_SPI_CLOSED_CAPTION_FONT_SIZE:
			case RAIL_SPI_CLOSED_CAPTION_FONT_STYLE:
			case RAIL_SPI_CLOSED_CAPTION_FONT_EDGE_EFFECT:
			case RAIL_SPI_CLOSED_CAPTION_BACKGROUND_COLOR:
			case RAIL_SPI_CLOSED_CAPTION_BACKGROUND_OPACITY:
			case RAIL_SPI_CLOSED_CAPTION_REGION_COLOR:
			case RAIL_SPI_CLOSED_CAPTION_REGION_OPACITY:
				/* TODO */
				break;
			}
		}
		break;
	case TS_RAIL_ORDER_SYSCOMMAND:
		break;
	case TS_RAIL_ORDER_HANDSHAKE:
		proto_tree_add_item(tree, hf_rail_caps_handshake_buildNumber, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case TS_RAIL_ORDER_NOTIFY_EVENT:
		proto_tree_add_item(tree, hf_rail_notify_iconId, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_rail_notify_message, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case TS_RAIL_ORDER_WINDOWMOVE:
		proto_tree_add_item(tree, hf_rail_windowmove_left, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_windowmove_top, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_windowmove_right, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_windowmove_bottom, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		break;
	case TS_RAIL_ORDER_LOCALMOVESIZE:
		proto_tree_add_item(tree, hf_rail_localmovesize_isMoveSizeStart, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_localmovesize_moveSizeType, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_localmovesize_posX, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_localmovesize_posY, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		break;
	case TS_RAIL_ORDER_MINMAXINFO:
		proto_tree_add_item(tree, hf_rail_minmaxinfo_maxwidth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_minmaxinfo_maxheight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_minmaxinfo_maxPosX, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_minmaxinfo_maxPosY, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_minmaxinfo_minTrackWidth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_minmaxinfo_minTrackHeight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_minmaxinfo_maxTrackWidth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rail_minmaxinfo_maxTrackHeight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		break;
	case TS_RAIL_ORDER_CLIENTSTATUS: {
		int *flags[] = {
			&hf_rail_cstatus_flags_allowlocalmove,
			&hf_rail_cstatus_autoreconnect,
			&hf_rail_cstatus_zorder_sync,
			&hf_rail_cstatus_resize_margin,
			&hf_rail_cstatus_hidpi_icons,
			&hf_rail_cstatus_appbar_remoting,
			&hf_rail_cstatus_powerdisplay,
			&hf_rail_cstatus_bidir_cloak,
			&hf_rail_cstatus_suppress_icon_border,
			NULL,
		};

		proto_tree_add_bitmask(tree, tvb, offset, hf_rail_cstatus_flags, ett_rdp_rail_clientstatus_flags, flags, ENC_LITTLE_ENDIAN);
		break;
	}
	case TS_RAIL_ORDER_SYSMENU:
	case TS_RAIL_ORDER_LANGBARINFO:
	case TS_RAIL_ORDER_EXEC_RESULT:
	case TS_RAIL_ORDER_GET_APPID_REQ:
	case TS_RAIL_ORDER_GET_APPID_RESP:
	case TS_RAIL_ORDER_TASKBARINFO:
	case TS_RAIL_ORDER_LANGUAGEIMEINFO:
	case TS_RAIL_ORDER_COMPARTMENTINFO:
		break;
	case TS_RAIL_ORDER_HANDSHAKE_EX: {
		int *flags[] = {
			&hf_rail_handshake_flags_hidef,
			&hf_rail_handshake_flags_ex_spi,
			&hf_rail_handshake_flags_snap,
			&hf_rail_handshake_flags_textscale,
			&hf_rail_handshake_flags_caretblink,
			&hf_rail_handshake_flags_ex_spi2,
			NULL,
		};

		proto_tree_add_item(tree, hf_rail_caps_handshake_buildNumber, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_bitmask(tree, tvb, offset, hf_rail_handshake_flags, ett_rdp_rail_handshake_flags, flags, ENC_LITTLE_ENDIAN);
		break;
	}
	case TS_RAIL_ORDER_ZORDER_SYNC:
		break;
	case TS_RAIL_ORDER_CLOAK:
		proto_tree_add_item(tree, hf_rail_cloak_cloaked, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;
	case TS_RAIL_ORDER_POWER_DISPLAY_REQUEST:
	case TS_RAIL_ORDER_SNAP_ARRANGE:
	case TS_RAIL_ORDER_GET_APPID_RESP_EX:
	case TS_RAIL_ORDER_TEXTSCALEINFO:
	case TS_RAIL_ORDER_CARETBLINKINFO:
			break;
	default:
		break;
	}

	offset = nextOffset;
	return offset;
}


void proto_register_rdp_rail(void) {
	static hf_register_info hf[] = {
		{ &hf_rail_orderType,
		  { "OrderType", "rdp_rail.ordertype",
		    FT_UINT16, BASE_HEX, VALS(rdp_rail_order_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_pduLength,
		  { "OrderLength", "rdp_rail.orderlength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_caps_handshake_buildNumber,
		  { "Build number", "rdp_rail.handshake.buildNumber",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_windowId,
		  { "WindowId", "rdp_rail.windowid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_windowmove_left,
		  { "Left", "rdp_rail.windowmove.left",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_windowmove_top,
		  { "Top", "rdp_rail.windowmove.top",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_windowmove_right,
		  { "Right", "rdp_rail.windowmove.right",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_windowmove_bottom,
		  { "Bottom", "rdp_rail.windowmove.bottom",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_localmovesize_isMoveSizeStart,
		  { "IsMoveSizeStart", "rdp_rail.localmovesize.ismovesizestart",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_localmovesize_moveSizeType,
		  { "Move size type", "rdp_rail.localmovesize.movesizetype",
			FT_UINT16, BASE_DEC, VALS(moveSizeStart_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_localmovesize_posX,
		  { "PosX", "rdp_rail.localmovesize.posx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_localmovesize_posY,
		  { "PosY", "rdp_rail.localmovesize.posy",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_maxwidth,
		  { "Max width", "rdp_rail.minmaxinfo.maxwidth",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_maxheight,
		  { "Max height", "rdp_rail.minmaxinfo.maxheight",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_maxPosX,
		  { "Max posX", "rdp_rail.minmaxinfo.maxposx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_maxPosY,
		  { "Max posY", "rdp_rail.minmaxinfo.maxposy",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_minTrackWidth,
		  { "Min track width", "rdp_rail.minmaxinfo.mintrackwidth",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_minTrackHeight,
		  { "Min track height", "rdp_rail.minmaxinfo.mintrackheight",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_maxTrackWidth,
		  { "Max track width", "rdp_rail.minmaxinfo.maxtrackwidth",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_minmaxinfo_maxTrackHeight,
		  { "Max track height", "rdp_rail.minmaxinfo.maxtrackheight",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rail_cloak_cloaked,
		  { "Cloaked", "rdp_rail.cloak.cloaked",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_rail_handshake_flags,
		  { "Flags", "rdp_rail.handshakeflags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL }},
		{ &hf_rail_handshake_flags_hidef,
		  { "HIDEF", "rdp_rail.handshakeflags.hidef",
			FT_UINT32, BASE_HEX, NULL, 0x00000001,
			NULL, HFILL }},
		{ &hf_rail_handshake_flags_ex_spi,
		  { "EXTENDED_SPI_SUPPORTED", "rdp_rail.handshakeflags.exspi",
			FT_UINT32, BASE_HEX, NULL, 0x00000002,
			NULL, HFILL }},
		{ &hf_rail_handshake_flags_snap,
		  { "SNAP_ARRANGE_SUPPORTED", "rdp_rail.handshakeflags.snap",
			FT_UINT32, BASE_HEX, NULL, 0x00000004,
			NULL, HFILL }},
		{ &hf_rail_handshake_flags_textscale,
		  { "TEXT_SCALE_SUPPORTED", "rdp_rail.handshakeflags.textscale",
			FT_UINT32, BASE_HEX, NULL, 0x00000008,
			NULL, HFILL }},
		{ &hf_rail_handshake_flags_caretblink,
		  { "CARET_BLINK_SUPPORTED", "rdp_rail.handshakeflags.caretblink",
			FT_UINT32, BASE_HEX, NULL, 0x00000010,
			NULL, HFILL }},
		{ &hf_rail_handshake_flags_ex_spi2,
		  { "EXTENDED_SPI_2_SUPPORTED", "rdp_rail.handshakeflags.exspi2",
			FT_UINT32, BASE_HEX, NULL, 0x00000020,
			NULL, HFILL }},

		{ &hf_rail_cstatus_flags,
		  { "Flags", "rdp_rail.clientstatus.flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_rail_cstatus_flags_allowlocalmove,
		  { "ALLOWLOCALMOVESIZE", "rdp_rail.clientstatus.allowlocalmove",
			FT_UINT32, BASE_HEX, NULL, 0x00000001,
			NULL, HFILL }},
		{ &hf_rail_cstatus_autoreconnect,
		  { "AUTORECONNECT", "rdp_rail.clientstatus.autoreconnect",
			FT_UINT32, BASE_HEX, NULL, 0x00000002,
			NULL, HFILL }},
		{ &hf_rail_cstatus_zorder_sync,
		  { "ZORDER_SYNC", "rdp_rail.clientstatus.zordersync",
			FT_UINT32, BASE_HEX, NULL, 0x00000004,
			NULL, HFILL }},
		{ &hf_rail_cstatus_resize_margin,
		  { "WINDOW_RESIZE_MARGIN_SUPPORTED", "rdp_rail.clientstatus.resizemargin",
			FT_UINT32, BASE_HEX, NULL, 0x00000010,
			NULL, HFILL }},
		{ &hf_rail_cstatus_hidpi_icons,
		  { "HIGH_DPI_ICONS_SUPPORTED", "rdp_rail.clientstatus.highdpiicons",
			FT_UINT32, BASE_HEX, NULL, 0x00000020,
			NULL, HFILL }},
		{ &hf_rail_cstatus_appbar_remoting,
		  { "APPBAR_REMOTING_SUPPORTED", "rdp_rail.clientstatus.appbarremoting",
			FT_UINT32, BASE_HEX, NULL, 0x00000040,
			NULL, HFILL }},
		{ &hf_rail_cstatus_powerdisplay,
		  { "POWER_DISPLAY_REQUEST_SUPPORTED", "rdp_rail.clientstatus.powerdisplay",
			FT_UINT32, BASE_HEX, NULL, 0x00000080,
			NULL, HFILL }},
		{ &hf_rail_cstatus_bidir_cloak,
		  { "BIDIRECTIONAL_CLOAK_SUPPORTED", "rdp_rail.clientstatus.bidircloak",
			FT_UINT32, BASE_HEX, NULL, 0x00000200,
			NULL, HFILL }},
		{ &hf_rail_cstatus_suppress_icon_border,
		  { "SUPPRESS_ICON_ORDERS", "rdp_rail.clientstatus.suppressiconborder",
			FT_UINT32, BASE_HEX, NULL, 0x00000400,
			NULL, HFILL }},
		{ &hf_rail_activate_enabled,
		  { "Enabled", "rdp_rail.activate.enabled",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_rail_notify_iconId,
		  { "IconId", "rdp_rail.notify.iconid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_rail_notify_message,
		  { "Message", "rdp_rail.notify.message",
			FT_UINT32, BASE_HEX, VALS(rdp_rail_notify_vals), 0x0,
			NULL, HFILL }},

		{ &hf_rail_sysparam_server_params,
		  { "SystemParameter", "rdp_rail.sysparam.serverparameter",
			FT_UINT32, BASE_HEX, VALS(rdp_rail_server_system_params_vals), 0x0,
			NULL, HFILL }},

		{ &hf_rail_sysparam_client_params,
		  { "SystemParameter", "rdp_rail.sysparam.clientparameter",
			FT_UINT32, BASE_HEX, VALS(rdp_rail_client_system_params_vals), 0x0,
			NULL, HFILL }},


	};

	static int *ett[] = {
		&ett_rdp_rail,
		&ett_rdp_rail_handshake_flags,
		&ett_rdp_rail_clientstatus_flags,
	};

	proto_rdp_rail = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_rail, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rdp_rail", dissect_rdp_rail, proto_rdp_rail);
}

void proto_reg_handoff_rdp_rail(void) {
}
