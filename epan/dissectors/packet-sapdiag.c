/* packet-saphdb.c
 * Routines for SAP Diag (SAP GUI Protocol) dissection
 * Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
 * Code contributed by SecureAuth Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/wmem/wmem.h>

#include "packet-sapsnc.h"

/* Define default ports. It right range shold be 32NN, but as prot numbers are
 * proprietary and not IANA assigned, we leave only the one corresponding to the
 * instance 00. In addition, 3298 it's generally used for the niping tool and 3299
 * is associated to SAP Router.
 */
#define SAPDIAG_PORT_RANGE "3200"

/* SAP Diag Header Communication Flag values */
#define SAPDIAG_COM_FLAG_TERM_EOS   0x01
#define SAPDIAG_COM_FLAG_TERM_EOC   0x02
#define SAPDIAG_COM_FLAG_TERM_NOP   0x04
#define SAPDIAG_COM_FLAG_TERM_EOP   0x08
#define SAPDIAG_COM_FLAG_TERM_INI   0x10
#define SAPDIAG_COM_FLAG_TERM_CAS   0x20
#define SAPDIAG_COM_FLAG_TERM_NNM   0x40
#define SAPDIAG_COM_FLAG_TERM_GRA   0x80


/* SAP Diag Header Compression field values */
static const value_string sapdiag_compress_vals[] = {
	{ 0x0, "Compression switched off" },
	{ 0x1, "Compression switched on" },
	{ 0x2, "Data encrypted" },
	{ 0x3, "Data encrypted wrap" },
	/* NULL */
	{ 0x0, NULL }
};

/* SAP Diag Header Algorithm field values */
static const value_string sapdiag_algorithm_vals[] = {
	{ 0x10, "LZC" },
	{ 0x12, "LZH" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag DP Header Request ID values */
static const value_string sapdiag_dp_request_id_vals[] = {
	{ 0x00000000, "NOWP" },
	{ 0x00000001, "DIA" },
	{ 0x00000002, "DUPD" },
	{ 0x00000003, "DENQ" },
	{ 0x00000004, "DBTC" },
	{ 0x00000005, "DSPO" },
	{ 0x00000006, "DUP2" },
	/* NULL */
	{ 0x00000000, NULL}
};

/* SAP Diag DP Header Sender ID values */
static const value_string sapdiag_dp_sender_id_vals[] = {
	{ 0x01, "DISPATCHER" },
	{ 0x02, "WORK_PROCESS" },
	{ 0x04, "REMOTE_TERMINAL" },
	{ 0x20, "APPC_TERMINAL" },
	{ 0x40, "APPC_GATEWAY" },
	{ 0xC8, "ICMAN" },
	{ 0xC9, "IC_MONITOR" },
	{ 0xCB, "LCOM" },
	/* NULL */
	{ 0x00, NULL}
};

/* SAP Diag DP Header Action Type values */
static const value_string sapdiag_dp_action_type_vals[] = {
	{ 0x01, "SEND_TO_DP" },
	{ 0x02, "SEND_TO_WP" },
	{ 0x03, "SEND_TO_TM" },
	{ 0x04, "SEND_TO_APPC" },
	{ 0x05, "SEND_TO_APPCTM" },
	{ 0x06, "SEND_MSG_TYPE" },
	{ 0x07, "SEND_MSG_REQUES" },
	{ 0x08, "SEND_MSG_REPLY" },
	{ 0x09, "SEND_MSG_ONEWAY" },
	{ 0x0A, "SEND_MSG_ADMIN" },
	{ 0x0B, "WAKE_UP_WPS" },
	{ 0x0C, "SET_TIMEOUT" },
	{ 0x0D, "DEL_SCHEDULE" },
	{ 0x0E, "ADD_SOFT_SERV" },
	{ 0x0F, "SUB_SOFT_SERV" },
	{ 0x10, "SHUTDOWN" },
	{ 0x11, "SEND_TO_MSGSERV" },
	{ 0x12, "SEND_TO_PLUGIN" },
	/* NULL */
	{ 0x00, NULL}
};

/* SAP Diag DP Header Request Info Flag constants */
#define SAPDIAG_DP_REQ_INFO_UNDEFINED 		0x00
#define SAPDIAG_DP_REQ_INFO_LOGIN		0x01
#define SAPDIAG_DP_REQ_INFO_LOGOFF		0x02
#define SAPDIAG_DP_REQ_INFO_SHUTDOWN		0x04
#define SAPDIAG_DP_REQ_INFO_GRAPHIC_TM		0x08
#define SAPDIAG_DP_REQ_INFO_ALPHA_TM		0x10
#define SAPDIAG_DP_REQ_INFO_ERROR_FROM_APPC	0x20
#define SAPDIAG_DP_REQ_INFO_CANCELMODE		0x40
#define SAPDIAG_DP_REQ_INFO_MSG_WITH_REQ_BUF	0x80

#define SAPDIAG_DP_REQ_INFO_MSG_WITH_OH		0x01
#define SAPDIAG_DP_REQ_INFO_BUFFER_REFRESH	0x02
#define SAPDIAG_DP_REQ_INFO_BTC_SCHEDULER	0x04
#define SAPDIAG_DP_REQ_INFO_APPC_SERVER_DOWN	0x08
#define SAPDIAG_DP_REQ_INFO_MS_ERROR		0x10
#define SAPDIAG_DP_REQ_INFO_SET_SYSTEM_USER	0x20
#define SAPDIAG_DP_REQ_INFO_DP_CANT_HANDLE_REQ	0x40
#define SAPDIAG_DP_REQ_INFO_DP_AUTO_ABAP	0x80

#define SAPDIAG_DP_REQ_INFO_DP_APPL_SERV_INFO	0x01
#define SAPDIAG_DP_REQ_INFO_DP_ADMIN		0x02
#define SAPDIAG_DP_REQ_INFO_DP_SPOOL_ALRM	0x04
#define SAPDIAG_DP_REQ_INFO_DP_HAND_SHAKE	0x08
#define SAPDIAG_DP_REQ_INFO_DP_CANCEL_PRIV	0x10
#define SAPDIAG_DP_REQ_INFO_DP_RAISE_TIMEOUT	0x20
#define SAPDIAG_DP_REQ_INFO_DP_NEW_MODE		0x40
#define SAPDIAG_DP_REQ_INFO_DP_SOFT_CANCEL	0x80

#define SAPDIAG_DP_REQ_INFO_DP_TM_INPUT		0x01
#define SAPDIAG_DP_REQ_INFO_DP_TM_OUTPUT	0x02
#define SAPDIAG_DP_REQ_INFO_DP_ASYNC_RFC	0x04
#define SAPDIAG_DP_REQ_INFO_DP_ICM_EVENT	0x08
#define SAPDIAG_DP_REQ_INFO_DP_AUTO_TH		0x10
#define SAPDIAG_DP_REQ_INFO_DP_RFC_CANCEL	0x20
#define SAPDIAG_DP_REQ_INFO_DP_MS_ADM		0x40

/* SAP Diag Support Bits */
#define SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR	0x01  /* 0 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS	0x02  /* 1 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION	0x04  /* 2 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT	0x08  /* 3 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT	0x10  /* 4 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC	0x20  /* 5 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED	0x40  /* 6 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE	0x80  /* 7 */

#define SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE	0x01  /* 8 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE	0x02  /* 9 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1	0x04  /* 10 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1	0x08  /* 11 */
#define SAPDIAG_SUPPORT_BIT_UPPERCASE	0x10  /* 12 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY	0x20  /* 13 */
#define SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE	0x40  /* 14 */
#define SAPDIAG_SUPPORT_BIT_RFC_DIALOG	0x80  /* 15 */

#define SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT	0x01  /* 16 */
#define SAPDIAG_SUPPORT_BIT_FKEY_TABLE	0x02  /* 17 */
#define SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT	0x04  /* 18 */
#define SAPDIAG_SUPPORT_BIT_STOP_TRANS	0x08  /* 19 */
#define SAPDIAG_SUPPORT_BIT_FULL_MENU	0x10  /* 20 */
#define SAPDIAG_SUPPORT_BIT_OBJECT_NAMES	0x20  /* 21 */
#define SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE	0x40  /* 22 */
#define SAPDIAG_SUPPORT_BIT_DLGH_FLAGS	0x80  /* 23 */

#define SAPDIAG_SUPPORT_BIT_APPL_MNU	0x01  /* 24 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_INFO	0x02  /* 25 */
#define SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1	0x04  /* 26 */
#define SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB	0x08  /* 27 */
#define SAPDIAG_SUPPORT_BIT_GUIAPI	0x10  /* 28 */
#define SAPDIAG_SUPPORT_BIT_NOGRAPH	0x20  /* 29 */
#define SAPDIAG_SUPPORT_BIT_NOMESSAGES	0x40  /* 30 */
#define SAPDIAG_SUPPORT_BIT_NORABAX	0x80  /* 31 */

#define SAPDIAG_SUPPORT_BIT_NOSYSMSG	0x01  /* 32 */
#define SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT	0x02  /* 33 */
#define SAPDIAG_SUPPORT_BIT_NORFC	0x04  /* 34 */
#define SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT	0x08  /* 35 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_VARS	0x10  /* 36 */
#define SAPDIAG_SUPPORT_BIT_OCX_SUPPORT	0x20  /* 37 */
#define SAPDIAG_SUPPORT_BIT_SCROLL_INFOS	0x40  /* 38 */
#define SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK	0x80  /* 39 */

#define SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2	0x01  /* 40 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE	0x02  /* 41 */
#define SAPDIAG_SUPPORT_BIT_CURR_TCODE	0x04  /* 42 */
#define SAPDIAG_SUPPORT_BIT_CONN_WSIZE	0x08  /* 43 */
#define SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2	0x10  /* 44 */
#define SAPDIAG_SUPPORT_BIT_TABSTRIP	0x20  /* 45 */
#define SAPDIAG_SUPPORT_BIT_UNKNOWN_1	0x40  /* 46 (Unknown support bit) */
#define SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS	0x80  /* 47 */

#define SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES	0x01  /* 48 */
#define SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST	0x02  /* 49 */
#define SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER	0x04  /* 50 */
#define SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER	0x08  /* 51 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER	0x10  /* 52 */
#define SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED	0x20  /* 53 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED	0x40  /* 54 */
#define SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO	0x80  /* 55 */

#define SAPDIAG_SUPPORT_BIT_TYPE_SERVER	0x01  /* 56 */
#define SAPDIAG_SUPPORT_BIT_COMBOBOX	0x02  /* 57 */
#define SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED	0x04  /* 58 */
#define SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE	0x08  /* 59 */
#define SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE	0x10  /* 60 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS	0x20  /* 61 */
#define SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS	0x40  /* 62 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_USERID	0x80  /* 63 */

#define SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT	0x01  /* 64 */
#define SAPDIAG_SUPPORT_BIT_USER_TURNTIME2	0x02  /* 65 */
#define SAPDIAG_SUPPORT_BIT_NUM_FIELD	0x04  /* 66 */
#define SAPDIAG_SUPPORT_BIT_WIN16	0x08  /* 67 */
#define SAPDIAG_SUPPORT_BIT_CONTEXT_MENU	0x10  /* 68 */
#define SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE	0x20  /* 69 */
#define SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION	0x40  /* 70 */
#define SAPDIAG_SUPPORT_BIT_LABEL_OWNER	0x80  /* 71 */

#define SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD	0x01  /* 72 */
#define SAPDIAG_SUPPORT_BIT_PROPERTY_BAG	0x02  /* 73 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_1	0x04  /* 74 */
#define SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2	0x08  /* 75 */
#define SAPDIAG_SUPPORT_BIT_PROPFONT_VALID	0x10  /* 76 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER	0x20  /* 77 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID	0x40  /* 78 */
#define SAPDIAG_SUPPORT_BIT_NOTGUI	0x80  /* 79 */

#define SAPDIAG_SUPPORT_BIT_WAN	0x01  /* 80 */
#define SAPDIAG_SUPPORT_BIT_XML_BLOBS	0x02  /* 81 */
#define SAPDIAG_SUPPORT_BIT_RFC_QUEUE	0x04  /* 82 */
#define SAPDIAG_SUPPORT_BIT_RFC_COMPRESS	0x08  /* 83 */
#define SAPDIAG_SUPPORT_BIT_JAVA_BEANS	0x10  /* 84 */
#define SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND	0x20  /* 85 */
#define SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE	0x40  /* 86 */
#define SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID	0x80  /* 87 */

#define SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB	0x01  /* 88 */
#define SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS	0x02  /* 89 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_2	0x04  /* 90 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_3	0x08  /* 91 */
#define SAPDIAG_SUPPORT_BIT_XML_PROPERTIES	0x10  /* 92 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_4	0x20  /* 93 */
#define SAPDIAG_SUPPORT_BIT_HEX_FIELD	0x40  /* 94 */
#define SAPDIAG_SUPPORT_BIT_HAS_CACHE	0x80  /* 95 */

#define SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE	0x01  /* 96 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_5	0x02  /* 97 */
#define SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2	0x04  /* 98 */
#define SAPDIAG_SUPPORT_BIT_ITS	0x08  /* 99 */
#define SAPDIAG_SUPPORT_BIT_NO_EASYACCESS	0x10  /* 100 */
#define SAPDIAG_SUPPORT_BIT_PROPERTYPUMP	0x20  /* 101 */
#define SAPDIAG_SUPPORT_BIT_COOKIE	0x40  /* 102 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_6	0x80  /* 103 */

#define SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE	0x01  /* 104 */
#define SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE	0x02  /* 105 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS	0x04  /* 106 */
#define SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY	0x08  /* 107 */
#define SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE	0x10  /* 108 */
#define SAPDIAG_SUPPORT_BIT_CACHED_VSETS	0x20  /* 109 */
#define SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR	0x40  /* 110 */
#define SAPDIAG_SUPPORT_BIT_AREA2FRONT	0x80  /* 111 */

#define SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH	0x01  /* 112 */
#define SAPDIAG_SUPPORT_BIT_AUTORESIZE	0x02  /* 113 */
#define SAPDIAG_SUPPORT_BIT_EDIT_VARLEN	0x04  /* 114 */
#define SAPDIAG_SUPPORT_BIT_WORKPLACE	0x08  /* 115 */
#define SAPDIAG_SUPPORT_BIT_PRINTDATA	0x10  /* 116 */
#define SAPDIAG_SUPPORT_BIT_UNKNOWN_2	0x20  /* 117 (Unknown support bit) */
#define SAPDIAG_SUPPORT_BIT_SINGLE_SESSION	0x40  /* 118 */
#define SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE	0x80  /* 119 */

#define SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT	0x01  /* 120 */
#define SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER	0x02  /* 121 */
#define SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO	0x04  /* 122 */
#define SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT	0x08  /* 123 */
#define SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT	0x10  /* 124 */
#define SAPDIAG_SUPPORT_BIT_WEBGUI	0x20  /* 125 */
#define SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE	0x40  /* 126 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST	0x80  /* 127 */

#define SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2	0x01  /* 128 */
#define SAPDIAG_SUPPORT_BIT_EOKDUMMY_1	0x02  /* 129 */
#define SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING	0x04  /* 130 */
#define SAPDIAG_SUPPORT_BIT_SLC	0x08  /* 131 */
#define SAPDIAG_SUPPORT_BIT_ACCESSIBILITY	0x10  /* 132 */
#define SAPDIAG_SUPPORT_BIT_ECATT	0x20  /* 133 */
#define SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3	0x40  /* 134 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_UTF8	0x80  /* 135 */

#define SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME	0x01  /* 136 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST	0x02  /* 137 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE	0x04  /* 138 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE	0x08  /* 139 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP	0x10  /* 140 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_APPL4	0x20  /* 141 */
#define SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL	0x40  /* 142 */
#define SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE	0x80  /* 143 */

#define SAPDIAG_SUPPORT_BIT_BINARY_EVENTID	0x01  /* 144 */
#define SAPDIAG_SUPPORT_BIT_GUI_THEME	0x02  /* 145 */
#define SAPDIAG_SUPPORT_BIT_TOP_WINDOW	0x04  /* 146 */
#define SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1	0x08  /* 147 */
#define SAPDIAG_SUPPORT_BIT_SPLITTER	0x10  /* 148 */
#define SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY	0x20  /* 149 */
#define SAPDIAG_SUPPORT_BIT_ACC_LIST	0x40  /* 150 */
#define SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO	0x80  /* 151 */

#define SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM	0x01  /* 152 */
#define SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS	0x02  /* 153 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1	0x04  /* 154 */
#define SAPDIAG_SUPPORT_BIT_FRAME_1	0x08  /* 155 */
#define SAPDIAG_SUPPORT_BIT_TICKET4GUI	0x10  /* 156 */
#define SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS	0x20  /* 157 */
#define SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT	0x40  /* 158 */
#define SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP	0x80  /* 159 */

#define SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2	0x01  /* 160 */
#define SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3	0x02  /* 161 */
#define SAPDIAG_SUPPORT_BIT_CELLINFO	0x04  /* 162 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2	0x08  /* 163 */
#define SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT	0x10  /* 164 */
#define SAPDIAG_SUPPORT_BIT_ITS_PLUGIN	0x20  /* 165 */
#define SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS	0x40  /* 166 */
#define SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI	0x80  /* 167 */

#define SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2	0x01  /* 168 */
#define SAPDIAG_SUPPORT_BIT_RCUI	0x02  /* 169 */
#define SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE	0x04  /* 170 */
#define SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE	0x08  /* 171 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION	0x10  /* 172 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP	0x20  /* 173 */
#define SAPDIAG_SUPPORT_BIT_EOKDUMMY_2	0x40  /* 174 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3	0x80  /* 175 */

#define SAPDIAG_SUPPORT_BIT_SBA2	0x01  /* 176 */
#define SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE	0x02  /* 177 */
#define SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2	0x04  /* 178 */
#define SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE	0x08  /* 179 */
#define SAPDIAG_SUPPORT_BIT_GUI_PACKET	0x10  /* 180 */
#define SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER	0x20  /* 181 */
#define SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION	0x40  /* 182 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST	0x80  /* 183 */

#define SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME	0x01  /* 184 */
#define SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN	0x02  /* 185 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1	0x04  /* 186 */
#define SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS	0x08  /* 187 */
#define SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO	0x10  /* 188 */
#define SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT	0x20  /* 189 */
#define SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH	0x40  /* 190 */
#define SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT	0x80  /* 191 */

#define SAPDIAG_SUPPORT_BIT_UNKNOWN_3	0x01  /* 192 (Unknown support bit) */
#define SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR	0x02  /* 193 */
#define SAPDIAG_SUPPORT_BIT_MAX_WSIZE	0x04  /* 194 */
#define SAPDIAG_SUPPORT_BIT_SAP_PERSONAS	0x08  /* 195 */
#define SAPDIAG_SUPPORT_BIT_IDA_ALV	0x10  /* 196 */
#define SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS	0x20  /* 197 */
#define SAPDIAG_SUPPORT_BIT_AMC	0x40  /* 198 */
#define SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC	0x80  /* 199 */

#define SAPDIAG_SUPPORT_BIT_GROUPBOX	0x01  /* 200 */
#define SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON	0x02  /* 201 */
#define SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST	0x04  /* 202 */
#define SAPDIAG_SUPPORT_BIT_FIORI_MODE	0x08  /* 203 */
#define SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE	0x10  /* 204 */
#define SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE	0x20  /* 205 */
#define SAPDIAG_SUPPORT_BIT_AGI_ID	0x40  /* 206 */
#define SAPDIAG_SUPPORT_BIT_AGI_ID_TC	0x80  /* 207 */

#define SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS	0x01  /* 208 */
#define SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE	0x02  /* 209 */
#define SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3	0x04  /* 210 */
#define SAPDIAG_SUPPORT_BIT_NWBC	0x08  /* 211 */
#define SAPDIAG_SUPPORT_BIT_CONTAINER_LIST	0x10  /* 212 */
#define SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR	0x20  /* 213 */
#define SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE	0x40  /* 214 */


/* SAP Diag DP Header New Status values */
static const value_string sapdiag_dp_new_stat_vals[] = {
	{ 0x00, "NO_CHANGE" },
	{ 0x01, "WP_SLOT_FREE" },
	{ 0x02, "WP_WAIT" },
	{ 0x04, "WP_RUN" },
	{ 0x08, "WP_HOLD" },
	{ 0x10, "WP_KILLED" },
	{ 0x20, "WP_SHUTDOWN" },
	{ 0x40, "WP_RESTRICTED" },
	{ 0x80, "WP_NEW" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item Type values */
static const value_string sapdiag_item_type_vals[] = {
	{ 0x01,	"SES" },
	{ 0x02, "ICO" },
	{ 0x03, "TIT" },
	{ 0x07, "DiagMessage (old format)" },
	{ 0x08, "OKC" },
	{ 0x09, "CHL" },
	{ 0x0a, "SFE" },
	{ 0x0b, "SBA" },
	{ 0x0c, "EOM" },
	{ 0x10,	"APPL" },
	{ 0x11, "DIAG_XMLBLOB" },
	{ 0x12, "APPL4" },
	{ 0x13, "SLC" },
	{ 0x15, "SBA2" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ID values */
static const value_string sapdiag_item_id_vals[] = {
	{ 0x01, "SCRIPT" },
	{ 0x02, "GRAPH" },
	{ 0x03, "IXOS" },
	{ 0x04, "ST_USER" },
	{ 0x05, "DYNN" },
	{ 0x06, "ST_R3INFO" },
	{ 0x07, "POPU" },
	{ 0x08, "RFC_TR" },
	{ 0x09, "DYNT" },
	{ 0x0a, "CONTAINER" },
	{ 0x0b, "MNUENTRY" },
	{ 0x0c, "VARINFO" },
	{ 0x0e, "CONTROL" },
	{ 0x0f, "UI_EVENT" },
	{ 0x12, "ACC_LIST" },
	{ 0x13, "RCUI" },
	{ 0x14, "GUI_PACKET" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 SCRIPT SID values */
static const value_string sapdiag_item_appl_script_vals[] = {
	/* SCRIPT */
	{ 0x01, "SCRIPT_OTF" },
	{ 0x02, "SCRIPT_SCREEN" },
	{ 0x03, "SCRIPT_POSTSCRIPT" },
	{ 0x04, "SCRIPT_ITF" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 GRAPH SID values */
static const value_string sapdiag_item_appl_graph_vals[] = {
	/* GRAPH */
	{ 0x03, "GRAPH RELEASE 3" },
	{ 0x05, "GRAPH RELEASE 5" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 IXOS SID values */
static const value_string sapdiag_item_appl_ixos_vals[] = {
	/* IXOS */
	{ 0x01, "ABLAGE" },
	{ 0x02, "ANZEIGE" },
	{ 0x03, "IXOS_COMMAND" },
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ST_USER SID values */
static const value_string sapdiag_item_appl_st_user_vals[] = {
	/* ST_USER */
	{ 0x01, "V1" },
	{ 0x02, "CONNECT" },
	{ 0x03, "SELECTEDRECT" },
	{ 0x04, "FONTMETRIC" },
	{ 0x05, "TABLEMETRIC" },
	{ 0x06, "GUITIME" },
	{ 0x07, "GUITIMEZONE" },
	{ 0x08, "TURNTIME" },
	{ 0x09, "GUIVERSION" },
	/* No entry for 0xa... */
	{ 0x0b, "SUPPORTDATA" },
	{ 0x0c, "RFC_CONNECT" },
	{ 0x0d, "WSIZE" },
	{ 0x0e, "V2" },
	{ 0x0f, "TURNTIME2" },
	{ 0x10, "RFC_PARENT_UUID" },
	{ 0x11, "RFC_NEW_UUID" },
	{ 0x12, "RFC_UUIDS" },
	{ 0x13, "RFC_UUIDS2" },
	{ 0x14, "XML_LOGIN" },
	{ 0x15, "XML_TRANSACTION" },
	{ 0x16, "SCROLLBAR_WIDTH" },
	{ 0x17, "TOOLBAR_HEIGHT" },
	{ 0x18, "PASSPORT_DATA" },
	{ 0x19, "GUI_STATE" },
	{ 0x1a, "DECIMALPOINT" },
	{ 0x1b, "LANGUAGE" },
	{ 0x1c, "USERNAME" },
	{ 0x1d, "GUIPATCHLEVEL" },
	{ 0x1e, "WSIZE_PIXEL" },
	{ 0x1f, "GUI_OS_VERSION" },
	{ 0x20, "BROWSER_VERSION" },
	{ 0x21, "OFFICE_VERSION" },
	{ 0x22, "JDK_VERSION" },
	{ 0x23, "GUIXT_VERSION" },
	{ 0x24, "DISPLAY_SIZE" },
	{ 0x25, "GUI_TYPE" },
	{ 0x26, "DIALOG_STEP_NUMBER" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 DYNN SID values */
static const value_string sapdiag_item_appl_dynn_vals[] = {
	/* DYNN */
	{ 0x01, "CHL" },
	{ 0x03, "XMLPROP DYNPRO" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ST_R3INFO SID values */
static const value_string sapdiag_item_appl_st_r3info_vals[] = {
	/* ST_R3INFO */
	{ 0x01, "MODENUMBER" },
	{ 0x02, "DBNAME" },
	{ 0x03, "CPUNAME" },
	{ 0x04, "RFC_TRIGGER" },
	{ 0x05, "GUI_LABEL" },
	{ 0x06, "DIAGVERSION" },
	{ 0x07, "TCODE" },
	{ 0x08, "RFC_WAITING" },
	{ 0x09, "RFC_REFRESH" },
	{ 0x0a, "IMODENUMBER" },
	{ 0x0b, "MESSAGE" },
	{ 0x0c, "CLIENT" },
	{ 0x0d, "DYNPRONAME" },
	{ 0x0e, "DYNPRONUMBER" },
	{ 0x0f, "CUANAME" },
	{ 0x10, "CUASTATUS" },
	{ 0x11, "SUPPORTDATA" },
	{ 0x12, "RFC_CONNECT_OK" },
	{ 0x13, "GUI_FKEY" },
	{ 0x14, "GUI_FKEYT" },
	{ 0x15, "STOP_TRANS" },
	{ 0x16, "RFC_DIAG_BLOCK_SIZE" },
	{ 0x17, "USER_CHECKED" },
	{ 0x18, "FLAGS" },
	{ 0x19, "USERID" },
	{ 0x1a, "ROLLCOUNT" },
	{ 0x1b, "GUI_XT_VAR" },
	{ 0x1c, "IMODEUUID" },
	{ 0x1d, "IMODEUUID_INVALIDATE" },
	{ 0x1e, "IMODEUUIDS" },
	{ 0x1f, "IMODEUUIDS2" },
	{ 0x20, "CODEPAGE" },
	{ 0x21, "CONTEXTID" },
	{ 0x22, "AUTOLOGOUT_TIME" },
	{ 0x23, "CODEPAGE_DIAG_GUI" },
	{ 0x24, "CODEPAGE_APP_SERVER" },
	{ 0x25, "GUI_THEME" },
	{ 0x26, "GUI_USER_SCRIPTING" },
	{ 0x27, "CODEPAGE_APP_SERVER_1" },
	{ 0x28, "TICKET4GUI" },
	{ 0x29, "KERNEL_VERSION" },
	{ 0x2a, "STD_TOOLBAR_ITEMS" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 POPU SID values */
static const value_string sapdiag_item_appl_popu_vals[] = {
	/* POPU */
	{ 0x02, "DEST" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 RFC_TR SID values */
static const value_string sapdiag_item_appl_rfc_tr_vals[] = {
	/* RFC_TR */
	{ 0x00, "RFC_TR_REQ" },
	{ 0x01, "RFC_TR_RET" },
	{ 0x02, "RFC_TR_ERR" },
	{ 0x03, "RFC_TR_RQT" },
	{ 0x04, "RFC_TR_MOR" },
	{ 0x05, "RFC_TR_MOB" },
	{ 0x06, "RFC_TR_RNB" },
	{ 0x07, "RFC_TR_RNT" },
	{ 0x08, "RFC_TR_DIS" },
	{ 0x09, "RFC_TR_CALL" },
	{ 0x0a, "RFC_TR_CALL_END" },
	{ 0x0b, "RFC_TR_RES" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 DYNT SID values */
static const value_string sapdiag_item_appl_dynt_vals[] = {
	/* DYNT */
	{ 0x01, "DYNT_FOCUS" },
	{ 0x02, "DYNT_ATOM" },
	{ 0x03, "DYNT_EVENT_UNUSED" },
	{ 0x04, "TABLE_ROW_REFERENCE" },
	{ 0x05, "TABLE_ROW_DAT_INPUT_DUMMY" },
	{ 0x06, "TABLE_INPUT_HEADER" },
	{ 0x07, "TABLE_OUTPUT_HEADER" },
	{ 0x08, "TABLE_ROW_DATA_INPUT" },
	{ 0x09, "TABLE_ROW_DATA_OUTPUT" },
	{ 0x0a, "DYNT_NOFOCUS" },
	{ 0x0b, "DYNT_FOCUS_1" },
	{ 0x0c, "TABLE_ROW_REFERENCE_1" },
	{ 0x0d, "TABLE_FIELD_NAMES" },
	{ 0x0e, "TABLE_HEADER" },
	{ 0x0f, "DYNT_TABSTRIP_HEADER" },
	{ 0x10, "DYNT_TABSTRIP_BUTTONS" },
	{ 0x11, "TABLE_ROW_REFERENCE_2" },
	{ 0x12, "DYNT_CONTROL_FOCUS" },
	{ 0x13, "TABLE_FIELD_XMLPROP" },
	{ 0x14, "DYNT_SPLITTER_HEADER" },
	{ 0x15, "DYNT_TC_COLUMN_TITLE_XMLP" },
	{ 0x16, "DYNT_TC_ROW_SELECTOR_NAME" },
	{ 0x17, "DYNT_FOCUS_FRAME" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 CONTAINER SID values */
static const value_string sapdiag_item_appl_container_vals[] = {
	/* CONTAINER */
	{ 0x01, "RESET" },
	{ 0x02, "DEFAULT" },
	{ 0x03, "SUBSCREEN" },
	{ 0x04, "LOOP" },
	{ 0x05, "TABLE" },
	{ 0x06, "NAME" },
	{ 0x08, "TABSTRIP" },
	{ 0x09, "TABSTRIP_PAGE" },
	{ 0x0a, "CONTROL" },
	{ 0x0c, "XMLPROP" },
	{ 0x0d, "SPLITTER" },
	{ 0x0e, "SPLITTER_CELL" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 MNUENTRY SID values */
static const value_string sapdiag_item_appl_mnuentry_vals[] = {
	/* MNUENTRY */
	{ 0x01, "MENU_ACT" },
	{ 0x02, "MENU_MNU" },
	{ 0x03, "MENU_PFK" },
	{ 0x04, "MENU_KYB" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 VARINFO SID values */
static const value_string sapdiag_item_appl_varinfo_vals[] = {
	/* VARINFO */
	{ 0x01, "MESTYPE" },
	{ 0x02, "SCROLL_INFOS" },
	{ 0x03, "MESTYPE2" },
	{ 0x04, "OKCODE" },
	{ 0x05, "CONTAINER" },
	{ 0x06, "SCROLL_INFOS2" },
	{ 0x07, "AREASIZE" },
	{ 0x08, "AREA_PIXELSIZE" },
	{ 0x09, "SESSION_TITLE" },
	{ 0x0a, "SESSION_ICON" },
	{ 0x0b, "LIST_CELL_TEXT" },
	{ 0x0c, "CONTAINER_LOOP" },
	{ 0x0d, "LIST_FOCUS" },
	{ 0x0e, "MAINAREA_PIXELSIZE" },
	{ 0x0f, "SERVICE_REQUEST" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 CONTROl SID values */
static const value_string sapdiag_item_appl_control_vals[] = {
	/* CONTROL */
	{ 0x01, "CONTROL_PROPERTIES" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 UI_EVENT SID values */
static const value_string sapdiag_item_appl_ui_event_vals[] = {
	/* UI_EVENT */
	{ 0x01, "UI_EVENT_SOURCE" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ACC_LIST SID values */
static const value_string sapdiag_item_appl_acc_list_vals[] = {
	/* ACC_LIST */
	{ 0x01, "ACC_LIST_INFO4FIELD" },
	{ 0x02, "ACC_LIST_CONTAINER" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 RCUI SID values */
static const value_string sapdiag_item_appl_rcui_vals[] = {
	/* RCUI */
	{ 0x01, "RCUI_STREAM" },
	{ 0x02, "RCUI_SYSTEM_ERROR" },
	{ 0x03, "RCUI_SPAGPA" },
	{ 0x04, "RCUI_MEMORYID" },
	{ 0x05, "RCUI_TXOPTION" },
	{ 0x06, "RCUI_VALUE" },
	{ 0x07, "RCUI_COMMAND" },
	{ 0x08, "RCUI_BDCMSG" },
	{ 0x09, "RCUI_CONNECT_DATA" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 GUI_PACKET SID values */
static const value_string sapdiag_item_appl_gui_packet_vals[] = {
	/* GUI_PACKET */
	{ 0x01, "GUI_PACKET_STATE" },
	{ 0x02, "GUI_PACKET_DATA" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Dynt Atom Etype values */
static const value_string sapdiag_item_dynt_atom_item_etype_vals[] = {
	{ 101, "DIAG_DGOTYP_EFIELD" },
	{ 102, "DIAG_DGOTYP_OFIELD" },
	{ 103, "DIAG_DGOTYP_KEYWORD" },
	{ 104, "DIAG_DGOTYP_CHECKBUTTON_4" },
	{ 105, "DIAG_DGOTYP_RADIOBUTTON_0" },
	{ 106, "DIAG_DGOTYP_PUSHBUTTON_3" },
	{ 107, "DIAG_DGOTYP_FRAME_3" },
	{ 108, "DIAG_DGOTYP_LOOP_6" },
	{ 109, "DIAG_DGOTYP_SUBSCREEN" },
	/* No value for 110? */
	{ 111, "DIAG_DGOTYP_PROPERTY" },
	{ 112, "DIAG_DGOTYP_ICON_0" },
	{ 113, "DIAG_DGOTYP_PUSHBUTTON_1" },
	{ 114, "DIAG_DGOTYP_FNAME" },
	{ 115, "DIAG_DGOTYP_PUSHBUTTON_2" },
	{ 116, "DIAG_DGOTYP_TABSTRIP_BUTTON" },
	{ 117, "DIAG_DGOTYP_COMBOBOX" },
	{ 118, "DIAG_DGOTYP_CHECKBUTTON_1" },
	{ 119, "DIAG_DGOTYP_RADIOBUTTON_1" },
	{ 120, "DIAG_DGOTYP_XMLPROP" },
	{ 121, "DIAG_DGOTYP_EFIELD_1" },
	{ 122, "DIAG_DGOTYP_OFIELD_1" },
	{ 123, "DIAG_DGOTYP_KEYWORD_1_1" },
	{ 124, "DIAG_DGOTYP_CHECKBUTTON_2" },
	{ 125, "DIAG_DGOTYP_RADIOBUTTON__0" },
	{ 126, "DIAG_DGOTYP_COMBOBOX_1" },
	{ 127, "DIAG_DGOTYP_FRAME_1" },
	{ 128, "DIAG_DGOTYP_CHECKBUTTON_3" },
	{ 129, "DIAG_DGOTYP_RADIOBUTTON_3" },
	{ 130, "DIAG_DGOTYP_EFIELD_2" },
	{ 131, "DIAG_DGOTYP_OFIELD_2" },
	{ 132, "DIAG_DGOTYP_KEYWORD_2" },
	/* NULL */
	{ 0, NULL }
};

/* SAP Diag UI Event Source Event Type Values */
static const value_string sapdiag_item_ui_event_event_type_vals[] = {
	{ 0x01, "SELECT" },
	{ 0x02, "HE" },
	{ 0x03, "VALUEHELP" },
	{ 0x06, "RESIZE" },
	{ 0x07, "FUNCTIONKEY" },
	{ 0x08, "SCROLL" },
	{ 0x09, "BUTTONPRESSED" },
	{ 0x0a, "VALUECHANGED" },
	{ 0x0b, "STATECHANGED" },
	{ 0x0c, "NAVIGATION" },
	/* NULL */
	{ 0x00, NULL }
};

static const value_string sapdiag_item_ui_event_control_type_vals[] = {
	{ 0x00, "NONE" },
	{ 0x01, "FIELD" },
	{ 0x02, "RADIOBUTTON" },
	{ 0x03, "CHECKBUTTON" },
	{ 0x04, "MENUBUTTON" },
	{ 0x05, "TOOLBARBUTTON" },
	{ 0x06, "STANDARDTOOLBARBUTTON" },
	{ 0x07, "PUSHBUTTON" },
	{ 0x08, "TABLEVIEW" },
	{ 0x09, "TABSTRIP" },
	{ 0x0a, "DYNPRO" },
	{ 0x0b, "CUSTOM_CONTROL" },
	{ 0x0d, "FRAME" },
	{ 0x0e, "TABLEVIEW_COLSEL_BUTTON" },
	{ 0x0f, "TABLEVIEW_ROWSEL_BUTTON" },
	{ 0x10, "TABLEVIEW_CELL" },
	{ 0x11, "CONTEXTMENU" },
	{ 0x12, "SPLITTER" },
	{ 0x13, "MESSAGE" },
	{ 0x14, "OKCODE" },
	{ 0x15, "ACC_CONTAINER" },
	/* NULL */
	{ 0x00, NULL }
};

static const value_string sapdiag_item_ui_event_navigation_data_vals[] = {
	{ 0x01, "TAB" },
	{ 0x02, "TAB_BACK" },
	{ 0x03, "JUMP_OVER" },
	{ 0x04, "JUMP_OVER_BACK" },
	{ 0x05, "JUMP_OUT" },
	{ 0x06, "JUMP_OUT_BACK" },
	{ 0x07, "JUMP_SECTION" },
	{ 0x08, "JUMP_SECTION_BACK" },
	{ 0x09, "FIRST_FIELD" },
	{ 0x0a, "LAST_FIELD" },
	/* NULL */
	{ 0x00, NULL }
};

static const value_string sapdiag_item_control_properties_id_vals[] = {
	{ 0x01, "CONTROL_AREA" },
	{ 0x02, "CONTROL_ID" },
	{ 0x03, "CONTROL_VISIBLE" },
	{ 0x04, "CONTROL_ROW" },
	{ 0x05, "CONTROL_COLUMN" },
	{ 0x06, "CONTROL_ROWS" },
	{ 0x07, "CONTROL_COLUMNS" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Dynt Atom Attr flags */
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_PROTECTED	0x01
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_INVISIBLE	0x02
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_INTENSIFY	0x04
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_JUSTRIGHT	0x08
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_MATCHCODE	0x10
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_PROPFONT		0x20
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_YES3D		0x40
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_COMBOSTYLE	0x80

/* SAP Diag UI Event Source flags */
#define SAPDIAG_UI_EVENT_VALID_FLAG_MENU_POS			0x01
#define SAPDIAG_UI_EVENT_VALID_FLAG_CONTROL_POS			0x02
#define SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA		0x04
#define SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA	0x08

static int proto_sapdiag;

static int hf_sapdiag_dp;
static int hf_sapdiag_header;
static int hf_sapdiag_payload;

/* Diag Header */
static int hf_sapdiag_mode;
static int hf_sapdiag_com_flag;
static int hf_sapdiag_com_flag_TERM_EOS;
static int hf_sapdiag_com_flag_TERM_EOC;
static int hf_sapdiag_com_flag_TERM_NOP;
static int hf_sapdiag_com_flag_TERM_EOP;
static int hf_sapdiag_com_flag_TERM_INI;
static int hf_sapdiag_com_flag_TERM_CAS;
static int hf_sapdiag_com_flag_TERM_NNM;
static int hf_sapdiag_com_flag_TERM_GRA;

static int hf_sapdiag_mode_stat;
static int hf_sapdiag_err_no;
static int hf_sapdiag_msg_type;
static int hf_sapdiag_msg_info;
static int hf_sapdiag_msg_rc;
static int hf_sapdiag_compress;

/* Error messages */
static int hf_sapdiag_error_message;

/* Compression header */
static int hf_sapdiag_compress_header;
static int hf_sapdiag_uncomplength;
static int hf_sapdiag_algorithm;
static int hf_sapdiag_magic;
static int hf_sapdiag_special;

/* Message Data */
static int hf_sapdiag_item;
static int hf_sapdiag_item_type;
static int hf_sapdiag_item_id;
static int hf_sapdiag_item_sid;
static int hf_sapdiag_item_length_short;
static int hf_sapdiag_item_length_long;
static int hf_sapdiag_item_value;

/* Message DP Header */
static int hf_sapdiag_dp_request_id;
static int hf_sapdiag_dp_retcode;
static int hf_sapdiag_dp_sender_id;
static int hf_sapdiag_dp_action_type;
static int hf_sapdiag_dp_req_info;

static int hf_sapdiag_dp_req_info_LOGIN;
static int hf_sapdiag_dp_req_info_LOGOFF;
static int hf_sapdiag_dp_req_info_SHUTDOWN;
static int hf_sapdiag_dp_req_info_GRAPHIC_TM;
static int hf_sapdiag_dp_req_info_ALPHA_TM;
static int hf_sapdiag_dp_req_info_ERROR_FROM_APPC;
static int hf_sapdiag_dp_req_info_CANCELMODE;
static int hf_sapdiag_dp_req_info_MSG_WITH_REQ_BUF;
static int hf_sapdiag_dp_req_info_MSG_WITH_OH;
static int hf_sapdiag_dp_req_info_BUFFER_REFRESH;
static int hf_sapdiag_dp_req_info_BTC_SCHEDULER;
static int hf_sapdiag_dp_req_info_APPC_SERVER_DOWN;
static int hf_sapdiag_dp_req_info_MS_ERROR;
static int hf_sapdiag_dp_req_info_SET_SYSTEM_USER;
static int hf_sapdiag_dp_req_info_DP_CANT_HANDLE_REQ;
static int hf_sapdiag_dp_req_info_DP_AUTO_ABAP;
static int hf_sapdiag_dp_req_info_DP_APPL_SERV_INFO;
static int hf_sapdiag_dp_req_info_DP_ADMIN;
static int hf_sapdiag_dp_req_info_DP_SPOOL_ALRM;
static int hf_sapdiag_dp_req_info_DP_HAND_SHAKE;
static int hf_sapdiag_dp_req_info_DP_CANCEL_PRIV;
static int hf_sapdiag_dp_req_info_DP_RAISE_TIMEOUT;
static int hf_sapdiag_dp_req_info_DP_NEW_MODE;
static int hf_sapdiag_dp_req_info_DP_SOFT_CANCEL;
static int hf_sapdiag_dp_req_info_DP_TM_INPUT;
static int hf_sapdiag_dp_req_info_DP_TM_OUTPUT;
static int hf_sapdiag_dp_req_info_DP_ASYNC_RFC;
static int hf_sapdiag_dp_req_info_DP_ICM_EVENT;
static int hf_sapdiag_dp_req_info_DP_AUTO_TH;
static int hf_sapdiag_dp_req_info_DP_RFC_CANCEL;
static int hf_sapdiag_dp_req_info_DP_MS_ADM;

static int hf_sapdiag_dp_tid;
static int hf_sapdiag_dp_uid;
static int hf_sapdiag_dp_mode;
static int hf_sapdiag_dp_wp_id;
static int hf_sapdiag_dp_wp_ca_blk;
static int hf_sapdiag_dp_appc_ca_blk;
static int hf_sapdiag_dp_len; /* Length of the SAP Diag Items in the login */
static int hf_sapdiag_dp_new_stat;
static int hf_sapdiag_dp_rq_id;
static int hf_sapdiag_dp_terminal;

/* Dynt Atom */
static int hf_sapdiag_item_dynt_atom;
static int hf_sapdiag_item_dynt_atom_item;
static int hf_sapdiag_item_dynt_atom_item_etype;
static int hf_sapdiag_item_dynt_atom_item_attr;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_COMBOSTYLE;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_YES3D;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROPFONT;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_MATCHCODE;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_JUSTRIGHT;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INTENSIFY;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INVISIBLE;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROTECTED;

/* Control properties */
static int hf_sapdiag_item_control_properties_id;
static int hf_sapdiag_item_control_properties_value;

/* UI Event Source */
static int hf_sapdiag_item_ui_event_event_type;
static int hf_sapdiag_item_ui_event_control_type;
static int hf_sapdiag_item_ui_event_valid;
static int hf_sapdiag_item_ui_event_valid_MENU_POS;
static int hf_sapdiag_item_ui_event_valid_CONTROL_POS;
static int hf_sapdiag_item_ui_event_valid_NAVIGATION_DATA;
static int hf_sapdiag_item_ui_event_valid_FUNCTIONKEY_DATA;
static int hf_sapdiag_item_ui_event_control_row;
static int hf_sapdiag_item_ui_event_control_col;
static int hf_sapdiag_item_ui_event_data;
static int hf_sapdiag_item_ui_event_navigation_data;
static int hf_sapdiag_item_ui_event_container_nrs;
static int hf_sapdiag_item_ui_event_container;

/* Menu Entries */
static int hf_sapdiag_item_menu_entry;

/* Diag Support Bits */
static int hf_SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1;
static int hf_SAPDIAG_SUPPORT_BIT_UPPERCASE;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY;
static int hf_SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_DIALOG;
static int hf_SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT;
static int hf_SAPDIAG_SUPPORT_BIT_FKEY_TABLE;
static int hf_SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT;
static int hf_SAPDIAG_SUPPORT_BIT_STOP_TRANS;
static int hf_SAPDIAG_SUPPORT_BIT_FULL_MENU;
static int hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES;
static int hf_SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE;
static int hf_SAPDIAG_SUPPORT_BIT_DLGH_FLAGS;
static int hf_SAPDIAG_SUPPORT_BIT_APPL_MNU;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO;
static int hf_SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1;
static int hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB;
static int hf_SAPDIAG_SUPPORT_BIT_GUIAPI;
static int hf_SAPDIAG_SUPPORT_BIT_NOGRAPH;
static int hf_SAPDIAG_SUPPORT_BIT_NOMESSAGES;
static int hf_SAPDIAG_SUPPORT_BIT_NORABAX;
static int hf_SAPDIAG_SUPPORT_BIT_NOSYSMSG;
static int hf_SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT;
static int hf_SAPDIAG_SUPPORT_BIT_NORFC;
static int hf_SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_VARS;
static int hf_SAPDIAG_SUPPORT_BIT_OCX_SUPPORT;
static int hf_SAPDIAG_SUPPORT_BIT_SCROLL_INFOS;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE;
static int hf_SAPDIAG_SUPPORT_BIT_CURR_TCODE;
static int hf_SAPDIAG_SUPPORT_BIT_CONN_WSIZE;
static int hf_SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2;
static int hf_SAPDIAG_SUPPORT_BIT_TABSTRIP;
static int hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_1;
static int hf_SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES;
static int hf_SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST;
static int hf_SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER;
static int hf_SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER;
static int hf_SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED;
static int hf_SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO;
static int hf_SAPDIAG_SUPPORT_BIT_TYPE_SERVER;
static int hf_SAPDIAG_SUPPORT_BIT_COMBOBOX;
static int hf_SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED;
static int hf_SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE;
static int hf_SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS;
static int hf_SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_USERID;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT;
static int hf_SAPDIAG_SUPPORT_BIT_USER_TURNTIME2;
static int hf_SAPDIAG_SUPPORT_BIT_NUM_FIELD;
static int hf_SAPDIAG_SUPPORT_BIT_WIN16;
static int hf_SAPDIAG_SUPPORT_BIT_CONTEXT_MENU;
static int hf_SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE;
static int hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION;
static int hf_SAPDIAG_SUPPORT_BIT_LABEL_OWNER;
static int hf_SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD;
static int hf_SAPDIAG_SUPPORT_BIT_PROPERTY_BAG;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_1;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2;
static int hf_SAPDIAG_SUPPORT_BIT_PROPFONT_VALID;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID;
static int hf_SAPDIAG_SUPPORT_BIT_NOTGUI;
static int hf_SAPDIAG_SUPPORT_BIT_WAN;
static int hf_SAPDIAG_SUPPORT_BIT_XML_BLOBS;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_QUEUE;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_COMPRESS;
static int hf_SAPDIAG_SUPPORT_BIT_JAVA_BEANS;
static int hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND;
static int hf_SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE;
static int hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB;
static int hf_SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_2;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_3;
static int hf_SAPDIAG_SUPPORT_BIT_XML_PROPERTIES;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_4;
static int hf_SAPDIAG_SUPPORT_BIT_HEX_FIELD;
static int hf_SAPDIAG_SUPPORT_BIT_HAS_CACHE;
static int hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_5;
static int hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2;
static int hf_SAPDIAG_SUPPORT_BIT_ITS;
static int hf_SAPDIAG_SUPPORT_BIT_NO_EASYACCESS;
static int hf_SAPDIAG_SUPPORT_BIT_PROPERTYPUMP;
static int hf_SAPDIAG_SUPPORT_BIT_COOKIE;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_6;
static int hf_SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE;
static int hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS;
static int hf_SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY;
static int hf_SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE;
static int hf_SAPDIAG_SUPPORT_BIT_CACHED_VSETS;
static int hf_SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR;
static int hf_SAPDIAG_SUPPORT_BIT_AREA2FRONT;
static int hf_SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH;
static int hf_SAPDIAG_SUPPORT_BIT_AUTORESIZE;
static int hf_SAPDIAG_SUPPORT_BIT_EDIT_VARLEN;
static int hf_SAPDIAG_SUPPORT_BIT_WORKPLACE;
static int hf_SAPDIAG_SUPPORT_BIT_PRINTDATA;
static int hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_2;
static int hf_SAPDIAG_SUPPORT_BIT_SINGLE_SESSION;
static int hf_SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE;
static int hf_SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT;
static int hf_SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER;
static int hf_SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO;
static int hf_SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT;
static int hf_SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT;
static int hf_SAPDIAG_SUPPORT_BIT_WEBGUI;
static int hf_SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST;
static int hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2;
static int hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_1;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING;
static int hf_SAPDIAG_SUPPORT_BIT_SLC;
static int hf_SAPDIAG_SUPPORT_BIT_ACCESSIBILITY;
static int hf_SAPDIAG_SUPPORT_BIT_ECATT;
static int hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF8;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_APPL4;
static int hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL;
static int hf_SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE;
static int hf_SAPDIAG_SUPPORT_BIT_BINARY_EVENTID;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_THEME;
static int hf_SAPDIAG_SUPPORT_BIT_TOP_WINDOW;
static int hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1;
static int hf_SAPDIAG_SUPPORT_BIT_SPLITTER;
static int hf_SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY;
static int hf_SAPDIAG_SUPPORT_BIT_ACC_LIST;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO;
static int hf_SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM;
static int hf_SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1;
static int hf_SAPDIAG_SUPPORT_BIT_FRAME_1;
static int hf_SAPDIAG_SUPPORT_BIT_TICKET4GUI;
static int hf_SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS;
static int hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT;
static int hf_SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP;
static int hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2;
static int hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3;
static int hf_SAPDIAG_SUPPORT_BIT_CELLINFO;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT;
static int hf_SAPDIAG_SUPPORT_BIT_ITS_PLUGIN;
static int hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2;
static int hf_SAPDIAG_SUPPORT_BIT_RCUI;
static int hf_SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE;
static int hf_SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP;
static int hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_2;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3;
static int hf_SAPDIAG_SUPPORT_BIT_SBA2;
static int hf_SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE;
static int hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2;
static int hf_SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_PACKET;
static int hf_SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER;
static int hf_SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST;
static int hf_SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME;
static int hf_SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1;
static int hf_SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS;
static int hf_SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO;
static int hf_SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT;
static int hf_SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH;
static int hf_SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT;
static int hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_3;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR;
static int hf_SAPDIAG_SUPPORT_BIT_MAX_WSIZE;
static int hf_SAPDIAG_SUPPORT_BIT_SAP_PERSONAS;
static int hf_SAPDIAG_SUPPORT_BIT_IDA_ALV;
static int hf_SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS;
static int hf_SAPDIAG_SUPPORT_BIT_AMC;
static int hf_SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC;
static int hf_SAPDIAG_SUPPORT_BIT_GROUPBOX;
static int hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON;
static int hf_SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST;
static int hf_SAPDIAG_SUPPORT_BIT_FIORI_MODE;
static int hf_SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE;
static int hf_SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE;
static int hf_SAPDIAG_SUPPORT_BIT_AGI_ID;
static int hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TC;
static int hf_SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS;
static int hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE;
static int hf_SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3;
static int hf_SAPDIAG_SUPPORT_BIT_NWBC;
static int hf_SAPDIAG_SUPPORT_BIT_CONTAINER_LIST;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR;
static int hf_SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE;

static int ett_sapdiag;

/* Expert info */
static expert_field ei_sapdiag_item_unknown;
static expert_field ei_sapdiag_item_partial;
static expert_field ei_sapdiag_item_unknown_length;
static expert_field ei_sapdiag_item_offset_invalid;
static expert_field ei_sapdiag_item_length_invalid;
static expert_field ei_sapdiag_atom_item_unknown;
static expert_field ei_sapdiag_atom_item_partial;
static expert_field ei_sapdiag_atom_item_malformed;
static expert_field ei_sapdiag_dynt_focus_more_cont_ids;
static expert_field ei_sapdiag_password_field;

/* Global RFC dissection preference */
static bool global_sapdiag_rfc_dissection = true;

/* Global SNC dissection preference */
static bool global_sapdiag_snc_dissection = true;

/* Global port preference */
static range_t *global_sapdiag_port_range;

/* Global highlight preference */
static bool global_sapdiag_highlight_items = true;

/* Protocol handle */
static dissector_handle_t sapdiag_handle;

void proto_register_sapdiag(void);
void proto_reg_handoff_sapdiag(void);


static void
dissect_sapdiag_dp_req_info(tvbuff_t *tvb, proto_tree *tree, uint32_t offset){
	proto_item *ri = NULL;
	proto_tree *req_info_tree;

	ri = proto_tree_add_item(tree, hf_sapdiag_dp_req_info, tvb, offset, 4, ENC_BIG_ENDIAN);
	req_info_tree = proto_item_add_subtree(ri, ett_sapdiag);

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_LOGIN, tvb, offset, 1, ENC_BIG_ENDIAN);		/* 0x08 */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_LOGOFF, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_SHUTDOWN, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_GRAPHIC_TM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_ALPHA_TM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_ERROR_FROM_APPC, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_CANCELMODE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_MSG_WITH_REQ_BUF, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_MSG_WITH_OH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0x09 */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_BUFFER_REFRESH, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_BTC_SCHEDULER, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_APPC_SERVER_DOWN, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_MS_ERROR, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_SET_SYSTEM_USER, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_CANT_HANDLE_REQ, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_AUTO_ABAP, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_APPL_SERV_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0x0a */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_ADMIN, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_SPOOL_ALRM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_HAND_SHAKE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_CANCEL_PRIV, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_RAISE_TIMEOUT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_NEW_MODE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_SOFT_CANCEL, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_TM_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0x0b */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_TM_OUTPUT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_ASYNC_RFC, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_ICM_EVENT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_AUTO_TH, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_RFC_CANCEL, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_MS_ADM, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_sapdiag_dp(tvbuff_t *tvb, proto_tree *tree, uint32_t offset){
	proto_item *dp = NULL;
	proto_tree *dp_tree;

	dp = proto_tree_add_item(tree, hf_sapdiag_dp, tvb, offset, 200, ENC_NA);
	dp_tree = proto_item_add_subtree(dp, ett_sapdiag);

	proto_tree_add_item(dp_tree, hf_sapdiag_dp_request_id, tvb, offset, 4, ENC_BIG_ENDIAN); 		/* 0x00 */
	offset+=4;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_retcode, tvb, offset, 1, ENC_BIG_ENDIAN);			/* 0x04 */
	offset++;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_sender_id, tvb, offset, 1, ENC_BIG_ENDIAN);			/* 0x05 */
	offset++;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_action_type, tvb, offset, 1, ENC_BIG_ENDIAN); 		/* 0x06 */
	offset++;
	dissect_sapdiag_dp_req_info(tvb, dp_tree, offset);          	/* Request info flags */		/* 0x07 */
	offset+=4;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_tid, tvb, offset, 4, ENC_BIG_ENDIAN);				/* 0x0b */
	offset+=4;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_uid, tvb, offset, 2, ENC_BIG_ENDIAN);				/* 0x0f */
	offset+=2;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_mode, tvb, offset, 1, ENC_BIG_ENDIAN);				/* 0x11 */
	offset++;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_wp_id, tvb, offset, 4, ENC_BIG_ENDIAN);				/* 0x12 */
	offset+=4;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_wp_ca_blk, tvb, offset, 4, ENC_BIG_ENDIAN);			/* 0x16 */
	offset+=4;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_appc_ca_blk, tvb, offset, 4, ENC_BIG_ENDIAN);		/* 0x1a */
	offset+=4;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);				/* 0x1e */
	offset+=4;
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_new_stat, tvb, offset, 1, ENC_BIG_ENDIAN);			/* 0x22 */
	offset++;
	offset+=4; 	/* Unknown 4 bytes */																/* 0x23 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_rq_id, tvb, offset, 2, ENC_BIG_ENDIAN);				/* 0x27 */
	offset+=2;
	offset+=40; /* Unknown 40 bytes (0x20 * 40) */													/* 0x29 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_terminal, tvb, offset, 15, ENC_ASCII|ENC_NA);		/* 0x51 */
}

static void
dissect_sapdiag_support_bits(tvbuff_t *tvb, proto_tree *tree, uint32_t offset){

	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 1 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 2 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 3 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 4 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 5 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 6 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 7 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 8 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 9 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 10 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 11 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UPPERCASE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 12 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 13 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 14 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_DIALOG, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 15 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 16 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FKEY_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 17 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 18 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_STOP_TRANS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 19 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FULL_MENU, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 20 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 21 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 22 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DLGH_FLAGS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 23 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_APPL_MNU, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 24 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 25 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 26 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 27 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUIAPI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 28 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOGRAPH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 29 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOMESSAGES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 30 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NORABAX, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 31 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOSYSMSG, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 32 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 33 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NORFC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 34 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 35 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_VARS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 36 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OCX_SUPPORT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 37 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SCROLL_INFOS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 38 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 39 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 40 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 41 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CURR_TCODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 42 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONN_WSIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 43 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 44 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSTRIP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 45 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 46 (Unknown support bit) */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 47 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 48 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 49 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 50 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 51 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 52 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 53 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 54 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 55 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TYPE_SERVER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 56 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_COMBOBOX, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 57 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 58 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 59 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 60 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 61 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 62 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_USERID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 63 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 64 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_USER_TURNTIME2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 65 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NUM_FIELD, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 66 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WIN16, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 67 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTEXT_MENU, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 68 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 69 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 70 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_LABEL_OWNER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 71 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 72 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROPERTY_BAG, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 73 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 74 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 75 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROPFONT_VALID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 76 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 77 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 78 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOTGUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 79 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WAN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 80 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_BLOBS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 81 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_QUEUE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 82 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_COMPRESS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 83 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_JAVA_BEANS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 84 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 85 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 86 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 87 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 88 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 89 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 90 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 91 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_PROPERTIES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 92 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_4, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 93 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_HEX_FIELD, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 94 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_HAS_CACHE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 95 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 96 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_5, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 97 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 98 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ITS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 99 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NO_EASYACCESS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 100 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROPERTYPUMP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 101 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_COOKIE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 102 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_6, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 103 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 104 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 105 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 106 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 107 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 108 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CACHED_VSETS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 109 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 110 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AREA2FRONT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 111 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 112 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AUTORESIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 113 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EDIT_VARLEN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 114 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WORKPLACE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 115 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PRINTDATA, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 116 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 117 (Unknown support bit) */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SINGLE_SESSION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 118 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 119 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 120 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 121 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 122 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 123 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 124 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WEBGUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 125 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 126 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 127 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 128 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 129 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 130 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SLC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 131 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ACCESSIBILITY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 132 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ECATT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 133 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 134 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF8, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 135 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 136 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 137 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 138 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 139 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 140 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_APPL4, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 141 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 142 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 143 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_BINARY_EVENTID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 144 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_THEME, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 145 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TOP_WINDOW, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 146 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 147 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SPLITTER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 148 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 149 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ACC_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 150 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 151 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 152 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 153 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 154 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FRAME_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 155 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TICKET4GUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 156 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 157 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 158 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 159 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 160 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 161 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CELLINFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 162 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 163 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 164 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ITS_PLUGIN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 165 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 166 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 167 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 168 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RCUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 169 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 170 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 171 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 172 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 173 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 174 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 175 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SBA2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 176 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 177 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 178 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 179 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_PACKET, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 180 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 181 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 182 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 183 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 184 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 185 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 186 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 187 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 188 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 189 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 190 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 191 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 192 (Unknown support bit) */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 193 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MAX_WSIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 194 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAP_PERSONAS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 195 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_IDA_ALV, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 196 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 197 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AMC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 198 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 199 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GROUPBOX, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 200 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 201 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 202 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FIORI_MODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 203 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 204 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 205 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AGI_ID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 206 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 207 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 208 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 209 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 210 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NWBC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 211 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTAINER_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 212 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 213 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 214 */
}

static void
dissect_sapdiag_rfc_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint32_t item_length){

	tvbuff_t *next_tvb = NULL;
	dissector_handle_t rfc_handle;

	/* Call the RFC internal dissector.
	 * TODO: This should be enabled when the RFC dissector is merged as they depend on each other.
	 */
	if (global_sapdiag_rfc_dissection && false){
		rfc_handle = find_dissector("saprfcinternal");
		if (rfc_handle){
			/* Set the column to not writable so the RFC dissector doesn't override the Diag info */
			col_set_writable(pinfo->cinfo, -1, false);
			/* Create a new tvb buffer and call the dissector */
			next_tvb = tvb_new_subset_length(tvb, offset, item_length);
			call_dissector(rfc_handle, next_tvb, pinfo, tree);
		}
	}

}


static bool
check_length(packet_info *pinfo, proto_tree *tree, uint32_t expected, uint32_t real, const char *name_string){
	if (expected != real){
		expert_add_info_format(pinfo, tree, &ei_sapdiag_item_length_invalid, "Item %s length is invalid", name_string);
		return false;
	} else return true;
}


static uint8_t
add_item_value_uint8(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, uint32_t offset, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, 1, "%s: %d", text, tvb_get_uint8(tvb, offset));
	proto_item_append_text(item, ", %s=%d", text, tvb_get_uint8(tvb, offset));
	return (tvb_get_uint8(tvb, offset));
}


static uint16_t
add_item_value_uint16(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, uint32_t offset, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, 2, "%s: %d", text, tvb_get_ntohs(tvb, offset));
	proto_item_append_text(item, ", %s=%d", text, tvb_get_ntohs(tvb, offset));
	return (tvb_get_ntohs(tvb, offset));
}


static uint32_t
add_item_value_uint32(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, uint32_t offset, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, 4, "%s: %d", text, tvb_get_ntohl(tvb, offset));
	proto_item_append_text(item, ", %s=%d", text, tvb_get_ntohl(tvb, offset));
	return (tvb_get_ntohl(tvb, offset));
}


static void
add_item_value_string(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int hf, uint32_t offset, uint32_t length, const char *text, int show_in_tree){
	uint8_t *string = tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII);
	proto_tree_add_none_format(tree, hf, tvb, offset, length, "%s: %s", text, string);
	if (show_in_tree) proto_item_append_text(item, ", %s=%s", text, string);
}


static uint32_t
add_item_value_stringz(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int hf, uint32_t offset, const char *text, int show_in_tree){
	uint32_t length = tvb_strsize(tvb, offset);
	uint8_t *string = tvb_get_string_enc(pinfo->pool, tvb, offset, length - 1, ENC_ASCII);
	proto_tree_add_none_format(tree, hf, tvb, offset, length, "%s: %s", text, string);
	if (show_in_tree) proto_item_append_text(item, ", %s=%s", text, string);
	return (length);
}


static void
add_item_value_hexstring(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int hf, uint32_t offset, uint32_t length, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, length, "%s: %s", text, tvb_bytes_to_str(pinfo->pool, tvb, offset, length));
	proto_item_append_text(item, ", %s=%s", text, tvb_bytes_to_str(pinfo->pool, tvb, offset, length));
}


static void
dissect_sapdiag_dyntatom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint32_t length){
	uint32_t final = offset + length;
	uint16_t atom_length = 0, atom_item_length = 0;
	uint8_t etype = 0, attr = 0;

	proto_item *atom = NULL, *atom_item = NULL, *atom_item_attr = NULL;
	proto_tree *atom_tree = NULL, *atom_item_tree = NULL, *atom_item_attr_tree = NULL;

	while (offset < final){

		etype = tvb_get_uint8(tvb, offset+4);
		if ((etype != 114) && (etype != 120)) {
			/* Add a new atom subtree */
			atom_length = 0;
			atom = proto_tree_add_item(tree, hf_sapdiag_item_dynt_atom, tvb, offset, atom_length, ENC_NA);
			atom_tree = proto_item_add_subtree(atom, ett_sapdiag);
			proto_item_append_text(atom, ", Etype=%s", val_to_str_const(etype, sapdiag_item_dynt_atom_item_etype_vals, "Unknown")); /* Add the Etype to the Atom tree also */
		}

		/* Check the atom_tree for NULL values. If the atom_tree wasn't created at this point, the atom
		 * starts with an item different to 114 or 120. */
		if (atom_tree == NULL){
			expert_add_info(pinfo, tree, &ei_sapdiag_atom_item_malformed);
			break;
		}

		/* Add the item atom subtree */
		atom_item = proto_tree_add_item(atom_tree, hf_sapdiag_item_dynt_atom_item, tvb, offset, tvb_get_ntohs(tvb, offset), ENC_NA);
		atom_item_tree = proto_item_add_subtree(atom_item, ett_sapdiag);

		/* Get the atom item length */
		atom_item_length = add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Atom Length");

		/* Adjust the length of the atom tree, adding the new item's length and the length field */
		atom_length+= atom_item_length;
		proto_item_set_len(atom_tree, atom_length);

		/* Continue with the dissection */
		offset+=2;
		atom_item_length-=2;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Dlg Flag 1");
		offset+=1;
		atom_item_length-=1;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Dlg Flag 2");
		offset+=1;
		atom_item_length-=1;

		proto_tree_add_item(atom_item_tree, hf_sapdiag_item_dynt_atom_item_etype, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_item_append_text(atom_item, ", EType=%d", tvb_get_uint8(tvb, offset));
		offset+=1;
		atom_item_length-=1;

		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Area");
		offset+=1;
		atom_item_length-=1;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Block");
		offset+=1;
		atom_item_length-=1;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Group");
		offset+=1;
		atom_item_length-=1;
		add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Row");
		offset+=2;
		atom_item_length-=2;
		add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Col");
		offset+=2;
		atom_item_length-=2;

		atom_item_attr = proto_tree_add_item(atom_item_tree, hf_sapdiag_item_dynt_atom_item_attr, tvb, offset, 1, ENC_BIG_ENDIAN);
		atom_item_attr_tree = proto_item_add_subtree(atom_item_attr, ett_sapdiag);

		attr = tvb_get_uint8(tvb, offset);
		proto_item_append_text(atom_item, ", Attr=%d", attr);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROTECTED, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INVISIBLE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INTENSIFY, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_JUSTRIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_MATCHCODE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROPFONT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_YES3D, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_COMBOSTYLE, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		atom_item_length-=1;

		/* If the attribute is set to invisible we're dealing probably with a password field */
		if (attr & SAPDIAG_ATOM_ATTR_DIAG_BSD_INVISIBLE){
			expert_add_info(pinfo, atom_item, &ei_sapdiag_password_field);
		}

		switch (etype){
			case 114:{  /* DIAG_DGOTYP_FNAME */
				add_item_value_string(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 1);
				proto_item_append_text(atom, ", Text=%s", tvb_get_string_enc(pinfo->pool, tvb, offset, atom_item_length, ENC_ASCII));
				break;

			} case 115:{ /* DIAG_DGOTYP_PUSHBUTTON_2 */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Length");
				offset+=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Height");
				offset+=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code Offset");
				offset+=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Offset");
				offset+=2;
				offset+=add_item_value_stringz(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text", 1);
				add_item_value_stringz(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code", 1);
				break;

			} case 116:{ /* DIAG_DGOTYP_TABSTRIP_BUTTON */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Length");
				offset+=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Height");
				offset+=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Page Id");
				offset+=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code Offset");
				offset+=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Offset");
				offset+=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Id Offset");
				offset+=2;
				offset+=add_item_value_stringz(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text", 1);
				offset+=add_item_value_stringz(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code", 1);
				add_item_value_stringz(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "ID", 1);
				break;

			} case 118:  /* DIAG_DGOTYP_CHECKBUTTON_1" */
			  case 119:{ /* DIAG_DGOTYP_RADIOBUTTON_1 */
				/* If the preference is set, report the item as partially dissected in the expert info */
				if (global_sapdiag_highlight_items){
					expert_add_info_format(pinfo, atom_item, &ei_sapdiag_atom_item_partial, "The Diag Atom is dissected partially (0x%.2x)", etype);
				}
				break;

			} case 120:{ /* DIAG_DGOTYP_XMLPROP */
				add_item_value_string(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "XMLProp", 1);
				proto_item_append_text(atom, ", XMLProp=%s", tvb_get_string_enc(pinfo->pool, tvb, offset, atom_item_length, ENC_ASCII));
				break;

			} case 121:  /* DIAG_DGOTYP_EFIELD_1 */
			  case 122:  /* DIAG_DGOTYP_OFIELD_1 */
			  case 123:{ /* DIAG_DGOTYP_KEYWORD_1_1 */
				/* Found in NW 7.00 and 7.01 versions */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Flag1");
				offset+=1;
				atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DLen");
				offset+=1;
				atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MLen");
				offset+=1;
				atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MaxNrChars");
				offset+=2;
				atom_item_length-=2;
				add_item_value_string(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 0);

				break;

			  } case 127:{ /* DIAG_DGOTYP_FRAME_1 */
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DRows");
				offset+=2;
				atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DCols");
				offset+=2;
				atom_item_length-=2;
				add_item_value_string(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 1); offset+=atom_item_length;
				break;

			} case 129:{ /* DIAG_DGOTYP_RADIOBUTTON_3 */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Button");
				offset+=1;
				atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Visible Label Length");
				offset+=2;
				atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "EventID Off");
				offset+=2;
				atom_item_length-=2;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "EventID Len");
				offset+=1;
				atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Off");
				offset+=2;
				atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Length");
				offset+=2;
				atom_item_length-=2;
				add_item_value_string(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 1);
				break;

			} case 130:  /* DIAG_DGOTYP_EFIELD_2 */
			  case 131:  /* DIAG_DGOTYP_OFIELD_2 */
			  case 132:{ /* DIAG_DGOTYP_KEYWORD_2 */
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Flag1");
				offset+=2;
				atom_item_length-=2;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DLen");
				offset+=1;
				atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MLen");
				offset+=1;
				atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MaxNrChars");
				offset+=2;
				atom_item_length-=2;
				add_item_value_string(tvb, pinfo, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 0);
				break;

			} default:
				/* If the preference is set, report the item as unknown in the expert info */
				if (global_sapdiag_highlight_items){
					expert_add_info_format(pinfo, atom_item, &ei_sapdiag_atom_item_unknown, "The Diag Atom has a unknown type that is not dissected (%d)", etype);
				}
				break;
		}
	}

}

static void
dissect_sapdiag_menu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint32_t length){

	uint32_t final = offset + length;

	proto_item *menu = NULL;
	proto_tree *menu_tree = NULL;

	while (offset < final){

		/* Add the menu entry subtree */
		menu = proto_tree_add_item(tree, hf_sapdiag_item_menu_entry, tvb, offset, tvb_get_ntohs(tvb, offset), ENC_NA);
		menu_tree = proto_item_add_subtree(menu, ett_sapdiag);

		add_item_value_uint16(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Length");
		offset+=2;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 1");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 2");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 3");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 4");
		offset+=1;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Flag"); /* XXX: Add flag values */
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Virtual Key");
		offset+=1;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 1");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 2");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 3");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 4");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 5");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 6");
		offset+=1;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 1");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 2");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 3");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 4");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 5");
		offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 6");
		offset+=1;

		offset+=add_item_value_stringz(tvb, pinfo, menu, menu_tree, hf_sapdiag_item_value, offset, "Text", 1);
		offset+=add_item_value_stringz(tvb, pinfo, menu, menu_tree, hf_sapdiag_item_value, offset, "Accelerator", 1);
		add_item_value_stringz(tvb, pinfo, menu, menu_tree, hf_sapdiag_item_value, offset, "Info", 1);
	}

}

static void
dissect_sapdiag_uievent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint32_t length){

	proto_item *event_valid_item = NULL;
	proto_tree *event_valid_tree = NULL;
	uint8_t event_valid = 0;
	uint16_t container_nrs = 0, i = 0;

	event_valid = tvb_get_uint8(tvb, offset);
	event_valid_item = proto_tree_add_item(tree, hf_sapdiag_item_ui_event_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
	event_valid_tree = proto_item_add_subtree(event_valid_item, ett_sapdiag);

	proto_tree_add_item(event_valid_tree, hf_sapdiag_item_ui_event_valid_MENU_POS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(event_valid_tree, hf_sapdiag_item_ui_event_valid_CONTROL_POS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(event_valid_tree, hf_sapdiag_item_ui_event_valid_NAVIGATION_DATA, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(event_valid_tree, hf_sapdiag_item_ui_event_valid_FUNCTIONKEY_DATA, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1;

	proto_tree_add_item(tree, hf_sapdiag_item_ui_event_event_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_item_append_text(tree, ", Event Type=%s", val_to_str_const(tvb_get_ntohs(tvb, offset), sapdiag_item_ui_event_event_type_vals, "Unknown")); offset+=2;length-=2;

	proto_tree_add_item(tree, hf_sapdiag_item_ui_event_control_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_item_append_text(tree, ", Control Type=%s", val_to_str_const(tvb_get_ntohs(tvb, offset), sapdiag_item_ui_event_control_type_vals, "Unknown")); offset+=2;length-=2;

	/* The semantic of the event data changes depending of the event valid flag and are ignored if the
	SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA flag or the SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA
	flags are not set. We dissect them always. */
	if (event_valid & SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA){
		proto_tree_add_item(tree, hf_sapdiag_item_ui_event_navigation_data, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		length-=1;
	} else { /* SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA */
		proto_tree_add_item(tree, hf_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		length-=1;
		proto_tree_add_item(tree, hf_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		length-=1;
		proto_tree_add_item(tree, hf_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		length-=1;
		proto_tree_add_item(tree, hf_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		length-=1;
	}

	/* These items are ignored if the flag SAPDIAG_UI_EVENT_VALID_FLAG_CONTROL_POS is not set. We dissect them always. */
	proto_tree_add_item(tree, hf_sapdiag_item_ui_event_control_row, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	length-=2;
	proto_tree_add_item(tree, hf_sapdiag_item_ui_event_control_col, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	length-=2;

	i = container_nrs = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_sapdiag_item_ui_event_container_nrs, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	length-=2;

	while (i>0 && length>0){
		proto_tree_add_item(tree, hf_sapdiag_item_ui_event_container, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;
		length-=1;
		i--;
	}

	if (i>0){
		expert_add_info_format(pinfo, tree, &ei_sapdiag_dynt_focus_more_cont_ids, "Number of Container IDs (%d) is invalid", container_nrs);
	}
}

static void
dissect_sapdiag_item(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *item_value_tree, proto_tree *parent_tree, uint32_t offset, uint8_t item_type, uint8_t item_id, uint8_t item_sid, uint32_t item_length){

	/* SES item */
	if (item_type==0x01){
		uint8_t event_array = 0;
		check_length(pinfo, item_value_tree, 16, item_length, "SES");

		event_array = tvb_get_uint8(tvb, offset);
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event Array");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 1");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 2");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 3");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 4");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 5");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Screen Flag"); /* XXX: Add flag values */
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Modal No");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "X Pos");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Y Pos");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "IMode");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flag 1"); /* XXX: Add flag values */
		offset+=3;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Dim Row");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Dim Col");

		/* TODO: Incomplete dissection of this item */
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The SES item is dissected partially (event array = 0x%.2x)", event_array);
		}

	} else if (item_type==0x0a) { /* SFE */
		check_length(pinfo, item_value_tree, 3, item_length, "SFE");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control format");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control color");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control extended");

	} else if (item_type==0x0b) { /* SBA */
		check_length(pinfo, item_value_tree, 2, item_length, "SBA");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control y-position");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control x-position");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x26){		/* Dialog Step Number */
		check_length(pinfo, item_value_tree, 4, item_length, "Dialog Step Number");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Dialog Step Number");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x02){		/* Connect */
		check_length(pinfo, item_value_tree, 12, item_length, "Connect");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Protocol Version");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Code Page");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "WS Type");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x04){		/* Font Metric */
		check_length(pinfo, item_value_tree, 8, item_length, "Font Metric");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Variable font size (y)");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Variable font size (x)");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Fixed font size (y)");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Fixed font size (x)");

	} else if ((item_type==0x10 && item_id==0x04 && item_sid==0x0b) ||		/* Support Data */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x11)){
		check_length(pinfo, item_value_tree, 32, item_length, "Support Data");
		dissect_sapdiag_support_bits(tvb, item_value_tree, offset);

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x0d){		/* Window Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Window Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Width");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x0f){		/* Turn Time 2 (Response time) */
		check_length(pinfo, item_value_tree, 4, item_length, "Response time");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Response time");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x16){		/* Scrollbar Width */
		check_length(pinfo, item_value_tree, 2, item_length, "Scrollbar Width");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Scrolllbar Width");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x17){		/* Scrollbar Height */
		check_length(pinfo, item_value_tree, 2, item_length, "Scrollbar Height");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Scrollbar Height");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x19){		/* Gui State */
		check_length(pinfo, item_value_tree, 2, item_length, "Gui State");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flag 1");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flag 2");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x1d){		/* GUI patch level */

		/* GUI Patch level could be a string in old versions, or a single byte integer in newer ones */
		if (item_length == 2){
			add_item_value_string(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, 2, "GUI patch level", 1);
		} else {
			check_length(pinfo, item_value_tree, 1, item_length, "GUI patch level");
			add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "GUI patch level");
		}

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x24){		/* Display Size */
		check_length(pinfo, item_value_tree, 8, item_length, "Display Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height");

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x25){		/* GUI Type */
		check_length(pinfo, item_value_tree, 2, item_length, "GUI Type");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "GUI Type");

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x01){		/* Mode Number */
		check_length(pinfo, item_value_tree, 2, item_length, "Mode Number");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Mode Number");

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x06){		/* Diag version */
		check_length(pinfo, item_value_tree, 2, item_length, "Diag version");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Diag version");

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x0a){		/* Internal Mode Number */
		check_length(pinfo, item_value_tree, 2, item_length, "Internal Mode Number");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Internal Mode Number");

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x13){		/* GUI_FKEY */
		uint32_t length = offset+item_length;
		offset++;  /* TODO: Skip one byte here */
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Virtual key number", 1);
		while ((offset < length) && tvb_offset_exists(tvb, offset)){
			offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "String number", 1);
		}
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x14){		/* GUI_FKEYT */
		offset++;  /* TODO: Skip one byte here */
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Virtual key number");
		offset+=2;  /* TODO: Skip one byte here */
		add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Virtual key text", 1);
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x16){		/* RFC Diag Block Size */
		check_length(pinfo, item_value_tree, 4, item_length, "RFC Diag Block Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "RFC Diag Block Size");

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x18){		/* Info flags */
		check_length(pinfo, item_value_tree, 2, item_length, "Info flags");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Info flags");
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x19){		/* User ID */
		check_length(pinfo, item_value_tree, 2, item_length, "User ID");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "User ID");

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x1f){		/* IMode uuids 2 */
		uint8_t uuids = tvb_get_uint8(tvb, offset);
		if (!check_length(pinfo, item_value_tree, 1 + 17 * uuids, item_length, "IMode uuids") ) return;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Number of uuids");
		offset+=1;
		while ((uuids > 0) && (tvb_offset_exists(tvb, offset + 16 + 1))){
			add_item_value_hexstring(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, 16, "UUID");
			offset+=16;
			add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Active context");
			offset+=1;
			uuids--;
		}

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x22){		/* Auto logout time */
		check_length(pinfo, item_value_tree, 4, item_length, "Auto logout time");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Auto logout time");

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x23){		/* Codepage Diag GUI */
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (numeric representation)");
		offset+=4;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Minimum number of bytes per character");
		offset+=1;
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (string representation)", 1);
		add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage description", 1);

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x27){		/* Codepage App Server */
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (numeric representation)");
		offset+=4;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Minimum number of bytes per character");
		offset+=1;
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (string representation)", 1);
		add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage description", 1);

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x29){		/* Kernel Version */
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Database version", 1);
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Kernel version", 1);
		add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Kernel patch level", 1);

	} else if (item_type==0x10 && item_id==0x09 && item_sid==0x0b){		/* Dynt Focus */
		uint32_t length = offset + item_length;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Num of Area ID");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Col");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Row Offset");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Col Offset");
		offset+=2;
		/* Container IDs up to 30 */
		if (length-offset > 30){
			expert_add_info_format(pinfo, item, &ei_sapdiag_dynt_focus_more_cont_ids, "The Dynt Focus contains more than 30 Container IDs (%d)", offset);
		}
		/* Dissect all the remaining container IDs */
		while((offset < length) && tvb_offset_exists(tvb, offset)){
			add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Container ID");
			offset+=1;
		}

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x01){		/* Container Reset */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Reset");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height");

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x04){		/* Container Loop */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Loop");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height");

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x05){		/* Container Table */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Table");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height");

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x06){		/* Container Name */
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Subscreen name", 1);
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Container name", 1);
		add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "Subdynpro name", 1);

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x08){		/* Container TabStrip */
		check_length(pinfo, item_value_tree, 9, item_length, "Container TabStrip");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height");

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x09){		/* Container TabStrip Page */
		check_length(pinfo, item_value_tree, 9, item_length, "Container TabStrip Page");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height");

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x0a){		/* Container Control */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Control");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height");

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x03){		/* Message type */
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);
		offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);
		add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x02){		/* Scroll Infos */
		check_length(pinfo, item_value_tree, 24, item_length, "Scroll Infos");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Width");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Width");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height Offset");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Width Offset");

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x06){		/* Scroll Infos 2 */
		check_length(pinfo, item_value_tree, 33, item_length, "Scroll Infos 2");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Width");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Width");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height Offset");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Width Offset");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Visible Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Visible Width");
		offset+=4;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Scroll Flag");

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x07){		/* Area Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Area Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Width");

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x08){		/* Pixel Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Pixel Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Width");

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x0c){		/* Container Loop */
		check_length(pinfo, item_value_tree, 2, item_length, "Container Loop");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Lines Per Loop Row");

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x0d){		/* List focus */
		check_length(pinfo, item_value_tree, 5, item_length, "List focus");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "List focus version");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "List focus Row");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "List focus Column");

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x0e){		/* Main Area Pixel Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Main Area Pixel Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width");

	/* Dynn items */
	} else if ((item_type==0x09) ||						/* CHL */
		   (item_type==0x10 && item_id==0x05 && item_sid==0x01)){	/* Dynn Chln */
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "scrflg");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "chlflag");
		offset+=2;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "current row");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "current column");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "V Slider Size");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimlistrow");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimlistcol");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "H Slider Size");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimrow");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimcol");
		offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "maxlistrow");
		offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "listrowoffset");
		offset+=2;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "maxlistcol");
		offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "listcoloffset");

		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	/* Control Properties */
	} else if (item_type==0x10 && item_id==0x0e && item_sid==0x01){ /* Control Properties */
		uint32_t length = offset + item_length;

		while((offset < length) && (tvb_offset_exists(tvb, offset + 3))){  /* Check against at least three bytes (2 for ID, 1 for null-terminated value) */
			proto_tree_add_item(item_value_tree, hf_sapdiag_item_control_properties_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_item_append_text(item, ", Control Property ID=%d", tvb_get_ntohs(tvb, offset));
			offset+=2;
			offset+=add_item_value_stringz(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_control_properties_value, offset, "Control Property Value", 1);
		}

	/* UI event source */
	} else if (item_type==0x10 && item_id==0x0f && item_sid==0x01){ /* UI Event Source */
		dissect_sapdiag_uievent(tvb, pinfo, item_value_tree, offset, item_length);

	/* GUI Packet state */
	} else if (item_type==0x10 && item_id==0x14 && item_sid==0x01){ /* GUI Packet state */
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flags"); /* TODO: Add flag values */
		offset+=1;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Bytes Total");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Bytes Send");
		offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Bytes Received");

	/* Dynt items */
	} else if ((item_type==0x12 && item_id==0x09 && item_sid==0x02) ||	/* Dynt Atom */
		   (item_type==0x10 && item_id==0x09 && item_sid==0x02)) {
		dissect_sapdiag_dyntatom(tvb, pinfo, item_value_tree, offset, item_length);

	/* String items */
	} else if ((item_type==0x10 && item_id==0x04 && item_sid==0x09) || 		/* Gui Version */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1a) || 		/* Decimal character */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1b) || 		/* Language */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1c) || 		/* Username */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1f) || 		/* Gui OS Version */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x20) || 		/* Browser Version */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x21) || 		/* Office Version */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x02) || 		/* Database name */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x03) ||	 	/* CPU name */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x07) || 		/* Transaction code */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0b) || 		/* Message */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0c) || 		/* Client */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0d) || 		/* Dynpro name */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0e) || 		/* Dynpro number */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0f) || 		/* Cuaname */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x10) || 		/* Cuastatus */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x21) || 		/* Context ID */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x24) || 		/* Codepage application server */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x25) || 		/* GUI Theme */
		   (item_type==0x10 && item_id==0x09 && item_sid==0x12) || 		/* Control Focus */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x04) || 		/* OK Code */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x09) || 		/* Session title */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x0a) || 		/* Session icon */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x0b)) 		/* List Cell text */
	{
		add_item_value_string(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, item_length, "Value", 1);

	/* RFC Embedded calls */
	} else if (item_type==0x10 && item_id==0x08){ /* RFC_TR */
		dissect_sapdiag_rfc_call(tvb, pinfo, parent_tree, offset, item_length);

	/* String items (long text) */
	} else if (item_type==0x11){										/* Data Stream */
		add_item_value_string(tvb, pinfo, item, item_value_tree, hf_sapdiag_item_value, offset, item_length, "Value", 0);

	/* Tab Strip Controls */
	} else if ((item_type==0x12 && item_id==0x09 && item_sid==0x10)) {
		dissect_sapdiag_dyntatom(tvb, pinfo, item_value_tree, offset, item_length);

	/* Menu Entries items */
	} else if ((item_type==0x12 && item_id==0x0b)) {
		dissect_sapdiag_menu(tvb, pinfo, item_value_tree, offset, item_length);

	} else if (item_type==0x13) { /* SLC */
		check_length(pinfo, item_value_tree, 2, item_length, "SLC");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Field length in characters");

	/* Another unknown item */
	} else {
		/* If the preference is set, report the item as unknown in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_unknown, "The Diag Item has a unknown type that is not dissected (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}
	}
}

static const char *
get_appl_string(uint8_t item_id, uint8_t item_sid){
	const char *item_name_string = NULL;

	switch (item_id){
		case 0x01:{   /* SCRIPT */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_script_vals, "Unknown");
			break;
		} case 0x02:{ /* GRAPH */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_graph_vals, "Unknown");
			break;
		} case 0x03:{ /* IXOS */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_ixos_vals, "Unknown");
			break;
		} case 0x04:{ /* ST_USER */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_st_user_vals, "Unknown");
			break;
		} case 0x05:{ /* DYNN */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_dynn_vals, "Unknown");
			break;
		} case 0x06:{ /* ST_R3INFO */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_st_r3info_vals, "Unknown");
			break;
		} case 0x07:{ /* POPU */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_popu_vals, "Unknown");
			break;
		} case 0x08:{ /* RFC_TR */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_rfc_tr_vals, "Unknown");
			break;
		} case 0x09:{ /* DYNT */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_dynt_vals, "Unknown");
			break;
		} case 0x0a:{ /* CONTAINER */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_container_vals, "Unknown");
			break;
		} case 0x0b:{ /* MNUENTRY */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_mnuentry_vals, "Unknown");
			break;
		} case 0x0c:{ /* VARINFO */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_varinfo_vals, "Unknown");
			break;
		} case 0x0e:{ /* CONTROL */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_control_vals, "Unknown");
			break;
		} case 0x0f:{ /* UI_EVENT */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_ui_event_vals, "Unknown");
			break;
		} case 0x12:{ /* ACC_LIST */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_acc_list_vals, "Unknown");
			break;
		} case 0x13:{ /* RCUI */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_rcui_vals, "Unknown");
			break;
		} case 0x14:{ /* GUI_PACKET */
	                item_name_string = val_to_str_const(item_sid, sapdiag_item_appl_gui_packet_vals, "Unknown");
			break;
		}
	}
	return (item_name_string);
}

static void
dissect_sapdiag_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parent_tree, uint32_t offset){
	int item_value_remaining_length;
	uint8_t item_type, item_long, item_id, item_sid;
	uint32_t item_length, item_value_length;
	const char *item_name_string = NULL;

	proto_item *item = NULL, *il = NULL, *item_value = NULL;
	proto_tree *item_tree, *item_value_tree;

	while (tvb_offset_exists(tvb, offset)){
		item_id = item_sid = item_length = item_value_length = item_long = 0;

		/* Add the item subtree. We start with a item's length of 1, as we don't have yet the real size of the item */
		item = proto_tree_add_item(tree, hf_sapdiag_item, tvb, offset, 1, ENC_NA);
		item_tree = proto_item_add_subtree(item, ett_sapdiag);

		/* Get the item type */
		item_type = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(item_tree, hf_sapdiag_item_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		item_length++;
		proto_item_append_text(item, ": %s", val_to_str_const(item_type, sapdiag_item_type_vals, "Unknown"));

		switch (item_type){
			case 0x01:{ /* SES */
				item_value_length = 16;
				break;
			}
			case 0x02:{ /* ICO */
				item_value_length = 20;
				break;
			}
			case 0x03:{ /* TIT */
				item_value_length = 3;
				break;
			}
			case 0x07:{ /* DiagMessage (old format) */
				item_value_length = 76;
				break;
			}
			case 0x08:{ /* OCK */
				/* If the preference is set, report the item as partially dissected in the expert info */
				if (global_sapdiag_highlight_items){
					expert_add_info_format(pinfo, item, &ei_sapdiag_item_unknown_length, "Diag Type of unknown length (0x%.2x)", item_type);
				}
				break;
			}
			case 0x09:{ /* CHL */
				item_value_length = 22;
				break;
			}
			case 0x0a:{ /* SFE */
				item_value_length = 3;
				break;
			}
			case 0x0b:{ /* SBA */
				item_value_length = 2;
				break;
			}
			case 0x0C:{ /* EOM End of message */
				break;
			}
			case 0x11:{ /* Data Stream */
				item_long = 4;
				break;
			}
			case 0x13:{ /* SLC */
				item_value_length = 2;
				break;
			}
			case 0x15:{ /* SBA2 XXX: Find the actual length */
				item_value_length = 36;
				break;
			}
			case 0x10:  /* APPL */
			case 0x12:{ /* APPL4 */
				/* Get the APPL(4) ID */
				item_id = tvb_get_uint8(tvb, offset);
				proto_item_append_text(item, ", %s", val_to_str_const(item_id, sapdiag_item_id_vals, "Unknown"));
				proto_tree_add_item(item_tree, hf_sapdiag_item_id, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				item_length++;

				/* Get the APPL item sid value and set the respective name string according to them XXX: Change this for a multi array */
				item_sid = tvb_get_uint8(tvb, offset);
				item_name_string = get_appl_string(item_id, item_sid);

				proto_item_append_text(item, ", %s", item_name_string);
				proto_tree_add_uint_format_value(item_tree, hf_sapdiag_item_sid, tvb, offset, 1, item_sid, "%s (0x%.2x)", item_name_string, item_sid);
				offset++;
				item_length++;

				if (item_type==0x10) {
					item_long = 2;
				} else if (item_type==0x12) {
					item_long = 4;
				}

				break;
			}
		}

		/* Get the item length (word o dword) */
		if (item_long == 2){
			item_value_length = tvb_get_ntohs(tvb, offset);
			il = proto_tree_add_item(item_tree, hf_sapdiag_item_length_short, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			item_length += 2;
		} else if (item_long == 4){
			item_value_length = tvb_get_ntohl(tvb, offset);
			il = proto_tree_add_item(item_tree, hf_sapdiag_item_length_long, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			item_length += 4;
		}

		/* Add the item length */
		proto_item_append_text(item, ", Len=%d", item_value_length);

		/* Now we have the real length of the item, set the proper size */
		item_length += item_value_length;
		proto_item_set_len(item, item_length);

		/* Add the item value */
		if (item_value_length > 0){
			/* Check if the item length is valid */
			item_value_remaining_length = tvb_reported_length_remaining(tvb, offset);
			if (item_value_remaining_length < 0){
				expert_add_info(pinfo, il, &ei_sapdiag_item_offset_invalid);
				return;
			}
			if ((uint32_t)item_value_remaining_length < item_value_length){
				expert_add_info(pinfo, il, &ei_sapdiag_item_length_invalid);
				item_value_length = (uint32_t)item_value_remaining_length;
			}
			item_value = proto_tree_add_item(item_tree, hf_sapdiag_item_value, tvb, offset, item_value_length, ENC_NA);
			item_value_tree = proto_item_add_subtree(item_value, ett_sapdiag);
			dissect_sapdiag_item(tvb, pinfo, item, item_value_tree, parent_tree, offset, item_type, item_id, item_sid, item_value_length);
			offset+= item_value_length;
		}
	}
}

static int
check_sapdiag_dp(tvbuff_t *tvb, uint32_t offset)
{
	/* Since there's no SAP Diag mode 0xff, if the first byte is a 0xFF the
	 * packet probably holds an initialization DP Header */
	if ((tvb_reported_length_remaining(tvb, offset) >= 200 + 8) && tvb_get_uint8(tvb, offset) == 0xFF){
		return true;
	}
	return false;
}

static int
check_sapdiag_compression(tvbuff_t *tvb, uint32_t offset)
{
	/* We check for the length, the algorithm value and the presence of magic bytes */
	if ((tvb_reported_length_remaining(tvb, offset) >= 8) &&
		((tvb_get_uint8(tvb, offset+4) == 0x11) || (tvb_get_uint8(tvb, offset+4) == 0x12)) &&
		(tvb_get_uint16(tvb, offset+5, ENC_LITTLE_ENDIAN) == 0x9d1f)){
		return true;
	}
	return false;
}

static void
dissect_sapdiag_compressed_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *sapdiag, uint32_t offset)
{
	uint32_t reported_length = 0;
	proto_item *compression_header = NULL;
	proto_tree *compression_header_tree = NULL;

	/* Add the compression header subtree */
	compression_header = proto_tree_add_item(tree, hf_sapdiag_compress_header, tvb, offset, 8, ENC_NA);
	compression_header_tree = proto_item_add_subtree(compression_header, ett_sapdiag);

	/* Add the uncompressed length */
	reported_length = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(compression_header_tree, hf_sapdiag_uncomplength, tvb, offset, 4, reported_length);
	offset+=4;
	proto_item_append_text(sapdiag, ", Uncompressed Len: %u", reported_length);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Uncompressed Length=%u ", reported_length);

	/* Add the algorithm */
	proto_tree_add_item(compression_header_tree, hf_sapdiag_algorithm, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	/* Add the magic bytes */
	proto_tree_add_item(compression_header_tree, hf_sapdiag_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	/* Add the max bits */
	proto_tree_add_item(compression_header_tree, hf_sapdiag_special, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* TODO: Decompression is not yet enabled until the LZC/LZH library is added
	 * Here we just add the payload subtree
	 */
	proto_tree_add_item(tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
}


static void
dissect_sapdiag_snc_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *sapdiag_tree, proto_tree *tree, uint32_t offset){

	tvbuff_t *next_tvb = NULL;
	proto_item *payload = NULL;
	proto_tree *payload_tree = NULL;

	/* Call the SNC dissector */
	if (global_sapdiag_snc_dissection == true){
		next_tvb = dissect_sapsnc_frame(tvb, pinfo, tree, offset);

		/* If the SNC dissection returned a new tvb, we've a payload to dissect */
		if (next_tvb != NULL) {

		/* Add a new data source for the unwrapped data. From now on, the offset is relative
		to the new tvb so its zero. */
			add_new_data_source(pinfo, next_tvb, "SNC unwrapped Data");

			/* Add the payload subtree using the new tvb*/
			payload = proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, next_tvb, 0, -1, ENC_NA);
			payload_tree = proto_item_add_subtree(payload, ett_sapdiag);

			if (check_sapdiag_compression(next_tvb, 0)) {
				dissect_sapdiag_compressed_payload(next_tvb, pinfo, payload_tree, payload, 0);
			} else {
				dissect_sapdiag_payload(next_tvb, pinfo, payload_tree, payload, 0);
			}
		}
	}
}

static int
dissect_sapdiag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint8_t compress = 0, error_no = 0;
	uint32_t offset = 0;
	proto_item *sapdiag = NULL, *header = NULL, *com_flag = NULL, *payload = NULL;
	proto_tree *sapdiag_tree = NULL, *header_tree = NULL, *com_flag_tree = NULL, *payload_tree = NULL;

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPDIAG");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/* Add the main SAPDiag subtree */
	sapdiag = proto_tree_add_item(tree, proto_sapdiag, tvb, 0, -1, ENC_NA);
	sapdiag_tree = proto_item_add_subtree(sapdiag, ett_sapdiag);

	/* Check if the packet holds a DP Header */
	if (check_sapdiag_dp(tvb, offset)){
		dissect_sapdiag_dp(tvb, sapdiag_tree, offset); offset+= 200;
	}

	/* Check for fixed error messages */
	if (tvb_strneql(tvb, 0, "**DPTMMSG**\x00", 12) == 0){
		proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
		return offset;
	} else if (tvb_strneql(tvb, 0, "**DPTMOPC**\x00", 12) == 0){
		proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
		return offset;
	}

	/* Add the header subtree */
	header = proto_tree_add_item(sapdiag_tree, hf_sapdiag_header, tvb, offset, 8, ENC_NA);
	header_tree = proto_item_add_subtree(header, ett_sapdiag);

	/* Add the fields */
	proto_tree_add_item(header_tree, hf_sapdiag_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	com_flag = proto_tree_add_item(header_tree, hf_sapdiag_com_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	com_flag_tree = proto_item_add_subtree(com_flag, ett_sapdiag);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_EOS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_EOC, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_NOP, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_EOP, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_INI, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_CAS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_NNM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_GRA, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(header_tree, hf_sapdiag_mode_stat, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	error_no = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(header_tree, hf_sapdiag_err_no, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(header_tree, hf_sapdiag_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(header_tree, hf_sapdiag_msg_info, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(header_tree, hf_sapdiag_msg_rc, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	compress = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(header_tree, hf_sapdiag_compress, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Check for error messages */
	if ((error_no != 0x00) && (tvb_reported_length_remaining(tvb, offset) > 0)){
		char *error_message = NULL;
		uint32_t error_message_length = 0;

		error_message_length = (uint32_t)tvb_reported_length_remaining(tvb, offset) - 1;
		error_message = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, error_message_length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		proto_tree_add_string(sapdiag_tree, hf_sapdiag_error_message, tvb, offset, error_message_length, error_message);

	/* If the message is compressed */
	} else if ((compress == 0x01) && (tvb_reported_length_remaining(tvb, offset) >= 8)){

		/* Dissect the compressed payload */
		dissect_sapdiag_compressed_payload(tvb, pinfo, sapdiag_tree, sapdiag, offset);

	/* Message wrapped with SNC */
	} else if (((compress == 0x02) || (compress == 0x03)) && (tvb_reported_length_remaining(tvb, offset) > 0)){

		/* Call the SNC dissector */
		dissect_sapdiag_snc_frame(tvb, pinfo, sapdiag_tree, tree, offset);

	/* Uncompressed payload */
	} else {
		/* Check the payload length */
		if (tvb_reported_length_remaining(tvb, offset) > 0){
			/* Add the payload subtree */
			payload = proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
			payload_tree = proto_item_add_subtree(payload, ett_sapdiag);

			/* Dissect the payload */
			dissect_sapdiag_payload(tvb, pinfo, payload_tree, tree, offset);
		}
	}

	return offset;
}

void
proto_register_sapdiag(void)
{
	static hf_register_info hf[] = {
		{ &hf_sapdiag_dp,
			{ "DP Header", "sapdiag.dp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_header,
			{ "Header", "sapdiag.header", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_payload,
			{ "Message", "sapdiag.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_mode,
			{ "Mode", "sapdiag.header.mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_com_flag,
			{ "Com Flag", "sapdiag.header.comflag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_EOS,
			{ "Com Flag TERM_EOS", "sapdiag.header.comflag.TERM_EOS", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_EOS, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_EOC,
			{ "Com Flag TERM_EOC", "sapdiag.header.comflag.TERM_EOC", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_EOC, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_NOP,
			{ "Com Flag TERM_NOP", "sapdiag.header.comflag.TERM_NOP", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_NOP, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_EOP,
			{ "Com Flag TERM_EOP", "sapdiag.header.comflag.TERM_EOP", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_EOP, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_INI,
			{ "Com Flag TERM_INI", "sapdiag.header.comflag.TERM_INI", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_INI, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_CAS,
			{ "Com Flag TERM_CAS", "sapdiag.header.comflag.TERM_CAS", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_CAS, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_NNM,
			{ "Com Flag TERM_NNM", "sapdiag.header.comflag.TERM_NNM", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_NNM, NULL, HFILL }},
		{ &hf_sapdiag_com_flag_TERM_GRA,
			{ "Com Flag TERM_GRA", "sapdiag.header.comflag.TERM_GRA", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_GRA, NULL, HFILL }},

		{ &hf_sapdiag_mode_stat,
			{ "Mode Stat", "sapdiag.header.modestat", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_err_no,
			{ "Error Number", "sapdiag.header.errorno", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_msg_type,
			{ "Message Type", "sapdiag.header.msgtype", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_msg_info,
			{ "Message Info", "sapdiag.header.msginfo", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_msg_rc,
			{ "Message Rc", "sapdiag.header.msgrc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_compress,
			{ "Compress", "sapdiag.header.compress", FT_UINT8, BASE_HEX, VALS(sapdiag_compress_vals), 0x0, NULL, HFILL }},

		/* Error Messages */
		{ &hf_sapdiag_error_message,
			{ "Error Message", "sapdiag.error_message", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Compression header */
		{ &hf_sapdiag_compress_header,
			{ "Compression Header", "sapdiag.header.compression", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_uncomplength,
			{ "Uncompressed Length", "sapdiag.header.compression.uncomplength", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_algorithm,
			{ "Compression Algorithm", "sapdiag.header.compression.algorithm", FT_UINT8, BASE_HEX, VALS(sapdiag_algorithm_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_magic,
			{ "Magic Bytes", "sapdiag.header.compression.magic", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_special,
			{ "Special", "sapdiag.header.compression.special", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		/* SAPDiag Messages */
		{ &hf_sapdiag_item,
			{ "Item", "sapdiag.item", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_type,
			{ "Type", "sapdiag.item.type", FT_UINT8, BASE_HEX, VALS(sapdiag_item_type_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_id,
			{ "ID", "sapdiag.item.id", FT_UINT8, BASE_HEX, VALS(sapdiag_item_id_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_sid,
			{ "SID", "sapdiag.item.sid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_length_short,
			{ "Length", "sapdiag.item.length_short", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_length_long,
			{ "Length", "sapdiag.item.length_long", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_value,
			{ "Value", "sapdiag.item.value", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		/* SAPDiag DP Header */
		{ &hf_sapdiag_dp_request_id,
			{ "Request ID", "sapdiag.dp.reqid", FT_INT32, BASE_DEC, VALS(sapdiag_dp_request_id_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_retcode,
			{ "Retcode", "sapdiag.dp.retcode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_sender_id,
			{ "Sender ID", "sapdiag.dp.senderid", FT_UINT8, BASE_HEX, VALS(sapdiag_dp_sender_id_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_action_type,
			{ "Action type", "sapdiag.dp.actiontype", FT_UINT8, BASE_HEX, VALS(sapdiag_dp_action_type_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info,
			{ "Request Info", "sapdiag.dp.reqinfo", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		/* Request Info Flag */
		{ &hf_sapdiag_dp_req_info_LOGIN,
			{ "Login Flag", "sapdiag.dp.reqinfo.login", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_LOGIN, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_LOGOFF,
			{ "Logoff Flag", "sapdiag.dp.reqinfo.logoff", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_LOGOFF, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_SHUTDOWN,
			{ "Shutdown Flag", "sapdiag.dp.reqinfo.shutdown", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_SHUTDOWN, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_GRAPHIC_TM,
			{ "Graphic TM Flag", "sapdiag.dp.reqinfo.graphictm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_GRAPHIC_TM, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_ALPHA_TM,
			{ "Alpha TM Flag", "sapdiag.dp.reqinfo.alphatm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_ALPHA_TM, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_ERROR_FROM_APPC,
			{ "Error from APPC Flag", "sapdiag.dp.reqinfo.errorfromappc", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_ERROR_FROM_APPC, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_CANCELMODE,
			{ "Cancel Mode Flag", "sapdiag.dp.reqinfo.cancelmode", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_CANCELMODE, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_MSG_WITH_REQ_BUF,
			{ "Msg with Req Buf Flag", "sapdiag.dp.reqinfo.msg_with_req_buf", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_MSG_WITH_REQ_BUF, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_MSG_WITH_OH,
			{ "Msg with OH Flag", "sapdiag.dp.reqinfo.msg_with_oh", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_MSG_WITH_OH, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_BUFFER_REFRESH,
			{ "Buffer Refresh Flag", "sapdiag.dp.reqinfo.buffer_refresh", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_BUFFER_REFRESH, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_BTC_SCHEDULER,
			{ "BTC Scheduler Flag", "sapdiag.dp.reqinfo.btc_scheduler", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_BTC_SCHEDULER, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_APPC_SERVER_DOWN,
			{ "APPC Server Down Flag", "sapdiag.dp.reqinfo.appc_server_down", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_APPC_SERVER_DOWN, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_MS_ERROR,
			{ "MS Error Flag", "sapdiag.dp.reqinfo.ms_error", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_MS_ERROR, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_SET_SYSTEM_USER,
			{ "Set System User Flag", "sapdiag.dp.reqinfo.set_system_user", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_SET_SYSTEM_USER, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_CANT_HANDLE_REQ,
			{ "DP Can't handle req Flag", "sapdiag.dp.reqinfo.dp_cant_handle_req", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_CANT_HANDLE_REQ, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_AUTO_ABAP,
			{ "DP Auto ABAP Flag", "sapdiag.dp.reqinfo.dp_auto_abap", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_AUTO_ABAP, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_APPL_SERV_INFO,
			{ "DP Appl Serv Info Flag", "sapdiag.dp.reqinfo.dp_appl_serv_info", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_APPL_SERV_INFO, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_ADMIN,
			{ "DP Admin Flag", "sapdiag.dp.reqinfo.dp_admin", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_ADMIN, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_SPOOL_ALRM,
			{ "DP Spool Alrm Flag", "sapdiag.dp.reqinfo.dp_spool_alrm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_SPOOL_ALRM, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_HAND_SHAKE,
			{ "DP Hand Shake Flag", "sapdiag.dp.reqinfo.dp_hand_shake", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_HAND_SHAKE, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_CANCEL_PRIV,
			{ "DP Cancel Privileges Flag", "sapdiag.dp.reqinfo.dp_cancel_priv", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_CANCEL_PRIV, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_RAISE_TIMEOUT,
			{ "DP Raise Timeout Flag", "sapdiag.dp.reqinfo.dp_raise_timeout", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_RAISE_TIMEOUT, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_NEW_MODE,
			{ "DP New Mode Flag", "sapdiag.dp.reqinfo.dp_new_mode", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_NEW_MODE, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_SOFT_CANCEL,
			{ "DP Soft Cancel Flag", "sapdiag.dp.reqinfo.dp_soft_cancel", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_SOFT_CANCEL, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_TM_INPUT,
			{ "DP TM Input Flag", "sapdiag.dp.reqinfo.dp_tm_input", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_TM_INPUT, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_TM_OUTPUT,
			{ "DP TM Output Flag", "sapdiag.dp.reqinfo.dp_tm_output", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_TM_OUTPUT, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_ASYNC_RFC,
			{ "DP Async RFC Flag", "sapdiag.dp.reqinfo.dp_async_rfc", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_ASYNC_RFC, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_ICM_EVENT,
			{ "DP ICM Event Flag", "sapdiag.dp.reqinfo.dp_icm_event", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_ICM_EVENT, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_AUTO_TH,
			{ "DP Auto TH Flag", "sapdiag.dp.reqinfo.dp_auto_th", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_AUTO_TH, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_RFC_CANCEL,
			{ "DP RFC Cancel Flag", "sapdiag.dp.reqinfo.dp_rfc_cancel", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_RFC_CANCEL, NULL, HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_MS_ADM,
			{ "DP MS Adm Flag", "sapdiag.dp.reqinfo.dp_ms_adm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_MS_ADM, NULL, HFILL }},
		{ &hf_sapdiag_dp_tid,
			{ "TID", "sapdiag.dp.tid", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_uid,
			{ "UID", "sapdiag.dp.uid", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_mode,
			{ "Mode", "sapdiag.dp.mode", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_wp_id,
			{ "WP Id", "sapdiag.dp.wpid", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_wp_ca_blk,
			{ "WP Ca Blk", "sapdiag.dp.wpcablk", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_appc_ca_blk,
			{ "APPC Ca Blk", "sapdiag.dp.appccablk", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_len,
			{ "Len", "sapdiag.dp.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_new_stat,
			{ "New Stat", "sapdiag.dp.newstat", FT_UINT8, BASE_HEX, VALS(sapdiag_dp_new_stat_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_rq_id,
			{ "Request ID", "sapdiag.dp.rqid", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_dp_terminal,
			{ "Terminal", "sapdiag.dp.terminal", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* SAP Diag Support Bits */
		{ &hf_SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR,
			{ "Support Bit PROGRESS_INDICATOR", "sapdiag.diag.supportbits.PROGRESS_INDICATOR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS,
			{ "Support Bit SAPGUI_LABELS", "sapdiag.diag.supportbits.SAPGUI_LABELS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION,
			{ "Support Bit SAPGUI_DIAGVERSION", "sapdiag.diag.supportbits.SAPGUI_DIAGVERSION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT,
			{ "Support Bit SAPGUI_SELECT_RECT", "sapdiag.diag.supportbits.SAPGUI_SELECT_RECT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT,
			{ "Support Bit SAPGUI_SYMBOL_RIGHT", "sapdiag.diag.supportbits.SAPGUI_SYMBOL_RIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC,
			{ "Support Bit SAPGUI_FONT_METRIC", "sapdiag.diag.supportbits.SAPGUI_FONT_METRIC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED,
			{ "Support Bit SAPGUI_COMPR_ENHANCED", "sapdiag.diag.supportbits.SAPGUI_COMPR_ENHANCED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE,
			{ "Support Bit SAPGUI_IMODE", "sapdiag.diag.supportbits.SAPGUI_IMODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE,
			{ "Support Bit SAPGUI_LONG_MESSAGE", "sapdiag.diag.supportbits.SAPGUI_LONG_MESSAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE,
			{ "Support Bit SAPGUI_TABLE", "sapdiag.diag.supportbits.SAPGUI_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1,
			{ "Support Bit SAPGUI_FOCUS_1", "sapdiag.diag.supportbits.SAPGUI_FOCUS_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1,
			{ "Support Bit SAPGUI_PUSHBUTTON_1", "sapdiag.diag.supportbits.SAPGUI_PUSHBUTTON_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UPPERCASE,
			{ "Support Bit UPPERCASE", "sapdiag.diag.supportbits.UPPERCASE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UPPERCASE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY,
			{ "Support Bit SAPGUI_TABPROPERTY", "sapdiag.diag.supportbits.SAPGUI_TABPROPERTY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE,
			{ "Support Bit INPUT_UPPERCASE", "sapdiag.diag.supportbits.INPUT_UPPERCASE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_DIALOG,
			{ "Support Bit RFC_DIALOG", "sapdiag.diag.supportbits.RFC_DIALOG", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_DIALOG, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT,
			{ "Support Bit LIST_HOTSPOT", "sapdiag.diag.supportbits.LIST_HOTSPOT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FKEY_TABLE,
			{ "Support Bit FKEY_TABLE", "sapdiag.diag.supportbits.FKEY_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FKEY_TABLE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT,
			{ "Support Bit MENU_SHORTCUT", "sapdiag.diag.supportbits.MENU_SHORTCUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_STOP_TRANS,
			{ "Support Bit STOP_TRANS", "sapdiag.diag.supportbits.STOP_TRANS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_STOP_TRANS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FULL_MENU,
			{ "Support Bit FULL_MENU", "sapdiag.diag.supportbits.FULL_MENU", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FULL_MENU, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES,
			{ "Support Bit OBJECT_NAMES", "sapdiag.diag.supportbits.OBJECT_NAMES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OBJECT_NAMES, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE,
			{ "Support Bit CONTAINER_TYPE", "sapdiag.diag.supportbits.CONTAINER_TYPE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DLGH_FLAGS,
			{ "Support Bit DLGH_FLAGS", "sapdiag.diag.supportbits.DLGH_FLAGS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DLGH_FLAGS, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_APPL_MNU,
			{ "Support Bit APPL_MNU", "sapdiag.diag.supportbits.APPL_MNU", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_APPL_MNU, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO,
			{ "Support Bit MESSAGE_INFO", "sapdiag.diag.supportbits.MESSAGE_INFO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_INFO, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1,
			{ "Support Bit MESDUM_FLAG1", "sapdiag.diag.supportbits.MESDUM_FLAG1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB,
			{ "Support Bit TABSEL_ATTRIB", "sapdiag.diag.supportbits.TABSEL_ATTRIB", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUIAPI,
			{ "Support Bit GUIAPI", "sapdiag.diag.supportbits.GUIAPI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUIAPI, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOGRAPH,
			{ "Support Bit NOGRAPH", "sapdiag.diag.supportbits.NOGRAPH", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOGRAPH, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOMESSAGES,
			{ "Support Bit NOMESSAGES", "sapdiag.diag.supportbits.NOMESSAGES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOMESSAGES, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NORABAX,
			{ "Support Bit NORABAX", "sapdiag.diag.supportbits.NORABAX", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NORABAX, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_NOSYSMSG,
			{ "Support Bit NOSYSMSG", "sapdiag.diag.supportbits.NOSYSMSG", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOSYSMSG, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT,
			{ "Support Bit NOSAPSCRIPT", "sapdiag.diag.supportbits.NOSAPSCRIPT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NORFC,
			{ "Support Bit NORFC", "sapdiag.diag.supportbits.NORFC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NORFC, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT,
			{ "Support Bit NEW_BSD_JUSTRIGHT", "sapdiag.diag.supportbits.NEW_BSD_JUSTRIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_VARS,
			{ "Support Bit MESSAGE_VARS", "sapdiag.diag.supportbits.MESSAGE_VARS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_VARS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OCX_SUPPORT,
			{ "Support Bit OCX_SUPPORT", "sapdiag.diag.supportbits.OCX_SUPPORT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OCX_SUPPORT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SCROLL_INFOS,
			{ "Support Bit SCROLL_INFOS", "sapdiag.diag.supportbits.SCROLL_INFOS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SCROLL_INFOS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK,
			{ "Support Bit TABLE_SIZE_OK", "sapdiag.diag.supportbits.TABLE_SIZE_OK", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2,
			{ "Support Bit MESSAGE_INFO2", "sapdiag.diag.supportbits.MESSAGE_INFO2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE,
			{ "Support Bit VARINFO_OKCODE", "sapdiag.diag.supportbits.VARINFO_OKCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CURR_TCODE,
			{ "Support Bit CURR_TCODE", "sapdiag.diag.supportbits.CURR_TCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CURR_TCODE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONN_WSIZE,
			{ "Support Bit CONN_WSIZE", "sapdiag.diag.supportbits.CONN_WSIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONN_WSIZE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2,
			{ "Support Bit PUSHBUTTON_2", "sapdiag.diag.supportbits.PUSHBUTTON_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSTRIP,
			{ "Support Bit TABSTRIP", "sapdiag.diag.supportbits.TABSTRIP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSTRIP, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_1,
			{ "Support Bit UNKNOWN_1", "sapdiag.diag.supportbits.UNKNOWN_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNKNOWN_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS,
			{ "Support Bit TABSCROLL_INFOS", "sapdiag.diag.supportbits.TABSCROLL_INFOS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES,
			{ "Support Bit TABLE_FIELD_NAMES", "sapdiag.diag.supportbits.TABLE_FIELD_NAMES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST,
			{ "Support Bit NEW_MODE_REQUEST", "sapdiag.diag.supportbits.NEW_MODE_REQUEST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER,
			{ "Support Bit RFCBLOB_DIAG_PARSER", "sapdiag.diag.supportbits.RFCBLOB_DIAG_PARSER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER,
			{ "Support Bit MULTI_LOGIN_USER", "sapdiag.diag.supportbits.MULTI_LOGIN_USER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER,
			{ "Support Bit CONTROL_CONTAINER", "sapdiag.diag.supportbits.CONTROL_CONTAINER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED,
			{ "Support Bit APPTOOLBAR_FIXED", "sapdiag.diag.supportbits.APPTOOLBAR_FIXED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED,
			{ "Support Bit R3INFO_USER_CHECKED", "sapdiag.diag.supportbits.R3INFO_USER_CHECKED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO,
			{ "Support Bit NEED_STDDYNPRO", "sapdiag.diag.supportbits.NEED_STDDYNPRO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TYPE_SERVER,
			{ "Support Bit TYPE_SERVER", "sapdiag.diag.supportbits.TYPE_SERVER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TYPE_SERVER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_COMBOBOX,
			{ "Support Bit COMBOBOX", "sapdiag.diag.supportbits.COMBOBOX", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_COMBOBOX, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED,
			{ "Support Bit INPUT_REQUIRED", "sapdiag.diag.supportbits.INPUT_REQUIRED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE,
			{ "Support Bit ISO_LANGUAGE", "sapdiag.diag.supportbits.ISO_LANGUAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE,
			{ "Support Bit COMBOBOX_TABLE", "sapdiag.diag.supportbits.COMBOBOX_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS,
			{ "Support Bit R3INFO_FLAGS", "sapdiag.diag.supportbits.R3INFO_FLAGS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS,
			{ "Support Bit CHECKRADIO_EVENTS", "sapdiag.diag.supportbits.CHECKRADIO_EVENTS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_USERID,
			{ "Support Bit R3INFO_USERID", "sapdiag.diag.supportbits.R3INFO_USERID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_USERID, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT,
			{ "Support Bit R3INFO_ROLLCOUNT", "sapdiag.diag.supportbits.R3INFO_ROLLCOUNT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_USER_TURNTIME2,
			{ "Support Bit USER_TURNTIME2", "sapdiag.diag.supportbits.USER_TURNTIME2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_USER_TURNTIME2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NUM_FIELD,
			{ "Support Bit NUM_FIELD", "sapdiag.diag.supportbits.NUM_FIELD", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NUM_FIELD, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WIN16,
			{ "Support Bit WIN16", "sapdiag.diag.supportbits.WIN16", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WIN16, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTEXT_MENU,
			{ "Support Bit CONTEXT_MENU", "sapdiag.diag.supportbits.CONTEXT_MENU", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTEXT_MENU, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE,
			{ "Support Bit SCROLLABLE_TABSTRIP_PAGE", "sapdiag.diag.supportbits.SCROLLABLE_TABSTRIP_PAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION,
			{ "Support Bit EVENT_DESCRIPTION", "sapdiag.diag.supportbits.EVENT_DESCRIPTION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_LABEL_OWNER,
			{ "Support Bit LABEL_OWNER", "sapdiag.diag.supportbits.LABEL_OWNER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_LABEL_OWNER, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD,
			{ "Support Bit CLICKABLE_FIELD", "sapdiag.diag.supportbits.CLICKABLE_FIELD", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PROPERTY_BAG,
			{ "Support Bit PROPERTY_BAG", "sapdiag.diag.supportbits.PROPERTY_BAG", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROPERTY_BAG, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_1,
			{ "Support Bit UNUSED_1", "sapdiag.diag.supportbits.UNUSED_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2,
			{ "Support Bit TABLE_ROW_REFERENCES_2", "sapdiag.diag.supportbits.TABLE_ROW_REFERENCES_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PROPFONT_VALID,
			{ "Support Bit PROPFONT_VALID", "sapdiag.diag.supportbits.PROPFONT_VALID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROPFONT_VALID, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER,
			{ "Support Bit VARINFO_CONTAINER", "sapdiag.diag.supportbits.VARINFO_CONTAINER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID,
			{ "Support Bit R3INFO_IMODEUUID", "sapdiag.diag.supportbits.R3INFO_IMODEUUID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOTGUI,
			{ "Support Bit NOTGUI", "sapdiag.diag.supportbits.NOTGUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOTGUI, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_WAN,
			{ "Support Bit WAN", "sapdiag.diag.supportbits.WAN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WAN, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XML_BLOBS,
			{ "Support Bit XML_BLOBS", "sapdiag.diag.supportbits.XML_BLOBS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_BLOBS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_QUEUE,
			{ "Support Bit RFC_QUEUE", "sapdiag.diag.supportbits.RFC_QUEUE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_QUEUE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_COMPRESS,
			{ "Support Bit RFC_COMPRESS", "sapdiag.diag.supportbits.RFC_COMPRESS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_COMPRESS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_JAVA_BEANS,
			{ "Support Bit JAVA_BEANS", "sapdiag.diag.supportbits.JAVA_BEANS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_JAVA_BEANS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND,
			{ "Support Bit DPLOADONDEMAND", "sapdiag.diag.supportbits.DPLOADONDEMAND", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE,
			{ "Support Bit CTL_PROPCACHE", "sapdiag.diag.supportbits.CTL_PROPCACHE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID,
			{ "Support Bit ENJOY_IMODEUUID", "sapdiag.diag.supportbits.ENJOY_IMODEUUID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB,
			{ "Support Bit RFC_ASYNC_BLOB", "sapdiag.diag.supportbits.RFC_ASYNC_BLOB", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS,
			{ "Support Bit KEEP_SCROLLPOS", "sapdiag.diag.supportbits.KEEP_SCROLLPOS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_2,
			{ "Support Bit UNUSED_2", "sapdiag.diag.supportbits.UNUSED_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_3,
			{ "Support Bit UNUSED_3", "sapdiag.diag.supportbits.UNUSED_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_3, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XML_PROPERTIES,
			{ "Support Bit XML_PROPERTIES", "sapdiag.diag.supportbits.XML_PROPERTIES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_PROPERTIES, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_4,
			{ "Support Bit UNUSED_4", "sapdiag.diag.supportbits.UNUSED_4", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_4, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_HEX_FIELD,
			{ "Support Bit HEX_FIELD", "sapdiag.diag.supportbits.HEX_FIELD", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_HEX_FIELD, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_HAS_CACHE,
			{ "Support Bit HAS_CACHE", "sapdiag.diag.supportbits.HAS_CACHE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_HAS_CACHE, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE,
			{ "Support Bit XML_PROP_TABLE", "sapdiag.diag.supportbits.XML_PROP_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_5,
			{ "Support Bit UNUSED_5", "sapdiag.diag.supportbits.UNUSED_5", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_5, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2,
			{ "Support Bit ENJOY_IMODEUUID2", "sapdiag.diag.supportbits.ENJOY_IMODEUUID2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ITS,
			{ "Support Bit ITS", "sapdiag.diag.supportbits.ITS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ITS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NO_EASYACCESS,
			{ "Support Bit NO_EASYACCESS", "sapdiag.diag.supportbits.NO_EASYACCESS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NO_EASYACCESS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PROPERTYPUMP,
			{ "Support Bit PROPERTYPUMP", "sapdiag.diag.supportbits.PROPERTYPUMP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROPERTYPUMP, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_COOKIE,
			{ "Support Bit COOKIE", "sapdiag.diag.supportbits.COOKIE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_COOKIE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_6,
			{ "Support Bit UNUSED_6", "sapdiag.diag.supportbits.UNUSED_6", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_6, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE,
			{ "Support Bit SUPPBIT_AREA_SIZE", "sapdiag.diag.supportbits.SUPPBIT_AREA_SIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE,
			{ "Support Bit DPLOADONDEMAND_WRITE", "sapdiag.diag.supportbits.DPLOADONDEMAND_WRITE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS,
			{ "Support Bit CONTROL_FOCUS", "sapdiag.diag.supportbits.CONTROL_FOCUS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY,
			{ "Support Bit ENTRY_HISTORY", "sapdiag.diag.supportbits.ENTRY_HISTORY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE,
			{ "Support Bit AUTO_CODEPAGE", "sapdiag.diag.supportbits.AUTO_CODEPAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CACHED_VSETS,
			{ "Support Bit CACHED_VSETS", "sapdiag.diag.supportbits.CACHED_VSETS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CACHED_VSETS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR,
			{ "Support Bit EMERGENCY_REPAIR", "sapdiag.diag.supportbits.EMERGENCY_REPAIR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AREA2FRONT,
			{ "Support Bit AREA2FRONT", "sapdiag.diag.supportbits.AREA2FRONT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AREA2FRONT, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH,
			{ "Support Bit SCROLLBAR_WIDTH", "sapdiag.diag.supportbits.SCROLLBAR_WIDTH", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AUTORESIZE,
			{ "Support Bit AUTORESIZE", "sapdiag.diag.supportbits.AUTORESIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AUTORESIZE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EDIT_VARLEN,
			{ "Support Bit EDIT_VARLEN", "sapdiag.diag.supportbits.EDIT_VARLEN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EDIT_VARLEN, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WORKPLACE,
			{ "Support Bit WORKPLACE", "sapdiag.diag.supportbits.WORKPLACE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WORKPLACE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PRINTDATA,
			{ "Support Bit PRINTDATA", "sapdiag.diag.supportbits.PRINTDATA", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PRINTDATA, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_2,
			{ "Support Bit UNKNOWN_2", "sapdiag.diag.supportbits.UNKNOWN_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNKNOWN_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SINGLE_SESSION,
			{ "Support Bit SINGLE_SESSION", "sapdiag.diag.supportbits.SINGLE_SESSION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SINGLE_SESSION, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE,
			{ "Support Bit NOTIFY_NEWMODE", "sapdiag.diag.supportbits.NOTIFY_NEWMODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT,
			{ "Support Bit TOOLBAR_HEIGHT", "sapdiag.diag.supportbits.TOOLBAR_HEIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER,
			{ "Support Bit XMLPROP_CONTAINER", "sapdiag.diag.supportbits.XMLPROP_CONTAINER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO,
			{ "Support Bit XMLPROP_DYNPRO", "sapdiag.diag.supportbits.XMLPROP_DYNPRO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT,
			{ "Support Bit DP_HTTP_PUT", "sapdiag.diag.supportbits.DP_HTTP_PUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT,
			{ "Support Bit DYNAMIC_PASSPORT", "sapdiag.diag.supportbits.DYNAMIC_PASSPORT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WEBGUI,
			{ "Support Bit WEBGUI", "sapdiag.diag.supportbits.WEBGUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WEBGUI, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE,
			{ "Support Bit WEBGUI_HELPMODE", "sapdiag.diag.supportbits.WEBGUI_HELPMODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST,
			{ "Support Bit CONTROL_FOCUS_ON_LIST", "sapdiag.diag.supportbits.CONTROL_FOCUS_ON_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2,
			{ "Support Bit CBU_RBUDUMMY_2", "sapdiag.diag.supportbits.CBU_RBUDUMMY_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_1,
			{ "Support Bit EOKDUMMY_1", "sapdiag.diag.supportbits.EOKDUMMY_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EOKDUMMY_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING,
			{ "Support Bit GUI_USER_SCRIPTING", "sapdiag.diag.supportbits.GUI_USER_SCRIPTING", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SLC,
			{ "Support Bit SLC", "sapdiag.diag.supportbits.SLC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SLC, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ACCESSIBILITY,
			{ "Support Bit ACCESSIBILITY", "sapdiag.diag.supportbits.ACCESSIBILITY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ACCESSIBILITY, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ECATT,
			{ "Support Bit ECATT", "sapdiag.diag.supportbits.ECATT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ECATT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3,
			{ "Support Bit ENJOY_IMODEUUID3", "sapdiag.diag.supportbits.ENJOY_IMODEUUID3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF8,
			{ "Support Bit ENABLE_UTF8", "sapdiag.diag.supportbits.ENABLE_UTF8", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_UTF8, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME,
			{ "Support Bit R3INFO_AUTOLOGOUT_TIME", "sapdiag.diag.supportbits.R3INFO_AUTOLOGOUT_TIME", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST,
			{ "Support Bit VARINFO_ICON_TITLE_LIST", "sapdiag.diag.supportbits.VARINFO_ICON_TITLE_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE,
			{ "Support Bit ENABLE_UTF16BE", "sapdiag.diag.supportbits.ENABLE_UTF16BE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE,
			{ "Support Bit ENABLE_UTF16LE", "sapdiag.diag.supportbits.ENABLE_UTF16LE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP,
			{ "Support Bit R3INFO_CODEPAGE_APP", "sapdiag.diag.supportbits.R3INFO_CODEPAGE_APP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_APPL4,
			{ "Support Bit ENABLE_APPL4", "sapdiag.diag.supportbits.ENABLE_APPL4", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_APPL4, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL,
			{ "Support Bit GUIPATCHLEVEL", "sapdiag.diag.supportbits.GUIPATCHLEVEL", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE,
			{ "Support Bit CBURBU_NEW_STATE", "sapdiag.diag.supportbits.CBURBU_NEW_STATE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_BINARY_EVENTID,
			{ "Support Bit BINARY_EVENTID", "sapdiag.diag.supportbits.BINARY_EVENTID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_BINARY_EVENTID, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_THEME,
			{ "Support Bit GUI_THEME", "sapdiag.diag.supportbits.GUI_THEME", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_THEME, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TOP_WINDOW,
			{ "Support Bit TOP_WINDOW", "sapdiag.diag.supportbits.TOP_WINDOW", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TOP_WINDOW, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1,
			{ "Support Bit EVENT_DESCRIPTION_1", "sapdiag.diag.supportbits.EVENT_DESCRIPTION_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SPLITTER,
			{ "Support Bit SPLITTER", "sapdiag.diag.supportbits.SPLITTER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SPLITTER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY,
			{ "Support Bit VALUE_4_HISTORY", "sapdiag.diag.supportbits.VALUE_4_HISTORY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ACC_LIST,
			{ "Support Bit ACC_LIST", "sapdiag.diag.supportbits.ACC_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ACC_LIST, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO,
			{ "Support Bit GUI_USER_SCRIPTING_INFO", "sapdiag.diag.supportbits.GUI_USER_SCRIPTING_INFO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM,
			{ "Support Bit TEXTEDIT_STREAM", "sapdiag.diag.supportbits.TEXTEDIT_STREAM", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS,
			{ "Support Bit DYNT_NOFOCUS", "sapdiag.diag.supportbits.DYNT_NOFOCUS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1,
			{ "Support Bit R3INFO_CODEPAGE_APP_1", "sapdiag.diag.supportbits.R3INFO_CODEPAGE_APP_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FRAME_1,
			{ "Support Bit FRAME_1", "sapdiag.diag.supportbits.FRAME_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FRAME_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TICKET4GUI,
			{ "Support Bit TICKET4GUI", "sapdiag.diag.supportbits.TICKET4GUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TICKET4GUI, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS,
			{ "Support Bit ACC_LIST_PROPS", "sapdiag.diag.supportbits.ACC_LIST_PROPS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT,
			{ "Support Bit TABSEL_ATTRIB_INPUT", "sapdiag.diag.supportbits.TABSEL_ATTRIB_INPUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP,
			{ "Support Bit DEFAULT_TOOLTIP", "sapdiag.diag.supportbits.DEFAULT_TOOLTIP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2,
			{ "Support Bit XML_PROP_TABLE_2", "sapdiag.diag.supportbits.XML_PROP_TABLE_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3,
			{ "Support Bit CBU_RBUDUMMY_3", "sapdiag.diag.supportbits.CBU_RBUDUMMY_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CELLINFO,
			{ "Support Bit CELLINFO", "sapdiag.diag.supportbits.CELLINFO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CELLINFO, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2,
			{ "Support Bit CONTROL_FOCUS_ON_LIST_2", "sapdiag.diag.supportbits.CONTROL_FOCUS_ON_LIST_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT,
			{ "Support Bit TABLE_COLUMNWIDTH_INPUT", "sapdiag.diag.supportbits.TABLE_COLUMNWIDTH_INPUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ITS_PLUGIN,
			{ "Support Bit ITS_PLUGIN", "sapdiag.diag.supportbits.ITS_PLUGIN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ITS_PLUGIN, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS,
			{ "Support Bit OBJECT_NAMES_4_LOGIN_PROCESS", "sapdiag.diag.supportbits.OBJECT_NAMES_4_LOGIN_PROCESS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI,
			{ "Support Bit RFC_SERVER_4_GUI", "sapdiag.diag.supportbits.RFC_SERVER_4_GUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2,
			{ "Support Bit R3INFO_FLAGS_2", "sapdiag.diag.supportbits.R3INFO_FLAGS_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RCUI,
			{ "Support Bit RCUI", "sapdiag.diag.supportbits.RCUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RCUI, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE,
			{ "Support Bit MENUENTRY_WITH_FCODE", "sapdiag.diag.supportbits.MENUENTRY_WITH_FCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE,
			{ "Support Bit WEBSAPCONSOLE", "sapdiag.diag.supportbits.WEBSAPCONSOLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION,
			{ "Support Bit R3INFO_KERNEL_VERSION", "sapdiag.diag.supportbits.R3INFO_KERNEL_VERSION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP,
			{ "Support Bit VARINFO_CONTAINER_LOOP", "sapdiag.diag.supportbits.VARINFO_CONTAINER_LOOP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_2,
			{ "Support Bit EOKDUMMY_2", "sapdiag.diag.supportbits.EOKDUMMY_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EOKDUMMY_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3,
			{ "Support Bit MESSAGE_INFO3", "sapdiag.diag.supportbits.MESSAGE_INFO3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SBA2,
			{ "Support Bit SBA2", "sapdiag.diag.supportbits.SBA2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SBA2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE,
			{ "Support Bit MAINAREA_SIZE", "sapdiag.diag.supportbits.MAINAREA_SIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2,
			{ "Support Bit GUIPATCHLEVEL_2", "sapdiag.diag.supportbits.GUIPATCHLEVEL_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE,
			{ "Support Bit DISPLAY_SIZE", "sapdiag.diag.supportbits.DISPLAY_SIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_PACKET,
			{ "Support Bit GUI_PACKET", "sapdiag.diag.supportbits.GUI_PACKET", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_PACKET, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER,
			{ "Support Bit DIALOG_STEP_NUMBER", "sapdiag.diag.supportbits.DIALOG_STEP_NUMBER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION,
			{ "Support Bit TC_KEEP_SCROLL_POSITION", "sapdiag.diag.supportbits.TC_KEEP_SCROLL_POSITION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST,
			{ "Support Bit MESSAGE_SERVICE_REQUEST", "sapdiag.diag.supportbits.MESSAGE_SERVICE_REQUEST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME,
			{ "Support Bit DYNT_FOCUS_FRAME", "sapdiag.diag.supportbits.DYNT_FOCUS_FRAME", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN,
			{ "Support Bit MAX_STRING_LEN", "sapdiag.diag.supportbits.MAX_STRING_LEN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1,
			{ "Support Bit VARINFO_CONTAINER_1", "sapdiag.diag.supportbits.VARINFO_CONTAINER_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS,
			{ "Support Bit STD_TOOLBAR_ITEMS", "sapdiag.diag.supportbits.STD_TOOLBAR_ITEMS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO,
			{ "Support Bit XMLPROP_LIST_DYNPRO", "sapdiag.diag.supportbits.XMLPROP_LIST_DYNPRO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT,
			{ "Support Bit TRACE_GUI_CONNECT", "sapdiag.diag.supportbits.TRACE_GUI_CONNECT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH,
			{ "Support Bit LIST_FULLWIDTH", "sapdiag.diag.supportbits.LIST_FULLWIDTH", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT,
			{ "Support Bit ALLWAYS_SEND_CLIENT", "sapdiag.diag.supportbits.ALLWAYS_SEND_CLIENT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_3,
			{ "Support Bit UNKNOWN_3", "sapdiag.diag.supportbits.UNKNOWN_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNKNOWN_3, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR,
			{ "Support Bit GUI_SIGNATURE_COLOR", "sapdiag.diag.supportbits.GUI_SIGNATURE_COLOR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MAX_WSIZE,
			{ "Support Bit MAX_WSIZE", "sapdiag.diag.supportbits.MAX_WSIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MAX_WSIZE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAP_PERSONAS,
			{ "Support Bit SAP_PERSONAS", "sapdiag.diag.supportbits.SAP_PERSONAS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAP_PERSONAS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_IDA_ALV,
			{ "Support Bit IDA_ALV", "sapdiag.diag.supportbits.IDA_ALV", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_IDA_ALV, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS,
			{ "Support Bit IDA_ALV_FRAGMENTS", "sapdiag.diag.supportbits.IDA_ALV_FRAGMENTS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AMC,
			{ "Support Bit AMC", "sapdiag.diag.supportbits.AMC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AMC, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC,
			{ "Support Bit EXTMODE_FONT_METRIC", "sapdiag.diag.supportbits.EXTMODE_FONT_METRIC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_GROUPBOX,
			{ "Support Bit GROUPBOX", "sapdiag.diag.supportbits.GROUPBOX", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GROUPBOX, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON,
			{ "Support Bit AGI_ID_TS_BUTTON", "sapdiag.diag.supportbits.AGI_ID_TS_BUTTON", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST,
			{ "Support Bit NO_FOCUS_ON_LIST", "sapdiag.diag.supportbits.NO_FOCUS_ON_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FIORI_MODE,
			{ "Support Bit FIORI_MODE", "sapdiag.diag.supportbits.FIORI_MODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FIORI_MODE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE,
			{ "Support Bit CONNECT_CHECK_DONE", "sapdiag.diag.supportbits.CONNECT_CHECK_DONE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE,
			{ "Support Bit MSGINFO_WITH_CODEPAGE", "sapdiag.diag.supportbits.MSGINFO_WITH_CODEPAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AGI_ID,
			{ "Support Bit AGI_ID", "sapdiag.diag.supportbits.AGI_ID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AGI_ID, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TC,
			{ "Support Bit AGI_ID_TC", "sapdiag.diag.supportbits.AGI_ID_TC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AGI_ID_TC, NULL, HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS,
			{ "Support Bit FIORI_TOOLBARS", "sapdiag.diag.supportbits.FIORI_TOOLBARS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE,
			{ "Support Bit OBJECT_NAMES_ENFORCE", "sapdiag.diag.supportbits.OBJECT_NAMES_ENFORCE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3,
			{ "Support Bit MESDUMMY_FLAGS_2_3", "sapdiag.diag.supportbits.MESDUMMY_FLAGS_2_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NWBC,
			{ "Support Bit NWBC", "sapdiag.diag.supportbits.NWBC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NWBC, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTAINER_LIST,
			{ "Support Bit CONTAINER_LIST", "sapdiag.diag.supportbits.CONTAINER_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTAINER_LIST, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR,
			{ "Support Bit GUI_SYSTEM_COLOR", "sapdiag.diag.supportbits.GUI_SYSTEM_COLOR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR, NULL, HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE,
			{ "Support Bit GROUPBOX_WITHOUT_BOTTOMLINE", "sapdiag.diag.supportbits.GROUPBOX_WITHOUT_BOTTOMLINE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE, NULL, HFILL }},

		/* Dynt Atom */
		{ &hf_sapdiag_item_dynt_atom,
			{ "Dynt Atom", "sapdiag.item.value.dyntatom", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item,
			{ "Dynt Atom Item", "sapdiag.item.value.dyntatom.item", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_etype,
			{ "Dynt Atom Item Type", "sapdiag.item.value.dyntatom.item.type", FT_UINT8, BASE_DEC, VALS(sapdiag_item_dynt_atom_item_etype_vals), 0x0, NULL, HFILL }},

		/* Dynt Atom Attribute Flags */
		{ &hf_sapdiag_item_dynt_atom_item_attr,
			{ "Dynt Atom Item Attributes", "sapdiag.item.value.dyntatom.item.attr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_COMBOSTYLE,
			{ "Dynt Atom Item Attribute Combo Style", "sapdiag.item.value.dyntatom.item.attr.COMBOSTYLE", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_COMBOSTYLE, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_YES3D,
			{ "Dynt Atom Item Attribute Yes3D", "sapdiag.item.value.dyntatom.item.attr.YES3D", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_YES3D, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROPFONT,
			{ "Dynt Atom Item Attribute Prop Font", "sapdiag.item.value.dyntatom.item.attr.PROPFONT", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_PROPFONT, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_MATCHCODE,
			{ "Dynt Atom Item Attribute Match Code", "sapdiag.item.value.dyntatom.item.attr.MATCHCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_MATCHCODE, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_JUSTRIGHT,
			{ "Dynt Atom Item Attribute Just Right", "sapdiag.item.value.dyntatom.item.attr.JUSTRIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_JUSTRIGHT, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INTENSIFY,
			{ "Dynt Atom Item Attribute Intensify", "sapdiag.item.value.dyntatom.item.attr.INTENSIFY", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_INTENSIFY, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INVISIBLE,
			{ "Dynt Atom Item Attribute Invisible", "sapdiag.item.value.dyntatom.item.attr.INVISIBLE", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_INVISIBLE, NULL, HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROTECTED,
			{ "Dynt Atom Item Attribute Protected", "sapdiag.item.value.dyntatom.item.attr.PROTECTED", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_PROTECTED, NULL, HFILL }},

		/* Control Properties fields */
		{ &hf_sapdiag_item_control_properties_id,
			{ "Control Properties ID", "sapdiag.item.value.controlproperties.id", FT_UINT16, BASE_HEX, VALS(sapdiag_item_control_properties_id_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_control_properties_value,
			{ "Control Properties Value", "sapdiag.item.value.controlproperties.value", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* UI Event Source fields */
		{ &hf_sapdiag_item_ui_event_event_type,
			{ "UI Event Source Type", "sapdiag.item.value.uievent.type", FT_UINT16, BASE_DEC, VALS(sapdiag_item_ui_event_event_type_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_control_type,
			{ "UI Event Control Type", "sapdiag.item.value.uievent.control", FT_UINT16, BASE_DEC, VALS(sapdiag_item_ui_event_control_type_vals), 0x0, NULL, HFILL }},

		{ &hf_sapdiag_item_ui_event_valid,
			{ "UI Event Valid", "sapdiag.item.value.uievent.valid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_valid_MENU_POS,
			{ "UI Event Valid Menu Pos", "sapdiag.item.value.uievent.valid.MENU_POS", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_MENU_POS, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_valid_CONTROL_POS,
			{ "UI Event Valid Control Pos", "sapdiag.item.value.uievent.valid.CONTROL_POS", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_CONTROL_POS, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_valid_NAVIGATION_DATA,
			{ "UI Event Valid Navigation Data", "sapdiag.item.value.uievent.valid.NAVIGATION_DATA", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_valid_FUNCTIONKEY_DATA,
			{ "UI Event Valid Function Key Data", "sapdiag.item.value.uievent.valid.FUNCTIONKEY_DATA", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA, NULL, HFILL }},

		{ &hf_sapdiag_item_ui_event_control_row,
			{ "UI Event Source Control Row", "sapdiag.item.value.uievent.controlrow", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_control_col,
			{ "UI Event Source Control Column", "sapdiag.item.value.uievent.controlcol", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_navigation_data,
			{ "UI Event Source Navigation Data", "sapdiag.item.value.uievent.navigationdata", FT_UINT32, BASE_DEC, VALS(sapdiag_item_ui_event_navigation_data_vals), 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_data,
			{ "UI Event Source Data", "sapdiag.item.value.uievent.data", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_container_nrs,
			{ "UI Event Source Container IDs Numbers", "sapdiag.item.value.uievent.containernrs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapdiag_item_ui_event_container,
			{ "UI Event Source Container ID", "sapdiag.item.value.uievent.container", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		/* Menu Entries */
		{ &hf_sapdiag_item_menu_entry,
			{ "Menu Entry", "sapdiag.item.value.menu", FT_NONE, BASE_NONE, NULL, 0x0, NULL,
			HFILL }},

	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_sapdiag
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_sapdiag_item_unknown, { "sapdiag.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Item has a unknown type that is not dissected", EXPFILL }},
		{ &ei_sapdiag_item_partial, { "sapdiag.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Item is dissected partially", EXPFILL }},
		{ &ei_sapdiag_item_unknown_length, { "sapdiag.item.length.unknown", PI_UNDECODED, PI_WARN, "Diag Type of unknown length", EXPFILL }},
		{ &ei_sapdiag_item_offset_invalid, { "sapdiag.item.offset.invalid", PI_MALFORMED, PI_ERROR, "Invalid offset", EXPFILL }},
		{ &ei_sapdiag_item_length_invalid, { "sapdiag.item.length.invalid", PI_MALFORMED, PI_WARN, "Item length is invalid", EXPFILL }},
		{ &ei_sapdiag_atom_item_unknown, { "sapdiag.item.value.dyntatom.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Atom has a unknown type that is not dissected", EXPFILL }},
		{ &ei_sapdiag_atom_item_partial, { "sapdiag.item.value.dyntatom.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Atom is dissected partially", EXPFILL }},
		{ &ei_sapdiag_atom_item_malformed, { "sapdiag.item.value.dyntatom.invalid", PI_MALFORMED, PI_WARN, "The Diag Atom is malformed", EXPFILL }},
		{ &ei_sapdiag_dynt_focus_more_cont_ids, { "sapdiag.item.value.uievent.containernrs.invalid", PI_MALFORMED, PI_WARN, "Number of Container IDs is invalid", EXPFILL }},
		{ &ei_sapdiag_password_field, { "sapdiag.item.value.dyntatom.item.password", PI_SECURITY, PI_WARN, "Password field?", EXPFILL }},
	};

	module_t *sapdiag_module;
	expert_module_t* sapdiag_expert;

	/* Register the protocol */
	proto_sapdiag = proto_register_protocol("SAP Diag Protocol", "SAPDIAG", "sapdiag");

	proto_register_field_array(proto_sapdiag, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	sapdiag_expert = expert_register_protocol(proto_sapdiag);
	expert_register_field_array(sapdiag_expert, ei, array_length(ei));

	register_dissector("sapdiag", dissect_sapdiag, proto_sapdiag);

	/* Register the preferences */
	sapdiag_module = prefs_register_protocol(proto_sapdiag, proto_reg_handoff_sapdiag);

	range_convert_str(wmem_epan_scope(), &global_sapdiag_port_range, SAPDIAG_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(sapdiag_module, "tcp_ports", "SAP Diag Protocol TCP port numbers", "Port numbers used for SAP Diag Protocol (default " SAPDIAG_PORT_RANGE ")", &global_sapdiag_port_range, MAX_TCP_PORT);

	prefs_register_bool_preference(sapdiag_module, "rfc_dissection", "Dissect embedded SAP RFC calls", "Whether the SAP Diag Protocol dissector should call the SAP RFC dissector for embedded RFC calls", &global_sapdiag_rfc_dissection);

	prefs_register_bool_preference(sapdiag_module, "snc_dissection", "Dissect SAP SNC frames", "Whether the SAP Diag Protocol dissector should call the SAP SNC dissector for SNC frames", &global_sapdiag_snc_dissection);

	prefs_register_bool_preference(sapdiag_module, "highlight_unknown_items", "Highlight unknown SAP Diag Items", "Whether the SAP Diag Protocol dissector should highlight unknown SAP Diag item (might be noise and generate a lot of expert warnings)", &global_sapdiag_highlight_items);

}

/**
 * Helpers for dealing with the port range
 */
static void range_delete_callback (uint32_t port, void *ptr _U_)
{
	dissector_delete_uint("sapni.port", port, sapdiag_handle);
}

static void range_add_callback (uint32_t port, void *ptr _U_)
{
	dissector_add_uint("sapni.port", port, sapdiag_handle);
}

/**
 * Register Hand off for the SAP Diag Protocol
 */
void
proto_reg_handoff_sapdiag(void)
{
	static range_t *sapdiag_port_range;
	static bool initialized = false;

	if (!initialized) {
		sapdiag_handle = create_dissector_handle(dissect_sapdiag, proto_sapdiag);
		initialized = true;
	} else {
		range_foreach(sapdiag_port_range, range_delete_callback, NULL);
		wmem_free(wmem_epan_scope(), sapdiag_port_range);
	}

	sapdiag_port_range = range_copy(wmem_epan_scope(), global_sapdiag_port_range);
	range_foreach(sapdiag_port_range, range_add_callback, NULL);
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
