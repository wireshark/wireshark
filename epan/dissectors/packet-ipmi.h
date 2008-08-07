/* packet-ipmi.h
 * Definitions for IPMI dissection
 * Copyright 2002-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __PACKET_IPMI_H__
#define __PACKET_IPMI_H__

/* IPMI definitions */

/* Max 32 netfn codes: 6 bits, of which 1 designates request/response */
#define IPMI_NETFN_MAX 32

/* IPMI Network Function supported values.
 */
#define IPMI_CHASSIS_REQ	0x00	/* Chassis */
#define IPMI_BRIDGE_REQ		0x02	/* Bridge */
#define IPMI_SE_REQ		0x04	/* Sensor/Event */
#define IPMI_APP_REQ		0x06	/* Application */
#define IPMI_UPDATE_REQ		0x08	/* Firmware update */
#define IPMI_STORAGE_REQ	0x0a	/* Storage */
#define IPMI_TRANSPORT_REQ	0x0c	/* Transport */
#define IPMI_GROUP_REQ		0x2c	/* Group */
#define IPMI_OEM_REQ		0x2e	/* OEM */

/* Selector for dissecting OEM commands which do not carry OEM signatures.
 * IPMI spec says these commands are to be specified by OEM and depend on
 * the IANA number reported via Get Device ID. However, Wireshark has no
 * means to guess that. Therefore, allow the user to select which OEM commands
 * should be used. This applies to the following netFns: 0x08/0x09 (Update),
 * 0x30..0x3f. Note that the commands which bear defining body signature
 * (netFns 0x2c..0x2f) are registered with IPMI_OEM_NONE, as they can be
 * recognized. */
enum {
	IPMI_OEM_NONE = 0,
	IPMI_OEM_PPS		/* Pigeon Point Systems extensions */
};

/* IPMI header fields */
struct ipmi_header {
	guint8 trg_sa;
	guint8 trg_lun;
	guint8 src_sa;
	guint8 src_lun;
	guint8 netfn;
	guint8 cmd;
	guint8 seq;
	guint8 ccode;
	guint8 data_len;
};

extern struct ipmi_header *ipmi_current_hdr;

/* Sub-parser */
typedef void (*ipmi_cmd_handler_t)(tvbuff_t *, proto_tree *);

/* IPMI command structure.  */
typedef struct {
	guint32			cmd;		/* Command number */
	ipmi_cmd_handler_t	parse_req;	/* Request parser */
	ipmi_cmd_handler_t	parse_resp;	/* Response parser */
	const value_string      *cs_cc;		/* Command-specific completion codes */
	const value_string	*subfn;		/* Subfunction codes */
	const char		*desc;		/* Command description */
	int			flags;		/* Command flags */
} ipmi_cmd_t;

/* Command flags */
#define CMD_MAYBROADCAST	0x01		/* Command can be broadcast over IPMB */
#define CMD_CALLRQ		0x02		/* Call request handler early to cache data */
#define CMD_NEWCONV		0x04		/* This command starts new conversation */

void ipmi_setsaveddata(guint idx, guint32 val);
gboolean ipmi_getsaveddata(guint idx, guint32 *val);

/* Top-level search structure: signatures (if any) + command table */
typedef struct ipmi_netfn_handler {
	struct ipmi_netfn_handler *next;
	const char *desc;
	guint oem_selector;
	const guint8 *sig;
	ipmi_cmd_t *cmdtab;
	guint32 cmdtablen;
} ipmi_netfn_t;

/* Handy wrapper around decode_bitfield_value() */
char *ipmi_dcd8(guint32 val, guint32 mask);

/* Stub parser. Use this to substitute for not-yet-written subparsers;
   NULL in command table means 'no custom data in this request/response' */
void ipmi_notimpl(tvbuff_t *tvb, proto_tree *tree);
#define IPMI_TBD  ipmi_notimpl, ipmi_notimpl

/* Add a Type/Length field to tree */
void ipmi_add_typelen(proto_tree *tree, const char *desc, tvbuff_t *tvb,
		guint offs, gboolean is_fru);

/* Add Timestamp in IPMI format */
void ipmi_add_timestamp(proto_tree *tree, gint hf, tvbuff_t *tvb, guint offset);

/* GUID, IPMI style (fields reversed, little-endian) */
void ipmi_add_guid(proto_tree *tree, gint hf, tvbuff_t *tvb, guint offset);

/* Common format routines */
void ipmi_fmt_10ms_1based(gchar *, guint32);
void ipmi_fmt_500ms_0based(gchar *, guint32);
void ipmi_fmt_500ms_1based(gchar *, guint32);
void ipmi_fmt_1s_0based(gchar *, guint32);
void ipmi_fmt_1s_1based(gchar *, guint32);
void ipmi_fmt_2s_0based(gchar *, guint32);
void ipmi_fmt_5s_1based(gchar *, guint32);
void ipmi_fmt_version(gchar *, guint32);
void ipmi_fmt_channel(gchar *, guint32);
void ipmi_fmt_udpport(gchar *, guint32);
void ipmi_fmt_percent(gchar *, guint32);

/* Registrar for subparsers */
void ipmi_register_netfn_cmdtab(guint32 netfn, guint oem_selector,
		const guint8 *sig, guint32 siglen, const char *desc,
		ipmi_cmd_t *cmdtab, guint32 cmdtablen);

/* Lookup routines */
guint32 ipmi_getsiglen(guint32 netfn);
const char *ipmi_getnetfnname(guint32 netfn, ipmi_netfn_t *nf);
ipmi_netfn_t *ipmi_getnetfn(guint32 netfn, const guint8 *sig);
ipmi_cmd_t *ipmi_getcmd(ipmi_netfn_t *nf, guint32 cmd);
const char *ipmi_get_completion_code(guint8 completion, ipmi_cmd_t *cmd);

/* Sub-registrars (ipmi_*.c) */
void ipmi_register_app(int proto);
void ipmi_register_bridge(int proto);
void ipmi_register_chassis(int proto);
void ipmi_register_picmg(int proto);
void ipmi_register_pps(int proto);
void ipmi_register_se(int proto);
void ipmi_register_storage(int proto);
void ipmi_register_transport(int proto);
void ipmi_register_update(int proto);

/* Main dissection routine */
#define IPMI_D_NONE			0x0001 /* Do not parse at all */
#define IPMI_D_SESSION_HANDLE		0x0002 /* Session handle */
#define IPMI_D_BROADCAST		0x0004 /* Check for broadcast message */
#define IPMI_D_TRG_SA			0x0008 /* Target slave addr is present */

struct ipmi_reqresp;

typedef struct {
	guint32 flags;
	gchar info[ITEM_LABEL_LENGTH];
	void *arg;			/* Argument passed to callbacks */

	/* Extra methods for requests that contain embedded commands */
	struct ipmi_header *(*getmoreheaders)(struct ipmi_header *base, void *arg, guint i);
	int (*whichresponse)(struct ipmi_header *hdr, struct ipmi_reqresp *rr);
	int (*otheridx)(struct ipmi_header *hdr);
} ipmi_dissect_format_t;

int ipmi_guess_dissect_flags(tvbuff_t *tvb);
void ipmi_do_dissect(tvbuff_t *tvb, proto_tree *tree, ipmi_dissect_format_t *dfmt);

struct ipmi_header *ipmi_sendmsg_getheaders(struct ipmi_header *base, void *arg, guint i);
int ipmi_sendmsg_whichresponse(struct ipmi_header *hdr, struct ipmi_reqresp *rr);
int ipmi_sendmsg_otheridx(struct ipmi_header *hdr);

#endif
