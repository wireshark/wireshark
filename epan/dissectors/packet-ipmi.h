/* packet-ipmi.h
 * Definitions for IPMI dissection
 * Copyright 2002-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IPMI_H__
#define __PACKET_IPMI_H__

#include <epan/expert.h>

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

/*
 * Command context (environment).
 */
enum {
	IPMI_E_NONE,		/* no surround environment */
	IPMI_E_SENDMSG_RQ,	/* encapsulated into Send Message request */
	IPMI_E_SENDMSG_RS,	/* encapsulated into Send Message response */
	IPMI_E_GETMSG		/* encapsulated into Get Message response */
};

/*
 * Cached IPMI message header.
 */
typedef struct {
	uint8_t context;
	uint8_t channel;
	uint8_t dir;
	uint8_t session;
	uint8_t rs_sa;
	uint8_t rs_lun;
	uint8_t netfn;
	uint8_t rq_sa;
	uint8_t rq_lun;
	uint8_t rq_seq;
	uint8_t cmd;
} ipmi_header_t;

/* Sub-parser */
typedef void (*ipmi_cmd_handler_t)(tvbuff_t *,
		packet_info *, proto_tree *);

/* IPMI command structure.  */
typedef struct {
	uint32_t			cmd;		/* Command number */
	ipmi_cmd_handler_t	parse_req;	/* Request parser */
	ipmi_cmd_handler_t	parse_resp;	/* Response parser */
	const value_string      *cs_cc;		/* Command-specific completion codes */
	const value_string	*subfn;		/* Subfunction codes */
	const char		*desc;		/* Command description */
	int			flags;		/* Command flags */
} ipmi_cmd_t;

/* Command flags */
#define CMD_CALLRQ		0x02		/* Call request handler early to cache data */

/* Get currently parsed message header */
const ipmi_header_t * ipmi_get_hdr(packet_info * pinfo);

/* Get completion code for currently parsed message */
uint8_t ipmi_get_ccode(packet_info * pinfo);

/* Save request data for later use in response */
void ipmi_set_data(packet_info *pinfo, unsigned idx, uint32_t data);

/* Get saved request data */
bool ipmi_get_data(packet_info *pinfo, unsigned idx, uint32_t * data);

/* Top-level search structure: signatures (if any) + command table */
typedef struct ipmi_netfn_handler {
	struct ipmi_netfn_handler *next;
	const char *desc;
	unsigned oem_selector;
	const uint8_t *sig;
	const ipmi_cmd_t *cmdtab;
	uint32_t cmdtablen;
} ipmi_netfn_t;

/* Stub parser. Use this to substitute for not-yet-written subparsers;
   NULL in command table means 'no custom data in this request/response' */
void ipmi_notimpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
#define IPMI_TBD  ipmi_notimpl, ipmi_notimpl

/* Add a Type/Length field to tree */
void ipmi_add_typelen(packet_info *pinfo, proto_tree *tree, int hf_string, int hf_type, int hf_length, tvbuff_t *tvb,
		unsigned offs, bool is_fru);

/* Add Timestamp in IPMI format */
void ipmi_add_timestamp(packet_info *pinfo, proto_tree *tree, int hf, tvbuff_t *tvb, unsigned offset);

/* GUID, IPMI style (fields reversed, little-endian) */
void ipmi_add_guid(proto_tree *tree, int hf, tvbuff_t *tvb, unsigned offset);

/* Common format routines */
void ipmi_fmt_10ms_1based(char *, uint32_t);
void ipmi_fmt_500ms_0based(char *, uint32_t);
void ipmi_fmt_500ms_1based(char *, uint32_t);
void ipmi_fmt_1s_0based(char *, uint32_t);
void ipmi_fmt_1s_1based(char *, uint32_t);
void ipmi_fmt_2s_0based(char *, uint32_t);
void ipmi_fmt_5s_1based(char *, uint32_t);
void ipmi_fmt_version(char *, uint32_t);
void ipmi_fmt_channel(char *, uint32_t);
void ipmi_fmt_udpport(char *, uint32_t);
void ipmi_fmt_percent(char *, uint32_t);

/* Registrar for subparsers */
void ipmi_register_netfn_cmdtab(uint32_t netfn, unsigned oem_selector,
		const uint8_t *sig, uint32_t siglen, const char *desc,
		const ipmi_cmd_t *cmdtab, uint32_t cmdtablen);

/* Lookup routines */
uint32_t ipmi_getsiglen(uint32_t netfn);
const char *ipmi_getnetfnname(wmem_allocator_t *pool, uint32_t netfn, ipmi_netfn_t *nf);
ipmi_netfn_t *ipmi_getnetfn(uint32_t netfn, const uint8_t *sig);
const ipmi_cmd_t *ipmi_getcmd(ipmi_netfn_t *nf, uint32_t cmd);
const char *ipmi_get_completion_code(uint8_t completion, const ipmi_cmd_t *cmd);

/* Used for sub-registrars (ipmi_*.c) */
extern int proto_ipmi;

/* Main dissection routine */
#define IPMI_D_NONE		0x0001 /* Do not parse at all */
#define IPMI_D_SESSION_HANDLE	0x0002 /* Session handle */
#define IPMI_D_BROADCAST	0x0004 /* Check for broadcast message */
#define IPMI_D_TRG_SA		0x0008 /* Target slave addr is present */
#define IPMI_D_TMODE		0x0010 /* Bridged field instead of Rq LUN */
#define IPMI_D_NO_CKS		0x0020 /* Checksum bytes are not present */
#define IPMI_D_NO_RQ_SA		0x0040 /* RQ SA is not present */
#define IPMI_D_NO_SEQ		0x0080 /* RQ Seq is not present */

/* IPMI dissector argument */
typedef struct {
	uint8_t context;
	uint8_t channel;
	uint8_t flags;
} ipmi_dissect_arg_t;

int
do_dissect_ipmb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		int hf_parent_item, int ett_tree, ipmi_dissect_arg_t * arg);

#endif /* __PACKET_IPMI_H__ */

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
