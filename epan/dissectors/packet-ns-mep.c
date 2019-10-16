/* packet-ns-mep.c
 * Routines for netscaler GSLB metric exchange protocol dissection
 * Copyright 2006, Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-tcp.h"

void proto_register_ns_mep(void);
void proto_reg_handoff_ns_mep(void);

static int proto_ns_mep = -1;

static gint ett_nsmep = -1;
static gint ett_nsmep_mfu = -1;
static gint ett_nsmep_nwu = -1;

static int hf_nsmep_majver = -1;
static int hf_nsmep_minver = -1;
static int hf_nsmep_msgtype = -1;
static int hf_nsmep_msglen = -1;
static int hf_nsmep_errcode = -1;
static int hf_nsmep_mfu_state = -1;


static int hf_ns_metricUpdate = -1;
static int hf_ns_forceUpdateRequest = -1;
static int hf_ns_forceUpdateResp = -1;
static int hf_ns_currentOpenConn = -1;
static int hf_ns_currentSurgeCount = -1;
static int hf_ns_currentIOHCount = -1;
static int hf_ns_currentReusePool  = -1;
static int hf_ns_currentServerConn = -1;
static int hf_ns_currentClientConn  = -1;
static int hf_ns_TotalReq = -1;
static int hf_ns_TotalReqBytes = -1;
static int hf_ns_TotalResp = -1;
static int hf_ns_TotalRespBytes = -1;
static int hf_ns_networkMetrics = -1;
static int hf_ns_roundTripTime = -1;
static int hf_ns_hops = -1;
static int hf_ns_persistenceInfo = -1;
static int hf_ns_persistenceGslbServIp = -1;
static int hf_ns_persistenceGslbServPort = -1;
static int hf_ns_persistenceId = -1;
static int hf_ns_sitePersistenceDom  = -1;
static int hf_ns_gslbDomNamelen  = -1;
static int hf_ns_gslbServPreflen  = -1;
static int hf_ns_gslbCookieDomNamelen  = -1;
static int hf_ns_gslbCookieTimeout = -1;
static int hf_ns_gslbVidlen = -1;
static int hf_ns_gslbFlags = -1;
static int hf_ns_gslbCookieDomName = -1;
static int hf_ns_gslbVs = -1;
static int hf_ns_gslbPrefix = -1;
static int hf_ns_sitePersistenceFlushDom = -1;
static int hf_ns_gslbDomName = -1;
static int hf_ns_sitePersistenceFlushServ = -1;
static int hf_ns_sitePersisGetServReq = -1;
static int hf_ns_siteDomTTL = -1;
static int hf_ns_sitePersistenceGetServResp = -1;



static int hf_nsmep_mfu_ip = -1;
static int hf_nsmep_mfu_port = -1;
static int hf_nsmep_mfu_svctype = -1;
static int hf_nsmep_mfu_eff_state = -1;
static int hf_nsmep_mfu_mepflag = -1;
static int hf_nsmep_mfu_reqflag = -1;

static int hf_nsmep_adv_ip = -1;

static int hf_nsmep_ldns_ip = -1;
static int hf_nsmep_site_persistence = -1;
dissector_handle_t nsrpc_handle;

/*GSLB MEP message types */
#define nslist_gslbmessage_VALUE_STRING_LIST(V) \
	V(GSLB_MSG_NONE, 0, "NONE")\
	V(GSLB_MSG_SITE_METRIC_UPDATE, 1, "SITE METRIC UPDATE") \
	V(GSLB_MSG_SITE_METRIC_FORCE_REQ, 2, "SITE METRIC FORCE REQ")\
	V(GSLB_MSG_SITE_ADV_IP_ADDR, 3, "SITE ADV IP ADDR")\
	V(GSLB_MSG_SITE_ADV_IP_ACK, 4, "SITE ADV IP ACK")\
	V(GSLB_MSG_SITE_ADV_IP_NACK, 5, "SITE ADV IP NACK")\
	V(GSLB_MSG_SITE_METRIC_FORCE_UPDATE, 6, "SITE METRIC FORCE UPDATE")\
	V(GSLB_MSG_NETW_METRIC_UPDATE, 7, "NETWORK METRIC UPDATE")\
	V(GSLB_MSG_PERSIST_RECORD, 8, "PERSIST RECORD")\
	V(GSLB_MSG_KEEP_ALIVE, 9, "KEEP ALIVE")\
	V(GSLB_MSG_CNAME_PERSIST_RECORD, 10, "CNAME PERSIST RECORD")\
	V(GSLB_MSG_LBNODE_DOM_INFO, 11, "DOMAIN INFO")\
	V(GSLB_MSG_LBNODE_SITE_INFO, 12, "SITE INFO")\
	V(GSLB_MSG_LBNODE_FLUSH_SVC_INFO, 13, "FLUSH SVC")\
	V(GSLB_MSG_LBNODE_FLUSH_DOM_INFO, 14, "FLUSH DOMAIN")\
	V(GSLB_MSG_LBNODE_GETSVC, 15, "GET SVC")\
	V(GSLB_MSG_LBNODE_GETSVC_RESP, 16, "GET SVC RESP")\

VALUE_STRING_ENUM(nslist_gslbmessage);
VALUE_STRING_ARRAY(nslist_gslbmessage);

static const value_string ns_entity_state_vals[] = {
	{ 0x01, "SERVER_STATE_DOWN" },
	{ 0x02, "SERVER_STATE_UNKNOWN" },
	{ 0x03, "SERVER_STATE_BUSY" },
	{ 0x04, "SERVER_STATE_OFS" },
	{ 0x05, "SERVER_STATE_TROFS" },
	{ 0x07, "SERVER_STATE_UP" },
	{ 0x08, "SERVER_STATE_TROFS_DOWN" },

	{ 0,			  NULL }
};


static const value_string ns_svc_type_vals[] = {
	{ 0x00, "NSSVC_HTTP"},
	{ 0x01, "NSSVC_FTP"},
	{ 0x02, "NSSVC_TCP"},
	{ 0x03, "NSSVC_UDP"},
	{ 0x04, "NSSVC_SSL_BRIDGE"},
	{ 0x05, "NSSVC_MONITOR"},
	{ 0x06, "NSSVC_MONITOR_UDP"},
	{ 0x07, "NSSVC_NNTP"},
	{ 0x08, "NSSVC_HTTPSVR"},
	{ 0x09, "NSSVC_HTTPCLNT"},
	{ 0x0a, "NSSVC_RPCSVR"},
	{ 0x0b, "NSSVC_RPCCLNT"},
	{ 0x0c, "NSSVC_NAT"},
	{ 0x0d, "NSSVC_ANY"},
	{ 0x0e, "NSSVC_SSL"},
	{ 0x0f, "NSSVC_DNS"},
	{ 0x10, "NSSVC_ADNS"},
	{ 0x11, "NSSVC_SNMP"},
	{ 0x12, "NSSVC_HA"},
	{ 0x13, "NSSVC_MONITOR_PING"},
	{ 0x14, "NSSVC_SSL_TCP"},
	{ 0x15, "NSSVC_AAA"},
	{ 0x16, "NSSVC_SINCTCP"},
	{ 0x17, "NSSVC_VPN_AFTP"},
	{ 0x18, "NSSVC_MONITORS"},
	{ 0x19, "NSSVC_SSLVPNUDP"},
	{ 0x1a, "NSSVC_SINCUDP"},
	{ 0x1b, "NSSVC_RIP"},
	{ 0x1c, "NSSVC_DNSCLT"},
	{ 0x1d, "NSSVC_SASP"},
	{ 0x1e, "NSSVC_RPCSVRS"},
	{ 0x1f, "NSSVC_RPCCLNTS"},
	{ 0x20, "NSSVC_WINS_RESOLVER"},
	{ 0x21, "NSSVC_DHCPRA"},
	{ 0x22, "NSSVC_ROUTE"},
	{ 0x23, "NSSVC_AUDIT"},
	{ 0x24, "NSSVC_SIP_UDP"},
	{ 0x25, "NSSVC_STA_HTTP"},
	{ 0x26, "NSSVC_STA_SSL"},
	{ 0x27, "NSSVC_DNS_RESOLV"},
	{ 0x28, "NSSVC_RTSP"},

	{ 0, NULL }
};

static const value_string ns_rpc_errcode_vals[] = {
	{ 0x000, "SUCCESS" },

	{ 0x101, "PERM ERR" },
	{ 0x10C, "NO MEM" },
	{ 0x135, "CONN ABORTED" },
	{ 0x150, "AUTH ERR" },
	{ 0x153, "NOCODE" },
	{ 0x154, "NOT SUPERUSER" },
	{ 0x155, "LARGE DATA"},
	{ 0x156, "SMALL DATA" },
	{ 0x160, "LOGIN REQD" },
	{ 0x161, "INVALID ARG" },
	{ 0x162, "INVALID USER/ PASSWD" },
	{ 0x163, "INVALID USER/ PASSWD" },

	{ 0x413, "INTERNAL ERR" },

	{ 0x6FF, "DH REQ" },

	{ 0, NULL }
};

static const value_string value_site_persistence[] = {
	{ 0x00, "NONE"},
	{ 0x01, "CONN-PROXY"},
	{ 0x02, "HTTP-REDIRECT"},
	{ 0, NULL}
};

#define GSLIB_EXCHANGE_DATA_SIZE    72
#define GSLB_FORCE_VIP_SIZE         12
#define GSLIB_NET_MET_TABLE_SIZE    8

#define NS_PERSIST_INFO_SIZE            12
#define NS_GSLB_DOM_INFO_MIN_SIZE       23
#define NS_GSLB_FLUSH_DOM_INFO_MIN_SIZE 9
#define Ns_GSLB_MSG_SITE_METRIC_UPDATE_SIZE 16

/* XXX - for informational purposes only */
typedef struct nsgslb_dom_info {
	guint32 public_ip;
	guint16	public_port;
	guint16 protocol;
	guint8	domainlen;
	guint8	prefixlen;
	guint8	cookiedomlen;
	guint8	site_persistence;
	guint8	cookietimeout;
	guint8	vidlen;
	guint8 flags;
	guint16 reserved;
}nsgslb_dom_info_t;

/*gslb domain info flag values */
#define NSGSLB_DOMINFO_DOGSLB 0x01
#define NSGSLB_DOMINFO_REDIRECT 0x02
#define NSGSLB_DOMINFO_FLUSH_ALL_GSLBINFO 0x4

static void
dissect_ns_mep_v02xx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 maj_ver, min_ver, mesgtype, mesglen, errcode;
	guint32 public_port, svctype, domainlen;
	proto_item *ti;
	proto_tree *ns_mep_tree;
	int offset = 0, start_offset;
	gchar* version_str;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NS-MEP");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_ns_mep, tvb, 0, -1, ENC_NA);
	ns_mep_tree = proto_item_add_subtree(ti, ett_nsmep);

	proto_tree_add_item_ret_uint(ns_mep_tree, hf_nsmep_majver, tvb, offset, 1, ENC_LITTLE_ENDIAN, &maj_ver);
	offset +=1;
	proto_tree_add_item_ret_uint(ns_mep_tree, hf_nsmep_minver, tvb, offset, 1, ENC_LITTLE_ENDIAN, &min_ver);
	offset +=1;
	proto_tree_add_item_ret_uint(ns_mep_tree, hf_nsmep_msgtype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &mesgtype);
	offset +=2;
	version_str = wmem_strdup_printf(wmem_packet_scope(), "v%d.%d %s", maj_ver, min_ver, val_to_str(mesgtype, nslist_gslbmessage, "Unknown Mesg Type:  0x%02X"));
	proto_item_append_text(ti, ", %s", version_str);
	proto_tree_add_item_ret_uint(ns_mep_tree, hf_nsmep_msglen, tvb, offset, 2, ENC_LITTLE_ENDIAN, &mesglen);
	offset +=2;
	proto_tree_add_item_ret_uint(ns_mep_tree, hf_nsmep_errcode, tvb, offset, 2, ENC_LITTLE_ENDIAN, &errcode);
	offset +=2;

	col_add_fstr(pinfo->cinfo, COL_INFO, "Mesg: %s; Len: %d", version_str, mesglen);

	switch (mesgtype)
	{
	case GSLB_MSG_SITE_METRIC_UPDATE:
	{
		proto_item *tf;
		proto_tree *ns_mep_mfu_tree;

		while (tvb_reported_length_remaining(tvb, offset) >= Ns_GSLB_MSG_SITE_METRIC_UPDATE_SIZE)
		{
			tf = proto_tree_add_item(ns_mep_tree, hf_ns_metricUpdate, tvb, offset, Ns_GSLB_MSG_SITE_METRIC_UPDATE_SIZE, ENC_NA);
			ns_mep_mfu_tree = proto_item_add_subtree(tf, ett_nsmep_mfu);

			/* proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_cmd, tvb, offset, 2, ENC_LITTLE_ENDIAN); */
			offset +=2;
			proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset +=2;
			proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset +=4;
			proto_tree_add_item_ret_uint(ns_mep_mfu_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
			offset +=2;
			proto_tree_add_item_ret_uint(ns_mep_mfu_tree, hf_nsmep_mfu_svctype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &svctype);
			offset +=2;

			proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));
			if ((maj_ver > 2) || ((maj_ver==2) && (min_ver > 2)))
			{
				proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_eff_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset +=1;
				proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_mepflag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset +=1;
				offset +=2;
			} else
			{
				offset +=4;
			}
		}
	}
	break;
	case GSLB_MSG_SITE_METRIC_FORCE_REQ:
	{
		proto_item *tf;
		proto_tree *ns_mep_mfr_tree;

		while (tvb_reported_length_remaining(tvb, offset) >= GSLB_FORCE_VIP_SIZE)
		{
			tf = proto_tree_add_item(ns_mep_tree, hf_ns_forceUpdateRequest, tvb, offset, GSLB_FORCE_VIP_SIZE, ENC_NA);
			ns_mep_mfr_tree = proto_item_add_subtree(tf, ett_nsmep_mfu);

			proto_tree_add_item(ns_mep_mfr_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset +=4;
			proto_tree_add_item_ret_uint(ns_mep_mfr_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
			offset +=2;
			proto_tree_add_item_ret_uint(ns_mep_mfr_tree, hf_nsmep_mfu_svctype, tvb, offset, 4, ENC_LITTLE_ENDIAN, &svctype);
			offset +=4;

			proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));

			if ((maj_ver > 2) || ((maj_ver==2) && (min_ver > 2)))
			{
				proto_tree_add_item(ns_mep_mfr_tree, hf_nsmep_mfu_reqflag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset +=1;
				offset +=1;
			} else
			{
				offset +=2;
			}
		}
	}
	break;
	case GSLB_MSG_SITE_ADV_IP_ADDR:
		proto_tree_add_item(ns_mep_tree, hf_nsmep_adv_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case GSLB_MSG_SITE_ADV_IP_ACK:
		break;
	case GSLB_MSG_SITE_ADV_IP_NACK:
		break;
	case GSLB_MSG_SITE_METRIC_FORCE_UPDATE:
	{
		proto_item *tf;
		proto_tree *ns_mep_mfu_tree;

		while (tvb_reported_length_remaining(tvb, offset) >= GSLIB_EXCHANGE_DATA_SIZE)
		{
			tf = proto_tree_add_item(ns_mep_tree, hf_ns_forceUpdateResp, tvb, offset, GSLIB_EXCHANGE_DATA_SIZE, ENC_NA);
			ns_mep_mfu_tree = proto_item_add_subtree(tf, ett_nsmep_mfu);

			/* proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_cmd, tvb, offset, 2, ENC_LITTLE_ENDIAN); */
			offset +=2;
			proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset +=2;
			proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset +=4;
			proto_tree_add_item_ret_uint(ns_mep_mfu_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
			offset +=2;
			proto_tree_add_item_ret_uint(ns_mep_mfu_tree, hf_nsmep_mfu_svctype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &svctype);
			offset +=2;

			proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));

			if ((maj_ver > 2) || ((maj_ver==2) && (min_ver > 2)))
			{
				proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_eff_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset +=1;
				proto_tree_add_item(ns_mep_mfu_tree, hf_nsmep_mfu_mepflag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset +=1;
				offset +=2;
			} else
			{
				offset +=4;
			}

			/* All the counters */
			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_currentOpenConn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_currentSurgeCount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_currentIOHCount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_currentReusePool, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_currentServerConn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_currentClientConn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_TotalReq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_TotalReqBytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_TotalResp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(ns_mep_mfu_tree, hf_ns_TotalRespBytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
		}
	}
	break;
	case GSLB_MSG_NETW_METRIC_UPDATE:
	{
		proto_item *tf;
		proto_tree *ns_mep_nwu_tree;

		while (tvb_reported_length_remaining(tvb, offset) >= GSLIB_NET_MET_TABLE_SIZE)
		{
			tf = proto_tree_add_item(ns_mep_tree, hf_ns_networkMetrics, tvb, offset, GSLIB_NET_MET_TABLE_SIZE, ENC_NA);
			proto_item_append_text(tf, " of %s", tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv4, offset));
			ns_mep_nwu_tree = proto_item_add_subtree(tf, ett_nsmep_nwu);

			proto_tree_add_item(ns_mep_nwu_tree, hf_nsmep_ldns_ip, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_tree, hf_ns_roundTripTime, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(ns_mep_tree, hf_ns_hops, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			offset += 1;
		}
	}
	break;
	case GSLB_MSG_PERSIST_RECORD:
	{
		proto_item *tf;
		proto_tree *ns_mep_pr_tree;

		while (tvb_reported_length_remaining(tvb, offset) >= NS_PERSIST_INFO_SIZE)
		{
			tf = proto_tree_add_item(ns_mep_tree, hf_ns_persistenceInfo, tvb, offset, NS_PERSIST_INFO_SIZE, ENC_NA);
			proto_item_append_text(tf, " %s", tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv4, offset));
			ns_mep_pr_tree = proto_item_add_subtree(tf, ett_nsmep_nwu);

			proto_tree_add_item(ns_mep_pr_tree, hf_nsmep_ldns_ip, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset +=4;

			proto_tree_add_item(ns_mep_tree, hf_ns_persistenceGslbServIp, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(ns_mep_tree, hf_ns_persistenceGslbServPort, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(ns_mep_tree, hf_ns_persistenceId, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
	}
	break;
	case GSLB_MSG_LBNODE_DOM_INFO:
	{
		proto_item *tf;
		proto_tree *ns_mep_di_tree;
		guint32 prefixlen, cookiedomlen, flags, vidlen;

		while (tvb_reported_length_remaining(tvb, offset) >= NS_GSLB_DOM_INFO_MIN_SIZE)
		{
			tf = proto_tree_add_item(ns_mep_tree, hf_ns_sitePersistenceDom, tvb, offset, NS_GSLB_DOM_INFO_MIN_SIZE, ENC_NA);
			ns_mep_di_tree = proto_item_add_subtree(tf, ett_nsmep_nwu);
			start_offset = offset;

			proto_tree_add_item(ns_mep_di_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
			offset += 2;
			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_svctype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &svctype);
			offset += 2;

			proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));

			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbDomNamelen, tvb, offset, 1, ENC_LITTLE_ENDIAN, &domainlen);
			offset += 1;
			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbServPreflen, tvb, offset, 1, ENC_LITTLE_ENDIAN, &prefixlen);
			offset += 1;
			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbCookieDomNamelen, tvb, offset, 1, ENC_LITTLE_ENDIAN, &cookiedomlen);
			offset += 1;
			proto_tree_add_item(ns_mep_di_tree, hf_nsmep_site_persistence, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbCookieTimeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbVidlen, tvb, offset, 4, ENC_LITTLE_ENDIAN, &vidlen);
			offset += 4;
			tf = proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbFlags, tvb, offset, 1, ENC_LITTLE_ENDIAN, &flags);
			if (flags == NSGSLB_DOMINFO_FLUSH_ALL_GSLBINFO)
			{
				proto_item_append_text(tf, "Flush all gslb information");
			}
			else if (flags)
			{
				proto_item_append_text(tf, "Undefined");
			}
			offset += 1;
			offset += 2; /* Skip reserved */

			proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbDomName, tvb, offset, domainlen, ENC_NA|ENC_ASCII);
			offset += domainlen;
			if (cookiedomlen)
			{
				proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbCookieDomName, tvb, offset, cookiedomlen, ENC_NA|ENC_ASCII);
				offset += cookiedomlen;
			}

			proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbVs, tvb, offset, vidlen, ENC_NA|ENC_ASCII);
			offset += vidlen;
			if (prefixlen)
			{
				proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbPrefix, tvb, offset, prefixlen, ENC_NA|ENC_ASCII);
				offset += prefixlen;
			}
			proto_item_set_len(tf, offset-start_offset);
		}
		break;
	}
	case GSLB_MSG_LBNODE_FLUSH_DOM_INFO:
	{
		proto_item *tf;
		proto_tree *ns_mep_di_tree;

		while (tvb_reported_length_remaining(tvb, offset) >= NS_GSLB_FLUSH_DOM_INFO_MIN_SIZE)
		{
			tf = proto_tree_add_item(ns_mep_tree, hf_ns_sitePersistenceFlushDom, tvb, offset, 9, ENC_NA);
			ns_mep_di_tree = proto_item_add_subtree(tf, ett_nsmep_nwu);
			start_offset = offset;

			proto_tree_add_item(ns_mep_di_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
			offset += 2;
			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_svctype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &svctype);
			offset += 2;

			proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));

			proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbDomNamelen, tvb, offset, 1, ENC_LITTLE_ENDIAN, &domainlen);
			offset += 1;
			proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbDomName, tvb, offset, domainlen, ENC_NA|ENC_ASCII);
			offset += domainlen;

			proto_item_set_len(tf, offset-start_offset);

			/* XXX - Do we really have a full domain info message here? */
		}
		break;
	}
	case GSLB_MSG_LBNODE_FLUSH_SVC_INFO:
	{
		proto_item *tf;
		proto_tree *ns_mep_di_tree;

		tf = proto_tree_add_item(ns_mep_tree, hf_ns_sitePersistenceFlushServ, tvb, offset, 8, ENC_NA);
		ns_mep_di_tree = proto_item_add_subtree(tf, ett_nsmep_nwu);

		proto_tree_add_item(ns_mep_di_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
		offset += 2;
		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_svctype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &svctype);
		offset += 2;

		proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));
		break;
	}
	case GSLB_MSG_LBNODE_GETSVC:
	{
		proto_item *tf;
		proto_tree *ns_mep_di_tree;

		tf = proto_tree_add_item(ns_mep_tree, hf_ns_sitePersisGetServReq, tvb, offset, 9, ENC_NA);
		ns_mep_di_tree = proto_item_add_subtree(tf, ett_nsmep_nwu);
		start_offset = offset;

		proto_tree_add_item(ns_mep_di_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
		offset += 2;
		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_svctype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &svctype);
		offset += 2;

		proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));

		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbDomNamelen, tvb, offset, 1, ENC_LITTLE_ENDIAN, &domainlen);
		offset += 1;
		proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbDomName, tvb, offset, domainlen, ENC_NA|ENC_ASCII);
		offset += domainlen;

		proto_item_set_len(tf, start_offset - offset);
		/* XXX - Do we really have a full domain info message here? */
		break;
	}
	case GSLB_MSG_LBNODE_GETSVC_RESP:
	{
		proto_item *tf;
		proto_tree *ns_mep_di_tree;

		tf = proto_tree_add_item(ns_mep_tree, hf_ns_sitePersistenceGetServResp, tvb, offset, 9, ENC_NA);
		ns_mep_di_tree = proto_item_add_subtree(tf, ett_nsmep_nwu);
		start_offset = offset;

		proto_tree_add_item(ns_mep_di_tree, hf_nsmep_mfu_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_port, tvb, offset, 2, ENC_BIG_ENDIAN, &public_port);
		offset += 2;
		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_nsmep_mfu_svctype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &svctype);
		offset += 2;

		proto_item_append_text(tf, " for %s:%d:%s", tvb_address_to_str(wmem_packet_scope(), tvb, FT_IPv4, offset-8), public_port, val_to_str(svctype, ns_svc_type_vals, "0x%02X"));

		proto_tree_add_item_ret_uint(ns_mep_di_tree, hf_ns_gslbDomNamelen, tvb, offset, 1, ENC_LITTLE_ENDIAN, &domainlen);
		offset += 1;
		proto_tree_add_item(ns_mep_di_tree, hf_ns_siteDomTTL, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(ns_mep_di_tree, hf_ns_gslbDomName, tvb, offset, domainlen, ENC_NA|ENC_ASCII);
		offset += domainlen;

		proto_item_set_len(tf, start_offset - offset);
		break;
	}
	case GSLB_MSG_KEEP_ALIVE:
	default:
		break;
	}
}

static int
dissect_ns_mep_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint16 ver;
	guint8 maj_ver, min_ver;

	ver = tvb_get_letohs(tvb, 0);
	maj_ver = tvb_get_guint8(tvb, 0);
	min_ver = tvb_get_guint8(tvb, 1);
	switch(ver)
	{
	case 0x0001:
	case 0x0102:
	case 0x0202:
	case 0x0302:
	case 0x0402:
	case 0x0502:
	case 0x0602:
		dissect_ns_mep_v02xx(tvb, pinfo, tree);
		return tvb_captured_length(tvb);

	default:
		/* It is netscaler mep packet of unknown mep version. */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NS-MEP");
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "The v%d.%d MEP Dissector unavailable", maj_ver, min_ver);
		break;
	}

	return tvb_captured_length(tvb);
}

static guint
get_ns_mep_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/* Get the length of the data from the header. */
	return tvb_get_letohs(tvb, offset + 4);
}

static int
dissect_ns_mep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint16 ns_rpc_sig;

	if (tvb_reported_length(tvb) >= 6)
	{
		/* Get the signature */
		ns_rpc_sig = tvb_get_letohs(tvb, 4);
		if (ns_rpc_sig == 0xA5A5)
		{
			/* If the signature is present, it is a netscaler-rpc connection. call
			the nsrpc dissector.  */
			call_dissector(nsrpc_handle, tvb, pinfo, tree);
			return tvb_captured_length(tvb);
		}
	}

	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 6, get_ns_mep_pdu_len, dissect_ns_mep_pdu, data);
	return tvb_captured_length(tvb);
}

void
proto_register_ns_mep(void)
{
	static hf_register_info hf_nsmep[] = {
		{ &hf_nsmep_majver,
			{ "Major Version", "nstrace.mep.maj", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_minver,
			{ "Minor Version", "nstrace.mep.min", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_msgtype,
			{ "Message Type", "nstrace.mep.type", FT_UINT16, BASE_HEX,  VALS(nslist_gslbmessage), 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_msglen,
			{ "Message Length", "nstrace.mep.len", FT_UINT16, BASE_DEC,  NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_errcode,
			{ "Status Code", "nstrace.mep.errcode", FT_UINT16, BASE_HEX, VALS(ns_rpc_errcode_vals), 0x0,
			NULL, HFILL }},

		//added newly
		{ &hf_ns_metricUpdate,
			{ "Metric Update", "nstrace.mep.mfu.metricUpdate", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_forceUpdateRequest,
			{ "Force Update Request", "nstrace.mep.mfu.forceUpdateRequest", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_forceUpdateResp,
			{ "Force Update Response", "nstrace.mep.mfu.mep_mfu_force_update", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_currentOpenConn,
			{ "Current Open Estd Conn", "nstrace.mep.mfu.currentOpenConn", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_currentSurgeCount,
			{ "Current Surge Count", "nstrace.mep.mfu.currentSurgeCount", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_currentIOHCount,
			{ "Current IOH Count", "nstrace.mep.mfu.currentIOHCount", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_currentReusePool,
			{ "Current Reuse pool", "nstrace.mep.mfu.currentReusePool", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_currentServerConn,
			{ "Current Server Conn", "nstrace.mep.mfu.currentServerConn", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_currentClientConn,
			{ "Current Client Conn", "nstrace.mep.mfu.currentClientConn", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_TotalReq,
			{ "Total Requests", "nstrace.mep.mfu.TotalReq", FT_UINT64, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_TotalReqBytes,
			{ "Total Requests Bytes", "nstrace.mep.mfu.TotalReqBytes", FT_UINT64, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_TotalResp,
			{ "Total Responses", "nstrace.mep.mfu.TotalResp", FT_UINT64, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_TotalRespBytes,
			{ "Total Responses Bytes", "nstrace.mep.mfu.TotalRespBytes", FT_UINT64, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_networkMetrics,
			{ "Network Metrics", "nstrace.mep.mfu.networkMetrics", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_roundTripTime,
			{ "Round Trip Time", "nstrace.mep.mfu.roundTripTime", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0,
			NULL, HFILL } },
		{ &hf_ns_hops,
			{ "Hops", "nstrace.mep.mfu.hops", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_persistenceInfo,
			{ "Persistence Info for LDNS IP", "nstrace.mep.mfu.persistenceInfo", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_persistenceGslbServIp,
			{ "Persistence GSLB Service IP", "nstrace.mep.mfu.persistenceGslbServIp", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_persistenceGslbServPort,
			{ "Persistence GSLB Service Port", "nstrace.mep.mfu.persistenceGslbServPort", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_persistenceId,
			{ "Persistence Id", "nstrace.mep.mfu.persistenceId", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_sitePersistenceDom,
			{ "Site persistence Domain Info", "nstrace.mep.mfu.sitePersistenceDom", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbDomNamelen,
			{ "GSLB Domain Name length", "nstrace.mep.mfu.gslbDomNamelen", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbServPreflen,
			{ "GSLB Service Prefix length", "nstrace.mep.mfu.gslbServPreflen", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbCookieDomNamelen,
			{ "GSLB Cookie domain name length", "nstrace.mep.mfu.gslbCookieDomNamelen", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbCookieTimeout,
			{ "GSLB cookie timeout", "nstrace.mep.mfu.gslbCookieTimeout", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbVidlen,
			{ "GSLB vserver ID length", "nstrace.mep.mfu.gslbVidlen", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbFlags,
			{ "Flags", "nstrace.mep.mfu.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbCookieDomName,
			{ "GSLB Cookie Domain Name", "nstrace.mep.mfu.gslbCookieDomName", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbVs,
			{ "GSLB Vserver ID", "nstrace.mep.mfu.gslbVs", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbPrefix,
			{ "GSLB service prefix", "nstrace.mep.mfu.gslbPrefix", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_sitePersistenceFlushDom,
			{ "Site persistence Flush Domain Info", "nstrace.mep.mfu.sitePersistenceFlushDom", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_gslbDomName,
			{ "GSLB Domain Name", "nstrace.mep.mfu.gslbDomName", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_sitePersistenceFlushServ,
			{ "Site persistence Flush Service", "nstrace.mep.mfu.sitePersistenceFlushServ", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_sitePersisGetServReq,
			{ "Site persistence Get Service request", "nstrace.mep.mfu.sitePersisGetServReq", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_sitePersistenceGetServResp,
			{ "Site persistence Get Service response", "nstrace.mep.mfu.sitePersistenceGetServResp", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL } },
		{ &hf_ns_siteDomTTL,
			{ "Site Domain TTL", "nstrace.mep.mfu.siteDomTTL", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL } },

		{ &hf_nsmep_mfu_state,
			{ "Service State", "nstrace.mep.mfu.state", FT_UINT16, BASE_HEX, VALS(ns_entity_state_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_mfu_eff_state,
			{ "Service Effective State", "nstrace.mep.mfu.effstate", FT_UINT8, BASE_HEX, VALS(ns_entity_state_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_mfu_mepflag,
			{ "MEP Flags", "nstrace.mep.mfu.mepflag", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_mfu_ip,
			{ "Service IP Address", "nstrace.mep.mfu.ip", FT_IPv4, BASE_NONE,  NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_mfu_port,
			{ "Service Port", "nstrace.mep.mfu.port", FT_UINT16, BASE_DEC_HEX,  NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_mfu_svctype,
			{ "Service Type", "nstrace.mep.mfu.svctype", FT_UINT16, BASE_HEX, VALS(ns_svc_type_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_mfu_reqflag,
			{ "Request Flags", "nstrace.mep.mfu.reqflag", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_adv_ip,
			{ "Advertise Local IP Address",	"nstrace.mep.adv.ip", FT_IPv4, BASE_NONE,  NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_ldns_ip,
			{ "LDNS IP Address", "nstrace.mep.ldns.ip", FT_IPv4, BASE_NONE,  NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsmep_site_persistence,
			{ "Site Persistence", "nstrace.mep.mfu.sitepers", FT_UINT16, BASE_HEX, VALS(value_site_persistence), 0x0,
			NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_nsmep,
		&ett_nsmep_mfu,
		&ett_nsmep_nwu,
	};

	proto_ns_mep = proto_register_protocol("NetScaler Metric Exchange Protocol", "NetScaler MEP", "nstrace.mep");
	proto_register_field_array(proto_ns_mep, hf_nsmep, array_length(hf_nsmep));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ns_mep(void)
{
	dissector_handle_t nsmep_handle;

	nsrpc_handle = find_dissector_add_dependency("nsrpc", proto_ns_mep);

	nsmep_handle = create_dissector_handle(dissect_ns_mep, proto_ns_mep);
	dissector_add_for_decode_as("tcp.port", nsmep_handle);
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
