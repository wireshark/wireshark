/* nettrace_3gpp_32_423.c
 *
 * Decoder for 3GPP TS 32.423 file format for the Wiretap library.
 * The main purpose is to have Wireshark decode raw message content (<rawMsg> tag).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=2010
 */

#include "config.h"
#define WS_LOG_DOMAIN "nettrace_3gpp"
#include "nettrace_3gpp_32_423.h"

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtap_module.h"
#include "file_wrappers.h"

#include <wsutil/exported_pdu_tlvs.h>
#include <wsutil/buffer.h>
#include <wsutil/pint.h>
#include "wsutil/tempfile.h"
#include "wsutil/os_version_info.h"
#include "wsutil/str_util.h"
#include <wsutil/inet_addr.h>
#include <wsutil/ws_assert.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <glib.h>

/* String constants sought in the XML data.
 * Written as strings instead of lists of chars for readability.
 * Use the CLEN() macro to get the length of the constant without counting
 * the null byte at the end.
 */
#define CLEN(x) (sizeof(x)-1)
static const unsigned char c_s_trace_rec_session[] = "<traceRecSession";
static const char c_s_msg[] = "<msg";
static const unsigned char c_e_msg[] = "</msg>";

/* Protocol mapping table: maps (protocol, function, name) from the XML trace
 * to Wireshark dissector names or dissector table entries.
 *
 * Match rules:
 *   - trace_protocol is compared case-insensitively against rawMsg protocol=""
 *   - trace_function (if non-NULL) must match msg function="" (case-insensitive)
 *   - trace_name (if non-NULL) must match msg name="" (case-insensitive)
 *   - First matching entry wins
 *
 * Dispatch modes:
 *   - If dissector_table is NULL, dissector_name is used directly via EXP_PDU_TAG_DISSECTOR_NAME
 *   - If dissector_table is non-NULL, table-based dispatch is used
 */
typedef struct {
	const char *trace_protocol;    /* rawMsg protocol="" value (case-insensitive match) */
	const char *trace_function;    /* msg function="" value, or NULL for any */
	const char *trace_name;        /* msg name="" value, or NULL for any */
	const char *dissector_name;    /* Wireshark dissector name (NULL if using table) */
	const char *dissector_table;   /* dissector table name (NULL if using dissector_name) */
	int         dissector_table_val; /* dissector table numeric value */
	const char *col_protocol;      /* protocol column override string, or NULL */
} protocol_mapping_t;

static const protocol_mapping_t protocol_map[] = {
	/* GTPv2 */
	{ "gtpv2-c",   NULL,  NULL,            "gtpv2",        NULL, 0, NULL },
	{ "gtpv2",     NULL,  NULL,            "gtpv2",        NULL, 0, NULL },

	/* NAS: dispatch depends on function (interface) */
	{ "nas",       "s1",  NULL,            "nas-eps_plain", NULL, 0, NULL },
	{ "nas",       "n1",  NULL,            "nas-5gs",      NULL, 0, NULL },

	/* GSM MAP: dispatch depends on message name */
	{ "map",       NULL,  "sai_request",   NULL, "gsm_map.v3.arg.opcode", 56, "GSM MAP" },
	{ "map",       NULL,  "sai_response",  NULL, "gsm_map.v3.res.opcode", 56, "GSM MAP" },

	/* 5GC / NG-RAN protocols */
	{ "ngap",      NULL,  NULL,            "ngap",         NULL, 0, NULL },
	{ "s1ap",      NULL,  NULL,            "s1ap",         NULL, 0, NULL },
	{ "x2ap",      NULL,  NULL,            "x2ap",         NULL, 0, NULL },
	{ "xnap",      NULL,  NULL,            "xnap",         NULL, 0, NULL },
	{ "f1ap",      NULL,  NULL,            "f1ap",         NULL, 0, NULL },
	{ "e1ap",      NULL,  NULL,            "e1ap",         NULL, 0, NULL },
	{ "pfcp",      NULL,  NULL,            "pfcp",         NULL, 0, NULL },

	/* Legacy UMTS protocols */
	{ "ranap",     NULL,  NULL,            "ranap",        NULL, 0, NULL },
	{ "nbap",      NULL,  NULL,            "nbap",         NULL, 0, NULL },
	{ "rnsap",     NULL,  NULL,            "rnsap",        NULL, 0, NULL },
	{ "rrc",       NULL,  NULL,            "rrc",          NULL, 0, NULL },

	/* Diameter (S6a, S13, etc.) */
	{ "diameter",  NULL,  NULL,            "diameter",     NULL, 0, NULL },

	/* GTP-C v1 */
	{ "gtp",       NULL,  NULL,            "gtp",          NULL, 0, NULL },

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL, 0, NULL }
};

/* Look up a protocol mapping entry.
 * Returns pointer to matching entry, or NULL if no match found.
 */
static const protocol_mapping_t *
nettrace_lookup_protocol(const char *protocol, const char *function, const char *name)
{
	for (const protocol_mapping_t *entry = protocol_map; entry->trace_protocol != NULL; entry++) {
		if (g_ascii_strcasecmp(protocol, entry->trace_protocol) != 0)
			continue;
		if (entry->trace_function != NULL &&
		    g_ascii_strcasecmp(function, entry->trace_function) != 0)
			continue;
		if (entry->trace_name != NULL &&
		    g_ascii_strcasecmp(name, entry->trace_name) != 0)
			continue;
		return entry;
	}
	return NULL;
}


#define RINGBUFFER_START_SIZE INT_MAX
#define RINGBUFFER_CHUNK_SIZE 1024

#define MAX_FUNCTION_LEN 64
#define MAX_NAME_LEN 128
#define MAX_PROTO_LEN 32
#define MAX_DTBL_LEN 64

/* We expect to find all the info we need to tell if this file is ours
 * within this many bytes. Must include the beginTime attribute.
 */
#define MAGIC_BUF_SIZE 1024

/* Per-packet session context recorded during sequential read for seek_read access.
 * The session_time and UE ID are derived from the most recent <traceRecSession>
 * preceding each <msg> and cannot be reliably recovered during random seek_read
 * since only the <msg>...</msg> block is re-read.
 */
typedef struct {
	nstime_t session_time;
	char *ue_id_type;
	char *ue_id_value;
} nettrace_packet_ctx_t;

typedef struct nettrace_3gpp_32_423_file_info {
	GByteArray *buffer;		// holds current chunk of file
	int64_t start_offset;		// where in the file the start of the buffer points
	nstime_t start_time;		// from <traceCollec beginTime=""> attribute
	nstime_t session_time;		// from most recent <traceRecSession stime=""> attribute
	char *session_ue_id_type;	// from most recent <ue idType="..."/>
	char *session_ue_id_value;	// from most recent <ue idValue="..."/>
	GHashTable *offset_pkt_ctx;	// maps data_offset (int64_t*) -> nettrace_packet_ctx_t*
} nettrace_3gpp_32_423_file_info_t;

typedef struct exported_pdu_info {
	uint32_t presence_flags;
	uint8_t src_ip[16];
	uint32_t ptype; /* Based on epan/address.h port_type valid for both src and dst*/
	uint32_t src_port;
	uint8_t dst_ip[16];
	uint32_t dst_port;
	char* proto_col_str;
} exported_pdu_info_t;

/* flags for exported_pdu_info.presence_flags */
#define EXP_PDU_TAG_IP_SRC_BIT		0x001
#define EXP_PDU_TAG_IP_DST_BIT		0x002
#define EXP_PDU_TAG_SRC_PORT_BIT	0x004
#define EXP_PDU_TAG_DST_PORT_BIT	0x008
#define EXP_PDU_TAG_ORIG_FNO_BIT	0x010
#define EXP_PDU_TAG_SS7_OPC_BIT		0x020
#define EXP_PDU_TAG_SS7_DPC_BIT		0x040
#define EXP_PDU_TAG_IP6_SRC_BIT		0x080
#define EXP_PDU_TAG_IP6_DST_BIT		0x100
#define EXP_PDU_TAG_DVBCI_EVT_BIT	0x0100
#define EXP_PDU_TAG_COL_PROT_BIT	0x0200


static int nettrace_3gpp_32_423_file_type_subtype = -1;

void register_nettrace_3gpp_32_423(void);

/* Hash table helper for per-packet session context storage */
static void
nettrace_packet_ctx_free(void *data)
{
	nettrace_packet_ctx_t *ctx = (nettrace_packet_ctx_t *)data;
	g_free(ctx->ue_id_type);
	g_free(ctx->ue_id_value);
	g_free(ctx);
}

/* Parse a string IPv4 or IPv6 address into bytes for exported_pdu_info.
 * Also parses the port pairs and transport layer type.
 */
static void
nettrace_parse_address(char* curr_pos, bool is_src_addr, exported_pdu_info_t *exported_pdu_info)
{
	unsigned port=0;
	ws_in6_addr ip6_addr;
	uint32_t ip4_addr;
	char *err; //for strtol function

	GMatchInfo *match_info;
	/* Compiled once, lives for process lifetime (intentional, not a leak) */
	static GRegex *regex = NULL;
	char *matched_ipaddress = NULL;
	char *matched_port = NULL;
	char *matched_transport = NULL;

	/* Example from one trace, unsure if it's generic...
	 * {address == 192.168.73.1, port == 5062, transport == Udp}
	 * {address == [2001:1b70:8294:210a::78], port...
	 * {address == 2001:1B70:8294:210A::90, port...
	 *  Address=198.142.204.199,Port=2123
	 */

	if (g_once_init_enter(&regex)) {
		GRegex *re = g_regex_new (
			"^.*address\\s*=*\\s*" //curr_pos will begin with address
			"\\[?(?P<ipaddress>(?:" //store ipv4 or ipv6 address in named group "ipaddress"
				"(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" //match an IPv4 address
				"|" // or
				"(?:[0-9a-f:]*)))\\]?" //match an IPv6 address.
			"(?:.*port\\s*=*\\s*(?P<port>\\d{1,5}))?" //match a port store it in named group "port"
			"(?:.*transport\\s*=*\\s*(?P<transport>\\w+))?", //match a transport store it in named group "transport"
			G_REGEX_CASELESS | G_REGEX_FIRSTLINE, 0, NULL);
		g_once_init_leave(&regex, re);
	 }

	/* curr_pos pointing to first char of "address" */
	g_regex_match (regex, curr_pos, 0, &match_info);

	if (g_match_info_matches (match_info)) {
		matched_ipaddress = g_match_info_fetch_named(match_info, "ipaddress"); //will be empty string if no ipv4 or ipv6
		matched_port = g_match_info_fetch_named(match_info, "port"); //will be empty string if port not in trace
		if (matched_port != NULL) {
			port = (unsigned) strtol(matched_port, &err, 10);
			g_free(matched_port);
		}
		matched_transport = g_match_info_fetch_named(match_info, "transport"); //will be empty string if transport not in trace
	} else {
		g_match_info_free(match_info);
		return;
	}

	g_match_info_free(match_info);
	if (ws_inet_pton6(matched_ipaddress, &ip6_addr)) {
		if (is_src_addr) {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP6_SRC_BIT;
			memcpy(exported_pdu_info->src_ip, ip6_addr.bytes, EXP_PDU_TAG_IPV6_LEN);
		}
		else {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP6_DST_BIT;
			memcpy(exported_pdu_info->dst_ip, ip6_addr.bytes, EXP_PDU_TAG_IPV6_LEN);
		}
	}
	else if (ws_inet_pton4(matched_ipaddress, &ip4_addr)) {
		if (is_src_addr) {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP_SRC_BIT;
			memcpy(exported_pdu_info->src_ip, &ip4_addr, EXP_PDU_TAG_IPV4_LEN);
		}
		else {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP_DST_BIT;
			memcpy(exported_pdu_info->dst_ip, &ip4_addr, EXP_PDU_TAG_IPV4_LEN);
		}
	}

	if (port > 0) {
		/* Only add port_type once */
		if (exported_pdu_info->ptype == EXP_PDU_PT_NONE) {
			static const struct {
				const char *name;
				unsigned    len;
				uint32_t    ptype;
			} transport_map[] = {
				{ "udp",  3, EXP_PDU_PT_UDP },
				{ "tcp",  3, EXP_PDU_PT_TCP },
				{ "sctp", 4, EXP_PDU_PT_SCTP },
			};
			/* Default to TCP so that ports are shown in column */
			exported_pdu_info->ptype = EXP_PDU_PT_TCP;
			for (size_t i = 0; i < G_N_ELEMENTS(transport_map); i++) {
				if (g_ascii_strncasecmp(matched_transport, transport_map[i].name, transport_map[i].len) == 0) {
					exported_pdu_info->ptype = transport_map[i].ptype;
					break;
				}
			}
		}
		if (is_src_addr) {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_SRC_PORT_BIT;
			exported_pdu_info->src_port = port;
		}
		else {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_DST_PORT_BIT;
			exported_pdu_info->dst_port = port;
		}
	}
	g_free(matched_ipaddress);
	g_free(matched_transport);
}

/* Parse the attributes of a <msg> element: function, name, changeTime.
 * Returns false on error (sets err/err_info), true on success.
 */
static bool
nettrace_parse_msg_attributes(xmlNodePtr msg_element,
                              const nettrace_3gpp_32_423_file_info_t *file_info,
                              wtap_rec *rec,
                              char *function_str, size_t function_str_size,
                              char *name_str, size_t name_str_size,
                              int *err, char **err_info)
{
	function_str[0] = '\0';
	name_str[0] = '\0';

	for (xmlAttrPtr attr = msg_element->properties; attr; attr = attr->next) {
		if (xmlStrcmp(attr->name, (const xmlChar*)"function") == 0) {
			xmlChar* str = xmlNodeListGetString(msg_element->doc, attr->children, 1);
			if (str != NULL) {
				size_t len = strlen((const char*)str);
				if (len > function_str_size - 1) {
					*err = WTAP_ERR_BAD_FILE;
					*err_info = ws_strdup_printf("nettrace_3gpp_32_423: function_str_len > %zu", function_str_size - 1);
					xmlFree(str);
					return false;
				}
				(void)g_strlcpy(function_str, (const char*)str, len + 1);
				ascii_strdown_inplace(function_str);
				xmlFree(str);
			}
		}
		else if (xmlStrcmp(attr->name, (const xmlChar*)"name") == 0) {
			xmlChar* str = xmlNodeListGetString(msg_element->doc, attr->children, 1);
			if (str != NULL) {
				size_t len = strlen((const char*)str);
				if (len > name_str_size - 1) {
					*err = WTAP_ERR_BAD_FILE;
					*err_info = ws_strdup_printf("nettrace_3gpp_32_423: name_str_len > %zu", name_str_size - 1);
					xmlFree(str);
					return false;
				}
				(void)g_strlcpy(name_str, (const char*)str, len + 1);
				ascii_strdown_inplace(name_str);
				xmlFree(str);
			}
		}
		else if (xmlStrcmp(attr->name, (const xmlChar*)"changeTime") == 0) {
			nstime_t start_time;
			/* Utilize stime from traceRecSession (if exist) otherwise use file info start time */
			if (!nstime_is_unset(&(file_info->session_time))) {
				start_time = file_info->session_time;
			} else if (!nstime_is_unset(&(file_info->start_time))) {
				start_time = file_info->start_time;
			} else {
				continue;
			}

			/* Check if we have a time stamp "changeTime"
			 * expressed in number of seconds and milliseconds (nbsec.ms).
			 * Only needed if we have a "beginTime" for this file.
			 */
			int scan_found;
			unsigned second = 0, ms = 0;

			xmlChar* str_time = xmlNodeListGetString(msg_element->doc, attr->children, 1);
			if (str_time != NULL) {
				scan_found = sscanf((const char*)str_time, "%u.%u", &second, &ms);
				if (scan_found == 2) {
					unsigned start_ms = start_time.nsecs / 1000000;
					unsigned elapsed_ms = start_ms + ms;
					/* Carry overflow milliseconds into seconds */
					second += elapsed_ms / 1000;
					elapsed_ms = elapsed_ms % 1000;
					rec->presence_flags |= WTAP_HAS_TS;
					rec->ts.secs = start_time.secs + second;
					rec->ts.nsecs = (elapsed_ms * 1000000);
				}
				/* Some traces sets "No value" when traceRecSession stime has been used,
				 * this is wrong as according to spec changeTime is a float...
				 * But let's use the values we have from start_time
				 */
				else {
					rec->presence_flags |= WTAP_HAS_TS;
					rec->ts.secs = start_time.secs;
					rec->ts.nsecs = start_time.nsecs;
				}
				xmlFree(str_time);
			}
		}
	}
	return true;
}

/* Build the exported PDU buffer: write EPDU tags (dissector, addresses, ports,
 * UE ID) then decode hex raw content into binary packet data.
 * Returns false on error, true on success.
 */
static bool
nettrace_build_epdu(wtap_rec *rec,
                    const nettrace_3gpp_32_423_file_info_t *file_info,
                    const char *proto_name_str,
                    bool use_proto_table,
                    const char *dissector_table_str,
                    int dissector_table_val,
                    exported_pdu_info_t *exported_pdu_info,
                    const exported_pdu_info_t *proxy_exported_pdu_info,
                    const xmlChar *raw_content,
                    int *err, char **err_info)
{
	/* Fill packet buff */
	ws_buffer_clean(&rec->data);
	if (use_proto_table == false) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_DISSECTOR_NAME, (const uint8_t*)proto_name_str, (uint16_t)strlen(proto_name_str));
	}
	else {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_DISSECTOR_TABLE_NAME, (const uint8_t*)dissector_table_str, (uint16_t)strlen(dissector_table_str));
		wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL, dissector_table_val);
	}

	if (exported_pdu_info->presence_flags & EXP_PDU_TAG_COL_PROT_BIT) {
		if (exported_pdu_info->proto_col_str) {
			wtap_buffer_append_epdu_string(&rec->data, EXP_PDU_TAG_COL_PROT_TEXT, exported_pdu_info->proto_col_str);
			g_free(exported_pdu_info->proto_col_str);
			exported_pdu_info->proto_col_str = NULL;
		}
	}

	if (exported_pdu_info->presence_flags & EXP_PDU_TAG_IP_SRC_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_SRC, exported_pdu_info->src_ip, EXP_PDU_TAG_IPV4_LEN);
	}
	else if (proxy_exported_pdu_info->presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_SRC, proxy_exported_pdu_info->dst_ip, EXP_PDU_TAG_IPV4_LEN);
	}
	if (exported_pdu_info->presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_DST, exported_pdu_info->dst_ip, EXP_PDU_TAG_IPV4_LEN);
	}
	else if (proxy_exported_pdu_info->presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_DST, proxy_exported_pdu_info->dst_ip, EXP_PDU_TAG_IPV4_LEN);
	}

	if (exported_pdu_info->presence_flags & EXP_PDU_TAG_IP6_SRC_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_SRC, exported_pdu_info->src_ip, EXP_PDU_TAG_IPV6_LEN);
	}
	else if (proxy_exported_pdu_info->presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_SRC, proxy_exported_pdu_info->dst_ip, EXP_PDU_TAG_IPV6_LEN);
	}
	if (exported_pdu_info->presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_DST, exported_pdu_info->dst_ip, EXP_PDU_TAG_IPV6_LEN);
	}
	else if (proxy_exported_pdu_info->presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
		wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_DST, proxy_exported_pdu_info->dst_ip, EXP_PDU_TAG_IPV6_LEN);
	}

	if (exported_pdu_info->presence_flags & (EXP_PDU_TAG_SRC_PORT_BIT | EXP_PDU_TAG_DST_PORT_BIT)) {
		wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_PORT_TYPE, exported_pdu_info->ptype);
	}
	else if (proxy_exported_pdu_info->presence_flags & (EXP_PDU_TAG_SRC_PORT_BIT | EXP_PDU_TAG_DST_PORT_BIT)) {
		wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_PORT_TYPE, proxy_exported_pdu_info->ptype);
	}
	if (exported_pdu_info->presence_flags & EXP_PDU_TAG_SRC_PORT_BIT) {
		wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_SRC_PORT, exported_pdu_info->src_port);
	}
	else if (proxy_exported_pdu_info->presence_flags & EXP_PDU_TAG_SRC_PORT_BIT) {
		wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_SRC_PORT, proxy_exported_pdu_info->src_port);
	}
	if (exported_pdu_info->presence_flags & EXP_PDU_TAG_DST_PORT_BIT) {
		wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_DST_PORT, exported_pdu_info->dst_port);
	}
	else if (proxy_exported_pdu_info->presence_flags & EXP_PDU_TAG_DST_PORT_BIT) {
		wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_DST_PORT, proxy_exported_pdu_info->dst_port);
	}

	/* Add UE identity if available */
	if (file_info->session_ue_id_type && file_info->session_ue_id_value) {
		size_t type_len = strlen(file_info->session_ue_id_type) + 1;
		size_t val_len = strlen(file_info->session_ue_id_value) + 1;
		uint8_t ue_id_buf[128];
		if (type_len + val_len <= sizeof(ue_id_buf)) {
			memcpy(ue_id_buf, file_info->session_ue_id_type, type_len);
			memcpy(ue_id_buf + type_len, file_info->session_ue_id_value, val_len);
			wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_3GPP_UE_ID, ue_id_buf, (uint16_t)(type_len + val_len));
		}
	}

	/* Add end of options */
	size_t raw_data_len = strlen((const char*)raw_content);
	int exp_pdu_tags_len = wtap_buffer_append_epdu_end(&rec->data);

	/* Convert the hex raw msg data to binary and write to the packet buf */
	size_t pkt_data_len = raw_data_len / 2;
	ws_buffer_assure_space(&rec->data, pkt_data_len);
	uint8_t* packet_buf = ws_buffer_end_ptr(&rec->data);

	const char* curr_pos = (const char*)raw_content;
	for (size_t i = 0; i < pkt_data_len; i++) {
		char chr1, chr2;
		int val1, val2;

		chr1 = *curr_pos++;
		chr2 = *curr_pos++;
		val1 = g_ascii_xdigit_value(chr1);
		val2 = g_ascii_xdigit_value(chr2);
		if ((val1 != -1) && (val2 != -1)) {
			*packet_buf++ = ((uint8_t)val1 * 16) + val2;
		}
		else {
			*err_info = ws_strdup_printf("nettrace_3gpp_32_423: Could not parse hex data, bufsize %zu index %zu %c%c",
				(pkt_data_len + exp_pdu_tags_len),
				i, chr1, chr2);
			*err = WTAP_ERR_BAD_FILE;
			return false;
		}
	}
	ws_buffer_increase_length(&rec->data, pkt_data_len);

	rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
	rec->rec_header.packet_header.len = (uint32_t)ws_buffer_length(&rec->data);

	return true;
}

/* Parse a <msg ...><rawMsg ...>XXXX</rawMsg></msg> into packet data. */
static bool
nettrace_msg_to_packet(wtap* wth, wtap_rec* rec, xmlNodePtr root_element, int* err, char** err_info)
{
	nettrace_3gpp_32_423_file_info_t* file_info = (nettrace_3gpp_32_423_file_info_t*)wth->priv;
	exported_pdu_info_t  exported_pdu_info = { 0 };
	exported_pdu_info_t  proxy_exported_pdu_info = { 0 };
	char function_str[MAX_FUNCTION_LEN + 1];
	char name_str[MAX_NAME_LEN + 1];
	char proto_name_str[MAX_PROTO_LEN + 1];
	char dissector_table_str[MAX_DTBL_LEN + 1];
	int dissector_table_val = 0;
	bool found_raw = false;
	bool use_proto_table = false;
	bool status = true;

	/* Sanity check */
	if (xmlStrcmp(root_element->name, (const xmlChar*)"msg") != 0) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup("nettrace_3gpp_32_423: Did not start with \"<msg\"");
		status = false;
		goto end;
	}

	if (root_element->children == NULL) {
		/* There is no rawmsg here. */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("Had \"<msg />\" with no \"<rawMsg>\"");
		status = false;
		goto end;
	}

	wtap_setup_packet_rec(rec, wth->file_encap);
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = 0; /* start out assuming no special features */
	rec->ts.secs = 0;
	rec->ts.nsecs = 0;

	/* Clear for each iteration */
	exported_pdu_info.presence_flags = 0;
	exported_pdu_info.ptype = EXP_PDU_PT_NONE;
	proxy_exported_pdu_info.presence_flags = 0;
	proxy_exported_pdu_info.ptype = EXP_PDU_PT_NONE;

	/* Extract msg attributes: function, name, changeTime */
	if (!nettrace_parse_msg_attributes(root_element, file_info, rec,
	                                   function_str, sizeof(function_str),
	                                   name_str, sizeof(name_str),
	                                   err, err_info)) {
		status = false;
		goto end;
	}

	/* Walk child elements: initiator, target, proxy, rawMsg */
	proto_name_str[0] = '\0';
	dissector_table_str[0] = '\0';
	for (xmlNodePtr cur = root_element->children; cur != NULL; cur = cur->next) {
		if (cur->type == XML_ELEMENT_NODE) {
			if (xmlStrcmp(cur->name, (const xmlChar*)"initiator") == 0) {
				xmlChar* initiator_content = xmlNodeGetContent(cur);

				nettrace_parse_address((char*)initiator_content, true/* SRC */, &exported_pdu_info);
				xmlFree(initiator_content);
			}
			else if (xmlStrcmp(cur->name, (const xmlChar*)"target") == 0) {
				xmlChar* target_content = xmlNodeGetContent(cur);

				nettrace_parse_address((char*)target_content, false/* DST */, &exported_pdu_info);
				xmlFree(target_content);
			}
			else if (xmlStrcmp(cur->name, (const xmlChar*)"proxy") == 0) {
				xmlChar* proxy_content = xmlNodeGetContent(cur);

				/* proxy info will be save in destination ip/port */
				nettrace_parse_address((char*)proxy_content, false/* SRC */, &proxy_exported_pdu_info);
				xmlFree(proxy_content);
			}
			else if (xmlStrcmp(cur->name, (const xmlChar*)"rawMsg") == 0) {
				bool found_protocol = false;
				xmlChar* raw_content;
				xmlNodePtr raw_node = cur;

				for (xmlAttrPtr attr = raw_node->properties; attr; attr = attr->next) {
					if (xmlStrcmp(attr->name, (const xmlChar*)"protocol") == 0) {

						xmlChar* str = xmlNodeListGetString(raw_node->doc, attr->children, 1);
						if (str != NULL) {
							size_t proto_str_len = strlen((char*)str);
							if (proto_str_len > MAX_PROTO_LEN) {
								xmlFree(str);
								status = false;
								goto end;
							}
							(void)g_strlcpy(proto_name_str, (const char*)str, (size_t)proto_str_len + 1);
							ascii_strdown_inplace(proto_name_str);
							found_protocol = true;
						}
					}
				}

				if (!found_protocol) {
					*err = WTAP_ERR_BAD_FILE;
					*err_info = ws_strdup("nettrace_3gpp_32_423: Did not find \"protocol\"");
					status = false;
					goto end;
				}

				/* Look up protocol mapping from table */
				const protocol_mapping_t *mapping = nettrace_lookup_protocol(proto_name_str, function_str, name_str);
				if (mapping == NULL) {
					/* No mapping found — pass through as-is (best-effort dissection) */
				}
				else if (mapping->dissector_table != NULL) {
					/* Table-based dispatch */
					use_proto_table = true;
					(void)g_strlcpy(dissector_table_str, mapping->dissector_table, sizeof(dissector_table_str));
					dissector_table_val = mapping->dissector_table_val;
					if (mapping->col_protocol != NULL) {
						exported_pdu_info.proto_col_str = g_strdup(mapping->col_protocol);
						exported_pdu_info.presence_flags |= EXP_PDU_TAG_COL_PROT_BIT;
					}
				}
				else {
					/* Direct dissector name dispatch */
					(void)g_strlcpy(proto_name_str, mapping->dissector_name, sizeof(proto_name_str));
					if (mapping->col_protocol != NULL) {
						exported_pdu_info.proto_col_str = g_strdup(mapping->col_protocol);
						exported_pdu_info.presence_flags |= EXP_PDU_TAG_COL_PROT_BIT;
					}
				}

				raw_content = xmlNodeGetContent(raw_node);
				if ((raw_content == NULL) || (raw_content[0] == '\0')) {
					xmlFree(raw_content);
					*err = WTAP_ERR_BAD_FILE;
					*err_info = ws_strdup("nettrace_3gpp_32_423: No raw data bytes");
					status = false;
					goto end;
				}

				/* Build the exported PDU: tags + hex-decoded payload */
				if (!nettrace_build_epdu(rec, file_info, proto_name_str,
				                         use_proto_table, dissector_table_str,
				                         dissector_table_val,
				                         &exported_pdu_info, &proxy_exported_pdu_info,
				                         raw_content, err, err_info)) {
					xmlFree(raw_content);
					status = false;
					goto end;
				}

				found_raw = true;
				xmlFree(raw_content);
			}
		}
	}

	if (!found_raw) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup("nettrace_3gpp_32_423: Did not find \"<rawMsg\"");
		status = false;
		goto end;
	}
end:
	return status;
}

/* Read from fh and store into buffer, until buffer contains needle.
 * Returns location of needle once found, or NULL if it's never found
 * (due to either EOF or read error).
 */
static uint8_t *
read_until(GByteArray *buffer, const unsigned char *needle, FILE_T fh, int *err, char **err_info)
{
	uint8_t read_buffer[RINGBUFFER_CHUNK_SIZE];
	uint8_t *found_it;
	int bytes_read = 0;

	while (NULL == (found_it = (uint8_t*)g_strstr_len((const char*)buffer->data, buffer->len, (const char*)needle))) {
		bytes_read = file_read(read_buffer, RINGBUFFER_CHUNK_SIZE, fh);
		if (bytes_read < 0) {
			*err = file_error(fh, err_info);
			break;
		}
		if (bytes_read == 0) {
			break;
		}
		g_byte_array_append(buffer, read_buffer, bytes_read);
	}
	return found_it;
}

/* Parse a <traceRecSession ...> tag and extract the stime attribute
 * into file_info->session_time. Also look for <ue idType="..." idValue="..."/>
 * within the session block.
 *
 * session_start points into the buffer at the '<' of <traceRecSession.
 * session_len is the number of bytes available from session_start.
 */
static void
nettrace_parse_session_tag(const char *session_start, size_t session_len, nettrace_3gpp_32_423_file_info_t *file_info)
{
	xmlDocPtr doc;
	xmlNodePtr root_element;

	/* Find the end of the <traceRecSession ...> opening tag.
	 * We need at least the opening tag to extract attributes.
	 * Wrap it as a self-closing element so libxml2 can parse it,
	 * and also include any <ue .../> child element if present.
	 */
	const char *tag_end = (const char*)memchr(session_start, '>', session_len);
	if (tag_end == NULL)
		return;

	/* Check if there's a <ue .../> element before the first <msg.
	 * Build a parseable fragment: <traceRecSession ...><ue .../></traceRecSession>
	 * or just <traceRecSession .../> if no children needed.
	 */
	const char *ue_start = g_strstr_len(session_start, (unsigned)session_len, "<ue ");
	const char *msg_start = g_strstr_len(session_start, (unsigned)session_len, "<msg");

	/* Determine the end of what we want to parse */
	const char *fragment_end;
	if (ue_start && (!msg_start || ue_start < msg_start)) {
		/* Include the <ue .../> element */
		const char *ue_end = (const char*)memchr(ue_start, '>', session_len - (size_t)(ue_start - session_start));
		if (ue_end)
			fragment_end = ue_end + 1;
		else
			fragment_end = tag_end + 1;
	} else {
		fragment_end = tag_end + 1;
	}

	/* Build a complete XML fragment we can parse */
	size_t frag_len = (size_t)(fragment_end - session_start);
	GString *xml_buf = g_string_sized_new(frag_len + 32);
	g_string_append_len(xml_buf, session_start, (gssize)frag_len);
	g_string_append(xml_buf, "</traceRecSession>");

	doc = xmlParseMemory(xml_buf->str, (int)xml_buf->len);
	g_string_free(xml_buf, TRUE);
	if (doc == NULL)
		return;

	root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL) {
		xmlFreeDoc(doc);
		return;
	}

	/* Extract stime attribute from <traceRecSession stime="..."> */
	for (xmlAttrPtr attr = root_element->properties; attr; attr = attr->next) {
		if (xmlStrcmp(attr->name, (const xmlChar*)"stime") == 0) {
			xmlChar* str = xmlNodeListGetString(root_element->doc, attr->children, 1);
			if (str != NULL) {
				iso8601_to_nstime(&file_info->session_time, (const char*)str, ISO8601_DATETIME);
				xmlFree(str);
			}
		}
	}

	/* Look for <ue idType="..." idValue="..."/> child element */
	for (xmlNodePtr cur = root_element->children; cur != NULL; cur = cur->next) {
		if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"ue") == 0) {
			xmlChar *id_type = NULL;
			xmlChar *id_value = NULL;
			for (xmlAttrPtr attr = cur->properties; attr; attr = attr->next) {
				if (xmlStrcmp(attr->name, (const xmlChar*)"idType") == 0) {
					id_type = xmlNodeListGetString(cur->doc, attr->children, 1);
				}
				else if (xmlStrcmp(attr->name, (const xmlChar*)"idValue") == 0) {
					id_value = xmlNodeListGetString(cur->doc, attr->children, 1);
				}
			}
			if (id_type && id_value) {
				g_free(file_info->session_ue_id_type);
				g_free(file_info->session_ue_id_value);
				file_info->session_ue_id_type = g_strdup((const char*)id_type);
				file_info->session_ue_id_value = g_strdup((const char*)id_value);
			}
			xmlFree(id_type);
			xmlFree(id_value);
			break;
		}
	}

	xmlFreeDoc(doc);
}

/* Parse a <msg>...</msg> block using XML and produce a packet */
static bool
nettrace_parse_msg(wtap *wth, wtap_rec *rec, uint8_t *msg_start, size_t msg_len, int *err, char **err_info)
{
	xmlDocPtr doc;
	xmlNodePtr root_element;
	bool status = false;

	doc = xmlParseMemory((const char*)msg_start, (int)msg_len);
	if (doc == NULL) {
		return false;
	}

	root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL) {
		xmlFreeDoc(doc);
		return false;
	}

	status = nettrace_msg_to_packet(wth, rec, root_element, err, err_info);

	xmlFreeDoc(doc);
	return status;
}

/* Search for a <traceRecSession> tag in the given buffer and parse it if found.
 * Updates file_info->session_time and UE identity fields.
 */
static void
nettrace_update_session_from_buffer(const uint8_t *buf, size_t buf_len, nettrace_3gpp_32_423_file_info_t *file_info)
{
	char *session_tag = g_strstr_len((const char*)buf, (unsigned)buf_len, (const char*)c_s_trace_rec_session);
	if (session_tag) {
		size_t session_avail = buf_len - (size_t)(session_tag - (const char*)buf);
		nettrace_parse_session_tag(session_tag, session_avail, file_info);
	}
}

/* Find a complete packet, parse and return it to wiretap.
 * Set as the subtype_read function in the file_open function below.
 */
static bool
nettrace_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset)
{
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;
	uint8_t *buf_start;
	uint8_t *msg_start, *msg_end;
	unsigned msg_offset = 0;
	size_t msg_len = 0;
	bool status = false;

	/* Make sure we have a start and end of msg in our buffer -- end first */
	msg_end = read_until(file_info->buffer, c_e_msg, wth->fh, err, err_info);
	if (msg_end == NULL) {
		goto end;
	}

	buf_start = file_info->buffer->data;

	/* Check if there's a <traceRecSession before this <msg and update session_time */
	nettrace_update_session_from_buffer(buf_start, (size_t)(msg_end - buf_start), file_info);

	/* Now search backwards for the msg start */
	msg_start = (uint8_t*)g_strrstr_len((const char*)buf_start, msg_end - buf_start, c_s_msg);
	if (msg_start == NULL || msg_start > msg_end) {
		*err_info = ws_strdup_printf("nettrace_3gpp_32_423: Found \"%s\" without matching \"%s\"", c_e_msg, c_s_msg);
		*err = WTAP_ERR_BAD_FILE;
		goto end;
	}

	/* We know we have a msg, what's its offset from the buffer start? */
	msg_offset = (unsigned)(msg_start - buf_start);
	msg_end += CLEN(c_e_msg);
	msg_len = (unsigned)(msg_end - msg_start);

	/* Tell Wireshark to put us at the start of the "<msg" for seek_read later */
	*data_offset = file_info->start_offset + msg_offset;

	/* Save the current session context for this packet so seek_read can retrieve it */
	{
		int64_t *key = g_new(int64_t, 1);
		*key = *data_offset;
		nettrace_packet_ctx_t *ctx = g_new0(nettrace_packet_ctx_t, 1);
		ctx->session_time = file_info->session_time;
		if (file_info->session_ue_id_type)
			ctx->ue_id_type = g_strdup(file_info->session_ue_id_type);
		if (file_info->session_ue_id_value)
			ctx->ue_id_value = g_strdup(file_info->session_ue_id_value);
		g_hash_table_insert(file_info->offset_pkt_ctx, key, ctx);
	}

	/* pass all of <msg....</msg> to nettrace_parse_msg() */
	status = nettrace_parse_msg(wth, rec, msg_start, msg_len, err, err_info);

	/* Finally, shift our buffer to the end of this message to get ready for the next one. */
	msg_len = msg_end - file_info->buffer->data;
	while (G_UNLIKELY(msg_len > UINT_MAX)) {
		g_byte_array_remove_range(file_info->buffer, 0, UINT_MAX);
		msg_len -= UINT_MAX;
	}
	g_byte_array_remove_range(file_info->buffer, 0, (unsigned)msg_len);
	file_info->start_offset += msg_len;

end:
	if (status == false) {
		/* There's no more to read. Empty out the buffer */
		g_byte_array_set_size(file_info->buffer, 0);
	}

	return status;
}

/* Seek to the complete packet at the offset, parse and return it to wiretap.
 * Set as the subtype_seek_read function in the file_open function below.
 */
static bool
nettrace_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, int *err, char **err_info)
{
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;
	bool status = false;
	uint8_t *msg_end;
	unsigned msg_len = 0;

	/* Restore the per-packet session context that was recorded during sequential read */
	nettrace_packet_ctx_t *ctx = (nettrace_packet_ctx_t *)g_hash_table_lookup(
		file_info->offset_pkt_ctx, &seek_off);
	if (ctx) {
		file_info->session_time = ctx->session_time;
		g_free(file_info->session_ue_id_type);
		g_free(file_info->session_ue_id_value);
		file_info->session_ue_id_type = ctx->ue_id_type ? g_strdup(ctx->ue_id_type) : NULL;
		file_info->session_ue_id_value = ctx->ue_id_value ? g_strdup(ctx->ue_id_value) : NULL;
	}

	/* We stored the offset of the "<msg" for this packet */
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	msg_end = read_until(file_info->buffer, c_e_msg, wth->random_fh, err, err_info);
	if (msg_end == NULL) {
		return false;
	}
	msg_end += CLEN(c_e_msg);
	msg_len = (unsigned)(msg_end - file_info->buffer->data);

	/* Find the <msg start in the buffer */
	uint8_t *msg_start = (uint8_t*)g_strstr_len((const char*)file_info->buffer->data, msg_len, c_s_msg);
	if (msg_start == NULL) {
		g_byte_array_set_size(file_info->buffer, 0);
		return false;
	}
	size_t actual_msg_len = (size_t)(msg_end - msg_start);

	status = nettrace_parse_msg(wth, rec, msg_start, actual_msg_len, err, err_info);

	g_byte_array_set_size(file_info->buffer, 0);
	return status;
}

/* Clean up any memory we allocated for dealing with this file.
 * Set as the subtype_close function in the file_open function below.
 * (wiretap frees wth->priv itself)
 */
static void
nettrace_close(wtap *wth)
{
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;

	if (file_info != NULL) {
		if (file_info->buffer != NULL) {
			g_byte_array_free(file_info->buffer, true);
			file_info->buffer = NULL;
		}
		g_free(file_info->session_ue_id_type);
		g_free(file_info->session_ue_id_value);
		file_info->session_ue_id_type = NULL;
		file_info->session_ue_id_value = NULL;
		if (file_info->offset_pkt_ctx != NULL) {
			g_hash_table_destroy(file_info->offset_pkt_ctx);
			file_info->offset_pkt_ctx = NULL;
		}
	}
}

/* Validate the file header and extract the beginTime timestamp.
 * Returns WTAP_OPEN_MINE if valid, WTAP_OPEN_NOT_MINE otherwise.
 * On success, start_time is set from the traceCollec beginTime attribute.
 */
static wtap_open_return_val
nettrace_parse_file_header(xmlNodePtr root_element, nstime_t *start_time)
{
	if (root_element->children == NULL)
		return WTAP_OPEN_NOT_MINE;

	for (xmlNodePtr cur = root_element->children; cur != NULL; cur = cur->next) {
		if (cur->type != XML_ELEMENT_NODE)
			continue;
		if (xmlStrcmp(cur->name, (const xmlChar*)"fileHeader") != 0)
			continue;

		/* Validate fileFormatVersion attribute */
		for (xmlAttrPtr attr = cur->properties; attr; attr = attr->next) {
			if (xmlStrcmp(attr->name, (const xmlChar*)"fileFormatVersion") == 0) {
				xmlChar* version = xmlNodeListGetString(cur->doc, attr->children, 1);
				if (version == NULL)
					return WTAP_OPEN_NOT_MINE;
				bool valid = (strncmp((const char*)version, "32.423", strlen("32.423")) == 0);
				xmlFree(version);
				if (!valid)
					return WTAP_OPEN_NOT_MINE;
			}
		}

		/* Extract beginTime from <traceCollec beginTime="..."> */
		for (xmlNodePtr child = cur->children; child != NULL; child = child->next) {
			if (child->type != XML_ELEMENT_NODE)
				continue;
			if (xmlStrcmp(child->name, (const xmlChar*)"traceCollec") != 0)
				continue;
			for (xmlAttrPtr attr = child->properties; attr; attr = attr->next) {
				if (xmlStrcmp(attr->name, (const xmlChar*)"beginTime") == 0) {
					xmlChar* str_begintime = xmlNodeListGetString(child->doc, attr->children, 1);
					if (str_begintime != NULL) {
						iso8601_to_nstime(start_time, (const char*)str_begintime, ISO8601_DATETIME);
						xmlFree(str_begintime);
					}
				}
			}
		}
		return WTAP_OPEN_MINE;
	}
	return WTAP_OPEN_NOT_MINE;
}

/* Test the current file to see if it's one we can read.
 * Set in file_access.c as the function to be called for this file type.
 */
wtap_open_return_val
nettrace_3gpp_32_423_file_open(wtap *wth, int *err _U_, char **err_info _U_)
{
	nstime_t start_time = NSTIME_INIT_UNSET;
	nettrace_3gpp_32_423_file_info_t *file_info;
	xmlDocPtr doc;
	xmlNodePtr root_element = NULL;

	doc = xmlReadFile(wth->pathname, NULL, XML_PARSE_NONET | XML_PARSE_NOERROR);
	if (doc == NULL) {
		return WTAP_OPEN_NOT_MINE;
	}

	root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL) {
		xmlFreeDoc(doc);
		return WTAP_OPEN_NOT_MINE;
	}

	/* Sanity check: root must be <traceCollecFile> (note: no 't' in Collec) */
	if (xmlStrcmp(root_element->name, (const xmlChar*)"traceCollecFile") != 0) {
		ws_debug("traceCollecFile did not match root_element->name %s", root_element->name);
		xmlFreeDoc(doc);
		return WTAP_OPEN_NOT_MINE;
	}

	/* Validate file header and extract beginTime */
	wtap_open_return_val header_result = nettrace_parse_file_header(root_element, &start_time);
	if (header_result != WTAP_OPEN_MINE) {
		xmlFreeDoc(doc);
		return header_result;
	}

	/* Ok it's our file. From here we'll need to free memory */
	xmlFreeDoc(doc);

	file_info = g_new0(nettrace_3gpp_32_423_file_info_t, 1);
	file_info->start_time = start_time;
	file_info->start_offset = 0;
	file_info->buffer = g_byte_array_sized_new(RINGBUFFER_START_SIZE);
	file_info->offset_pkt_ctx = g_hash_table_new_full(g_int64_hash, g_int64_equal,
	                                                   g_free, nettrace_packet_ctx_free);

	wth->file_type_subtype = nettrace_3gpp_32_423_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
	wth->file_tsprec = WTAP_TSPREC_MSEC;
	wth->file_start_ts = start_time;
	wth->subtype_read = nettrace_read;
	wth->subtype_seek_read = nettrace_seek_read;
	wth->subtype_close = nettrace_close;
	wth->snapshot_length = 0;
	wth->priv = (void*)file_info;

	return WTAP_OPEN_MINE;
}

static const struct supported_block_type nettrace_3gpp_32_423_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info nettrace_3gpp_32_423_info = {
	"3GPP TS 32.423 Trace", "3gpp32423", NULL, NULL,
	false, BLOCKS_SUPPORTED(nettrace_3gpp_32_423_blocks_supported),
	NULL, NULL, NULL
};

void register_nettrace_3gpp_32_423(void)
{
	nettrace_3gpp_32_423_file_type_subtype = wtap_register_file_type_subtype(&nettrace_3gpp_32_423_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("NETTRACE_3GPP_32_423",
	    nettrace_3gpp_32_423_file_type_subtype);
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
