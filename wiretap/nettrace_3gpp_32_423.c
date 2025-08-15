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
#include "nettrace_3gpp_32_423.h"

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtap-int.h"
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
static const unsigned char c_xml_magic[] = "<?xml";
static const unsigned char c_file_header[] = "<fileHeader";
static const unsigned char c_file_format_version[] = "fileFormatVersion=\"";
static const unsigned char c_threegpp_doc_no[] = "32.423";
static const unsigned char c_begin_time[] = "<traceCollec beginTime=\"";
static const unsigned char c_s_msg[] = "<msg";
static const unsigned char c_e_msg[] = "</msg>";

/* These are protocol names we may put in the exported-pdu data based on
 * what's in the XML. They're defined here as constants so we can use
 * sizeof()/CLEN() on them and slightly reduce our use of magic constants
 * for their size. (Modern compilers should make this no slower than that.)
 */
static const unsigned char c_sai_req[] = "gsm_map.v3.arg.opcode";
static const unsigned char c_sai_rsp[] = "gsm_map.v3.res.opcode";
static const unsigned char c_nas_eps[] = "nas-eps_plain";
static const unsigned char c_nas_5gs[] = "nas-5gs";


#define RINGBUFFER_START_SIZE INT_MAX
#define RINGBUFFER_CHUNK_SIZE 1024

#define MAX_FUNCTION_LEN 64
#define MAX_NAME_LEN 128
#define MAX_PROTO_LEN 16
#define MAX_DTBL_LEN 32

/* We expect to find all the info we need to tell if this file is ours
 * within this many bytes. Must include the beginTime attribute.
 */
#define MAGIC_BUF_SIZE 1024

typedef struct nettrace_3gpp_32_423_file_info {
	GByteArray *buffer;		// holds current chunk of file
	int64_t start_offset;		// where in the file the start of the buffer points
	nstime_t start_time;		// from <traceCollec beginTime=""> attribute
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
	static GRegex *regex = NULL;
	char *matched_ipaddress = NULL;
	char *matched_port = NULL;
	char *matched_transport = NULL;

	/* Excample from one trace, unsure if it's generic...
	 * {address == 192.168.73.1, port == 5062, transport == Udp}
	 * {address == [2001:1b70:8294:210a::78], port...
	 * {address == 2001:1B70:8294:210A::90, port...
	 *  Address=198.142.204.199,Port=2123
	 */

	if (regex == NULL) {
		regex = g_regex_new (
			"^.*address\\s*=*\\s*" //curr_pos will begin with address
			"\\[?(?P<ipaddress>(?:" //store ipv4 or ipv6 address in named group "ipaddress"
				"(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" //match an IPv4 address
				"|" // or
				"(?:[0-9a-f:]*)))\\]?" //match an IPv6 address.
			"(?:.*port\\s*=*\\s*(?P<port>\\d{1,5}))?" //match a port store it in named group "port"
			"(?:.*transport\\s*=*\\s*(?P<transport>\\w+))?", //match a transport store it in named group "transport"
			G_REGEX_CASELESS | G_REGEX_FIRSTLINE, 0, NULL);
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
			if (g_ascii_strncasecmp(matched_transport, "udp", 3) == 0) {
				exported_pdu_info->ptype = EXP_PDU_PT_UDP;
			}
			else if (g_ascii_strncasecmp(matched_transport, "tcp", 3) == 0) {
				exported_pdu_info->ptype = EXP_PDU_PT_TCP;
			}
			else if (g_ascii_strncasecmp(matched_transport, "sctp", 4) == 0) {
				exported_pdu_info->ptype = EXP_PDU_PT_SCTP;
			}
			else {
				/* fall to something so that ports are shown in column */
				exported_pdu_info->ptype = EXP_PDU_PT_TCP;
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

/* Parse a <msg ...><rawMsg ...>XXXX</rawMsg></msg> into packet data. */
static bool
nettrace_msg_to_packet(wtap* wth, wtap_rec* rec, const char* text, size_t len, int* err, char** err_info)
{
	nettrace_3gpp_32_423_file_info_t* file_info = (nettrace_3gpp_32_423_file_info_t*)wth->priv;
	xmlDocPtr           doc;
	xmlNodePtr root_element;
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

	doc = xmlParseMemory(text, (int)len);
	if (doc == NULL) {
		return false;
	}

	root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL) {
		ws_debug("empty xml doc");
		status = false;
		goto end;
	}

	//Sanity check
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

	//Start with attributes not existing
	function_str[0] = '\0';
	name_str[0] = '\0';

	/* Walk the attributes of the message */
	for (xmlAttrPtr attr = root_element->properties; attr; attr = attr->next) {
		if (xmlStrcmp(attr->name, (const xmlChar*)"function") == 0) {
			xmlChar* str = xmlNodeListGetString(root_element->doc, attr->children, 1);
			if (str != NULL) {
				size_t function_str_len = strlen(str);
				if (function_str_len > MAX_FUNCTION_LEN) {
					*err = WTAP_ERR_BAD_FILE;
					*err_info = ws_strdup_printf("nettrace_3gpp_32_423: function_str_len > %d", MAX_FUNCTION_LEN);
					xmlFree(str);
					status = false;
					goto end;
				}

				(void)g_strlcpy(function_str, str, (size_t)function_str_len + 1);
				ascii_strdown_inplace(function_str);

				xmlFree(str);
			}
		}
		else if (xmlStrcmp(attr->name, (const xmlChar*)"name") == 0) {
			xmlChar* str = xmlNodeListGetString(root_element->doc, attr->children, 1);
			if (str != NULL) {
				size_t name_str_len = strlen(str);
				if (name_str_len > MAX_NAME_LEN) {
					*err = WTAP_ERR_BAD_FILE;
					*err_info = ws_strdup_printf("nettrace_3gpp_32_423: name_str_len > %d", MAX_NAME_LEN);
					xmlFree(str);
					status = false;
					goto end;
				}

				(void)g_strlcpy(name_str, str, (size_t)name_str_len + 1);
				ascii_strdown_inplace(name_str);
				xmlFree(str);
			}
		}
		else if (xmlStrcmp(attr->name, (const xmlChar*)"changeTime") == 0) {

			/* Check if we have a time stamp "changeTime"
			 * expressed in number of seconds and milliseconds (nbsec.ms).
			 * Only needed if we have a "beginTime" for this file.
			 */
			if (!nstime_is_unset(&(file_info->start_time))) {
				int scan_found;
				unsigned second = 0, ms = 0;

				xmlChar* str_time = xmlNodeListGetString(root_element->doc, attr->children, 1);
				if (str_time != NULL) {
					scan_found = sscanf(str_time, "%u.%u", &second, &ms);

					if (scan_found == 2) {
						unsigned start_ms = file_info->start_time.nsecs / 1000000;
						unsigned elapsed_ms = start_ms + ms;
						if (elapsed_ms > 1000) {
							elapsed_ms -= 1000;
							second++;
						}
						rec->presence_flags |= WTAP_HAS_TS;
						rec->ts.secs = file_info->start_time.secs + second;
						rec->ts.nsecs = (elapsed_ms * 1000000);
					}

					xmlFree(str_time);
				}
			}
		}
	}

	/* Check the children of the msg root */
	proto_name_str[0] = '\0';
	dissector_table_str[0] = '\0';
	for (xmlNodePtr cur = root_element->children; cur != NULL; cur = cur->next) {
		if (cur->type == XML_ELEMENT_NODE) {
			if (xmlStrcmp(cur->name, (const xmlChar*)"initiator") == 0) {
				xmlChar* initiator_content = xmlNodeGetContent(cur);

				nettrace_parse_address(initiator_content, true/* SRC */, &exported_pdu_info);
				xmlFree(initiator_content);
			}
			else if (xmlStrcmp(cur->name, (const xmlChar*)"target") == 0) {
				xmlChar* target_content = xmlNodeGetContent(cur);

				nettrace_parse_address(target_content, false/* DST */, &exported_pdu_info);
				xmlFree(target_content);
			}
			else if (xmlStrcmp(cur->name, (const xmlChar*)"proxy") == 0) {
				xmlChar* proxy_content = xmlNodeGetContent(cur);

				/* proxy info will be save in destination ip/port */
				nettrace_parse_address(proxy_content, false/* SRC */, &proxy_exported_pdu_info);
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
							size_t proto_str_len = strlen(str);
							if (proto_str_len > MAX_PROTO_LEN) {
								xmlFree(str);
								status = false;
								goto end;
							}
							(void)g_strlcpy(proto_name_str, str, (size_t)proto_str_len + 1);
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

				/* Do string matching and replace with Wiresharks protocol name */
				if (strcmp(proto_name_str, "gtpv2-c") == 0) {
					/* Change to gtpv2 */
					proto_name_str[5] = '\0';
				}
				else if (strcmp(proto_name_str, "nas") == 0) {
					if (strcmp(function_str, "s1") == 0) {
						/* Change to nas-eps_plain */
						(void)g_strlcpy(proto_name_str, c_nas_eps, sizeof(c_nas_eps));
					}
					else if (strcmp(function_str, "n1") == 0) {
						/* Change to nas-5gs */
						(void)g_strlcpy(proto_name_str, c_nas_5gs, sizeof(c_nas_5gs));
					}
					else {
						*err = WTAP_ERR_BAD_FILE;
						*err_info = ws_strdup_printf("nettrace_3gpp_32_423: No handle of message \"%s\" on function \"%s\" ", proto_name_str, function_str);
						status = false;
						goto end;
					}
				}
				else if (strcmp(proto_name_str, "map") == 0) {
					/* For GSM map, it looks like the message data is stored like SendAuthenticationInfoArg
					 * use the GSM MAP dissector table to dissect the content.
					 */
					exported_pdu_info.proto_col_str = g_strdup("GSM MAP");

					if (strcmp(name_str, "sai_request") == 0) {
						use_proto_table = true;
						(void)g_strlcpy(dissector_table_str, c_sai_req, sizeof(c_sai_req));
						dissector_table_val = 56;
						exported_pdu_info.presence_flags |= EXP_PDU_TAG_COL_PROT_BIT;
					}
					else if (strcmp(name_str, "sai_response") == 0) {
						use_proto_table = true;
						(void)g_strlcpy(dissector_table_str, c_sai_rsp, sizeof(c_sai_rsp));
						dissector_table_val = 56;
						exported_pdu_info.presence_flags |= EXP_PDU_TAG_COL_PROT_BIT;
					}
					else {
						g_free(exported_pdu_info.proto_col_str);
						exported_pdu_info.proto_col_str = NULL;
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

				/* Fill packet buff */
				ws_buffer_clean(&rec->data);
				if (use_proto_table == false) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_DISSECTOR_NAME, proto_name_str, (uint16_t)strlen(proto_name_str));
				}
				else {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_DISSECTOR_TABLE_NAME, dissector_table_str, (uint16_t)strlen(dissector_table_str));
					wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL, dissector_table_val);
				}

				if (exported_pdu_info.presence_flags & EXP_PDU_TAG_COL_PROT_BIT) {
					wtap_buffer_append_epdu_string(&rec->data, EXP_PDU_TAG_COL_PROT_TEXT, exported_pdu_info.proto_col_str);
					g_free(exported_pdu_info.proto_col_str);
					exported_pdu_info.proto_col_str = NULL;
				}

				if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_SRC_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_SRC, exported_pdu_info.src_ip, EXP_PDU_TAG_IPV4_LEN);
				}
				else if (proxy_exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_SRC, proxy_exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV4_LEN);
				}
				if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_DST, exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV4_LEN);
				}
				else if (proxy_exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV4_DST, proxy_exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV4_LEN);
				}

				if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_SRC_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_SRC, exported_pdu_info.src_ip, EXP_PDU_TAG_IPV6_LEN);
				}
				else if (proxy_exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_SRC, proxy_exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV6_LEN);
				}
				if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_DST, exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV6_LEN);
				}
				else if (proxy_exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
					wtap_buffer_append_epdu_tag(&rec->data, EXP_PDU_TAG_IPV6_DST, proxy_exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV6_LEN);
				}

				if (exported_pdu_info.presence_flags & (EXP_PDU_TAG_SRC_PORT_BIT | EXP_PDU_TAG_DST_PORT_BIT)) {
					wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_PORT_TYPE, exported_pdu_info.ptype);
				}
				else if (proxy_exported_pdu_info.presence_flags & (EXP_PDU_TAG_SRC_PORT_BIT | EXP_PDU_TAG_DST_PORT_BIT)) {
					wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_PORT_TYPE, proxy_exported_pdu_info.ptype);
				}
				if (exported_pdu_info.presence_flags & EXP_PDU_TAG_SRC_PORT_BIT) {
					wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_SRC_PORT, exported_pdu_info.src_port);
				}
				else if (proxy_exported_pdu_info.presence_flags & EXP_PDU_TAG_DST_PORT_BIT) {
					wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_SRC_PORT, proxy_exported_pdu_info.dst_port);
				}
				if (exported_pdu_info.presence_flags & EXP_PDU_TAG_DST_PORT_BIT) {
					wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_DST_PORT, exported_pdu_info.dst_port);
				}
				else if (proxy_exported_pdu_info.presence_flags & EXP_PDU_TAG_DST_PORT_BIT) {
					wtap_buffer_append_epdu_uint(&rec->data, EXP_PDU_TAG_DST_PORT, proxy_exported_pdu_info.dst_port);
				}

				/* Add end of options */
				size_t raw_data_len = strlen(raw_content);
				int exp_pdu_tags_len = wtap_buffer_append_epdu_end(&rec->data);

				/* Convert the hex raw msg data to binary and write to the packet buf*/
				size_t pkt_data_len = raw_data_len / 2;
				ws_buffer_assure_space(&rec->data, pkt_data_len);
				uint8_t* packet_buf = ws_buffer_end_ptr(&rec->data);

				const char* curr_pos = raw_content;
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
						/* Something wrong, bail out */
						*err_info = ws_strdup_printf("nettrace_3gpp_32_423: Could not parse hex data, bufsize %zu index %zu %c%c",
							(pkt_data_len + exp_pdu_tags_len),
							i, chr1, chr2);
						*err = WTAP_ERR_BAD_FILE;
						xmlFree(raw_content);
						status = false;
						goto end;
					}
				}
				ws_buffer_increase_length(&rec->data, pkt_data_len);

				rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
				rec->rec_header.packet_header.len = (uint32_t)ws_buffer_length(&rec->data);

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
	xmlFreeDoc(doc);
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

	while (NULL == (found_it = g_strstr_len(buffer->data, buffer->len, needle))) {
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

	/* Make sure we have a start and end of message in our buffer -- end first */
	msg_end = read_until(file_info->buffer, c_e_msg, wth->fh, err, err_info);
	if (msg_end == NULL) {
		goto end;
	}

	buf_start = file_info->buffer->data;
	/* Now search backwards for the message start
	 * (doing it this way should skip over any empty "<msg ... />" tags we have)
	 */
	msg_start = g_strrstr_len(buf_start, (unsigned)(msg_end - buf_start), c_s_msg);
	if (msg_start == NULL || msg_start > msg_end) {
		*err_info = ws_strdup_printf("nettrace_3gpp_32_423: Found \"%s\" without matching \"%s\"", c_e_msg, c_s_msg);
		*err = WTAP_ERR_BAD_FILE;
		goto end;
	}

	/* We know we have a message, what's its offset from the buffer start? */
	msg_offset = (unsigned)(msg_start - buf_start);
	msg_end += CLEN(c_e_msg);
	msg_len = (unsigned)(msg_end - msg_start);

	/* Tell Wireshark to put us at the start of the "<msg" for seek_read later */
	*data_offset = file_info->start_offset + msg_offset;

	/* pass all of <msg....</msg> to nettrace_msg_to_packet() */
	status = nettrace_msg_to_packet(wth, rec, msg_start, msg_len, err, err_info);

	/* Finally, shift our buffer to the end of this message to get ready for the next one.
	 * Re-use msg_len to get the length of the data we're done with.
	 */
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

	/* We stored the offset of the "<msg" for this packet */
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	msg_end = read_until(file_info->buffer, c_e_msg, wth->random_fh, err, err_info);
	if (msg_end == NULL) {
		return false;
	}
	msg_end += CLEN(c_e_msg);
	msg_len = (unsigned)(msg_end - file_info->buffer->data);

	status = nettrace_msg_to_packet(wth, rec, file_info->buffer->data, msg_len, err, err_info);
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

	if (file_info != NULL && file_info->buffer != NULL) {
		g_byte_array_free(file_info->buffer, true);
		file_info->buffer = NULL;
	}
}

/* Test the current file to see if it's one we can read.
 * Set in file_access.c as the function to be called for this file type.
 */
wtap_open_return_val
nettrace_3gpp_32_423_file_open(wtap *wth, int *err, char **err_info)
{
	char magic_buf[MAGIC_BUF_SIZE+1];
	int bytes_read;
	const char *curr_pos;
	nstime_t start_time;
	nettrace_3gpp_32_423_file_info_t *file_info;
	int64_t start_offset;

	start_offset = file_tell(wth->fh); // Most likely 0 but doesn't hurt to check
	bytes_read = file_read(magic_buf, MAGIC_BUF_SIZE, wth->fh);

	if (bytes_read < 0) {
		*err = file_error(wth->fh, err_info);
		return WTAP_OPEN_ERROR;
	}
	if (bytes_read == 0){
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(magic_buf, c_xml_magic, CLEN(c_xml_magic)) != 0){
		return WTAP_OPEN_NOT_MINE;
	}

	curr_pos = g_strstr_len(magic_buf, bytes_read, c_file_header);
	if (!curr_pos) {
		return WTAP_OPEN_NOT_MINE;
	}
	curr_pos = g_strstr_len(curr_pos, bytes_read-(curr_pos-magic_buf), c_file_format_version);
	if (!curr_pos) {
		return WTAP_OPEN_NOT_MINE;
	}
	curr_pos += CLEN(c_file_format_version);
	if (memcmp(curr_pos, c_threegpp_doc_no, CLEN(c_threegpp_doc_no)) != 0){
		return WTAP_OPEN_NOT_MINE;
	}
	/* Next we expect something like <traceCollec beginTime="..."/> */
	curr_pos = g_strstr_len(curr_pos, bytes_read-(curr_pos-magic_buf), c_begin_time);
	if (!curr_pos) {
		return WTAP_OPEN_NOT_MINE;
	}
	curr_pos += CLEN(c_begin_time);
	/* Next we expect an ISO 8601-format time */
	curr_pos = iso8601_to_nstime(&start_time, curr_pos, ISO8601_DATETIME);
	if (!curr_pos) {
		return WTAP_OPEN_NOT_MINE;
	}

	/* Ok it's our file. From here we'll need to free memory */
	file_info = g_new0(nettrace_3gpp_32_423_file_info_t, 1);
	file_info->start_time = start_time;
	file_info->start_offset = start_offset + (curr_pos - magic_buf);
	file_info->buffer = g_byte_array_sized_new(RINGBUFFER_START_SIZE);
	g_byte_array_append(file_info->buffer, curr_pos, (unsigned)(bytes_read - (curr_pos - magic_buf)));

	wth->file_type_subtype = nettrace_3gpp_32_423_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
	wth->file_tsprec = WTAP_TSPREC_MSEC;
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
