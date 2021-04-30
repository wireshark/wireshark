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

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <epan/exported_pdu.h>
#include <wsutil/buffer.h>
#include "wsutil/tempfile.h"
#include "wsutil/os_version_info.h"
#include "wsutil/str_util.h"
#include <wsutil/inet_addr.h>


#include "nettrace_3gpp_32_423.h"

/* String constants sought in the XML data.
 * Written as strings instead of lists of chars for readability.
 * Use the CLEN() macro to get the length of the constant without counting
 * the null byte at the end.
 */
#define CLEN(x) (sizeof(x)-1)
static const guchar c_xml_magic[] = "<?xml";
static const guchar c_file_header[] = "<fileHeader";
static const guchar c_file_format_version[] = "fileFormatVersion=\"";
static const guchar c_threegpp_doc_no[] = "32.423";
static const guchar c_begin_time[] = "<traceCollec beginTime=\"";
static const guchar c_s_msg[] = "<msg";
static const guchar c_e_msg[] = "</msg>";
static const guchar c_s_rawmsg[] = "<rawMsg";
static const guchar c_change_time[] = "changeTime=\"";
static const guchar c_proto_name[] = "name=\"";
static const guchar c_address[] = "ddress"; /* omit the 'a' to cater for "Address" */
static const guchar c_s_initiator[] = "<initiator";
static const guchar c_e_initiator[] = "</initiator>";
static const guchar c_s_target[] = "<target";
static const guchar c_e_target[] = "</target>";
static const guchar c_protocol[] = "protocol=\"";

/* These are protocol names we may put in the exported-pdu data based on
 * what's in the XML. They're defined here as constants so we can use
 * sizeof()/CLEN() on them and slightly reduce our use of magic constants
 * for their size. (Modern compilers should make this no slower than that.)
 */
static const guchar c_sai_req[] = "gsm_map.v3.arg.opcode";
static const guchar c_sai_rsp[] = "gsm_map.v3.res.opcode";
static const guchar c_nas_eps[] = "nas-eps_plain";

#define RINGBUFFER_START_SIZE G_MAXINT
#define RINGBUFFER_CHUNK_SIZE 1024

#define MAX_NAME_LEN 64
#define MAX_PROTO_LEN 16
#define MAX_DTBL_LEN 32

/* We expect to find all the info we need to tell if this file is ours
 * within this many bytes. Must include the beginTime attribute.
 */
#define MAGIC_BUF_SIZE 1024

typedef struct nettrace_3gpp_32_423_file_info {
	GByteArray *buffer;		// holds current chunk of file
	gint64 start_offset;		// where in the file the start of the buffer points
	nstime_t start_time;		// from <traceCollec beginTime=""> attribute
} nettrace_3gpp_32_423_file_info_t;


typedef struct exported_pdu_info {
	guint32 presence_flags;
	guint8 src_ip[16];
	guint32 ptype; /* Based on epan/address.h port_type valid for both src and dst*/
	guint32 src_port;
	guint8 dst_ip[16];
	guint32 dst_port;
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
static char*
nettrace_parse_address(char* curr_pos, char* next_pos, gboolean is_src_addr, exported_pdu_info_t *exported_pdu_info)
{
	guint port;
	char transp_str[5];
	int scan_found;
	char str[3];
	char* end_pos, *skip_pos;
	char ip_addr_str[WS_INET6_ADDRSTRLEN];
	int str_len;
	ws_in6_addr ip6_addr;
	guint32 ip4_addr;
	gchar tempchar;

	/* curr_pos pointing to first char after address */

	/* Excample from one trace, unsure if it's generic...
	 * {address == 192.168.73.1, port == 5062, transport == Udp}
	 * {address == [2001:1b70:8294:210a::78], port...
	 * {address == 2001:1B70:8294:210A::90, port...
	 *  Address=198.142.204.199,Port=2123
	 */
	/* Skip whitespace and equalsigns) */
	for (skip_pos = curr_pos; skip_pos < next_pos &&
		((tempchar = *skip_pos) == ' ' ||
			tempchar == '\t' || tempchar == '\r' || tempchar == '\n' || tempchar == '=');
		skip_pos++);

	curr_pos = skip_pos;

	(void) g_strlcpy(str, curr_pos, 3);
	/* If we find "" here we have no IP address */
	if (strcmp(str, "\"\"") == 0) {
		return next_pos;
	}
	str[1] = 0;
	if (strcmp(str, "[") == 0) {
		/* Should we check for a digit here?*/
		end_pos = strstr(curr_pos, "]");

	}else {
		/* Should we check for a digit here?*/
		end_pos = strstr(curr_pos, ",");
	}
	if (!end_pos) {
		return next_pos;
	}

	str_len = (int)(end_pos - curr_pos)+1;
	if (str_len > WS_INET6_ADDRSTRLEN) {
		return next_pos;
	}
	(void) g_strlcpy(ip_addr_str, curr_pos, str_len);
	curr_pos = end_pos;
	if (ws_inet_pton6(ip_addr_str, &ip6_addr)) {
		if (is_src_addr) {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP6_SRC_BIT;
			memcpy(exported_pdu_info->src_ip, ip6_addr.bytes, EXP_PDU_TAG_IPV6_LEN);
		}
		else {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP6_DST_BIT;
			memcpy(exported_pdu_info->dst_ip, ip6_addr.bytes, EXP_PDU_TAG_IPV6_LEN);
		}
	}
	else if (ws_inet_pton4(ip_addr_str, &ip4_addr)) {
		if (is_src_addr) {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP_SRC_BIT;
			memcpy(exported_pdu_info->src_ip, &ip4_addr, EXP_PDU_TAG_IPV4_LEN);
		}
		else {
			exported_pdu_info->presence_flags |= EXP_PDU_TAG_IP_DST_BIT;
			memcpy(exported_pdu_info->dst_ip, &ip4_addr, EXP_PDU_TAG_IPV4_LEN);
		}
	}

	curr_pos++;
	scan_found = sscanf(curr_pos, ", %*s %*s %5u, %*s %*s %4s", &port, transp_str);
	if (scan_found == 2) {
		/* Only add port_type once */
		if (exported_pdu_info->ptype == OLD_PT_NONE) {
			if (g_ascii_strncasecmp(transp_str, "udp", 3) == 0) {
				exported_pdu_info->ptype = OLD_PT_UDP;
			}
			else if (g_ascii_strncasecmp(transp_str, "tcp", 3) == 0) {
				exported_pdu_info->ptype = OLD_PT_TCP;
			}
			else if (g_ascii_strncasecmp(transp_str, "sctp", 4) == 0) {
				exported_pdu_info->ptype = OLD_PT_SCTP;
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
	return next_pos;
}


/* Parse a <msg ...><rawMsg ...>XXXX</rawMsg></msg> into packet data. */
static gboolean
nettrace_msg_to_packet(nettrace_3gpp_32_423_file_info_t *file_info, wtap_rec *rec, Buffer *buf, guint8 *input, gsize len, int *err, gchar **err_info)
{
/* Convenience macro. haystack must be >= input! */
#define STRNSTR(haystack, needle) g_strstr_len(haystack, (len - ((guint8*)(haystack) - (guint8*)input)), needle)

	gboolean status = TRUE;
	char *curr_pos, *next_msg_pos, *next_pos, *prev_pos;
	exported_pdu_info_t  exported_pdu_info = {0};

	char* raw_msg_pos;
	char* start_msg_tag_cont;
	char name_str[MAX_NAME_LEN+1];
	char proto_name_str[MAX_PROTO_LEN+1];
	char dissector_table_str[MAX_DTBL_LEN+1];
	int dissector_table_val = 0;

	int name_str_len = 0;
	int tag_str_len = 0;
	int proto_str_len, dissector_table_str_len, raw_data_len, pkt_data_len,  exp_pdu_tags_len, i, j;
	guint8 *packet_buf;
	gint val1, val2;
	gboolean port_type_defined = FALSE;
	gboolean use_proto_table = FALSE;

	/* We should always and only be called with a <msg....</msg> payload */
	if (0 != strncmp(input, c_s_msg, CLEN(c_s_msg))) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("Did not start with \"%s\"", c_s_msg);
		return FALSE;
	}
	prev_pos = curr_pos = input + CLEN(c_s_msg);

	rec->rec_type = REC_TYPE_PACKET;
	rec->presence_flags = 0; /* start out assuming no special features */
	rec->ts.secs = 0;
	rec->ts.nsecs = 0;

	/* Clear for each iteration */
	exported_pdu_info.presence_flags = 0;
	exported_pdu_info.ptype = OLD_PT_NONE;

	prev_pos = curr_pos = curr_pos + 4;
	/* Look for the end of the tag first */
	next_msg_pos = STRNSTR(curr_pos, ">");
	if (!next_msg_pos) {
		/* Something's wrong, bail out */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("Did not find end of tag \">\"");
		status = FALSE;
		goto end;
	}
	/* Check if its a tag close "/>" */
	if (*(next_msg_pos - 1) == '/') {
		/* There is no rawmsg here. Should have been caught before we got called */
		*err = WTAP_ERR_INTERNAL;
		*err_info = g_strdup("Had \"<msg />\" with no \"<rawMsg>\"");
		status = FALSE;
		goto end;
	}
	start_msg_tag_cont = curr_pos = prev_pos;
	next_msg_pos = STRNSTR(curr_pos, c_e_msg);
	if (!next_msg_pos) {
		/* Something's wrong, bail out */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("Did not find \"%s\"", c_e_msg);
		status = FALSE;
		goto end;
	}
	next_msg_pos += CLEN(c_e_msg);

	/* Check if we have a time stamp "changeTime"
	 * expressed in number of seconds and milliseconds (nbsec.ms).
	 * Only needed if we have a "beginTime" for this file.
	 */
	if (!nstime_is_unset(&(file_info->start_time))) {
		int scan_found;
		guint second = 0, ms = 0;

		curr_pos = STRNSTR(start_msg_tag_cont, c_change_time);
		/* Check if we have the tag or if we passed the end of the current message */
		if (curr_pos != NULL) {
			curr_pos += CLEN(c_change_time);
			scan_found = sscanf(curr_pos, "%u.%u", &second, &ms);

			if (scan_found == 2) {
				guint start_ms = file_info->start_time.nsecs / 1000000;
				guint elapsed_ms = start_ms + ms;
				if (elapsed_ms > 1000) {
					elapsed_ms -= 1000;
					second++;
				}
				rec->presence_flags |= WTAP_HAS_TS;
				rec->ts.secs = file_info->start_time.secs + second;
				rec->ts.nsecs = file_info->start_time.nsecs + (elapsed_ms * 1000000);
			}
		}
	}

	/* See if we have a "name" */
	curr_pos = STRNSTR(start_msg_tag_cont, c_proto_name);
	if (curr_pos != NULL) {
		/* extract the name */
		curr_pos += CLEN(c_proto_name);
		next_pos = STRNSTR(curr_pos, "\"");
		name_str_len = (int)(next_pos - curr_pos);
		if (name_str_len > MAX_NAME_LEN) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("name_str_len > %d", MAX_NAME_LEN);
			goto end;
		}

		(void) g_strlcpy(name_str, curr_pos, (gsize)name_str_len + 1);
		ascii_strdown_inplace(name_str);

	}
	/* Check if we have "<initiator>"
	 *  It might contain an address
	 */
	curr_pos = STRNSTR(start_msg_tag_cont, c_s_initiator);
	/* Check if we have the tag or if we passed the end of the current message */
	if (curr_pos != NULL) {
		curr_pos += CLEN(c_s_initiator);
		next_pos = STRNSTR(curr_pos, c_e_initiator);
		/* Find address */
		curr_pos = STRNSTR(curr_pos, c_address);
		if (curr_pos != NULL) {
			curr_pos += CLEN(c_address);
			nettrace_parse_address(curr_pos, next_pos, TRUE/* SRC */, &exported_pdu_info);
		}
	}

	/* Check if we have "<target>"
	 *  It might contain an address
	 */
	curr_pos = STRNSTR(start_msg_tag_cont, c_s_target);
	/* Check if we have the tag or if we passed the end of the current message */
	if (curr_pos != NULL) {
		curr_pos += CLEN(c_s_target);
		curr_pos = curr_pos + 7;
		next_pos = STRNSTR(curr_pos, c_e_target);
		/* Find address */
		curr_pos = STRNSTR(curr_pos, c_address);
		if (curr_pos != NULL) {
			curr_pos += CLEN(c_address);
			/* curr_pos set below */
			nettrace_parse_address(curr_pos, next_pos, FALSE/* DST */, &exported_pdu_info);
		}
	}

	/* Do we have a raw message in the <msg> </msg> section? */
	raw_msg_pos = STRNSTR(start_msg_tag_cont, c_s_rawmsg);
	if (raw_msg_pos == NULL) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("Did not find \"%s\"", c_s_rawmsg);
		status = FALSE;
		goto end;
	}
	curr_pos = STRNSTR(raw_msg_pos, c_protocol);
	if (curr_pos == NULL) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("Did not find \"%s\"", c_protocol);
		status = FALSE;
		goto end;
	}
	curr_pos += CLEN(c_protocol);
	next_pos = STRNSTR(curr_pos, "\"");
	proto_str_len = (int)(next_pos - curr_pos);
	if (proto_str_len > MAX_PROTO_LEN){
		status = FALSE;
		goto end;
	}
	(void) g_strlcpy(proto_name_str, curr_pos, (gsize)proto_str_len+1);
	ascii_strdown_inplace(proto_name_str);

	/* Do string matching and replace with Wiresharks protocol name */
	if (strcmp(proto_name_str, "gtpv2-c") == 0) {
		/* Change to gtpv2 */
		proto_name_str[5] = '\0';
		proto_str_len = 5;
	}
	/* XXX Do we need to check for function="S1"? */
	if (strcmp(proto_name_str, "nas") == 0) {
		/* Change to nas-eps_plain */
		(void) g_strlcpy(proto_name_str, c_nas_eps, sizeof(c_nas_eps));
		proto_str_len = CLEN(c_nas_eps);
	}
	if (strcmp(proto_name_str, "map") == 0) {
		/* For GSM map, it looks like the message data is stored like SendAuthenticationInfoArg
		 * use the GSM MAP dissector table to dissect the content.
		 */
		exported_pdu_info.proto_col_str = g_strdup("GSM MAP");

		if (strcmp(name_str, "sai_request") == 0) {
			use_proto_table = TRUE;
			(void) g_strlcpy(dissector_table_str, c_sai_req, sizeof(c_sai_req));
			dissector_table_str_len = CLEN(c_sai_req);
			dissector_table_val = 56;
			exported_pdu_info.presence_flags |= EXP_PDU_TAG_COL_PROT_BIT;
		}
		else if (strcmp(name_str, "sai_response") == 0) {
			use_proto_table = TRUE;
			(void) g_strlcpy(dissector_table_str, c_sai_rsp, sizeof(c_sai_rsp));
			dissector_table_str_len = CLEN(c_sai_rsp);
			dissector_table_val = 56;
			exported_pdu_info.presence_flags |= EXP_PDU_TAG_COL_PROT_BIT;
		} else {
			g_free(exported_pdu_info.proto_col_str);
			exported_pdu_info.proto_col_str = NULL;
		}
	}
	/* Find the start of the raw data */
	curr_pos = STRNSTR(next_pos, ">") + 1;
	next_pos = STRNSTR(curr_pos, "<");
	raw_data_len = (int)(next_pos - curr_pos);

	/* Calculate the space needed for exp pdu tags */
	if (use_proto_table == FALSE) {
		tag_str_len = (proto_str_len + 3) & 0xfffffffc;
		exp_pdu_tags_len = tag_str_len + 4;
	} else {
		tag_str_len = (dissector_table_str_len + 3) & 0xfffffffc;
		exp_pdu_tags_len = tag_str_len + 4;
		/* Add EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL + length */
		exp_pdu_tags_len += 4 + 4;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_COL_PROT_BIT) {
		/* The assert prevents static code analyzers to raise warnings */
		g_assert(exported_pdu_info.proto_col_str);
		exp_pdu_tags_len += 4 + (int)strlen(exported_pdu_info.proto_col_str);
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_SRC_BIT) {
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_IPV4_LEN;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_SRC_BIT) {
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_IPV6_LEN;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_SRC_PORT_BIT) {
		if (!port_type_defined) {
			exp_pdu_tags_len += 4 + EXP_PDU_TAG_PORT_TYPE_LEN;
			port_type_defined = TRUE;
		}
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_PORT_LEN;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_IPV4_LEN;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_IPV6_LEN;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_DST_PORT_BIT) {
		if (!port_type_defined) {
			exp_pdu_tags_len += 4 + EXP_PDU_TAG_PORT_TYPE_LEN;
			port_type_defined = TRUE;
		}
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_PORT_LEN;
	}
	exp_pdu_tags_len += 4; /* account for opt_endofopt */

	/* Allocate the packet buf */
	pkt_data_len = raw_data_len / 2;
	ws_buffer_assure_space(buf, (gsize)pkt_data_len + (gsize)exp_pdu_tags_len);
	ws_buffer_increase_length(buf, (gsize)pkt_data_len + (gsize)exp_pdu_tags_len);
	packet_buf = ws_buffer_start_ptr(buf);

	/* Fill packet buff */
	if (use_proto_table == FALSE) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_PROTO_NAME;
		*packet_buf++ = 0;
		*packet_buf++ = tag_str_len;
		memset(packet_buf, 0, tag_str_len);
		memcpy(packet_buf, proto_name_str, proto_str_len);
		packet_buf += tag_str_len;
	}
	else {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_DISSECTOR_TABLE_NAME;
		*packet_buf++ = 0;
		*packet_buf++ = tag_str_len;
		memset(packet_buf, 0, tag_str_len);
		memcpy(packet_buf, dissector_table_str, dissector_table_str_len);
		packet_buf += tag_str_len;

		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL;
		*packet_buf++ = 0;
		*packet_buf++ = 4; /* option length */
		*packet_buf++ = 0;
		*packet_buf++ = 0;
		*packet_buf++ = 0;
		*packet_buf++ = dissector_table_val;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_COL_PROT_BIT) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_COL_PROT_TEXT;
		*packet_buf++ = 0;
		*packet_buf++ = (guint8)strlen(exported_pdu_info.proto_col_str);
		for (j = 0; j < (int)strlen(exported_pdu_info.proto_col_str); j++) {
			*packet_buf++ = exported_pdu_info.proto_col_str[j];
		}
		g_free(exported_pdu_info.proto_col_str);
		exported_pdu_info.proto_col_str = NULL;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_SRC_BIT) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV4_SRC;
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV4_LEN;
		memcpy(packet_buf, exported_pdu_info.src_ip, EXP_PDU_TAG_IPV4_LEN);
		packet_buf += EXP_PDU_TAG_IPV4_LEN;
	}
	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP_DST_BIT) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV4_DST;
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV4_LEN;
		memcpy(packet_buf, exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV4_LEN);
		packet_buf += EXP_PDU_TAG_IPV4_LEN;
	}

	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_SRC_BIT) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV6_SRC;
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV6_LEN;
		memcpy(packet_buf, exported_pdu_info.src_ip, EXP_PDU_TAG_IPV6_LEN);
		packet_buf += EXP_PDU_TAG_IPV6_LEN;
	}
	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_IP6_DST_BIT) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV6_DST;
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_IPV6_LEN;
		memcpy(packet_buf, exported_pdu_info.dst_ip, EXP_PDU_TAG_IPV6_LEN);
		packet_buf += EXP_PDU_TAG_IPV6_LEN;
	}

	if (exported_pdu_info.presence_flags & (EXP_PDU_TAG_SRC_PORT_BIT | EXP_PDU_TAG_DST_PORT_BIT)) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_PORT_TYPE;
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_PORT_TYPE_LEN;
		*packet_buf++ = (exported_pdu_info.ptype & 0xff000000) >> 24;
		*packet_buf++ = (exported_pdu_info.ptype & 0x00ff0000) >> 16;
		*packet_buf++ = (exported_pdu_info.ptype & 0x0000ff00) >> 8;
		*packet_buf++ = (exported_pdu_info.ptype & 0x000000ff);
	}
	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_SRC_PORT_BIT) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_SRC_PORT;
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_PORT_LEN;
		*packet_buf++ = (exported_pdu_info.src_port & 0xff000000) >> 24;
		*packet_buf++ = (exported_pdu_info.src_port & 0x00ff0000) >> 16;
		*packet_buf++ = (exported_pdu_info.src_port & 0x0000ff00) >> 8;
		*packet_buf++ = (exported_pdu_info.src_port & 0x000000ff);
	}
	if (exported_pdu_info.presence_flags & EXP_PDU_TAG_DST_PORT_BIT) {
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_DST_PORT;
		*packet_buf++ = 0;
		*packet_buf++ = EXP_PDU_TAG_PORT_LEN;
		*packet_buf++ = (exported_pdu_info.dst_port & 0xff000000) >> 24;
		*packet_buf++ = (exported_pdu_info.dst_port & 0x00ff0000) >> 16;
		*packet_buf++ = (exported_pdu_info.dst_port & 0x0000ff00) >> 8;
		*packet_buf++ = (exported_pdu_info.dst_port & 0x000000ff);
	}

	/* Add end of options */
	*packet_buf++ = 0;
	*packet_buf++ = 0;
	*packet_buf++ = 0;
	*packet_buf++ = 0;

	/* Convert the hex raw msg data to binary and write to the packet buf*/
	for (i = 0; i < pkt_data_len; i++) {
		gchar chr1, chr2;

		chr1 = *curr_pos++;
		chr2 = *curr_pos++;
		val1 = g_ascii_xdigit_value(chr1);
		val2 = g_ascii_xdigit_value(chr2);
		if ((val1 != -1) && (val2 != -1)) {
			*packet_buf++ = ((guint8)val1 * 16) + val2;
		}
		else {
			/* Something wrong, bail out */
			*err_info = g_strdup_printf("Could not parse hex data, bufsize %u index %u %c%c",
				(pkt_data_len + exp_pdu_tags_len),
				i,
				chr1,
				chr2);
			*err = WTAP_ERR_BAD_FILE;
			status = FALSE;
			goto end;
		}
	}

	rec->rec_header.packet_header.caplen = pkt_data_len + exp_pdu_tags_len;
	rec->rec_header.packet_header.len = pkt_data_len + exp_pdu_tags_len;

end:
	return status;
#undef STRNSTR
}

/* Read from fh and store into buffer, until buffer contains needle.
 * Returns location of needle once found, or NULL if it's never found
 * (due to either EOF or read error).
 */
static guint8 *
read_until(GByteArray *buffer, const guchar *needle, FILE_T fh, int *err, gchar **err_info)
{
	guint8 read_buffer[RINGBUFFER_CHUNK_SIZE];
	guint8 *found_it;
	gint bytes_read = 0;

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
static gboolean
nettrace_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info, gint64 *data_offset)
{
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;
	guint8 *buf_start;
	guint8 *msg_start, *msg_end;
	guint msg_offset = 0;
	gsize msg_len = 0;
	gboolean status = FALSE;

	/* Make sure we have a start and end of message in our buffer -- end first */
	msg_end = read_until(file_info->buffer, c_e_msg, wth->fh, err, err_info);
	if (msg_end == NULL) {
		goto end;
	}

	buf_start = file_info->buffer->data;
	/* Now search backwards for the message start
	 * (doing it this way should skip over any empty "<msg ... />" tags we have)
	 */
	msg_start = g_strrstr_len(buf_start, (guint)(msg_end - buf_start), c_s_msg);
	if (msg_start == NULL || msg_start > msg_end) {
		*err_info = g_strdup_printf("Found \"%s\" without matching \"%s\"", c_e_msg, c_s_msg);
		*err = WTAP_ERR_BAD_FILE;
		goto end;
	}

	/* We know we have a message, what's its offset from the buffer start? */
	msg_offset = (guint)(msg_start - buf_start);
	msg_end += CLEN(c_e_msg);
	msg_len = (guint)(msg_end - msg_start);

	/* Tell Wireshark to put us at the start of the "<msg" for seek_read later */
	*data_offset = file_info->start_offset + msg_offset;

	/* pass all of <msg....</msg> to nettrace_msg_to_packet() */
	status = nettrace_msg_to_packet(file_info, rec, buf, msg_start, msg_len, err, err_info);

	/* Finally, shift our buffer to the end of this message to get ready for the next one.
	 * Re-use msg_len to get the length of the data we're done with.
	 */
	msg_len = msg_end - file_info->buffer->data;
	while (G_UNLIKELY(msg_len > G_MAXUINT)) {
		g_byte_array_remove_range(file_info->buffer, 0, G_MAXUINT);
		msg_len -= G_MAXUINT;
	}
	g_byte_array_remove_range(file_info->buffer, 0, (guint)msg_len);
	file_info->start_offset += msg_len;

end:
	if (status == FALSE) {
		/* There's no more to read. Empty out the buffer */
		g_byte_array_set_size(file_info->buffer, 0);
	}

	return status;
}

/* Seek to the complete packet at the offset, parse and return it to wiretap.
 * Set as the subtype_seek_read function in the file_open function below.
 */
static gboolean
nettrace_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info)
{
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;
	gboolean status = FALSE;
	guint8 *msg_end;
	guint msg_len = 0;

	/* We stored the offset of the "<msg" for this packet */
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	msg_end = read_until(file_info->buffer, c_e_msg, wth->random_fh, err, err_info);
	if (msg_end == NULL) {
		return FALSE;
	}
	msg_end += CLEN(c_e_msg);
	msg_len = (guint)(msg_end - file_info->buffer->data);

	status = nettrace_msg_to_packet(file_info, rec, buf, file_info->buffer->data, msg_len, err, err_info);
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
		g_byte_array_free(file_info->buffer, TRUE);
		file_info->buffer = NULL;
	}
}

/* Test the current file to see if it's one we can read.
 * Set in file_access.c as the function to be called for this file type.
 */
wtap_open_return_val
nettrace_3gpp_32_423_file_open(wtap *wth, int *err, gchar **err_info)
{
	char magic_buf[MAGIC_BUF_SIZE+1];
	int bytes_read;
	char *curr_pos;
	nettrace_3gpp_32_423_file_info_t *file_info;
	gint64 start_offset;

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

	/* Ok it's our file. From here we'll need to free memory */
	file_info = g_new0(nettrace_3gpp_32_423_file_info_t, 1);
	curr_pos += iso8601_to_nstime(&file_info->start_time, curr_pos);
	file_info->start_offset = start_offset + (curr_pos - magic_buf);
	file_info->buffer = g_byte_array_sized_new(RINGBUFFER_START_SIZE);
	g_byte_array_append(file_info->buffer, curr_pos, (guint)(bytes_read - (curr_pos - magic_buf)));

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
	FALSE, BLOCKS_SUPPORTED(nettrace_3gpp_32_423_blocks_supported),
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
