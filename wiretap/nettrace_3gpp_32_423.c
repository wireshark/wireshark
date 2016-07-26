/* nettrace_3gpp_32_423.c
 *
 * Decoder for 3GPP TS 32.423 file format for the Wiretap library.
 * The main purpose is to have Wireshark decode raw message content (<rawMsg> tag).
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref: http://www.3gpp.org/DynaReport/32423.htm
 */

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "pcap-encap.h"

#include <wsutil/buffer.h>
#include "wsutil/tempfile.h"
#include "wsutil/os_version_info.h"
#include "ws_version_info.h"
#include "wsutil/str_util.h"


#include "pcapng.h"
#include "nettrace_3gpp_32_423.h"

/*
* Impose a not-too-large limit on the maximum file size, to avoid eating
* up 99% of the (address space, swap partition, disk space for swap/page
* files); if we were to return smaller chunks and let the dissector do
* reassembly, it would *still* have to allocate a buffer the size of
* the file, so it's not as if we'd never try to allocate a buffer the
* size of the file. Laeve space for the exported PDU tag 12 bytes.
*/
#define MAX_FILE_SIZE	(G_MAXINT-12)

static const guint8 xml_magic[] = { '<', '?', 'x', 'm', 'l' };
static const guint8 Threegpp_doc_no[] = { '3', '2', '.', '4', '2', '3' };

typedef struct nettrace_3gpp_32_423_file_info {
	char *tmpname;
	wtap *wth_tmp_file;
} nettrace_3gpp_32_423_file_info_t;

/* From epan/address.h Types of port numbers Wireshark knows about. */
typedef enum {
	PT_NONE,            /* no port number */
	PT_SCTP,            /* SCTP */
	PT_TCP,             /* TCP */
	PT_UDP,             /* UDP */
	PT_DCCP,            /* DCCP */
	PT_IPX,             /* IPX sockets */
	PT_NCP,             /* NCP connection */
	PT_EXCHG,           /* Fibre Channel exchange */
	PT_DDP,             /* DDP AppleTalk connection */
	PT_SBCCS,           /* FICON */
	PT_IDP,             /* XNS IDP sockets */
	PT_TIPC,            /* TIPC PORT */
	PT_USB,             /* USB endpoint 0xffff means the host */
	PT_I2C,
	PT_IBQP,            /* Infiniband QP number */
	PT_BLUETOOTH,
	PT_TDMOP
} port_type;

typedef struct exported_pdu_info {
	guint32 precense_flags;
	/*const char* proto_name;*/
	guint8 src_ipv4_d1;
	guint8 src_ipv4_d2;
	guint8 src_ipv4_d3;
	guint8 src_ipv4_d4;
	port_type ptype; /* epan/address.h port_type valid for both src and dst*/
	guint32 src_port;
	guint8 dst_ipv4_d1;
	guint8 dst_ipv4_d2;
	guint8 dst_ipv4_d3;
	guint8 dst_ipv4_d4;
	guint32 dst_port;
	char* proto_col_str;
}exported_pdu_info_t ;

/* From epan/epxported_pdu.h*/
#define EXP_PDU_TAG_END_OF_OPT         0 /**< End-of-options Tag. */
/* 1 - 9 reserved */
#define EXP_PDU_TAG_OPTIONS_LENGTH    10 /**< Total length of the options excluding this TLV */
#define EXP_PDU_TAG_PROTO_NAME        12 /**< The value part should be an ASCII non NULL terminated string
* of the registered dissector used by Wireshark e.g "sip"
* Will be used to call the next dissector.
*/
#define EXP_PDU_TAG_DISSECTOR_TABLE_NAME 14 /**< The value part should be an ASCII non NULL terminated string
* containing the dissector table name given
* during registration, e.g "gsm_map.v3.arg.opcode"
* Will be used to call the next dissector.
*/

#define EXP_PDU_TAG_IPV4_SRC        20
#define EXP_PDU_TAG_IPV4_DST        21
#define EXP_PDU_TAG_SRC_PORT        25
#define EXP_PDU_TAG_PORT_TYPE       24  /**< value part is port_type enum from epan/address.h */
#define EXP_PDU_TAG_DST_PORT        26
#define EXP_PDU_TAG_SS7_OPC         28
#define EXP_PDU_TAG_SS7_DPC         29

#define EXP_PDU_TAG_ORIG_FNO        30

#define EXP_PDU_TAG_DVBCI_EVT       31

#define EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL 32 /**< value part is the numeric value to be used calling the dissector table
*  given with tag EXP_PDU_TAG_DISSECTOR_TABLE_NAME, must follow emediatly after the table tag.
*/

#define EXP_PDU_TAG_COL_PROT_TEXT   33 /**< Text string to put in COL_PROTOCOL, one use case is in conjunction with dissector tables where 
*   COL_PROTOCOL might not be filled in.
*/

#define EXP_PDU_TAG_IP_SRC_BIT          0x01
#define EXP_PDU_TAG_IP_DST_BIT          0x02
#define EXP_PDU_TAG_SRC_PORT_BIT        0x04
#define EXP_PDU_TAG_DST_PORT_BIT        0x08
#define EXP_PDU_TAG_SS7_OPC_BIT         0x20
#define EXP_PDU_TAG_SS7_DPC_BIT         0x40
#define EXP_PDU_TAG_ORIG_FNO_BIT        0x80

/* 2nd byte of optional tags bitmap */
#define EXP_PDU_TAG_DVBCI_EVT_BIT       0x0100
#define EXP_PDU_TAG_COL_PROT_BIT        0x0200

#define EXP_PDU_TAG_IPV4_SRC_LEN        4
#define EXP_PDU_TAG_IPV4_DST_LEN        4
#define EXP_PDU_TAG_PORT_TYPE_LEN       4
#define EXP_PDU_TAG_SRC_PORT_LEN        4
#define EXP_PDU_TAG_DST_PORT_LEN        4


static gboolean
nettrace_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	struct Buffer               *frame_buffer_saved;
	gboolean result;

	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;

	frame_buffer_saved = file_info->wth_tmp_file->frame_buffer;
	file_info->wth_tmp_file->frame_buffer = wth->frame_buffer;
	/* we read the created pcapng file instead */
	result =  wtap_read(file_info->wth_tmp_file, err, err_info, data_offset);
	file_info->wth_tmp_file->frame_buffer = frame_buffer_saved;
	if (!result)
		return result;
	wth->phdr.rec_type = file_info->wth_tmp_file->phdr.rec_type;
	wth->phdr.presence_flags = file_info->wth_tmp_file->phdr.presence_flags;
	wth->phdr.ts = file_info->wth_tmp_file->phdr.ts;
	wth->phdr.caplen = file_info->wth_tmp_file->phdr.caplen;
	wth->phdr.len = file_info->wth_tmp_file->phdr.len;
	wth->phdr.pkt_encap = file_info->wth_tmp_file->phdr.pkt_encap;
	wth->phdr.pkt_tsprec = file_info->wth_tmp_file->phdr.pkt_tsprec;
	wth->phdr.interface_id = file_info->wth_tmp_file->phdr.interface_id;
	wth->phdr.opt_comment = file_info->wth_tmp_file->phdr.opt_comment;
	wth->phdr.drop_count = file_info->wth_tmp_file->phdr.drop_count;
	wth->phdr.pack_flags = file_info->wth_tmp_file->phdr.pack_flags;
	wth->phdr.ft_specific_data = file_info->wth_tmp_file->phdr.ft_specific_data;

	return result;
}

static gboolean
nettrace_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
	struct Buffer               *frame_buffer_saved;
	gboolean result;
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;

	frame_buffer_saved = file_info->wth_tmp_file->frame_buffer;
	file_info->wth_tmp_file->frame_buffer = wth->frame_buffer;

	result = wtap_seek_read(file_info->wth_tmp_file, seek_off, phdr, buf, err, err_info);
	file_info->wth_tmp_file->frame_buffer = frame_buffer_saved;

	return result;
}

/* classic wtap: close capture file */
static void
nettrace_close(wtap *wth)
{
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;

	wtap_close(file_info->wth_tmp_file);

	/* delete the temp file */
	ws_unlink(file_info->tmpname);

}

/* This attribute specification contains a timestamp that refers to the start of the
* first trace data that is stored in this file.
*
* It is a complete timestamp including day, time and delta UTC hour. E.g.
* "2001-09-11T09:30:47-05:00".
*/

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

static guint8*
nettrace_parse_begin_time(guint8 *curr_pos, struct wtap_pkthdr *phdr)
{
	/* Time vars*/
	guint year, month, day, hour, minute, second, ms;
	int UTCdiffh;
	guint UTCdiffm;
	int scan_found;
	static const guint days_in_month[12] = {
	    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};
	struct tm tm;
	guint8 *prev_pos, *next_pos;
	int length;

	prev_pos = curr_pos;
	next_pos = strstr(curr_pos, "\"/>");
	length = (int)(next_pos - prev_pos);

	if (length < 2) {
		return next_pos + 3;
	}
	/* Scan for all fields                                  */
	scan_found = sscanf(curr_pos, "%4u-%2u-%2uT%2u:%2u:%2u%3d:%2u",
		&year, &month, &day, &hour, &minute, &second, &UTCdiffh, &UTCdiffm);

	phdr->ts.nsecs = 0;
	if (scan_found != 8) {
		/* Found this format in a file:
		* beginTime="2013-09-11T15:45:00,666+02:00"/>
		*/
		scan_found = sscanf(curr_pos, "%4u-%2u-%2uT%2u:%2u:%2u,%3u%3d:%2u",
			&year, &month, &day, &hour, &minute, &second, &ms, &UTCdiffh, &UTCdiffm);

		if (scan_found == 9) {
			phdr->ts.nsecs = ms * 1000;
			/* Use the code below to set the time stamp */
			scan_found = 8;
		} else {
			phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
			phdr->ts.secs = 0;
			phdr->ts.nsecs = 0;
			g_warning("Failed to parse second time format, scan_found %u", scan_found);
			return curr_pos;
		}
	}
	if (scan_found == 8) {
		guint UTCdiffsec;
		/* Only set time if we managed to parse it*/
		/* Fill in remaining fields and return it in a time_t */
		tm.tm_year = year - 1900;
		if (month < 1 || month > 12) {
			phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
			phdr->ts.secs = 0;
			phdr->ts.nsecs = 0;
			g_warning("Failed to parse time, month is %u", month);
			return curr_pos;
		}
		tm.tm_mon = month - 1; /* Zero count*/
		if (day > ((month == 2 && isleap(year)) ? 29 : days_in_month[month - 1])) {
			phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
			phdr->ts.secs = 0;
			phdr->ts.nsecs = 0;
			g_warning("Failed to parse time, %u-%02u-%2u is not a valid day",
			    year, month, day);
			return curr_pos;
		}
		tm.tm_mday = day;
		if (hour > 23) {
			phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
			phdr->ts.secs = 0;
			phdr->ts.nsecs = 0;
			g_warning("Failed to parse time, hour is %u", hour);
			return curr_pos;
		}
		tm.tm_hour = hour;
		if (minute > 59) {
			phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
			phdr->ts.secs = 0;
			phdr->ts.nsecs = 0;
			g_warning("Failed to parse time, minute is %u", minute);
			return curr_pos;
		}
		tm.tm_min = minute;
		if (second > 60) {
			/*
			 * Yes, 60, for leap seconds - POSIX's and Windows'
			 * refusal to believe in them nonwithstanding.
			 */
			phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
			phdr->ts.secs = 0;
			phdr->ts.nsecs = 0;
			g_warning("Failed to parse time, second is %u", second);
			return curr_pos;
		}
		tm.tm_sec = second;
		tm.tm_isdst = -1;    /* daylight saving time info not known */

							 /* Get seconds from this time */
		phdr->presence_flags = WTAP_HAS_TS;
		phdr->ts.secs = mktime(&tm);

		UTCdiffsec = (abs(UTCdiffh) * 60 * 60) + (UTCdiffm * 60);

		if (UTCdiffh < 0) {
			phdr->ts.secs = phdr->ts.secs - UTCdiffsec;
		} else {
			phdr->ts.secs = phdr->ts.secs + UTCdiffsec;
		}
	} else {
		g_warning("Failed to parse time, only %u fields", scan_found);
		phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
		phdr->ts.secs = 0;
		phdr->ts.nsecs = 0;
	}

	return curr_pos;
}
/* Parsing something like
 * <rawMsg
 *   protocol="Diameter"
 *   version="1">
 *    [truncated]010001244000012C01000...
 * </rawMsg>
 */
static wtap_open_return_val
write_packet_data(wtap_dumper *wdh, struct wtap_pkthdr *phdr, int *err, gchar **err_info, guint8 *file_buf, time_t start_time, int ms, exported_pdu_info_t *exported_pdu_info, char name_str[64])
{
	char *curr_pos, *next_pos;
	char proto_name_str[16];
	char dissector_table_str[32];
	int dissector_table_val=0;
	int tag_str_len = 0;
	int proto_str_len, dissector_table_str_len, raw_data_len, pkt_data_len,  exp_pdu_tags_len, i, j;
	guint8 *packet_buf;
	gchar chr;
	gint val1, val2;
	gboolean port_type_defined = FALSE;
	gboolean use_proto_table = FALSE;

	memset(proto_name_str, 0, sizeof(proto_name_str));
	/* Extract the protocol name */
	curr_pos = strstr(file_buf, "protocol=\"");
	if (!curr_pos){
		return WTAP_OPEN_ERROR;
	}
	curr_pos = curr_pos + 10;
	next_pos = strstr(curr_pos, "\"");
	proto_str_len = (int)(next_pos - curr_pos);
	if (proto_str_len > 15){
		return WTAP_OPEN_ERROR;
	}

	g_strlcpy(proto_name_str, curr_pos, proto_str_len+1);
	ascii_strdown_inplace(proto_name_str);

	/* Do string matching and replace with Wiresharks protocol name */
	if (strcmp(proto_name_str, "gtpv2-c") == 0){
		/* Change to gtpv2 */
		proto_name_str[5] = '\0';
		proto_name_str[6] = '\0';
		proto_str_len = 5;
	}
	/* XXX Do we need to check for function="S1" */
	if (strcmp(proto_name_str, "nas") == 0){
		/* Change to nas-eps_plain */
		g_strlcpy(proto_name_str, "nas-eps_plain", 14);
		proto_name_str[13] = '\0';
		proto_str_len = 13;
	}
	if (strcmp(proto_name_str, "map") == 0) {
		/* For /GSM) map, it looks like the message data is stored like SendAuthenticationInfoArg
		 * use the GSM MAP dissector table to dissect the content.
		 */
		exported_pdu_info->proto_col_str = g_strdup("GSM MAP");

		if (strcmp(name_str, "sai_request") == 0) {
			use_proto_table = TRUE;
			g_strlcpy(dissector_table_str, "gsm_map.v3.arg.opcode", 22);
			dissector_table_str[21] = '\0';
			dissector_table_str_len = 21;
			dissector_table_val = 56;
			exported_pdu_info->precense_flags = exported_pdu_info->precense_flags + EXP_PDU_TAG_COL_PROT_BIT;
		}
		else if (strcmp(name_str, "sai_response") == 0) {
			use_proto_table = TRUE;
			g_strlcpy(dissector_table_str, "gsm_map.v3.res.opcode", 22);
			dissector_table_str[21] = '\0';
			dissector_table_str_len = 21;
			dissector_table_val = 56;
			exported_pdu_info->precense_flags = exported_pdu_info->precense_flags + EXP_PDU_TAG_COL_PROT_BIT;
		}
	}
	/* Find the start of the raw data*/
	curr_pos = strstr(next_pos, ">") + 1;
	next_pos = strstr(next_pos, "<");

	raw_data_len = (int)(next_pos - curr_pos);

	/* Calculate the space needed for exp pdu tags*/
	if (use_proto_table == FALSE) {
		tag_str_len = (proto_str_len + 3) & 0xfffffffc;
		exp_pdu_tags_len = tag_str_len + 4;
	} else {
		tag_str_len = (dissector_table_str_len + 3) & 0xfffffffc;
		exp_pdu_tags_len = tag_str_len + 4;
		/* Add EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL + length*/
		exp_pdu_tags_len = exp_pdu_tags_len + 4 + 4;
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_COL_PROT_BIT) == EXP_PDU_TAG_COL_PROT_BIT) {
		exp_pdu_tags_len += 4 + (int)strlen(exported_pdu_info->proto_col_str);
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_IP_SRC_BIT) == EXP_PDU_TAG_IP_SRC_BIT) {
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_IPV4_SRC_LEN;
	}
	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_SRC_PORT_BIT) == EXP_PDU_TAG_SRC_PORT_BIT) {
		if (!port_type_defined) {
			exp_pdu_tags_len += 4 + EXP_PDU_TAG_PORT_TYPE_LEN;
			port_type_defined = TRUE;
		}
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_SRC_PORT_LEN;
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_IP_DST_BIT) == EXP_PDU_TAG_IP_DST_BIT) {
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_IPV4_DST_LEN;
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_DST_PORT_BIT) == EXP_PDU_TAG_DST_PORT_BIT) {
		if (!port_type_defined) {
			exp_pdu_tags_len += 4 + EXP_PDU_TAG_PORT_TYPE_LEN;
		}
		exp_pdu_tags_len += 4 + EXP_PDU_TAG_SRC_PORT_LEN;
	}

	port_type_defined = FALSE;

	/* Allocate the packet buf */
	pkt_data_len = raw_data_len / 2;
	packet_buf = (guint8 *)g_malloc0(pkt_data_len + exp_pdu_tags_len +4);

	/* Fill packet buff */
	if (use_proto_table == FALSE) {
		packet_buf[0] = 0;
		packet_buf[1] = 12; /* EXP_PDU_TAG_PROTO_NAME */
		packet_buf[2] = 0;
		packet_buf[3] = tag_str_len;
		for (i = 4, j = 0; j < tag_str_len; i++, j++) {
			packet_buf[i] = proto_name_str[j];
		}
	}else{
		packet_buf[0] = 0;
		packet_buf[1] = 14; /* EXP_PDU_TAG_DISSECTOR_TABLE_NAME */
		packet_buf[2] = 0;
		packet_buf[3] = tag_str_len;
		for (i = 4, j = 0; j < tag_str_len; i++, j++) {
			packet_buf[i] = dissector_table_str[j];
		}
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = 4; /* tag length */;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = dissector_table_val;
		i++;
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_COL_PROT_BIT) == EXP_PDU_TAG_COL_PROT_BIT) {
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_COL_PROT_TEXT;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = (guint8)strlen(exported_pdu_info->proto_col_str);
		i++;
		for (j = 0; j < (int)strlen(exported_pdu_info->proto_col_str); i++, j++) {
			packet_buf[i] = exported_pdu_info->proto_col_str[j];
		}
		g_free(exported_pdu_info->proto_col_str);
	}


	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_IP_SRC_BIT) == EXP_PDU_TAG_IP_SRC_BIT) {
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_IPV4_SRC;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_IPV4_SRC_LEN; /* tag length */;
		i++;
		packet_buf[i] = exported_pdu_info->src_ipv4_d1;
		i++;
		packet_buf[i] = exported_pdu_info->src_ipv4_d2;
		i++;
		packet_buf[i] = exported_pdu_info->src_ipv4_d3;
		i++;
		packet_buf[i] = exported_pdu_info->src_ipv4_d4;
		i++;
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_SRC_PORT_BIT) == EXP_PDU_TAG_SRC_PORT_BIT) {
		if (!port_type_defined) {
			port_type_defined = TRUE;
			packet_buf[i] = 0;
			i++;
			packet_buf[i] = EXP_PDU_TAG_PORT_TYPE;
			i++;
			packet_buf[i] = 0;
			i++;
			packet_buf[i] = EXP_PDU_TAG_PORT_TYPE_LEN; /* tag length */;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0xff000000) >> 24;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0x00ff0000) >> 16;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0x0000ff00) >> 8;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0x000000ff);
			i++;
		}
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_SRC_PORT;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_SRC_PORT_LEN; /* tag length */;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0xff000000) >> 24;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0x00ff0000) >> 16;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0x0000ff00) >> 8;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0x000000ff);
		i++;
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_IP_DST_BIT) == EXP_PDU_TAG_IP_DST_BIT) {
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_IPV4_DST;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_IPV4_DST_LEN; /* tag length */;
		i++;
		packet_buf[i] = exported_pdu_info->dst_ipv4_d1;
		i++;
		packet_buf[i] = exported_pdu_info->dst_ipv4_d2;
		i++;
		packet_buf[i] = exported_pdu_info->dst_ipv4_d3;
		i++;
		packet_buf[i] = exported_pdu_info->dst_ipv4_d4;
		i++;
	}

	if ((exported_pdu_info->precense_flags & EXP_PDU_TAG_DST_PORT_BIT) == EXP_PDU_TAG_DST_PORT_BIT) {
		if (!port_type_defined) {
			packet_buf[i] = 0;
			i++;
			packet_buf[i] = EXP_PDU_TAG_PORT_TYPE;
			i++;
			packet_buf[i] = 0;
			i++;
			packet_buf[i] = EXP_PDU_TAG_PORT_TYPE_LEN; /* tag length */;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0xff000000) >> 24;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0x00ff0000) >> 16;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0x0000ff00) >> 8;
			i++;
			packet_buf[i] = (exported_pdu_info->ptype & 0x000000ff);
			i++;
		}
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_DST_PORT;
		i++;
		packet_buf[i] = 0;
		i++;
		packet_buf[i] = EXP_PDU_TAG_DST_PORT_LEN; /* tag length */;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0xff000000) >> 24;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0x00ff0000) >> 16;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0x0000ff00) >> 8;
		i++;
		packet_buf[i] = (exported_pdu_info->src_port & 0x000000ff);
		i++;
	}

	/* Add end of options */
	packet_buf[i] = 0;
	i++;
	packet_buf[i] = 0;
	i++;
	packet_buf[i] = 0;
	i++;
	packet_buf[i] = 0;
	i++;
	exp_pdu_tags_len = exp_pdu_tags_len + 4;

	/* Convert the hex raw msg data to binary and write to the packet buf*/
	for (; i < (pkt_data_len + exp_pdu_tags_len); i++){
		chr = *curr_pos;
		val1 = g_ascii_xdigit_value(chr);
		curr_pos++;
		chr = *curr_pos;
		val2 = g_ascii_xdigit_value(chr);
		if ((val1 != -1) && (val2 != -1)){
			packet_buf[i] = ((guint8)val1 * 16) + val2;
		}
		else{
			/* Something wrong, bail out */
			g_free(packet_buf);
			return WTAP_OPEN_ERROR;
		}
		curr_pos++;
	}
	/* Construct the phdr */
	memset(phdr, 0, sizeof(struct wtap_pkthdr));
	phdr->rec_type = REC_TYPE_PACKET;
	if (start_time == 0) {
		phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
		phdr->ts.secs = 0;
		phdr->ts.nsecs = 0;
	} else {
		phdr->presence_flags = WTAP_HAS_TS;
		phdr->ts.secs = start_time;
		phdr->ts.nsecs = ms * 1000000;
	}

	phdr->caplen = pkt_data_len + exp_pdu_tags_len;
	phdr->len = pkt_data_len + exp_pdu_tags_len;

	if (!wtap_dump(wdh, phdr, packet_buf, err, err_info)) {
		switch (*err) {

		case WTAP_ERR_UNWRITABLE_REC_DATA:
			g_free(err_info);
			break;

		default:
			break;
		}
		g_free(packet_buf);
		return WTAP_OPEN_ERROR;
	}

	g_free(packet_buf);
	return WTAP_OPEN_MINE;
}

/*
 * Opens an .xml file with Trace data formated according to 3GPP TS 32.423 and converts it to
 * an "Exported PDU type file with the entire xml file as the first "packet" appending the
 * raw messages as subsequent packages to be dissected by wireshark.
 */
static wtap_open_return_val
create_temp_pcapng_file(wtap *wth, int *err, gchar **err_info, nettrace_3gpp_32_423_file_info_t *file_info)
{
	int import_file_fd;
	wtap_dumper* wdh_exp_pdu;
	int   exp_pdu_file_err;
	wtap_open_return_val result = WTAP_OPEN_MINE;

	/* pcapng defs */
	GArray                      *shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
	wtap_block_t                 shb_hdr;
	wtapng_iface_descriptions_t *idb_inf = NULL;
	wtap_block_t                 int_data;
	wtapng_if_descr_mandatory_t *int_data_mand;
	GString                     *os_info_str;
	gint64 file_size;
	int packet_size;
	guint8 *packet_buf = NULL;
	int wrt_err;
	gchar *wrt_err_info = NULL;
	struct wtap_pkthdr phdr;
	time_t start_time;
	int scan_found;
	unsigned second, ms;
	gboolean do_random = FALSE;
	char *curr_pos, *next_msg_pos, *next_pos, *prev_pos;
	int name_str_len;
	char name_str[64];
	gsize opt_len;
	gchar *opt_str;
	/* Info to build exported_pdu tags*/
	exported_pdu_info_t  exported_pdu_info;

	exported_pdu_info.precense_flags = 0;
	exported_pdu_info.src_ipv4_d1 = 0;
	exported_pdu_info.src_ipv4_d2 = 0;
	exported_pdu_info.src_ipv4_d3 = 0;
	exported_pdu_info.src_ipv4_d4 = 0;
	exported_pdu_info.ptype = PT_NONE;
	exported_pdu_info.src_port = 0;
	exported_pdu_info.dst_ipv4_d1 = 0;
	exported_pdu_info.dst_ipv4_d2 = 0;
	exported_pdu_info.dst_ipv4_d3 = 0;
	exported_pdu_info.dst_ipv4_d4 = 0;
	exported_pdu_info.dst_port = 0;
	exported_pdu_info.proto_col_str = NULL;

	import_file_fd = create_tempfile(&(file_info->tmpname), "Wireshark_PDU_", NULL);

	/* Now open a file and dump to it */
	/* Create data for SHB  */
	os_info_str = g_string_new("");
	get_os_version_info(os_info_str);

	shb_hdr = wtap_block_create(WTAP_BLOCK_NG_SECTION);
	/* options */
	wtap_block_add_string_option(shb_hdr, OPT_COMMENT, "File converted to Exported PDU format during opening",
															strlen("File converted to Exported PDU format during opening"));
	/*
	* UTF-8 string containing the name of the operating system used to create
	* this section.
	*/
	opt_len = os_info_str->len;
	opt_str = g_string_free(os_info_str, FALSE);
	if (opt_str) {
		wtap_block_add_string_option(shb_hdr, OPT_SHB_OS, opt_str, opt_len);
		g_free(opt_str);
	}

	/*
	* UTF-8 string containing the name of the application used to create
	* this section.
	*/
	wtap_block_add_string_option_format(shb_hdr, OPT_SHB_USERAPPL, "Wireshark %s", get_ws_vcs_version_info());

	/* Add header to the array */
	g_array_append_val(shb_hdrs, shb_hdr);


	/* Create fake IDB info */
	idb_inf = g_new(wtapng_iface_descriptions_t, 1);
	idb_inf->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

	/* create the fake interface data */
	int_data = wtap_block_create(WTAP_BLOCK_IF_DESCR);
	int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
	int_data_mand->wtap_encap = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
	int_data_mand->time_units_per_second = 1000000; /* default microsecond resolution */
	int_data_mand->link_type = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_WIRESHARK_UPPER_PDU);
	int_data_mand->snap_len = WTAP_MAX_PACKET_SIZE;
	wtap_block_add_string_option(int_data, OPT_IDB_NAME, "Fake IF", strlen("Fake IF"));
	int_data_mand->num_stat_entries = 0;          /* Number of ISB:s */
	int_data_mand->interface_statistics = NULL;

	g_array_append_val(idb_inf->interface_data, int_data);

	wdh_exp_pdu = wtap_dump_fdopen_ng(import_file_fd, WTAP_FILE_TYPE_SUBTYPE_PCAPNG, WTAP_ENCAP_WIRESHARK_UPPER_PDU,
					  WTAP_MAX_PACKET_SIZE, FALSE, shb_hdrs, idb_inf, NULL, &exp_pdu_file_err);
	if (wdh_exp_pdu == NULL) {
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* OK we've opend a new pcap-ng file and written the headers, time to do the packets, strt by finding the file size */

	if ((file_size = wtap_file_size(wth, err)) == -1) {
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	if (file_size > MAX_FILE_SIZE) {
		/*
		* Don't blow up trying to allocate space for an
		* immensely-large file.
		*/
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("mime_file: File has %" G_GINT64_MODIFIER "d-byte packet, bigger than maximum of %u",
			file_size, MAX_FILE_SIZE);
		result = WTAP_OPEN_ERROR;
		goto end;
	}
	packet_size = (int)file_size;
	/* Allocate the packet buffer
	* (the whole file + Exported PDU tag "protocol" and
	* the string "xml" + 1 filler to end on 4 byte boundary for the tag
	* + End of options 4 bytes
	*/
	/* XXX add the length of exported bdu tag(s) here */
	packet_buf = (guint8 *)g_malloc(packet_size + 12 + 1);

	packet_buf[0] = 0;
	packet_buf[1] = EXP_PDU_TAG_PROTO_NAME;
	packet_buf[2] = 0;
	packet_buf[3] = 4;
	packet_buf[4] = 'x';
	packet_buf[5] = 'm';
	packet_buf[6] = 'l';
	packet_buf[7] = 0;
	/* End of options */
	packet_buf[8] = 0;
	packet_buf[9] = 0;
	packet_buf[10] = 0;
	packet_buf[11] = 0;

	if (!wtap_read_bytes(wth->fh, packet_buf + 12, packet_size, &wrt_err, &wrt_err_info)){
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* Null-terminate buffer; we'll be processing it as a string. */
	packet_buf[packet_size + 12] = '\0';

	/* Create the packet header */
	memset(&phdr, 0, sizeof(struct wtap_pkthdr));

	/* Read the file header of the input file, currently we only need the beginTime*/

	/* Advance *packet_buf to point at the raw file data */
	curr_pos = packet_buf + 12;
	/* Find the file header */
	curr_pos = strstr(curr_pos, "<fileHeader");
	curr_pos = curr_pos + 11;

	/* Find start time */
	curr_pos = strstr(curr_pos, "<traceCollec beginTime=\"");
	curr_pos = curr_pos + 24;

	curr_pos = nettrace_parse_begin_time(curr_pos, &phdr);

	start_time = phdr.ts.secs;

	/* set rest of the pkt hdr data */
	phdr.rec_type = REC_TYPE_PACKET;

	phdr.caplen = packet_size + 12;
	phdr.len = packet_size + 12;

	/* XXX: report errors! */
	if (!wtap_dump(wdh_exp_pdu, &phdr, packet_buf, &wrt_err, &wrt_err_info)) {
		switch (wrt_err) {

		case WTAP_ERR_UNWRITABLE_REC_DATA:
			g_free(wrt_err_info);
			wrt_err_info = NULL;
			break;

		default:
			break;
		}
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* Lets add the raw messages as packets after the main "packet" with the whole file */
	while ((curr_pos = strstr(curr_pos, "<msg")) != NULL){
		wtap_open_return_val temp_val;
		/* Clear for each itteration */
		exported_pdu_info.precense_flags = 0;
		exported_pdu_info.ptype = PT_NONE;

		curr_pos = curr_pos + 4;
		next_msg_pos = strstr(curr_pos, "</msg>");
		if (!next_msg_pos){
			/* Somethings wrong, bail out */
			break;
		}
		next_msg_pos = next_msg_pos + 6;
		/* Check if we have a time stamp "changeTime"
		 * expressed in number of seconds and milliseconds (nbsec.ms).
		 */
		prev_pos = curr_pos;
		ms = 0;
		/* See if we have a "name" */
		curr_pos = strstr(curr_pos, "name=");
		if ((curr_pos) && (curr_pos < next_msg_pos)) {
			/* extract the name */
			curr_pos = curr_pos + 6;
			next_pos = strstr(curr_pos, "\"");
			name_str_len = (int)(next_pos - curr_pos);
			if (name_str_len > 63) {
				return WTAP_OPEN_ERROR;
			}

			g_strlcpy(name_str, curr_pos, name_str_len + 1);
			ascii_strdown_inplace(name_str);

		}
		else {
			curr_pos = prev_pos;
		}
		curr_pos = strstr(curr_pos, "changeTime");
		/* Check if we have the tag or if we pased the end of the current message */
		if ((curr_pos)&&(curr_pos < next_msg_pos)){
			curr_pos = curr_pos + 12;
			scan_found = sscanf(curr_pos, "%u.%u",&second, &ms);

			if ((scan_found == 2) && (start_time != 0)) {
				start_time = start_time + second;
			}
		} else {
			curr_pos = prev_pos;
		}
		/* Check if we have "<initiator>"
		*  It might contain an address
		*/
		prev_pos = curr_pos;
		curr_pos = strstr(curr_pos, "<initiator>");
		/* Check if we have the tag or if we pased the end of the current message */
		if ((curr_pos) && (curr_pos < next_msg_pos)) {
			curr_pos = curr_pos + 11;
			next_pos = strstr(curr_pos, "</initiator>");
			/* Find address*/
			curr_pos = strstr(curr_pos, "address");
			if ((curr_pos) && (curr_pos < next_pos)) {
				guint d1, d2, d3, d4, port;
				char transp_str[5];

				curr_pos = curr_pos + 7;
				/* Excample from one trace, unsure if it's generic...
				 * {address == 192.168.73.1, port == 5062, transport == Udp}
				 */
				scan_found = sscanf(curr_pos, "%*s %3u.%3u.%3u.%3u, %*s %*s %5u, %*s %*s %4s",
					&d1, &d2, &d3, &d4, &port, transp_str);
				if (scan_found == 6) {
					exported_pdu_info.precense_flags = exported_pdu_info.precense_flags + EXP_PDU_TAG_IP_SRC_BIT + EXP_PDU_TAG_SRC_PORT_BIT;
					exported_pdu_info.src_ipv4_d1 = d1;
					exported_pdu_info.src_ipv4_d2 = d2;
					exported_pdu_info.src_ipv4_d3 = d3;
					exported_pdu_info.src_ipv4_d4 = d4;

					/* Only add port_type once */
					if(exported_pdu_info.ptype == PT_NONE){
						if (g_ascii_strncasecmp(transp_str, "udp", 3) == 0)  exported_pdu_info.ptype = PT_UDP;
						else if (g_ascii_strncasecmp(transp_str, "tcp", 3) == 0)  exported_pdu_info.ptype = PT_TCP;
						else if (g_ascii_strncasecmp(transp_str, "sctp", 4) == 0)  exported_pdu_info.ptype = PT_SCTP;
					}
					exported_pdu_info.src_port = port;
				} else {
					g_warning("scan_found:%u, %u.%u.%u.%u Port %u transport %s", scan_found, d1, d2, d3, d4, port, transp_str);
				}
			} else {
				/* address not found*/
				curr_pos = next_pos;
			}
		} else {
			/*"<initiator>" not found */
			curr_pos = prev_pos;
		}

		/* Check if we have "<target>"
		*  It might contain an address
		*/
		prev_pos = curr_pos;
		curr_pos = strstr(curr_pos, "<target>");
		/* Check if we have the tag or if we pased the end of the current message */
		if ((curr_pos) && (curr_pos < next_msg_pos)) {
			curr_pos = curr_pos + 8;
			next_pos = strstr(curr_pos, "</target>");
			/* Find address*/
			curr_pos = strstr(curr_pos, "address");
			if ((curr_pos) && (curr_pos < next_pos)) {
				guint d1, d2, d3, d4, port;
				char transp_str[5];

				curr_pos = curr_pos + 7;
				/* Excample from one trace, unsure if it's generic...
				* {address == 192.168.73.1, port == 5062, transport == Udp}
				*/
				scan_found = sscanf(curr_pos, "%*s %3u.%3u.%3u.%3u, %*s %*s %5u, %*s %*s %4s",
					&d1, &d2, &d3, &d4, &port, transp_str);
				if (scan_found == 6) {
					exported_pdu_info.precense_flags = exported_pdu_info.precense_flags + EXP_PDU_TAG_IP_DST_BIT + EXP_PDU_TAG_DST_PORT_BIT;
					exported_pdu_info.dst_ipv4_d1 = d1;
					exported_pdu_info.dst_ipv4_d2 = d2;
					exported_pdu_info.dst_ipv4_d3 = d3;
					exported_pdu_info.dst_ipv4_d4 = d4;
					/* Only add port_type once */
					if (exported_pdu_info.ptype == PT_NONE) {
						if (g_ascii_strncasecmp(transp_str, "udp", 3) == 0)  exported_pdu_info.ptype = PT_UDP;
						else if (g_ascii_strncasecmp(transp_str, "tcp", 3) == 0)  exported_pdu_info.ptype = PT_TCP;
						else if (g_ascii_strncasecmp(transp_str, "sctp", 4) == 0)  exported_pdu_info.ptype = PT_SCTP;
					}
					exported_pdu_info.dst_port = port;
				} else {
					g_warning("scan_found:%u, %u.%u.%u.%u Port %u transport %s", scan_found, d1, d2, d3, d4, port, transp_str);
				}
			}
			else {
				/* address not found */
				curr_pos = next_pos;
			}
		} else {
			/* "<target>" not found */
			curr_pos = prev_pos;
		}

		/* Do we have a raw msg?) */
		curr_pos = strstr(curr_pos, "<rawMsg");
		if (!curr_pos){
			/* No rawMsg, continue */
			curr_pos = next_msg_pos;
			continue;
		}
		curr_pos = curr_pos + 7;
		/* Add the raw msg*/
		temp_val = write_packet_data(wdh_exp_pdu, &phdr, &wrt_err, &wrt_err_info, curr_pos, start_time, ms, &exported_pdu_info, name_str);
		if (temp_val != WTAP_OPEN_MINE){
			result = temp_val;
			goto end;
		}
		curr_pos = next_msg_pos;
	}

	/* Close the written file*/
	if (!wtap_dump_close(wdh_exp_pdu, err)){
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* Now open the file for reading */

	/* Find out if random read was requested */
	if (wth->random_fh){
		do_random = TRUE;
	}
	file_info->wth_tmp_file =
		wtap_open_offline(file_info->tmpname, WTAP_TYPE_AUTO, err, err_info, do_random);

	if (!file_info->wth_tmp_file){
		result = WTAP_OPEN_ERROR;
		goto end;
	}

end:
	g_free(wrt_err_info);
	g_free(packet_buf);
	wtap_block_array_free(shb_hdrs);
	wtap_free_idb_info(idb_inf);

	return result;
}

wtap_open_return_val
nettrace_3gpp_32_423_file_open(wtap *wth, int *err, gchar **err_info)
{
	char magic_buf[512+1]; /* increase buffer size when needed */
	int bytes_read;
	char *curr_pos;
	nettrace_3gpp_32_423_file_info_t *file_info;
	wtap_open_return_val temp_val;


	bytes_read = file_read(magic_buf, 512, wth->fh);

	if (bytes_read < 0) {
		*err = file_error(wth->fh, err_info);
		return WTAP_OPEN_ERROR;
	}
	if (bytes_read == 0){
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(magic_buf, xml_magic, sizeof(xml_magic)) != 0){
		return WTAP_OPEN_NOT_MINE;
	}

	/* Null-terminate buffer; we'll be processing it as a string. */
	magic_buf[512] = '\0';

	/* File header should contain something like fileFormatVersion="32.423 V8.1.0" */
	curr_pos = strstr(magic_buf, "fileFormatVersion");

	if (!curr_pos){
		return WTAP_OPEN_NOT_MINE;
	}
	curr_pos += 19;
	if (memcmp(curr_pos, Threegpp_doc_no, sizeof(Threegpp_doc_no)) != 0){
		return WTAP_OPEN_NOT_MINE;
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Ok it's our file, open a temp file and do the conversion */
	file_info = g_new0(nettrace_3gpp_32_423_file_info_t, 1);
	temp_val = create_temp_pcapng_file(wth, err, err_info, file_info);

	if (temp_val != WTAP_OPEN_MINE){
		return temp_val;
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Copy data from the temp file wth */
	wtap_block_copy(g_array_index(wth->shb_hdrs, wtap_block_t, 0), g_array_index(file_info->wth_tmp_file->shb_hdrs, wtap_block_t, 0));

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_NETTRACE_3GPP_32_423;
	wth->file_encap = file_info->wth_tmp_file->file_encap;
	wth->file_tsprec = file_info->wth_tmp_file->file_tsprec;
	wth->subtype_read = nettrace_read;
	wth->subtype_seek_read = nettrace_seek_read;
	wth->subtype_close = nettrace_close;
	wth->snapshot_length = 0;

	wth->priv = (void*)file_info;

	return WTAP_OPEN_MINE;

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
