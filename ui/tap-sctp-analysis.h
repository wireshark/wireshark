/*
 * Copyright 2004-2013, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __TAP_SCTP_ANALYSIS_H__
#define __TAP_SCTP_ANALYSIS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <epan/dissectors/packet-sctp.h>
#include <epan/address.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#endif

#define SCTP_DATA_CHUNK_ID               0
#define SCTP_INIT_CHUNK_ID               1
#define SCTP_INIT_ACK_CHUNK_ID           2
#define SCTP_SACK_CHUNK_ID               3
#define SCTP_HEARTBEAT_CHUNK_ID          4
#define SCTP_HEARTBEAT_ACK_CHUNK_ID      5
#define SCTP_ABORT_CHUNK_ID              6
#define SCTP_SHUTDOWN_CHUNK_ID           7
#define SCTP_SHUTDOWN_ACK_CHUNK_ID       8
#define SCTP_ERROR_CHUNK_ID              9
#define SCTP_COOKIE_ECHO_CHUNK_ID       10
#define SCTP_COOKIE_ACK_CHUNK_ID        11
#define SCTP_ECNE_CHUNK_ID              12
#define SCTP_CWR_CHUNK_ID               13
#define SCTP_SHUTDOWN_COMPLETE_CHUNK_ID 14
#define SCTP_AUTH_CHUNK_ID              15
#define SCTP_NR_SACK_CHUNK_ID           16
#define SCTP_ASCONF_ACK_CHUNK_ID      0x80
#define SCTP_PKTDROP_CHUNK_ID         0x81
#define SCTP_RE_CONFIG_CHUNK_ID       0x82
#define SCTP_PAD_CHUNK_ID             0x84
#define SCTP_FORWARD_TSN_CHUNK_ID     0xC0
#define SCTP_ASCONF_CHUNK_ID          0xC1
#define SCTP_IETF_EXT                 0xFF

#define IS_SCTP_CHUNK_TYPE(t) \
        (((t) <= 16) || ((t) == 0xC0) || ((t) == 0xC1) || ((t) == 0x80) || ((t) == 0x81))

#define CHUNK_TYPE_LENGTH             1
#define CHUNK_FLAGS_LENGTH            1
#define CHUNK_LENGTH_LENGTH           2

#define CHUNK_HEADER_OFFSET           0
#define CHUNK_TYPE_OFFSET             CHUNK_HEADER_OFFSET
#define CHUNK_FLAGS_OFFSET            (CHUNK_TYPE_OFFSET + CHUNK_TYPE_LENGTH)
#define CHUNK_LENGTH_OFFSET           (CHUNK_FLAGS_OFFSET + CHUNK_FLAGS_LENGTH)
#define CHUNK_VALUE_OFFSET            (CHUNK_LENGTH_OFFSET + CHUNK_LENGTH_LENGTH)

#define INIT_CHUNK_INITIATE_TAG_LENGTH               4
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH      4
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH 2
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH  2


#define INIT_CHUNK_INITIATE_TAG_OFFSET               CHUNK_VALUE_OFFSET
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET      (INIT_CHUNK_INITIATE_TAG_OFFSET + \
                                                      INIT_CHUNK_INITIATE_TAG_LENGTH )
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET (INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET + \
                                                      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH )
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET  (INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET + \
                                                      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH )
#define INIT_CHUNK_INITIAL_TSN_OFFSET                (INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET + \
                                                      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH )

#define DATA_CHUNK_TSN_LENGTH         4
#define DATA_CHUNK_TSN_OFFSET         (CHUNK_VALUE_OFFSET + 0)
#define DATA_CHUNK_STREAM_ID_OFFSET   (DATA_CHUNK_TSN_OFFSET + DATA_CHUNK_TSN_LENGTH)
#define DATA_CHUNK_STREAM_ID_LENGTH   2
#define DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH 2
#define DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH 4
#define DATA_CHUNK_HEADER_LENGTH      (CHUNK_HEADER_LENGTH + \
                                       DATA_CHUNK_TSN_LENGTH + \
                                       DATA_CHUNK_STREAM_ID_LENGTH + \
                                       DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH + \
                                       DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define MAX_ADDRESS_LEN                47

#define SCTP_ABORT_CHUNK_T_BIT        0x01

#define PARAMETER_TYPE_LENGTH            2
#define PARAMETER_LENGTH_LENGTH          2
#define PARAMETER_HEADER_LENGTH          (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET          0
#define PARAMETER_TYPE_OFFSET            PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET          (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET           (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4ADDRESS_PARAMETER_ID             0x0005
#define IPV6ADDRESS_PARAMETER_ID             0x0006

#define SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH    4
#define SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET (CHUNK_VALUE_OFFSET + 0)
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH 4
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET (SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + \
                                                 SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH)

#define INIT_CHUNK_INITIAL_TSN_LENGTH                4
#define INIT_CHUNK_FIXED_PARAMTERS_LENGTH            (INIT_CHUNK_INITIATE_TAG_LENGTH + \
                                                      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH + \
                                                      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH + \
                                                      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH + \
                                                      INIT_CHUNK_INITIAL_TSN_LENGTH)
#define CHUNK_HEADER_LENGTH           (CHUNK_TYPE_LENGTH + \
                                       CHUNK_FLAGS_LENGTH + \
                                       CHUNK_LENGTH_LENGTH)
#define INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET  (INIT_CHUNK_INITIAL_TSN_OFFSET + \
                                                      INIT_CHUNK_INITIAL_TSN_LENGTH )

static const value_string chunk_type_values[] = {
	{ SCTP_DATA_CHUNK_ID,              "DATA" },
	{ SCTP_INIT_CHUNK_ID,              "INIT" },
	{ SCTP_INIT_ACK_CHUNK_ID,          "INIT_ACK" },
	{ SCTP_SACK_CHUNK_ID,              "SACK" },
	{ SCTP_HEARTBEAT_CHUNK_ID,         "HEARTBEAT" },
	{ SCTP_HEARTBEAT_ACK_CHUNK_ID,     "HEARTBEAT_ACK" },
	{ SCTP_ABORT_CHUNK_ID,             "ABORT" },
	{ SCTP_SHUTDOWN_CHUNK_ID,          "SHUTDOWN" },
	{ SCTP_SHUTDOWN_ACK_CHUNK_ID,      "SHUTDOWN_ACK" },
	{ SCTP_ERROR_CHUNK_ID,             "ERROR" },
	{ SCTP_COOKIE_ECHO_CHUNK_ID,       "COOKIE_ECHO" },
	{ SCTP_COOKIE_ACK_CHUNK_ID,        "COOKIE_ACK" },
	{ SCTP_ECNE_CHUNK_ID,              "ECNE" },
	{ SCTP_CWR_CHUNK_ID,               "CWR" },
	{ SCTP_SHUTDOWN_COMPLETE_CHUNK_ID, "SHUTDOWN_COMPLETE" },
	{ SCTP_AUTH_CHUNK_ID,              "AUTH" },
	{ SCTP_NR_SACK_CHUNK_ID,           "NR-SACK" },
	{ SCTP_ASCONF_ACK_CHUNK_ID,        "ASCONF_ACK" },
	{ SCTP_PKTDROP_CHUNK_ID,           "PKTDROP" },
	{ SCTP_RE_CONFIG_CHUNK_ID,         "RE_CONFIG" },
	{ SCTP_PAD_CHUNK_ID,               "PAD" },
	{ SCTP_FORWARD_TSN_CHUNK_ID,       "FORWARD_TSN" },
	{ SCTP_ASCONF_CHUNK_ID,            "ASCONF" },
	{ SCTP_IETF_EXT,                   "IETF_EXTENSION" },
	{ 0,                               NULL } };

/* The below value is 255 */
#define NUM_CHUNKS  0x100

/* This variable is used as an index into arrays
 * which store the cumulative information corresponding
 * all chunks with Chunk Type greater > 16
 * The value for the below variable is 17
 */
#define OTHER_CHUNKS_INDEX	0xfe

/* VNB */
/* This variable stores the maximum chunk type value
 * that can be associated with a sctp chunk.
 */
#define MAX_SCTP_CHUNK_TYPE 256

typedef struct _tsn {
	guint32 frame_number;
	guint32 secs;    /* Absolute seconds */
	guint32 usecs;
	address src;
	address dst;
	guint32	first_tsn;
	GList   *tsns;
} tsn_t;

typedef struct _sctp_tmp_info {
	guint16 assoc_id;
	guint16 direction;
	address src;
	address dst;
	guint16 port1;
	guint16 port2;
	guint32 verification_tag1;
	guint32 verification_tag2;
	guint32 initiate_tag;
	guint32 n_tvbs;
} sctp_tmp_info_t;

typedef struct _sctp_min_max {
	guint32 tmp_min_secs;
	guint32 tmp_min_usecs;
	guint32 tmp_max_secs;
	guint32 tmp_max_usecs;
	guint32 tmp_min_tsn1;
	guint32 tmp_min_tsn2;
	guint32 tmp_max_tsn1;
	guint32 tmp_max_tsn2;
	gint    tmp_secs;
} sctp_min_max_t;

struct tsn_sort{
	guint32 tsnumber;
	guint32 secs;
	guint32 usecs;
	guint32 offset;
	guint32 length;
	guint32 framenumber;
};

typedef struct _sctp_addr_chunk {
	guint32  direction;
	address* addr;
	/* The array is initialized to MAX_SCTP_CHUNK_TYPE
	 * so that there is no memory overwrite
	 * when accessed using sctp chunk type as index.
	 */
	guint32  addr_count[MAX_SCTP_CHUNK_TYPE];
} sctp_addr_chunk;

typedef struct _sctp_assoc_info {
	guint16   assoc_id;
	address   src;
	address   dst;
	guint16   port1;
	guint16   port2;
	guint32   verification_tag1;
	guint32   verification_tag2;
	guint32   initiate_tag;
	guint32   n_tvbs;
	GList     *addr1;
	GList     *addr2;
	guint16   instream1;
	guint16   outstream1;
	guint16   instream2;
	guint16   outstream2;
	guint32   n_adler32_calculated;
	guint32   n_adler32_correct;
	guint32   n_crc32c_calculated;
	guint32   n_crc32c_correct;
	gchar     checksum_type[8];
	guint32   n_checksum_errors;
	guint32   n_bundling_errors;
	guint32   n_padding_errors;
	guint32   n_length_errors;
	guint32   n_value_errors;
	guint32   n_data_chunks;
	guint32   n_forward_chunks;
	guint32   n_forward_chunks_ep1;
	guint32   n_forward_chunks_ep2;
	guint32   n_data_bytes;
	guint32   n_packets;
	guint32   n_data_chunks_ep1;
	guint32   n_data_bytes_ep1;
	guint32   n_data_chunks_ep2;
	guint32   n_data_bytes_ep2;
	guint32   n_sack_chunks_ep1;
	guint32   n_sack_chunks_ep2;
	guint32   n_array_tsn1;
	guint32   n_array_tsn2;
	guint32   max_window1;
	guint32   max_window2;
	guint32   arwnd1;
	guint32   arwnd2;
	gboolean  init;
	gboolean  initack;
	guint16    initack_dir;
	guint16    direction;
	guint32   min_secs;
	guint32   min_usecs;
	guint32   max_secs;
	guint32   max_usecs;
	guint32   min_tsn1;
	guint32   min_tsn2;
	guint32   max_tsn1;
	guint32   max_tsn2;
	guint32   max_bytes1;
	guint32   max_bytes2;
	GSList    *min_max;
	GList     *frame_numbers;
	GList     *tsn1;
	GPtrArray *sort_tsn1;
	GPtrArray *sort_sack1;
	GList     *sack1;
	GList     *tsn2;
	GPtrArray *sort_tsn2;
	GPtrArray *sort_sack2;
	GList     *sack2;
	gboolean  check_address;
	GList*    error_info_list;
	/* The array is initialized to MAX_SCTP_CHUNK_TYPE
	 * so that there is no memory overwrite
	 * when accessed using sctp chunk type as index.
	 */
	guint32   chunk_count[MAX_SCTP_CHUNK_TYPE];
	guint32   ep1_chunk_count[MAX_SCTP_CHUNK_TYPE];
	guint32   ep2_chunk_count[MAX_SCTP_CHUNK_TYPE];
	GList*    addr_chunk_count;
} sctp_assoc_info_t;

typedef struct _sctp_error_info {
	guint32 frame_number;
	gchar   chunk_info[200];
	const gchar  *info_text;
} sctp_error_info_t;


typedef struct _sctp_allassocs_info {
	guint32  sum_tvbs;
	GList*   assoc_info_list;
	gboolean is_registered;
	GList*   children;
} sctp_allassocs_info_t;



void register_tap_listener_sctp_stat(void);

const sctp_allassocs_info_t* sctp_stat_get_info(void);

void sctp_stat_scan(void);

void remove_tap_listener_sctp_stat(void);


const sctp_assoc_info_t* get_selected_assoc(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __TAP_SCTP_ANALYSIS_H__ */
