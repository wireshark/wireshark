/** @file
 *
 * Copyright 2004-2013, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_SCTP_ANALYSIS_H__
#define __TAP_SCTP_ANALYSIS_H__

#include <stdbool.h>
#include <epan/dissectors/packet-sctp.h>
#include <epan/address.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CHUNK_TYPE_LENGTH	      1
#define CHUNK_FLAGS_LENGTH	      1
#define CHUNK_LENGTH_LENGTH	      2

#define CHUNK_HEADER_OFFSET	      0
#define CHUNK_TYPE_OFFSET	      CHUNK_HEADER_OFFSET
#define CHUNK_FLAGS_OFFSET	      (CHUNK_TYPE_OFFSET + CHUNK_TYPE_LENGTH)
#define CHUNK_LENGTH_OFFSET	      (CHUNK_FLAGS_OFFSET + CHUNK_FLAGS_LENGTH)
#define CHUNK_VALUE_OFFSET	      (CHUNK_LENGTH_OFFSET + CHUNK_LENGTH_LENGTH)

#define INIT_CHUNK_INITIATE_TAG_LENGTH		     4
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH	     4
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH 2
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH  2


#define INIT_CHUNK_INITIATE_TAG_OFFSET		     CHUNK_VALUE_OFFSET
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET	     (INIT_CHUNK_INITIATE_TAG_OFFSET + \
						      INIT_CHUNK_INITIATE_TAG_LENGTH )
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET (INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET + \
						      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH )
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET  (INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET + \
						      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH )
#define INIT_CHUNK_INITIAL_TSN_OFFSET		     (INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET + \
						      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH )

#define DATA_CHUNK_TSN_LENGTH	      4
#define DATA_CHUNK_TSN_OFFSET	      (CHUNK_VALUE_OFFSET + 0)
#define DATA_CHUNK_STREAM_ID_OFFSET   (DATA_CHUNK_TSN_OFFSET + DATA_CHUNK_TSN_LENGTH)
#define DATA_CHUNK_STREAM_ID_LENGTH   2
#define DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH 2
#define DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH 4
#define I_DATA_CHUNK_RESERVED_LENGTH 2
#define I_DATA_CHUNK_MID_LENGTH 4
#define I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH 4
#define I_DATA_CHUNK_FSN_LENGTH 4
#define I_DATA_CHUNK_RESERVED_OFFSET  (DATA_CHUNK_STREAM_ID_OFFSET + \
                                       DATA_CHUNK_STREAM_ID_LENGTH)
#define I_DATA_CHUNK_MID_OFFSET       (I_DATA_CHUNK_RESERVED_OFFSET + \
                                       I_DATA_CHUNK_RESERVED_LENGTH)
#define I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET (I_DATA_CHUNK_MID_OFFSET + \
                                                 I_DATA_CHUNK_MID_LENGTH)
#define I_DATA_CHUNK_FSN_OFFSET       (I_DATA_CHUNK_MID_OFFSET + \
                                       I_DATA_CHUNK_MID_LENGTH)
#define I_DATA_CHUNK_PAYLOAD_OFFSET   (I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET + \
                                       I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define DATA_CHUNK_HEADER_LENGTH      (CHUNK_HEADER_LENGTH + \
				       DATA_CHUNK_TSN_LENGTH + \
				       DATA_CHUNK_STREAM_ID_LENGTH + \
				       DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH + \
				       DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define I_DATA_CHUNK_HEADER_LENGTH    (CHUNK_HEADER_LENGTH + \
                                       DATA_CHUNK_TSN_LENGTH + \
                                       DATA_CHUNK_STREAM_ID_LENGTH + \
                                       I_DATA_CHUNK_RESERVED_LENGTH + \
                                       I_DATA_CHUNK_MID_LENGTH +\
                                       I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define MAX_ADDRESS_LEN		       47

#define SCTP_ABORT_CHUNK_T_BIT	      0x01

#define PARAMETER_TYPE_LENGTH		 2
#define PARAMETER_LENGTH_LENGTH		 2
#define PARAMETER_HEADER_LENGTH		 (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET		 0
#define PARAMETER_TYPE_OFFSET		 PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET		 (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET		 (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4ADDRESS_PARAMETER_ID	     0x0005
#define IPV6ADDRESS_PARAMETER_ID	     0x0006

#define SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH	4
#define SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET (CHUNK_VALUE_OFFSET + 0)
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH 4
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET (SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + \
						 SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH)

#define INIT_CHUNK_INITIAL_TSN_LENGTH		     4
#define INIT_CHUNK_FIXED_PARAMETERS_LENGTH	     (INIT_CHUNK_INITIATE_TAG_LENGTH + \
						      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH + \
						      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH + \
						      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH + \
						      INIT_CHUNK_INITIAL_TSN_LENGTH)
#define CHUNK_HEADER_LENGTH	      (CHUNK_TYPE_LENGTH + \
				       CHUNK_FLAGS_LENGTH + \
				       CHUNK_LENGTH_LENGTH)
#define INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET  (INIT_CHUNK_INITIAL_TSN_OFFSET + \
						      INIT_CHUNK_INITIAL_TSN_LENGTH )

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
	guint32	 frame_number;
	guint32	 secs;		/* Absolute seconds */
	guint32	 usecs;
	address	 src;
	address	 dst;
	guint32	 first_tsn;
	GList	*tsns;
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

typedef struct _sctp_init_collision {
	guint32 init_vtag;		/* initiate tag of the INIT chunk */
	guint32 initack_vtag;		/* initiate tag of the INIT-ACK chunk */
	guint32 init_min_tsn;		/* initial tsn of the INIT chunk */
	guint32 initack_min_tsn;	/* initial tsn of the INIT-ACK chunk */
	bool    init:1;
	bool    initack:1;
} sctp_init_collision_t;

struct tsn_sort{
	guint32 tsnumber;
	guint32 secs;
	guint32 usecs;
	guint32 offset;
	guint32 length;
	guint32 framenumber;
};

typedef struct _sctp_addr_chunk {
	guint32	 direction;
	address addr;
	/* The array is initialized to MAX_SCTP_CHUNK_TYPE
	 * so that there is no memory overwrite
	 * when accessed using sctp chunk type as index.
	 */
	guint32	 addr_count[MAX_SCTP_CHUNK_TYPE];
} sctp_addr_chunk;

typedef struct _sctp_assoc_info {
	guint16	   assoc_id;
	address	   src;
	address	   dst;
	guint16	   port1;
	guint16	   port2;
	guint32	   verification_tag1;
	guint32	   verification_tag2;
	guint32	   initiate_tag;
	guint32	   n_tvbs;
	GList	  *addr1;
	GList	  *addr2;
	guint16	   instream1;
	guint16	   outstream1;
	guint16	   instream2;
	guint16	   outstream2;
	guint32	   n_adler32_calculated;
	guint32	   n_adler32_correct;
	guint32	   n_crc32c_calculated;
	guint32	   n_crc32c_correct;
	gchar	   checksum_type[8];
	guint32	   n_checksum_errors;
	guint32	   n_bundling_errors;
	guint32	   n_padding_errors;
	guint32	   n_length_errors;
	guint32	   n_value_errors;
	guint32	   n_data_chunks;
	guint32	   n_forward_chunks;
	guint32	   n_forward_chunks_ep1;
	guint32	   n_forward_chunks_ep2;
	guint32	   n_data_bytes;
	guint32	   n_packets;
	guint32	   n_data_chunks_ep1;
	guint32	   n_data_bytes_ep1;
	guint32	   n_data_chunks_ep2;
	guint32	   n_data_bytes_ep2;
	guint32	   n_sack_chunks_ep1;
	guint32	   n_sack_chunks_ep2;
	guint32	   n_array_tsn1;
	guint32	   n_array_tsn2;
	guint32	   max_window1;
	guint32	   max_window2;
	guint32	   arwnd1;
	guint32	   arwnd2;
	bool       init:1;
	bool       initack:1;
	bool       firstdata:1;
	bool       init_collision:1;
	guint16	   initack_dir;
	guint16	   direction;
	guint32	   min_secs;
	guint32	   min_usecs;
	guint32	   max_secs;
	guint32	   max_usecs;
	guint32	   min_tsn1;
	guint32	   min_tsn2;
	guint32	   max_tsn1;
	guint32	   max_tsn2;
	guint32	   max_bytes1;
	guint32	   max_bytes2;
	sctp_init_collision_t *dir1;
	sctp_init_collision_t *dir2;
	GSList	  *min_max;
	GList	  *frame_numbers;
	GList	  *tsn1;
	GPtrArray *sort_tsn1;
	GPtrArray *sort_sack1;
	GList	  *sack1;
	GList	  *tsn2;
	GPtrArray *sort_tsn2;
	GPtrArray *sort_sack2;
	GList	  *sack2;
	gboolean   check_address;
	GList*	   error_info_list;
	/* The array is initialized to MAX_SCTP_CHUNK_TYPE
	 * so that there is no memory overwrite
	 * when accessed using sctp chunk type as index.
	 */
	guint32	   chunk_count[MAX_SCTP_CHUNK_TYPE];
	guint32	   ep1_chunk_count[MAX_SCTP_CHUNK_TYPE];
	guint32	   ep2_chunk_count[MAX_SCTP_CHUNK_TYPE];
	GList *addr_chunk_count;
} sctp_assoc_info_t;

typedef struct _sctp_error_info {
	guint32	     frame_number;
	gchar	     chunk_info[200];
	const gchar *info_text;
} sctp_error_info_t;


typedef struct _sctp_allassocs_info {
	guint32	  sum_tvbs;
	GList	 *assoc_info_list;
	gboolean  is_registered;
	GList	 *children;
} sctp_allassocs_info_t;



void register_tap_listener_sctp_stat(void);

const sctp_allassocs_info_t* sctp_stat_get_info(void);

void sctp_stat_scan(void);

void remove_tap_listener_sctp_stat(void);

const sctp_assoc_info_t* get_sctp_assoc_info(guint16 assoc_id);
const sctp_assoc_info_t* get_selected_assoc(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_SCTP_ANALYSIS_H__ */
