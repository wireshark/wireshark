/* packet-sctp.c
 * Routines for Stream Control Transmission Protocol dissection
 * Copyright 2000, Michael Tüxen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-sctp.c,v 1.8 2001/01/03 06:55:32 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>


#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "packet-ip.h"

/* Initialize the protocol and registered fields */
static int proto_sctp = -1;
static int hf_sctp_source_port      = -1;
static int hf_sctp_destination_port = -1;
static int hf_sctp_verification_tag = -1;
static int hf_sctp_checksum         = -1;

static int hf_sctp_chunk_type       = -1;
static int hf_sctp_chunk_flags      = -1;
static int hf_sctp_chunk_length     = -1;

static int hf_sctp_init_chunk_initiate_tag   = -1;
static int hf_sctp_init_chunk_adv_rec_window_credit = -1;
static int hf_sctp_init_chunk_number_of_outbound_streams = -1;
static int hf_sctp_init_chunk_number_of_inbound_streams  = -1;
static int hf_sctp_init_chunk_initial_tsn    = -1;

static int hf_sctp_cumulative_tsn_ack = -1;

static int hf_sctp_data_chunk_tsn = -1;
static int hf_sctp_data_chunk_stream_id = -1;
static int hf_sctp_data_chunk_stream_seq_number = -1;
static int hf_sctp_data_chunk_payload_proto_id = -1;

static int hf_sctp_data_chunk_e_bit = -1;
static int hf_sctp_data_chunk_b_bit = -1;
static int hf_sctp_data_chunk_u_bit = -1;

static int hf_sctp_sack_chunk_cumulative_tsn_ack = -1;
static int hf_sctp_sack_chunk_adv_rec_window_credit = -1;
static int hf_sctp_sack_chunk_number_of_gap_blocks = -1;
static int hf_sctp_sack_chunk_number_of_dup_tsns = -1;
static int hf_sctp_sack_chunk_gap_block_start = -1;
static int hf_sctp_sack_chunk_gap_block_end = -1;
static int hf_sctp_sack_chunk_duplicate_tsn = -1;

static int hf_sctp_shutdown_chunk_cumulative_tsn_ack = -1;

static int hf_sctp_cwr_chunk_lowest_tsn = -1;

static int hf_sctp_ecne_chunk_lowest_tsn = -1;

static int hf_sctp_shutdown_complete_chunk_t_bit = -1;

static int hf_sctp_chunk_parameter_type = -1;
static int hf_sctp_chunk_parameter_length = -1;
static int hf_sctp_parameter_ipv4_address = -1;
static int hf_sctp_parameter_ipv6_address = -1;
static int hf_sctp_parameter_cookie_preservative_increment = -1;
static int hf_sctp_parameter_hostname_hostname = -1;
static int hf_sctp_supported_address_types_parameter = -1;

static int hf_sctp_cause_code = -1;
static int hf_sctp_cause_length = -1;
static int hf_sctp_cause_stream_identifier = -1;

static int hf_sctp_cause_number_of_missing_parameters = -1;
static int hf_sctp_cause_missing_parameter_type = -1;

static int hf_sctp_cause_measure_of_staleness = -1;

static int hf_sctp_cause_tsn = -1;

static dissector_table_t sctp_dissector_table;

/* Initialize the subtree pointers */
static gint ett_sctp = -1;
static gint ett_sctp_chunk = -1;
static gint ett_sctp_chunk_parameter = -1;
static gint ett_sctp_chunk_cause = -1;
static gint ett_sctp_data_chunk_flags = -1;
static gint ett_sctp_sack_chunk_gap_block = -1;
static gint ett_sctp_supported_address_types_parameter = -1;
static gint ett_sctp_unrecognized_parameter_parameter = -1;

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
#define SCTP_IETF_EXT                  255

static const value_string sctp_chunk_type_values[] = {
  { SCTP_DATA_CHUNK_ID,              "DATA" },
  { SCTP_INIT_CHUNK_ID,              "INIT" },
  { SCTP_INIT_ACK_CHUNK_ID,          "INIT ACK" },
  { SCTP_SACK_CHUNK_ID,              "SACK" },
  { SCTP_HEARTBEAT_CHUNK_ID,         "HEARTBEAT" },
  { SCTP_HEARTBEAT_ACK_CHUNK_ID,     "HEARTBEAT ACK" },
  { SCTP_ABORT_CHUNK_ID,             "ABORT" },
  { SCTP_SHUTDOWN_CHUNK_ID,          "SHUTDOWN" },
  { SCTP_SHUTDOWN_ACK_CHUNK_ID,      "SHUTDOWN ACK" },
  { SCTP_ERROR_CHUNK_ID,             "ERROR" },
  { SCTP_COOKIE_ECHO_CHUNK_ID,       "COOKIE ECHO" },
  { SCTP_COOKIE_ACK_CHUNK_ID,        "COOKIE ACK" },
  { SCTP_ECNE_CHUNK_ID,              "ECNE" },
  { SCTP_CWR_CHUNK_ID,               "CWR" },
  { SCTP_SHUTDOWN_COMPLETE_CHUNK_ID, "SHUTDOWN COMPLETE" },
  { SCTP_IETF_EXT,                   "IETF EXTENSION" },
  { 0,                               NULL } };

#define HEARTBEAT_INFO_PARAMETER_ID          0x0001
#define IPV4ADDRESS_PARAMETER_ID             0x0005
#define IPV6ADDRESS_PARAMETER_ID             0x0006
#define STATE_COOKIE_PARAMETER_ID            0x0007
#define UNREC_PARA_PARAMETER_ID              0x0008
#define COOKIE_PRESERVATIVE_PARAMETER_ID     0x0009
#define HOSTNAME_ADDRESS_PARAMETER_ID        0x000b
#define SUPPORTED_ADDRESS_TYPES_PARAMETER_ID 0x000c
#define ECN_PARAMETER_ID                     0x8000

static const value_string sctp_parameter_identifier_values[] = {
  { HEARTBEAT_INFO_PARAMETER_ID,          "Heartbeat info" },
  { IPV4ADDRESS_PARAMETER_ID,             "IPv4 address" },
  { IPV6ADDRESS_PARAMETER_ID,             "IPv6 address" },
  { STATE_COOKIE_PARAMETER_ID,            "State cookie" },
  { UNREC_PARA_PARAMETER_ID,              "Unrecognized parameters" },
  { COOKIE_PRESERVATIVE_PARAMETER_ID,     "Cookie preservative" },
  { HOSTNAME_ADDRESS_PARAMETER_ID,        "Hostname address" },
  { SUPPORTED_ADDRESS_TYPES_PARAMETER_ID, "Supported address types" },
  { ECN_PARAMETER_ID,                     "ECN" },
  { 0,                                    NULL } };

#define PARAMETER_TYPE_LENGTH            2
#define PARAMETER_LENGTH_LENGTH          2
#define PARAMETER_HEADER_LENGTH          (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET          0
#define PARAMETER_TYPE_OFFSET            PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET          (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET           (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

#define HEARTBEAT_INFO_PARAMETER_INFO_OFFSET PARAMETER_VALUE_OFFSET
#define HEARTBEAT_INFO_PARAMETER_HEADER_LENGTH PARAMETER_HEADER_LENGTH

#define IPV4_ADDRESS_LENGTH              4
#define IPV6_ADDRESS_LENGTH              16

#define STATE_COOKIE_PARAMETER_HEADER_LENGTH   PARAMETER_HEADER_LENGTH
#define STATE_COOKIE_PARAMETER_COOKIE_OFFSET   PARAMETER_VALUE_OFFSET

#define COOKIE_PRESERVATIVE_PARAMETER_INCR_OFFSET PARAMETER_VALUE_OFFSET
#define COOKIE_PRESERVATIVE_PARAMETER_INCR_LENGTH 4
#define SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH 2

#define CAUSE_CODE_LENGTH            2
#define CAUSE_LENGTH_LENGTH          2
#define CAUSE_HEADER_LENGTH          (CAUSE_CODE_LENGTH + CAUSE_LENGTH_LENGTH)

#define CAUSE_HEADER_OFFSET          0
#define CAUSE_CODE_OFFSET            CAUSE_HEADER_OFFSET
#define CAUSE_LENGTH_OFFSET          (CAUSE_CODE_OFFSET + CAUSE_CODE_LENGTH)
#define CAUSE_INFO_OFFSET            (CAUSE_LENGTH_OFFSET + CAUSE_LENGTH_LENGTH)

#define CAUSE_STREAM_IDENTIFIER_LENGTH 2
#define CAUSE_RESERVED_LENGTH 2
#define CAUSE_STREAM_IDENTIFIER_OFFSET CAUSE_INFO_OFFSET
#define CAUSE_RESERVED_OFFSET          (CAUSE_STREAM_IDENTIFIER_OFFSET + CAUSE_STREAM_IDENTIFIER_LENGTH)

#define CAUSE_NUMBER_OF_MISSING_PARAMETERS_LENGTH 4
#define CAUSE_MISSING_PARAMETER_TYPE_LENGTH       2

#define CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET CAUSE_INFO_OFFSET
#define CAUSE_FIRST_MISSING_PARAMETER_TYPE_OFFSET (CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET + \
                                                   CAUSE_NUMBER_OF_MISSING_PARAMETERS_LENGTH )

#define CAUSE_MEASURE_OF_STALENESS_LENGTH 4
#define CAUSE_MEASURE_OF_STALENESS_OFFSET CAUSE_INFO_OFFSET

#define CAUSE_TSN_LENGTH 4
#define CAUSE_TSN_OFFSET CAUSE_INFO_OFFSET

#define INVALID_STREAM_IDENTIFIER              0x01
#define MISSING_MANDATORY_PARAMETERS           0x02
#define STALE_COOKIE_ERROR                     0x03
#define OUT_OF_RESOURCE                        0x04
#define UNRESOLVABLE_ADDRESS                   0x05
#define UNRECOGNIZED_CHUNK_TYPE                0x06
#define INVALID_MANDATORY_PARAMETER            0x07
#define UNRECOGNIZED_PARAMETERS                0x08
#define NO_USER_DATA                           0x09
#define COOKIE_RECEIVED_WHILE_SHUTTING_DOWN    0x0a

static const value_string sctp_cause_code_values[] = {
  { INVALID_STREAM_IDENTIFIER,           "Invalid stream idetifier" },
  { MISSING_MANDATORY_PARAMETERS,        "Missing mandator parameter" },
  { STALE_COOKIE_ERROR,                  "Stale cookie error" },
  { OUT_OF_RESOURCE,                     "Out of resource" },
  { UNRESOLVABLE_ADDRESS,                "Unresolvable address" },
  { UNRECOGNIZED_CHUNK_TYPE,             "Unrecognized chunk type " },
  { INVALID_MANDATORY_PARAMETER,         "Invalid mandatory parameter" },
  { UNRECOGNIZED_PARAMETERS,             "Unrecognized parameters" },
  { NO_USER_DATA,                        "No user data" },
  { COOKIE_RECEIVED_WHILE_SHUTTING_DOWN, "Cookie received while shutting down" },
  { 0,                           NULL } };

/* The structure of the common header is described by the following constants */
#define SOURCE_PORT_LENGTH      2
#define DESTINATION_PORT_LENGTH 2
#define VERIFICATION_TAG_LENGTH 4
#define CHECKSUM_LENGTH         4
#define COMMON_HEADER_LENGTH    (SOURCE_PORT_LENGTH + \
				 DESTINATION_PORT_LENGTH + \
				 VERIFICATION_TAG_LENGTH + \
				 CHECKSUM_LENGTH)
#define SOURCE_PORT_OFFSET      0
#define DESTINATION_PORT_OFFSET (SOURCE_PORT_OFFSET + SOURCE_PORT_LENGTH)
#define VERIFICATION_TAG_OFFSET (DESTINATION_PORT_OFFSET + DESTINATION_PORT_LENGTH)
#define CHECKSUM_OFFSET         (VERIFICATION_TAG_OFFSET + VERIFICATION_TAG_LENGTH)

/* The structure of the chunk header is described by the following constants */
#define CHUNK_TYPE_LENGTH             1
#define CHUNK_FLAGS_LENGTH            1
#define CHUNK_LENGTH_LENGTH           2
#define CHUNK_HEADER_LENGTH           (CHUNK_TYPE_LENGTH + \
                                       CHUNK_FLAGS_LENGTH + \
                                       CHUNK_LENGTH_LENGTH)
#define CHUNK_HEADER_OFFSET           0
#define CHUNK_TYPE_OFFSET             CHUNK_HEADER_OFFSET
#define CHUNK_FLAGS_OFFSET            (CHUNK_TYPE_OFFSET + CHUNK_TYPE_LENGTH)
#define CHUNK_LENGTH_OFFSET           (CHUNK_FLAGS_OFFSET + CHUNK_FLAGS_LENGTH)
#define CHUNK_VALUE_OFFSET            (CHUNK_LENGTH_OFFSET + CHUNK_LENGTH_LENGTH)

/* The following constants describe the structure of DATA chunks */
#define DATA_CHUNK_TSN_LENGTH         4
#define DATA_CHUNK_STREAM_ID_LENGTH   2
#define DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH 2
#define DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH 4

#define DATA_CHUNK_TSN_OFFSET         (CHUNK_VALUE_OFFSET + 0)
#define DATA_CHUNK_STREAM_ID_OFFSET   (DATA_CHUNK_TSN_OFFSET + DATA_CHUNK_TSN_LENGTH)
#define DATA_CHUNK_STREAM_SEQ_NUMBER_OFFSET (DATA_CHUNK_STREAM_ID_OFFSET + \
                                             DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH)
#define DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET (DATA_CHUNK_STREAM_SEQ_NUMBER_OFFSET + \
                                               DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH)
#define DATA_CHUNK_PAYLOAD_OFFSET     (DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET + \
                                       DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)

#define DATA_CHUNK_HEADER_LENGTH      (CHUNK_HEADER_LENGTH + \
                                       DATA_CHUNK_TSN_LENGTH + \
                                       DATA_CHUNK_STREAM_ID_LENGTH + \
                                       DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH + \
                                       DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)

#define SCTP_DATA_CHUNK_E_BIT 0x01
#define SCTP_DATA_CHUNK_B_BIT 0x02
#define SCTP_DATA_CHUNK_U_BIT 0x04

#define INIT_CHUNK_INITIATE_TAG_LENGTH               4
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH      4
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH 2
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH  2
#define INIT_CHUNK_INITIAL_TSN_LENGTH                4

#define INIT_CHUNK_INITIATE_TAG_OFFSET               CHUNK_VALUE_OFFSET
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET      (INIT_CHUNK_INITIATE_TAG_OFFSET + \
                                                      INIT_CHUNK_INITIATE_TAG_LENGTH )
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET (INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET + \
                                                      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH )
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET  (INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET + \
                                                      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH )
#define INIT_CHUNK_INITIAL_TSN_OFFSET                (INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET + \
                                                      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH )
#define INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET  (INIT_CHUNK_INITIAL_TSN_OFFSET + \
                                                      INIT_CHUNK_INITIAL_TSN_LENGTH )


#define SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH    4
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH 4
#define SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_LENGTH  2
#define SACK_CHUNK_NUMBER_OF_DUP_TSNS_LENGTH    2
#define SACK_CHUNK_GAP_BLOCK_LENGTH             4
#define SACK_CHUNK_GAP_BLOCK_START_LENGTH       2
#define SACK_CHUNK_GAP_BLOCK_END_LENGTH         2
#define SACK_CHUNK_DUP_TSN_LENGTH               4

#define SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET (CHUNK_VALUE_OFFSET + 0)
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET (SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + \
                                                 SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH)
#define SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET (SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET + \
                                                SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH)
#define SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET (SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET + \
                                              SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_LENGTH)
#define SACK_CHUNK_GAP_BLOCK_OFFSET (SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET + \
                                     SACK_CHUNK_NUMBER_OF_DUP_TSNS_LENGTH)

#define HEARTBEAT_CHUNK_INFO_OFFSET CHUNK_VALUE_OFFSET

#define SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET CHUNK_VALUE_OFFSET
#define SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_LENGTH 4
		
#define ABORT_CHUNK_FIRST_ERROR_CAUSE_OFFSET 4     
#define ERROR_CHUNK_FIRST_ERROR_CAUSE_OFFSET 4     

#define COOKIE_ECHO_CHUNK_COOKIE_OFFSET CHUNK_VALUE_OFFSET

#define ECNE_CHUNK_LOWEST_TSN_OFFSET CHUNK_VALUE_OFFSET
#define ECNE_CHUNK_LOWEST_TSN_LENGTH 4

#define CWR_CHUNK_LOWEST_TSN_OFFSET CHUNK_VALUE_OFFSET
#define CWR_CHUNK_LOWEST_TSN_LENGTH 4
		     
#define SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT 0x01

static const true_false_string sctp_data_chunk_e_bit_value = {
  "Last segment",
  "Not the last segment"
};

static const true_false_string sctp_data_chunk_b_bit_value = {
  "First segment",
  "Subsequent segment"
};

static const true_false_string sctp_data_chunk_u_bit_value = {
  "Unordered delivery",
  "Ordered deliviery"
};

static const true_false_string sctp_shutdown_complete_chunk_t_bit_value = {
  "No TCB destroyed",
  "TCB destroyed"
};

/* adler32.c -- compute the Adler-32 checksum of a data stream
 * Copyright (C) 1995-1996 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 * available, e.g. from  http://www.cdrom.com/pub/infozip/zlib/
 *
 * It was modified for the use in this dissector.
 */

#define BASE 65521L /* largest prime smaller than 65536      */
#define NMAX 5540   /* NMAX is the largest n - 12 such that  */
		    /* 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

#define DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

unsigned int sctp_adler_32(const unsigned char* buf,
			         unsigned int len)
{
    unsigned int s1 = 1L;
    unsigned int s2 = 0L;
    int k;
    
    /* handle the first 8 bytes of the datagram */
    DO8(buf,0);
    buf += SOURCE_PORT_LENGTH + 
           DESTINATION_PORT_LENGTH + 
           VERIFICATION_TAG_LENGTH;
    
    /* handle four 0 bytes as checksum */
    s2  += CHECKSUM_LENGTH * s1;
    buf += CHECKSUM_LENGTH;

    /* now we have 12 bytes handled */
    len -= COMMON_HEADER_LENGTH;

    /* handle the rest of the datagram */
    while (len > 0) {
        k = len < NMAX ? len : NMAX;
        len -= k;
        while (k >= 16) {
            DO16(buf);
            buf += 16;
            k -= 16;
        }
        if (k != 0) do {
            s1 += *buf++;
            s2 += s1;
        } while (--k);
        s1 %= BASE;
        s2 %= BASE;
    }
    return (s2 << 16) | s1;
}

static char *sctp_checksum_state(tvbuff_t *tvb, guint orig_checksum)
{
  guint length;
  
  length = tvb_length(tvb);
  if (orig_checksum == sctp_adler_32(tvb_get_ptr(tvb, 0, length), length))
    return "correct";
  else
    return "incorrect";
}

guint 
nr_of_padding_bytes (guint length)
{
  guint remainder;

  remainder = length % 4;

  if (remainder == 0)
    return 0;
  else
    return 4 - remainder;
}

/* 
 * TLV parameter stuff for INIT and INIT-ACK chunks
 */

void
dissect_parameter(tvbuff_t *, proto_tree *);

void
dissect_sctp_chunk(tvbuff_t *, packet_info *, proto_tree *, proto_tree *);

void dissect_tlv_parameter_list(tvbuff_t *parameter_list_tvb, proto_tree *tree)
{
  guint offset, length, padding_length, total_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while(tvb_length_remaining(parameter_list_tvb, offset)) {
    length         = tvb_get_ntohs(parameter_list_tvb, offset + PARAMETER_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the chunk including the padding bytes */
    parameter_tvb    = tvb_new_subset(parameter_list_tvb, offset, total_length, total_length);
    dissect_parameter(parameter_tvb, tree); 
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

void
dissect_heartbeat_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, heartbeat_info_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  heartbeat_info_length = length - HEARTBEAT_INFO_PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, HEARTBEAT_INFO_PARAMETER_INFO_OFFSET, heartbeat_info_length,
		      "Heartbeat info (%u byte%s)",
		      heartbeat_info_length, plurality(heartbeat_info_length, "", "s"));

  proto_item_set_text(parameter_item, "Heartbeat info parameter with %u byte%s of info",
		      heartbeat_info_length, plurality(heartbeat_info_length, "", "s"));
}

void
dissect_ipv4_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 ipv4_address;

  tvb_memcpy(parameter_tvb, (guint8 *)&ipv4_address, PARAMETER_VALUE_OFFSET, IPV4_ADDRESS_LENGTH); 
  proto_tree_add_ipv4(parameter_tree, hf_sctp_parameter_ipv4_address,
		      parameter_tvb, PARAMETER_VALUE_OFFSET, IPV4_ADDRESS_LENGTH,
		      ipv4_address);  
  proto_item_set_text(parameter_item, "IPV4 address parameter");
}

void
dissect_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_ipv6(parameter_tree, hf_sctp_parameter_ipv6_address,
		      parameter_tvb, PARAMETER_VALUE_OFFSET, IPV6_ADDRESS_LENGTH,
		      tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, IPV6_ADDRESS_LENGTH));
  
  proto_item_set_text(parameter_item, "IPV6 address parameter");
}

void
dissect_state_cookie_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, state_cookie_length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  state_cookie_length = length - STATE_COOKIE_PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, STATE_COOKIE_PARAMETER_COOKIE_OFFSET, state_cookie_length,
		      "State cookie (%u byte%s)",
		      state_cookie_length, plurality(state_cookie_length, "", "s"));

  proto_item_set_text(parameter_item, "State Cookie Parameter with %u byte%s cookie",
		      state_cookie_length, plurality(state_cookie_length, "", "s"));
}

void
dissect_unrecognized_parameters_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, parameter_value_length;
  tvbuff_t *unrecognized_parameters_tvb;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  unrecognized_parameters_tvb = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, 
					       parameter_value_length, parameter_value_length);
  dissect_tlv_parameter_list(unrecognized_parameters_tvb, parameter_tree);
   
  proto_item_set_text(parameter_item, "Unrecognized parameter of type");
}

void
dissect_cookie_preservative_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 increment;

  increment =  tvb_get_ntohl(parameter_tvb, COOKIE_PRESERVATIVE_PARAMETER_INCR_OFFSET);
  
  proto_tree_add_uint(parameter_tree, hf_sctp_parameter_cookie_preservative_increment, parameter_tvb, 
		      COOKIE_PRESERVATIVE_PARAMETER_INCR_OFFSET, 
		      COOKIE_PRESERVATIVE_PARAMETER_INCR_LENGTH,
		      increment);
  
  proto_item_set_text(parameter_item, "Cookie preservative parameter requesting for a %u msec increment",
		      increment);
}

void
dissect_hostname_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16  length, hostname_length;
  char *hostname;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  hostname_length = length - PARAMETER_HEADER_LENGTH;
  hostname = (char *)tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, hostname_length);
  proto_tree_add_string(parameter_tree, hf_sctp_parameter_hostname_hostname, parameter_tvb,
			PARAMETER_VALUE_OFFSET, hostname_length,
			hostname);

  proto_item_set_text(parameter_item, "Hostname parameter");
}

void
dissect_supported_address_types_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, address_type, number_of_address_types, address_type_number, list_of_address_types_length ;
  guint offset;
  proto_item *address_list_item;
  proto_tree *address_list_tree;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  list_of_address_types_length = length - PARAMETER_HEADER_LENGTH;
  number_of_address_types = list_of_address_types_length / SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH;

  address_list_item = proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_VALUE_OFFSET, list_of_address_types_length,
					  "Supported Address Types (%u address type%s)",
					  number_of_address_types, plurality(number_of_address_types, "", "s"));
  address_list_tree = proto_item_add_subtree(address_list_item, ett_sctp_supported_address_types_parameter);
 
  offset = PARAMETER_VALUE_OFFSET;
  for(address_type_number = 1; address_type_number <= number_of_address_types; address_type_number++) {
    address_type = tvb_get_ntohs(parameter_tvb, offset);
    proto_tree_add_uint_format(address_list_tree, hf_sctp_supported_address_types_parameter,
			       parameter_tvb, offset, SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH,
			       address_type, "Supported address type: %u (%s)",
			       address_type, val_to_str(address_type, sctp_parameter_identifier_values, "unknown"));
    offset += SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH;
  };

  proto_item_set_text(parameter_item, "Supported address types parameter reporting %u address type%s",
		      number_of_address_types, plurality(number_of_address_types, "", "s"));
}

void
dissect_ecn_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
   proto_item_set_text(parameter_item, "ECN parameter");
}

void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 type, length, parameter_value_length;
  
  type   = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length,
		      "Parameter value (%u byte%s)",
		      parameter_value_length, plurality(parameter_value_length, "", "s"));

  proto_item_set_text(parameter_item, "Parameter of type %u and %u byte%s value",
		      type, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

void
dissect_parameter(tvbuff_t *parameter_tvb, proto_tree *chunk_tree)
{
  guint16 type, length, padding_length, total_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  type           = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  total_length   = length + padding_length;
   
  parameter_item = proto_tree_add_notext(chunk_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, total_length);
  parameter_tree = proto_item_add_subtree(parameter_item, ett_sctp_chunk_parameter);
 
  proto_tree_add_uint_format(parameter_tree, hf_sctp_chunk_parameter_type, 
			     parameter_tvb, PARAMETER_TYPE_OFFSET, PARAMETER_TYPE_LENGTH,
			     type, "Parameter type: %u (%s)",
			     type, val_to_str(type, sctp_parameter_identifier_values, "unknown"));
  proto_tree_add_uint(parameter_tree, hf_sctp_chunk_parameter_length, 
		      parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH,
		      length);
 
  switch(type) {
  case HEARTBEAT_INFO_PARAMETER_ID:
    dissect_heartbeat_info_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV4ADDRESS_PARAMETER_ID:
    dissect_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV6ADDRESS_PARAMETER_ID:
    dissect_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STATE_COOKIE_PARAMETER_ID:
    dissect_state_cookie_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case UNREC_PARA_PARAMETER_ID:
    dissect_unrecognized_parameters_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case COOKIE_PRESERVATIVE_PARAMETER_ID:
    dissect_cookie_preservative_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case HOSTNAME_ADDRESS_PARAMETER_ID:
    dissect_hostname_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SUPPORTED_ADDRESS_TYPES_PARAMETER_ID:
    dissect_supported_address_types_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ECN_PARAMETER_ID:
    dissect_ecn_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };
  if (padding_length > 0)
    proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
}

/*
 * Code to handle error causes for ABORT and ERROR chunks
 */
void
dissect_invalid_stream_identifier_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 stream_identifier;

  stream_identifier   = tvb_get_ntohs(cause_tvb, CAUSE_STREAM_IDENTIFIER_OFFSET);
  proto_tree_add_uint(cause_tree, hf_sctp_cause_stream_identifier, 
		      cause_tvb, CAUSE_STREAM_IDENTIFIER_OFFSET, CAUSE_STREAM_IDENTIFIER_LENGTH,
		      stream_identifier);
  proto_tree_add_text(cause_tree, cause_tvb, CAUSE_RESERVED_OFFSET, CAUSE_RESERVED_LENGTH,
		      "Reserved (2 bytes)");

  proto_item_set_text(cause_item, "Error cause reporting invalid stream identifier %u",
		      stream_identifier);
}

void
dissect_missing_mandatory_parameters_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint32 number_of_missing_parameters, missing_parameter_number;
  guint16 parameter_type;
  guint   offset;

  number_of_missing_parameters = tvb_get_ntohl(cause_tvb, CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET);
  proto_tree_add_uint(cause_tree, hf_sctp_cause_number_of_missing_parameters, 
		      cause_tvb, CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET, CAUSE_NUMBER_OF_MISSING_PARAMETERS_LENGTH,
		      number_of_missing_parameters);
  offset = CAUSE_FIRST_MISSING_PARAMETER_TYPE_OFFSET;
  for(missing_parameter_number = 1; missing_parameter_number <= number_of_missing_parameters; missing_parameter_number++) {
    parameter_type = tvb_get_ntohs(cause_tvb, offset);
    proto_tree_add_uint_format(cause_tree, hf_sctp_cause_missing_parameter_type,
			       cause_tvb, offset, CAUSE_MISSING_PARAMETER_TYPE_LENGTH,
			       parameter_type, "Missing parameter type: %u (%s)",
			       parameter_type, 
			       val_to_str(parameter_type, sctp_parameter_identifier_values, "unknown"));
    offset +=  CAUSE_MISSING_PARAMETER_TYPE_LENGTH;
  };

  proto_item_set_text(cause_item, "Error cause reporting %u missing mandatory parameter%s",
		      number_of_missing_parameters, plurality(number_of_missing_parameters, "", "s") );
}

void
dissect_stale_cookie_error_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint32 measure_of_staleness;

  measure_of_staleness =  tvb_get_ntohl(cause_tvb, CAUSE_MEASURE_OF_STALENESS_OFFSET);
  
  proto_tree_add_uint(cause_tree, hf_sctp_cause_measure_of_staleness, cause_tvb, 
		      CAUSE_MEASURE_OF_STALENESS_OFFSET, 
		      CAUSE_MEASURE_OF_STALENESS_LENGTH,
		      measure_of_staleness);
  
  proto_item_set_text(cause_item, "Error cause reporting a measure of staleness of %u usec",
		      measure_of_staleness);
}

void
dissect_out_of_resource_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_item_set_text(cause_item, "Error cause reporting lack of resources");
}

void
dissect_unresolvable_address_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 code, length, parameter_length, parameter_type;
  tvbuff_t *parameter_tvb;

  code   = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  
  parameter_length = length - CAUSE_HEADER_LENGTH;
  parameter_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, 
				 parameter_length, parameter_length);

  dissect_parameter(parameter_tvb, cause_tree);
  parameter_type = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
 
  proto_item_set_text(cause_item, "Error cause reporting unresolvable address of type %u (%s)",
		      parameter_type, val_to_str(parameter_type, sctp_parameter_identifier_values, "unknown") );
}

void
dissect_unrecognized_chunk_type_cause(tvbuff_t *cause_tvb,  packet_info *pinfo, 
				      proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 length, chunk_length;
  guint8 unrecognized_type;
  tvbuff_t *unrecognized_chunk_tvb;

  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  
  chunk_length = length - CAUSE_HEADER_LENGTH;

  unrecognized_chunk_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, 
					  chunk_length, chunk_length);
  dissect_sctp_chunk(unrecognized_chunk_tvb, pinfo, cause_tree,cause_tree);

  unrecognized_type   = tvb_get_guint8(unrecognized_chunk_tvb, CHUNK_TYPE_OFFSET);
 
  proto_item_set_text(cause_item, "Error cause reporting unrecognized chunk of type %u (%s)",
		      unrecognized_type,
		      val_to_str(unrecognized_type, sctp_chunk_type_values, "unknown"));
}

void
dissect_invalid_mandatory_parameter_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_item_set_text(cause_item, "Error cause reporting an invalid mandatory parameter");
}

void
dissect_unrecognized_parameters_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 length, cause_info_length;
  tvbuff_t *unrecognized_parameters_tvb;

  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  
  cause_info_length = length - CAUSE_HEADER_LENGTH;

  unrecognized_parameters_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, 
					       cause_info_length, cause_info_length);
  dissect_tlv_parameter_list(unrecognized_parameters_tvb, cause_tree);
 
  proto_item_set_text(cause_item, "Error cause reporting unrecognized parameters");
}

void
dissect_no_user_data_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint32 tsn;

  tsn = tvb_get_ntohl(cause_tvb, CAUSE_TSN_OFFSET);
  proto_tree_add_uint(cause_tree, hf_sctp_cause_tsn, cause_tvb, 
		      CAUSE_TSN_OFFSET, 
		      CAUSE_TSN_LENGTH,
		      tsn);

  proto_item_set_text(cause_item, "Error cause reporting data chunk with TSN %u contains no data",
		      tsn);
}

void
dissect_cookie_received_while_shutting_down_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_item_set_text(cause_item, "Error cause reporting cookie reception while shutting down");
}

void
dissect_unknown_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 code, length, cause_info_length;

  code   = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  
  cause_info_length = length - CAUSE_HEADER_LENGTH;

  proto_tree_add_text(cause_tree, cause_tvb, CAUSE_INFO_OFFSET, cause_info_length,
		      "Cause specific information (%u byte%s)",
		      cause_info_length, plurality(cause_info_length, "", "s"));

  proto_item_set_text(cause_item, "Error cause with code %u and %u byte%s information",
		      code, cause_info_length, plurality(cause_info_length, "", "s"));
}

void
dissect_error_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *chunk_tree)
{
  guint16 code, length, padding_length, total_length;
  proto_item *cause_item;
  proto_tree *cause_tree;

  code           = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length         = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  total_length   = length + padding_length;
  
  cause_item = proto_tree_add_notext(chunk_tree, cause_tvb, CAUSE_HEADER_OFFSET, total_length);
  proto_item_set_text(cause_item, "BAD ERROR CAUSE");
  cause_tree = proto_item_add_subtree(cause_item, ett_sctp_chunk_cause);
 
  proto_tree_add_uint_format(cause_tree, hf_sctp_cause_code, 
			     cause_tvb, CAUSE_CODE_OFFSET, CAUSE_CODE_LENGTH,
			     code, "Cause code: %u (%s)",
			     code, val_to_str(code, sctp_cause_code_values, "unknown"));
  proto_tree_add_uint(cause_tree, hf_sctp_cause_length, 
		      cause_tvb, CAUSE_LENGTH_OFFSET, CAUSE_LENGTH_LENGTH,
		      length);
 
  switch(code) {
  case INVALID_STREAM_IDENTIFIER:
    dissect_invalid_stream_identifier_cause(cause_tvb, cause_tree, cause_item);
    break;
  case MISSING_MANDATORY_PARAMETERS:
    dissect_missing_mandatory_parameters_cause(cause_tvb, cause_tree, cause_item);
    break;
  case STALE_COOKIE_ERROR:
    dissect_stale_cookie_error_cause(cause_tvb, cause_tree, cause_item);
    break;
  case OUT_OF_RESOURCE:
    dissect_out_of_resource_cause(cause_tvb, cause_tree, cause_item);
    break;
  case UNRESOLVABLE_ADDRESS:
    dissect_unresolvable_address_cause(cause_tvb, cause_tree, cause_item);
    break;
  case UNRECOGNIZED_CHUNK_TYPE:
    dissect_unrecognized_chunk_type_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case INVALID_MANDATORY_PARAMETER:
    dissect_invalid_mandatory_parameter_cause(cause_tvb, cause_tree, cause_item);
    break;
  case UNRECOGNIZED_PARAMETERS:
    dissect_unrecognized_parameters_cause(cause_tvb, cause_tree, cause_item);
    break;
  case NO_USER_DATA:
    dissect_no_user_data_cause(cause_tvb, cause_tree, cause_item);
    break;
  case COOKIE_RECEIVED_WHILE_SHUTTING_DOWN:
    dissect_cookie_received_while_shutting_down_cause(cause_tvb, cause_tree, cause_item);
    break;
  default:
    dissect_unknown_cause(cause_tvb, cause_tree, cause_item);
    break;
  };
  if (padding_length > 0)
    proto_tree_add_text(cause_tree, cause_tvb, CAUSE_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
}

/*
 * Code to actually dissect the packets 
*/

static void
dissect_payload(tvbuff_t *payload_tvb, packet_info *pinfo, proto_tree *tree,
		proto_tree *chunk_tree, guint16 payload_length, guint16 padding_length)
{
  /* do lookup with the subdissector table */
  if (dissector_try_port(sctp_dissector_table, pi.srcport,  payload_tvb, pinfo, tree) ||
      dissector_try_port(sctp_dissector_table, pi.destport, payload_tvb, pinfo, tree))
    return;
  else {
    proto_tree_add_text(chunk_tree, payload_tvb, 0, payload_length,
			"Payload (%u byte%s)",
			payload_length, plurality(payload_length, "", "s")); 
    if (padding_length > 0)
      proto_tree_add_text(chunk_tree, payload_tvb, payload_length, padding_length,
			  "Padding: %u byte%s",
			  padding_length, plurality(padding_length, "", "s"));
  }
}





static void
dissect_data_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint8  flags;
  guint16 length, total_payload_length, payload_length, padding_length, stream_id, stream_seq_number;
  guint32 tsn, payload_proto_id;
  proto_tree *flag_tree;
  tvbuff_t *payload_tvb;

  flags             = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET);
  length            = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
   
  flag_tree = proto_item_add_subtree(flags_item, ett_sctp_data_chunk_flags);
  proto_tree_add_boolean(flag_tree, hf_sctp_data_chunk_e_bit, chunk_tvb,
			 CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, flags);
  proto_tree_add_boolean(flag_tree, hf_sctp_data_chunk_b_bit, chunk_tvb,
			 CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, flags);
  proto_tree_add_boolean(flag_tree, hf_sctp_data_chunk_u_bit, chunk_tvb,
			 CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, flags);

  tsn               = tvb_get_ntohl(chunk_tvb, DATA_CHUNK_TSN_OFFSET);
  stream_id         = tvb_get_ntohs(chunk_tvb, DATA_CHUNK_STREAM_ID_OFFSET);
  stream_seq_number = tvb_get_ntohs(chunk_tvb, DATA_CHUNK_STREAM_SEQ_NUMBER_OFFSET);
  payload_proto_id  = tvb_get_ntohl(chunk_tvb, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET);
  
  payload_length       = length - DATA_CHUNK_HEADER_LENGTH;
  padding_length       = nr_of_padding_bytes(length);
  total_payload_length = payload_length + padding_length;
  payload_tvb          = tvb_new_subset(chunk_tvb, DATA_CHUNK_PAYLOAD_OFFSET,
				  total_payload_length, total_payload_length);
   
  proto_tree_add_uint(chunk_tree, hf_sctp_data_chunk_tsn, 
		      chunk_tvb,
		      DATA_CHUNK_TSN_OFFSET, DATA_CHUNK_TSN_LENGTH,
		      tsn);
  proto_tree_add_uint(chunk_tree, hf_sctp_data_chunk_stream_id, 
		      chunk_tvb, 
		      DATA_CHUNK_STREAM_ID_OFFSET, DATA_CHUNK_STREAM_ID_LENGTH,
		      stream_id);
  proto_tree_add_uint(chunk_tree, hf_sctp_data_chunk_stream_seq_number, 
		      chunk_tvb, 
		      DATA_CHUNK_STREAM_SEQ_NUMBER_OFFSET, DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH,
		      stream_seq_number);
  proto_tree_add_uint(chunk_tree, hf_sctp_data_chunk_payload_proto_id, 
		      chunk_tvb,
		      DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH,
		      payload_proto_id);
  proto_item_set_text(chunk_item, "DATA chunk with TSN %u (%u:%u) containing %u byte%s of payload",
		      tsn, stream_id, stream_seq_number, 
		      payload_length, plurality(payload_length, "", "s"));

  dissect_payload(payload_tvb, pinfo, tree, chunk_tree, payload_length, padding_length);
} 

void
dissect_init_chunk(tvbuff_t *chunk_tvb,  packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 initiate_tag, adv_rec_window_credit, initial_tsn;
  guint16 number_of_inbound_streams, number_of_outbound_streams;
  guint8  type;
  tvbuff_t *parameter_list_tvb;

  type                       = tvb_get_guint8(chunk_tvb, CHUNK_TYPE_OFFSET);
 
  initiate_tag               = tvb_get_ntohl(chunk_tvb, INIT_CHUNK_INITIATE_TAG_OFFSET);
  adv_rec_window_credit      = tvb_get_ntohl(chunk_tvb, INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET);
  number_of_inbound_streams  = tvb_get_ntohs(chunk_tvb, INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET);
  number_of_outbound_streams = tvb_get_ntohs(chunk_tvb, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET);
  initial_tsn                = tvb_get_ntohl(chunk_tvb, INIT_CHUNK_INITIAL_TSN_OFFSET);

  /* handle fixed parameters */
  proto_tree_add_uint(chunk_tree, hf_sctp_init_chunk_initiate_tag, 
		      chunk_tvb,
		      INIT_CHUNK_INITIATE_TAG_OFFSET, INIT_CHUNK_INITIATE_TAG_LENGTH,
		      initiate_tag);
  proto_tree_add_uint(chunk_tree, hf_sctp_init_chunk_adv_rec_window_credit, 
		      chunk_tvb,
		      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET, INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH,
		      adv_rec_window_credit);
  proto_tree_add_uint(chunk_tree, hf_sctp_init_chunk_number_of_outbound_streams, 
		      chunk_tvb,
		      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH,
		      number_of_outbound_streams);
  proto_tree_add_uint(chunk_tree, hf_sctp_init_chunk_number_of_inbound_streams, 
		      chunk_tvb,
		      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET, INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH,
		      number_of_inbound_streams);
  proto_tree_add_uint(chunk_tree, hf_sctp_init_chunk_initial_tsn, 
		      chunk_tvb,
		      INIT_CHUNK_INITIAL_TSN_OFFSET, INIT_CHUNK_INITIAL_TSN_LENGTH,
		      initial_tsn);
  
  /* handle variable paramters */
  parameter_list_tvb = tvb_new_subset(chunk_tvb, INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET, -1, -1);
  dissect_tlv_parameter_list(parameter_list_tvb, chunk_tree);

  proto_item_set_text(chunk_item, 
		      "%s chunk requesting for %u outbound stream%s and accepting up to %u inbound stream%s",
		      val_to_str(type, sctp_chunk_type_values, "unknown"),
		      number_of_outbound_streams, plurality(number_of_outbound_streams, "", "s"),
		      number_of_inbound_streams, plurality(number_of_inbound_streams, "", "s"));
} 

void
dissect_init_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		       proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  dissect_init_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
} 

void
dissect_sack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 cumulative_tsn_ack, adv_rec_window_credit, dup_tsn;
  guint16 number_of_gap_blocks, number_of_dup_tsns;
  guint16 gap_block_number, dup_tsn_number, start, end;
  gint gap_block_offset, dup_tsn_offset;
  proto_item *block_item;
  proto_tree *block_tree;

  cumulative_tsn_ack    = tvb_get_ntohl(chunk_tvb, SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
  adv_rec_window_credit = tvb_get_ntohl(chunk_tvb, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET);
  number_of_gap_blocks  = tvb_get_ntohs(chunk_tvb, SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET);
  number_of_dup_tsns    = tvb_get_ntohs(chunk_tvb, SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET);
  
  proto_tree_add_uint(chunk_tree, hf_sctp_sack_chunk_cumulative_tsn_ack, 
		      chunk_tvb,
		      SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET, SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH,
		      cumulative_tsn_ack);
  proto_tree_add_uint(chunk_tree, hf_sctp_sack_chunk_adv_rec_window_credit, 
		      chunk_tvb,
		      SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH,
		      adv_rec_window_credit);
  proto_tree_add_uint(chunk_tree, hf_sctp_sack_chunk_number_of_gap_blocks, 
		      chunk_tvb,
		      SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET, SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_LENGTH,
		      number_of_gap_blocks);
  proto_tree_add_uint(chunk_tree, hf_sctp_sack_chunk_number_of_dup_tsns, 
		      chunk_tvb,
		      SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET, SACK_CHUNK_NUMBER_OF_DUP_TSNS_LENGTH,
		      number_of_dup_tsns);
  
  /* handle the gap acknowledgement blocks */
  gap_block_offset = SACK_CHUNK_GAP_BLOCK_OFFSET;
  for(gap_block_number = 1; gap_block_number <= number_of_gap_blocks; gap_block_number++) {
    start = tvb_get_ntohs(chunk_tvb, gap_block_offset);
    end   = tvb_get_ntohs(chunk_tvb, gap_block_offset + SACK_CHUNK_GAP_BLOCK_START_LENGTH);
    block_item = proto_tree_add_text(chunk_tree, chunk_tvb,
				     gap_block_offset, SACK_CHUNK_GAP_BLOCK_LENGTH,
				     "Gap Acknowledgement for %u TSN%s",
				     1 + end - start, plurality(1 + end - start, "", "s"));
    block_tree = proto_item_add_subtree(block_item, ett_sctp_sack_chunk_gap_block);
    proto_tree_add_uint(block_tree, hf_sctp_sack_chunk_gap_block_start, 
			chunk_tvb,
			gap_block_offset, SACK_CHUNK_GAP_BLOCK_START_LENGTH,
			start);
    proto_tree_add_uint(block_tree, hf_sctp_sack_chunk_gap_block_end, 
			chunk_tvb,
			gap_block_offset + SACK_CHUNK_GAP_BLOCK_START_LENGTH,
			SACK_CHUNK_GAP_BLOCK_END_LENGTH,
			end);
    gap_block_offset += SACK_CHUNK_GAP_BLOCK_LENGTH;
  };
  
  /* handle the duplicate TSNs */
  dup_tsn_offset = SACK_CHUNK_GAP_BLOCK_OFFSET + number_of_gap_blocks * SACK_CHUNK_GAP_BLOCK_LENGTH;
  for(dup_tsn_number = 1; dup_tsn_number <= number_of_dup_tsns; dup_tsn_number++) {
    dup_tsn = tvb_get_ntohl(chunk_tvb, dup_tsn_offset);
    proto_tree_add_uint(chunk_tree, hf_sctp_sack_chunk_duplicate_tsn, 
			chunk_tvb,
			dup_tsn, SACK_CHUNK_DUP_TSN_LENGTH,
			dup_tsn);
    dup_tsn_offset += SACK_CHUNK_DUP_TSN_LENGTH;
  };

  proto_item_set_text(chunk_item, 
		      "SACK chunk acknowledging TSN %u and reporting %u gap%s and %u duplicate TSN%s",
		      cumulative_tsn_ack,
		      number_of_gap_blocks, plurality(number_of_gap_blocks, "", "s"),
		      number_of_dup_tsns, plurality(number_of_dup_tsns, "", "s"));
} 

void
dissect_heartbeat_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{
  tvbuff_t   *parameter_tvb;
  guint chunk_length, info_length, padding_length, total_length;

  chunk_length   = tvb_get_ntohs(chunk_tvb,  CHUNK_LENGTH_OFFSET);
  info_length    = chunk_length - CHUNK_HEADER_LENGTH;
  padding_length = nr_of_padding_bytes(info_length);
  total_length   = info_length + padding_length;
  parameter_tvb  = tvb_new_subset(chunk_tvb, HEARTBEAT_CHUNK_INFO_OFFSET, total_length, total_length);
    
  dissect_parameter(parameter_tvb, chunk_tree);

  proto_item_set_text(chunk_item, "HEARTBEAT chunk");
}
 
void
dissect_heartbeat_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			    proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{  
  tvbuff_t   *parameter_tvb;
  guint chunk_length, info_length, padding_length, total_length;

  chunk_length   = tvb_get_ntohs(chunk_tvb,  CHUNK_LENGTH_OFFSET);
  info_length    = chunk_length - CHUNK_HEADER_LENGTH;
  padding_length = nr_of_padding_bytes(info_length);
  total_length   = info_length + padding_length;

  parameter_tvb  = tvb_new_subset(chunk_tvb, HEARTBEAT_CHUNK_INFO_OFFSET, total_length, total_length);
    
  dissect_parameter(parameter_tvb, chunk_tree);

  proto_item_set_text(chunk_item, "HEARTBEAT ACK chunk");
} 

void
dissect_abort_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		    proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{
  guint offset, number_of_causes;
  guint16 length, padding_length, total_length;
  tvbuff_t *cause_tvb;

  number_of_causes = 0;
  offset = ABORT_CHUNK_FIRST_ERROR_CAUSE_OFFSET;
  while(tvb_length_remaining(chunk_tvb, offset)) {
    length         = tvb_get_ntohs(chunk_tvb, offset + CAUSE_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the chunk including the padding bytes */
    cause_tvb      = tvb_new_subset(chunk_tvb, offset, total_length, total_length);
    dissect_error_cause(cause_tvb, pinfo, chunk_tree); 
    /* get rid of the handled parameter */
    offset += total_length;
    number_of_causes++;
  };

  proto_item_set_text(chunk_item, "Abort chunk with %u cause%s",
		      number_of_causes, plurality(number_of_causes, "", "s"));
} 

void
dissect_shutdown_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		       proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 cumulative_tsn_ack;

  cumulative_tsn_ack = tvb_get_ntohl(chunk_tvb, SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
  proto_tree_add_uint(chunk_tree, hf_sctp_shutdown_chunk_cumulative_tsn_ack, 
		      chunk_tvb,
		      SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET,
		      SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_LENGTH,
		      cumulative_tsn_ack);

  proto_item_set_text(chunk_item, "SHUTDOWN chunk acknowledging up to TSN %u",
		      cumulative_tsn_ack);
} 

void
dissect_shutdown_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  proto_item_set_text(chunk_item, "SHUTDOWN ACK chunk");
} 

void
dissect_error_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		    proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint offset, number_of_causes;
  guint16 length, padding_length, total_length;
  tvbuff_t *cause_tvb;
  
  number_of_causes = 0;
  offset = ERROR_CHUNK_FIRST_ERROR_CAUSE_OFFSET;
  do {
    length         = tvb_get_ntohs(chunk_tvb, offset + CAUSE_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the chunk including the padding bytes */
    cause_tvb      = tvb_new_subset(chunk_tvb, offset, total_length, total_length);
    dissect_error_cause(cause_tvb, pinfo, chunk_tree); 
    /* get rid of the handled parameter */
    offset += total_length;
    number_of_causes++;
  } while(tvb_length_remaining(chunk_tvb, offset));

  proto_item_set_text(chunk_item, "Error chunk with %u cause%s",
		      number_of_causes, plurality(number_of_causes, "", "s"));
} 

void
dissect_cookie_echo_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			  proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint length, cookie_length, padding_length;

  length         = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  cookie_length  = length - CHUNK_HEADER_LENGTH;
  
  proto_tree_add_text(chunk_tree, chunk_tvb, COOKIE_ECHO_CHUNK_COOKIE_OFFSET, cookie_length,
		      "Cookie (%u byte%s)",
		      cookie_length, plurality(cookie_length, "", "s"));
  proto_item_set_text(chunk_item, "COOKIE ECHO chunk containing a cookie of %u byte%s",
		      cookie_length, plurality(cookie_length, "", "s"));

  if (padding_length > 0)
    proto_tree_add_text(chunk_tree, chunk_tvb, CHUNK_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
} 

void
dissect_cookie_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			 proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  proto_item_set_text(chunk_item, "COOKIE ACK chunk");
} 

void
dissect_ecne_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 lowest_tsn;

  lowest_tsn = tvb_get_ntohl(chunk_tvb, ECNE_CHUNK_LOWEST_TSN_OFFSET);
  proto_tree_add_uint(chunk_tree, hf_sctp_ecne_chunk_lowest_tsn, 
		      chunk_tvb,
		      ECNE_CHUNK_LOWEST_TSN_OFFSET, ECNE_CHUNK_LOWEST_TSN_LENGTH,
		      lowest_tsn);

  proto_item_set_text(chunk_item, "ECNE chunk");
} 

void
dissect_cwr_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		  proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 lowest_tsn;

  lowest_tsn = tvb_get_ntohl(chunk_tvb, CWR_CHUNK_LOWEST_TSN_OFFSET);
  proto_tree_add_uint(chunk_tree, hf_sctp_cwr_chunk_lowest_tsn, 
		      chunk_tvb,
		      CWR_CHUNK_LOWEST_TSN_OFFSET, CWR_CHUNK_LOWEST_TSN_LENGTH,
		      lowest_tsn);

  proto_item_set_text(chunk_item, "CWR chunk");
} 

void
dissect_shutdown_complete_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
				proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint8  flags;
  guint16 length;
  proto_tree *flag_tree;

  flags             = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET);
  length            = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);

  flag_tree = proto_item_add_subtree(flags_item, ett_sctp_data_chunk_flags);
  proto_tree_add_boolean(flag_tree, hf_sctp_shutdown_complete_chunk_t_bit, chunk_tvb,
			 CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, flags);

  proto_item_set_text(chunk_item, "SHUTDOWN COMPLETE chunk");
} 

void
dissect_unknown_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		      proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint length, chunk_value_length, padding_length;
  guint8 type;

  length         = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  type           = tvb_get_guint8(chunk_tvb, CHUNK_TYPE_OFFSET);
 
  chunk_value_length = length - CHUNK_HEADER_LENGTH;
  
  proto_tree_add_text(chunk_tree, chunk_tvb, CHUNK_VALUE_OFFSET, chunk_value_length,
		      "Chunk value (%u byte%s)",
		      chunk_value_length, plurality(chunk_value_length, "", "s"));
  
  if (padding_length > 0)
    proto_tree_add_text(chunk_tree, chunk_tvb, CHUNK_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
   
  proto_item_set_text(chunk_item, "Chunk of type %u and %u byte%s value",
		      type, chunk_value_length, plurality(chunk_value_length, "", "s"));

 
} 


void
dissect_sctp_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *sctp_tree)
{  
  guint8 type, flags;
  guint16 length;
  proto_item *flags_item;
  proto_item *chunk_item;
  proto_tree *chunk_tree;

  /* first extract the chunk header */
  type   = tvb_get_guint8(chunk_tvb, CHUNK_TYPE_OFFSET);
  flags  = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET);
  length = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);

  /* create proto_tree stuff */
  chunk_item   = proto_tree_add_text(sctp_tree, chunk_tvb,
				     CHUNK_HEADER_OFFSET, tvb_length(chunk_tvb), "Incomplete chunk");
  chunk_tree   = proto_item_add_subtree(chunk_item, ett_sctp_chunk);
  
  /* then insert the chunk header components into the protocol tree */
  proto_tree_add_uint_format(chunk_tree, hf_sctp_chunk_type, 
			     chunk_tvb, CHUNK_TYPE_OFFSET, CHUNK_TYPE_LENGTH,
			     type, "Identifier: %u (%s)",
			     type, val_to_str(type, sctp_chunk_type_values, "unknown"));
  flags_item = proto_tree_add_uint(chunk_tree, hf_sctp_chunk_flags, 
		      chunk_tvb, CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH,
		      flags);
  proto_tree_add_uint(chunk_tree, hf_sctp_chunk_length, 
		      chunk_tvb, CHUNK_LENGTH_OFFSET, CHUNK_LENGTH_LENGTH,
		      length);
  
  /* now dissect the chunk value */
  switch(type) {
  case SCTP_DATA_CHUNK_ID:
    dissect_data_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_INIT_CHUNK_ID:
    dissect_init_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_INIT_ACK_CHUNK_ID:
    dissect_init_ack_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_SACK_CHUNK_ID:
    dissect_sack_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break; 
  case SCTP_HEARTBEAT_CHUNK_ID:
    dissect_heartbeat_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_HEARTBEAT_ACK_CHUNK_ID:
    dissect_heartbeat_ack_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_ABORT_CHUNK_ID:
    dissect_abort_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_SHUTDOWN_CHUNK_ID:
    dissect_shutdown_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_SHUTDOWN_ACK_CHUNK_ID:
    dissect_shutdown_ack_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_ERROR_CHUNK_ID:
    dissect_error_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_COOKIE_ECHO_CHUNK_ID:
    dissect_cookie_echo_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_COOKIE_ACK_CHUNK_ID:
    dissect_cookie_ack_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_ECNE_CHUNK_ID:
    dissect_ecne_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_CWR_CHUNK_ID:
    dissect_cwr_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_SHUTDOWN_COMPLETE_CHUNK_ID:
    dissect_shutdown_complete_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  default:
    dissect_unknown_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  }  
}

void
dissect_sctp_chunks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *sctp_tree)
{ 
  tvbuff_t *chunk_tvb;
  guint16 length, padding_length, total_length;
  gint offset;
  
  /* the common header of the datagram is already handled */
  offset = COMMON_HEADER_LENGTH;

  while(tvb_length_remaining(tvb, offset) > 0) {
    /* extract the chunk length and compute number of padding bytes */
    length         = tvb_get_ntohs(tvb, offset + CHUNK_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the chunk including the padding bytes */
    chunk_tvb    = tvb_new_subset(tvb, offset, total_length, total_length);
    /* call dissect_sctp_chunk for a actual work */
    dissect_sctp_chunk(chunk_tvb, pinfo, tree, sctp_tree);
    /* get rid of the dissected chunk */
    offset += total_length;
  }
}



/* dissect_sctp handles the common header of a SCTP datagram.
 * For the handling of the chunks dissect_sctp_chunks is called.
 */

static void
dissect_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 source_port, destination_port;
  guint32 verification_tag, checksum;
  proto_item *ti;
  proto_tree *sctp_tree;

  CHECK_DISPLAY_AS_DATA(proto_sctp, tvb, pinfo, tree);

  pinfo->current_proto = "SCTP";

  /* Extract the common header */
  source_port      = tvb_get_ntohs(tvb, SOURCE_PORT_OFFSET);
  destination_port = tvb_get_ntohs(tvb, DESTINATION_PORT_OFFSET);
  verification_tag = tvb_get_ntohl(tvb, VERIFICATION_TAG_OFFSET);
  checksum         = tvb_get_ntohl(tvb, CHECKSUM_OFFSET);

  /* update pi structure */
  pi.ptype = PT_SCTP;
  pi.srcport = source_port;
  pi.destport = destination_port;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
    col_set_str(pinfo->fd, COL_PROTOCOL, "SCTP");

  /* Make entries in Info column on summary display */
  if (check_col(pinfo->fd, COL_INFO)) 
    col_add_fstr(pinfo->fd, COL_INFO, "%u > %u: tag 0x%x",
		 source_port, destination_port, verification_tag);
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the sctp protocol tree */
    ti = proto_tree_add_protocol_format(tree, proto_sctp, tvb, 0, tvb_length(tvb), 
					"Stream Control Transmission Protocol");
    sctp_tree = proto_item_add_subtree(ti, ett_sctp);

    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(sctp_tree, hf_sctp_source_port, 
			tvb, SOURCE_PORT_OFFSET, SOURCE_PORT_LENGTH,
			source_port);
    proto_tree_add_uint(sctp_tree, hf_sctp_destination_port,
			tvb, DESTINATION_PORT_OFFSET, DESTINATION_PORT_LENGTH,
			destination_port);
    proto_tree_add_uint(sctp_tree, hf_sctp_verification_tag,
			tvb, VERIFICATION_TAG_OFFSET, VERIFICATION_TAG_LENGTH,
			verification_tag);
    proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum,
			       tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, checksum,
			       "Adler-32 checksum: 0x%08x (%s)",
			       checksum, sctp_checksum_state(tvb, checksum));
    
    /* add all chunks of the sctp datagram to the protocol tree */
    dissect_sctp_chunks(tvb, pinfo, tree, sctp_tree);
  };
}

/* Register the protocol with Ethereal */
void
proto_register_sctp(void)
{                 

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_sctp_source_port,
      { "Source port", "sctp.srcport",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sctp_destination_port,
      { "Destination port", "sctp.dstport",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    { &hf_sctp_verification_tag,
      { "Verification tag", "sctp.verfication_tag",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    },
    { &hf_sctp_checksum,
      { "Adler-32 checksum", "sctp.checksum",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    },
    { &hf_sctp_chunk_type,
      { "Identifier", "sctp.chunk_type",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sctp_chunk_flags,
      { "Flags", "sctp.chunk_flags",
	FT_UINT8, BASE_BIN, NULL, 0x0,          
	""}
    },
    { &hf_sctp_chunk_length,
      { "Length", "sctp.chunk_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sctp_init_chunk_initiate_tag,
      { "Initiate tag", "sctp.init.chunk.initiate.tag",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    },
    { &hf_sctp_init_chunk_adv_rec_window_credit,
      { "Advertised reciever window credit (a_rwnd)", "sctp.init.chunk.credit",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sctp_init_chunk_number_of_outbound_streams,
      { "Number of outbound streams", "sctp.init.chunk.nr.out.streams",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sctp_init_chunk_number_of_inbound_streams,
      { "Number of inbound streams", "sctp.init.chunk.nr.in.streams",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    {&hf_sctp_init_chunk_initial_tsn,
      { "Initial TSN", "sctp.init.chunk.initial.tsn",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
    {&hf_sctp_cumulative_tsn_ack,
     { "Cumulative TSN Ack", "sctp.cumulative.tsn.ack",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    },
    {&hf_sctp_data_chunk_tsn,
     { "TSN", "sctp.tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    },
    {&hf_sctp_data_chunk_stream_id,
     { "Stream Identifier", "sctp.stream_id",
	FT_UINT16, BASE_HEX, NULL, 0x0,          
	""}
    },
    {&hf_sctp_data_chunk_stream_seq_number,
     { "Stream sequence number", "sctp.stream_seq_number",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_data_chunk_payload_proto_id,
     { "Payload Protocol identifier", "sctp.payload_proto_id",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	""}
    },
    {&hf_sctp_data_chunk_e_bit,
     { "E-Bit", "sctp.data.e_bit",
       FT_BOOLEAN, 8, TFS(&sctp_data_chunk_e_bit_value), SCTP_DATA_CHUNK_E_BIT,          
       ""}
    },
    {&hf_sctp_data_chunk_b_bit,
     { "B-Bit", "sctp.data.b_bit",
       FT_BOOLEAN, 8, TFS(&sctp_data_chunk_b_bit_value), SCTP_DATA_CHUNK_B_BIT,          
       ""}
    },
    {&hf_sctp_data_chunk_u_bit,
     { "U-Bit", "sctp.data.u.bit",
       FT_BOOLEAN, 8, TFS(&sctp_data_chunk_u_bit_value), SCTP_DATA_CHUNK_U_BIT,          
       ""}
    },
    {&hf_sctp_sack_chunk_cumulative_tsn_ack,
     { "Cumulative TSN ACK", "sctp.sack.cumulative_tsn_ack",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_sack_chunk_adv_rec_window_credit,
     { "Advertised receiver window credit (a_rwnd)", "sctp.sack.a_rwnd",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_sack_chunk_number_of_gap_blocks,
     { "Number of gap acknowldgement blocks ", "sctp.sack.number_of_gap_blocks",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_sack_chunk_number_of_dup_tsns,
     { "Number of duplicated TSNs", "sctp.sack.number_of_duplicated_tsns",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_sack_chunk_gap_block_start,
     { "Start", "sctp.sack.gap_block_start",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_sack_chunk_gap_block_end,
     { "End", "sctp.sack.gap_block_end",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_sack_chunk_duplicate_tsn,
     { "Duplicate TSN", "sctp.sack.duplicate.tsn",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },  
    {&hf_sctp_shutdown_chunk_cumulative_tsn_ack,
     { "Cumulative TSN Ack", "sctp.shutdown.cumulative_tsn_ack",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    },
    {&hf_sctp_ecne_chunk_lowest_tsn,
     { "Lowest TSN", "sctp.ecne.lowest_tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_cwr_chunk_lowest_tsn,
     { "Lowest TSN", "sctp.cwr.lowest_tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_shutdown_complete_chunk_t_bit,
     { "E-Bit", "sctp.shutdown_complete.t_bit",
       FT_BOOLEAN, 8, TFS(&sctp_shutdown_complete_chunk_t_bit_value), SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT,
       ""}
    },
    {&hf_sctp_chunk_parameter_type,
     { "Parameter type", "sctp.parameter.type",
       FT_UINT16, BASE_HEX, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_chunk_parameter_length,
     { "Parameter length", "sctp.parameter.length",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_parameter_ipv4_address,
     { "IP Version 4 address", "sctp.parameter.ipv4_address",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       ""}
    },
    {&hf_sctp_parameter_ipv6_address,
     { "IP Version 6 address", "sctp.parameter.ipv6_address",
       FT_IPv6, BASE_NONE, NULL, 0x0,
       ""}
    },
    {&hf_sctp_parameter_cookie_preservative_increment,
     { "Suggested Cookie life-span increment (msec)", "sctp.parameter.cookie_preservative_incr",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_parameter_hostname_hostname,
     { "Hostname", "sctp.parameter.hostname.hostname",
       FT_STRING, BASE_NONE, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_supported_address_types_parameter,
     { "Supported address type", "sctp.parameter.supported_addres_type",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_cause_code,
     { "Cause code", "sctp.cause.code",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_cause_length,
     { "Cause length", "sctp.cause.length",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_cause_stream_identifier,
     { "Stream identifier", "sctp.cause.stream_identifier",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_cause_number_of_missing_parameters,
     { "Number of missing parameters", "sctp.cause.nr_of_missing_parameters",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    }, 
    {&hf_sctp_cause_missing_parameter_type,
     { "Missing parameters type", "sctp.cause.missing_parameter_type",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_cause_measure_of_staleness,
     { "Measure of staleness in usec", "sctp.cause.measure_of_staleness",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    },
    {&hf_sctp_cause_tsn,
     { "TSN", "sctp.cause.tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       ""}
    },
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sctp,
    &ett_sctp_chunk,
    &ett_sctp_chunk_parameter,
    &ett_sctp_chunk_cause,
    &ett_sctp_data_chunk_flags,
    &ett_sctp_sack_chunk_gap_block,
    &ett_sctp_supported_address_types_parameter,
    &ett_sctp_unrecognized_parameter_parameter
  };
  
  /* Register the protocol name and description */
  proto_sctp = proto_register_protocol("Stream Control Transmission Protcol",
				       "SCTP", "sctp");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sctp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  sctp_dissector_table = register_dissector_table("sctp.port");

};

void
proto_reg_handoff_sctp(void)
{
	dissector_add("ip.proto", IP_PROTO_SCTP, dissect_sctp);
}
