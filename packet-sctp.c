/* packet-sctp.c
 * Routines for Stream Control Transmission Protocol dissection
 * It should be compilant to
 * - RFC 2960, for basic SCTP support
 * - http://www.ietf.org/internet-drafts/draft-ietf-tsvwg-addip-sctp-03.txt for the add-IP extension
 * - http://www.sctp.org/draft-ietf-tsvwg-usctp-01.txt for the 'Limited Retransmission' extension
 * - http://www.ietf.org/internet-drafts/draft-ietf-tsvwg-sctpcsum-03.txt
 * Copyright 2000, 2001, 2002, Michael Tuexen <Michael.Tuexen@icn.siemens.de>
 * Still to do (so stay tuned)
 * - support for reassembly
 * - code cleanup
 *
 * $Id: packet-sctp.c,v 1.32 2002/03/02 07:29:10 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "prefs.h"
#include <epan/packet.h>
#include "ipproto.h"

/* Initialize the protocol and registered fields */
static int proto_sctp = -1;
static int hf_sctp_port = -1;
static int hf_sctp_source_port      = -1;
static int hf_sctp_destination_port = -1;
static int hf_sctp_verification_tag = -1;
static int hf_sctp_checksum         = -1;
static int hf_sctp_checksum_bad     = -1;

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

static int hf_sctp_forward_tsn_chunk_tsn = -1;

static int hf_sctp_ustreams_start = -1;
static int hf_sctp_ustreams_end   = -1;

static int hf_sctp_asconf_ack_serial = -1;
static int hf_sctp_asconf_ack_correlation_id = -1;

static int hf_sctp_asconf_serial = -1;
static int hf_sctp_asconf_correlation_id = -1;
static int hf_sctp_asconf_reserved = -1;
static int hf_sctp_asconf_addr_type = -1;
static int hf_sctp_asconf_addr = -1;
static int hf_sctp_asconf_ipv4_address = -1;
static int hf_sctp_asconf_ipv6_address = -1;
static int hf_sctp_adap_indication = -1;

static dissector_table_t sctp_port_dissector_table;
static dissector_table_t sctp_ppi_dissector_table;

static module_t *sctp_module;

/* Initialize the subtree pointers */
static gint ett_sctp = -1;
static gint ett_sctp_chunk = -1;
static gint ett_sctp_chunk_parameter = -1;
static gint ett_sctp_chunk_cause = -1;
static gint ett_sctp_data_chunk_flags = -1;
static gint ett_sctp_sack_chunk_gap_block = -1;
static gint ett_sctp_supported_address_types_parameter = -1;
static gint ett_sctp_unrecognized_parameter_parameter = -1;
static gint ett_sctp_unreliable_streams_interval = -1;

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
#define SCTP_FORWARD_TSN_CHUNK_ID      192 
#define SCTP_ASCONF_ACK_CHUNK_ID      0x80
#define SCTP_ASCONF_CHUNK_ID          0XC1

#define SCTP_IETF_EXT                  255

static const value_string sctp_chunk_type_values[] = {
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
  { SCTP_FORWARD_TSN_CHUNK_ID,       "FORWARD TSN" },
  { SCTP_ASCONF_ACK_CHUNK_ID,        "ASCONF_ACK" },
  { SCTP_ASCONF_CHUNK_ID,            "ASCONF" },
  { SCTP_IETF_EXT,                   "IETF_EXTENSION" },
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
#define UNRELIABLE_STREAMS_PARAMETER_ID      0xC000
#define ADD_IP_ADDRESS_PARAMETER_ID          0xC001
#define DEL_IP_ADDRESS_PARAMETER_ID          0xC002
#define ERROR_CAUSE_INDICATION_PARAMETER_ID  0xC003
#define SET_PRIMARY_ADDRESS_PARAMETER_ID     0xC004
#define SUCCESS_REPORT_PARAMETER_ID          0xC005
#define ADAP_LAYER_INDICATION_PARAMETER_ID   0xC006

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
  { UNRELIABLE_STREAMS_PARAMETER_ID,      "Unreliable streams" },
  { ADD_IP_ADDRESS_PARAMETER_ID,          "Add IP address" },
  { DEL_IP_ADDRESS_PARAMETER_ID,          "Delete IP address" },
  { ERROR_CAUSE_INDICATION_PARAMETER_ID,  "Error cause indication" },
  { SET_PRIMARY_ADDRESS_PARAMETER_ID,     "Set primary address" },
  { SUCCESS_REPORT_PARAMETER_ID,          "Success report" },
  { ADAP_LAYER_INDICATION_PARAMETER_ID,   "Adaptation Layer Indication" },
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

#define INVALID_STREAM_IDENTIFIER                  0x01
#define MISSING_MANDATORY_PARAMETERS               0x02
#define STALE_COOKIE_ERROR                         0x03
#define OUT_OF_RESOURCE                            0x04
#define UNRESOLVABLE_ADDRESS                       0x05
#define UNRECOGNIZED_CHUNK_TYPE                    0x06
#define INVALID_MANDATORY_PARAMETER                0x07
#define UNRECOGNIZED_PARAMETERS                    0x08
#define NO_USER_DATA                               0x09
#define COOKIE_RECEIVED_WHILE_SHUTTING_DOWN        0x0a
#define REQUEST_TO_DELETE_LAST_ADDRESS             0x0c
#define OPERATION_REFUSED_DUE_TO_RESOURCE_SHORTAGE 0X0d
#define REQUEST_TO_DELETE_SOURCE_ADDRESS           0x0e

static const value_string sctp_cause_code_values[] = {
  { INVALID_STREAM_IDENTIFIER,                  "Invalid stream identifier" },
  { MISSING_MANDATORY_PARAMETERS,               "Missing mandator parameter" },
  { STALE_COOKIE_ERROR,                         "Stale cookie error" },
  { OUT_OF_RESOURCE,                            "Out of resource" },
  { UNRESOLVABLE_ADDRESS,                       "Unresolvable address" },
  { UNRECOGNIZED_CHUNK_TYPE,                    "Unrecognized chunk type " },
  { INVALID_MANDATORY_PARAMETER,                "Invalid mandatory parameter" },
  { UNRECOGNIZED_PARAMETERS,                    "Unrecognized parameters" },
  { NO_USER_DATA,                               "No user data" },
  { COOKIE_RECEIVED_WHILE_SHUTTING_DOWN,        "Cookie received while shutting down" },
  { REQUEST_TO_DELETE_LAST_ADDRESS,             "Request to delete last address" },
  { OPERATION_REFUSED_DUE_TO_RESOURCE_SHORTAGE, "Operation refused due to resource shortage" },
  { REQUEST_TO_DELETE_SOURCE_ADDRESS,           "Request to delete source address" },
  { 0,                                          NULL } };

#define NOT_SPECIFIED_PROTOCOL_ID  0
#define IUA_PAYLOAD_PROTOCOL_ID    1
#define M2UA_PAYLOAD_PROTOCOL_ID   2
#define M3UA_PAYLOAD_PROTOCOL_ID   3
#define SUA_PAYLOAD_PROTOCOL_ID    4
#define M2PA_PAYLOAD_PROTOCOL_ID   5
#define V5UA_PAYLOAD_PROTOCOL_ID   6

static const value_string sctp_payload_proto_id_values[] = {
  { NOT_SPECIFIED_PROTOCOL_ID,           "not specified" },
  { IUA_PAYLOAD_PROTOCOL_ID,             "IUA" },
  { M2UA_PAYLOAD_PROTOCOL_ID,            "M2UA" },
  { M3UA_PAYLOAD_PROTOCOL_ID,            "M3UA" },
  { SUA_PAYLOAD_PROTOCOL_ID,             "SUA" },
  { M2PA_PAYLOAD_PROTOCOL_ID,            "M2PA" },
  { V5UA_PAYLOAD_PROTOCOL_ID,            "V5UA" },
  { 0,                                   NULL } };

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

#define SCTP_CHECKSUM_NONE      0
#define SCTP_CHECKSUM_ADLER32   1
#define SCTP_CHECKSUM_CRC32C    2
#define SCTP_CHECKSUM_AUTOMATIC 3

static gint sctp_checksum = SCTP_CHECKSUM_ADLER32;

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

static unsigned int
sctp_adler32(const unsigned char* buf, unsigned int len)
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

/* The CRC32C code is taken from draft-ietf-tsvwg-sctpcsum-01.txt.
 * That code is copyrighted by D. Otis and has been modified.
 */
  
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF]) 
static unsigned long crc_c[256] = 
{ 
0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,  
0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,  
0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,  
0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,  
0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,  
0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,  
0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,  
0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,  
0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,  
0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,  
0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,  
0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,  
0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,  
0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,  
0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,  
0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,  
0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,  
0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,  
0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,  
0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,  
0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,  
0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,  
0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,  
0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,  
0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,  
0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,  
0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,  
0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,  
0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,  
0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,  
0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,  
0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,  
0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,  
0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,  
0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,  
0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,  
0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,  
0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,  
0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,  
0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,  
0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,  
0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,  
0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,  
0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,  
0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,  
0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,  
0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,  
0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,  
0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,  
0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,  
0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,  
0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,  
0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,  
0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,  
0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,  
0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,  
0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,  
0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,  
0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,  
0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,  
0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,  
0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,  
0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,  
0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,  
}; 
     
static unsigned int
sctp_crc32c(const unsigned char* buf, unsigned int len)
{
  unsigned int i; 
  unsigned long crc32 = ~0L; 
  unsigned long result;
  unsigned char byte0,byte1,byte2,byte3;

  for (i = 0; i < SOURCE_PORT_LENGTH + DESTINATION_PORT_LENGTH + VERIFICATION_TAG_LENGTH; i++) 
  { 
    CRC32C(crc32, buf[i]); 
  }
  CRC32C(crc32, 0);
  CRC32C(crc32, 0);
  CRC32C(crc32, 0);
  CRC32C(crc32, 0);
  for (i = COMMON_HEADER_LENGTH; i < len; i++) 
  { 
    CRC32C(crc32, buf[i]); 
  }  
  result = ~crc32;
  
  byte0 = result & 0xff;
  byte1 = (result>>8) & 0xff;
  byte2 = (result>>16) & 0xff;
  byte3 = (result>>24) & 0xff;
  crc32 = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
  return ( crc32 );
}

static guint 
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

static void
dissect_parameter(tvbuff_t *, packet_info *, proto_tree *);

static void
dissect_error_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *chunk_tree);

static gboolean
dissect_sctp_chunk(tvbuff_t *, packet_info *, proto_tree *, proto_tree *);

static void 
dissect_tlv_parameter_list(tvbuff_t *parameter_list_tvb, packet_info *pinfo, proto_tree *tree)
{
  guint offset, length, padding_length, total_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while(tvb_reported_length_remaining(parameter_list_tvb, offset)) {
    length         = tvb_get_ntohs(parameter_list_tvb, offset + PARAMETER_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the chunk including the padding bytes */
    parameter_tvb    = tvb_new_subset(parameter_list_tvb, offset, total_length, total_length);
    dissect_parameter(parameter_tvb, pinfo, tree); 
    /* get rid of the handled parameter */
    offset += total_length;
  }
}

static void
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

static void
dissect_ipv4_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 ipv4_address;

  tvb_memcpy(parameter_tvb, (guint8 *)&ipv4_address, PARAMETER_VALUE_OFFSET, IPV4_ADDRESS_LENGTH); 
  proto_tree_add_ipv4(parameter_tree, hf_sctp_parameter_ipv4_address,
		      parameter_tvb, PARAMETER_VALUE_OFFSET, IPV4_ADDRESS_LENGTH,
		      ipv4_address);  
  proto_item_set_text(parameter_item, "IPV4 address parameter");
}

static void
dissect_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_ipv6(parameter_tree, hf_sctp_parameter_ipv6_address,
		      parameter_tvb, PARAMETER_VALUE_OFFSET, IPV6_ADDRESS_LENGTH,
		      tvb_get_ptr(parameter_tvb, PARAMETER_VALUE_OFFSET, IPV6_ADDRESS_LENGTH));
  
  proto_item_set_text(parameter_item, "IPV6 address parameter");
}

static void
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

static void
dissect_unrecognized_parameters_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, padding_length, parameter_value_length;
  tvbuff_t *unrecognized_parameters_tvb;

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);

  parameter_value_length = length - PARAMETER_HEADER_LENGTH + padding_length;

  unrecognized_parameters_tvb = tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, 
					       parameter_value_length, parameter_value_length);
  dissect_tlv_parameter_list(unrecognized_parameters_tvb, pinfo, parameter_tree);
   
  proto_item_set_text(parameter_item, "Unrecognized parameter of type");
}

static void
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

static void
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

static void
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
			       address_type, "Supported address type: 0x%04x (%s)",
			       address_type, val_to_str(address_type, sctp_parameter_identifier_values, "unknown"));
    offset += SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH;
  };

  proto_item_set_text(parameter_item, "Supported address types parameter reporting %u address type%s",
		      number_of_address_types, plurality(number_of_address_types, "", "s"));
}

static void
dissect_ecn_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
   proto_item_set_text(parameter_item, "ECN parameter");
}

#define USTREAMS_START_LENGTH    2
#define USTREAMS_END_LENGTH      2
#define USTREAMS_INTERVAL_LENGTH (USTREAMS_START_LENGTH + USTREAMS_END_LENGTH)

static void
dissect_unreliable_streams_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{  
    guint16 length, start, end, number_of_intervals, interval_number;
    proto_item *interval_item;
    proto_tree *interval_tree;
    gint interval_offset;
    
    length              = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
    number_of_intervals = (length - PARAMETER_HEADER_LENGTH) / USTREAMS_INTERVAL_LENGTH;
    
    interval_offset     = PARAMETER_VALUE_OFFSET;
    for(interval_number = 1; interval_number <= number_of_intervals; interval_number++) {
      start = tvb_get_ntohs(parameter_tvb, interval_offset);
      end   = tvb_get_ntohs(parameter_tvb, interval_offset + USTREAMS_START_LENGTH);
      interval_item = proto_tree_add_text(parameter_tree, parameter_tvb, interval_offset, USTREAMS_INTERVAL_LENGTH, "Unreliable streams (%u-%u)", start, end);
      interval_tree = proto_item_add_subtree(interval_item, ett_sctp_unreliable_streams_interval);
      proto_tree_add_uint(interval_tree, hf_sctp_ustreams_start, parameter_tvb, interval_offset, USTREAMS_START_LENGTH, start);
      proto_tree_add_uint(interval_tree, hf_sctp_ustreams_end,  parameter_tvb, interval_offset + USTREAMS_START_LENGTH, USTREAMS_END_LENGTH, end);
      interval_offset += USTREAMS_INTERVAL_LENGTH;
    };
   proto_item_set_text(parameter_item, "Unreliable streams parameter");
}

static void
dissect_add_ip_address_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, parameter_value_length;
  tvbuff_t *address_tvb;

  length                 = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  address_tvb            =  tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, parameter_value_length);
  dissect_parameter(address_tvb, pinfo, parameter_tree); 

  proto_item_set_text(parameter_item, "Add IP address parameter");
}

static void
dissect_del_ip_address_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, parameter_value_length;
  tvbuff_t *address_tvb;

  length                 = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  address_tvb            =  tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, parameter_value_length);
  dissect_parameter(address_tvb, pinfo, parameter_tree); 

  proto_item_set_text(parameter_item, "Delete IP address parameter");
}

static void
dissect_error_cause_indication_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, padding_length, total_length;
  gint offset;
  tvbuff_t *error_cause_tvb;

  offset = PARAMETER_VALUE_OFFSET;
  while(tvb_reported_length_remaining(parameter_tvb, offset)) {
    length         = tvb_get_ntohs(parameter_tvb, offset + CAUSE_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the chunk including the padding bytes */
    error_cause_tvb    = tvb_new_subset(parameter_tvb, offset , total_length, total_length);
    dissect_error_cause(error_cause_tvb, pinfo, parameter_tree); 
    /* get rid of the handled parameter */
    offset += total_length;
  }
  proto_item_set_text(parameter_item, "Error cause indication");
}

static void
dissect_set_primary_address_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 length, parameter_value_length;
  tvbuff_t *address_tvb;

  length                 = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  parameter_value_length = length - PARAMETER_HEADER_LENGTH;

  address_tvb            =  tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, parameter_value_length);
  dissect_parameter(address_tvb, pinfo, parameter_tree); 

  proto_item_set_text(parameter_item, "Set primary address parameter");
}

static void
dissect_success_report_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
   proto_item_set_text(parameter_item, "Success report parameter");
}

#define ADAP_INDICATION_LENGTH 4
#define ADAP_INDICATION_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_adap_indication_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 indication;

  indication =  tvb_get_ntohl(parameter_tvb, ADAP_INDICATION_OFFSET);
  proto_tree_add_uint(parameter_tree, hf_sctp_adap_indication, parameter_tvb, ADAP_INDICATION_OFFSET, ADAP_INDICATION_LENGTH, indication);
  proto_item_set_text(parameter_item, "Adaptation layer indication");
}

static void
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

static void
dissect_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *chunk_tree)
{
  guint16 type, length, padding_length, total_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;

  type           = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  total_length   = length + padding_length;
   
  parameter_item = proto_tree_add_text(chunk_tree, parameter_tvb,
	PARAMETER_HEADER_OFFSET, total_length, "%s parameter",
	val_to_str(type, sctp_parameter_identifier_values, "Unknown"));
  parameter_tree = proto_item_add_subtree(parameter_item, ett_sctp_chunk_parameter);
 
  proto_tree_add_uint(parameter_tree, hf_sctp_chunk_parameter_type, 
		      parameter_tvb, PARAMETER_TYPE_OFFSET, PARAMETER_TYPE_LENGTH,
		      type);
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
    dissect_unrecognized_parameters_parameter(parameter_tvb, pinfo,  parameter_tree, parameter_item);
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
  case UNRELIABLE_STREAMS_PARAMETER_ID:
    dissect_unreliable_streams_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ADD_IP_ADDRESS_PARAMETER_ID:
    dissect_add_ip_address_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
    break;
  case DEL_IP_ADDRESS_PARAMETER_ID:
    dissect_del_ip_address_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
    break;
  case ERROR_CAUSE_INDICATION_PARAMETER_ID:
    dissect_error_cause_indication_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
    break;
  case SET_PRIMARY_ADDRESS_PARAMETER_ID:
    dissect_set_primary_address_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
    break;    
  case SUCCESS_REPORT_PARAMETER_ID:
    dissect_success_report_parameter(parameter_tvb, parameter_tree, parameter_item);
    break; 
  case ADAP_LAYER_INDICATION_PARAMETER_ID:
    dissect_adap_indication_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;    
  default:
    dissect_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  };
  if ((padding_length > 0) && (type != UNREC_PARA_PARAMETER_ID))
    proto_tree_add_text(parameter_tree, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
}

/*
 * Code to handle error causes for ABORT and ERROR chunks
 */
static void
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

static void
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
    proto_tree_add_uint(cause_tree, hf_sctp_cause_missing_parameter_type,
			cause_tvb, offset, CAUSE_MISSING_PARAMETER_TYPE_LENGTH,
			parameter_type);
    offset +=  CAUSE_MISSING_PARAMETER_TYPE_LENGTH;
  };

  proto_item_set_text(cause_item, "Error cause reporting %u missing mandatory parameter%s",
		      number_of_missing_parameters, plurality(number_of_missing_parameters, "", "s") );
}

static void
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

static void
dissect_out_of_resource_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_item_set_text(cause_item, "Error cause reporting lack of resources");
}

static void
dissect_unresolvable_address_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 code, length, parameter_length, parameter_type;
  tvbuff_t *parameter_tvb;

  code   = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  
  parameter_length = length - CAUSE_HEADER_LENGTH;
  parameter_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, 
				 parameter_length, parameter_length);

  dissect_parameter(parameter_tvb, pinfo, cause_tree);
  parameter_type = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
 
  proto_item_set_text(cause_item, "Error cause reporting unresolvable address of type 0x%04x (%s)",
		      parameter_type, val_to_str(parameter_type, sctp_parameter_identifier_values, "unknown") );
}

static void
dissect_unrecognized_chunk_type_cause(tvbuff_t *cause_tvb,  packet_info *pinfo, 
				      proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 length, chunk_length;
  guint8 unrecognized_type;
  tvbuff_t *unrecognized_chunk_tvb;

  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  
  chunk_length = length - CAUSE_HEADER_LENGTH;

  unrecognized_chunk_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, chunk_length, chunk_length);
  dissect_sctp_chunk(unrecognized_chunk_tvb, pinfo, cause_tree,cause_tree);

  unrecognized_type   = tvb_get_guint8(unrecognized_chunk_tvb, CHUNK_TYPE_OFFSET);
 
  proto_item_set_text(cause_item, "Error cause reporting unrecognized chunk of type %u (%s)",
		      unrecognized_type,
		      val_to_str(unrecognized_type, sctp_chunk_type_values, "unknown"));
}

static void
dissect_invalid_mandatory_parameter_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_item_set_text(cause_item, "Error cause reporting an invalid mandatory parameter");
}

static void
dissect_unrecognized_parameters_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 length, padding_length, cause_info_length;
  tvbuff_t *unrecognized_parameters_tvb;

  length            = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  padding_length    = nr_of_padding_bytes(length);
  cause_info_length = length - CAUSE_HEADER_LENGTH + padding_length;

  unrecognized_parameters_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  dissect_tlv_parameter_list(unrecognized_parameters_tvb, pinfo, cause_tree);
 
  proto_item_set_text(cause_item, "Error cause reporting unrecognized parameters");
}

static void
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

static void
dissect_cookie_received_while_shutting_down_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_item_set_text(cause_item, "Error cause reporting cookie reception while shutting down");
}

static void
dissect_delete_last_address_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 length, cause_info_length;
  tvbuff_t *parameter_tvb;

  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  cause_info_length = length - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  dissect_parameter(parameter_tvb, pinfo, cause_tree); 
  proto_item_set_text(cause_item, "Delete last address cause");
}

static void
dissect_resource_outage_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 length, cause_info_length;
  tvbuff_t *parameter_tvb;

  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  cause_info_length = length - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  dissect_parameter(parameter_tvb, pinfo, cause_tree); 
  proto_item_set_text(cause_item, "Operation refused due to resource shortage");
}

static void
dissect_delete_source_address_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 length, cause_info_length;
  tvbuff_t *parameter_tvb;

  length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  cause_info_length = length - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  dissect_parameter(parameter_tvb, pinfo, cause_tree); 
  proto_item_set_text(cause_item, "Delete source address cause");
}

static void
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

static void
dissect_error_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *chunk_tree)
{
  guint16 code, length, padding_length, total_length;
  proto_item *cause_item;
  proto_tree *cause_tree;

  code           = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length         = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  total_length   = length + padding_length;

  cause_item = proto_tree_add_text(chunk_tree, cause_tvb,
				   CAUSE_HEADER_OFFSET, total_length,
				   "BAD ERROR CAUSE");
  cause_tree = proto_item_add_subtree(cause_item, ett_sctp_chunk_cause);
 
  proto_tree_add_uint(cause_tree, hf_sctp_cause_code, 
		      cause_tvb, CAUSE_CODE_OFFSET, CAUSE_CODE_LENGTH,
		      code);
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
    dissect_unresolvable_address_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case UNRECOGNIZED_CHUNK_TYPE:
    dissect_unrecognized_chunk_type_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case INVALID_MANDATORY_PARAMETER:
    dissect_invalid_mandatory_parameter_cause(cause_tvb, cause_tree, cause_item);
    break;
  case UNRECOGNIZED_PARAMETERS:
    dissect_unrecognized_parameters_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case NO_USER_DATA:
    dissect_no_user_data_cause(cause_tvb, cause_tree, cause_item);
    break;
  case COOKIE_RECEIVED_WHILE_SHUTTING_DOWN:
    dissect_cookie_received_while_shutting_down_cause(cause_tvb, cause_tree, cause_item);
    break;
  case REQUEST_TO_DELETE_LAST_ADDRESS:
    dissect_delete_last_address_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case OPERATION_REFUSED_DUE_TO_RESOURCE_SHORTAGE:
    dissect_resource_outage_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case REQUEST_TO_DELETE_SOURCE_ADDRESS:
    dissect_delete_source_address_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  default:
    dissect_unknown_cause(cause_tvb, cause_tree, cause_item);
    break;
  };
  if ((padding_length > 0) && (code != UNRECOGNIZED_PARAMETERS))
    proto_tree_add_text(cause_tree, cause_tvb, CAUSE_HEADER_OFFSET + length, padding_length,
			"Padding: %u byte%s",
			padding_length, plurality(padding_length, "", "s"));
}

/*
 * Code to actually dissect the packets 
*/

static gboolean
dissect_payload(tvbuff_t *payload_tvb, packet_info *pinfo, proto_tree *tree,
		proto_tree *chunk_tree, guint32 ppi, guint16 payload_length, guint16 padding_length)
{
  /* do lookup with the subdissector table */
  if (dissector_try_port (sctp_ppi_dissector_table, ppi,  payload_tvb, pinfo, tree) ||
      dissector_try_port(sctp_port_dissector_table, pinfo->srcport,  payload_tvb, pinfo, tree) ||
      dissector_try_port(sctp_port_dissector_table, pinfo->destport, payload_tvb, pinfo, tree)){
    return TRUE;
  }
  else {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_str(pinfo->cinfo, COL_INFO, "DATA ");
    proto_tree_add_text(chunk_tree, payload_tvb, 0, payload_length,
			"Payload (%u byte%s)",
			payload_length, plurality(payload_length, "", "s")); 
    if (padding_length > 0)
      proto_tree_add_text(chunk_tree, payload_tvb, payload_length, padding_length,
			  "Padding: %u byte%s",
			  padding_length, plurality(padding_length, "", "s"));
    return FALSE;
  }
}

static gboolean
dissect_data_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint8  flags;
  guint16 length, total_payload_length, payload_length, padding_length, stream_id, stream_seq_number;
  guint32 tsn, payload_proto_id;
  proto_tree *flag_tree;
  tvbuff_t *payload_tvb;
   
  length            = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
  payload_length       = length - DATA_CHUNK_HEADER_LENGTH;
  padding_length       = nr_of_padding_bytes(length);
  total_payload_length = payload_length + padding_length;
  payload_tvb          = tvb_new_subset(chunk_tvb, DATA_CHUNK_PAYLOAD_OFFSET,
					  total_payload_length, total_payload_length);
  payload_proto_id     = tvb_get_ntohl(chunk_tvb, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET);

  if (chunk_tree) {
    flags             = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET);
     
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
			chunk_tvb, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH,
			payload_proto_id);
    proto_item_set_text(chunk_item, "DATA chunk with TSN %u (%u:%u) containing %u byte%s of payload",
			tsn, stream_id, stream_seq_number, 
			payload_length, plurality(payload_length, "", "s"));
  };   
  return dissect_payload(payload_tvb, pinfo, tree, chunk_tree, payload_proto_id, payload_length, padding_length); 
}

static void
dissect_init_chunk(tvbuff_t *chunk_tvb,  packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 initiate_tag, adv_rec_window_credit, initial_tsn;
  guint16 number_of_inbound_streams, number_of_outbound_streams;
  guint8  type;
  tvbuff_t *parameter_list_tvb;

  type                       = tvb_get_guint8(chunk_tvb, CHUNK_TYPE_OFFSET);
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    if (type == SCTP_INIT_CHUNK_ID) {
      col_append_str(pinfo->cinfo, COL_INFO, "INIT ");
    } else {
      col_append_str(pinfo->cinfo, COL_INFO, "INIT_ACK ");
    };
  };
  
  if (chunk_tree) {
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
    dissect_tlv_parameter_list(parameter_list_tvb, pinfo, chunk_tree);
    
    proto_item_set_text(chunk_item, 
			"%s chunk requesting for %u outbound stream%s and accepting up to %u inbound stream%s",
			val_to_str(type, sctp_chunk_type_values, "unknown"),
			number_of_outbound_streams, plurality(number_of_outbound_streams, "", "s"),
			number_of_inbound_streams, plurality(number_of_inbound_streams, "", "s"));
  }
} 

static void
dissect_init_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		       proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  dissect_init_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
} 

static void
dissect_sack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 cumulative_tsn_ack, adv_rec_window_credit, dup_tsn;
  guint16 number_of_gap_blocks, number_of_dup_tsns;
  guint16 gap_block_number, dup_tsn_number, start, end;
  gint gap_block_offset, dup_tsn_offset;
  proto_item *block_item;
  proto_tree *block_tree;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "SACK ");

  if (chunk_tree) {
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
    }
    
    proto_item_set_text(chunk_item, 
			"SACK chunk acknowledging TSN %u and reporting %u gap%s and %u duplicate TSN%s",
			cumulative_tsn_ack,
			number_of_gap_blocks, plurality(number_of_gap_blocks, "", "s"),
			number_of_dup_tsns, plurality(number_of_dup_tsns, "", "s"));
  } 
}

static void
dissect_heartbeat_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{
  tvbuff_t   *parameter_tvb;
  guint chunk_length, info_length, padding_length, total_length;
    
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "HEARTBEAT ");

  if (chunk_tree) {
    chunk_length   = tvb_get_ntohs(chunk_tvb,  CHUNK_LENGTH_OFFSET);
    info_length    = chunk_length - CHUNK_HEADER_LENGTH;
    padding_length = nr_of_padding_bytes(info_length);
    total_length   = info_length + padding_length;
    parameter_tvb  = tvb_new_subset(chunk_tvb, HEARTBEAT_CHUNK_INFO_OFFSET, total_length, total_length);
    
    dissect_parameter(parameter_tvb, pinfo, chunk_tree);
    
    proto_item_set_text(chunk_item, "HEARTBEAT chunk");
  }
}
 
static void
dissect_heartbeat_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			    proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{  
  tvbuff_t   *parameter_tvb;
  guint chunk_length, info_length, padding_length, total_length;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "HEARTBEAT_ACK ");

  if (chunk_tree) {
    chunk_length   = tvb_get_ntohs(chunk_tvb,  CHUNK_LENGTH_OFFSET);
    info_length    = chunk_length - CHUNK_HEADER_LENGTH;
    padding_length = nr_of_padding_bytes(info_length);
    total_length   = info_length + padding_length;

    parameter_tvb  = tvb_new_subset(chunk_tvb, HEARTBEAT_CHUNK_INFO_OFFSET, total_length, total_length);
    
    dissect_parameter(parameter_tvb, pinfo, chunk_tree);
    
    proto_item_set_text(chunk_item, "HEARTBEAT ACK chunk");
  } 
}

static void
dissect_abort_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		    proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{
  guint offset, number_of_causes;
  guint16 length, padding_length, total_length;
  tvbuff_t *cause_tvb;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "ABORT ");

  if (chunk_tree) {
    number_of_causes = 0;
    offset = ABORT_CHUNK_FIRST_ERROR_CAUSE_OFFSET;
    while(tvb_reported_length_remaining(chunk_tvb, offset)) {
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
}

static void
dissect_shutdown_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		       proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 cumulative_tsn_ack;
 
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "SHUTDOWN ");

  if (chunk_tree) {
    cumulative_tsn_ack = tvb_get_ntohl(chunk_tvb, SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
    proto_tree_add_uint(chunk_tree, hf_sctp_shutdown_chunk_cumulative_tsn_ack, 
			chunk_tvb,
			SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET,
			SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_LENGTH,
			cumulative_tsn_ack);
    
    proto_item_set_text(chunk_item, "SHUTDOWN chunk acknowledging up to TSN %u",
			cumulative_tsn_ack);
  } 
}

static void
dissect_shutdown_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "SHUTDOWN_ACK ");

  if (chunk_tree) {
    proto_item_set_text(chunk_item, "SHUTDOWN ACK chunk");
  } 
}

static void
dissect_error_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		    proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint offset, number_of_causes;
  guint16 length, padding_length, total_length;
  tvbuff_t *cause_tvb;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "ERROR ");

  if (chunk_tree) {
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
    } while(tvb_reported_length_remaining(chunk_tvb, offset));
    
    proto_item_set_text(chunk_item, "Error chunk with %u cause%s",
			number_of_causes, plurality(number_of_causes, "", "s"));
  } 
}

static void
dissect_cookie_echo_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			  proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint length, cookie_length, padding_length;

  length         = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
  padding_length = nr_of_padding_bytes(length);
  cookie_length  = length - CHUNK_HEADER_LENGTH;
 
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "COOKIE_ECHO ");

  if (chunk_tree) {  
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
}

static void
dissect_cookie_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
			 proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "COOKIE_ACK ");

  if (chunk_tree) {
    proto_item_set_text(chunk_item, "COOKIE ACK chunk");
  } 
}

static void
dissect_ecne_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		   proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 lowest_tsn;
 
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "ECNE ");

  if (chunk_tree) {
    lowest_tsn = tvb_get_ntohl(chunk_tvb, ECNE_CHUNK_LOWEST_TSN_OFFSET);
    proto_tree_add_uint(chunk_tree, hf_sctp_ecne_chunk_lowest_tsn, 
			chunk_tvb,
			ECNE_CHUNK_LOWEST_TSN_OFFSET, ECNE_CHUNK_LOWEST_TSN_LENGTH,
			lowest_tsn);
    
    proto_item_set_text(chunk_item, "ECNE chunk");
  } 
}

static void
dissect_cwr_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		  proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 lowest_tsn;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "CWR ");

  if (chunk_tree) {
    lowest_tsn = tvb_get_ntohl(chunk_tvb, CWR_CHUNK_LOWEST_TSN_OFFSET);
    proto_tree_add_uint(chunk_tree, hf_sctp_cwr_chunk_lowest_tsn, 
			chunk_tvb,
			CWR_CHUNK_LOWEST_TSN_OFFSET, CWR_CHUNK_LOWEST_TSN_LENGTH,
			lowest_tsn);
    
    proto_item_set_text(chunk_item, "CWR chunk");
  } 
}

static void
dissect_shutdown_complete_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
				proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint8  flags;
  guint16 length;
  proto_tree *flag_tree;
 
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "SHUTDOWN_COMPLETE ");

  if (chunk_tree) {
    flags             = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET);
    length            = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
    
    flag_tree = proto_item_add_subtree(flags_item, ett_sctp_data_chunk_flags);
    proto_tree_add_boolean(flag_tree, hf_sctp_shutdown_complete_chunk_t_bit, chunk_tvb,
			   CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, flags);
    
    proto_item_set_text(chunk_item, "SHUTDOWN COMPLETE chunk");
  } 
}

#define FORWARD_TSN_CHUNK_TSN_OFFSET CHUNK_VALUE_OFFSET
#define FORWARD_TSN_CHUNK_TSN_LENGTH 4

static void
dissect_forward_tsn_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 tsn;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "FORWARD TSN ");

  if (chunk_tree) {
    tsn = tvb_get_ntohl(chunk_tvb, FORWARD_TSN_CHUNK_TSN_OFFSET);
    proto_tree_add_uint(chunk_tree, hf_sctp_forward_tsn_chunk_tsn, chunk_tvb, FORWARD_TSN_CHUNK_TSN_OFFSET, FORWARD_TSN_CHUNK_TSN_LENGTH, tsn);
    proto_item_set_text(chunk_item, "FORWARD TSN chunk (new cumulative TSN %u)", tsn);
  } 
}

#define SERIAL_NUMBER_LENGTH    4
#define CORRELATION_ID_LENGTH   4
#define ASCONF_RESERVED_LENGTH  3
#define ASCONF_ADDR_TYPE_LENGTH 1
#define ASCONF_ADDR_LENGTH      16
#define SERIAL_NUMBER_OFFSET    PARAMETER_VALUE_OFFSET

#define IP_V4_ADDRESS_TYPE      5
#define IP_V6_ADDRESS_TYPE      6

static const value_string sctp_address_type_values[] = {
  { IP_V4_ADDRESS_TYPE,         "IP V4 address" },
  { IP_V6_ADDRESS_TYPE,         "IP V6 address" },
  { 0,                           NULL } };

static void
dissect_asconf_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 serial_number, correlation_id, ipv4_address;
  guint offset, length, padding_length, total_length;
  guint8 addr_type;
  tvbuff_t *parameter_tvb;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "ASCONF ");

  if (chunk_tree) {
    offset = SERIAL_NUMBER_OFFSET;
    serial_number    = tvb_get_ntohl(chunk_tvb, offset);
    proto_tree_add_uint(chunk_tree, hf_sctp_asconf_serial, chunk_tvb, offset, SERIAL_NUMBER_LENGTH, serial_number);
    offset          += SERIAL_NUMBER_LENGTH;
    proto_tree_add_bytes(chunk_tree, hf_sctp_asconf_reserved, chunk_tvb, offset, ASCONF_RESERVED_LENGTH, tvb_get_ptr(chunk_tvb, offset, ASCONF_RESERVED_LENGTH));
    offset          += ASCONF_RESERVED_LENGTH;
    addr_type = tvb_get_guint8(chunk_tvb, offset);
    proto_tree_add_uint(chunk_tree, hf_sctp_asconf_addr_type, chunk_tvb, offset, ASCONF_ADDR_TYPE_LENGTH, addr_type);
    offset          += ASCONF_ADDR_TYPE_LENGTH;
    switch (addr_type) {
      case IP_V4_ADDRESS_TYPE:
        tvb_memcpy(chunk_tvb, (guint8 *)&ipv4_address, offset, IPV4_ADDRESS_LENGTH); 
        proto_tree_add_ipv4(chunk_tree, hf_sctp_asconf_ipv4_address, chunk_tvb, offset, IPV4_ADDRESS_LENGTH, ipv4_address);
        proto_tree_add_bytes(chunk_tree, hf_sctp_asconf_addr, chunk_tvb, offset + IPV4_ADDRESS_LENGTH, ASCONF_ADDR_LENGTH - IPV4_ADDRESS_LENGTH,
                             tvb_get_ptr(chunk_tvb, offset + IPV4_ADDRESS_LENGTH, ASCONF_ADDR_LENGTH - IPV4_ADDRESS_LENGTH));
        break;
      case IP_V6_ADDRESS_TYPE:
          proto_tree_add_ipv6(chunk_tree, hf_sctp_asconf_ipv6_address, chunk_tvb, offset, IPV6_ADDRESS_LENGTH,
		                          tvb_get_ptr(chunk_tvb, offset, IPV6_ADDRESS_LENGTH));
        break;
      default:
        proto_tree_add_bytes(chunk_tree, hf_sctp_asconf_addr, chunk_tvb, offset, ASCONF_ADDR_LENGTH, tvb_get_ptr(chunk_tvb, offset, ASCONF_ADDR_LENGTH));
        break;
    }
    offset          += ASCONF_ADDR_LENGTH;
    proto_item_set_text(chunk_item, "ASCONF chunk");
    
    while(tvb_reported_length_remaining(chunk_tvb, offset)) {
      correlation_id = tvb_get_ntohl(chunk_tvb, offset);
      proto_tree_add_uint(chunk_tree, hf_sctp_asconf_correlation_id, chunk_tvb, offset, CORRELATION_ID_LENGTH, correlation_id);
      offset        += CORRELATION_ID_LENGTH;
      length         = tvb_get_ntohs(chunk_tvb, offset + PARAMETER_LENGTH_OFFSET);
      padding_length = nr_of_padding_bytes(length);
      total_length   = length + padding_length;
      /* create a tvb for the chunk including the padding bytes */
      parameter_tvb  = tvb_new_subset(chunk_tvb, offset, total_length, total_length);
      dissect_parameter(parameter_tvb, pinfo, chunk_tree); 
      /* get rid of the handled parameter */
      offset        += total_length;
    }
  } 
}

static void
dissect_asconf_ack_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint32 serial_number, correlation_id;
  guint offset, length, padding_length, total_length;
  tvbuff_t *parameter_tvb;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "ASCONF-ACK ");

  if (chunk_tree) {
    serial_number = tvb_get_ntohl(chunk_tvb, SERIAL_NUMBER_OFFSET);
    proto_tree_add_uint(chunk_tree, hf_sctp_asconf_ack_serial, chunk_tvb, SERIAL_NUMBER_OFFSET, SERIAL_NUMBER_LENGTH, serial_number);
    proto_item_set_text(chunk_item, "ASCONF-ACK chunk");
    
    offset = SERIAL_NUMBER_OFFSET + SERIAL_NUMBER_LENGTH;
    while(tvb_reported_length_remaining(chunk_tvb, offset)) {
      correlation_id = tvb_get_ntohl(chunk_tvb, offset);
      proto_tree_add_uint(chunk_tree, hf_sctp_asconf_ack_correlation_id, chunk_tvb, offset, CORRELATION_ID_LENGTH, correlation_id);
      offset        += CORRELATION_ID_LENGTH;
      length         = tvb_get_ntohs(chunk_tvb, offset + PARAMETER_LENGTH_OFFSET);
      padding_length = nr_of_padding_bytes(length);
      total_length   = length + padding_length;
      /* create a tvb for the chunk including the padding bytes */
      parameter_tvb  = tvb_new_subset(chunk_tvb, offset, total_length, total_length);
      dissect_parameter(parameter_tvb, pinfo, chunk_tree); 
      /* get rid of the handled parameter */
      offset        += total_length;
    }
  } 
}

static void
dissect_unknown_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree,
		      proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{ 
  guint length, chunk_value_length, padding_length;
  guint8 type;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "UNKNOWN ");

  if (chunk_tree) {
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
} 


static gboolean
dissect_sctp_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *sctp_tree)
{  
  guint8 type, flags;
  guint16 length;
  gboolean result;
  proto_item *flags_item;
  proto_item *chunk_item;
  proto_tree *chunk_tree;

  result = FALSE;
  
  /* first extract the chunk header */
  type   = tvb_get_guint8(chunk_tvb, CHUNK_TYPE_OFFSET);
  flags  = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET);
  length = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
 
  if (tree) {
    /* create proto_tree stuff */
    chunk_item   = proto_tree_add_text(sctp_tree, chunk_tvb, CHUNK_HEADER_OFFSET, -1, "Incomplete chunk");
    chunk_tree   = proto_item_add_subtree(chunk_item, ett_sctp_chunk);
    
    /* then insert the chunk header components into the protocol tree */
    proto_tree_add_uint(chunk_tree, hf_sctp_chunk_type, chunk_tvb, CHUNK_TYPE_OFFSET, CHUNK_TYPE_LENGTH, type);
    flags_item = proto_tree_add_uint(chunk_tree, hf_sctp_chunk_flags, chunk_tvb, CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, flags);
    proto_tree_add_uint(chunk_tree, hf_sctp_chunk_length, chunk_tvb, CHUNK_LENGTH_OFFSET, CHUNK_LENGTH_LENGTH, length);
  } else {
    chunk_tree = NULL;
    chunk_item = NULL;
    flags_item = NULL;
  };
  
  /* now dissect the chunk value */

  switch(type) {
  case SCTP_DATA_CHUNK_ID:
    result = dissect_data_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
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
  case SCTP_FORWARD_TSN_CHUNK_ID:
    dissect_forward_tsn_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_ASCONF_ACK_CHUNK_ID:
    dissect_asconf_ack_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_ASCONF_CHUNK_ID:
    dissect_asconf_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  default:
    dissect_unknown_chunk(chunk_tvb, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  };
  return result;
}

static void
dissect_sctp_chunks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *sctp_item, proto_tree *sctp_tree)
{ 
  tvbuff_t *chunk_tvb;
  guint16 length, padding_length, total_length;
  gint last_offset, offset;
  gboolean sctp_item_length_set;

  /* the common header of the datagram is already handled */
  last_offset = 0;
  offset = COMMON_HEADER_LENGTH;
  sctp_item_length_set = FALSE;

  while(tvb_reported_length_remaining(tvb, offset) > 0) {
    /* extract the chunk length and compute number of padding bytes */
    length         = tvb_get_ntohs(tvb, offset + CHUNK_LENGTH_OFFSET);
    padding_length = nr_of_padding_bytes(length);
    total_length   = length + padding_length;
    /* create a tvb for the chunk including the padding bytes */
    chunk_tvb    = tvb_new_subset(tvb, offset, total_length, total_length);
    /* call dissect_sctp_chunk for a actual work */
    if (dissect_sctp_chunk(chunk_tvb, pinfo, tree, sctp_tree) && (tree)) {
      proto_item_set_len(sctp_item, offset - last_offset + DATA_CHUNK_HEADER_LENGTH);
      sctp_item_length_set = TRUE;
      offset += total_length;
      last_offset = offset;
      if (tvb_reported_length_remaining(tvb, offset) > 0) {
	sctp_item = proto_tree_add_item(tree, proto_sctp, tvb, offset, -1, FALSE);
	sctp_tree = proto_item_add_subtree(sctp_item, ett_sctp);
	sctp_item_length_set = FALSE;
      }
    } else {
    /* get rid of the dissected chunk */
    offset += total_length;
    }
  };
  if (!sctp_item_length_set && (tree)) { 
    proto_item_set_len(sctp_item, offset - last_offset);
  };
}

/* dissect_sctp handles the common header of a SCTP datagram.
 * For the handling of the chunks dissect_sctp_chunks is called.
 */

static void
dissect_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 source_port, destination_port;
  guint32 verification_tag, checksum, calculated_crc32c, calculated_adler32;
  guint length;
  gboolean crc32c_correct, adler32_correct;
  proto_item *sctp_item;
  proto_tree *sctp_tree;

  /* Extract the common header */
  source_port      = tvb_get_ntohs(tvb, SOURCE_PORT_OFFSET);
  destination_port = tvb_get_ntohs(tvb, DESTINATION_PORT_OFFSET);
  verification_tag = tvb_get_ntohl(tvb, VERIFICATION_TAG_OFFSET);
  checksum         = tvb_get_ntohl(tvb, CHECKSUM_OFFSET);

  /* update pi structure */
  pinfo->ptype    = PT_SCTP;
  pinfo->srcport  = source_port;
  pinfo->destport = destination_port;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCTP");

  /* Clear entries in Info column on summary display */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, "");
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the sctp protocol tree */
    sctp_item = proto_tree_add_item(tree, proto_sctp, tvb, 0, -1, FALSE);
    sctp_tree = proto_item_add_subtree(sctp_item, ett_sctp);
    
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(sctp_tree, hf_sctp_source_port, tvb, SOURCE_PORT_OFFSET, SOURCE_PORT_LENGTH, source_port);
    proto_tree_add_uint(sctp_tree, hf_sctp_destination_port, tvb, DESTINATION_PORT_OFFSET, DESTINATION_PORT_LENGTH, destination_port);
    proto_tree_add_uint(sctp_tree, hf_sctp_verification_tag, tvb, VERIFICATION_TAG_OFFSET, VERIFICATION_TAG_LENGTH, verification_tag);
    proto_tree_add_uint_hidden(sctp_tree, hf_sctp_port, tvb, SOURCE_PORT_OFFSET, SOURCE_PORT_LENGTH, source_port);
    proto_tree_add_uint_hidden(sctp_tree, hf_sctp_port, tvb, DESTINATION_PORT_OFFSET, DESTINATION_PORT_LENGTH, destination_port);

    length = tvb_length(tvb);
    switch(sctp_checksum) {
    case SCTP_CHECKSUM_NONE:
      proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, checksum, "Checksum: 0x%08x (not verified)", checksum);
      break;
    case SCTP_CHECKSUM_ADLER32:
      calculated_adler32 = sctp_adler32(tvb_get_ptr(tvb, 0, length), length);
      adler32_correct    = (checksum == calculated_adler32);
      if (adler32_correct)
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x (correct Adler32)", checksum);
      else
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, 
                                   checksum, "Checksum: 0x%08x (incorrect Adler32, should be 0x%08x)", checksum, calculated_adler32);    
      proto_tree_add_boolean_hidden(sctp_tree, hf_sctp_checksum_bad, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, !(adler32_correct));
      break;
    case SCTP_CHECKSUM_CRC32C:
      calculated_crc32c = sctp_crc32c(tvb_get_ptr(tvb, 0, length), length);
      crc32c_correct    = (checksum == calculated_crc32c);
      if (crc32c_correct)
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x (correct CRC32C)", checksum);
      else
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, 
                                   checksum, "Checksum: 0x%08x (incorrect CRC32C, should be 0x%08x)", checksum, calculated_crc32c);    
      proto_tree_add_boolean_hidden(sctp_tree, hf_sctp_checksum_bad, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, !(crc32c_correct));
      break;
    case SCTP_CHECKSUM_AUTOMATIC:
      calculated_adler32 = sctp_adler32(tvb_get_ptr(tvb, 0, length), length);
      adler32_correct    = (checksum == calculated_adler32);
      calculated_crc32c  = sctp_crc32c(tvb_get_ptr(tvb, 0, length), length);
      crc32c_correct     = (checksum == calculated_crc32c);
      if ((adler32_correct) && !(crc32c_correct))
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x (correct Adler32)", checksum);
      else if (!(adler32_correct) && (crc32c_correct))
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x (correct CRC32C)", checksum);
      else if ((adler32_correct) && (crc32c_correct))
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x (correct Adler32 and CRC32C)", checksum);
      else
        proto_tree_add_uint_format(sctp_tree, hf_sctp_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, 
                                   checksum, "Checksum: 0x%08x (incorrect, should be 0x%08x (Adler32) or 0x%08x (CRC32C))",
                                   checksum, calculated_adler32, calculated_crc32c);
      proto_tree_add_boolean_hidden(sctp_tree, hf_sctp_checksum_bad, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, !(crc32c_correct || adler32_correct));
      break;
    }
  } else {
    sctp_tree = NULL;
    sctp_item = NULL;
  };
  /* add all chunks of the sctp datagram to the protocol tree */
  dissect_sctp_chunks(tvb, pinfo, tree, sctp_item, sctp_tree);
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
	      "", HFILL }
    },
    { &hf_sctp_destination_port,
      { "Destination port", "sctp.dstport",
	       FT_UINT16, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sctp_port,
      { "Port", "sctp.port",
	       FT_UINT16, BASE_DEC, NULL, 0x0,          
	       "", HFILL }
    }, 
    { &hf_sctp_verification_tag,
      { "Verification tag", "sctp.verfication_tag",
	       FT_UINT32, BASE_HEX, NULL, 0x0,          
	       "", HFILL }
    },
    { &hf_sctp_checksum,
      { "Checksum", "sctp.checksum",
	      FT_UINT32, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sctp_checksum_bad,
      { "Bad checksum", "sctp.checksum_bad",
	      FT_BOOLEAN, BASE_NONE, NULL, 0x0,          
	      "", HFILL }
    },
    { &hf_sctp_chunk_type,
      { "Identifier", "sctp.chunk_type",
	FT_UINT8, BASE_DEC, VALS(sctp_chunk_type_values), 0x0,          
	"", HFILL }
    },
    { &hf_sctp_chunk_flags,
      { "Flags", "sctp.chunk_flags",
	FT_UINT8, BASE_BIN, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_sctp_chunk_length,
      { "Length", "sctp.chunk_length",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_sctp_init_chunk_initiate_tag,
      { "Initiate tag", "sctp.init.chunk.initiate.tag",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_sctp_init_chunk_adv_rec_window_credit,
      { "Advertised reciever window credit (a_rwnd)", "sctp.init.chunk.credit",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_sctp_init_chunk_number_of_outbound_streams,
      { "Number of outbound streams", "sctp.init.chunk.nr.out.streams",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_sctp_init_chunk_number_of_inbound_streams,
      { "Number of inbound streams", "sctp.init.chunk.nr.in.streams",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    },
    {&hf_sctp_init_chunk_initial_tsn,
      { "Initial TSN", "sctp.init.chunk.initial.tsn",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    }, 
    {&hf_sctp_cumulative_tsn_ack,
     { "Cumulative TSN Ack", "sctp.cumulative.tsn.ack",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    },
    {&hf_sctp_data_chunk_tsn,
     { "TSN", "sctp.tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    },
    {&hf_sctp_data_chunk_stream_id,
     { "Stream Identifier", "sctp.stream_id",
	FT_UINT16, BASE_HEX, NULL, 0x0,          
	"", HFILL }
    },
    {&hf_sctp_data_chunk_stream_seq_number,
     { "Stream sequence number", "sctp.stream_seq_number",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_data_chunk_payload_proto_id,
     { "Payload protocol identifier", "sctp.payload_proto_id",
	FT_UINT32, BASE_DEC, VALS(sctp_payload_proto_id_values), 0x0,          
	"", HFILL }
    },
    {&hf_sctp_data_chunk_e_bit,
     { "E-Bit", "sctp.data.e_bit",
       FT_BOOLEAN, 8, TFS(&sctp_data_chunk_e_bit_value), SCTP_DATA_CHUNK_E_BIT,          
       "", HFILL }
    },
    {&hf_sctp_data_chunk_b_bit,
     { "B-Bit", "sctp.data.b_bit",
       FT_BOOLEAN, 8, TFS(&sctp_data_chunk_b_bit_value), SCTP_DATA_CHUNK_B_BIT,          
       "", HFILL }
    },
    {&hf_sctp_data_chunk_u_bit,
     { "U-Bit", "sctp.data.u.bit",
       FT_BOOLEAN, 8, TFS(&sctp_data_chunk_u_bit_value), SCTP_DATA_CHUNK_U_BIT,          
       "", HFILL }
    },
    {&hf_sctp_sack_chunk_cumulative_tsn_ack,
     { "Cumulative TSN ACK", "sctp.sack.cumulative_tsn_ack",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_sack_chunk_adv_rec_window_credit,
     { "Advertised receiver window credit (a_rwnd)", "sctp.sack.a_rwnd",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_sack_chunk_number_of_gap_blocks,
     { "Number of gap acknowldgement blocks ", "sctp.sack.number_of_gap_blocks",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_sack_chunk_number_of_dup_tsns,
     { "Number of duplicated TSNs", "sctp.sack.number_of_duplicated_tsns",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_sack_chunk_gap_block_start,
     { "Start", "sctp.sack.gap_block_start",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_sack_chunk_gap_block_end,
     { "End", "sctp.sack.gap_block_end",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_sack_chunk_duplicate_tsn,
     { "Duplicate TSN", "sctp.sack.duplicate.tsn",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },  
    {&hf_sctp_shutdown_chunk_cumulative_tsn_ack,
     { "Cumulative TSN Ack", "sctp.shutdown.cumulative_tsn_ack",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	"", HFILL }
    },
    {&hf_sctp_ecne_chunk_lowest_tsn,
     { "Lowest TSN", "sctp.ecne.lowest_tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_cwr_chunk_lowest_tsn,
     { "Lowest TSN", "sctp.cwr.lowest_tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_shutdown_complete_chunk_t_bit,
     { "E-Bit", "sctp.shutdown_complete.t_bit",
       FT_BOOLEAN, 8, TFS(&sctp_shutdown_complete_chunk_t_bit_value), SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT,
       "", HFILL }
    },
    {&hf_sctp_forward_tsn_chunk_tsn,
     { "New cumulative TSN", "sctp.forward_tsn.tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_chunk_parameter_type,
     { "Parameter type", "sctp.parameter.type",
       FT_UINT16, BASE_HEX, VALS(sctp_parameter_identifier_values), 0x0,
       "", HFILL }
    },
    {&hf_sctp_chunk_parameter_length,
     { "Parameter length", "sctp.parameter.length",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_parameter_ipv4_address,
     { "IP Version 4 address", "sctp.parameter.ipv4_address",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    {&hf_sctp_parameter_ipv6_address,
     { "IP Version 6 address", "sctp.parameter.ipv6_address",
       FT_IPv6, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    {&hf_sctp_parameter_cookie_preservative_increment,
     { "Suggested Cookie life-span increment (msec)", "sctp.parameter.cookie_preservative_incr",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_parameter_hostname_hostname,
     { "Hostname", "sctp.parameter.hostname.hostname",
       FT_STRING, BASE_NONE, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_supported_address_types_parameter,
     { "Supported address type", "sctp.parameter.supported_addres_type",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_ustreams_start,
     { "Start", "sctp.unreliable_streams.start",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_ustreams_end,
     { "End", "sctp.unreliable_streams.end",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },     
    {&hf_sctp_asconf_serial,
     { "Serial Number", "sctp.asconf.serial_number",
       FT_UINT32, BASE_HEX, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_asconf_correlation_id,
     { "Correlation_id", "sctp.asconf.correlation_id",
       FT_UINT32, BASE_HEX, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_asconf_reserved,
     { "Reserved", "sctp.asconf.reserved",
       FT_BYTES, BASE_NONE, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_asconf_addr_type,
     { "Address type", "sctp.asconf.address_type",
       FT_UINT8, BASE_HEX, VALS(sctp_address_type_values), 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_asconf_addr,
     { "Address bytes", "sctp.asconf.address_bytes",
       FT_BYTES, BASE_NONE, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_asconf_ipv4_address,
     { "IP Version 4 address", "sctp.asconf.ipv4_address",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    {&hf_sctp_asconf_ipv6_address,
     { "IP Version 6 address", "sctp.asconf.ipv6_address",
       FT_IPv6, BASE_NONE, NULL, 0x0,
       "", HFILL }
    },
    {&hf_sctp_asconf_ack_serial,
     { "Serial Number", "sctp.asconf_ack.serial_number",
       FT_UINT32, BASE_HEX, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_asconf_ack_correlation_id,
     { "Correlation_id", "sctp.asconf_ack.correlation_id",
       FT_UINT32, BASE_HEX, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_adap_indication,
     { "Indication", "sctp.adapation_layer_indication.indication",
       FT_UINT32, BASE_HEX, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_cause_code,
     { "Cause code", "sctp.cause.code",
       FT_UINT16, BASE_HEX, VALS(sctp_cause_code_values), 0x0,          
       "", HFILL }
    },
    {&hf_sctp_cause_length,
     { "Cause length", "sctp.cause.length",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_cause_stream_identifier,
     { "Stream identifier", "sctp.cause.stream_identifier",
       FT_UINT16, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_cause_number_of_missing_parameters,
     { "Number of missing parameters", "sctp.cause.nr_of_missing_parameters",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    }, 
    {&hf_sctp_cause_missing_parameter_type,
     { "Missing parameter type", "sctp.cause.missing_parameter_type",
       FT_UINT16, BASE_HEX, VALS(sctp_parameter_identifier_values), 0x0,
       "", HFILL }
    },
    {&hf_sctp_cause_measure_of_staleness,
     { "Measure of staleness in usec", "sctp.cause.measure_of_staleness",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
    },
    {&hf_sctp_cause_tsn,
     { "TSN", "sctp.cause.tsn",
       FT_UINT32, BASE_DEC, NULL, 0x0,          
       "", HFILL }
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
    &ett_sctp_unrecognized_parameter_parameter,
    &ett_sctp_unreliable_streams_interval
  };
  
  static enum_val_t sctp_checksum_options[] = {
    { "None",        SCTP_CHECKSUM_NONE },
    { "Adler 32",    SCTP_CHECKSUM_ADLER32 },
    { "CRC 32c",     SCTP_CHECKSUM_CRC32C },
    { "Automatic",   SCTP_CHECKSUM_AUTOMATIC},
    { NULL, 0 }
  };
 
  /* Register the protocol name and description */
  proto_sctp = proto_register_protocol("Stream Control Transmission Protocol", "SCTP", "sctp");
  sctp_module = prefs_register_protocol(proto_sctp, NULL);
  prefs_register_enum_preference(sctp_module, "checksum",
				 "Checksum type",
				 "The type of checksum used in SCTP packets",
                                 &sctp_checksum, sctp_checksum_options, FALSE);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sctp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* subdissector code */
  sctp_port_dissector_table = register_dissector_table("sctp.port", "SCTP port", FT_UINT16, BASE_DEC);
  sctp_ppi_dissector_table  = register_dissector_table("sctp.ppi",  "SCTP payload protocol identifier", FT_UINT32, BASE_HEX);

};

void
proto_reg_handoff_sctp(void)
{
  dissector_handle_t sctp_handle;

  sctp_handle = create_dissector_handle(dissect_sctp, proto_sctp);
  dissector_add("ip.proto", IP_PROTO_SCTP, sctp_handle);
}
