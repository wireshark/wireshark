/* packet-sctp.c
 * Routines for Stream Control Transmission Protocol dissection
 *
 * It should be compilant to
 * - RFC 2960
 * - RFC 3309
 * - RFC 3758
 * - http://www.ietf.org/internet-drafts/draft-ietf-tsvwg-sctpimpguide-15.txt
 * - http://www.ietf.org/internet-drafts/draft-ietf-tsvwg-addip-sctp-13.txt
 * - http://www.ietf.org/internet-drafts/draft-ietf-tsvwg-sctp-auth-02.txt
 * - http://www.ietf.org/internet-drafts/draft-stewart-sctp-pktdrprep-02.txt
 * - http://www.ietf.org/internet-drafts/draft-stewart-sctpstrrst-01.txt
 * - http://www.ietf.org/internet-drafts/draft-ladha-sctp-nonce-02.txt
 *
 *
 * Copyright 2000-2005 Michael Tuexen <tuexen [AT] fh-muenster.de>
 * Still to do (so stay tuned)
 * - support for reassembly
 * - error checking mode
 *   * padding errors
 *   * length errors
 *   * bundling errors
 *   * value errors
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include "packet-sctp.h"
#include <epan/sctpppids.h>

#define NETWORK_BYTE_ORDER     FALSE
#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)
#define UDP_TUNNELING_PORT 9899

/* Initialize the protocol and registered fields */
static int proto_sctp = -1;
static int hf_port = -1;
static int hf_source_port      = -1;
static int hf_destination_port = -1;
static int hf_verification_tag = -1;
static int hf_checksum         = -1;
static int hf_checksum_bad     = -1;

static int hf_chunk_type       = -1;
static int hf_chunk_flags      = -1;
static int hf_chunk_bit_1      = -1;
static int hf_chunk_bit_2      = -1;
static int hf_chunk_length     = -1;
static int hf_chunk_padding    = -1;
static int hf_chunk_value    = -1;

static int hf_initiate_tag   = -1;
static int hf_init_chunk_initiate_tag   = -1;
static int hf_init_chunk_adv_rec_window_credit = -1;
static int hf_init_chunk_number_of_outbound_streams = -1;
static int hf_init_chunk_number_of_inbound_streams  = -1;
static int hf_init_chunk_initial_tsn    = -1;

static int hf_initack_chunk_initiate_tag   = -1;
static int hf_initack_chunk_adv_rec_window_credit = -1;
static int hf_initack_chunk_number_of_outbound_streams = -1;
static int hf_initack_chunk_number_of_inbound_streams  = -1;
static int hf_initack_chunk_initial_tsn    = -1;

static int hf_cumulative_tsn_ack = -1;

static int hf_data_chunk_tsn = -1;
static int hf_data_chunk_stream_id = -1;
static int hf_data_chunk_stream_seq_number = -1;
static int hf_data_chunk_payload_proto_id = -1;

static int hf_data_chunk_e_bit = -1;
static int hf_data_chunk_b_bit = -1;
static int hf_data_chunk_u_bit = -1;

static int hf_sack_chunk_ns = -1;
static int hf_sack_chunk_cumulative_tsn_ack = -1;
static int hf_sack_chunk_adv_rec_window_credit = -1;
static int hf_sack_chunk_number_of_gap_blocks = -1;
static int hf_sack_chunk_number_of_dup_tsns = -1;
static int hf_sack_chunk_gap_block_start = -1;
static int hf_sack_chunk_gap_block_end = -1;
static int hf_sack_chunk_duplicate_tsn = -1;

static int hf_shutdown_chunk_cumulative_tsn_ack = -1;
static int hf_cookie = -1;
static int hf_cwr_chunk_lowest_tsn = -1;

static int hf_ecne_chunk_lowest_tsn = -1;
static int hf_abort_chunk_t_bit = -1;
static int hf_shutdown_complete_chunk_t_bit = -1;

static int hf_parameter_type = -1;
static int hf_parameter_length = -1;
static int hf_parameter_value = -1;
static int hf_parameter_padding = -1;
static int hf_parameter_bit_1      = -1;
static int hf_parameter_bit_2      = -1;
static int hf_ipv4_address = -1;
static int hf_ipv6_address = -1;
static int hf_heartbeat_info = -1;
static int hf_state_cookie = -1;
static int hf_cookie_preservative_increment = -1;
static int hf_hostname = -1;
static int hf_supported_address_type = -1;
static int hf_stream_reset_req_seq_nr = -1;
static int hf_stream_reset_rsp_seq_nr = -1;
static int hf_senders_last_assigned_tsn = -1;
static int hf_senders_next_tsn = -1;
static int hf_receivers_next_tsn = -1;
static int hf_stream_reset_rsp_result = -1;
static int hf_stream_reset_sid = -1;
static int hf_random_number = -1;
static int hf_chunks_to_auth = -1;
static int hf_hmac_id = -1;
static int hf_hmac = -1;
static int hf_shared_key_id = -1;
static int hf_supported_chunk_type = -1;

static int hf_cause_code = -1;
static int hf_cause_length = -1;
static int hf_cause_padding = -1;
static int hf_cause_info = -1;

static int hf_cause_stream_identifier = -1;
static int hf_cause_reserved = -1;

static int hf_cause_number_of_missing_parameters = -1;
static int hf_cause_missing_parameter_type = -1;

static int hf_cause_measure_of_staleness = -1;

static int hf_cause_tsn = -1;

static int hf_forward_tsn_chunk_tsn = -1;
static int hf_forward_tsn_chunk_sid = -1;
static int hf_forward_tsn_chunk_ssn = -1;

static int hf_asconf_ack_serial = -1;
static int hf_asconf_serial = -1;
static int hf_correlation_id = -1;

static int hf_adap_indication = -1;

static int hf_pktdrop_chunk_m_bit = -1;
static int hf_pktdrop_chunk_b_bit = -1;
static int hf_pktdrop_chunk_t_bit = -1;
static int hf_pktdrop_chunk_bandwidth = -1;
static int hf_pktdrop_chunk_queuesize = -1;
static int hf_pktdrop_chunk_truncated_length = -1;
static int hf_pktdrop_chunk_reserved = -1;
static int hf_pktdrop_chunk_data_field = -1;

static dissector_table_t sctp_port_dissector_table;
static dissector_table_t sctp_ppi_dissector_table;
static heur_dissector_list_t sctp_heur_subdissector_list;
static int sctp_tap = -1;
static module_t *sctp_module;

/* Initialize the subtree pointers */
static gint ett_sctp = -1;
static gint ett_sctp_chunk = -1;
static gint ett_sctp_chunk_parameter = -1;
static gint ett_sctp_chunk_cause = -1;
static gint ett_sctp_chunk_type = -1;
static gint ett_sctp_data_chunk_flags = -1;
static gint ett_sctp_sack_chunk_flags = -1;
static gint ett_sctp_abort_chunk_flags = -1;
static gint ett_sctp_shutdown_complete_chunk_flags = -1;
static gint ett_sctp_pktdrop_chunk_flags = -1;
static gint ett_sctp_parameter_type= -1;
static gint ett_sctp_sack_chunk_gap_block = -1;
static gint ett_sctp_unrecognized_parameter_parameter = -1;

static dissector_handle_t data_handle;

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
#define SCTP_ASCONF_ACK_CHUNK_ID      0x80
#define SCTP_PKTDROP_CHUNK_ID         0x81
#define SCTP_STREAM_RESET_CHUNK_ID    0x82
#define SCTP_FORWARD_TSN_CHUNK_ID     0xC0
#define SCTP_ASCONF_CHUNK_ID          0xC1
#define SCTP_IETF_EXT                 0xFF

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
  { SCTP_STREAM_RESET_CHUNK_ID,      "STREAM_RESET" },
  { SCTP_AUTH_CHUNK_ID,              "AUTH" },
  { SCTP_FORWARD_TSN_CHUNK_ID,       "FORWARD_TSN" },
  { SCTP_ASCONF_ACK_CHUNK_ID,        "ASCONF_ACK" },
  { SCTP_PKTDROP_CHUNK_ID,           "PKTDROP" },
  { SCTP_ASCONF_CHUNK_ID,            "ASCONF" },
  { SCTP_IETF_EXT,                   "IETF_EXTENSION" },
  { 0,                               NULL } };

static const value_string sctp_payload_proto_id_values[] = {
  { NOT_SPECIFIED_PROTOCOL_ID,           "not specified" },
  { IUA_PAYLOAD_PROTOCOL_ID,             "IUA" },
  { M2UA_PAYLOAD_PROTOCOL_ID,            "M2UA" },
  { M3UA_PAYLOAD_PROTOCOL_ID,            "M3UA" },
  { SUA_PAYLOAD_PROTOCOL_ID,             "SUA" },
  { M2PA_PAYLOAD_PROTOCOL_ID,            "M2PA" },
  { V5UA_PAYLOAD_PROTOCOL_ID,            "V5UA" },
  { H248_PAYLOAD_PROTOCOL_ID,            "H.248/MEGACO" },
  { BICC_PAYLOAD_PROTOCOL_ID,            "BICC/Q.2150.3" },
  { TALI_PAYLOAD_PROTOCOL_ID,            "TALI" },
  { DUA_PAYLOAD_PROTOCOL_ID,             "DUA" },
  { ASAP_PAYLOAD_PROTOCOL_ID,            "ASAP" },
  { ENRP_PAYLOAD_PROTOCOL_ID,            "ENRP" },
  { H323_PAYLOAD_PROTOCOL_ID,            "H.323" },
  { QIPC_PAYLOAD_PROTOCOL_ID,            "Q.IPC/Q.2150.3" },
  { SIMCO_PAYLOAD_PROTOCOL_ID,           "SIMCO" },
  { 0,                                   NULL } };


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

#define PARAMETER_TYPE_LENGTH            2
#define PARAMETER_LENGTH_LENGTH          2
#define PARAMETER_HEADER_LENGTH          (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET          0
#define PARAMETER_TYPE_OFFSET            PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET          (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET           (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

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

#define SCTP_CHECKSUM_NONE      0
#define SCTP_CHECKSUM_ADLER32   1
#define SCTP_CHECKSUM_CRC32C    2
#define SCTP_CHECKSUM_AUTOMATIC 3

/* default values for preferences */
static gboolean show_port_numbers          = TRUE;
/* FIXME
static gboolean show_chunk_types           = TRUE;
*/
static gboolean show_always_control_chunks = TRUE;
static gint sctp_checksum                  = SCTP_CHECKSUM_CRC32C;

static struct _sctp_info sctp_info;

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
 *
 * Polynomial is
 *
 *    x^32 + x^28 + x^27 + x^26 + x^25 + x^23 + x^22 + x^20 + x^19 +
 *    x^18 + x^14 + x^13 + x^11 + x^10 + x^9 + x^8 + x^6 + 1
 *
 * Note that this is not the AUTODIN/HDLC/802.x CRC - it uses a different
 * polynomial.
 */

#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])
static guint32 crc_c[256] =
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

static guint32
sctp_crc32c(const unsigned char* buf, unsigned int len)
{
  unsigned int i;
  guint32 crc32 = ~0L;
  guint32 result;
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

/*
 * Routines for dissecting parameters
 */

static void
dissect_parameter(tvbuff_t *, packet_info *, proto_tree *, proto_item *, gboolean);

static void
dissect_parameters(tvbuff_t *, packet_info *, proto_tree *, proto_item *, gboolean);

static void
dissect_error_cause(tvbuff_t *, packet_info *, proto_tree *);

static void
dissect_error_causes(tvbuff_t *, packet_info *, proto_tree *);

static gboolean
dissect_sctp_chunk(tvbuff_t *, packet_info *, proto_tree *, proto_tree *, gboolean);

static void
dissect_sctp_packet(tvbuff_t *, packet_info *, proto_tree *, gboolean);



#define HEARTBEAT_INFO_PARAMETER_INFO_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_heartbeat_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 heartbeat_info_length;
  
  heartbeat_info_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (heartbeat_info_length > 0)
    proto_tree_add_item(parameter_tree, hf_heartbeat_info, parameter_tvb, HEARTBEAT_INFO_PARAMETER_INFO_OFFSET, heartbeat_info_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (Information: %u byte%s)", heartbeat_info_length, plurality(heartbeat_info_length, "", "s"));
}

#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv4_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, proto_item *additional_item, gboolean dissecting_init_init_ack_chunk)
{
  if (parameter_tree) {
    proto_tree_add_item(parameter_tree, hf_ipv4_address, parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(parameter_item, " (Address: %s)", ip_to_str((const guint8 *)tvb_get_ptr(parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH)));
    if (additional_item)
        proto_item_append_text(additional_item, "%s", ip_to_str((const guint8 *)tvb_get_ptr(parameter_tvb, IPV4_ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH)));
  }
  if (dissecting_init_init_ack_chunk) {
    if (sctp_info.number_of_tvbs < MAXIMUM_NUMBER_OF_TVBS)
      sctp_info.tvb[sctp_info.number_of_tvbs++] = parameter_tvb;
    else
      sctp_info.incomplete = TRUE;
  }
}

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ipv6_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, proto_item *additional_item, gboolean dissecting_init_init_ack_chunk)
{
  if (parameter_tree) {
    proto_tree_add_item(parameter_tree, hf_ipv6_address, parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(parameter_item, " (Address: %s)", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH)));
    if (additional_item)
      proto_item_append_text(additional_item, "%s", ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(parameter_tvb, IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH)));
  }
  if (dissecting_init_init_ack_chunk) {
    if (sctp_info.number_of_tvbs < MAXIMUM_NUMBER_OF_TVBS)
      sctp_info.tvb[sctp_info.number_of_tvbs++] = parameter_tvb;
    else
      sctp_info.incomplete = TRUE;
  }
}

#define STATE_COOKIE_PARAMETER_COOKIE_OFFSET   PARAMETER_VALUE_OFFSET

static void
dissect_state_cookie_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 state_cookie_length;

  state_cookie_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (state_cookie_length > 0)
    proto_tree_add_item(parameter_tree, hf_state_cookie, parameter_tvb, STATE_COOKIE_PARAMETER_COOKIE_OFFSET, state_cookie_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (Cookie length: %u byte%s)", state_cookie_length, plurality(state_cookie_length, "", "s"));
}

static void
dissect_unrecognized_parameters_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree)
{
  /* FIXME: Does it contain one or more parameters? */
  dissect_parameter(tvb_new_subset(parameter_tvb, PARAMETER_VALUE_OFFSET, -1, -1), pinfo, parameter_tree, NULL, FALSE);
}

#define COOKIE_PRESERVATIVE_PARAMETER_INCR_LENGTH 4
#define COOKIE_PRESERVATIVE_PARAMETER_INCR_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_cookie_preservative_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_cookie_preservative_increment, parameter_tvb, COOKIE_PRESERVATIVE_PARAMETER_INCR_OFFSET, COOKIE_PRESERVATIVE_PARAMETER_INCR_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (Increment :%u msec)", tvb_get_ntohl(parameter_tvb, COOKIE_PRESERVATIVE_PARAMETER_INCR_OFFSET));
}

#define HOSTNAME_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_hostname_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 hostname_length;

  hostname_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  proto_tree_add_item(parameter_tree, hf_hostname, parameter_tvb, HOSTNAME_OFFSET, hostname_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (Hostname: %.*s)", hostname_length, (const char *)tvb_get_ptr(parameter_tvb, HOSTNAME_OFFSET, hostname_length));

}

#define IPv4_ADDRESS_TYPE      5
#define IPv6_ADDRESS_TYPE      6
#define HOSTNAME_ADDRESS_TYPE 11

static const value_string address_types_values[] = {
  {  IPv4_ADDRESS_TYPE,    "IPv4 address"     },
  {  IPv6_ADDRESS_TYPE,    "IPv6 address"     },
  { HOSTNAME_ADDRESS_TYPE, "Hostname address" },
  {  0, NULL               }
};

#define SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH 2

static void
dissect_supported_address_types_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 address_type, number_of_address_types, address_type_number;
  guint offset;

  number_of_address_types = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH)
                            / SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH;

  offset = PARAMETER_VALUE_OFFSET;
  proto_item_append_text(parameter_item, " (Supported types: ");
  for(address_type_number = 1; address_type_number <= number_of_address_types; address_type_number++) {
    proto_tree_add_item(parameter_tree, hf_supported_address_type, parameter_tvb, offset, SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH, NETWORK_BYTE_ORDER);
    address_type = tvb_get_ntohs(parameter_tvb, offset);
    switch (address_type) {
      case IPv4_ADDRESS_TYPE:
        proto_item_append_text(parameter_item, "IPv4");
        break;
      case IPv6_ADDRESS_TYPE:
        proto_item_append_text(parameter_item, "IPv6");
        break;
      case HOSTNAME_ADDRESS_TYPE:
        proto_item_append_text(parameter_item, "hostname");
        break;
      default:
        proto_item_append_text(parameter_item, "%u", address_type);
    }
    if (address_type_number < number_of_address_types)
      proto_item_append_text(parameter_item, ", ");
    offset += SUPPORTED_ADDRESS_TYPE_PARAMETER_ADDRESS_TYPE_LENGTH;
  }
  proto_item_append_text(parameter_item, ")");
}

#define STREAM_RESET_SEQ_NR_LENGTH       4
#define SENDERS_LAST_ASSIGNED_TSN_LENGTH 4
#define SID_LENGTH                       2

#define STREAM_RESET_REQ_SEQ_NR_OFFSET     PARAMETER_VALUE_OFFSET
#define STREAM_RESET_REQ_RSP_SEQ_NR_OFFSET (PARAMETER_VALUE_OFFSET + STREAM_RESET_SEQ_NR_LENGTH)
#define SENDERS_LAST_ASSIGNED_TSN_OFFSET   (STREAM_RESET_REQ_RSP_SEQ_NR_OFFSET + STREAM_RESET_SEQ_NR_LENGTH)

static void
dissect_outgoing_ssn_reset_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint length, number_of_sids, sid_number, sid_offset;
  
  proto_tree_add_item(parameter_tree, hf_stream_reset_req_seq_nr,   parameter_tvb, STREAM_RESET_REQ_SEQ_NR_OFFSET,     STREAM_RESET_SEQ_NR_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_stream_reset_rsp_seq_nr,   parameter_tvb, STREAM_RESET_REQ_RSP_SEQ_NR_OFFSET, STREAM_RESET_SEQ_NR_LENGTH,       NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_senders_last_assigned_tsn, parameter_tvb, SENDERS_LAST_ASSIGNED_TSN_OFFSET,   SENDERS_LAST_ASSIGNED_TSN_LENGTH, NETWORK_BYTE_ORDER);

  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  sid_offset = SENDERS_LAST_ASSIGNED_TSN_OFFSET + SENDERS_LAST_ASSIGNED_TSN_LENGTH;
  if (length > PARAMETER_HEADER_LENGTH + STREAM_RESET_SEQ_NR_LENGTH + STREAM_RESET_SEQ_NR_LENGTH + SENDERS_LAST_ASSIGNED_TSN_LENGTH) {
    number_of_sids = (length - (PARAMETER_HEADER_LENGTH + STREAM_RESET_SEQ_NR_LENGTH + STREAM_RESET_SEQ_NR_LENGTH + SENDERS_LAST_ASSIGNED_TSN_LENGTH)) / SID_LENGTH;
    for(sid_number = 1; sid_number <= number_of_sids; sid_number++) {
      proto_tree_add_item(parameter_tree, hf_stream_reset_sid, parameter_tvb, sid_offset, SID_LENGTH, NETWORK_BYTE_ORDER);
      sid_offset += SID_LENGTH;
    }
  }
}

static void
dissect_incoming_ssn_reset_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint length, number_of_sids, sid_number, sid_offset;

  proto_tree_add_item(parameter_tree, hf_stream_reset_req_seq_nr, parameter_tvb, STREAM_RESET_REQ_SEQ_NR_OFFSET, STREAM_RESET_SEQ_NR_LENGTH, NETWORK_BYTE_ORDER);
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  sid_offset = STREAM_RESET_REQ_SEQ_NR_OFFSET + STREAM_RESET_SEQ_NR_LENGTH;
  if (length > PARAMETER_HEADER_LENGTH + STREAM_RESET_SEQ_NR_LENGTH) {
    number_of_sids = (length - (PARAMETER_HEADER_LENGTH + STREAM_RESET_SEQ_NR_LENGTH)) / SID_LENGTH;
    for(sid_number = 1; sid_number <= number_of_sids; sid_number++) {
      proto_tree_add_item(parameter_tree, hf_stream_reset_sid, parameter_tvb, sid_offset, SID_LENGTH, NETWORK_BYTE_ORDER);
      sid_offset += SID_LENGTH;
    }
  }
}

#define STREAM_RESET_REQ_SEQ_NR_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_ssn_tsn_reset_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  proto_tree_add_item(parameter_tree, hf_stream_reset_req_seq_nr, parameter_tvb, STREAM_RESET_REQ_SEQ_NR_OFFSET, STREAM_RESET_SEQ_NR_LENGTH, NETWORK_BYTE_ORDER);
}

#define STREAM_RESET_RSP_RESULT_LENGTH 4
#define SENDERS_NEXT_TSN_LENGTH        4
#define RECEIVERS_NEXT_TSN_LENGTH      4

#define STREAM_RESET_RSP_RSP_SEQ_NR_OFFSET PARAMETER_VALUE_OFFSET
#define STREAM_RESET_RSP_RESULT_OFFSET     (STREAM_RESET_RSP_RSP_SEQ_NR_OFFSET + STREAM_RESET_SEQ_NR_LENGTH)
#define SENDERS_NEXT_TSN_OFFSET            (STREAM_RESET_RSP_RESULT_OFFSET + STREAM_RESET_RSP_RESULT_LENGTH)
#define RECEIVERS_NEXT_TSN_OFFSET          (SENDERS_NEXT_TSN_OFFSET + SENDERS_NEXT_TSN_LENGTH)

static const value_string stream_reset_result_values[] = {
  { 0, "Nothing to do"                       },
  { 1, "Performed"                           },
  { 2, "Denied"                              },
  { 3, "Error - Wrong SSN"                   },
  { 4, "Error - Request already in progress" },
  { 0, NULL                                  }
};


static void
dissect_stream_reset_response_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint length;
  
  length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);

  proto_tree_add_item(parameter_tree, hf_stream_reset_rsp_seq_nr, parameter_tvb, STREAM_RESET_RSP_RSP_SEQ_NR_OFFSET, STREAM_RESET_SEQ_NR_LENGTH,     NETWORK_BYTE_ORDER);
  proto_tree_add_item(parameter_tree, hf_stream_reset_rsp_result, parameter_tvb, STREAM_RESET_RSP_RESULT_OFFSET,     STREAM_RESET_RSP_RESULT_LENGTH, NETWORK_BYTE_ORDER);
  if (length >= PARAMETER_HEADER_LENGTH + STREAM_RESET_SEQ_NR_LENGTH + STREAM_RESET_RSP_RESULT_LENGTH + SENDERS_NEXT_TSN_LENGTH)
    proto_tree_add_item(parameter_tree, hf_senders_next_tsn,   parameter_tvb, SENDERS_NEXT_TSN_OFFSET,   SENDERS_NEXT_TSN_LENGTH,   NETWORK_BYTE_ORDER);
  if (length >= PARAMETER_HEADER_LENGTH + STREAM_RESET_SEQ_NR_LENGTH + STREAM_RESET_RSP_RESULT_LENGTH + SENDERS_NEXT_TSN_LENGTH + RECEIVERS_NEXT_TSN_LENGTH)
    proto_tree_add_item(parameter_tree, hf_receivers_next_tsn, parameter_tvb, RECEIVERS_NEXT_TSN_OFFSET, RECEIVERS_NEXT_TSN_LENGTH, NETWORK_BYTE_ORDER);
}

static void
dissect_ecn_parameter(tvbuff_t *parameter_tvb _U_)
{
}

static void
dissect_nonce_supported_parameter(tvbuff_t *parameter_tvb _U_)
{
}

#define RANDOM_NUMBER_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_random_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  gint32 number_length;

  number_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  if (number_length > 0)
    proto_tree_add_item(parameter_tree, hf_random_number, parameter_tvb, RANDOM_NUMBER_OFFSET, number_length, NETWORK_BYTE_ORDER);
}

static void
dissect_chunks_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  gint32 number_of_chunks;
  guint16 chunk_number, offset;
  
  number_of_chunks = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;
  for(chunk_number = 1, offset = PARAMETER_VALUE_OFFSET; chunk_number <= number_of_chunks; chunk_number++, offset +=  CHUNK_TYPE_LENGTH)
    proto_tree_add_item(parameter_tree, hf_chunks_to_auth, parameter_tvb, offset, CHUNK_TYPE_LENGTH, NETWORK_BYTE_ORDER);
}

static const value_string hmac_id_values[] = {
  { 0,              "Reserved" },
  { 1,              "SHA-1"    },
  { 2,              "MD-5"     },
  { 0,              NULL       } };

#define HMAC_ID_LENGTH 2

static void
dissect_hmac_algo_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree)
{
  gint32 number_of_ids;
  guint16 id_number, offset;
  
  number_of_ids = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) / HMAC_ID_LENGTH;
  for(id_number = 1, offset = PARAMETER_VALUE_OFFSET; id_number <= number_of_ids; id_number++, offset +=  HMAC_ID_LENGTH)
    proto_tree_add_item(parameter_tree, hf_hmac_id, parameter_tvb, offset, HMAC_ID_LENGTH, NETWORK_BYTE_ORDER);
}

static void
dissect_supported_extensions_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  gint32 number_of_types;
  guint16 type_number, offset;
  
  proto_item_append_text(parameter_item, " (Supported types: ");
  number_of_types = (tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH) / CHUNK_TYPE_LENGTH;
  for(type_number = 1, offset = PARAMETER_VALUE_OFFSET; type_number <= number_of_types; type_number++, offset +=  CHUNK_TYPE_LENGTH) {
    proto_tree_add_item(parameter_tree, hf_supported_chunk_type, parameter_tvb, offset, CHUNK_TYPE_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(parameter_item, val_to_str(tvb_get_guint8(parameter_tvb, offset), chunk_type_values, "Unknown"));
    if (type_number < number_of_types)
      proto_item_append_text(parameter_item, ", ");
  
  }
  proto_item_append_text(parameter_item, ")");
}

static void
dissect_forward_tsn_supported_parameter(tvbuff_t *parameter_tvb _U_)
{
}

#define CORRELATION_ID_LENGTH    4
#define CORRELATION_ID_OFFSET    PARAMETER_VALUE_OFFSET
#define ADDRESS_PARAMETER_OFFSET (CORRELATION_ID_OFFSET + CORRELATION_ID_LENGTH)

static void
dissect_add_ip_address_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 address_length;
  tvbuff_t *address_tvb;

  address_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH;
  
  proto_tree_add_item(parameter_tree, hf_correlation_id, parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH, NETWORK_BYTE_ORDER);
  address_tvb    =  tvb_new_subset(parameter_tvb, ADDRESS_PARAMETER_OFFSET, address_length, address_length);
  proto_item_append_text(parameter_item, " (Address: ");
  dissect_parameter(address_tvb, pinfo, parameter_tree, parameter_item, FALSE);
  proto_item_append_text(parameter_item, ", correlation ID: %u)", tvb_get_ntohl(parameter_tvb, CORRELATION_ID_OFFSET));
}

static void
dissect_del_ip_address_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 address_length;
  tvbuff_t *address_tvb;

  address_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH;
  
  proto_tree_add_item(parameter_tree, hf_correlation_id, parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH, NETWORK_BYTE_ORDER);
  address_tvb    =  tvb_new_subset(parameter_tvb, ADDRESS_PARAMETER_OFFSET, address_length, address_length);
  proto_item_append_text(parameter_item, " (Address: ");
  dissect_parameter(address_tvb, pinfo, parameter_tree, parameter_item, FALSE);
  proto_item_append_text(parameter_item, ", correlation ID: %u)", tvb_get_ntohl(parameter_tvb, CORRELATION_ID_OFFSET));
}

#define ERROR_CAUSE_IND_CASUES_OFFSET (CORRELATION_ID_OFFSET + CORRELATION_ID_LENGTH)

static void
dissect_error_cause_indication_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree)
{
  guint16 causes_length;
  tvbuff_t *causes_tvb;

  proto_tree_add_item(parameter_tree, hf_correlation_id, parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH, NETWORK_BYTE_ORDER);
  causes_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH;
  causes_tvb    = tvb_new_subset(parameter_tvb, ERROR_CAUSE_IND_CASUES_OFFSET, causes_length, causes_length);
  dissect_error_causes(causes_tvb, pinfo,  parameter_tree);
}

static void
dissect_set_primary_address_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 address_length;
  tvbuff_t *address_tvb;

  address_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH;
  
  proto_tree_add_item(parameter_tree, hf_correlation_id, parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH, NETWORK_BYTE_ORDER);
  address_tvb    =  tvb_new_subset(parameter_tvb, ADDRESS_PARAMETER_OFFSET, address_length, address_length);
  proto_item_append_text(parameter_item, " (Address: ");
  dissect_parameter(address_tvb, pinfo, parameter_tree, parameter_item, FALSE);
  proto_item_append_text(parameter_item, ", correlation ID: %u)", tvb_get_ntohl(parameter_tvb, CORRELATION_ID_OFFSET));
}

static void
dissect_success_report_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_correlation_id, parameter_tvb, CORRELATION_ID_OFFSET, CORRELATION_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (Correlation ID: %u)", tvb_get_ntohl(parameter_tvb, CORRELATION_ID_OFFSET));
}

#define ADAP_INDICATION_LENGTH 4
#define ADAP_INDICATION_OFFSET PARAMETER_VALUE_OFFSET

static void
dissect_adap_indication_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_item(parameter_tree, hf_adap_indication, parameter_tvb, ADAP_INDICATION_OFFSET, ADAP_INDICATION_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(parameter_item, " (Indication: %u)", tvb_get_ntohl(parameter_tvb, ADAP_INDICATION_OFFSET));
}

static void
dissect_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 type, parameter_value_length;

  type                   = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  parameter_value_length = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET) - PARAMETER_HEADER_LENGTH;

  if (parameter_value_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_value, parameter_tvb, PARAMETER_VALUE_OFFSET, parameter_value_length, NETWORK_BYTE_ORDER);

  proto_item_append_text(parameter_item, " (Type %u, value length: %u byte%s)", type, parameter_value_length, plurality(parameter_value_length, "", "s"));
}

#define HEARTBEAT_INFO_PARAMETER_ID             0x0001
#define IPV4ADDRESS_PARAMETER_ID                0x0005
#define IPV6ADDRESS_PARAMETER_ID                0x0006
#define STATE_COOKIE_PARAMETER_ID               0x0007
#define UNREC_PARA_PARAMETER_ID                 0x0008
#define COOKIE_PRESERVATIVE_PARAMETER_ID        0x0009
#define HOSTNAME_ADDRESS_PARAMETER_ID           0x000b
#define SUPPORTED_ADDRESS_TYPES_PARAMETER_ID    0x000c
#define OUTGOING_SSN_RESET_REQUEST_PARAMETER_ID 0x000d
#define INCOMING_SSN_RESET_REQUEST_PARAMETER_ID 0x000e
#define SSN_TSN_RESET_REQUEST_PARAMETER_ID      0x000f
#define STREAM_RESET_RESPONSE_PARAMETER_ID      0x0010
#define ECN_PARAMETER_ID                        0x8000
#define NONCE_SUPPORTED_PARAMETER_ID            0x8001
#define RANDOM_PARAMETER_ID                     0x8002
#define CHUNKS_PARAMETER_ID                     0x8003
#define HMAC_ALGO_PARAMETER_ID                  0x8004
#define SUPPORTED_EXTENSIONS_PARAMETER_ID       0x8008
#define FORWARD_TSN_SUPPORTED_PARAMETER_ID      0xC000
#define ADD_IP_ADDRESS_PARAMETER_ID             0xC001
#define DEL_IP_ADDRESS_PARAMETER_ID             0xC002
#define ERROR_CAUSE_INDICATION_PARAMETER_ID     0xC003
#define SET_PRIMARY_ADDRESS_PARAMETER_ID        0xC004
#define SUCCESS_REPORT_PARAMETER_ID             0xC005
#define ADAP_LAYER_INDICATION_PARAMETER_ID      0xC006

static const value_string parameter_identifier_values[] = {
  { HEARTBEAT_INFO_PARAMETER_ID,             "Heartbeat info"              },
  { IPV4ADDRESS_PARAMETER_ID,                "IPv4 address"                },
  { IPV6ADDRESS_PARAMETER_ID,                "IPv6 address"                },
  { STATE_COOKIE_PARAMETER_ID,               "State cookie"                },
  { UNREC_PARA_PARAMETER_ID,                 "Unrecognized parameter"      },
  { COOKIE_PRESERVATIVE_PARAMETER_ID,        "Cookie preservative"         },
  { HOSTNAME_ADDRESS_PARAMETER_ID,           "Hostname address"            },
  { OUTGOING_SSN_RESET_REQUEST_PARAMETER_ID, "Outgoing SSN reset request"  },
  { INCOMING_SSN_RESET_REQUEST_PARAMETER_ID, "Incoming SSN reset request"  },
  { SSN_TSN_RESET_REQUEST_PARAMETER_ID,      "SSN/TSN reset request"       },
  { STREAM_RESET_RESPONSE_PARAMETER_ID,      "Stream reset response"       },
  { SUPPORTED_ADDRESS_TYPES_PARAMETER_ID,    "Supported address types"     },
  { ECN_PARAMETER_ID,                        "ECN"                         },
  { NONCE_SUPPORTED_PARAMETER_ID,            "Nonce supported"             },
  { RANDOM_PARAMETER_ID,                     "Random"                      },
  { CHUNKS_PARAMETER_ID,                     "Chunk list"                  },
  { HMAC_ALGO_PARAMETER_ID,                  "Requested HMAC Algorithm"    },
  { SUPPORTED_EXTENSIONS_PARAMETER_ID,       "Supported Extensions"        },
  { FORWARD_TSN_SUPPORTED_PARAMETER_ID,      "Forward TSN supported"       },
  { ADD_IP_ADDRESS_PARAMETER_ID,             "Add IP address"              },
  { DEL_IP_ADDRESS_PARAMETER_ID,             "Delete IP address"           },
  { ERROR_CAUSE_INDICATION_PARAMETER_ID,     "Error cause indication"      },
  { SET_PRIMARY_ADDRESS_PARAMETER_ID,        "Set primary address"         },
  { SUCCESS_REPORT_PARAMETER_ID,             "Success report"              },
  { ADAP_LAYER_INDICATION_PARAMETER_ID,      "Adaptation Layer Indication" },
  { 0,                                       NULL                          } };

#define SCTP_PARAMETER_BIT_1  0x8000
#define SCTP_PARAMETER_BIT_2 0x4000

static const true_false_string sctp_parameter_bit_1_value = {
  "Skip parameter and continue processing of the chunk",
  "Stop processing of chunk"
};

static const true_false_string sctp_parameter_bit_2_value = {
  "Do report",
  "Do not report"
};

static void
dissect_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *chunk_tree, proto_item *additional_item, gboolean dissecting_init_init_ack_chunk)
{
  guint16 type, length, padding_length;
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  proto_item *type_item;
  proto_tree *type_tree;

  type           = tvb_get_ntohs(parameter_tvb, PARAMETER_TYPE_OFFSET);
  length         = tvb_get_ntohs(parameter_tvb, PARAMETER_LENGTH_OFFSET);
  padding_length = tvb_length(parameter_tvb) - length;

  if (!(chunk_tree || (dissecting_init_init_ack_chunk && (type == IPV4ADDRESS_PARAMETER_ID || type == IPV6ADDRESS_PARAMETER_ID))))
    return;

  if (chunk_tree) {
    parameter_item = proto_tree_add_text(chunk_tree, parameter_tvb, PARAMETER_HEADER_OFFSET, tvb_length(parameter_tvb), "%s parameter", val_to_str(type, parameter_identifier_values, "Unknown"));
    parameter_tree = proto_item_add_subtree(parameter_item, ett_sctp_chunk_parameter);

    type_item = proto_tree_add_item(parameter_tree, hf_parameter_type,   parameter_tvb, PARAMETER_TYPE_OFFSET,   PARAMETER_TYPE_LENGTH,   NETWORK_BYTE_ORDER);
    type_tree = proto_item_add_subtree(type_item, ett_sctp_parameter_type);
    proto_tree_add_item(type_tree, hf_parameter_bit_1,  parameter_tvb, PARAMETER_TYPE_OFFSET,  PARAMETER_TYPE_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(type_tree, hf_parameter_bit_2,  parameter_tvb, PARAMETER_TYPE_OFFSET,  PARAMETER_TYPE_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(parameter_tree, hf_parameter_length, parameter_tvb, PARAMETER_LENGTH_OFFSET, PARAMETER_LENGTH_LENGTH, NETWORK_BYTE_ORDER);
  } else {
    parameter_item = NULL;
    parameter_tree = NULL;
  }
  
  switch(type) {
  case HEARTBEAT_INFO_PARAMETER_ID:
    dissect_heartbeat_info_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case IPV4ADDRESS_PARAMETER_ID:
    dissect_ipv4_parameter(parameter_tvb, parameter_tree, parameter_item, additional_item, dissecting_init_init_ack_chunk);
    break;
  case IPV6ADDRESS_PARAMETER_ID:
    dissect_ipv6_parameter(parameter_tvb, parameter_tree, parameter_item, additional_item, dissecting_init_init_ack_chunk);
    break;
  case STATE_COOKIE_PARAMETER_ID:
    dissect_state_cookie_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case UNREC_PARA_PARAMETER_ID:
    dissect_unrecognized_parameters_parameter(parameter_tvb, pinfo,  parameter_tree);
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
  case OUTGOING_SSN_RESET_REQUEST_PARAMETER_ID:
    dissect_outgoing_ssn_reset_request_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case INCOMING_SSN_RESET_REQUEST_PARAMETER_ID:
    dissect_incoming_ssn_reset_request_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case SSN_TSN_RESET_REQUEST_PARAMETER_ID:
    dissect_ssn_tsn_reset_request_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case STREAM_RESET_RESPONSE_PARAMETER_ID:
    dissect_stream_reset_response_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case ECN_PARAMETER_ID:
    dissect_ecn_parameter(parameter_tvb);
    break;
  case NONCE_SUPPORTED_PARAMETER_ID:
    dissect_nonce_supported_parameter(parameter_tvb);
    break;
  case RANDOM_PARAMETER_ID:
    dissect_random_parameter(parameter_tvb, parameter_tree);
    break;
  case CHUNKS_PARAMETER_ID:
    dissect_chunks_parameter(parameter_tvb, parameter_tree);
    break;
  case HMAC_ALGO_PARAMETER_ID:
    dissect_hmac_algo_parameter(parameter_tvb, parameter_tree);
    break;
  case SUPPORTED_EXTENSIONS_PARAMETER_ID:
    dissect_supported_extensions_parameter(parameter_tvb, parameter_tree, parameter_item);
    break;
  case FORWARD_TSN_SUPPORTED_PARAMETER_ID:
    dissect_forward_tsn_supported_parameter(parameter_tvb);
    break;
  case ADD_IP_ADDRESS_PARAMETER_ID:
    dissect_add_ip_address_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
    break;
  case DEL_IP_ADDRESS_PARAMETER_ID:
    dissect_del_ip_address_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
    break;
  case ERROR_CAUSE_INDICATION_PARAMETER_ID:
    dissect_error_cause_indication_parameter(parameter_tvb, pinfo, parameter_tree);
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
  }
  
  if (padding_length > 0)
    proto_tree_add_item(parameter_tree, hf_parameter_padding, parameter_tvb, PARAMETER_HEADER_OFFSET + length, padding_length, NETWORK_BYTE_ORDER);
}

static void
dissect_parameters(tvbuff_t *parameters_tvb, packet_info *pinfo, proto_tree *tree, proto_item *additional_item, gboolean dissecting_init_init_ack_chunk)
{
  gint offset, length, total_length, remaining_length;
  tvbuff_t *parameter_tvb;

  offset = 0;
  while((remaining_length = tvb_length_remaining(parameters_tvb, offset))) {
    if ((offset > 0) && additional_item)
      proto_item_append_text(additional_item, " ");
    length       = tvb_get_ntohs(parameters_tvb, offset + PARAMETER_LENGTH_OFFSET);
    total_length = ADD_PADDING(length);
    if (remaining_length >= length)
      total_length = MIN(total_length, remaining_length);
    /* create a tvb for the parameter including the padding bytes */
    parameter_tvb  = tvb_new_subset(parameters_tvb, offset, total_length, total_length);
    dissect_parameter(parameter_tvb, pinfo, tree, additional_item, dissecting_init_init_ack_chunk);
    /* get rid of the handled parameter */
    offset += total_length;
  }
}


/*
 * Code to handle error causes for ABORT and ERROR chunks
 */
 
 
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
 
static void
dissect_invalid_stream_identifier_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_tree_add_item(cause_tree, hf_cause_stream_identifier, cause_tvb, CAUSE_STREAM_IDENTIFIER_OFFSET, CAUSE_STREAM_IDENTIFIER_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(cause_tree, hf_cause_reserved,          cause_tvb, CAUSE_RESERVED_OFFSET,          CAUSE_RESERVED_LENGTH,          NETWORK_BYTE_ORDER);
  proto_item_append_text(cause_item, " (SID: %u)", tvb_get_ntohs(cause_tvb, CAUSE_STREAM_IDENTIFIER_OFFSET));
}

#define CAUSE_NUMBER_OF_MISSING_PARAMETERS_LENGTH 4
#define CAUSE_MISSING_PARAMETER_TYPE_LENGTH       2

#define CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET CAUSE_INFO_OFFSET
#define CAUSE_FIRST_MISSING_PARAMETER_TYPE_OFFSET (CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET + \
                                                   CAUSE_NUMBER_OF_MISSING_PARAMETERS_LENGTH )

static void
dissect_missing_mandatory_parameters_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree)
{
  guint32 number_of_missing_parameters, missing_parameter_number;
  guint   offset;

  number_of_missing_parameters = tvb_get_ntohl(cause_tvb, CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET);
  proto_tree_add_item(cause_tree, hf_cause_number_of_missing_parameters, cause_tvb, CAUSE_NUMBER_OF_MISSING_PARAMETERS_OFFSET, CAUSE_NUMBER_OF_MISSING_PARAMETERS_LENGTH, NETWORK_BYTE_ORDER);
  offset = CAUSE_FIRST_MISSING_PARAMETER_TYPE_OFFSET;
  for(missing_parameter_number = 1; missing_parameter_number <= number_of_missing_parameters; missing_parameter_number++) {
    proto_tree_add_item(cause_tree, hf_cause_missing_parameter_type, cause_tvb, offset, CAUSE_MISSING_PARAMETER_TYPE_LENGTH, NETWORK_BYTE_ORDER);
    offset +=  CAUSE_MISSING_PARAMETER_TYPE_LENGTH;
  }
}

#define CAUSE_MEASURE_OF_STALENESS_LENGTH 4
#define CAUSE_MEASURE_OF_STALENESS_OFFSET CAUSE_INFO_OFFSET

static void
dissect_stale_cookie_error_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_tree_add_item(cause_tree, hf_cause_measure_of_staleness, cause_tvb, CAUSE_MEASURE_OF_STALENESS_OFFSET, CAUSE_MEASURE_OF_STALENESS_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(cause_item, " (Measure: %u usec)", tvb_get_ntohl(cause_tvb, CAUSE_MEASURE_OF_STALENESS_OFFSET));
}

static void
dissect_out_of_resource_cause(tvbuff_t *cause_tvb _U_)
{
}

static void
dissect_unresolvable_address_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 parameter_length;
  tvbuff_t *parameter_tvb;

  parameter_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, parameter_length, parameter_length);
  proto_item_append_text(cause_item, " (Address: ");
  dissect_parameter(parameter_tvb, pinfo, cause_tree, cause_item, FALSE);
  proto_item_append_text(cause_item, ")");
}

static void
dissect_unrecognized_chunk_type_cause(tvbuff_t *cause_tvb,  packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 chunk_length;
  guint8 unrecognized_type;
  tvbuff_t *unrecognized_chunk_tvb;

  chunk_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  unrecognized_chunk_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, chunk_length, chunk_length);
  dissect_sctp_chunk(unrecognized_chunk_tvb, pinfo, cause_tree,cause_tree, FALSE);
  unrecognized_type   = tvb_get_guint8(unrecognized_chunk_tvb, CHUNK_TYPE_OFFSET);
  proto_item_append_text(cause_item, " (Type: %u (%s))", unrecognized_type, val_to_str(unrecognized_type, chunk_type_values, "unknown"));
}

static void
dissect_invalid_mandatory_parameter_cause(tvbuff_t *cause_tvb _U_)
{
}

static void
dissect_unrecognized_parameters_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree)
{
  guint16 cause_info_length;
  tvbuff_t *unrecognized_parameters_tvb;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;

  unrecognized_parameters_tvb = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  dissect_parameters(unrecognized_parameters_tvb, pinfo, cause_tree, NULL, FALSE);
}

#define CAUSE_TSN_LENGTH 4
#define CAUSE_TSN_OFFSET CAUSE_INFO_OFFSET

static void
dissect_no_user_data_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  proto_tree_add_item(cause_tree, hf_cause_tsn, cause_tvb, CAUSE_TSN_OFFSET, CAUSE_TSN_LENGTH, NETWORK_BYTE_ORDER);
  proto_item_append_text(cause_item, " (TSN: %u)", tvb_get_ntohl(cause_tvb, CAUSE_TSN_OFFSET));
}

static void
dissect_cookie_received_while_shutting_down_cause(tvbuff_t *cause_tvb _U_)
{
}

static void
dissect_restart_with_new_address_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree* cause_tree, proto_item *cause_item)
{
  guint16 cause_info_length;
  tvbuff_t *parameter_tvb;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  proto_item_append_text(cause_item, " (New addresses: ");
  dissect_parameters(parameter_tvb, pinfo, cause_tree, cause_item, FALSE);
  proto_item_append_text(cause_item, ")");
}

static void
dissect_user_initiated_abort_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree)
{
  guint16 cause_info_length;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  if (cause_info_length > 0)
    proto_tree_add_item(cause_tree, hf_cause_info, cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, NETWORK_BYTE_ORDER);
}

static void
dissect_protocol_violation_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree)
{
  guint16 cause_info_length;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  if (cause_info_length > 0)
    proto_tree_add_item(cause_tree, hf_cause_info, cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, NETWORK_BYTE_ORDER);
}

static void
dissect_delete_last_address_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 cause_info_length;
  tvbuff_t *parameter_tvb;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  proto_item_append_text(cause_item, " (Last address: ");
  dissect_parameter(parameter_tvb, pinfo, cause_tree, cause_item, FALSE);
  proto_item_append_text(cause_item, ")");
}

static void
dissect_resource_outage_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree)
{
  guint16 cause_info_length;
  tvbuff_t *parameter_tvb;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  parameter_tvb     = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  dissect_parameter(parameter_tvb, pinfo, cause_tree, NULL, FALSE);
}

static void
dissect_delete_source_address_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 cause_info_length;
  tvbuff_t *parameter_tvb;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  proto_item_append_text(cause_item, " (Deleted address: ");
  dissect_parameter(parameter_tvb, pinfo, cause_tree, cause_item, FALSE);
  proto_item_append_text(cause_item, ")");
}

static void
dissect_request_refused_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *cause_tree)
{
  guint16 cause_info_length;
  tvbuff_t *parameter_tvb;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  parameter_tvb    = tvb_new_subset(cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, cause_info_length);
  dissect_parameter(parameter_tvb, pinfo, cause_tree, NULL, FALSE);
}

static void
dissect_unsupported_hmac_id_cause(tvbuff_t *cause_tvb, packet_info *pinfo _U_, proto_tree *cause_tree)
{
  proto_tree_add_item(cause_tree, hf_hmac_id, cause_tvb, CAUSE_INFO_OFFSET, HMAC_ID_LENGTH, NETWORK_BYTE_ORDER);
}

static void
dissect_unknown_cause(tvbuff_t *cause_tvb, proto_tree *cause_tree, proto_item *cause_item)
{
  guint16 cause_info_length;

  cause_info_length = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET) - CAUSE_HEADER_LENGTH;
  if (cause_info_length > 0)
    proto_tree_add_item(cause_tree, hf_cause_info, cause_tvb, CAUSE_INFO_OFFSET, cause_info_length, NETWORK_BYTE_ORDER);
  proto_item_append_text(cause_item, " (Code: %u, information length: %u byte%s)", tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET), cause_info_length, plurality(cause_info_length, "", "s"));
}

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
#define RESTART_WITH_NEW_ADDRESSES                 0x0b
#define USER_INITIATED_ABORT                       0x0c
#define PROTOCOL_VIOLATION                         0x0d
#define REQUEST_TO_DELETE_LAST_ADDRESS             0x0100
#define OPERATION_REFUSED_DUE_TO_RESOURCE_SHORTAGE 0X0101
#define REQUEST_TO_DELETE_SOURCE_ADDRESS           0x0102
#define ABORT_DUE_TO_ILLEGAL_ASCONF                0x0103
#define REQUEST_REFUSED                            0x0104
#define UNSUPPORTED_HMAC_ID                        0x0105

static const value_string cause_code_values[] = {
  { INVALID_STREAM_IDENTIFIER,                  "Invalid stream identifier" },
  { MISSING_MANDATORY_PARAMETERS,               "Missing mandatory parameter" },
  { STALE_COOKIE_ERROR,                         "Stale cookie error" },
  { OUT_OF_RESOURCE,                            "Out of resource" },
  { UNRESOLVABLE_ADDRESS,                       "Unresolvable address" },
  { UNRECOGNIZED_CHUNK_TYPE,                    "Unrecognized chunk type" },
  { INVALID_MANDATORY_PARAMETER,                "Invalid mandatory parameter" },
  { UNRECOGNIZED_PARAMETERS,                    "Unrecognized parameters" },
  { NO_USER_DATA,                               "No user data" },
  { COOKIE_RECEIVED_WHILE_SHUTTING_DOWN,        "Cookie received while shutting down" },
  { RESTART_WITH_NEW_ADDRESSES,                 "Restart of an association with new addresses" },
  { USER_INITIATED_ABORT,                       "User initiated ABORT" },
  { PROTOCOL_VIOLATION,                         "Protocol violation" },
  { REQUEST_TO_DELETE_LAST_ADDRESS,             "Request to delete last address" },
  { OPERATION_REFUSED_DUE_TO_RESOURCE_SHORTAGE, "Operation refused due to resource shortage" },
  { REQUEST_TO_DELETE_SOURCE_ADDRESS,           "Request to delete source address" },
  { ABORT_DUE_TO_ILLEGAL_ASCONF,                "Association Aborted due to illegal ASCONF-ACK" },
  { REQUEST_REFUSED,                            "Request refused - no authorization" },
  { UNSUPPORTED_HMAC_ID,                        "Unsupported HMAC identifier" },
  { 0,                                          NULL } };


static void
dissect_error_cause(tvbuff_t *cause_tvb, packet_info *pinfo, proto_tree *chunk_tree)
{
  guint16 code, length, padding_length;
  proto_item *cause_item;
  proto_tree *cause_tree;

  code           = tvb_get_ntohs(cause_tvb, CAUSE_CODE_OFFSET);
  length         = tvb_get_ntohs(cause_tvb, CAUSE_LENGTH_OFFSET);
  padding_length = tvb_length(cause_tvb) - length;

  cause_item = proto_tree_add_text(chunk_tree, cause_tvb, CAUSE_HEADER_OFFSET, tvb_length(cause_tvb), "%s cause", val_to_str(code, cause_code_values, "Unknown"));
  cause_tree = proto_item_add_subtree(cause_item, ett_sctp_chunk_cause);

  proto_tree_add_item(cause_tree, hf_cause_code, cause_tvb,   CAUSE_CODE_OFFSET,   CAUSE_CODE_LENGTH,   NETWORK_BYTE_ORDER);
  proto_tree_add_item(cause_tree, hf_cause_length, cause_tvb, CAUSE_LENGTH_OFFSET, CAUSE_LENGTH_LENGTH, NETWORK_BYTE_ORDER);

  switch(code) {
  case INVALID_STREAM_IDENTIFIER:
    dissect_invalid_stream_identifier_cause(cause_tvb, cause_tree, cause_item);
    break;
  case MISSING_MANDATORY_PARAMETERS:
    dissect_missing_mandatory_parameters_cause(cause_tvb, cause_tree);
    break;
  case STALE_COOKIE_ERROR:
    dissect_stale_cookie_error_cause(cause_tvb, cause_tree, cause_item);
    break;
  case OUT_OF_RESOURCE:
    dissect_out_of_resource_cause(cause_tvb);
    break;
  case UNRESOLVABLE_ADDRESS:
    dissect_unresolvable_address_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case UNRECOGNIZED_CHUNK_TYPE:
    dissect_unrecognized_chunk_type_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case INVALID_MANDATORY_PARAMETER:
    dissect_invalid_mandatory_parameter_cause(cause_tvb);
    break;
  case UNRECOGNIZED_PARAMETERS:
    dissect_unrecognized_parameters_cause(cause_tvb, pinfo, cause_tree);
    break;
  case NO_USER_DATA:
    dissect_no_user_data_cause(cause_tvb, cause_tree, cause_item);
    break;
  case COOKIE_RECEIVED_WHILE_SHUTTING_DOWN:
    dissect_cookie_received_while_shutting_down_cause(cause_tvb);
    break;
  case RESTART_WITH_NEW_ADDRESSES:
    dissect_restart_with_new_address_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case USER_INITIATED_ABORT:
    dissect_user_initiated_abort_cause(cause_tvb, cause_tree);
    break;
  case PROTOCOL_VIOLATION:
    dissect_protocol_violation_cause(cause_tvb, cause_tree);
    break;
  case REQUEST_TO_DELETE_LAST_ADDRESS:
    dissect_delete_last_address_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case OPERATION_REFUSED_DUE_TO_RESOURCE_SHORTAGE:
    dissect_resource_outage_cause(cause_tvb, pinfo, cause_tree);
    break;
  case REQUEST_TO_DELETE_SOURCE_ADDRESS:
    dissect_delete_source_address_cause(cause_tvb, pinfo, cause_tree, cause_item);
    break;
  case REQUEST_REFUSED:
    dissect_request_refused_cause(cause_tvb, pinfo, cause_tree);
    break;
  case UNSUPPORTED_HMAC_ID:
    dissect_unsupported_hmac_id_cause(cause_tvb, pinfo, cause_tree);
    break;
  default:
    dissect_unknown_cause(cause_tvb, cause_tree, cause_item);
    break;
  }
  
  if (padding_length > 0)
    proto_tree_add_item(cause_tree, hf_cause_padding, cause_tvb, CAUSE_HEADER_OFFSET + length, padding_length, NETWORK_BYTE_ORDER);
}

static void
dissect_error_causes(tvbuff_t *causes_tvb, packet_info *pinfo, proto_tree *tree)
{
  gint offset, length, total_length, remaining_length;
  tvbuff_t *cause_tvb;

  offset = 0;
  while((remaining_length = tvb_length_remaining(causes_tvb, offset))) {
    length       = tvb_get_ntohs(causes_tvb, offset + CAUSE_LENGTH_OFFSET);
    total_length = ADD_PADDING(length);
    if (remaining_length >= length)
      total_length = MIN(total_length, remaining_length);
    /* create a tvb for the parameter including the padding bytes */
    cause_tvb    = tvb_new_subset(causes_tvb, offset, total_length, total_length);
    dissect_error_cause(cause_tvb, pinfo, tree);
    /* get rid of the handled cause */
    offset += total_length;
  }
}


/*
 * Code to actually dissect the packets
*/

static gboolean try_heuristic_first = FALSE;

static gboolean
dissect_payload(tvbuff_t *payload_tvb, packet_info *pinfo, proto_tree *tree, guint32 ppi)
{
  guint32 low_port, high_port;

  if (try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(sctp_heur_subdissector_list, payload_tvb, pinfo, tree))
       return TRUE;
  }

  /* Do lookups with the subdissector table.

     When trying port numbers, we try the port number with the lower value
     first, followed by the port number with the higher value.  This means
     that, for packets where a dissector is registered for *both* port
     numbers, and where there's no match on the PPI:

  1) we pick the same dissector for traffic going in both directions;

  2) we prefer the port number that's more likely to be the right
     one (as that prefers well-known ports to reserved ports);

     although there is, of course, no guarantee that any such strategy
     will always pick the right port number.

     XXX - we ignore port numbers of 0, as some dissectors use a port
     number of 0 to disable the port. */
  if (dissector_try_port(sctp_ppi_dissector_table, ppi, payload_tvb, pinfo, tree))
    return TRUE;
  if (pinfo->srcport > pinfo->destport) {
    low_port = pinfo->destport;
    high_port = pinfo->srcport;
  } else {
    low_port = pinfo->srcport;
    high_port = pinfo->destport;
  }
  if (low_port != 0 &&
      dissector_try_port(sctp_port_dissector_table, low_port, payload_tvb, pinfo, tree))
    return TRUE;
  if (high_port != 0 &&
      dissector_try_port(sctp_port_dissector_table, high_port, payload_tvb, pinfo, tree))
    return TRUE;

  if (!try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(sctp_heur_subdissector_list, payload_tvb, pinfo, tree))
       return TRUE;
  }

  /* Oh, well, we don't know this; dissect it as data. */
  call_dissector(data_handle, payload_tvb, pinfo, tree);
  return TRUE;
}

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

static gboolean
dissect_data_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *tree, proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{
  guint number_of_ppid;
  guint32 payload_proto_id;
  tvbuff_t *payload_tvb;
  proto_tree *flags_tree;
  guint8 e_bit, b_bit, u_bit;

  if (chunk_length <= DATA_CHUNK_HEADER_LENGTH) {
    proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                           chunk_length, DATA_CHUNK_HEADER_LENGTH);
    return TRUE;
  }
  payload_proto_id  = tvb_get_ntohl(chunk_tvb, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET);
  
  /* insert the PPID in the pinfo structure if it is non-zero, not already there and there is still room */
  if (payload_proto_id) {
    for(number_of_ppid = 0; number_of_ppid < MAX_NUMBER_OF_PPIDS; number_of_ppid++)
      if ((pinfo->ppid[number_of_ppid] == 0) || (pinfo->ppid[number_of_ppid] == payload_proto_id))
        break;
    if ((number_of_ppid < MAX_NUMBER_OF_PPIDS) && (pinfo->ppid[number_of_ppid] == 0))
      pinfo->ppid[number_of_ppid] = payload_proto_id;
  }

  if (chunk_tree) {
    proto_item_set_len(chunk_item, DATA_CHUNK_HEADER_LENGTH);
    flags_tree  = proto_item_add_subtree(flags_item, ett_sctp_data_chunk_flags);
    proto_tree_add_item(flags_tree, hf_data_chunk_e_bit,             chunk_tvb, CHUNK_FLAGS_OFFSET,                    CHUNK_FLAGS_LENGTH,                    NETWORK_BYTE_ORDER);
    proto_tree_add_item(flags_tree, hf_data_chunk_b_bit,             chunk_tvb, CHUNK_FLAGS_OFFSET,                    CHUNK_FLAGS_LENGTH,                    NETWORK_BYTE_ORDER);
    proto_tree_add_item(flags_tree, hf_data_chunk_u_bit,             chunk_tvb, CHUNK_FLAGS_OFFSET,                    CHUNK_FLAGS_LENGTH,                    NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_data_chunk_tsn,               chunk_tvb, DATA_CHUNK_TSN_OFFSET,                 DATA_CHUNK_TSN_LENGTH,                 NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_data_chunk_stream_id,         chunk_tvb, DATA_CHUNK_STREAM_ID_OFFSET,           DATA_CHUNK_STREAM_ID_LENGTH,           NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_data_chunk_stream_seq_number, chunk_tvb, DATA_CHUNK_STREAM_SEQ_NUMBER_OFFSET,   DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_data_chunk_payload_proto_id,  chunk_tvb, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET, DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH, NETWORK_BYTE_ORDER);

    e_bit = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET) & SCTP_DATA_CHUNK_E_BIT;
    b_bit = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET) & SCTP_DATA_CHUNK_B_BIT;
    u_bit = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET) & SCTP_DATA_CHUNK_U_BIT;

    proto_item_append_text(chunk_item, "(%s, ", (u_bit) ? "unordered" : "ordered");
    if (b_bit) {
      if (e_bit)
        proto_item_append_text(chunk_item, "complete");
      else
        proto_item_append_text(chunk_item, "first");
    } else {
      if (e_bit)
        proto_item_append_text(chunk_item, "last");
      else
        proto_item_append_text(chunk_item, "middle");
    }

    proto_item_append_text(chunk_item, " segment, TSN: %u, SID: %u, SSN: %u, PPID: %u, payload length: %u byte%s)",
                           tvb_get_ntohl(chunk_tvb, DATA_CHUNK_TSN_OFFSET), 
                           tvb_get_ntohs(chunk_tvb, DATA_CHUNK_STREAM_ID_OFFSET),
                           tvb_get_ntohs(chunk_tvb, DATA_CHUNK_STREAM_SEQ_NUMBER_OFFSET),
                           payload_proto_id,
                           chunk_length - DATA_CHUNK_HEADER_LENGTH, plurality(chunk_length - DATA_CHUNK_HEADER_LENGTH, "", "s"));
  }

  payload_tvb       = tvb_new_subset(chunk_tvb, DATA_CHUNK_PAYLOAD_OFFSET, chunk_length - DATA_CHUNK_HEADER_LENGTH, chunk_length - DATA_CHUNK_HEADER_LENGTH);
  return dissect_payload(payload_tvb, pinfo, tree, payload_proto_id);
}

#define INIT_CHUNK_INITIATE_TAG_LENGTH               4
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH      4
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH 2
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH  2
#define INIT_CHUNK_INITIAL_TSN_LENGTH                4
#define INIT_CHUNK_FIXED_PARAMTERS_LENGTH            (CHUNK_HEADER_LENGTH + \
                                                      INIT_CHUNK_INITIATE_TAG_LENGTH + \
                                                      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH + \
                                                      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH + \
                                                      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH + \
                                                      INIT_CHUNK_INITIAL_TSN_LENGTH)
                                                      
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

static void
dissect_init_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item)
{
  tvbuff_t *parameters_tvb;

  if (chunk_length < INIT_CHUNK_FIXED_PARAMTERS_LENGTH) {
    proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                           chunk_length,
                           INIT_CHUNK_FIXED_PARAMTERS_LENGTH);
    return;
  }
  if (chunk_tree) {
    /* handle fixed parameters */
    proto_tree_add_item(chunk_tree, hf_init_chunk_initiate_tag,               chunk_tvb, INIT_CHUNK_INITIATE_TAG_OFFSET,               INIT_CHUNK_INITIATE_TAG_LENGTH,               NETWORK_BYTE_ORDER);
    proto_tree_add_item_hidden(chunk_tree, hf_initiate_tag,                   chunk_tvb, INIT_CHUNK_INITIATE_TAG_OFFSET,               INIT_CHUNK_INITIATE_TAG_LENGTH,               NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_init_chunk_adv_rec_window_credit,      chunk_tvb, INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET,      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH,      NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_init_chunk_number_of_outbound_streams, chunk_tvb, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_init_chunk_number_of_inbound_streams,  chunk_tvb, INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET,  INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_init_chunk_initial_tsn,                chunk_tvb, INIT_CHUNK_INITIAL_TSN_OFFSET,                INIT_CHUNK_INITIAL_TSN_LENGTH,                NETWORK_BYTE_ORDER);

    proto_item_append_text(chunk_item, " (Outbound streams: %u, inbound streams: %u)",
                           tvb_get_ntohs(chunk_tvb, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET),
                           tvb_get_ntohs(chunk_tvb, INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET));
  }
  /* handle variable parameters */
  chunk_length -= INIT_CHUNK_FIXED_PARAMTERS_LENGTH;
  parameters_tvb = tvb_new_subset(chunk_tvb, INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET, chunk_length, chunk_length);
  dissect_parameters(parameters_tvb, pinfo, chunk_tree, NULL, TRUE);
}

static void
dissect_init_ack_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item)
{
  tvbuff_t *parameters_tvb;

  if (chunk_length < INIT_CHUNK_FIXED_PARAMTERS_LENGTH) {
    proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                           chunk_length,
                           INIT_CHUNK_FIXED_PARAMTERS_LENGTH);
    return;
  }
  if (chunk_tree) {
    /* handle fixed parameters */
    proto_tree_add_item(chunk_tree, hf_initack_chunk_initiate_tag,               chunk_tvb, INIT_CHUNK_INITIATE_TAG_OFFSET,               INIT_CHUNK_INITIATE_TAG_LENGTH,               NETWORK_BYTE_ORDER);
    proto_tree_add_item_hidden(chunk_tree, hf_initiate_tag,                      chunk_tvb, INIT_CHUNK_INITIATE_TAG_OFFSET,               INIT_CHUNK_INITIATE_TAG_LENGTH,               NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_initack_chunk_adv_rec_window_credit,      chunk_tvb, INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET,      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH,      NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_initack_chunk_number_of_outbound_streams, chunk_tvb, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_initack_chunk_number_of_inbound_streams,  chunk_tvb, INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET,  INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_initack_chunk_initial_tsn,                chunk_tvb, INIT_CHUNK_INITIAL_TSN_OFFSET,                INIT_CHUNK_INITIAL_TSN_LENGTH,                NETWORK_BYTE_ORDER);

    proto_item_append_text(chunk_item, " (Outbound streams: %u, inbound streams: %u)",
                           tvb_get_ntohs(chunk_tvb, INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET),
                           tvb_get_ntohs(chunk_tvb, INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET));
  }
  /* handle variable paramters */
  chunk_length -= INIT_CHUNK_FIXED_PARAMTERS_LENGTH;
  parameters_tvb = tvb_new_subset(chunk_tvb, INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET, chunk_length, chunk_length);
  dissect_parameters(parameters_tvb, pinfo, chunk_tree, NULL, TRUE);
}

#define SCTP_SACK_CHUNK_NS_BIT                  0x01
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


static void
dissect_sack_chunk(tvbuff_t *chunk_tvb, proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{
  guint16 number_of_gap_blocks, number_of_dup_tsns;
  guint16 gap_block_number, dup_tsn_number, start, end;
  gint gap_block_offset, dup_tsn_offset;
  guint32 cum_tsn_ack;
  proto_item *block_item;
  proto_tree *block_tree, *flags_tree;

  if (chunk_tree) {
    flags_tree  = proto_item_add_subtree(flags_item, ett_sctp_sack_chunk_flags);
    proto_tree_add_item(flags_tree, hf_sack_chunk_ns,                    chunk_tvb, CHUNK_FLAGS_OFFSET,                      CHUNK_FLAGS_LENGTH,                      NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_sack_chunk_cumulative_tsn_ack,    chunk_tvb, SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET,    SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH,    NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_sack_chunk_adv_rec_window_credit, chunk_tvb, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_sack_chunk_number_of_gap_blocks,  chunk_tvb, SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET,  SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_sack_chunk_number_of_dup_tsns,    chunk_tvb, SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET,    SACK_CHUNK_NUMBER_OF_DUP_TSNS_LENGTH,    NETWORK_BYTE_ORDER);

    /* handle the gap acknowledgement blocks */
    number_of_gap_blocks = tvb_get_ntohs(chunk_tvb, SACK_CHUNK_NUMBER_OF_GAP_BLOCKS_OFFSET);
    gap_block_offset     = SACK_CHUNK_GAP_BLOCK_OFFSET;
    cum_tsn_ack          = tvb_get_ntohl(chunk_tvb, SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
    for(gap_block_number = 1; gap_block_number <= number_of_gap_blocks; gap_block_number++) {
      start = tvb_get_ntohs(chunk_tvb, gap_block_offset);
      end   = tvb_get_ntohs(chunk_tvb, gap_block_offset + SACK_CHUNK_GAP_BLOCK_START_LENGTH);
      block_item = proto_tree_add_text(chunk_tree, chunk_tvb, gap_block_offset, SACK_CHUNK_GAP_BLOCK_LENGTH, "Gap Acknowledgement for TSN %u to %u", cum_tsn_ack + start, cum_tsn_ack + end);
      block_tree = proto_item_add_subtree(block_item, ett_sctp_sack_chunk_gap_block);
      proto_tree_add_item(block_tree, hf_sack_chunk_gap_block_start, chunk_tvb, gap_block_offset,                                     SACK_CHUNK_GAP_BLOCK_START_LENGTH, NETWORK_BYTE_ORDER);
      proto_tree_add_item(block_tree, hf_sack_chunk_gap_block_end,   chunk_tvb, gap_block_offset + SACK_CHUNK_GAP_BLOCK_START_LENGTH, SACK_CHUNK_GAP_BLOCK_END_LENGTH,   NETWORK_BYTE_ORDER);
      gap_block_offset += SACK_CHUNK_GAP_BLOCK_LENGTH;
    }

    /* handle the duplicate TSNs */
    number_of_dup_tsns = tvb_get_ntohs(chunk_tvb, SACK_CHUNK_NUMBER_OF_DUP_TSNS_OFFSET);
    dup_tsn_offset     = SACK_CHUNK_GAP_BLOCK_OFFSET + number_of_gap_blocks * SACK_CHUNK_GAP_BLOCK_LENGTH;
    for(dup_tsn_number = 1; dup_tsn_number <= number_of_dup_tsns; dup_tsn_number++) {
      proto_tree_add_item(chunk_tree, hf_sack_chunk_duplicate_tsn, chunk_tvb, dup_tsn_offset, SACK_CHUNK_DUP_TSN_LENGTH, NETWORK_BYTE_ORDER);
      dup_tsn_offset += SACK_CHUNK_DUP_TSN_LENGTH;
    }

    proto_item_append_text(chunk_item, " (Cumulative TSN: %u, a_rwnd: %u, gaps: %u, duplicate TSNs: %u)",
                     tvb_get_ntohl(chunk_tvb, SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET),
                     tvb_get_ntohl(chunk_tvb, SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET),
                     number_of_gap_blocks, number_of_dup_tsns);
  }
}

#define HEARTBEAT_CHUNK_INFO_OFFSET CHUNK_VALUE_OFFSET

static void
dissect_heartbeat_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item)
{
  tvbuff_t   *parameter_tvb;
  
  if (chunk_tree) {
    proto_item_append_text(chunk_item, " (Information: %u byte%s)", chunk_length - CHUNK_HEADER_LENGTH, plurality(chunk_length - CHUNK_HEADER_LENGTH, "", "s"));
    parameter_tvb  = tvb_new_subset(chunk_tvb, HEARTBEAT_CHUNK_INFO_OFFSET, chunk_length - CHUNK_HEADER_LENGTH, chunk_length - CHUNK_HEADER_LENGTH);
    /* FIXME: Parameters or parameter? */
    dissect_parameter(parameter_tvb, pinfo, chunk_tree, NULL, FALSE);
  }
}

static void
dissect_heartbeat_ack_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item)
{
  tvbuff_t   *parameter_tvb;

  if (chunk_tree) {
    proto_item_append_text(chunk_item, " (Information: %u byte%s)", chunk_length - CHUNK_HEADER_LENGTH, plurality(chunk_length - CHUNK_HEADER_LENGTH, "", "s"));
    parameter_tvb  = tvb_new_subset(chunk_tvb, HEARTBEAT_CHUNK_INFO_OFFSET, chunk_length - CHUNK_HEADER_LENGTH, chunk_length - CHUNK_HEADER_LENGTH);
    /* FIXME: Parameters or parameter? */
    dissect_parameter(parameter_tvb, pinfo, chunk_tree, NULL, FALSE);
  }
}

#define ABORT_CHUNK_FIRST_ERROR_CAUSE_OFFSET 4
#define SCTP_ABORT_CHUNK_T_BIT               0x01

static void
dissect_abort_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *flags_item)
{
  tvbuff_t *causes_tvb;
  proto_tree *flags_tree;
  
  sctp_info.vtag_reflected =
      (tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET) & SCTP_ABORT_CHUNK_T_BIT) != 0;

  if (chunk_tree) {
    flags_tree  = proto_item_add_subtree(flags_item, ett_sctp_abort_chunk_flags);
    proto_tree_add_item(flags_tree, hf_abort_chunk_t_bit, chunk_tvb, CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, NETWORK_BYTE_ORDER);
    causes_tvb    = tvb_new_subset(chunk_tvb, CHUNK_VALUE_OFFSET, chunk_length - CHUNK_HEADER_LENGTH, chunk_length - CHUNK_HEADER_LENGTH);
    dissect_error_causes(causes_tvb, pinfo, chunk_tree);
  }
}

#define SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET CHUNK_VALUE_OFFSET
#define SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_LENGTH 4

static void
dissect_shutdown_chunk(tvbuff_t *chunk_tvb, proto_tree *chunk_tree, proto_item *chunk_item)
{
  if (chunk_tree) {
    proto_tree_add_item(chunk_tree, hf_shutdown_chunk_cumulative_tsn_ack, chunk_tvb, SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET, SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(chunk_item, " (Cumulative TSN ack: %u)", tvb_get_ntohl(chunk_tvb, SHUTDOWN_CHUNK_CUMULATIVE_TSN_ACK_OFFSET));
  }
}

static void
dissect_shutdown_ack_chunk(tvbuff_t *chunk_tvb _U_)
{
}

#define ERROR_CAUSE_IND_CAUSES_OFFSET CHUNK_VALUE_OFFSET

static void
dissect_error_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree)
{
  tvbuff_t *causes_tvb;

  if (chunk_tree) {
    causes_tvb    = tvb_new_subset(chunk_tvb, ERROR_CAUSE_IND_CAUSES_OFFSET, chunk_length - CHUNK_HEADER_LENGTH, chunk_length - CHUNK_HEADER_LENGTH);
    dissect_error_causes(causes_tvb, pinfo, chunk_tree);    
  }
}

#define COOKIE_OFFSET CHUNK_VALUE_OFFSET

static void
dissect_cookie_echo_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, proto_tree *chunk_tree, proto_item *chunk_item)
{
  if (chunk_tree) {
    proto_tree_add_item(chunk_tree, hf_cookie, chunk_tvb, COOKIE_OFFSET, chunk_length - CHUNK_HEADER_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(chunk_item, " (Cookie length: %u byte%s)", chunk_length - CHUNK_HEADER_LENGTH, plurality(chunk_length - CHUNK_HEADER_LENGTH, "", "s"));
  }
}

static void
dissect_cookie_ack_chunk(tvbuff_t *chunk_tvb _U_)
{
}

#define ECNE_CHUNK_LOWEST_TSN_OFFSET CHUNK_VALUE_OFFSET
#define ECNE_CHUNK_LOWEST_TSN_LENGTH 4

static void
dissect_ecne_chunk(tvbuff_t *chunk_tvb, proto_tree *chunk_tree, proto_item *chunk_item)
{
  if (chunk_tree)
    proto_tree_add_item(chunk_tree, hf_ecne_chunk_lowest_tsn, chunk_tvb, ECNE_CHUNK_LOWEST_TSN_OFFSET, ECNE_CHUNK_LOWEST_TSN_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(chunk_item, " (Lowest TSN: %u)", tvb_get_ntohl(chunk_tvb, ECNE_CHUNK_LOWEST_TSN_OFFSET));
}

#define CWR_CHUNK_LOWEST_TSN_OFFSET CHUNK_VALUE_OFFSET
#define CWR_CHUNK_LOWEST_TSN_LENGTH 4

static void
dissect_cwr_chunk(tvbuff_t *chunk_tvb, proto_tree *chunk_tree, proto_item *chunk_item)
{
  if (chunk_tree)
    proto_tree_add_item(chunk_tree, hf_cwr_chunk_lowest_tsn, chunk_tvb, CWR_CHUNK_LOWEST_TSN_OFFSET, CWR_CHUNK_LOWEST_TSN_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(chunk_item, " (Lowest TSN: %u)", tvb_get_ntohl(chunk_tvb, CWR_CHUNK_LOWEST_TSN_OFFSET));
}

#define SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT 0x01


static const true_false_string sctp_shutdown_complete_chunk_t_bit_value = {
  "Tag reflected",
  "Tag not reflected"
};


static void
dissect_shutdown_complete_chunk(tvbuff_t *chunk_tvb, proto_tree *chunk_tree, proto_item *flags_item)
{
  proto_tree *flags_tree;

  sctp_info.vtag_reflected =
      (tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET) & SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT) != 0;

  if (chunk_tree) {
    flags_tree  = proto_item_add_subtree(flags_item, ett_sctp_shutdown_complete_chunk_flags);
    proto_tree_add_item(flags_tree, hf_shutdown_complete_chunk_t_bit, chunk_tvb, CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, NETWORK_BYTE_ORDER);
  }
}

#define FORWARD_TSN_CHUNK_TSN_LENGTH 4
#define FORWARD_TSN_CHUNK_SID_LENGTH 2
#define FORWARD_TSN_CHUNK_SSN_LENGTH 2
#define FORWARD_TSN_CHUNK_TSN_OFFSET CHUNK_VALUE_OFFSET
#define FORWARD_TSN_CHUNK_SID_OFFSET 0
#define FORWARD_TSN_CHUNK_SSN_OFFSET (FORWARD_TSN_CHUNK_SID_OFFSET + FORWARD_TSN_CHUNK_SID_LENGTH)

static void
dissect_forward_tsn_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, proto_tree *chunk_tree, proto_item *chunk_item)
{
  guint   offset;
  guint16 number_of_affected_streams, affected_stream;

  /* FIXME */
  if (chunk_length < CHUNK_HEADER_LENGTH + FORWARD_TSN_CHUNK_TSN_LENGTH) {
    proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                           chunk_length,
                           CHUNK_HEADER_LENGTH + FORWARD_TSN_CHUNK_TSN_LENGTH);
    return;
  }
  if (chunk_tree) {
    proto_tree_add_item(chunk_tree, hf_forward_tsn_chunk_tsn, chunk_tvb, FORWARD_TSN_CHUNK_TSN_OFFSET, FORWARD_TSN_CHUNK_TSN_LENGTH, NETWORK_BYTE_ORDER);
    number_of_affected_streams = (chunk_length - CHUNK_HEADER_LENGTH - FORWARD_TSN_CHUNK_TSN_LENGTH) /
                                 (FORWARD_TSN_CHUNK_SID_LENGTH + FORWARD_TSN_CHUNK_SSN_LENGTH);
    offset = CHUNK_VALUE_OFFSET + FORWARD_TSN_CHUNK_TSN_LENGTH;

    for(affected_stream = 0;  affected_stream < number_of_affected_streams; affected_stream++) {
        proto_tree_add_item(chunk_tree, hf_forward_tsn_chunk_sid, chunk_tvb, offset + FORWARD_TSN_CHUNK_SID_OFFSET, FORWARD_TSN_CHUNK_SID_LENGTH, NETWORK_BYTE_ORDER);
        proto_tree_add_item(chunk_tree, hf_forward_tsn_chunk_ssn, chunk_tvb, offset + FORWARD_TSN_CHUNK_SSN_OFFSET, FORWARD_TSN_CHUNK_SSN_LENGTH, NETWORK_BYTE_ORDER);
        offset = offset + (FORWARD_TSN_CHUNK_SID_LENGTH + FORWARD_TSN_CHUNK_SSN_LENGTH);
    }
    proto_item_append_text(chunk_item, "(Cumulative TSN: %u)", tvb_get_ntohl(chunk_tvb, FORWARD_TSN_CHUNK_TSN_OFFSET));
  }
}

#define STREAM_RESET_PARAMETERS_OFFSET CHUNK_HEADER_LENGTH

static void
dissect_stream_reset_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item _U_)
{
  tvbuff_t *parameters_tvb;

  if (chunk_tree) {
    parameters_tvb = tvb_new_subset(chunk_tvb, STREAM_RESET_PARAMETERS_OFFSET, chunk_length - CHUNK_HEADER_LENGTH, chunk_length - CHUNK_HEADER_LENGTH);
    dissect_parameters(parameters_tvb, pinfo, chunk_tree, NULL, FALSE);
  }
}

#define SHARED_KEY_ID_LENGTH 2

#define SHARED_KEY_ID_OFFSET PARAMETER_VALUE_OFFSET
#define HMAC_ID_OFFSET       (SHARED_KEY_ID_OFFSET + SHARED_KEY_ID_LENGTH)
#define HMAC_OFFSET          (HMAC_ID_OFFSET + HMAC_ID_LENGTH)

static void
dissect_auth_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, proto_tree *chunk_tree, proto_item *chunk_item _U_)
{
  guint hmac_length;
  
  hmac_length = chunk_length - CHUNK_HEADER_LENGTH - HMAC_ID_LENGTH - SHARED_KEY_ID_LENGTH;
  proto_tree_add_item(chunk_tree, hf_shared_key_id, chunk_tvb, SHARED_KEY_ID_OFFSET, SHARED_KEY_ID_LENGTH, NETWORK_BYTE_ORDER);
  proto_tree_add_item(chunk_tree, hf_hmac_id,       chunk_tvb, HMAC_ID_OFFSET,       HMAC_ID_LENGTH,       NETWORK_BYTE_ORDER);
  if (hmac_length > 0)
    proto_tree_add_item(chunk_tree, hf_hmac,    chunk_tvb, HMAC_OFFSET,    hmac_length,    NETWORK_BYTE_ORDER);
}

#define SERIAL_NUMBER_LENGTH    4
#define SERIAL_NUMBER_OFFSET    CHUNK_VALUE_OFFSET
#define ASCONF_CHUNK_PARAMETERS_OFFSET (SERIAL_NUMBER_OFFSET + SERIAL_NUMBER_LENGTH)

static void
dissect_asconf_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item)
{
  tvbuff_t *parameters_tvb;

  if (chunk_length < CHUNK_HEADER_LENGTH + SERIAL_NUMBER_LENGTH) {
    proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                           chunk_length,
                           CHUNK_HEADER_LENGTH + SERIAL_NUMBER_LENGTH);
    return;
  }
  if (chunk_tree) {
    proto_tree_add_item(chunk_tree, hf_asconf_serial, chunk_tvb, SERIAL_NUMBER_OFFSET, SERIAL_NUMBER_LENGTH, NETWORK_BYTE_ORDER);
    chunk_length -= CHUNK_HEADER_LENGTH + SERIAL_NUMBER_LENGTH;
    parameters_tvb    = tvb_new_subset(chunk_tvb, ASCONF_CHUNK_PARAMETERS_OFFSET, chunk_length, chunk_length);
    dissect_parameters(parameters_tvb, pinfo, chunk_tree, NULL, FALSE);
  }
}

#define ASCONF_ACK_CHUNK_PARAMETERS_OFFSET (SERIAL_NUMBER_OFFSET + SERIAL_NUMBER_LENGTH)

static void
dissect_asconf_ack_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item)
{
  tvbuff_t *parameters_tvb;

  if (chunk_length < CHUNK_HEADER_LENGTH + SERIAL_NUMBER_LENGTH) {
    proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                           chunk_length + CHUNK_HEADER_LENGTH,
                           CHUNK_HEADER_LENGTH + SERIAL_NUMBER_LENGTH);
    return;
  }
  if (chunk_tree) {
    proto_tree_add_item(chunk_tree, hf_asconf_ack_serial, chunk_tvb, SERIAL_NUMBER_OFFSET, SERIAL_NUMBER_LENGTH, NETWORK_BYTE_ORDER);
    chunk_length -= CHUNK_HEADER_LENGTH + SERIAL_NUMBER_LENGTH;
    parameters_tvb    = tvb_new_subset(chunk_tvb, ASCONF_ACK_CHUNK_PARAMETERS_OFFSET, chunk_length, chunk_length);
    dissect_parameters(parameters_tvb, pinfo, chunk_tree, NULL, FALSE);
  }
}

#define PKTDROP_CHUNK_BANDWIDTH_LENGTH      4
#define PKTDROP_CHUNK_QUEUESIZE_LENGTH      4
#define PKTDROP_CHUNK_TRUNCATED_SIZE_LENGTH 2
#define PKTDROP_CHUNK_RESERVED_SIZE_LENGTH  2

#define PKTDROP_CHUNK_HEADER_LENGTH (CHUNK_HEADER_LENGTH + \
                   PKTDROP_CHUNK_BANDWIDTH_LENGTH + \
                   PKTDROP_CHUNK_QUEUESIZE_LENGTH + \
                   PKTDROP_CHUNK_TRUNCATED_SIZE_LENGTH + \
                   PKTDROP_CHUNK_RESERVED_SIZE_LENGTH)
                   
#define PKTDROP_CHUNK_BANDWIDTH_OFFSET      CHUNK_VALUE_OFFSET
#define PKTDROP_CHUNK_QUEUESIZE_OFFSET      (PKTDROP_CHUNK_BANDWIDTH_OFFSET + PKTDROP_CHUNK_BANDWIDTH_LENGTH)
#define PKTDROP_CHUNK_TRUNCATED_SIZE_OFFSET (PKTDROP_CHUNK_QUEUESIZE_OFFSET + PKTDROP_CHUNK_QUEUESIZE_LENGTH)
#define PKTDROP_CHUNK_RESERVED_SIZE_OFFSET  (PKTDROP_CHUNK_TRUNCATED_SIZE_OFFSET + PKTDROP_CHUNK_TRUNCATED_SIZE_LENGTH)
#define PKTDROP_CHUNK_DATA_FIELD_OFFSET     (PKTDROP_CHUNK_RESERVED_SIZE_OFFSET + PKTDROP_CHUNK_RESERVED_SIZE_LENGTH)

#define SCTP_PKTDROP_CHUNK_M_BIT 0x01
#define SCTP_PKTDROP_CHUNK_B_BIT 0x02
#define SCTP_PKTDROP_CHUNK_T_BIT 0x04

static const true_false_string sctp_pktdropk_m_bit_value = {
  "Source is a middlebox",
  "Source is an endhost"
};

static const true_false_string sctp_pktdropk_b_bit_value = {
  "SCTP checksum was incorrect",
  "SCTP checksum was correct"
};

static const true_false_string sctp_pktdropk_t_bit_value = {
  "Packet is truncated",
  "Packet is not truncated"
};

static void
dissect_pktdrop_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, packet_info *pinfo, proto_tree *chunk_tree, proto_item *chunk_item, proto_item *flags_item)
{
  tvbuff_t *data_field_tvb;
  proto_tree *flags_tree;

  if (chunk_length < PKTDROP_CHUNK_HEADER_LENGTH) {
    proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                           chunk_length,
                           PKTDROP_CHUNK_HEADER_LENGTH);
    return;
  }
  chunk_length -= PKTDROP_CHUNK_HEADER_LENGTH;
  data_field_tvb = tvb_new_subset(chunk_tvb, PKTDROP_CHUNK_DATA_FIELD_OFFSET, chunk_length, chunk_length);

  if (chunk_tree) {
    flags_tree  = proto_item_add_subtree(flags_item, ett_sctp_pktdrop_chunk_flags);

    proto_tree_add_item(flags_tree, hf_pktdrop_chunk_m_bit,            chunk_tvb, CHUNK_FLAGS_OFFSET,                  CHUNK_FLAGS_LENGTH,                  NETWORK_BYTE_ORDER);
    proto_tree_add_item(flags_tree, hf_pktdrop_chunk_b_bit,            chunk_tvb, CHUNK_FLAGS_OFFSET,                  CHUNK_FLAGS_LENGTH,                  NETWORK_BYTE_ORDER);
    proto_tree_add_item(flags_tree, hf_pktdrop_chunk_t_bit,            chunk_tvb, CHUNK_FLAGS_OFFSET,                  CHUNK_FLAGS_LENGTH,                  NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_pktdrop_chunk_bandwidth,        chunk_tvb, PKTDROP_CHUNK_BANDWIDTH_OFFSET,      PKTDROP_CHUNK_BANDWIDTH_LENGTH,      NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_pktdrop_chunk_queuesize,        chunk_tvb, PKTDROP_CHUNK_QUEUESIZE_OFFSET,      PKTDROP_CHUNK_QUEUESIZE_LENGTH,      NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_pktdrop_chunk_truncated_length, chunk_tvb, PKTDROP_CHUNK_TRUNCATED_SIZE_OFFSET, PKTDROP_CHUNK_TRUNCATED_SIZE_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(chunk_tree, hf_pktdrop_chunk_reserved,         chunk_tvb, PKTDROP_CHUNK_RESERVED_SIZE_OFFSET,  PKTDROP_CHUNK_RESERVED_SIZE_LENGTH,  NETWORK_BYTE_ORDER);
    /* XXX - set pinfo->in_error_pkt? */
    if (chunk_length > 0) {
      if (tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET) & SCTP_PKTDROP_CHUNK_T_BIT)
        proto_tree_add_item(chunk_tree, hf_pktdrop_chunk_data_field,   chunk_tvb, PKTDROP_CHUNK_DATA_FIELD_OFFSET,     chunk_length,                   NETWORK_BYTE_ORDER);
      else
        dissect_sctp_packet(data_field_tvb, pinfo, chunk_tree, TRUE);
    }
  }
}

static void
dissect_unknown_chunk(tvbuff_t *chunk_tvb, guint16 chunk_length, proto_tree *chunk_tree, proto_item *chunk_item)
{
  if (chunk_tree) {
    if (chunk_length > CHUNK_HEADER_LENGTH)
      proto_tree_add_item(chunk_tree, hf_chunk_value, chunk_tvb, CHUNK_VALUE_OFFSET, chunk_length - CHUNK_HEADER_LENGTH, NETWORK_BYTE_ORDER);
    proto_item_append_text(chunk_item, " (Type: %u, value length: %u byte%s)", chunk_length, chunk_length, plurality(chunk_length - CHUNK_HEADER_LENGTH, "", "s"));
  }
}

#define SCTP_CHUNK_BIT_1 0x80
#define SCTP_CHUNK_BIT_2 0x40

static const true_false_string sctp_chunk_bit_1_value = {
  "Skip chunk and continue processing of the packet",
  "Stop processing of the packet"
};

static const true_false_string sctp_chunk_bit_2_value = {
  "Do report",
  "Do not report"
};


static gboolean
dissect_sctp_chunk(tvbuff_t *chunk_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *sctp_tree, gboolean useinfo)
{
  guint8 type, flags;
  guint16 length, padding_length;
  gboolean result;
  proto_item *flags_item;
  proto_item *chunk_item;
  proto_tree *chunk_tree;
  proto_item *type_item;
  proto_tree *type_tree;

  result = FALSE;

  /* first extract the chunk header */
  type           = tvb_get_guint8(chunk_tvb, CHUNK_TYPE_OFFSET);
  flags          = tvb_get_guint8(chunk_tvb, CHUNK_FLAGS_OFFSET);
  length         = tvb_get_ntohs(chunk_tvb, CHUNK_LENGTH_OFFSET);
  padding_length = tvb_length(chunk_tvb) - length;

 if (useinfo && (check_col(pinfo->cinfo, COL_INFO)))
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, chunk_type_values, "RESERVED"));
 
  if (tree) {
    /* create proto_tree stuff */
    chunk_item   = proto_tree_add_text(sctp_tree, chunk_tvb, CHUNK_HEADER_OFFSET, tvb_length(chunk_tvb), "%s chunk", val_to_str(type, chunk_type_values, "RESERVED"));
    chunk_tree   = proto_item_add_subtree(chunk_item, ett_sctp_chunk);

    /* then insert the chunk header components into the protocol tree */
    type_item  = proto_tree_add_item(chunk_tree, hf_chunk_type, chunk_tvb, CHUNK_TYPE_OFFSET, CHUNK_TYPE_LENGTH, NETWORK_BYTE_ORDER);
    type_tree  = proto_item_add_subtree(type_item, ett_sctp_chunk_type);
    proto_tree_add_item(type_tree, hf_chunk_bit_1,  chunk_tvb, CHUNK_TYPE_OFFSET,  CHUNK_TYPE_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(type_tree, hf_chunk_bit_2,  chunk_tvb, CHUNK_TYPE_OFFSET,  CHUNK_TYPE_LENGTH,  NETWORK_BYTE_ORDER);
    flags_item = proto_tree_add_item(chunk_tree, hf_chunk_flags, chunk_tvb, CHUNK_FLAGS_OFFSET, CHUNK_FLAGS_LENGTH, NETWORK_BYTE_ORDER);
  } else {
    chunk_tree = NULL;
    chunk_item = NULL;
    flags_item = NULL;
  }
  if (length < CHUNK_HEADER_LENGTH) {
    if (tree) {
      proto_tree_add_uint_format(chunk_tree, hf_chunk_length, chunk_tvb,
                                 CHUNK_LENGTH_OFFSET, CHUNK_LENGTH_LENGTH,
                                 length,
                                 "Chunk length: %u (invalid, should be >= %u)",
                                 length, CHUNK_HEADER_LENGTH);
      proto_item_append_text(chunk_item, ", bogus chunk length %u < %u)",
                             length, CHUNK_HEADER_LENGTH);
    }
    if (type == SCTP_DATA_CHUNK_ID)
      result = TRUE;
    return result;
  }
  if (tree) {
    proto_tree_add_uint(chunk_tree, hf_chunk_length, chunk_tvb, CHUNK_LENGTH_OFFSET, CHUNK_LENGTH_LENGTH, length);
  }
  /*
  length -= CHUNK_HEADER_LENGTH;
  */
  
  /* now dissect the chunk value */
  switch(type) {
  case SCTP_DATA_CHUNK_ID:
    result = dissect_data_chunk(chunk_tvb, length, pinfo, tree, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_INIT_CHUNK_ID:
    dissect_init_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item);
    break;
  case SCTP_INIT_ACK_CHUNK_ID:
    dissect_init_ack_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item);
    break;
  case SCTP_SACK_CHUNK_ID:
    dissect_sack_chunk(chunk_tvb, chunk_tree, chunk_item, flags_item);
    break;
  case SCTP_HEARTBEAT_CHUNK_ID:
    dissect_heartbeat_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item);
    break;
  case SCTP_HEARTBEAT_ACK_CHUNK_ID:
    dissect_heartbeat_ack_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item);
    break;
  case SCTP_ABORT_CHUNK_ID:
    dissect_abort_chunk(chunk_tvb, length, pinfo, chunk_tree, flags_item);
    break;
  case SCTP_SHUTDOWN_CHUNK_ID:
    dissect_shutdown_chunk(chunk_tvb, chunk_tree, chunk_item);
    break;
  case SCTP_SHUTDOWN_ACK_CHUNK_ID:
    dissect_shutdown_ack_chunk(chunk_tvb);
    break;
  case SCTP_ERROR_CHUNK_ID:
    dissect_error_chunk(chunk_tvb, length, pinfo, chunk_tree);
    break;
  case SCTP_COOKIE_ECHO_CHUNK_ID:
    dissect_cookie_echo_chunk(chunk_tvb, length, chunk_tree, chunk_item);
    break;
  case SCTP_COOKIE_ACK_CHUNK_ID:
    dissect_cookie_ack_chunk(chunk_tvb);
    break;
  case SCTP_ECNE_CHUNK_ID:
    dissect_ecne_chunk(chunk_tvb, chunk_tree, chunk_item);
    break;
  case SCTP_CWR_CHUNK_ID:
    dissect_cwr_chunk(chunk_tvb, chunk_tree, chunk_item);
    break;
  case SCTP_SHUTDOWN_COMPLETE_CHUNK_ID:
    dissect_shutdown_complete_chunk(chunk_tvb, chunk_tree, flags_item);
    break;
  case SCTP_FORWARD_TSN_CHUNK_ID:
    dissect_forward_tsn_chunk(chunk_tvb, length, chunk_tree, chunk_item);
    break;
  case SCTP_STREAM_RESET_CHUNK_ID:
    dissect_stream_reset_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item);
    break;
  case SCTP_AUTH_CHUNK_ID:
    dissect_auth_chunk(chunk_tvb, length, chunk_tree, chunk_item);
    break;
  case SCTP_ASCONF_ACK_CHUNK_ID:
    dissect_asconf_ack_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item);
    break;
  case SCTP_ASCONF_CHUNK_ID:
    dissect_asconf_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item);
    break;
  case SCTP_PKTDROP_CHUNK_ID:
    col_set_writable(pinfo->cinfo, FALSE);
    dissect_pktdrop_chunk(chunk_tvb, length, pinfo, chunk_tree, chunk_item, flags_item);
    col_set_writable(pinfo->cinfo, TRUE);
    break;
  default:
    dissect_unknown_chunk(chunk_tvb, length, chunk_tree, chunk_item);
    break;
  }
  
  if (padding_length > 0)
    proto_tree_add_item(chunk_tree, hf_chunk_padding, chunk_tvb, CHUNK_HEADER_OFFSET + length, padding_length, NETWORK_BYTE_ORDER);

  if (useinfo && ((type == SCTP_DATA_CHUNK_ID) || show_always_control_chunks) && check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_fence(pinfo->cinfo, COL_INFO);

  return result;
}

static void
dissect_sctp_chunks(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *sctp_item, proto_tree *sctp_tree, gboolean encapsulated)
{
  tvbuff_t *chunk_tvb;
  guint16 length, total_length, remaining_length;
  gint last_offset, offset;
  gboolean sctp_item_length_set;
  
  /* the common header of the datagram is already handled */
  last_offset = 0;
  offset = COMMON_HEADER_LENGTH;
  sctp_item_length_set = FALSE;

  while((remaining_length = tvb_length_remaining(tvb, offset))) {
    /* extract the chunk length and compute number of padding bytes */
    length         = tvb_get_ntohs(tvb, offset + CHUNK_LENGTH_OFFSET);
    total_length   = ADD_PADDING(length);
    if (remaining_length >= length)
      total_length = MIN(total_length, remaining_length);
    /* create a tvb for the chunk including the padding bytes */
    chunk_tvb    = tvb_new_subset(tvb, offset, total_length, total_length);

    /* save it in the sctp_info structure */
    if (!encapsulated) {
      if (sctp_info.number_of_tvbs < MAXIMUM_NUMBER_OF_TVBS)
        sctp_info.tvb[sctp_info.number_of_tvbs++] = chunk_tvb;
      else
        sctp_info.incomplete = TRUE;
    }

    /* call dissect_sctp_chunk for the actual work */
    if (dissect_sctp_chunk(chunk_tvb, pinfo, tree, sctp_tree, !encapsulated) && (tree)) {
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
  }
  if (!sctp_item_length_set && (tree)) {
    proto_item_set_len(sctp_item, offset - last_offset);
  }
}

static void
dissect_sctp_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean encapsulated)
{
  guint32 checksum = 0, calculated_crc32c = 0, calculated_adler32 = 0;
  guint16 source_port, destination_port;
  guint length;
  gboolean crc32c_correct = FALSE, adler32_correct = FALSE;
  proto_item *sctp_item;
  proto_tree *sctp_tree;

  length    = tvb_length(tvb);
  checksum  = tvb_get_ntohl(tvb, CHECKSUM_OFFSET);
  sctp_info.checksum_zero = (checksum == 0);
  
  switch(sctp_checksum) {
  case SCTP_CHECKSUM_NONE:
    break;
  case SCTP_CHECKSUM_ADLER32:
    calculated_adler32           = sctp_adler32(tvb_get_ptr(tvb, 0, length), length);
    adler32_correct              = (checksum == calculated_adler32);
    sctp_info.adler32_calculated = TRUE;
    sctp_info.adler32_correct    = adler32_correct;
    break;
  case SCTP_CHECKSUM_CRC32C:
    calculated_crc32c            = sctp_crc32c(tvb_get_ptr(tvb, 0, length), length);
    crc32c_correct               = (checksum == calculated_crc32c);
    sctp_info.crc32c_calculated  = TRUE;
    sctp_info.crc32c_correct     = crc32c_correct;
    break;
  case SCTP_CHECKSUM_AUTOMATIC:
    calculated_adler32           = sctp_adler32(tvb_get_ptr(tvb, 0, length), length);
    adler32_correct              = (checksum == calculated_adler32);
    calculated_crc32c            = sctp_crc32c(tvb_get_ptr(tvb, 0, length), length);
    crc32c_correct               = (checksum == calculated_crc32c);
    sctp_info.adler32_calculated = TRUE;
    sctp_info.adler32_correct    = adler32_correct;
    sctp_info.crc32c_calculated  = TRUE;
    sctp_info.crc32c_correct     = crc32c_correct;
    break;
  }
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    source_port      = tvb_get_ntohs(tvb, SOURCE_PORT_OFFSET);
    destination_port = tvb_get_ntohs(tvb, DESTINATION_PORT_OFFSET);

    /* create the sctp protocol tree */
    if (show_port_numbers)
      sctp_item = proto_tree_add_protocol_format(tree, proto_sctp, tvb, 0, -1,
                                                 "Stream Control Transmission Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
                                                 get_sctp_port(source_port), source_port,
                                                 get_sctp_port(destination_port), destination_port);
    else
      sctp_item = proto_tree_add_item(tree, proto_sctp, tvb, 0, -1, FALSE);
    sctp_tree = proto_item_add_subtree(sctp_item, ett_sctp);

    /* add the components of the common header to the protocol tree */
    proto_tree_add_item(sctp_tree, hf_source_port,      tvb, SOURCE_PORT_OFFSET,      SOURCE_PORT_LENGTH,      NETWORK_BYTE_ORDER);
    proto_tree_add_item(sctp_tree, hf_destination_port, tvb, DESTINATION_PORT_OFFSET, DESTINATION_PORT_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(sctp_tree, hf_verification_tag, tvb, VERIFICATION_TAG_OFFSET, VERIFICATION_TAG_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item_hidden(sctp_tree, hf_port, tvb, SOURCE_PORT_OFFSET,      SOURCE_PORT_LENGTH,      NETWORK_BYTE_ORDER);
    proto_tree_add_item_hidden(sctp_tree, hf_port, tvb, DESTINATION_PORT_OFFSET, DESTINATION_PORT_LENGTH, NETWORK_BYTE_ORDER);

    length    = tvb_length(tvb);
    checksum  = tvb_get_ntohl(tvb, CHECKSUM_OFFSET);
    switch(sctp_checksum) {
    case SCTP_CHECKSUM_NONE:
      proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, checksum, "Checksum: 0x%08x (not verified)", checksum);
      break;
    case SCTP_CHECKSUM_ADLER32:
      if (adler32_correct)
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [correct Adler32]", checksum);
      else
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [incorrect Adler32, should be 0x%08x]", checksum, calculated_adler32);
      proto_tree_add_boolean_hidden(sctp_tree, hf_checksum_bad, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, !(adler32_correct));
     break;
    case SCTP_CHECKSUM_CRC32C:
      if (crc32c_correct)
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [correct CRC32C]", checksum);
      else
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [incorrect CRC32C, should be 0x%08x]", checksum, calculated_crc32c);
      proto_tree_add_boolean_hidden(sctp_tree, hf_checksum_bad, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, !(crc32c_correct));
      break;
    case SCTP_CHECKSUM_AUTOMATIC:
      if ((adler32_correct) && !(crc32c_correct))
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [correct Adler32]", checksum);
      else if ((!adler32_correct) && (crc32c_correct))
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [correct CRC32C]", checksum);
      else if ((adler32_correct) && (crc32c_correct))
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [correct Adler32 and CRC32C]", checksum);
      else
        proto_tree_add_uint_format(sctp_tree, hf_checksum, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH,
                                   checksum, "Checksum: 0x%08x [incorrect, should be 0x%08x (Adler32) or 0x%08x (CRC32C)]",
                                   checksum, calculated_adler32, calculated_crc32c);
      proto_tree_add_boolean_hidden(sctp_tree, hf_checksum_bad, tvb, CHECKSUM_OFFSET, CHECKSUM_LENGTH, !(crc32c_correct || adler32_correct));
      break;
    }
  } else {
    sctp_tree = NULL;
    sctp_item = NULL;
  };
  /* add all chunks of the sctp datagram to the protocol tree */
  dissect_sctp_chunks(tvb, pinfo, tree, sctp_item, sctp_tree, encapsulated);
}

static void
dissect_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 source_port, destination_port;
  guint number_of_ppid;

  /* Extract the common header */
  source_port      = tvb_get_ntohs(tvb, SOURCE_PORT_OFFSET);
  destination_port = tvb_get_ntohs(tvb, DESTINATION_PORT_OFFSET);

  /* update pi structure */
  pinfo->ptype    = PT_SCTP;
  pinfo->srcport  = source_port;
  pinfo->destport = destination_port;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCTP");

  /* Clear entries in Info column on summary display */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "");
      
  /* is this done automatically ? */
  for(number_of_ppid = 0; number_of_ppid < MAX_NUMBER_OF_PPIDS; number_of_ppid++)
    pinfo->ppid[number_of_ppid] = 0;

  memset(&sctp_info, 0, sizeof(struct _sctp_info));
  sctp_info.verification_tag = tvb_get_ntohl(tvb, VERIFICATION_TAG_OFFSET);
  
  /* FIXME: Do we need to put this into _sctp_info? */
  sctp_info.sport = pinfo->srcport;
  sctp_info.dport = pinfo->destport;
  SET_ADDRESS(&sctp_info.ip_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
  SET_ADDRESS(&sctp_info.ip_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);
  
  dissect_sctp_packet(tvb, pinfo, tree, FALSE);
  if (!pinfo->in_error_pkt)
    tap_queue_packet(sctp_tap, pinfo, &sctp_info);
}

/* Register the protocol with Wireshark */
void
proto_register_sctp(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_source_port,                              { "Source port",                                 "sctp.srcport",                                         FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_destination_port,                         { "Destination port",                            "sctp.dstport",                                         FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_port,                                     { "Port",                                        "sctp.port",                                            FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_verification_tag,                         { "Verification tag",                            "sctp.verification_tag",                                FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_checksum,                                 { "Checksum",                                    "sctp.checksum",                                        FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_checksum_bad,                             { "Bad checksum",                                "sctp.checksum_bad",                                    FT_BOOLEAN, BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_chunk_type,                               { "Chunk type",                                  "sctp.chunk_type",                                      FT_UINT8,   BASE_DEC,  VALS(chunk_type_values),                        0x0,                                "", HFILL } },
    { &hf_chunk_flags,                              { "Chunk flags",                                 "sctp.chunk_flags",                                     FT_UINT8,   BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_chunk_bit_1,                              { "Bit",                                         "sctp.chunk_bit_1",                                     FT_BOOLEAN, 8,         TFS(&sctp_chunk_bit_1_value),                   SCTP_CHUNK_BIT_1,                   "", HFILL } },
    { &hf_chunk_bit_2,                              { "Bit",                                         "sctp.chunk_bit_2",                                     FT_BOOLEAN, 8,         TFS(&sctp_chunk_bit_2_value),                   SCTP_CHUNK_BIT_2,                   "", HFILL } },
    { &hf_chunk_length,                             { "Chunk length",                                "sctp.chunk_length",                                    FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_chunk_padding,                            { "Chunk padding",                               "sctp.chunk_padding",                                   FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_chunk_value,                              { "Chunk value",                                 "sctp.chunk_value",                                     FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_cookie,                                   { "Cookie",                                      "sctp.cookie",                                          FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_initiate_tag,                             { "Initiate tag",                                "sctp.initiate_tag",                                    FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_init_chunk_initiate_tag,                  { "Initiate tag",                                "sctp.init_initiate_tag",                               FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_init_chunk_adv_rec_window_credit,         { "Advertised receiver window credit (a_rwnd)",  "sctp.init_credit",                                     FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_init_chunk_number_of_outbound_streams,    { "Number of outbound streams",                  "sctp.init_nr_out_streams",                             FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_init_chunk_number_of_inbound_streams,     { "Number of inbound streams",                   "sctp.init_nr_in_streams",                              FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_init_chunk_initial_tsn,                   { "Initial TSN",                                 "sctp.init_initial_tsn",                                FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_initack_chunk_initiate_tag,               { "Initiate tag",                                "sctp.initack_initiate_tag",                            FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_initack_chunk_adv_rec_window_credit,      { "Advertised receiver window credit (a_rwnd)",  "sctp.initack_credit",                                  FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_initack_chunk_number_of_outbound_streams, { "Number of outbound streams",                  "sctp.initack_nr_out_streams",                          FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_initack_chunk_number_of_inbound_streams,  { "Number of inbound streams",                   "sctp.initack_nr_in_streams",                           FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_initack_chunk_initial_tsn,                { "Initial TSN",                                 "sctp.initack_initial_tsn",                             FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_cumulative_tsn_ack,                       { "Cumulative TSN Ack",                          "sctp.cumulative_tsn_ack",                              FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_data_chunk_tsn,                           { "TSN",                                         "sctp.data_tsn",                                        FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_data_chunk_stream_id,                     { "Stream Identifier",                           "sctp.data_sid",                                        FT_UINT16,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_data_chunk_stream_seq_number,             { "Stream sequence number",                      "sctp.data_ssn",                                        FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_data_chunk_payload_proto_id,              { "Payload protocol identifier",                 "sctp.data_payload_proto_id",                           FT_UINT32,  BASE_DEC,  VALS(sctp_payload_proto_id_values),             0x0,                                "", HFILL } },
    { &hf_data_chunk_e_bit,                         { "E-Bit",                                       "sctp.data_e_bit",                                      FT_BOOLEAN, 8,         TFS(&sctp_data_chunk_e_bit_value),              SCTP_DATA_CHUNK_E_BIT,              "", HFILL } },
    { &hf_data_chunk_b_bit,                         { "B-Bit",                                       "sctp.data_b_bit",                                      FT_BOOLEAN, 8,         TFS(&sctp_data_chunk_b_bit_value),              SCTP_DATA_CHUNK_B_BIT,              "", HFILL } },
    { &hf_data_chunk_u_bit,                         { "U-Bit",                                       "sctp.data_u_bit",                                      FT_BOOLEAN, 8,         TFS(&sctp_data_chunk_u_bit_value),              SCTP_DATA_CHUNK_U_BIT,              "", HFILL } },
    { &hf_sack_chunk_ns,                            { "Nounce sum",                                  "sctp.sack_nounce_sum",                                 FT_UINT8,   BASE_DEC,  NULL,                                           SCTP_SACK_CHUNK_NS_BIT,             "", HFILL } },
    { &hf_sack_chunk_cumulative_tsn_ack,            { "Cumulative TSN ACK",                          "sctp.sack_cumulative_tsn_ack",                         FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_sack_chunk_adv_rec_window_credit,         { "Advertised receiver window credit (a_rwnd)",  "sctp.sack_a_rwnd",                                     FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_sack_chunk_number_of_gap_blocks,          { "Number of gap acknowledgement blocks ",       "sctp.sack_number_of_gap_blocks",                       FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_sack_chunk_number_of_dup_tsns,            { "Number of duplicated TSNs",                   "sctp.sack_number_of_duplicated_tsns",                  FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_sack_chunk_gap_block_start,               { "Start",                                       "sctp.sack_gap_block_start",                            FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_sack_chunk_gap_block_end,                 { "End",                                         "sctp.sack_gap_block_end",                              FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_sack_chunk_duplicate_tsn,                 { "Duplicate TSN",                               "sctp.sack_duplicate_tsn",                              FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_shutdown_chunk_cumulative_tsn_ack,        { "Cumulative TSN Ack",                          "sctp.shutdown_cumulative_tsn_ack",                     FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_ecne_chunk_lowest_tsn,                    { "Lowest TSN",                                  "sctp.ecne_lowest_tsn",                                 FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_cwr_chunk_lowest_tsn,                     { "Lowest TSN",                                  "sctp.cwr_lowest_tsn",                                  FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_shutdown_complete_chunk_t_bit,            { "T-Bit",                                       "sctp.shutdown_complete_t_bit",                         FT_BOOLEAN, 8,         TFS(&sctp_shutdown_complete_chunk_t_bit_value), SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT, "", HFILL } },
    { &hf_abort_chunk_t_bit,                        { "T-Bit",                                       "sctp.abort_t_bit",                                     FT_BOOLEAN, 8,         TFS(&sctp_shutdown_complete_chunk_t_bit_value), SCTP_ABORT_CHUNK_T_BIT,             "", HFILL } },
    { &hf_forward_tsn_chunk_tsn,                    { "New cumulative TSN",                          "sctp.forward_tsn_tsn",                                 FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_forward_tsn_chunk_sid,                    { "Stream identifier",                           "sctp.forward_tsn_sid",                                 FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_forward_tsn_chunk_ssn,                    { "Stream sequence number",                      "sctp.forward_tsn_ssn",                                 FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_parameter_type,                           { "Parameter type",                              "sctp.parameter_type",                                  FT_UINT16,  BASE_HEX,  VALS(parameter_identifier_values),              0x0,                                "", HFILL } },
    { &hf_parameter_length,                         { "Parameter length",                            "sctp.parameter_length",                                FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_parameter_value,                          { "Parameter value",                             "sctp.parameter_value",                                 FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_parameter_padding,                        { "Parameter padding",                           "sctp.parameter_padding",                               FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_parameter_bit_1,                          { "Bit",                                         "sctp.parameter_bit_1",                                 FT_BOOLEAN, 16,        TFS(&sctp_parameter_bit_1_value),               SCTP_PARAMETER_BIT_1,               "", HFILL } },
    { &hf_parameter_bit_2,                          { "Bit",                                         "sctp.parameter_bit_2",                                 FT_BOOLEAN, 16,        TFS(&sctp_parameter_bit_2_value),               SCTP_PARAMETER_BIT_2,               "", HFILL } },
    { &hf_ipv4_address,                             { "IP Version 4 address",                        "sctp.parameter_ipv4_address",                          FT_IPv4,    BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_ipv6_address,                             { "IP Version 6 address",                        "sctp.parameter_ipv6_address",                          FT_IPv6,    BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_heartbeat_info,                           { "Heartbeat information",                       "sctp.parameter_heartbeat_information",                 FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_state_cookie,                             { "State cookie",                                "sctp.parameter_state_cookie",                          FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_cookie_preservative_increment,            { "Suggested Cookie life-span increment (msec)", "sctp.parameter_cookie_preservative_incr",              FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_hostname,                                 { "Hostname",                                    "sctp.parameter_hostname",                              FT_STRING,  BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_supported_address_type,                   { "Supported address type",                      "sctp.parameter_supported_addres_type",                 FT_UINT16,  BASE_DEC,  VALS(address_types_values),                     0x0,                                "", HFILL } },
    { &hf_stream_reset_req_seq_nr,                  { "Stream reset request sequence number",        "sctp.parameter_stream_reset_request_sequence_number",  FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_stream_reset_rsp_seq_nr,                  { "Stream reset response sequence number",       "sctp.parameter_stream_reset_response_sequence_number", FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_senders_last_assigned_tsn,                { "Senders last assigned TSN",                   "sctp.parameter_senders_last_assigned_tsn",             FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_senders_next_tsn,                         { "Senders next TSN",                            "sctp.parameter_senders_next_tsn",                      FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_receivers_next_tsn,                       { "Receivers next TSN",                          "sctp.parameter_receivers_next_tsn",                    FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_stream_reset_rsp_result,                  { "Result",                                      "sctp.parameter_stream_reset_response_result",          FT_UINT32,  BASE_DEC,  VALS(stream_reset_result_values),               0x0,                                "", HFILL } },
    { &hf_stream_reset_sid,                         { "Stream Identifier",                           "sctp.parameter_stream_reset_sid",                      FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_asconf_serial,                            { "Serial number",                               "sctp.asconf_serial_number",                            FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_asconf_ack_serial,                        { "Serial number",                               "sctp.asconf_ack_serial_number",                        FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_correlation_id,                           { "Correlation_id",                              "sctp.correlation_id",                                  FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_adap_indication,                          { "Indication",                                  "sctp.adapation_layer_indication",                      FT_UINT32,  BASE_HEX,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_random_number,                            { "Random number",                               "sctp.random_number",                                   FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_chunks_to_auth,                           { "Chunk type",                                  "sctp.chunk_type_to_auth",                              FT_UINT8,   BASE_DEC,  VALS(chunk_type_values),                        0x0,                                "", HFILL } },
    { &hf_hmac_id,                                  { "HMAC identifier",                             "sctp.hmac_id",                                         FT_UINT16,  BASE_DEC,  VALS(hmac_id_values),                           0x0,                                "", HFILL } },
    { &hf_hmac,                                     { "HMAC",                                        "sctp.hmac",                                            FT_BYTES,   BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_shared_key_id,                            { "Shared key identifier",                       "sctp.shared_key_id",                                   FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_supported_chunk_type,                     { "Supported chunk type",                        "sctp.supported_chunk_type",                            FT_UINT8,   BASE_DEC,  VALS(chunk_type_values),                        0x0,                                "", HFILL } },
    { &hf_cause_code,                               { "Cause code",                                  "sctp.cause_code",                                      FT_UINT16,  BASE_HEX,  VALS(cause_code_values),                        0x0,                                "", HFILL } },
    { &hf_cause_length,                             { "Cause length",                                "sctp.cause_length",                                    FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_cause_info,                               { "Cause information",                           "sctp.cause_information",                               FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_cause_padding,                            { "Cause padding",                               "sctp.cause_padding",                                   FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
    { &hf_cause_stream_identifier,                  { "Stream identifier",                           "sctp.cause_stream_identifier",                         FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_cause_reserved,                           { "Reserved",                                    "sctp.cause_reserved",                                  FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_cause_number_of_missing_parameters,       { "Number of missing parameters",                "sctp.cause_nr_of_missing_parameters",                  FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_cause_missing_parameter_type,             { "Missing parameter type",                      "sctp.cause_missing_parameter_type",                    FT_UINT16,  BASE_HEX,  VALS(parameter_identifier_values),              0x0,                                "", HFILL } },
    { &hf_cause_measure_of_staleness,               { "Measure of staleness in usec",                "sctp.cause_measure_of_staleness",                      FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_cause_tsn,                                { "TSN",                                         "sctp.cause_tsn",                                       FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_pktdrop_chunk_m_bit,                      { "M-Bit",                                       "sctp.pckdrop_m_bit",                                   FT_BOOLEAN, 8,         TFS(&sctp_pktdropk_m_bit_value),                SCTP_PKTDROP_CHUNK_M_BIT,           "", HFILL } },
    { &hf_pktdrop_chunk_b_bit,                      { "B-Bit",                                       "sctp.pckdrop_b_bit",                                   FT_BOOLEAN, 8,         TFS(&sctp_pktdropk_b_bit_value),                SCTP_PKTDROP_CHUNK_B_BIT,           "", HFILL } },
    { &hf_pktdrop_chunk_t_bit,                      { "T-Bit",                                       "sctp.pckdrop_t_bit",                                   FT_BOOLEAN, 8,         TFS(&sctp_pktdropk_t_bit_value),                SCTP_PKTDROP_CHUNK_T_BIT,           "", HFILL } },
    { &hf_pktdrop_chunk_bandwidth,                  { "Bandwidth",                                   "sctp.pktdrop_bandwidth",                               FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_pktdrop_chunk_queuesize,                  { "Queuesize",                                   "sctp.pktdrop_queuesize",                               FT_UINT32,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_pktdrop_chunk_truncated_length,           { "Truncated length",                            "sctp.pktdrop_truncated_length",                        FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_pktdrop_chunk_reserved,                   { "Reserved",                                    "sctp.pktdrop_reserved",                                FT_UINT16,  BASE_DEC,  NULL,                                           0x0,                                "", HFILL } },
    { &hf_pktdrop_chunk_data_field,                 { "Data field",                                  "sctp.pktdrop_datafield",                               FT_BYTES,   BASE_NONE, NULL,                                           0x0,                                "", HFILL } },
 };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sctp,
    &ett_sctp_chunk,
    &ett_sctp_chunk_parameter,
    &ett_sctp_chunk_cause,
    &ett_sctp_chunk_type,
    &ett_sctp_data_chunk_flags,
    &ett_sctp_sack_chunk_flags,
    &ett_sctp_abort_chunk_flags,
    &ett_sctp_shutdown_complete_chunk_flags,
    &ett_sctp_pktdrop_chunk_flags,
    &ett_sctp_parameter_type,
    &ett_sctp_sack_chunk_gap_block,
    &ett_sctp_unrecognized_parameter_parameter,
  };

  static enum_val_t sctp_checksum_options[] = {
    { "none",      "None",        SCTP_CHECKSUM_NONE },
    { "adler-32",  "Adler 32",    SCTP_CHECKSUM_ADLER32 },
    { "crc-32c",   "CRC 32c",     SCTP_CHECKSUM_CRC32C },
    { "automatic", "Automatic",   SCTP_CHECKSUM_AUTOMATIC},
    { NULL, NULL, 0 }
  };

  /* Register the protocol name and description */
  proto_sctp = proto_register_protocol("Stream Control Transmission Protocol", "SCTP", "sctp");
  sctp_module = prefs_register_protocol(proto_sctp, NULL);
  prefs_register_bool_preference(sctp_module, "show_port_numbers_in_tree",
                         "Show port numbers in the protocol tree",
                         "Show source and destination port numbers in the protocol tree",
                         &show_port_numbers);
  /* FIXME
  prefs_register_bool_preference(sctp_module, "show_chunk_types_in_tree",
                         "Show chunk types in the protocol tree",
                         "Show chunk types in the protocol tree",
                         &show_chunk_types);
  */
  prefs_register_enum_preference(sctp_module, "checksum", "Checksum type",
                         "The type of checksum used in SCTP packets",
                         &sctp_checksum, sctp_checksum_options, FALSE);
  prefs_register_bool_preference(sctp_module, "show_always_control_chunks",
                         "Show always control chunks",
                         "Show always SCTP control chunks in the Info column",
                         &show_always_control_chunks);
  prefs_register_bool_preference(sctp_module, "try_heuristic_first",
                         "Try heuristic sub-dissectors first",
                         "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port or PPI",
                         &try_heuristic_first);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sctp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  sctp_tap = register_tap("sctp");
  /* subdissector code */
  sctp_port_dissector_table = register_dissector_table("sctp.port", "SCTP port", FT_UINT16, BASE_DEC);
  sctp_ppi_dissector_table  = register_dissector_table("sctp.ppi",  "SCTP payload protocol identifier", FT_UINT32, BASE_HEX);
  register_heur_dissector_list("sctp", &sctp_heur_subdissector_list);
}

void
proto_reg_handoff_sctp(void)
{
  dissector_handle_t sctp_handle;

  data_handle = find_dissector("data");
  sctp_handle = create_dissector_handle(dissect_sctp, proto_sctp);
  dissector_add("ip.proto", IP_PROTO_SCTP, sctp_handle);
  dissector_add("udp.port", UDP_TUNNELING_PORT, sctp_handle);
}
