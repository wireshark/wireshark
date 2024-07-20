/* packet-zrtp.c
 * Routines for zrtp packet dissection
 * IETF draft draft-zimmermann-avt-zrtp-22
 * RFC 6189
 * Copyright 2007, Sagar Pai <sagar@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include <wsutil/crc32.h>
#include "packet-rtp.h"
#include "packet-rtcp.h"

void proto_reg_handoff_zrtp(void);
void proto_register_zrtp(void);

/*
  RTP header
*/
static int proto_zrtp;
static int hf_zrtp_rtpversion;
static int hf_zrtp_rtppadding;
static int hf_zrtp_rtpextension;
/* static int hf_zrtp_id; */
static int hf_zrtp_sequence;
static int hf_zrtp_cookie;
static int hf_zrtp_source_id;

/*
  ZRTP header
*/
static int hf_zrtp_signature;
static int hf_zrtp_msg_length;
static int hf_zrtp_msg_type;
static int hf_zrtp_msg_version;

/*
  Hello Data
*/
static int hf_zrtp_msg_client_id;
static int hf_zrtp_msg_zid;
static int hf_zrtp_msg_sigcap;
static int hf_zrtp_msg_mitm;
static int hf_zrtp_msg_passive;
static int hf_zrtp_msg_hash_count;
static int hf_zrtp_msg_cipher_count;
static int hf_zrtp_msg_authtag_count;
static int hf_zrtp_msg_key_count;
static int hf_zrtp_msg_sas_count;
static int hf_zrtp_msg_hash;
static int hf_zrtp_msg_cipher;
static int hf_zrtp_msg_at;
static int hf_zrtp_msg_keya;
static int hf_zrtp_msg_sas;
static int hf_zrtp_msg_hash_image;

/*
  Commit Data
*/
static int hf_zrtp_msg_hvi;
static int hf_zrtp_msg_nonce;
static int hf_zrtp_msg_key_id;

/*
  DHParts Data
*/
static int hf_zrtp_msg_rs1ID;
static int hf_zrtp_msg_rs2ID;
static int hf_zrtp_msg_auxs;
static int hf_zrtp_msg_pbxs;

/*
  Confirm Data
*/
static int hf_zrtp_msg_hmac;
static int hf_zrtp_msg_cfb;

/*
  Error Data
*/
static int hf_zrtp_msg_error;

/*
  Ping Data
*/
static int hf_zrtp_msg_ping_version;
static int hf_zrtp_msg_ping_endpointhash;
static int hf_zrtp_msg_pingack_endpointhash;
static int hf_zrtp_msg_ping_ssrc;

/*
  Checksum Data
*/
static int hf_zrtp_checksum;
static int hf_zrtp_checksum_status;

/*
  Sub-Tree
*/
static int ett_zrtp;
static int ett_zrtp_msg;
static int ett_zrtp_msg_data;

static int ett_zrtp_msg_hc;
static int ett_zrtp_msg_kc;
static int ett_zrtp_msg_ac;
static int ett_zrtp_msg_cc;
static int ett_zrtp_msg_sc;

static int ett_zrtp_checksum;


static expert_field ei_zrtp_checksum;

static dissector_handle_t zrtp_handle;


/*
  Definitions
*/
#define ZRTP_ERR_10 0x10
#define ZRTP_ERR_20 0x20
#define ZRTP_ERR_30 0x30
#define ZRTP_ERR_40 0x40
#define ZRTP_ERR_51 0x51
#define ZRTP_ERR_52 0x52
#define ZRTP_ERR_53 0x53
#define ZRTP_ERR_54 0x54
#define ZRTP_ERR_55 0x55
#define ZRTP_ERR_56 0x56
#define ZRTP_ERR_61 0x61
#define ZRTP_ERR_62 0x62
#define ZRTP_ERR_63 0x63
#define ZRTP_ERR_70 0x70
#define ZRTP_ERR_80 0x80
#define ZRTP_ERR_90 0x90
#define ZRTP_ERR_91 0x91
#define ZRTP_ERR_A0 0xA0
#define ZRTP_ERR_B0 0xB0
#define ZRTP_ERR_100 0x100

/*
  Text for Display
*/
typedef struct _value_zrtp_versions {
  const char *version;
} value_zrtp_versions;


typedef struct _value_string_keyval {
  const char *key;
  const char *val;
} value_string_keyval;


static const value_zrtp_versions valid_zrtp_versions[] =
  {
    {"1.1x"},
    {"1.0x"},
    {"0.95"},
    {"0.90"},
    {"0.85"},
    {NULL}
  };

static const value_string_keyval zrtp_hash_type_vals[] =
  {
    { "S256",   "SHA-256 Hash"},
    { "S384",   "SHA-384 Hash"},
    { "N256",   "SHA-3 256-bit hash"},
    { "N384",   "SHA-3 384 bit hash"},
    { NULL,             NULL }
  };

static const value_string_keyval zrtp_cipher_type_vals[] =
  {
    { "AES1",   "AES-CM with 128 bit keys"},
    { "AES2",   "AES-CM with 192 bit keys"},
    { "AES3",   "AES-CM with 256 bit keys"},
    { "2FS1",   "TwoFish with 128 bit keys"},
    { "2FS2",   "TwoFish with 192 bit keys"},
    { "2FS3",   "TwoFish with 256 bit keys"},
    { "CAM1",   "Camellia with 128 bit keys"},
    { "CAM2",   "Camellia with 192 bit keys"},
    { "CAM3",   "Camellia with 256 bit keys"},
    { NULL,             NULL }
  };

static const value_string_keyval zrtp_auth_tag_vals[] =
  {
    { "HS32",   "HMAC-SHA1 32 bit authentication tag"},
    { "HS80",   "HMAC-SHA1 80 bit authentication tag"},
    { "SK32",   "Skein-512-MAC 32 bit authentication tag"},
    { "SK64",   "Skein-512-MAC 64 bit authentication tag"},
    { NULL,             NULL }
  };

static const value_string_keyval zrtp_sas_type_vals[] =
  {
    { "B32 ",   "Short authentication string using base 32"},
    { "B256",   "Short authentication string using base 256"},
    { NULL,             NULL }
  };

static const value_string_keyval zrtp_key_agreement_vals[] =
  {
    { "DH2k",   "DH mode with p=2048 bit prime"},
    { "DH3k",   "DH mode with p=3072 bit prime"},
    { "DH4k",   "DH mode with p=4096 bit prime"},
    { "Prsh",   "Preshared non-DH mode using shared secret"},
    { "EC25",   "Elliptic Curve DH-256"},
    { "EC38",   "Elliptic Curve DH-384"},
    { "EC52",   "Elliptic Curve DH-521"},
    { "Mult",   "Multistream mode"},
    { NULL,             NULL }
  };

static const value_string zrtp_error_vals[] =
  {
    { ZRTP_ERR_10, "Malformed Packet (CRC OK but wrong structure)"},
    { ZRTP_ERR_20, "Critical Software Error"},
    { ZRTP_ERR_30, "Unsupported ZRTP version"},
    { ZRTP_ERR_40, "Hello Components mismatch"},
    { ZRTP_ERR_51, "Hash type unsupported"},
    { ZRTP_ERR_52, "Cipher type not supported"},
    { ZRTP_ERR_53, "Public key exchange not supported"},
    { ZRTP_ERR_54, "SRTP auth. tag not supported"},
    { ZRTP_ERR_55, "SAS scheme not supported"},
    { ZRTP_ERR_56, "No shared secret available, DH mode required"},
    { ZRTP_ERR_61, "DH Error: bad pv for initiator/responder value is (1,0,p-1)"},
    { ZRTP_ERR_62, "DH Error: bad hash commitment (hvi != hashed data)"},
    { ZRTP_ERR_63, "Received relayed SAS from untrusted MiTM"},
    { ZRTP_ERR_70, "Auth. Error Bad Confirm Packet HMAC"},
    { ZRTP_ERR_80, "Nonce is reused"},
    { ZRTP_ERR_90, "Equal ZID's in Hello"},
    { ZRTP_ERR_91, "SSRC collision"},
    { ZRTP_ERR_A0, "Service unavailable"},
    { ZRTP_ERR_B0, "Protocol timeout error"},
    { ZRTP_ERR_100, "GoClear packet received, but not allowed"},
    { 0, NULL}
  };

static void
dissect_Hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree);
static void
dissect_ErrorACK(packet_info *pinfo);
static void
dissect_Commit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree);
static void
dissect_ClearACK( packet_info *pinfo);
static void
dissect_Conf2ACK(packet_info *pinfo);
static void
dissect_HelloACK( packet_info *pinfo);
static void
dissect_GoClear(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree);
static void
dissect_Error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree);
static void
dissect_Confirm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree, int part);
static void
dissect_DHPart(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree, int part);
static void
dissect_SASrelay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree);
static void
dissect_RelayACK(packet_info *pinfo);
static void
dissect_Ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree);
static void
dissect_PingACK(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree);


static const char *
key_to_val(const char *key, int keylen, const value_string_keyval *kv, const char *fmt) {
  int i = 0;
  while (kv[i].key) {
    if (!strncmp(kv[i].key, key, keylen)) {
      return kv[i].val;
    }
    i++;
  }
  return wmem_strdup_printf(wmem_packet_scope(), fmt, key);
}

static const char *
check_valid_version(const char *version) {
  int i = 0;
  int match_size = (version[0] == '0') ? 4 : 3;
  while (valid_zrtp_versions[i].version) {
    if (!strncmp(valid_zrtp_versions[i].version, version, match_size)) {
      return valid_zrtp_versions[i].version;
    }
    i++;
  }
  return NULL;
}


static int
dissect_zrtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree    *zrtp_tree;
  proto_tree    *zrtp_msg_tree;
  proto_tree    *zrtp_msg_data_tree;
  proto_item    *ti;
  int            linelen;
  int            checksum_offset;
  unsigned char  message_type[9];
  unsigned int   prime_offset = 0;
  unsigned int   msg_offset   = 12;
  uint32_t       calc_crc;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZRTP");

  col_set_str(pinfo->cinfo, COL_INFO, "Unknown ZRTP Packet");

  ti = proto_tree_add_protocol_format(tree, proto_zrtp, tvb, 0, -1, "ZRTP protocol");
  zrtp_tree = proto_item_add_subtree(ti, ett_zrtp);

  proto_tree_add_item(zrtp_tree, hf_zrtp_rtpversion, tvb, prime_offset+0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(zrtp_tree, hf_zrtp_rtppadding, tvb, prime_offset+0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(zrtp_tree, hf_zrtp_rtpextension, tvb, prime_offset+0, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(zrtp_tree, hf_zrtp_sequence, tvb, prime_offset+2, 2, ENC_BIG_ENDIAN);

  proto_tree_add_item(zrtp_tree, hf_zrtp_cookie, tvb, prime_offset+4, 4, ENC_ASCII);

  proto_tree_add_item(zrtp_tree, hf_zrtp_source_id, tvb, prime_offset+8, 4, ENC_BIG_ENDIAN);

  linelen = tvb_reported_length_remaining(tvb, msg_offset);
  checksum_offset = linelen-4;

  ti = proto_tree_add_protocol_format(zrtp_tree, proto_zrtp, tvb, msg_offset, linelen-4, "Message");
  zrtp_msg_tree = proto_item_add_subtree(ti, ett_zrtp_msg);

  proto_tree_add_item(zrtp_msg_tree, hf_zrtp_signature, tvb, msg_offset+0, 2, ENC_BIG_ENDIAN);

  proto_tree_add_item(zrtp_msg_tree, hf_zrtp_msg_length, tvb, msg_offset+2, 2, ENC_BIG_ENDIAN);

  tvb_memcpy(tvb, (void *)message_type, msg_offset+4, 8);
  message_type[8] = '\0';
  proto_tree_add_item(zrtp_msg_tree, hf_zrtp_msg_type, tvb, msg_offset+4, 8, ENC_ASCII);

  linelen = tvb_reported_length_remaining(tvb, msg_offset+12);

  if (!strncmp(message_type, "Hello   ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_Hello(tvb, pinfo, zrtp_msg_data_tree);
  } else if (!strncmp(message_type, "HelloACK", 8)) {
    dissect_HelloACK(pinfo);
  } else if (!strncmp(message_type, "Commit  ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_Commit(tvb, pinfo, zrtp_msg_data_tree);
  } else if (!strncmp(message_type, "DHPart1 ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_DHPart(tvb, pinfo, zrtp_msg_data_tree, 1);
  } else if (!strncmp(message_type, "DHPart2 ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_DHPart(tvb, pinfo, zrtp_msg_data_tree, 2);
  } else if (!strncmp(message_type, "Confirm1", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_Confirm(tvb, pinfo, zrtp_msg_data_tree, 1);
  } else if (!strncmp(message_type, "Confirm2", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_Confirm(tvb, pinfo, zrtp_msg_data_tree, 2);
  } else if (!strncmp(message_type, "Conf2ACK", 8)) {
    dissect_Conf2ACK(pinfo);
  } else if (!strncmp(message_type, "Error   ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_Error(tvb, pinfo, zrtp_msg_data_tree);
  } else if (!strncmp(message_type, "ErrorACK", 8)) {
    dissect_ErrorACK(pinfo);
  } else if (!strncmp(message_type, "GoClear ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_GoClear(tvb, pinfo, zrtp_msg_data_tree);
  } else if (!strncmp(message_type, "ClearACK", 8)) {
    dissect_ClearACK(pinfo);
  } else if (!strncmp(message_type, "SASrelay", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_SASrelay(tvb, pinfo, zrtp_msg_data_tree);
  } else if (!strncmp(message_type, "RelayACK", 8)) {
    dissect_RelayACK(pinfo);
  } else if (!strncmp(message_type, "Ping    ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_Ping(tvb, pinfo, zrtp_msg_data_tree);
  } else if (!strncmp(message_type, "PingACK ", 8)) {
    ti = proto_tree_add_protocol_format(zrtp_msg_tree, proto_zrtp, tvb, msg_offset+12, linelen-4, "Data");
    zrtp_msg_data_tree = proto_item_add_subtree(ti, ett_zrtp_msg_data);
    dissect_PingACK(tvb, pinfo, zrtp_msg_data_tree);
  }

  calc_crc = ~crc32c_tvb_offset_calculate(tvb, 0, msg_offset+checksum_offset, CRC32C_PRELOAD);

  proto_tree_add_checksum(zrtp_tree, tvb, msg_offset+checksum_offset, hf_zrtp_checksum, hf_zrtp_checksum_status, &ei_zrtp_checksum, pinfo, calc_crc,
                            ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
  return tvb_captured_length(tvb);
}

static void
dissect_ErrorACK(packet_info *pinfo) {
  col_set_str(pinfo->cinfo, COL_INFO, "ErrorACK Packet");
}

static void
dissect_ClearACK(packet_info *pinfo) {
  col_set_str(pinfo->cinfo, COL_INFO, "ClearACK Packet");
}

static void
dissect_RelayACK(packet_info *pinfo) {
  col_set_str(pinfo->cinfo, COL_INFO, "RelayACK Packet");
}

static void
dissect_Conf2ACK(packet_info *pinfo) {

  /* Signals start of SRT(C)P streams */
  struct srtp_info *dummy_srtp_info = wmem_new0(wmem_file_scope(), struct srtp_info);

  dummy_srtp_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
  dummy_srtp_info->auth_algorithm = SRTP_AUTH_ALG_HMAC_SHA1;
  dummy_srtp_info->mki_len = 0;
  dummy_srtp_info->auth_tag_len = 4;

  srtp_add_address(pinfo, PT_UDP, &pinfo->net_src, pinfo->srcport, pinfo->destport,
                   "ZRTP", pinfo->num, RTP_MEDIA_AUDIO, NULL, dummy_srtp_info, NULL);

  srtp_add_address(pinfo, PT_UDP, &pinfo->net_dst, pinfo->destport, pinfo->srcport,
                   "ZRTP", pinfo->num, RTP_MEDIA_AUDIO, NULL, dummy_srtp_info, NULL);

  srtcp_add_address(pinfo, &pinfo->net_src, pinfo->srcport+1, pinfo->destport+1,
                    "ZRTP", pinfo->num, dummy_srtp_info);

  srtcp_add_address(pinfo, &pinfo->net_dst, pinfo->destport+1, pinfo->srcport+1,
                    "ZRTP", pinfo->num, dummy_srtp_info);

  col_set_str(pinfo->cinfo, COL_INFO, "Conf2ACK Packet");
}

static void
dissect_HelloACK(packet_info *pinfo) {
  col_set_str(pinfo->cinfo, COL_INFO, "HelloACK Packet");
}

static void
dissect_Ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree) {
  unsigned int data_offset = 24;

  col_set_str(pinfo->cinfo, COL_INFO, "Ping Packet");

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_ping_version,      tvb, data_offset,   4, ENC_ASCII);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_ping_endpointhash, tvb, data_offset+4, 8, ENC_BIG_ENDIAN);
}

static void
dissect_PingACK(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree) {
  unsigned int data_offset = 24;

  col_set_str(pinfo->cinfo, COL_INFO, "PingACK Packet");

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_ping_version,         tvb, data_offset,    4, ENC_ASCII);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_pingack_endpointhash, tvb, data_offset+4,  8, ENC_BIG_ENDIAN);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_ping_endpointhash,    tvb, data_offset+12, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_ping_ssrc,            tvb, data_offset+20, 4, ENC_BIG_ENDIAN);
}

static void
dissect_GoClear(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree) {
  unsigned int data_offset = 24;

  col_set_str(pinfo->cinfo, COL_INFO, "GoClear Packet");

  /* Now we should clear the SRT(C)P session... */

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hmac, tvb, data_offset+0, 8, ENC_NA);
}

static void
dissect_Error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree) {
  unsigned int data_offset = 24;

  col_set_str(pinfo->cinfo, COL_INFO, "Error Packet");

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_error, tvb, data_offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_Confirm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree, int part) {
  unsigned int data_offset = 24;
  int          linelen;

  col_add_fstr(pinfo->cinfo, COL_INFO, (part == 1) ? "Confirm1 Packet" : "Confirm2 Packet");

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hmac, tvb, data_offset+0, 8, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_cfb, tvb, data_offset+8, 16, ENC_NA);
  linelen = tvb_reported_length_remaining(tvb, data_offset+24);
  proto_tree_add_protocol_format(zrtp_tree, proto_zrtp, tvb, data_offset+24, linelen-4, "Encrypted Data");
}

static void
dissect_SASrelay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree) {
  unsigned int data_offset = 24;
  int          linelen;

  col_set_str(pinfo->cinfo, COL_INFO, "SASrelay Packet");

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hmac, tvb, data_offset+0, 8, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_cfb, tvb, data_offset+8, 16, ENC_NA);
  linelen = tvb_reported_length_remaining(tvb, data_offset+24);
  proto_tree_add_protocol_format(zrtp_tree, proto_zrtp, tvb, data_offset+24, linelen-4, "Encrypted Data");
}

static void
dissect_DHPart(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree, int part) {
  unsigned int msg_offset  = 12;
  unsigned int data_offset = 56;
  int          linelen, pvr_len;

  col_add_fstr(pinfo->cinfo, COL_INFO, (part == 1) ? "DHPart1 Packet" : "DHPart2 Packet");

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hash_image, tvb, msg_offset+12, 32, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_rs1ID,      tvb, data_offset+0,  8, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_rs2ID,      tvb, data_offset+8,  8, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_auxs,       tvb, data_offset+16, 8, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_pbxs,       tvb, data_offset+24, 8, ENC_NA);
  linelen = tvb_reported_length_remaining(tvb, data_offset+32);
  pvr_len = linelen-8-4;
  proto_tree_add_protocol_format(zrtp_tree, proto_zrtp, tvb, data_offset+32, pvr_len, (part==1) ? "pvr Data" : "pvi Data");
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hmac, tvb, data_offset+32+pvr_len, 8, ENC_NA);
}

static void
dissect_Commit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree) {
  unsigned int  msg_offset  = 12;
  unsigned int  data_offset = 56;
  char         *value;
  int           key_type    = 0;
  /*
    0 - other type
    1 - "Mult"
    2 - "Prsh"
  */
  unsigned int  offset;

  col_set_str(pinfo->cinfo, COL_INFO, "Commit Packet");

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hash_image, tvb, msg_offset+12, 32, ENC_NA);
  /* ZID */
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_zid, tvb, data_offset+0, 12, ENC_NA);
  value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, data_offset+12, 4, ENC_ASCII|ENC_NA);
  proto_tree_add_string_format_value(zrtp_tree, hf_zrtp_msg_hash, tvb, data_offset+12, 4, value,
                                  "%s", key_to_val(value, 4, zrtp_hash_type_vals, "Unknown hash type %s"));
  value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, data_offset+16, 4, ENC_ASCII|ENC_NA);
  proto_tree_add_string_format_value(zrtp_tree, hf_zrtp_msg_cipher, tvb, data_offset+16, 4, value, "%s",
                                  key_to_val(value, 4, zrtp_cipher_type_vals, "Unknown cipher type %s"));
  value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, data_offset+20, 4, ENC_ASCII|ENC_NA);
  proto_tree_add_string_format(zrtp_tree, hf_zrtp_msg_at, tvb, data_offset+20, 4, value,
                                  "Auth tag: %s", key_to_val(value, 4, zrtp_auth_tag_vals, "Unknown auth tag %s"));
  value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, data_offset+24, 4, ENC_ASCII|ENC_NA);
  proto_tree_add_string_format_value(zrtp_tree, hf_zrtp_msg_keya, tvb, data_offset+24, 4, value,
                                  "%s", key_to_val(value, 4, zrtp_key_agreement_vals, "Unknown key agreement %s"));

  if(!strncmp(value, "Mult", 4)) {
    key_type = 1;
  } else if (!strncmp(value, "Prsh", 4)) {
    key_type = 2;
  }
  value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, data_offset+28, 4, ENC_ASCII|ENC_NA);
  proto_tree_add_string_format(zrtp_tree, hf_zrtp_msg_sas, tvb, data_offset+28, 4, value,
                                  "SAS type: %s", key_to_val(value, 4, zrtp_sas_type_vals, "Unknown SAS type %s"));

  switch (key_type) {
  case 1: /*
             Mult
          */
    proto_tree_add_item(zrtp_tree, hf_zrtp_msg_nonce,  tvb, data_offset+32, 16, ENC_NA);
    offset = 48;
    break;
  case 2: /*
            Prsh
          */
    proto_tree_add_item(zrtp_tree, hf_zrtp_msg_nonce,  tvb, data_offset+32, 16, ENC_NA);
    proto_tree_add_item(zrtp_tree, hf_zrtp_msg_key_id, tvb, data_offset+48,  8, ENC_NA);
    offset = 56;
    break;
  default: /*
             other
           */
    proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hvi,    tvb, data_offset+32, 32, ENC_NA);
    offset = 64;
    break;
  }

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hmac,     tvb, data_offset+offset, 8, ENC_NA);
}

static void
dissect_Hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *zrtp_tree) {
  proto_item    *ti;
  unsigned int   msg_offset  = 12;
  unsigned int   data_offset = 88;
  uint8_t        val_b;
  unsigned int   i;
  unsigned int   run_offset;
  unsigned int   hc, cc, ac, kc, sc;
  unsigned int   vhc, vcc, vac, vkc, vsc;
  char          *value;
  char          *version_str;
  proto_tree    *tmp_tree;

  col_set_str(pinfo->cinfo, COL_INFO, "Hello Packet");

  version_str = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, msg_offset+12, 4, ENC_ASCII|ENC_NA);
  if (check_valid_version(version_str) == NULL) {
    col_set_str(pinfo->cinfo, COL_INFO, "Unsupported version of ZRTP protocol");
  }
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_version,    tvb, msg_offset+12,  4, ENC_ASCII);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_client_id,  tvb, msg_offset+16, 16, ENC_ASCII);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hash_image, tvb, msg_offset+32, 32, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_zid,        tvb, msg_offset+64, 12, ENC_NA);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_sigcap,     tvb, data_offset+0,  1, ENC_BIG_ENDIAN);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_mitm,       tvb, data_offset+0,  1, ENC_BIG_ENDIAN);
  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_passive,    tvb, data_offset+0,  1, ENC_BIG_ENDIAN);

  val_b = tvb_get_uint8(tvb, data_offset+1);
  hc = val_b & 0x0F;
  vhc = hc;

  val_b = tvb_get_uint8(tvb, data_offset+2);
  cc = val_b & 0xF0;
  ac = val_b & 0x0F;
  vcc = cc >> 4;
  vac = ac;

  val_b = tvb_get_uint8(tvb, data_offset+3);
  kc = val_b & 0xF0;
  sc = val_b & 0x0F;
  vkc = kc >> 4;
  vsc = sc;

  ti = proto_tree_add_uint_format(zrtp_tree, hf_zrtp_msg_hash_count, tvb, data_offset+1, 1, hc, "Hash type count = %d", vhc);
  tmp_tree = proto_item_add_subtree(ti, ett_zrtp_msg_hc);
  run_offset = data_offset+4;
  for (i=0; i<vhc; i++) {
    value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, run_offset, 4, ENC_ASCII|ENC_NA);
    proto_tree_add_string_format(tmp_tree, hf_zrtp_msg_hash, tvb, run_offset, 4, value,
                                    "Hash[%d]: %s", i, key_to_val(value, 4, zrtp_hash_type_vals, "Unknown hash type %s"));
    run_offset += 4;
  }
  ti = proto_tree_add_uint_format(zrtp_tree, hf_zrtp_msg_cipher_count, tvb, data_offset+2, 1, cc, "Cipher type count = %d", vcc);
  tmp_tree = proto_item_add_subtree(ti, ett_zrtp_msg_cc);
  for (i=0; i<vcc; i++) {
    value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, run_offset, 4, ENC_ASCII|ENC_NA);
    proto_tree_add_string_format(tmp_tree, hf_zrtp_msg_cipher, tvb, run_offset, 4, value, "Cipher[%d]: %s", i,
                                    key_to_val(value, 4, zrtp_cipher_type_vals, "Unknown cipher type %s"));
    run_offset += 4;
  }
  ti = proto_tree_add_uint_format(zrtp_tree, hf_zrtp_msg_authtag_count, tvb, data_offset+2, 1, ac, "Auth tag count = %d", vac);
  tmp_tree = proto_item_add_subtree(ti, ett_zrtp_msg_ac);
  for (i=0; i<vac; i++) {
    value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, run_offset, 4, ENC_ASCII|ENC_NA);
    proto_tree_add_string_format(tmp_tree, hf_zrtp_msg_at, tvb, run_offset, 4, value,
                                    "Auth tag[%d]: %s", i, key_to_val(value, 4, zrtp_auth_tag_vals, "Unknown auth tag %s"));
    run_offset += 4;
  }
  ti = proto_tree_add_uint_format(zrtp_tree, hf_zrtp_msg_key_count, tvb, data_offset+3, 1, kc, "Key agreement type count = %d", vkc);
  tmp_tree = proto_item_add_subtree(ti, ett_zrtp_msg_kc);
  for (i=0; i<vkc; i++) {
    value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, run_offset, 4, ENC_ASCII|ENC_NA);
    proto_tree_add_string_format(tmp_tree, hf_zrtp_msg_keya, tvb, run_offset, 4, value,
                                    "Key agreement[%d]: %s", i, key_to_val(value, 4, zrtp_key_agreement_vals, "Unknown key agreement %s"));
    run_offset += 4;
  }
  ti = proto_tree_add_uint_format(zrtp_tree, hf_zrtp_msg_sas_count, tvb, data_offset+3, 1, sc, "SAS type count = %d", vsc);
  tmp_tree = proto_item_add_subtree(ti, ett_zrtp_msg_sc);
  for (i=0; i<vsc; i++) {
    value = (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, run_offset, 4, ENC_ASCII|ENC_NA);
    proto_tree_add_string_format(tmp_tree, hf_zrtp_msg_sas, tvb, run_offset, 4, value,
                                    "SAS type[%d]: %s", i, key_to_val(value, 4, zrtp_sas_type_vals, "Unknown SAS type %s"));
    run_offset += 4;
  }

  proto_tree_add_item(zrtp_tree, hf_zrtp_msg_hmac, tvb, run_offset, 8, ENC_NA);
}

void
proto_register_zrtp(void)
{
  static hf_register_info hf[] = {
    {&hf_zrtp_rtpversion,
     {
       "RTP Version", "zrtp.rtpversion",
       FT_UINT8, BASE_DEC,
       NULL, 0xC0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_rtppadding,
     {
       "RTP padding", "zrtp.rtppadding",
       FT_BOOLEAN, 8,
       NULL, 0x20,
       NULL, HFILL
     }
    },

    {&hf_zrtp_rtpextension,
     {
       "RTP Extension", "zrtp.rtpextension",
       FT_BOOLEAN, 8,
       NULL, 0x10,
       NULL, HFILL
     }
    },

#if 0
    {&hf_zrtp_id,
     {
       "ID", "zrtp.id",
       FT_UINT8, BASE_HEX,
       NULL, 0x0,
       NULL, HFILL
     }
    },
#endif

    {&hf_zrtp_sequence,
     {
       "Sequence", "zrtp.sequence",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_cookie,
     {
       "Magic Cookie", "zrtp.cookie",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_source_id,
     {
       "Source Identifier", "zrtp.source_id",
       FT_UINT32, BASE_HEX,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    /*
       Message Types
    */
    {&hf_zrtp_signature,
     {
       "Signature", "zrtp.signature",
       FT_UINT16, BASE_HEX,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_length,
     {
       "Length", "zrtp.length",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_type,
     {
       "Type", "zrtp.type",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_version,
     {
       "ZRTP protocol version", "zrtp.version",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_client_id,
     {
       "Client Identifier", "zrtp.client_source_id",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_hash_image,
     {
       "Hash Image", "zrtp.hash_image",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_zid,
     {
       "ZID", "zrtp.zid",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_sigcap,
     {
       "Sig.capable", "zrtp.sigcap",
       FT_BOOLEAN, 8,
       NULL, 0x40,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_mitm,
     {
       "MiTM", "zrtp.mitm",
       FT_BOOLEAN, 8,
       NULL, 0x20,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_passive,
     {
       "Passive", "zrtp.passive",
       FT_BOOLEAN, 8,
       NULL, 0x10,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_hash_count,
     {
       "Hash Count", "zrtp.hc",
       FT_UINT8, BASE_DEC,
       NULL, 0x0F,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_cipher_count,
     {
       "Cipher Count", "zrtp.cc",
       FT_UINT8, BASE_DEC,
       NULL, 0xF0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_authtag_count,
     {
       "Auth tag Count", "zrtp.ac",
       FT_UINT8, BASE_DEC,
       NULL, 0x0F,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_key_count,
     {
       "Key Agreement Count", "zrtp.kc",
       FT_UINT8, BASE_DEC,
       NULL, 0xF0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_sas_count,
     {
       "SAS Count", "zrtp.sc",
       FT_UINT8, BASE_DEC,
       NULL, 0x0F,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_hash,
     {
       "Hash", "zrtp.hash",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_cipher,
     {
       "Cipher", "zrtp.cipher",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_at,
     {
       "AT", "zrtp.at",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_keya,
     {
       "Key Agreement", "zrtp.keya",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_sas,
     {
       "SAS", "zrtp.sas",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_rs1ID,
     {
       "rs1ID", "zrtp.rs1id",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_rs2ID,
     {
       "rs2ID", "zrtp.rs2id",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_auxs,
     {
       "auxs", "zrtp.auxs",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_pbxs,
     {
       "pbxs", "zrtp.pbxs",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_hmac,
     {
       "HMAC", "zrtp.hmac",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_cfb,
     {
       "CFB", "zrtp.cfb",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_error,
     {
       "Error", "zrtp.error",
       FT_UINT32, BASE_DEC,
       VALS(zrtp_error_vals), 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_ping_version,
     {
       "Ping Version", "zrtp.ping_version",
       FT_STRING, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_ping_endpointhash,
     {
       "Ping Endpoint Hash", "zrtp.ping_endpointhash",
       FT_UINT64, BASE_HEX,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_pingack_endpointhash,
     {
       "PingAck Endpoint Hash", "zrtp.pingack_endpointhash",
       FT_UINT64, BASE_HEX,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_ping_ssrc,
     {
       "Ping SSRC", "zrtp.ping_ssrc",
       FT_UINT32, BASE_HEX,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_checksum,
     {
       "Checksum", "zrtp.checksum",
       FT_UINT32, BASE_HEX,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_checksum_status,
     {
       "Checksum Status", "zrtp.checksum.status",
       FT_UINT8, BASE_NONE,
       VALS(proto_checksum_vals), 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_hvi,
     {
       "hvi", "zrtp.hvi",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_nonce,
     {
       "nonce", "zrtp.nonce",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    },

    {&hf_zrtp_msg_key_id,
     {
       "key ID", "zrtp.key_id",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL
     }
    }
  };

  static int *ett[] = {
    &ett_zrtp,
    &ett_zrtp_msg,
    &ett_zrtp_msg_data,
    &ett_zrtp_msg_hc,
    &ett_zrtp_msg_kc,
    &ett_zrtp_msg_ac,
    &ett_zrtp_msg_cc,
    &ett_zrtp_msg_sc,
    &ett_zrtp_checksum
  };

  static ei_register_info ei[] = {
    { &ei_zrtp_checksum, { "zrtp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
  };

  expert_module_t* expert_zrtp;

  proto_zrtp = proto_register_protocol("ZRTP", "ZRTP", "zrtp");
  proto_register_field_array(proto_zrtp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  zrtp_handle = register_dissector("zrtp", dissect_zrtp, proto_zrtp);
  expert_zrtp = expert_register_protocol(proto_zrtp);
  expert_register_field_array(expert_zrtp, ei, array_length(ei));
}

void
proto_reg_handoff_zrtp(void)
{
  dissector_add_for_decode_as_with_preference("udp.port", zrtp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
