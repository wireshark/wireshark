/* packet-uftp.c
 * Routines for UFTP packet dissection
 * Copyright Dennis Bush <bush@tcnj.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#define UFTP_VER_NUM 0x31
#define UFTP_3_0_VER 0x30

#define ANNOUNCE    1
#define REGISTER    2
#define CLIENT_KEY  3
#define REG_CONF    4
#define FILEINFO    5
#define KEYINFO     6
#define INFO_ACK    7
#define FILESEG     8
#define DONE        9
#define STATUS     10
#define PRSTATUS   11
#define COMPLETE   12
#define DONE_CONF  13
#define HB_REQ     14
#define HB_RESP    15
#define KEY_REQ    16
#define PROXY_KEY  17
#define ENCRYPTED  80
#define ABORT      99

#define MAXDEST 10000
#define MAXFILENAME 100
#define MAXDIRNAME 200
#define MAXPATHNAME 300
#define MAXPROXYDEST 1000

#define DESTNAME_LEN 100
#define MAXFILES 500
#define IFNAME_LEN 25
#define MAX_INTERFACES 20
#define IPSTR_LEN 16

#define FTYPE_REG 0
#define FTYPE_DIR 1
#define FTYPE_LINK 2

#define KEY_NONE 0x00
#define KEY_DES 0x01
#define KEY_DES_EDE3 0x02
#define KEY_AES128 0x03
#define KEY_AES256 0x04

#define HASH_NONE 0x00
#define HASH_MD5 0x01
#define HASH_SHA1 0x02
#define HASH_SHA256 0x03

#define SIG_NONE 0x00
#define SIG_HMAC 0x01
#define SIG_RSA 0x02

#define FLAG_RESTART 0x01
#define FLAG_SYNC_MODE 0x02
#define FLAG_SYNC_PREVIEW 0x04
#define FLAG_ANNOUNCE_RESERVED 0xF8

#define FLAG_PARTIAL 0x01
#define FLAG_INFOACK_RESERVED 0xFE

#define FLAG_CURRENT_FILE 0x01
#define FLAG_ABORT_RESERVED 0xFE

#define COMP_STAT_NORMAL 0
#define COMP_STAT_SKIPPED 1
#define COMP_STAT_OVERWRITE 2
#define COMP_STAT_REJECTED 3

#define HB_AUTH_FAILED 0
#define HB_AUTH_OK 1
#define HB_AUTH_CHALLENGE 2

#define PUBKEY_LEN 256  /* big enough for RSA-2048 */
#define RAND_LEN 32     /* rfc 5246 */
#define HMAC_LEN 32     /* big enough for SHA-256 */
#define VERIFY_LEN 12   /* rfc 5246 */
#define MASTER_LEN 48   /* rfc 5246 */
#define MAXIV 16        /* big enough for AES256 */
#define MAXKEY 32       /* big enough for AES256 */
#define KEYBLSIZE 16    /* Maximum symetric key blocksize */
#define DEF_RSA_LEN 512 /* Default length of generated RSA keys */
#define RSA_EXP 65537   /* Public key exponent of generated RSA keys */

#define UFTP_LEN 16
#define ANNOUNCE_LEN 64
#define REGISTER_LEN 40
#define CLIENT_KEY_LEN 12
#define REG_CONF_LEN 4
#define FILEINFO_LEN 324
#define FILEINFO_30_LEN 320
#define KEYINFO_LEN 12
#define DESTKEY_LEN 52
#define INFO_ACK_LEN 20
#define FILESEG_LEN 12
#define DONE_LEN 8
#define STATUS_LEN 12
#define PRSTATUS_LEN 12
#define COMPLETE_LEN 8
#define DONE_CONF_LEN 8
#define HB_REQ_LEN 16
#define HB_RESP_LEN 8
#define KEY_REQ_LEN 4
#define PROXY_KEY_LEN 16
#define ENCRYPTED_LEN 12
#define ABORT_LEN 308

void proto_register_uftp(void);
void proto_reg_handoff_uftp(void);

static int proto_uftp = -1;
static int uftp_port = 1044;

/* main header and common fields */
static int hf_uftp_version = -1;
static int hf_uftp_func = -1;
static int hf_uftp_blsize = -1;
static int hf_uftp_group_id = -1;
static int hf_uftp_srcaddr = -1;
static int hf_uftp_destaddr = -1;

static int hf_uftp_destlist = -1;
static int hf_uftp_dest = -1;

/* ANNOUNCE fields */
static int hf_uftp_announce = -1;
static int hf_uftp_announce_func = -1;
static int hf_uftp_announce_flags = -1;
static int hf_uftp_announce_flags_restart = -1;
static int hf_uftp_announce_flags_sync = -1;
static int hf_uftp_announce_flags_syncpreview = -1;
static int hf_uftp_announce_flags_reserved = -1;
static int hf_uftp_announce_destcount = -1;
static int hf_uftp_announce_announce_int = -1;
static int hf_uftp_announce_status_int = -1;
static int hf_uftp_announce_register_int = -1;
static int hf_uftp_announce_done_int = -1;
static int hf_uftp_announce_announce_time = -1;
static int hf_uftp_announce_status_time = -1;
static int hf_uftp_announce_mtu = -1;
static int hf_uftp_announce_privatemcast = -1;
static int hf_uftp_announce_client_auth = -1;
static int hf_uftp_announce_sigtype = -1;
static int hf_uftp_announce_hashtype = -1;
static int hf_uftp_announce_keytype = -1;
static int hf_uftp_announce_keylen = -1;
static int hf_uftp_announce_reserved = -1;
static int hf_uftp_announce_keyexp = -1;
static int hf_uftp_announce_rand1 = -1;
static int hf_uftp_announce_keymod = -1;

/* REGISTER fields */
static int hf_uftp_register = -1;
static int hf_uftp_register_func = -1;
static int hf_uftp_register_reserved = -1;
static int hf_uftp_register_destcount = -1;
static int hf_uftp_register_premaster_len = -1;
static int hf_uftp_register_rand2 = -1;
static int hf_uftp_register_premaster = -1;

/* CLIENT_KEY fields */
static int hf_uftp_clientkey = -1;
static int hf_uftp_clientkey_func = -1;
static int hf_uftp_clientkey_reserved = -1;
static int hf_uftp_clientkey_keylen = -1;
static int hf_uftp_clientkey_verifylen = -1;
static int hf_uftp_clientkey_keyexp = -1;
static int hf_uftp_clientkey_keymod = -1;
static int hf_uftp_clientkey_verify = -1;

/* REG_CONF fields */
static int hf_uftp_regconf = -1;
static int hf_uftp_regconf_func = -1;
static int hf_uftp_regconf_reserved = -1;
static int hf_uftp_regconf_destcount = -1;

/* FILEINFO fields */
static int hf_uftp_fileinfo = -1;
static int hf_uftp_fileinfo_func = -1;
static int hf_uftp_fileinfo_ftype = -1;
static int hf_uftp_fileinfo_file_id = -1;
static int hf_uftp_fileinfo_block_total = -1;
static int hf_uftp_fileinfo_section_total = -1;
static int hf_uftp_fileinfo_destcount = -1;
static int hf_uftp_fileinfo_fsize = -1;
static int hf_uftp_fileinfo_ftstamp = -1;
static int hf_uftp_fileinfo_name = -1;

/* KEYINFO fields */
static int hf_uftp_keyinfo = -1;
static int hf_uftp_keyinfo_func = -1;
static int hf_uftp_keyinfo_reserved = -1;
static int hf_uftp_keyinfo_destcount = -1;
static int hf_uftp_keyinfo_groupmaster_len = -1;
static int hf_uftp_keyinfo_tstamp = -1;
static int hf_uftp_keyinfo_destkey = -1;
static int hf_uftp_keyinfo_destaddr = -1;
static int hf_uftp_keyinfo_groupmaster = -1;

/* INFO_ACK fields */
static int hf_uftp_infoack = -1;
static int hf_uftp_infoack_func = -1;
static int hf_uftp_infoack_flags = -1;
static int hf_uftp_infoack_flags_partial = -1;
static int hf_uftp_infoack_flags_reserved = -1;
static int hf_uftp_infoack_file_id = -1;
static int hf_uftp_infoack_destcount = -1;
static int hf_uftp_infoack_reserved = -1;
static int hf_uftp_infoack_verify_data = -1;

/* FILESEG fields */
static int hf_uftp_fileseg = -1;
static int hf_uftp_fileseg_func = -1;
static int hf_uftp_fileseg_reserved1 = -1;
static int hf_uftp_fileseg_file_id = -1;
static int hf_uftp_fileseg_pass = -1;
static int hf_uftp_fileseg_reserved2 = -1;
static int hf_uftp_fileseg_section = -1;
static int hf_uftp_fileseg_seq_num = -1;
static int hf_uftp_fileseg_data = -1;

/* DONE fields */
static int hf_uftp_done = -1;
static int hf_uftp_done_func = -1;
static int hf_uftp_done_pass = -1;
static int hf_uftp_done_section = -1;
static int hf_uftp_done_file_id = -1;
static int hf_uftp_done_destcount = -1;

/* STATUS fields */
static int hf_uftp_status = -1;
static int hf_uftp_status_func = -1;
static int hf_uftp_status_reserved = -1;
static int hf_uftp_status_file_id = -1;
static int hf_uftp_status_pass = -1;
static int hf_uftp_status_seq = -1;
static int hf_uftp_status_section = -1;
static int hf_uftp_status_nak_count = -1;
static int hf_uftp_status_naks = -1;

/* PRSTATUS fields */
static int hf_uftp_prstatus = -1;
static int hf_uftp_prstatus_func = -1;
static int hf_uftp_prstatus_reserved1 = -1;
static int hf_uftp_prstatus_file_id = -1;
static int hf_uftp_prstatus_pass = -1;
static int hf_uftp_prstatus_seq = -1;
static int hf_uftp_prstatus_section = -1;
static int hf_uftp_prstatus_destcount = -1;
static int hf_uftp_prstatus_reserved2 = -1;

/* COMPLETE fields */
static int hf_uftp_complete = -1;
static int hf_uftp_complete_func = -1;
static int hf_uftp_complete_status = -1;
static int hf_uftp_complete_file_id = -1;
static int hf_uftp_complete_destcount = -1;
static int hf_uftp_complete_reserved2 = -1;

/* DONE_CONF fields */
static int hf_uftp_doneconf = -1;
static int hf_uftp_doneconf_func = -1;
static int hf_uftp_doneconf_reserved1 = -1;
static int hf_uftp_doneconf_file_id = -1;
static int hf_uftp_doneconf_destcount = -1;
static int hf_uftp_doneconf_reserved2 = -1;

/* HB_REQ fields */
static int hf_uftp_hbreq = -1;
static int hf_uftp_hbreq_func = -1;
static int hf_uftp_hbreq_reserved = -1;
static int hf_uftp_hbreq_nonce = -1;
static int hf_uftp_hbreq_keylen = -1;
static int hf_uftp_hbreq_siglen = -1;
static int hf_uftp_hbreq_keyexp = -1;
static int hf_uftp_hbreq_keymod = -1;
static int hf_uftp_hbreq_verify = -1;

/* HB_RESP fields */
static int hf_uftp_hbresp = -1;
static int hf_uftp_hbresp_func = -1;
static int hf_uftp_hbresp_authenticated = -1;
static int hf_uftp_hbresp_reserved = -1;
static int hf_uftp_hbresp_nonce = -1;

/* KEY_REQ fields */
static int hf_uftp_keyreq = -1;
static int hf_uftp_keyreq_func = -1;
static int hf_uftp_keyreq_reserved = -1;

/* PROXY_KEY fields */
static int hf_uftp_proxykey = -1;
static int hf_uftp_proxykey_func = -1;
static int hf_uftp_proxykey_reserved = -1;
static int hf_uftp_proxykey_nonce = -1;
static int hf_uftp_proxykey_keylen = -1;
static int hf_uftp_proxykey_siglen = -1;
static int hf_uftp_proxykey_keyexp = -1;
static int hf_uftp_proxykey_keymod = -1;
static int hf_uftp_proxykey_verify = -1;

/* ENCRYPTED fields */
static int hf_uftp_encrypted = -1;
static int hf_uftp_encrypted_tstamp = -1;
static int hf_uftp_encrypted_sig_len = -1;
static int hf_uftp_encrypted_payload_len = -1;
static int hf_uftp_encrypted_signature = -1;
static int hf_uftp_encrypted_payload = -1;

/* ABORT fields */
static int hf_uftp_abort = -1;
static int hf_uftp_abort_func = -1;
static int hf_uftp_abort_flags = -1;
static int hf_uftp_abort_flags_curfile = -1;
static int hf_uftp_abort_flags_reserved = -1;
static int hf_uftp_abort_reserved = -1;
static int hf_uftp_abort_host = -1;
static int hf_uftp_abort_message = -1;

static gint ett_uftp = -1;
static gint ett_uftp_announce = -1;
static gint ett_uftp_register = -1;
static gint ett_uftp_clientkey = -1;
static gint ett_uftp_regconf = -1;
static gint ett_uftp_fileinfo = -1;
static gint ett_uftp_keyinfo = -1;
static gint ett_uftp_infoack = -1;
static gint ett_uftp_fileseg = -1;
static gint ett_uftp_done = -1;
static gint ett_uftp_status = -1;
static gint ett_uftp_prstatus = -1;
static gint ett_uftp_complete = -1;
static gint ett_uftp_doneconf = -1;
static gint ett_uftp_hbreq = -1;
static gint ett_uftp_hbresp = -1;
static gint ett_uftp_keyreq = -1;
static gint ett_uftp_proxykey = -1;
static gint ett_uftp_encrypted = -1;
static gint ett_uftp_abort = -1;

static gint ett_uftp_announce_flags = -1;
static gint ett_uftp_keyinfo_destkey = -1;
static gint ett_uftp_infoack_flags = -1;
static gint ett_uftp_abort_flags = -1;

static gint ett_uftp_destlist = -1;

static expert_field ei_uftp_length_invalid = EI_INIT;
static expert_field ei_uftp_func_unknown = EI_INIT;

static dissector_handle_t uftp4_handle;

static const value_string messages[] = {
    { ANNOUNCE,   "ANNOUNCE" },
    { REGISTER,   "REGISTER" },
    { CLIENT_KEY, "CLIENT_KEY" },
    { REG_CONF,   "REG_CONF" },
    { FILEINFO,   "FILEINFO" },
    { KEYINFO,    "KEYINFO" },
    { INFO_ACK,   "INFO_ACK" },
    { FILESEG,    "FILESEG" },
    { DONE,       "DONE" },
    { STATUS,     "STATUS" },
    { PRSTATUS,   "PRSTATUS" },
    { COMPLETE,   "COMPLETE" },
    { DONE_CONF,  "DONE_CONF" },
    { HB_REQ,     "HB_REQ" },
    { HB_RESP,    "HB_RESP" },
    { KEY_REQ,    "KEY_REQ" },
    { PROXY_KEY,  "PROXY_KEY" },
    { ENCRYPTED,  "ENCRYPTED" },
    { ABORT,      "ABORT" },
    { 0, NULL }
};

static const value_string signature_types[] = {
    { SIG_NONE, "NONE" },
    { SIG_HMAC, "HMAC" },
    { SIG_RSA,  "RSA" },
    { 0, NULL }
};

static const value_string hash_types[] = {
    { HASH_NONE,   "NONE" },
    { HASH_MD5,    "MD5" },
    { HASH_SHA1,   "SHA-1" },
    { HASH_SHA256, "SHA-256" },
    { 0, NULL }
};

static const value_string key_types[] = {
    { KEY_NONE,     "NONE" },
    { KEY_DES,      "DES" },
    { KEY_DES_EDE3, "3 Key Triple DES" },
    { KEY_AES128,   "AES-128" },
    { KEY_AES256,   "AES-256" },
    { 0, NULL }
};

static const value_string hb_auth_types[] = {
    { HB_AUTH_FAILED,    "Authorization Failed" },
    { HB_AUTH_OK,        "Authorization Succeeded" },
    { HB_AUTH_CHALLENGE, "Authorization Required" },
    { 0, NULL }
};

static const value_string file_types[] = {
    { FTYPE_REG,  "Regular file" },
    { FTYPE_DIR,  "Directory" },
    { FTYPE_LINK, "Symbolic link" },
    { 0, NULL }
};

static const int *announce_flags[] = {
    &hf_uftp_announce_flags_restart,
    &hf_uftp_announce_flags_sync,
    &hf_uftp_announce_flags_syncpreview,
    &hf_uftp_announce_flags_reserved,
    NULL
};

static const int *infoack_flags[] = {
    &hf_uftp_infoack_flags_partial,
    &hf_uftp_infoack_flags_reserved,
    NULL
};

static const int *abort_flags[] = {
    &hf_uftp_abort_flags_curfile,
    &hf_uftp_abort_flags_reserved,
    NULL
};

static const value_string comp_status[] = {
    { COMP_STAT_NORMAL,     "Normal" },
    { COMP_STAT_SKIPPED,    "Skipped" },
    { COMP_STAT_OVERWRITE,  "Overwrite" },
    { COMP_STAT_REJECTED,   "Rejected" },
    { 0, NULL }
};

static void dissect_uftp_announce(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *announce_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 destcount, keylen, idx;

    if (tvb_reported_length(tvb) < ANNOUNCE_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 2);
    keylen = tvb_get_ntohs(tvb, 24);
    if ((gint)tvb_reported_length(tvb) < ANNOUNCE_LEN + keylen + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, keylen = %d, count=%d",
                            tvb_reported_length(tvb), keylen, destcount);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_announce, tvb, offset, -1, ENC_NA);
    announce_tree = proto_item_add_subtree(ti, ett_uftp_announce);
    proto_tree_add_item(announce_tree, hf_uftp_announce_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(announce_tree, tvb, offset, hf_uftp_announce_flags, ett_uftp_announce_flags, announce_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_announce_int, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_status_int, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_register_int, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_done_int, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_announce_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_status_time, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_mtu, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_privatemcast, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(announce_tree, hf_uftp_announce_client_auth, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_sigtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_hashtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_keytype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_keylen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_keyexp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(announce_tree, hf_uftp_announce_rand1, tvb, offset, RAND_LEN, ENC_NA);
    offset += RAND_LEN;
    if (keylen > 0) {
        proto_tree_add_item(announce_tree, hf_uftp_announce_keymod, tvb, offset, keylen, ENC_NA);
        offset += keylen;
    }
    if (destcount > 0) {
        destlist = proto_tree_add_item(announce_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_register(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *register_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 destcount, keylen, idx;

    if (tvb_reported_length(tvb) < REGISTER_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 4);
    keylen = tvb_get_ntohs(tvb, 6);
    if ((gint)tvb_reported_length(tvb) < REGISTER_LEN + keylen + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, keylen = %d, count=%d",
                            tvb_reported_length(tvb), keylen, destcount);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_register, tvb, offset, -1, ENC_NA);
    register_tree = proto_item_add_subtree(ti, ett_uftp_register);
    proto_tree_add_item(register_tree, hf_uftp_register_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(register_tree, hf_uftp_register_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(register_tree, hf_uftp_register_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(register_tree, hf_uftp_register_premaster_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(register_tree, hf_uftp_register_rand2, tvb, offset, RAND_LEN, ENC_NA);
    offset += RAND_LEN;
    if (keylen > 0) {
        proto_tree_add_item(register_tree, hf_uftp_register_premaster, tvb, offset, keylen, ENC_NA);
        offset += keylen;
    }
    if (destcount > 0) {
        destlist = proto_tree_add_item(register_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_clientkey(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *clientkey_tree = NULL;
    gint offset = 0;
    guint16 keylen, verifylen;

    if (tvb_reported_length(tvb) < CLIENT_KEY_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    keylen = tvb_get_ntohs(tvb, 4);
    verifylen = tvb_get_ntohs(tvb, 6);
    if ((gint)tvb_reported_length(tvb) < CLIENT_KEY_LEN + keylen + verifylen) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, keylen=%d verifylen=%d",
                            tvb_reported_length(tvb), keylen, verifylen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_clientkey, tvb, offset, -1, ENC_NA);
    clientkey_tree = proto_item_add_subtree(ti, ett_uftp_clientkey);
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_keylen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_verifylen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_keyexp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (keylen > 0) {
        proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_keymod, tvb, offset, keylen, ENC_NA);
        offset += keylen;
    }
    if (verifylen > 0) {
        proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_verify, tvb, offset, verifylen, ENC_NA);
    }
}

static void dissect_uftp_regconf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *regconf_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 destcount, idx;

    if (tvb_reported_length(tvb) < REG_CONF_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 2);
    if ((gint)tvb_reported_length(tvb) < REG_CONF_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_regconf, tvb, offset, -1, ENC_NA);
    regconf_tree = proto_item_add_subtree(ti, ett_uftp_regconf);
    proto_tree_add_item(regconf_tree, hf_uftp_regconf_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(regconf_tree, hf_uftp_regconf_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(regconf_tree, hf_uftp_regconf_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (destcount > 0) {
        destlist = proto_tree_add_item(regconf_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_fileinfo_30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *fileinfo_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 file_id, destcount, idx;

    if (tvb_reported_length(tvb) < FILEINFO_30_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 10);
    if ((gint)tvb_reported_length(tvb) < FILEINFO_30_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X", file_id);

    ti = proto_tree_add_item(tree, hf_uftp_fileinfo, tvb, offset, -1, ENC_NA);
    fileinfo_tree = proto_item_add_subtree(ti, ett_uftp_fileinfo);
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_ftype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_block_total, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_section_total, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_fsize, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_name, tvb, offset, MAXPATHNAME, ENC_ASCII|ENC_NA);
    offset += MAXPATHNAME;
    if (destcount > 0) {
        destlist = proto_tree_add_item(fileinfo_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_fileinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *fileinfo_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 file_id, destcount, idx;

    if (tvb_reported_length(tvb) < FILEINFO_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 10);
    if ((gint)tvb_reported_length(tvb) < FILEINFO_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X", file_id);

    ti = proto_tree_add_item(tree, hf_uftp_fileinfo, tvb, offset, -1, ENC_NA);
    fileinfo_tree = proto_item_add_subtree(ti, ett_uftp_fileinfo);
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_ftype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_block_total, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_section_total, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_fsize, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_ftstamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_name, tvb, offset, MAXPATHNAME, ENC_ASCII|ENC_NA);
    offset += MAXPATHNAME;
    if (destcount > 0) {
        destlist = proto_tree_add_item(fileinfo_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_keyinfo(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_item *destkey = NULL;
    proto_tree *keyinfo_tree = NULL;
    proto_tree *destlist_tree = NULL;
    proto_tree *destkey_tree = NULL;
    gint offset = 0;
    guint8 destcount, idx;

    if (tvb_reported_length(tvb) < KEYINFO_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_guint8(tvb, 2);
    if ((gint)tvb_reported_length(tvb) < KEYINFO_LEN + (destcount * DESTKEY_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_keyinfo, tvb, offset, -1, ENC_NA);
    keyinfo_tree = proto_item_add_subtree(ti, ett_uftp_keyinfo);
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_destcount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_groupmaster_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_tstamp, tvb, offset, 8, FALSE);
    offset += 8;
    if (destcount > 0) {
        destlist = proto_tree_add_item(keyinfo_tree, hf_uftp_destlist, tvb, offset, destcount * DESTKEY_LEN, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        destkey = proto_tree_add_item(destlist_tree, hf_uftp_keyinfo_destkey, tvb, offset, DESTKEY_LEN, ENC_NA);
        destkey_tree = proto_item_add_subtree(destkey, ett_uftp_keyinfo_destkey);
        proto_tree_add_item(destkey_tree, hf_uftp_keyinfo_destaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(destkey_tree, hf_uftp_keyinfo_groupmaster, tvb, offset, 48, ENC_NA);
        offset += 48;
    }
}

static void dissect_uftp_infoack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *infoack_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 file_id, destcount, idx;

    if (tvb_reported_length(tvb) < INFO_ACK_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 4);
    if ((gint)tvb_reported_length(tvb) < INFO_ACK_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    if (file_id > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X", file_id);
    }

    ti = proto_tree_add_item(tree, hf_uftp_infoack, tvb, offset, -1, ENC_NA);
    infoack_tree = proto_item_add_subtree(ti, ett_uftp_infoack);
    proto_tree_add_item(infoack_tree, hf_uftp_infoack_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(infoack_tree, tvb, offset, hf_uftp_infoack_flags, ett_uftp_infoack_flags, infoack_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(infoack_tree, hf_uftp_infoack_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(infoack_tree, hf_uftp_infoack_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(infoack_tree, hf_uftp_infoack_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(infoack_tree, hf_uftp_infoack_verify_data, tvb, offset, VERIFY_LEN, ENC_NA);
    offset += VERIFY_LEN;
    if (destcount > 0) {
        destlist = proto_tree_add_item(infoack_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_fileseg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *fileseg_tree = NULL;
    gint offset = 0;
    guint8 pass;
    guint16 file_id;
    guint32 seq_num;

    if (tvb_reported_length(tvb) < FILESEG_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    pass = tvb_get_guint8(tvb, 4);
    seq_num = tvb_get_ntohl(tvb, 8);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X  Pass=%d  Seq=%d",
                    file_id, pass, seq_num);

    ti = proto_tree_add_item(tree, hf_uftp_fileseg, tvb, offset, -1, ENC_NA);
    fileseg_tree = proto_item_add_subtree(ti, ett_uftp_fileseg);
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_pass, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_section, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_seq_num, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_data, tvb, offset, -1, ENC_NA);
}

static void dissect_uftp_done(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *done_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint8 pass;
    guint16 file_id, section, destcount, idx;

    if (tvb_reported_length(tvb) < DONE_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 6);
    if ((gint)tvb_reported_length(tvb) < DONE_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    pass = tvb_get_guint8(tvb, 1);
    section = tvb_get_ntohs(tvb, 2);
    file_id = tvb_get_ntohs(tvb, 4);
    if (file_id > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X  Pass=%d  Section=%d",
                        file_id, pass, section);
    }

    ti = proto_tree_add_item(tree, hf_uftp_done, tvb, offset, -1, ENC_NA);
    done_tree = proto_item_add_subtree(ti, ett_uftp_done);
    proto_tree_add_item(done_tree, hf_uftp_done_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(done_tree, hf_uftp_done_pass, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(done_tree, hf_uftp_done_section, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(done_tree, hf_uftp_done_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(done_tree, hf_uftp_done_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (destcount > 0) {
        destlist = proto_tree_add_item(done_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *status_tree = NULL;
    gint offset = 0;
    guint8 pass, seq;
    guint16 file_id, section;
    guint32 nak_count;

    if (tvb_reported_length(tvb) < STATUS_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    section = tvb_get_ntohs(tvb, 2);
    pass = tvb_get_guint8(tvb, 4);
    seq = tvb_get_guint8(tvb, 5);
    nak_count = tvb_get_ntohl(tvb, 8);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X  Pass=%d  Section=%d Seq=%d",
                    file_id, pass, section, seq);

    ti = proto_tree_add_item(tree, hf_uftp_status, tvb, offset, -1, ENC_NA);
    status_tree = proto_item_add_subtree(ti, ett_uftp_status);
    proto_tree_add_item(status_tree, hf_uftp_status_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(status_tree, hf_uftp_status_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(status_tree, hf_uftp_status_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(status_tree, hf_uftp_status_pass, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(status_tree, hf_uftp_status_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(status_tree, hf_uftp_status_section, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(status_tree, hf_uftp_status_nak_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (nak_count > 0) {
        proto_tree_add_item(status_tree, hf_uftp_status_naks, tvb, offset, -1, ENC_NA);
    }
}

static void dissect_uftp_prstatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *prstatus_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint8 pass, seq;
    guint16 file_id, destcount, idx, section;
    guint32 nak_count;

    if (tvb_reported_length(tvb) < PRSTATUS_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 8);
    if ((gint)tvb_reported_length(tvb) < PRSTATUS_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    section = tvb_get_ntohs(tvb, 2);
    pass = tvb_get_guint8(tvb, 4);
    seq = tvb_get_guint8(tvb, 5);
    nak_count = tvb_get_ntohl(tvb, 8);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X  Pass=%d Section=%d Seq=%d "
                    "NAKs=%d", file_id, pass, section, seq, nak_count);

    ti = proto_tree_add_item(tree, hf_uftp_prstatus, tvb, offset, -1, ENC_NA);
    prstatus_tree = proto_item_add_subtree(ti, ett_uftp_prstatus);
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_pass, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_section, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(prstatus_tree, hf_uftp_prstatus_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (destcount > 0) {
        destlist = proto_tree_add_item(prstatus_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *complete_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 file_id, destcount, idx;

    if (tvb_reported_length(tvb) < COMPLETE_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 4);
    if ((gint)tvb_reported_length(tvb) < COMPLETE_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    if (file_id > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X", file_id);
    }

    ti = proto_tree_add_item(tree, hf_uftp_complete, tvb, offset, -1, ENC_NA);
    complete_tree = proto_item_add_subtree(ti, ett_uftp_complete);
    proto_tree_add_item(complete_tree, hf_uftp_complete_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(complete_tree, hf_uftp_complete_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(complete_tree, hf_uftp_complete_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(complete_tree, hf_uftp_complete_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(complete_tree, hf_uftp_complete_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (destcount > 0) {
        destlist = proto_tree_add_item(complete_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_doneconf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *doneconf_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    guint16 file_id, destcount, idx;

    if (tvb_reported_length(tvb) < DONE_CONF_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    destcount = tvb_get_ntohs(tvb, 4);
    if ((gint)tvb_reported_length(tvb) < DONE_CONF_LEN + (destcount * 4)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, count=%d",
                            tvb_reported_length(tvb), destcount);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    if (file_id > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X", file_id);
    }

    ti = proto_tree_add_item(tree, hf_uftp_doneconf, tvb, offset, -1, ENC_NA);
    doneconf_tree = proto_item_add_subtree(ti, ett_uftp_doneconf);
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_destcount, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (destcount > 0) {
        destlist = proto_tree_add_item(doneconf_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_hbreq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *hbreq_tree = NULL;
    gint offset = 0;
    guint16 keylen, siglen;

    if (tvb_reported_length(tvb) < HB_REQ_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    keylen = tvb_get_ntohs(tvb, 8);
    siglen = tvb_get_ntohs(tvb, 10);
    if ((gint)tvb_reported_length(tvb) < HB_REQ_LEN + keylen + siglen) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, keylen=%d siglen=%d",
                            tvb_reported_length(tvb), keylen, siglen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_hbreq, tvb, offset, -1, ENC_NA);
    hbreq_tree = proto_item_add_subtree(ti, ett_uftp_hbreq);
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_keylen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_siglen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_keyexp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (keylen > 0) {
        proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_keymod, tvb, offset, keylen, ENC_NA);
        offset += keylen;
    }
    if (siglen > 0) {
        proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_verify, tvb, offset, siglen, ENC_NA);
    }
}

static void dissect_uftp_hbresp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *hbresp_tree = NULL;
    gint offset = 0;

    if (tvb_reported_length(tvb) < HB_RESP_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_hbresp, tvb, offset, -1, ENC_NA);
    hbresp_tree = proto_item_add_subtree(ti, ett_uftp_hbresp);
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_authenticated, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void dissect_uftp_keyreq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *keyreq_tree = NULL;
    gint offset = 0;

    if (tvb_reported_length(tvb) < KEY_REQ_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_keyreq, tvb, offset, -1, ENC_NA);
    keyreq_tree = proto_item_add_subtree(ti, ett_uftp_keyreq);
    proto_tree_add_item(keyreq_tree, hf_uftp_keyreq_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyreq_tree, hf_uftp_keyreq_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
}

static void dissect_uftp_proxykey(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *proxykey_tree = NULL;
    gint offset = 0;
    guint16 keylen, siglen;

    if (tvb_reported_length(tvb) < PROXY_KEY_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    keylen = tvb_get_ntohs(tvb, 8);
    siglen = tvb_get_ntohs(tvb, 10);
    if ((gint)tvb_reported_length(tvb) < PROXY_KEY_LEN + keylen + siglen) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, keylen=%d siglen=%d",
                            tvb_reported_length(tvb), keylen, siglen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_proxykey, tvb, offset, -1, ENC_NA);
    proxykey_tree = proto_item_add_subtree(ti, ett_uftp_proxykey);
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_keylen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_siglen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_keyexp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (keylen > 0) {
        proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_keymod, tvb, offset, keylen, ENC_NA);
        offset += keylen;
    }
    if (siglen > 0) {
        proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_verify, tvb, offset, siglen, ENC_NA);
    }
}

static void dissect_uftp_encrypted(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *encrypted_tree = NULL;
    gint offset = 0;
    guint16 sig_len, payload_len;

    if (tvb_reported_length(tvb) < ENCRYPTED_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    sig_len = tvb_get_ntohs(tvb, 8);
    payload_len = tvb_get_ntohs(tvb, 10);
    if ((gint)tvb_reported_length(tvb) < ENCRYPTED_LEN + sig_len + payload_len) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, sig=%d, payload=%d",
                            tvb_reported_length(tvb), sig_len, payload_len);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_encrypted, tvb, offset, -1, ENC_NA);
    encrypted_tree = proto_item_add_subtree(ti, ett_uftp_encrypted);
    proto_tree_add_item(encrypted_tree, hf_uftp_encrypted_tstamp, tvb, offset, 8, FALSE);
    offset += 8;
    proto_tree_add_item(encrypted_tree, hf_uftp_encrypted_sig_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(encrypted_tree, hf_uftp_encrypted_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(encrypted_tree, hf_uftp_encrypted_signature, tvb, offset, sig_len, ENC_NA);
    offset += sig_len;
    proto_tree_add_item(encrypted_tree, hf_uftp_encrypted_payload, tvb, offset, payload_len, ENC_NA);
}

static void dissect_uftp_abort(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *abort_tree = NULL;
    gint offset = 0;

    if (tvb_reported_length(tvb) < ABORT_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_abort, tvb, offset, -1, ENC_NA);
    abort_tree = proto_item_add_subtree(ti, ett_uftp_abort);
    proto_tree_add_item(abort_tree, hf_uftp_abort_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(abort_tree, tvb, offset, hf_uftp_abort_flags, ett_uftp_abort_flags, abort_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(abort_tree, hf_uftp_abort_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(abort_tree, hf_uftp_abort_host, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(abort_tree, hf_uftp_abort_message, tvb, offset, -1, ENC_ASCII|ENC_NA);
}

static int dissect_uftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 version;
    guint8 mes_type;
    guint32 group_id;
    guint16 blsize;
    tvbuff_t *next_tvb;
    proto_item *ti = NULL;
    proto_tree *uftp_tree = NULL;
    gint offset = 0;

    version = tvb_get_guint8(tvb, 0);
    if (version == 0x40) {
        return call_dissector(uftp4_handle, tvb, pinfo, tree);
    } else if (version != UFTP_VER_NUM && version != UFTP_3_0_VER) {
        return 0;
    }

    if (tvb_reported_length(tvb) < UFTP_LEN) {
        return 0;
    }

    mes_type = tvb_get_guint8(tvb, 1);
    blsize = tvb_get_ntohs(tvb, 2);
    group_id = tvb_get_ntohl(tvb, 4);

    if (tvb_reported_length(tvb) != (unsigned)UFTP_LEN + blsize) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UFTP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%-10s",
                 val_to_str(mes_type, messages, "Unknown (%d)"));
    if ((mes_type != HB_REQ) && (mes_type != HB_RESP)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " ID=%08X", group_id);
    }

    ti = proto_tree_add_item(tree, proto_uftp, tvb, 0, -1, ENC_NA);
    uftp_tree = proto_item_add_subtree(ti, ett_uftp);
    proto_tree_add_item(uftp_tree, hf_uftp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(uftp_tree, hf_uftp_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(uftp_tree, hf_uftp_blsize, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(uftp_tree, hf_uftp_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(uftp_tree, hf_uftp_srcaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(uftp_tree, hf_uftp_destaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    next_tvb = tvb_new_subset(tvb, offset, -1, blsize);

    switch (mes_type) {
        case ANNOUNCE:
            dissect_uftp_announce(next_tvb, pinfo, uftp_tree);
            break;
        case REGISTER:
            dissect_uftp_register(next_tvb, pinfo, uftp_tree);
            break;
        case CLIENT_KEY:
            dissect_uftp_clientkey(next_tvb, pinfo, uftp_tree);
            break;
        case REG_CONF:
            dissect_uftp_regconf(next_tvb, pinfo, uftp_tree);
            break;
        case FILEINFO:
            if (version == UFTP_3_0_VER) {
                dissect_uftp_fileinfo_30(next_tvb, pinfo, uftp_tree);
            } else {
                dissect_uftp_fileinfo(next_tvb, pinfo, uftp_tree);
            }
            break;
        case KEYINFO:
            dissect_uftp_keyinfo(next_tvb, pinfo, uftp_tree);
            break;
        case INFO_ACK:
            dissect_uftp_infoack(next_tvb, pinfo, uftp_tree);
            break;
        case FILESEG:
            dissect_uftp_fileseg(next_tvb, pinfo, uftp_tree);
            break;
        case DONE:
            dissect_uftp_done(next_tvb, pinfo, uftp_tree);
            break;
        case STATUS:
            dissect_uftp_status(next_tvb, pinfo, uftp_tree);
            break;
        case PRSTATUS:
            dissect_uftp_prstatus(next_tvb, pinfo, uftp_tree);
            break;
        case COMPLETE:
            dissect_uftp_complete(next_tvb, pinfo, uftp_tree);
            break;
        case DONE_CONF:
            dissect_uftp_doneconf(next_tvb, pinfo, uftp_tree);
            break;
        case HB_REQ:
            dissect_uftp_hbreq(next_tvb, pinfo, uftp_tree);
            break;
        case HB_RESP:
            dissect_uftp_hbresp(next_tvb, pinfo, uftp_tree);
            break;
        case KEY_REQ:
            dissect_uftp_keyreq(next_tvb, pinfo, uftp_tree);
            break;
        case PROXY_KEY:
            dissect_uftp_proxykey(next_tvb, pinfo, uftp_tree);
            break;
        case ENCRYPTED:
            dissect_uftp_encrypted(next_tvb, pinfo, uftp_tree);
            break;
        case ABORT:
            dissect_uftp_abort(next_tvb, pinfo, uftp_tree);
            break;
        default:
            proto_tree_add_expert_format(tree, pinfo, &ei_uftp_func_unknown, tvb, offset, -1,
                        "Function unknown: %d", mes_type);
            break;
    }

    return tvb_reported_length(tvb);
}

void proto_register_uftp(void)
{
    static hf_register_info hf[] = {
        { &hf_uftp_version,
            { "Protocol Version", "uftp.version",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_func,
            { "Type", "uftp.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_blsize,
            { "Block Size", "uftp.blsize",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_group_id,
            { "Group ID", "uftp.group_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_srcaddr,
            { "Source Address", "uftp.srcaddr",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_destaddr,
            { "Destination Address", "uftp.destaddr",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_destlist,
            { "Destination List", "uftp.destlist",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_dest,
            { "Destination", "uftp.dest",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce,
            { "ANNOUNCE", "uftp.announce",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_func,
            { "Type", "uftp.announce.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_flags,
            { "Flags", "uftp.announce.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_restart,
            { "Restart", "uftp.announce.flags.restart",
            FT_BOOLEAN, 8, NULL, FLAG_RESTART, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_sync,
            { "Sync mode", "uftp.announce.flags.sync",
            FT_BOOLEAN, 8, NULL, FLAG_SYNC_MODE, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_syncpreview,
            { "Sync preview mode", "uftp.announce.flags.syncpreview",
            FT_BOOLEAN, 8, NULL, FLAG_SYNC_PREVIEW, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_reserved,
            { "Reserved", "uftp.announce.flags.reserved",
            FT_BOOLEAN, 8, NULL, FLAG_ANNOUNCE_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_announce_destcount,
            { "Destination Count", "uftp.announce.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_announce_int,
            { "Announce Interval", "uftp.announce.announce_int",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_status_int,
            { "Status Interval", "uftp.announce.status_int",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_register_int,
            { "Register Interval", "uftp.announce.register_int",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_done_int,
            { "Done Interval", "uftp.announce.done_int",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_announce_time,
            { "Announce Time", "uftp.announce.announce_time",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_status_time,
            { "Status Time", "uftp.announce.status_time",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_mtu,
            { "MTU", "uftp.announce.mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_privatemcast,
            { "Private Multicast Address", "uftp.announce.privatemcast",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_client_auth,
            { "Client Auth", "uftp.announce.client_auth",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_sigtype,
            { "Signature Type", "uftp.announce.sigtype",
            FT_UINT8, BASE_DEC, VALS(signature_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_hashtype,
            { "Hash Type", "uftp.announce.hashtype",
            FT_UINT8, BASE_DEC, VALS(hash_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_keytype,
            { "Key Type", "uftp.announce.keytype",
            FT_UINT8, BASE_DEC, VALS(key_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_keylen,
            { "Public Key Length", "uftp.announce.keylen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_reserved,
            { "Reserved", "uftp.announce.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_keyexp,
            { "Public Key Exponent", "uftp.announce.keyexp",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_rand1,
            { "Server Random Number", "uftp.announce.rand1",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_keymod,
            { "Public Key Modulus", "uftp.announce.keymod",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register,
            { "REGISTER", "uftp.register",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_func,
            { "Type", "uftp.register.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_reserved,
            { "Reserved", "uftp.register.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_destcount,
            { "Destination Count", "uftp.register.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_premaster_len,
            { "Premaster Secret Length", "uftp.register.premaster_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_rand2,
            { "Client Random Number", "uftp.register.rand2",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_premaster,
            { "Encrypted Premaster Secret", "uftp.register.premaster",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey,
            { "CLIENT_KEY", "uftp.clientkey",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_func,
            { "Type", "uftp.clientkey.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_reserved,
            { "Reserved", "uftp.clientkey.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_keylen,
            { "Key Length", "uftp.clientkey.keylen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_verifylen,
            { "Signature Length", "uftp.clientkey.verifylen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_keyexp,
            { "Public Key Exponent", "uftp.clientkey.keyexp",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_keymod,
            { "Public Key Modulus", "uftp.clientkey.keymod",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_verify,
            { "Signature", "uftp.clientkey.verify",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf,
            { "REG_CONF", "uftp.regconf",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf_func,
            { "Type", "uftp.regconf.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf_reserved,
            { "Reserved", "uftp.regconf.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf_destcount,
            { "Destination Count", "uftp.regconf.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo,
            { "FILEINFO", "uftp.fileinfo",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_func,
            { "Type", "uftp.fileinfo.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_ftype,
            { "File Type", "uftp.fileinfo.ftype",
            FT_UINT8, BASE_DEC, VALS(file_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_file_id,
            { "File ID", "uftp.fileinfo.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_block_total,
            { "Total Blocks", "uftp.fileinfo.block_total",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_section_total,
            { "Total Sections", "uftp.fileinfo.section_total",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_destcount,
            { "Destination Count", "uftp.fileinfo.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_fsize,
            { "File Size", "uftp.fileinfo.fsize",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_ftstamp,
            { "File Timestamp", "uftp.fileinfo.tstamp",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_name,
            { "File Name", "uftp.fileinfo.name",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo,
            { "KEYINFO", "uftp.keyinfo",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_func,
            { "Type", "uftp.keyinfo.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_reserved,
            { "Reserved", "uftp.keyinfo.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_destcount,
            { "Destination Count", "uftp.keyinfo.destcount",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_groupmaster_len,
            { "Group Master Length", "uftp.keyinfo.groupmaster_len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_tstamp,
            { "Timestamp", "uftp.keyinfo.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_destkey,
            { "Destination Key", "uftp.keyinfo.destkey",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_destaddr,
            { "Destination Address", "uftp.keyinfo.destaddr",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_groupmaster,
            { "Encrypted Group Master", "uftp.keyinfo.groupmaster",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_infoack,
            { "INFO_ACK", "uftp.infoack",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_infoack_func,
            { "Type", "uftp.infoack.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_infoack_flags,
            { "Flags", "uftp.infoack.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_infoack_flags_partial,
            { "Partial", "uftp.infoack.flags.partial",
            FT_BOOLEAN, 8, NULL, FLAG_PARTIAL, NULL, HFILL }
        },
        { &hf_uftp_infoack_flags_reserved,
            { "Reserved", "uftp.infoack.flags.reserved",
            FT_BOOLEAN, 8, NULL, FLAG_INFOACK_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_infoack_file_id,
            { "File ID", "uftp.infoack.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_infoack_destcount,
            { "Destination Count", "uftp.infoack.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_infoack_reserved,
            { "Reserved", "uftp.infoack.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_infoack_verify_data,
            { "Verify Data", "uftp.infoack.verify_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg,
            { "FILESEG", "uftp.fileseg",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_func,
            { "Type", "uftp.fileseg.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_reserved1,
            { "Reserved", "uftp.fileseg.reserved1",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_file_id,
            { "File ID", "uftp.fileseg.file_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_pass,
            { "Pass", "uftp.fileseg.pass",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_reserved2,
            { "Reserved", "uftp.fileseg.reserved2",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_section,
            { "Section", "uftp.fileseg.section",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_seq_num,
            { "Sequence Number", "uftp.fileseg.seq_num",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_data,
            { "Data", "uftp.fileseg.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done,
            { "DONE", "uftp.done",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_func,
            { "Type", "uftp.done.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_pass,
            { "Pass", "uftp.done.pass",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_section,
            { "Section", "uftp.done.section",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_file_id,
            { "File ID", "uftp.done.file_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_destcount,
            { "Destination Count", "uftp.done.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status,
            { "STATUS", "uftp.status",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_func,
            { "Type", "uftp.status.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_reserved,
            { "Reserved", "uftp.status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_file_id,
            { "File ID", "uftp.status.file_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_pass,
            { "Pass", "uftp.status.pass",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_seq,
            { "Sequence", "uftp.status.seq",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_section,
            { "Section", "uftp.status.section",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_nak_count,
            { "NAK Count", "uftp.status.nak_count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_naks,
            { "NAKs", "uftp.status.naks",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus,
            { "PRSTATUS", "uftp.prstatus",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_func,
            { "Type", "uftp.prstatus.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_reserved1,
            { "Reserved", "uftp.prstatus.reserved1",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_file_id,
            { "File ID", "uftp.prstatus.file_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_pass,
            { "Pass", "uftp.prstatus.pass",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_seq,
            { "Sequence", "uftp.prstatus.seq",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_section,
            { "Section", "uftp.prstatus.section",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_destcount,
            { "Destination Count", "uftp.prstatus.destcount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_prstatus_reserved2,
            { "Reserved", "uftp.prstatus.reserved2",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete,
            { "COMPLETE", "uftp.complete",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_func,
            { "Type", "uftp.complete.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_status,
            { "Completion status", "uftp.complete.status",
            FT_UINT8, BASE_DEC, VALS(comp_status), 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_file_id,
            { "File ID", "uftp.complete.file_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_destcount,
            { "Destination Count", "uftp.complete.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_reserved2,
            { "Reserved", "uftp.complete.reserved2",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf,
            { "DONE_CONF", "uftp.doneconf",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_func,
            { "Type", "uftp.doneconf.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_reserved1,
            { "Reserved", "uftp.doneconf.reserved1",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_file_id,
            { "File ID", "uftp.doneconf.file_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_destcount,
            { "Destination Count", "uftp.doneconf.destcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_reserved2,
            { "Reserved", "uftp.doneconf.reserved2",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq,
            { "HB_REQ", "uftp.hbreq",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_func,
            { "Type", "uftp.hbreq.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_reserved,
            { "Reserved", "uftp.hbreq.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_nonce,
            { "Nonce", "uftp.hbreq.nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_keylen,
            { "Key Length", "uftp.hbreq.keylen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_siglen,
            { "Signature Length", "uftp.hbreq.siglen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_keyexp,
            { "Public Key Exponent", "uftp.hbreq.keyexp",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_keymod,
            { "Public Key Modulus", "uftp.hbreq.keymod",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_verify,
            { "Signature", "uftp.hbreq.verify",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp,
            { "HB_RESP", "uftp.hbresp",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_func,
            { "Type", "uftp.hbresp.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_authenticated,
            { "Authenticated", "uftp.hbresp.authenticated",
            FT_UINT8, BASE_DEC, VALS(hb_auth_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_reserved,
            { "Reserved", "uftp.hbresp.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_nonce,
            { "Nonce", "uftp.hbresp.nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyreq,
            { "KEY_REQ", "uftp.keyreq",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyreq_func,
            { "Type", "uftp.keyreq.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyreq_reserved,
            { "Reserved", "uftp.keyreq.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey,
            { "PROXY_KEY", "uftp.proxykey",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_func,
            { "Type", "uftp.proxykey.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_reserved,
            { "Reserved", "uftp.proxykey.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_nonce,
            { "Nonce", "uftp.proxykey.nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_keylen,
            { "Key Length", "uftp.proxykey.keylen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_siglen,
            { "Signature Length", "uftp.proxykey.siglen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_keyexp,
            { "Public Key Exponent", "uftp.proxykey.keyexp",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_keymod,
            { "Public Key Modulus", "uftp.proxykey.keymod",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_verify,
            { "Signature", "uftp.proxykey.verify",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted,
            { "ENCRYPTED", "uftp.encrypted",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_tstamp,
            { "Timestamp", "uftp.encrypted.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_sig_len,
            { "Signature Length", "uftp.encrypted.sig_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_payload_len,
            { "Payload Length", "uftp.encrypted.payload_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_signature,
            { "Signature", "uftp.encrypted.signature",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_payload,
            { "Encrypted Payload", "uftp.encrypted.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort,
            { "ABORT", "uftp.abort",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_func,
            { "Type", "uftp.abort.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_flags,
            { "Flags", "uftp.abort.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_flags_curfile,
            { "Current file", "uftp.abort.flags.curfile",
            FT_BOOLEAN, 8, NULL, FLAG_CURRENT_FILE, NULL, HFILL }
        },
        { &hf_uftp_abort_flags_reserved,
            { "Reserved", "uftp.abort.flags.reserved",
            FT_BOOLEAN, 8, NULL, FLAG_ABORT_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_abort_reserved,
            { "Reserved", "uftp.abort.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_host,
            { "Host", "uftp.abort.host",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_message,
            { "Message", "uftp.abort.message",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_uftp,
        &ett_uftp_announce,
        &ett_uftp_register,
        &ett_uftp_clientkey,
        &ett_uftp_regconf,
        &ett_uftp_fileinfo,
        &ett_uftp_keyinfo,
        &ett_uftp_keyinfo_destkey,
        &ett_uftp_infoack,
        &ett_uftp_fileseg,
        &ett_uftp_done,
        &ett_uftp_status,
        &ett_uftp_prstatus,
        &ett_uftp_complete,
        &ett_uftp_doneconf,
        &ett_uftp_hbreq,
        &ett_uftp_hbresp,
        &ett_uftp_keyreq,
        &ett_uftp_proxykey,
        &ett_uftp_encrypted,
        &ett_uftp_abort,
        &ett_uftp_announce_flags,
        &ett_uftp_infoack_flags,
        &ett_uftp_abort_flags,
        &ett_uftp_destlist
    };

    static ei_register_info ei[] = {
        { &ei_uftp_length_invalid, { "uftp.length.invalid", PI_MALFORMED, PI_ERROR, "Length is invalid", EXPFILL }},
        { &ei_uftp_func_unknown, { "uftp.func.invalid", PI_MALFORMED, PI_ERROR, "Unknown function", EXPFILL }}
    };

    expert_module_t* expert_uftp;

    proto_uftp = proto_register_protocol("UDP based FTP w/ multicast",
        "UFTP", "uftp");
    proto_register_field_array(proto_uftp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_uftp = expert_register_protocol(proto_uftp);
    expert_register_field_array(expert_uftp, ei, array_length(ei));
}

void proto_reg_handoff_uftp(void)
{
    static dissector_handle_t uftp_handle;

    uftp4_handle = find_dissector("uftp4");
    uftp_handle = create_dissector_handle(dissect_uftp, proto_uftp);
    dissector_add_uint("udp.port", uftp_port, uftp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
