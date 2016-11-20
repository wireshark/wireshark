/* packet-uftp4.c
 * Routines for UFTP version 4 packet dissection
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
#include <math.h>

#define UFTP_VER_NUM 0x40

#define ANNOUNCE       1
#define REGISTER       2
#define CLIENT_KEY     3
#define REG_CONF       4
#define KEYINFO        5
#define KEYINFO_ACK    6
#define FILEINFO       7
#define FILEINFO_ACK   8
#define FILESEG        9
#define DONE          10
#define STATUS        11
#define COMPLETE      12
#define DONE_CONF     13
#define HB_REQ        14
#define HB_RESP       15
#define KEY_REQ       16
#define PROXY_KEY     17
#define ENCRYPTED     18
#define ABORT         19
#define CONG_CTRL     20
#define CC_ACK        21

#define FTYPE_REG   0
#define FTYPE_DIR   1
#define FTYPE_LINK  2
#define FTYPE_DELETE    3
#define FTYPE_FREESPACE 4

#define KEY_NONE        0
#define KEY_DES         1
#define KEY_DES_EDE3    2
#define KEY_AES128_CBC  3
#define KEY_AES256_CBC  4
#define KEY_AES128_GCM  5
#define KEY_AES256_GCM  6
#define KEY_AES128_CCM  7
#define KEY_AES256_CCM  8

#define HASH_NONE   0
#define HASH_MD5    1
#define HASH_SHA1   2
#define HASH_SHA256 3
#define HASH_SHA384 4
#define HASH_SHA512 5

#define SIG_NONE    0
#define SIG_HMAC    1
#define SIG_KEYEX   2
#define SIG_AUTHENC 3

#define KEYEX_NONE          0
#define KEYEX_RSA           1
#define KEYEX_ECDH_RSA      2
#define KEYEX_ECDH_ECDSA    3

#define KEYBLOB_RSA     1
#define KEYBLOB_EC      2

#define CURVE_sect163k1     1
#define CURVE_sect163r1     2
#define CURVE_sect163r2     3
#define CURVE_sect193r1     4
#define CURVE_sect193r2     5
#define CURVE_sect233k1     6
#define CURVE_sect233r1     7
#define CURVE_sect239k1     8
#define CURVE_sect283k1     9
#define CURVE_sect283r1     10
#define CURVE_sect409k1     11
#define CURVE_sect409r1     12
#define CURVE_sect571k1     13
#define CURVE_sect571r1     14
#define CURVE_secp160k1     15
#define CURVE_secp160r1     16
#define CURVE_secp160r2     17
#define CURVE_secp192k1     18
#define CURVE_secp192r1     19
#define CURVE_secp224k1     20
#define CURVE_secp224r1     21
#define CURVE_secp256k1     22
#define CURVE_secp256r1     23
#define CURVE_secp384r1     24
#define CURVE_secp521r1     25
#define CURVE_prime192v1    CURVE_secp192r1
#define CURVE_prime256v1    CURVE_secp256r1

#define CC_NONE     0
#define CC_UFTP3    1
#define CC_TFMCC    2
#define CC_PGMCC    3

#define EXT_ENC_INFO        1
#define EXT_TFMCC_DATA_INFO 2
#define EXT_TFMCC_ACK_INFO  3

#define EXT_PGMCC_DATA_INFO 4
#define EXT_PGMCC_NAK_INFO  5
#define EXT_PGMCC_ACK_INFO  6

#define EXT_FREESPACE_INFO 7

#define FLAG_SYNC_MODE      0x01
#define FLAG_SYNC_PREVIEW   0x02
#define FLAG_IPV6           0x04
#define FLAG_ANNOUNCE_RESERVED 0xF8

#define FLAG_CLIENT_AUTH    0x01
#define FLAG_ENCINFO_RESERVED 0xFE

#define FLAG_PARTIAL        0x01
#define FLAG_FILEINFOACK_RESERVED 0xFE

#define FLAG_CURRENT_FILE   0x01
#define FLAG_ABORT_RESERVED 0xFE

#define FLAG_CC_CLR         0x01
#define FLAG_CC_RTT         0x02
#define FLAG_CC_START       0x04
#define FLAG_CC_LEAVE       0x08
#define FLAG_CC_RESERVED    0xF0

#define COMP_STAT_NORMAL    0
#define COMP_STAT_SKIPPED   1
#define COMP_STAT_OVERWRITE 2
#define COMP_STAT_REJECTED  3

#define HB_AUTH_FAILED      0
#define HB_AUTH_OK          1
#define HB_AUTH_CHALLENGE   2

#define MAXFILENAME 100
#define MAXDIRNAME 200
#define MAXPATHNAME 300
#define MAXBACKUPPATHNAME 600
#define MAXPROXYDEST 1000
#define MAXDIR 10
#define MAXSECTION 65536

#define DESTNAME_LEN 80
#define IFNAME_LEN 25
#define MAX_INTERFACES 100
#define IPSTR_LEN 16

#define PUBKEY_LEN 256  /* big enough for RSA-2048 */
#define RAND_LEN 32     /* rfc 5246 */
#define HMAC_LEN 64     /* big enough for SHA-512 */
#define VERIFY_LEN 12   /* rfc 5246 */
#define MASTER_LEN 48   /* rfc 5246 */
#define MAXIV 16        /* big enough for AES256 */
#define MAXKEY 32       /* big enough for AES256 */
#define KEYBLSIZE 16    /* Maximum symetric key blocksize */
#define DEF_RSA_LEN 512 /* Default length of generated RSA keys */
#define RSA_EXP 65537   /* Public key exponent of generated RSA keys */
#define SALT_LEN 4      /* Length of salt for IV */
#define GCM_IV_LEN 12   /* Length of IV for ciphers in GCM mode */
#define CCM_IV_LEN 12   /* Length of IV for ciphers in CCM mode */
#define GCM_TAG_LEN 16  /* Length of tag for ciphers in GCM mode */
#define CCM_TAG_LEN 16  /* Length of tag for ciphers in CCM mode */

#define UFTP_LEN 16
#define ANNOUNCE_LEN 16
#define ENC_INFO_LEN 44
#define REGISTER_LEN 44
#define CLIENT_KEY_LEN 8
#define REG_CONF_LEN 4
#define KEYINFO_LEN 12
#define DESTKEY_LEN 52
#define KEYINFO_ACK_LEN 16
#define FILEINFO_LEN 28
#define FILEINFO_ACK_LEN 16
#define FILESEG_LEN 8
#define TFMCC_DATA_LEN 8
#define DONE_LEN 8
#define STATUS_LEN 8
#define COMPLETE_LEN 8
#define FREESPACE_LEN 12
#define DONE_CONF_LEN 4
#define HB_REQ_LEN 12
#define HB_RESP_LEN 8
#define KEY_REQ_LEN 4
#define PROXY_KEY_LEN 12
#define ENCRYPTED_LEN 12
#define ABORT_LEN 308
#define CONG_CTRL_LEN 16
#define CC_ITEM_LEN 8
#define CC_ACK_LEN 4
#define TFMCC_ACK_LEN 20
#define RSA_BLOB_LEN 8
#define EC_BLOB_LEN 4

void proto_register_uftp4(void);
void proto_reg_handoff_uftp4(void);

static int proto_uftp = -1;

/* main header and common fields */
static int hf_uftp_version = -1;
static int hf_uftp_func = -1;
static int hf_uftp_seq = -1;
static int hf_uftp_src_id = -1;
static int hf_uftp_group_id = -1;
static int hf_uftp_group_inst = -1;
static int hf_uftp_grtt = -1;
static int hf_uftp_gsize = -1;
static int hf_uftp_reserved = -1;

static int hf_uftp_destlist = -1;
static int hf_uftp_dest = -1;

/* ANNOUNCE fields */
static int hf_uftp_announce = -1;
static int hf_uftp_announce_func = -1;
static int hf_uftp_announce_hlen = -1;
static int hf_uftp_announce_flags = -1;
static int hf_uftp_announce_flags_sync = -1;
static int hf_uftp_announce_flags_syncpreview = -1;
static int hf_uftp_announce_flags_ipv6 = -1;
static int hf_uftp_announce_flags_reserved = -1;
static int hf_uftp_announce_robust = -1;
static int hf_uftp_announce_cc_type = -1;
static int hf_uftp_announce_reserved = -1;
static int hf_uftp_announce_blocksize = -1;
static int hf_uftp_announce_tstamp = -1;
static int hf_uftp_announce_publicmcast_ipv4 = -1;
static int hf_uftp_announce_publicmcast_ipv6 = -1;
static int hf_uftp_announce_privatemcast_ipv4 = -1;
static int hf_uftp_announce_privatemcast_ipv6 = -1;

/* EXT_ENC_INFO fields */
static int hf_uftp_encinfo = -1;
static int hf_uftp_encinfo_exttype = -1;
static int hf_uftp_encinfo_extlen = -1;
static int hf_uftp_encinfo_flags = -1;
static int hf_uftp_encinfo_flags_client_auth = -1;
static int hf_uftp_encinfo_flags_reserved = -1;
static int hf_uftp_encinfo_keyextype = -1;
static int hf_uftp_encinfo_sigtype = -1;
static int hf_uftp_encinfo_keytype = -1;
static int hf_uftp_encinfo_hashtype = -1;
static int hf_uftp_encinfo_keylen = -1;
static int hf_uftp_encinfo_dhlen = -1;
static int hf_uftp_encinfo_siglen = -1;
static int hf_uftp_encinfo_rand1 = -1;
static int hf_uftp_encinfo_keyblob = -1;
static int hf_uftp_encinfo_dhblob = -1;
static int hf_uftp_encinfo_sig = -1;

/* rsa_blob_t fields */
static int hf_uftp_rsablob_blobtype = -1;
static int hf_uftp_rsablob_reserved = -1;
static int hf_uftp_rsablob_modlen = -1;
static int hf_uftp_rsablob_exponent = -1;
static int hf_uftp_rsablob_modulus = -1;

/* ec_blob_t fields */
static int hf_uftp_ecblob_blobtype = -1;
static int hf_uftp_ecblob_curve = -1;
static int hf_uftp_ecblob_keylen = -1;
static int hf_uftp_ecblob_key = -1;

/* REGISTER fields */
static int hf_uftp_register = -1;
static int hf_uftp_register_func = -1;
static int hf_uftp_register_hlen = -1;
static int hf_uftp_register_keyinfo_len = -1;
static int hf_uftp_register_tstamp = -1;
static int hf_uftp_register_rand2 = -1;
static int hf_uftp_register_keyinfo = -1;

/* CLIENT_KEY fields */
static int hf_uftp_clientkey = -1;
static int hf_uftp_clientkey_func = -1;
static int hf_uftp_clientkey_hlen = -1;
static int hf_uftp_clientkey_reserved = -1;
static int hf_uftp_clientkey_bloblen = -1;
static int hf_uftp_clientkey_siglen = -1;
static int hf_uftp_clientkey_keyblob = -1;
static int hf_uftp_clientkey_verify = -1;

/* REG_CONF fields */
static int hf_uftp_regconf = -1;
static int hf_uftp_regconf_func = -1;
static int hf_uftp_regconf_hlen = -1;
static int hf_uftp_regconf_reserved = -1;

/* KEYINFO fields */
static int hf_uftp_keyinfo = -1;
static int hf_uftp_keyinfo_func = -1;
static int hf_uftp_keyinfo_hlen = -1;
static int hf_uftp_keyinfo_reserved = -1;
static int hf_uftp_keyinfo_ivctr = -1;
static int hf_uftp_keyinfo_destkey = -1;
static int hf_uftp_keyinfo_destid = -1;
static int hf_uftp_keyinfo_groupmaster = -1;

/* KEYINFO_ACK fields */
static int hf_uftp_keyinfoack = -1;
static int hf_uftp_keyinfoack_func = -1;
static int hf_uftp_keyinfoack_hlen = -1;
static int hf_uftp_keyinfoack_reserved = -1;
static int hf_uftp_keyinfoack_verify_data = -1;

/* FILEINFO fields */
static int hf_uftp_fileinfo = -1;
static int hf_uftp_fileinfo_func = -1;
static int hf_uftp_fileinfo_hlen = -1;
static int hf_uftp_fileinfo_file_id = -1;
static int hf_uftp_fileinfo_ftype = -1;
static int hf_uftp_fileinfo_reserved = -1;
static int hf_uftp_fileinfo_namelen = -1;
static int hf_uftp_fileinfo_linklen = -1;
static int hf_uftp_fileinfo_fsize = -1;
static int hf_uftp_fileinfo_ftstamp = -1;
static int hf_uftp_fileinfo_tstamp = -1;
static int hf_uftp_fileinfo_name = -1;
static int hf_uftp_fileinfo_link = -1;

/* FILEINFO_ACK fields */
static int hf_uftp_fileinfoack = -1;
static int hf_uftp_fileinfoack_func = -1;
static int hf_uftp_fileinfoack_hlen = -1;
static int hf_uftp_fileinfoack_file_id = -1;
static int hf_uftp_fileinfoack_flags = -1;
static int hf_uftp_fileinfoack_flags_partial = -1;
static int hf_uftp_fileinfoack_flags_reserved = -1;
static int hf_uftp_fileinfoack_reserved = -1;
static int hf_uftp_fileinfoack_tstamp = -1;

/* FILESEG fields */
static int hf_uftp_fileseg = -1;
static int hf_uftp_fileseg_func = -1;
static int hf_uftp_fileseg_hlen = -1;
static int hf_uftp_fileseg_file_id = -1;
static int hf_uftp_fileseg_section = -1;
static int hf_uftp_fileseg_sec_block = -1;
static int hf_uftp_fileseg_data = -1;

/* EXT_TFMCC_DATA_INFO fields */
static int hf_uftp_tfmccdata = -1;
static int hf_uftp_tfmccdata_exttype = -1;
static int hf_uftp_tfmccdata_extlen = -1;
static int hf_uftp_tfmccdata_send_rate = -1;
static int hf_uftp_tfmccdata_cc_seq = -1;
static int hf_uftp_tfmccdata_cc_rate = -1;

/* DONE fields */
static int hf_uftp_done = -1;
static int hf_uftp_done_func = -1;
static int hf_uftp_done_hlen = -1;
static int hf_uftp_done_file_id = -1;
static int hf_uftp_done_section = -1;
static int hf_uftp_done_reserved = -1;

/* STATUS fields */
static int hf_uftp_status = -1;
static int hf_uftp_status_func = -1;
static int hf_uftp_status_hlen = -1;
static int hf_uftp_status_file_id = -1;
static int hf_uftp_status_section = -1;
static int hf_uftp_status_reserved = -1;
static int hf_uftp_status_naks = -1;

/* COMPLETE fields */
static int hf_uftp_complete = -1;
static int hf_uftp_complete_func = -1;
static int hf_uftp_complete_hlen = -1;
static int hf_uftp_complete_file_id = -1;
static int hf_uftp_complete_status = -1;
static int hf_uftp_complete_reserved = -1;

/* EXT_FREESPACE_INFO fields */
static int hf_uftp_freespace = -1;
static int hf_uftp_freespace_exttype = -1;
static int hf_uftp_freespace_extlen = -1;
static int hf_uftp_freespace_reserved = -1;
static int hf_uftp_freespace_freespace = -1;

/* DONE_CONF fields */
static int hf_uftp_doneconf = -1;
static int hf_uftp_doneconf_func = -1;
static int hf_uftp_doneconf_hlen = -1;
static int hf_uftp_doneconf_reserved = -1;

/* HB_REQ fields */
static int hf_uftp_hbreq = -1;
static int hf_uftp_hbreq_func = -1;
static int hf_uftp_hbreq_hlen = -1;
static int hf_uftp_hbreq_reserved = -1;
static int hf_uftp_hbreq_bloblen = -1;
static int hf_uftp_hbreq_siglen = -1;
static int hf_uftp_hbreq_nonce = -1;
static int hf_uftp_hbreq_keyblob = -1;
static int hf_uftp_hbreq_verify = -1;

/* HB_RESP fields */
static int hf_uftp_hbresp = -1;
static int hf_uftp_hbresp_func = -1;
static int hf_uftp_hbresp_hlen = -1;
static int hf_uftp_hbresp_authenticated = -1;
static int hf_uftp_hbresp_reserved = -1;
static int hf_uftp_hbresp_nonce = -1;

/* KEY_REQ fields */
static int hf_uftp_keyreq = -1;
static int hf_uftp_keyreq_func = -1;
static int hf_uftp_keyreq_hlen = -1;
static int hf_uftp_keyreq_reserved = -1;

/* PROXY_KEY fields */
static int hf_uftp_proxykey = -1;
static int hf_uftp_proxykey_func = -1;
static int hf_uftp_proxykey_hlen = -1;
static int hf_uftp_proxykey_bloblen = -1;
static int hf_uftp_proxykey_dhlen = -1;
static int hf_uftp_proxykey_siglen = -1;
static int hf_uftp_proxykey_nonce = -1;
static int hf_uftp_proxykey_keyblob = -1;
static int hf_uftp_proxykey_dhblob = -1;
static int hf_uftp_proxykey_verify = -1;

/* CONG_CTRL fields */
static int hf_uftp_congctrl = -1;
static int hf_uftp_congctrl_func = -1;
static int hf_uftp_congctrl_hlen = -1;
static int hf_uftp_congctrl_reserved = -1;
static int hf_uftp_congctrl_cc_seq = -1;
static int hf_uftp_congctrl_cc_rate = -1;
static int hf_uftp_congctrl_tstamp = -1;
static int hf_uftp_congctrl_cclist = -1;
static int hf_uftp_congctrl_item = -1;
static int hf_uftp_congctrl_item_destid = -1;
static int hf_uftp_congctrl_item_flags = -1;
static int hf_uftp_congctrl_item_flags_clr = -1;
static int hf_uftp_congctrl_item_flags_rtt = -1;
static int hf_uftp_congctrl_item_flags_start = -1;
static int hf_uftp_congctrl_item_flags_leave = -1;
static int hf_uftp_congctrl_item_flags_reserved = -1;
static int hf_uftp_congctrl_item_rtt = -1;
static int hf_uftp_congctrl_item_rate = -1;

/* CC_ACK fields */
static int hf_uftp_ccack = -1;
static int hf_uftp_ccack_func = -1;
static int hf_uftp_ccack_hlen = -1;
static int hf_uftp_ccack_reserved = -1;

/* EXT_TFMCC_ACK_INFO fields */
static int hf_uftp_tfmccack = -1;
static int hf_uftp_tfmccack_exttype = -1;
static int hf_uftp_tfmccack_extlen = -1;
static int hf_uftp_tfmccack_flags = -1;
static int hf_uftp_tfmccack_flags_clr = -1;
static int hf_uftp_tfmccack_flags_rtt = -1;
static int hf_uftp_tfmccack_flags_start = -1;
static int hf_uftp_tfmccack_flags_leave = -1;
static int hf_uftp_tfmccack_flags_reserved = -1;
static int hf_uftp_tfmccack_reserved = -1;
static int hf_uftp_tfmccack_cc_seq = -1;
static int hf_uftp_tfmccack_cc_rate = -1;
static int hf_uftp_tfmccack_client_id = -1;
static int hf_uftp_tfmccack_tstamp = -1;

/* ENCRYPTED fields */
static int hf_uftp_encrypted = -1;
static int hf_uftp_encrypted_ivctr = -1;
static int hf_uftp_encrypted_sig_len = -1;
static int hf_uftp_encrypted_payload_len = -1;
static int hf_uftp_encrypted_signature = -1;
static int hf_uftp_encrypted_payload = -1;

/* ABORT fields */
static int hf_uftp_abort = -1;
static int hf_uftp_abort_func = -1;
static int hf_uftp_abort_hlen = -1;
static int hf_uftp_abort_flags = -1;
static int hf_uftp_abort_flags_curfile = -1;
static int hf_uftp_abort_flags_reserved = -1;
static int hf_uftp_abort_reserved = -1;
static int hf_uftp_abort_clientid = -1;
static int hf_uftp_abort_message = -1;

static gint ett_uftp = -1;
static gint ett_uftp_announce = -1;
static gint ett_uftp_register = -1;
static gint ett_uftp_clientkey = -1;
static gint ett_uftp_regconf = -1;
static gint ett_uftp_keyinfo = -1;
static gint ett_uftp_keyinfoack = -1;
static gint ett_uftp_fileinfo = -1;
static gint ett_uftp_fileinfoack = -1;
static gint ett_uftp_fileseg = -1;
static gint ett_uftp_done = -1;
static gint ett_uftp_status = -1;
static gint ett_uftp_complete = -1;
static gint ett_uftp_doneconf = -1;
static gint ett_uftp_hbreq = -1;
static gint ett_uftp_hbresp = -1;
static gint ett_uftp_keyreq = -1;
static gint ett_uftp_proxykey = -1;
static gint ett_uftp_congctrl = -1;
static gint ett_uftp_ccack = -1;
static gint ett_uftp_encrypted = -1;
static gint ett_uftp_abort = -1;

static gint ett_uftp_announce_flags = -1;
static gint ett_uftp_encinfo = -1;
static gint ett_uftp_encinfo_flags = -1;
static gint ett_uftp_keyinfo_destkey = -1;
static gint ett_uftp_fileinfoack_flags = -1;
static gint ett_uftp_congctrl_cclist = -1;
static gint ett_uftp_congctrl_item = -1;
static gint ett_uftp_congctrl_item_flags = -1;
static gint ett_uftp_tfmccdata = -1;
static gint ett_uftp_tfmccack = -1;
static gint ett_uftp_tfmccack_flags = -1;
static gint ett_uftp_freespace = -1;
static gint ett_uftp_abort_flags = -1;

static gint ett_uftp_destlist = -1;
static gint ett_uftp_rsablob = -1;
static gint ett_uftp_ecblob = -1;

static expert_field ei_uftp_length_invalid = EI_INIT;
static expert_field ei_uftp_func_unknown = EI_INIT;

static const value_string messages[] = {
    { ANNOUNCE,      "ANNOUNCE" },
    { REGISTER,      "REGISTER" },
    { CLIENT_KEY,    "CLIENT_KEY" },
    { REG_CONF,      "REG_CONF" },
    { KEYINFO,       "KEYINFO" },
    { KEYINFO_ACK,   "KEYINFO_ACK" },
    { FILEINFO,      "FILEINFO" },
    { FILEINFO_ACK,  "FILEINFO_ACK" },
    { FILESEG,       "FILESEG" },
    { DONE,          "DONE" },
    { STATUS,        "STATUS" },
    { COMPLETE,      "COMPLETE" },
    { DONE_CONF,     "DONE_CONF" },
    { HB_REQ,        "HB_REQ" },
    { HB_RESP,       "HB_RESP" },
    { KEY_REQ,       "KEY_REQ" },
    { PROXY_KEY,     "PROXY_KEY" },
    { ENCRYPTED,     "ENCRYPTED" },
    { ABORT,         "ABORT" },
    { CONG_CTRL,     "CONG_CTRL" },
    { CC_ACK,        "CC_ACK" },
    { 0, NULL }
};

static const value_string extensions[] = {
    { EXT_ENC_INFO,         "EXT_ENC_INFO" },
    { EXT_TFMCC_DATA_INFO,  "EXT_TFMCC_DATA_INFO" },
    { EXT_TFMCC_ACK_INFO,   "EXT_TFMCC_ACK_INFO" },
    { EXT_PGMCC_DATA_INFO,  "EXT_PGMCC_DATA_INFO" },
    { EXT_PGMCC_NAK_INFO,   "EXT_PGMCC_NAK_INFO" },
    { EXT_PGMCC_ACK_INFO,   "EXT_PGMCC_ACK_INFO" },
    { EXT_FREESPACE_INFO,   "EXT_FREESPACE_INFO" },
    { 0, NULL }
};

static const value_string cc_types[] = {
    { CC_NONE,  "NONE" },
    { CC_UFTP3,  "UFTP3" },
    { CC_TFMCC,  "TFMCC" },
    { CC_PGMCC,  "PGMCC" },
    { 0, NULL }
};

static const value_string keyblob_types[] = {
    { KEYBLOB_RSA,  "RSA" },
    { KEYBLOB_EC,   "EC" },
    { 0, NULL }
};

static const value_string curves[] = {
    { CURVE_sect163k1,  "sect163k1" },
    { CURVE_sect163r1,  "sect163r1" },
    { CURVE_sect163r2,  "sect163r2" },
    { CURVE_sect193r1,  "sect193r1" },
    { CURVE_sect193r2,  "sect193r2" },
    { CURVE_sect233k1,  "sect233k1" },
    { CURVE_sect233r1,  "sect233r1" },
    { CURVE_sect239k1,  "sect239k1" },
    { CURVE_sect283k1,  "sect283k1" },
    { CURVE_sect283r1,  "sect283r1" },
    { CURVE_sect409k1,  "sect409k1" },
    { CURVE_sect409r1,  "sect409r1" },
    { CURVE_sect571k1,  "sect571k1" },
    { CURVE_sect571r1,  "sect571r1" },
    { CURVE_secp160k1,  "secp160k1" },
    { CURVE_secp160r1,  "secp160r1" },
    { CURVE_secp160r2,  "secp160r2" },
    { CURVE_secp192k1,  "secp192k1" },
    { CURVE_secp192r1,  "prime192v1" },
    { CURVE_secp224k1,  "secp224k1" },
    { CURVE_secp224r1,  "secp224r1" },
    { CURVE_secp256k1,  "secp256k1" },
    { CURVE_secp256r1,  "prime256v1" },
    { CURVE_secp384r1,  "secp384r1" },
    { CURVE_secp521r1,  "secp521r1" },
    { 0, NULL }
};


static const value_string keyexchange_types[] = {
    { KEYEX_NONE,       "NONE" },
    { KEYEX_RSA,        "RSA" },
    { KEYEX_ECDH_RSA,   "ECDH_RSA" },
    { KEYEX_ECDH_ECDSA, "ECDH_ECDSA" },
    { 0, NULL }
};

static const value_string signature_types[] = {
    { SIG_NONE,     "NONE" },
    { SIG_HMAC,     "HMAC" },
    { SIG_KEYEX,    "KEYEX" },
    { SIG_AUTHENC,  "AUTHENC" },
    { 0, NULL }
};

static const value_string hash_types[] = {
    { HASH_NONE,   "NONE" },
    { HASH_MD5,    "MD5" },
    { HASH_SHA1,   "SHA-1" },
    { HASH_SHA256, "SHA-256" },
    { HASH_SHA384, "SHA-384" },
    { HASH_SHA512, "SHA-512" },
    { 0, NULL }
};

static const value_string key_types[] = {
    { KEY_NONE,         "NONE" },
    { KEY_DES,          "DES" },
    { KEY_DES_EDE3,     "3 Key Triple DES" },
    { KEY_AES128_CBC,   "AES-128-CBC" },
    { KEY_AES256_CBC,   "AES-256-CBC" },
    { KEY_AES128_GCM,   "AES-128-GCM" },
    { KEY_AES256_GCM,   "AES-256-GCM" },
    { KEY_AES128_CCM,   "AES-128-CCM" },
    { KEY_AES256_CCM,   "AES-256-CCM" },
    { 0, NULL }
};

static const value_string hb_auth_types[] = {
    { HB_AUTH_FAILED,    "Authorization Failed" },
    { HB_AUTH_OK,        "Authorization Succeeded" },
    { HB_AUTH_CHALLENGE, "Authorization Required" },
    { 0, NULL }
};

static const value_string file_types[] = {
    { FTYPE_REG,        "Regular file" },
    { FTYPE_DIR,        "Directory" },
    { FTYPE_LINK,       "Symbolic link" },
    { FTYPE_DELETE,     "Delete request" },
    { FTYPE_FREESPACE,  "Free space request" },
    { 0, NULL }
};

static const int *announce_flags[] = {
    &hf_uftp_announce_flags_sync,
    &hf_uftp_announce_flags_syncpreview,
    &hf_uftp_announce_flags_ipv6,
    &hf_uftp_announce_flags_reserved,
    NULL
};

static const int *encinfo_flags[] = {
    &hf_uftp_encinfo_flags_client_auth,
    &hf_uftp_encinfo_flags_reserved,
    NULL
};

static const int *fileinfoack_flags[] = {
    &hf_uftp_fileinfoack_flags_partial,
    &hf_uftp_fileinfoack_flags_reserved,
    NULL
};

static const int *abort_flags[] = {
    &hf_uftp_abort_flags_curfile,
    &hf_uftp_abort_flags_reserved,
    NULL
};

static const int *cc_item_flags[] = {
    &hf_uftp_congctrl_item_flags_clr,
    &hf_uftp_congctrl_item_flags_rtt,
    &hf_uftp_congctrl_item_flags_start,
    &hf_uftp_congctrl_item_flags_leave,
    &hf_uftp_congctrl_item_flags_reserved,
    NULL
};

static const int *tfmcc_ack_flags[] = {
    &hf_uftp_tfmccack_flags_clr,
    &hf_uftp_tfmccack_flags_rtt,
    &hf_uftp_tfmccack_flags_start,
    &hf_uftp_tfmccack_flags_leave,
    &hf_uftp_tfmccack_flags_reserved,
    NULL
};

static const value_string comp_status[] = {
    { COMP_STAT_NORMAL,     "Normal" },
    { COMP_STAT_SKIPPED,    "Skipped" },
    { COMP_STAT_OVERWRITE,  "Overwrite" },
    { COMP_STAT_REJECTED,   "Rejected" },
    { 0, NULL }
};

#define RTT_MIN 1.0e-6
#define RTT_MAX 1000.0

static double unquantize_grtt(guint8 rtt)
{
    return ((rtt <= 31) ?
            (((double)(rtt + 1)) * (double)RTT_MIN) :
            (RTT_MAX / exp(((double)(255 - rtt)) / (double)13.0)));
}

static guint unquantize_gsize(guint8 size)
{
    gint E, i;
    double rval;

    E = size & 0x7;
    rval =  (size >> 3) * (10.0 / 32.0);
    for (i = 0; i < E; i++) {
        rval *= 10;
    }

    return (guint)(rval + 0.5);
}

static guint unquantize_rate(guint16 rate)
{
    gint E, i;
    double rval;

    E = rate & 0xF;
    rval = (rate >> 4) * (10.0 / 4096.0);
    for (i = 0; i < E; i++) {
        rval *= 10;
    }

    return (guint)rval;
}

static int dissect_uftp_rsablob(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int tree_hf)
{
    proto_item *ti = NULL;
    proto_tree *rsablob_tree = NULL;
    gint offset = 0, modlen;

    if (tvb_reported_length(tvb) < RSA_BLOB_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return 0;
    }

    modlen = (gint)tvb_get_ntohs(tvb, 2);
    if ((gint)tvb_reported_length(tvb) < modlen + RSA_BLOB_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d", tvb_reported_length(tvb));
        return 0;
    }

    ti = proto_tree_add_item(tree, tree_hf, tvb, offset, RSA_BLOB_LEN + modlen, ENC_NA);
    rsablob_tree = proto_item_add_subtree(ti, ett_uftp_rsablob);
    proto_tree_add_item(rsablob_tree, hf_uftp_rsablob_blobtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(rsablob_tree, hf_uftp_rsablob_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(rsablob_tree, hf_uftp_rsablob_modlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(rsablob_tree, hf_uftp_rsablob_exponent, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(rsablob_tree, hf_uftp_rsablob_modulus, tvb, offset, modlen, ENC_NA);

    return RSA_BLOB_LEN + modlen;
}

static int dissect_uftp_ecblob(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int tree_hf)
{
    proto_item *ti = NULL;
    proto_tree *ecblob_tree = NULL;
    gint offset = 0, keylen;

    if (tvb_reported_length(tvb) < EC_BLOB_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return 0;
    }

    keylen = (gint)tvb_get_ntohs(tvb, 2);
    if ((gint)tvb_reported_length(tvb) < keylen + EC_BLOB_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d", tvb_reported_length(tvb));
        return 0;
    }

    ti = proto_tree_add_item(tree, tree_hf, tvb, offset, EC_BLOB_LEN + keylen, ENC_NA);
    ecblob_tree = proto_item_add_subtree(ti, ett_uftp_ecblob);
    proto_tree_add_item(ecblob_tree, hf_uftp_ecblob_blobtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ecblob_tree, hf_uftp_ecblob_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ecblob_tree, hf_uftp_ecblob_keylen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ecblob_tree, hf_uftp_ecblob_key, tvb, offset, keylen, ENC_NA);

    return EC_BLOB_LEN + keylen;
}

static gint dissect_uftp_encinfo(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *encinfo_tree = NULL;
    gint offset = 0, hlen, keylen, dhlen, siglen;
    gint8 blobtype;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < ENC_INFO_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return 0;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    keylen = (gint)tvb_get_ntohs(tvb, 6);
    dhlen = (gint)tvb_get_ntohs(tvb, 8);
    siglen = (gint)tvb_get_ntohs(tvb, 10);
    if (((gint)tvb_reported_length(tvb) < hlen) ||
            (hlen < ENC_INFO_LEN + keylen + dhlen + siglen)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d, "
                            "keylen = %d, dhlen = %d, siglen = %d",
                            tvb_reported_length(tvb), hlen, keylen, dhlen, siglen);
        return 0;
    }

    ti = proto_tree_add_item(tree, hf_uftp_encinfo, tvb, offset, ENC_INFO_LEN + keylen + dhlen + siglen, ENC_NA);
    encinfo_tree = proto_item_add_subtree(ti, ett_uftp_encinfo);
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_exttype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_extlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(encinfo_tree, tvb, offset, hf_uftp_encinfo_flags, ett_uftp_encinfo_flags, encinfo_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_keyextype, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_sigtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_keytype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_hashtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_keylen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_dhlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_siglen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_rand1, tvb, offset, RAND_LEN, ENC_NA);
    offset += RAND_LEN;
    if (keylen > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, keylen);
        blobtype = tvb_get_guint8(tvb, offset);
        switch (blobtype) {
        case KEYBLOB_RSA:
            parsed = dissect_uftp_rsablob(next_tvb, pinfo, encinfo_tree, hf_uftp_encinfo_keyblob);
            break;
        case KEYBLOB_EC:
            parsed = dissect_uftp_ecblob(next_tvb, pinfo, encinfo_tree, hf_uftp_encinfo_keyblob);
            break;
        }
        offset += parsed;
    }
    if (dhlen > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, dhlen);
        blobtype = tvb_get_guint8(tvb, offset);
        switch (blobtype) {
        case KEYBLOB_RSA:
            parsed = dissect_uftp_rsablob(next_tvb, pinfo, encinfo_tree, hf_uftp_encinfo_dhblob);
            break;
        case KEYBLOB_EC:
            parsed = dissect_uftp_ecblob(next_tvb, pinfo, encinfo_tree, hf_uftp_encinfo_dhblob);
            break;
        }
        offset += parsed;
    }
    if (siglen > 0) {
        proto_tree_add_item(encinfo_tree, hf_uftp_encinfo_sig, tvb, offset, siglen, ENC_NA);
    }

    return ENC_INFO_LEN + keylen + dhlen + siglen;
}

static void dissect_uftp_announce(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *announce_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0;
    gint hlen, iplen, destcount, idx, extlen_total;
    guint8 flags, ext_type;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < ANNOUNCE_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if ((gint)tvb_reported_length(tvb) < hlen) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    flags = tvb_get_guint8(tvb, 2);

    ti = proto_tree_add_item(tree, hf_uftp_announce, tvb, offset, -1, ENC_NA);
    announce_tree = proto_item_add_subtree(ti, ett_uftp_announce);
    proto_tree_add_item(announce_tree, hf_uftp_announce_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(announce_tree, tvb, offset, hf_uftp_announce_flags, ett_uftp_announce_flags, announce_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_robust, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_cc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(announce_tree, hf_uftp_announce_blocksize, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(announce_tree, hf_uftp_announce_tstamp, tvb, offset, 8, ENC_TIME_TIMESPEC);
    offset += 8;
    if (flags & FLAG_IPV6) {
        iplen = 16;
        proto_tree_add_item(announce_tree, hf_uftp_announce_publicmcast_ipv6, tvb, offset, iplen, ENC_NA);
        offset += iplen;
        proto_tree_add_item(announce_tree, hf_uftp_announce_privatemcast_ipv6, tvb, offset, iplen, ENC_NA);
        offset += iplen;
    } else {
        iplen = 4;
        proto_tree_add_item(announce_tree, hf_uftp_announce_publicmcast_ipv4, tvb, offset, iplen, ENC_BIG_ENDIAN);
        offset += iplen;
        proto_tree_add_item(announce_tree, hf_uftp_announce_privatemcast_ipv4, tvb, offset, iplen, ENC_BIG_ENDIAN);
        offset += iplen;
    }

    extlen_total = hlen - (ANNOUNCE_LEN + ( 2 * iplen));
    while (extlen_total > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, extlen_total);
        ext_type = tvb_get_guint8(tvb, offset);
        switch (ext_type) {
        case EXT_ENC_INFO:
            parsed = dissect_uftp_encinfo(next_tvb, pinfo, announce_tree);
            break;
        }
        if (!parsed) break;
        extlen_total -= parsed;
        offset += parsed;
    }

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
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
    gint offset = 0, hlen;
    guint16 destcount, keylen, idx;

    if (tvb_reported_length(tvb) < REGISTER_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    keylen = tvb_get_ntohs(tvb, 2);
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < REGISTER_LEN + keylen)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d, keylen = %d",
                            tvb_reported_length(tvb), hlen, keylen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_register, tvb, offset, -1, ENC_NA);
    register_tree = proto_item_add_subtree(ti, ett_uftp_register);
    proto_tree_add_item(register_tree, hf_uftp_register_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(register_tree, hf_uftp_register_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(register_tree, hf_uftp_register_keyinfo_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(register_tree, hf_uftp_register_tstamp, tvb, offset, 8, ENC_TIME_TIMESPEC);
    offset += 8;
    proto_tree_add_item(register_tree, hf_uftp_register_rand2, tvb, offset, RAND_LEN, ENC_NA);
    offset += RAND_LEN;
    if (keylen > 0) {
        proto_tree_add_item(register_tree, hf_uftp_register_keyinfo, tvb, offset, keylen, ENC_NA);
    }

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
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
    gint offset = 0, hlen;
    guint16 keylen, verifylen;
    gint8 blobtype;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < CLIENT_KEY_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    keylen = tvb_get_ntohs(tvb, 4);
    verifylen = tvb_get_ntohs(tvb, 6);
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < CLIENT_KEY_LEN + keylen + verifylen)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d, keylen = %d verifylen = %d",
                            tvb_reported_length(tvb), hlen, keylen, verifylen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_clientkey, tvb, offset, -1, ENC_NA);
    clientkey_tree = proto_item_add_subtree(ti, ett_uftp_clientkey);
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_bloblen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(clientkey_tree, hf_uftp_clientkey_siglen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (keylen > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, keylen);
        blobtype = tvb_get_guint8(tvb, offset);
        switch (blobtype) {
        case KEYBLOB_RSA:
            parsed = dissect_uftp_rsablob(next_tvb, pinfo, clientkey_tree, hf_uftp_clientkey_keyblob);
            break;
        case KEYBLOB_EC:
            parsed = dissect_uftp_ecblob(next_tvb, pinfo, clientkey_tree, hf_uftp_clientkey_keyblob);
            break;
        }
        offset += parsed;
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
    gint offset = 0, hlen;
    guint16 destcount, idx;

    if (tvb_reported_length(tvb) < REG_CONF_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < REG_CONF_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_regconf, tvb, offset, -1, ENC_NA);
    regconf_tree = proto_item_add_subtree(ti, ett_uftp_regconf);
    proto_tree_add_item(regconf_tree, hf_uftp_regconf_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(regconf_tree, hf_uftp_regconf_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(regconf_tree, hf_uftp_regconf_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
    if (destcount > 0) {
        destlist = proto_tree_add_item(regconf_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
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
    gint offset = 0, hlen;
    guint8 destcount, idx;

    if (tvb_reported_length(tvb) < KEYINFO_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < KEYINFO_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_keyinfo, tvb, offset, -1, ENC_NA);
    keyinfo_tree = proto_item_add_subtree(ti, ett_uftp_keyinfo);
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(keyinfo_tree, hf_uftp_keyinfo_ivctr, tvb, offset, 8, ENC_BIG_ENDIAN);

    destcount = (tvb_reported_length(tvb) - hlen) / DESTKEY_LEN;
    offset = hlen;
    if (destcount > 0) {
        destlist = proto_tree_add_item(keyinfo_tree, hf_uftp_destlist, tvb, offset, destcount * DESTKEY_LEN, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        destkey = proto_tree_add_item(destlist_tree, hf_uftp_keyinfo_destkey, tvb, offset, DESTKEY_LEN, ENC_NA);
        destkey_tree = proto_item_add_subtree(destkey, ett_uftp_keyinfo_destkey);
        proto_tree_add_item(destkey_tree, hf_uftp_keyinfo_destid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(destkey_tree, hf_uftp_keyinfo_groupmaster, tvb, offset, 48, ENC_NA);
        offset += 48;
    }
}

static void dissect_uftp_keyinfoack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *keyinfoack_tree = NULL;
    gint offset = 0, hlen;

    if (tvb_reported_length(tvb) < KEYINFO_ACK_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < KEYINFO_ACK_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_keyinfoack, tvb, offset, -1, ENC_NA);
    keyinfoack_tree = proto_item_add_subtree(ti, ett_uftp_keyinfoack);
    proto_tree_add_item(keyinfoack_tree, hf_uftp_keyinfoack_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfoack_tree, hf_uftp_keyinfoack_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyinfoack_tree, hf_uftp_keyinfoack_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(keyinfoack_tree, hf_uftp_keyinfoack_verify_data, tvb, offset, VERIFY_LEN, ENC_NA);
}

static void dissect_uftp_fileinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *fileinfo_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0, hlen;
    guint16 file_id, destcount, idx, namelen, linklen;

    if (tvb_reported_length(tvb) < FILEINFO_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    namelen = tvb_get_guint8(tvb, 8) * 4;
    linklen = tvb_get_guint8(tvb, 9) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < FILEINFO_LEN + namelen + linklen)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d, namelen = %d, linklen = %d",
                            tvb_reported_length(tvb), hlen, namelen, linklen);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X", file_id);

    ti = proto_tree_add_item(tree, hf_uftp_fileinfo, tvb, offset, -1, ENC_NA);
    fileinfo_tree = proto_item_add_subtree(ti, ett_uftp_fileinfo);
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_ftype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_namelen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_linklen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_fsize, tvb, offset, 6, ENC_BIG_ENDIAN);
    offset += 6;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_ftstamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_tstamp, tvb, offset, 8, ENC_TIME_TIMESPEC);
    offset += 8;
    proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_name, tvb, offset, namelen, ENC_ASCII|ENC_NA);
    offset += namelen;
    if (linklen > 0) {
        proto_tree_add_item(fileinfo_tree, hf_uftp_fileinfo_link, tvb, offset, linklen, ENC_ASCII|ENC_NA);
    }

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
    if (destcount > 0) {
        destlist = proto_tree_add_item(fileinfo_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_fileinfoack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *fileinfoack_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0, hlen;
    guint16 file_id, destcount, idx;

    if (tvb_reported_length(tvb) < FILEINFO_ACK_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < FILEINFO_ACK_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    if (file_id > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X", file_id);
    }

    ti = proto_tree_add_item(tree, hf_uftp_fileinfoack, tvb, offset, -1, ENC_NA);
    fileinfoack_tree = proto_item_add_subtree(ti, ett_uftp_fileinfoack);
    proto_tree_add_item(fileinfoack_tree, hf_uftp_fileinfoack_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfoack_tree, hf_uftp_fileinfoack_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfoack_tree, hf_uftp_fileinfoack_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(fileinfoack_tree, tvb, offset, hf_uftp_fileinfoack_flags, ett_uftp_fileinfoack_flags, fileinfoack_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileinfoack_tree, hf_uftp_fileinfoack_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(fileinfoack_tree, hf_uftp_fileinfoack_tstamp, tvb, offset, 8, ENC_TIME_TIMESPEC);

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
    if (destcount > 0) {
        destlist = proto_tree_add_item(fileinfoack_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static gint dissect_uftp_tfmccdata(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *tfmccdata_tree = NULL;
    gint offset = 0, hlen;
    guint rate, srate;

    if (tvb_reported_length(tvb) < TFMCC_DATA_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return 0;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < TFMCC_DATA_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return 0;
    }

    rate = unquantize_rate(tvb_get_ntohs(tvb, 6));
    srate = unquantize_rate(tvb_get_ntohs(tvb, 2));

    ti = proto_tree_add_item(tree, hf_uftp_tfmccdata, tvb, offset, TFMCC_DATA_LEN, ENC_NA);
    tfmccdata_tree = proto_item_add_subtree(ti, ett_uftp_tfmccdata);
    proto_tree_add_item(tfmccdata_tree, hf_uftp_tfmccdata_exttype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tfmccdata_tree, hf_uftp_tfmccdata_extlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_uint(tfmccdata_tree, hf_uftp_tfmccdata_send_rate, tvb, offset, 2, srate);
    offset += 2;
    proto_tree_add_item(tfmccdata_tree, hf_uftp_tfmccdata_cc_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_uint(tfmccdata_tree, hf_uftp_tfmccdata_cc_rate, tvb, offset, 2, rate);

    return TFMCC_DATA_LEN;
}

static void dissect_uftp_fileseg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *fileseg_tree = NULL;
    gint offset = 0, hlen, extlen_total;
    guint16 file_id, section, sec_block;
    guint8 ext_type;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < FILESEG_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < FILESEG_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    section = tvb_get_ntohs(tvb, 4);
    sec_block = tvb_get_ntohs(tvb, 6);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X  Section=%d  Block=%d",
                    file_id, section, sec_block);

    ti = proto_tree_add_item(tree, hf_uftp_fileseg, tvb, offset, -1, ENC_NA);
    fileseg_tree = proto_item_add_subtree(ti, ett_uftp_fileseg);
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_section, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_sec_block, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    extlen_total = hlen - FILESEG_LEN;
    while (extlen_total > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, extlen_total);
        ext_type = tvb_get_guint8(tvb, offset);
        switch (ext_type) {
        case EXT_TFMCC_DATA_INFO:
            parsed = dissect_uftp_tfmccdata(next_tvb, pinfo, fileseg_tree);
            break;
        }
        if (!parsed) break;
        extlen_total -= parsed;
        offset += parsed;
    }

    offset = hlen;
    proto_tree_add_item(fileseg_tree, hf_uftp_fileseg_data, tvb, offset, -1, ENC_NA);
}

static void dissect_uftp_done(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *done_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0, hlen;
    guint16 file_id, section, destcount, idx;

    if (tvb_reported_length(tvb) < DONE_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < DONE_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    section = tvb_get_ntohs(tvb, 6);
    if (file_id > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X  Section=%d",
                        file_id, section);
    }

    ti = proto_tree_add_item(tree, hf_uftp_done, tvb, offset, -1, ENC_NA);
    done_tree = proto_item_add_subtree(ti, ett_uftp_done);
    proto_tree_add_item(done_tree, hf_uftp_done_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(done_tree, hf_uftp_done_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(done_tree, hf_uftp_done_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(done_tree, hf_uftp_done_section, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(done_tree, hf_uftp_done_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
    if (destcount > 0) {
        destlist = proto_tree_add_item(done_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static gint dissect_uftp_tfmccack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *tfmccack_tree = NULL;
    gint offset = 0, hlen;
    guint rate;

    if (tvb_reported_length(tvb) < TFMCC_ACK_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return 0;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < TFMCC_ACK_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return 0;
    }

    rate = unquantize_rate(tvb_get_ntohs(tvb, 6));

    ti = proto_tree_add_item(tree, hf_uftp_tfmccack, tvb, offset, TFMCC_ACK_LEN, ENC_NA);
    tfmccack_tree = proto_item_add_subtree(ti, ett_uftp_tfmccack);
    proto_tree_add_item(tfmccack_tree, hf_uftp_tfmccack_exttype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tfmccack_tree, hf_uftp_tfmccack_extlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(tfmccack_tree, tvb, offset, hf_uftp_tfmccack_flags, ett_uftp_tfmccack_flags, tfmcc_ack_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tfmccack_tree, hf_uftp_tfmccack_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tfmccack_tree, hf_uftp_tfmccack_cc_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_uint(tfmccack_tree, hf_uftp_tfmccack_cc_rate, tvb, offset, 2, rate);
    offset += 2;
    proto_tree_add_item(tfmccack_tree, hf_uftp_tfmccack_client_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tfmccack_tree, hf_uftp_tfmccack_tstamp, tvb, offset, 8, ENC_TIME_TIMESPEC);

    return TFMCC_ACK_LEN;
}

static void dissect_uftp_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *status_tree = NULL;
    gint offset = 0, hlen, extlen_total;
    guint16 file_id, section;
    guint8 ext_type;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < STATUS_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < STATUS_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    file_id = tvb_get_ntohs(tvb, 2);
    section = tvb_get_ntohs(tvb, 4);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%04X  Section=%d",
                    file_id, section);

    ti = proto_tree_add_item(tree, hf_uftp_status, tvb, offset, -1, ENC_NA);
    status_tree = proto_item_add_subtree(ti, ett_uftp_status);
    proto_tree_add_item(status_tree, hf_uftp_status_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(status_tree, hf_uftp_status_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(status_tree, hf_uftp_status_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(status_tree, hf_uftp_status_section, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(status_tree, hf_uftp_status_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    extlen_total = hlen - STATUS_LEN;
    while (extlen_total > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, extlen_total);
        ext_type = tvb_get_guint8(tvb, offset);
        switch (ext_type) {
        case EXT_TFMCC_ACK_INFO:
            parsed = dissect_uftp_tfmccack(next_tvb, pinfo, status_tree);
            break;
        }
        if (!parsed) break;
        extlen_total -= parsed;
        offset += parsed;
    }

    offset = hlen;
    proto_tree_add_item(status_tree, hf_uftp_status_naks, tvb, offset, -1, ENC_NA);
}

static gint dissect_uftp_freespace(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *freespace_tree = NULL;
    gint offset = 0, hlen;

    if (tvb_reported_length(tvb) < FREESPACE_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return 0;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < FREESPACE_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return 0;
    }

    ti = proto_tree_add_item(tree, hf_uftp_freespace, tvb, offset, FREESPACE_LEN, ENC_NA);
    freespace_tree = proto_item_add_subtree(ti, ett_uftp_freespace);
    proto_tree_add_item(freespace_tree, hf_uftp_freespace_exttype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(freespace_tree, hf_uftp_freespace_extlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(freespace_tree, hf_uftp_freespace_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(freespace_tree, hf_uftp_freespace_freespace, tvb, offset, 8, ENC_BIG_ENDIAN);

    return FREESPACE_LEN;
}

static void dissect_uftp_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *complete_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0, hlen, extlen_total;
    guint16 file_id, destcount, idx;
    guint8 ext_type;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < COMPLETE_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < COMPLETE_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
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
    proto_tree_add_item(complete_tree, hf_uftp_complete_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(complete_tree, hf_uftp_complete_file_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(complete_tree, hf_uftp_complete_status, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(complete_tree, hf_uftp_complete_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 3;

    extlen_total = hlen - COMPLETE_LEN;
    while (extlen_total > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, extlen_total);
        ext_type = tvb_get_guint8(tvb, offset);
        switch (ext_type) {
        case EXT_FREESPACE_INFO:
            parsed = dissect_uftp_freespace(next_tvb, pinfo, complete_tree);
            break;
        }
        if (!parsed) break;
        extlen_total -= parsed;
        offset += parsed;
    }

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
    if (destcount > 0) {
        destlist = proto_tree_add_item(complete_tree, hf_uftp_destlist, tvb, offset, destcount * 4, ENC_NA);
        destlist_tree = proto_item_add_subtree(destlist, ett_uftp_destlist);
    }
    for (idx = 0; idx < destcount; idx++) {
        proto_tree_add_item(destlist_tree, hf_uftp_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

static void dissect_uftp_doneconf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *destlist = NULL;
    proto_tree *doneconf_tree = NULL;
    proto_tree *destlist_tree = NULL;
    gint offset = 0, hlen;
    guint16 destcount, idx;

    if (tvb_reported_length(tvb) < DONE_CONF_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < DONE_CONF_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_doneconf, tvb, offset, -1, ENC_NA);
    doneconf_tree = proto_item_add_subtree(ti, ett_uftp_doneconf);
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(doneconf_tree, hf_uftp_doneconf_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);

    destcount = (tvb_reported_length(tvb) - hlen) / 4;
    offset = hlen;
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
    gint offset = 0, hlen;
    guint16 keylen, siglen;
    gint8 blobtype;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < HB_REQ_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    keylen = tvb_get_ntohs(tvb, 4);
    siglen = tvb_get_ntohs(tvb, 6);
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < HB_REQ_LEN + keylen + siglen)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d, keylen=%d siglen=%d",
                            tvb_reported_length(tvb), hlen, keylen, siglen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_hbreq, tvb, offset, -1, ENC_NA);
    hbreq_tree = proto_item_add_subtree(ti, ett_uftp_hbreq);
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_bloblen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_siglen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (keylen > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, keylen);
        blobtype = tvb_get_guint8(tvb, offset);
        switch (blobtype) {
        case KEYBLOB_RSA:
            parsed = dissect_uftp_rsablob(next_tvb, pinfo, hbreq_tree, hf_uftp_hbreq_keyblob);
            break;
        case KEYBLOB_EC:
            parsed = dissect_uftp_ecblob(next_tvb, pinfo, hbreq_tree, hf_uftp_hbreq_keyblob);
            break;
        }
        offset += parsed;
    }
    if (siglen > 0) {
        proto_tree_add_item(hbreq_tree, hf_uftp_hbreq_verify, tvb, offset, siglen, ENC_NA);
    }
}

static void dissect_uftp_hbresp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *hbresp_tree = NULL;
    gint offset = 0, hlen;

    if (tvb_reported_length(tvb) < HB_RESP_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < HB_RESP_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_hbresp, tvb, offset, -1, ENC_NA);
    hbresp_tree = proto_item_add_subtree(ti, ett_uftp_hbresp);
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_authenticated, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hbresp_tree, hf_uftp_hbresp_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void dissect_uftp_keyreq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *keyreq_tree = NULL;
    gint offset = 0, hlen;

    if (tvb_reported_length(tvb) < KEY_REQ_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < KEY_REQ_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_keyreq, tvb, offset, -1, ENC_NA);
    keyreq_tree = proto_item_add_subtree(ti, ett_uftp_keyreq);
    proto_tree_add_item(keyreq_tree, hf_uftp_keyreq_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyreq_tree, hf_uftp_keyreq_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(keyreq_tree, hf_uftp_keyreq_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void dissect_uftp_proxykey(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *proxykey_tree = NULL;
    gint offset = 0, hlen;
    guint16 keylen, dhlen, siglen;
    gint8 blobtype;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < PROXY_KEY_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    keylen = tvb_get_ntohs(tvb, 2);
    dhlen = tvb_get_ntohs(tvb, 4);
    siglen = tvb_get_ntohs(tvb, 6);
    if (((gint)tvb_reported_length(tvb) < hlen) ||
            (hlen < PROXY_KEY_LEN + keylen + dhlen + siglen)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                "Invalid length, len = %d, hlen = %d, keylen=%d, dhlen=%d, siglen=%d",
                tvb_reported_length(tvb), hlen, keylen, dhlen, siglen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_proxykey, tvb, offset, -1, ENC_NA);
    proxykey_tree = proto_item_add_subtree(ti, ett_uftp_proxykey);
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_bloblen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_dhlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_siglen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (keylen > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, keylen);
        blobtype = tvb_get_guint8(tvb, offset);
        switch (blobtype) {
        case KEYBLOB_RSA:
            parsed = dissect_uftp_rsablob(next_tvb, pinfo, proxykey_tree, hf_uftp_proxykey_keyblob);
            break;
        case KEYBLOB_EC:
            parsed = dissect_uftp_ecblob(next_tvb, pinfo, proxykey_tree, hf_uftp_proxykey_keyblob);
            break;
        }
        offset += parsed;
    }
    if (dhlen > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, dhlen);
        blobtype = tvb_get_guint8(tvb, offset);
        switch (blobtype) {
        case KEYBLOB_RSA:
            parsed = dissect_uftp_rsablob(next_tvb, pinfo, proxykey_tree, hf_uftp_proxykey_dhblob);
            break;
        case KEYBLOB_EC:
            parsed = dissect_uftp_ecblob(next_tvb, pinfo, proxykey_tree, hf_uftp_proxykey_dhblob);
            break;
        }
        offset += parsed;
    }
    if (siglen > 0) {
        proto_tree_add_item(proxykey_tree, hf_uftp_proxykey_verify, tvb, offset, siglen, ENC_NA);
    }
}

static void dissect_uftp_congctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *cclist = NULL;
    proto_item *ccitem = NULL;
    proto_tree *congctrl_tree = NULL;
    proto_tree *cclist_tree = NULL;
    proto_tree *ccitem_tree = NULL;
    gint offset = 0, hlen;
    guint rate;
    guint8 itemcount, idx;

    if (tvb_reported_length(tvb) < CONG_CTRL_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < CONG_CTRL_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    rate = unquantize_rate(tvb_get_ntohs(tvb, 6));

    ti = proto_tree_add_item(tree, hf_uftp_congctrl, tvb, offset, -1, ENC_NA);
    congctrl_tree = proto_item_add_subtree(ti, ett_uftp_congctrl);
    proto_tree_add_item(congctrl_tree, hf_uftp_congctrl_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(congctrl_tree, hf_uftp_congctrl_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(congctrl_tree, hf_uftp_congctrl_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(congctrl_tree, hf_uftp_congctrl_cc_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_uint(congctrl_tree, hf_uftp_congctrl_cc_rate, tvb, offset, 2, rate);
    offset += 2;
    proto_tree_add_item(congctrl_tree, hf_uftp_congctrl_tstamp, tvb, offset, 8, ENC_TIME_TIMESPEC);

    itemcount = (tvb_reported_length(tvb) - hlen) / CC_ITEM_LEN;
    offset = hlen;
    if (itemcount > 0) {
        cclist = proto_tree_add_item(congctrl_tree, hf_uftp_congctrl_cclist, tvb, offset, itemcount * CC_ITEM_LEN, ENC_NA);
        cclist_tree = proto_item_add_subtree(cclist, ett_uftp_congctrl_cclist);
    }
    for (idx = 0; idx < itemcount; idx++) {
        guint itemrate;
        double itemrtt;
        itemrtt = unquantize_grtt(tvb_get_guint8(tvb, offset + 5));
        itemrate = unquantize_rate(tvb_get_ntohs(tvb, offset + 6));

        ccitem = proto_tree_add_item(cclist_tree, hf_uftp_congctrl_item, tvb, offset, CC_ITEM_LEN, ENC_NA);
        ccitem_tree = proto_item_add_subtree(ccitem, ett_uftp_congctrl_item);
        proto_tree_add_item(ccitem_tree, hf_uftp_congctrl_item_destid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_bitmask(ccitem_tree, tvb, offset, hf_uftp_congctrl_item_flags, ett_uftp_congctrl_item_flags, cc_item_flags, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_double(ccitem_tree, hf_uftp_congctrl_item_rtt, tvb, offset, 1, itemrtt);
        offset += 1;
        proto_tree_add_uint(ccitem_tree, hf_uftp_congctrl_item_rate, tvb, offset, 2, itemrate);
        offset += 2;
    }
}

static void dissect_uftp_ccack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *ccack_tree = NULL;
    gint offset = 0, hlen, extlen_total;
    guint8 ext_type;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < CC_ACK_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < CC_ACK_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_ccack, tvb, offset, -1, ENC_NA);
    ccack_tree = proto_item_add_subtree(ti, ett_uftp_ccack);
    proto_tree_add_item(ccack_tree, hf_uftp_ccack_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ccack_tree, hf_uftp_ccack_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ccack_tree, hf_uftp_ccack_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    extlen_total = hlen - CC_ACK_LEN;
    while (extlen_total > 0) {
        gint parsed = 0;

        next_tvb = tvb_new_subset(tvb, offset, -1, extlen_total);
        ext_type = tvb_get_guint8(tvb, offset);
        switch (ext_type) {
        case EXT_TFMCC_ACK_INFO:
            parsed = dissect_uftp_tfmccack(next_tvb, pinfo, ccack_tree);
            break;
        }
        if (!parsed) break;
        extlen_total -= parsed;
        offset += parsed;
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
    proto_tree_add_item(encrypted_tree, hf_uftp_encrypted_ivctr, tvb, offset, 8, ENC_BIG_ENDIAN);
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
    gint offset = 0, hlen;

    if (tvb_reported_length(tvb) < ABORT_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length: %d", tvb_reported_length(tvb));
        return;
    }

    hlen = (gint)tvb_get_guint8(tvb, 1) * 4;
    if (((gint)tvb_reported_length(tvb) < hlen) || (hlen < ABORT_LEN)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_uftp_length_invalid, tvb, offset, -1,
                            "Invalid length, len = %d, hlen = %d",
                            tvb_reported_length(tvb), hlen);
        return;
    }

    ti = proto_tree_add_item(tree, hf_uftp_abort, tvb, offset, -1, ENC_NA);
    abort_tree = proto_item_add_subtree(ti, ett_uftp_abort);
    proto_tree_add_item(abort_tree, hf_uftp_abort_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(abort_tree, hf_uftp_abort_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_bitmask(abort_tree, tvb, offset, hf_uftp_abort_flags, ett_uftp_abort_flags, abort_flags, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(abort_tree, hf_uftp_abort_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(abort_tree, hf_uftp_abort_clientid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(abort_tree, hf_uftp_abort_message, tvb, offset, -1, ENC_ASCII|ENC_NA);
}

static int dissect_uftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 version;
    guint8 mes_type;
    guint32 group_id;
    tvbuff_t *next_tvb;
    proto_item *ti = NULL;
    proto_tree *uftp_tree = NULL;
    gint offset = 0;
    guint l_gsize;
    double grtt;

    if (tvb_reported_length(tvb) < UFTP_LEN + 4) {
        return 0;
    }

    version = tvb_get_guint8(tvb, 0);
    mes_type = tvb_get_guint8(tvb, 1);
    group_id = tvb_get_ntohl(tvb, 8);

    if (version != UFTP_VER_NUM) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UFTP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%-12s",
                 val_to_str(mes_type, messages, "Unknown (%d)"));
    if ((mes_type != HB_REQ) && (mes_type != HB_RESP)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " ID=%08X", group_id);
    }

    grtt = unquantize_grtt(tvb_get_guint8(tvb, 13));
    l_gsize = unquantize_gsize(tvb_get_guint8(tvb, 14));

    ti = proto_tree_add_item(tree, proto_uftp, tvb, 0, -1, ENC_NA);
    uftp_tree = proto_item_add_subtree(ti, ett_uftp);
    proto_tree_add_item(uftp_tree, hf_uftp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(uftp_tree, hf_uftp_func, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(uftp_tree, hf_uftp_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(uftp_tree, hf_uftp_src_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(uftp_tree, hf_uftp_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(uftp_tree, hf_uftp_group_inst, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_double(uftp_tree, hf_uftp_grtt, tvb, offset, 1, grtt);
    offset += 1;
    proto_tree_add_uint(uftp_tree, hf_uftp_gsize, tvb, offset, 1, l_gsize);
    offset += 1;
    proto_tree_add_item(uftp_tree, hf_uftp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    next_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb) - UFTP_LEN);

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
        case KEYINFO:
            dissect_uftp_keyinfo(next_tvb, pinfo, uftp_tree);
            break;
        case KEYINFO_ACK:
            dissect_uftp_keyinfoack(next_tvb, pinfo, uftp_tree);
            break;
        case FILEINFO:
            dissect_uftp_fileinfo(next_tvb, pinfo, uftp_tree);
            break;
        case FILEINFO_ACK:
            dissect_uftp_fileinfoack(next_tvb, pinfo, uftp_tree);
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
        case CONG_CTRL:
            dissect_uftp_congctrl(next_tvb, pinfo, uftp_tree);
            break;
        case CC_ACK:
            dissect_uftp_ccack(next_tvb, pinfo, uftp_tree);
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

void proto_register_uftp4(void)
{
    static hf_register_info hf[] = {
        { &hf_uftp_version,
            { "Protocol Version", "uftp4.version",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_func,
            { "Type", "uftp4.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_seq,
            { "Sequence Number", "uftp4.seq",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_src_id,
            { "Source ID", "uftp4.src_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_group_id,
            { "Group ID", "uftp4.group_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_group_inst,
            { "Group Instance ID", "uftp4.group_inst",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_grtt,
            { "Group Round Trip Time", "uftp4.grtt",
            FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_gsize,
            { "Group Size", "uftp4.gsize",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_reserved,
            { "Reserved", "uftp4.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_destlist,
            { "Destination List", "uftp4.destlist",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_dest,
            { "Destination", "uftp4.dest",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce,
            { "ANNOUNCE", "uftp4.announce",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_func,
            { "Type", "uftp4.announce.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_hlen,
            { "Header Length", "uftp4.announce.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_flags,
            { "Flags", "uftp4.announce.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_sync,
            { "Sync mode", "uftp4.announce.flags.sync",
            FT_BOOLEAN, 8, NULL, FLAG_SYNC_MODE, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_syncpreview,
            { "Sync preview mode", "uftp4.announce.flags.syncpreview",
            FT_BOOLEAN, 8, NULL, FLAG_SYNC_PREVIEW, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_ipv6,
            { "IPv6", "uftp4.announce.flags.ipv6",
            FT_BOOLEAN, 8, NULL, FLAG_IPV6, NULL, HFILL }
        },
        { &hf_uftp_announce_flags_reserved,
            { "Reserved", "uftp4.announce.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, FLAG_ANNOUNCE_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_announce_robust,
            { "Robustness Factor", "uftp4.announce.robust",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_cc_type,
            { "Congestion Control Type", "uftp4.announce.cc_type",
            FT_UINT8, BASE_DEC, VALS(cc_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_reserved,
            { "Reserved", "uftp4.announce.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_blocksize,
            { "Block Size", "uftp4.announce.blocksize",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_tstamp,
            { "Timestamp", "uftp4.announce.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_publicmcast_ipv4,
            { "Public Multicast Address", "uftp4.announce.publicmcast.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_publicmcast_ipv6,
            { "Public Multicast Address", "uftp4.announce.publicmcast.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_privatemcast_ipv4,
            { "Private Multicast Address", "uftp4.announce.privatemcast.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_announce_privatemcast_ipv6,
            { "Private Multicast Address", "uftp4.announce.privatemcast.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo,
            { "EXT_ENC_INFO", "uftp4.encinfo",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_exttype,
            { "Extension Type", "uftp4.encinfo.exttype",
            FT_UINT8, BASE_DEC, VALS(extensions), 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_extlen,
            { "Extension Length", "uftp4.encinfo.extlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_flags,
            { "Flags", "uftp4.encinfo.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_flags_client_auth,
            { "Client Authorization", "uftp4.encinfo.flags.client_auth",
            FT_BOOLEAN, 8, NULL, FLAG_CLIENT_AUTH, NULL, HFILL }
        },
        { &hf_uftp_encinfo_flags_reserved,
            { "Reserved", "uftp4.encinfo.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, FLAG_ENCINFO_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_encinfo_keyextype,
            { "Key Exchange Type", "uftp4.encinfo.keyextype",
            FT_UINT8, BASE_DEC, VALS(keyexchange_types), 0xF0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_sigtype,
            { "Signature Type", "uftp4.encinfo.sigtype",
            FT_UINT8, BASE_DEC, VALS(signature_types), 0x0F, NULL, HFILL }
        },
        { &hf_uftp_encinfo_keytype,
            { "Key Type", "uftp4.encinfo.keytype",
            FT_UINT8, BASE_DEC, VALS(key_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_hashtype,
            { "Hash Type", "uftp4.encinfo.hashtype",
            FT_UINT8, BASE_DEC, VALS(hash_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_keylen,
            { "Public Key Length", "uftp4.encinfo.keylen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_dhlen,
            { "Diffie-Hellman Key Length", "uftp4.encinfo.dhlen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_siglen,
            { "Signature Length", "uftp4.encinfo.siglen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_rand1,
            { "Server Random Number", "uftp4.encinfo.rand1",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_keyblob,
            { "Public Key Blob", "uftp4.encinfo.keyblob",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_dhblob,
            { "Diffie-Hellman Key Blob", "uftp4.encinfo.dhblob",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encinfo_sig,
            { "Signature", "uftp4.encinfo.sig",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_rsablob_blobtype,
            { "Keyblob Type", "uftp4.rsablob.blobtype",
            FT_UINT8, BASE_DEC, VALS(keyblob_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_rsablob_reserved,
            { "Reserved", "uftp4.rsablob.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_rsablob_modlen,
            { "Modulus Length", "uftp4.rsablob.modlen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_rsablob_exponent,
            { "Exponent", "uftp4.rsablob.exponent",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_rsablob_modulus,
            { "Modulus", "uftp4.rsablob.modulus",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_ecblob_blobtype,
            { "Keyblob Type", "uftp4.ecblob.blobtype",
            FT_UINT8, BASE_DEC, VALS(keyblob_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_ecblob_curve,
            { "Curve", "uftp4.ecblob.curve",
            FT_UINT8, BASE_DEC, VALS(curves), 0x0, NULL, HFILL }
        },
        { &hf_uftp_ecblob_keylen,
            { "Key Length", "uftp4.ecblob.keylen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_ecblob_key,
            { "Key", "uftp4.ecblob.key",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register,
            { "REGISTER", "uftp4.register",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_func,
            { "Type", "uftp4.register.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_hlen,
            { "Header Length", "uftp4.register.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_keyinfo_len,
            { "Key Info Length", "uftp4.register.keyinfo_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_tstamp,
            { "Timestamp", "uftp4.register.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_rand2,
            { "Client Random Number", "uftp4.register.rand2",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_register_keyinfo,
            { "Key Info", "uftp4.register.keyinfo",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey,
            { "CLIENT_KEY", "uftp4.clientkey",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_func,
            { "Type", "uftp4.clientkey.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_hlen,
            { "Header Length", "uftp4.clientkey.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_reserved,
            { "Reserved", "uftp4.clientkey.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_bloblen,
            { "Keyblob Length", "uftp4.clientkey.bloblen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_siglen,
            { "Signature Length", "uftp4.clientkey.siglen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_keyblob,
            { "Public Key Blob", "uftp4.clientkey.keyblob",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_clientkey_verify,
            { "Signature", "uftp4.clientkey.verify",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf,
            { "REG_CONF", "uftp4.regconf",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf_func,
            { "Type", "uftp4.regconf.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf_hlen,
            { "Header Length", "uftp4.regconf.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_regconf_reserved,
            { "Reserved", "uftp4.regconf.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo,
            { "KEYINFO", "uftp4.keyinfo",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_func,
            { "Type", "uftp4.keyinfo.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_hlen,
            { "Header Length", "uftp4.keyinfo.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_reserved,
            { "Reserved", "uftp4.keyinfo.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_ivctr,
            { "IV Counter", "uftp4.keyinfo.ivctr",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_destkey,
            { "Destination Key", "uftp4.keyinfo.destkey",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_destid,
            { "Destination ID", "uftp4.keyinfo.destid",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfo_groupmaster,
            { "Encrypted Group Master", "uftp4.keyinfo.groupmaster",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfoack,
            { "KEYINFO_ACK", "uftp4.keyinfoack",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfoack_func,
            { "Type", "uftp4.keyinfoack.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfoack_hlen,
            { "Header Length", "uftp4.keyinfoack.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfoack_reserved,
            { "Reserved", "uftp4.keyinfoack.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyinfoack_verify_data,
            { "Verify Data", "uftp4.keyinfoack.verify_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo,
            { "FILEINFO", "uftp4.fileinfo",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_func,
            { "Type", "uftp4.fileinfo.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_hlen,
            { "Header Length", "uftp4.fileinfo.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_file_id,
            { "File ID", "uftp4.fileinfo.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_ftype,
            { "File Type", "uftp4.fileinfo.ftype",
            FT_UINT8, BASE_DEC, VALS(file_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_reserved,
            { "Reserved", "uftp4.fileinfo.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_namelen,
            { "Name Length", "uftp4.fileinfo.namelen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_linklen,
            { "Link Length", "uftp4.fileinfo.linklen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_fsize,
            { "File Size", "uftp4.fileinfo.fsize",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_ftstamp,
            { "File Timestamp", "uftp4.fileinfo.ftstamp",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_tstamp,
            { "Timestamp", "uftp4.fileinfo.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_name,
            { "File Name", "uftp4.fileinfo.name",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfo_link,
            { "Link Name", "uftp4.fileinfo.link",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack,
            { "FILEINFO_ACK", "uftp4.fileinfoack",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_func,
            { "Type", "uftp4.fileinfoack.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_hlen,
            { "Header Length", "uftp4.fileinfoack.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_file_id,
            { "File ID", "uftp4.fileinfoack.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_flags,
            { "Flags", "uftp4.fileinfoack.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_flags_partial,
            { "Partial", "uftp4.fileinfoack.flags.partial",
            FT_BOOLEAN, 8, NULL, FLAG_PARTIAL, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_flags_reserved,
            { "Reserved", "uftp4.fileinfoack.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, FLAG_FILEINFOACK_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_reserved,
            { "Reserved", "uftp4.fileinfoack.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileinfoack_tstamp,
            { "Timestamp", "uftp4.fileinfoack.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg,
            { "FILESEG", "uftp4.fileseg",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_func,
            { "Type", "uftp4.fileseg.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_hlen,
            { "Header Length", "uftp4.fileseg.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_file_id,
            { "File ID", "uftp4.fileseg.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_section,
            { "Section", "uftp4.fileseg.section",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_sec_block,
            { "Block", "uftp4.fileseg.sec_block",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccdata,
            { "EXT_TFMCC_DATA_INFO", "uftp4.tfmccdata",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccdata_exttype,
            { "Extension Type", "uftp4.tfmccdata.exttype",
            FT_UINT8, BASE_DEC, VALS(extensions), 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccdata_extlen,
            { "Extension Length", "uftp4.tfmccdata.extlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccdata_send_rate,
            { "Send Rate", "uftp4.tfmccdata.send_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccdata_cc_seq,
            { "CC Sequence Number", "uftp4.tfmccdata.cc_seq",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccdata_cc_rate,
            { "Rate", "uftp4.tfmccdata.cc_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_fileseg_data,
            { "Data", "uftp4.fileseg.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done,
            { "DONE", "uftp4.done",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_func,
            { "Type", "uftp4.done.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_hlen,
            { "Header Length", "uftp4.done.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_file_id,
            { "File ID", "uftp4.done.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_section,
            { "Section", "uftp4.done.section",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_done_reserved,
            { "Reserved", "uftp4.done.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status,
            { "STATUS", "uftp4.status",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_func,
            { "Type", "uftp4.status.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_hlen,
            { "Header Length", "uftp4.status.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_file_id,
            { "File ID", "uftp4.status.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_section,
            { "Section", "uftp4.status.section",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_reserved,
            { "Reserved", "uftp4.status.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_status_naks,
            { "NAKs", "uftp4.status.naks",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete,
            { "COMPLETE", "uftp4.complete",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_func,
            { "Type", "uftp4.complete.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_hlen,
            { "Header Length", "uftp4.complete.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_file_id,
            { "File ID", "uftp4.complete.file_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_status,
            { "Completion Status", "uftp4.complete.status",
            FT_UINT8, BASE_DEC, VALS(comp_status), 0x0, NULL, HFILL }
        },
        { &hf_uftp_complete_reserved,
            { "Reserved", "uftp4.complete.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_freespace,
            { "EXT_FREESPACE_INFO", "uftp4.freespace",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_freespace_exttype,
            { "Extension Type", "uftp4.freespace.exttype",
            FT_UINT8, BASE_DEC, VALS(extensions), 0x0, NULL, HFILL }
        },
        { &hf_uftp_freespace_extlen,
            { "Extension Length", "uftp4.freespace.extlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_freespace_reserved,
            { "Reserved", "uftp4.freespace.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_freespace_freespace,
            { "Free Space", "uftp4.freespace.freespace",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf,
            { "DONE_CONF", "uftp4.doneconf",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_func,
            { "Type", "uftp4.doneconf.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_hlen,
            { "Header Length", "uftp4.doneconf.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_doneconf_reserved,
            { "Reserved", "uftp4.doneconf.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq,
            { "HB_REQ", "uftp4.hbreq",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_func,
            { "Type", "uftp4.hbreq.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_hlen,
            { "Header Length", "uftp4.hbreq.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_reserved,
            { "Reserved", "uftp4.hbreq.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_bloblen,
            { "Keyblob Length", "uftp4.hbreq.bloblen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_siglen,
            { "Signature Length", "uftp4.hbreq.siglen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_nonce,
            { "Nonce", "uftp4.hbreq.nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_keyblob,
            { "Public Key Blob", "uftp4.hbreq.keyblob",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbreq_verify,
            { "Signature", "uftp4.hbreq.verify",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp,
            { "HB_RESP", "uftp4.hbresp",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_func,
            { "Type", "uftp4.hbresp.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_hlen,
            { "Header Length", "uftp4.hbresp.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_authenticated,
            { "Authenticated", "uftp4.hbresp.authenticated",
            FT_UINT8, BASE_DEC, VALS(hb_auth_types), 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_reserved,
            { "Reserved", "uftp4.hbresp.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_hbresp_nonce,
            { "Nonce", "uftp4.hbresp.nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyreq,
            { "KEY_REQ", "uftp4.keyreq",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyreq_func,
            { "Type", "uftp4.keyreq.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyreq_hlen,
            { "Header Length", "uftp4.keyreq.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_keyreq_reserved,
            { "Reserved", "uftp4.keyreq.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey,
            { "PROXY_KEY", "uftp4.proxykey",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_func,
            { "Type", "uftp4.proxykey.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_hlen,
            { "Header Length", "uftp4.proxykey.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_bloblen,
            { "Keyblob Length", "uftp4.proxykey.bloblen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_dhlen,
            { "Diffie-Hellman Keyblob Length", "uftp4.proxykey.dhlen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_siglen,
            { "Signature Length", "uftp4.proxykey.siglen",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_nonce,
            { "Nonce", "uftp4.proxykey.nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_keyblob,
            { "Public Key Blob", "uftp4.proxykey.keyblob",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_dhblob,
            { "Diffie-Hellman Key Blob", "uftp4.proxykey.dhblob",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_proxykey_verify,
            { "Signature", "uftp4.proxykey.verify",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl,
            { "CONG_CTRL", "uftp4.congctrl",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_func,
            { "Type", "uftp4.congctrl.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_hlen,
            { "Header Length", "uftp4.congctrl.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_reserved,
            { "Reserved", "uftp4.congctrl.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_cc_seq,
            { "CC Sequence", "uftp4.congctrl.cc_seq",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_cc_rate,
            { "Rate", "uftp4.congctrl.cc_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_tstamp,
            { "Timestamp", "uftp4.congctrl.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_cclist,
            { "Congestion Control List", "uftp4.congctrl.cclist",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item,
            { "Destination", "uftp4.congctrl.item",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_destid,
            { "Destination ID", "uftp4.congctrl.item.destid",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_flags,
            { "Flags", "uftp4.congctrl.item.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_flags_clr,
            { "CLR", "uftp4.congctrl.item.flags.clr",
            FT_BOOLEAN, 8, NULL, FLAG_CC_CLR, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_flags_rtt,
            { "RTT", "uftp4.congctrl.item.flags.rtt",
            FT_BOOLEAN, 8, NULL, FLAG_CC_RTT, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_flags_start,
            { "Slowstart", "uftp4.congctrl.item.flags.start",
            FT_BOOLEAN, 8, NULL, FLAG_CC_START, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_flags_leave,
            { "Leave", "uftp4.congctrl.item.flags.leave",
            FT_BOOLEAN, 8, NULL, FLAG_CC_LEAVE, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_flags_reserved,
            { "Reserved", "uftp4.congctrl.item.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, FLAG_CC_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_rtt,
            { "Round Trip Time", "uftp4.congctrl.item.rtt",
            FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_congctrl_item_rate,
            { "Rate", "uftp4.congctrl.item.rate",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_ccack,
            { "CC_ACK", "uftp4.ccack",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_ccack_func,
            { "Type", "uftp4.ccack.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_ccack_hlen,
            { "Header Length", "uftp4.ccack.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_ccack_reserved,
            { "Reserved", "uftp4.ccack.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack,
            { "EXT_TFMCC_ACK_INFO", "uftp4.tfmccack",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_exttype,
            { "Extension Type", "uftp4.tfmccack.exttype",
            FT_UINT8, BASE_DEC, VALS(extensions), 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_extlen,
            { "Extension Length", "uftp4.tfmccack.extlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_flags,
            { "Flags", "uftp4.tfmccack.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_flags_clr,
            { "CLR", "uftp4.tfmccack.flags.clr",
            FT_BOOLEAN, 8, NULL, FLAG_CC_CLR, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_flags_rtt,
            { "RTT", "uftp4.tfmccack.flags.rtt",
            FT_BOOLEAN, 8, NULL, FLAG_CC_RTT, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_flags_start,
            { "Slowstart", "uftp4.tfmccack.flags.start",
            FT_BOOLEAN, 8, NULL, FLAG_CC_START, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_flags_leave,
            { "Leave", "uftp4.tfmccack.flags.leave",
            FT_BOOLEAN, 8, NULL, FLAG_CC_LEAVE, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_flags_reserved,
            { "Reserved", "uftp4.tfmccack.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, FLAG_CC_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_reserved,
            { "Reserved", "uftp4.tfmccack.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_cc_seq,
            { "CC Sequence Number", "uftp4.tfmccack.cc_seq",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_cc_rate,
            { "Rate", "uftp4.tfmccack.cc_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_client_id,
            { "Client ID", "uftp4.tfmccack.client_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_tfmccack_tstamp,
            { "Timestamp", "uftp4.tfmccack.tstamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted,
            { "ENCRYPTED", "uftp4.encrypted",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_ivctr,
            { "IV Counter", "uftp4.encrypted.ivctr",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_sig_len,
            { "Signature Length", "uftp4.encrypted.sig_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_payload_len,
            { "Payload Length", "uftp4.encrypted.payload_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_signature,
            { "Signature", "uftp4.encrypted.signature",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_encrypted_payload,
            { "Encrypted Payload", "uftp4.encrypted.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort,
            { "ABORT", "uftp4.abort",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_func,
            { "Type", "uftp4.abort.func",
            FT_UINT8, BASE_DEC, VALS(messages), 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_hlen,
            { "Header Length", "uftp4.abort.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_flags,
            { "Flags", "uftp4.abort.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_flags_curfile,
            { "Current file", "uftp4.abort.flags.curfile",
            FT_BOOLEAN, 8, NULL, FLAG_CURRENT_FILE, NULL, HFILL }
        },
        { &hf_uftp_abort_flags_reserved,
            { "Reserved", "uftp4.abort.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, FLAG_ABORT_RESERVED, NULL, HFILL }
        },
        { &hf_uftp_abort_reserved,
            { "Reserved", "uftp4.abort.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_clientid,
            { "Client ID", "uftp4.abort.clientid",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_uftp_abort_message,
            { "Message", "uftp4.abort.message",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_uftp,
        &ett_uftp_announce,
        &ett_uftp_encinfo,
        &ett_uftp_register,
        &ett_uftp_clientkey,
        &ett_uftp_regconf,
        &ett_uftp_keyinfo,
        &ett_uftp_keyinfo_destkey,
        &ett_uftp_keyinfoack,
        &ett_uftp_fileinfo,
        &ett_uftp_fileinfoack,
        &ett_uftp_fileseg,
        &ett_uftp_tfmccdata,
        &ett_uftp_done,
        &ett_uftp_status,
        &ett_uftp_complete,
        &ett_uftp_freespace,
        &ett_uftp_doneconf,
        &ett_uftp_hbreq,
        &ett_uftp_hbresp,
        &ett_uftp_keyreq,
        &ett_uftp_proxykey,
        &ett_uftp_congctrl,
        &ett_uftp_congctrl_cclist,
        &ett_uftp_congctrl_item,
        &ett_uftp_ccack,
        &ett_uftp_tfmccack,
        &ett_uftp_encrypted,
        &ett_uftp_abort,
        &ett_uftp_announce_flags,
        &ett_uftp_encinfo_flags,
        &ett_uftp_fileinfoack_flags,
        &ett_uftp_abort_flags,
        &ett_uftp_congctrl_item_flags,
        &ett_uftp_tfmccack_flags,
        &ett_uftp_destlist,
        &ett_uftp_rsablob,
        &ett_uftp_ecblob
    };

    static ei_register_info ei[] = {
        { &ei_uftp_length_invalid, { "uftp4.length.invalid", PI_MALFORMED, PI_ERROR, "Length is invalid", EXPFILL }},
        { &ei_uftp_func_unknown, { "uftp4.func.invalid", PI_MALFORMED, PI_ERROR, "Unknown function", EXPFILL }}
    };

    expert_module_t* expert_uftp;

    proto_uftp = proto_register_protocol("UDP based FTP w/ multicast V4",
        "UFTP4", "uftp4");
    proto_register_field_array(proto_uftp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("uftp4", dissect_uftp, proto_uftp);
    expert_uftp = expert_register_protocol(proto_uftp);
    expert_register_field_array(expert_uftp, ei, array_length(ei));
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
