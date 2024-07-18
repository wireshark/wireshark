/* packet-pdcp-lte.c
 * Routines for LTE PDCP
 *
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/proto_data.h>

#include <wsutil/wsgcrypt.h>
#include <wsutil/report_message.h>

/* Define these symbols if you have working implementations of SNOW3G/ZUC f8() and f9() available.
   Note that the use of these algorithms is restricted, so a version of Wireshark with these
   ciphering algorithms enabled would not be distributable. */

/* #define HAVE_SNOW3G */
/* #define HAVE_ZUC */

#include "packet-mac-lte.h"
#include "packet-rlc-lte.h"
#include "packet-pdcp-lte.h"

void proto_register_pdcp_lte(void);
void proto_reg_handoff_pdcp_lte(void);

/* Described in:
 * 3GPP TS 36.323 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Packet Data Convergence Protocol (PDCP) specification v14.3.0
 */


/* TODO:
   - Decipher even if sequence analysis isn't 'OK'?
      - know SN, but might be unsure about HFN.
   - Speed up AES decryption by keeping the crypt handle around for the channel
     (like ESP decryption in IPSEC dissector).  N.B. do lazily when it needs to be used.
     CTR will need to be applied before each frame.
   - Add Relay Node user plane data PDU dissection
   - Add SLRB user data plane data PDU dissection
   - Break out security and sequence analysis into a separate common file to be
     shared with pdcp-nr
*/


/* Initialize the protocol and registered fields. */
int proto_pdcp_lte;

extern int proto_rlc_lte;

/* Configuration (info known outside of PDU) */
static int hf_pdcp_lte_configuration;
static int hf_pdcp_lte_direction;
static int hf_pdcp_lte_ueid;
static int hf_pdcp_lte_channel_type;
static int hf_pdcp_lte_channel_id;

static int hf_pdcp_lte_rohc_compression;
static int hf_pdcp_lte_rohc_mode;
static int hf_pdcp_lte_rohc_rnd;
static int hf_pdcp_lte_rohc_udp_checksum_present;
static int hf_pdcp_lte_rohc_profile;

static int hf_pdcp_lte_no_header_pdu;
static int hf_pdcp_lte_plane;
static int hf_pdcp_lte_seqnum_length;
static int hf_pdcp_lte_cid_inclusion_info;
static int hf_pdcp_lte_large_cid_present;

/* PDCP header fields */
static int hf_pdcp_lte_control_plane_reserved;
static int hf_pdcp_lte_seq_num_5;
static int hf_pdcp_lte_seq_num_7;
static int hf_pdcp_lte_reserved3;
static int hf_pdcp_lte_seq_num_12;
static int hf_pdcp_lte_seq_num_15;
static int hf_pdcp_lte_polling;
static int hf_pdcp_lte_reserved5;
static int hf_pdcp_lte_seq_num_18;
static int hf_pdcp_lte_signalling_data;
static int hf_pdcp_lte_mac;
static int hf_pdcp_lte_data_control;
static int hf_pdcp_lte_user_plane_data;
static int hf_pdcp_lte_control_pdu_type;
static int hf_pdcp_lte_fms;
static int hf_pdcp_lte_reserved4;
static int hf_pdcp_lte_fms2;
static int hf_pdcp_lte_reserved6;
static int hf_pdcp_lte_fms3;
static int hf_pdcp_lte_bitmap;
static int hf_pdcp_lte_bitmap_byte;
static int hf_pdcp_lte_hrw;
static int hf_pdcp_lte_nmp;
static int hf_pdcp_lte_reserved7;
static int hf_pdcp_lte_hrw2;
static int hf_pdcp_lte_nmp2;
static int hf_pdcp_lte_hrw3;
static int hf_pdcp_lte_reserved8;
static int hf_pdcp_lte_nmp3;
static int hf_pdcp_lte_lsn;
static int hf_pdcp_lte_lsn2;
static int hf_pdcp_lte_lsn3;

/* Sequence Analysis */
static int hf_pdcp_lte_sequence_analysis;
static int hf_pdcp_lte_sequence_analysis_ok;
static int hf_pdcp_lte_sequence_analysis_previous_frame;
static int hf_pdcp_lte_sequence_analysis_next_frame;
static int hf_pdcp_lte_sequence_analysis_expected_sn;

static int hf_pdcp_lte_sequence_analysis_repeated;
static int hf_pdcp_lte_sequence_analysis_skipped;

/* Security Settings */
static int hf_pdcp_lte_security;
static int hf_pdcp_lte_security_setup_frame;
static int hf_pdcp_lte_security_integrity_algorithm;
static int hf_pdcp_lte_security_ciphering_algorithm;

static int hf_pdcp_lte_security_bearer;
static int hf_pdcp_lte_security_direction;
static int hf_pdcp_lte_security_count;
static int hf_pdcp_lte_security_cipher_key;
static int hf_pdcp_lte_security_integrity_key;

static int hf_pdcp_lte_security_deciphered_data;

/* Protocol subtree. */
static int ett_pdcp;
static int ett_pdcp_configuration;
static int ett_pdcp_packet;
static int ett_pdcp_lte_sequence_analysis;
static int ett_pdcp_report_bitmap;
static int ett_pdcp_security;

static expert_field ei_pdcp_lte_sequence_analysis_wrong_sequence_number;
static expert_field ei_pdcp_lte_reserved_bits_not_zero;
static expert_field ei_pdcp_lte_sequence_analysis_sn_repeated;
static expert_field ei_pdcp_lte_sequence_analysis_sn_missing;
static expert_field ei_pdcp_lte_digest_wrong;
static expert_field ei_pdcp_lte_unknown_udp_framing_tag;
static expert_field ei_pdcp_lte_missing_udp_framing_tag;


/*-------------------------------------
 * UAT for UE Keys
 *-------------------------------------
 */
/* UAT entry structure. */
typedef struct {
   uint32_t ueid;
   char    *rrcCipherKeyString;
   char    *upCipherKeyString;
   char    *rrcIntegrityKeyString;

   uint8_t  rrcCipherBinaryKey[16];
   bool rrcCipherKeyOK;
   uint8_t  upCipherBinaryKey[16];
   bool upCipherKeyOK;
   uint8_t  rrcIntegrityBinaryKey[16];
   bool rrcIntegrityKeyOK;
} uat_ue_keys_record_t;

/* N.B. this is an array/table of the struct above, where ueid is the key */
static uat_ue_keys_record_t *uat_ue_keys_records;

/* Entries added by UAT */
static uat_t * ue_keys_uat;
static unsigned num_ue_keys_uat;

/* Convert an ascii hex character into a digit.  Should only be given valid
   hex ascii characters */
static unsigned char hex_ascii_to_binary(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    }
    else if ((c >= 'a') && (c <= 'f')) {
        return 10 + c - 'a';
    }
    else if ((c >= 'A') && (c <= 'F')) {
        return 10 + c - 'A';
    }
    else {
        return 0;
    }
}

static void* uat_ue_keys_record_copy_cb(void* n, const void* o, size_t siz _U_) {
    uat_ue_keys_record_t* new_rec = (uat_ue_keys_record_t *)n;
    const uat_ue_keys_record_t* old_rec = (const uat_ue_keys_record_t *)o;

    new_rec->ueid = old_rec->ueid;
    new_rec->rrcCipherKeyString = g_strdup(old_rec->rrcCipherKeyString);
    new_rec->upCipherKeyString = g_strdup(old_rec->upCipherKeyString);
    new_rec->rrcIntegrityKeyString = g_strdup(old_rec->rrcIntegrityKeyString);

    return new_rec;
}

/* If raw_string is a valid key, set check_string & return true.  Can be spaced out with ' ' or '-' */
static bool check_valid_key_string(const char* raw_string, char* checked_string, char **error)
{
    unsigned n;
    unsigned written = 0;
    unsigned length = (int)strlen(raw_string);

    /* Can't be valid if not long enough. */
    if (length < 32) {
        if (length > 0) {
            *error = ws_strdup_printf("PDCP LTE: Invalid key string (%s) - should include 32 ASCII hex characters (16 bytes) but only %u chars given",
                                     raw_string, length);
        }

        return false;
    }

    for (n=0; (n < length) && (written < 32); n++) {
        char c = raw_string[n];

        /* Skipping past allowed 'padding' characters */
        if ((c == ' ') || (c == '-')) {
            continue;
        }

        /* Other characters must be hex digits, otherwise string is invalid */
        if (((c >= '0') && (c <= '9')) ||
            ((c >= 'a') && (c <= 'f')) ||
            ((c >= 'A') && (c <= 'F'))) {
            checked_string[written++] = c;
        }
        else {
            *error = ws_strdup_printf("PDCP-LTE: Invalid char '%c' given in key", c);
            return false;
        }
    }

    /* Must have found exactly 32 hex ascii chars for 16-byte key */
    if (n<length) {
        *error = ws_strdup_printf("PDCP-LTE: Key (%s) should contain 32 hex characters (16 bytes) but more detected", raw_string);
        return false;
    }
    if (written != 32) {
        *error = ws_strdup_printf("PDCP-LTE: Key (%s) should contain 32 hex characters (16 bytes) but %u detected", raw_string, written);
        return false;
    }
    else {
        return true;
    }

}

/* Write binary key by converting each nibble from the string version */
static void update_key_from_string(const char *stringKey, uint8_t *binaryKey, bool *pKeyOK, char **error)
{
    int  n;
    char cleanString[32];

    if (!check_valid_key_string(stringKey, cleanString, error)) {
        *pKeyOK = false;
    }
    else {
        for (n=0; n < 32; n += 2) {
            binaryKey[n/2] = (hex_ascii_to_binary(cleanString[n]) << 4) +
                              hex_ascii_to_binary(cleanString[n+1]);
        }
        *pKeyOK = true;
    }
}

/* Update by checking whether the 3 key strings are valid or not, and storing result */
static bool uat_ue_keys_record_update_cb(void* record, char** error) {
    uat_ue_keys_record_t* rec = (uat_ue_keys_record_t *)record;

    /* Check and convert RRC key */
    update_key_from_string(rec->rrcCipherKeyString, rec->rrcCipherBinaryKey, &rec->rrcCipherKeyOK, error);

    /* Check and convert User-plane key */
    update_key_from_string(rec->upCipherKeyString, rec->upCipherBinaryKey, &rec->upCipherKeyOK, error);

    /* Check and convert Integrity key */
    update_key_from_string(rec->rrcIntegrityKeyString, rec->rrcIntegrityBinaryKey, &rec->rrcIntegrityKeyOK, error);

    /* Return true only if *error has not been set by checking code. */
    return *error == NULL;
}

/* Free heap parts of record */
static void uat_ue_keys_record_free_cb(void*r) {
    uat_ue_keys_record_t* rec = (uat_ue_keys_record_t*)r;

    g_free(rec->rrcCipherKeyString);
    g_free(rec->upCipherKeyString);
    g_free(rec->rrcIntegrityKeyString);
}

UAT_DEC_CB_DEF(uat_ue_keys_records, ueid, uat_ue_keys_record_t)
UAT_CSTRING_CB_DEF(uat_ue_keys_records, rrcCipherKeyString, uat_ue_keys_record_t)
UAT_CSTRING_CB_DEF(uat_ue_keys_records, upCipherKeyString,  uat_ue_keys_record_t)
UAT_CSTRING_CB_DEF(uat_ue_keys_records, rrcIntegrityKeyString,  uat_ue_keys_record_t)


/* Also supporting a hash table with entries from these functions */

/* Table from ueid -> ue_key_entries_t* */
static wmem_map_t *pdcp_security_key_hash;

typedef enum {
    rrc_cipher,
    rrc_integrity,
    up_cipher,
} ue_key_type_t;

typedef struct {
    ue_key_type_t key_type;
    char          *keyString;
    uint8_t       binaryKey[16];
    bool          keyOK;
    uint32_t      setup_frame;
} key_entry_t;

/* List of key entries for an individual UE */
typedef struct {
    #define MAX_KEY_ENTRIES_PER_UE 32
    unsigned    num_entries_set;
    key_entry_t entries[MAX_KEY_ENTRIES_PER_UE];
} ue_key_entries_t;



void set_pdcp_lte_rrc_ciphering_key(uint16_t ueid, const char *key, uint32_t frame_num)
{
    char *err = NULL;

    /* Get or create struct for this UE */
    ue_key_entries_t *key_entries = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                       GUINT_TO_POINTER((unsigned)ueid));
    if (key_entries == NULL) {
        /* Create and add to table */
        key_entries = wmem_new0(wmem_file_scope(), ue_key_entries_t);
        wmem_map_insert(pdcp_security_key_hash, GUINT_TO_POINTER((unsigned)ueid), key_entries);
    }

    if (key_entries->num_entries_set == MAX_KEY_ENTRIES_PER_UE) {
        /* No more room.. */
        return;
    }

    key_entry_t *new_key_entry = &key_entries->entries[key_entries->num_entries_set++];
    new_key_entry->key_type = rrc_cipher;
    new_key_entry->keyString = g_strdup(key);
    new_key_entry->setup_frame = frame_num;
    update_key_from_string(new_key_entry->keyString, new_key_entry->binaryKey, &new_key_entry->keyOK, &err);
    if (err) {
        report_failure("%s: (RRC Ciphering Key)", err);
        g_free(err);
    }
}

void set_pdcp_lte_rrc_integrity_key(uint16_t ueid, const char *key, uint32_t frame_num)
{
    char *err = NULL;

    /* Get or create struct for this UE */
    ue_key_entries_t *key_entries = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                       GUINT_TO_POINTER((unsigned)ueid));
    if (key_entries == NULL) {
        /* Create and add to table */
        key_entries = wmem_new0(wmem_file_scope(), ue_key_entries_t);
        wmem_map_insert(pdcp_security_key_hash, GUINT_TO_POINTER((unsigned)ueid), key_entries);
    }

    if (key_entries->num_entries_set == MAX_KEY_ENTRIES_PER_UE) {
        /* No more room.. */
        return;
    }

    key_entry_t *new_key_entry = &key_entries->entries[key_entries->num_entries_set++];
    new_key_entry->key_type = rrc_integrity;
    new_key_entry->keyString = g_strdup(key);
    new_key_entry->setup_frame = frame_num;
    update_key_from_string(new_key_entry->keyString, new_key_entry->binaryKey, &new_key_entry->keyOK, &err);
    if (err) {
        report_failure("%s: (RRC Ciphering Key)", err);
        g_free(err);
    }
}

void set_pdcp_lte_up_ciphering_key(uint16_t ueid, const char *key, uint32_t frame_num)
{
    char *err = NULL;

    /* Get or create struct for this UE */
    ue_key_entries_t *key_entries = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                       GUINT_TO_POINTER((unsigned)ueid));
    if (key_entries == NULL) {
        /* Create and add to table */
        key_entries = wmem_new0(wmem_file_scope(), ue_key_entries_t);
        wmem_map_insert(pdcp_security_key_hash, GUINT_TO_POINTER((unsigned)ueid), key_entries);
    }

    if (key_entries->num_entries_set == MAX_KEY_ENTRIES_PER_UE) {
        /* No more room.. */
        return;
    }

    key_entry_t *new_key_entry = &key_entries->entries[key_entries->num_entries_set++];
    new_key_entry->key_type = up_cipher;
    new_key_entry->keyString = g_strdup(key);
    new_key_entry->setup_frame = frame_num;
    update_key_from_string(new_key_entry->keyString, new_key_entry->binaryKey, &new_key_entry->keyOK, &err);
    if (err) {
        report_failure("%s: (RRC Ciphering Key)", err);
        g_free(err);
    }
}


/* Preference settings for deciphering and integrity checking. */
static bool global_pdcp_decipher_signalling = true;
static bool global_pdcp_decipher_userplane;  /* Can be slow, so default to false */
static bool global_pdcp_check_integrity = true;
static bool global_pdcp_ignore_sec;          /* Ignore Set Security Algo calls */

/* Use these values where we know the keys but may have missed the algorithm,
   e.g. when handing over and RRCReconfigurationRequest goes to target cell only */
static enum lte_security_ciphering_algorithm_e global_default_ciphering_algorithm = eea0;
static enum lte_security_integrity_algorithm_e global_default_integrity_algorithm = eia0;


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string pdcp_plane_vals[] = {
    { SIGNALING_PLANE,    "Signalling" },
    { USER_PLANE,         "User" },
    { 0,   NULL }
};

static const value_string logical_channel_vals[] = {
    { Channel_DCCH,  "DCCH"},
    { Channel_BCCH,  "BCCH"},
    { Channel_CCCH,  "CCCH"},
    { Channel_PCCH,  "PCCH"},
    { 0,             NULL}
};

static const value_string rohc_mode_vals[] = {
    { UNIDIRECTIONAL,            "Unidirectional" },
    { OPTIMISTIC_BIDIRECTIONAL,  "Optimistic Bidirectional" },
    { RELIABLE_BIDIRECTIONAL,    "Reliable Bidirectional" },
    { 0,   NULL }
};


/* Values taken from:
   http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.txt */
static const value_string rohc_profile_vals[] = {
    { 0x0000,   "ROHC uncompressed" },      /* [RFC5795] */
    { 0x0001,   "ROHC RTP" },               /* [RFC3095] */
    { 0x0002,   "ROHC UDP" },               /* [RFC3095] */
    { 0x0003,   "ROHC ESP" },               /* [RFC3095] */
    { 0x0004,   "ROHC IP" },                /* [RFC3843] */
    { 0x0005,   "ROHC LLA" },               /* [RFC4362] */
    { 0x0006,   "ROHC TCP" },               /* [RFC4996] */
    { 0x0007,   "ROHC RTP/UDP-Lite" },      /* [RFC4019] */
    { 0x0008,   "ROHC UDP-Lite" },          /* [RFC4019] */
    { 0x0101,   "ROHCv2 RTP" },             /* [RFC5225] */
    { 0x0102,   "ROHCv2 UDP" },             /* [RFC5225] */
    { 0x0103,   "ROHCv2 ESP" },             /* [RFC5225] */
    { 0x0104,   "ROHCv2 IP" },              /* [RFC5225] */
    { 0x0105,   "ROHC LLA with R-mode" },   /* [RFC3408] */
    { 0x0107,   "ROHCv2 RTP/UDP-Lite" },    /* [RFC5225] */
    { 0x0108,   "ROHCv2 UDP-Lite" },        /* [RFC5225] */
    { 0,   NULL }
};

static const value_string control_pdu_type_vals[] = {
    { 0,   "PDCP status report" },
    { 1,   "Interspersed ROHC feedback packet" },
    { 2,   "LWA status report" },
    { 3,   "LWA end-marker packet"},
    { 0,   NULL }
};

static const value_string integrity_algorithm_vals[] = {
    { eia0,   "EIA0 (NULL)" },
    { eia1,   "EIA1 (SNOW3G)" },
    { eia2,   "EIA2 (AES)" },
    { eia3,   "EIA3 (ZUC)" },
    { 0,   NULL }
};

static const value_string ciphering_algorithm_vals[] = {
    { eea0,   "EEA0 (NULL)" },
    { eea1,   "EEA1 (SNOW3G)" },
    { eea2,   "EEA2 (AES)" },
    { eea3,   "EEA3 (ZUC)" },
    { 0,   NULL }
};


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t rohc_handle;
static dissector_handle_t lte_rrc_ul_ccch;
static dissector_handle_t lte_rrc_dl_ccch;
static dissector_handle_t lte_rrc_pcch;
static dissector_handle_t lte_rrc_bcch_bch;
static dissector_handle_t lte_rrc_bcch_dl_sch;
static dissector_handle_t lte_rrc_ul_dcch;
static dissector_handle_t lte_rrc_dl_dcch;
static dissector_handle_t lte_rrc_ul_ccch_nb;
static dissector_handle_t lte_rrc_dl_ccch_nb;
static dissector_handle_t lte_rrc_pcch_nb;
static dissector_handle_t lte_rrc_bcch_bch_nb;
static dissector_handle_t lte_rrc_bcch_dl_sch_nb;
static dissector_handle_t lte_rrc_ul_dcch_nb;
static dissector_handle_t lte_rrc_dl_dcch_nb;


#define SEQUENCE_ANALYSIS_RLC_ONLY  1
#define SEQUENCE_ANALYSIS_PDCP_ONLY 2

/* Preference variables */
static bool global_pdcp_dissect_user_plane_as_ip = true;
static bool global_pdcp_dissect_signalling_plane_as_rrc = true;
static int      global_pdcp_check_sequence_numbers = true;
static bool global_pdcp_dissect_rohc;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowRLCLayer, ShowPDCPLayer, ShowTrafficLayer
};
static int      global_pdcp_lte_layer_to_show = (int)ShowRLCLayer;



/**************************************************/
/* Sequence number analysis                       */

/* Channel key */
typedef struct
{
    /* Using bit fields to fit into 32 bits, so avoiding the need to allocate
       heap memory for these structs */
    unsigned        ueId : 16;
    unsigned        plane : 2;
    unsigned        channelId : 6;
    unsigned        direction : 1;
    unsigned        notUsed : 7;
} pdcp_channel_hash_key;

/* Channel state */
typedef struct
{
    uint32_t previousSequenceNumber;
    uint32_t previousFrameNum;
    uint32_t hfn;
} pdcp_channel_status;

/* The sequence analysis channel hash table.
   Maps pdcp_channel_hash_key -> *pdcp_channel_status */
static wmem_map_t *pdcp_sequence_analysis_channel_hash;


/* Hash table types & functions for frame reports */

typedef struct {
    uint32_t        frameNumber;
    uint32_t        SN :       18;
    uint32_t        plane :    2;
    uint32_t        channelId: 5;
    uint32_t        direction: 1;
    uint32_t        notUsed :  6;
} pdcp_result_hash_key;

static int pdcp_result_hash_equal(const void *v, const void *v2)
{
    const pdcp_result_hash_key* val1 = (const pdcp_result_hash_key *)v;
    const pdcp_result_hash_key* val2 = (const pdcp_result_hash_key *)v2;

    /* All fields must match */
    return (memcmp(val1, val2, sizeof(pdcp_result_hash_key)) == 0);
}

/* Compute a hash value for a given key. */
static unsigned pdcp_result_hash_func(const void *v)
{
    const pdcp_result_hash_key* val1 = (const pdcp_result_hash_key *)v;

    /* TODO: This is a bit random.  */
    return val1->frameNumber + (val1->channelId<<7) +
                               (val1->plane<<12) +
                               (val1->SN<<14) +
                               (val1->direction<<6);
}

/* pdcp_channel_hash_key fits into the pointer, so just copy the value into
   a unsigned, cast to a pointer and return that as the key */
static void *get_channel_hash_key(pdcp_channel_hash_key *key)
{
    unsigned  asInt = 0;
    /* TODO: assert that sizeof(pdcp_channel_hash_key) <= sizeof(unsigned) ? */
    memcpy(&asInt, key, sizeof(pdcp_channel_hash_key));
    return GUINT_TO_POINTER(asInt);
}

/* Convenience function to get a pointer for the hash_func to work with */
static void *get_report_hash_key(uint32_t SN, uint32_t frameNumber,
                                    pdcp_lte_info *p_pdcp_lte_info,
                                    bool do_persist)
{
    static pdcp_result_hash_key  key;
    pdcp_result_hash_key        *p_key;

    /* Only allocate a struct when will be adding entry */
    if (do_persist) {
        p_key = wmem_new(wmem_file_scope(), pdcp_result_hash_key);
    }
    else {
        memset(&key, 0, sizeof(pdcp_result_hash_key));
        p_key = &key;
    }

    /* Fill in details, and return pointer */
    p_key->frameNumber = frameNumber;
    p_key->SN = SN;
    p_key->plane = (uint8_t)p_pdcp_lte_info->plane;
    p_key->channelId = p_pdcp_lte_info->channelId;
    p_key->direction = p_pdcp_lte_info->direction;
    p_key->notUsed = 0;

    return p_key;
}


/* Info to attach to frame when first read, recording what to show about sequence */
typedef enum
{
    SN_OK, SN_Repeated, SN_MAC_Retx, SN_Retx, SN_Missing
} sequence_state;
typedef struct
{
    bool sequenceExpectedCorrect;
    uint32_t sequenceExpected;
    uint32_t previousFrameNum;
    uint32_t nextFrameNum;

    uint32_t firstSN;
    uint32_t lastSN;
    uint32_t hfn;

    sequence_state state;
} pdcp_sequence_report_in_frame;

/* The sequence analysis frame report hash table.
   Maps pdcp_result_hash_key* -> pdcp_sequence_report_in_frame* */
static wmem_map_t *pdcp_lte_sequence_analysis_report_hash;

/* Gather together security settings in order to be able to do deciphering */
typedef struct pdu_security_settings_t
{
    enum lte_security_ciphering_algorithm_e ciphering;
    enum lte_security_integrity_algorithm_e integrity;
    uint8_t* cipherKey;
    uint8_t* integrityKey;
    bool cipherKeyValid;
    bool integrityKeyValid;
    uint32_t count;
    uint8_t bearer;
    uint8_t direction;
} pdu_security_settings_t;


static uat_ue_keys_record_t* look_up_keys_record(uint16_t ueid, uint32_t frame_num,
                                                 uint32_t *config_frame_rrc_cipher,
                                                 uint32_t *config_frame_rrc_integrity,
                                                 uint32_t *config_frame_up_cipher)
{
    unsigned int record_id;

    /* Try hash table first (among entries added by set_pdcp_nr_xxx_key() functions) */
    ue_key_entries_t* key_record = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                      GUINT_TO_POINTER((unsigned)ueid));
    if (key_record != NULL) {
        /* Will build up and return usual type */
        uat_ue_keys_record_t *keys = wmem_new0(wmem_file_scope(), uat_ue_keys_record_t);

        /* Fill in details */
        keys->ueid = ueid;
        /* Walk entries backwards (want last entry before frame_num) */
        for (int e=key_record->num_entries_set; e>0; e--) {
            key_entry_t *entry = &key_record->entries[e-1];

            if (frame_num > entry->setup_frame) {
                /* This frame is after corresponding setup, so can adopt if don't have one */
                switch (entry->key_type) {
                    case rrc_cipher:
                        if (!keys->rrcCipherKeyOK) {
                            keys->rrcCipherKeyString = entry->keyString;
                            memcpy(keys->rrcCipherBinaryKey, entry->binaryKey, 16);
                            keys->rrcCipherKeyOK = entry->keyOK;
                            *config_frame_rrc_cipher = entry->setup_frame;
                        }
                        break;
                    case rrc_integrity:
                        if (!keys->rrcIntegrityKeyOK) {
                            keys->rrcIntegrityKeyString = entry->keyString;
                            memcpy(keys->rrcIntegrityBinaryKey, entry->binaryKey, 16);
                            keys->rrcIntegrityKeyOK = entry->keyOK;
                            *config_frame_rrc_integrity = entry->setup_frame;
                        }
                        break;
                    case up_cipher:
                        if (!keys->upCipherKeyOK) {
                            keys->upCipherKeyString = entry->keyString;
                            memcpy(keys->upCipherBinaryKey, entry->binaryKey, 16);
                            keys->upCipherKeyOK = entry->keyOK;
                            *config_frame_up_cipher = entry->setup_frame;
                        }
                        break;
                }
            }
        }
        /* Return this struct (even if doesn't have all/any keys set..) */
        return keys;
    }


    /* Else look up UAT entries. N.B. linear search... */
    for (record_id=0; record_id < num_ue_keys_uat; record_id++) {
        if (uat_ue_keys_records[record_id].ueid == ueid) {
            return &uat_ue_keys_records[record_id];
        }
    }

    /* No match at all - return NULL */
    return NULL;
}

/* Add to the tree values associated with sequence analysis for this frame */
static void addChannelSequenceInfo(pdcp_sequence_report_in_frame *p,
                                   pdcp_lte_info *p_pdcp_lte_info,
                                   uint32_t  sequenceNumber,
                                   packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                                   proto_tree *security_tree,
                                   pdu_security_settings_t *pdu_security)
{
    proto_tree *seqnum_tree;
    proto_item *seqnum_ti;
    proto_item *ti_expected_sn;
    proto_item *ti;
    uat_ue_keys_record_t *keys_record;

    /* Create subtree */
    seqnum_ti = proto_tree_add_string_format(tree,
                                             hf_pdcp_lte_sequence_analysis,
                                             tvb, 0, 0,
                                             "", "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_pdcp_lte_sequence_analysis);
    proto_item_set_generated(seqnum_ti);


    /* Previous channel frame */
    if (p->previousFrameNum != 0) {
        proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_previous_frame,
                            tvb, 0, 0, p->previousFrameNum);
    }

    /* Expected sequence number */
    ti_expected_sn = proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_expected_sn,
                                         tvb, 0, 0, p->sequenceExpected);
    proto_item_set_generated(ti_expected_sn);

    /* Make sure we have recognised SN length */
    switch (p_pdcp_lte_info->seqnum_length) {
        case PDCP_SN_LENGTH_5_BITS:
        case PDCP_SN_LENGTH_7_BITS:
        case PDCP_SN_LENGTH_12_BITS:
        case PDCP_SN_LENGTH_15_BITS:
        case PDCP_SN_LENGTH_18_BITS:
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    switch (p->state) {
        case SN_OK:
            proto_item_set_hidden(ti_expected_sn);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, true);
            proto_item_set_generated(ti);
            proto_item_append_text(seqnum_ti, " - OK");

            /* Link to next SN in channel (if known) */
            if (p->nextFrameNum != 0) {
                proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_next_frame,
                                    tvb, 0, 0, p->nextFrameNum);
            }

            /* May also be able to add key inputs to security tree here */
            if ((pdu_security->ciphering != eea0) ||
                (pdu_security->integrity != eia0)) {

                uint32_t             hfn_multiplier;
                uint32_t             count;
                char                 *cipher_key = NULL;
                char                 *integrity_key = NULL;

                /* BEARER */
                ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_bearer,
                                         tvb, 0, 0, p_pdcp_lte_info->channelId-1);
                proto_item_set_generated(ti);

                pdu_security->bearer = p_pdcp_lte_info->channelId-1;

                /* DIRECTION */
                ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_direction,
                                         tvb, 0, 0, p_pdcp_lte_info->direction);
                proto_item_set_generated(ti);

                /* COUNT (HFN * snLength^2 + SN) */
                switch (p_pdcp_lte_info->seqnum_length) {
                    case PDCP_SN_LENGTH_5_BITS:
                        hfn_multiplier = 32;
                        break;
                    case PDCP_SN_LENGTH_7_BITS:
                        hfn_multiplier = 128;
                        break;
                    case PDCP_SN_LENGTH_12_BITS:
                        hfn_multiplier = 4096;
                        break;
                    case PDCP_SN_LENGTH_15_BITS:
                        hfn_multiplier = 32768;
                        break;
                    case PDCP_SN_LENGTH_18_BITS:
                        hfn_multiplier = 262144;
                        break;
                    default:
                        DISSECTOR_ASSERT_NOT_REACHED();
                        break;
                }
                count = (p->hfn * hfn_multiplier) + sequenceNumber;
                ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_count,
                                         tvb, 0, 0, count);
                proto_item_set_generated(ti);
                pdu_security->count = count;

                /* KEY.  Look this UE up among UEs that have keys configured */
                uint32_t config_frame_rrc_cipher=0, config_frame_rrc_integrity=0,
                        config_frame_up_cipher=0;
                keys_record = look_up_keys_record(p_pdcp_lte_info->ueid, pinfo->num,
                                                  &config_frame_rrc_cipher, &config_frame_rrc_integrity,
                                                  &config_frame_up_cipher);
                if (keys_record != NULL) {
                    if (p_pdcp_lte_info->plane == SIGNALING_PLANE) {
                        /* Get RRC ciphering key */
                        if (keys_record->rrcCipherKeyOK) {
                            cipher_key = keys_record->rrcCipherKeyString;
                            pdu_security->cipherKey = &(keys_record->rrcCipherBinaryKey[0]);
                            pdu_security->cipherKeyValid = true;
                        }
                        /* Get RRC integrity key */
                        if (keys_record->rrcIntegrityKeyOK) {
                            integrity_key = keys_record->rrcIntegrityKeyString;
                            pdu_security->integrityKey = &(keys_record->rrcIntegrityBinaryKey[0]);
                            pdu_security->integrityKeyValid = true;
                        }
                    }
                    else {
                        /* Get userplane ciphering key */
                        if (keys_record->upCipherKeyOK) {
                            cipher_key = keys_record->upCipherKeyString;
                            pdu_security->cipherKey = &(keys_record->upCipherBinaryKey[0]);
                            pdu_security->cipherKeyValid = true;
                        }
                    }

                    /* Show keys where known and valid */
                    if (cipher_key != NULL) {
                        ti = proto_tree_add_string(security_tree, hf_pdcp_lte_security_cipher_key,
                                                   tvb, 0, 0, cipher_key);
                        proto_item_set_generated(ti);
                    }
                    if (integrity_key != NULL) {
                        ti = proto_tree_add_string(security_tree, hf_pdcp_lte_security_integrity_key,
                                                   tvb, 0, 0, integrity_key);
                        proto_item_set_generated(ti);
                    }

                    pdu_security->direction = p_pdcp_lte_info->direction;
                }
            }
            break;

        case SN_Missing:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, false);
            proto_item_set_generated(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_skipped,
                                        tvb, 0, 0, true);
            proto_item_set_generated(ti);
            if (p->lastSN != p->firstSN) {
                expert_add_info_format(pinfo, ti, &ei_pdcp_lte_sequence_analysis_sn_missing,
                                       "PDCP SNs (%u to %u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN, p->lastSN,
                                       val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_lte_info->ueid,
                                       val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                       p_pdcp_lte_info->channelId);
                proto_item_append_text(seqnum_ti, " - SNs missing (%u to %u)",
                                       p->firstSN, p->lastSN);
            }
            else {
                expert_add_info_format(pinfo, ti, &ei_pdcp_lte_sequence_analysis_sn_missing,
                                       "PDCP SN (%u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN,
                                       val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_lte_info->ueid,
                                       val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                       p_pdcp_lte_info->channelId);
                proto_item_append_text(seqnum_ti, " - SN missing (%u)",
                                       p->firstSN);
            }
            break;

        case SN_Repeated:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, false);
            proto_item_set_generated(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_repeated,
                                        tvb, 0, 0, true);
            proto_item_set_generated(ti);
            expert_add_info_format(pinfo, ti, &ei_pdcp_lte_sequence_analysis_sn_repeated,
                                   "PDCP SN (%u) repeated for %s for UE %u (%s-%u)",
                                   p->firstSN,
                                   val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_lte_info->ueid,
                                   val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                   p_pdcp_lte_info->channelId);
            proto_item_append_text(seqnum_ti, "- SN %u Repeated",
                                   p->firstSN);
            break;

        default:
            /* Incorrect sequence number */
            expert_add_info_format(pinfo, ti_expected_sn, &ei_pdcp_lte_sequence_analysis_wrong_sequence_number,
                                   "Wrong Sequence Number for %s on UE %u (%s-%u) - got %u, expected %u",
                                   val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_lte_info->ueid,
                                   val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                   p_pdcp_lte_info->channelId,
                                   sequenceNumber, p->sequenceExpected);
            break;
    }
}


/* Update the channel status and set report for this frame */
static void checkChannelSequenceInfo(packet_info *pinfo, tvbuff_t *tvb,
                                     pdcp_lte_info *p_pdcp_lte_info,
                                     uint32_t sequenceNumber,
                                     proto_tree *tree,
                                     proto_tree *security_tree,
                                     pdu_security_settings_t *pdu_security)
{
    pdcp_channel_hash_key          channel_key;
    pdcp_channel_status           *p_channel_status;
    pdcp_sequence_report_in_frame *p_report_in_frame      = NULL;
    bool                           createdChannel         = false;
    uint32_t                       expectedSequenceNumber = 0;
    uint32_t                       snLimit                = 0;

    /* If find stat_report_in_frame already, use that and get out */
    if (PINFO_FD_VISITED(pinfo)) {
        p_report_in_frame =
            (pdcp_sequence_report_in_frame*)wmem_map_lookup(pdcp_lte_sequence_analysis_report_hash,
                                                            get_report_hash_key(sequenceNumber,
                                                                                pinfo->num,
                                                                                p_pdcp_lte_info, false));
        if (p_report_in_frame != NULL) {
            addChannelSequenceInfo(p_report_in_frame, p_pdcp_lte_info,
                                   sequenceNumber,
                                   pinfo, tree, tvb, security_tree, pdu_security);
            return;
        }
        else {
            /* Give up - we must have tried already... */
            return;
        }
    }


    /**************************************************/
    /* Create or find an entry for this channel state */
    channel_key.ueId = p_pdcp_lte_info->ueid;
    channel_key.plane = p_pdcp_lte_info->plane;
    channel_key.channelId = p_pdcp_lte_info->channelId;
    channel_key.direction = p_pdcp_lte_info->direction;
    channel_key.notUsed = 0;

    /* Do the table lookup */
    p_channel_status = (pdcp_channel_status*)wmem_map_lookup(pdcp_sequence_analysis_channel_hash,
                                                             get_channel_hash_key(&channel_key));

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {
        createdChannel = true;

        /* Allocate a new value and duplicate key contents */
        p_channel_status = wmem_new0(wmem_file_scope(), pdcp_channel_status);

        /* Add entry */
        wmem_map_insert(pdcp_sequence_analysis_channel_hash,
                        get_channel_hash_key(&channel_key), p_channel_status);
    }

    /* Create space for frame state_report */
    p_report_in_frame = wmem_new(wmem_file_scope(), pdcp_sequence_report_in_frame);
    p_report_in_frame->nextFrameNum = 0;

    switch (p_pdcp_lte_info->seqnum_length) {
        case PDCP_SN_LENGTH_5_BITS:
            snLimit = 32;
            break;
        case PDCP_SN_LENGTH_7_BITS:
            snLimit = 128;
            break;
        case PDCP_SN_LENGTH_12_BITS:
            snLimit = 4096;
            break;
        case PDCP_SN_LENGTH_15_BITS:
            snLimit = 32768;
            break;
        case PDCP_SN_LENGTH_18_BITS:
            snLimit = 262144;
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    /* Work out expected sequence number */
    if (!createdChannel) {
        expectedSequenceNumber = (p_channel_status->previousSequenceNumber + 1) % snLimit;
    }
    else {
        expectedSequenceNumber = sequenceNumber;
    }

    /* Set report for this frame */
    /* For PDCP, sequence number is always expectedSequence number */
    p_report_in_frame->sequenceExpectedCorrect = (sequenceNumber == expectedSequenceNumber);
    p_report_in_frame->hfn = p_channel_status->hfn;

    /* For wrong sequence number... */
    if (!p_report_in_frame->sequenceExpectedCorrect) {

        /* Frames are not missing if we get an earlier sequence number again */
        if (((snLimit + expectedSequenceNumber - sequenceNumber) % snLimit) > 15) {
            p_report_in_frame->state = SN_Missing;
            p_report_in_frame->firstSN = expectedSequenceNumber;
            p_report_in_frame->lastSN = (snLimit + sequenceNumber - 1) % snLimit;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;

            /* Update channel status to remember *this* frame */
            p_channel_status->previousFrameNum = pinfo->num;
            p_channel_status->previousSequenceNumber = sequenceNumber;
        }
        else {
            /* An SN has been repeated */
            p_report_in_frame->state = SN_Repeated;
            p_report_in_frame->firstSN = sequenceNumber;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
        }
    }
    else {
        /* SN was OK */
        p_report_in_frame->state = SN_OK;
        p_report_in_frame->sequenceExpected = expectedSequenceNumber;
        p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
        /* SN has rolled around, inc hfn! */
        if (!createdChannel && (sequenceNumber == 0)) {
            /* TODO: not worrying about HFN rolling over for now! */
            p_channel_status->hfn++;
            p_report_in_frame->hfn = p_channel_status->hfn;
        }

        /* Update channel status to remember *this* frame */
        p_channel_status->previousFrameNum = pinfo->num;
        p_channel_status->previousSequenceNumber = sequenceNumber;

        if (p_report_in_frame->previousFrameNum != 0) {
            /* Get report for previous frame */
            pdcp_sequence_report_in_frame *p_previous_report;
            p_previous_report = (pdcp_sequence_report_in_frame*)wmem_map_lookup(pdcp_lte_sequence_analysis_report_hash,
                                                                                get_report_hash_key((sequenceNumber+262144) % 262144,
                                                                                                    p_report_in_frame->previousFrameNum,
                                                                                                    p_pdcp_lte_info,
                                                                                                    false));
            /* It really shouldn't be NULL... */
            if (p_previous_report != NULL) {
                /* Point it forward to this one */
                p_previous_report->nextFrameNum = pinfo->num;
            }
        }
    }

    /* Associate with this frame number */
    wmem_map_insert(pdcp_lte_sequence_analysis_report_hash,
                    get_report_hash_key(sequenceNumber, pinfo->num,
                                        p_pdcp_lte_info, true),
                    p_report_in_frame);

    /* Add state report for this frame into tree */
    addChannelSequenceInfo(p_report_in_frame, p_pdcp_lte_info, sequenceNumber,
                           pinfo, tree, tvb, security_tree, pdu_security);
}



/* Hash table for security state for a UE
   Maps UEId -> pdcp_security_info_t*  */
static wmem_map_t *pdcp_security_hash;

/* Result is (ueid, framenum) -> pdcp_security_info_t*  */
typedef struct  ueid_frame_t {
    uint32_t framenum;
    uint16_t ueid;
} ueid_frame_t;

/* Convenience function to get a pointer for the hash_func to work with */
static void *get_ueid_frame_hash_key(uint16_t ueid, uint32_t frameNumber,
                                        bool do_persist)
{
    static ueid_frame_t  key;
    ueid_frame_t        *p_key;

    /* Only allocate a struct when will be adding entry */
    if (do_persist) {
        p_key = wmem_new(wmem_file_scope(), ueid_frame_t);
    }
    else {
        /* Only looking up, so just use static */
        memset(&key, 0, sizeof(ueid_frame_t));
        p_key = &key;
    }

    /* Fill in details, and return pointer */
    p_key->framenum = frameNumber;
    p_key->ueid = ueid;

    return p_key;
}

static int pdcp_lte_ueid_frame_hash_equal(const void *v, const void *v2)
{
    const ueid_frame_t *ueid_frame_1 = (const ueid_frame_t *)v;
    const ueid_frame_t *ueid_frame_2 = (const ueid_frame_t *)v2;
    return ((ueid_frame_1->framenum == ueid_frame_2->framenum) &&
            (ueid_frame_1->ueid == ueid_frame_2->ueid));
}
static unsigned pdcp_lte_ueid_frame_hash_func(const void *v)
{
    const ueid_frame_t *ueid_frame = (const ueid_frame_t *)v;
    return ueid_frame->framenum + 100*ueid_frame->ueid;
}
static wmem_map_t *pdcp_security_result_hash;




/* Write the given formatted text to:
   - the info column
   - the top-level RLC PDU item */
static void write_pdu_label_and_info(proto_item *pdu_ti,
                                     packet_info *pinfo, const char *format, ...) G_GNUC_PRINTF(3, 4);
static void write_pdu_label_and_info(proto_item *pdu_ti,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];

    va_list ap;

    va_start(ap, format);
    vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    /* TODO: gets called a lot, so a shame there isn't a proto_item_append_string() */
    proto_item_append_text(pdu_ti, "%s", info_buffer);
}



/***************************************************************/



/* Show in the tree the config info attached to this frame, as generated fields */
static void show_pdcp_config(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                             pdcp_lte_info *p_pdcp_info)
{
    proto_item *ti;
    proto_tree *configuration_tree;
    proto_item *configuration_ti = proto_tree_add_item(tree,
                                                       hf_pdcp_lte_configuration,
                                                       tvb, 0, 0, ENC_ASCII);
    configuration_tree = proto_item_add_subtree(configuration_ti, ett_pdcp_configuration);

    /* Direction */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_direction, tvb, 0, 0,
                             p_pdcp_info->direction);
    proto_item_set_generated(ti);

    /* Plane */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_plane, tvb, 0, 0,
                             p_pdcp_info->plane);
    proto_item_set_generated(ti);

    /* UEId */
    if (p_pdcp_info->ueid != 0) {
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_ueid, tvb, 0, 0,
                                 p_pdcp_info->ueid);
        proto_item_set_generated(ti);
    }

    /* Channel type */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_type, tvb, 0, 0,
                             p_pdcp_info->channelType);
    proto_item_set_generated(ti);
    if (p_pdcp_info->channelId != 0) {
        /* Channel type */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_id, tvb, 0, 0,
                                 p_pdcp_info->channelId);
        proto_item_set_generated(ti);
    }


    /* User-plane-specific fields */
    if (p_pdcp_info->plane == USER_PLANE) {

        /* No Header PDU */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_no_header_pdu, tvb, 0, 0,
                                 p_pdcp_info->no_header_pdu);
        proto_item_set_generated(ti);

        if (!p_pdcp_info->no_header_pdu) {

            /* Seqnum length */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_seqnum_length, tvb, 0, 0,
                                     p_pdcp_info->seqnum_length);
            proto_item_set_generated(ti);
        }
    }

    /* ROHC compression */
    ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_lte_rohc_compression, tvb, 0, 0,
                                p_pdcp_info->rohc.rohc_compression);
    proto_item_set_generated(ti);

    /* ROHC-specific settings */
    if (p_pdcp_info->rohc.rohc_compression) {

        /* Show ROHC mode */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_mode, tvb, 0, 0,
                                 p_pdcp_info->rohc.mode);
        proto_item_set_generated(ti);

        /* Show RND */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_rnd, tvb, 0, 0,
                                 p_pdcp_info->rohc.rnd);
        proto_item_set_generated(ti);

        /* UDP Checksum */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_udp_checksum_present, tvb, 0, 0,
                                 p_pdcp_info->rohc.udp_checksum_present);
        proto_item_set_generated(ti);

        /* ROHC profile */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_profile, tvb, 0, 0,
                                 p_pdcp_info->rohc.profile);
        proto_item_set_generated(ti);

        /* CID Inclusion Info */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_cid_inclusion_info, tvb, 0, 0,
                                 p_pdcp_info->rohc.cid_inclusion_info);
        proto_item_set_generated(ti);

        /* Large CID */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_large_cid_present, tvb, 0, 0,
                                 p_pdcp_info->rohc.large_cid_present);
        proto_item_set_generated(ti);
    }

    /* Append summary to configuration root */
    proto_item_append_text(configuration_ti, "(direction=%s, plane=%s",
                           val_to_str_const(p_pdcp_info->direction, direction_vals, "Unknown"),
                           val_to_str_const(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

    if (p_pdcp_info->rohc.rohc_compression) {
        const char *mode = val_to_str_const(p_pdcp_info->rohc.mode, rohc_mode_vals, "Error");
        proto_item_append_text(configuration_ti, ", mode=%c, profile=%s",
                               mode[0],
                               val_to_str_const(p_pdcp_info->rohc.profile, rohc_profile_vals, "Unknown"));
    }
    proto_item_append_text(configuration_ti, ")");
    proto_item_set_generated(configuration_ti);

    /* Show plane in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s: ",
                    val_to_str_const(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

}


/* Look for an RRC dissector for signalling data (using channel type and direction) */
static dissector_handle_t lookup_rrc_dissector_handle(struct pdcp_lte_info  *p_pdcp_info)
{
    dissector_handle_t rrc_handle = 0;

    switch (p_pdcp_info->channelType)
    {
        case Channel_CCCH:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = lte_rrc_ul_ccch;
            }
            else {
                rrc_handle = lte_rrc_dl_ccch;
            }
            break;
        case Channel_PCCH:
            rrc_handle = lte_rrc_pcch;
            break;
        case Channel_BCCH:
            switch (p_pdcp_info->BCCHTransport) {
                case BCH_TRANSPORT:
                    rrc_handle = lte_rrc_bcch_bch;
                    break;
                case DLSCH_TRANSPORT:
                    rrc_handle = lte_rrc_bcch_dl_sch;
                    break;
            }
            break;
        case Channel_DCCH:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = lte_rrc_ul_dcch;
            }
            else {
                rrc_handle = lte_rrc_dl_dcch;
            }
            break;
        case Channel_CCCH_NB:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = lte_rrc_ul_ccch_nb;
            }
            else {
                rrc_handle = lte_rrc_dl_ccch_nb;
            }
            break;
        case Channel_PCCH_NB:
            rrc_handle = lte_rrc_pcch_nb;
            break;
        case Channel_BCCH_NB:
            switch (p_pdcp_info->BCCHTransport) {
                case BCH_TRANSPORT:
                    rrc_handle = lte_rrc_bcch_bch_nb;
                    break;
                case DLSCH_TRANSPORT:
                    rrc_handle = lte_rrc_bcch_dl_sch_nb;
                    break;
            }
            break;
        case Channel_DCCH_NB:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = lte_rrc_ul_dcch_nb;
            }
            else {
                rrc_handle = lte_rrc_dl_dcch_nb;
            }
            break;


        default:
            break;
    }

    return rrc_handle;
}


/* Forward declarations */
static int dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static void report_heur_error(proto_tree *tree, packet_info *pinfo, expert_field *eiindex,
                              tvbuff_t *tvb, int start, int length)
{
    proto_item *ti;
    proto_tree *subtree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-LTE");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_pdcp_lte, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_pdcp);
    proto_tree_add_expert(subtree, pinfo, eiindex, tvb, start, length);
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static bool dissect_pdcp_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data _U_)
{
    int                   offset                 = 0;
    struct pdcp_lte_info *p_pdcp_lte_info;
    tvbuff_t             *pdcp_tvb;
    uint8_t               tag                    = 0;
    bool                  seqnumLengthTagPresent = false;

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of PDCP PDU payload */
    if (tvb_captured_length_remaining(tvb, offset) < (int)(strlen(PDCP_LTE_START_STRING)+3+2)) {
        return false;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, PDCP_LTE_START_STRING, strlen(PDCP_LTE_START_STRING)) != 0) {
        return false;
    }
    offset += (int)strlen(PDCP_LTE_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_pdcp_lte_info = (pdcp_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0);
    if (p_pdcp_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_pdcp_lte_info = wmem_new0(wmem_file_scope(), pdcp_lte_info);

        /* Read fixed fields */
        p_pdcp_lte_info->no_header_pdu = (bool)tvb_get_uint8(tvb, offset++);
        p_pdcp_lte_info->plane = (enum pdcp_plane)tvb_get_uint8(tvb, offset++);
        if (p_pdcp_lte_info->plane == SIGNALING_PLANE) {
            p_pdcp_lte_info->seqnum_length = PDCP_SN_LENGTH_5_BITS;
        }
        p_pdcp_lte_info->rohc.rohc_compression = (bool)tvb_get_uint8(tvb, offset++);

        /* Read optional fields */
        while (tag != PDCP_LTE_PAYLOAD_TAG) {
            /* Process next tag */
            tag = tvb_get_uint8(tvb, offset++);
            switch (tag) {
                case PDCP_LTE_SEQNUM_LENGTH_TAG:
                    p_pdcp_lte_info->seqnum_length = tvb_get_uint8(tvb, offset);
                    offset++;
                    seqnumLengthTagPresent = true;
                    break;
                case PDCP_LTE_DIRECTION_TAG:
                    p_pdcp_lte_info->direction = tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_LOG_CHAN_TYPE_TAG:
                    p_pdcp_lte_info->channelType = (LogicalChannelType)tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_BCCH_TRANSPORT_TYPE_TAG:
                    p_pdcp_lte_info->BCCHTransport = (BCCHTransportType)tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_ROHC_IP_VERSION_TAG:
                    /* RoHC IP version field is now 1 byte only; let's skip most significant byte
                       to keep backward compatibility with existing UDP framing protocol */
                    p_pdcp_lte_info->rohc.rohc_ip_version = tvb_get_uint8(tvb, offset+1);
                    offset += 2;
                    break;
                case PDCP_LTE_ROHC_CID_INC_INFO_TAG:
                    p_pdcp_lte_info->rohc.cid_inclusion_info = tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_ROHC_LARGE_CID_PRES_TAG:
                    p_pdcp_lte_info->rohc.large_cid_present = tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_ROHC_MODE_TAG:
                    p_pdcp_lte_info->rohc.mode = (enum rohc_mode)tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_ROHC_RND_TAG:
                    p_pdcp_lte_info->rohc.rnd = tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_ROHC_UDP_CHECKSUM_PRES_TAG:
                    p_pdcp_lte_info->rohc.udp_checksum_present = tvb_get_uint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_LTE_ROHC_PROFILE_TAG:
                    p_pdcp_lte_info->rohc.profile = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case PDCP_LTE_CHANNEL_ID_TAG:
                    p_pdcp_lte_info->channelId = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case PDCP_LTE_UEID_TAG:
                    p_pdcp_lte_info->ueid = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;

                case PDCP_LTE_PAYLOAD_TAG:
                    /* Have reached data, so get out of loop */
                    p_pdcp_lte_info->pdu_length = tvb_reported_length_remaining(tvb, offset);
                    continue;

                default:
                    /* It must be a recognised tag */
                    report_heur_error(tree, pinfo, &ei_pdcp_lte_unknown_udp_framing_tag, tvb, offset-1, 1);
                    wmem_free(wmem_file_scope(), p_pdcp_lte_info);
                    return true;
            }
        }

        if ((p_pdcp_lte_info->plane == USER_PLANE) && (seqnumLengthTagPresent == false)) {
            /* Conditional field is not present */
            report_heur_error(tree, pinfo, &ei_pdcp_lte_missing_udp_framing_tag, tvb, 0, offset);
            wmem_free(wmem_file_scope(), p_pdcp_lte_info);
            return true;
        }

        /* Store info in packet */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0, p_pdcp_lte_info);
    }
    else {
        offset = tvb_reported_length(tvb) - p_pdcp_lte_info->pdu_length;
    }


    /**************************************/
    /* OK, now dissect as PDCP LTE        */

    /* Create tvb that starts at actual PDCP PDU */
    pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_pdcp_lte(pdcp_tvb, pinfo, tree, data);
    return true;
}

/* Called from control protocol to configure security algorithms for the given UE */
void set_pdcp_lte_security_algorithms(uint16_t ueid, pdcp_lte_security_info_t *security_info)
{
    /* Use for this frame so can check integrity on SecurityCommandRequest frame */
    /* N.B. won't work for internal, non-RRC signalling methods... */
    pdcp_lte_security_info_t *p_frame_security;

    /* Disable this entire sub-routine with the Preference */
    /* Used when the capture is already deciphered */
    if (global_pdcp_ignore_sec) {
        return;
    }

    /* Create or update current settings, by UEID */
    pdcp_lte_security_info_t* ue_security =
        (pdcp_lte_security_info_t*)wmem_map_lookup(pdcp_security_hash,
                                                   GUINT_TO_POINTER((unsigned)ueid));
    if (ue_security == NULL) {
        /* Copy whole security struct */
        ue_security = wmem_new(wmem_file_scope(), pdcp_lte_security_info_t);
        *ue_security = *security_info;

        /* And add into security table */
        wmem_map_insert(pdcp_security_hash, GUINT_TO_POINTER((unsigned)ueid), ue_security);
    }
    else {
        /* Just update existing entry already in table */
        ue_security->previous_configuration_frame = ue_security->configuration_frame;
        ue_security->previous_integrity = ue_security->integrity;
        ue_security->previous_ciphering = ue_security->ciphering;

        ue_security->configuration_frame = security_info->configuration_frame;
        ue_security->integrity = security_info->integrity;
        ue_security->ciphering = security_info->ciphering;
        ue_security->seen_next_ul_pdu = false;
    }

    /* Also add an entry for this PDU already to use these settings, as otherwise it won't be present
       when we query it on the first pass. */
    p_frame_security = wmem_new(wmem_file_scope(), pdcp_lte_security_info_t);
    *p_frame_security = *ue_security;
    wmem_map_insert(pdcp_security_result_hash,
                    get_ueid_frame_hash_key(ueid, ue_security->configuration_frame, true),
                    p_frame_security);
}

/* UE failed to process SecurityModeCommand so go back to previous security settings */
void set_pdcp_lte_security_algorithms_failed(uint16_t ueid)
{
    /* Look up current state by UEID */
    pdcp_lte_security_info_t* ue_security =
        (pdcp_lte_security_info_t*)wmem_map_lookup(pdcp_security_hash,
                                                   GUINT_TO_POINTER((unsigned)ueid));
    if (ue_security != NULL) {
        /* TODO: could remove from table if previous_configuration_frame is 0 */
        /* Go back to previous state */
        ue_security->configuration_frame = ue_security->previous_configuration_frame;
        ue_security->integrity = ue_security->previous_integrity;
        ue_security->ciphering = ue_security->previous_ciphering;
    }
}

/* Reset UE's bearers */
void pdcp_lte_reset_ue_bearers(packet_info *pinfo, uint16_t ueid, bool including_drb_am)
{
    if (PINFO_FD_VISITED(pinfo)) {
        return;
    }

    pdcp_channel_hash_key channel_key;
    pdcp_channel_status  *p_channel_status;

    channel_key.notUsed = 0;
    channel_key.ueId = ueid;
    channel_key.plane = SIGNALING_PLANE;

    /* SRBs (1-2, both directions) */
    for (uint32_t channelId=1; channelId <= 2; ++channelId) {
        for (uint32_t direction=0; direction <=1; ++direction) {
            /* Update key */
            channel_key.channelId = channelId;
            channel_key.direction = direction;

            p_channel_status = (pdcp_channel_status*)wmem_map_lookup(pdcp_sequence_analysis_channel_hash,
                                                                     get_channel_hash_key(&channel_key));
            if (p_channel_status) {
                p_channel_status->hfn = 0;
                p_channel_status->previousFrameNum = 0;
                p_channel_status->previousSequenceNumber = -1;
            }
        }
    }

    /* DRBs (1-32, both directions) */
    channel_key.plane = USER_PLANE;
    for (uint32_t channelId=1; channelId <= 32; ++channelId) {
        for (uint32_t direction=0; direction <=1; ++direction) {
            /* Update key */
            channel_key.channelId = channelId;
            channel_key.direction = direction;

            p_channel_status = (pdcp_channel_status*)wmem_map_lookup(pdcp_sequence_analysis_channel_hash,
                                                                     get_channel_hash_key(&channel_key));
            if (p_channel_status) {
                if (including_drb_am || get_mac_lte_channel_mode(ueid, channelId) == RLC_UM_MODE) {
                    p_channel_status->hfn = 0;
                    p_channel_status->previousFrameNum = 0;
                    p_channel_status->previousSequenceNumber = -1;
                }
            }
        }
    }
}


/* Decipher payload if algorithm is supported and plausible inputs are available */
static tvbuff_t *decipher_payload(tvbuff_t *tvb, packet_info *pinfo, int *offset,
                                  pdu_security_settings_t *pdu_security_settings,
                                  struct pdcp_lte_info *p_pdcp_info, bool will_be_deciphered,
                                  bool *deciphered)
{
    uint8_t* decrypted_data = NULL;
    int payload_length = 0;
    tvbuff_t *decrypted_tvb;

    /* Nothing to do if NULL ciphering */
    if (pdu_security_settings->ciphering == eea0) {
        return tvb;
    }

    /* Nothing to do if don't have valid cipher key */
    if (!pdu_security_settings->cipherKeyValid) {
        return tvb;
    }

    /* Check whether algorithm supported (only drop through and process if we do) */
    if (pdu_security_settings->ciphering == eea1) {
#ifndef HAVE_SNOW3G
        return tvb;
#endif
    }
    else if (pdu_security_settings->ciphering == eea3) {
#ifndef HAVE_ZUC
        return tvb;
#endif
    }
    else if (pdu_security_settings->ciphering != eea2) {
        /* An algorithm we don't support at all! */
        return tvb;
    }

    /* Don't decipher if turned off in preferences */
    if (((p_pdcp_info->plane == SIGNALING_PLANE) &&  !global_pdcp_decipher_signalling) ||
        ((p_pdcp_info->plane == USER_PLANE) &&       !global_pdcp_decipher_userplane)) {
        return tvb;
    }

    /* Don't decipher user-plane control messages */
    if ((p_pdcp_info->plane == USER_PLANE) && ((tvb_get_uint8(tvb, 0) & 0x80) == 0x00)) {
        return tvb;
    }

    /* Don't decipher common control messages */
    if ((p_pdcp_info->plane == SIGNALING_PLANE) && (p_pdcp_info->channelType != Channel_DCCH)) {
        return tvb;
    }

    /* Don't decipher if not yet past SecurityModeResponse */
    if (!will_be_deciphered) {
        return tvb;
    }

    /* AES */
    if (pdu_security_settings->ciphering == eea2) {
        unsigned char ctr_block[16];
        gcry_cipher_hd_t cypher_hd;
        int gcrypt_err;

        /* TS 33.401 B.1.3 */

        /* Set CTR */
        memset(ctr_block, 0, 16);
        /* Only first 5 bytes set */
        ctr_block[0] = (pdu_security_settings->count & 0xff000000) >> 24;
        ctr_block[1] = (pdu_security_settings->count & 0x00ff0000) >> 16;
        ctr_block[2] = (pdu_security_settings->count & 0x0000ff00) >> 8;
        ctr_block[3] = (pdu_security_settings->count & 0x000000ff);
        ctr_block[4] = (pdu_security_settings->bearer << 3) + (pdu_security_settings->direction << 2);

        /* Open gcrypt handle */
        gcrypt_err = gcry_cipher_open(&cypher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0);
        if (gcrypt_err != 0) {
            return tvb;
        }

        /* Set the key */
        gcrypt_err = gcry_cipher_setkey(cypher_hd, pdu_security_settings->cipherKey, 16);
        if (gcrypt_err != 0) {
            gcry_cipher_close(cypher_hd);
            return tvb;
        }

        /* Set the CTR */
        gcrypt_err = gcry_cipher_setctr(cypher_hd, ctr_block, 16);
        if (gcrypt_err != 0) {
            gcry_cipher_close(cypher_hd);
            return tvb;
        }

        /* Extract the encrypted data into a buffer */
        payload_length = tvb_captured_length_remaining(tvb, *offset);
        decrypted_data = (uint8_t *)tvb_memdup(pinfo->pool, tvb, *offset, payload_length);

        /* Decrypt the actual data */
        gcrypt_err = gcry_cipher_decrypt(cypher_hd,
                                         decrypted_data, payload_length,
                                         NULL, 0);
        if (gcrypt_err != 0) {
            gcry_cipher_close(cypher_hd);
            return tvb;
        }

        /* Close gcrypt handle */
        gcry_cipher_close(cypher_hd);
    }

#ifdef HAVE_SNOW3G
    /* SNOW-3G */
    if (pdu_security_settings->ciphering == eea1) {
        /* Extract the encrypted data into a buffer */
        payload_length = tvb_captured_length_remaining(tvb, *offset);
        decrypted_data = (uint8_t *)tvb_memdup(pinfo->pool, tvb, *offset, payload_length);

        /* Do the algorithm */
        snow3g_f8(pdu_security_settings->cipherKey,
                  pdu_security_settings->count,
                  pdu_security_settings->bearer,
                  pdu_security_settings->direction,
                  decrypted_data, payload_length*8);
    }
#endif

#ifdef HAVE_ZUC
    /* ZUC */
    if (pdu_security_settings->ciphering == eea3) {
        /* Extract the encrypted data into a buffer */
        payload_length = tvb_captured_length_remaining(tvb, *offset);
        decrypted_data = (uint8_t *)tvb_memdup(pinfo->pool, tvb, *offset, payload_length);

        /* Do the algorithm.  Assuming implementation works in-place */
        zuc_f8(pdu_security_settings->cipherKey,
               pdu_security_settings->count,
               pdu_security_settings->bearer,
               pdu_security_settings->direction,
               payload_length*8,                   /* Length is in bits */
               (uint32_t*)decrypted_data, (uint32_t*)decrypted_data);
    }
#endif

    /* Create tvb for resulting deciphered sdu */
    decrypted_tvb = tvb_new_child_real_data(tvb, decrypted_data, payload_length, payload_length);
    add_new_data_source(pinfo, decrypted_tvb, "Deciphered Payload");

    /* Return deciphered data, i.e. beginning of new tvb */
    *offset = 0;
    *deciphered = true;
    return decrypted_tvb;
}


/* Try to calculate digest to compare with that found in frame. */
static uint32_t calculate_digest(pdu_security_settings_t *pdu_security_settings, uint8_t header,
                                tvbuff_t *tvb, packet_info *pinfo, int offset, bool *calculated)
{
    *calculated = false;

    if (pdu_security_settings->integrity == eia0) {
        /* Should be zero in this case */
        *calculated = true;
        return 0;
    }

    /* Can't calculate if don't have valid integrity key */
    if (!pdu_security_settings->integrityKeyValid) {
        return 0;
    }

    /* Can only do if indicated in preferences */
    if (!global_pdcp_check_integrity) {
        return 0;
    }

    switch (pdu_security_settings->integrity) {

#ifdef HAVE_SNOW3G
        case eia1:
            {
                /* SNOW3G */
                uint8_t *mac;
                int message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                uint8_t *message_data = (uint8_t *)wmem_alloc0(pinfo->pool, message_length+5);

                /* TS 33.401 B.2.2 */

                /* Data is header byte */
                message_data[0] = header;
                /* Followed by the decrypted message (but not the digest bytes) */
                tvb_memcpy(tvb, message_data+1, offset, message_length);

                mac = (u8*)snow3g_f9(pdu_security_settings->integrityKey,
                                     pdu_security_settings->count,
                                     /* 'Fresh' is the bearer bits then zeros */
                                     pdu_security_settings->bearer << 27,
                                     pdu_security_settings->direction,
                                     message_data,
                                     (message_length+1)*8);

                *calculated = true;
                return ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
            }
#endif

        case eia2:
            {
                /* AES */
                gcry_mac_hd_t mac_hd;
                int gcrypt_err;
                int message_length;
                uint8_t *message_data;
                uint8_t mac[4];
                size_t read_digest_length = 4;

                /* Open gcrypt handle */
                gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
                if (gcrypt_err != 0) {
                    return 0;
                }

                /* Set the key */
                gcrypt_err = gcry_mac_setkey(mac_hd, pdu_security_settings->integrityKey, 16);
                if (gcrypt_err != 0) {
                    gcry_mac_close(mac_hd);
                    return 0;
                }

                /* TS 33.401 B.2.3 */

                /* Extract the encrypted data into a buffer */
                message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                message_data = (uint8_t *)wmem_alloc0(pinfo->pool, message_length+9);
                message_data[0] = (pdu_security_settings->count & 0xff000000) >> 24;
                message_data[1] = (pdu_security_settings->count & 0x00ff0000) >> 16;
                message_data[2] = (pdu_security_settings->count & 0x0000ff00) >> 8;
                message_data[3] = (pdu_security_settings->count & 0x000000ff);
                message_data[4] = (pdu_security_settings->bearer << 3) + (pdu_security_settings->direction << 2);
                /* rest of first 8 bytes are left as zeroes... */
                /* Now the header byte */
                message_data[8] = header;
                /* Followed by the decrypted message (but not the digest bytes) */
                tvb_memcpy(tvb, message_data+9, offset, message_length);

                /* Pass in the message */
                gcrypt_err = gcry_mac_write(mac_hd, message_data, message_length+9);
                if (gcrypt_err != 0) {
                    gcry_mac_close(mac_hd);
                    return 0;
                }

                /* Read out the digest */
                gcrypt_err = gcry_mac_read(mac_hd, mac, &read_digest_length);
                if (gcrypt_err != 0) {
                    gcry_mac_close(mac_hd);
                    return 0;
                }

                /* Now close the mac handle */
                gcry_mac_close(mac_hd);

                *calculated = true;
                return ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
            }
#ifdef HAVE_ZUC
        case eia3:
            {
                /* ZUC */
                uint32_t mac;
                int message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                uint8_t *message_data = (uint8_t *)wmem_alloc0(pinfo->pool, message_length+5);

                /* Data is header byte */
                message_data[0] = header;
                /* Followed by the decrypted message (but not the digest bytes) */
                tvb_memcpy(tvb, message_data+1, offset, message_length);

                zuc_f9(pdu_security_settings->integrityKey,
                       pdu_security_settings->count,
                       pdu_security_settings->direction,
                       pdu_security_settings->bearer,
                       (message_length+1)*8,
                       (uint32_t*)message_data,
                       &mac);

                *calculated = true;
                return mac;
            }
#endif

        default:
            /* Can't calculate */
            *calculated = false;
            return 0;
    }
}

/******************************/
/* Main dissection function.  */
static int dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    const char           *mode;
    proto_tree           *pdcp_tree           = NULL;
    proto_item           *root_ti             = NULL;
    proto_item           *ti                  = NULL;
    int                   offset              = 0;
    struct pdcp_lte_info *p_pdcp_info;
    tvbuff_t             *rohc_tvb            = NULL;
    uint32_t              reserved_value;
    uint32_t              seqnum = 0;

    pdcp_lte_security_info_t *current_security = NULL;   /* current security for this UE */
    pdcp_lte_security_info_t *pdu_security;              /* security in place for this PDU */
    proto_tree *security_tree = NULL;
    proto_item *security_ti;
    tvbuff_t *payload_tvb;
    pdu_security_settings_t  pdu_security_settings;
    bool payload_deciphered = false;

    /* Initialise security settings */
    memset(&pdu_security_settings, 0, sizeof(pdu_security_settings));

    /* Set protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-LTE");

    /* Look for attached packet info! */
    p_pdcp_info = (struct pdcp_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0);
    /* Can't dissect anything without it... */
    if (p_pdcp_info == NULL) {
        return 0;
    }

    /* Don't want to overwrite the RLC Info column if configured not to */
    if ((global_pdcp_lte_layer_to_show == ShowRLCLayer) &&
        (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0) != NULL)) {

        col_set_writable(pinfo->cinfo, COL_INFO, false);
    }
    else {
        /* TODO: won't help with multiple PDCP-or-traffic PDUs / frame... */
        col_clear(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, COL_INFO, true);
    }

    /* Create pdcp tree. */
    if (tree) {
        root_ti = proto_tree_add_item(tree, proto_pdcp_lte, tvb, offset, -1, ENC_NA);
        pdcp_tree = proto_item_add_subtree(root_ti, ett_pdcp);
    }

    /* Set mode string */
    mode = val_to_str_const(p_pdcp_info->rohc.mode, rohc_mode_vals, "Error");

    /*****************************************************/
    /* Show configuration (attached packet) info in tree */
    if (pdcp_tree) {
        show_pdcp_config(pinfo, tvb, pdcp_tree, p_pdcp_info);
    }

    /* Show ROHC mode */
    if (p_pdcp_info->rohc.rohc_compression) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (mode=%c)", mode[0]);
    }

    /***************************************/
    /* UE security algorithms              */
    if (!PINFO_FD_VISITED(pinfo)) {
        /* Look up current state by UEID */
        current_security = (pdcp_lte_security_info_t*)wmem_map_lookup(pdcp_security_hash,
                                                                      GUINT_TO_POINTER((unsigned)p_pdcp_info->ueid));
        if (current_security != NULL) {
            /* Store any result for this frame in the result table */
            pdcp_lte_security_info_t *security_to_store = wmem_new(wmem_file_scope(), pdcp_lte_security_info_t);
            /* Take a deep copy of the settings */
            *security_to_store = *current_security;
            wmem_map_insert(pdcp_security_result_hash,
                            get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->num, true),
                            security_to_store);
        }
        else {
            /* No entry added from RRC, but still use configured defaults */
            if ((global_default_ciphering_algorithm != eea0) ||
                (global_default_integrity_algorithm != eia0)) {
                /* Copy algorithms from preference defaults */
                pdcp_lte_security_info_t *security_to_store = wmem_new0(wmem_file_scope(), pdcp_lte_security_info_t);
                security_to_store->ciphering = global_default_ciphering_algorithm;
                security_to_store->integrity = global_default_integrity_algorithm;
                security_to_store->seen_next_ul_pdu = true;
                wmem_map_insert(pdcp_security_result_hash,
                                get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->num, true),
                                security_to_store);
            }
        }
    }

    /* Show security settings for this PDU */
    pdu_security = (pdcp_lte_security_info_t*)wmem_map_lookup(pdcp_security_result_hash,
                                                              get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->num, false));
    if (pdu_security != NULL) {
        /* Create subtree */
        security_ti = proto_tree_add_string_format(pdcp_tree,
                                                   hf_pdcp_lte_security,
                                                   tvb, 0, 0,
                                                   "", "UE Security");
        security_tree = proto_item_add_subtree(security_ti, ett_pdcp_security);
        proto_item_set_generated(security_ti);

        /* Setup frame */
        if (pinfo->num > pdu_security->configuration_frame) {
            ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_setup_frame,
                                     tvb, 0, 0, pdu_security->configuration_frame);
            proto_item_set_generated(ti);
        }

        /* Ciphering */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_ciphering_algorithm,
                                 tvb, 0, 0, pdu_security->ciphering);
        proto_item_set_generated(ti);

        /* Integrity */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_integrity_algorithm,
                                 tvb, 0, 0, pdu_security->integrity);
        proto_item_set_generated(ti);

        /* Show algorithms in security root */
        proto_item_append_text(security_ti, " (ciphering=%s, integrity=%s)",
                               val_to_str_const(pdu_security->ciphering, ciphering_algorithm_vals, "Unknown"),
                               val_to_str_const(pdu_security->integrity, integrity_algorithm_vals, "Unknown"));

        pdu_security_settings.ciphering = pdu_security->ciphering;
        pdu_security_settings.integrity = pdu_security->integrity;
    }


    /***********************************/
    /* Handle PDCP header (if present) */
    if (!p_pdcp_info->no_header_pdu) {

        seqnum = 0;
        bool seqnum_set = false;

        uint8_t first_byte = tvb_get_uint8(tvb, offset);

        /*****************************/
        /* Signalling plane messages */
        if (p_pdcp_info->plane == SIGNALING_PLANE) {
            /* Verify 3 reserved bits are 0 */
            uint8_t reserved = (first_byte & 0xe0) >> 5;
            ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_control_plane_reserved,
                                     tvb, offset, 1, ENC_BIG_ENDIAN);
            if (reserved != 0) {
                expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                       "PDCP signalling header reserved bits not zero");
            }

            /* 5-bit sequence number */
            proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_seq_num_5, tvb, offset, 1, ENC_BIG_ENDIAN, &seqnum);
            seqnum_set = true;
            write_pdu_label_and_info(root_ti, pinfo, " sn=%-2u ", seqnum);
            offset++;

            if (tvb_captured_length_remaining(tvb, offset) == 0) {
                /* Only PDCP header was captured, stop dissection here */
                return offset;
            }
        }
        else if (p_pdcp_info->plane == USER_PLANE) {

            /**********************************/
            /* User-plane messages            */
            uint8_t pdu_type = (first_byte & 0x80) >> 7;

            /* Data/Control flag */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_data_control, tvb, offset, 1, ENC_BIG_ENDIAN);

            if (pdu_type == 1) {
                /*****************************/
                /* User-plane Data            */

                /* Number of sequence number bits depends upon config */
                switch (p_pdcp_info->seqnum_length) {
                    case PDCP_SN_LENGTH_7_BITS:
                        proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_seq_num_7, tvb, offset, 1, ENC_BIG_ENDIAN, &seqnum);
                        seqnum_set = true;
                        offset++;
                        break;
                    case PDCP_SN_LENGTH_12_BITS:
                        /* 3 reserved bits */
                        ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                        /* Complain if not 0 */
                        if (reserved_value != 0) {
                            expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                   "Reserved bits have value 0x%x - should be 0x0",
                                                   reserved_value);
                        }

                        /* 12-bit sequence number */
                        proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_seq_num_12, tvb, offset, 2, ENC_BIG_ENDIAN, &seqnum);
                        seqnum_set = true;
                        offset += 2;
                        break;
                    case PDCP_SN_LENGTH_15_BITS:
                        proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_seq_num_15, tvb, offset, 2, ENC_BIG_ENDIAN, &seqnum);
                        seqnum_set = true;
                        offset += 2;
                        break;
                    case PDCP_SN_LENGTH_18_BITS:
                        /* Polling bit */
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_polling, tvb, offset, 1, ENC_BIG_ENDIAN);

                        /* 4 reserved bits */
                        ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved5, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                        /* Complain if not 0 */
                        if (reserved_value != 0) {
                            expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                   "Reserved bits have value 0x%x - should be 0x0",
                                                   reserved_value);
                        }

                        /* 18-bit sequence number */
                        proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_seq_num_18, tvb, offset, 3, ENC_BIG_ENDIAN, &seqnum);
                        seqnum_set = true;
                        offset += 3;
                        break;
                    default:
                        /* Not a recognised data format!!!!! */
                        return 1;
                }

                write_pdu_label_and_info(root_ti, pinfo, " (SN=%u)", seqnum);
            }
            else {
                /*******************************/
                /* User-plane Control messages */
                uint32_t control_pdu_type;
                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_control_pdu_type, tvb,
                                             offset, 1, ENC_BIG_ENDIAN, &control_pdu_type);

                switch (control_pdu_type) {
                    case 0:    /* PDCP status report */
                        {
                            uint32_t fms;
                            uint32_t modulo;
                            unsigned   not_received = 0;
                            unsigned   sn, i, j, l;
                            uint32_t len, bit_offset;
                            proto_tree *bitmap_tree;
                            proto_item *bitmap_ti = NULL;
                            char   *buff = NULL;
                            #define BUFF_SIZE 57

                            if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_12_BITS) {
                                /* First-Missing-Sequence SN */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_fms, tvb,
                                                             offset, 2, ENC_BIG_ENDIAN, &fms);
                                sn = (fms + 1) % 4096;
                                offset += 2;
                                modulo = 4096;
                            } else if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_15_BITS) {

                                /* 5 reserved bits */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved4, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved_value);
                                offset++;

                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                /* First-Missing-Sequence SN */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_fms2, tvb,
                                                             offset, 2, ENC_BIG_ENDIAN, &fms);
                                sn = (fms + 1) % 32768;
                                offset += 2;
                                modulo = 32768;
                            } else {
                                /* 2 reserved bits */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved6, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                /* First-Missing-Sequence SN */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_fms3, tvb,
                                                             offset, 3, ENC_BIG_ENDIAN, &fms);
                                sn = (fms + 1) % 262144;
                                offset += 3;
                                modulo = 262144;
                            }

                            /* Bitmap tree */
                            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                                bitmap_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_bitmap, tvb,
                                                                offset, -1, ENC_NA);
                                bitmap_tree = proto_item_add_subtree(bitmap_ti, ett_pdcp_report_bitmap);

                                buff = (char *)wmem_alloc(pinfo->pool, BUFF_SIZE);
                                len = tvb_reported_length_remaining(tvb, offset);
                                bit_offset = offset<<3;

                                /* For each byte... */
                                for (i=0; i<len; i++) {
                                    uint8_t bits = tvb_get_bits8(tvb, bit_offset, 8);
                                    for (l=0, j=0; l<8; l++) {
                                        if ((bits << l) & 0x80) {
                                            if (bitmap_tree) {
                                                j += snprintf(&buff[j], BUFF_SIZE-j, "%6u,", (unsigned)(sn+(8*i)+l)%modulo);
                                            }
                                        } else {
                                            if (bitmap_tree) {
                                                j += (unsigned)g_strlcpy(&buff[j], "      ,", BUFF_SIZE-j);
                                            }
                                            not_received++;
                                        }
                                    }
                                    if (bitmap_tree) {
                                        proto_tree_add_uint_format(bitmap_tree, hf_pdcp_lte_bitmap_byte, tvb, bit_offset/8, 1, bits, "%s", buff);
                                    }
                                    bit_offset += 8;
                                }
                            }

                            if (bitmap_ti != NULL) {
                                proto_item_append_text(bitmap_ti, " (%u SNs not received)", not_received);
                            }
                            write_pdu_label_and_info(root_ti, pinfo, " Status Report (fms=%u) not-received=%u",
                                                    fms, not_received);
                        }
                        return 1;

                    case 1:     /* ROHC Feedback */
                        offset++;
                        break;  /* Drop-through to dissect feedback */


                    case 2:     /* LWA status report */
                        {
                            uint32_t fms;
                            uint32_t nmp;

                            if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_12_BITS) {
                                /* First-Missing-Sequence SN */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_fms, tvb,
                                                             offset, 2, ENC_BIG_ENDIAN, &fms);
                                offset += 2;

                                /* HRW */
                                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_hrw, tvb,
                                                    offset, 2, ENC_BIG_ENDIAN);
                                offset += 1;

                                /* NMP */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_nmp, tvb,
                                                             offset, 2, ENC_BIG_ENDIAN, &nmp);
                                offset += 2;
                            } else if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_15_BITS) {
                                /* 5 reserved bits */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved4, tvb,
                                                                  offset, 2, ENC_BIG_ENDIAN, &reserved_value);
                                offset++;
                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                /* First-Missing-Sequence SN */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_fms2, tvb,
                                                             offset, 2, ENC_BIG_ENDIAN, &fms);
                                offset += 2;

                                /* 1 reserved bit */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved7, tvb,
                                                                  offset, 1, ENC_BIG_ENDIAN, &reserved_value);
                                /* Complain if not 0 */
                                if (reserved_value) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x1 - should be 0x0");
                                }

                                /* HRW */
                                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_hrw2, tvb,
                                                    offset, 2, ENC_BIG_ENDIAN);
                                offset += 2;

                                /* 1 reserved bit */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved7, tvb,
                                                                  offset, 1, ENC_BIG_ENDIAN, &reserved_value);
                                /* Complain if not 0 */
                                if (reserved_value) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x1 - should be 0x0");
                                }

                                /* NMP */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_nmp2, tvb,
                                                    offset, 2, ENC_BIG_ENDIAN, &nmp);
                                offset += 2;
                            } else {
                                /* 2 reserved bits */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved6,
                                                                  tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);
                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                /* First-Missing-Sequence SN */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_fms3, tvb,
                                                             offset, 3, ENC_BIG_ENDIAN, &fms);
                                offset += 3;

                                /* HRW */
                                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_hrw3, tvb,
                                                    offset, 3, ENC_BIG_ENDIAN);
                                offset += 2;

                                /* 4 reserved bits */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved8,
                                                                  tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);
                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                /* NMP */
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_nmp3, tvb,
                                                    offset, 3, ENC_BIG_ENDIAN, &nmp);
                                offset += 3;
                            }

                            write_pdu_label_and_info(root_ti, pinfo, " LWA Status Report (fms=%u) not-received=%u",
                                                     fms, nmp);
                        }
                        return 1;

                    case 3:     /* LWA end-marker packet */
                        {
                            uint32_t lsn;

                            if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_12_BITS) {
                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_lsn, tvb,
                                                             offset, 2, ENC_BIG_ENDIAN, &lsn);
                                offset += 2;
                            } else if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_15_BITS) {
                                /* 5 reserved bits */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved4, tvb,
                                                                  offset, 2, ENC_BIG_ENDIAN, &reserved_value);
                                offset++;
                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_lsn2, tvb,
                                                             offset, 2, ENC_BIG_ENDIAN, &lsn);
                                offset += 2;
                            } else {
                                /* 2 reserved bits */
                                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_reserved6,
                                                                  tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);
                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_lsn3, tvb,
                                                             offset, 3, ENC_BIG_ENDIAN, &lsn);
                                offset += 3;
                            }

                            write_pdu_label_and_info(root_ti, pinfo, " LWA End-Marker Packet (lsn=%u)", lsn);
                        }
                        return 1;
                    default:    /* Reserved */
                        return 1;
                }
            }
        }
        else {
            /* Invalid plane setting...! */
            write_pdu_label_and_info(root_ti, pinfo, " - INVALID PLANE (%u)",
                                     p_pdcp_info->plane);
            return 1;
        }

        /* Do sequence analysis if configured to. */
        if (seqnum_set) {
            bool do_analysis = false;

            switch (global_pdcp_check_sequence_numbers) {
                case false:
                    break;
                case SEQUENCE_ANALYSIS_RLC_ONLY:
                    if ((p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0) != NULL) &&
                        !p_pdcp_info->is_retx) {
                        do_analysis = true;
                    }
                    break;
                case SEQUENCE_ANALYSIS_PDCP_ONLY:
                    if (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0) == NULL) {
                        do_analysis = true;
                    }
                    break;
            }

            if (do_analysis) {
                checkChannelSequenceInfo(pinfo, tvb, p_pdcp_info,
                                         seqnum, pdcp_tree, security_tree,
                                         &pdu_security_settings);
            }
        }
    }
    else {
        /* Show that it's a no-header PDU */
        write_pdu_label_and_info(root_ti, pinfo, " No-Header ");
    }

    /*******************************************************/
    /* Now deal with the payload                           */
    /*******************************************************/

    payload_tvb = decipher_payload(tvb, pinfo, &offset, &pdu_security_settings, p_pdcp_info,
                                   pdu_security ? pdu_security->seen_next_ul_pdu: false, &payload_deciphered);

    /* Add deciphered data as a filterable field */
    if (payload_deciphered) {
        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_security_deciphered_data,
                            payload_tvb, 0, tvb_reported_length(payload_tvb), ENC_NA);
    }

    if (p_pdcp_info->plane == SIGNALING_PLANE) {
        uint32_t data_length;
        uint32_t mac;
        proto_item *mac_ti;
        uint32_t calculated_digest = 0;
        bool digest_was_calculated = false;

        /* Compute payload length (no MAC on common control channels) */
        data_length = tvb_reported_length_remaining(payload_tvb, offset) - ((p_pdcp_info->channelType == Channel_DCCH) ? 4 : 0);

        /* Try to calculate digest so we can check it */
        if (global_pdcp_check_integrity && (p_pdcp_info->channelType == Channel_DCCH)) {
            calculated_digest = calculate_digest(&pdu_security_settings, tvb_get_uint8(tvb, 0), payload_tvb,
                                                 pinfo, offset, &digest_was_calculated);
        }

        /* RRC data is all but last 4 bytes.
           Call lte-rrc dissector (according to direction and channel type) if we have valid data */
        if ((global_pdcp_dissect_signalling_plane_as_rrc) &&
            ((pdu_security == NULL) || (pdu_security->ciphering == eea0) || payload_deciphered || !pdu_security->seen_next_ul_pdu)) {

            /* Get appropriate dissector handle */
            dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info);

            if (rrc_handle != 0) {
                /* Call RRC dissector if have one */
                tvbuff_t *rrc_payload_tvb = tvb_new_subset_length(payload_tvb, offset, data_length);
                bool was_writable = col_get_writable(pinfo->cinfo, COL_INFO);

                /* We always want to see this in the info column */
                col_set_writable(pinfo->cinfo, COL_INFO, true);

                call_dissector_only(rrc_handle, rrc_payload_tvb, pinfo, pdcp_tree, NULL);

                /* Restore to whatever it was */
                col_set_writable(pinfo->cinfo, COL_INFO, was_writable);
            }
            else {
                 /* Just show data */
                 proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, payload_tvb, offset,
                                     data_length, ENC_NA);
            }

            if (!PINFO_FD_VISITED(pinfo) &&
                (current_security != NULL) && !current_security->seen_next_ul_pdu &&
                p_pdcp_info->direction == DIRECTION_UPLINK)
            {
                /* i.e. we have already seen SecurityModeResponse! */
                current_security->seen_next_ul_pdu = true;
            }

        }
        else {
            /* Just show as unparsed data */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, payload_tvb, offset,
                                data_length, ENC_NA);
        }

        offset += data_length;

        if (p_pdcp_info->channelType == Channel_DCCH) {
            /* Last 4 bytes are MAC */
            mac_ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_lte_mac, payload_tvb, offset, 4,
                                                  ENC_BIG_ENDIAN, &mac);
            offset += 4;

            if (digest_was_calculated) {
                /* Compare what was found with calculated value! */
                if (mac != calculated_digest) {
                    expert_add_info_format(pinfo, mac_ti, &ei_pdcp_lte_digest_wrong,
                                           "MAC-I Digest wrong - calculated %08x but found %08x",
                                           calculated_digest, mac);
                    proto_item_append_text(mac_ti, " (but calculated %08x !)", calculated_digest);
                }
                else {
                    proto_item_append_text(mac_ti, " [Matches calculated result]");
                }
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " MAC=0x%08x (%u bytes data)",
                            mac, data_length);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%u bytes data)", data_length);
        }
    }
    else if (tvb_captured_length_remaining(payload_tvb, offset)) {
        /* User-plane payload here */

        /* If not compressed with ROHC, show as user-plane data */
        if (!p_pdcp_info->rohc.rohc_compression) {
            int payload_length = tvb_reported_length_remaining(payload_tvb, offset);
            if (payload_length > 0) {
                if (p_pdcp_info->plane == USER_PLANE) {

                    /* Not attempting to decode payload if ciphering is enabled
                       (and NULL ciphering is not being used) */
                    if (global_pdcp_dissect_user_plane_as_ip &&
                        ((pdu_security == NULL) || (pdu_security->ciphering == eea0) || payload_deciphered))
                    {
                        tvbuff_t *ip_payload_tvb = tvb_new_subset_remaining(payload_tvb, offset);

                        /* Don't update info column for ROHC unless configured to */
                        if (global_pdcp_lte_layer_to_show != ShowTrafficLayer) {
                            col_set_writable(pinfo->cinfo, COL_INFO, false);
                        }

                        switch (tvb_get_uint8(ip_payload_tvb, 0) & 0xf0) {
                            case 0x40:
                                call_dissector_only(ip_handle, ip_payload_tvb, pinfo, pdcp_tree, NULL);
                                break;
                            case 0x60:
                                call_dissector_only(ipv6_handle, ip_payload_tvb, pinfo, pdcp_tree, NULL);
                                break;
                            default:
                                call_data_dissector(ip_payload_tvb, pinfo, pdcp_tree);
                                break;
                        }

                        /* Freeze the columns again because we don't want other layers writing to info */
                        if (global_pdcp_lte_layer_to_show == ShowTrafficLayer) {
                            col_set_writable(pinfo->cinfo, COL_INFO, false);
                        }

                    }
                    else {
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_user_plane_data, payload_tvb, offset, -1, ENC_NA);
                    }
                }

                write_pdu_label_and_info(root_ti, pinfo, "(%u bytes data)",
                                         payload_length);
            }

            /* (there will be no signalling data left at this point) */

            /* Let RLC write to columns again */
            col_set_writable(pinfo->cinfo, COL_INFO, global_pdcp_lte_layer_to_show == ShowRLCLayer);

            /* DROPPING OUT HERE IF NOT DOING ROHC! */
            return tvb_captured_length(tvb);
        }
        else {
            /***************************/
            /* ROHC packets            */
            /***************************/

            /* Only attempt ROHC if configured to */
            if (!global_pdcp_dissect_rohc) {
                col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
                                val_to_str_const(p_pdcp_info->rohc.profile, rohc_profile_vals, "Unknown"));
                return 1;
            }

            rohc_tvb = tvb_new_subset_remaining(payload_tvb, offset);

            /* Only enable writing to column if configured to show ROHC */
            if (global_pdcp_lte_layer_to_show != ShowTrafficLayer) {
                col_set_writable(pinfo->cinfo, COL_INFO, false);
            }
            else {
                col_clear(pinfo->cinfo, COL_INFO);
            }

            /* Call the ROHC dissector */
            call_dissector_with_data(rohc_handle, rohc_tvb, pinfo, tree, &p_pdcp_info->rohc);

            /* Let RLC write to columns again */
            col_set_writable(pinfo->cinfo, COL_INFO, global_pdcp_lte_layer_to_show == ShowRLCLayer);
        }
    }
    return tvb_captured_length(tvb);
}


void proto_register_pdcp_lte(void)
{
    static hf_register_info hf[] =
    {
        { &hf_pdcp_lte_configuration,
            { "Configuration",
              "pdcp-lte.configuration", FT_STRING, BASE_NONE, NULL, 0x0,
              "Configuration info passed into dissector", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_compression,
            { "ROHC Compression",
              "pdcp-lte.rohc.compression", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_mode,
            { "ROHC Mode",
              "pdcp-lte.rohc.mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_rnd,
            { "RND",
              "pdcp-lte.rohc.rnd", FT_UINT8, BASE_DEC, NULL, 0x0,
              "RND of outer ip header", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_udp_checksum_present,
            { "UDP Checksum",
              "pdcp-lte.rohc.checksum-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              "UDP Checksum present", HFILL
            }
        },
        { &hf_pdcp_lte_direction,
            { "Direction",
              "pdcp-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_pdcp_lte_ueid,
            { "UE",
              "pdcp-lte.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "UE Identifier", HFILL
            }
        },
        { &hf_pdcp_lte_channel_type,
            { "Channel type",
              "pdcp-lte.channel-type", FT_UINT8, BASE_DEC, VALS(logical_channel_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_channel_id,
            { "Channel Id",
              "pdcp-lte.channel-id", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_profile,
            { "ROHC profile",
              "pdcp-lte.rohc.profile", FT_UINT16, BASE_DEC, VALS(rohc_profile_vals), 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_lte_no_header_pdu,
            { "No Header PDU",
              "pdcp-lte.no-header_pdu", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_plane,
            { "Plane",
              "pdcp-lte.plane", FT_UINT8, BASE_DEC, VALS(pdcp_plane_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_seqnum_length,
            { "Seqnum length",
              "pdcp-lte.seqnum_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Sequence Number Length", HFILL
            }
        },


        { &hf_pdcp_lte_cid_inclusion_info,
            { "CID Inclusion Info",
              "pdcp-lte.cid-inclusion-info", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_large_cid_present,
            { "Large CID Present",
              "pdcp-lte.large-cid-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_control_plane_reserved,
            { "Reserved",
              "pdcp-lte.reserved", FT_UINT8, BASE_DEC, NULL, 0xe0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_5,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT8, BASE_DEC, NULL, 0x1f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_7,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT8, BASE_DEC, NULL, 0x7f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_reserved3,
            { "Reserved",
              "pdcp-lte.reserved3", FT_UINT8, BASE_HEX, NULL, 0x70,
              "3 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_12,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_15,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT16, BASE_DEC, NULL, 0x7fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_polling,
            { "Polling",
              "pdcp-lte.polling", FT_BOOLEAN, 8, NULL, 0x40,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_reserved5,
            { "Reserved",
              "pdcp-lte.reserved5", FT_UINT8, BASE_HEX, NULL, 0x3c,
              "4 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_18,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT24, BASE_DEC, NULL, 0x03ffff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_signalling_data,
            { "Signalling Data",
              "pdcp-lte.signalling-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_mac,
            { "MAC",
              "pdcp-lte.mac", FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_data_control,
            { "PDU Type",
              "pdcp-lte.pdu-type", FT_BOOLEAN, 8, TFS(&tfs_data_pdu_control_pdu), 0x80,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_user_plane_data,
            { "User-Plane Data",
              "pdcp-lte.user-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_control_pdu_type,
            { "Control PDU Type",
              "pdcp-lte.control-pdu-type", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_fms,
            { "First Missing Sequence Number",
              "pdcp-lte.fms", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "First Missing PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_reserved4,
            { "Reserved",
              "pdcp-lte.reserved4", FT_UINT16, BASE_HEX, NULL, 0x0f80,
              "5 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_fms2,
            { "First Missing Sequence Number",
              "pdcp-lte.fms", FT_UINT16, BASE_DEC, NULL, 0x7fff,
              "First Missing PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_reserved6,
            { "Reserved",
              "pdcp-lte.reserved6", FT_UINT8, BASE_HEX, NULL, 0x0c,
              "2 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_fms3,
            { "First Missing Sequence Number",
              "pdcp-lte.fms", FT_UINT24, BASE_DEC, NULL, 0x03ffff,
              "First Missing PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap,
            { "Bitmap",
              "pdcp-lte.bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Status report bitmap (0=error, 1=OK)", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap_byte,
            { "Bitmap byte",
              "pdcp-lte.bitmap.byte", FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_hrw,
            { "Highest Received Sequence Number on WLAN",
              "pdcp-lte.hwr", FT_UINT16, BASE_DEC, NULL, 0xfff0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_nmp,
            { "Number of Missing PDCP SDUs",
              "pdcp-lte.nmp", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_reserved7,
            { "Reserved",
              "pdcp-lte.reserved7", FT_UINT8, BASE_HEX, NULL, 0x80,
              "1 reserved bit", HFILL
            }
        },
        { &hf_pdcp_lte_hrw2,
            { "Highest Received Sequence Number on WLAN",
              "pdcp-lte.hwr", FT_UINT16, BASE_DEC, NULL, 0x7fff,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_nmp2,
            { "Number of Missing PDCP SDUs",
              "pdcp-lte.nmp", FT_UINT16, BASE_DEC, NULL, 0x7fff,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_hrw3,
            { "Highest Received Sequence Number on WLAN",
              "pdcp-lte.hwr", FT_UINT24, BASE_DEC, NULL, 0xffffc0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_reserved8,
            { "Reserved",
              "pdcp-lte.reserved8", FT_UINT8, BASE_HEX, NULL, 0x3c,
              "4 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_nmp3,
            { "Number of Missing PDCP SDUs",
              "pdcp-lte.nmp", FT_UINT24, BASE_DEC, NULL, 0x03ffff,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_lsn,
            { "Last PDCP PDU SN ciphered with previous key",
              "pdcp-lte.lsn", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_lsn2,
            { "Last PDCP PDU SN ciphered with previous key",
              "pdcp-lte.lsn", FT_UINT16, BASE_DEC, NULL, 0x7fff,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_lsn3,
            { "Last PDCP PDU SN ciphered with previous key",
              "pdcp-lte.lsn", FT_UINT24, BASE_DEC, NULL, 0x03ffff,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_sequence_analysis,
            { "Sequence Analysis",
              "pdcp-lte.sequence-analysis", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_ok,
            { "OK",
              "pdcp-lte.sequence-analysis.ok", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_previous_frame,
            { "Previous frame for channel",
              "pdcp-lte.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_next_frame,
            { "Next frame for channel",
              "pdcp-lte.sequence-analysis.next-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_expected_sn,
            { "Expected SN",
              "pdcp-lte.sequence-analysis.expected-sn", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_skipped,
            { "Skipped frames",
              "pdcp-lte.sequence-analysis.skipped-frames", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_repeated,
            { "Repeated frame",
              "pdcp-lte.sequence-analysis.repeated-frame", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        /* Security fields */
        { &hf_pdcp_lte_security,
            { "Security Config",
              "pdcp-lte.security-config", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_setup_frame,
            { "Configuration frame",
              "pdcp-lte.security-config.setup-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_integrity_algorithm,
            { "Integrity Algorithm",
              "pdcp-lte.security-config.integrity", FT_UINT16, BASE_DEC, VALS(integrity_algorithm_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_ciphering_algorithm,
            { "Ciphering Algorithm",
              "pdcp-lte.security-config.ciphering", FT_UINT16, BASE_DEC, VALS(ciphering_algorithm_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_bearer,
            { "BEARER",
              "pdcp-lte.security-config.bearer", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_direction,
            { "DIRECTION",
              "pdcp-lte.security-config.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_count,
            { "COUNT",
              "pdcp-lte.security-config.count", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_cipher_key,
            { "CIPHER KEY",
              "pdcp-lte.security-config.cipher-key", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_integrity_key,
            { "INTEGRITY KEY",
              "pdcp-lte.security-config.integrity-key", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_deciphered_data,
            { "Deciphered Data",
              "pdcp-lte.deciphered-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        }
    };

    static int *ett[] =
    {
        &ett_pdcp,
        &ett_pdcp_configuration,
        &ett_pdcp_packet,
        &ett_pdcp_lte_sequence_analysis,
        &ett_pdcp_report_bitmap,
        &ett_pdcp_security
    };

    static ei_register_info ei[] = {
        { &ei_pdcp_lte_sequence_analysis_sn_missing, { "pdcp-lte.sequence-analysis.sn-missing", PI_SEQUENCE, PI_WARN, "PDCP SN missing", EXPFILL }},
        { &ei_pdcp_lte_sequence_analysis_sn_repeated, { "pdcp-lte.sequence-analysis.sn-repeated", PI_SEQUENCE, PI_WARN, "PDCP SN repeated", EXPFILL }},
        { &ei_pdcp_lte_sequence_analysis_wrong_sequence_number, { "pdcp-lte.sequence-analysis.wrong-sequence-number", PI_SEQUENCE, PI_WARN, "Wrong Sequence Number", EXPFILL }},
        { &ei_pdcp_lte_reserved_bits_not_zero, { "pdcp-lte.reserved-bits-not-zero", PI_MALFORMED, PI_ERROR, "Reserved bits not zero", EXPFILL }},
        { &ei_pdcp_lte_digest_wrong, { "pdcp-lte.maci-wrong", PI_SEQUENCE, PI_ERROR, "MAC-I doesn't match expected value", EXPFILL }},
        { &ei_pdcp_lte_unknown_udp_framing_tag, { "pdcp-lte.unknown-udp-framing-tag", PI_UNDECODED, PI_WARN, "Unknown UDP framing tag, aborting dissection", EXPFILL }},
        { &ei_pdcp_lte_missing_udp_framing_tag, { "pdcp-lte.missing-udp-framing-tag", PI_UNDECODED, PI_WARN, "Missing UDP framing conditional tag, aborting dissection", EXPFILL }}
    };

    static const enum_val_t sequence_analysis_vals[] = {
        {"no-analysis", "No-Analysis",      false},
        {"rlc-only",    "Only-RLC-frames",  SEQUENCE_ANALYSIS_RLC_ONLY},
        {"pdcp-only",   "Only-PDCP-frames", SEQUENCE_ANALYSIS_PDCP_ONLY},
        {NULL, NULL, -1}
    };

    static const enum_val_t show_info_col_vals[] = {
        {"show-rlc", "RLC Info", ShowRLCLayer},
        {"show-pdcp", "PDCP Info", ShowPDCPLayer},
        {"show-traffic", "Traffic Info", ShowTrafficLayer},
        {NULL, NULL, -1}
    };

    static const enum_val_t default_ciphering_algorithm_vals[] = {
        {"eea0", "EEA0 (NULL)",   eea0},
        {"eea1", "EEA1 (SNOW3G)", eea1},
        {"eea2", "EEA2 (AES)",    eea2},
        {"eea3", "EEA3 (ZUC)",    eea3},
        {NULL, NULL, -1}
    };

    static const enum_val_t default_integrity_algorithm_vals[] = {
        {"eia0", "EIA0 (NULL)",   eia0},
        {"eia1", "EIA1 (SNOW3G)", eia1},
        {"eia2", "EIA2 (AES)",    eia2},
        {"eia3", "EIA3 (ZUC)",    eia3},
        {NULL, NULL, -1}
    };

  static uat_field_t ue_keys_uat_flds[] = {
      UAT_FLD_DEC(uat_ue_keys_records, ueid, "UEId", "UE Identifier of UE associated with keys"),
      UAT_FLD_CSTRING(uat_ue_keys_records, rrcCipherKeyString, "RRC Cipher Key",        "Key for deciphering signalling messages"),
      UAT_FLD_CSTRING(uat_ue_keys_records, upCipherKeyString,  "User-Plane Cipher Key", "Key for deciphering user-plane messages"),
      UAT_FLD_CSTRING(uat_ue_keys_records, rrcIntegrityKeyString,  "RRC Integrity Key", "Key for calculating integrity MAC"),
      UAT_END_FIELDS
    };

    module_t *pdcp_lte_module;
    expert_module_t* expert_pdcp_lte;

    /* Register protocol. */
    proto_pdcp_lte = proto_register_protocol("PDCP-LTE", "PDCP-LTE", "pdcp-lte");
    proto_register_field_array(proto_pdcp_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pdcp_lte = expert_register_protocol(proto_pdcp_lte);
    expert_register_field_array(expert_pdcp_lte, ei, array_length(ei));

    /* Allow other dissectors to find this one by name. */
    register_dissector("pdcp-lte", dissect_pdcp_lte, proto_pdcp_lte);

    pdcp_lte_module = prefs_register_protocol(proto_pdcp_lte, NULL);

    /* Obsolete preferences */
    prefs_register_obsolete_preference(pdcp_lte_module, "show_feedback_option_tag_length");

    /* Dissect uncompressed user-plane data as IP */
    prefs_register_bool_preference(pdcp_lte_module, "show_user_plane_as_ip",
        "Show uncompressed User-Plane data as IP",
        "Show uncompressed User-Plane data as IP",
        &global_pdcp_dissect_user_plane_as_ip);

    /* Dissect unciphered signalling data as RRC */
    prefs_register_bool_preference(pdcp_lte_module, "show_signalling_plane_as_rrc",
        "Show unciphered Signalling-Plane data as RRC",
        "Show unciphered Signalling-Plane data as RRC",
        &global_pdcp_dissect_signalling_plane_as_rrc);

    /* Check for missing sequence numbers */
    prefs_register_enum_preference(pdcp_lte_module, "check_sequence_numbers",
        "Do sequence number analysis",
        "Do sequence number analysis",
        &global_pdcp_check_sequence_numbers, sequence_analysis_vals, false);

    /* Attempt to dissect ROHC messages */
    prefs_register_bool_preference(pdcp_lte_module, "dissect_rohc",
        "Attempt to decode ROHC data",
        "Attempt to decode ROHC data",
        &global_pdcp_dissect_rohc);

    prefs_register_obsolete_preference(pdcp_lte_module, "heuristic_pdcp_lte_over_udp");

    prefs_register_enum_preference(pdcp_lte_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show RLC, PDCP or Traffic layer info in Info column",
        &global_pdcp_lte_layer_to_show, show_info_col_vals, false);

    ue_keys_uat = uat_new("PDCP UE security keys",
              sizeof(uat_ue_keys_record_t),    /* record size */
              "pdcp_lte_ue_keys",              /* filename */
              true,                            /* from_profile */
              &uat_ue_keys_records,            /* data_ptr */
              &num_ue_keys_uat,                /* numitems_ptr */
              UAT_AFFECTS_DISSECTION,          /* affects dissection of packets, but not set of named fields */
              NULL,                            /* help */
              uat_ue_keys_record_copy_cb,      /* copy callback */
              uat_ue_keys_record_update_cb,    /* update callback */
              uat_ue_keys_record_free_cb,      /* free callback */
              NULL,                            /* post update callback */
              NULL,                            /* reset callback */
              ue_keys_uat_flds);               /* UAT field definitions */

    prefs_register_uat_preference(pdcp_lte_module,
                                  "ue_keys_table",
                                  "PDCP UE Keys",
                                  "Preconfigured PDCP keys",
                                  ue_keys_uat);

    prefs_register_enum_preference(pdcp_lte_module, "default_ciphering_algorithm",
        "Ciphering algorithm to use if not signalled",
        "If RRC Security Info not seen, e.g. in Handover",
        (int*)&global_default_ciphering_algorithm, default_ciphering_algorithm_vals, false);

    prefs_register_enum_preference(pdcp_lte_module, "default_integrity_algorithm",
        "Integrity algorithm to use if not signalled",
        "If RRC Security Info not seen, e.g. in Handover",
        (int*)&global_default_integrity_algorithm, default_integrity_algorithm_vals, false);

    /* Attempt to decipher RRC messages */
    prefs_register_bool_preference(pdcp_lte_module, "decipher_signalling",
        "Attempt to decipher Signalling (RRC) SDUs",
        "N.B. only possible if build with algorithm support, and have key available and configured",
        &global_pdcp_decipher_signalling);

    /* Attempt to decipher user-plane messages */
    prefs_register_bool_preference(pdcp_lte_module, "decipher_userplane",
        "Attempt to decipher User-plane (IP) SDUs",
        "N.B. only possible if build with algorithm support, and have key available and configured",
        &global_pdcp_decipher_userplane);

    /* Attempt to verify RRC integrity/authentication digest */
    prefs_register_bool_preference(pdcp_lte_module, "verify_integrity",
        "Attempt to check integrity calculation",
        "N.B. only possible if build with algorithm support, and have key available and configured",
        &global_pdcp_check_integrity);

    prefs_register_bool_preference(pdcp_lte_module, "ignore_rrc_sec_params",
        "Ignore RRC security parameters",
        "Ignore the LTE RRC security algorithm configuration, to be used when PDCP is already deciphered in the capture",
        &global_pdcp_ignore_sec);

    pdcp_sequence_analysis_channel_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    pdcp_lte_sequence_analysis_report_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pdcp_result_hash_func, pdcp_result_hash_equal);
    pdcp_security_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    pdcp_security_result_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pdcp_lte_ueid_frame_hash_func, pdcp_lte_ueid_frame_hash_equal);
    pdcp_security_key_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void proto_reg_handoff_pdcp_lte(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_pdcp_lte_heur, "PDCP-LTE over UDP", "pdcp_lte_udp", proto_pdcp_lte, HEURISTIC_DISABLE);

    ip_handle              = find_dissector_add_dependency("ip", proto_pdcp_lte);
    ipv6_handle            = find_dissector_add_dependency("ipv6", proto_pdcp_lte);
    rohc_handle            = find_dissector_add_dependency("rohc", proto_pdcp_lte);
    lte_rrc_ul_ccch        = find_dissector_add_dependency("lte_rrc.ul_ccch", proto_pdcp_lte);
    lte_rrc_dl_ccch        = find_dissector_add_dependency("lte_rrc.dl_ccch", proto_pdcp_lte);
    lte_rrc_pcch           = find_dissector_add_dependency("lte_rrc.pcch", proto_pdcp_lte);
    lte_rrc_bcch_bch       = find_dissector_add_dependency("lte_rrc.bcch_bch", proto_pdcp_lte);
    lte_rrc_bcch_dl_sch    = find_dissector_add_dependency("lte_rrc.bcch_dl_sch", proto_pdcp_lte);
    lte_rrc_ul_dcch        = find_dissector_add_dependency("lte_rrc.ul_dcch", proto_pdcp_lte);
    lte_rrc_dl_dcch        = find_dissector_add_dependency("lte_rrc.dl_dcch", proto_pdcp_lte);
    lte_rrc_ul_ccch_nb     = find_dissector_add_dependency("lte_rrc.ul_ccch.nb", proto_pdcp_lte);
    lte_rrc_dl_ccch_nb     = find_dissector_add_dependency("lte_rrc.dl_ccch.nb", proto_pdcp_lte);
    lte_rrc_pcch_nb        = find_dissector_add_dependency("lte_rrc.pcch.nb", proto_pdcp_lte);
    lte_rrc_bcch_bch_nb    = find_dissector_add_dependency("lte_rrc.bcch_bch.nb", proto_pdcp_lte);
    lte_rrc_bcch_dl_sch_nb = find_dissector_add_dependency("lte_rrc.bcch_dl_sch.nb", proto_pdcp_lte);
    lte_rrc_ul_dcch_nb     = find_dissector_add_dependency("lte_rrc.ul_dcch.nb", proto_pdcp_lte);
    lte_rrc_dl_dcch_nb     = find_dissector_add_dependency("lte_rrc.dl_dcch.nb", proto_pdcp_lte);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
