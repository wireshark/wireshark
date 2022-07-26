/* packet-pdcp-nr.c
 * Routines for nr PDCP
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


#include "packet-rlc-nr.h"
#include "packet-pdcp-nr.h"

void proto_register_pdcp_nr(void);
void proto_reg_handoff_pdcp_nr(void);

/* Described in:
 * 3GPP TS 38.323 Technical Specification Group Radio Access Netowrk; NR;
 *                Packet Data Convergence Protocol (PDCP) specification (Release 15.1.0)
 * 3GPP TS 37.324 Technical Specification Group Radio Access Network; E-UTRA and NR;
 *                Service Data Adaptation Protocol (SDAP) specification (Release 15)
 */


/* TODO:
   - look into refactoring/sharing parts of deciphering/integrity with LTE implementation
 */


/* Initialize the protocol and registered fields. */
int proto_pdcp_nr = -1;

extern int proto_rlc_nr;

/* Configuration (info known outside of PDU) */
static int hf_pdcp_nr_configuration = -1;
static int hf_pdcp_nr_direction = -1;
static int hf_pdcp_nr_ueid = -1;
static int hf_pdcp_nr_bearer_type = -1;
static int hf_pdcp_nr_bearer_id = -1;
static int hf_pdcp_nr_plane = -1;
static int hf_pdcp_nr_seqnum_length = -1;
static int hf_pdcp_nr_maci_present = -1;
static int hf_pdcp_nr_sdap = -1;
static int hf_pdcp_nr_ciphering_disabled = -1;

static int hf_pdcp_nr_rohc_compression = -1;
static int hf_pdcp_nr_rohc_mode = -1;
static int hf_pdcp_nr_rohc_rnd = -1;
static int hf_pdcp_nr_rohc_udp_checksum_present = -1;
static int hf_pdcp_nr_rohc_profile = -1;
static int hf_pdcp_nr_cid_inclusion_info = -1;
static int hf_pdcp_nr_large_cid_present = -1;

/* PDCP header fields */
static int hf_pdcp_nr_control_plane_reserved = -1;
static int hf_pdcp_nr_reserved3 = -1;
static int hf_pdcp_nr_seq_num_12 = -1;
static int hf_pdcp_nr_reserved5 = -1;
static int hf_pdcp_nr_seq_num_18 = -1;
static int hf_pdcp_nr_signalling_data = -1;
static int hf_pdcp_nr_mac = -1;
static int hf_pdcp_nr_data_control = -1;
static int hf_pdcp_nr_user_plane_data = -1;
static int hf_pdcp_nr_control_pdu_type = -1;
static int hf_pdcp_nr_fmc = -1;
static int hf_pdcp_nr_reserved4 = -1;
static int hf_pdcp_nr_bitmap = -1;
static int hf_pdcp_nr_bitmap_byte = -1;

/* Sequence Analysis */
static int hf_pdcp_nr_sequence_analysis = -1;
static int hf_pdcp_nr_sequence_analysis_ok = -1;
static int hf_pdcp_nr_sequence_analysis_previous_frame = -1;
static int hf_pdcp_nr_sequence_analysis_next_frame = -1;
static int hf_pdcp_nr_sequence_analysis_expected_sn = -1;
static int hf_pdcp_nr_sequence_analysis_repeated = -1;
static int hf_pdcp_nr_sequence_analysis_skipped = -1;

/* Security Settings */
static int hf_pdcp_nr_security = -1;
static int hf_pdcp_nr_security_setup_frame = -1;
static int hf_pdcp_nr_security_integrity_algorithm = -1;
static int hf_pdcp_nr_security_ciphering_algorithm = -1;

static int hf_pdcp_nr_security_bearer = -1;
static int hf_pdcp_nr_security_direction = -1;
static int hf_pdcp_nr_security_count = -1;
static int hf_pdcp_nr_security_cipher_key = -1;
static int hf_pdcp_nr_security_integrity_key = -1;
static int hf_pdcp_nr_security_cipher_key_setup_frame = -1;
static int hf_pdcp_nr_security_integrity_key_setup_frame = -1;


/* Protocol subtree. */
static int ett_pdcp = -1;
static int ett_pdcp_configuration = -1;
static int ett_pdcp_packet = -1;
static int ett_pdcp_nr_sequence_analysis = -1;
static int ett_pdcp_report_bitmap = -1;
static int ett_pdcp_security = -1;

static expert_field ei_pdcp_nr_sequence_analysis_wrong_sequence_number_ul = EI_INIT;
static expert_field ei_pdcp_nr_sequence_analysis_wrong_sequence_number_dl = EI_INIT;
static expert_field ei_pdcp_nr_reserved_bits_not_zero = EI_INIT;
static expert_field ei_pdcp_nr_sequence_analysis_sn_repeated_ul = EI_INIT;
static expert_field ei_pdcp_nr_sequence_analysis_sn_repeated_dl = EI_INIT;
static expert_field ei_pdcp_nr_sequence_analysis_sn_missing_ul = EI_INIT;
static expert_field ei_pdcp_nr_sequence_analysis_sn_missing_dl = EI_INIT;
static expert_field ei_pdcp_nr_digest_wrong = EI_INIT;
static expert_field ei_pdcp_nr_unknown_udp_framing_tag = EI_INIT;
static expert_field ei_pdcp_nr_missing_udp_framing_tag = EI_INIT;

/*-------------------------------------
 * UAT for UE Keys
 *-------------------------------------
 */
/* UAT entry structure. */
typedef struct {
   guint32 ueid;
   gchar   *rrcCipherKeyString;
   gchar   *upCipherKeyString;
   gchar   *rrcIntegrityKeyString;
   gchar   *upIntegrityKeyString;

   guint8   rrcCipherBinaryKey[16];
   gboolean rrcCipherKeyOK;
   guint8   upCipherBinaryKey[16];
   gboolean upCipherKeyOK;
   guint8   rrcIntegrityBinaryKey[16];
   gboolean rrcIntegrityKeyOK;
   guint8   upIntegrityBinaryKey[16];
   gboolean upIntegrityKeyOK;

} uat_ue_keys_record_t;

/* N.B. this is an array/table of the struct above, where ueid is the key */
static uat_ue_keys_record_t *uat_ue_keys_records = NULL;

/* Entries added by UAT */
static uat_t * ue_keys_uat = NULL;
static guint num_ue_keys_uat = 0;

/* Convert an ascii hex character into a digit.  Should only be given valid
   hex ascii characters */
static guchar hex_ascii_to_binary(gchar c)
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
    new_rec->rrcCipherKeyString =    g_strdup(old_rec->rrcCipherKeyString);
    new_rec->upCipherKeyString =     g_strdup(old_rec->upCipherKeyString);
    new_rec->rrcIntegrityKeyString = g_strdup(old_rec->rrcIntegrityKeyString);
    new_rec->upIntegrityKeyString =  g_strdup(old_rec->upIntegrityKeyString);

    return new_rec;
}

/* If raw_string is a valid key, set check_string & return TRUE.  Can be spaced out with ' ' or '-' */
static gboolean check_valid_key_string(const char* raw_string, char* checked_string, char **error)
{
    guint n;
    guint written = 0;
    guint length = (gint)strlen(raw_string);

    /* Can't be valid if not long enough. */
    if (length < 32) {
        if (length > 0) {
            *error = ws_strdup_printf("PDCP NR: Invalid key string (%s) - should include 32 ASCII hex characters (16 bytes) but only %u chars given",
                                      raw_string, length);
        }
        return FALSE;
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
            *error = ws_strdup_printf("PDCP-NR: Invalid char '%c' given in key", c);
            return FALSE;
        }
    }

    /* Must have found exactly 32 hex ascii chars for 16-byte key */
    if (n<length) {
        *error = ws_strdup_printf("PDCP-NR: Key (%s) should contain 32 hex characters (16 bytes) but more detected", raw_string);
        return FALSE;
    }
    if (written != 32) {
        *error = ws_strdup_printf("PDCP-NR: Key (%s) should contain 32 hex characters (16 bytes) but %u detected", raw_string, written);
        return FALSE;
    }
    else {
        return TRUE;
    }
}

/* Write binary key by converting each nibble from the string version */
static void update_key_from_string(const char *stringKey, guint8 *binaryKey, gboolean *pKeyOK, char **error)
{
    int  n;
    char cleanString[32];

    if (!check_valid_key_string(stringKey, cleanString, error)) {
        *pKeyOK = FALSE;
    }
    else {
        for (n=0; n < 32; n += 2) {
            binaryKey[n/2] = (hex_ascii_to_binary(cleanString[n]) << 4) +
                              hex_ascii_to_binary(cleanString[n+1]);
        }
        *pKeyOK = TRUE;
    }
}

/* Update by checking whether the 3 key strings are valid or not, and storing result */
static gboolean uat_ue_keys_record_update_cb(void* record, char** error) {
    uat_ue_keys_record_t* rec = (uat_ue_keys_record_t *)record;

    /* Check and convert RRC cipher key */
    update_key_from_string(rec->rrcCipherKeyString, rec->rrcCipherBinaryKey, &rec->rrcCipherKeyOK, error);

    /* Check and convert User-plane cipher key */
    update_key_from_string(rec->upCipherKeyString, rec->upCipherBinaryKey, &rec->upCipherKeyOK, error);

    /* Check and convert RRC Integrity key */
    update_key_from_string(rec->rrcIntegrityKeyString, rec->rrcIntegrityBinaryKey, &rec->rrcIntegrityKeyOK, error);

    /* Check and convert User-plane Integrity key */
    update_key_from_string(rec->upIntegrityKeyString, rec->upIntegrityBinaryKey, &rec->upIntegrityKeyOK, error);

    /* Return TRUE only if *error has not been set by checking code. */
    return *error == NULL;
}

/* Free heap parts of record */
static void uat_ue_keys_record_free_cb(void*r) {
    uat_ue_keys_record_t* rec = (uat_ue_keys_record_t*)r;

    g_free(rec->rrcCipherKeyString);
    g_free(rec->upCipherKeyString);
    g_free(rec->rrcIntegrityKeyString);
    g_free(rec->upIntegrityKeyString);
}

UAT_DEC_CB_DEF(uat_ue_keys_records, ueid, uat_ue_keys_record_t)
UAT_CSTRING_CB_DEF(uat_ue_keys_records, rrcCipherKeyString,    uat_ue_keys_record_t)
UAT_CSTRING_CB_DEF(uat_ue_keys_records, upCipherKeyString,     uat_ue_keys_record_t)
UAT_CSTRING_CB_DEF(uat_ue_keys_records, rrcIntegrityKeyString, uat_ue_keys_record_t)
UAT_CSTRING_CB_DEF(uat_ue_keys_records, upIntegrityKeyString,  uat_ue_keys_record_t)

/* Also supporting a hash table with entries from these functions */

/* Table from ueid -> ue_key_entries_t* */
static wmem_map_t *pdcp_security_key_hash = NULL;

typedef enum {
    rrc_cipher,
    rrc_integrity,
    up_cipher,
    up_integrity
} ue_key_type_t;

typedef struct {
    ue_key_type_t key_type;
    gchar         *keyString;
    guint8        binaryKey[16];
    gboolean      keyOK;
    guint32       setup_frame;
} key_entry_t;

/* List of key entries for an individual UE */
typedef struct {
    #define MAX_KEY_ENTRIES_PER_UE 32
    guint       num_entries_set;
    key_entry_t entries[MAX_KEY_ENTRIES_PER_UE];
} ue_key_entries_t;


void set_pdcp_nr_rrc_ciphering_key(guint16 ueid, const char *key, guint32 frame_num)
{
    char *err = NULL;

    /* Get or create struct for this UE */
    ue_key_entries_t *key_entries = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                       GUINT_TO_POINTER((guint)ueid));
    if (key_entries == NULL) {
        /* Create and add to table */
        key_entries = wmem_new0(wmem_file_scope(), ue_key_entries_t);
        wmem_map_insert(pdcp_security_key_hash, GUINT_TO_POINTER((guint)ueid), key_entries);
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

void set_pdcp_nr_rrc_integrity_key(guint16 ueid, const char *key, guint32 frame_num)
{
    char *err = NULL;

    /* Get or create struct for this UE */
    ue_key_entries_t *key_entries = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                       GUINT_TO_POINTER((guint)ueid));
    if (key_entries == NULL) {
        /* Create and add to table */
        key_entries = wmem_new0(wmem_file_scope(), ue_key_entries_t);
        wmem_map_insert(pdcp_security_key_hash, GUINT_TO_POINTER((guint)ueid), key_entries);
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
        report_failure("%s: (RRC Integrity Key)", err);
        g_free(err);
    }
}

void set_pdcp_nr_up_ciphering_key(guint16 ueid, const char *key, guint32 frame_num)
{
    char *err = NULL;

    /* Get or create struct for this UE */
    ue_key_entries_t *key_entries = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                       GUINT_TO_POINTER((guint)ueid));
    if (key_entries == NULL) {
        /* Create and add to table */
        key_entries = wmem_new0(wmem_file_scope(), ue_key_entries_t);
        wmem_map_insert(pdcp_security_key_hash, GUINT_TO_POINTER((guint)ueid), key_entries);
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
        report_failure("%s: (UP Cipher Key)", err);
        g_free(err);
    }
}

void set_pdcp_nr_up_integrity_key(guint16 ueid, const char *key, guint32 frame_num)
{
    char *err = NULL;

    /* Get or create struct for this UE */
    ue_key_entries_t *key_entries = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                       GUINT_TO_POINTER((guint)ueid));
    if (key_entries == NULL) {
        /* Create and add to table */
        key_entries = wmem_new0(wmem_file_scope(), ue_key_entries_t);
        wmem_map_insert(pdcp_security_key_hash, GUINT_TO_POINTER((guint)ueid), key_entries);
    }

    if (key_entries->num_entries_set == MAX_KEY_ENTRIES_PER_UE) {
        /* No more room.. */
        return;
    }

    key_entry_t *new_key_entry = &key_entries->entries[key_entries->num_entries_set++];
    new_key_entry->key_type = up_integrity;
    new_key_entry->keyString = g_strdup(key);
    new_key_entry->setup_frame = frame_num;
    update_key_from_string(new_key_entry->keyString, new_key_entry->binaryKey, &new_key_entry->keyOK, &err);
    if (err) {
        report_failure("%s: (UP Integrity Key)", err);
        g_free(err);
    }
}


static const value_string direction_vals[] =
{
    { PDCP_NR_DIRECTION_UPLINK,      "Uplink"},
    { PDCP_NR_DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string pdcp_plane_vals[] = {
    { NR_SIGNALING_PLANE,    "Signalling" },
    { NR_USER_PLANE,         "User" },
    { 0,   NULL }
};

static const value_string bearer_type_vals[] = {
    { Bearer_DCCH,        "DCCH"},
    { Bearer_BCCH_BCH,    "BCCH_BCH"},
    { Bearer_BCCH_DL_SCH, "BCCH_DL_SCH"},
    { Bearer_CCCH,        "CCCH"},
    { Bearer_PCCH,        "PCCH"},
    { 0,                  NULL}
};

static const value_string rohc_mode_vals[] = {
    { UNIDIRECTIONAL,            "Unidirectional" },
    { OPTIMISTIC_BIDIRECTIONAL,  "Optimistic Bidirectional" },
    { RELIABLE_BIDIRECTIONAL,    "Reliable Bidirectional" },
    { 0,   NULL }
};


/* Entries taken from Table 5.7.1-1.
   Descriptions from http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.txt */
static const value_string rohc_profile_vals[] = {
    { 0x0000,   "ROHC uncompressed" },      /* [RFC5795] */
    { 0x0001,   "ROHC RTP" },               /* [RFC3095] */
    { 0x0002,   "ROHC UDP" },               /* [RFC3095] */
    { 0x0003,   "ROHC ESP" },               /* [RFC3095] */
    { 0x0004,   "ROHC IP" },                /* [RFC3843] */
    { 0x0006,   "ROHC TCP" },               /* [RFC4996] */

    { 0x0101,   "ROHCv2 RTP" },             /* [RFC5225] */
    { 0x0102,   "ROHCv2 UDP" },             /* [RFC5225] */
    { 0x0103,   "ROHCv2 ESP" },             /* [RFC5225] */
    { 0x0104,   "ROHCv2 IP" },              /* [RFC5225] */
    { 0,   NULL }
};

static const true_false_string pdu_type_bit = {
    "Data PDU",
    "Control PDU"
};


static const value_string control_pdu_type_vals[] = {
    { 0,   "PDCP status report" },
    { 1,   "Interspersed ROHC feedback packet" },
    { 0,   NULL }
};

static const value_string integrity_algorithm_vals[] = {
    { nia0,         "NIA0 (NULL)" },
    { nia1,         "NIA1 (SNOW3G)" },
    { nia2,         "NIA2 (AES)" },
    { nia3,         "NIA3 (ZUC)" },
    { 0,   NULL }
};

static const value_string ciphering_algorithm_vals[] = {
    { nea0,         "NEA0 (NULL)" },
    { nea1,         "NEA1 (SNOW3G)" },
    { nea2,         "NEA2 (AES)" },
    { nea3,         "NEA3 (ZUC)" },
    { nea_disabled, "Ciphering disabled" },
    { 0,   NULL }
};


/* SDAP header fields and tree */
static int proto_sdap = -1;
static int hf_sdap_rdi = -1;
static int hf_sdap_rqi = -1;
static int hf_sdap_qfi = -1;
static int hf_sdap_data_control = -1;
static int hf_sdap_reserved = -1;
static gint ett_sdap = -1;

static const true_false_string sdap_rdi = {
    "To store QoS flow to DRB mapping rule",
    "No action"
};

static const true_false_string sdap_rqi = {
    "To inform NAS that RQI bit is set to 1",
    "No action"
};


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t rohc_handle;
static dissector_handle_t nr_rrc_ul_ccch;
static dissector_handle_t nr_rrc_ul_ccch1;
static dissector_handle_t nr_rrc_dl_ccch;
static dissector_handle_t nr_rrc_pcch;
static dissector_handle_t nr_rrc_bcch_bch;
static dissector_handle_t nr_rrc_bcch_dl_sch;
static dissector_handle_t nr_rrc_ul_dcch;
static dissector_handle_t nr_rrc_dl_dcch;


#define SEQUENCE_ANALYSIS_RLC_ONLY  1
#define SEQUENCE_ANALYSIS_PDCP_ONLY 2

/* Preference variables */
static gboolean global_pdcp_dissect_user_plane_as_ip = TRUE;
static gboolean global_pdcp_dissect_signalling_plane_as_rrc = TRUE;
static gint     global_pdcp_check_sequence_numbers = TRUE;
static gboolean global_pdcp_dissect_rohc = FALSE;

/* Preference settings for deciphering and integrity checking. */
static gboolean global_pdcp_decipher_signalling = TRUE;
static gboolean global_pdcp_decipher_userplane = FALSE;  /* Can be slow, so default to FALSE */
static gboolean global_pdcp_check_integrity = TRUE;
static gboolean global_pdcp_ignore_sec = FALSE;          /* Ignore Set Security Algo calls */

/* Use these values where we know the keys but may have missed the algorithm,
   e.g. when handing over and RRCReconfigurationRequest goes to target cell only */
static enum nr_security_ciphering_algorithm_e global_default_ciphering_algorithm = nea0;
static enum nr_security_integrity_algorithm_e global_default_integrity_algorithm = nia0;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowRLCLayer, ShowPDCPLayer, ShowTrafficLayer
};
static gint     global_pdcp_nr_layer_to_show = (gint)ShowRLCLayer;


/* Function to be called from outside this module (e.g. in a plugin) to get per-packet data */
pdcp_nr_info *get_pdcp_nr_proto_data(packet_info *pinfo)
{
    return (pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
}

/* Function to be called from outside this module (e.g. in a plugin) to set per-packet data */
void set_pdcp_nr_proto_data(packet_info *pinfo, pdcp_nr_info *p_pdcp_nr_info)
{
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
}



/**************************************************/
/* Sequence number analysis                       */

/* Bearer key */
typedef struct
{
    /* Using bit fields to fit into 32 bits, so avoiding the need to allocate
       heap memory for these structs */
    guint           ueId : 16;
    guint           plane : 2;
    guint           bearerId : 6;
    guint           direction : 1;
    guint           notUsed : 7;
} pdcp_bearer_hash_key;

/* Bearer state */
typedef struct
{
    guint32  previousSequenceNumber;
    guint32  previousFrameNum;
    guint32  hfn;
} pdcp_bearer_status;

/* The sequence analysis bearer hash table.
   Maps key -> status */
static wmem_map_t *pdcp_sequence_analysis_bearer_hash = NULL;


/* Hash table types & functions for frame reports */

typedef struct {
    guint32         frameNumber;
    guint32         SN :       18;
    guint32         plane :    2;
    guint32         bearerId: 5;
    guint32         direction: 1;
    guint32         notUsed :  6;
} pdcp_result_hash_key;

static gint pdcp_result_hash_equal(gconstpointer v, gconstpointer v2)
{
    const pdcp_result_hash_key* val1 = (const pdcp_result_hash_key *)v;
    const pdcp_result_hash_key* val2 = (const pdcp_result_hash_key *)v2;

    /* All fields must match */
    return (memcmp(val1, val2, sizeof(pdcp_result_hash_key)) == 0);
}

/* Compute a hash value for a given key. */
static guint pdcp_result_hash_func(gconstpointer v)
{
    const pdcp_result_hash_key* val1 = (const pdcp_result_hash_key *)v;

    /* TODO: This is a bit random.  */
    return val1->frameNumber + (val1->bearerId<<7) +
                               (val1->plane<<12) +
                               (val1->SN<<14) +
                               (val1->direction<<6);
}

/* pdcp_bearer_hash_key fits into the pointer, so just copy the value into
   a guint, cast to a pointer and return that as the key */
static gpointer get_bearer_hash_key(pdcp_bearer_hash_key *key)
{
    guint  asInt = 0;
    /* TODO: assert that sizeof(pdcp_bearer_hash_key) <= sizeof(guint) ? */
    memcpy(&asInt, key, sizeof(pdcp_bearer_hash_key));
    return GUINT_TO_POINTER(asInt);
}

/* Convenience function to get a pointer for the hash_func to work with */
static gpointer get_report_hash_key(guint32 SN, guint32 frameNumber,
                                    pdcp_nr_info *p_pdcp_nr_info,
                                    gboolean do_persist)
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
    p_key->plane = (guint8)p_pdcp_nr_info->plane;
    p_key->bearerId = p_pdcp_nr_info->bearerId;
    p_key->direction = p_pdcp_nr_info->direction;
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
    gboolean sequenceExpectedCorrect;
    guint32  sequenceExpected;
    guint32  previousFrameNum;
    guint32  nextFrameNum;

    guint32  firstSN;
    guint32  lastSN;
    guint32  hfn;

    sequence_state state;
} pdcp_sequence_report_in_frame;

/* The sequence analysis frame report hash table.
   Maps pdcp_result_hash_key* -> pdcp_sequence_report_in_frame* */
static wmem_map_t *pdcp_nr_sequence_analysis_report_hash = NULL;

/* Gather together security settings in order to be able to do deciphering */
typedef struct pdu_security_settings_t
{
    enum nr_security_ciphering_algorithm_e ciphering;
    enum nr_security_integrity_algorithm_e integrity;
    guint8* cipherKey;
    guint8* integrityKey;
    gboolean cipherKeyValid;
    gboolean integrityKeyValid;
    guint32 count;
    guint8  bearer;
    guint8  direction;
} pdu_security_settings_t;

static uat_ue_keys_record_t* look_up_keys_record(guint16 ueid, guint32 frame_num,
                                                 guint32 *config_frame_rrc_cipher,
                                                 guint32 *config_frame_rrc_integrity,
                                                 guint32 *config_frame_up_cipher,
                                                 guint32 *config_frame_up_integrity)
{
    unsigned int record_id;

    /* Try hash table first (among entries added by set_pdcp_nr_xxx_key() functions) */
    ue_key_entries_t* key_record = (ue_key_entries_t*)wmem_map_lookup(pdcp_security_key_hash,
                                                                      GUINT_TO_POINTER((guint)ueid));
    if (key_record != NULL) {
        /* Will build up and return usual type */
        uat_ue_keys_record_t *keys = wmem_new0(wmem_file_scope(), uat_ue_keys_record_t);

        /* Fill in details */
        keys->ueid = ueid;
        /* Walk entries backwards (want last entry before frame_num) */
        for (gint e=key_record->num_entries_set; e>0; e--) {
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
                    case up_integrity:
                        if (!keys->upIntegrityKeyOK) {
                            keys->upIntegrityKeyString = entry->keyString;
                            memcpy(keys->upIntegrityBinaryKey, entry->binaryKey, 16);
                            keys->upIntegrityKeyOK = entry->keyOK;
                            *config_frame_up_integrity = entry->setup_frame;
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
static void addBearerSequenceInfo(pdcp_sequence_report_in_frame *p,
                                  pdcp_nr_info *p_pdcp_nr_info,
                                  guint32   sequenceNumber,
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
                                             hf_pdcp_nr_sequence_analysis,
                                             tvb, 0, 0,
                                             "", "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_pdcp_nr_sequence_analysis);
    proto_item_set_generated(seqnum_ti);


    /* Previous bearer frame */
    if (p->previousFrameNum != 0) {
        proto_tree_add_uint(seqnum_tree, hf_pdcp_nr_sequence_analysis_previous_frame,
                            tvb, 0, 0, p->previousFrameNum);
    }

    /* Expected sequence number */
    ti_expected_sn = proto_tree_add_uint(seqnum_tree, hf_pdcp_nr_sequence_analysis_expected_sn,
                                         tvb, 0, 0, p->sequenceExpected);
    proto_item_set_generated(ti_expected_sn);

    /* Make sure we have recognised SN length */
    switch (p_pdcp_nr_info->seqnum_length) {
        case PDCP_NR_SN_LENGTH_12_BITS:
        case PDCP_NR_SN_LENGTH_18_BITS:
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    switch (p->state) {
        case SN_OK:
            proto_item_set_hidden(ti_expected_sn);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_ok,
                                        tvb, 0, 0, TRUE);
            proto_item_set_generated(ti);
            proto_item_append_text(seqnum_ti, " - OK");

            /* Link to next SN in bearer (if known) */
            if (p->nextFrameNum != 0) {
                proto_tree_add_uint(seqnum_tree, hf_pdcp_nr_sequence_analysis_next_frame,
                                    tvb, 0, 0, p->nextFrameNum);
            }

            break;

        case SN_Missing:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            proto_item_set_generated(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_skipped,
                                        tvb, 0, 0, TRUE);
            proto_item_set_generated(ti);
            if (p->lastSN != p->firstSN) {
                /* Range missing */
                expert_add_info_format(pinfo, ti,
                                       (p_pdcp_nr_info->direction == PDCP_NR_DIRECTION_UPLINK) ?
                                           &ei_pdcp_nr_sequence_analysis_sn_missing_ul :
                                           &ei_pdcp_nr_sequence_analysis_sn_missing_dl,
                                       "PDCP SNs (%u to %u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN, p->lastSN,
                                       val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_nr_info->ueid,
                                       val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                       p_pdcp_nr_info->bearerId);
                proto_item_append_text(seqnum_ti, " - SNs missing (%u to %u)",
                                       p->firstSN, p->lastSN);
            }
            else {
                /* Single SN missing */
                expert_add_info_format(pinfo, ti,
                                       (p_pdcp_nr_info->direction == PDCP_NR_DIRECTION_UPLINK) ?
                                           &ei_pdcp_nr_sequence_analysis_sn_missing_ul :
                                           &ei_pdcp_nr_sequence_analysis_sn_missing_dl,
                                       "PDCP SN (%u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN,
                                       val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_nr_info->ueid,
                                       val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                       p_pdcp_nr_info->bearerId);
                proto_item_append_text(seqnum_ti, " - SN missing (%u)",
                                       p->firstSN);
            }
            break;

        case SN_Repeated:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            proto_item_set_generated(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_repeated,
                                        tvb, 0, 0, TRUE);
            proto_item_set_generated(ti);
            expert_add_info_format(pinfo, ti,
                                   (p_pdcp_nr_info->direction == PDCP_NR_DIRECTION_UPLINK) ?
                                       &ei_pdcp_nr_sequence_analysis_sn_repeated_ul :
                                       &ei_pdcp_nr_sequence_analysis_sn_repeated_dl,
                                   "PDCP SN (%u) repeated for %s for UE %u (%s-%u)",
                                   p->firstSN,
                                   val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_nr_info->ueid,
                                   val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                   p_pdcp_nr_info->bearerId);
            proto_item_append_text(seqnum_ti, "- SN %u Repeated",
                                   p->firstSN);
            break;

        default:
            /* Incorrect sequence number */
            expert_add_info_format(pinfo, ti_expected_sn,
                                   (p_pdcp_nr_info->direction == PDCP_NR_DIRECTION_UPLINK) ?
                                       &ei_pdcp_nr_sequence_analysis_wrong_sequence_number_ul :
                                       &ei_pdcp_nr_sequence_analysis_wrong_sequence_number_dl,
                                   "Wrong Sequence Number for %s on UE %u (%s-%u) - got %u, expected %u",
                                   val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_nr_info->ueid,
                                   val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                   p_pdcp_nr_info->bearerId,
                                   sequenceNumber, p->sequenceExpected);
            break;
    }

    /* May also be able to add key inputs to security tree here */
    if ((pdu_security->ciphering != nea0) ||
        (pdu_security->integrity != nia0)) {
        guint32              hfn_multiplier;
        guint32              count;
        gchar                *cipher_key = NULL;
        gchar                *integrity_key = NULL;

        /* BEARER */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_bearer,
                                 tvb, 0, 0, p_pdcp_nr_info->bearerId-1);
        proto_item_set_generated(ti);
        pdu_security->bearer = p_pdcp_nr_info->bearerId-1;

        /* DIRECTION */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_direction,
                                 tvb, 0, 0, p_pdcp_nr_info->direction);
        proto_item_set_generated(ti);

        /* COUNT (HFN * snLength^2 + SN) */
        switch (p_pdcp_nr_info->seqnum_length) {
            case PDCP_NR_SN_LENGTH_12_BITS:
                hfn_multiplier = 4096;
                break;
            case PDCP_NR_SN_LENGTH_18_BITS:
                hfn_multiplier = 262144;
                break;
            default:
                DISSECTOR_ASSERT_NOT_REACHED();
                break;
        }
        count = (p->hfn * hfn_multiplier) + sequenceNumber;
        ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_count,
                                 tvb, 0, 0, count);
        proto_item_set_generated(ti);
        pdu_security->count = count;

        /* KEY.  Look this UE up among UEs that have keys configured */
        guint32 config_frame_rrc_cipher=0, config_frame_rrc_integrity=0,
                config_frame_up_cipher=0, config_frame_up_integrity=0;
        keys_record = look_up_keys_record(p_pdcp_nr_info->ueid, pinfo->num,
                                          &config_frame_rrc_cipher, &config_frame_rrc_integrity,
                                          &config_frame_up_cipher,  &config_frame_up_integrity);

        guint32 config_frame_cipher=0, config_frame_integrity=0;

        if (keys_record != NULL) {
            if (p_pdcp_nr_info->plane == NR_SIGNALING_PLANE) {
                /* Get RRC ciphering key */
                if (keys_record->rrcCipherKeyOK) {
                    cipher_key = keys_record->rrcCipherKeyString;
                    pdu_security->cipherKey = &(keys_record->rrcCipherBinaryKey[0]);
                    pdu_security->cipherKeyValid = TRUE;
                    config_frame_cipher = config_frame_rrc_cipher;
                }
                /* Get RRC integrity key */
                if (keys_record->rrcIntegrityKeyOK) {
                    integrity_key = keys_record->rrcIntegrityKeyString;
                    pdu_security->integrityKey = &(keys_record->rrcIntegrityBinaryKey[0]);
                    pdu_security->integrityKeyValid = TRUE;
                    config_frame_integrity = config_frame_rrc_integrity;
                }
            }
            else {
                /* Get userplane ciphering key */
                if (keys_record->upCipherKeyOK) {
                    cipher_key = keys_record->upCipherKeyString;
                    pdu_security->cipherKey = &(keys_record->upCipherBinaryKey[0]);
                    pdu_security->cipherKeyValid = TRUE;
                    config_frame_cipher = config_frame_up_cipher;
                }
                /* Get userplane integrity key */
                if (keys_record->upIntegrityKeyOK) {
                    integrity_key = keys_record->upIntegrityKeyString;
                    pdu_security->integrityKey = &(keys_record->upIntegrityBinaryKey[0]);
                    pdu_security->integrityKeyValid = TRUE;
                    config_frame_integrity = config_frame_up_integrity;
                }
            }

            /* Show keys where known and valid */
            if (cipher_key != NULL) {
                ti = proto_tree_add_string(security_tree, hf_pdcp_nr_security_cipher_key,
                                           tvb, 0, 0, cipher_key);
                proto_item_set_generated(ti);
                /* If came from frame, link to it */
                if (config_frame_cipher != 0) {
                    ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_cipher_key_setup_frame,
                                             tvb, 0, 0, config_frame_cipher);
                    proto_item_set_generated(ti);
                }
            }
            if (integrity_key != NULL) {
                ti = proto_tree_add_string(security_tree, hf_pdcp_nr_security_integrity_key,
                                           tvb, 0, 0, integrity_key);
                proto_item_set_generated(ti);
                /* If came from frame, link to it */
                if (config_frame_integrity != 0) {
                    ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_integrity_key_setup_frame,
                                             tvb, 0, 0, config_frame_integrity);
                    proto_item_set_generated(ti);
                }
            }

            pdu_security->direction = p_pdcp_nr_info->direction;
        }
    }
}


/* Update the bearer status and set report for this frame */
static void checkBearerSequenceInfo(packet_info *pinfo, tvbuff_t *tvb,
                                    pdcp_nr_info *p_pdcp_nr_info,
                                    guint32 sequenceNumber,
                                    proto_tree *tree,
                                    proto_tree *security_tree,
                                    pdu_security_settings_t *pdu_security)
{
    pdcp_bearer_hash_key          bearer_key;
    pdcp_bearer_status           *p_bearer_status;
    pdcp_sequence_report_in_frame *p_report_in_frame      = NULL;
    gboolean                       createdBearer          = FALSE;
    guint32                        expectedSequenceNumber = 0;
    guint32                        snLimit                = 0;

    /* If find stat_report_in_frame already, use that and get out */
    if (PINFO_FD_VISITED(pinfo)) {
        p_report_in_frame =
            (pdcp_sequence_report_in_frame*)wmem_map_lookup(pdcp_nr_sequence_analysis_report_hash,
                                                            get_report_hash_key(sequenceNumber,
                                                                                pinfo->num,
                                                                                p_pdcp_nr_info, FALSE));
        if (p_report_in_frame != NULL) {
            addBearerSequenceInfo(p_report_in_frame, p_pdcp_nr_info,
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
    /* Create or find an entry for this bearer state */
    bearer_key.ueId = p_pdcp_nr_info->ueid;
    bearer_key.plane = p_pdcp_nr_info->plane;
    bearer_key.bearerId = p_pdcp_nr_info->bearerId;
    bearer_key.direction = p_pdcp_nr_info->direction;
    bearer_key.notUsed = 0;

    /* Do the table lookup */
    p_bearer_status = (pdcp_bearer_status*)wmem_map_lookup(pdcp_sequence_analysis_bearer_hash,
                                                             get_bearer_hash_key(&bearer_key));

    /* Create table entry if necessary */
    if (p_bearer_status == NULL) {
        createdBearer = TRUE;

        /* Allocate a new value and duplicate key contents */
        p_bearer_status = wmem_new0(wmem_file_scope(), pdcp_bearer_status);

        /* Add entry */
        wmem_map_insert(pdcp_sequence_analysis_bearer_hash,
                        get_bearer_hash_key(&bearer_key), p_bearer_status);
    }

    /* Create space for frame state_report */
    p_report_in_frame = wmem_new(wmem_file_scope(), pdcp_sequence_report_in_frame);
    p_report_in_frame->nextFrameNum = 0;

    switch (p_pdcp_nr_info->seqnum_length) {
        case PDCP_NR_SN_LENGTH_12_BITS:
            snLimit = 4096;
            break;
        case PDCP_NR_SN_LENGTH_18_BITS:
            snLimit = 262144;
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    /* Work out expected sequence number */
    if (!createdBearer) {
        expectedSequenceNumber = (p_bearer_status->previousSequenceNumber + 1) % snLimit;
    }
    else {
        expectedSequenceNumber = sequenceNumber;
    }

    /* Set report for this frame */
    /* For PDCP, sequence number is always expectedSequence number */
    p_report_in_frame->sequenceExpectedCorrect = (sequenceNumber == expectedSequenceNumber);
    p_report_in_frame->hfn = p_bearer_status->hfn;


    /* For wrong sequence number... */
    if (!p_report_in_frame->sequenceExpectedCorrect) {

        /* Frames are not missing if we get an earlier sequence number again */
        if (((snLimit + expectedSequenceNumber - sequenceNumber) % snLimit) > 15) {
            p_report_in_frame->state = SN_Missing;
            p_report_in_frame->firstSN = expectedSequenceNumber;
            p_report_in_frame->lastSN = (snLimit + sequenceNumber - 1) % snLimit;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_bearer_status->previousFrameNum;

            /* Update Bearer status to remember *this* frame */
            p_bearer_status->previousFrameNum = pinfo->num;
            p_bearer_status->previousSequenceNumber = sequenceNumber;
        }
        else {
            /* An SN has been repeated */
            p_report_in_frame->state = SN_Repeated;
            p_report_in_frame->firstSN = sequenceNumber;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_bearer_status->previousFrameNum;
        }
    }
    else {
        /* SN was OK */
        p_report_in_frame->state = SN_OK;
        p_report_in_frame->sequenceExpected = expectedSequenceNumber;
        p_report_in_frame->previousFrameNum = p_bearer_status->previousFrameNum;
        /* SN has rolled around, inc hfn! */
        if (!createdBearer && (sequenceNumber == 0)) {
            /* Should handover before HFN needs to wrap, so don't worry about it */
            p_bearer_status->hfn++;
            p_report_in_frame->hfn = p_bearer_status->hfn;
        }

        /* Update Bearer status to remember *this* frame */
        p_bearer_status->previousFrameNum = pinfo->num;
        p_bearer_status->previousSequenceNumber = sequenceNumber;

        if (p_report_in_frame->previousFrameNum != 0) {
            /* Get report for previous frame */
            pdcp_sequence_report_in_frame *p_previous_report;
            p_previous_report = (pdcp_sequence_report_in_frame*)wmem_map_lookup(pdcp_nr_sequence_analysis_report_hash,
                                                                                get_report_hash_key((sequenceNumber+262144) % 262144,
                                                                                                    p_report_in_frame->previousFrameNum,
                                                                                                    p_pdcp_nr_info,
                                                                                                    FALSE));
            /* It really shouldn't be NULL... */
            if (p_previous_report != NULL) {
                /* Point it forward to this one */
                p_previous_report->nextFrameNum = pinfo->num;
            }
        }
    }

    /* Associate with this frame number */
    wmem_map_insert(pdcp_nr_sequence_analysis_report_hash,
                    get_report_hash_key(sequenceNumber, pinfo->num,
                                        p_pdcp_nr_info, TRUE),
                    p_report_in_frame);

    /* Add state report for this frame into tree */
    addBearerSequenceInfo(p_report_in_frame, p_pdcp_nr_info, sequenceNumber,
                           pinfo, tree, tvb, security_tree, pdu_security);
}


/* Hash table for security state for a UE
   Maps UEId -> pdcp_security_info_t*  */
static wmem_map_t *pdcp_security_hash = NULL;


typedef struct  ueid_frame_t {
    guint32 framenum;
    guint16 ueid;
} ueid_frame_t;

/* Convenience function to get a pointer for the hash_func to work with */
static gpointer get_ueid_frame_hash_key(guint16 ueid, guint32 frameNumber,
                                        gboolean do_persist)
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

static gint pdcp_nr_ueid_frame_hash_equal(gconstpointer v, gconstpointer v2)
{
    const ueid_frame_t *ueid_frame_1 = (const ueid_frame_t *)v;
    const ueid_frame_t *ueid_frame_2 = (const ueid_frame_t *)v2;
    return ((ueid_frame_1->framenum == ueid_frame_2->framenum) &&
            (ueid_frame_1->ueid == ueid_frame_2->ueid));
}
static guint pdcp_nr_ueid_frame_hash_func(gconstpointer v)
{
    const ueid_frame_t *ueid_frame = (const ueid_frame_t *)v;
    return ueid_frame->framenum + 100*ueid_frame->ueid;
}

/* Result is ueid_frame_t -> pdcp_security_info_t*  */
static wmem_map_t *pdcp_security_result_hash = NULL;




/* Write the given formatted text to:
   - the info column
   - the top-level PDCP PDU item */
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
                             pdcp_nr_info *p_pdcp_info)
{
    proto_item *ti;
    proto_tree *configuration_tree;
    proto_item *configuration_ti = proto_tree_add_item(tree,
                                                       hf_pdcp_nr_configuration,
                                                       tvb, 0, 0, ENC_ASCII);
    configuration_tree = proto_item_add_subtree(configuration_ti, ett_pdcp_configuration);

    /* Direction */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_direction, tvb, 0, 0,
                             p_pdcp_info->direction);
    proto_item_set_generated(ti);

    /* Plane */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_plane, tvb, 0, 0,
                             p_pdcp_info->plane);
    proto_item_set_generated(ti);

    /* UEId */
    if (p_pdcp_info->ueid != 0) {
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_ueid, tvb, 0, 0,
                                 p_pdcp_info->ueid);
        proto_item_set_generated(ti);
        write_pdu_label_and_info(configuration_ti, pinfo, "UEId=%3u", p_pdcp_info->ueid);
    }

    /* Bearer type */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_bearer_type, tvb, 0, 0,
                             p_pdcp_info->bearerType);
    proto_item_set_generated(ti);
    if (p_pdcp_info->bearerId != 0) {
        /* Bearer id */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_bearer_id, tvb, 0, 0,
                                 p_pdcp_info->bearerId);
        proto_item_set_generated(ti);
    }

    /* Show bearer type in root/Info */
    if (p_pdcp_info->bearerType == Bearer_DCCH) {
        write_pdu_label_and_info(configuration_ti, pinfo, "   %s-%u  ",
                                 (p_pdcp_info->plane == NR_SIGNALING_PLANE) ? "SRB" : "DRB",
                                 p_pdcp_info->bearerId);
    }
    else {
        write_pdu_label_and_info(configuration_ti, pinfo, "   %s",
                                 val_to_str_const(p_pdcp_info->bearerType, bearer_type_vals, "Unknown"));
    }

    /* Seqnum length */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_seqnum_length, tvb, 0, 0,
                             p_pdcp_info->seqnum_length);
    proto_item_set_generated(ti);

    /* MAC-I Present */
    ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_maci_present, tvb, 0, 0,
                                p_pdcp_info->maci_present);
    proto_item_set_generated(ti);

    /* Ciphering disabled */
    ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_ciphering_disabled, tvb, 0, 0,
                                p_pdcp_info->ciphering_disabled);
    proto_item_set_generated(ti);
    /* Hide unless set */
    if (!p_pdcp_info->ciphering_disabled) {
        proto_item_set_hidden(ti);
    }


    if (p_pdcp_info->plane == NR_USER_PLANE) {

        /* SDAP */
        ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_sdap, tvb, 0, 0,
                                    (p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK) ?
                                        p_pdcp_info->sdap_header & PDCP_NR_UL_SDAP_HEADER_PRESENT :
                                        p_pdcp_info->sdap_header & PDCP_NR_DL_SDAP_HEADER_PRESENT);
        proto_item_set_generated(ti);


        /* ROHC compression */
        ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_rohc_compression, tvb, 0, 0,
                                    p_pdcp_info->rohc.rohc_compression);
        proto_item_set_generated(ti);

        /* ROHC-specific settings */
        if (p_pdcp_info->rohc.rohc_compression) {

            /* Show ROHC mode */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_rohc_mode, tvb, 0, 0,
                                     p_pdcp_info->rohc.mode);
            proto_item_set_generated(ti);

            /* Show RND */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_rohc_rnd, tvb, 0, 0,
                                        p_pdcp_info->rohc.rnd);
            proto_item_set_generated(ti);

            /* UDP Checksum */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_rohc_udp_checksum_present, tvb, 0, 0,
                                        p_pdcp_info->rohc.udp_checksum_present);
            proto_item_set_generated(ti);

            /* ROHC profile */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_rohc_profile, tvb, 0, 0,
                                     p_pdcp_info->rohc.profile);
            proto_item_set_generated(ti);

            /* CID Inclusion Info */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_cid_inclusion_info, tvb, 0, 0,
                                        p_pdcp_info->rohc.cid_inclusion_info);
            proto_item_set_generated(ti);

            /* Large CID */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_large_cid_present, tvb, 0, 0,
                                        p_pdcp_info->rohc.large_cid_present);
            proto_item_set_generated(ti);
        }
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


/* Look for an RRC dissector for signalling data (using Bearer type and direction) */
static dissector_handle_t lookup_rrc_dissector_handle(struct pdcp_nr_info  *p_pdcp_info, guint32 data_length)
{
    dissector_handle_t rrc_handle = NULL;

    switch (p_pdcp_info->bearerType)
    {
        case Bearer_CCCH:
            if (p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK) {
                rrc_handle = (data_length == 8) ? nr_rrc_ul_ccch1 : nr_rrc_ul_ccch;
            } else {
                rrc_handle = nr_rrc_dl_ccch;
            }
            break;
        case Bearer_PCCH:
            rrc_handle = nr_rrc_pcch;
            break;
        case Bearer_BCCH_BCH:
            rrc_handle = nr_rrc_bcch_bch;
            break;
        case Bearer_BCCH_DL_SCH:
            rrc_handle = nr_rrc_bcch_dl_sch;
            break;
        case Bearer_DCCH:
            if (p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK) {
                rrc_handle = nr_rrc_ul_dcch;
            } else {
                rrc_handle = nr_rrc_dl_dcch;
            }
            break;

        default:
            break;
    }

    return rrc_handle;
}


/* Called from control protocol to configure security algorithms for the given UE */
void set_pdcp_nr_security_algorithms(guint16 ueid, pdcp_nr_security_info_t *security_info)
{
    /* Use for this frame so can check integrity on SecurityCommandRequest frame */
    /* N.B. won't work for internal, non-RRC signalling methods... */
    pdcp_nr_security_info_t *p_frame_security;

    /* Disable this entire sub-routine with the Preference */
    /* Used when the capture is already deciphered */
    if (global_pdcp_ignore_sec) {
        return;
    }

    /* Create or update current settings, by UEID */
    pdcp_nr_security_info_t* ue_security =
        (pdcp_nr_security_info_t*)wmem_map_lookup(pdcp_security_hash,
                                                  GUINT_TO_POINTER((guint)ueid));
    if (ue_security == NULL) {
        /* Copy whole security struct */
        ue_security = wmem_new(wmem_file_scope(), pdcp_nr_security_info_t);
        *ue_security = *security_info;

        /* And add into security table */
        wmem_map_insert(pdcp_security_hash, GUINT_TO_POINTER((guint)ueid), ue_security);
    }
    else {
        /* Just update existing entry already in table */
        ue_security->previous_algorithm_configuration_frame = ue_security->algorithm_configuration_frame;
        ue_security->previous_integrity = ue_security->integrity;
        ue_security->previous_ciphering = ue_security->ciphering;

        ue_security->algorithm_configuration_frame = security_info->algorithm_configuration_frame;
        ue_security->integrity = security_info->integrity;
        ue_security->ciphering = security_info->ciphering;
        ue_security->seen_next_ul_pdu = FALSE;
        ue_security->dl_after_reest_request = FALSE;
    }

    /* Also add an entry for this PDU already to use these settings, as otherwise it won't be present
       when we query it on the first pass. */
    p_frame_security = wmem_new(wmem_file_scope(), pdcp_nr_security_info_t);
    /* Deep copy*/
    *p_frame_security = *ue_security;
    wmem_map_insert(pdcp_security_result_hash,
                    get_ueid_frame_hash_key(ueid, ue_security->algorithm_configuration_frame, TRUE),
                    p_frame_security);
}


/* UE failed to process SecurityModeCommand so go back to previous security settings */
void set_pdcp_nr_security_algorithms_failed(guint16 ueid)
{
    /* Look up current state by UEID */
    pdcp_nr_security_info_t* ue_security =
        (pdcp_nr_security_info_t*)wmem_map_lookup(pdcp_security_hash,
                                                  GUINT_TO_POINTER((guint)ueid));
    if (ue_security != NULL) {
        /* TODO: could remove from table if previous_configuration_frame is 0 */
        /* Go back to previous state */
        ue_security->algorithm_configuration_frame = ue_security->previous_algorithm_configuration_frame;
        ue_security->integrity = ue_security->previous_integrity;
        ue_security->ciphering = ue_security->previous_ciphering;
    }
}

/* Function to indicate rrcReestablishmentRequest.
 * This results in the next DL SRB1 PDU not being decrypted */
void set_pdcp_nr_rrc_reestablishment_request(guint16 ueid)
{
    pdcp_nr_security_info_t *pdu_security = (pdcp_nr_security_info_t*)wmem_map_lookup(pdcp_security_hash,
                                                                                      GUINT_TO_POINTER(ueid));
    /* Set flag if entry found */
    if (pdu_security) {
        pdu_security->dl_after_reest_request = TRUE;
    }
}


/* Decipher payload if algorithm is supported and plausible inputs are available */
static tvbuff_t *decipher_payload(tvbuff_t *tvb, packet_info *pinfo, int *offset,
                                  pdu_security_settings_t *pdu_security_settings,
                                  struct pdcp_nr_info *p_pdcp_info, guint sdap_length,
                                  gboolean will_be_deciphered, gboolean *deciphered)
{
    guint8* decrypted_data = NULL;
    gint payload_length = 0;
    tvbuff_t *decrypted_tvb;

    /* Nothing to do if NULL ciphering */
    if (pdu_security_settings->ciphering == nea0 || pdu_security_settings->ciphering == nea_disabled) {
        return tvb;
    }

    /* Nothing to do if don't have valid cipher key */
    if (!pdu_security_settings->cipherKeyValid) {
        return tvb;
    }

    /* Check whether algorithm supported (only drop through and process if we do) */
    if (pdu_security_settings->ciphering == nea1) {
#ifndef HAVE_SNOW3G
        return tvb;
#endif
    }
    else if (pdu_security_settings->ciphering == nea3) {
#ifndef HAVE_ZUC
        return tvb;
#endif
    }
    else if (pdu_security_settings->ciphering != nea2) {
        /* An algorithm we don't support at all! */
        return tvb;
    }


    /* Don't decipher if turned off in preferences */
    if (((p_pdcp_info->plane == NR_SIGNALING_PLANE) &&  !global_pdcp_decipher_signalling) ||
        ((p_pdcp_info->plane == NR_USER_PLANE) &&       !global_pdcp_decipher_userplane)) {
        return tvb;
    }

    /* Don't decipher user-plane control messages */
    if ((p_pdcp_info->plane == NR_USER_PLANE) && ((tvb_get_guint8(tvb, 0) & 0x80) == 0x00)) {
        return tvb;
    }

    /* Don't decipher common control messages */
    if ((p_pdcp_info->plane == NR_SIGNALING_PLANE) && (p_pdcp_info->bearerType != Bearer_DCCH)) {
        return tvb;
    }

    /* Don't decipher if not yet past SecurityModeResponse */
    if (!will_be_deciphered) {
        return tvb;
    }

    /* AES */
    if (pdu_security_settings->ciphering == nea2) {
        unsigned char ctr_block[16];
        gcry_cipher_hd_t cypher_hd;
        int gcrypt_err;
        /* TS 33.501 D.4.4 defers to TS 33.401 B.1.3 */

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
        payload_length = tvb_captured_length_remaining(tvb, *offset+sdap_length);
        decrypted_data = (guint8 *)tvb_memdup(pinfo->pool, tvb, *offset+sdap_length, payload_length);

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
    if (pdu_security_settings->ciphering == nea1) {
        /* TS 33.501 D.4.3 defers to RS 33.401 */

        /* Extract the encrypted data into a buffer */
        payload_length = tvb_captured_length_remaining(tvb, *offset+sdap_length);
        decrypted_data = (guint8 *)tvb_memdup(pinfo->pool, tvb, *offset+sdap_length, payload_length);

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
    if (pdu_security_settings->ciphering == nea3) {
        /* Extract the encrypted data into a buffer */
        payload_length = tvb_captured_length_remaining(tvb, *offset+sdap_length);
        decrypted_data = (guint8 *)tvb_memdup(pinfo->pool, tvb, *offset+sdap_length, payload_length);

        /* Do the algorithm.  Assuming implementation works in-place */
        zuc_f8(pdu_security_settings->cipherKey,
               pdu_security_settings->count,
               pdu_security_settings->bearer,
               pdu_security_settings->direction,
               payload_length*8,                   /* Length is in bits */
               (guint32*)decrypted_data, (guint32*)decrypted_data);
    }
#endif

    /* Create tvb for resulting deciphered sdu */
    decrypted_tvb = tvb_new_child_real_data(tvb, decrypted_data, payload_length, payload_length);
    add_new_data_source(pinfo, decrypted_tvb, "Deciphered Payload");

    /* Return deciphered data, i.e. beginning of new tvb */
    *offset = 0;
    *deciphered = TRUE;
    return decrypted_tvb;
}

/* Try to calculate digest to compare with that found in frame. */
static guint32 calculate_digest(pdu_security_settings_t *pdu_security_settings, tvbuff_t *header_tvb _U_,
                                tvbuff_t *tvb _U_, gint offset _U_, guint sdap_length _U_, gboolean *calculated)
{
    *calculated = FALSE;

    if (pdu_security_settings->integrity == nia0) {
        /* Should be zero in this case */
        *calculated = TRUE;
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
        case nia1:
            {
                /* SNOW3G */
                guint8  *mac;
                guint header_length = tvb_reported_length(header_tvb);
                gint message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                guint8 *message_data = (guint8 *)wmem_alloc0(wmem_packet_scope(), header_length+message_length-sdap_length+4);

                /* TS 33.401 B.2.2 */

                /* Data is header bytes */
                tvb_memcpy(header_tvb, message_data, 0, header_length);
                /* Followed by the decrypted message (but not the digest bytes) */
                tvb_memcpy(tvb, message_data+header_length, offset+sdap_length, message_length-sdap_length);

                mac = (u8*)snow3g_f9(pdu_security_settings->integrityKey,
                                     pdu_security_settings->count,
                                     /* 'Fresh' is the bearer bits then zeros */
                                     pdu_security_settings->bearer << 27,
                                     pdu_security_settings->direction,
                                     message_data,
                                     (message_length+1)*8);

                *calculated = TRUE;
                return ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
            }
#endif

        case nia2:
            {
                /* AES */
                gcry_mac_hd_t mac_hd;
                int gcrypt_err;
                guint header_length;
                gint message_length;
                guint8 *message_data;
                guint8  mac[4];
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

                /* TS 33.501 D.4.3 defers to TS 33.401 B.2.3 */

                /* Extract the encrypted data into a buffer */
                header_length = tvb_reported_length(header_tvb);
                message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                message_data = (guint8 *)wmem_alloc0(wmem_packet_scope(), 8+header_length+message_length-sdap_length);
                message_data[0] = (pdu_security_settings->count & 0xff000000) >> 24;
                message_data[1] = (pdu_security_settings->count & 0x00ff0000) >> 16;
                message_data[2] = (pdu_security_settings->count & 0x0000ff00) >> 8;
                message_data[3] = (pdu_security_settings->count & 0x000000ff);
                message_data[4] = (pdu_security_settings->bearer << 3) + (pdu_security_settings->direction << 2);
                /* rest of first 8 bytes are left as zeroes... */

                /* Now the header bytes */
                tvb_memcpy(header_tvb, message_data+8, 0, header_length);
                /* Followed by the decrypted message (but not the digest bytes or any SDAP bytes) */
                tvb_memcpy(tvb, message_data+8+header_length, offset+sdap_length, message_length-sdap_length);

                /* Pass in the message */
                gcrypt_err = gcry_mac_write(mac_hd, message_data, 8+header_length+message_length-sdap_length);
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

                *calculated = TRUE;
                return ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
            }
#ifdef HAVE_ZUC
        case nia3:
            {
                /* ZUC */
                guint32  mac;
                guint header_length = tvb_reported_length(header_tvb);
                gint message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                guint8 *message_data = (guint8 *)wmem_alloc0(wmem_packet_scope(), header_length+message_length-sdap_length+4);

                /* Data is header bytes */
                tvb_memcpy(header_tvb, message_data, 0, header_length);
                /* Followed by the decrypted message (but not the digest bytes) */
                tvb_memcpy(tvb, message_data+header_length, offset+sdap_length, message_length-sdap_length);

                zuc_f9(pdu_security_settings->integrityKey,
                       pdu_security_settings->count,
                       pdu_security_settings->direction,
                       pdu_security_settings->bearer,
                       (message_length+header_length)*8,
                       (guint32*)message_data,
                       &mac);

                *calculated = TRUE;
                return mac;
            }
#endif

        default:
            /* Can't calculate */
            *calculated = FALSE;
            return 0;
    }
}




/* Forward declarations */
static int dissect_pdcp_nr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static void report_heur_error(proto_tree *tree, packet_info *pinfo, expert_field *eiindex,
                              tvbuff_t *tvb, gint start, gint length)
{
    proto_item *ti;
    proto_tree *subtree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-NR");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_pdcp_nr, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_pdcp);
    proto_tree_add_expert(subtree, pinfo, eiindex, tvb, start, length);
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_pdcp_nr_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data _U_)
{
    gint                  offset                 = 0;
    struct pdcp_nr_info *p_pdcp_nr_info;
    tvbuff_t             *pdcp_tvb;
    guint8                tag                    = 0;
    gboolean              seqnumLengthTagPresent = FALSE;

    /* Needs to be at least as long as:
       - the signature string
       - fixed header byte(s)
       - tag for data
       - at least one byte of PDCP PDU payload.
      However, let attempted dissection show if there are any tags at all. */
    gint min_length = (gint)(strlen(PDCP_NR_START_STRING) + 3); /* signature */

    if (tvb_captured_length_remaining(tvb, offset) < min_length) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, PDCP_NR_START_STRING, strlen(PDCP_NR_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(PDCP_NR_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_pdcp_nr_info = (pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
    if (p_pdcp_nr_info == NULL) {
        /* Allocate new info struct for this frame */
        p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);

        /* Read fixed fields */
        p_pdcp_nr_info->plane = (enum pdcp_nr_plane)tvb_get_guint8(tvb, offset++);
        if (p_pdcp_nr_info->plane == NR_SIGNALING_PLANE) {
            /* Signalling plane always has 12 SN bits */
            p_pdcp_nr_info->seqnum_length = PDCP_NR_SN_LENGTH_12_BITS;
        }

        /* Read tagged fields */
        while (tag != PDCP_NR_PAYLOAD_TAG) {
            /* Process next tag */
            tag = tvb_get_guint8(tvb, offset++);
            switch (tag) {
                case PDCP_NR_SEQNUM_LENGTH_TAG:
                    p_pdcp_nr_info->seqnum_length = tvb_get_guint8(tvb, offset);
                    offset++;
                    seqnumLengthTagPresent = TRUE;
                    break;
                case PDCP_NR_DIRECTION_TAG:
                    p_pdcp_nr_info->direction = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_BEARER_TYPE_TAG:
                    p_pdcp_nr_info->bearerType = (NRBearerType)tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_BEARER_ID_TAG:
                    p_pdcp_nr_info->bearerId = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_UEID_TAG:
                    p_pdcp_nr_info->ueid = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case PDCP_NR_ROHC_COMPRESSION_TAG:
                    p_pdcp_nr_info->rohc.rohc_compression = TRUE;
                    break;
                case PDCP_NR_ROHC_IP_VERSION_TAG:
                    p_pdcp_nr_info->rohc.rohc_ip_version = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_ROHC_CID_INC_INFO_TAG:
                    p_pdcp_nr_info->rohc.cid_inclusion_info = TRUE;
                    break;
                case PDCP_NR_ROHC_LARGE_CID_PRES_TAG:
                    p_pdcp_nr_info->rohc.large_cid_present = TRUE;
                    break;
                case PDCP_NR_ROHC_MODE_TAG:
                    p_pdcp_nr_info->rohc.mode = (enum rohc_mode)tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_ROHC_RND_TAG:
                    p_pdcp_nr_info->rohc.rnd = TRUE;
                    break;
                case PDCP_NR_ROHC_UDP_CHECKSUM_PRES_TAG:
                    p_pdcp_nr_info->rohc.udp_checksum_present = TRUE;
                    break;
                case PDCP_NR_ROHC_PROFILE_TAG:
                    p_pdcp_nr_info->rohc.profile = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case PDCP_NR_MACI_PRES_TAG:
                    p_pdcp_nr_info->maci_present = TRUE;
                    break;
                case PDCP_NR_SDAP_HEADER_TAG:
                    p_pdcp_nr_info->sdap_header = tvb_get_guint8(tvb, offset) & 0x03;
                    offset++;
                    break;
                case PDCP_NR_CIPHER_DISABLED_TAG:
                    p_pdcp_nr_info->ciphering_disabled = TRUE;
                    break;


                case PDCP_NR_PAYLOAD_TAG:
                    /* Have reached data, so get out of loop */
                    p_pdcp_nr_info->pdu_length = tvb_reported_length_remaining(tvb, offset);
                    continue;

                default:
                    /* It must be a recognised tag */
                    report_heur_error(tree, pinfo, &ei_pdcp_nr_unknown_udp_framing_tag, tvb, offset-1, 1);
                    wmem_free(wmem_file_scope(), p_pdcp_nr_info);
                    return TRUE;
            }
        }

        if ((p_pdcp_nr_info->plane == NR_USER_PLANE) && (seqnumLengthTagPresent == FALSE)) {
            /* Conditional field is not present */
            report_heur_error(tree, pinfo, &ei_pdcp_nr_missing_udp_framing_tag, tvb, 0, offset);
            wmem_free(wmem_file_scope(), p_pdcp_nr_info);
            return TRUE;
        }

        /* Store info in packet */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
    }
    else {
        offset = tvb_reported_length(tvb) - p_pdcp_nr_info->pdu_length;
    }

    /**************************************/
    /* OK, now dissect as PDCP nr         */

    /* Create tvb that starts at actual PDCP PDU */
    pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_pdcp_nr(pdcp_tvb, pinfo, tree, data);
    return TRUE;
}


/******************************/
/* Main dissection function.  */
static int dissect_pdcp_nr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    const char           *mode;
    proto_tree           *pdcp_tree          = NULL;
    proto_item           *root_ti            = NULL;
    proto_item           *ti;
    gint                 offset              = 0;
    struct pdcp_nr_info  *p_pdcp_info;
    tvbuff_t             *rohc_tvb           = NULL;

    pdcp_nr_security_info_t *current_security = NULL;   /* current security for this UE */
    pdcp_nr_security_info_t *pdu_security;              /* security in place for this PDU */
    proto_tree *security_tree = NULL;
    proto_item *security_ti;
    tvbuff_t *payload_tvb;
    pdu_security_settings_t  pdu_security_settings;
    gboolean payload_deciphered = FALSE;

    /* Initialise security settings */
    memset(&pdu_security_settings, 0, sizeof(pdu_security_settings));

    /* Set protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-NR");

    /* Look for attached packet info! */
    p_pdcp_info = (struct pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
    /* Can't dissect anything without it... */
    if (p_pdcp_info == NULL) {
        if (!data) {
            return 0;
        }
        p_pdcp_info = (struct pdcp_nr_info *)data;
    }

    /* If no RLC layer in this frame, query RLC table for configured drb settings */
    if (!p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0)) {
        /* Signalling plane is always 12 bits SN */
        if (p_pdcp_info->plane == NR_SIGNALING_PLANE && p_pdcp_info->bearerType == Bearer_DCCH) {
            p_pdcp_info->seqnum_length = PDCP_NR_SN_LENGTH_12_BITS;
        }
        /* If DRB channel, query rlc mappings (from RRC) */
        else if (p_pdcp_info->plane == NR_USER_PLANE) {
            pdcp_bearer_parameters *params = get_rlc_nr_drb_pdcp_mapping(p_pdcp_info->ueid, p_pdcp_info->bearerId);
            if (params) {
                if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                    p_pdcp_info->seqnum_length = params->pdcp_sn_bits_ul;
                    if (params->pdcp_sdap_ul) {
                        p_pdcp_info->sdap_header |= PDCP_NR_UL_SDAP_HEADER_PRESENT;
                    }
                }
                else {
                    p_pdcp_info->seqnum_length = params->pdcp_sn_bits_dl;
                    if (params->pdcp_sdap_dl) {
                        p_pdcp_info->sdap_header |= PDCP_NR_DL_SDAP_HEADER_PRESENT;
                    }
                }
                p_pdcp_info->maci_present = params->pdcp_integrity;
                p_pdcp_info->ciphering_disabled = params->pdcp_ciphering_disabled;
            }
        }
    }

    /* Don't want to overwrite the RLC Info column if configured not to */
    if ((global_pdcp_nr_layer_to_show == ShowRLCLayer) &&
        (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0) != NULL)) {

        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
    }
    else {
        /* TODO: won't help with multiple PDCP-or-traffic PDUs / frame... */
        col_clear(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, COL_INFO, TRUE);
    }

    /* MACI always present for SRBs */
    if ((p_pdcp_info->plane == NR_SIGNALING_PLANE) && (p_pdcp_info->bearerType == Bearer_DCCH)) {
        p_pdcp_info->maci_present = TRUE;
    }

    /* Create pdcp tree. */
    if (tree) {
        root_ti = proto_tree_add_item(tree, proto_pdcp_nr, tvb, offset, -1, ENC_NA);
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
        current_security = (pdcp_nr_security_info_t*)wmem_map_lookup(pdcp_security_hash,
                                                                     GUINT_TO_POINTER((guint)p_pdcp_info->ueid));
        if (current_security != NULL) {
            /* Store any result for this frame in the result table */
            pdcp_nr_security_info_t *security_to_store = wmem_new(wmem_file_scope(), pdcp_nr_security_info_t);
            /* Take a deep copy of the settings */
            *security_to_store = *current_security;

            /* But ciphering may be turned off for this channel */
            if (p_pdcp_info->ciphering_disabled) {
                security_to_store->ciphering = nea_disabled;
            }
            wmem_map_insert(pdcp_security_result_hash,
                            get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->num, TRUE),
                            security_to_store);
        }
        else {
            /* No entry added from RRC, but still use configured defaults */
            if ((global_default_ciphering_algorithm != nea0) ||
                (global_default_integrity_algorithm != nia0)) {
                /* Copy algorithms from preference defaults */
                pdcp_nr_security_info_t *security_to_store = wmem_new0(wmem_file_scope(), pdcp_nr_security_info_t);
                security_to_store->ciphering = global_default_ciphering_algorithm;
                security_to_store->integrity = global_default_integrity_algorithm;
                security_to_store->seen_next_ul_pdu = TRUE;
                wmem_map_insert(pdcp_security_result_hash,
                                get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->num, TRUE),
                                security_to_store);
            }
        }
    }

    /* Show security settings for this PDU */
    pdu_security = (pdcp_nr_security_info_t*)wmem_map_lookup(pdcp_security_result_hash,
                                                             get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->num, FALSE));
    if (pdu_security != NULL) {
        /* Create subtree */
        security_ti = proto_tree_add_string_format(pdcp_tree,
                                                   hf_pdcp_nr_security,
                                                   tvb, 0, 0,
                                                   "", "UE Security");
        security_tree = proto_item_add_subtree(security_ti, ett_pdcp_security);
        proto_item_set_generated(security_ti);

        /* Setup frame */
        if (pinfo->num > pdu_security->algorithm_configuration_frame) {
            ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_setup_frame,
                                     tvb, 0, 0, pdu_security->algorithm_configuration_frame);
            proto_item_set_generated(ti);
        }

        /* Ciphering */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_ciphering_algorithm,
                                 tvb, 0, 0, pdu_security->ciphering);
        proto_item_set_generated(ti);

        /* Integrity */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_nr_security_integrity_algorithm,
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
    /* Handle PDCP header              */

    guint32  seqnum = 0;
    gboolean seqnum_set = FALSE;

    guint8  first_byte = tvb_get_guint8(tvb, offset);

    /*****************************/
    /* Signalling plane messages */
    if (p_pdcp_info->plane == NR_SIGNALING_PLANE) {
        if (p_pdcp_info->seqnum_length != 0) {
            /* Always 12 bits SN */
            /* Verify 4 reserved bits are 0 */
            guint8 reserved = (first_byte & 0xf0) >> 4;
            ti = proto_tree_add_item(pdcp_tree, hf_pdcp_nr_control_plane_reserved,
                                     tvb, offset, 1, ENC_BIG_ENDIAN);
            if (reserved != 0) {
                expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                       "PDCP signalling header reserved bits not zero");
            }

            /* 12-bit sequence number */
            proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_seq_num_12, tvb, offset, 2, ENC_BIG_ENDIAN, &seqnum);
            seqnum_set = TRUE;
            write_pdu_label_and_info(root_ti, pinfo, " (SN=%-4u)", seqnum);
            offset += 2;

            if (tvb_captured_length_remaining(tvb, offset) == 0) {
                /* Only PDCP header was captured, stop dissection here */
                return offset;
            }
        }
    }
    else if (p_pdcp_info->plane == NR_USER_PLANE) {

        /**********************************/
        /* User-plane messages            */
        gboolean is_user_plane;

        /* Data/Control flag */
        proto_tree_add_item_ret_boolean(pdcp_tree, hf_pdcp_nr_data_control, tvb, offset, 1, ENC_BIG_ENDIAN, &is_user_plane);

        if (is_user_plane) {
            /*****************************/
            /* User-plane Data           */
            guint32 reserved_value;

            /* Number of sequence number bits depends upon config */
            switch (p_pdcp_info->seqnum_length) {
            case PDCP_NR_SN_LENGTH_12_BITS:
                /* 3 reserved bits */
                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                /* Complain if not 0 */
                if (reserved_value != 0) {
                    expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                           "Reserved bits have value 0x%x - should be 0x0",
                                           reserved_value);
                }

                /* 12-bit sequence number */
                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_seq_num_12, tvb, offset, 2, ENC_BIG_ENDIAN, &seqnum);
                seqnum_set = TRUE;
                offset += 2;
                break;
            case PDCP_NR_SN_LENGTH_18_BITS:
                /* 5 reserved bits */
                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_reserved5, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                /* Complain if not 0 */
                if (reserved_value != 0) {
                    expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                           "Reserved bits have value 0x%x - should be 0x0",
                                           reserved_value);
                }

                /* 18-bit sequence number */
                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_seq_num_18, tvb, offset, 3, ENC_BIG_ENDIAN, &seqnum);
                seqnum_set = TRUE;
                offset += 3;
                break;
            default:
                /* Not a recognised data format!!!!! */
                return 1;
            }

            write_pdu_label_and_info(root_ti, pinfo, " (SN=%-6u)", seqnum);
        }
        else {
            /*******************************/
            /* User-plane Control messages */
            guint32 control_pdu_type;
            proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_control_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN, &control_pdu_type);

            switch (control_pdu_type) {
            case 0:    /* PDCP status report */
            {
                guint32 fmc;
                guint   not_received = 0;
                guint   i, j, l;
                guint32 len, bit_offset;
                proto_tree *bitmap_tree;
                proto_item *bitmap_ti = NULL;
                gchar  *buff = NULL;
#define BUFF_SIZE 89
                guint32 reserved_value;

                /* 4 bits reserved */
                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_reserved4, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                /* Complain if not 0 */
                if (reserved_value != 0) {
                    expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                           "Reserved bits have value 0x%x - should be 0x0",
                                           reserved_value);
                }
                offset++;

                /* First-Missing-Count */
                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_fmc, tvb, offset, 4, ENC_BIG_ENDIAN, &fmc);
                offset += 4;


                /* Bitmap tree */
                if (tvb_reported_length_remaining(tvb, offset) > 0) {
                    bitmap_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_nr_bitmap, tvb,
                                                    offset, -1, ENC_NA);
                    bitmap_tree = proto_item_add_subtree(bitmap_ti, ett_pdcp_report_bitmap);

                    buff = (gchar *)wmem_alloc(wmem_packet_scope(), BUFF_SIZE);
                    len = tvb_reported_length_remaining(tvb, offset);
                    bit_offset = offset<<3;

                    /* For each byte... */
                    for (i=0; i<len; i++) {
                        guint8 bits = tvb_get_bits8(tvb, bit_offset, 8);
                        for (l=0, j=0; l<8; l++) {
                            if ((bits << l) & 0x80) {
                                if (bitmap_tree) {
                                    /* TODO: better to do mod and show as SN instead? */
                                    j += snprintf(&buff[j], BUFF_SIZE-j, "%10u,", (unsigned)(fmc+(8*i)+l+1));
                                }
                            } else {
                                if (bitmap_tree) {
                                    j += (guint)g_strlcpy(&buff[j], "          ,", BUFF_SIZE-j);
                                }
                                not_received++;
                            }
                        }
                        if (bitmap_tree) {
                            proto_tree_add_uint_format(bitmap_tree, hf_pdcp_nr_bitmap_byte, tvb, bit_offset/8, 1, bits, "%s", buff);
                        }
                        bit_offset += 8;
                    }
                }

                if (bitmap_ti != NULL) {
                    proto_item_append_text(bitmap_ti, " (%u SNs not received)", not_received);
                }
                write_pdu_label_and_info(root_ti, pinfo, " Status Report (fmc=%u) not-received=%u",
                                         fmc, not_received);
            }
                return 1;

            case 1:     /* ROHC Feedback */
                offset++;
                break;  /* Drop-through to dissect feedback */
            }
        }
    }
    else {
        /* Invalid plane setting...! */
        write_pdu_label_and_info(root_ti, pinfo, " - INVALID PLANE (%u)",
                                 p_pdcp_info->plane);
        return 1;
    }

    /* Have reached the end of the header (for data frames) */
    gint header_length = offset;

    /* Do sequence analysis if configured to. */
    if (seqnum_set) {
        gboolean do_analysis = FALSE;

        switch (global_pdcp_check_sequence_numbers) {
        case FALSE:
            break;
        case SEQUENCE_ANALYSIS_RLC_ONLY:
            if ((p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0) != NULL) &&
                    !p_pdcp_info->is_retx) {
                do_analysis = TRUE;
            }
            break;
        case SEQUENCE_ANALYSIS_PDCP_ONLY:
            if (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0) == NULL) {
                do_analysis = TRUE;
            }
            break;
        }

        if (do_analysis) {
            checkBearerSequenceInfo(pinfo, tvb, p_pdcp_info,
                                    seqnum, pdcp_tree, security_tree,
                                    &pdu_security_settings);
        }
    }


    /*******************************************************/
    /* Now deal with the payload                           */
    /*******************************************************/

    /* Any SDAP bytes (between header and payload) are ignored for integrity/encryption */
    guint sdap_length = 0;
    if (p_pdcp_info->plane == NR_USER_PLANE) {
        if ((p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK   && (p_pdcp_info->sdap_header & PDCP_NR_UL_SDAP_HEADER_PRESENT)) ||
            (p_pdcp_info->direction == PDCP_NR_DIRECTION_DOWNLINK && (p_pdcp_info->sdap_header & PDCP_NR_DL_SDAP_HEADER_PRESENT))) {
            /* Currently, all SDAP message bytes are 1 byte long */
            sdap_length = 1;
        }
    }

    /* Decipher payload if necessary */
    gboolean should_decipher = FALSE;
    if (pdu_security && !p_pdcp_info->ciphering_disabled) {
        if (p_pdcp_info->plane == NR_USER_PLANE) {
            /* Should decipher DRBs if have key */
            should_decipher = TRUE;
        }
        else {
            /* Control plane */
            /* Decipher if past securityModeComplete, snf not on DL after reestRequest */
            should_decipher = pdu_security->seen_next_ul_pdu && !pdu_security->dl_after_reest_request;

        }
    }
    payload_tvb = decipher_payload(tvb, pinfo, &offset, &pdu_security_settings, p_pdcp_info, sdap_length,
                                   should_decipher,
                                   &payload_deciphered);

    if ((p_pdcp_info->direction == PDCP_NR_DIRECTION_DOWNLINK) && current_security && (current_security->dl_after_reest_request)) {
        /* Have passed DL frame following reestRequest, so set back again */
        current_security->dl_after_reest_request = FALSE;
    }

    proto_item *mac_ti = NULL;
    guint32  calculated_digest = 0;
    gboolean digest_was_calculated = FALSE;

    /* Try to calculate digest so we can check it */
    if (global_pdcp_check_integrity && p_pdcp_info->maci_present) {
        calculated_digest = calculate_digest(&pdu_security_settings,
                                             tvb_new_subset_length(tvb, 0, header_length),
                                             payload_tvb,
                                             offset, sdap_length, &digest_was_calculated);
    }

    if (p_pdcp_info->plane == NR_SIGNALING_PLANE) {
        /* Compute payload length (no MAC on common control Bearers) */
        guint32 data_length = tvb_reported_length_remaining(payload_tvb, offset)-4;

        /* RRC data is all but last 4 bytes.
           Call nr-rrc dissector (according to direction and Bearer type) if we have valid data */
        if ((global_pdcp_dissect_signalling_plane_as_rrc) &&
            ((pdu_security == NULL) || (pdu_security->ciphering == nea0) || payload_deciphered ||
             p_pdcp_info->ciphering_disabled || !pdu_security->seen_next_ul_pdu || pdu_security->dl_after_reest_request)) {

            /* Get appropriate dissector handle */
            dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info, data_length);

            if (rrc_handle != NULL) {
                /* Call RRC dissector if have one */
                tvbuff_t *rrc_payload_tvb = tvb_new_subset_length(payload_tvb, offset, data_length);
                gboolean was_writable = col_get_writable(pinfo->cinfo, COL_INFO);

                /* We always want to see this in the info column */
                col_set_writable(pinfo->cinfo, COL_INFO, TRUE);

                /* N.B. Have seen some cases where RRC dissector throws an exception and doesn't return here, or show as malformed... */
                /* Have attempted to TRY CATCH etc, but with no joy */
                call_dissector_only(rrc_handle, rrc_payload_tvb, pinfo, pdcp_tree, NULL);

                /* Restore to whatever it was */
                col_set_writable(pinfo->cinfo, COL_INFO, was_writable);
            }
            else {
                 /* Just show data */
                 proto_tree_add_item(pdcp_tree, hf_pdcp_nr_signalling_data, payload_tvb, offset,
                                     data_length, ENC_NA);
            }

            /* Have we seen SecurityModResponse? */
            if (!PINFO_FD_VISITED(pinfo) &&
                (current_security != NULL) && !current_security->seen_next_ul_pdu &&
                p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK)
            {
                /* i.e. we have now seen SecurityModeResponse! */
                current_security->seen_next_ul_pdu = TRUE;
            }
        }
        else {
            /* Just show as unparsed data */
            proto_tree_add_item(pdcp_tree, hf_pdcp_nr_signalling_data, payload_tvb, offset,
                                data_length, ENC_NA);
        }
    }
    else if (tvb_captured_length_remaining(payload_tvb, offset)) {
        /* User-plane payload here. */
        gint payload_length = tvb_reported_length_remaining(payload_tvb, offset) - ((p_pdcp_info->maci_present) ? 4 : 0);

        if (sdap_length) {

            /* SDAP */
            proto_item *sdap_ti;
            proto_tree *sdap_tree;
            guint32 qfi;

            /* Protocol subtree */
            sdap_ti = proto_tree_add_item(pdcp_tree, proto_sdap, payload_tvb, offset, 1, ENC_NA);
            sdap_tree = proto_item_add_subtree(sdap_ti, ett_sdap);
            if (p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK) {
                gboolean data_control;
                proto_tree_add_item_ret_boolean(sdap_tree, hf_sdap_data_control, payload_tvb, offset, 1, ENC_NA, &data_control);
                proto_tree_add_item(sdap_tree, hf_sdap_reserved, payload_tvb, offset, 1, ENC_NA);
                proto_item_append_text(sdap_ti, " (%s", tfs_get_string(data_control, &pdu_type_bit));
            } else {
                gboolean rdi, rqi;
                proto_tree_add_item_ret_boolean(sdap_tree, hf_sdap_rdi, payload_tvb, offset, 1, ENC_NA, &rdi);
                proto_tree_add_item_ret_boolean(sdap_tree, hf_sdap_rqi, payload_tvb, offset, 1, ENC_NA, &rqi);
                proto_item_append_text(sdap_ti, " (RDI=%s, RQI=%s",
                                       tfs_get_string(rdi, &sdap_rdi), tfs_get_string(rqi, &sdap_rqi));
            }
            /* QFI is common to both directions */
            proto_tree_add_item_ret_uint(sdap_tree, hf_sdap_qfi, payload_tvb, offset, 1, ENC_NA, &qfi);
            offset++;
            proto_item_append_text(sdap_ti, "  QFI=%u)", qfi);
            payload_length--;
        }

        if (payload_length > 0) {
            /* If not compressed with ROHC, show as user-plane data */
            if (!p_pdcp_info->rohc.rohc_compression) {
                /* Not attempting to decode payload if payload ciphered and we did decipher */
                if (global_pdcp_dissect_user_plane_as_ip &&
                   ((pdu_security == NULL) || (pdu_security->ciphering == nea0) || payload_deciphered)) {

                    tvbuff_t *ip_payload_tvb = tvb_new_subset_length(payload_tvb, offset, payload_length);

                    /* Don't update info column for ROHC unless configured to */
                    if (global_pdcp_nr_layer_to_show != ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
                    }

                    switch (tvb_get_guint8(ip_payload_tvb, 0) & 0xf0) {
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
                    if (global_pdcp_nr_layer_to_show == ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
                    }

                }
                else {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_nr_user_plane_data, payload_tvb, offset, payload_length, ENC_NA);
                }
            }
            else {
                /***************************/
                /* ROHC packets            */
                /***************************/

                /* Only attempt ROHC if configured to */
                if (!global_pdcp_dissect_rohc) {
                    col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
                                    val_to_str_const(p_pdcp_info->rohc.profile, rohc_profile_vals, "Unknown"));
                    proto_tree_add_item(pdcp_tree, hf_pdcp_nr_user_plane_data, payload_tvb, offset, payload_length, ENC_NA);
                }
                else {
                    rohc_tvb = tvb_new_subset_length(payload_tvb, offset, payload_length);

                    /* Only enable writing to column if configured to show ROHC */
                    if (global_pdcp_nr_layer_to_show != ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
                    }
                    else {
                        col_clear(pinfo->cinfo, COL_INFO);
                    }

                    /* Call the ROHC dissector */
                    call_dissector_with_data(rohc_handle, rohc_tvb, pinfo, tree, &p_pdcp_info->rohc);
                }
            }
        }
    }

    /* MAC */
    if (p_pdcp_info->maci_present) {
        /* Last 4 bytes are MAC */
        gint mac_offset = tvb_reported_length(payload_tvb)-4;
        guint32 mac = tvb_get_ntohl(payload_tvb, mac_offset);
        mac_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_nr_mac, payload_tvb, mac_offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (digest_was_calculated) {
            /* Compare what was found with calculated value! */
            if (mac != calculated_digest) {
                expert_add_info_format(pinfo, mac_ti, &ei_pdcp_nr_digest_wrong,
                                       "MAC-I Digest wrong - calculated %08x but found %08x",
                                       calculated_digest, mac);
                proto_item_append_text(mac_ti, " (but calculated %08x !)", calculated_digest);
            }
            else {
                proto_item_append_text(mac_ti, " [Matches calculated result]");
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " MAC=0x%08x", mac);
    }

    /* Let RLC write to columns again */
    col_set_writable(pinfo->cinfo, COL_INFO, global_pdcp_nr_layer_to_show == ShowRLCLayer);

    return tvb_captured_length(tvb);
}


void proto_register_pdcp_nr(void)
{
    static hf_register_info hf_pdcp[] =
    {
        { &hf_pdcp_nr_configuration,
            { "Configuration",
              "pdcp-nr.configuration", FT_STRING, BASE_NONE, NULL, 0x0,
              "Configuration info passed into dissector", HFILL
            }
        },
        { &hf_pdcp_nr_direction,
            { "Direction",
              "pdcp-nr.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_pdcp_nr_ueid,
            { "UE",
              "pdcp-nr.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "UE Identifier", HFILL
            }
        },
        { &hf_pdcp_nr_bearer_type,
            { "Bearer type",
              "pdcp-nr.Bearer-type", FT_UINT8, BASE_DEC, VALS(bearer_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_bearer_id,
            { "Bearer Id",
              "pdcp-nr.bearer-id", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_plane,
            { "Plane",
              "pdcp-nr.plane", FT_UINT8, BASE_DEC, VALS(pdcp_plane_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_seqnum_length,
            { "Seqnum length",
              "pdcp-nr.seqnum_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Sequence Number Length", HFILL
            }
        },
        { &hf_pdcp_nr_maci_present,
            { "MAC-I Present",
              "pdcp-nr.maci_present", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "Indicates whether MAC-I digest bytes are expected", HFILL
            }
        },
        { &hf_pdcp_nr_sdap,
            { "SDAP header",
              "pdcp-nr.sdap", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
              "Indicates whether SDAP appears after PDCP headers", HFILL
            }
        },
        { &hf_pdcp_nr_ciphering_disabled,
            { "Ciphering disabled",
              "pdcp-nr.ciphering-disabled", FT_BOOLEAN, 8, NULL, 0x0,
              NULL, HFILL
            }
        },


        { &hf_pdcp_nr_rohc_compression,
            { "ROHC Compression",
              "pdcp-nr.rohc.compression", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_rohc_mode,
            { "ROHC Mode",
              "pdcp-nr.rohc.mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_rohc_rnd,
            { "RND",
              "pdcp-nr.rohc.rnd", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "RND of outer ip header", HFILL
            }
        },
        { &hf_pdcp_nr_rohc_udp_checksum_present,
            { "UDP Checksum",
              "pdcp-nr.rohc.checksum-present", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "UDP Checksum present", HFILL
            }
        },
        { &hf_pdcp_nr_rohc_profile,
            { "ROHC profile",
              "pdcp-nr.rohc.profile", FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_nr_cid_inclusion_info,
            { "CID Inclusion Info",
              "pdcp-nr.cid-inclusion-info", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_large_cid_present,
            { "Large CID Present",
              "pdcp-nr.large-cid-present", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_nr_control_plane_reserved,
            { "Reserved",
              "pdcp-nr.reserved", FT_UINT8, BASE_DEC, NULL, 0xf0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_reserved3,
            { "Reserved",
              "pdcp-nr.reserved3", FT_UINT8, BASE_HEX, NULL, 0x70,
              "3 reserved bits", HFILL
            }
        },
        { &hf_pdcp_nr_seq_num_12,
            { "Seq Num",
              "pdcp-nr.seq-num", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_nr_reserved5,
            { "Reserved",
              "pdcp-nr.reserved5", FT_UINT8, BASE_HEX, NULL, 0x7c,
              "5 reserved bits", HFILL
            }
        },
        { &hf_pdcp_nr_seq_num_18,
            { "Seq Num",
              "pdcp-nr.seq-num", FT_UINT24, BASE_DEC, NULL, 0x03ffff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_nr_signalling_data,
            { "Signalling Data",
              "pdcp-nr.signalling-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_mac,
            { "MAC",
              "pdcp-nr.mac", FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_data_control,
            { "PDU Type",
              "pdcp-nr.pdu-type", FT_BOOLEAN, 8, TFS(&pdu_type_bit), 0x80,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_user_plane_data,
            { "User-Plane Data",
              "pdcp-nr.user-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_control_pdu_type,
            { "Control PDU Type",
              "pdcp-nr.control-pdu-type", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_fmc,
            { "First Missing Count",
              "pdcp-nr.fmc", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_reserved4,
            { "Reserved",
              "pdcp-nr.reserved4", FT_UINT8, BASE_HEX, NULL, 0x0f,
              "4 reserved bits", HFILL
            }
        },
        { &hf_pdcp_nr_bitmap,
            { "Bitmap",
              "pdcp-nr.bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Status report bitmap (0=error, 1=OK)", HFILL
            }
        },
        { &hf_pdcp_nr_bitmap_byte,
            { "Bitmap byte",
              "pdcp-nr.bitmap.byte", FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_nr_sequence_analysis,
            { "Sequence Analysis",
              "pdcp-nr.sequence-analysis", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_ok,
            { "OK",
              "pdcp-nr.sequence-analysis.ok", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_previous_frame,
            { "Previous frame for Bearer",
              "pdcp-nr.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_next_frame,
            { "Next frame for Bearer",
              "pdcp-nr.sequence-analysis.next-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_expected_sn,
            { "Expected SN",
              "pdcp-nr.sequence-analysis.expected-sn", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_skipped,
            { "Skipped frames",
              "pdcp-nr.sequence-analysis.skipped-frames", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_repeated,
            { "Repeated frame",
              "pdcp-nr.sequence-analysis.repeated-frame", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        /* Security fields */
        { &hf_pdcp_nr_security,
            { "Security Config",
              "pdcp-nr.security-config", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_setup_frame,
            { "Configuration frame",
              "pdcp-nr.security-config.setup-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_integrity_algorithm,
            { "Integrity Algorithm",
              "pdcp-nr.security-config.integrity", FT_UINT16, BASE_DEC, VALS(integrity_algorithm_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_ciphering_algorithm,
            { "Ciphering Algorithm",
              "pdcp-nr.security-config.ciphering", FT_UINT16, BASE_DEC, VALS(ciphering_algorithm_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_bearer,
            { "BEARER",
              "pdcp-nr.security-config.bearer", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_direction,
            { "DIRECTION",
              "pdcp-nr.security-config.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_count,
            { "COUNT",
              "pdcp-nr.security-config.count", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_cipher_key,
            { "CIPHER KEY",
              "pdcp-nr.security-config.cipher-key", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_integrity_key,
            { "INTEGRITY KEY",
              "pdcp-nr.security-config.integrity-key", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_cipher_key_setup_frame,
            { "CIPHER KEY setup",
              "pdcp-nr.security-config.cipher-key.setup-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_security_integrity_key_setup_frame,
            { "INTEGRITY KEY setup",
              "pdcp-nr.security-config.integrity-key.setup-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        }
    };

    static hf_register_info hf_sdap[] =
    {
        { &hf_sdap_rdi,
            { "RDI",
              "sdap.rdi", FT_BOOLEAN, 8, TFS(&sdap_rdi), 0x80,
              "Reflective QoS flow to DRB mapping Indication", HFILL
            }
        },
        { &hf_sdap_rqi,
            { "RQI",
              "sdap.rqi", FT_BOOLEAN, 8, TFS(&sdap_rqi), 0x40,
              "Reflective QoS Indication", HFILL
            }
        },
        { &hf_sdap_qfi,
            { "QFI",
              "sdap.qfi", FT_UINT8, BASE_DEC, NULL, 0x3f,
              "QoS Flow ID", HFILL
            }
        },
        { &hf_sdap_data_control,
            { "PDU Type",
              "sdap.pdu-type", FT_BOOLEAN, 8, TFS(&pdu_type_bit), 0x80,
              NULL, HFILL
            }
        },
        { &hf_sdap_reserved,
            { "Reserved",
              "sdap.reserved", FT_UINT8, BASE_HEX, NULL, 0x40,
              NULL, HFILL
            }
        }
    };

    static gint *ett[] =
    {
        &ett_pdcp,
        &ett_pdcp_configuration,
        &ett_pdcp_packet,
        &ett_pdcp_nr_sequence_analysis,
        &ett_pdcp_report_bitmap,
        &ett_sdap,
        &ett_pdcp_security
    };

    static ei_register_info ei[] = {
        { &ei_pdcp_nr_sequence_analysis_sn_missing_ul, { "pdcp-nr.sequence-analysis.sn-missing-ul", PI_SEQUENCE, PI_WARN, "UL PDCP SNs missing", EXPFILL }},
        { &ei_pdcp_nr_sequence_analysis_sn_missing_dl, { "pdcp-nr.sequence-analysis.sn-missing-dl", PI_SEQUENCE, PI_WARN, "DL PDCP SNs missing", EXPFILL }},
        { &ei_pdcp_nr_sequence_analysis_sn_repeated_ul, { "pdcp-nr.sequence-analysis.sn-repeated-ul", PI_SEQUENCE, PI_WARN, "UL PDCP SNs repeated", EXPFILL }},
        { &ei_pdcp_nr_sequence_analysis_sn_repeated_dl, { "pdcp-nr.sequence-analysis.sn-repeated-dl", PI_SEQUENCE, PI_WARN, "DL PDCP SNs repeated", EXPFILL }},
        { &ei_pdcp_nr_sequence_analysis_wrong_sequence_number_ul, { "pdcp-nr.sequence-analysis.wrong-sequence-number-ul", PI_SEQUENCE, PI_WARN, "UL Wrong Sequence Number", EXPFILL }},
        { &ei_pdcp_nr_sequence_analysis_wrong_sequence_number_dl, { "pdcp-nr.sequence-analysis.wrong-sequence-number-dl", PI_SEQUENCE, PI_WARN, "DL Wrong Sequence Number", EXPFILL }},
        { &ei_pdcp_nr_reserved_bits_not_zero, { "pdcp-nr.reserved-bits-not-zero", PI_MALFORMED, PI_ERROR, "Reserved bits not zero", EXPFILL }},
        { &ei_pdcp_nr_digest_wrong, { "pdcp-nr.maci-wrong", PI_SEQUENCE, PI_ERROR, "MAC-I doesn't match expected value", EXPFILL }},
        { &ei_pdcp_nr_unknown_udp_framing_tag, { "pdcp-nr.unknown-udp-framing-tag", PI_UNDECODED, PI_WARN, "Unknown UDP framing tag, aborting dissection", EXPFILL }},
        { &ei_pdcp_nr_missing_udp_framing_tag, { "pdcp-nr.missing-udp-framing-tag", PI_UNDECODED, PI_WARN, "Missing UDP framing conditional tag, aborting dissection", EXPFILL }}
    };

    static const enum_val_t sequence_analysis_vals[] = {
        {"no-analysis", "No-Analysis",      FALSE},
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
        {"nea0", "NEA0 (NULL)",   nea0},
        {"nea1", "NEA1 (SNOW3G)", nea1},
        {"nea2", "NEA2 (AES)",    nea2},
        {"nea3", "NEA3 (ZUC)",    nea3},
        {NULL, NULL, -1}
    };

    static const enum_val_t default_integrity_algorithm_vals[] = {
        {"nia0", "NIA0 (NULL)",   nia0},
        {"nia1", "NIA1 (SNOW3G)", nia1},
        {"nia2", "NIA2 (AES)",    nia2},
        {"nia3", "NIA3 (ZUC)",    nia3},
        {NULL, NULL, -1}
    };

  static uat_field_t ue_keys_uat_flds[] = {
      UAT_FLD_DEC(uat_ue_keys_records, ueid, "UEId", "UE Identifier of UE associated with keys"),
      UAT_FLD_CSTRING(uat_ue_keys_records, rrcCipherKeyString,    "RRC Cipher Key",           "Key for deciphering signalling messages"),
      UAT_FLD_CSTRING(uat_ue_keys_records, upCipherKeyString,     "User-Plane Cipher Key",    "Key for deciphering user-plane messages"),
      UAT_FLD_CSTRING(uat_ue_keys_records, rrcIntegrityKeyString, "RRC Integrity Key",        "Key for calculating signalling integrity MAC"),
      UAT_FLD_CSTRING(uat_ue_keys_records, upIntegrityKeyString,  "User-Plane Integrity Key", "Key for calculating user-plane integrity MAC"),
      UAT_END_FIELDS
    };


    module_t *pdcp_nr_module;
    expert_module_t* expert_pdcp_nr;

    /* Register protocol. */
    proto_pdcp_nr = proto_register_protocol("PDCP-NR", "PDCP-NR", "pdcp-nr");
    proto_register_field_array(proto_pdcp_nr, hf_pdcp, array_length(hf_pdcp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pdcp_nr = expert_register_protocol(proto_pdcp_nr);
    expert_register_field_array(expert_pdcp_nr, ei, array_length(ei));
    proto_sdap = proto_register_protocol("SDAP", "SDAP", "sdap");
    proto_register_field_array(proto_sdap, hf_sdap, array_length(hf_sdap));

    /* Allow other dissectors to find this one by name. */
    register_dissector("pdcp-nr", dissect_pdcp_nr, proto_pdcp_nr);

    pdcp_nr_module = prefs_register_protocol(proto_pdcp_nr, NULL);

    /* Dissect uncompressed user-plane data as IP */
    prefs_register_bool_preference(pdcp_nr_module, "show_user_plane_as_ip",
        "Show uncompressed User-Plane data as IP",
        "Show uncompressed User-Plane data as IP",
        &global_pdcp_dissect_user_plane_as_ip);

    /* Dissect unciphered signalling data as RRC */
    prefs_register_bool_preference(pdcp_nr_module, "show_signalling_plane_as_rrc",
        "Show unciphered Signalling-Plane data as RRC",
        "Show unciphered Signalling-Plane data as RRC",
        &global_pdcp_dissect_signalling_plane_as_rrc);

    /* Check for missing sequence numbers */
    prefs_register_enum_preference(pdcp_nr_module, "check_sequence_numbers",
        "Do sequence number analysis",
        "Do sequence number analysis",
        &global_pdcp_check_sequence_numbers, sequence_analysis_vals, FALSE);

    /* Attempt to dissect ROHC messages */
    prefs_register_bool_preference(pdcp_nr_module, "dissect_rohc",
        "Attempt to decode ROHC data",
        "Attempt to decode ROHC data",
        &global_pdcp_dissect_rohc);

    prefs_register_obsolete_preference(pdcp_nr_module, "heuristic_pdcp_nr_over_udp");

    prefs_register_enum_preference(pdcp_nr_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show RLC, PDCP or Traffic layer info in Info column",
        &global_pdcp_nr_layer_to_show, show_info_col_vals, FALSE);

    ue_keys_uat = uat_new("PDCP UE security keys",
              sizeof(uat_ue_keys_record_t),    /* record size */
              "pdcp_nr_ue_keys",               /* filename */
              TRUE,                            /* from_profile */
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

    prefs_register_uat_preference(pdcp_nr_module,
                                  "ue_keys_table",
                                  "PDCP UE Keys",
                                  "Preconfigured PDCP keys",
                                  ue_keys_uat);

    prefs_register_enum_preference(pdcp_nr_module, "default_ciphering_algorithm",
        "Ciphering algorithm to use if not signalled",
        "If RRC Security Info not seen, e.g. in Handover",
        (gint*)&global_default_ciphering_algorithm, default_ciphering_algorithm_vals, FALSE);

    prefs_register_enum_preference(pdcp_nr_module, "default_integrity_algorithm",
        "Integrity algorithm to use if not signalled",
        "If RRC Security Info not seen, e.g. in Handover",
        (gint*)&global_default_integrity_algorithm, default_integrity_algorithm_vals, FALSE);

    /* Attempt to decipher RRC messages */
    prefs_register_bool_preference(pdcp_nr_module, "decipher_signalling",
        "Attempt to decipher Signalling (RRC) SDUs",
        "N.B. only possible if build with algorithm support, and have key available and configured",
        &global_pdcp_decipher_signalling);

    /* Attempt to decipher user-plane messages */
    prefs_register_bool_preference(pdcp_nr_module, "decipher_userplane",
        "Attempt to decipher User-plane (IP) SDUs",
        "N.B. only possible if build with algorithm support, and have key available and configured",
        &global_pdcp_decipher_userplane);

    /* Attempt to verify RRC integrity/authentication digest */
    prefs_register_bool_preference(pdcp_nr_module, "verify_integrity",
        "Attempt to check integrity calculation",
        "N.B. only possible if build with algorithm support, and have key available and configured",
        &global_pdcp_check_integrity);


    prefs_register_bool_preference(pdcp_nr_module, "ignore_rrc_sec_params",
        "Ignore RRC security parameters",
        "Ignore the NR RRC security algorithm configuration, to be used when PDCP is already deciphered in the capture",
        &global_pdcp_ignore_sec);


    pdcp_sequence_analysis_bearer_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    pdcp_nr_sequence_analysis_report_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pdcp_result_hash_func, pdcp_result_hash_equal);
    pdcp_security_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    pdcp_security_result_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pdcp_nr_ueid_frame_hash_func, pdcp_nr_ueid_frame_hash_equal);
    pdcp_security_key_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void proto_reg_handoff_pdcp_nr(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_pdcp_nr_heur, "PDCP-NR over UDP", "pdcp_nr_udp", proto_pdcp_nr, HEURISTIC_DISABLE);

    ip_handle              = find_dissector_add_dependency("ip", proto_pdcp_nr);
    ipv6_handle            = find_dissector_add_dependency("ipv6", proto_pdcp_nr);
    rohc_handle            = find_dissector_add_dependency("rohc", proto_pdcp_nr);
    nr_rrc_ul_ccch         = find_dissector_add_dependency("nr-rrc.ul.ccch", proto_pdcp_nr);
    nr_rrc_ul_ccch1        = find_dissector_add_dependency("nr-rrc.ul.ccch1", proto_pdcp_nr);
    nr_rrc_dl_ccch         = find_dissector_add_dependency("nr-rrc.dl.ccch", proto_pdcp_nr);
    nr_rrc_pcch            = find_dissector_add_dependency("nr-rrc.pcch", proto_pdcp_nr);
    nr_rrc_bcch_bch        = find_dissector_add_dependency("nr-rrc.bcch.bch", proto_pdcp_nr);
    nr_rrc_bcch_dl_sch     = find_dissector_add_dependency("nr-rrc.bcch.dl.sch", proto_pdcp_nr);
    nr_rrc_ul_dcch         = find_dissector_add_dependency("nr-rrc.ul.dcch", proto_pdcp_nr);
    nr_rrc_dl_dcch         = find_dissector_add_dependency("nr-rrc.dl.dcch", proto_pdcp_nr);
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
