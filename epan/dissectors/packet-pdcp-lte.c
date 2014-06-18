/* Routines for LTE PDCP
 *
 * Martin Mathieson
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

#include "config.h"

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/wmem/wmem.h>

#include <epan/uat.h>

#ifdef HAVE_LIBGCRYPT
#include <wsutil/wsgcrypt.h>
#endif /* HAVE_LIBGCRYPT */

/* Define this symbol if you have a working implementation of SNOW3G f8() and f9() available.
   Note that the use of this algorithm is restricted, and that an administrative charge
   may be applicable if you use it (see e.g. http://www.gsma.com/technicalprojects/fraud-security/security-algorithms).
   A version of Wireshark with this enabled would not be distributable. */
/* #define HAVE_SNOW3G */

#include "packet-rlc-lte.h"
#include "packet-pdcp-lte.h"

void proto_register_pdcp(void);
void proto_reg_handoff_pdcp_lte(void);

/* Described in:
 * 3GPP TS 36.323 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Packet Data Convergence Protocol (PDCP) specification v11.0.0
 */


/* TODO:
   - Decipher even if sequence analysis isn't 'OK'?
      - know SN, but might be unsure about HFN.
   - Speed up AES decryption by keeping the crypt handle around for the channel
     (like ESP decryption in IPSEC dissector) 
   - Add Relay Node user plane data PDU dissection
*/


/* Initialize the protocol and registered fields. */
int proto_pdcp_lte = -1;

extern int proto_rlc_lte;

/* Configuration (info known outside of PDU) */
static int hf_pdcp_lte_configuration = -1;
static int hf_pdcp_lte_direction = -1;
static int hf_pdcp_lte_ueid = -1;
static int hf_pdcp_lte_channel_type = -1;
static int hf_pdcp_lte_channel_id = -1;

static int hf_pdcp_lte_rohc_compression = -1;
static int hf_pdcp_lte_rohc_mode = -1;
static int hf_pdcp_lte_rohc_rnd = -1;
static int hf_pdcp_lte_rohc_udp_checksum_present = -1;
static int hf_pdcp_lte_rohc_profile = -1;

static int hf_pdcp_lte_no_header_pdu = -1;
static int hf_pdcp_lte_plane = -1;
static int hf_pdcp_lte_seqnum_length = -1;
static int hf_pdcp_lte_cid_inclusion_info = -1;
static int hf_pdcp_lte_large_cid_present = -1;

/* PDCP header fields */
static int hf_pdcp_lte_control_plane_reserved = -1;
static int hf_pdcp_lte_seq_num_5 = -1;
static int hf_pdcp_lte_seq_num_7 = -1;
static int hf_pdcp_lte_reserved3 = -1;
static int hf_pdcp_lte_seq_num_12 = -1;
static int hf_pdcp_lte_seq_num_15 = -1;
static int hf_pdcp_lte_signalling_data = -1;
static int hf_pdcp_lte_mac = -1;
static int hf_pdcp_lte_data_control = -1;
static int hf_pdcp_lte_user_plane_data = -1;
static int hf_pdcp_lte_control_pdu_type = -1;
static int hf_pdcp_lte_fms = -1;
static int hf_pdcp_lte_reserved4 = -1;
static int hf_pdcp_lte_fms2 = -1;
static int hf_pdcp_lte_bitmap = -1;


/* Sequence Analysis */
static int hf_pdcp_lte_sequence_analysis = -1;
static int hf_pdcp_lte_sequence_analysis_ok = -1;
static int hf_pdcp_lte_sequence_analysis_previous_frame = -1;
static int hf_pdcp_lte_sequence_analysis_next_frame = -1;
static int hf_pdcp_lte_sequence_analysis_expected_sn = -1;

static int hf_pdcp_lte_sequence_analysis_repeated = -1;
static int hf_pdcp_lte_sequence_analysis_skipped = -1;

/* Security Settings */
static int hf_pdcp_lte_security = -1;
static int hf_pdcp_lte_security_setup_frame = -1;
static int hf_pdcp_lte_security_integrity_algorithm = -1;
static int hf_pdcp_lte_security_ciphering_algorithm = -1;

static int hf_pdcp_lte_security_bearer = -1;
static int hf_pdcp_lte_security_direction = -1;
static int hf_pdcp_lte_security_count = -1;
static int hf_pdcp_lte_security_cipher_key = -1;
static int hf_pdcp_lte_security_integrity_key = -1;



/* Protocol subtree. */
static int ett_pdcp = -1;
static int ett_pdcp_configuration = -1;
static int ett_pdcp_packet = -1;
static int ett_pdcp_lte_sequence_analysis = -1;
static int ett_pdcp_report_bitmap = -1;
static int ett_pdcp_security = -1;

static expert_field ei_pdcp_lte_sequence_analysis_wrong_sequence_number = EI_INIT;
static expert_field ei_pdcp_lte_reserved_bits_not_zero = EI_INIT;
static expert_field ei_pdcp_lte_sequence_analysis_sn_repeated = EI_INIT;
static expert_field ei_pdcp_lte_sequence_analysis_sn_missing = EI_INIT;
static expert_field ei_pdcp_lte_digest_wrong = EI_INIT;

/*-------------------------------------
 * UAT for UE Keys
 *-------------------------------------
 */
/* UAT entry structure. */
typedef struct {
   guint16 ueid;
   gchar   *rrcCipherKeyString;
   gchar   *upCipherKeyString;
   gchar   *rrcIntegrityKeyString;

   guint8   rrcCipherBinaryKey[16];
   gboolean rrcCipherKeyOK;
   guint8   upCipherBinaryKey[16];
   gboolean upCipherKeyOK;
   guint8   rrcIntegrityBinaryKey[16];
   gboolean rrcIntegrityKeyOK;
} uat_ue_keys_record_t;

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
    else
        return 0;
}

static void* uat_ue_keys_record_copy_cb(void* n, const void* o, size_t siz _U_) {
    uat_ue_keys_record_t* new_rec = (uat_ue_keys_record_t *)n;
    const uat_ue_keys_record_t* old_rec = (const uat_ue_keys_record_t *)o;

    new_rec->ueid = old_rec->ueid;
    new_rec->rrcCipherKeyString = (old_rec->rrcCipherKeyString) ? g_strdup(old_rec->rrcCipherKeyString) : NULL;
    new_rec->upCipherKeyString = (old_rec->upCipherKeyString) ? g_strdup(old_rec->upCipherKeyString) : NULL;
    new_rec->rrcIntegrityKeyString = (old_rec->rrcIntegrityKeyString) ? g_strdup(old_rec->rrcIntegrityKeyString) : NULL;

    return new_rec;
}

/* If raw_string is a valid key, set check_string & return TRUE */
static gboolean check_valid_key_sring(const char* raw_string, char* checked_string)
{
    guint n;
    guint written = 0;
    guint length = (gint)strlen(raw_string);

    /* Can't be valid if not long enough. */
    if (length < 32) {
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
            return FALSE;
        }
    }

    /* Must have found exactly 32 hex ascii chars for 16-byte key */
    return (written == 32);
}

static void update_key_from_string(const char *stringKey, guint8 *binaryKey, gboolean *pKeyOK)
{
    int  n;
    char cleanString[32];

    if (!check_valid_key_sring(stringKey, cleanString)) {
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
static void uat_ue_keys_record_update_cb(void* record, const char** error _U_) {
    uat_ue_keys_record_t* rec = (uat_ue_keys_record_t *)record;

    /* Check and convert RRC key */
    update_key_from_string(rec->rrcCipherKeyString, rec->rrcCipherBinaryKey, &rec->rrcCipherKeyOK);

    /* Check and convert User-plane key */
    update_key_from_string(rec->upCipherKeyString, rec->upCipherBinaryKey, &rec->upCipherKeyOK);

    /* Check and convert Integrity key */
    update_key_from_string(rec->rrcIntegrityKeyString, rec->rrcIntegrityBinaryKey, &rec->rrcIntegrityKeyOK);
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

/* Table from ueid -> uat_ue_keys_record_t* */
static GHashTable *pdcp_security_key_hash = NULL;


void set_pdcp_lte_rrc_ciphering_key(guint16 ueid, const char *key)
{
    /* Get or create struct for this UE */
    uat_ue_keys_record_t *key_record = (uat_ue_keys_record_t*)g_hash_table_lookup(pdcp_security_key_hash,
                                                                                  GUINT_TO_POINTER((guint)ueid));
    if (key_record == NULL) {
        /* Create and add to table */
        key_record = wmem_new0(wmem_file_scope(), uat_ue_keys_record_t);
        key_record->ueid = ueid;
        g_hash_table_insert(pdcp_security_key_hash, GUINT_TO_POINTER((guint)ueid), key_record);
    }

    /* Check and convert RRC key */
    key_record->rrcCipherKeyString = g_strdup(key);
    update_key_from_string(key_record->rrcCipherKeyString, key_record->rrcCipherBinaryKey, &key_record->rrcCipherKeyOK);}

void set_pdcp_lte_rrc_integrity_key(guint16 ueid, const char *key)
{
    /* Get or create struct for this UE */
    uat_ue_keys_record_t *key_record = (uat_ue_keys_record_t*)g_hash_table_lookup(pdcp_security_key_hash,
                                                                                  GUINT_TO_POINTER((guint)ueid));
    if (key_record == NULL) {
        /* Create and add to table */
        key_record = wmem_new0(wmem_file_scope(), uat_ue_keys_record_t);
        key_record->ueid = ueid;
        g_hash_table_insert(pdcp_security_key_hash, GUINT_TO_POINTER((guint)ueid), key_record);
    }

    /* Check and convert RRC integrity key */
    key_record->rrcIntegrityKeyString = g_strdup(key);
    update_key_from_string(key_record->rrcIntegrityKeyString, key_record->rrcIntegrityBinaryKey, &key_record->rrcIntegrityKeyOK);
}

void set_pdcp_lte_up_ciphering_key(guint16 ueid, const char *key)
{
    /* Get or create struct for this UE */
    uat_ue_keys_record_t *key_record = (uat_ue_keys_record_t*)g_hash_table_lookup(pdcp_security_key_hash,
                                                                                  GUINT_TO_POINTER((guint)ueid));
    if (key_record == NULL) {
        /* Create and add to table */
        key_record = wmem_new0(wmem_file_scope(), uat_ue_keys_record_t);
        key_record->ueid = ueid;
        g_hash_table_insert(pdcp_security_key_hash, GUINT_TO_POINTER((guint)ueid), key_record);
    }

    /* Check and convert UP key */
    key_record->upCipherKeyString = g_strdup(key);
    update_key_from_string(key_record->upCipherKeyString, key_record->upCipherBinaryKey, &key_record->upCipherKeyOK);
}


/* Preference settings for deciphering and integrity checking.  Currently all default to off */
static gboolean global_pdcp_decipher_signalling = TRUE;
static gboolean global_pdcp_decipher_userplane = FALSE;  /* Can be slow, so default to FALSE */
static gboolean global_pdcp_check_integrity = FALSE;



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
    { 0x0101,   "ROHCv2 RTP" },             /* [RFC5225] */
    { 0x0002,   "ROHC UDP" },               /* [RFC3095] */
    { 0x0102,   "ROHCv2 UDP" },             /* [RFC5225] */
    { 0x0003,   "ROHC ESP" },               /* [RFC3095] */
    { 0x0103,   "ROHCv2 ESP" },             /* [RFC5225] */
    { 0x0004,   "ROHC IP" },                /* [RFC3843] */
    { 0x0104,   "ROHCv2 IP" },              /* [RFC5225] */
    { 0x0005,   "ROHC LLA" },               /* [RFC4362] */
    { 0x0105,   "ROHC LLA with R-mode" },   /* [RFC3408] */
    { 0x0006,   "ROHC TCP" },               /* [RFC4996] */
    { 0x0007,   "ROHC RTP/UDP-Lite" },      /* [RFC4019] */
    { 0x0107,   "ROHCv2 RTP/UDP-Lite" },    /* [RFC5225] */
    { 0x0008,   "ROHC UDP-Lite" },          /* [RFC4019] */
    { 0x0108,   "ROHCv2 UDP-Lite" },        /* [RFC5225] */
    { 0,   NULL }
};

static const value_string pdu_type_vals[] = {
    { 0,   "Control PDU" },
    { 1,   "Data PDU" },
    { 0,   NULL }
};

static const value_string control_pdu_type_vals[] = {
    { 0,   "PDCP Status report" },
    { 1,   "Header Compression Feedback Information" },
    { 0,   NULL }
};

static const value_string integrity_algorithm_vals[] = {
    { 0,   "EIA0" },
    { 1,   "EIA1" },
    { 2,   "EIA2" },
    { 3,   "EIA3" },
    { 0,   NULL }
};

static const value_string ciphering_algorithm_vals[] = {
    { 0,   "EEA0" },
    { 1,   "EEA1" },
    { 2,   "EEA2" },
    { 3,   "EEA3" },
    { 0,   NULL }
};


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t rohc_handle;
static dissector_handle_t data_handle;


#define SEQUENCE_ANALYSIS_RLC_ONLY  1
#define SEQUENCE_ANALYSIS_PDCP_ONLY 2

/* Preference variables */
static gboolean global_pdcp_dissect_user_plane_as_ip = TRUE;
static gboolean global_pdcp_dissect_signalling_plane_as_rrc = TRUE;
static gint     global_pdcp_check_sequence_numbers = TRUE;
static gboolean global_pdcp_dissect_rohc = FALSE;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowRLCLayer, ShowPDCPLayer, ShowTrafficLayer
};
static gint     global_pdcp_lte_layer_to_show = (gint)ShowRLCLayer;



/**************************************************/
/* Sequence number analysis                       */

/* Channel key */
typedef struct
{
    /* Using bit fields to fit into 32 bits, so avoiding the need to allocate
       heap memory for these structs */
    guint           ueId : 16;
    guint           plane : 2;
    guint           channelId : 6;
    guint           direction : 1;
    guint           notUsed : 7;
} pdcp_channel_hash_key;

/* Channel state */
typedef struct
{
    guint16  previousSequenceNumber;
    guint32  previousFrameNum;
    guint32  hfn;
} pdcp_channel_status;

/* The sequence analysis channel hash table.
   Maps key -> status */
static GHashTable *pdcp_sequence_analysis_channel_hash = NULL;

/* Equal keys */
static gint pdcp_channel_equal(gconstpointer v, gconstpointer v2)
{
    /* Key fits in 4 bytes, so just compare pointers! */
    return (v == v2);
}

/* Compute a hash value for a given key. */
static guint pdcp_channel_hash_func(gconstpointer v)
{
    /* Just use pointer, as the fields are all in this value */
    return GPOINTER_TO_UINT(v);
}


/* Hash table types & functions for frame reports */

typedef struct {
    guint32         frameNumber;
    guint32         SN :       15;
    guint32         plane :    2;
    guint32         channelId: 5;
    guint32         direction: 1;
    guint32         notUsed :  9;
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
    return val1->frameNumber + (val1->channelId<<13) +
                               (val1->plane<<5) +
                               (val1->SN<<18) +
                               (val1->direction<<9);
}

/* pdcp_channel_hash_key fits into the pointer, so just copy the value into
   a guint, cast to apointer and return that as the key */
static gpointer get_channel_hash_key(pdcp_channel_hash_key *key)
{
    guint  asInt = 0;
    /* TODO: assert that sizeof(pdcp_channel_hash_key) <= sizeof(guint) ? */
    memcpy(&asInt, key, sizeof(pdcp_channel_hash_key));
    return GUINT_TO_POINTER(asInt);
}

/* Convenience function to get a pointer for the hash_func to work with */
static gpointer get_report_hash_key(guint16 SN, guint32 frameNumber,
                                    pdcp_lte_info *p_pdcp_lte_info,
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
    p_key->plane = (guint8)p_pdcp_lte_info->plane;
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
    gboolean sequenceExpectedCorrect;
    guint16  sequenceExpected;
    guint32  previousFrameNum;
    guint32  nextFrameNum;

    guint16  firstSN;
    guint16  lastSN;
    guint32  hfn;

    sequence_state state;
} pdcp_sequence_report_in_frame;

/* The sequence analysis frame report hash table.
   Maps pdcp_result_hash_key* -> pdcp_sequence_report_in_frame* */
static GHashTable *pdcp_lte_sequence_analysis_report_hash = NULL;

/* Gather together security settings in order to be able to do deciphering */
typedef struct pdu_security_settings_t
{
    enum security_ciphering_algorithm_e ciphering;
    enum security_integrity_algorithm_e integrity;
    guint8* cipherKey;
    guint8* integrityKey;
    gboolean cipherKeyValid;
    gboolean integrityKeyValid;
    guint32 count;
    guint8  bearer;
    guint8  direction;
} pdu_security_settings_t;


static uat_ue_keys_record_t* look_up_keys_record(guint16 ueid)
{
    unsigned int record_id;
    /* Try hash table first */
    uat_ue_keys_record_t* key_record = (uat_ue_keys_record_t*)g_hash_table_lookup(pdcp_security_key_hash,
                                                                                  GUINT_TO_POINTER((guint)ueid));
    if (key_record != NULL) {
        return key_record;
    }

    /* Else look up UAT entries */
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
                                   guint16   sequenceNumber,
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
    PROTO_ITEM_SET_GENERATED(seqnum_ti);


    /* Previous channel frame */
    if (p->previousFrameNum != 0) {
        proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_previous_frame,
                            tvb, 0, 0, p->previousFrameNum);
    }

    /* Expected sequence number */
    ti_expected_sn = proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_expected_sn,
                                         tvb, 0, 0, p->sequenceExpected);
    PROTO_ITEM_SET_GENERATED(ti_expected_sn);

    /* Make sure we have recognised SN length */
    switch (p_pdcp_lte_info->seqnum_length) {
        case PDCP_SN_LENGTH_5_BITS:
        case PDCP_SN_LENGTH_7_BITS:
        case PDCP_SN_LENGTH_12_BITS:
        case PDCP_SN_LENGTH_15_BITS:
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    switch (p->state) {
        case SN_OK:
            PROTO_ITEM_SET_HIDDEN(ti_expected_sn);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(seqnum_ti, " - OK");

            /* Link to next SN in channel (if known) */
            if (p->nextFrameNum != 0) {
                proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_next_frame,
                                    tvb, 0, 0, p->nextFrameNum);
            }

            /* May also be able to add key inputs to security tree here */
            if ((pdu_security->ciphering != eea0) ||
                (pdu_security->integrity != eia0)) {
                guint32              hfn_multiplier;
                guint32              count;
                gchar                *cipher_key = NULL;
                gchar                *integrity_key = NULL;

                /* BEARER */
                ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_bearer,
                                         tvb, 0, 0, p_pdcp_lte_info->channelId-1);
                PROTO_ITEM_SET_GENERATED(ti);
                pdu_security->bearer = p_pdcp_lte_info->channelId-1;

                /* DIRECTION */
                ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_direction,
                                         tvb, 0, 0, p_pdcp_lte_info->direction);
                PROTO_ITEM_SET_GENERATED(ti);

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
                    default:
                        DISSECTOR_ASSERT_NOT_REACHED();
                        break;
                }
                count = (p->hfn * hfn_multiplier) + sequenceNumber;
                ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_count,
                                         tvb, 0, 0, count);
                PROTO_ITEM_SET_GENERATED(ti);
                pdu_security->count = count;

                /* KEY.  Look this UE up among UEs that have keys configured */
                keys_record = look_up_keys_record(p_pdcp_lte_info->ueid);
                if (keys_record != NULL) {
                    if (p_pdcp_lte_info->plane == SIGNALING_PLANE) {
                        /* Get RRC ciphering key */
                        if (keys_record->rrcCipherKeyOK) {
                            cipher_key = keys_record->rrcCipherKeyString;
                            pdu_security->cipherKey = &(keys_record->rrcCipherBinaryKey[0]);
                            pdu_security->cipherKeyValid = TRUE;
                        }
                        /* Get RRC integrity key */
                        if (keys_record->rrcIntegrityKeyOK) {
                            integrity_key = keys_record->rrcIntegrityKeyString;
                            pdu_security->integrityKey = &(keys_record->rrcIntegrityBinaryKey[0]);
                            pdu_security->integrityKeyValid = TRUE;
                        }
                    }
                    else {
                        /* Get userplane ciphering key */
                        if (keys_record->upCipherKeyOK) {
                            cipher_key = keys_record->upCipherKeyString;
                            pdu_security->cipherKey = &(keys_record->upCipherBinaryKey[0]);
                            pdu_security->cipherKeyValid = TRUE;
                        }
                    }

                    /* Show keys where known and valid */
                    if (cipher_key != NULL) {
                        ti = proto_tree_add_string(security_tree, hf_pdcp_lte_security_cipher_key,
                                                   tvb, 0, 0, cipher_key);
                        PROTO_ITEM_SET_GENERATED(ti);
                    }
                    if (integrity_key != NULL) {
                        ti = proto_tree_add_string(security_tree, hf_pdcp_lte_security_integrity_key,
                                                   tvb, 0, 0, integrity_key);
                        PROTO_ITEM_SET_GENERATED(ti);
                    }

                    pdu_security->direction = p_pdcp_lte_info->direction;
                }
            }
            break;

        case SN_Missing:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_skipped,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
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
                                        tvb, 0, 0, FALSE);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_repeated,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
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
                                     guint16 sequenceNumber,
                                     proto_tree *tree,
                                     proto_tree *security_tree,
                                     pdu_security_settings_t *pdu_security)
{
    pdcp_channel_hash_key          channel_key;
    pdcp_channel_status           *p_channel_status;
    pdcp_sequence_report_in_frame *p_report_in_frame      = NULL;
    gboolean                       createdChannel         = FALSE;
    guint16                        expectedSequenceNumber = 0;
    guint16                        snLimit                = 0;

    /* If find stat_report_in_frame already, use that and get out */
    if (pinfo->fd->flags.visited) {
        p_report_in_frame =
            (pdcp_sequence_report_in_frame*)g_hash_table_lookup(pdcp_lte_sequence_analysis_report_hash,
                                                                get_report_hash_key(sequenceNumber,
                                                                                    pinfo->fd->num,
                                                                                    p_pdcp_lte_info, FALSE));
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
    p_channel_status = (pdcp_channel_status*)g_hash_table_lookup(pdcp_sequence_analysis_channel_hash,
                                                                 get_channel_hash_key(&channel_key));

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {
        createdChannel = TRUE;

        /* Allocate a new value and duplicate key contents */
        p_channel_status = wmem_new0(wmem_file_scope(), pdcp_channel_status);

        /* Add entry */
        g_hash_table_insert(pdcp_sequence_analysis_channel_hash,
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
            p_channel_status->previousFrameNum = pinfo->fd->num;
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
        p_channel_status->previousFrameNum = pinfo->fd->num;
        p_channel_status->previousSequenceNumber = sequenceNumber;

        if (p_report_in_frame->previousFrameNum != 0) {
            /* Get report for previous frame */
            pdcp_sequence_report_in_frame *p_previous_report;
            p_previous_report = (pdcp_sequence_report_in_frame*)g_hash_table_lookup(pdcp_lte_sequence_analysis_report_hash,
                                                                                    get_report_hash_key((sequenceNumber+32767) % 32768,
                                                                                                        p_report_in_frame->previousFrameNum,
                                                                                                        p_pdcp_lte_info,
                                                                                                        FALSE));
            /* It really shouldn't be NULL... */
            if (p_previous_report != NULL) {
                /* Point it forward to this one */
                p_previous_report->nextFrameNum = pinfo->fd->num;
            }
        }
    }

    /* Associate with this frame number */
    g_hash_table_insert(pdcp_lte_sequence_analysis_report_hash,
                        get_report_hash_key(sequenceNumber, pinfo->fd->num,
                                            p_pdcp_lte_info, TRUE),
                        p_report_in_frame);

    /* Add state report for this frame into tree */
    addChannelSequenceInfo(p_report_in_frame, p_pdcp_lte_info, sequenceNumber,
                           pinfo, tree, tvb, security_tree, pdu_security);
}



/* Hash table for security state for a UE
   Maps UEId -> pdcp_security_info_t*  */
static gint pdcp_lte_ueid_hash_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}
static guint pdcp_lte_ueid_hash_func(gconstpointer v)
{
    return GPOINTER_TO_UINT(v);
}
static GHashTable *pdcp_security_hash = NULL;

/* Result is (ueid, framenum) -> pdcp_security_info_t*  */
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
        memset(&key, 0, sizeof(ueid_frame_t));
        p_key = &key;
    }

    /* Fill in details, and return pointer */
    p_key->framenum = frameNumber;
    p_key->ueid = ueid;

    return p_key;
}

static gint pdcp_lte_ueid_frame_hash_equal(gconstpointer v, gconstpointer v2)
{
    const ueid_frame_t *ueid_frame_1 = (const ueid_frame_t *)v;
    const ueid_frame_t *ueid_frame_2 = (const ueid_frame_t *)v2;
    return ((ueid_frame_1->framenum == ueid_frame_2->framenum) && (ueid_frame_1->ueid == ueid_frame_2->ueid));
}
static guint pdcp_lte_ueid_frame_hash_func(gconstpointer v)
{
    const ueid_frame_t *ueid_frame = (const ueid_frame_t *)v;
    return ueid_frame->framenum + 100*ueid_frame->ueid;
}
static GHashTable *pdcp_security_result_hash = NULL;




/* Write the given formatted text to:
   - the info column
   - the top-level RLC PDU item */
static void write_pdu_label_and_info(proto_item *pdu_ti,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];

    va_list ap;

    va_start(ap, format);
    g_vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
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
                                                       tvb, 0, 0, ENC_ASCII|ENC_NA);
    configuration_tree = proto_item_add_subtree(configuration_ti, ett_pdcp_configuration);

    /* Direction */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_direction, tvb, 0, 0,
                             p_pdcp_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Plane */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_plane, tvb, 0, 0,
                             p_pdcp_info->plane);
    PROTO_ITEM_SET_GENERATED(ti);

    /* UEId */
    if (p_pdcp_info->ueid != 0) {
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_ueid, tvb, 0, 0,
                                 p_pdcp_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Channel type */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_type, tvb, 0, 0,
                             p_pdcp_info->channelType);
    PROTO_ITEM_SET_GENERATED(ti);
    if (p_pdcp_info->channelId != 0) {
        /* Channel type */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_id, tvb, 0, 0,
                                 p_pdcp_info->channelId);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    /* User-plane-specific fields */
    if (p_pdcp_info->plane == USER_PLANE) {

        /* No Header PDU */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_no_header_pdu, tvb, 0, 0,
                                 p_pdcp_info->no_header_pdu);
        PROTO_ITEM_SET_GENERATED(ti);

        if (!p_pdcp_info->no_header_pdu) {

            /* Seqnum length */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_seqnum_length, tvb, 0, 0,
                                     p_pdcp_info->seqnum_length);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    /* ROHC compression */
    ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_lte_rohc_compression, tvb, 0, 0,
                                p_pdcp_info->rohc.rohc_compression);
    PROTO_ITEM_SET_GENERATED(ti);

    /* ROHC-specific settings */
    if (p_pdcp_info->rohc.rohc_compression) {

        /* Show ROHC mode */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_mode, tvb, 0, 0,
                                 p_pdcp_info->rohc.mode);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Show RND */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_rnd, tvb, 0, 0,
                                 p_pdcp_info->rohc.rnd);
        PROTO_ITEM_SET_GENERATED(ti);

        /* UDP Checksum */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_udp_checksum_present, tvb, 0, 0,
                                 p_pdcp_info->rohc.udp_checksum_present);
        PROTO_ITEM_SET_GENERATED(ti);

        /* ROHC profile */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_profile, tvb, 0, 0,
                                 p_pdcp_info->rohc.profile);
        PROTO_ITEM_SET_GENERATED(ti);

        /* CID Inclusion Info */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_cid_inclusion_info, tvb, 0, 0,
                                 p_pdcp_info->rohc.cid_inclusion_info);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Large CID */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_large_cid_present, tvb, 0, 0,
                                 p_pdcp_info->rohc.large_cid_present);
        PROTO_ITEM_SET_GENERATED(ti);
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
    PROTO_ITEM_SET_GENERATED(configuration_ti);

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
                rrc_handle = find_dissector("lte_rrc.ul_ccch");
            }
            else {
                rrc_handle = find_dissector("lte_rrc.dl_ccch");
            }
            break;
        case Channel_PCCH:
            rrc_handle = find_dissector("lte_rrc.pcch");
            break;
        case Channel_BCCH:
            switch (p_pdcp_info->BCCHTransport) {
                case BCH_TRANSPORT:
                    rrc_handle = find_dissector("lte_rrc.bcch_bch");
                    break;
                case DLSCH_TRANSPORT:
                    rrc_handle = find_dissector("lte_rrc.bcch_dl_sch");
                    break;
            }
            break;
        case Channel_DCCH:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = find_dissector("lte_rrc.ul_dcch");
            }
            else {
                rrc_handle = find_dissector("lte_rrc.dl_dcch");
            }
            break;


        default:
            break;
    }

    return rrc_handle;
}


/* Forwad declarations */
static void dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Heuristic dissection */
static gboolean global_pdcp_lte_heur = FALSE;

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_pdcp_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data _U_)
{
    gint                  offset                 = 0;
    struct pdcp_lte_info *p_pdcp_lte_info;
    tvbuff_t             *pdcp_tvb;
    guint8                tag                    = 0;
    gboolean              infoAlreadySet         = FALSE;
    gboolean              seqnumLengthTagPresent = FALSE;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!global_pdcp_lte_heur) {
        return FALSE;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of PDCP PDU payload */
    if (tvb_captured_length_remaining(tvb, offset) < (gint)(strlen(PDCP_LTE_START_STRING)+3+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, PDCP_LTE_START_STRING, strlen(PDCP_LTE_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(PDCP_LTE_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_pdcp_lte_info = (pdcp_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0);
    if (p_pdcp_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_pdcp_lte_info = wmem_new0(wmem_file_scope(), pdcp_lte_info);
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }


    /* Read fixed fields */
    p_pdcp_lte_info->no_header_pdu = (gboolean)tvb_get_guint8(tvb, offset++);
    p_pdcp_lte_info->plane = (enum pdcp_plane)tvb_get_guint8(tvb, offset++);
    if (p_pdcp_lte_info->plane == SIGNALING_PLANE) {
        p_pdcp_lte_info->seqnum_length = PDCP_SN_LENGTH_5_BITS;
    }
    p_pdcp_lte_info->rohc.rohc_compression = (gboolean)tvb_get_guint8(tvb, offset++);

    /* Read optional fields */
    while (tag != PDCP_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case PDCP_LTE_SEQNUM_LENGTH_TAG:
                p_pdcp_lte_info->seqnum_length = tvb_get_guint8(tvb, offset);
                offset++;
                seqnumLengthTagPresent = TRUE;
                break;
            case PDCP_LTE_DIRECTION_TAG:
                p_pdcp_lte_info->direction = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_LOG_CHAN_TYPE_TAG:
                p_pdcp_lte_info->channelType = (LogicalChannelType)tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_BCCH_TRANSPORT_TYPE_TAG:
                p_pdcp_lte_info->BCCHTransport = (BCCHTransportType)tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_IP_VERSION_TAG:
                p_pdcp_lte_info->rohc.rohc_ip_version = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case PDCP_LTE_ROHC_CID_INC_INFO_TAG:
                p_pdcp_lte_info->rohc.cid_inclusion_info = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_LARGE_CID_PRES_TAG:
                p_pdcp_lte_info->rohc.large_cid_present = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_MODE_TAG:
                p_pdcp_lte_info->rohc.mode = (enum rohc_mode)tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_RND_TAG:
                p_pdcp_lte_info->rohc.rnd = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_UDP_CHECKSUM_PRES_TAG:
                p_pdcp_lte_info->rohc.udp_checksum_present = tvb_get_guint8(tvb, offset);
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
                continue;

            default:
                /* It must be a recognised tag */
                return FALSE;
        }
    }

    if ((p_pdcp_lte_info->plane == USER_PLANE) && (seqnumLengthTagPresent == FALSE)) {
        /* Conditional field is not present */
        return FALSE;
    }

    if (!infoAlreadySet) {
        /* Store info in packet */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0, p_pdcp_lte_info);
    }

    /**************************************/
    /* OK, now dissect as PDCP LTE        */

    /* Create tvb that starts at actual PDCP PDU */
    pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_pdcp_lte(pdcp_tvb, pinfo, tree);
    return TRUE;
}

/* Called from control protocol to configure security algorithms for the given UE */
void set_pdcp_lte_security_algorithms(guint16 ueid, pdcp_security_info_t *security_info)
{
    /* Use for this frame so can check integrity on SecurityCommandRequest frame */
    /* N.B. won't work for internal, non-RRC signalling methods... */
    pdcp_security_info_t *p_frame_security;

    /* Create or update current settings, by UEID */
    pdcp_security_info_t* ue_security =
        (pdcp_security_info_t*)g_hash_table_lookup(pdcp_security_hash,
                                                   GUINT_TO_POINTER((guint)ueid));
    if (ue_security == NULL) {
        /* Copy whole security struct */
        ue_security = wmem_new(wmem_file_scope(), pdcp_security_info_t);
        *ue_security = *security_info;

        /* And add into security table */
        g_hash_table_insert(pdcp_security_hash, GUINT_TO_POINTER((guint)ueid), ue_security);
    }
    else {
        /* Just update existing entry already in table */
        ue_security->previous_configuration_frame = ue_security->configuration_frame;
        ue_security->previous_integrity = ue_security->integrity;
        ue_security->previous_ciphering = ue_security->ciphering;

        ue_security->configuration_frame = security_info->configuration_frame;
        ue_security->integrity = security_info->integrity;
        ue_security->ciphering = security_info->ciphering;
        ue_security->seen_next_ul_pdu = FALSE;
    }

    /* Also add an entry for this PDU already to use these settings, as otherwise it won't be present
       when we query it on the first pass. */
    p_frame_security = wmem_new(wmem_file_scope(), pdcp_security_info_t);
    *p_frame_security = *ue_security;
    g_hash_table_insert(pdcp_security_result_hash,
                        get_ueid_frame_hash_key(ueid, ue_security->configuration_frame, TRUE),
                        p_frame_security);
}

/* UE failed to process SecurityModeCommand so go back to previous security settings */
void set_pdcp_lte_security_algorithms_failed(guint16 ueid)
{
    /* Look up current state by UEID */
    pdcp_security_info_t* ue_security =
        (pdcp_security_info_t*)g_hash_table_lookup(pdcp_security_hash,
                                                   GUINT_TO_POINTER((guint)ueid));
    if (ue_security != NULL) {
        /* TODO: could remove from table if previous_configuration_frame is 0 */
        /* Go back to previous state */
        ue_security->configuration_frame = ue_security->previous_configuration_frame;
        ue_security->integrity = ue_security->previous_integrity;
        ue_security->ciphering = ue_security->previous_ciphering;
    }
}

/* Decipher payload if algorithm is supported and plausible inputs are available */
static tvbuff_t *decipher_payload(tvbuff_t *tvb, packet_info *pinfo, int *offset,
                                  pdu_security_settings_t *pdu_security_settings,
                                  enum pdcp_plane plane, gboolean will_be_deciphered,
                                  gboolean *deciphered)
{
    guint8* decrypted_data = NULL;
    gint payload_length = 0;
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
    else
    if (pdu_security_settings->ciphering == eea2) {
#ifndef HAVE_LIBGCRYPT
        return tvb;
#endif
    }
    else {
        /* An algorithm we don't support at all! */
        return tvb;
    }

    /* Don't decipher if turned off in preferences */
    if (((plane == SIGNALING_PLANE) &&  !global_pdcp_decipher_signalling) ||
        ((plane == USER_PLANE) &&       !global_pdcp_decipher_userplane)) {
        return tvb;
    }

    /* Don't decipher control messages */
    if ((plane == USER_PLANE) && ((tvb_get_guint8(tvb, 0) & 0x80) == 0x00)) {
        return tvb;
    }

    /* Don't decipher if not yet past SecurityModeResponse */
    if (!will_be_deciphered) {
        return tvb;
    }

#ifdef HAVE_LIBGCRYPT
    /* AES */
    if (pdu_security_settings->ciphering == eea2) {
        unsigned char ctr_block[16];
        gcry_cipher_hd_t cypher_hd;
        int gcrypt_err;

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
        decrypted_data = (guint8 *)g_malloc0(payload_length);
        tvb_memcpy(tvb, decrypted_data, *offset, payload_length);

        /* Decrypt the actual data */
        gcrypt_err = gcry_cipher_decrypt(cypher_hd,
                                         decrypted_data, payload_length,
                                         NULL, 0);
        if (gcrypt_err != 0) {
            gcry_cipher_close(cypher_hd);
            g_free(decrypted_data);
            return tvb;
        }

        /* Close gcrypt handle */
        gcry_cipher_close(cypher_hd);
    }
#endif

#ifdef HAVE_SNOW3G
    /* SNOW-3G */
    if (pdu_security_settings->ciphering == eea1) {
        /* Extract the encrypted data into a buffer */
        payload_length = tvb_captured_length_remaining(tvb, *offset);
        decrypted_data = (guint8 *)g_malloc0(payload_length+4);
        tvb_memcpy(tvb, decrypted_data, *offset, payload_length);

        /* Do the algorithm */
        snow3g_f8(pdu_security_settings->cipherKey,
                  pdu_security_settings->count,
                  pdu_security_settings->bearer,
                  pdu_security_settings->direction,
                  decrypted_data, payload_length*8);
    }
#endif

    /* Create tvb for resulting deciphered sdu */
    decrypted_tvb = tvb_new_child_real_data(tvb, decrypted_data, payload_length, payload_length);
    tvb_set_free_cb(decrypted_tvb, g_free);
    add_new_data_source(pinfo, decrypted_tvb, "Deciphered Payload");

    /* Return deciphered data, i.e. beginning of new tvb */
    *offset = 0;
    *deciphered = TRUE;
    return decrypted_tvb;
}


/* Try to calculate digest to compare with that found in frame. */
static guint32 calculate_digest(pdu_security_settings_t *pdu_security_settings, guint8 header _U_,
                                tvbuff_t *tvb _U_, gint offset _U_, gboolean *calculated)
{
    *calculated = FALSE;

    if (pdu_security_settings->integrity == eia0) {
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
        case eia1:
            {
                guint8  *mac;
                gint message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                guint8 *message_data = (guint8 *)g_malloc0(message_length+5);
                message_data[0] = header;
                tvb_memcpy(tvb, message_data+1, offset, message_length);

                mac = (u8*)snow3g_f9(pdu_security_settings->integrityKey,
                                     pdu_security_settings->count,
                                     /* 'Fresh' is the bearer bits then zeros */
                                     pdu_security_settings->bearer << 27,
                                     pdu_security_settings->direction,
                                     message_data,
                                     (message_length+1)*8);

                *calculated = TRUE;
                g_free(message_data);
                return ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
            }
#endif

#if (defined GCRYPT_VERSION_NUMBER) && (GCRYPT_VERSION_NUMBER >= 0x010600)
        case eia2:
            {
                gcry_mac_hd_t mac_hd;
                int gcrypt_err;
                gint message_length;
                guint8 *message_data;
                guint8  mac[4];
                size_t read_digest_length = 4;

                /* Open gcrypt handle */
                /* N.B. Unfortunately GCRY_MAC_CMAC_AES is not available in currently used version of gcrypt! */
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

                /* Extract the encrypted data into a buffer */
                message_length = tvb_captured_length_remaining(tvb, offset) - 4;
                message_data = (guint8 *)g_malloc0(message_length+9);
                message_data[0] = (pdu_security_settings->count & 0xff000000) >> 24;
                message_data[1] = (pdu_security_settings->count & 0x00ff0000) >> 16;
                message_data[2] = (pdu_security_settings->count & 0x0000ff00) >> 8;
                message_data[3] = (pdu_security_settings->count & 0x000000ff);
                message_data[4] = (pdu_security_settings->bearer << 3) + (pdu_security_settings->direction << 2);
                /* rest of first 8 bytes are left as zeroes... */
                message_data[8] = header;
                tvb_memcpy(tvb, message_data+9, offset, message_length);

                /* Pass in the message */
                gcrypt_err = gcry_mac_write(mac_hd, message_data, message_length+9);
                if (gcrypt_err != 0) {
                    gcry_mac_close(mac_hd);
                    g_free(message_data);
                    return 0;
                }

                /* Read out the digest */
                gcrypt_err = gcry_mac_read(mac_hd, mac, &read_digest_length);
                if (gcrypt_err != 0) {
                    gcry_mac_close(mac_hd);
                    g_free(message_data);
                    return 0;
                }

                /* Now close the mac handle */
                gcry_mac_close(mac_hd);

                g_free(message_data);

                *calculated = TRUE;
                return ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
            }
#endif

        default:
            /* Can't calculate */
            *calculated = FALSE;
            return 0;
    }
}



/******************************/
/* Main dissection function.  */
static void dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    const char           *mode;
    proto_tree           *pdcp_tree           = NULL;
    proto_item           *root_ti             = NULL;
    gint                  offset              = 0;
    struct pdcp_lte_info *p_pdcp_info;
    tvbuff_t             *rohc_tvb            = NULL;

    pdcp_security_info_t *current_security = NULL;   /* current security for this UE */
    pdcp_security_info_t *pdu_security;              /* security in place for this PDU */
    proto_tree *security_tree = NULL;
    proto_item *security_ti;
    tvbuff_t *payload_tvb;
    pdu_security_settings_t  pdu_security_settings;
    gboolean payload_deciphered = FALSE;

    /* Initialise security settings */
    memset(&pdu_security_settings, 0, sizeof(pdu_security_settings));

    /* Set protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-LTE");

    /* Look for attached packet info! */
    p_pdcp_info = (struct pdcp_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0);
    /* Can't dissect anything without it... */
    if (p_pdcp_info == NULL) {
        return;
    }

    /* Don't want to overwrite the RLC Info column if configured not to */
    if ((global_pdcp_lte_layer_to_show == ShowRLCLayer) &&
        (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0) != NULL)) {

        col_set_writable(pinfo->cinfo, FALSE);
    }
    else {
        /* TODO: won't help with multiple PDCP-or-traffic PDUs / frame... */
        col_clear(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, TRUE);
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
    if (!pinfo->fd->flags.visited) {
        /* Look up current state by UEID */
        current_security = (pdcp_security_info_t*)g_hash_table_lookup(pdcp_security_hash,
                                                                      GUINT_TO_POINTER((guint)p_pdcp_info->ueid));
        if (current_security != NULL) {
            /* Store any result for this frame in the result table */
            pdcp_security_info_t *security_to_store = wmem_new(wmem_file_scope(), pdcp_security_info_t);
            /* Take a deep copy of the settings */
            *security_to_store = *current_security;
            g_hash_table_insert(pdcp_security_result_hash,
                                get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->fd->num, TRUE),
                                security_to_store);
        }
    }

    /* Show security settings for this PDU */
    pdu_security = (pdcp_security_info_t*)g_hash_table_lookup(pdcp_security_result_hash, get_ueid_frame_hash_key(p_pdcp_info->ueid, pinfo->fd->num, FALSE));
    if (pdu_security != NULL) {
        proto_item *ti;

        /* Create subtree */
        security_ti = proto_tree_add_string_format(pdcp_tree,
                                                   hf_pdcp_lte_security,
                                                   tvb, 0, 0,
                                                   "", "UE Security");
        security_tree = proto_item_add_subtree(security_ti, ett_pdcp_security);
        PROTO_ITEM_SET_GENERATED(security_ti);

        /* Setup frame */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_setup_frame,
                                 tvb, 0, 0, pdu_security->configuration_frame);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Ciphering */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_ciphering_algorithm,
                                 tvb, 0, 0, pdu_security->ciphering);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Integrity */
        ti = proto_tree_add_uint(security_tree, hf_pdcp_lte_security_integrity_algorithm,
                                 tvb, 0, 0, pdu_security->integrity);
        PROTO_ITEM_SET_GENERATED(ti);

        proto_item_append_text(security_ti, " (ciphering=%s, integrity=%s)",
                               val_to_str_const(pdu_security->ciphering, ciphering_algorithm_vals, "Unknown"),
                               val_to_str_const(pdu_security->integrity, integrity_algorithm_vals, "Unknown"));

        pdu_security_settings.ciphering = pdu_security->ciphering;
        pdu_security_settings.integrity = pdu_security->integrity;
    }


    /***********************************/
    /* Handle PDCP header (if present) */
    if (!p_pdcp_info->no_header_pdu) {

        /* TODO: shouldn't need to initialise this one!! */
        guint16  seqnum = 0;
        gboolean seqnum_set = FALSE;

        guint8  first_byte = tvb_get_guint8(tvb, offset);

        /*****************************/
        /* Signalling plane messages */
        if (p_pdcp_info->plane == SIGNALING_PLANE) {
            /* Verify 3 reserved bits are 0 */
            guint8 reserved = (first_byte & 0xe0) >> 5;
            proto_item *ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_control_plane_reserved,
                                                 tvb, offset, 1, ENC_BIG_ENDIAN);
            if (reserved != 0) {
                expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                       "PDCP signalling header reserved bits not zero");
            }

            /* 5-bit sequence number */
            seqnum = first_byte & 0x1f;
            seqnum_set = TRUE;
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_5, tvb, offset, 1, ENC_BIG_ENDIAN);
            write_pdu_label_and_info(root_ti, pinfo, " sn=%-2u ", seqnum);
            offset++;

            if (tvb_reported_length_remaining(tvb, offset) == 0) {
                /* Only PDCP header was captured, stop dissection here */
                return;
            }
        }
        else if (p_pdcp_info->plane == USER_PLANE) {

            /**********************************/
            /* User-plane messages            */
            gboolean pdu_type = (first_byte & 0x80) >> 7;

            /* Data/Control flag */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_data_control, tvb, offset, 1, ENC_BIG_ENDIAN);

            if (pdu_type == 1) {
                /*****************************/
                /* Use-plane Data            */

                /* Number of sequence number bits depends upon config */
                switch (p_pdcp_info->seqnum_length) {
                    case PDCP_SN_LENGTH_7_BITS:
                        seqnum = first_byte & 0x7f;
                        seqnum_set = TRUE;
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_7, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        break;
                    case PDCP_SN_LENGTH_12_BITS:
                        {
                            proto_item *ti;
                            guint8 reserved_value;

                            /* 3 reserved bits */
                            ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN);
                            reserved_value = (first_byte & 0x70) >> 4;

                            /* Complain if not 0 */
                            if (reserved_value != 0) {
                                expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                       "Reserved bits have value 0x%x - should be 0x0",
                                                       reserved_value);
                            }

                            /* 12-bit sequence number */
                            seqnum = tvb_get_ntohs(tvb, offset) & 0x0fff;
                            seqnum_set = TRUE;
                            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_12, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                        }
                        break;
                    case PDCP_SN_LENGTH_15_BITS:
                        seqnum = tvb_get_ntohs(tvb, offset) & 0x7fff;
                        seqnum_set = TRUE;
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_15, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        break;
                    default:
                        /* Not a recognised data format!!!!! */
                        return;
                }

                write_pdu_label_and_info(root_ti, pinfo, " (SN=%u)", seqnum);
            }
            else {
                /*******************************/
                /* User-plane Control messages */
                guint8 control_pdu_type = (first_byte & 0x70) >> 4;
                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_control_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);

                switch (control_pdu_type) {
                    case 0:    /* PDCP status report */
                        {
                            guint8  bits;
                            guint16 fms;
                            guint16 modulo;
                            guint   not_received = 0;
                            guint   sn, i, j, l;
                            guint32 len, bit_offset;
                            proto_tree *bitmap_tree;
                            proto_item *bitmap_ti = NULL;
                            gchar  *buff = NULL;
                            #define BUFF_SIZE 49

                            if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_12_BITS) {
                                /* First-Missing-Sequence SN */
                                fms = tvb_get_ntohs(tvb, offset) & 0x0fff;
                                sn = (fms + 1) % 4096;
                                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_fms, tvb,
                                                    offset, 2, ENC_BIG_ENDIAN);
                                offset += 2;
                                modulo = 4096;
                            } else {
                                proto_item *ti;
                                guint8 reserved_value;

                                /* 5 reserved bits */
                                ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_reserved4, tvb, offset, 2, ENC_BIG_ENDIAN);
                                reserved_value = (tvb_get_ntohs(tvb, offset) & 0x0f80)>>7;
                                offset++;

                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, &ei_pdcp_lte_reserved_bits_not_zero,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                /* First-Missing-Sequence SN */
                                fms = tvb_get_ntohs(tvb, offset) & 0x7fff;
                                sn = (fms + 1) % 32768;
                                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_fms2, tvb,
                                                    offset, 2, ENC_BIG_ENDIAN);
                                offset += 2;
                                modulo = 32768;
                            }

                            /* Bitmap tree */
                            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                                bitmap_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_bitmap, tvb,
                                                                offset, -1, ENC_NA);
                                bitmap_tree = proto_item_add_subtree(bitmap_ti, ett_pdcp_report_bitmap);

                                 buff = (gchar *)wmem_alloc(wmem_packet_scope(), BUFF_SIZE);
                                 len = tvb_reported_length_remaining(tvb, offset);
                                 bit_offset = offset<<3;
                                /* For each byte... */
                                for (i=0; i<len; i++) {
                                    bits = tvb_get_bits8(tvb, bit_offset, 8);
                                    for (l=0, j=0; l<8; l++) {
                                        if ((bits << l) & 0x80) {
                                            j += g_snprintf(&buff[j], BUFF_SIZE-j, "%5u,", (unsigned)(sn+(8*i)+l)%modulo);
                                        } else {
                                            j += g_snprintf(&buff[j], BUFF_SIZE-j, "     ,");
                                            not_received++;
                                        }
                                    }
                                    proto_tree_add_text(bitmap_tree, tvb, bit_offset/8, 1, "%s", buff);
                                    bit_offset += 8;
                                }
                            }

                            if (bitmap_ti != NULL) {
                                proto_item_append_text(bitmap_ti, " (%u SNs not received)", not_received);
                            }
                            write_pdu_label_and_info(root_ti, pinfo, " Status Report (fms=%u) not-received=%u",
                                                    fms, not_received);
                        }
                        return;

                    case 1:     /* ROHC Feedback */
                        offset++;
                        break;  /* Drop-through to dissect feedback */

                    default:    /* Reserved */
                        return;
                }
            }
        }
        else {
            /* Invalid plane setting...! */
            write_pdu_label_and_info(root_ti, pinfo, " - INVALID PLANE (%u)",
                                     p_pdcp_info->plane);
            return;
        }

        /* Do sequence analysis if configured to. */
        if (seqnum_set) {
            gboolean do_analysis = FALSE;

            switch (global_pdcp_check_sequence_numbers) {
                case FALSE:
                    break;
                case SEQUENCE_ANALYSIS_RLC_ONLY:
                    if ((p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0) != NULL) &&
                        !p_pdcp_info->is_retx) {
                        do_analysis = TRUE;
                    }
                    break;
                case SEQUENCE_ANALYSIS_PDCP_ONLY:
                    if (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_lte, 0) == NULL) {
                        do_analysis = TRUE;
                    }
                    break;
            }

            if (do_analysis) {
                checkChannelSequenceInfo(pinfo, tvb, p_pdcp_info,
                                         (guint16)seqnum, pdcp_tree, security_tree,
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

    /* Check pdu_security_settings - may need to do deciphering before calling
       further dissectors on payload */
    payload_tvb = decipher_payload(tvb, pinfo, &offset, &pdu_security_settings, p_pdcp_info->plane,
                                   pdu_security ? pdu_security->seen_next_ul_pdu: FALSE, &payload_deciphered);

    if (p_pdcp_info->plane == SIGNALING_PLANE) {
        guint32 data_length;
        guint32 mac;
        proto_item *mac_ti;
        guint32  calculated_digest = 0;
        gboolean digest_was_calculated = FALSE;

        /* Try to calculate digest so we can check it */
        if (global_pdcp_check_integrity) {
            calculated_digest = calculate_digest(&pdu_security_settings, tvb_get_guint8(tvb, 0), payload_tvb,
                                                 offset, &digest_was_calculated);
        }

        /* RRC data is all but last 4 bytes.
           Call lte-rrc dissector (according to direction and channel type) if we have valid data */
        if ((global_pdcp_dissect_signalling_plane_as_rrc) &&
            ((pdu_security == NULL) || (pdu_security->ciphering == eea0) || payload_deciphered || !pdu_security->seen_next_ul_pdu)) {
            /* Get appropriate dissector handle */
            dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info);

            if (rrc_handle != 0) {
                /* Call RRC dissector if have one */
                tvbuff_t *rrc_payload_tvb = tvb_new_subset(payload_tvb, offset,
                                                           tvb_captured_length_remaining(payload_tvb, offset) - 4,
                                                           tvb_reported_length_remaining(payload_tvb, offset) - 4);
                gboolean was_writable = col_get_writable(pinfo->cinfo);

                /* We always want to see this in the info column */
                col_set_writable(pinfo->cinfo, TRUE);

                call_dissector_only(rrc_handle, rrc_payload_tvb, pinfo, pdcp_tree, NULL);

                /* Restore to whatever it was */
                col_set_writable(pinfo->cinfo, was_writable);
            }
            else {
                 /* Just show data */
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, payload_tvb, offset,
                                        tvb_reported_length_remaining(tvb, offset) - 4, ENC_NA);
            }

            if (!pinfo->fd->flags.visited &&
                (current_security != NULL) && !current_security->seen_next_ul_pdu &&
                p_pdcp_info->direction == DIRECTION_UPLINK)
            {
                /* i.e. we have already seen SecurityModeResponse! */
                current_security->seen_next_ul_pdu = TRUE;
            }

        }
        else {
            /* Just show as unparsed data */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, payload_tvb, offset,
                                tvb_reported_length_remaining(tvb, offset) - 4, ENC_NA);
        }

        data_length = tvb_reported_length_remaining(payload_tvb, offset) - 4;
        offset += data_length;

        /* Last 4 bytes are MAC */
        mac = tvb_get_ntohl(payload_tvb, offset);
        mac_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_mac, payload_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (digest_was_calculated) {
            /* Compare what was found with calculated value! */
            if (mac != calculated_digest) {
                expert_add_info_format(pinfo, mac_ti, &ei_pdcp_lte_digest_wrong,
                                       "MAC-I Digest wrong expected %08x but found %08x",
                                       calculated_digest, mac);
            }
            else {
                proto_item_append_text(mac_ti, " [Matches calculated result]");
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " MAC=0x%08x (%u bytes data)",
                        mac, data_length);
    }
    else {
        /* User-plane payload here */

        /* If not compressed with ROHC, show as user-plane data */
        if (!p_pdcp_info->rohc.rohc_compression) {
            gint payload_length = tvb_reported_length_remaining(payload_tvb, offset);
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
                            col_set_writable(pinfo->cinfo, FALSE);
                        }

                        switch (tvb_get_guint8(ip_payload_tvb, 0) & 0xf0) {
                            case 0x40:
                                call_dissector_only(ip_handle, ip_payload_tvb, pinfo, pdcp_tree, NULL);
                                break;
                            case 0x60:
                                call_dissector_only(ipv6_handle, ip_payload_tvb, pinfo, pdcp_tree, NULL);
                                break;
                            default:
                                call_dissector_only(data_handle, ip_payload_tvb, pinfo, pdcp_tree, NULL);
                                break;
                        }

                        /* Freeze the columns again because we don't want other layers writing to info */
                        if (global_pdcp_lte_layer_to_show == ShowTrafficLayer) {
                            col_set_writable(pinfo->cinfo, FALSE);
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
            col_set_writable(pinfo->cinfo, global_pdcp_lte_layer_to_show == ShowRLCLayer);

            /* DROPPING OUT HERE IF NOT DOING ROHC! */
            return;
        }
        else {
            /***************************/
            /* ROHC packets            */
            /***************************/

            /* Only attempt ROHC if configured to */
            if (!global_pdcp_dissect_rohc) {
                col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
                                val_to_str_const(p_pdcp_info->rohc.profile, rohc_profile_vals, "Unknown"));
                return;
            }

            rohc_tvb = tvb_new_subset_remaining(payload_tvb, offset);

            /* Only enable writing to column if configured to show ROHC */
            if (global_pdcp_lte_layer_to_show != ShowTrafficLayer) {
                col_set_writable(pinfo->cinfo, FALSE);
            }
            else {
                col_clear(pinfo->cinfo, COL_INFO);
            }

            /* Call the ROHC dissector */
            call_dissector_with_data(rohc_handle, rohc_tvb, pinfo, tree, &p_pdcp_info->rohc);

            /* Let RLC write to columns again */
            col_set_writable(pinfo->cinfo, global_pdcp_lte_layer_to_show == ShowRLCLayer);
        }
    }
}

/* Initializes the hash tables each time a new
 * file is loaded or re-loaded in wireshark */
static void pdcp_lte_init_protocol(void)
{
    /* Destroy any existing hashes. */
    if (pdcp_sequence_analysis_channel_hash) {
        g_hash_table_destroy(pdcp_sequence_analysis_channel_hash);
    }
    if (pdcp_lte_sequence_analysis_report_hash) {
        g_hash_table_destroy(pdcp_lte_sequence_analysis_report_hash);
    }
    if (pdcp_security_hash) {
        g_hash_table_destroy(pdcp_security_hash);
    }
    if (pdcp_security_result_hash) {
        g_hash_table_destroy(pdcp_security_result_hash);
    }
    if (pdcp_security_key_hash) {
        g_hash_table_destroy(pdcp_security_key_hash);
    }


    /* Now create them over */
    pdcp_sequence_analysis_channel_hash = g_hash_table_new(pdcp_channel_hash_func, pdcp_channel_equal);
    pdcp_lte_sequence_analysis_report_hash = g_hash_table_new(pdcp_result_hash_func, pdcp_result_hash_equal);
    pdcp_security_hash = g_hash_table_new(pdcp_lte_ueid_hash_func, pdcp_lte_ueid_hash_equal);
    pdcp_security_result_hash = g_hash_table_new(pdcp_lte_ueid_frame_hash_func, pdcp_lte_ueid_frame_hash_equal);
    pdcp_security_key_hash = g_hash_table_new(pdcp_lte_ueid_hash_func, pdcp_lte_ueid_hash_equal);
}



void proto_register_pdcp(void)
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
              "pdcp-lte.rohc.profile", FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
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
        { &hf_pdcp_lte_signalling_data,
            { "Signalling Data",
              "pdcp-lte.signalling-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_mac,
            { "MAC",
              "pdcp-lte.mac", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_data_control,
            { "PDU Type",
              "pdcp-lte.pdu-type", FT_UINT8, BASE_HEX, VALS(pdu_type_vals), 0x80,
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
              "pdcp-lte.fms", FT_UINT16, BASE_DEC, NULL, 0x07fff,
              "First Missing PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap,
            { "Bitmap",
              "pdcp-lte.bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Status report bitmap (0=error, 1=OK)", HFILL
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
              "pdcp-lte.sequence-analysis.expected-sn", FT_UINT16, BASE_DEC, 0, 0x0,
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

        { &hf_pdcp_lte_security,
            { "Security Config",
              "pdcp-lte.security-cofig", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_security_setup_frame,
            { "Configuration frame",
              "pdcp-lte.security-config.setup-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
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
    };

    static gint *ett[] =
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
        { &ei_pdcp_lte_digest_wrong, { "pdcp-lte.maci-wrong", PI_SEQUENCE, PI_ERROR, "MAC-I doesn't match expected value", EXPFILL }}
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

  static uat_field_t ue_keys_uat_flds[] = {
      UAT_FLD_DEC(uat_ue_keys_records, ueid, "UEId", "UE Identifier of UE associated with keys"),
      UAT_FLD_CSTRING(uat_ue_keys_records, rrcCipherKeyString, "RRC Cipher Key",        "Key for deciphering signalling messages"),
      UAT_FLD_CSTRING(uat_ue_keys_records, upCipherKeyString,  "User-Plane Cipher Key", "Key for deciphering user-plane messages"),
      UAT_FLD_CSTRING(uat_ue_keys_records, rrcIntegrityKeyString,  "RRC Integrity Key", "Key for deciphering user-plane messages"),
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
        &global_pdcp_check_sequence_numbers, sequence_analysis_vals, FALSE);

    /* Attempt to dissect ROHC messages */
    prefs_register_bool_preference(pdcp_lte_module, "dissect_rohc",
        "Attempt to decode ROHC data",
        "Attempt to decode ROHC data",
        &global_pdcp_dissect_rohc);

    prefs_register_bool_preference(pdcp_lte_module, "heuristic_pdcp_lte_over_udp",
        "Try Heuristic LTE-PDCP over UDP framing",
        "When enabled, use heuristic dissector to find PDCP-LTE frames sent with "
        "UDP framing",
        &global_pdcp_lte_heur);

    prefs_register_enum_preference(pdcp_lte_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show RLC, PDCP or Traffic layer info in Info column",
        &global_pdcp_lte_layer_to_show, show_info_col_vals, FALSE);

    ue_keys_uat = uat_new("PDCP UE security keys",
              sizeof(uat_ue_keys_record_t),    /* record size */
              "pdcp_lte_ue_keys",              /* filename */
              TRUE,                            /* from_profile */
              &uat_ue_keys_records,            /* data_ptr */
              &num_ue_keys_uat,                /* numitems_ptr */
              UAT_AFFECTS_DISSECTION,          /* affects dissection of packets, but not set of named fields */
              NULL,                            /* help */
              uat_ue_keys_record_copy_cb,      /* copy callback */
              uat_ue_keys_record_update_cb,    /* update callback */
              uat_ue_keys_record_free_cb,      /* free callback */
              NULL,                            /* post update callback */
              ue_keys_uat_flds);               /* UAT field definitions */

    prefs_register_uat_preference(pdcp_lte_module,
                                  "ue_keys_table",
                                  "PDCP UE Keys",
                                  "Preconfigured PDCP keys",
                                  ue_keys_uat);

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

    register_init_routine(&pdcp_lte_init_protocol);
}

void proto_reg_handoff_pdcp_lte(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_pdcp_lte_heur, proto_pdcp_lte);

    ip_handle   = find_dissector("ip");
    ipv6_handle = find_dissector("ipv6");
    rohc_handle = find_dissector("rohc");
    data_handle = find_dissector("data");
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
