/* packet-ieee802154.c
 *
 * Multipurpose frame support
 * By Devan Lai <devanl@davisinstruments.com>
 * Copyright 2019 Davis Instruments
 *
 * IEEE 802.15.4-2015 CCM* nonce for TSCH mode
 * By Maxime Brunelle <Maxime.Brunelle@trilliant.com>
 * Copyright 2019 Trilliant Inc.
 *
 * IEEE802154 TAP link type
 * By James Ko <jck@exegin.com>
 * Copyright 2019 Exegin Technologies Limited
 *
 * 4-byte FCS support and ACK tracking
 * By Carl Levesque Imbeault <carl.levesque@trilliant.com>
 * Copyright 2018 Trilliant Inc.
 * Integrated and added FCS type enum
 * by James Ko <jck@exegin.com>
 * Copyright 2019 Exegin Technologies Limited
 *
 * Auxiliary Security Header support and
 * option to force TI CC24xx FCS format
 * By Jean-Francois Wauthy <jfw@info.fundp.ac.be>
 * Copyright 2009 The University of Namur, Belgium
 *
 * IEEE 802.15.4 Dissectors for Wireshark
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2007 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *------------------------------------------------------------
 *
 *  In IEEE 802.15.4 packets, all fields are little endian. And
 *  Each byte is transmitted least significant bit first (reflected
 *  bit ordering).
 *------------------------------------------------------------
 *
 *  Most IEEE 802.15.4 Packets have the following format:
 *  |  FCF  |Seq No|  Addressing |         Data          |   FCS   |
 *  |2 bytes|1 byte|0 to 20 bytes|Length-(Overhead) bytes|2/4 Bytes|
 *------------------------------------------------------------
 *
 *  Multipurpose frame packets have the following format:
 *  |   FCF   | Seq No  |  Addressing |         Data          |  FCS  |
 *  |1/2 bytes|0/1 bytes|0 to 20 bytes|Length-(Overhead) bytes|2 bytes|
 *------------------------------------------------------------
 *
 *  CRC16 is calculated using the x^16 + x^12 + x^5 + 1 polynomial
 *  as specified by ITU-T, and is calculated over the IEEE 802.15.4
 *  packet (excluding the FCS) as transmitted over the air. Note,
 *  that because the least significan bits are transmitted first, this
 *  will require reversing the bit-order in each byte. Also, unlike
 *  most CRC algorithms, IEEE 802.15.4 uses an initial and final value
 *  of 0x0000, instead of 0xffff (which is used by the ITU-T).
 *
 *  For a 4-byte FCS, CRC32 is calculated using the ITU-T CRC32.
 *
 *  (Fun fact: the reference to "a 32-bit CRC equivalent to ANSI X3.66-1979"
 *  in IEEE Std 802.15.4-2015 nonwithstanding, ANSI X3.66-1979 does not
 *  describe any 32-bit CRC, only a 16-bit CRC from ITU-T V.41.  ITU-T
 *  V.42 describes both a 16-bit and 32-bit CRC; all the 16-bit CRCs
 *  floating around seem to use the same generator polynomial,
 *  x^16 + x^12 + x^5 + 1, but have different initial conditions and
 *  no-error final remainder; the 32-bit CRC from V.42 and the one
 *  described in IEEE Std 802.15.4-2015 also use the same generator
 *  polynomial.)
 *------------------------------------------------------------
 *
 *  This dissector supports both link-layer IEEE 802.15.4 captures
 *  and IEEE 802.15.4 packets encapsulated within other layers.
 *  Additionally, support has been provided for 16-bit and 32-bit
 *  FCS, as well as for frames with no FCS but with a 16-bit
 *  ChipCon/Texas Instruments CC24xx-style metadata field.
 *------------------------------------------------------------
 */

/*  Include files */
#include "config.h"
#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/exceptions.h>
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/address_types.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>
#include <epan/etypes.h>
#include <epan/oui.h>
#include <epan/tap.h>
#include <wsutil/pint.h>

/* Use libgcrypt for cipher libraries. */
#include <wsutil/wsgcrypt.h>

#include "packet-ieee802154.h"
#include "packet-sll.h"

void proto_register_ieee802154(void);
void proto_reg_handoff_ieee802154(void);

/* Dissection Options for dissect_ieee802154_common */
#define DISSECT_IEEE802154_OPTION_CC24xx    0x00000001 /* Frame has TI CC24xx metadata, not an FCS, at the end */
#define DISSECT_IEEE802154_OPTION_ZBOSS     0x00000002 /* ZBOSS traffic dump */

/* ethertype for 802.15.4 tag - encapsulating an Ethernet packet */
static unsigned int ieee802154_ethertype = 0x809A;

/* FCS Types used by user configuration */
#define IEEE802154_CC24XX_METADATA 0 /* Not an FCS, but TI CC24xx metadata */
#define IEEE802154_FCS_16_BIT      1 /* ITU-T CRC16 */
#define IEEE802154_FCS_32_BIT      2 /* ITU-T CRC32 */

static gint ieee802154_fcs_type = IEEE802154_FCS_16_BIT;

/* 802.15.4 TAP Fields */
typedef enum {
    IEEE802154_TAP_FCS_TYPE             = 0x0000,
    IEEE802154_TAP_RSS                  = 0x0001,
    IEEE802154_TAP_BIT_RATE             = 0x0002,
    IEEE802154_TAP_CHANNEL_ASSIGNMENT   = 0x0003,
    IEEE802154_TAP_SUN_PHY_INFO         = 0x0004,
    IEEE802154_TAP_START_OF_FRAME_TS    = 0x0005,
    IEEE802154_TAP_END_OF_FRAME_TS      = 0x0006,
    IEEE802154_TAP_ASN                  = 0x0007,
    IEEE802154_TAP_SLOT_START_TS        = 0x0008,
    IEEE802154_TAP_TIMESLOT_LENGTH      = 0x0009,
    IEEE802154_TAP_LQI                  = 0x000A,
    IEEE802154_TAP_CHANNEL_FREQUENCY    = 0x000B,
    IEEE802154_TAP_CHANNEL_PLAN         = 0x000C,
} ieee802154_info_type_t;

typedef enum {
    IEEE802154_FCS_TYPE_NONE        = 0,
    IEEE802154_FCS_TYPE_16_BIT      = 1, /* ITU-T CRC16 */
    IEEE802154_FCS_TYPE_32_BIT      = 2, /* ITU-T CRC32 */
} ieee802154_fcs_type_t;

typedef enum {
    IEEE802154_SUN_TYPE_FSK_A       = 0x00,
    IEEE802154_SUN_TYPE_FSK_B       = 0x01,
    IEEE802154_SUN_TYPE_OQPSK_A     = 0x02,
    IEEE802154_SUN_TYPE_OQPSK_B     = 0x03,
    IEEE802154_SUN_TYPE_OQPSK_C     = 0x04,
    IEEE802154_SUN_TYPE_OFDM_OPT1   = 0x05,
    IEEE802154_SUN_TYPE_OFDM_OPT2   = 0x06,
    IEEE802154_SUN_TYPE_OFDM_OPT3   = 0x07,
    IEEE802154_SUN_TYPE_OFDM_OPT4   = 0x08,
} ieee802154_sun_type_t;

/* boolean value set if the FCS must be ok before payload is dissected */
static gboolean ieee802154_fcs_ok = TRUE;

/* boolean value set to enable ack tracking */
static gboolean ieee802154_ack_tracking = FALSE;

/* boolean value set to enable 802.15.4e dissection compatibility */
static gboolean ieee802154e_compatibility = FALSE;

/* TSCH ASN for nonce in decryption */
static guint64 ieee802154_tsch_asn = 0;

static const char  *ieee802154_user    = "User";

static wmem_tree_t* mac_key_hash_handlers;

#ifndef ROUND_UP
#define ROUND_UP(_offset_, _align_) (((_offset_) + (_align_) - 1) / (_align_) * (_align_))
#endif

/*
 * Address Hash Tables
 *
 */
ieee802154_map_tab_t ieee802154_map = { NULL, NULL };

/*
 * Static Address Mapping UAT
 *
 */
/* UAT entry structure. */
typedef struct {
    guchar *eui64;
    guint   eui64_len;
    guint   addr16;
    guint   pan;
} static_addr_t;

/* UAT variables */
static uat_t         *static_addr_uat  = NULL;
static static_addr_t *static_addrs     = NULL;
static guint          num_static_addrs = 0;

static void*
addr_uat_copy_cb(void *dest, const void *source, size_t len _U_)
{
    const static_addr_t* o = (const static_addr_t*)source;
    static_addr_t* d = (static_addr_t*)dest;

    d->eui64 = (guchar *)g_memdup2(o->eui64, o->eui64_len);
    d->eui64_len = o->eui64_len;
    d->addr16 = o->addr16;
    d->pan = o->pan;

    return dest;
}

/* Sanity-checks a UAT record. */
static gboolean
addr_uat_update_cb(void *r, char **err)
{
    static_addr_t *map = (static_addr_t *)r;
    /* Ensure a valid short address */
    if (map->addr16 >= IEEE802154_NO_ADDR16) {
        *err = g_strdup("Invalid short address");
        return FALSE;
    }
    /* Ensure a valid PAN identifier. */
    if (map->pan >= IEEE802154_BCAST_PAN) {
        *err = g_strdup("Invalid PAN identifier");
        return FALSE;
    }
    /* Ensure a valid EUI-64 length */
    if (map->eui64_len != sizeof(guint64)) {
        *err = g_strdup("Invalid EUI-64 length");
        return FALSE;
    }
    return TRUE;
} /* ieee802154_addr_uat_update_cb */

static void
addr_uat_free_cb(void *r)
{
    static_addr_t *rec = (static_addr_t *)r;
    g_free(rec->eui64);
}

/* Field callbacks. */
UAT_HEX_CB_DEF(addr_uat, addr16, static_addr_t)
UAT_HEX_CB_DEF(addr_uat, pan, static_addr_t)
UAT_BUFFER_CB_DEF(addr_uat, eui64, static_addr_t, eui64, eui64_len)

/*
 * Decryption Keys UAT
 */

/* UAT variables */
static uat_t            *ieee802154_key_uat = NULL;
static ieee802154_key_t *ieee802154_keys = NULL;
static guint             num_ieee802154_keys = 0;

static void ieee802154_key_post_update_cb(void)
{
    guint i;
    GByteArray *bytes;

    for (i = 0; i < num_ieee802154_keys; i++)
    {
        switch (ieee802154_keys[i].hash_type) {
        case KEY_HASH_NONE:
        case KEY_HASH_ZIP:
            /* Get the IEEE 802.15.4 decryption key. */
            bytes = g_byte_array_new();
            if (hex_str_to_bytes(ieee802154_keys[i].pref_key, bytes, FALSE))
            {
                if (ieee802154_keys[i].hash_type == KEY_HASH_ZIP) {
                    char digest[32];

                    if (!ws_hmac_buffer(GCRY_MD_SHA256, digest, "ZigBeeIP", 8, bytes->data, IEEE802154_CIPHER_SIZE)) {
                        /* Copy upper hashed bytes to the key */
                        memcpy(ieee802154_keys[i].key, &digest[IEEE802154_CIPHER_SIZE], IEEE802154_CIPHER_SIZE);
                        /* Copy lower hashed bytes to the MLE key */
                        memcpy(ieee802154_keys[i].mle_key, digest, IEEE802154_CIPHER_SIZE);
                    } else {
                        /* Just copy the keys verbatim */
                        memcpy(ieee802154_keys[i].key, bytes->data, IEEE802154_CIPHER_SIZE);
                        memcpy(ieee802154_keys[i].mle_key, bytes->data, IEEE802154_CIPHER_SIZE);
                    }
                } else {
                    /* Just copy the keys verbatim */
                    memcpy(ieee802154_keys[i].key, bytes->data, IEEE802154_CIPHER_SIZE);
                    memcpy(ieee802154_keys[i].mle_key, bytes->data, IEEE802154_CIPHER_SIZE);
                }
            }
            g_byte_array_free(bytes, TRUE);
            break;
        case KEY_HASH_THREAD:
            /* XXX - TODO? */
            break;
        }
    }
}

static gboolean ieee802154_key_update_cb(void *r, char **err)
{
    ieee802154_key_t* rec = (ieee802154_key_t*)r;
    GByteArray *bytes;

    switch (rec->hash_type) {
    case KEY_HASH_NONE:
    case KEY_HASH_ZIP:
        bytes = g_byte_array_new();
        if (hex_str_to_bytes(rec->pref_key, bytes, FALSE) == FALSE)
        {
            *err = g_strdup("Invalid key");
            g_byte_array_free(bytes, TRUE);
            return FALSE;
        }

        if (bytes->len < IEEE802154_CIPHER_SIZE)
        {
            *err = ws_strdup_printf("Key must be at least %d bytes", IEEE802154_CIPHER_SIZE);
            g_byte_array_free(bytes, TRUE);
            return FALSE;
        }
        g_byte_array_free(bytes, TRUE);
        break;
    case KEY_HASH_THREAD:
        /* XXX - TODO? */
        break;
    }

    return TRUE;
}

static void* ieee802154_key_copy_cb(void* n, const void* o, size_t siz _U_) {
    ieee802154_key_t* new_record = (ieee802154_key_t*)n;
    const ieee802154_key_t* old_record = (const ieee802154_key_t*)o;

    new_record->pref_key = g_strdup(old_record->pref_key);
    new_record->key_index = old_record->key_index;
    new_record->hash_type = old_record->hash_type;

    return new_record;
}

static void ieee802154_key_free_cb(void*r) {
    ieee802154_key_t* rec = (ieee802154_key_t *)r;

    g_free(rec->pref_key);
}

/* Field callbacks. */
UAT_CSTRING_CB_DEF(key_uat, pref_key, ieee802154_key_t)
UAT_DEC_CB_DEF(key_uat, key_index, ieee802154_key_t)
UAT_VS_DEF(key_uat, hash_type, ieee802154_key_t, ieee802154_key_hash, KEY_HASH_NONE, "No hash")


/*-------------------------------------
 * Dissector Function Prototypes
 *-------------------------------------
 */

/* Dissection Routines. */
static int dissect_ieee802154_nonask_phy   (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_ieee802154              (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_ieee802154_nofcs        (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_ieee802154_cc24xx       (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_ieee802154_tap          (tvbuff_t *, packet_info *, proto_tree *, void *);
static tvbuff_t *dissect_zboss_specific    (tvbuff_t *, packet_info *, proto_tree *);
static void dissect_ieee802154_common      (tvbuff_t *, packet_info *, proto_tree *, guint, guint);
static void ieee802154_dissect_fcs(tvbuff_t *tvb, proto_tree *ieee802154_tree, guint fcs_len, gboolean fcs_ok);
static void ieee802154_dissect_cc24xx_metadata(tvbuff_t *tvb, proto_tree *ieee802154_tree, gboolean fcs_ok);
static ieee802154_fcs_type_t dissect_ieee802154_tap_tlvs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Information Elements */
static int dissect_ieee802154_header_ie        (tvbuff_t *, packet_info *, proto_tree *, guint, ieee802154_packet *);
static int dissect_ieee802154_payload_ie       (tvbuff_t *, packet_info *, proto_tree *, guint, ieee802154_packet *);
static int dissect_802154_eb_filter            (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_802154_tsch_time_sync       (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_802154_tsch_timeslot        (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_802154_tsch_slotframe_link  (tvbuff_t *, packet_info *, proto_tree *, void *);
static int dissect_802154_channel_hopping      (tvbuff_t *, packet_info *, proto_tree *, void *);
/* Sub-dissector helpers. */
static void dissect_ieee802154_fcf             (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *, guint *);
static void dissect_ieee802154_command         (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);
static void dissect_ieee802154_assoc_req       (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);
static void dissect_ieee802154_assoc_rsp       (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);
static void dissect_ieee802154_disassoc        (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);
static void dissect_ieee802154_realign         (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);
static void dissect_ieee802154_gtsreq          (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);

/* Decryption helpers. */
static tvbuff_t *dissect_ieee802154_decrypt(tvbuff_t *, guint, packet_info *, ieee802154_packet *, ieee802154_decrypt_info_t*);

static guint ieee802154_set_mac_key(ieee802154_packet *packet, unsigned char *key, unsigned char *alt_key, ieee802154_key_t *uat_key);
static void tsch_ccm_init_nonce(guint64 addr, guint64 asn, gchar* generic_nonce);

/* Initialize Protocol and Registered fields */
static int proto_ieee802154_nonask_phy = -1;
static int hf_ieee802154_nonask_phy_preamble = -1;
static int hf_ieee802154_nonask_phy_sfd = -1;
static int hf_ieee802154_nonask_phy_length = -1;
static int hf_ieee802154_nonask_phr = -1;

static int proto_ieee802154 = -1;
static int proto_ieee802154_tap = -1;
static int hf_ieee802154_frame_length = -1;
static int hf_ieee802154_fcf = -1;
static int hf_ieee802154_frame_type = -1;
static int hf_ieee802154_security = -1;
static int hf_ieee802154_pending = -1;
static int hf_ieee802154_ack_request = -1;
static int hf_ieee802154_pan_id_compression = -1;
static int hf_ieee802154_fcf_reserved = -1;
static int hf_ieee802154_seqno_suppression = -1;
static int hf_ieee802154_ie_present = -1;
static int hf_ieee802154_src_addr_mode = -1;
static int hf_ieee802154_version = -1;
static int hf_ieee802154_dst_addr_mode = -1;

static int hf_ieee802154_mpf_long_frame_control = -1;
static int hf_ieee802154_mpf_dst_addr_mode = -1;
static int hf_ieee802154_mpf_src_addr_mode = -1;
static int hf_ieee802154_mpf_pan_id_present = -1;
static int hf_ieee802154_mpf_security = -1;
static int hf_ieee802154_mpf_seqno_suppression = -1;
static int hf_ieee802154_mpf_pending = -1;
static int hf_ieee802154_mpf_version = -1;
static int hf_ieee802154_mpf_ack_request = -1;
static int hf_ieee802154_mpf_ie_present = -1;

static int hf_ieee802154_header_ies = -1;
static int hf_ieee802154_header_ie_tlv = -1;
static int hf_ieee802154_header_ie_type = -1;
static int hf_ieee802154_header_ie_id = -1;
static int hf_ieee802154_header_ie_length = -1;
static int hf_ieee802154_ie_unknown_content = -1;
static int hf_ieee802154_hie_unsupported = -1;
static int hf_ieee802154_hie_time_correction = -1;
static int hf_ieee802154_hie_ht1 = -1;
static int hf_ieee802154_hie_ht2 = -1;
static int hf_ieee802154_nack = -1;
static int hf_ieee802154_hie_time_correction_time_sync_info = -1;
static int hf_ieee802154_hie_time_correction_value = -1;
static int hf_ieee802154_hie_csl = -1;
static int hf_ieee802154_hie_csl_phase = -1;
static int hf_ieee802154_hie_csl_period = -1;
static int hf_ieee802154_hie_csl_rendezvous_time = -1;
static int hf_ieee802154_hie_rdv = -1;
static int hf_ieee802154_hie_rdv_wakeup_interval = -1;
static int hf_ieee802154_hie_global_time = -1;
static int hf_ieee802154_hie_global_time_value = -1;
static int hf_ieee802154_hie_vendor_specific = -1;
static int hf_ieee802154_hie_vendor_specific_vendor_oui = -1;
static int hf_ieee802154_hie_vendor_specific_content = -1;
static int hf_ieee802154_payload_ies = -1;
static int hf_ieee802154_payload_ie_tlv = -1;
static int hf_ieee802154_payload_ie_type = -1;
static int hf_ieee802154_payload_ie_id = -1;
static int hf_ieee802154_payload_ie_length = -1;
static int hf_ieee802154_pie_unsupported = -1;
static int hf_ieee802154_pie_termination = -1;
static int hf_ieee802154_pie_vendor = -1;
static int hf_ieee802154_pie_vendor_oui = -1;
static int hf_ieee802154_pie_ietf = -1;
static int hf_ieee802154_mlme = -1;
static int hf_ieee802154_mlme_ie_data = -1;
static int hf_ieee802154_mlme_ie_unsupported = -1;
static int hf_ieee802154_psie = -1;
static int hf_ieee802154_psie_type = -1;
static int hf_ieee802154_psie_id_short = -1;
static int hf_ieee802154_psie_length_short = -1;
static int hf_ieee802154_psie_id_long = -1;
static int hf_ieee802154_psie_length_long = -1;

static int hf_ieee802154_tsch_sync = -1;
static int hf_ieee802154_tsch_asn = -1;
static int hf_ieee802154_tsch_join_metric = -1;
static int hf_ieee802154_tsch_slotframe = -1;
static int hf_ieee802154_tsch_link_info = -1;
static int hf_ieee802154_tsch_slotf_link_nb_slotf = -1;
static int hf_ieee802154_tsch_slotf_link_slotf_handle= -1;
static int hf_ieee802154_tsch_slotf_size = -1;
static int hf_ieee802154_tsch_slotf_link_nb_links = -1;
static int hf_ieee802154_tsch_slotf_link_timeslot = -1;
static int hf_ieee802154_tsch_slotf_link_channel_offset = -1;
static int hf_ieee802154_tsch_slotf_link_options = -1;
static int hf_ieee802154_tsch_slotf_link_options_tx = -1;
static int hf_ieee802154_tsch_slotf_link_options_rx = -1;
static int hf_ieee802154_tsch_slotf_link_options_shared = -1;
static int hf_ieee802154_tsch_slotf_link_options_timkeeping = -1;
static int hf_ieee802154_tsch_slotf_link_options_priority = -1;
static int hf_ieee802154_tsch_channel_hopping = -1;
static int hf_ieee802154_tsch_hopping_sequence_id = -1;
static int hf_ieee802154_tsch_timeslot = -1;
static int hf_ieee802154_tsch_timeslot_id = -1;
static int hf_ieee802154_tsch_timeslot_cca_offset = -1;
static int hf_ieee802154_tsch_timeslot_cca = -1;
static int hf_ieee802154_tsch_timeslot_tx_offset = -1;
static int hf_ieee802154_tsch_timeslot_rx_offset = -1;
static int hf_ieee802154_tsch_timeslot_rx_ack_delay = -1;
static int hf_ieee802154_tsch_timeslot_tx_ack_delay = -1;
static int hf_ieee802154_tsch_timeslot_rx_wait = -1;
static int hf_ieee802154_tsch_timeslot_ack_wait = -1;
static int hf_ieee802154_tsch_timeslot_turnaround = -1;
static int hf_ieee802154_tsch_timeslot_max_ack = -1;
static int hf_ieee802154_tsch_timeslot_max_tx = -1;
static int hf_ieee802154_tsch_timeslot_length = -1;

static int hf_ieee802154_psie_eb_filter = -1;
static int hf_ieee802154_psie_eb_filter_pjoin = -1;
static int hf_ieee802154_psie_eb_filter_lqi = -1;
static int hf_ieee802154_psie_eb_filter_lqi_min = -1;
static int hf_ieee802154_psie_eb_filter_percent = -1;
static int hf_ieee802154_psie_eb_filter_percent_prob = -1;
static int hf_ieee802154_psie_eb_filter_attr_id = -1;
static int hf_ieee802154_psie_eb_filter_attr_id_bitmap = -1;
static int hf_ieee802154_p_ie_ietf_sub_id = -1;

static int hf_ieee802154_6top = -1;
static int hf_ieee802154_6top_version = -1;
static int hf_ieee802154_6top_type = -1;
static int hf_ieee802154_6top_flags_reserved = -1;
static int hf_ieee802154_6top_code = -1;
static int hf_ieee802154_6top_sfid = -1;
static int hf_ieee802154_6top_seqnum = -1;
static int hf_ieee802154_6top_metadata = -1;
static int hf_ieee802154_6top_cell_options = -1;
static int hf_ieee802154_6top_cell_option_tx = -1;
static int hf_ieee802154_6top_cell_option_rx = -1;
static int hf_ieee802154_6top_cell_option_shared = -1;
static int hf_ieee802154_6top_cell_option_reserved = -1;
static int hf_ieee802154_6top_num_cells = -1;
static int hf_ieee802154_6top_cell_list = -1;
static int hf_ieee802154_6top_rel_cell_list = -1;
static int hf_ieee802154_6top_cand_cell_list = -1;
static int hf_ieee802154_6top_cell = -1;
static int hf_ieee802154_6top_reserved = -1;
static int hf_ieee802154_6top_offset = -1;
static int hf_ieee802154_6top_max_num_cells = -1;
static int hf_ieee802154_6top_slot_offset = -1;
static int hf_ieee802154_6top_channel_offset = -1;
static int hf_ieee802154_6top_total_num_cells = -1;
static int hf_ieee802154_6top_payload = -1;

static int hf_ieee802159_mpx = -1;
static int hf_ieee802159_mpx_transaction_control = -1;
static int hf_ieee802159_mpx_transfer_type = -1;
static int hf_ieee802159_mpx_transaction_id = -1;
static int hf_ieee802159_mpx_transaction_id_as_multiplex_id = -1;
static int hf_ieee802159_mpx_fragment_number = -1;
static int hf_ieee802159_mpx_total_frame_size = -1;
static int hf_ieee802159_mpx_multiplex_id = -1;
static int hf_ieee802159_mpx_kmp_id = -1;
static int hf_ieee802159_mpx_kmp_vendor_oui = -1;
static int hf_ieee802159_mpx_fragment = -1;
static int hf_ieee802159_mpx_wisun_subid = -1;

static int proto_zboss = -1;
static int hf_zboss_direction = -1;
static int hf_zboss_page = -1;
static int hf_zboss_channel = -1;
static int hf_zboss_trace_number = -1;

static int hf_ieee802154_seqno = -1;
static int hf_ieee802154_dst_panID = -1;
static int hf_ieee802154_dst16 = -1;
static int hf_ieee802154_dst64 = -1;
static int hf_ieee802154_src_panID = -1;
static int hf_ieee802154_src16 = -1;
static int hf_ieee802154_src64 = -1;
static int hf_ieee802154_src64_origin = -1;
static int hf_ieee802154_addr16 = -1;
static int hf_ieee802154_addr64 = -1;
static int hf_ieee802154_fcs = -1;
static int hf_ieee802154_fcs32 = -1;
static int hf_ieee802154_rssi = -1;
static int hf_ieee802154_fcs_ok = -1;
static int hf_ieee802154_correlation = -1;

/* Registered fields for Command Packets */
static int hf_ieee802154_cmd_id = -1;
static int hf_ieee802154_cinfo_alt_coord = -1;
static int hf_ieee802154_cinfo_device_type = -1;
static int hf_ieee802154_cinfo_power_src = -1;
static int hf_ieee802154_cinfo_idle_rx = -1;
static int hf_ieee802154_cinfo_sec_capable = -1;
static int hf_ieee802154_cinfo_alloc_addr = -1;
static int hf_ieee802154_assoc_addr = -1;
static int hf_ieee802154_assoc_status = -1;
static int hf_ieee802154_disassoc_reason = -1;
static int hf_ieee802154_realign_pan = -1;
static int hf_ieee802154_realign_caddr = -1;
static int hf_ieee802154_realign_channel = -1;
static int hf_ieee802154_realign_addr = -1;
static int hf_ieee802154_realign_channel_page = -1;
static int hf_ieee802154_gtsreq_len = -1;
static int hf_ieee802154_gtsreq_dir = -1;
static int hf_ieee802154_gtsreq_type = -1;
static int hf_ieee802154_cmd_vendor_oui = -1;

/* Registered fields for Beacon Packets */
static int hf_ieee802154_beacon_order = -1;
static int hf_ieee802154_superframe_order = -1;
static int hf_ieee802154_cap = -1;
static int hf_ieee802154_superframe_battery_ext = -1;
static int hf_ieee802154_superframe_coord = -1;
static int hf_ieee802154_assoc_permit = -1;
static int hf_ieee802154_gts_count = -1;
static int hf_ieee802154_gts_permit = -1;
static int hf_ieee802154_gts_direction = -1;
static int hf_ieee802154_gts_address = -1;
static int hf_ieee802154_pending16 = -1;
static int hf_ieee802154_pending64 = -1;

/* Registered fields for Auxiliary Security Header */
static int hf_ieee802154_aux_security_header = -1;
static int hf_ieee802154_aux_sec_security_control = -1;
static int hf_ieee802154_aux_sec_security_level = -1;
static int hf_ieee802154_aux_sec_key_id_mode = -1;
static int hf_ieee802154_aux_sec_frame_counter_suppression = -1;
static int hf_ieee802154_aux_sec_asn_in_nonce = -1;
static int hf_ieee802154_aux_sec_reserved = -1;
static int hf_ieee802154_aux_sec_frame_counter = -1;
static int hf_ieee802154_aux_sec_key_source = -1;
static int hf_ieee802154_aux_sec_key_source_bytes = -1;
static int hf_ieee802154_aux_sec_key_index = -1;
static int hf_ieee802154_mic = -1;
static int hf_ieee802154_key_number = -1;

/* 802.15.4-2003 security */
static int hf_ieee802154_sec_frame_counter = -1;
static int hf_ieee802154_sec_key_sequence_counter = -1;

/* 802.15.4 ack */
static int hf_ieee802154_no_ack = -1;
static int hf_ieee802154_no_ack_request = -1;
static int hf_ieee802154_ack_in = -1;
static int hf_ieee802154_ack_to = -1;
static int hf_ieee802154_ack_time = -1;

/* 802.15.4 TAP */
static int hf_ieee802154_tap_version = -1;
static int hf_ieee802154_tap_reserved = -1;
static int hf_ieee802154_tap_length = -1;
static int hf_ieee802154_tap_data_length = -1;
static int hf_ieee802154_tap_tlv_type = -1;
static int hf_ieee802154_tap_tlv_length = -1;
static int hf_ieee802154_tap_tlv_unknown = -1;
static int hf_ieee802154_tap_tlv_padding = -1;
static int hf_ieee802154_tap_fcs_type = -1;
static int hf_ieee802154_tap_rss = -1;
static int hf_ieee802154_ch_page = -1;
static int hf_ieee802154_ch_num = -1;
static int hf_ieee802154_bit_rate = -1;
static int hf_ieee802154_sun_band = -1;
static int hf_ieee802154_sun_type = -1;
static int hf_ieee802154_sun_mode = -1;
static int hf_ieee802154_mode_fsk_a = -1;
static int hf_ieee802154_mode_fsk_b = -1;
static int hf_ieee802154_mode_oqpsk_a = -1;
static int hf_ieee802154_mode_oqpsk_b = -1;
static int hf_ieee802154_mode_oqpsk_c = -1;
static int hf_ieee802154_mode_ofdm = -1;
static int hf_ieee802154_sof_ts = -1;
static int hf_ieee802154_eof_ts = -1;
static int hf_ieee802154_slot_start_ts = -1;
static int hf_ieee802154_tap_timeslot_length = -1;
static int hf_ieee802154_tap_lqi = -1;
static int hf_ieee802154_chplan_start = -1;
static int hf_ieee802154_chplan_spacing = -1;
static int hf_ieee802154_chplan_channels = -1;
static int hf_ieee802154_ch_freq = -1;
static int hf_ieee802154_frame_start_offset = -1;
static int hf_ieee802154_frame_duration = -1;
static int hf_ieee802154_frame_end_offset = -1;
static int hf_ieee802154_asn = -1;

typedef struct _ieee802154_transaction_t {
    guint64 dst64;
    guint64 src64;
    gint32 dst_addr_mode;
    gint32 src_addr_mode;
    guint16 dst16;
    guint16 src16;
    guint32 rqst_frame;
    guint32 ack_frame;
    nstime_t rqst_time;
    nstime_t ack_time;
    gboolean dst_pan_present;
    gboolean src_pan_present;
    guint16 dst_pan;
    guint16 src_pan;
} ieee802154_transaction_t;

static const nstime_t ieee802154_transaction_timeout = NSTIME_INIT_SECS_MSECS(1, 0); // ACKs usually arrive within milliseconds

static wmem_tree_t *transaction_unmatched_pdus;
static wmem_tree_t *transaction_matched_pdus;

static ieee802154_transaction_t *transaction_start(packet_info *pinfo, proto_tree *tree, const ieee802154_packet *packet, guint32 *key);
static ieee802154_transaction_t *transaction_end(packet_info *pinfo, proto_tree *tree, const ieee802154_packet *packet, guint32 *key);

/* Initialize Subtree Pointers */
static gint ett_ieee802154_nonask_phy = -1;
static gint ett_ieee802154_nonask_phy_phr = -1;
static gint ett_ieee802154_tap = -1;
static gint ett_ieee802154_tap_header = -1;
static gint ett_ieee802154_tap_tlv = -1;
static gint ett_ieee802154 = -1;
static gint ett_ieee802154_fcf = -1;
static gint ett_ieee802154_auxiliary_security = -1;
static gint ett_ieee802154_aux_sec_control = -1;
static gint ett_ieee802154_aux_sec_key_id = -1;
static gint ett_ieee802154_fcs = -1;
static gint ett_ieee802154_cmd = -1;
static gint ett_ieee802154_superframe = -1;
static gint ett_ieee802154_gts = -1;
static gint ett_ieee802154_gts_direction = -1;
static gint ett_ieee802154_gts_descriptors = -1;
static gint ett_ieee802154_pendaddr = -1;
static gint ett_ieee802154_header_ies = -1;
static gint ett_ieee802154_header_ie = -1;
static gint ett_ieee802154_header_ie_tlv = -1;
static gint ett_ieee802154_hie_unsupported = -1;
static gint ett_ieee802154_hie_time_correction = -1;
static gint ett_ieee802154_hie_ht = -1;
static gint ett_ieee802154_hie_csl = -1;
static gint ett_ieee802154_hie_rdv = -1;
static gint ett_ieee802154_hie_global_time = -1;
static gint ett_ieee802154_hie_vendor_specific = -1;
static gint ett_ieee802154_payload_ie = -1;
static gint ett_ieee802154_payload_ie_tlv = -1;
static gint ett_ieee802154_pie_termination = -1;
static gint ett_ieee802154_pie_vendor = -1;
static gint ett_ieee802154_pie_ietf = -1;
static gint ett_ieee802154_pie_unsupported = -1;
static gint ett_ieee802154_mlme = -1;
static gint ett_ieee802154_mlme_payload = -1;
static gint ett_ieee802154_mlme_payload_data = -1;
static gint ett_ieee802154_mlme_unsupported = -1;
static gint ett_ieee802154_tsch_slotframe = -1;
static gint ett_ieee802154_tsch_slotframe_list = -1;
static gint ett_ieee802154_tsch_slotframe_link = -1;
static gint ett_ieee802154_tsch_slotframe_link_options = -1;
static gint ett_ieee802154_tsch_timeslot = -1;
static gint ett_ieee802154_tsch_synch = -1;
static gint ett_ieee802154_channel_hopping = -1;
static gint ett_ieee802154_psie = -1;
static gint ett_ieee802154_eb_filter = -1;
static gint ett_ieee802154_eb_filter_bitmap = -1;
static gint ett_ieee802154_zigbee = -1;
static gint ett_ieee802154_zboss = -1;
static gint ett_ieee802154_p_ie_6top = -1;
static gint ett_ieee802154_p_ie_6top_cell_options = -1;
static gint ett_ieee802154_p_ie_6top_cell_list = -1;
static gint ett_ieee802154_p_ie_6top_cand_cell_list = -1;
static gint ett_ieee802154_p_ie_6top_rel_cell_list = -1;
static gint ett_ieee802154_p_ie_6top_cell = -1;
static gint ett_ieee802159_mpx = -1;
static gint ett_ieee802159_mpx_transaction_control = -1;

static expert_field ei_ieee802154_fcs_bitmask_len = EI_INIT;
static expert_field ei_ieee802154_invalid_addressing = EI_INIT;
static expert_field ei_ieee802154_invalid_panid_compression = EI_INIT;
static expert_field ei_ieee802154_invalid_panid_compression2 = EI_INIT;
static expert_field ei_ieee802154_fcs = EI_INIT;
static expert_field ei_ieee802154_decrypt_error = EI_INIT;
static expert_field ei_ieee802154_dst = EI_INIT;
static expert_field ei_ieee802154_src = EI_INIT;
static expert_field ei_ieee802154_frame_ver = EI_INIT;
/* static expert_field ei_ieee802154_frame_type = EI_INIT; */
static expert_field ei_ieee802154_seqno_suppression = EI_INIT;
static expert_field ei_ieee802154_ack_not_found = EI_INIT;
static expert_field ei_ieee802154_ack_request_not_found = EI_INIT;
static expert_field ei_ieee802154_time_correction_error = EI_INIT;
static expert_field ei_ieee802154_6top_unsupported_type = EI_INIT;
static expert_field ei_ieee802154_6top_unsupported_return_code = EI_INIT;
static expert_field ei_ieee802154_6top_unsupported_command = EI_INIT;
static expert_field ei_ieee802154_ie_unsupported_id = EI_INIT;
static expert_field ei_ieee802154_ie_unknown_extra_content = EI_INIT;
static expert_field ei_ieee802159_mpx_invalid_transfer_type = EI_INIT;
static expert_field ei_ieee802159_mpx_unsupported_kmp = EI_INIT;
static expert_field ei_ieee802159_mpx_unknown_kmp = EI_INIT;
static expert_field ei_ieee802154_missing_payload_ie = EI_INIT;
static expert_field ei_ieee802154_payload_ie_in_header = EI_INIT;
static expert_field ei_ieee802154_unsupported_cmd = EI_INIT;
static expert_field ei_ieee802154_unknown_cmd = EI_INIT;
static expert_field ei_ieee802154_tap_tlv_invalid_type = EI_INIT;
static expert_field ei_ieee802154_tap_tlv_invalid_length = EI_INIT;
static expert_field ei_ieee802154_tap_tlv_padding_not_zeros = EI_INIT;
static expert_field ei_ieee802154_tap_tlv_invalid_fcs_type = EI_INIT;

static int ieee802_15_4_short_address_type = -1;
/*
 * Dissector handles
 *  - beacon dissection is always heuristic.
 *  - the PANID table is for stateful dissectors only (ie: Decode-As)
 *  - otherwise, data dissectors fall back to the heuristic dissectors.
 */
static dissector_table_t        panid_dissector_table;
static heur_dissector_list_t    ieee802154_beacon_subdissector_list;
static heur_dissector_list_t    ieee802154_heur_subdissector_list;

/* For the IEs and the vendor specific command */
static dissector_table_t header_ie_dissector_table;
static dissector_table_t payload_ie_dissector_table;
static dissector_table_t mlme_ie_dissector_table;
static dissector_table_t cmd_vendor_dissector_table;

static dissector_handle_t  zigbee_ie_handle;
static dissector_handle_t  zigbee_nwk_handle;
static dissector_handle_t  ieee802154_handle;
static dissector_handle_t  ieee802154_nonask_phy_handle;
static dissector_handle_t  ieee802154_nofcs_handle;
static dissector_handle_t  ieee802154_tap_handle;

static int ieee802154_tap = -1;

/* Handles for MPX-IE the Multiplex ID */
static dissector_table_t ethertype_table;
static dissector_handle_t eapol_handle;
static dissector_handle_t lowpan_handle;
static dissector_handle_t wisun_sec_handle;

/* Versions */
static const value_string ieee802154_frame_versions[] = {
    { IEEE802154_VERSION_2003,     "IEEE Std 802.15.4-2003" },
    { IEEE802154_VERSION_2006,     "IEEE Std 802.15.4-2006" },
    { IEEE802154_VERSION_2015,     "IEEE Std 802.15.4-2015" },
    { IEEE802154_VERSION_RESERVED, "Reserved" },
    { 0, NULL }
};

/* Name Strings */
static const value_string ieee802154_frame_types[] = {
    { IEEE802154_FCF_BEACON,       "Beacon" },
    { IEEE802154_FCF_DATA,         "Data" },
    { IEEE802154_FCF_ACK,          "Ack" },
    { IEEE802154_FCF_CMD,          "Command" },
    { IEEE802154_FCF_RESERVED,     "Reserved" },
    { IEEE802154_FCF_MULTIPURPOSE, "Multipurpose" },
    { IEEE802154_FCF_FRAGMENT,     "Fragment or Frak" },
    { IEEE802154_FCF_EXTENDED,     "Extended" },
    { 0, NULL }
};

static const value_string ieee802154_addr_modes[] = {
    { IEEE802154_FCF_ADDR_NONE,     "None" },
    { IEEE802154_FCF_ADDR_RESERVED, "Reserved" },
    { IEEE802154_FCF_ADDR_SHORT,    "Short/16-bit" },
    { IEEE802154_FCF_ADDR_EXT,      "Long/64-bit" },
    { 0, NULL }
};

static const value_string ieee802154_cmd_names[] = {
    { IEEE802154_CMD_ASSOC_REQ,                 "Association Request" },
    { IEEE802154_CMD_ASSOC_RSP,                 "Association Response" },
    { IEEE802154_CMD_DISASSOC_NOTIFY,           "Disassociation Notification" },
    { IEEE802154_CMD_DATA_RQ,                   "Data Request" },
    { IEEE802154_CMD_PANID_CONFLICT,            "PAN ID Conflict" },
    { IEEE802154_CMD_ORPHAN_NOTIFY,             "Orphan Notification" },
    { IEEE802154_CMD_BEACON_REQ,                "Beacon Request" },
    { IEEE802154_CMD_COORD_REALIGN,             "Coordinator Realignment" },
    { IEEE802154_CMD_GTS_REQ,                   "GTS Request" },
    { IEEE802154_CMD_TRLE_MGMT_REQ,             "TRLE Management Request"},
    { IEEE802154_CMD_TRLE_MGMT_RSP,             "TRLE Management Response"},
    { IEEE802154_CMD_DSME_ASSOC_REQ,            "DSME Association Request"},
    { IEEE802154_CMD_DSME_ASSOC_RSP,            "DSME Association Response"},
    { IEEE802154_CMD_DSME_GTS_REQ,              "DSME GTS Request"},
    { IEEE802154_CMD_DSME_GTS_RSP,              "DSME GTS Response"},
    { IEEE802154_CMD_DSME_GTS_NOTIFY,           "DSME GTS Notify"},
    { IEEE802154_CMD_DSME_INFO_REQ,             "DSME Information Request"},
    { IEEE802154_CMD_DSME_INFO_RSP,             "DSME Information Response"},
    { IEEE802154_CMD_DSME_BEACON_ALLOC_NOTIFY,  "DSME Beacon Allocation Notification"},
    { IEEE802154_CMD_DSME_BEACON_COLL_NOTIFY,   "DSME Beacon Collision Notification"},
    { IEEE802154_CMD_DSME_LINK_REPORT,          "DSME Link Report"},
    { IEEE802154_CMD_RIT_DATA_REQ,              "RIT Data Request"},
    { IEEE802154_CMD_DBS_REQ,                   "DBS Request"},
    { IEEE802154_CMD_DBS_RSP,                   "DBS Response"},
    { IEEE802154_CMD_RIT_DATA_RSP,              "RIT Data Response"},
    { IEEE802154_CMD_VENDOR_SPECIFIC,           "Vendor Specific"},
    { 0, NULL }
};

static const value_string ieee802154_sec_level_names[] = {
    { SECURITY_LEVEL_NONE,        "No Security" },
    { SECURITY_LEVEL_MIC_32,      "32-bit Message Integrity Code" },
    { SECURITY_LEVEL_MIC_64,      "64-bit Message Integrity Code" },
    { SECURITY_LEVEL_MIC_128,     "128-bit Message Integrity Code" },
    { SECURITY_LEVEL_ENC,         "Encryption" },
    { SECURITY_LEVEL_ENC_MIC_32,  "Encryption with 32-bit Message Integrity Code" },
    { SECURITY_LEVEL_ENC_MIC_64,  "Encryption with 64-bit Message Integrity Code" },
    { SECURITY_LEVEL_ENC_MIC_128, "Encryption with 128-bit Message Integrity Code" },
    { 0, NULL }
};

static const value_string ieee802154_key_id_mode_names[] = {
    { KEY_ID_MODE_IMPLICIT,       "Implicit Key" },
    { KEY_ID_MODE_KEY_INDEX,      "Indexed Key using the Default Key Source" },
    { KEY_ID_MODE_KEY_EXPLICIT_4, "Explicit Key with 4-octet Key Source" },
    { KEY_ID_MODE_KEY_EXPLICIT_8, "Explicit Key with 8-octet Key Source" },
    { 0, NULL }
};

static const true_false_string ieee802154_gts_direction_tfs = {
    "Receive Only",
    "Transmit Only"
};

/* The 802.15.4-2003 security suites for the security preferences (only AES-CCM suites are supported). */
/* NOTE: The equivalent 2006 security level identifier enumerations are used to simplify 2003 & 2006 integration! */
static const enum_val_t ieee802154_2003_sec_suite_enums[] = {
    { "AES-CCM-128", "AES-128 Encryption, 128-bit Integrity Protection", SECURITY_LEVEL_ENC_MIC_128 },
    { "AES-CCM-64",  "AES-128 Encryption, 64-bit Integrity Protection",  SECURITY_LEVEL_ENC_MIC_64 },
    { "AES-CCM-32",  "AES-128 Encryption, 32-bit Integrity Protection",  SECURITY_LEVEL_ENC_MIC_32 },
    { NULL, NULL, 0 }
};

/* Enumeration for key generation */
static const value_string ieee802154_key_hash_vals[] = {
    { KEY_HASH_NONE, "No hash"},
    { KEY_HASH_ZIP, "ZigBee IP hash" },
    { KEY_HASH_THREAD, "Thread hash" },
    { 0, NULL }
};

static const value_string ieee802154_ie_types[] = {
    { 0, "Header" },
    { 1, "Payload" },
    { 0, NULL }
};

static const value_string ieee802154_psie_types[] = {
    { 0, "Short" },
    { 1, "Long" },
    { 0, NULL }
};

static const value_string ieee802154_header_ie_names[] = {
    { IEEE802154_HEADER_IE_VENDOR_SPECIFIC, "Vendor Specific IE" },
    { IEEE802154_HEADER_IE_CSL,             "CSL IE" },
    { IEEE802154_HEADER_IE_RIT,             "RIT IE" },
    { IEEE802154_HEADER_IE_DSME_PAN,        "DSME PAN descriptor IE" },
    { IEEE802154_HEADER_IE_RENDEZVOUS,      "Rendezvous Time IE" },
    { IEEE802154_HEADER_IE_TIME_CORR,       "Time Correction IE" },
    { IEEE802154_HEADER_IE_EXT_DSME_PAN,    "Extended DSME PAN descriptor IE" },
    { IEEE802154_HEADER_IE_FSCD,            "Fragment Sequence Context Description (FSCD) IE" },
    { IEEE802154_HEADER_IE_SMPL_SUPER_FRM,  "Simplified Superframe Specification IE" },
    { IEEE802154_HEADER_IE_SMPL_GTS,        "Simplified GTS Specification IE" },
    { IEEE802154_HEADER_IE_LECIM,           "LECIM Capabilities IE" },
    { IEEE802154_HEADER_IE_TRLE,            "TRLE Descriptor" },
    { IEEE802154_HEADER_IE_RCC_CAP,         "RCC Capabilities IE" },
    { IEEE802154_HEADER_IE_RCCN,            "RCCN Descriptor IE" },
    { IEEE802154_HEADER_IE_GLOBAL_TIME,     "Global Time IE" },
    { IEEE802154_HEADER_IE_WISUN,           "Wi-SUN IE" },
    { IEEE802154_HEADER_IE_DA_IE,           "DA IE" },
    { IEEE802154_HEADER_IE_HT1,             "Header Termination 1 IE" },
    { IEEE802154_HEADER_IE_HT2,             "Header Termination 2 IE" },
    { 0, NULL }
};

static const true_false_string hf_ieee802154_nack_tfs = {
    "Negative Acknowledgement",
    "Acknowledgement"
};

static const value_string ieee802154_payload_ie_names[] = {
    { IEEE802154_PAYLOAD_IE_ESDU,                     "ESDU IE" },
    { IEEE802154_PAYLOAD_IE_MLME,                     "MLME IE" },
    { IEEE802154_PAYLOAD_IE_VENDOR,                   "Vendor Specific IE" },
    { IEEE802154_PAYLOAD_IE_MPX,                      "MPX IE" },
    { IEEE802154_PAYLOAD_IE_WISUN,                    "Wi-SUN IE" },
    { IEEE802154_PAYLOAD_IE_IETF,                     "IETF IE" },
    { IEEE802154_PAYLOAD_IE_TERMINATION,              "Payload Termination IE" },
    { 0, NULL }
};

static const value_string ieee802154_psie_names[] = {
    { IEEE802154_MLME_SUBIE_CHANNEL_HOPPING,          "Channel Hopping IE" },
    { IEEE802154_MLME_SUBIE_TSCH_SYNCH,               "TSCH Synchronization IE" },
    { IEEE802154_MLME_SUBIE_TSCH_SLOTFR_LINK,         "TSCH Slotframe and Link IE" },
    { IEEE802154_MLME_SUBIE_TSCH_TIMESLOT,            "TSCH Timeslot IE" },
    { IEEE802154_MLME_SUBIE_HOPPING_TIMING,           "Hopping Timing IE" },
    { IEEE802154_MLME_SUBIE_ENHANCED_BEACON_FILTER,   "Enhanced Beacon Filter IE" },
    { IEEE802154_MLME_SUBIE_MAC_METRICS,              "MAC Metrics IE" },
    { IEEE802154_MLME_SUBIE_ALL_MAC_METRICS,          "All MAC Metrics IE" },
    { IEEE802154_MLME_SUBIE_COEXISTENCE_SPEC,         "Coexistence Specification IE" },
    { IEEE802154_MLME_SUBIE_SUN_DEVICE_CAPABILITIES,  "SUN Device Capabilities IE" },
    { IEEE802154_MLME_SUBIE_SUN_FSK_GEN_PHY,          "SUN FSK Generic PHY IE" },
    { IEEE802154_MLME_SUBIE_MODE_SWITCH_PARAMETER,    "Mode Switch Parameter IE" },
    { IEEE802154_MLME_SUBIE_PHY_PARAMETER_CHANGE,     "PHY Parameter Change IE" },
    { IEEE802154_MLME_SUBIE_O_QPSK_PHY_MODE,          "O-QPSY PHY Mode IE" },
    { IEEE802154_MLME_SUBIE_PCA_ALLOCATION,           "PCA Allocation IE" },
    { IEEE802154_MLME_SUBIE_DSSS_OPER_MODE,           "LECIM DSSS Operating Mode IE"},
    { IEEE802154_MLME_SUBIE_FSK_OPER_MODE,            "LECIM FSK Operating Mode IE" },
    { IEEE802154_MLME_SUBIE_TVWS_PHY_OPE_MODE,        "TVWS PHY Operating Mode Description IE" },
    { IEEE802154_MLME_SUBIE_TVWS_DEVICE_CAPAB,        "TVWS Device Capabilities IE" },
    { IEEE802154_MLME_SUBIE_TVWS_DEVICE_CATEG,        "TVWS Device Category IE" },
    { IEEE802154_MLME_SUBIE_TVWS_DEVICE_IDENTIF,      "TVWS Device Identification IE" },
    { IEEE802154_MLME_SUBIE_TVWS_DEVICE_LOCATION,     "TVWS Device Location IE" },
    { IEEE802154_MLME_SUBIE_TVWS_CH_INFOR_QUERY,      "TVWS Channel Information Query IE" },
    { IEEE802154_MLME_SUBIE_TVWS_CH_INFOR_SOURCE,     "TVWS Channel Information Source IE" },
    { IEEE802154_MLME_SUBIE_CTM,                      "CTM IE" },
    { IEEE802154_MLME_SUBIE_TIMESTAMP,                "Timestamp IE" },
    { IEEE802154_MLME_SUBIE_TIMESTAMP_DIFF,           "Timestamp Difference IE"},
    { IEEE802154_MLME_SUBIE_TMCP_SPECIFICATION,       "TMCTP Specification IE" },
    { IEEE802154_MLME_SUBIE_RCC_PHY_OPER_MODE,        "RCC PHY Operating Mode IE" },
    { IEEE802154_IETF_SUBIE_6TOP,                     "6top IE" },
    { 0, NULL }
};

const value_string zboss_page_names[] = {
    { 0, "2.4 GHz" },
    { 28, "863-868 MHz band"},
    { 29, "868-870, 870-876 MHz band" },
    { 30, "870-876 MHz band" },
    { 31, "915-921 MHz band" },
    { 0, NULL }
};

static const value_string zboss_direction_names[] = {
    { 0, "IN" },
    { 1, "OUT" },
    { 0, NULL }
};

static const value_string tap_tlv_types[] = {
    { IEEE802154_TAP_FCS_TYPE,  "FCS type"},
    { IEEE802154_TAP_RSS, "RSS"},
    { IEEE802154_TAP_BIT_RATE, "Bit rate"},
    { IEEE802154_TAP_CHANNEL_ASSIGNMENT, "Channel assignment"},
    { IEEE802154_TAP_SUN_PHY_INFO, "SUN PHY Information"},
    { IEEE802154_TAP_START_OF_FRAME_TS, "Start of frame timestamp"},
    { IEEE802154_TAP_END_OF_FRAME_TS, "End of frame timestamp"},
    { IEEE802154_TAP_ASN, "Absolute Slot Number (ASN)"},
    { IEEE802154_TAP_SLOT_START_TS, "Start of slot timestamp"},
    { IEEE802154_TAP_TIMESLOT_LENGTH, "Slot length"},
    { IEEE802154_TAP_LQI, "Link Quality Indicator"},
    { IEEE802154_TAP_CHANNEL_FREQUENCY, "Channel center frequency"},
    { IEEE802154_TAP_CHANNEL_PLAN, "Channel plan"},
    { 0, NULL }
};

static const value_string tap_fcs_type_names[] = {
    { IEEE802154_FCS_TYPE_NONE, "None" },
    { IEEE802154_FCS_TYPE_16_BIT, "ITU-T CRC16" },
    { IEEE802154_FCS_TYPE_32_BIT, "ITU-T CRC32" },
    { 0, NULL }
};

/* IEEE 802.15.4 Table 7-19 */
static const value_string sun_bands[] = {
    { 0, "169 MHz [169.400-169.475]" },
    { 1, "450 MHz [450-470]" },
    { 2, "470 MHz [470-510]" },
    { 3, "780 MHz [779-787]" },
    { 4, "863 MHz [863-870]" },
    { 5, "896 MHz [896-901]" },
    { 6, "901 MHz [901-902]" },
    { 7, "915 MHz [902-928]" },
    { 8, "917 MHz [917-923.5]" },
    { 9, "920 MHz [920-928]" },
    { 10, "928 MHz [928-960]" },
    { 11, "920 MHz [920-960]" },
    { 12, "1427 MHz [1427-1518]" },
    { 13, "2450 MHz [2400-2483.5]" },
    { 14, "866 MHz [865-867]" },
    { 15, "870 MHz [870-876]" },
    { 16, "915 MHz-a [902-928 alternate]" },
    { 17, "915 MHz-b [902-907.5 & 915-928]" },
    { 18, "915 MHz-c [915-928]" },
    { 19, "915 MHz-d [915-921]" },
    { 20, "915 MHz-e [915-918]" },
    { 21, "919 MHz [919-923]" },
    { 22, "920 MHz-a [920.5-924.5]" },
    { 23, "920 MHz-b [920-925]" },
    { 24, "867 MHz [866-869]" },
    /* Exegin defined numbers for bands in Table 10-1 but not in Table 7-19 */
    { 32, "433 MHz [433.05-434.79]" },
    { 33, "868 MHz [868-868.6]" },
    { 34, "2380 MHz [2360-2400]" },
    { 0, NULL }
};

/* IEEE 802.15.4 Table 7-20 */
static const value_string sun_types[] = {
    { IEEE802154_SUN_TYPE_FSK_A, "FSK-A" },
    { IEEE802154_SUN_TYPE_FSK_B, "FSK-B" },
    { IEEE802154_SUN_TYPE_OQPSK_A, "O-QPSK-A" },
    { IEEE802154_SUN_TYPE_OQPSK_B, "O-QPSK-B" },
    { IEEE802154_SUN_TYPE_OQPSK_C, "O-QPSK-C" },
    { IEEE802154_SUN_TYPE_OFDM_OPT1, "OFDM Option 1" },
    { IEEE802154_SUN_TYPE_OFDM_OPT2, "OFDM Option 2" },
    { IEEE802154_SUN_TYPE_OFDM_OPT3, "OFDM Option 3" },
    { IEEE802154_SUN_TYPE_OFDM_OPT4, "OFDM Option 4" },
    { 0, NULL }
};

static const value_string fsk_a_modes[] = {
    { 0, "4.8 kb/s; 2-FSK; mod index = 1.0; channel spacing = 12.5 kHz" },
    { 1, "9.6 kb/s; 4-FSK; mod index = 0.33; channel spacing = 12.5 kHz" },
    { 2, "10 kb/s; 2-FSK; mod index = 0.5; channel spacing = 12.5 kHz" },
    { 3, "20 kb/s; 2-FSK; mod index = 0.5; channel spacing = 12.5 kHz" },
    { 4, "40 kb/s; 2-FSK; mod index = 0.5; channel spacing = 12.5 kHz" },
    { 5, "4.8 kb/s; 2-FSK; mod index = 0.5; channel spacing = 12.5 kHz" },
    { 6, "2.4 kb/s; 2-FSK; mod index = 2.0; channel spacing = 12.5 kHz" },
    { 7, "9.6 kb/s; 4-FSK; mod index = 0.33; channel spacing = 12.5 kHz" },
    { 0, NULL }
};

static const value_string fsk_b_modes[] = {
    { 0, "50 kb/s; 2-FSK; mod index = 1.0; channel spacing = 200 kHz" },
    { 1, "100 kb/s; 2-FSK; mod index = 1.0; channel spacing = 400 kHz" },
    { 2, "150 kb/s; 2-FSK; mod index = 0.5; channel spacing = 400 kHz" },
    { 3, "200 kb/s; 2-FSK; mod index = 0.5; channel spacing = 400 kHz" },
    { 4, "200 kb/s; 4-FSK; mod index = 0.33; channel spacing = 400 kHz" },
    { 5, "200 kb/s; 2-FSK; mod index = 1.0; channel spacing = 600 kHz" },
    { 6, "400 kb/s; 4-FSK; mod index = 0.33; channel spacing = 600 kHz" },
    { 7, "100 kb/s; 2-FSK; mod index = 0.5; channel spacing = 200 kHz"},
    { 8, "50 kb/s; 2-FSK; mod index = 0.5; channel spacing = 100 kHz"},
    { 9, "150 kb/s; 2-FSK; mod index = 0.5; channel spacing = 200 kHz"},
    { 10, "300 kb/s; 2-FSK; mod index = 0.5; channel spacing = 400 kHz" },
    { 0, NULL }
};

static const value_string oqpsk_a_modes[] = {
    { 0, "chip rate = 100 kchip/s; SpreadingMode = DSSS; RateMode = 0; data rate = 6.25 kb/s"},
    { 1, "chip rate = 100 kchip/s; SpreadingMode = DSSS; RateMode = 1; data rate = 12.5 kb/s"},
    { 2, "chip rate = 100 kchip/s; SpreadingMode = DSSS; RateMode = 2; data rate = 25 kb/s"},
    { 3, "chip rate = 100 kchip/s; SpreadingMode = DSSS; RateMode = 3; data rate = 50 kb/s"},
    { 0, NULL }
};

static const value_string oqpsk_b_modes[] = {
    { 0, "chip rate = 1000 kchip/s; SpreadingMode = DSSS; RateMode = 0; data rate = 31.25 kb/s"},
    { 1, "chip rate = 1000 kchip/s; SpreadingMode = DSSS; RateMode = 1; data rate = 125 kb/s"},
    { 2, "chip rate = 1000 kchip/s; SpreadingMode = DSSS; RateMode = 2; data rate = 250 kb/s"},
    { 3, "chip rate = 1000 kchip/s; SpreadingMode = DSSS; RateMode = 3; data rate = 500 kb/s"},
    { 4, "chip rate = 1000 kchip/s; SpreadingMode = MDSSS; RateMode = 0; data rate = 62.5 kb/s"},
    { 5, "chip rate = 1000 kchip/s; SpreadingMode = MDSSS; RateMode = 1; data rate = 125 kb/s"},
    { 6, "chip rate = 1000 kchip/s; SpreadingMode = MDSSS; RateMode = 2; data rate = 250 kb/s"},
    { 7, "chip rate = 1000 kchip/s; SpreadingMode = MDSSS; RateMode = 3; data rate = 500 kb/s"},
    { 0, NULL }
};

static const value_string oqpsk_c_modes[] = {
    { 0, "chip rate = 2000 kchip/s; SpreadingMode = DSSS; RateMode = 0; data rate = 31.25 kb/s"},
    { 1, "chip rate = 2000 kchip/s; SpreadingMode = DSSS; RateMode = 1; data rate = 125 kb/s"},
    { 2, "chip rate = 2000 kchip/s; SpreadingMode = DSSS; RateMode = 2; data rate = 250 kb/s"},
    { 3, "chip rate = 2000 kchip/s; SpreadingMode = DSSS; RateMode = 3; data rate = 500 kb/s"},
    { 4, "chip rate = 2000 kchip/s; SpreadingMode = MDSSS; RateMode = 0; data rate = 62.5 kb/s"},
    { 5, "chip rate = 2000 kchip/s; SpreadingMode = MDSSS; RateMode = 1; data rate = 125 kb/s"},
    { 6, "chip rate = 2000 kchip/s; SpreadingMode = MDSSS; RateMode = 2; data rate = 250 kb/s"},
    { 7, "chip rate = 2000 kchip/s; SpreadingMode = MDSSS; RateMode = 3; data rate = 500 kb/s"},
    { 0, NULL }
};

static const value_string ofdm_modes[] = {
    { 0, "MCS0" },
    { 1, "MCS1" },
    { 2, "MCS2" },
    { 3, "MCS3" },
    { 4, "MCS4" },
    { 5, "MCS5" },
    { 6, "MCS6" },
    { 0, NULL },
};

static const value_string channel_page_names[] = {
    { 0, "Default" },
    { 1, "ASK" },
    { 2, "O-QPSK" },
    { 3, "CSS" },
    { 4, "HRP UWB" },
    { 5, "780 MHz" },
    { 6, "GFSK" },
    { 7, "MSK" },
    { 8, "LRP_UWB" },
    { 9, "SUN" },
    { 10, "SUN FSK" },
    { 11, "2380 MHz" },
    { 12, "LECIM" },
    { 13, "RCC" },
    { 0, NULL }
};

static const value_string ietf_6top_types[] = {
    { IETF_6TOP_TYPE_REQUEST, "Request" },
    { IETF_6TOP_TYPE_RESPONSE, "Response" },
    { IETF_6TOP_TYPE_CONFIRMATION, "Confirmation" },
    { 0, NULL }
};

static const value_string ietf_6top_command_identifiers[] = {
    { IETF_6TOP_CMD_ADD, "ADD" },
    { IETF_6TOP_CMD_DELETE, "DELETE" },
    { IETF_6TOP_CMD_RELOCATE, "RELOCATE" },
    { IETF_6TOP_CMD_COUNT, "COUNT" },
    { IETF_6TOP_CMD_LIST, "LIST" },
    { IETF_6TOP_CMD_SIGNAL, "SIGNAL" },
    { IETF_6TOP_CMD_CLEAR, "CLEAR" },
    { 0, NULL }
};

static const value_string ietf_6top_return_codes[] = {
    { IETF_6TOP_RC_SUCCESS, "SUCCESS" },
    { IETF_6TOP_RC_EOL, "RC_EOL" },
    { IETF_6TOP_RC_ERR, "RC_ERR" },
    { IETF_6TOP_RC_RESET, "RC_RESET" },
    { IETF_6TOP_RC_ERR_VERSION, "RC_ERR_VERSION" },
    { IETF_6TOP_RC_ERR_SFID, "RC_ERR_SFID" },
    { IETF_6TOP_RC_ERR_SEQNUM, "RC_ERR_SEQNUM" },
    { IETF_6TOP_RC_ERR_CELLLIST, "RC_ERR_CELLLIST" },
    { IETF_6TOP_RC_ERR_BUSY, "RC_ERR_BUSY" },
    { IETF_6TOP_RC_ERR_LOCKED, "RC_ERR_LOCKED" },
    { 0, NULL }
};

static const value_string ietf_6top_cell_options[] = {
    { 0, "ALL" },
    { 1, "TX" },
    { 2, "RX" },
    { 3, "TX|RX" },
    { 4, "SHARED" },
    { 5, "TX|SHARED" },
    { 6, "RX|SHARED" },
    { 7, "TX|RX|SHARED" },
    { 0, NULL}
};

static const value_string mpx_transfer_type_vals[] = {
    { IEEE802159_MPX_FULL_FRAME, "Full Frame" },
    { IEEE802159_MPX_FULL_FRAME_NO_MUXID, "Full frame with compressed Multiplex ID" },
    { IEEE802159_MPX_NON_LAST_FRAGMENT, "Non-last Fragment" },
    { IEEE802159_MPX_LAST_FRAGMENT, "Last Fragment" },
    { IEEE802159_MPX_ABORT, "Abort" },
    { 0, NULL }
};

static const value_string mpx_multiplex_id_vals[] = {
    { IEEE802159_MPX_MULTIPLEX_ID_KMP, "KMP" },
    { IEEE802159_MPX_MULTIPLEX_ID_WISUN, "Wi-SUN" },
    { 0, NULL }
};

// used by the Wi-SUN dissector
const value_string ieee802154_mpx_kmp_id_vals[] = {
    { IEEE802159_MPX_KMP_ID_IEEE8021X, "IEEE 802.1X/MKA" },
    { IEEE802159_MPX_KMP_ID_HIP, "HIP" },
    { IEEE802159_MPX_KMP_ID_IKEV2, "IKEv2" },
    { IEEE802159_MPX_KMP_ID_PANA, "PANA" },
    { IEEE802159_MPX_KMP_ID_DRAGONFLY, "Dragonfly" },
    { IEEE802159_MPX_KMP_ID_IEEE80211_4WH, "IEEE 802.11/4WH" },
    { IEEE802159_MPX_KMP_ID_IEEE80211_GKH, "IEEE 802.11/GKH" },
    { IEEE802159_MPX_KMP_ID_ETSI_TS_102_887_2, "ETSI TS 102 887-2" },
    { IEEE802159_MPX_KMP_ID_VENDOR_SPECIFIC, "Vendor-specific" },
    { 0, NULL }
};

static const value_string mpx_wisun_subid_vals[] = {
    { IEEE802159_MPX_WISUN_SUBID_MHDS, "WM-MHDS" },
    { IEEE802159_MPX_WISUN_SUBID_6LOWPAN, "WM-6LO" },
    { IEEE802159_MPX_WISUN_SUBID_SECURITY, "WM-SEC" },
    { 0, NULL }
};

/* Preferences for 2003 security */
static gint ieee802154_sec_suite = SECURITY_LEVEL_ENC_MIC_64;
static gboolean ieee802154_extend_auth = TRUE;

/* Macro to check addressing, and throw a warning flag if incorrect. */
#define IEEE802154_CMD_ADDR_CHECK(_pinfo_, _item_, _cmdid_, _x_)     \
   if (!(_x_))                                                       \
     expert_add_info_format(_pinfo_, _item_, &ei_ieee802154_invalid_addressing, \
                            "Invalid Addressing for %s",             \
                            val_to_str_const(_cmdid_, ieee802154_cmd_names, "Unknown Command"))

/* CRC definitions. IEEE 802.15.4 CRCs vary from ITU-T by using an initial value of
 * 0x0000, and no XOR out. IEEE802154_CRC_XOR is defined as 0xFFFF in order to un-XOR
 * the output from the ITU-T (CCITT) CRC routines in Wireshark.
 */
#define IEEE802154_CRC_SEED     0x0000
#define IEEE802154_CRC_XOROUT   0xFFFF
#define ieee802154_crc_tvb(tvb, offset)   (crc16_ccitt_tvb_seed(tvb, offset, IEEE802154_CRC_SEED) ^ IEEE802154_CRC_XOROUT)

/* For the 32-bit CRC, IEEE 802.15.4 uses ITU-T (CCITT) CRC-32. */
#define ieee802154_crc32_tvb(tvb, offset) (crc32_ccitt_tvb(tvb, offset))

static int ieee802_15_4_short_address_to_str(const address* addr, gchar *buf, int buf_len)
{
    guint16 ieee_802_15_4_short_addr = pletoh16(addr->data);

    if (ieee_802_15_4_short_addr == 0xffff)
    {
        (void) g_strlcpy(buf, "Broadcast", buf_len);
        return 10;
    }

    *buf++ = '0';
    *buf++ = 'x';
    buf = word_to_hex(buf, ieee_802_15_4_short_addr);
    *buf = '\0'; /* NULL terminate */

    return 7;
}

static int ieee802_15_4_short_address_str_len(const address* addr _U_)
{
    return 11;
}

static int ieee802_15_4_short_address_len(void)
{
    return 2;
}

/* ======================================================================= */
static conversation_t *_find_or_create_conversation(packet_info *pinfo, const address *src_addr, const address *dst_addr)
{
    conversation_t *conv = NULL;

    /* Have we seen this conversation before? */
    conv = find_conversation(pinfo->num, src_addr, dst_addr, ENDPOINT_NONE, 0, 0, 0);
    if (conv == NULL) {
        /* No, this is a new conversation. */
        conv = conversation_new(pinfo->num, src_addr, dst_addr, ENDPOINT_NONE, 0, 0, 0);
    }
    return conv;
}

/* ======================================================================= */
static ieee802154_transaction_t *transaction_start(packet_info *pinfo, proto_tree *tree, const ieee802154_packet *packet, guint32 *key)
{
    ieee802154_transaction_t    *ieee802154_trans;
    wmem_tree_key_t             ieee802154_key[3];
    proto_item                  *it;

    if (!PINFO_FD_VISITED(pinfo)) {
        /*
         * This is a new request, create a new transaction structure and map it
         * to the unmatched table.
         */
        ieee802154_key[0].length = 2;
        ieee802154_key[0].key = key;
        ieee802154_key[1].length = 0;
        ieee802154_key[1].key = NULL;

        ieee802154_trans = wmem_new0(wmem_file_scope(), ieee802154_transaction_t);

        if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT)
            ieee802154_trans->dst16 = packet->dst16;
        else if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)
            ieee802154_trans->dst64 = packet->dst64;
        ieee802154_trans->dst_addr_mode = packet->dst_addr_mode;

        if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT)
            ieee802154_trans->src16 = packet->src16;
        else if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)
            ieee802154_trans->src64 = packet->src64;
        ieee802154_trans->src_addr_mode = packet->src_addr_mode;

        if (packet->dst_pan_present) {
            ieee802154_trans->dst_pan_present = TRUE;
            ieee802154_trans->dst_pan = packet->dst_pan;
        }
        if (packet->src_pan_present) {
            ieee802154_trans->src_pan_present = TRUE;
            ieee802154_trans->src_pan = packet->src_pan;
        }
        ieee802154_trans->rqst_frame = pinfo->num;
        ieee802154_trans->ack_frame = 0;
        ieee802154_trans->rqst_time = pinfo->abs_ts;
        nstime_set_unset(&ieee802154_trans->ack_time);
        wmem_tree_insert32_array(transaction_unmatched_pdus, ieee802154_key, (void *)ieee802154_trans);
    } else {
        /* Already visited this frame */
        guint32 frame_num = pinfo->num;

        ieee802154_key[0].length = 2;
        ieee802154_key[0].key = key;
        ieee802154_key[1].length = 1;
        ieee802154_key[1].key = &frame_num;
        ieee802154_key[2].length = 0;
        ieee802154_key[2].key = NULL;

        ieee802154_trans = (ieee802154_transaction_t *)wmem_tree_lookup32_array(transaction_matched_pdus, ieee802154_key);

        if (!ieee802154_trans) {
            /* No ACK found - add field and expert info */
            it = proto_tree_add_item(tree, hf_ieee802154_no_ack, NULL, 0, 0, ENC_NA);
            proto_item_set_generated(it);

            expert_add_info_format(pinfo, it, &ei_ieee802154_ack_not_found, "No ack found to request in frame %u", pinfo->num);

            return NULL;
        }
    }

    /* Print state tracking in the tree */
    if (ieee802154_trans->ack_frame) {
        it = proto_tree_add_uint(tree, hf_ieee802154_ack_in, NULL, 0, 0, ieee802154_trans->ack_frame);
        proto_item_set_generated(it);
    }

    return ieee802154_trans;
} /* transaction_start() */

static ieee802154_transaction_t *transaction_end(packet_info *pinfo, proto_tree *tree, const ieee802154_packet *packet, guint32 *key)
{
    ieee802154_transaction_t    *ieee802154_trans = NULL;
    wmem_tree_key_t             ieee802154_key[3];
    proto_item                  *it;

    if (!PINFO_FD_VISITED(pinfo)) {
        guint32 frame_num;
        nstime_t ns;

        ieee802154_key[0].length = 2;
        ieee802154_key[0].key = key;
        ieee802154_key[1].length = 0;
        ieee802154_key[1].key = NULL;

        ieee802154_trans = (ieee802154_transaction_t *)wmem_tree_lookup32_array(transaction_unmatched_pdus, ieee802154_key);
        if (ieee802154_trans == NULL)
            return NULL;

        /* we have already seen this response, or an identical one */
        if (ieee802154_trans->ack_frame != 0)
            return NULL;

        /* If addresses are present they must match */
        if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
            if (packet->src16 != ieee802154_trans->dst16)
                return NULL;
        }
        else if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
            if (packet->src64 != ieee802154_trans->dst64)
                return NULL;
        }
        if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
            if (packet->dst16 != ieee802154_trans->src16)
                return NULL;
        }
        else if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
            if (packet->dst64 != ieee802154_trans->src64)
                return NULL;
        }

        nstime_delta(&ns, &pinfo->abs_ts, &ieee802154_trans->rqst_time);
        if (nstime_cmp(&ns, &ieee802154_transaction_timeout) > 0)
            return NULL;

        ieee802154_trans->ack_time = ns;
        ieee802154_trans->ack_frame = pinfo->num;

        /*
         * We found a match.  Add entries to the matched table for both
         * request and ack frames
         */
        ieee802154_key[0].length = 2;
        ieee802154_key[0].key = key;
        ieee802154_key[1].length = 1;
        ieee802154_key[1].key = &frame_num;
        ieee802154_key[2].length = 0;
        ieee802154_key[2].key = NULL;

        frame_num = ieee802154_trans->rqst_frame;
        wmem_tree_insert32_array(transaction_matched_pdus, ieee802154_key, (void *)ieee802154_trans);

        frame_num = ieee802154_trans->ack_frame;
        wmem_tree_insert32_array(transaction_matched_pdus, ieee802154_key, (void *)ieee802154_trans);
    } else {
        /* Already visited this frame */
        guint32 frame_num = pinfo->num;

        ieee802154_key[0].length = 2;
        ieee802154_key[0].key = key;
        ieee802154_key[1].length = 1;
        ieee802154_key[1].key = &frame_num;
        ieee802154_key[2].length = 0;
        ieee802154_key[2].key = NULL;

        ieee802154_trans = (ieee802154_transaction_t *)wmem_tree_lookup32_array(transaction_matched_pdus, ieee802154_key);

        if (!ieee802154_trans) {
            /* No ack request found - add field and expert info */
            it = proto_tree_add_item(tree, hf_ieee802154_no_ack_request, NULL, 0, 0, ENC_NA);
            proto_item_set_generated(it);

            expert_add_info_format(pinfo, it, &ei_ieee802154_ack_request_not_found, "No request found to ack in frame %u", pinfo->num);
            return NULL;
        }
    }

    if (packet->dst_pan_present == FALSE) {
        if (ieee802154_trans->src_pan_present) {
            it = proto_tree_add_uint(tree, hf_ieee802154_dst_panID, NULL, 0, 0, ieee802154_trans->src_pan);
            proto_item_set_generated(it);
        }
        else if (ieee802154_trans->dst_pan_present) {
            it = proto_tree_add_uint(tree, hf_ieee802154_dst_panID, NULL, 0, 0, ieee802154_trans->dst_pan);
            proto_item_set_generated(it);
        }
    }
    if ((packet->src_pan_present == FALSE) && (ieee802154_trans->src_pan_present) && (ieee802154_trans->dst_pan_present)) {
        it = proto_tree_add_uint(tree, hf_ieee802154_src_panID, NULL, 0, 0, ieee802154_trans->dst_pan);
        proto_item_set_generated(it);
    }

    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) {
        if (ieee802154_trans->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
            it = proto_tree_add_uint(tree, hf_ieee802154_dst16, NULL, 0, 0, ieee802154_trans->src16);
            proto_item_set_generated(it);

            it = proto_tree_add_uint(tree, hf_ieee802154_addr16, NULL, 0, 0, ieee802154_trans->src16);
            proto_item_set_hidden(it);
            proto_item_set_generated(it);
        }
        else if (ieee802154_trans->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
            it = proto_tree_add_eui64(tree, hf_ieee802154_dst64, NULL, 0, 0, ieee802154_trans->src64);
            proto_item_set_generated(it);

            it = proto_tree_add_eui64(tree, hf_ieee802154_addr64, NULL, 0, 0, ieee802154_trans->src64);
            proto_item_set_hidden(it);
            proto_item_set_generated(it);
        }
    }

    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) {
        if (ieee802154_trans->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
            it = proto_tree_add_uint(tree, hf_ieee802154_src16, NULL, 0, 0, ieee802154_trans->dst16);
            proto_item_set_generated(it);

            it = proto_tree_add_uint(tree, hf_ieee802154_addr16, NULL, 0, 0, ieee802154_trans->dst16);
            proto_item_set_hidden(it);
            proto_item_set_generated(it);
        }
        else if (ieee802154_trans->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
            it = proto_tree_add_eui64(tree, hf_ieee802154_src64, NULL, 0, 0, ieee802154_trans->dst64);
            proto_item_set_generated(it);

            it = proto_tree_add_eui64(tree, hf_ieee802154_addr64, NULL, 0, 0, ieee802154_trans->dst64);
            proto_item_set_hidden(it);
            proto_item_set_generated(it);
        }
    }

    /* Print state tracking in the tree */
    it = proto_tree_add_uint(tree, hf_ieee802154_ack_to, NULL, 0, 0, ieee802154_trans->rqst_frame);
    proto_item_set_generated(it);

    it = proto_tree_add_time(tree, hf_ieee802154_ack_time, NULL, 0, 0, &ieee802154_trans->ack_time);
    proto_item_set_generated(it);

    return ieee802154_trans;

} /* transaction_end() */

/**
 * Dissector helper, parses and displays the frame control field.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 * @param packet IEEE 802.15.4 packet information.
 * @param offset offset into the tvb to find the FCF.
 *
 */
static void
dissect_ieee802154_fcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet, guint *offset)
{
    guint16     fcf;
    static int * const ieee802154_fields[] = {
        &hf_ieee802154_frame_type,
        &hf_ieee802154_security,
        &hf_ieee802154_pending,
        &hf_ieee802154_ack_request,
        &hf_ieee802154_pan_id_compression,
        &hf_ieee802154_fcf_reserved,
        &hf_ieee802154_seqno_suppression,
        &hf_ieee802154_ie_present,
        &hf_ieee802154_dst_addr_mode,
        &hf_ieee802154_version,
        &hf_ieee802154_src_addr_mode,
        NULL
    };

    static int* const ieee802154_mpf_short_fields[] = {
        &hf_ieee802154_frame_type,
        &hf_ieee802154_mpf_long_frame_control,
        &hf_ieee802154_mpf_dst_addr_mode,
        &hf_ieee802154_mpf_src_addr_mode,
        NULL
    };

    static int* const ieee802154_mpf_long_fields[] = {
        &hf_ieee802154_frame_type,
        &hf_ieee802154_mpf_long_frame_control,
        &hf_ieee802154_mpf_dst_addr_mode,
        &hf_ieee802154_mpf_src_addr_mode,
        &hf_ieee802154_mpf_pan_id_present,
        &hf_ieee802154_mpf_security,
        &hf_ieee802154_mpf_seqno_suppression,
        &hf_ieee802154_mpf_pending,
        &hf_ieee802154_mpf_version,
        &hf_ieee802154_mpf_ack_request,
        &hf_ieee802154_mpf_ie_present,
        NULL
    };

    /* Get the FCF field. */
    fcf = tvb_get_letohs(tvb, *offset);

     /* Parse FCF Flags. */
    packet->frame_type          = (fcf & IEEE802154_FCF_TYPE_MASK);

    if (packet->frame_type == IEEE802154_FCF_MULTIPURPOSE) {
        /* Multipurpose frames use a different 1 or 2 byte FCF */
        packet->long_frame_control  = (fcf & IEEE802154_MPF_FCF_LONG_FC) >> 3;
        packet->dst_addr_mode       = (fcf & IEEE802154_MPF_FCF_DADDR_MASK) >> 4;
        packet->src_addr_mode       = (fcf & IEEE802154_MPF_FCF_SADDR_MASK) >> 6;

        /* The second octet of the FCF is only present if the long frame control bit is set */
        if (packet->long_frame_control) {
            packet->pan_id_present = (fcf & IEEE802154_MPF_FCF_PAN_ID_PRESENT) >> 8;
            packet->security_enable = (fcf & IEEE802154_MPF_FCF_SEC_EN) >> 9;
            packet->seqno_suppression = (fcf & IEEE802154_MPF_FCF_SEQNO_SUPPRESSION) >> 10;
            packet->frame_pending   = (fcf & IEEE802154_MPF_FCF_FRAME_PND) >> 11;
            packet->version         = (fcf & IEEE802154_MPF_FCF_VERSION) >> 12;
            packet->ack_request     = (fcf & IEEE802154_MPF_FCF_ACK_REQ) >> 14;
            packet->ie_present      = (fcf & IEEE802154_MPF_FCF_IE_PRESENT) >> 15;
        }
        else {
            packet->security_enable = FALSE;
            packet->seqno_suppression = FALSE;
            packet->frame_pending   = FALSE;
            packet->version         = 0;
            packet->ack_request     = FALSE;
            packet->ie_present      = FALSE;
        }

        if (ieee802154e_compatibility) {
            if (((tvb_reported_length(tvb) == IEEE802154E_LE_WUF_LEN)) && !packet->long_frame_control) {
                /* Check if this is an IEEE 802.15.4e LE-multipurpose Wake-up Frame, which has a single-octet FCF
                 * and a static layout that cannot be inferred from the FCF alone. */
                guint16 ie_header = tvb_get_letohs(tvb, (*offset) + 6);
                guint16 id = (guint16)((ie_header & IEEE802154_HEADER_IE_ID_MASK) >> 7);
                guint16 length = (guint16)(ie_header & IEEE802154_HEADER_IE_LENGTH_MASK);
                if ((id == IEEE802154_HEADER_IE_RENDEZVOUS) && (length == 2)) {
                    /* This appears to be a WUF, as identified by containing a single
                     * Rendezvous Time Header IE with only a rendezvous time. */
                    packet->ie_present = TRUE;
                    packet->pan_id_present = TRUE;
                }
            }
        }
    }
    else {
        /* Standard 802.15.4 FCF */
        packet->security_enable     = (fcf & IEEE802154_FCF_SEC_EN) >> 3;
        packet->frame_pending       = (fcf & IEEE802154_FCF_FRAME_PND) >> 4;
        packet->ack_request         = (fcf & IEEE802154_FCF_ACK_REQ) >> 5;
        packet->pan_id_compression  = (fcf & IEEE802154_FCF_PAN_ID_COMPRESSION) >> 6;
        /* bit 7 reserved */
        packet->seqno_suppression   = (fcf & IEEE802154_FCF_SEQNO_SUPPRESSION) >> 8;
        packet->ie_present          = (fcf & IEEE802154_FCF_IE_PRESENT) >> 9;
        packet->dst_addr_mode       = (fcf & IEEE802154_FCF_DADDR_MASK) >> 10;
        packet->version             = (fcf & IEEE802154_FCF_VERSION) >> 12;
        packet->src_addr_mode       = (fcf & IEEE802154_FCF_SADDR_MASK) >> 14;
    }

    if ((packet->version == IEEE802154_VERSION_2015) && (packet->frame_type == IEEE802154_FCF_BEACON)) {
        proto_item_append_text(tree, " Enhanced Beacon");
        col_set_str(pinfo->cinfo, COL_INFO, "Enhanced Beacon");
    }
    else {
        proto_item_append_text(tree, " %s", val_to_str_const(packet->frame_type, ieee802154_frame_types, "Reserved"));
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet->frame_type, ieee802154_frame_types, "Reserved"));
    }

    if (packet->frame_type == IEEE802154_FCF_MULTIPURPOSE) {
        if (packet->long_frame_control) {
            proto_tree_add_bitmask(tree, tvb, *offset, hf_ieee802154_fcf,
                                   ett_ieee802154_fcf, ieee802154_mpf_long_fields, ENC_LITTLE_ENDIAN);
            *offset += 2;
        }
        else {
            proto_tree_add_bitmask_len(tree, tvb, *offset, 1, hf_ieee802154_fcf,
                                       ett_ieee802154_fcf, ieee802154_mpf_short_fields,
                                       &ei_ieee802154_fcs_bitmask_len, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }
    else {
        proto_tree_add_bitmask(tree, tvb, *offset, hf_ieee802154_fcf,
                               ett_ieee802154_fcf, ieee802154_fields, ENC_LITTLE_ENDIAN);
        *offset += 2;
    }

} /* dissect_ieee802154_fcf */

void register_ieee802154_mac_key_hash_handler(guint hash_identifier, ieee802154_set_key_func key_func)
{
    /* Ensure no duplication */
    DISSECTOR_ASSERT(wmem_tree_lookup32(mac_key_hash_handlers, hash_identifier) == NULL);

    wmem_tree_insert32(mac_key_hash_handlers, hash_identifier, (void*)key_func);
}

void dissect_ieee802154_aux_sec_header_and_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, ieee802154_packet *packet, guint *offset)
{
    proto_tree *field_tree, *header_tree;
    proto_item *ti, *hidden_item;
    guint8     security_control;
    guint      aux_length = 1; /* Minimum length of the auxiliary header. */
    static int * const security_fields[] = {
            &hf_ieee802154_aux_sec_security_level,
            &hf_ieee802154_aux_sec_key_id_mode,
            &hf_ieee802154_aux_sec_frame_counter_suppression,
            &hf_ieee802154_aux_sec_asn_in_nonce,
            &hf_ieee802154_aux_sec_reserved,
            NULL
    };

    /* Parse the security control field. */
    security_control = tvb_get_guint8(tvb, *offset);
    packet->security_level = (ieee802154_security_level)(security_control & IEEE802154_AUX_SEC_LEVEL_MASK);
    packet->key_id_mode = (ieee802154_key_id_mode)((security_control & IEEE802154_AUX_KEY_ID_MODE_MASK) >> IEEE802154_AUX_KEY_ID_MODE_SHIFT);
    if (packet->version == IEEE802154_VERSION_2015) {
        packet->frame_counter_suppression = security_control & IEEE802154_AUX_FRAME_COUNTER_SUPPRESSION_MASK ? TRUE : FALSE;
    }

    /* Compute the length of the auxiliary header and create a subtree.  */
    if (!packet->frame_counter_suppression) aux_length += 4;
    if (packet->key_id_mode != KEY_ID_MODE_IMPLICIT) aux_length++;
    if (packet->key_id_mode == KEY_ID_MODE_KEY_EXPLICIT_4) aux_length += 4;
    if (packet->key_id_mode == KEY_ID_MODE_KEY_EXPLICIT_8) aux_length += 8;

    ti = proto_tree_add_item(tree, hf_ieee802154_aux_security_header, tvb, *offset, aux_length, ENC_NA);
    header_tree = proto_item_add_subtree(ti, ett_ieee802154_auxiliary_security);

    /* Security Control Field */
    proto_tree_add_bitmask(header_tree, tvb, *offset, hf_ieee802154_aux_sec_security_control, ett_ieee802154_aux_sec_control, security_fields, ENC_NA);
    (*offset)++;

    /* Frame Counter Field */
    if (!packet->frame_counter_suppression) {
        proto_tree_add_item_ret_uint(header_tree, hf_ieee802154_aux_sec_frame_counter, tvb, *offset, 4, ENC_LITTLE_ENDIAN, &packet->frame_counter);
        (*offset) += 4;
    }
    else {
        packet->asn = ieee802154_tsch_asn;
    }

    /* Key identifier field(s). */
    if (packet->key_id_mode != KEY_ID_MODE_IMPLICIT) {
        /* Create a subtree. */
        field_tree = proto_tree_add_subtree(header_tree, tvb, *offset, 1,
                ett_ieee802154_aux_sec_key_id, &ti, "Key Identifier Field"); /* Will fix length later. */
        /* Add key source, if it exists. */
        if (packet->key_id_mode == KEY_ID_MODE_KEY_EXPLICIT_4) {
            packet->key_source.addr32 = tvb_get_ntohl(tvb, *offset);
            proto_tree_add_uint64(field_tree, hf_ieee802154_aux_sec_key_source, tvb, *offset, 4, packet->key_source.addr32);
            hidden_item = proto_tree_add_item(field_tree, hf_ieee802154_aux_sec_key_source_bytes, tvb, *offset, 4, ENC_NA);
            proto_item_set_hidden(hidden_item);
            proto_item_set_len(ti, 1 + 4);
            (*offset) += 4;
        }
        if (packet->key_id_mode == KEY_ID_MODE_KEY_EXPLICIT_8) {
            packet->key_source.addr64 = tvb_get_ntoh64(tvb, *offset);
            proto_tree_add_uint64(field_tree, hf_ieee802154_aux_sec_key_source, tvb, *offset, 8, packet->key_source.addr64);
            hidden_item = proto_tree_add_item(field_tree, hf_ieee802154_aux_sec_key_source_bytes, tvb, *offset, 8, ENC_NA);
            proto_item_set_hidden(hidden_item);
            proto_item_set_len(ti, 1 + 8);
            (*offset) += 8;
        }
        /* Add key identifier. */
        packet->key_index = tvb_get_guint8(tvb, *offset);
        proto_tree_add_uint(field_tree, hf_ieee802154_aux_sec_key_index, tvb, *offset, 1, packet->key_index);
        (*offset)++;
    }
}

tvbuff_t *decrypt_ieee802154_payload(tvbuff_t * tvb, guint offset, packet_info * pinfo, proto_tree* key_tree,
                                     ieee802154_packet * packet, ieee802154_decrypt_info_t* decrypt_info,
                                     ieee802154_set_key_func set_key_func, ieee802154_decrypt_func decrypt_func)
{
    proto_item* ti;
    unsigned char key[IEEE802154_CIPHER_SIZE];
    unsigned char alt_key[IEEE802154_CIPHER_SIZE];
    tvbuff_t * payload_tvb = NULL;

    /* Lookup the key. */
    for (decrypt_info->key_number = 0; decrypt_info->key_number < num_ieee802154_keys; decrypt_info->key_number++) {
        guint nkeys = set_key_func(packet, key, alt_key, &ieee802154_keys[decrypt_info->key_number]);
        if (nkeys >= 1) {
            /* Try with the initial key */
            decrypt_info->key = key;
            payload_tvb = decrypt_func(tvb, offset, pinfo, packet, decrypt_info);
            if (!((*decrypt_info->status == DECRYPT_PACKET_MIC_CHECK_FAILED) || (*decrypt_info->status == DECRYPT_PACKET_DECRYPT_FAILED))) {
                break;
            }
        }
        if (nkeys >= 2) {
            /* Try also with the alternate key */
            decrypt_info->key = alt_key;
            payload_tvb = decrypt_func(tvb, offset, pinfo, packet, decrypt_info);
            if (!((*decrypt_info->status == DECRYPT_PACKET_MIC_CHECK_FAILED) || (*decrypt_info->status == DECRYPT_PACKET_DECRYPT_FAILED))) {
                break;
            }
        }
    }
    if (decrypt_info->key_number == num_ieee802154_keys) {
        /* None of the stored keys seemed to work */
        *decrypt_info->status = DECRYPT_PACKET_NO_KEY;
    }

    /* Store the key number used for retrieval */
    ti = proto_tree_add_uint(key_tree, hf_ieee802154_key_number, tvb, 0, 0, decrypt_info->key_number);
    proto_item_set_hidden(ti);
    return payload_tvb;
}


/**
 * Check if the CRC-OK flag in the CC24xx metadata trailer is true
 * @param tvb the IEEE 802.15.4 frame
 * @return if the flag is true
 */
static gboolean
is_cc24xx_crc_ok(tvbuff_t *tvb)
{
    return tvb_get_letohs(tvb, tvb_reported_length(tvb)-2) & IEEE802154_CC24xx_CRC_OK ? TRUE : FALSE;
}

/**
 * Verify the 16/32 bit IEEE 802.15.4 FCS
 * @param tvb the IEEE 802.15.4 frame from the FCF up to and including the FCS
 * @return if the computed FCS matches the transmitted FCS
 */
static gboolean
is_fcs_ok(tvbuff_t *tvb, guint fcs_len)
{
    if (fcs_len == 2) {
        /* The FCS is in the last two bytes of the packet. */
        guint16 fcs = tvb_get_letohs(tvb, tvb_reported_length(tvb)-2);
        guint16 fcs_calc = (guint16) ieee802154_crc_tvb(tvb, tvb_reported_length(tvb)-2);
        return fcs == fcs_calc;
    }
    else {
        /* The FCS is in the last four bytes of the packet. */
        guint32 fcs = tvb_get_letohl(tvb, tvb_reported_length(tvb)-4);
        guint32 fcs_calc = ieee802154_crc32_tvb(tvb, tvb_reported_length(tvb)-4);
        return fcs == fcs_calc;
    }
}

/**
 * Dissector for IEEE 802.15.4 packets with a PHY for which there's a
 * 4-octet preamble, a 1-octet SFD, and a 1-octet PHY header
 * with the uppermost bit reserved and the remaining 7 bits being
 * the frame length, and a 16-bit CRC value at the end.
 *
 * Currently, those are the following PHYs:
 *
 *    O-QPSK
 *    Binary phase-shift keying (BPSK)
 *    GFSK
 *    MSK
 *    RCC DSSS BPSK
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_ieee802154_nonask_phy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ieee802154_tree = NULL;
    proto_item *proto_root      = NULL;

    guint       offset          = 0;
    guint8      phr;
    tvbuff_t*   mac;

    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_ieee802154_nonask_phy, tvb, 0, tvb_captured_length(tvb), "IEEE 802.15.4 non-ASK PHY");
        ieee802154_tree = proto_item_add_subtree(proto_root, ett_ieee802154_nonask_phy);
    }

    /* Add the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 802.15.4 non-ASK PHY");

    phr = tvb_get_guint8(tvb,offset+4+1);

    if (tree) {
        guint loffset = offset;
        static int * const phr_fields[] = {
                    &hf_ieee802154_nonask_phy_length,
                    NULL
                };

        proto_tree_add_item(ieee802154_tree, hf_ieee802154_nonask_phy_preamble, tvb, loffset, 4, ENC_LITTLE_ENDIAN);
        loffset +=4 ;
        proto_tree_add_item(ieee802154_tree, hf_ieee802154_nonask_phy_sfd, tvb, loffset, 1, ENC_LITTLE_ENDIAN);
        loffset +=1 ;

        proto_tree_add_bitmask(ieee802154_tree, tvb, loffset, hf_ieee802154_nonask_phr, ett_ieee802154_nonask_phy_phr,
            phr_fields, ENC_NA);
    }

    offset += 4+2*1;
    mac = tvb_new_subset_length_caplen(tvb,offset,-1, phr & IEEE802154_PHY_LENGTH_MASK);

    /* These always have the FCS at the end. */

    /*
     * Call the common dissector; FCS length is 2, and no flags.
     */
    dissect_ieee802154_common(mac, pinfo, ieee802154_tree, 2, 0);
    return tvb_captured_length(tvb);
} /* dissect_ieee802154_nonask_phy */

/* Return the length in octets for the user configured
 * FCS/metadata following the PHY Payload */
static guint
ieee802154_fcs_type_len(guint i)
{
    guint fcs_type_lengths[] = { 2, 2, 4 };
    if (i < array_length(fcs_type_lengths)) {
        return fcs_type_lengths[i];
    }
    return 0;
}

/**
 * Dissector for IEEE 802.15.4 packet with an FCS containing a 16/32-bit
 * CRC value, or TI CC24xx metadata, at the end.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_ieee802154(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *new_tvb = dissect_zboss_specific(tvb, pinfo, tree);
    guint options = 0;
    guint fcs_len;

    /* Set the default FCS length based on the FCS type in the configuration */
    fcs_len = ieee802154_fcs_type_len(ieee802154_fcs_type);

    if (ieee802154_fcs_type == IEEE802154_CC24XX_METADATA) {
        options = DISSECT_IEEE802154_OPTION_CC24xx;
    }

    if (new_tvb != tvb) {
        /* ZBOSS traffic dump: always TI metadata trailer, always ZigBee */
        options = DISSECT_IEEE802154_OPTION_CC24xx|DISSECT_IEEE802154_OPTION_ZBOSS;
        fcs_len = 2;
    }

    /* Call the common dissector. */
    dissect_ieee802154_common(new_tvb, pinfo, tree, fcs_len, options);
    return tvb_captured_length(tvb);
} /* dissect_ieee802154 */

/**
 * Dissector for IEEE 802.15.4 packet with no FCS present.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 * @return captured length.
 */
static int
dissect_ieee802154_nofcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    /*
     * Call the common dissector; FCS length is 0, and no flags.
     */
    dissect_ieee802154_common(tvb, pinfo, tree, 0, 0);
    return tvb_captured_length(tvb);
} /* dissect_ieee802154_nofcs */

/**
 * Dissector for IEEE 802.15.4 packet dump produced by ZBOSS
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 * @return new tvb subset if this is really ZBOSS dump, else oririnal tvb.
 */
static tvbuff_t *
dissect_zboss_specific(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree *zboss_tree;
    proto_item *proto_root;
    guint off = 0;
    guint32 direction_byte, page_byte, channel;

    if (tvb_captured_length(tvb) > 5)
    {
        if (tvb_get_guint8(tvb, off++) == 'Z'
            && tvb_get_guint8(tvb, off++) == 'B'
            && tvb_get_guint8(tvb, off++) == 'O'
            && tvb_get_guint8(tvb, off++) == 'S'
            && tvb_get_guint8(tvb, off++) == 'S')
        {
            /* Create the protocol tree. */
            proto_root = proto_tree_add_protocol_format(tree, proto_zboss, tvb, 0, tvb_captured_length(tvb), "ZBOSS dump");
            zboss_tree = proto_item_add_subtree(proto_root, ett_ieee802154_zboss);

            proto_tree_add_item_ret_uint(zboss_tree, hf_zboss_direction, tvb, off, 1, ENC_NA, &direction_byte);
            proto_item_append_text(proto_root, ", %s", direction_byte ? "OUT" : "IN");

            proto_tree_add_item_ret_uint(zboss_tree, hf_zboss_page, tvb, off, 1, ENC_NA, &page_byte);
            proto_item_append_text(proto_root, ", page %u", page_byte);
            off++;

            proto_tree_add_item_ret_uint(zboss_tree, hf_zboss_channel, tvb, off, 1, ENC_NA, &channel);
            proto_item_append_text(proto_root, ", channel %u", channel);
            off++;

            proto_tree_add_item(zboss_tree, hf_zboss_trace_number, tvb, off, 4, ENC_LITTLE_ENDIAN);
            off += 4;

            return tvb_new_subset_remaining(tvb, off);
        }
    }
    return tvb;
} /* dissect_zboss_specific */

/**
 * Dissector for IEEE 802.15.4 packet with 2 bytes of ChipCon/Texas
 * Instruments compatible metadata at the end of the frame, and no FCS.
 * This is typically called by layers encapsulating an IEEE 802.15.4 packet.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_ieee802154_cc24xx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    /*
     * Call the common dissector.
     * 2 bytes of metadata at the end of the packet data.
     */
    dissect_ieee802154_common(tvb, pinfo, tree, 2, DISSECT_IEEE802154_OPTION_CC24xx);
    return tvb_captured_length(tvb);
} /* dissect_ieee802154_cc24xx */

/**
 * Dissector for IEEE 802.15.4 TAP packet
 *
 * Contains optional TLVs and encapsulates an IEEE 802.15.4 packet.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_ieee802154_tap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_tree *info_tree = NULL;
    proto_tree *header_tree = NULL;
    proto_item *proto_root = NULL;
    proto_item *ti = NULL;
    guint32     version = 0;
    guint32     length = 0;
    guint32     data_length = 0;
    tvbuff_t*   tlv_tvb;
    tvbuff_t*   payload_tvb;
    ieee802154_fcs_type_t tap_fcs_type;
    guint       fcs_len;

    /* Check the version in the TAP header */
    version = tvb_get_guint8(tvb, 0);
    if (version != 0) {
        /* Malformed packet. We do not understand any other version at this time */
        return 0;
    }

    /* Get the total length of the header and TLVs */
    length = tvb_get_letohs(tvb, 2);

    if (length > tvb_captured_length(tvb)) {
        /* Malformed packet. The TLVs exceeds our captured packet. */
        return 0;
    }

    /* Create the protocol tree */
    proto_root = proto_tree_add_protocol_format(tree, proto_ieee802154_tap, tvb, 0, length, "IEEE 802.15.4 TAP");
    info_tree = proto_item_add_subtree(proto_root, ett_ieee802154_tap);

    header_tree = proto_tree_add_subtree(info_tree, tvb, 0, 4, ett_ieee802154_tap_header, &proto_root, "Header");
    proto_tree_add_item(header_tree, hf_ieee802154_tap_version, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(header_tree, hf_ieee802154_tap_reserved, tvb, 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(header_tree, hf_ieee802154_tap_length, tvb, 2, 2, ENC_LITTLE_ENDIAN);

    /* Add the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 802.15.4 TAP");

    /* Create a new tvb subset with only the TLVs to dissect */
    tlv_tvb = tvb_new_subset_length(tvb, 4, length - 4);
    tap_fcs_type = dissect_ieee802154_tap_tlvs(tlv_tvb, pinfo, info_tree);

    /* Set the FCS length based on the FCS type */
    switch (tap_fcs_type) {

    case IEEE802154_FCS_TYPE_NONE:
        fcs_len = 0;
        break;

    case IEEE802154_FCS_TYPE_16_BIT:
        fcs_len = 2;
        break;

    case IEEE802154_FCS_TYPE_32_BIT:
        fcs_len = 4;
        break;

    default:
        /* Not valid */
        return tvb_captured_length(tvb);
    }

    /* Report the remaining bytes as the IEEE 802.15.4 Data Length */
    data_length = tvb_reported_length_remaining(tvb, length);
    ti = proto_tree_add_uint(info_tree, hf_ieee802154_tap_data_length, NULL, 0, 0, data_length);
    proto_item_set_generated(ti);

    /*
     * Call the common dissector with the real 802.15.4 data which follows the TLV header.
     * Create a separate packet bytes pane for the real data.
     * Specified FCS length, no flags.
     */
    payload_tvb = tvb_new_child_real_data(tvb, tvb_get_ptr(tvb, length, data_length), data_length, data_length);
    add_new_data_source(pinfo, payload_tvb, "IEEE 802.15.4 Data");
    dissect_ieee802154_common(payload_tvb, pinfo, tree, fcs_len, 0);

    return tvb_captured_length(tvb);
} /* dissect_ieee802154_tap */

/**
 * IEEE 802.15.4 packet dissection routine for Wireshark.
 *
 * This function extracts all the information first before displaying.
 * If payload exists, that portion will be passed into another dissector
 * for further processing.
 *
 * This is called after the individual dissect_ieee802154* functions
 * have been called to determine what sort of FCS is present, if any.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree Wireshark uses to display packet.
 * @param options bitwise or of dissector options (see DISSECT_IEEE802154_OPTION_xxx).
 */
static void
dissect_ieee802154_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint fcs_len, guint options)
{
    proto_tree *ieee802154_tree;
    ieee802154_packet *packet;
    gboolean fcs_present;
    gboolean fcs_ok;
    tvbuff_t* no_fcs_tvb;

    if (fcs_len != 0) {
        /*
         * Well, this packet should, in theory, have an FCS or CC24xx
         * metadata.
         * Do we have the entire packet, and does it have enough data for
         * the FCS/metadata?
         */
        guint reported_len = tvb_reported_length(tvb);

        if (reported_len < fcs_len) {
            /*
             * The packet is claimed not to even have enough data
             * for the FCS/metadata.  Pretend it doesn't have one.
             */
            no_fcs_tvb = tvb;
            fcs_present = FALSE;
            fcs_ok = TRUE;  // assume OK if not present
        } else {
            /*
             * The packet is claimed to have enough data for the
             * FCS/metadata.
             * Slice it off from the reported length.
             */
            reported_len -= fcs_len;
            no_fcs_tvb = tvb_new_subset_length(tvb, 0, reported_len);

            /*
             * Is the FCS/metadata present in the captured data?
             * reported_len is now the length of the packet without the
             * FCS/metadata, so the FCS/metadata begins at an offset of
             * reported_len.
             */
            if (tvb_bytes_exist(tvb, reported_len, fcs_len)) {
                /*
                 * Yes.  Check whether the FCS was OK.
                 *
                 * If we have an FCS, check it.
                 * If we have metadata, check its "FCS OK" flag.
                 */
                fcs_present = TRUE;
                fcs_ok = options & DISSECT_IEEE802154_OPTION_CC24xx ? is_cc24xx_crc_ok(tvb) : is_fcs_ok(tvb, fcs_len);
            } else {
                /*
                 * No.
                 *
                 * Either 1) this means that there was a snapshot length
                 * in effect when the capture was done, and that sliced
                 * some or all of the FCS/metadata off or 2) this is a
                 * capture with no FCS/metadata, using the same link-layer
                 * header type value as captures with the FCS/metadata,
                 * and indicating the lack of the FCS/metadata by having
                 * the captured length be the length of the packet minus
                 * the length of the FCS/metadata and the actual length
                 * being the length of the packet including the FCS/metadata,
                 * rather than by using the "no FCS" link-layer header type.
                 *
                 * We could try to distinguish between them by checking
                 * for a captured length that's exactly fcs_len bytes
                 * less than the actual length.  That would allow us to
                 * report packets that are cut short just before, or in
                 * the middle of, the FCS as having been cut short by the
                 * snapshot length.
                 *
                 * However, we can't distinguish between a packet that
                 * happened to be cut fcs_len bytes short due to a
                 * snapshot length being in effect when the capture was
                 * done and a packet that *wasn't* cut short by a snapshot
                 * length but that doesn't include the FCS/metadata.
                 * Let's hope that rarely happens.
                 */
                fcs_present = FALSE;
                fcs_ok = TRUE;  // assume OK if not present
            }
        }
    } else {
        no_fcs_tvb = tvb;
        fcs_present = FALSE;
        fcs_ok = TRUE;  // assume OK if not present
    }

    guint mhr_len = ieee802154_dissect_header(no_fcs_tvb, pinfo, tree, 0, &ieee802154_tree, &packet);
    if (!mhr_len || tvb_reported_length_remaining(no_fcs_tvb, mhr_len) < 0 ) {
        return;
    }

    if ((packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE) && (packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE)) {
        _find_or_create_conversation(pinfo, &pinfo->dl_src, &pinfo->dl_dst);
    }

    if (ieee802154_ack_tracking && (packet->ack_request || packet->frame_type == IEEE802154_FCF_ACK)) {
        guint32 key[2] = {0};

        key[0] = packet->seqno;
        if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
            key[1] = pinfo->rec->rec_header.packet_header.interface_id;
        }

        if (packet->ack_request) {
            transaction_start(pinfo, ieee802154_tree, packet, key);
        }
        else {
            transaction_end(pinfo, ieee802154_tree, packet, key);
        }
    }

    tvbuff_t* payload = ieee802154_decrypt_payload(no_fcs_tvb, mhr_len, pinfo, ieee802154_tree, packet);
    if (payload) {
        guint pie_size = ieee802154_dissect_payload_ies(payload, pinfo, ieee802154_tree, packet);
        payload = tvb_new_subset_remaining(payload, pie_size);
        if (options & DISSECT_IEEE802154_OPTION_ZBOSS && packet->frame_type == IEEE802154_FCF_DATA) {
            if ((!fcs_ok && ieee802154_fcs_ok) || !tvb_reported_length(payload)) {
                call_data_dissector(payload, pinfo, tree);
            } else {
                call_dissector_with_data(zigbee_nwk_handle, payload, pinfo, tree, packet);
            }
        } else {
            ieee802154_dissect_frame_payload(payload, pinfo, ieee802154_tree, packet, fcs_ok);
        }
    }

    if (fcs_present) {
        if (options & DISSECT_IEEE802154_OPTION_CC24xx)
            ieee802154_dissect_cc24xx_metadata(tvb, ieee802154_tree, fcs_ok);
        else
            ieee802154_dissect_fcs(tvb, ieee802154_tree, fcs_len, fcs_ok);

        /* If the CRC is invalid, make a note of it in the info column. */
        if (!fcs_ok) {
            col_append_str(pinfo->cinfo, COL_INFO, ", Bad FCS");
            proto_item_append_text(proto_tree_get_parent(ieee802154_tree), ", Bad FCS");

            /* Flag packet as having a bad crc. */
            expert_add_info(pinfo, proto_tree_get_parent(ieee802154_tree), &ei_ieee802154_fcs);
        }
    } else {
        if (ieee802154_tree) {
            /* Even if the FCS isn't present, add the fcs_ok field to the tree to
             * help with filter. Be sure not to make it visible though.
             */
            proto_item *ti = proto_tree_add_boolean_format_value(ieee802154_tree, hf_ieee802154_fcs_ok, tvb, 0, 0, fcs_ok, "Unknown");
            proto_item_set_hidden(ti);
        }
    }

    tap_queue_packet(ieee802154_tap, pinfo, NULL);
}

guint
ieee802154_dissect_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint options, proto_tree **created_header_tree, ieee802154_packet **parsed_info)
{
    proto_tree              *ieee802154_tree = NULL;
    proto_item              *proto_root = NULL;
    proto_item              *hidden_item;
    proto_item              *ti;
    guint                   offset = 0;
    ieee802154_packet      *packet = wmem_new0(pinfo->pool, ieee802154_packet);
    ieee802154_short_addr   addr16;
    ieee802154_hints_t     *ieee_hints;

    packet->short_table = ieee802154_map.short_table;

    /* Allocate frame data with hints for upper layers */
    if (!PINFO_FD_VISITED(pinfo) ||
        (ieee_hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ieee802154, 0)) == NULL) {
        ieee_hints = wmem_new0(wmem_file_scope(), ieee802154_hints_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ieee802154, 0, ieee_hints);
    }

    /* Save a pointer to the whole packet */
    ieee_hints->packet = packet;

    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_ieee802154, tvb, 0, tvb_captured_length(tvb), "IEEE 802.15.4");
        ieee802154_tree = proto_item_add_subtree(proto_root, ett_ieee802154);
    }
    /* Add the protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 802.15.4");

    /* Set out parameters */
    *created_header_tree = ieee802154_tree;
    *parsed_info = packet;

    /* Add the packet length to the filter field */
    hidden_item = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_frame_length, NULL, 0, 0, tvb_reported_length(tvb));
    proto_item_set_hidden(hidden_item);

    /* Frame Control Field */
    dissect_ieee802154_fcf(tvb, pinfo, ieee802154_tree, packet, &offset);

    /* Sequence Number */
    if (packet->seqno_suppression) {
        if (packet->version != IEEE802154_VERSION_2015 && packet->frame_type != IEEE802154_FCF_MULTIPURPOSE) {
            expert_add_info(pinfo, proto_root, &ei_ieee802154_seqno_suppression);
        }
    } else { /* IEEE 802.15.4 Sequence Number Suppression */
        packet->seqno = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_seqno, tvb, offset, 1, packet->seqno);
            /* For Ack packets display this in the root. */
            if (packet->frame_type == IEEE802154_FCF_ACK) {
                proto_item_append_text(proto_root, ", Sequence Number: %u", packet->seqno);
            }
        }
        offset += 1;
    }

    /*
     * ADDRESSING FIELDS
     */
    /* Clear out the addressing strings. */
    clear_address(&pinfo->net_dst);
    clear_address(&pinfo->dl_dst);
    clear_address(&pinfo->dst);
    clear_address(&pinfo->net_src);
    clear_address(&pinfo->dl_src);
    clear_address(&pinfo->src);

    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_RESERVED) {
        /* Invalid Destination Address Mode. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_ieee802154_dst);
        return 0;
    }

    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_RESERVED) {
        /* Invalid Source Address Mode. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_ieee802154_src);
        return 0;
    }

    if (packet->frame_type == IEEE802154_FCF_MULTIPURPOSE) {
        /* Multipurpose frames have a different set of frame versions, with 0 as the only valid version */
        if (packet->version != 0) {
            /* Unknown Frame Version for Multipurpose frames. Abort Dissection */
            expert_add_info(pinfo, proto_root, &ei_ieee802154_frame_ver);
            return 0;
        }

        /* The source PAN ID is always omitted in multipurpose frames */
        packet->src_pan_present = FALSE;

        if (packet->pan_id_present) {
            packet->dst_pan_present = TRUE;
        }
    }
    else if (packet->version == IEEE802154_VERSION_RESERVED) {
        /* Unknown Frame Version. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_ieee802154_frame_ver);
        return 0;
    }
    else if ((packet->version == IEEE802154_VERSION_2003) ||  /* For Frame Version 0b00 and */
             (packet->version == IEEE802154_VERSION_2006))  { /* 0b01 effect defined in section 7.2.1.5 */

        if ((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) && /* if both destination and source */
            (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE)) { /* addressing information is present */
            if (packet->pan_id_compression == 1) { /* PAN IDs are identical */
                packet->dst_pan_present = TRUE;
                packet->src_pan_present = FALSE; /* source PAN ID is omitted */
            }
            else { /* PAN IDs are different, both shall be included in the frame */
                packet->dst_pan_present = TRUE;
                packet->src_pan_present = TRUE;
            }
        }
        else {
            if (packet->pan_id_compression == 1) { /* all remaining cases pan_id_compression must be zero */
                expert_add_info(pinfo, proto_root, &ei_ieee802154_invalid_panid_compression);
                return 0;
            }
            else {
                /* only either the destination or the source addressing information is present */
                if ((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) &&        /*   Present   */
                    (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE)) {        /* Not Present */
                    packet->dst_pan_present = TRUE;
                    packet->src_pan_present = FALSE;
                }
                else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) &&   /* Not Present */
                         (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE)) {   /*   Present   */
                    packet->dst_pan_present = FALSE;
                    packet->src_pan_present = TRUE;
                }
                else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) &&   /* Not Present */
                         (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE)) {   /* Not Present */
                    packet->dst_pan_present = FALSE;
                    packet->src_pan_present = FALSE;
                }
                else {
                    expert_add_info(pinfo, proto_root, &ei_ieee802154_invalid_addressing);
                    return 0;
                }
            }
        }
    }
    else if (packet->version == IEEE802154_VERSION_2015) {
        /* for Frame Version 0b10 PAN Id Compression only applies to these frame types */
        if ((packet->frame_type == IEEE802154_FCF_BEACON) ||
            (packet->frame_type == IEEE802154_FCF_DATA)   ||
            (packet->frame_type == IEEE802154_FCF_ACK)    ||
            (packet->frame_type == IEEE802154_FCF_CMD)       ) {

            /* Implements Table 7-6 of IEEE 802.15.4-2015
             *
             *      Destination Address  Source Address  Destination PAN ID  Source PAN ID   PAN ID Compression
             *-------------------------------------------------------------------------------------------------
             *  1.  Not Present          Not Present     Not Present         Not Present     0
             *  2.  Not Present          Not Present     Present             Not Present     1
             *  3.  Present              Not Present     Present             Not Present     0
             *  4.  Present              Not Present     Not Present         Not Present     1
             *
             *  5.  Not Present          Present         Not Present         Present         0
             *  6.  Not Present          Present         Not Present         Not Present     1
             *
             *  7.  Extended             Extended        Present             Not Present     0
             *  8.  Extended             Extended        Not Present         Not Present     1
             *
             *  9.  Short                Short           Present             Present         0
             * 10.  Short                Extended        Present             Present         0
             * 11.  Extended             Short           Present             Present         0
             *
             * 12.  Short                Extended        Present             Not Present     1
             * 13.  Extended             Short           Present             Not Present     1
             * 14.  Short                Short           Present             Not Present     1
             */

            /* Row 1 */
            if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) &&      /* Not Present */
                (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) &&      /* Not Present */
                (packet->pan_id_compression == 0)) {
                        packet->dst_pan_present = FALSE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 2 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->pan_id_compression == 1)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 3 */
            else if ((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->pan_id_compression == 0)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 4 */
            else if ((packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->pan_id_compression == 1)) {
                        packet->dst_pan_present = FALSE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 5 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->pan_id_compression == 0)) {
                        packet->dst_pan_present = FALSE;
                        packet->src_pan_present = TRUE;
            }
            /* Row 6 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) && /* Not Present */
                     (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE) && /*  Present    */
                     (packet->pan_id_compression == 1)) {
                        packet->dst_pan_present = FALSE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 7 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->pan_id_compression == 0)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 8 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) && /*  Extended    */
                     (packet->pan_id_compression == 1)) {
                        packet->dst_pan_present = FALSE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 9 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) && /*  Short     */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) && /*  Short     */
                     (packet->pan_id_compression == 0)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = (ieee802154e_compatibility ? FALSE : TRUE);
            }
            /* Row 10 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) && /*  Short    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&   /*  Extended */
                     (packet->pan_id_compression == 0)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = (ieee802154e_compatibility ? FALSE : TRUE);
            }
            /* Row 11 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)   &&   /*  Extended */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->pan_id_compression == 0)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = (ieee802154e_compatibility ? FALSE : TRUE);
            }
            /* Row 12 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)   &&   /*  Extended */
                     (packet->pan_id_compression == 1)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 13 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)   &&   /*  Extended */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->pan_id_compression == 1)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = FALSE;
            }
            /* Row 14 */
            else if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&   /*  Short    */
                     (packet->pan_id_compression == 1)) {
                        packet->dst_pan_present = TRUE;
                        packet->src_pan_present = FALSE;
            }
            else {
                expert_add_info(pinfo, proto_root, &ei_ieee802154_invalid_panid_compression2);
                return 0;
            }
        }
        else { /* Frame Type is neither Beacon, Data, Ack, nor Command: PAN ID Compression is not used */
            packet->dst_pan_present = FALSE; /* no PAN ID will */
            packet->src_pan_present = FALSE; /* be present     */
        }
    }
    else {
        /* Unknown Frame Version. Abort Dissection. */
        expert_add_info(pinfo, proto_root, &ei_ieee802154_frame_ver);
        return 0;
    }

    /*
     * Addressing Fields
     */

    /* Destination PAN Id */
    if (packet->dst_pan_present) {
        packet->dst_pan = tvb_get_letohs(tvb, offset);
        if (ieee802154_tree) {
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_dst_panID, tvb, offset, 2, packet->dst_pan);
        }
        offset += 2;
    }

    /* Destination Address  */
    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        gchar* dst_addr;

        /* Get the address. */
        packet->dst16 = tvb_get_letohs(tvb, offset);

        /* Provide address hints to higher layers that need it. */
        if (ieee_hints) {
            ieee_hints->dst16 = packet->dst16;
        }

        set_address_tvb(&pinfo->dl_dst, ieee802_15_4_short_address_type, 2, tvb, offset);
        copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
        dst_addr = address_to_str(pinfo->pool, &pinfo->dst);

        proto_tree_add_uint(ieee802154_tree, hf_ieee802154_dst16, tvb, offset, 2, packet->dst16);
        proto_item_append_text(proto_root, ", Dst: %s", dst_addr);
        ti = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_addr16, tvb, offset, 2, packet->dst16);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", dst_addr);
        offset += 2;
    }
    else if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64 *p_addr = (guint64 *)wmem_new(pinfo->pool, guint64);

        /* Get the address */
        packet->dst64 = tvb_get_letoh64(tvb, offset);

        /* Copy and convert the address to network byte order. */
        *p_addr = pntoh64(&(packet->dst64));

        /* Display the destination address. */
        /* XXX - OUI resolution doesn't happen when displaying resolved
         * EUI64 addresses; that should probably be fixed in
         * epan/addr_resolv.c.
         */
        set_address(&pinfo->dl_dst, AT_EUI64, 8, p_addr);
        copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
        if (tree) {
            proto_tree_add_item(ieee802154_tree, hf_ieee802154_dst64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(proto_root, ", Dst: %s", eui64_to_display(pinfo->pool, packet->dst64));
            ti = proto_tree_add_item(ieee802154_tree, hf_ieee802154_addr64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(ti);
            proto_item_set_hidden(ti);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", eui64_to_display(pinfo->pool, packet->dst64));
        offset += 8;
    }

    /* Source PAN Id */
    if (packet->src_pan_present) {
        packet->src_pan = tvb_get_letohs(tvb, offset);
        proto_tree_add_uint(ieee802154_tree, hf_ieee802154_src_panID, tvb, offset, 2, packet->src_pan);
        offset += 2;
    }
    else {
        if (packet->dst_pan_present) {
            packet->src_pan = packet->dst_pan;
        }
        else {
            packet->src_pan = IEEE802154_BCAST_PAN;
        }
    }
    if (ieee_hints) {
        ieee_hints->src_pan = packet->src_pan;
    }

    /* Source Address */
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        gchar* src_addr;

        /* Get the address. */
        packet->src16 = tvb_get_letohs(tvb, offset);

        if (!PINFO_FD_VISITED(pinfo)) {
            /* If we know our extended source address from previous packets,
                * provide a pointer to it in a hint for upper layers */
            addr16.addr = packet->src16;
            addr16.pan = packet->src_pan;

            if (ieee_hints) {
                ieee_hints->src16 = packet->src16;
                ieee_hints->map_rec = (ieee802154_map_rec *)
                    g_hash_table_lookup(ieee802154_map.short_table, &addr16);
            }
        }

        set_address_tvb(&pinfo->dl_src, ieee802_15_4_short_address_type, 2, tvb, offset);
        copy_address_shallow(&pinfo->src, &pinfo->dl_src);
        src_addr = address_to_str(pinfo->pool, &pinfo->src);

        /* Add the addressing info to the tree. */
        if (tree) {
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_src16, tvb, offset, 2, packet->src16);
            proto_item_append_text(proto_root, ", Src: %s", src_addr);
            ti = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_addr16, tvb, offset, 2, packet->src16);
            proto_item_set_generated(ti);
            proto_item_set_hidden(ti);

            if (ieee_hints && ieee_hints->map_rec) {
                /* Display inferred source address info */
                ti = proto_tree_add_eui64(ieee802154_tree, hf_ieee802154_src64, tvb, offset, 0,
                        ieee_hints->map_rec->addr64);
                proto_item_set_generated(ti);
                ti = proto_tree_add_eui64(ieee802154_tree, hf_ieee802154_addr64, tvb, offset, 0, ieee_hints->map_rec->addr64);
                proto_item_set_generated(ti);
                proto_item_set_hidden(ti);

                if ( ieee_hints->map_rec->start_fnum ) {
                    ti = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_src64_origin, tvb, 0, 0,
                        ieee_hints->map_rec->start_fnum);
                }
                else {
                    ti = proto_tree_add_uint_format_value(ieee802154_tree, hf_ieee802154_src64_origin, tvb, 0, 0,
                        ieee_hints->map_rec->start_fnum, "Pre-configured");
                }
                proto_item_set_generated(ti);
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", src_addr);

        offset += 2;
    }
    else if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64 *p_addr = (guint64 *)wmem_new(pinfo->pool, guint64);

        /* Get the address. */
        packet->src64 = tvb_get_letoh64(tvb, offset);

        /* Copy and convert the address to network byte order. */
        *p_addr = pntoh64(&(packet->src64));

        /* Display the source address. */
        /* XXX - OUI resolution doesn't happen when displaying resolved
         * EUI64 addresses; that should probably be fixed in
         * epan/addr_resolv.c.
         */
        set_address(&pinfo->dl_src, AT_EUI64, 8, p_addr);
        copy_address_shallow(&pinfo->src, &pinfo->dl_src);
        if (tree) {
            proto_tree_add_item(ieee802154_tree, hf_ieee802154_src64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(proto_root, ", Src: %s", eui64_to_display(pinfo->pool, packet->src64));
            ti = proto_tree_add_item(ieee802154_tree, hf_ieee802154_addr64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(ti);
            proto_item_set_hidden(ti);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", eui64_to_display(pinfo->pool, packet->src64));
        offset += 8;
    }

    /* Existence of the Auxiliary Security Header is controlled by the Security Enabled Field */
    if ((packet->security_enable) && (packet->version != IEEE802154_VERSION_2003) && !(options & IEEE802154_DISSECT_HEADER_OPTION_NO_AUX_SEC_HDR)) {
        dissect_ieee802154_aux_sec_header_and_key(tvb, pinfo, ieee802154_tree, packet, &offset);
    }

    /*
     * NONPAYLOAD FIELDS
     *
     */
    /* All of the beacon fields, except the beacon payload are considered nonpayload. */
    if (((packet->version == IEEE802154_VERSION_2003) || (packet->version == IEEE802154_VERSION_2006)) && (packet->frame_type != IEEE802154_FCF_MULTIPURPOSE)) {
        if (packet->frame_type == IEEE802154_FCF_BEACON) { /* Regular Beacon. Some are not present in frame version (Enhanced) Beacons */
            dissect_ieee802154_superframe(tvb, pinfo, ieee802154_tree, &offset); /* superframe spec */
            dissect_ieee802154_gtsinfo(tvb, pinfo, ieee802154_tree, &offset);    /* GTS information fields */
            dissect_ieee802154_pendaddr(tvb, pinfo, ieee802154_tree, &offset);   /* Pending address list */
        }

        if (packet->frame_type == IEEE802154_FCF_CMD) {
            /**
             * In IEEE802.15.4-2003 and 2006 the command identifier is considered to be part of the header
             * and is thus not encrypted. For IEEE802.15.4-2012e and later the command id is considered to be
             * part of the payload, is encrypted, and follows the payload IEs. Thus we only parse the command id
             * here for 2006 and earlier frames. */
            packet->command_id = tvb_get_guint8(tvb, offset);
            if (tree) {
                proto_tree_add_uint(ieee802154_tree, hf_ieee802154_cmd_id, tvb, offset, 1, packet->command_id);
            }
            offset++;

            /* Display the command identifier in the info column. */
            col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet->command_id, ieee802154_cmd_names, "Unknown Command"));
        }
    }
    else {
        if (packet->ie_present) {
            offset += dissect_ieee802154_header_ie(tvb, pinfo, ieee802154_tree, offset, packet);
        }
    }

    /* IEEE 802.15.4-2003 may have security information pre-pended to payload */
    if (packet->security_enable && (packet->version == IEEE802154_VERSION_2003)) {
        /* Store security suite preference in the 2006 security level identifier to simplify 2003 integration! */
        packet->security_level = (ieee802154_security_level)ieee802154_sec_suite;

        /* Frame Counter and Key Sequence Counter prepended to the payload of an encrypted frame */
        if (IEEE802154_IS_ENCRYPTED(packet->security_level)) {
            packet->frame_counter = tvb_get_letohl (tvb, offset);
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_sec_frame_counter, tvb, offset, (int)sizeof(guint32), packet->frame_counter);
            offset += (int)sizeof(guint32);

            packet->key_sequence_counter = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_sec_key_sequence_counter, tvb, offset, (int)sizeof(guint8), packet->key_sequence_counter);
            offset += (int)sizeof(guint8);
        }
    }

    return offset;
}

/*
 * XXX - "mhr_len" is really a general offset; this is used elsewhere.
 */
tvbuff_t*
ieee802154_decrypt_payload(tvbuff_t *tvb, guint mhr_len, packet_info *pinfo, proto_tree *ieee802154_tree, ieee802154_packet *packet)
{
    proto_item *proto_root = proto_tree_get_parent(ieee802154_tree);
    proto_tree *tree = proto_tree_get_parent_tree(ieee802154_tree);
    unsigned char rx_mic[IEEE802154_CIPHER_SIZE];
    guint rx_mic_len = IEEE802154_MIC_LENGTH(packet->security_level);
    ieee802154_decrypt_status status = DECRYPT_NOT_ENCRYPTED;
    tvbuff_t *payload_tvb;

    /* Encrypted Payload. */
    if (packet->security_enable) {
        ieee802154_decrypt_info_t decrypt_info;

        decrypt_info.rx_mic = rx_mic;
        decrypt_info.rx_mic_length = &rx_mic_len;
        decrypt_info.status = &status;
        decrypt_info.key = NULL; /* payload function will fill that in */

        /* call with NULL tree since we add the key_number below without hiding it */
        payload_tvb = decrypt_ieee802154_payload(tvb, mhr_len, pinfo, NULL, packet, &decrypt_info,
                                     ieee802154_set_mac_key, dissect_ieee802154_decrypt);

        /* Get the unencrypted data if decryption failed.  */
        if (!payload_tvb) {
            /* Deal with possible truncation and the MIC field at the end. */
            gint reported_len = tvb_reported_length(tvb)-mhr_len-rx_mic_len;
            payload_tvb = tvb_new_subset_length(tvb, mhr_len, reported_len);
        }

        /* Display the MIC. */
        if (rx_mic_len) {
            if (tvb_bytes_exist(tvb, tvb_reported_length(tvb) - rx_mic_len, rx_mic_len)) {
                proto_tree_add_item(ieee802154_tree, hf_ieee802154_mic, tvb, tvb_reported_length(tvb)-rx_mic_len, rx_mic_len, ENC_NA);
            }
        }

        /* Display the reason for failure, and abort if the error was fatal. */
        switch (status) {
        case DECRYPT_PACKET_SUCCEEDED:
        {
            proto_item *pi = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_key_number, tvb, 0, 0, decrypt_info.key_number);
            proto_item_set_generated(pi);
            break;
        }
        case DECRYPT_NOT_ENCRYPTED:
            break;  // nothing to do

        case DECRYPT_FRAME_COUNTER_SUPPRESSION_UNSUPPORTED:
            expert_add_info_format(pinfo, proto_root, &ei_ieee802154_decrypt_error, "Decryption of 802.15.4-2015 with frame counter suppression is not supported");
            call_data_dissector(payload_tvb, pinfo, tree);
            return NULL;

        case DECRYPT_PACKET_TOO_SMALL:
            expert_add_info_format(pinfo, proto_root, &ei_ieee802154_decrypt_error, "Packet was too small to include the CRC and MIC");
            call_data_dissector(payload_tvb, pinfo, tree);
            return NULL;

        case DECRYPT_PACKET_NO_EXT_SRC_ADDR:
            expert_add_info_format(pinfo, proto_root, &ei_ieee802154_decrypt_error, "No extended source address - can't decrypt");
            call_data_dissector(payload_tvb, pinfo, tree);
            return NULL;

        case DECRYPT_PACKET_NO_KEY:
            expert_add_info_format(pinfo, proto_root, &ei_ieee802154_decrypt_error, "No encryption key set - can't decrypt");
            call_data_dissector(payload_tvb, pinfo, tree);
            return NULL;

        case DECRYPT_PACKET_DECRYPT_FAILED:
            expert_add_info_format(pinfo, proto_root, &ei_ieee802154_decrypt_error, "Decrypt failed");
            call_data_dissector(payload_tvb, pinfo, tree);
            return NULL;

        case DECRYPT_PACKET_MIC_CHECK_FAILED:
            expert_add_info_format(pinfo, proto_root, &ei_ieee802154_decrypt_error, "MIC check failed");
            /*
             * Abort only if the payload was encrypted, in which case we
             * probably didn't decrypt the packet right (eg: wrong key).
             */
            if (IEEE802154_IS_ENCRYPTED(packet->security_level)) {
                call_data_dissector(payload_tvb, pinfo, tree);
                return NULL;
            }
            break;
        }
    }
    /* Plaintext Payload. */
    else {
        /* Deal with possible truncation. */
        gint reported_len = tvb_reported_length(tvb)-mhr_len;
        payload_tvb = tvb_new_subset_length(tvb, mhr_len, reported_len);
    }

    return payload_tvb;
}


guint ieee802154_dissect_payload_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ieee802154_tree, ieee802154_packet *packet)
{
    /* Presence of Payload IEs is defined by the termination of the Header IEs */
    if (packet->payload_ie_present) {
        if (tvb_reported_length(tvb) > 2) {
            return (guint) dissect_ieee802154_payload_ie(tvb, pinfo, ieee802154_tree, 0, packet);
        } else {
            expert_add_info(pinfo, proto_tree_get_parent(ieee802154_tree), &ei_ieee802154_missing_payload_ie);
        }
    }
    return 0;
}


guint ieee802154_dissect_frame_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ieee802154_tree, ieee802154_packet *packet, gboolean fcs_ok)
{
    tvbuff_t *payload_tvb = tvb;
    proto_tree *tree = proto_tree_get_parent_tree(ieee802154_tree);
    heur_dtbl_entry_t *hdtbl_entry;

    /* There are commands without payload */
    if (tvb_captured_length(payload_tvb) > 0 || packet->frame_type == IEEE802154_FCF_CMD) {
        /*
         * Wrap the sub-dissection in a try/catch block in case the payload is
         * broken. First we store the current protocol so we can fix it if an
         * exception is thrown by the subdissectors.
         */
        const char* saved_proto = pinfo->current_proto;
        /* Try to dissect the payload. */
        TRY {
            switch (packet->frame_type) {
            case IEEE802154_FCF_BEACON:
                if (!dissector_try_heuristic(ieee802154_beacon_subdissector_list, payload_tvb, pinfo, tree, &hdtbl_entry, packet)) {
                    /* Could not subdissect, call the data dissector instead. */
                    call_data_dissector(payload_tvb, pinfo, tree);
                }
                break;

            case IEEE802154_FCF_CMD:
                dissect_ieee802154_command(payload_tvb, pinfo, ieee802154_tree, packet);
                break;

            case IEEE802154_FCF_DATA:
                /* Sanity-check. */
                if ((!fcs_ok && ieee802154_fcs_ok) || !tvb_reported_length(payload_tvb)) {
                    call_data_dissector(payload_tvb, pinfo, tree);
                    break;
                }
                /* Try the PANID dissector table for stateful dissection. */
                if (dissector_try_uint_new(panid_dissector_table, packet->src_pan, payload_tvb, pinfo, tree, TRUE, packet)) {
                    break;
                }
                /* Try again with the destination PANID (if different) */
                if (((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) ||
                     (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)) &&
                        (packet->dst_pan != packet->src_pan) &&
                        dissector_try_uint_new(panid_dissector_table, packet->src_pan, payload_tvb, pinfo, tree, TRUE, packet)) {
                    break;
                }
                /* Try heuristic dissection. */
                if (dissector_try_heuristic(ieee802154_heur_subdissector_list, payload_tvb, pinfo, tree, &hdtbl_entry, packet)) break;
                /* Fall-through to dump undissectable payloads. */
                /* FALL THROUGH */
            default:
                /* Could not subdissect, call the data dissector instead. */
                call_data_dissector(payload_tvb, pinfo, tree);
            } /* switch */
        }
        CATCH_ALL {
            /*
             * Someone encountered an error while dissecting the payload. But
             * we haven't yet finished processing all of our layer. Catch and
             * display the exception, then fall-through to finish displaying
             * the FCS (which we display last so the frame is ordered correctly
             * in the tree).
             */
            show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
            pinfo->current_proto = saved_proto;
        }
        ENDTRY;
    }
    return tvb_captured_length(tvb);
}

/**
 * Dissect the FCS at the end of the frame.
 * That is only displayed if the included length of the tvb encompasses it.
 *
 * @param tvb the 802.15.4 frame tvb
 * @param ieee802154_tree the 802.15.4 protocol tree
 * @param fcs_len length of the FCS field
 * @param fcs_ok set to FALSE to indicate FCS verification failed
 */
static void
ieee802154_dissect_fcs(tvbuff_t *tvb, proto_tree *ieee802154_tree, guint fcs_len, gboolean fcs_ok)
{
    proto_item *ti;
    /* The FCS should be the last bytes of the reported packet. */
    guint offset = tvb_reported_length(tvb)-fcs_len;
    /* Dissect the FCS only if it exists (captures which don't or can't get the
     * FCS will simply truncate the packet to omit it, but should still set the
     * reported length to cover the original packet length), so if the snapshot
     * is too short for an FCS don't make a fuss.
     */
    if (ieee802154_tree) {
        if (fcs_len == 2) {
            guint16     fcs = tvb_get_letohs(tvb, offset);

            ti = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_fcs, tvb, offset, 2, fcs);
            if (fcs_ok) {
                proto_item_append_text(ti, " (Correct)");
            }
            else {
                proto_item_append_text(ti, " (Incorrect, expected FCS=0x%04x)", ieee802154_crc_tvb(tvb, offset));
            }
            /* To Help with filtering, add the fcs_ok field to the tree.  */
            ti = proto_tree_add_boolean(ieee802154_tree, hf_ieee802154_fcs_ok, tvb, offset, 2, (guint32) fcs_ok);
            proto_item_set_hidden(ti);
        }
        else {
            guint32 fcs = tvb_get_letohl(tvb, offset);

            ti = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_fcs32, tvb, offset, 4, fcs);
            if (fcs_ok) {
                proto_item_append_text(ti, " (Correct)");
            }
            else {
                proto_item_append_text(ti, " (Incorrect, expected FCS=0x%08x)", ieee802154_crc32_tvb(tvb, offset));
            }
            /* To Help with filtering, add the fcs_ok field to the tree.  */
            ti = proto_tree_add_boolean(ieee802154_tree, hf_ieee802154_fcs_ok, tvb, offset, 2, (guint32) fcs_ok);
            proto_item_set_hidden(ti);
        }
    }
} /* ieee802154_dissect_fcs */

/**
 * Dissect the TI CC24xx metadata at the end of the frame.
 * That is only displayed if the included length of the tvb encompasses it.
 *
 * @param tvb the 802.15.4 frame tvb
 * @param ieee802154_tree the 802.15.4 protocol tree
 * @param fcs_ok set to FALSE to indicate FCS verification failed
 */
static void
ieee802154_dissect_cc24xx_metadata(tvbuff_t *tvb, proto_tree *ieee802154_tree, gboolean fcs_ok)
{
    /* The metadata should be the last 2 bytes of the reported packet. */
    guint offset = tvb_reported_length(tvb)-2;
    /* Dissect the metadata only if it exists (captures which don't or can't get the
     * metadata will simply truncate the packet to omit it, but should still set the
     * reported length to cover the original packet length), so if the snapshot
     * is too short for the metadata don't make a fuss.
     */
    if (ieee802154_tree) {
        proto_tree  *field_tree;
        guint16     metadata = tvb_get_letohs(tvb, offset);

        /* Create a subtree for the metadata. */
        field_tree = proto_tree_add_subtree_format(ieee802154_tree, tvb, offset, 2, ett_ieee802154_fcs, NULL,
                     "TI CC24xx-format metadata: FCS %s", (fcs_ok) ? "OK" : "Bad");
        /* Display metadata contents.  */
        proto_tree_add_boolean(field_tree, hf_ieee802154_fcs_ok, tvb, offset, 1, (guint32) (metadata & IEEE802154_CC24xx_CRC_OK));
        proto_tree_add_int(field_tree, hf_ieee802154_rssi, tvb, offset++, 1, (gint8) (metadata & IEEE802154_CC24xx_RSSI));
        proto_tree_add_uint(field_tree, hf_ieee802154_correlation, tvb, offset, 1, (guint8) ((metadata & IEEE802154_CC24xx_CORRELATION) >> 8));
    }
} /* ieee802154_dissect_cc24xx_metadata */

static void
dissect_ieee802154_tap_sun_phy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint length)
{
    (void) pinfo;
    if (length == 3) {
        guint32 band;
        guint32 sun_type;
        guint32 mode;
        proto_tree_add_item_ret_uint(tree, hf_ieee802154_sun_band, tvb, offset, 1, ENC_LITTLE_ENDIAN, &band);
        proto_item_append_text(proto_tree_get_parent(tree), ": Band: %s (%u)", val_to_str_const(band, sun_bands, "Unknown"), band);
        proto_tree_add_item_ret_uint(tree, hf_ieee802154_sun_type, tvb, offset+1, 1, ENC_LITTLE_ENDIAN, &sun_type);
        if (sun_type < array_length(sun_types)) {
            proto_item_append_text(proto_tree_get_parent(tree), ", Type: %s (%u)", val_to_str_const(sun_type, sun_types, "Unknown"), sun_type);
        }

        switch (sun_type) {
            case IEEE802154_SUN_TYPE_FSK_A:
                proto_tree_add_item_ret_uint(tree, hf_ieee802154_mode_fsk_a, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &mode);
                proto_item_append_text(proto_tree_get_parent(tree), ", Mode: %u", mode);
                break;
            case IEEE802154_SUN_TYPE_FSK_B:
                proto_tree_add_item_ret_uint(tree, hf_ieee802154_mode_fsk_b, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &mode);
                proto_item_append_text(proto_tree_get_parent(tree), ", Mode: %u", mode);
                break;
            case IEEE802154_SUN_TYPE_OQPSK_A:
                proto_tree_add_item_ret_uint(tree, hf_ieee802154_mode_oqpsk_a, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &mode);
                proto_item_append_text(proto_tree_get_parent(tree), ", Mode: %u", mode);
                break;
            case IEEE802154_SUN_TYPE_OQPSK_B:
                proto_tree_add_item_ret_uint(tree, hf_ieee802154_mode_oqpsk_b, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &mode);
                proto_item_append_text(proto_tree_get_parent(tree), ", Mode: %u", mode);
                break;
            case IEEE802154_SUN_TYPE_OQPSK_C:
                proto_tree_add_item_ret_uint(tree, hf_ieee802154_mode_oqpsk_c, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &mode);
                proto_item_append_text(proto_tree_get_parent(tree), ", Mode: %u", mode);
                break;
            case IEEE802154_SUN_TYPE_OFDM_OPT1:
            case IEEE802154_SUN_TYPE_OFDM_OPT2:
            case IEEE802154_SUN_TYPE_OFDM_OPT3:
            case IEEE802154_SUN_TYPE_OFDM_OPT4:
                proto_tree_add_item_ret_uint(tree, hf_ieee802154_mode_ofdm, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &mode);
                proto_item_append_text(proto_tree_get_parent(tree), ", Mode: %u", mode);
                break;
            default:
                proto_tree_add_item(tree, hf_ieee802154_sun_mode, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
                break;
        } /* switch (sun_type) */
    }
} /* dissect_ieee802154_tap_sun_phy */

/**
 * Create a tree for a TAP TLV
 *
 * @param tree the tree to append this item to
 * @param tvb the tv buffer
 * @param offset offset into the tvbuff to begin dissection
 * @param type TLV type
 * @param length TLV length
 * @returns the tree created for the Payload IE
 */
static proto_tree*
ieee802154_create_tap_tlv_tree(proto_tree *tree, tvbuff_t *tvb, gint offset, guint32 *type, guint32 *length)
{
    proto_tree *subtree = NULL;
    proto_item *ti = NULL;
    guint32 subtree_length;

    *length = tvb_get_letohs(tvb, offset+2);

    subtree_length = 4 + *length;
    if (*length % 4) {
        subtree_length += (4 - *length % 4);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, subtree_length, ett_ieee802154_tap_tlv, &ti, "");

    /* Check if we have a valid TLV */
    proto_tree_add_item_ret_uint(subtree, hf_ieee802154_tap_tlv_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, type);
    if (*type < array_length(tap_tlv_types)) {
        proto_item_append_text(ti, "%s", val_to_str_const(*type, tap_tlv_types, "Unknown"));
    }
    else {
        expert_add_info(NULL, ti, &ei_ieee802154_tap_tlv_invalid_type);
    }

    proto_tree_add_item(subtree, hf_ieee802154_tap_tlv_length, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
    if (!tvb_bytes_exist(tvb, offset+4, *length)) {
        expert_add_info(NULL, ti, &ei_ieee802154_tap_tlv_invalid_length);
    }
    return subtree;
} /* ieee802154_create_tap_tlv_tree */

static ieee802154_fcs_type_t
dissect_ieee802154_tap_tlvs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint32 type;
    guint32 length;
    gint offset = 0;
    proto_item *ti;
    proto_tree *tlvtree;
    guint32 tap_fcs_type;
    const char *type_str;
    nstime_t nstime;
    guint64 frame_start_ts = 0;
    guint64 frame_end_ts = 0;
    guint64 slot_start_ts = 0;
    double delta_us = 0;
    guint32 timeslot_length = 0;

    /* Default the FCS type to NONE when parsing TAP packets */
    tap_fcs_type = IEEE802154_FCS_TYPE_NONE;

    while (tvb_bytes_exist(tvb, offset, 4)) {
        tlvtree = ieee802154_create_tap_tlv_tree(tree, tvb, offset, &type, &length);
        offset += 4;

        switch (type) {
            case IEEE802154_TAP_FCS_TYPE:
                ti = proto_tree_add_item_ret_uint(tlvtree, hf_ieee802154_tap_fcs_type, tvb, offset, 1,
                                                  ENC_LITTLE_ENDIAN, &tap_fcs_type);
                type_str = try_val_to_str(tap_fcs_type, tap_fcs_type_names);
                if (type_str == NULL) {
                    /* Invalid - flag it as such */
                    expert_add_info(NULL, ti, &ei_ieee802154_tap_tlv_invalid_fcs_type);

                    /* Use "Unknown" for the parent */
                    type_str = "Unknown";
                }
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %s (%u)",
                                       type_str, tap_fcs_type);
                break;
            case IEEE802154_TAP_RSS: {
                gfloat rss = tvb_get_ieee_float(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_float_format_value(tlvtree, hf_ieee802154_tap_rss, tvb, offset, 4, rss, "%.2f dBm", rss);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %.2f dBm", rss);
                break;
            }
            case IEEE802154_TAP_BIT_RATE: {
                guint32 bitrate;
                proto_tree_add_item_ret_uint(tlvtree, hf_ieee802154_bit_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN, &bitrate);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %.3f kbps", bitrate/1000.0);
                break;
            }
            case IEEE802154_TAP_CHANNEL_ASSIGNMENT: {
                guint32 channel;
                guint32 page;
                proto_tree_add_item_ret_uint(tlvtree, hf_ieee802154_ch_num, tvb, offset, 2, ENC_LITTLE_ENDIAN, &channel);
                proto_tree_add_item_ret_uint(tlvtree, hf_ieee802154_ch_page, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &page);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": Page: %s (%u), Number: %u", val_to_str_const(page, channel_page_names, "Unknown"), page, channel);
                break;
            }
            case IEEE802154_TAP_SUN_PHY_INFO:
                dissect_ieee802154_tap_sun_phy(tvb, pinfo, tlvtree, offset, length);
                break;
            case IEEE802154_TAP_START_OF_FRAME_TS:
                proto_tree_add_item_ret_uint64(tlvtree, hf_ieee802154_sof_ts, tvb, offset, 8,
                                               ENC_LITTLE_ENDIAN, &frame_start_ts);
                nstime.secs = (time_t)frame_start_ts / 1000000000L;
                nstime.nsecs = frame_start_ts % 1000000000UL;
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %s s", rel_time_to_secs_str(pinfo->pool, &nstime));
                break;
            case IEEE802154_TAP_END_OF_FRAME_TS:
                proto_tree_add_item_ret_uint64(tlvtree, hf_ieee802154_eof_ts, tvb, offset, 8,
                                    ENC_LITTLE_ENDIAN, &frame_end_ts);
                nstime.secs = (time_t)frame_end_ts / 1000000000L;
                nstime.nsecs = frame_end_ts % 1000000000UL;
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %s s", rel_time_to_secs_str(pinfo->pool, &nstime));
                break;
            case IEEE802154_TAP_ASN:
                proto_tree_add_item_ret_uint64(tlvtree, hf_ieee802154_asn, tvb, offset, 8, ENC_LITTLE_ENDIAN, &ieee802154_tsch_asn);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %"PRIu64, ieee802154_tsch_asn);
                break;
            case IEEE802154_TAP_SLOT_START_TS:
                proto_tree_add_item_ret_uint64(tlvtree, hf_ieee802154_slot_start_ts, tvb, offset, 8,
                                    ENC_LITTLE_ENDIAN, &slot_start_ts);
                nstime.secs = (time_t)slot_start_ts / 1000000000L;
                nstime.nsecs = slot_start_ts % 1000000000UL;
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %s s", rel_time_to_secs_str(pinfo->pool, &nstime));
                break;
            case IEEE802154_TAP_TIMESLOT_LENGTH:
                proto_tree_add_item_ret_uint(tlvtree, hf_ieee802154_tap_timeslot_length, tvb, offset, 4,
                                             ENC_LITTLE_ENDIAN, &timeslot_length);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %"PRIu32" %s", timeslot_length, units_microseconds.singular);
                break;
            case IEEE802154_TAP_LQI: {
                guint32 lqi;
                proto_tree_add_item_ret_uint(tlvtree, hf_ieee802154_tap_lqi, tvb, offset, 1, ENC_LITTLE_ENDIAN, &lqi);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %u", lqi);
                break;
            }
            case IEEE802154_TAP_CHANNEL_FREQUENCY: {
                gfloat freq = tvb_get_ieee_float(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_float_format_value(tlvtree, hf_ieee802154_ch_freq, tvb, offset, 4, freq, "%.3f kHz", freq);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": %.3f kHz", freq);
                break;
            }
            case IEEE802154_TAP_CHANNEL_PLAN: {
                guint32 count;
                gfloat ch0_freq = tvb_get_ieee_float(tvb, offset, ENC_LITTLE_ENDIAN);
                gfloat spacing = tvb_get_ieee_float(tvb, offset+4, ENC_LITTLE_ENDIAN);
                proto_tree_add_float_format_value(tlvtree, hf_ieee802154_chplan_start, tvb, offset, 4, ch0_freq, "%.3f kHz", ch0_freq);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ": Start %.3f kHz", ch0_freq);
                proto_tree_add_float_format_value(tlvtree, hf_ieee802154_chplan_spacing, tvb, offset+4, 4, spacing, "%.3f kHz", spacing);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ", Spacing %.3f kHz", spacing);
                proto_tree_add_item_ret_uint(tlvtree, hf_ieee802154_chplan_channels, tvb, offset+8, 2, ENC_LITTLE_ENDIAN, &count);
                proto_item_append_text(proto_tree_get_parent(tlvtree), ", Channels %u", count);
                break;
            }
            default:
                proto_tree_add_item(tlvtree, hf_ieee802154_tap_tlv_unknown, tvb, offset, length, ENC_NA);
                proto_item_append_text(proto_tree_get_parent(tlvtree), "Unknown TLV");
                break;
        } /* switch (tlv_type) */

        if (length%4) {
            guint32 zero = 0;
            GByteArray *padding = g_byte_array_sized_new(4);
            ti = proto_tree_add_bytes_item(tlvtree, hf_ieee802154_tap_tlv_padding, tvb, offset+length, 4-length%4, ENC_NA, padding, NULL, NULL);
            if (memcmp(&zero, padding->data, 4-length%4)) {
                expert_add_info(NULL, ti, &ei_ieee802154_tap_tlv_padding_not_zeros);
            }
            g_byte_array_free(padding, TRUE);
        }
        offset += ROUND_UP(length, 4);
    } /* while */

    /* if we have both slot start and frame start timestamp, show frame start offset */
    if (slot_start_ts && frame_start_ts) {
        delta_us = (double)(frame_start_ts - slot_start_ts) / 1000;
        ti = proto_tree_add_double_format_value(tree, hf_ieee802154_frame_start_offset, NULL, 0, 0, delta_us, "%.3f %s", delta_us, units_microseconds.singular);
        proto_item_set_generated(ti);
    }

    /* if we have both start and end frame timestamp, show frame duration */
    if (frame_start_ts && frame_end_ts) {
        delta_us = (double)(frame_end_ts - frame_start_ts) / 1000;
        ti = proto_tree_add_double_format_value(tree, hf_ieee802154_frame_duration, NULL, 0, 0, delta_us, "%.3f %s", delta_us, units_microseconds.singular);
        proto_item_set_generated(ti);
    }

    /* if we have start of slot, timeslot length, and end of frame timestamp, show frame overflow (+ve) or underflow (-ve) */
    if (timeslot_length && frame_end_ts && slot_start_ts) {
        /* overflow = frame_end_ts - slot_start_ts - timeslot_length */
        delta_us = (double)(frame_end_ts - slot_start_ts) / 1000;
        delta_us -= timeslot_length;
        ti = proto_tree_add_double_format_value(tree, hf_ieee802154_frame_end_offset, NULL, 0, 0, delta_us, "%.3f %s", delta_us, units_microseconds.singular);
        proto_item_set_generated(ti);
    }

    return (ieee802154_fcs_type_t)tap_fcs_type;
} /* dissect_ieee802154_tap_tlvs */

/*
 * Information Elements Processing (IEs)
 */

/**
 * Create a tree for a Payload IE incl. the TLV header and append the IE name to the parent item
 *
 * @param tvb the tv buffer
 * @param tree the tree to append this item to
 * @param hf field index
 * @param ett tree index
 * @returns the tree created for the Payload IE
 */
proto_tree*
ieee802154_create_pie_tree(tvbuff_t *tvb, proto_tree *tree, int hf, gint ett)
{
    proto_item *subitem;
    proto_tree *subtree;
    header_field_info *hfinfo;
    static int * const tlv_fields[] = {
            &hf_ieee802154_payload_ie_type,
            &hf_ieee802154_payload_ie_id,
            &hf_ieee802154_payload_ie_length,
            NULL
    };

    subitem = proto_tree_add_item(tree, hf, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    subtree = proto_item_add_subtree(subitem, ett);
    proto_tree_add_bitmask_with_flags(subtree, tvb, 0, hf_ieee802154_payload_ie_tlv, ett_ieee802154_payload_ie_tlv,
                                      tlv_fields, ENC_LITTLE_ENDIAN, BMT_NO_FLAGS);

    hfinfo = proto_registrar_get_nth(hf);
    if (hfinfo && hfinfo->name) {
        proto_item_append_text(proto_tree_get_parent(tree), ", %s", hfinfo->name);
    }
    return subtree;
}

/**
 * Create a tree for a Payload Sub-IE incl. the TLV header and append the IE name to the parent item
 *
 * @param tvb the tv buffer
 * @param tree the tree to append this item to
 * @param hf field index
 * @param ett tree index
 * @returns the tree created for the Payload IE
 */
static proto_tree*
ieee802154_create_psie_tree(tvbuff_t *tvb, proto_tree *tree, int hf, gint ett)
{
    proto_item *subitem;
    proto_tree *subtree;
    header_field_info *hfinfo;

    subitem  = proto_tree_add_item(tree, hf, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    subtree = proto_item_add_subtree(subitem, ett);
    if (tvb_get_letohs(tvb, 0) & IEEE802154_PSIE_TYPE_MASK) {
        static int * const fields_long[] = {
            &hf_ieee802154_psie_type,
            &hf_ieee802154_psie_id_long,
            &hf_ieee802154_psie_length_long,
            NULL
        };
        proto_tree_add_bitmask(subtree, tvb, 0, hf_ieee802154_psie, ett_ieee802154_psie, fields_long, ENC_LITTLE_ENDIAN);
    }
    else {
        static int * const fields_short[] = {
            &hf_ieee802154_psie_type,
            &hf_ieee802154_psie_id_short,
            &hf_ieee802154_psie_length_short,
            NULL
        };
        proto_tree_add_bitmask(subtree, tvb, 0, hf_ieee802154_psie, ett_ieee802154_psie, fields_short, ENC_LITTLE_ENDIAN);
    }

    hfinfo = proto_registrar_get_nth(hf);
    if (hfinfo && hfinfo->name) {
        proto_item_append_text(proto_tree_get_parent(tree), ", %s", hfinfo->name);
    }
    return subtree;
}

/**
 * Subdissector for the MLME Channel Hopping Payload IE
 */
static int
dissect_802154_channel_hopping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = ieee802154_create_psie_tree(tvb, tree, hf_ieee802154_tsch_channel_hopping, ett_ieee802154_mlme_payload);

    proto_tree_add_item(subtree, hf_ieee802154_tsch_hopping_sequence_id, tvb, 2, 1, ENC_LITTLE_ENDIAN);

    if (tvb_reported_length_remaining(tvb, 3) > 1) {
        /* TODO: There's still a huge amount of optional stuff that could follow */
        proto_tree_add_item(subtree, hf_ieee802154_mlme_ie_data, tvb, 3, tvb_reported_length_remaining(tvb, 3), ENC_NA);
    }
    return tvb_reported_length(tvb);
} /* dissect_802154_channel_hopping */

/**
 * Subdissector for the Nested MLME IE for TSCH Synchronization
 */
static int
dissect_802154_tsch_time_sync(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = ieee802154_create_psie_tree(tvb, tree, hf_ieee802154_tsch_sync, ett_ieee802154_tsch_synch);

    proto_tree_add_item(subtree, hf_ieee802154_tsch_asn, tvb, 2, 5, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_ieee802154_tsch_join_metric, tvb, 7, 1, ENC_LITTLE_ENDIAN);
    return 8;
}/* dissect_802154_tsch_time_sync*/

/**
 * Subdissector for the Nested MLME IE for TSCH Slotframe and Link
 */
static int
dissect_802154_tsch_slotframe_link(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    guint8 nb_slotframes;
    guint8 slotframe_index;
    proto_tree *subtree;
    guint offset = 0;

    subtree = ieee802154_create_psie_tree(tvb, tree, hf_ieee802154_tsch_slotframe, ett_ieee802154_tsch_slotframe);
    offset += 2;

    nb_slotframes = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_ieee802154_tsch_slotf_link_nb_slotf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    for (slotframe_index = 1; slotframe_index <= nb_slotframes; slotframe_index++) {
        /* Create a tree for the slotframe. */
        guint8 nb_links = tvb_get_guint8(tvb, offset + 3);
        proto_item *sf_item = proto_tree_add_subtree_format(subtree, tvb, offset, 4 + (5 * nb_links),
                                                            ett_ieee802154_tsch_slotframe, NULL,
                                                            "Slotframes [%u]", slotframe_index);
        proto_tree *sf_tree = proto_item_add_subtree(sf_item, ett_ieee802154_tsch_slotframe_list);
        proto_tree_add_item(sf_tree, hf_ieee802154_tsch_slotf_link_slotf_handle, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sf_tree, hf_ieee802154_tsch_slotf_size, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sf_tree, hf_ieee802154_tsch_slotf_link_nb_links, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);

        /* Create a tree for each link in the slotframe. */
        offset += 4;
        while (nb_links > 0) {
            static int * const fields_options[] = {
                &hf_ieee802154_tsch_slotf_link_options_tx,
                &hf_ieee802154_tsch_slotf_link_options_rx,
                &hf_ieee802154_tsch_slotf_link_options_shared,
                &hf_ieee802154_tsch_slotf_link_options_timkeeping,
                &hf_ieee802154_tsch_slotf_link_options_priority,
                NULL
            };

            proto_item  *link_item = proto_tree_add_item(sf_tree, hf_ieee802154_tsch_link_info, tvb, offset, 5, ENC_NA);
            proto_tree  *link_tree = proto_item_add_subtree(link_item, ett_ieee802154_tsch_slotframe_link);
            proto_tree_add_item(link_tree, hf_ieee802154_tsch_slotf_link_timeslot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(link_tree, hf_ieee802154_tsch_slotf_link_channel_offset, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_bitmask(link_tree, tvb, offset + 4, hf_ieee802154_tsch_slotf_link_options, ett_ieee802154_tsch_slotframe_link_options, fields_options, ENC_LITTLE_ENDIAN);
            nb_links -= 1;
            offset += 5;
        }
    }

    return offset;
}/* dissect_802154_tsch_slotframe_link */

/**
 * Subdissector for the Nested MLME IE for TSCH Timeslot Description
 */
static int
dissect_802154_tsch_timeslot(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = ieee802154_create_psie_tree(tvb, tree, hf_ieee802154_tsch_timeslot, ett_ieee802154_tsch_timeslot);
    guint offset = 2;

    proto_tree_add_item(subtree, hf_ieee802154_tsch_timeslot_id, tvb, 2, 1, ENC_LITTLE_ENDIAN);
    offset++;

    if (tvb_reported_length(tvb) > offset) {
        const int timeslot_fields[] = {
            hf_ieee802154_tsch_timeslot_cca_offset,
            hf_ieee802154_tsch_timeslot_cca,
            hf_ieee802154_tsch_timeslot_tx_offset,
            hf_ieee802154_tsch_timeslot_rx_offset,
            hf_ieee802154_tsch_timeslot_rx_ack_delay,
            hf_ieee802154_tsch_timeslot_tx_ack_delay,
            hf_ieee802154_tsch_timeslot_rx_wait,
            hf_ieee802154_tsch_timeslot_ack_wait,
            hf_ieee802154_tsch_timeslot_turnaround,
            hf_ieee802154_tsch_timeslot_max_ack,
        };
        unsigned int i;
        for (i = 0; i < sizeof(timeslot_fields)/sizeof(timeslot_fields[1]); i++) {
            proto_tree_add_item(subtree, timeslot_fields[i], tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        /* The last two fields are may have different encodings depending on the length of the IE. */
        if (tvb_reported_length_remaining(tvb, offset) > 4) {
            proto_tree_add_item(subtree, hf_ieee802154_tsch_timeslot_max_tx, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
            proto_tree_add_item(subtree, hf_ieee802154_tsch_timeslot_length, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        }
        else {
            proto_tree_add_item(subtree, hf_ieee802154_tsch_timeslot_max_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_ieee802154_tsch_timeslot_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
    }
    return offset;
} /* dissect_802154_tsch_timeslot */

/**
 * Subdissector for the 6TOP Protocol contained within the Payload Information Elements.
 */
static int
dissect_ietf_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ies_tree, void *data _U_)
{
    const guint8 supported_6p_version = 0x00;

    proto_tree *p_inf_elem_tree = ieee802154_create_pie_tree(tvb, ies_tree, hf_ieee802154_pie_ietf, ett_ieee802154_pie_ietf);
    guint      offset = 2;
    guint      pie_length = tvb_reported_length(tvb) - 2;
    guint8     subie;
    guint8     version;
    guint8     type;
    guint8     code;
    guint8     num_cells = 0;
    gboolean   have_cell_list = FALSE;
    int        i;
    proto_item *sixtop_item = NULL;
    proto_tree *sixtop_tree = NULL;
    proto_item *cell_list_item = NULL;
    proto_tree *cell_list_tree = NULL;
    proto_item *cell_item = NULL;
    proto_tree *cell_tree = NULL;
    proto_item *type_item = NULL;
    proto_item *code_item = NULL;
    const gchar *code_str = NULL;
    static int * const cell_options[] = {
        &hf_ieee802154_6top_cell_option_tx,
        &hf_ieee802154_6top_cell_option_rx,
        &hf_ieee802154_6top_cell_option_shared,
        &hf_ieee802154_6top_cell_option_reserved,
        NULL
    };

    if (pie_length < 5) {
        return pie_length + 2;
    }

    subie = tvb_get_guint8(tvb, offset);
    version =  tvb_get_guint8(tvb, offset + 1) & IETF_6TOP_VERSION;

    if (subie != IEEE802154_IETF_SUBIE_6TOP || version != supported_6p_version) {
        return pie_length + 2;
    }

    type = (tvb_get_guint8(tvb, offset + 1) & IETF_6TOP_TYPE) >> 4;
    code = tvb_get_guint8(tvb, offset + 2);

    proto_tree_add_item(p_inf_elem_tree, hf_ieee802154_p_ie_ietf_sub_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    sixtop_item = proto_tree_add_item(p_inf_elem_tree, hf_ieee802154_6top, tvb, offset, pie_length, ENC_NA);
    sixtop_tree = proto_item_add_subtree(sixtop_item, ett_ieee802154_p_ie_6top);

    proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_version, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    type_item = proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_type, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_flags_reserved, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
    code_item = proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_code, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_sfid, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_seqnum, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "6top");
    if (type == IETF_6TOP_TYPE_REQUEST) {
      code_str = val_to_str_const(code, ietf_6top_command_identifiers,"Unknown");
      col_add_fstr(pinfo->cinfo, COL_INFO, "6P %s Request", code_str);
    } else {
      code_str = val_to_str_const(code, ietf_6top_return_codes,"Unknown");
      col_add_fstr(pinfo->cinfo, COL_INFO, "6P %s (%s)",
                   val_to_str_const(type, ietf_6top_types,"Unknown"), code_str);
    }
    proto_item_append_text(code_item, " (%s)", code_str);

    offset += 5;
    pie_length -= 5;

    if (type == IETF_6TOP_TYPE_REQUEST) {
        switch (code) {
        case IETF_6TOP_CMD_ADD:
        case IETF_6TOP_CMD_DELETE:
        case IETF_6TOP_CMD_RELOCATE:
            if (pie_length < 4) {
                break;
            }
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_metadata, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_bitmask(sixtop_tree, tvb, offset + 2, hf_ieee802154_6top_cell_options, ett_ieee802154_p_ie_6top_cell_options, cell_options, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_num_cells, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
            num_cells = tvb_get_guint8(tvb, offset + 3);
            pie_length -= 4;
            offset += 4;
            if (pie_length > 0 && (pie_length % 4) == 0) {
                have_cell_list = TRUE;
            }
            break;
        case IETF_6TOP_CMD_COUNT:
            if (pie_length < 3) {
                break;
            }
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_metadata, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_bitmask(sixtop_tree, tvb, offset + 2, hf_ieee802154_6top_cell_options, ett_ieee802154_p_ie_6top_cell_options, cell_options, ENC_LITTLE_ENDIAN);
            pie_length -= 3;
            offset += 3;
            break;
        case IETF_6TOP_CMD_LIST:
            if (pie_length != 8) {
                break;
            }
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_metadata, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_bitmask(sixtop_tree, tvb, offset + 2, hf_ieee802154_6top_cell_options, ett_ieee802154_p_ie_6top_cell_options, cell_options, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_reserved, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_offset, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_max_num_cells, tvb, offset + 6, 2, ENC_LITTLE_ENDIAN);
            pie_length -= 8;
            offset += 8;
            break;
        case IETF_6TOP_CMD_SIGNAL:
            if (pie_length < 2) {
                break;
            }
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_metadata, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            if (pie_length > 2) {
                proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_payload, tvb, offset + 2, pie_length - 2, ENC_NA);
            }
            offset += pie_length;
            pie_length = 0;
            break;
        case IETF_6TOP_CMD_CLEAR:
            if (pie_length < 2) {
                break;
            }
            proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_metadata, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            pie_length -= 2;
            offset += 2;
            break;
        default:
            /* unsupported command */
            expert_add_info(pinfo, code_item, &ei_ieee802154_6top_unsupported_command);
            break;
        }
    } else if (type == IETF_6TOP_TYPE_RESPONSE || type == IETF_6TOP_TYPE_CONFIRMATION) {
        switch(code) {
        case IETF_6TOP_RC_SUCCESS:
            if (pie_length > 0) {
                if (pie_length == 2) {
                    proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_total_num_cells, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    pie_length -= 2;
                    offset += 2;
                } else if ((pie_length % 4) == 0) {
                    have_cell_list = TRUE;
                } else {
                    proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_payload, tvb, offset, pie_length, ENC_NA);
                    offset += pie_length;
                    pie_length = 0;
                }
            }
            break;
        case IETF_6TOP_RC_EOL:
            if(pie_length > 0 && (pie_length % 4) == 0) {
                have_cell_list = TRUE;
            }
            break;
        case IETF_6TOP_RC_ERR:
        case IETF_6TOP_RC_RESET:
        case IETF_6TOP_RC_ERR_VERSION:
        case IETF_6TOP_RC_ERR_SFID:
        case IETF_6TOP_RC_ERR_SEQNUM:
        case IETF_6TOP_RC_ERR_CELLLIST:
        case IETF_6TOP_RC_ERR_BUSY:
        case IETF_6TOP_RC_ERR_LOCKED:
            /* They have no other field */
            break;
        default:
            /* unsupported return code */
            expert_add_info(pinfo, code_item, &ei_ieee802154_6top_unsupported_return_code);
            break;
        }
    } else {
        /* unsupported type */
        expert_add_info(pinfo, type_item, &ei_ieee802154_6top_unsupported_type);
    }

    if (have_cell_list) {
        if (type == IETF_6TOP_TYPE_REQUEST && code == IETF_6TOP_CMD_RELOCATE) {
            cell_list_item = proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_rel_cell_list, tvb, offset, pie_length, ENC_NA);
            cell_list_tree = proto_item_add_subtree(cell_list_item, ett_ieee802154_p_ie_6top_rel_cell_list);
            /* num_cells is expected to be set properly */
            for (i = 0; i < num_cells; offset += 4, i++) {
                cell_item = proto_tree_add_item(cell_list_tree, hf_ieee802154_6top_cell, tvb, offset, 4, ENC_NA);
                cell_tree = proto_item_add_subtree(cell_item, ett_ieee802154_p_ie_6top_cell);
                proto_tree_add_item(cell_tree, hf_ieee802154_6top_slot_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cell_tree, hf_ieee802154_6top_channel_offset, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
            }
            pie_length -= num_cells * 4;
            cell_list_item = proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_cand_cell_list, tvb, offset, pie_length, ENC_NA);
            cell_list_tree = proto_item_add_subtree(cell_list_item, ett_ieee802154_p_ie_6top_cand_cell_list);
            for (i = 0; pie_length > 0; pie_length -= 4, offset += 4, i++) {
                cell_item = proto_tree_add_item(cell_list_tree, hf_ieee802154_6top_cell, tvb, offset, 4, ENC_NA);
                cell_tree = proto_item_add_subtree(cell_item, ett_ieee802154_p_ie_6top_cell);
                proto_tree_add_item(cell_tree, hf_ieee802154_6top_slot_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cell_tree, hf_ieee802154_6top_channel_offset, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
            }
        } else {
            cell_list_item = proto_tree_add_item(sixtop_tree, hf_ieee802154_6top_cell_list, tvb, offset, pie_length, ENC_NA);
            cell_list_tree = proto_item_add_subtree(cell_list_item, ett_ieee802154_p_ie_6top_cell_list);
            for (i = 0; pie_length > 0; pie_length -= 4, offset += 4, i++) {
                cell_item = proto_tree_add_item(cell_list_tree, hf_ieee802154_6top_cell, tvb, offset, 4, ENC_NA);
                cell_tree = proto_item_add_subtree(cell_item, ett_ieee802154_p_ie_6top_cell);
                proto_tree_add_item(cell_tree, hf_ieee802154_6top_slot_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cell_tree, hf_ieee802154_6top_channel_offset, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
            }
        }
    }

    return offset;
} /* dissect_ieee802154_6top */

/**
 * Subdissector for the Superframe specification sub-field within the beacon frame.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields (unused).
 * @param tree pointer to command subtree.
 * @param offset offset into the tvbuff to begin dissection.
 */
void
dissect_ieee802154_superframe(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    static int * const superframe[] = {
        &hf_ieee802154_beacon_order,
        &hf_ieee802154_superframe_order,
        &hf_ieee802154_cap,
        &hf_ieee802154_superframe_battery_ext,
        &hf_ieee802154_superframe_coord,
        &hf_ieee802154_assoc_permit,
        NULL
    };

    proto_tree_add_bitmask_text(tree, tvb, *offset, 2, "Superframe Specification: ", NULL , ett_ieee802154_superframe, superframe, ENC_LITTLE_ENDIAN, BMT_NO_INT|BMT_NO_TFS);
    (*offset) += 2;
} /* dissect_ieee802154_superframe */

/**
 * Subdissector for the GTS information fields within the beacon frame.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields (unused).
 * @param tree pointer to command subtree.
 * @param offset offset into the tvbuff to begin dissection.
 */
void
dissect_ieee802154_gtsinfo(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    proto_tree *field_tree = NULL;
    proto_tree *subtree    = NULL;
    proto_item *ti;
    guint8      gts_spec;
    guint8      gts_count;

    /*  Get and display the GTS specification field */
    gts_spec = tvb_get_guint8(tvb, *offset);
    gts_count = gts_spec & IEEE802154_GTS_COUNT_MASK;
    if (tree) {
        /*  Add Subtree for GTS information. */
        if (gts_count) {
            field_tree = proto_tree_add_subtree(tree, tvb, *offset, 2 + (gts_count * 3), ett_ieee802154_gts, NULL, "GTS");
        }
        else {
            field_tree = proto_tree_add_subtree(tree, tvb, *offset, 1, ett_ieee802154_gts, NULL, "GTS");
        }

        proto_tree_add_uint(field_tree, hf_ieee802154_gts_count, tvb, *offset, 1, gts_count);
        proto_tree_add_boolean(field_tree, hf_ieee802154_gts_permit, tvb, *offset, 1, gts_spec & IEEE802154_GTS_PERMIT_MASK);
    }
    (*offset) += 1;

    /* If the GTS descriptor count is nonzero, then the GTS directions mask and descriptor list are present. */
    if (gts_count) {
        guint8  gts_directions = tvb_get_guint8(tvb, *offset);
        guint   gts_rx = 0;
        int     i;

        /* Display the directions mask. */
        if (tree) {
            proto_tree  *dir_tree;

            /* Create a subtree. */
            dir_tree = proto_tree_add_subtree(field_tree, tvb, *offset, 1, ett_ieee802154_gts_direction, &ti, "GTS Directions");

            /* Add the directions to the subtree. */
            for (i=0; i<gts_count; i++) {
                gboolean    dir = gts_directions & IEEE802154_GTS_DIRECTION_SLOT(i);
                proto_tree_add_boolean_format(dir_tree, hf_ieee802154_gts_direction, tvb, *offset, 1, dir, "GTS Slot %i: %s", i+1, dir?"Receive Only":"Transmit Only");
                if (dir) gts_rx++;
            } /* for */
            proto_item_append_text(ti, ": %i Receive & %i Transmit", gts_rx, gts_count - gts_rx);
        }
        (*offset) += 1;

        /* Create a subtree for the GTS descriptors. */
        subtree = proto_tree_add_subtree(field_tree, tvb, *offset, gts_count * 3, ett_ieee802154_gts_descriptors, NULL, "GTS Descriptors");

        /* Get and display the GTS descriptors. */
        for (i=0; i<gts_count; i++) {
            guint16 gts_addr        = tvb_get_letohs(tvb, (*offset));
            guint8  gts_slot        = tvb_get_guint8(tvb, (*offset)+2);
            guint8  gts_length      = (gts_slot & IEEE802154_GTS_LENGTH_MASK) >> IEEE802154_GTS_LENGTH_SHIFT;

            gts_slot = (gts_slot & IEEE802154_GTS_SLOT_MASK);

            if (tree) {
                /* Add address, slot, and time length fields. */
                ti = proto_tree_add_uint(subtree, hf_ieee802154_gts_address, tvb, (*offset), 3, gts_addr);
                proto_item_append_text(ti, ", Slot: %i", gts_slot);
                proto_item_append_text(ti, ", Length: %i", gts_length);
            }
            (*offset) += 3;
        } /* for */
    }
} /* dissect_ieee802154_gtsinfo */

/**
 * Subdissector for the pending address list fields within the beacon frame.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields (unused).
 * @param tree pointer to command subtree.
 * @param offset into the tvbuff to begin dissection.
 */
void
dissect_ieee802154_pendaddr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    proto_tree *subtree;
    guint8      pend_spec;
    guint8      pend_num16;
    guint8      pend_num64;
    int         i;

    /*  Get the Pending Addresses specification fields */
    pend_spec = tvb_get_guint8(tvb, *offset);
    pend_num16 = pend_spec & IEEE802154_PENDADDR_SHORT_MASK;
    pend_num64 = (pend_spec & IEEE802154_PENDADDR_LONG_MASK) >> IEEE802154_PENDADDR_LONG_SHIFT;

    /*  Add Subtree for the addresses */
    subtree = proto_tree_add_subtree_format(tree, tvb, *offset, 1 + 2*pend_num16 + 8*pend_num64,
                        ett_ieee802154_pendaddr, NULL, "Pending Addresses: %i Short and %i Long", pend_num16, pend_num64);
    (*offset) += 1;

    for (i=0; i<pend_num16; i++) {
        guint16 addr = tvb_get_letohs(tvb, *offset);
        proto_tree_add_uint(subtree, hf_ieee802154_pending16, tvb, *offset, 2, addr);
        (*offset) += 2;
    } /* for */
    for (i=0; i<pend_num64; i++) {
        proto_tree_add_item(subtree, hf_ieee802154_pending64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
        (*offset) += 8;
    } /* for */
} /* dissect_ieee802154_pendaddr */

/*
 * Header IEs
 */

/**
 * Create a tree for a Header IE incl. the TLV header and append the IE name to the parent item
 *
 * @param tvb the tv buffer
 * @param tree the tree to append this item to
 * @param hf field index
 * @param ett tree index
 * @returns the tree created for the Header IE
 */
proto_tree*
ieee802154_create_hie_tree(tvbuff_t *tvb, proto_tree *tree, int hf, gint ett)
{
    proto_item *subitem;
    proto_tree *subtree;
    header_field_info *hfinfo;
    static int * const tlv_fields[] = {
            &hf_ieee802154_header_ie_type,
            &hf_ieee802154_header_ie_id,
            &hf_ieee802154_header_ie_length,
            NULL
    };

    subitem = proto_tree_add_item(tree, hf, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    subtree = proto_item_add_subtree(subitem, ett);
    proto_tree_add_bitmask_with_flags(subtree, tvb, 0, hf_ieee802154_header_ie_tlv, ett_ieee802154_header_ie_tlv,
                                      tlv_fields, ENC_LITTLE_ENDIAN, BMT_NO_FLAGS);

    hfinfo = proto_registrar_get_nth(hf);
    if (hfinfo && hfinfo->name) {
        proto_item_append_text(proto_tree_get_parent(tree), ", %s", hfinfo->name);
    }
    return subtree;
}

/*
 * The dissectors for the individual Header IEs
 * They are called via call_dissector with the tvb including the IE header and data as ieee802154_packet
 */

/**
 * Dissect the CSL IE (7.4.2.3)
 */
static int
dissect_hie_csl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = ieee802154_create_hie_tree(tvb, tree, hf_ieee802154_hie_csl, ett_ieee802154_hie_csl);
    proto_tree_add_item(subtree, hf_ieee802154_hie_csl_phase, tvb, 2, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_ieee802154_hie_csl_period, tvb, 4, 2, ENC_LITTLE_ENDIAN);
    if (tvb_reported_length(tvb) >= 8) {
        proto_tree_add_item(subtree, hf_ieee802154_hie_csl_rendezvous_time, tvb, 6, 2, ENC_LITTLE_ENDIAN);
        return 2 + 6;
    }
    return 2 + 4;
}

/**
 * Dissect the Rendez-Vous Time IE (7.4.2.6)
 * The IE is made of 2 fields:
 *  - RendezVous Time: in 802.15.4-2015, this is exactly the same field as in the CSL IE
 *  - Wake-Up Interval: the spec text is unclear about the field being optional or not. This dissector assumes it is
 */
static int
dissect_hie_rendezvous_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = ieee802154_create_hie_tree(tvb, tree, hf_ieee802154_hie_rdv, ett_ieee802154_hie_rdv);

    // reuse field from CSL IE
    proto_tree_add_item(subtree, hf_ieee802154_hie_csl_rendezvous_time, tvb, 2, 2, ENC_LITTLE_ENDIAN);

    // In 802.15.4-2015, Rendez-Vous Time IE is only present in CSL Wake-Up Frames
    // Update the packet information
    col_set_str(pinfo->cinfo, COL_INFO, "CSL Wake-up Frame");
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Rendez-Vous Time: %d", tvb_get_guint16(tvb, 2, ENC_LITTLE_ENDIAN));

    // Assume Wake-Up Interval is optional. Spec says "only present [...] when macCslInterval is nonzero"
    if (tvb_reported_length(tvb) >= 6) {
        proto_tree_add_item(subtree, hf_ieee802154_hie_rdv_wakeup_interval, tvb, 4, 2, ENC_LITTLE_ENDIAN);
        return 2 + 4;
    }

    return 2 + 2;
}

/**
 * Dissect the Time Correction Header IE (7.4.2.7)
 *
 * This field is constructed by taking a signed 16-bit 2's compliment time
 * correction in the range of -2048 us to 2047 us, AND'ing it with 0xfff, and
 * OR'ing again with 0x8000 to indicate a negative acknowledgment.
 */
static int
dissect_hie_time_correction(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ies_tree, void *data _U_)
{
    static int * const fields[] = {
            &hf_ieee802154_hie_time_correction_value,
            &hf_ieee802154_nack,
            NULL
    };
    proto_tree *tree = ieee802154_create_hie_tree(tvb, ies_tree, hf_ieee802154_hie_time_correction, ett_ieee802154_hie_time_correction);
    guint16 time_sync_value = tvb_get_letohs(tvb, 2);
    proto_tree_add_bitmask_with_flags(tree, tvb, 2, hf_ieee802154_hie_time_correction_time_sync_info, ett_ieee802154_header_ie,
                                      fields, ENC_LITTLE_ENDIAN, BMT_NO_FLAGS);

    if (time_sync_value & ~(0x8fff)) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_ieee802154_time_correction_error);
    }
    if (time_sync_value & 0x8000) {
        proto_item_append_text(proto_tree_get_parent(ies_tree), ": NACK");
    }
    return 2 + 2;
}

static int
dissect_hie_global_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = ieee802154_create_hie_tree(tvb, tree, hf_ieee802154_hie_global_time, ett_ieee802154_hie_global_time);
    proto_tree_add_item(subtree, hf_ieee802154_hie_global_time_value, tvb, 2, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
    return 2 + 4;
}

/**
 * Dissect the Vendor Specific IE (7.4.2.2)
 */
static int
dissect_hie_vendor_specific(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree = ieee802154_create_hie_tree(tvb, tree, hf_ieee802154_hie_vendor_specific,
                                                                ett_ieee802154_hie_vendor_specific);

    guint hie_length = tvb_reported_length(tvb) - 2;
    guint      offset = 2;

    tvb_get_letoh24(tvb, offset);
    proto_tree_add_item(subtree, hf_ieee802154_hie_vendor_specific_vendor_oui, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3; /* adjust for vendor OUI */
    hie_length -= 3;

    proto_tree_add_item(subtree, hf_ieee802154_hie_vendor_specific_content, tvb, offset, hie_length, ENC_NA);

    return tvb_reported_length(tvb);
}

/**
 * Subdissector for Header IEs (Information Elements)
 *
 * Since the header is never encrypted and the payload may be encrypted,
 * we dissect header and payload IEs separately.
 * The termination of the Header IE tells us whether there are any
 * payload IEs to follow.
 *
 * @param tvb the tv buffer
 * @param pinfo pointer to packet information fields.
 * @param tree the tree to append this item to
 * @param orig_offset offset into the tvbuff to begin dissection.
 * @param packet IEEE 802.15.4 packet information.
 */
static int
dissect_ieee802154_header_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint orig_offset, ieee802154_packet *packet)
{
    // GCC emits a spurious -Wclobbered if offset is used as function parameter (even with volatile)
    volatile guint offset = orig_offset;
    proto_item *ies_item = proto_tree_add_item(tree, hf_ieee802154_header_ies, tvb, offset, -1, ENC_NA);
    proto_tree *ies_tree = proto_item_add_subtree(ies_item, ett_ieee802154_header_ie);
    volatile gint remaining = tvb_reported_length_remaining(tvb, offset) - IEEE802154_MIC_LENGTH(packet->security_level);

    // Loop as long as we don't:
    //
    // 1) run out of data;
    // 2) get a header termination IE.
    //
    // See Table 9-6 "Termination IE inclusion rules" of IEEE Std 802.15.4-2015;
    // unless we have no payload IEs and no payload data, we *have* to have
    // a header termination IE to end the list of header IEs, so the "run out
    // of data" check needs only to check whether there's any data
    // left in the tvbuff (which has already had the FCS removed from
    // it), other than a MIC if present - if we have no payload IEs or
    // payload data, there might still be a MIC to Check the Message
    // Integrity.
    //
    // XXX - we should make sure we have enough data left for an IE header,
    // and report a malformed frame if not, and if we do have enough data,
    // make sure we have enough data for the full IE, and report a malformed
    // frame if not.
    do {
        volatile int consumed = 0;
        guint16 ie_header = tvb_get_letohs(tvb, offset);
        guint16 id = (guint16) ((ie_header & IEEE802154_HEADER_IE_ID_MASK) >> 7);
        guint16 length = (guint16) (ie_header & IEEE802154_HEADER_IE_LENGTH_MASK);
        tvbuff_t *ie_tvb = tvb_new_subset_length(tvb, offset, 2 + length);

        if (id == IEEE802154_HEADER_IE_HT1 || id == IEEE802154_HEADER_IE_HT2) {
            int hf_term_ie = (id == IEEE802154_HEADER_IE_HT1) ? hf_ieee802154_hie_ht1 : hf_ieee802154_hie_ht2;
            ieee802154_create_hie_tree(ie_tvb, ies_tree, hf_term_ie, ett_ieee802154_hie_ht);
            consumed = 2;
        } else {
            TRY {
                consumed = dissector_try_uint_new(header_ie_dissector_table, id, ie_tvb, pinfo, ies_tree, FALSE, packet);
                if (consumed == 0) {
                    proto_tree *subtree = ieee802154_create_hie_tree(ie_tvb, ies_tree, hf_ieee802154_hie_unsupported,
                                                                ett_ieee802154_hie_unsupported);
                    proto_tree_add_item(subtree, hf_ieee802154_ie_unknown_content, ie_tvb, 2, length, ENC_NA);
                    consumed = 2 + length;
                    if (ie_header & IEEE802154_PAYLOAD_IE_TYPE_MASK) {
                        expert_add_info(pinfo, ies_tree, &ei_ieee802154_payload_ie_in_header);
                    } else {
                        expert_add_info(pinfo, ies_tree, &ei_ieee802154_ie_unsupported_id);
                    }
                }
            }
            CATCH_ALL {
                show_exception(tvb, pinfo, ies_tree, EXCEPT_CODE, GET_MESSAGE);
                consumed = 2 + length;
            }
            ENDTRY;
        }

        if (consumed < 2 + length) {
            proto_tree_add_item(ies_tree, hf_ieee802154_ie_unknown_content, ie_tvb, consumed, 2 + length - consumed, ENC_NA);
            expert_add_info(pinfo, ies_item, &ei_ieee802154_ie_unknown_extra_content);
        }

        offset += 2 + length;
        remaining -= 2 + length;

        if (id == IEEE802154_HEADER_IE_HT1 || id == IEEE802154_HEADER_IE_HT2) {
            packet->payload_ie_present = (id == IEEE802154_HEADER_IE_HT1);
            break;
        }
    } while (remaining > 0);

    proto_item_set_len(ies_item, offset - orig_offset);
    return offset - orig_offset;
}

static int
dissect_802154_eb_filter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    guint8  filter;
    guint8  attr_len;
    proto_tree *subtree;
    guint offset = 0;

    static int * const fields_eb_filter[] = {
        &hf_ieee802154_psie_eb_filter_pjoin,
        &hf_ieee802154_psie_eb_filter_lqi,
        &hf_ieee802154_psie_eb_filter_percent,
        &hf_ieee802154_psie_eb_filter_attr_id,
        /* reserved 5-7 */
        NULL
    };

    subtree = ieee802154_create_psie_tree(tvb, tree, hf_ieee802154_psie_eb_filter, ett_ieee802154_eb_filter);
    offset += 2;

    filter = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(subtree, tvb, offset, hf_ieee802154_psie_eb_filter,
                           ett_ieee802154_eb_filter_bitmap, fields_eb_filter, ENC_NA);
    offset++;

    if (filter & IEEE802154_MLME_PSIE_EB_FLT_LQI) {
        proto_tree_add_item(subtree, hf_ieee802154_psie_eb_filter_lqi_min, tvb, offset, 1, ENC_NA);
        offset++;
    }

    if (filter & IEEE802154_MLME_PSIE_EB_FLT_PERCENT) {
        proto_tree_add_item(subtree, hf_ieee802154_psie_eb_filter_percent_prob, tvb, offset, 1, ENC_NA);
        offset++;
    }

    attr_len = (guint8) ((filter & IEEE802154_MLME_PSIE_EB_FLT_ATTR_LEN) >> 3);
    if (attr_len) {
        /* just display in hex until we know how to decode */
        proto_tree_add_item(subtree, hf_ieee802154_psie_eb_filter_attr_id_bitmap, tvb, offset, attr_len, ENC_LITTLE_ENDIAN);
        offset += attr_len;
    }

    return offset;
}

/**
 * Subdissector for MLME IEs
 */
static int
dissect_pie_mlme(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ies_tree, void *data)
{
    proto_tree *tree = ieee802154_create_pie_tree(tvb, ies_tree, hf_ieee802154_mlme, ett_ieee802154_mlme);
    volatile guint offset = 2;

    while (tvb_reported_length_remaining(tvb, offset) > 1) {
        guint16             psie_ie = tvb_get_letohs(tvb, offset);
        volatile guint16    psie_id;
        tvbuff_t *volatile  psie_tvb;

        if (psie_ie & IEEE802154_PSIE_TYPE_MASK) {
            /* long format: Table 7-17-Sub-ID allocation for long format */
            psie_id  = (guint16) ((psie_ie & IEEE802154_PSIE_ID_MASK_LONG) >> 11);
            psie_tvb = tvb_new_subset_length(tvb, offset, (psie_ie & IEEE802154_PSIE_LENGTH_MASK_LONG) + 2);
        }
        else {
            /* short format: Table 7-16-Sub-ID allocation for short format */
            psie_id  = (guint16) ((psie_ie & IEEE802154_PSIE_ID_MASK_SHORT) >> 8);
            psie_tvb = tvb_new_subset_length(tvb, offset, (psie_ie & IEEE802154_PSIE_LENGTH_MASK_SHORT) + 2);
        }
        offset += tvb_reported_length(psie_tvb);

        /* Pass the tvb off to a subdissector. */
        TRY {
            guint consumed = dissector_try_uint_new(mlme_ie_dissector_table, psie_id, psie_tvb, pinfo, tree, FALSE, data);
            if (consumed == 0) {
                proto_tree *subtree = ieee802154_create_psie_tree(psie_tvb, tree, hf_ieee802154_mlme_ie_unsupported, ett_ieee802154_mlme_unsupported);
                if (tvb_reported_length(psie_tvb) > 2) {
                    proto_tree_add_item(subtree, hf_ieee802154_mlme_ie_data, psie_tvb, 2, -1, ENC_NA);
                }
                expert_add_info(pinfo, subtree, &ei_ieee802154_ie_unsupported_id);
            }
        }
        CATCH_ALL {
            show_exception(tvb, pinfo, ies_tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
    }
    return offset;
}

/**
 * Subdissector for MPX IEs (IEEE 802.15.9)
 */
static int
dissect_mpx_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ies_tree, void *data _U_)
{
    static int * const fields[] = {
            &hf_ieee802159_mpx_transaction_id,
            &hf_ieee802159_mpx_transfer_type,
            NULL
    };
    static int * const fields_compressed_multiplex_id[] = {
            &hf_ieee802159_mpx_transaction_id_as_multiplex_id,
            &hf_ieee802159_mpx_transfer_type,
            NULL
    };

    proto_tree *tree = ieee802154_create_pie_tree(tvb, ies_tree, hf_ieee802159_mpx, ett_ieee802159_mpx);
    guint offset = 2;
    guint8 transaction_control = tvb_get_guint8(tvb, offset);
    guint8 transfer_type = (guint8) (transaction_control & IEEE802159_MPX_TRANSFER_TYPE_MASK);
    guint8 transaction_id = (guint8) ((transaction_control & IEEE802159_MPX_TRANSACTION_ID_MASK) >> IEEE802159_MPX_TRANSACTION_ID_SHIFT);
    gint32 multiplex_id = -1;
    guint8 fragment_number;

    if (transfer_type == IEEE802159_MPX_FULL_FRAME_NO_MUXID) {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_ieee802159_mpx_transaction_control, ett_ieee802159_mpx_transaction_control,
                               fields_compressed_multiplex_id, ENC_LITTLE_ENDIAN, BMT_NO_FLAGS);
        multiplex_id = transaction_id;
    } else {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_ieee802159_mpx_transaction_control, ett_ieee802159_mpx_transaction_control,
                               fields, ENC_LITTLE_ENDIAN, BMT_NO_FLAGS);
    }
    offset += 1;

    switch (transfer_type) {  // cf. IEEE 802.15.9 Table 18 - Summary of different MPX IE formats
        case IEEE802159_MPX_FULL_FRAME:
            multiplex_id = tvb_get_letohs(tvb, offset);
            proto_tree_add_uint_format_value(tree, hf_ieee802159_mpx_multiplex_id, tvb, offset, 2, multiplex_id, "%s (0x%04x)",
                val_to_str_const(multiplex_id, (multiplex_id > 1500) ? etype_vals : mpx_multiplex_id_vals, "Unknown"), multiplex_id);
            offset += 2;
            break;
        case IEEE802159_MPX_FULL_FRAME_NO_MUXID:
            break;  // nothing to do
        case IEEE802159_MPX_NON_LAST_FRAGMENT:
            fragment_number = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_ieee802159_mpx_fragment_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            if (fragment_number == 0) {
                proto_tree_add_item(tree, hf_ieee802159_mpx_total_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                multiplex_id = tvb_get_letohs(tvb, offset);
                proto_tree_add_item(tree, hf_ieee802159_mpx_multiplex_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            break;
        case IEEE802159_MPX_LAST_FRAGMENT:
            proto_tree_add_item(tree, hf_ieee802159_mpx_fragment_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case IEEE802159_MPX_ABORT:
            if (tvb_reported_length_remaining(tvb, offset) == 2) {
                proto_tree_add_item(tree, hf_ieee802159_mpx_total_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            return offset;
        default:  // reserved values -> warning and return
            expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_ieee802159_mpx_invalid_transfer_type);
            return offset;
    }

    // TODO: reassembly

    dissector_handle_t dissector = NULL;

    if (multiplex_id == IEEE802159_MPX_MULTIPLEX_ID_KMP) {
        guint8 kmp_id = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_ieee802159_mpx_kmp_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        switch (kmp_id) {
            case IEEE802159_MPX_KMP_ID_IEEE8021X:
            case IEEE802159_MPX_KMP_ID_IEEE80211_4WH:
            case IEEE802159_MPX_KMP_ID_IEEE80211_GKH:
                dissector = eapol_handle;
                break;

            // TODO
            case IEEE802159_MPX_KMP_ID_HIP:
            case IEEE802159_MPX_KMP_ID_IKEV2:
            case IEEE802159_MPX_KMP_ID_PANA:
            case IEEE802159_MPX_KMP_ID_DRAGONFLY:
            case IEEE802159_MPX_KMP_ID_ETSI_TS_102_887_2:
                expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_ieee802159_mpx_unsupported_kmp);
                break;

            case IEEE802159_MPX_KMP_ID_VENDOR_SPECIFIC:
                proto_tree_add_item(tree, hf_ieee802159_mpx_kmp_vendor_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
                break;

            // Unknown
            default:
                expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_ieee802159_mpx_unknown_kmp);
        }
    }
    else if (multiplex_id == IEEE802159_MPX_MULTIPLEX_ID_WISUN) {
        guint8 subid = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_ieee802159_mpx_wisun_subid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        switch (subid) {
            case IEEE802159_MPX_WISUN_SUBID_6LOWPAN:
                dissector = lowpan_handle;
                break;

            case IEEE802159_MPX_WISUN_SUBID_SECURITY:
                dissector = wisun_sec_handle;
                break;

            case IEEE802159_MPX_WISUN_SUBID_MHDS:
                expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_ieee802159_mpx_unsupported_kmp);
                break;

            default:
                expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_ieee802159_mpx_unknown_kmp);
                break;
        }
    }
    else if (multiplex_id > 1500) {
        dissector = dissector_get_uint_handle(ethertype_table, (guint)multiplex_id);
    }

    if (transfer_type == IEEE802159_MPX_FULL_FRAME || transfer_type == IEEE802159_MPX_FULL_FRAME_NO_MUXID) {
        tvbuff_t * payload = tvb_new_subset_remaining(tvb, offset);
        if (dissector) {
            call_dissector(dissector, payload, pinfo, proto_tree_get_root(tree));  // exceptions are caught in our caller
        } else {
            call_data_dissector(payload, pinfo, proto_tree_get_root(tree));
        }
    } else {
        proto_tree_add_item(tree, hf_ieee802159_mpx_fragment, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
    }
    offset = tvb_reported_length(tvb);

    return offset;
}

/**
 * Subdissector for Vendor Specific Payload IEs (Information Elements)
 */
static int
dissect_pie_vendor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ies_tree, void *data _U_)
{
    proto_tree *tree = ieee802154_create_pie_tree(tvb, ies_tree, hf_ieee802154_pie_vendor, ett_ieee802154_pie_vendor);

    guint      offset = 2;
    guint      pie_length = tvb_reported_length(tvb) - 2;
    tvbuff_t  *next_tvb;
    guint32    vendor_oui;

    vendor_oui = tvb_get_letoh24(tvb, offset);
    proto_tree_add_item(tree, hf_ieee802154_pie_vendor_oui, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3; /* adjust for vendor OUI */
    pie_length -= 3;
    next_tvb = tvb_new_subset_length(tvb, offset, pie_length);

    switch (vendor_oui) {
        case OUI_ZIGBEE:
            call_dissector_with_data(zigbee_ie_handle, next_tvb, pinfo, tree, &pie_length);
            break;

        default:
            call_data_dissector(next_tvb, pinfo, tree);
            break;
    }

    return tvb_reported_length(tvb);
}

/**
 * Subdissector for Payload IEs (Information Elements)
 *
 * @param tvb the tv buffer
 * @param pinfo pointer to packet information fields.
 * @param tree the tree to append this item to
 * @param orig_offset offset into the tvbuff to begin dissection.
 * @param packet IEEE 802.15.4 packet information.
*/
static int
dissect_ieee802154_payload_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint orig_offset, ieee802154_packet *packet)
{
    // GCC emits a spurious -Wclobbered if offset is used as function parameter (even with volatile)
    volatile guint offset = orig_offset;
    proto_item *ies_item = proto_tree_add_item(tree, hf_ieee802154_payload_ies, tvb, offset, -1, ENC_NA);
    proto_tree *ies_tree = proto_item_add_subtree(ies_item, ett_ieee802154_payload_ie);

    do {
        volatile int consumed = 0;
        guint16 ie_header = tvb_get_letohs(tvb, offset);
        guint16 id = (guint16) ((ie_header & IEEE802154_PAYLOAD_IE_ID_MASK) >> 11);
        volatile guint16 length = (guint16) (ie_header & IEEE802154_PAYLOAD_IE_LENGTH_MASK);
        tvbuff_t *ie_tvb = tvb_new_subset_length(tvb, offset, 2 + length);

        if (id == IEEE802154_PAYLOAD_IE_TERMINATION) {
            ieee802154_create_pie_tree(ie_tvb, ies_tree, hf_ieee802154_pie_termination, ett_ieee802154_pie_termination);
            consumed = 2;
        } else {
            TRY {
                consumed = dissector_try_uint_new(payload_ie_dissector_table, id, ie_tvb, pinfo, ies_tree, FALSE, packet);
                if (consumed == 0) {
                    proto_tree *subtree = ieee802154_create_pie_tree(ie_tvb, ies_tree, hf_ieee802154_pie_unsupported,
                                                                 ett_ieee802154_pie_unsupported);
                    proto_tree_add_item(subtree, hf_ieee802154_ie_unknown_content, ie_tvb, 2, length, ENC_NA);
                    consumed = 2 + length;
                    expert_add_info(pinfo, proto_tree_get_parent(subtree), &ei_ieee802154_ie_unsupported_id);
                }
            }
            CATCH_ALL {
                show_exception(tvb, pinfo, ies_tree, EXCEPT_CODE, GET_MESSAGE);
                consumed = 2 + length;
            }
            ENDTRY;
        }

        if (consumed < 2 + length) {
            proto_tree_add_item(ies_tree, hf_ieee802154_ie_unknown_content, ie_tvb, consumed, 2 + length - consumed, ENC_NA);
            expert_add_info(pinfo, ies_item, &ei_ieee802154_ie_unknown_extra_content);
        }

        offset += 2 + length;

        if (id == IEEE802154_PAYLOAD_IE_TERMINATION) {
            break;
        }
    } while (tvb_reported_length_remaining(tvb, offset) > 1);

    proto_item_set_len(ies_item, offset - orig_offset);
    return offset - orig_offset;
}

static const true_false_string tfs_cinfo_device_type = { "FFD", "RFD" };
static const true_false_string tfs_cinfo_power_src = { "AC/Mains Power", "Battery" };

/**
 * Command subdissector routine for the Association request command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet IEEE 802.15.4 packet information.
 */

static void
dissect_ieee802154_assoc_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
{
    guint8 cap;
    proto_tree *subtree;
    static int * const capability[] = {
        &hf_ieee802154_cinfo_alt_coord,
        &hf_ieee802154_cinfo_device_type,
        &hf_ieee802154_cinfo_power_src,
        &hf_ieee802154_cinfo_idle_rx,
        &hf_ieee802154_cinfo_sec_capable,
        &hf_ieee802154_cinfo_alloc_addr,
        NULL
    };

    cap = tvb_get_guint8(tvb, 0);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", tfs_get_string(cap & IEEE802154_CMD_CINFO_DEVICE_TYPE, &tfs_cinfo_device_type));

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, 0, 1, ett_ieee802154_cmd, NULL,
                    val_to_str_const(packet->command_id, ieee802154_cmd_names, "Unknown Command"));

    /* Get and display capability info. */
    proto_tree_add_bitmask_list(subtree, tvb, 0, 1, capability, ENC_NA);

    /* Call the data dissector for any leftover bytes. */
    if (tvb_reported_length(tvb) > 1) {
        call_data_dissector(tvb_new_subset_remaining(tvb, 1), pinfo, tree);
    }
} /* dissect_ieee802154_assoc_req */

/**
 * Command subdissector routine for the Association response command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet IEEE 802.15.4 packet information.
 */
static void
dissect_ieee802154_assoc_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
{
    proto_tree *subtree;
    proto_item *ti;
    guint16     short_addr;
    guint8      status;
    guint       offset  = 0;

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_ieee802154_cmd, NULL,
                    val_to_str_const(packet->command_id, ieee802154_cmd_names, "Unknown Command"));

    /* Get and display the short address. */
    short_addr = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(subtree, hf_ieee802154_assoc_addr, tvb, offset, 2, short_addr);
    offset += 2;

    /* Get and display the status. */
    status = tvb_get_guint8(tvb, offset);
    if (tree) {
        ti = proto_tree_add_uint(subtree, hf_ieee802154_assoc_status, tvb, offset, 1, status);
        if (status == IEEE802154_CMD_ASRSP_AS_SUCCESS) proto_item_append_text(ti, " (Association Successful)");
        else if (status == IEEE802154_CMD_ASRSP_PAN_FULL) proto_item_append_text(ti, " (PAN Full)");
        else if (status == IEEE802154_CMD_ASRSP_PAN_DENIED) proto_item_append_text(ti, " (Association Denied)");
        else proto_item_append_text(ti, " (Reserved)");
    }
    offset += 1;

    /* Update the info column. */
    if (status == IEEE802154_CMD_ASRSP_AS_SUCCESS) {
        /* Association was successful. */
        if (packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", PAN: 0x%04x", packet->dst_pan);
        }
        if (short_addr != IEEE802154_NO_ADDR16) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Addr: 0x%04x", short_addr);
        }
    }
    else {
        /* Association was unsuccessful. */
        col_append_str(pinfo->cinfo, COL_INFO, ", Unsuccessful");
    }

    /* Update the address table. */
    if ((status == IEEE802154_CMD_ASRSP_AS_SUCCESS) && (short_addr != IEEE802154_NO_ADDR16)) {
        ieee802154_addr_update(&ieee802154_map, short_addr, packet->dst_pan, packet->dst64,
                pinfo->current_proto, pinfo->num);
    }

    /* Call the data dissector for any leftover bytes. */
    if (tvb_captured_length(tvb) > offset) {
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
    }
} /* dissect_ieee802154_assoc_rsp */

/**
 * Command subdissector routine for the Disassociate command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet IEEE 802.15.4 packet information.
 */
static void
dissect_ieee802154_disassoc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
{
    proto_tree *subtree;
    proto_item *ti;
    guint8      reason;

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, 0, 1, ett_ieee802154_cmd, NULL,
                    val_to_str_const(packet->command_id, ieee802154_cmd_names, "Unknown Command"));

    /* Get and display the disassociation reason. */
    reason = tvb_get_guint8(tvb, 0);
    if (tree) {
        ti = proto_tree_add_uint(subtree, hf_ieee802154_disassoc_reason, tvb, 0, 1, reason);
        switch (reason) {
            case 0x01:
                proto_item_append_text(ti, " (Coordinator requests device to leave)");
                break;

            case 0x02:
                proto_item_append_text(ti, " (Device wishes to leave)");
                break;

            default:
                proto_item_append_text(ti, " (Reserved)");
                break;
        } /* switch */
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        /* Update the address tables */
        if ( packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT ) {
            ieee802154_long_addr_invalidate(packet->dst64, pinfo->num);
        } else if ( packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT ) {
            ieee802154_short_addr_invalidate(packet->dst16, packet->dst_pan, pinfo->num);
        }
    }

    /* Call the data dissector for any leftover bytes. */
    if (tvb_captured_length(tvb) > 1) {
        call_data_dissector(tvb_new_subset_remaining(tvb, 1), pinfo, tree);
    }
} /* dissect_ieee802154_disassoc */

/**
 * Command subdissector routine for the Coordinator Realignment command.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to protocol tree.
 * @param packet IEEE 802.15.4 packet information.
 */
static void
dissect_ieee802154_realign(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
{
    proto_tree *subtree;
    proto_item *subitem;
    guint16     pan_id;
    guint16     coord_addr;
    guint8      channel;
    guint16     short_addr;
    guint       offset  = 0;

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_ieee802154_cmd, &subitem,
                val_to_str_const(packet->command_id, ieee802154_cmd_names, "Unknown Command"));

    /* Get and display the command PAN ID. */
    pan_id = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(subtree, hf_ieee802154_realign_pan, tvb, offset, 2, pan_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", PAN: 0x%04x", pan_id);
    offset += 2;

    /* Get and display the coordinator address. */
    coord_addr = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(subtree, hf_ieee802154_realign_caddr, tvb, offset, 2, coord_addr);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Coordinator: 0x%04x", coord_addr);
    offset += 2;

    /* Get and display the channel. */
    channel = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(subtree, hf_ieee802154_realign_channel, tvb, offset, 1, channel);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Channel: %u", channel);
    offset += 1;

    /* Get and display the short address. */
    short_addr = tvb_get_letohs(tvb, offset);
    if (tree) proto_tree_add_uint(subtree, hf_ieee802154_realign_addr, tvb, offset, 2, short_addr);
    if ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)
        && (short_addr != IEEE802154_NO_ADDR16)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Addr: 0x%04x", short_addr);
    }
    offset += 2;
    /* Update the address table. */
    if ((short_addr != IEEE802154_NO_ADDR16) && (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)) {
        ieee802154_addr_update(&ieee802154_map, short_addr, packet->dst_pan, packet->dst64,
                pinfo->current_proto, pinfo->num);
    }

    /* Get and display the channel page, if it exists. Added in IEEE802.15.4-2006 */
    if (tvb_bytes_exist(tvb, offset, 1)) {
        guint8  channel_page = tvb_get_guint8(tvb, offset);
        if (tree) proto_tree_add_uint(subtree, hf_ieee802154_realign_channel_page, tvb, offset, 1, channel_page);
        offset += 1;
    }

    /* Fix the length of the command subtree. */
    if (tree) {
        proto_item_set_len(subitem, offset);
    }

    /* Call the data dissector for any leftover bytes. */
    if (tvb_captured_length(tvb) > offset) {
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
    }
} /* dissect_ieee802154_realign */

static const true_false_string tfs_gtsreq_dir = { "Receive", "Transmit" };
static const true_false_string tfs_gtsreq_type= { "Allocate GTS", "Deallocate GTS" };

/**
 * Command subdissector routine for the GTS request command.
 *
 * Assumes that COL_INFO will be set to the command name,
 * command name will already be appended to the command subtree
 * and protocol root. In addition, assumes that the command ID
 * has already been parsed.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields (unused).
 * @param tree pointer to protocol tree.
 * @param packet IEEE 802.15.4 packet information (unused).
 */

static void
dissect_ieee802154_gtsreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
{
    proto_tree *subtree;
    static int * const characteristics[] = {
        &hf_ieee802154_gtsreq_len,
        &hf_ieee802154_gtsreq_dir,
        &hf_ieee802154_gtsreq_type,
        NULL
    };

    /* Create a subtree for this command frame. */
    subtree = proto_tree_add_subtree(tree, tvb, 0, 1, ett_ieee802154_cmd, NULL,
                val_to_str_const(packet->command_id, ieee802154_cmd_names, "Unknown Command"));

    proto_tree_add_bitmask_list(subtree, tvb, 0, 1, characteristics, ENC_NA);

    /* Call the data dissector for any leftover bytes. */
    if (tvb_reported_length(tvb) > 1) {
        call_data_dissector(tvb_new_subset_remaining(tvb, 1), pinfo, tree);
    }
} /* dissect_ieee802154_gtsreq */

/**
 * Subdissector routine for IEEE 802.15.4 commands
 *
 * @param tvb pointer to buffer containing the command payload
 * @param pinfo pointer to packet information fields
 * @param tree pointer to the protocol tree
 * @param packet IEEE 802.15.4 packet information
 */
static void
dissect_ieee802154_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
{
    if ((packet->version == IEEE802154_VERSION_2015) && (packet->frame_type == IEEE802154_FCF_CMD)) {
        /* In 802.15.4e and later the Command Id follows the Payload IEs. */
        packet->command_id = tvb_get_guint8(tvb, 0);
        proto_tree_add_uint(tree, hf_ieee802154_cmd_id, tvb, 0, 1, packet->command_id);
        tvb = tvb_new_subset_remaining(tvb, 1);

        /* Display the command identifier in the info column. */
        if ((packet->version == IEEE802154_VERSION_2015) && (packet->command_id == IEEE802154_CMD_BEACON_REQ)) {
            col_set_str(pinfo->cinfo, COL_INFO, "Enhanced Beacon Request");
        }
        else {
            col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet->command_id, ieee802154_cmd_names, "Unknown Command"));
        }
    }

    switch (packet->command_id) {
    case IEEE802154_CMD_ASSOC_REQ:
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
            (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&
            (packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE));
        dissect_ieee802154_assoc_req(tvb, pinfo, tree, packet);
        break;

    case IEEE802154_CMD_ASSOC_RSP:
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
            (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&
            (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT));
        dissect_ieee802154_assoc_rsp(tvb, pinfo, tree, packet);
        break;

    case IEEE802154_CMD_DISASSOC_NOTIFY:
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
            (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&
            (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT));
        dissect_ieee802154_disassoc(tvb, pinfo, tree, packet);
        break;

    case IEEE802154_CMD_DATA_RQ:
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id, packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE);
        /* No payload expected. */
        break;

    case IEEE802154_CMD_PANID_CONFLICT:
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
            (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&
            (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT));
        /* No payload expected. */
        break;

    case IEEE802154_CMD_ORPHAN_NOTIFY:
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
            (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&
            (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&
            (packet->dst16 == IEEE802154_BCAST_ADDR) &&
            (packet->src_pan == IEEE802154_BCAST_PAN) &&
            (packet->dst_pan == IEEE802154_BCAST_PAN));
        /* No payload expected. */
        break;

    case IEEE802154_CMD_BEACON_REQ:
        if ((packet->version == IEEE802154_VERSION_2003) || (packet->version == IEEE802154_VERSION_2006)) {
            IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
                    (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&
                    (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) &&
                    (packet->dst16 == IEEE802154_BCAST_ADDR) &&
                    (packet->dst_pan == IEEE802154_BCAST_PAN));
        }
        /* No payload expected. */
        break;

    case IEEE802154_CMD_COORD_REALIGN:
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
            (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) &&
            (packet->dst_pan == IEEE802154_BCAST_PAN) &&
            (packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE));
        if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
            /* If directed to a 16-bit address, check that it is being broadcast. */
            IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id, packet->dst16 == IEEE802154_BCAST_ADDR);
        }
        dissect_ieee802154_realign(tvb, pinfo, tree, packet);
        break;

    case IEEE802154_CMD_GTS_REQ:
        /* Check that the addressing is correct for this command type. */
        IEEE802154_CMD_ADDR_CHECK(pinfo, tree, packet->command_id,
            (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) &&
            (packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) &&
            (packet->src16 != IEEE802154_BCAST_ADDR) &&
            (packet->src16 != IEEE802154_NO_ADDR16));
        dissect_ieee802154_gtsreq(tvb, pinfo, tree, packet);
        break;

    case IEEE802154_CMD_VENDOR_SPECIFIC:
    {
        guint32 oui = tvb_get_ntoh24(tvb, 0);
        if (!dissector_try_uint_new(cmd_vendor_dissector_table, oui, tvb, pinfo, tree, FALSE, packet)) {
            proto_tree_add_item(tree, hf_ieee802154_cmd_vendor_oui, tvb, 0, 3, ENC_BIG_ENDIAN);
            call_data_dissector(tvb_new_subset_remaining(tvb, 3), pinfo, tree);
        }
        break;
    }

    case IEEE802154_CMD_TRLE_MGMT_REQ:
    case IEEE802154_CMD_TRLE_MGMT_RSP:
    case IEEE802154_CMD_DSME_ASSOC_REQ:
    case IEEE802154_CMD_DSME_ASSOC_RSP:
    case IEEE802154_CMD_DSME_GTS_REQ:
    case IEEE802154_CMD_DSME_GTS_RSP:
    case IEEE802154_CMD_DSME_GTS_NOTIFY:
    case IEEE802154_CMD_DSME_INFO_REQ:
    case IEEE802154_CMD_DSME_INFO_RSP:
    case IEEE802154_CMD_DSME_BEACON_ALLOC_NOTIFY:
    case IEEE802154_CMD_DSME_BEACON_COLL_NOTIFY:
    case IEEE802154_CMD_DSME_LINK_REPORT:
    case IEEE802154_CMD_RIT_DATA_REQ:
    case IEEE802154_CMD_DBS_REQ:
    case IEEE802154_CMD_DBS_RSP:
    case IEEE802154_CMD_RIT_DATA_RSP:
        /* TODO add support for these commands, for now if anything remains, dump it */
        expert_add_info(pinfo, tree, &ei_ieee802154_unsupported_cmd);
        if (tvb_captured_length_remaining(tvb, 0) > 0) {
            call_data_dissector(tvb, pinfo, tree);
        }
        break;
    default:
        expert_add_info(pinfo, tree, &ei_ieee802154_unknown_cmd);
        if (tvb_captured_length_remaining(tvb, 0) > 0) {
            call_data_dissector(tvb, pinfo, tree);
        }
    } /* switch */
} /* dissect_ieee802154_command */

/**
 * IEEE 802.15.4 decryption algorithm
 * @param tvb IEEE 802.15.4 packet, not including the FCS or metadata trailer.
 * @param pinfo Packet info structure.
 * @param offset Offset where the ciphertext 'c' starts.
 * @param packet IEEE 802.15.4 packet information.
 * @return decrypted payload.
 */
static tvbuff_t *
dissect_ieee802154_decrypt(tvbuff_t *tvb,
                           guint offset,
                           packet_info *pinfo,
                           ieee802154_packet *packet,
                           ieee802154_decrypt_info_t* decrypt_info)
{
    tvbuff_t           *ptext_tvb;
    gboolean            have_mic = FALSE;
    guint64             srcAddr = 0;
    unsigned char       tmp[IEEE802154_CIPHER_SIZE];
    guint               M;
    gint                captured_len;
    gint                reported_len;
    ieee802154_hints_t *ieee_hints;
    gchar              *generic_nonce_ptr = NULL;
    gchar               generic_nonce[13];

    ieee_hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ieee802154, 0);

    /* Get the captured and on-the-air length of the payload. */
    M = IEEE802154_MIC_LENGTH(packet->security_level);
    *decrypt_info->rx_mic_length = M;

    /* Is the MIC larger than the total amount of data? */
    reported_len = tvb_reported_length_remaining(tvb, offset) - M;
    if (reported_len < 0) {
        /* Yes.  Give up. */
        *decrypt_info->status = DECRYPT_PACKET_TOO_SMALL;
        return NULL;
    }
    /* Check whether the payload is truncated by a snapshot length. */
    if (tvb_bytes_exist(tvb, offset, reported_len)) {
        /* It's not, so we have all of the payload. */
        captured_len = reported_len;
    }
    else {
        /*
         * It is, so we don't have all of the payload - and we don't
         * have the MIC, either, as that comes after the payload.
         * As the MIC isn't part of the captured data - the captured
         * data was cut short before the first byte of the MIC - we
         * don't subtract the length of the MIC from the amount of
         * captured data.
         */
        captured_len = tvb_captured_length_remaining(tvb, offset);
    }

    /* Check if the MIC is present in the captured data. */
    have_mic = tvb_bytes_exist(tvb, offset + reported_len, M);
    if (have_mic) {
        /* It is - save a copy of it. */
        tvb_memcpy(tvb, decrypt_info->rx_mic, offset + reported_len, M);
    }

    /* We need the extended source address. */
    if ((packet->key_index == IEEE802154_THR_WELL_KNOWN_KEY_INDEX) &&
        (packet->key_source.addr32 == IEEE802154_THR_WELL_KNOWN_KEY_SRC))
    {
        /* Use the well-known extended address */
        srcAddr = IEEE802154_THR_WELL_KNOWN_EXT_ADDR;
    } else {
        if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
            /* The source EUI-64 is included in the headers. */
            srcAddr = packet->src64;
        }
        else if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT && packet->frame_counter_suppression) {
            /* In TSCH mode, the source address is a combination of 802.15 CID, PAN ID and Short Address */
            srcAddr = IEEE80215_CID << 40;
            srcAddr |= ((guint64)packet->src_pan & 0xffff) << 16;
            srcAddr |= packet->src16;
        }
        else if (ieee_hints && ieee_hints->map_rec && ieee_hints->map_rec->addr64) {
            /* Use the hint */
            srcAddr = ieee_hints->map_rec->addr64;
        }
        else {
            /* Lookup failed.  */
            *decrypt_info->status = DECRYPT_PACKET_NO_EXT_SRC_ADDR;
            return NULL;
        }
    }

    /*
     * CCM* - CTR mode payload encryption
     *
     */
    /* 802.15.4-2015 TSCH mode */
    if (packet->frame_counter_suppression) {
        tsch_ccm_init_nonce(srcAddr, packet->asn, generic_nonce);
        generic_nonce_ptr = generic_nonce;
    }

    /* Create the CCM* initial block for decryption (Adata=0, M=0, counter=0). */
    if (packet->version == IEEE802154_VERSION_2003)
        ccm_init_block(tmp, FALSE, 0, srcAddr, packet->frame_counter, packet->key_sequence_counter, 0, NULL);
    else
        ccm_init_block(tmp, FALSE, 0, srcAddr, packet->frame_counter, packet->security_level, 0, generic_nonce_ptr);

    /*
     * If the payload is encrypted, so that it's the ciphertext, and we
     * have at least one byte of it in the captured data, decrypt the
     * ciphertext, and place the plaintext in a new tvb.
     */
    if (IEEE802154_IS_ENCRYPTED(packet->security_level) && captured_len) {
        guint8 *text;
        /*
         * Make a copy of the ciphertext in heap memory.
         *
         * We will decrypt the message in-place and then use the buffer as the
         * real data for the new tvb.
         */
        text = (guint8 *)tvb_memdup(pinfo->pool, tvb, offset, captured_len);

        /* Perform CTR-mode transformation. */
        if (!ccm_ctr_encrypt(decrypt_info->key, tmp, decrypt_info->rx_mic, text, captured_len)) {
            wmem_free(pinfo->pool, text);
            *decrypt_info->status = DECRYPT_PACKET_DECRYPT_FAILED;
            return NULL;
        }

        /* Create a tvbuff for the plaintext. */
        ptext_tvb = tvb_new_child_real_data(tvb, text, captured_len, reported_len);
        add_new_data_source(pinfo, ptext_tvb, "Decrypted IEEE 802.15.4 payload");
        *decrypt_info->status = DECRYPT_PACKET_SUCCEEDED;
    }
    else {
        /*
         * Either the payload isn't encrypted or we don't have any of it
         * in the captured data.
         */
        /* Decrypt the MIC (if present). */
        if ((have_mic) && (!ccm_ctr_encrypt(decrypt_info->key, tmp, decrypt_info->rx_mic, NULL, 0))) {
            *decrypt_info->status = DECRYPT_PACKET_DECRYPT_FAILED;
            return NULL;
        }

        /* Create a tvbuff for the plaintext. This might result in a zero-length tvbuff. */
        ptext_tvb = tvb_new_subset_length_caplen(tvb, offset, captured_len, reported_len);
        *decrypt_info->status = DECRYPT_PACKET_SUCCEEDED;
    }

    /*
     * CCM* - CBC-mode message authentication
     *
     */
    /* We can only verify the message if the MIC wasn't truncated. */
    if (have_mic) {
        unsigned char           dec_mic[16];
        guint                   l_m = captured_len;
        guint                   l_a = offset;

        /* Adjust the lengths of the plaintext and additional data if unencrypted. */
        if (!IEEE802154_IS_ENCRYPTED(packet->security_level)) {
            l_a += l_m;
            l_m = 0;
        }
        else if ((packet->version == IEEE802154_VERSION_2003) && !ieee802154_extend_auth)
            l_a -= 5;   /* Exclude Frame Counter (4 bytes) and Key Sequence Counter (1 byte) from authentication data */


        /* Create the CCM* initial block for authentication (Adata!=0, M!=0, counter=l(m)). */
        if (packet->version == IEEE802154_VERSION_2003)
            ccm_init_block(tmp, TRUE, M, srcAddr, packet->frame_counter, packet->key_sequence_counter, l_m, NULL);
        else
            ccm_init_block(tmp, TRUE, M, srcAddr, packet->frame_counter, packet->security_level, l_m, generic_nonce_ptr);

        /* Compute CBC-MAC authentication tag. */
        /*
         * And yes, despite the warning in tvbuff.h, I think tvb_get_ptr is the
         * right function here since either A) the payload wasn't encrypted, in
         * which case l_m is zero, or B) the payload was encrypted, and the tvb
         * already points to contiguous memory, since we just allocated it in
         * decryption phase.
         */
        memset(dec_mic, 0, sizeof(dec_mic));
        if (!ccm_cbc_mac(decrypt_info->key, tmp, (const gchar *)tvb_memdup(pinfo->pool, tvb, 0, l_a), l_a, tvb_get_ptr(ptext_tvb, 0, l_m), l_m, dec_mic)) {
            *decrypt_info->status = DECRYPT_PACKET_MIC_CHECK_FAILED;
        }
        /* Compare the received MIC with the one we generated. */
        else if (memcmp(decrypt_info->rx_mic, dec_mic, M) != 0) {
            *decrypt_info->status = DECRYPT_PACKET_MIC_CHECK_FAILED;
        }
    }

    /* Done! */
    return ptext_tvb;
} /* dissect_ieee802154_decrypt */

/**
 * Creates the CCM* initial block value for IEEE 802.15.4.
 *
 * @param block Output pointer for the initial block.
 * @param adata TRUE if additional auth data is present
 * @param M CCM* parameter M.
 * @param addr Source extended address.
 * @param frame_counter Packet frame counter
 * @param level Security level or key_sequence_counter for 802.15.4-2003
 * @param ctr_val Value in the last L bytes of the block.
 * @param generic_nonce 13-byte nonce to be set by non 802.15.4 calls. If set addr, frame_counter and level are ignored.
 */
void
ccm_init_block(gchar *block, gboolean adata, gint M, guint64 addr, guint32 frame_counter, guint8 level, gint ctr_val, const gchar *generic_nonce)
{
    gint                i = 0;

    /* Flags: Reserved(0) || Adata || (M-2)/2 || (L-1) */
    block[i] = (0x2 - 1); /* (L-1) */
    if (M > 0) block[i] |= (((M-2)/2) << 3); /* (M-2)/2 */
    if (adata) block[i] |= (1 << 6); /* Adata */
    i++;
    if (generic_nonce == NULL) {
        /* 2003 CCM Nonce:  Source Address || Frame Counter || Key Sequence Counter */
        /* 2006 CCM* Nonce: Source Address || Frame Counter || Security Level */
        block[i++] = (guint8)((addr >> 56) & 0xff);
        block[i++] = (guint8)((addr >> 48) & 0xff);
        block[i++] = (guint8)((addr >> 40) & 0xff);
        block[i++] = (guint8)((addr >> 32) & 0xff);
        block[i++] = (guint8)((addr >> 24) & 0xff);
        block[i++] = (guint8)((addr >> 16) & 0xff);
        block[i++] = (guint8)((addr >> 8) & 0xff);
        block[i++] = (guint8)((addr >> 0) & 0xff);
        block[i++] = (guint8)((frame_counter >> 24) & 0xff);
        block[i++] = (guint8)((frame_counter >> 16) & 0xff);
        block[i++] = (guint8)((frame_counter >> 8) & 0xff);
        block[i++] = (guint8)((frame_counter >> 0) & 0xff);
        block[i++] = level;
    } else {
        memcpy(&block[i], generic_nonce, 13);
        i += 13;
    }
    /* Plaintext length. */
    block[i++] = (guint8)((ctr_val >> 8) & 0xff);
    block[i] = (guint8)((ctr_val >> 0) & 0xff);
} /* ccm_init_block */

/**
 * Creates the IEEE 802.15.4 TSCH nonce.
 *
 * @param addr Source extended address.
 * @param asn TSCH Absolute Slot Number
 * @param generic_nonce 13-byte nonce to returned by this function.
 */
static void
tsch_ccm_init_nonce(guint64 addr, guint64 asn, gchar* generic_nonce)
{
    gint i = 0;

    /* 2015 CCM* Nonce: Source Address || ASN */
    generic_nonce[i++] = (guint8)((addr >> 56) & 0xff);
    generic_nonce[i++] = (guint8)((addr >> 48) & 0xff);
    generic_nonce[i++] = (guint8)((addr >> 40) & 0xff);
    generic_nonce[i++] = (guint8)((addr >> 32) & 0xff);
    generic_nonce[i++] = (guint8)((addr >> 24) & 0xff);
    generic_nonce[i++] = (guint8)((addr >> 16) & 0xff);
    generic_nonce[i++] = (guint8)((addr >> 8) & 0xff);
    generic_nonce[i++] = (guint8)((addr >> 0) & 0xff);
    generic_nonce[i++] = (guint8)((asn >> 32) & 0xff);
    generic_nonce[i++] = (guint8)((asn >> 24) & 0xff);
    generic_nonce[i++] = (guint8)((asn >> 16) & 0xff);
    generic_nonce[i++] = (guint8)((asn >> 8) & 0xff);
    generic_nonce[i++] = (guint8)((asn >> 0) & 0xff);
} /* tsch_ccm_init_nonce */

/**
 * Perform an in-place CTR-mode encryption/decryption.
 *
 * @param key Encryption Key.
 * @param iv Counter initial value.
 * @param mic MIC to encrypt/decrypt.
 * @param data Buffer to encrypt/decrypt.
 * @param length Length of the buffer.
 * @return TRUE on SUCCESS, FALSE on error.
 */
gboolean
ccm_ctr_encrypt(const gchar *key, const gchar *iv, gchar *mic, gchar *data, gint length)
{
    gcry_cipher_hd_t    cipher_hd;

    /* Open the cipher. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
        return FALSE;
    }

    /* Set the key and initial value. */
    if (gcry_cipher_setkey(cipher_hd, key, 16)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    if (gcry_cipher_setctr(cipher_hd, iv, 16)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    /* Decrypt the MIC. */
    if (gcry_cipher_encrypt(cipher_hd, mic, 16, NULL, 0)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Decrypt the payload. */
    if (gcry_cipher_encrypt(cipher_hd, data, length, NULL, 0)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    /* Done with the cipher. */
    gcry_cipher_close(cipher_hd);
    return TRUE;
} /* ccm_ctr_encrypt */

/**
 * Generate a CBC-MAC of the decrypted payload and additional authentication headers.
 * @param key Encryption Key.
 * @param iv Counter initial value.
 * @param a Additional auth headers.
 * @param a_len Length of the additional headers.
 * @param m Plaintext message.
 * @param m_len Length of plaintext message.
 * @param mic Output for CBC-MAC.
 * @return  TRUE on SUCCESS, FALSE on error.
 */
gboolean
ccm_cbc_mac(const gchar *key, const gchar *iv, const gchar *a, gint a_len, const gchar *m, gint m_len, gchar *mic)
{
    gcry_cipher_hd_t cipher_hd;
    guint            i = 0;
    unsigned char    block[IEEE802154_CIPHER_SIZE];

    /* Open the cipher. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_MAC)) return FALSE;

    /* Set the key. */
    if (gcry_cipher_setkey(cipher_hd, key, IEEE802154_CIPHER_SIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    /* Process the initial value. */
    if (gcry_cipher_encrypt(cipher_hd, mic, 16, iv, 16)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    /* Encode L(a) */
    i = 0;

/* XXX: GINT_MAX is not defined so #if ... will always be false */
#if (GINT_MAX >= (1LL << 32))
    if (a_len >= (1LL << 32)) {
        block[i++] = 0xff;
        block[i++] = 0xff;
        block[i++] = (a_len >> 56) & 0xff;
        block[i++] = (a_len >> 48) & 0xff;
        block[i++] = (a_len >> 40) & 0xff;
        block[i++] = (a_len >> 32) & 0xff;
        block[i++] = (a_len >> 24) & 0xff;
        block[i++] = (a_len >> 16) & 0xff;
        block[i++] = (a_len >> 8) & 0xff;
        block[i++] = (a_len >> 0) & 0xff;
    }
    else
#endif
    if (a_len >= ((1 << 16) - (1 << 8))) {
        block[i++] = 0xff;
        block[i++] = 0xfe;
        block[i++] = (a_len >> 24) & 0xff;
        block[i++] = (a_len >> 16) & 0xff;
        block[i++] = (a_len >> 8) & 0xff;
        block[i++] = (a_len >> 0) & 0xff;
    }
    else {
        block[i++] = (a_len >> 8) & 0xff;
        block[i++] = (a_len >> 0) & 0xff;
    }
    /* Append a to get the first block of input (pad if we encounter the end of a). */
    while ((i < sizeof(block)) && (a_len > 0)) {
        block[i++] = *a++;
        a_len--;
    }
    while (i < sizeof(block)) {
        block[i++] = 0;
    }

    /* Process the first block of AuthData. */
    if (gcry_cipher_encrypt(cipher_hd, mic, 16, block, 16)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    /* Transform and process the remainder of a. */
    while (a_len > 0) {
        /* Copy and pad. */
        if ((guint)a_len >= sizeof(block)) {
            memcpy(block, a, sizeof(block));
        }
        else {
            memcpy(block, a, a_len);
            memset(block+a_len, 0, sizeof(block)-a_len);
        }
        /* Adjust pointers. */
        a += sizeof(block);
        a_len -= (int)sizeof(block);
        /* Execute the CBC-MAC algorithm. */
        if (gcry_cipher_encrypt(cipher_hd, mic, 16, block, sizeof(block))) {
            gcry_cipher_close(cipher_hd);
            return FALSE;
        }
    } /* while */

    /* Process the message, m. */
    while (m_len > 0) {
        /* Copy and pad. */
        if ((guint)m_len >= sizeof(block)) {
            memcpy(block, m, sizeof(block));
        }
        else {
            memcpy(block, m, m_len);
            memset(block+m_len, 0, sizeof(block)-m_len);
        }
        /* Adjust pointers. */
        m += sizeof(block);
        m_len -= (int)sizeof(block);
        /* Execute the CBC-MAC algorithm. */
        if (gcry_cipher_encrypt(cipher_hd, mic, 16, block, sizeof(block))) {
            gcry_cipher_close(cipher_hd);
            return FALSE;
        }
    }

    /* Done with the cipher. */
    gcry_cipher_close(cipher_hd);
    return TRUE;
} /* ccm_cbc_mac */

/* Key hash function. */
guint ieee802154_short_addr_hash(gconstpointer key)
{
    return (((const ieee802154_short_addr *)key)->addr) | (((const ieee802154_short_addr *)key)->pan << 16);
}

/* Key equal function. */
gboolean ieee802154_short_addr_equal(gconstpointer a, gconstpointer b)
{
    return (((const ieee802154_short_addr *)a)->pan == ((const ieee802154_short_addr *)b)->pan) &&
           (((const ieee802154_short_addr *)a)->addr == ((const ieee802154_short_addr *)b)->addr);
}

/* Key hash function. */
guint ieee802154_long_addr_hash(gconstpointer key)
{
    return (guint)(((const ieee802154_long_addr *)key)->addr) & 0xFFFFFFFF;
}

/* Key equal function. */
gboolean ieee802154_long_addr_equal(gconstpointer a, gconstpointer b)
{
    return (((const ieee802154_long_addr *)a)->addr == ((const ieee802154_long_addr *)b)->addr);
}

/* Set MAC key function. */
static guint ieee802154_set_mac_key(ieee802154_packet *packet, unsigned char *key, unsigned char *alt_key, ieee802154_key_t *uat_key)
{
    ieee802154_set_key_func func = (ieee802154_set_key_func)wmem_tree_lookup32(mac_key_hash_handlers, uat_key->hash_type);

    if (func != NULL)
        return func(packet, key, alt_key, uat_key);

    /* Right now, KEY_HASH_NONE and KEY_HASH_ZIP are not registered because they
        work with this "default" behavior */
    if (packet->key_index == uat_key->key_index)
    {
        memcpy(key, uat_key->key, IEEE802154_CIPHER_SIZE);
        return 1;
    }

    return 0;
}

/**
 * Creates a record that maps the given short address and pan to a long (extended) address.
 * @param short_addr 16-bit short address
 * @param pan 16-bit PAN id
 * @param long_addr 64-bit long (extended) address
 * @param proto pointer to name of current protocol
 * @param fnum Frame number this mapping became valid
 * @return TRUE Record was updated, FALSE Couldn't find it
 */
ieee802154_map_rec *ieee802154_addr_update(ieee802154_map_tab_t *au_ieee802154_map,
        guint16 short_addr, guint16 pan, guint64 long_addr, const char *proto, guint fnum)
{
    ieee802154_short_addr  addr16;
    ieee802154_map_rec    *p_map_rec;
    gpointer               old_key;

    /* Look up short address hash */
    addr16.pan = pan;
    addr16.addr = short_addr;
    p_map_rec = (ieee802154_map_rec *)g_hash_table_lookup(au_ieee802154_map->short_table, &addr16);

    /* Update mapping record */
    if (p_map_rec) {
        /* record already exists */
        if ( p_map_rec->addr64 == long_addr ) {
            /* no change */
            return p_map_rec;
        }
        else {
            /* mark current mapping record invalid */
            p_map_rec->end_fnum = fnum;
        }
    }

    /* create a new mapping record */
    p_map_rec = wmem_new(wmem_file_scope(), ieee802154_map_rec);
    p_map_rec->proto = proto;
    p_map_rec->start_fnum = fnum;
    p_map_rec->end_fnum = 0;
    p_map_rec->addr64 = long_addr;

    /* link new mapping record to addr hash tables */
    if ( g_hash_table_lookup_extended(au_ieee802154_map->short_table, &addr16, &old_key, NULL) ) {
        /* update short addr hash table, reusing pointer to old key */
        g_hash_table_insert(au_ieee802154_map->short_table, old_key, p_map_rec);
    } else {
        /* create new hash entry */
        g_hash_table_insert(au_ieee802154_map->short_table, wmem_memdup(wmem_file_scope(), &addr16, sizeof(addr16)), p_map_rec);
    }

    if ( g_hash_table_lookup_extended(au_ieee802154_map->long_table, &long_addr, &old_key, NULL) ) {
        /* update long addr hash table, reusing pointer to old key */
        g_hash_table_insert(au_ieee802154_map->long_table, old_key, p_map_rec);
    } else {
        /* create new hash entry */
        g_hash_table_insert(au_ieee802154_map->long_table, wmem_memdup(wmem_file_scope(), &long_addr, sizeof(long_addr)), p_map_rec);
    }

    return p_map_rec;
} /* ieee802154_addr_update */

/**
 * Marks a mapping record associated with device with short_addr
 * as invalid at a certain frame number, typically when a
 * disassociation occurs.
 *
 * @param short_addr 16-bit short address
 * @param pan 16-bit PAN id
 * @param fnum Frame number when mapping became invalid
 * @return TRUE Record was updated, FALSE Couldn't find it
 */
gboolean ieee802154_short_addr_invalidate(guint16 short_addr, guint16 pan, guint fnum)
{
    ieee802154_short_addr  addr16;
    ieee802154_map_rec    *map_rec;

    addr16.pan = pan;
    addr16.addr = short_addr;

    map_rec = (ieee802154_map_rec *)g_hash_table_lookup(ieee802154_map.short_table, &addr16);
    if ( map_rec ) {
        /* indicates this mapping is invalid at frame fnum */
        map_rec->end_fnum = fnum;
        return TRUE;
    }

    return FALSE;
} /* ieee802154_short_addr_invalidate */

/**
 * Mark a mapping record associated with device with long_addr
 * as invalid at a certain frame number, typically when a
 * disassociation occurs.
 *
 * @param long_addr 16-bit short address
 * @param fnum Frame number when mapping became invalid
 * @return TRUE If record was updated, FALSE otherwise
 */
gboolean ieee802154_long_addr_invalidate(guint64 long_addr, guint fnum)
{
    ieee802154_map_rec   *map_rec;

    map_rec = (ieee802154_map_rec *)g_hash_table_lookup(ieee802154_map.long_table, &long_addr);
    if ( map_rec ) {
        /* indicates this mapping is invalid at frame fnum */
        map_rec->end_fnum = fnum;
        return TRUE;
    }

    return FALSE;
} /* ieee802154_long_addr_invalidate */

/**
 * Init routine for the IEEE 802.15.4 dissector. Creates hash
 * tables for mapping between 16-bit to 64-bit addresses and
 * populates them with static address pairs from a UAT
 * preference table.
 */
static void
proto_init_ieee802154(void)
{
    guint       i;

    ieee802154_map.short_table = g_hash_table_new(ieee802154_short_addr_hash, ieee802154_short_addr_equal);
    ieee802154_map.long_table = g_hash_table_new(ieee802154_long_addr_hash, ieee802154_long_addr_equal);
    /* Reload the hash table from the static address UAT. */
    for (i=0; (i<num_static_addrs) && (static_addrs); i++) {
        ieee802154_addr_update(&ieee802154_map,(guint16)static_addrs[i].addr16, (guint16)static_addrs[i].pan,
               pntoh64(static_addrs[i].eui64), ieee802154_user, IEEE802154_USER_MAPPING);
    } /* for */
} /* proto_init_ieee802154 */

/**
 * Cleanup for the IEEE 802.15.4 dissector.
 */
static void
proto_cleanup_ieee802154(void)
{
    g_hash_table_destroy(ieee802154_map.short_table);
    g_hash_table_destroy(ieee802154_map.long_table);
}

/* Returns the prompt string for the Decode-As dialog. */
static void ieee802154_da_prompt(packet_info *pinfo _U_, gchar* result)
{
    ieee802154_hints_t *hints;
    hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ieee802154, 0);
    if (hints)
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "IEEE 802.15.4 PAN 0x%04x as", hints->src_pan);
    else
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "IEEE 802.15.4 PAN Unknown");
} /* iee802154_da_prompt */

/* Returns the value to index the panid decode table with (source PAN)*/
static gpointer ieee802154_da_value(packet_info *pinfo _U_)
{
    ieee802154_hints_t *hints;
    hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ieee802154, 0);
    if (hints)
        return GUINT_TO_POINTER((guint)(hints->src_pan));
    else
        return NULL;
} /* iee802154_da_value */

static const char* ieee802154_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == ieee802_15_4_short_address_type)
            return "wpan.src16";
        else if (conv->src_address.type == AT_EUI64)
            return "wpan.src64";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == ieee802_15_4_short_address_type)
            return "wpan.dst16";
        else if (conv->dst_address.type == AT_EUI64)
            return "wpan.dst64";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == ieee802_15_4_short_address_type)
            return "wpan.addr16";
        else if (conv->src_address.type == AT_EUI64)
            return "wpan.addr64";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t ieee802154_ct_dissector_info = {&ieee802154_conv_get_filter_type };

static tap_packet_status ieee802154_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*)pct;
    hash->flags = flags;

    add_conversation_table_data(hash, &pinfo->dl_src, &pinfo->dl_dst, 0, 0, 1,
            pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
            &ieee802154_ct_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static const char* ieee802154_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if (filter == CONV_FT_ANY_ADDRESS) {
        if (host->myaddress.type == ieee802_15_4_short_address_type)
            return "wpan.addr16";
        else if (host->myaddress.type == AT_EUI64)
            return "wpan.addr64";
    }

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t ieee802154_host_dissector_info = {&ieee802154_host_get_filter_type };

static tap_packet_status ieee802154_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*)pit;
    hash->flags = flags;

    /* Take two "add" passes per packet, adding for each direction, ensures that all
     packets are counted properly (even if address is sending to itself)
     XXX - this could probably be done more efficiently inside hostlist_table */
    add_hostlist_table_data(hash, &pinfo->dl_src, 0, TRUE, 1,
            pinfo->fd->pkt_len, &ieee802154_host_dissector_info, ENDPOINT_NONE);
    add_hostlist_table_data(hash, &pinfo->dl_dst, 0, FALSE, 1,
            pinfo->fd->pkt_len, &ieee802154_host_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static gboolean ieee802154_filter_valid(packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "wpan")
            && ((pinfo->dl_src.type == ieee802_15_4_short_address_type) || (pinfo->dl_src.type == AT_EUI64))
            && ((pinfo->dl_dst.type == ieee802_15_4_short_address_type) || (pinfo->dl_dst.type == AT_EUI64));
}

static gchar* ieee802154_build_filter(packet_info *pinfo)
{
    return ws_strdup_printf("wpan.%s eq %s and wpan.%s eq %s",
            (pinfo->dl_src.type == ieee802_15_4_short_address_type) ? "addr16" : "addr64",
            address_to_str(pinfo->pool, &pinfo->dl_src),
            (pinfo->dl_dst.type == ieee802_15_4_short_address_type) ? "addr16" : "addr64",
            address_to_str(pinfo->pool, &pinfo->dl_dst));
}

/**
 * IEEE 802.15.4 protocol registration routine.
 */
void proto_register_ieee802154(void)
{
    /* Protocol fields  */
    static hf_register_info hf_phy[] = {
        /* PHY level */

        { &hf_ieee802154_nonask_phy_preamble,
        { "Preamble",                       "wpan-nonask-phy.preamble", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_nonask_phy_sfd,
        { "Start of Frame Delimiter",       "wpan-nonask-phy.sfd", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_nonask_phy_length,
        { "Frame Length",                   "wpan-nonask-phy.frame_length", FT_UINT8, BASE_HEX, NULL,
            IEEE802154_PHY_LENGTH_MASK, NULL, HFILL }},

        { &hf_ieee802154_nonask_phr,
        { "PHR",                            "wpan-nonask-phy.phr", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
    };

    static hf_register_info hf[] = {

        { &hf_ieee802154_frame_length,
        { "Frame Length",                   "wpan.frame_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Frame Length as reported from lower layer", HFILL }},

        { &hf_ieee802154_fcf,
        { "Frame Control Field",            "wpan.fcf", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_ieee802154_frame_type,
        { "Frame Type",                     "wpan.frame_type", FT_UINT16, BASE_HEX, VALS(ieee802154_frame_types),
            IEEE802154_FCF_TYPE_MASK, NULL, HFILL }},

        { &hf_ieee802154_security,
        { "Security Enabled",               "wpan.security", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_SEC_EN,
            "Whether security operations are performed at the MAC layer or not.", HFILL }},

        { &hf_ieee802154_pending,
        { "Frame Pending",                  "wpan.pending", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_FRAME_PND,
            "Indication of additional packets waiting to be transferred from the source device.", HFILL }},

        { &hf_ieee802154_ack_request,
        { "Acknowledge Request",            "wpan.ack_request", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_ACK_REQ,
            "Whether the sender of this packet requests acknowledgment or not.", HFILL }},

        { &hf_ieee802154_pan_id_compression,
        { "PAN ID Compression",             "wpan.pan_id_compression", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_PAN_ID_COMPRESSION,
            "Whether this packet contains the PAN ID or not.", HFILL }},

        { &hf_ieee802154_fcf_reserved,
        { "Reserved",                       "wpan.fcf.reserved", FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }},

        { &hf_ieee802154_seqno_suppression,
        { "Sequence Number Suppression",    "wpan.seqno_suppression", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_SEQNO_SUPPRESSION,
            "Whether this packet contains the Sequence Number or not.", HFILL }},

        { &hf_ieee802154_ie_present,
        { "Information Elements Present",   "wpan.ie_present", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_IE_PRESENT,
            "Whether this packet contains the Information Elements or not.", HFILL }},

        { &hf_ieee802154_dst_addr_mode,
        { "Destination Addressing Mode",    "wpan.dst_addr_mode", FT_UINT16, BASE_HEX, VALS(ieee802154_addr_modes),
            IEEE802154_FCF_DADDR_MASK, NULL, HFILL }},

        { &hf_ieee802154_version,
        { "Frame Version",                  "wpan.version", FT_UINT16, BASE_DEC, VALS(ieee802154_frame_versions),
            IEEE802154_FCF_VERSION, NULL, HFILL }},

        { &hf_ieee802154_src_addr_mode,
        { "Source Addressing Mode",         "wpan.src_addr_mode", FT_UINT16, BASE_HEX, VALS(ieee802154_addr_modes),
            IEEE802154_FCF_SADDR_MASK, NULL, HFILL }},

        /* 802.15.4-2015 Multipurpose frame control fields */
        { &hf_ieee802154_mpf_long_frame_control,
        { "Long Frame Control",             "wpan.long_frame_control", FT_BOOLEAN, 16, NULL, IEEE802154_MPF_FCF_LONG_FC,
            "Whether this frame control field uses one or two octets.", HFILL }},

        { &hf_ieee802154_mpf_dst_addr_mode,
        { "Destination Addressing Mode",    "wpan.dst_addr_mode", FT_UINT16, BASE_HEX, VALS(ieee802154_addr_modes),
            IEEE802154_MPF_FCF_DADDR_MASK, NULL, HFILL }},

        { &hf_ieee802154_mpf_src_addr_mode,
        { "Source Addressing Mode",         "wpan.src_addr_mode", FT_UINT16, BASE_HEX, VALS(ieee802154_addr_modes),
            IEEE802154_MPF_FCF_SADDR_MASK, NULL, HFILL }},

        { &hf_ieee802154_mpf_pan_id_present,
        { "PAN ID Present",                 "wpan.pan_id_present", FT_BOOLEAN, 16, NULL, IEEE802154_MPF_FCF_PAN_ID_PRESENT,
            "Whether this packet contains the destination PAN ID or not", HFILL }},

        { &hf_ieee802154_mpf_security,
        { "Security Enabled",               "wpan.security", FT_BOOLEAN, 16, NULL, IEEE802154_MPF_FCF_SEC_EN,
            "Whether security operations are performed at the MAC layer or not.", HFILL }},

        { &hf_ieee802154_mpf_seqno_suppression,
        { "Sequence Number Suppression",    "wpan.seqno_suppression", FT_BOOLEAN, 16, NULL, IEEE802154_MPF_FCF_SEQNO_SUPPRESSION,
            "Whether this packet contains the Sequence Number or not.", HFILL }},

        { &hf_ieee802154_mpf_pending,
        { "Frame Pending",                  "wpan.pending", FT_BOOLEAN, 16, NULL, IEEE802154_MPF_FCF_FRAME_PND,
            "Indication of additional packets waiting to be transferred from the source device.", HFILL }},

        { &hf_ieee802154_mpf_version,
        { "Multipurpose Frame Version",     "wpan.mpf_version", FT_UINT16, BASE_DEC, NULL,
            IEEE802154_MPF_FCF_VERSION, NULL, HFILL }},

        { &hf_ieee802154_mpf_ack_request,
        { "Acknowledge Request",            "wpan.ack_request", FT_BOOLEAN, 16, NULL, IEEE802154_MPF_FCF_ACK_REQ,
            "Whether the sender of this packet requests acknowledgment or not.", HFILL }},

        { &hf_ieee802154_mpf_ie_present,
        { "Information Elements Present",   "wpan.ie_present", FT_BOOLEAN, 16, NULL, IEEE802154_MPF_FCF_IE_PRESENT,
            "Whether this packet contains the Information Elements or not.", HFILL }},

        { &hf_ieee802154_seqno,
        { "Sequence Number",                "wpan.seq_no", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_dst_panID,
        { "Destination PAN",                "wpan.dst_pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_dst16,
        { "Destination",                    "wpan.dst16", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_dst64,
        { "Destination",                    "wpan.dst64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_src_panID,
        { "Source PAN",                     "wpan.src_pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_src16,
        { "Source",                         "wpan.src16", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_src64,
        { "Extended Source",                "wpan.src64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_addr16,
        { "Address",                        "wpan.addr16", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_addr64,
        { "Extended Address",               "wpan.addr64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_src64_origin,
        { "Origin",                         "wpan.src64.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_fcs,
        { "FCS",                            "wpan.fcs", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_fcs32,
        { "FCS",                            "wpan.fcs32", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_rssi,
        { "RSSI",                           "wpan.rssi", FT_INT8, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0x0,
            "Received Signal Strength", HFILL }},

        { &hf_ieee802154_fcs_ok,
        { "FCS Valid",                      "wpan.fcs_ok", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_correlation,
        { "LQI Correlation Value",          "wpan.correlation", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        /* Information Elements */

        { &hf_ieee802154_ie_unknown_content,
        { "Unknown Content",                "wpan.ie.unknown_content", FT_BYTES, SEP_SPACE, NULL, 0x0,
            NULL, HFILL }},

        /* Header IE */

        { &hf_ieee802154_header_ies,
        { "Header IEs",                     "wpan.header_ie", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_ieee802154_header_ie_tlv,
          { "IE Header",                    "wpan.header_ie_tlv", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        { &hf_ieee802154_header_ie_type,
        { "Type",                           "wpan.header_ie.type", FT_UINT16, BASE_DEC, VALS(ieee802154_ie_types),
                IEEE802154_HEADER_IE_TYPE_MASK, NULL, HFILL }},

        { &hf_ieee802154_header_ie_id,
        { "Id",                             "wpan.header_ie.id", FT_UINT16, BASE_HEX, VALS(ieee802154_header_ie_names),
                IEEE802154_HEADER_IE_ID_MASK, NULL, HFILL }},

        { &hf_ieee802154_header_ie_length,
        { "Length",                         "wpan.header_ie.length", FT_UINT16, BASE_DEC, NULL,
                IEEE802154_HEADER_IE_LENGTH_MASK, NULL, HFILL }},


        /* Individual Header IEs */

        { &hf_ieee802154_hie_unsupported,
        { "Unsupported Header IE",          "wpan.header_ie.unsupported", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_hie_ht1,
        { "Header Termination 1 IE (Payload IEs follow)", "wpan.header_ie.ht1", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_hie_ht2,
        { "Header Termination 2 IE (Payload follows)",    "wpan.header_ie.ht2", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},


        /* Time correction IE */
        { &hf_ieee802154_hie_time_correction,
        { "Time Correction IE",             "wpan.header_ie.time_correction", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_hie_time_correction_time_sync_info,
        { "Time Sync Info",                 "wpan.header_ie.time_correction.time_sync_info", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_nack,
        { "Nack",                           "wpan.nack", FT_BOOLEAN, 16, TFS(&hf_ieee802154_nack_tfs), 0x8000,
            NULL, HFILL }},

        { &hf_ieee802154_hie_time_correction_value,
        { "Time Correction",                "wpan.header_ie.time_correction.value", FT_INT16, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0FFF,
            "Time correction in microseconds", HFILL }},

        /* CSL IE */
        { &hf_ieee802154_hie_csl,
        { "CSL IE", "wpan.header_ie.csl", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_hie_csl_phase,
        { "Phase", "wpan.header_ie.csl.phase", FT_INT16, BASE_DEC, NULL, 0x0,
            "CSL Phase in units of 10 symbols", HFILL }},

        { &hf_ieee802154_hie_csl_period,
        { "Period", "wpan.header_ie.csl.period", FT_INT16, BASE_DEC, NULL, 0x0,
            "CSL Period in units of 10 symbols", HFILL }},

        { &hf_ieee802154_hie_csl_rendezvous_time,
        { "Rendezvous Time", "wpan.header_ie.csl.rendezvous_time", FT_INT16, BASE_DEC, NULL, 0x0,
            "CSL Rendezvous Time in units of 10 symbols", HFILL }},

        /* RendezVous Time IE */
        { &hf_ieee802154_hie_rdv,
        { "Rendezvous Time IE", "wpan.header_ie.rdv", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_hie_rdv_wakeup_interval,
        { "Wake-up Interval", "wpan.header_ie.csl.wakeup_interval", FT_INT16, BASE_DEC, NULL, 0x0,
            "Interval between two successive Wake-Up frames, in units of 10 symbols", HFILL }},

        /* Global Time IE */
        { &hf_ieee802154_hie_global_time,
        { "Global Time IE",                 "wpan.header_ie.global_time", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_hie_global_time_value,
        { "Global Time",                    "wpan.header_ie.global_time.value", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }},

		/* Vendor Specific IE */
        { &hf_ieee802154_hie_vendor_specific,
        { "Vendor Specific IE",             "wpan.header_ie.vendor_specific", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_hie_vendor_specific_vendor_oui,
        { "Vendor OUI",                 "wpan.header_ie.vendor_specific.vendor_oui", FT_UINT24, BASE_OUI, NULL, 0x0,
            NULL, HFILL }},

		{ &hf_ieee802154_hie_vendor_specific_content,
        { "Vendor Content",                "wpan.header_ie.vendor_specific.content", FT_BYTES, SEP_SPACE, NULL, 0x0,
            NULL, HFILL }},

        /* Payload IEs */

        { &hf_ieee802154_payload_ies,
        { "Payload IEs",                    "wpan.payload_ie", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_payload_ie_tlv,
        { "IE Header",                      "wpan.payload_ie_tlv", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_payload_ie_type,
        { "Type",                           "wpan.payload_ie.type", FT_UINT16, BASE_DEC, VALS(ieee802154_ie_types),
                IEEE802154_PAYLOAD_IE_TYPE_MASK, NULL, HFILL }},

        { &hf_ieee802154_payload_ie_id,
        { "Id",                             "wpan.payload_ie.id", FT_UINT16, BASE_HEX, VALS(ieee802154_payload_ie_names),
                IEEE802154_PAYLOAD_IE_ID_MASK, NULL, HFILL }},

        { &hf_ieee802154_payload_ie_length,
        { "Length",                         "wpan.payload_ie.length", FT_UINT16, BASE_DEC, NULL,
                IEEE802154_PAYLOAD_IE_LENGTH_MASK, NULL, HFILL }},


        /* Individual Payload IEs */

        { &hf_ieee802154_pie_unsupported,
        { "Unknown Payload IE",             "wpan.payload_ie.unknown", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_pie_termination,
        { "Payload Termination IE",         "wpan.payload_ie.termination", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_pie_vendor,
        { "Vendor Specific IE",             "wpan.payload_ie.vendor", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_pie_vendor_oui,
        { "Vendor OUI",                     "wpan.payload_ie.vendor.oui", FT_UINT24, BASE_OUI, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_mlme,
        { "MLME IE",                        "wpan.mlme", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_psie_type,
        { "Type",                           "wpan.mlme.ie.type", FT_UINT16, BASE_DEC, VALS(ieee802154_psie_types),
                IEEE802154_PSIE_TYPE_MASK, NULL, HFILL }},

        { &hf_ieee802154_psie,
        { "MLME Sub IE",                    "wpan.mlme.ie", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_ieee802154_psie_id_short,
        { "Sub ID",                         "wpan.mlme.ie.id", FT_UINT16, BASE_HEX, VALS(ieee802154_psie_names),
                IEEE802154_PSIE_ID_MASK_SHORT, NULL, HFILL }},

        { &hf_ieee802154_psie_length_short,
        { "Length",                         "wpan.mlme.ie.length", FT_UINT16, BASE_DEC, NULL,
                IEEE802154_PSIE_LENGTH_MASK_SHORT, NULL, HFILL }},

        { &hf_ieee802154_psie_id_long,
        { "Sub ID",                         "wpan.mlme.ie.id", FT_UINT16, BASE_HEX, VALS(ieee802154_psie_names),
                IEEE802154_PSIE_ID_MASK_LONG, NULL, HFILL }},

        { &hf_ieee802154_psie_length_long,
        { "Length",                         "wpan.mlme.ie.length", FT_UINT16, BASE_DEC, NULL,
                IEEE802154_PSIE_LENGTH_MASK_LONG, NULL, HFILL }},

        { &hf_ieee802154_mlme_ie_unsupported,
        { "Unsupported Sub IE",             "wpan.mlme.unsupported", FT_NONE, BASE_NONE, NULL,
              0, NULL, HFILL }},

        { &hf_ieee802154_mlme_ie_data,
        { "Data",                            "wpan.mlme.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter,
        { "Enhanced Beacon Filter",         "wpan.eb_filter", FT_UINT8, BASE_HEX, NULL,
              0, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter_pjoin,
        { "Permit Join Filter",             "wpan.eb_filter.pjoin", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled),
              IEEE802154_MLME_PSIE_EB_FLT_PJOIN, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter_lqi,
        { "LQI Filter",                     "wpan.eb_filter.lqi", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled),
            IEEE802154_MLME_PSIE_EB_FLT_LQI, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter_lqi_min,
        { "Minimum LQI",                    "wpan.eb_filter.lqi_minimum", FT_UINT8, BASE_DEC, NULL,
             0x0, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter_percent,
        { "Probability to Respond",         "wpan.eb_filter.contains_prob", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled),
            IEEE802154_MLME_PSIE_EB_FLT_PERCENT, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter_percent_prob,
        { "Response Probability Percentage", "wpan.eb_filter.prob", FT_UINT8, BASE_DEC, NULL,
                 0x0, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter_attr_id,
        { "Requested Attribute Length",      "wpan.eb_filter.attr_id", FT_UINT8, BASE_DEC, NULL,
            IEEE802154_MLME_PSIE_EB_FLT_ATTR_LEN, NULL, HFILL }},

        { &hf_ieee802154_psie_eb_filter_attr_id_bitmap,
        { "Attribute ID Bitmap",             "wpan.eb_filter.attr_id_bits", FT_UINT24, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_ieee802154_tsch_sync,
          { "TSCH Synchronization IE",      "wpan.tsch.time_sync", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_asn,
        { "Absolute Slot Number",           "wpan.tsch.asn", FT_UINT40, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_join_metric,
        { "Join Metric",                    "wpan.tsch.join_metric", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_timeslot,
          { "TSCH Timeslot IE",             "wpan.tsch.timeslot", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_timeslot_id,
          { "Timeslot ID",                  "wpan.tsch.timeslot.id", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Identifier of the Timeslot Template", HFILL }},

        { &hf_ieee802154_tsch_timeslot_cca_offset,
          { "CCA Offset",                   "wpan.tsch.timeslot.cca_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Time between the beginning of the timeslot and the start of CCA", HFILL }},

        { &hf_ieee802154_tsch_timeslot_cca,
          { "CCA",                          "wpan.tsch.timeslot.cca", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Duration of CCA", HFILL }},

        { &hf_ieee802154_tsch_timeslot_tx_offset,
          { "TX Offset",                    "wpan.tsch.timeslot.tx_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Time between the beginning of the timeslot and the start of frame transmission", HFILL }},

        { &hf_ieee802154_tsch_timeslot_rx_offset,
          { "RX Offset",                    "wpan.tsch.timeslot.rx_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Time between the beginning of the timeslot to when the receiver shall be listening", HFILL }},

        { &hf_ieee802154_tsch_timeslot_rx_ack_delay,
          { "RX Ack Delay",                "wpan.tsch.timeslot.rx_ack_delay", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Time between the end of frame to when the transmitter shall listen for acknowledgment", HFILL }},

        { &hf_ieee802154_tsch_timeslot_tx_ack_delay,
          { "TX Ack Delay",                "wpan.tsch.timeslot.tx_ack_delay", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Time between the end of frame to start of acknowledgment", HFILL }},

        { &hf_ieee802154_tsch_timeslot_rx_wait,
          { "RX Wait",                      "wpan.tsch.timeslot.rx_wait", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Time to wait for the start of frame", HFILL }},

        { &hf_ieee802154_tsch_timeslot_ack_wait,
          { "Ack Wait",                     "wpan.tsch.timeslot.ack_wait", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Minimum time to wait for the start of an acknowledgment", HFILL }},

        { &hf_ieee802154_tsch_timeslot_turnaround,
          { "Turn Around",                  "wpan.tsch.timeslot.turnaround", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Transmit to receive turnaround time", HFILL }},

        { &hf_ieee802154_tsch_timeslot_max_ack,
          { "Max Ack",                      "wpan.tsch.timeslot.max_ack", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Transmission time to send an acknowledgment", HFILL }},

        { &hf_ieee802154_tsch_timeslot_max_tx,
          { "Max TX",                      "wpan.tsch.timeslot.max_tx", FT_UINT24, BASE_DEC, NULL, 0x0,
            "Transmission time to send the maximum length frame", HFILL }},

        { &hf_ieee802154_tsch_timeslot_length,
          { "Timeslot Length",              "wpan.tsch.timeslot.length", FT_UINT24, BASE_DEC, NULL, 0x0,
            "Total length of the timeslot, including any unused time after frame transmission", HFILL }},

        { &hf_ieee802154_tsch_channel_hopping,
        { "Channel Hopping IE",             "wpan.channel_hopping", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotframe,
        { "Slotframe IE", "wpan.tsch.slotframe", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_tsch_link_info,
        { "Link Information", "wpan.tsch.link_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_nb_slotf,
        { "Number of Slotframes",           "wpan.tsch.slotframe_num", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_slotf_handle,
        { "Slotframe handle",               "wpan.tsch.slotframe_handle", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_size,
        { "Slotframe size",                 "wpan.tsch.slotframe_size", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_nb_links,
        { "Number of Links",                "wpan.tsch.nb_links", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_timeslot,
        { "Timeslot",                       "wpan.tsch.link_timeslot", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_channel_offset,
        { "Channel Offset",                 "wpan.tsch.channel_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_options,
        { "Link Options",                   "wpan.tsch.link_options", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_options_tx,
        { "TX Link",                        "wpan.tsch.link_options.tx", FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_options_rx,
        { "RX Link",                        "wpan.tsch.link_options.rx", FT_BOOLEAN, 8, NULL, (1 << 1),
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_options_shared,
        { "Shared Link",                    "wpan.tsch.link_options.shared", FT_BOOLEAN, 8, NULL, (1 << 2),
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_options_timkeeping,
        { "Timekeeping",                    "wpan.tsch.link_options.timekeeping", FT_BOOLEAN, 8, NULL, (1 << 3),
            NULL, HFILL }},

        { &hf_ieee802154_tsch_slotf_link_options_priority,
        { "Priority",                       "wpan.tsch.link_options.priority", FT_BOOLEAN, 8, NULL, (1 << 4),
            NULL, HFILL }},

        { &hf_ieee802154_tsch_hopping_sequence_id,
        { "Hopping Sequence ID",            "wpan.tsch.hopping_sequence_id", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* IETF IE */
        { &hf_ieee802154_pie_ietf,
        { "IETF Payload IE",                 "wpan.payload_ie.ietf", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_ieee802154_p_ie_ietf_sub_id,
        { "Sub-ID",                          "wpan.ietf_ie.sub_id", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

        /* IETF IE - 6top IE */
        { &hf_ieee802154_6top,
        { "6top IE", "wpan.6top", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_version,
        { "6P Version", "wpan.6top_version", FT_UINT8, BASE_DEC, NULL, IETF_6TOP_VERSION,
          NULL, HFILL }},

        { &hf_ieee802154_6top_type,
          { "Type", "wpan.6top_type", FT_UINT8, BASE_HEX, VALS(ietf_6top_types), IETF_6TOP_TYPE,
          NULL, HFILL }},

        { &hf_ieee802154_6top_flags_reserved,
        { "Reserved", "wpan.6top_flags_reserved", FT_UINT8, BASE_HEX, NULL, IETF_6TOP_FLAGS_RESERVED,
          NULL, HFILL }},

        { &hf_ieee802154_6top_code,
        { "Code",  "wpan.6top_code", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_sfid,
        { "SFID (6top Scheduling Function ID)", "wpan.6top_sfid", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_seqnum,
        { "SeqNum", "wpan.6top_seqnum", FT_UINT8, BASE_DEC, NULL, IETF_6TOP_SEQNUM,
          NULL, HFILL }},

        { &hf_ieee802154_6top_metadata,
        { "Metadata", "wpan.6top_metadata", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cell_options,
          { "Cell Options", "wpan.6top_cell_options", FT_UINT8, BASE_HEX, VALS(ietf_6top_cell_options), 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cell_option_tx,
        { "Transmit (TX) Cell", "wpan.6top_cell_option_tx", FT_UINT8, BASE_HEX, NULL, IETF_6TOP_CELL_OPTION_TX,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cell_option_rx,
        { "Receive (RX) Cell", "wpan.6top_cell_option_rx", FT_UINT8, BASE_HEX, NULL, IETF_6TOP_CELL_OPTION_RX,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cell_option_shared,
        { "SHARED Cell", "wpan.6top_cell_option_shared", FT_UINT8, BASE_HEX, NULL, IETF_6TOP_CELL_OPTION_SHARED,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cell_option_reserved,
        { "Reserved", "wpan.6top_cell_option_reserved", FT_UINT8, BASE_HEX, NULL, IETF_6TOP_CELL_OPTION_RESERVED,
          NULL, HFILL }},

        { &hf_ieee802154_6top_num_cells,
        { "Number of Cells", "wpan.6top_num_cells", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cell_list,
        { "CellList", "wpan.6top_cell_list", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_rel_cell_list,
        { "Rel. CellList", "wpan.6top_rel_cell_list", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cand_cell_list,
        { "Cand. CellList", "wpan.6top_cand_cell_list", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_cell,
        { "Cell", "wpan.6top_cell", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_reserved,
        { "Reserved", "wpan.6top_reserved", FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_offset,
        { "Offset", "wpan.6top_offset", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_max_num_cells,
        { "Maximum Number of Requested Cells", "wpan.6top_max_num_cells", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_slot_offset,
        { "Slot Offset", "wpan.6top_cell_slot_offset", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_channel_offset,
        { "Channel Offset", "wpan.6top_channel_offset", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_total_num_cells,
        { "Total Number of Cells", "wpan.6top_total_num_cells", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_ieee802154_6top_payload,
        { "Payload", "wpan.6top_payload", FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        /* MPX IE (IEEE 802.15.9) */
        { &hf_ieee802159_mpx,
          { "MPX IE", "wpan.mpx", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_transaction_control,
          { "Transaction Control", "wpan.mpx.transaction_control", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_transfer_type,
          { "Transfer Type", "wpan.mpx.transfer_type", FT_UINT8, BASE_HEX, VALS(mpx_transfer_type_vals), IEEE802159_MPX_TRANSFER_TYPE_MASK,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_transaction_id,
          { "Transaction ID", "wpan.mpx.transaction_id", FT_UINT8, BASE_HEX, NULL, IEEE802159_MPX_TRANSACTION_ID_MASK,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_transaction_id_as_multiplex_id,
          { "Multiplex ID", "wpan.mpx.multiplex_id", FT_UINT8, BASE_HEX, VALS(mpx_multiplex_id_vals), IEEE802159_MPX_TRANSACTION_ID_MASK,
            "Transaction ID used as Multiplex ID", HFILL }
        },

        { &hf_ieee802159_mpx_fragment_number,
          { "Fragment Number", "wpan.mpx.fragment_number", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_total_frame_size,
          { "Total Frame Size", "wpan.mpx.total_frame_size", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Total Upper-Layer Frame Size", HFILL }
        },

        { &hf_ieee802159_mpx_multiplex_id,
          { "Multiplex ID", "wpan.mpx.multiplex_id", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_kmp_id,
          { "KMP ID", "wpan.mpx.kmp.id", FT_UINT8, BASE_DEC, VALS(ieee802154_mpx_kmp_id_vals), 0x0,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_kmp_vendor_oui,
          { "Vendor OUI", "wpan.mpx.kmp.vendor_oui", FT_UINT24, BASE_OUI, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_fragment,
          { "Upper-Layer Frame Fragment", "wpan.mpx.fragment", FT_BYTES, SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ieee802159_mpx_wisun_subid,
          { "Wi-SUN Multiplex Sub ID", "wpan.mpx.wisun", FT_UINT8, BASE_HEX, VALS(mpx_wisun_subid_vals), 0x0,
            NULL, HFILL }
        },

        /* Command Frame Specific Fields */

        { &hf_ieee802154_cmd_id,
        { "Command Identifier",         "wpan.cmd", FT_UINT8, BASE_HEX, VALS(ieee802154_cmd_names), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_cmd_vendor_oui,
        { "Vendor OUI",                 "wpan.cmd.vendor_oui", FT_UINT24, BASE_OUI, NULL, 0x0,
            NULL, HFILL }},

        /*  Capability Information Fields */

        { &hf_ieee802154_cinfo_alt_coord,
        { "Alternate PAN Coordinator",  "wpan.cinfo.alt_coord", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_ALT_PAN_COORD,
            "Whether this device can act as a PAN coordinator or not.", HFILL }},

        { &hf_ieee802154_cinfo_device_type,
        { "Device Type",                "wpan.cinfo.device_type", FT_BOOLEAN, 8, TFS(&tfs_cinfo_device_type), IEEE802154_CMD_CINFO_DEVICE_TYPE,
            "Whether this device is RFD (reduced-function device) or FFD (full-function device).", HFILL }},

        { &hf_ieee802154_cinfo_power_src,
        { "Power Source",               "wpan.cinfo.power_src", FT_BOOLEAN, 8, TFS(&tfs_cinfo_power_src), IEEE802154_CMD_CINFO_POWER_SRC,
            "Whether this device is operating on AC/mains or battery power.", HFILL }},

        { &hf_ieee802154_cinfo_idle_rx,
        { "Receive On When Idle",       "wpan.cinfo.idle_rx", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_IDLE_RX,
            "Whether this device can receive packets while idle or not.", HFILL }},

        { &hf_ieee802154_cinfo_sec_capable,
        { "Security Capability",        "wpan.cinfo.sec_capable", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_SEC_CAPABLE,
            "Whether this device is capable of receiving encrypted packets.", HFILL }},

        { &hf_ieee802154_cinfo_alloc_addr,
        { "Allocate Address",           "wpan.cinfo.alloc_addr", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_ALLOC_ADDR,
            "Whether this device wishes to use a 16-bit short address instead of its IEEE 802.15.4 64-bit long address.", HFILL }},

        /*  Association response fields */

        { &hf_ieee802154_assoc_addr,
        { "Short Address",              "wpan.asoc.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "The short address that the device should assume. An address of 0xfffe indicates that the device should use its IEEE 64-bit long address.", HFILL }},

        { &hf_ieee802154_assoc_status,
        { "Association Status",         "wpan.assoc.status", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_disassoc_reason,
        { "Disassociation Reason",      "wpan.disassoc.reason", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /*  Coordinator Realignment fields */

        { &hf_ieee802154_realign_pan,
        { "PAN ID",                     "wpan.realign.pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            "The PAN identifier the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_realign_caddr,
        { "Coordinator Short Address",  "wpan.realign.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "The 16-bit address the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_realign_channel,
        { "Logical Channel",            "wpan.realign.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The logical channel the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_realign_addr,
        { "Short Address",              "wpan.realign.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "A short-address that the orphaned device shall assume if applicable.", HFILL }},

        { &hf_ieee802154_realign_channel_page,
        { "Channel Page",               "wpan.realign.channel_page", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The logical channel page the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_gtsreq_len,
        { "GTS Length",                 "wpan.gtsreq.length", FT_UINT8, BASE_DEC, NULL, IEEE802154_CMD_GTS_REQ_LEN,
            "Number of superframe slots the device is requesting.", HFILL }},

        { &hf_ieee802154_gtsreq_dir,
        { "GTS Direction",              "wpan.gtsreq.direction", FT_BOOLEAN, 8, TFS(&tfs_gtsreq_dir), IEEE802154_CMD_GTS_REQ_DIR,
            "The direction of traffic in the guaranteed timeslot.", HFILL }},

        { &hf_ieee802154_gtsreq_type,
        { "Characteristic Type",        "wpan.gtsreq.type", FT_BOOLEAN, 8, TFS(&tfs_gtsreq_type), IEEE802154_CMD_GTS_REQ_TYPE,
            "Whether this request is to allocate or deallocate a timeslot.", HFILL }},

        /* Beacon Frame Specific Fields */

        { &hf_ieee802154_beacon_order,
        { "Beacon Interval",            "wpan.beacon_order", FT_UINT16, BASE_DEC, NULL, IEEE802154_BEACON_ORDER_MASK,
            "Specifies the transmission interval of the beacons.", HFILL }},

        { &hf_ieee802154_superframe_order,
        { "Superframe Interval",        "wpan.superframe_order", FT_UINT16, BASE_DEC, NULL,
            IEEE802154_SUPERFRAME_ORDER_MASK,
            "Specifies the length of time the coordinator will interact with the PAN.", HFILL }},

        { &hf_ieee802154_cap,
        { "Final CAP Slot",             "wpan.cap", FT_UINT16, BASE_DEC, NULL, IEEE802154_SUPERFRAME_CAP_MASK,
            "Specifies the final superframe slot used by the CAP.", HFILL }},

        { &hf_ieee802154_superframe_battery_ext,
        { "Battery Extension",          "wpan.battery_ext", FT_BOOLEAN, 16, NULL, IEEE802154_BATT_EXTENSION_MASK,
            "Whether transmissions may not extend past the length of the beacon frame.", HFILL }},

        { &hf_ieee802154_superframe_coord,
        { "PAN Coordinator",            "wpan.bcn_coord", FT_BOOLEAN, 16, NULL, IEEE802154_SUPERFRAME_COORD_MASK,
            "Whether this beacon frame is being transmitted by the PAN coordinator or not.", HFILL }},

        { &hf_ieee802154_assoc_permit,
        { "Association Permit",         "wpan.assoc_permit", FT_BOOLEAN, 16, NULL, IEEE802154_ASSOC_PERMIT_MASK,
            "Whether this PAN is accepting association requests or not.", HFILL }},

        { &hf_ieee802154_gts_count,
        { "GTS Descriptor Count",       "wpan.gts.count", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The number of GTS descriptors present in this beacon frame.", HFILL }},

        { &hf_ieee802154_gts_permit,
        { "GTS Permit",                 "wpan.gts.permit", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Whether the PAN coordinator is accepting GTS requests or not.", HFILL }},

        { &hf_ieee802154_gts_direction,
        { "Direction",                  "wpan.gts.direction", FT_BOOLEAN, BASE_NONE, TFS(&ieee802154_gts_direction_tfs), 0x0,
            "A flag defining the direction of the GTS Slot.", HFILL }},

        { &hf_ieee802154_gts_address,
        { "Address",                    "wpan.gts.address", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_pending16,
        { "Address",                    "wpan.pending16", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Device with pending data to receive.", HFILL }},

        { &hf_ieee802154_pending64,
        { "Address",                    "wpan.pending64", FT_EUI64, BASE_NONE, NULL, 0x0,
            "Device with pending data to receive.", HFILL }},

        /* Auxiliary Security Header Fields */
        { &hf_ieee802154_aux_security_header,
        { "Auxiliary Security Header", "wpan.aux_sec.hdr", FT_NONE, BASE_NONE, NULL,
            0x0, "The Auxiliary Security Header of the frame", HFILL }},

        { &hf_ieee802154_aux_sec_security_level,
        { "Security Level", "wpan.aux_sec.sec_level", FT_UINT8, BASE_HEX, VALS(ieee802154_sec_level_names),
            IEEE802154_AUX_SEC_LEVEL_MASK, "The Security Level of the frame", HFILL }},

        { &hf_ieee802154_aux_sec_security_control,
        { "Security Control Field", "wpan.aux_sec.security_control_field", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_ieee802154_aux_sec_key_id_mode,
        { "Key Identifier Mode", "wpan.aux_sec.key_id_mode", FT_UINT8, BASE_HEX, VALS(ieee802154_key_id_mode_names),
            IEEE802154_AUX_KEY_ID_MODE_MASK,
            "The scheme to use by the recipient to lookup the key in its key table", HFILL }},

        { &hf_ieee802154_aux_sec_frame_counter_suppression,
        { "Frame Counter Suppression", "wpan.aux_sec.frame_counter_suppression", FT_BOOLEAN, 8, NULL,
            IEEE802154_AUX_FRAME_COUNTER_SUPPRESSION_MASK,
            "Whether the frame counter is omitted from the Auxiliary Security Header", HFILL }},

        { &hf_ieee802154_aux_sec_asn_in_nonce,
        { "ASN in Nonce", "wpan.aux_sec.asn_in_nonce", FT_BOOLEAN, 8, NULL,
            IEEE802154_AUX_ASN_IN_NONCE_MASK,
            "Whether the ASN is used to generate the nonce instead of the frame counter", HFILL }},

        { &hf_ieee802154_aux_sec_reserved,
        { "Reserved", "wpan.aux_sec.reserved", FT_UINT8, BASE_HEX, NULL, IEEE802154_AUX_CTRL_RESERVED_MASK,
            NULL, HFILL }},

        { &hf_ieee802154_aux_sec_frame_counter,
        { "Frame Counter", "wpan.aux_sec.frame_counter", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Frame counter of the originator of the protected frame", HFILL }},

        { &hf_ieee802154_aux_sec_key_source,
        { "Key Source", "wpan.aux_sec.key_source", FT_UINT64, BASE_HEX, NULL, 0x0,
            "Key Source for processing of the protected frame", HFILL }},

        { &hf_ieee802154_aux_sec_key_source_bytes,
        { "Key Source", "wpan.aux_sec.key_source.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Key Source for processing of the protected frame", HFILL }},

        { &hf_ieee802154_aux_sec_key_index,
        { "Key Index", "wpan.aux_sec.key_index", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Key Index for processing of the protected frame", HFILL }},

        { &hf_ieee802154_mic,
        { "MIC", "wpan.mic", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_key_number,
        { "Key Number", "wpan.key_number", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Key number used to decode", HFILL }},

        /* IEEE 802.15.4-2003 Security Header Fields */
        { &hf_ieee802154_sec_frame_counter,
        { "Frame Counter", "wpan.sec_frame_counter", FT_UINT32, BASE_HEX, NULL, 0x0,
            "Frame counter of the originator of the protected frame (802.15.4-2003)", HFILL }},

        { &hf_ieee802154_sec_key_sequence_counter,
        { "Key Sequence Counter", "wpan.sec_key_sequence_counter", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Key Sequence counter of the originator of the protected frame (802.15.4-2003)", HFILL }},

        { &hf_ieee802154_no_ack,
        { "No ack found", "wpan.no_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "No corresponding ack frame was found", HFILL }},

        { &hf_ieee802154_no_ack_request,
        { "No request found", "wpan.no_ack_request", FT_NONE, BASE_NONE, NULL, 0x0,
            "No corresponding request frame was found", HFILL }},

        { &hf_ieee802154_ack_in,
        { "Ack In", "wpan.ack_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The ack to this request is in this frame", HFILL }},

        { &hf_ieee802154_ack_to,
        { "Ack To", "wpan.ack_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0,
            "This is the ack to the request in this frame", HFILL }},

        { &hf_ieee802154_ack_time,
        { "Ack Time", "wpan.ack_time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "The time between the request and the ack", HFILL }},

        /* ZBOSS dump */

        { &hf_zboss_page,
        { "Page", "wpan-zboss.page", FT_UINT8, BASE_DEC_HEX, VALS(zboss_page_names), 0xFE,
            "IEEE802.15.4 page number", HFILL } },

        { &hf_zboss_channel,
        { "Channel", "wpan-zboss.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Channel number", HFILL }},

        { &hf_zboss_direction,
        { "ZBOSS Direction", "wpan-zboss.direction", FT_UINT8, BASE_HEX, VALS(zboss_direction_names), 0x01,
            "ZBOSS Packet Direction", HFILL }},

        { &hf_zboss_trace_number,
        { "Trace number", "wpan-zboss.trace", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Trace item number", HFILL }},

        /* TAP Packet Fields */
        { &hf_ieee802154_tap_version,
        { "Version",        "wpan-tap.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            "TAP Packet Version", HFILL }},

        { &hf_ieee802154_tap_reserved,
        { "Reserved",        "wpan-tap.reserved", FT_UINT8, BASE_DEC, NULL, 0x0,
            "TAP Packet Reserved", HFILL }},

        { &hf_ieee802154_tap_length,
        { "Length",        "wpan-tap.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            "TAP Packet Length", HFILL }},

        { &hf_ieee802154_tap_data_length,
        { "Data Length",   "wpan-tap.data_length", FT_UINT16, BASE_DEC, NULL, 0x0,
            "IEEE 802.15.4 Data Length", HFILL }},

        { &hf_ieee802154_tap_tlv_type,
        { "TLV Type",       "wpan-tap.tlv.type", FT_UINT16, BASE_DEC, VALS(tap_tlv_types), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tap_tlv_length,
        { "TLV Length",       "wpan-tap.tlv.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tap_tlv_unknown,
        { "Unknown",                "wpan-tap.tlv.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tap_tlv_padding,
        { "Padding",                "wpan-tap.tlv.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tap_fcs_type,
        { "FCS Type",       "wpan-tap.fcs_type", FT_UINT8, BASE_DEC, VALS(tap_fcs_type_names), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tap_rss,
        { "RSS",           "wpan-tap.rss", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_dbm, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_ch_num,
        { "Channel",        "wpan-tap.ch_num", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Channel number", HFILL }},

        { &hf_ieee802154_ch_page,
        { "Page",           "wpan-tap.ch_page", FT_UINT8, BASE_DEC, VALS(channel_page_names), 0x0,
            "Channel page", HFILL }},

        { &hf_ieee802154_bit_rate,
        { "Bit Rate",       "wpan-tap.bit_rate", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_sun_band,
        { "Band",           "wpan-tap.sun_band", FT_UINT8, BASE_DEC, VALS(sun_bands), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_sun_type,
        { "Type",           "wpan-tap.sun_type", FT_UINT8, BASE_DEC, VALS(sun_types), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_sun_mode,
        { "Mode",           "wpan-tap.sun_mode", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_mode_fsk_a,
        { "FSK-A mode",     "wpan-tap.mode.fsk_a", FT_UINT8, BASE_DEC, VALS(fsk_a_modes), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_mode_fsk_b,
        { "FSK-B mode",     "wpan-tap.mode.fsk_b", FT_UINT8, BASE_DEC, VALS(fsk_b_modes), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_mode_oqpsk_a,
        { "O-QPSK-A mode",   "wpan-tap.mode.oqpsk_a", FT_UINT8, BASE_DEC, VALS(oqpsk_a_modes), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_mode_oqpsk_b,
        { "O-QPSK-B mode",   "wpan-tap.mode.oqpsk_b", FT_UINT8, BASE_DEC, VALS(oqpsk_b_modes), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_mode_oqpsk_c,
        { "O-QPSK-C mode",   "wpan-tap.mode.oqpsk_c", FT_UINT8, BASE_DEC, VALS(oqpsk_c_modes), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_mode_ofdm,
        { "OFDM mode",       "wpan-tap.mode.ofdm", FT_UINT8, BASE_DEC, VALS(ofdm_modes), 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_sof_ts,
        { "Start of frame timestamp",   "wpan-tap.sof_ts", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_eof_ts,
        { "End of frame timestamp",     "wpan-tap.eof_ts", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_slot_start_ts,
        { "Start of slot timestamp",    "wpan-tap.slot_start_ts", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_nanoseconds, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tap_timeslot_length,
        { "Timeslot length",            "wpan-tap.timeslot_length", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_microseconds, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_tap_lqi,
        { "Link Quality Indicator",     "wpan-tap.lqi", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ieee802154_chplan_start,
        { "Channel0 freq",              "wpan-tap.chplan.start", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_khz, 0x0,
            "Channel 0 center frequency", HFILL }},

        { &hf_ieee802154_chplan_spacing,
        { "Spacing",                    "wpan-tap.chplan.spacing", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_khz, 0x0,
            "Channel spacing", HFILL }},

        { &hf_ieee802154_chplan_channels,
        { "Channels",                   "wpan-tap.chplan.channels", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of channels", HFILL }},

        { &hf_ieee802154_ch_freq,
        { "Frequency",                  "wpan-tap.ch_freq", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, &units_khz, 0x0,
            "Channel center frequency", HFILL }},

        { &hf_ieee802154_frame_start_offset,
        { "Frame start offset",       "wpan.tsch.frame_start_offset", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_microseconds, 0x0,
            "Start of frame timestamp - start of slot timestamp", HFILL }},

        { &hf_ieee802154_frame_duration,
        { "Frame duration",           "wpan.tsch.frame_duration", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_microseconds, 0x0,
            "End of frame timestamp - start of frame timestamp", HFILL }},

        { &hf_ieee802154_frame_end_offset,
        { "Frame end offset", "wpan.tsch.frame_end_offset", FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, &units_microseconds, 0x0,
            "End of frame timestamp - (start of slot timestamp + timeslot length)", HFILL }},

        { &hf_ieee802154_asn,
        { "ASN", "wpan-tap.asn", FT_UINT64, BASE_DEC, NULL, 0x0,
            "Absolute Slot Number", HFILL }},

    };

    /* Subtrees */
    static gint *ett[] = {
        &ett_ieee802154_nonask_phy,
        &ett_ieee802154_nonask_phy_phr,
        &ett_ieee802154_tap,
        &ett_ieee802154_tap_header,
        &ett_ieee802154_tap_tlv,
        &ett_ieee802154,
        &ett_ieee802154_fcf,
        &ett_ieee802154_auxiliary_security,
        &ett_ieee802154_aux_sec_control,
        &ett_ieee802154_aux_sec_key_id,
        &ett_ieee802154_fcs,
        &ett_ieee802154_cmd,
        &ett_ieee802154_superframe,
        &ett_ieee802154_gts,
        &ett_ieee802154_gts_direction,
        &ett_ieee802154_gts_descriptors,
        &ett_ieee802154_pendaddr,
        &ett_ieee802154_header_ies,
        &ett_ieee802154_header_ie,
        &ett_ieee802154_header_ie_tlv,
        &ett_ieee802154_hie_unsupported,
        &ett_ieee802154_hie_time_correction,
        &ett_ieee802154_hie_ht,
        &ett_ieee802154_hie_csl,
        &ett_ieee802154_hie_rdv,
        &ett_ieee802154_hie_global_time,
        &ett_ieee802154_hie_vendor_specific,
        &ett_ieee802154_payload_ie,
        &ett_ieee802154_payload_ie_tlv,
        &ett_ieee802154_pie_termination,
        &ett_ieee802154_pie_vendor,
        &ett_ieee802159_mpx,
        &ett_ieee802159_mpx_transaction_control,
        &ett_ieee802154_pie_ietf,
        &ett_ieee802154_pie_unsupported,
        &ett_ieee802154_tsch_slotframe,
        &ett_ieee802154_tsch_slotframe_list,
        &ett_ieee802154_tsch_slotframe_link,
        &ett_ieee802154_tsch_slotframe_link_options,
        &ett_ieee802154_tsch_timeslot,
        &ett_ieee802154_tsch_synch,
        &ett_ieee802154_channel_hopping,
        &ett_ieee802154_mlme,
        &ett_ieee802154_mlme_payload,
        &ett_ieee802154_mlme_payload_data,
        &ett_ieee802154_mlme_unsupported,
        &ett_ieee802154_psie,
        &ett_ieee802154_eb_filter,
        &ett_ieee802154_eb_filter_bitmap,
        &ett_ieee802154_zigbee,
        &ett_ieee802154_zboss,
        &ett_ieee802154_p_ie_6top,
        &ett_ieee802154_p_ie_6top_cell_options,
        &ett_ieee802154_p_ie_6top_cell_list,
        &ett_ieee802154_p_ie_6top_rel_cell_list,
        &ett_ieee802154_p_ie_6top_cand_cell_list,
        &ett_ieee802154_p_ie_6top_cell
    };

    static ei_register_info ei[] = {
        { &ei_ieee802154_fcs_bitmask_len, { "wpan.bitmask_len_error", PI_UNDECODED, PI_WARN,
                "Only least-significant bytes decoded", EXPFILL }},
        { &ei_ieee802154_invalid_addressing, { "wpan.invalid_addressing", PI_MALFORMED, PI_WARN,
                "Invalid Addressing", EXPFILL }},
        { &ei_ieee802154_invalid_panid_compression, { "wpan.invalid_panid_compression", PI_MALFORMED, PI_ERROR,
                "Invalid Setting for PAN ID Compression", EXPFILL }},
        { &ei_ieee802154_invalid_panid_compression2, { "wpan.invalid_panid_compression", PI_MALFORMED, PI_ERROR,
                "Invalid Pan ID Compression and addressing combination for Frame Version 2", EXPFILL }},
        { &ei_ieee802154_dst, { "wpan.dst_invalid", PI_MALFORMED, PI_ERROR,
                "Invalid Destination Address Mode", EXPFILL }},
        { &ei_ieee802154_src, { "wpan.src_invalid", PI_MALFORMED, PI_ERROR,
                "Invalid Source Address Mode", EXPFILL }},
        { &ei_ieee802154_frame_ver,  { "wpan.frame_version_unknown", PI_MALFORMED, PI_ERROR,
                "Frame Version Unknown Cannot Dissect", EXPFILL }},
#if 0
        { &ei_ieee802154_frame_type, { "wpan.frame_type_unknown", PI_MALFORMED, PI_ERROR,
                "Frame Type Unknown Cannot Dissect", EXPFILL }},
#endif
        { &ei_ieee802154_decrypt_error, { "wpan.decrypt_error", PI_UNDECODED, PI_WARN,
                "Decryption error", EXPFILL }},
        { &ei_ieee802154_fcs, { "wpan.fcs.bad", PI_CHECKSUM, PI_WARN,
                "Bad FCS", EXPFILL }},
        { &ei_ieee802154_ack_not_found, { "wpan.ack_not_found",  PI_SEQUENCE, PI_NOTE,
                "Ack not found", EXPFILL }},
        { &ei_ieee802154_ack_request_not_found, { "wpan.ack_request_not_found",  PI_SEQUENCE, PI_NOTE,
                "Request not found", EXPFILL }},
        { &ei_ieee802154_seqno_suppression, { "wpan.seqno_suppression_invalid",  PI_MALFORMED, PI_WARN,
                "Sequence Number Suppression invalid for 802.15.4-2003 and 2006", EXPFILL }},
        { &ei_ieee802154_6top_unsupported_type, { "wpan.6top_unsupported_type", PI_PROTOCOL, PI_WARN,
                "Unsupported Type of Message", EXPFILL }},
        { &ei_ieee802154_6top_unsupported_command, { "wpan.6top_unsupported_command", PI_PROTOCOL, PI_WARN,
                "Unsupported 6top command", EXPFILL }},
        { &ei_ieee802154_time_correction_error, { "wpan.time_correction.error", PI_PROTOCOL, PI_WARN,
                "Incorrect value. Reference: IEEE-802.15.4-2015. Table 7-8: Values of the Time Sync Info field for ACK with timing information", EXPFILL}},
        { &ei_ieee802154_6top_unsupported_return_code, { "wpan.6top_unsupported_code", PI_PROTOCOL, PI_WARN,
                "Unsupported 6top return code", EXPFILL }},
        { &ei_ieee802154_ie_unsupported_id, { "wpan.ie_unsupported_id", PI_PROTOCOL, PI_WARN,
                "Unsupported IE ID", EXPFILL }},
        { &ei_ieee802154_ie_unknown_extra_content, { "wpan.ie_unknown_extra_content", PI_PROTOCOL, PI_WARN,
                "Unexpected extra content for IE", EXPFILL }},
        { &ei_ieee802159_mpx_invalid_transfer_type, { "wpan.payload_ie.mpx.invalid_transfer_type", PI_PROTOCOL, PI_WARN,
                "Invalid transfer type (cf. IEEE 802.15.9 Table 19)", EXPFILL }},
        { &ei_ieee802159_mpx_unsupported_kmp, { "wpan.mpx.unsupported_kmp", PI_PROTOCOL, PI_WARN,
                "Unsupported KMP ID", EXPFILL }},
        { &ei_ieee802159_mpx_unknown_kmp, { "wpan.mpx.unknown_kmp", PI_PROTOCOL, PI_WARN,
                "Unknown KMP ID (cf. IEEE 802.15.9 Table 21)", EXPFILL }},
        { &ei_ieee802154_missing_payload_ie, { "wpan.payload_ie.missing",  PI_MALFORMED, PI_WARN,
                "Payload IE indicated by Header Termination, but no Payload IE present", EXPFILL }},
        { &ei_ieee802154_payload_ie_in_header, { "wpan.payload_ie.in_header",  PI_MALFORMED, PI_WARN,
                "Payload IE in header", EXPFILL }},
        { &ei_ieee802154_unsupported_cmd, { "wpan.cmd.unsupported_cmd", PI_PROTOCOL, PI_WARN,
                "Unsupported Command ID", EXPFILL }},
        { &ei_ieee802154_unknown_cmd, { "wpan.cmd.unknown_cmd", PI_PROTOCOL, PI_WARN,
                "Unknown Command Id (cf. IEEE 802.15.4-2015 Table 7-49)", EXPFILL }},
        { &ei_ieee802154_tap_tlv_invalid_type, { "wpan-tap.tlv.invalid_type", PI_MALFORMED, PI_WARN,
                "Invalid TLV type", EXPFILL }},
        { &ei_ieee802154_tap_tlv_invalid_length, { "wpan-tap.tlv.invalid_length", PI_MALFORMED, PI_WARN,
                "Invalid TLV length", EXPFILL }},
        { &ei_ieee802154_tap_tlv_padding_not_zeros, { "wpan-tap.tlv.padding_not_zeros", PI_MALFORMED, PI_WARN,
                "TLV padding not zero", EXPFILL }},
        { &ei_ieee802154_tap_tlv_invalid_fcs_type, { "wpan-tap.tlv.invalid_fcs_type", PI_MALFORMED, PI_ERROR,
                "Invalid FCS type", EXPFILL }},
    };

    /* Preferences. */
    module_t *ieee802154_module;
    expert_module_t* expert_ieee802154;

    static uat_field_t addr_uat_flds[] = {
        UAT_FLD_HEX(addr_uat,addr16,"Short Address",
                "16-bit short address in hexadecimal."),
        UAT_FLD_HEX(addr_uat,pan,"PAN Identifier",
                "16-bit PAN identifier in hexadecimal."),
        UAT_FLD_BUFFER(addr_uat,eui64,"EUI-64",
                "64-bit extended unique identifier."),
        UAT_END_FIELDS
    };

    static uat_field_t key_uat_flds[] = {
        UAT_FLD_CSTRING(key_uat,pref_key,"Decryption key",
                "128-bit decryption key in hexadecimal format"),
        UAT_FLD_DEC(key_uat,key_index,"Decryption key index",
                "Key index in decimal format"),
        UAT_FLD_VS(key_uat, hash_type, "Key hash", ieee802154_key_hash_vals, "Specifies which hash scheme is used to derived the key"),
        UAT_END_FIELDS
    };

    static const enum_val_t fcs_type_vals[] = {
        {"cc24xx", "TI CC24xx metadata",    IEEE802154_CC24XX_METADATA},
        {"16",     "ITU-T CRC-16",          IEEE802154_FCS_16_BIT},
        {"32",     "ITU-T CRC-32",          IEEE802154_FCS_32_BIT},
        {NULL, NULL, -1}
    };

    static build_valid_func     ieee802154_da_build_value[1] = {ieee802154_da_value};
    static decode_as_value_t    ieee802154_da_values = {ieee802154_da_prompt, 1, ieee802154_da_build_value};
    static decode_as_t          ieee802154_da = {
        IEEE802154_PROTOABBREV_WPAN, IEEE802154_PROTOABBREV_WPAN_PANID,
        1, 0, &ieee802154_da_values, NULL, NULL,
        decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL
    };

    /* Register the init routine. */
    register_init_routine(proto_init_ieee802154);
    register_cleanup_routine(proto_cleanup_ieee802154);

    /*  Register Protocol name and description. */
    proto_ieee802154 = proto_register_protocol("IEEE 802.15.4 Low-Rate Wireless PAN", "IEEE 802.15.4",
           IEEE802154_PROTOABBREV_WPAN);
    proto_ieee802154_nonask_phy = proto_register_protocol("IEEE 802.15.4 Low-Rate Wireless PAN non-ASK PHY",
            "IEEE 802.15.4 non-ASK PHY", "wpan-nonask-phy");
    proto_zboss = proto_register_protocol("ZBOSS IEEE 802.15.4 dump",
                                          "ZBOSS dump", "wpan-zboss");
    proto_ieee802154_tap = proto_register_protocol("IEEE 802.15.4 Low-Rate Wireless PAN TAP",
                                          "IEEE 802.15.4 TAP", "wpan-tap");

    /*  Register header fields and subtrees. */
    proto_register_field_array(proto_ieee802154, hf, array_length(hf));
    proto_register_field_array(proto_ieee802154, hf_phy, array_length(hf_phy));

    proto_register_subtree_array(ett, array_length(ett));

    expert_ieee802154 = expert_register_protocol(proto_ieee802154);
    expert_register_field_array(expert_ieee802154, ei, array_length(ei));

    ieee802_15_4_short_address_type = address_type_dissector_register("AT_IEEE_802_15_4_SHORT", "IEEE 802.15.4 16-bit short address",
                                        ieee802_15_4_short_address_to_str, ieee802_15_4_short_address_str_len, NULL, NULL, ieee802_15_4_short_address_len, NULL, NULL);

    /* add a user preference to set the 802.15.4 ethertype */
    ieee802154_module = prefs_register_protocol(proto_ieee802154,
                                   proto_reg_handoff_ieee802154);
    prefs_register_uint_preference(ieee802154_module, "802154_ethertype",
                                   "802.15.4 Ethertype (in hex)",
                                   "(Hexadecimal) Ethertype used to indicate IEEE 802.15.4 frame.",
                                   16, &ieee802154_ethertype);
    prefs_register_obsolete_preference(ieee802154_module, "802154_cc24xx");
    prefs_register_enum_preference(ieee802154_module, "fcs_format",
                                   "FCS format",
                                   "The FCS format in the captured payload",
                                   &ieee802154_fcs_type, fcs_type_vals, FALSE);
    prefs_register_bool_preference(ieee802154_module, "802154_fcs_ok",
                                   "Dissect only good FCS",
                                   "Dissect payload only if FCS is valid.",
                                   &ieee802154_fcs_ok);
    prefs_register_bool_preference(ieee802154_module, "802154_ack_tracking",
                                   "Enable ACK tracking",
                                   "Match frames with ACK request to ACK packets",
                                   &ieee802154_ack_tracking);
    prefs_register_bool_preference(ieee802154_module, "802154e_compatibility",
                                    "Assume 802.15.4e-2012 for compatibility",
                                    "Parse assuming 802.15.4e quirks for compatibility",
                                    &ieee802154e_compatibility);

    /* Create a UAT for static address mappings. */
    static_addr_uat = uat_new("Static Addresses",
            sizeof(static_addr_t),      /* record size */
            "802154_addresses",         /* filename */
            TRUE,                       /* from_profile */
            &static_addrs,              /* data_ptr */
            &num_static_addrs,          /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,     /* affects dissection of packets, but not set of named fields */
            NULL,                       /* help */
            addr_uat_copy_cb,           /* copy callback */
            addr_uat_update_cb,         /* update callback */
            addr_uat_free_cb,           /* free callback */
            NULL,                       /* post update callback */
            NULL,                       /* reset callback */
            addr_uat_flds);             /* UAT field definitions */
    prefs_register_uat_preference(ieee802154_module, "static_addr",
                "Static Addresses",
                "A table of static address mappings between 16-bit short addressing and EUI-64 addresses",
                static_addr_uat);

    /* Create a UAT for key management. */
    ieee802154_key_uat = uat_new("Keys",
            sizeof(ieee802154_key_t),   /* record size */
            "ieee802154_keys",          /* filename */
            TRUE,                       /* from_profile */
            &ieee802154_keys,           /* data_ptr */
            &num_ieee802154_keys,       /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,     /* affects dissection of packets, but not set of named fields */
            NULL,                       /* help */
            ieee802154_key_copy_cb,     /* copy callback */
            ieee802154_key_update_cb,   /* update callback */
            ieee802154_key_free_cb,     /* free callback */
            ieee802154_key_post_update_cb, /* post update callback */
            NULL,                       /* reset callback */
            key_uat_flds);              /* UAT field definitions */
    prefs_register_uat_preference(ieee802154_module, "ieee802154_keys",
                "Decryption Keys",
                "Decryption key configuration data",
                ieee802154_key_uat);

    /* Register preferences for a decryption key */
    prefs_register_obsolete_preference(ieee802154_module, "802154_key");

    prefs_register_enum_preference(ieee802154_module, "802154_sec_suite",
                                   "Security Suite (802.15.4-2003)",
                                   "Specifies the security suite to use for 802.15.4-2003 secured frames"
                                   " (only supported suites are listed). Option ignored for 802.15.4-2006"
                                   " and unsecured frames.",
                                   &ieee802154_sec_suite, ieee802154_2003_sec_suite_enums, FALSE);

    prefs_register_bool_preference(ieee802154_module, "802154_extend_auth",
                                   "Extend authentication data (802.15.4-2003)",
                                   "Set if the manufacturer extends the authentication data with the"
                                   " security header. Option ignored for 802.15.4-2006 and unsecured frames.",
                                   &ieee802154_extend_auth);

    /* Register the subdissector list */
    panid_dissector_table = register_dissector_table(IEEE802154_PROTOABBREV_WPAN_PANID, "IEEE 802.15.4 PANID", proto_ieee802154, FT_UINT16, BASE_HEX);
    ieee802154_heur_subdissector_list = register_heur_dissector_list(IEEE802154_PROTOABBREV_WPAN, proto_ieee802154);
    ieee802154_beacon_subdissector_list = register_heur_dissector_list(IEEE802154_PROTOABBREV_WPAN_BEACON, proto_ieee802154);

    /* Register dissector tables */
    header_ie_dissector_table = register_dissector_table(IEEE802154_HEADER_IE_DTABLE, "IEEE 802.15.4 Header IEs", proto_ieee802154, FT_UINT8, BASE_HEX);
    payload_ie_dissector_table = register_dissector_table(IEEE802154_PAYLOAD_IE_DTABLE, "IEEE 802.15.4 Payload IEs", proto_ieee802154, FT_UINT8, BASE_HEX);
    mlme_ie_dissector_table = register_dissector_table(IEEE802154_MLME_IE_DTABLE, "IEEE 802.15.4 Nested IEs", proto_ieee802154, FT_UINT8, BASE_HEX);
    cmd_vendor_dissector_table = register_dissector_table(IEEE802154_CMD_VENDOR_DTABLE, "IEEE 802.15.4 Vendor Specific Commands", proto_ieee802154, FT_UINT24, BASE_HEX );

    /* Register dissectors with Wireshark */
    ieee802154_handle = register_dissector(IEEE802154_PROTOABBREV_WPAN, dissect_ieee802154, proto_ieee802154);
    ieee802154_nofcs_handle = register_dissector("wpan_nofcs", dissect_ieee802154_nofcs, proto_ieee802154);
    register_dissector("wpan_cc24xx", dissect_ieee802154_cc24xx, proto_ieee802154);
    ieee802154_nonask_phy_handle = register_dissector("wpan-nonask-phy", dissect_ieee802154_nonask_phy, proto_ieee802154_nonask_phy);
    ieee802154_tap_handle = register_dissector("wpan-tap", dissect_ieee802154_tap, proto_ieee802154_tap);

    /* Setup registration for other dissectors to provide mac key hash algorithms */
    mac_key_hash_handlers = wmem_tree_new(wmem_epan_scope());

    /* Register a Decode-As handler */
    register_decode_as(&ieee802154_da);

    /* Create trees for transactions */
    transaction_unmatched_pdus = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    transaction_matched_pdus = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    ieee802154_tap = register_tap(IEEE802154_PROTOABBREV_WPAN);

    register_conversation_table(proto_ieee802154, TRUE, ieee802154_conversation_packet, ieee802154_hostlist_packet);
    register_conversation_filter(IEEE802154_PROTOABBREV_WPAN, "IEEE 802.15.4", ieee802154_filter_valid, ieee802154_build_filter);
} /* proto_register_ieee802154 */


/**
 * Registers the IEEE 802.15.4 dissector with Wireshark.
 * Will be called every time 'apply' is pressed in the preferences menu.
 * as well as during Wireshark initialization
 */
void proto_reg_handoff_ieee802154(void)
{
    static gboolean            prefs_initialized = FALSE;
    static unsigned int        old_ieee802154_ethertype;

    if (!prefs_initialized) {
        /* Get the dissector handles. */
        zigbee_ie_handle = find_dissector_add_dependency("zbee_ie", proto_ieee802154);
        zigbee_nwk_handle = find_dissector("zbee_nwk");

        dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE802_15_4, ieee802154_handle);
        dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE802_15_4_NONASK_PHY, ieee802154_nonask_phy_handle);
        dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE802_15_4_NOFCS, ieee802154_nofcs_handle);
        dissector_add_uint("wtap_encap", WTAP_ENCAP_IEEE802_15_4_TAP, ieee802154_tap_handle);
        dissector_add_uint("sll.ltype", LINUX_SLL_P_IEEE802154, ieee802154_handle);

        /* Register internal IE handlers */
        dissector_add_uint(IEEE802154_HEADER_IE_DTABLE, IEEE802154_HEADER_IE_TIME_CORR, create_dissector_handle(dissect_hie_time_correction, -1));
        dissector_add_uint(IEEE802154_HEADER_IE_DTABLE, IEEE802154_HEADER_IE_CSL, create_dissector_handle(dissect_hie_csl, -1));
        dissector_add_uint(IEEE802154_HEADER_IE_DTABLE, IEEE802154_HEADER_IE_RENDEZVOUS, create_dissector_handle(dissect_hie_rendezvous_time, -1));
        dissector_add_uint(IEEE802154_HEADER_IE_DTABLE, IEEE802154_HEADER_IE_GLOBAL_TIME, create_dissector_handle(dissect_hie_global_time, -1));
        dissector_add_uint(IEEE802154_HEADER_IE_DTABLE, IEEE802154_HEADER_IE_VENDOR_SPECIFIC, create_dissector_handle(dissect_hie_vendor_specific, -1));

        dissector_add_uint(IEEE802154_PAYLOAD_IE_DTABLE, IEEE802154_PAYLOAD_IE_MLME, create_dissector_handle(dissect_pie_mlme, -1));
        dissector_add_uint(IEEE802154_PAYLOAD_IE_DTABLE, IEEE802154_PAYLOAD_IE_VENDOR, create_dissector_handle(dissect_pie_vendor, -1));
        dissector_add_uint(IEEE802154_PAYLOAD_IE_DTABLE, IEEE802154_PAYLOAD_IE_MPX, create_dissector_handle(dissect_mpx_ie, -1));
        dissector_add_uint(IEEE802154_PAYLOAD_IE_DTABLE, IEEE802154_PAYLOAD_IE_IETF, create_dissector_handle(dissect_ietf_ie, -1));

        dissector_add_uint(IEEE802154_MLME_IE_DTABLE, IEEE802154_MLME_SUBIE_CHANNEL_HOPPING, create_dissector_handle(dissect_802154_channel_hopping, -1));
        dissector_add_uint(IEEE802154_MLME_IE_DTABLE, IEEE802154_MLME_SUBIE_TSCH_SYNCH, create_dissector_handle(dissect_802154_tsch_time_sync, -1));
        dissector_add_uint(IEEE802154_MLME_IE_DTABLE, IEEE802154_MLME_SUBIE_TSCH_SLOTFR_LINK, create_dissector_handle(dissect_802154_tsch_slotframe_link, -1));
        dissector_add_uint(IEEE802154_MLME_IE_DTABLE, IEEE802154_MLME_SUBIE_TSCH_TIMESLOT, create_dissector_handle(dissect_802154_tsch_timeslot, -1));
        dissector_add_uint(IEEE802154_MLME_IE_DTABLE, IEEE802154_MLME_SUBIE_ENHANCED_BEACON_FILTER, create_dissector_handle(dissect_802154_eb_filter, -1));

        /* For the MPX-IE */
        ethertype_table = find_dissector_table("ethertype");
        eapol_handle = find_dissector("eapol");
        lowpan_handle = find_dissector("6lowpan");
        wisun_sec_handle = find_dissector("wisun.sec");
        prefs_initialized = TRUE;
    } else {
        dissector_delete_uint("ethertype", old_ieee802154_ethertype, ieee802154_handle);
    }

    old_ieee802154_ethertype = ieee802154_ethertype;

    /* Register dissector handles. */
    dissector_add_uint("ethertype", ieee802154_ethertype, ieee802154_handle);

} /* proto_reg_handoff_ieee802154 */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
