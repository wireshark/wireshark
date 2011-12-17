/* packet-zbee-security.c
 * Dissector helper routines for encrypted ZigBee frames.
 * By Owen Kirby <osk@exegin.com>; portions by Fred Fierling <fff@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*  Include Files */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVEHCONFIG_H */

#include <string.h>

#include <epan/packet.h>

#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>

/* We require libgcrpyt in order to decrypt ZigBee packets. Without it the best
 * we can do is parse the security header and give up.
 */
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif /* HAVE_LIBGCRYPT */

#include "packet-ieee802154.h"
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-security.h"

/* Helper Functions */
#ifdef HAVE_LIBGCRYPT
static gboolean    zbee_sec_ccm_decrypt(const gchar *, const gchar *, const gchar *, const gchar *, gchar *,
        guint, guint, guint);
static guint8 *    zbee_sec_key_hash(guint8 *, guint8, guint8 *);
static void        zbee_sec_make_nonce (zbee_security_packet *, guint8 *);
static gboolean    zbee_sec_decrypt_payload(zbee_security_packet *, const gchar *, const gchar, guint8 *,
        guint, guint, guint8 *);
#endif
static gboolean    zbee_security_parse_key(const gchar *, guint8 *, gboolean);
static void proto_init_zbee_security(void);

/* Field pointers. */
static int hf_zbee_sec_key_id = -1;
static int hf_zbee_sec_nonce = -1;
static int hf_zbee_sec_counter = -1;
static int hf_zbee_sec_src64 = -1;
static int hf_zbee_sec_key_seqno = -1;
static int hf_zbee_sec_mic = -1;
static int hf_zbee_sec_key_origin = -1;

/* Subtree pointers. */
static gint ett_zbee_sec = -1;
static gint ett_zbee_sec_control = -1;

static dissector_handle_t   data_handle;

static const value_string zbee_sec_key_names[] = {
    { ZBEE_SEC_KEY_LINK,        "Link Key" },
    { ZBEE_SEC_KEY_NWK,         "Network Key" },
    { ZBEE_SEC_KEY_TRANSPORT,   "Key-Transport Key" },
    { ZBEE_SEC_KEY_LOAD,        "Key-Load Key" },
    { 0, NULL }
};

#if 0
/* These aren't really used anymore, as ZigBee no longer includes them in the
 * security control field. If we were to display them all we would ever see is
 * security level 0.
 */
static const value_string zbee_sec_level_names[] = {
    { ZBEE_SEC_NONE,        "None" },
    { ZBEE_SEC_MIC32,       "No Encryption, 32-bit MIC" },
    { ZBEE_SEC_MIC64,       "No Encryption, 64-bit MIC" },
    { ZBEE_SEC_MIC128,      "No Encryption, 128-bit MIC" },
    { ZBEE_SEC_ENC,         "Encryption, No MIC" },
    { ZBEE_SEC_ENC_MIC32,   "Encryption, 32-bit MIC" },
    { ZBEE_SEC_ENC_MIC64,   "Encryption, 64-bit MIC" },
    { ZBEE_SEC_ENC_MIC128,  "Encryption, 128-bit MIC" },
    { 0, NULL }
};
#endif

/* The ZigBee security level, in enum_val_t for the security preferences. */
static enum_val_t zbee_sec_level_enums[] = {
    { "None",       "No Security",                                      ZBEE_SEC_NONE },
    { "MIC32",      "No Encryption, 32-bit Integrity Protection",       ZBEE_SEC_MIC32 },
    { "MIC64",      "No Encryption, 64-bit Integrity Protection",       ZBEE_SEC_MIC64 },
    { "MIC128",     "No Encryption, 128-bit Integrity Protection",      ZBEE_SEC_MIC128 },
    { "ENC",        "AES-128 Encryption, No Integrity Protection",      ZBEE_SEC_ENC },
    { "ENC-MIC32",  "AES-128 Encryption, 32-bit Integrity Protection",  ZBEE_SEC_ENC_MIC32 },
    { "ENC-MIC64",  "AES-128 Encryption, 64-bit Integrity Protection",  ZBEE_SEC_ENC_MIC64 },
    { "ENC-MIC128", "AES-128 Encryption, 128-bit Integrity Protection", ZBEE_SEC_ENC_MIC128 },
    { NULL, NULL, 0 }
};

static gint         gPREF_zbee_sec_level = ZBEE_SEC_ENC_MIC32;
static uat_t       *zbee_sec_key_table_uat;

static const value_string byte_order_vals[] = {
    { 0, "Normal"},
    { 1, "Reverse"},
    { 0, NULL }
};

/* UAT Key Entry */
typedef struct _uat_key_record_t {
    gchar    *string;
    guint8    byte_order;
    gchar    *label;
    guint8    key[ZBEE_SEC_CONST_KEYSIZE];
} uat_key_record_t;

/*  */
static uat_key_record_t *uat_key_records = NULL;
static guint             num_uat_key_records = 0;

static void* uat_key_record_copy_cb(void* n, const void* o, size_t siz _U_) {
    uat_key_record_t* new_key = (uat_key_record_t *)n;
    const uat_key_record_t* old_key = (uat_key_record_t *)o;

    if (old_key->string) {
        new_key->string = g_strdup(old_key->string);
    } else {
        new_key->string = NULL;
    }

    if (old_key->label) {
        new_key->label = g_strdup(old_key->label);
    } else {
        new_key->label = NULL;
    }

    return new_key;
}

static void uat_key_record_update_cb(void* r, const char** err) {
    uat_key_record_t* rec = (uat_key_record_t *)r;

    if (rec->string == NULL) {
         *err = ep_strdup_printf("Key can't be blank");
    } else {
        g_strstrip(rec->string);

        if (rec->string[0] != 0) {
            *err = NULL;
            if ( !zbee_security_parse_key(rec->string, rec->key, rec->byte_order) ) {
                *err = ep_strdup_printf("Expecting %d hexadecimal bytes or\n"
                        "a %d character double-quoted string", ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
            }
        } else {
            *err = ep_strdup_printf("Key can't be blank");
        }
    }
}

static void uat_key_record_free_cb(void*r) {
    uat_key_record_t* key = (uat_key_record_t *)r;

    if (key->string) g_free(key->string);
    if (key->label) g_free(key->label);
}

UAT_CSTRING_CB_DEF(uat_key_records, string, uat_key_record_t)
UAT_VS_DEF(uat_key_records, byte_order, uat_key_record_t, 0, "Normal")
UAT_CSTRING_CB_DEF(uat_key_records, label, uat_key_record_t)

static GSList *zbee_pc_keyring = NULL;

/*
 * Enable this macro to use libgcrypt's CBC_MAC mode for the authentication
 * phase. Unfortunately, this is broken, and I don't know why. However, using
 * the messier EBC mode (to emulate CCM*) still works fine.
 */
#if 0
#define ZBEE_SEC_USE_GCRYPT_CBC_MAC
#endif
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_security_register
 *  DESCRIPTION
 *      Called by proto_register_zbee_nwk() to initialize the security
 *      dissectors.
 *  PARAMETERS
 *      module_t    zbee_prefs   - Prefs module to load preferences under.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void zbee_security_register(module_t *zbee_prefs, int proto)
{
    static hf_register_info hf[] = {
        { &hf_zbee_sec_key_id,
          { "Key Id",                    "zbee.sec.key", FT_UINT8, BASE_HEX, VALS(zbee_sec_key_names),
            ZBEE_SEC_CONTROL_KEY, NULL, HFILL }},

        { &hf_zbee_sec_nonce,
          { "Extended Nonce",         "zbee.sec.ext_nonce", FT_BOOLEAN, 8, NULL, ZBEE_SEC_CONTROL_NONCE,
            NULL, HFILL }},

        { &hf_zbee_sec_counter,
          { "Frame Counter",          "zbee.sec.counter", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_src64,
          { "Extended Source",                 "zbee.sec.src64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_key_seqno,
          { "Key Sequence Number",    "zbee.sec.key_seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_mic,
          { "Message Integrity Code", "zbee.sec.mic", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_key_origin,
          { "Key Origin", "zbee.sec.key.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_zbee_sec,
        &ett_zbee_sec_control
    };

    static uat_field_t key_uat_fields[] = {
        UAT_FLD_CSTRING(uat_key_records, string, "Key",
                        "A 16-byte key in hexadecimal with optional dash-,\n"
                        "colon-, or space-separator characters, or a\n"
                        "a 16-character string in double-quotes."),
        UAT_FLD_VS(uat_key_records, byte_order, "Byte Order", byte_order_vals,
                        "Byte order of key."),
        UAT_FLD_LSTRING(uat_key_records, label, "Label", "User label for key."),
        UAT_END_FIELDS
    };

    /* If no prefs module was supplied, register our own. */
    if (zbee_prefs == NULL) {
        zbee_prefs = prefs_register_protocol(proto, NULL);
    }

    /*  Register preferences */
    prefs_register_enum_preference(zbee_prefs, "seclevel", "Security Level",
                 "Specifies the security level to use in the\n"
                 "decryption process. This value is ignored\n"
                 "for ZigBee 2004 and unsecured networks.",
                 &gPREF_zbee_sec_level, zbee_sec_level_enums, FALSE);

    zbee_sec_key_table_uat = uat_new("Pre-configured Keys",
                               sizeof(uat_key_record_t),
                               "zigbee_pc_keys",
                               TRUE,
                               (void*) &uat_key_records,
                               &num_uat_key_records,
                               UAT_CAT_FFMT,
                               NULL,  /* TODO: ptr to help manual? */
                               uat_key_record_copy_cb,
                               uat_key_record_update_cb,
                               uat_key_record_free_cb,
                               NULL, /* TODO: post_update */
                               key_uat_fields );

    prefs_register_uat_preference(zbee_prefs,
                                  "key_table",
                                  "Pre-configured Keys",
                                  "Pre-configured link or network keys.",
                                  zbee_sec_key_table_uat);

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the init routine. */
    register_init_routine(proto_init_zbee_security);
} /* zbee_security_register */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_security_parse_key
 *  DESCRIPTION
 *      Parses a key string from left to right into a buffer with
 *      increasing (normal byte order) or decreasing (reverse byte
 *      order) address.
 *  PARAMETERS
 *      const gchar    *key_str - pointer to the string
 *      guint8         *key_buf - destination buffer in memory
 *      gboolean        big_end - fill key_buf with incrementing address
 *  RETURNS
 *      gboolean
 *---------------------------------------------------------------
 */
static gboolean
zbee_security_parse_key(const gchar *key_str, guint8 *key_buf, gboolean byte_order)
{
    int             i, j;
    gchar           temp;
    gboolean        string_mode = FALSE;

    /* Clear the key. */
    memset(key_buf, 0, ZBEE_SEC_CONST_KEYSIZE);
    if (key_str == NULL) {
        return FALSE;
    }

    /*
     * Attempt to parse the key string. The key string must
     * be at least 16 pairs of hexidecimal digits with the
     * following optional separators: ':', '-', " ", or 16
     * alphanumeric characters after a double-quote.
     */
    if ( (temp = *key_str++) == '"') {
        string_mode = TRUE;
        temp = *key_str++;
    }

    j = byte_order?ZBEE_SEC_CONST_KEYSIZE-1:0;
    for (i=ZBEE_SEC_CONST_KEYSIZE-1; i>=0; i--) {
        if ( string_mode ) {
            if ( g_ascii_isprint(temp) ) {
                key_buf[j] = temp;
                temp = *key_str++;
            } else {
                return FALSE;
            }
        }
        else {
            /* If this character is a separator, skip it. */
            if ( (temp == ':') || (temp == '-') || (temp == ' ') ) temp = *(key_str++);

            /* Process a nibble. */
            if ( g_ascii_isxdigit (temp) ) key_buf[j] = g_ascii_xdigit_value(temp)<<4;
            else return FALSE;

            /* Get the next nibble. */
            temp = *(key_str++);

            /* Process another nibble. */
            if ( g_ascii_isxdigit (temp) ) key_buf[j] |= g_ascii_xdigit_value(temp);
            else return FALSE;

            /* Get the next nibble. */
            temp = *(key_str++);
        }

        /* Move key_buf pointer */
        if ( byte_order ) {
            j--;
        } else {
            j++;
        }

    } /* for */

    /* If we get this far, then the key was good. */
    return TRUE;
} /* zbee_security_parse_key */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_security_handoff
 *  DESCRIPTION
 *      Hands off the security dissector.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      tvbuff_t *
 *---------------------------------------------------------------
 */
void
zbee_security_handoff(void)
{
    /* Lookup the data dissector. */
    data_handle = find_dissector("data");
} /* zbee_security_handoff */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_secure
 *  DESCRIPTION
 *      Dissects and decrypts secured ZigBee frames.
 *
 *      Will return a valid tvbuff only if security processing was
 *      successful. If processing fails, then this function will
 *      handle internally and return NULL.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *      guint       offset  - pointer to the start of the auxilliary security header.
 *      guint64     src64   - extended source address, or 0 if unknown.
 *  RETURNS
 *      tvbuff_t *
 *---------------------------------------------------------------
 */
tvbuff_t *
dissect_zbee_secure(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree, guint offset)
{
    proto_tree     *sec_tree = NULL;
    proto_item     *sec_root;
    proto_tree     *field_tree;
    proto_item     *ti;

    zbee_security_packet    packet;
    guint           mic_len;
    gint            payload_len;
    tvbuff_t       *payload_tvb;

#ifdef HAVE_LIBGCRYPT
    guint8             *enc_buffer;
    guint8             *dec_buffer;
    gboolean            decrypted;
    GSList            **nwk_keyring;
    GSList             *GSList_i;
    key_record_t       *key_rec = NULL;
#endif
    zbee_nwk_hints_t   *nwk_hints;
    ieee802154_hints_t *ieee_hints;
    ieee802154_map_rec *map_rec = NULL;

    /* Init */
    memset(&packet, 0, sizeof(zbee_security_packet));

    /* Get pointers to any useful frame data from lower layers */
    nwk_hints = (zbee_nwk_hints_t *)p_get_proto_data(pinfo->fd, proto_get_id_by_filter_name(ZBEE_PROTOABBREV_NWK));
    ieee_hints = (ieee802154_hints_t *)p_get_proto_data(pinfo->fd,
    proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN));

    /* Create a subtree for the security information. */
    if (tree) {
        sec_root = proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "ZigBee Security Header");
        sec_tree = proto_item_add_subtree(sec_root, ett_zbee_sec);
    }

    /*  Get and display the Security control field */
    packet.control  = tvb_get_guint8(tvb, offset);

    /* Patch the security level. */
    packet.control &= ~ZBEE_SEC_CONTROL_LEVEL;
    packet.control |= (ZBEE_SEC_CONTROL_LEVEL & gPREF_zbee_sec_level);

    /*
     * Eww, I think I just threw up a little...  ZigBee requires this field
     * to be patched before computing the MIC, but we don't have write-access
     * to the tvbuff. So we need to allocate a copy of the whole thing just
     * so we can fix these 3 bits. Memory allocated by ep_tvb_memdup() is
     * automatically freed before the next packet is processed.
     */
#ifdef HAVE_LIBGCRYPT
    enc_buffer = (guint8 *)ep_tvb_memdup(tvb, 0, tvb_length(tvb));
    /*
     * Override the const qualifiers and patch the security level field, we
     * know it is safe to overide the const qualifiers because we just
     * allocated this memory via ep_tvb_memdup().
     */
    enc_buffer[offset] = packet.control;
#endif /* HAVE_LIBGCRYPT */
    packet.level    = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_LEVEL);
    packet.key_id   = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_KEY);
    packet.nonce    = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_NONCE);
    if (tree) {
        ti = proto_tree_add_text(sec_tree, tvb, offset, 1, "Security Control Field");
        field_tree = proto_item_add_subtree(ti, ett_zbee_sec_control);

        proto_tree_add_uint(field_tree, hf_zbee_sec_key_id, tvb, offset, 1,
                                packet.control & ZBEE_SEC_CONTROL_KEY);
        proto_tree_add_boolean(field_tree, hf_zbee_sec_nonce, tvb, offset, 1,
                                packet.control & ZBEE_SEC_CONTROL_NONCE);
    }
    offset += 1;

    /* Get and display the frame counter field. */
    packet.counter = tvb_get_letohl(tvb, offset);
    if (tree) {
        proto_tree_add_uint(sec_tree, hf_zbee_sec_counter, tvb, offset, 4, packet.counter);
    }
    offset += 4;

    if (packet.nonce) {
        /* Get and display the source address of the device that secured this payload. */
        packet.src64 = tvb_get_letoh64(tvb, offset);
        if (tree) {
            proto_tree_add_item(sec_tree, hf_zbee_sec_src64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        }
#if 1
        if (!pinfo->fd->flags.visited) {
            switch ( packet.key_id ) {
                case ZBEE_SEC_KEY_LINK:
                if (nwk_hints) {
                    /* Map this long address with the nwk layer short address. */
                    nwk_hints->map_rec = ieee802154_addr_update(&zbee_nwk_map, nwk_hints->src,
                            ieee_hints->src_pan, packet.src64, pinfo->current_proto, pinfo->fd->num);
                }
                break;

                case ZBEE_SEC_KEY_NWK:
                if (ieee_hints) {
                    /* Map this long address with the ieee short address. */
                    ieee_hints->map_rec = ieee802154_addr_update(&zbee_nwk_map, ieee_hints->src16,
                        ieee_hints->src_pan, packet.src64, pinfo->current_proto, pinfo->fd->num);
                }
                break;

                /* We ignore the extended source addresses used to encrypt payloads with these
                 * types of keys, because they can emerge from APS tunnels created by nodes whose
                 * short address is not recorded in the packet. */
                case ZBEE_SEC_KEY_TRANSPORT:
                case ZBEE_SEC_KEY_LOAD:
                break;
            }
        }
#endif
        offset += 8;
    }
    else {
        /* Look for a source address in hints */
        switch ( packet.key_id ) {
            case ZBEE_SEC_KEY_NWK:
                /* use the ieee extended source address for NWK decryption */
                if ( ieee_hints && (map_rec = ieee_hints->map_rec) ) packet.src64 = map_rec->addr64;
                else if (tree) proto_tree_add_text(sec_tree, tvb, 0, 0, "[Extended Source: Unknown]");
                break;

            default:
                /* use the nwk extended source address for APS decryption */
                if ( nwk_hints && (map_rec = nwk_hints->map_rec) ) packet.src64 = map_rec->addr64;
                else if (tree) proto_tree_add_text(sec_tree, tvb, 0, 0, "[Extended Source: Unknown]");
                break;
        }
    }

    if (packet.key_id == ZBEE_SEC_KEY_NWK) {
        /* Get and display the key sequence number. */
        packet.key_seqno = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(sec_tree, hf_zbee_sec_key_seqno, tvb, offset, 1, packet.key_seqno);
        }
        offset += 1;
    }

    /* Determine the length of the MIC. */
    switch (packet.level) {
        case ZBEE_SEC_ENC:
        case ZBEE_SEC_NONE:
        default:
            mic_len=0;
            break;

        case ZBEE_SEC_ENC_MIC32:
        case ZBEE_SEC_MIC32:
            mic_len=4;
            break;

        case ZBEE_SEC_ENC_MIC64:
        case ZBEE_SEC_MIC64:
            mic_len=8;
            break;

        case ZBEE_SEC_ENC_MIC128:
        case ZBEE_SEC_MIC128:
            mic_len=16;
            break;
    } /* switch */

    /* Get and display the MIC. */
    if (mic_len) {
        /* Display the MIC. */
        if (tree) {
            proto_tree_add_item(sec_tree, hf_zbee_sec_mic, tvb, (gint)(tvb_length(tvb)-mic_len),
                   mic_len, ENC_NA);
        }
    }

    /* Check for null payload. */
    if ( !(payload_len = tvb_reported_length_remaining(tvb, offset+mic_len)) ) {
        return NULL;
    } else if ( payload_len < 0 ) {
        THROW(ReportedBoundsError);
    }

    /**********************************************
     *  Perform Security Operations on the Frame  *
     **********************************************
     */
    if ((packet.level == ZBEE_SEC_NONE) ||
        (packet.level == ZBEE_SEC_MIC32) ||
        (packet.level == ZBEE_SEC_MIC64) ||
        (packet.level == ZBEE_SEC_MIC128)) {

        /* Payload is only integrity protected. Just return the sub-tvbuff. */
        return tvb_new_subset(tvb, offset, payload_len, payload_len);
    }

#ifdef HAVE_LIBGCRYPT
    /* Allocate memory to decrypt the payload into. */
    dec_buffer = (guint8 *)g_malloc(payload_len);

    decrypted = FALSE;
    if ( packet.src64 ) {
        if (pinfo->fd->flags.visited) {
            if ( nwk_hints ) {
                /* Use previously found key */
                switch ( packet.key_id ) {
                    case ZBEE_SEC_KEY_NWK:
                        if ( (key_rec = nwk_hints->nwk) ) {
                            decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                                payload_len, mic_len, nwk_hints->nwk->key);
                        }
                        break;

                    default:
                        if ( (key_rec = nwk_hints->link) ) {
                            decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                                payload_len, mic_len, nwk_hints->link->key);
                        }
                        break;
                }
            }
        } /* ( !pinfo->fd->flags.visited ) */
        else {
            /* We only search for sniffed keys in the first pass,
             * to save time, and because decrypting with keys
             * transported in future packets is cheating */

            /* Lookup NWK and link key in hash for this pan. */
            /* This overkill approach is a placeholder for a hash that looks up
             * a key ring for a link key associated with a pair of devices.
             */
            if ( nwk_hints ) {
                nwk_keyring = (GSList **)g_hash_table_lookup(zbee_table_nwk_keyring, &nwk_hints->src_pan);

                if ( nwk_keyring ) {
                    GSList_i = *nwk_keyring;
                    while ( GSList_i && !decrypted ) {
                        decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                                payload_len, mic_len, ((key_record_t *)(GSList_i->data))->key);

                        if (decrypted) {
                            /* save pointer to the successful key record */
                            switch (packet.key_id) {
                                case ZBEE_SEC_KEY_NWK:
                                    key_rec = nwk_hints->nwk = (key_record_t *)(GSList_i->data);
                                    break;

                                default:
                                    key_rec = nwk_hints->link = (key_record_t *)(GSList_i->data);
                                    break;
                            }
                        } else {
                            GSList_i = g_slist_next(GSList_i);
                        }
                    }
                }

                /* Loop through user's password table for preconfigured keys, our last resort */
                GSList_i = zbee_pc_keyring;
                while ( GSList_i && !decrypted ) {
                    decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                            payload_len, mic_len, ((key_record_t *)(GSList_i->data))->key);

                    if (decrypted) {
                        /* save pointer to the successful key record */
                        switch (packet.key_id) {
                            case ZBEE_SEC_KEY_NWK:
                                key_rec = nwk_hints->nwk = (key_record_t *)(GSList_i->data);
                                break;

                            default:
                                key_rec = nwk_hints->link = (key_record_t *)(GSList_i->data);
                                break;
                        }
                    } else {
                        GSList_i = g_slist_next(GSList_i);
                    }
                }
            }
        } /* ( ! pinfo->fd->flags.visited ) */
    } /* ( packet.src64 ) */

    if ( decrypted ) {
        if ( tree && key_rec ) {
            if ( key_rec->frame_num == ZBEE_SEC_PC_KEY ) {
                ti = proto_tree_add_text(sec_tree, tvb, 0, 0, "Decryption Key: %s", key_rec->label);
            } else {
                ti = proto_tree_add_uint(sec_tree, hf_zbee_sec_key_origin, tvb, 0, 0,
                        key_rec->frame_num);
            }
            PROTO_ITEM_SET_GENERATED(ti);
        }

        /* Found a key that worked, setup the new tvbuff_t and return */
        payload_tvb = tvb_new_child_real_data(tvb, dec_buffer, payload_len, payload_len);
        tvb_set_free_cb(payload_tvb, g_free); /* set up callback to free dec_buffer */
        add_new_data_source(pinfo, payload_tvb, "Decrypted ZigBee Payload");

        /* Done! */
        return payload_tvb;
    }

    g_free(dec_buffer);
#endif /* HAVE_LIBGCRYPT */

    /* Add expert info. */
    expert_add_info_format(pinfo, sec_tree, PI_UNDECODED, PI_WARN, "Encrypted Payload");
    /* Create a buffer for the undecrypted payload. */
    payload_tvb = tvb_new_subset(tvb, offset, payload_len, -1);
    /* Dump the payload to the data dissector. */
    call_dissector(data_handle, payload_tvb, pinfo, tree);
    /* Couldn't decrypt, so return NULL. */
    return NULL;
} /* dissect_zbee_secure */

#ifdef HAVE_LIBGCRYPT
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_decrypt_payload
 *  DESCRIPTION
 *      Creates a nonce and decrypts a secured payload.
 *  PARAMETERS
 *      gchar                *nonce  - Nonce Buffer.
 *      zbee_security_packet *packet - Security information.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static gboolean
zbee_sec_decrypt_payload(zbee_security_packet *packet, const gchar *enc_buffer, const gchar offset, guint8 *dec_buffer,
        guint payload_len, guint mic_len, guint8 *key)
{
    guint8  nonce[ZBEE_SEC_CONST_NONCE_LEN];
    guint8  buffer[ZBEE_SEC_CONST_BLOCKSIZE+1];
    guint8 *key_buffer = buffer;

    switch (packet->key_id) {
        case ZBEE_SEC_KEY_NWK:
            /* Decrypt with the PAN's current network key */
        case ZBEE_SEC_KEY_LINK:
            /* Decrypt with the unhashed link key assigned by the trust center to this
             * source/destination pair */
            key_buffer = key;
            break;

        case ZBEE_SEC_KEY_TRANSPORT:
            /* Decrypt with a Key-Transport key, a hashed link key that protects network
             * keys sent from the trust center */
            zbee_sec_key_hash(key, 0x00, buffer);
            key_buffer = buffer;
            break;

        case ZBEE_SEC_KEY_LOAD:
            /* Decrypt with a Key-Load key, a hashed link key that protects link keys
             * sent from the trust center. */
            zbee_sec_key_hash(key, 0x02, buffer);
            key_buffer = buffer;
            break;

        default:
            break;
    } /* switch */

    /* Perform Decryption. */
    zbee_sec_make_nonce(packet, nonce);

    if ( zbee_sec_ccm_decrypt(key_buffer,   /* key */
                        nonce,              /* Nonce */
                        enc_buffer,         /* a, length l(a) */
                        enc_buffer+offset,  /* c, length l(c) = l(m) + M */
                        dec_buffer,         /* m, length l(m) */
                        offset,             /* l(a) */
                        payload_len,        /* l(m) */
                        mic_len) ) {        /* M */
        return TRUE;
    }
    else return FALSE;
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_make_nonce
 *  DESCRIPTION
 *      Fills in the ZigBee security nonce from the provided security
 *      packet structure.
 *  PARAMETERS
 *      zbee_security_packet *packet - Security information.
 *      gchar           *nonce  - Nonce Buffer.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zbee_sec_make_nonce(zbee_security_packet *packet, guint8 *nonce)
{
    /* First 8 bytes are the extended source address (little endian). */
    *(nonce++) = (guint8)((packet->src64)>>0 & 0xff);
    *(nonce++) = (guint8)((packet->src64)>>8 & 0xff);
    *(nonce++) = (guint8)((packet->src64)>>16 & 0xff);
    *(nonce++) = (guint8)((packet->src64)>>24 & 0xff);
    *(nonce++) = (guint8)((packet->src64)>>32 & 0xff);
    *(nonce++) = (guint8)((packet->src64)>>40 & 0xff);
    *(nonce++) = (guint8)((packet->src64)>>48 & 0xff);
    *(nonce++) = (guint8)((packet->src64)>>56 & 0xff);
    /* Next 4 bytes are the frame counter (little endian). */
    *(nonce++) = (guint8)((packet->counter)>>0 & 0xff);
    *(nonce++) = (guint8)((packet->counter)>>8 & 0xff);
    *(nonce++) = (guint8)((packet->counter)>>16 & 0xff);
    *(nonce++) = (guint8)((packet->counter)>>24 & 0xff);
    /* Next byte is the security control field. */
    *(nonce) = packet->control;
} /* zbee_sec_make_nonce */
#endif

#ifdef HAVE_LIBGCRYPT
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_ccm_decrypt
 *  DESCRIPTION
 *      Performs the Reverse CCM* Transformation (specified in
 *      section A.3 of ZigBee Specification (053474r17).
 *
 *      The length of parameter c (l(c)) is derived from the length
 *      of the payload and length of the MIC tag. Input buffer a
 *      will NOT be modified.
 *
 *      When l_m is 0, then there is no payload to encrypt (ie: the
 *      payload is in plaintext), and this function will perform
 *      MIC verification only. When l_m is 0, m may be NULL.
 *  PARAMETERS
 *      gchar   *key    - ZigBee Security Key (must be ZBEE_SEC_CONST_KEYSIZE) in length.
 *      gchar   *nonce  - ZigBee CCM* Nonce (must be ZBEE_SEC_CONST_NONCE_LEN) in length.
 *      gchar   *a      - CCM* Parameter a (must be l(a) in length). Additional data covered
 *                          by the authentication process.
 *      gchar   *c      - CCM* Parameter c (must be l(c) = l(m) + M in length). Encrypted
 *                          payload + encrypted authentication tag U.
 *      gchar   *m      - CCM* Output (must be l(m) in length). Decrypted Payload.
 *      guint   l_a     - l(a), length of CCM* parameter a.
 *      guint   l_m     - l(m), length of expected payload.
 *      guint   M       - M, length of CCM* authentication tag.
 *  RETURNS
 *      gboolean        - TRUE if successful.
 *---------------------------------------------------------------
 */
static gboolean
zbee_sec_ccm_decrypt(const gchar    *key,   /* Input */
                    const gchar     *nonce, /* Input */
                    const gchar     *a,     /* Input */
                    const gchar     *c,     /* Input */
                    gchar           *m,     /* Output */
                    guint           l_a,    /* sizeof(a) */
                    guint           l_m,    /* sizeof(m) */
                    guint           M)      /* sizeof(c) - sizeof(m) = sizeof(MIC) */
{
    guint8              cipher_in[ZBEE_SEC_CONST_BLOCKSIZE];
    guint8              cipher_out[ZBEE_SEC_CONST_BLOCKSIZE];
    guint8              decrypted_mic[ZBEE_SEC_CONST_BLOCKSIZE];
    guint               i, j;
    /* Cipher Instance. */
    gcry_cipher_hd_t    cipher_hd;

    /* Sanity-Check. */
    if (M > ZBEE_SEC_CONST_BLOCKSIZE) return FALSE;
    /*
     * The CCM* counter is L bytes in length, ensure that the payload
     * isn't long enough to overflow it.
     */
    if ((1 + (l_a/ZBEE_SEC_CONST_BLOCKSIZE)) > (1<<(ZBEE_SEC_CONST_L*8))) return FALSE;

    /******************************************************
     * Step 1: Encryption/Decryption Transformation
     ******************************************************
     */
    /* Create the CCM* counter block A0 */
    memset(cipher_in, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in + 1, nonce, ZBEE_SEC_CONST_NONCE_LEN);
    /*
     * The encryption/decryption process of CCM* works in CTR mode. Open a CTR
     * mode cipher for this phase. NOTE: The 'counter' part of the CCM* counter
     * block is the last two bytes, and is big-endian.
     */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
        return FALSE;
    }
    /* Set the Key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Set the counter. */
    if (gcry_cipher_setctr(cipher_hd, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /*
     * Copy the MIC into the stack buffer. We need to feed the cipher a full
     * block when decrypting the MIC (so that the payload starts on the second
     * block). However, the MIC may be less than a full block so use a fixed
     * size buffer to store the MIC, letting the CTR cipher overstep the MIC
     * if need be.
     */
    memset(decrypted_mic, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    memcpy(decrypted_mic, c + l_m, M);
    /* Encrypt/Decrypt the MIC in-place. */
    if (gcry_cipher_encrypt(cipher_hd, decrypted_mic, ZBEE_SEC_CONST_BLOCKSIZE, decrypted_mic, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Encrypt/Decrypt the payload. */
    if (gcry_cipher_encrypt(cipher_hd, m, l_m, c, l_m)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Done with the CTR Cipher. */
    gcry_cipher_close(cipher_hd);

    /******************************************************
     * Step 3: Authentication Transformation
     ******************************************************
     */
    if (M == 0) {
        /* There is no authentication tag. We're done! */
        return TRUE;
    }
    /*
     * The authentication process in CCM* operates in CBC-MAC mode, but
     * unfortunately, the input to the CBC-MAC process needs some substantial
     * transformation and padding before we can feed it into the CBC-MAC
     * algorithm. Instead we will operate in ECB mode and perform the
     * transformation and padding on the fly.
     *
     * I also think that libgcrypt requires the input to be memory-aligned
     * when using CBC-MAC mode, in which case can't just feed it with data
     * from the packet buffer. All things considered it's just a lot easier
     * to use ECB mode and do CBC-MAC manually.
     */
    /* Re-open the cipher in ECB mode. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return FALSE;
    }
    /* Re-load the key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Generate the first cipher block B0. */
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_M(M) |
                    ZBEE_SEC_CCM_FLAG_ADATA(l_a) |
                    ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in+sizeof(gchar), nonce, ZBEE_SEC_CONST_NONCE_LEN);
    for (i=0;i<ZBEE_SEC_CONST_L; i++) {
        cipher_in[(ZBEE_SEC_CONST_BLOCKSIZE-1)-i] = (l_m >> (8*i)) & 0xff;
    } /* for */
    /* Generate the first cipher block, X1 = E(Key, 0^128 XOR B0). */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /*
     * We avoid mallocing() big chunks of memory by recycling small stack
     * buffers for the encryption process. Throughout this process, j is always
     * pointed to the position within the current buffer.
     */
    j = 0;
    /* AuthData = L(a) || a || Padding || m || Padding
     * Where L(a) =
     *      - an empty string if l(a) == 0.
     *      - 2-octet encoding of l(a) if 0 < l(a) < (2^16 - 2^8)
     *      - 0xff || 0xfe || 4-octet encoding of l(a) if (2^16 - 2^8) <= l(a) < 2^32
     *      - 0xff || 0xff || 8-octet encoding of l(a)
     * But for ZigBee, the largest packet size we should ever see is 2^7, so we
     * are only really concerned with the first two cases.
     *
     * To generate the MIC tag CCM* operates similar to CBC-MAC mode. Each block
     * of AuthData is XOR'd with the last block of cipher output to produce the
     * next block of cipher output. Padding sections have the minimum non-negative
     * length such that the padding ends on a block boundary. Padded bytes are 0.
     */
    if (l_a > 0) {
        /* Process L(a) into the cipher block. */
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 8) & 0xff);
        j++;
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 0) & 0xff);
        j++;
        /* Process a into the cipher block. */
        for (i=0;i<l_a;i++,j++) {
            if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
                /* Generate the next cipher block. */
                if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                            ZBEE_SEC_CONST_BLOCKSIZE)) {
                    gcry_cipher_close(cipher_hd);
                    return FALSE;
                }
                /* Reset j to point back to the start of the new cipher block. */
                j = 0;
            }
            /* Cipher in = cipher_out ^ a */
            cipher_in[j] = cipher_out[j] ^ a[i];
        } /* for */
        /* Process padding into the cipher block. */
        for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
            cipher_in[j] = cipher_out[j];
    }
    /* Process m into the cipher block. */
    for (i=0; i<l_m; i++, j++) {
        if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
            /* Generate the next cipher block. */
            if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                       ZBEE_SEC_CONST_BLOCKSIZE)) {
                gcry_cipher_close(cipher_hd);
                return FALSE;
            }
            /* Reset j to point back to the start of the new cipher block. */
            j = 0;
        }
        /* Cipher in = cipher out ^ m */
        cipher_in[j] = cipher_out[j] ^ m[i];
    } /* for */
    /* Padding. */
    for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
        cipher_in[j] = cipher_out[j];
    /* Generate the last cipher block, which will be the MIC tag. */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Done with the Cipher. */
    gcry_cipher_close(cipher_hd);

    /* Compare the MIC's */
    return (memcmp(cipher_out, decrypted_mic, M) == 0);
} /* zbee_ccm_decrypt */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_hash
 *  DESCRIPTION
 *      ZigBee Cryptographic Hash Function, described in ZigBee
 *      specification sections B.1.3 and B.6.
 *
 *      This is a Matyas-Meyer-Oseas hash function using the AES-128
 *      cipher. We use the ECB mode of libgcrypt to get a raw block
 *      cipher.
 *
 *      Input may be any length, and the output must be exactly 1-block in length.
 *
 *      Implements the function:
 *          Hash(text) = Hash[t];
 *          Hash[0] = 0^(blocksize).
 *          Hash[i] = E(Hash[i-1], M[i]) XOR M[j];
 *          M[i] = i'th block of text, with some padding and flags concatenated.
 *  PARAMETERS
 *      guint8 *    input       - Hash Input (any length).
 *      guint8      input_len   - Hash Input Length.
 *      guint8 *    output      - Hash Output (exactly one block in length).
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zbee_sec_hash(guint8 *input, guint input_len, guint8 *output)
{
    guint8              cipher_in[ZBEE_SEC_CONST_BLOCKSIZE];
    guint               i, j;
    /* Cipher Instance. */
    gcry_cipher_hd_t    cipher_hd;

    /* Clear the first hash block (Hash0). */
    memset(output, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    /* Create the cipher instance in ECB mode. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return; /* Failed. */
    }
    /* Create the subsequent hash blocks using the formula: Hash[i] = E(Hash[i-1], M[i]) XOR M[i]
     *
     * because we can't garauntee that M will be exactly a multiple of the
     * block size, we will need to copy it into local buffers and pad it.
     *
     * Note that we check for the next cipher block at the end of the loop
     * rather than the start. This is so that if the input happens to end
     * on a block boundary, the next cipher block will be generated for the
     * start of the padding to be placed into.
     */
    i = 0;
    j = 0;
    while (i<input_len) {
        /* Copy data into the cipher input. */
        cipher_in[j++] = input[i++];
        /* Check if this cipher block is done. */
        if (j >= ZBEE_SEC_CONST_BLOCKSIZE) {
            /* We have reached the end of this block. Process it with the
             * cipher, note that the Key input to the cipher is actually
             * the previous hash block, which we are keeping in output.
             */
            (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
            (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
            /* Now we have to XOR the input into the hash block. */
            for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
            /* Reset j to start again at the beginning at the next block. */
            j = 0;
        }
    } /* for */
    /* Need to append the bit '1', followed by '0' padding long enough to end
     * the hash input on a block boundary. However, because 'n' is 16, and 'l'
     * will be a multiple of 8, the padding will be >= 7-bits, and we can just
     * append the byte 0x80.
     */
    cipher_in[j++] = 0x80;
    /* Pad with '0' until the the current block is exactly 'n' bits from the
     * end.
     */
    while (j!=(ZBEE_SEC_CONST_BLOCKSIZE-2)) {
        if (j >= ZBEE_SEC_CONST_BLOCKSIZE) {
            /* We have reached the end of this block. Process it with the
             * cipher, note that the Key input to the cipher is actually
             * the previous hash block, which we are keeping in output.
             */
            (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
            (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
            /* Now we have to XOR the input into the hash block. */
            for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
            /* Reset j to start again at the beginning at the next block. */
            j = 0;
        }
        /* Pad the input with 0. */
        cipher_in[j++] = 0x00;
    } /* while */
    /* Add the 'n'-bit representation of 'l' to the end of the block. */
    cipher_in[j++] = ((input_len * 8) >> 8) & 0xff;
    cipher_in[j] = ((input_len * 8) >> 0) & 0xff;
    /* Process the last cipher block. */
    (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
    (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
    /* XOR the last input block back into the cipher output to get the hash. */
    for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
    /* Cleanup the cipher. */
    gcry_cipher_close(cipher_hd);
    /* Done */
} /* zbee_sec_hash */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_key_hash
 *  DESCRIPTION
 *      ZigBee Keyed Hash Function. Described in ZigBee specification
 *      section B.1.4, and in FIPS Publication 198. Strictly speaking
 *      there is nothing about the Keyed Hash Function which restricts
 *      it to only a single byte input, but that's all ZigBee ever uses.
 *
 *      This function implements the hash function:
 *          Hash(Key, text) = H((Key XOR opad) || H((Key XOR ipad) || text));
 *          ipad = 0x36 repeated.
 *          opad = 0x5c repeated.
 *          H() = ZigBee Cryptographic Hash (B.1.3 and B.6).
 *
 *      The output of this function is an ep_alloced buffer containing
 *      the key-hashed output, and is garaunteed never to return NULL.
 *  PARAMETERS
 *      guint8  *key    - ZigBee Security Key (must be ZBEE_SEC_CONST_KEYSIZE) in length.
 *      guint8  input   - ZigBee CCM* Nonce (must be ZBEE_SEC_CONST_NONCE_LEN) in length.
 *      packet_info *pinfo  - pointer to packet information fields
 *  RETURNS
 *      guint8*
 *---------------------------------------------------------------
 */
static guint8 *
zbee_sec_key_hash(guint8 *key, guint8 input, guint8 *hash_out)
{
    guint8              hash_in[2*ZBEE_SEC_CONST_BLOCKSIZE];
    int                 i;
    static const guint8 ipad = 0x36;
    static const guint8 opad = 0x5c;

    /* Copy the key into hash_in and XOR with opad to form: (Key XOR opad) */
    for (i=0; i<ZBEE_SEC_CONST_KEYSIZE; i++) hash_in[i] = key[i] ^ opad;
    /* Copy the Key into hash_out and XOR with ipad to form: (Key XOR ipad) */
    for (i=0; i<ZBEE_SEC_CONST_KEYSIZE; i++) hash_out[i] = key[i] ^ ipad;
    /* Append the input byte to form: (Key XOR ipad) || text. */
    hash_out[ZBEE_SEC_CONST_BLOCKSIZE] = input;
    /* Hash the contents of hash_out and append the contents to hash_in to
     * form: (Key XOR opad) || H((Key XOR ipad) || text).
     */
    zbee_sec_hash(hash_out, ZBEE_SEC_CONST_BLOCKSIZE+1, hash_in+ZBEE_SEC_CONST_BLOCKSIZE);
    /* Hash the contents of hash_in to get the final result. */
    zbee_sec_hash(hash_in, 2*ZBEE_SEC_CONST_BLOCKSIZE, hash_out);
    return hash_out;
} /* zbee_sec_key_hash */
#endif  /* HAVE_LIBGCRYPT */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_init_zbee_security
 *  DESCRIPTION
 *      Init routine for the
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
proto_init_zbee_security(void)
{
    guint           i;
    key_record_t    key_record;

        /* empty the key ring */
    if (zbee_pc_keyring) {
       g_slist_free(zbee_pc_keyring);
       zbee_pc_keyring = NULL;
    }

    /* Load the pre-configured slist from the UAT. */
    for (i=0; (uat_key_records) && (i<num_uat_key_records) ; i++) {
        key_record.frame_num = ZBEE_SEC_PC_KEY; /* means it's a user PC key */
        key_record.label = se_strdup(uat_key_records[i].label);
        memcpy(&key_record.key, &uat_key_records[i].key, ZBEE_SEC_CONST_KEYSIZE);

        zbee_pc_keyring = g_slist_prepend(zbee_pc_keyring, se_memdup(&key_record, sizeof(key_record_t)));
    } /* for */
} /* proto_init_zbee_security */
