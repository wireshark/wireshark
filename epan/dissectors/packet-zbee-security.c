/* packet-zbee-security.c
 * Dissector helper routines for encrypted ZigBee frames.
 * By Owen Kirby <osk@exegin.com>
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
#include <stdlib.h>
#include <glib.h>
#include <gmodule.h>
#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* We require libgcrpyt in order to decrypt ZigBee packets. Without it the best
 * we can do is parse the security header and give up.
 */
#ifdef HAVE_LIBGCRYPT
#ifdef _WIN32
#include <winposixtype.h>
#endif /* _WIN32 */

#include <gcrypt.h>
#endif /* HAVE_LIBGCRYPT */

#include "packet-zbee.h"
#include "packet-zbee-security.h"

/* Helper Functions */
static void        zbee_security_parse_prefs(void);
static gboolean    zbee_sec_ccm_decrypt(const gchar *, const gchar *, const gchar *, const gchar *, gchar *, guint, guint, guint);
static void        zbee_sec_make_nonce (guint8 *, zbee_security_packet *);
static guint8 *    zbee_sec_key_hash(guint8 *, guint8, packet_info *);

/* Field pointers. */
static int hf_zbee_sec_level = -1;
static int hf_zbee_sec_key = -1;
static int hf_zbee_sec_nonce = -1;
static int hf_zbee_sec_counter = -1;
static int hf_zbee_sec_src = -1;
static int hf_zbee_sec_key_seqno = -1;
static int hf_zbee_sec_mic = -1;

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

/* Network Key. */
static gboolean zbee_sec_have_nwk_key = FALSE;
static guint8   zbee_sec_nwk_key[ZBEE_SEC_CONST_KEYSIZE];

/* Trust-Center Link Key. */
static gboolean zbee_sec_have_tclink_key = FALSE;
static guint8   zbee_sec_tclink_key[ZBEE_SEC_CONST_KEYSIZE];

/* Trust-Center Extended Address */
static guint64  zbee_sec_tcaddr = 0;

/* ZigBee Security Preferences. */
static gint     gPREF_zbee_sec_level = ZBEE_SEC_ENC_MIC32;
static const gchar *  gPREF_zbee_sec_nwk_key = NULL;
static const gchar *  gPREF_zbee_sec_tcaddr = NULL;
static const gchar *  gPREF_zbee_sec_tclink_key = NULL;

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
 *      Called to initialize the security dissectors. Roughly the
 *      equivalent of proto_register_*
 *  PARAMETERS
 *      module_t    prefs   - Prefs module to load preferences under.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void zbee_security_register(module_t *prefs, int proto)
{
    static hf_register_info hf[] = {
            { &hf_zbee_sec_level,
            { "Level",                  "zbee.sec.level", FT_UINT8, BASE_HEX, VALS(zbee_sec_level_names), ZBEE_SEC_CONTROL_LEVEL,
                NULL, HFILL }},

            { &hf_zbee_sec_key,
            { "Key",                    "zbee.sec.key", FT_UINT8, BASE_HEX, VALS(zbee_sec_key_names), ZBEE_SEC_CONTROL_KEY,
                NULL, HFILL }},

            { &hf_zbee_sec_nonce,
            { "Extended Nonce",         "zbee.sec.ext_nonce", FT_BOOLEAN, 8, NULL, ZBEE_SEC_CONTROL_NONCE,
                NULL, HFILL }},

            { &hf_zbee_sec_counter,
            { "Frame Counter",          "zbee.sec.counter", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_sec_src,
            { "Source",                 "zbee.sec.src", FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_sec_key_seqno,
            { "Key Sequence Number",    "zbee.sec.key_seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

            { &hf_zbee_sec_mic,
            { "Message Integrity Code", "zbee.sec.mic", FT_BYTES, BASE_HEX, NULL, 0x0,
                NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_zbee_sec,
        &ett_zbee_sec_control
    };

    /* If no prefs module was supplied, register our own. */
    if (prefs == NULL) {
        prefs = prefs_register_protocol(proto, zbee_security_parse_prefs);
    }

    /*  Register preferences */
    prefs_register_enum_preference(prefs, "seclevel", "Security Level",
                 "Specifies the security level to use in the decryption process. This value is ignored for ZigBee 2004 and unsecured networks.",
                 &gPREF_zbee_sec_level, zbee_sec_level_enums, FALSE);
    prefs_register_string_preference(prefs, "nwkkey", "Network Key",
                 "Specifies the network key to use for decryption.",
                 &gPREF_zbee_sec_nwk_key);
    prefs_register_string_preference(prefs, "tcaddr", "Trust Center Address",
                "The Extended address of the trust center.",
                &gPREF_zbee_sec_tcaddr);
    prefs_register_string_preference(prefs, "tclinkkey", "Trust Center Link Key",
                 "Specifies the trust center link key to use for decryption.",
                 &gPREF_zbee_sec_tclink_key);

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
} /* zbee_security_register */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_security_parse_key
 *  DESCRIPTION
 *      Parses a key string into a buffer.
 *  PARAMETERS
 *      const gchar *   key_str;
 *      guint8          key_buf;
 *  RETURNS
 *      gboolean
 *---------------------------------------------------------------
 */
static gboolean
zbee_security_parse_key(const gchar *key_str, guint8 *key_buf)
{
    int             i;
    gchar           temp;

    /* Clear the key. */
    memset(key_buf, 0, ZBEE_SEC_CONST_KEYSIZE);
    if (key_str == NULL) {
        return FALSE;
    }
    /*
     * Attempt to parse the key string. The key string must represent
     * exactly 16 bytes in hexadecimal format with the following
     * separators: ':', '-', " ", or no separator at all. Start by
     * getting the first character.
     */
    temp = *(key_str++);
    for (i=ZBEE_SEC_CONST_KEYSIZE-1; i>=0; i--) {
        /* If this character is a separator, skip it. */
        if ((temp == ':') || (temp == '-') || (temp == ' ')) temp = *(key_str++);
        /* Process this nibble. */
        if (('0' <= temp) && (temp <= '9'))      key_buf[i] |= ((temp-'0')<<4);
        else if (('a' <= temp) && (temp <= 'f')) key_buf[i] |= ((temp-'a'+0x0a)<<4);
        else if (('A' <= temp) && (temp <= 'F')) key_buf[i] |= ((temp-'A'+0x0A)<<4);
        else return FALSE;
        /* Get the next nibble. */
        temp = *(key_str++);
        /* Process this nibble. */
        if (('0' <= temp) && (temp <= '9'))      key_buf[i] |= (temp-'0');
        else if (('a' <= temp) && (temp <= 'f')) key_buf[i] |= (temp-'a'+0x0a);
        else if (('A' <= temp) && (temp <= 'F')) key_buf[i] |= (temp-'A'+0x0A);
        else return FALSE;
        /* Get the next nibble. */
        temp = *(key_str++);
    } /* for */
    /* If we get this far, then the key was good. */
    return TRUE;
} /* zbee_security_parse_key */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_security_parse_prefs
 *  DESCRIPTION
 *      Parses the security preferences into the parameters needed
 *      for decryption.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zbee_security_parse_prefs(void)
{
    int             i;
    const gchar *   str_ptr;
    gchar           temp;

    /* Get the network key. */
    zbee_sec_have_nwk_key = zbee_security_parse_key(gPREF_zbee_sec_nwk_key, zbee_sec_nwk_key);
    /* Get the trust-center link key. */
    zbee_sec_have_tclink_key = zbee_security_parse_key(gPREF_zbee_sec_tclink_key, zbee_sec_tclink_key);
    /* Get the trust-center address. */
    zbee_sec_tcaddr = 0;
    str_ptr = gPREF_zbee_sec_tcaddr;
    temp = *(str_ptr++);
    for (i=0;i<(int)sizeof(guint64);i++) {
        /* Except for the first octet, ensure the next character is a
         * separator and skip over it.
         */
        if ((temp == ':') || (temp == '-')) temp = *(str_ptr++);
        else if (i!=0) goto bad_tcaddr;
        /* Process this nibble. */
        if (('0' <= temp) && (temp <= '9'))      zbee_sec_tcaddr |= ((guint64)(temp-'0'+0x00)<<(8*(sizeof(guint64)-i)-4));
        else if (('a' <= temp) && (temp <= 'f')) zbee_sec_tcaddr |= ((guint64)(temp-'a'+0x0a)<<(8*(sizeof(guint64)-i)-4));
        else if (('A' <= temp) && (temp <= 'F')) zbee_sec_tcaddr |= ((guint64)(temp-'A'+0x0A)<<(8*(sizeof(guint64)-i)-4));
        else goto bad_tcaddr;
        /* Get the next nibble. */
        temp = *(str_ptr++);
        /* Process this nibble. */
        if (('0' <= temp) && (temp <= '9'))      zbee_sec_tcaddr |= ((guint64)(temp-'0'+0x00)<<(8*(sizeof(guint64)-i)-8));
        else if (('a' <= temp) && (temp <= 'f')) zbee_sec_tcaddr |= ((guint64)(temp-'a'+0x0a)<<(8*(sizeof(guint64)-i)-8));
        else if (('A' <= temp) && (temp <= 'F')) zbee_sec_tcaddr |= ((guint64)(temp-'A'+0x0A)<<(8*(sizeof(guint64)-i)-8));
        else goto bad_tcaddr;
        /* Get the next nibble. */
        temp = *(str_ptr++);
    } /* for */
    /* Done */
    return;

bad_tcaddr:
    zbee_sec_tcaddr = 0;
} /* zbee_security_parse_prefs */

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
    /* Parse the security prefs. */
    zbee_security_parse_prefs();
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
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *      guint       offset  - pointer to the start of the auxilliary security header.
 *      guint64     src     - extended source address, or 0 if unknown.
 *  RETURNS
 *      tvbuff_t *
 *---------------------------------------------------------------
 */
tvbuff_t *
dissect_zbee_secure(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree, guint offset, guint64 src)
{
    proto_tree *    sec_tree = NULL;
    proto_item *    sec_root;
    proto_tree *    field_tree;
    proto_item *    ti;

    zbee_security_packet    packet;
    guint           mic_len;
    guint           payload_len;
    tvbuff_t *      payload_tvb;

#ifdef HAVE_LIBGCRYPT
    const guint8 *  enc_buffer;
    guint8 *        dec_buffer;
    guint8 *        key_buffer;
    guint8          nonce[ZBEE_SEC_CONST_NONCE_LEN];
#endif

    /* Create a substree for the security information. */
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
     * so we can fix these 3 bits.
     */
#ifdef HAVE_LIBGCRYPT
    enc_buffer = ep_tvb_memdup(tvb, 0, tvb_length(tvb));
    /*
     * Override the const qualifiers and patch the security level field, we
     * know it is safe to overide the const qualifiers because we just
     * allocated this memory via ep_tvb_memdup().
     */
    ((guint8 *)(enc_buffer))[offset] = packet.control;
#endif /* HAVE_LIBGCRYPT */
    packet.level    = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_LEVEL);
    packet.key      = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_KEY);
    packet.nonce    = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_NONCE);
    if (tree) {
        ti = proto_tree_add_text(sec_tree, tvb, offset, sizeof(guint8), "Security Control Field");
        field_tree = proto_item_add_subtree(ti, ett_zbee_sec_control);

        proto_tree_add_uint(field_tree, hf_zbee_sec_key, tvb, offset, sizeof(guint8), packet.control & ZBEE_SEC_CONTROL_KEY);
        proto_tree_add_boolean(field_tree, hf_zbee_sec_nonce, tvb, offset, sizeof(guint8), packet.control & ZBEE_SEC_CONTROL_NONCE);
    }
    offset += sizeof(guint8);

    /* Get and display the frame counter field. */
    packet.counter = tvb_get_letohl(tvb, offset);
    if (tree) {
        proto_tree_add_uint(sec_tree, hf_zbee_sec_counter, tvb, offset, sizeof(guint32), packet.counter);
    }
    offset += sizeof(guint32);

    if (packet.nonce) {
        /* Get and display the source address. */
        packet.src = tvb_get_letoh64(tvb, offset);
        if (tree) {
            proto_tree_add_eui64(sec_tree, hf_zbee_sec_src, tvb, offset, sizeof(guint64), packet.src);
        }
        offset += sizeof(guint64);
    }
    else {
        /* This field is required in the security decryption process, so
         * fill it in in case the higher layer provided it.
         */
        packet.src = src;
    }

    if (packet.key == ZBEE_SEC_KEY_NWK) {
        /* Get and display the key sequence number. */
        packet.key_seqno = tvb_get_guint8(tvb, offset);
        if (tree) {
            proto_tree_add_uint(sec_tree, hf_zbee_sec_key_seqno, tvb, offset, sizeof(guint8), packet.key_seqno);
        }
        offset += sizeof(guint8);
    }

    /* Determine the length of the MIC. */
    switch (packet.level){
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

    /* Ensure that the payload exists (length >= 1) for this length. */
    payload_len = tvb_ensure_length_remaining(tvb, offset+mic_len+1)+1;

    /* Get and display the MIC. */
    if (mic_len) {
        /* Display the MIC. */
        if (tree) {
            ti = proto_tree_add_bytes(sec_tree, hf_zbee_sec_mic, tvb, tvb_length(tvb)-mic_len, mic_len, ep_tvb_memdup(tvb, tvb_length(tvb)-mic_len, mic_len));
        }
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
    /* Ensure we have enough security material to decrypt this payload. */
    switch (packet.key) {
        /* Network Keys use the shared network key. */
        case ZBEE_SEC_KEY_NWK:
            if (!zbee_sec_have_nwk_key) {
                /* Without a key we can't decrypt (if we could what good would security be?)*/
                goto decrypt_failed;
            }
            if (packet.src == 0) {
                /* Without the extended source address, we can't create the nonce. */
                goto decrypt_failed;
            }
            /* The key, is the network key. */
            key_buffer = zbee_sec_nwk_key;
            break;

        /* Link Key might use the trust center link key. */
        case ZBEE_SEC_KEY_LINK:
            if (!zbee_sec_have_tclink_key) {
                /* Without a key we can't decrypt. */
                goto decrypt_failed;
            }
            if ((packet.src == 0) && (zbee_sec_tcaddr == 0)){
                /* Without the extended source address, we can't create the nonce. */
                goto decrypt_failed;
            }
            else if (packet.src == 0) {
                packet.src = zbee_sec_tcaddr;
            }
            key_buffer = zbee_sec_tclink_key;
            break;

        /* Key-Transport Key should use the trust center link key. */
        case ZBEE_SEC_KEY_TRANSPORT:
            if (!zbee_sec_have_tclink_key) {
                /* Without a key we can't decrypt. */
                goto decrypt_failed;
            }
            if ((packet.src == 0) && (zbee_sec_tcaddr == 0)){
                /* Without the extended source address, we can't create the nonce. */
                goto decrypt_failed;
            }
            else if (packet.src == 0) {
                packet.src = zbee_sec_tcaddr;
            }
            key_buffer = zbee_sec_key_hash(zbee_sec_tclink_key, 0x00, pinfo);
            break;

        /* Key-Load Key should use the trust center link key. */
        case ZBEE_SEC_KEY_LOAD:
            if (!zbee_sec_have_tclink_key) {
                /* Without a key we can't decrypt. */
                goto decrypt_failed;
            }
            if ((packet.src == 0) && (zbee_sec_tcaddr == 0)){
                /* Without the extended source address, we can't create the nonce. */
                goto decrypt_failed;
            }
            else if (packet.src == 0) {
                packet.src = zbee_sec_tcaddr;
            }
            key_buffer = zbee_sec_key_hash(zbee_sec_tclink_key, 0x02, pinfo);
            break;

        default:
            goto decrypt_failed;
    } /* switch */

    /* Create the nonce. */
    zbee_sec_make_nonce(nonce, &packet);
    /* Allocate memory to decrypt the payload into. */
    dec_buffer = g_malloc(payload_len);
    /* Perform Decryption. */
    if (!zbee_sec_ccm_decrypt(key_buffer, /* key */
                nonce,              /* Nonce */
                enc_buffer,         /* a, length l(a) */
                enc_buffer+offset,  /* c, length l(c) = l(m) + M */
                dec_buffer,         /* m, length l(m) */
                offset,             /* l(a) */
                payload_len,        /* l(m) */
                mic_len)) {         /* M */
        /* Decryption Failed! */
        g_free(dec_buffer);
        goto decrypt_failed;
    }

    /* Setup the new tvbuff_t and return */
    payload_tvb = tvb_new_real_data(dec_buffer, payload_len, payload_len);
    tvb_set_child_real_data_tvbuff(tvb, payload_tvb);
    add_new_data_source(pinfo, payload_tvb, "Decrypted ZigBee Payload");
    /* Done! */
    return payload_tvb;

decrypt_failed:
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

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_make_nonce
 *  DESCRIPTION
 *      Fills in the ZigBee security nonce from the provided security
 *      packet structure.
 *  PARAMETERS
 *      gchar           *nonce  - Nonce Buffer.
 *      zbee_security_packet *packet - Security information.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zbee_sec_make_nonce(guint8 *nonce, zbee_security_packet *packet)
{
    /* First 8 bytes are the extended source address (little endian). */
    *(nonce++) = (guint8)((packet->src)>>0 & 0xff);
    *(nonce++) = (guint8)((packet->src)>>8 & 0xff);
    *(nonce++) = (guint8)((packet->src)>>16 & 0xff);
    *(nonce++) = (guint8)((packet->src)>>24 & 0xff);
    *(nonce++) = (guint8)((packet->src)>>32 & 0xff);
    *(nonce++) = (guint8)((packet->src)>>40 & 0xff);
    *(nonce++) = (guint8)((packet->src)>>48 & 0xff);
    *(nonce++) = (guint8)((packet->src)>>56 & 0xff);
    /* Next 4 bytes are the frame counter (little endian). */
    *(nonce++) = (guint8)((packet->counter)>>0 & 0xff);
    *(nonce++) = (guint8)((packet->counter)>>8 & 0xff);
    *(nonce++) = (guint8)((packet->counter)>>16 & 0xff);
    *(nonce++) = (guint8)((packet->counter)>>24 & 0xff);
    /* Next byte is the security control field. */
    *(nonce++) = packet->control;
} /* zbee_sec_make_nonce */

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
                if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
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
            if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
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
    cipher_in[j++] = ((input_len * 8) >> 0) & 0xff;
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
 *  RETURNS
 *      guint8*
 *---------------------------------------------------------------
 */
static guint8 *
zbee_sec_key_hash(guint8 *key, guint8 input, packet_info *pinfo _U_)
{
    guint8              hash_in[2*ZBEE_SEC_CONST_BLOCKSIZE];
    guint8 *            hash_out = ep_alloc(ZBEE_SEC_CONST_BLOCKSIZE+1);
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
