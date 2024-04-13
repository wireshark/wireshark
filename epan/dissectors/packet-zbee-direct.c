/* packet-zbee-direct.c
 * Dissector routines for the ZigBee Direct
 * Copyright 2021 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <gcrypt.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/uat.h>

#include "packet-zbee-security.h"
#include "packet-bluetooth.h"
#include "packet-ieee802154.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-tlv.h"
#include "packet-zbee-direct.h"

/*-------------------------------------
 * Dissector Function Prototypes
 *-------------------------------------
 */

static int dissect_zb_direct_dump_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_secur_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset, guint msg_id);
static int dissect_zb_direct_secur_c25519_aesmmo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_secur_c25519_sha256(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_secur_p256(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_formation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_permit_join(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_leave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_manage_joiners(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_identify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_finding_binding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_zb_direct_tunneling(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static int dissect_zb_direct_common(tvbuff_t **tvb, packet_info *pinfo, proto_tree **tree, void *data, unsigned offset, const guint8 *serv_uuid, const guint8 *char_uuid);

/* Used dissectors */
static dissector_handle_t zbee_nwk_handle;

/* TLV Node-elements */
static int proto_zb_direct;

/* Leaf-elements */
static int hf_zb_direct_info_type;
static int hf_zb_direct_info_key;
static int hf_zb_direct_info_zdd_ieee;
static int hf_zb_direct_info_zvd_ieee;
static int hf_zb_direct_info_encryption;
static int hf_zb_direct_msg_type;

/* Commissioning */
static int hf_zb_direct_comm_permit_time;
static int hf_zb_direct_comm_rejoin;
static int hf_zb_direct_comm_rm_children;
static int hf_zb_direct_comm_identify_time;
static int hf_zb_direct_comm_fb_endpoint;
static int hf_zb_direct_comm_fb_initiator;

/* Markers (also leafs) */
static int hf_zb_direct_unrecognized_msg;
static int hf_zb_direct_char_info;
static int hf_zb_direct_char_c25519_aesmmo;
static int hf_zb_direct_char_c25519_sha256;
static int hf_zb_direct_char_p256;
static int hf_zb_direct_char_form;
static int hf_zb_direct_char_status;
static int hf_zb_direct_char_join;
static int hf_zb_direct_char_permit_join;
static int hf_zb_direct_char_leave;
static int hf_zb_direct_char_manage_joiners;
static int hf_zb_direct_char_identify;
static int hf_zb_direct_char_finding_binding;
static int hf_zb_direct_char_tunneling;

/* Expert items */
static expert_field ei_zb_direct_crypt_error;

/* Trees entities */
static gint ett_zb_direct;

static const guint8 serv_secur_uuid[]           = { 0xe3, 0x29, 0xb4, 0x99, 0x02, 0x6d, 0xe9, 0xbf,
                                                    0x81, 0x44, 0x00, 0x00, 0xf4, 0x4a, 0x14, 0x29 };
static const guint8 char_p256_uuid[]            = { 0xe3, 0x29, 0xb4, 0x99, 0x02, 0x6d, 0xe9, 0xbf,
                                                    0x81, 0x44, 0x03, 0x00, 0xf4, 0x4a, 0x14, 0x29 };
static const guint8 char_c25519_aesmmo_uuid[]   = { 0xe3, 0x29, 0xb4, 0x99, 0x02, 0x6d, 0xe9, 0xbf,
                                                    0x81, 0x44, 0x01, 0x00, 0xf4, 0x4a, 0x14, 0x29 };
static const guint8 char_c25519_sha256_uuid[]   = { 0xe3, 0x29, 0xb4, 0x99, 0x02, 0x6d, 0xe9, 0xbf,
                                                    0x81, 0x44, 0x02, 0x00, 0xf4, 0x4a, 0x14, 0x29 };
static const guint8 serv_comm_uuid[]            = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
                                                    0x00, 0x10, 0x00, 0x00, 0xf7, 0xff, 0x00, 0x00 };
static const guint8 char_form_uuid[]            = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x01, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 char_join_uuid[]            = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x02, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 char_permit_uuid[]          = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x03, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 char_leave_uuid[]           = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x04, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 char_status_uuid[]          = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x05, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 char_identify_uuid[]        = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x07, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 char_manage_joiners_uuid[]  = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x06, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 char_finding_binding_uuid[] = { 0x61, 0x3a, 0x33, 0x27, 0x1c, 0x49, 0x63, 0xb1,
                                                    0x1c, 0x42, 0x08, 0x00, 0x7d, 0x37, 0x72, 0x70 };
static const guint8 serv_tunnel_uuid[]          = { 0x3f, 0x31, 0xd5, 0x8b, 0x37, 0xb2, 0x20, 0x81,
                                                    0xf4, 0x45, 0x00, 0x00, 0xfd, 0x78, 0xd1, 0x8b };
static const guint8 char_tunnel_uuid[]          = { 0x3f, 0x31, 0xd5, 0x8b, 0x37, 0xb2, 0x20, 0x81,
                                                    0xf4, 0x45, 0x01, 0x00, 0xfd, 0x78, 0xd1, 0x8b };
#define ZIGBEE_DIRECT_MAX_ATT_SIZE  248
#define ZIGBEE_DIRECT_AUTH_STR_SIZE (16 + 1 + 16 + 1)
#define ZIGBEE_DIRECT_SECUR_CONTROL 0x05

/* MIC length */
#define ZB_CCM_M 4

#define KEY_LEN         16
#define MAX_CONNECTIONS 2

/*****************************************************************************/
/******************************** Static Data ********************************/
/*****************************************************************************/

static uat_t *zbd_secur_key_table_uat;

/* Values in the key rings. */
typedef struct
{
    guint  frame_num;
    guint8 zdd_ieee[8];
    guint8 zvd_ieee[8];
    guint8 key[KEY_LEN];
    gchar *label;
} zb_direct_key_record_t;

/* UAT Key Entry */
typedef struct uat_key_record_s
{
    gchar *zdd_ieee;
    gchar *zvd_ieee;
    gchar *key;
    gchar *label;
} uat_key_record_t;

UAT_CSTRING_CB_DEF(uat_key_records, zdd_ieee, uat_key_record_t)
UAT_CSTRING_CB_DEF(uat_key_records, zvd_ieee, uat_key_record_t)
UAT_CSTRING_CB_DEF(uat_key_records, key, uat_key_record_t)
UAT_CSTRING_CB_DEF(uat_key_records, label, uat_key_record_t)

static GSList           *zbee_pc_keyring;
static uat_key_record_t *uat_key_records;
static guint             num_uat_key_records;

/* Common data */
static guint8 g_conn_id;

static bool ignore_late_keys = true;

/* Info types */
typedef enum
{
    DUMP_INFO_KEY_DEL,
    DUMP_INFO_KEY_SET,
    DUMP_INFO_ENCRYPTION_STATUS
} dump_info_t;

static const value_string info_type_str[] =
{
    { DUMP_INFO_KEY_DEL,           "Delete CCM* key" },
    { DUMP_INFO_KEY_SET,           "Set CCM* key" },
    { DUMP_INFO_ENCRYPTION_STATUS, "Set encryption status" },
    { 0, NULL }
};

/* Message types */
typedef enum
{
    MSG_SE1 = 1,
    MSG_SE2 = 2,
    MSG_SE3 = 3,
    MSG_SE4 = 4
} msg_type_t;

static const value_string msg_type_str[] =
{
    { MSG_SE1, "Message SE1" },
    { MSG_SE2, "Message SE2" },
    { MSG_SE3, "Message SE3" },
    { MSG_SE4, "Message SE4" },
    { 0, NULL }
};

#define BOOLSTR(b) ((b) ? "TRUE" : "FALSE")

/* "Cast" GSList node to zb_direct_key_record_t* */
#define keyrec(node) ((zb_direct_key_record_t*)((node)->data))

/**
 * Like memcpy, but in reverse order.
 *
 * @param  dst pointer to destination (copy to)
 * @param  src pointer to source (copy from)
 * @param  len number of bytes
 */
static inline void memcpy_reverse(guint8 *dst, const guint8 *src, gsize len)
{
    len -= 1;

    for (gsize i = 0; i <= len; ++i)
    {
        dst[i] = src[len - i];
    }
}

/*****************************************************************************/
/************************************ UAT ************************************/
/*****************************************************************************/

/**
 * Parses a hex string into bytes.
 *
 * @param  str       pointer to a hex string
 * @param  buf       pointer to buffer, where to place result
 * @param  bytes_num number of bytes to retrive from the string
 * @return success
 */
static gboolean zbd_parse_uat_hexline(const gchar *str,
                                      guint8      *buf,
                                      guint        bytes_num)
{
    gint      i, j;
    gchar     temp;
    gboolean  string_mode = FALSE;

    /* Clear the key. */
    memset(buf, 0, bytes_num);
    if (str == NULL)
    {
        return FALSE;
    }

    /**
     * Attempt to parse the hex string. The hex string must
     * be at least 16 pairs of hexidecimal digits with the
     * following optional separators: ':', '-', " ", or 16
     * alphanumeric characters after a double-quote.
     */
    if ((temp = *str++) == '"')
    {
        string_mode = TRUE;
        temp = *str++;
    }

    j = 0;
    for (i = bytes_num - 1; i >= 0; i--)
    {
        if (string_mode)
        {
            if (g_ascii_isprint(temp))
            {
                buf[j] = temp;
                temp = *str++;
            }
            else
            {
                return FALSE;
            }
        }
        else
        {
            /* If this character is a separator, skip it. */
            if (temp == ':' || temp == '-' || temp == ' ')
            {
                temp = *str++;
            }

            /* Process a nibble. */
            if (g_ascii_isxdigit(temp))
            {
                buf[j] = g_ascii_xdigit_value(temp) << 4;
            }
            else
            {
                return FALSE;
            }

            /* Get the next nibble. */
            temp = *str++;

            /* Process another nibble. */
            if (g_ascii_isxdigit(temp))
            {
                buf[j] |= g_ascii_xdigit_value(temp);
            }
            else
            {
                return FALSE;
            }

            /* Get the next nibble. */
            temp = *str++;
        }

        /* Move buf pointer */
        j++;
    }

    /* If we get this far, then the key was good. */
    return TRUE;
}

/**
 * UAT Copy callback.
 *
 * @param  n     pointer to new uat_kkey_record_t
 * @param  o     pointer to old uat_key_record_t
 * @param  size  unused
 */
static void *uat_key_record_copy_cb(void *n, const void *o, size_t size _U_)
{
    uat_key_record_t       *new_key = (uat_key_record_t *)n;
    const uat_key_record_t *old_key = (const uat_key_record_t *)o;

    new_key->zdd_ieee = g_strdup(old_key->zdd_ieee);
    new_key->zvd_ieee = g_strdup(old_key->zvd_ieee);
    new_key->key      = g_strdup(old_key->key);
    new_key->label    = g_strdup(old_key->label);

    return new_key;
}

/**
 * UAT Update callback.
 *
 * @param  r     pointer to uat_kkey_record_t
 * @param  err   pointer to error pointer
 * @return success
 */
static bool uat_key_record_update_cb(void *r, char **err)
{
    uat_key_record_t *rec = (uat_key_record_t *)r;
    guint8            zdd_ieee[8];
    guint8            zvd_ieee[8];
    guint8            key[KEY_LEN];

    *err = NULL;

    if (rec->zdd_ieee == NULL)
    {
        *err = g_strdup("ZDD IEEE can't be blank");
        return FALSE;
    }

    if (rec->zvd_ieee == NULL)
    {
        *err = g_strdup("ZVD IEEE can't be blank");
        return FALSE;
    }

    if (rec->key == NULL)
    {
        *err = g_strdup("Key can't be blank");
        return FALSE;
    }

    g_strstrip(rec->zdd_ieee);
    g_strstrip(rec->zvd_ieee);
    g_strstrip(rec->key);

    if (rec->zdd_ieee[0] == 0)
    {
        *err = g_strdup("ZDD IEEE can't be blank");
        return FALSE;
    }

    if (rec->zvd_ieee[0] == 0)
    {
        *err = g_strdup("ZVD IEEE can't be blank");
        return FALSE;
    }

    if (rec->key[0] == 0)
    {
        *err = g_strdup("Key can't be blank");
        return FALSE;
    }

    if (!zbd_parse_uat_hexline(rec->zdd_ieee, zdd_ieee, 8))
    {
        *err = g_strdup_printf("Expecting %d hexadecimal bytes or a %d character double-quoted string", 8, 8);
        return FALSE;
    }

    if (!zbd_parse_uat_hexline(rec->zvd_ieee, zvd_ieee, 8))
    {
        *err = g_strdup_printf("Expecting %d hexadecimal bytes or a %d character double-quoted string", 8, 8);
        return FALSE;
    }

    if (!zbd_parse_uat_hexline(rec->key, key, 16))
    {
        *err = g_strdup_printf("Expecting %d hexadecimal bytes or a %d character double-quoted string", 16, 16);
        return FALSE;
    }

    return TRUE;
}

/**
 * UAT Free callback.
 *
 * @param  r  pointer to a uat_key_record_t
 */
static void uat_key_record_free_cb(void *r)
{
    uat_key_record_t *key = (uat_key_record_t *)r;

    g_free(key->zdd_ieee);
    g_free(key->zvd_ieee);
    g_free(key->key);
    g_free(key->label);
}

/**
 * Frees zb_direct_key_record_t.
 *
 * @param  ptr  pointer to a zb_direct_key_record_t
 */
static void zbd_free_key_record(gpointer ptr)
{
    zb_direct_key_record_t *k = (zb_direct_key_record_t *)ptr;

    g_free(k->label);
    g_free(k);
}

/**
 * Deletes all existing keys in zbee_pc_keyrig and adds new ones
 * from uat_key_records.
 */
static void uat_key_record_post_update(void)
{
    zb_direct_key_record_t key_record;
    guint8                 zdd_ieee[8];
    guint8                 zvd_ieee[8];
    guint8                 key[KEY_LEN];

    /* Empty UAT keys */
    GSList *element = zbee_pc_keyring;

    /* Find where UAT table keys begin */
    while (element && keyrec(element)->frame_num > 0)
    {
        element = g_slist_next(element);
    }

    /* Delete all UAT keys */
    while (element)
    {
        GSList *next = element->next;

        zbee_pc_keyring = g_slist_remove_link(zbee_pc_keyring, element);

        g_slist_free_full(element, zbd_free_key_record);
        element = next;
    }

    /* Load the pre-configured slist from the UAT */
    for (guint i = 0U; uat_key_records && i < num_uat_key_records; i++)
    {
        bool success = zbd_parse_uat_hexline(uat_key_records[i].zdd_ieee, zdd_ieee, sizeof(zdd_ieee))
            | zbd_parse_uat_hexline(uat_key_records[i].zvd_ieee, zvd_ieee, sizeof(zvd_ieee))
            | zbd_parse_uat_hexline(uat_key_records[i].key, key, sizeof(key));

        if (success)
        {
            key_record.frame_num = 0; /* means it's a user PC key */
            key_record.label = g_strdup(uat_key_records[i].label);

            memcpy_reverse(key_record.zdd_ieee, zdd_ieee, 8);
            memcpy_reverse(key_record.zvd_ieee, zvd_ieee, 8);
            memcpy(key_record.key, key, KEY_LEN);

            /* Add UAT keys to the end */
            zbee_pc_keyring = g_slist_append(zbee_pc_keyring, g_memdup2(&key_record, sizeof(key_record)));
        }
    }
}

/*****************************************************************************/
/******************************** Decryption *********************************/
/*****************************************************************************/

#define MAX_CRYPT_TOGGLES 4096

typedef struct encryption_states_handler_s
{
    /* How many toggles were performed */
    guint16 counter;
    /* Even entries point, where encryption enabled region starts, odd ones point, where they end */
    guint32 states[MAX_CRYPT_TOGGLES];
} encryption_states_handler_t;

static encryption_states_handler_t enc_h[MAX_CONNECTIONS];

/**
 * Enables encryption for packet_info if possible.
 *
 * @param  pinfo  pointer to packet
 */
static void zb_direct_encryption_enable(packet_info *pinfo)
{
    encryption_states_handler_t *h = &enc_h[g_conn_id];

    /* If currently enabled && was not disabled previously, exit */
    if (h->counter % 2 == 1)
    {
        return;
    }

    /* If this packet was already handled, exit */
    if (h->counter != 0 && pinfo->num <= h->states[h->counter - 1])
    {
        return;
    }

    if (h->counter >= MAX_CRYPT_TOGGLES)
    {
        return;
    }

    /* Enable */
    h->states[h->counter++] = pinfo->num;
}

/**
 * Disables encryption for packet_info if possible.
 *
 * @param  pinfo  pointer to packet
 */
static void zb_direct_encryption_disable(packet_info *pinfo)
{
    encryption_states_handler_t *h = &enc_h[g_conn_id];

    /* If currently enabled && was not disabled previously */
    if (h->counter % 2 == 0)
    {
        return;
    }

    if (pinfo->num <= h->states[h->counter - 1])
    {
        return;
    }

    /* Enable */
    h->states[h->counter++] = pinfo->num;
}

/**
 * Checks if the packet must be decrypted.
 *
 * @param  pinfo  pointer to packet
 * @return true, if decryption is needed, false, otherwise
 */
static gboolean zb_direct_decryption_needed(packet_info *pinfo)
{
    encryption_states_handler_t *h = &enc_h[g_conn_id];

    for (gint i = 0; i < h->counter; i += 2)
    {
        if (h->states[i] < pinfo->num)
        {
            /* If the packet is before the beginning of current crypted block, shutdown the search */
            if (pinfo->num < h->states[i])
            {
                return FALSE;
            }

            /* If encrypted block was opened and not closed till now, or closed after current packet */
            if (i == h->counter - 1 || pinfo->num < h->states[i + 1])
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static gboolean decrypt_data(const guint8 *serv_uuid,
                             const guint8 *char_uuid,
                             gboolean      to_zdd,
                             const guint8 *in,
                             guint8       *out,
                             guint16      *len,
                             guint8        zdd_ieee[8],
                             guint8        zvd_ieee[8],
                             guint8        key[KEY_LEN]);

/**
 * Tries to decrypt packet payload as ZDD and ZVD.
 *
 * @param  serv_uuid  service UUID
 * @param  char_uuid  characteristic UUID
 * @param  in         pointer to encrypted payload
 * @param  out        pointer to buffer for the result
 * @param  len        pointer to the length of payload, outputs length of out
 * @param  zdd_ieee   ZDD IEEE
 * @param  zvd_ieee   ZVD IEEE
 * @param  key        key for decryption
 * @return success
 */
static gboolean try_decrypt(const guint8 *serv_uuid,
                            const guint8 *char_uuid,
                            const guint8 *in,
                            guint8       *out,
                            guint16      *len,
                            guint8        zdd_ieee[8],
                            guint8        zvd_ieee[8],
                            guint8        key[KEY_LEN])
{
    /* As there is no reliable way known to determine,
     * if the packet is from zdd or zvd, try both cases */

    guint16 len_buf  = *len;
    gboolean success = decrypt_data(serv_uuid, char_uuid,
                                    true,
                                    in,
                                    out, len,
                                    zdd_ieee, zvd_ieee, key);

    if (!success)
    {
        *len = len_buf;
        success = decrypt_data(serv_uuid, char_uuid,
                               false,
                               in,
                               out, len,
                               zdd_ieee, zvd_ieee, key);
    }

    return success;
}

/**
 * @brief Generates IEEE address from BLE MAC.
 *
 * @param mac_address BLE MAC in BE
 * @param ieee        generated IEEE in BE
 */
static void zb_direct_ieee_from_mac(const guint8 *mac_address, guint8 *ieee)
{
    ieee[0] = mac_address[0] ^ 0x02;
    ieee[1] = mac_address[1];
    ieee[2] = mac_address[2];
    ieee[3] = 0xFF;
    ieee[4] = 0xFE;
    ieee[5] = mac_address[3];
    ieee[6] = mac_address[4];
    ieee[7] = mac_address[5];
}

/**
 * @brief Get BLE MAC address of the device which sent current packet from the packet data.
 *
 * @param  pinfo packet info
 * @param  mac   BLE MAC (bd_addr) corresponding to current packet sender
 */
static void zb_direct_bd_addr_from_packet_data(const packet_info *pinfo,
                                               guint8            *mac)
{
    (void)address_to_bytes(&pinfo->dl_src, mac, 6);
}

/**
 * @brief Get IEEE address of the device which generated current packet from the packet data.
 *
 * @param  pinfo packet info
 * @param  ieee  calculated IEEE in BE
 */
static void zb_direct_ieee_from_packet_data(const packet_info *pinfo,
                                            guint8            *ieee)
{
    guint8 mac[6];
    zb_direct_bd_addr_from_packet_data(pinfo, mac);
    zb_direct_ieee_from_mac(mac, ieee);
}

/**
 * Decrypts ZB Direct packets.
 *
 * @param  tvb        pointer to buffer containing raw packet
 * @param  pinfo      pointer to packet information fields
 * @param  tree       pointer to the command subtree
 * @param  data       raw packet private data
 * @param  offset     offset into the tvb to begin dissection
 * @param  serv_uuid  service UUID
 * @param  char_uuid  characteristic UUID
 * @return offset after command dissection
 */
static int zb_direct_decrypt(tvbuff_t    **tvb,
                             packet_info  *pinfo,
                             proto_tree   *tree,
                             void         *data  _U_,
                             unsigned      offset,
                             const guint8 *serv_uuid,
                             const guint8 *char_uuid)
{
    if (zb_direct_decryption_needed(pinfo))
    {
        guint8   ieee[8];
        gboolean success = FALSE;
        guint16  size = tvb_reported_length_remaining(*tvb, offset);
        guint8  *decrypted = (guint8 *)wmem_alloc(pinfo->pool, 512);
        GList   *pan_keyring;
        GSList  *i = zbee_pc_keyring;
        guint16  init_size = size;

        zb_direct_ieee_from_packet_data(pinfo, ieee);

        if (ignore_late_keys)
        {
            /* Skip all keys, which were reported after current package */
            while (i && (keyrec(i)->frame_num > pinfo->num))
            {
                i = g_slist_next(i);
            }
        }

        /* Try potential keys from preconfigured table and dump info packets */
        while (i && !success)
        {
            success = try_decrypt(serv_uuid,
                                  char_uuid,
                                  tvb_get_ptr(*tvb, offset, size),
                                  decrypted,
                                  &size,
                                  keyrec(i)->zdd_ieee,
                                  keyrec(i)->zvd_ieee,
                                  keyrec(i)->key);

            if (!success)
            {
                i = g_slist_next(i);
                size = init_size;
            }
        }

        /* Retrieve all pan-specific nwk keyrings from the hash table */
        if (!success && zbee_table_nwk_keyring)
        {
            pan_keyring = (GList*)g_hash_table_get_values(zbee_table_nwk_keyring);

            while (!success && pan_keyring)
            {
                i = *((GSList**)pan_keyring->data);

                /* Iterate over keys in the keyring */
                while (!success && i)
                {
                    if (!ignore_late_keys || ((key_record_t*)i->data)->frame_num > pinfo->num)
                    {
                        success = decrypt_data(serv_uuid, char_uuid, FALSE,
                                               tvb_get_ptr(*tvb, offset, size),
                                               decrypted, &size,
                                               ieee, NULL, ((key_record_t*)i->data)->key);

                        i = g_slist_next(i);
                        if (!success)
                        {
                            size = init_size;
                        }
                    }
                }
                pan_keyring = g_list_next(i);
            }
        }

        if (success)
        {
            /* On decryption success: replace the tvb, make offset point to its beginning */
            *tvb = tvb_new_child_real_data(*tvb, decrypted, size, size);
            add_new_data_source(pinfo, *tvb, "CCM* decrypted payload");
            offset = 0;
        }
        else
        {
            /* On decryption error: make offset point to the end of original tvb */
            offset = tvb_reported_length(*tvb);
            expert_add_info(pinfo, tree, &ei_zb_direct_crypt_error);
        }
    }

    return offset;
}

/* 6.4.3. CCM Nonce */
typedef struct
#if defined(_MSC_VER)
# pragma pack(push, 1)
#else
__attribute__((__packed__))
#endif
    zb_secur_ccm_nonce_s
{
    guint8   source_address[8];
    guint32  frame_counter;
    guint8   secur_control;
} zb_secur_ccm_nonce_t;
#ifdef _MSC_VER
# pragma pack(pop)
#endif

/**
 * Creates an auth string.
 *
 * @param  serv_uuid    service UUID
 * @param  char_uuid    characteristic UUID
 * @param  auth_string  output buffer
 */
static void create_auth_string(const guint8 serv_uuid[16],
                               const guint8 char_uuid[16],
                               guint8 auth_string[ZIGBEE_DIRECT_AUTH_STR_SIZE])
{
    /* 6.4.5. Unique address */
    memcpy_reverse(auth_string, serv_uuid, 16);
    auth_string[16] = 0;
    memcpy_reverse(&auth_string[17], char_uuid, 16);
    auth_string[33] = 0;
}

/**
 * Decrypts packet payload as ZDD and ZVD.
 *
 * @param  serv_uuid  service UUID
 * @param  char_uuid  characteristic UUID
 * @param  to_zdd     true if packet ws sent to zdd, false if to zvd (needed for nonce formation)
 * @param  in         pointer to encrypted payload
 * @param  out        pointer to buffer for the result
 * @param  len        pointer to the length of payload, outputs length of out
 * @param  zdd_ieee   ZDD IEEE
 * @param  zvd_ieee   ZVD IEEE
 * @param  key        key for decryption
 * @return success
 */
static gboolean decrypt_data(const guint8 *serv_uuid,
                             const guint8 *char_uuid,
                             gboolean      to_zdd,
                             const guint8 *in,
                             guint8       *out,
                             guint16      *len,
                             guint8        zdd_ieee[8],
                             guint8        zvd_ieee[8],
                             guint8        key[KEY_LEN])
{
    gboolean success = true;
    guint8   auth_str[ZIGBEE_DIRECT_AUTH_STR_SIZE];
    guint8   decrypted_data[ZIGBEE_DIRECT_MAX_ATT_SIZE + 16];
    guint16  decrypted_data_len = sizeof(decrypted_data);

    /* Remove 32-bit counter from the beginning */
    const guint8 *encrypted_data     = in + sizeof(guint32);
    guint16       encrypted_data_len = *len - sizeof(guint32);

    /* Form the nonce */
    zb_secur_ccm_nonce_t nonce = (zb_secur_ccm_nonce_t)
    {
        .secur_control = ZIGBEE_DIRECT_SECUR_CONTROL
    };

    /* Fetch counter from the packet (don't check) */
    memcpy(&nonce.frame_counter, in, sizeof(guint32));
    memcpy(&nonce.source_address, to_zdd ? zvd_ieee : zdd_ieee, 8);

    if (*len < 8) return false;

    create_auth_string(serv_uuid, char_uuid, auth_str);

    success = zbee_sec_ccm_decrypt(key,
                                   (guint8*)&nonce,
                                   auth_str,
                                   encrypted_data,
                                   decrypted_data,
                                   sizeof(auth_str),
                                   encrypted_data_len - ZB_CCM_M,
                                   ZB_CCM_M);


    if (success)
    {
        decrypted_data_len = encrypted_data_len - ZB_CCM_M;
        memcpy(out, decrypted_data, decrypted_data_len);
        *len = decrypted_data_len;
    }
    else
    {
        *len = 0;
    }

    return success;
}

/*****************************************************************************/
/***************************** Dissectors Common *****************************/
/*****************************************************************************/

/**
 * Common helper dissector.
 *
 * @param  tvb        pointer to buffer containing raw packet
 * @param  pinfo      pointer to packet information fields
 * @param  tree       pointer to the command subtree
 * @param  data       pointer to packet data
 * @param  offset     offset into the tvb to begin dissection
 * @param  serv_uuid  service UUID
 * @param  char_uuid  characteristic UUID
 * @return offset after command dissection
 */
static int dissect_zb_direct_common(tvbuff_t    **tvb,
                                    packet_info  *pinfo,
                                    proto_tree  **tree,
                                    void         *data,
                                    unsigned      offset,
                                    const guint8 *serv_uuid,
                                    const guint8 *char_uuid)
{
    proto_item *ti;

    /** TODO: find a way to detect direct (master/slave) and particular connection from data, passed from Bluetooth dissector */

    /* Set basic columns (proto, src, dst) */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZBD");

    /**
     * Actually should think of better way to know
     *
     * (probably try fetch BLE data: indication would reveal ZDD for example)
     */
    /* Add ZB Direct subtree */
    ti = proto_tree_add_item(*tree, proto_zb_direct, *tvb, 0, -1, ENC_LITTLE_ENDIAN);
    *tree = proto_item_add_subtree(ti, ett_zb_direct);

    g_conn_id = 0;

    proto_item_append_text(ti, " (Connection ID: %d)", (int)g_conn_id);

    /* NULL uuid is for chars, which do not have to be encrypted at all (dump info) */
    if (char_uuid != NULL && serv_uuid != NULL && memcmp(serv_uuid, serv_secur_uuid, sizeof(serv_secur_uuid)))
    {
        offset = zb_direct_decrypt(tvb, pinfo, *tree, data, offset, serv_uuid, char_uuid);
    }

    return offset;
}

/*****************************************************************************/
/**************************** Dump Info Dissector ****************************/
/*****************************************************************************/

typedef enum zb_dump_info_e
{
    /* Clear current used key */
    ZB_DUMP_INFO_CCM_KEY_DELETE,
    /* Replace current key with a new one */
    ZB_DUMP_INFO_CCM_KEY_SET,
    /* Specify, if encryption is needed or not */
    ZB_DUMP_INFO_ENCRYPTION_STATUS
} zb_dump_info_t;

/**
 * Dump Info dissector.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  data    raw packet private data
 * @return offset after command dissection
 */
static int dissect_zb_direct_dump_info(tvbuff_t    *tvb,
                                       packet_info *pinfo,
                                       proto_tree  *tree,
                                       void        *data)
{
    proto_item* ti;
    unsigned offset = 0;
    guint32 type;

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, NULL, NULL);
    col_set_str(pinfo->cinfo, COL_INFO, "Dump info");

    ti = proto_tree_add_item(tree, hf_zb_direct_char_info, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    proto_tree_add_item_ret_uint(tree, hf_zb_direct_info_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &type);
    offset += 1;

    switch(type)
    {
        case ZB_DUMP_INFO_CCM_KEY_DELETE:
            /* Obsolete option */
            break;

        case ZB_DUMP_INFO_CCM_KEY_SET:
        {
            zb_direct_key_record_t key_record;
            col_append_str(pinfo->cinfo, COL_INFO, ": update key");

            /**
             * From the Wireshark Developer's Guide:
             *
             * Wireshark performs a first pass of dissecting all packets as they are loaded from the file.
             * All packets are dissected sequentially...
             *
             * So, we can assume that keys are coming in order they will be used in file
             */

            proto_tree_add_item(tree, hf_zb_direct_info_key, tvb, offset, KEY_LEN, ENC_NA);
            tvb_memcpy(tvb, key_record.key, offset, KEY_LEN);
            offset += KEY_LEN;

            proto_tree_add_item(tree, hf_zb_direct_info_zdd_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            tvb_memcpy(tvb, key_record.zdd_ieee, offset, sizeof(key_record.zdd_ieee));
            offset += 8;

            proto_tree_add_item(tree, hf_zb_direct_info_zvd_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            tvb_memcpy(tvb, key_record.zvd_ieee, offset, sizeof(key_record.zdd_ieee));
            offset += 8;

            key_record.frame_num = pinfo->num;
            key_record.label = g_strdup_printf("Key reported over air in packet #%d", pinfo->num);

            /* Check if this key was already added */
            if (zbee_pc_keyring == NULL || keyrec(zbee_pc_keyring)->frame_num < pinfo->num)
            {
                /* store the keys in order: latest <- ... <- first <- (UAT: top <- ... <- bottom) */
                zbee_pc_keyring = g_slist_prepend(zbee_pc_keyring,
                                                  g_memdup2(&key_record, sizeof(zb_direct_key_record_t)));
            }
            break;
        }

        case ZB_DUMP_INFO_ENCRYPTION_STATUS:
        {
            gboolean is_enabled = tvb_get_guint8(tvb, offset);

            if (is_enabled)
            {
                zb_direct_encryption_enable(pinfo);
            }
            else
            {
                zb_direct_encryption_disable(pinfo);
            }

            proto_tree_add_item(tree,
                                hf_zb_direct_info_encryption,
                                tvb,
                                offset,
                                1,
                                ENC_LITTLE_ENDIAN);
            offset += 1;

            if (is_enabled)
            {
                col_append_str(pinfo->cinfo, COL_INFO, ": encryption ON");
            }
            else
            {
                col_append_str(pinfo->cinfo, COL_INFO, ": encryption OFF");
            }
            break;
        }
    }
    return offset;
}

/*****************************************************************************/
/********* Zigbee Direct Security Service Characteristics Dissectors *********/
/*****************************************************************************/

/**
 * Dissector for the security packets.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  data    raw packet private data
 * @param  offset  offset into the tvb to begin dissection.
 * @param  msg_id  ZB Direct local Message ID
 * @return offset after command dissection
 */
static int dissect_zb_direct_secur_common(tvbuff_t    *tvb,
                                          packet_info *pinfo,
                                          proto_tree  *tree,
                                          void        *data,
                                          unsigned     offset,
                                          guint        msg_id)
{
    unsigned cap_len = tvb_captured_length(tvb);
    proto_item* ti;

    const guint8 *decrypt_char_uuid;

    switch (msg_id)
    {
        case ZB_DIRECT_MSG_ID_SECUR_C25519_AESMMO:
            decrypt_char_uuid = char_c25519_aesmmo_uuid;
            break;

        case ZB_DIRECT_MSG_ID_SECUR_C25519_SHA256:
            decrypt_char_uuid = char_c25519_sha256_uuid;
            break;

        case ZB_DIRECT_MSG_ID_SECUR_P256:
            decrypt_char_uuid = char_p256_uuid;
            break;

        default:
            DISSECTOR_ASSERT(FALSE);
            break;
    }

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset,
                                      serv_secur_uuid, decrypt_char_uuid);

    switch (msg_id)
    {
        case ZB_DIRECT_MSG_ID_SECUR_C25519_AESMMO:
            ti = proto_tree_add_item(tree, hf_zb_direct_char_c25519_aesmmo, tvb, offset, 0, ENC_NA);
            break;

        case ZB_DIRECT_MSG_ID_SECUR_C25519_SHA256:
            ti = proto_tree_add_item(tree, hf_zb_direct_char_c25519_sha256, tvb, offset, 0, ENC_NA);
            break;

        case ZB_DIRECT_MSG_ID_SECUR_P256:
            ti = proto_tree_add_item(tree, hf_zb_direct_char_p256, tvb, offset, 0, ENC_NA);
            break;

        default:
            DISSECTOR_ASSERT(false);
            break;
    }

    proto_item_set_generated(ti);

    /* Discover type of the message */
    guint8 msg_type = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_zb_direct_msg_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    if (msg_type == MSG_SE1)
    {
        zb_direct_encryption_disable(pinfo);
    }
    else if (msg_type == MSG_SE4)
    {
        zb_direct_encryption_enable(pinfo);
    }

    offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data,
                               ZBEE_TLV_SRC_TYPE_ZB_DIRECT, msg_id);

    if (msg_type >= MSG_SE1 && msg_type <= MSG_SE4)
    {
        gsize msg_type_idx = msg_type - MSG_SE1;
        col_set_str(pinfo->cinfo, COL_INFO, msg_type_str[msg_type_idx].strptr);
    }
    else
    {
        proto_tree_add_item(tree, hf_zb_direct_unrecognized_msg, tvb, 0, cap_len, ENC_NA);
        offset = cap_len;

        col_set_str(pinfo->cinfo, COL_INFO, "Unrecognized SE message");
    }

    return offset;
}

/**
 * Dissector for security packets authenticated with Curve25519/AESMMO.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  data    raw packet private data
 * @return offset after command dissection
 */
static int dissect_zb_direct_secur_c25519_aesmmo(tvbuff_t    *tvb,
                                                 packet_info *pinfo,
                                                 proto_tree  *tree,
                                                 void        *data)
{
    return dissect_zb_direct_secur_common(tvb, pinfo, tree, data, 0U, ZB_DIRECT_MSG_ID_SECUR_C25519_AESMMO);
}

/**
 * Dissector for security packets authenticated with Curve25519/SHA256.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  data    raw packet private data
 * @return offset after command dissection
 */
static int dissect_zb_direct_secur_c25519_sha256(tvbuff_t    *tvb,
                                                 packet_info *pinfo,
                                                 proto_tree  *tree,
                                                 void        *data)
{
    return dissect_zb_direct_secur_common(tvb, pinfo, tree, data, 0U, ZB_DIRECT_MSG_ID_SECUR_C25519_SHA256);
}

/**
 * Dissector for security packets authenticated with curve P-256.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  data    raw packet private data
 * @return offset after command dissection
 */
static int dissect_zb_direct_secur_p256(tvbuff_t    *tvb,
                                        packet_info *pinfo,
                                        proto_tree  *tree,
                                        void        *data)
{
    return dissect_zb_direct_secur_common(tvb, pinfo, tree, data, 0U, ZB_DIRECT_MSG_ID_SECUR_P256);
}

/*****************************************************************************/
/****************** BLE Service Characteristics Dissectors *******************/
/*****************************************************************************/

/**
 * Dissector for Form Network.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_formation(tvbuff_t    *tvb,
                                       packet_info *pinfo,
                                       proto_tree  *tree,
                                       void        *data)
{
    proto_item* ti;
    unsigned offset = 0;

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_form_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_form, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "FORM Request");

    if (tree)
    {
        offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data,
                                   ZBEE_TLV_SRC_TYPE_ZB_DIRECT,
                                   ZB_DIRECT_MSG_ID_FORMATION);
    }

    return offset;
}

/**
 * Dissector for Commissioning Status.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_status(tvbuff_t    *tvb,
                                    packet_info *pinfo,
                                    proto_tree  *tree,
                                    void        *data)
{
    proto_item* ti;
    unsigned offset = 0;
    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_status_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_status, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "COMM STATUS Notification");

    offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data,
                               ZBEE_TLV_SRC_TYPE_ZB_DIRECT,
                               ZB_DIRECT_MSG_ID_STATUS);

    return offset;
}

/**
 * Dissector for Join Network.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_join(tvbuff_t    *tvb,
                                  packet_info *pinfo,
                                  proto_tree  *tree,
                                  void        *data)
{
    proto_item* ti;
    unsigned offset = 0;

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_join_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_join, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "JOIN Request");

    if (tree)
    {
        offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data,
                                   ZBEE_TLV_SRC_TYPE_ZB_DIRECT,
                                   ZB_DIRECT_MSG_ID_JOIN);
    }

    return offset;
}

/**
 * Dissector for Permit Joining.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_permit_join(tvbuff_t    *tvb,
                                         packet_info *pinfo,
                                         proto_tree  *tree,
                                         void        *data)
{
    proto_item* ti;
    unsigned offset = 0;

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_permit_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_permit_join, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "PERMIT JOIN Request");

    if (offset < tvb_reported_length(tvb))
    {
        guint32 parent_time;

        proto_tree_add_item_ret_uint(tree, hf_zb_direct_comm_permit_time, tvb, offset, 1, ENC_LITTLE_ENDIAN, &parent_time);
        offset += 1;

        if (parent_time > 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": open for %us", parent_time);
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": close");
        }
    }

    return offset;
}

/**
 * Dissector for Leave Networ.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_leave(tvbuff_t    *tvb,
                                   packet_info *pinfo,
                                   proto_tree  *tree,
                                   void        *data)
{
    proto_item* ti;
    unsigned offset = 0;

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_leave_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_leave, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "LEAVE Request");

    if (offset < tvb_reported_length(tvb))
    {
        bool rm_children;
        bool rejoin;

        proto_tree_add_item_ret_boolean(tree, hf_zb_direct_comm_rm_children, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rm_children);
        offset += 1;

        proto_tree_add_item_ret_boolean(tree, hf_zb_direct_comm_rejoin, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rejoin);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, " (remove children: %s, rejoin: %s)", BOOLSTR(rm_children), BOOLSTR(rejoin));
    }

    return offset;
}

/**
 * Dissector for Manage Joiners.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_manage_joiners(tvbuff_t    *tvb,
                                            packet_info *pinfo,
                                            proto_tree  *tree,
                                            void        *data)
{
    proto_item* ti;
    unsigned offset = 0;

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_manage_joiners_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_manage_joiners, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "MANAGE JOINERS Request");

    if (tree)
    {
        offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data,
                                   ZBEE_TLV_SRC_TYPE_ZB_DIRECT,
                                   ZB_DIRECT_MSG_ID_MANAGE_JOINERS);
    }

    return offset;
}

/**
 * Dissector for Indentify.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_identify(tvbuff_t    *tvb,
                                      packet_info *pinfo,
                                      proto_tree  *tree,
                                      void        *data)
{
    proto_item* ti;
    unsigned offset = 0;
    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_identify_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_identify, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "IDENTIFY Request");

    if (offset < tvb_reported_length(tvb))
    {
        guint32 parent_time;

        proto_tree_add_item_ret_uint(tree, hf_zb_direct_comm_identify_time, tvb, offset, 2, ENC_LITTLE_ENDIAN, &parent_time);
        offset += 2;

        if (parent_time > 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": start for %us", parent_time);
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": stop");
        }
    }

    return offset;
}

/**
 * Dissector for Finding & Binding.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_finding_binding(tvbuff_t    *tvb,
                                             packet_info *pinfo,
                                             proto_tree  *tree,
                                             void        *data)
{
    proto_item* ti;
    unsigned offset = 0;

    offset = dissect_zb_direct_common(&tvb, pinfo, &tree, data, offset, serv_comm_uuid, char_finding_binding_uuid);
    ti = proto_tree_add_item(tree, hf_zb_direct_char_finding_binding, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    col_set_str(pinfo->cinfo, COL_INFO, "FINDING & BINDING Request");

    if (offset < tvb_reported_length(tvb))
    {
        guint32 endpoint;
        bool initiator;

        proto_tree_add_item_ret_uint(tree, hf_zb_direct_comm_fb_endpoint, tvb, offset, 1, ENC_LITTLE_ENDIAN, &endpoint);
        offset += 1;
        proto_tree_add_item_ret_boolean(tree, hf_zb_direct_comm_fb_initiator, tvb, offset, 1, ENC_LITTLE_ENDIAN, &initiator);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, " (endpoint: %u, initiator: %s)", endpoint, BOOLSTR(initiator));
    }

    return offset;
}

/**
 * Helper dissector for Tunneling.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  data    raw packet private data
 * @return offset after dissection
 */
static int dissect_zb_direct_tunneling(tvbuff_t    *tvb,
                                       packet_info *pinfo,
                                       proto_tree  *tree,
                                       void        *data)
{
    proto_item* ti;
    unsigned offset = 0;

    offset = dissect_zb_direct_common(&tvb,
                                      pinfo,
                                      &tree,
                                      data,
                                      offset,
                                      serv_tunnel_uuid,
                                      char_tunnel_uuid);


    ti = proto_tree_add_item(tree, hf_zb_direct_char_tunneling, tvb, offset, 0, ENC_NA);
    proto_item_set_generated(ti);

    offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data,
                               ZBEE_TLV_SRC_TYPE_ZB_DIRECT,
                               ZB_DIRECT_MSG_ID_TUNNELING);

    return offset;
}

/*****************************************************************************/
/******************************* Registration ********************************/
/*****************************************************************************/

/**
 * ZigBee Direct initialization routine.
 */
static void zb_direct_init(void)
{
    for (gint i = 0; i < MAX_CONNECTIONS; i++)
    {
        enc_h[i].counter = 0;

        for (gint j = 0; j < MAX_CRYPT_TOGGLES && enc_h[i].states[j] != 0; j++)
        {
            enc_h[i].states[j] = 0;
        }
    }
}

/**
 * ZigBee Direct clean routine.
 */
static void zb_direct_cleanup(void)
{
    /* Empty temporary keys */
    while (zbee_pc_keyring && keyrec(zbee_pc_keyring)->frame_num > 0)
    {
        GSList *element = zbee_pc_keyring;

        zbee_pc_keyring = g_slist_delete_link(zbee_pc_keyring, element);
    }
}

/**
 * ZigBee Direct registration routine.
 */
void proto_register_zb_direct(void)
{
    static hf_register_info hf[] =
    {
        { &hf_zb_direct_unrecognized_msg,
            { "Unrecognized message", "zbd.unrecognized",
                FT_BYTES, SEP_SPACE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_info_type,
            { "Type", "zbd.dump_info.type",
                FT_UINT8, BASE_DEC,
                VALS(info_type_str), 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_info_key,
            { "Key", "zbd.key",
                FT_BYTES, SEP_SPACE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_info_zdd_ieee,
            { "ZDD IEEE Address", "zbd.dump_info.zdd_addr",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_info_zvd_ieee,
            { "ZVD IEEE Address", "zbd.dump_info.zvd_addr",
                FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_info_encryption,
            { "Encryption enabled", "zbd.encryption_status",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /* secur */
        { &hf_zb_direct_msg_type,
            { "Message type", "zbd.secur.msg_type",
                FT_UINT8, BASE_HEX,
                VALS(msg_type_str), 0x0,
                NULL, HFILL }
        },

        /* Markers */
        { &hf_zb_direct_char_info,
            { "Dump info", "zbd.dump_info",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_c25519_aesmmo,
            { "Characteristic: Security / C25519-AES-MMO", "zbd.secur.c25519_aesmmo",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_c25519_sha256,
            { "Characteristic: Security / C25519-SHA-256", "zbd.secur.c25519_sha256",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_p256,
            { "Characteristic: Security / P-256", "zbd.secur.p256",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_form,
            { "Characteristic: Commissioning / Formation", "zbd.comm.form",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_status,
            { "Characteristic: Commissioning / Status", "zbd.comm.status",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_join,
            { "Characteristic: Commissioning / Join", "zbd.comm.join",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_permit_join,
            { "Characteristic: Commissioning / Permit Join", "zbd.comm.permit_join",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_leave,
            { "Characteristic: Commissioning / Leave", "zbd.comm.leave",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_manage_joiners,
            { "Characteristic: Commissioning / Manage Joiners", "zbd.comm.manage_joiners",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_identify,
            { "Characteristic: Commissioning / Identify", "zbd.comm.identify",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_finding_binding,
            { "Characteristic: Commissioning / Finding & Binding", "zbd.comm.finding_binding",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_char_tunneling,
            { "Characteristic: Tunneling", "zbd.comm.tunneling",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },

        /* Subtrees elements */
        { &hf_zb_direct_comm_permit_time,
            { "Permit time interval (sec)", "zbd.comm.permit_time",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_comm_rejoin,
            { "Rejoin", "zbd.comm.rejoin",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_comm_rm_children,
            { "Remove children", "zbd.comm.rm_children",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_comm_identify_time,
            { "Identify time", "zbd.comm.identify_time",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_comm_fb_endpoint,
            { "Endpoint", "zbd.comm.fb_endpoint",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_zb_direct_comm_fb_initiator,
            { "Initiator", "zbd.comm.fb_initiator",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_zb_direct_crypt_error,
            { "zbd.error.decryption", PI_UNDECODED, PI_WARN,
                "Decryption fail",
                EXPFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
    {
        &ett_zb_direct,
    };

    expert_module_t *expert_zb_direct;

    proto_zb_direct = proto_register_protocol("ZigBee Direct", /* name        */
                                              "ZBD",           /* short_name  */
                                              "zbd");          /* filter_name */

    proto_register_field_array(proto_zb_direct, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_zb_direct = expert_register_protocol(proto_zb_direct);
    expert_register_field_array(expert_zb_direct, ei, array_length(ei));

    register_init_routine(zb_direct_init);
    register_cleanup_routine(zb_direct_cleanup);

    module_t *zbd_prefs = prefs_register_protocol(proto_zb_direct, NULL);

    static uat_field_t key_uat_fields[] =
    {
        UAT_FLD_CSTRING(uat_key_records, zdd_ieee, "ZDD IEEE",
                        "A 8-byte address of ZDD in hexadecimal with optional "
                        "dash-, colon-, or space-separator characters, "
                        "in Big Endian"),
        UAT_FLD_CSTRING(uat_key_records, zvd_ieee, "ZVD IEEE",
                        "A 8-byte address of ZVD in hexadecimal with optional "
                        "dash-, colon-, or space-separator characters, "
                        "in Big Endian"),
        UAT_FLD_CSTRING(uat_key_records, key, "Key",
                        "A 16-byte session key in hexadecimal with optional "
                        "dash-, colon-, or space-separator characters, "
                        "in Big Endian"),

        UAT_FLD_CSTRING(uat_key_records, label, "Label", "User comment"),
        UAT_END_FIELDS
    };

    /* Affects dissection of packets, but not set of named fields */
    guint uat_flags = UAT_AFFECTS_DISSECTION;

    zbd_secur_key_table_uat = uat_new("Pre-configured Keys",
                                      sizeof(uat_key_record_t),
                                      "zigbee_direct_pc_keys",
                                      TRUE,
                                      &uat_key_records,
                                      &num_uat_key_records,
                                      uat_flags,
                                      NULL, /** TODO: ptr to help manual? */
                                      uat_key_record_copy_cb,
                                      uat_key_record_update_cb,
                                      uat_key_record_free_cb,
                                      uat_key_record_post_update,
                                      NULL,
                                      key_uat_fields);

    prefs_register_uat_preference(zbd_prefs,
                                  "key_table",
                                  "Pre-configured Keys",
                                  "Pre-configured session keys",
                                  zbd_secur_key_table_uat);

    prefs_register_bool_preference(zbd_prefs,
                                   "ignore_late_keys",
                                   "Ignore Late Keys",
                                   "Whether or not dissector shall ignore keys, "
                                   "which were provided after current packet "
                                   "during decryption",
                                   &ignore_late_keys);
}

/**
 * ZigBee Direct handoff routine.
 */
void proto_reg_handoff_zb_direct(void)
{
    typedef struct
    {
        const char *uuid;
        dissector_t dissector;
    } zb_direct_service_t;

    static zb_direct_service_t services[] =
    {
        { "29144af4-00ff-4481-bfe9-6d0299b429e3", dissect_zb_direct_dump_info },

        /* 6.5.1. Zigbee Direct Security Service characteristic */
        { "29144af4-0001-4481-bfe9-6d0299b429e3", dissect_zb_direct_secur_c25519_aesmmo },
        { "29144af4-0002-4481-bfe9-6d0299b429e3", dissect_zb_direct_secur_c25519_sha256 },
        { "29144af4-0003-4481-bfe9-6d0299b429e3", dissect_zb_direct_secur_p256 },

        /* 7.7.2.3. Zigbee Direct Commissioning Service characteristics */
        { "7072377d-0001-421c-b163-491c27333a61", dissect_zb_direct_formation },
        { "7072377d-0002-421c-b163-491c27333a61", dissect_zb_direct_join },
        { "7072377d-0003-421c-b163-491c27333a61", dissect_zb_direct_permit_join },
        { "7072377d-0004-421c-b163-491c27333a61", dissect_zb_direct_leave },
        { "7072377d-0005-421c-b163-491c27333a61", dissect_zb_direct_status },
        { "7072377d-0006-421c-b163-491c27333a61", dissect_zb_direct_manage_joiners },
        { "7072377d-0007-421c-b163-491c27333a61", dissect_zb_direct_identify },
        { "7072377d-0008-421c-b163-491c27333a61", dissect_zb_direct_finding_binding },

        /* 7.7.3.3. Zigbee Direct Tunnel Service characteristics */
        { "8bd178fd-0001-45f4-8120-b2378bd5313f", dissect_zb_direct_tunneling },
        { NULL, NULL },
    };

    for (gsize i = 0; services[i].uuid; i++)
    {
        dissector_handle_t handle = create_dissector_handle(services[i].dissector, proto_zb_direct);
        dissector_add_string("bluetooth.uuid", services[i].uuid, handle);
    }

    zbee_nwk_handle = find_dissector("zbee_nwk");
}

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
