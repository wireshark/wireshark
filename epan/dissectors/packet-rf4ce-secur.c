/* packet-rf4ce-secur.c
 * Security related functions and objects for RF4CE dissector
 * Copyright (C) Atmosic 2023
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet-rf4ce-secur.h"
#include "packet-zbee-security.h"
#include "packet-ieee802154.h"
#include <wsutil/wsgcrypt.h>
#include <epan/proto_data.h>

#ifdef RF4CE_DEBUG_EN
void rf4ce_print_arr(const gchar *str, guint8 *ptr, guint16 len);
#define RF4CE_PRINT_ARR(s, p, l) rf4ce_print_arr(s, p, l)
#else
#define RF4CE_PRINT_ARR(s, p, l)
#endif /* RF4CE_DEBUG_EN */

static keypair_context_t keypair_context;
static key_exchange_context_t key_exchange_context;
static addr_entry_t addr_table[RF4CE_ADDR_TABLE_SIZE];
static nwk_key_entry_t nwk_key_storage[RF4CE_NWK_KEY_STORAGE_SIZE];
static vendor_secret_entry_t vendor_secret_storage[RF4CE_VENDOR_SECRET_STORAGE_SIZE];

static void keypair_context_calc_key(guint8 *nwk_key);
static nwk_key_entry_t *nwk_key_storage_get_entry_by_key(guint8 *nwk_key, gboolean key_from_gui);

static void reverse(guint8 *dest, guint8 *src, guint16 size);

/* RF4CE GDP 2.0 spec, part 7.4.1 Key Exchange negotiation
 * Default secret: This is a 128-bit “secret” that is known to all devices that are certified to
 * conform to this specification. The value shall be set to the following octet string (lowest order
 * octet first)
 * Note that this value should be expected to be widely known and the overall link security
 * should not depend on this value remaining a secret.
 */
guint8 DEFAULT_SECRET[SEC_STR_LEN] =
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

void keypair_context_init(const guint8 *controller_ieee, const guint8 *target_ieee, guint8 expected_transfer_count)
{
    if ((controller_ieee == NULL) || (target_ieee == NULL))
    {
        return;
    }
    memset(&keypair_context, 0, sizeof(keypair_context_t));

    memcpy(keypair_context.controller_addr, controller_ieee, RF4CE_IEEE_ADDR_LEN);
    memcpy(keypair_context.target_addr, target_ieee, RF4CE_IEEE_ADDR_LEN);

    keypair_context.nwk_key_exchange_transfer_expected = expected_transfer_count;
}

static void keypair_context_calc_key(guint8 *nwk_key)
{
    for (int i = 0; i < keypair_context.nwk_key_exchange_transfer_received; i++)
    {
        for (int j = 0; j < KEY_LEN; j++)
        {
            keypair_context.nwk_key_seed[(i + 1) * KEY_LEN + j] ^= keypair_context.nwk_key_seed[i * KEY_LEN + j];
        }
    }

    memcpy(nwk_key, &keypair_context.nwk_key_seed[RF4CE_NWK_KEY_SEED_DATA_LENGTH - KEY_LEN], KEY_LEN);
}

void keypair_context_update_seed(guint8 *seed, guint8 seed_seqn)
{
    gboolean is_retransmit = (seed_seqn == keypair_context.nwk_key_exchange_transfer_received - 1);
    gboolean is_latest_seed = (seed_seqn + 1 == keypair_context.nwk_key_exchange_transfer_expected);

    /* retransmitt of the latest key seed - we must to re-calculate a NWK key */
    if (is_retransmit && is_latest_seed)
    {
        memcpy(keypair_context.nwk_key_seed, keypair_context.nwk_key_seed_prev, RF4CE_NWK_KEY_SEED_DATA_LENGTH);
    }

    if (seed_seqn == 0)
    {
        memcpy(keypair_context.nwk_key_seed_latest, seed, RF4CE_NWK_KEY_SEED_DATA_LENGTH);
        keypair_context.nwk_key_exchange_transfer_received = 1;
        return;
    }

    /* Retransmit of the previous key seed. Should take this one */
    if (is_retransmit)
    {
        /* save this one as a candidate */
        memcpy(keypair_context.nwk_key_seed_latest, seed, RF4CE_NWK_KEY_SEED_DATA_LENGTH);

        /* move on if it's the latest seed to re-calculate a NWK key */
        if (!is_latest_seed)
        {
            return;
        }
    }

    if (seed_seqn == keypair_context.nwk_key_exchange_transfer_received)
    {
        /* Apply previous key seed, it has been accepted since we received the next one */
        for (int i = 0; i < RF4CE_NWK_KEY_SEED_DATA_LENGTH; i++)
        {
            keypair_context.nwk_key_seed[i] ^= keypair_context.nwk_key_seed_latest[i];
        }

        /* save this one as a candidate */
        memcpy(keypair_context.nwk_key_seed_latest, seed, RF4CE_NWK_KEY_SEED_DATA_LENGTH);
        keypair_context.nwk_key_exchange_transfer_received += 1;
    }

    if (is_latest_seed)
    {
        guint8 nwk_key[KEY_LEN] = {0};
        addr_entry_t *controller_addr_ent = rf4ce_addr_table_get_addr_entry_by_ieee(keypair_context.controller_addr);
        addr_entry_t *target_addr_ent = rf4ce_addr_table_get_addr_entry_by_ieee(keypair_context.target_addr);

        /* save the current key seed to avoid retransmitts of the latest one in future */
        memcpy(keypair_context.nwk_key_seed_prev, keypair_context.nwk_key_seed, RF4CE_NWK_KEY_SEED_DATA_LENGTH);

        for (int i = 0; i < RF4CE_NWK_KEY_SEED_DATA_LENGTH; i++)
        {
            keypair_context.nwk_key_seed[i] ^= keypair_context.nwk_key_seed_latest[i];
        }

        keypair_context_calc_key(nwk_key);

        nwk_key_storage_add_entry(
            nwk_key,
            controller_addr_ent,
            target_addr_ent,
            FALSE, /* key from commissioning session */
            TRUE); /* is_pairing_key                 */
    }
}

static nwk_key_entry_t *nwk_key_storage_get_entry_by_key(guint8 *nwk_key, gboolean key_from_gui)
{
    nwk_key_entry_t *entry = NULL;
    int idx = 0;

    while (idx < RF4CE_NWK_KEY_STORAGE_SIZE)
    {
        if (nwk_key_storage[idx].is_used && (nwk_key_storage[idx].key_from_gui == key_from_gui) && (memcmp(nwk_key_storage[idx].nwk_key, nwk_key, KEY_LEN) == 0))
        {
            entry = nwk_key_storage + idx;
            break;
        }

        idx++;
    }

    return entry;
}

void nwk_key_storage_add_entry(guint8 *nwk_key, addr_entry_t *controller_addr_ent, addr_entry_t *target_addr_ent, gboolean key_from_gui, gboolean is_pairing_key)
{
    /* find an existing entry so as not to add duplicates */
    nwk_key_entry_t *nwk_key_entry = nwk_key_storage_get_entry_by_key(nwk_key, key_from_gui);

    if (nwk_key_entry == NULL)
    {
        int idx = 0;

        while (idx < RF4CE_NWK_KEY_STORAGE_SIZE)
        {
            if (!nwk_key_storage[idx].is_used)
            {
                memcpy(nwk_key_storage[idx].nwk_key, nwk_key, KEY_LEN);
                nwk_key_storage[idx].controller_addr_ent = controller_addr_ent;
                nwk_key_storage[idx].target_addr_ent = target_addr_ent;
                nwk_key_storage[idx].key_from_gui = key_from_gui;
                nwk_key_storage[idx].is_used = TRUE;
                nwk_key_storage[idx].is_pairing_key = is_pairing_key;
                break;
            }

            idx++;
        }
    }
}

void nwk_key_storage_release_entry(guint8 *nwk_key, gboolean key_from_gui)
{
    nwk_key_entry_t *nwk_key_entry = nwk_key_storage_get_entry_by_key(nwk_key, key_from_gui);

    if (nwk_key_entry != NULL)
    {
        nwk_key_entry->is_used = FALSE;
    }
}

void rf4ce_addr_table_add_addrs(const void *ieee_addr, guint16 short_addr)
{
    guint idx = 0;

    if (ieee_addr == NULL)
    {
        return;
    }

    /* search for addresses so as not to add duplicates */
    while (idx < RF4CE_ADDR_TABLE_SIZE)
    {
        if (addr_table[idx].is_used && (memcmp(addr_table[idx].ieee_addr, ieee_addr, RF4CE_IEEE_ADDR_LEN) == 0) && addr_table[idx].short_addr == short_addr)
        {
            return;
        }

        idx++;
    }

    /* no duplicates found, search for a free slot */
    idx = 0;
    while (idx < RF4CE_ADDR_TABLE_SIZE && addr_table[idx].is_used)
    {
        idx++;
    }

    if (idx < RF4CE_ADDR_TABLE_SIZE)
    {
        memcpy(addr_table[idx].ieee_addr, ieee_addr, RF4CE_IEEE_ADDR_LEN);
        addr_table[idx].short_addr = short_addr;
        addr_table[idx].is_used = TRUE;
    }
}

gboolean rf4ce_addr_table_get_ieee_addr(guint8 *ieee_addr, packet_info *pinfo, gboolean is_src)
{
    gboolean addr_found = FALSE;
    address_type addr_type;
    ieee802154_hints_t *hints;
    const void *p_addr = NULL;
    guint16 short_addr = 0xffff;

    /* Check inputs */
    if ((ieee_addr == NULL) || (pinfo == NULL))
    {
        return FALSE;
    }
    if (is_src)
    {
        addr_type = pinfo->dl_src.type;
        p_addr = pinfo->dl_src.data;
    }
    else
    {
        addr_type = pinfo->dl_dst.type;
        p_addr = pinfo->dl_dst.data;
    }
    if (addr_type == AT_EUI64)
    {
        if (p_addr == NULL)
        {
            return FALSE;
        }
    }
    else
    {
        /* Get addresses */
        hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(),
                                                       pinfo,
                                                       proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN),
                                                       0
        );
        if (hints == NULL)
        {
            return FALSE;
        }
        short_addr = (is_src) ? hints->src16 : hints->dst16;
    }
    /* Search address in address table */
    for (guint idx = 0; idx < RF4CE_ADDR_TABLE_SIZE; idx++)
    {
        if (addr_table[idx].is_used)
        {
            if (addr_type == AT_EUI64)
            {
                if (memcmp(addr_table[idx].ieee_addr, p_addr, RF4CE_IEEE_ADDR_LEN) == 0) {
                    addr_found = TRUE;
                }
            }
            else
            {
                if (addr_table[idx].short_addr == short_addr) {
                    addr_found = TRUE;
                }
            }
            if (addr_found)
            {
                memcpy(ieee_addr, addr_table[idx].ieee_addr, RF4CE_IEEE_ADDR_LEN);
                break;
            }
        }
    }
    return addr_found;
}

addr_entry_t *rf4ce_addr_table_get_addr_entry_by_ieee(guint8 *ieee_addr)
{
    addr_entry_t *entry = NULL;
    guint idx = 0;

    while (ieee_addr != NULL && idx < RF4CE_ADDR_TABLE_SIZE)
    {
        if (addr_table[idx].is_used && memcmp(addr_table[idx].ieee_addr, ieee_addr, RF4CE_IEEE_ADDR_LEN) == 0)
        {
            entry = addr_table + idx;
            break;
        }

        idx++;
    }

    return entry;
}

void key_exchange_context_init(void)
{
    memset(&key_exchange_context.rand_a, 0, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH);
    memset(&key_exchange_context.rand_b, 0, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH);
    memset(&key_exchange_context.mac_a, 0, RF4CE_IEEE_ADDR_LEN);
    memset(&key_exchange_context.mac_b, 0, RF4CE_IEEE_ADDR_LEN);
}

void key_exchange_context_start_procedure(void)
{
    if (!key_exchange_context.is_proc_started)
    {
        key_exchange_context.is_proc_started = TRUE;
    }
}

void key_exchange_context_stop_procedure(void)
{
    if (key_exchange_context.is_proc_started)
    {
        key_exchange_context.is_proc_started = FALSE;
    }
}

gboolean key_exchange_context_is_procedure_started(void)
{
    return key_exchange_context.is_proc_started;
}

void key_exchange_context_set_rand_a(guint8 *rand_a)
{
    if (rand_a != NULL)
    {
        memcpy(key_exchange_context.rand_a, rand_a, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH);
    }
}

void key_exchange_context_set_rand_b(guint8 *rand_b)
{
    if (rand_b != NULL)
    {
        memcpy(key_exchange_context.rand_b, rand_b, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH);
    }
}

void key_exchange_context_set_mac_a(guint8 *mac_a)
{
    if (mac_a != NULL)
    {
        memcpy(key_exchange_context.mac_a, mac_a, RF4CE_IEEE_ADDR_LEN);
    }
}

void key_exchange_context_set_mac_b(guint8 *mac_b)
{
    if (mac_b != NULL)
    {
        memcpy(key_exchange_context.mac_b, mac_b, RF4CE_IEEE_ADDR_LEN);
    }
}

#ifdef RF4CE_DEBUG_EN
void rf4ce_print_arr(const gchar *str, guint8 *ptr, guint16 len)
{
  g_print("%s: ", str);
  for (guint16 i = 0; i < len-1; i++)
  {
    g_print("%02x:", *(ptr+i));
  }
  g_print("%02x\n", *(ptr+len-1));
}
#endif /* RF4CE_DEBUG_EN */

static gboolean calc_key_cmac(guint8 *secret, guint8 *nwk_key, guint32 tag_b_pack, guint8 *key_out)
{
    guint8 mac_a[RF4CE_IEEE_ADDR_LEN];
    guint8 mac_b[RF4CE_IEEE_ADDR_LEN];

    guint8 *rand_a = key_exchange_context.rand_a;
    guint8 *rand_b = key_exchange_context.rand_b;

    rf4ce_key_dk_tag_t k_dk_data;
    rf4ce_key_dk_tag_t k_dk_data_reversed;

    rf4ce_key_context_t context_data;

    guint8 k_dk_key[KEY_LEN];
    guint8 new_key[KEY_LEN];

    guint8 dummy[KEY_LEN];
    guint32 tag_b_calc;

    reverse(mac_a, key_exchange_context.mac_a, RF4CE_IEEE_ADDR_LEN);
    reverse(mac_b, key_exchange_context.mac_b, RF4CE_IEEE_ADDR_LEN);

    memcpy(k_dk_data.a, rand_a, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH);
    memcpy(k_dk_data.b, rand_b, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH);

    memcpy(k_dk_data_reversed.a, rand_b, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH);
    memcpy(k_dk_data_reversed.b, rand_a, RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH);

    memcpy(context_data.context, CONTEXT_STR, CONTEXT_STR_LEN);
    memcpy(context_data.mac_a, mac_a, RF4CE_IEEE_ADDR_LEN);
    memcpy(context_data.mac_b, mac_b, RF4CE_IEEE_ADDR_LEN);
    memcpy(context_data.pairing_key, nwk_key, KEY_LEN);

    /* Generic Device Profile Version 2.0
     * 7.4.2 Key generation
     * Calculate derivation key
     * K_dk = AES-128-CMAC (RAND-A || RAND-B, Shared secret)
     */
    rf4ce_aes_cmac(secret, SEC_STR_LEN, (guint8 *)&k_dk_data, k_dk_key);

    /* Calculate new link key
     * Link key = AES-128-CMAC (K_dk, context || label || pairing key)
     */
    rf4ce_aes_cmac((guint8 *)&context_data, sizeof(context_data), k_dk_key, new_key);

    /* Calculate TAG-B value
     * TAG-B = AES-128-CMAC(link key, RAND-B || RAND-A)
     */
    rf4ce_aes_cmac((guint8 *)&k_dk_data_reversed, sizeof(k_dk_data_reversed), new_key, dummy);
    memcpy((guint8 *)&tag_b_calc, dummy, RF4CE_PROFILE_CMD_KEY_EXCHANGE_TAG_A_LENGTH);

    RF4CE_PRINT_ARR("tag_b_calc", (guint8 *)&tag_b_calc, 4);
    RF4CE_PRINT_ARR("   new_key", new_key, 16);

    if (tag_b_pack == tag_b_calc)
    {
        memcpy(key_out, new_key, KEY_LEN);
        return TRUE;
    }

    return FALSE;
}

static gboolean key_exchange_calc_key_cont(guint8 *secret, guint32 tag_b_pack, gboolean try_pairing_key, guint8 *new_key_out)
{
    gboolean is_new_key_found = FALSE;

    for (guint i = 0; i < RF4CE_NWK_KEY_STORAGE_SIZE; i++)
    {
        if (nwk_key_storage[i].is_used && ((try_pairing_key && nwk_key_storage[i].is_pairing_key) || (!try_pairing_key && nwk_key_storage[i].key_from_gui)))
        {
            is_new_key_found = calc_key_cmac(secret, nwk_key_storage[i].nwk_key, tag_b_pack, new_key_out);

            if (is_new_key_found)
            {
                break;
            }
        }
    }

    return is_new_key_found;
}

void key_exchange_calc_key(guint32 tag_b_pack)
{
    guint8 *controller_addr = key_exchange_context.mac_a;
    guint8 *target_addr = key_exchange_context.mac_b;

    addr_entry_t *controller_addr_ent = rf4ce_addr_table_get_addr_entry_by_ieee(controller_addr);
    addr_entry_t *target_addr_ent = rf4ce_addr_table_get_addr_entry_by_ieee(target_addr);

    guint8 *secret;

    guint8 new_key[KEY_LEN];
    gboolean is_new_key_found = FALSE;

    for (guint i = 0; i < RF4CE_VENDOR_SECRET_STORAGE_SIZE; i++)
    {
        if (!vendor_secret_storage[i].is_used)
        {
            continue;
        }

        secret = vendor_secret_storage[i].secret;

        /* try all the pairing keys first */
        is_new_key_found = key_exchange_calc_key_cont(secret, tag_b_pack, TRUE, new_key);

        /* try other keys */
        if (!is_new_key_found)
        {
            is_new_key_found = key_exchange_calc_key_cont(secret, tag_b_pack, FALSE, new_key);
        }

        if (is_new_key_found)
        {
            nwk_key_storage_add_entry(
                new_key,
                controller_addr_ent,
                target_addr_ent,
                FALSE,  /* key from the Key Exchange procedure */
                FALSE); /* !is_pairing_key */

            break;
        }
    }
}

static vendor_secret_entry_t *vendor_secret_storage_get_entry(guint8 *secret)
{
    vendor_secret_entry_t *entry = NULL;
    int idx = 0;

    while (idx < RF4CE_VENDOR_SECRET_STORAGE_SIZE)
    {
        if (vendor_secret_storage[idx].is_used && (memcmp(vendor_secret_storage[idx].secret, secret, SEC_STR_LEN) == 0))
        {
            entry = vendor_secret_storage + idx;
            break;
        }

        idx++;
    }

    return entry;
}

void vendor_secret_storage_add_entry(guint8 *secret)
{
    guint idx = 0;
    vendor_secret_entry_t *entry = vendor_secret_storage_get_entry(secret);

    if (entry != NULL)
    {
        return;
    }

    while (idx < RF4CE_VENDOR_SECRET_STORAGE_SIZE && vendor_secret_storage[idx].is_used)
    {
        idx++;
    }

    if (idx < RF4CE_VENDOR_SECRET_STORAGE_SIZE)
    {
        memcpy(vendor_secret_storage[idx].secret, secret, SEC_STR_LEN);
        vendor_secret_storage[idx].is_used = TRUE;
    }
}

void vendor_secret_storage_release_entry(guint8 *secret)
{
    vendor_secret_entry_t *entry = vendor_secret_storage_get_entry(secret);

    if (entry != NULL)
    {
        entry->is_used = FALSE;
    }
}

void rf4ce_secur_cleanup(void)
{
    int idx = 0;

    memset(&keypair_context, 0, sizeof(keypair_context));
    memset(addr_table, 0, sizeof(addr_table));

    while (idx < RF4CE_NWK_KEY_STORAGE_SIZE)
    {
        if (nwk_key_storage[idx].is_used && !nwk_key_storage[idx].key_from_gui)
        {
            nwk_key_storage[idx].is_used = FALSE;
        }

        idx++;
    }
}

static void reverse(guint8 *dest, guint8 *src, guint16 size)
{
    for (int i = 0; i < size; i++)
    {
        dest[size - i - 1] = src[i];
    }
}

gboolean decrypt_data(
    const guint8 *in, guint8 *out,
    guint16 payload_offset,
    guint16 *len,
    guint8 src_ieee[RF4CE_IEEE_ADDR_LEN], guint8 dst_ieee[RF4CE_IEEE_ADDR_LEN])
{
    gboolean ret = FALSE;
    guint8 frame_control = *in;
    int idx = 0;

    if (*len < RF4CE_MIN_NWK_LENGTH || *len > RF4CE_MAX_NWK_LENGTH)
    {
        return FALSE;
    }

    while (idx < RF4CE_NWK_KEY_STORAGE_SIZE)
    {
        if (nwk_key_storage[idx].is_used)
        {
            /* Form the nonce (3.5.11.3 Outgoing frame security) */
            rf4ce_secur_ccm_nonce_t nonce =
                (rf4ce_secur_ccm_nonce_t){
                    .secur_control = RF4CE_SECUR_CONTROL};

            /* Fetch counter from the packet (don't check) */
            memcpy(&(nonce.frame_counter), in + 1, sizeof(guint32));
            reverse(&(nonce.source_address[0]), src_ieee, 8);

            /* Form the auth string (3.5.11.3 Outgoing frame security) */
            rf4ce_secur_ccm_auth_t auth =
                (rf4ce_secur_ccm_auth_t){
                    .frame_control = frame_control};

            /* Fetch counter from the packet (don't check) */
            memcpy(&(auth.frame_counter), in + 1, sizeof(guint32));
            reverse(&(auth.dest_address[0]), dst_ieee, 8);

            ret = zbee_sec_ccm_decrypt(nwk_key_storage[idx].nwk_key,
                                       (guint8 *)&nonce,
                                       (guint8 *)&auth,
                                       in + payload_offset,
                                       out,
                                       sizeof(auth),
                                       *len - payload_offset - RF4CE_CCM_M,
                                       RF4CE_CCM_M);

            if (ret)
            {
                *len = *len - payload_offset - RF4CE_CCM_M;
                break;
            }
        }

        idx++;
    }

    return ret;
}

// Calculate the CMAC
void rf4ce_aes_cmac(guchar *input, gulong length, guchar *key, guchar *mac_value)
{
    gcry_mac_hd_t mac_hd;
    size_t l = length;

    if (gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL))
    {
        return;
    }
    if (gcry_mac_setkey(mac_hd, key, KEY_LEN))
    {
        gcry_mac_close(mac_hd);
        return;
    }
    if (gcry_mac_write(mac_hd, input, length))
    {
        gcry_mac_close(mac_hd);
        return;
    }
    if (gcry_mac_read(mac_hd, mac_value, &l))
    {
        gcry_mac_close(mac_hd);
        return;
    }
    gcry_mac_close(mac_hd);
}
