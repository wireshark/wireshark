/* packet-rf4ce-secur.h
 * Security related functions and objects for RF4CE dissector
 * Copyright (C) Atmosic 2023
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RF4CE_SECUR_H
#define PACKET_RF4CE_SECUR_H

#include <stdbool.h>
#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/value_string.h>

#define RF4CE_IEEE_ADDR_LEN                 8
#define RF4CE_SHORT_ADDR_LEN                2

#define RF4CE_MIN_NWK_LENGTH                5
#define RF4CE_MAX_NWK_LENGTH                148

#define RF4CE_VENDOR_SECRET_STORAGE_SIZE    64
#define RF4CE_NWK_KEY_STORAGE_SIZE          64
#define RF4CE_ADDR_TABLE_SIZE               (RF4CE_NWK_KEY_STORAGE_SIZE * 2)

#define RF4CE_NWK_KEY_SEED_DATA_LENGTH      80

#define RF4CE_CCM_M                         4
#define RF4CE_CCM_L                         2
#define RF4CE_CCM_NONCE_LEN                 (15 - RF4CE_CCM_L)
#define RF4CE_SECUR_CONTROL                 5
#define SEC_STR_LEN                         16
#define KEY_LEN                             SEC_STR_LEN

typedef struct keypair_context_s {
    guint8 nwk_key_seed_latest[RF4CE_NWK_KEY_SEED_DATA_LENGTH];
    guint8 nwk_key_seed_prev[RF4CE_NWK_KEY_SEED_DATA_LENGTH];
    guint8 nwk_key_seed[RF4CE_NWK_KEY_SEED_DATA_LENGTH];
    guint8 controller_addr[RF4CE_IEEE_ADDR_LEN];
    guint8 target_addr[RF4CE_IEEE_ADDR_LEN];
    guint8 nwk_key_exchange_transfer_expected;
    guint8 nwk_key_exchange_transfer_received;
} keypair_context_t;

#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH    8
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH    8

#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_AB_LENGTH   \
    (RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH       \
     + RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH)

#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_TAG_A_LENGTH     4
#define RF4CE_PROFILE_CMD_KEY_EXCHANGE_TAG_B_LENGTH     4

#define RF4CE_KEY_EXCHANGE_CONTEXT_LENGTH               9
#define RF4CE_KEY_EXCHANGE_LABEL_LENGTH                 (2 * (RF4CE_IEEE_ADDR_LEN))

#define RF4CE_CMAC_ARG_2_LENGTH         \
    (RF4CE_KEY_EXCHANGE_CONTEXT_LENGTH  \
     + RF4CE_KEY_EXCHANGE_LABEL_LENGTH  \
     + KEY_LEN)

/* RF4CE GDP 2.0 spec, part 7.4.2 Key generation
 * Context shall be set to the ASCII representation of the nine character string (including a space
 * after “RF4CE” but without quotes and without null termination) “RF4CE GDP”.
 */
#define CONTEXT_STR         "RF4CE GDP"
#define CONTEXT_STR_LEN     9

extern guint8 DEFAULT_SECRET[SEC_STR_LEN];

typedef struct key_exchange_context_s {
    guint8 rand_a[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH];
    guint8 rand_b[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH];
    guint8 mac_a[RF4CE_IEEE_ADDR_LEN]; /* target address     */
    guint8 mac_b[RF4CE_IEEE_ADDR_LEN]; /* controller address */
    gboolean is_proc_started;
} key_exchange_context_t;

typedef struct
#if defined(_MSC_VER)
# pragma pack(push, 1)
#else
__attribute__((__packed__))
#endif
rf4ce_key_dk_tag_s
{
    guint8 a[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH];
    guint8 b[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH];
} rf4ce_key_dk_tag_t;
#ifdef _MSC_VER
# pragma pack(pop)
#endif

typedef struct
#if defined(_MSC_VER)
# pragma pack(push, 1)
#else
__attribute__((__packed__))
#endif
rf4ce_key_context_s
{
    guint8 context[CONTEXT_STR_LEN];
    guint8 mac_a[RF4CE_IEEE_ADDR_LEN];
    guint8 mac_b[RF4CE_IEEE_ADDR_LEN];
    guint8 pairing_key[KEY_LEN];
}
rf4ce_key_context_t;
#ifdef _MSC_VER
# pragma pack(pop)
#endif

void rf4ce_aes_cmac(guchar *input, gulong length, guchar *key, guchar *mac_value);

typedef struct addr_entry_s {
    guint8 ieee_addr[RF4CE_IEEE_ADDR_LEN];
    guint16 short_addr;
    gboolean is_used;
} addr_entry_t;

typedef struct nwk_key_entry_s {
    guint8 nwk_key[KEY_LEN];
    addr_entry_t *controller_addr_ent;
    addr_entry_t *target_addr_ent;
    gboolean key_from_gui;
    gboolean is_used;
    gboolean is_pairing_key;
} nwk_key_entry_t;

typedef struct vendor_secret_entry_s {
    guint8 secret[SEC_STR_LEN];
    gboolean is_used;
} vendor_secret_entry_t;

typedef struct uat_security_record_s {
    gchar *sec_str;
    guint8 type;
    gchar *label;
} uat_security_record_t;

void keypair_context_init(const guint8 *controller_ieee, const guint8 *target_ieee, guint8 expected_transfer_count);
void keypair_context_update_seed(guint8 *seed, guint8 seed_seqn);

void nwk_key_storage_add_entry(guint8 *nwk_key, addr_entry_t *controller_addr_ent, addr_entry_t *target_addr_ent, gboolean key_from_gui, gboolean is_pairing_key);
void nwk_key_storage_release_entry(guint8 *nwk_key, gboolean key_from_gui);

void rf4ce_addr_table_add_addrs(const void *ieee_addr, guint16 short_addr);
gboolean rf4ce_addr_table_get_ieee_addr(guint8 *ieee_addr, packet_info *pinfo, gboolean is_src);
addr_entry_t *rf4ce_addr_table_get_addr_entry_by_ieee(guint8 *ieee_addr);

void key_exchange_context_init(void);

void key_exchange_context_start_procedure(void);
void key_exchange_context_stop_procedure(void);
gboolean key_exchange_context_is_procedure_started(void);

void key_exchange_context_set_rand_a(guint8 *rand_a);
void key_exchange_context_set_rand_b(guint8 *rand_b);

void key_exchange_context_set_mac_a(guint8 *mac_a);
void key_exchange_context_set_mac_b(guint8 *mac_b);

void key_exchange_calc_key(guint32 tag_b_pack);

void vendor_secret_storage_add_entry(guint8 *secret);
void vendor_secret_storage_release_entry(guint8 *secret);

void rf4ce_secur_cleanup(void);

typedef struct
#if defined(_MSC_VER)
# pragma pack(push, 1)
#else
__attribute__((__packed__))
#endif
rf4ce_secur_ccm_nonce_s
{
    guint8 source_address[RF4CE_IEEE_ADDR_LEN];     /*!< Extended Source */
    guint32 frame_counter;                          /*!< Frame Counter */
    guint8 secur_control;                           /*!< Security Control Field */
} rf4ce_secur_ccm_nonce_t;
#ifdef _MSC_VER
# pragma pack(pop)
#endif

typedef struct
#if defined(_MSC_VER)
# pragma pack(push, 1)
#else
__attribute__((__packed__))
#endif
rf4ce_secur_ccm_auth_s
{
    guint8 frame_control;                           /*!< Security Control Field */
    guint32 frame_counter;                          /*!< Frame Counter */
    guint8 dest_address[RF4CE_IEEE_ADDR_LEN];       /*!< Extended Source */
} rf4ce_secur_ccm_auth_t;
#ifdef _MSC_VER
# pragma pack(pop)
#endif

gboolean decrypt_data(
    const guint8 *in,
    guint8 *out,
    guint16 payload_offset,
    guint16 *len,
    guint8 src_ieee[RF4CE_IEEE_ADDR_LEN],
    guint8 dst_ieee[RF4CE_IEEE_ADDR_LEN]);

#endif /* PACKET_RF4CE_SECUR_H */
