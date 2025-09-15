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
    uint8_t nwk_key_seed_latest[RF4CE_NWK_KEY_SEED_DATA_LENGTH];
    uint8_t nwk_key_seed_prev[RF4CE_NWK_KEY_SEED_DATA_LENGTH];
    uint8_t nwk_key_seed[RF4CE_NWK_KEY_SEED_DATA_LENGTH];
    uint8_t controller_addr[RF4CE_IEEE_ADDR_LEN];
    uint8_t target_addr[RF4CE_IEEE_ADDR_LEN];
    uint8_t nwk_key_exchange_transfer_expected;
    uint8_t nwk_key_exchange_transfer_received;
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
 * after "RF4CE" but without quotes and without null termination) "RF4CE GDP".
 */
#define CONTEXT_STR         "RF4CE GDP"
#define CONTEXT_STR_LEN     9

extern uint8_t DEFAULT_SECRET[SEC_STR_LEN];

typedef struct key_exchange_context_s {
    uint8_t rand_a[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_A_LENGTH];
    uint8_t rand_b[RF4CE_PROFILE_CMD_KEY_EXCHANGE_RAND_B_LENGTH];
    uint8_t mac_a[RF4CE_IEEE_ADDR_LEN]; /* target address     */
    uint8_t mac_b[RF4CE_IEEE_ADDR_LEN]; /* controller address */
    bool is_proc_started;
} key_exchange_context_t;

void rf4ce_aes_cmac(unsigned char *input, unsigned long length, unsigned char *key, unsigned char *mac_value);

typedef struct addr_entry_s {
    uint8_t ieee_addr[RF4CE_IEEE_ADDR_LEN];
    uint16_t short_addr;
    bool is_used;
} addr_entry_t;

typedef struct nwk_key_entry_s {
    uint8_t nwk_key[KEY_LEN];
    addr_entry_t *controller_addr_ent;
    addr_entry_t *target_addr_ent;
    bool key_from_gui;
    bool is_used;
    bool is_pairing_key;
} nwk_key_entry_t;

typedef struct vendor_secret_entry_s {
    uint8_t secret[SEC_STR_LEN];
    bool is_used;
} vendor_secret_entry_t;

typedef struct uat_security_record_s {
    char *sec_str;
    uint8_t type;
    char *label;
} uat_security_record_t;

void keypair_context_init(const uint8_t *controller_ieee, const uint8_t *target_ieee, uint8_t expected_transfer_count);
void keypair_context_update_seed(uint8_t *seed, uint8_t seed_seqn);

void nwk_key_storage_add_entry(uint8_t *nwk_key, addr_entry_t *controller_addr_ent, addr_entry_t *target_addr_ent, bool key_from_gui, bool is_pairing_key);
void nwk_key_storage_release_entry(uint8_t *nwk_key, bool key_from_gui);

void rf4ce_addr_table_add_addrs(const void *ieee_addr, uint16_t short_addr);
bool rf4ce_addr_table_get_ieee_addr(uint8_t *ieee_addr, packet_info *pinfo, bool is_src);
addr_entry_t *rf4ce_addr_table_get_addr_entry_by_ieee(uint8_t *ieee_addr);

void key_exchange_context_init(void);

void key_exchange_context_start_procedure(void);
void key_exchange_context_stop_procedure(void);
bool key_exchange_context_is_procedure_started(void);

void key_exchange_context_set_rand_a(uint8_t *rand_a);
void key_exchange_context_set_rand_b(uint8_t *rand_b);

void key_exchange_context_set_mac_a(uint8_t *mac_a);
void key_exchange_context_set_mac_b(uint8_t *mac_b);

void key_exchange_calc_key(uint32_t tag_b_pack);

void vendor_secret_storage_add_entry(uint8_t *secret);
void vendor_secret_storage_release_entry(uint8_t *secret);

void rf4ce_secur_cleanup(void);

bool decrypt_data(
    const uint8_t *in,
    uint8_t *out,
    uint16_t payload_offset,
    uint16_t *len,
    uint8_t src_ieee[RF4CE_IEEE_ADDR_LEN],
    uint8_t dst_ieee[RF4CE_IEEE_ADDR_LEN]);

#endif /* PACKET_RF4CE_SECUR_H */
