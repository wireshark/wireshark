/* packet-btmesh.c
 * Routines for Bluetooth mesh dissection
 *
 * Copyright 2017, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2019, Piotr Winiarczyk <wino45@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: Mesh Profile v1.0
 */

#include "packet-bluetooth.h"
#include "packet-btatt.h"
#include "packet-btmesh.h"
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/wsgcrypt.h>
#include <epan/expert.h>
#include <stdio.h>
#include <epan/uat.h>
#include <epan/reassemble.h>

#define BTMESH_NOT_USED 0
#define BTMESH_KEY_ENTRY_VALID 4
#define BTMESH_DEVICE_KEY_ENTRY_VALID 2
#define BTMESH_LABEL_UUID_ENTRY_VALID 1
#define NO_LABEL_UUID_IDX_USED -1

#define CONFIG_APPKEY_ADD                                        0x0000
#define CONFIG_APPKEY_UPDATE                                     0x0001
#define CONFIG_COMPOSITION_DATA_STATUS                           0x0002
#define CONFIG_MODEL_PUBLICATION_SET                             0x0003
#define HEALTH_CURRENT_STATUS                                    0x0004
#define HEALTH_FAULT_STATUS                                      0x0005
#define CONFIG_HEARTBEAT_PUBLICATION_STATUS                      0x0006
#define CONFIG_APPKEY_DELETE                                     0x8000
#define CONFIG_APPKEY_GET                                        0x8001
#define CONFIG_APPKEY_LIST                                       0x8002
#define CONFIG_APPKEY_STATUS                                     0x8003
#define HEALTH_ATTENTION_GET                                     0x8004
#define HEALTH_ATTENTION_SET                                     0x8005
#define HEALTH_ATTENTION_SET_UNACKNOWLEDGED                      0x8006
#define HEALTH_ATTENTION_STATUS                                  0x8007
#define CONFIG_COMPOSITION_DATA_GET                              0x8008
#define CONFIG_BEACON_GET                                        0x8009
#define CONFIG_BEACON_SET                                        0x800a
#define CONFIG_BEACON_STATUS                                     0x800b
#define CONFIG_DEFAULT_TTL_GET                                   0x800c
#define CONFIG_DEFAULT_TTL_SET                                   0x800d
#define CONFIG_DEFAULT_TTL_STATUS                                0x800e
#define CONFIG_FRIEND_GET                                        0x800f
#define CONFIG_FRIEND_SET                                        0x8010
#define CONFIG_FRIEND_STATUS                                     0x8011
#define CONFIG_GATT_PROXY_GET                                    0x8012
#define CONFIG_GATT_PROXY_SET                                    0x8013
#define CONFIG_GATT_PROXY_STATUS                                 0x8014
#define CONFIG_KEY_REFRESH_PHASE_GET                             0x8015
#define CONFIG_KEY_REFRESH_PHASE_SET                             0x8016
#define CONFIG_KEY_REFRESH_PHASE_STATUS                          0x8017
#define CONFIG_MODEL_PUBLICATION_GET                             0x8018
#define CONFIG_MODEL_PUBLICATION_STATUS                          0x8019
#define CONFIG_MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET             0x801a
#define CONFIG_MODEL_SUBSCRIPTION_ADD                            0x801b
#define CONFIG_MODEL_SUBSCRIPTION_DELETE                         0x801c
#define CONFIG_MODEL_SUBSCRIPTION_DELETE_ALL                     0x801d
#define CONFIG_MODEL_SUBSCRIPTION_OVERWRITE                      0x801e
#define CONFIG_MODEL_SUBSCRIPTION_STATUS                         0x801f
#define CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD            0x8020
#define CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE         0x8021
#define CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE      0x8022
#define CONFIG_NETWORK_TRANSMIT_GET                              0x8023
#define CONFIG_NETWORK_TRANSMIT_SET                              0x8024
#define CONFIG_NETWORK_TRANSMIT_STATUS                           0x8025
#define CONFIG_RELAY_GET                                         0x8026
#define CONFIG_RELAY_SET                                         0x8027
#define CONFIG_RELAY_STATUS                                      0x8028
#define CONFIG_SIG_MODEL_SUBSCRIPTION_GET                        0x8029
#define CONFIG_SIG_MODEL_SUBSCRIPTION_LIST                       0x802a
#define CONFIG_VENDOR_MODEL_SUBSCRIPTION_GET                     0x802b
#define CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST                    0x802c
#define CONFIG_LOW_POWER_NODE_POLLTIMEOUT_GET                    0x802d
#define CONFIG_LOW_POWER_NODE_POLLTIMEOUT_STATUS                 0x802e
#define HEALTH_FAULT_CLEAR                                       0x802f
#define HEALTH_FAULT_CLEAR_UNACKNOWLEDGED                        0x8030
#define HEALTH_FAULT_GET                                         0x8031
#define HEALTH_FAULT_TEST                                        0x8032
#define HEALTH_FAULT_TEST_UNACKNOWLEDGED                         0x8033
#define HEALTH_PERIOD_GET                                        0x8034
#define HEALTH_PERIOD_SET                                        0x8035
#define HEALTH_PERIOD_SET_UNACKNOWLEDGED                         0x8036
#define HEALTH_PERIOD_STATUS                                     0x8037
#define CONFIG_HEARTBEAT_PUBLICATION_GET                         0x8038
#define CONFIG_HEARTBEAT_PUBLICATION_SET                         0x8039
#define CONFIG_HEARTBEAT_SUBSCRIPTION_GET                        0x803a
#define CONFIG_HEARTBEAT_SUBSCRIPTION_SET                        0x803b
#define CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS                     0x803c
#define CONFIG_MODEL_APP_BIND                                    0x803d
#define CONFIG_MODEL_APP_STATUS                                  0x803e
#define CONFIG_MODEL_APP_UNBIND                                  0x803f
#define CONFIG_NETKEY_ADD                                        0x8040
#define CONFIG_NETKEY_DELETE                                     0x8041
#define CONFIG_NETKEY_GET                                        0x8042
#define CONFIG_NETKEY_LIST                                       0x8043
#define CONFIG_NETKEY_STATUS                                     0x8044
#define CONFIG_NETKEY_UPDATE                                     0x8045
#define CONFIG_NODE_IDENTITY_GET                                 0x8046
#define CONFIG_NODE_IDENTITY_SET                                 0x8047
#define CONFIG_NODE_IDENTITY_STATUS                              0x8048
#define CONFIG_NODE_RESET                                        0x8049
#define CONFIG_NODE_RESET_STATUS                                 0x804a
#define CONFIG_SIG_MODEL_APP_GET                                 0x804b
#define CONFIG_SIG_MODEL_APP_LIST                                0x804c
#define CONFIG_VENDOR_MODEL_APP_GET                              0x804d
#define CONFIG_VENDOR_MODEL_APP_LIST                             0x804e

void proto_register_btmesh(void);

static int proto_btmesh = -1;
static dissector_table_t btmesh_model_vendor_dissector_table;

/*-------------------------------------
 * UAT for BT Mesh
 *-------------------------------------
 */
static uat_t *btmesh_uat = NULL;
static guint num_btmesh_uat = 0;

/* UAT Network, Application and IVIndex entry structure. */
typedef struct {
    gchar *network_key_string;
    guint8 *network_key;
    gint network_key_length;
    gchar *ivindex_string;
    gint ivindex_string_length;
    guint8 *ivindex;
    guint8 *privacykey;
    guint8 *encryptionkey;
    guint8 nid;
    gchar *application_key_string;
    guint8 *application_key;
    gint application_key_length;
    guint8 aid;
    guint8 valid; /* this counter must be equal to BTMESH_KEY_ENTRY_VALID make UAT entry valid */
    guint32 net_key_iv_index_hash; /* Used to identify net key / IV index pair */
} uat_btmesh_record_t;

static uat_btmesh_record_t *uat_btmesh_records = NULL;

static uat_t *btmesh_dev_key_uat = NULL;
static guint num_btmesh_dev_key_uat = 0;

/* UAT Device Key entry structure. */
typedef struct {
    gchar *device_key_string;
    guint8 *device_key;
    gint device_key_length;
    gchar *src_string;
    gint src_length;
    guint8 *src;
    guint8 valid; /* this counter must be equal to BTMESH_DEVICE_KEY_ENTRY_VALID make UAT entry valid */
} uat_btmesh_dev_key_record_t;

static uat_btmesh_dev_key_record_t *uat_btmesh_dev_key_records = NULL;

static uat_t * btmesh_label_uuid_uat = NULL;
static guint num_btmesh_label_uuid_uat = 0;

/* UAT Label UUID entry structure. */
typedef struct {
    gchar *label_uuid_string;
    guint8 *label_uuid;
    gint label_uuid_length;
    guint16 hash;
    guint8 valid; /* this counter must be equal to BTMESH_LABEL_UUID_ENTRY_VALID make UAT entry valid */
} uat_btmesh_label_uuid_record_t;

static uat_btmesh_label_uuid_record_t *uat_btmesh_label_uuid_records = NULL;

static int hf_btmesh_ivi = -1;
static int hf_btmesh_nid = -1;
static int hf_btmesh_obfuscated = -1;
static int hf_btmesh_encrypted = -1;
static int hf_btmesh_netmic = -1;

static int hf_btmesh_ctl = -1;
static int hf_btmesh_ttl = -1;
static int hf_btmesh_seq = -1;
static int hf_btmesh_src = -1;
static int hf_btmesh_dst = -1;

static int hf_btmesh_transp_pdu = -1;
static int hf_btmesh_cntr_seg = -1;
static int hf_btmesh_acc_seg = -1;
static int hf_btmesh_cntr_opcode = -1;
static int hf_btmesh_acc_akf = -1;
static int hf_btmesh_acc_aid = -1;
static int hf_btmesh_obo = -1;
static int hf_btmesh_seqzero = -1;
static int hf_btmesh_rfu = -1;
static int hf_btmesh_blockack = -1;
static int hf_btmesh_cntr_criteria_rfu = -1;
static int hf_btmesh_cntr_padding = -1;
static int hf_btmesh_cntr_fsn = -1;

static int hf_btmesh_cntr_key_refresh_flag = -1;
static int hf_btmesh_cntr_iv_update_flag = -1;
static int hf_btmesh_cntr_flags_rfu = -1;
static int hf_btmesh_cntr_iv_index = -1;
static int hf_btmesh_cntr_md = -1;

static int hf_btmesh_cntr_heartbeat_rfu = -1;
static int hf_btmesh_cntr_init_ttl = -1;
static int hf_btmesh_cntr_feature_relay = -1;
static int hf_btmesh_cntr_feature_proxy = -1;
static int hf_btmesh_cntr_feature_friend = -1;
static int hf_btmesh_cntr_feature_low_power = -1;
static int hf_btmesh_cntr_feature_rfu = -1;

static int hf_btmesh_cntr_criteria_rssifactor = -1;
static int hf_btmesh_cntr_criteria_receivewindowfactor = -1;
static int hf_btmesh_cntr_criteria_minqueuesizelog = -1;
static int hf_btmesh_cntr_receivedelay = -1;
static int hf_btmesh_cntr_polltimeout = -1;
static int hf_btmesh_cntr_previousaddress = -1;
static int hf_btmesh_cntr_numelements = -1;
static int hf_btmesh_cntr_lpncounter = -1;
static int hf_btmesh_cntr_receivewindow = -1;
static int hf_btmesh_cntr_queuesize = -1;
static int hf_btmesh_cntr_subscriptionlistsize = -1;
static int hf_btmesh_cntr_rssi = -1;
static int hf_btmesh_cntr_friendcounter = -1;
static int hf_btmesh_cntr_lpnaddress = -1;
static int hf_btmesh_cntr_transactionnumber = -1;
static int hf_btmesh_enc_access_pld = -1;
static int hf_btmesh_transtmic = -1;
static int hf_btmesh_szmic = -1;
static int hf_btmesh_seqzero_data = -1;
static int hf_btmesh_sego = -1;
static int hf_btmesh_segn = -1;
static int hf_btmesh_seg_rfu = -1;
static int hf_btmesh_segment = -1;
static int hf_btmesh_cntr_unknown_payload = -1;

static int hf_btmesh_segmented_access_fragments = -1;
static int hf_btmesh_segmented_access_fragment = -1;
static int hf_btmesh_segmented_access_fragment_overlap = -1;
static int hf_btmesh_segmented_access_fragment_overlap_conflict = -1;
static int hf_btmesh_segmented_access_fragment_multiple_tails = -1;
static int hf_btmesh_segmented_access_fragment_too_long_fragment = -1;
static int hf_btmesh_segmented_access_fragment_error = -1;
static int hf_btmesh_segmented_access_fragment_count = -1;
static int hf_btmesh_segmented_access_reassembled_length = -1;

static int hf_btmesh_segmented_control_fragments = -1;
static int hf_btmesh_segmented_control_fragment = -1;
static int hf_btmesh_segmented_control_fragment_overlap = -1;
static int hf_btmesh_segmented_control_fragment_overlap_conflict = -1;
static int hf_btmesh_segmented_control_fragment_multiple_tails = -1;
static int hf_btmesh_segmented_control_fragment_too_long_fragment = -1;
static int hf_btmesh_segmented_control_fragment_error = -1;
static int hf_btmesh_segmented_control_fragment_count = -1;
static int hf_btmesh_segmented_control_reassembled_length = -1;

static int hf_btmesh_decrypted_access = -1;
static int hf_btmesh_model_layer_opcode = -1;
static int hf_btmesh_model_layer_parameters = -1;
static int hf_btmesh_model_layer_vendor_opcode = -1;
static int hf_btmesh_model_layer_vendor = -1;

static int hf_btmesh_config_appkey_add_netkeyindexandappkeyindex = -1;
static int hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_net = -1;
static int hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_app = -1;
static int hf_btmesh_config_appkey_add_appkey = -1;
static int hf_btmesh_config_appkey_update_netkeyindexandappkeyindex = -1;
static int hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_net = -1;
static int hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_app = -1;
static int hf_btmesh_config_appkey_update_appkey = -1;
static int hf_btmesh_config_composition_data_status_page = -1;
static int hf_btmesh_config_composition_data_status_cid = -1;
static int hf_btmesh_config_composition_data_status_pid = -1;
static int hf_btmesh_config_composition_data_status_vid = -1;
static int hf_btmesh_config_composition_data_status_crpl = -1;
static int hf_btmesh_config_composition_data_status_features_relay = -1;
static int hf_btmesh_config_composition_data_status_features_proxy = -1;
static int hf_btmesh_config_composition_data_status_features_friend = -1;
static int hf_btmesh_config_composition_data_status_features_low_power = -1;
static int hf_btmesh_config_composition_data_status_features_rfu = -1;
static int hf_btmesh_config_composition_data_status_features = -1;
static int hf_btmesh_config_composition_data_status_loc = -1;
static int hf_btmesh_config_composition_data_status_nums = -1;
static int hf_btmesh_config_composition_data_status_numv = -1;
static int hf_btmesh_config_composition_data_status_sig_model = -1;
static int hf_btmesh_config_composition_data_status_vendor_model = -1;
static int hf_btmesh_config_model_publication_set_elementaddress = -1;
static int hf_btmesh_config_model_publication_set_publishaddress = -1;
static int hf_btmesh_config_model_publication_set_appkey = -1;
static int hf_btmesh_config_model_publication_set_appkeyindex = -1;
static int hf_btmesh_config_model_publication_set_credentialflag = -1;
static int hf_btmesh_config_model_publication_set_rfu = -1;
static int hf_btmesh_config_model_publication_set_publishttl = -1;
static int hf_btmesh_config_model_publication_set_publishperiod = -1;
static int hf_btmesh_config_model_publication_set_publishperiod_resolution = -1;
static int hf_btmesh_config_model_publication_set_publishperiod_steps = -1;
static int hf_btmesh_config_model_publication_set_publishretransmit = -1;
static int hf_btmesh_config_model_publication_set_publishretransmit_count = -1;
static int hf_btmesh_config_model_publication_set_publishretransmit_intervalsteps = -1;
static int hf_btmesh_config_model_publication_set_modelidentifier = -1;
static int hf_btmesh_config_model_publication_set_vendormodelidentifier = -1;
static int hf_btmesh_health_current_status_test_id = -1;
static int hf_btmesh_health_current_status_company_id = -1;
static int hf_btmesh_health_current_status_fault = -1;
static int hf_btmesh_health_fault_status_test_id = -1;
static int hf_btmesh_health_fault_status_company_id = -1;
static int hf_btmesh_health_fault_status_fault = -1;
static int hf_btmesh_config_heartbeat_publication_status_status = -1;
static int hf_btmesh_config_heartbeat_publication_status_destination = -1;
static int hf_btmesh_config_heartbeat_publication_status_countlog = -1;
static int hf_btmesh_config_heartbeat_publication_status_periodlog = -1;
static int hf_btmesh_config_heartbeat_publication_status_ttl = -1;
static int hf_btmesh_config_heartbeat_publication_status_features_relay = -1;
static int hf_btmesh_config_heartbeat_publication_status_features_proxy = -1;
static int hf_btmesh_config_heartbeat_publication_status_features_friend = -1;
static int hf_btmesh_config_heartbeat_publication_status_features_low_power = -1;
static int hf_btmesh_config_heartbeat_publication_status_features_rfu = -1;
static int hf_btmesh_config_heartbeat_publication_status_features = -1;
static int hf_btmesh_config_heartbeat_publication_status_netkeyindex = -1;
static int hf_btmesh_config_heartbeat_publication_status_netkeyindex_idx = -1;
static int hf_btmesh_config_heartbeat_publication_status_netkeyindex_rfu = -1;
static int hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex = -1;
static int hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_net = -1;
static int hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_app = -1;
static int hf_btmesh_config_appkey_get_netkeyindex = -1;
static int hf_btmesh_config_appkey_get_netkeyindex_idx = -1;
static int hf_btmesh_config_appkey_get_netkeyindex_rfu = -1;
static int hf_btmesh_config_appkey_list_status = -1;
static int hf_btmesh_config_appkey_list_netkeyindex = -1;
static int hf_btmesh_config_appkey_list_netkeyindex_idx = -1;
static int hf_btmesh_config_appkey_list_netkeyindex_rfu = -1;
static int hf_btmesh_config_appkey_list_appkeyindex = -1;
static int hf_btmesh_config_appkey_list_appkeyindex_rfu = -1;
static int hf_btmesh_config_appkey_status_status = -1;
static int hf_btmesh_config_appkey_status_netkeyindexandappkeyindex = -1;
static int hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_net = -1;
static int hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_app = -1;
static int hf_btmesh_health_attention_set_attention = -1;
static int hf_btmesh_health_attention_set_unacknowledged_attention = -1;
static int hf_btmesh_health_attention_status_attention = -1;
static int hf_btmesh_config_composition_data_get_page = -1;
static int hf_btmesh_config_beacon_set_beacon = -1;
static int hf_btmesh_config_beacon_status_beacon = -1;
static int hf_btmesh_config_default_ttl_set_ttl = -1;
static int hf_btmesh_config_default_ttl_status_ttl = -1;
static int hf_btmesh_config_friend_set_friend = -1;
static int hf_btmesh_config_friend_status_friend = -1;
static int hf_btmesh_config_gatt_proxy_set_gattproxy = -1;
static int hf_btmesh_config_gatt_proxy_status_gattproxy = -1;
static int hf_btmesh_config_key_refresh_phase_get_netkeyindex = -1;
static int hf_btmesh_config_key_refresh_phase_get_netkeyindex_idx = -1;
static int hf_btmesh_config_key_refresh_phase_get_netkeyindex_rfu = -1;
static int hf_btmesh_config_key_refresh_phase_set_netkeyindex = -1;
static int hf_btmesh_config_key_refresh_phase_set_netkeyindex_idx = -1;
static int hf_btmesh_config_key_refresh_phase_set_netkeyindex_rfu = -1;
static int hf_btmesh_config_key_refresh_phase_set_transition = -1;
static int hf_btmesh_config_key_refresh_phase_status_status = -1;
static int hf_btmesh_config_key_refresh_phase_status_netkeyindex = -1;
static int hf_btmesh_config_key_refresh_phase_status_netkeyindex_idx = -1;
static int hf_btmesh_config_key_refresh_phase_status_netkeyindex_rfu = -1;
static int hf_btmesh_config_key_refresh_phase_status_phase = -1;
static int hf_btmesh_config_model_publication_get_elementaddress = -1;
static int hf_btmesh_config_model_publication_get_modelidentifier = -1;
static int hf_btmesh_config_model_publication_get_vendormodelidentifier = -1;
static int hf_btmesh_config_model_publication_status_status = -1;
static int hf_btmesh_config_model_publication_status_elementaddress = -1;
static int hf_btmesh_config_model_publication_status_publishaddress = -1;
static int hf_btmesh_config_model_publication_status_appkey = -1;
static int hf_btmesh_config_model_publication_status_appkeyindex = -1;
static int hf_btmesh_config_model_publication_status_credentialflag = -1;
static int hf_btmesh_config_model_publication_status_rfu = -1;
static int hf_btmesh_config_model_publication_status_publishttl = -1;
static int hf_btmesh_config_model_publication_status_publishperiod = -1;
static int hf_btmesh_config_model_publication_status_publishperiod_resolution = -1;
static int hf_btmesh_config_model_publication_status_publishperiod_steps = -1;
static int hf_btmesh_config_model_publication_status_publishretransmit = -1;
static int hf_btmesh_config_model_publication_status_publishretransmit_count = -1;
static int hf_btmesh_config_model_publication_status_publishretransmit_intervalsteps = -1;
static int hf_btmesh_config_model_publication_status_modelidentifier = -1;
static int hf_btmesh_config_model_publication_status_vendormodelidentifier = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_elementaddress = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishaddress = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_appkey = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_appkeyindex = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_credentialflag = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_rfu = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishttl = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishperiod = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishperiod_resolution = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishperiod_steps = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishretransmit = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_count = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_intervalsteps = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_modelidentifier = -1;
static int hf_btmesh_config_model_publication_virtual_address_set_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_add_elementaddress = -1;
static int hf_btmesh_config_model_subscription_add_address = -1;
static int hf_btmesh_config_model_subscription_add_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_add_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_delete_elementaddress = -1;
static int hf_btmesh_config_model_subscription_delete_address = -1;
static int hf_btmesh_config_model_subscription_delete_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_delete_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_delete_all_elementaddress = -1;
static int hf_btmesh_config_model_subscription_delete_all_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_delete_all_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_overwrite_elementaddress = -1;
static int hf_btmesh_config_model_subscription_overwrite_address = -1;
static int hf_btmesh_config_model_subscription_overwrite_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_overwrite_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_status_status = -1;
static int hf_btmesh_config_model_subscription_status_elementaddress = -1;
static int hf_btmesh_config_model_subscription_status_address = -1;
static int hf_btmesh_config_model_subscription_status_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_status_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_virtual_address_add_elementaddress = -1;
static int hf_btmesh_config_model_subscription_virtual_address_add_label = -1;
static int hf_btmesh_config_model_subscription_virtual_address_add_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_virtual_address_add_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_virtual_address_delete_elementaddress = -1;
static int hf_btmesh_config_model_subscription_virtual_address_delete_label = -1;
static int hf_btmesh_config_model_subscription_virtual_address_delete_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_virtual_address_delete_vendormodelidentifier = -1;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_elementaddress = -1;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_label = -1;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_modelidentifier = -1;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_vendormodelidentifier = -1;
static int hf_btmesh_config_network_transmit_set_networktransmit = -1;
static int hf_btmesh_config_network_transmit_set_networktransmit_count = -1;
static int hf_btmesh_config_network_transmit_set_networktransmit_intervalsteps = -1;
static int hf_btmesh_config_network_transmit_status_networktransmit = -1;
static int hf_btmesh_config_network_transmit_status_networktransmit_count = -1;
static int hf_btmesh_config_network_transmit_status_networktransmit_intervalsteps = -1;
static int hf_btmesh_config_relay_set_relay = -1;
static int hf_btmesh_config_relay_set_relayretransmit = -1;
static int hf_btmesh_config_relay_set_relayretransmit_count = -1;
static int hf_btmesh_config_relay_set_relayretransmit_intervalsteps = -1;
static int hf_btmesh_config_relay_status_relay = -1;
static int hf_btmesh_config_relay_status_relayretransmit = -1;
static int hf_btmesh_config_relay_status_relayretransmit_count = -1;
static int hf_btmesh_config_relay_status_relayretransmit_intervalsteps = -1;
static int hf_btmesh_config_sig_model_subscription_get_elementaddress = -1;
static int hf_btmesh_config_sig_model_subscription_get_modelidentifier = -1;
static int hf_btmesh_config_sig_model_subscription_list_status = -1;
static int hf_btmesh_config_sig_model_subscription_list_elementaddress = -1;
static int hf_btmesh_config_sig_model_subscription_list_modelidentifier = -1;
static int hf_btmesh_config_sig_model_subscription_list_address = -1;
static int hf_btmesh_config_vendor_model_subscription_get_elementaddress = -1;
static int hf_btmesh_config_vendor_model_subscription_get_modelidentifier = -1;
static int hf_btmesh_config_vendor_model_subscription_list_status = -1;
static int hf_btmesh_config_vendor_model_subscription_list_elementaddress = -1;
static int hf_btmesh_config_vendor_model_subscription_list_modelidentifier = -1;
static int hf_btmesh_config_vendor_model_subscription_list_address = -1;
static int hf_btmesh_config_low_power_node_polltimeout_get_lpnaddress = -1;
static int hf_btmesh_config_low_power_node_polltimeout_status_lpnaddress = -1;
static int hf_btmesh_config_low_power_node_polltimeout_status_polltimeout = -1;
static int hf_btmesh_health_fault_clear_company_id = -1;
static int hf_btmesh_health_fault_clear_unacknowledged_company_id = -1;
static int hf_btmesh_health_fault_get_company_id = -1;
static int hf_btmesh_health_fault_test_test_id = -1;
static int hf_btmesh_health_fault_test_company_id = -1;
static int hf_btmesh_health_fault_test_unacknowledged_test_id = -1;
static int hf_btmesh_health_fault_test_unacknowledged_company_id = -1;
static int hf_btmesh_health_period_set_fastperioddivisor = -1;
static int hf_btmesh_health_period_set_unacknowledged_fastperioddivisor = -1;
static int hf_btmesh_health_period_status_fastperioddivisor = -1;
static int hf_btmesh_config_heartbeat_publication_set_destination = -1;
static int hf_btmesh_config_heartbeat_publication_set_countlog = -1;
static int hf_btmesh_config_heartbeat_publication_set_periodlog = -1;
static int hf_btmesh_config_heartbeat_publication_set_ttl = -1;
static int hf_btmesh_config_heartbeat_publication_set_features_relay = -1;
static int hf_btmesh_config_heartbeat_publication_set_features_proxy = -1;
static int hf_btmesh_config_heartbeat_publication_set_features_friend = -1;
static int hf_btmesh_config_heartbeat_publication_set_features_low_power = -1;
static int hf_btmesh_config_heartbeat_publication_set_features_rfu = -1;
static int hf_btmesh_config_heartbeat_publication_set_features = -1;
static int hf_btmesh_config_heartbeat_publication_set_netkeyindex = -1;
static int hf_btmesh_config_heartbeat_publication_set_netkeyindex_idx = -1;
static int hf_btmesh_config_heartbeat_publication_set_netkeyindex_rfu = -1;
static int hf_btmesh_config_heartbeat_subscription_set_source = -1;
static int hf_btmesh_config_heartbeat_subscription_set_destination = -1;
static int hf_btmesh_config_heartbeat_subscription_set_periodlog = -1;
static int hf_btmesh_config_heartbeat_subscription_status_status = -1;
static int hf_btmesh_config_heartbeat_subscription_status_source = -1;
static int hf_btmesh_config_heartbeat_subscription_status_destination = -1;
static int hf_btmesh_config_heartbeat_subscription_status_periodlog = -1;
static int hf_btmesh_config_heartbeat_subscription_status_countlog = -1;
static int hf_btmesh_config_heartbeat_subscription_status_minhops = -1;
static int hf_btmesh_config_heartbeat_subscription_status_maxhops = -1;
static int hf_btmesh_config_model_app_bind_elementaddress = -1;
static int hf_btmesh_config_model_app_bind_appkeyindex = -1;
static int hf_btmesh_config_model_app_bind_appkeyindex_idx = -1;
static int hf_btmesh_config_model_app_bind_appkeyindex_rfu = -1;
static int hf_btmesh_config_model_app_bind_modelidentifier = -1;
static int hf_btmesh_config_model_app_bind_vendormodelidentifier = -1;
static int hf_btmesh_config_model_app_status_status = -1;
static int hf_btmesh_config_model_app_status_elementaddress = -1;
static int hf_btmesh_config_model_app_status_appkeyindex = -1;
static int hf_btmesh_config_model_app_status_appkeyindex_idx = -1;
static int hf_btmesh_config_model_app_status_appkeyindex_rfu = -1;
static int hf_btmesh_config_model_app_status_modelidentifier = -1;
static int hf_btmesh_config_model_app_status_vendormodelidentifier = -1;
static int hf_btmesh_config_model_app_unbind_elementaddress = -1;
static int hf_btmesh_config_model_app_unbind_appkeyindex = -1;
static int hf_btmesh_config_model_app_unbind_appkeyindex_idx = -1;
static int hf_btmesh_config_model_app_unbind_appkeyindex_rfu = -1;
static int hf_btmesh_config_model_app_unbind_modelidentifier = -1;
static int hf_btmesh_config_model_app_unbind_vendormodelidentifier = -1;
static int hf_btmesh_config_netkey_add_netkeyindex = -1;
static int hf_btmesh_config_netkey_add_netkeyindex_idx = -1;
static int hf_btmesh_config_netkey_add_netkeyindex_rfu = -1;
static int hf_btmesh_config_netkey_add_netkey = -1;
static int hf_btmesh_config_netkey_delete_netkeyindex = -1;
static int hf_btmesh_config_netkey_delete_netkeyindex_idx = -1;
static int hf_btmesh_config_netkey_delete_netkeyindex_rfu = -1;
static int hf_btmesh_config_netkey_list_netkeyindex = -1;
static int hf_btmesh_config_netkey_list_netkeyindex_rfu = -1;
static int hf_btmesh_config_netkey_status_status = -1;
static int hf_btmesh_config_netkey_status_netkeyindex = -1;
static int hf_btmesh_config_netkey_status_netkeyindex_idx = -1;
static int hf_btmesh_config_netkey_status_netkeyindex_rfu = -1;
static int hf_btmesh_config_netkey_update_netkeyindex = -1;
static int hf_btmesh_config_netkey_update_netkeyindex_idx = -1;
static int hf_btmesh_config_netkey_update_netkeyindex_rfu = -1;
static int hf_btmesh_config_netkey_update_netkey = -1;
static int hf_btmesh_config_node_identity_get_netkeyindex = -1;
static int hf_btmesh_config_node_identity_get_netkeyindex_idx = -1;
static int hf_btmesh_config_node_identity_get_netkeyindex_rfu = -1;
static int hf_btmesh_config_node_identity_set_netkeyindex = -1;
static int hf_btmesh_config_node_identity_set_netkeyindex_idx = -1;
static int hf_btmesh_config_node_identity_set_netkeyindex_rfu = -1;
static int hf_btmesh_config_node_identity_set_identity = -1;
static int hf_btmesh_config_node_identity_status_status = -1;
static int hf_btmesh_config_node_identity_status_netkeyindex = -1;
static int hf_btmesh_config_node_identity_status_netkeyindex_idx = -1;
static int hf_btmesh_config_node_identity_status_netkeyindex_rfu = -1;
static int hf_btmesh_config_node_identity_status_identity = -1;
static int hf_btmesh_config_sig_model_app_get_elementaddress = -1;
static int hf_btmesh_config_sig_model_app_get_modelidentifier = -1;
static int hf_btmesh_config_sig_model_app_list_status = -1;
static int hf_btmesh_config_sig_model_app_list_elementaddress = -1;
static int hf_btmesh_config_sig_model_app_list_modelidentifier = -1;
static int hf_btmesh_config_sig_model_app_list_appkeyindex = -1;
static int hf_btmesh_config_sig_model_app_list_appkeyindex_rfu = -1;
static int hf_btmesh_config_vendor_model_app_get_elementaddress = -1;
static int hf_btmesh_config_vendor_model_app_get_modelidentifier = -1;
static int hf_btmesh_config_vendor_model_app_list_status = -1;
static int hf_btmesh_config_vendor_model_app_list_elementaddress = -1;
static int hf_btmesh_config_vendor_model_app_list_modelidentifier = -1;
static int hf_btmesh_config_vendor_model_app_list_appkeyindex = -1;
static int hf_btmesh_config_vendor_model_app_list_appkeyindex_rfu = -1;

static int ett_btmesh = -1;
static int ett_btmesh_net_pdu = -1;
static int ett_btmesh_transp_pdu = -1;
static int ett_btmesh_transp_ctrl_msg = -1;
static int ett_btmesh_upper_transp_acc_pdu = -1;
static int ett_btmesh_segmented_access_fragments = -1;
static int ett_btmesh_segmented_access_fragment = -1;
static int ett_btmesh_segmented_control_fragments = -1;
static int ett_btmesh_segmented_control_fragment = -1;
static int ett_btmesh_access_pdu = -1;
static int ett_btmesh_model_layer = -1;

static int ett_btmesh_config_model_netapp_index = -1;
static int ett_btmesh_config_model_publishperiod = -1;
static int ett_btmesh_config_model_publishretransmit = -1;
static int ett_btmesh_config_model_relayretransmit = -1;
static int ett_btmesh_config_model_network_transmit = -1;
static int ett_btmesh_config_model_element = -1;
static int ett_btmesh_config_model_model = -1;
static int ett_btmesh_config_model_vendor = -1;
static int ett_btmesh_config_composition_data_status_features = -1;
static int ett_btmesh_config_model_pub_app_index = -1;
static int ett_btmesh_config_model_addresses = -1;
static int ett_btmesh_config_model_netkey_list = -1;
static int ett_btmesh_config_model_appkey_list = -1;
static int ett_btmesh_config_model_net_index = -1;
static int ett_btmesh_config_model_app_index = -1;
static int ett_btmesh_config_heartbeat_publication_set_features = -1;
static int ett_btmesh_config_heartbeat_publication_status_features = -1;
static int ett_btmesh_config_model_fault_array = -1;

static expert_field ei_btmesh_not_decoded_yet = EI_INIT;
static expert_field ei_btmesh_unknown_payload = EI_INIT;

static const value_string btmesh_ctl_vals[] = {
    { 0, "Access Message" },
    { 1, "Control Message" },
    { 0, NULL }
};

static const value_string btmesh_ctrl_seg_vals[] = {
    { 0, "Unsegmented Control Message" },
    { 1, "Segmented Control Message" },
    { 0, NULL }
};

static const value_string btmesh_acc_seg_vals[] = {
    { 0, "Unsegmented Access Message" },
    { 1, "Segmented Access Message" },
    { 0, NULL }
};

static const value_string btmesh_acc_akf_vals[] = {
    { 0, "Device key" },
    { 1, "Application key" },
    { 0, NULL }
};

static const value_string btmesh_ctrl_opcode_vals[] = {
    { 0x0, "Segment Acknowledgment" }, /* Reserved for lower transport layer */
    { 0x1, "Friend Poll" },
    { 0x2, "Friend Update" },
    { 0x3, "Friend Request" },
    { 0x4, "Friend Offer" },
    { 0x5, "Friend Clear" },
    { 0x6, "Friend Clear Confirm" },
    { 0x7, "Friend Subscription List Add" },
    { 0x8, "Friend Subscription List Remove" },
    { 0x9, "Friend Subscription List Confirm" },
    { 0xa, "Heartbeat" },
    { 0, NULL }
};

static const value_string btmesh_cntr_key_refresh_flag_vals[] = {
    { 0x0, "Not-In-Phase2" },
    { 0x1, "In-Phase2" },
    { 0, NULL }
};

static const value_string btmesh_cntr_iv_update_flag_vals[] = {
    { 0x0, "Normal operation" },
    { 0x1, "IV Update active" },
    { 0, NULL }
};

static const value_string btmesh_cntr_md_vals[] = {
    { 0x0, "Friend Queue is empty" },
    { 0x1, "Friend Queue is not empty" },
    { 0, NULL }
};

static const true_false_string  btmesh_obo = {
    "Friend node that is acknowledging this message on behalf of a Low Power node",
    "Node that is directly addressed by the received message"
};

static const value_string btmesh_criteria_rssifactor_vals[] = {
    { 0x0, "1" },
    { 0x1, "1.5" },
    { 0x2, "2" },
    { 0x3, "2.5" },
    { 0, NULL }
};

static const value_string btmesh_criteria_receivewindowfactor_vals[] = {
    { 0x0, "1" },
    { 0x1, "1.5" },
    { 0x2, "2" },
    { 0x3, "2.5" },
    { 0, NULL }
};

static const value_string btmesh_criteria_minqueuesizelog_vals[] = {
    { 0x0, "Prohibited" },
    { 0x1, "N = 2" },
    { 0x2, "N = 4" },
    { 0x3, "N = 8" },
    { 0x4, "N = 16" },
    { 0x5, "N = 32" },
    { 0x6, "N = 64" },
    { 0x7, "N = 128" },
    { 0, NULL }
};

static const value_string btmesh_szmic_vals[] = {
    { 0x0, "32-bit" },
    { 0x1, "64-bit" },
    { 0, NULL }
};

static const value_string btmesh_models_opcode_vals[] = {
    /* Bluetooth Mesh Foundation messages */
    { 0x00, "Config AppKey Add" },
    { 0x01, "Config AppKey Update" },
    { 0x02, "Config Composition Data Status" },
    { 0x03, "Config Config Model Publication Set" },
    { 0x04, "Health Current Status" },
    { 0x05, "Health Fault Status" },
    { 0x06, "Config Heartbeat Publication Status" },
    { 0x8000, "Config AppKey Delete" },
    { 0x8001, "Config AppKey Get" },
    { 0x8002, "Config AppKey List" },
    { 0x8003, "Config AppKey Status" },
    { 0x8004, "Health Attention Get" },
    { 0x8005, "Health Attention Set" },
    { 0x8006, "Health Attention Set Unacknowledged" },
    { 0x8007, "Health Attention Status" },
    { 0x8008, "Config Composition Data Get" },
    { 0x8009, "Config Beacon Get" },
    { 0x800A, "Config Beacon Set" },
    { 0x800B, "Config Beacon Status" },
    { 0x800C, "Config Default TTL Get" },
    { 0x800D, "Config Default TTL Set" },
    { 0x800E, "Config Default TTL Status" },
    { 0x800F, "Config Friend Get" },
    { 0x8010, "Config Friend Set" },
    { 0x8011, "Config Friend Status" },
    { 0x8012, "Config GATT Proxy Get" },
    { 0x8013, "Config GATT Proxy Set" },
    { 0x8014, "Config GATT Proxy Status" },
    { 0x8015, "Config Key Refresh Phase Get" },
    { 0x8016, "Config Key Refresh Phase Set" },
    { 0x8017, "Config Key Refresh Phase Status" },
    { 0x8018, "Config Model Publication Get" },
    { 0x8019, "Config Model Publication Status" },
    { 0x801A, "Config Model Publication Virtual Address Set" },
    { 0x801B, "Config Model Subscription Add" },
    { 0x801C, "Config Model Subscription Delete" },
    { 0x801D, "Config Model Subscription Delete All" },
    { 0x801E, "Config Model Subscription Overwrite" },
    { 0x801F, "Config Model Subscription Status" },
    { 0x8020, "Config Model Subscription Virtual Address Add" },
    { 0x8021, "Config Model Subscription Virtual Address Delete" },
    { 0x8022, "Config Model Subscription Virtual Address Overwrite" },
    { 0x8023, "Config Network Transmit Get" },
    { 0x8024, "Config Network Transmit Set" },
    { 0x8025, "Config Network Transmit Status" },
    { 0x8026, "Config Relay Get" },
    { 0x8027, "Config Relay Set" },
    { 0x8028, "Config Relay Status" },
    { 0x8029, "Config SIG Model Subscription Get" },
    { 0x802A, "Config SIG Model Subscription List" },
    { 0x802B, "Config Vendor Model Subscription Get" },
    { 0x802C, "Config Vendor Model Subscription List" },
    { 0x802D, "Config Low Power Node PollTimeout Get" },
    { 0x802E, "Config Low Power Node PollTimeout Status" },
    { 0x802F, "Health Fault Clear" },
    { 0x8030, "Health Fault Clear Unacknowledged" },
    { 0x8031, "Health Fault Get" },
    { 0x8032, "Health Fault Test" },
    { 0x8033, "Health Fault Test Unacknowledged" },
    { 0x8034, "Health Period Get" },
    { 0x8035, "Health Period Set" },
    { 0x8036, "Health Period Set Unacknowledged" },
    { 0x8037, "Health Period Status" },
    { 0x8038, "Config Heartbeat Publication Get" },
    { 0x8039, "Config Heartbeat Publication Set" },
    { 0x803A, "Config Heartbeat Subscription Get" },
    { 0x803B, "Config Heartbeat Subscription Set" },
    { 0x803C, "Config Heartbeat Subscription Status" },
    { 0x803D, "Config Model App Bind" },
    { 0x803E, "Config Model App Status" },
    { 0x803F, "Config Model App Unbind" },
    { 0x8040, "Config NetKey Add" },
    { 0x8041, "Config NetKey Delete" },
    { 0x8042, "Config NetKey Get" },
    { 0x8043, "Config NetKey List" },
    { 0x8044, "Config NetKey Status" },
    { 0x8045, "Config NetKey Update" },
    { 0x8046, "Config Node Identity Get" },
    { 0x8047, "Config Node Identity Set" },
    { 0x8048, "Config Node Identity Status" },
    { 0x8049, "Config Node Reset" },
    { 0x804A, "Config Node Reset Status" },
    { 0x804B, "Config SIG Model App Get" },
    { 0x804C, "Config SIG Model App List" },
    { 0x804D, "Config Vendor Model App Get" },
    { 0x804E, "Config Vendor Model App List" },

    /* Bluetooth Mesh Model messages */
    { 0x8201, "Generic OnOff Get" },
    { 0x8202, "Generic OnOff Set" },
    { 0x8203, "Generic OnOff Set Unacknowledged" },
    { 0x8204, "Generic OnOff Status" },
    { 0x8205, "Generic Level Get" },
    { 0x8206, "Generic Level Set" },
    { 0x8207, "Generic Level Set Unacknowledged" },
    { 0x8208, "Generic Level Status" },
    { 0x8209, "Generic Delta Set" },
    { 0x820A, "Generic Delta Set Unacknowledged" },
    { 0x820B, "Generic Move Set" },
    { 0x820C, "Generic Move Set Unacknowledged" },
    { 0x820D, "Generic Default Transition Time Get" },
    { 0x820E, "Generic Default Transition Time Set" },
    { 0x820F, "Generic Default Transition Time Set Unacknowledged" },
    { 0x8210, "Generic Default Transition Time Status" },
    { 0x8211, "Generic OnPowerUp Get" },
    { 0x8212, "Generic OnPowerUp Status" },
    { 0x8213, "Generic OnPowerUp Set" },
    { 0x8214, "Generic OnPowerUp Set Unacknowledged" },
    { 0x8215, "Generic Power Level Get" },
    { 0x8216, "Generic Power Level Set" },
    { 0x8217, "Generic Power Level Set Unacknowledged" },
    { 0x8218, "Generic Power Level Status" },
    { 0x8219, "Generic Power Last Get" },
    { 0x821A, "Generic Power Last Status" },
    { 0x821B, "Generic Power Default Get" },
    { 0x821C, "Generic Power Default Status" },
    { 0x821D, "Generic Power Range Get" },
    { 0x821E, "Generic Power Range Status" },
    { 0x821F, "Generic Power Default Set" },
    { 0x8220, "Generic Power Default Set Unacknowledged" },
    { 0x8221, "Generic Power Range Set" },
    { 0x8222, "Generic Power Range Set Unacknowledged" },
    { 0x8223, "Generic Battery Get" },
    { 0x8224, "Generic Battery Status" },
    { 0x8225, "Generic Location Global Get" },
    { 0x40, "Generic Location Global Status" },
    { 0x8226, "Generic Location Local Get" },
    { 0x8227, "Generic Location Local Status" },
    { 0x41, "Generic Location Global Set" },
    { 0x42, "Generic Location Global Set Unacknowledged" },
    { 0x8228, "Generic Location Local Set" },
    { 0x8229, "Generic Location Local Set Unacknowledged" },
    { 0x822A, "Generic Manufacturer Properties Get" },
    { 0x43, "Generic Manufacturer Properties Status" },
    { 0x822B, "Generic Manufacturer Property Get" },
    { 0x44, "Generic Manufacturer Property Set" },
    { 0x45, "Generic Manufacturer Property Set Unacknowledged" },
    { 0x46, "Generic Manufacturer Property Status" },
    { 0x822C, "Generic Admin Properties Get" },
    { 0x47, "Generic Admin Properties Status" },
    { 0x822D, "Generic Admin Property Get" },
    { 0x48, "Generic Admin Property Set" },
    { 0x49, "Generic Admin Property Set Unacknowledged" },
    { 0x4A, "Generic Admin Property Status" },
    { 0x822E, "Generic User Properties Get" },
    { 0x4B, "Generic User Properties Status" },
    { 0x822F, "Generic User Property Get" },
    { 0x4C, "Generic User Property Set" },
    { 0x4D, "Generic User Property Set Unacknowledged" },
    { 0x4E, "Generic User Property Status" },
    { 0x4F, "Generic Client Properties Get" },
    { 0x50, "Generic Client Properties Status" },
    { 0x8230, "Sensor Descriptor Get" },
    { 0x51, "Sensor Descriptor Status" },
    { 0x8231, "Sensor Get" },
    { 0x52, "Sensor Status" },
    { 0x8232, "Sensor Column Get" },
    { 0x53, "Sensor Column Status" },
    { 0x8233, "Sensor Series Get" },
    { 0x54, "Sensor Series Status" },
    { 0x8234, "Sensor Cadence Get" },
    { 0x55, "Sensor Cadence Set" },
    { 0x56, "Sensor Cadence Set Unacknowledged" },
    { 0x57, "Sensor Cadence Status" },
    { 0x8235, "Sensor Settings Get" },
    { 0x58, "Sensor Settings Status" },
    { 0x8236, "Sensor Setting Get" },
    { 0x59, "Sensor Setting Set" },
    { 0x5A, "Sensor Setting Set Unacknowledged" },
    { 0x5B, "Sensor Setting Status" },
    { 0x8237, "Time Get" },
    { 0x5C, "Time Set" },
    { 0x5D, "Time Status" },
    { 0x8238, "Time Role Get" },
    { 0x8239, "Time Role Set" },
    { 0x823A, "Time Role Status" },
    { 0x823B, "Time Zone Get" },
    { 0x823C, "Time Zone Set" },
    { 0x823D, "Time Zone Status" },
    { 0x823E, "TAI-UTC Delta Get" },
    { 0x823F, "TAI-UTC Delta Set" },
    { 0x8240, "TAI-UTC Delta Status" },
    { 0x8241, "Scene Get" },
    { 0x8242, "Scene Recall" },
    { 0x8243, "Scene Recall Unacknowledged" },
    { 0x5E, "Scene Status" },
    { 0x8244, "Scene Register Get" },
    { 0x8245, "Scene Register Status" },
    { 0x8246, "Scene Store" },
    { 0x8247, "Scene Store Unacknowledged" },
    { 0x829E, "Scene Delete" },
    { 0x829F, "Scene Delete Unacknowledged" },
    { 0x8248, "Scheduler Action Get" },
    { 0x5F, "Scheduler Action Status" },
    { 0x8249, "Scheduler Get" },
    { 0x824A, "Scheduler Status" },
    { 0x60, "Scheduler Action Set" },
    { 0x61, "Scheduler Action Set Unacknowledged" },
    { 0x824B, "Light Lightness Light Lightness Get" },
    { 0x824C, "Light Lightness Set" },
    { 0x824D, "Light Lightness Set Unacknowledged" },
    { 0x824E, "Light Lightness Status" },
    { 0x824F, "Light Lightness Linear Get" },
    { 0x8250, "Light Lightness Linear Set" },
    { 0x8251, "Light Lightness Linear Set Unacknowledged" },
    { 0x8252, "Light Lightness Linear Status" },
    { 0x8253, "Light Lightness Last Get" },
    { 0x8254, "Light Lightness Last Status" },
    { 0x8255, "Light Lightness Default Get" },
    { 0x8256, "Light Lightness Default Status" },
    { 0x8257, "Light Lightness Range Get" },
    { 0x8258, "Light Lightness Range Status" },
    { 0x8259, "Light Lightness Default Set" },
    { 0x825A, "Light Lightness Default Set Unacknowledged" },
    { 0x825B, "Light Lightness Range Set" },
    { 0x825C, "Light Lightness Range Set Unacknowledged" },
    { 0x825D, "Light CTL Get" },
    { 0x825E, "Light CTL Set" },
    { 0x825F, "Light CTL Set Unacknowledged" },
    { 0x8260, "Light CTL Status" },
    { 0x8261, "Light CTL Temperature Get" },
    { 0x8262, "Light CTL Temperature Range Get" },
    { 0x8263, "Light CTL Temperature Range Status" },
    { 0x8264, "Light CTL Temperature Set" },
    { 0x8265, "Light CTL Temperature Set Unacknowledged" },
    { 0x8266, "Light CTL Temperature Status" },
    { 0x8267, "Light CTL Default Get" },
    { 0x8268, "Light CTL Default Status" },
    { 0x8269, "Light CTL Default Set" },
    { 0x826A, "Light CTL Default Set Unacknowledged" },
    { 0x826B, "Light CTL Temperature Range Set" },
    { 0x826C, "Light CTL Temperature Range Set Unacknowledged" },
    { 0x826D, "Light HSL Get" },
    { 0x826E, "Light HSL Hue Get" },
    { 0x826F, "Light HSL Hue Set" },
    { 0x8270, "Light HSL Hue Set Unacknowledged" },
    { 0x8271, "Light HSL Hue Status" },
    { 0x8272, "Light HSL Saturation Get" },
    { 0x8273, "Light HSL Saturation Set" },
    { 0x8274, "Light HSL Saturation Set Unacknowledged" },
    { 0x8275, "Light HSL Saturation Status" },
    { 0x8276, "Light HSL Set" },
    { 0x8277, "Light HSL Set Unacknowledged" },
    { 0x8278, "Light HSL Status" },
    { 0x8279, "Light HSL Target Get" },
    { 0x827A, "Light HSL Target Status" },
    { 0x827B, "Light HSL Default Get" },
    { 0x827C, "Light HSL Default Status" },
    { 0x827D, "Light HSL Range Get" },
    { 0x827E, "Light HSL Range Status" },
    { 0x827F, "Light HSL Default Set" },
    { 0x8280, "Light HSL Default Set Unacknowledged" },
    { 0x8281, "Light HSL Range Set" },
    { 0x8282, "Light HSL Range Set Unacknowledged" },
    { 0x8283, "Light xyL Get" },
    { 0x8284, "Light xyL Set" },
    { 0x8285, "Light xyL Set Unacknowledged" },
    { 0x8286, "Light xyL Status" },
    { 0x8287, "Light xyL Target Get" },
    { 0x8288, "Light xyL Target Status" },
    { 0x8289, "Light xyL Default Get" },
    { 0x828A, "Light xyL Default Status" },
    { 0x828B, "Light xyL Range Get" },
    { 0x828C, "Light xyL Range Status" },
    { 0x828D, "Light xyL Default Set" },
    { 0x828E, "Light xyL Default Set Unacknowledged" },
    { 0x828F, "Light xyL Range Set" },
    { 0x8290, "Light xyL Range Set Unacknowledged" },
    { 0x8291, "Light LC Mode Get" },
    { 0x8292, "Light LC Mode Set" },
    { 0x8293, "Light LC Mode Set Unacknowledged" },
    { 0x8294, "Light LC Mode Status" },
    { 0x8295, "Light LC OM Get" },
    { 0x8296, "Light LC OM Set" },
    { 0x8297, "Light LC OM Set Unacknowledged" },
    { 0x8298, "Light LC OM Status" },
    { 0x8299, "Light LC Light OnOff Get" },
    { 0x829A, "Light LC Light OnOff Set" },
    { 0x829B, "Light LC Light OnOff Set Unacknowledged" },
    { 0x829C, "Light LC Light OnOff Status" },
    { 0x829D, "Light LC Property Get" },
    { 0x62, "Light LC Property Set" },
    { 0x63, "Light LC Property Set Unacknowledged" },
    { 0x64, "Light LC Property Status" },
    { 0, NULL }
};

static const value_string btmesh_beacon_broadcast_vals[] = {
    { 0x00, "Not broadcasting a Secure Network beacon" },
    { 0x01, "Broadcasting a Secure Network beacon" },
    { 0, NULL }
};

static const value_string btmesh_gatt_proxy_vals[] = {
    { 0x00, "Proxy feature is supported and disabled" },
    { 0x01, "Proxy feature is supported and enabled" },
    { 0x02, "Proxy feature is not supported" },
    { 0, NULL }
};

static const value_string btmesh_relay_vals[] = {
    { 0x00, "Relay feature is supported and disabled" },
    { 0x01, "Relay feature is supported and enabled" },
    { 0x02, "Relay feature is not supported" },
    { 0, NULL }
};

static const value_string btmesh_friend_vals[] = {
    { 0x00, "Friend feature is supported and disabled" },
    { 0x01, "Friend feature is supported and enabled" },
    { 0x02, "Friend feature is not supported" },
    { 0, NULL }
};

static const value_string btmesh_publishperiod_resolution_vals[] = {
    { 0x00, "100 milliseconds" },
    { 0x01, "1 second" },
    { 0x02, "10 seconds" },
    { 0x03, "10 minutes" },
    { 0, NULL }
};

static const value_string btmesh_friendship_credentials_flag_vals[] = {
    { 0x00, "Master security material is used" },
    { 0x01, "Friendship security material is used" },
    { 0, NULL }
};

static const value_string btmesh_phase_vals[] = {
    { 0x00, "Normal operation" },
    { 0x01, "First phase of Key Refresh procedure" },
    { 0x02, "Second phase of Key Refresh procedure" },
    { 0, NULL }
};

static const range_string btmesh_transition_vals[] = {
    { 0x00, 0x01, "Prohibited" },
    { 0x02, 0x02, "Transition 2" },
    { 0x03, 0x03, "Transition 3" },
    { 0x04, 0xFF, "Prohibited" },
    { 0, 0, NULL }
};

static const value_string btmesh_fault_array_vals[] = {
    { 0x00, "No Fault" },
    { 0x01, "Battery Low Warning" },
    { 0x02, "Battery Low Error" },
    { 0x03, "Supply Voltage Too Low Warning" },
    { 0x04, "Supply Voltage Too Low Error" },
    { 0x05, "Supply Voltage Too High Warning" },
    { 0x06, "Supply Voltage Too High Error" },
    { 0x07, "Power Supply Interrupted Warning" },
    { 0x08, "Power Supply Interrupted Error" },
    { 0x09, "No Load Warning" },
    { 0x0A, "No Load Error" },
    { 0x0B, "Overload Warning" },
    { 0x0C, "Overload Error" },
    { 0x0D, "Overheat Warning" },
    { 0x0E, "Overheat Error" },
    { 0x0F, "Condensation Warning" },
    { 0x10, "Condensation Error" },
    { 0x11, "Vibration Warning" },
    { 0x12, "Vibration Error" },
    { 0x13, "Configuration Warning" },
    { 0x14, "Configuration Error" },
    { 0x15, "Element Not Calibrated Warning" },
    { 0x16, "Element Not Calibrated Error" },
    { 0x17, "Memory Warning" },
    { 0x18, "Memory Error" },
    { 0x19, "Self-Test Warning" },
    { 0x1A, "Self-Test Error" },
    { 0x1B, "Input Too Low Warning" },
    { 0x1C, "Input Too Low Error" },
    { 0x1D, "Input Too High Warning" },
    { 0x1E, "Input Too High Error" },
    { 0x1F, "Input No Change Warning" },
    { 0x20, "Input No Change Error" },
    { 0x21, "Actuator Blocked Warning" },
    { 0x22, "Actuator Blocked Error" },
    { 0x23, "Housing Opened Warning" },
    { 0x24, "Housing Opened Error" },
    { 0x25, "Tamper Warning" },
    { 0x26, "Tamper Error" },
    { 0x27, "Device Moved Warning" },
    { 0x28, "Device Moved Error" },
    { 0x29, "Device Dropped Warning" },
    { 0x2A, "Device Dropped Error" },
    { 0x2B, "Overflow Warning" },
    { 0x2C, "Overflow Error" },
    { 0x2D, "Empty Warning" },
    { 0x2E, "Empty Error" },
    { 0x2F, "Internal Bus Warning" },
    { 0x30, "Internal Bus Error" },
    { 0x31, "Mechanism Jammed Warning" },
    { 0x32, "Mechanism Jammed Error" },
    { 0, NULL }
};

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */

static int * const config_composition_data_status_features_headers[] = {
    &hf_btmesh_config_composition_data_status_features_relay,
    &hf_btmesh_config_composition_data_status_features_proxy,
    &hf_btmesh_config_composition_data_status_features_friend,
    &hf_btmesh_config_composition_data_status_features_low_power,
    &hf_btmesh_config_composition_data_status_features_rfu,
    NULL
};

static int * const config_heartbeat_publication_set_features_headers[] = {
    &hf_btmesh_config_heartbeat_publication_set_features_relay,
    &hf_btmesh_config_heartbeat_publication_set_features_proxy,
    &hf_btmesh_config_heartbeat_publication_set_features_friend,
    &hf_btmesh_config_heartbeat_publication_set_features_low_power,
    &hf_btmesh_config_heartbeat_publication_set_features_rfu,
    NULL
};

static int * const config_heartbeat_publication_status_features_headers[] = {
    &hf_btmesh_config_heartbeat_publication_status_features_relay,
    &hf_btmesh_config_heartbeat_publication_status_features_proxy,
    &hf_btmesh_config_heartbeat_publication_status_features_friend,
    &hf_btmesh_config_heartbeat_publication_status_features_low_power,
    &hf_btmesh_config_heartbeat_publication_status_features_rfu,
    NULL
};

#endif

static const value_string btmesh_status_code_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Invalid Address" },
    { 0x02, "Invalid Model" },
    { 0x03, "Invalid AppKey Index" },
    { 0x04, "Invalid NetKey Index" },
    { 0x05, "Insufficient Resources" },
    { 0x06, "Key Index Already Stored" },
    { 0x07, "Invalid Publish Parameters" },
    { 0x08, "Not a Subscribe Model" },
    { 0x09, "Storage Failure" },
    { 0x0A, "Feature Not Supported" },
    { 0x0B, "Cannot Update" },
    { 0x0C, "Cannot Remove" },
    { 0x0D, "Cannot Bind" },
    { 0x0E, "Temporarily Unable to Change State" },
    { 0x0F, "Cannot Set" },
    { 0x10, "Unspecified Error" },
    { 0x11, "Invalid Binding" },
    { 0, NULL }
};

static const value_string btmesh_model_vals[] = {
    { 0x0000, "Configuration Server" },
    { 0x0001, "Configuration Client" },
    { 0x0002, "Health Server" },
    { 0x0003, "Health Client" },
    { 0x1000, "Generic OnOff Server" },
    { 0x1001, "Generic OnOff Client" },
    { 0x1002, "Generic Level Server" },
    { 0x1003, "Generic Level Client" },
    { 0x1004, "Generic Default Transition Time Server" },
    { 0x1005, "Generic Default Transition Time Client" },
    { 0x1006, "Generic Power OnOff Server" },
    { 0x1007, "Generic Power OnOff Setup Server" },
    { 0x1008, "Generic Power OnOff Client" },
    { 0x1009, "Generic Power Level Server" },
    { 0x100A, "Generic Power Level Setup Server" },
    { 0x100B, "Generic Power Level Client" },
    { 0x100C, "Generic Battery Server" },
    { 0x100D, "Generic Battery Client" },
    { 0x100E, "Generic Location Server" },
    { 0x100F, "Generic Location Setup Server" },
    { 0x1010, "Generic Location Client" },
    { 0x1011, "Generic Admin Property Server" },
    { 0x1012, "Generic Manufacturer Property Server" },
    { 0x1013, "Generic User Property Server" },
    { 0x1014, "Generic Client Property Server" },
    { 0x1015, "Generic Property Clien" },
    { 0x1100, "Sensors Sensor Server" },
    { 0x1101, "Sensor Setup Server" },
    { 0x1102, "Sensor Client" },
    { 0x1200, "Time Server" },
    { 0x1201, "Time Setup Server" },
    { 0x1202, "Time Client" },
    { 0x1203, "Scene Server" },
    { 0x1204, "Scene Setup Server" },
    { 0x1205, "Scene Client" },
    { 0x1206, "Scheduler Server" },
    { 0x1207, "Scheduler Setup Server" },
    { 0x1208, "Scheduler Client" },
    { 0x1300, "Light Lightness Server" },
    { 0x1301, "Light Lightness Setup Server" },
    { 0x1302, "Light Lightness Client" },
    { 0x1303, "Light CTL Server" },
    { 0x1304, "Light CTL Setup Server" },
    { 0x1305, "Light CTL Client" },
    { 0x1306, "Light CTL Temperature Server" },
    { 0x1307, "Light HSL Server" },
    { 0x1308, "Light HSL Setup Server" },
    { 0x1309, "Light HSL Client" },
    { 0x130A, "Light HSL Hue Server" },
    { 0x130B, "Light HSL Saturation Server" },
    { 0x130C, "Light xyL Server" },
    { 0x130D, "Light xyL Setup Server" },
    { 0x130E, "Light xyL Client" },
    { 0x130F, "Light LC Server" },
    { 0x1310, "Light LC Setup Server" },
    { 0x1311, "Light LC Client" },
    { 0, NULL }
};


/* Upper Transport Message reassembly */

static reassembly_table upper_transport_reassembly_table;

static const fragment_items btmesh_segmented_access_frag_items = {
    &ett_btmesh_segmented_access_fragments,
    &ett_btmesh_segmented_access_fragment,

    &hf_btmesh_segmented_access_fragments,
    &hf_btmesh_segmented_access_fragment,
    &hf_btmesh_segmented_access_fragment_overlap,
    &hf_btmesh_segmented_access_fragment_overlap_conflict,
    &hf_btmesh_segmented_access_fragment_multiple_tails,
    &hf_btmesh_segmented_access_fragment_too_long_fragment,
    &hf_btmesh_segmented_access_fragment_error,
    &hf_btmesh_segmented_access_fragment_count,
    NULL,
    &hf_btmesh_segmented_access_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

static const fragment_items btmesh_segmented_control_frag_items = {
    &ett_btmesh_segmented_control_fragments,
    &ett_btmesh_segmented_control_fragment,

    &hf_btmesh_segmented_control_fragments,
    &hf_btmesh_segmented_control_fragment,
    &hf_btmesh_segmented_control_fragment_overlap,
    &hf_btmesh_segmented_control_fragment_overlap_conflict,
    &hf_btmesh_segmented_control_fragment_multiple_tails,
    &hf_btmesh_segmented_control_fragment_too_long_fragment,
    &hf_btmesh_segmented_control_fragment_error,
    &hf_btmesh_segmented_control_fragment_count,
    NULL,
    &hf_btmesh_segmented_control_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

typedef struct _upper_transport_fragment_key {
    guint16 src;
    guint16 seq0;
} upper_transport_fragment_key;

static guint
upper_transport_fragment_hash(gconstpointer k)
{
    const upper_transport_fragment_key* key = (const upper_transport_fragment_key*) k;
    guint hash_val;

    hash_val = key->src;
    hash_val += ( ((guint)key->seq0) << 16);
    return hash_val;
}

static gint
upper_transport_fragment_equal(gconstpointer k1, gconstpointer k2)
{
    const upper_transport_fragment_key* key1 = (const upper_transport_fragment_key*) k1;
    const upper_transport_fragment_key* key2 = (const upper_transport_fragment_key*) k2;

    return ((key1->src == key2->src) && (key1->seq0 == key2->seq0)
            ? TRUE : FALSE);
}

static void *
upper_transport_fragment_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_,
                              const void *data)
{
    upper_transport_fragment_key *key = g_slice_new(upper_transport_fragment_key);
    const upper_transport_fragment_key *pkt = (const upper_transport_fragment_key *)data;

    key->src = pkt->src;
    key->seq0 = pkt->seq0;

    return key;
}

static void
upper_transport_fragment_free_temporary_key(gpointer ptr)
{
    upper_transport_fragment_key *key = (upper_transport_fragment_key *)ptr;

    g_slice_free(upper_transport_fragment_key, key);
}

static void *
upper_transport_fragment_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_,
                              const void *data)
{
    upper_transport_fragment_key *key = g_slice_new(upper_transport_fragment_key);
    const upper_transport_fragment_key *pkt = (const upper_transport_fragment_key *)data;

    key->src = pkt->src;
    key->seq0 = pkt->seq0;

    return key;
}

static void
upper_transport_fragment_free_persistent_key(gpointer ptr)
{
    upper_transport_fragment_key *key = (upper_transport_fragment_key *)ptr;
    if (key) {
        g_slice_free(upper_transport_fragment_key, key);
    }
}

static const reassembly_table_functions upper_transport_reassembly_table_functions = {
    upper_transport_fragment_hash,
    upper_transport_fragment_equal,
    upper_transport_fragment_temporary_key,
    upper_transport_fragment_persistent_key,
    upper_transport_fragment_free_temporary_key,
    upper_transport_fragment_free_persistent_key
};

static void
upper_transport_init_routine(void)
{
    reassembly_table_register(&upper_transport_reassembly_table, &upper_transport_reassembly_table_functions);
}

/* A BT Mesh dissector is not realy useful without decryption as all packets are encrypted. Just leave a stub dissector outside of */
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */

/* BT Mesh s1 function */
static gboolean
s1(guint8 *m, size_t mlen, guint8 *salt)
{

    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;
    size_t read_digest_length = 16;
    guint8  zero[16] = { 0 };

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &zero, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, m, mlen);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, salt, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return TRUE;
}

/* BT Mesh Labebl UUID hash function
 *
 * SALT = s1 ("vtad")
 * hash = AES-CMAC(SALT, Label UUID) mod 2(pow)14
 *
 */
static gboolean
label_uuid_hash(uat_btmesh_label_uuid_record_t *label_uuid_record)
{
    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;
    guint8 vtad[4] = { 'v', 't', 'a', 'd' };
    size_t mlen = 4;
    guint8 salt[16];
    guint8 hash[16];
    size_t read_digest_length = 16;

    if (label_uuid_record->label_uuid_length != 16) {
        return FALSE;
    }

    /* SALT = s1("vtad") */
    if (s1(vtad, mlen, salt) == FALSE) {
        return FALSE;
    }

    /* hash = AES-CMAC(SALT, Label UUID) */
    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &salt, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, label_uuid_record->label_uuid, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, hash, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    label_uuid_record->hash = hash[15] + ((guint16)(hash[14] & 0x3f) << 8) + 0x8000;

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return TRUE;
}

/* BT Mesh K2 function
 * Allow plen up to 9 char
 *
 * The key (T) is computed as follows:
 * T = AES-CMACSALT (N)
 * SALT is the 128-bit value computed as follows
 * SALT = s1("smk2")
 * The output of the key generation function k2 is as follows:
 * T0 = empty string (zero length)
 * T1 = AES-CMACT (T0 || P || 0x01)
 * T2 = AES-CMACT (T1 || P || 0x02)
 * T3 = AES-CMACT (T2 || P || 0x03)
 * k2(N, P) = (T1 || T2 || T3) mod 2(pow)263
 */
static gboolean
k2(uat_btmesh_record_t * net_key_set, guint8 *p, size_t plen)
{
    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;
    guint8 smk2[4] = { 's', 'm', 'k', '2' };
    size_t mlen = 4;
    guint8 salt[16];
    guint8 t[16];
    guint8 t1[16];
    guint8 p_t1[9 + 1];
    guint8 p_t2[16 + 9 + 1];
    guint8 p_t3[16 + 9 + 1];

    size_t read_digest_length = 16;

    if (plen > 8) {
        return FALSE;
    }

    if (net_key_set->network_key_length != 16) {
        return FALSE;
    }

    /* SALT = s1("smk2") */
    if (s1(smk2, mlen, salt) == FALSE) {
        return FALSE;
    }

    /* T = AES-CMAC_SALT(N) */
    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &salt, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, net_key_set->network_key, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    /*
     * T0 = empty string (zero length)
     * T1 = AES-CMAC_T(T0 || P || 0x01)
     */
    memcpy(p_t1, p, plen);
    p_t1[plen] = 0x01;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &p_t1, plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t1, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }
    net_key_set->nid = (t1[15] & 0x7f);
    /*
     * T2 = AES-CMAC_T(T1 || P || 0x02)
     * (EncryptionKey)
     */

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    memcpy(p_t2, t1, 16);
    memcpy(&p_t2[16], p, plen);
    p_t2[16 + plen] = 0x02;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &p_t2, 16 + plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, net_key_set->encryptionkey, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    /* T3 = AES-CMAC_T(T2 || P || 0x03) */
    /* PrivacyKey */
    memcpy(p_t3, net_key_set->encryptionkey, 16);
    memcpy(&p_t3[16], p, plen);
    p_t3[16 + plen] = 0x03;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, p_t3, 16 + plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, net_key_set->privacykey, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return TRUE;
}

/* BT Mesh K4 function

   The inputs to function k4 is:
   N is 128 bits

   The key (T) is computed as follows:
   T = AES-CMAC (SALT, N)

   SALT is the 128-bit value computed as follows:
   SALT = s1("smk4")

   The output of the derivation function k4 is as follows:
   K4(N) = AES-CMAC (T, "id6" || 0x01 ) mod 2(pow)6
*/

static gboolean
k4(uat_btmesh_record_t *key_set)
{
    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;

    guint8 smk4[4] = { 's', 'm', 'k', '4' };
    size_t mlen = 4;
    guint8 id6[4] = { 'i', 'd', '6', 0x01 };
    size_t id6len = 4;
    guint8 salt[16];
    guint8 t[16];
    guint8 t1[16];

    size_t read_digest_length = 16;

    if (key_set->application_key_length != 16) {
        return FALSE;
    }

    /* SALT = s1("smk4") */
    if (s1(smk4, mlen, salt) == FALSE) {
        return FALSE;
    }

    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &salt, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, key_set->application_key, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &id6, id6len);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t1, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    key_set->aid = (t1[15] & 0x3f);

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return TRUE;
}

static gboolean
create_master_security_keys(uat_btmesh_record_t * net_key_set)
{
    guint8 p[1] = { 0 };
    size_t plen = 1;

    return k2(net_key_set, p, plen);
}

static tvbuff_t *
btmesh_deobfuscate(tvbuff_t *tvb, packet_info *pinfo, int offset _U_, uat_btmesh_record_t *net_key_set)
{
    tvbuff_t *de_obf_tvb = NULL;

    /* Decode ObfuscatedData
     * Privacy Random = (EncDST || EncTransportPDU || NetMIC)[0-6]
     * PECB = e ((PrivacyKey, 0x0000000000 || IV Index || Privacy Random)
     * (CTL || TTL || SEQ || SRC) = ObfuscatedData
     */
    guint8 in[16]; /*  0x0000000000 || IV Index || Privacy Random */
    gcry_cipher_hd_t cipher_hd;
    guint8 pecb[16];
    guint8 *plaintextnetworkheader = (guint8 *)wmem_alloc(pinfo->pool, 6);
    int i;

    /* at least 1 + 6 + 2 + 1 + 4 + 4 = 18 octets must be present in tvb to decrypt */
    if (!tvb_bytes_exist(tvb, 0, 18)) {
        return NULL;
    }

    memset(in, 0x00, 5);
    memcpy((guint8 *)&in + 5, net_key_set->ivindex, 4);

    /* Privacy random */
    tvb_memcpy(tvb, (guint8 *)&in + 9, 7, 7);

    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return NULL;
    }

    if (gcry_cipher_setkey(cipher_hd, net_key_set->privacykey, 16)) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Decrypt */
    if (gcry_cipher_encrypt(cipher_hd, &pecb, 16, &in, 16)) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Now close the cipher handle */
    gcry_cipher_close(cipher_hd);

    for ( i = 0; i < 6; i++) {
        plaintextnetworkheader[i] = tvb_get_guint8(tvb, i + 1) ^ pecb[i];
    }

    de_obf_tvb = tvb_new_child_real_data(tvb, plaintextnetworkheader, 6, 6);
    return de_obf_tvb;
}

static const gchar *period_interval_unit[] = {"ms", "s", "s", "min"};
static const guint32 period_interval_multiplier[] = {100, 1, 10, 10};

static void
format_publish_period(gchar *buf, guint32 value) {
    guint32 idx = (value & 0xC0 ) >> 5;
    guint32 val = (value & 0x3F ) * period_interval_multiplier[idx];
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u %s", val, period_interval_unit[idx]);
}

static void
format_transmit(gchar *buf, guint32 value) {
    guint32 prd = (((value & 0xF8 ) >> 3 ) + 1 ) * 10;
    guint32 ctr = (value & 0x07 );
    switch (ctr) {
    case 0:
        g_snprintf(buf, ITEM_LABEL_LENGTH, "One transmissions");
        break;

    default:
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%u transmissions at interval of %u ms", ctr, prd);
    }
}

static void
format_retransmit(gchar *buf, guint32 value) {
    guint32 prd = (((value & 0xF8 ) >> 3 ) + 1 ) * 10;
    guint32 ctr = (value & 0x07 );
    switch (ctr) {
    case 0:
        g_snprintf(buf, ITEM_LABEL_LENGTH, "No retransmissions");
        break;

    case 1:
        g_snprintf(buf, ITEM_LABEL_LENGTH, "One retransmission after %u ms", prd);
        break;

    default:
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%u retransmissions at interval of %u ms", ctr, prd);
    }
}

static void
format_interval_steps(gchar *buf, guint32 value) {
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u ms (%u)", (value + 1) * 10, value);
}

static void
format_key_index(gchar *buf, guint32 value) {
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u (0x%03x)", value & 0xFFF, value & 0xFFF);
}

static void
format_key_index_rfu(gchar *buf, guint32 value) {
    g_snprintf(buf, ITEM_LABEL_LENGTH, "0x%1x", (value & 0xF000) >> 12);
}

static void
format_dual_key_index(gchar *buf, guint32 value) {
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u (0x%03x), %u (0x%03x)", value & 0xFFF, value & 0xFFF, ( value & 0xFFF000 ) >> 12, ( value & 0xFFF000 ) >> 12);
}

static void
format_vendor_model(gchar *buf, guint32 value) {
    g_snprintf(buf, ITEM_LABEL_LENGTH, "0x%04x of %s", value >> 16, val_to_str_ext_const(value & 0xFFFF, &bluetooth_company_id_vals_ext, "Unknown"));
}

static void
format_publish_appkeyindex_model(gchar *buf, guint32 value) {
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u (0x%03x) using %s security material", value & 0x0FFF, value & 0x0FFF, (value & 0x1000 ? "Friendship" : "Master"));
}

static void
dissect_btmesh_model_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree *sub_tree;
    tvbuff_t *payload_tvb;
    guint32 opcode;
    guint16 vendor;
    proto_item *netapp_index_item, *app_index_item, *pub_app_index_item, *net_index_item;
    proto_item *relayretransmit_index, *transmit_index;
    proto_item *publishperiod_item, *publishretransmit_item;

    proto_tree *netapp_index_sub_tree, *app_index_sub_tree, *pub_app_index_sub_tree, *net_index_sub_tree;
    proto_tree *relayretransmit_sub_tree, *transmit_sub_tree, *subscriptionlist_tree;
    proto_tree *publishperiod_sub_tree, *publishretransmit_sub_tree;
    proto_tree *element_sub_tree, *model_sub_tree, *vendor_sub_tree;
    proto_tree *netkeylist_tree, *appkeylist_tree;
    proto_tree *fault_array_tree;

    guint32 netkeyindexes, appkeyindexes;
    guint32 nums, numv, element;
    guint i;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_model_layer, NULL, "Model Layer");

    opcode = tvb_get_guint8(tvb, offset);
    if (opcode & 0x80) {
        if (opcode & 0x40) {
            /* Vendor opcode */
            proto_tree_add_item(sub_tree, hf_btmesh_model_layer_vendor_opcode, tvb, offset, 1, ENC_NA);
            vendor = tvb_get_guint16(tvb, offset+1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_btmesh_model_layer_vendor, tvb, offset+1, 2, ENC_NA);
            payload_tvb = tvb_new_subset_remaining(tvb, offset);
            dissector_try_uint_new(btmesh_model_vendor_dissector_table, vendor, payload_tvb, pinfo, tree, TRUE, GUINT_TO_POINTER(vendor));
            offset+=3;
        } else {
        /* Two octet opcode */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_model_layer_opcode, tvb, offset, 2, ENC_NA, &opcode);
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, btmesh_models_opcode_vals, "Unknown"));
        offset+=2;
        }
    } else {
        /* One octet opcode */
        proto_tree_add_item(sub_tree, hf_btmesh_model_layer_opcode, tvb, offset, 1, ENC_NA);
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, btmesh_models_opcode_vals, "Unknown"));
        offset++;
    }

    switch (opcode) {
    case CONFIG_APPKEY_ADD:
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_add_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_add_appkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_APPKEY_UPDATE:
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_update_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_update_appkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_COMPOSITION_DATA_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_page, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_pid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_vid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_crpl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset,
            hf_btmesh_config_composition_data_status_features,
            ett_btmesh_config_composition_data_status_features,
            config_composition_data_status_features_headers,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        offset+=2;
        /* Elements */
        element = 1;
        while (tvb_reported_length_remaining(tvb, offset) > 2) {
            nums = tvb_get_guint8(tvb, offset + 2 );
            numv = tvb_get_guint8(tvb, offset + 2 + 1);
            element_sub_tree = proto_tree_add_subtree_format(sub_tree, tvb, offset, 4 + nums * 2 + numv * 4, ett_btmesh_config_model_element, NULL, "Element #%u", element);
            proto_tree_add_item(element_sub_tree, hf_btmesh_config_composition_data_status_loc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(element_sub_tree, hf_btmesh_config_composition_data_status_nums, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(element_sub_tree, hf_btmesh_config_composition_data_status_numv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            if (nums > 0 ) {
                model_sub_tree = proto_tree_add_subtree(element_sub_tree, tvb, offset, nums * 2, ett_btmesh_config_model_model, NULL, "SIG Models");
                for (i = 0; i < nums; i++) {
                    proto_tree_add_item(model_sub_tree, hf_btmesh_config_composition_data_status_sig_model, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset+=2;
                }
            }
            if (numv > 0 ) {
                vendor_sub_tree = proto_tree_add_subtree(element_sub_tree, tvb, offset, numv * 4, ett_btmesh_config_model_vendor, NULL, "Vendor Models");
                for (i = 0; i < numv; i++) {
                    proto_tree_add_item(vendor_sub_tree, hf_btmesh_config_composition_data_status_vendor_model, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset+=4;
                }
            }
            element++;
        }
        break;
    case CONFIG_MODEL_PUBLICATION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        pub_app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_appkey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        pub_app_index_sub_tree= proto_item_add_subtree(pub_app_index_item, ett_btmesh_config_model_pub_app_index);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_set_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_set_credentialflag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_set_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_set_publishperiod_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_set_publishperiod_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishretransmit_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishretransmit_sub_tree = proto_item_add_subtree(publishretransmit_item, ett_btmesh_config_model_publishretransmit);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_set_publishretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_set_publishretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case HEALTH_CURRENT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_current_status_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_current_status_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        fault_array_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_fault_array, NULL, "FaultArray");
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(fault_array_tree, hf_btmesh_health_current_status_fault, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case HEALTH_FAULT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_status_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_status_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        fault_array_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_fault_array, NULL, "FaultArray");
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(fault_array_tree, hf_btmesh_health_fault_status_fault, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case CONFIG_HEARTBEAT_PUBLICATION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_countlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset,
            hf_btmesh_config_heartbeat_publication_status_features,
            ett_btmesh_config_heartbeat_publication_status_features,
            config_heartbeat_publication_status_features_headers,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        offset+=2;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_APPKEY_DELETE:
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        break;
    case CONFIG_APPKEY_GET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_get_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_get_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_get_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_APPKEY_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_list_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_list_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_list_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        appkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_appkey_list, NULL, "AppKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                appkeyindexes = tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x000FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex, tvb, offset +1 , 2, (appkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                appkeyindexes = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x0FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex_rfu, tvb, offset, 2, (appkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
    case CONFIG_APPKEY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_status_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        break;
    case HEALTH_ATTENTION_GET:
        break;
    case HEALTH_ATTENTION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_health_attention_set_attention, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_ATTENTION_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_attention_set_unacknowledged_attention, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_ATTENTION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_attention_status_attention, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_COMPOSITION_DATA_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_get_page, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_BEACON_GET:
        break;
    case CONFIG_BEACON_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_beacon_set_beacon, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_BEACON_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_beacon_status_beacon, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_DEFAULT_TTL_GET:
        break;
    case CONFIG_DEFAULT_TTL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_default_ttl_set_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_DEFAULT_TTL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_default_ttl_status_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_FRIEND_GET:
        break;
    case CONFIG_FRIEND_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_friend_set_friend, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_FRIEND_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_friend_status_friend, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_GATT_PROXY_GET:
        break;
    case CONFIG_GATT_PROXY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_gatt_proxy_set_gattproxy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_GATT_PROXY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_gatt_proxy_status_gattproxy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_KEY_REFRESH_PHASE_GET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_get_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_get_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_get_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_KEY_REFRESH_PHASE_SET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_set_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_set_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_set_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_set_transition, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_KEY_REFRESH_PHASE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_status_phase, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_MODEL_PUBLICATION_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_get_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_PUBLICATION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        pub_app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_appkey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        pub_app_index_sub_tree= proto_item_add_subtree(pub_app_index_item, ett_btmesh_config_model_pub_app_index);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_status_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_status_credentialflag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_status_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_status_publishperiod_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_status_publishperiod_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishretransmit_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishretransmit_sub_tree = proto_item_add_subtree(publishretransmit_item, ett_btmesh_config_model_publishretransmit);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_status_publishretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_status_publishretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishaddress, tvb, offset, 16, ENC_NA);
        offset+=16;
        pub_app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_appkey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        pub_app_index_sub_tree= proto_item_add_subtree(pub_app_index_item, ett_btmesh_config_model_pub_app_index);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_credentialflag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishperiod_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishperiod_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishretransmit_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishretransmit_sub_tree = proto_item_add_subtree(publishretransmit_item, ett_btmesh_config_model_publishretransmit);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_ADD:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_DELETE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_DELETE_ALL:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_all_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_all_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_all_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_OVERWRITE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_label, tvb, offset, 16, ENC_NA);
        offset+=16;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_label, tvb, offset, 16, ENC_NA);
        offset+=16;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_label, tvb, offset, 16, ENC_NA);
        offset+=16;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_NETWORK_TRANSMIT_GET:
        break;
    case CONFIG_NETWORK_TRANSMIT_SET:
        transmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_network_transmit_set_networktransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        transmit_sub_tree = proto_item_add_subtree(transmit_index, ett_btmesh_config_model_network_transmit);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_set_networktransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_set_networktransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_NETWORK_TRANSMIT_STATUS:
        transmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_network_transmit_status_networktransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        transmit_sub_tree = proto_item_add_subtree(transmit_index, ett_btmesh_config_model_network_transmit);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_status_networktransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_status_networktransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_RELAY_GET:
        break;
    case CONFIG_RELAY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_relay_set_relay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        relayretransmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_relay_set_relayretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        relayretransmit_sub_tree = proto_item_add_subtree(relayretransmit_index, ett_btmesh_config_model_relayretransmit);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_set_relayretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_set_relayretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_RELAY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_relay_status_relay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        relayretransmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_relay_status_relayretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        relayretransmit_sub_tree = proto_item_add_subtree(relayretransmit_index, ett_btmesh_config_model_relayretransmit);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_status_relayretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_status_relayretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_SIG_MODEL_SUBSCRIPTION_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_SIG_MODEL_SUBSCRIPTION_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_list_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        subscriptionlist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_addresses, NULL, "Addresses");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(subscriptionlist_tree, hf_btmesh_config_sig_model_subscription_list_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_VENDOR_MODEL_SUBSCRIPTION_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_get_modelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        break;
    case CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_list_modelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        subscriptionlist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_addresses, NULL, "Addresses");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(subscriptionlist_tree, hf_btmesh_config_vendor_model_subscription_list_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_LOW_POWER_NODE_POLLTIMEOUT_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_low_power_node_polltimeout_get_lpnaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_LOW_POWER_NODE_POLLTIMEOUT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_low_power_node_polltimeout_status_lpnaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_low_power_node_polltimeout_status_polltimeout, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        break;
    case HEALTH_FAULT_CLEAR:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_clear_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_CLEAR_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_clear_unacknowledged_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_get_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_TEST:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_TEST_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_unacknowledged_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_unacknowledged_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_PERIOD_GET:
        break;
    case HEALTH_PERIOD_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_health_period_set_fastperioddivisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_PERIOD_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_period_set_unacknowledged_fastperioddivisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_PERIOD_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_period_status_fastperioddivisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_HEARTBEAT_PUBLICATION_GET:
        break;
    case CONFIG_HEARTBEAT_PUBLICATION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_countlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset,
            hf_btmesh_config_heartbeat_publication_set_features,
            ett_btmesh_config_heartbeat_publication_set_features,
            config_heartbeat_publication_set_features_headers,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        offset+=2;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_set_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_set_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_HEARTBEAT_SUBSCRIPTION_GET:
        break;
    case CONFIG_HEARTBEAT_SUBSCRIPTION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_set_source, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_set_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_set_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_source, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_countlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_minhops, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_maxhops, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_MODEL_APP_BIND:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        app_index_sub_tree = proto_item_add_subtree(app_index_item, ett_btmesh_config_model_app_index);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_bind_appkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_bind_appkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_APP_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        app_index_sub_tree = proto_item_add_subtree(app_index_item, ett_btmesh_config_model_app_index);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_status_appkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_status_appkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_APP_UNBIND:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        app_index_sub_tree = proto_item_add_subtree(app_index_item, ett_btmesh_config_model_app_index);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_unbind_appkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_unbind_appkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_NETKEY_ADD:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_add_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_add_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_add_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_add_netkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_NETKEY_DELETE:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_delete_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_delete_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_delete_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_NETKEY_GET:
        break;
    case CONFIG_NETKEY_LIST:
        netkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_netkey_list, NULL, "NetKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                netkeyindexes = tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex, tvb, offset, 2, netkeyindexes & 0x000FFF);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex, tvb, offset + 1, 2, (netkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                netkeyindexes = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex, tvb, offset, 2, netkeyindexes & 0x0FFF);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex_rfu, tvb, offset, 2, (netkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
    case CONFIG_NETKEY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_NETKEY_UPDATE:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_update_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_update_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_update_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_update_netkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_NODE_IDENTITY_GET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_get_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_get_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_get_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_NODE_IDENTITY_SET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_set_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_set_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_set_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_set_identity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_NODE_IDENTITY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_status_identity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_NODE_RESET:
        break;
    case CONFIG_NODE_RESET_STATUS:
        break;
    case CONFIG_SIG_MODEL_APP_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_SIG_MODEL_APP_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_list_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        appkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_appkey_list, NULL, "AppKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                appkeyindexes = tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x000FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex, tvb, offset +1 , 2, (appkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                appkeyindexes = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x0FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex_rfu, tvb, offset, 2, (appkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
    case CONFIG_VENDOR_MODEL_APP_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=4;
        break;
    case CONFIG_VENDOR_MODEL_APP_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_list_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=4;
        appkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_appkey_list, NULL, "AppKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                appkeyindexes = tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x000FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex, tvb, offset +1 , 2, (appkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                appkeyindexes = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x0FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex_rfu, tvb, offset, 2, (appkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
    default:
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(sub_tree, hf_btmesh_model_layer_parameters, tvb, offset, -1, ENC_NA);
            offset+=tvb_reported_length_remaining(tvb, offset);
        }
    }
    /* Still some octets left */
    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_unknown_payload, tvb, offset, -1);
    }
}

static void
dissect_btmesh_access_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
   proto_tree *sub_tree;

   sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_access_pdu, NULL, "Access PDU");
   proto_tree_add_item(sub_tree, hf_btmesh_decrypted_access, tvb, offset, -1, ENC_NA);

   dissect_btmesh_model_layer(tvb, pinfo, tree, offset);
}

static void
dissect_btmesh_transport_control_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint32 opcode)
{
    proto_tree *sub_tree;

    sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_btmesh_transp_ctrl_msg, NULL, "Transport Control Message %s",
        val_to_str_const(opcode, btmesh_ctrl_opcode_vals, "Unknown"));

    switch (opcode) {
    case 1:
        /* 3.6.5.1 Friend Poll */
        /* Padding 7 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* FSN 1 bit*/
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_fsn, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* 3.6.5.2 Friend Update */
        /* Flags 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_key_refresh_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_iv_update_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_flags_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* IV Index 4 octets*/
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_iv_index, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        /* MD 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_md, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;
    case 3:
        /* Friend Request */
        /* Criteria 1 octet */
        /* RFU 1 bit */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* RSSIFactor 2 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_rssifactor, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* ReceiveWindowFactor 2 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_receivewindowfactor, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* MinQueueSizeLog 3 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_minqueuesizelog, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* ReceiveDelay 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_receivedelay, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* PollTimeout 3 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_polltimeout, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
        /* PreviousAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_previousaddress, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* NumElements 1 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_numelements, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* LPNCounter 1 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 4:
        /* 3.6.5.4 Friend Offer */
        /* ReceiveWindow 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_receivewindow, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* QueueSize 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_queuesize, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* SubscriptionListSize 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_subscriptionlistsize, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* RSSI 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* FriendCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_friendcounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 5:
        /* 3.6.5.5 Friend Clear */
        /* LPNAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpnaddress, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;
        /* LPNCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 6:
        /* 3.6.5.6 Friend Clear Confirm */
        /* LPNAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpnaddress, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;
        /* LPNCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);

        break;
    case 7:
        /* 3.6.5.7 Friend Subscription List Add */
        /* TransactionNumber 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* AddressList 2 * N */
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    case 8:
        /* 3.6.5.8 Friend Subscription List Remove */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* AddressList 2 * N */
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    case 9:
        /* 3.6.5.9 Friend Subscription List Confirm */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;
    case 10:
        /* 3.6.5.10 Heartbeat */
        /* RFU & InitTTL */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_heartbeat_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_init_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* Features */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_relay, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_proxy, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_friend, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_low_power, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_rfu, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    default:
        /* Unknown Control Message */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_unknown_payload, tvb, offset, -1, ENC_NA);
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    }
}

static gboolean
try_access_decrypt(tvbuff_t *tvb, int offset, guint8 *decrypted_data, int enc_data_len, guint8 *key, network_decryption_ctx_t *dec_ctx)
{
    guint8 accessnonce[13];
    guint32 seq0;
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t gcrypt_err;
    guint64 ccm_lengths[3];
    guint8 *tag;

    accessnonce[0] = dec_ctx->app_nonce_type;
    accessnonce[1] = (dec_ctx->transmic_size == 4 ? 0x00 : 0x80 );
    memcpy((guint8 *)&accessnonce + 2, dec_ctx->seq_src_buf, 5);
    if (dec_ctx->seg) {
        /* Use 13 Lsbs from seqzero */
        seq0 = dec_ctx->seq;
        /* Check for overflow */
        if ((dec_ctx->seq & 0x1fff) < dec_ctx->seqzero) {
            seq0 -= 0x2000;
        }
        seq0 = seq0 & ~0x1fff;
        seq0 += dec_ctx->seqzero;
        accessnonce[2] = (seq0 & 0xff0000 ) >> 16;
        accessnonce[3] = (seq0 & 0x00ff00 ) >> 8;
        accessnonce[4] = (seq0 & 0x0000ff ) ;
    }
    memcpy((guint8 *)&accessnonce + 7, dec_ctx->dst_buf, 2);
    memcpy((guint8 *)&accessnonce + 9, dec_ctx->ivindex_buf, 4);

    /* Decrypt packet EXPERIMENTAL CODE */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0)) {
        return FALSE;
    }
    /* Set key */
    gcrypt_err = gcry_cipher_setkey(cipher_hd, key, 16);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
   /* Load nonce */
    gcrypt_err = gcry_cipher_setiv(cipher_hd, &accessnonce, 13);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    ccm_lengths[0] = enc_data_len;
    ccm_lengths[1] = (dec_ctx->label_uuid_idx == NO_LABEL_UUID_IDX_USED ? 0 : 16);
    ccm_lengths[2] = dec_ctx->transmic_size;

    gcrypt_err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    if (dec_ctx->label_uuid_idx != NO_LABEL_UUID_IDX_USED) {
        gcrypt_err = gcry_cipher_authenticate(cipher_hd, uat_btmesh_label_uuid_records[dec_ctx->label_uuid_idx].label_uuid, 16);
        if (gcrypt_err != 0) {
            gcry_cipher_close(cipher_hd);
            return FALSE;
        }
    }

    /* Decrypt */
    gcrypt_err = gcry_cipher_decrypt(cipher_hd, decrypted_data, enc_data_len, tvb_get_ptr(tvb, offset, enc_data_len), enc_data_len);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    tag = (guint8 *)wmem_alloc(wmem_packet_scope(), dec_ctx->transmic_size);
    gcrypt_err = gcry_cipher_gettag(cipher_hd, tag, dec_ctx->transmic_size);
    gcry_cipher_close(cipher_hd);

    if (gcrypt_err != 0 || memcmp(tag, tvb_get_ptr(tvb, offset + enc_data_len, dec_ctx->transmic_size), dec_ctx->transmic_size)) {
        /* Tag mismatch or cipher error */
        return FALSE;
    }
    /* Tag authenticated */
    return TRUE;
}

static guint
check_address_type(guint32 btmesh_address)
{
    if (btmesh_address & 0x8000 ) {
        if (btmesh_address & 0x4000) {
            return BTMESH_ADDRESS_GROUP;
        }
        return BTMESH_ADDRESS_VIRTUAL;
    } else {
        if (btmesh_address) {
            return BTMESH_ADDRESS_UNICAST;
        }
        return BTMESH_ADDRESS_UNASSIGNED;
    }
}

static tvbuff_t *
btmesh_access_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, int offset, network_decryption_ctx_t *dec_ctx)
{
    guint i, j, dst_address_type;
    uat_btmesh_record_t *record;
    uat_btmesh_dev_key_record_t *dev_record;
    uat_btmesh_label_uuid_record_t *label_record;
    int enc_data_len;
    guint8 *decrypted_data;

    enc_data_len = tvb_reported_length_remaining(tvb, offset) - dec_ctx->transmic_size;
    decrypted_data = (guint8 *)wmem_alloc(pinfo->pool, enc_data_len);
    dec_ctx->label_uuid_idx = NO_LABEL_UUID_IDX_USED;

    if (enc_data_len <= 0) {
        return NULL;
    }

    dst_address_type = check_address_type(dec_ctx->dst);

    /* Application key */
    if (dec_ctx->app_nonce_type == BTMESH_NONCE_TYPE_APPLICATION) {
        for (i = 0; i < num_btmesh_uat; i++) {
            record = &uat_btmesh_records[i];
            if (record->valid == BTMESH_KEY_ENTRY_VALID) {
                if (dec_ctx->net_key_iv_index_hash == record->net_key_iv_index_hash && dec_ctx->aid == record->aid) {
                    /* Try Label UUID */
                    if (dst_address_type == BTMESH_ADDRESS_VIRTUAL) {
                        for (j = 0; j < num_btmesh_label_uuid_uat; j++) {
                            label_record = &uat_btmesh_label_uuid_records[j];
                            if (label_record->valid == BTMESH_LABEL_UUID_ENTRY_VALID && label_record->hash == dec_ctx->dst){
                                dec_ctx->label_uuid_idx = j;
                                if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, record->application_key, dec_ctx)) {
                                    return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                                }
                            }
                        }
                    } else {
                        if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, record->application_key, dec_ctx)) {
                            return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                        }
                    }
                }
            }
        }
    }
    /* Device key */
    if (dec_ctx->app_nonce_type == BTMESH_NONCE_TYPE_DEVICE) {
        for (i = 0; i < num_btmesh_dev_key_uat; i++) {
            dev_record = &uat_btmesh_dev_key_records[i];
            if (dev_record->valid == BTMESH_DEVICE_KEY_ENTRY_VALID) {
                /* Try Device Key from SRC */
                if ( !memcmp(dev_record->src, dec_ctx->seq_src_buf + 3, 2) ) {
                    /* Try Label UUID */
                    if (dst_address_type == BTMESH_ADDRESS_VIRTUAL) {
                        for (j = 0; j < num_btmesh_label_uuid_uat; j++) {
                            label_record = &uat_btmesh_label_uuid_records[j];
                            if (label_record->valid == BTMESH_LABEL_UUID_ENTRY_VALID && label_record->hash == dec_ctx->dst){
                                dec_ctx->label_uuid_idx = j;
                                if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, dev_record->device_key, dec_ctx)) {
                                    return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                                }
                            }
                        }
                    } else {
                        if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, dev_record->device_key, dec_ctx)) {
                            return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                        }
                    }
                }
                /* Try Device Key from DST when DST is a unicast address */
                if (dst_address_type == BTMESH_ADDRESS_UNICAST) {
                    if ( !memcmp(dev_record->src, dec_ctx->dst_buf, 2) ) {
                        if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, dev_record->device_key, dec_ctx)) {
                            return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

static void
dissect_btmesh_transport_access_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, network_decryption_ctx_t *dec_ctx)
{
    tvbuff_t *de_acc_tvb;
    proto_tree *sub_tree;

    int length = tvb_reported_length_remaining(tvb, offset);

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_upper_transp_acc_pdu, NULL, "Upper Transport Access PDU");
    de_acc_tvb = btmesh_access_find_key_and_decrypt(tvb, pinfo, offset, dec_ctx);

    proto_tree_add_item(sub_tree, hf_btmesh_enc_access_pld, tvb, offset, length - dec_ctx->transmic_size, ENC_NA);
    offset += (length - dec_ctx->transmic_size);

    proto_tree_add_item(sub_tree, hf_btmesh_transtmic, tvb, offset, dec_ctx->transmic_size, ENC_NA);

    if (de_acc_tvb) {
        add_new_data_source(pinfo, de_acc_tvb, "Decrypted access data");
        dissect_btmesh_access_message(de_acc_tvb, pinfo, tree, 0);
    }
}

static void
dissect_btmesh_transport_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean cntrl, network_decryption_ctx_t *dec_ctx)
{
    proto_tree *sub_tree;
    proto_item *ti;
    int offset = 0;
    guint32 seg, opcode, rfu;
    guint32 seqzero, sego, segn;

    /* We receive the full decrypted buffer including DST, skip to opcode */
    offset += 2;
    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_transp_pdu, &ti, "Lower Transport PDU");
    if (cntrl) {
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_cntr_seg, tvb, offset, 1, ENC_BIG_ENDIAN, &seg);
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_cntr_opcode, tvb, offset, 1, ENC_BIG_ENDIAN, &opcode);
        offset++;

        if (seg) {
            /* Segmented */
            fragment_head *fd_head = NULL;

            /* RFU */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seg_rfu, tvb, offset, 3, ENC_BIG_ENDIAN, &rfu);
            /* SeqZero 13 */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seqzero_data, tvb, offset, 3, ENC_BIG_ENDIAN, &seqzero);
            /* SegO 5 Segment Offset number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sego, tvb, offset, 3, ENC_BIG_ENDIAN, &sego);
            /* SegN 5 Last Segment number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_segn, tvb, offset, 3, ENC_BIG_ENDIAN, &segn);
            offset += 3;

            /* Segment */
            proto_tree_add_item(sub_tree, hf_btmesh_segment, tvb, offset, -1, ENC_NA);

            upper_transport_fragment_key frg_key;
            /* src is 15 bit, seqzero is 13 bit*/
            frg_key.src = dec_ctx->src;
            frg_key.seq0 = seqzero;

            if (!pinfo->fd->visited) {
                guint32 total_length = 0;
                if (segn == sego) {
                    total_length = segn * 8 + tvb_captured_length_remaining(tvb, offset);
                }

                /* Last fragment can be delivered out of order, and can be the first one. */
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);

                if ((fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
                fd_head = fragment_add(&upper_transport_reassembly_table,
                            tvb, offset, pinfo,
                            BTMESH_NOT_USED, &frg_key,
                            8 * sego,
                            tvb_captured_length_remaining(tvb, offset),
                            ( segn == 0 ? FALSE : TRUE) );

                if ((!fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
            } else {
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);
                if (fd_head && (fd_head->flags&FD_DEFRAGMENTED)) {
                    tvbuff_t *next_tvb;
                    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Control PDU", fd_head, &btmesh_segmented_control_frag_items, NULL, sub_tree);
                    if (next_tvb) {
                        dissect_btmesh_transport_control_message(next_tvb, pinfo, tree, 0, opcode);
                        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", sego);
                    }
                }
            }
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                val_to_str_const(opcode, btmesh_ctrl_opcode_vals, "Unknown"));
            if (opcode == 0) {
                /* OBO 1 */
                proto_tree_add_item(sub_tree, hf_btmesh_obo, tvb, offset, 2, ENC_BIG_ENDIAN);
                /* SeqZero 13 */
                proto_tree_add_item(sub_tree, hf_btmesh_seqzero, tvb, offset, 2, ENC_BIG_ENDIAN);
                /* RFU 2 */
                proto_tree_add_item(sub_tree, hf_btmesh_rfu, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* BlockAck 32 */
                proto_tree_add_item(sub_tree, hf_btmesh_blockack, tvb, offset, 4, ENC_BIG_ENDIAN);
                return;
            }
            dissect_btmesh_transport_control_message(tvb, pinfo, tree, offset, opcode);
        }
    } else {
        /* Access message */
        guint32 afk, aid, szmic;
        /* Access message */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_seg, tvb, offset, 1, ENC_BIG_ENDIAN, &seg);
        /* AKF 1 Application Key Flag */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_akf, tvb, offset, 1, ENC_BIG_ENDIAN, &afk);
        /* AID 6 Application key identifier */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_aid, tvb, offset, 1, ENC_BIG_ENDIAN, &aid);
        offset++;

        dec_ctx->seg = seg;
        dec_ctx->aid = aid;
        dec_ctx->app_nonce_type = (afk ? BTMESH_NONCE_TYPE_APPLICATION : BTMESH_NONCE_TYPE_DEVICE);

        if (seg) {
            /* Segmented */
            fragment_head *fd_head = NULL;

            /* SZMIC 1 Size of TransMIC */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_szmic, tvb, offset, 3, ENC_BIG_ENDIAN, &szmic);
            /* SeqZero 13 Least significant bits of SeqAuth */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seqzero_data, tvb, offset, 3, ENC_BIG_ENDIAN, &seqzero);
            /* SegO 5 Segment Offset number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sego, tvb, offset, 3, ENC_BIG_ENDIAN, &sego);
            /* SegN 5 Last Segment number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_segn, tvb, offset, 3, ENC_BIG_ENDIAN, &segn);
            offset += 3;

            dec_ctx->seqzero = seqzero;

            /* Segment m 8 to 96 Segment m of the Upper Transport Access PDU */
            proto_tree_add_item(sub_tree, hf_btmesh_segment, tvb, offset, -1, ENC_NA);

            upper_transport_fragment_key frg_key;
            /* src is 15 bit, seqzero is 13 bit*/
            frg_key.src = dec_ctx->src;
            frg_key.seq0 = seqzero;

            if (!pinfo->fd->visited) {
                guint32 total_length = 0;
                if (segn == sego) {
                    total_length = segn * 12 + tvb_captured_length_remaining(tvb, offset);
                }

                /* Last fragment can be delivered out of order, and can be the first one. */
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);

                if ((fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
                fd_head = fragment_add(&upper_transport_reassembly_table,
                            tvb, offset, pinfo,
                            BTMESH_NOT_USED, &frg_key,
                            12 * sego,
                            tvb_captured_length_remaining(tvb, offset),
                            ( segn == 0 ? FALSE : TRUE) );

                if ((!fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
            } else {
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);
                if (fd_head && (fd_head->flags&FD_DEFRAGMENTED)) {
                    tvbuff_t *next_tvb;
                    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Access PDU", fd_head, &btmesh_segmented_access_frag_items, NULL, sub_tree);
                    if (next_tvb) {
                        dec_ctx->transmic_size = (szmic ? 8 : 4 );
                        dissect_btmesh_transport_access_message(next_tvb, pinfo, tree, 0, dec_ctx);
                        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", sego);
                    }
                }
            }
        } else {
            proto_item_set_len(ti, 1);
            dec_ctx->transmic_size = 4; /*TransMic is 32 bits*/
            dissect_btmesh_transport_access_message(tvb, pinfo, tree, offset, dec_ctx);
        }
    }
}

tvbuff_t *
btmesh_network_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, guint8 **decrypted_data, int *enc_data_len, network_decryption_ctx_t *dec_ctx) {
    guint i;
    guint8 nid;
    int offset = 0;
    tvbuff_t *de_obf_tvb;
    guint8 networknonce[13];
    uat_btmesh_record_t *record;
    gcry_cipher_hd_t cipher_hd;
    guint32 net_mic_size;
    gcry_error_t gcrypt_err;
    guint64 ccm_lengths[3];
    int enc_offset;

    nid = tvb_get_guint8(tvb, offset) & 0x7f;

    /* Get the next record to try */
    for (i = 0; i < num_btmesh_uat; i++) {
        record = &uat_btmesh_records[i];
        if (nid == record->nid) {
            offset = 1;
            de_obf_tvb = btmesh_deobfuscate(tvb, pinfo, offset, record);

            if (de_obf_tvb == NULL) {
                continue;
            }
            net_mic_size = (((tvb_get_guint8(de_obf_tvb, 0) & 0x80) >> 7 ) + 1 ) * 4; /* CTL */
            offset +=6;

            (*enc_data_len) = tvb_reported_length(tvb) - offset - net_mic_size;
            enc_offset = offset;

            /* Start setting network nounce.*/
            networknonce[0] = dec_ctx->net_nonce_type; /* Nonce Type */

            tvb_memcpy(de_obf_tvb, (guint8 *)&networknonce + 1, 0, 6);
            if (dec_ctx->net_nonce_type == BTMESH_NONCE_TYPE_PROXY) {
                networknonce[1] = 0x00;    /*Pad*/
            }
            networknonce[7] = 0x00;    /*Pad*/
            networknonce[8] = 0x00;    /*Pad*/

            memcpy((guint8 *)&networknonce + 9, record->ivindex, 4);
            /* Decrypt packet EXPERIMENTAL CODE */
            if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0)) {
                return NULL;
            }

            gcrypt_err = gcry_cipher_setkey(cipher_hd, record->encryptionkey, 16);
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            /* Load nonce */
            gcrypt_err = gcry_cipher_setiv(cipher_hd, &networknonce, 13);
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }
            /* */
            ccm_lengths[0] = (*enc_data_len);
            ccm_lengths[1] = 0; /* aad */
            ccm_lengths[2] = net_mic_size; /* icv */

            gcrypt_err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            (*decrypted_data) = (guint8 *)wmem_alloc(pinfo->pool, *enc_data_len);
            /* Decrypt */
            gcrypt_err = gcry_cipher_decrypt(cipher_hd, (*decrypted_data), *enc_data_len, tvb_get_ptr(tvb, enc_offset, *enc_data_len), *enc_data_len);
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            guint8 *tag;
            tag = (guint8 *)wmem_alloc(wmem_packet_scope(), net_mic_size);
            gcrypt_err = gcry_cipher_gettag(cipher_hd, tag, net_mic_size);

            if (gcrypt_err == 0 && !memcmp(tag, tvb_get_ptr(tvb, enc_offset + (*enc_data_len), net_mic_size), net_mic_size)) {
                /* Tag authenticated, now close the cypher handle */
                gcry_cipher_close(cipher_hd);
                dec_ctx->net_key_iv_index_hash = record->net_key_iv_index_hash;
                memcpy(dec_ctx->ivindex_buf, record->ivindex, 4);

                return de_obf_tvb;
            }  else {
                /* Now close the cypher handle */
                gcry_cipher_close(cipher_hd);

                /* Tag mismatch or cipher error */
                continue;
            }
        }
    }
    return NULL;
}

static gint
dissect_btmesh_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *netw_tree, *sub_tree;
    int offset = 0;
    guint32 net_mic_size, seq, src, dst;
    int enc_data_len = 0;
    tvbuff_t *de_obf_tvb;
    tvbuff_t *de_cry_tvb;
    int decry_off;
    guint8 *decrypted_data = NULL;
    network_decryption_ctx_t *dec_ctx;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh");
    col_clear(pinfo->cinfo, COL_INFO);

    item = proto_tree_add_item(tree, proto_btmesh, tvb, offset, -1, ENC_NA);
    netw_tree = proto_item_add_subtree(item, ett_btmesh);

    sub_tree = proto_tree_add_subtree(netw_tree, tvb, offset, -1, ett_btmesh_net_pdu, NULL, "Network PDU");
    /* Check length >= , if not error packet */
    /* First byte in plaintext */
    /* IVI 1 bit Least significant bit of IV Index */
    proto_tree_add_item(sub_tree, hf_btmesh_ivi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_btmesh_nid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    dec_ctx = wmem_new(wmem_packet_scope(), network_decryption_ctx_t);
    dec_ctx->net_nonce_type = BTMESH_NONCE_TYPE_NETWORK;

    de_obf_tvb = btmesh_network_find_key_and_decrypt(tvb, pinfo, &decrypted_data, &enc_data_len, dec_ctx);

    if (de_obf_tvb) {
        add_new_data_source(pinfo, de_obf_tvb, "Deobfuscated data");

        gboolean cntrl;

        /* CTL 1 bit Network Control*/
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_ctl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN, &net_mic_size);
        /* 32 or 64 bits ( 0 or 1 )*/
        cntrl = net_mic_size;
        net_mic_size = (net_mic_size + 1) * 4;
        /* The TTL field is a 7-bit field */
        proto_tree_add_item(sub_tree, hf_btmesh_ttl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN);

        /* SEQ field is a 24-bit integer */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seq, de_obf_tvb, 1, 3, ENC_BIG_ENDIAN, &seq);

        /* SRC field is a 16-bit value */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_src, de_obf_tvb, 4, 2, ENC_BIG_ENDIAN, &src);
        offset += 6;

        de_cry_tvb = tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
        add_new_data_source(pinfo, de_cry_tvb, "Decrypted network data");

        decry_off = 0;
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_dst, de_cry_tvb, decry_off, 2, ENC_BIG_ENDIAN, &dst);
        decry_off += 2;
        /* TransportPDU */
        proto_tree_add_item(sub_tree, hf_btmesh_transp_pdu, de_cry_tvb, decry_off, enc_data_len-2, ENC_NA);
        offset += enc_data_len;

        proto_tree_add_item(sub_tree, hf_btmesh_netmic, tvb, offset, net_mic_size, ENC_BIG_ENDIAN);
        offset += net_mic_size;

        if (de_cry_tvb) {
            dec_ctx->src = src;
            dec_ctx->seq = seq;
            dec_ctx->dst = dst;
            tvb_memcpy(de_obf_tvb, dec_ctx->seq_src_buf, 1, 5);
            tvb_memcpy(de_cry_tvb, dec_ctx->dst_buf, 0, 2);

            dissect_btmesh_transport_pdu(de_cry_tvb, pinfo, netw_tree, cntrl, dec_ctx);
        }
    } else {
        proto_tree_add_item(sub_tree, hf_btmesh_obfuscated, tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(sub_tree, hf_btmesh_encrypted, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
    }

    return offset;
}

#else /* GCRYPT_VERSION_NUMBER >= 0x010600 */

static void
format_transmit(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_key_index_rfu(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_interval_steps(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_retransmit(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_publish_period(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_publish_appkeyindex_model(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_vendor_model(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_key_index(gchar *buf _U_, guint32 value _U_)
{
}

static void
format_dual_key_index(gchar *buf _U_, guint32 value _U_)
{
}

static gboolean
create_master_security_keys(uat_btmesh_record_t * net_key_set _U_)
{
    return FALSE;
}

static gboolean
k4(uat_btmesh_record_t *key_set _U_)
{
    return FALSE;
}

static gboolean
label_uuid_hash(uat_btmesh_label_uuid_record_t *label_uuid_record _U_)
{
    return FALSE;
}

/* Stub dissector if decryption not available on build system */
static gint
dissect_btmesh_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh");
    col_clear(pinfo->cinfo, COL_INFO);

    item = proto_tree_add_item(tree, proto_btmesh, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_btmesh);

    /* First byte in plaintext */
    /* IVI 1 bit Least significant bit of IV Index */
    proto_tree_add_item(sub_tree, hf_btmesh_ivi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_btmesh_nid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(sub_tree, hf_btmesh_obfuscated, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(sub_tree, hf_btmesh_encrypted, tvb, offset, -1, ENC_NA);

    return tvb_reported_length(tvb);
}

#endif /* GCRYPT_VERSION_NUMBER >= 0x010600 */

static gint
compute_ascii_key(guchar **ascii_key, const gchar *key)
{
    guint key_len = 0, raw_key_len;
    gint hex_digit;
    guchar key_byte;
    guint i, j;

    if (key != NULL)
    {
        raw_key_len = (guint)strlen(key);
        if ((raw_key_len > 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
        {
            /*
             * Key begins with "0x" or "0X"; skip that and treat the rest
             * as a sequence of hex digits.
             */
            i = 2;    /* first character after "0[Xx]" */
            j = 0;
            if (raw_key_len % 2 == 1)
            {
                /*
                 * Key has an odd number of characters; we act as if the
                 * first character had a 0 in front of it, making the
                 * number of characters even.
                 */
                key_len = (raw_key_len - 2) / 2 + 1;
                *ascii_key = (guchar *)g_malloc((key_len + 1) * sizeof(gchar));
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    return -1;    /* not a valid hex digit */
                }
                (*ascii_key)[j] = (guchar)hex_digit;
                j++;
            }
            else
            {
                /*
                 * Key has an even number of characters, so we treat each
                 * pair of hex digits as a single byte value.
                 */
                key_len = (raw_key_len - 2) / 2;
                *ascii_key = (guchar *)g_malloc((key_len + 1) * sizeof(gchar));
            }

            while (i < (raw_key_len - 1))
            {
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    return -1;    /* not a valid hex digit */
                }
                key_byte = ((guchar)hex_digit) << 4;
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    return -1;    /* not a valid hex digit */
                }
                key_byte |= (guchar)hex_digit;
                (*ascii_key)[j] = key_byte;
                j++;
            }
            (*ascii_key)[j] = '\0';
        }

        else if ((raw_key_len == 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
        {
            return 0;
        }
        else
        {
            key_len = raw_key_len;
            *ascii_key = (guchar*)g_strdup(key);
        }
    }
    return key_len;
}

static gboolean
uat_btmesh_record_update_cb(void *r, char **err _U_)
{
    uat_btmesh_record_t *rec = (uat_btmesh_record_t *)r;

    rec->valid = 0;

    /* Compute keys & lengths once and for all */
    if (rec->network_key_string) {
        g_free(rec->network_key);
        rec->network_key_length = compute_ascii_key(&rec->network_key, rec->network_key_string);
        g_free(rec->encryptionkey);
        rec->encryptionkey = (guint8 *)g_malloc(16 * sizeof(guint8));
        memset(rec->encryptionkey, 0, 16 * sizeof(guint8));
        g_free(rec->privacykey);
        rec->privacykey = (guint8 *)g_malloc(16 * sizeof(guint8));
        if (create_master_security_keys(rec)) {
            rec->valid++;
        }
    } else {
        rec->network_key_length = 0;
        rec->network_key = NULL;
    }
    if (rec->application_key_string) {
        g_free(rec->application_key);
        rec->application_key_length = compute_ascii_key(&rec->application_key, rec->application_key_string);
        /* compute AID */
        if (k4(rec)) {
            rec->valid++;
        }
    } else {
        rec->application_key_length = 0;
        rec->application_key = NULL;
    }
    if (rec->ivindex_string) {
        g_free(rec->ivindex);
        rec->ivindex_string_length = compute_ascii_key(&rec->ivindex, rec->ivindex_string);
        if (rec->ivindex_string_length == 4) {
            rec->valid++;
        }
    }
    if (rec->valid == BTMESH_KEY_ENTRY_VALID - 1) {
        /* Compute net_key_index_hash */
        rec->net_key_iv_index_hash =    (guint32) rec->encryptionkey[0];
        rec->net_key_iv_index_hash +=  ((guint32)(rec->encryptionkey[1]) << 8);
        rec->net_key_iv_index_hash +=  ((guint32)(rec->encryptionkey[2]) << 16);
        rec->net_key_iv_index_hash +=  ((guint32)(rec->encryptionkey[3]) << 24);
        rec->net_key_iv_index_hash +=   (guint32) rec->ivindex[0];
        rec->net_key_iv_index_hash +=  ((guint32)(rec->ivindex[1]) << 8);
        rec->net_key_iv_index_hash +=  ((guint32)(rec->ivindex[2]) << 16);
        rec->net_key_iv_index_hash +=  ((guint32)(rec->ivindex[3]) << 24);
        rec->valid++;
    }
    return TRUE;
}

static void *
uat_btmesh_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_btmesh_record_t *new_rec = (uat_btmesh_record_t *)n;
    const uat_btmesh_record_t* old_rec = (const uat_btmesh_record_t *)o;

    memset(new_rec, 0x00, sizeof(uat_btmesh_record_t));

    /* Copy UAT fields */
    new_rec->network_key_string = g_strdup(old_rec->network_key_string);
    new_rec->application_key_string = g_strdup(old_rec->application_key_string);
    new_rec->ivindex_string = g_strdup(old_rec->ivindex_string);

    /* Parse keys as in an update */
    uat_btmesh_record_update_cb(new_rec, NULL);

    return new_rec;
}

static void
uat_btmesh_record_free_cb(void *r)
{
    uat_btmesh_record_t *rec = (uat_btmesh_record_t *)r;

    g_free(rec->network_key_string);
    g_free(rec->network_key);
    g_free(rec->application_key_string);
    g_free(rec->application_key);
    g_free(rec->ivindex_string);
    g_free(rec->ivindex);
    g_free(rec->privacykey);
    g_free(rec->encryptionkey);
}

UAT_CSTRING_CB_DEF(uat_btmesh_records, network_key_string, uat_btmesh_record_t)
UAT_CSTRING_CB_DEF(uat_btmesh_records, application_key_string, uat_btmesh_record_t)
UAT_CSTRING_CB_DEF(uat_btmesh_records, ivindex_string, uat_btmesh_record_t)

static gboolean
uat_btmesh_dev_key_record_update_cb(void *r, char **err _U_)
{
    uat_btmesh_dev_key_record_t *rec = (uat_btmesh_dev_key_record_t *)r;

    rec->valid = 0;

    /* Compute key & lengths once and for all */
    if (rec->device_key_string) {
        g_free(rec->device_key);
        rec->device_key_length = compute_ascii_key(&rec->device_key, rec->device_key_string);
        if (rec->device_key_length == 16) {
            rec->valid++;
        }
    } else {
        rec->device_key_length = 0;
        rec->device_key = NULL;
    }
    if (rec->src_string) {
        g_free(rec->src);
        rec->src_length = compute_ascii_key(&rec->src, rec->src_string);
        if (rec->src_length == 2) {
            rec->valid++;
        }
    } else {
        rec->src_length = 0;
        rec->src = NULL;
    }
    return TRUE;
}

static void *
uat_btmesh_dev_key_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_btmesh_dev_key_record_t *new_rec = (uat_btmesh_dev_key_record_t *)n;
    const uat_btmesh_dev_key_record_t* old_rec = (const uat_btmesh_dev_key_record_t *)o;

    memset(new_rec, 0x00, sizeof(uat_btmesh_dev_key_record_t));

    /* Copy UAT fields */
    new_rec->device_key_string = g_strdup(old_rec->device_key_string);
    new_rec->src_string = g_strdup(old_rec->src_string);

    /* Parse key and src as in an update */
    uat_btmesh_dev_key_record_update_cb(new_rec, NULL);

    return new_rec;
}

static void
uat_btmesh_dev_key_record_free_cb(void *r)
{
    uat_btmesh_dev_key_record_t *rec = (uat_btmesh_dev_key_record_t *)r;

    g_free(rec->device_key_string);
    g_free(rec->device_key);
    g_free(rec->src_string);
    g_free(rec->src);
}

UAT_CSTRING_CB_DEF(uat_btmesh_dev_key_records, device_key_string, uat_btmesh_dev_key_record_t)
UAT_CSTRING_CB_DEF(uat_btmesh_dev_key_records, src_string, uat_btmesh_dev_key_record_t)

static gboolean
uat_btmesh_label_uuid_record_update_cb(void *r, char **err _U_)
{
    uat_btmesh_label_uuid_record_t *rec = (uat_btmesh_label_uuid_record_t *)r;

    rec->valid = 0;

    /* Compute label UUID & lengths */
    if (rec->label_uuid_string) {
        g_free(rec->label_uuid);
        rec->label_uuid_length = compute_ascii_key(&rec->label_uuid, rec->label_uuid_string);
        if (label_uuid_hash(rec)) {
            rec->valid++;
        }
    } else {
        rec->label_uuid_length = 0;
        rec->label_uuid = NULL;
    }
    return TRUE;
}

static void *
uat_btmesh_label_uuid_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_btmesh_label_uuid_record_t *new_rec = (uat_btmesh_label_uuid_record_t *)n;
    const uat_btmesh_label_uuid_record_t* old_rec = (const uat_btmesh_label_uuid_record_t *)o;

    memset(new_rec, 0x00, sizeof(uat_btmesh_label_uuid_record_t));

    /* Copy UAT field */
    new_rec->label_uuid_string = g_strdup(old_rec->label_uuid_string);

    /* Parse Label UUID as in an update */
    uat_btmesh_label_uuid_record_update_cb(new_rec, NULL);

    return new_rec;
}

static void
uat_btmesh_label_uuid_record_free_cb(void *r)
{
    uat_btmesh_label_uuid_record_t *rec = (uat_btmesh_label_uuid_record_t *)r;

    g_free(rec->label_uuid_string);
    g_free(rec->label_uuid);
}

UAT_CSTRING_CB_DEF(uat_btmesh_label_uuid_records, label_uuid_string, uat_btmesh_label_uuid_record_t)

void
proto_register_btmesh(void)
{
    static hf_register_info hf[] = {
        { &hf_btmesh_ivi,
            { "IVI", "btmesh.ivi",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_nid,
            { "NID", "btmesh.nid",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_obfuscated,
            { "Obfuscated", "btmesh.obfuscated",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_encrypted,
            { "Encrypted data and NetMIC", "btmesh.encrypted",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_netmic,
            { "NetMIC", "btmesh.netmic",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_ctl,
            { "CTL", "btmesh.ctl",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctl_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_ttl,
            { "TTL", "btmesh.ttl",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_seq,
            { "SEQ", "btmesh.seq",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_src,
            { "SRC", "btmesh.src",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_dst,
            { "DST", "btmesh.dst",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_transp_pdu,
            { "TransportPDU", "btmesh.transp_pdu",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_seg,
            { "SEG", "btmesh.cntr.seg",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctrl_seg_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_seg,
            { "SEG", "btmesh.acc.seg",
                FT_UINT8, BASE_DEC, VALS(btmesh_acc_seg_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_opcode,
            { "Opcode", "btmesh.cntr.opcode",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctrl_opcode_vals), 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_akf,
            { "AKF", "btmesh.acc.akf",
                FT_UINT8, BASE_DEC, VALS(btmesh_acc_akf_vals), 0x40,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_aid,
            { "AID", "btmesh.acc.aid",
                FT_UINT8, BASE_DEC, NULL, 0x3f,
                NULL, HFILL }
        },
        { &hf_btmesh_obo,
            { "OBO", "btmesh.obo",
                FT_BOOLEAN, 16, TFS(&btmesh_obo), 0x8000,
                NULL, HFILL }
        },
        { &hf_btmesh_seqzero,
            { "SeqZero", "btmesh.seqzero",
                FT_UINT16, BASE_DEC, NULL, 0x7ffc,
                NULL, HFILL }
        },
        { &hf_btmesh_rfu,
            { "Reserved for Future Use", "btmesh.rfu",
                FT_UINT16, BASE_DEC, NULL, 0x0003,
                NULL, HFILL }
        },
        { &hf_btmesh_blockack,
            { "BlockAck", "btmesh.blockack",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_rfu,
            { "RFU", "btmesh.cntr.criteria.rfu",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_padding,
            { "Padding", "btmesh.cntr.padding",
                FT_UINT8, BASE_DEC, NULL, 0xfe,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_fsn,
            { "Friend Sequence Number(FSN)", "btmesh.cntr.fsn",
                FT_UINT8, BASE_DEC, NULL, 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_key_refresh_flag,
            { "Key Refresh Flag", "btmesh.cntr.keyrefreshflag",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_key_refresh_flag_vals), 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_iv_update_flag,
            { "IV Update Flag", "btmesh.cntr.ivupdateflag",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_iv_update_flag_vals), 0x02,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_flags_rfu,
            { "IV Update Flag", "btmesh.cntr.flagsrfu",
                FT_UINT8, BASE_DEC, NULL, 0xFC,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_iv_index,
            { "IV Index", "btmesh.cntr.ivindex",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_md,
            { "MD (More Data)", "btmesh.cntr.md",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_md_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_rssifactor,
            { "RSSIFactor", "btmesh.cntr.criteria.rssifactor",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_rssifactor_vals), 0x60,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_receivewindowfactor,
            { "ReceiveWindowFactor", "btmesh.cntr.criteria.receivewindowfactor",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_receivewindowfactor_vals), 0x18,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_minqueuesizelog,
            { "MinQueueSizeLog", "btmesh.cntr.criteria.minqueuesizelog",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_minqueuesizelog_vals), 0x07,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_receivedelay,
            { "ReceiveDelay", "btmesh.cntr.receivedelay",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_polltimeout,
            { "PollTimeout", "btmesh.cntr.polltimeout",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_previousaddress,
            { "PreviousAddress", "btmesh.cntr.previousaddress",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_numelements,
            { "NumElements", "btmesh.cntr.numelements",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_lpncounter,
            { "LPNCounter", "btmesh.cntr.lpncounter",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_receivewindow,
            { "ReceiveWindow", "btmesh.cntr.receivewindow",
                FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_queuesize,
            { "QueueSize", "btmesh.cntr.queuesize",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_subscriptionlistsize,
            { "SubscriptionListSize", "btmesh.cntr.subscriptionlistsize",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_rssi,
            { "RSSI", "btmesh.cntr.rssi",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_friendcounter,
            { "FriendCounter", "btmesh.cntr.friendcounter",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_lpnaddress,
            { "LPNAddress", "btmesh.cntr.lpnaddress",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_transactionnumber,
            { "TransactionNumber", "btmesh.cntr.transactionnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_heartbeat_rfu,
            { "Reserved for Future Use", "btmesh.cntr.heartbeatrfu",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_init_ttl,
            { "InitTTL", "btmesh.cntr.initttl",
                FT_UINT8, BASE_DEC, NULL, 0x7F,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_relay,
            { "Relay feature in use", "btmesh.cntr.feature.relay",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0001,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_proxy,
            { "Proxy feature in use", "btmesh.cntr.feature.proxy",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0002,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_friend,
            { "Friend feature in use", "btmesh.cntr.feature.friend",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0004,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_low_power,
            { "Low Power feature in use", "btmesh.cntr.feature.lowpower",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0008,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_rfu,
            { "Reserved for Future Use", "btmesh.cntr.feature.rfu",
                FT_UINT16, BASE_DEC, NULL, 0xfff0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_unknown_payload,
        { "Unknown Control Message payload", "btmesh.cntr.unknownpayload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_enc_access_pld,
        { "Encrypted Access Payload", "btmesh.enc_access_pld",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_transtmic,
        { "TransMIC", "btmesh.transtmic",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_szmic,
        { "SZMIC", "btmesh.szmic",
            FT_UINT24, BASE_DEC, VALS(btmesh_szmic_vals), 0x800000,
            NULL, HFILL }
        },
        { &hf_btmesh_seqzero_data,
        { "SeqZero", "btmesh.seqzero_data",
            FT_UINT24, BASE_DEC, NULL, 0x7ffc00,
            NULL, HFILL }
        },
        { &hf_btmesh_sego,
        { "Segment Offset number(SegO)", "btmesh.sego",
            FT_UINT24, BASE_DEC, NULL, 0x0003e0,
            NULL, HFILL }
        },
        { &hf_btmesh_segn,
        { "Last Segment number(SegN)", "btmesh.segn",
            FT_UINT24, BASE_DEC, NULL, 0x00001f,
            NULL, HFILL }
        },
        { &hf_btmesh_seg_rfu,
        { "RFU", "btmesh.seg.rfu",
            FT_UINT24, BASE_DEC, NULL, 0x800000,
            NULL, HFILL }
        },
        { &hf_btmesh_segment,
        { "Segment", "btmesh.segment",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        /* Access Message Reassembly */
        { &hf_btmesh_segmented_access_fragments,
            { "Reassembled Segmented Access Message Fragments", "btmesh.segmented.access.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Segmented Access Message Fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment,
            { "Segmented Access Message Fragment", "btmesh.segmented.access.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_overlap,
            { "Fragment overlap", "btmesh.segmented.access.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "btmesh.segmented.access.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_multiple_tails,
            { "Multiple tail fragments found", "btmesh.segmented.access.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_too_long_fragment,
            { "Fragment too long", "btmesh.segmented.access.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_error,
            { "Defragmentation error", "btmesh.segmented.access.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_count,
            { "Fragment count", "btmesh.segmented.access.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_access_reassembled_length,
            { "Reassembled Segmented Access Message length", "btmesh.segmented.access.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
        /* Control Message Reassembly */
        { &hf_btmesh_segmented_control_fragments,
            { "Reassembled Segmented Control Message Fragments", "btmesh.segmented.control.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Segmented Access Message Fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment,
            { "Segmented Control Message Fragment", "btmesh.segmented.control.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_overlap,
            { "Fragment overlap", "btmesh.segmented.control.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "btmesh.segmented.control.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_multiple_tails,
            { "Multiple tail fragments found", "btmesh.segmented.control.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_too_long_fragment,
            { "Fragment too long", "btmesh.segmented.control.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_error,
            { "Defragmentation error", "btmesh.segmented.control.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_count,
            { "Fragment count", "btmesh.segmented.control.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_control_reassembled_length,
            { "Reassembled Segmented Control Message length", "btmesh.segmented.control.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
        { &hf_btmesh_decrypted_access,
            { "Decrypted Access", "btmesh.access.decrypted",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_vendor_opcode,
            { "Opcode", "btmesh.model.vendor.opcode",
                FT_UINT8, BASE_DEC, NULL, 0x3f,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_vendor,
            { "Opcode", "btmesh.model.vendor",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_opcode,
            { "Opcode", "btmesh.model.opcode",
                FT_UINT16, BASE_HEX, VALS(btmesh_models_opcode_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_parameters,
            { "Parameters", "btmesh.model.parameters",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        /* Config Model opcodes parameters */
        { &hf_btmesh_config_appkey_add_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_add.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_add.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_add.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_add_appkey,
            { "AppKey", "btmesh.model.config_appkey_add.appkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_update.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_update.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_update.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_appkey,
            { "AppKey", "btmesh.model.config_appkey_update.appkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_page,
            { "Page", "btmesh.model.config_composition_data_status.page",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_cid,
            { "CID", "btmesh.model.config_composition_data_status.cid",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_pid,
            { "PID", "btmesh.model.config_composition_data_status.pid",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_vid,
            { "VID", "btmesh.model.config_composition_data_status.vid",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_crpl,
            { "CRPL", "btmesh.model.config_composition_data_status.crpl",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_relay,
            { "Relay feature", "btmesh.model.config_composition_data_status.features.relay",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_proxy,
            { "Proxy feature", "btmesh.model.config_composition_data_status.features.proxy",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0002,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_friend,
            { "Friend feature", "btmesh.model.config_composition_data_status.features.friend",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0004,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_low_power,
            { "Low Power feature", "btmesh.model.config_composition_data_status.features.low_power",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0008,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_rfu,
            { "RFU", "btmesh.model.config_composition_data_status.features.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features,
            { "Features", "btmesh.model.config_composition_data_status.features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_loc,
            { "Loc", "btmesh.model.config_composition_data_status.loc",
            FT_UINT16, BASE_HEX, VALS(characteristic_presentation_namespace_description_btsig_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_nums,
            { "NumS", "btmesh.model.config_composition_data_status.nums",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_numv,
            { "NumV", "btmesh.model.config_composition_data_status.numv",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_sig_model,
            { "SIG Model", "btmesh.model.config_composition_data_status.sig_model",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_vendor_model,
            { "Vendor Model", "btmesh.model.config_composition_data_status.vendor_model",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_set.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishaddress,
            { "PublishAddress", "btmesh.model.config_model_publication_set.publishaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_appkey,
            { "AppKeyIndex", "btmesh.model.config_model_publication_set.appkey",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_publish_appkeyindex_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_publication_set.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_credentialflag,
            { "CredentialFlag", "btmesh.model.config_model_publication_set.credentialflag",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0x1000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_rfu,
            { "RFU", "btmesh.model.config_model_publication_set.rfu",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0xE000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishttl,
            { "PublishTTL", "btmesh.model.config_model_publication_set.publishttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishperiod,
            { "PublishPeriod", "btmesh.model.config_model_publication_set.publishperiod",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishperiod_resolution,
            { "Step Resolution", "btmesh.model.config_model_publication_set.publishperiod.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishperiod_steps,
            { "Number of Steps", "btmesh.model.config_model_publication_set.publishperiod.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishretransmit,
            { "PublishRetransmit", "btmesh.model.config_model_publication_set.publishretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishretransmit_count,
            { "PublishRetransmitCount", "btmesh.model.config_model_publication_set.publishretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishretransmit_intervalsteps,
            { "PublishRetransmitIntervalSteps", "btmesh.model.config_model_publication_set.publishretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_set.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_set.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_current_status_test_id,
            { "Test ID", "btmesh.model.health_current_status.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_current_status_company_id,
            { "Company ID", "btmesh.model.health_current_status.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_current_status_fault,
            { "Fault", "btmesh.model.health_current_status.fault",
            FT_UINT8, BASE_DEC, VALS(btmesh_fault_array_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_status_test_id,
            { "Test ID", "btmesh.model.health_fault_status.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_status_company_id,
            { "Company ID", "btmesh.model.health_fault_status.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_status_fault,
            { "Fault", "btmesh.model.health_fault_status.fault",
            FT_UINT8, BASE_DEC, VALS(btmesh_fault_array_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_status,
            { "Status", "btmesh.model.config_heartbeat_publication_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_destination,
            { "Destination", "btmesh.model.config_heartbeat_publication_status.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_countlog,
            { "CountLog", "btmesh.model.config_heartbeat_publication_status.countlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_publication_status.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_ttl,
            { "TTL", "btmesh.model.config_heartbeat_publication_status.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_relay,
            { "Relay feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.relay",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_proxy,
            { "Proxy feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.proxy",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0002,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_friend,
            { "Friend feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.friend",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0004,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_low_power,
            { "Low Power feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.low_power",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0008,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_status.features.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features,
            { "Features", "btmesh.model.config_heartbeat_publication_status.features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_status.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_status.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_status.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_delete.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_delete.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_delete.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_get_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_appkey_get.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_get_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_appkey_get.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_get_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_appkey_get.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_status,
            { "Status", "btmesh.model.config_appkey_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_appkey_list.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_appkey_list.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_appkey_list.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_appkey_list.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_appkey_list.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_status,
            { "Status", "btmesh.model.config_appkey_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_status.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_status.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_status.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_health_attention_set_attention,
            { "Attention", "btmesh.model.health_attention_set.attention",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_attention_set_unacknowledged_attention,
            { "Attention", "btmesh.model.health_attention_set_unacknowledged.attention",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_attention_status_attention,
            { "Attention", "btmesh.model.health_attention_status.attention",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_get_page,
            { "Page", "btmesh.model.config_composition_data_get.page",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_beacon_set_beacon,
            { "Beacon", "btmesh.model.config_beacon_set.beacon",
            FT_UINT8, BASE_DEC, VALS(btmesh_beacon_broadcast_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_beacon_status_beacon,
            { "Beacon", "btmesh.model.config_beacon_status.beacon",
            FT_UINT8, BASE_DEC, VALS(btmesh_beacon_broadcast_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_default_ttl_set_ttl,
            { "TTL", "btmesh.model.config_default_ttl_set.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_default_ttl_status_ttl,
            { "TTL", "btmesh.model.config_default_ttl_status.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_friend_set_friend,
            { "Friend", "btmesh.model.config_friend_set.friend",
            FT_UINT8, BASE_DEC, VALS(btmesh_friend_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_friend_status_friend,
            { "Friend", "btmesh.model.config_friend_status.friend",
            FT_UINT8, BASE_DEC, VALS(btmesh_friend_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_gatt_proxy_set_gattproxy,
            { "GATTProxy", "btmesh.model.config_gatt_proxy_set.gattproxy",
            FT_UINT8, BASE_HEX, VALS(btmesh_gatt_proxy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_gatt_proxy_status_gattproxy,
            { "GATTProxy", "btmesh.model.config_gatt_proxy_status.gattproxy",
            FT_UINT8, BASE_HEX, VALS(btmesh_gatt_proxy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_get_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_get.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_get_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_get.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_get_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_key_refresh_phase_get.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_set.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_set.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_key_refresh_phase_set.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_transition,
            { "Transition", "btmesh.model.config_key_refresh_phase_set.transition",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(btmesh_transition_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_status,
            { "Status", "btmesh.model.config_key_refresh_phase_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_status.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_status.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_key_refresh_phase_status.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_phase,
            { "Phase", "btmesh.model.config_key_refresh_phase_status.phase",
            FT_UINT8, BASE_DEC, VALS(btmesh_phase_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_get.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_get_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_get.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_status,
            { "Status", "btmesh.model.config_model_publication_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_status.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishaddress,
            { "PublishAddress", "btmesh.model.config_model_publication_status.publishaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_appkey,
            { "AppKeyIndex", "btmesh.model.config_model_publication_status.appkey",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_publish_appkeyindex_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_publication_status.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_credentialflag,
            { "CredentialFlag", "btmesh.model.config_model_publication_status.credentialflag",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0x1000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_rfu,
            { "RFU", "btmesh.model.config_model_publication_status.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishttl,
            { "PublishTTL", "btmesh.model.config_model_publication_status.publishttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishperiod,
            { "PublishPeriod", "btmesh.model.config_model_publication_status.publishperiod",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishperiod_resolution,
            { "Step Resolution", "btmesh.model.config_model_publication_status.publishperiod.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishperiod_steps,
            { "Number of Steps", "btmesh.model.config_model_publication_status.publishperiod.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishretransmit,
            { "PublishRetransmit", "btmesh.model.config_model_publication_status.publishretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishretransmit_count,
            { "PublishRetransmitCount", "btmesh.model.config_model_publication_status.publishretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishretransmit_intervalsteps,
            { "PublishRetransmitIntervalSteps", "btmesh.model.config_model_publication_status.publishretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_status.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_status.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_virtual_address_set.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishaddress,
            { "PublishAddress", "btmesh.model.config_model_publication_virtual_address_set.publishaddress",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_appkey,
            { "AppKeyIndex", "btmesh.model.config_model_publication_virtual_address_set.appkey",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_publish_appkeyindex_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_publication_virtual_address_set.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_credentialflag,
            { "CredentialFlag", "btmesh.model.config_model_publication_virtual_address_set.credentialflag",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0x1000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_rfu,
            { "RFU", "btmesh.model.config_model_publication_virtual_address_set.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishttl,
            { "PublishTTL", "btmesh.model.config_model_publication_virtual_address_set.publishttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishperiod,
            { "PublishPeriod", "btmesh.model.config_model_publication_virtual_address_set.publishperiod",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishperiod_resolution,
            { "Step Resolution", "btmesh.model.config_model_publication_virtual_address_set.publishperiod.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishperiod_steps,
            { "Number of Steps", "btmesh.model.config_model_publication_virtual_address_set.publishperiod.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishretransmit,
            { "PublishRetransmit", "btmesh.model.config_model_publication_virtual_address_set.publishretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_count,
            { "PublishRetransmitCount", "btmesh.model.config_model_publication_virtual_address_set.publishretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_intervalsteps,
            { "PublishRetransmitIntervalSteps", "btmesh.model.config_model_publication_virtual_address_set.publishretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_virtual_address_set.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_virtual_address_set.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_add.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_address,
            { "Address", "btmesh.model.config_model_subscription_add.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_add.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_add.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_delete.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_address,
            { "Address", "btmesh.model.config_model_subscription_delete.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_all_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_delete_all.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_all_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete_all.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_all_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete_all.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_overwrite.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_address,
            { "Address", "btmesh.model.config_model_subscription_overwrite.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_overwrite.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_overwrite.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_status,
            { "Status", "btmesh.model.config_model_subscription_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_status.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_address,
            { "Address", "btmesh.model.config_model_subscription_status.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_status.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_status.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_virtual_address_add.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_label,
            { "Label", "btmesh.model.config_model_subscription_virtual_address_add.label",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_add.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_add.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_virtual_address_delete.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_label,
            { "Label", "btmesh.model.config_model_subscription_virtual_address_delete.label",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_delete.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_delete.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_virtual_address_overwrite.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_label,
            { "Label", "btmesh.model.config_model_subscription_virtual_address_overwrite.label",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_overwrite.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_overwrite.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_set_networktransmit,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_set.networktransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_transmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_set_networktransmit_count,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_set.networktransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_set_networktransmit_intervalsteps,
            { "NetworkTransmitIntervalSteps", "btmesh.model.config_network_transmit_set.networktransmitinterval.steps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_status_networktransmit,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_status.networktransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_transmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_status_networktransmit_count,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_status.networktransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_status_networktransmit_intervalsteps,
            { "NetworkTransmitIntervalSteps", "btmesh.model.config_network_transmit_status.networktransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relay,
            { "Relay", "btmesh.model.config_relay_set.relay",
            FT_UINT8, BASE_DEC, VALS(btmesh_relay_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relayretransmit,
            { "RelayRetransmitCount", "btmesh.model.config_relay_set.relayretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relayretransmit_count,
            { "RelayRetransmitCount", "btmesh.model.config_relay_set.relayretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relayretransmit_intervalsteps,
            { "RelayRetransmitIntervalSteps", "btmesh.model.config_relay_set.relayretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relay,
            { "Relay", "btmesh.model.config_relay_status.relay",
            FT_UINT8, BASE_DEC, VALS(btmesh_relay_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relayretransmit,
            { "RelayRetransmit", "btmesh.model.config_relay_status.relayretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relayretransmit_count,
            { "RelayRetransmitCount", "btmesh.model.config_relay_status.relayretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relayretransmit_intervalsteps,
            { "RelayRetransmitIntervalSteps", "btmesh.model.config_relay_status.relayretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_subscription_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_subscription_get.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_status,
            { "Status", "btmesh.model.config_sig_model_subscription_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_subscription_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_subscription_list.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_address,
            { "Address", "btmesh.model.config_sig_model_subscription_list.address",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_subscription_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_subscription_get.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_status,
            { "Status", "btmesh.model.config_vendor_model_subscription_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_subscription_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_subscription_list.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_address,
            { "Address", "btmesh.model.config_vendor_model_subscription_list.address",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_low_power_node_polltimeout_get_lpnaddress,
            { "LPNAddress", "btmesh.model.config_low_power_node_polltimeout_get.lpnaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_low_power_node_polltimeout_status_lpnaddress,
            { "LPNAddress", "btmesh.model.config_low_power_node_polltimeout_status.lpnaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_low_power_node_polltimeout_status_polltimeout,
            { "PollTimeout", "btmesh.model.config_low_power_node_polltimeout_status.polltimeout",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_clear_company_id,
            { "Company ID", "btmesh.model.health_fault_clear.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_clear_unacknowledged_company_id,
            { "Company ID", "btmesh.model.health_fault_clear_unacknowledged.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_get_company_id,
            { "Company ID", "btmesh.model.health_fault_get.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_test_id,
            { "Test ID", "btmesh.model.health_fault_test.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_company_id,
            { "Company ID", "btmesh.model.health_fault_test.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_unacknowledged_test_id,
            { "Test ID", "btmesh.model.health_fault_test_unacknowledged.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_unacknowledged_company_id,
            { "Company ID", "btmesh.model.health_fault_test_unacknowledged.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_period_set_fastperioddivisor,
            { "FastPeriodDivisor", "btmesh.model.health_period_set.fastperioddivisor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_period_set_unacknowledged_fastperioddivisor,
            { "FastPeriodDivisor", "btmesh.model.health_period_set_unacknowledged.fastperioddivisor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_period_status_fastperioddivisor,
            { "FastPeriodDivisor", "btmesh.model.health_period_status.fastperioddivisor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_destination,
            { "Destination", "btmesh.model.config_heartbeat_publication_set.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_countlog,
            { "CountLog", "btmesh.model.config_heartbeat_publication_set.countlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_publication_set.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_ttl,
            { "TTL", "btmesh.model.config_heartbeat_publication_set.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_relay,
            { "Relay feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.relay",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_proxy,
            { "Proxy feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.proxy",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0002,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_friend,
            { "Friend feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.friend",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0004,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_low_power,
            { "Low Power feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.low_power",
            FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0008,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_set.features.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features,
            { "Features", "btmesh.model.config_heartbeat_publication_set.features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_set.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_set.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_set.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_set_source,
            { "Source", "btmesh.model.config_heartbeat_subscription_set.source",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_set_destination,
            { "Destination", "btmesh.model.config_heartbeat_subscription_set.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_set_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_subscription_set.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_status,
            { "Status", "btmesh.model.config_heartbeat_subscription_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_source,
            { "Source", "btmesh.model.config_heartbeat_subscription_status.source",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_destination,
            { "Destination", "btmesh.model.config_heartbeat_subscription_status.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_subscription_status.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_countlog,
            { "CountLog", "btmesh.model.config_heartbeat_subscription_status.countlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_minhops,
            { "MinHops", "btmesh.model.config_heartbeat_subscription_status.minhops",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_maxhops,
            { "MaxHops", "btmesh.model.config_heartbeat_subscription_status.maxhops",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_app_bind.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_app_bind.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_appkeyindex_idx,
            { "AppKeyIndex", "btmesh.model.config_model_app_bind.appkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_model_app_bind.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_bind.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_bind.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_status,
            { "Status", "btmesh.model.config_model_app_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_app_status.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_app_status.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_appkeyindex_idx,
            { "AppKeyIndex", "btmesh.model.config_model_app_status.appkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_model_app_status.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_status.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_status.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_app_unbind.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_app_unbind.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_appkeyindex_idx,
            { "AppKeyIndex", "btmesh.model.config_model_app_unbind.appkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_appkeyindex_rfu,
            { "AppKeyIndex", "btmesh.model.config_model_app_unbind.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_unbind.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_unbind.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_add.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_add.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_add.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkey,
            { "NetKey", "btmesh.model.config_netkey_add.netkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_delete_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_delete.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_delete_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_delete.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_delete_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_delete.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_list_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_list.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_list_netkeyindex_rfu,
            { "NetKeyIndex RFU", "btmesh.model.config_netkey_list.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_status,
            { "Status", "btmesh.model.config_netkey_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_status.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_status.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_status.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_update.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_update.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_update.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkey,
            { "NetKey", "btmesh.model.config_netkey_update.netkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_get_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_node_identity_get.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_get_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_node_identity_get.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_get_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_node_identity_get.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_node_identity_set.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_node_identity_set.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_node_identity_set.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_identity,
            { "Identity", "btmesh.model.config_node_identity_set.identity",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_status,
            { "Status", "btmesh.model.config_node_identity_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_node_identity_status.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_node_identity_status.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_node_identity_status.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_identity,
            { "Identity", "btmesh.model.config_node_identity_status.identity",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_app_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_app_get.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_status,
            { "Status", "btmesh.model.config_sig_model_app_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_app_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_app_list.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_sig_model_app_list.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_sig_model_app_list.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_app_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_app_get.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_status,
            { "Status", "btmesh.model.config_vendor_model_app_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_app_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_app_list.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_vendor_model_app_list.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_vendor_model_app_list.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
};

    static gint *ett[] = {
        &ett_btmesh,
        &ett_btmesh_net_pdu,
        &ett_btmesh_transp_pdu,
        &ett_btmesh_transp_ctrl_msg,
        &ett_btmesh_upper_transp_acc_pdu,
        &ett_btmesh_segmented_access_fragments,
        &ett_btmesh_segmented_access_fragment,
        &ett_btmesh_segmented_control_fragments,
        &ett_btmesh_segmented_control_fragment,
        &ett_btmesh_access_pdu,
        &ett_btmesh_model_layer,
        &ett_btmesh_config_model_netapp_index,
        &ett_btmesh_config_model_publishperiod,
        &ett_btmesh_config_model_publishretransmit,
        &ett_btmesh_config_model_relayretransmit,
        &ett_btmesh_config_model_network_transmit,
        &ett_btmesh_config_model_element,
        &ett_btmesh_config_model_model,
        &ett_btmesh_config_model_vendor,
        &ett_btmesh_config_composition_data_status_features,
        &ett_btmesh_config_model_pub_app_index,
        &ett_btmesh_config_model_addresses,
        &ett_btmesh_config_model_netkey_list,
        &ett_btmesh_config_model_appkey_list,
        &ett_btmesh_config_model_net_index,
        &ett_btmesh_config_model_app_index,
        &ett_btmesh_config_heartbeat_publication_set_features,
        &ett_btmesh_config_heartbeat_publication_status_features,
        &ett_btmesh_config_model_fault_array,
    };

    static ei_register_info ei[] = {
        { &ei_btmesh_not_decoded_yet,{ "btmesh.not_decoded_yet", PI_PROTOCOL, PI_NOTE, "Not decoded yet", EXPFILL } },
        { &ei_btmesh_unknown_payload,{ "btmesh.unknown_payload", PI_PROTOCOL, PI_ERROR, "Unknown Payload", EXPFILL } },
    };

    expert_module_t* expert_btmesh;

    module_t *btmesh_module;

    /* UAT Net Key and App Key definitions */
    static uat_field_t btmesh_uat_flds[] = {
        UAT_FLD_CSTRING(uat_btmesh_records, network_key_string, "Network Key", "Network Key"),
        UAT_FLD_CSTRING(uat_btmesh_records, application_key_string, "Application Key", "Application Key"),
        UAT_FLD_CSTRING(uat_btmesh_records, ivindex_string, "IVindex", "IVindex"),
        UAT_END_FIELDS
    };

    /* UAT Device Key definition */
    static uat_field_t btmesh_dev_key_uat_flds[] = {
        UAT_FLD_CSTRING(uat_btmesh_dev_key_records, device_key_string, "Device Key", "Device Key"),
        UAT_FLD_CSTRING(uat_btmesh_dev_key_records, src_string, "SRC Address", "SRC Address"),
        UAT_END_FIELDS
    };

    /* UAT Label UUID definition */
    static uat_field_t btmesh_label_uuid_uat_flds[] = {
        UAT_FLD_CSTRING(uat_btmesh_label_uuid_records, label_uuid_string, "Label UUID", "Label UUID"),
        UAT_END_FIELDS
    };

    proto_btmesh = proto_register_protocol("Bluetooth Mesh", "BT Mesh", "btmesh");

    proto_register_field_array(proto_btmesh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btmesh = expert_register_protocol(proto_btmesh);
    expert_register_field_array(expert_btmesh, ei, array_length(ei));

    btmesh_module = prefs_register_protocol_subtree("Bluetooth", proto_btmesh, NULL);

    prefs_register_static_text_preference(btmesh_module, "version",
            "Bluetooth Mesh Profile v1.0",
            "Version of protocol supported by this dissector.");

    btmesh_uat = uat_new("BTMesh Network and Application keys",
        sizeof(uat_btmesh_record_t),    /* record size */
        "btmesh_nw_keys",               /* filename */
        TRUE,                           /* from_profile */
        &uat_btmesh_records,            /* data_ptr */
        &num_btmesh_uat,                /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
        NULL,                           /* help */
        uat_btmesh_record_copy_cb,      /* copy callback */
        uat_btmesh_record_update_cb,    /* update callback */
        uat_btmesh_record_free_cb,      /* free callback */
        NULL,                           /* post update callback */
        NULL,                           /* reset callback */
        btmesh_uat_flds);               /* UAT field definitions */

    prefs_register_uat_preference(btmesh_module,
        "mesh_keys_table",
        "Mesh Keys",
        "Configured Mesh Keys",
        btmesh_uat);

    btmesh_dev_key_uat = uat_new("BTMesh Device keys",
        sizeof(uat_btmesh_dev_key_record_t),  /* record size */
        "btmesh_dev_keys",                    /* filename */
        TRUE,                                 /* from_profile */
        &uat_btmesh_dev_key_records,          /* data_ptr */
        &num_btmesh_dev_key_uat,              /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,               /* affects dissection of packets, but not set of named fields */
        NULL,                                 /* help */
        uat_btmesh_dev_key_record_copy_cb,    /* copy callback */
        uat_btmesh_dev_key_record_update_cb,  /* update callback */
        uat_btmesh_dev_key_record_free_cb,    /* free callback */
        NULL,                                 /* post update callback */
        NULL,                                 /* reset callback */
        btmesh_dev_key_uat_flds);             /* UAT field definitions */

    prefs_register_uat_preference(btmesh_module,
        "mesh_dev_key_table",
        "Device Keys",
        "Configured Mesh Device Keys",
        btmesh_dev_key_uat);

    btmesh_label_uuid_uat = uat_new("BTMesh Label UUIDs",
        sizeof(uat_btmesh_label_uuid_record_t),  /* record size */
        "btmesh_label_uuids",                    /* filename */
        TRUE,                                    /* from_profile */
        &uat_btmesh_label_uuid_records,          /* data_ptr */
        &num_btmesh_label_uuid_uat,              /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,                  /* affects dissection of packets, but not set of named fields */
        NULL,                                    /* help */
        uat_btmesh_label_uuid_record_copy_cb,    /* copy callback */
        uat_btmesh_label_uuid_record_update_cb,  /* update callback */
        uat_btmesh_label_uuid_record_free_cb,    /* free callback */
        NULL,                                    /* post update callback */
        NULL,                                    /* reset callback */
        btmesh_label_uuid_uat_flds);             /* UAT field definitions */

    prefs_register_uat_preference(btmesh_module,
        "mesh_label_uuid_table",
        "Label UUIDs",
        "Configured Mesh Label UUIDs",
        btmesh_label_uuid_uat);

    btmesh_model_vendor_dissector_table  = register_dissector_table("btmesh.model.vendor",  "BT Mesh model vendor", proto_btmesh, FT_UINT16, BASE_DEC);

    register_dissector("btmesh.msg", dissect_btmesh_msg, proto_btmesh);

    register_init_routine(&upper_transport_init_routine);
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
