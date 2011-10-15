/* packet-wps.c
 *
 * Wifi Simple Config aka Wifi Protected Setup
 *
 * Written by Jens Braeuer using WiFi-Alliance Spec 1.0h and
 * parts of a patch by JP Jiang and Philippe Teuwen. November 2007
 *
 * Spec:
 * https://www.wi-fi.org/knowledge_center_overview.php?type=4
 * Patch:
 * http://wireshark.digimirror.nl/lists/wireshark-dev/200703/msg00121.html
 *
 * Copyright 2007 Jens Braeuer <jensb@cs.tu-berlin.de>
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>

#include "packet-wps.h"

static int   hf_eapwps_opcode     = -1;
static int   hf_eapwps_flags      = -1;
static int   hf_eapwps_flag_mf    = -1;
static int   hf_eapwps_flag_lf    = -1;
static int   hf_eapwps_msglen     = -1;

static gint ett_eap_wps_attr      = -1;
static gint ett_eap_wps_flags     = -1;

/* OPCodes */
#define OPC_WSC_START    0x01   /* WPS OPCODE WSC_Start */
#define OPC_WSC_ACK      0x02   /* WPS OPCODE WSC_ACK */
#define OPC_WSC_NACK     0x03   /* WPS OPCODE WSC_NACK */
#define OPC_WSC_MSG      0x04   /* WPS OPCODE WSC_MSG */
#define OPC_WSC_DONE     0x05   /* WPS OPCODE WSC_Done */
#define OPC_WSC_FRAG_ACK 0x06   /* WPS OPCODE WSC_FRAG_ACK */

static const value_string eapwps_opcode_vals[] = {
  { OPC_WSC_START,    "WSC Start"},
  { OPC_WSC_ACK,      "WSC Ack"},
  { OPC_WSC_NACK,     "WSC Nack" },
  { OPC_WSC_MSG,      "WSC Msg" },
  { OPC_WSC_DONE,     "WSC Done" },
  { OPC_WSC_FRAG_ACK, "WSC Frag Ack" },
  { 0, NULL }
};

/*  Flag-Field masks  */
#define MASK_WSC_FLAG_MF   0x01 /* WPS Flag more frag */
#define MASK_WSC_FLAG_LF   0x02 /* WPS flag length field */

#define WPS_TLV_TYPE_AP_CHANNEL                         0x1001
#define WPS_TLV_TYPE_ASSOCIATION_STATE                  0x1002
#define WPS_TLV_TYPE_AUTHENTICATION_TYPE                0x1003
#define WPS_TLV_TYPE_AUTHENTICATION_TYPE_FLAGS          0x1004
#define WPS_TLV_TYPE_AUTHENTICATOR                      0x1005
#define WPS_TLV_TYPE_CONFIG_METHODS                     0x1008
#define WPS_TLV_TYPE_CONFIGURATION_ERROR                0x1009
#define WPS_TLV_TYPE_CONFIRMATION_URL4                  0x100a
#define WPS_TLV_TYPE_CONFIRMATION_URL6                  0x100b
#define WPS_TLV_TYPE_CONNECTION_TYPE                    0x100c
#define WPS_TLV_TYPE_CONNECTION_TYPE_FLAGS              0x100d
#define WPS_TLV_TYPE_CREDENTIAL                         0x100e
#define WPS_TLV_TYPE_DEVICE_NAME                        0x1011
#define WPS_TLV_TYPE_DEVICE_PASSWORD_ID                 0x1012
#define WPS_TLV_TYPE_E_HASH1                            0X1014
#define WPS_TLV_TYPE_E_HASH2                            0x1015
#define WPS_TLV_TYPE_E_SNONCE1                          0x1016
#define WPS_TLV_TYPE_E_SNONCE2                          0x1017
#define WPS_TLV_TYPE_ENCRYPTED_SETTINGS                 0x1018
#define WPS_TLV_TYPE_ENCRYPTION_TYPE                    0x100f
#define WPS_TLV_TYPE_ENCRYPTION_TYPE_FLAGS              0x1010
#define WPS_TLV_TYPE_ENROLLEE_NONCE                     0x101a
#define WPS_TLV_TYPE_FEATURE_ID                         0x101b
#define WPS_TLV_TYPE_IDENTITY                           0x101c
#define WPS_TLV_TYPE_IDENTITY_PROOF                     0x101d
#define WPS_TLV_TYPE_KEY_WRAP_AUTHENTICATOR             0x101e
#define WPS_TLV_TYPE_KEY_IDENTIFIER                     0x101f
#define WPS_TLV_TYPE_MAC_ADDRESS                        0x1020
#define WPS_TLV_TYPE_MANUFACTURER                       0x1021
#define WPS_TLV_TYPE_MESSAGE_TYPE                       0x1022
#define WPS_TLV_TYPE_MODEL_NAME                         0x1023
#define WPS_TLV_TYPE_MODEL_NUMBER                       0x1024
#define WPS_TLV_TYPE_NETWORK_INDEX                      0x1026
#define WPS_TLV_TYPE_NETWORK_KEY                        0x1027
#define WPS_TLV_TYPE_NETWORK_KEY_INDEX                  0x1028
#define WPS_TLV_TYPE_NEW_DEVICE_NAME                    0x1029
#define WPS_TLV_TYPE_NEW_PASSWORD                       0x102a
#define WPS_TLV_TYPE_OOB_DEVICE_PASSWORD                0x102c
#define WPS_TLV_TYPE_OS_VERSION                         0x102d
#define WPS_TLV_TYPE_POWER_LEVEL                        0x102f
#define WPS_TLV_TYPE_PSK_CURRENT                        0x1030
#define WPS_TLV_TYPE_PSK_MAX                            0x1031
#define WPS_TLV_TYPE_PUBLIC_KEY                         0x1032
#define WPS_TLV_TYPE_RADIO_ENABLED                      0x1033
#define WPS_TLV_TYPE_REBOOT                             0x1034
#define WPS_TLV_TYPE_REGISTRAR_CURRENT                  0x1035
#define WPS_TLV_TYPE_REGISTRAR_ESTABLISHED              0x1036
#define WPS_TLV_TYPE_REGISTRAR_LIST                     0x1037
#define WPS_TLV_TYPE_REGISTRAR_MAX                      0x1038
#define WPS_TLV_TYPE_REGISTRAR_NONCE                    0x1039
#define WPS_TLV_TYPE_REQUEST_TYPE                       0x103a
#define WPS_TLV_TYPE_RESPONSE_TYPE                      0x103b
#define WPS_TLV_TYPE_RF_BANDS                           0x103c
#define WPS_TLV_TYPE_R_HASH1                            0x103d
#define WPS_TLV_TYPE_R_HASH2                            0x103e
#define WPS_TLV_TYPE_R_SNONCE1                          0x103f
#define WPS_TLV_TYPE_R_SNONCE2                          0x1040
#define WPS_TLV_TYPE_SELECTED_REGISTRAR                 0x1041
#define WPS_TLV_TYPE_SERIAL_NUMBER                      0x1042
#define WPS_TLV_TYPE_WIFI_PROTECTED_SETUP_STATE         0x1044
#define WPS_TLV_TYPE_SSID                               0x1045
#define WPS_TLV_TYPE_TOTAL_NETWORKS                     0x1046
#define WPS_TLV_TYPE_UUID_E                             0x1047
#define WPS_TLV_TYPE_UUID_R                             0x1048
#define WPS_TLV_TYPE_VENDOR_EXTENSION                   0x1049
#define WPS_TLV_TYPE_VERSION                            0x104a
#define WPS_TLV_TYPE_X509_CERTIFICATE_REQUEST           0x104b
#define WPS_TLV_TYPE_X509_CERTIFICATE                   0x104c
#define WPS_TLV_TYPE_EAP_IDENTITY                       0x104d
#define WPS_TLV_TYPE_MESSAGE_COUNTER                    0x104e
#define WPS_TLV_TYPE_PUBLIC_KEY_HASH                    0x104f
#define WPS_TLV_TYPE_REKEY_KEY                          0x1050
#define WPS_TLV_TYPE_KEY_LIFETIME                       0x1051
#define WPS_TLV_TYPE_PERMITTED_CONFIG_METHODS           0x1052
#define WPS_TLV_TYPE_SELECTED_REGISTRAR_CONFIG_METHODS  0x1053
#define WPS_TLV_TYPE_PRIMARY_DEVICE_TYPE                0x1054
#define WPS_TLV_TYPE_SECONDARY_DEVICE_TYPE_LIST         0x1055
#define WPS_TLV_TYPE_PORTABLE_DEVICE                    0x1056
#define WPS_TLV_TYPE_AP_SETUP_LOCKED                    0x1057
#define WPS_TLV_TYPE_APPLICATION_EXTENSION              0x1058
#define WPS_TLV_TYPE_EAP_TYPE                           0x1059
#define WPS_TLV_TYPE_INITIALIZATION_VECTOR              0x1060
#define WPS_TLV_TYPE_KEY_PROVIDED_AUTOMATICALLY         0x1061
#define WPS_TLV_TYPE_8021X_ENABLED                      0x1062
#define WPS_TLV_TYPE_APPSESSIONKEY                      0x1063
#define WPS_TLV_TYPE_WEPTRANSMITKEY                     0x1064
#define WPS_TLV_TYPE_REQUESTED_DEV_TYPE                 0x106a


static const value_string eapwps_tlv_types[] = {
  { WPS_TLV_TYPE_AP_CHANNEL,                        "AP Channel" },
  { WPS_TLV_TYPE_ASSOCIATION_STATE,                 "Association State" },
  { WPS_TLV_TYPE_AUTHENTICATION_TYPE,               "Authentication Type" },
  { WPS_TLV_TYPE_AUTHENTICATION_TYPE_FLAGS,         "Authentication Type Flags" },
  { WPS_TLV_TYPE_AUTHENTICATOR,                     "Authenticator" },
  { WPS_TLV_TYPE_CONFIG_METHODS,                    "Config Methods" },
  { WPS_TLV_TYPE_CONFIGURATION_ERROR,               "Configuration Error" },
  { WPS_TLV_TYPE_CONFIRMATION_URL4,                 "Confirmation URL4" },
  { WPS_TLV_TYPE_CONFIRMATION_URL6,                 "Confirmation URL6" },
  { WPS_TLV_TYPE_CONNECTION_TYPE,                   "Connection Type" },
  { WPS_TLV_TYPE_CONNECTION_TYPE_FLAGS,             "Connection Type Flags" },
  { WPS_TLV_TYPE_CREDENTIAL,                        "Credential" },
  { WPS_TLV_TYPE_DEVICE_NAME,                       "Device Name" },
  { WPS_TLV_TYPE_DEVICE_PASSWORD_ID,                "Device Password ID" },
  { WPS_TLV_TYPE_E_HASH1,                           "E Hash1" },
  { WPS_TLV_TYPE_E_HASH2,                           "E Hash2" },
  { WPS_TLV_TYPE_E_SNONCE1,                         "E SNonce1" },
  { WPS_TLV_TYPE_E_SNONCE2,                         "E SNonce2" },
  { WPS_TLV_TYPE_ENCRYPTED_SETTINGS,                "Encrypted Settings" },
  { WPS_TLV_TYPE_ENCRYPTION_TYPE,                   "Encryption Type" },
  { WPS_TLV_TYPE_ENCRYPTION_TYPE_FLAGS,             "Encryption Type Flags" },
  { WPS_TLV_TYPE_ENROLLEE_NONCE,                    "Enrollee Nonce" },
  { WPS_TLV_TYPE_FEATURE_ID,                        "Feature Id" },
  { WPS_TLV_TYPE_IDENTITY,                          "Identity" },
  { WPS_TLV_TYPE_IDENTITY_PROOF,                    "Identity Proof" },
  { WPS_TLV_TYPE_KEY_WRAP_AUTHENTICATOR,            "Key Wrap Authenticator" },
  { WPS_TLV_TYPE_KEY_IDENTIFIER,                    "Key Identifier" },
  { WPS_TLV_TYPE_MAC_ADDRESS,                       "MAC Address" },
  { WPS_TLV_TYPE_MANUFACTURER,                      "Manufacturer" },
  { WPS_TLV_TYPE_MESSAGE_TYPE,                      "Message Type" },
  { WPS_TLV_TYPE_MODEL_NAME,                        "Model Name" },
  { WPS_TLV_TYPE_MODEL_NUMBER,                      "Model Number" },
  { WPS_TLV_TYPE_NETWORK_INDEX,                     "Network Index" },
  { WPS_TLV_TYPE_NETWORK_KEY,                       "Network Key" },
  { WPS_TLV_TYPE_NETWORK_KEY_INDEX,                 "Network Key Index" },
  { WPS_TLV_TYPE_NEW_DEVICE_NAME,                   "New Device Name" },
  { WPS_TLV_TYPE_NEW_PASSWORD,                      "New Password" },
  { WPS_TLV_TYPE_OOB_DEVICE_PASSWORD,               "OOB Device Password" },
  { WPS_TLV_TYPE_OS_VERSION,                        "OS Version" },
  { WPS_TLV_TYPE_POWER_LEVEL,                       "Power Level" },
  { WPS_TLV_TYPE_PSK_CURRENT,                       "PSK Current" },
  { WPS_TLV_TYPE_PSK_MAX,                           "PSK Max" },
  { WPS_TLV_TYPE_PUBLIC_KEY,                        "Public Key" },
  { WPS_TLV_TYPE_RADIO_ENABLED,                     "Radio Enabled" },
  { WPS_TLV_TYPE_REBOOT,                            "Reboot" },
  { WPS_TLV_TYPE_REGISTRAR_CURRENT,                 "Registrar Current" },
  { WPS_TLV_TYPE_REGISTRAR_ESTABLISHED,             "Registrar Established" },
  { WPS_TLV_TYPE_REGISTRAR_LIST,                    "Registrar List" },
  { WPS_TLV_TYPE_REGISTRAR_MAX,                     "registrar_max" },
  { WPS_TLV_TYPE_REGISTRAR_NONCE,                   "Registrar Nonce" },
  { WPS_TLV_TYPE_REQUEST_TYPE,                      "Request Type" },
  { WPS_TLV_TYPE_RESPONSE_TYPE,                     "Response Type" },
  { WPS_TLV_TYPE_RF_BANDS,                          "RF Bands" },
  { WPS_TLV_TYPE_R_HASH1,                           "R Hash1" },
  { WPS_TLV_TYPE_R_HASH2,                           "R Hash2" },
  { WPS_TLV_TYPE_R_SNONCE1,                         "R Snonce1" },
  { WPS_TLV_TYPE_R_SNONCE2,                         "R Snonce2" },
  { WPS_TLV_TYPE_SELECTED_REGISTRAR,                "Selected Registrar" },
  { WPS_TLV_TYPE_SERIAL_NUMBER,                     "Serial Number" },
  { WPS_TLV_TYPE_WIFI_PROTECTED_SETUP_STATE,        "Wifi Protected Setup State" },
  { WPS_TLV_TYPE_SSID,                              "SSID" },
  { WPS_TLV_TYPE_TOTAL_NETWORKS,                    "Total Networks" },
  { WPS_TLV_TYPE_UUID_E,                            "UUID E" },
  { WPS_TLV_TYPE_UUID_R,                            "UUID R" },
  { WPS_TLV_TYPE_VENDOR_EXTENSION,                  "Vendor Extension" },
  { WPS_TLV_TYPE_VERSION,                           "Version" },
  { WPS_TLV_TYPE_X509_CERTIFICATE_REQUEST,          "X509 Certificate Request" },
  { WPS_TLV_TYPE_X509_CERTIFICATE,                  "X509 Certificate" },
  { WPS_TLV_TYPE_EAP_IDENTITY,                      "EAP Identity" },
  { WPS_TLV_TYPE_MESSAGE_COUNTER,                   "Message Counter" },
  { WPS_TLV_TYPE_PUBLIC_KEY_HASH,                   "Public Key Hash" },
  { WPS_TLV_TYPE_REKEY_KEY,                         "Rekey Key" },
  { WPS_TLV_TYPE_KEY_LIFETIME,                      "Key Lifetime" },
  { WPS_TLV_TYPE_PERMITTED_CONFIG_METHODS,          "Permitted Config Methods" },
  { WPS_TLV_TYPE_SELECTED_REGISTRAR_CONFIG_METHODS, "Selected Registrar Config Methods" },
  { WPS_TLV_TYPE_PRIMARY_DEVICE_TYPE,               "Primary Device Type" },
  { WPS_TLV_TYPE_SECONDARY_DEVICE_TYPE_LIST,        "Secondary Device Type List" },
  { WPS_TLV_TYPE_PORTABLE_DEVICE,                   "Portable Device" },
  { WPS_TLV_TYPE_AP_SETUP_LOCKED,                   "Ap Setup Locked" },
  { WPS_TLV_TYPE_APPLICATION_EXTENSION,             "Application Extension" },
  { WPS_TLV_TYPE_EAP_TYPE,                          "EAP Type" },
  { WPS_TLV_TYPE_INITIALIZATION_VECTOR,             "Initialization Vector" },
  { WPS_TLV_TYPE_KEY_PROVIDED_AUTOMATICALLY,        "Key Provided Automatically" },
  { WPS_TLV_TYPE_8021X_ENABLED,                     "8021x Enabled" },
  { WPS_TLV_TYPE_APPSESSIONKEY,                     "AppSessionKey" },
  { WPS_TLV_TYPE_WEPTRANSMITKEY,                    "WEPTransmitKey" },
  { WPS_TLV_TYPE_REQUESTED_DEV_TYPE,                "Requested Device Type" },
  { 0, NULL }
};


/* WFA Vendor Extension */

#define WPS_WFA_EXT_VERSION2              0x00
#define WPS_WFA_EXT_AUTHORIZEDMACS        0x01
#define WPS_WFA_EXT_NETWORK_KEY_SHAREABLE 0x02
#define WPS_WFA_EXT_REQUEST_TO_ENROLL     0x03
#define WPS_WFA_EXT_SETTINGS_DELAY_TIME   0x04

static const value_string eapwps_wfa_ext_types[] = {
  { WPS_WFA_EXT_VERSION2,              "Version2" },
  { WPS_WFA_EXT_AUTHORIZEDMACS,        "AuthorizedMACs" },
  { WPS_WFA_EXT_NETWORK_KEY_SHAREABLE, "Network Key Shareable" },
  { WPS_WFA_EXT_REQUEST_TO_ENROLL,     "Request to Enroll" },
  { WPS_WFA_EXT_SETTINGS_DELAY_TIME,   "Settings Delay Time" },
  { 0, NULL }
};
#define WFA_OUI             0x0050F204

static int proto_wps = -1;

static int hf_eapwps_tlv_type   = -1;
static int hf_eapwps_tlv_len    = -1;

static int hf_eapwps_tlv_ap_channel = -1;
static int hf_eapwps_tlv_association_state = -1;
static int hf_eapwps_tlv_authentication_type = -1;
static int hf_eapwps_tlv_authentication_type_flags = -1;
static int hf_eapwps_tlv_authentication_type_flags_open = -1;
static int hf_eapwps_tlv_authentication_type_flags_wpapsk = -1;
static int hf_eapwps_tlv_authentication_type_flags_shared = -1;
static int hf_eapwps_tlv_authentication_type_flags_wpa = -1;
static int hf_eapwps_tlv_authentication_type_flags_wpa2 = -1;
static int hf_eapwps_tlv_authentication_type_flags_wpa2psk = -1;
static int hf_eapwps_tlv_authenticator = -1;
static int hf_eapwps_tlv_config_methods = -1;
static int hf_eapwps_tlv_config_methods_usba = -1;
static int hf_eapwps_tlv_config_methods_ethernet = -1;
static int hf_eapwps_tlv_config_methods_label = -1;
static int hf_eapwps_tlv_config_methods_display = -1;
static int hf_eapwps_tlv_config_methods_phy_display = -1;
static int hf_eapwps_tlv_config_methods_virt_display = -1;
static int hf_eapwps_tlv_config_methods_nfcext = -1;
static int hf_eapwps_tlv_config_methods_nfcint = -1;
static int hf_eapwps_tlv_config_methods_nfcinf = -1;
static int hf_eapwps_tlv_config_methods_pushbutton = -1;
static int hf_eapwps_tlv_config_methods_phy_pushbutton = -1;
static int hf_eapwps_tlv_config_methods_virt_pushbutton = -1;
static int hf_eapwps_tlv_config_methods_keypad = -1;
static int hf_eapwps_tlv_configuration_error = -1;
static int hf_eapwps_tlv_confirmation_url4 = -1;
static int hf_eapwps_tlv_confirmation_url6 = -1;
static int hf_eapwps_tlv_connection_type = -1;
static int hf_eapwps_tlv_connection_type_flags = -1;
static int hf_eapwps_tlv_connection_type_flags_ess = -1;
static int hf_eapwps_tlv_connection_type_flags_ibss = -1;
static int hf_eapwps_tlv_credential = -1;
static int hf_eapwps_tlv_device_name = -1;
static int hf_eapwps_tlv_device_password_id = -1;
static int hf_eapwps_tlv_e_hash1 = -1;
static int hf_eapwps_tlv_e_hash2 = -1;
static int hf_eapwps_tlv_e_snonce1 = -1;
static int hf_eapwps_tlv_e_snonce2 = -1;
static int hf_eapwps_tlv_encrypted_settings = -1;
static int hf_eapwps_tlv_encryption_type = -1;
static int hf_eapwps_tlv_encryption_type_flags = -1;
static int hf_eapwps_tlv_encryption_type_flags_none = -1;
static int hf_eapwps_tlv_encryption_type_flags_wep = -1;
static int hf_eapwps_tlv_encryption_type_flags_tkip = -1;
static int hf_eapwps_tlv_encryption_type_flags_aes = -1;
static int hf_eapwps_tlv_enrollee_nonce = -1;
static int hf_eapwps_tlv_feature_id = -1;
static int hf_eapwps_tlv_identity = -1;
static int hf_eapwps_tlv_identity_proof = -1;
static int hf_eapwps_tlv_key_wrap_authenticator = -1;
static int hf_eapwps_tlv_key_identifier = -1;
static int hf_eapwps_tlv_mac_address = -1;
static int hf_eapwps_tlv_manufacturer = -1;
static int hf_eapwps_tlv_message_type = -1;
static int hf_eapwps_tlv_model_name = -1;
static int hf_eapwps_tlv_model_number = -1;
static int hf_eapwps_tlv_network_index = -1;
static int hf_eapwps_tlv_network_key = -1;
static int hf_eapwps_tlv_network_key_index = -1;
static int hf_eapwps_tlv_new_device_name = -1;
static int hf_eapwps_tlv_new_password = -1;
static int hf_eapwps_tlv_oob_device_password = -1;
static int hf_eapwps_tlv_os_version = -1;
static int hf_eapwps_tlv_power_level = -1;
static int hf_eapwps_tlv_psk_current = -1;
static int hf_eapwps_tlv_psk_max = -1;
static int hf_eapwps_tlv_public_key = -1;
static int hf_eapwps_tlv_radio_enabled = -1;
static int hf_eapwps_tlv_reboot = -1;
static int hf_eapwps_tlv_registrar_current = -1;
static int hf_eapwps_tlv_registrar_established = -1;
static int hf_eapwps_tlv_registrar_list = -1;
static int hf_eapwps_tlv_registrar_max = -1;
static int hf_eapwps_tlv_registrar_nonce = -1;
static int hf_eapwps_tlv_request_type = -1;
static int hf_eapwps_tlv_response_type = -1;
static int hf_eapwps_tlv_rf_bands = -1;
static int hf_eapwps_tlv_r_hash1 = -1;
static int hf_eapwps_tlv_r_hash2 = -1;
static int hf_eapwps_tlv_r_snonce1 = -1;
static int hf_eapwps_tlv_r_snonce2 = -1;
static int hf_eapwps_tlv_selected_registrar = -1;
static int hf_eapwps_tlv_serial_number = -1;
static int hf_eapwps_tlv_wifi_protected_setup_state = -1;
static int hf_eapwps_tlv_ssid = -1;
static int hf_eapwps_tlv_total_networks = -1;
static int hf_eapwps_tlv_uuid_e = -1;
static int hf_eapwps_tlv_uuid_r = -1;
static int hf_eapwps_tlv_vendor_extension = -1;
static int hf_eapwps_tlv_version = -1;
static int hf_eapwps_tlv_x509_certificate_request = -1;
static int hf_eapwps_tlv_x509_certificate = -1;
static int hf_eapwps_tlv_eap_identity = -1;
static int hf_eapwps_tlv_message_counter = -1;
static int hf_eapwps_tlv_public_key_hash = -1;
static int hf_eapwps_tlv_rekey_key = -1;
static int hf_eapwps_tlv_key_lifetime = -1;
static int hf_eapwps_tlv_permitted_config_methods = -1;
static int hf_eapwps_tlv_selected_registrar_config_methods = -1;
static int hf_eapwps_tlv_primary_device_type = -1;
static int hf_eapwps_tlv_primary_device_type_category = -1;
#define WPS_DEVICE_TYPE_CATEGORY_MAX 11
static int hf_eapwps_tlv_primary_device_type_subcategory[WPS_DEVICE_TYPE_CATEGORY_MAX] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
static int hf_eapwps_tlv_secondary_device_type_list = -1;
static int hf_eapwps_tlv_portable_device = -1;
static int hf_eapwps_tlv_ap_setup_locked = -1;
static int hf_eapwps_tlv_application_extension = -1;
static int hf_eapwps_tlv_eap_type = -1;
static int hf_eapwps_tlv_initialization_vector = -1;
static int hf_eapwps_tlv_key_provided_automatically = -1;
static int hf_eapwps_tlv_8021x_enabled = -1;
static int hf_eapwps_tlv_appsessionkey = -1;
static int hf_eapwps_tlv_weptransmitkey = -1;
static int hf_eapwps_tlv_requested_dev_type = -1;

static int hf_eapwps_vendor_id = -1;
static int hf_eapwps_wfa_ext_id = -1;
static int hf_eapwps_wfa_ext_len = -1;

static int hf_eapwps_wfa_ext_version2 = -1;
static int hf_eapwps_wfa_ext_authorizedmacs = -1;
static int hf_eapwps_wfa_ext_network_key_shareable = -1;
static int hf_eapwps_wfa_ext_request_to_enroll = -1;
static int hf_eapwps_wfa_ext_settings_delay_time = -1;

static gint ett_wps_tlv = -1;
static gint ett_eap_wps_ap_channel = -1;
static gint ett_eap_wps_association_state = -1;
static gint ett_eap_wps_authentication_type = -1;
static gint ett_eap_wps_authentication_type_flags = -1;
static gint ett_eap_wps_authenticator = -1;
static gint ett_eap_wps_config_methods = -1;
static gint ett_eap_wps_configuration_error = -1;
static gint ett_eap_wps_confirmation_url4 = -1;
static gint ett_eap_wps_confirmation_url6 = -1;
static gint ett_eap_wps_connection_type = -1;
static gint ett_eap_wps_connection_type_flags = -1;
static gint ett_eap_wps_credential = -1;
static gint ett_eap_wps_device_name = -1;
static gint ett_eap_wps_device_password_id = -1;
static gint ett_eap_wps_e_hash1 = -1;
static gint ett_eap_wps_e_hash2 = -1;
static gint ett_eap_wps_e_snonce1 = -1;
static gint ett_eap_wps_e_snonce2 = -1;
static gint ett_eap_wps_encrypted_settings = -1;
static gint ett_eap_wps_encryption_type = -1;
static gint ett_eap_wps_encryption_type_flags = -1;
static gint ett_eap_wps_enrollee_nonce = -1;
static gint ett_eap_wps_feature_id = -1;
static gint ett_eap_wps_identity = -1;
static gint ett_eap_wps_identity_proof = -1;
static gint ett_eap_wps_key_wrap_authenticator = -1;
static gint ett_eap_wps_key_identifier = -1;
static gint ett_eap_wps_mac_address = -1;
static gint ett_eap_wps_manufacturer = -1;
static gint ett_eap_wps_message_type = -1;
static gint ett_eap_wps_model_name = -1;
static gint ett_eap_wps_model_number = -1;
static gint ett_eap_wps_network_index = -1;
static gint ett_eap_wps_network_key = -1;
static gint ett_eap_wps_network_key_index = -1;
static gint ett_eap_wps_new_device_name = -1;
static gint ett_eap_wps_new_password = -1;
static gint ett_eap_wps_oob_device_password = -1;
static gint ett_eap_wps_os_version = -1;
static gint ett_eap_wps_power_level = -1;
static gint ett_eap_wps_psk_current = -1;
static gint ett_eap_wps_psk_max = -1;
static gint ett_eap_wps_public_key = -1;
static gint ett_eap_wps_radio_enabled = -1;
static gint ett_eap_wps_reboot = -1;
static gint ett_eap_wps_registrar_current = -1;
static gint ett_eap_wps_registrar_established = -1;
static gint ett_eap_wps_registrar_list = -1;
static gint ett_eap_wps_registrar_max = -1;
static gint ett_eap_wps_registrar_nonce = -1;
static gint ett_eap_wps_request_type = -1;
static gint ett_eap_wps_response_type = -1;
static gint ett_eap_wps_rf_bands = -1;
static gint ett_eap_wps_r_hash1 = -1;
static gint ett_eap_wps_r_hash2 = -1;
static gint ett_eap_wps_r_snonce1 = -1;
static gint ett_eap_wps_r_snonce2 = -1;
static gint ett_eap_wps_selected_registrar = -1;
static gint ett_eap_wps_serial_number = -1;
static gint ett_eap_wps_wifi_protected_setup_state = -1;
static gint ett_eap_wps_ssid = -1;
static gint ett_eap_wps_total_networks = -1;
static gint ett_eap_wps_uuid_e = -1;
static gint ett_eap_wps_uuid_r = -1;
static gint ett_eap_wps_vendor_extension = -1;
static gint ett_eap_wps_version = -1;
static gint ett_eap_wps_x509_certificate_request = -1;
static gint ett_eap_wps_x509_certificate = -1;
static gint ett_eap_wps_eap_identity = -1;
static gint ett_eap_wps_message_counter = -1;
static gint ett_eap_wps_public_key_hash = -1;
static gint ett_eap_wps_rekey_key = -1;
static gint ett_eap_wps_key_lifetime = -1;
static gint ett_eap_wps_permitted_config_methods = -1;
static gint ett_eap_wps_selected_registrar_config_methods = -1;
static gint ett_eap_wps_primary_device_type = -1;
static gint ett_eap_wps_secondary_device_type_list = -1;
static gint ett_eap_wps_portable_device = -1;
static gint ett_eap_wps_ap_setup_locked = -1;
static gint ett_eap_wps_application_extension = -1;
static gint ett_eap_wps_eap_type = -1;
static gint ett_eap_wps_initialization_vector = -1;
static gint ett_eap_wps_key_provided_automatically = -1;
static gint ett_eap_wps_8021x_enabled = -1;
static gint ett_eap_wps_appsessionkey = -1;
static gint ett_eap_wps_weptransmitkey = -1;
static gint ett_wps_wfa_ext = -1;

static const value_string eapwps_tlv_association_state_vals[] = {
  { 0, "Not associated" },
  { 1, "Connection success" },
  { 2, "Configuration Failure" },
  { 3, "Association Failure" },
  { 4, "IP Failure" },
  { 0, NULL }
};

#define EAPWPS_AUTHTYPE_OPEN    0x1
#define EAPWPS_AUTHTYPE_WPAPSK  0x2
#define EAPWPS_AUTHTYPE_SHARED  0x4
#define EAPWPS_AUTHTYPE_WPA     0x8
#define EAPWPS_AUTHTYPE_WPA2    0x10
#define EAPWPS_AUTHTYPE_WPA2PSK 0x20

static const value_string eapwps_tlv_authentication_type_vals[] = {
  { EAPWPS_AUTHTYPE_OPEN,    "Open" },
  { EAPWPS_AUTHTYPE_WPA2PSK, "WPA PSK" },
  { EAPWPS_AUTHTYPE_SHARED,  "Shared" },
  { EAPWPS_AUTHTYPE_WPA,     "WPA" },
  { EAPWPS_AUTHTYPE_WPA2,    "WPA2" },
  { EAPWPS_AUTHTYPE_WPA2PSK, "WPA2 PSK" },
  { 0, NULL }
};

#define EAPWPS_CONFMETH_USBA             0x1
#define EAPWPS_CONFMETH_ETHERNET         0x2
#define EAPWPS_CONFMETH_LABEL            0x4
#define EAPWPS_CONFMETH_DISPLAY          0x8
#define EAPWPS_CONFMETH_VIRT_DISPLAY     0x2000
#define EAPWPS_CONFMETH_PHY_DISPLAY      0x4000
#define EAPWPS_CONFMETH_NFCEXT           0x10
#define EAPWPS_CONFMETH_NFCINT           0x20
#define EAPWPS_CONFMETH_NFCINF           0x40
#define EAPWPS_CONFMETH_PUSHBUTTON       0x80
#define EAPWPS_CONFMETH_VIRT_PUSHBUTTON  0x200
#define EAPWPS_CONFMETH_PHY_PUSHBUTTON   0x400
#define EAPWPS_CONFMETH_KEYPAD           0x100

static const value_string eapwps_tlv_configuration_error_vals[] = {
  {  0, "No Error" },
  {  1, "OOB Interface Read Error" },
  {  2, "Decryption CRC Failure" },
  {  3, "2.4 channel not supported" },
  {  4, "5.0 channel not supported" },
  {  5, "Signal too weak" },
  {  6, "Network auth failure" },
  {  7, "Network association failure" },
  {  8, "No DHCP response" },
  {  9, "failed DHCP config" },
  { 10, "IP address conflict" },
  { 11, "Couldn't connect to Registrar" },
  { 12, "Multiple PBC sessions detected" },
  { 13, "Rogue activity suspected" },
  { 14, "Device busy" },
  { 15, "Setup locked" },
  { 16, "Message Timeout" },
  { 17, "Registration Session Timeout" },
  { 18, "Device Password Auth Failure" },
  { 0, NULL }
};

#define EAPWPS_CONNTYPE_ESS  0x1
#define EAPWPS_CONNTYPE_IBSS 0x2

static const value_string eapwps_tlv_connection_type_vals[] = {
  { EAPWPS_CONNTYPE_ESS,  "ESS" },
  { EAPWPS_CONNTYPE_IBSS, "IBSS" },
  { 0, NULL}
};

#define EAPWPS_DEVPW_PIN 0x0
#define EAPWPS_DEVPW_USER 0x1
#define EAPWPS_DEVPW_MACHINE 0x2
#define EAPWPS_DEVPW_REKEY 0x3
#define EAPWPS_DEVPW_PUSHBUTTON 0x4
#define EAPWPS_DEVPW_REGISTRAR 0x5

static const value_string eapwps_tlv_device_password_id_vals[] = {
  { EAPWPS_DEVPW_PIN,  "PIN (default)" },
  { EAPWPS_DEVPW_USER,  "User specified" },
  { EAPWPS_DEVPW_MACHINE,  "Machine specified" },
  { EAPWPS_DEVPW_REKEY,  "Rekey" },
  { EAPWPS_DEVPW_PUSHBUTTON,  "PushButton" },
  { EAPWPS_DEVPW_REGISTRAR,  "Registrar specified" },
  { 0, NULL }
};

#define EAPWPS_ENCTYPE_NONE 0x1
#define EAPWPS_ENCTYPE_WEP  0x2
#define EAPWPS_ENCTYPE_TKIP 0x4
#define EAPWPS_ENCTYPE_AES  0x8

static const value_string eapwps_tlv_encryption_type_vals[] = {
  { EAPWPS_ENCTYPE_NONE, "none" },
  { EAPWPS_ENCTYPE_WEP,  "WEP" },
  { EAPWPS_ENCTYPE_TKIP, "TKIP" },
  { EAPWPS_ENCTYPE_AES,  "AES" },
  { 0, NULL }
};

static const value_string eapwps_tlv_message_type_vals[] = {
  { 0x01, "Beacon" },
  { 0x02, "Probe Request" },
  { 0x03, "Probe Response" },
  { 0x04, "M1" },
  { 0x05, "M2" },
  { 0x06, "M2D" },
  { 0x07, "M3" },
  { 0x08, "M4" },
  { 0x09, "M5" },
  { 0x0A, "M6" },
  { 0x0B, "M7" },
  { 0x0C, "M8" },
  { 0x0D, "WSC_ACK" },
  { 0x0E, "WSC_NACK" },
  { 0x0F, "WSC_DONE" },
  { 0, NULL }
};


static const value_string eapwps_tlv_request_type_vals[] = {
  { 0x00, "Enrollee, Info only" },
  { 0x01, "Enrollee, open 802.1X" },
  { 0x02, "Registrar" },
  { 0x03, "WLAN Manager Registrar" },
  { 0, NULL }
};

static const value_string eapwps_tlv_response_type_vals[] = {
  { 0x00, "Enrollee, Info only" },
  { 0x01, "Enrollee, open 802.1X" },
  { 0x02, "Registrar" },
  { 0x03, "AP" },
  { 0, NULL }
};

static const value_string eapwps_tlv_rf_bands_vals[] = {
  { 0x01, "2.4 GHz" },
  { 0x02, "5 GHz" },
  { 0x03, "2.4 and 5 GHz" },
  { 0, NULL }
};

static const value_string eapwps_tlv_wifi_protected_setup_state[] = {
  { 0x00, "Reserved" },
  { 0x01, "Not configured" },
  { 0x02, "Configured" },
  { 0, NULL }
};

static const value_string eapwps_tlv_primary_device_type_category[] = {
  { 0x01, "Computer" },
  { 0x02, "Input Device" },
  { 0x03, "Printers, Scanners, Faxes and Copiers" },
  { 0x04, "Camera" },
  { 0x05, "Storage" },
  { 0x06, "Network Infrastructure" },
  { 0x07, "Displays" },
  { 0x08, "Multimedia Devices" },
  { 0x09, "Gaming Devices" },
  { 0x0A, "Telephone" },
  { 0x0B, "Audio Devices" },
  { 0, NULL }
};

static const value_string eapwps_tlv_computer_subcategory[] = {
  { 0x01, "PC" },
  { 0x02, "Server" },
  { 0x03, "Media Center" },
  { 0x04, "Ultra-mobile PC" },
  { 0x05, "Notebook" },
  { 0x06, "Desktop" },
  { 0x07, "MID (Mobile Internet Device)" },
  { 0x08, "Netbook" },
  { 0, NULL }
};

static const value_string eapwps_tlv_input_device_subcategory[] = {
  { 0x01, "Keyboard" },
  { 0x02, "Mouse" },
  { 0x03, "Joystick" },
  { 0x04, "Trackball" },
  { 0x05, "Gaming controller" },
  { 0x06, "Remote" },
  { 0x07, "Touchscreen" },
  { 0x08, "Biometric reader" },
  { 0x09, "Barcode reader" },
  { 0, NULL }
};

static const value_string eapwps_tlv_printers_scanners_faxes_copiers_subcategory[] = {
  { 0x01, "Printer or Print Server" },
  { 0x02, "Scanner" },
  { 0x03, "Fax" },
  { 0x04, "Copier" },
  { 0x05, "All-in-one (Printer, Scanner, Fax, Copier)" },
  { 0, NULL }
};

static const value_string eapwps_tlv_camera_subcategory[] = {
  { 0x01, "Digital Still Camera" },
  { 0x02, "Video Camera" },
  { 0x03, "Web Camera" },
  { 0x04, "Security Camera" },
  { 0, NULL }
};

static const value_string eapwps_tlv_storage_subcategory[] = {
  { 0x01, "NAS" },
  { 0, NULL }
};

static const value_string eapwps_tlv_network_infrastructure_subcategory[] = {
  { 0x01, "AP" },
  { 0x02, "Router" },
  { 0x03, "Switch" },
  { 0x04, "Gateway" },
  { 0x05, "Bridge" },
  { 0, NULL }
};

static const value_string eapwps_tlv_displays_subcategory[] = {
  { 0x01, "Television" },
  { 0x02, "Electronic Picture Frame" },
  { 0x03, "Projector" },
  { 0x04, "Monitor" },
  { 0, NULL }
};

static const value_string eapwps_tlv_multimedia_devices_subcategory[] = {
  { 0x01, "DAR" },
  { 0x02, "PVR" },
  { 0x03, "MCX" },
  { 0x04, "Set-top box" },
  { 0x05, "Media Server/Media Adapter/Media Extender" },
  { 0x06, "Portable Video Player" },
  { 0, NULL }
};

static const value_string eapwps_tlv_gaming_devices_subcategory[] = {
  { 0x01, "Xbox" },
  { 0x02, "Xbox360" },
  { 0x03, "Playstation" },
  { 0x04, "Game Console/Game Console Adapter" },
  { 0x05, "Portable Gaming Device" },
  { 0, NULL }
};

static const value_string eapwps_tlv_telephone_subcategory[] = {
  { 0x01, "Windows Mobile" },
  { 0x02, "Phone - single mode" },
  { 0x03, "Phone - dual mode" },
  { 0x04, "Smartphone - single mode" },
  { 0x05, "Smartphone - dual mode" },
  { 0, NULL }
};

static const value_string eapwps_tlv_audio_devices_subcategory[] = {
  { 0x01, "Audio tuner/receiver" },
  { 0x02, "Speakers" },
  { 0x03, "Portable Music Player (PMP)" },
  { 0x04, "Headset (headphones + microphone)" },
  { 0x05, "Headphones" },
  { 0x06, "Microphone" },
  { 0x07, "Home Theater Systems" },
  { 0, NULL }
};

/*  ********************************************************************** */
/*  pinfo may be NULL ! */
/*  ********************************************************************** */
static void
dissect_wps_config_methods(proto_tree *root, tvbuff_t* tvb, int offset,
                           gint _U_ size, packet_info _U_ *pinfo)
{
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_usba,            tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_ethernet,        tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_label,           tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_display,         tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_virt_display,    tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_phy_display,     tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_nfcext,          tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_nfcint,          tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_nfcinf,          tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_pushbutton,      tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_virt_pushbutton, tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_phy_pushbutton,  tvb, offset+4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(root, hf_eapwps_tlv_config_methods_keypad,          tvb, offset+4, 2, ENC_BIG_ENDIAN);
}

static void add_wps_wfa_ext(guint8 id, proto_tree *tree, tvbuff_t *tvb,
                            int offset, gint size)
{
  proto_item *item;
  proto_tree *elem;
  guint8 val8;

  item = proto_tree_add_text(tree, tvb, offset - 2, 2 + size, "%s",
                             val_to_str(id, eapwps_wfa_ext_types,
                                        "Unknown (%u)"));
  elem = proto_item_add_subtree(item, ett_wps_wfa_ext);
  proto_tree_add_item(elem, hf_eapwps_wfa_ext_id,  tvb, offset - 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(elem, hf_eapwps_wfa_ext_len, tvb, offset - 1, 1, ENC_BIG_ENDIAN);

  switch (id) {
  case WPS_WFA_EXT_VERSION2:
    val8 = tvb_get_guint8(tvb, offset);
    proto_item_append_text(item, ": %d.%d", val8 >> 4, val8 & 0x0f);
    proto_tree_add_item(elem, hf_eapwps_wfa_ext_version2, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    break;
  case WPS_WFA_EXT_AUTHORIZEDMACS:
    proto_tree_add_item(elem, hf_eapwps_wfa_ext_authorizedmacs,
                        tvb, offset, size, ENC_NA);
    break;
  case WPS_WFA_EXT_NETWORK_KEY_SHAREABLE:
    val8 = tvb_get_guint8(tvb, offset);
    proto_item_append_text(item, ": %s", val8 ? "TRUE" : "FALSE");
    proto_tree_add_item(elem, hf_eapwps_wfa_ext_network_key_shareable,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    break;
  case WPS_WFA_EXT_REQUEST_TO_ENROLL:
    val8 = tvb_get_guint8(tvb, offset);
    proto_item_append_text(item, ": %s", val8 ? "TRUE" : "FALSE");
    proto_tree_add_item(elem, hf_eapwps_wfa_ext_request_to_enroll,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    break;
  case WPS_WFA_EXT_SETTINGS_DELAY_TIME:
    val8 = tvb_get_guint8(tvb, offset);
    proto_item_append_text(item, ": %d second(s)", val8);
    proto_tree_add_item(elem, hf_eapwps_wfa_ext_settings_delay_time,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    break;
  default:
    break;
  }
}

static void dissect_wps_wfa_ext(proto_tree *tree, tvbuff_t *tvb,
                                int offset, gint size)
{
  int pos = offset;
  int end = offset + size;
  guint8 id, len;

  while (pos + 2 < end) {
    id = tvb_get_guint8(tvb, pos);
    len = tvb_get_guint8(tvb, pos + 1);
    if (pos + 2 + len > end)
      break;
    pos += 2;
    add_wps_wfa_ext(id, tree, tvb, pos, len);
    pos += len;
  }
}

static void dissect_wps_vendor_ext(proto_tree *tree, tvbuff_t *tvb,
                                   int offset, gint size)
{
  guint32 vendor_id;

  if (size < 3)
    return;
  vendor_id = tvb_get_ntoh24(tvb, offset);
  proto_tree_add_item(tree, hf_eapwps_vendor_id, tvb, offset, 3, ENC_BIG_ENDIAN);
  if (vendor_id == VENDOR_WIFI_ALLIANCE)
    dissect_wps_wfa_ext(tree, tvb, offset + 3, size - 3);
}

/* ********************************************************************** */
/*  pinfo may be NULL ! */
/* ********************************************************************** */
void
dissect_wps_tlvs(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
                gint size, packet_info* pinfo)
{
  static const char* fmt_warn_too_long = "Value to long (max. %d)";
  static const char* fmt_length_warn = "Value length not %d";

  guint16 tlv_len = 0;
  guint16 tlv_type = 0;

  proto_item* tlv_item = NULL; /* the root item */
  proto_tree* tlv_root = NULL;
  proto_item* tmp_item = NULL;

  int hfindex = -1;

  while(size > 0) {

    /* incomplete tlv-entry case */
    if (size < 4) {
      if (tmp_item != NULL && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, "Packet to short");
      break;
    }

    tlv_item = NULL;
    tlv_root = NULL;
    tmp_item = NULL;

    tlv_type = tvb_get_ntohs(tvb, offset);
    tlv_len = tvb_get_ntohs(tvb, offset+2);

    /* TOP Node for each TLV-item */
    tlv_item = proto_tree_add_text(eap_tree, tvb, offset, tlv_len+4, "Unknown Type (0x%04x)", tlv_type);
    tlv_root = proto_item_add_subtree(tlv_item, ett_wps_tlv);

    /* analog to Tagged parameters in 802.11 */
    proto_tree_add_item(tlv_root, hf_eapwps_tlv_type, tvb, offset,   2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root, hf_eapwps_tlv_len,  tvb, offset+2, 2, ENC_BIG_ENDIAN);

    switch(tlv_type) {
    case WPS_TLV_TYPE_AP_CHANNEL:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_ap_channel, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_ap_channel;

      break;

    case WPS_TLV_TYPE_ASSOCIATION_STATE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_association_state, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_association_state;

      break;

    case WPS_TLV_TYPE_AUTHENTICATION_TYPE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_authentication_type;

      break;

    case WPS_TLV_TYPE_AUTHENTICATION_TYPE_FLAGS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type_flags, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_authentication_type_flags;

      proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type_flags_open,    tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type_flags_wpapsk,  tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type_flags_shared,  tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type_flags_wpa,     tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type_flags_wpa2,    tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_authentication_type_flags_wpa2psk, tvb, offset+4, 2, ENC_BIG_ENDIAN);

      break;

    case WPS_TLV_TYPE_AUTHENTICATOR:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_authenticator, tvb, offset+4, 8, ENC_NA);
      hfindex = hf_eapwps_tlv_authenticator;

      proto_item_append_text(tmp_item, " (1st 64 bits of HMAC)");
      break;

    case WPS_TLV_TYPE_CONFIG_METHODS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_config_methods;

      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_usba,            tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_ethernet,        tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_label,           tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_display,         tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_virt_display,    tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_phy_display,     tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_nfcext,          tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_nfcint,          tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_nfcinf,          tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_pushbutton,      tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_virt_pushbutton, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_phy_pushbutton,  tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_config_methods_keypad,          tvb, offset+4, 2, ENC_BIG_ENDIAN);

      break;

    case WPS_TLV_TYPE_CONFIGURATION_ERROR:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_configuration_error, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_configuration_error;

      break;

    case WPS_TLV_TYPE_CONFIRMATION_URL4: /* max len is 64 */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_confirmation_url4, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_confirmation_url4;
      if (tlv_len > 64 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_CONFIRMATION_URL6: /* max len is 76 */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_confirmation_url6, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_confirmation_url6;
      if (tlv_len > 76 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_CONNECTION_TYPE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_connection_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_connection_type;

      break;

    case WPS_TLV_TYPE_CONNECTION_TYPE_FLAGS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_connection_type_flags, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_connection_type_flags;

      proto_tree_add_item(tlv_root, hf_eapwps_tlv_connection_type_flags_ess,  tvb, offset+4, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_connection_type_flags_ibss, tvb, offset+4, 1, ENC_BIG_ENDIAN);

      break;

    case WPS_TLV_TYPE_CREDENTIAL:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_credential, tvb, offset+4, tlv_len, FALSE);
      hfindex = hf_eapwps_tlv_credential;

      break;

    case WPS_TLV_TYPE_DEVICE_NAME: /* len <= 32, check !  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_device_name, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_device_name;
      if (tlv_len > 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_DEVICE_PASSWORD_ID:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_device_password_id, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_device_password_id;

      break;

    case WPS_TLV_TYPE_E_HASH1:
      /* assert tlv_len == 32  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_e_hash1, tvb, offset+4, 32, ENC_NA);
      hfindex = hf_eapwps_tlv_e_hash1;
      if (tlv_len != 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_length_warn, 32);

      break;

    case WPS_TLV_TYPE_E_HASH2:
      /* assert tlv_len == 32  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_e_hash2, tvb, offset+4, 32, ENC_NA);
      hfindex = hf_eapwps_tlv_e_hash2;
      if (tlv_len != 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_length_warn, 32);

      break;

    case WPS_TLV_TYPE_E_SNONCE1:
      /* assert tlv_len == 16  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_e_snonce1, tvb, offset+4, 16, ENC_NA);
      hfindex = hf_eapwps_tlv_e_snonce1;
      if (tlv_len != 16 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_length_warn, 16);

      break;

    case WPS_TLV_TYPE_E_SNONCE2:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_e_snonce2, tvb, offset+4, 16, ENC_NA);
      hfindex = hf_eapwps_tlv_e_snonce2;
      if (tlv_len != 16 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_length_warn, 16);

      break;

    case WPS_TLV_TYPE_ENCRYPTED_SETTINGS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_encrypted_settings, tvb, offset+4, tlv_len, FALSE);
      hfindex = hf_eapwps_tlv_encrypted_settings;

      break;

    case WPS_TLV_TYPE_ENCRYPTION_TYPE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_encryption_type, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_encryption_type;

      break;

    case WPS_TLV_TYPE_ENCRYPTION_TYPE_FLAGS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_encryption_type_flags, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_encryption_type_flags;

      proto_tree_add_item(tlv_root, hf_eapwps_tlv_encryption_type_flags_none,    tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_encryption_type_flags_wep,     tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_encryption_type_flags_tkip,    tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_root, hf_eapwps_tlv_encryption_type_flags_aes,     tvb, offset+4, 2, ENC_BIG_ENDIAN);

      break;

    case WPS_TLV_TYPE_ENROLLEE_NONCE:
      /* assert tlv_len == 16  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_enrollee_nonce, tvb, offset+4, 16, ENC_NA);
      hfindex = hf_eapwps_tlv_enrollee_nonce;
      if (tlv_len != 16 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_length_warn, 16);

      break;

    case WPS_TLV_TYPE_FEATURE_ID:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_feature_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_feature_id;

      break;

    case WPS_TLV_TYPE_IDENTITY:
      /* check that tlv_len <= 80  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_identity, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_identity;
      if (tlv_len > 80 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_IDENTITY_PROOF:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_identity_proof, tvb, offset+4, tlv_len, FALSE);
      hfindex = hf_eapwps_tlv_identity_proof;

      break;

    case WPS_TLV_TYPE_KEY_WRAP_AUTHENTICATOR:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_key_wrap_authenticator, tvb, offset+4, 8, ENC_NA);
      hfindex = hf_eapwps_tlv_key_wrap_authenticator;

      break;

    case WPS_TLV_TYPE_KEY_IDENTIFIER:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_key_identifier, tvb, offset+4, 16, ENC_NA);
      hfindex = hf_eapwps_tlv_key_identifier;

      break;

    case WPS_TLV_TYPE_MAC_ADDRESS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_mac_address, tvb, offset+4, 6, FALSE);
      hfindex = hf_eapwps_tlv_mac_address;

      break;

    case WPS_TLV_TYPE_MANUFACTURER:
      /* check tlv_len <= 64 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_manufacturer, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_manufacturer;
      if (tlv_len > 64 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_MESSAGE_TYPE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_message_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_message_type;
      if (pinfo != NULL && check_col(pinfo->cinfo, COL_INFO))
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(tvb_get_guint8(tvb, offset+4),
                                                                   eapwps_tlv_message_type_vals,
                                                                   "Unknown (0x%02x)"));
      break;

    case WPS_TLV_TYPE_MODEL_NAME:
      /* check tlv_len <= 32 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_model_name, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_model_name;
      if (tlv_len > 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_MODEL_NUMBER:
      /* check tlv_len <= 32 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_model_number, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_model_number;
      if (tlv_len > 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_NETWORK_INDEX:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_network_index, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_network_index;

      break;

    case WPS_TLV_TYPE_NETWORK_KEY:
      /* check tlv_len <= 64 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_network_key, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_network_key;
      if (tlv_len > 64 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_NETWORK_KEY_INDEX:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_network_key_index, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_network_key_index;

      break;

    case WPS_TLV_TYPE_NEW_DEVICE_NAME:
      /* check tlv_len <= 32 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_new_device_name, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_new_device_name;
      if (tlv_len > 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_NEW_PASSWORD:
      /* check tlv_len <= 64 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_new_password, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_new_password;
      if (tlv_len > 64 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_OOB_DEVICE_PASSWORD:
      /* check tlv_len <= 56 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_oob_device_password, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_oob_device_password;
      if (tlv_len > 56 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_OS_VERSION:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_os_version, tvb, offset+4, 4, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_os_version;

      break;

    case WPS_TLV_TYPE_POWER_LEVEL:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_power_level, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_power_level;

      break;

    case WPS_TLV_TYPE_PSK_CURRENT:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_psk_current, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_psk_current;

      break;

    case WPS_TLV_TYPE_PSK_MAX:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_psk_max, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_psk_max;

      break;

    case WPS_TLV_TYPE_PUBLIC_KEY:
      /* check tlv_len == 192 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_public_key, tvb, offset+4, 192, ENC_NA);
      hfindex = hf_eapwps_tlv_public_key;
      if (tlv_len != 192 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_length_warn, 192);

      break;

    case WPS_TLV_TYPE_RADIO_ENABLED:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_radio_enabled, tvb, offset+4, 1, FALSE);
      hfindex = hf_eapwps_tlv_radio_enabled;

      break;

    case WPS_TLV_TYPE_REBOOT:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_reboot, tvb, offset+4, 1, FALSE);
      hfindex = hf_eapwps_tlv_reboot;

      break;

    case WPS_TLV_TYPE_REGISTRAR_CURRENT:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_registrar_current, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_registrar_current;

      break;

    case WPS_TLV_TYPE_REGISTRAR_ESTABLISHED:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_registrar_established, tvb, offset+4, 1, FALSE);
      hfindex = hf_eapwps_tlv_registrar_established;

      break;

    case WPS_TLV_TYPE_REGISTRAR_LIST:
      /* NYI: list is */
      /* - 16 bytes uuid */
      /* - NULL-Terminated device name string  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_registrar_list, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_registrar_list;

      break;

    case WPS_TLV_TYPE_REGISTRAR_MAX:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_registrar_max, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_registrar_max;

      break;

    case WPS_TLV_TYPE_REGISTRAR_NONCE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_registrar_nonce, tvb, offset+4, 16, ENC_NA);
      hfindex = hf_eapwps_tlv_registrar_nonce;

      break;

    case WPS_TLV_TYPE_REQUEST_TYPE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_request_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_request_type;

      break;

    case WPS_TLV_TYPE_RESPONSE_TYPE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_response_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_response_type;

      break;

    case WPS_TLV_TYPE_RF_BANDS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_rf_bands, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_rf_bands;

      break;

    case WPS_TLV_TYPE_R_HASH1:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_r_hash1, tvb, offset+4, 32, ENC_NA);
      hfindex = hf_eapwps_tlv_r_hash1;

      break;

    case WPS_TLV_TYPE_R_HASH2:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_r_hash2, tvb, offset+4, 32, ENC_NA);
      hfindex = hf_eapwps_tlv_r_hash2;

      break;

    case WPS_TLV_TYPE_R_SNONCE1:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_r_snonce1, tvb, offset+4, 16, ENC_NA);
      hfindex = hf_eapwps_tlv_r_snonce1;

      break;

    case WPS_TLV_TYPE_R_SNONCE2:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_r_snonce2, tvb, offset+4, 16, ENC_NA);
      hfindex = hf_eapwps_tlv_r_snonce2;

      break;

    case WPS_TLV_TYPE_SELECTED_REGISTRAR:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_selected_registrar, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_selected_registrar;

      break;

    case WPS_TLV_TYPE_SERIAL_NUMBER:
      /* check tlv_len <= 32 bytes  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_serial_number, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_serial_number;
      if (tlv_len > 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_WIFI_PROTECTED_SETUP_STATE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_wifi_protected_setup_state, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_wifi_protected_setup_state;

      break;

    case WPS_TLV_TYPE_SSID:
      /* check tlv_len <= 32 bytes  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_ssid, tvb, offset+4, tlv_len, ENC_ASCII|ENC_NA);
      hfindex = hf_eapwps_tlv_ssid;
      if (tlv_len > 32 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_TOTAL_NETWORKS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_total_networks, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_total_networks;

      break;

    case WPS_TLV_TYPE_UUID_E:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_uuid_e, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_uuid_e;
      if (tlv_len > 16 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_UUID_R:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_uuid_r, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_uuid_r;
      if (tlv_len > 16 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_VENDOR_EXTENSION:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_vendor_extension, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_vendor_extension;

      break;

    case WPS_TLV_TYPE_VERSION:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_version, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_version;

      break;

    case WPS_TLV_TYPE_X509_CERTIFICATE_REQUEST:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_x509_certificate_request, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_x509_certificate_request;

      break;

    case WPS_TLV_TYPE_X509_CERTIFICATE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_x509_certificate, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_x509_certificate;

      break;

    case WPS_TLV_TYPE_EAP_IDENTITY:
      /* check tlv_len <= 64 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_eap_identity, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_eap_identity;
      if (tlv_len > 64 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_MESSAGE_COUNTER:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_message_counter, tvb, offset+4, 8, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_message_counter;

      break;

    case WPS_TLV_TYPE_PUBLIC_KEY_HASH:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_public_key_hash, tvb, offset+4, 20, ENC_NA);
      hfindex = hf_eapwps_tlv_public_key_hash;

      break;

    case WPS_TLV_TYPE_REKEY_KEY:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_rekey_key, tvb, offset+4, 32, ENC_NA);
      hfindex = hf_eapwps_tlv_rekey_key;

      break;

    case WPS_TLV_TYPE_KEY_LIFETIME:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_key_lifetime, tvb, offset+4, 4, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_key_lifetime;

      break;

    case WPS_TLV_TYPE_PERMITTED_CONFIG_METHODS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_permitted_config_methods, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_permitted_config_methods;

      dissect_wps_config_methods(tlv_root, tvb, offset, size, pinfo);

      break;

    case WPS_TLV_TYPE_SELECTED_REGISTRAR_CONFIG_METHODS:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_selected_registrar_config_methods, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_selected_registrar_config_methods;

      dissect_wps_config_methods(tlv_root, tvb, offset, size, pinfo);

      break;

    case WPS_TLV_TYPE_PRIMARY_DEVICE_TYPE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_primary_device_type, tvb, offset+4, 8, ENC_NA);
      hfindex = hf_eapwps_tlv_primary_device_type;
      if (tvb_get_ntohl(tvb, offset+6) == WFA_OUI) {
        guint16 dev_cat = tvb_get_ntohs(tvb, offset+4);
        if (dev_cat > 0 && dev_cat <= WPS_DEVICE_TYPE_CATEGORY_MAX) {
          proto_tree_add_item(tlv_root, hf_eapwps_tlv_primary_device_type_category, tvb, offset+4, 2, ENC_BIG_ENDIAN);
          proto_tree_add_item(tlv_root, hf_eapwps_tlv_primary_device_type_subcategory[dev_cat-1], tvb, offset+10, 2, FALSE);
        }
      }
      
      break;

    case WPS_TLV_TYPE_SECONDARY_DEVICE_TYPE_LIST:
      /* check tlv_len <= 128 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_secondary_device_type_list, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_secondary_device_type_list;
      if (tlv_len > 128 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_PORTABLE_DEVICE:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_portable_device, tvb, offset+4, 1, FALSE);
      hfindex = hf_eapwps_tlv_portable_device;

      break;

    case WPS_TLV_TYPE_AP_SETUP_LOCKED:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_ap_setup_locked, tvb, offset+4, 1, FALSE);
      hfindex = hf_eapwps_tlv_ap_setup_locked;

      break;

    case WPS_TLV_TYPE_APPLICATION_EXTENSION:
      /* check tlv_len <= 512 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_application_extension, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_application_extension;
      if (tlv_len > 512 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_EAP_TYPE:
      /* check tlv_len <= 8 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_eap_type, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_eap_type;
      if (tlv_len > 8 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_INITIALIZATION_VECTOR:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_initialization_vector, tvb, offset+4, 32, ENC_NA);
      hfindex = hf_eapwps_tlv_initialization_vector;

      break;

    case WPS_TLV_TYPE_KEY_PROVIDED_AUTOMATICALLY:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_key_provided_automatically, tvb, offset+4, 1, FALSE);
      hfindex = hf_eapwps_tlv_key_provided_automatically;

      break;

    case WPS_TLV_TYPE_8021X_ENABLED:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_8021x_enabled, tvb, offset+4, 1, FALSE);
      hfindex = hf_eapwps_tlv_8021x_enabled;

      break;

    case WPS_TLV_TYPE_APPSESSIONKEY:
      /* check tlv_len <= 128 byte  */
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_appsessionkey, tvb, offset+4, tlv_len, ENC_NA);
      hfindex = hf_eapwps_tlv_appsessionkey;
      if (tlv_len > 128 && pinfo)
        expert_add_info_format(pinfo, tmp_item, PI_MALFORMED, PI_ERROR, fmt_warn_too_long, tlv_len);

      break;

    case WPS_TLV_TYPE_WEPTRANSMITKEY:
      tmp_item = proto_tree_add_item(tlv_root, hf_eapwps_tlv_weptransmitkey, tvb, offset+4, 1, ENC_BIG_ENDIAN);
      hfindex = hf_eapwps_tlv_weptransmitkey;

      break;

    case WPS_TLV_TYPE_REQUESTED_DEV_TYPE:
      tmp_item = proto_tree_add_item(tlv_root,
                                     hf_eapwps_tlv_requested_dev_type, tvb,
                                     offset + 4, 8, ENC_NA);
      hfindex = hf_eapwps_tlv_requested_dev_type;
      break;

    default:
      /* do something usefull ?  */
      tmp_item = NULL;
      hfindex = -1;
    }

    if (tmp_item != NULL && tlv_item != NULL) {
      /* make the tree look nicer :-)
         tmp_item -> a proto_item specific to the _value_
         tlv_item ->  root-item grouping
                      - "Data Element Type"
                      - "Date Element Length"
                      - tmp_item */
      guint32 value = -1;
      void* valuep = NULL;
      header_field_info* hf_info = NULL;
      char* fmt = NULL;

      proto_item_set_text(tlv_item, "%s",
                          val_to_str(tlv_type, eapwps_tlv_types, "Unknown (0x%04x)"));

      /* Rendered strings for value. Thanks to Stig Bjorlykke */
      hf_info = proto_registrar_get_nth(hfindex);
      if (hf_info != NULL) {
        switch(hf_info->type) {
        case FT_UINT8:
          fmt = hf_info->strings ? ": %s (0x%02x)": ": 0x%02x";
          value = tvb_get_guint8 (tvb, offset+4);
          break;
        case FT_UINT16:
          fmt = hf_info->strings ? ": %s (0x%04x)": ": 0x%04x";
          value = tvb_get_ntohs (tvb, offset+4);
          break;
        case FT_UINT32:
          fmt = hf_info->strings ? ": %s (0x%08x)": ": 0x%08x";
          value = tvb_get_ntohl (tvb, offset+4);
          break;
        case FT_STRING:
          fmt = ": %s";
          valuep = tvb_get_ephemeral_string(tvb, offset+4, tlv_len);
          break;
        default:
          /* make compiler happy */
          break;
        }
      }

      if (hf_info != NULL && hf_info->strings) {
        /* item has value_string */
        proto_item_append_text(tlv_item, fmt, val_to_str(value,
                                                         hf_info->strings,
                                                         "Unknown: %d"), value);
      } else if (valuep != NULL) {
        /* the string-case */
        proto_item_append_text(tlv_item, fmt, valuep);
      } else if (fmt != NULL) {
        /* field is FT_UINT(8|16|32) but has no value_string */
        proto_item_append_text(tlv_item, fmt, value);
      } else {
        /* field is either FT_ETHER or FT_BYTES, dont do anything */
      }

    }

    if (tlv_type == WPS_TLV_TYPE_VENDOR_EXTENSION)
      dissect_wps_vendor_ext(tlv_root, tvb, offset + 4, tlv_len);

    offset += tlv_len + 2 + 2;
    size   -= tlv_len + 2 + 2;
  }
}

/********************************************************************** */
/********************************************************************** */
void
dissect_exteap_wps(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
                   gint size, packet_info* pinfo)
{
  proto_item* pi;
  proto_tree* pt;
  guint8 flags;

  pi = proto_tree_add_item(eap_tree, hf_eapwps_opcode,     tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1; size -= 1;

  pi = proto_item_get_parent(pi);
  if (pi != NULL)
    proto_item_append_text(pi, " (Wifi Alliance, WifiProtectedSetup)");
  if (pinfo != NULL && check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, ", WPS");


  /* Flag field, if msg-len flag set, add approriate field  */
  flags = tvb_get_guint8(tvb,offset);
  pi = proto_tree_add_item(eap_tree, hf_eapwps_flags,      tvb, offset, 1, ENC_BIG_ENDIAN);
  pt = proto_item_add_subtree(pi, ett_eap_wps_flags);

  proto_tree_add_item(pt, hf_eapwps_flag_mf,    tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(pt, hf_eapwps_flag_lf,    tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1; size -= 1;

  if (flags & MASK_WSC_FLAG_LF) {
    /* length field is present in first eap-packet when msg is fragmented  */
    proto_tree_add_item(eap_tree, hf_eapwps_msglen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2; size -= 2;
  }

  dissect_wps_tlvs(eap_tree, tvb, offset, size, pinfo);
}

/********************************************************************** */
/********************************************************************** */
void
proto_register_wps(void)
{
  static hf_register_info hf[] = {

    /* These data-elements are sent in EAP-Pakets using expanded types */
    /* (see RFC3748 Section 5.7) */
    /* Paket dissections is done here and not in (packet-eap) as */
    /* both (tlvs and fields named eap.wps.*) are defined by */
    /* WifiAlliance  */
    { &hf_eapwps_opcode,
      { "Opcode", "eap.wps.code",
        FT_UINT8, BASE_DEC, VALS(eapwps_opcode_vals), 0x0,
        "WSC Message Type", HFILL }},
    { &hf_eapwps_flags,
      { "Flags", "eap.wps.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_eapwps_flag_mf,
      { "More flag", "eap.wps.flags.more",
        FT_BOOLEAN, 8, NULL, MASK_WSC_FLAG_MF,
        NULL, HFILL }},
    { &hf_eapwps_flag_lf,
      { "Length field present", "eap.wps.flags.length",
        FT_BOOLEAN, 8, NULL, MASK_WSC_FLAG_LF,
        NULL, HFILL }},
    { &hf_eapwps_msglen,
      { "Length field", "eap.wps.msglen",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* TLV encoded data which may be contained in */
    /* 802.11 Management frames and EAP-extended type */
    { &hf_eapwps_tlv_type,
      { "Data Element Type", "wps.type",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_types), 0x0,
        NULL, HFILL }},
    { &hf_eapwps_tlv_len,
      { "Data Element Length", "wps.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapwps_tlv_ap_channel,
      { "AP Channel", "wps.ap_channel",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_eapwps_tlv_association_state,
      { "Association State", "wps.association_state",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_association_state_vals), 0x0,
        NULL, HFILL }},

    { &hf_eapwps_tlv_authentication_type,
      { "Authentication Type", "wps.authentication_type",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_authentication_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_eapwps_tlv_authentication_type_flags,
      { "Authentication Type Flags", "wps.authentication_type_flags",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_authentication_type_flags_open,
      { "Open", "wps.authentication_type.open",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_AUTHTYPE_OPEN, NULL, HFILL }},
    { &hf_eapwps_tlv_authentication_type_flags_wpapsk,
      { "WPA PSK", "wps.authentication_type.wpapsk",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_AUTHTYPE_WPAPSK, NULL, HFILL }},
    { &hf_eapwps_tlv_authentication_type_flags_shared,
      { "Shared", "wps.authentication_type.shared",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_AUTHTYPE_SHARED, NULL, HFILL }},
    { &hf_eapwps_tlv_authentication_type_flags_wpa,
      { "WPA", "wps.authentication_type.wpa",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_AUTHTYPE_WPA, NULL, HFILL }},
    { &hf_eapwps_tlv_authentication_type_flags_wpa2,
      { "WPA2", "wps.authentication_type.wpa2",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_AUTHTYPE_WPA2, NULL, HFILL }},
    { &hf_eapwps_tlv_authentication_type_flags_wpa2psk,
      { "WPA2PSK", "wps.authentication_type.wpa2psk",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_AUTHTYPE_WPA2PSK, NULL, HFILL }},

    { &hf_eapwps_tlv_authenticator,
      { "Authenticator", "wps.authenticator",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_config_methods,
      { "Configuration Methods", "wps.config_methods",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_usba,
      { "USB", "wps.config_methods.usba",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_USBA, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_ethernet,
      { "Ethernet", "wps.config_methods.ethernet",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_ETHERNET, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_label,
      { "Label", "wps.config_methods.label",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_LABEL, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_display,
      { "Display", "wps.config_methods.display",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_DISPLAY, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_virt_display,
      { "Virtual Display", "wps.config_methods.virt_display",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_VIRT_DISPLAY, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_phy_display,
      { "Physical Display", "wps.config_methods.phy_display",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_PHY_DISPLAY, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_nfcext,
      { "External NFC", "wps.config_methods.nfcext",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_NFCEXT, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_nfcint,
      { "Internal NFC", "wps.config_methods.nfcint",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_NFCINT, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_nfcinf,
      { "NFC Interface", "wps.config_methods.nfcinf",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_NFCINF, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_pushbutton,
      { "Push Button", "wps.config_methods.pushbutton",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_PUSHBUTTON, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_virt_pushbutton,
      { "Virtual Push Button", "wps.config_methods.virt_pushbutton",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_VIRT_PUSHBUTTON, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_phy_pushbutton,
      { "Physical Push Button", "wps.config_methods.phy_pushbutton",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_PHY_PUSHBUTTON, NULL, HFILL }},
    { &hf_eapwps_tlv_config_methods_keypad,
      { "Keypad", "wps.config_methods.keypad",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_CONFMETH_KEYPAD, NULL, HFILL }},


    { &hf_eapwps_tlv_configuration_error,
      { "Configuration Error", "wps.configuration_error",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_configuration_error_vals), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_confirmation_url4,
      { "Confirmation URL4", "wps.confirmation_url4",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_confirmation_url6,
      { "Confirmation URL6", "wps.confirmation_url6",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_connection_type,
      { "Connection Type", "wps.connection_type",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_connection_type_flags,
      { "Connection Types", "wps.connection_type_flags",
        FT_UINT8, BASE_HEX, VALS(eapwps_tlv_connection_type_vals), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_connection_type_flags_ess,
      { "ESS", "wps.connection_type_flags.ess",
        FT_UINT8, BASE_HEX, NULL, EAPWPS_CONNTYPE_ESS, NULL, HFILL }},
    { &hf_eapwps_tlv_connection_type_flags_ibss,
      { "IBSS", "wps.connection_type_flags.ibss",
        FT_UINT8, BASE_HEX, NULL, EAPWPS_CONNTYPE_IBSS, NULL, HFILL }},

    { &hf_eapwps_tlv_credential,  /* Encrypted  */
      { "Credential", "wps.credential",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_device_name,
      { "Device Name", "wps.device_name",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_device_password_id,
      { "Device Password ID", "wps.device_password_id",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_device_password_id_vals), 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_e_hash1,
      { "Enrollee Hash 1", "wps.e_hash1",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_e_hash2,
      { "Enrollee Hash 2", "wps.e_hash2",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_e_snonce1,
      { "Enrollee SNounce 1", "wps.e_snonce1",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_e_snonce2,
      { "Enrollee SNounce 2", "wps.e_snonce2",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_encrypted_settings, /* Encrypted !  */
      { "Encrypted Settings", "wps.encrypted_settings",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_encryption_type,
      { "Encryption Type", "wps.encryption_type",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_encryption_type_vals), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_encryption_type_flags,
      { "Encryption Type Flags", "wps.encryption_type_flags",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_encryption_type_flags_none,
      { "None", "wps.encryption_type_flags.none",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_ENCTYPE_NONE, NULL, HFILL }},
    { &hf_eapwps_tlv_encryption_type_flags_wep,
      { "WEP", "wps.encryption_type_flags.wep",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_ENCTYPE_WEP, NULL, HFILL }},
    { &hf_eapwps_tlv_encryption_type_flags_tkip,
      { "TKIP", "wps.encryption_type_flags.tkip",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_ENCTYPE_TKIP, NULL, HFILL }},
    { &hf_eapwps_tlv_encryption_type_flags_aes,
      { "AES", "wps.encryption_type_flags.aes",
        FT_UINT16, BASE_HEX, NULL, EAPWPS_ENCTYPE_AES, NULL, HFILL }},

    { &hf_eapwps_tlv_enrollee_nonce,
      { "Enrollee Nonce", "wps.enrollee_nonce",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_feature_id,
      { "Feature ID", "wps.feature_id",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_identity,
      { "Identity", "wps.identity",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_identity_proof, /* Encrypted !  */
      { "Identity Proof", "wps.identity_proof",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_key_wrap_authenticator,
      { "Key Wrap Authenticator", "wps.key_wrap_authenticator",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_key_identifier,
      { "Key Identifier", "wps.key_identifier",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_mac_address,
      { "MAC", "wps.mac_address",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_manufacturer,
      { "Manufacturer", "wps.manufacturer",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_message_type,
      { "Message Type", "wps.message_type",
        FT_UINT8, BASE_HEX, VALS(eapwps_tlv_message_type_vals), 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_model_name,
      { "Model Name", "wps.model_name",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_model_number,
      { "Model Number", "wps.model_number",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_network_index,
      { "Network Index", "wps.network_index",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_network_key,
      { "Network Key", "wps.network_key",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_network_key_index,
      { "Network Key Index", "wps.network_key_index",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_new_device_name,
      { "New Device Name", "wps.new_device_name",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_new_password,
      { "New Password", "wps.new_password",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_oob_device_password,
      { "OOB Device Password", "wps.oob_device_password",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_os_version,
      { "OS Version", "wps.os_version",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_power_level,
      { "Power Level", "wps.power_level",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_psk_current,
      { "PSK Current", "wps.psk_current",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_psk_max,
      { "PSK Max", "wps.psk_max",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_public_key,
      { "Public Key", "wps.public_key",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_radio_enabled, /* Add info  */
      { "Radio Enabled", "wps.radio_enabled",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_reboot, /* Add info  */
      { "Reboot", "wps.reboot",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_registrar_current,
      { "Registrar current", "wps.registrar_current",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_registrar_established, /* Add info  */
      { "Registrar established", "wps.registrar_established",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_registrar_list,
      { "Registrar list", "wps.registrar_list",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_registrar_max,
      { "Registrar max", "wps.registrar_max",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_registrar_nonce,
      { "Registrar Nonce", "wps.registrar_nonce",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_request_type,
      { "Request Type", "wps.request_type",
        FT_UINT8, BASE_HEX, VALS(eapwps_tlv_request_type_vals), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_response_type,
      { "Response Type", "wps.response_type",
        FT_UINT8, BASE_HEX, VALS(eapwps_tlv_response_type_vals), 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_rf_bands,
      { "RF Bands", "wps.rf_bands",
        FT_UINT8, BASE_HEX, VALS(eapwps_tlv_rf_bands_vals), 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_r_hash1,
      { "Registrar Hash 1", "wps.r_hash1",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_r_hash2,
      { "Registrar Hash 2", "wps.r_hash2",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_r_snonce1,
      { "Registrar Snonce1", "wps.r_snonce1",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_r_snonce2,
      { "Registrar Snonce 2", "wps.r_snonce2",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_selected_registrar,
      { "Selected Registrar", "wps.selected_registrar",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_serial_number,
      { "Serial Number", "wps.serial_number",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_wifi_protected_setup_state,
      { "Wifi Protected Setup State", "wps.wifi_protected_setup_state",
        FT_UINT8, BASE_HEX, VALS(eapwps_tlv_wifi_protected_setup_state), 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_ssid,
      { "SSID", "wps.ssid",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_total_networks,
      { "Total Networks", "wps.total_networks",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_uuid_e,
      { "UUID Enrollee", "wps.uuid_e",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_uuid_r,
      { "UUID Registrar", "wps.uuid_r",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_vendor_extension,
      { "Vendor Extension", "wps.vendor_extension",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_version,
      { "Version", "wps.version",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_x509_certificate_request,
      { "X509 Certificate Request", "wps.x509_certificate_request",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_x509_certificate,
      { "X509 Certificate", "wps.x509_certificate",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_eap_identity,
      { "EAP Identity", "wps.eap_identity",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_message_counter,
      { "Message Counter", "wps.message_counter",
        FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_public_key_hash,
      { "Public Key Hash", "wps.public_key_hash",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_rekey_key,
      { "Rekey Key", "wps.rekey_key",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_key_lifetime,
      { "Key Lifetime", "wps.key_lifetime",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_permitted_config_methods,
      { "Permitted COnfig Methods", "wps.permitted_config_methods",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_selected_registrar_config_methods,
      { "Selected Registrar Config Methods", "wps.selected_registrar_config_methods",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_primary_device_type,
      { "Primary Device Type", "wps.primary_device_type",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_category,
      { "Category", "wps.primary_device_type.category",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_primary_device_type_category), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[0],
      { "Subcategory", "wps.primary_device_type.subcategory_computer",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_computer_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[1],
      { "Subcategory", "wps.primary_device_type.subcategory_input_device",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_input_device_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[2],
      { "Subcategory", "wps.primary_device_type.subcategory_printers_scanners_faxes_copiers",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_printers_scanners_faxes_copiers_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[3],
      { "Subcategory", "wps.primary_device_type.subcategory_camera",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_camera_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[4],
      { "Subcategory", "wps.primary_device_type.subcategory_storage",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_storage_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[5],
      { "Subcategory", "wps.primary_device_type.subcategory_network_infrastructure",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_network_infrastructure_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[6],
      { "Subcategory", "wps.primary_device_type.subcategory_displays",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_displays_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[7],
      { "Subcategory", "wps.primary_device_type.subcategory_multimedia_devices",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_multimedia_devices_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[8],
      { "Subcategory", "wps.primary_device_type.subcategory_gaming_devices",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_gaming_devices_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[9],
      { "Subcategory", "wps.primary_device_type.subcategory_telephone",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_telephone_subcategory), 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_primary_device_type_subcategory[10],
      { "Subcategory", "wps.primary_device_type.subcategory_audio_devices",
        FT_UINT16, BASE_HEX, VALS(eapwps_tlv_audio_devices_subcategory), 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_secondary_device_type_list,
      { "Secondary Device Type List", "wps.secondary_device_type_list",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_portable_device, /* Add info  */
      { "Portable Device", "wps.portable_device",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_ap_setup_locked, /* Add info  */
      { "AP Setup Locked", "wps.ap_setup_locked",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_application_extension,
      { "Application Extension", "wps.application_extension",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_eap_type,
      { "EAP Type", "wps.eap_type",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_initialization_vector,
      { "Initialization Vector", "wps.initialization_vector",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_key_provided_automatically, /* Add info  */
      { "Key Provided Automatically", "wps.key_provided_automatically",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_8021x_enabled, /* Add info  */
      { "8021x Enabled", "wps.8021x_enabled",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_appsessionkey,
      { "AppSessionKey", "wps.appsessionkey",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_eapwps_tlv_weptransmitkey,
      { "WEP Transmit Key", "wps.weptransmitkey",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_tlv_requested_dev_type,
      { "Requested Device Type", "wps.requested_dev_type",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_vendor_id,
      { "Vendor ID", "wps.vendor_id",
        FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_wfa_ext_id,
      { "WFA Extension Subelement ID", "wps.ext.id",
        FT_UINT8, BASE_DEC, VALS(eapwps_wfa_ext_types), 0x0, NULL, HFILL }},

    { &hf_eapwps_wfa_ext_len,
      { "WFA Extension Subelement Length", "wps.ext.len",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_wfa_ext_version2,
      { "Version2", "wps.ext.version2",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_wfa_ext_authorizedmacs,
      { "AuthorizedMACs", "wps.ext.authorizedmacs",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_wfa_ext_network_key_shareable,
      { "Network Key Shareable", "wps.ext.network_key_shareable",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_wfa_ext_request_to_enroll,
      { "Request to Enroll", "wps.ext.request_to_enroll",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_eapwps_wfa_ext_settings_delay_time,
      { "Settings Delay Time", "wps.ext.settings_delay_time",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_eap_wps_attr,
    &ett_eap_wps_flags,
    /* EAP WPS  */
    &ett_wps_tlv,
    &ett_eap_wps_ap_channel,
    &ett_eap_wps_association_state,
    &ett_eap_wps_authentication_type,
    &ett_eap_wps_authentication_type_flags,
    &ett_eap_wps_authenticator,
    &ett_eap_wps_config_methods,
    &ett_eap_wps_configuration_error,
    &ett_eap_wps_confirmation_url4,
    &ett_eap_wps_confirmation_url6,
    &ett_eap_wps_connection_type,
    &ett_eap_wps_connection_type_flags,
    &ett_eap_wps_credential,
    &ett_eap_wps_device_name,
    &ett_eap_wps_device_password_id,
    &ett_eap_wps_e_hash1,
    &ett_eap_wps_e_hash2,
    &ett_eap_wps_e_snonce1,
    &ett_eap_wps_e_snonce2,
    &ett_eap_wps_encrypted_settings,
    &ett_eap_wps_encryption_type,
    &ett_eap_wps_encryption_type_flags,
    &ett_eap_wps_enrollee_nonce,
    &ett_eap_wps_feature_id,
    &ett_eap_wps_identity,
    &ett_eap_wps_identity_proof,
    &ett_eap_wps_key_wrap_authenticator,
    &ett_eap_wps_key_identifier,
    &ett_eap_wps_mac_address,
    &ett_eap_wps_manufacturer,
    &ett_eap_wps_message_type,
    &ett_eap_wps_model_name,
    &ett_eap_wps_model_number,
    &ett_eap_wps_network_index,
    &ett_eap_wps_network_key,
    &ett_eap_wps_network_key_index,
    &ett_eap_wps_new_device_name,
    &ett_eap_wps_new_password,
    &ett_eap_wps_oob_device_password,
    &ett_eap_wps_os_version,
    &ett_eap_wps_power_level,
    &ett_eap_wps_psk_current,
    &ett_eap_wps_psk_max,
    &ett_eap_wps_public_key,
    &ett_eap_wps_radio_enabled,
    &ett_eap_wps_reboot,
    &ett_eap_wps_registrar_current,
    &ett_eap_wps_registrar_established,
    &ett_eap_wps_registrar_list,
    &ett_eap_wps_registrar_max,
    &ett_eap_wps_registrar_nonce,
    &ett_eap_wps_request_type,
    &ett_eap_wps_response_type,
    &ett_eap_wps_rf_bands,
    &ett_eap_wps_r_hash1,
    &ett_eap_wps_r_hash2,
    &ett_eap_wps_r_snonce1,
    &ett_eap_wps_r_snonce2,
    &ett_eap_wps_selected_registrar,
    &ett_eap_wps_serial_number,
    &ett_eap_wps_wifi_protected_setup_state,
    &ett_eap_wps_ssid,
    &ett_eap_wps_total_networks,
    &ett_eap_wps_uuid_e,
    &ett_eap_wps_uuid_r,
    &ett_eap_wps_vendor_extension,
    &ett_eap_wps_version,
    &ett_eap_wps_x509_certificate_request,
    &ett_eap_wps_x509_certificate,
    &ett_eap_wps_eap_identity,
    &ett_eap_wps_message_counter,
    &ett_eap_wps_public_key_hash,
    &ett_eap_wps_rekey_key,
    &ett_eap_wps_key_lifetime,
    &ett_eap_wps_permitted_config_methods,
    &ett_eap_wps_selected_registrar_config_methods,
    &ett_eap_wps_primary_device_type,
    &ett_eap_wps_secondary_device_type_list,
    &ett_eap_wps_portable_device,
    &ett_eap_wps_ap_setup_locked,
    &ett_eap_wps_application_extension,
    &ett_eap_wps_eap_type,
    &ett_eap_wps_initialization_vector,
    &ett_eap_wps_key_provided_automatically,
    &ett_eap_wps_8021x_enabled,
    &ett_eap_wps_appsessionkey,
    &ett_eap_wps_weptransmitkey,
    &ett_wps_wfa_ext,
  };

  proto_wps = proto_register_protocol("Wifi Protected Setup",
                                      "WPS", "wps");
  proto_register_field_array(proto_wps, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
