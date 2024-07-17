/* packet-aruba-papi.c
 * Routines for Aruba PAPI dissection
 * Copyright 2010, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Real name of PAPI : Protocol Application Program Interface
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include "packet-ipv6.h"

/* This is not IANA assigned nor registered */
#define UDP_PORT_PAPI 8211

void proto_register_papi(void);
void proto_reg_handoff_papi(void);

static dissector_handle_t papi_handle;

/* Initialize the protocol and registered fields */
static int proto_papi;
static int hf_papi_hdr_magic;
static int hf_papi_hdr_version;
static int hf_papi_hdr_dest_ip;
static int hf_papi_hdr_src_ip;
static int hf_papi_hdr_nat_port_number;
static int hf_papi_hdr_garbage;
static int hf_papi_hdr_dest_port;
static int hf_papi_hdr_src_port;
static int hf_papi_hdr_packet_type;
static int hf_papi_hdr_packet_size;
static int hf_papi_hdr_seq_number;
static int hf_papi_hdr_message_code;
static int hf_papi_hdr_checksum;

static int hf_papi_hdr_srcipv6;
static int hf_papi_hdr_destipv6;

static int hf_papi_debug;
static int hf_papi_debug_text;
static int hf_papi_debug_text_length;
static int hf_papi_debug_48bits;
static int hf_papi_debug_8bits;
static int hf_papi_debug_16bits;
static int hf_papi_debug_32bits;
static int hf_papi_debug_ipv4;
static int hf_papi_debug_64bits;
static int hf_papi_debug_bytes;
static int hf_papi_debug_bytes_length;

static int hf_papi_licmgr;
static int hf_papi_licmgr_payload_len;
static int hf_papi_licmgr_tlv;
static int hf_papi_licmgr_type;
static int hf_papi_licmgr_length;
static int hf_papi_licmgr_value;
static int hf_papi_licmgr_ip;
static int hf_papi_licmgr_serial_number;
static int hf_papi_licmgr_hostname;
static int hf_papi_licmgr_mac_address;
static int hf_papi_licmgr_license_ap_remaining;
static int hf_papi_licmgr_license_pef_remaining;
static int hf_papi_licmgr_license_rfp_remaining;
static int hf_papi_licmgr_license_xsec_remaining;
static int hf_papi_licmgr_license_acr_remaining;
static int hf_papi_licmgr_license_ap_used;
static int hf_papi_licmgr_license_pef_used;
static int hf_papi_licmgr_license_rfp_used;
static int hf_papi_licmgr_license_xsec_used;
static int hf_papi_licmgr_license_acr_used;
static int hf_papi_licmgr_padding;

static expert_field ei_papi_debug_unknown;

/* variable for dissector table for subdissectors */
static dissector_table_t papi_dissector_table;

/* Global PAPI Debug Preference */
static bool g_papi_debug;

/* Initialize the subtree pointers */
static int ett_papi;
static int ett_papi_licmgr;
static int ett_papi_licmgr_tlv;

#define SAMBA_WRAPPER               8442
#define RESOLVER_PORT               8392
#define PB_INT_TASK                 8448
#define STATION_MANAGEMENT_LOPRI    8419
#define MOBILE_IP                   8383
#define SIBYTE_FASTPATH_PORT        8355
#define WLAN_MANAGEMENT_SERVER      8224
#define SIBYTE_CONSOLE_CLIENT2      8357
#define AUTH_SERVER_LOPRI           8420
#define MOB_FASTPATH_PORT           8354
#define SAP_RRAD_PORT               8382
#define REPGEN                      8418
#define RAPPER_PORT2                8424
#define IKE_DAEMON_RAW              8232
#define STATION_MANAGEMENT          8345
#define PPPD_START                  8241
#define SETUP_DIALOG                8434
#define WEB_GRAPHGEN1               8346
#define SNMP_TRAP_RAW               8402
#define ARUBA_NTPD                  8377
#define STATION_MANAGEMENT_LOPRI_AP 8452
#define CLI_LOG_RAW                 8364
#define AUTH_SERVER_RAW             8227
#define RAPPER_PORT5                8427
#define MESH_DAEMON                 8433
#define PHONE_HOME                  8437
#define FPCLI_SIBYTE_CONSOLE2       8368
#define FASTPATH_WEB_CLIENT         8218
#define SERVER_LOAD_BALANCING       8384
#define IKE_DAEMON                  8231
#define CPSEC                       8453
#define MOBILITY_CLIENT             8217
#define SNMP_TRAPMGR                8363
#define PIM_TOSIBYTE                8416
#define RAPPER_PORT9                8431
#define CERT_MANAGER_MASTER         8353
#define MISC_PROC                   8445
#define PPPD_END                    8340
#define SYSMGR                      8450
#define RAPPER_PORT6                8428
#define RRA_SERVER                  8238
#define NANNY_PORT_MEM_MON          8371
#define SYS_MAPPER_LOPRI            8435
#define RAPPER_PORT4                8426
#define SAPM_HYBRID_AP              8436
#define FASTPATH_CLI_CLIENT         8213
#define CFGM_RAW                    8362
#define SPOTMGR                     8398
#define SYSLOGDWRAP                 8407
#define WEBS_AM_PORT                8352
#define QPDQ_STANDALONE             8401
#define FPCLI_RAW                   8361
#define VRRP_DAEMON                 8391
#define AMAP_MGMT_PORT              8395
#define CAP_MGMT_PORT               8351
#define SAPM_SERVER                 8222
#define PPPD_DAEMON                 8234
#define LAST_SERVICE                8999
#define DHCP_SERVER                 8390
#define ADMINSERVER                 8403
#define SYS_MAPPER                  8396
#define PUBSUB_SERVER               8378
#define AMAPI_SNMP_TRAP_CLIENT      8440
#define PPTPD                       8341
#define SIBYTE_CONSOLE_PORT         8348
#define SNMP_DAEMON                 8219
#define SIBYTE_DNLD_FILE            8374
#define UTILITY_PROCESS             8449
#define SAPM_RAPCP                  8438
#define SIBYTE_MACH_INFO            8386
#define SIBYTE_CONSOLE_CLIENT1      8356
#define SWKEY                       8373
#define RF_CLIENT                   8410
#define HAMGR                       8408
#define FASTPATH_CLI_SERVER         8239
#define FASTPATH_AUTH_CLIENT        8360
#define CRYPTO_POST_PORT            8400
#define HTTPD_WRAP                  8404
#define MMSCONFIGMGR                8412
#define FPAPPS_AUTH_PORT            8381
#define FPWEB_RAW                   8415
#define L2TPD                       8342
#define CERT_CLIENT                 8349
#define SIBYTE_RAW                  8228
#define FPAPPS_VRRP_PORT            8379
#define AIR_MONITOR                 8225
#define ANOMALY_DETECTION           8387
#define ARUBA_FILTER                8388
#define MSGH_HELPER                 8446
#define FASTPATH_SERVER             8212
#define MOBILITY_AGENT              8229
#define OSPF_DAEMON                 8441
#define PIM                         8385
#define MOBILITY_SERVER             8216
#define SIBYTE_CONSOLE_CLIENT3      8358
#define FPCLI_SIBYTE_CONSOLE1       8367
#define AUTH_CLIENT                 8215
#define FPCLI_SIBYTE_CONSOLE3       8369
#define AMAPI_SAMPLE_CLIENT         8221
#define PPPOE_DAEMON                8411
#define UDB_SERVER                  8344
#define RAPPER_PORT1                8423
#define PAPI_EPHEMERAL              65535
#define MVC_SERVER                  8422
#define RAPPER_PORT3                8425
#define DHCP_DAEMON                 8359
#define EMWEB_RAW                   8365
#define STATSMGR                    8397
#define FASTPATH_ADD_SERVER         8240
#define AMAPI_CLI_CLIENT            8220
#define AUTH_SERVER                 8214
#define MESSAGE_HANDLER             8999
#define AMAP_PROC                   8394
#define CTS                         8413
#define CFGMANAGER                  8226
#define RAPPER_PORT8                8430
#define L2TPD_DAEMON_RAW            8233
#define WLAN_MANAGEMENT_SERVER_LOPRI 8421
#define NANNY_PORT                  8370
#define RAPPER_PORT10               8432
#define RAPPER_PORT7                8429
#define AMAPI_WEB_CLIENT            8235
#define WEB_CLI_RAW                 8375
#define CERT_MANAGER                8343
#define NCFGTEST_APP                8406
#define REM_DSLMGR                  8439
#define PROFILE_MANAGER             8405
#define LICENSE_MANAGER             8389
#define MMSWEBSVC                   8414
#define SSH_AUTH_PORT               8393
#define STATION_MANAGEMENT_AP       8451
#define AMP_SERVER                  8444
#define HTTPD_WRAP_AUTH_PORT        8417
#define FAULTMGR                    8399
#define SIBYTE_HEARTBEAT            8237
#define USBHELPER_CLIENT            8447
#define SAPM_CLIENT                 8223
#define RF_MANAGER                  8409
#define WEB_GRAPHGEN2               8347
#define HARDWARE_MONITOR_PORT       8366
#define P8MGR                       8454
#define WIRED_MAC_LOOKUP            8376
#define CDP_PROC                    8350
#define AAA_MGMT_PORT               8372
#define DBSYNC_PORT                 8380
#define AMAPI_SNMP_CLIENT           8236
#define PORT_UBT                    15560

/* defining Packet Size & HDR version no for PAPI */
#define PAPI_PACKET_SIZE 76
#define V4V6_HDR_VERSION 0x03

static const value_string papi_port_vals[] = {
    { FASTPATH_SERVER, "FASTPATH_SERVER" },
    { FASTPATH_CLI_CLIENT, "FASTPATH_CLI_CLIENT" },
    { AUTH_SERVER, "AUTH_SERVER" },
    { AUTH_CLIENT, "AUTH_CLIENT" },
    { MOBILITY_SERVER, "MOBILITY_SERVER" },
    { MOBILITY_CLIENT, "MOBILITY_CLIENT" },
    { FASTPATH_WEB_CLIENT, "FASTPATH_WEB_CLIENT" },
    { SNMP_DAEMON, "SNMP_DAEMON" },
    { AMAPI_CLI_CLIENT, "AMAPI_CLI_CLIENT" },
    { AMAPI_SAMPLE_CLIENT, "AMAPI_SAMPLE_CLIENT" },
    { SAPM_SERVER, "SAPM_SERVER" },
    { SAPM_CLIENT, "SAPM_CLIENT" },
    { WLAN_MANAGEMENT_SERVER, "WLAN_MANAGEMENT_SERVER" },
    { AIR_MONITOR, "AIR_MONITOR" },
    { CFGMANAGER, "CFGMANAGER" },
    { AUTH_SERVER_RAW, "AUTH_SERVER_RAW" },
    { SIBYTE_RAW, "SIBYTE_RAW" },
    { MOBILITY_AGENT, "MOBILITY_AGENT" },
    { IKE_DAEMON, "IKE_DAEMON" },
    { IKE_DAEMON_RAW, "IKE_DAEMON_RAW" },
    { L2TPD_DAEMON_RAW, "L2TPD_DAEMON_RAW" },
    { PPPD_DAEMON, "PPPD_DAEMON" },
    { AMAPI_WEB_CLIENT, "AMAPI_WEB_CLIENT" },
    { AMAPI_SNMP_CLIENT, "AMAPI_SNMP_CLIENT" },
    { SIBYTE_HEARTBEAT, "SIBYTE_HEARTBEAT" },
    { RRA_SERVER, "RRA_SERVER" },
    { FASTPATH_CLI_SERVER, "FASTPATH_CLI_SERVER" },
    { FASTPATH_ADD_SERVER, "FASTPATH_ADD_SERVER" },
    { PPPD_START, "PPPD_START" },
    { PPPD_END, "PPPD_END" },
    { PPTPD, "PPTPD" },
    { L2TPD, "L2TPD" },
    { CERT_MANAGER, "CERT_MANAGER" },
    { UDB_SERVER, "UDB_SERVER" },
    { STATION_MANAGEMENT, "STATION_MANAGEMENT" },
    { WEB_GRAPHGEN1, "WEB_GRAPHGEN1" },
    { WEB_GRAPHGEN2, "WEB_GRAPHGEN2" },
    { SIBYTE_CONSOLE_PORT, "SIBYTE_CONSOLE_PORT" },
    { CERT_CLIENT, "CERT_CLIENT" },
    { CDP_PROC, "CDP_PROC" },
    { CAP_MGMT_PORT, "CAP_MGMT_PORT" },
    { WEBS_AM_PORT, "WEBS_AM_PORT" },
    { CERT_MANAGER_MASTER, "CERT_MANAGER_MASTER" },
    { MOB_FASTPATH_PORT, "MOB_FASTPATH_PORT" },
    { SIBYTE_FASTPATH_PORT, "SIBYTE_FASTPATH_PORT" },
    { SIBYTE_CONSOLE_CLIENT1, "SIBYTE_CONSOLE_CLIENT1" },
    { SIBYTE_CONSOLE_CLIENT2, "SIBYTE_CONSOLE_CLIENT2" },
    { SIBYTE_CONSOLE_CLIENT3, "SIBYTE_CONSOLE_CLIENT3" },
    { DHCP_DAEMON, "DHCP_DAEMON" },
    { FASTPATH_AUTH_CLIENT, "FASTPATH_AUTH_CLIENT" },
    { FPCLI_RAW, "FPCLI_RAW" },
    { CFGM_RAW, "CFGM_RAW" },
    { SNMP_TRAPMGR, "SNMP_TRAPMGR" },
    { CLI_LOG_RAW, "CLI_LOG_RAW" },
    { EMWEB_RAW, "EMWEB_RAW" },
    { HARDWARE_MONITOR_PORT, "HARDWARE_MONITOR_PORT" },
    { FPCLI_SIBYTE_CONSOLE1, "FPCLI_SIBYTE_CONSOLE1" },
    { FPCLI_SIBYTE_CONSOLE2, "FPCLI_SIBYTE_CONSOLE2" },
    { FPCLI_SIBYTE_CONSOLE3, "FPCLI_SIBYTE_CONSOLE3" },
    { NANNY_PORT, "NANNY_PORT" },
    { NANNY_PORT_MEM_MON, "NANNY_PORT_MEM_MON" },
    { AAA_MGMT_PORT, "AAA_MGMT_PORT" },
    { SWKEY, "SWKEY" },
    { SIBYTE_DNLD_FILE, "SIBYTE_DNLD_FILE" },
    { WEB_CLI_RAW, "WEB_CLI_RAW" },
    { WIRED_MAC_LOOKUP, "WIRED_MAC_LOOKUP" },
    { ARUBA_NTPD, "ARUBA_NTPD" },
    { PUBSUB_SERVER, "PUBSUB_SERVER" },
    { FPAPPS_VRRP_PORT, "FPAPPS_VRRP_PORT" },
    { DBSYNC_PORT, "DBSYNC_PORT" },
    { FPAPPS_AUTH_PORT, "FPAPPS_AUTH_PORT" },
    { SAP_RRAD_PORT, "SAP_RRAD_PORT" },
    { MOBILE_IP, "MOBILE_IP" },
    { SERVER_LOAD_BALANCING, "SERVER_LOAD_BALANCING" },
    { PIM, "PIM" },
    { SIBYTE_MACH_INFO, "SIBYTE_MACH_INFO" },
    { ANOMALY_DETECTION, "ANOMALY_DETECTION" },
    { ARUBA_FILTER, "ARUBA_FILTER" },
    { LICENSE_MANAGER, "LICENSE_MANAGER" },
    { DHCP_SERVER, "DHCP_SERVER" },
    { VRRP_DAEMON, "VRRP_DAEMON" },
    { RESOLVER_PORT, "RESOLVER_PORT" },
    { SSH_AUTH_PORT, "SSH_AUTH_PORT" },
    { AMAP_PROC, "AMAP_PROC" },
    { AMAP_MGMT_PORT, "AMAP_MGMT_PORT" },
    { SYS_MAPPER, "SYS_MAPPER" },
    { STATSMGR, "STATSMGR" },
    { SPOTMGR, "SPOTMGR" },
    { FAULTMGR, "FAULTMGR" },
    { CRYPTO_POST_PORT, "CRYPTO_POST_PORT" },
    { QPDQ_STANDALONE, "QPDQ_STANDALONE" },
    { SNMP_TRAP_RAW, "SNMP_TRAP_RAW" },
    { ADMINSERVER, "ADMINSERVER" },
    { HTTPD_WRAP, "HTTPD_WRAP" },
    { PROFILE_MANAGER, "PROFILE_MANAGER" },
    { NCFGTEST_APP, "NCFGTEST_APP" },
    { SYSLOGDWRAP, "SYSLOGDWRAP" },
    { HAMGR, "HAMGR" },
    { RF_MANAGER, "RF_MANAGER" },
    { RF_CLIENT, "RF_CLIENT" },
    { PPPOE_DAEMON, "PPPOE_DAEMON" },
    { MMSCONFIGMGR, "MMSCONFIGMGR" },
    { CTS, "CTS" },
    { MMSWEBSVC, "MMSWEBSVC" },
    { FPWEB_RAW, "FPWEB_RAW" },
    { PIM_TOSIBYTE, "PIM_TOSIBYTE" },
    { HTTPD_WRAP_AUTH_PORT, "HTTPD_WRAP_AUTH_PORT" },
    { REPGEN, "REPGEN" },
    { STATION_MANAGEMENT_LOPRI, "STATION_MANAGEMENT_LOPRI" },
    { AUTH_SERVER_LOPRI, "AUTH_SERVER_LOPRI" },
    { WLAN_MANAGEMENT_SERVER_LOPRI, "WLAN_MANAGEMENT_SERVER_LOPRI" },
    { MVC_SERVER, "MVC_SERVER" },
    { RAPPER_PORT1, "RAPPER_PORT1" },
    { RAPPER_PORT2, "RAPPER_PORT2" },
    { RAPPER_PORT3, "RAPPER_PORT3" },
    { RAPPER_PORT4, "RAPPER_PORT4" },
    { RAPPER_PORT5, "RAPPER_PORT5" },
    { RAPPER_PORT6, "RAPPER_PORT6" },
    { RAPPER_PORT7, "RAPPER_PORT7" },
    { RAPPER_PORT8, "RAPPER_PORT8" },
    { RAPPER_PORT9, "RAPPER_PORT9" },
    { RAPPER_PORT10, "RAPPER_PORT10" },
    { MESH_DAEMON, "MESH_DAEMON" },
    { SETUP_DIALOG, "SETUP_DIALOG" },
    { SYS_MAPPER_LOPRI, "SYS_MAPPER_LOPRI" },
    { SAPM_HYBRID_AP, "SAPM_HYBRID_AP" },
    { PHONE_HOME, "PHONE_HOME" },
    { SAPM_RAPCP, "SAPM_RAPCP" },
    { REM_DSLMGR, "REM_DSLMGR" },
    { AMAPI_SNMP_TRAP_CLIENT, "AMAPI_SNMP_TRAP_CLIENT" },
    { OSPF_DAEMON, "OSPF_DAEMON" },
    { SAMBA_WRAPPER, "SAMBA_WRAPPER" },
    { AMP_SERVER, "AMP_SERVER" },
    { MISC_PROC, "MISC_PROC" },
    { MSGH_HELPER, "MSGH_HELPER" },
    { USBHELPER_CLIENT, "USBHELPER_CLIENT" },
    { PB_INT_TASK, "PB_INT_TASK" },
    { UTILITY_PROCESS, "UTILITY_PROCESS" },
    { SYSMGR, "SYSMGR" },
    { STATION_MANAGEMENT_AP, "STATION_MANAGEMENT_AP" },
    { STATION_MANAGEMENT_LOPRI_AP, "STATION_MANAGEMENT_LOPRI_AP" },
    { CPSEC, "CPSEC" },
    { P8MGR, "P8MGR" },
    { LAST_SERVICE, "LAST_SERVICE / MESSAGE_HANDLER" },
    //{ MESSAGE_HANDLER, "MESSAGE_HANDLER" },
    { PORT_UBT, "PORT_UBT" },
    { PAPI_EPHEMERAL, "PAPI_EPHEMERAL" },
    { 0,     NULL     }
};

static value_string_ext papi_port_vals_ext = VALUE_STRING_EXT_INIT(papi_port_vals);

/* PAPI License Manager ! */
static const value_string licmgr_type_vals[] = {
    { 1, "IP Address" },
    { 2, "Serial Number" },
    { 3, "Hostname" },
    { 5, "Mac Address" },
    { 7, "License AP Remaining" },
    { 8, "License PEF Remaining" },
    { 9, "License RFP Remaining" },
    { 10, "License xSec Remaining " },
    { 11, "License ACR Remaining " },
    { 12, "License AP Used" },
    { 13, "License PEF Used" },
    { 14, "License AP Used" },
    { 15, "License xSec Used" },
    { 16, "License ACR Used" },
    { 17, "License WebCC Key ?" },
    { 18, "License WebCC Remaining ?" },
    { 19, "License WebCC Used ?" },
    { 0,     NULL     }
};
static int
dissect_papi_license_manager(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *licmgr_tree, *licmgr_subtree;
    unsigned offset_end, payload_len, offset = 0;

    ti = proto_tree_add_item(tree, hf_papi_licmgr, tvb, offset, -1, ENC_NA);
    licmgr_tree = proto_item_add_subtree(ti, ett_papi_licmgr);

    proto_tree_add_item_ret_uint(licmgr_tree, hf_papi_licmgr_payload_len, tvb, offset, 2, ENC_BIG_ENDIAN, &payload_len);
    offset += 2;
    col_set_str(pinfo->cinfo, COL_INFO, "PAPI - Licence Manager");

    offset_end = offset + payload_len;

    while (offset< offset_end) {
        unsigned optlen, type;
        proto_item *tlv_item;

        type = tvb_get_ntohs(tvb, offset);
        optlen = tvb_get_ntohs(tvb, offset+2);
        tlv_item = proto_tree_add_item(licmgr_tree, hf_papi_licmgr_tlv, tvb, offset, 2+2+optlen, ENC_NA );

        proto_item_append_text(tlv_item, ": (t=%d,l=%d) %s", type, optlen, val_to_str(type, licmgr_type_vals, "Unknown Type (%02d)") );

        licmgr_subtree = proto_item_add_subtree(tlv_item, ett_papi_licmgr_tlv);

        proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_value, tvb, offset, optlen, ENC_NA);

        switch (type) {
            case 1: /* IP Address */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_ip, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
            break;
            case 2: /* Serial Number */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_serial_number, tvb, offset, 32, ENC_ASCII);
                proto_item_append_text(tlv_item, ": %s", tvb_get_string_enc(pinfo->pool,tvb, offset, optlen, ENC_ASCII));
            break;
            case 3: /* Hostname */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_hostname, tvb, offset, optlen, ENC_ASCII);
                proto_item_append_text(tlv_item, ": %s", tvb_get_string_enc(pinfo->pool,tvb, offset, optlen, ENC_ASCII));
            break;
            case 5: /* MAC Address */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_mac_address, tvb, offset, optlen, ENC_NA);
                proto_item_append_text(tlv_item, ": %s", tvb_get_ether_name(tvb, offset));
                break;
            case 7: /* License AP remaining  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_ap_remaining, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 8: /* License PEF remaining  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_pef_remaining, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 9: /* License RFP remaining  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_rfp_remaining, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 10: /* License xSec remaining  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_xsec_remaining, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 11: /* License ACR remaining  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_acr_remaining, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 12: /* License AP used  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_ap_used, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 13: /* License PEF used  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_pef_used, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 14: /* License RFP used  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_rfp_used, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 15: /* License xSec used  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_xsec_used, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
            case 16: /* License ACR used  */
                proto_tree_add_item(licmgr_subtree, hf_papi_licmgr_license_acr_used, tvb, offset, 4, ENC_NA);
                proto_item_append_text(tlv_item, ": %u", tvb_get_ntohl(tvb, offset));
            break;
        }
        offset += optlen;
    }

    proto_tree_add_item(licmgr_tree, hf_papi_licmgr_padding, tvb, offset, -1, ENC_NA);
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

/* PAPI Debug loop ! */
static int
dissect_papi_debug(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *debug_tree, *debug_sub_tree;


    ti = proto_tree_add_item(tree, hf_papi_debug, tvb, offset, -1, ENC_NA);
    debug_tree = proto_item_add_subtree(ti, ett_papi);

    while(offset < tvb_reported_length(tvb)) {
        switch(tvb_get_uint8(tvb,offset)) {
        case 0x00:
            ti = proto_tree_add_item(debug_tree, hf_papi_debug_text, tvb, offset+3, tvb_get_ntohs(tvb,offset+1), ENC_ASCII);
            debug_sub_tree = proto_item_add_subtree(ti, ett_papi);
            proto_tree_add_item(debug_sub_tree, hf_papi_debug_text_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += tvb_get_ntohs(tvb, offset+1) + 3;
        break;
        case 0x01:
            proto_tree_add_item(debug_tree, hf_papi_debug_48bits, tvb, offset+1, 6, ENC_BIG_ENDIAN);
            offset += 7;
        break;
        case 0x02:
            proto_tree_add_item(debug_tree, hf_papi_debug_8bits, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case 0x03:
            proto_tree_add_item(debug_tree, hf_papi_debug_16bits, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += 3;
        break;
        case 0x04:
            proto_tree_add_item(debug_tree, hf_papi_debug_32bits, tvb, offset+1, 4, ENC_BIG_ENDIAN);
            offset += 5;
        break;
        case 0x05:
            proto_tree_add_item(debug_tree, hf_papi_debug_ipv4, tvb, offset+1, 4, ENC_BIG_ENDIAN);
            offset += 5;
        break;
        case 0x07:
            proto_tree_add_item(debug_tree, hf_papi_debug_16bits, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += 3;
        break;
        case 0x08:
            ti = proto_tree_add_item(debug_tree, hf_papi_debug_bytes, tvb, offset+3, tvb_get_ntohs(tvb,offset+1), ENC_NA);
            debug_sub_tree = proto_item_add_subtree(ti, ett_papi);
            proto_tree_add_item(debug_sub_tree, hf_papi_debug_bytes_length, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            offset += tvb_get_ntohs(tvb,offset+1) + 3;
        break;
        case 0x09:
            proto_tree_add_item(debug_tree, hf_papi_debug_64bits, tvb, offset+1, 8, ENC_BIG_ENDIAN);
            offset += 9;
        break;
        default:
            proto_tree_add_expert_format(debug_tree, pinfo, &ei_papi_debug_unknown, tvb, offset, 1, "Unknown (%d)", tvb_get_uint8(tvb, offset));
            offset +=1;
           }
    }

    return offset;
}

static int
dissect_papi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *papi_tree;
    unsigned  offset = 0;
    uint32_t dest_port, src_port, hdr_version;
    tvbuff_t *next_tvb;


    /* All PAPI packet start with 0x4972 !  */
    if ( tvb_get_ntohs(tvb, offset) != 0x4972 )
        return false;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PAPI");
    col_set_str(pinfo->cinfo, COL_INFO, "PAPI - Aruba AP Control Protocol");

    ti = proto_tree_add_item(tree, proto_papi, tvb, 0, PAPI_PACKET_SIZE, ENC_NA);
    papi_tree = proto_item_add_subtree(ti, ett_papi);

    proto_tree_add_item(papi_tree, hf_papi_hdr_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(papi_tree, hf_papi_hdr_version, tvb, offset, 2, ENC_BIG_ENDIAN, &hdr_version);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_dest_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(papi_tree, hf_papi_hdr_src_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(papi_tree, hf_papi_hdr_nat_port_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_garbage, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(papi_tree, hf_papi_hdr_dest_port, tvb, offset, 2, ENC_BIG_ENDIAN, &dest_port);
    offset += 2;

    proto_tree_add_item_ret_uint(papi_tree, hf_papi_hdr_src_port, tvb, offset, 2, ENC_BIG_ENDIAN, &src_port);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_packet_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_packet_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_seq_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_message_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(papi_tree, hf_papi_hdr_checksum, tvb, offset, 16, ENC_NA);
    offset += 16;

    if (hdr_version == V4V6_HDR_VERSION) {

        proto_tree_add_item(papi_tree, hf_papi_hdr_destipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
        offset += IPv6_ADDR_SIZE;

        proto_tree_add_item(papi_tree, hf_papi_hdr_srcipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
        offset += IPv6_ADDR_SIZE;

    }

    if(g_papi_debug)
    {
        offset = dissect_papi_debug(tvb, pinfo, offset, papi_tree);
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_uint_new(papi_dissector_table, dest_port, next_tvb, pinfo, tree, true, NULL)) {
        if (!dissector_try_uint_new(papi_dissector_table, src_port, next_tvb, pinfo, tree, true, NULL)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_papi(void)
{
    module_t *papi_module;

    static hf_register_info hf[] = {
        { &hf_papi_hdr_magic,
            { "Magic", "papi.hdr.magic",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "PAPI Header Magic Number", HFILL }
        },
        { &hf_papi_hdr_version,
            { "Version",  "papi.hdr.version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "PAPI Protocol Version", HFILL }
        },
        { &hf_papi_hdr_dest_ip,
            { "Destination IP", "papi.hdr.dest.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_src_ip,
            { "Source IP", "papi.hdr.src.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_nat_port_number,
            { "NAT Port Number", "papi.hdr.nat_port_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_garbage,
            { "Garbage", "papi.hdr.garbage",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_dest_port,
            { "Destination Port", "papi.hdr.dest.port",
            FT_UINT16, BASE_DEC|BASE_EXT_STRING, &papi_port_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_src_port,
            { "Source Port", "papi.hdr.src.port",
            FT_UINT16, BASE_DEC|BASE_EXT_STRING, &papi_port_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_packet_type,
            { "Packet Type", "papi.hdr.packet.type",
            FT_UINT16, BASE_DEC|BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_packet_size,
            { "Packet Size", "papi.hdr.packet.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_seq_number,
            { "Sequence Number", "papi.hdr.seq_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_message_code,
            { "Message Code", "papi.hdr.message_code",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_checksum,
            { "Checksum", "papi.hdr.checksum",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_destipv6,/* IPv6 address of Destination */
            { "Destination IPv6", "papi.hdr.dest.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_hdr_srcipv6,/* IPv6 address of Source */
            { "Source IPv6", "papi.hdr.src.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug,
            { "Debug", "papi.debug",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_text,
            { "Debug (Text)", "papi.debug.text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_text_length,
            { "Debug Text Length", "papi.debug.text_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_bytes,
            { "Debug (Bytes)", "papi.debug.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_bytes_length,
            { "Debug Bytes Length", "papi.debug.bytes_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_48bits,
            { "Debug (48 Bits)", "papi.debug.48bits",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_8bits,
            { "Debug (8 Bits)", "papi.debug.8bits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_16bits,
            { "Debug (16 Bits)", "papi.debug.16bits",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_32bits,
            { "Debug (32 Bits)", "papi.debug.32bits",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_ipv4,
            { "Debug (IPv4)", "papi.debug.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_debug_64bits,
            { "Debug (64 Bits)", "papi.debug.64bits",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_papi_licmgr,
            { "License Manager", "papi.licmgr",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_payload_len,
            { "Payload Length", "papi.licmgr.payload_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_tlv,
            { "TLV", "papi.licmgr.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_type,
            { "Type", "papi.licmgr.type",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_length,
            { "Length", "papi.licmgr.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_value,
            { "Value", "papi.licmgr.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_ip,
            { "License Manager IP Address", "papi.licmgr.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_serial_number,
            { "Serial Number", "papi.licmgr.serial_number",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_hostname,
            { "Hostname", "papi.licmgr.hostname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_mac_address,
            { "MAC Address", "papi.licmgr.mac_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_ap_remaining,
            { "License AP remaining", "papi.licmgr.license.ap.remaining",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_pef_remaining,
            { "License PEF remaining", "papi.licmgr.license.pef.remaining",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_rfp_remaining,
            { "License RFP remaining", "papi.licmgr.license.rfp.remaining",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_xsec_remaining,
            { "License xSEC remaining", "papi.licmgr.license.xsec.remaining",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_acr_remaining,
            { "License ACR remaining", "papi.licmgr.license.acr.remaining",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_ap_used,
            { "License AP used", "papi.licmgr.license.ap.used",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_pef_used,
            { "License PEF used", "papi.licmgr.license.pef.used",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_rfp_used,
            { "License RFP used", "papi.licmgr.license.rfp.used",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_xsec_used,
            { "License xSec used", "papi.licmgr.license.xsec.used",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_license_acr_used,
            { "License ACR used", "papi.licmgr.license.acr.used",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_papi_licmgr_padding,
            { "Padding", "papi.licmgr.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_papi,
        &ett_papi_licmgr,
        &ett_papi_licmgr_tlv
    };

    static ei_register_info ei[] = {
        { &ei_papi_debug_unknown, { "papi.debug.unknown", PI_PROTOCOL, PI_WARN, "Unknown", EXPFILL }},
    };

    expert_module_t* expert_papi;

    proto_papi = proto_register_protocol("Aruba PAPI", "PAPI", "papi");

    proto_register_field_array(proto_papi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_papi = expert_register_protocol(proto_papi);
    expert_register_field_array(expert_papi, ei, array_length(ei));

    papi_module = prefs_register_protocol(proto_papi, NULL);

    /* creating a dissector table for the protocol & registering the same */
    papi_dissector_table = register_dissector_table("papi.port", "PAPI protocol", proto_papi, FT_UINT16, BASE_DEC);

    prefs_register_bool_preference(papi_module, "experimental_decode",
                       "Do experimental decode",
                       "Attempt to decode parts of the message that aren't fully understood yet",
                       &g_papi_debug);

    papi_handle = register_dissector("papi", dissect_papi, proto_papi);
}


void
proto_reg_handoff_papi(void)
{
    dissector_add_uint("papi.port", LICENSE_MANAGER, create_dissector_handle(dissect_papi_license_manager, -1));
    dissector_add_uint_with_preference("udp.port", UDP_PORT_PAPI, papi_handle);
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
