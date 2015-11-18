/* packet-knxnetip.c
 * Routines for KNXnet/IP dissection
 * Copyright 2014, Alexander Gaertner <gaertner.alex@gmx.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

#define KNXNETIP_PROTOCOL_VERSION 0x10
#define KNXNETIP_HEADER_LENGTH 0x06

#define SEARCH_REQ 0x0201
#define SEARCH_RES 0x0202
#define DESCRIPTION_REQ 0x0203
#define DESCRIPTION_RES 0x0204
#define CONNECT_REQ 0x0205
#define CONNECT_RES 0x0206
#define CONNECTIONSTATE_REQ 0x0207
#define CONNECTIONSTATE_RES 0x0208
#define DISCONNECT_REQ 0x0209
#define DISCONNECT_RES 0x020A
#define DEVICE_CONFIGURATION_REQ 0x0310
#define DEVICE_CONFIGURATION_ACK 0x0311
#define TUNNELLING_REQ 0x0420
#define TUNNELLING_ACK 0x0421
#define ROUTING_INDICATION 0x0530
#define ROUTING_LOST 0x0531
#define ROUTING_BUSY 0x0532
#define REMOTE_DIAG_REQ 0x0740
#define REMOTE_DIAG_RES 0x0741
#define REMOTE_BASIC_CONF_REQ 0x0742
#define REMOTE_RESET_REQ 0x0743
#define DIB_DEVICE_INFO 0x01
#define DIB_SUPP_SVC 0x02
#define DIB_IP_CONF 0x03
#define DIB_IP_CURRENT 0x04
#define DIB_KNX_ADDRESS 0x05
#define DIB_MFR_DATA 0xFE
#define KNX_TUNNEL_CONNECTION 0x04
#define FLAGS_DEVICESTATUS_RESERVED 0xFE
#define FLAGS_DEVICESTATUS_PROGRAM 0x01
#define FLAGS_IPCAPABILITES_RESERVED 0xF8
#define FLAGS_IPCAPABILITES_BOOTIP 0x01
#define FLAGS_IPCAPABILITES_DHCP 0x02
#define FLAGS_IPCAPABILITES_AUTOIP 0x04
#define FLAGS_DEVICESTATE_RESERVED 0xFC
#define FLAGS_DEVICESTATE_KNX 0x01
#define FLAGS_DEVICESTATE_IP 0x02
/*for CEMI*/
#define RAW_REQ 0x10
#define DATA_REQ 0x11
#define POLL_DATA_REQ 0x13
#define POLL_DATA_CON 0x25
#define DATA_IND 0x29
#define BUSMON_IND 0x2B
#define RAW_IND 0x2D
#define DATA_CON 0x2E
#define RAW_CON 0x2F
#define DATA_CONNEC_REQ 0x41
#define DATA_INDV_REQ 0x4A
#define DATA_CONNEC_IND 0x89
#define DATA_INDV_IND 0x94
#define RESET_IND 0xF0
#define RESET_REQ 0xF1
#define PROPWRITE_CON 0xF5
#define PROPWRITE_REQ 0xF6
#define PROPINFO_IND 0xF7
#define FUNCPROPCOM_REQ 0xF8
#define FUNCPROPSTATREAD_REQ 0xF9
#define FUNCPROPCOM_CON 0xFA
#define PROPREAD_CON 0xFB
#define PROPREAD_REQ 0xFC
#define PL_INFO 0x1
#define RF_INFO 0x2
#define BUSMON_INFO 0x3
#define TIME_REL 0x4
#define TIME_DELAY 0x5
#define EXEND_TIME 0x6
#define BIBAT_INFO 0x7
#define RF_MULTI 0x8
#define PREAMBEL 0x9
#define RF_FAST_ACK 0xA
#define MANU_DATA 0xFE
#define RESER 0xFF
#define A_GROUPVALUE_RES 0x040
#define A_GROUPVALUE_WRT 0x080
#define A_ADC_RED 0x180
#define A_ADC_RES 0x1C0
#define A_MEM_RED 0x200
#define A_MEM_RES 0x240
#define A_MEM_WRT 0x280
#define A_SYS_RED 0x1C8
#define A_SYS_RES 0x1C9
#define A_SYS_WRT 0x1CA
#define A_SYS_BROAD 0x1CB
#define GROUPADD 0x80
#define COUPLER_SPECIFIC_SERVICE 0x3C0
#define A_AUTHORIZE_REQ 0x3D1
#define A_AUTHORIZE_RES 0x3D2
#define A_KEY_WRT 0x3D3
#define A_KEY_RES 0x3D4
#define A_PROPVALUE_RED 0x3D5
#define A_PROPVALUE_RES 0x3D6

#define FLAGS_CEMI_CONTROL1_FT 0x80
#define FLAGS_CEMI_CONTROL1_R 0x20
#define FLAGS_CEMI_CONTROL1_SB 0x10
#define FLAGS_CEMI_CONTROL1_P 0x0C
#define FLAGS_CEMI_CONTROL1_A 0x02
#define FLAGS_CEMI_CONTROL1_C 0x01
#define FLAGS_CEMI_CONTROL2_AT 0x80
#define FLAGS_CEMI_CONTROL2_HC 0x70
#define FLAGS_CEMI_CONTROL2_EFF 0x0F
#define FLAGS_CEMI_RF_RESERVED 0xC0
#define FLAGS_CEMI_RF_MESURE 0x30
#define FLAGS_CEMI_RF_MESURE_RE 0x0C
#define FLAGS_CEMI_RF_BATTERY 0x02
#define FLAGS_CEMI_RF_BIDIRETIONAL 0x01
#define FLAGS_CEMI_BUS_F 0x80
#define FLAGS_CEMI_BUS_B 0x40
#define FLAGS_CEMI_BUS_P 0x20
#define FLAGS_CEMI_BUS_D 0x10
#define FLAGS_CEMI_BUS_L 0x08
#define FLAGS_CEMI_BUS_SSS 0x07
#define FLAGS_CEMI_FASTACK_CRC 0x400
#define FLAGS_CEMI_FASTACK_ERROR 0x200
#define FLAGS_CEMI_FASTACK_RES 0x100
#define FLAGS_CEMI_FASTACK_INFO 0xFF


void proto_register_knxnetip(void);
void proto_reg_handoff_knxnetip(void);

static int proto_knxnetip = -1;
static int hf_knxnetip_headerlength = -1;
static int hf_knxnetip_version = -1;
static int hf_knxnetip_servicetype = -1;
static int hf_knxnetip_totallength = -1;
static int hf_knxnetip_hpai = -1;
static int hf_knxnetip_hpai_structure_length = -1;
static int hf_knxnetip_hpai_host_protocol = -1;
static int hf_knxnetip_hpai_ip_address = -1;
static int hf_knxnetip_hpai_port = -1;
static int hf_knxnetip_dib = -1;
static int hf_knxnetip_structure_length = -1;
static int hf_knxnetip_dib_type = -1;
static int hf_knxnetip_dib_medium = -1;
static int hf_knxnetip_knxaddress = -1;
static int hf_knxnetip_dib_projectid = -1;
static int hf_knxnetip_dib_serialnumber = -1;
static int hf_knxnetip_dib_multicast_address = -1;
static int hf_knxnetip_mac_address = -1;
static int hf_knxnetip_dib_friendly = -1;
static int hf_knxnetip_dib_service = -1;
static int hf_knxnetip_dib_ipaddress = -1;
static int hf_knxnetip_dib_subnet = -1;
static int hf_knxnetip_dib_gateway = -1;
static int hf_knxnetip_dib_ipassign = -1;
static int hf_knxnetip_dib_dhcp = -1;
static int hf_knxnetip_dib_manuid = -1;
static int hf_knxnetip_dib_manudata = -1;
static int hf_knxnetip_cri = -1;
static int hf_knxnetip_connection_type = -1;
static int hf_knxnetip_cri_protocol_data = -1;
static int hf_knxnetip_communication_channel_id = -1;
static int hf_knxnetip_crd_protocol_data = -1;
static int hf_knxnetip_crd = -1;
static int hf_knxnetip_connect_status = -1;
static int hf_knxnetip_connectionstate_status = -1;
static int hf_knxnetip_counter = -1;
static int hf_knxnetip_confack_status = -1;
static int hf_knxnetip_tunnelack_status = -1;
static int hf_knxnetip_numberoflost = -1;
static int hf_knxnetip_busywaittime = -1;
static int hf_knxnetip_busycontrol = -1;
static int hf_knxnetip_knxlayer = -1;
static int hf_knxnetip_selector_type = -1;
static int hf_knxnetip_reset = -1;
static int hf_knxnetip_projectnumber = -1;
static int hf_knxnetip_installnumber = -1;
static int hf_knxnetip_dib_svc_version = -1;
static int hf_knxnetip_reserved = -1;
static int hf_knxnetip_raw = -1;
static int hf_knxnetip_data = -1;
static int hf_knxnetip_additional = -1;
static int hf_knxnetip_unknown = -1;
static int hf_knxnetip_polldata = -1;


static int hf_knxnetip_cemi = -1;
static int hf_knxnetip_cemi_mc = -1;
static int hf_knxnetip_cemi_addlength = -1;
static int hf_knxnetip_cemi_additemlength = -1;
static int hf_knxnetip_cemi_typid = -1;
static int hf_knxnetip_cemi_type_pl = -1;
static int hf_knxnetip_cemi_type_relt = -1;
static int hf_knxnetip_cemi_type_delay = -1;
static int hf_knxnetip_cemi_type_exttime = -1;
static int hf_knxnetip_cemi_type_bibat = -1;
static int hf_knxnetip_cemi_sourceaddress = -1;
static int hf_knxnetip_cemi_destaddress = -1;
static int hf_knxnetip_cemi_tpci = -1;
static int hf_knxnetip_cemi_counter = -1;
static int hf_knxnetip_cemi_npdu_length = -1;
static int hf_knxnetip_cemi_tpdu_length = -1;
static int hf_knxnetip_cemi_apci = -1;
static int hf_knxnetip_cemi_data = -1;
static int hf_knxnetip_cemi_numberofslots = -1;
static int hf_knxnetip_cemi_iot = -1;
static int hf_knxnetip_cemi_oi = -1;
static int hf_knxnetip_cemi_six = -1;
static int hf_knxnetip_cemi_pid = -1;
static int hf_knxnetip_cemi_reserved = -1;
static int hf_knxnetip_cemi_noe = -1;
static int hf_knxnetip_cemi_error = -1;
static int hf_knxnetip_cemi_return = -1;
static int hf_knxnetip_cemi_numberofelements = -1;
static int hf_knxnetip_cemi_apci_memory_number = -1;
static int hf_knxnetip_cemi_rf_lfn = -1;
static int hf_knxnetip_cemi_type_bibat_block = -1;
static int hf_knxnetip_cemi_type_rf_multi_fastack = -1;
static int hf_knxnetip_cemi_type_rf_multi_freq = -1;
static int hf_knxnetip_cemi_type_rf_multi_channel = -1;
static int hf_knxnetip_cemi_type_rf_multi_recep_freq = -1;
static int hf_knxnetip_cemi_rf_sn = -1;
static int hf_knxnetip_cemi_type_preamble_length = -1;
static int hf_knxnetip_cemi_type_postamble_length = -1;
static int hf_knxnetip_cemi_subfunction = -1;
static int hf_knxnetip_cemi_manuspecificdata = -1;
static int hf_knxnetip_cemi_apci_mem_address = -1;
static int hf_knxnetip_cemi_channel = -1;
static int hf_knxnetip_cemi_apci_key = -1;
static int hf_knxnetip_cemi_apci_level = -1;
static int hf_knxnetip_cemi_apci_object = -1;
static int hf_knxnetip_cemi_apci_propid = -1;


/*FLAGS
DIB Device Status Flags*/
static int hf_knxnetip_dib_status = -1;
static int hf_knxnetip_dib_status_flag_reserved = -1;
static int hf_knxnetip_dib_status_flag_program = -1;
static const int *dib_device_status_flags[] = {
    &hf_knxnetip_dib_status_flag_reserved,
    &hf_knxnetip_dib_status_flag_program,
    NULL
};
/*DIB IP Capabilities Flags*/
static int hf_knxnetip_dib_ipcapa = -1;
static int hf_knxnetip_dib_ipcapa_flag_bootip = -1;
static int hf_knxnetip_dib_ipcapa_flag_dhcp = -1;
static int hf_knxnetip_dib_ipcapa_flag_autoip = -1;
static int hf_knxnetip_dib_ipcapa_flag_reserved = -1;
static const int *dib_ipcapabilities_flags[] = {
    &hf_knxnetip_dib_ipcapa_flag_bootip,
    &hf_knxnetip_dib_ipcapa_flag_dhcp,
    &hf_knxnetip_dib_ipcapa_flag_autoip,
    &hf_knxnetip_dib_ipcapa_flag_reserved,
    NULL
};
/*Device State*/
static int hf_knxnetip_devicestate = -1;
static int hf_knxnetip_devicestate_reserved = -1;
static int hf_knxnetip_devicestate_knx = -1;
static int hf_knxnetip_devicestate_ip = -1;
static const int *devicestate_flags[] = {
    &hf_knxnetip_devicestate_knx,
    &hf_knxnetip_devicestate_ip,
    &hf_knxnetip_devicestate_reserved,
    NULL
};
/*cEMI FLAGS
controlfield 1*/
static int hf_knxnetip_cemi_controlfield1 = -1;
static int hf_knxnetip_cemi_flag_frametype = -1;
static int hf_knxnetip_cemi_flag_repeat = -1;
static int hf_knxnetip_cemi_flag_sb = -1;
static int hf_knxnetip_cemi_flag_priority = -1;
static int hf_knxnetip_cemi_flag_ack = -1;
static int hf_knxnetip_cemi_flag_confirm = -1;
static const int *cemi_control1_flags[] = {
    &hf_knxnetip_cemi_flag_frametype,
    &hf_knxnetip_cemi_flag_repeat,
    &hf_knxnetip_cemi_flag_sb,
    &hf_knxnetip_cemi_flag_priority,
    &hf_knxnetip_cemi_flag_ack,
    &hf_knxnetip_cemi_flag_confirm,
    NULL
};
/*controlfield 2*/
static int hf_knxnetip_cemi_controlfield2 = -1;
static int hf_knxnetip_flag_destaddress = -1;
static int hf_knxnetip_flag_hop = -1;
static int hf_knxnetip_flag_eff = -1;
static const int *cemi_control2_flags[] = {
    &hf_knxnetip_flag_destaddress,
    &hf_knxnetip_flag_hop,
    &hf_knxnetip_flag_eff,
    NULL
};

static int hf_knxnetip_cemi_type_rf_info = -1;
static int hf_knxnetip_cemi_type_rf_reserved = -1;
static int hf_knxnetip_cemi_type_rf_mesure = -1;
static int hf_knxnetip_cemi_type_rf_mesure_re = -1;
static int hf_knxnetip_cemi_type_rf_battery = -1;
static int hf_knxnetip_cemi_type_rf_bidirekt = -1;
static const int *cemi_rf_info[] = {
    &hf_knxnetip_cemi_type_rf_reserved,
    &hf_knxnetip_cemi_type_rf_mesure,
    &hf_knxnetip_cemi_type_rf_mesure_re,
    &hf_knxnetip_cemi_type_rf_battery,
    &hf_knxnetip_cemi_type_rf_bidirekt,
    NULL
};

static int hf_knxnetip_cemi_type_bus = -1;
static int hf_knxnetip_cemi_type_bus_flag_f = -1;
static int hf_knxnetip_cemi_type_bus_flag_b = -1;
static int hf_knxnetip_cemi_type_bus_flag_p = -1;
static int hf_knxnetip_cemi_type_bus_flag_d = -1;
static int hf_knxnetip_cemi_type_bus_flag_l = -1;
static int hf_knxnetip_cemi_type_bus_flag_sss = -1;
static const int *cemi_bus_flags[] = {
    &hf_knxnetip_cemi_type_bus_flag_f,
    &hf_knxnetip_cemi_type_bus_flag_b,
    &hf_knxnetip_cemi_type_bus_flag_p,
    &hf_knxnetip_cemi_type_bus_flag_d,
    &hf_knxnetip_cemi_type_bus_flag_l,
    &hf_knxnetip_cemi_type_bus_flag_sss,
    NULL
};

static int hf_knxnetip_cemi_type_fastack = -1;
static int hf_knxnetip_cemi_type_fastack_crc = -1;
static int hf_knxnetip_cemi_type_fastack_error = -1;
static int hf_knxnetip_cemi_type_fastack_received = -1;
static int hf_knxnetip_cemi_type_fastack_info = -1;
static const int *cemi_fastack_flags[] = {
    &hf_knxnetip_cemi_type_fastack_crc,
    &hf_knxnetip_cemi_type_fastack_error,
    &hf_knxnetip_cemi_type_fastack_received,
    &hf_knxnetip_cemi_type_fastack_info,
    NULL
};


static const value_string knxnetip_service_identifier[] = {
    { SEARCH_REQ,               "SEARCH_REQUEST" },
    { SEARCH_RES,               "SEARCH_RESPONSE" },
    { DESCRIPTION_REQ,          "DESCRIPTION_REQUEST" },
    { DESCRIPTION_RES,          "DESCRIPTION_RESPONSE" },
    { CONNECT_REQ,              "CONNECT_REQUEST" },
    { CONNECT_RES,              "CONNECT_RESPONSE" },
    { CONNECTIONSTATE_REQ,      "CONNECTIONSTATE_REQUEST" },
    { CONNECTIONSTATE_RES,      "CONNECTIONSTATE_RESPONSE" },
    { DISCONNECT_REQ,           "DISCONNECT_REQUEST" },
    { DISCONNECT_RES,           "DISCONNECT_RESPONSE" },
    { DEVICE_CONFIGURATION_REQ, "DEVICE_CONFIGURATION_REQUEST" },
    { DEVICE_CONFIGURATION_ACK, "DEVICE_CONFIGURATION_ACK" },
    { TUNNELLING_REQ,           "TUNNELLING_REQUEST" },
    { TUNNELLING_ACK,           "TUNNELING_ACK" },
    { ROUTING_INDICATION,       "ROUTING_INDICATION" },
    { ROUTING_LOST,             "ROUTING_LOST_MESSAGE" },
    { ROUTING_BUSY,             "ROUTING_BUSY" },
    { REMOTE_DIAG_REQ,          "REMOTE_DIAGNOSTIC_REQUEST" },
    { REMOTE_DIAG_RES,          "REMOTE_DIAGNOSTIC_RESPONSE" },
    { REMOTE_BASIC_CONF_REQ,    "REMOTE_BASIC_CONFIGURATION_REQUEST" },
    { REMOTE_RESET_REQ,         "REMOTE_RESET_REQUEST" },
    { 0, NULL }
};


static const value_string knxnetip_service_types[] = {
    { 0x02, "KNXnet/IP Core" },
    { 0x03, "KNXnet/IP Device Management" },
    { 0x04, "KNXnet/IP Tunneling" },
    { 0x05, "KNXnet/IP Routing" },
    { 0x06, "KNXnet/IP Remote Logging" },
    { 0x07, "KNXnet/IP Remote Configuration and Diagnosis" },
    { 0x08, "KNXnet/IP Object Server" },
    { 0, NULL }
};

static const value_string knxnetip_connection_types[] = {
    { 0x03, "DEVICE_MGMT_CONNECTION" },
    { 0x04, "TUNNEL_CONNECTION" },
    { 0x06, "REMLOG_CONNECTION" },
    { 0x07, "REMCONF_CONNECTION" },
    { 0x08, "OBJSVR_CONNECTION" },
    { 0, NULL }
};


static const value_string knxnetip_connect_response_status_codes[] = {
    { 0x00, "E_NO_ERROR - The connection was established successfully" },
    { 0x22, "E_CONNECTION_TYPE - The KNXnet/IP server device does not support the requested connection type" },
    { 0x23, "E_CONNECTION_OPTION - The KNXnet/IP server device does not support one or more requested connection options" },
    { 0x24, "E_NO_MORE_CONNECTIONS - The KNXnet/IP server device could not accept the new data connection (busy)" },
    { 0, NULL }
};

static const value_string knxnetip_connectionstate_response_status_codes[] = {
    { 0x00, "E_NO_ERROR - The connection state is normal" },
    { 0x21, "E_CONNECTION_ID - The KNXnet/IP server device could not find an active data connection with the specified ID" },
    { 0x26, "E_DATA_CONNECTION - The KNXnet/IP server device detected an error concerning the data connection with the specified ID" },
    { 0x27, "E_KNX_CONNECTION - The KNXnet/IP server device detected an error concerning the EIB bus / KNX subsystem connection with the specified ID" },
    { 0, NULL }
};

static const value_string knxnetip_tunneling_error_codes[] = {
    { 0x00, "E_NO_ERROR - The message was received successfully" },
    { 0x29, "E_TUNNELLING_LAYER - The KNXnet/IP server device does not support the requested tunnelling layer" },
    { 0, NULL }
};

static const value_string knxnetip_device_configuration_ack_status_codes[] = {
    { 0x00, "E_NO_ERROR - The message was received successfully" },
    { 0, NULL }
};

static const value_string knxnetip_dib_description_type_codes[] = {
    { DIB_DEVICE_INFO, "DEVICE_INFO" },
    { DIB_SUPP_SVC,    "SUPP_SVC_FAMILIES" },
    { DIB_IP_CONF,     "IP_CONFIG" },
    { DIB_IP_CURRENT,  "IP_CUR_CONFIG" },
    { DIB_KNX_ADDRESS, "KNX_ADDRESSES" },
    { DIB_MFR_DATA,    "MFR_DATA" },
    { 0, NULL }
};

static const value_string knxnetip_dib_medium_codes[] = {
    { 0x01, "reserved" },
    { 0x02, "KNX TP" },
    { 0x04, "KNX PL110" },
    { 0x08, "reserved" },
    { 0x10, "KNX RF" },
    { 0x20, "KNX IP" },
    { 0, NULL }
};

static const value_string knxnetip_host_protocol_codes[] = {
    { 0x01, "IPV4_UDP" },
    { 0x02, "IPV4_TCP" },
    { 0, NULL }
};

static const value_string knxnetip_ip_assignment_method[] = {
    { 0x01, "manuell" },
    { 0x02, "BootP" },
    { 0x04, "DHCP" },
    { 0x08, "AutoIP" },
    { 0, NULL }
};

static const value_string knxnetip_knxlayer_values[] = {
    { 0x02, "TUNNEL_LINKLAYER" },
    { 0x04, "TUNNEL_RAW"},
    { 0x80, "TUNNEL_BUSMONITOR"},
    { 0, NULL}
};

static const value_string knxnetip_selector_types[] = {
    { 0x01, "PrgMode Selector" },
    { 0x02, "MAC Selector" },
    { 0, NULL }
};

static const value_string knxnetip_reset_codes[] = {
    { 0x01, "Restart" },
    { 0x02, "Master Reset" },
    { 0, NULL }
};

/*for CEMI*/
static const value_string cemi_messagecodes[] = {
    { RAW_REQ,              "L_Raw.req"},
    { DATA_REQ,             "L_Data.req"},
    { POLL_DATA_REQ,        "L_Poll_Data.req"},
    { POLL_DATA_CON,        "L_Poll_Data.con"},
    { DATA_IND,             "L_Data.ind"},
    { BUSMON_IND,           "L_Busmon.ind"},
    { RAW_IND,              "L_Raw.ind"},
    { DATA_CON,             "L_Data.con"},
    { RAW_CON,              "L_Raw.con"},
    { DATA_CONNEC_REQ,      "T_Data_Connected.req"},
    { DATA_INDV_REQ,        "T_Data_Individual.req"},
    { DATA_CONNEC_IND,      "T_Data_Connected.ind"},
    { DATA_INDV_IND,        "T_Data_Individual.ind"},
    { RESET_IND,            "M_Reset.ind"},
    { RESET_REQ,            "M_Reset.req"},
    { PROPWRITE_CON,        "M_PropWrite.con"},
    { PROPWRITE_REQ,        "M_PropWrite.req"},
    { PROPINFO_IND,         "M_PropInfo.ind"},
    { FUNCPROPCOM_REQ,      "M_FuncPropCommand.req"},
    { FUNCPROPSTATREAD_REQ, "M_FuncPropStateRead.req"},
    { FUNCPROPCOM_CON,      "M_FuncPropCommand/StateRead.con"},
    { PROPREAD_CON,         "M_PropRead.con"},
    { PROPREAD_REQ,         "M_PropRead.req"},
    { 0, NULL }
};

static const value_string cemi_add_type_id[] = {
    { 0x00,        "reserved" },
    { PL_INFO,     "PL Info"},
    { RF_INFO,     "RF Info"},
    { BUSMON_INFO, "Busmonitor Info"},
    { TIME_REL,    "relative timestamp"},
    { TIME_DELAY,  "time delay until send"},
    { EXEND_TIME,  "extended relative timestamp"},
    { BIBAT_INFO,  "BiBat information"},
    { RF_MULTI,    "RF Multi information"},
    { PREAMBEL,    "Preamble and postamble"},
    { RF_FAST_ACK, "RF Fast Ack information"},
    { MANU_DATA,   "Manufacturer specific data"},
    { RESER,       "reserved"},
    { 0, NULL}
};

static const value_string cemi_tpci_vals[] = {
    { 0x0, "UDT (Unnumbered Data Packet)" },
    { 0x2, "UCD (Unnumbered)"},
    { 0x1, "NDT (Numbered Data Packet)"},
    { 0x3, "NCD (Numbered Control Data)"},
    { 0, NULL}
};

static const value_string cemi_apci_codes[] = {
    { 0x000, "A_GroupValue_Read" },
    { 0x001, "A_GroupValue_Response"},
    { 0x002, "A_GroupValue_Write"},
    { 0x0C0, "A_IndividualAddress_Write"},
    { 0x100, "A_IndividualAddress_Read"},
    { 0x140, "A_IndividualAddress_Response"},
    { 0x006, "A_ADC_Read"},
    { 0x1C0, "A_ADC_Response"},
    { 0x1C4, "A_SystemNetworkParameter_Read"},
    { 0x1C9, "A_SystemNetworkParameter_Response"},
    { 0x1CA, "A_SystemNetworkParameter_Write"},
    { 0x020, "A_Memory_Read"},
    { 0x024, "A_Memory_Response"},
    { 0x028, "A_Memory_Write"},
    { 0x2C0, "A_UserMemory_Read"},
    { 0x2C1, "A_UserMemory_Response"},
    { 0x2C2, "A_UserMemory_Write"},
    { 0x2C5, "A_UserManufacturerInfo_Read"},
    { 0x2C6, "A_UserManufacturerInfo_Response"},
    { 0x2C7, "A_FunctionPropertyCommand"},
    { 0x2C8, "A_FunctionPropertyState_Read"},
    { 0x2C9, "A_FunctionPropertyState_Response"},
    { 0x300, "A_DeviceDescriptor_Read"},
    { 0x340, "A_DeviceDescriptor_Response"},
    { 0x380, "A_Restart"},
    { 0x3D1, "A_Authorize_Request"},
    { 0x3D2, "A_Authorize_Response"},
    { 0x3D3, "A_Key_Write"},
    { 0x3D4, "A_Key_Response"},
    { 0x3D5, "A_PropertyValue_Read"},
    { 0x3D6, "A_PropertyValue_Response"},
    { 0x3D7, "A_PropertyValue_Write"},
    { 0x3D8, "A_PropertyDescription_Read"},
    { 0x3D9, "A_PropertyDescription_Response"},
    { 0x3DA, "A_NetworkParameter_Read"},
    { 0x3DB, "A_NetworkParameter_Response"},
    { 0x3DC, "A_IndividualAddressSerialNumber_Read"},
    { 0x3DD, "A_IndividualAddressSerialNumber_Response"},
    { 0x3DF, "A_IndividualAddressSerialNumber_Write"},
    { 0x3E0, "A_DomainAddress_Write"},
    { 0x3E1, "A_DomainAddress_Read"},
    { 0x3E2, "A_DomainAddress_Response"},
    { 0x3E3, "A_DomainAddressSelective_Read"},
    { 0x3E4, "A_NetworkParameter_Write"},
    { 0x3E5, "A_Link_Read"},
    { 0x3E6, "A_Link_Response"},
    { 0x3E7, "A_Link_Write"},
    { 0x3E8, "A_GroupPropValue_Read"},
    { 0x3E9, "A_GroupPropValue_Response"},
    { 0x3EA, "A_GroupPropValue_Write"},
    { 0x3EB, "A_GroupPropValue_InfoReport"},
    { 0x3EC, "A_DomainAddressSerialNumber_Read"},
    { 0x3ED, "A_DomainAddressSerialNumber_Response"},
    { 0x3EE, "A_DomainAddressSerialNumber_Write"},
    { 0x3F0, "A_FileStream_InforReport"},
    { 0, NULL}
};

static const value_string cemi_propertyid[] = {
    {  1, "PID_OBJECT_TYPE" },
    {  8, "PID_SERVICE_CONTROL" },
    {  9, "PID_FIRMWARE_REVISION" },
    { 11, "PID_SERIAL_NUMBER" },
    { 12, "PID_MANUFACTURER_ID" },
    { 14, "PID_DEVICE_CONTROL" },
    { 19, "PID_MANUFACTURE_DATA" },
    { 51, "PID_ROUTING_COUNT" },
    { 52, "PID_MAX_RETRY_COUNT " },
    { 53, "PID_ERROR_FLAGS" },
    { 54, "PID_PROGMODE" },
    { 56, "PID_MAX_APDULENGTH" },
    { 57, "PID_SUBNET_ADDR" },
    { 58, "PID_DEVICE_ADDR" },
    { 59, "PID_PB_CONFIG" },
    { 60, "PID_ADDR_REPORT" },
    { 61, "PID_ADDR_CHECK" },
    { 62, "PID_OBJECT_VALUE" },
    { 63, "PID_OBJECTLINK" },
    { 64, "PID_APPLICATION" },
    { 65, "PID_PARAMETER" },
    { 66, "PID_OBJECTADDRESS" },
    { 67, "PID_PSU_TYPE" },
    { 68, "PID_PSU_STATUS" },
    { 70, "PID_DOMAIN_ADDR"},
    { 71, "PID_IO_LIST"},
    { 0, NULL }
};

static const value_string cemi_error_codes[] = {
    { 0x00, "Unspecified Error"},
    { 0x01, "Out of range"},
    { 0x02, "Out of maxrange"},
    { 0x03, "Out of minrange"},
    { 0x04, "Memory Error"},
    { 0x05, "Read only"},
    { 0x06, "Illegal command"},
    { 0x07, "Void DP"},
    { 0x08, "Type conflict"},
    { 0x09, "Prop. Index range error"},
    { 0x0A, "Value temporarily not writeable"},
    { 0, NULL }
};

static const value_string cemi_bibat_ctrl[] = {
    { 0x0, "asynchr. RF frame"},
    { 0x1, "Fast_ACK"},
    { 0x4, "synchronous L_Data frames"},
    { 0x5, "Sync frame"},
    { 0x6, "Help Call"},
    { 0x7, "Help Call Response"},
    { 0, NULL }
};

static gint ett_knxnetip = -1;
static gint ett_knxnetip_header = -1;
static gint ett_knxnetip_body = -1;
static gint ett_knxnetip_hpai = -1;
static gint ett_knxnetip_dib = -1;
static gint ett_knxnetip_dib_projectid = -1;
static gint ett_knxnetip_dib_service = -1;
static gint ett_knxnetip_cri = -1;
static gint ett_knxnetip_crd = -1;
static gint ett_knxnetip_dib_status = -1;
static gint ett_knxnetip_dib_ipcapa = -1;
static gint ett_knxnetip_devicestate = -1;
static gint ett_knxnetip_cemi = -1;
static gint ett_knxnetip_cemi_additional = -1;
static gint ett_knxnetip_cemi_additional_item = -1;
static gint ett_knxnetip_cemi_control1 = -1;
static gint ett_knxnetip_cemi_control2 = -1;
static gint ett_knxnetip_cemi_rf_info = -1;
static gint ett_knxnetip_cemi_bus_info = -1;
static gint ett_knxnetip_cemi_fastack = -1;

static expert_field ei_knxnetip_length = EI_INIT;

static void dissect_hpai(tvbuff_t *tvb, guint32 *offset, proto_tree *insert_tree, const char *append_text) {

    proto_item *hpai_item = NULL;
    proto_item *slength = NULL;

    proto_tree *hpai_tree = NULL;

    hpai_item = proto_tree_add_item( insert_tree, hf_knxnetip_hpai, tvb, *offset, 8, ENC_NA );
    hpai_tree = proto_item_add_subtree(hpai_item, ett_knxnetip_hpai);
    proto_item_append_text(hpai_item, "%s", append_text);
    slength= proto_tree_add_item(hpai_tree, hf_knxnetip_hpai_structure_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(slength, " octets");
    *offset+=1;
    proto_tree_add_item(hpai_tree, hf_knxnetip_hpai_host_protocol, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset+=1;
    proto_tree_add_item(hpai_tree, hf_knxnetip_hpai_ip_address, tvb, *offset, 4, ENC_BIG_ENDIAN);
    *offset+=4;
    proto_tree_add_item(hpai_tree, hf_knxnetip_hpai_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
    *offset+=2;

}

static gboolean dissect_dib(tvbuff_t *tvb, guint32 *offset, proto_tree *insert_tree) {

    proto_item *dib_item = NULL;
    proto_item *struct_length = NULL;
    proto_item *projectid_item = NULL;
    proto_item *service_item = NULL;

    proto_tree *dib_tree = NULL;
    proto_tree *projectid_tree = NULL;
    proto_tree *service_tree = NULL;

    guint8 i;
    guint8 dib_type;
    guint8 length;
    guint16 knx_address;
    guint16 install_id;

    length = tvb_get_guint8(tvb, *offset);
    dib_item = proto_tree_add_item(insert_tree, hf_knxnetip_dib, tvb, *offset, length, ENC_NA);
    dib_tree = proto_item_add_subtree(dib_item, ett_knxnetip_dib);
    struct_length= proto_tree_add_item(dib_tree, hf_knxnetip_structure_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(struct_length, " octets");
    *offset+=1;
    proto_tree_add_item(dib_tree, hf_knxnetip_dib_type, tvb, *offset, 1, ENC_BIG_ENDIAN);
    dib_type = tvb_get_guint8(tvb, *offset);
    proto_item_append_text(dib_item, ": %s", val_to_str_const(dib_type, knxnetip_dib_description_type_codes, "Unknown Type"));
    *offset+=1;

    switch (dib_type){

        case(DIB_DEVICE_INFO):
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_medium, tvb, *offset, 1, ENC_BIG_ENDIAN);
            *offset+=1;
            proto_tree_add_bitmask(dib_tree, tvb, *offset, hf_knxnetip_dib_status, ett_knxnetip_dib_status, dib_device_status_flags, ENC_BIG_ENDIAN);
            *offset+=1;
            knx_address = tvb_get_ntohs(tvb, *offset);
            proto_tree_add_uint_format(dib_tree, hf_knxnetip_knxaddress, tvb, *offset, 2, knx_address, "KNX Address %d.%d.%d", ((knx_address & 0xF000)>>12),((knx_address & 0x0F00)>>8),(knx_address & 0xFF));
            *offset+=2;
            projectid_item = proto_tree_add_item(dib_tree, hf_knxnetip_dib_projectid, tvb, *offset, 2, ENC_BIG_ENDIAN);
            projectid_tree = proto_item_add_subtree(projectid_item, ett_knxnetip_dib_projectid);
            install_id = tvb_get_ntohs(tvb, *offset);
            proto_tree_add_uint_format(projectid_tree, hf_knxnetip_projectnumber, tvb, *offset, 2, install_id, "Project number %d", (install_id & 0xFFF0)>>4);
            proto_tree_add_uint_format(projectid_tree, hf_knxnetip_installnumber, tvb, *offset, 2, install_id, "Installation number %d", (install_id & 0xF));
            *offset+=2;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_serialnumber, tvb, *offset, 6, ENC_NA);
            *offset+=6;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_multicast_address, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_item(dib_tree, hf_knxnetip_mac_address, tvb, *offset, 6, ENC_NA);
            *offset+=6;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_friendly, tvb, *offset, 30, ENC_ASCII|ENC_NA );
            *offset+=30;
            break;

        case(DIB_SUPP_SVC):
             if (length > 4) {
                length-=4;
             } else {
                return TRUE;
             }

             for (i = 0; i <= length; i+=2) {
                 service_item = proto_tree_add_item(dib_tree, hf_knxnetip_dib_service, tvb, *offset, 1, ENC_BIG_ENDIAN);
                 service_tree = proto_item_add_subtree(service_item, ett_knxnetip_dib_service);
                 *offset+=1;
                 proto_tree_add_item(service_tree, hf_knxnetip_dib_svc_version, tvb, *offset, 1, ENC_BIG_ENDIAN);
                 *offset+=1;
             }
             break;

        case(DIB_IP_CONF):
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_ipaddress, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_subnet, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_gateway, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_bitmask(dib_tree, tvb, *offset, hf_knxnetip_dib_ipcapa, ett_knxnetip_dib_ipcapa, dib_ipcapabilities_flags, ENC_BIG_ENDIAN);
            *offset+=1;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_ipassign, tvb, *offset, 1, ENC_BIG_ENDIAN);
            *offset+=1;
            break;

        case(DIB_IP_CURRENT):
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_ipaddress, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_subnet, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_gateway, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_dhcp, tvb, *offset, 4, ENC_BIG_ENDIAN);
            *offset+=4;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_ipassign, tvb, *offset, 1, ENC_BIG_ENDIAN);
            *offset+=1;
            proto_tree_add_item(dib_tree, hf_knxnetip_reserved, tvb, *offset, 1, ENC_NA);
            *offset+=1;
            break;

        case(DIB_KNX_ADDRESS):
            if (length > 4) {
                length-=4;
            } else {
                return TRUE;
            }

            for (i = 0; i <= length; i+=2) {
                knx_address = tvb_get_ntohs(tvb, *offset);
                proto_tree_add_uint_format(dib_tree, hf_knxnetip_knxaddress, tvb, *offset, 2, knx_address, "KNX Address %d.%d.%d", ((knx_address & 0xF000)>>12),((knx_address & 0x0F00)>>8),(knx_address & 0xFF));
                *offset+=2;
             }
             break;

        case(DIB_MFR_DATA):
            if (length > 4) {
                length-=4;
            } else {
                return TRUE;
            }
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_manuid, tvb, *offset, 2, ENC_BIG_ENDIAN);
            *offset+=2;
            proto_tree_add_item(dib_tree, hf_knxnetip_dib_manudata, tvb, *offset, length, ENC_ASCII|ENC_NA);
            *offset+=length;
            break;
    }

    return FALSE;
}

static guint dissect_cri(tvbuff_t *tvb, guint32 offset, proto_tree *insert_tree) {

    proto_item *cri_item = NULL;
    proto_item *cri_length = NULL;
    proto_tree *cri_tree = NULL;

    guint8 length;

    length = tvb_get_guint8(tvb ,offset);
    cri_item = proto_tree_add_item(insert_tree, hf_knxnetip_cri, tvb, offset, length, ENC_NA);
    cri_tree = proto_item_add_subtree(cri_item, ett_knxnetip_cri);

    cri_length= proto_tree_add_item(cri_tree, hf_knxnetip_structure_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(cri_length, " octets");
    offset+=1;
    proto_tree_add_item(cri_tree, hf_knxnetip_connection_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    if (tvb_get_guint8(tvb,offset-1)== KNX_TUNNEL_CONNECTION ){
        proto_tree_add_item(cri_tree, hf_knxnetip_knxlayer, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        proto_tree_add_item(cri_tree, hf_knxnetip_reserved, tvb, offset, 1, ENC_NA);
        offset+=1;
    }
    else if (length > 2) {
        proto_tree_add_item(cri_tree, hf_knxnetip_cri_protocol_data, tvb, offset, (length-2), ENC_NA);
        offset+=(length-2);
    }
    return offset;
}

static void dissect_crd(tvbuff_t *tvb, guint32 *offset, proto_tree *insert_tree) {

    proto_item *crd_item = NULL;
    proto_item *crd_length = NULL;
    proto_tree *crd_tree = NULL;

    guint8 length;
    guint16 knx_address;

    length = tvb_get_guint8(tvb, *offset);
    crd_item = proto_tree_add_item(insert_tree, hf_knxnetip_crd, tvb, *offset, length, ENC_NA);
    crd_tree = proto_item_add_subtree(crd_item, ett_knxnetip_crd);

    crd_length= proto_tree_add_item(crd_tree, hf_knxnetip_structure_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(crd_length, " octets");
    *offset+=1;
    proto_tree_add_item(crd_tree, hf_knxnetip_connection_type, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset+=1;
    if (tvb_get_guint8(tvb, *offset-1) == KNX_TUNNEL_CONNECTION){
        knx_address = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint_format(crd_tree, hf_knxnetip_knxaddress, tvb, *offset, 2, knx_address, "KNX Address %d.%d.%d", ((knx_address & 0xF000)>>12),((knx_address & 0x0F00)>>8),(knx_address & 0xFF));
        *offset+=2;
    }
    else if (length > 2) {
        proto_tree_add_item(crd_tree, hf_knxnetip_crd_protocol_data, tvb, *offset, (length-2), ENC_NA);
        *offset+=(length-2);
    }
}

static guint dissect_connection_header(tvbuff_t *tvb, guint32 offset, proto_tree *insert_tree, gboolean have_status) {

    proto_item *struct_length = NULL;

    struct_length= proto_tree_add_item(insert_tree, hf_knxnetip_structure_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(struct_length, " octets");
    offset+=1;
    proto_tree_add_item(insert_tree, hf_knxnetip_communication_channel_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    proto_tree_add_item(insert_tree, hf_knxnetip_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    if (have_status == FALSE){
        proto_tree_add_item(insert_tree, hf_knxnetip_reserved, tvb, offset, 1, ENC_NA);
        offset+=1;
    }

    return offset;
}

static guint dissect_selector(tvbuff_t *tvb, guint32 offset, proto_tree *insert_tree){

    proto_item *struct_length = NULL;

    struct_length= proto_tree_add_item(insert_tree, hf_knxnetip_structure_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(struct_length, " octets");
    offset+=1;
    proto_tree_add_item(insert_tree, hf_knxnetip_selector_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    if (tvb_get_guint8(tvb, offset-1)==0x02){
        proto_tree_add_item(insert_tree, hf_knxnetip_mac_address, tvb, offset, 6, ENC_NA);
        offset+=6;
    }
    return offset;
}

static void dissect_apci(tvbuff_t *tvb, guint32 *offset, proto_tree *insert_tree, gboolean tpdu){

    guint16 type;
    guint16 sub_type;
    guint8 length;

    length = tvb_get_guint8(tvb, *offset-1);
    if (tpdu == TRUE){
        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_reserved, tvb, *offset, 1, ENC_BIG_ENDIAN);
    }
    else {
        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_tpci, tvb, *offset, 1, ENC_BIG_ENDIAN);
        type = (tvb_get_guint8(tvb, *offset)&0xC0);
        if (type == 0x40 || type == 0xC0){
            proto_tree_add_item(insert_tree, hf_knxnetip_cemi_counter, tvb, *offset, 1, ENC_BIG_ENDIAN);
        }
    }

    if (length != 0) {
        type = (tvb_get_ntohs(tvb, *offset) & 0x03C0);
        switch (type){
            case(A_ADC_RED):
            case(A_ADC_RES):
                type = (tvb_get_ntohs(tvb, *offset) & 0x2FF);
                if (type == A_SYS_RED || type == A_SYS_RES || type == A_SYS_WRT || type == A_SYS_BROAD){
                    proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_apci, tvb, (*offset*8)+6, 10, ENC_BIG_ENDIAN);
                }
                else {
                    proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_apci, tvb, (*offset*8)+6, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_channel, tvb, (*offset*8)+10, 6, ENC_BIG_ENDIAN);
                }
                *offset+=2;
                break;
            case(A_GROUPVALUE_RES):
            case(A_GROUPVALUE_WRT):
                proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_apci, tvb, (*offset*8)+6, 4, ENC_BIG_ENDIAN);
                    if (length == 1){
                        proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_data, tvb, (*offset*8)+10, 6, ENC_BIG_ENDIAN);
                    }
                *offset+=2;
                break;
            case(A_MEM_RED):
            case(A_MEM_RES):
            case(A_MEM_WRT):
                proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_apci, tvb, (*offset*8)+6, 6, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_apci_memory_number, tvb, (*offset*8)+12, 4, ENC_BIG_ENDIAN);
                *offset+=2;
                proto_tree_add_item(insert_tree, hf_knxnetip_cemi_apci_mem_address, tvb, *offset, 2, ENC_BIG_ENDIAN);
                *offset+=2;
                break;
            case(COUPLER_SPECIFIC_SERVICE):
                sub_type = (tvb_get_ntohs(tvb, *offset) & 0x3FF);
                proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_apci, tvb, (*offset*8)+6, 10, ENC_BIG_ENDIAN);
                *offset+=2;
                switch(sub_type){
                    case(A_AUTHORIZE_REQ):
                    case(A_KEY_WRT):
                        proto_tree_add_item(insert_tree, hf_knxnetip_reserved, tvb, *offset, 1, ENC_NA);
                        *offset+=1;
                        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_apci_key, tvb, *offset, 4, ENC_NA);
                        *offset+=4;
                        break;
                    case(A_AUTHORIZE_RES):
                    case(A_KEY_RES):
                        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_apci_level, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        break;
                    case(A_PROPVALUE_RED):
                    case(A_PROPVALUE_RES):
                        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_apci_object, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_apci_propid, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_noe, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(insert_tree, hf_knxnetip_cemi_six, tvb, *offset, 2, ENC_BIG_ENDIAN);
                        *offset+=2;
                }
                break;
            default:
                proto_tree_add_bits_item(insert_tree, hf_knxnetip_cemi_apci, tvb, (*offset*8)+6, 10, ENC_BIG_ENDIAN);
                *offset+=2;
        }

        if (length >= 1){
           length-=1;
        }

        if (length >= 1 && (tvb_reported_length_remaining(tvb, *offset) > 0)){
            proto_tree_add_item(insert_tree, hf_knxnetip_data, tvb, *offset, -1, ENC_NA);
            *offset+=length;
        }

    }
    else {
        *offset+=1;
    }

}


static gboolean dissect_cemi(tvbuff_t *tvb, guint32 *offset, proto_tree *insert_tree, packet_info *pinfo){

    proto_item *cemi_item = NULL;
    proto_item *additional_info_totallength = NULL;
    proto_item *additional_item = NULL;
    proto_item *additional_info = NULL;
    proto_item *tpdu_length = NULL;
    proto_item *npdu_length = NULL;

    proto_tree *cemi_tree = NULL;
    proto_tree *additional_tree = NULL;
    proto_tree *additional_subtree = NULL;

    guint8 i;
    guint8 messagecode;
    guint8 length;
    guint8 type_id;
    guint8 noe;
    guint8 num_of_octets;
    guint16 knx_address;
    guint16 six;

    cemi_item = proto_tree_add_item(insert_tree, hf_knxnetip_cemi, tvb, *offset, -1, ENC_NA);
    cemi_tree = proto_item_add_subtree(cemi_item, ett_knxnetip_cemi);
    messagecode = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_mc, tvb, *offset, 1, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, "| cEMI: %s", val_to_str(messagecode, cemi_messagecodes, "Unknown MC:0x%0x"));
    *offset+=1;
    /*check if M_ Message*/
    if ((messagecode & 0xF0) < 0xF0){
        length = tvb_get_guint8(tvb, *offset);
        additional_info_totallength= proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_addlength, tvb, *offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(additional_info_totallength, " octets");
        *offset+=1;

        if (length != 0){

            additional_info = proto_tree_add_item(cemi_tree, hf_knxnetip_additional, tvb, *offset, length, ENC_NA);
            additional_tree = proto_item_add_subtree(additional_info, ett_knxnetip_cemi_additional);
            do {
                type_id = tvb_get_guint8(tvb, *offset);
                additional_item = proto_tree_add_item(additional_tree, hf_knxnetip_cemi_typid, tvb, *offset, 1, ENC_BIG_ENDIAN);
                additional_subtree = proto_item_add_subtree(additional_item, ett_knxnetip_cemi_additional_item);
                *offset+=1;
                additional_info_totallength= proto_tree_add_item(additional_item, hf_knxnetip_cemi_additemlength, tvb, *offset, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(additional_info_totallength, " octets");
                *offset+=1;
                if (length >= 2){
                    length-=2;
                }
                else{
                    return TRUE;
                }

                switch(type_id){
                    case(PL_INFO):
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_pl, tvb, *offset, 2, ENC_BIG_ENDIAN);
                        *offset+=2;
                        if (length >= 2){
                            length-=2;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(RF_INFO):
                        proto_tree_add_bitmask(additional_subtree, tvb, *offset, hf_knxnetip_cemi_type_rf_info, ett_knxnetip_cemi_rf_info, cemi_rf_info, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_rf_sn, tvb, *offset, 6, ENC_BIG_ENDIAN);
                        *offset+=6;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_rf_lfn, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        if (length >= 8){
                            length-=8;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(BUSMON_INFO):
                        proto_tree_add_bitmask(additional_subtree, tvb, *offset, hf_knxnetip_cemi_type_bus, ett_knxnetip_cemi_bus_info, cemi_bus_flags, ENC_BIG_ENDIAN);
                        *offset+=1;
                        if (length >= 1){
                            length-=1;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(TIME_REL):
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_relt, tvb, *offset, 2, ENC_BIG_ENDIAN);
                        *offset+=2;
                        if (length >= 2){
                            length-=2;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(TIME_DELAY):
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_delay, tvb, *offset, 4, ENC_BIG_ENDIAN);
                        *offset+=4;
                        if (length >= 4){
                            length-=4;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(EXEND_TIME):
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_exttime, tvb, *offset, 4, ENC_BIG_ENDIAN);
                        *offset+=4;
                        if (length >= 4){
                            length-=4;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(BIBAT_INFO):
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_bibat, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_bibat_block, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        if (length >= 2){
                            length-=2;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(RF_MULTI):
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_rf_multi_freq, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_rf_multi_channel, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_rf_multi_fastack, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_rf_multi_recep_freq, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        if (length >= 4){
                            length-=4;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(PREAMBEL):
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_preamble_length, tvb, *offset, 2, ENC_BIG_ENDIAN);
                        *offset+=2;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_type_postamble_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        if (length >= 3){
                            length-=3;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    case(RF_FAST_ACK):
                        num_of_octets = tvb_get_guint8(tvb, *offset-1);
                        for(i=0; i<num_of_octets; i++) {
                            proto_tree_add_bitmask(additional_subtree, tvb, *offset, hf_knxnetip_cemi_type_fastack, ett_knxnetip_cemi_fastack, cemi_fastack_flags, ENC_BIG_ENDIAN);
                            *offset+=2;
                            if (length >= 2){
                            length-=2;
                        }
                        else{
                            return TRUE;
                        }
                        }
                        break;
                    case(MANU_DATA):
                        num_of_octets = tvb_get_guint8(tvb, *offset-1);
                        proto_tree_add_item(additional_subtree, hf_knxnetip_dib_manuid, tvb, *offset, 2, ENC_BIG_ENDIAN);
                        *offset+=2;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_subfunction, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset+=1;
                        proto_tree_add_item(additional_subtree, hf_knxnetip_cemi_manuspecificdata, tvb, *offset, (num_of_octets-3), ENC_NA);
                        *offset+=(num_of_octets-3);
                        if (length >= num_of_octets){
                            length-=num_of_octets;
                        }
                        else{
                            return TRUE;
                        }
                        break;
                    default:
                        proto_tree_add_item(additional_subtree, hf_knxnetip_unknown, tvb, *offset, -1, ENC_NA);
                        return *offset;
                }
            } while (length > 0);
        }
    }
        switch (messagecode){
            case(DATA_REQ):
            case(DATA_CON):
            case(DATA_IND):
            case(POLL_DATA_REQ):
            case(POLL_DATA_CON):
                proto_tree_add_bitmask(cemi_tree, tvb, *offset, hf_knxnetip_cemi_controlfield1, ett_knxnetip_cemi_control1, cemi_control1_flags, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_bitmask(cemi_tree, tvb, *offset, hf_knxnetip_cemi_controlfield2, ett_knxnetip_cemi_control2, cemi_control2_flags, ENC_BIG_ENDIAN);
                *offset+=1;
                knx_address = tvb_get_ntohs(tvb, *offset);
                proto_tree_add_uint_format(cemi_tree, hf_knxnetip_cemi_sourceaddress, tvb, *offset, 2, knx_address, "Source Address %d.%d.%d", ((knx_address & 0xF000)>>12),((knx_address & 0x0F00)>>8),(knx_address & 0xFF));
                *offset+=2;
                knx_address = tvb_get_ntohs(tvb, *offset);
                if ((tvb_get_guint8(tvb, *offset-3) & 0x80) == GROUPADD){
                    proto_tree_add_uint_format(cemi_tree, hf_knxnetip_cemi_destaddress, tvb, *offset, 2, knx_address, "Destination Address %d/%d/%d or %d/%d", ((knx_address & 0x7800)>>11),((knx_address & 0x0700)>>8),(knx_address & 0xFF), ((knx_address & 0x7800)>>11),(knx_address & 0x7FF));
                }
                else {
                    proto_tree_add_uint_format(cemi_tree, hf_knxnetip_cemi_destaddress, tvb, *offset, 2, knx_address, "Destination Address %d.%d.%d", ((knx_address & 0xF000)>>12),((knx_address & 0x0F00)>>8),(knx_address & 0xFF));
                }
                *offset+=2;
                if (messagecode == POLL_DATA_REQ){
                    proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_numberofslots, tvb, *offset, 1, ENC_BIG_ENDIAN);
                    *offset+=1;
                }
                else if (messagecode == POLL_DATA_CON){
                    proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_numberofslots, tvb, *offset, 1, ENC_BIG_ENDIAN);
                    *offset+=1;
                    proto_tree_add_item(cemi_tree, hf_knxnetip_polldata, tvb, *offset, -1, ENC_NA);
                }
                else {
                    npdu_length = proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_npdu_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
                    proto_item_append_text(npdu_length, " octets");
                    *offset+=1;
                    dissect_apci(tvb, offset, cemi_tree, FALSE);
                }
                break;
            case(RAW_REQ):
            case(RAW_CON):
            case(RAW_IND):
            case(BUSMON_IND):
                proto_tree_add_item(cemi_tree, hf_knxnetip_raw, tvb, *offset, -1, ENC_NA);
                break;
            case(DATA_INDV_IND):
            case(DATA_INDV_REQ):
            case(DATA_CONNEC_IND):
            case(DATA_CONNEC_REQ):
                proto_tree_add_item(cemi_tree, hf_knxnetip_reserved, tvb, *offset, 6, ENC_NA);
                *offset+=6;
                tpdu_length = proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_tpdu_length, tvb, *offset, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(tpdu_length, " octets");
                *offset+=1;
                dissect_apci(tvb, offset, cemi_tree, TRUE);
                break;
            case(PROPREAD_REQ):
            case(PROPREAD_CON):
            case(PROPWRITE_REQ):
            case(PROPWRITE_CON):
            case(PROPINFO_IND):
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_iot, tvb, *offset, 2, ENC_BIG_ENDIAN);
                *offset+=2;
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_oi, tvb, *offset, 1, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_pid, tvb, *offset, 1, ENC_BIG_ENDIAN);
                *offset+=1;
                noe = ((tvb_get_guint8(tvb, *offset)& 0xF0)>>4);
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_noe, tvb, *offset, 1, ENC_BIG_ENDIAN);
                six = tvb_get_bits16(tvb, (*offset*8+4), 12, ENC_BIG_ENDIAN);
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_six, tvb, *offset, 2, ENC_BIG_ENDIAN);
                *offset+=2;
                if (messagecode == PROPREAD_REQ || (messagecode == PROPREAD_CON && noe > 0)){
                    break;
                }
                else if (noe == 0){
                    proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_error, tvb, *offset, 1, ENC_BIG_ENDIAN);
                    *offset+=1;
                }
                else if (noe == 1 && six == 0){
                    proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_numberofelements, tvb, *offset, 2, ENC_BIG_ENDIAN);
                    *offset+=2;
                }
                else {
                    proto_tree_add_item(cemi_tree, hf_knxnetip_data, tvb, *offset, -1, ENC_NA);
                }
                break;
            case(FUNCPROPCOM_REQ):
            case(FUNCPROPSTATREAD_REQ):
            case(FUNCPROPCOM_CON):
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_iot, tvb, *offset, 2, ENC_BIG_ENDIAN);
                *offset+=2;
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_oi, tvb, *offset, 1, ENC_BIG_ENDIAN);
                *offset+=1;
                proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_pid, tvb, *offset, 1, ENC_BIG_ENDIAN);
                *offset+=1;
                if (messagecode == FUNCPROPCOM_CON){
                    proto_tree_add_item(cemi_tree, hf_knxnetip_cemi_return, tvb, *offset, 1, ENC_BIG_ENDIAN);
                    *offset+=1;
                }
                proto_tree_add_item(cemi_tree, hf_knxnetip_data, tvb, *offset, -1, ENC_NA);
                break;
            case(RESET_REQ):
            case(RESET_IND):
                break;
            default:
                proto_tree_add_item(cemi_tree, hf_knxnetip_data, tvb, *offset, -1, ENC_NA);
        }
        return FALSE;
}



static void dissect_knxnetip (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    proto_item *knx_item = NULL;
    proto_item *total_length = NULL;
    proto_item *struct_length = NULL;
    proto_item *busy_item = NULL;

    proto_tree *knx_tree = NULL;
    proto_tree *header_tree = NULL;
    proto_tree *body_tree = NULL;

    guint offset = 0;
    guint16 service_type = 0;
    gboolean err = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KNXnetIP");
    col_clear(pinfo->cinfo,COL_INFO);

    knx_item = proto_tree_add_item(tree, proto_knxnetip, tvb, 0, -1, ENC_NA);
    knx_tree = proto_item_add_subtree(knx_item, ett_knxnetip);

    /* HEADER*/
    header_tree = proto_tree_add_subtree(knx_tree, tvb, offset, 6, ett_knxnetip_header, NULL, "Header");
    proto_tree_add_item(header_tree, hf_knxnetip_headerlength, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    proto_tree_add_item(header_tree, hf_knxnetip_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    service_type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(header_tree, hf_knxnetip_servicetype, tvb, offset, 2, ENC_BIG_ENDIAN);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %d > %d", val_to_str(service_type, knxnetip_service_identifier, "Unknown Identifier:0x%02x"), pinfo->srcport, pinfo->destport);
    offset+=2;
    total_length = proto_tree_add_item(header_tree, hf_knxnetip_totallength, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(total_length, " octets");
    offset+=2;
    /* BODY */
    body_tree = proto_tree_add_subtree(knx_tree, tvb, offset, -1, ett_knxnetip_body, NULL, "Body");

    switch(service_type) {

        case(SEARCH_REQ):
            dissect_hpai(tvb, &offset, body_tree, ": Discovery endpoint");
            break;
        case(SEARCH_RES):
            dissect_hpai(tvb, &offset, body_tree, ": Control endpoint");
            err = dissect_dib(tvb, &offset, body_tree);
            if (err == TRUE){
                proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                break;
            }
            err = dissect_dib(tvb, &offset, body_tree);
            if (err == TRUE){
                proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                break;
            }
            break;
        case(DESCRIPTION_REQ):
            dissect_hpai(tvb, &offset, body_tree, ": Control endpoint");
            break;
        case(DESCRIPTION_RES):
            err = dissect_dib(tvb, &offset, body_tree);
            if (err == TRUE){
                proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                break;
            }
            err = dissect_dib(tvb, &offset, body_tree);
            if (err == TRUE){
                proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                break;
            }
            if (tvb_reported_length_remaining(tvb, offset) != 0){
                err = dissect_dib(tvb, &offset, body_tree);
                if (err == TRUE){
                    proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                }
            }
            break;
        case(CONNECT_REQ):
            dissect_hpai(tvb, &offset, body_tree, ": Discovery endpoint");
            dissect_hpai(tvb, &offset, body_tree, ": Data endpoint");
            offset = dissect_cri(tvb, offset, body_tree);
            break;
        case(CONNECT_RES):
            proto_tree_add_item(body_tree, hf_knxnetip_communication_channel_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            proto_tree_add_item(body_tree, hf_knxnetip_connect_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            dissect_hpai(tvb, &offset, body_tree, ": Data endpoint");
            dissect_crd(tvb, &offset, body_tree);
            break;
        case(CONNECTIONSTATE_REQ):
        case(DISCONNECT_REQ):
            proto_tree_add_item(body_tree, hf_knxnetip_communication_channel_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            proto_tree_add_item(body_tree, hf_knxnetip_reserved, tvb, offset, 1, ENC_NA);
            offset+=1;
            dissect_hpai(tvb, &offset, body_tree, ": Control endpoint");
            break;
        case(DISCONNECT_RES):
        case(CONNECTIONSTATE_RES):
            proto_tree_add_item(body_tree, hf_knxnetip_communication_channel_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            proto_tree_add_item(body_tree, hf_knxnetip_connectionstate_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            break;
        case(DEVICE_CONFIGURATION_ACK):
            offset = dissect_connection_header(tvb, offset, body_tree, TRUE);
            proto_tree_add_item(body_tree, hf_knxnetip_confack_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            break;
        case(DEVICE_CONFIGURATION_REQ):
        case(TUNNELLING_REQ):
            offset = dissect_connection_header(tvb, offset, body_tree, FALSE);
            err =  dissect_cemi (tvb, &offset, body_tree, pinfo);
            if (err == TRUE){
                proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
            }
            break;
        case(TUNNELLING_ACK):
            offset = dissect_connection_header(tvb, offset, body_tree, TRUE);
            proto_tree_add_item(body_tree, hf_knxnetip_tunnelack_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case(ROUTING_INDICATION):
            err = dissect_cemi (tvb, &offset, body_tree, pinfo);
            if (err == TRUE){
                proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
            }
            break;
        case(ROUTING_LOST):
            struct_length= proto_tree_add_item(body_tree, hf_knxnetip_structure_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(struct_length, " octets");
            offset+=1;
            proto_tree_add_bitmask(body_tree, tvb, offset, hf_knxnetip_devicestate, ett_knxnetip_devicestate, devicestate_flags, ENC_BIG_ENDIAN);
            offset+=1;
            proto_tree_add_item(body_tree, hf_knxnetip_numberoflost, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            break;
        case(ROUTING_BUSY):
            struct_length= proto_tree_add_item(body_tree, hf_knxnetip_structure_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(struct_length, " octets");
            offset+=1;
            proto_tree_add_bitmask(body_tree, tvb, offset, hf_knxnetip_devicestate, ett_knxnetip_devicestate, devicestate_flags, ENC_BIG_ENDIAN);
            offset+=1;
            busy_item = proto_tree_add_item(body_tree, hf_knxnetip_busywaittime, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(busy_item, " ms");
            offset+=2;
            proto_tree_add_item(body_tree, hf_knxnetip_busycontrol, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            break;
        case(REMOTE_DIAG_REQ):
            dissect_hpai(tvb, &offset, body_tree, ": Discovery endpoint");
            offset = dissect_selector(tvb ,offset, body_tree);
            break;
        case(REMOTE_DIAG_RES):
            offset = dissect_selector(tvb ,offset, body_tree);
            do{
                err = dissect_dib(tvb, &offset, body_tree);
                if (err == TRUE){
                    proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                    break;
                }
            } while (tvb_reported_length_remaining(tvb,offset) > 0);
            break;
        case(REMOTE_BASIC_CONF_REQ):
            dissect_hpai(tvb, &offset, body_tree, ": Discovery endpoint");
            offset = dissect_selector(tvb ,offset, body_tree);
            err = dissect_dib(tvb, &offset, body_tree);
            if (err == TRUE){
                proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                break;
            }
            if (tvb_reported_length_remaining(tvb,offset) > 0) {
                err = dissect_dib(tvb, &offset, body_tree);
                if (err == TRUE){
                    proto_tree_add_expert(body_tree, pinfo, &ei_knxnetip_length, tvb, offset, -1);
                }
            }
            break;
        case(REMOTE_RESET_REQ):
            offset = dissect_selector(tvb ,offset, body_tree);
            proto_tree_add_item(body_tree, hf_knxnetip_reset, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            proto_tree_add_item(body_tree, hf_knxnetip_reserved, tvb, offset, 1, ENC_NA);
            offset+=1;
            break;

        default:
            proto_tree_add_item(body_tree, hf_knxnetip_unknown, tvb, offset, -1, ENC_NA);
    }
}

static gboolean dissect_knxnetip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

    gint idx;
    idx = 0;

    if (tvb_captured_length(tvb) < 8){
        return (FALSE);
    }
    if ( tvb_get_guint8(tvb, 0) != KNXNETIP_HEADER_LENGTH) {
        return (FALSE);
    }
    if ( tvb_get_guint8(tvb, 1) != KNXNETIP_PROTOCOL_VERSION){
        return (FALSE);
    }
    try_val_to_str_idx((guint32)tvb_get_ntohs(tvb, 2), knxnetip_service_identifier, &idx);
    if (idx == -1){
        return (FALSE);
    }

    dissect_knxnetip(tvb, pinfo, tree);
    return (TRUE);
}

void proto_register_knxnetip (void) {
    expert_module_t*  expert_knxnetip;

    static hf_register_info hf[] = {
        { &hf_knxnetip_headerlength,
            { "Header Length", "knxnetip.header_length", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_version,
            { "Protocol Version", "knxnetip.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_servicetype,
            { "Service Type Identifier", "knxnetip.service_type_identifier", FT_UINT16, BASE_HEX, VALS(knxnetip_service_identifier), 0x0, NULL, HFILL }},
        { &hf_knxnetip_totallength,
            { "Total Length", "knxnetip.total_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_hpai,
            { "HPAI", "knxnetip.hpai", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_hpai_structure_length,
            { "Structure Length", "knxnetip.hpai_structure_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_structure_length,
            { "Structure Length", "knxnetip.struct_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_hpai_host_protocol,
            { "Host Protocol Code", "knxnetip.hpai_host_protocol", FT_UINT8, BASE_HEX, VALS(knxnetip_host_protocol_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_hpai_ip_address,
            { "IP Address", "knxnetip.hpai_ip_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_hpai_port,
            { "IP Port", "knxnetip.hpai_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib,
            { "DIB", "knxnetip.dib", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cri,
            { "Connection Request Information", "knxnetip.cri", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_type,
            { "Description Type", "knxnetip.dib_type", FT_UINT8, BASE_HEX, VALS(knxnetip_dib_description_type_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_medium,
            { "KNX medium", "knxnetip.dib_medium", FT_UINT8, BASE_HEX, VALS(knxnetip_dib_medium_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_status,
            { "Device Status", "knxnetip.dib_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_projectid,
            { "Project-Installation identifier", "knxnetip.dib_projectid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_knxaddress,
            { "KNX Individual Address", "knxnetip.knxaddress", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_serialnumber,
            { "KNXnet/IP device serial number", "knxnetip.serialnumber", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_multicast_address,
            { "KNXnet/IP device multicast address", "knxnetip.multicast", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_mac_address,
            { "KNXnet/IP device MAC address", "knxnetip.macaddress", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_friendly,
            { "Device Friendly Name", "knxnetip.devicename", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_service,
            { "Service ID", "knxnetip.dib_service", FT_UINT8, BASE_HEX, VALS(knxnetip_service_types), 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_ipaddress,
            { "IP Address", "knxnetip.dib_ipaddress", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_subnet,
            { "Subnet Mask", "knxnetip.dib_subnet", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_gateway,
            { "Default Gateway", "knxnetip.dib_gateway", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_ipcapa,
            { "IP Capabilities", "knxnetip.dib_ipcapabilities", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_ipassign,
            { "IP assignment method", "knxnetip.dib_assignment", FT_UINT8, BASE_HEX, VALS(knxnetip_ip_assignment_method), 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_dhcp,
            { "DHCP Server", "knxnetip.dib_dhcp", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_manuid,
            { "Manufacturer ID", "knxnetip.manufacturer_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_manudata,
            { "Manufacturer specific data", "knxnetip.manufacturer_data", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_connection_type,
            { "Connection Type", "knxnetip.connection_type", FT_UINT8, BASE_HEX, VALS(knxnetip_connection_types), 0x0, NULL, HFILL }},
        { &hf_knxnetip_cri_protocol_data,
            { "Protocol Data", "knxnetip.cri_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_communication_channel_id,
            { "Communication Channel ID", "knxnetip.communication_channel_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_connect_status,
            { "Status", "knxnetip.connect_status", FT_UINT8, BASE_HEX, VALS(knxnetip_connect_response_status_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_crd_protocol_data,
            { "Protocol Data", "knxnetip.crd_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_crd,
            { "Connection Response Data Block", "knxnetip.crd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_connectionstate_status,
            { "Status", "knxnetip.connect_state_status", FT_UINT8, BASE_HEX, VALS(knxnetip_connectionstate_response_status_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_counter,
            { "Sequence Counter", "knxnetip.sequence_counter", FT_UINT8, BASE_DEC, 0x0, 0x0, NULL, HFILL }},
        { &hf_knxnetip_confack_status,
            { "Status", "knxnetip.confirm_ack_status", FT_UINT8, BASE_HEX, VALS(knxnetip_device_configuration_ack_status_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_tunnelack_status,
            { "Status", "knxnetip.tunnel_status", FT_UINT8, BASE_HEX, VALS(knxnetip_tunneling_error_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_status_flag_reserved,
            { "reserved", "knxnetip.dib_reserved", FT_UINT8, BASE_HEX, NULL, FLAGS_DEVICESTATUS_RESERVED, NULL, HFILL }},
        { &hf_knxnetip_dib_status_flag_program,
            { "program mode", "knxnetip.dib_program_mode", FT_UINT8, BASE_DEC, NULL, FLAGS_DEVICESTATUS_PROGRAM, NULL , HFILL }},
        { &hf_knxnetip_dib_ipcapa_flag_reserved,
            { "reserved", "knxnetip.ip_capabilities_reserved", FT_UINT8, BASE_HEX, NULL, FLAGS_IPCAPABILITES_RESERVED, NULL, HFILL }},
        { &hf_knxnetip_dib_ipcapa_flag_bootip,
            { "BootIP", "knxnetip.ip_capabilities_bootip", FT_UINT8, BASE_DEC, NULL, FLAGS_IPCAPABILITES_BOOTIP, NULL, HFILL }},
        { &hf_knxnetip_dib_ipcapa_flag_dhcp,
            { "DHCP", "knxnetip.ip_capabilities_dhcp", FT_UINT8, BASE_DEC, NULL, FLAGS_IPCAPABILITES_DHCP, NULL, HFILL }},
        { &hf_knxnetip_dib_ipcapa_flag_autoip,
            { "AutoIP", "knxnetip.ip_capabilities_autoip", FT_UINT8, BASE_DEC, NULL, FLAGS_IPCAPABILITES_AUTOIP, NULL, HFILL }},
        { &hf_knxnetip_devicestate,
            { "DeviceState", "knxnetip.devicestate", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_devicestate_reserved,
            { "reserved", "knxnetip.devicestate_reserved", FT_UINT8, BASE_HEX, NULL, FLAGS_DEVICESTATE_RESERVED, NULL, HFILL }},
        { &hf_knxnetip_devicestate_knx,
            { "KNX Fault", "knxnetip.devicestate_knx", FT_UINT8, BASE_DEC, NULL, FLAGS_DEVICESTATE_KNX, "is set if KNX network cannot be accessed", HFILL }},
        { &hf_knxnetip_devicestate_ip,
            { "IP Fault", "knxnetip.devicestate_ip", FT_UINT8, BASE_DEC, NULL, FLAGS_DEVICESTATE_IP, "is set if IP network cannot be accessed", HFILL }},
        { &hf_knxnetip_numberoflost,
            { "NumberofLostMessages", "knxnetip.number_of_lost_msg", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_busywaittime,
            { "Busy Wait Time", "knxnetip.busy_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_busycontrol,
            { "Busy Control Field", "knxnetip.busy_control", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_knxlayer,
            { "KNX Layer", "knxnetip.layer", FT_UINT8, BASE_HEX, VALS(knxnetip_knxlayer_values), 0x0, NULL, HFILL }},
        { &hf_knxnetip_selector_type,
            { "Selector Type Code", "knxnetip.selector", FT_UINT8, BASE_HEX, VALS(knxnetip_selector_types), 0x0, NULL, HFILL }},
        { &hf_knxnetip_reset,
            { "Reset Command", "knxnetip.reset", FT_UINT8, BASE_HEX, VALS(knxnetip_reset_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi,
            { "cEMI", "knxnetip.cemi", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_mc,
            { "messagecode", "knxnetip.cemi_messagecode", FT_UINT8, BASE_HEX, VALS(cemi_messagecodes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_addlength,
            { "add information length", "knxnetip.additional_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_additemlength,
            { "Length", "knxnetip.additional_item_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_typid,
            { "Type id", "knxnetip.cemi_type_id", FT_UINT8, BASE_HEX, VALS(cemi_add_type_id), 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_pl,
            { "Domain-Address", "knxnetip.cemi_type_pl", FT_UINT16, BASE_HEX, 0x0, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bus,
            { "Busmonitor error flags", "knxnetip.cemi_type_bus", FT_UINT8, BASE_HEX, 0x0, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_relt,
            { "relative timestamp", "knxnetip.cemi_type_reltime", FT_UINT16, BASE_HEX, 0x0, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_delay,
            { "delay", "knxnetip.cemi_type_delay", FT_UINT32, BASE_HEX, 0x0, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_exttime,
            { "extended timestamp", "knxnetip.cemi_type_exttime", FT_UINT32, BASE_HEX, 0x0, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bibat,
            { "BiBat", "knxnetip.cemi_type_bibat", FT_UINT8, BASE_HEX, VALS(cemi_bibat_ctrl), 0xF8, NULL, HFILL }},
        { &hf_knxnetip_cemi_controlfield1,
            { "Controlfield 1", "knxnetip.controlfield_one", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_flag_frametype,
            { "Frametype", "knxnetip.controlfield_type", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_CONTROL1_FT, "0: extended frame; 1: standard frame", HFILL }},
        { &hf_knxnetip_cemi_flag_repeat,
            { "Repeat", "knxnetip.controlfield_repeat", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_CONTROL1_R, "0: repeat if error frame; 1: do not repeat", HFILL }},
        { &hf_knxnetip_cemi_flag_sb,
            { "System-Broadcast", "knxnetip.controlfield_broadcast", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_CONTROL1_SB, "0: system-broadcast; 1: broadcast", HFILL }},
        { &hf_knxnetip_cemi_flag_priority,
            { "Priority", "knxnetip.controlfield_priority", FT_UINT8, BASE_HEX, NULL, FLAGS_CEMI_CONTROL1_P, NULL, HFILL }},
        { &hf_knxnetip_cemi_flag_ack,
            { "Acknowledge-Request", "knxnetip.controlfield_ack", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_CONTROL1_A, "0: no request for ack; 1: request ack", HFILL }},
        { &hf_knxnetip_cemi_flag_confirm,
            { "Confirm-Flag", "knxnetip.controlfield_confirm", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_CONTROL1_C, "0: no error in frame; 1: error in frame", HFILL }},
        { &hf_knxnetip_cemi_controlfield2,
            { "Controlfield 2", "knxnetip.controlfield_two", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_flag_destaddress,
            { "Destination address type", "knxnetip.controldestaddress", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_CONTROL2_AT, "0: individual; 1: group", HFILL }},
        { &hf_knxnetip_flag_hop,
            { "Hop count", "knxnetip.controlhop", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_CONTROL2_HC, NULL, HFILL }},
        { &hf_knxnetip_flag_eff,
            { "Extended Frame Format", "knxnetip.controleff", FT_UINT8, BASE_HEX, NULL, FLAGS_CEMI_CONTROL2_EFF, "0000b for standard frame", HFILL }},
        { &hf_knxnetip_cemi_sourceaddress,
            { "Source Address", "knxnetip.cemisource", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_destaddress,
            { "Destination Address", "knxnetip.cemidestination", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_tpci,
            { "TPCI", "knxnetip.cemitpci", FT_UINT8, BASE_HEX, VALS(cemi_tpci_vals), 0xC0, NULL, HFILL }},
        { &hf_knxnetip_cemi_npdu_length,
            { "NPDU length", "knxnetip.npdulength", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_tpdu_length,
            { "TPDU length", "knxnetip.tpdulength", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_counter,
            { "sequence NCD/NDT", "knxnetip.npduseq", FT_UINT8, BASE_DEC, NULL, 0x3C, NULL, HFILL }},
        { &hf_knxnetip_cemi_apci,
            { "APCI", "knxnetip.npduapci", FT_UINT16, BASE_HEX, VALS(cemi_apci_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_data,
            { "Data", "knxnetip.cemidata", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_numberofslots,
            { "number of slots", "knxnetip.ceminumberofslots", FT_UINT8, BASE_DEC, NULL, 0xF, NULL, HFILL }},
        { &hf_knxnetip_cemi_apci_memory_number,
            { "number of octets to be read/write", "knxnetip.cemidata", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_iot,
            { "Interface object type", "knxnetip.cemiiot", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_oi,
            { "Object Instance", "knxnetip.cemioi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_pid,
            { "Property Identifier", "knxnetip.cemipid", FT_UINT8, BASE_DEC, VALS(cemi_propertyid), 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_noe,
            { "Number of Elements", "knxnetip.ceminoe", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
        { &hf_knxnetip_cemi_six,
            { "Startindex", "knxnetip.cemipid", FT_UINT16, BASE_DEC, NULL, 0xFFF, NULL, HFILL }},
        { &hf_knxnetip_cemi_numberofelements,
            { "Number of Elements", "knxnetip.ceminumber", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_error,
            { "Error Code", "knxnetip.cemierror", FT_UINT8, BASE_HEX, VALS(cemi_error_codes), 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_return,
            { "retrun code", "knxnetip.cemireturn", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_reserved,
            { "reserved", "knxnetip.cemireserved", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_info,
            { "RF-Info", "knxnetip.cemirfinfo", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_mesure,
            { "received signal strength", "knxnetip.cemirfmesure", FT_UINT8, BASE_HEX, NULL, FLAGS_CEMI_RF_MESURE, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_reserved,
            { "reserved", "knxnetip.cemirfreserved", FT_UINT8, BASE_HEX, NULL, FLAGS_CEMI_RF_RESERVED, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_mesure_re,
            { "retransmitter signal strrength", "knxnetip.cemirfmesurere", FT_UINT8, BASE_HEX, NULL, FLAGS_CEMI_RF_MESURE_RE, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_battery,
            { "Battery state", "knxnetip.cemirfbattery", FT_UINT8, BASE_HEX, NULL, FLAGS_CEMI_RF_BATTERY, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_bidirekt,
            { "is not bidirektional", "knxnetip.cemirfbattery", FT_UINT8, BASE_HEX, NULL, FLAGS_CEMI_RF_BIDIRETIONAL, NULL, HFILL }},
        { &hf_knxnetip_cemi_rf_sn,
            { "KNX Serial Number", "knxnetip.cemiknxsn", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_rf_lfn,
            { "Data Link Layer frame number", "knxnetip.cemilfn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bus_flag_f,
            { "Frame error flag", "knxnetip.cemibusferror", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_BUS_F, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bus_flag_b,
            { "Bit error flag", "knxnetip.cemibusberror", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_BUS_B, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bus_flag_p,
            { "Parity error flag", "knxnetip.cemibusparity", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_BUS_P, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bus_flag_d,
            { "dont care", "knxnetip.cemibusdont", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_BUS_D, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bus_flag_l,
            { "Lost flag", "knxnetip.cemibuslost", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_BUS_L, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bus_flag_sss,
            { "Sequence Number", "knxnetip.cemibusseq", FT_UINT8, BASE_DEC, NULL, FLAGS_CEMI_BUS_SSS, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_bibat_block,
            { "BiBat Block number", "knxnetip.cemibibbatblock", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_multi_fastack,
            { "KNX RF Multi Fast Ack", "knxnetip.cemirffastack", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_multi_freq,
            { "KNX RF Multi Transmission Frequency", "knxnetip.cemirffreq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_multi_channel,
            { "KNX RF Multi Call Channel", "knxnetip.cemirfchannel", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_rf_multi_recep_freq,
            { "KNX RF Multi Reception Frequency", "knxnetip.cemirfrecfreq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_preamble_length,
            { "Preamble Length", "knxnetip.cemipreamblelength", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_postamble_length,
            { "Postamble Length", "knxnetip.cemipostamblelength", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_fastack,
            { "Fast Ack information", "knxnetip.cemifastack", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_fastack_crc,
            { "Fast Ack is received with a CRC", "knxnetip.cemifastackcrc", FT_UINT16, BASE_DEC, NULL, FLAGS_CEMI_FASTACK_CRC, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_fastack_error,
            { "Fast Ack is received with a Manchester error", "knxnetip.cemifastackerror", FT_UINT16, BASE_DEC, NULL, FLAGS_CEMI_FASTACK_ERROR, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_fastack_received,
            { "Fast Ack has been received", "knxnetip.cemifastackres", FT_UINT16, BASE_DEC, NULL, FLAGS_CEMI_FASTACK_RES, NULL, HFILL }},
        { &hf_knxnetip_cemi_type_fastack_info,
            { "Fast Ack Info", "knxnetip.cemifastackinfo", FT_UINT16, BASE_HEX, NULL, FLAGS_CEMI_FASTACK_INFO, NULL, HFILL }},
        { &hf_knxnetip_cemi_subfunction,
            { "Subfunction", "knxnetip.cemisubfunction", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_manuspecificdata,
            { "Manufacturer specific data", "knxnetip.cemimanuspecificdata", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_projectnumber,
            { "Project number", "knxnetip.projectnumber", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_installnumber,
            { "Installation number", "knxnetip.installnumber", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_dib_svc_version,
            { "Version", "knxnetip.svcversion", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_reserved,
            { "reserved", "knxnetip.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_data,
            { "data", "knxnetip.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_polldata,
            { "Poll data", "knxnetip.polldata", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_raw,
            { "RAW Frame", "knxnetip.raw", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_additional,
            { "Additional information", "knxnetip.additional", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_unknown,
            { "UNKNOWN", "knxnetip.unknown", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_apci_mem_address,
            { "Memory Address", "knxnetip.cemimemaddress", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_channel,
            { "Channel nr", "knxnetip.cemichannel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_apci_key,
            { "key", "knxnetip.apcikey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_apci_level,
            { "level", "knxnetip.apcilevel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_apci_object,
            { "object index", "knxnetip.apciobjidx", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_knxnetip_cemi_apci_propid,
            { "property id", "knxnetip.apcipropid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_knxnetip,
        &ett_knxnetip_header,
        &ett_knxnetip_body,
        &ett_knxnetip_hpai,
        &ett_knxnetip_dib,
        &ett_knxnetip_dib_projectid,
        &ett_knxnetip_dib_service,
        &ett_knxnetip_cri,
        &ett_knxnetip_crd,
        &ett_knxnetip_dib_status,
        &ett_knxnetip_dib_ipcapa,
        &ett_knxnetip_devicestate,
        &ett_knxnetip_cemi,
        &ett_knxnetip_cemi_additional,
        &ett_knxnetip_cemi_additional_item,
        &ett_knxnetip_cemi_control1,
        &ett_knxnetip_cemi_control2,
        &ett_knxnetip_cemi_rf_info,
        &ett_knxnetip_cemi_bus_info,
        &ett_knxnetip_cemi_fastack
    };

    static ei_register_info ei[] = {
        { &ei_knxnetip_length, { "knxnetip.invalid.length", PI_PROTOCOL, PI_ERROR, "invalid length", EXPFILL }},
    };

    proto_knxnetip = proto_register_protocol("KNXnet/IP", "knxnetip", "knx");
    proto_register_field_array(proto_knxnetip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_knxnetip = expert_register_protocol(proto_knxnetip);
    expert_register_field_array(expert_knxnetip, ei, array_length(ei));
}


void proto_reg_handoff_knxnetip(void) {
    /* register as heuristic dissector for both TCP and UDP */
    heur_dissector_add("tcp", dissect_knxnetip_heur, "KNXnet/IP over TCP", "knxnetip_tcp", proto_knxnetip, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_knxnetip_heur, "KNXnet/IP over UDP", "knxnetip_udp", proto_knxnetip, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
