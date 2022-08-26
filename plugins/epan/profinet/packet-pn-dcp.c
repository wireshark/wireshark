/* packet-pn-dcp.c
 * Routines for PN-DCP (PROFINET Discovery and basic Configuration Protocol)
 * packet dissection.
 *
 * IEC 61158-6-10 section 4.3
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Cyclic PNIO RTC1 Data Dissection:
 *
 * Added new functions to packet-pn-dcp.c. The profinet plug-in will now save
 * the information (Stationname, -type, -id)  of "Ident OK" frames. Those
 * informations will later be used for detailled dissection of cyclic PNIO RTC1
 * dataframes.
 *
 * The declaration of the new added structures are within packet-pn.h to
 * use the information within packet-pn-rtc-one.c
 *
 * Overview for cyclic PNIO RTC1 data dissection functions:
 *   -> dissect_PNDCP_Suboption_Device (Save Stationname, -type, -id)
 */


#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/to_str.h>
#include <epan/wmem_scopes.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#include "packet-pn.h"


void proto_register_pn_dcp(void);
void proto_reg_handoff_pn_dcp(void);

int proto_pn_dcp = -1;

static int hf_pn_dcp_service_id = -1;
static int hf_pn_dcp_service_type = -1;
static int hf_pn_dcp_xid = -1;
static int hf_pn_dcp_reserved8 = -1;
static int hf_pn_dcp_reserved16 = -1;
static int hf_pn_dcp_response_delay = -1;
static int hf_pn_dcp_data_length = -1;
static int hf_pn_dcp_block_length = -1;

static int hf_pn_dcp_block = -1;

static int hf_pn_dcp_block_error = -1;

static int hf_pn_dcp_option = -1;
static int hf_pn_dcp_block_info = -1;
static int hf_pn_dcp_block_qualifier = -1;
static int hf_pn_dcp_blockqualifier = -1;
static int hf_pn_dcp_blockqualifier_r2f = -1;

static int hf_pn_dcp_suboption_ip = -1;
static int hf_pn_dcp_suboption_ip_block_info = -1;
static int hf_pn_dcp_suboption_ip_ip = -1;
static int hf_pn_dcp_suboption_ip_subnetmask = -1;
static int hf_pn_dcp_suboption_ip_standard_gateway = -1;
static int hf_pn_dcp_suboption_ip_mac_address = -1;

static int hf_pn_dcp_suboption_device = -1;
static int hf_pn_dcp_suboption_device_typeofstation = -1;
static int hf_pn_dcp_suboption_device_nameofstation = -1;
static int hf_pn_dcp_suboption_vendor_id = -1;
static int hf_pn_dcp_suboption_device_id = -1;
static int hf_pn_dcp_suboption_device_role = -1;
static int hf_pn_dcp_suboption_device_aliasname = -1;
static int hf_pn_dcp_suboption_device_instance_high = -1;
static int hf_pn_dcp_suboption_device_instance_low = -1;
static int hf_pn_dcp_suboption_device_oem_ven_id = -1;
static int hf_pn_dcp_suboption_device_oem_dev_id = -1;

static int hf_pn_dcp_rsi_properties_value = -1;
static int hf_pn_dcp_rsi_properties_value_bit0 = -1;
static int hf_pn_dcp_rsi_properties_value_bit1 = -1;
static int hf_pn_dcp_rsi_properties_value_bit2 = -1;
static int hf_pn_dcp_rsi_properties_value_bit3 = -1;
static int hf_pn_dcp_rsi_properties_value_bit4 = -1;
static int hf_pn_dcp_rsi_properties_value_bit5 = -1;
static int hf_pn_dcp_rsi_properties_value_otherbits = -1;

static int hf_pn_dcp_suboption_tsn = -1;
static int hf_pn_dcp_suboption_tsn_domain_name = -1;
static int hf_pn_dcp_suboption_tsn_domain_uuid = -1;
static int hf_pn_dcp_suboption_tsn_nme_prio = -1;
static int hf_pn_dcp_suboption_tsn_nme_parameter_uuid = -1;
static int hf_pn_dcp_suboption_tsn_nme_agent = -1;

static int hf_pn_dcp_suboption_dhcp = -1;
static int hf_pn_dcp_suboption_dhcp_option_code = -1;
static int hf_pn_dcp_suboption_dhcp_parameter_length = -1;
static int hf_pn_dcp_suboption_dhcp_parameter_data = -1;
static int hf_pn_dcp_suboption_dhcp_arbitrary_client_id = -1;
static int hf_pn_dcp_suboption_dhcp_control_parameter_data = -1;

static int hf_pn_dcp_suboption_control = -1;
static int hf_pn_dcp_suboption_control_option = -1;
static int hf_pn_dcp_suboption_control_signal_value = -1;

static int hf_pn_dcp_suboption_deviceinitiative = -1;
static int hf_pn_dcp_deviceinitiative_value = -1;

static int hf_pn_dcp_suboption_all = -1;

static int hf_pn_dcp_suboption_manuf = -1;

static int hf_pn_dcp_vendor_id_high = -1;
static int hf_pn_dcp_vendor_id_low = -1;
static int hf_pn_dcp_device_id_high = -1;
static int hf_pn_dcp_device_id_low = -1;
static int hf_pn_dcp_instance_id_high = -1;
static int hf_pn_dcp_instance_id_low = -1;
static gint ett_pn_dcp = -1;
static gint ett_pn_dcp_block = -1;

static gint ett_pn_dcp_rsi_properties_value = -1;

static expert_field ei_pn_dcp_block_parse_error = EI_INIT;
static expert_field ei_pn_dcp_block_error_unknown = EI_INIT;
static expert_field ei_pn_dcp_ip_conflict = EI_INIT;

#define PNDCP_SERVICE_ID_GET        0x03
#define PNDCP_SERVICE_ID_SET        0x04
#define PNDCP_SERVICE_ID_IDENTIFY   0x05
#define PNDCP_SERVICE_ID_HELLO      0x06

static const value_string pn_dcp_service_id[] = {
    { 0x00,                     "reserved" },
    { 0x01,                     "Manufacturer specific" },
    { 0x02,                     "Manufacturer specific" },
    { PNDCP_SERVICE_ID_GET,     "Get" },
    { PNDCP_SERVICE_ID_SET,     "Set" },
    { PNDCP_SERVICE_ID_IDENTIFY,"Identify" },
    { PNDCP_SERVICE_ID_HELLO,   "Hello" },
    /* 0x07 - 0xff reserved */
    { 0, NULL }
};

#define PNDCP_SERVICE_TYPE_REQUEST              0
#define PNDCP_SERVICE_TYPE_RESPONSE_SUCCESS     1
#define PNDCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED 5

static const value_string pn_dcp_service_type[] = {
    { PNDCP_SERVICE_TYPE_REQUEST,               "Request" },
    { PNDCP_SERVICE_TYPE_RESPONSE_SUCCESS,      "Response Success" },
    { PNDCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED,  "Response - Request not supported" },
    /* all others reserved */
    { 0, NULL }
};

static const value_string pn_dcp_block_error[] = {
    { 0x00, "Ok" },
    { 0x01, "Option unsupp." },
    { 0x02, "Suboption unsupp. or no DataSet avail." },
    { 0x03, "Suboption not set" },
    { 0x04, "Resource Error" },
    { 0x05, "SET not possible by local reasons" },
    { 0x06, "In operation, SET not possible" },
    /* all others reserved */
    { 0, NULL }
};

static const range_string pn_dcp_block_info[] = {
    { 0x0000, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const value_string pn_dcp_block_qualifier[] = {
    { 0x0000, "Use the value temporary" },
    { 0x0001, "Save the value permanent" },
    /*0x0002 - 0xffff reserved */
    { 0, NULL }
};

static const value_string pn_dcp_BlockQualifier[] = {
    { 0x0002, "Reset application data" },
    { 0x0003, "Reset application data" },
    { 0x0004, "Reset communication parameter" },
    { 0x0005, "Reset communication parameter" },
    { 0x0006, "Reset engineering parameter" },
    { 0x0007, "Reset engineering parameter" },
    { 0x0008, "Resets all stored data" },
    { 0x0009, "Resets all stored data" },
    { 0x000A, "Reset engineering parameter" },
    { 0x000B, "Reset engineering parameter" },
    { 0x000C, "Reserved" },
    { 0x000D, "Reserved" },
    { 0x000E, "Reserved" },
    { 0x0010, "Resets all stored data in the IOD or IOC to its factory values" },
    { 0x0011, "Resets all stored data in the IOD or IOC to its factory values" },
    { 0x0012, "Reset and restore data" },
    { 0x0013, "Reset and restore data" },
    { 0x0014, "Reserved" },
    { 0x0015, "Reserved" },
    { 0x0016, "Reserved" },
    { 0, NULL }
};

#define PNDCP_OPTION_IP                 0x01
#define PNDCP_OPTION_DEVICE             0x02
#define PNDCP_OPTION_DHCP               0x03
#define PNDCP_OPTION_RESERVED           0x04
#define PNDCP_OPTION_CONTROL            0x05
#define PNDCP_OPTION_DEVICEINITIATIVE   0x06
#define PNDCP_OPTION_TSN                0x07
#define PNDCP_OPTION_MANUF_X80          0x80
#define PNDCP_OPTION_MANUF_XFE          0xFE
#define PNDCP_OPTION_ALLSELECTOR        0xFF

static const range_string pn_dcp_option[] = {
    { 0x00, 0x00, "Reserved" },
    { PNDCP_OPTION_IP              , PNDCP_OPTION_IP              , "IP" },
    { PNDCP_OPTION_DEVICE          , PNDCP_OPTION_DEVICE          , "Device properties" },
    { PNDCP_OPTION_DHCP            , PNDCP_OPTION_DHCP            , "DHCP" },
    { PNDCP_OPTION_RESERVED        , PNDCP_OPTION_RESERVED        , "Reserved" },
    { PNDCP_OPTION_CONTROL         , PNDCP_OPTION_CONTROL         , "Control" },
    { PNDCP_OPTION_DEVICEINITIATIVE, PNDCP_OPTION_DEVICEINITIATIVE, "Device Initiative" },
    { PNDCP_OPTION_TSN             , PNDCP_OPTION_TSN             , "TSN Domain"},
    /*0x07 - 0x7F reserved */
    /*0x80 - 0xFE manufacturer specific */
    { PNDCP_OPTION_MANUF_X80  , PNDCP_OPTION_MANUF_XFE  , "Manufacturer specific" },
    { PNDCP_OPTION_ALLSELECTOR, PNDCP_OPTION_ALLSELECTOR, "All Selector" },
    { 0, 0, NULL }
};

#define PNDCP_SUBOPTION_IP_MAC  0x01
#define PNDCP_SUBOPTION_IP_IP   0x02
#define PNDCP_SUBOPTION_IP_FULL_IP_SUITE   0x03

static const value_string pn_dcp_suboption_ip[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_IP_MAC,   "MAC address" },
    { PNDCP_SUBOPTION_IP_IP,    "IP parameter" },
    { PNDCP_SUBOPTION_IP_FULL_IP_SUITE,    "Full IP suite" },
    /*0x03 - 0xff reserved */
    { 0, NULL }
};

static const value_string pn_dcp_suboption_ip_block_info[] = {
    { 0x0000, "IP not set" },
    { 0x0001, "IP set" },
    { 0x0002, "IP set by DHCP" },
    { 0x0080, "IP not set (address conflict detected)" },
    { 0x0081, "IP set (address conflict detected)" },
    { 0x0082, "IP set by DHCP (address conflict detected)" },
    /*0x0003 - 0xffff reserved */
    { 0, NULL }
};

static const value_string pn_dcp_suboption_control_signal_value[] = {
    {0x0100, "Flash Once"},
    {0, NULL}
};

#define PNDCP_SUBOPTION_DEVICE_MANUF            0x01
#define PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION    0x02
#define PNDCP_SUBOPTION_DEVICE_DEV_ID           0x03
#define PNDCP_SUBOPTION_DEVICE_DEV_ROLE         0x04
#define PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS      0x05
#define PNDCP_SUBOPTION_DEVICE_ALIAS_NAME       0x06
#define PNDCP_SUBOPTION_DEVICE_DEV_INSTANCE     0x07
#define PNDCP_SUBOPTION_DEVICE_OEM_DEV_ID       0x08
#define PNDCP_SUBOPTION_DEVICE_RSI_PROPERTIES   0x0A

static const value_string pn_dcp_suboption_device[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_DEVICE_MANUF,         "Manufacturer specific (Type of Station)" },
    { PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION, "Name of Station" },
    { PNDCP_SUBOPTION_DEVICE_DEV_ID,        "Device ID" },
    { PNDCP_SUBOPTION_DEVICE_DEV_ROLE,      "Device Role" },
    { PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS,   "Device Options" },
    { PNDCP_SUBOPTION_DEVICE_ALIAS_NAME,    "Alias Name" },
    { PNDCP_SUBOPTION_DEVICE_DEV_INSTANCE,  "Device Instance" },
    { PNDCP_SUBOPTION_DEVICE_OEM_DEV_ID,    "OEM Device ID"},
    { PNDCP_SUBOPTION_DEVICE_RSI_PROPERTIES,"RSI Properties" },
    /*0x09 - 0xff reserved */
    { 0, NULL }
};

static const true_false_string pn_dcp_rsi_properties_value_bit =
    {  "Available", "Not available" } ;

#define PNDCP_SUBOPTION_TSN_DOMAIN_NAME            0x01
#define PNDCP_SUBOPTION_TSN_NME_MANAGER            0x02
#define PNDCP_SUBOPTION_TSN_NME_PARAMETER_UUID     0x03
#define PNDCP_SUBOPTION_TSN_NME_AGENT              0x04
#define PNDCP_SUBOPTION_TSN_CIM_INTERFACE          0x05

static const value_string pn_dcp_suboption_tsn[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_TSN_DOMAIN_NAME,         "TSN Domain Name" },
    { PNDCP_SUBOPTION_TSN_NME_MANAGER,         "NME Manager" },
    { PNDCP_SUBOPTION_TSN_NME_PARAMETER_UUID,  "NME Paramater UUID" },
    { PNDCP_SUBOPTION_TSN_NME_AGENT,           "NME Agent" },
    { PNDCP_SUBOPTION_TSN_CIM_INTERFACE,       "CIM Interface" },
    { 0, NULL }
};

static const range_string pn_dcp_suboption_tsn_nme_prio[] =
{
    { 0x0000, 0x0000, "Highest priority NME manager" },
    { 0x0001, 0x3000, "High priorities for NME manager" },
    { 0x3001, 0x9FFF, "Low priorities for NME manager" },
    { 0xA000, 0xA000, "Lowest priority for NME manager / Default priority for NME manager" },
    { 0xA001, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

#define PNDCP_SUBOPTION_DHCP_CLIENT_ID  61
#define PNDCP_SUBOPTION_DHCP_CONTROL_FOR_ADDRESS_RES  255

static const value_string pn_dcp_suboption_dhcp[] = {
    { 12, "Host name" },
    { 43, "Vendor specific" },
    { 54, "Server identifier" },
    { 55, "Parameter request list" },
    { 60, "Class identifier" },
    { PNDCP_SUBOPTION_DHCP_CLIENT_ID, "DHCP client identifier" },
    { 81, "FQDN, Fully Qualified Domain Name" },
    { 97, "UUID/GUID-based Client" },
    { PNDCP_SUBOPTION_DHCP_CONTROL_FOR_ADDRESS_RES, "Control DHCP for address resolution" },
    /*all others reserved */
    { 0, NULL }
};

static const value_string pn_dcp_suboption_dhcp_control_parameter_data[] = {
    { 0x00, "Don't use DHCP (Default)" },
    { 0x01, "Don't use DHCP, all DHCPOptions set to Reset to Factory value" },
    { 0x02, "Use DHCP with the given set of DHCPOptions" },
    { 0, NULL }
};

#define PNDCP_SUBOPTION_CONTROL_START_TRANS 0x01
#define PNDCP_SUBOPTION_CONTROL_END_TRANS   0x02
#define PNDCP_SUBOPTION_CONTROL_SIGNAL      0x03
#define PNDCP_SUBOPTION_CONTROL_RESPONSE    0x04
#define PNDCP_SUBOPTION_CONTROL_FACT_RESET  0x05
#define PNDCP_SUBOPTION_CONTROL_RESET_TO_FACT  0x06

static const value_string pn_dcp_suboption_control[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_CONTROL_START_TRANS, "Start Transaction" },
    { PNDCP_SUBOPTION_CONTROL_END_TRANS,   "End Transaction" },
    { PNDCP_SUBOPTION_CONTROL_SIGNAL,      "Signal" },
    { PNDCP_SUBOPTION_CONTROL_RESPONSE,    "Response" },
    { PNDCP_SUBOPTION_CONTROL_FACT_RESET,  "Reset Factory Settings" },
    { PNDCP_SUBOPTION_CONTROL_RESET_TO_FACT,"Reset to Factory" },
    /*0x07 - 0xff reserved */
    { 0, NULL }
};

#define PNDCP_SUBOPTION_DEVICEINITIATIVE 0x01

static const value_string pn_dcp_suboption_deviceinitiative[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_DEVICEINITIATIVE, "Device Initiative" },
    /*0x00 - 0xff reserved */
    { 0, NULL }
};

static const value_string pn_dcp_deviceinitiative_value[] = {
    { 0x00, "Device does not issue a DCP-Hello-ReqPDU after power on" },
    { 0x01, "Device does issue a DCP-Hello-ReqPDU after power on" },
    /*0x02 - 0xff reserved */
    { 0, NULL }
};

static const value_string pn_dcp_suboption_all[] = {
    { 0xff, "ALL Selector" },
    /* all other reserved */
    { 0, NULL }
};

static const value_string pn_dcp_suboption_other[] = {
    { 0x00, "Default" },
    /* all other reserved */
    { 0, NULL }
};

static const value_string pn_dcp_suboption_manuf[] = {
    /* none known */
    { 0, NULL }
};





/* dissect the option field */
static int
dissect_PNDCP_Option(tvbuff_t *tvb, int offset, packet_info *pinfo,
                             proto_tree *tree, proto_item *block_item, int hfindex, gboolean append_col)
{
    guint8 option;
    guint8 suboption;
    const value_string *val_str;

    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hfindex, &option);
    switch (option) {
    case PNDCP_OPTION_IP:
        offset  = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip, &suboption);
        val_str = pn_dcp_suboption_ip;
        break;
    case PNDCP_OPTION_DEVICE:
        offset  = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device, &suboption);
        val_str = pn_dcp_suboption_device;
        break;
    case PNDCP_OPTION_DHCP:
        offset  = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp, &suboption);
        val_str = pn_dcp_suboption_dhcp;
        break;
    case PNDCP_OPTION_CONTROL:
        offset  = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_control, &suboption);
        val_str = pn_dcp_suboption_control;
        break;
    case PNDCP_OPTION_DEVICEINITIATIVE:
        offset  = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_deviceinitiative, &suboption);
        val_str = pn_dcp_suboption_deviceinitiative;
        break;
    case PNDCP_OPTION_TSN:
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_tsn, &suboption);
        val_str = pn_dcp_suboption_tsn;
        break;
    case PNDCP_OPTION_ALLSELECTOR:
        offset  = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_all, &suboption);
        val_str = pn_dcp_suboption_all;
        break;
    default:
        offset  = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_manuf, &suboption);
        val_str = pn_dcp_suboption_manuf;
    }

    proto_item_append_text(block_item, ", Status from %s - %s",
        rval_to_str(option, pn_dcp_option, "Unknown"), val_to_str(suboption, val_str, "Unknown"));

    if (append_col) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(suboption, val_str, "Unknown"));
    }

    return offset;
}


/* dissect the "IP" suboption */
static int
dissect_PNDCP_Suboption_IP(tvbuff_t *tvb, int offset, packet_info *pinfo,
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                            guint8 service_id, gboolean is_response)
{
    guint8      suboption;
    guint16     block_length;
    guint16     block_info;
    guint16     block_qualifier;
    gboolean    have_block_info = FALSE;
    gboolean    have_block_qualifier = FALSE;
    guint8      mac[6];
    guint32     ip;
    proto_item *item = NULL;
    address     addr;


    /* SuboptionIPParameter */
    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip, &suboption);
    /* DCPBlockLength */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    switch (suboption) {
    case PNDCP_SUBOPTION_IP_MAC:
        /* MACAddressValue? */
        pn_append_info(pinfo, dcp_item, ", MAC");
        proto_item_append_text(block_item, "IP/MAC");

        /* BlockInfo? */
        if (((service_id == PNDCP_SERVICE_ID_IDENTIFY) && is_response) ||
            ((service_id == PNDCP_SERVICE_ID_HELLO) && !is_response) ||
            ((service_id == PNDCP_SERVICE_ID_GET) && is_response)) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
            have_block_info = TRUE;
            block_length -= 2;
        }

        /* BlockQualifier? */
        if ((service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
            have_block_qualifier = TRUE;
            block_length -= 2;
        }

        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }

        offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_mac_address, mac);
        set_address(&addr, AT_ETHER, 6, mac);
        proto_item_append_text(block_item, ", MACAddress: %s", address_to_str(pinfo->pool, &addr));
        break;
    case PNDCP_SUBOPTION_IP_IP:
        pn_append_info(pinfo, dcp_item, ", IP");
        proto_item_append_text(block_item, "IP/IP");

        /* BlockInfo? */
        if (((service_id == PNDCP_SERVICE_ID_IDENTIFY) && is_response) ||
            ((service_id == PNDCP_SERVICE_ID_HELLO) && !is_response) ||
            ((service_id == PNDCP_SERVICE_ID_GET) && is_response)) {
            block_info = tvb_get_ntohs(tvb, offset);
            if (tree) {
                item = proto_tree_add_uint(tree, hf_pn_dcp_suboption_ip_block_info, tvb, offset, 2, block_info);
            }
            offset += 2;
            proto_item_append_text(block_item, ", BlockInfo: %s",
                val_to_str(block_info, pn_dcp_suboption_ip_block_info, "Undecoded"));
            block_length -= 2;
            if (block_info & 0x80) {
                expert_add_info(pinfo, item, &ei_pn_dcp_ip_conflict);
            }
        }

        /* BlockQualifier? */
        if ( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
            block_length -= 2;
        }

        /* IPParameterValue ... */

        /* IPAddress */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_ip, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", IP: %s", address_to_str(pinfo->pool, &addr));

        /* Subnetmask */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_subnetmask, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", Subnet: %s", address_to_str(pinfo->pool, &addr));

        /* StandardGateway */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_standard_gateway, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", Gateway: %s", address_to_str(pinfo->pool, &addr));
        break;
    case PNDCP_SUBOPTION_IP_FULL_IP_SUITE:
        pn_append_info(pinfo, dcp_item, ", MAC");
        proto_item_append_text(block_item, "IP/MAC");

        /* BlockInfo? */
        if (((service_id == PNDCP_SERVICE_ID_IDENTIFY) && is_response) ||
            ((service_id == PNDCP_SERVICE_ID_HELLO) && !is_response) ||
            ((service_id == PNDCP_SERVICE_ID_GET) && is_response)) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
            have_block_info = TRUE;
            block_length -= 2;
        }

        /* BlockQualifier? */
        if ((service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
            have_block_qualifier = TRUE;
            block_length -= 2;
        }

        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
               val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }

        /* IPAddress */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_ip, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", IP: %s", address_to_str(pinfo->pool, &addr));

        /* Subnetmask */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_subnetmask, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", Subnet: %s", address_to_str(pinfo->pool, &addr));

        /* StandardGateway */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_standard_gateway, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", Gateway: %s", address_to_str(pinfo->pool, &addr));

        /* IPAddress_1 */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_ip, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", DNSServerIP1: %s", address_to_str(pinfo->pool, &addr));

        /* IPAddress_2 */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_subnetmask, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", DNSServerIP2: %s", address_to_str(pinfo->pool, &addr));

        /* IPAddress_3 */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_standard_gateway, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", DNSServerIP3: %s", address_to_str(pinfo->pool, &addr));

        /* IPAddress_4 */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_standard_gateway, &ip);
        set_address(&addr, AT_IPv4, 4, &ip);
        proto_item_append_text(block_item, ", DNSServerIP4: %s", address_to_str(pinfo->pool, &addr));

        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length);
    }

    return offset;
}


/* dissect the "device" suboption */
static int
dissect_PNDCP_Suboption_Device(tvbuff_t *tvb, int offset, packet_info *pinfo,
                               proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                               guint8 service_id, gboolean is_response)
{
    guint8    suboption;
    guint16   block_length;
    gchar    *info_str;
    guint8    device_role;
    guint16   vendor_id;
    guint16   device_id;
    char     *typeofstation;
    char     *nameofstation;
    char     *aliasname;
    guint16   block_info = 0;
    guint16   block_qualifier = 0;
    gboolean  have_block_info      = FALSE;
    gboolean  have_block_qualifier = FALSE;
    guint8    device_instance_high;
    guint8    device_instance_low;
    guint16   oem_vendor_id;
    guint16   oem_device_id;
    proto_item *sub_item;
    proto_tree *sub_tree;
    conversation_t    *conversation;
    stationInfo       *station_info;

    /* SuboptionDevice... */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device, &suboption);
    /* DCPBlockLength */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    /* BlockInfo? */
    if ( ((service_id == PNDCP_SERVICE_ID_IDENTIFY) &&  is_response) ||
         ((service_id == PNDCP_SERVICE_ID_HELLO)    && !is_response) ||
         ((service_id == PNDCP_SERVICE_ID_GET)      &&  is_response)) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
        have_block_info = TRUE;
        block_length -= 2;
    }

    /* BlockQualifier? */
    if ( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        have_block_qualifier = TRUE;
        block_length -= 2;
    }

    switch (suboption) {
    case PNDCP_SUBOPTION_DEVICE_MANUF:
        /*
         * XXX - IEC 61158-6-10 Edition 4.0, section 4.3, says this field
         * "shall be coded as data type VisibleString", and that VisibleString
         * is "ISO/IEC 646 - International Reference Version without the "del"
         * (coding 0x7F) character", i.e. ASCII.
         *
         * However, at least one capture has a packet where 0xAE is used in
         * a place where a registered trademark symbol would be appropriate,
         * so the host sending it apparently extended ASCII to ISO 8859-n
         * for some value of n.  That may have just been an error on their
         * part, not realizing that they should have done "(R)" or something
         * such as that.
         */
        proto_tree_add_item_ret_display_string (tree, hf_pn_dcp_suboption_device_typeofstation, tvb, offset, block_length, ENC_ASCII, pinfo->pool, &typeofstation);
        pn_append_info(pinfo, dcp_item, ", DeviceVendorValue");
        proto_item_append_text(block_item, "Device/Manufacturer specific");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info){
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        proto_item_append_text(block_item, ", DeviceVendorValue: \"%s\"", typeofstation);


        if (PINFO_FD_VISITED(pinfo) == FALSE) {
            /* Create a conversation between the MAC addresses */
            conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
            if (conversation == NULL) {
                /* Create new conversation, need to switch dl_src & dl_dst if not a response
                 * All conversations are based on Device MAC as addr1 */
                if (is_response) {
                   conversation = conversation_new(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
                }
                else {
                   conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
                }
            }

            station_info = (stationInfo*)conversation_get_proto_data(conversation, proto_pn_dcp);
            if (station_info == NULL) {
                station_info = wmem_new0(wmem_file_scope(), stationInfo);
                init_pnio_rtc1_station(station_info);
                conversation_add_proto_data(conversation, proto_pn_dcp, station_info);
            }

            station_info->typeofstation = wmem_strdup(wmem_file_scope(), typeofstation);
        }

        offset += block_length;
        break;

    case PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION:
        /*
         * XXX - IEC 61158-6-10 Edition 4.0 says, in section 4.3.1.4.15
         * "Coding of the field NameOfStationValue", that "This field shall
         * be coded as data type OctetString with 1 to 240 octets.  The
         * definition of IETF RFC 5890 and the following syntax applies: ..."
         *
         * RFC 5890 means Punycode; should we translate the domain name to
         * UTF-8 and show both the untranslated and translated domain name?
         *
         * They don't mention anything about the RFC 1035 encoding of
         * domain names as mentioned in section 3.1 "Name space definitions",
         * with the labels being counted strings; does that mean that this
         * is just an ASCII string to be interpreted as a Punycode Unicode
         * domain name?
         */
        proto_tree_add_item_ret_display_string (tree, hf_pn_dcp_suboption_device_nameofstation, tvb, offset, block_length, ENC_ASCII, pinfo->pool, &nameofstation);
        pn_append_info(pinfo, dcp_item, wmem_strdup_printf(pinfo->pool, ", NameOfStation:\"%s\"", nameofstation));
        proto_item_append_text(block_item, "Device/NameOfStation");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        proto_item_append_text(block_item, ", \"%s\"", nameofstation);


        if (PINFO_FD_VISITED(pinfo) == FALSE) {
            /* Create a conversation between the MAC addresses */
            conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
            if (conversation == NULL) {
                /* Create new conversation, need to switch dl_src & dl_dst if not a response
                 * All conversations are based on Device MAC as addr1 */
                if (is_response) {
                   conversation = conversation_new(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
                }
                else {
                   conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
                }
            }

            station_info = (stationInfo*)conversation_get_proto_data(conversation, proto_pn_dcp);
            if (station_info == NULL) {
                station_info = wmem_new0(wmem_file_scope(), stationInfo);
                init_pnio_rtc1_station(station_info);
                conversation_add_proto_data(conversation, proto_pn_dcp, station_info);
            }

            station_info->nameofstation = wmem_strdup(wmem_file_scope(), nameofstation);
        }

        offset += block_length;
        break;

    case PNDCP_SUBOPTION_DEVICE_DEV_ID:
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_vendor_id, &vendor_id);
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_id, &device_id);

        if (PINFO_FD_VISITED(pinfo) == FALSE) {
            /* Create a conversation between the MAC addresses */
            conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
            if (conversation == NULL) {
                /* Create new conversation, need to switch dl_src & dl_dst if not a response
                 * All conversations are based on Device MAC as addr1 */
                if (is_response) {
                   conversation = conversation_new(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
                }
                else {
                   conversation = conversation_new(pinfo->num, &pinfo->dl_dst, &pinfo->dl_src, CONVERSATION_NONE, 0, 0, 0);
                }
            }

            station_info = (stationInfo*)conversation_get_proto_data(conversation, proto_pn_dcp);
            if (station_info == NULL) {
                station_info = wmem_new0(wmem_file_scope(), stationInfo);
                init_pnio_rtc1_station(station_info);
                conversation_add_proto_data(conversation, proto_pn_dcp, station_info);
            }

            station_info->u16Vendor_id = vendor_id;
            station_info->u16Device_id = device_id;
        }


        pn_append_info(pinfo, dcp_item, ", Dev-ID");
        proto_item_append_text(block_item, "Device/Device ID");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        proto_item_append_text(block_item, ", VendorID: 0x%04x / DeviceID: 0x%04x", vendor_id, device_id);
        break;
    case PNDCP_SUBOPTION_DEVICE_DEV_ROLE:
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_role, &device_role);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_reserved8, NULL);
        pn_append_info(pinfo, dcp_item, ", Dev-Role");
        proto_item_append_text(block_item, "Device/Device Role");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        if (device_role & 0x01)
            proto_item_append_text(block_item, ", IO-Device");
        if (device_role & 0x02)
            proto_item_append_text(block_item, ", IO-Controller");
        if (device_role & 0x04)
            proto_item_append_text(block_item, ", IO-Multidevice");
        if (device_role & 0x08)
            proto_item_append_text(block_item, ", PN-Supervisor");
        break;
    case PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS:
        info_str = wmem_strdup_printf(pinfo->pool, ", Dev-Options(%u)", block_length/2);
        pn_append_info(pinfo, dcp_item, info_str);
        proto_item_append_text(block_item, "Device/Device Options");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        proto_item_append_text(block_item, ", %u options", block_length/2);
        for( ; block_length != 0; block_length -= 2) {
            offset = dissect_PNDCP_Option(tvb, offset, pinfo, tree, NULL /*block_item*/, hf_pn_dcp_option,
                FALSE /* append_col */);
        }
        break;
    case PNDCP_SUBOPTION_DEVICE_ALIAS_NAME:
        /*
         * XXX - IEC 61158-6-10 Edition 4.0, section 4.3.1.4.17 "Coding of
         * the field AliasNameValue", says this field "shall be coded as
         * OctetString. The content shall be the concatenation of the content
         * of the fields NameOfPort and NameOfStation.
         *
         *    AliasNameValue = NameOfPort + "." + NameOfStation
         *
         * " and:
         *
         *   It says in section 4.3.1.4.16 "Coding of the field NameOfPort"
         *   that "This field shall be coded as OctetString[8] or
         *   OctetString[14] as "port-xyz" or "port-xyz-rstuv" where x, y,
         *   z is in the range "0"-"9" from 001 up to 255 and r, s, t, u, v
         *   is in the range "0"-"9" from 00000 up to 65535. ...
         *   Furthermore, the definition of IETF RFC 5890 shall be applied."
         *
         *   That suggests that the Octets are probably just ASCII characters;
         *   IETF RFC 5890 means Punycode, but there isn't anything in those
         *   string formats that requires non-ASCII characters - they're
         *   just literally "port-" followed by numbers and hyphens.
         *
         *   It says in section 4.3.1.4.15 "Coding of the field
         *   NameOfStationValue" that it's a domain name, complete with
         *   RFC 5890 Punycode.
         */
        proto_tree_add_item_ret_display_string (tree, hf_pn_dcp_suboption_device_aliasname, tvb, offset, block_length, ENC_ASCII, pinfo->pool, &aliasname);
        pn_append_info(pinfo, dcp_item, wmem_strdup_printf(pinfo->pool, ", AliasName:\"%s\"", aliasname));
        proto_item_append_text(block_item, "Device/AliasName");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        proto_item_append_text(block_item, ", \"%s\"", aliasname);
        offset += block_length;
        break;
    case PNDCP_SUBOPTION_DEVICE_DEV_INSTANCE:
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_instance_high, &device_instance_high);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_instance_low, &device_instance_low);
        pn_append_info(pinfo, dcp_item, ", Dev-Instance");
        proto_item_append_text(block_item, "Device/Device Instance");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        proto_item_append_text(block_item, ", InstanceHigh: %d, Instance Low: %d",
                               device_instance_high, device_instance_low);
        break;
    case PNDCP_SUBOPTION_DEVICE_OEM_DEV_ID:
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_oem_ven_id, &oem_vendor_id);
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_oem_dev_id, &oem_device_id);
        pn_append_info(pinfo, dcp_item, ", OEM-Dev-ID");
        proto_item_append_text(block_item, "Device/OEM Device ID");
        if(have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if(have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        proto_item_append_text(block_item, ", OEMVendorID: 0x%04x / OEMDeviceID: 0x%04x", oem_vendor_id, oem_device_id);
        break;
    case PNDCP_SUBOPTION_DEVICE_RSI_PROPERTIES:
        sub_item = proto_tree_add_item(tree, hf_pn_dcp_rsi_properties_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_dcp_rsi_properties_value);

        static int* const flags[] = {
            &hf_pn_dcp_rsi_properties_value_bit0,
            &hf_pn_dcp_rsi_properties_value_bit1,
            &hf_pn_dcp_rsi_properties_value_bit2,
            &hf_pn_dcp_rsi_properties_value_bit3,
            &hf_pn_dcp_rsi_properties_value_bit4,
            &hf_pn_dcp_rsi_properties_value_bit5,
            &hf_pn_dcp_rsi_properties_value_otherbits,
            NULL
        };

        proto_tree_add_bitmask(sub_tree, tvb, offset, hf_pn_dcp_rsi_properties_value, ett_pn_dcp_rsi_properties_value, flags, ENC_BIG_ENDIAN);

        offset = offset + 2;

        if (pinfo->fd->visited == FALSE) {
            /* Create a conversation between the MAC addresses */
            conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
            if (conversation == NULL) {
                conversation = conversation_new(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
            }

            station_info = (stationInfo*)conversation_get_proto_data(conversation, proto_pn_dcp);
            if (station_info == NULL) {
                station_info = wmem_new0(wmem_file_scope(), stationInfo);
                init_pnio_rtc1_station(station_info);
                conversation_add_proto_data(conversation, proto_pn_dcp, station_info);
            }
        }

        pn_append_info(pinfo, dcp_item, ", RSI-Properties");
        proto_item_append_text(block_item, "Device/RSI Properties");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length);
    }

    return offset;
}

/* dissect the "tsn" suboption */
static int
dissect_PNDCP_Suboption_TSN(tvbuff_t* tvb, int offset, packet_info* pinfo,
    proto_tree* tree, proto_item* block_item, proto_item* dcp_item,
    guint8 service_id, gboolean is_response)
{
    guint8    suboption;
    guint16   block_length;
    char     *domain_name;
    guint16   nme_prio;
    e_guid_t  tsn_domain_uuid;
    e_guid_t  nme_parameter_uuid;
    e_guid_t  nme_name_uuid;
    guint16   vendor_id;
    guint16   device_id;
    guint16   block_info = 0;
    guint16   block_qualifier = 0;
    gboolean  have_block_info = FALSE;
    gboolean  have_block_qualifier = FALSE;
    guint8    instance_id_high;
    guint8    instance_id_low;
    conversation_t* conversation;
    stationInfo* station_info;
    gboolean is_zeros = TRUE;

    /* SuboptionTSN... */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_tsn, &suboption);

    /* DCPBlockLength */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    /* BlockInfo? */
    if (((service_id == PNDCP_SERVICE_ID_IDENTIFY) && is_response) ||
        ((service_id == PNDCP_SERVICE_ID_HELLO) && !is_response) ||
        ((service_id == PNDCP_SERVICE_ID_GET) && is_response)) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
        have_block_info = TRUE;
        block_length -= 2;
    }

    /* BlockQualifier? */
    if ((service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        have_block_qualifier = TRUE;
        block_length -= 2;
    }

    switch (suboption) {
    case PNDCP_SUBOPTION_TSN_DOMAIN_NAME:

        offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_tsn_domain_uuid, &tsn_domain_uuid);
        proto_tree_add_item_ret_display_string(tree, hf_pn_dcp_suboption_tsn_domain_name, tvb, offset, (block_length-16), ENC_ASCII | ENC_NA, wmem_packet_scope(), &domain_name);

        pn_append_info(pinfo, dcp_item, ", TSN-Domain Name");
        proto_item_append_text(block_item, "TSN/TSN-Domain Name");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", rval_to_str(block_info, pn_dcp_block_info, "Unknown"));

        pn_append_info(pinfo, dcp_item, wmem_strdup_printf(wmem_packet_scope(), ", DomainName:\"%s\"", domain_name));
        proto_item_append_text(block_item, ", \"%s\"", domain_name);
        offset += (block_length-16);
        is_zeros = TRUE;

        for (int i = 0; i < 8; i++)
        {
            if (tsn_domain_uuid.data4[i] != 0)
            {
                is_zeros = FALSE;
                break;
            }
        }

        if ((tsn_domain_uuid.data1 == 0) && (tsn_domain_uuid.data2 == 0) && (tsn_domain_uuid.data3 == 0) && (is_zeros))
            proto_item_append_text(block_item, ", No TSN domain assigned");
        else
            proto_item_append_text(block_item, ", UUID identifying a TSN domain using SNMP/ LLDP/ DCP");

        break;

    case PNDCP_SUBOPTION_TSN_NME_MANAGER:

        pn_append_info(pinfo, dcp_item, ", NME-Manager");
        proto_item_append_text(block_item, "TSN/NME-Manager");

        if (have_block_qualifier)
        {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }

        if (have_block_info)
        {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_tsn_nme_prio, &nme_prio);
            proto_item_append_text(block_item, ", BlockInfo: %s", rval_to_str(block_info, pn_dcp_block_info, "Unknown"));

            if (nme_prio == 0x0000)
                proto_item_append_text(block_item, ", Highest priority NME manager");
            else if ((0x0001 <= nme_prio) && (nme_prio <= 0x3000))
                proto_item_append_text(block_item, ", High priorities for NME manager");
            else if ((0x3001 <= nme_prio) && (nme_prio <= 0x9FFF))
                proto_item_append_text(block_item, ", Low priorities for NME manager");
            else if (0xA000 == nme_prio)
                proto_item_append_text(block_item, ", Lowest priority for NME manager / Default priority for NME manager");
            else
                proto_item_append_text(block_item, ", Reserved");
        }

        break;

    case PNDCP_SUBOPTION_TSN_NME_PARAMETER_UUID:

        pn_append_info(pinfo, dcp_item, ", NME-Parameter UUID");
        proto_item_append_text(block_item, "TSN/NME-Parameter UUID");

        if (block_length > 0)
        {
            offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_tsn_nme_parameter_uuid, &nme_parameter_uuid);

            if (have_block_qualifier)
            {
                proto_item_append_text(block_item, ", BlockQualifier: %s",
                    val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
            }
            if (have_block_info)
                proto_item_append_text(block_item, ", BlockInfo: %s", rval_to_str(block_info, pn_dcp_block_info, "Unknown"));

            is_zeros = TRUE;

            for (int i = 0; i < 8; i++)
            {
                if (nme_parameter_uuid.data4[i] != 0)
                {
                    is_zeros = FALSE;
                    break;
                }
            }
            if ((nme_parameter_uuid.data1 == 0) && (nme_parameter_uuid.data2 == 0) && (nme_parameter_uuid.data3 == 0) && (is_zeros))
                proto_item_append_text(block_item, ", Unconfigured");
            else
                proto_item_append_text(block_item, ", UUID identifying an NME parameter set within the TSN domain.");
        }
        break;

    case PNDCP_SUBOPTION_TSN_NME_AGENT:

        pn_append_info(pinfo, dcp_item, ", NME-Agent");
        proto_item_append_text(block_item, "TSN/NME-Agent");

        if (have_block_qualifier)
        {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }

        if (have_block_info)
        {
            offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_tsn_nme_agent, &nme_name_uuid);
            proto_item_append_text(block_item, ", BlockInfo: %s", rval_to_str(block_info, pn_dcp_block_info, "Unknown"));

            is_zeros = TRUE;
            for (int i = 0; i < 8; i++)
            {
                if (nme_name_uuid.data4[i] != 0)
                {
                    is_zeros = FALSE;
                    break;
                }
            }

            if ((nme_name_uuid.data1 == 0) && (nme_name_uuid.data2 == 0) && (nme_name_uuid.data3 == 0) && (is_zeros))
                proto_item_append_text(block_item, ", No NME assigned");
            else
                proto_item_append_text(block_item, ", UUID identifying an NME using SNMP / LLDP / DCP");
        }
        break;

    case PNDCP_SUBOPTION_TSN_CIM_INTERFACE:

        pn_append_info(pinfo, dcp_item, ", CIM-Interface");
        proto_item_append_text(block_item, "TSN/CIM-Interface");

        if (have_block_qualifier)
        {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info)
        {
            // CIMVDIValue
            dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_vendor_id_high, &vendor_id);
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_vendor_id_low, &vendor_id);

            dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_device_id_high, &device_id);
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_device_id_low, &device_id);

            offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_instance_id_high, &instance_id_high);
            offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_instance_id_low, &instance_id_low);

            if (pinfo->fd->visited == FALSE) {
                /* Create a conversation between the MAC addresses */
                conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
                if (conversation == NULL) {
                    conversation = conversation_new(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);
                }

                station_info = (stationInfo*)conversation_get_proto_data(conversation, proto_pn_dcp);
                if (station_info == NULL) {
                    station_info = wmem_new0(wmem_file_scope(), stationInfo);
                    init_pnio_rtc1_station(station_info);
                    conversation_add_proto_data(conversation, proto_pn_dcp, station_info);
                }

                station_info->u16Vendor_id = vendor_id;
                station_info->u16Device_id = device_id;
            }

            proto_item_append_text(block_item, ", BlockInfo: %s", rval_to_str(block_info, pn_dcp_block_info, "Unknown"));

            proto_item_append_text(block_item, ", VendorID: 0x%04x / DeviceID: 0x%04x / InstanceIDHigh: 0x%04x / InstanceIDLow: 0x%04x", vendor_id, device_id, instance_id_high, instance_id_low);
        }
        break;

    default:
        pn_append_info(pinfo, dcp_item, ", TSN/Reserved");
        proto_item_append_text(block_item, "TSN/Reserved");
    }

    return offset;
}

/* dissect the "DHCP" suboption */
static int
dissect_PNDCP_Suboption_DHCP(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                                guint8 service_id _U_, gboolean is_response _U_)
{
    guint8   suboption;
    guint8   option_code = 0;
    guint16  block_length;
    guint16  block_info = 0;
    guint16  block_qualifier = 0;
    guint8   dhcpparameterlength = 0;
    guint8   dhcpparameterdata = 0;
    guint8   dhcpcontrolparameterdata = 0;
    gboolean have_block_info      = FALSE;
    gboolean have_block_qualifier = FALSE;
    int      expected_offset;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    expected_offset = offset + block_length;

    /* BlockInfo? */
    if ( ((service_id == PNDCP_SERVICE_ID_IDENTIFY) &&  is_response) ||
         ((service_id == PNDCP_SERVICE_ID_HELLO)    && !is_response) ||
         ((service_id == PNDCP_SERVICE_ID_GET)      &&  is_response)) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
        have_block_info=TRUE;
        block_length -= 2;
    }
    /* BlockQualifier? */
    if ( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        have_block_qualifier=TRUE;
        block_length -= 2;
    }

    switch (suboption) {
    case PNDCP_SUBOPTION_DHCP_CLIENT_ID:
        pn_append_info(pinfo, dcp_item, ", DHCP client identifier");
        proto_item_append_text(block_item, "DHCP/Client-ID");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                                   val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                                   rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp_option_code, &option_code);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp_parameter_length, &dhcpparameterlength);
        if (dhcpparameterlength > 0) {
            offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp_parameter_data, &dhcpparameterdata);
            if (dhcpparameterlength == 1) {
                if (dhcpparameterdata == 1) {
                    proto_item_append_text(block_item, ", Client-ID: MAC Address");
                }
                else {
                    proto_item_append_text(block_item, ", Client-ID: Name of Station");
                }
            }
            else {
                proto_item_append_text(block_item, ", Client-ID: Arbitrary");
                /*
                 * XXX - IEC 61158-6-10 Edition 4.0, section 4.3.1.4.21.5
                 * "Use of arbitrary client identifier", that this is an
                 * OctetString to be used as a client identifier with DHCP.
                 *
                 * Does that mean it should be FT_BYTES, possibly with
                 * the BASE_SHOW_ASCII_PRINTABLE flag to show it as ASCII
                 * iff it's printable?  Or should packet-dhcp.c export
                 * dissect_dhcpopt_client_identifier(), so that we can
                 * use its heuristics?
                 */
                proto_tree_add_item(tree, hf_pn_dcp_suboption_dhcp_arbitrary_client_id, tvb, offset, dhcpparameterlength - 1, ENC_ASCII);
                offset += (dhcpparameterlength-1);
            }
        }
        break;
    case PNDCP_SUBOPTION_DHCP_CONTROL_FOR_ADDRESS_RES:
        pn_append_info(pinfo, dcp_item, ", Control DHCP for address resolution");
        proto_item_append_text(block_item, "DHCP/Control DHCP for address resolution");
        if (have_block_qualifier) {
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        }
        if (have_block_info) {
            proto_item_append_text(block_item, ", BlockInfo: %s",
                rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        }
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp_option_code, &option_code);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp_parameter_length, &dhcpparameterlength);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp_control_parameter_data, &dhcpcontrolparameterdata);
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length);
    }

    if (expected_offset > offset) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree, expected_offset - offset, "Undefined");
    }

    return offset;
}


/* dissect the "control" suboption */
static int
dissect_PNDCP_Suboption_Control(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                                guint8 service_id _U_, gboolean is_response _U_)
{
    guint8      suboption;
    guint16     block_length;
    guint16     block_qualifier;
    guint16     BlockQualifier;
    guint16     u16SignalValue;
    gchar      *info_str;
    guint8      block_error;
    proto_item *item = NULL;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_control, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    if (service_id == PNDCP_SERVICE_ID_SET && block_length == 0) {
        pn_append_info(pinfo, dcp_item, ", Erroneous DCPSet block");
        proto_item_append_text(block_item, "Control/Erroneous DCPSet block");
    }
    else {
        switch (suboption) {
        case PNDCP_SUBOPTION_CONTROL_START_TRANS:
            pn_append_info(pinfo, dcp_item, ", Start-Trans");
            proto_item_append_text(block_item, "Control/Start-Transaction");
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
            break;
        case PNDCP_SUBOPTION_CONTROL_END_TRANS:
            pn_append_info(pinfo, dcp_item, ", End-Trans");
            proto_item_append_text(block_item, "Control/End-Transaction");
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
            break;
        case PNDCP_SUBOPTION_CONTROL_SIGNAL:
            pn_append_info(pinfo, dcp_item, ", Signal");
            proto_item_append_text(block_item, "Control/Signal");
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
            block_length -= 2;

            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_control_signal_value, &u16SignalValue);
            break;
        case PNDCP_SUBOPTION_CONTROL_RESPONSE:
            proto_item_append_text(block_item, "Control/Response");
            offset = dissect_PNDCP_Option(tvb, offset, pinfo, tree, block_item, hf_pn_dcp_suboption_control_option,
                FALSE /* append_col */);
            block_error = tvb_get_guint8(tvb, offset);
            if (tree) {
                item = proto_tree_add_uint(tree, hf_pn_dcp_block_error, tvb, offset, 1, block_error);
            }
            offset += 1;
            if (block_error != 0) {
                expert_add_info_format(pinfo, item, &ei_pn_dcp_block_error_unknown, "%s",
                    val_to_str(block_error, pn_dcp_block_error, "Unknown"));
            }
            info_str = wmem_strdup_printf(pinfo->pool, ", Response(%s)",
                val_to_str(block_error, pn_dcp_block_error, "Unknown"));
            pn_append_info(pinfo, dcp_item, info_str);
            proto_item_append_text(block_item, ", BlockError: %s",
                val_to_str(block_error, pn_dcp_block_error, "Unknown"));

            break;
        case PNDCP_SUBOPTION_CONTROL_FACT_RESET:
            pn_append_info(pinfo, dcp_item, ", Reset FactorySettings");
            proto_item_append_text(block_item, "Control/Reset FactorySettings");
            block_length -= 2;
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_blockqualifier, &BlockQualifier);
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(BlockQualifier, pn_dcp_suboption_other, "reserved"));
            block_length -= 2;
            break;

        case PNDCP_SUBOPTION_CONTROL_RESET_TO_FACT:
            pn_append_info(pinfo, dcp_item, ", Reset to Factory");
            proto_item_append_text(block_item, "Reset to FactorySettings");

            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_blockqualifier_r2f, &BlockQualifier);
            proto_item_append_text(block_item, ", BlockQualifier: %s",
                val_to_str(BlockQualifier, pn_dcp_BlockQualifier, "reserved"));
            block_length -= 2;

            break;
        default:
            offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length);
        }
    }

    return offset;
}


/* dissect the "deviceinitaitve" suboption */
static int
dissect_PNDCP_Suboption_DeviceInitiative(tvbuff_t *tvb, int offset, packet_info *pinfo,
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                            guint8 service_id, gboolean is_response)
{
    guint8  suboption;
    guint16 block_length;
    guint16 block_info;
    guint16 block_qualifier;
    guint16 value;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_deviceinitiative, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    pn_append_info(pinfo, dcp_item, ", DeviceInitiative");
    proto_item_append_text(block_item, "DeviceInitiative/DeviceInitiative");

    /* BlockInfo? */
    if ( ((service_id == PNDCP_SERVICE_ID_IDENTIFY) &&  is_response) ||
        ((service_id == PNDCP_SERVICE_ID_HELLO)    && !is_response) ||
        ((service_id == PNDCP_SERVICE_ID_GET)      &&  is_response)) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
        proto_item_append_text(block_item, ", BlockInfo: %s",
                               rval_to_str(block_info, pn_dcp_block_info, "Unknown"));
        block_length -= 2;
    }

    /* BlockQualifier? */
    if ( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        proto_item_append_text(block_item, ", BlockQualifier: %s",
                               val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        block_length -= 2;
    }

    /* DeviceInitiativeValue */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_deviceinitiative_value, &value);

    return offset;
}


/* dissect the "all" suboption */
static int
dissect_PNDCP_Suboption_All(tvbuff_t *tvb, int offset, packet_info *pinfo,
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                            guint8 service_id _U_, gboolean is_response _U_)
{
    guint8  suboption;
    guint16 block_length;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_all, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    switch (suboption) {
    case 255:    /* All */
        pn_append_info(pinfo, dcp_item, ", All");
        proto_item_append_text(block_item, "All/All");
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length);
    }

    return offset;
}


/* dissect the "manufacturer" suboption */
static int
dissect_PNDCP_Suboption_Manuf(tvbuff_t *tvb, int offset, packet_info *pinfo,
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                            guint8 service_id _U_, gboolean is_response _U_)
{
    guint16 block_length;

    offset = dissect_pn_uint8( tvb, offset, pinfo, tree, hf_pn_dcp_suboption_manuf, NULL);

    pn_append_info(pinfo, dcp_item, ", Manufacturer Specific");
    proto_item_append_text(block_item, "Manufacturer Specific");

    if (tvb_reported_length_remaining(tvb, offset)>0)
    {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length);
    }
    return offset;
}


/* dissect one DCP block */
static int
dissect_PNDCP_Block(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, proto_item *dcp_item,
                    guint8 service_id, gboolean is_response)
{
    guint8      option;
    proto_item *block_item;
    proto_tree *block_tree;
    int         ori_offset = offset;

    /* subtree for block */
    block_item = proto_tree_add_none_format(tree, hf_pn_dcp_block,
        tvb, offset, 0, "Block: ");
    block_tree = proto_item_add_subtree(block_item, ett_pn_dcp_block);


    offset = dissect_pn_uint8(tvb, offset, pinfo, block_tree, hf_pn_dcp_option, &option);

    if (option == PNDCP_OPTION_IP)
    {
        offset = dissect_PNDCP_Suboption_IP(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else if (option == PNDCP_OPTION_DEVICE)
    {
        offset = dissect_PNDCP_Suboption_Device(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else if (option == PNDCP_OPTION_DHCP)
    {
        offset = dissect_PNDCP_Suboption_DHCP(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else if (option == PNDCP_OPTION_CONTROL)
    {
        offset = dissect_PNDCP_Suboption_Control(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else if (option == PNDCP_OPTION_DEVICEINITIATIVE)
    {
        offset = dissect_PNDCP_Suboption_DeviceInitiative(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else if (option == PNDCP_OPTION_TSN)
    {
        offset = dissect_PNDCP_Suboption_TSN(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else if (option == PNDCP_OPTION_ALLSELECTOR)
    {
        offset = dissect_PNDCP_Suboption_All(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else if (PNDCP_OPTION_MANUF_X80 <= option && option <= PNDCP_OPTION_MANUF_XFE)
    {
        offset = dissect_PNDCP_Suboption_Manuf(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }
    else
    {
        pn_append_info(pinfo, dcp_item, ", Reserved");
        proto_item_append_text(block_item, "Reserved");
        /* there isn't a predefined suboption type for reserved option, rest of the block will be seen as padding */
    }

    proto_item_set_len(block_item, offset-ori_offset);

    if (((offset-ori_offset) & 1) && (tvb_reported_length_remaining(tvb, offset) > 0)) {
        /* we have an odd number of bytes in this block, add a padding byte */
        offset = dissect_pn_padding(tvb, offset, pinfo, tree, 1);
    }

    return offset;
}


/* dissect a whole DCP PDU */
static void
dissect_PNDCP_PDU(tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, proto_item *dcp_item)
{
    guint8    service_id;
    guint8    service_type;
    guint32   xid;
    guint16   response_delay;
    guint16   data_length;
    int       offset      = 0;
    gchar    *xid_str;
    gboolean  is_response = FALSE;


    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hf_pn_dcp_service_id, &service_id);
    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hf_pn_dcp_service_type, &service_type);
    proto_tree_add_item_ret_uint(tree, hf_pn_dcp_xid, tvb, offset, 4, ENC_BIG_ENDIAN, &xid);
    offset += 4;
    if (service_id == PNDCP_SERVICE_ID_IDENTIFY && service_type == PNDCP_SERVICE_TYPE_REQUEST) {
        /* multicast header */
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_response_delay, &response_delay);
    } else {
        /* unicast header */
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_reserved16, NULL);
    }
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_data_length, &data_length);

    switch (service_id) {
    case PNDCP_SERVICE_ID_GET:
        pn_append_info(pinfo, dcp_item, "Get");
        break;
    case PNDCP_SERVICE_ID_SET:
        pn_append_info(pinfo, dcp_item, "Set");
        break;
    case PNDCP_SERVICE_ID_IDENTIFY:
        pn_append_info(pinfo, dcp_item, "Ident");
        break;
    case PNDCP_SERVICE_ID_HELLO:
        pn_append_info(pinfo, dcp_item, "Hello");
        break;
    default:
        dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_captured_length_remaining(tvb, offset));
        return;
    }

    switch (service_type) {
    case PNDCP_SERVICE_TYPE_REQUEST:
        pn_append_info(pinfo, dcp_item, " Req");
        break;
    case PNDCP_SERVICE_TYPE_RESPONSE_SUCCESS:
        pn_append_info(pinfo, dcp_item, " Ok ");
        is_response = TRUE;
        break;
    case PNDCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED:
        pn_append_info(pinfo, dcp_item, " unsupported");
        is_response = TRUE;
        break;
    default:
        dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_captured_length_remaining(tvb, offset));
        return;
    }

    xid_str = wmem_strdup_printf(pinfo->pool, ", Xid:0x%x", xid);
    pn_append_info(pinfo, dcp_item, xid_str);

    /* dissect a number of blocks (depending on the remaining length) */
    while(data_length) {
        int ori_offset = offset;

        if (service_id == PNDCP_SERVICE_ID_GET && service_type == PNDCP_SERVICE_TYPE_REQUEST) {
            /* Selectors */
            offset = dissect_PNDCP_Option(tvb, offset, pinfo,
                                 tree, dcp_item, hf_pn_dcp_option, TRUE /* append_col */);
        } else {
            offset = dissect_PNDCP_Block(tvb, offset, pinfo, tree, dcp_item, service_id, is_response);
        }
        /* prevent an infinite loop */
        if (offset <= ori_offset || data_length < (offset - ori_offset)) {
            proto_tree_add_expert(tree, pinfo, &ei_pn_dcp_block_parse_error,
                            tvb, ori_offset, tvb_captured_length_remaining(tvb, ori_offset));
            break;
        }
        data_length -= (offset - ori_offset);
    }
}


/* possibly dissect a PN-RT packet (frame ID must be in the appropriate range) */
static gboolean
dissect_PNDCP_Data_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data)
{
    /* the tvb will NOT contain the frame_id here, so get it from dissection data! */
    guint16     u16FrameID = GPOINTER_TO_UINT(data);
    proto_item *item;
    proto_tree *dcp_tree;


    /* frame id must be in valid range (acyclic Real-Time, DCP) */
    if (u16FrameID < FRAME_ID_DCP_HELLO || u16FrameID > FRAME_ID_DCP_IDENT_RES) {
        /* we are not interested in this packet */
        return FALSE;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-DCP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* subtree for DCP */
    item = proto_tree_add_protocol_format(tree, proto_pn_dcp, tvb, 0, tvb_get_ntohs(tvb, 8) + 10,
                "PROFINET DCP, ");
    dcp_tree = proto_item_add_subtree(item, ett_pn_dcp);

    /* dissect this PDU */
    dissect_PNDCP_PDU(tvb, pinfo, dcp_tree, item);

    return TRUE;
}


void
proto_register_pn_dcp (void)
{
    static hf_register_info hf[] = {
        { &hf_pn_dcp_service_id,
          { "ServiceID", "pn_dcp.service_id",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_service_id), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_service_type,
          { "ServiceType", "pn_dcp.service_type",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_service_type), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_xid,
          { "Xid", "pn_dcp.xid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_reserved8,
          { "Reserved", "pn_dcp.reserved8",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_reserved16,
          { "Reserved", "pn_dcp.reserved16",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_response_delay,
          { "ResponseDelay", "pn_dcp.response_delay",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_data_length,
          { "DCPDataLength", "pn_dcp.data_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_block_length,
          { "DCPBlockLength", "pn_dcp.block_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_option,
          { "Option", "pn_dcp.option",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(pn_dcp_option), 0x0,
            NULL, HFILL }},

#if 0
        { &hf_pn_dcp_suboption,
          { "Suboption", "pn_dcp.suboption",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
#endif

        { &hf_pn_dcp_block_error,
          { "BlockError", "pn_dcp.block_error",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_block_error), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_block,
          { "Block", "pn_dcp.block",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_block_info,
          { "BlockInfo", "pn_dcp.block_info",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(pn_dcp_block_info), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_block_qualifier,
          { "BlockQualifier", "pn_dcp.block_qualifier",
            FT_UINT16, BASE_DEC, VALS(pn_dcp_block_qualifier), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_blockqualifier_r2f,
          { "BlockQualifier: ResettoFactory", "pn_dcp.block_qualifier_reset",
            FT_UINT16, BASE_DEC, VALS(pn_dcp_BlockQualifier), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_blockqualifier,
          { "BlockQualifier: ResetFactorySettings", "pn_dcp.block_qualifier_reset",
            FT_UINT16, BASE_DEC, VALS(pn_dcp_suboption_other), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_ip,
          { "Suboption", "pn_dcp.suboption_ip",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_ip), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_ip_block_info,
          { "BlockInfo", "pn_dcp.suboption_ip_block_info",
            FT_UINT16, BASE_DEC, VALS(pn_dcp_suboption_ip_block_info), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_ip_mac_address,
          { "MAC Address", "pn_dcp.suboption_ip_mac_address",
             FT_ETHER, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},

        { &hf_pn_dcp_suboption_ip_ip,
          { "IPaddress", "pn_dcp.suboption_ip_ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_ip_subnetmask,
          { "Subnetmask", "pn_dcp.suboption_ip_subnetmask",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_ip_standard_gateway,
          { "StandardGateway", "pn_dcp.suboption_ip_standard_gateway",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device,
          { "Suboption", "pn_dcp.suboption_device",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_device), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_typeofstation,
          { "DeviceVendorValue", "pn_dcp.suboption_device_devicevendorvalue",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_nameofstation,
          { "NameOfStation", "pn_dcp.suboption_device_nameofstation",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_vendor_id,
          { "VendorID", "pn_dcp.suboption_vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_id,
          { "DeviceID", "pn_dcp.suboption_device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_role,
          { "DeviceRoleDetails", "pn_dcp.suboption_device_role",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_aliasname,
          { "AliasName", "pn_dcp.suboption_device_aliasname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_instance_high,
          { "DeviceInstanceHigh", "pn_dcp.suboption_device_instance",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_instance_low,
          { "DeviceInstanceLow", "pn_dcp.suboption_device_instance",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_oem_ven_id,
          { "OEMVendorID", "pn_dcp.suboption_device_oem_ven_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_device_oem_dev_id,
          { "OEMDeviceID", "pn_dcp.suboption_device_oem_dev_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_rsi_properties_value,
          { "RsiPropertiesValue", "pn_dcp.suboption_device_rsi_properties_value",
            FT_UINT16, BASE_HEX, 0, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_rsi_properties_value_bit0,
          { "IP Stack", "pn_dcp.suboption_device_rsi_properties_value.bit0",
            FT_BOOLEAN, 16, TFS(&pn_dcp_rsi_properties_value_bit), 0x0001,
            NULL, HFILL } },

        { &hf_pn_dcp_rsi_properties_value_bit1,
          { "CLRPC Interface", "pn_dcp.suboption_device_rsi_properties_value.bit1",
            FT_BOOLEAN, 16, TFS(&pn_dcp_rsi_properties_value_bit), 0x0002,
            NULL, HFILL } },

        { &hf_pn_dcp_rsi_properties_value_bit2,
          { "RSI AR Interface", "pn_dcp.suboption_device_rsi_properties_value.bit2",
            FT_BOOLEAN, 16, TFS(&pn_dcp_rsi_properties_value_bit), 0x0004,
            NULL, HFILL } },

        { &hf_pn_dcp_rsi_properties_value_bit3,
          { "RSI AR Read Implicit Interface", "pn_dcp.suboption_device_rsi_properties_value.bit3",
            FT_BOOLEAN, 16, TFS(&pn_dcp_rsi_properties_value_bit), 0x0008,
            NULL, HFILL } },

        { &hf_pn_dcp_rsi_properties_value_bit4,
          { "RSI CIM Interface", "pn_dcp.suboption_device_rsi_properties_value.bit4",
            FT_BOOLEAN, 16, TFS(&pn_dcp_rsi_properties_value_bit), 0x0010,
            NULL, HFILL } },

        { &hf_pn_dcp_rsi_properties_value_bit5,
          { "RSI CIM Read Implicit Interface", "pn_dcp.suboption_device_rsi_properties_value.bit5",
            FT_BOOLEAN, 16, TFS(&pn_dcp_rsi_properties_value_bit), 0x0020,
            NULL, HFILL } },

        { &hf_pn_dcp_rsi_properties_value_otherbits,
          { "RsiPropertiesValue.Bit6-15", "pn_dcp.suboption_device_rsi_properties_value.otherbits",
            FT_UINT16, BASE_HEX, NULL, 0xFFC0,
            NULL, HFILL } },

        { &hf_pn_dcp_vendor_id_high,
          { "VendorIDHigh", "pn_dcp.vendor_id_high",
            FT_UINT16, BASE_HEX, NULL, 0xFF00,
            NULL, HFILL } },

        { &hf_pn_dcp_vendor_id_low,
          { "VendorIDLow", "pn_dcp.vendor_id_low",
            FT_UINT16, BASE_HEX, NULL, 0x00FF,
            NULL, HFILL } },

        { &hf_pn_dcp_device_id_high,
          { "DeviceIDHigh", "pn_dcp.device_id_high",
            FT_UINT16, BASE_HEX, NULL, 0xFF00,
            NULL, HFILL } },

        { &hf_pn_dcp_device_id_low,
          { "DeviceIDLow", "pn_dcp.device_id_low",
            FT_UINT16, BASE_HEX, NULL, 0x00FF,
            NULL, HFILL } },

        { &hf_pn_dcp_instance_id_high,
          { "InstanceHigh", "pn_dcp.instance_id_high",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_instance_id_low,
          { "InstanceLow", "pn_dcp.instance_id_low",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_dhcp,
          { "Suboption", "pn_dcp.suboption_dhcp",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_dhcp), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_dhcp_option_code,
          { "Option-Code", "pn_dcp.suboption_dhcp_option_code",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_dhcp), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_dhcp_arbitrary_client_id,
          { "Client ID", "pn_dcp.suboption_dhcp_client_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_dhcp_parameter_length,
          { "DHCP Parameter Length", "pn_dcp.suboption_dhcp_parameter_length",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_dhcp_parameter_data,
          { "DHCP Parameter Data", "pn_dcp.suboption_dhcp_parameter_data",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_dhcp_control_parameter_data,
          { "DHCP Parameter Data", "pn_dcp.suboption_dhcp_parameter_data",
            FT_UINT8, BASE_HEX, VALS(pn_dcp_suboption_dhcp_control_parameter_data), 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_control,
          { "Suboption", "pn_dcp.suboption_control",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_control), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_control_option,
          { "Option", "pn_dcp.suboption_control_option",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(pn_dcp_option), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_control_signal_value,
          { "SignalValue", "pn_dcp.suboption_control_signal_value",
            FT_UINT16, BASE_HEX, VALS(pn_dcp_suboption_control_signal_value), 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_deviceinitiative,
          { "Suboption", "pn_dcp.suboption_deviceinitiative",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_deviceinitiative), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_deviceinitiative_value,
          { "DeviceInitiativeValue", "pn_dcp.deviceinitiative_value",
            FT_UINT16, BASE_DEC, VALS(pn_dcp_deviceinitiative_value), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_tsn,
          { "Suboption", "pn_dcp.suboption_tsn",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_tsn), 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_tsn_domain_name,
          { "TSNDomainName", "pn_dcp.suboption_tsn_domain_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_tsn_domain_uuid,
          { "TSNDomainUUID", "pn_dcp.tsn_domain_uuid",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_tsn_nme_prio,
          { "NMEPrio", "pn_dcp.suboption_tsn_nme_prio",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING, RVALS(pn_dcp_suboption_tsn_nme_prio), 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_tsn_nme_parameter_uuid,
          { "NMEParameterUUID", "pn_dcp.suboption_tsn_nme_parameter_uuid",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_tsn_nme_agent,
          { "NMEAgent", "pn_dcp.suboption_tsn_nme_agent",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },

        { &hf_pn_dcp_suboption_all,
          { "Suboption", "pn_dcp.suboption_all",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_all), 0x0,
            NULL, HFILL }},

        { &hf_pn_dcp_suboption_manuf,
          { "Suboption", "pn_dcp.suboption_manuf",
            FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_manuf), 0x0,
            NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_pn_dcp,
        &ett_pn_dcp_block,
        &ett_pn_dcp_rsi_properties_value
    };

    static ei_register_info ei[] = {
        { &ei_pn_dcp_block_parse_error, { "pn_dcp.block_error.parse", PI_PROTOCOL, PI_ERROR, "parse error", EXPFILL }},
        { &ei_pn_dcp_block_error_unknown, { "pn_dcp.block_error.unknown", PI_RESPONSE_CODE, PI_CHAT, "Unknown", EXPFILL }},
        { &ei_pn_dcp_ip_conflict, { "pn_dcp.ip_conflict", PI_RESPONSE_CODE, PI_NOTE, "IP address conflict detected!", EXPFILL }},
    };

    expert_module_t* expert_pn_dcp;

    proto_pn_dcp = proto_register_protocol ("PROFINET DCP", "PN-DCP", "pn_dcp");
    proto_register_field_array (proto_pn_dcp, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    expert_pn_dcp = expert_register_protocol(proto_pn_dcp);
    expert_register_field_array(expert_pn_dcp, ei, array_length(ei));
}

void
proto_reg_handoff_pn_dcp (void)
{
    /* register ourself as an heuristic pn-rt payload dissector */
    heur_dissector_add("pn_rt", dissect_PNDCP_Data_heur, "PROFINET DCP IO", "pn_dcp_pn_rt", proto_pn_dcp, HEURISTIC_ENABLE);
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
