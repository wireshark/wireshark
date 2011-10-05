/* packet-pn-dcp.c
 * Routines for PN-DCP (PROFINET Discovery and basic Configuration Protocol) 
 * packet dissection.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-dcerpc.h>

#include "packet-pn.h"



static int proto_pn_dcp = -1;

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
static int hf_pn_dcp_suboption = -1;
static int hf_pn_dcp_block_info = -1;
static int hf_pn_dcp_block_qualifier = -1;

static int hf_pn_dcp_suboption_ip = -1;
static int hf_pn_dcp_suboption_ip_block_info = -1;
static int hf_pn_dcp_suboption_ip_ip = -1;
static int hf_pn_dcp_suboption_ip_subnetmask = -1;
static int hf_pn_dcp_suboption_ip_standard_gateway = -1;

static int hf_pn_dcp_suboption_device = -1;
static int hf_pn_dcp_suboption_device_typeofstation = -1;
static int hf_pn_dcp_suboption_device_nameofstation = -1;
static int hf_pn_dcp_suboption_vendor_id = -1;
static int hf_pn_dcp_suboption_device_id = -1;
static int hf_pn_dcp_suboption_device_role = -1;
static int hf_pn_dcp_suboption_device_aliasname = -1;

static int hf_pn_dcp_suboption_dhcp = -1;
static int hf_pn_dcp_suboption_dhcp_device_id = -1;

static int hf_pn_dcp_suboption_control = -1;
static int hf_pn_dcp_suboption_control_response = -1;

static int hf_pn_dcp_suboption_deviceinitiative = -1;
static int hf_pn_dcp_deviceinitiative_value = -1;

static int hf_pn_dcp_suboption_all = -1;

static int hf_pn_dcp_suboption_manuf = -1;


static gint ett_pn_dcp = -1;
static gint ett_pn_dcp_block = -1;



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

static const value_string pn_dcp_block_info[] = {
    { 0x0000, "Reserved" },
    /*0x0001 - 0xffff reserved */
    { 0, NULL }
};

static const value_string pn_dcp_block_qualifier[] = {
    { 0x0000, "Use the value temporary" },
    { 0x0001, "Save the value permanent" },
    /*0x0002 - 0xffff reserved */
    { 0, NULL }
};


#define PNDCP_OPTION_IP                 0x01
#define PNDCP_OPTION_DEVICE             0x02
#define PNDCP_OPTION_DHCP               0x03
#define PNDCP_OPTION_RESERVED           0x04
#define PNDCP_OPTION_CONTROL            0x05
#define PNDCP_OPTION_DEVICEINITIATIVE   0x06
#define PNDCP_OPTION_MANUF_X80          0x80
#define PNDCP_OPTION_MANUF_X81          0x81
#define PNDCP_OPTION_MANUF_X82          0x82
#define PNDCP_OPTION_MANUF_X83          0x83
#define PNDCP_OPTION_MANUF_X84          0x84
#define PNDCP_OPTION_MANUF_X85          0x85
#define PNDCP_OPTION_MANUF_X86          0x86
#define PNDCP_OPTION_ALLSELECTOR        0xff

static const value_string pn_dcp_option[] = {
    { 0x00, "reserved" },
    { PNDCP_OPTION_IP,                  "IP" },
    { PNDCP_OPTION_DEVICE,              "Device properties" },
    { PNDCP_OPTION_DHCP,                "DHCP" },
    { PNDCP_OPTION_RESERVED,            "Reserved" },
    { PNDCP_OPTION_CONTROL,             "Control" },
    { PNDCP_OPTION_DEVICEINITIATIVE,    "Device Initiative" },
    /*0x07 - 0x7f reserved */
    /*0x80 - 0xfe manufacturer specific */
    { PNDCP_OPTION_MANUF_X80,           "Manufacturer specific" },
    { PNDCP_OPTION_MANUF_X81,           "Manufacturer specific" },
    { PNDCP_OPTION_MANUF_X82,           "Manufacturer specific" },
    { PNDCP_OPTION_MANUF_X83,           "Manufacturer specific" },
    { PNDCP_OPTION_MANUF_X84,           "Manufacturer specific" },
    { PNDCP_OPTION_MANUF_X85,           "Manufacturer specific" },
    { PNDCP_OPTION_MANUF_X86,           "Manufacturer specific" },
    { PNDCP_OPTION_ALLSELECTOR,         "All Selector" },
    { 0, NULL }
};

#define PNDCP_SUBOPTION_IP_MAC  0x01
#define PNDCP_SUBOPTION_IP_IP   0x02

static const value_string pn_dcp_suboption_ip[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_IP_MAC,   "MAC address" },
    { PNDCP_SUBOPTION_IP_IP,    "IP parameter" },
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

#define PNDCP_SUBOPTION_DEVICE_MANUF            0x01
#define PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION    0x02
#define PNDCP_SUBOPTION_DEVICE_DEV_ID           0x03
#define PNDCP_SUBOPTION_DEVICE_DEV_ROLE         0x04
#define PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS      0x05
#define PNDCP_SUBOPTION_DEVICE_ALIAS_NAME       0x06

static const value_string pn_dcp_suboption_device[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_DEVICE_MANUF,         "Manufacturer specific (Type of Station)" },
    { PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION, "Name of Station" },
    { PNDCP_SUBOPTION_DEVICE_DEV_ID,        "Device ID" },
    { PNDCP_SUBOPTION_DEVICE_DEV_ROLE,      "Device Role" },
    { PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS,   "Device Options" },
    { PNDCP_SUBOPTION_DEVICE_ALIAS_NAME,    "Alias Name" },
    /*0x07 - 0xff reserved */
    { 0, NULL }
};

#define PNDCP_SUBOPTION_DHCP_CLIENT_ID	61

static const value_string pn_dcp_suboption_dhcp[] = {
    {  12, "Host name" },
    {  43, "Vendor specific" },
    {  54, "Server identifier" },
    {  55, "Parameter request list" },
    {  60, "Class identifier" },
    {  PNDCP_SUBOPTION_DHCP_CLIENT_ID, "DHCP client identifier" },
    {  81, "FQDN, Fully Qualified Domain Name" },
    {  97, "UUID/GUID-based Client" },
    { 255, "Control DHCP for address resolution" },
    /*all others reserved */
    { 0, NULL }
};

#define PNDCP_SUBOPTION_CONTROL_START_TRANS 0x01
#define PNDCP_SUBOPTION_CONTROL_END_TRANS   0x02
#define PNDCP_SUBOPTION_CONTROL_SIGNAL      0x03
#define PNDCP_SUBOPTION_CONTROL_RESPONSE    0x04
#define PNDCP_SUBOPTION_CONTROL_FACT_RESET  0x05

static const value_string pn_dcp_suboption_control[] = {
    { 0x00, "Reserved" },
    { PNDCP_SUBOPTION_CONTROL_START_TRANS, "Start Transaction" },
    { PNDCP_SUBOPTION_CONTROL_END_TRANS, "End Transaction" },
    { PNDCP_SUBOPTION_CONTROL_SIGNAL, "Signal" },
    { PNDCP_SUBOPTION_CONTROL_RESPONSE, "Response" },
	{ PNDCP_SUBOPTION_CONTROL_FACT_RESET, "Reset Factory Settings" },
    /*0x05 - 0xff reserved */
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
    switch(option) {
    case(PNDCP_OPTION_IP):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip, &suboption);
        val_str = pn_dcp_suboption_ip;
        break;
    case(PNDCP_OPTION_DEVICE):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device, &suboption);
        val_str = pn_dcp_suboption_device;
        break;
    case(PNDCP_OPTION_DHCP):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp, &suboption);
        val_str = pn_dcp_suboption_dhcp;
        break;
    case(PNDCP_OPTION_CONTROL):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_control, &suboption);
        val_str = pn_dcp_suboption_control;
        break;
    case(PNDCP_OPTION_DEVICEINITIATIVE):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_deviceinitiative, &suboption);
        val_str = pn_dcp_suboption_deviceinitiative;
        break;
    case(PNDCP_OPTION_ALLSELECTOR):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_all, &suboption);
        val_str = pn_dcp_suboption_all;
        break;
    default:
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_manuf, &suboption);
        val_str = pn_dcp_suboption_manuf;
    }

    proto_item_append_text(block_item, ", Status from %s - %s", 
        val_to_str(option, pn_dcp_option, "Unknown"), val_to_str(suboption, val_str, "Unknown"));

    if(append_col) {
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
    guint8 suboption;
    guint16 block_length;
    guint16 block_info;
    guint16 block_qualifier;
    guint32 ip;
    proto_item *item = NULL;


    /* SuboptionIPParameter */
    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip, &suboption);
    /* DCPBlockLength */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    switch(suboption) {
    case(PNDCP_SUBOPTION_IP_MAC):
        /* MACAddressValue? */
        pn_append_info(pinfo, dcp_item, ", MAC");
        proto_item_append_text(block_item, "IP/MAC");

        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length); 
        break;
    case(PNDCP_SUBOPTION_IP_IP):
        pn_append_info(pinfo, dcp_item, ", IP");
        proto_item_append_text(block_item, "IP/IP");

        /* BlockInfo? */
        if( ((service_id == PNDCP_SERVICE_ID_IDENTIFY) &&  is_response) ||
            ((service_id == PNDCP_SERVICE_ID_HELLO)    && !is_response) ||
            ((service_id == PNDCP_SERVICE_ID_GET)      &&  is_response)) {
            block_info = tvb_get_ntohs (tvb, offset);
            if (tree) {
                item = proto_tree_add_uint(tree, hf_pn_dcp_suboption_ip_block_info, tvb, offset, 2, block_info);
            }
            offset += 2;
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_suboption_ip_block_info, "Undecoded"));
            block_length -= 2;
            if(block_info & 0x80) {
                expert_add_info_format(pinfo, item, PI_RESPONSE_CODE, PI_NOTE, "IP address conflict detected!");
            }
        }

        /* BlockQualifier? */
        if( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
            block_length -= 2;
        }

        /* IPParameterValue ... */

        /* IPAddress */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_ip, &ip);
        proto_item_append_text(block_item, ", IP: %s", ip_to_str((guint8*)&ip));

        /* Subnetmask */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_subnetmask, &ip);
        proto_item_append_text(block_item, ", Subnet: %s", ip_to_str((guint8*)&ip));

        /* StandardGateway */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_standard_gateway, &ip);
        proto_item_append_text(block_item, ", Gateway: %s", ip_to_str((guint8*)&ip));
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
    guint8 suboption;
    guint16 block_length;
    gchar *info_str;
    guint8 device_role;
    guint16 vendor_id;
    guint16 device_id;
    char *typeofstation;
    char *nameofstation;
    char *aliasname;
    guint16 block_info;
    guint16 block_qualifier;
    gboolean have_block_info=FALSE;
    gboolean have_block_qualifier=FALSE;


    /* SuboptionDevice... */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device, &suboption);
    /* DCPBlockLength */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    /* BlockInfo? */
    if( ((service_id == PNDCP_SERVICE_ID_IDENTIFY) &&  is_response) ||
        ((service_id == PNDCP_SERVICE_ID_HELLO)    && !is_response) ||
        ((service_id == PNDCP_SERVICE_ID_GET)      &&  is_response)) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
        have_block_info=TRUE;
        block_length -= 2;
    }

    /* BlockQualifier? */
    if( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        have_block_qualifier=TRUE;
        block_length -= 2;
    }

    switch(suboption) {
    case(PNDCP_SUBOPTION_DEVICE_MANUF):
        typeofstation = ep_alloc(block_length+1);
        tvb_memcpy(tvb, (guint8 *) typeofstation, offset, block_length);
        typeofstation[block_length] = '\0';
        proto_tree_add_string (tree, hf_pn_dcp_suboption_device_typeofstation, tvb, offset, block_length, typeofstation);
        pn_append_info(pinfo, dcp_item, ", TypeOfStation");
        proto_item_append_text(block_item, "Device/Manufacturer specific");
        if(have_block_qualifier)
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        if(have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        proto_item_append_text(block_item, ", TypeOfStation: \"%s\"", typeofstation);
        offset += block_length;
        break;
    case(PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION):
        nameofstation = ep_alloc(block_length+1);
        tvb_memcpy(tvb, (guint8 *) nameofstation, offset, block_length);
        nameofstation[block_length] = '\0';
        proto_tree_add_string (tree, hf_pn_dcp_suboption_device_nameofstation, tvb, offset, block_length, nameofstation);
        pn_append_info(pinfo, dcp_item, ep_strdup_printf(", NameOfStation:\"%s\"", nameofstation));
        proto_item_append_text(block_item, "Device/NameOfStation");
        if(have_block_qualifier)
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        if(have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        proto_item_append_text(block_item, ", \"%s\"", nameofstation);
        offset += block_length;
        break;
    case(PNDCP_SUBOPTION_DEVICE_DEV_ID):
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_vendor_id, &vendor_id);
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_id, &device_id);
        pn_append_info(pinfo, dcp_item, ", Dev-ID");
        proto_item_append_text(block_item, "Device/Device ID");
        if(have_block_qualifier)
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        if(have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        proto_item_append_text(block_item, ", VendorID: 0x%04x / DeviceID: 0x%04x", vendor_id, device_id);
        break;
    case(PNDCP_SUBOPTION_DEVICE_DEV_ROLE):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_role, &device_role);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_reserved8, NULL);
        pn_append_info(pinfo, dcp_item, ", Dev-Role");
        proto_item_append_text(block_item, "Device/Device Role");
        if(have_block_qualifier)
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        if(have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        if(device_role & 0x01)
            proto_item_append_text(block_item, ", IO-Device");
        if(device_role & 0x02)
            proto_item_append_text(block_item, ", IO-Controller");
        if(device_role & 0x04)
            proto_item_append_text(block_item, ", IO-Multidevice");
        if(device_role & 0x08)
            proto_item_append_text(block_item, ", PN-Supervisor");
        break;
    case(PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS):
        info_str = ep_strdup_printf(", Dev-Options(%u)", block_length/2);
        pn_append_info(pinfo, dcp_item, info_str);
        proto_item_append_text(block_item, "Device/Device Options");
        if(have_block_qualifier)
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        if(have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        proto_item_append_text(block_item, ", %u options", block_length/2);
        for( ; block_length != 0; block_length -= 2) {
            offset = dissect_PNDCP_Option(tvb, offset, pinfo, tree, NULL /*block_item*/, hf_pn_dcp_option, 
                FALSE /* append_col */);
        }
        break;
    case(PNDCP_SUBOPTION_DEVICE_ALIAS_NAME):
        aliasname = ep_alloc(block_length+1);
        tvb_memcpy(tvb, (guint8 *) aliasname, offset, block_length);
        aliasname[block_length] = '\0';
        proto_tree_add_string (tree, hf_pn_dcp_suboption_device_aliasname, tvb, offset, block_length, aliasname);
        pn_append_info(pinfo, dcp_item, ep_strdup_printf(", AliasName:\"%s\"", aliasname));
        proto_item_append_text(block_item, "Device/AliasName");
        if(have_block_qualifier)
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        if(have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        proto_item_append_text(block_item, ", \"%s\"", aliasname);
        offset += block_length;
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length); 
    }

    return offset;
}


/* dissect the "DHCP" suboption */
static int
dissect_PNDCP_Suboption_DHCP(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                                proto_tree *tree, proto_item *block_item, proto_item *dcp_item, 
                                guint8 service_id _U_, gboolean is_response _U_)
{
    guint8 suboption;
    guint16 block_length;
    guint16 block_info;
    guint16 block_qualifier;
    gboolean have_block_info=FALSE;
    gboolean have_block_qualifier=FALSE;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    /* BlockInfo? */
    if( ((service_id == PNDCP_SERVICE_ID_IDENTIFY) &&  is_response) ||
        ((service_id == PNDCP_SERVICE_ID_HELLO)    && !is_response) ||
        ((service_id == PNDCP_SERVICE_ID_GET)      &&  is_response)) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
        have_block_info=TRUE;
        block_length -= 2;
    }

    /* BlockQualifier? */
    if( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        have_block_qualifier=TRUE;
        block_length -= 2;
    }

    switch(suboption) {
    case(PNDCP_SUBOPTION_DHCP_CLIENT_ID):
        pn_append_info(pinfo, dcp_item, ", DHCP client identifier");
        proto_item_append_text(block_item, "DHCP/Client-ID");
        if(have_block_qualifier)
            proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
        if(have_block_info)
            proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        proto_tree_add_item(tree, hf_pn_dcp_suboption_dhcp_device_id, tvb, offset, block_length, ENC_NA);
        offset += block_length;
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length); 
    }

    return offset;
}


/* dissect the "control" suboption */
static int
dissect_PNDCP_Suboption_Control(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                                proto_tree *tree, proto_item *block_item, proto_item *dcp_item, 
                                guint8 service_id _U_, gboolean is_response _U_)
{
    guint8 suboption;
    guint16 block_length;
    guint16 block_qualifier;
    gchar *info_str;
    guint8 block_error;
    proto_item *item = NULL;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_control, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    switch(suboption) {
    case(PNDCP_SUBOPTION_CONTROL_START_TRANS):
        pn_append_info(pinfo, dcp_item, ", Start-Trans");
        proto_item_append_text(block_item, "Control/Start-Transaction");
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        break;
    case(PNDCP_SUBOPTION_CONTROL_END_TRANS):
        pn_append_info(pinfo, dcp_item, ", End-Trans");
        proto_item_append_text(block_item, "Control/End-Transaction");
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        break;
    case(PNDCP_SUBOPTION_CONTROL_SIGNAL):
        pn_append_info(pinfo, dcp_item, ", Signal");
        proto_item_append_text(block_item, "Control/Signal");
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        block_length -= 2;

        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length); 
        break;
    case(PNDCP_SUBOPTION_CONTROL_RESPONSE):
        proto_item_append_text(block_item, "Control/Response");
        offset = dissect_PNDCP_Option(tvb, offset, pinfo, tree, block_item, hf_pn_dcp_suboption_control_response, 
            FALSE /* append_col */);
        block_error = tvb_get_guint8 (tvb, offset);
        if (tree) {
            item = proto_tree_add_uint(tree, hf_pn_dcp_block_error, tvb, offset, 1, block_error);
        }
        offset += 1;
        if(block_error != 0) {
            expert_add_info_format(pinfo, item, PI_RESPONSE_CODE, PI_CHAT,
                "%s", val_to_str(block_error, pn_dcp_block_error, "Unknown"));
        }
        info_str = ep_strdup_printf(", Response(%s)", val_to_str(block_error, pn_dcp_block_error, "Unknown"));
        pn_append_info(pinfo, dcp_item, info_str);
        proto_item_append_text(block_item, ", BlockError: %s", val_to_str(block_error, pn_dcp_block_error, "Unknown"));

        break;
    case(PNDCP_SUBOPTION_CONTROL_FACT_RESET):
        pn_append_info(pinfo, dcp_item, ", Reset FactorySettings");
        proto_item_append_text(block_item, "Control/Reset FactorySettings");
        offset       += 2;
        block_length -= 2;
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, block_length); 
    }

    return offset;
}


/* dissect the "deviceinitaitve" suboption */
static int
dissect_PNDCP_Suboption_DeviceInitiative(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                            guint8 service_id, gboolean is_response)
{
    guint8 suboption;
    guint16 block_length;
    guint16 block_info;
    guint16 block_qualifier;
    guint16 value;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_deviceinitiative, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    pn_append_info(pinfo, dcp_item, ", DeviceInitiative");
    proto_item_append_text(block_item, "DeviceInitiative/DeviceInitiative");

    /* BlockInfo? */
    if( ((service_id == PNDCP_SERVICE_ID_IDENTIFY) &&  is_response) ||
        ((service_id == PNDCP_SERVICE_ID_HELLO)    && !is_response) ||
        ((service_id == PNDCP_SERVICE_ID_GET)      &&  is_response)) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_info, &block_info);
        proto_item_append_text(block_item, ", BlockInfo: %s", val_to_str(block_info, pn_dcp_block_info, "Unknown"));
        block_length -= 2;
    }

    /* BlockQualifier? */
    if( (service_id == PNDCP_SERVICE_ID_SET) && !is_response) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_qualifier, &block_qualifier);
        proto_item_append_text(block_item, ", BlockQualifier: %s", val_to_str(block_qualifier, pn_dcp_block_qualifier, "Unknown"));
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
    guint8 suboption;
    guint16 block_length;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_all, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    switch(suboption) {
    case(255):    /* All */
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
    guint8 suboption;
    guint16 block_length;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_manuf, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    switch(suboption) {
    default:
        pn_append_info(pinfo, dcp_item, ", Manufacturer Specific");
        proto_item_append_text(block_item, "Manufacturer Specific");
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
    guint8 option;
    proto_item *block_item;
    proto_tree *block_tree;
    int ori_offset = offset;

    /* subtree for block */
    block_item = proto_tree_add_none_format(tree, hf_pn_dcp_block, 
        tvb, offset, 0, "Block: ");
    block_tree = proto_item_add_subtree(block_item, ett_pn_dcp_block);


    offset = dissect_pn_uint8(tvb, offset, pinfo, block_tree, hf_pn_dcp_option, &option);

    switch(option) {
    case(PNDCP_OPTION_IP):
        offset = dissect_PNDCP_Suboption_IP(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
        break;
    case(PNDCP_OPTION_DEVICE):
        offset = dissect_PNDCP_Suboption_Device(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
        break;
    case(PNDCP_OPTION_DHCP):
        offset = dissect_PNDCP_Suboption_DHCP(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
        break;
    case(PNDCP_OPTION_CONTROL):
        offset = dissect_PNDCP_Suboption_Control(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
        break;
    case(PNDCP_OPTION_DEVICEINITIATIVE):
        offset = dissect_PNDCP_Suboption_DeviceInitiative(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
        break;
    case(PNDCP_OPTION_ALLSELECTOR):
        offset = dissect_PNDCP_Suboption_All(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
        break;
    case(PNDCP_OPTION_MANUF_X80):
    case(PNDCP_OPTION_MANUF_X81):
    default:
        offset = dissect_PNDCP_Suboption_Manuf(tvb, offset, pinfo, block_tree, block_item, dcp_item, service_id, is_response);
    }

    proto_item_set_len(block_item, offset-ori_offset);

    if((offset-ori_offset) & 1) {
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
    guint8 service_id;
    guint8 service_type;
    guint32 xid;
    guint16 response_delay;
    guint16 data_length;
    int offset = 0;
    gchar *xid_str;
    gboolean is_response = FALSE;


    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hf_pn_dcp_service_id, &service_id);
    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hf_pn_dcp_service_type, &service_type);
    offset = dissect_pn_uint32(tvb, offset, pinfo, tree, hf_pn_dcp_xid, &xid);
    if(service_id == PNDCP_SERVICE_ID_IDENTIFY && service_type == PNDCP_SERVICE_TYPE_REQUEST) {
        /* multicast header */
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_response_delay, &response_delay);
    } else {
        /* unicast header */
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_reserved16, NULL);
    }
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_data_length, &data_length);

    switch(service_id) {
    case(PNDCP_SERVICE_ID_GET):
        pn_append_info(pinfo, dcp_item, "Get");
        break;
    case(PNDCP_SERVICE_ID_SET):
        pn_append_info(pinfo, dcp_item, "Set");
        break;
    case(PNDCP_SERVICE_ID_IDENTIFY):
        pn_append_info(pinfo, dcp_item, "Ident");
        break;
    case(PNDCP_SERVICE_ID_HELLO):
        pn_append_info(pinfo, dcp_item, "Hello");
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_length_remaining(tvb, offset)); 
        return;
    }

    switch(service_type) {
    case(PNDCP_SERVICE_TYPE_REQUEST):
        pn_append_info(pinfo, dcp_item, " Req");
        break;
    case(PNDCP_SERVICE_TYPE_RESPONSE_SUCCESS):
        pn_append_info(pinfo, dcp_item, " Ok ");
        is_response = TRUE;
        break;
    case(PNDCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED):
        pn_append_info(pinfo, dcp_item, " unsupported");
        is_response = TRUE;
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_length_remaining(tvb, offset)); 
        return;
    }

    xid_str = ep_strdup_printf(", Xid:0x%x", xid);
    pn_append_info(pinfo, dcp_item, xid_str);

    /* dissect a number of blocks (depending on the remaining length) */
    while(data_length) {
        int ori_offset = offset;

        if(service_id == PNDCP_SERVICE_ID_GET && service_type == PNDCP_SERVICE_TYPE_REQUEST) {
            /* Selectors */
            offset = dissect_PNDCP_Option(tvb, offset, pinfo, 
                                 tree, dcp_item, hf_pn_dcp_option, TRUE /* append_col */);
        } else {
            offset = dissect_PNDCP_Block(tvb, offset, pinfo, tree, dcp_item, service_id, is_response);
        }
        /* prevent an infinite loop */
        if(offset <= ori_offset || data_length < (offset - ori_offset)) {
            THROW(ReportedBoundsError);
        }
        data_length -= (offset - ori_offset);
    }
}


/* possibly dissect a PN-RT packet (frame ID must be in the appropriate range) */
static gboolean
dissect_PNDCP_Data_heur(tvbuff_t *tvb, 
    packet_info *pinfo, proto_tree *tree)
{
    guint16 u16FrameID;
    proto_item *item = NULL;
    proto_tree *dcp_tree = NULL;


    /* the tvb will NOT contain the frame_id here, so get it from our private data! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

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
        { "ServiceID", "pn_dcp.service_id", FT_UINT8, BASE_DEC, VALS(pn_dcp_service_id), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_service_type,
        { "ServiceType", "pn_dcp.service_type", FT_UINT8, BASE_DEC, VALS(pn_dcp_service_type), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_xid,
        { "Xid", "pn_dcp.xid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_reserved8,
        { "Reserved", "pn_dcp.reserved8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_reserved16,
        { "Reserved", "pn_dcp.reserved16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_response_delay,
        { "ResponseDelay", "pn_dcp.response_delay", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_data_length,
        { "DCPDataLength", "pn_dcp.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_block_length,
        { "DCPBlockLength", "pn_dcp.block_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_option,
        { "Option", "pn_dcp.option", FT_UINT8, BASE_DEC, VALS(pn_dcp_option), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption,
        { "Suboption", "pn_dcp.suboption", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_block_error,
        { "BlockError", "pn_dcp.block_error", FT_UINT8, BASE_DEC, VALS(pn_dcp_block_error), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_block,
        { "Block", "pn_dcp.block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_block_info,
        { "BlockInfo", "pn_dcp.block_info", FT_UINT16, BASE_DEC, VALS(pn_dcp_block_info), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_block_qualifier,
        { "BlockQualifier", "pn_dcp.block_qualifier", FT_UINT16, BASE_DEC, VALS(pn_dcp_block_qualifier), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_ip,
        { "Suboption", "pn_dcp.suboption_ip", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_ip), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_ip_block_info,
        { "BlockInfo", "pn_dcp.suboption_ip_block_info", FT_UINT16, BASE_DEC, VALS(pn_dcp_suboption_ip_block_info), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_ip_ip,
        { "IPaddress", "pn_dcp.subobtion_ip_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_ip_subnetmask,
        { "Subnetmask", "pn_dcp.subobtion_ip_subnetmask", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_ip_standard_gateway,
        { "StandardGateway", "pn_dcp.suboption_ip_standard_gateway", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_dcp_suboption_device,
        { "Suboption", "pn_dcp.suboption_device", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_device), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_device_typeofstation,
        { "TypeOfStation", "pn_dcp.suboption_device_typeofstation", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_device_nameofstation,
        { "NameOfStation", "pn_dcp.suboption_device_nameofstation", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_vendor_id,
        { "VendorID", "pn_dcp.suboption_vendor_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_device_id,
        { "DeviceID", "pn_dcp.suboption_device_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_device_role,
        { "DeviceRoleDetails", "pn_dcp.suboption_device_role", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_device_aliasname,
        { "AliasName", "pn_dcp.suboption_device_aliasname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_dcp_suboption_dhcp,
        { "Suboption", "pn_dcp.suboption_dhcp", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_dhcp), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_dhcp_device_id,
        { "Device ID", "pn_dcp.suboption_dhcp_device_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_pn_dcp_suboption_control,
        { "Suboption", "pn_dcp.suboption_control", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_control), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_suboption_control_response,
        { "Response", "pn_dcp.suboption_control_response", FT_UINT8, BASE_DEC, VALS(pn_dcp_option), 0x0, NULL, HFILL }},

    { &hf_pn_dcp_suboption_deviceinitiative,
        { "Suboption", "pn_dcp.suboption_deviceinitiative", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_deviceinitiative), 0x0, NULL, HFILL }},
    { &hf_pn_dcp_deviceinitiative_value,
        { "DeviceInitiativeValue", "pn_dcp.deviceinitiative_value", FT_UINT16, BASE_DEC, VALS(pn_dcp_deviceinitiative_value), 0x0, NULL, HFILL }},

    { &hf_pn_dcp_suboption_all,
        { "Suboption", "pn_dcp.suboption_all", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_all), 0x0, NULL, HFILL }},

    { &hf_pn_dcp_suboption_manuf,
        { "Suboption", "pn_dcp.suboption_manuf", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_manuf), 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_pn_dcp,
        &ett_pn_dcp_block
    };
    proto_pn_dcp = proto_register_protocol ("PROFINET DCP", "PN-DCP", "pn_dcp");
    proto_register_field_array (proto_pn_dcp, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_pn_dcp (void)
{
    /* register ourself as an heuristic pn-rt payload dissector */
    heur_dissector_add("pn_rt", dissect_PNDCP_Data_heur, proto_pn_dcp);
}
