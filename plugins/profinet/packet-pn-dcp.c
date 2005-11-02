/* packet-pn-dcp.c
 * Routines for PN-DCP (PROFINET Discovery and basic Configuration Protocol) 
 * packet dissection.
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <epan/dissectors/packet-dcerpc.h>

static int proto_pn_dcp = -1;

static int hf_pn_dcp = -1;

static int hf_pn_dcp_service_id = -1;
static int hf_pn_dcp_service_type = -1;
static int hf_pn_dcp_xid = -1;
static int hf_pn_dcp_reserved8 = -1;
static int hf_pn_dcp_reserved16 = -1;
static int hf_pn_dcp_response_delay = -1;
static int hf_pn_dcp_data_length = -1;
static int hf_pn_dcp_block_length = -1;

static int hf_pn_dcp_block = -1;

static int hf_pn_dcp_result = -1;

static int hf_pn_dcp_option = -1;
static int hf_pn_dcp_suboption = -1;
static int hf_pn_dcp_req_status = -1;
static int hf_pn_dcp_res_status = -1;

static int hf_pn_dcp_suboption_ip = -1;
static int hf_pn_dcp_suboption_ip_status = -1;
static int hf_pn_dcp_suboption_ip_ip = -1;
static int hf_pn_dcp_suboption_ip_subnetmask = -1;
static int hf_pn_dcp_suboption_ip_default_router = -1;

static int hf_pn_dcp_suboption_device = -1;
static int hf_pn_dcp_suboption_device_typeofstation = -1;
static int hf_pn_dcp_suboption_device_nameofstation = -1;
static int hf_pn_dcp_suboption_vendor_id = -1;
static int hf_pn_dcp_suboption_device_id = -1;
static int hf_pn_dcp_suboption_device_role = -1;

static int hf_pn_dcp_suboption_dhcp = -1;
static int hf_pn_dcp_suboption_dhcp_device_id = -1;

static int hf_pn_dcp_suboption_lldp = -1;

static int hf_pn_dcp_suboption_control = -1;
static int hf_pn_dcp_suboption_control_status = -1;

static int hf_pn_dcp_suboption_all = -1;

static int hf_pn_dcp_suboption_manuf = -1;

static int hf_pn_dcp_data = -1;


static gint ett_pn_dcp = -1;
static gint ett_pn_dcp_block = -1;

#define FRAME_ID_UC         0xfefd
#define FRAME_ID_MC         0xfefe
#define FRAME_ID_MC_RESP    0xfeff


#define PNDCP_SERVICE_ID_GET        0x03
#define PNDCP_SERVICE_ID_SET        0x04
#define PNDCP_SERVICE_ID_IDENTIFY   0x05

static const value_string pn_dcp_service_id[] = {
	{ 0x00, "reserved" },
	{ 0x01, "Manufacturer specific" },
	{ 0x02, "Manufacturer specific" },
	{ PNDCP_SERVICE_ID_GET, "Get" },
	{ PNDCP_SERVICE_ID_SET, "Set" },
	{ PNDCP_SERVICE_ID_IDENTIFY, "Identify" },
    /* 0x06 - 0xff reserved */
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

static const value_string pn_dcp_result[] = {
	{ 0x00, "Ok" },
	{ 0x01, "Option unsupp." },
	{ 0x02, "Suboption unsupp." },
	{ 0x03, "Suboption not set" },
	{ 0x04, "Manufacturer specific" },
	{ 0x05, "Manufacturer specific" },
	{ 0x06, "Ressource Error" },
    /* all others reserved */
    { 0, NULL }
};

static const value_string pn_dcp_req_status[] = {
	{ 0x0000, "Don't save data permanent" },
	{ 0x0001, "Save data permanent" },
    /*0x0002 - 0xffff reserved */
    { 0, NULL }
};


#define PNDCP_OPTION_IP             0x01
#define PNDCP_OPTION_DEVICE         0x02
#define PNDCP_OPTION_DHCP           0x03
#define PNDCP_OPTION_LLDP           0x04
#define PNDCP_OPTION_CONTROL        0x05
#define PNDCP_OPTION_MANUF_X80      0x80
#define PNDCP_OPTION_MANUF_X81      0x81
#define PNDCP_OPTION_ALLSELECTOR    0xff

static const value_string pn_dcp_option[] = {
	{ 0x00, "reserved" },
	{ PNDCP_OPTION_IP,          "IP" },
	{ PNDCP_OPTION_DEVICE,      "Device properties" },
	{ PNDCP_OPTION_DHCP,        "DHCP" },
	{ PNDCP_OPTION_LLDP,        "LLDP" },
	{ PNDCP_OPTION_CONTROL,     "Control" },
    /*0x06 - 0x7f reserved */
    /*0x80 - 0xfe manufacturer specific */
	{ PNDCP_OPTION_MANUF_X80,   "Manufacturer specific" },
	{ PNDCP_OPTION_MANUF_X81,   "Manufacturer specific" },
	{ PNDCP_OPTION_ALLSELECTOR, "All Selector" },
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

static const value_string pn_dcp_suboption_ip_status[] = {
	{ 0x0000, "IP not set" },
	{ 0x0001, "IP set" },
	{ 0x0002, "IP set by DHCP" },
    /*0x0003 - 0xffff reserved */
    { 0, NULL }
};

#define PNDCP_SUBOPTION_DEVICE_MANUF            0x01
#define PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION    0x02
#define PNDCP_SUBOPTION_DEVICE_DEV_ID           0x03
#define PNDCP_SUBOPTION_DEVICE_DEV_ROLE         0x04
#define PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS      0x05

static const value_string pn_dcp_suboption_device[] = {
	{ 0x00, "Reserved" },
	{ PNDCP_SUBOPTION_DEVICE_MANUF,         "Manufacturer specific (Type of Station)" },
	{ PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION, "Name of Station" },
	{ PNDCP_SUBOPTION_DEVICE_DEV_ID,        "Device ID" },
	{ PNDCP_SUBOPTION_DEVICE_DEV_ROLE,      "Device Role" },
	{ PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS,   "Device Options" },
    /*0x06 - 0xff reserved */
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

static const value_string pn_dcp_suboption_lldp[] = {
    /* currently unknown */
    { 0, NULL }
};

#define PNDCP_SUBOPTION_CONTROL_START_TRANS 0x01
#define PNDCP_SUBOPTION_CONTROL_END_TRANS   0x02
#define PNDCP_SUBOPTION_CONTROL_SIGNAL      0x03
#define PNDCP_SUBOPTION_CONTROL_RESPONSE    0x04

static const value_string pn_dcp_suboption_control[] = {
	{ 0x00, "Reserved" },
	{ PNDCP_SUBOPTION_CONTROL_START_TRANS, "Start Transaction" },
	{ PNDCP_SUBOPTION_CONTROL_END_TRANS, "End Transaction" },
	{ PNDCP_SUBOPTION_CONTROL_SIGNAL, "Signal" },
	{ PNDCP_SUBOPTION_CONTROL_RESPONSE, "Response" },
    /*0x05 - 0xff reserved */
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



/* dissect an 8 bit unsigned integer */
static int
dissect_pn_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                  proto_tree *tree, int hfindex, guint8 *pdata)
{
    guint8 data;

    data = tvb_get_guint8 (tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hfindex, tvb, offset, 1, data);
    }
    if (pdata)
        *pdata = data;
    return offset + 1;
}

/* dissect a 16 bit unsigned integer */
static int
dissect_pn_uint16(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, guint16 *pdata)
{
    guint16 data;

    data = tvb_get_ntohs (tvb, offset);

    if (tree) {
        proto_tree_add_uint(tree, hfindex, tvb, offset, 2, data);
    }
    if (pdata)
        *pdata = data;
    return offset + 2;
}

/* dissect a 32 bit unsigned integer */
static int
dissect_pn_uint32(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, guint32 *pdata)
{
    guint32 data;

    data = tvb_get_ntohl (tvb, offset);

    if (tree) {
        proto_tree_add_uint(tree, hfindex, tvb, offset, 4, data);
    }
    if (pdata)
        *pdata = data;
    return offset+4;
}

/* dissect an IPv4 address */
static int 
dissect_pn_ipv4(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, guint32 *pdata)
{
    guint32 data;

    data = tvb_get_ipv4(tvb, offset);
    if(tree)
        proto_tree_add_ipv4(tree, hfindex, tvb, offset, 4, data);

    if (pdata)
        *pdata = data;

    return offset + 4;
}

/* dissect some padding data (with the given length) */
static int 
dissect_pn_padding(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int length)
{
    proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, length, "data", 
        "Padding: %u byte", length);

    return offset + length;
}

/* append the given info text */
static void
pn_append_info(packet_info *pinfo, proto_item *dcp_item, const char *text)
{
    if (check_col(pinfo->cinfo, COL_INFO))
        col_append_fstr(pinfo->cinfo, COL_INFO, text);

    proto_item_append_text(dcp_item, "%s", text);
}


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
    case(PNDCP_OPTION_LLDP):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_lldp, &suboption);
        val_str = pn_dcp_suboption_lldp;
        break;
    case(PNDCP_OPTION_CONTROL):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_control, &suboption);
        val_str = pn_dcp_suboption_control;
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
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(suboption, val_str, "Unknown"));
    }

    return offset;
}


/* dissect the "IP" suboption */
static int
dissect_PNDCP_Suboption_IP(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item,
                            gboolean is_response)
{
    guint8 suboption;
    guint16 block_length;
    guint16 status;
    guint16 req_status;
    guint32 ip;

    
    offset = dissect_pn_uint8 (tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip, &suboption);
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);

    switch(suboption) {
    case(PNDCP_SUBOPTION_IP_MAC):
        pn_append_info(pinfo, dcp_item, ", MAC");
        proto_item_append_text(block_item, "IP/MAC");

        /* XXX - improve this */
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data(0x%x/0x%x): %d bytes", PNDCP_OPTION_IP, suboption, block_length);
        offset += block_length;
        break;
    case(PNDCP_SUBOPTION_IP_IP):
        pn_append_info(pinfo, dcp_item, ", IP");
        proto_item_append_text(block_item, "IP/IP");

        if(is_response) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_status, &status);
            proto_item_append_text(block_item, ", Status: %s", val_to_str(status, pn_dcp_suboption_ip_status, "Unknown"));
        } else {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_req_status, &req_status);
            proto_item_append_text(block_item, ", Status: %s", val_to_str(req_status, pn_dcp_req_status, "Unknown"));
        }

        /* ip address */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_ip, &ip);
        proto_item_append_text(block_item, ", IP: %s", ip_to_str((guint8*)&ip));

        /* subnetmask */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_subnetmask, &ip);
        proto_item_append_text(block_item, ", Subnet: %s", ip_to_str((guint8*)&ip));

        /* default router */
        offset = dissect_pn_ipv4(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_ip_default_router, &ip);
        proto_item_append_text(block_item, ", Router: %s", ip_to_str((guint8*)&ip));
        break;
    default:
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data(0x%x/0x%x): %d bytes", PNDCP_OPTION_IP, suboption, block_length);
        offset += block_length;
    }

    return offset;
}


/* dissect the "device" suboption */
static int
dissect_PNDCP_Suboption_Device(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                               proto_tree *tree, proto_item *block_item, proto_item *dcp_item, 
                               int length, gboolean is_response)
{
    guint8 suboption;
    guint16 block_length;
    gchar *info_str;
    guint8 device_role;
    guint16 vendor_id;
    guint16 device_id;
    guint8* typeofstation;
    guint8* nameofstation;
    guint16 status;

    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device, &suboption);
    length--;

    if(length) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);
        if(is_response) {
            offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_res_status, &status);
            block_length -= 2;
        }
    }

    switch(suboption) {
    case(PNDCP_SUBOPTION_DEVICE_MANUF):
/*        if(is_response) {*/
            typeofstation = g_malloc(block_length+1);
            tvb_memcpy(tvb, typeofstation, offset, block_length);
            typeofstation[block_length] = '\0';
            proto_tree_add_string (tree, hf_pn_dcp_suboption_device_typeofstation, tvb, offset, block_length, typeofstation);
            pn_append_info(pinfo, dcp_item, ", TypeOfStation");
            proto_item_append_text(block_item, "Device/Manufacturer specific");
            if(is_response)
                proto_item_append_text(block_item, ", Status: %u", status);
            proto_item_append_text(block_item, ", TypeOfStation: \"%s\"", typeofstation);
            g_free(typeofstation);
            offset += block_length;
/*        } else {
            pn_append_info(pinfo, dcp_item, ", TypeOfStation");
            proto_item_append_text(block_item, "Device/Manufacturer specific(TypeOfStation)");
            offset += block_length;
        }*/
        break;
    case(PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION):
        nameofstation = g_malloc(block_length+1);
        tvb_memcpy(tvb, nameofstation, offset, block_length);
        nameofstation[block_length] = '\0';
        proto_tree_add_string (tree, hf_pn_dcp_suboption_device_nameofstation, tvb, offset, block_length, nameofstation);
        pn_append_info(pinfo, dcp_item, ", NameOfStation");
        proto_item_append_text(block_item, "Device/NameOfStation");
        if(is_response)
            proto_item_append_text(block_item, ", Status: %u", status);
        proto_item_append_text(block_item, ", \"%s\"", nameofstation);
        g_free(nameofstation);
        offset += block_length;
        break;
    case(PNDCP_SUBOPTION_DEVICE_DEV_ID):
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_vendor_id, &vendor_id);
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_id, &device_id);
        pn_append_info(pinfo, dcp_item, ", Dev-ID");
        proto_item_append_text(block_item, "Device/Device ID");
        if(is_response)
            proto_item_append_text(block_item, ", Status: %u", status);
        proto_item_append_text(block_item, ", 0x%04x/0x%04x", vendor_id, device_id);
        break;
    case(PNDCP_SUBOPTION_DEVICE_DEV_ROLE):
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_device_role, &device_role);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_reserved8, NULL);
        pn_append_info(pinfo, dcp_item, ", Dev-Role");
        proto_item_append_text(block_item, "Device/Device Role");
        if(is_response)
            proto_item_append_text(block_item, ", Status: %u", status);
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
        info_str = g_strdup_printf(", Dev-Options(%u)", block_length/2);
        pn_append_info(pinfo, dcp_item, info_str);
        g_free(info_str);
        proto_item_append_text(block_item, "Device/Device Options");
        if(is_response)
            proto_item_append_text(block_item, ", Status: %u", status);
        proto_item_append_text(block_item, ", %u options", block_length/2);
        for( ; block_length != 0; block_length -= 2) {
            offset = dissect_PNDCP_Option(tvb, offset, pinfo, tree, NULL /*block_item*/, hf_pn_dcp_option, 
                FALSE /* append_col */);
        }
        break;
    default:
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data(0x%x/0x%x): %d bytes", PNDCP_OPTION_DEVICE, suboption, block_length);
        offset += block_length;
    }

    return offset;
}


/* dissect the "DHCP" suboption */
static int
dissect_PNDCP_Suboption_DHCP(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                                proto_tree *tree, proto_item *block_item, proto_item *dcp_item, 
								int length)
{
    /*guint8 result;*/
    guint8 suboption;
    guint16 block_length;
    /*gchar *info_str;*/
    /*guint16 status;*/


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_dhcp, &suboption);
    length--;

    if(length) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);
    }

    switch(suboption) {
	case(PNDCP_SUBOPTION_DHCP_CLIENT_ID):
        pn_append_info(pinfo, dcp_item, ", DHCP client identifier");
        proto_item_append_text(block_item, "DHCP/Client-ID");
        proto_tree_add_item(tree, hf_pn_dcp_suboption_dhcp_device_id, tvb, offset, block_length, FALSE);
        offset += block_length;
		break;
    default:
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data(0x%x/0x%x): %d bytes", PNDCP_OPTION_DHCP, suboption, block_length);
        offset += block_length;
    }

    return offset;
}


/* dissect the "control" suboption */
static int
dissect_PNDCP_Suboption_Control(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                                proto_tree *tree, proto_item *block_item, proto_item *dcp_item, int length)
{
    guint8 result;
    guint8 suboption;
    guint16 block_length;
    gchar *info_str;
    guint16 status;


    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_control, &suboption);
    length--;

    if(length) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);
    }

    switch(suboption) {
    case(PNDCP_SUBOPTION_CONTROL_START_TRANS):
        pn_append_info(pinfo, dcp_item, ", Start-Trans");
        proto_item_append_text(block_item, "Control/Start-Transaction");
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_res_status, &status);
        break;
    case(PNDCP_SUBOPTION_CONTROL_END_TRANS):
        pn_append_info(pinfo, dcp_item, ", End-Trans");
        proto_item_append_text(block_item, "Control/End-Transaction");
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_res_status, &status);
        break;
    case(PNDCP_SUBOPTION_CONTROL_SIGNAL):
        pn_append_info(pinfo, dcp_item, ", Signal");
        proto_item_append_text(block_item, "Control/Signal");
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_res_status, &status);
        block_length -= 2;

        /* XXX - improve this */
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data: %d bytes", block_length);
        offset += block_length;
        break;
    case(PNDCP_SUBOPTION_CONTROL_RESPONSE):
        proto_item_append_text(block_item, "Control/Response");
        offset = dissect_PNDCP_Option(tvb, offset, pinfo, tree, block_item, hf_pn_dcp_suboption_control_status, 
            FALSE /* append_col */);
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_result, &result);
        length = 0;
        info_str = g_strdup_printf(", Response(%s)", val_to_str(result, pn_dcp_result, "Unknown"));
        pn_append_info(pinfo, dcp_item, info_str);
        g_free(info_str);
        proto_item_append_text(block_item, ", Result: %s", val_to_str(result, pn_dcp_result, "Unknown"));
        break;
    default:
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data(0x%x/0x%x): %d bytes", PNDCP_OPTION_CONTROL, suboption, block_length);
        offset += block_length;
    }

    return offset;
}


/* dissect the "all" suboption */
static int
dissect_PNDCP_Suboption_All(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item, int length)
{
    guint8 suboption;
    guint16 block_length;

    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_all, &suboption);
    length--;

    if(length) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);
        length-=2;
    }

    switch(suboption) {
    case(255):    /* All */
        pn_append_info(pinfo, dcp_item, ", All");
        proto_item_append_text(block_item, "All/All");
        break;
    default:
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data(0x%x/0x%x): %d bytes", PNDCP_OPTION_ALLSELECTOR, suboption, block_length);
        offset += block_length;
    }

    return offset;
}


/* dissect the "manufacturer" suboption */
static int
dissect_PNDCP_Suboption_Manuf(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                            proto_tree *tree, proto_item *block_item, proto_item *dcp_item, int length)
{
    guint8 suboption;
    guint16 block_length;

    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_dcp_suboption_manuf, &suboption);
    length--;

    if(length) {
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_dcp_block_length, &block_length);
        length-=2;
    }

    switch(suboption) {
    default:
        pn_append_info(pinfo, dcp_item, ", Manufacturer Specific");
        proto_item_append_text(block_item, "Manufacturer Specific");
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, block_length, "data", 
            "Block data: %d bytes", block_length);
        offset += block_length;
    }

    return offset;
}


/* dissect one DCP block */
static int
dissect_PNDCP_Block(tvbuff_t *tvb, int offset, packet_info *pinfo, 
                    proto_tree *tree, proto_item *dcp_item, 
                    int length, gboolean is_response)
{
    guint8 option;
    guint8 suboption;
    proto_item *block_item;
    proto_tree *block_tree;
    guint16 block_length;

    block_length = tvb_get_ntohs(tvb, offset + 2) + 4;
    if(block_length > length) 
        block_length = length;

    /* subtree for block */
	block_item = proto_tree_add_none_format(tree, hf_pn_dcp_block, 
		tvb, offset, block_length, "Block: ");
	block_tree = proto_item_add_subtree(block_item, ett_pn_dcp_block);


    offset = dissect_pn_uint8(tvb, offset, pinfo, block_tree, hf_pn_dcp_option, &option);
    length--;

    switch(option) {
    case(PNDCP_OPTION_IP):
        offset = dissect_PNDCP_Suboption_IP(tvb, offset, pinfo, block_tree, block_item, dcp_item, is_response);
        break;
    case(PNDCP_OPTION_DEVICE):
        offset = dissect_PNDCP_Suboption_Device(tvb, offset, pinfo, block_tree, block_item, dcp_item, length, is_response);
        break;
    case(PNDCP_OPTION_DHCP):
        offset = dissect_PNDCP_Suboption_DHCP(tvb, offset, pinfo, block_tree, block_item, dcp_item, length);
        break;
    case(PNDCP_OPTION_LLDP):
        /* XXX - improve this */
        offset = dissect_pn_uint8(tvb, offset, pinfo, block_tree, hf_pn_dcp_suboption_lldp, &suboption);
        break;
    case(PNDCP_OPTION_CONTROL):
        offset = dissect_PNDCP_Suboption_Control(tvb, offset, pinfo, block_tree, block_item, dcp_item, length);
        break;
    case(PNDCP_OPTION_ALLSELECTOR):
        offset = dissect_PNDCP_Suboption_All(tvb, offset, pinfo, block_tree, block_item, dcp_item, length);
        break;
    case(PNDCP_OPTION_MANUF_X80):
    case(PNDCP_OPTION_MANUF_X81):
    default:
        offset = dissect_PNDCP_Suboption_Manuf(tvb, offset, pinfo, block_tree, block_item, dcp_item, length);
    }

    if(block_length & 1) {
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
    default:
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, tvb_length_remaining(tvb, offset), "data", 
            "PN-DCP Unknown service ID %u, Data: %d bytes", service_id, tvb_length_remaining(tvb, offset));
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
        proto_tree_add_string_format(tree, hf_pn_dcp_data, tvb, offset, tvb_length_remaining(tvb, offset), "data", 
            "PN-DCP Unknown service type %u, Data: %d bytes", service_type, tvb_length_remaining(tvb, offset));
        return;
    }

    xid_str = g_strdup_printf(", Xid:0x%x", xid);
    pn_append_info(pinfo, dcp_item, xid_str);
    g_free(xid_str);

    /* dissect a number of blocks (depending on the remaining length) */
    while(data_length) {
        int ori_offset = offset;
        if(service_id == PNDCP_SERVICE_ID_GET && service_type == PNDCP_SERVICE_TYPE_REQUEST) {
            /* Selectors */
            offset = dissect_PNDCP_Option(tvb, offset, pinfo, 
                                 tree, dcp_item, hf_pn_dcp_option, TRUE /* append_col */);
        } else {
            offset = dissect_PNDCP_Block(tvb, offset, pinfo, tree, dcp_item, data_length, is_response);
        }
        ori_offset= offset - ori_offset;
        data_length -= ori_offset;
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
	if (u16FrameID < FRAME_ID_UC || u16FrameID > FRAME_ID_MC_RESP) {
        /* we are not interested in this packet */
        return FALSE;
    }

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PN-DCP");
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_str(pinfo->cinfo, COL_INFO, "");

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
	{ &hf_pn_dcp,
		{ "PROFINET DCP", "pn_dcp", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_service_id,
		{ "Service-ID", "pn_dcp.service_id", FT_UINT8, BASE_DEC, VALS(pn_dcp_service_id), 0x0, "", HFILL }},
	{ &hf_pn_dcp_service_type,
		{ "Service-Type", "pn_dcp.service_type", FT_UINT8, BASE_DEC, VALS(pn_dcp_service_type), 0x0, "", HFILL }},
	{ &hf_pn_dcp_xid,
		{ "xid", "pn_dcp.xid", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_reserved8,
		{ "Reserved", "pn_dcp.reserved8", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_reserved16,
		{ "Reserved", "pn_dcp.reserved16", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_response_delay,
		{ "ResponseDelay", "pn_dcp.response_delay", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_data_length,
		{ "DCPDataLength", "pn_dcp.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_block_length,
		{ "DataBlockLength", "pn_dcp.block_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_option,
		{ "Option", "pn_dcp.option", FT_UINT8, BASE_DEC, VALS(pn_dcp_option), 0x0, "", HFILL }},
	{ &hf_pn_dcp_suboption,
		{ "Suboption", "pn_dcp.suboption", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_result,
		{ "Result", "pn_dcp.result", FT_UINT8, BASE_DEC, VALS(pn_dcp_result), 0x0, "", HFILL }},
	{ &hf_pn_dcp_block,
		{ "Block", "pn_dcp.block", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_req_status,
		{ "Status", "pn_dcp.req_status", FT_UINT16, BASE_DEC, VALS(pn_dcp_req_status), 0x0, "", HFILL }},
	{ &hf_pn_dcp_res_status,
		{ "ResponseStatus", "pn_dcp.res_status", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_ip,
		{ "Suboption", "pn_dcp.suboption_ip", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_ip), 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_ip_status,
		{ "Status", "pn_dcp.suboption_ip_status", FT_UINT16, BASE_DEC, VALS(pn_dcp_suboption_ip_status), 0x0, "", HFILL }},
	{ &hf_pn_dcp_suboption_ip_ip,
		{ "IPaddress", "pn_dcp.subobtion_ip_ip", FT_IPv4, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_suboption_ip_subnetmask,
		{ "Subnetmask", "pn_dcp.subobtion_ip_subnetmask", FT_IPv4, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_dcp_suboption_ip_default_router,
		{ "Default-router", "pn_dcp.subobtion_ip_default_router", FT_IPv4, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_pn_dcp_suboption_device,
		{ "Suboption", "pn_dcp.suboption_device", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_device), 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_device_typeofstation,
		{ "TypeOfStation", "pn_dcp.suboption_device_typeofstation", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_device_nameofstation,
		{ "NameOfStation", "pn_dcp.suboption_device_nameofstation", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_vendor_id,
		{ "VendorID", "pn_dcp.suboption_vendor_id", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_device_id,
		{ "DeviceID", "pn_dcp.suboption_device_id", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_device_role,
		{ "Device-role", "pn_dcp.suboption_device_role", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_pn_dcp_suboption_dhcp,
		{ "Suboption", "pn_dcp.suboption_dhcp", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_dhcp), 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_dhcp_device_id,
		{ "Device ID", "pn_dcp.suboption_dhcp_device_id", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_pn_dcp_suboption_lldp,
		{ "Suboption", "pn_dcp.suboption_lldp", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_lldp), 0x0, "", HFILL }},

    { &hf_pn_dcp_suboption_control,
		{ "Suboption", "pn_dcp.suboption_control", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_control), 0x0, "", HFILL }},
    { &hf_pn_dcp_suboption_control_status,
		{ "ResponseStatus", "pn_dcp.suboption_control_status", FT_UINT8, BASE_DEC, VALS(pn_dcp_option), 0x0, "", HFILL }},

    { &hf_pn_dcp_suboption_all,
		{ "Suboption", "pn_dcp.suboption_all", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_all), 0x0, "", HFILL }},

    { &hf_pn_dcp_suboption_manuf,
		{ "Suboption", "pn_dcp.suboption_manuf", FT_UINT8, BASE_DEC, VALS(pn_dcp_suboption_manuf), 0x0, "", HFILL }},

    { &hf_pn_dcp_data,
      { "Undecoded Data", "pn_dcp.data", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},
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
