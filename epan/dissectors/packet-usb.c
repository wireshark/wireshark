/* packet-usb.c
 *
 * $Id$
 *
 * usb basic dissector
 * By Paolo Abeni <paolo.abeni@email.com>
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
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <string.h>

typedef enum { 
  URB_CONTROL_INPUT,
  URB_CONTROL_OUTPUT,
  URB_ISOCHRONOUS_INPUT,
  URB_ISOCHRONOUS_OUTPUT,
  URB_INTERRUPT_INPUT,
  URB_INTERRUPT_OUTPUT,
  URB_BULK_INPUT,
  URB_BULK_OUTPUT,
  URB_UNKNOWN
} urb_type_t;

typedef struct usb_header {
  guint32 urb_type;  
  guint32 device_address;
  guint32 endpoint_number;
  guint32 setup_packet;
} usb_header_t;

typedef struct usb_setup {
  guint8 bmRequestType;
  guint8 bRequest;
  guint16 wValue;
  guint16 wIndex;
  guint16 wLength;
} usb_setup_t;


/* protocols and header fields */
static int proto_usb = -1;
static int hf_usb_urb_type = -1;
static int hf_usb_device_address = -1;
static int hf_usb_endpoint_number = -1;
static int hf_usb_request_type = -1;
static int hf_usb_request = -1;
static int hf_usb_value = -1;
static int hf_usb_index = -1;
static int hf_usb_length = -1;
static int hf_usb_data = -1;

static gint usb_hdr = -1;
static gint usb_setup_hdr = -1;

static const value_string usb_urb_type_vals[] = {
    {URB_CONTROL_INPUT, "URB_CONTROL_INPUT"},
    {URB_CONTROL_OUTPUT,"URB_CONTROL_OUTPUT"},
    {URB_ISOCHRONOUS_INPUT,"URB_ISOCHRONOUS_INPUT"},
    {URB_ISOCHRONOUS_OUTPUT,"URB_ISOCHRONOUS_OUTPUT"},
    {URB_INTERRUPT_INPUT,"URB_INTERRUPT_INPUT"},
    {URB_INTERRUPT_OUTPUT,"URB_INTERRUPT_OUTPUT"},
    {URB_BULK_INPUT,"URB_BULK_INPUT"},
    {URB_BULK_OUTPUT,"URB_BULK_OUTPUT"},
    {URB_UNKNOWN, "URB_UNKNOWN"},
    {0, NULL}
};

static void
dissect_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent)
{
    int offset = 0;
    int type;
    gboolean setup;
    proto_tree *tree = NULL;
    static guint32 src_addr=0xffffffff, dst_addr=0xffffffff; /* has to be static due to SET_ADDRESS */
    guint32 tmpaddr;
    
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB");

    /* add usb hdr*/    
    if (parent) {
      proto_item *ti = NULL;
      ti = proto_tree_add_protocol_format(parent, proto_usb, tvb, 0, sizeof(usb_header_t), "USB URB");

      tree = proto_item_add_subtree(ti, usb_hdr);
    }

    
    type = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_usb_urb_type, tvb, offset, 4, FALSE);
    offset += 4;

#define USB_ADDR_LEN 4
    proto_tree_add_item(tree, hf_usb_device_address, tvb, offset, 4, FALSE);
    switch(type){
    case URB_CONTROL_INPUT:
    case URB_ISOCHRONOUS_INPUT:
    case URB_INTERRUPT_INPUT:
    case URB_BULK_INPUT:
        src_addr=tvb_get_ntohl(tvb, offset);
        break;
    case URB_CONTROL_OUTPUT:
    case URB_ISOCHRONOUS_OUTPUT:
    case URB_INTERRUPT_OUTPUT:
    case URB_BULK_OUTPUT:
        dst_addr=tvb_get_ntohl(tvb, offset);
        break;
    default:
        break;
    }
    offset += 4;
    SET_ADDRESS(&pinfo->net_src, AT_USB, USB_ADDR_LEN, (char *)&src_addr);
    SET_ADDRESS(&pinfo->src, AT_USB, USB_ADDR_LEN, (char *)&src_addr);
    SET_ADDRESS(&pinfo->net_dst, AT_USB, USB_ADDR_LEN, (char *)&dst_addr);
    SET_ADDRESS(&pinfo->dst, AT_USB, USB_ADDR_LEN, (char *)&dst_addr);

    proto_tree_add_item(tree, hf_usb_endpoint_number, tvb, offset, 4, FALSE);
    offset += 4;
    
    /* check for setup hdr presence */
    setup = tvb_get_ntohl(tvb, offset);
    offset += 4;
    if (setup)
    {
        proto_item *ti = NULL;
        proto_tree *setup_tree = NULL;


        ti = proto_tree_add_protocol_format(parent, proto_usb, tvb, offset, sizeof(usb_setup_t), "URB setup");
        setup_tree = proto_item_add_subtree(ti, usb_setup_hdr);
        
        proto_tree_add_item(setup_tree, hf_usb_request_type, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(setup_tree, hf_usb_request, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(setup_tree, hf_usb_value, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item(setup_tree, hf_usb_index, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item(setup_tree, hf_usb_length, tvb, offset, 2, FALSE);
        offset += 2;
    }
    
    proto_tree_add_item(tree, hf_usb_data, tvb,
        offset, tvb_length_remaining(tvb, offset), FALSE);
}

void
proto_register_usb(void)
{
    static hf_register_info hf[] = {
    
        { &hf_usb_urb_type,
        { "URB type", "usb.urb_type", FT_UINT32, BASE_DEC, 
                VALS(usb_urb_type_vals), 0x0,
                "URB type", HFILL }},

        { &hf_usb_device_address,
        { "Device", "usb.device_address", FT_UINT32, BASE_DEC, NULL, 0x0,
                "USB device address", HFILL }},

        { &hf_usb_endpoint_number,
        { "Endpoint", "usb.endpoint_number", FT_UINT32, BASE_DEC, NULL, 0x0,
                "usb endpoint number", HFILL }},

        { &hf_usb_request_type,
        { "Request Type", "usb.setup.request_type", FT_UINT8, BASE_HEX, NULL, 0x0,
                "", HFILL }},

        { &hf_usb_request,
        { "Request", "usb.setup.request", FT_UINT8, BASE_HEX, NULL, 0x0,
                "", HFILL }},

        { &hf_usb_value,
        { "value", "usb.setup.value", FT_UINT16, BASE_HEX, NULL, 0x0,
                "", HFILL }},

        { &hf_usb_index,
        { "Index", "usb.setup.index", FT_UINT16, BASE_DEC, NULL, 0x0,
                "", HFILL }},

        { &hf_usb_length,
        { "Length", "usb.setup.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                "", HFILL }},
                
        { &hf_usb_data,
        {"Application Data", "usb.data",
            FT_BYTES, BASE_HEX, NULL, 0x0,
            "Payload is application data", HFILL }}
    
    };
    
    static gint *usb_subtrees[] = {
            &usb_hdr,
            &usb_setup_hdr
    };

     
    proto_usb = proto_register_protocol("USB", "USB", "usb");
    proto_register_field_array(proto_usb, hf, array_length(hf));
    proto_register_subtree_array(usb_subtrees, array_length(usb_subtrees));

    
    register_dissector("eth", dissect_usb, proto_usb);
}

void
proto_reg_handoff_usb(void)
{
    dissector_handle_t usb_handle;
    usb_handle = create_dissector_handle(dissect_usb, proto_usb);

    dissector_add("wtap_encap", WTAP_ENCAP_USB, usb_handle);
}
