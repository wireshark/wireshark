/* packet-usb.h
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
 */

#ifndef __PACKET_USB_H__
#define __PACKET_USB_H__

typedef struct _usb_conv_info_t usb_conv_info_t;

/* there is one such structure for each request/response */
typedef struct _usb_trans_info_t {
    guint32 request_in;
    guint32 response_in;
    guint8 requesttype;
    guint8 request;
    union {
        struct {
            guint8 type;
            guint8 index;
        } get_descriptor;
    };


    /* used to pass the interface class from the
     * interface descriptor onto the endpoint
     * descriptors so that we can create a
     * conversation with the appropriate class
     * once we know the endpoint.
     */
    usb_conv_info_t *interface_info;
} usb_trans_info_t;

/* there is one such structure for each device/endpoint conversation */
struct _usb_conv_info_t {
    guint16 class;		/* class for this conversation */
    emem_tree_t *transactions;
    void *masstorage;           /* mass storage data */
    usb_trans_info_t *usb_trans_info; /* pointer to the current transaction */
};


/* This is the endpoint number user for "no endpoint" or the fake endpoint 
 * for the host side since we need two endpoints to manage conversations
 * properly.
 */
#define NO_ENDPOINT 0xffff


#define IF_CLASS_UNKNOWN		0xffff
#define IF_CLASS_FROM_INTERFACE_DESC	0x00
#define IF_CLASS_AUDIO			0x01
#define IF_CLASS_COMMUNICATIONS		0x02
#define IF_CLASS_HID			0x03
#define IF_CLASS_PHYSICAL		0x05
#define IF_CLASS_IMAGE			0x06
#define IF_CLASS_PRINTER		0x07
#define IF_CLASS_MASSTORAGE		0x08
#define IF_CLASS_HUB			0x09
#define IF_CLASS_CDC_DATA		0x0a
#define IF_CLASS_SMART_CARD		0x0b
#define IF_CLASS_CONTENT_SECURITY	0x0d
#define IF_CLASS_VIDEO			0x0e
#define IF_CLASS_DIAGNOSTIC_DEVICE	0xdc
#define IF_CLASS_WIRELESS_CONTROLLER	0xe0
#define IF_CLASS_MISCELLANEOUS		0xef
#define IF_CLASS_APPLICATION_SPECIFIC	0xfe
#define IF_CLASS_VENDOR_SPECIFIC	0xff

#endif
