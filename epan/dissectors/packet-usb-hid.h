/* packet-usb-hid.h
 *
 * USB HID dissector
 * By Adam Nielsen <a.nielsen@shikadi.net> 2009
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_USB_HID_H__
#define __PACKET_USB_HID_H__


int
dissect_usb_hid_get_report_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, urb_info_t *urb _U_);

#endif
