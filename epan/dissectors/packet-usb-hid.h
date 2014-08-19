/* packet-usb-hid.h
 *
 * USB HID dissector
 * By Adam Nielsen <a.nielsen@shikadi.net> 2009
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_USB_HID_H__
#define __PACKET_USB_HID_H__


int
dissect_usb_hid_get_report_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_conv_info_t *usb_conv_info _U_);

#endif
