/* packet-s7comm.h
 *
 * Author:      Thomas Wiens, 2014 (th.wiens@gmx.de)
 * Description: Wireshark dissector for S7-Communication
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __PACKET_S7COMM_H__
#define __PACKET_S7COMM_H__

/**************************************************************************
 * Returnvalues of an item response
 */
#define S7COMM_ITEM_RETVAL_RESERVED             0x00
#define S7COMM_ITEM_RETVAL_DATA_HW_FAULT        0x01
#define S7COMM_ITEM_RETVAL_DATA_ACCESS_FAULT    0x03
#define S7COMM_ITEM_RETVAL_DATA_OUTOFRANGE      0x05        /* the desired address is beyond limit for this PLC */
#define S7COMM_ITEM_RETVAL_DATA_NOT_SUP         0x06        /* Type is not supported */
#define S7COMM_ITEM_RETVAL_DATA_SIZEMISMATCH    0x07        /* Data type inconsistent */
#define S7COMM_ITEM_RETVAL_DATA_ERR             0x0a        /* the desired item is not available in the PLC, e.g. when trying to read a non existing DB*/
#define S7COMM_ITEM_RETVAL_DATA_OK              0xff

/**************************************************************************
 * Names of userdata subfunctions in group 4 (CPU functions)
 */
#define S7COMM_UD_SUBF_CPU_READSZL          0x01
#define S7COMM_UD_SUBF_CPU_MSGS             0x02
#define S7COMM_UD_SUBF_CPU_DIAGMSG          0x03
#define S7COMM_UD_SUBF_CPU_ALARM8_IND       0x05
#define S7COMM_UD_SUBF_CPU_NOTIFY_IND       0x06
#define S7COMM_UD_SUBF_CPU_ALARM8LOCK       0x07
#define S7COMM_UD_SUBF_CPU_ALARM8UNLOCK     0x08
#define S7COMM_UD_SUBF_CPU_ALARMACK         0x0b
#define S7COMM_UD_SUBF_CPU_ALARMACK_IND     0x0c
#define S7COMM_UD_SUBF_CPU_ALARM8LOCK_IND   0x0d
#define S7COMM_UD_SUBF_CPU_ALARM8UNLOCK_IND 0x0e
#define S7COMM_UD_SUBF_CPU_ALARMSQ_IND      0x11
#define S7COMM_UD_SUBF_CPU_ALARMS_IND       0x12
#define S7COMM_UD_SUBF_CPU_ALARMQUERY       0x13
#define S7COMM_UD_SUBF_CPU_NOTIFY8_IND      0x16

/**************************************************************************
 * Names of types in userdata parameter part
 */
#define S7COMM_UD_TYPE_PUSH                 0x0
#define S7COMM_UD_TYPE_REQ                  0x4
#define S7COMM_UD_TYPE_RES                  0x8

extern const value_string s7comm_item_return_valuenames[];

guint32 s7comm_decode_ud_cpu_diagnostic_message(tvbuff_t *tvb, packet_info *pinfo, gboolean add_info_to_col, proto_tree *data_tree, guint32 offset);

#endif

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
