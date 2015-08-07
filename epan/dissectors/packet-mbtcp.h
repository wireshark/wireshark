/* packet-mbtcp.h
 *
 * Routines for Modbus/TCP dissection
 * By Riaan Swart <rswart@cs.sun.ac.za>
 * Copyright 2001, Institute for Applied Computer Science
 *                      University of Stellenbosch
 *
 * See http://www.modbus.org/ for information on Modbus/TCP.
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
#define PORT_MBTCP        502    /* Modbus/TCP located on port 502, with IANA registration */
#define PORT_MBRTU        0    /* Modbus RTU over TCP does not have a standard port, default to zero */

/* Modbus protocol function codes */
#define READ_COILS                  1
#define READ_DISCRETE_INPUTS        2
#define READ_HOLDING_REGS           3
#define READ_INPUT_REGS             4
#define WRITE_SINGLE_COIL           5
#define WRITE_SINGLE_REG            6
#define READ_EXCEPT_STAT            7
#define DIAGNOSTICS                 8
#define GET_COMM_EVENT_CTRS         11
#define GET_COMM_EVENT_LOG          12
#define WRITE_MULT_COILS            15
#define WRITE_MULT_REGS             16
#define REPORT_SLAVE_ID             17
#define READ_FILE_RECORD            20
#define WRITE_FILE_RECORD           21
#define MASK_WRITE_REG              22
#define READ_WRITE_REG              23
#define READ_FIFO_QUEUE             24
#define ENCAP_INTERFACE_TRANSP      43
#define UNITY_SCHNEIDER             90

/* Modbus protocol exception codes */
#define ILLEGAL_FUNCTION            0x01
#define ILLEGAL_ADDRESS             0x02
#define ILLEGAL_VALUE               0x03
#define SLAVE_FAILURE               0x04
#define ACKNOWLEDGE                 0x05
#define SLAVE_BUSY                  0x06
#define MEMORY_ERR                  0x08
#define GATEWAY_UNAVAILABLE         0x0a
#define GATEWAY_TRGT_FAIL           0x0b

/* Modbus diagnostic subfunction codes */
#define RETURN_QUERY_DATA                 0x00
#define RESTART_COMMUNICATION_OPTION      0x01
#define RETURN_DIAGNOSTIC_REGISTER        0x02
#define CHANGE_ASCII_INPUT_DELIMITER      0x03
#define FORCE_LISTEN_ONLY_MODE            0x04
#define CLEAR_COUNTERS_AND_DIAG_REG       0x0A
#define RETURN_BUS_MESSAGE_COUNT          0x0B
#define RETURN_BUS_COMM_ERROR_COUNT       0x0C
#define RETURN_BUS_EXCEPTION_ERROR_COUNT  0x0D
#define RETURN_SLAVE_MESSAGE_COUNT        0x0E
#define RETURN_SLAVE_NO_RESPONSE_COUNT    0x0F
#define RETURN_SLAVE_NAK_COUNT            0x10
#define RETURN_SLAVE_BUSY_COUNT           0x11
#define RETURN_BUS_CHAR_OVERRUN_COUNT     0x12
#define CLEAR_OVERRUN_COUNTER_AND_FLAG    0x14



/* Encapsulation Interface codes */
#define CANOPEN_REQ_RESP   0x0D
#define READ_DEVICE_ID     0x0E

/* Event byte codes */
#define REMOTE_DEVICE_RECV_EVENT_MASK     0x80
#define REMOTE_DEVICE_SEND_EVENT_MASK     0xc0
#define REMOTE_DEVICE_SEND_EVENT_VALUE    0x40

/* return codes of function classifying packets as query/response */
#define QUERY_PACKET            0
#define RESPONSE_PACKET         1
#define CANNOT_CLASSIFY         2

#define MODBUS_PROTOCOL_ID      0

/* Preferences for Modbus/TCP Dissector */
#define MODBUS_PREF_REGISTER_FORMAT_UINT16          0
#define MODBUS_PREF_REGISTER_FORMAT_UINT32          1
#define MODBUS_PREF_REGISTER_FORMAT_IEEE_FLOAT      2
#define MODBUS_PREF_REGISTER_FORMAT_MODICON_FLOAT   3
#define MODBUS_PREF_REGISTER_FORMAT_INT16           4
#define MODBUS_PREF_REGISTER_FORMAT_INT32           5

typedef struct {
    guint32 fnum;
    guint8  function_code;
    guint16 base_address;
    guint16 num_reg;
} modbus_request_info_t;

/* List contains request data  */
typedef struct {
    wmem_list_t *modbus_request_frame_data;
    gint        register_format;
} modbus_conversation;

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
