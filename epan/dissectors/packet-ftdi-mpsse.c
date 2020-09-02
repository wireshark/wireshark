/* packet-ftdi-mpsse.c
 * Routines for FTDI Multi-Protocol Synchronous Serial Engine dissection
 *
 * Copyright 2020 Tomasz Mon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/str_util.h>
#include "packet-ftdi-ft.h"

static int proto_ftdi_mpsse = -1;

static gint hf_mpsse_command = -1;
/* Data Shifting commands bits (b0-b6 are relevant only if b7 is 0) */
static gint hf_mpsse_command_b0 = -1;
static gint hf_mpsse_command_b1 = -1;
static gint hf_mpsse_command_b2 = -1;
static gint hf_mpsse_command_b3 = -1;
static gint hf_mpsse_command_b4 = -1;
static gint hf_mpsse_command_b5 = -1;
static gint hf_mpsse_command_b6 = -1;
static gint hf_mpsse_command_b7 = -1;
static gint hf_mpsse_command_with_parameters = -1;
static gint hf_mpsse_bad_command_error = -1;
static gint hf_mpsse_bad_command_code = -1;
static gint hf_mpsse_response = -1;
static gint hf_mpsse_command_in = -1;
static gint hf_mpsse_response_in = -1;
static gint hf_mpsse_length_uint8 = -1;
static gint hf_mpsse_length_uint16 = -1;
static gint hf_mpsse_bytes_out = -1;
static gint hf_mpsse_bytes_in = -1;
static gint hf_mpsse_bits_out = -1;
static gint hf_mpsse_bits_in = -1;
static gint hf_mpsse_value = -1;
static gint hf_mpsse_value_b0 = -1;
static gint hf_mpsse_value_b1 = -1;
static gint hf_mpsse_value_b2 = -1;
static gint hf_mpsse_value_b3 = -1;
static gint hf_mpsse_value_b4 = -1;
static gint hf_mpsse_value_b5 = -1;
static gint hf_mpsse_value_b6 = -1;
static gint hf_mpsse_value_b7 = -1;
static gint hf_mpsse_direction = -1;
static gint hf_mpsse_direction_b0 = -1;
static gint hf_mpsse_direction_b1 = -1;
static gint hf_mpsse_direction_b2 = -1;
static gint hf_mpsse_direction_b3 = -1;
static gint hf_mpsse_direction_b4 = -1;
static gint hf_mpsse_direction_b5 = -1;
static gint hf_mpsse_direction_b6 = -1;
static gint hf_mpsse_direction_b7 = -1;
static gint hf_mpsse_cpumode_address_short = -1;
static gint hf_mpsse_cpumode_address_extended = -1;
static gint hf_mpsse_cpumode_data = -1;
static gint hf_mpsse_clk_divisor = -1;
static gint hf_mpsse_open_drain_enable_low = -1;
static gint hf_mpsse_open_drain_enable_low_b0 = -1;
static gint hf_mpsse_open_drain_enable_low_b1 = -1;
static gint hf_mpsse_open_drain_enable_low_b2 = -1;
static gint hf_mpsse_open_drain_enable_low_b3 = -1;
static gint hf_mpsse_open_drain_enable_low_b4 = -1;
static gint hf_mpsse_open_drain_enable_low_b5 = -1;
static gint hf_mpsse_open_drain_enable_low_b6 = -1;
static gint hf_mpsse_open_drain_enable_low_b7 = -1;
static gint hf_mpsse_open_drain_enable_high = -1;
static gint hf_mpsse_open_drain_enable_high_b0 = -1;
static gint hf_mpsse_open_drain_enable_high_b1 = -1;
static gint hf_mpsse_open_drain_enable_high_b2 = -1;
static gint hf_mpsse_open_drain_enable_high_b3 = -1;
static gint hf_mpsse_open_drain_enable_high_b4 = -1;
static gint hf_mpsse_open_drain_enable_high_b5 = -1;
static gint hf_mpsse_open_drain_enable_high_b6 = -1;
static gint hf_mpsse_open_drain_enable_high_b7 = -1;

static gint ett_ftdi_mpsse = -1;
static gint ett_mpsse_command = -1;
static gint ett_mpsse_command_with_parameters = -1;
static gint ett_mpsse_response_data = -1;
static gint ett_mpsse_value = -1;
static gint ett_mpsse_direction = -1;
static gint ett_mpsse_open_drain_enable = -1;
static gint ett_mpsse_skipped_response_data = -1;

static expert_field ei_undecoded = EI_INIT;
static expert_field ei_response_without_command = EI_INIT;
static expert_field ei_skipped_response_data = EI_INIT;
static expert_field ei_reassembly_unavailable = EI_INIT;

static dissector_handle_t ftdi_mpsse_handle;

/* Commands expecting response add command_data_t entry to a list. The list is created when first command
 * appears on MPSSE instance TX or when previously created list has matched responses to all entries.
 * When a new list is created, head pointer is inserted into both tx_command_info and rx_command_info tree.
 *
 * When RX packet is dissected, it obtains the pointer to a list (if there isn't any then the capture is
 * incomplete/malformed and ei_response_without_command is presented to the user). The RX dissection code
 * matches commands with responses and updates the response_in_packet and is_response_set flag. When next
 * RX packet is being dissected, it skips all the command_data_t entries that have is_response_set flag set.
 * To reduce the effective list length that needs to be traversed, a pointer to the first element that does
 * not have is_response_set flag set, is added to rx_command_info with the current packet number in the key.
 *
 * After first pass, RX packets always obtain relevant command_data_t entry without traversing the list.
 * If there wasn't a separate tree TX packets (tx_command_info), TX packet dissection would have to to
 * traverse the list from the pointer obtained from rx_command_info. In normal conditions the number of
 * entries to skip in such case is low. However, when the capture file has either:
 *   * A lot of TX packets with commands expecting response but no RX packets, or
 *   * Bad Command in TX packet that does not have matching Bad Command response in RX data
 * then the traversal time in TX packet dissection becomes significant. To bring performance to acceptable
 * levels, tx_command_info tree is being used. It contains pointers to the same list as rx_command_info but
 * allows TX dissection to obtain the relevant command_data_t entry without traversing the list.
 */
static wmem_tree_t *rx_command_info = NULL;
static wmem_tree_t *tx_command_info = NULL;

typedef struct _command_data command_data_t;

struct _command_data {
    ftdi_mpsse_info_t  mpsse_info;

    /* TRUE if complete command parameters were not dissected yet */
    gboolean           preliminary;
    /* TRUE if response_in_packet has been set (response packet is known) */
    gboolean           is_response_set;
    guint8             cmd;
    gint32             response_length;
    guint32            command_in_packet;
    guint32            response_in_packet;

    command_data_t    *next;
};

void proto_register_ftdi_mpsse(void);

#define BAD_COMMAND_SYNC_CODE                      0xFA

#define CMD_SET_DATA_BITS_LOW_BYTE                 0x80
#define CMD_READ_DATA_BITS_LOW_BYTE                0x81
#define CMD_SET_DATA_BITS_HIGH_BYTE                0x82
#define CMD_READ_DATA_BITS_HIGH_BYTE               0x83
#define CMD_CLOCK_SET_DIVISOR                      0x86
#define CMD_CLOCK_N_BITS                           0x8E
#define CMD_CLOCK_N_TIMES_8_BITS                   0x8F
#define CMD_CPUMODE_READ_SHORT_ADDR                0x90
#define CMD_CPUMODE_READ_EXT_ADDR                  0x91
#define CMD_CPUMODE_WRITE_SHORT_ADDR               0x92
#define CMD_CPUMODE_WRITE_EXT_ADDR                 0x93
#define CMD_CLOCK_N_TIMES_8_BITS_OR_UNTIL_L1_HIGH  0x9C
#define CMD_CLOCK_N_TIMES_8_BITS_OR_UNTIL_L1_LOW   0x9D
#define CMD_IO_OPEN_DRAIN_ENABLE                   0x9E

static const value_string command_vals[] = {
    {0x10, "Clock Data Bytes Out on + ve clock edge MSB first(no read) [Use if CLK starts at '1']"},
    {0x11, "Clock Data Bytes Out on -ve clock edge MSB first (no read) [Use if CLK starts at '0']"},
    {0x12, "Clock Data Bits Out on +ve clock edge MSB first (no read) [Use if CLK starts at '1']"},
    {0x13, "Clock Data Bits Out on -ve clock edge MSB first (no read) [Use if CLK starts at '0']"},
    {0x18, "Clock Data Bytes Out on +ve clock edge LSB first (no read) [Use if CLK starts at '1']"},
    {0x19, "Clock Data Bytes Out on -ve clock edge LSB first (no read) [Use if CLK starts at '0']"},
    {0x1A, "Clock Data Bits Out on +ve clock edge LSB first (no read) [Use if CLK starts at '1']"},
    {0x1B, "Clock Data Bits Out on -ve clock edge LSB first (no read) [Use if CLK starts at '0']"},
    {0x20, "Clock Data Bytes In on +ve clock edge MSB first (no write)"},
    {0x22, "Clock Data Bits In on +ve clock edge MSB first (no write) [TDO/DI sampled just prior to rising edge]"},
    {0x24, "Clock Data Bytes In on -ve clock edge MSB first (no write)"},
    {0x26, "Clock Data Bits In on -ve clock edge MSB first (no write) [TDO/DI sampled just prior to falling edge]"},
    {0x28, "Clock Data Bytes In on +ve clock edge LSB first (no write)"},
    {0x2A, "Clock Data Bits In on +ve clock edge LSB first (no write) [TDO/DI sampled just prior to rising edge]"},
    {0x2C, "Clock Data Bytes In on -ve clock edge LSB first (no write)"},
    {0x2E, "Clock Data Bits In on -ve clock edge LSB first (no write) [TDO/DI sampled just prior to falling edge]"},
    {0x31, "Clock Data Bytes In and Out MSB first [out on -ve edge, in on +ve edge]"},
    {0x33, "Clock Data Bits In and Out MSB first [out on -ve edge, in on +ve edge]"},
    {0x34, "Clock Data Bytes In and Out MSB first [out on +ve edge, in on -ve edge]"},
    {0x36, "Clock Data Bits In and Out MSB first [out on +ve edge, in on -ve edge]"},
    {0x39, "Clock Data Bytes In and Out LSB first [out on -ve edge, in on +ve edge]"},
    {0x3B, "Clock Data Bits In and Out LSB first [out on -ve edge, in on +ve edge]"},
    {0x3C, "Clock Data Bytes In and Out LSB first [out on +ve edge, in on -ve edge]"},
    {0x3E, "Clock Data Bits In and Out LSB first [out on +ve edge, in on -ve edge]"},
    {0x4A, "Clock Data to TMS pin (no read) [TMS with LSB first on +ve clk edge - use if clk is set to '1']"},
    {0x4B, "Clock Data to TMS pin (no read) [TMS with LSB first on -ve clk edge - use if clk is set to '0']"},
    {0x6A, "Clock Data to TMS pin with read [TMS with LSB first on +ve clk edge, read on +ve edge - use if clk is set to '1']"},
    {0x6B, "Clock Data to TMS pin with read [TMS with LSB first on -ve clk edge, read on +ve edge - use if clk is set to '0']"},
    {0x6E, "Clock Data to TMS pin with read [TMS with LSB first on +ve clk edge, read on -ve edge - use if clk is set to '1']"},
    {0x6F, "Clock Data to TMS pin with read [TMS with LSB first on -ve clk edge, read on -ve edge - use if clk is set to '0']"},
    {CMD_SET_DATA_BITS_LOW_BYTE, "Set Data bits LowByte"},
    {CMD_READ_DATA_BITS_LOW_BYTE, "Read Data bits LowByte"},
    {CMD_SET_DATA_BITS_HIGH_BYTE, "Set Data bits HighByte"},
    {CMD_READ_DATA_BITS_HIGH_BYTE, "Read Data bits HighByte"},
    {0x84, "Connect TDI to TDO for Loopback"},
    {0x85, "Disconnect TDI to TDO for Loopback"},
    {0x87, "Send Immediate (flush buffer back to the PC)"},
    {0x88, "Wait On I/O High (wait until GPIOL1 (JTAG) or I/O1 (CPU) is high)"},
    {0x89, "Wait On I/O Low (wait until GPIOL1 (JTAG) or I/O1 (CPU) is low)"},
    {0, NULL}
};
static value_string_ext command_vals_ext = VALUE_STRING_EXT_INIT(command_vals);

static const value_string cpumode_command_vals[] = {
    {CMD_CPUMODE_READ_SHORT_ADDR, "CPUMode Read Short Address"},
    {CMD_CPUMODE_READ_EXT_ADDR, "CPUMode Read Extended Address"},
    {CMD_CPUMODE_WRITE_SHORT_ADDR, "CPUMode Write Short Address"},
    {CMD_CPUMODE_WRITE_EXT_ADDR, "CPUMode Write Extended Address"},
    {0, NULL}
};
static value_string_ext cpumode_command_vals_ext = VALUE_STRING_EXT_INIT(cpumode_command_vals);

static const value_string ft2232d_only_command_vals[] = {
    {CMD_CLOCK_SET_DIVISOR, "Set TCK/SK Divisor"},
    {0, NULL}
};

/* FT232H, FT2232H and FT4232H only commands */
static const value_string h_only_command_vals[] = {
    {CMD_CLOCK_SET_DIVISOR, "Set clk divisor"},
    {0x8A, "Disable Clk Divide by 5"},
    {0x8B, "Enable Clk Divide by 5"},
    {0x8C, "Enable 3 Phase Data Clocking"},
    {0x8D, "Disable 3 Phase Data Clocking"},
    {CMD_CLOCK_N_BITS, "Clock For n bits with no data transfer"},
    {CMD_CLOCK_N_TIMES_8_BITS, "Clock For n x 8 bits with no data transfer"},
    {0x94, "Clk continuously and Wait On I/O High"},
    {0x95, "Clk continuously and Wait On I/O Low"},
    {0x96, "Turn On Adaptive clocking"},
    {0x97, "Turn Off Adaptive clocking"},
    {CMD_CLOCK_N_TIMES_8_BITS_OR_UNTIL_L1_HIGH, "Clock For n x 8 bits with no data transfer or Until GPIOL1 is High"},
    {CMD_CLOCK_N_TIMES_8_BITS_OR_UNTIL_L1_LOW, "Clock For n x 8 bits with no data transfer or Until GPIOL1 is Low"},
    {0, NULL}
};
static value_string_ext h_only_command_vals_ext = VALUE_STRING_EXT_INIT(h_only_command_vals);

static const value_string ft232h_only_command_vals[] = {
    {CMD_IO_OPEN_DRAIN_ENABLE, "Set I/O to only drive on a '0' and tristate on a '1'"},
    {0, NULL}
};

static const value_string data_shifting_command_b1_vals[] = {
    {0, "Byte mode"},
    {1, "Bit mode"},
    {0, NULL}
};

static const value_string data_shifting_command_b3_vals[] = {
    {0, "MSB first"},
    {1, "LSB first"},
    {0, NULL}
};

static const value_string command_b7_vals[] = {
    {0, "Data Shifting Command"},
    {1, "Other (Not Data Shifting) Command"},
    {0, NULL}
};

#define IS_DATA_SHIFTING_COMMAND_BIT_ACTIVE(cmd) ((cmd & (1u << 7)) == 0)
#define IS_DATA_SHIFTING_BYTE_MODE(cmd)          ((cmd & (1u << 1)) == 0)
#define IS_DATA_SHIFTING_MSB_FIRST(cmd)          ((cmd & (1u << 3)) == 0)
#define IS_DATA_SHIFTING_WRITING_TDI(cmd)        (cmd & (1u << 4))
#define IS_DATA_SHIFTING_READING_TDO(cmd)        (cmd & (1u << 5))
#define IS_DATA_SHIFTING_WRITING_TMS(cmd)        (cmd & (1u << 6))

static gboolean is_data_shifting_command(guint8 cmd)
{
    switch (cmd)
    {
    /* Not all data shifting commands (with bit 7 clear) are explicitly listed in MPSSE documentation
     * Some undocumented data shifting commands trigger BadCommmand response, but some seem to be handled by the device.
     *
     * Commands listed below (with bit 7 clear) trigger BadCommand response on FT2232L, FT232H and FT2232H
     */
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x0E: case 0x0F:
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49:
    case 0x4C: case 0x4D:
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: case 0x59:
    case 0x5C: case 0x5D:
    case 0x60: case 0x61:
    case 0x64: case 0x65:
    case 0x68: case 0x69:
    case 0x6C: case 0x6D:
    case 0x70: case 0x71:
    case 0x74: case 0x75:
    case 0x78: case 0x79:
    case 0x7C: case 0x7D:
        return FALSE;
    default:
        return IS_DATA_SHIFTING_COMMAND_BIT_ACTIVE(cmd);
    }
}

static gboolean is_data_shifting_command_returning_response(guint8 cmd, ftdi_mpsse_info_t *mpsse_info)
{
    DISSECTOR_ASSERT(is_data_shifting_command(cmd));
    if (mpsse_info->mcu_mode)
    {
        /* MCU mode seems to consume data shifting payloads but do not actually return any response data */
        return FALSE;
    }

    return IS_DATA_SHIFTING_READING_TDO(cmd) ? TRUE : FALSE;
}

/* Returns human-readable command description string or NULL on BadCommand */
static const char *
get_command_string(guint8 cmd, ftdi_mpsse_info_t *mpsse_info)
{
    const char *str;

    /* First, try commands that are common on all chips */
    str = try_val_to_str_ext(cmd, &command_vals_ext);
    if (str)
    {
        return str;
    }

    if (is_data_shifting_command(cmd))
    {
        return "Undocumented Data Shifting Command";
    }

    /* Check chip specific commands */
    switch (mpsse_info->chip)
    {
    case FTDI_CHIP_FT2232D:
        str = try_val_to_str(cmd, ft2232d_only_command_vals);
        break;
    case FTDI_CHIP_FT232H:
        str = try_val_to_str(cmd, ft232h_only_command_vals);
        if (str)
        {
            break;
        }
        /* Fallthrough */
    case FTDI_CHIP_FT2232H:
    case FTDI_CHIP_FT4232H:
        str = try_val_to_str_ext(cmd, &h_only_command_vals_ext);
        break;
    default:
        break;
    }

    if (!str && mpsse_info->mcu_mode)
    {
        str = try_val_to_str_ext(cmd, &cpumode_command_vals_ext);
    }

    return str;
}

static gboolean is_valid_command(guint8 cmd, ftdi_mpsse_info_t *mpsse_info)
{
    return get_command_string(cmd, mpsse_info) != NULL;
}

static gboolean is_same_mpsse_instance(ftdi_mpsse_info_t *info1, ftdi_mpsse_info_t *info2)
{
    return (info1->bus_id == info2->bus_id) &&
           (info1->device_address == info2->device_address) &&
           (info1->chip == info2->chip) &&
           (info1->iface == info2->iface) &&
           (info1->mcu_mode == info2->mcu_mode);
}

static command_data_t *
get_recorded_command_data(wmem_tree_t *command_tree, packet_info *pinfo, ftdi_mpsse_info_t *mpsse_info)
{
    guint32         k_bus_id = mpsse_info->bus_id;
    guint32         k_device_address = mpsse_info->device_address;
    guint32         k_chip = (guint32)mpsse_info->chip;
    guint32         k_interface = (guint32)mpsse_info->iface;
    guint32         k_mcu_mode = mpsse_info->mcu_mode;
    wmem_tree_key_t key[] = {
        {1, &k_bus_id},
        {1, &k_device_address},
        {1, &k_chip},
        {1, &k_interface},
        {1, &k_mcu_mode},
        {1, &pinfo->num},
        {0, NULL}
    };

    command_data_t *data = NULL;
    data = (command_data_t *)wmem_tree_lookup32_array_le(command_tree, key);
    if (data && is_same_mpsse_instance(mpsse_info, &data->mpsse_info))
    {
        return data;
    }

    return NULL;
}

static void
insert_command_data_pointer(wmem_tree_t *command_tree, packet_info *pinfo, ftdi_mpsse_info_t *mpsse_info, command_data_t *data)
{
    guint32         k_bus_id = mpsse_info->bus_id;
    guint32         k_device_address = mpsse_info->device_address;
    guint32         k_chip = (guint32)mpsse_info->chip;
    guint32         k_interface = (guint32)mpsse_info->iface;
    guint32         k_mcu_mode = mpsse_info->mcu_mode;
    wmem_tree_key_t key[] = {
        {1, &k_bus_id},
        {1, &k_device_address},
        {1, &k_chip},
        {1, &k_interface},
        {1, &k_mcu_mode},
        {1, &pinfo->num},
        {0, NULL}
    };

    wmem_tree_insert32_array(command_tree, key, data);
}

static void
record_command_data(command_data_t **cmd_data, packet_info *pinfo, ftdi_mpsse_info_t *mpsse_info, guint8 cmd,
                    gint32 response_length, gboolean preliminary)
{
    command_data_t *data = *cmd_data;

    DISSECTOR_ASSERT(response_length > 0);

    if (data && data->preliminary)
    {
        DISSECTOR_ASSERT(data->cmd == cmd);
        DISSECTOR_ASSERT(data->response_length == response_length);
        data->command_in_packet = pinfo->num;
        data->preliminary = preliminary;
        return;
    }

    data = wmem_new(wmem_file_scope(), command_data_t);
    memcpy(&data->mpsse_info, mpsse_info, sizeof(ftdi_mpsse_info_t));
    data->preliminary = preliminary;
    data->is_response_set = FALSE;
    data->cmd = cmd;
    data->response_length = response_length;
    data->command_in_packet = pinfo->num;
    data->response_in_packet = 0;
    data->next = NULL;

    if (*cmd_data && (!(*cmd_data)->is_response_set))
    {
        DISSECTOR_ASSERT((*cmd_data)->next == NULL);
        (*cmd_data)->next = data;
        if ((*cmd_data)->command_in_packet != pinfo->num)
        {
            insert_command_data_pointer(tx_command_info, pinfo, mpsse_info, data);
        }
    }
    else
    {
        insert_command_data_pointer(rx_command_info, pinfo, mpsse_info, data);
        insert_command_data_pointer(tx_command_info, pinfo, mpsse_info, data);
    }
    *cmd_data = data;
}

static void expect_response(command_data_t **cmd_data, packet_info *pinfo, proto_tree *tree,
                            ftdi_mpsse_info_t *mpsse_info, guint8 cmd, guint16 response_length)
{
    if (pinfo->fd->visited)
    {
        DISSECTOR_ASSERT(*cmd_data);
        DISSECTOR_ASSERT((*cmd_data)->cmd == cmd);
        DISSECTOR_ASSERT((*cmd_data)->response_length == response_length);
        if ((*cmd_data)->is_response_set)
        {
            proto_tree *response_in = proto_tree_add_uint(tree, hf_mpsse_response_in, NULL, 0, 0, (*cmd_data)->response_in_packet);
            proto_item_set_generated(response_in);
            DISSECTOR_ASSERT((*cmd_data)->command_in_packet == pinfo->num);
        }
        *cmd_data = (*cmd_data)->next;
    }
    else
    {
        record_command_data(cmd_data, pinfo, mpsse_info, cmd, response_length, FALSE);
    }
}

static gchar* freq_to_str(gfloat freq)
{
    if (freq < 1e3)
    {
        return g_strdup_printf("%.12g Hz", freq);
    }
    else if (freq < 1e6)
    {
        return g_strdup_printf("%.12g kHz", freq / 1e3);
    }
    else
    {
        return g_strdup_printf("%.12g MHz", freq / 1e6);
    }
}

static gint
dissect_data_shifting_command_parameters(guint8 cmd, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                                         ftdi_mpsse_info_t *mpsse_info, command_data_t **cmd_data)
{
    gint         offset_start = offset;
    gint32       length;

    DISSECTOR_ASSERT(is_data_shifting_command(cmd));

    if (IS_DATA_SHIFTING_BYTE_MODE(cmd))
    {
        length = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        proto_tree_add_uint_format(tree, hf_mpsse_length_uint16, tvb, offset, 2, length, "Length: %d byte%s", length + 1, plurality(length + 1, "", "s"));
        offset += 2;

        if (IS_DATA_SHIFTING_WRITING_TDI(cmd))
        {
            proto_tree_add_item(tree, hf_mpsse_bytes_out, tvb, offset, length + 1, ENC_NA);
            offset += length + 1;
        }
    }
    else
    {
        length = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_mpsse_length_uint8, tvb, offset, 1, length, "Length: %d bit%s", length + 1, plurality(length + 1, "", "s"));
        offset += 1;

        if (IS_DATA_SHIFTING_WRITING_TMS(cmd) && IS_DATA_SHIFTING_READING_TDO(cmd) && IS_DATA_SHIFTING_MSB_FIRST(cmd))
        {
            /* These undocumented commands do not seem to consume the data byte, only the length */
        }
        else if (IS_DATA_SHIFTING_WRITING_TDI(cmd) || IS_DATA_SHIFTING_WRITING_TMS(cmd))
        {
            proto_tree_add_item(tree, hf_mpsse_bits_out, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }
    }

    if (is_data_shifting_command_returning_response(cmd, mpsse_info))
    {
        expect_response(cmd_data, pinfo, tree, mpsse_info, cmd, IS_DATA_SHIFTING_BYTE_MODE(cmd) ? length + 1 : 1);
    }

    return offset - offset_start;
}

static gint
dissect_set_data_bits_parameters(guint8 cmd _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset,
                                 const char *signal_names[8], const char *pin_prefix, guint num_pins)
{
    static const gint *value_bits_hf[] = {
        &hf_mpsse_value_b0,
        &hf_mpsse_value_b1,
        &hf_mpsse_value_b2,
        &hf_mpsse_value_b3,
        &hf_mpsse_value_b4,
        &hf_mpsse_value_b5,
        &hf_mpsse_value_b6,
        &hf_mpsse_value_b7,
    };
    static const gint *direction_bits_hf[] = {
        &hf_mpsse_direction_b0,
        &hf_mpsse_direction_b1,
        &hf_mpsse_direction_b2,
        &hf_mpsse_direction_b3,
        &hf_mpsse_direction_b4,
        &hf_mpsse_direction_b5,
        &hf_mpsse_direction_b6,
        &hf_mpsse_direction_b7,
    };
    guint32 value, direction;
    proto_item *item;
    proto_item *value_item, *direction_item;
    proto_tree *value_tree, *direction_tree;
    guint bit;

    value_item = proto_tree_add_item_ret_uint(tree, hf_mpsse_value, tvb, offset, 1, ENC_LITTLE_ENDIAN, &value);
    direction_item = proto_tree_add_item_ret_uint(tree, hf_mpsse_direction, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN, &direction);

    value_tree = proto_item_add_subtree(value_item, ett_mpsse_value);
    for (bit = 0; bit < 8; bit++)
    {
        const char *state;
        if ((1 << bit) & direction)
        {
            state = ((1 << bit) & value) ? "Output High" : "Output Low";
        }
        else
        {
            state = "N/A (Input)";
        }
        item = proto_tree_add_uint_format_value(value_tree, *value_bits_hf[bit], tvb, offset, 1, value, "%s", signal_names[bit]);
        if (pin_prefix && (bit < num_pins))
        {
            proto_item_append_text(item, " [%s%d]", pin_prefix, bit);
        }
        proto_item_append_text(item, " %s", state);
    }

    direction_tree = proto_item_add_subtree(direction_item, ett_mpsse_direction);
    for (bit = 0; bit < 8; bit++)
    {
        const char *type = ((1 << bit) & direction) ? "Output" : "Input";
        item = proto_tree_add_uint_format_value(direction_tree, *direction_bits_hf[bit], tvb, offset + 1, 1, direction, "%s", signal_names[bit]);
        if (pin_prefix && (bit < num_pins))
        {
            proto_item_append_text(item, " [%s%d]", pin_prefix, bit);
        }
        proto_item_append_text(item, " %s", type);
    }

    return 2;
}

static gint
dissect_cpumode_parameters(guint8 cmd, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                           ftdi_mpsse_info_t *mpsse_info, command_data_t **cmd_data)
{
    gint         offset_start = offset;

    /* Address is either short (1 byte) or extended (2 bytes) */
    if ((cmd == CMD_CPUMODE_READ_SHORT_ADDR) || (cmd == CMD_CPUMODE_WRITE_SHORT_ADDR))
    {
        proto_tree_add_item(tree, hf_mpsse_cpumode_address_short, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    else if ((cmd == CMD_CPUMODE_READ_EXT_ADDR) || (cmd == CMD_CPUMODE_WRITE_EXT_ADDR))
    {
        proto_tree_add_item(tree, hf_mpsse_cpumode_address_extended, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* Write commands have data parameter (1 byte) */
    if ((cmd == CMD_CPUMODE_WRITE_SHORT_ADDR) || (cmd == CMD_CPUMODE_WRITE_EXT_ADDR))
    {
        proto_tree_add_item(tree, hf_mpsse_cpumode_data, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    if ((cmd == CMD_CPUMODE_READ_SHORT_ADDR) || (cmd == CMD_CPUMODE_READ_EXT_ADDR))
    {
        expect_response(cmd_data, pinfo, tree, mpsse_info, cmd, 1);
    }

    return offset - offset_start;
}

static gint
dissect_clock_parameters(guint8 cmd _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, ftdi_mpsse_info_t *mpsse_info)
{
    gint         offset_start = offset;
    guint32      value;
    proto_item   *item;
    gchar        *str_old, *str;

    item = proto_tree_add_item_ret_uint(tree, hf_mpsse_clk_divisor, tvb, offset, 2, ENC_LITTLE_ENDIAN, &value);
    offset += 2;

    str_old = freq_to_str((gfloat) 12e6 / ((1 + value) * 2));
    str = freq_to_str((gfloat) 60e6 / ((1 + value) * 2));

    if (mpsse_info->chip == FTDI_CHIP_FT2232D)
    {
        proto_item_append_text(item, ", TCK/SK Max: %s", str_old);
    }
    else
    {
        proto_item_append_text(item, ", TCK Max: %s (60 MHz master clock) or %s (12 MHz master clock)", str, str_old);
    }

    g_free(str_old);
    g_free(str);

    return offset - offset_start;
}

static gint
dissect_clock_n_bits_parameters(guint8 cmd _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, ftdi_mpsse_info_t *mpsse_info _U_)
{
    guint32 length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format(tree, hf_mpsse_length_uint8, tvb, offset, 1, length, "Length: %d clock%s", length + 1, plurality(length + 1, "", "s"));
    return 1;
}

static gint
dissect_clock_n_times_8_bits_parameters(guint8 cmd _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, ftdi_mpsse_info_t *mpsse_info _U_)
{
    guint32 length = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_uint_format(tree, hf_mpsse_length_uint16, tvb, offset, 2, length, "Length: %d clocks", (length + 1) * 8);
    return 2;
}

static const char *
get_data_bit_pin_prefix(gboolean is_high_byte, ftdi_mpsse_info_t *mpsse_info, guint *out_num_pins, const char *(**out_names)[8])
{
    static const char *low_byte_signal_names[8] = {
        "TCK/SK",
        "TDI/DO",
        "TDO/DI",
        "TMS/CS",
        "GPIOL0",
        "GPIOL1",
        "GPIOL2",
        "GPIOL3",
    };
    static const char *high_byte_signal_names[8] = {
        "GPIOH0",
        "GPIOH1",
        "GPIOH2",
        "GPIOH3",
        "GPIOH4",
        "GPIOH5",
        "GPIOH6",
        "GPIOH7",
    };

    *out_names = (is_high_byte) ? &high_byte_signal_names : &low_byte_signal_names;

    /* Based on table from FTDI AN_108 chapter 2.1 Data bit Definition */
    switch (mpsse_info->chip)
    {
    case FTDI_CHIP_FT2232D:
        if (mpsse_info->iface == FTDI_INTERFACE_A)
        {
            *out_num_pins = (is_high_byte) ? 4 : 8;
            return (is_high_byte) ? "ACBUS" : "ADBUS";
        }
        break;
    case FTDI_CHIP_FT232H:
        *out_num_pins = 8;
        return (is_high_byte) ? "ACBUS" : "ADBUS";
    case FTDI_CHIP_FT2232H:
        if (mpsse_info->iface == FTDI_INTERFACE_A)
        {
            *out_num_pins = 8;
            return (is_high_byte) ? "ACBUS" : "ADBUS";
        }
        else if (mpsse_info->iface == FTDI_INTERFACE_B)
        {
            *out_num_pins = 8;
            return (is_high_byte) ? "BCBUS" : "BDBUS";
        }
        break;
    case FTDI_CHIP_FT4232H:
        if (!is_high_byte)
        {
            if (mpsse_info->iface == FTDI_INTERFACE_A)
            {
                *out_num_pins = 8;
                return "ADBUS";
            }
            else if (mpsse_info->iface == FTDI_INTERFACE_B)
            {
                *out_num_pins = 8;
                return "BDBUS";
            }
        }
        break;
    default:
        break;
    }

    *out_num_pins = 0;
    return NULL;
}

static gint
dissect_io_open_drain_enable_parameters(guint8 cmd _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, ftdi_mpsse_info_t *mpsse_info _U_)
{
    static const gint *low_byte_bits_hf[] = {
        &hf_mpsse_open_drain_enable_low_b0,
        &hf_mpsse_open_drain_enable_low_b1,
        &hf_mpsse_open_drain_enable_low_b2,
        &hf_mpsse_open_drain_enable_low_b3,
        &hf_mpsse_open_drain_enable_low_b4,
        &hf_mpsse_open_drain_enable_low_b5,
        &hf_mpsse_open_drain_enable_low_b6,
        &hf_mpsse_open_drain_enable_low_b7,
    };
    static const gint *high_byte_bits_hf[] = {
        &hf_mpsse_open_drain_enable_high_b0,
        &hf_mpsse_open_drain_enable_high_b1,
        &hf_mpsse_open_drain_enable_high_b2,
        &hf_mpsse_open_drain_enable_high_b3,
        &hf_mpsse_open_drain_enable_high_b4,
        &hf_mpsse_open_drain_enable_high_b5,
        &hf_mpsse_open_drain_enable_high_b6,
        &hf_mpsse_open_drain_enable_high_b7,
    };
    gint        offset_start = offset;
    const char *pin_prefix = NULL;
    guint       num_pins = 0;
    const char *(*signal_names)[8] = NULL;
    guint32     value;
    proto_item *item;
    proto_item *byte_item;
    proto_tree *byte_tree;
    guint       bit;

    pin_prefix = get_data_bit_pin_prefix(FALSE, mpsse_info, &num_pins, &signal_names);
    byte_item = proto_tree_add_item_ret_uint(tree, hf_mpsse_open_drain_enable_low, tvb, offset, 1, ENC_LITTLE_ENDIAN, &value);
    byte_tree = proto_item_add_subtree(byte_item, ett_mpsse_open_drain_enable);
    for (bit = 0; bit < 8; bit++)
    {
        const char *output_type = ((1 << bit) & value) ? "Open-Drain" : "Push-Pull";
        item = proto_tree_add_uint_format_value(byte_tree, *low_byte_bits_hf[bit], tvb, offset, 1, value, "%s", (*signal_names)[bit]);
        if (pin_prefix && (bit < num_pins))
        {
            proto_item_append_text(item, " [%s%d]", pin_prefix, bit);
        }
        proto_item_append_text(item, " %s", output_type);
    }
    offset++;

    pin_prefix = get_data_bit_pin_prefix(TRUE, mpsse_info, &num_pins, &signal_names);
    byte_item = proto_tree_add_item_ret_uint(tree, hf_mpsse_open_drain_enable_high, tvb, offset, 1, ENC_LITTLE_ENDIAN, &value);
    byte_tree = proto_item_add_subtree(byte_item, ett_mpsse_open_drain_enable);
    for (bit = 0; bit < 8; bit++)
    {
        const char *output_type = ((1 << bit) & value) ? "Open-Drain" : "Push-Pull";
        item = proto_tree_add_uint_format_value(byte_tree, *high_byte_bits_hf[bit], tvb, offset, 1, value, "%s", (*signal_names)[bit]);
        if (pin_prefix && (bit < num_pins))
        {
            proto_item_append_text(item, " [%s%d]", pin_prefix, bit);
        }
        proto_item_append_text(item, " %s", output_type);
    }
    offset++;

    return offset - offset_start;
}

static gint
dissect_non_data_shifting_command_parameters(guint8 cmd, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                                             ftdi_mpsse_info_t *mpsse_info, command_data_t **cmd_data)
{
    const char *pin_prefix         = NULL;
    guint       num_pins           = 0;
    const char *(*signal_names)[8] = NULL;

    DISSECTOR_ASSERT(!is_data_shifting_command(cmd) && is_valid_command(cmd, mpsse_info));

    switch (cmd)
    {
    case CMD_SET_DATA_BITS_LOW_BYTE:
        pin_prefix = get_data_bit_pin_prefix(FALSE, mpsse_info, &num_pins, &signal_names);
        return dissect_set_data_bits_parameters(cmd, tvb, pinfo, tree, offset, *signal_names, pin_prefix, num_pins);
    case CMD_SET_DATA_BITS_HIGH_BYTE:
        pin_prefix = get_data_bit_pin_prefix(TRUE, mpsse_info, &num_pins, &signal_names);
        return dissect_set_data_bits_parameters(cmd, tvb, pinfo, tree, offset, *signal_names, pin_prefix, num_pins);
    case CMD_READ_DATA_BITS_LOW_BYTE:
    case CMD_READ_DATA_BITS_HIGH_BYTE:
        expect_response(cmd_data, pinfo, tree, mpsse_info, cmd, 1);
        return 0;
    case CMD_CPUMODE_READ_SHORT_ADDR:
    case CMD_CPUMODE_READ_EXT_ADDR:
    case CMD_CPUMODE_WRITE_SHORT_ADDR:
    case CMD_CPUMODE_WRITE_EXT_ADDR:
        return dissect_cpumode_parameters(cmd, tvb, pinfo, tree, offset, mpsse_info, cmd_data);
    case CMD_CLOCK_SET_DIVISOR:
        return dissect_clock_parameters(cmd, tvb, pinfo, tree, offset, mpsse_info);
    case CMD_CLOCK_N_BITS:
        return dissect_clock_n_bits_parameters(cmd, tvb, pinfo, tree, offset, mpsse_info);
    case CMD_CLOCK_N_TIMES_8_BITS:
    case CMD_CLOCK_N_TIMES_8_BITS_OR_UNTIL_L1_HIGH:
    case CMD_CLOCK_N_TIMES_8_BITS_OR_UNTIL_L1_LOW:
        return dissect_clock_n_times_8_bits_parameters(cmd, tvb, pinfo, tree, offset, mpsse_info);
    case CMD_IO_OPEN_DRAIN_ENABLE:
        return dissect_io_open_drain_enable_parameters(cmd, tvb, pinfo, tree, offset, mpsse_info);
    default:
        return 0;
    }
}

static gint estimated_command_parameters_length(guint8 cmd, tvbuff_t *tvb, packet_info *pinfo, gint offset,
                                                ftdi_mpsse_info_t *mpsse_info, command_data_t **cmd_data)
{
    gint parameters_length = 0;

    if (!is_valid_command(cmd, mpsse_info))
    {
        return 0;
    }

    if (is_data_shifting_command(cmd))
    {
        gint32 data_length = 0;
        if (IS_DATA_SHIFTING_BYTE_MODE(cmd))
        {
            parameters_length = 2;
            if (IS_DATA_SHIFTING_WRITING_TDI(cmd))
            {
                if (tvb_reported_length_remaining(tvb, offset) >= 2)
                {
                    data_length = (gint32)tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 1;
                    parameters_length += data_length;
                }
                /* else length is not available already so the caller will know that reassembly is needed */
            }
        }
        else /* bit mode */
        {
            parameters_length = (IS_DATA_SHIFTING_WRITING_TDI(cmd) || IS_DATA_SHIFTING_WRITING_TMS(cmd)) ? 2 : 1;
            data_length = 1;
            if (IS_DATA_SHIFTING_WRITING_TMS(cmd) && IS_DATA_SHIFTING_READING_TDO(cmd) && IS_DATA_SHIFTING_MSB_FIRST(cmd))
            {
                /* These undocumented commands do not seem to consume the data byte, only the length */
                parameters_length = 1;
            }
        }

        if (!pinfo->fd->visited)
        {
            if (is_data_shifting_command_returning_response(cmd, mpsse_info) && data_length)
            {
                /* Record preliminary command info so the response handler can find the matching command
                 * if host starts reading data before all output is sent. If this command requires reassembly
                 * the command_in_packet member will continue updating until the reassembly is complete.
                 * The preliminary flag will be reset when expect_response() executes.
                 */
                record_command_data(cmd_data, pinfo, mpsse_info, cmd, data_length, TRUE);
            }
        }
    }
    else
    {
        switch (cmd)
        {
        case CMD_CPUMODE_WRITE_EXT_ADDR:
            parameters_length = 3;
            break;
        case CMD_SET_DATA_BITS_LOW_BYTE:
        case CMD_SET_DATA_BITS_HIGH_BYTE:
        case CMD_CPUMODE_READ_EXT_ADDR:
        case CMD_CPUMODE_WRITE_SHORT_ADDR:
        case CMD_CLOCK_SET_DIVISOR:
        case 0x8F: case 0x9C: case 0x9D: case 0x9E:
            parameters_length = 2;
            break;
        case CMD_CPUMODE_READ_SHORT_ADDR:
        case 0x8E:
            parameters_length = 1;
            break;
        case 0x81: case 0x83: case 0x84: case 0x85: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x94: case 0x95: case 0x96: case 0x97:
            parameters_length = 0;
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
        }
    }

    return parameters_length;
}

static guint8
dissect_command_code(guint8 cmd, const char *cmd_str, tvbuff_t *tvb, proto_tree *tree, gint offset, ftdi_mpsse_info_t *mpsse_info _U_)
{
    proto_item        *cmd_item;
    proto_tree        *cmd_tree;
    int               * const *cmd_bits;
    static int * const data_shifting_cmd_bits[] = {
        &hf_mpsse_command_b7,
        &hf_mpsse_command_b6,
        &hf_mpsse_command_b5,
        &hf_mpsse_command_b4,
        &hf_mpsse_command_b3,
        &hf_mpsse_command_b2,
        &hf_mpsse_command_b1,
        &hf_mpsse_command_b0,
        NULL
    };

    static int * const non_data_shifting_cmd_bits[] = {
        &hf_mpsse_command_b7,
        NULL
    };

    cmd_item = proto_tree_add_uint_format(tree, hf_mpsse_command, tvb, offset, 1, cmd, "Command: %s (0x%02x)", cmd_str, cmd);
    cmd_tree = proto_item_add_subtree(cmd_item, ett_mpsse_command);
    cmd_bits = IS_DATA_SHIFTING_COMMAND_BIT_ACTIVE(cmd) ? data_shifting_cmd_bits : non_data_shifting_cmd_bits;

    proto_tree_add_bitmask_list_value(cmd_tree, tvb, offset, 1, cmd_bits, cmd);

    return cmd;
}

static gint
dissect_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gboolean *need_reassembly,
                ftdi_mpsse_info_t *mpsse_info, command_data_t **cmd_data)
{
    guint8       cmd;
    const char  *cmd_str;
    gint         offset_start = offset;
    gint         parameters_length;
    gint         dissected;
    proto_item  *cmd_with_parameters;
    proto_tree  *cmd_tree;

    cmd = tvb_get_guint8(tvb, offset);
    cmd_str = get_command_string(cmd, mpsse_info);
    parameters_length = estimated_command_parameters_length(cmd, tvb, pinfo, offset + 1, mpsse_info, cmd_data);
    if (tvb_reported_length_remaining(tvb, offset + 1) < parameters_length)
    {
        *need_reassembly = TRUE;
        return 0;
    }

    if (!cmd_str)
    {
        cmd_str = "Bad Command";
    }

    cmd_with_parameters = proto_tree_add_bytes_format(tree, hf_mpsse_command_with_parameters, tvb, offset, 1 + parameters_length, NULL, "%s", cmd_str);
    cmd_tree = proto_item_add_subtree(cmd_with_parameters, ett_mpsse_command_with_parameters);

    cmd = dissect_command_code(cmd, cmd_str, tvb, cmd_tree, offset, mpsse_info);
    offset += 1;

    *need_reassembly = FALSE;
    if (is_valid_command(cmd, mpsse_info))
    {
        if (IS_DATA_SHIFTING_COMMAND_BIT_ACTIVE(cmd))
        {
            dissected = dissect_data_shifting_command_parameters(cmd, tvb, pinfo, cmd_tree, offset, mpsse_info, cmd_data);
            DISSECTOR_ASSERT(dissected == parameters_length);
            offset += dissected;
        }
        else
        {
            dissected = dissect_non_data_shifting_command_parameters(cmd, tvb, pinfo, cmd_tree, offset, mpsse_info, cmd_data);
            if (parameters_length > dissected)
            {
                proto_tree_add_expert(cmd_tree, pinfo, &ei_undecoded, tvb, offset + dissected, parameters_length - dissected);
            }
            offset += parameters_length;
        }
    }
    else
    {
        /* Expect Bad Command response */
        expect_response(cmd_data, pinfo, cmd_tree, mpsse_info, cmd, 2);
    }

    return offset - offset_start;
}


static gint
dissect_read_data_bits_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset,
                                const char *signal_names[8], const char *pin_prefix, guint num_pins)
{
    static const gint *value_bits_hf[] = {
        &hf_mpsse_value_b0,
        &hf_mpsse_value_b1,
        &hf_mpsse_value_b2,
        &hf_mpsse_value_b3,
        &hf_mpsse_value_b4,
        &hf_mpsse_value_b5,
        &hf_mpsse_value_b6,
        &hf_mpsse_value_b7,
    };
    guint32 value;
    proto_item *item;
    proto_item *value_item;
    proto_tree *value_tree;
    guint bit;

    value_item = proto_tree_add_item_ret_uint(tree, hf_mpsse_value, tvb, offset, 1, ENC_LITTLE_ENDIAN, &value);
    value_tree = proto_item_add_subtree(value_item, ett_mpsse_value);
    for (bit = 0; bit < 8; bit++)
    {
        const char *state;
        state = ((1 << bit) & value) ? "High" : "Low";
        item = proto_tree_add_uint_format_value(value_tree, *value_bits_hf[bit], tvb, offset, 1, value, "%s", signal_names[bit]);
        if (pin_prefix && (bit < num_pins))
        {
            proto_item_append_text(item, " [%s%d]", pin_prefix, bit);
        }
        proto_item_append_text(item, " %s", state);
    }

    return 1;
}

static gint
dissect_cpumode_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_tree_add_item(tree, hf_mpsse_cpumode_data, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    return 1;
}

static gint
dissect_non_data_shifting_command_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, command_data_t *cmd_data)
{
    const char *pin_prefix         = NULL;
    guint       num_pins           = 0;
    const char *(*signal_names)[8] = NULL;

    DISSECTOR_ASSERT(!is_data_shifting_command(cmd_data->cmd) && is_valid_command(cmd_data->cmd, &cmd_data->mpsse_info));

    switch (cmd_data->cmd)
    {
    case CMD_READ_DATA_BITS_LOW_BYTE:
        pin_prefix = get_data_bit_pin_prefix(FALSE, &cmd_data->mpsse_info, &num_pins, &signal_names);
        return dissect_read_data_bits_response(tvb, pinfo, tree, offset, *signal_names, pin_prefix, num_pins);
    case CMD_READ_DATA_BITS_HIGH_BYTE:
        pin_prefix = get_data_bit_pin_prefix(TRUE, &cmd_data->mpsse_info, &num_pins, &signal_names);
        return dissect_read_data_bits_response(tvb, pinfo, tree, offset, *signal_names, pin_prefix, num_pins);
    case CMD_CPUMODE_READ_SHORT_ADDR:
    case CMD_CPUMODE_READ_EXT_ADDR:
        return dissect_cpumode_response(tvb, pinfo, tree, offset);
    default:
        return 0;
    }
}
static gint
dissect_response_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, command_data_t *cmd_data)
{
    gint         offset_start = offset;

    if (pinfo->fd->visited)
    {
        DISSECTOR_ASSERT(cmd_data->is_response_set && cmd_data->response_in_packet == pinfo->num);
    }
    else
    {
        DISSECTOR_ASSERT(!cmd_data->is_response_set);
        cmd_data->response_in_packet = pinfo->num;
        cmd_data->is_response_set = TRUE;
    }

    if (is_valid_command(cmd_data->cmd, &cmd_data->mpsse_info))
    {
        if (IS_DATA_SHIFTING_COMMAND_BIT_ACTIVE(cmd_data->cmd))
        {
            if (IS_DATA_SHIFTING_BYTE_MODE(cmd_data->cmd))
            {
                proto_tree_add_item(tree, hf_mpsse_bytes_in, tvb, offset, cmd_data->response_length, ENC_NA);
            }
            else
            {
                proto_tree_add_item(tree, hf_mpsse_bits_in, tvb, offset, cmd_data->response_length, ENC_LITTLE_ENDIAN);
            }
            offset += cmd_data->response_length;
        }
        else
        {
            gint dissected;

            dissected = dissect_non_data_shifting_command_response(tvb, pinfo, tree, offset, cmd_data);
            offset += dissected;

            DISSECTOR_ASSERT(dissected <= cmd_data->response_length);
            if (cmd_data->response_length > dissected)
            {
                proto_tree_add_expert(tree, pinfo, &ei_undecoded, tvb, offset, cmd_data->response_length - dissected);
                offset += (cmd_data->response_length - dissected);
            }
        }
    }
    else
    {
        proto_tree_add_item(tree, hf_mpsse_bad_command_error, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_mpsse_bad_command_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
    }

    return offset - offset_start;
}

static gint
dissect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gboolean *need_reassembly,
                 command_data_t *cmd_data)
{
    const char  *cmd_str;
    gint         offset_start = offset;
    proto_item  *rsp_data;
    proto_tree  *rsp_tree;
    proto_item  *command_in;

    cmd_str = get_command_string(cmd_data->cmd, &cmd_data->mpsse_info);
    if (!cmd_str)
    {
        gboolean found = FALSE;
        gboolean request_reassembly = FALSE;

        DISSECTOR_ASSERT(cmd_data->response_length == 2);
        cmd_str = "Bad Command";

        /* Look for Bad Command response in data */
        while (tvb_reported_length_remaining(tvb, offset) >= 2)
        {
            if (tvb_get_guint8(tvb, offset) == BAD_COMMAND_SYNC_CODE)
            {
                if (tvb_get_guint8(tvb, offset + 1) == cmd_data->cmd)
                {
                    found = TRUE;
                    break;
                }
            }
            offset++;
        }

        if (!found)
        {
            if (tvb_get_guint8(tvb, offset) == BAD_COMMAND_SYNC_CODE)
            {
                /* Request reassembly only if there is chance it will help */
                request_reassembly = TRUE;
            }
            else
            {
                offset++;
            }
        }

        if (offset != offset_start)
        {
            proto_item *item;
            proto_tree *expert_tree;

            item = proto_tree_add_expert(tree, pinfo, &ei_skipped_response_data, tvb, offset_start, offset - offset_start);
            expert_tree = proto_item_add_subtree(item, ett_mpsse_skipped_response_data);

            command_in = proto_tree_add_uint_format(expert_tree, hf_mpsse_command_in, NULL, 0, 0, cmd_data->command_in_packet,
                                                    "Bad Command 0x%02x in: %" G_GUINT32_FORMAT, cmd_data->cmd, cmd_data->command_in_packet);
            proto_item_set_generated(command_in);
            if (cmd_data->is_response_set)
            {
                proto_item *response_in;

                response_in = proto_tree_add_uint(expert_tree, hf_mpsse_response_in, NULL, 0, 0, cmd_data->response_in_packet);
                proto_item_set_generated(response_in);
            }
        }

        if (!found)
        {
            *need_reassembly = request_reassembly;
            return offset - offset_start;
        }
    }

    if (tvb_reported_length_remaining(tvb, offset) < cmd_data->response_length)
    {
        *need_reassembly = TRUE;
        return 0;
    }

    rsp_data = proto_tree_add_bytes_format(tree, hf_mpsse_response, tvb, offset, cmd_data->response_length, NULL, "%s", cmd_str);
    rsp_tree = proto_item_add_subtree(rsp_data, ett_mpsse_response_data);

    command_in = proto_tree_add_uint_format(rsp_tree, hf_mpsse_command_in, NULL, 0, 0, cmd_data->command_in_packet,
                                            "Command 0x%02x in: %" G_GUINT32_FORMAT, cmd_data->cmd, cmd_data->command_in_packet);
    proto_item_set_generated(command_in);

    offset += dissect_response_data(tvb, pinfo, rsp_tree, offset, cmd_data);

    return offset - offset_start;
}

static gint
dissect_ftdi_mpsse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gboolean           need_reassembly = FALSE;
    ftdi_mpsse_info_t *mpsse_info = (ftdi_mpsse_info_t *)data;
    gint               offset = 0;
    proto_item        *main_item;
    proto_tree        *main_tree;

    if (!mpsse_info)
    {
        return offset;
    }

    main_item = proto_tree_add_item(tree, proto_ftdi_mpsse, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_ftdi_mpsse);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTDI MPSSE");

    if (pinfo->p2p_dir == P2P_DIR_SENT)
    {
        command_data_t *iter = get_recorded_command_data(tx_command_info, pinfo, mpsse_info);

        if (!pinfo->fd->visited)
        {
            /* Not visited yet - advance iterator to last element */
            while (iter && iter->next)
            {
                DISSECTOR_ASSERT(!iter->preliminary);
                iter = iter->next;
            }
        }

        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (!need_reassembly))
        {
            offset += dissect_command(tvb, pinfo, main_tree, offset, &need_reassembly, mpsse_info, &iter);
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV)
    {
        command_data_t *head = get_recorded_command_data(rx_command_info, pinfo, mpsse_info);
        command_data_t *iter = head;

        if (!pinfo->fd->visited)
        {
            while (iter && iter->is_response_set)
            {
                iter = iter->next;
            }

            if (iter != head)
            {
                insert_command_data_pointer(rx_command_info, pinfo, mpsse_info, iter);
            }
        }

        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (!need_reassembly))
        {
            if (!iter)
            {
                proto_tree_add_expert(main_tree, pinfo, &ei_response_without_command, tvb, offset, -1);
                offset += tvb_reported_length_remaining(tvb, offset);
            }
            else
            {
                offset += dissect_response(tvb, pinfo, main_tree, offset, &need_reassembly, iter);
                iter = iter->next;
            }
        }
    }

    if (need_reassembly)
    {
        if (pinfo->can_desegment)
        {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        }
        else
        {
            proto_tree_add_expert(main_tree, pinfo, &ei_reassembly_unavailable, tvb, offset, -1);
        }
        offset += tvb_reported_length_remaining(tvb, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        proto_tree_add_expert(main_tree, pinfo, &ei_undecoded, tvb, offset, -1);
    }

    return tvb_reported_length(tvb);
}

void
proto_register_ftdi_mpsse(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_mpsse_command,
          { "Command", "ftdi-mpsse.command",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_command_b0,
          { "-ve CLK on write", "ftdi-mpsse.command.b0",
            FT_BOOLEAN, 8, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_mpsse_command_b1,
          { "Mode", "ftdi-mpsse.command.b1",
            FT_UINT8, BASE_DEC, VALS(data_shifting_command_b1_vals), (1 << 1),
            NULL, HFILL }
        },
        { &hf_mpsse_command_b2,
          { "-ve CLK on read", "ftdi-mpsse.command.b2",
            FT_BOOLEAN, 8, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_mpsse_command_b3,
          { "Endianness", "ftdi-mpsse.command.b3",
            FT_UINT8, BASE_DEC, VALS(data_shifting_command_b3_vals), (1 << 3),
            NULL, HFILL }
        },
        { &hf_mpsse_command_b4,
          { "Do write TDI", "ftdi-mpsse.command.b4",
            FT_BOOLEAN, 8, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_mpsse_command_b5,
          { "Do read TDO", "ftdi-mpsse.command.b5",
            FT_BOOLEAN, 8, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_mpsse_command_b6,
          { "Do write TMS", "ftdi-mpsse.command.b6",
            FT_BOOLEAN, 8, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_mpsse_command_b7,
          { "Type", "ftdi-mpsse.command.b7",
            FT_UINT8, BASE_DEC, VALS(command_b7_vals), (1 << 7),
            NULL, HFILL }
        },
        { &hf_mpsse_command_with_parameters,
          { "Command with parameters", "ftdi-mpsse.command_with_parameters",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Command including optional parameter bytes", HFILL }
        },
        { &hf_mpsse_bad_command_error,
          { "Error code", "ftdi-mpsse.bad_command.error",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Bad Command error code 0xFA", HFILL }
        },
        { &hf_mpsse_bad_command_code,
          { "Received invalid command", "ftdi-mpsse.bad_command.command",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Byte which caused the bad command", HFILL }
        },
        { &hf_mpsse_response,
          { "Command response data", "ftdi-mpsse.response",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_command_in,
          { "Command in", "ftdi-mpsse.command.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_response_in,
          { "Response in", "ftdi-mpsse.response.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_length_uint8,
          { "Length", "ftdi-mpsse.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_length_uint16,
          { "Length", "ftdi-mpsse.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_bytes_out,
          { "Bytes out", "ftdi-mpsse.bytes_out",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_bytes_in,
          { "Bytes in", "ftdi-mpsse.bytes_in",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_bits_out,
          { "Bits out", "ftdi-mpsse.bits_out",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_bits_in,
          { "Bits in", "ftdi-mpsse.bits_in",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_value,
          { "Value", "ftdi-mpsse.value",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_value_b0,
          { "Bit 0", "ftdi-mpsse.value.b0",
            FT_UINT8, BASE_DEC, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_mpsse_value_b1,
          { "Bit 1", "ftdi-mpsse.value.b1",
            FT_UINT8, BASE_DEC, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_mpsse_value_b2,
          { "Bit 2", "ftdi-mpsse.value.b2",
            FT_UINT8, BASE_DEC, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_mpsse_value_b3,
          { "Bit 3", "ftdi-mpsse.value.b3",
            FT_UINT8, BASE_DEC, NULL, (1 << 3),
            NULL, HFILL }
        },
        { &hf_mpsse_value_b4,
          { "Bit 4", "ftdi-mpsse.value.b4",
            FT_UINT8, BASE_DEC, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_mpsse_value_b5,
          { "Bit 5", "ftdi-mpsse.value.b5",
            FT_UINT8, BASE_DEC, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_mpsse_value_b6,
          { "Bit 6", "ftdi-mpsse.value.b6",
            FT_UINT8, BASE_DEC, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_mpsse_value_b7,
          { "Bit 7", "ftdi-mpsse.value.b7",
            FT_UINT8, BASE_DEC, NULL, (1 << 7),
            NULL, HFILL }
        },
        { &hf_mpsse_direction,
          { "Direction", "ftdi-mpsse.direction",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b0,
          { "Bit 0", "ftdi-mpsse.direction.b0",
            FT_UINT8, BASE_DEC, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b1,
          { "Bit 1", "ftdi-mpsse.direction.b1",
            FT_UINT8, BASE_DEC, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b2,
          { "Bit 2", "ftdi-mpsse.direction.b2",
            FT_UINT8, BASE_DEC, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b3,
          { "Bit 3", "ftdi-mpsse.direction.b3",
            FT_UINT8, BASE_DEC, NULL, (1 << 3),
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b4,
          { "Bit 4", "ftdi-mpsse.direction.b4",
            FT_UINT8, BASE_DEC, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b5,
          { "Bit 5", "ftdi-mpsse.direction.b5",
            FT_UINT8, BASE_DEC, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b6,
          { "Bit 6", "ftdi-mpsse.direction.b6",
            FT_UINT8, BASE_DEC, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_mpsse_direction_b7,
          { "Bit 7", "ftdi-mpsse.direction.b7",
            FT_UINT8, BASE_DEC, NULL, (1 << 7),
            NULL, HFILL }
        },
        { &hf_mpsse_cpumode_address_short,
          { "Address", "ftdi-mpsse.cpumode_address",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "CPUMode Short Address", HFILL }
        },
        { &hf_mpsse_cpumode_address_extended,
          { "Address", "ftdi-mpsse.cpumode_address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "CPUMode Extended Address", HFILL }
        },
        { &hf_mpsse_cpumode_data,
          { "Data", "ftdi-mpsse.cpumode_data",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_clk_divisor,
          { "Divisor", "ftdi-mpsse.clk_divisor",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low,
          { "Low Byte", "ftdi-mpsse.open_drain_enable_low",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b0,
          { "Bit 0", "ftdi-mpsse.open_drain_enable_low.b0",
            FT_UINT8, BASE_DEC, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b1,
          { "Bit 1", "ftdi-mpsse.open_drain_enable_low.b1",
            FT_UINT8, BASE_DEC, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b2,
          { "Bit 2", "ftdi-mpsse.open_drain_enable_low.b2",
            FT_UINT8, BASE_DEC, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b3,
          { "Bit 3", "ftdi-mpsse.open_drain_enable_low.b3",
            FT_UINT8, BASE_DEC, NULL, (1 << 3),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b4,
          { "Bit 4", "ftdi-mpsse.open_drain_enable_low.b4",
            FT_UINT8, BASE_DEC, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b5,
          { "Bit 5", "ftdi-mpsse.open_drain_enable_low.b5",
            FT_UINT8, BASE_DEC, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b6,
          { "Bit 6", "ftdi-mpsse.open_drain_enable_low.b6",
            FT_UINT8, BASE_DEC, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_low_b7,
          { "Bit 7", "ftdi-mpsse.open_drain_enable_low.b7",
            FT_UINT8, BASE_DEC, NULL, (1 << 7),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high,
          { "High Byte", "ftdi-mpsse.open_drain_enable_high",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b0,
          { "Bit 0", "ftdi-mpsse.open_drain_enable_high.b0",
            FT_UINT8, BASE_DEC, NULL, (1 << 0),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b1,
          { "Bit 1", "ftdi-mpsse.open_drain_enable_high.b1",
            FT_UINT8, BASE_DEC, NULL, (1 << 1),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b2,
          { "Bit 2", "ftdi-mpsse.open_drain_enable_high.b2",
            FT_UINT8, BASE_DEC, NULL, (1 << 2),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b3,
          { "Bit 3", "ftdi-mpsse.open_drain_enable_high.b3",
            FT_UINT8, BASE_DEC, NULL, (1 << 3),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b4,
          { "Bit 4", "ftdi-mpsse.open_drain_enable_high.b4",
            FT_UINT8, BASE_DEC, NULL, (1 << 4),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b5,
          { "Bit 5", "ftdi-mpsse.open_drain_enable_high.b5",
            FT_UINT8, BASE_DEC, NULL, (1 << 5),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b6,
          { "Bit 6", "ftdi-mpsse.open_drain_enable_high.b6",
            FT_UINT8, BASE_DEC, NULL, (1 << 6),
            NULL, HFILL }
        },
        { &hf_mpsse_open_drain_enable_high_b7,
          { "Bit 7", "ftdi-mpsse.open_drain_enable_high.b7",
            FT_UINT8, BASE_DEC, NULL, (1 << 7),
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_undecoded, { "ftdi-mpsse.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_response_without_command, { "ftdi-mpsse.response_without_command", PI_PROTOCOL, PI_ERROR, "Unable to associate response with command (response without command?)", EXPFILL }},
        { &ei_skipped_response_data, { "ftdi-mpsse.skipped_response_data", PI_PROTOCOL, PI_WARN, "Skipped response data while looking for Bad Command response", EXPFILL }},
        { &ei_reassembly_unavailable, { "ftdi-mpsse.reassembly_unavailable", PI_UNDECODED, PI_ERROR, "Data source dissector does not support reassembly. Dissection will get out of sync.", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_ftdi_mpsse,
        &ett_mpsse_command,
        &ett_mpsse_command_with_parameters,
        &ett_mpsse_response_data,
        &ett_mpsse_value,
        &ett_mpsse_direction,
        &ett_mpsse_open_drain_enable,
        &ett_mpsse_skipped_response_data,
    };

    rx_command_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    tx_command_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_ftdi_mpsse = proto_register_protocol("FTDI Multi-Protocol Synchronous Serial Engine", "FTDI MPSSE", "ftdi-mpsse");
    proto_register_field_array(proto_ftdi_mpsse, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    ftdi_mpsse_handle = register_dissector("ftdi-mpsse", dissect_ftdi_mpsse, proto_ftdi_mpsse);

    expert_module = expert_register_protocol(proto_ftdi_mpsse);
    expert_register_field_array(expert_module, ei, array_length(ei));
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
