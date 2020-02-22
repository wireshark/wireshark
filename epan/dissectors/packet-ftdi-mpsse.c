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
static gint hf_mpsse_length_uint8 = -1;
static gint hf_mpsse_length_uint16 = -1;
static gint hf_mpsse_bytes_out = -1;
static gint hf_mpsse_bits_out = -1;
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

static gint ett_ftdi_mpsse = -1;
static gint ett_mpsse_command = -1;
static gint ett_mpsse_value = -1;
static gint ett_mpsse_direction = -1;

static expert_field ei_undecoded = EI_INIT;

static dissector_handle_t ftdi_mpsse_handle;

void proto_register_ftdi_mpsse(void);

#define CMD_SET_DATA_BITS_LOW_BYTE    0x80
#define CMD_SET_DATA_BITS_HIGH_BYTE   0x82
#define CMD_CPUMODE_READ_SHORT_ADDR   0x90
#define CMD_CPUMODE_READ_EXT_ADDR     0x91
#define CMD_CPUMODE_WRITE_SHORT_ADDR  0x92
#define CMD_CPUMODE_WRITE_EXT_ADDR    0x93

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
    {0x81, "Read Data bits LowByte"},
    {CMD_SET_DATA_BITS_HIGH_BYTE, "Set Data bits HighByte"},
    {0x83, "Read Data bits HighByte"},
    {0x84, "Connect TDI to TDO for Loopback"},
    {0x85, "Disconnect TDI to TDO for Loopback"},
    {0x86, "Set TCK/SK Divisor (FT2232D) / Set clk divisor (FT232H/FT2232H/FT4232H)"},
    {0x87, "Send Immediate (flush buffer back to the PC)"},
    {0x88, "Wait On I/O High (wait until GPIOL1 (JTAG) or I/O1 (CPU) is high)"},
    {0x89, "Wait On I/O Low (wait until GPIOL1 (JTAG) or I/O1 (CPU) is low)"},
    {0x8A, "Disable Clk Divide by 5 (FT232H, FT2232H & FT4232H ONLY)"},
    {0x8B, "Enable Clk Divide by 5 (FT232H, FT2232H & FT4232H ONLY)"},
    {0x8C, "Enable 3 Phase Data Clocking (FT232H, FT2232H & FT4232H ONLY)"},
    {0x8D, "Disable 3 Phase Data Clocking (FT232H, FT2232H & FT4232H ONLY)"},
    {0x8E, "Clock For n bits with no data transfer (FT232H, FT2232H & FT4232H ONLY)"},
    {0x8F, "Clock For n x 8 bits with no data transfer (FT232H, FT2232H & FT4232H ONLY)"},
    {CMD_CPUMODE_READ_SHORT_ADDR, "CPUMode Read Short Address"},
    {CMD_CPUMODE_READ_EXT_ADDR, "CPUMode Read Extended Address"},
    {CMD_CPUMODE_WRITE_SHORT_ADDR, "CPUMode Write Short Address"},
    {CMD_CPUMODE_WRITE_EXT_ADDR, "CPUMode Write Extended Address"},
    {0x94, "Clk continuously and Wait On I/O High (FT232H, FT2232H & FT4232H ONLY)"},
    {0x95, "Clk continuously and Wait On I/O Low (FT232H, FT2232H & FT4232H ONLY)"},
    {0x96, "Turn On Adaptive clocking (FT232H, FT2232H & FT4232H ONLY)"},
    {0x97, "Turn Off Adaptive clocking (FT232H, FT2232H & FT4232H ONLY)"},
    {0x9C, "Clock For n x 8 bits with no data transfer or Until GPIOL1 is High (FT232H, FT2232H & FT4232H ONLY)"},
    {0x9D, "Clock For n x 8 bits with no data transfer or Until GPIOL1 is Low (FT232H, FT2232H & FT4232H ONLY)"},
    {0x9E, "Set I/O to only drive on a '0' and tristate on a '1' (FT232H ONLY)"},
    {0, NULL}
};
static value_string_ext command_vals_ext = VALUE_STRING_EXT_INIT(command_vals);

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

static gboolean is_valid_command(guint8 cmd)
{
    return try_val_to_str_ext(cmd, &command_vals_ext) != NULL;
}

#define IS_DATA_SHIFTING_COMMAND(cmd)     ((cmd & (1u << 7)) == 0)
#define IS_DATA_SHIFTING_BYTE_MODE(cmd)   ((cmd & (1u << 1)) == 0)
#define IS_DATA_SHIFTING_WRITING_TDI(cmd) (cmd & (1u << 4))
#define IS_DATA_SHIFTING_WRITING_TMS(cmd) (cmd & (1u << 6))

static gint
dissect_data_shifting_command_parameters(guint8 cmd, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    gint         offset_start = offset;
    guint32      length;

    DISSECTOR_ASSERT(IS_DATA_SHIFTING_COMMAND(cmd) && is_valid_command(cmd));

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

        if (IS_DATA_SHIFTING_WRITING_TDI(cmd) || IS_DATA_SHIFTING_WRITING_TMS(cmd))
        {
            proto_tree_add_item(tree, hf_mpsse_bits_out, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }
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
dissect_cpumode_parameters(guint8 cmd, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
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

    return offset - offset_start;
}

static const char *get_data_bit_pin_prefix(gboolean is_high_byte, ftdi_mpsse_info_t *mpsse_info, guint *out_num_pins)
{
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
dissect_non_data_shifting_command_parameters(guint8 cmd, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, ftdi_mpsse_info_t *mpsse_info)
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

    const char *pin_prefix = NULL;
    guint       num_pins   = 0;

    DISSECTOR_ASSERT(!IS_DATA_SHIFTING_COMMAND(cmd) && is_valid_command(cmd));

    switch (cmd)
    {
    case CMD_SET_DATA_BITS_LOW_BYTE:
        pin_prefix = get_data_bit_pin_prefix(FALSE, mpsse_info, &num_pins);
        return dissect_set_data_bits_parameters(cmd, tvb, pinfo, tree, offset, low_byte_signal_names, pin_prefix, num_pins);
    case CMD_SET_DATA_BITS_HIGH_BYTE:
        pin_prefix = get_data_bit_pin_prefix(TRUE, mpsse_info, &num_pins);
        return dissect_set_data_bits_parameters(cmd, tvb, pinfo, tree, offset, high_byte_signal_names, pin_prefix, num_pins);
    case CMD_CPUMODE_READ_SHORT_ADDR:
    case CMD_CPUMODE_READ_EXT_ADDR:
    case CMD_CPUMODE_WRITE_SHORT_ADDR:
    case CMD_CPUMODE_WRITE_EXT_ADDR:
        return dissect_cpumode_parameters(cmd, tvb, pinfo, tree, offset);
    default:
        return 0;
    }
}

static gint estimated_command_parameters_length(guint8 cmd, tvbuff_t *tvb, gint offset)
{
    gint parameters_length = 0;

    DISSECTOR_ASSERT(is_valid_command(cmd));

    if (IS_DATA_SHIFTING_COMMAND(cmd))
    {
        if (IS_DATA_SHIFTING_BYTE_MODE(cmd))
        {
            parameters_length = 2;
            if (IS_DATA_SHIFTING_WRITING_TDI(cmd))
            {
                if (tvb_reported_length_remaining(tvb, offset) >= 2)
                {
                    parameters_length += tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) + 1;
                }
                /* else length is not available already so the caller will know that reassembly is needed */
            }
        }
        else /* bit mode */
        {
            parameters_length = (IS_DATA_SHIFTING_WRITING_TDI(cmd) || IS_DATA_SHIFTING_WRITING_TMS(cmd)) ? 2 : 1;
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
        case 0x86: case 0x8F: case 0x9C: case 0x9D: case 0x9E:
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

static gint
dissect_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gboolean *need_reassembly, ftdi_mpsse_info_t *mpsse_info)
{
    guint8       cmd;
    gint         offset_start = offset;

    static const int *data_shifting_cmd_bits[] = {
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

    static const int *non_data_shifting_cmd_bits[] = {
        &hf_mpsse_command_b7,
        NULL
    };

    cmd = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_mpsse_command, ett_mpsse_command,
                                      IS_DATA_SHIFTING_COMMAND(cmd) ? data_shifting_cmd_bits : non_data_shifting_cmd_bits,
                                      ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
    offset += 1;

    if (is_valid_command(cmd))
    {
        gint parameters_length = estimated_command_parameters_length(cmd, tvb, offset);
        if (tvb_reported_length_remaining(tvb, offset) >= parameters_length)
        {
            gint dissected;
            *need_reassembly = FALSE;
            if (IS_DATA_SHIFTING_COMMAND(cmd))
            {
                dissected = dissect_data_shifting_command_parameters(cmd, tvb, pinfo, tree, offset);
                DISSECTOR_ASSERT(dissected == parameters_length);
                offset += dissected;
            }
            else if (parameters_length > 0)
            {
                dissected = dissect_non_data_shifting_command_parameters(cmd, tvb, pinfo, tree, offset, mpsse_info);
                if (parameters_length > dissected)
                {
                    proto_tree_add_expert(tree, pinfo, &ei_undecoded, tvb, offset + dissected, parameters_length - dissected);
                }
                offset += parameters_length;
            }
        }
        else
        {
            *need_reassembly = TRUE;
        }
    }

    return offset - offset_start;
}

static gint
dissect_ftdi_mpsse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
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
        gboolean need_reassembly = FALSE;
        while ((tvb_reported_length_remaining(tvb, offset) > 0) && (!need_reassembly))
        {
            offset += dissect_command(tvb, pinfo, main_tree, offset, &need_reassembly, mpsse_info);
        }

        if (need_reassembly)
        {
            /* TODO: Implement desegmentation in FTDI FT and ask for one more segment */
            REPORT_DISSECTOR_BUG("Reassembly is not implemented yet. Dissection will get out of sync.");
        }
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
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &command_vals_ext, 0x0,
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
          { "Bytes", "ftdi-mpsse.bytes_out",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mpsse_bits_out,
          { "Bits", "ftdi-mpsse.bits_out",
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
    };

    static ei_register_info ei[] = {
        { &ei_undecoded, { "ftdi-mpsse.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_ftdi_mpsse,
        &ett_mpsse_command,
        &ett_mpsse_value,
        &ett_mpsse_direction,
    };

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
