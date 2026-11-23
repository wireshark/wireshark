/* packet-celestron-aux.c
 * Routines for the Celestron AUX bus protocol dissection
 * Copyright 2021-2026, Patricio Latini <p_latini@hotmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The AUX bus links the parts of a Celestron telescope mount: the hand
 * controller, the two motor controllers, the GPS, StarSense cameras, focusers,
 * dew heaters and the Wi-Fi module. SkyPortal and Evolution Wi-Fi modules carry
 * the bus as a plain TCP byte stream (usually on port 2000, which Wireshark
 * already gives to Skinny, so use Decode As or the heuristic), with frames split
 * across segments at any point.
 *
 * Two frame formats share the bus:
 *
 *   AUX packet:        3B | len | src | dst | cmd | data... | checksum
 *   StarSense frame:   3C | len (4 bytes, big-endian) | payload... | checksum
 *
 * len of an AUX packet counts src, dst, cmd and the data. The checksum is the
 * two's complement of the sum of every byte from len to the last data byte. In a
 * StarSense frame (a star list, 8 bytes per star) every 3B in the length and
 * payload is escaped as 3B 02 02; its checksum covers the unescaped bytes.
 *
 * Celestron does not publish the protocol. The names and payload formats here
 * come from captures of real devices and community reverse engineering, as
 * collected by celestron-aux (https://github.com/platini2/celestron-aux). Its
 * payload decoders are ported here function by function, with the same names,
 * and give the same text; the tables between the GENERATED markers are written
 * from its catalog.
 *
 * pcap files exported by celestron-aux (--export-pcap) use LINKTYPE_USER0, one
 * frame per record; map DLT User 0 to "celestron_aux" to read them. Records
 * starting with "#MARK " are notes taken during the capture.
 */

#include "config.h"

#include <math.h>
#include <string.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <wsutil/pint.h>
#include <wsutil/sign_ext.h>
#include <wsutil/str_util.h>
#include <wsutil/time_util.h>
#include <wsutil/to_str.h>

void proto_register_celestron_aux(void);
void proto_reg_handoff_celestron_aux(void);

//static dissector_handle_t celestron_aux_handle;
static dissector_handle_t celestron_aux_tcp_handle;

static int proto_celestron_aux;

static int hf_celestron_aux_preamble;
static int hf_celestron_aux_length;
static int hf_celestron_aux_src;
static int hf_celestron_aux_dst;
static int hf_celestron_aux_cmd;
static int hf_celestron_aux_cmd_name;
static int hf_celestron_aux_data;
static int hf_celestron_aux_value;
static int hf_celestron_aux_checksum;
static int hf_celestron_aux_checksum_status;
static int hf_celestron_aux_starsense_length;
static int hf_celestron_aux_starsense_stars;
static int hf_celestron_aux_starsense_data;
static int hf_celestron_aux_mark;

static int ett_celestron_aux;

static expert_field ei_celestron_aux_bad_checksum;
static expert_field ei_celestron_aux_unexpected_format;
static expert_field ei_celestron_aux_outside_frame;
static expert_field ei_celestron_aux_cut_short;

#define AUX_PREAMBLE        0x3b
#define STARSENSE_PREAMBLE  0x3c
#define AUX_MIN_LENGTH      3       /* src, dst and cmd */
#define STARSENSE_MAX_PAYLOAD 0xffff
#define MARK_PREFIX         "#MARK "
#define MARK_PREFIX_LEN     6

typedef struct {
    wmem_allocator_t *scope;
    packet_info *pinfo;
    unsigned key;               /* the frame's offset in the packet: one TCP segment can hold several */
    tvbuff_t *tvb;              /* the payload, for its floating-point values */
} celestron_aux_ctx_t;

/* A payload decoder: the text celestron-aux shows for the payload, or NULL when
 * the payload does not fit the command's known format. */
typedef char *(*celestron_aux_decoder_t)(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply);

/* BEGIN GENERATED TABLES: from the celestron-aux catalog */
static const value_string celestron_aux_devices[] = {
    { 0x01, "Main Board" },
    { 0x04, "Nexstar HC" },
    { 0x0d, "Nexstar+ HC" },
    { 0x0e, "Starsense HC" },
    { 0x10, "AZM MC" },
    { 0x11, "ALT MC" },
    { 0x12, "Focuser" },
    { 0x17, "Dew Heater Controller" },
    { 0x20, "CPWI" },
    { 0x21, "CFM" },
    { 0x22, "Focuser Utility" },
    { 0x2f, "AUXBUS Scanner" },
    { 0x30, "CGX RA Switch" },
    { 0x31, "CGX DEC Switch" },
    { 0x32, "CGX DEC Autoguide Pt" },
    { 0xb0, "GPS" },
    { 0xb2, "RTC" },
    { 0xb3, "Skyportal Accessory" },
    { 0xb4, "Starsense Camera" },
    { 0xb5, "Nexstar EVO WiFi" },
    { 0xb6, "Battery Power Cont" },
    { 0xb7, "Charge Port" },
    { 0xb8, "Starsense Camera SW" },
    { 0xb9, "Starsense AutoGuider" },
    { 0xbb, "Dew Heater Controller" },
    { 0xbd, "Starsense AutoAlign V2" },
    { 0xbf, "Mount Lights" },
    { 0, NULL }
};

static const value_string celestron_aux_generic_commands[] = {
    { 0xfe, "GET_VERSION" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_01[] = {
    { 0xfe, "MB_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_04[] = {
    { 0xfe, "NXS_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_10[] = {
    { 0x01, "MTR_GET_POSITION" },
    { 0x02, "MTR_GOTO_FAST" },
    { 0x04, "MTR_SET_POSITION" },
    { 0x05, "MTR_GET_MODEL" },
    { 0x06, "MTR_PTRACK" },
    { 0x07, "MTR_NTRACK" },
    { 0x08, "MTR_REMOTE_SWITCH_ALIVE" },
    { 0x09, "MTR_SWITCH_STATE_CHANGE" },
    { 0x0a, "MTR_AG_STATE_CHANGE" },
    { 0x0b, "MTR_MVSWITCH" },
    { 0x0c, "MTR_PECTRAIN" },
    { 0x0d, "MTR_PECPLAY" },
    { 0x0e, "MTR_GET_PEC_BIN" },
    { 0x10, "MTR_SET_POS_BACKLASH" },
    { 0x11, "MTR_SET_NEG_BACKLASH" },
    { 0x12, "MTR_IS_MVSWITCH_OVER" },
    { 0x13, "MTR_IS_GOTO_OVER" },
    { 0x14, "MTR_PEC_STATE_CHANGE" },
    { 0x15, "MTR_IS_PECTRAIN_OVER" },
    { 0x16, "MTR_CANCEL_PECTRAIN" },
    { 0x17, "MTR_GOTO_SLOW" },
    { 0x18, "MTR_IS_INDEX_FOUND" },
    { 0x19, "MTR_FIND_INDEX" },
    { 0x1a, "MTR_SET_USER_LIMIT_MIN" },
    { 0x1b, "MTR_SET_USER_LIMIT_MAX" },
    { 0x1c, "MTR_GET_USER_LIMIT_MIN" },
    { 0x1d, "MTR_GET_USER_LIMIT_MAX" },
    { 0x1e, "MTR_IS_USER_LIMIT_ENABLED" },
    { 0x1f, "MTR_SET_USER_LIMIT_ENABLED" },
    { 0x20, "MTR_SET_CUSTOM_RATE9" },
    { 0x21, "MTR_GET_CUSTOM_RATE9" },
    { 0x22, "MTR_SET_CUSTOM_RATE9_ENA" },
    { 0x23, "MTR_GET_CUSTOM_RATE9_ENA" },
    { 0x24, "MTR_PMSLEW_RATE" },
    { 0x25, "MTR_NMSLEW_RATE" },
    { 0x26, "MTR_AUX_GUIDE" },
    { 0x27, "MTR_IS_AUX_GUIDE_ACTIVE" },
    { 0x2a, "MTR_HS_CALIBRATION_ENABLE" },
    { 0x2b, "MTR_IS_HS_CALIBRATED" },
    { 0x2c, "MTR_GET_HS_POSITIONS" },
    { 0x30, "MTR_EEPROM_READ" },
    { 0x31, "MTR_EEPROM_WRITE" },
    { 0x32, "MTR_PROGRAM_READ" },
    { 0x38, "MTR_CORDWRAP_ON" },
    { 0x39, "MTR_CORDWRAP_OFF" },
    { 0x3a, "MTR_SET_CORDWRAP_POSITION" },
    { 0x3b, "MTR_IS_CORDWRAP_ON" },
    { 0x3c, "MTR_GET_CORDWRAP_POSITION" },
    { 0x3d, "MTR_SET_SHUTTER" },
    { 0x40, "MTR_GET_POS_BACKLASH" },
    { 0x41, "MTR_GET_NEG_BACKLASH" },
    { 0x46, "MTR_SET_AUTOGUIDE_RATE" },
    { 0x47, "MTR_GET_AUTOGUIDE_RATE" },
    { 0x48, "MTR_SET_SWITCH_CALIBRATION" },
    { 0x49, "MTR_GET_SWITCH_CALIBRATION" },
    { 0x4a, "MTR_SET_PRN_VALUE" },
    { 0x4b, "MTR_GET_PRN_VALUE" },
    { 0x50, "MTR_SEND_WARNING" },
    { 0x51, "MTR_SEND_ERROR" },
    { 0x5b, "MTR_SET_PID_KP" },
    { 0x5c, "MTR_SET_PID_KI" },
    { 0x5d, "MTR_SET_PID_KD" },
    { 0x5f, "MTR_ENABLE_PID_ANALYSIS" },
    { 0x81, "MTR_PROGRAM_ENTER" },
    { 0x82, "MTR_PROGRAM_INIT" },
    { 0x83, "MTR_PROGRAM_DATA" },
    { 0x84, "MTR_PROGRAM_END" },
    { 0x8a, "MTR_PROGRAMMER_ENABLE" },
    { 0xee, "MTR_GET_HARDSWITCH_ENABLE" },
    { 0xef, "MTR_SET_HARDSWITCH_ENABLE" },
    { 0xfa, "MTR_GET_CHIPVERSION" },
    { 0xfb, "MTR_GET_BOOTVERSION" },
    { 0xfc, "MTR_IS_APPROACH_DIR_NEG" },
    { 0xfd, "MTR_SET_APPROACH_DIR_NEG" },
    { 0xfe, "MTR_GET_VERSION" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_12[] = {
    { 0x01, "FOCUS_GET_POSITION" },
    { 0x02, "FOCUS_GOTO_FAST" },
    { 0x05, "FOCUS_GET_MODEL" },
    { 0x13, "FOCUS_SLEW_DONE" },
    { 0x24, "FOCUS_MOVE_POS" },
    { 0x25, "FOCUS_MOVE_NEG" },
    { 0x2a, "FOCUS_CALIBRATION_ENABLE" },
    { 0x2b, "FOCUS_IS_CALIBRATED" },
    { 0x2c, "FOCUS_GET_CALIBRATION_POSITIONS" },
    { 0x3b, "FOCUS_UNKNOWN_3B" },
    { 0xfe, "FOCUS_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_17[] = {
    { 0x00, "DEWHEATER_GET_CURRENT_POWER" },
    { 0x02, "DEWHEATER_GET_LED_BRIGHTNESS" },
    { 0x03, "DEWHEATER_SET_INPUT_LIMIT" },
    { 0x04, "DEWHEATER_GET_LIMIT_POWER" },
    { 0x10, "DEWHEATER_GET_POWER_PORTS" },
    { 0x11, "DEWHEATER_GET_PORTS" },
    { 0x12, "DEWHEATER_GET_STATUS" },
    { 0x14, "DEWHEATER_ENABLE_PORT" },
    { 0x16, "DEWHEATER_SET_AUTO_AGGRESSION" },
    { 0x17, "DEWHEATER_SET_MANUAL_POWER" },
    { 0x18, "DEWHEATER_GET_AMBIENT" },
    { 0x19, "DEWHEATER_RECALIBRATE_SENSOR" },
    { 0x1a, "DEWHEATER_IS_CALIBRATING" },
    { 0x20, "DEWHEATER_SET_LED_BRIGHTNESS" },
    { 0x21, "DEWHEATER_UNKNOWN_21" },
    { 0xfe, "GET_VERSION" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_b0[] = {
    { 0x01, "GPS_GET_LAT" },
    { 0x02, "GPS_GET_LONG" },
    { 0x03, "GPS_GET_DATE" },
    { 0x04, "GPS_GET_YEAR" },
    { 0x07, "GPS_GET_SAT_INFO" },
    { 0x08, "GPS_GET_RCVR_STATUS" },
    { 0x33, "GPS_GET_TIME" },
    { 0x36, "GPS_TIME_VALID" },
    { 0x37, "GPS_LINKED" },
    { 0x55, "GPS_GET_HW_VER" },
    { 0xa0, "GPS_GET_COMPASS" },
    { 0xfe, "GPS_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_b3[] = {
    { 0xfe, "WIFI_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_b4[] = {
    { 0x3e, "SS_SET_ALIGN_CENTER" },
    { 0x3f, "SS_GET_ALIGN_CENTER" },
    { 0x90, "SS_RESET_CAPTURE" },
    { 0x91, "SS_GET_STATUS" },
    { 0x92, "SS_GET_CAPTURE_DATA" },
    { 0x94, "SS_START_CAPTURE" },
    { 0x9f, "SS_GET_IMAGE3" },
    { 0xfe, "SS_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_b5[] = {
    { 0x10, "WIFI_SET_ENABLE" },
    { 0xfe, "WIFI_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_b6[] = {
    { 0x10, "BAT_GET_VOLTAGE" },
    { 0x18, "BAT_GET_MAX_CURRENT" },
    { 0xfe, "BAT_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_b7[] = {
    { 0x10, "CHG_MODE" },
    { 0xfe, "CHG_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_b9[] = {
    { 0x01, "SSAG_START_PLATE_SOLVE" },
    { 0x02, "SSAG_GET_PLATE_STATUS" },
    { 0x03, "SSAG_START_CALIBRATE" },
    { 0x04, "SSAG_GET_CALIBRATE_STATUS" },
    { 0x07, "SSAG_UNKNOWN_07" },
    { 0x20, "SSAG_SET_GUIDING" },
    { 0x23, "SSAG_GET_GUIDING_DATA" },
    { 0x30, "SSAG_SET_MOUNT_INFO" },
    { 0x31, "SSAG_SET_GEOLOCATION" },
    { 0x32, "SSAG_SET_TIME_NOW" },
    { 0x45, "SSAG_GET_IMAGE_ROTATION" },
    { 0xfe, "SSAG_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_bb[] = {
    { 0xfe, "DEWHEATER_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_bd[] = {
    { 0x01, "SS2_START_PLATE_SOLVE" },
    { 0x02, "SS2_GET_PLATE_STATUS" },
    { 0x03, "SS2_START_CALIBRATE" },
    { 0x04, "SS2_GET_CALIBRATE_STATUS" },
    { 0x07, "SS2_IS_CALIBRATED" },
    { 0x08, "SS2_GET_CALIBRATION_DATA" },
    { 0x13, "SS2_SET_ASPA" },
    { 0x15, "SS2_GET_ASPA_POLE" },
    { 0x16, "SS2_GET_ASPA_ERROR" },
    { 0x17, "SS2_GET_ASPA_PROGRESS" },
    { 0x30, "SS2_SET_MOUNT_INFO" },
    { 0x31, "SS2_SET_GEOLOCATION" },
    { 0x32, "SS2_SET_TIME_NOW" },
    { 0x45, "SS2_GET_IMAGE_ROTATION" },
    { 0x4b, "SS2_GET_TELESCOPE_POSITION" },
    { 0xfe, "SS2_GET_FW_VER" },
    { 0, NULL }
};

static const value_string celestron_aux_commands_bf[] = {
    { 0x10, "LIGHT_LEVEL" },
    { 0xfe, "LIGHT_GET_FW_VER" },
    { 0, NULL }
};

/* The command names of a device, or NULL when only the generic ones are known. */
static const value_string *
celestron_aux_command_table(uint8_t device)
{
    switch (device) {
    case 0x01:
        return celestron_aux_commands_01;
    case 0x04:
    case 0x0d:
    case 0x0e:
    case 0x20:
        return celestron_aux_commands_04;
    case 0x10:
    case 0x11:
        return celestron_aux_commands_10;
    case 0x12:
        return celestron_aux_commands_12;
    case 0x17:
        return celestron_aux_commands_17;
    case 0xb0:
        return celestron_aux_commands_b0;
    case 0xb3:
        return celestron_aux_commands_b3;
    case 0xb4:
        return celestron_aux_commands_b4;
    case 0xb5:
        return celestron_aux_commands_b5;
    case 0xb6:
        return celestron_aux_commands_b6;
    case 0xb7:
        return celestron_aux_commands_b7;
    case 0xb9:
        return celestron_aux_commands_b9;
    case 0xbb:
        return celestron_aux_commands_bb;
    case 0xbd:
        return celestron_aux_commands_bd;
    case 0xbf:
        return celestron_aux_commands_bf;
    default:
        return NULL;
    }
}

static bool
celestron_aux_is_controller(uint8_t addr)
{
    switch (addr) {
    case 0x04:
    case 0x0d:
    case 0x0e:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x2f:
        return true;
    default:
        return false;
    }
}

static bool
celestron_aux_is_motor_client(uint8_t addr)
{
    switch (addr) {
    case 0xb9:
        return true;
    default:
        return false;
    }
}

static bool
celestron_aux_is_motor(uint8_t addr)
{
    switch (addr) {
    case 0x10:
    case 0x11:
        return true;
    default:
        return false;
    }
}

#define CELESTRON_AUX_SCANNER 0x2f

static const value_string celestron_aux_mount_models[] = {
    { 0x0001, "Nexstar GPS" },
    { 0x0682, "Advanced GT" },
    { 0x0783, "Nexstar SLT" },
    { 0x0b83, "4/5SE" },
    { 0x0c82, "6/8SE" },
    { 0x1189, "CPC Deluxe" },
    { 0x1283, "GT Series" },
    { 0x1485, "AVX" },
    { 0x1687, "Nexstar Evolution" },
    { 0x1788, "CGX" },
    { 0x1888, "CGX-L" },
    { 0x1d8a, "Origin" },
    { 0, NULL }
};

static const value_string celestron_aux_mount_families[] = {
    { 0x05, "CGE" },
    { 0x06, "Advanced GT / CG-5" },
    { 0x07, "Nexstar SLT" },
    { 0x09, "CPC" },
    { 0x0a, "GT" },
    { 0x0b, "4/5SE" },
    { 0x0c, "6/8SE" },
    { 0x0d, "CGE Pro" },
    { 0x0e, "CGEM DX" },
    { 0x0f, "LCM" },
    { 0x10, "SkyProdigy" },
    { 0x11, "CPC Deluxe" },
    { 0x12, "GT Series" },
    { 0x13, "StarSeeker" },
    { 0x14, "AVX" },
    { 0x15, "Cosmos" },
    { 0x16, "Nexstar Evolution" },
    { 0x17, "CGX" },
    { 0x18, "CGX-L" },
    { 0x19, "AstroFi" },
    { 0x1a, "SkyWatcher" },
    { 0x1d, "Origin" },
    { 0, NULL }
};
/* END GENERATED TABLES */

/* rint() rounds halves to the even neighbour, as Python's round() does; this
 * keeps its result within int64_t. */
#define ROUNDABLE(x) (isfinite(x) && fabs(x) <= 9e15)

/* --- formatting helpers, matching celestron-aux's Python output ------------ */

#define DEG "\xc2\xb0"                    /* the degree sign, UTF-8 */
#define EPOCH_2000 INT64_C(946684800)       /* 2000-01-01 00:00:00 UTC in Unix seconds */
#define MAX_TIMESTAMP 253402300800.0        /* the year 10000 */
#define MAX_ANGLE 1e9                       /* larger angles come from garbage bytes */

/* _labelled: "value - label", or just the value. */
static char *
labelled(celestron_aux_ctx_t *ctx, unsigned value, const value_string *labels)
{
    const char *name = try_val_to_str(value, labels);

    return name ? wmem_strdup_printf(ctx->scope, "%u - %s", value, name) : wmem_strdup_printf(ctx->scope, "%u", value);
}

/* A 0/1 flag as a standard true/false string (NULL: "True"/"False"); any other value as its number. */
static char *
flag_str(celestron_aux_ctx_t *ctx, unsigned value, const true_false_string *tfs)
{
    return value <= 1 ? wmem_strdup(ctx->scope, tfs_get_string(value == 1, tfs)) : wmem_strdup_printf(ctx->scope, "%u", value);
}

/* The same, as "value - label" like labelled(). */
static char *
flag_labelled(celestron_aux_ctx_t *ctx, unsigned value, const true_false_string *tfs)
{
    return value <= 1 ? wmem_strdup_printf(ctx->scope, "%u - %s", value, tfs_get_string(value == 1, tfs))
                      : wmem_strdup_printf(ctx->scope, "%u", value);
}

/* bam_to_degrees(data[:3]): a signed big-endian binary angle of 1-3 bytes. */
static double
bam_degrees(const uint8_t *data, unsigned len)
{
    switch (len) {
    case 1:
        return (int8_t)data[0] * (360.0 / 256);
    case 2:
        return (int16_t)pntohu16(data) * (360.0 / 65536);
    default:
        return (int32_t)ws_sign_ext32(pntohu24(data), 24) * (360.0 / 16777216);
    }
}

static char *
dms(celestron_aux_ctx_t *ctx, double degrees)
{
    int64_t hundredths, whole, minutes, rest;

    if (isnan(degrees) || fabs(degrees) > MAX_ANGLE)
        return NULL;
    if (!ROUNDABLE(degrees * 360000))
        return NULL;
    hundredths = (int64_t)rint(fabs(degrees) * 360000);
    whole = hundredths / 360000;
    rest = hundredths % 360000;
    minutes = rest / 6000;
    rest %= 6000;
    return wmem_strdup_printf(ctx->scope, "%s%" PRId64 DEG "%02" PRId64 "'%05.2f\"", degrees < 0 ? "-" : "",
               whole, minutes, (double)rest / 100);
}

static char *
hms(celestron_aux_ctx_t *ctx, double degrees)
{
    double wrapped = fmod(degrees, 360);
    int64_t hundredths, hours, minutes, rest;

    if (wrapped < 0)
        wrapped += 360;   /* Python's %: the sign of the divisor */
    if (!ROUNDABLE(wrapped / 15 * 360000))
        return NULL;
    hundredths = (int64_t)rint(wrapped / 15 * 360000);
    hundredths %= 24 * 360000;
    hours = hundredths / 360000;
    rest = hundredths % 360000;
    minutes = rest / 6000;
    rest %= 6000;
    return wmem_strdup_printf(ctx->scope, "%" PRId64 "h%02" PRId64 "m%05.2fs", hours, minutes, (double)rest / 100);
}

static char *
version(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len)
{
    wmem_strbuf_t *text;

    if (len >= 4)
        return wmem_strdup_printf(ctx->scope, "%u.%u.%u", data[0], data[1], (unsigned)pntohu16(data + 2));
    text = wmem_strbuf_new(ctx->scope, "");
    for (unsigned i = 0; i < len; i++)
        wmem_strbuf_append_printf(text, i ? ".%u" : "%u", data[i]);
    return wmem_strbuf_finalize(text);
}

static char *
mount_name(celestron_aux_ctx_t *ctx, uint64_t model)
{
    const char *name = model <= UINT32_MAX ? try_val_to_str((unsigned)model, celestron_aux_mount_models) : NULL;
    const char *family = NULL;

    if (name)
        return wmem_strdup(ctx->scope, name);
    if (model > 0xff && (model >> 8) <= UINT32_MAX)
        family = try_val_to_str((unsigned)(model >> 8), celestron_aux_mount_families);
    if (family)
        return wmem_strdup_printf(ctx->scope, "%s family (0x%04" PRIx64 ")", family, model);
    return wmem_strdup_printf(ctx->scope, "Unknown (0x%04" PRIx64 ")", model);
}

/* The RA and Dec at ``offset``: big-endian float32 in radians. */
static char *
ra_dec(celestron_aux_ctx_t *ctx, unsigned offset, unsigned len)
{
    char *ra, *dec;

    if (len < offset + 8)
        return NULL;
    ra = hms(ctx, tvb_get_ntohieee_float(ctx->tvb, offset) * (180.0 / G_PI));
    dec = dms(ctx, tvb_get_ntohieee_float(ctx->tvb, offset + 4) * (180.0 / G_PI));
    if (!ra || !dec)
        return NULL;
    return wmem_strdup_printf(ctx->scope, "RA %s, Dec %s", ra, dec);
}

static char *
utc(celestron_aux_ctx_t *ctx, int64_t seconds, bool with_seconds)
{
    time_t when = (time_t)seconds;
    struct tm tm;

    if (!ws_gmtime_r(&when, &tm))
        return NULL;
    if (with_seconds)
        return wmem_strdup_printf(ctx->scope, "%04d-%02d-%02d %02d:%02d:%02d UTC", tm.tm_year + 1900, tm.tm_mon + 1,
                   tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return wmem_strdup_printf(ctx->scope, "%04d-%02d-%02d %02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
               tm.tm_hour, tm.tm_min);
}

static bool
all_zero(const uint8_t *data, unsigned len)
{
    for (unsigned i = 0; i < len; i++)
        if (data[i])
            return false;
    return true;
}

/* --- payload decoders: ports of celestron_aux/decoding.py ------------------- */

#define NEED(size) do { if (len < (size)) return NULL; } while (0)

static const value_string ack_labels[] = { { 1, "ACK" }, { 0, NULL } };

#define IN_PROGRESS 0
#define SOLVED      1
#define FAILED      4

static char *
decode_version(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    return version(ctx, data, len);
}

static char *
decode_motor_position(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    return dms(ctx, bam_degrees(data, len));
}

static char *
decode_motor_goto2(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    if (reply)
        return labelled(ctx, data[0], ack_labels);
    return dms(ctx, bam_degrees(data, len));
}

static char *
decode_motor_track_rate(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    if (reply)
        return labelled(ctx, data[0], ack_labels);
    /* Up to three bytes: shorter payloads give a smaller number, as in celestron-aux. */
    return wmem_strdup_printf(ctx->scope, "%.4f arcsec/s",
                              (double)tvb_get_uint64_with_length(ctx->tvb, 0, MIN(len, 3), ENC_BIG_ENDIAN) / 1024);
}

static char *
decode_motor_model(celestron_aux_ctx_t *ctx, const uint8_t *data _U_, unsigned len, bool reply _U_)
{
    uint64_t model;

    if (len > 8)
        return NULL;   /* Python prints integers of any size; real replies have 1 or 2 bytes */
    model = tvb_get_uint64_with_length(ctx->tvb, 0, len, ENC_BIG_ENDIAN);
    return wmem_strdup_printf(ctx->scope, "0x%04" PRIx64 " (%s)", model, mount_name(ctx, model));
}

static const value_string goto_over_labels[] = { { 0, "Not done" }, { 1, "Check" }, { 0xff, "Done" }, { 0, NULL } };
static const value_string cordwrap_labels[] = { { 0, "Disabled" }, { 0xff, "Enabled" }, { 0, NULL } };
static const value_string approach_labels[] = { { 0, "Positive" }, { 1, "Negative" }, { 0, NULL } };

static char *
decode_motor_switch_over(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return flag_labelled(ctx, data[0], NULL);
}

static char *
decode_motor_goto_over(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return labelled(ctx, data[0], goto_over_labels);
}

static char *
decode_motor_custom_rate_enabled(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return flag_labelled(ctx, data[0], &tfs_enabled_disabled);
}

static char *
decode_motor_single_byte(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return wmem_strdup_printf(ctx->scope, "%u", data[0]);
}

static char *
decode_motor_cordwrap_on(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return labelled(ctx, data[0], cordwrap_labels);
}

static char *
decode_motor_autoguide_rate(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return wmem_strdup_printf(ctx->scope, "%g%%", 100.0 * data[0] / 256);
}

static char *
decode_motor_approach_direction(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return labelled(ctx, data[0], approach_labels);
}

static char *
decode_gps_coordinate(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    return dms(ctx, bam_degrees(data, len));
}

static char *
decode_gps_date(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(2);
    return wmem_strdup_printf(ctx->scope, "%u/%u", data[0], data[1]);
}

static char *
decode_gps_year(celestron_aux_ctx_t *ctx, const uint8_t *data _U_, unsigned len, bool reply _U_)
{
    if (len > 8)
        return NULL;   /* as decode_motor_model */
    return wmem_strdup_printf(ctx->scope, "%" PRIu64, tvb_get_uint64_with_length(ctx->tvb, 0, len, ENC_BIG_ENDIAN));
}

static char *
decode_gps_satellites(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(2);
    return wmem_strdup_printf(ctx->scope, "%u - %u", data[0], data[1]);
}

static char *
decode_gps_time(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(3);
    return wmem_strdup_printf(ctx->scope, "%02u:%02u:%02u", data[0], data[1], data[2]);
}

static char *
decode_gps_hardware_version(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return wmem_strdup_printf(ctx->scope, "0x%02x%s", data[0], data[0] == 0xab ? " (Celestron GPS)" : "");
}

static char *
decode_gps_flag(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return flag_labelled(ctx, data[0], &tfs_yes_no);
}

static char *
decode_starsense_align_center(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    if (len == 8)
        return wmem_strdup_printf(ctx->scope, "%u - %u", pletohu32(data), pletohu32(data + 4));
    return wmem_strdup_printf(ctx->scope, "%u", data[0]);
}

static const value_string starsense_status_labels[] = {
    { 1, "Idle / none found" }, { 3, "Ready" }, { 9, "Finished" }, { 0, NULL }
};

static char *
decode_starsense_status(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    char *status = labelled(ctx, data[0], starsense_status_labels);

    return len > 1 ? wmem_strdup_printf(ctx->scope, "%s - Stars: %u", status, data[1]) : status;
}

static char *
decode_ssag_plate_status(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    char *position;

    if (data[0] == IN_PROGRESS)
        return wmem_strdup(ctx->scope, "In progress");
    if (data[0] == FAILED)
        return wmem_strdup_printf(ctx->scope, "Failed (status %u)", data[0]);
    if (!(position = ra_dec(ctx, 1, len)))
        return NULL;
    if (data[0] == SOLVED)
        return wmem_strdup_printf(ctx->scope, "Solved, %s", position);
    return wmem_strdup_printf(ctx->scope, "Status %u, %s", data[0], position);
}

static char *
decode_ssag_start_calibrate(celestron_aux_ctx_t *ctx, const uint8_t *data _U_, unsigned len, bool reply _U_)
{
    return ra_dec(ctx, 0, len);
}

static char *
decode_ssag_calibrate_status(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    if (data[0] == IN_PROGRESS)
        return wmem_strdup(ctx->scope, "In progress");
    if (data[0] == FAILED)
        return wmem_strdup_printf(ctx->scope, "Failed (status %u)", data[0]);
    NEED(5);
    return wmem_strdup_printf(ctx->scope, "%s, x %u, y %u",
               data[0] == 1 ? "Solved" : wmem_strdup_printf(ctx->scope, "Status %u", data[0]),
               (unsigned)pntohu16(data + 1), (unsigned)pntohu16(data + 3));
}

static char *
decode_ssag_set_guiding(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    if (data[0] == 0)
        return wmem_strdup(ctx->scope, "Disabled");
    return wmem_strdup_printf(ctx->scope, "Enabled, flags 0x%02x", data[0]);
}

static char *
decode_ss2_is_calibrated(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    if (reply)
        return flag_str(ctx, data[0], &tfs_yes_no);
    return bytes_to_str_maxlen(ctx->scope, data, len, 0);
}

static const value_string aspa_labels[] = { { 0, "Stop" }, { 1, "Start" }, { 4, "Adjust" }, { 0, NULL } };

static char *
decode_ss2_set_aspa(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    const char *name;

    if (reply)
        return data[0] == 0 ? wmem_strdup(ctx->scope, "OK") : bytes_to_str_maxlen(ctx->scope, data, len, 0);
    name = try_val_to_str(data[0], aspa_labels);
    return name ? wmem_strdup(ctx->scope, name) : bytes_to_str_maxlen(ctx->scope, data, len, 0);
}

static char *
decode_ss2_aspa_pole(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    char *position;

    if (data[0] == SOLVED && len >= 9) {
        if (!(position = ra_dec(ctx, 1, len)))
            return NULL;
        return wmem_strdup_printf(ctx->scope, "Polar axis %s", position);
    }
    if (data[0] == FAILED)
        return wmem_strdup(ctx->scope, "No estimate yet");
    return wmem_strdup_printf(ctx->scope, "Status %u", data[0]);
}

static char *
decode_ss2_aspa_error(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    if (data[0] != SOLVED || len < 9) {
        if (all_zero(data, len))
            return wmem_strdup(ctx->scope, "No measurement");
        return wmem_strdup_printf(ctx->scope, "Status %u", data[0]);
    }
    return wmem_strdup_printf(ctx->scope, "Altitude error %+.2f', azimuth error %+.2f'",
               tvb_get_ntohieee_float(ctx->tvb, 1) * 60.0, tvb_get_ntohieee_float(ctx->tvb, 5) * 60.0);
}

static char *
decode_ss2_aspa_progress(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    char *text;

    NEED(6);
    text = wmem_strdup_printf(ctx->scope, "Completion %u %%, uncertainty %.2f" DEG, data[1],
                              tvb_get_ntohieee_float(ctx->tvb, 2));
    return data[0] == SOLVED ? text : wmem_strdup_printf(ctx->scope, "Waiting (%s)", text);
}

static char *
decode_ssag_image_rotation(celestron_aux_ctx_t *ctx, const uint8_t *data _U_, unsigned len, bool reply _U_)
{
    NEED(4);
    return wmem_strdup_printf(ctx->scope, "Rotation %.2f" DEG, tvb_get_ntohieee_float(ctx->tvb, 0));
}

/* The stored calibration (0x08), one slot per request. A reply does not say
 * which slot it holds, so the slot requested last in the conversation is
 * remembered, and the slot each reply got is kept with its frame. */
static const value_string calibration_slot_labels[] = {
    { 0, "offset position RA" },
    { 1, "offset position Dec" },
    { 2, "calibration star RA" },
    { 3, "calibration star Dec" },
    { 4, "image rotation" },
    { 5, "calibration time" },
    { 0, NULL }
};

#define NO_SLOT -1

typedef struct {
    int last_slot;
} celestron_aux_conv_t;

static char *
slot_name(celestron_aux_ctx_t *ctx, int slot)
{
    return wmem_strdup_printf(ctx->scope, "Slot %d: %s", slot, val_to_str_const(slot, calibration_slot_labels, "unknown"));
}

static int
calibration_slot(celestron_aux_ctx_t *ctx, int requested)
{
    conversation_t *conversation = find_or_create_conversation(ctx->pinfo);
    celestron_aux_conv_t *state = (celestron_aux_conv_t *)conversation_get_proto_data(conversation, proto_celestron_aux);
    void *stored;

    if (!state) {
        state = wmem_new(wmem_file_scope(), celestron_aux_conv_t);
        state->last_slot = NO_SLOT;
        conversation_add_proto_data(conversation, proto_celestron_aux, state);
    }
    if (requested != NO_SLOT) {             /* a request */
        if (!PINFO_FD_VISITED(ctx->pinfo))
            state->last_slot = requested;
        return requested;
    }
    stored = p_get_proto_data(wmem_file_scope(), ctx->pinfo, proto_celestron_aux, ctx->key);
    if (stored)                             /* stored as slot + 2, so NO_SLOT is not NULL */
        return GPOINTER_TO_INT(stored) - 2;
    p_add_proto_data(wmem_file_scope(), ctx->pinfo, proto_celestron_aux, ctx->key,
                     GINT_TO_POINTER(state->last_slot + 2));
    return state->last_slot;
}

static char *
decode_ss2_calibration_data(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    double value;
    int slot;
    char *text;

    if (!reply)
        return slot_name(ctx, calibration_slot(ctx, data[0]));
    NEED(4);
    value = tvb_get_ntohieee_float(ctx->tvb, 0);
    slot = calibration_slot(ctx, NO_SLOT);
    if (value == 0) {
        text = wmem_strdup(ctx->scope, "0 (empty)");
    } else if (slot == 5 || (slot == NO_SLOT && value > 1e9)) {
        char *when;

        if (!(value >= 0 && value < MAX_TIMESTAMP) || !(when = utc(ctx, (int64_t)floor(value), false)))
            return NULL;
        text = wmem_strdup_printf(ctx->scope, "%s UTC (%.0f)", when, value);
    } else if (slot == 0 || slot == 2) {
        char *hours = hms(ctx, value);

        if (!hours)
            return NULL;
        text = wmem_strdup_printf(ctx->scope, "%s (%.4f" DEG ")", hours, value);
    } else if (slot == 1 || slot == 3) {
        if (!(text = dms(ctx, value)))
            return NULL;
    } else if (slot == 4) {
        text = wmem_strdup_printf(ctx->scope, "%.2f" DEG, value);
    } else {
        text = wmem_strdup_printf(ctx->scope, "%.6g", value);
    }
    return slot == NO_SLOT ? text : wmem_strdup_printf(ctx->scope, "%s, %s", slot_name(ctx, slot), text);
}

static char *
decode_ssag_mount_info(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    const char *family;

    NEED(4);
    family = try_val_to_str(data[0], celestron_aux_mount_families);
    return wmem_strdup_printf(ctx->scope, "Model 0x%02x%s, mount mode %u, AZM firmware %u.%u", data[0],
               family ? wmem_strdup_printf(ctx->scope, " (%s family)", family) : "", data[1], data[2], data[3]);
}

static char *
decode_ssag_geolocation(celestron_aux_ctx_t *ctx, const uint8_t *data _U_, unsigned len, bool reply _U_)
{
    NEED(8);
    return wmem_strdup_printf(ctx->scope, "Lat %.4f, Lon %.4f",
                              tvb_get_ntohieee_float(ctx->tvb, 0), tvb_get_ntohieee_float(ctx->tvb, 4));
}

static char *
decode_ssag_time(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(4);
    return utc(ctx, EPOCH_2000 + (int64_t)pntohu32(data), true);
}

static char *
decode_dew_power(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(4);
    return wmem_strdup_printf(ctx->scope, "%g V - %g A", pntohu16(data) / 1000.0, pntohu16(data + 2) / 1000.0);
}

static char *
decode_dew_power_limit(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(4);
    return wmem_strdup_printf(ctx->scope, "%g A - %g A", pntohu16(data) / 1000.0, pntohu16(data + 2) / 1000.0);
}

static char *
decode_dew_power_ports(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return wmem_strdup_printf(ctx->scope, "%u", data[0]);
}

static const value_string dew_ports_labels[] = { { 0, "Get 12V ports" }, { 1, "Get dew heater ports" }, { 0, NULL } };
static const value_string dew_port_labels[] = { { 0, "Port 1" }, { 1, "Port 2" }, { 0, NULL } };
static const value_string dew_mode_labels[] = { { 0, "Manual" }, { 1, "Auto" }, { 0, NULL } };

static char *
decode_dew_ports(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply)
{
    if (reply)
        return wmem_strdup_printf(ctx->scope, "%u", data[0]);
    return labelled(ctx, data[0], dew_ports_labels);
}

static char *
decode_dew_status(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    char *text;

    if (!reply)
        return labelled(ctx, data[0], dew_port_labels);
    NEED(6);
    text = wmem_strdup_printf(ctx->scope, "Port %u - %s - Power: %s %u - Aggression %u", data[0],
               val_to_str(ctx->scope, data[1], dew_mode_labels, "%u"), tfs_get_string(data[2] != 0, &tfs_on_off), data[2], data[5]);
    if (data[2]) {
        NEED(10);
        text = wmem_strdup_printf(ctx->scope, "%s - Temp %g" DEG "C", text, pntohu32(data + 6) / 1000.0);
    }
    return text;
}

static char *
decode_dew_led_brightness(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return wmem_strdup_printf(ctx->scope, "Brightness %u", data[0]);
}

static char *
decode_dew_set_input_limit(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(2);
    return wmem_strdup_printf(ctx->scope, "%g A", pntohu16(data) / 1000.0);
}

static char *
decode_dew_enable_port(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    const char *state;

    NEED(2);
    state = flag_str(ctx, data[1], &tfs_on_off);
    return wmem_strdup_printf(ctx->scope, "Port %u %s", data[0], wmem_ascii_strdown(ctx->scope, state, -1));
}

static char *
decode_dew_set_aggression(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(2);
    return wmem_strdup_printf(ctx->scope, "Heater %u, aggression %u", data[0] + 1, data[1]);
}

static char *
decode_dew_set_manual_power(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    int64_t percent;

    NEED(2);
    percent = (int64_t)rint(data[1] / 2.55);
    return wmem_strdup_printf(ctx->scope, "Heater %u, power %" PRId64 "%%", data[0] + 1, percent);
}

static char *
decode_dew_recalibrate(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return wmem_strdup(ctx->scope, data[0] ? "Start" : "Stop");
}

static char *
decode_dew_is_calibrating(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return wmem_strdup(ctx->scope, data[0] ? "Calibrating" : "Not calibrating");
}

static char *
decode_dew_ambient(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(9);
    return wmem_strdup_printf(ctx->scope, "Temp: %g" DEG "C Dew: %g" DEG "C Hum: %u%%", pntohu32(data) / 1000.0,
               pntohu32(data + 4) / 1000.0, data[8]);
}

static const value_string battery_level_labels[] = { { 0, "low" }, { 1, "medium" }, { 2, "high" }, { 0, NULL } };

static char *
decode_battery_status(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    const char *level;

    if (!reply)
        return bytes_to_str_maxlen(ctx->scope, data, len, 0);
    NEED(6);
    level = try_val_to_str(data[1], battery_level_labels);
    return wmem_strdup_printf(ctx->scope, "%.3f V, status %u%s, %s", pntohu32(data + 2) / 1000000.0, data[1],
               level ? wmem_strdup_printf(ctx->scope, " (%s)", level) : "", data[0] ? "charging" : "not charging");
}

static char *
decode_wifi_enable(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return flag_str(ctx, data[0], &tfs_on_off);
}

static char *
decode_battery_current(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(2);
    return wmem_strdup_printf(ctx->scope, "%u mA", (unsigned)pntohu16(data));
}

static char *
decode_charger_mode(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply)
{
    char *state = wmem_ascii_strdown(ctx->scope, flag_str(ctx, data[0], &tfs_on_off), -1);

    return wmem_strdup_printf(ctx->scope, reply ? "Charging %s" : "Set charging %s", state);
}

static const value_string light_labels[] = { { 0, "tray" }, { 1, "logo" }, { 2, "Wi-Fi" }, { 0, NULL } };

static char *
decode_light_level(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    const char *name;
    char *light;

    if (reply)
        return wmem_strdup_printf(ctx->scope, "Level %u", data[0]);
    name = try_val_to_str(data[0], light_labels);
    light = name ? wmem_strdup(ctx->scope, name) : wmem_strdup_printf(ctx->scope, "light %u", data[0]);
    if (len >= 2)
        return wmem_strdup_printf(ctx->scope, "Set %s light to %u", light, data[1]);
    light[0] = g_ascii_toupper(light[0]);
    return wmem_strdup_printf(ctx->scope, "%s light", light);
}

static char *
decode_focuser_position(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(3);
    return wmem_strdup_printf(ctx->scope, "%u", (unsigned)pntohu24(data));
}

static char *
decode_focuser_goto(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply)
{
    if (reply)
        return labelled(ctx, data[0], ack_labels);
    NEED(3);
    return wmem_strdup_printf(ctx->scope, "To %u", (unsigned)pntohu24(data));
}

static const value_string slew_done_labels[] = { { 0, "Moving" }, { 0xff, "Done" }, { 0, NULL } };

static char *
decode_focuser_slew_done(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply _U_)
{
    return labelled(ctx, data[0], slew_done_labels);
}

static char *
decode_focuser_move_rate(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len _U_, bool reply)
{
    if (reply)
        return labelled(ctx, data[0], ack_labels);
    return wmem_strdup_printf(ctx->scope, "Rate %u", data[0]);
}

static char *
decode_focuser_limits(celestron_aux_ctx_t *ctx, const uint8_t *data, unsigned len, bool reply _U_)
{
    NEED(8);
    return wmem_strdup_printf(ctx->scope, "Limits %u to %u", (unsigned)pntohu32(data), (unsigned)pntohu32(data + 4));
}

/* BEGIN GENERATED DISPATCH: from the celestron-aux catalog */
/* The decoder of a device's command, as decoding.py registers them: the device's
 * own decoder first, then one that applies to every device. */
static celestron_aux_decoder_t
celestron_aux_decoder(uint8_t device, uint8_t command)
{
    switch (device) {
    case 0x10:
        switch (command) {
        case 0x01: return decode_motor_position;
        case 0x02: return decode_motor_position;
        case 0x05: return decode_motor_model;
        case 0x06: return decode_motor_track_rate;
        case 0x07: return decode_motor_track_rate;
        case 0x12: return decode_motor_switch_over;
        case 0x13: return decode_motor_goto_over;
        case 0x17: return decode_motor_goto2;
        case 0x23: return decode_motor_custom_rate_enabled;
        case 0x24: return decode_motor_single_byte;
        case 0x25: return decode_motor_single_byte;
        case 0x3a: return decode_motor_position;
        case 0x3b: return decode_motor_cordwrap_on;
        case 0x3c: return decode_motor_position;
        case 0x40: return decode_motor_single_byte;
        case 0x41: return decode_motor_single_byte;
        case 0x46: return decode_motor_autoguide_rate;
        case 0x47: return decode_motor_autoguide_rate;
        case 0xfc: return decode_motor_approach_direction;
        case 0xfd: return decode_motor_approach_direction;
        default: break;
        }
        break;
    case 0x11:
        switch (command) {
        case 0x01: return decode_motor_position;
        case 0x02: return decode_motor_position;
        case 0x05: return decode_motor_model;
        case 0x06: return decode_motor_track_rate;
        case 0x07: return decode_motor_track_rate;
        case 0x12: return decode_motor_switch_over;
        case 0x13: return decode_motor_goto_over;
        case 0x17: return decode_motor_goto2;
        case 0x23: return decode_motor_custom_rate_enabled;
        case 0x24: return decode_motor_single_byte;
        case 0x25: return decode_motor_single_byte;
        case 0x3a: return decode_motor_position;
        case 0x3b: return decode_motor_cordwrap_on;
        case 0x3c: return decode_motor_position;
        case 0x40: return decode_motor_single_byte;
        case 0x41: return decode_motor_single_byte;
        case 0x46: return decode_motor_autoguide_rate;
        case 0x47: return decode_motor_autoguide_rate;
        case 0xfc: return decode_motor_approach_direction;
        case 0xfd: return decode_motor_approach_direction;
        default: break;
        }
        break;
    case 0x12:
        switch (command) {
        case 0x01: return decode_focuser_position;
        case 0x02: return decode_focuser_goto;
        case 0x13: return decode_focuser_slew_done;
        case 0x24: return decode_focuser_move_rate;
        case 0x25: return decode_focuser_move_rate;
        case 0x2c: return decode_focuser_limits;
        default: break;
        }
        break;
    case 0x17:
        switch (command) {
        case 0x00: return decode_dew_power;
        case 0x02: return decode_dew_led_brightness;
        case 0x03: return decode_dew_set_input_limit;
        case 0x04: return decode_dew_power_limit;
        case 0x10: return decode_dew_power_ports;
        case 0x11: return decode_dew_ports;
        case 0x12: return decode_dew_status;
        case 0x14: return decode_dew_enable_port;
        case 0x16: return decode_dew_set_aggression;
        case 0x17: return decode_dew_set_manual_power;
        case 0x18: return decode_dew_ambient;
        case 0x19: return decode_dew_recalibrate;
        case 0x1a: return decode_dew_is_calibrating;
        case 0x20: return decode_dew_led_brightness;
        default: break;
        }
        break;
    case 0xb0:
        switch (command) {
        case 0x01: return decode_gps_coordinate;
        case 0x02: return decode_gps_coordinate;
        case 0x03: return decode_gps_date;
        case 0x04: return decode_gps_year;
        case 0x07: return decode_gps_satellites;
        case 0x33: return decode_gps_time;
        case 0x36: return decode_gps_flag;
        case 0x37: return decode_gps_flag;
        case 0x55: return decode_gps_hardware_version;
        default: break;
        }
        break;
    case 0xb4:
        switch (command) {
        case 0x3f: return decode_starsense_align_center;
        case 0x91: return decode_starsense_status;
        case 0x92: return decode_starsense_status;
        case 0x94: return decode_starsense_status;
        case 0x9f: return decode_starsense_status;
        default: break;
        }
        break;
    case 0xb5:
        switch (command) {
        case 0x10: return decode_wifi_enable;
        default: break;
        }
        break;
    case 0xb6:
        switch (command) {
        case 0x10: return decode_battery_status;
        case 0x18: return decode_battery_current;
        default: break;
        }
        break;
    case 0xb7:
        switch (command) {
        case 0x10: return decode_charger_mode;
        default: break;
        }
        break;
    case 0xb9:
        switch (command) {
        case 0x02: return decode_ssag_plate_status;
        case 0x03: return decode_ssag_start_calibrate;
        case 0x04: return decode_ssag_calibrate_status;
        case 0x20: return decode_ssag_set_guiding;
        case 0x30: return decode_ssag_mount_info;
        case 0x31: return decode_ssag_geolocation;
        case 0x32: return decode_ssag_time;
        case 0x45: return decode_ssag_image_rotation;
        default: break;
        }
        break;
    case 0xbd:
        switch (command) {
        case 0x02: return decode_ssag_plate_status;
        case 0x03: return decode_ssag_start_calibrate;
        case 0x04: return decode_ssag_calibrate_status;
        case 0x07: return decode_ss2_is_calibrated;
        case 0x08: return decode_ss2_calibration_data;
        case 0x13: return decode_ss2_set_aspa;
        case 0x15: return decode_ss2_aspa_pole;
        case 0x16: return decode_ss2_aspa_error;
        case 0x17: return decode_ss2_aspa_progress;
        case 0x30: return decode_ssag_mount_info;
        case 0x31: return decode_ssag_geolocation;
        case 0x32: return decode_ssag_time;
        case 0x45: return decode_ssag_image_rotation;
        case 0x4b: return decode_ssag_plate_status;
        default: break;
        }
        break;
    case 0xbf:
        switch (command) {
        case 0x10: return decode_light_level;
        default: break;
        }
        break;
    default:
        break;
    }
    switch (command) {
    case 0xfe: return decode_version;
    default:
        return NULL;
    }
}
/* END GENERATED DISPATCH */

/* --- frames ------------------------------------------------------------------ */

/* The device a packet is about: command numbers belong to it. */
static uint8_t
subject_device(uint8_t src, uint8_t dst)
{
    if (src == CELESTRON_AUX_SCANNER)
        return dst;
    if (dst == CELESTRON_AUX_SCANNER)
        return src;
    if (celestron_aux_is_motor_client(src) && celestron_aux_is_motor(dst))
        return dst;
    return celestron_aux_is_controller(src) ? dst : src;
}

static const char *
command_name(uint8_t device, uint8_t command)
{
    const value_string *table = celestron_aux_command_table(device);
    const char *name = table ? try_val_to_str(command, table) : NULL;

    if (!name)
        name = try_val_to_str(command, celestron_aux_generic_commands);
    return name ? name : "Unknown";
}

static const char *
device_name(uint8_t addr)
{
    return val_to_str_const(addr, celestron_aux_devices, "Unknown");
}

/* Reads one logical byte of a StarSense frame at *offset, undoing 3B 02 02
 * escapes. Returns false when the buffer ends first. */
static bool
starsense_byte(tvbuff_t *tvb, unsigned *offset, uint8_t *byte)
{
    unsigned available = tvb_captured_length(tvb);

    if (*offset >= available)
        return false;
    *byte = tvb_get_uint8(tvb, *offset);
    if (*byte != AUX_PREAMBLE) {
        *offset += 1;
        return true;
    }
    if (*offset + 2 >= available)
        return false;
    *offset += (tvb_get_uint8(tvb, *offset + 1) == 2 && tvb_get_uint8(tvb, *offset + 2) == 2) ? 3 : 1;
    return true;
}

#define NEED_MORE 0
#define NO_FRAME  -1

/* The size of the frame starting at offset, NEED_MORE when the buffer ends
 * first, or NO_FRAME when no frame can start there (as celestron-aux's parser). */
static int
frame_length(tvbuff_t *tvb, unsigned offset)
{
    unsigned available = tvb_captured_length_remaining(tvb, offset);
    uint8_t first = tvb_get_uint8(tvb, offset);

    if (first == AUX_PREAMBLE) {
        unsigned length;

        if (available < 2)
            return NEED_MORE;
        length = tvb_get_uint8(tvb, offset + 1);
        if (length < AUX_MIN_LENGTH)
            return NO_FRAME;
        return available < length + 3 ? NEED_MORE : (int)(length + 3);
    }
    if (first == STARSENSE_PREAMBLE) {
        unsigned position = offset + 1;
        uint32_t payload = 0;
        uint8_t byte;

        for (int i = 0; i < 4; i++) {
            if (!starsense_byte(tvb, &position, &byte))
                return NEED_MORE;
            payload = (payload << 8) | byte;
        }
        if (payload > STARSENSE_MAX_PAYLOAD)
            return NO_FRAME;
        for (uint32_t i = 0; i < payload; i++)
            if (!starsense_byte(tvb, &position, &byte))
                return NEED_MORE;
        if (position >= tvb_captured_length(tvb))
            return NEED_MORE;
        return (int)(position + 1 - offset);
    }
    return NO_FRAME;
}

/* The checksum a frame should end with: the two's complement of the sum of
 * its bytes after the preamble (unescaped, for a StarSense frame). */
static uint8_t
expected_checksum(tvbuff_t *tvb, unsigned offset, unsigned size)
{
    uint32_t sum = 0;

    if (tvb_get_uint8(tvb, offset) == AUX_PREAMBLE) {
        for (unsigned i = offset + 1; i < offset + size - 1; i++)
            sum += tvb_get_uint8(tvb, i);
    } else {
        unsigned position = offset + 1;
        uint8_t byte;

        while (position < offset + size - 1 && starsense_byte(tvb, &position, &byte))
            sum += byte;
    }
    return (uint8_t)((0x100 - (sum & 0xff)) & 0xff);
}

static bool
checksum_ok(tvbuff_t *tvb, unsigned offset, unsigned size)
{
    return tvb_get_uint8(tvb, offset + size - 1) == expected_checksum(tvb, offset, size);
}

static char *
dissect_aux_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned key)
{
    unsigned length = tvb_get_uint8(tvb, 1);
    unsigned data_length = length - AUX_MIN_LENGTH;
    uint8_t src = tvb_get_uint8(tvb, 2);
    uint8_t dst = tvb_get_uint8(tvb, 3);
    uint8_t cmd = tvb_get_uint8(tvb, 4);
    uint8_t device = subject_device(src, dst);
    const char *name = command_name(device, cmd);
    char *value = NULL;
    bool unexpected = false;
    const char *shown;
    proto_item *ti;

    proto_item_append_text(proto_tree_get_parent(tree), ", %s -> %s, %s", device_name(src), device_name(dst), name);
    proto_tree_add_item(tree, hf_celestron_aux_preamble, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(tree, hf_celestron_aux_length, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_celestron_aux_src, tvb, 2, 1, ENC_NA);
    proto_tree_add_item(tree, hf_celestron_aux_dst, tvb, 3, 1, ENC_NA);
    ti = proto_tree_add_item(tree, hf_celestron_aux_cmd, tvb, 4, 1, ENC_NA);
    proto_item_append_text(ti, " (%s)", name);
    proto_tree_add_string(tree, hf_celestron_aux_cmd_name, tvb, 4, 1, name);

    if (data_length > 0) {
        celestron_aux_decoder_t decoder = celestron_aux_decoder(device, cmd);
        const uint8_t *data = tvb_get_ptr(tvb, 5, data_length);

        proto_tree_add_item(tree, hf_celestron_aux_data, tvb, 5, data_length, ENC_NA);
        if (decoder) {
            celestron_aux_ctx_t ctx = { pinfo->pool, pinfo, key, tvb_new_subset_length(tvb, 5, data_length) };

            value = decoder(&ctx, data, data_length, src == device);
            unexpected = (value == NULL);
        }
        if (value) {
            proto_tree_add_string(tree, hf_celestron_aux_value, tvb, 5, data_length, value);
            proto_item_append_text(proto_tree_get_parent(tree), ", %s", value);
        } else if (unexpected) {
            proto_tree_add_expert(tree, pinfo, &ei_celestron_aux_unexpected_format, tvb, 5, data_length);
        }
    }

    proto_tree_add_checksum(tree, tvb, length + 2, hf_celestron_aux_checksum, hf_celestron_aux_checksum_status,
                            &ei_celestron_aux_bad_checksum, pinfo, expected_checksum(tvb, 0, length + 3), ENC_NA,
                            PROTO_CHECKSUM_VERIFY);

    /* As celestron-aux's own log: the decoded value, else the data in hex. */
    if (value)
        shown = value;
    else if (data_length > 0)
        shown = wmem_strdup_printf(pinfo->pool, "%s%s", tvb_bytes_to_str(pinfo->pool, tvb, 5, data_length),
                                   unexpected ? " (unexpected format)" : "");
    else
        shown = "";
    return wmem_strdup_printf(pinfo->pool, "%s -> %s  %s (0x%02x)%s%s%s", device_name(src), device_name(dst),
                              name, cmd, *shown ? " " : "", shown, checksum_ok(tvb, 0, length + 3) ? "" : "  [bad checksum]");
}

static char *
dissect_starsense_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned size = tvb_captured_length(tvb);
    unsigned position = 1;
    uint32_t payload = 0;
    uint8_t byte;
    bool ok = checksum_ok(tvb, 0, size);

    proto_tree_add_item(tree, hf_celestron_aux_preamble, tvb, 0, 1, ENC_NA);
    for (int i = 0; i < 4; i++) {
        starsense_byte(tvb, &position, &byte);   /* frame_length checked the frame is complete */
        payload = (payload << 8) | byte;
    }
    proto_item_append_text(proto_tree_get_parent(tree), ", StarSense star list, %u stars", payload / 8);
    proto_tree_add_uint(tree, hf_celestron_aux_starsense_length, tvb, 1, position - 1, payload);
    proto_item_set_generated(proto_tree_add_uint(tree, hf_celestron_aux_starsense_stars, tvb, 1, position - 1,
                                                 payload / 8));
    proto_tree_add_item(tree, hf_celestron_aux_starsense_data, tvb, position, size - 1 - position, ENC_NA);
    proto_tree_add_checksum(tree, tvb, size - 1, hf_celestron_aux_checksum, hf_celestron_aux_checksum_status,
                            &ei_celestron_aux_bad_checksum, pinfo, expected_checksum(tvb, 0, size), ENC_NA,
                            PROTO_CHECKSUM_VERIFY);
    return wmem_strdup_printf(pinfo->pool, "StarSense star list, %u stars%s", payload / 8,
                              ok ? "" : "  [bad checksum]");
}

/* Dissects every frame in tvb. Over TCP a frame can span segments: then it
 * asks for more data, as the bus is a plain byte stream. */
static int
dissect_frames(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool can_desegment)
{
    unsigned offset = 0;
    unsigned captured = tvb_captured_length(tvb);
    wmem_strbuf_t *info = wmem_strbuf_new(pinfo->pool, "");
    bool any = false;

    while (offset < captured) {
        int size = frame_length(tvb, offset);
        proto_item *ti;
        proto_tree *frame_tree;

        if (size == NEED_MORE && can_desegment) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            break;
        }
        if (size == NEED_MORE) {
            ti = proto_tree_add_item(tree, proto_celestron_aux, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, ti, &ei_celestron_aux_cut_short);
            wmem_strbuf_append_printf(info, "%sFrame cut short", any ? " | " : "");
            any = true;
            offset = captured;
        } else if (size == NO_FRAME) {
            unsigned stop = offset + 1;

            while (stop < captured && tvb_get_uint8(tvb, stop) != AUX_PREAMBLE &&
                   tvb_get_uint8(tvb, stop) != STARSENSE_PREAMBLE)
                stop++;
            ti = proto_tree_add_item(tree, proto_celestron_aux, tvb, offset, stop - offset, ENC_NA);
            proto_item_append_text(ti, ", bytes outside any frame");
            expert_add_info(pinfo, ti, &ei_celestron_aux_outside_frame);
            wmem_strbuf_append_printf(info, "%sBytes outside any frame", any ? " | " : "");
            any = true;
            offset = stop;
        } else {
            tvbuff_t *frame = tvb_new_subset_length(tvb, offset, size);
            char *text;

            ti = proto_tree_add_item(tree, proto_celestron_aux, tvb, offset, size, ENC_NA);
            frame_tree = proto_item_add_subtree(ti, ett_celestron_aux);
            if (tvb_get_uint8(frame, 0) == AUX_PREAMBLE)
                text = dissect_aux_packet(frame, pinfo, frame_tree, offset);
            else
                text = dissect_starsense_frame(frame, pinfo, frame_tree);
            wmem_strbuf_append_printf(info, "%s%s", any ? " | " : "", text);
            any = true;
            /* After a bad checksum, move on one byte only, as celestron-aux's own
             * parser does: the "frame" may be noise whose length byte swallowed
             * real frames, which are found again by resynchronising. */
            offset += checksum_ok(tvb, offset, size) ? (unsigned)size : 1;
        }
    }
    /* Columns only for complete frames: a segment holding just the start of a
     * frame stays TCP until the frame is reassembled. */
    if (any) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Celestron AUX");
        col_add_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(info));
    }
    return captured;
}

/* One frame (or a celestron-aux mark) per record, as in exported pcap files. */
static int
dissect_celestron_aux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    unsigned captured = tvb_captured_length(tvb);

    if (captured == 0)
        return 0;
    if (captured >= MARK_PREFIX_LEN && tvb_memeql(tvb, 0, (const uint8_t *)MARK_PREFIX, MARK_PREFIX_LEN) == 0) {
        proto_item *ti = proto_tree_add_item(tree, proto_celestron_aux, tvb, 0, -1, ENC_NA);
        proto_tree *mark_tree = proto_item_add_subtree(ti, ett_celestron_aux);
        const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, MARK_PREFIX_LEN,
                                                            captured - MARK_PREFIX_LEN, ENC_UTF_8);

        proto_tree_add_string(mark_tree, hf_celestron_aux_mark, tvb, 0, -1, text);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MARK");
        col_add_fstr(pinfo->cinfo, COL_INFO, "MARK: %s", text);
        return captured;
    }
    return dissect_frames(tvb, pinfo, tree, false);
}

static int
dissect_celestron_aux_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (tvb_captured_length(tvb) == 0)
        return 0;
    return dissect_frames(tvb, pinfo, tree, pinfo->can_desegment > 0);
}

/* A TCP payload that starts with a complete AUX packet whose checksum is right. */
static bool
dissect_celestron_aux_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    unsigned captured = tvb_captured_length(tvb);
    unsigned length;
    uint32_t sum = 0;

    if (captured < 6 || tvb_get_uint8(tvb, 0) != AUX_PREAMBLE)
        return false;
    length = tvb_get_uint8(tvb, 1);
    if (length < AUX_MIN_LENGTH || captured < length + 3)
        return false;
    for (unsigned i = 1; i < length + 2; i++)
        sum += tvb_get_uint8(tvb, i);
    if (tvb_get_uint8(tvb, length + 2) != ((0x100 - (sum & 0xff)) & 0xff))
        return false;
    conversation_set_dissector(find_or_create_conversation(pinfo), celestron_aux_tcp_handle);
    dissect_celestron_aux_tcp(tvb, pinfo, tree, data);
    return true;
}

void
proto_register_celestron_aux(void)
{
    static hf_register_info hf[] = {
        { &hf_celestron_aux_preamble,
          { "Preamble", "celestron_aux.preamble", FT_UINT8, BASE_HEX, NULL, 0x0,
            "0x3b for an AUX packet, 0x3c for a StarSense frame", HFILL }},
        { &hf_celestron_aux_length,
          { "Length", "celestron_aux.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Bytes from source to the end of the data", HFILL }},
        { &hf_celestron_aux_src,
          { "Source", "celestron_aux.src", FT_UINT8, BASE_HEX, VALS(celestron_aux_devices), 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_dst,
          { "Destination", "celestron_aux.dst", FT_UINT8, BASE_HEX, VALS(celestron_aux_devices), 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_cmd,
          { "Command", "celestron_aux.cmd", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Command number, named by the device the packet is about", HFILL }},
        { &hf_celestron_aux_cmd_name,
          { "Command name", "celestron_aux.cmd_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_data,
          { "Data", "celestron_aux.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_value,
          { "Value", "celestron_aux.value", FT_STRING, BASE_NONE, NULL, 0x0,
            "The data decoded", HFILL }},
        { &hf_celestron_aux_checksum,
          { "Checksum", "celestron_aux.checksum", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_checksum_status,
          { "Checksum Status", "celestron_aux.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_starsense_length,
          { "StarSense payload length", "celestron_aux.starsense.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_starsense_stars,
          { "Stars", "celestron_aux.starsense.stars", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_starsense_data,
          { "StarSense frame (escaped)", "celestron_aux.starsense.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_celestron_aux_mark,
          { "Mark", "celestron_aux.mark", FT_STRING, BASE_NONE, NULL, 0x0,
            "A note taken while recording with celestron-aux", HFILL }},
    };

    static int *ett[] = {
        &ett_celestron_aux,
    };

    static ei_register_info ei[] = {
        { &ei_celestron_aux_bad_checksum,
          { "celestron_aux.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_celestron_aux_unexpected_format,
          { "celestron_aux.unexpected_format", PI_PROTOCOL, PI_WARN,
            "Data does not fit the command's known format", EXPFILL }},
        { &ei_celestron_aux_outside_frame,
          { "celestron_aux.outside_frame", PI_MALFORMED, PI_ERROR, "Bytes outside any frame", EXPFILL }},
        { &ei_celestron_aux_cut_short,
          { "celestron_aux.cut_short", PI_MALFORMED, PI_ERROR, "Frame cut short", EXPFILL }},
    };

    expert_module_t *expert_celestron_aux;

    proto_celestron_aux = proto_register_protocol("Celestron AUX bus", "Celestron AUX", "celestron_aux");
    proto_register_field_array(proto_celestron_aux, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_celestron_aux = expert_register_protocol(proto_celestron_aux);
    expert_register_field_array(expert_celestron_aux, ei, array_length(ei));

    /* celestron_aux_handle = */ register_dissector("celestron_aux", dissect_celestron_aux, proto_celestron_aux);
    celestron_aux_tcp_handle = register_dissector("celestron_aux.tcp", dissect_celestron_aux_tcp,
                                                  proto_celestron_aux);
}

void
proto_reg_handoff_celestron_aux(void)
{
    /* TCP port 2000 is Skinny's, so no port by default: use Decode As, the
     * TCP port preference, or the heuristic. */
    dissector_add_for_decode_as_with_preference("tcp.port", celestron_aux_tcp_handle);
    heur_dissector_add("tcp", dissect_celestron_aux_heur_tcp, "Celestron AUX over TCP",
                       "celestron_aux_tcp", proto_celestron_aux, HEURISTIC_DISABLE);
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
