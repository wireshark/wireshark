/* packet-rdm-etc.c
 * Manufacturer-Specific extensions to RDM for ETC.
 *
 * This dissector is written by
 *
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2003, 2011, 2012 Erwin Rol
 *
 *  Shaun Jackman <sjackman@gmail.com>
 *  Copyright 2006 Pathway Connectivity
 *
 *  Matt Morris <mattm.dev.1[AT]gmail.com>
 *  Copyright (c) 2025
 *
 *  Wireshark - Network traffic analyzer
 *  Gerald Combs <gerald@wireshark.org>
 *  Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-rdm.h"

#define RDM_CC_DISCOVERY_COMMAND           0x10
#define RDM_CC_DISCOVERY_COMMAND_RESPONSE  0x11
#define RDM_CC_GET_COMMAND                 0x20
#define RDM_CC_GET_COMMAND_RESPONSE        0x21
#define RDM_CC_SET_COMMAND                 0x30
#define RDM_CC_SET_COMMAND_RESPONSE        0x31

static const value_string true_false_vals[] = {
  { 0x00,  "False" },
  { 0x01,  "True" },
  { 0, NULL },
};

static const value_string enabled_disabled_vals[] = {
  { 0x00,  "Disabled" },
  { 0x01,  "Enabled" },
  { 0, NULL },
};
static const value_string on_off_vals[] = {
  { 0x00,  "Off" },
  { 0x01,  "On" },
  { 0, NULL },
};

static int proto_rdm_ext;

static dissector_handle_t rdm_etc_handle;

/* ETC manufacturer-specific PIDs */
#define ETC_PARAM_ID_LED_CURVE                             0x8101
#define ETC_PARAM_ID_LED_CURVE_DESCRIPTION                 0x8102
#define ETC_PARAM_ID_LED_STROBE                            0x8103
#define ETC_PARAM_ID_LED_OUTPUT_MODE                       0x8104
#define ETC_PARAM_ID_LED_OUTPUT_MODE_DESCRIPTION           0x8105
#define ETC_PARAM_ID_LED_RED_SHIFT                         0x8106
#define ETC_PARAM_ID_LED_WHITE_POINT                       0x8107
#define ETC_PARAM_ID_LED_WHITE_POINT_DESCRIPTION           0x8108
#define ETC_PARAM_ID_LED_FREQUENCY                         0x8109
#define ETC_PARAM_ID_DMX_LOSS_BEHAVIOR                     0x810A
#define ETC_PARAM_ID_DMX_LOSS_BEHAVIOR_DESCRIPTION         0x810B
#define ETC_PARAM_ID_LED_PLUS_SEVEN                        0x810C
#define ETC_PARAM_ID_BACKLIGHT_BRIGHTNESS                  0x810D
#define ETC_PARAM_ID_BACKLIGHT_TIMEOUT                     0x810E
#define ETC_PARAM_ID_STATUS_INDICATORS                     0x810F
#define ETC_PARAM_ID_RECALIBRATE_FIXTURE                   0x8110
#define ETC_PARAM_ID_OVERTEMPMODE                          0x8111
#define ETC_PARAM_ID_SIMPLESETUPMODE                       0x8112
#define ETC_PARAM_ID_LED_STROBE_DESCRIPTION                0x8113
#define ETC_PARAM_ID_LED_RED_SHIFT_DESCRIPTION             0x8114
#define ETC_PARAM_ID_LED_PLUS_SEVEN_DESCRIPTION            0x8115
#define ETC_PARAM_ID_BACKLIGHT_TIMEOUT_DESCRIPTION         0x8116
#define ETC_PARAM_ID_SIMPLESETUPMODE_DESCRIPTION           0x8117
#define ETC_PARAM_ID_OVERTEMPMODE_DESCRIPTION              0x8118
#define ETC_PARAM_ID_LED_REQUESTED_XY                      0x8119
#define ETC_PARAM_ID_LED_CURRENT_XY                        0x811A
#define ETC_PARAM_ID_LED_CURRENT_PWM                       0x811B
#define ETC_PARAM_ID_LED_TRISTIMULUS                       0x811C
#define ETC_PARAM_ID_LED_INFORMATION                       0x811D
#define ETC_PARAM_ID_PRESETCONFIG                          0x811E
#define ETC_PARAM_ID_SEQUENCE_PLAYBACK                     0x811F
#define ETC_PARAM_ID_SEQUENCE_CONFIG                       0x8120
#define ETC_PARAM_ID_LOW_POWER_TIMEOUT                     0x8121
#define ETC_PARAM_ID_LOW_POWER_TIMEOUT_DESCRIPTION         0x8122
#define ETC_PARAM_ID_LED_ENUM_FREQUENCY                    0x8123
#define ETC_PARAM_ID_LED_ENUM_FREQUENCY_DESCRIPTION        0x8124
#define ETC_PARAM_ID_RGBI_PRESETCONFIG                     0x8125
#define ETC_PARAM_ID_CCT_PRESETCONFIG                      0x8126
#define ETC_PARAM_ID_SUPPLEMENTARY_DEVICE_VERSION          0x8130
/* do not display
#define ETC_PARAM_ID_START_UWB_DISCOVER                    0x8150
#define ETC_PARAM_ID_START_UWB_MEASURE                     0x8151
#define ETC_PARAM_ID_POSITION                              0x8152
*/
#define ETC_PARAM_ID_S4DIM_CALIBRATE                       0x9000
#define ETC_PARAM_ID_S4DIM_CALIBRATE_DESCRIPTION           0x9001
#define ETC_PARAM_ID_S4DIM_TEST_MODE                       0x9002
#define ETC_PARAM_ID_S4DIM_TEST_MODE_DESCRIPTION           0x9003
#define ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE              0x9004
#define ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE_DESCRIPTION  0x9005
#define ETC_PARAM_ID_POWER_COMMAND                         0xA000
#define ETC_PARAM_ID_POWER_COMMAND_DESCRIPTION             0xA001
#define ETC_PARAM_ID_THRESHOLD_COMMAND                     0xA002
#define ETC_PARAM_ID_TURNON_DELAY_COMMAND                  0xA003
#define ETC_PARAM_ID_SET_DALI_SHORTADDRESS                 0xA004
#define ETC_PARAM_ID_DALI_GROUP_MEMBERSHIP                 0xA005
#define ETC_PARAM_ID_AUTOBIND                              0xA006
#define ETC_PARAM_ID_DELETE_SUBDEVICE                      0xA007
#define ETC_PARAM_ID_PACKET_DELAY                          0xB000
#define ETC_PARAM_ID_HAS_ENUM_TEXT                         0xE000
#define ETC_PARAM_ID_GET_ENUM_TEXT                         0xE001
#define ETC_PARAM_ID_PREPAREFORSOFTWAREDOWNLOAD            0xF000

static const value_string etc_param_id_vals[] = {
  { ETC_PARAM_ID_LED_CURVE,                             "LED Curve" },
  { ETC_PARAM_ID_LED_CURVE_DESCRIPTION,                 "LED Curve Description" },
  { ETC_PARAM_ID_LED_STROBE,                            "LED Strobe" },
  { ETC_PARAM_ID_LED_OUTPUT_MODE,                       "LED Output Mode" },
  { ETC_PARAM_ID_LED_OUTPUT_MODE_DESCRIPTION,           "LED Output Mode Description" },
  { ETC_PARAM_ID_LED_RED_SHIFT,                         "LED Red Shift" },
  { ETC_PARAM_ID_LED_WHITE_POINT,                       "LED White Point" },
  { ETC_PARAM_ID_LED_WHITE_POINT_DESCRIPTION,           "LED White Point Description" },
  { ETC_PARAM_ID_LED_FREQUENCY,                         "LED Frequency" },
  { ETC_PARAM_ID_DMX_LOSS_BEHAVIOR,                     "DMX Loss Behavior" },
  { ETC_PARAM_ID_DMX_LOSS_BEHAVIOR_DESCRIPTION,         "DMX Loss Behavior Description" },
  { ETC_PARAM_ID_LED_PLUS_SEVEN,                        "LED Plus Seven" },
  { ETC_PARAM_ID_BACKLIGHT_BRIGHTNESS,                  "Backlight Brightness" },
  { ETC_PARAM_ID_BACKLIGHT_TIMEOUT,                     "Backlight Timeout" },
  { ETC_PARAM_ID_STATUS_INDICATORS,                     "Status Indicators" },
  { ETC_PARAM_ID_RECALIBRATE_FIXTURE,                   "Recalibrate Fixture" },
  { ETC_PARAM_ID_OVERTEMPMODE,                          "Overtemp Mode" },
  { ETC_PARAM_ID_SIMPLESETUPMODE,                       "Simple Setup Mode" },
  { ETC_PARAM_ID_LED_STROBE_DESCRIPTION,                "LED Strobe Description" },
  { ETC_PARAM_ID_LED_RED_SHIFT_DESCRIPTION,             "LED Red Shift Description" },
  { ETC_PARAM_ID_LED_PLUS_SEVEN_DESCRIPTION,            "LED Plus Seven Description" },
  { ETC_PARAM_ID_BACKLIGHT_TIMEOUT_DESCRIPTION,         "Backlight Timeout Description" },
  { ETC_PARAM_ID_SIMPLESETUPMODE_DESCRIPTION,           "Simple Setup Mode Description" },
  { ETC_PARAM_ID_OVERTEMPMODE_DESCRIPTION,              "Overtemp Mode Description" },
  { ETC_PARAM_ID_LED_REQUESTED_XY,                      "LED Requested XY" },
  { ETC_PARAM_ID_LED_CURRENT_XY,                        "LED Current XY" },
  { ETC_PARAM_ID_LED_CURRENT_PWM,                       "LED Current PWM" },
  { ETC_PARAM_ID_LED_TRISTIMULUS,                       "LED Tristimulus" },
  { ETC_PARAM_ID_LED_INFORMATION,                       "LED Information" },
  { ETC_PARAM_ID_PRESETCONFIG,                          "Preset Config" },
  { ETC_PARAM_ID_SEQUENCE_PLAYBACK,                     "Sequence Playback" },
  { ETC_PARAM_ID_SEQUENCE_CONFIG,                       "Sequence Config" },
  { ETC_PARAM_ID_LOW_POWER_TIMEOUT,                     "Low Power Timeout" },
  { ETC_PARAM_ID_LOW_POWER_TIMEOUT_DESCRIPTION,         "Low Power Timeout Description" },
  { ETC_PARAM_ID_LED_ENUM_FREQUENCY,                    "LED Enum Frequency" },
  { ETC_PARAM_ID_LED_ENUM_FREQUENCY_DESCRIPTION,        "LED Enum Frequency Description" },
  { ETC_PARAM_ID_RGBI_PRESETCONFIG,                     "RGBI Preset Config" },
  { ETC_PARAM_ID_CCT_PRESETCONFIG,                      "CCT Preset Config" },
  { ETC_PARAM_ID_SUPPLEMENTARY_DEVICE_VERSION,          "Supplementary Device Version" },
  /* do not display
  { ETC_PARAM_ID_START_UWB_DISCOVER,                    "Start UWB Discover" },
  { ETC_PARAM_ID_START_UWB_MEASURE,                     "Start UWB Measure" },
  { ETC_PARAM_ID_POSITION,                              "Position" },
  */
  { ETC_PARAM_ID_S4DIM_CALIBRATE,                       "S4Dimmer Calibrate" },
  { ETC_PARAM_ID_S4DIM_CALIBRATE_DESCRIPTION,           "S4Dimmer Calibrate Description" },
  { ETC_PARAM_ID_S4DIM_TEST_MODE,                       "S4Dimmer Test Mode" },
  { ETC_PARAM_ID_S4DIM_TEST_MODE_DESCRIPTION,           "S4Dimmer Test Mode Description" },
  { ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE,              "S4Dimmer Max Output Voltage" },
  { ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE_DESCRIPTION,  "S4Dimmer Max Output Voltage Description" },
  { ETC_PARAM_ID_POWER_COMMAND,                         "Power Command" },
  { ETC_PARAM_ID_POWER_COMMAND_DESCRIPTION,             "Power Command Description" },
  { ETC_PARAM_ID_THRESHOLD_COMMAND,                     "Threshold Command" },
  { ETC_PARAM_ID_TURNON_DELAY_COMMAND,                  "Turn On Delay Command" },
  { ETC_PARAM_ID_SET_DALI_SHORTADDRESS,                 "Set DALI Short Address" },
  { ETC_PARAM_ID_DALI_GROUP_MEMBERSHIP,                 "DALI Group Membership" },
  { ETC_PARAM_ID_AUTOBIND,                              "Auto Bind" },
  { ETC_PARAM_ID_DELETE_SUBDEVICE,                      "Delete Subdevice" },
  { ETC_PARAM_ID_PACKET_DELAY,                          "Packet Delay" },
  { ETC_PARAM_ID_HAS_ENUM_TEXT,                         "Has Enum Text" },
  { ETC_PARAM_ID_GET_ENUM_TEXT,                         "Get Enum Text" },
  { ETC_PARAM_ID_PREPAREFORSOFTWAREDOWNLOAD,            "Prepare For Software Load" },
  { 0, NULL },
};

value_string_ext etc_param_id_vals_ext = VALUE_STRING_EXT_INIT(etc_param_id_vals);

#define ETC_LED_CURVE_STANDARD      0x00
#define ETC_LED_CURVE_INCANDESCENT  0x01
#define ETC_LED_CURVE_LINEAR        0x02
#define ETC_LED_CURVE_QUICK         0x03

static const value_string etc_led_curve_vals[] = {
  { ETC_LED_CURVE_STANDARD,      "Standard" },
  { ETC_LED_CURVE_INCANDESCENT,  "Incandescent" },
  { ETC_LED_CURVE_LINEAR,        "Linear" },
  { ETC_LED_CURVE_QUICK,         "Quick" },
  { 0, NULL },
};

#define ETC_LED_OUTPUT_MODE_REGULATED  0x00
#define ETC_LED_OUTPUT_MODE_BOOST      0x01
#define ETC_LED_OUTPUT_MODE_PROTECTED  0x02

static const value_string etc_led_output_mode_vals[] = {
  { ETC_LED_OUTPUT_MODE_REGULATED,  "Regulated" },
  { ETC_LED_OUTPUT_MODE_BOOST,      "Boost" },
  { ETC_LED_OUTPUT_MODE_PROTECTED,  "Protected" },
  { 0, NULL },
};

#define ETC_LED_WHITE_POINT_2950K    0x00
#define ETC_LED_WHITE_POINT_3200K    0x01
#define ETC_LED_WHITE_POINT_5600K    0x02
#define ETC_LED_WHITE_POINT_6500K    0x03

static const value_string etc_led_white_point_vals[] = {
  { ETC_LED_WHITE_POINT_2950K,    "2950 K" },
  { ETC_LED_WHITE_POINT_3200K,    "3200 K" },
  { ETC_LED_WHITE_POINT_5600K,    "5600 K" },
  { ETC_LED_WHITE_POINT_6500K,    "6500 K" },
  { 0, NULL },
};

#define ETC_DMX_LOSS_BEHAVIOR_INSTANT   0x00
#define ETC_DMX_LOSS_BEHAVIOR_WAIT2MIN  0x01
#define ETC_DMX_LOSS_BEHAVIOR_HLL       0x02

static const value_string etc_dmx_data_loss_vals[] = {
  { ETC_DMX_LOSS_BEHAVIOR_INSTANT,   "Instant" },
  { ETC_DMX_LOSS_BEHAVIOR_WAIT2MIN,  "Hold Last Look 2 Minutes" },
  { ETC_DMX_LOSS_BEHAVIOR_HLL,       "Hold Last Look Forever" },
  { 0, NULL },
};

#define ETC_DMX_BACKLIGHT_TIMEOUT_NEVER  0x00
#define ETC_DMX_BACKLIGHT_TIMEOUT_30SEC  0x01
#define ETC_DMX_BACKLIGHT_TIMEOUT_1MIN   0x02
#define ETC_DMX_BACKLIGHT_TIMEOUT_5MIN   0x03
#define ETC_DMX_BACKLIGHT_TIMEOUT_15MIN  0x04

static const value_string etc_backlight_timeout_vals[] = {
  { ETC_DMX_BACKLIGHT_TIMEOUT_NEVER,  "Never" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_30SEC,  "30 Seconds" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_1MIN,   "1 Minute" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_5MIN,   "5 Minute" },
  { ETC_DMX_BACKLIGHT_TIMEOUT_15MIN,  "15 Minute" },
  { 0, NULL },
};

#define ETC_OVERTEMP_MODE_DARK     0x00
#define ETC_OVERTEMP_MODE_VISIBLE  0x01

static const value_string etc_overtemp_mode_vals[] = {
  { ETC_OVERTEMP_MODE_DARK,     "Dark When Overtemp" },
  { ETC_OVERTEMP_MODE_VISIBLE,  "Red When Overtemp" },
  { 0, NULL },
};

#define ETC_EASY_MODE_GENERAL   0x00
#define ETC_EASY_MODE_STAGE     0x01
#define ETC_EASY_MODE_ARCH      0x02
#define ETC_EASY_MODE_EFFECTS   0x03
#define ETC_EASY_MODE_STUDIO    0x04
#define ETC_EASY_MODE_ADVANCED  0x05

static const value_string etc_simple_setup_mode_vals[] = {
  { ETC_EASY_MODE_GENERAL,   "General Use" },
  { ETC_EASY_MODE_STAGE,     "Stage Setup" },
  { ETC_EASY_MODE_ARCH,      "Arch Setup" },
  { ETC_EASY_MODE_EFFECTS,   "Effects Setup" },
  { ETC_EASY_MODE_STUDIO,    "Studio Setup" },
  { ETC_EASY_MODE_ADVANCED,  "Advanced Setup" },
  { 0, NULL },
};

#define ETC_LOW_POWER_TIMEOUT_NEVER   0x00
#define ETC_LOW_POWER_TIMEOUT_15MIN   0x01
#define ETC_LOW_POWER_TIMEOUT_30MIN   0x02
#define ETC_LOW_POWER_TIMEOUT_1HOUR   0x03
#define ETC_LOW_POWER_TIMEOUT_4HOURS  0x04
#define ETC_LOW_POWER_TIMEOUT_8HOURS  0x05

static const value_string etc_low_power_timeout_vals[] = {
  { ETC_LOW_POWER_TIMEOUT_NEVER,   "Never" },
  { ETC_LOW_POWER_TIMEOUT_15MIN,   "15 Minutes" },
  { ETC_LOW_POWER_TIMEOUT_30MIN,   "30 Minutes" },
  { ETC_LOW_POWER_TIMEOUT_1HOUR,   "1 Hour" },
  { ETC_LOW_POWER_TIMEOUT_4HOURS,  "4 Hours" },
  { ETC_LOW_POWER_TIMEOUT_8HOURS,  "8 Hours" },
  { 0, NULL },
};

#define ETC_LED_FREQ_ENUM_1200HZ   0x00
#define ETC_LED_FREQ_ENUM_25000HZ  0x01

static const value_string etc_led_frequency_enum_vals[] = {
  { ETC_LED_FREQ_ENUM_1200HZ,   "1.2 kHz" },
  { ETC_LED_FREQ_ENUM_25000HZ,  "25 kHz" },
  { 0, NULL },
};

#define ETC_MODEL_ID_SMARTBAR                           0x0001
#define ETC_MODEL_ID_SOURCE_4_LED_LUSTR_PLUS            0x0101
#define ETC_MODEL_ID_DESIRE_ICE_40_LED                  0x0102
#define ETC_MODEL_ID_DESIRE_FIRE_40_LED                 0x0103
#define ETC_MODEL_ID_SOURCE_4_LED_TUNGSTEN              0x0107
#define ETC_MODEL_ID_SOURCE_4_LED_DAYLIGHT              0x0108
#define ETC_MODEL_ID_DESIRE_VIVID_40_LED                0x0109
#define ETC_MODEL_ID_DESIRE_LUSTR_60_LED_OBS            0x0111
#define ETC_MODEL_ID_DESIRE_ICE_60_LED                  0x0112
#define ETC_MODEL_ID_DESIRE_FIRE_60_LED                 0x0113
#define ETC_MODEL_ID_DESIRE_VIVID_60_LED                0x0119
#define ETC_MODEL_ID_DESIRE_STUDIO_40_LED               0x0121
#define ETC_MODEL_ID_DESIRE_STUDIO_60_LED               0x0129
#define ETC_MODEL_ID_DESIRE_LUSTR_40_LED                0x0131
#define ETC_MODEL_ID_DESIRE_LUSTR_60_LED                0x0139
#define ETC_MODEL_ID_DESIRE_DAYLIGHT_40_LED             0x0141
#define ETC_MODEL_ID_DESIRE_TUNGSTEN_40_LED             0x0142
#define ETC_MODEL_ID_DESIRE_DAYLIGHT_60_LED             0x0149
#define ETC_MODEL_ID_DESIRE_TUNGSTEN_60_LED             0x014A
#define ETC_MODEL_ID_DESIRE_D22_LUSTR_PLUS_LED          0x0151
#define ETC_MODEL_ID_DESIRE_D22_DAYLIGHT_LED            0x0159
#define ETC_MODEL_ID_DESIRE_D22_TUNGSTEN_LED            0x015A
#define ETC_MODEL_ID_SOURCE_4_LED_STUDIO_HD             0x0179
#define ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_LUSTR        0x0181
#define ETC_MODEL_ID_DESIRE_D22_STUDIO_HD               0x0189
#define ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_TUNGSTEN_HD  0x0191
#define ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_DAYLIGHT_HD  0x0199
#define ETC_MODEL_ID_COLORSOURCE_BOOTLOADER             0x0200
#define ETC_MODEL_ID_COLORSOURCE_PAR                    0x0201
#define ETC_MODEL_ID_COLORSOURCE_PAR_DEEP_BLUE          0x0202
#define ETC_MODEL_ID_COLORSOURCE_PAR_PEARL              0x0203
#define ETC_MODEL_ID_COLORSOURCE_SPOT                   0x0205
#define ETC_MODEL_ID_COLORSOURCE_SPOT_DEEP_BLUE         0x0206
#define ETC_MODEL_ID_COLORSOURCE_SPOT_PEARL             0x0207
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_1               0x0209
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_1_DEEP_BLUE     0x020A
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_1_PEARL         0x020B
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_2               0x020D
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_2_DEEP_BLUE     0x020E
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_2_PEARL         0x020F
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_4               0x0211
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_4_DEEP_BLUE     0x0212
#define ETC_MODEL_ID_COLORSOURCE_LINEAR_4_PEARL         0x0213
#define ETC_MODEL_ID_COLORSOURCE_CYC                    0x0215
#define ETC_MODEL_ID_SOURCE_FORWARD_120V                0x0800
#define ETC_MODEL_ID_SOURCE_FORWARD_230V                0x0801
#define ETC_MODEL_ID_IRIDEON_FPZ                        0x0900
#define ETC_MODEL_ID_SOURCE_FOUR_DIMMER                 0x1001
#define ETC_MODEL_ID_KILLSWITCH_WIRELESS                0x1002
#define ETC_MODEL_ID_KILLSWITCH_DMX                     0x1003
#define ETC_MODEL_ID_KILLSWITCH_ETHERNET                0x1004
#define ETC_MODEL_ID_KILLSWITCH_TRANSMITTER             0x1005
#define ETC_MODEL_ID_DMX_ZONE_CONTROLLER_SINGLE_DIMMER  0x1006
#define ETC_MODEL_ID_DMX_ZONE_CONTROLLER_RELAY          0x1007
#define ETC_MODEL_ID_DMX_ZONE_CONTROLLER__4_8_CH        0x1008
#define ETC_MODEL_ID_COLORSOURCE_THRUPOWER_DIMMER       0x1101
#define ETC_MODEL_ID_DMX_DALI_GATEWAY_DIN_RAIL          0x1110

const value_string etc_model_id_vals[] = {
  { ETC_MODEL_ID_SMARTBAR,                           "Smartbar" },
  { ETC_MODEL_ID_SOURCE_4_LED_LUSTR_PLUS,            "Source 4 LED Lustr+" },
  { ETC_MODEL_ID_DESIRE_ICE_40_LED,                  "Desire Ice 40 LED" },
  { ETC_MODEL_ID_DESIRE_FIRE_40_LED,                 "Desire Fire 40 LED" },
  { ETC_MODEL_ID_SOURCE_4_LED_TUNGSTEN,              "Source 4 LED Tungsten" },
  { ETC_MODEL_ID_SOURCE_4_LED_DAYLIGHT,              "Source 4 LED Daylight" },
  { ETC_MODEL_ID_DESIRE_VIVID_40_LED,                "Desire Vivid 40 LED" },
  { ETC_MODEL_ID_DESIRE_LUSTR_60_LED_OBS,            "Desire Lustr 60 LED (obsolete)" },
  { ETC_MODEL_ID_DESIRE_ICE_60_LED,                  "Desire Ice 60 LED" },
  { ETC_MODEL_ID_DESIRE_FIRE_60_LED,                 "Desire Fire 60 LED" },
  { ETC_MODEL_ID_DESIRE_VIVID_60_LED,                "Desire Vivid 60 LED" },
  { ETC_MODEL_ID_DESIRE_STUDIO_40_LED,               "Desire Studio 40 LED" },
  { ETC_MODEL_ID_DESIRE_STUDIO_60_LED,               "Desire Studio 60 LED" },
  { ETC_MODEL_ID_DESIRE_LUSTR_40_LED,                "Desire Lustr 40 LED" },
  { ETC_MODEL_ID_DESIRE_LUSTR_60_LED,                "Desire Lustr 60 LED" },
  { ETC_MODEL_ID_DESIRE_DAYLIGHT_40_LED,             "Desire Daylight 40 LED" },
  { ETC_MODEL_ID_DESIRE_TUNGSTEN_40_LED,             "Desire Tungsten 40 LED" },
  { ETC_MODEL_ID_DESIRE_DAYLIGHT_60_LED,             "Desire Daylight 60 LED" },
  { ETC_MODEL_ID_DESIRE_TUNGSTEN_60_LED,             "Desire Tungsten 60 LED" },
  { ETC_MODEL_ID_DESIRE_D22_LUSTR_PLUS_LED,          "Desire D22 Lustr+ LED" },
  { ETC_MODEL_ID_DESIRE_D22_DAYLIGHT_LED,            "Desire D22 Daylight LED" },
  { ETC_MODEL_ID_DESIRE_D22_TUNGSTEN_LED,            "Desire D22 Tungsten LED" },
  { ETC_MODEL_ID_SOURCE_4_LED_STUDIO_HD,             "Source 4 LED Studio HD" },
  { ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_LUSTR,        "Source 4 LED Series 2 Lustr" },
  { ETC_MODEL_ID_DESIRE_D22_STUDIO_HD,               "Desire D22 Studio HD" },
  { ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_TUNGSTEN_HD,  "Source 4 LED Series 2 Tungsten HD" },
  { ETC_MODEL_ID_SOURCE_4_LED_SERIES_2_DAYLIGHT_HD,  "Source 4 LED Series 2 Daylight HD" },
  { ETC_MODEL_ID_COLORSOURCE_BOOTLOADER,             "ColorSource Bootloader" },
  { ETC_MODEL_ID_COLORSOURCE_PAR,                    "ColorSource Par" },
  { ETC_MODEL_ID_COLORSOURCE_PAR_DEEP_BLUE,          "ColorSource Par DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_PAR_PEARL,              "ColorSource Par Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_SPOT,                   "ColorSource Spot" },
  { ETC_MODEL_ID_COLORSOURCE_SPOT_DEEP_BLUE,         "ColorSource Spot DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_SPOT_PEARL,             "ColorSource Spot Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_1,               "ColorSource Linear 1" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_1_DEEP_BLUE,     "ColorSource Linear 1 DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_1_PEARL,         "ColorSource Linear 1 Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_2,               "ColorSource Linear 2" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_2_DEEP_BLUE,     "ColorSource Linear 2 DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_2_PEARL,         "ColorSource Linear 2 Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_4,               "ColorSource Linear 4" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_4_DEEP_BLUE,     "ColorSource Linear 4 DeepBlue" },
  { ETC_MODEL_ID_COLORSOURCE_LINEAR_4_PEARL,         "ColorSource Linear 4 Pearl" },
  { ETC_MODEL_ID_COLORSOURCE_CYC,                    "ColorSource Cyc" },
  { ETC_MODEL_ID_SOURCE_FORWARD_120V,                "Source Forward 120v" },
  { ETC_MODEL_ID_SOURCE_FORWARD_230V,                "Source Forward 230v" },
  { ETC_MODEL_ID_IRIDEON_FPZ,                        "Irideon FPZ" },
  { ETC_MODEL_ID_SOURCE_FOUR_DIMMER,                 "Source Four Dimmer" },
  { ETC_MODEL_ID_KILLSWITCH_WIRELESS,                "Killswitch Wireless" },
  { ETC_MODEL_ID_KILLSWITCH_DMX,                     "Killswitch DMX" },
  { ETC_MODEL_ID_KILLSWITCH_ETHERNET,                "Killswitch Ethernet" },
  { ETC_MODEL_ID_KILLSWITCH_TRANSMITTER,             "Killswitch Transmitter" },
  { ETC_MODEL_ID_DMX_ZONE_CONTROLLER_SINGLE_DIMMER,  "DMX Zone Controller, Single Dimmer" },
  { ETC_MODEL_ID_DMX_ZONE_CONTROLLER_RELAY,          "DMX Zone Controller, Relay" },
  { ETC_MODEL_ID_DMX_ZONE_CONTROLLER__4_8_CH,        "DMX Zone Controller, 4-8 Channel Room Controller" },
  { ETC_MODEL_ID_COLORSOURCE_THRUPOWER_DIMMER,       "ColorSource Thrupower Dimmer" },
  { ETC_MODEL_ID_DMX_DALI_GATEWAY_DIN_RAIL,          "DMX-DALI Gateway, DIN Rail" },
  { 0, NULL },
};

static int hf_etc_pd_led_curve;
static int hf_etc_pd_led_curve_description_curve;
static int hf_etc_pd_led_curve_description_text;
static int hf_etc_pd_led_strobe;
static int hf_etc_pd_led_output_mode;
static int hf_etc_pd_led_output_mode_description_mode;
static int hf_etc_pd_led_output_mode_description_text;
static int hf_etc_pd_led_red_shift;
static int hf_etc_pd_led_white_point;
static int hf_etc_pd_led_white_point_description_white_point;
static int hf_etc_pd_led_white_point_description_text;
static int hf_etc_pd_led_frequency;
static int hf_etc_pd_dmx_data_loss_behavior;
static int hf_etc_pd_dmx_data_loss_behavior_description_behavior;
static int hf_etc_pd_dmx_data_loss_behavior_description_text;
static int hf_etc_pd_led_plus_seven;
static int hf_etc_pd_backlight_brightness;
static int hf_etc_pd_backlight_timeout;
static int hf_etc_pd_status_indicators;
static int hf_etc_pd_overtemp_mode;
static int hf_etc_pd_simple_setup_mode;
static int hf_etc_pd_led_strobe_description_strobe;
static int hf_etc_pd_led_strobe_description_text;
static int hf_etc_pd_red_shift_description_red_shift;
static int hf_etc_pd_red_shift_description_text;
static int hf_etc_pd_plus_seven_description_plus_seven;
static int hf_etc_pd_plus_seven_description_text;
static int hf_etc_pd_backlight_timeout_description_timeout;
static int hf_etc_pd_backlight_timeout_description_text;
static int hf_etc_pd_simple_setup_mode_description_mode;
static int hf_etc_pd_simple_setup_mode_description_text;
static int hf_etc_pd_overtemp_mode_description_mode;
static int hf_etc_pd_overtemp_mode_description_text;
static int hf_etc_pd_led_requested_xy_x;
static int hf_etc_pd_led_requested_xy_y;
static int hf_etc_pd_led_current_xy_x;
static int hf_etc_pd_led_current_xy_y;
static int hf_etc_pd_current_pwm_led_number;
static int hf_etc_pd_current_pwm_channel_duty_cycle;
static int hf_etc_pd_tristimulus_led_number;
static int hf_etc_pd_tristimulus_x;
static int hf_etc_pd_tristimulus_y;
static int hf_etc_pd_tristimulus_z;
static int hf_etc_pd_led_information_led_number;
static int hf_etc_pd_led_information_type;
static int hf_etc_pd_led_information_dmx_control_channel;
static int hf_etc_pd_led_information_drive_current;
static int hf_etc_pd_led_information_gamut_polygon_order;
static int hf_etc_pd_led_information_quantity;
static int hf_etc_pd_preset_config_preset_number;
static int hf_etc_pd_preset_config_fade_time;
static int hf_etc_pd_preset_config_delay_time;
static int hf_etc_pd_preset_config_hue;
static int hf_etc_pd_preset_config_saturation;
static int hf_etc_pd_preset_config_intensity;
static int hf_etc_pd_preset_config_strobe;
static int hf_etc_pd_sequence_playback_sequence_number;
static int hf_etc_pd_sequence_config_sequence_number;
static int hf_etc_pd_sequence_config_preset_steps;
static int hf_etc_pd_sequence_config_preset_step;
static int hf_etc_pd_sequence_config_step_link_times;
static int hf_etc_pd_sequence_config_step_link_time;
static int hf_etc_pd_sequence_config_rate;
static int hf_etc_pd_sequence_config_end_state;
static int hf_etc_pd_low_power_timeout;
static int hf_etc_pd_low_power_timeout_description_timeout;
static int hf_etc_pd_low_power_timeout_description_text;
static int hf_etc_pd_led_enum_frequency;
static int hf_etc_pd_led_enum_frequency_description_frequency;
static int hf_etc_pd_led_enum_frequency_description_text;
static int hf_etc_pd_rgbi_preset_config_preset_number;
static int hf_etc_pd_rgbi_preset_config_fade_time;
static int hf_etc_pd_rgbi_preset_config_delay_time;
static int hf_etc_pd_rgbi_preset_config_red;
static int hf_etc_pd_rgbi_preset_config_green;
static int hf_etc_pd_rgbi_preset_config_blue;
static int hf_etc_pd_rgbi_preset_config_intensity;
static int hf_etc_pd_rgbi_preset_config_strobe;
static int hf_etc_pd_cct_preset_config_preset_number;
static int hf_etc_pd_cct_preset_config_fade_time;
static int hf_etc_pd_cct_preset_config_delay_time;
static int hf_etc_pd_cct_preset_config_white_point;
static int hf_etc_pd_cct_preset_config_tint;
static int hf_etc_pd_cct_preset_config_strobe;
static int hf_etc_pd_cct_preset_config_intensity;
static int hf_etc_pd_cct_preset_config_tone;
static int hf_etc_pd_cct_preset_config_reserved;
static int hf_etc_pd_supplementary_device_version_param_index;
static int hf_etc_pd_supplementary_device_version_param_description;
static int hf_etc_pd_power_command;
static int hf_etc_pd_power_command_description_state;
static int hf_etc_pd_power_command_description_text;
static int hf_etc_pd_dali_short_address;
static int hf_etc_pd_dali_group_membership;
static int hf_etc_pd_auto_bind;
static int hf_etc_pd_packet_delay;
static int hf_etc_pd_has_enum_text_pid;
static int hf_etc_pd_has_enum_text_true_false;
static int hf_etc_pd_get_enum_text_pid;
static int hf_etc_pd_get_enum_text_enum;
static int hf_etc_pd_get_enum_text_description;

static int ett_etc_sequence_config_steps;
static int ett_etc_sequence_config_times;

static unsigned
dissect_etc_pd_led_curve(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_curve_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_curve_description_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_curve_description_curve, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_curve_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_strobe(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_strobe, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_output_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_output_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_output_mode_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_output_mode_description_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_output_mode_description_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_output_mode_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_red_shift(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_red_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_white_point(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_white_point, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_white_point_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_white_point_description_white_point, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_white_point_description_white_point, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_white_point_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_frequency(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_frequency, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dmx_data_loss_behavior(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_dmx_data_loss_behavior, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dmx_data_loss_behavior_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_dmx_data_loss_behavior_description_behavior, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_dmx_data_loss_behavior_description_behavior, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_dmx_data_loss_behavior_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_plus_seven(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_plus_seven, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_backlight_brightness(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_backlight_brightness, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_backlight_timeout(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_backlight_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_status_indicators(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_status_indicators, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_recalibrate_fixture(unsigned offset)
{
  /* set-only, no data */
  return offset;
}

static unsigned
dissect_etc_pd_overtemp_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_overtemp_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_simple_setup_mode(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_simple_setup_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_strobe_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_strobe_description_strobe, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_strobe_description_strobe, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_strobe_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_red_shift_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_red_shift_description_red_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_red_shift_description_red_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_red_shift_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_plus_seven_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_plus_seven_description_plus_seven, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_plus_seven_description_plus_seven, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_plus_seven_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_backlight_timeout_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_backlight_timeout_description_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_backlight_timeout_description_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_backlight_timeout_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_simple_setup_mode_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_simple_setup_mode_description_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_simple_setup_mode_description_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_simple_setup_mode_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_overtemp_mode_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_overtemp_mode_description_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_overtemp_mode_description_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_overtemp_mode_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_requested_xy(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_requested_xy_x, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_led_requested_xy_y, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_current_xy(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_current_xy_x, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_led_current_xy_y, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_current_pwm(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_current_pwm_led_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_current_pwm_led_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_current_pwm_channel_duty_cycle, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_tristimulus(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_tristimulus_led_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_tristimulus_led_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_tristimulus_x, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_etc_pd_tristimulus_y, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_etc_pd_tristimulus_z, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_information(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_information_led_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_information_led_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_information_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_information_dmx_control_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_information_drive_current, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_led_information_gamut_polygon_order, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_information_quantity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_preset_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_preset_config_preset_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_preset_config_preset_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_preset_config_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_preset_config_delay_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_preset_config_hue, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_preset_config_saturation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_preset_config_intensity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_preset_config_strobe, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_sequence_playback(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_sequence_playback_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_sequence_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  unsigned    i;
  proto_tree *preset_steps_tree, *preset_steps_sub_item;
  proto_tree *step_link_times_tree, *step_link_times_sub_item;

  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_sequence_config_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_sequence_config_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    preset_steps_tree = proto_tree_add_item(tree, hf_etc_pd_sequence_config_preset_steps, tvb, offset, 24, ENC_NA);
    preset_steps_sub_item = proto_item_add_subtree(preset_steps_tree, ett_etc_sequence_config_steps);
    for (i = 0; i < 24; i++) {
      proto_tree_add_item(preset_steps_sub_item, hf_etc_pd_sequence_config_preset_step, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
    }

    step_link_times_tree = proto_tree_add_item(tree, hf_etc_pd_sequence_config_step_link_times, tvb, offset, 48, ENC_NA);
    step_link_times_sub_item = proto_item_add_subtree(step_link_times_tree, ett_etc_sequence_config_times);
    for (i = 0; i < 24; i++) {
      proto_tree_add_item(step_link_times_sub_item, hf_etc_pd_sequence_config_step_link_time, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }

    proto_tree_add_item(tree, hf_etc_pd_sequence_config_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_sequence_config_end_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_low_power_timeout(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_low_power_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_low_power_timeout_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_low_power_timeout_description_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_low_power_timeout_description_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_low_power_timeout_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_enum_frequency(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_enum_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_led_enum_frequency_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_led_enum_frequency_description_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_led_enum_frequency_description_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_led_enum_frequency_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_rgbi_preset_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_preset_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_preset_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_delay_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_red, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_green, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_blue, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_intensity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_rgbi_preset_config_strobe, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_cct_preset_config(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_preset_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_preset_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_fade_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_delay_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_white_point, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_tint, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_strobe, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_intensity, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_tone, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_cct_preset_config_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_supplementary_device_version(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_supplementary_device_version_param_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_supplementary_device_version_param_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_supplementary_device_version_param_description, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_power_command(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_power_command, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_power_command_description(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_power_command_description_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_power_command_description_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_etc_pd_power_command_description_text, tvb, offset, len-1, ENC_UTF_8);
    offset += len-1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dali_short_address(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_dali_short_address, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_dali_group_membership(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_dali_group_membership, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_auto_bind(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_auto_bind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_delete_subdevice(unsigned offset)
{
  /* set-only, no data */
  return offset;
}

static unsigned
dissect_etc_pd_packet_delay(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND_RESPONSE:
  case RDM_CC_SET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_packet_delay, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_has_enum_text(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_has_enum_text_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_has_enum_text_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_has_enum_text_true_false, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_get_enum_text(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint8_t len)
{
  switch(cc) {
  case RDM_CC_GET_COMMAND:
    proto_tree_add_item(tree, hf_etc_pd_get_enum_text_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_get_enum_text_enum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case RDM_CC_GET_COMMAND_RESPONSE:
    proto_tree_add_item(tree, hf_etc_pd_get_enum_text_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_etc_pd_get_enum_text_enum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_etc_pd_get_enum_text_description, tvb, offset, len-6, ENC_UTF_8);
    offset += len-6;
    break;
  }

  return offset;
}

static unsigned
dissect_etc_pd_prepare_for_software_download(unsigned offset)
{
  /* set-only, no data */
  return offset;
}

static unsigned
dissect_etc_pd(tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t cc, uint16_t param_id, uint8_t pdl)
{
  switch(param_id) {
  case ETC_PARAM_ID_LED_CURVE:
    offset = dissect_etc_pd_led_curve(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_CURVE_DESCRIPTION:
    offset = dissect_etc_pd_led_curve_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_STROBE:
    offset = dissect_etc_pd_led_strobe(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_OUTPUT_MODE:
    offset = dissect_etc_pd_led_output_mode(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_OUTPUT_MODE_DESCRIPTION:
    offset = dissect_etc_pd_led_output_mode_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_RED_SHIFT:
    offset = dissect_etc_pd_led_red_shift(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_WHITE_POINT:
    offset = dissect_etc_pd_led_white_point(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_WHITE_POINT_DESCRIPTION:
    offset = dissect_etc_pd_led_white_point_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_FREQUENCY:
    offset = dissect_etc_pd_led_frequency(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DMX_LOSS_BEHAVIOR:
    offset = dissect_etc_pd_dmx_data_loss_behavior(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DMX_LOSS_BEHAVIOR_DESCRIPTION:
    offset = dissect_etc_pd_dmx_data_loss_behavior_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_PLUS_SEVEN:
    offset = dissect_etc_pd_led_plus_seven(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_BACKLIGHT_BRIGHTNESS:
    offset = dissect_etc_pd_backlight_brightness(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_BACKLIGHT_TIMEOUT:
    offset = dissect_etc_pd_backlight_timeout(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_STATUS_INDICATORS:
    offset = dissect_etc_pd_status_indicators(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_RECALIBRATE_FIXTURE:
    offset = dissect_etc_pd_recalibrate_fixture(offset);
    break;
  case ETC_PARAM_ID_OVERTEMPMODE:
    offset = dissect_etc_pd_overtemp_mode(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SIMPLESETUPMODE:
    offset = dissect_etc_pd_simple_setup_mode(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_STROBE_DESCRIPTION:
    offset = dissect_etc_pd_led_strobe_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_RED_SHIFT_DESCRIPTION:
    offset = dissect_etc_pd_red_shift_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_PLUS_SEVEN_DESCRIPTION:
    offset = dissect_etc_pd_plus_seven_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_BACKLIGHT_TIMEOUT_DESCRIPTION:
    offset = dissect_etc_pd_backlight_timeout_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_SIMPLESETUPMODE_DESCRIPTION:
    offset = dissect_etc_pd_simple_setup_mode_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_OVERTEMPMODE_DESCRIPTION:
    offset = dissect_etc_pd_overtemp_mode_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_REQUESTED_XY:
    offset = dissect_etc_pd_led_requested_xy(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_CURRENT_XY:
    offset = dissect_etc_pd_led_current_xy(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_CURRENT_PWM:
    offset = dissect_etc_pd_current_pwm(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_TRISTIMULUS:
    offset = dissect_etc_pd_tristimulus(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_INFORMATION:
    offset = dissect_etc_pd_led_information(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_PRESETCONFIG:
    offset = dissect_etc_pd_preset_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SEQUENCE_PLAYBACK:
    offset = dissect_etc_pd_sequence_playback(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SEQUENCE_CONFIG:
    offset = dissect_etc_pd_sequence_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LOW_POWER_TIMEOUT:
    offset = dissect_etc_pd_low_power_timeout(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LOW_POWER_TIMEOUT_DESCRIPTION:
    offset = dissect_etc_pd_low_power_timeout_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_LED_ENUM_FREQUENCY:
    offset = dissect_etc_pd_led_enum_frequency(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_LED_ENUM_FREQUENCY_DESCRIPTION:
    offset = dissect_etc_pd_led_enum_frequency_description(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_RGBI_PRESETCONFIG:
    offset = dissect_etc_pd_rgbi_preset_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_CCT_PRESETCONFIG:
    offset = dissect_etc_pd_cct_preset_config(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_SUPPLEMENTARY_DEVICE_VERSION:
    offset = dissect_etc_pd_supplementary_device_version(tvb, offset, tree, cc, pdl);
    break;
/* do not display
  case ETC_PARAM_ID_START_UWB_DISCOVER:
    break;
  case ETC_PARAM_ID_START_UWB_MEASURE:
    break;
  case ETC_PARAM_ID_POSITION:
    break;
*/
/* TODO: begin need descriptions */
  case ETC_PARAM_ID_S4DIM_CALIBRATE:
    break;
  case ETC_PARAM_ID_S4DIM_CALIBRATE_DESCRIPTION:
    break;
  case ETC_PARAM_ID_S4DIM_TEST_MODE:
    break;
  case ETC_PARAM_ID_S4DIM_TEST_MODE_DESCRIPTION:
    break;
  case ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE:
    break;
  case ETC_PARAM_ID_S4DIM_MAX_OUTPUT_VOLTAGE_DESCRIPTION:
    break;
/* TODO: end need descriptions */
  case ETC_PARAM_ID_POWER_COMMAND:
    offset = dissect_etc_pd_power_command(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_POWER_COMMAND_DESCRIPTION:
    offset = dissect_etc_pd_power_command_description(tvb, offset, tree, cc, pdl);
    break;
/* TODO: begin need descriptions */
  case ETC_PARAM_ID_THRESHOLD_COMMAND:
    break;
  case ETC_PARAM_ID_TURNON_DELAY_COMMAND:
    break;
/* TODO: end need descriptions */
  case ETC_PARAM_ID_SET_DALI_SHORTADDRESS:
    offset = dissect_etc_pd_dali_short_address(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DALI_GROUP_MEMBERSHIP:
    offset = dissect_etc_pd_dali_group_membership(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_AUTOBIND:
    offset = dissect_etc_pd_auto_bind(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_DELETE_SUBDEVICE:
    offset = dissect_etc_pd_delete_subdevice(offset);
    break;
  case ETC_PARAM_ID_PACKET_DELAY:
    offset = dissect_etc_pd_packet_delay(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_HAS_ENUM_TEXT:
    offset = dissect_etc_pd_has_enum_text(tvb, offset, tree, cc);
    break;
  case ETC_PARAM_ID_GET_ENUM_TEXT:
    offset = dissect_etc_pd_get_enum_text(tvb, offset, tree, cc, pdl);
    break;
  case ETC_PARAM_ID_PREPAREFORSOFTWAREDOWNLOAD:
    offset = dissect_etc_pd_prepare_for_software_download(offset);
    break;
  }

  return offset;
}

static int
dissect_etc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data)
{
  if (data == NULL) {
    return 0;
  }

  unsigned int tvb_len = tvb_reported_length(tvb);
  uint8_t pdl = tvb_len > 255 ? 255 : tvb_len;
  rdm_pid_info* pid_info = (rdm_pid_info*)data;

  if (pdl > 0) {
    return dissect_etc_pd(tvb, 0, tree, pid_info->command_class, pid_info->pid, pdl);
  }
  return 0;
}

void
proto_register_rdm_etc(void)
{
  static hf_register_info hf[] = {
    { &hf_etc_pd_led_curve,
      { "Curve", "rdm_etc.pd.led_curve.curve",
        FT_UINT8, BASE_DEC, VALS(etc_led_curve_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_curve_description_curve,
      { "Curve", "rdm_etc.pd.led_curve_description.curve",
        FT_UINT8, BASE_DEC, VALS(etc_led_curve_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_curve_description_text,
      { "Description", "rdm_etc.pd.led_curve_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_strobe,
      { "Strobe", "rdm_etc.pd.led_strobe",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_output_mode,
      { "Output Mode", "rdm_etc.pd.led_output_mode",
        FT_UINT8, BASE_DEC, VALS(etc_led_output_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_output_mode_description_mode,
      { "Output Mode", "rdm_etc.pd.led_output_mode_description.output_mode",
        FT_UINT8, BASE_DEC, VALS(etc_led_output_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_output_mode_description_text,
      { "Description", "rdm_etc.pd.lled_output_mode_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_red_shift,
      { "Red Shift", "rdm_etc.pd.led_red_shift",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_white_point,
      { "White Point", "rdm_etc.pd.led_white_point",
        FT_UINT8, BASE_DEC, VALS(etc_led_white_point_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_white_point_description_white_point,
      { "White Point", "rdm_etc.pd.led_white_point_description.white_point",
        FT_UINT8, BASE_DEC, VALS(etc_led_white_point_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_white_point_description_text,
      { "Description", "rdm_etc.pd.led_white_point_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_frequency,
      { "LED Frequency (Hz)", "rdm_etc.pd.led_frequency",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dmx_data_loss_behavior,
      { "DMX Data Loss Behavior", "rdm_etc.pd.dmx_data_loss_behavior",
        FT_UINT8, BASE_DEC, VALS(etc_dmx_data_loss_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dmx_data_loss_behavior_description_behavior,
      { "DMX Data Loss Behavior", "rdm_etc.pd.dmx_data_loss_behavior_description.behavior",
        FT_UINT8, BASE_DEC, VALS(etc_dmx_data_loss_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dmx_data_loss_behavior_description_text,
      { "Description", "rdm_etc.pd.dmx_data_loss_behavior_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_plus_seven,
      { "LED Plus Seven", "rdm_etc.pd.led_plus_seven",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_brightness,
      { "Backlight Brightness", "rdm_etc.pd.backlight_brightness",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_timeout,
      { "Backlight Timeout", "rdm_etc.pd.backlight_timeout",
        FT_UINT8, BASE_DEC, VALS(etc_backlight_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_status_indicators,
      { "Status Indicators", "rdm_etc.pd.status_indicators",
        FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_overtemp_mode,
      { "Overtemp Mode", "rdm_etc.pd.overtemp_mode",
        FT_UINT8, BASE_DEC, VALS(etc_overtemp_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_simple_setup_mode,
      { "Simple Setup Mode", "rdm_etc.pd.simple_setup_mode",
        FT_UINT8, BASE_DEC, VALS(etc_simple_setup_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_strobe_description_strobe,
      { "Strobe", "rdm_etc.pd.led_strobe_description.led_strobe",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_strobe_description_text,
      { "Description", "rdm_etc.pd.led_strobe_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_red_shift_description_red_shift,
      { "Red Shift", "rdm_etc.pd.red_shift_description.red_shift",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_red_shift_description_text,
      { "Description", "rdm_etc.pd.red_shift_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_plus_seven_description_plus_seven,
      { "Plus Seven", "rdm_etc.pd.plus_seven_description.plus_seven",
        FT_UINT8, BASE_DEC, VALS(enabled_disabled_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_plus_seven_description_text,
      { "Description", "rdm_etc.pd.plus_seven_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_timeout_description_timeout,
      { "Backlight Timeout", "rdm_etc.pd.backlight_timeout_description.backlight_timeout",
        FT_UINT8, BASE_DEC, VALS(etc_backlight_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_backlight_timeout_description_text,
      { "Description", "rdm_etc.pd.backlight_timeout_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_simple_setup_mode_description_mode,
      { "Simple Setup Mode", "rdm_etc.pd.simple_setup_mode_description.mode",
        FT_UINT8, BASE_DEC, VALS(etc_simple_setup_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_simple_setup_mode_description_text,
      { "Description", "rdm_etc.pd.simple_setup_mode_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_overtemp_mode_description_mode,
      { "Overtemp Mode", "rdm_etc.pd.overtemp_mode_description.mode",
        FT_UINT8, BASE_DEC, VALS(etc_overtemp_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_overtemp_mode_description_text,
      { "Description", "rdm_etc.pd.overtemp_mode_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_requested_xy_x,
      { "X Coordinate", "rdm_etc.pd.led_requested_xy.x",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_requested_xy_y,
      { "Y Coordinate", "rdm_etc.pd.led_requested_xy.y",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_current_xy_x,
      { "X Coordinate", "rdm_etc.pd.led_current_xy.x",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_current_xy_y,
      { "Y Coordinate", "rdm_etc.pd.led_current_xy.y",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_current_pwm_led_number,
      { "LED Number", "rdm_etc.pd.current_pwm.led_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_current_pwm_channel_duty_cycle,
      { "Channel Duty Cycle", "rdm_etc.pd.current_pwm.channel_duty_cycle",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_led_number,
      { "LED Number", "rdm_etc.pd.tristimulus.led_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_x,
      { "X", "rdm_etc.pd.tristimulus.x",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_y,
      { "Y", "rdm_etc.pd.tristimulus.y",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_tristimulus_z,
      { "Z", "rdm_etc.pd.tristimulus.z",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_led_number,
      { "LED Number", "rdm_etc.pd.led_information.led_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_type,
      { "Type", "rdm_etc.pd.led_information.type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_dmx_control_channel,
      { "DMX Control Channel", "rdm_etc.pd.led_information.dmx_control_channel",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_drive_current,
      { "Drive Current (ma)", "rdm_etc.pd.led_information.drive_current",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_gamut_polygon_order,
      { "Gamut Polygon Order", "rdm_etc.pd.led_information.gamut_polygon_order",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_information_quantity,
      { "Quantity", "rdm_etc.pd.led_information.quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_preset_number,
      { "Preset Number", "rdm_etc.pd.preset_config.preset_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_fade_time,
      { "Fade Time (seconds)", "rdm_etc.pd.preset_config.fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_delay_time,
      { "Delay Time (seconds)", "rdm_etc.pd.preset_config.delay_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_hue,
      { "Hue", "rdm_etc.pd.preset_config.hue",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_saturation,
      { "Saturation", "rdm_etc.pd.preset_config.saturation",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_intensity,
      { "Intensity", "rdm_etc.pd.preset_config.intensity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_preset_config_strobe,
      { "Strobe", "rdm_etc.pd.preset_config.strobe",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_playback_sequence_number,
      { "Sequence Number", "rdm_etc.pd.sequence_playback.sequence_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_sequence_number,
      { "Sequence Number", "rdm_etc.pd.sequence_config.sequence_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_preset_steps,
      { "Preset Steps", "rdm_etc.pd.sequence_config.preset_steps",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_preset_step,
      { "Preset Step", "rdm_etc.pd.sequence_config.preset_step",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_step_link_times,
      { "Step Link Times (seconds)", "rdm_etc.pd.sequence_config.step_link_times",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_step_link_time,
      { "Step Link Time", "rdm_etc.pd.sequence_config.step_link_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_rate,
      { "Rate", "rdm_etc.pd.sequence_config.rate",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_sequence_config_end_state,
      { "End State", "rdm_etc.pd.sequence_config.end_state",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_low_power_timeout,
      { "Low Power Timeout", "rdm_etc.pd.low_power_timeout",
        FT_UINT8, BASE_DEC, VALS(etc_low_power_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_low_power_timeout_description_timeout,
      { "Low Power Timeout", "rdm_etc.pd.low_power_timeout_description.timeout",
        FT_UINT8, BASE_DEC, VALS(etc_low_power_timeout_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_low_power_timeout_description_text,
      { "Description", "rdm_etc.pd.low_power_timeout_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_enum_frequency,
      { "Frequency", "rdm_etc.pd.led_enum_frequency",
        FT_UINT8, BASE_DEC, VALS(etc_led_frequency_enum_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_enum_frequency_description_frequency,
      { "Frequency", "rdm_etc.pd.led_enum_frequency_description.frequency",
        FT_UINT8, BASE_DEC, VALS(etc_led_frequency_enum_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_led_enum_frequency_description_text,
      { "Description", "rdm_etc.pd.led_enum_frequency_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_preset_number,
      { "Preset Number", "rdm_etc.pd.rgbi_preset_config.preset_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_fade_time,
      { "Fade Time (seconds)", "rdm_etc.pd.rgbi_preset_config.fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_delay_time,
      { "Delay Time (seconds)", "rdm_etc.pd.rgbi_preset_config.delay_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_red,
      { "Red", "rdm_etc.pd.rgbi_preset_config.red",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_green,
      { "Green", "rdm_etc.pd.rgbi_preset_config.green",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_blue,
      { "Blue", "rdm_etc.pd.rgbi_preset_config.blue",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_intensity,
      { "Intensity", "rdm_etc.pd.rgbi_preset_config.intensity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_rgbi_preset_config_strobe,
      { "Strobe", "rdm_etc.pd.rgbi_preset_config.strobe",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_preset_number,
      { "Preset Number", "rdm_etc.pd.cct_preset_config.preset_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_fade_time,
      { "Fade Time (seconds)", "rdm_etc.pd.cct_preset_config.fade_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_delay_time,
      { "Delay Time (seconds)", "rdm_etc.pd.cct_preset_config.delay_time",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_white_point,
      { "White Point", "rdm_etc.pd.cct_preset_config.white_point",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_tint,
      { "Tint", "rdm_etc.pd.cct_preset_config.tint",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_strobe,
      { "Strobe", "rdm_etc.pd.cct_preset_config.strobe",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_intensity,
      { "Intensity", "rdm_etc.pd.cct_preset_config.intensity",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_tone,
      { "Tone", "rdm_etc.pd.cct_preset_config.tone",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_cct_preset_config_reserved,
      { "Reserved", "rdm_etc.pd.cct_preset_config.reserved",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_supplementary_device_version_param_index,
      { "Param Index", "rdm_etc.pd.supplementary_device_version.param_index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_supplementary_device_version_param_description,
      { "Param Description", "rdm_etc.pd.supplementary_device_version.param_description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_power_command,
      { "State", "rdm_etc.pd.power_command",
        FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_power_command_description_state,
      { "State", "rdm_etc.pd.power_command_description.state",
        FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_power_command_description_text,
      { "Description", "rdm_etc.pd.power_command_description.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dali_short_address,
      { "Short Address", "rdm_etc.pd.dali_short_address",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_dali_group_membership,
      { "Group Membership", "rdm_etc.pd.dali_group_membership",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_auto_bind,
      { "Auto Bind", "rdm_etc.pd.auto_bind",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_packet_delay,
      { "Packet Delay", "rdm_etc.pd.packet_delay",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_has_enum_text_pid,
      { "PID", "rdm_etc.pd.has_enum_text.pid",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_has_enum_text_true_false,
      { "Value", "rdm_etc.pd.has_enum_text.value",
        FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_get_enum_text_pid,
      { "PID", "rdm_etc.pd.get_enum_text.pid",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_get_enum_text_enum,
      { "Enum", "rdm_etc.pd.get_enum_text.enum",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_etc_pd_get_enum_text_description,
      { "Description", "rdm_etc.pd.get_enum_text.description",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_etc_sequence_config_steps,
    &ett_etc_sequence_config_times
  };

  proto_rdm_ext = proto_register_protocol("ETC RDM Extensions", "RDM-ETC", "rdm_etc");
  proto_register_field_array(proto_rdm_ext, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  rdm_etc_handle = register_dissector("rdm_etc", dissect_etc, proto_rdm_ext);
}

void
proto_reg_handoff_rdm_etc(void) {
  dissector_add_uint("rdm.manf_id", RDM_MANUFACTURER_ID_ETC, rdm_etc_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
