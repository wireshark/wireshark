/* packet-btmesh.c
 * Routines for Bluetooth mesh dissection
 *
 * Copyright 2017, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2019-2021, Piotr Winiarczyk <wino45@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: Mesh Profile v1.0
 */
#include "config.h"

#include "packet-bluetooth.h"
#include "packet-btatt.h"
#include "packet-btmesh.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/wsgcrypt.h>
#include <epan/expert.h>
#include <math.h>
#include <epan/uat.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>

#define BTMESH_NOT_USED 0
#define BTMESH_KEY_ENTRY_VALID 4
#define BTMESH_DEVICE_KEY_ENTRY_VALID 2
#define BTMESH_LABEL_UUID_ENTRY_VALID 1
#define NO_LABEL_UUID_IDX_USED -1
#define PROPERTY_LENGTH_NO_HINT -1

#define SENSOR_CADENCE_TRIGGER_TYPE_PROPERTY 0
#define SENSOR_CADENCE_TRIGGER_TYPE_PERCENTAGE 1

#define MPID_FORMAT_A 0
#define MPID_FORMAT_B 1

#define DISSECTOR_SIMPLE       0
#define DISSECTOR_THREE_VALUES 1

#define NOT_SUPPORTED_PROPERTY 0
#define NOT_SUPPORTED_CHARACTERISTIC -1

#define CONFIG_APPKEY_ADD                                        0x0000
#define CONFIG_APPKEY_UPDATE                                     0x0001
#define CONFIG_COMPOSITION_DATA_STATUS                           0x0002
#define CONFIG_MODEL_PUBLICATION_SET                             0x0003
#define HEALTH_CURRENT_STATUS                                    0x0004
#define HEALTH_FAULT_STATUS                                      0x0005
#define CONFIG_HEARTBEAT_PUBLICATION_STATUS                      0x0006
#define LIGHT_LC_PROPERTY_SET                                    0x0062
#define LIGHT_LC_PROPERTY_SET_UNACKNOWLEDGED                     0x0063
#define LIGHT_LC_PROPERTY_STATUS                                 0x0064
#define CONFIG_APPKEY_DELETE                                     0x8000
#define CONFIG_APPKEY_GET                                        0x8001
#define CONFIG_APPKEY_LIST                                       0x8002
#define CONFIG_APPKEY_STATUS                                     0x8003
#define HEALTH_ATTENTION_GET                                     0x8004
#define HEALTH_ATTENTION_SET                                     0x8005
#define HEALTH_ATTENTION_SET_UNACKNOWLEDGED                      0x8006
#define HEALTH_ATTENTION_STATUS                                  0x8007
#define CONFIG_COMPOSITION_DATA_GET                              0x8008
#define CONFIG_BEACON_GET                                        0x8009
#define CONFIG_BEACON_SET                                        0x800a
#define CONFIG_BEACON_STATUS                                     0x800b
#define CONFIG_DEFAULT_TTL_GET                                   0x800c
#define CONFIG_DEFAULT_TTL_SET                                   0x800d
#define CONFIG_DEFAULT_TTL_STATUS                                0x800e
#define CONFIG_FRIEND_GET                                        0x800f
#define CONFIG_FRIEND_SET                                        0x8010
#define CONFIG_FRIEND_STATUS                                     0x8011
#define CONFIG_GATT_PROXY_GET                                    0x8012
#define CONFIG_GATT_PROXY_SET                                    0x8013
#define CONFIG_GATT_PROXY_STATUS                                 0x8014
#define CONFIG_KEY_REFRESH_PHASE_GET                             0x8015
#define CONFIG_KEY_REFRESH_PHASE_SET                             0x8016
#define CONFIG_KEY_REFRESH_PHASE_STATUS                          0x8017
#define CONFIG_MODEL_PUBLICATION_GET                             0x8018
#define CONFIG_MODEL_PUBLICATION_STATUS                          0x8019
#define CONFIG_MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET             0x801a
#define CONFIG_MODEL_SUBSCRIPTION_ADD                            0x801b
#define CONFIG_MODEL_SUBSCRIPTION_DELETE                         0x801c
#define CONFIG_MODEL_SUBSCRIPTION_DELETE_ALL                     0x801d
#define CONFIG_MODEL_SUBSCRIPTION_OVERWRITE                      0x801e
#define CONFIG_MODEL_SUBSCRIPTION_STATUS                         0x801f
#define CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD            0x8020
#define CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE         0x8021
#define CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE      0x8022
#define CONFIG_NETWORK_TRANSMIT_GET                              0x8023
#define CONFIG_NETWORK_TRANSMIT_SET                              0x8024
#define CONFIG_NETWORK_TRANSMIT_STATUS                           0x8025
#define CONFIG_RELAY_GET                                         0x8026
#define CONFIG_RELAY_SET                                         0x8027
#define CONFIG_RELAY_STATUS                                      0x8028
#define CONFIG_SIG_MODEL_SUBSCRIPTION_GET                        0x8029
#define CONFIG_SIG_MODEL_SUBSCRIPTION_LIST                       0x802a
#define CONFIG_VENDOR_MODEL_SUBSCRIPTION_GET                     0x802b
#define CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST                    0x802c
#define CONFIG_LOW_POWER_NODE_POLLTIMEOUT_GET                    0x802d
#define CONFIG_LOW_POWER_NODE_POLLTIMEOUT_STATUS                 0x802e
#define HEALTH_FAULT_CLEAR                                       0x802f
#define HEALTH_FAULT_CLEAR_UNACKNOWLEDGED                        0x8030
#define HEALTH_FAULT_GET                                         0x8031
#define HEALTH_FAULT_TEST                                        0x8032
#define HEALTH_FAULT_TEST_UNACKNOWLEDGED                         0x8033
#define HEALTH_PERIOD_GET                                        0x8034
#define HEALTH_PERIOD_SET                                        0x8035
#define HEALTH_PERIOD_SET_UNACKNOWLEDGED                         0x8036
#define HEALTH_PERIOD_STATUS                                     0x8037
#define CONFIG_HEARTBEAT_PUBLICATION_GET                         0x8038
#define CONFIG_HEARTBEAT_PUBLICATION_SET                         0x8039
#define CONFIG_HEARTBEAT_SUBSCRIPTION_GET                        0x803a
#define CONFIG_HEARTBEAT_SUBSCRIPTION_SET                        0x803b
#define CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS                     0x803c
#define CONFIG_MODEL_APP_BIND                                    0x803d
#define CONFIG_MODEL_APP_STATUS                                  0x803e
#define CONFIG_MODEL_APP_UNBIND                                  0x803f
#define CONFIG_NETKEY_ADD                                        0x8040
#define CONFIG_NETKEY_DELETE                                     0x8041
#define CONFIG_NETKEY_GET                                        0x8042
#define CONFIG_NETKEY_LIST                                       0x8043
#define CONFIG_NETKEY_STATUS                                     0x8044
#define CONFIG_NETKEY_UPDATE                                     0x8045
#define CONFIG_NODE_IDENTITY_GET                                 0x8046
#define CONFIG_NODE_IDENTITY_SET                                 0x8047
#define CONFIG_NODE_IDENTITY_STATUS                              0x8048
#define CONFIG_NODE_RESET                                        0x8049
#define CONFIG_NODE_RESET_STATUS                                 0x804a
#define CONFIG_SIG_MODEL_APP_GET                                 0x804b
#define CONFIG_SIG_MODEL_APP_LIST                                0x804c
#define CONFIG_VENDOR_MODEL_APP_GET                              0x804d
#define CONFIG_VENDOR_MODEL_APP_LIST                             0x804e
#define GENERIC_LOCATION_GLOBAL_STATUS                           0x0040
#define GENERIC_LOCATION_GLOBAL_SET                              0x0041
#define GENERIC_LOCATION_GLOBAL_SET_UNACKNOWLEDGED               0x0042
#define GENERIC_ONOFF_GET                                        0x8201
#define GENERIC_ONOFF_SET                                        0x8202
#define GENERIC_ONOFF_SET_UNACKNOWLEDGED                         0x8203
#define GENERIC_ONOFF_STATUS                                     0x8204
#define GENERIC_LEVEL_GET                                        0x8205
#define GENERIC_LEVEL_SET                                        0x8206
#define GENERIC_LEVEL_SET_UNACKNOWLEDGED                         0x8207
#define GENERIC_LEVEL_STATUS                                     0x8208
#define GENERIC_DELTA_SET                                        0x8209
#define GENERIC_DELTA_SET_UNACKNOWLEDGED                         0x820a
#define GENERIC_MOVE_SET                                         0x820b
#define GENERIC_MOVE_SET_UNACKNOWLEDGED                          0x820c
#define GENERIC_DEFAULT_TRANSITION_TIME_GET                      0x820d
#define GENERIC_DEFAULT_TRANSITION_TIME_SET                      0x820e
#define GENERIC_DEFAULT_TRANSITION_TIME_SET_UNACKNOWLEDGED       0x820f
#define GENERIC_DEFAULT_TRANSITION_TIME_STATUS                   0x8210
#define GENERIC_ONPOWERUP_GET                                    0x8211
#define GENERIC_ONPOWERUP_STATUS                                 0x8212
#define GENERIC_ONPOWERUP_SET                                    0x8213
#define GENERIC_ONPOWERUP_SET_UNACKNOWLEDGED                     0x8214
#define GENERIC_POWER_LEVEL_GET                                  0x8215
#define GENERIC_POWER_LEVEL_SET                                  0x8216
#define GENERIC_POWER_LEVEL_SET_UNACKNOWLEDGED                   0x8217
#define GENERIC_POWER_LEVEL_STATUS                               0x8218
#define GENERIC_POWER_LAST_GET                                   0x8219
#define GENERIC_POWER_LAST_STATUS                                0x821a
#define GENERIC_POWER_DEFAULT_GET                                0x821b
#define GENERIC_POWER_DEFAULT_STATUS                             0x821c
#define GENERIC_POWER_RANGE_GET                                  0x821d
#define GENERIC_POWER_RANGE_STATUS                               0x821e
#define GENERIC_POWER_DEFAULT_SET                                0x821f
#define GENERIC_POWER_DEFAULT_SET_UNACKNOWLEDGED                 0x8220
#define GENERIC_POWER_RANGE_SET                                  0x8221
#define GENERIC_POWER_RANGE_SET_UNACKNOWLEDGED                   0x8222
#define GENERIC_BATTERY_GET                                      0x8223
#define GENERIC_BATTERY_STATUS                                   0x8224
#define GENERIC_LOCATION_GLOBAL_GET                              0x8225
#define GENERIC_LOCATION_LOCAL_GET                               0x8226
#define GENERIC_LOCATION_LOCAL_STATUS                            0x8227
#define GENERIC_LOCATION_LOCAL_SET                               0x8228
#define GENERIC_LOCATION_LOCAL_SET_UNACKNOWLEDGED                0x8229
#define SCENE_STATUS                                             0x005e
#define SCENE_GET                                                0x8241
#define SCENE_RECALL                                             0x8242
#define SCENE_RECALL_UNACKNOWLEDGED                              0x8243
#define SCENE_REGISTER_GET                                       0x8244
#define SCENE_REGISTER_STATUS                                    0x8245
#define SCENE_STORE                                              0x8246
#define SCENE_STORE_UNACKNOWLEDGED                               0x8247
#define SCENE_DELETE                                             0x829e
#define SCENE_DELETE_UNACKNOWLEDGED                              0x829f
#define TIME_SET                                                 0x005c
#define TIME_STATUS                                              0x005d
#define SCHEDULER_ACTION_STATUS                                  0x005f
#define SCHEDULER_ACTION_SET                                     0x0060
#define SCHEDULER_ACTION_SET_UNACKNOWLEDGED                      0x0061
#define TIME_GET                                                 0x8237
#define TIME_ROLE_GET                                            0x8238
#define TIME_ROLE_SET                                            0x8239
#define TIME_ROLE_STATUS                                         0x823a
#define TIME_ZONE_GET                                            0x823b
#define TIME_ZONE_SET                                            0x823c
#define TIME_ZONE_STATUS                                         0x823d
#define TAI_UTC_DELTA_GET                                        0x823e
#define TAI_UTC_DELTA_SET                                        0x823f
#define TAI_UTC_DELTA_STATUS                                     0x8240
#define SCHEDULER_ACTION_GET                                     0x8248
#define SCHEDULER_GET                                            0x8249
#define SCHEDULER_STATUS                                         0x824a

#define GENERIC_MANUFACTURER_PROPERTIES_STATUS                   0x0043
#define GENERIC_MANUFACTURER_PROPERTY_SET                        0x0044
#define GENERIC_MANUFACTURER_PROPERTY_SET_UNACKNOWLEDGED         0x0045
#define GENERIC_MANUFACTURER_PROPERTY_STATUS                     0x0046
#define GENERIC_ADMIN_PROPERTIES_STATUS                          0x0047
#define GENERIC_ADMIN_PROPERTY_SET                               0x0048
#define GENERIC_ADMIN_PROPERTY_SET_UNACKNOWLEDGED                0x0049
#define GENERIC_ADMIN_PROPERTY_STATUS                            0x004a
#define GENERIC_USER_PROPERTIES_STATUS                           0x004b
#define GENERIC_USER_PROPERTY_SET                                0x004c
#define GENERIC_USER_PROPERTY_SET_UNACKNOWLEDGED                 0x004d
#define GENERIC_USER_PROPERTY_STATUS                             0x004e
#define GENERIC_CLIENT_PROPERTIES_GET                            0x004f
#define GENERIC_CLIENT_PROPERTIES_STATUS                         0x0050

#define SENSOR_DESCRIPTOR_STATUS                                 0x0051
#define SENSOR_STATUS                                            0x0052
#define SENSOR_COLUMN_STATUS                                     0x0053
#define SENSOR_SERIES_STATUS                                     0x0054
#define SENSOR_CADENCE_SET                                       0x0055
#define SENSOR_CADENCE_SET_UNACKNOWLEDGED                        0x0056
#define SENSOR_CADENCE_STATUS                                    0x0057
#define SENSOR_SETTINGS_STATUS                                   0x0058
#define SENSOR_SETTING_SET                                       0x0059
#define SENSOR_SETTING_SET_UNACKNOWLEDGED                        0x005a
#define SENSOR_SETTING_STATUS                                    0x005b
#define GENERIC_MANUFACTURER_PROPERTIES_GET                      0x822a
#define GENERIC_MANUFACTURER_PROPERTY_GET                        0x822b
#define GENERIC_ADMIN_PROPERTIES_GET                             0x822c
#define GENERIC_ADMIN_PROPERTY_GET                               0x822d
#define GENERIC_USER_PROPERTIES_GET                              0x822e
#define GENERIC_USER_PROPERTY_GET                                0x822f
#define SENSOR_DESCRIPTOR_GET                                    0x8230
#define SENSOR_GET                                               0x8231
#define SENSOR_COLUMN_GET                                        0x8232
#define SENSOR_SERIES_GET                                        0x8233
#define SENSOR_CADENCE_GET                                       0x8234
#define SENSOR_SETTINGS_GET                                      0x8235
#define SENSOR_SETTING_GET                                       0x8236

#define LIGHT_LIGHTNESS_GET                                      0x824b
#define LIGHT_LIGHTNESS_SET                                      0x824c
#define LIGHT_LIGHTNESS_SET_UNACKNOWLEDGED                       0x824d
#define LIGHT_LIGHTNESS_STATUS                                   0x824e
#define LIGHT_LIGHTNESS_LINEAR_GET                               0x824f
#define LIGHT_LIGHTNESS_LINEAR_SET                               0x8250
#define LIGHT_LIGHTNESS_LINEAR_SET_UNACKNOWLEDGED                0x8251
#define LIGHT_LIGHTNESS_LINEAR_STATUS                            0x8252
#define LIGHT_LIGHTNESS_LAST_GET                                 0x8253
#define LIGHT_LIGHTNESS_LAST_STATUS                              0x8254
#define LIGHT_LIGHTNESS_DEFAULT_GET                              0x8255
#define LIGHT_LIGHTNESS_DEFAULT_STATUS                           0x8256
#define LIGHT_LIGHTNESS_RANGE_GET                                0x8257
#define LIGHT_LIGHTNESS_RANGE_STATUS                             0x8258
#define LIGHT_LIGHTNESS_DEFAULT_SET                              0x8259
#define LIGHT_LIGHTNESS_DEFAULT_SET_UNACKNOWLEDGED               0x825a
#define LIGHT_LIGHTNESS_RANGE_SET                                0x825b
#define LIGHT_LIGHTNESS_RANGE_SET_UNACKNOWLEDGED                 0x825c
#define LIGHT_CTL_GET                                            0x825d
#define LIGHT_CTL_SET                                            0x825e
#define LIGHT_CTL_SET_UNACKNOWLEDGED                             0x825f
#define LIGHT_CTL_STATUS                                         0x8260
#define LIGHT_CTL_TEMPERATURE_GET                                0x8261
#define LIGHT_CTL_TEMPERATURE_RANGE_GET                          0x8262
#define LIGHT_CTL_TEMPERATURE_RANGE_STATUS                       0x8263
#define LIGHT_CTL_TEMPERATURE_SET                                0x8264
#define LIGHT_CTL_TEMPERATURE_SET_UNACKNOWLEDGED                 0x8265
#define LIGHT_CTL_TEMPERATURE_STATUS                             0x8266
#define LIGHT_CTL_DEFAULT_GET                                    0x8267
#define LIGHT_CTL_DEFAULT_STATUS                                 0x8268
#define LIGHT_CTL_DEFAULT_SET                                    0x8269
#define LIGHT_CTL_DEFAULT_SET_UNACKNOWLEDGED                     0x826a
#define LIGHT_CTL_TEMPERATURE_RANGE_SET                          0x826b
#define LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACKNOWLEDGED           0x826c
#define LIGHT_HSL_GET                                            0x826d
#define LIGHT_HSL_HUE_GET                                        0x826e
#define LIGHT_HSL_HUE_SET                                        0x826f
#define LIGHT_HSL_HUE_SET_UNACKNOWLEDGED                         0x8270
#define LIGHT_HSL_HUE_STATUS                                     0x8271
#define LIGHT_HSL_SATURATION_GET                                 0x8272
#define LIGHT_HSL_SATURATION_SET                                 0x8273
#define LIGHT_HSL_SATURATION_SET_UNACKNOWLEDGED                  0x8274
#define LIGHT_HSL_SATURATION_STATUS                              0x8275
#define LIGHT_HSL_SET                                            0x8276
#define LIGHT_HSL_SET_UNACKNOWLEDGED                             0x8277
#define LIGHT_HSL_STATUS                                         0x8278
#define LIGHT_HSL_TARGET_GET                                     0x8279
#define LIGHT_HSL_TARGET_STATUS                                  0x827a
#define LIGHT_HSL_DEFAULT_GET                                    0x827b
#define LIGHT_HSL_DEFAULT_STATUS                                 0x827c
#define LIGHT_HSL_RANGE_GET                                      0x827d
#define LIGHT_HSL_RANGE_STATUS                                   0x827e
#define LIGHT_HSL_DEFAULT_SET                                    0x827f
#define LIGHT_HSL_DEFAULT_SET_UNACKNOWLEDGED                     0x8280
#define LIGHT_HSL_RANGE_SET                                      0x8281
#define LIGHT_HSL_RANGE_SET_UNACKNOWLEDGED                       0x8282
#define LIGHT_XYL_GET                                            0x8283
#define LIGHT_XYL_SET                                            0x8284
#define LIGHT_XYL_SET_UNACKNOWLEDGED                             0x8285
#define LIGHT_XYL_STATUS                                         0x8286
#define LIGHT_XYL_TARGET_GET                                     0x8287
#define LIGHT_XYL_TARGET_STATUS                                  0x8288
#define LIGHT_XYL_DEFAULT_GET                                    0x8289
#define LIGHT_XYL_DEFAULT_STATUS                                 0x828a
#define LIGHT_XYL_RANGE_GET                                      0x828b
#define LIGHT_XYL_RANGE_STATUS                                   0x828c
#define LIGHT_XYL_DEFAULT_SET                                    0x828d
#define LIGHT_XYL_DEFAULT_SET_UNACKNOWLEDGED                     0x828e
#define LIGHT_XYL_RANGE_SET                                      0x828f
#define LIGHT_XYL_RANGE_SET_UNACKNOWLEDGED                       0x8290
#define LIGHT_LC_MODE_GET                                        0x8291
#define LIGHT_LC_MODE_SET                                        0x8292
#define LIGHT_LC_MODE_SET_UNACKNOWLEDGED                         0x8293
#define LIGHT_LC_MODE_STATUS                                     0x8294
#define LIGHT_LC_OM_GET                                          0x8295
#define LIGHT_LC_OM_SET                                          0x8296
#define LIGHT_LC_OM_SET_UNACKNOWLEDGED                           0x8297
#define LIGHT_LC_OM_STATUS                                       0x8298
#define LIGHT_LC_LIGHT_ONOFF_GET                                 0x8299
#define LIGHT_LC_LIGHT_ONOFF_SET                                 0x829a
#define LIGHT_LC_LIGHT_ONOFF_SET_UNACKNOWLEDGED                  0x829b
#define LIGHT_LC_LIGHT_ONOFF_STATUS                              0x829c
#define LIGHT_LC_PROPERTY_GET                                    0x829d

#define PHONY_PROPERTY_PERCENTAGE_CHANGE_16                                 0xFFFF
#define PHONY_PROPERTY_INDEX                                                0xFFFE
#define PROPERTY_AVERAGE_AMBIENT_TEMPERATURE_IN_A_PERIOD_OF_DAY             0x0001
#define PROPERTY_AVERAGE_INPUT_CURRENT                                      0x0002
#define PROPERTY_AVERAGE_INPUT_VOLTAGE                                      0x0003
#define PROPERTY_AVERAGE_OUTPUT_CURRENT                                     0x0004
#define PROPERTY_AVERAGE_OUTPUT_VOLTAGE                                     0x0005
#define PROPERTY_CENTER_BEAM_INTENSITY_AT_FULL_POWER                        0x0006
#define PROPERTY_CHROMATICITY_TOLERANCE                                     0x0007
#define PROPERTY_COLOR_RENDERING_INDEX_R9                                   0x0008
#define PROPERTY_COLOR_RENDERING_INDEX_RA                                   0x0009
#define PROPERTY_DEVICE_APPEARANCE                                          0x000A
#define PROPERTY_DEVICE_COUNTRY_OF_ORIGIN                                   0x000B
#define PROPERTY_DEVICE_DATE_OF_MANUFACTURE                                 0x000C
#define PROPERTY_DEVICE_ENERGY_USE_SINCE_TURN_ON                            0x000D
#define PROPERTY_DEVICE_FIRMWARE_REVISION                                   0x000E
#define PROPERTY_DEVICE_GLOBAL_TRADE_ITEM_NUMBER                            0x000F
#define PROPERTY_DEVICE_HARDWARE_REVISION                                   0x0010
#define PROPERTY_DEVICE_MANUFACTURER_NAME                                   0x0011
#define PROPERTY_DEVICE_MODEL_NUMBER                                        0x0012
#define PROPERTY_DEVICE_OPERATING_TEMPERATURE_RANGE_SPECIFICATION           0x0013
#define PROPERTY_DEVICE_OPERATING_TEMPERATURE_STATISTICAL_VALUES            0x0014
#define PROPERTY_DEVICE_OVER_TEMPERATURE_EVENT_STATISTICS                   0x0015
#define PROPERTY_DEVICE_POWER_RANGE_SPECIFICATION                           0x0016
#define PROPERTY_DEVICE_RUNTIME_SINCE_TURN_ON                               0x0017
#define PROPERTY_DEVICE_RUNTIME_WARRANTY                                    0x0018
#define PROPERTY_DEVICE_SERIAL_NUMBER                                       0x0019
#define PROPERTY_DEVICE_SOFTWARE_REVISION                                   0x001A
#define PROPERTY_DEVICE_UNDER_TEMPERATURE_EVENT_STATISTICS                  0x001B
#define PROPERTY_INDOOR_AMBIENT_TEMPERATURE_STATISTICAL_VALUES              0x001C
#define PROPERTY_INITIAL_CIE_1931_CHROMATICITY_COORDINATES                  0x001D
#define PROPERTY_INITIAL_CORRELATED_COLOR_TEMPERATURE                       0x001E
#define PROPERTY_INITIAL_LUMINOUS_FLUX                                      0x001F
#define PROPERTY_INITIAL_PLANCKIAN_DISTANCE                                 0x0020
#define PROPERTY_INPUT_CURRENT_RANGE_SPECIFICATION                          0x0021
#define PROPERTY_INPUT_CURRENT_STATISTICS                                   0x0022
#define PROPERTY_INPUT_OVER_CURRENT_EVENT_STATISTICS                        0x0023
#define PROPERTY_INPUT_OVER_RIPPLE_VOLTAGE_EVENT_STATISTICS                 0x0024
#define PROPERTY_INPUT_OVER_VOLTAGE_EVENT_STATISTICS                        0x0025
#define PROPERTY_INPUT_UNDER_CURRENT_EVENT_STATISTICS                       0x0026
#define PROPERTY_INPUT_UNDER_VOLTAGE_EVENT_STATISTICS                       0x0027
#define PROPERTY_INPUT_VOLTAGE_RANGE_SPECIFICATION                          0x0028
#define PROPERTY_INPUT_VOLTAGE_RIPPLE_SPECIFICATION                         0x0029
#define PROPERTY_INPUT_VOLTAGE_STATISTICS                                   0x002A
#define PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_ON                         0x002B
#define PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_PROLONG                    0x002C
#define PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_STANDBY                    0x002D
#define PROPERTY_LIGHT_CONTROL_LIGHTNESS_ON                                 0x002E
#define PROPERTY_LIGHT_CONTROL_LIGHTNESS_PROLONG                            0x002F
#define PROPERTY_LIGHT_CONTROL_LIGHTNESS_STANDBY                            0x0030
#define PROPERTY_LIGHT_CONTROL_REGULATOR_ACCURACY                           0x0031
#define PROPERTY_LIGHT_CONTROL_REGULATOR_KID                                0x0032
#define PROPERTY_LIGHT_CONTROL_REGULATOR_KIU                                0x0033
#define PROPERTY_LIGHT_CONTROL_REGULATOR_KPD                                0x0034
#define PROPERTY_LIGHT_CONTROL_REGULATOR_KPU                                0x0035
#define PROPERTY_LIGHT_CONTROL_TIME_FADE                                    0x0036
#define PROPERTY_LIGHT_CONTROL_TIME_FADE_ON                                 0x0037
#define PROPERTY_LIGHT_CONTROL_TIME_FADE_STANDBY_AUTO                       0x0038
#define PROPERTY_LIGHT_CONTROL_TIME_FADE_STANDBY_MANUAL                     0x0039
#define PROPERTY_LIGHT_CONTROL_TIME_OCCUPANCY_DELAY                         0x003A
#define PROPERTY_LIGHT_CONTROL_TIME_PROLONG                                 0x003B
#define PROPERTY_LIGHT_CONTROL_TIME_RUN_ON                                  0x003C
#define PROPERTY_LUMEN_MAINTENANCE_FACTOR                                   0x003D
#define PROPERTY_LUMINOUS_EFFICACY                                          0x003E
#define PROPERTY_LUMINOUS_ENERGY_SINCE_TURN_ON                              0x003F
#define PROPERTY_LUMINOUS_EXPOSURE                                          0x0040
#define PROPERTY_LUMINOUS_FLUX_RANGE                                        0x0041
#define PROPERTY_MOTION_SENSED                                              0x0042
#define PROPERTY_MOTION_THRESHOLD                                           0x0043
#define PROPERTY_OPEN_CIRCUIT_EVENT_STATISTICS                              0x0044
#define PROPERTY_OUTDOOR_STATISTICAL_VALUES                                 0x0045
#define PROPERTY_OUTPUT_CURRENT_RANGE                                       0x0046
#define PROPERTY_OUTPUT_CURRENT_STATISTICS                                  0x0047
#define PROPERTY_OUTPUT_RIPPLE_VOLTAGE_SPECIFICATION                        0x0048
#define PROPERTY_OUTPUT_VOLTAGE_RANGE                                       0x0049
#define PROPERTY_OUTPUT_VOLTAGE_STATISTICS                                  0x004A
#define PROPERTY_OVER_OUTPUT_RIPPLE_VOLTAGE_EVENT_STATISTICS                0x004B
#define PROPERTY_PEOPLE_COUNT                                               0x004C
#define PROPERTY_PRESENCE_DETECTED                                          0x004D
#define PROPERTY_PRESENT_AMBIENT_LIGHT_LEVEL                                0x004E
#define PROPERTY_PRESENT_AMBIENT_TEMPERATURE                                0x004F
#define PROPERTY_PRESENT_CIE_1931_CHROMATICITY_COORDINATES                  0x0050
#define PROPERTY_PRESENT_CORRELATED_COLOR_TEMPERATURE                       0x0051
#define PROPERTY_PRESENT_DEVICE_INPUT_POWER                                 0x0052
#define PROPERTY_PRESENT_DEVICE_OPERATING_EFFICIENCY                        0x0053
#define PROPERTY_PRESENT_DEVICE_OPERATING_TEMPERATURE                       0x0054
#define PROPERTY_PRESENT_ILLUMINANCE                                        0x0055
#define PROPERTY_PRESENT_INDOOR_AMBIENT_TEMPERATURE                         0x0056
#define PROPERTY_PRESENT_INPUT_CURRENT                                      0x0057
#define PROPERTY_PRESENT_INPUT_RIPPLE_VOLTAGE                               0x0058
#define PROPERTY_PRESENT_INPUT_VOLTAGE                                      0x0059
#define PROPERTY_PRESENT_LUMINOUS_FLUX                                      0x005A
#define PROPERTY_PRESENT_OUTDOOR_AMBIENT_TEMPERATURE                        0x005B
#define PROPERTY_PRESENT_OUTPUT_CURRENT                                     0x005C
#define PROPERTY_PRESENT_OUTPUT_VOLTAGE                                     0x005D
#define PROPERTY_PRESENT_PLANCKIAN_DISTANCE                                 0x005E
#define PROPERTY_PRESENT_RELATIVE_OUTPUT_RIPPLE_VOLTAGE                     0x005F
#define PROPERTY_RELATIVE_DEVICE_ENERGY_USE_IN_A_PERIOD_OF_DAY              0x0060
#define PROPERTY_RELATIVE_DEVICE_RUNTIME_IN_A_GENERIC_LEVEL_RANGE           0x0061
#define PROPERTY_RELATIVE_EXPOSURE_TIME_IN_AN_ILLUMINANCE_RANGE             0x0062
#define PROPERTY_RELATIVE_RUNTIME_IN_A_CORRELATED_COLOR_TEMPERATURE_RANGE   0x0063
#define PROPERTY_RELATIVE_RUNTIME_IN_A_DEVICE_OPERATING_TEMPERATURE_RANGE   0x0064
#define PROPERTY_RELATIVE_RUNTIME_IN_AN_INPUT_CURRENT_RANGE                 0x0065
#define PROPERTY_RELATIVE_RUNTIME_IN_AN_INPUT_VOLTAGE_RANGE                 0x0066
#define PROPERTY_SHORT_CIRCUIT_EVENT_STATISTICS                             0x0067
#define PROPERTY_TIME_SINCE_MOTION_SENSED                                   0x0068
#define PROPERTY_TIME_SINCE_PRESENCE_DETECTED                               0x0069
#define PROPERTY_TOTAL_DEVICE_ENERGY_USE                                    0x006A
#define PROPERTY_TOTAL_DEVICE_OFF_ON_CYCLES                                 0x006B
#define PROPERTY_TOTAL_DEVICE_POWER_ON_CYCLES                               0x006C
#define PROPERTY_TOTAL_DEVICE_POWER_ON_TIME                                 0x006D
#define PROPERTY_TOTAL_DEVICE_RUNTIME                                       0x006E
#define PROPERTY_TOTAL_LIGHT_EXPOSURE_TIME                                  0x006F
#define PROPERTY_TOTAL_LUMINOUS_ENERGY                                      0x0070
#define PROPERTY_DESIRED_AMBIENT_TEMPERATURE                                0x0071
#define PROPERTY_PRECISE_TOTAL_DEVICE_ENERGY_USE                            0x0072
#define PROPERTY_POWER_FACTOR                                               0x0073
#define PROPERTY_SENSOR_GAIN                                                0x0074
#define PROPERTY_PRECISE_PRESENT_AMBIENT_TEMPERATURE                        0x0075
#define PROPERTY_PRESENT_AMBIENT_RELATIVE_HUMIDITY                          0x0076
#define PROPERTY_PRESENT_AMBIENT_CARBON_DIOXIDE_CONCENTRATION               0x0077
#define PROPERTY_PRESENT_AMBIENT_VOLATILE_ORGANIC_COMPOUNDS_CONCENTRATION   0x0078
#define PROPERTY_PRESENT_AMBIENT_NOISE                                      0x0079
#define PROPERTY_ACTIVE_ENERGY_LOADSIDE                                     0x0080
#define PROPERTY_ACTIVE_POWER_LOADSIDE                                      0x0081
#define PROPERTY_AIR_PRESSURE                                               0x0082
#define PROPERTY_APPARENT_ENERGY                                            0x0083
#define PROPERTY_APPARENT_POWER                                             0x0084
#define PROPERTY_APPARENT_WIND_DIRECTION                                    0x0085
#define PROPERTY_APPARENT_WIND_SPEED                                        0x0086
#define PROPERTY_DEW_POINT                                                  0x0087
#define PROPERTY_EXTERNAL_SUPPLY_VOLTAGE                                    0x0088
#define PROPERTY_EXTERNAL_SUPPLY_VOLTAGE_FREQUENCY                          0x0089
#define PROPERTY_GUST_FACTOR                                                0x008A
#define PROPERTY_HEAT_INDEX                                                 0x008B
#define PROPERTY_LIGHT_DISTRIBUTION                                         0x008C
#define PROPERTY_LIGHT_SOURCE_CURRENT                                       0x008D
#define PROPERTY_LIGHT_SOURCE_ON_TIME_NOT_RESETTABLE                        0x008E
#define PROPERTY_LIGHT_SOURCE_ON_TIME_RESETTABLE                            0x008F
#define PROPERTY_LIGHT_SOURCE_OPEN_CIRCUIT_STATISTICS                       0x0090
#define PROPERTY_LIGHT_SOURCE_OVERALL_FAILURES_STATISTICS                   0x0091
#define PROPERTY_LIGHT_SOURCE_SHORT_CIRCUIT_STATISTICS                      0x0092
#define PROPERTY_LIGHT_SOURCE_START_COUNTER_RESETTABLE                      0x0093
#define PROPERTY_LIGHT_SOURCE_TEMPERATURE                                   0x0094
#define PROPERTY_LIGHT_SOURCE_THERMAL_DERATING_STATISTICS                   0x0095
#define PROPERTY_LIGHT_SOURCE_THERMAL_SHUTDOWN_STATISTICS                   0x0096
#define PROPERTY_LIGHT_SOURCE_TOTAL_POWER_ON_CYCLES                         0x0097
#define PROPERTY_LIGHT_SOURCE_VOLTAGE                                       0x0098
#define PROPERTY_LUMINAIRE_COLOR                                            0x0099
#define PROPERTY_LUMINAIRE_IDENTIFICATION_NUMBER                            0x009A
#define PROPERTY_LUMINAIRE_MANUFACTURER_GTIN                                0x009B
#define PROPERTY_LUMINAIRE_NOMINAL_INPUT_POWER                              0x009C
#define PROPERTY_LUMINAIRE_NOMINAL_MAXIMUM_AC_MAINS_VOLTAGE                 0x009D
#define PROPERTY_LUMINAIRE_NOMINAL_MINIMUM_AC_MAINS_VOLTAGE                 0x009E
#define PROPERTY_LUMINAIRE_POWER_AT_MINIMUM_DIM_LEVEL                       0x009F
#define PROPERTY_LUMINAIRE_TIME_OF_MANUFACTURE                              0x00A0
#define PROPERTY_MAGNETIC_DECLINATION                                       0x00A1
#define PROPERTY_MAGNETIC_FLUX_DENSITY_2_D                                  0x00A2
#define PROPERTY_MAGNETIC_FLUX_DENSITY_3_D                                  0x00A3
#define PROPERTY_NOMINAL_LIGHT_OUTPUT                                       0x00A4
#define PROPERTY_OVERALL_FAILURE_CONDITION                                  0x00A5
#define PROPERTY_POLLEN_CONCENTRATION                                       0x00A6
#define PROPERTY_PRESENT_INDOOR_RELATIVE_HUMIDITY                           0x00A7
#define PROPERTY_PRESENT_OUTDOOR_RELATIVE_HUMIDITY                          0x00A8
#define PROPERTY_PRESSURE                                                   0x00A9
#define PROPERTY_RAINFALL                                                   0x00AA
#define PROPERTY_RATED_MEDIAN_USEFUL_LIFE_OF_LUMINAIRE                      0x00AB
#define PROPERTY_RATED_MEDIAN_USEFUL_LIGHT_SOURCE_STARTS                    0x00AC
#define PROPERTY_REFERENCE_TEMPERATURE                                      0x00AD
#define PROPERTY_TOTAL_DEVICE_STARTS                                        0x00AE
#define PROPERTY_TRUE_WIND_DIRECTION                                        0x00AF
#define PROPERTY_TRUE_WIND_SPEED                                            0x00B0
#define PROPERTY_UV_INDEX                                                   0x00B1
#define PROPERTY_WIND_CHILL                                                 0x00B2
#define PROPERTY_LIGHT_SOURCE_TYPE                                          0x00B3
#define PROPERTY_LUMINAIRE_IDENTIFICATION_STRING                            0x00B4
#define PROPERTY_OUTPUT_POWER_LIMITATION                                    0x00B5
#define PROPERTY_THERMAL_DERATING                                           0x00B6
#define PROPERTY_OUTPUT_CURRENT_PERCENT                                     0x00B7

#define PHONY_CHARACTERISTIC_PERCENTAGE_CHANGE_16                 0xFFFF
#define PHONY_CHARACTERISTIC_INDEX                                0xFFFE
#define CHARACTERISTIC_APPARENT_ENERGY32                          0x2BCF
#define CHARACTERISTIC_APPARENT_POWER                             0x2BD0
#define CHARACTERISTIC_APPARENT_WIND_DIRECTION                    0x2A73
#define CHARACTERISTIC_APPARENT_WIND_SPEED                        0x2A72
#define CHARACTERISTIC_APPEARANCE                                 0x2A01
#define CHARACTERISTIC_AVERAGE_CURRENT                            0x2AE0
#define CHARACTERISTIC_AVERAGE_VOLTAGE                            0x2AE1
#define CHARACTERISTIC_BOOLEAN                                    0x2AE2
#define CHARACTERISTIC_CHROMATIC_DISTANCE_FROM_PLANCKIAN          0x2AE3
#define CHARACTERISTIC_CHROMATICITY_COORDINATES                   0x2AE4
#define CHARACTERISTIC_CHROMATICITY_TOLERANCE                     0x2AE6
#define CHARACTERISTIC_CIE_13_3_1995_COLOR_RENDERING_INDEX        0x2AE7
#define CHARACTERISTIC_CO2_CONCENTRATION                          0x2BD1
#define CHARACTERISTIC_COEFFICIENT                                0x2AE8
#define CHARACTERISTIC_CORRELATED_COLOR_TEMPERATURE               0x2AE9
#define CHARACTERISTIC_COSINE_OF_THE_ANGLE                        0x2BD2
#define CHARACTERISTIC_COUNT_16                                   0x2AEA
#define CHARACTERISTIC_COUNT_24                                   0x2AEB
#define CHARACTERISTIC_COUNTRY_CODE                               0x2AEC
#define CHARACTERISTIC_DATE_UTC                                   0x2AED
#define CHARACTERISTIC_DECIHOUR_8                                 0x2B12
#define CHARACTERISTIC_DEW_POINT                                  0x2BD3
#define CHARACTERISTIC_ELECTRIC_CURRENT                           0x2AEE
#define CHARACTERISTIC_ELECTRIC_CURRENT_RANGE                     0x2AEF
#define CHARACTERISTIC_ELECTRIC_CURRENT_SPECIFICATION             0x2AF0
#define CHARACTERISTIC_ELECTRIC_CURRENT_STATISTICS                0x2AF1
#define CHARACTERISTIC_ENERGY                                     0x2AF2
#define CHARACTERISTIC_ENERGY_IN_A_PERIOD_OF_DAY                  0x2AF3
#define CHARACTERISTIC_ENERGY32                                   0x2BD4
#define CHARACTERISTIC_EVENT_STATISTICS                           0x2AF4
#define CHARACTERISTIC_FIXED_STRING_16                            0x2AF5
#define CHARACTERISTIC_FIXED_STRING_24                            0x2AF6
#define CHARACTERISTIC_FIXED_STRING_36                            0x2AF7
#define CHARACTERISTIC_FIXED_STRING_64                            0x2BD5
#define CHARACTERISTIC_FIXED_STRING_8                             0x2AF8
#define CHARACTERISTIC_GENERIC_LEVEL                              0X2AF9
#define CHARACTERISTIC_GLOBAL_TRADE_ITEM_NUMBER                   0x2AFA
#define CHARACTERISTIC_GUST_FACTOR                                0x2A74
#define CHARACTERISTIC_HEAT_INDEX                                 0x2A7A
#define CHARACTERISTIC_HIGH_TEMPERATURE                           0x2BD6
#define CHARACTERISTIC_HIGH_VOLTAGE                               0x2BD7
#define CHARACTERISTIC_HUMIDITY                                   0x2A6F
#define CHARACTERISTIC_ILLUMINANCE                                0x2AFB
#define CHARACTERISTIC_LIGHT_DISTRIBUTION                         0x2BD8
#define CHARACTERISTIC_LIGHT_OUTPUT                               0x2BD9
#define CHARACTERISTIC_LIGHT_SOURCE_TYPE                          0x2BDA
#define CHARACTERISTIC_LUMINOUS_EFFICACY                          0x2AFC
#define CHARACTERISTIC_LUMINOUS_ENERGY                            0x2AFD
#define CHARACTERISTIC_LUMINOUS_EXPOSURE                          0x2AFE
#define CHARACTERISTIC_LUMINOUS_FLUX                              0x2AFF
#define CHARACTERISTIC_LUMINOUS_FLUX_RANGE                        0x2B00
#define CHARACTERISTIC_LUMINOUS_INTENSITY                         0x2B01
#define CHARACTERISTIC_MAGNETIC_DECLINATION                       0x2BDB
#define CHARACTERISTIC_MAGNETIC_FLUX_DENSITY_2_D                  0x2AA0
#define CHARACTERISTIC_MAGNETIC_FLUX_DENSITY_3_D                  0x2AA1
#define CHARACTERISTIC_NOISE                                      0x2BDC
#define CHARACTERISTIC_PERCEIVED_LIGHTNESS                        0x2B03
#define CHARACTERISTIC_PERCENTAGE_8                               0x2B04
#define CHARACTERISTIC_POLLEN_CONCENTRATION                       0x2A75
#define CHARACTERISTIC_POWER                                      0x2B05
#define CHARACTERISTIC_POWER_SPECIFICATION                        0x2B06
#define CHARACTERISTIC_PRESSURE                                   0x2A6D
#define CHARACTERISTIC_RAINFALL                                   0x2A78
#define CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_CURRENT_RANGE        0x2B07
#define CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_GENERIC_LEVEL_RANGE  0x2B08
#define CHARACTERISTIC_RELATIVE_VALUE_IN_A_TEMPERATURE_RANGE      0x2B0C
#define CHARACTERISTIC_RELATIVE_VALUE_IN_A_VOLTAGE_RANGE          0x2B09
#define CHARACTERISTIC_RELATIVE_VALUE_IN_AN_ILLUMINANCE_RANGE     0x2B0A
#define CHARACTERISTIC_TEMPERATURE                                0x2A6E
#define CHARACTERISTIC_TEMPERATURE_8                              0x2B0D
#define CHARACTERISTIC_TEMPERATURE_8_IN_A_PERIOD_OF_DAY           0x2B0E
#define CHARACTERISTIC_TEMPERATURE_8_STATISTICS                   0x2B0F
#define CHARACTERISTIC_TEMPERATURE_RANGE                          0x2B10
#define CHARACTERISTIC_TEMPERATURE_STATISTICS                     0x2B11
#define CHARACTERISTIC_TIME_HOUR_24                               0x2B14
#define CHARACTERISTIC_TIME_MILLISECOND_24                        0x2B15
#define CHARACTERISTIC_TIME_SECOND_16                             0x2B16
#define CHARACTERISTIC_TIME_SECOND_32                             0x2BDE
#define CHARACTERISTIC_TRUE_WIND_DIRECTION                        0x2A71
#define CHARACTERISTIC_TRUE_WIND_SPEED                            0x2A70
#define CHARACTERISTIC_UV_INDEX                                   0x2A76
#define CHARACTERISTIC_VOC_CONCENTRATION                          0x2BDF
#define CHARACTERISTIC_VOLTAGE                                    0x2B18
#define CHARACTERISTIC_VOLTAGE_FREQUENCY                          0x2BE0
#define CHARACTERISTIC_VOLTAGE_SPECIFICATION                      0x2B19
#define CHARACTERISTIC_VOLTAGE_STATISTICS                         0x2B1A
#define CHARACTERISTIC_WIND_CHILL                                 0x2A79

void proto_register_btmesh(void);

static int proto_btmesh;
static dissector_table_t btmesh_model_vendor_dissector_table;

/*-------------------------------------
 * UAT for BT Mesh
 *-------------------------------------
 */
static uat_t *btmesh_uat;
static unsigned num_btmesh_uat;

/* UAT Network, Application and IVIndex entry structure. */
typedef struct {
    char *network_key_string;
    uint8_t *network_key;
    int network_key_length;
    char *ivindex_string;
    int ivindex_string_length;
    uint8_t *ivindex;
    uint8_t *privacykey;
    uint8_t *encryptionkey;
    uint8_t nid;
    char *application_key_string;
    uint8_t *application_key;
    int application_key_length;
    uint8_t aid;
    uint8_t valid; /* this counter must be equal to BTMESH_KEY_ENTRY_VALID make UAT entry valid */
    uint32_t net_key_iv_index_hash; /* Used to identify net key / IV index pair */
} uat_btmesh_record_t;

static uat_btmesh_record_t *uat_btmesh_records;

static uat_t *btmesh_dev_key_uat;
static unsigned num_btmesh_dev_key_uat;

/* UAT Device Key entry structure. */
typedef struct {
    char *device_key_string;
    uint8_t *device_key;
    int device_key_length;
    char *src_string;
    int src_length;
    uint8_t *src;
    uint8_t valid; /* this counter must be equal to BTMESH_DEVICE_KEY_ENTRY_VALID make UAT entry valid */
} uat_btmesh_dev_key_record_t;

static uat_btmesh_dev_key_record_t *uat_btmesh_dev_key_records;

static uat_t * btmesh_label_uuid_uat;
static unsigned num_btmesh_label_uuid_uat;

/* UAT Label UUID entry structure. */
typedef struct {
    char *label_uuid_string;
    uint8_t *label_uuid;
    int label_uuid_length;
    uint16_t hash;
    uint8_t valid; /* this counter must be equal to BTMESH_LABEL_UUID_ENTRY_VALID make UAT entry valid */
} uat_btmesh_label_uuid_record_t;

static uat_btmesh_label_uuid_record_t *uat_btmesh_label_uuid_records;

typedef struct {
    uint16_t property_id;
    uint16_t characteristic_id;
} btmesh_property_t;

typedef struct {
    uint16_t characteristic_id;
    uint16_t characteristic_value_length;
    int     *hfindex;
    uint8_t dissector_type;
} bt_gatt_characteristic_t;

typedef struct {
    uint16_t characteristic_id;
    uint16_t x_characteristic_id;
    uint16_t y_characteristic_id;
} btmesh_column_property_t;

typedef struct {
    int *hf_status_trigger_delta_up;
    int *hf_status_trigger_delta_down;
    int *hf_status_min_interval;
    int *hf_fast_cadence_low;
    int *hf_fast_cadence_high;
    int *hf_remainder_not_dissected;
} bt_sensor_cadence_dissector_t;

typedef struct {
    int *hf_raw_value_a;
    int *hf_raw_value_b;
    int *hf_raw_value_c;
} bt_property_raw_value_entry_t;

typedef struct {
    int *hf_raw_value_a1;
    int *hf_raw_value_a2;
} bt_property_columns_raw_value_t;

static int hf_btmesh_ivi;
static int hf_btmesh_nid;
static int hf_btmesh_obfuscated;
static int hf_btmesh_encrypted;
static int hf_btmesh_netmic;

static int hf_btmesh_ctl;
static int hf_btmesh_ttl;
static int hf_btmesh_seq;
static int hf_btmesh_src;
static int hf_btmesh_dst;

static int hf_btmesh_transp_pdu;
static int hf_btmesh_cntr_seg;
static int hf_btmesh_acc_seg;
static int hf_btmesh_cntr_opcode;
static int hf_btmesh_acc_akf;
static int hf_btmesh_acc_aid;
static int hf_btmesh_obo;
static int hf_btmesh_seqzero;
static int hf_btmesh_rfu;
static int hf_btmesh_blockack;
static int hf_btmesh_cntr_criteria_rfu;
static int hf_btmesh_cntr_padding;
static int hf_btmesh_cntr_fsn;

static int hf_btmesh_cntr_key_refresh_flag;
static int hf_btmesh_cntr_iv_update_flag;
static int hf_btmesh_cntr_flags_rfu;
static int hf_btmesh_cntr_iv_index;
static int hf_btmesh_cntr_md;

static int hf_btmesh_cntr_heartbeat_rfu;
static int hf_btmesh_cntr_init_ttl;
static int hf_btmesh_cntr_feature_relay;
static int hf_btmesh_cntr_feature_proxy;
static int hf_btmesh_cntr_feature_friend;
static int hf_btmesh_cntr_feature_low_power;
static int hf_btmesh_cntr_feature_rfu;

static int hf_btmesh_cntr_criteria_rssifactor;
static int hf_btmesh_cntr_criteria_receivewindowfactor;
static int hf_btmesh_cntr_criteria_minqueuesizelog;
static int hf_btmesh_cntr_receivedelay;
static int hf_btmesh_cntr_polltimeout;
static int hf_btmesh_cntr_previousaddress;
static int hf_btmesh_cntr_numelements;
static int hf_btmesh_cntr_lpncounter;
static int hf_btmesh_cntr_receivewindow;
static int hf_btmesh_cntr_queuesize;
static int hf_btmesh_cntr_subscriptionlistsize;
static int hf_btmesh_cntr_rssi;
static int hf_btmesh_cntr_friendcounter;
static int hf_btmesh_cntr_lpnaddress;
static int hf_btmesh_cntr_transactionnumber;
static int hf_btmesh_enc_access_pld;
static int hf_btmesh_transtmic;
static int hf_btmesh_szmic;
static int hf_btmesh_seqzero_data;
static int hf_btmesh_sego;
static int hf_btmesh_segn;
static int hf_btmesh_seg_rfu;
static int hf_btmesh_segment;
static int hf_btmesh_cntr_unknown_payload;

static int hf_btmesh_segmented_access_fragments;
static int hf_btmesh_segmented_access_fragment;
static int hf_btmesh_segmented_access_fragment_overlap;
static int hf_btmesh_segmented_access_fragment_overlap_conflict;
static int hf_btmesh_segmented_access_fragment_multiple_tails;
static int hf_btmesh_segmented_access_fragment_too_long_fragment;
static int hf_btmesh_segmented_access_fragment_error;
static int hf_btmesh_segmented_access_fragment_count;
static int hf_btmesh_segmented_access_reassembled_length;

static int hf_btmesh_segmented_control_fragments;
static int hf_btmesh_segmented_control_fragment;
static int hf_btmesh_segmented_control_fragment_overlap;
static int hf_btmesh_segmented_control_fragment_overlap_conflict;
static int hf_btmesh_segmented_control_fragment_multiple_tails;
static int hf_btmesh_segmented_control_fragment_too_long_fragment;
static int hf_btmesh_segmented_control_fragment_error;
static int hf_btmesh_segmented_control_fragment_count;
static int hf_btmesh_segmented_control_reassembled_length;

static int hf_btmesh_decrypted_access;
static int hf_btmesh_model_layer_opcode;
static int hf_btmesh_model_layer_parameters;
static int hf_btmesh_model_layer_vendor_opcode;
static int hf_btmesh_model_layer_vendor;

static int hf_btmesh_config_appkey_add_netkeyindexandappkeyindex;
static int hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_net;
static int hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_app;
static int hf_btmesh_config_appkey_add_appkey;
static int hf_btmesh_config_appkey_update_netkeyindexandappkeyindex;
static int hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_net;
static int hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_app;
static int hf_btmesh_config_appkey_update_appkey;
static int hf_btmesh_config_composition_data_status_page;
static int hf_btmesh_config_composition_data_status_cid;
static int hf_btmesh_config_composition_data_status_pid;
static int hf_btmesh_config_composition_data_status_vid;
static int hf_btmesh_config_composition_data_status_crpl;
static int hf_btmesh_config_composition_data_status_features_relay;
static int hf_btmesh_config_composition_data_status_features_proxy;
static int hf_btmesh_config_composition_data_status_features_friend;
static int hf_btmesh_config_composition_data_status_features_low_power;
static int hf_btmesh_config_composition_data_status_features_rfu;
static int hf_btmesh_config_composition_data_status_features;
static int hf_btmesh_config_composition_data_status_loc;
static int hf_btmesh_config_composition_data_status_nums;
static int hf_btmesh_config_composition_data_status_numv;
static int hf_btmesh_config_composition_data_status_sig_model;
static int hf_btmesh_config_composition_data_status_vendor_model;
static int hf_btmesh_config_model_publication_set_elementaddress;
static int hf_btmesh_config_model_publication_set_publishaddress;
static int hf_btmesh_config_model_publication_set_appkey;
static int hf_btmesh_config_model_publication_set_appkeyindex;
static int hf_btmesh_config_model_publication_set_credentialflag;
static int hf_btmesh_config_model_publication_set_rfu;
static int hf_btmesh_config_model_publication_set_publishttl;
static int hf_btmesh_config_model_publication_set_publishperiod;
static int hf_btmesh_config_model_publication_set_publishperiod_resolution;
static int hf_btmesh_config_model_publication_set_publishperiod_steps;
static int hf_btmesh_config_model_publication_set_publishretransmit;
static int hf_btmesh_config_model_publication_set_publishretransmit_count;
static int hf_btmesh_config_model_publication_set_publishretransmit_intervalsteps;
static int hf_btmesh_config_model_publication_set_modelidentifier;
static int hf_btmesh_config_model_publication_set_vendormodelidentifier;
static int hf_btmesh_health_current_status_test_id;
static int hf_btmesh_health_current_status_company_id;
static int hf_btmesh_health_current_status_fault;
static int hf_btmesh_health_fault_status_test_id;
static int hf_btmesh_health_fault_status_company_id;
static int hf_btmesh_health_fault_status_fault;
static int hf_btmesh_config_heartbeat_publication_status_status;
static int hf_btmesh_config_heartbeat_publication_status_destination;
static int hf_btmesh_config_heartbeat_publication_status_countlog;
static int hf_btmesh_config_heartbeat_publication_status_periodlog;
static int hf_btmesh_config_heartbeat_publication_status_ttl;
static int hf_btmesh_config_heartbeat_publication_status_features_relay;
static int hf_btmesh_config_heartbeat_publication_status_features_proxy;
static int hf_btmesh_config_heartbeat_publication_status_features_friend;
static int hf_btmesh_config_heartbeat_publication_status_features_low_power;
static int hf_btmesh_config_heartbeat_publication_status_features_rfu;
static int hf_btmesh_config_heartbeat_publication_status_features;
static int hf_btmesh_config_heartbeat_publication_status_netkeyindex;
static int hf_btmesh_config_heartbeat_publication_status_netkeyindex_idx;
static int hf_btmesh_config_heartbeat_publication_status_netkeyindex_rfu;
static int hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex;
static int hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_net;
static int hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_app;
static int hf_btmesh_config_appkey_get_netkeyindex;
static int hf_btmesh_config_appkey_get_netkeyindex_idx;
static int hf_btmesh_config_appkey_get_netkeyindex_rfu;
static int hf_btmesh_config_appkey_list_status;
static int hf_btmesh_config_appkey_list_netkeyindex;
static int hf_btmesh_config_appkey_list_netkeyindex_idx;
static int hf_btmesh_config_appkey_list_netkeyindex_rfu;
static int hf_btmesh_config_appkey_list_appkeyindex;
static int hf_btmesh_config_appkey_list_appkeyindex_rfu;
static int hf_btmesh_config_appkey_status_status;
static int hf_btmesh_config_appkey_status_netkeyindexandappkeyindex;
static int hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_net;
static int hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_app;
static int hf_btmesh_health_attention_set_attention;
static int hf_btmesh_health_attention_set_unacknowledged_attention;
static int hf_btmesh_health_attention_status_attention;
static int hf_btmesh_config_composition_data_get_page;
static int hf_btmesh_config_beacon_set_beacon;
static int hf_btmesh_config_beacon_status_beacon;
static int hf_btmesh_config_default_ttl_set_ttl;
static int hf_btmesh_config_default_ttl_status_ttl;
static int hf_btmesh_config_friend_set_friend;
static int hf_btmesh_config_friend_status_friend;
static int hf_btmesh_config_gatt_proxy_set_gattproxy;
static int hf_btmesh_config_gatt_proxy_status_gattproxy;
static int hf_btmesh_config_key_refresh_phase_get_netkeyindex;
static int hf_btmesh_config_key_refresh_phase_get_netkeyindex_idx;
static int hf_btmesh_config_key_refresh_phase_get_netkeyindex_rfu;
static int hf_btmesh_config_key_refresh_phase_set_netkeyindex;
static int hf_btmesh_config_key_refresh_phase_set_netkeyindex_idx;
static int hf_btmesh_config_key_refresh_phase_set_netkeyindex_rfu;
static int hf_btmesh_config_key_refresh_phase_set_transition;
static int hf_btmesh_config_key_refresh_phase_status_status;
static int hf_btmesh_config_key_refresh_phase_status_netkeyindex;
static int hf_btmesh_config_key_refresh_phase_status_netkeyindex_idx;
static int hf_btmesh_config_key_refresh_phase_status_netkeyindex_rfu;
static int hf_btmesh_config_key_refresh_phase_status_phase;
static int hf_btmesh_config_model_publication_get_elementaddress;
static int hf_btmesh_config_model_publication_get_modelidentifier;
static int hf_btmesh_config_model_publication_get_vendormodelidentifier;
static int hf_btmesh_config_model_publication_status_status;
static int hf_btmesh_config_model_publication_status_elementaddress;
static int hf_btmesh_config_model_publication_status_publishaddress;
static int hf_btmesh_config_model_publication_status_appkey;
static int hf_btmesh_config_model_publication_status_appkeyindex;
static int hf_btmesh_config_model_publication_status_credentialflag;
static int hf_btmesh_config_model_publication_status_rfu;
static int hf_btmesh_config_model_publication_status_publishttl;
static int hf_btmesh_config_model_publication_status_publishperiod;
static int hf_btmesh_config_model_publication_status_publishperiod_resolution;
static int hf_btmesh_config_model_publication_status_publishperiod_steps;
static int hf_btmesh_config_model_publication_status_publishretransmit;
static int hf_btmesh_config_model_publication_status_publishretransmit_count;
static int hf_btmesh_config_model_publication_status_publishretransmit_intervalsteps;
static int hf_btmesh_config_model_publication_status_modelidentifier;
static int hf_btmesh_config_model_publication_status_vendormodelidentifier;
static int hf_btmesh_config_model_publication_virtual_address_set_elementaddress;
static int hf_btmesh_config_model_publication_virtual_address_set_publishaddress;
static int hf_btmesh_config_model_publication_virtual_address_set_appkey;
static int hf_btmesh_config_model_publication_virtual_address_set_appkeyindex;
static int hf_btmesh_config_model_publication_virtual_address_set_credentialflag;
static int hf_btmesh_config_model_publication_virtual_address_set_rfu;
static int hf_btmesh_config_model_publication_virtual_address_set_publishttl;
static int hf_btmesh_config_model_publication_virtual_address_set_publishperiod;
static int hf_btmesh_config_model_publication_virtual_address_set_publishperiod_resolution;
static int hf_btmesh_config_model_publication_virtual_address_set_publishperiod_steps;
static int hf_btmesh_config_model_publication_virtual_address_set_publishretransmit;
static int hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_count;
static int hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_intervalsteps;
static int hf_btmesh_config_model_publication_virtual_address_set_modelidentifier;
static int hf_btmesh_config_model_publication_virtual_address_set_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_add_elementaddress;
static int hf_btmesh_config_model_subscription_add_address;
static int hf_btmesh_config_model_subscription_add_modelidentifier;
static int hf_btmesh_config_model_subscription_add_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_delete_elementaddress;
static int hf_btmesh_config_model_subscription_delete_address;
static int hf_btmesh_config_model_subscription_delete_modelidentifier;
static int hf_btmesh_config_model_subscription_delete_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_delete_all_elementaddress;
static int hf_btmesh_config_model_subscription_delete_all_modelidentifier;
static int hf_btmesh_config_model_subscription_delete_all_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_overwrite_elementaddress;
static int hf_btmesh_config_model_subscription_overwrite_address;
static int hf_btmesh_config_model_subscription_overwrite_modelidentifier;
static int hf_btmesh_config_model_subscription_overwrite_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_status_status;
static int hf_btmesh_config_model_subscription_status_elementaddress;
static int hf_btmesh_config_model_subscription_status_address;
static int hf_btmesh_config_model_subscription_status_modelidentifier;
static int hf_btmesh_config_model_subscription_status_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_virtual_address_add_elementaddress;
static int hf_btmesh_config_model_subscription_virtual_address_add_label;
static int hf_btmesh_config_model_subscription_virtual_address_add_modelidentifier;
static int hf_btmesh_config_model_subscription_virtual_address_add_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_virtual_address_delete_elementaddress;
static int hf_btmesh_config_model_subscription_virtual_address_delete_label;
static int hf_btmesh_config_model_subscription_virtual_address_delete_modelidentifier;
static int hf_btmesh_config_model_subscription_virtual_address_delete_vendormodelidentifier;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_elementaddress;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_label;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_modelidentifier;
static int hf_btmesh_config_model_subscription_virtual_address_overwrite_vendormodelidentifier;
static int hf_btmesh_config_network_transmit_set_networktransmit;
static int hf_btmesh_config_network_transmit_set_networktransmit_count;
static int hf_btmesh_config_network_transmit_set_networktransmit_intervalsteps;
static int hf_btmesh_config_network_transmit_status_networktransmit;
static int hf_btmesh_config_network_transmit_status_networktransmit_count;
static int hf_btmesh_config_network_transmit_status_networktransmit_intervalsteps;
static int hf_btmesh_config_relay_set_relay;
static int hf_btmesh_config_relay_set_relayretransmit;
static int hf_btmesh_config_relay_set_relayretransmit_count;
static int hf_btmesh_config_relay_set_relayretransmit_intervalsteps;
static int hf_btmesh_config_relay_status_relay;
static int hf_btmesh_config_relay_status_relayretransmit;
static int hf_btmesh_config_relay_status_relayretransmit_count;
static int hf_btmesh_config_relay_status_relayretransmit_intervalsteps;
static int hf_btmesh_config_sig_model_subscription_get_elementaddress;
static int hf_btmesh_config_sig_model_subscription_get_modelidentifier;
static int hf_btmesh_config_sig_model_subscription_list_status;
static int hf_btmesh_config_sig_model_subscription_list_elementaddress;
static int hf_btmesh_config_sig_model_subscription_list_modelidentifier;
static int hf_btmesh_config_sig_model_subscription_list_address;
static int hf_btmesh_config_vendor_model_subscription_get_elementaddress;
static int hf_btmesh_config_vendor_model_subscription_get_modelidentifier;
static int hf_btmesh_config_vendor_model_subscription_list_status;
static int hf_btmesh_config_vendor_model_subscription_list_elementaddress;
static int hf_btmesh_config_vendor_model_subscription_list_modelidentifier;
static int hf_btmesh_config_vendor_model_subscription_list_address;
static int hf_btmesh_config_low_power_node_polltimeout_get_lpnaddress;
static int hf_btmesh_config_low_power_node_polltimeout_status_lpnaddress;
static int hf_btmesh_config_low_power_node_polltimeout_status_polltimeout;
static int hf_btmesh_health_fault_clear_company_id;
static int hf_btmesh_health_fault_clear_unacknowledged_company_id;
static int hf_btmesh_health_fault_get_company_id;
static int hf_btmesh_health_fault_test_test_id;
static int hf_btmesh_health_fault_test_company_id;
static int hf_btmesh_health_fault_test_unacknowledged_test_id;
static int hf_btmesh_health_fault_test_unacknowledged_company_id;
static int hf_btmesh_health_period_set_fast_period_divisor;
static int hf_btmesh_health_period_set_unacknowledged_fast_period_divisor;
static int hf_btmesh_health_period_status_fast_period_divisor;
static int hf_btmesh_config_heartbeat_publication_set_destination;
static int hf_btmesh_config_heartbeat_publication_set_countlog;
static int hf_btmesh_config_heartbeat_publication_set_periodlog;
static int hf_btmesh_config_heartbeat_publication_set_ttl;
static int hf_btmesh_config_heartbeat_publication_set_features_relay;
static int hf_btmesh_config_heartbeat_publication_set_features_proxy;
static int hf_btmesh_config_heartbeat_publication_set_features_friend;
static int hf_btmesh_config_heartbeat_publication_set_features_low_power;
static int hf_btmesh_config_heartbeat_publication_set_features_rfu;
static int hf_btmesh_config_heartbeat_publication_set_features;
static int hf_btmesh_config_heartbeat_publication_set_netkeyindex;
static int hf_btmesh_config_heartbeat_publication_set_netkeyindex_idx;
static int hf_btmesh_config_heartbeat_publication_set_netkeyindex_rfu;
static int hf_btmesh_config_heartbeat_subscription_set_source;
static int hf_btmesh_config_heartbeat_subscription_set_destination;
static int hf_btmesh_config_heartbeat_subscription_set_periodlog;
static int hf_btmesh_config_heartbeat_subscription_status_status;
static int hf_btmesh_config_heartbeat_subscription_status_source;
static int hf_btmesh_config_heartbeat_subscription_status_destination;
static int hf_btmesh_config_heartbeat_subscription_status_periodlog;
static int hf_btmesh_config_heartbeat_subscription_status_countlog;
static int hf_btmesh_config_heartbeat_subscription_status_minhops;
static int hf_btmesh_config_heartbeat_subscription_status_maxhops;
static int hf_btmesh_config_model_app_bind_elementaddress;
static int hf_btmesh_config_model_app_bind_appkeyindex;
static int hf_btmesh_config_model_app_bind_appkeyindex_idx;
static int hf_btmesh_config_model_app_bind_appkeyindex_rfu;
static int hf_btmesh_config_model_app_bind_modelidentifier;
static int hf_btmesh_config_model_app_bind_vendormodelidentifier;
static int hf_btmesh_config_model_app_status_status;
static int hf_btmesh_config_model_app_status_elementaddress;
static int hf_btmesh_config_model_app_status_appkeyindex;
static int hf_btmesh_config_model_app_status_appkeyindex_idx;
static int hf_btmesh_config_model_app_status_appkeyindex_rfu;
static int hf_btmesh_config_model_app_status_modelidentifier;
static int hf_btmesh_config_model_app_status_vendormodelidentifier;
static int hf_btmesh_config_model_app_unbind_elementaddress;
static int hf_btmesh_config_model_app_unbind_appkeyindex;
static int hf_btmesh_config_model_app_unbind_appkeyindex_idx;
static int hf_btmesh_config_model_app_unbind_appkeyindex_rfu;
static int hf_btmesh_config_model_app_unbind_modelidentifier;
static int hf_btmesh_config_model_app_unbind_vendormodelidentifier;
static int hf_btmesh_config_netkey_add_netkeyindex;
static int hf_btmesh_config_netkey_add_netkeyindex_idx;
static int hf_btmesh_config_netkey_add_netkeyindex_rfu;
static int hf_btmesh_config_netkey_add_netkey;
static int hf_btmesh_config_netkey_delete_netkeyindex;
static int hf_btmesh_config_netkey_delete_netkeyindex_idx;
static int hf_btmesh_config_netkey_delete_netkeyindex_rfu;
static int hf_btmesh_config_netkey_list_netkeyindex;
static int hf_btmesh_config_netkey_list_netkeyindex_rfu;
static int hf_btmesh_config_netkey_status_status;
static int hf_btmesh_config_netkey_status_netkeyindex;
static int hf_btmesh_config_netkey_status_netkeyindex_idx;
static int hf_btmesh_config_netkey_status_netkeyindex_rfu;
static int hf_btmesh_config_netkey_update_netkeyindex;
static int hf_btmesh_config_netkey_update_netkeyindex_idx;
static int hf_btmesh_config_netkey_update_netkeyindex_rfu;
static int hf_btmesh_config_netkey_update_netkey;
static int hf_btmesh_config_node_identity_get_netkeyindex;
static int hf_btmesh_config_node_identity_get_netkeyindex_idx;
static int hf_btmesh_config_node_identity_get_netkeyindex_rfu;
static int hf_btmesh_config_node_identity_set_netkeyindex;
static int hf_btmesh_config_node_identity_set_netkeyindex_idx;
static int hf_btmesh_config_node_identity_set_netkeyindex_rfu;
static int hf_btmesh_config_node_identity_set_identity;
static int hf_btmesh_config_node_identity_status_status;
static int hf_btmesh_config_node_identity_status_netkeyindex;
static int hf_btmesh_config_node_identity_status_netkeyindex_idx;
static int hf_btmesh_config_node_identity_status_netkeyindex_rfu;
static int hf_btmesh_config_node_identity_status_identity;
static int hf_btmesh_config_sig_model_app_get_elementaddress;
static int hf_btmesh_config_sig_model_app_get_modelidentifier;
static int hf_btmesh_config_sig_model_app_list_status;
static int hf_btmesh_config_sig_model_app_list_elementaddress;
static int hf_btmesh_config_sig_model_app_list_modelidentifier;
static int hf_btmesh_config_sig_model_app_list_appkeyindex;
static int hf_btmesh_config_sig_model_app_list_appkeyindex_rfu;
static int hf_btmesh_config_vendor_model_app_get_elementaddress;
static int hf_btmesh_config_vendor_model_app_get_modelidentifier;
static int hf_btmesh_config_vendor_model_app_list_status;
static int hf_btmesh_config_vendor_model_app_list_elementaddress;
static int hf_btmesh_config_vendor_model_app_list_modelidentifier;
static int hf_btmesh_config_vendor_model_app_list_appkeyindex;
static int hf_btmesh_config_vendor_model_app_list_appkeyindex_rfu;
static int hf_btmesh_generic_location_global_status_global_latitude;
static int hf_btmesh_generic_location_global_status_global_longitude;
static int hf_btmesh_generic_location_global_status_global_altitude;
static int hf_btmesh_generic_location_global_set_global_latitude;
static int hf_btmesh_generic_location_global_set_global_longitude;
static int hf_btmesh_generic_location_global_set_global_altitude;
static int hf_btmesh_generic_location_global_set_unacknowledged_global_latitude;
static int hf_btmesh_generic_location_global_set_unacknowledged_global_longitude;
static int hf_btmesh_generic_location_global_set_unacknowledged_global_altitude;
static int hf_btmesh_generic_onoff_set_onoff;
static int hf_btmesh_generic_onoff_set_tid;
static int hf_btmesh_generic_onoff_set_transition_time;
static int hf_btmesh_generic_onoff_set_transition_time_steps;
static int hf_btmesh_generic_onoff_set_transition_time_resolution;
static int hf_btmesh_generic_onoff_set_delay;
static int hf_btmesh_generic_onoff_set_unacknowledged_onoff;
static int hf_btmesh_generic_onoff_set_unacknowledged_tid;
static int hf_btmesh_generic_onoff_set_unacknowledged_transition_time;
static int hf_btmesh_generic_onoff_set_unacknowledged_transition_time_steps;
static int hf_btmesh_generic_onoff_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_generic_onoff_set_unacknowledged_delay;
static int hf_btmesh_generic_onoff_status_present_onoff;
static int hf_btmesh_generic_onoff_status_target_onoff;
static int hf_btmesh_generic_onoff_status_remaining_time;
static int hf_btmesh_generic_onoff_status_remaining_time_steps;
static int hf_btmesh_generic_onoff_status_remaining_time_resolution;
static int hf_btmesh_generic_level_set_level;
static int hf_btmesh_generic_level_set_tid;
static int hf_btmesh_generic_level_set_transition_time;
static int hf_btmesh_generic_level_set_transition_time_steps;
static int hf_btmesh_generic_level_set_transition_time_resolution;
static int hf_btmesh_generic_level_set_delay;
static int hf_btmesh_generic_level_set_unacknowledged_level;
static int hf_btmesh_generic_level_set_unacknowledged_tid;
static int hf_btmesh_generic_level_set_unacknowledged_transition_time;
static int hf_btmesh_generic_level_set_unacknowledged_transition_time_steps;
static int hf_btmesh_generic_level_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_generic_level_set_unacknowledged_delay;
static int hf_btmesh_generic_level_status_present_level;
static int hf_btmesh_generic_level_status_target_level;
static int hf_btmesh_generic_level_status_remaining_time;
static int hf_btmesh_generic_level_status_remaining_time_steps;
static int hf_btmesh_generic_level_status_remaining_time_resolution;
static int hf_btmesh_generic_delta_set_delta_level;
static int hf_btmesh_generic_delta_set_tid;
static int hf_btmesh_generic_delta_set_transition_time;
static int hf_btmesh_generic_delta_set_transition_time_steps;
static int hf_btmesh_generic_delta_set_transition_time_resolution;
static int hf_btmesh_generic_delta_set_delay;
static int hf_btmesh_generic_delta_set_unacknowledged_delta_level;
static int hf_btmesh_generic_delta_set_unacknowledged_tid;
static int hf_btmesh_generic_delta_set_unacknowledged_transition_time;
static int hf_btmesh_generic_delta_set_unacknowledged_transition_time_steps;
static int hf_btmesh_generic_delta_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_generic_delta_set_unacknowledged_delay;
static int hf_btmesh_generic_move_set_delta_level;
static int hf_btmesh_generic_move_set_tid;
static int hf_btmesh_generic_move_set_transition_time;
static int hf_btmesh_generic_move_set_transition_time_steps;
static int hf_btmesh_generic_move_set_transition_time_resolution;
static int hf_btmesh_generic_move_set_delay;
static int hf_btmesh_generic_move_set_unacknowledged_delta_level;
static int hf_btmesh_generic_move_set_unacknowledged_tid;
static int hf_btmesh_generic_move_set_unacknowledged_transition_time;
static int hf_btmesh_generic_move_set_unacknowledged_transition_time_steps;
static int hf_btmesh_generic_move_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_generic_move_set_unacknowledged_delay;
static int hf_btmesh_generic_default_transition_time_set_transition_time;
static int hf_btmesh_generic_default_transition_time_set_transition_time_steps;
static int hf_btmesh_generic_default_transition_time_set_transition_time_resolution;
static int hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time;
static int hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time_steps;
static int hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_generic_default_transition_time_status_transition_time;
static int hf_btmesh_generic_default_transition_time_status_transition_time_steps;
static int hf_btmesh_generic_default_transition_time_status_transition_time_resolution;
static int hf_btmesh_generic_onpowerup_status_onpowerup;
static int hf_btmesh_generic_onpowerup_set_onpowerup;
static int hf_btmesh_generic_onpowerup_set_unacknowledged_onpowerup;
static int hf_btmesh_generic_power_level_set_power;
static int hf_btmesh_generic_power_level_set_tid;
static int hf_btmesh_generic_power_level_set_transition_time;
static int hf_btmesh_generic_power_level_set_transition_time_steps;
static int hf_btmesh_generic_power_level_set_transition_time_resolution;
static int hf_btmesh_generic_power_level_set_delay;
static int hf_btmesh_generic_power_level_set_unacknowledged_power;
static int hf_btmesh_generic_power_level_set_unacknowledged_tid;
static int hf_btmesh_generic_power_level_set_unacknowledged_transition_time;
static int hf_btmesh_generic_power_level_set_unacknowledged_transition_time_steps;
static int hf_btmesh_generic_power_level_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_generic_power_level_set_unacknowledged_delay;
static int hf_btmesh_generic_power_level_status_present_power;
static int hf_btmesh_generic_power_level_status_target_power;
static int hf_btmesh_generic_power_level_status_remaining_time;
static int hf_btmesh_generic_power_level_status_remaining_time_steps;
static int hf_btmesh_generic_power_level_status_remaining_time_resolution;
static int hf_btmesh_generic_power_last_status_power;
static int hf_btmesh_generic_power_default_status_power;
static int hf_btmesh_generic_power_range_status_status_code;
static int hf_btmesh_generic_power_range_status_range_min;
static int hf_btmesh_generic_power_range_status_range_max;
static int hf_btmesh_generic_power_default_set_power;
static int hf_btmesh_generic_power_default_set_unacknowledged_power;
static int hf_btmesh_generic_power_range_set_range_min;
static int hf_btmesh_generic_power_range_set_range_max;
static int hf_btmesh_generic_power_range_set_unacknowledged_range_min;
static int hf_btmesh_generic_power_range_set_unacknowledged_range_max;
static int hf_btmesh_generic_battery_status_battery_level;
static int hf_btmesh_generic_battery_status_time_to_discharge;
static int hf_btmesh_generic_battery_status_time_to_charge;
static int hf_btmesh_generic_battery_status_flags_presence;
static int hf_btmesh_generic_battery_status_flags_indicator;
static int hf_btmesh_generic_battery_status_flags_charging;
static int hf_btmesh_generic_battery_status_flags_serviceability;
static int hf_btmesh_generic_location_local_status_local_north;
static int hf_btmesh_generic_location_local_status_local_east;
static int hf_btmesh_generic_location_local_status_local_altitude;
static int hf_btmesh_generic_location_local_status_floor_number;
static int hf_btmesh_generic_location_local_status_uncertainty_stationary;
static int hf_btmesh_generic_location_local_status_uncertainty_rfu;
static int hf_btmesh_generic_location_local_status_uncertainty_update_time;
static int hf_btmesh_generic_location_local_status_uncertainty_precision;
static int hf_btmesh_generic_location_local_set_local_north;
static int hf_btmesh_generic_location_local_set_local_east;
static int hf_btmesh_generic_location_local_set_local_altitude;
static int hf_btmesh_generic_location_local_set_floor_number;
static int hf_btmesh_generic_location_local_set_uncertainty_stationary;
static int hf_btmesh_generic_location_local_set_uncertainty_rfu;
static int hf_btmesh_generic_location_local_set_uncertainty_update_time;
static int hf_btmesh_generic_location_local_set_uncertainty_precision;
static int hf_btmesh_generic_location_local_set_unacknowledged_local_north;
static int hf_btmesh_generic_location_local_set_unacknowledged_local_east;
static int hf_btmesh_generic_location_local_set_unacknowledged_local_altitude;
static int hf_btmesh_generic_location_local_set_unacknowledged_floor_number;
static int hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_stationary;
static int hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_rfu;
static int hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_update_time;
static int hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_precision;
static int hf_btmesh_scene_status_status_code;
static int hf_btmesh_scene_status_current_scene;
static int hf_btmesh_scene_status_target_scene;
static int hf_btmesh_scene_status_remaining_time;
static int hf_btmesh_scene_status_remaining_time_steps;
static int hf_btmesh_scene_status_remaining_time_resolution;
static int hf_btmesh_scene_recall_scene_number;
static int hf_btmesh_scene_recall_tid;
static int hf_btmesh_scene_recall_transition_time;
static int hf_btmesh_scene_recall_transition_time_steps;
static int hf_btmesh_scene_recall_transition_time_resolution;
static int hf_btmesh_scene_recall_delay;
static int hf_btmesh_scene_recall_unacknowledged_scene_number;
static int hf_btmesh_scene_recall_unacknowledged_tid;
static int hf_btmesh_scene_recall_unacknowledged_transition_time;
static int hf_btmesh_scene_recall_unacknowledged_transition_time_steps;
static int hf_btmesh_scene_recall_unacknowledged_transition_time_resolution;
static int hf_btmesh_scene_recall_unacknowledged_delay;
static int hf_btmesh_scene_register_status_status_code;
static int hf_btmesh_scene_register_status_current_scene;
static int hf_btmesh_scene_register_status_scene;
static int hf_btmesh_scene_store_scene_number;
static int hf_btmesh_scene_store_unacknowledged_scene_number;
static int hf_btmesh_scene_delete_scene_number;
static int hf_btmesh_scene_delete_unacknowledged_scene_number;
static int hf_btmesh_time_set_tai_seconds;
static int hf_btmesh_time_set_subsecond;
static int hf_btmesh_time_set_uncertainty;
static int hf_btmesh_time_set_time_authority;
static int hf_btmesh_time_set_tai_utc_delta;
static int hf_btmesh_time_set_time_zone_offset;
static int hf_btmesh_time_status_tai_seconds;
static int hf_btmesh_time_status_subsecond;
static int hf_btmesh_time_status_uncertainty;
static int hf_btmesh_time_status_time_authority;
static int hf_btmesh_time_status_tai_utc_delta;
static int hf_btmesh_time_status_time_zone_offset;
static int hf_btmesh_scheduler_action_status_index;
static int hf_btmesh_scheduler_action_status_schedule_register_year;
static int hf_btmesh_scheduler_action_status_schedule_register_month;
static int hf_btmesh_scheduler_action_status_schedule_register_day;
static int hf_btmesh_scheduler_action_status_schedule_register_hour;
static int hf_btmesh_scheduler_action_status_schedule_register_minute;
static int hf_btmesh_scheduler_action_status_schedule_register_second;
static int hf_btmesh_scheduler_action_status_schedule_register_day_of_week;
static int hf_btmesh_scheduler_action_status_schedule_register_action;
static int hf_btmesh_scheduler_action_status_schedule_register_transition_time;
static int hf_btmesh_scheduler_action_status_schedule_register_transition_time_steps;
static int hf_btmesh_scheduler_action_status_schedule_register_transition_time_resolution;
static int hf_btmesh_scheduler_action_status_schedule_register_scene_number;
static int hf_btmesh_scheduler_schedule_register_month_january;
static int hf_btmesh_scheduler_schedule_register_month_february;
static int hf_btmesh_scheduler_schedule_register_month_march;
static int hf_btmesh_scheduler_schedule_register_month_april;
static int hf_btmesh_scheduler_schedule_register_month_may;
static int hf_btmesh_scheduler_schedule_register_month_june;
static int hf_btmesh_scheduler_schedule_register_month_july;
static int hf_btmesh_scheduler_schedule_register_month_august;
static int hf_btmesh_scheduler_schedule_register_month_september;
static int hf_btmesh_scheduler_schedule_register_month_october;
static int hf_btmesh_scheduler_schedule_register_month_november;
static int hf_btmesh_scheduler_schedule_register_month_december;
static int hf_btmesh_scheduler_schedule_register_day_of_week_monday;
static int hf_btmesh_scheduler_schedule_register_day_of_week_tuesday;
static int hf_btmesh_scheduler_schedule_register_day_of_week_wednesday;
static int hf_btmesh_scheduler_schedule_register_day_of_week_thursday;
static int hf_btmesh_scheduler_schedule_register_day_of_week_friday;
static int hf_btmesh_scheduler_schedule_register_day_of_week_saturday;
static int hf_btmesh_scheduler_schedule_register_day_of_week_sunday;
static int hf_btmesh_scheduler_action_set_index;
static int hf_btmesh_scheduler_action_set_schedule_register_year;
static int hf_btmesh_scheduler_action_set_schedule_register_month;
static int hf_btmesh_scheduler_action_set_schedule_register_day;
static int hf_btmesh_scheduler_action_set_schedule_register_hour;
static int hf_btmesh_scheduler_action_set_schedule_register_minute;
static int hf_btmesh_scheduler_action_set_schedule_register_second;
static int hf_btmesh_scheduler_action_set_schedule_register_day_of_week;
static int hf_btmesh_scheduler_action_set_schedule_register_action;
static int hf_btmesh_scheduler_action_set_schedule_register_transition_time;
static int hf_btmesh_scheduler_action_set_schedule_register_transition_time_steps;
static int hf_btmesh_scheduler_action_set_schedule_register_transition_time_resolution;
static int hf_btmesh_scheduler_action_set_schedule_register_scene_number;
static int hf_btmesh_scheduler_action_set_unacknowledged_index;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_year;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_month;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_day;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_hour;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_minute;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_second;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_day_of_week;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_action;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time_steps;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time_resolution;
static int hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_scene_number;
static int hf_btmesh_time_role_set_time_role;
static int hf_btmesh_time_role_status_time_role;
static int hf_btmesh_time_zone_set_time_zone_offset_new;
static int hf_btmesh_time_zone_set_tai_of_zone_change;
static int hf_btmesh_time_zone_status_time_zone_offset_current;
static int hf_btmesh_time_zone_status_time_zone_offset_new;
static int hf_btmesh_time_zone_status_tai_of_zone_change;
static int hf_btmesh_tai_utc_delta_set_tai_utc_delta_new;
static int hf_btmesh_tai_utc_delta_set_padding;
static int hf_btmesh_tai_utc_delta_set_tai_of_delta_change;
static int hf_btmesh_tai_utc_delta_status_tai_utc_delta_current;
static int hf_btmesh_tai_utc_delta_status_padding_1;
static int hf_btmesh_tai_utc_delta_status_tai_utc_delta_new;
static int hf_btmesh_tai_utc_delta_status_padding_2;
static int hf_btmesh_tai_utc_delta_status_tai_of_delta_change;
static int hf_btmesh_scheduler_action_get_index;
static int hf_btmesh_scheduler_status_schedules;
static int hf_btmesh_scheduler_status_schedules_schedule_0;
static int hf_btmesh_scheduler_status_schedules_schedule_1;
static int hf_btmesh_scheduler_status_schedules_schedule_2;
static int hf_btmesh_scheduler_status_schedules_schedule_3;
static int hf_btmesh_scheduler_status_schedules_schedule_4;
static int hf_btmesh_scheduler_status_schedules_schedule_5;
static int hf_btmesh_scheduler_status_schedules_schedule_6;
static int hf_btmesh_scheduler_status_schedules_schedule_7;
static int hf_btmesh_scheduler_status_schedules_schedule_8;
static int hf_btmesh_scheduler_status_schedules_schedule_9;
static int hf_btmesh_scheduler_status_schedules_schedule_10;
static int hf_btmesh_scheduler_status_schedules_schedule_11;
static int hf_btmesh_scheduler_status_schedules_schedule_12;
static int hf_btmesh_scheduler_status_schedules_schedule_13;
static int hf_btmesh_scheduler_status_schedules_schedule_14;
static int hf_btmesh_scheduler_status_schedules_schedule_15;

static int hf_btmesh_light_lc_property_set_light_lc_property_id;
static int hf_btmesh_light_lc_property_set_light_lc_property_value;
static int hf_btmesh_light_lc_property_set_unacknowledged_light_lc_property_id;
static int hf_btmesh_light_lc_property_set_unacknowledged_light_lc_property_value;
static int hf_btmesh_light_lc_property_status_light_lc_property_id;
static int hf_btmesh_light_lc_property_status_light_lc_property_value;
static int hf_btmesh_light_lightness_set_lightness;
static int hf_btmesh_light_lightness_set_tid;
static int hf_btmesh_light_lightness_set_transition_time;
static int hf_btmesh_light_lightness_set_transition_time_steps;
static int hf_btmesh_light_lightness_set_transition_time_resolution;
static int hf_btmesh_light_lightness_set_delay;
static int hf_btmesh_light_lightness_set_unacknowledged_lightness;
static int hf_btmesh_light_lightness_set_unacknowledged_tid;
static int hf_btmesh_light_lightness_set_unacknowledged_transition_time;
static int hf_btmesh_light_lightness_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_lightness_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_lightness_set_unacknowledged_delay;
static int hf_btmesh_light_lightness_status_present_lightness;
static int hf_btmesh_light_lightness_status_target_lightness;
static int hf_btmesh_light_lightness_status_remaining_time;
static int hf_btmesh_light_lightness_status_remaining_time_steps;
static int hf_btmesh_light_lightness_status_remaining_time_resolution;
static int hf_btmesh_light_lightness_linear_set_lightness;
static int hf_btmesh_light_lightness_linear_set_tid;
static int hf_btmesh_light_lightness_linear_set_transition_time;
static int hf_btmesh_light_lightness_linear_set_transition_time_steps;
static int hf_btmesh_light_lightness_linear_set_transition_time_resolution;
static int hf_btmesh_light_lightness_linear_set_delay;
static int hf_btmesh_light_lightness_linear_set_unacknowledged_lightness;
static int hf_btmesh_light_lightness_linear_set_unacknowledged_tid;
static int hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time;
static int hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_lightness_linear_set_unacknowledged_delay;
static int hf_btmesh_light_lightness_linear_status_present_lightness;
static int hf_btmesh_light_lightness_linear_status_target_lightness;
static int hf_btmesh_light_lightness_linear_status_remaining_time;
static int hf_btmesh_light_lightness_linear_status_remaining_time_steps;
static int hf_btmesh_light_lightness_linear_status_remaining_time_resolution;
static int hf_btmesh_light_lightness_last_status_lightness;
static int hf_btmesh_light_lightness_default_status_lightness;
static int hf_btmesh_light_lightness_range_status_status_code;
static int hf_btmesh_light_lightness_range_status_range_min;
static int hf_btmesh_light_lightness_range_status_range_max;
static int hf_btmesh_light_lightness_default_set_lightness;
static int hf_btmesh_light_lightness_default_set_unacknowledged_lightness;
static int hf_btmesh_light_lightness_range_set_range_min;
static int hf_btmesh_light_lightness_range_set_range_max;
static int hf_btmesh_light_lightness_range_set_unacknowledged_range_min;
static int hf_btmesh_light_lightness_range_set_unacknowledged_range_max;
static int hf_btmesh_light_ctl_set_ctl_lightness;
static int hf_btmesh_light_ctl_set_ctl_temperature;
static int hf_btmesh_light_ctl_set_ctl_delta_uv;
static int hf_btmesh_light_ctl_set_tid;
static int hf_btmesh_light_ctl_set_transition_time;
static int hf_btmesh_light_ctl_set_transition_time_steps;
static int hf_btmesh_light_ctl_set_transition_time_resolution;
static int hf_btmesh_light_ctl_set_delay;
static int hf_btmesh_light_ctl_set_unacknowledged_ctl_lightness;
static int hf_btmesh_light_ctl_set_unacknowledged_ctl_temperature;
static int hf_btmesh_light_ctl_set_unacknowledged_ctl_delta_uv;
static int hf_btmesh_light_ctl_set_unacknowledged_tid;
static int hf_btmesh_light_ctl_set_unacknowledged_transition_time;
static int hf_btmesh_light_ctl_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_ctl_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_ctl_set_unacknowledged_delay;
static int hf_btmesh_light_ctl_status_present_ctl_lightness;
static int hf_btmesh_light_ctl_status_present_ctl_temperature;
static int hf_btmesh_light_ctl_status_target_ctl_lightness;
static int hf_btmesh_light_ctl_status_target_ctl_temperature;
static int hf_btmesh_light_ctl_status_remaining_time;
static int hf_btmesh_light_ctl_status_remaining_time_steps;
static int hf_btmesh_light_ctl_status_remaining_time_resolution;
static int hf_btmesh_light_ctl_temperature_range_status_status_code;
static int hf_btmesh_light_ctl_temperature_range_status_range_min;
static int hf_btmesh_light_ctl_temperature_range_status_range_max;
static int hf_btmesh_light_ctl_temperature_set_ctl_temperature;
static int hf_btmesh_light_ctl_temperature_set_ctl_delta_uv;
static int hf_btmesh_light_ctl_temperature_set_tid;
static int hf_btmesh_light_ctl_temperature_set_transition_time;
static int hf_btmesh_light_ctl_temperature_set_transition_time_steps;
static int hf_btmesh_light_ctl_temperature_set_transition_time_resolution;
static int hf_btmesh_light_ctl_temperature_set_delay;
static int hf_btmesh_light_ctl_temperature_set_unacknowledged_ctl_temperature;
static int hf_btmesh_light_ctl_temperature_set_unacknowledged_ctl_delta_uv;
static int hf_btmesh_light_ctl_temperature_set_unacknowledged_tid;
static int hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time;
static int hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_ctl_temperature_set_unacknowledged_delay;
static int hf_btmesh_light_ctl_temperature_status_present_ctl_temperature;
static int hf_btmesh_light_ctl_temperature_status_present_ctl_delta_uv;
static int hf_btmesh_light_ctl_temperature_status_target_ctl_temperature;
static int hf_btmesh_light_ctl_temperature_status_target_ctl_delta_uv;
static int hf_btmesh_light_ctl_temperature_status_remaining_time;
static int hf_btmesh_light_ctl_temperature_status_remaining_time_steps;
static int hf_btmesh_light_ctl_temperature_status_remaining_time_resolution;
static int hf_btmesh_light_ctl_default_status_lightness;
static int hf_btmesh_light_ctl_default_status_temperature;
static int hf_btmesh_light_ctl_default_status_delta_uv;
static int hf_btmesh_light_ctl_default_set_lightness;
static int hf_btmesh_light_ctl_default_set_temperature;
static int hf_btmesh_light_ctl_default_set_delta_uv;
static int hf_btmesh_light_ctl_default_set_unacknowledged_lightness;
static int hf_btmesh_light_ctl_default_set_unacknowledged_temperature;
static int hf_btmesh_light_ctl_default_set_unacknowledged_delta_uv;
static int hf_btmesh_light_ctl_temperature_range_set_range_min;
static int hf_btmesh_light_ctl_temperature_range_set_range_max;
static int hf_btmesh_light_ctl_temperature_range_set_unacknowledged_range_min;
static int hf_btmesh_light_ctl_temperature_range_set_unacknowledged_range_max;
static int hf_btmesh_light_hsl_hue_set_hue;
static int hf_btmesh_light_hsl_hue_set_tid;
static int hf_btmesh_light_hsl_hue_set_transition_time;
static int hf_btmesh_light_hsl_hue_set_transition_time_steps;
static int hf_btmesh_light_hsl_hue_set_transition_time_resolution;
static int hf_btmesh_light_hsl_hue_set_delay;
static int hf_btmesh_light_hsl_hue_set_unacknowledged_hue;
static int hf_btmesh_light_hsl_hue_set_unacknowledged_tid;
static int hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time;
static int hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_hsl_hue_set_unacknowledged_delay;
static int hf_btmesh_light_hsl_hue_status_present_hue;
static int hf_btmesh_light_hsl_hue_status_target_hue;
static int hf_btmesh_light_hsl_hue_status_remaining_time;
static int hf_btmesh_light_hsl_hue_status_remaining_time_steps;
static int hf_btmesh_light_hsl_hue_status_remaining_time_resolution;
static int hf_btmesh_light_hsl_saturation_set_saturation;
static int hf_btmesh_light_hsl_saturation_set_tid;
static int hf_btmesh_light_hsl_saturation_set_transition_time;
static int hf_btmesh_light_hsl_saturation_set_transition_time_steps;
static int hf_btmesh_light_hsl_saturation_set_transition_time_resolution;
static int hf_btmesh_light_hsl_saturation_set_delay;
static int hf_btmesh_light_hsl_saturation_set_unacknowledged_saturation;
static int hf_btmesh_light_hsl_saturation_set_unacknowledged_tid;
static int hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time;
static int hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_hsl_saturation_set_unacknowledged_delay;
static int hf_btmesh_light_hsl_saturation_status_present_saturation;
static int hf_btmesh_light_hsl_saturation_status_target_saturation;
static int hf_btmesh_light_hsl_saturation_status_remaining_time;
static int hf_btmesh_light_hsl_saturation_status_remaining_time_steps;
static int hf_btmesh_light_hsl_saturation_status_remaining_time_resolution;
static int hf_btmesh_light_hsl_set_hsl_lightness;
static int hf_btmesh_light_hsl_set_hsl_hue;
static int hf_btmesh_light_hsl_set_hsl_saturation;
static int hf_btmesh_light_hsl_set_tid;
static int hf_btmesh_light_hsl_set_transition_time;
static int hf_btmesh_light_hsl_set_transition_time_steps;
static int hf_btmesh_light_hsl_set_transition_time_resolution;
static int hf_btmesh_light_hsl_set_delay;
static int hf_btmesh_light_hsl_set_unacknowledged_hsl_lightness;
static int hf_btmesh_light_hsl_set_unacknowledged_hsl_hue;
static int hf_btmesh_light_hsl_set_unacknowledged_hsl_saturation;
static int hf_btmesh_light_hsl_set_unacknowledged_tid;
static int hf_btmesh_light_hsl_set_unacknowledged_transition_time;
static int hf_btmesh_light_hsl_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_hsl_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_hsl_set_unacknowledged_delay;
static int hf_btmesh_light_hsl_status_hsl_lightness;
static int hf_btmesh_light_hsl_status_hsl_hue;
static int hf_btmesh_light_hsl_status_hsl_saturation;
static int hf_btmesh_light_hsl_status_remaining_time;
static int hf_btmesh_light_hsl_status_remaining_time_steps;
static int hf_btmesh_light_hsl_status_remaining_time_resolution;
static int hf_btmesh_light_hsl_target_status_hsl_lightness_target;
static int hf_btmesh_light_hsl_target_status_hsl_hue_target;
static int hf_btmesh_light_hsl_target_status_hsl_saturation_target;
static int hf_btmesh_light_hsl_target_status_remaining_time;
static int hf_btmesh_light_hsl_target_status_remaining_time_steps;
static int hf_btmesh_light_hsl_target_status_remaining_time_resolution;
static int hf_btmesh_light_hsl_default_status_lightness;
static int hf_btmesh_light_hsl_default_status_hue;
static int hf_btmesh_light_hsl_default_status_saturation;
static int hf_btmesh_light_hsl_range_status_status_code;
static int hf_btmesh_light_hsl_range_status_hue_range_min;
static int hf_btmesh_light_hsl_range_status_hue_range_max;
static int hf_btmesh_light_hsl_range_status_saturation_range_min;
static int hf_btmesh_light_hsl_range_status_saturation_range_max;
static int hf_btmesh_light_hsl_default_set_lightness;
static int hf_btmesh_light_hsl_default_set_hue;
static int hf_btmesh_light_hsl_default_set_saturation;
static int hf_btmesh_light_hsl_default_set_unacknowledged_lightness;
static int hf_btmesh_light_hsl_default_set_unacknowledged_hue;
static int hf_btmesh_light_hsl_default_set_unacknowledged_saturation;
static int hf_btmesh_light_hsl_range_set_hue_range_min;
static int hf_btmesh_light_hsl_range_set_hue_range_max;
static int hf_btmesh_light_hsl_range_set_saturation_range_min;
static int hf_btmesh_light_hsl_range_set_saturation_range_max;
static int hf_btmesh_light_hsl_range_set_unacknowledged_hue_range_min;
static int hf_btmesh_light_hsl_range_set_unacknowledged_hue_range_max;
static int hf_btmesh_light_hsl_range_set_unacknowledged_saturation_range_min;
static int hf_btmesh_light_hsl_range_set_unacknowledged_saturation_range_max;
static int hf_btmesh_light_xyl_set_xyl_lightness;
static int hf_btmesh_light_xyl_set_xyl_x;
static int hf_btmesh_light_xyl_set_xyl_y;
static int hf_btmesh_light_xyl_set_tid;
static int hf_btmesh_light_xyl_set_transition_time;
static int hf_btmesh_light_xyl_set_transition_time_steps;
static int hf_btmesh_light_xyl_set_transition_time_resolution;
static int hf_btmesh_light_xyl_set_delay;
static int hf_btmesh_light_xyl_set_unacknowledged_xyl_lightness;
static int hf_btmesh_light_xyl_set_unacknowledged_xyl_x;
static int hf_btmesh_light_xyl_set_unacknowledged_xyl_y;
static int hf_btmesh_light_xyl_set_unacknowledged_tid;
static int hf_btmesh_light_xyl_set_unacknowledged_transition_time;
static int hf_btmesh_light_xyl_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_xyl_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_xyl_set_unacknowledged_delay;
static int hf_btmesh_light_xyl_status_xyl_lightness;
static int hf_btmesh_light_xyl_status_xyl_x;
static int hf_btmesh_light_xyl_status_xyl_y;
static int hf_btmesh_light_xyl_status_remaining_time;
static int hf_btmesh_light_xyl_status_remaining_time_steps;
static int hf_btmesh_light_xyl_status_remaining_time_resolution;
static int hf_btmesh_light_xyl_target_status_target_xyl_lightness;
static int hf_btmesh_light_xyl_target_status_target_xyl_x;
static int hf_btmesh_light_xyl_target_status_target_xyl_y;
static int hf_btmesh_light_xyl_target_status_remaining_time;
static int hf_btmesh_light_xyl_target_status_remaining_time_steps;
static int hf_btmesh_light_xyl_target_status_remaining_time_resolution;
static int hf_btmesh_light_xyl_default_status_lightness;
static int hf_btmesh_light_xyl_default_status_xyl_x;
static int hf_btmesh_light_xyl_default_status_xyl_y;
static int hf_btmesh_light_xyl_range_status_status_code;
static int hf_btmesh_light_xyl_range_status_xyl_x_range_min;
static int hf_btmesh_light_xyl_range_status_xyl_x_range_max;
static int hf_btmesh_light_xyl_range_status_xyl_y_range_min;
static int hf_btmesh_light_xyl_range_status_xyl_y_range_max;
static int hf_btmesh_light_xyl_default_set_lightness;
static int hf_btmesh_light_xyl_default_set_xyl_x;
static int hf_btmesh_light_xyl_default_set_xyl_y;
static int hf_btmesh_light_xyl_default_set_unacknowledged_lightness;
static int hf_btmesh_light_xyl_default_set_unacknowledged_xyl_x;
static int hf_btmesh_light_xyl_default_set_unacknowledged_xyl_y;
static int hf_btmesh_light_xyl_range_set_xyl_x_range_min;
static int hf_btmesh_light_xyl_range_set_xyl_x_range_max;
static int hf_btmesh_light_xyl_range_set_xyl_y_range_min;
static int hf_btmesh_light_xyl_range_set_xyl_y_range_max;
static int hf_btmesh_light_xyl_range_set_unacknowledged_xyl_x_range_min;
static int hf_btmesh_light_xyl_range_set_unacknowledged_xyl_x_range_max;
static int hf_btmesh_light_xyl_range_set_unacknowledged_xyl_y_range_min;
static int hf_btmesh_light_xyl_range_set_unacknowledged_xyl_y_range_max;
static int hf_btmesh_light_lc_mode_set_mode;
static int hf_btmesh_light_lc_mode_set_unacknowledged_mode;
static int hf_btmesh_light_lc_mode_status_mode;
static int hf_btmesh_light_lc_om_set_mode;
static int hf_btmesh_light_lc_om_set_unacknowledged_mode;
static int hf_btmesh_light_lc_om_status_mode;
static int hf_btmesh_light_lc_light_onoff_set_light_onoff;
static int hf_btmesh_light_lc_light_onoff_set_tid;
static int hf_btmesh_light_lc_light_onoff_set_transition_time;
static int hf_btmesh_light_lc_light_onoff_set_transition_time_steps;
static int hf_btmesh_light_lc_light_onoff_set_transition_time_resolution;
static int hf_btmesh_light_lc_light_onoff_set_delay;
static int hf_btmesh_light_lc_light_onoff_set_unacknowledged_light_onoff;
static int hf_btmesh_light_lc_light_onoff_set_unacknowledged_tid;
static int hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time;
static int hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time_steps;
static int hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time_resolution;
static int hf_btmesh_light_lc_light_onoff_set_unacknowledged_delay;
static int hf_btmesh_light_lc_light_onoff_status_present_light_onoff;
static int hf_btmesh_light_lc_light_onoff_status_target_light_onoff;
static int hf_btmesh_light_lc_light_onoff_status_remaining_time;
static int hf_btmesh_light_lc_light_onoff_status_remaining_time_steps;
static int hf_btmesh_light_lc_light_onoff_status_remaining_time_resolution;
static int hf_btmesh_light_lc_property_get_light_lc_property_id;

static int hf_btmesh_generic_manufacturer_properties_status_manufacturer_property_id;
static int hf_btmesh_generic_manufacturer_property_set_manufacturer_property_id;
static int hf_btmesh_generic_manufacturer_property_set_manufacturer_user_access;
static int hf_btmesh_generic_manufacturer_property_set_unacknowledged_manufacturer_property_id;
static int hf_btmesh_generic_manufacturer_property_set_unacknowledged_manufacturer_user_access;
static int hf_btmesh_generic_manufacturer_property_status_manufacturer_property_id;
static int hf_btmesh_generic_manufacturer_property_status_manufacturer_user_access;
static int hf_btmesh_generic_manufacturer_property_status_manufacturer_property_value;
static int hf_btmesh_generic_admin_properties_status_admin_property_id;
static int hf_btmesh_generic_admin_property_set_admin_property_id;
static int hf_btmesh_generic_admin_property_set_admin_user_access;
static int hf_btmesh_generic_admin_property_set_admin_property_value;
static int hf_btmesh_generic_admin_property_set_unacknowledged_admin_property_id;
static int hf_btmesh_generic_admin_property_set_unacknowledged_admin_user_access;
static int hf_btmesh_generic_admin_property_set_unacknowledged_admin_property_value;
static int hf_btmesh_generic_admin_property_status_admin_property_id;
static int hf_btmesh_generic_admin_property_status_admin_user_access;
static int hf_btmesh_generic_admin_property_status_admin_property_value;
static int hf_btmesh_generic_user_properties_status_user_property_id;
static int hf_btmesh_generic_user_property_set_user_property_id;
static int hf_btmesh_generic_user_property_set_user_property_value;
static int hf_btmesh_generic_user_property_set_unacknowledged_user_property_id;
static int hf_btmesh_generic_user_property_set_unacknowledged_user_property_value;
static int hf_btmesh_generic_user_property_status_user_property_id;
static int hf_btmesh_generic_user_property_status_user_access;
static int hf_btmesh_generic_user_property_status_user_property_value;
static int hf_btmesh_generic_client_properties_get_client_property_id;
static int hf_btmesh_generic_client_properties_status_client_property_id;
static int hf_btmesh_sensor_descriptor_get_property_id;
static int hf_btmesh_sensor_descriptor_status_descriptor_sensor_property_id;
static int hf_btmesh_sensor_descriptor_status_descriptor_sensor_positive_tolerance;
static int hf_btmesh_sensor_descriptor_status_descriptor_sensor_negative_tolerance;
static int hf_btmesh_sensor_descriptor_status_descriptor_sensor_sampling_function;
static int hf_btmesh_sensor_descriptor_status_descriptor_sensor_measurement_period;
static int hf_btmesh_sensor_descriptor_status_descriptor_sensor_update_interval;
static int hf_btmesh_sensor_status_mpid_format;
static int hf_btmesh_sensor_status_mpid_format_a_length;
static int hf_btmesh_sensor_status_mpid_format_a_property_id;
static int hf_btmesh_sensor_status_mpid_format_b_length;
static int hf_btmesh_sensor_status_mpid_format_b_property_id;
static int hf_btmesh_sensor_status_raw_value;
static int hf_btmesh_sensor_column_status_property_id;
static int hf_btmesh_sensor_column_status_raw_value_a;
static int hf_btmesh_sensor_column_status_raw_value_b;
static int hf_btmesh_sensor_column_status_raw_value_c;
static int hf_btmesh_sensor_series_status_property_id;
static int hf_btmesh_sensor_series_status_raw_value_a;
static int hf_btmesh_sensor_series_status_raw_value_b;
static int hf_btmesh_sensor_series_status_raw_value_c;
static int hf_btmesh_sensor_cadence_set_property_id;
static int hf_btmesh_sensor_cadence_set_fast_cadence_period_divisor;
static int hf_btmesh_sensor_cadence_set_status_trigger_type;
static int hf_btmesh_sensor_cadence_set_status_trigger_delta_down;
static int hf_btmesh_sensor_cadence_set_status_trigger_delta_up;
static int hf_btmesh_sensor_cadence_set_status_min_interval;
static int hf_btmesh_sensor_cadence_set_fast_cadence_low;
static int hf_btmesh_sensor_cadence_set_fast_cadence_high;
static int hf_btmesh_sensor_cadence_set_remainder_not_dissected;
static int hf_btmesh_sensor_cadence_set_unacknowledged_property_id;
static int hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_period_divisor;
static int hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_type;
static int hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_delta_down;
static int hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_delta_up;
static int hf_btmesh_sensor_cadence_set_unacknowledged_status_min_interval;
static int hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_low;
static int hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_high;
static int hf_btmesh_sensor_cadence_set_unacknowledged_remainder_not_dissected;
static int hf_btmesh_sensor_cadence_status_property_id;
static int hf_btmesh_sensor_cadence_status_fast_cadence_period_divisor;
static int hf_btmesh_sensor_cadence_status_status_trigger_type;
static int hf_btmesh_sensor_cadence_status_status_trigger_delta_down;
static int hf_btmesh_sensor_cadence_status_status_trigger_delta_up;
static int hf_btmesh_sensor_cadence_status_status_min_interval;
static int hf_btmesh_sensor_cadence_status_fast_cadence_low;
static int hf_btmesh_sensor_cadence_status_fast_cadence_high;
static int hf_btmesh_sensor_cadence_status_remainder_not_dissected;
static int hf_btmesh_sensor_settings_status_sensor_property_id;
static int hf_btmesh_sensor_settings_status_sensor_setting_property_id;
static int hf_btmesh_sensor_setting_set_sensor_property_id;
static int hf_btmesh_sensor_setting_set_sensor_setting_property_id;
static int hf_btmesh_sensor_setting_set_sensor_setting_raw;
static int hf_btmesh_sensor_setting_set_unacknowledged_sensor_property_id;
static int hf_btmesh_sensor_setting_set_unacknowledged_sensor_setting_property_id;
static int hf_btmesh_sensor_setting_set_unacknowledged_sensor_setting_raw;
static int hf_btmesh_sensor_setting_status_sensor_property_id;
static int hf_btmesh_sensor_setting_status_sensor_setting_property_id;
static int hf_btmesh_sensor_setting_status_sensor_setting_access;
static int hf_btmesh_sensor_setting_status_sensor_setting_raw;
static int hf_btmesh_generic_manufacturer_property_get_manufacturer_property_id;
static int hf_btmesh_generic_admin_property_get_admin_property_id;
static int hf_btmesh_generic_user_property_get_user_property_id;

static int hf_btmesh_sensor_get_property_id;
static int hf_btmesh_sensor_column_get_property_id;
static int hf_btmesh_sensor_column_get_raw_value_a;
static int hf_btmesh_sensor_series_get_property_id;
static int hf_btmesh_sensor_series_get_raw_value_a1;
static int hf_btmesh_sensor_series_get_raw_value_a2;
static int hf_btmesh_sensor_cadence_get_property_id;
static int hf_btmesh_sensor_settings_get_sensor_property_id;
static int hf_btmesh_sensor_setting_get_sensor_property_id;
static int hf_btmesh_sensor_setting_get_sensor_setting_property_id;

static int hf_bt_phony_characteristic_percentage_change_16;
static int hf_bt_phony_characteristic_index;
static int hf_bt_characteristic_time_decihour_8;
static int hf_bt_characteristic_temperature_8;
static int hf_bt_characteristic_temperature;
static int hf_bt_characteristic_electric_current;
static int hf_bt_characteristic_energy;
static int hf_bt_characteristic_generic_level;
static int hf_bt_characteristic_boolean;
static int hf_bt_characteristic_coefficient;
static int hf_bt_characteristic_count_16;
static int hf_bt_characteristic_illuminance;
static int hf_bt_characteristic_perceived_lightness;
static int hf_bt_characteristic_percentage_8;
static int hf_bt_characteristic_time_millisecond_24;
static int hf_bt_characteristic_time_second_16;

static const
bt_property_raw_value_entry_t sensor_column_status_hfs = {
    .hf_raw_value_a = &hf_btmesh_sensor_column_status_raw_value_a,
    .hf_raw_value_b = &hf_btmesh_sensor_column_status_raw_value_b,
    .hf_raw_value_c = &hf_btmesh_sensor_column_status_raw_value_c
};

static const
bt_property_raw_value_entry_t sensor_series_status_hfs = {
    .hf_raw_value_a = &hf_btmesh_sensor_series_status_raw_value_a,
    .hf_raw_value_b = &hf_btmesh_sensor_series_status_raw_value_b,
    .hf_raw_value_c = &hf_btmesh_sensor_series_status_raw_value_c
};

static const
bt_sensor_cadence_dissector_t sensor_cadence_set_hfs = {
    .hf_status_trigger_delta_up   = &hf_btmesh_sensor_cadence_set_status_trigger_delta_down,
    .hf_status_trigger_delta_down = &hf_btmesh_sensor_cadence_set_status_trigger_delta_up,
    .hf_status_min_interval       = &hf_btmesh_sensor_cadence_set_status_min_interval,
    .hf_fast_cadence_low          = &hf_btmesh_sensor_cadence_set_fast_cadence_low,
    .hf_fast_cadence_high         = &hf_btmesh_sensor_cadence_set_fast_cadence_high,
    .hf_remainder_not_dissected   = &hf_btmesh_sensor_cadence_set_remainder_not_dissected
};

static const
bt_sensor_cadence_dissector_t sensor_cadence_set_unacknowledged_hfs = {
    .hf_status_trigger_delta_up   = &hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_delta_down,
    .hf_status_trigger_delta_down = &hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_delta_up,
    .hf_status_min_interval       = &hf_btmesh_sensor_cadence_set_unacknowledged_status_min_interval,
    .hf_fast_cadence_low          = &hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_low,
    .hf_fast_cadence_high         = &hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_high,
    .hf_remainder_not_dissected   = &hf_btmesh_sensor_cadence_set_unacknowledged_remainder_not_dissected
};

static const
bt_sensor_cadence_dissector_t sensor_cadence_status_hfs = {
    .hf_status_trigger_delta_up   = &hf_btmesh_sensor_cadence_status_status_trigger_delta_down,
    .hf_status_trigger_delta_down = &hf_btmesh_sensor_cadence_status_status_trigger_delta_up,
    .hf_status_min_interval       = &hf_btmesh_sensor_cadence_status_status_min_interval,
    .hf_fast_cadence_low          = &hf_btmesh_sensor_cadence_status_fast_cadence_low,
    .hf_fast_cadence_high         = &hf_btmesh_sensor_cadence_status_fast_cadence_high,
    .hf_remainder_not_dissected   = &hf_btmesh_sensor_cadence_status_remainder_not_dissected
};

static const
bt_property_columns_raw_value_t sensor_column_get_hfs = {
    .hf_raw_value_a1 = &hf_btmesh_sensor_column_get_raw_value_a,
    .hf_raw_value_a2 = NULL
};

static const
bt_property_columns_raw_value_t sensor_series_get_hfs = {
    .hf_raw_value_a1 = &hf_btmesh_sensor_series_get_raw_value_a1,
    .hf_raw_value_a2 = &hf_btmesh_sensor_series_get_raw_value_a2
};

static int ett_btmesh;
static int ett_btmesh_net_pdu;
static int ett_btmesh_transp_pdu;
static int ett_btmesh_transp_ctrl_msg;
static int ett_btmesh_upper_transp_acc_pdu;
static int ett_btmesh_segmented_access_fragments;
static int ett_btmesh_segmented_access_fragment;
static int ett_btmesh_segmented_control_fragments;
static int ett_btmesh_segmented_control_fragment;
static int ett_btmesh_access_pdu;
static int ett_btmesh_model_layer;

static int ett_btmesh_config_model_netapp_index;
static int ett_btmesh_config_model_publishperiod;
static int ett_btmesh_config_model_publishretransmit;
static int ett_btmesh_config_model_relayretransmit;
static int ett_btmesh_config_model_network_transmit;
static int ett_btmesh_config_model_element;
static int ett_btmesh_config_model_model;
static int ett_btmesh_config_model_vendor;
static int ett_btmesh_config_composition_data_status_features;
static int ett_btmesh_config_model_pub_app_index;
static int ett_btmesh_config_model_addresses;
static int ett_btmesh_config_model_netkey_list;
static int ett_btmesh_config_model_appkey_list;
static int ett_btmesh_config_model_net_index;
static int ett_btmesh_config_model_app_index;
static int ett_btmesh_config_heartbeat_publication_set_features;
static int ett_btmesh_config_heartbeat_publication_status_features;
static int ett_btmesh_config_model_fault_array;
static int ett_btmesh_scene_register_status_scenes;
static int ett_btmesh_scheduler_model_month;
static int ett_btmesh_scheduler_model_day_of_week;
static int ett_btmesh_scheduler_schedules;
static int ett_btmesh_user_property_ids;
static int ett_btmesh_admin_property_ids;
static int ett_btmesh_manufacturer_property_ids;
static int ett_btmesh_generic_client_property_ids;
static int ett_btmesh_sensor_setting_property_ids;

static expert_field ei_btmesh_not_decoded_yet;
static expert_field ei_btmesh_unknown_payload;

static const value_string btmesh_ctl_vals[] = {
    { 0, "Access Message" },
    { 1, "Control Message" },
    { 0, NULL }
};

static const value_string btmesh_ctrl_seg_vals[] = {
    { 0, "Unsegmented Control Message" },
    { 1, "Segmented Control Message" },
    { 0, NULL }
};

static const value_string btmesh_acc_seg_vals[] = {
    { 0, "Unsegmented Access Message" },
    { 1, "Segmented Access Message" },
    { 0, NULL }
};

static const value_string btmesh_acc_akf_vals[] = {
    { 0, "Device key" },
    { 1, "Application key" },
    { 0, NULL }
};

static const value_string btmesh_ctrl_opcode_vals[] = {
    { 0x0, "Segment Acknowledgment" }, /* Reserved for lower transport layer */
    { 0x1, "Friend Poll" },
    { 0x2, "Friend Update" },
    { 0x3, "Friend Request" },
    { 0x4, "Friend Offer" },
    { 0x5, "Friend Clear" },
    { 0x6, "Friend Clear Confirm" },
    { 0x7, "Friend Subscription List Add" },
    { 0x8, "Friend Subscription List Remove" },
    { 0x9, "Friend Subscription List Confirm" },
    { 0xa, "Heartbeat" },
    { 0, NULL }
};

static const value_string btmesh_cntr_key_refresh_flag_vals[] = {
    { 0x0, "Not-In-Phase2" },
    { 0x1, "In-Phase2" },
    { 0, NULL }
};

static const value_string btmesh_cntr_iv_update_flag_vals[] = {
    { 0x0, "Normal operation" },
    { 0x1, "IV Update active" },
    { 0, NULL }
};

static const value_string btmesh_cntr_md_vals[] = {
    { 0x0, "Friend Queue is empty" },
    { 0x1, "Friend Queue is not empty" },
    { 0, NULL }
};

static const true_false_string  btmesh_obo = {
    "Friend node that is acknowledging this message on behalf of a Low Power node",
    "Node that is directly addressed by the received message"
};

static const value_string btmesh_criteria_rssifactor_vals[] = {
    { 0x0, "1" },
    { 0x1, "1.5" },
    { 0x2, "2" },
    { 0x3, "2.5" },
    { 0, NULL }
};

static const value_string btmesh_criteria_receivewindowfactor_vals[] = {
    { 0x0, "1" },
    { 0x1, "1.5" },
    { 0x2, "2" },
    { 0x3, "2.5" },
    { 0, NULL }
};

static const value_string btmesh_criteria_minqueuesizelog_vals[] = {
    { 0x0, "Prohibited" },
    { 0x1, "N = 2" },
    { 0x2, "N = 4" },
    { 0x3, "N = 8" },
    { 0x4, "N = 16" },
    { 0x5, "N = 32" },
    { 0x6, "N = 64" },
    { 0x7, "N = 128" },
    { 0, NULL }
};

static const value_string btmesh_szmic_vals[] = {
    { 0x0, "32-bit" },
    { 0x1, "64-bit" },
    { 0, NULL }
};

static const value_string btmesh_models_opcode_vals[] = {
    /* Bluetooth Mesh Foundation messages */
    { CONFIG_APPKEY_ADD                                   , "Config AppKey Add"                                  },
    { CONFIG_APPKEY_UPDATE                                , "Config AppKey Update"                               },
    { CONFIG_COMPOSITION_DATA_STATUS                      , "Config Composition Data Status"                     },
    { CONFIG_MODEL_PUBLICATION_SET                        , "Config Model Publication Set"                       },
    { HEALTH_CURRENT_STATUS                               , "Health Current Status"                              },
    { HEALTH_FAULT_STATUS                                 , "Health Fault Status"                                },
    { CONFIG_HEARTBEAT_PUBLICATION_STATUS                 , "Config Heartbeat Publication Status"                },
    { CONFIG_APPKEY_DELETE                                , "Config AppKey Delete"                               },
    { CONFIG_APPKEY_GET                                   , "Config AppKey Get"                                  },
    { CONFIG_APPKEY_LIST                                  , "Config AppKey List"                                 },
    { CONFIG_APPKEY_STATUS                                , "Config AppKey Status"                               },
    { HEALTH_ATTENTION_GET                                , "Health Attention Get"                               },
    { HEALTH_ATTENTION_SET                                , "Health Attention Set"                               },
    { HEALTH_ATTENTION_SET_UNACKNOWLEDGED                 , "Health Attention Set Unacknowledged"                },
    { HEALTH_ATTENTION_STATUS                             , "Health Attention Status"                            },
    { CONFIG_COMPOSITION_DATA_GET                         , "Config Composition Data Get"                        },
    { CONFIG_BEACON_GET                                   , "Config Beacon Get"                                  },
    { CONFIG_BEACON_SET                                   , "Config Beacon Set"                                  },
    { CONFIG_BEACON_STATUS                                , "Config Beacon Status"                               },
    { CONFIG_DEFAULT_TTL_GET                              , "Config Default TTL Get"                             },
    { CONFIG_DEFAULT_TTL_SET                              , "Config Default TTL Set"                             },
    { CONFIG_DEFAULT_TTL_STATUS                           , "Config Default TTL Status"                          },
    { CONFIG_FRIEND_GET                                   , "Config Friend Get"                                  },
    { CONFIG_FRIEND_SET                                   , "Config Friend Set"                                  },
    { CONFIG_FRIEND_STATUS                                , "Config Friend Status"                               },
    { CONFIG_GATT_PROXY_GET                               , "Config GATT Proxy Get"                              },
    { CONFIG_GATT_PROXY_SET                               , "Config GATT Proxy Set"                              },
    { CONFIG_GATT_PROXY_STATUS                            , "Config GATT Proxy Status"                           },
    { CONFIG_KEY_REFRESH_PHASE_GET                        , "Config Key Refresh Phase Get"                       },
    { CONFIG_KEY_REFRESH_PHASE_SET                        , "Config Key Refresh Phase Set"                       },
    { CONFIG_KEY_REFRESH_PHASE_STATUS                     , "Config Key Refresh Phase Status"                    },
    { CONFIG_MODEL_PUBLICATION_GET                        , "Config Model Publication Get"                       },
    { CONFIG_MODEL_PUBLICATION_STATUS                     , "Config Model Publication Status"                    },
    { CONFIG_MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET        , "Config Model Publication Virtual Address Set"       },
    { CONFIG_MODEL_SUBSCRIPTION_ADD                       , "Config Model Subscription Add"                      },
    { CONFIG_MODEL_SUBSCRIPTION_DELETE                    , "Config Model Subscription Delete"                   },
    { CONFIG_MODEL_SUBSCRIPTION_DELETE_ALL                , "Config Model Subscription Delete All"               },
    { CONFIG_MODEL_SUBSCRIPTION_OVERWRITE                 , "Config Model Subscription Overwrite"                },
    { CONFIG_MODEL_SUBSCRIPTION_STATUS                    , "Config Model Subscription Status"                   },
    { CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD       , "Config Model Subscription Virtual Address Add"      },
    { CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE    , "Config Model Subscription Virtual Address Delete"   },
    { CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE , "Config Model Subscription Virtual Address Overwrite"},
    { CONFIG_NETWORK_TRANSMIT_GET                         , "Config Network Transmit Get"                        },
    { CONFIG_NETWORK_TRANSMIT_SET                         , "Config Network Transmit Set"                        },
    { CONFIG_NETWORK_TRANSMIT_STATUS                      , "Config Network Transmit Status"                     },
    { CONFIG_RELAY_GET                                    , "Config Relay Get"                                   },
    { CONFIG_RELAY_SET                                    , "Config Relay Set"                                   },
    { CONFIG_RELAY_STATUS                                 , "Config Relay Status"                                },
    { CONFIG_SIG_MODEL_SUBSCRIPTION_GET                   , "Config SIG Model Subscription Get"                  },
    { CONFIG_SIG_MODEL_SUBSCRIPTION_LIST                  , "Config SIG Model Subscription List"                 },
    { CONFIG_VENDOR_MODEL_SUBSCRIPTION_GET                , "Config Vendor Model Subscription Get"               },
    { CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST               , "Config Vendor Model Subscription List"              },
    { CONFIG_LOW_POWER_NODE_POLLTIMEOUT_GET               , "Config Low Power Node PollTimeout Get"              },
    { CONFIG_LOW_POWER_NODE_POLLTIMEOUT_STATUS            , "Config Low Power Node PollTimeout Status"           },
    { HEALTH_FAULT_CLEAR                                  , "Health Fault Clear"                                 },
    { HEALTH_FAULT_CLEAR_UNACKNOWLEDGED                   , "Health Fault Clear Unacknowledged"                  },
    { HEALTH_FAULT_GET                                    , "Health Fault Get"                                   },
    { HEALTH_FAULT_TEST                                   , "Health Fault Test"                                  },
    { HEALTH_FAULT_TEST_UNACKNOWLEDGED                    , "Health Fault Test Unacknowledged"                   },
    { HEALTH_PERIOD_GET                                   , "Health Period Get"                                  },
    { HEALTH_PERIOD_SET                                   , "Health Period Set"                                  },
    { HEALTH_PERIOD_SET_UNACKNOWLEDGED                    , "Health Period Set Unacknowledged"                   },
    { HEALTH_PERIOD_STATUS                                , "Health Period Status"                               },
    { CONFIG_HEARTBEAT_PUBLICATION_GET                    , "Config Heartbeat Publication Get"                   },
    { CONFIG_HEARTBEAT_PUBLICATION_SET                    , "Config Heartbeat Publication Set"                   },
    { CONFIG_HEARTBEAT_SUBSCRIPTION_GET                   , "Config Heartbeat Subscription Get"                  },
    { CONFIG_HEARTBEAT_SUBSCRIPTION_SET                   , "Config Heartbeat Subscription Set"                  },
    { CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS                , "Config Heartbeat Subscription Status"               },
    { CONFIG_MODEL_APP_BIND                               , "Config Model App Bind"                              },
    { CONFIG_MODEL_APP_STATUS                             , "Config Model App Status"                            },
    { CONFIG_MODEL_APP_UNBIND                             , "Config Model App Unbind"                            },
    { CONFIG_NETKEY_ADD                                   , "Config NetKey Add"                                  },
    { CONFIG_NETKEY_DELETE                                , "Config NetKey Delete"                               },
    { CONFIG_NETKEY_GET                                   , "Config NetKey Get"                                  },
    { CONFIG_NETKEY_LIST                                  , "Config NetKey List"                                 },
    { CONFIG_NETKEY_STATUS                                , "Config NetKey Status"                               },
    { CONFIG_NETKEY_UPDATE                                , "Config NetKey Update"                               },
    { CONFIG_NODE_IDENTITY_GET                            , "Config Node Identity Get"                           },
    { CONFIG_NODE_IDENTITY_SET                            , "Config Node Identity Set"                           },
    { CONFIG_NODE_IDENTITY_STATUS                         , "Config Node Identity Status"                        },
    { CONFIG_NODE_RESET                                   , "Config Node Reset"                                  },
    { CONFIG_NODE_RESET_STATUS                            , "Config Node Reset Status"                           },
    { CONFIG_SIG_MODEL_APP_GET                            , "Config SIG Model App Get"                           },
    { CONFIG_SIG_MODEL_APP_LIST                           , "Config SIG Model App List"                          },
    { CONFIG_VENDOR_MODEL_APP_GET                         , "Config Vendor Model App Get"                        },
    { CONFIG_VENDOR_MODEL_APP_LIST                        , "Config Vendor Model App List"                       },

      /* Bluetooth Mesh Model messages */
    { GENERIC_ONOFF_GET                                   , "Generic OnOff Get"                                  },
    { GENERIC_ONOFF_SET                                   , "Generic OnOff Set"                                  },
    { GENERIC_ONOFF_SET_UNACKNOWLEDGED                    , "Generic OnOff Set Unacknowledged"                   },
    { GENERIC_ONOFF_STATUS                                , "Generic OnOff Status"                               },
    { GENERIC_LEVEL_GET                                   , "Generic Level Get"                                  },
    { GENERIC_LEVEL_SET                                   , "Generic Level Set"                                  },
    { GENERIC_LEVEL_SET_UNACKNOWLEDGED                    , "Generic Level Set Unacknowledged"                   },
    { GENERIC_LEVEL_STATUS                                , "Generic Level Status"                               },
    { GENERIC_DELTA_SET                                   , "Generic Delta Set"                                  },
    { GENERIC_DELTA_SET_UNACKNOWLEDGED                    , "Generic Delta Set Unacknowledged"                   },
    { GENERIC_MOVE_SET                                    , "Generic Move Set"                                   },
    { GENERIC_MOVE_SET_UNACKNOWLEDGED                     , "Generic Move Set Unacknowledged"                    },
    { GENERIC_DEFAULT_TRANSITION_TIME_GET                 , "Generic Default Transition Time Get"                },
    { GENERIC_DEFAULT_TRANSITION_TIME_SET                 , "Generic Default Transition Time Set"                },
    { GENERIC_DEFAULT_TRANSITION_TIME_SET_UNACKNOWLEDGED  , "Generic Default Transition Time Set Unacknowledged" },
    { GENERIC_DEFAULT_TRANSITION_TIME_STATUS              , "Generic Default Transition Time Status"             },
    { GENERIC_ONPOWERUP_GET                               , "Generic OnPowerUp Get"                              },
    { GENERIC_ONPOWERUP_STATUS                            , "Generic OnPowerUp Status"                           },
    { GENERIC_ONPOWERUP_SET                               , "Generic OnPowerUp Set"                              },
    { GENERIC_ONPOWERUP_SET_UNACKNOWLEDGED                , "Generic OnPowerUp Set Unacknowledged"               },
    { GENERIC_POWER_LEVEL_GET                             , "Generic Power Level Get"                            },
    { GENERIC_POWER_LEVEL_SET                             , "Generic Power Level Set"                            },
    { GENERIC_POWER_LEVEL_SET_UNACKNOWLEDGED              , "Generic Power Level Set Unacknowledged"             },
    { GENERIC_POWER_LEVEL_STATUS                          , "Generic Power Level Status"                         },
    { GENERIC_POWER_LAST_GET                              , "Generic Power Last Get"                             },
    { GENERIC_POWER_LAST_STATUS                           , "Generic Power Last Status"                          },
    { GENERIC_POWER_DEFAULT_GET                           , "Generic Power Default Get"                          },
    { GENERIC_POWER_DEFAULT_STATUS                        , "Generic Power Default Status"                       },
    { GENERIC_POWER_RANGE_GET                             , "Generic Power Range Get"                            },
    { GENERIC_POWER_RANGE_STATUS                          , "Generic Power Range Status"                         },
    { GENERIC_POWER_DEFAULT_SET                           , "Generic Power Default Set"                          },
    { GENERIC_POWER_DEFAULT_SET_UNACKNOWLEDGED            , "Generic Power Default Set Unacknowledged"           },
    { GENERIC_POWER_RANGE_SET                             , "Generic Power Range Set"                            },
    { GENERIC_POWER_RANGE_SET_UNACKNOWLEDGED              , "Generic Power Range Set Unacknowledged"             },
    { GENERIC_BATTERY_GET                                 , "Generic Battery Get"                                },
    { GENERIC_BATTERY_STATUS                              , "Generic Battery Status"                             },
    { GENERIC_LOCATION_GLOBAL_GET                         , "Generic Location Global Get"                        },
    { GENERIC_LOCATION_GLOBAL_STATUS                      , "Generic Location Global Status"                     },
    { GENERIC_LOCATION_LOCAL_GET                          , "Generic Location Local Get"                         },
    { GENERIC_LOCATION_LOCAL_STATUS                       , "Generic Location Local Status"                      },
    { GENERIC_LOCATION_GLOBAL_SET                         , "Generic Location Global Set"                        },
    { GENERIC_LOCATION_GLOBAL_SET_UNACKNOWLEDGED          , "Generic Location Global Set Unacknowledged"         },
    { GENERIC_LOCATION_LOCAL_SET                          , "Generic Location Local Set"                         },
    { GENERIC_LOCATION_LOCAL_SET_UNACKNOWLEDGED           , "Generic Location Local Set Unacknowledged"          },
    { GENERIC_MANUFACTURER_PROPERTIES_GET                 , "Generic Manufacturer Properties Get"                },
    { GENERIC_MANUFACTURER_PROPERTIES_STATUS              , "Generic Manufacturer Properties Status"             },
    { GENERIC_MANUFACTURER_PROPERTY_GET                   , "Generic Manufacturer Property Get"                  },
    { GENERIC_MANUFACTURER_PROPERTY_SET                   , "Generic Manufacturer Property Set"                  },
    { GENERIC_MANUFACTURER_PROPERTY_SET_UNACKNOWLEDGED    , "Generic Manufacturer Property Set Unacknowledged"   },
    { GENERIC_MANUFACTURER_PROPERTY_STATUS                , "Generic Manufacturer Property Status"               },
    { GENERIC_ADMIN_PROPERTIES_GET                        , "Generic Admin Properties Get"                       },
    { GENERIC_ADMIN_PROPERTIES_STATUS                     , "Generic Admin Properties Status"                    },
    { GENERIC_ADMIN_PROPERTY_GET                          , "Generic Admin Property Get"                         },
    { GENERIC_ADMIN_PROPERTY_SET                          , "Generic Admin Property Set"                         },
    { GENERIC_ADMIN_PROPERTY_SET_UNACKNOWLEDGED           , "Generic Admin Property Set Unacknowledged"          },
    { GENERIC_ADMIN_PROPERTY_STATUS                       , "Generic Admin Property Status"                      },
    { GENERIC_USER_PROPERTIES_GET                         , "Generic User Properties Get"                        },
    { GENERIC_USER_PROPERTIES_STATUS                      , "Generic User Properties Status"                     },
    { GENERIC_USER_PROPERTY_GET                           , "Generic User Property Get"                          },
    { GENERIC_USER_PROPERTY_SET                           , "Generic User Property Set"                          },
    { GENERIC_USER_PROPERTY_SET_UNACKNOWLEDGED            , "Generic User Property Set Unacknowledged"           },
    { GENERIC_USER_PROPERTY_STATUS                        , "Generic User Property Status"                       },
    { GENERIC_CLIENT_PROPERTIES_GET                       , "Generic Client Properties Get"                      },
    { GENERIC_CLIENT_PROPERTIES_STATUS                    , "Generic Client Properties Status"                   },
    { SENSOR_DESCRIPTOR_GET                               , "Sensor Descriptor Get"                              },
    { SENSOR_DESCRIPTOR_STATUS                            , "Sensor Descriptor Status"                           },
    { SENSOR_GET                                          , "Sensor Get"                                         },
    { SENSOR_STATUS                                       , "Sensor Status"                                      },
    { SENSOR_COLUMN_GET                                   , "Sensor Column Get"                                  },
    { SENSOR_COLUMN_STATUS                                , "Sensor Column Status"                               },
    { SENSOR_SERIES_GET                                   , "Sensor Series Get"                                  },
    { SENSOR_SERIES_STATUS                                , "Sensor Series Status"                               },
    { SENSOR_CADENCE_GET                                  , "Sensor Cadence Get"                                 },
    { SENSOR_CADENCE_SET                                  , "Sensor Cadence Set"                                 },
    { SENSOR_CADENCE_SET_UNACKNOWLEDGED                   , "Sensor Cadence Set Unacknowledged"                  },
    { SENSOR_CADENCE_STATUS                               , "Sensor Cadence Status"                              },
    { SENSOR_SETTINGS_GET                                 , "Sensor Settings Get"                                },
    { SENSOR_SETTINGS_STATUS                              , "Sensor Settings Status"                             },
    { SENSOR_SETTING_GET                                  , "Sensor Setting Get"                                 },
    { SENSOR_SETTING_SET                                  , "Sensor Setting Set"                                 },
    { SENSOR_SETTING_SET_UNACKNOWLEDGED                   , "Sensor Setting Set Unacknowledged"                  },
    { SENSOR_SETTING_STATUS                               , "Sensor Setting Status"                              },
    { TIME_GET                                            , "Time Get"                                           },
    { TIME_SET                                            , "Time Set"                                           },
    { TIME_STATUS                                         , "Time Status"                                        },
    { TIME_ROLE_GET                                       , "Time Role Get"                                      },
    { TIME_ROLE_SET                                       , "Time Role Set"                                      },
    { TIME_ROLE_STATUS                                    , "Time Role Status"                                   },
    { TIME_ZONE_GET                                       , "Time Zone Get"                                      },
    { TIME_ZONE_SET                                       , "Time Zone Set"                                      },
    { TIME_ZONE_STATUS                                    , "Time Zone Status"                                   },
    { TAI_UTC_DELTA_GET                                   , "TAI-UTC Delta Get"                                  },
    { TAI_UTC_DELTA_SET                                   , "TAI-UTC Delta Set"                                  },
    { TAI_UTC_DELTA_STATUS                                , "TAI-UTC Delta Status"                               },
    { SCENE_GET                                           , "Scene Get"                                          },
    { SCENE_RECALL                                        , "Scene Recall"                                       },
    { SCENE_RECALL_UNACKNOWLEDGED                         , "Scene Recall Unacknowledged"                        },
    { SCENE_STATUS                                        , "Scene Status"                                       },
    { SCENE_REGISTER_GET                                  , "Scene Register Get"                                 },
    { SCENE_REGISTER_STATUS                               , "Scene Register Status"                              },
    { SCENE_STORE                                         , "Scene Store"                                        },
    { SCENE_STORE_UNACKNOWLEDGED                          , "Scene Store Unacknowledged"                         },
    { SCENE_DELETE                                        , "Scene Delete"                                       },
    { SCENE_DELETE_UNACKNOWLEDGED                         , "Scene Delete Unacknowledged"                        },
    { SCHEDULER_ACTION_GET                                , "Scheduler Action Get"                               },
    { SCHEDULER_ACTION_STATUS                             , "Scheduler Action Status"                            },
    { SCHEDULER_GET                                       , "Scheduler Get"                                      },
    { SCHEDULER_STATUS                                    , "Scheduler Status"                                   },
    { SCHEDULER_ACTION_SET                                , "Scheduler Action Set"                               },
    { SCHEDULER_ACTION_SET_UNACKNOWLEDGED                 , "Scheduler Action Set Unacknowledged"                },
    { LIGHT_LIGHTNESS_GET                                 , "Light Lightness Get"                                },
    { LIGHT_LIGHTNESS_SET                                 , "Light Lightness Set"                                },
    { LIGHT_LIGHTNESS_SET_UNACKNOWLEDGED                  , "Light Lightness Set Unacknowledged"                 },
    { LIGHT_LIGHTNESS_STATUS                              , "Light Lightness Status"                             },
    { LIGHT_LIGHTNESS_LINEAR_GET                          , "Light Lightness Linear Get"                         },
    { LIGHT_LIGHTNESS_LINEAR_SET                          , "Light Lightness Linear Set"                         },
    { LIGHT_LIGHTNESS_LINEAR_SET_UNACKNOWLEDGED           , "Light Lightness Linear Set Unacknowledged"          },
    { LIGHT_LIGHTNESS_LINEAR_STATUS                       , "Light Lightness Linear Status"                      },
    { LIGHT_LIGHTNESS_LAST_GET                            , "Light Lightness Last Get"                           },
    { LIGHT_LIGHTNESS_LAST_STATUS                         , "Light Lightness Last Status"                        },
    { LIGHT_LIGHTNESS_DEFAULT_GET                         , "Light Lightness Default Get"                        },
    { LIGHT_LIGHTNESS_DEFAULT_STATUS                      , "Light Lightness Default Status"                     },
    { LIGHT_LIGHTNESS_RANGE_GET                           , "Light Lightness Range Get"                          },
    { LIGHT_LIGHTNESS_RANGE_STATUS                        , "Light Lightness Range Status"                       },
    { LIGHT_LIGHTNESS_DEFAULT_SET                         , "Light Lightness Default Set"                        },
    { LIGHT_LIGHTNESS_DEFAULT_SET_UNACKNOWLEDGED          , "Light Lightness Default Set Unacknowledged"         },
    { LIGHT_LIGHTNESS_RANGE_SET                           , "Light Lightness Range Set"                          },
    { LIGHT_LIGHTNESS_RANGE_SET_UNACKNOWLEDGED            , "Light Lightness Range Set Unacknowledged"           },
    { LIGHT_CTL_GET                                       , "Light CTL Get"                                      },
    { LIGHT_CTL_SET                                       , "Light CTL Set"                                      },
    { LIGHT_CTL_SET_UNACKNOWLEDGED                        , "Light CTL Set Unacknowledged"                       },
    { LIGHT_CTL_STATUS                                    , "Light CTL Status"                                   },
    { LIGHT_CTL_TEMPERATURE_GET                           , "Light CTL Temperature Get"                          },
    { LIGHT_CTL_TEMPERATURE_RANGE_GET                     , "Light CTL Temperature Range Get"                    },
    { LIGHT_CTL_TEMPERATURE_RANGE_STATUS                  , "Light CTL Temperature Range Status"                 },
    { LIGHT_CTL_TEMPERATURE_SET                           , "Light CTL Temperature Set"                          },
    { LIGHT_CTL_TEMPERATURE_SET_UNACKNOWLEDGED            , "Light CTL Temperature Set Unacknowledged"           },
    { LIGHT_CTL_TEMPERATURE_STATUS                        , "Light CTL Temperature Status"                       },
    { LIGHT_CTL_DEFAULT_GET                               , "Light CTL Default Get"                              },
    { LIGHT_CTL_DEFAULT_STATUS                            , "Light CTL Default Status"                           },
    { LIGHT_CTL_DEFAULT_SET                               , "Light CTL Default Set"                              },
    { LIGHT_CTL_DEFAULT_SET_UNACKNOWLEDGED                , "Light CTL Default Set Unacknowledged"               },
    { LIGHT_CTL_TEMPERATURE_RANGE_SET                     , "Light CTL Temperature Range Set"                    },
    { LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACKNOWLEDGED      , "Light CTL Temperature Range Set Unacknowledged"     },
    { LIGHT_HSL_GET                                       , "Light HSL Get"                                      },
    { LIGHT_HSL_HUE_GET                                   , "Light HSL Hue Get"                                  },
    { LIGHT_HSL_HUE_SET                                   , "Light HSL Hue Set"                                  },
    { LIGHT_HSL_HUE_SET_UNACKNOWLEDGED                    , "Light HSL Hue Set Unacknowledged"                   },
    { LIGHT_HSL_HUE_STATUS                                , "Light HSL Hue Status"                               },
    { LIGHT_HSL_SATURATION_GET                            , "Light HSL Saturation Get"                           },
    { LIGHT_HSL_SATURATION_SET                            , "Light HSL Saturation Set"                           },
    { LIGHT_HSL_SATURATION_SET_UNACKNOWLEDGED             , "Light HSL Saturation Set Unacknowledged"            },
    { LIGHT_HSL_SATURATION_STATUS                         , "Light HSL Saturation Status"                        },
    { LIGHT_HSL_SET                                       , "Light HSL Set"                                      },
    { LIGHT_HSL_SET_UNACKNOWLEDGED                        , "Light HSL Set Unacknowledged"                       },
    { LIGHT_HSL_STATUS                                    , "Light HSL Status"                                   },
    { LIGHT_HSL_TARGET_GET                                , "Light HSL Target Get"                               },
    { LIGHT_HSL_TARGET_STATUS                             , "Light HSL Target Status"                            },
    { LIGHT_HSL_DEFAULT_GET                               , "Light HSL Default Get"                              },
    { LIGHT_HSL_DEFAULT_STATUS                            , "Light HSL Default Status"                           },
    { LIGHT_HSL_RANGE_GET                                 , "Light HSL Range Get"                                },
    { LIGHT_HSL_RANGE_STATUS                              , "Light HSL Range Status"                             },
    { LIGHT_HSL_DEFAULT_SET                               , "Light HSL Default Set"                              },
    { LIGHT_HSL_DEFAULT_SET_UNACKNOWLEDGED                , "Light HSL Default Set Unacknowledged"               },
    { LIGHT_HSL_RANGE_SET                                 , "Light HSL Range Set"                                },
    { LIGHT_HSL_RANGE_SET_UNACKNOWLEDGED                  , "Light HSL Range Set Unacknowledged"                 },
    { LIGHT_XYL_GET                                       , "Light xyL Get"                                      },
    { LIGHT_XYL_SET                                       , "Light xyL Set"                                      },
    { LIGHT_XYL_SET_UNACKNOWLEDGED                        , "Light xyL Set Unacknowledged"                       },
    { LIGHT_XYL_STATUS                                    , "Light xyL Status"                                   },
    { LIGHT_XYL_TARGET_GET                                , "Light xyL Target Get"                               },
    { LIGHT_XYL_TARGET_STATUS                             , "Light xyL Target Status"                            },
    { LIGHT_XYL_DEFAULT_GET                               , "Light xyL Default Get"                              },
    { LIGHT_XYL_DEFAULT_STATUS                            , "Light xyL Default Status"                           },
    { LIGHT_XYL_RANGE_GET                                 , "Light xyL Range Get"                                },
    { LIGHT_XYL_RANGE_STATUS                              , "Light xyL Range Status"                             },
    { LIGHT_XYL_DEFAULT_SET                               , "Light xyL Default Set"                              },
    { LIGHT_XYL_DEFAULT_SET_UNACKNOWLEDGED                , "Light xyL Default Set Unacknowledged"               },
    { LIGHT_XYL_RANGE_SET                                 , "Light xyL Range Set"                                },
    { LIGHT_XYL_RANGE_SET_UNACKNOWLEDGED                  , "Light xyL Range Set Unacknowledged"                 },
    { LIGHT_LC_MODE_GET                                   , "Light LC Mode Get"                                  },
    { LIGHT_LC_MODE_SET                                   , "Light LC Mode Set"                                  },
    { LIGHT_LC_MODE_SET_UNACKNOWLEDGED                    , "Light LC Mode Set Unacknowledged"                   },
    { LIGHT_LC_MODE_STATUS                                , "Light LC Mode Status"                               },
    { LIGHT_LC_OM_GET                                     , "Light LC OM Get"                                    },
    { LIGHT_LC_OM_SET                                     , "Light LC OM Set"                                    },
    { LIGHT_LC_OM_SET_UNACKNOWLEDGED                      , "Light LC OM Set Unacknowledged"                     },
    { LIGHT_LC_OM_STATUS                                  , "Light LC OM Status"                                 },
    { LIGHT_LC_LIGHT_ONOFF_GET                            , "Light LC Light OnOff Get"                           },
    { LIGHT_LC_LIGHT_ONOFF_SET                            , "Light LC Light OnOff Set"                           },
    { LIGHT_LC_LIGHT_ONOFF_SET_UNACKNOWLEDGED             , "Light LC Light OnOff Set Unacknowledged"            },
    { LIGHT_LC_LIGHT_ONOFF_STATUS                         , "Light LC Light OnOff Status"                        },
    { LIGHT_LC_PROPERTY_GET                               , "Light LC Property Get"                              },
    { LIGHT_LC_PROPERTY_SET                               , "Light LC Property Set"                              },
    { LIGHT_LC_PROPERTY_SET_UNACKNOWLEDGED                , "Light LC Property Set Unacknowledged"               },
    { LIGHT_LC_PROPERTY_STATUS                            , "Light LC Property Status"                           },
    { 0, NULL }
};

static const value_string btmesh_beacon_broadcast_vals[] = {
    { 0x00, "Not broadcasting a Secure Network beacon" },
    { 0x01, "Broadcasting a Secure Network beacon" },
    { 0, NULL }
};

static const value_string btmesh_gatt_proxy_vals[] = {
    { 0x00, "Proxy feature is supported and disabled" },
    { 0x01, "Proxy feature is supported and enabled" },
    { 0x02, "Proxy feature is not supported" },
    { 0, NULL }
};

static const value_string btmesh_relay_vals[] = {
    { 0x00, "Relay feature is supported and disabled" },
    { 0x01, "Relay feature is supported and enabled" },
    { 0x02, "Relay feature is not supported" },
    { 0, NULL }
};

static const value_string btmesh_friend_vals[] = {
    { 0x00, "Friend feature is supported and disabled" },
    { 0x01, "Friend feature is supported and enabled" },
    { 0x02, "Friend feature is not supported" },
    { 0, NULL }
};

static const value_string btmesh_publishperiod_resolution_vals[] = {
    { 0x00, "100 milliseconds" },
    { 0x01, "1 second" },
    { 0x02, "10 seconds" },
    { 0x03, "10 minutes" },
    { 0, NULL }
};

static const value_string btmesh_friendship_credentials_flag_vals[] = {
    { 0x00, "Central security material is used" },
    { 0x01, "Friendship security material is used" },
    { 0, NULL }
};

static const value_string btmesh_phase_vals[] = {
    { 0x00, "Normal operation" },
    { 0x01, "First phase of Key Refresh procedure" },
    { 0x02, "Second phase of Key Refresh procedure" },
    { 0, NULL }
};

static const range_string btmesh_transition_vals[] = {
    { 0x00, 0x01, "Prohibited" },
    { 0x02, 0x02, "Transition 2" },
    { 0x03, 0x03, "Transition 3" },
    { 0x04, 0xFF, "Prohibited" },
    { 0, 0, NULL }
};

static const value_string btmesh_fault_array_vals[] = {
    { 0x00, "No Fault" },
    { 0x01, "Battery Low Warning" },
    { 0x02, "Battery Low Error" },
    { 0x03, "Supply Voltage Too Low Warning" },
    { 0x04, "Supply Voltage Too Low Error" },
    { 0x05, "Supply Voltage Too High Warning" },
    { 0x06, "Supply Voltage Too High Error" },
    { 0x07, "Power Supply Interrupted Warning" },
    { 0x08, "Power Supply Interrupted Error" },
    { 0x09, "No Load Warning" },
    { 0x0A, "No Load Error" },
    { 0x0B, "Overload Warning" },
    { 0x0C, "Overload Error" },
    { 0x0D, "Overheat Warning" },
    { 0x0E, "Overheat Error" },
    { 0x0F, "Condensation Warning" },
    { 0x10, "Condensation Error" },
    { 0x11, "Vibration Warning" },
    { 0x12, "Vibration Error" },
    { 0x13, "Configuration Warning" },
    { 0x14, "Configuration Error" },
    { 0x15, "Element Not Calibrated Warning" },
    { 0x16, "Element Not Calibrated Error" },
    { 0x17, "Memory Warning" },
    { 0x18, "Memory Error" },
    { 0x19, "Self-Test Warning" },
    { 0x1A, "Self-Test Error" },
    { 0x1B, "Input Too Low Warning" },
    { 0x1C, "Input Too Low Error" },
    { 0x1D, "Input Too High Warning" },
    { 0x1E, "Input Too High Error" },
    { 0x1F, "Input No Change Warning" },
    { 0x20, "Input No Change Error" },
    { 0x21, "Actuator Blocked Warning" },
    { 0x22, "Actuator Blocked Error" },
    { 0x23, "Housing Opened Warning" },
    { 0x24, "Housing Opened Error" },
    { 0x25, "Tamper Warning" },
    { 0x26, "Tamper Error" },
    { 0x27, "Device Moved Warning" },
    { 0x28, "Device Moved Error" },
    { 0x29, "Device Dropped Warning" },
    { 0x2A, "Device Dropped Error" },
    { 0x2B, "Overflow Warning" },
    { 0x2C, "Overflow Error" },
    { 0x2D, "Empty Warning" },
    { 0x2E, "Empty Error" },
    { 0x2F, "Internal Bus Warning" },
    { 0x30, "Internal Bus Error" },
    { 0x31, "Mechanism Jammed Warning" },
    { 0x32, "Mechanism Jammed Error" },
    { 0, NULL }
};

static const value_string btmesh_generic_onpowerup_vals[] = {
    { 0x00, "Off" },
    { 0x01, "Default" },
    { 0x02, "Restore" },
    { 0, NULL }
};

static const value_string btmesh_on_off_vals[] = {
    { 0x0, "Off" },
    { 0x1, "On" },
    { 0, NULL }
};

static const value_string btmesh_generic_battery_flags_presence_vals[] = {
    { 0x0, "The battery is not present." },
    { 0x1, "The battery is present and is removable." },
    { 0x2, "The battery is present and is non-removable." },
    { 0x3, "The battery presence is unknown." },
    { 0, NULL }
};

static const value_string btmesh_generic_battery_flags_indicator_vals[] = {
    { 0x0, "The battery charge is Critically Low Level." },
    { 0x1, "The battery charge is Low Level." },
    { 0x2, "The battery charge is Good Level." },
    { 0x3, "The battery charge is unknown." },
    { 0, NULL }
};

static const value_string btmesh_generic_battery_flags_charging_vals[] = {
    { 0x0, "The battery is not chargeable." },
    { 0x1, "The battery is chargeable and is not charging." },
    { 0x2, "The battery is chargeable and is charging." },
    { 0x3, "The battery charging state is unknown." },
    { 0, NULL }
};

static const value_string btmesh_generic_battery_flags_serviceability_vals[] = {
    { 0x0, "Reserved for Future Use" },
    { 0x1, "The battery does not require service." },
    { 0x2, "The battery requires service." },
    { 0x3, "The battery serviceability is unknown." },
    { 0, NULL }
};

static const value_string btmesh_generic_location_local_stationary_vals[] = {
    { 0x0, "Stationary" },
    { 0x1, "Mobile" },
    { 0, NULL }
};

static const value_string btmesh_yes_or_dash_vals[] = {
    { 0x0, "-" },
    { 0x1, "Scheduled" },
    { 0, NULL }
};

static const value_string btmesh_time_authority_vals[] = {
    { 0x0, "No Time Authority" },
    { 0x1, "Time Authority" },
    { 0, NULL }
};

static const value_string btmesh_time_role_vals[] = {
    { 0x0, "None" },
    { 0x1, "Mesh Time Authority" },
    { 0x2, "Mesh Time Relay" },
    { 0x3, "Mesh Time Client" },
    { 0, NULL }
};

static const value_string btmesh_defined_or_dash_vals[] = {
    { 0x0, "-" },
    { 0x1, "Defined" },
    { 0, NULL }
};

static int * const config_composition_data_status_features_headers[] = {
    &hf_btmesh_config_composition_data_status_features_relay,
    &hf_btmesh_config_composition_data_status_features_proxy,
    &hf_btmesh_config_composition_data_status_features_friend,
    &hf_btmesh_config_composition_data_status_features_low_power,
    &hf_btmesh_config_composition_data_status_features_rfu,
    NULL
};

static int * const config_heartbeat_publication_set_features_headers[] = {
    &hf_btmesh_config_heartbeat_publication_set_features_relay,
    &hf_btmesh_config_heartbeat_publication_set_features_proxy,
    &hf_btmesh_config_heartbeat_publication_set_features_friend,
    &hf_btmesh_config_heartbeat_publication_set_features_low_power,
    &hf_btmesh_config_heartbeat_publication_set_features_rfu,
    NULL
};

static int * const config_heartbeat_publication_status_features_headers[] = {
    &hf_btmesh_config_heartbeat_publication_status_features_relay,
    &hf_btmesh_config_heartbeat_publication_status_features_proxy,
    &hf_btmesh_config_heartbeat_publication_status_features_friend,
    &hf_btmesh_config_heartbeat_publication_status_features_low_power,
    &hf_btmesh_config_heartbeat_publication_status_features_rfu,
    NULL
};

static const fragment_items btmesh_segmented_access_frag_items = {
    &ett_btmesh_segmented_access_fragments,
    &ett_btmesh_segmented_access_fragment,

    &hf_btmesh_segmented_access_fragments,
    &hf_btmesh_segmented_access_fragment,
    &hf_btmesh_segmented_access_fragment_overlap,
    &hf_btmesh_segmented_access_fragment_overlap_conflict,
    &hf_btmesh_segmented_access_fragment_multiple_tails,
    &hf_btmesh_segmented_access_fragment_too_long_fragment,
    &hf_btmesh_segmented_access_fragment_error,
    &hf_btmesh_segmented_access_fragment_count,
    NULL,
    &hf_btmesh_segmented_access_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

static const fragment_items btmesh_segmented_control_frag_items = {
    &ett_btmesh_segmented_control_fragments,
    &ett_btmesh_segmented_control_fragment,

    &hf_btmesh_segmented_control_fragments,
    &hf_btmesh_segmented_control_fragment,
    &hf_btmesh_segmented_control_fragment_overlap,
    &hf_btmesh_segmented_control_fragment_overlap_conflict,
    &hf_btmesh_segmented_control_fragment_multiple_tails,
    &hf_btmesh_segmented_control_fragment_too_long_fragment,
    &hf_btmesh_segmented_control_fragment_error,
    &hf_btmesh_segmented_control_fragment_count,
    NULL,
    &hf_btmesh_segmented_control_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

static const value_string btmesh_status_code_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Invalid Address" },
    { 0x02, "Invalid Model" },
    { 0x03, "Invalid AppKey Index" },
    { 0x04, "Invalid NetKey Index" },
    { 0x05, "Insufficient Resources" },
    { 0x06, "Key Index Already Stored" },
    { 0x07, "Invalid Publish Parameters" },
    { 0x08, "Not a Subscribe Model" },
    { 0x09, "Storage Failure" },
    { 0x0A, "Feature Not Supported" },
    { 0x0B, "Cannot Update" },
    { 0x0C, "Cannot Remove" },
    { 0x0D, "Cannot Bind" },
    { 0x0E, "Temporarily Unable to Change State" },
    { 0x0F, "Cannot Set" },
    { 0x10, "Unspecified Error" },
    { 0x11, "Invalid Binding" },
    { 0, NULL }
};

static const value_string btmesh_generic_status_code_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Cannot Set Range Min" },
    { 0x02, "Cannot Set Range Max" },
    { 0, NULL }
};

static const value_string btmesh_scene_status_code_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Scene Register Full" },
    { 0x02, "Scene Not Found" },
    { 0, NULL }
};

static const value_string btmesh_sensor_sampling_function_vals[] = {
    { 0x00, "Unspecified" },
    { 0x01, "Instantaneous" },
    { 0x02, "Arithmetic Mean" },
    { 0x03, "RMS" },
    { 0x04, "Maximum" },
    { 0x05, "Minimum" },
    { 0x06, "Accumulated" },
    { 0x07, "Count" },
    { 0, NULL }
};

static const value_string btmesh_status_trigger_type_vals[] = {
    { 0x00, "same format as property" },
    { 0x01, "unitless" },
    { 0, NULL }
};

static const value_string btmesh_mpid_format_vals[] = {
    { 0x00, "Format A" },
    { 0x01, "Format B" },
    { 0, NULL }
};

static const value_string btmesh_model_vals[] = {
    { 0x0000, "Configuration Server" },
    { 0x0001, "Configuration Client" },
    { 0x0002, "Health Server" },
    { 0x0003, "Health Client" },
    { 0x1000, "Generic OnOff Server" },
    { 0x1001, "Generic OnOff Client" },
    { 0x1002, "Generic Level Server" },
    { 0x1003, "Generic Level Client" },
    { 0x1004, "Generic Default Transition Time Server" },
    { 0x1005, "Generic Default Transition Time Client" },
    { 0x1006, "Generic Power OnOff Server" },
    { 0x1007, "Generic Power OnOff Setup Server" },
    { 0x1008, "Generic Power OnOff Client" },
    { 0x1009, "Generic Power Level Server" },
    { 0x100A, "Generic Power Level Setup Server" },
    { 0x100B, "Generic Power Level Client" },
    { 0x100C, "Generic Battery Server" },
    { 0x100D, "Generic Battery Client" },
    { 0x100E, "Generic Location Server" },
    { 0x100F, "Generic Location Setup Server" },
    { 0x1010, "Generic Location Client" },
    { 0x1011, "Generic Admin Property Server" },
    { 0x1012, "Generic Manufacturer Property Server" },
    { 0x1013, "Generic User Property Server" },
    { 0x1014, "Generic Client Property Server" },
    { 0x1015, "Generic Property Client" },
    { 0x1100, "Sensors Sensor Server" },
    { 0x1101, "Sensor Setup Server" },
    { 0x1102, "Sensor Client" },
    { 0x1200, "Time Server" },
    { 0x1201, "Time Setup Server" },
    { 0x1202, "Time Client" },
    { 0x1203, "Scene Server" },
    { 0x1204, "Scene Setup Server" },
    { 0x1205, "Scene Client" },
    { 0x1206, "Scheduler Server" },
    { 0x1207, "Scheduler Setup Server" },
    { 0x1208, "Scheduler Client" },
    { 0x1300, "Light Lightness Server" },
    { 0x1301, "Light Lightness Setup Server" },
    { 0x1302, "Light Lightness Client" },
    { 0x1303, "Light CTL Server" },
    { 0x1304, "Light CTL Setup Server" },
    { 0x1305, "Light CTL Client" },
    { 0x1306, "Light CTL Temperature Server" },
    { 0x1307, "Light HSL Server" },
    { 0x1308, "Light HSL Setup Server" },
    { 0x1309, "Light HSL Client" },
    { 0x130A, "Light HSL Hue Server" },
    { 0x130B, "Light HSL Saturation Server" },
    { 0x130C, "Light xyL Server" },
    { 0x130D, "Light xyL Setup Server" },
    { 0x130E, "Light xyL Client" },
    { 0x130F, "Light LC Server" },
    { 0x1310, "Light LC Setup Server" },
    { 0x1311, "Light LC Client" },
    { 0, NULL }
};

static const value_string btmesh_properties_vals[] = {
    { PHONY_PROPERTY_PERCENTAGE_CHANGE_16                              , "Percentage Change"                                        },
    { PHONY_PROPERTY_INDEX                                             , "Index"                                                    },
    { PROPERTY_AVERAGE_AMBIENT_TEMPERATURE_IN_A_PERIOD_OF_DAY          , "Average Ambient Temperature In A Period Of Day"           },
    { PROPERTY_AVERAGE_INPUT_CURRENT                                   , "Average Input Current"                                    },
    { PROPERTY_AVERAGE_INPUT_VOLTAGE                                   , "Average Input Voltage"                                    },
    { PROPERTY_AVERAGE_OUTPUT_CURRENT                                  , "Average Output Current"                                   },
    { PROPERTY_AVERAGE_OUTPUT_VOLTAGE                                  , "Average Output Voltage"                                   },
    { PROPERTY_CENTER_BEAM_INTENSITY_AT_FULL_POWER                     , "Center Beam Intensity At Full Power"                      },
    { PROPERTY_CHROMATICITY_TOLERANCE                                  , "Chromaticity Tolerance"                                   },
    { PROPERTY_COLOR_RENDERING_INDEX_R9                                , "Color Rendering Index R9"                                 },
    { PROPERTY_COLOR_RENDERING_INDEX_RA                                , "Color Rendering Index Ra"                                 },
    { PROPERTY_DEVICE_APPEARANCE                                       , "Device Appearance"                                        },
    { PROPERTY_DEVICE_COUNTRY_OF_ORIGIN                                , "Device Country Of Origin"                                 },
    { PROPERTY_DEVICE_DATE_OF_MANUFACTURE                              , "Device Date Of Manufacture"                               },
    { PROPERTY_DEVICE_ENERGY_USE_SINCE_TURN_ON                         , "Device Energy Use Since Turn On"                          },
    { PROPERTY_DEVICE_FIRMWARE_REVISION                                , "Device Firmware Revision"                                 },
    { PROPERTY_DEVICE_GLOBAL_TRADE_ITEM_NUMBER                         , "Device Global Trade Item Number"                          },
    { PROPERTY_DEVICE_HARDWARE_REVISION                                , "Device Hardware Revision"                                 },
    { PROPERTY_DEVICE_MANUFACTURER_NAME                                , "Device Manufacturer Name"                                 },
    { PROPERTY_DEVICE_MODEL_NUMBER                                     , "Device Model Number"                                      },
    { PROPERTY_DEVICE_OPERATING_TEMPERATURE_RANGE_SPECIFICATION        , "Device Operating Temperature Range Specification"         },
    { PROPERTY_DEVICE_OPERATING_TEMPERATURE_STATISTICAL_VALUES         , "Device Operating Temperature Statistical Values"          },
    { PROPERTY_DEVICE_OVER_TEMPERATURE_EVENT_STATISTICS                , "Device Over Temperature Event Statistics"                 },
    { PROPERTY_DEVICE_POWER_RANGE_SPECIFICATION                        , "Device Power Range Specification"                         },
    { PROPERTY_DEVICE_RUNTIME_SINCE_TURN_ON                            , "Device Runtime Since Turn On"                             },
    { PROPERTY_DEVICE_RUNTIME_WARRANTY                                 , "Device Runtime Warranty"                                  },
    { PROPERTY_DEVICE_SERIAL_NUMBER                                    , "Device Serial Number"                                     },
    { PROPERTY_DEVICE_SOFTWARE_REVISION                                , "Device Software Revision"                                 },
    { PROPERTY_DEVICE_UNDER_TEMPERATURE_EVENT_STATISTICS               , "Device Under Temperature Event Statistics"                },
    { PROPERTY_INDOOR_AMBIENT_TEMPERATURE_STATISTICAL_VALUES           , "Indoor Ambient Temperature Statistical Values"            },
    { PROPERTY_INITIAL_CIE_1931_CHROMATICITY_COORDINATES               , "Initial CIE 1931 Chromaticity Coordinates"                },
    { PROPERTY_INITIAL_CORRELATED_COLOR_TEMPERATURE                    , "Initial Correlated Color Temperature"                     },
    { PROPERTY_INITIAL_LUMINOUS_FLUX                                   , "Initial Luminous Flux"                                    },
    { PROPERTY_INITIAL_PLANCKIAN_DISTANCE                              , "Initial Planckian Distance"                               },
    { PROPERTY_INPUT_CURRENT_RANGE_SPECIFICATION                       , "Input Current Range Specification"                        },
    { PROPERTY_INPUT_CURRENT_STATISTICS                                , "Input Current Statistics"                                 },
    { PROPERTY_INPUT_OVER_CURRENT_EVENT_STATISTICS                     , "Input Over Current Event Statistics"                      },
    { PROPERTY_INPUT_OVER_RIPPLE_VOLTAGE_EVENT_STATISTICS              , "Input Over Ripple Voltage Event Statistics"               },
    { PROPERTY_INPUT_OVER_VOLTAGE_EVENT_STATISTICS                     , "Input Over Voltage Event Statistics"                      },
    { PROPERTY_INPUT_UNDER_CURRENT_EVENT_STATISTICS                    , "Input Under Current Event Statistics"                     },
    { PROPERTY_INPUT_UNDER_VOLTAGE_EVENT_STATISTICS                    , "Input Under Voltage Event Statistics"                     },
    { PROPERTY_INPUT_VOLTAGE_RANGE_SPECIFICATION                       , "Input Voltage Range Specification"                        },
    { PROPERTY_INPUT_VOLTAGE_RIPPLE_SPECIFICATION                      , "Input Voltage Ripple Specification"                       },
    { PROPERTY_INPUT_VOLTAGE_STATISTICS                                , "Input Voltage Statistics"                                 },
    { PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_ON                      , "Light Control Ambient LuxLevel On"                        },
    { PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_PROLONG                 , "Light Control Ambient LuxLevel Prolong"                   },
    { PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_STANDBY                 , "Light Control Ambient LuxLevel Standby"                   },
    { PROPERTY_LIGHT_CONTROL_LIGHTNESS_ON                              , "Light Control Lightness On"                               },
    { PROPERTY_LIGHT_CONTROL_LIGHTNESS_PROLONG                         , "Light Control Lightness Prolong"                          },
    { PROPERTY_LIGHT_CONTROL_LIGHTNESS_STANDBY                         , "Light Control Lightness Standby"                          },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_ACCURACY                        , "Light Control Regulator Accuracy"                         },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KID                             , "Light Control Regulator Kid"                              },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KIU                             , "Light Control Regulator Kiu"                              },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KPD                             , "Light Control Regulator Kpd"                              },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KPU                             , "Light Control Regulator Kpu"                              },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE                                 , "Light Control Time Fade"                                  },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE_ON                              , "Light Control Time Fade On"                               },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE_STANDBY_AUTO                    , "Light Control Time Fade Standby Auto"                     },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE_STANDBY_MANUAL                  , "Light Control Time Fade Standby Manual"                   },
    { PROPERTY_LIGHT_CONTROL_TIME_OCCUPANCY_DELAY                      , "Light Control Time Occupancy Delay"                       },
    { PROPERTY_LIGHT_CONTROL_TIME_PROLONG                              , "Light Control Time Prolong"                               },
    { PROPERTY_LIGHT_CONTROL_TIME_RUN_ON                               , "Light Control Time Run On"                                },
    { PROPERTY_LUMEN_MAINTENANCE_FACTOR                                , "Lumen Maintenance Factor"                                 },
    { PROPERTY_LUMINOUS_EFFICACY                                       , "Luminous Efficacy"                                        },
    { PROPERTY_LUMINOUS_ENERGY_SINCE_TURN_ON                           , "Luminous Energy Since Turn On"                            },
    { PROPERTY_LUMINOUS_EXPOSURE                                       , "Luminous Exposure"                                        },
    { PROPERTY_LUMINOUS_FLUX_RANGE                                     , "Luminous Flux Range"                                      },
    { PROPERTY_MOTION_SENSED                                           , "Motion Sensed"                                            },
    { PROPERTY_MOTION_THRESHOLD                                        , "Motion Threshold"                                         },
    { PROPERTY_OPEN_CIRCUIT_EVENT_STATISTICS                           , "Open Circuit Event Statistics"                            },
    { PROPERTY_OUTDOOR_STATISTICAL_VALUES                              , "Outdoor Statistical Values"                               },
    { PROPERTY_OUTPUT_CURRENT_RANGE                                    , "Output Current Range"                                     },
    { PROPERTY_OUTPUT_CURRENT_STATISTICS                               , "Output Current Statistics"                                },
    { PROPERTY_OUTPUT_RIPPLE_VOLTAGE_SPECIFICATION                     , "Output Ripple Voltage Specification"                      },
    { PROPERTY_OUTPUT_VOLTAGE_RANGE                                    , "Output Voltage Range"                                     },
    { PROPERTY_OUTPUT_VOLTAGE_STATISTICS                               , "Output Voltage Statistics"                                },
    { PROPERTY_OVER_OUTPUT_RIPPLE_VOLTAGE_EVENT_STATISTICS             , "Over Output Ripple Voltage Event Statistics"              },
    { PROPERTY_PEOPLE_COUNT                                            , "People Count"                                             },
    { PROPERTY_PRESENCE_DETECTED                                       , "Presence Detected"                                        },
    { PROPERTY_PRESENT_AMBIENT_LIGHT_LEVEL                             , "Present Ambient Light Level"                              },
    { PROPERTY_PRESENT_AMBIENT_TEMPERATURE                             , "Present Ambient Temperature"                              },
    { PROPERTY_PRESENT_CIE_1931_CHROMATICITY_COORDINATES               , "Present CIE 1931 Chromaticity Coordinates"                },
    { PROPERTY_PRESENT_CORRELATED_COLOR_TEMPERATURE                    , "Present Correlated Color Temperature"                     },
    { PROPERTY_PRESENT_DEVICE_INPUT_POWER                              , "Present Device Input Power"                               },
    { PROPERTY_PRESENT_DEVICE_OPERATING_EFFICIENCY                     , "Present Device Operating Efficiency"                      },
    { PROPERTY_PRESENT_DEVICE_OPERATING_TEMPERATURE                    , "Present Device Operating Temperature"                     },
    { PROPERTY_PRESENT_ILLUMINANCE                                     , "Present Illuminance"                                      },
    { PROPERTY_PRESENT_INDOOR_AMBIENT_TEMPERATURE                      , "Present Indoor Ambient Temperature"                       },
    { PROPERTY_PRESENT_INPUT_CURRENT                                   , "Present Input Current"                                    },
    { PROPERTY_PRESENT_INPUT_RIPPLE_VOLTAGE                            , "Present Input Ripple Voltage"                             },
    { PROPERTY_PRESENT_INPUT_VOLTAGE                                   , "Present Input Voltage"                                    },
    { PROPERTY_PRESENT_LUMINOUS_FLUX                                   , "Present Luminous Flux"                                    },
    { PROPERTY_PRESENT_OUTDOOR_AMBIENT_TEMPERATURE                     , "Present Outdoor Ambient Temperature"                      },
    { PROPERTY_PRESENT_OUTPUT_CURRENT                                  , "Present Output Current"                                   },
    { PROPERTY_PRESENT_OUTPUT_VOLTAGE                                  , "Present Output Voltage"                                   },
    { PROPERTY_PRESENT_PLANCKIAN_DISTANCE                              , "Present Planckian Distance"                               },
    { PROPERTY_PRESENT_RELATIVE_OUTPUT_RIPPLE_VOLTAGE                  , "Present Relative Output Ripple Voltage"                   },
    { PROPERTY_RELATIVE_DEVICE_ENERGY_USE_IN_A_PERIOD_OF_DAY           , "Relative Device Energy Use In A Period Of Day"            },
    { PROPERTY_RELATIVE_DEVICE_RUNTIME_IN_A_GENERIC_LEVEL_RANGE        , "Relative Device Runtime In A Generic Level Range"         },
    { PROPERTY_RELATIVE_EXPOSURE_TIME_IN_AN_ILLUMINANCE_RANGE          , "Relative Exposure Time In An Illuminance Range"           },
    { PROPERTY_RELATIVE_RUNTIME_IN_A_CORRELATED_COLOR_TEMPERATURE_RANGE, "Relative Runtime In A Correlated Color Temperature Range" },
    { PROPERTY_RELATIVE_RUNTIME_IN_A_DEVICE_OPERATING_TEMPERATURE_RANGE, "Relative Runtime In A Device Operating Temperature Range" },
    { PROPERTY_RELATIVE_RUNTIME_IN_AN_INPUT_CURRENT_RANGE              , "Relative Runtime In An Input Current Range"               },
    { PROPERTY_RELATIVE_RUNTIME_IN_AN_INPUT_VOLTAGE_RANGE              , "Relative Runtime In An Input Voltage Range"               },
    { PROPERTY_SHORT_CIRCUIT_EVENT_STATISTICS                          , "Short Circuit Event Statistics"                           },
    { PROPERTY_TIME_SINCE_MOTION_SENSED                                , "Time Since Motion Sensed"                                 },
    { PROPERTY_TIME_SINCE_PRESENCE_DETECTED                            , "Time Since Presence Detected"                             },
    { PROPERTY_TOTAL_DEVICE_ENERGY_USE                                 , "Total Device Energy Use"                                  },
    { PROPERTY_TOTAL_DEVICE_OFF_ON_CYCLES                              , "Total Device Off On Cycles"                               },
    { PROPERTY_TOTAL_DEVICE_POWER_ON_CYCLES                            , "Total Device Power On Cycles"                             },
    { PROPERTY_TOTAL_DEVICE_POWER_ON_TIME                              , "Total Device Power On Time"                               },
    { PROPERTY_TOTAL_DEVICE_RUNTIME                                    , "Total Device Runtime"                                     },
    { PROPERTY_TOTAL_LIGHT_EXPOSURE_TIME                               , "Total Light Exposure Time"                                },
    { PROPERTY_TOTAL_LUMINOUS_ENERGY                                   , "Total Luminous Energy"                                    },
    { PROPERTY_DESIRED_AMBIENT_TEMPERATURE                             , "Desired Ambient Temperature"                              },
    { PROPERTY_PRECISE_TOTAL_DEVICE_ENERGY_USE                         , "Precise Total Device Energy Use"                          },
    { PROPERTY_POWER_FACTOR                                            , "Power Factor"                                             },
    { PROPERTY_SENSOR_GAIN                                             , "Sensor Gain"                                              },
    { PROPERTY_PRECISE_PRESENT_AMBIENT_TEMPERATURE                     , "Precise Present Ambient Temperature"                      },
    { PROPERTY_PRESENT_AMBIENT_RELATIVE_HUMIDITY                       , "Present Ambient Relative Humidity"                        },
    { PROPERTY_PRESENT_AMBIENT_CARBON_DIOXIDE_CONCENTRATION            , "Present Ambient Carbon Dioxide Concentration"             },
    { PROPERTY_PRESENT_AMBIENT_VOLATILE_ORGANIC_COMPOUNDS_CONCENTRATION, "Present Ambient Volatile Organic Compounds Concentration" },
    { PROPERTY_PRESENT_AMBIENT_NOISE                                   , "Present Ambient Noise"                                    },
    { PROPERTY_ACTIVE_ENERGY_LOADSIDE                                  , "Active Energy Loadside"                                   },
    { PROPERTY_ACTIVE_POWER_LOADSIDE                                   , "Active Power Loadside"                                    },
    { PROPERTY_AIR_PRESSURE                                            , "Air Pressure"                                             },
    { PROPERTY_APPARENT_ENERGY                                         , "Apparent Energy"                                          },
    { PROPERTY_APPARENT_POWER                                          , "Apparent Power"                                           },
    { PROPERTY_APPARENT_WIND_DIRECTION                                 , "Apparent Wind Direction"                                  },
    { PROPERTY_APPARENT_WIND_SPEED                                     , "Apparent Wind Speed"                                      },
    { PROPERTY_DEW_POINT                                               , "Dew Point"                                                },
    { PROPERTY_EXTERNAL_SUPPLY_VOLTAGE                                 , "External Supply Voltage"                                  },
    { PROPERTY_EXTERNAL_SUPPLY_VOLTAGE_FREQUENCY                       , "External Supply Voltage Frequency"                        },
    { PROPERTY_GUST_FACTOR                                             , "Gust Factor"                                              },
    { PROPERTY_HEAT_INDEX                                              , "Heat Index"                                               },
    { PROPERTY_LIGHT_DISTRIBUTION                                      , "Light Distribution"                                       },
    { PROPERTY_LIGHT_SOURCE_CURRENT                                    , "Light Source Current"                                     },
    { PROPERTY_LIGHT_SOURCE_ON_TIME_NOT_RESETTABLE                     , "Light Source On Time Not Resettable"                      },
    { PROPERTY_LIGHT_SOURCE_ON_TIME_RESETTABLE                         , "Light Source On Time Resettable"                          },
    { PROPERTY_LIGHT_SOURCE_OPEN_CIRCUIT_STATISTICS                    , "Light Source Open Circuit Statistics"                     },
    { PROPERTY_LIGHT_SOURCE_OVERALL_FAILURES_STATISTICS                , "Light Source Overall Failures Statistics"                 },
    { PROPERTY_LIGHT_SOURCE_SHORT_CIRCUIT_STATISTICS                   , "Light Source Short Circuit Statistics"                    },
    { PROPERTY_LIGHT_SOURCE_START_COUNTER_RESETTABLE                   , "Light Source Start Counter Resettable"                    },
    { PROPERTY_LIGHT_SOURCE_TEMPERATURE                                , "Light Source Temperature"                                 },
    { PROPERTY_LIGHT_SOURCE_THERMAL_DERATING_STATISTICS                , "Light Source Thermal Derating Statistics"                 },
    { PROPERTY_LIGHT_SOURCE_THERMAL_SHUTDOWN_STATISTICS                , "Light Source Thermal Shutdown Statistics"                 },
    { PROPERTY_LIGHT_SOURCE_TOTAL_POWER_ON_CYCLES                      , "Light Source Total Power On Cycles"                       },
    { PROPERTY_LIGHT_SOURCE_VOLTAGE                                    , "Light Source Voltage"                                     },
    { PROPERTY_LUMINAIRE_COLOR                                         , "Luminaire Color"                                          },
    { PROPERTY_LUMINAIRE_IDENTIFICATION_NUMBER                         , "Luminaire Identification Number"                          },
    { PROPERTY_LUMINAIRE_MANUFACTURER_GTIN                             , "Luminaire Manufacturer GTIN"                              },
    { PROPERTY_LUMINAIRE_NOMINAL_INPUT_POWER                           , "Luminaire Nominal Input Power"                            },
    { PROPERTY_LUMINAIRE_NOMINAL_MAXIMUM_AC_MAINS_VOLTAGE              , "Luminaire Nominal Maximum AC Mains Voltage"               },
    { PROPERTY_LUMINAIRE_NOMINAL_MINIMUM_AC_MAINS_VOLTAGE              , "Luminaire Nominal Minimum AC Mains Voltage"               },
    { PROPERTY_LUMINAIRE_POWER_AT_MINIMUM_DIM_LEVEL                    , "Luminaire Power At Minimum Dim Level"                     },
    { PROPERTY_LUMINAIRE_TIME_OF_MANUFACTURE                           , "Luminaire Time Of Manufacture"                            },
    { PROPERTY_MAGNETIC_DECLINATION                                    , "Magnetic Declination"                                     },
    { PROPERTY_MAGNETIC_FLUX_DENSITY_2_D                               , "Magnetic Flux Density - 2D"                               },
    { PROPERTY_MAGNETIC_FLUX_DENSITY_3_D                               , "Magnetic Flux Density - 3D"                               },
    { PROPERTY_NOMINAL_LIGHT_OUTPUT                                    , "Nominal Light Output"                                     },
    { PROPERTY_OVERALL_FAILURE_CONDITION                               , "Overall Failure Condition"                                },
    { PROPERTY_POLLEN_CONCENTRATION                                    , "Pollen Concentration"                                     },
    { PROPERTY_PRESENT_INDOOR_RELATIVE_HUMIDITY                        , "Present Indoor Relative Humidity"                         },
    { PROPERTY_PRESENT_OUTDOOR_RELATIVE_HUMIDITY                       , "Present Outdoor Relative Humidity"                        },
    { PROPERTY_PRESSURE                                                , "Pressure"                                                 },
    { PROPERTY_RAINFALL                                                , "Rainfall"                                                 },
    { PROPERTY_RATED_MEDIAN_USEFUL_LIFE_OF_LUMINAIRE                   , "Rated Median Useful Life Of Luminaire"                    },
    { PROPERTY_RATED_MEDIAN_USEFUL_LIGHT_SOURCE_STARTS                 , "Rated Median Useful Light Source Starts"                  },
    { PROPERTY_REFERENCE_TEMPERATURE                                   , "Reference Temperature"                                    },
    { PROPERTY_TOTAL_DEVICE_STARTS                                     , "Total Device Starts"                                      },
    { PROPERTY_TRUE_WIND_DIRECTION                                     , "True Wind Direction"                                      },
    { PROPERTY_TRUE_WIND_SPEED                                         , "True Wind Speed"                                          },
    { PROPERTY_UV_INDEX                                                , "UV Index"                                                 },
    { PROPERTY_WIND_CHILL                                              , "Wind Chill"                                               },
    { PROPERTY_LIGHT_SOURCE_TYPE                                       , "Light Source Type"                                        },
    { PROPERTY_LUMINAIRE_IDENTIFICATION_STRING                         , "Luminaire Identification String"                          },
    { PROPERTY_OUTPUT_POWER_LIMITATION                                 , "Output Power Limitation"                                  },
    { PROPERTY_THERMAL_DERATING                                        , "Thermal Derating"                                         },
    { PROPERTY_OUTPUT_CURRENT_PERCENT                                  , "Output Current Percent"                                   },
    { 0, NULL }
};

static const btmesh_property_t btmesh_properties[] = {
    { PHONY_PROPERTY_PERCENTAGE_CHANGE_16                              , PHONY_CHARACTERISTIC_PERCENTAGE_CHANGE_16                },
    { PHONY_PROPERTY_INDEX                                             , PHONY_CHARACTERISTIC_INDEX                               },
    { PROPERTY_ACTIVE_ENERGY_LOADSIDE                                  , CHARACTERISTIC_ENERGY32                                  },
    { PROPERTY_ACTIVE_POWER_LOADSIDE                                   , CHARACTERISTIC_POWER                                     },
    { PROPERTY_AIR_PRESSURE                                            , CHARACTERISTIC_PRESSURE                                  },
    { PROPERTY_APPARENT_ENERGY                                         , CHARACTERISTIC_APPARENT_ENERGY32                         },
    { PROPERTY_APPARENT_POWER                                          , CHARACTERISTIC_APPARENT_POWER                            },
    { PROPERTY_APPARENT_WIND_DIRECTION                                 , CHARACTERISTIC_APPARENT_WIND_DIRECTION                   },
    { PROPERTY_APPARENT_WIND_SPEED                                     , CHARACTERISTIC_APPARENT_WIND_SPEED                       },
    { PROPERTY_AVERAGE_AMBIENT_TEMPERATURE_IN_A_PERIOD_OF_DAY          , CHARACTERISTIC_TEMPERATURE_8_IN_A_PERIOD_OF_DAY          },
    { PROPERTY_AVERAGE_INPUT_CURRENT                                   , CHARACTERISTIC_AVERAGE_CURRENT                           },
    { PROPERTY_AVERAGE_INPUT_VOLTAGE                                   , CHARACTERISTIC_AVERAGE_VOLTAGE                           },
    { PROPERTY_AVERAGE_OUTPUT_CURRENT                                  , CHARACTERISTIC_AVERAGE_CURRENT                           },
    { PROPERTY_AVERAGE_OUTPUT_VOLTAGE                                  , CHARACTERISTIC_AVERAGE_VOLTAGE                           },
    { PROPERTY_CENTER_BEAM_INTENSITY_AT_FULL_POWER                     , CHARACTERISTIC_LUMINOUS_INTENSITY                        },
    { PROPERTY_CHROMATICITY_TOLERANCE                                  , CHARACTERISTIC_CHROMATICITY_TOLERANCE                    },
    { PROPERTY_COLOR_RENDERING_INDEX_R9                                , CHARACTERISTIC_CIE_13_3_1995_COLOR_RENDERING_INDEX       },
    { PROPERTY_COLOR_RENDERING_INDEX_RA                                , CHARACTERISTIC_CIE_13_3_1995_COLOR_RENDERING_INDEX       },
    { PROPERTY_DESIRED_AMBIENT_TEMPERATURE                             , CHARACTERISTIC_TEMPERATURE_8                             },
    { PROPERTY_DEVICE_APPEARANCE                                       , CHARACTERISTIC_APPEARANCE                                },
    { PROPERTY_DEVICE_COUNTRY_OF_ORIGIN                                , CHARACTERISTIC_COUNTRY_CODE                              },
    { PROPERTY_DEVICE_DATE_OF_MANUFACTURE                              , CHARACTERISTIC_DATE_UTC                                  },
    { PROPERTY_DEVICE_ENERGY_USE_SINCE_TURN_ON                         , CHARACTERISTIC_ENERGY                                    },
    { PROPERTY_DEVICE_FIRMWARE_REVISION                                , CHARACTERISTIC_FIXED_STRING_8                            },
    { PROPERTY_DEVICE_GLOBAL_TRADE_ITEM_NUMBER                         , CHARACTERISTIC_GLOBAL_TRADE_ITEM_NUMBER                  },
    { PROPERTY_DEVICE_HARDWARE_REVISION                                , CHARACTERISTIC_FIXED_STRING_16                           },
    { PROPERTY_DEVICE_MANUFACTURER_NAME                                , CHARACTERISTIC_FIXED_STRING_36                           },
    { PROPERTY_DEVICE_MODEL_NUMBER                                     , CHARACTERISTIC_FIXED_STRING_24                           },
    { PROPERTY_DEVICE_OPERATING_TEMPERATURE_RANGE_SPECIFICATION        , CHARACTERISTIC_TEMPERATURE_RANGE                         },
    { PROPERTY_DEVICE_OPERATING_TEMPERATURE_STATISTICAL_VALUES         , CHARACTERISTIC_TEMPERATURE_STATISTICS                    },
    { PROPERTY_DEVICE_OVER_TEMPERATURE_EVENT_STATISTICS                , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_DEVICE_POWER_RANGE_SPECIFICATION                        , CHARACTERISTIC_POWER_SPECIFICATION                       },
    { PROPERTY_DEVICE_RUNTIME_SINCE_TURN_ON                            , CHARACTERISTIC_TIME_HOUR_24                              },
    { PROPERTY_DEVICE_RUNTIME_WARRANTY                                 , CHARACTERISTIC_TIME_HOUR_24                              },
    { PROPERTY_DEVICE_SERIAL_NUMBER                                    , CHARACTERISTIC_FIXED_STRING_16                           },
    { PROPERTY_DEVICE_SOFTWARE_REVISION                                , CHARACTERISTIC_FIXED_STRING_8                            },
    { PROPERTY_DEVICE_UNDER_TEMPERATURE_EVENT_STATISTICS               , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_DEW_POINT                                               , CHARACTERISTIC_DEW_POINT                                 },
    { PROPERTY_EXTERNAL_SUPPLY_VOLTAGE                                 , CHARACTERISTIC_HIGH_VOLTAGE                              },
    { PROPERTY_EXTERNAL_SUPPLY_VOLTAGE_FREQUENCY                       , CHARACTERISTIC_VOLTAGE_FREQUENCY                         },
    { PROPERTY_GUST_FACTOR                                             , CHARACTERISTIC_GUST_FACTOR                               },
    { PROPERTY_HEAT_INDEX                                              , CHARACTERISTIC_HEAT_INDEX                                },
    { PROPERTY_INDOOR_AMBIENT_TEMPERATURE_STATISTICAL_VALUES           , CHARACTERISTIC_TEMPERATURE_8_STATISTICS                  },
    { PROPERTY_INITIAL_CIE_1931_CHROMATICITY_COORDINATES               , CHARACTERISTIC_CHROMATICITY_COORDINATES                  },
    { PROPERTY_INITIAL_CORRELATED_COLOR_TEMPERATURE                    , CHARACTERISTIC_CORRELATED_COLOR_TEMPERATURE              },
    { PROPERTY_INITIAL_LUMINOUS_FLUX                                   , CHARACTERISTIC_LUMINOUS_FLUX                             },
    { PROPERTY_INITIAL_PLANCKIAN_DISTANCE                              , CHARACTERISTIC_CHROMATIC_DISTANCE_FROM_PLANCKIAN         },
    { PROPERTY_INPUT_CURRENT_RANGE_SPECIFICATION                       , CHARACTERISTIC_ELECTRIC_CURRENT_SPECIFICATION            },
    { PROPERTY_INPUT_CURRENT_STATISTICS                                , CHARACTERISTIC_ELECTRIC_CURRENT_STATISTICS               },
    { PROPERTY_INPUT_OVER_CURRENT_EVENT_STATISTICS                     , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_INPUT_OVER_RIPPLE_VOLTAGE_EVENT_STATISTICS              , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_INPUT_OVER_VOLTAGE_EVENT_STATISTICS                     , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_INPUT_UNDER_CURRENT_EVENT_STATISTICS                    , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_INPUT_UNDER_VOLTAGE_EVENT_STATISTICS                    , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_INPUT_VOLTAGE_RANGE_SPECIFICATION                       , CHARACTERISTIC_VOLTAGE_SPECIFICATION                     },
    { PROPERTY_INPUT_VOLTAGE_RIPPLE_SPECIFICATION                      , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_INPUT_VOLTAGE_STATISTICS                                , CHARACTERISTIC_VOLTAGE_STATISTICS                        },
    { PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_ON                      , CHARACTERISTIC_ILLUMINANCE                               },
    { PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_PROLONG                 , CHARACTERISTIC_ILLUMINANCE                               },
    { PROPERTY_LIGHT_CONTROL_AMBIENT_LUX_LEVEL_STANDBY                 , CHARACTERISTIC_ILLUMINANCE                               },
    { PROPERTY_LIGHT_CONTROL_LIGHTNESS_ON                              , CHARACTERISTIC_PERCEIVED_LIGHTNESS                       },
    { PROPERTY_LIGHT_CONTROL_LIGHTNESS_PROLONG                         , CHARACTERISTIC_PERCEIVED_LIGHTNESS                       },
    { PROPERTY_LIGHT_CONTROL_LIGHTNESS_STANDBY                         , CHARACTERISTIC_PERCEIVED_LIGHTNESS                       },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_ACCURACY                        , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KID                             , CHARACTERISTIC_COEFFICIENT                               },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KIU                             , CHARACTERISTIC_COEFFICIENT                               },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KPD                             , CHARACTERISTIC_COEFFICIENT                               },
    { PROPERTY_LIGHT_CONTROL_REGULATOR_KPU                             , CHARACTERISTIC_COEFFICIENT                               },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE                                 , CHARACTERISTIC_TIME_MILLISECOND_24                       },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE_ON                              , CHARACTERISTIC_TIME_MILLISECOND_24                       },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE_STANDBY_AUTO                    , CHARACTERISTIC_TIME_MILLISECOND_24                       },
    { PROPERTY_LIGHT_CONTROL_TIME_FADE_STANDBY_MANUAL                  , CHARACTERISTIC_TIME_MILLISECOND_24                       },
    { PROPERTY_LIGHT_CONTROL_TIME_OCCUPANCY_DELAY                      , CHARACTERISTIC_TIME_MILLISECOND_24                       },
    { PROPERTY_LIGHT_CONTROL_TIME_PROLONG                              , CHARACTERISTIC_TIME_MILLISECOND_24                       },
    { PROPERTY_LIGHT_CONTROL_TIME_RUN_ON                               , CHARACTERISTIC_TIME_MILLISECOND_24                       },
    { PROPERTY_LIGHT_DISTRIBUTION                                      , CHARACTERISTIC_LIGHT_DISTRIBUTION                        },
    { PROPERTY_LIGHT_SOURCE_CURRENT                                    , CHARACTERISTIC_AVERAGE_CURRENT                           },
    { PROPERTY_LIGHT_SOURCE_ON_TIME_NOT_RESETTABLE                     , CHARACTERISTIC_TIME_SECOND_32                            },
    { PROPERTY_LIGHT_SOURCE_ON_TIME_RESETTABLE                         , CHARACTERISTIC_TIME_SECOND_32                            },
    { PROPERTY_LIGHT_SOURCE_OPEN_CIRCUIT_STATISTICS                    , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_LIGHT_SOURCE_OVERALL_FAILURES_STATISTICS                , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_LIGHT_SOURCE_SHORT_CIRCUIT_STATISTICS                   , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_LIGHT_SOURCE_START_COUNTER_RESETTABLE                   , CHARACTERISTIC_COUNT_24                                  },
    { PROPERTY_LIGHT_SOURCE_TEMPERATURE                                , CHARACTERISTIC_HIGH_TEMPERATURE                          },
    { PROPERTY_LIGHT_SOURCE_THERMAL_DERATING_STATISTICS                , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_LIGHT_SOURCE_THERMAL_SHUTDOWN_STATISTICS                , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_LIGHT_SOURCE_TOTAL_POWER_ON_CYCLES                      , CHARACTERISTIC_COUNT_24                                  },
    { PROPERTY_LIGHT_SOURCE_TYPE                                       , CHARACTERISTIC_LIGHT_SOURCE_TYPE                         },
    { PROPERTY_LIGHT_SOURCE_VOLTAGE                                    , CHARACTERISTIC_AVERAGE_VOLTAGE                           },
    { PROPERTY_LUMEN_MAINTENANCE_FACTOR                                , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_LUMINAIRE_COLOR                                         , CHARACTERISTIC_FIXED_STRING_24                           },
    { PROPERTY_LUMINAIRE_IDENTIFICATION_NUMBER                         , CHARACTERISTIC_FIXED_STRING_24                           },
    { PROPERTY_LUMINAIRE_IDENTIFICATION_STRING                         , CHARACTERISTIC_FIXED_STRING_64                           },
    { PROPERTY_LUMINAIRE_MANUFACTURER_GTIN                             , CHARACTERISTIC_GLOBAL_TRADE_ITEM_NUMBER                  },
    { PROPERTY_LUMINAIRE_NOMINAL_INPUT_POWER                           , CHARACTERISTIC_POWER                                     },
    { PROPERTY_LUMINAIRE_NOMINAL_MAXIMUM_AC_MAINS_VOLTAGE              , CHARACTERISTIC_VOLTAGE                                   },
    { PROPERTY_LUMINAIRE_NOMINAL_MINIMUM_AC_MAINS_VOLTAGE              , CHARACTERISTIC_VOLTAGE                                   },
    { PROPERTY_LUMINAIRE_POWER_AT_MINIMUM_DIM_LEVEL                    , CHARACTERISTIC_POWER                                     },
    { PROPERTY_LUMINAIRE_TIME_OF_MANUFACTURE                           , CHARACTERISTIC_DATE_UTC                                  },
    { PROPERTY_LUMINOUS_EFFICACY                                       , CHARACTERISTIC_LUMINOUS_EFFICACY                         },
    { PROPERTY_LUMINOUS_ENERGY_SINCE_TURN_ON                           , CHARACTERISTIC_LUMINOUS_ENERGY                           },
    { PROPERTY_LUMINOUS_EXPOSURE                                       , CHARACTERISTIC_LUMINOUS_EXPOSURE                         },
    { PROPERTY_LUMINOUS_FLUX_RANGE                                     , CHARACTERISTIC_LUMINOUS_FLUX_RANGE                       },
    { PROPERTY_MAGNETIC_DECLINATION                                    , CHARACTERISTIC_MAGNETIC_DECLINATION                      },
    { PROPERTY_MAGNETIC_FLUX_DENSITY_2_D                               , CHARACTERISTIC_MAGNETIC_FLUX_DENSITY_2_D                 },
    { PROPERTY_MAGNETIC_FLUX_DENSITY_3_D                               , CHARACTERISTIC_MAGNETIC_FLUX_DENSITY_3_D                 },
    { PROPERTY_MOTION_SENSED                                           , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_MOTION_THRESHOLD                                        , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_NOMINAL_LIGHT_OUTPUT                                    , CHARACTERISTIC_LIGHT_OUTPUT                              },
    { PROPERTY_OPEN_CIRCUIT_EVENT_STATISTICS                           , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_OUTDOOR_STATISTICAL_VALUES                              , CHARACTERISTIC_TEMPERATURE_8_STATISTICS                  },
    { PROPERTY_OUTPUT_CURRENT_PERCENT                                  , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_OUTPUT_CURRENT_RANGE                                    , CHARACTERISTIC_ELECTRIC_CURRENT_RANGE                    },
    { PROPERTY_OUTPUT_CURRENT_STATISTICS                               , CHARACTERISTIC_ELECTRIC_CURRENT_STATISTICS               },
    { PROPERTY_OUTPUT_POWER_LIMITATION                                 , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_OUTPUT_RIPPLE_VOLTAGE_SPECIFICATION                     , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_OUTPUT_VOLTAGE_RANGE                                    , CHARACTERISTIC_VOLTAGE_SPECIFICATION                     },
    { PROPERTY_OUTPUT_VOLTAGE_STATISTICS                               , CHARACTERISTIC_VOLTAGE_STATISTICS                        },
    { PROPERTY_OVER_OUTPUT_RIPPLE_VOLTAGE_EVENT_STATISTICS             , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_OVERALL_FAILURE_CONDITION                               , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_PEOPLE_COUNT                                            , CHARACTERISTIC_COUNT_16                                  },
    { PROPERTY_POLLEN_CONCENTRATION                                    , CHARACTERISTIC_POLLEN_CONCENTRATION                      },
    { PROPERTY_POWER_FACTOR                                            , CHARACTERISTIC_COSINE_OF_THE_ANGLE                       },
    { PROPERTY_PRECISE_PRESENT_AMBIENT_TEMPERATURE                     , CHARACTERISTIC_TEMPERATURE                               },
    { PROPERTY_PRECISE_TOTAL_DEVICE_ENERGY_USE                         , CHARACTERISTIC_ENERGY32                                  },
    { PROPERTY_PRESENCE_DETECTED                                       , CHARACTERISTIC_BOOLEAN                                   },
    { PROPERTY_PRESENT_AMBIENT_CARBON_DIOXIDE_CONCENTRATION            , CHARACTERISTIC_CO2_CONCENTRATION                         },
    { PROPERTY_PRESENT_AMBIENT_LIGHT_LEVEL                             , CHARACTERISTIC_ILLUMINANCE                               },
    { PROPERTY_PRESENT_AMBIENT_NOISE                                   , CHARACTERISTIC_NOISE                                     },
    { PROPERTY_PRESENT_AMBIENT_RELATIVE_HUMIDITY                       , CHARACTERISTIC_HUMIDITY                                  },
    { PROPERTY_PRESENT_AMBIENT_TEMPERATURE                             , CHARACTERISTIC_TEMPERATURE_8                             },
    { PROPERTY_PRESENT_AMBIENT_VOLATILE_ORGANIC_COMPOUNDS_CONCENTRATION, CHARACTERISTIC_VOC_CONCENTRATION                         },
    { PROPERTY_PRESENT_CIE_1931_CHROMATICITY_COORDINATES               , CHARACTERISTIC_CHROMATICITY_COORDINATES                  },
    { PROPERTY_PRESENT_CORRELATED_COLOR_TEMPERATURE                    , CHARACTERISTIC_CORRELATED_COLOR_TEMPERATURE              },
    { PROPERTY_PRESENT_DEVICE_INPUT_POWER                              , CHARACTERISTIC_POWER                                     },
    { PROPERTY_PRESENT_DEVICE_OPERATING_EFFICIENCY                     , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_PRESENT_DEVICE_OPERATING_TEMPERATURE                    , CHARACTERISTIC_TEMPERATURE                               },
    { PROPERTY_PRESENT_ILLUMINANCE                                     , CHARACTERISTIC_ILLUMINANCE                               },
    { PROPERTY_PRESENT_INDOOR_AMBIENT_TEMPERATURE                      , CHARACTERISTIC_TEMPERATURE_8                             },
    { PROPERTY_PRESENT_INDOOR_RELATIVE_HUMIDITY                        , CHARACTERISTIC_HUMIDITY                                  },
    { PROPERTY_PRESENT_INPUT_CURRENT                                   , CHARACTERISTIC_ELECTRIC_CURRENT                          },
    { PROPERTY_PRESENT_INPUT_RIPPLE_VOLTAGE                            , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_PRESENT_INPUT_VOLTAGE                                   , CHARACTERISTIC_VOLTAGE                                   },
    { PROPERTY_PRESENT_LUMINOUS_FLUX                                   , CHARACTERISTIC_LUMINOUS_FLUX                             },
    { PROPERTY_PRESENT_OUTDOOR_AMBIENT_TEMPERATURE                     , CHARACTERISTIC_TEMPERATURE_8                             },
    { PROPERTY_PRESENT_OUTDOOR_RELATIVE_HUMIDITY                       , CHARACTERISTIC_HUMIDITY                                  },
    { PROPERTY_PRESENT_OUTPUT_CURRENT                                  , CHARACTERISTIC_ELECTRIC_CURRENT                          },
    { PROPERTY_PRESENT_OUTPUT_VOLTAGE                                  , CHARACTERISTIC_VOLTAGE                                   },
    { PROPERTY_PRESENT_PLANCKIAN_DISTANCE                              , CHARACTERISTIC_CHROMATIC_DISTANCE_FROM_PLANCKIAN         },
    { PROPERTY_PRESENT_RELATIVE_OUTPUT_RIPPLE_VOLTAGE                  , CHARACTERISTIC_PERCENTAGE_8                              },
    { PROPERTY_PRESSURE                                                , CHARACTERISTIC_PRESSURE                                  },
    { PROPERTY_RAINFALL                                                , CHARACTERISTIC_RAINFALL                                  },
    { PROPERTY_RATED_MEDIAN_USEFUL_LIFE_OF_LUMINAIRE                   , CHARACTERISTIC_TIME_HOUR_24                              },
    { PROPERTY_RATED_MEDIAN_USEFUL_LIGHT_SOURCE_STARTS                 , CHARACTERISTIC_COUNT_24                                  },
    { PROPERTY_REFERENCE_TEMPERATURE                                   , CHARACTERISTIC_HIGH_TEMPERATURE                          },
    { PROPERTY_RELATIVE_DEVICE_ENERGY_USE_IN_A_PERIOD_OF_DAY           , CHARACTERISTIC_ENERGY_IN_A_PERIOD_OF_DAY                 },
    { PROPERTY_RELATIVE_DEVICE_RUNTIME_IN_A_GENERIC_LEVEL_RANGE        , CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_GENERIC_LEVEL_RANGE },
    { PROPERTY_RELATIVE_EXPOSURE_TIME_IN_AN_ILLUMINANCE_RANGE          , CHARACTERISTIC_RELATIVE_VALUE_IN_AN_ILLUMINANCE_RANGE    },
    { PROPERTY_RELATIVE_RUNTIME_IN_A_CORRELATED_COLOR_TEMPERATURE_RANGE, CHARACTERISTIC_LUMINOUS_ENERGY                           },
    { PROPERTY_RELATIVE_RUNTIME_IN_A_DEVICE_OPERATING_TEMPERATURE_RANGE, CHARACTERISTIC_RELATIVE_VALUE_IN_A_TEMPERATURE_RANGE     },
    { PROPERTY_RELATIVE_RUNTIME_IN_AN_INPUT_CURRENT_RANGE              , CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_CURRENT_RANGE       },
    { PROPERTY_RELATIVE_RUNTIME_IN_AN_INPUT_VOLTAGE_RANGE              , CHARACTERISTIC_RELATIVE_VALUE_IN_A_VOLTAGE_RANGE         },
    { PROPERTY_SENSOR_GAIN                                             , CHARACTERISTIC_COEFFICIENT                               },
    { PROPERTY_SHORT_CIRCUIT_EVENT_STATISTICS                          , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_THERMAL_DERATING                                        , CHARACTERISTIC_EVENT_STATISTICS                          },
    { PROPERTY_TIME_SINCE_MOTION_SENSED                                , CHARACTERISTIC_TIME_SECOND_16                            },
    { PROPERTY_TIME_SINCE_PRESENCE_DETECTED                            , CHARACTERISTIC_TIME_SECOND_16                            },
    { PROPERTY_TOTAL_DEVICE_ENERGY_USE                                 , CHARACTERISTIC_ENERGY                                    },
    { PROPERTY_TOTAL_DEVICE_OFF_ON_CYCLES                              , CHARACTERISTIC_COUNT_24                                  },
    { PROPERTY_TOTAL_DEVICE_POWER_ON_CYCLES                            , CHARACTERISTIC_COUNT_24                                  },
    { PROPERTY_TOTAL_DEVICE_POWER_ON_TIME                              , CHARACTERISTIC_TIME_HOUR_24                              },
    { PROPERTY_TOTAL_DEVICE_RUNTIME                                    , CHARACTERISTIC_TIME_HOUR_24                              },
    { PROPERTY_TOTAL_DEVICE_STARTS                                     , CHARACTERISTIC_COUNT_24                                  },
    { PROPERTY_TOTAL_LIGHT_EXPOSURE_TIME                               , CHARACTERISTIC_TIME_HOUR_24                              },
    { PROPERTY_TOTAL_LUMINOUS_ENERGY                                   , CHARACTERISTIC_LUMINOUS_ENERGY                           },
    { PROPERTY_TRUE_WIND_DIRECTION                                     , CHARACTERISTIC_TRUE_WIND_DIRECTION                       },
    { PROPERTY_TRUE_WIND_SPEED                                         , CHARACTERISTIC_TRUE_WIND_SPEED                           },
    { PROPERTY_UV_INDEX                                                , CHARACTERISTIC_UV_INDEX                                  },
    { PROPERTY_WIND_CHILL                                              , CHARACTERISTIC_WIND_CHILL                                },
    { 0, 0},
};

static const btmesh_column_property_t  btmesh_column_properties[] = {
    { CHARACTERISTIC_TEMPERATURE_8_IN_A_PERIOD_OF_DAY, CHARACTERISTIC_DECIHOUR_8, CHARACTERISTIC_TEMPERATURE_8 },
    { CHARACTERISTIC_RELATIVE_VALUE_IN_A_TEMPERATURE_RANGE, CHARACTERISTIC_TEMPERATURE, CHARACTERISTIC_PERCENTAGE_8 },
    { CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_CURRENT_RANGE, CHARACTERISTIC_ELECTRIC_CURRENT, CHARACTERISTIC_PERCENTAGE_8 },
    { CHARACTERISTIC_ENERGY_IN_A_PERIOD_OF_DAY, CHARACTERISTIC_DECIHOUR_8, CHARACTERISTIC_ENERGY },
    { CHARACTERISTIC_RELATIVE_VALUE_IN_AN_ILLUMINANCE_RANGE, CHARACTERISTIC_ILLUMINANCE, CHARACTERISTIC_PERCENTAGE_8 },
    { CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_GENERIC_LEVEL_RANGE, CHARACTERISTIC_GENERIC_LEVEL, CHARACTERISTIC_PERCENTAGE_8 },
    { 0, 0, 0},
};

static const bt_gatt_characteristic_t bt_gatt_characteristics[] = {
    { PHONY_CHARACTERISTIC_PERCENTAGE_CHANGE_16               , 2, &hf_bt_phony_characteristic_percentage_change_16 , DISSECTOR_SIMPLE },
    { PHONY_CHARACTERISTIC_INDEX                              , 2, &hf_bt_phony_characteristic_index         , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_APPARENT_ENERGY32                        , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_APPARENT_POWER                           , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_APPARENT_WIND_DIRECTION                  , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_APPARENT_WIND_SPEED                      , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_APPEARANCE                               , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_AVERAGE_CURRENT                          , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_AVERAGE_VOLTAGE                          , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_BOOLEAN                                  , 1, &hf_bt_characteristic_boolean             , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_CHROMATIC_DISTANCE_FROM_PLANCKIAN        , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_CHROMATICITY_COORDINATES                 , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_CHROMATICITY_TOLERANCE                   , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_CIE_13_3_1995_COLOR_RENDERING_INDEX      , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_CO2_CONCENTRATION                        , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_COEFFICIENT                              , 4, &hf_bt_characteristic_coefficient         , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_CORRELATED_COLOR_TEMPERATURE             , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_COSINE_OF_THE_ANGLE                      , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_COUNT_16                                 , 2, &hf_bt_characteristic_count_16            , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_COUNT_24                                 , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_COUNTRY_CODE                             , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_DATE_UTC                                 , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_DECIHOUR_8                               , 1, &hf_bt_characteristic_time_decihour_8     , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_DEW_POINT                                , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_ELECTRIC_CURRENT                         , 2, &hf_bt_characteristic_electric_current    , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_ELECTRIC_CURRENT_RANGE                   , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_ELECTRIC_CURRENT_SPECIFICATION           , 6, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_ELECTRIC_CURRENT_STATISTICS              , 9, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_ENERGY                                   , 3, &hf_bt_characteristic_energy              , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_ENERGY_IN_A_PERIOD_OF_DAY                , 5, NULL                                      , DISSECTOR_THREE_VALUES },
    { CHARACTERISTIC_ENERGY32                                 , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_EVENT_STATISTICS                         , 6, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_FIXED_STRING_16                          , 16, NULL                                     , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_FIXED_STRING_24                          , 24, NULL                                     , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_FIXED_STRING_36                          , 36, NULL                                     , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_FIXED_STRING_64                          , 64, NULL                                     , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_FIXED_STRING_8                           , 8, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_GENERIC_LEVEL                            , 2, &hf_bt_characteristic_generic_level       , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_GLOBAL_TRADE_ITEM_NUMBER                 , 6, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_GUST_FACTOR                              , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_HEAT_INDEX                               , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_HIGH_TEMPERATURE                         , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_HIGH_VOLTAGE                             , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_HUMIDITY                                 , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_ILLUMINANCE                              , 3, &hf_bt_characteristic_illuminance         , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LIGHT_DISTRIBUTION                       , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LIGHT_OUTPUT                             , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LIGHT_SOURCE_TYPE                        , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LUMINOUS_EFFICACY                        , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LUMINOUS_ENERGY                          , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LUMINOUS_EXPOSURE                        , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LUMINOUS_FLUX                            , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LUMINOUS_FLUX_RANGE                      , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_LUMINOUS_INTENSITY                       , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_MAGNETIC_DECLINATION                     , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_MAGNETIC_FLUX_DENSITY_2_D                , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_MAGNETIC_FLUX_DENSITY_3_D                , 6, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_NOISE                                    , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_PERCEIVED_LIGHTNESS                      , 2, &hf_bt_characteristic_perceived_lightness , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_PERCENTAGE_8                             , 1, &hf_bt_characteristic_percentage_8        , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_POLLEN_CONCENTRATION                     , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_POWER                                    , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_POWER_SPECIFICATION                      , 9, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_PRESSURE                                 , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_RAINFALL                                 , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_CURRENT_RANGE      , 5, NULL                                      , DISSECTOR_THREE_VALUES },
    { CHARACTERISTIC_RELATIVE_RUNTIME_IN_A_GENERIC_LEVEL_RANGE, 5, NULL                                      , DISSECTOR_THREE_VALUES },
    { CHARACTERISTIC_RELATIVE_VALUE_IN_A_TEMPERATURE_RANGE    , 5, NULL                                      , DISSECTOR_THREE_VALUES },
    { CHARACTERISTIC_RELATIVE_VALUE_IN_A_VOLTAGE_RANGE        , 5, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_RELATIVE_VALUE_IN_AN_ILLUMINANCE_RANGE   , 7, NULL                                      , DISSECTOR_THREE_VALUES },
    { CHARACTERISTIC_TEMPERATURE                              , 2, &hf_bt_characteristic_temperature         , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TEMPERATURE_8                            , 1, &hf_bt_characteristic_temperature_8       , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TEMPERATURE_8_IN_A_PERIOD_OF_DAY         , 3, NULL                                      , DISSECTOR_THREE_VALUES },
    { CHARACTERISTIC_TEMPERATURE_8_STATISTICS                 , 5, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TEMPERATURE_RANGE                        , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TEMPERATURE_STATISTICS                   , 9, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TIME_HOUR_24                             , 3, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TIME_MILLISECOND_24                      , 3, &hf_bt_characteristic_time_millisecond_24 , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TIME_SECOND_16                           , 2, &hf_bt_characteristic_time_second_16      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TIME_SECOND_32                           , 4, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TRUE_WIND_DIRECTION                      , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_TRUE_WIND_SPEED                          , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_UV_INDEX                                 , 1, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_VOC_CONCENTRATION                        , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_VOLTAGE                                  , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_VOLTAGE_FREQUENCY                        , 2, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_VOLTAGE_SPECIFICATION                    , 6, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_VOLTAGE_STATISTICS                       , 9, NULL                                      , DISSECTOR_SIMPLE },
    { CHARACTERISTIC_WIND_CHILL                               , 1, NULL                                      , DISSECTOR_SIMPLE },
    { 0, 0, NULL, 0},
};

/* Upper Transport Message reassembly */

static reassembly_table upper_transport_reassembly_table;

typedef struct _upper_transport_fragment_key {
    uint16_t src;
    unsigned seq0;
    unsigned ivindex;
    uint32_t net_key_iv_index_hash;
} upper_transport_fragment_key;

static unsigned
upper_transport_fragment_hash(const void *k)
{
    const upper_transport_fragment_key* key = (const upper_transport_fragment_key*) k;
    unsigned hash_val;

    const uint8_t hash_buf_len = sizeof(uint16_t) + 2 * sizeof(unsigned) + sizeof(uint32_t);
    unsigned idx=0;
    uint8_t* hash_buf = (uint8_t*)wmem_alloc(wmem_packet_scope(), hash_buf_len);
    memcpy(hash_buf, &key->src, sizeof(uint16_t));
    idx += sizeof(uint16_t);
    memcpy(&hash_buf[idx], &key->seq0, sizeof(unsigned));
    idx += sizeof(unsigned);
    memcpy(&hash_buf[idx], &key->ivindex, sizeof(key->ivindex));
    idx += sizeof(unsigned);
    memcpy(&hash_buf[idx], &key->net_key_iv_index_hash, sizeof(key->net_key_iv_index_hash));
    hash_val = wmem_strong_hash(hash_buf, hash_buf_len);

    return hash_val;
}

static int
upper_transport_fragment_equal(const void *k1, const void *k2)
{
    const upper_transport_fragment_key* key1 = (const upper_transport_fragment_key*) k1;
    const upper_transport_fragment_key* key2 = (const upper_transport_fragment_key*) k2;

    return ((key1->src == key2->src) && (key1->seq0 == key2->seq0) &&
            (key1->ivindex == key2->ivindex) && (key1->net_key_iv_index_hash == key2->net_key_iv_index_hash)
            ? true : false);
}

static void *
upper_transport_fragment_temporary_key(const packet_info *pinfo _U_, const uint32_t id _U_,
                              const void *data)
{
    upper_transport_fragment_key *key = g_slice_new(upper_transport_fragment_key);
    const upper_transport_fragment_key *pkt = (const upper_transport_fragment_key *)data;

    key->src = pkt->src;
    key->seq0 = pkt->seq0;
    key->ivindex = pkt->ivindex;
    key->net_key_iv_index_hash = pkt->net_key_iv_index_hash;

    return key;
}

static void
upper_transport_fragment_free_temporary_key(void *ptr)
{
    upper_transport_fragment_key *key = (upper_transport_fragment_key *)ptr;

    g_slice_free(upper_transport_fragment_key, key);
}

static void *
upper_transport_fragment_persistent_key(const packet_info *pinfo _U_, const uint32_t id _U_,
                              const void *data)
{
    upper_transport_fragment_key *key = g_slice_new(upper_transport_fragment_key);
    const upper_transport_fragment_key *pkt = (const upper_transport_fragment_key *)data;

    key->src = pkt->src;
    key->seq0 = pkt->seq0;
    key->ivindex = pkt->ivindex;
    key->net_key_iv_index_hash = pkt->net_key_iv_index_hash;

    return key;
}

static void
upper_transport_fragment_free_persistent_key(void *ptr)
{
    upper_transport_fragment_key *key = (upper_transport_fragment_key *)ptr;
    if (key) {
        g_slice_free(upper_transport_fragment_key, key);
    }
}

static const reassembly_table_functions upper_transport_reassembly_table_functions = {
    upper_transport_fragment_hash,
    upper_transport_fragment_equal,
    upper_transport_fragment_temporary_key,
    upper_transport_fragment_persistent_key,
    upper_transport_fragment_free_temporary_key,
    upper_transport_fragment_free_persistent_key
};

/* A BT Mesh dissector is not really useful without decryption as all packets are encrypted. Just leave a stub dissector outside of */

/* BT Mesh s1 function */
static bool
s1(uint8_t *m, size_t mlen, uint8_t *salt)
{

    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;
    size_t read_digest_length = 16;
    uint8_t zero[16] = { 0 };

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &zero, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, m, mlen);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, salt, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return true;
}

/* BT Mesh Labebl UUID hash function
 *
 * SALT = s1 ("vtad")
 * hash = AES-CMAC(SALT, Label UUID) mod 2(pow)14
 *
 */
static bool
label_uuid_hash(uat_btmesh_label_uuid_record_t *label_uuid_record)
{
    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;
    uint8_t vtad[4] = { 'v', 't', 'a', 'd' };
    size_t mlen = 4;
    uint8_t salt[16];
    uint8_t hash[16];
    size_t read_digest_length = 16;

    if (label_uuid_record->label_uuid_length != 16) {
        return false;
    }

    /* SALT = s1("vtad") */
    if (s1(vtad, mlen, salt) == false) {
        return false;
    }

    /* hash = AES-CMAC(SALT, Label UUID) */
    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &salt, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, label_uuid_record->label_uuid, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, hash, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    label_uuid_record->hash = hash[15] + ((uint16_t)(hash[14] & 0x3f) << 8) + 0x8000;

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return true;
}

/* BT Mesh K2 function
 * Allow plen up to 9 char
 *
 * The key (T) is computed as follows:
 * T = AES-CMACSALT (N)
 * SALT is the 128-bit value computed as follows
 * SALT = s1("smk2")
 * The output of the key generation function k2 is as follows:
 * T0 = empty string (zero length)
 * T1 = AES-CMACT (T0 || P || 0x01)
 * T2 = AES-CMACT (T1 || P || 0x02)
 * T3 = AES-CMACT (T2 || P || 0x03)
 * k2(N, P) = (T1 || T2 || T3) mod 2(pow)263
 */
static bool
k2(uat_btmesh_record_t * net_key_set, uint8_t *p, size_t plen)
{
    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;
    uint8_t smk2[4] = { 's', 'm', 'k', '2' };
    size_t mlen = 4;
    uint8_t salt[16];
    uint8_t t[16];
    uint8_t t1[16];
    uint8_t p_t1[9 + 1];
    uint8_t p_t2[16 + 9 + 1];
    uint8_t p_t3[16 + 9 + 1];

    size_t read_digest_length = 16;

    if (plen > 8) {
        return false;
    }

    if (net_key_set->network_key_length != 16) {
        return false;
    }

    /* SALT = s1("smk2") */
    if (s1(smk2, mlen, salt) == false) {
        return false;
    }

    /* T = AES-CMAC_SALT(N) */
    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &salt, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, net_key_set->network_key, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    /*
     * T0 = empty string (zero length)
     * T1 = AES-CMAC_T(T0 || P || 0x01)
     */
    memcpy(p_t1, p, plen);
    p_t1[plen] = 0x01;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &p_t1, plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t1, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }
    net_key_set->nid = (t1[15] & 0x7f);
    /*
     * T2 = AES-CMAC_T(T1 || P || 0x02)
     * (EncryptionKey)
     */

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    memcpy(p_t2, t1, 16);
    memcpy(&p_t2[16], p, plen);
    p_t2[16 + plen] = 0x02;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &p_t2, 16 + plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, net_key_set->encryptionkey, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    /* T3 = AES-CMAC_T(T2 || P || 0x03) */
    /* PrivacyKey */
    memcpy(p_t3, net_key_set->encryptionkey, 16);
    memcpy(&p_t3[16], p, plen);
    p_t3[16 + plen] = 0x03;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, p_t3, 16 + plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, net_key_set->privacykey, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return true;
}

/* BT Mesh K4 function

   The inputs to function k4 is:
   N is 128 bits

   The key (T) is computed as follows:
   T = AES-CMAC (SALT, N)

   SALT is the 128-bit value computed as follows:
   SALT = s1("smk4")

   The output of the derivation function k4 is as follows:
   K4(N) = AES-CMAC (T, "id6" || 0x01 ) mod 2(pow)6
*/

static bool
k4(uat_btmesh_record_t *key_set)
{
    gcry_mac_hd_t mac_hd;
    gcry_error_t gcrypt_err;

    uint8_t smk4[4] = { 's', 'm', 'k', '4' };
    size_t mlen = 4;
    uint8_t id6[4] = { 'i', 'd', '6', 0x01 };
    size_t id6len = 4;
    uint8_t salt[16];
    uint8_t t[16];
    uint8_t t1[16];

    size_t read_digest_length = 16;

    if (key_set->application_key_length != 16) {
        return false;
    }

    /* SALT = s1("smk4") */
    if (s1(smk4, mlen, salt) == false) {
        return false;
    }

    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &salt, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, key_set->application_key, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return false;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &id6, id6len);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t1, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return false;
    }

    key_set->aid = (t1[15] & 0x3f);

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);
    return true;
}

static bool
create_central_security_keys(uat_btmesh_record_t * net_key_set)
{
    uint8_t p[1] = { 0 };
    size_t plen = 1;

    return k2(net_key_set, p, plen);
}

static tvbuff_t *
btmesh_deobfuscate(tvbuff_t *tvb, packet_info *pinfo, int offset _U_, uat_btmesh_record_t *net_key_set)
{
    tvbuff_t *de_obf_tvb = NULL;

    /* Decode ObfuscatedData
     * Privacy Random = (EncDST || EncTransportPDU || NetMIC)[0-6]
     * PECB = e ((PrivacyKey, 0x0000000000 || IV Index || Privacy Random)
     * (CTL || TTL || SEQ || SRC) = ObfuscatedData
     */
    uint8_t in[16]; /*  0x0000000000 || IV Index || Privacy Random */
    gcry_cipher_hd_t cipher_hd;
    uint8_t pecb[16];
    uint8_t *plaintextnetworkheader = (uint8_t *)wmem_alloc(pinfo->pool, 6);
    int i;

    /* at least 1 + 6 + 2 + 1 + 4 + 4 = 18 octets must be present in tvb to decrypt */
    if (!tvb_bytes_exist(tvb, 0, 18)) {
        return NULL;
    }

    memset(in, 0x00, 5);
    memcpy((uint8_t *)&in + 5, net_key_set->ivindex, 4);

    /* Privacy random */
    tvb_memcpy(tvb, (uint8_t *)&in + 9, 7, 7);

    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return NULL;
    }

    if (gcry_cipher_setkey(cipher_hd, net_key_set->privacykey, 16)) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Decrypt */
    if (gcry_cipher_encrypt(cipher_hd, &pecb, 16, &in, 16)) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Now close the cipher handle */
    gcry_cipher_close(cipher_hd);

    for ( i = 0; i < 6; i++) {
        plaintextnetworkheader[i] = tvb_get_uint8(tvb, i + 1) ^ pecb[i];
    }

    de_obf_tvb = tvb_new_child_real_data(tvb, plaintextnetworkheader, 6, 6);
    return de_obf_tvb;
}

static const char *period_interval_unit[] = {"ms", "s", "s", "min"};
static const uint32_t period_interval_multiplier[] = {100, 1, 10, 10};

static void
format_publish_period(char *buf, uint32_t value) {
    uint32_t idx = (value & 0xC0 ) >> 6;
    uint32_t val = (value & 0x3F ) * period_interval_multiplier[idx];
    snprintf(buf, ITEM_LABEL_LENGTH, "%u %s", val, period_interval_unit[idx]);
}

static void
format_transmit(char *buf, uint32_t value) {
    uint32_t prd = (((value & 0xF8 ) >> 3 ) + 1 ) * 10;
    uint32_t ctr = (value & 0x07 );
    switch (ctr) {
    case 0:
        snprintf(buf, ITEM_LABEL_LENGTH, "One transmissions");
        break;

    default:
        snprintf(buf, ITEM_LABEL_LENGTH, "%u transmissions at interval of %u ms", ctr, prd);
    }
}

static void
format_retransmit(char *buf, uint32_t value) {
    uint32_t prd = (((value & 0xF8 ) >> 3 ) + 1 ) * 10;
    uint32_t ctr = (value & 0x07 );
    switch (ctr) {
    case 0:
        snprintf(buf, ITEM_LABEL_LENGTH, "No retransmissions");
        break;

    case 1:
        snprintf(buf, ITEM_LABEL_LENGTH, "One retransmission after %u ms", prd);
        break;

    default:
        snprintf(buf, ITEM_LABEL_LENGTH, "%u retransmissions at interval of %u ms", ctr, prd);
    }
}

static void
format_interval_steps(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u ms (%u)", (value + 1) * 10, value);
}

static void
format_key_index(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u (0x%03x)", value & 0xFFF, value & 0xFFF);
}

static void
format_key_index_rfu(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "0x%1x", (value & 0xF000) >> 12);
}

static void
format_dual_key_index(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u (0x%03x), %u (0x%03x)", value & 0xFFF, value & 0xFFF, ( value & 0xFFF000 ) >> 12, ( value & 0xFFF000 ) >> 12);
}

static void
format_vendor_model(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "0x%04x of %s", value >> 16, val_to_str_ext_const(value & 0xFFFF, &bluetooth_company_id_vals_ext, "Unknown"));
}

static void
format_publish_appkeyindex_model(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u (0x%03x) using %s security material", value & 0x0FFF, value & 0x0FFF, ((value & 0x1000) ? "Friendship" : "Central"));
}

static void
format_delay_ms(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u ms", value * 5);
}

static void
format_power(char *buf, uint32_t value) {
    double val;
    val =  (double)value / (double)655.35;
    snprintf(buf, ITEM_LABEL_LENGTH, "% 3.2f %%", val);
}

static void
format_battery_level(char *buf, uint32_t value) {
    if (value == 0xFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "The percentage of the charge level is unknown");
        return;
    }
    if (value <= 0x64) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%u %%", value);
        return;
    }
    snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%u)", value);
}

static void
format_battery_time(char *buf, uint32_t value) {
    if (value == 0xFFFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "The remaining time is not known");
        return;
    }
    snprintf(buf, ITEM_LABEL_LENGTH, "%u minutes", value);
}

static void
format_global_latitude(char *buf, int32_t value) {
    if (value == INT_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Global Latitude is not configured.");
        return;
    }
    double val;
    val =  (double)90.0 / (double) (0x7FFFFFFF) * (double)value ;
    snprintf(buf, ITEM_LABEL_LENGTH, "% 2.6f°", val);
}

static void
format_global_longitude(char *buf, int32_t value) {
    if (value == INT_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Global Longitude is not configured.");
        return;
    }
    double val;
    val =  (double)180.0 / (double) (0x7FFFFFFF) * (double)value;
    snprintf(buf, ITEM_LABEL_LENGTH, "% 2.6f°", val);
}

static void
format_global_altitude(char *buf, int16_t value) {
    if (value == 0x7FFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Global Altitude is not configured.");
        return;
    }
    if (value == 0x7FFE) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Global Altitude is greater than or equal to 32766 meters.");
        return;
    }
    snprintf(buf, ITEM_LABEL_LENGTH, "%d meters", value);
}

static void
format_local_north(char *buf, int16_t value) {
    if (value == -32768) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Local North information is not configured.");
        return;
    }
    double val;
    val =  (double)value / (double) 10.0;
    snprintf(buf, ITEM_LABEL_LENGTH, "%.1f meters", val);
}

static void
format_local_east(char *buf, int16_t value) {
    if (value == -32768) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Local East information is not configured.");
        return;
    }
    double val;
    val =  (double)value / (double) 10.0;
    snprintf(buf, ITEM_LABEL_LENGTH, "%.1f meters", val);
}

static void
format_local_altitude(char *buf, int16_t value) {
    if (value == 0x7FFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Local Altitude is not configured.");
        return;
    }
    if (value == 0x7FFE) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Local Altitude is greater than or equal to 3276.6 meters.");
        return;
    }
    double val;
    val =  (double)value / (double) 10.0;
    snprintf(buf, ITEM_LABEL_LENGTH, "%.1f meters", val);
}

static void
format_floor_number(char *buf, uint8_t value) {
    switch (value) {
        case 0x00:
            snprintf(buf, ITEM_LABEL_LENGTH, "Floor -20 or any floor below -20.");
        break;

        case 0xFC:
            snprintf(buf, ITEM_LABEL_LENGTH, "Floor 232 or any floor above 232.");
        break;

        case 0xFD:
            snprintf(buf, ITEM_LABEL_LENGTH, "Ground floor. Floor 0.");
        break;

        case 0xFE:
            snprintf(buf, ITEM_LABEL_LENGTH, "Ground floor. Floor 1.");
        break;

        case 0xFF:
            snprintf(buf, ITEM_LABEL_LENGTH, "Not configured.");
        break;

        default:
            snprintf(buf, ITEM_LABEL_LENGTH, "%d", (int16_t)value - (int16_t)20 );
        break;
    }
}

static void
format_update_time(char *buf, uint16_t value) {
    double val;
    val =  pow((double)2.0, (double)(value - 3));
    snprintf(buf, ITEM_LABEL_LENGTH, "%.*f seconds", (value<4?3-value:0), val);
}

static void
format_precision(char *buf, uint16_t value) {
    double val;
    val =  pow((double)2.0, (double)(value - 3));
    snprintf(buf, ITEM_LABEL_LENGTH, "%.*f meters", (value<4?3-value:0),val);
}

static void
format_scheduler_year(char *buf, int32_t value) {
    if (value <= 0x63) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d", 2000+value);
    } else if (value == 0x64 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Any year");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
    }
}

static void
format_scheduler_day(char *buf, int32_t value) {
    if (value > 0x0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "Any day");
    }
}

static void
format_scheduler_hour(char *buf, int32_t value) {
    if (value < 24 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
    } else if (value == 0x18 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Any hour of the day");
    } else if (value == 0x19 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Once a day (at a random hour)");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
    }
}

static void
format_scheduler_minute(char *buf, int32_t value) {
    switch (value) {
        case 0x3C:
            snprintf(buf, ITEM_LABEL_LENGTH, "Any minute of the hour");
        break;

        case 0x3D:
            snprintf(buf, ITEM_LABEL_LENGTH, "Every 15 minutes (minute modulo 15 is 0) (0, 15, 30, 45)");
        break;

        case 0x3E:
            snprintf(buf, ITEM_LABEL_LENGTH, "Every 20 minutes (minute modulo 20 is 0) (0, 20, 40)");
        break;

        case 0x3F:
            snprintf(buf, ITEM_LABEL_LENGTH, "Once an hour (at a random minute)");
        break;

        default:
            snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
        break;
    }
}

static void
format_scheduler_second(char *buf, int32_t value) {
    switch (value) {
        case 0x3C:
            snprintf(buf, ITEM_LABEL_LENGTH, "Any second of the minute");
        break;

        case 0x3D:
            snprintf(buf, ITEM_LABEL_LENGTH, "Every 15 seconds (second modulo 15 is 0) (0, 15, 30, 45)");
        break;

        case 0x3E:
            snprintf(buf, ITEM_LABEL_LENGTH, "Every 20 seconds (second modulo 20 is 0) (0, 20, 40)");
        break;

        case 0x3F:
            snprintf(buf, ITEM_LABEL_LENGTH, "Once a minute (at a random second)");
        break;

        default:
            snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
        break;
    }
}

static void
format_scheduler_action(char *buf, int32_t value) {
    switch (value) {
        case 0x0:
            snprintf(buf, ITEM_LABEL_LENGTH, "Turn Off");
        break;

        case 0x1:
            snprintf(buf, ITEM_LABEL_LENGTH, "Turn On");
        break;

        case 0x2:
            snprintf(buf, ITEM_LABEL_LENGTH, "Scene Recall");
        break;

        case 0xF:
            snprintf(buf, ITEM_LABEL_LENGTH, "Inactive");
        break;

        default:
            snprintf(buf, ITEM_LABEL_LENGTH, "Reserved for Future Use");
        break;
    }
}

static void
format_scheduler_month(char *buf, int32_t value) {
    static const char ab_month_name[][4] =
    {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    int i;
    bool is_first = true;

    *buf = '\0';
    for (i = 0; i < 12; i++) {
        if (value & (1 << i)) {
            if (is_first) {
                is_first = false;
            } else {
                buf = g_stpcpy(buf, ", ");
            }
            buf = g_stpcpy(buf, ab_month_name[i]);
        }
    }
}

static void
format_scheduler_day_of_week(char *buf, int32_t value) {
    static char const ab_weekday_name[][4] =
    {
        "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
    };

    int i;
    bool is_first = true;

    *buf = '\0';
    for (i = 0; i < 7; i++) {
        if (value & (1 << i)) {
            if (is_first) {
                is_first = false;
            } else {
                buf = g_stpcpy(buf, ", ");
            }
            buf = g_stpcpy(buf, ab_weekday_name[i]);
        }
    }
}

static void
format_subsecond_ms(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%.1f ms", (double)value / 0.256);
}

static void
format_uncertainty_ms(char *buf, uint32_t value) {
    snprintf(buf, ITEM_LABEL_LENGTH, "%u ms", value * 10);
}

static void
format_tai_utc_delta_s(char *buf, uint32_t value) {
    int32_t val = (int32_t)value - 255;
    snprintf(buf, ITEM_LABEL_LENGTH, "%d s", val);
}

static void
format_time_zone_offset_h(char *buf, uint32_t value) {
    int32_t val = (int32_t)value - 64;
    if (val >= 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%+d:%02d", val/4, (val%4)*15 );
    } else {
        val *=-1;
        snprintf(buf, ITEM_LABEL_LENGTH, "-%d:%02d", val/4, (val%4)*15 );
    }
}

static void
format_tai_to_utc_date(char *buf, uint64_t value) {

    if (value == 0 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Unknown");
    } else {
        char *time_str;
        time_t val;

        // Leap seconds removal
        uint64_t delta = 0;
        // TAI epoch is 2000-01-01T00:00:00 TAI
        uint64_t leap_seconds[] = {
            189388800, // 1 January 2006, 00:00:00, seconds from TAI epoch
            284083200, // 1 January 2009, 00:00:00, seconds from TAI epoch
            394416000, // 1 July 2012, 00:00:00, seconds from TAI epoch
            489024000, // 1 July 2015, 00:00:00, seconds from TAI epoch
            536544000, // 1 January 2017, 00:00:00, seconds from TAI epoch
        };
        for (int i = 0; i < 5; i++) {
            if (value >= leap_seconds[i]) {
                delta++;
            } else {
                break;
            }
        }
        // 946684800 seconds between 1.1.1970 and 1.1.2000
        // 32 leap seconds difference between TAI and UTC on 1.1.2000
        val = (time_t)(value + 946684800ll - 32ll - delta);
        time_str = abs_time_secs_to_str(NULL, val, ABSOLUTE_TIME_UTC, true);
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", time_str);
    }
}

static void
format_temperature_kelvin(char *buf, uint32_t value) {
    if (value < 0x0320 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%d)", value);
    } else if (value > 0x4E20 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%d)", value);
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d K", value);
    }
}

static void
format_temperature_kelvin_unknown(char *buf, uint32_t value) {
    if (value < 0x0320 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%d)", value);
    } else if (value > 0x4E20 && value != 0xFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%d)", value);
    } else if (value == 0xFFFF ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Unknown");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d K", value);
    }
}

static void
format_light_lightness_prohibited(char *buf, uint32_t value) {
    if (value == 0x0 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%d)", value);
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
    }
}

static void
format_light_lightness_default(char *buf, uint32_t value) {
    if (value == 0x0 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Use the Light Lightness Last value");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
    }
}

static void
format_hsl_hue(char *buf, uint32_t value) {
    double val;
    val =  (double)360.0 / (double) (0x10000) * (double)value;
    snprintf(buf, ITEM_LABEL_LENGTH, "% 3.3f°", val);
}

static void
format_xyl_coordinate(char *buf, uint32_t value) {
    double val;
    val =  (double)value / (double) (0xFFFF);
    snprintf(buf, ITEM_LABEL_LENGTH, "%1.5f", val);
}

static void
format_sensor_setting_access(char *buf, uint32_t value)
{
    if (value == 0x01 ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Can be read");
    } else if (value == 0x03) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Can be read and written");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
    }
}

static void
format_fast_cadence_period_divisor(char *buf, uint32_t value)
{
    if (value > 15) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
    } else {
        uint32_t v = (1 << value);
        snprintf(buf, ITEM_LABEL_LENGTH, "%d", v);
    }
}

static void
format_status_min_interval(char *buf, uint32_t value)
{
    if (value > 26) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
    } else {
        uint32_t v = (1 << value);
        snprintf(buf, ITEM_LABEL_LENGTH, "%d ms", v);
    }
}

static void
format_admin_user_access(char *buf, uint32_t value)
{
    switch (value) {
        case 0x0:
            snprintf(buf, ITEM_LABEL_LENGTH, "Not a Generic User Property");
        break;

        case 0x1:
            snprintf(buf, ITEM_LABEL_LENGTH, "Can be read");
        break;

        case 0x2:
            snprintf(buf, ITEM_LABEL_LENGTH, "Can be written");
        break;

        case 0x3:
            snprintf(buf, ITEM_LABEL_LENGTH, "Can be read and written");
        break;

        default:
            snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
        break;
    }
}

static void
format_manufacturer_user_access(char *buf, uint32_t value)
{
    if (value == 0x00) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Not a Generic User Property");
    } else if (value == 0x01) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Can be read");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
    }
}

static void
format_user_access(char *buf, uint32_t value)
{
    switch (value) {
        case 0x1:
            snprintf(buf, ITEM_LABEL_LENGTH, "Can be read");
        break;

        case 0x2:
            snprintf(buf, ITEM_LABEL_LENGTH, "Can be written");
        break;

        case 0x3:
            snprintf(buf, ITEM_LABEL_LENGTH, "Can be read and written");
        break;

        default:
            snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
        break;
    }
}

static void
format_sensor_descriptor_tolerance(char *buf, uint32_t value)
{
    if (value == 0x000) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Unspecified");
    } else {
        double val;
        val =  (double)value / (double)40.95;
        snprintf(buf, ITEM_LABEL_LENGTH, "% 3.2f %%", val);
    }
}

static void
format_sensor_period(char *buf, uint32_t value)
{
    if (value == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Not Applicable");
    } else {
        double val;

        val = pow((double)1.1, (double)value - (double)64.0);
        if ( val < 1.0 ) { //Milliseconds
            snprintf(buf, ITEM_LABEL_LENGTH, "%.0f ms", val * 1000.0);
        } else {
            if ( val < 60.0 ) { //Seconds
                snprintf(buf, ITEM_LABEL_LENGTH, "%.1f s", val);
            } else {
                unsigned long v = (unsigned long)val;
                    if ( val < 86400 ) { //Hours:Minutes:Seconds
                        snprintf(buf, ITEM_LABEL_LENGTH, "%02lu:%02lu:%02lu", v/3600, (v % 3600)/60, v % 60);
                    } else { //Days Hours:Minutes:Seconds
                        snprintf(buf, ITEM_LABEL_LENGTH, "%lu days %02lu:%02lu:%02lu", v/86400, (v % 86400)/3600, (v % 3600)/60, v % 60);
                    }
            }
        }
    }
}

static void
format_percentage_change_16(char *buf, uint32_t value)
{
    double val;
    val =  (double)value / (double)(100);
    snprintf(buf, ITEM_LABEL_LENGTH, "%.2f %%", val);
}

static void
format_decihour_8(char *buf, uint32_t value)
{
    if (value == 0xFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        if (value > 240) {
            snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
        } else {
            double val;
            val =  (double)value / (double)(10);
            snprintf(buf, ITEM_LABEL_LENGTH, "%.1f h", val);
        }
    }
}

static void
format_temperature_8(char *buf, int32_t value)
{
    if (value == 0x7F) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        double val;
        val =  (double)value * (double)(0.5);
        snprintf(buf, ITEM_LABEL_LENGTH, "%.1f C", val);
    }
}

static void
format_temperature(char *buf, int32_t value)
{
    if (value == INT16_MIN ) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        if (value < (int32_t)(-27315)) {
            snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited");
        } else {
            double val;
            val =  (double)value / (double)(100);
            snprintf(buf, ITEM_LABEL_LENGTH, "%.2f C", val);
        }
    }
}

static void
format_electric_current(char *buf, uint32_t value)
{
    if (value == 0xFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        double val;
        val =  (double)value / (double)(100);
        snprintf(buf, ITEM_LABEL_LENGTH, "%.2f A", val);
    }
}

static void
format_energy(char *buf, uint32_t value)
{
    if (value == 0xFFFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d kWh", value);
    }
}

static void
format_illuminance(char *buf, uint32_t value) {
    if (value == 0xFFFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        double val;
        val =  (double)value / (double)(100);
        snprintf(buf, ITEM_LABEL_LENGTH, "%.2f lux", val);
    }
}

static void
format_percentage_8(char *buf, uint32_t value) {
    if (value == 0xFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else if (value > 200) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%d)", value);
    } else {
        double val;
        val =  (double)value / (double)(2);
        snprintf(buf, ITEM_LABEL_LENGTH, "%.1f %%", val);
    }
}

static void
format_time_millisecond_24(char *buf, uint32_t value) {
    if (value == 0xFFFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        double val;
        val =  (double)value / (double)(1000);
        snprintf(buf, ITEM_LABEL_LENGTH, "%.2f s", val);
    }
}

static void
format_count_16(char *buf, uint32_t value) {
    if (value == 0xFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
    }
}

static void
format_boolean(char *buf, uint32_t value) {
    if (value == 0x00) {
        snprintf(buf, ITEM_LABEL_LENGTH, "False");
    } else if (value == 0x01) {
        snprintf(buf, ITEM_LABEL_LENGTH, "True");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "Prohibited (%d)", value);
    }
}

static void
format_time_second_16(char *buf, uint32_t value) {
    if (value == 0xFFFF) {
        snprintf(buf, ITEM_LABEL_LENGTH, "Value is not known");
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%d s", value);
    }
}

static uint16_t
find_characteristic_id(uint16_t property_id)
{
    int i;
    uint16_t characteristic_id = NOT_SUPPORTED_PROPERTY;

    for (i=0; btmesh_properties[i].characteristic_id !=0; i++ ) {
        if (btmesh_properties[i].property_id == property_id) {
            characteristic_id = btmesh_properties[i].characteristic_id;
            break;
        }
    }
    return characteristic_id;
}

static int
find_characteristic_idx(uint16_t characteristic_id)
{
    int i, idx = NOT_SUPPORTED_CHARACTERISTIC;

    for (i=0; bt_gatt_characteristics[i].characteristic_id !=0; i++ ) {
        if (bt_gatt_characteristics[i].characteristic_id == characteristic_id) {
            idx = i;
            break;
        }
    }
    return idx;
}

static int
find_column_properties_idx(int idx)
{
    int idx_3 = NOT_SUPPORTED_CHARACTERISTIC;
    for (int i=0; btmesh_column_properties[i].characteristic_id !=0; i++ ) {
        if (btmesh_column_properties[i].characteristic_id == bt_gatt_characteristics[idx].characteristic_id) {
            idx_3 = i;
            break;
        }
    }
    return idx_3;
}

static uint16_t
dissect_btmesh_property_idx(tvbuff_t *tvb, proto_tree *tree, int offset, int characteristic_idx)
{
    uint16_t characteristic_value_length = 0;
    int hfindex = -1;
    proto_item *pi;

    if (characteristic_idx < 0) {
        return 0;
    }

    characteristic_value_length = bt_gatt_characteristics[characteristic_idx].characteristic_value_length;
    if (bt_gatt_characteristics[characteristic_idx].characteristic_value_length == 0) {
        return 0;
    }

    if (bt_gatt_characteristics[characteristic_idx].dissector_type == DISSECTOR_SIMPLE) {
        //DISSECTOR_SIMPLE case
        if (bt_gatt_characteristics[characteristic_idx].hfindex == NULL) {
            return 0;
        }
        hfindex = *bt_gatt_characteristics[characteristic_idx].hfindex;

        pi = proto_tree_add_item(tree, hfindex, tvb, offset, characteristic_value_length, ENC_LITTLE_ENDIAN);
        proto_item_set_generated(pi);
    } else {
        //DISSECTOR_THREE_VALUES case
        int idx_3 = find_column_properties_idx(characteristic_idx);
        if (idx_3 != NOT_SUPPORTED_CHARACTERISTIC) {
            int idx_x = find_characteristic_idx(btmesh_column_properties[idx_3].x_characteristic_id);
            if (idx_x == NOT_SUPPORTED_CHARACTERISTIC ||
                bt_gatt_characteristics[idx_x].characteristic_value_length == 0 ||
                bt_gatt_characteristics[idx_x].hfindex == NULL ||
                bt_gatt_characteristics[idx_x].dissector_type != DISSECTOR_SIMPLE) {
                return 0;
            }
            int idx_y = find_characteristic_idx(btmesh_column_properties[idx_3].y_characteristic_id);
            if (idx_y == NOT_SUPPORTED_CHARACTERISTIC ||
                bt_gatt_characteristics[idx_y].characteristic_value_length == 0 ||
                bt_gatt_characteristics[idx_y].hfindex == NULL ||
                bt_gatt_characteristics[idx_y].dissector_type != DISSECTOR_SIMPLE) {
                return 0;
            }
            characteristic_value_length=0;
            pi = proto_tree_add_item(tree, *bt_gatt_characteristics[idx_x].hfindex,
                tvb, offset,
                bt_gatt_characteristics[idx_x].characteristic_value_length, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(pi);
            characteristic_value_length+=bt_gatt_characteristics[idx_x].characteristic_value_length;

            pi = proto_tree_add_item(tree, *bt_gatt_characteristics[idx_x].hfindex,
                tvb, offset+characteristic_value_length,
                bt_gatt_characteristics[idx_x].characteristic_value_length, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(pi);
            characteristic_value_length+=bt_gatt_characteristics[idx_x].characteristic_value_length;

            pi = proto_tree_add_item(tree, *bt_gatt_characteristics[idx_y].hfindex,
                tvb, offset+characteristic_value_length,
                bt_gatt_characteristics[idx_y].characteristic_value_length, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(pi);
            characteristic_value_length+=bt_gatt_characteristics[idx_y].characteristic_value_length;
        } else {
            return 0;
        }
    }
    return characteristic_value_length;
}

static int
find_btmesh_property_characteristic_idx(uint16_t property_id)
{
    int characteristic_idx;
    uint16_t characteristic_id = 0;

    characteristic_id = find_characteristic_id(property_id);
    if (characteristic_id == NOT_SUPPORTED_PROPERTY) {
        return NOT_SUPPORTED_CHARACTERISTIC;
    }
    characteristic_idx = find_characteristic_idx(characteristic_id);
    if (characteristic_idx == NOT_SUPPORTED_CHARACTERISTIC) {
        return NOT_SUPPORTED_CHARACTERISTIC;
    }
    return characteristic_idx;
}

static int
find_btmesh_property_length(uint16_t property_id)
{
    int characteristic_idx;
    uint16_t characteristic_id = 0;

    characteristic_id = find_characteristic_id(property_id);
    if (characteristic_id == NOT_SUPPORTED_PROPERTY) {
        return 0;
    }
    characteristic_idx = find_characteristic_idx(characteristic_id);
    if (characteristic_idx == NOT_SUPPORTED_CHARACTERISTIC) {
        return 0;
    }
    return bt_gatt_characteristics[characteristic_idx].characteristic_value_length;
}

static uint16_t
dissect_btmesh_property(proto_tree *tree, int p_id, tvbuff_t *tvb, int offset, uint16_t property_id, int length_hint)
{
    int characteristic_idx;
    int characteristic_length;
    int guessed_property_length;
    uint16_t delta = 0;

    if (length_hint == PROPERTY_LENGTH_NO_HINT) {
        guessed_property_length = tvb_reported_length_remaining(tvb, offset);
    } else {
        guessed_property_length = length_hint;
    }

    characteristic_idx = find_btmesh_property_characteristic_idx(property_id);
    if (characteristic_idx != NOT_SUPPORTED_CHARACTERISTIC) {
        characteristic_length = bt_gatt_characteristics[characteristic_idx].characteristic_value_length;
        if (characteristic_length > 0 ) {
            proto_tree_add_item(tree, p_id, tvb, offset, characteristic_length, ENC_NA);
            dissect_btmesh_property_idx(tvb, tree, offset, characteristic_idx);
            delta = characteristic_length;
        } else {
            proto_tree_add_item(tree, p_id, tvb, offset, guessed_property_length, ENC_NA);
            delta = guessed_property_length;
        }
    } else {
        proto_tree_add_item(tree, p_id, tvb, offset, guessed_property_length, ENC_NA);
        delta = guessed_property_length;
    }
    return delta;
}

static int
dissect_sensor_cadence(proto_tree *tree, tvbuff_t *tvb, int offset, uint16_t property_id, uint8_t trigger_type, const bt_sensor_cadence_dissector_t *sensor_cadence_hfs)
{
    int initial_offset = offset;
    int guessed_property_length;
    int trigger_delta_length = 0;
    int fast_cadence_length = 0;

    //Trigger delta length
    if ( trigger_type == SENSOR_CADENCE_TRIGGER_TYPE_PROPERTY) {
        //Find or guess trigger delta and fast cadence fields length
        trigger_delta_length = find_btmesh_property_length(property_id);
        if (trigger_delta_length == 0) {
            guessed_property_length = tvb_reported_length_remaining(tvb, offset) - 1;
            if (guessed_property_length % 4 == 0) {
                trigger_delta_length = guessed_property_length/4;
            } else {
                //Failed to guess fields length
                trigger_delta_length = PROPERTY_LENGTH_NO_HINT;
            }
        }
        fast_cadence_length = trigger_delta_length;
    } else {
        //Trigger delta length is always 2 octets here
        trigger_delta_length = 2;
        //Find or guess fast cadence field length
        fast_cadence_length = find_btmesh_property_length(property_id);
        if (fast_cadence_length == 0) {
            guessed_property_length = tvb_reported_length_remaining(tvb, offset) - 1 - 2 * trigger_delta_length;
            if (guessed_property_length % 2 == 0) {
                fast_cadence_length = guessed_property_length/2;
            } else {
                //Failed to guess field length
                fast_cadence_length = PROPERTY_LENGTH_NO_HINT;
            }
        }
    }

    if (trigger_delta_length != PROPERTY_LENGTH_NO_HINT) {
        //Trigger delta field length is known, so dissect individual fields
        if ( trigger_type == SENSOR_CADENCE_TRIGGER_TYPE_PROPERTY) {
            offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_status_trigger_delta_down, tvb, offset, property_id, trigger_delta_length);
            offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_status_trigger_delta_up, tvb, offset, property_id, trigger_delta_length);
        } else {
            offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_status_trigger_delta_down, tvb, offset, PHONY_PROPERTY_PERCENTAGE_CHANGE_16, trigger_delta_length);
            offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_status_trigger_delta_up, tvb, offset, PHONY_PROPERTY_PERCENTAGE_CHANGE_16, trigger_delta_length);
        }
        proto_tree_add_item(tree, *sensor_cadence_hfs->hf_status_min_interval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (fast_cadence_length != PROPERTY_LENGTH_NO_HINT) {
            //Fast cadence field length is known
            offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_fast_cadence_low, tvb, offset, property_id, fast_cadence_length);
            offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_fast_cadence_high, tvb, offset, property_id, fast_cadence_length);
        } else {
           offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_remainder_not_dissected, tvb, offset, property_id, tvb_reported_length_remaining(tvb, offset));
        }
    } else {
        //Property field length is unknown, fail to dissect
        offset+=dissect_btmesh_property(tree, *sensor_cadence_hfs->hf_remainder_not_dissected, tvb, offset, property_id, tvb_reported_length_remaining(tvb, offset));
    }
    return offset - initial_offset;
}

static int
dissect_property_raw_value_entry(proto_tree *tree, tvbuff_t *tvb, int offset, uint16_t property_id, const bt_property_raw_value_entry_t *property_raw_value_entry_hfs)
{
    bool display_raw;
    int idx;
    int initial_offset = offset;
    int guessed_field_length;

    idx = find_btmesh_property_characteristic_idx(property_id);
    display_raw = true;
    guessed_field_length = tvb_reported_length_remaining(tvb, offset);
    if ( idx != NOT_SUPPORTED_CHARACTERISTIC) {
        if (bt_gatt_characteristics[idx].dissector_type == DISSECTOR_SIMPLE) {
            //Single value
            offset+=dissect_btmesh_property(tree, *property_raw_value_entry_hfs->hf_raw_value_a, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
            display_raw = false;
        } else {
            //Three values expected
            int idx_3 = find_column_properties_idx(idx);
            if (idx_3 != NOT_SUPPORTED_CHARACTERISTIC) {
                int idx_x = find_characteristic_idx(btmesh_column_properties[idx_3].x_characteristic_id);
                if (idx_x != NOT_SUPPORTED_CHARACTERISTIC) {
                    if ( bt_gatt_characteristics[idx_x].characteristic_value_length != 0) {
                        if (bt_gatt_characteristics[idx_x].hfindex != NULL &&
                            bt_gatt_characteristics[idx_x].dissector_type == DISSECTOR_SIMPLE)
                        {
                            //Full dissection
                            display_raw = false;
                            proto_tree_add_item(tree, *property_raw_value_entry_hfs->hf_raw_value_a, tvb, offset, bt_gatt_characteristics[idx_x].characteristic_value_length, ENC_NA);
                            dissect_btmesh_property_idx(tvb, tree, offset, idx_x);
                            offset+=bt_gatt_characteristics[idx_x].characteristic_value_length;
                            proto_tree_add_item(tree, *property_raw_value_entry_hfs->hf_raw_value_b, tvb, offset, bt_gatt_characteristics[idx_x].characteristic_value_length, ENC_NA);
                            dissect_btmesh_property_idx(tvb, tree, offset, idx_x);
                            offset+=bt_gatt_characteristics[idx_x].characteristic_value_length;
                            //Value C
                            int idx_y = find_characteristic_idx(btmesh_column_properties[idx_3].y_characteristic_id);
                            if (idx_y != NOT_SUPPORTED_CHARACTERISTIC &&
                                bt_gatt_characteristics[idx_y].characteristic_value_length != 0 &&
                                bt_gatt_characteristics[idx_y].hfindex != NULL &&
                                bt_gatt_characteristics[idx_y].dissector_type == DISSECTOR_SIMPLE)
                            {
                                proto_tree_add_item(tree, *property_raw_value_entry_hfs->hf_raw_value_c, tvb, offset, bt_gatt_characteristics[idx_y].characteristic_value_length, ENC_NA);
                                dissect_btmesh_property_idx(tvb, tree, offset, idx_y);
                                offset+=bt_gatt_characteristics[idx_y].characteristic_value_length;
                            } else {
                                proto_tree_add_item(tree, *property_raw_value_entry_hfs->hf_raw_value_c, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
                                offset+=tvb_reported_length_remaining(tvb, offset);
                            }
                        } else {
                            //Raw value, but length is known
                            guessed_field_length = bt_gatt_characteristics[idx_x].characteristic_value_length;
                        }
                    }
                }
            }
        }
    }
    if (display_raw) {
        //Raw value, no interpretation, just Value A
        proto_tree_add_item(tree, *property_raw_value_entry_hfs->hf_raw_value_a, tvb, offset, guessed_field_length, ENC_NA);
        offset+=guessed_field_length;
    }
    return offset - initial_offset;
}

static int
dissect_columns_raw_value(proto_tree *sub_tree, tvbuff_t *tvb, int offset, uint16_t property_id, const bt_property_columns_raw_value_t *columns_raw_value_hfs)
{
    bool display_raw;
    int idx;
    int initial_offset = offset;
    int guessed_field_length;

    idx = find_btmesh_property_characteristic_idx(property_id);
    display_raw = true;
    guessed_field_length = tvb_reported_length_remaining(tvb, offset);

    if (columns_raw_value_hfs->hf_raw_value_a2 != NULL && guessed_field_length > 1) {
        //Two values are expected
        guessed_field_length = guessed_field_length / 2;
    }

    if ( idx != NOT_SUPPORTED_CHARACTERISTIC) {
        if (bt_gatt_characteristics[idx].dissector_type == DISSECTOR_SIMPLE) {
            //Index - phony characteristics, 2 octets
            display_raw = false;
            offset+=dissect_btmesh_property(sub_tree, *columns_raw_value_hfs->hf_raw_value_a1, tvb, offset, PHONY_PROPERTY_INDEX, 2);
            if (columns_raw_value_hfs->hf_raw_value_a2 != NULL ) {
                offset+=dissect_btmesh_property(sub_tree, *columns_raw_value_hfs->hf_raw_value_a2, tvb, offset, PHONY_PROPERTY_INDEX, 2);
            }
        } else {
            //DISSECTOR_THREE_VALUES, first value
            int idx_3 = find_column_properties_idx(idx);
            if (idx_3 != NOT_SUPPORTED_CHARACTERISTIC) {
                int idx_x = find_characteristic_idx(btmesh_column_properties[idx_3].x_characteristic_id);
                if (idx_x != NOT_SUPPORTED_CHARACTERISTIC) {
                    if ( bt_gatt_characteristics[idx_x].characteristic_value_length != 0) {
                        if (bt_gatt_characteristics[idx_x].hfindex != NULL &&
                            bt_gatt_characteristics[idx_x].dissector_type == DISSECTOR_SIMPLE)
                        {
                            //full dissection
                            display_raw = false;
                            proto_tree_add_item(sub_tree, *columns_raw_value_hfs->hf_raw_value_a1, tvb, offset, bt_gatt_characteristics[idx_x].characteristic_value_length, ENC_NA);
                            dissect_btmesh_property_idx(tvb, sub_tree, offset, idx_x);
                            offset+=bt_gatt_characteristics[idx_x].characteristic_value_length;
                            if (columns_raw_value_hfs->hf_raw_value_a2 != NULL ) {
                                proto_tree_add_item(sub_tree, *columns_raw_value_hfs->hf_raw_value_a2, tvb, offset, bt_gatt_characteristics[idx_x].characteristic_value_length, ENC_NA);
                                dissect_btmesh_property_idx(tvb, sub_tree, offset, idx_x);
                                offset+=bt_gatt_characteristics[idx_x].characteristic_value_length;
                            }
                        } else {
                            //raw, but known length
                            guessed_field_length = bt_gatt_characteristics[idx_x].characteristic_value_length;
                        }
                    }
                }
            }
        }
    }
    if (display_raw) {
        //Raw values, no interpretation
        proto_tree_add_item(sub_tree, *columns_raw_value_hfs->hf_raw_value_a1, tvb, offset, guessed_field_length, ENC_NA);
        offset+=guessed_field_length;
        if (columns_raw_value_hfs->hf_raw_value_a2 != NULL ) {
            proto_tree_add_item(sub_tree, *columns_raw_value_hfs->hf_raw_value_a2, tvb, offset, guessed_field_length, ENC_NA);
            offset+=guessed_field_length;
        }
    }
    return offset - initial_offset;
}

static void
dissect_btmesh_model_layer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree *sub_tree;
    tvbuff_t *payload_tvb;
    uint32_t opcode;
    uint16_t vendor;
    proto_item *netapp_index_item, *app_index_item, *pub_app_index_item, *net_index_item;
    proto_item *relayretransmit_index, *transmit_index;
    proto_item *publishperiod_item, *publishretransmit_item;
    proto_item *month_item, *day_of_week_item, *scheduler_item;

    proto_tree *netapp_index_sub_tree, *app_index_sub_tree, *pub_app_index_sub_tree, *net_index_sub_tree;
    proto_tree *relayretransmit_sub_tree, *transmit_sub_tree, *subscriptionlist_tree;
    proto_tree *publishperiod_sub_tree, *publishretransmit_sub_tree;
    proto_tree *element_sub_tree, *model_sub_tree, *vendor_sub_tree;
    proto_tree *netkeylist_tree, *appkeylist_tree;
    proto_tree *fault_array_tree;
    proto_tree *sceneslist_tree, *month_sub_tree, *day_of_week_sub_tree;
    proto_tree *scheduler_tree;
    proto_tree *user_property_ids_tree;
    proto_tree *admin_property_ids_tree;
    proto_tree *manufacturer_property_ids_tree;
    proto_tree *generic_client_property_ids_tree;
    proto_tree *sensor_setting_property_ids_tree;
    proto_tree *root_tree = proto_tree_get_parent_tree(tree);

    uint32_t netkeyindexes, appkeyindexes;
    uint32_t nums, numv, element;
    unsigned i;
    uint16_t property_id;
    uint8_t trigger_type;
    uint32_t mpid_format, mpid_property_id, mpid_length;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_model_layer, NULL, "Model Layer");

    opcode = tvb_get_uint8(tvb, offset);
    if (opcode & 0x80) {
        if (opcode & 0x40) {
            /* Vendor opcode */
            proto_tree_add_item(sub_tree, hf_btmesh_model_layer_vendor_opcode, tvb, offset, 1, ENC_NA);
            vendor = tvb_get_uint16(tvb, offset + 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sub_tree, hf_btmesh_model_layer_vendor, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
            payload_tvb = tvb_new_subset_remaining(tvb, offset);
            col_set_str(pinfo->cinfo, COL_INFO, "Access Message - Vendor Opcode");
            dissector_try_uint_new(btmesh_model_vendor_dissector_table, vendor, payload_tvb, pinfo, root_tree, true, GUINT_TO_POINTER(vendor));
            offset+=3;
        } else {
            /* Two octet opcode */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_model_layer_opcode, tvb, offset, 2, ENC_NA, &opcode);
            col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, btmesh_models_opcode_vals, "Access Message Unknown"));
            offset+=2;
        }
    } else {
        /* One octet opcode */
        proto_tree_add_item(sub_tree, hf_btmesh_model_layer_opcode, tvb, offset, 1, ENC_NA);
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, btmesh_models_opcode_vals, "Access Message Unknown"));
        offset++;
    }

    switch (opcode) {
    case CONFIG_APPKEY_ADD:
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_add_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_add_appkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_APPKEY_UPDATE:
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_update_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_update_appkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_COMPOSITION_DATA_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_page, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_pid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_vid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_status_crpl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset,
            hf_btmesh_config_composition_data_status_features,
            ett_btmesh_config_composition_data_status_features,
            config_composition_data_status_features_headers,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        offset+=2;
        /* Elements */
        element = 1;
        while (tvb_reported_length_remaining(tvb, offset) > 2) {
            nums = tvb_get_uint8(tvb, offset + 2 );
            numv = tvb_get_uint8(tvb, offset + 2 + 1);
            element_sub_tree = proto_tree_add_subtree_format(sub_tree, tvb, offset, 4 + nums * 2 + numv * 4, ett_btmesh_config_model_element, NULL, "Element #%u", element);
            proto_tree_add_item(element_sub_tree, hf_btmesh_config_composition_data_status_loc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(element_sub_tree, hf_btmesh_config_composition_data_status_nums, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(element_sub_tree, hf_btmesh_config_composition_data_status_numv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            if (nums > 0 ) {
                model_sub_tree = proto_tree_add_subtree(element_sub_tree, tvb, offset, nums * 2, ett_btmesh_config_model_model, NULL, "SIG Models");
                for (i = 0; i < nums; i++) {
                    proto_tree_add_item(model_sub_tree, hf_btmesh_config_composition_data_status_sig_model, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset+=2;
                }
            }
            if (numv > 0 ) {
                vendor_sub_tree = proto_tree_add_subtree(element_sub_tree, tvb, offset, numv * 4, ett_btmesh_config_model_vendor, NULL, "Vendor Models");
                for (i = 0; i < numv; i++) {
                    proto_tree_add_item(vendor_sub_tree, hf_btmesh_config_composition_data_status_vendor_model, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset+=4;
                }
            }
            element++;
        }
        break;
    case CONFIG_MODEL_PUBLICATION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        pub_app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_appkey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        pub_app_index_sub_tree= proto_item_add_subtree(pub_app_index_item, ett_btmesh_config_model_pub_app_index);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_set_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_set_credentialflag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_set_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_set_publishperiod_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_set_publishperiod_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishretransmit_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_publishretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishretransmit_sub_tree = proto_item_add_subtree(publishretransmit_item, ett_btmesh_config_model_publishretransmit);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_set_publishretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_set_publishretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_set_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case HEALTH_CURRENT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_current_status_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_current_status_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        fault_array_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_fault_array, NULL, "FaultArray");
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(fault_array_tree, hf_btmesh_health_current_status_fault, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case HEALTH_FAULT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_status_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_status_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        fault_array_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_fault_array, NULL, "FaultArray");
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(fault_array_tree, hf_btmesh_health_fault_status_fault, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case CONFIG_HEARTBEAT_PUBLICATION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_countlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset,
            hf_btmesh_config_heartbeat_publication_status_features,
            ett_btmesh_config_heartbeat_publication_status_features,
            config_heartbeat_publication_status_features_headers,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        offset+=2;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_APPKEY_DELETE:
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        break;
    case CONFIG_APPKEY_GET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_get_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_get_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_get_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_APPKEY_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_list_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_list_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_appkey_list_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        appkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_appkey_list, NULL, "AppKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                appkeyindexes = tvb_get_uint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x000FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex, tvb, offset + 1, 2, (appkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                appkeyindexes = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x0FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_appkey_list_appkeyindex_rfu, tvb, offset, 2, (appkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
    case CONFIG_APPKEY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        netapp_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_appkey_status_netkeyindexandappkeyindex, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        netapp_index_sub_tree = proto_item_add_subtree(netapp_index_item, ett_btmesh_config_model_netapp_index);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_net, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(netapp_index_sub_tree, hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_app, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        break;
    case HEALTH_ATTENTION_GET:
        break;
    case HEALTH_ATTENTION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_health_attention_set_attention, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_ATTENTION_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_attention_set_unacknowledged_attention, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_ATTENTION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_attention_status_attention, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_COMPOSITION_DATA_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_composition_data_get_page, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_BEACON_GET:
        break;
    case CONFIG_BEACON_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_beacon_set_beacon, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_BEACON_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_beacon_status_beacon, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_DEFAULT_TTL_GET:
        break;
    case CONFIG_DEFAULT_TTL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_default_ttl_set_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_DEFAULT_TTL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_default_ttl_status_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_FRIEND_GET:
        break;
    case CONFIG_FRIEND_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_friend_set_friend, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_FRIEND_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_friend_status_friend, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_GATT_PROXY_GET:
        break;
    case CONFIG_GATT_PROXY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_gatt_proxy_set_gattproxy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_GATT_PROXY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_gatt_proxy_status_gattproxy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_KEY_REFRESH_PHASE_GET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_get_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_get_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_get_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_KEY_REFRESH_PHASE_SET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_set_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_set_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_set_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_set_transition, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_KEY_REFRESH_PHASE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_key_refresh_phase_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_key_refresh_phase_status_phase, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_MODEL_PUBLICATION_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_get_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_PUBLICATION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        pub_app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_appkey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        pub_app_index_sub_tree= proto_item_add_subtree(pub_app_index_item, ett_btmesh_config_model_pub_app_index);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_status_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_status_credentialflag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_status_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_status_publishperiod_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_status_publishperiod_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishretransmit_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_publishretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishretransmit_sub_tree = proto_item_add_subtree(publishretransmit_item, ett_btmesh_config_model_publishretransmit);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_status_publishretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_status_publishretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_status_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishaddress, tvb, offset, 16, ENC_NA);
        offset+=16;
        pub_app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_appkey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        pub_app_index_sub_tree= proto_item_add_subtree(pub_app_index_item, ett_btmesh_config_model_pub_app_index);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_credentialflag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pub_app_index_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishperiod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishperiod_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishperiod_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        publishretransmit_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishretransmit_sub_tree = proto_item_add_subtree(publishretransmit_item, ett_btmesh_config_model_publishretransmit);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishretransmit_sub_tree, hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_publication_virtual_address_set_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_ADD:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_add_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_DELETE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_DELETE_ALL:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_all_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_all_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_delete_all_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_OVERWRITE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_overwrite_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_status_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_label, tvb, offset, 16, ENC_NA);
        offset+=16;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_add_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_label, tvb, offset, 16, ENC_NA);
        offset+=16;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_delete_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_label, tvb, offset, 16, ENC_NA);
        offset+=16;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_subscription_virtual_address_overwrite_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_NETWORK_TRANSMIT_GET:
        break;
    case CONFIG_NETWORK_TRANSMIT_SET:
        transmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_network_transmit_set_networktransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        transmit_sub_tree = proto_item_add_subtree(transmit_index, ett_btmesh_config_model_network_transmit);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_set_networktransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_set_networktransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_NETWORK_TRANSMIT_STATUS:
        transmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_network_transmit_status_networktransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        transmit_sub_tree = proto_item_add_subtree(transmit_index, ett_btmesh_config_model_network_transmit);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_status_networktransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(transmit_sub_tree, hf_btmesh_config_network_transmit_status_networktransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_RELAY_GET:
        break;
    case CONFIG_RELAY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_relay_set_relay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        relayretransmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_relay_set_relayretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        relayretransmit_sub_tree = proto_item_add_subtree(relayretransmit_index, ett_btmesh_config_model_relayretransmit);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_set_relayretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_set_relayretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_RELAY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_relay_status_relay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        relayretransmit_index = proto_tree_add_item(sub_tree, hf_btmesh_config_relay_status_relayretransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        relayretransmit_sub_tree = proto_item_add_subtree(relayretransmit_index, ett_btmesh_config_model_relayretransmit);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_status_relayretransmit_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(relayretransmit_sub_tree, hf_btmesh_config_relay_status_relayretransmit_intervalsteps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_SIG_MODEL_SUBSCRIPTION_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_SIG_MODEL_SUBSCRIPTION_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_subscription_list_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        subscriptionlist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_addresses, NULL, "Addresses");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(subscriptionlist_tree, hf_btmesh_config_sig_model_subscription_list_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_VENDOR_MODEL_SUBSCRIPTION_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_get_modelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        break;
    case CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_subscription_list_modelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        subscriptionlist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_addresses, NULL, "Addresses");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(subscriptionlist_tree, hf_btmesh_config_vendor_model_subscription_list_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_LOW_POWER_NODE_POLLTIMEOUT_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_low_power_node_polltimeout_get_lpnaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_LOW_POWER_NODE_POLLTIMEOUT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_low_power_node_polltimeout_status_lpnaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_low_power_node_polltimeout_status_polltimeout, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        break;
    case HEALTH_FAULT_CLEAR:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_clear_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_CLEAR_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_clear_unacknowledged_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_get_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_TEST:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_FAULT_TEST_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_unacknowledged_test_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_health_fault_test_unacknowledged_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case HEALTH_PERIOD_GET:
        break;
    case HEALTH_PERIOD_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_health_period_set_fast_period_divisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_PERIOD_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_health_period_set_unacknowledged_fast_period_divisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case HEALTH_PERIOD_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_health_period_status_fast_period_divisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_HEARTBEAT_PUBLICATION_GET:
        break;
    case CONFIG_HEARTBEAT_PUBLICATION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_countlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_ttl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset,
            hf_btmesh_config_heartbeat_publication_set_features,
            ett_btmesh_config_heartbeat_publication_set_features,
            config_heartbeat_publication_set_features_headers,
            ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
        offset+=2;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_publication_set_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_set_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_heartbeat_publication_set_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_HEARTBEAT_SUBSCRIPTION_GET:
        break;
    case CONFIG_HEARTBEAT_SUBSCRIPTION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_set_source, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_set_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_set_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_source, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_destination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_periodlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_countlog, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_minhops, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_heartbeat_subscription_status_maxhops, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_MODEL_APP_BIND:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        app_index_sub_tree = proto_item_add_subtree(app_index_item, ett_btmesh_config_model_app_index);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_bind_appkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_bind_appkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_bind_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_APP_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        app_index_sub_tree = proto_item_add_subtree(app_index_item, ett_btmesh_config_model_app_index);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_status_appkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_status_appkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_status_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_MODEL_APP_UNBIND:
        proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        app_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_appkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        app_index_sub_tree = proto_item_add_subtree(app_index_item, ett_btmesh_config_model_app_index);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_unbind_appkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(app_index_sub_tree, hf_btmesh_config_model_app_unbind_appkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        if (tvb_reported_length_remaining(tvb, offset) > 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_vendormodelidentifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            proto_tree_add_item(sub_tree, hf_btmesh_config_model_app_unbind_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case CONFIG_NETKEY_ADD:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_add_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_add_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_add_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_add_netkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_NETKEY_DELETE:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_delete_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_delete_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_delete_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_NETKEY_GET:
        break;
    case CONFIG_NETKEY_LIST:
        netkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_netkey_list, NULL, "NetKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                netkeyindexes = tvb_get_uint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex, tvb, offset, 2, netkeyindexes & 0x000FFF);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex, tvb, offset + 1, 2, (netkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                netkeyindexes = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex, tvb, offset, 2, netkeyindexes & 0x0FFF);
                proto_tree_add_uint(netkeylist_tree, hf_btmesh_config_netkey_list_netkeyindex_rfu, tvb, offset, 2, (netkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
    case CONFIG_NETKEY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_NETKEY_UPDATE:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_update_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_update_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_netkey_update_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_netkey_update_netkey, tvb, offset, 16, ENC_NA);
        offset+=16;
        break;
    case CONFIG_NODE_IDENTITY_GET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_get_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_get_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_get_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_NODE_IDENTITY_SET:
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_set_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_set_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_set_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_set_identity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_NODE_IDENTITY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_status_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        net_index_item = proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_status_netkeyindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        net_index_sub_tree = proto_item_add_subtree(net_index_item, ett_btmesh_config_model_net_index);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_status_netkeyindex_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(net_index_sub_tree, hf_btmesh_config_node_identity_status_netkeyindex_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_node_identity_status_identity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case CONFIG_NODE_RESET:
        break;
    case CONFIG_NODE_RESET_STATUS:
        break;
    case CONFIG_SIG_MODEL_APP_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case CONFIG_SIG_MODEL_APP_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_sig_model_app_list_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        appkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_appkey_list, NULL, "AppKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                appkeyindexes = tvb_get_uint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x000FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex, tvb, offset + 1, 2, (appkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                appkeyindexes = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x0FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_sig_model_app_list_appkeyindex_rfu, tvb, offset, 2, (appkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
    case CONFIG_VENDOR_MODEL_APP_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_get_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_get_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=4;
        break;
    case CONFIG_VENDOR_MODEL_APP_LIST:
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_list_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_list_elementaddress, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_config_vendor_model_app_list_modelidentifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=4;
        appkeylist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_config_model_appkey_list, NULL, "AppKeyIndexes");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            if (tvb_reported_length_remaining(tvb, offset) >= 3) {
                appkeyindexes = tvb_get_uint24(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x000FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex, tvb, offset + 1, 2, (appkeyindexes >> 12 ) & 0x000FFF);
                offset+=3;
            } else {
                appkeyindexes = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex, tvb, offset, 2, appkeyindexes & 0x0FFF);
                proto_tree_add_uint(appkeylist_tree, hf_btmesh_config_vendor_model_app_list_appkeyindex_rfu, tvb, offset, 2, (appkeyindexes >> 12 ) & 0xF);
                offset+=2;
            }
        }
        break;
//
//  ******************************************************************************************
//
    case GENERIC_LOCATION_GLOBAL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_status_global_latitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_status_global_longitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_status_global_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_LOCATION_GLOBAL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_set_global_latitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_set_global_longitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_set_global_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_LOCATION_GLOBAL_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_set_unacknowledged_global_latitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_set_unacknowledged_global_longitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_global_set_unacknowledged_global_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_ONOFF_GET:
        break;
    case GENERIC_ONOFF_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_onoff_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_onoff_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_ONOFF_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_unacknowledged_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_onoff_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_onoff_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_ONOFF_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_status_present_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_status_target_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_onoff_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_onoff_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_onoff_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_LEVEL_GET:
        break;
    case GENERIC_LEVEL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_level_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_level_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_LEVEL_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_unacknowledged_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_level_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_level_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_level_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_LEVEL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_level_status_present_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_generic_level_status_target_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_level_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_level_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_level_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_DELTA_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_delta_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_delta_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_delta_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_DELTA_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_unacknowledged_delta_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_delta_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_delta_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_delta_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_MOVE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_delta_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_move_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_move_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_MOVE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_unacknowledged_delta_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_move_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_move_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_move_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_DEFAULT_TRANSITION_TIME_GET:
        break;
    case GENERIC_DEFAULT_TRANSITION_TIME_SET:
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_default_transition_time_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_default_transition_time_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_default_transition_time_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_DEFAULT_TRANSITION_TIME_SET_UNACKNOWLEDGED:
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_DEFAULT_TRANSITION_TIME_STATUS:
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_default_transition_time_status_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_default_transition_time_status_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_default_transition_time_status_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_ONPOWERUP_GET:
        break;
    case GENERIC_ONPOWERUP_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onpowerup_status_onpowerup, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_ONPOWERUP_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onpowerup_set_onpowerup, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_ONPOWERUP_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_onpowerup_set_unacknowledged_onpowerup, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_POWER_LEVEL_GET:
        break;
    case GENERIC_POWER_LEVEL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_power_level_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_power_level_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_POWER_LEVEL_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_unacknowledged_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_power_level_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_power_level_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_POWER_LEVEL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_status_present_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_status_target_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_generic_power_level_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_power_level_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_generic_power_level_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case GENERIC_POWER_LAST_GET:
        break;
    case GENERIC_POWER_LAST_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_last_status_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_POWER_DEFAULT_GET:
        break;
    case GENERIC_POWER_DEFAULT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_default_status_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_POWER_RANGE_GET:
        break;
    case GENERIC_POWER_RANGE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_range_status_status_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_range_status_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_range_status_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_POWER_DEFAULT_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_default_set_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_POWER_DEFAULT_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_default_set_unacknowledged_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_POWER_RANGE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_range_set_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_range_set_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_POWER_RANGE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_range_set_unacknowledged_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_power_range_set_unacknowledged_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_BATTERY_GET:
        break;
    case GENERIC_BATTERY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_battery_status_battery_level, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_battery_status_time_to_discharge, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_battery_status_time_to_charge, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_battery_status_flags_presence, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_battery_status_flags_indicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_battery_status_flags_charging, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_battery_status_flags_serviceability, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_LOCATION_GLOBAL_GET:
        break;
    case GENERIC_LOCATION_LOCAL_GET:
        break;
    case GENERIC_LOCATION_LOCAL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_local_north, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_local_east, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_local_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_floor_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_uncertainty_stationary, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_uncertainty_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_uncertainty_update_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_status_uncertainty_precision, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_LOCATION_LOCAL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_local_north, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_local_east, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_local_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_floor_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_uncertainty_stationary, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_uncertainty_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_uncertainty_update_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_uncertainty_precision, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_LOCATION_LOCAL_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_local_north, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_local_east, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_local_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_floor_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_stationary, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_update_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_precision, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;

    case SCENE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_status_status_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_scene_status_current_scene, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_scene_status_target_scene, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_scene_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scene_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scene_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case SCENE_GET:
        break;
    case SCENE_RECALL:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scene_recall_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scene_recall_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case SCENE_RECALL_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_unacknowledged_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scene_recall_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scene_recall_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_scene_recall_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case SCENE_REGISTER_GET:
        break;
    case SCENE_REGISTER_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_register_status_status_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_scene_register_status_current_scene, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        sceneslist_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_scene_register_status_scenes, NULL, "Scenes");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(sceneslist_tree, hf_btmesh_scene_register_status_scene, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case SCENE_STORE:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_store_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SCENE_STORE_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_store_unacknowledged_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SCENE_DELETE:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_delete_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SCENE_DELETE_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_scene_delete_unacknowledged_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case TIME_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_time_set_tai_seconds, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset+=5;
        proto_tree_add_item(sub_tree, hf_btmesh_time_set_subsecond, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_time_set_uncertainty, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_time_set_time_authority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_time_set_tai_utc_delta, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_time_set_time_zone_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case TIME_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_time_status_tai_seconds, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset+=5;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_time_status_subsecond, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_time_status_uncertainty, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_time_status_time_authority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(sub_tree, hf_btmesh_time_status_tai_utc_delta, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(sub_tree, hf_btmesh_time_status_time_zone_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case SCHEDULER_ACTION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_year, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        month_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_month, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        month_sub_tree = proto_item_add_subtree(month_item, ett_btmesh_scheduler_model_month);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_january, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_february, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_march, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_april, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_may, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_june, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_july, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_august, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_september, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_october, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_november, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_december, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_day, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_hour, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_minute, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_second, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        day_of_week_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_day_of_week, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        day_of_week_sub_tree = proto_item_add_subtree(day_of_week_item, ett_btmesh_scheduler_model_day_of_week);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_monday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_tuesday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_wednesday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_thursday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_friday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_saturday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_sunday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scheduler_action_status_schedule_register_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scheduler_action_status_schedule_register_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
         offset+=1;
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_status_schedule_register_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SCHEDULER_ACTION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_year, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        month_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_month, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        month_sub_tree = proto_item_add_subtree(month_item, ett_btmesh_scheduler_model_month);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_january, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_february, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_march, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_april, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_may, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_june, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_july, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_august, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_september, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_october, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_november, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_december, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_day, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_hour, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_minute, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_second, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        day_of_week_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_day_of_week, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        day_of_week_sub_tree = proto_item_add_subtree(day_of_week_item, ett_btmesh_scheduler_model_day_of_week);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_monday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_tuesday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_wednesday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_thursday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_friday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_saturday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_sunday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scheduler_action_set_schedule_register_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scheduler_action_set_schedule_register_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_schedule_register_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SCHEDULER_ACTION_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_year, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        month_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_month, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        month_sub_tree = proto_item_add_subtree(month_item, ett_btmesh_scheduler_model_month);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_january, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_february, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_march, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_april, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_may, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_june, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_july, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_august, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_september, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_october, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_november, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(month_sub_tree, hf_btmesh_scheduler_schedule_register_month_december, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_day, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=3;
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_hour, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_minute, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_second, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        day_of_week_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_day_of_week, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        day_of_week_sub_tree = proto_item_add_subtree(day_of_week_item, ett_btmesh_scheduler_model_day_of_week);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_monday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_tuesday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_wednesday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_thursday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_friday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_saturday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(day_of_week_sub_tree, hf_btmesh_scheduler_schedule_register_day_of_week_sunday, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset+=1;
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_scene_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case TIME_GET:
        break;
    case TIME_ROLE_GET:
        break;
    case TIME_ROLE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_time_role_set_time_role, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case TIME_ROLE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_time_role_status_time_role, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case TIME_ZONE_GET:
        break;
    case TIME_ZONE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_time_zone_set_time_zone_offset_new, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_time_zone_set_tai_of_zone_change, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset+=5;
        break;
    case TIME_ZONE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_time_zone_status_time_zone_offset_current, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_time_zone_status_time_zone_offset_new, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_time_zone_status_tai_of_zone_change, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset+=5;
        break;
    case TAI_UTC_DELTA_GET:
        break;
    case TAI_UTC_DELTA_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_set_tai_utc_delta_new, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_set_padding, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_set_tai_of_delta_change, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset+=5;
        break;
    case TAI_UTC_DELTA_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_status_tai_utc_delta_current, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_status_padding_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_status_tai_utc_delta_new, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_status_padding_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_tai_utc_delta_status_tai_of_delta_change, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset+=5;
        break;
    case SCHEDULER_ACTION_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_scheduler_action_get_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case SCHEDULER_GET:
        break;
    case SCHEDULER_STATUS:
        scheduler_item = proto_tree_add_item(sub_tree, hf_btmesh_scheduler_status_schedules, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        scheduler_tree = proto_item_add_subtree(scheduler_item, ett_btmesh_scheduler_schedules);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_4, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_6, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_7, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_8, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_9, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_10, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_11, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_12, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_13, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_14, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scheduler_tree, hf_btmesh_scheduler_status_schedules_schedule_15, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LC_PROPERTY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_property_set_light_lc_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_light_lc_property_set_light_lc_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case LIGHT_LC_PROPERTY_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_property_set_unacknowledged_light_lc_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_light_lc_property_set_unacknowledged_light_lc_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case LIGHT_LC_PROPERTY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_property_status_light_lc_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_light_lc_property_status_light_lc_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case LIGHT_LIGHTNESS_GET:
        break;
    case LIGHT_LIGHTNESS_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LIGHTNESS_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_unacknowledged_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LIGHTNESS_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_status_present_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_status_target_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LIGHTNESS_LINEAR_GET:
        break;
    case LIGHT_LIGHTNESS_LINEAR_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_linear_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_linear_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LIGHTNESS_LINEAR_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_unacknowledged_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LIGHTNESS_LINEAR_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_status_present_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_status_target_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_linear_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_linear_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lightness_linear_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LIGHTNESS_LAST_GET:
        break;
    case LIGHT_LIGHTNESS_LAST_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_last_status_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LIGHTNESS_DEFAULT_GET:
        break;
    case LIGHT_LIGHTNESS_DEFAULT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_default_status_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LIGHTNESS_RANGE_GET:
        break;
    case LIGHT_LIGHTNESS_RANGE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_range_status_status_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_range_status_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_range_status_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LIGHTNESS_DEFAULT_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_default_set_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LIGHTNESS_DEFAULT_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_default_set_unacknowledged_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LIGHTNESS_RANGE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_range_set_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_range_set_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LIGHTNESS_RANGE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_range_set_unacknowledged_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lightness_range_set_unacknowledged_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_CTL_GET:
        break;
    case LIGHT_CTL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_ctl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_ctl_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_CTL_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_unacknowledged_ctl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_unacknowledged_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_unacknowledged_ctl_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_CTL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_status_present_ctl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_status_present_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_status_target_ctl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_status_target_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_CTL_TEMPERATURE_GET:
        break;
    case LIGHT_CTL_TEMPERATURE_RANGE_GET:
        break;
    case LIGHT_CTL_TEMPERATURE_RANGE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_range_status_status_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_range_status_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_range_status_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_CTL_TEMPERATURE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_ctl_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_temperature_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_temperature_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_CTL_TEMPERATURE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_unacknowledged_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_unacknowledged_ctl_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_CTL_TEMPERATURE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_status_present_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_status_present_ctl_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_status_target_ctl_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_status_target_ctl_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_temperature_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_ctl_temperature_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_CTL_DEFAULT_GET:
        break;
    case LIGHT_CTL_DEFAULT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_status_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_status_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_status_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_CTL_DEFAULT_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_set_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_set_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_set_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_CTL_DEFAULT_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_set_unacknowledged_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_set_unacknowledged_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_default_set_unacknowledged_delta_uv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_CTL_TEMPERATURE_RANGE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_range_set_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_range_set_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_range_set_unacknowledged_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_ctl_temperature_range_set_unacknowledged_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_HSL_GET:
        break;
    case LIGHT_HSL_HUE_GET:
        break;
    case LIGHT_HSL_HUE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_hue_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_hue_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_HUE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_unacknowledged_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_HUE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_status_present_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_status_target_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_hue_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_hue_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_hue_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_SATURATION_GET:
        break;
    case LIGHT_HSL_SATURATION_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_saturation_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_saturation_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_SATURATION_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_unacknowledged_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_SATURATION_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_status_present_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_status_target_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_saturation_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_saturation_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_saturation_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_hsl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_hsl_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_hsl_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_unacknowledged_hsl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_unacknowledged_hsl_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_unacknowledged_hsl_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_status_hsl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_status_hsl_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_status_hsl_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_TARGET_GET:
        break;
    case LIGHT_HSL_TARGET_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_target_status_hsl_lightness_target, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_target_status_hsl_hue_target, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_target_status_hsl_saturation_target, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_target_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_target_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_hsl_target_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_HSL_DEFAULT_GET:
        break;
    case LIGHT_HSL_DEFAULT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_status_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_status_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_status_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_HSL_RANGE_GET:
        break;
    case LIGHT_HSL_RANGE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_status_status_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_status_hue_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_status_hue_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_status_saturation_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_status_saturation_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_HSL_DEFAULT_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_set_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_set_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_set_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_HSL_DEFAULT_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_set_unacknowledged_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_set_unacknowledged_hue, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_default_set_unacknowledged_saturation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_HSL_RANGE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_hue_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_hue_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_saturation_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_saturation_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_HSL_RANGE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_unacknowledged_hue_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_unacknowledged_hue_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_unacknowledged_saturation_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_hsl_range_set_unacknowledged_saturation_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_XYL_GET:
        break;
    case LIGHT_XYL_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_xyl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_xyl_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_xyl_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_XYL_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_unacknowledged_xyl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_unacknowledged_xyl_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_unacknowledged_xyl_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_XYL_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_status_xyl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_status_xyl_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_status_xyl_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_XYL_TARGET_GET:
        break;
    case LIGHT_XYL_TARGET_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_target_status_target_xyl_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_target_status_target_xyl_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_target_status_target_xyl_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_target_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_target_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_xyl_target_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_XYL_DEFAULT_GET:
        break;
    case LIGHT_XYL_DEFAULT_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_status_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_status_xyl_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_status_xyl_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_XYL_RANGE_GET:
        break;
    case LIGHT_XYL_RANGE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_status_status_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_status_xyl_x_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_status_xyl_x_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_status_xyl_y_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_status_xyl_y_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_XYL_DEFAULT_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_set_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_set_xyl_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_set_xyl_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_XYL_DEFAULT_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_set_unacknowledged_lightness, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_set_unacknowledged_xyl_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_default_set_unacknowledged_xyl_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_XYL_RANGE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_xyl_x_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_xyl_x_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_xyl_y_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_xyl_y_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_XYL_RANGE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_unacknowledged_xyl_x_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_unacknowledged_xyl_x_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_unacknowledged_xyl_y_range_min, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_light_xyl_range_set_unacknowledged_xyl_y_range_max, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case LIGHT_LC_MODE_GET:
        break;
    case LIGHT_LC_MODE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_mode_set_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case LIGHT_LC_MODE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_mode_set_unacknowledged_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case LIGHT_LC_MODE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_mode_status_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case LIGHT_LC_OM_GET:
        break;
    case LIGHT_LC_OM_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_om_set_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case LIGHT_LC_OM_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_om_set_unacknowledged_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case LIGHT_LC_OM_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_om_status_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case LIGHT_LC_LIGHT_ONOFF_GET:
        break;
    case LIGHT_LC_LIGHT_ONOFF_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_light_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lc_light_onoff_set_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lc_light_onoff_set_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LC_LIGHT_ONOFF_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_unacknowledged_light_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_unacknowledged_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_set_unacknowledged_delay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LC_LIGHT_ONOFF_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_status_present_light_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        /* Optional */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_status_target_light_onoff, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            publishperiod_item = proto_tree_add_item(sub_tree, hf_btmesh_light_lc_light_onoff_status_remaining_time, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            publishperiod_sub_tree = proto_item_add_subtree(publishperiod_item, ett_btmesh_config_model_publishperiod);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lc_light_onoff_status_remaining_time_steps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(publishperiod_sub_tree, hf_btmesh_light_lc_light_onoff_status_remaining_time_resolution, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
        }
        break;
    case LIGHT_LC_PROPERTY_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_light_lc_property_get_light_lc_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_MANUFACTURER_PROPERTIES_GET:
        break;
    case GENERIC_MANUFACTURER_PROPERTIES_STATUS:
        manufacturer_property_ids_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_manufacturer_property_ids, NULL, "Manufacturer Property IDs");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(manufacturer_property_ids_tree, hf_btmesh_generic_manufacturer_properties_status_manufacturer_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case GENERIC_MANUFACTURER_PROPERTY_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_manufacturer_property_get_manufacturer_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_MANUFACTURER_PROPERTY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_manufacturer_property_set_manufacturer_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_manufacturer_property_set_manufacturer_user_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_MANUFACTURER_PROPERTY_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_manufacturer_property_set_unacknowledged_manufacturer_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_manufacturer_property_set_unacknowledged_manufacturer_user_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        break;
    case GENERIC_MANUFACTURER_PROPERTY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_manufacturer_property_status_manufacturer_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        // Optional
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_generic_manufacturer_property_status_manufacturer_user_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset+=dissect_btmesh_property(sub_tree, hf_btmesh_generic_manufacturer_property_status_manufacturer_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        }
        break;
    case GENERIC_ADMIN_PROPERTIES_GET:
        break;
    case GENERIC_ADMIN_PROPERTIES_STATUS:
        admin_property_ids_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_admin_property_ids, NULL, "Admin Property IDs");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(admin_property_ids_tree, hf_btmesh_generic_admin_properties_status_admin_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case GENERIC_ADMIN_PROPERTY_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_admin_property_get_admin_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_ADMIN_PROPERTY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_admin_property_set_admin_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_admin_property_set_admin_user_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_generic_admin_property_set_admin_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case GENERIC_ADMIN_PROPERTY_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_admin_property_set_unacknowledged_admin_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_generic_admin_property_set_unacknowledged_admin_user_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_generic_admin_property_set_unacknowledged_admin_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case GENERIC_ADMIN_PROPERTY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_admin_property_status_admin_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        // Optional
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_generic_admin_property_status_admin_user_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset+=dissect_btmesh_property(sub_tree, hf_btmesh_generic_admin_property_status_admin_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        }
        break;
    case GENERIC_USER_PROPERTIES_GET:
        break;
    case GENERIC_USER_PROPERTIES_STATUS:
        user_property_ids_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_user_property_ids, NULL, "User Property IDs");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(user_property_ids_tree, hf_btmesh_generic_user_properties_status_user_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case GENERIC_USER_PROPERTY_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_user_property_get_user_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_USER_PROPERTY_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_user_property_set_user_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_generic_user_property_set_user_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case GENERIC_USER_PROPERTY_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_user_property_set_unacknowledged_user_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_generic_user_property_set_unacknowledged_user_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case GENERIC_USER_PROPERTY_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_user_property_status_user_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        // Optional
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_generic_user_property_status_user_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset+=dissect_btmesh_property(sub_tree, hf_btmesh_generic_user_property_status_user_property_value, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        }
        break;
    case GENERIC_CLIENT_PROPERTIES_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_generic_client_properties_get_client_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case GENERIC_CLIENT_PROPERTIES_STATUS:
        generic_client_property_ids_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_generic_client_property_ids, NULL, "Client Property IDs");
        while (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(generic_client_property_ids_tree, hf_btmesh_generic_client_properties_status_client_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case SENSOR_DESCRIPTOR_GET:
        // Optional
        if (tvb_reported_length_remaining(tvb, offset) > 1) {
            proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_get_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case SENSOR_DESCRIPTOR_STATUS:
        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_status_descriptor_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        } else {
            while (tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_status_descriptor_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
                proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_status_descriptor_sensor_positive_tolerance, tvb, offset, 3, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_status_descriptor_sensor_negative_tolerance, tvb, offset, 3, ENC_LITTLE_ENDIAN);
                offset+=3;
                proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_status_descriptor_sensor_sampling_function, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset+=1;
                proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_status_descriptor_sensor_measurement_period, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset+=1;
                proto_tree_add_item(sub_tree, hf_btmesh_sensor_descriptor_status_descriptor_sensor_update_interval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset+=1;
            }
        }
        break;
    case SENSOR_CADENCE_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_get_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SENSOR_CADENCE_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_set_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_set_fast_cadence_period_divisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_set_status_trigger_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        trigger_type = tvb_get_uint8(tvb, offset) >> 7;
        offset++;
        offset+=dissect_sensor_cadence(sub_tree, tvb, offset, property_id, trigger_type, &sensor_cadence_set_hfs);
        break;
    case SENSOR_CADENCE_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_set_unacknowledged_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_period_divisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        trigger_type = tvb_get_uint8(tvb, offset) >> 7;
        offset++;

        offset+=dissect_sensor_cadence(sub_tree, tvb, offset, property_id, trigger_type, &sensor_cadence_set_unacknowledged_hfs);
        break;
    case SENSOR_CADENCE_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_status_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_status_fast_cadence_period_divisor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_cadence_status_status_trigger_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        trigger_type = tvb_get_uint8(tvb, offset) >> 7;
        offset++;
        offset+=dissect_sensor_cadence(sub_tree, tvb, offset, property_id, trigger_type, &sensor_cadence_status_hfs);
        break;
    case SENSOR_SETTINGS_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_settings_get_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SENSOR_SETTINGS_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_settings_status_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        // Optional
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            sensor_setting_property_ids_tree = proto_tree_add_subtree(sub_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), ett_btmesh_sensor_setting_property_ids, NULL, "Sensor Setting Property IDs");
            while (tvb_reported_length_remaining(tvb, offset) > 1) {
                proto_tree_add_item(sensor_setting_property_ids_tree, hf_btmesh_sensor_settings_status_sensor_setting_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset+=2;
            }
        }
        break;
    case SENSOR_SETTING_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_get_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_get_sensor_setting_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        break;
    case SENSOR_SETTING_SET:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_set_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_set_sensor_setting_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_sensor_setting_set_sensor_setting_raw, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case SENSOR_SETTING_SET_UNACKNOWLEDGED:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_set_unacknowledged_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_set_unacknowledged_sensor_setting_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_btmesh_property(sub_tree, hf_btmesh_sensor_setting_set_unacknowledged_sensor_setting_raw, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        break;
    case SENSOR_SETTING_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_status_sensor_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_status_sensor_setting_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        //Optional
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_sensor_setting_status_sensor_setting_access, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            offset+=dissect_btmesh_property(sub_tree, hf_btmesh_sensor_setting_status_sensor_setting_raw, tvb, offset, property_id, PROPERTY_LENGTH_NO_HINT);
        }
        break;
    case SENSOR_GET:
        // Optional
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(sub_tree, hf_btmesh_sensor_get_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
        break;
    case SENSOR_STATUS:
        // Optional
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sensor_status_mpid_format, tvb, offset, 1, ENC_LITTLE_ENDIAN, &mpid_format);
            if (mpid_format == MPID_FORMAT_A) {
                proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sensor_status_mpid_format_a_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &mpid_length);
                proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sensor_status_mpid_format_a_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &mpid_property_id);
                offset+=2;
            } else {
                proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sensor_status_mpid_format_b_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &mpid_length);
                offset++;
                proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sensor_status_mpid_format_b_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &mpid_property_id);
                offset+=2;
            }
            offset+=dissect_btmesh_property(sub_tree, hf_btmesh_sensor_status_raw_value, tvb, offset, (uint16_t)mpid_property_id, mpid_length);
        }
        break;
    case SENSOR_COLUMN_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_column_get_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_columns_raw_value(sub_tree, tvb, offset, property_id, &sensor_column_get_hfs);
        break;
    case SENSOR_COLUMN_STATUS:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_column_status_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        offset+=dissect_property_raw_value_entry(sub_tree, tvb, offset, property_id, &sensor_column_status_hfs);
        break;
    case SENSOR_SERIES_GET:
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_series_get_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        // Optional
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            offset+=dissect_columns_raw_value(sub_tree, tvb, offset, property_id, &sensor_series_get_hfs);
        }
        break;
    case SENSOR_SERIES_STATUS:
        //first property_id is manadatory
        proto_tree_add_item(sub_tree, hf_btmesh_sensor_series_status_property_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        property_id = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset+=2;
        //Optional, dissect one or more values
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            offset+=dissect_property_raw_value_entry(sub_tree, tvb, offset, property_id, &sensor_series_status_hfs);
        }
        break;
//
//  ******************************************************************************************
//
    default:
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(sub_tree, hf_btmesh_model_layer_parameters, tvb, offset, -1, ENC_NA);
            offset+=tvb_reported_length_remaining(tvb, offset);
        }
    }
    /* Still some octets left */
    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_unknown_payload, tvb, offset, -1);
    }
}

static void
dissect_btmesh_access_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
   proto_tree *sub_tree;

   sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_access_pdu, NULL, "Access PDU");
   proto_tree_add_item(sub_tree, hf_btmesh_decrypted_access, tvb, offset, -1, ENC_NA);

   dissect_btmesh_model_layer(tvb, pinfo, tree, offset);
}

static void
dissect_btmesh_transport_control_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t opcode)
{
    proto_tree *sub_tree;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
        val_to_str_const(opcode, btmesh_ctrl_opcode_vals, "Control Message Unknown"));

    sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_btmesh_transp_ctrl_msg, NULL, "Transport Control Message %s",
        val_to_str_const(opcode, btmesh_ctrl_opcode_vals, "Unknown"));

    switch (opcode) {
    case 1:
        /* 3.6.5.1 Friend Poll */
        /* Padding 7 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* FSN 1 bit*/
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_fsn, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* 3.6.5.2 Friend Update */
        /* Flags 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_key_refresh_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_iv_update_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_flags_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* IV Index 4 octets*/
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_iv_index, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        /* MD 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_md, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;
    case 3:
        /* Friend Request */
        /* Criteria 1 octet */
        /* RFU 1 bit */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* RSSIFactor 2 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_rssifactor, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* ReceiveWindowFactor 2 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_receivewindowfactor, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* MinQueueSizeLog 3 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_minqueuesizelog, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* ReceiveDelay 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_receivedelay, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* PollTimeout 3 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_polltimeout, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
        /* PreviousAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_previousaddress, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* NumElements 1 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_numelements, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* LPNCounter 1 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 4:
        /* 3.6.5.4 Friend Offer */
        /* ReceiveWindow 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_receivewindow, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* QueueSize 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_queuesize, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* SubscriptionListSize 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_subscriptionlistsize, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* RSSI 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* FriendCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_friendcounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 5:
        /* 3.6.5.5 Friend Clear */
        /* LPNAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpnaddress, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;
        /* LPNCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 6:
        /* 3.6.5.6 Friend Clear Confirm */
        /* LPNAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpnaddress, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;
        /* LPNCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);

        break;
    case 7:
        /* 3.6.5.7 Friend Subscription List Add */
        /* TransactionNumber 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* AddressList 2 * N */
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    case 8:
        /* 3.6.5.8 Friend Subscription List Remove */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* AddressList 2 * N */
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    case 9:
        /* 3.6.5.9 Friend Subscription List Confirm */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;
    case 10:
        /* 3.6.5.10 Heartbeat */
        /* RFU & InitTTL */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_heartbeat_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_init_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* Features */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_relay, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_proxy, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_friend, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_low_power, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_rfu, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    default:
        /* Unknown Control Message */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_unknown_payload, tvb, offset, -1, ENC_NA);
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    }
}

static bool
try_access_decrypt(tvbuff_t *tvb, int offset, uint8_t *decrypted_data, int enc_data_len, uint8_t *key, network_decryption_ctx_t *dec_ctx)
{
    uint8_t accessnonce[13];
    gcry_cipher_hd_t cipher_hd;
    gcry_error_t gcrypt_err;
    uint64_t ccm_lengths[3];
    uint8_t *tag;

    accessnonce[0] = dec_ctx->app_nonce_type;
    accessnonce[1] = (dec_ctx->transmic_size == 4 ? 0x00 : 0x80 );
    memcpy((uint8_t *)&accessnonce + 2, dec_ctx->seq_src_buf, 5);
    if (dec_ctx->seg) {
        accessnonce[2] = (dec_ctx->seqzero & 0xff0000 ) >> 16;
        accessnonce[3] = (dec_ctx->seqzero & 0x00ff00 ) >> 8;
        accessnonce[4] = (dec_ctx->seqzero & 0x0000ff );
    }
    memcpy((uint8_t *)&accessnonce + 7, dec_ctx->dst_buf, sizeof(dec_ctx->dst_buf));
    memcpy((uint8_t *)&accessnonce + 9, dec_ctx->ivindex_buf, sizeof(dec_ctx->ivindex_buf));

    /* Decrypt packet EXPERIMENTAL CODE */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0)) {
        return false;
    }
    /* Set key */
    gcrypt_err = gcry_cipher_setkey(cipher_hd, key, 16);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
   /* Load nonce */
    gcrypt_err = gcry_cipher_setiv(cipher_hd, &accessnonce, 13);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    ccm_lengths[0] = enc_data_len;
    ccm_lengths[1] = (dec_ctx->label_uuid_idx == NO_LABEL_UUID_IDX_USED ? 0 : 16);
    ccm_lengths[2] = dec_ctx->transmic_size;

    gcrypt_err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return false;
    }

    if (dec_ctx->label_uuid_idx != NO_LABEL_UUID_IDX_USED) {
        gcrypt_err = gcry_cipher_authenticate(cipher_hd, uat_btmesh_label_uuid_records[dec_ctx->label_uuid_idx].label_uuid, 16);
        if (gcrypt_err != 0) {
            gcry_cipher_close(cipher_hd);
            return false;
        }
    }

    /* Decrypt */
    gcrypt_err = gcry_cipher_decrypt(cipher_hd, decrypted_data, enc_data_len, tvb_get_ptr(tvb, offset, enc_data_len), enc_data_len);
    if (gcrypt_err != 0) {
        gcry_cipher_close(cipher_hd);
        return false;
    }

    tag = (uint8_t *)wmem_alloc(wmem_packet_scope(), dec_ctx->transmic_size);
    gcrypt_err = gcry_cipher_gettag(cipher_hd, tag, dec_ctx->transmic_size);
    gcry_cipher_close(cipher_hd);

    if (gcrypt_err != 0 || memcmp(tag, tvb_get_ptr(tvb, offset + enc_data_len, dec_ctx->transmic_size), dec_ctx->transmic_size)) {
        /* Tag mismatch or cipher error */
        return false;
    }
    /* Tag authenticated */
    return true;
}

static unsigned
check_address_type(uint32_t btmesh_address)
{
    if (btmesh_address & 0x8000 ) {
        if (btmesh_address & 0x4000) {
            return BTMESH_ADDRESS_GROUP;
        }
        return BTMESH_ADDRESS_VIRTUAL;
    } else {
        if (btmesh_address) {
            return BTMESH_ADDRESS_UNICAST;
        }
        return BTMESH_ADDRESS_UNASSIGNED;
    }
}

static tvbuff_t *
btmesh_access_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, int offset, network_decryption_ctx_t *dec_ctx)
{
    unsigned i, j, dst_address_type;
    uat_btmesh_record_t *record;
    uat_btmesh_dev_key_record_t *dev_record;
    uat_btmesh_label_uuid_record_t *label_record;
    int enc_data_len;
    uint8_t *decrypted_data;

    enc_data_len = tvb_reported_length_remaining(tvb, offset) - dec_ctx->transmic_size;
    decrypted_data = (uint8_t *)wmem_alloc(pinfo->pool, enc_data_len);
    dec_ctx->label_uuid_idx = NO_LABEL_UUID_IDX_USED;

    if (enc_data_len <= 0) {
        return NULL;
    }

    dst_address_type = check_address_type(dec_ctx->dst);

    /* Application key */
    if (dec_ctx->app_nonce_type == BTMESH_NONCE_TYPE_APPLICATION) {
        for (i = 0; i < num_btmesh_uat; i++) {
            record = &uat_btmesh_records[i];
            if (record->valid == BTMESH_KEY_ENTRY_VALID) {
                if (dec_ctx->net_key_iv_index_hash == record->net_key_iv_index_hash && dec_ctx->aid == record->aid) {
                    /* Try Label UUID */
                    if (dst_address_type == BTMESH_ADDRESS_VIRTUAL) {
                        for (j = 0; j < num_btmesh_label_uuid_uat; j++) {
                            label_record = &uat_btmesh_label_uuid_records[j];
                            if (label_record->valid == BTMESH_LABEL_UUID_ENTRY_VALID && label_record->hash == dec_ctx->dst) {
                                dec_ctx->label_uuid_idx = j;
                                if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, record->application_key, dec_ctx)) {
                                    return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                                }
                            }
                        }
                    } else {
                        if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, record->application_key, dec_ctx)) {
                            return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                        }
                    }
                }
            }
        }
    }
    /* Device key */
    if (dec_ctx->app_nonce_type == BTMESH_NONCE_TYPE_DEVICE) {
        for (i = 0; i < num_btmesh_dev_key_uat; i++) {
            dev_record = &uat_btmesh_dev_key_records[i];
            if (dev_record->valid == BTMESH_DEVICE_KEY_ENTRY_VALID) {
                /* Try Device Key from SRC */
                if ( !memcmp(dev_record->src, dec_ctx->seq_src_buf + 3, 2) ) {
                    /* Try Label UUID */
                    if (dst_address_type == BTMESH_ADDRESS_VIRTUAL) {
                        for (j = 0; j < num_btmesh_label_uuid_uat; j++) {
                            label_record = &uat_btmesh_label_uuid_records[j];
                            if (label_record->valid == BTMESH_LABEL_UUID_ENTRY_VALID && label_record->hash == dec_ctx->dst) {
                                dec_ctx->label_uuid_idx = j;
                                if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, dev_record->device_key, dec_ctx)) {
                                    return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                                }
                            }
                        }
                    } else {
                        if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, dev_record->device_key, dec_ctx)) {
                            return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                        }
                    }
                }
                /* Try Device Key from DST when DST is a unicast address */
                if (dst_address_type == BTMESH_ADDRESS_UNICAST) {
                    if ( !memcmp(dev_record->src, dec_ctx->dst_buf, 2) ) {
                        if (try_access_decrypt(tvb, offset, decrypted_data, enc_data_len, dev_record->device_key, dec_ctx)) {
                            return tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

static void
dissect_btmesh_transport_access_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, network_decryption_ctx_t *dec_ctx)
{
    tvbuff_t *de_acc_tvb;
    proto_tree *sub_tree;

    int length = tvb_reported_length_remaining(tvb, offset);

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_upper_transp_acc_pdu, NULL, "Upper Transport Access PDU");
    de_acc_tvb = btmesh_access_find_key_and_decrypt(tvb, pinfo, offset, dec_ctx);

    proto_tree_add_item(sub_tree, hf_btmesh_enc_access_pld, tvb, offset, length - dec_ctx->transmic_size, ENC_NA);
    offset += (length - dec_ctx->transmic_size);

    proto_tree_add_item(sub_tree, hf_btmesh_transtmic, tvb, offset, dec_ctx->transmic_size, ENC_NA);

    if (de_acc_tvb) {
        add_new_data_source(pinfo, de_acc_tvb, "Decrypted access data");
        dissect_btmesh_access_message(de_acc_tvb, pinfo, tree, 0);
    }
}

static void
dissect_btmesh_transport_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool cntrl, network_decryption_ctx_t *dec_ctx)
{
    proto_tree *sub_tree;
    proto_item *ti;
    int offset = 0;
    uint32_t seg, opcode, rfu;
    uint32_t seqzero, sego, segn;

    /* We receive the full decrypted buffer including DST, skip to opcode */
    offset += 2;
    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_transp_pdu, &ti, "Lower Transport PDU");
    if (cntrl) {
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_cntr_seg, tvb, offset, 1, ENC_BIG_ENDIAN, &seg);
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_cntr_opcode, tvb, offset, 1, ENC_BIG_ENDIAN, &opcode);
        offset++;

        if (seg) {
            /* Segmented */
            fragment_head *fd_head = NULL;

            /* RFU */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seg_rfu, tvb, offset, 3, ENC_BIG_ENDIAN, &rfu);
            /* SeqZero 13 */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seqzero_data, tvb, offset, 3, ENC_BIG_ENDIAN, &seqzero);
            /* SegO 5 Segment Offset number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sego, tvb, offset, 3, ENC_BIG_ENDIAN, &sego);
            /* SegN 5 Last Segment number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_segn, tvb, offset, 3, ENC_BIG_ENDIAN, &segn);
            offset += 3;

            /* Segment */
            proto_tree_add_item(sub_tree, hf_btmesh_segment, tvb, offset, -1, ENC_NA);

            /* Use 13 Lsbs from seqzero */
            dec_ctx->seqzero = dec_ctx->seq;
            /* Check for overflow */
            if ((dec_ctx->seq & 0x1fff) < seqzero) {
                dec_ctx->seqzero -= 0x2000;
            }
            dec_ctx->seqzero = dec_ctx->seqzero & ~0x1fff;
            dec_ctx->seqzero += seqzero;

            if (segn == 0) {
                dissect_btmesh_transport_control_message(tvb, pinfo, tree, offset, opcode);
            } else {
                upper_transport_fragment_key frg_key;
                frg_key.src = dec_ctx->src;
                frg_key.net_key_iv_index_hash = dec_ctx->net_key_iv_index_hash;
                memcpy(&frg_key.ivindex, dec_ctx->ivindex_buf, sizeof(frg_key.ivindex));
                frg_key.seq0 = dec_ctx->seqzero;

                if (!pinfo->fd->visited) {
                    uint32_t total_length = 0;
                    if (segn == sego) {
                        total_length = segn * 8 + tvb_captured_length_remaining(tvb, offset);
                    }

                    /* Last fragment can be delivered out of order, and can be the first one. */
                    fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);

                    if ((fd_head) && (total_length)) {
                        fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                    }
                    fd_head = fragment_add(&upper_transport_reassembly_table,
                                tvb, offset, pinfo,
                                BTMESH_NOT_USED, &frg_key,
                                8 * sego,
                                tvb_captured_length_remaining(tvb, offset),
                                ( segn == 0 ? false : true) );

                    if ((!fd_head) && (total_length)) {
                        fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                    }
                } else {
                    fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);
                    if (fd_head && (fd_head->flags&FD_DEFRAGMENTED)) {
                        tvbuff_t *next_tvb;
                        next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Control PDU", fd_head, &btmesh_segmented_control_frag_items, NULL, sub_tree);
                        if (next_tvb) {
                            dissect_btmesh_transport_control_message(next_tvb, pinfo, tree, 0, opcode);
                            col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
                        } else {
                            col_clear(pinfo->cinfo, COL_INFO);
                            col_append_fstr(pinfo->cinfo, COL_INFO,"Control Message (fragment %u)", sego);
                        }
                    }
                }
            }
        } else {
            if (opcode == 0) {
                col_clear(pinfo->cinfo, COL_INFO);
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                    val_to_str_const(opcode, btmesh_ctrl_opcode_vals, "Control Message Unknown"));
                /* OBO 1 */
                proto_tree_add_item(sub_tree, hf_btmesh_obo, tvb, offset, 2, ENC_BIG_ENDIAN);
                /* SeqZero 13 */
                proto_tree_add_item(sub_tree, hf_btmesh_seqzero, tvb, offset, 2, ENC_BIG_ENDIAN);
                /* RFU 2 */
                proto_tree_add_item(sub_tree, hf_btmesh_rfu, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* BlockAck 32 */
                proto_tree_add_item(sub_tree, hf_btmesh_blockack, tvb, offset, 4, ENC_BIG_ENDIAN);
                return;
            }
            dissect_btmesh_transport_control_message(tvb, pinfo, tree, offset, opcode);
        }
    } else {
        /* Access message */
        uint32_t afk, aid, szmic;
        /* Access message */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_seg, tvb, offset, 1, ENC_BIG_ENDIAN, &seg);
        /* AKF 1 Application Key Flag */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_akf, tvb, offset, 1, ENC_BIG_ENDIAN, &afk);
        /* AID 6 Application key identifier */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_aid, tvb, offset, 1, ENC_BIG_ENDIAN, &aid);
        offset++;

        dec_ctx->seg = seg;
        dec_ctx->aid = aid;
        dec_ctx->app_nonce_type = (afk ? BTMESH_NONCE_TYPE_APPLICATION : BTMESH_NONCE_TYPE_DEVICE);

        if (seg) {
            /* Segmented */
            fragment_head *fd_head = NULL;

            /* SZMIC 1 Size of TransMIC */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_szmic, tvb, offset, 3, ENC_BIG_ENDIAN, &szmic);
            /* SeqZero 13 Least significant bits of SeqAuth */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seqzero_data, tvb, offset, 3, ENC_BIG_ENDIAN, &seqzero);
            /* SegO 5 Segment Offset number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sego, tvb, offset, 3, ENC_BIG_ENDIAN, &sego);
            /* SegN 5 Last Segment number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_segn, tvb, offset, 3, ENC_BIG_ENDIAN, &segn);
            offset += 3;

            /* Segment m 8 to 96 Segment m of the Upper Transport Access PDU */
            proto_tree_add_item(sub_tree, hf_btmesh_segment, tvb, offset, -1, ENC_NA);

            /* Use 13 Lsbs from seqzero */
            dec_ctx->seqzero = dec_ctx->seq;
            /* Check for overflow */
            if ((dec_ctx->seq & 0x1fff) < seqzero) {
                dec_ctx->seqzero -= 0x2000;
            }
            dec_ctx->seqzero = dec_ctx->seqzero & ~0x1fff;
            dec_ctx->seqzero += seqzero;

            if (segn == 0) {
                proto_item_set_len(ti, 1);
                dec_ctx->transmic_size = 4; /*TransMic is 32 bits*/
                dissect_btmesh_transport_access_message(tvb, pinfo, tree, offset, dec_ctx);
            } else {
                upper_transport_fragment_key frg_key;
                frg_key.src = dec_ctx->src;
                frg_key.net_key_iv_index_hash = dec_ctx->net_key_iv_index_hash;
                memcpy(&frg_key.ivindex, dec_ctx->ivindex_buf, sizeof(frg_key.ivindex));
                frg_key.seq0 = dec_ctx->seqzero;

                if (!pinfo->fd->visited) {
                    uint32_t total_length = 0;
                    if (segn == sego) {
                        total_length = segn * 12 + tvb_captured_length_remaining(tvb, offset);
                    }

                    /* Last fragment can be delivered out of order, and can be the first one. */
                    fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);

                    if ((fd_head) && (total_length)) {
                        fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                    }
                    fd_head = fragment_add(&upper_transport_reassembly_table,
                                tvb, offset, pinfo,
                                BTMESH_NOT_USED, &frg_key,
                                12 * sego,
                                tvb_captured_length_remaining(tvb, offset),
                                ( segn == 0 ? false : true) );

                    if ((!fd_head) && (total_length)) {
                        fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                    }
                } else {
                    fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);
                    if (fd_head && (fd_head->flags&FD_DEFRAGMENTED)) {
                        tvbuff_t *next_tvb;
                        next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Access PDU", fd_head, &btmesh_segmented_access_frag_items, NULL, sub_tree);
                        if (next_tvb) {
                            dec_ctx->transmic_size = (szmic ? 8 : 4 );
                            dissect_btmesh_transport_access_message(next_tvb, pinfo, tree, 0, dec_ctx);
                            col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
                        } else {
                            col_clear(pinfo->cinfo, COL_INFO);
                            col_append_fstr(pinfo->cinfo, COL_INFO, "Access Message (fragment %u)", sego);
                        }
                    }
                }
            }
        } else {
            proto_item_set_len(ti, 1);
            dec_ctx->transmic_size = 4; /*TransMic is 32 bits*/
            dissect_btmesh_transport_access_message(tvb, pinfo, tree, offset, dec_ctx);
        }
    }
}

tvbuff_t *
btmesh_network_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, uint8_t **decrypted_data, int *enc_data_len, network_decryption_ctx_t *dec_ctx) {
    unsigned i;
    uint8_t nid;
    int offset = 0;
    tvbuff_t *de_obf_tvb;
    uint8_t networknonce[13];
    uat_btmesh_record_t *record;
    gcry_cipher_hd_t cipher_hd;
    uint32_t net_mic_size;
    gcry_error_t gcrypt_err;
    uint64_t ccm_lengths[3];
    int enc_offset;

    nid = tvb_get_uint8(tvb, offset) & 0x7f;

    /* Get the next record to try */
    for (i = 0; i < num_btmesh_uat; i++) {
        record = &uat_btmesh_records[i];
        if (record->valid == BTMESH_KEY_ENTRY_VALID && nid == record->nid) {
            offset = 1;
            de_obf_tvb = btmesh_deobfuscate(tvb, pinfo, offset, record);

            if (de_obf_tvb == NULL) {
                continue;
            }
            net_mic_size = (((tvb_get_uint8(de_obf_tvb, 0) & 0x80) >> 7 ) + 1 ) * 4; /* CTL */
            offset +=6;

            (*enc_data_len) = tvb_reported_length(tvb) - offset - net_mic_size;
            enc_offset = offset;

            /* Start setting network nonce.*/
            networknonce[0] = dec_ctx->net_nonce_type; /* Nonce Type */

            tvb_memcpy(de_obf_tvb, (uint8_t *)&networknonce + 1, 0, 6);
            if (dec_ctx->net_nonce_type == BTMESH_NONCE_TYPE_PROXY) {
                networknonce[1] = 0x00;    /*Pad*/
            }
            networknonce[7] = 0x00;    /*Pad*/
            networknonce[8] = 0x00;    /*Pad*/

            memcpy((uint8_t *)&networknonce + 9, record->ivindex, 4);
            /* Decrypt packet EXPERIMENTAL CODE */
            if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0)) {
                return NULL;
            }

            gcrypt_err = gcry_cipher_setkey(cipher_hd, record->encryptionkey, 16);
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            /* Load nonce */
            gcrypt_err = gcry_cipher_setiv(cipher_hd, &networknonce, 13);
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }
            /* */
            ccm_lengths[0] = (*enc_data_len);
            ccm_lengths[1] = 0; /* aad */
            ccm_lengths[2] = net_mic_size; /* icv */

            gcrypt_err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            (*decrypted_data) = (uint8_t *)wmem_alloc(pinfo->pool, *enc_data_len);
            /* Decrypt */
            gcrypt_err = gcry_cipher_decrypt(cipher_hd, (*decrypted_data), *enc_data_len, tvb_get_ptr(tvb, enc_offset, *enc_data_len), *enc_data_len);
            if (gcrypt_err != 0) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            uint8_t *tag;
            tag = (uint8_t *)wmem_alloc(pinfo->pool, net_mic_size);
            gcrypt_err = gcry_cipher_gettag(cipher_hd, tag, net_mic_size);

            if (gcrypt_err == 0 && !memcmp(tag, tvb_get_ptr(tvb, enc_offset + (*enc_data_len), net_mic_size), net_mic_size)) {
                /* Tag authenticated, now close the cypher handle */
                gcry_cipher_close(cipher_hd);
                dec_ctx->net_key_iv_index_hash = record->net_key_iv_index_hash;
                memcpy(dec_ctx->ivindex_buf, record->ivindex, sizeof(dec_ctx->ivindex_buf));

                return de_obf_tvb;
            }  else {
                /* Now close the cypher handle */
                gcry_cipher_close(cipher_hd);

                /* Tag mismatch or cipher error */
                continue;
            }
        }
    }
    return NULL;
}

static int
dissect_btmesh_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *netw_tree, *sub_tree;
    int offset = 0;
    uint32_t net_mic_size, seq, src, dst;
    int enc_data_len = 0;
    tvbuff_t *de_obf_tvb;
    tvbuff_t *de_cry_tvb;
    int decry_off;
    uint8_t *decrypted_data = NULL;
    network_decryption_ctx_t *dec_ctx;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh");

    item = proto_tree_add_item(tree, proto_btmesh, tvb, offset, -1, ENC_NA);
    netw_tree = proto_item_add_subtree(item, ett_btmesh);

    sub_tree = proto_tree_add_subtree(netw_tree, tvb, offset, -1, ett_btmesh_net_pdu, NULL, "Network PDU");
    /* Check length >= , if not error packet */
    /* First byte in plaintext */
    /* IVI 1 bit Least significant bit of IV Index */
    proto_tree_add_item(sub_tree, hf_btmesh_ivi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_btmesh_nid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    dec_ctx = wmem_new(pinfo->pool, network_decryption_ctx_t);
    dec_ctx->net_nonce_type = BTMESH_NONCE_TYPE_NETWORK;

    de_obf_tvb = btmesh_network_find_key_and_decrypt(tvb, pinfo, &decrypted_data, &enc_data_len, dec_ctx);

    if (de_obf_tvb) {
        add_new_data_source(pinfo, de_obf_tvb, "Deobfuscated data");

        bool cntrl;

        /* CTL 1 bit Network Control*/
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_ctl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN, &net_mic_size);
        /* 32 or 64 bits ( 0 or 1 )*/
        cntrl = net_mic_size;
        net_mic_size = (net_mic_size + 1) * 4;
        /* The TTL field is a 7-bit field */
        proto_tree_add_item(sub_tree, hf_btmesh_ttl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN);

        /* SEQ field is a 24-bit integer */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seq, de_obf_tvb, 1, 3, ENC_BIG_ENDIAN, &seq);

        /* SRC field is a 16-bit value */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_src, de_obf_tvb, 4, 2, ENC_BIG_ENDIAN, &src);
        offset += 6;

        de_cry_tvb = tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
        add_new_data_source(pinfo, de_cry_tvb, "Decrypted network data");

        decry_off = 0;
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_dst, de_cry_tvb, decry_off, 2, ENC_BIG_ENDIAN, &dst);
        decry_off += 2;
        /* TransportPDU */
        proto_tree_add_item(sub_tree, hf_btmesh_transp_pdu, de_cry_tvb, decry_off, enc_data_len-2, ENC_NA);
        offset += enc_data_len;

        proto_tree_add_item(sub_tree, hf_btmesh_netmic, tvb, offset, net_mic_size, ENC_BIG_ENDIAN);
        offset += net_mic_size;

        if (de_cry_tvb) {
            dec_ctx->src = src;
            dec_ctx->seq = seq;
            dec_ctx->dst = dst;
            tvb_memcpy(de_obf_tvb, dec_ctx->seq_src_buf, 1, 5);
            tvb_memcpy(de_cry_tvb, dec_ctx->dst_buf, 0, 2);

            dissect_btmesh_transport_pdu(de_cry_tvb, pinfo, netw_tree, cntrl, dec_ctx);
        }
    } else {
        proto_tree_add_item(sub_tree, hf_btmesh_obfuscated, tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(sub_tree, hf_btmesh_encrypted, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
    }

    return offset;
}

static int
compute_ascii_key(unsigned char **ascii_key, const char *key, const char *key_name, unsigned expected_octets, char **err)
{
    unsigned key_len = 0, raw_key_len;
    int hex_digit;
    unsigned char key_byte;
    unsigned i, j;

    if (key != NULL)
    {
        raw_key_len = (unsigned)strlen(key);
        if (((raw_key_len == expected_octets * 2 + 2) || (raw_key_len == expected_octets * 2 + 1)) &&
            (key[0] == '0')
            && ((key[1] == 'x') || (key[1] == 'X')))
        {
            /*
             * Key begins with "0x" or "0X"; skip that and treat the rest
             * as a sequence of hex digits.
             */
            i = 2;    /* first character after "0[Xx]" */
            j = 0;
            if (raw_key_len % 2 == 1)
            {
                /*
                 * Key has an odd number of characters; we act as if the
                 * first character had a 0 in front of it, making the
                 * number of characters even.
                 */
                key_len = (raw_key_len - 2) / 2 + 1;
                *ascii_key = (unsigned char *)g_malloc((key_len + 1) * sizeof(char));
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    *err = ws_strdup_printf("Key %s begins with an invalid hex char (%c)", key, key[i]);
                    return -1;    /* not a valid hex digit */
                }
                (*ascii_key)[j] = (unsigned char)hex_digit;
                j++;
            }
            else
            {
                /*
                 * Key has an even number of characters, so we treat each
                 * pair of hex digits as a single byte value.
                 */
                key_len = (raw_key_len - 2) / 2;
                *ascii_key = (unsigned char *)g_malloc((key_len + 1) * sizeof(char));
            }
            while (i < (raw_key_len - 1))
            {
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    *err = ws_strdup_printf("%s %s has an invalid hex char (%c)", key_name, key, key[i-1]);
                    return -1;    /* not a valid hex digit */
                }
                key_byte = ((unsigned char)hex_digit) << 4;
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    *err = ws_strdup_printf("%s %s has an invalid hex char (%c)", key_name, key, key[i-1]);
                    return -1;    /* not a valid hex digit */
                }
                key_byte |= (unsigned char)hex_digit;
                (*ascii_key)[j] = key_byte;
                j++;
            }
            (*ascii_key)[j] = '\0';
        } else {
            *ascii_key = NULL;
            *err = ws_strdup_printf("%s %s has to start with '0x' or '0X', and represent exactly %d octets", key_name, key, expected_octets);
            return -1;
        }
    }
    return key_len;
}

static bool
uat_btmesh_record_update_cb(void *r, char **err)
{
    uat_btmesh_record_t *rec = (uat_btmesh_record_t *)r;

    rec->valid = 0;

    /* Compute keys & lengths once and for all */
    if (rec->network_key_string) {
        g_free(rec->network_key);
        rec->network_key_length = compute_ascii_key(&rec->network_key, rec->network_key_string, "Network Key", 16, err);
        g_free(rec->encryptionkey);
        rec->encryptionkey = g_new(uint8_t, 16);
        memset(rec->encryptionkey, 0, 16 * sizeof(uint8_t));
        g_free(rec->privacykey);
        rec->privacykey = g_new(uint8_t, 16);
        if (*err == NULL && create_central_security_keys(rec)) {
            rec->valid++;
        }
    } else {
        rec->network_key_length = 0;
        rec->network_key = NULL;
    }
    if (*err == NULL && rec->application_key_string) {
        g_free(rec->application_key);
        rec->application_key_length = compute_ascii_key(&rec->application_key, rec->application_key_string, "Application Key", 16, err);
        /* compute AID */
        if (*err == NULL && k4(rec)) {
            rec->valid++;
        }
    } else {
        rec->application_key_length = 0;
        rec->application_key = NULL;
    }
    if (*err == NULL && rec->ivindex_string) {
        g_free(rec->ivindex);
        rec->ivindex_string_length = compute_ascii_key(&rec->ivindex, rec->ivindex_string, "IVindex", 4, err);
        if (*err == NULL) {
            rec->valid++;
        }
    }
    if (rec->valid == BTMESH_KEY_ENTRY_VALID - 1) {
        /* Compute net_key_index_hash */
        const uint8_t hash_buf_len = 16 + 4;
        unsigned idx=0;
        uint8_t* hash_buf = (uint8_t *)g_malloc(hash_buf_len);
        memcpy(hash_buf, rec->encryptionkey, 16);
        idx += 16;
        memcpy(&hash_buf[idx], rec->ivindex, 4);
        rec->net_key_iv_index_hash = wmem_strong_hash(hash_buf, hash_buf_len);
        g_free(hash_buf);
        rec->valid++;
    }
    return rec->valid == BTMESH_KEY_ENTRY_VALID;
}

static void *
uat_btmesh_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_btmesh_record_t *new_rec = (uat_btmesh_record_t *)n;
    const uat_btmesh_record_t* old_rec = (const uat_btmesh_record_t *)o;

    memset(new_rec, 0x00, sizeof(uat_btmesh_record_t));

    /* Copy UAT fields */
    new_rec->network_key_string = g_strdup(old_rec->network_key_string);
    new_rec->application_key_string = g_strdup(old_rec->application_key_string);
    new_rec->ivindex_string = g_strdup(old_rec->ivindex_string);

    /* Parse keys as in an update */
    char *err = NULL;
    uat_btmesh_record_update_cb(new_rec, &err);
    if (err) {
        g_free(err);
    }
    return new_rec;
}

static void
uat_btmesh_record_free_cb(void *r)
{
    uat_btmesh_record_t *rec = (uat_btmesh_record_t *)r;

    g_free(rec->network_key_string);
    g_free(rec->network_key);
    g_free(rec->application_key_string);
    g_free(rec->application_key);
    g_free(rec->ivindex_string);
    g_free(rec->ivindex);
    g_free(rec->privacykey);
    g_free(rec->encryptionkey);
}

UAT_CSTRING_CB_DEF(uat_btmesh_records, network_key_string, uat_btmesh_record_t)
UAT_CSTRING_CB_DEF(uat_btmesh_records, application_key_string, uat_btmesh_record_t)
UAT_CSTRING_CB_DEF(uat_btmesh_records, ivindex_string, uat_btmesh_record_t)

static bool
uat_btmesh_dev_key_record_update_cb(void *r, char **err)
{
    uat_btmesh_dev_key_record_t *rec = (uat_btmesh_dev_key_record_t *)r;

    rec->valid = 0;

    /* Compute key & lengths once and for all */
    if (rec->device_key_string) {
        g_free(rec->device_key);
        rec->device_key_length = compute_ascii_key(&rec->device_key, rec->device_key_string, "Device Key", 16, err);
        if (*err == NULL) {
            rec->valid++;
        }
    } else {
        rec->device_key_length = 0;
        rec->device_key = NULL;
    }
    if (*err == NULL && rec->src_string) {
        g_free(rec->src);
        rec->src_length = compute_ascii_key(&rec->src, rec->src_string, "SRC Address", 2, err);
        if (*err == NULL) {
            rec->valid++;
        }
    } else {
        rec->src_length = 0;
        rec->src = NULL;
    }
    return rec->valid == BTMESH_DEVICE_KEY_ENTRY_VALID;
}

static void *
uat_btmesh_dev_key_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_btmesh_dev_key_record_t *new_rec = (uat_btmesh_dev_key_record_t *)n;
    const uat_btmesh_dev_key_record_t* old_rec = (const uat_btmesh_dev_key_record_t *)o;

    memset(new_rec, 0x00, sizeof(uat_btmesh_dev_key_record_t));

    /* Copy UAT fields */
    new_rec->device_key_string = g_strdup(old_rec->device_key_string);
    new_rec->src_string = g_strdup(old_rec->src_string);

    /* Parse key and src as in an update */
    char *err = NULL;
    uat_btmesh_dev_key_record_update_cb(new_rec, &err);
    if (err) {
        g_free(err);
    }
    return new_rec;
}

static void
uat_btmesh_dev_key_record_free_cb(void *r)
{
    uat_btmesh_dev_key_record_t *rec = (uat_btmesh_dev_key_record_t *)r;

    g_free(rec->device_key_string);
    g_free(rec->device_key);
    g_free(rec->src_string);
    g_free(rec->src);
}

UAT_CSTRING_CB_DEF(uat_btmesh_dev_key_records, device_key_string, uat_btmesh_dev_key_record_t)
UAT_CSTRING_CB_DEF(uat_btmesh_dev_key_records, src_string, uat_btmesh_dev_key_record_t)

static bool
uat_btmesh_label_uuid_record_update_cb(void *r, char **err)
{
    uat_btmesh_label_uuid_record_t *rec = (uat_btmesh_label_uuid_record_t *)r;

    rec->valid = 0;

    /* Compute label UUID & lengths */
    if (rec->label_uuid_string) {
        g_free(rec->label_uuid);
        rec->label_uuid_length = compute_ascii_key(&rec->label_uuid, rec->label_uuid_string, "Label UUID", 16, err);
        if (*err == NULL && label_uuid_hash(rec)) {
            rec->valid++;
        }
    } else {
        rec->label_uuid_length = 0;
        rec->label_uuid = NULL;
    }
    return rec->valid == BTMESH_LABEL_UUID_ENTRY_VALID;
}

static void *
uat_btmesh_label_uuid_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_btmesh_label_uuid_record_t *new_rec = (uat_btmesh_label_uuid_record_t *)n;
    const uat_btmesh_label_uuid_record_t* old_rec = (const uat_btmesh_label_uuid_record_t *)o;

    memset(new_rec, 0x00, sizeof(uat_btmesh_label_uuid_record_t));

    /* Copy UAT field */
    new_rec->label_uuid_string = g_strdup(old_rec->label_uuid_string);

    /* Parse Label UUID as in an update */
    char *err = NULL;
    uat_btmesh_label_uuid_record_update_cb(new_rec, &err);
    if (err) {
        g_free(err);
    }

    return new_rec;
}

static void
uat_btmesh_label_uuid_record_free_cb(void *r)
{
    uat_btmesh_label_uuid_record_t *rec = (uat_btmesh_label_uuid_record_t *)r;

    g_free(rec->label_uuid_string);
    g_free(rec->label_uuid);
}

UAT_CSTRING_CB_DEF(uat_btmesh_label_uuid_records, label_uuid_string, uat_btmesh_label_uuid_record_t)

void
proto_register_btmesh(void)
{
    static hf_register_info hf[] = {
        { &hf_btmesh_ivi,
            { "IVI", "btmesh.ivi",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_nid,
            { "NID", "btmesh.nid",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_obfuscated,
            { "Obfuscated", "btmesh.obfuscated",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_encrypted,
            { "Encrypted data and NetMIC", "btmesh.encrypted",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_netmic,
            { "NetMIC", "btmesh.netmic",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_ctl,
            { "CTL", "btmesh.ctl",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctl_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_ttl,
            { "TTL", "btmesh.ttl",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_seq,
            { "SEQ", "btmesh.seq",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_src,
            { "SRC", "btmesh.src",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_dst,
            { "DST", "btmesh.dst",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_transp_pdu,
            { "TransportPDU", "btmesh.transp_pdu",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_seg,
            { "SEG", "btmesh.cntr.seg",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctrl_seg_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_seg,
            { "SEG", "btmesh.acc.seg",
                FT_UINT8, BASE_DEC, VALS(btmesh_acc_seg_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_opcode,
            { "Opcode", "btmesh.cntr.opcode",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctrl_opcode_vals), 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_akf,
            { "AKF", "btmesh.acc.akf",
                FT_UINT8, BASE_DEC, VALS(btmesh_acc_akf_vals), 0x40,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_aid,
            { "AID", "btmesh.acc.aid",
                FT_UINT8, BASE_DEC, NULL, 0x3f,
                NULL, HFILL }
        },
        { &hf_btmesh_obo,
            { "OBO", "btmesh.obo",
                FT_BOOLEAN, 16, TFS(&btmesh_obo), 0x8000,
                NULL, HFILL }
        },
        { &hf_btmesh_seqzero,
            { "SeqZero", "btmesh.seqzero",
                FT_UINT16, BASE_DEC, NULL, 0x7ffc,
                NULL, HFILL }
        },
        { &hf_btmesh_rfu,
            { "Reserved for Future Use", "btmesh.rfu",
                FT_UINT16, BASE_DEC, NULL, 0x0003,
                NULL, HFILL }
        },
        { &hf_btmesh_blockack,
            { "BlockAck", "btmesh.blockack",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_rfu,
            { "RFU", "btmesh.cntr.criteria.rfu",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_padding,
            { "Padding", "btmesh.cntr.padding",
                FT_UINT8, BASE_DEC, NULL, 0xfe,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_fsn,
            { "Friend Sequence Number(FSN)", "btmesh.cntr.fsn",
                FT_UINT8, BASE_DEC, NULL, 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_key_refresh_flag,
            { "Key Refresh Flag", "btmesh.cntr.keyrefreshflag",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_key_refresh_flag_vals), 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_iv_update_flag,
            { "IV Update Flag", "btmesh.cntr.ivupdateflag",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_iv_update_flag_vals), 0x02,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_flags_rfu,
            { "IV Update Flag", "btmesh.cntr.flagsrfu",
                FT_UINT8, BASE_DEC, NULL, 0xFC,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_iv_index,
            { "IV Index", "btmesh.cntr.ivindex",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_md,
            { "MD (More Data)", "btmesh.cntr.md",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_md_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_rssifactor,
            { "RSSIFactor", "btmesh.cntr.criteria.rssifactor",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_rssifactor_vals), 0x60,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_receivewindowfactor,
            { "ReceiveWindowFactor", "btmesh.cntr.criteria.receivewindowfactor",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_receivewindowfactor_vals), 0x18,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_minqueuesizelog,
            { "MinQueueSizeLog", "btmesh.cntr.criteria.minqueuesizelog",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_minqueuesizelog_vals), 0x07,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_receivedelay,
            { "ReceiveDelay", "btmesh.cntr.receivedelay",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_polltimeout,
            { "PollTimeout", "btmesh.cntr.polltimeout",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_previousaddress,
            { "PreviousAddress", "btmesh.cntr.previousaddress",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_numelements,
            { "NumElements", "btmesh.cntr.numelements",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_lpncounter,
            { "LPNCounter", "btmesh.cntr.lpncounter",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_receivewindow,
            { "ReceiveWindow", "btmesh.cntr.receivewindow",
                FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_queuesize,
            { "QueueSize", "btmesh.cntr.queuesize",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_subscriptionlistsize,
            { "SubscriptionListSize", "btmesh.cntr.subscriptionlistsize",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_rssi,
            { "RSSI", "btmesh.cntr.rssi",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_friendcounter,
            { "FriendCounter", "btmesh.cntr.friendcounter",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_lpnaddress,
            { "LPNAddress", "btmesh.cntr.lpnaddress",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_transactionnumber,
            { "TransactionNumber", "btmesh.cntr.transactionnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_heartbeat_rfu,
            { "Reserved for Future Use", "btmesh.cntr.heartbeatrfu",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_init_ttl,
            { "InitTTL", "btmesh.cntr.initttl",
                FT_UINT8, BASE_DEC, NULL, 0x7F,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_relay,
            { "Relay feature in use", "btmesh.cntr.feature.relay",
                FT_BOOLEAN, 16, NULL, 0x0001,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_proxy,
            { "Proxy feature in use", "btmesh.cntr.feature.proxy",
                FT_BOOLEAN, 16, NULL, 0x0002,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_friend,
            { "Friend feature in use", "btmesh.cntr.feature.friend",
                FT_BOOLEAN, 16, NULL, 0x0004,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_low_power,
            { "Low Power feature in use", "btmesh.cntr.feature.lowpower",
                FT_BOOLEAN, 16, NULL, 0x0008,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_rfu,
            { "Reserved for Future Use", "btmesh.cntr.feature.rfu",
                FT_UINT16, BASE_DEC, NULL, 0xfff0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_unknown_payload,
            { "Unknown Control Message payload", "btmesh.cntr.unknownpayload",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
            },
        { &hf_btmesh_enc_access_pld,
            { "Encrypted Access Payload", "btmesh.enc_access_pld",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
            },
        { &hf_btmesh_transtmic,
            { "TransMIC", "btmesh.transtmic",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
            },
        { &hf_btmesh_szmic,
            { "SZMIC", "btmesh.szmic",
                FT_UINT24, BASE_DEC, VALS(btmesh_szmic_vals), 0x800000,
                NULL, HFILL }
            },
        { &hf_btmesh_seqzero_data,
            { "SeqZero", "btmesh.seqzero_data",
                FT_UINT24, BASE_DEC, NULL, 0x7ffc00,
                NULL, HFILL }
            },
        { &hf_btmesh_sego,
            { "Segment Offset number(SegO)", "btmesh.sego",
                FT_UINT24, BASE_DEC, NULL, 0x0003e0,
                NULL, HFILL }
            },
        { &hf_btmesh_segn,
            { "Last Segment number(SegN)", "btmesh.segn",
                FT_UINT24, BASE_DEC, NULL, 0x00001f,
                NULL, HFILL }
            },
        { &hf_btmesh_seg_rfu,
            { "RFU", "btmesh.seg.rfu",
                FT_UINT24, BASE_DEC, NULL, 0x800000,
                NULL, HFILL }
            },
        { &hf_btmesh_segment,
            { "Segment", "btmesh.segment",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
            },
        /* Access Message Reassembly */
        { &hf_btmesh_segmented_access_fragments,
            { "Reassembled Segmented Access Message Fragments", "btmesh.segmented.access.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_access_fragment,
            { "Segmented Access Message Fragment", "btmesh.segmented.access.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_overlap,
            { "Fragment overlap", "btmesh.segmented.access.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "btmesh.segmented.access.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_multiple_tails,
            { "Multiple tail fragments found", "btmesh.segmented.access.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_too_long_fragment,
            { "Fragment too long", "btmesh.segmented.access.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_error,
            { "Defragmentation error", "btmesh.segmented.access.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_count,
            { "Fragment count", "btmesh.segmented.access.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_access_reassembled_length,
            { "Reassembled Segmented Access Message length", "btmesh.segmented.access.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
        /* Control Message Reassembly */
        { &hf_btmesh_segmented_control_fragments,
            { "Reassembled Segmented Control Message Fragments", "btmesh.segmented.control.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Segmented Access Message Fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment,
            { "Segmented Control Message Fragment", "btmesh.segmented.control.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_overlap,
            { "Fragment overlap", "btmesh.segmented.control.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "btmesh.segmented.control.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_multiple_tails,
            { "Multiple tail fragments found", "btmesh.segmented.control.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_too_long_fragment,
            { "Fragment too long", "btmesh.segmented.control.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_error,
            { "Defragmentation error", "btmesh.segmented.control.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_count,
            { "Fragment count", "btmesh.segmented.control.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_control_reassembled_length,
            { "Reassembled Segmented Control Message length", "btmesh.segmented.control.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
        { &hf_btmesh_decrypted_access,
            { "Decrypted Access", "btmesh.access.decrypted",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_vendor_opcode,
            { "Opcode", "btmesh.model.vendor.opcode",
                FT_UINT8, BASE_DEC, NULL, 0x3f,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_vendor,
            { "Company ID", "btmesh.model.vendor",
                FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_opcode,
            { "Opcode", "btmesh.model.opcode",
                FT_UINT16, BASE_HEX, VALS(btmesh_models_opcode_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_model_layer_parameters,
            { "Parameters", "btmesh.model.parameters",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        /* Config Model opcodes parameters */
        { &hf_btmesh_config_appkey_add_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_add.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_add.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0x000FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_add_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_add.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_add_appkey,
            { "AppKey", "btmesh.model.config_appkey_add.appkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_update.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_update.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0x000FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_update.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_update_appkey,
            { "AppKey", "btmesh.model.config_appkey_update.appkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_page,
            { "Page", "btmesh.model.config_composition_data_status.page",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_cid,
            { "CID", "btmesh.model.config_composition_data_status.cid",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_pid,
            { "PID", "btmesh.model.config_composition_data_status.pid",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_vid,
            { "VID", "btmesh.model.config_composition_data_status.vid",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_crpl,
            { "CRPL", "btmesh.model.config_composition_data_status.crpl",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_relay,
            { "Relay feature", "btmesh.model.config_composition_data_status.features.relay",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_proxy,
            { "Proxy feature", "btmesh.model.config_composition_data_status.features.proxy",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0002,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_friend,
            { "Friend feature", "btmesh.model.config_composition_data_status.features.friend",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0004,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_low_power,
            { "Low Power feature", "btmesh.model.config_composition_data_status.features.low_power",
            FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0008,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features_rfu,
            { "RFU", "btmesh.model.config_composition_data_status.features.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_features,
            { "Features", "btmesh.model.config_composition_data_status.features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_loc,
            { "Loc", "btmesh.model.config_composition_data_status.loc",
            FT_UINT16, BASE_HEX, VALS(characteristic_presentation_namespace_description_btsig_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_nums,
            { "NumS", "btmesh.model.config_composition_data_status.nums",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_numv,
            { "NumV", "btmesh.model.config_composition_data_status.numv",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_sig_model,
            { "SIG Model", "btmesh.model.config_composition_data_status.sig_model",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_status_vendor_model,
            { "Vendor Model", "btmesh.model.config_composition_data_status.vendor_model",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_set.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishaddress,
            { "PublishAddress", "btmesh.model.config_model_publication_set.publishaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_appkey,
            { "AppKeyIndex", "btmesh.model.config_model_publication_set.appkey",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_publish_appkeyindex_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_publication_set.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_credentialflag,
            { "CredentialFlag", "btmesh.model.config_model_publication_set.credentialflag",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0x1000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_rfu,
            { "RFU", "btmesh.model.config_model_publication_set.rfu",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0xE000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishttl,
            { "PublishTTL", "btmesh.model.config_model_publication_set.publishttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishperiod,
            { "PublishPeriod", "btmesh.model.config_model_publication_set.publishperiod",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishperiod_resolution,
            { "Step Resolution", "btmesh.model.config_model_publication_set.publishperiod.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishperiod_steps,
            { "Number of Steps", "btmesh.model.config_model_publication_set.publishperiod.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishretransmit,
            { "PublishRetransmit", "btmesh.model.config_model_publication_set.publishretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishretransmit_count,
            { "PublishRetransmitCount", "btmesh.model.config_model_publication_set.publishretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_publishretransmit_intervalsteps,
            { "PublishRetransmitIntervalSteps", "btmesh.model.config_model_publication_set.publishretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_set.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_set_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_set.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_current_status_test_id,
            { "Test ID", "btmesh.model.health_current_status.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_current_status_company_id,
            { "Company ID", "btmesh.model.health_current_status.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_current_status_fault,
            { "Fault", "btmesh.model.health_current_status.fault",
            FT_UINT8, BASE_DEC, VALS(btmesh_fault_array_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_status_test_id,
            { "Test ID", "btmesh.model.health_fault_status.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_status_company_id,
            { "Company ID", "btmesh.model.health_fault_status.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_status_fault,
            { "Fault", "btmesh.model.health_fault_status.fault",
            FT_UINT8, BASE_DEC, VALS(btmesh_fault_array_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_status,
            { "Status", "btmesh.model.config_heartbeat_publication_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_destination,
            { "Destination", "btmesh.model.config_heartbeat_publication_status.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_countlog,
            { "CountLog", "btmesh.model.config_heartbeat_publication_status.countlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_publication_status.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_ttl,
            { "TTL", "btmesh.model.config_heartbeat_publication_status.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_relay,
            { "Relay feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.relay",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_proxy,
            { "Proxy feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.proxy",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_friend,
            { "Friend feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.friend",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_low_power,
            { "Low Power feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_status.features.low_power",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_status.features.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_features,
            { "Features", "btmesh.model.config_heartbeat_publication_status.features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_status.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_status.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_status.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_delete.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_delete.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0x000FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_delete_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_delete.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_get_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_appkey_get.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_get_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_appkey_get.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_get_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_appkey_get.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_status,
            { "Status", "btmesh.model.config_appkey_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_appkey_list.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_appkey_list.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_appkey_list.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_appkey_list.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_list_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_appkey_list.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_status,
            { "Status", "btmesh.model.config_appkey_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_netkeyindexandappkeyindex,
            { "NetKeyIndexAndAppKeyIndex", "btmesh.model.config_appkey_status.netkeyindexandappkeyindex",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_dual_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_net,
            { "NetKeyIndex", "btmesh.model.config_appkey_status.netkeyindexandappkeyindex.net",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0x000FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_appkey_status_netkeyindexandappkeyindex_app,
            { "AppKeyIndex", "btmesh.model.config_appkey_status.netkeyindexandappkeyindex.app",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_key_index), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_health_attention_set_attention,
            { "Attention", "btmesh.model.health_attention_set.attention",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_attention_set_unacknowledged_attention,
            { "Attention", "btmesh.model.health_attention_set_unacknowledged.attention",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_attention_status_attention,
            { "Attention", "btmesh.model.health_attention_status.attention",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_composition_data_get_page,
            { "Page", "btmesh.model.config_composition_data_get.page",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_beacon_set_beacon,
            { "Beacon", "btmesh.model.config_beacon_set.beacon",
            FT_UINT8, BASE_DEC, VALS(btmesh_beacon_broadcast_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_beacon_status_beacon,
            { "Beacon", "btmesh.model.config_beacon_status.beacon",
            FT_UINT8, BASE_DEC, VALS(btmesh_beacon_broadcast_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_default_ttl_set_ttl,
            { "TTL", "btmesh.model.config_default_ttl_set.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_default_ttl_status_ttl,
            { "TTL", "btmesh.model.config_default_ttl_status.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_friend_set_friend,
            { "Friend", "btmesh.model.config_friend_set.friend",
            FT_UINT8, BASE_DEC, VALS(btmesh_friend_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_friend_status_friend,
            { "Friend", "btmesh.model.config_friend_status.friend",
            FT_UINT8, BASE_DEC, VALS(btmesh_friend_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_gatt_proxy_set_gattproxy,
            { "GATTProxy", "btmesh.model.config_gatt_proxy_set.gattproxy",
            FT_UINT8, BASE_HEX, VALS(btmesh_gatt_proxy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_gatt_proxy_status_gattproxy,
            { "GATTProxy", "btmesh.model.config_gatt_proxy_status.gattproxy",
            FT_UINT8, BASE_HEX, VALS(btmesh_gatt_proxy_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_get_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_get.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_get_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_get.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_get_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_key_refresh_phase_get.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_set.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_set.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_key_refresh_phase_set.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_set_transition,
            { "Transition", "btmesh.model.config_key_refresh_phase_set.transition",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(btmesh_transition_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_status,
            { "Status", "btmesh.model.config_key_refresh_phase_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_status.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_key_refresh_phase_status.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_key_refresh_phase_status.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_key_refresh_phase_status_phase,
            { "Phase", "btmesh.model.config_key_refresh_phase_status.phase",
            FT_UINT8, BASE_DEC, VALS(btmesh_phase_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_get.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_get_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_get.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_status,
            { "Status", "btmesh.model.config_model_publication_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_status.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishaddress,
            { "PublishAddress", "btmesh.model.config_model_publication_status.publishaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_appkey,
            { "AppKeyIndex", "btmesh.model.config_model_publication_status.appkey",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_publish_appkeyindex_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_publication_status.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_credentialflag,
            { "CredentialFlag", "btmesh.model.config_model_publication_status.credentialflag",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0x1000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_rfu,
            { "RFU", "btmesh.model.config_model_publication_status.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishttl,
            { "PublishTTL", "btmesh.model.config_model_publication_status.publishttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishperiod,
            { "PublishPeriod", "btmesh.model.config_model_publication_status.publishperiod",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishperiod_resolution,
            { "Step Resolution", "btmesh.model.config_model_publication_status.publishperiod.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishperiod_steps,
            { "Number of Steps", "btmesh.model.config_model_publication_status.publishperiod.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishretransmit,
            { "PublishRetransmit", "btmesh.model.config_model_publication_status.publishretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishretransmit_count,
            { "PublishRetransmitCount", "btmesh.model.config_model_publication_status.publishretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_publishretransmit_intervalsteps,
            { "PublishRetransmitIntervalSteps", "btmesh.model.config_model_publication_status.publishretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_status.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_status_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_status.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_publication_virtual_address_set.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishaddress,
            { "PublishAddress", "btmesh.model.config_model_publication_virtual_address_set.publishaddress",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_appkey,
            { "AppKeyIndex", "btmesh.model.config_model_publication_virtual_address_set.appkey",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_publish_appkeyindex_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_publication_virtual_address_set.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_credentialflag,
            { "CredentialFlag", "btmesh.model.config_model_publication_virtual_address_set.credentialflag",
            FT_UINT16, BASE_DEC, VALS(btmesh_friendship_credentials_flag_vals), 0x1000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_rfu,
            { "RFU", "btmesh.model.config_model_publication_virtual_address_set.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishttl,
            { "PublishTTL", "btmesh.model.config_model_publication_virtual_address_set.publishttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishperiod,
            { "PublishPeriod", "btmesh.model.config_model_publication_virtual_address_set.publishperiod",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishperiod_resolution,
            { "Step Resolution", "btmesh.model.config_model_publication_virtual_address_set.publishperiod.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishperiod_steps,
            { "Number of Steps", "btmesh.model.config_model_publication_virtual_address_set.publishperiod.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishretransmit,
            { "PublishRetransmit", "btmesh.model.config_model_publication_virtual_address_set.publishretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_count,
            { "PublishRetransmitCount", "btmesh.model.config_model_publication_virtual_address_set.publishretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_publishretransmit_intervalsteps,
            { "PublishRetransmitIntervalSteps", "btmesh.model.config_model_publication_virtual_address_set.publishretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_virtual_address_set.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_publication_virtual_address_set_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_publication_virtual_address_set.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_add.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_address,
            { "Address", "btmesh.model.config_model_subscription_add.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_add.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_add_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_add.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_delete.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_address,
            { "Address", "btmesh.model.config_model_subscription_delete.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_all_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_delete_all.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_all_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete_all.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_delete_all_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_delete_all.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_overwrite.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_address,
            { "Address", "btmesh.model.config_model_subscription_overwrite.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_overwrite.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_overwrite_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_overwrite.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_status,
            { "Status", "btmesh.model.config_model_subscription_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_status.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_address,
            { "Address", "btmesh.model.config_model_subscription_status.address",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_status.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_status_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_status.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_virtual_address_add.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_label,
            { "Label", "btmesh.model.config_model_subscription_virtual_address_add.label",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_add.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_add_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_add.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_virtual_address_delete.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_label,
            { "Label", "btmesh.model.config_model_subscription_virtual_address_delete.label",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_delete.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_delete_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_delete.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_subscription_virtual_address_overwrite.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_label,
            { "Label", "btmesh.model.config_model_subscription_virtual_address_overwrite.label",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_overwrite.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_subscription_virtual_address_overwrite_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_subscription_virtual_address_overwrite.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_set_networktransmit,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_set.networktransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_transmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_set_networktransmit_count,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_set.networktransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_set_networktransmit_intervalsteps,
            { "NetworkTransmitIntervalSteps", "btmesh.model.config_network_transmit_set.networktransmitinterval.steps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_status_networktransmit,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_status.networktransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_transmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_status_networktransmit_count,
            { "NetworkTransmitCount", "btmesh.model.config_network_transmit_status.networktransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_network_transmit_status_networktransmit_intervalsteps,
            { "NetworkTransmitIntervalSteps", "btmesh.model.config_network_transmit_status.networktransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relay,
            { "Relay", "btmesh.model.config_relay_set.relay",
            FT_UINT8, BASE_DEC, VALS(btmesh_relay_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relayretransmit,
            { "RelayRetransmitCount", "btmesh.model.config_relay_set.relayretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relayretransmit_count,
            { "RelayRetransmitCount", "btmesh.model.config_relay_set.relayretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_set_relayretransmit_intervalsteps,
            { "RelayRetransmitIntervalSteps", "btmesh.model.config_relay_set.relayretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relay,
            { "Relay", "btmesh.model.config_relay_status.relay",
            FT_UINT8, BASE_DEC, VALS(btmesh_relay_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relayretransmit,
            { "RelayRetransmit", "btmesh.model.config_relay_status.relayretransmit",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_retransmit), 0x00,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relayretransmit_count,
            { "RelayRetransmitCount", "btmesh.model.config_relay_status.relayretransmit.count",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btmesh_config_relay_status_relayretransmit_intervalsteps,
            { "RelayRetransmitIntervalSteps", "btmesh.model.config_relay_status.relayretransmit.intervalsteps",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_interval_steps), 0xF8,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_subscription_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_subscription_get.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_status,
            { "Status", "btmesh.model.config_sig_model_subscription_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_subscription_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_subscription_list.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_subscription_list_address,
            { "Address", "btmesh.model.config_sig_model_subscription_list.address",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_subscription_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_subscription_get.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_status,
            { "Status", "btmesh.model.config_vendor_model_subscription_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_subscription_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_subscription_list.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_subscription_list_address,
            { "Address", "btmesh.model.config_vendor_model_subscription_list.address",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_low_power_node_polltimeout_get_lpnaddress,
            { "LPNAddress", "btmesh.model.config_low_power_node_polltimeout_get.lpnaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_low_power_node_polltimeout_status_lpnaddress,
            { "LPNAddress", "btmesh.model.config_low_power_node_polltimeout_status.lpnaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_low_power_node_polltimeout_status_polltimeout,
            { "PollTimeout", "btmesh.model.config_low_power_node_polltimeout_status.polltimeout",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_clear_company_id,
            { "Company ID", "btmesh.model.health_fault_clear.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_clear_unacknowledged_company_id,
            { "Company ID", "btmesh.model.health_fault_clear_unacknowledged.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_get_company_id,
            { "Company ID", "btmesh.model.health_fault_get.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_test_id,
            { "Test ID", "btmesh.model.health_fault_test.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_company_id,
            { "Company ID", "btmesh.model.health_fault_test.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_unacknowledged_test_id,
            { "Test ID", "btmesh.model.health_fault_test_unacknowledged.test_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_fault_test_unacknowledged_company_id,
            { "Company ID", "btmesh.model.health_fault_test_unacknowledged.company_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_period_set_fast_period_divisor,
            { "Fast Period Divisor", "btmesh.model.health_period_set.fast_period_divisor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_period_set_unacknowledged_fast_period_divisor,
            { "Fast Period Divisor", "btmesh.model.health_period_set_unacknowledged.fast_period_divisor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_health_period_status_fast_period_divisor,
            { "Fast Period Divisor", "btmesh.model.health_period_status.fast_period_divisor",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_destination,
            { "Destination", "btmesh.model.config_heartbeat_publication_set.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_countlog,
            { "CountLog", "btmesh.model.config_heartbeat_publication_set.countlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_publication_set.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_ttl,
            { "TTL", "btmesh.model.config_heartbeat_publication_set.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_relay,
            { "Relay feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.relay",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_proxy,
            { "Proxy feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.proxy",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_friend,
            { "Friend feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.friend",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_low_power,
            { "Low Power feature change triggers a Heartbeat message", "btmesh.model.config_heartbeat_publication_set.features.low_power",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_set.features.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_features,
            { "Features", "btmesh.model.config_heartbeat_publication_set.features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_set.netkeyindex",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_heartbeat_publication_set.netkeyindex.idx",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_publication_set_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_heartbeat_publication_set.netkeyindex.rfu",
                FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
                NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_set_source,
            { "Source", "btmesh.model.config_heartbeat_subscription_set.source",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_set_destination,
            { "Destination", "btmesh.model.config_heartbeat_subscription_set.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_set_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_subscription_set.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_status,
            { "Status", "btmesh.model.config_heartbeat_subscription_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_source,
            { "Source", "btmesh.model.config_heartbeat_subscription_status.source",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_destination,
            { "Destination", "btmesh.model.config_heartbeat_subscription_status.destination",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_periodlog,
            { "PeriodLog", "btmesh.model.config_heartbeat_subscription_status.periodlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_countlog,
            { "CountLog", "btmesh.model.config_heartbeat_subscription_status.countlog",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_minhops,
            { "MinHops", "btmesh.model.config_heartbeat_subscription_status.minhops",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_heartbeat_subscription_status_maxhops,
            { "MaxHops", "btmesh.model.config_heartbeat_subscription_status.maxhops",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_app_bind.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_app_bind.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_appkeyindex_idx,
            { "AppKeyIndex", "btmesh.model.config_model_app_bind.appkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_model_app_bind.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_bind.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_bind_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_bind.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_status,
            { "Status", "btmesh.model.config_model_app_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_app_status.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_app_status.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_appkeyindex_idx,
            { "AppKeyIndex", "btmesh.model.config_model_app_status.appkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_model_app_status.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_status.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_status_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_status.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_elementaddress,
            { "ElementAddress", "btmesh.model.config_model_app_unbind.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_model_app_unbind.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_appkeyindex_idx,
            { "AppKeyIndex", "btmesh.model.config_model_app_unbind.appkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_appkeyindex_rfu,
            { "AppKeyIndex", "btmesh.model.config_model_app_unbind.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_unbind.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_model_app_unbind_vendormodelidentifier,
            { "ModelIdentifier", "btmesh.model.config_model_app_unbind.vendormodelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_add.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_add.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_add.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_add_netkey,
            { "NetKey", "btmesh.model.config_netkey_add.netkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_delete_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_delete.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_delete_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_delete.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_delete_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_delete.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_list_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_list.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_list_netkeyindex_rfu,
            { "NetKeyIndex RFU", "btmesh.model.config_netkey_list.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_status,
            { "Status", "btmesh.model.config_netkey_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_status.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_status.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_status.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_netkey_update.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_netkey_update.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_netkey_update.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_netkey_update_netkey,
            { "NetKey", "btmesh.model.config_netkey_update.netkey",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_get_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_node_identity_get.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_get_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_node_identity_get.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_get_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_node_identity_get.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_node_identity_set.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_node_identity_set.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_node_identity_set.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_set_identity,
            { "Identity", "btmesh.model.config_node_identity_set.identity",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_status,
            { "Status", "btmesh.model.config_node_identity_status.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_netkeyindex,
            { "NetKeyIndex", "btmesh.model.config_node_identity_status.netkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_netkeyindex_idx,
            { "NetKeyIndex", "btmesh.model.config_node_identity_status.netkeyindex.idx",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_netkeyindex_rfu,
            { "RFU", "btmesh.model.config_node_identity_status.netkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_config_node_identity_status_identity,
            { "Identity", "btmesh.model.config_node_identity_status.identity",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_app_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_app_get.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_status,
            { "Status", "btmesh.model.config_sig_model_app_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_sig_model_app_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_sig_model_app_list.modelidentifier",
            FT_UINT16, BASE_HEX, VALS(btmesh_model_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_sig_model_app_list.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_sig_model_app_list_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_sig_model_app_list.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_get_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_app_get.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_get_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_app_get.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_status,
            { "Status", "btmesh.model.config_vendor_model_app_list.status",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_elementaddress,
            { "ElementAddress", "btmesh.model.config_vendor_model_app_list.elementaddress",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_modelidentifier,
            { "ModelIdentifier", "btmesh.model.config_vendor_model_app_list.modelidentifier",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_vendor_model), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_appkeyindex,
            { "AppKeyIndex", "btmesh.model.config_vendor_model_app_list.appkeyindex",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_config_vendor_model_app_list_appkeyindex_rfu,
            { "RFU", "btmesh.model.config_vendor_model_app_list.appkeyindex.rfu",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_key_index_rfu), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_status_global_latitude,
            { "Global Latitude", "btmesh.model.generic_location_global_status.global_latitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(format_global_latitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_status_global_longitude,
            { "Global Longitude", "btmesh.model.generic_location_global_status.global_longitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(format_global_longitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_status_global_altitude,
            { "Global Altitude", "btmesh.model.generic_location_global_status.global_altitude",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_global_altitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_set_global_latitude,
            { "Global Latitude", "btmesh.model.generic_location_global_set.global_latitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(format_global_latitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_set_global_longitude,
            { "Global Longitude", "btmesh.model.generic_location_global_set.global_longitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(format_global_longitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_set_global_altitude,
            { "Global Altitude", "btmesh.model.generic_location_global_set.global_altitude",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_global_altitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_set_unacknowledged_global_latitude,
            { "Global Latitude", "btmesh.model.generic_location_global_set_unacknowledged.global_latitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(format_global_latitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_set_unacknowledged_global_longitude,
            { "Global Longitude", "btmesh.model.generic_location_global_set_unacknowledged.global_longitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(format_global_longitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_global_set_unacknowledged_global_altitude,
            { "Global Altitude", "btmesh.model.generic_location_global_set_unacknowledged.global_altitude",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_global_altitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_onoff,
            { "OnOff", "btmesh.model.generic_onoff_set.onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_tid,
            { "TID", "btmesh.model.generic_onoff_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_transition_time,
            { "Transition Time", "btmesh.model.generic_onoff_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_onoff_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_onoff_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_delay,
            { "Delay", "btmesh.model.generic_onoff_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_unacknowledged_onoff,
            { "OnOff", "btmesh.model.generic_onoff_set_unacknowledged.onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_unacknowledged_tid,
            { "TID", "btmesh.model.generic_onoff_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.generic_onoff_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_onoff_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_onoff_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_set_unacknowledged_delay,
            { "Delay", "btmesh.model.generic_onoff_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_status_present_onoff,
            { "Present OnOff", "btmesh.model.generic_onoff_status.present_onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_status_target_onoff,
            { "Target OnOff", "btmesh.model.generic_onoff_status.target_onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_status_remaining_time,
            { "Remaining Time", "btmesh.model.generic_onoff_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.generic_onoff_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onoff_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.generic_onoff_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_level,
            { "Level", "btmesh.model.generic_level_set.level",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_tid,
            { "TID", "btmesh.model.generic_level_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_transition_time,
            { "Transition Time", "btmesh.model.generic_level_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_level_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_level_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_delay,
            { "Delay", "btmesh.model.generic_level_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_unacknowledged_level,
            { "Level", "btmesh.model.generic_level_set_unacknowledged.level",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_unacknowledged_tid,
            { "TID", "btmesh.model.generic_level_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.generic_level_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_level_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_level_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_set_unacknowledged_delay,
            { "Delay", "btmesh.model.generic_level_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_status_present_level,
            { "Present Level", "btmesh.model.generic_level_status.present_level",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_status_target_level,
            { "Target Level", "btmesh.model.generic_level_status.target_level",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_status_remaining_time,
            { "Remaining Time", "btmesh.model.generic_level_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.generic_level_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_level_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.generic_level_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_delta_level,
            { "Delta Level", "btmesh.model.generic_delta_set.delta_level",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_tid,
            { "TID", "btmesh.model.generic_delta_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_transition_time,
            { "Transition Time", "btmesh.model.generic_delta_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_delta_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_delta_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_delay,
            { "Delay", "btmesh.model.generic_delta_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_unacknowledged_delta_level,
            { "Delta Level", "btmesh.model.generic_delta_set_unacknowledged.delta_level",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_unacknowledged_tid,
            { "TID", "btmesh.model.generic_delta_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.generic_delta_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_delta_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_delta_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_delta_set_unacknowledged_delay,
            { "Delay", "btmesh.model.generic_delta_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_delta_level,
            { "Delta Level", "btmesh.model.generic_move_set.delta_level",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_tid,
            { "TID", "btmesh.model.generic_move_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_transition_time,
            { "Transition Time", "btmesh.model.generic_move_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_move_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_move_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_delay,
            { "Delay", "btmesh.model.generic_move_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_unacknowledged_delta_level,
            { "Delta Level", "btmesh.model.generic_move_set_unacknowledged.delta_level",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_unacknowledged_tid,
            { "TID", "btmesh.model.generic_move_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.generic_move_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_move_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_move_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_move_set_unacknowledged_delay,
            { "Delay", "btmesh.model.generic_move_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_set_transition_time,
            { "Transition Time", "btmesh.model.generic_default_transition_time_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_default_transition_time_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_default_transition_time_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.generic_default_transition_time_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_default_transition_time_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_default_transition_time_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_status_transition_time,
            { "Transition Time", "btmesh.model.generic_default_transition_time_status.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_status_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_default_transition_time_status.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_default_transition_time_status_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_default_transition_time_status.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onpowerup_status_onpowerup,
            { "OnPowerUp", "btmesh.model.generic_onpowerup_status.onpowerup",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_onpowerup_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onpowerup_set_onpowerup,
            { "OnPowerUp", "btmesh.model.generic_onpowerup_set.onpowerup",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_onpowerup_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_onpowerup_set_unacknowledged_onpowerup,
            { "OnPowerUp", "btmesh.model.generic_onpowerup_set_unacknowledged.onpowerup",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_onpowerup_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_power,
            { "Power", "btmesh.model.generic_power_level_set.power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_tid,
            { "TID", "btmesh.model.generic_power_level_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_transition_time,
            { "Transition Time", "btmesh.model.generic_power_level_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_power_level_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_power_level_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_delay,
            { "Delay", "btmesh.model.generic_power_level_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_unacknowledged_power,
            { "Power", "btmesh.model.generic_power_level_set_unacknowledged.power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_unacknowledged_tid,
            { "TID", "btmesh.model.generic_power_level_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.generic_power_level_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.generic_power_level_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.generic_power_level_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_set_unacknowledged_delay,
            { "Delay", "btmesh.model.generic_power_level_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_status_present_power,
            { "Present Power", "btmesh.model.generic_power_level_status.present_power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_status_target_power,
            { "Target Power", "btmesh.model.generic_power_level_status.target_power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_status_remaining_time,
            { "Remaining Time", "btmesh.model.generic_power_level_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.generic_power_level_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_level_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.generic_power_level_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_last_status_power,
            { "Power", "btmesh.model.generic_power_last_status.power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_default_status_power,
            { "Power", "btmesh.model.generic_power_default_status.power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_range_status_status_code,
            { "Status Code", "btmesh.model.generic_power_range_status.status_code",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_range_status_range_min,
            { "Range Min", "btmesh.model.generic_power_range_status.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_range_status_range_max,
            { "Range Max", "btmesh.model.generic_power_range_status.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_default_set_power,
            { "Power", "btmesh.model.generic_power_default_set.power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_default_set_unacknowledged_power,
            { "Power", "btmesh.model.generic_power_default_set_unacknowledged.power",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_range_set_range_min,
            { "Range Min", "btmesh.model.generic_power_range_set.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_range_set_range_max,
            { "Range Max", "btmesh.model.generic_power_range_set.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_range_set_unacknowledged_range_min,
            { "Range Min", "btmesh.model.generic_power_range_set_unacknowledged.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_power_range_set_unacknowledged_range_max,
            { "Range Max", "btmesh.model.generic_power_range_set_unacknowledged.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_power), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_battery_status_battery_level,
            { "Battery Level", "btmesh.model.generic_battery_status.battery_level",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_battery_level), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_battery_status_time_to_discharge,
            { "Time to Discharge", "btmesh.model.generic_battery_status.time_to_discharge",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_battery_time), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_battery_status_time_to_charge,
            { "Time to Charge", "btmesh.model.generic_battery_status.time_to_charge",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_battery_time), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_battery_status_flags_presence,
            { "Flags", "btmesh.model.generic_battery_status.flags.presence",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_battery_flags_presence_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_battery_status_flags_indicator,
            { "Flags", "btmesh.model.generic_battery_status.flags.indicator",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_battery_flags_indicator_vals), 0x0C,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_battery_status_flags_charging,
            { "Flags", "btmesh.model.generic_battery_status.flags.charging",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_battery_flags_charging_vals), 0x30,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_battery_status_flags_serviceability,
            { "Flags", "btmesh.model.generic_battery_status.flags.serviceability",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_battery_flags_serviceability_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_local_north,
            { "Local North", "btmesh.model.generic_location_local_status.local_north",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_north), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_local_east,
            { "Local East", "btmesh.model.generic_location_local_status.local_east",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_east), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_local_altitude,
            { "Local Altitude", "btmesh.model.generic_location_local_status.local_altitude",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_altitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_floor_number,
            { "Floor Number", "btmesh.model.generic_location_local_status.floor_number",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_floor_number), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_uncertainty_stationary,
            { "Stationary", "btmesh.model.generic_location_local_status.uncertainty.stationary",
            FT_UINT16, BASE_DEC, VALS(btmesh_generic_location_local_stationary_vals), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_uncertainty_rfu,
            { "RFU", "btmesh.model.generic_location_local_status.uncertainty.rfu",
            FT_UINT16, BASE_DEC, NULL, 0x00FE,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_uncertainty_update_time,
            { "Update Time", "btmesh.model.generic_location_local_status.uncertainty.update_time",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_update_time), 0x0F00,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_status_uncertainty_precision,
            { "Precision", "btmesh.model.generic_location_local_status.uncertainty.precision",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_precision), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_local_north,
            { "Local North", "btmesh.model.generic_location_local_set.local_north",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_north), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_local_east,
            { "Local East", "btmesh.model.generic_location_local_set.local_east",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_east), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_local_altitude,
            { "Local Altitude", "btmesh.model.generic_location_local_set.local_altitude",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_altitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_floor_number,
            { "Floor Number", "btmesh.model.generic_location_local_set.floor_number",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_floor_number), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_uncertainty_stationary,
            { "Stationary", "btmesh.model.generic_location_local_set.uncertainty.stationary",
            FT_UINT16, BASE_DEC, VALS(btmesh_generic_location_local_stationary_vals), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_uncertainty_rfu,
            { "RFU", "btmesh.model.generic_location_local_set.uncertainty.rfu",
            FT_UINT16, BASE_DEC, NULL, 0x00FE,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_uncertainty_update_time,
            { "Update Time", "btmesh.model.generic_location_local_set.uncertainty.update_time",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_update_time), 0x0F00,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_uncertainty_precision,
            { "Precision", "btmesh.model.generic_location_local_set.uncertainty.precision",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_precision), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_local_north,
            { "Local North", "btmesh.model.generic_location_local_set_unacknowledged.local_north",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_north), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_local_east,
            { "Local East", "btmesh.model.generic_location_local_set_unacknowledged.local_east",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_east), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_local_altitude,
            { "Local Altitude", "btmesh.model.generic_location_local_set_unacknowledged.local_altitude",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_local_altitude), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_floor_number,
            { "Floor Number", "btmesh.model.generic_location_local_set_unacknowledged.floor_number",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_floor_number), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_stationary,
            { "Stationary", "btmesh.model.generic_location_local_set_unacknowledged.uncertainty.stationary",
            FT_UINT16, BASE_DEC, VALS(btmesh_generic_location_local_stationary_vals), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_rfu,
            { "RFU", "btmesh.model.generic_location_local_set_unacknowledged.uncertainty.rfu",
            FT_UINT16, BASE_DEC, NULL, 0x00FE,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_update_time,
            { "Update Time", "btmesh.model.generic_location_local_set_unacknowledged.uncertainty.update_time",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_update_time), 0x0F00,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_location_local_set_unacknowledged_uncertainty_precision,
            { "Precision", "btmesh.model.generic_location_local_set_unacknowledged.uncertainty.precision",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_precision), 0xF000,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_status_status_code,
            { "Status Code", "btmesh.model.scene_status.status_code",
            FT_UINT8, BASE_DEC, VALS(btmesh_scene_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_status_current_scene,
            { "Current Scene", "btmesh.model.scene_status.current_scene",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_status_target_scene,
            { "Target Scene", "btmesh.model.scene_status.target_scene",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_status_remaining_time,
            { "Remaining Time", "btmesh.model.scene_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.scene_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.scene_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_scene_number,
            { "Scene Number", "btmesh.model.scene_recall.scene_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_tid,
            { "TID", "btmesh.model.scene_recall.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_transition_time,
            { "Transition Time", "btmesh.model.scene_recall.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_transition_time_resolution,
            { "Step Resolution", "btmesh.model.scene_recall.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_transition_time_steps,
            { "Number of Steps", "btmesh.model.scene_recall.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_delay,
            { "Delay", "btmesh.model.scene_recall.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_unacknowledged_scene_number,
            { "Scene Number", "btmesh.model.scene_recall_unacknowledged.scene_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_unacknowledged_tid,
            { "TID", "btmesh.model.scene_recall_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.scene_recall_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.scene_recall_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.scene_recall_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_recall_unacknowledged_delay,
            { "Delay", "btmesh.model.scene_recall_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_register_status_status_code,
            { "Status Code", "btmesh.model.scene_register_status.status_code",
            FT_UINT8, BASE_DEC, VALS(btmesh_scene_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_register_status_current_scene,
            { "Current Scene", "btmesh.model.scene_register_status.current_scene",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_register_status_scene,
            { "Scene", "btmesh.model.scene_register_status.scene",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_store_scene_number,
            { "Scene Number", "btmesh.model.scene_store.scene_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_store_unacknowledged_scene_number,
            { "Scene Number", "btmesh.model.scene_store_unacknowledged.scene_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_delete_scene_number,
            { "Scene Number", "btmesh.model.scene_delete.scene_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scene_delete_unacknowledged_scene_number,
            { "Scene Number", "btmesh.model.scene_delete_unacknowledged.scene_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_set_tai_seconds,
            { "TAI Seconds", "btmesh.model.time_set.tai_seconds",
            FT_UINT40, BASE_CUSTOM, CF_FUNC(format_tai_to_utc_date), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_set_subsecond,
            { "Subsecond", "btmesh.model.time_set.subsecond",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_subsecond_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_set_uncertainty,
            { "Uncertainty", "btmesh.model.time_set.uncertainty",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_uncertainty_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_set_time_authority,
            { "Time Authority", "btmesh.model.time_set.time_authority",
            FT_UINT16, BASE_DEC, VALS(btmesh_time_authority_vals), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_time_set_tai_utc_delta,
            { "TAI-UTC Delta", "btmesh.model.time_set.tai_utc_delta",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_tai_utc_delta_s), 0xFFFE,
            NULL, HFILL }
        },
        { &hf_btmesh_time_set_time_zone_offset,
            { "Time Zone Offset", "btmesh.model.time_set.time_zone_offset",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_time_zone_offset_h), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_status_tai_seconds,
            { "TAI Seconds", "btmesh.model.time_status.tai_seconds",
            FT_UINT40, BASE_CUSTOM, CF_FUNC(format_tai_to_utc_date), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_status_subsecond,
            { "Subsecond", "btmesh.model.time_status.subsecond",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_subsecond_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_status_uncertainty,
            { "Uncertainty", "btmesh.model.time_status.uncertainty",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_uncertainty_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_status_time_authority,
            { "Time Authority", "btmesh.model.time_status.time_authority",
            FT_UINT16, BASE_DEC, VALS(btmesh_time_authority_vals), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_time_status_tai_utc_delta,
            { "TAI-UTC Delta", "btmesh.model.time_status.tai_utc_delta",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_tai_utc_delta_s), 0xFFFE,
            NULL, HFILL }
        },
        { &hf_btmesh_time_status_time_zone_offset,
            { "Time Zone Offset", "btmesh.model.time_status.time_zone_offset",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_time_zone_offset_h), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_january,
            { "January", "btmesh.model.schedule_register.month.january",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00000800,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_february,
            { "February", "btmesh.model.schedule_register.month.february",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00001000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_march,
            { "March", "btmesh.model.schedule_register.month.march",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00002000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_april,
            { "April", "btmesh.model.schedule_register.month.april",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00004000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_may,
            { "May", "btmesh.model.schedule_register.month.may",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00008000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_june,
            { "June", "btmesh.model.schedule_register.month.june",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00010000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_july,
            { "July", "btmesh.model.schedule_register.month.july",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00020000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_august,
            { "August", "btmesh.model.schedule_register.month.august",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00040000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_september,
            { "September", "btmesh.model.schedule_register.month.september",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00080000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_october,
            { "October", "btmesh.model.schedule_register.month.october",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00100000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_november,
            { "November", "btmesh.model.schedule_register.month.november",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00200000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_month_december,
            { "December", "btmesh.model.schedule_register.month.december",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00400000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_day_of_week_monday,
            { "Monday", "btmesh.model.schedule_register.day_of_week.monday",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00200000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_day_of_week_tuesday,
            { "Tuesday", "btmesh.model.schedule_register.day_of_week.tuesday",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00400000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_day_of_week_wednesday,
            { "Wednesday", "btmesh.model.schedule_register.day_of_week.wednesday",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x00800000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_day_of_week_thursday,
            { "Thursday", "btmesh.model.schedule_register.day_of_week.thursday",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x01000000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_day_of_week_friday,
            { "Friday", "btmesh.model.schedule_register.day_of_week.friday",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x02000000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_day_of_week_saturday,
            { "Saturday", "btmesh.model.schedule_register.day_of_week.saturday",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x04000000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_schedule_register_day_of_week_sunday,
            { "Sunday", "btmesh.model.schedule_register.day_of_week.sunday",
            FT_UINT32, BASE_NONE, VALS(btmesh_yes_or_dash_vals), 0x08000000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_index,
            { "Index", "btmesh.model.scheduler_action_status.index",
            FT_UINT32, BASE_DEC, NULL, 0x0000000F,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_year,
            { "Year", "btmesh.model.scheduler_action_status.schedule_register.year",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_year), 0x000007F0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_month,
            { "Month", "btmesh.model.scheduler_action_status.schedule_register.month",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_month), 0x007FF800,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_day,
            { "Day", "btmesh.model.scheduler_action_status.schedule_register.day",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_day), 0x0F800000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_hour,
            { "Hour", "btmesh.model.scheduler_action_status.schedule_register.hour",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_hour), 0x000001F0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_minute,
            { "Minute", "btmesh.model.scheduler_action_status.schedule_register.minute",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_minute), 0x00007E00,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_second,
            { "Second", "btmesh.model.scheduler_action_status.schedule_register.second",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_second), 0x001F8000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_day_of_week,
            { "DayOfWeek", "btmesh.model.scheduler_action_status.schedule_register.day_of_week",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_day_of_week), 0x0FE00000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_action,
            { "Action", "btmesh.model.scheduler_action_status.schedule_register.action",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_action), 0xF0000000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_transition_time,
            { "Transition Time", "btmesh.model.scheduler_action_status.schedule_register.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_transition_time_resolution,
            { "Step Resolution", "btmesh.model.scheduler_action_status.schedule_register.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_transition_time_steps,
            { "Number of Steps", "btmesh.model.scheduler_action_status.schedule_register.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_status_schedule_register_scene_number,
            { "Scene Number", "btmesh.model.scheduler_action_status.schedule_register.scene_number",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_index,
            { "Index", "btmesh.model.scheduler_action_set.index",
            FT_UINT32, BASE_DEC, NULL, 0x0000000F,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_year,
            { "Year", "btmesh.model.scheduler_action_set.schedule_register.year",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_year), 0x000007F0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_month,
            { "Month", "btmesh.model.scheduler_action_set.schedule_register.month",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_month), 0x007FF800,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_day,
            { "Day", "btmesh.model.scheduler_action_set.schedule_register.day",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_day), 0x0F800000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_hour,
            { "Hour", "btmesh.model.scheduler_action_set.schedule_register.hour",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_hour), 0x000001F0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_minute,
            { "Minute", "btmesh.model.scheduler_action_set.schedule_register.minute",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_minute), 0x00007E00,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_second,
            { "Second", "btmesh.model.scheduler_action_set.schedule_register.second",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_second), 0x001F8000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_day_of_week,
            { "DayOfWeek", "btmesh.model.scheduler_action_set.schedule_register.day_of_week",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_day_of_week), 0x0FE00000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_action,
            { "Action", "btmesh.model.scheduler_action_set.schedule_register.action",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_action), 0xF0000000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_transition_time,
            { "Transition Time", "btmesh.model.scheduler_action_set.schedule_register.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_transition_time_resolution,
            { "Step Resolution", "btmesh.model.scheduler_action_set.schedule_register.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_transition_time_steps,
            { "Number of Steps", "btmesh.model.scheduler_action_set.schedule_register.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_schedule_register_scene_number,
            { "Scene Number", "btmesh.model.scheduler_action_set.schedule_register.scene_number",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_index,
            { "Index", "btmesh.model.scheduler_action_set_unacknowledged.index",
            FT_UINT32, BASE_DEC, NULL, 0x0000000F,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_year,
            { "Year", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.year",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_year), 0x000007F0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_month,
            { "Month", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.month",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_month), 0x007FF800,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_day,
            { "Day", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.day",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_day), 0x0F800000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_hour,
            { "Hour", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.hour",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_hour), 0x000001F0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_minute,
            { "Minute", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.minute",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_minute), 0x00007E00,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_second,
            { "Second", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.second",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_second), 0x001F8000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_day_of_week,
            { "DayOfWeek", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.day_of_week",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_day_of_week), 0x0FE00000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_action,
            { "Action", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.action",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(format_scheduler_action), 0xF0000000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time,
            { "Transition Time", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time_resolution,
            { "Step Resolution", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_transition_time_steps,
            { "Number of Steps", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_set_unacknowledged_schedule_register_scene_number,
            { "Scene Number", "btmesh.model.scheduler_action_set_unacknowledged.schedule_register.scene_number",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_role_set_time_role,
            { "Time Role", "btmesh.model.time_role_set.time_role",
            FT_UINT8, BASE_DEC, VALS(btmesh_time_role_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_role_status_time_role,
            { "Time Role", "btmesh.model.time_role_status.time_role",
            FT_UINT8, BASE_DEC, VALS(btmesh_time_role_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_zone_set_time_zone_offset_new,
            { "Time Zone Offset New", "btmesh.model.time_zone_set.time_zone_offset_new",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_time_zone_offset_h), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_zone_set_tai_of_zone_change,
            { "TAI of Zone Change", "btmesh.model.time_zone_set.tai_of_zone_change",
            FT_UINT40, BASE_CUSTOM, CF_FUNC(format_tai_to_utc_date), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_zone_status_time_zone_offset_current,
            { "Time Zone Offset Current", "btmesh.model.time_zone_status.time_zone_offset_current",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_time_zone_offset_h), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_zone_status_time_zone_offset_new,
            { "Time Zone Offset New", "btmesh.model.time_zone_status.time_zone_offset_new",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_time_zone_offset_h), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_time_zone_status_tai_of_zone_change,
            { "TAI of Zone Change", "btmesh.model.time_zone_status.tai_of_zone_change",
            FT_UINT40, BASE_CUSTOM, CF_FUNC(format_tai_to_utc_date), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_set_tai_utc_delta_new,
            { "TAI-UTC Delta New", "btmesh.model.tai_utc_delta_set.tai_utc_delta_new",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_tai_utc_delta_s), 0x7FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_set_padding,
            { "Padding", "btmesh.model.tai_utc_delta_set.padding",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_set_tai_of_delta_change,
            { "TAI of Delta Change", "btmesh.model.tai_utc_delta_set.tai_of_delta_change",
            FT_UINT40, BASE_CUSTOM, CF_FUNC(format_tai_to_utc_date), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_status_tai_utc_delta_current,
            { "TAI-UTC Delta Current", "btmesh.model.tai_utc_delta_status.tai_utc_delta_current",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_tai_utc_delta_s), 0x7FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_status_padding_1,
            { "Padding 1", "btmesh.model.tai_utc_delta_status.padding_1",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_status_tai_utc_delta_new,
            { "TAI-UTC Delta New", "btmesh.model.tai_utc_delta_status.tai_utc_delta_new",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_tai_utc_delta_s), 0x7FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_status_padding_2,
            { "Padding 2", "btmesh.model.tai_utc_delta_status.padding_2",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_btmesh_tai_utc_delta_status_tai_of_delta_change,
            { "TAI of Delta Change", "btmesh.model.tai_utc_delta_status.tai_of_delta_change",
            FT_UINT40, BASE_CUSTOM, CF_FUNC(format_tai_to_utc_date), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_action_get_index,
            { "Index", "btmesh.model.scheduler_action_get.index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules,
            { "Schedules", "btmesh.model.scheduler_status.schedules",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_0,
            { "Schedule 0", "btmesh.model.scheduler_status.schedules.schedule_0",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0001,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_1,
            { "Schedule 1", "btmesh.model.scheduler_status.schedules.schedule_1",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0002,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_2,
            { "Schedule 2", "btmesh.model.scheduler_status.schedules.schedule_2",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0004,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_3,
            { "Schedule 3", "btmesh.model.scheduler_status.schedules.schedule_3",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0008,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_4,
            { "Schedule 4", "btmesh.model.scheduler_status.schedules.schedule_4",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0010,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_5,
            { "Schedule 5", "btmesh.model.scheduler_status.schedules.schedule_5",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0020,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_6,
            { "Schedule 6", "btmesh.model.scheduler_status.schedules.schedule_6",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0040,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_7,
            { "Schedule 7", "btmesh.model.scheduler_status.schedules.schedule_7",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0080,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_8,
            { "Schedule 8", "btmesh.model.scheduler_status.schedules.schedule_8",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0100,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_9,
            { "Schedule 9", "btmesh.model.scheduler_status.schedules.schedule_9",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0200,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_10,
            { "Schedule 10", "btmesh.model.scheduler_status.schedules.schedule_10",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0400,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_11,
            { "Schedule 11", "btmesh.model.scheduler_status.schedules.schedule_11",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x0800,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_12,
            { "Schedule 12", "btmesh.model.scheduler_status.schedules.schedule_12",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x1000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_13,
            { "Schedule 13", "btmesh.model.scheduler_status.schedules.schedule_13",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x2000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_14,
            { "Schedule 14", "btmesh.model.scheduler_status.schedules.schedule_14",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x4000,
            NULL, HFILL }
        },
        { &hf_btmesh_scheduler_status_schedules_schedule_15,
            { "Schedule 15", "btmesh.model.scheduler_status.schedules.schedule_15",
            FT_UINT16, BASE_NONE, VALS(btmesh_defined_or_dash_vals), 0x8000,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_property_set_light_lc_property_id,
            { "Light LC Property ID", "btmesh.model.light_lc_property_set.light_lc_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_property_set_light_lc_property_value,
            { "Light LC Property Value", "btmesh.model.light_lc_property_set.light_lc_property_value",
           FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_property_set_unacknowledged_light_lc_property_id,
            { "Light LC Property ID", "btmesh.model.light_lc_property_set_unacknowledged.light_lc_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_property_set_unacknowledged_light_lc_property_value,
            { "Light LC Property Value", "btmesh.model.light_lc_property_set_unacknowledged.light_lc_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_property_status_light_lc_property_id,
            { "Light LC Property ID", "btmesh.model.light_lc_property_status.light_lc_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_property_status_light_lc_property_value,
            { "Light LC Property Value", "btmesh.model.light_lc_property_status.light_lc_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_lightness,
            { "Lightness", "btmesh.model.light_lightness_set.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_tid,
            { "TID", "btmesh.model.light_lightness_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_transition_time,
            { "Transition Time", "btmesh.model.light_lightness_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_lightness_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_lightness_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_delay,
            { "Delay", "btmesh.model.light_lightness_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_unacknowledged_lightness,
            { "Lightness", "btmesh.model.light_lightness_set_unacknowledged.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_lightness_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_lightness_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_lightness_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_lightness_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_lightness_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_status_present_lightness,
            { "Present Lightness", "btmesh.model.light_lightness_status.present_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_status_target_lightness,
            { "Target Lightness", "btmesh.model.light_lightness_status.target_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_lightness_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_lightness_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_lightness_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_lightness,
            { "Lightness", "btmesh.model.light_lightness_linear_set.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_tid,
            { "TID", "btmesh.model.light_lightness_linear_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_transition_time,
            { "Transition Time", "btmesh.model.light_lightness_linear_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_lightness_linear_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_lightness_linear_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_delay,
            { "Delay", "btmesh.model.light_lightness_linear_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_unacknowledged_lightness,
            { "Lightness", "btmesh.model.light_lightness_linear_set_unacknowledged.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_lightness_linear_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_lightness_linear_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_lightness_linear_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_lightness_linear_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_lightness_linear_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_status_present_lightness,
            { "Present Lightness", "btmesh.model.light_lightness_linear_status.present_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_status_target_lightness,
            { "Target Lightness", "btmesh.model.light_lightness_linear_status.target_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_lightness_linear_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_lightness_linear_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_linear_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_lightness_linear_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_last_status_lightness,
            { "Lightness", "btmesh.model.light_lightness_last_status.lightness",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_prohibited), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_default_status_lightness,
            { "Lightness", "btmesh.model.light_lightness_default_status.lightness",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_default), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_range_status_status_code,
            { "Status Code", "btmesh.model.light_lightness_range_status.status_code",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_range_status_range_min,
            { "Range Min", "btmesh.model.light_lightness_range_status.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_prohibited), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_range_status_range_max,
            { "Range Max", "btmesh.model.light_lightness_range_status.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_prohibited), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_default_set_lightness,
            { "Lightness", "btmesh.model.light_lightness_default_set.lightness",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_default), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_default_set_unacknowledged_lightness,
            { "Lightness", "btmesh.model.light_lightness_default_set_unacknowledged.lightness",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_default), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_range_set_range_min,
            { "Range Min", "btmesh.model.light_lightness_range_set.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_prohibited), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_range_set_range_max,
            { "Range Max", "btmesh.model.light_lightness_range_set.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_prohibited), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_range_set_unacknowledged_range_min,
            { "Range Min", "btmesh.model.light_lightness_range_set_unacknowledged.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_prohibited), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lightness_range_set_unacknowledged_range_max,
            { "Range Max", "btmesh.model.light_lightness_range_set_unacknowledged.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_light_lightness_prohibited), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_ctl_lightness,
            { "CTL Lightness", "btmesh.model.light_ctl_set.ctl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_ctl_temperature,
            { "CTL Temperature", "btmesh.model.light_ctl_set.ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_ctl_delta_uv,
            { "CTL Delta UV", "btmesh.model.light_ctl_set.ctl_delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_tid,
            { "TID", "btmesh.model.light_ctl_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_transition_time,
            { "Transition Time", "btmesh.model.light_ctl_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_ctl_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_ctl_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_delay,
            { "Delay", "btmesh.model.light_ctl_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_ctl_lightness,
            { "CTL Lightness", "btmesh.model.light_ctl_set_unacknowledged.ctl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_ctl_temperature,
            { "CTL Temperature", "btmesh.model.light_ctl_set_unacknowledged.ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_ctl_delta_uv,
            { "CTL Delta UV", "btmesh.model.light_ctl_set_unacknowledged.ctl_delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_ctl_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_ctl_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_ctl_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_ctl_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_ctl_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_status_present_ctl_lightness,
            { "Present CTL Lightness", "btmesh.model.light_ctl_status.present_ctl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_status_present_ctl_temperature,
            { "Present CTL Temperature", "btmesh.model.light_ctl_status.present_ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_status_target_ctl_lightness,
            { "Target CTL Lightness", "btmesh.model.light_ctl_status.target_ctl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_status_target_ctl_temperature,
            { "Target CTL Temperature", "btmesh.model.light_ctl_status.target_ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_ctl_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_ctl_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_ctl_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_range_status_status_code,
            { "Status Code", "btmesh.model.light_ctl_temperature_range_status.status_code",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_range_status_range_min,
            { "Range Min", "btmesh.model.light_ctl_temperature_range_status.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin_unknown), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_range_status_range_max,
            { "Range Max", "btmesh.model.light_ctl_temperature_range_status.range_max",
            FT_UINT16,BASE_CUSTOM, CF_FUNC(format_temperature_kelvin_unknown), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_ctl_temperature,
            { "CTL Temperature", "btmesh.model.light_ctl_temperature_set.ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_ctl_delta_uv,
            { "CTL Delta UV", "btmesh.model.light_ctl_temperature_set.ctl_delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_tid,
            { "TID", "btmesh.model.light_ctl_temperature_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_transition_time,
            { "Transition Time", "btmesh.model.light_ctl_temperature_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_ctl_temperature_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_ctl_temperature_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_delay,
            { "Delay", "btmesh.model.light_ctl_temperature_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_unacknowledged_ctl_temperature,
            { "CTL Temperature", "btmesh.model.light_ctl_temperature_set_unacknowledged.ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_unacknowledged_ctl_delta_uv,
            { "CTL Delta UV", "btmesh.model.light_ctl_temperature_set_unacknowledged.ctl_delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_ctl_temperature_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_ctl_temperature_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_ctl_temperature_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_ctl_temperature_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_ctl_temperature_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_status_present_ctl_temperature,
            { "Present CTL Temperature", "btmesh.model.light_ctl_temperature_status.present_ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_status_present_ctl_delta_uv,
            { "Present CTL Delta UV", "btmesh.model.light_ctl_temperature_status.present_ctl_delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_status_target_ctl_temperature,
            { "Target CTL Temperature", "btmesh.model.light_ctl_temperature_status.target_ctl_temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_status_target_ctl_delta_uv,
            { "Target CTL Delta UV", "btmesh.model.light_ctl_temperature_status.target_ctl_delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_ctl_temperature_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_ctl_temperature_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_ctl_temperature_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_status_lightness,
            { "Lightness", "btmesh.model.light_ctl_default_status.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_status_temperature,
            { "Temperature", "btmesh.model.light_ctl_default_status.temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_status_delta_uv,
            { "Delta UV", "btmesh.model.light_ctl_default_status.delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_set_lightness,
            { "Lightness", "btmesh.model.light_ctl_default_set.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_set_temperature,
            { "Temperature", "btmesh.model.light_ctl_default_set.temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_set_delta_uv,
            { "Delta UV", "btmesh.model.light_ctl_default_set.delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_set_unacknowledged_lightness,
            { "Lightness", "btmesh.model.light_ctl_default_set_unacknowledged.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_set_unacknowledged_temperature,
            { "Temperature", "btmesh.model.light_ctl_default_set_unacknowledged.temperature",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_default_set_unacknowledged_delta_uv,
            { "Delta UV", "btmesh.model.light_ctl_default_set_unacknowledged.delta_uv",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_range_set_range_min,
            { "Range Min", "btmesh.model.light_ctl_temperature_range_set.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin_unknown), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_range_set_range_max,
            { "Range Max", "btmesh.model.light_ctl_temperature_range_set.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin_unknown), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_range_set_unacknowledged_range_min,
            { "Range Min", "btmesh.model.light_ctl_temperature_range_set_unacknowledged.range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin_unknown), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_ctl_temperature_range_set_unacknowledged_range_max,
            { "Range Max", "btmesh.model.light_ctl_temperature_range_set_unacknowledged.range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_temperature_kelvin_unknown), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_hue,
            { "Hue", "btmesh.model.light_hsl_hue_set.hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_tid,
            { "TID", "btmesh.model.light_hsl_hue_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_transition_time,
            { "Transition Time", "btmesh.model.light_hsl_hue_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_hue_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_hue_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_delay,
            { "Delay", "btmesh.model.light_hsl_hue_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_unacknowledged_hue,
            { "Hue", "btmesh.model.light_hsl_hue_set_unacknowledged.hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_hsl_hue_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_hsl_hue_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_hue_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_hue_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_hsl_hue_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_status_present_hue,
            { "Present Hue", "btmesh.model.light_hsl_hue_status.present_hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_status_target_hue,
            { "Target Hue", "btmesh.model.light_hsl_hue_status.target_hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_hsl_hue_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_hue_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_hue_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_hue_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_saturation,
            { "Saturation", "btmesh.model.light_hsl_saturation_set.saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_tid,
            { "TID", "btmesh.model.light_hsl_saturation_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_transition_time,
            { "Transition Time", "btmesh.model.light_hsl_saturation_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_saturation_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_saturation_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_delay,
            { "Delay", "btmesh.model.light_hsl_saturation_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_unacknowledged_saturation,
            { "Saturation", "btmesh.model.light_hsl_saturation_set_unacknowledged.saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_hsl_saturation_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_hsl_saturation_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_saturation_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_saturation_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_hsl_saturation_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_status_present_saturation,
            { "Present Saturation", "btmesh.model.light_hsl_saturation_status.present_saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_status_target_saturation,
            { "Target Saturation", "btmesh.model.light_hsl_saturation_status.target_saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_hsl_saturation_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_saturation_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_saturation_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_saturation_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_hsl_lightness,
            { "HSL Lightness", "btmesh.model.light_hsl_set.hsl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_hsl_hue,
            { "HSL Hue", "btmesh.model.light_hsl_set.hsl_hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_hsl_saturation,
            { "HSL Saturation", "btmesh.model.light_hsl_set.hsl_saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_tid,
            { "TID", "btmesh.model.light_hsl_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_transition_time,
            { "Transition Time", "btmesh.model.light_hsl_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_delay,
            { "Delay", "btmesh.model.light_hsl_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_hsl_lightness,
            { "HSL Lightness", "btmesh.model.light_hsl_set_unacknowledged.hsl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_hsl_hue,
            { "HSL Hue", "btmesh.model.light_hsl_set_unacknowledged.hsl_hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_hsl_saturation,
            { "HSL Saturation", "btmesh.model.light_hsl_set_unacknowledged.hsl_saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_hsl_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_hsl_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_hsl_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_status_hsl_lightness,
            { "HSL Lightness", "btmesh.model.light_hsl_status.hsl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_status_hsl_hue,
            { "HSL Hue", "btmesh.model.light_hsl_status.hsl_hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_status_hsl_saturation,
            { "HSL Saturation", "btmesh.model.light_hsl_status.hsl_saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_hsl_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_target_status_hsl_lightness_target,
            { "HSL Lightness Target", "btmesh.model.light_hsl_target_status.hsl_lightness_target",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_target_status_hsl_hue_target,
            { "HSL Hue Target", "btmesh.model.light_hsl_target_status.hsl_hue_target",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_target_status_hsl_saturation_target,
            { "HSL Saturation Target", "btmesh.model.light_hsl_target_status.hsl_saturation_target",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_target_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_hsl_target_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_target_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_hsl_target_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_target_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_hsl_target_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_status_lightness,
            { "Lightness", "btmesh.model.light_hsl_default_status.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_status_hue,
            { "Hue", "btmesh.model.light_hsl_default_status.hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_status_saturation,
            { "Saturation", "btmesh.model.light_hsl_default_status.saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_status_status_code,
            { "Status Code", "btmesh.model.light_hsl_range_status.status_code",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_status_hue_range_min,
            { "Hue Range Min", "btmesh.model.light_hsl_range_status.hue_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_status_hue_range_max,
            { "Hue Range Max", "btmesh.model.light_hsl_range_status.hue_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_status_saturation_range_min,
            { "Saturation Range Min", "btmesh.model.light_hsl_range_status.saturation_range_min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_status_saturation_range_max,
            { "Saturation Range Max", "btmesh.model.light_hsl_range_status.saturation_range_max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_set_lightness,
            { "Lightness", "btmesh.model.light_hsl_default_set.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_set_hue,
            { "Hue", "btmesh.model.light_hsl_default_set.hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_set_saturation,
            { "Saturation", "btmesh.model.light_hsl_default_set.saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_set_unacknowledged_lightness,
            { "Lightness", "btmesh.model.light_hsl_default_set_unacknowledged.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_set_unacknowledged_hue,
            { "Hue", "btmesh.model.light_hsl_default_set_unacknowledged.hue",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_default_set_unacknowledged_saturation,
            { "Saturation", "btmesh.model.light_hsl_default_set_unacknowledged.saturation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_hue_range_min,
            { "Hue Range Min", "btmesh.model.light_hsl_range_set.hue_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_hue_range_max,
            { "Hue Range Max", "btmesh.model.light_hsl_range_set.hue_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_saturation_range_min,
            { "Saturation Range Min", "btmesh.model.light_hsl_range_set.saturation_range_min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_saturation_range_max,
            { "Saturation Range Max", "btmesh.model.light_hsl_range_set.saturation_range_max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_unacknowledged_hue_range_min,
            { "Hue Range Min", "btmesh.model.light_hsl_range_set_unacknowledged.hue_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_unacknowledged_hue_range_max,
            { "Hue Range Max", "btmesh.model.light_hsl_range_set_unacknowledged.hue_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_hsl_hue), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_unacknowledged_saturation_range_min,
            { "Saturation Range Min", "btmesh.model.light_hsl_range_set_unacknowledged.saturation_range_min",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_hsl_range_set_unacknowledged_saturation_range_max,
            { "Saturation Range Max", "btmesh.model.light_hsl_range_set_unacknowledged.saturation_range_max",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_xyl_lightness,
            { "xyL Lightness", "btmesh.model.light_xyl_set.xyl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_xyl_x,
            { "xyL x", "btmesh.model.light_xyl_set.xyl_x",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_xyl_y,
            { "xyL y", "btmesh.model.light_xyl_set.xyl_y",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_tid,
            { "TID", "btmesh.model.light_xyl_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_transition_time,
            { "Transition Time", "btmesh.model.light_xyl_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_xyl_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_xyl_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_delay,
            { "Delay", "btmesh.model.light_xyl_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_xyl_lightness,
            { "xyL Lightness", "btmesh.model.light_xyl_set_unacknowledged.xyl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_xyl_x,
            { "xyL x", "btmesh.model.light_xyl_set_unacknowledged.xyl_x",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_xyl_y,
            { "xyL y", "btmesh.model.light_xyl_set_unacknowledged.xyl_y",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_xyl_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_xyl_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_xyl_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_xyl_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_xyl_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_status_xyl_lightness,
            { "xyL Lightness", "btmesh.model.light_xyl_status.xyl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_status_xyl_x,
            { "xyL x", "btmesh.model.light_xyl_status.xyl_x",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_status_xyl_y,
            { "xyL y", "btmesh.model.light_xyl_status.xyl_y",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_xyl_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_xyl_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_xyl_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_target_status_target_xyl_lightness,
            { "Target xyL Lightness", "btmesh.model.light_xyl_target_status.target_xyl_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_target_status_target_xyl_x,
            { "Target xyL x", "btmesh.model.light_xyl_target_status.target_xyl_x",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_target_status_target_xyl_y,
            { "Target xyL y", "btmesh.model.light_xyl_target_status.target_xyl_y",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_target_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_xyl_target_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_target_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_xyl_target_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_target_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_xyl_target_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_status_lightness,
            { "Lightness", "btmesh.model.light_xyl_default_status.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_status_xyl_x,
            { "xyL x", "btmesh.model.light_xyl_default_status.xyl_x",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_status_xyl_y,
            { "xyL y", "btmesh.model.light_xyl_default_status.xyl_y",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_status_status_code,
            { "Status Code", "btmesh.model.light_xyl_range_status.status_code",
            FT_UINT8, BASE_DEC, VALS(btmesh_generic_status_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_status_xyl_x_range_min,
            { "xyL x Range Min", "btmesh.model.light_xyl_range_status.xyl_x_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_status_xyl_x_range_max,
            { "xyL x Range Max", "btmesh.model.light_xyl_range_status.xyl_x_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_status_xyl_y_range_min,
            { "xyL y Range Min", "btmesh.model.light_xyl_range_status.xyl_y_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_status_xyl_y_range_max,
            { "xyL y Range Max", "btmesh.model.light_xyl_range_status.xyl_y_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_set_lightness,
            { "Lightness", "btmesh.model.light_xyl_default_set.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_set_xyl_x,
            { "xyL x", "btmesh.model.light_xyl_default_set.xyl_x",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_set_xyl_y,
            { "xyL y", "btmesh.model.light_xyl_default_set.xyl_y",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_set_unacknowledged_lightness,
            { "Lightness", "btmesh.model.light_xyl_default_set_unacknowledged.lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_set_unacknowledged_xyl_x,
            { "xyL x", "btmesh.model.light_xyl_default_set_unacknowledged.xyl_x",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_default_set_unacknowledged_xyl_y,
            { "xyL y", "btmesh.model.light_xyl_default_set_unacknowledged.xyl_y",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_xyl_x_range_min,
            { "xyL x Range Min", "btmesh.model.light_xyl_range_set.xyl_x_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_xyl_x_range_max,
            { "xyL x Range Max", "btmesh.model.light_xyl_range_set.xyl_x_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_xyl_y_range_min,
            { "xyL y Range Min", "btmesh.model.light_xyl_range_set.xyl_y_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_xyl_y_range_max,
            { "xyL y Range Max", "btmesh.model.light_xyl_range_set.xyl_y_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_unacknowledged_xyl_x_range_min,
            { "xyL x Range Min", "btmesh.model.light_xyl_range_set_unacknowledged.xyl_x_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_unacknowledged_xyl_x_range_max,
            { "xyL x Range Max", "btmesh.model.light_xyl_range_set_unacknowledged.xyl_x_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_unacknowledged_xyl_y_range_min,
            { "xyL y Range Min", "btmesh.model.light_xyl_range_set_unacknowledged.xyl_y_range_min",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_xyl_range_set_unacknowledged_xyl_y_range_max,
            { "xyL y Range Max", "btmesh.model.light_xyl_range_set_unacknowledged.xyl_y_range_max",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_xyl_coordinate), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_mode_set_mode,
            { "Mode", "btmesh.model.light_lc_mode_set.mode",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_mode_set_unacknowledged_mode,
            { "Mode", "btmesh.model.light_lc_mode_set_unacknowledged.mode",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_mode_status_mode,
            { "Mode", "btmesh.model.light_lc_mode_status.mode",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_om_set_mode,
            { "Mode", "btmesh.model.light_lc_om_set.mode",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_om_set_unacknowledged_mode,
            { "Mode", "btmesh.model.light_lc_om_set_unacknowledged.mode",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_om_status_mode,
            { "Mode", "btmesh.model.light_lc_om_status.mode",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_light_onoff,
            { "Light OnOff", "btmesh.model.light_lc_light_onoff_set.light_onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_tid,
            { "TID", "btmesh.model.light_lc_light_onoff_set.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_transition_time,
            { "Transition Time", "btmesh.model.light_lc_light_onoff_set.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_lc_light_onoff_set.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_lc_light_onoff_set.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_delay,
            { "Delay", "btmesh.model.light_lc_light_onoff_set.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_unacknowledged_light_onoff,
            { "Light OnOff", "btmesh.model.light_lc_light_onoff_set_unacknowledged.light_onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_unacknowledged_tid,
            { "TID", "btmesh.model.light_lc_light_onoff_set_unacknowledged.tid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time,
            { "Transition Time", "btmesh.model.light_lc_light_onoff_set_unacknowledged.transition_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time_resolution,
            { "Step Resolution", "btmesh.model.light_lc_light_onoff_set_unacknowledged.transition_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_unacknowledged_transition_time_steps,
            { "Number of Steps", "btmesh.model.light_lc_light_onoff_set_unacknowledged.transition_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_set_unacknowledged_delay,
            { "Delay", "btmesh.model.light_lc_light_onoff_set_unacknowledged.delay",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_delay_ms), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_status_present_light_onoff,
            { "Present Light OnOff", "btmesh.model.light_lc_light_onoff_status.present_light_onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_status_target_light_onoff,
            { "Target Light OnOff", "btmesh.model.light_lc_light_onoff_status.target_light_onoff",
            FT_UINT8, BASE_DEC, VALS(btmesh_on_off_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_status_remaining_time,
            { "Remaining Time", "btmesh.model.light_lc_light_onoff_status.remaining_time",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_publish_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_status_remaining_time_resolution,
            { "Step Resolution", "btmesh.model.light_lc_light_onoff_status.remaining_time.resolution",
            FT_UINT8, BASE_DEC, VALS(btmesh_publishperiod_resolution_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_light_onoff_status_remaining_time_steps,
            { "Number of Steps", "btmesh.model.light_lc_light_onoff_status.remaining_time.steps",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_btmesh_light_lc_property_get_light_lc_property_id,
            { "Light LC Property ID", "btmesh.model.light_lc_property_get.light_lc_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_properties_status_manufacturer_property_id,
            { "Manufacturer Property ID", "btmesh.model.generic_manufacturer_properties_status.manufacturer_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_set_manufacturer_property_id,
            { "Manufacturer Property ID", "btmesh.model.generic_manufacturer_property_set.manufacturer_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_set_manufacturer_user_access,
            { "Manufacturer User Access", "btmesh.model.generic_manufacturer_property_set.manufacturer_user_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_manufacturer_user_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_set_unacknowledged_manufacturer_property_id,
            { "Manufacturer Property ID", "btmesh.model.generic_manufacturer_property_set_unacknowledged.manufacturer_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_set_unacknowledged_manufacturer_user_access,
            { "Manufacturer User Access", "btmesh.model.generic_manufacturer_property_set_unacknowledged.manufacturer_user_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_manufacturer_user_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_status_manufacturer_property_id,
            { "Manufacturer Property ID", "btmesh.model.generic_manufacturer_property_status.manufacturer_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_status_manufacturer_user_access,
            { "Manufacturer User Access", "btmesh.model.generic_manufacturer_property_status.manufacturer_user_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_manufacturer_user_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_status_manufacturer_property_value,
            { "Manufacturer Property Value", "btmesh.model.generic_manufacturer_property_status.manufacturer_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_properties_status_admin_property_id,
            { "Admin Property ID", "btmesh.model.generic_admin_properties_status.admin_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_set_admin_property_id,
            { "Admin Property ID", "btmesh.model.generic_admin_property_set.admin_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_set_admin_user_access,
            { "Admin User Access", "btmesh.model.generic_admin_property_set.admin_user_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_admin_user_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_set_admin_property_value,
            { "Admin Property Value", "btmesh.model.generic_admin_property_set.admin_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_set_unacknowledged_admin_property_id,
            { "Admin Property ID", "btmesh.model.generic_admin_property_set_unacknowledged.admin_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_set_unacknowledged_admin_user_access,
            { "Admin User Access", "btmesh.model.generic_admin_property_set_unacknowledged.admin_user_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_admin_user_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_set_unacknowledged_admin_property_value,
            { "Admin Property Value", "btmesh.model.generic_admin_property_set_unacknowledged.admin_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_status_admin_property_id,
            { "Admin Property ID", "btmesh.model.generic_admin_property_status.admin_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_status_admin_user_access,
            { "Admin User Access", "btmesh.model.generic_admin_property_status.admin_user_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_admin_user_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_status_admin_property_value,
            { "Admin Property Value", "btmesh.model.generic_admin_property_status.admin_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_properties_status_user_property_id,
            { "User Property ID", "btmesh.model.generic_user_properties_status.user_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_set_user_property_id,
            { "User Property ID", "btmesh.model.generic_user_property_set.user_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_set_user_property_value,
            { "User Property Value", "btmesh.model.generic_user_property_set.user_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_set_unacknowledged_user_property_id,
            { "User Property ID", "btmesh.model.generic_user_property_set_unacknowledged.user_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_set_unacknowledged_user_property_value,
            { "User Property Value", "btmesh.model.generic_user_property_set_unacknowledged.user_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_status_user_property_id,
            { "User Property ID", "btmesh.model.generic_user_property_status.user_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_status_user_access,
            { "User Access", "btmesh.model.generic_user_property_status.user_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_user_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_status_user_property_value,
            { "User Property Value", "btmesh.model.generic_user_property_status.user_property_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_client_properties_get_client_property_id,
            { "Client Property ID", "btmesh.model.generic_client_properties_get.client_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_client_properties_status_client_property_id,
            { "Client Property ID", "btmesh.model.generic_client_properties_status.client_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_descriptor_status_descriptor_sensor_property_id,
            { "Sensor Property ID", "btmesh.model.sensor_descriptor_status.descriptor_sensor_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_descriptor_status_descriptor_sensor_positive_tolerance,
            { "Sensor Positive Tolerance", "btmesh.model.sensor_descriptor_status.descriptor_positive_tolerance",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_sensor_descriptor_tolerance), 0x000FFF,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_descriptor_status_descriptor_sensor_negative_tolerance,
            { "Sensor Negative Tolerance", "btmesh.model.sensor_descriptor_status.descriptor_negative_tolerance",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_sensor_descriptor_tolerance), 0xFFF000,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_descriptor_status_descriptor_sensor_sampling_function,
            { "Sensor Sampling Function", "btmesh.model.sensor_descriptor_status.descriptor_sensor_sampling_function",
            FT_UINT8, BASE_DEC, VALS(btmesh_sensor_sampling_function_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_descriptor_status_descriptor_sensor_measurement_period,
            { "Sensor Measurement Period", "btmesh.model.sensor_descriptor_status.descriptor_sensor_measurement_period",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_sensor_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_descriptor_status_descriptor_sensor_update_interval,
            { "Sensor Update Interval", "btmesh.model.sensor_descriptor_status.descriptor_sensor_update_interval",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_sensor_period), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_status_mpid_format,
            { "MPID Format", "btmesh.model.sensor_status.mpid.format",
            FT_UINT8, BASE_DEC, VALS(btmesh_mpid_format_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_status_mpid_format_a_length,
            { "MPID Length", "btmesh.model.sensor_status.mpid.format_a.length",
            FT_UINT8, BASE_DEC, NULL, 0x1e,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_status_mpid_format_b_length,
            { "MPID Length", "btmesh.model.sensor_status.mpid.format_b.length",
            FT_UINT8, BASE_DEC, NULL, 0xfe,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_status_mpid_format_a_property_id,
            { "MPID Property ID", "btmesh.model.sensor_status.mpid.format_a.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0xFFE0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_status_mpid_format_b_property_id,
            { "MPID Property ID", "btmesh.model.sensor_status.mpid.format_b.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_status_raw_value,
            { "Raw Value", "btmesh.model.sensor_status.raw_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_column_status_property_id,
            { "Property ID", "btmesh.model.sensor_column_status.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_column_status_raw_value_a,
            { "Raw Value A", "btmesh.model.sensor_column_status.raw_value_a",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_column_status_raw_value_b,
            { "Raw Value B", "btmesh.model.sensor_column_status.raw_value_b",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_column_status_raw_value_c,
            { "Raw Value C", "btmesh.model.sensor_column_status.raw_value_c",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_series_status_property_id,
            { "Property ID", "btmesh.model.sensor_series_status.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_series_status_raw_value_a,
            { "Raw Value A", "btmesh.model.sensor_series_status.raw_value_a",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_series_status_raw_value_b,
            { "Raw Value B", "btmesh.model.sensor_series_status.raw_value_b",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_series_status_raw_value_c,
            { "Raw Value C", "btmesh.model.sensor_series_status.raw_value_c",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_property_id,
            { "Property ID", "btmesh.model.sensor_cadence_set.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_fast_cadence_period_divisor,
            { "Fast Cadence Period Divisor", "btmesh.model.sensor_cadence_set.fast_cadence_period_divisor",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_fast_cadence_period_divisor), 0x7F,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_status_trigger_type,
            { "Status Trigger Type", "btmesh.model.sensor_cadence_set.status_trigger_type",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_trigger_type_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_status_trigger_delta_down,
            { "Status Trigger Delta Down", "btmesh.model.sensor_cadence_set.status_trigger_delta_down",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_status_trigger_delta_up,
            { "Status Trigger Delta Up", "btmesh.model.sensor_cadence_set.status_trigger_delta_up",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_status_min_interval,
            { "Status Min Interval", "btmesh.model.sensor_cadence_set.status_min_interval",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_status_min_interval), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_fast_cadence_low,
            { "Fast Cadence Low", "btmesh.model.sensor_cadence_set.fast_cadence_low",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_fast_cadence_high,
            { "Fast Cadence High", "btmesh.model.sensor_cadence_set.fast_cadence_high",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_remainder_not_dissected,
            { "Remainder Not Dissected", "btmesh.model.sensor_cadence_set.remainder_not_dissected",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_property_id,
            { "Property ID", "btmesh.model.sensor_cadence_set_unacknowledged.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_period_divisor,
            { "Fast Cadence Period Divisor", "btmesh.model.sensor_cadence_set_unacknowledged.fast_cadence_period_divisor",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_fast_cadence_period_divisor), 0x7F,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_type,
            { "Status Trigger Type", "btmesh.model.sensor_cadence_set_unacknowledged.status_trigger_type",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_trigger_type_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_delta_down,
            { "Status Trigger Delta Down", "btmesh.model.sensor_cadence_set_unacknowledged.status_trigger_delta_down",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_status_trigger_delta_up,
            { "Status Trigger Delta Up", "btmesh.model.sensor_cadence_set_unacknowledged.status_trigger_delta_up",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_status_min_interval,
            { "Status Min Interval", "btmesh.model.sensor_cadence_set_unacknowledged.status_min_interval",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_status_min_interval), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_low,
            { "Fast Cadence Low", "btmesh.model.sensor_cadence_set_unacknowledged.fast_cadence_low",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_fast_cadence_high,
            { "Fast Cadence High", "btmesh.model.sensor_cadence_set_unacknowledged.fast_cadence_high",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_set_unacknowledged_remainder_not_dissected,
            { "Remainder Not Dissected", "btmesh.model.sensor_cadence_set_unacknowledged.remainder_not_dissected",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_property_id,
            { "Property ID", "btmesh.model.sensor_cadence_status.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_fast_cadence_period_divisor,
            { "Fast Cadence Period Divisor", "btmesh.model.sensor_cadence_status.fast_cadence_period_divisor",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_fast_cadence_period_divisor), 0x7F,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_status_trigger_type,
            { "Status Trigger Type", "btmesh.model.sensor_cadence_status.status_trigger_type",
            FT_UINT8, BASE_DEC, VALS(btmesh_status_trigger_type_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_status_trigger_delta_down,
            { "Status Trigger Delta Down", "btmesh.model.sensor_cadence_status.status_trigger_delta_down",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_status_trigger_delta_up,
            { "Status Trigger Delta Up", "btmesh.model.sensor_cadence_status.status_trigger_delta_up",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_status_min_interval,
            { "Status Min Interval", "btmesh.model.sensor_cadence_status.status_min_interval",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_status_min_interval), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_fast_cadence_low,
            { "Fast Cadence Low", "btmesh.model.sensor_cadence_status.fast_cadence_low",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_fast_cadence_high,
            { "Fast Cadence High", "btmesh.model.sensor_cadence_status.fast_cadence_high",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_status_remainder_not_dissected,
            { "Remainder Not Dissected", "btmesh.model.sensor_cadence_status.remainder_not_dissected",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_settings_status_sensor_property_id,
            { "Sensor Property ID", "btmesh.model.sensor_settings_status.sensor_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_settings_status_sensor_setting_property_id,
            { "Sensor Setting Property ID", "btmesh.model.sensor_settings_status.sensor_setting_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_set_sensor_property_id,
            { "Sensor Property ID", "btmesh.model.sensor_setting_set.sensor_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_set_sensor_setting_property_id,
            { "Sensor Setting Property ID", "btmesh.model.sensor_setting_set.sensor_setting_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_set_sensor_setting_raw,
            { "Sensor Setting Raw", "btmesh.model.sensor_setting_set.sensor_setting_raw",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_set_unacknowledged_sensor_property_id,
            { "Sensor Property ID", "btmesh.model.sensor_setting_set_unacknowledged.sensor_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_set_unacknowledged_sensor_setting_property_id,
            { "Sensor Setting Property ID", "btmesh.model.sensor_setting_set_unacknowledged.sensor_setting_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_set_unacknowledged_sensor_setting_raw,
            { "Sensor Setting Raw", "btmesh.model.sensor_setting_set_unacknowledged.sensor_setting_raw",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_status_sensor_property_id,
            { "Sensor Property ID", "btmesh.model.sensor_setting_status.sensor_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_status_sensor_setting_property_id,
            { "Sensor Setting Property ID", "btmesh.model.sensor_setting_status.sensor_setting_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_status_sensor_setting_access,
            { "Sensor Setting Access", "btmesh.model.sensor_setting_status.sensor_setting_access",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_sensor_setting_access), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_status_sensor_setting_raw,
            { "Sensor Setting Raw", "btmesh.model.sensor_setting_status.sensor_setting_raw",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_manufacturer_property_get_manufacturer_property_id,
            { "Manufacturer Property ID", "btmesh.model.generic_manufacturer_property_get.manufacturer_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_admin_property_get_admin_property_id,
            { "Admin Property ID", "btmesh.model.generic_admin_property_get.admin_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_generic_user_property_get_user_property_id,
            { "User Property ID", "btmesh.model.generic_user_property_get.user_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_descriptor_get_property_id,
            { "Property ID", "btmesh.model.sensor_descriptor_get.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_get_property_id,
            { "Property ID", "btmesh.model.sensor_get.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_column_get_property_id,
            { "Property ID", "btmesh.model.sensor_column_get.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_column_get_raw_value_a,
            { "Raw Value A", "btmesh.model.sensor_column_get.raw_value_a",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_series_get_property_id,
            { "Property ID", "btmesh.model.sensor_series_get.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_series_get_raw_value_a1,
            { "Raw Value A1", "btmesh.model.sensor_series_get.raw_value_a1",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_series_get_raw_value_a2,
            { "Raw Value A2", "btmesh.model.sensor_series_get.raw_value_a2",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_cadence_get_property_id,
            { "Property ID", "btmesh.model.sensor_cadence_get.property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_settings_get_sensor_property_id,
            { "Sensor Property ID", "btmesh.model.sensor_settings_get.sensor_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_get_sensor_property_id,
            { "Sensor Property ID", "btmesh.model.sensor_setting_get.sensor_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_sensor_setting_get_sensor_setting_property_id,
            { "Sensor Setting Property ID", "btmesh.model.sensor_setting_get.sensor_setting_property_id",
            FT_UINT16, BASE_DEC, VALS(btmesh_properties_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_illuminance,
            { "Illuminance", "btmesh.property.illuminance",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_illuminance), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_perceived_lightness,
            { "Perceived Lightness", "btmesh.property.perceived_lightness",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_percentage_8,
            { "Percentage 8", "btmesh.property.percentage_8",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_percentage_8), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_coefficient,
            { "Coefficient", "btmesh.property.coefficient",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_time_millisecond_24,
            { "Time Millisecond 24", "btmesh.property.time_millisecond_24",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_time_millisecond_24), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_count_16,
            { "Count 16", "btmesh.property.count_16",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_count_16), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_phony_characteristic_percentage_change_16,
            { "Percentage Change", "btmesh.property.percentage_change_16",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_percentage_change_16), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_phony_characteristic_index,
            { "Index", "btmesh.property.index",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_time_decihour_8,
            { "Time Decihour 8", "btmesh.property.time_decihour_8",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_decihour_8), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_temperature_8,
            { "Temperature 8", "btmesh.property.temperature_8",
            FT_INT8, BASE_CUSTOM, CF_FUNC(format_temperature_8), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_temperature,
            { "Temperature", "btmesh.property.temperature",
            FT_INT16, BASE_CUSTOM, CF_FUNC(format_temperature), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_electric_current,
            { "Electric Current", "btmesh.property.electric_current",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_electric_current), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_energy,
            { "Energy", "btmesh.property.energy",
            FT_UINT24, BASE_CUSTOM, CF_FUNC(format_energy), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_generic_level,
            { "Generic Level", "btmesh.property.generic_level",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_boolean,
            { "Boolean", "btmesh.property.boolean",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(format_boolean), 0x0,
            NULL, HFILL }
        },
        { &hf_bt_characteristic_time_second_16,
            { "Time Second 16", "btmesh.property.time_second_16",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(format_time_second_16), 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_btmesh,
        &ett_btmesh_net_pdu,
        &ett_btmesh_transp_pdu,
        &ett_btmesh_transp_ctrl_msg,
        &ett_btmesh_upper_transp_acc_pdu,
        &ett_btmesh_segmented_access_fragments,
        &ett_btmesh_segmented_access_fragment,
        &ett_btmesh_segmented_control_fragments,
        &ett_btmesh_segmented_control_fragment,
        &ett_btmesh_access_pdu,
        &ett_btmesh_model_layer,
        &ett_btmesh_config_model_netapp_index,
        &ett_btmesh_config_model_publishperiod,
        &ett_btmesh_config_model_publishretransmit,
        &ett_btmesh_config_model_relayretransmit,
        &ett_btmesh_config_model_network_transmit,
        &ett_btmesh_config_model_element,
        &ett_btmesh_config_model_model,
        &ett_btmesh_config_model_vendor,
        &ett_btmesh_config_composition_data_status_features,
        &ett_btmesh_config_model_pub_app_index,
        &ett_btmesh_config_model_addresses,
        &ett_btmesh_config_model_netkey_list,
        &ett_btmesh_config_model_appkey_list,
        &ett_btmesh_config_model_net_index,
        &ett_btmesh_config_model_app_index,
        &ett_btmesh_config_heartbeat_publication_set_features,
        &ett_btmesh_config_heartbeat_publication_status_features,
        &ett_btmesh_config_model_fault_array,
        &ett_btmesh_scene_register_status_scenes,
        &ett_btmesh_scheduler_model_month,
        &ett_btmesh_scheduler_model_day_of_week,
        &ett_btmesh_scheduler_schedules,
        &ett_btmesh_user_property_ids,
        &ett_btmesh_admin_property_ids,
        &ett_btmesh_manufacturer_property_ids,
        &ett_btmesh_generic_client_property_ids,
        &ett_btmesh_sensor_setting_property_ids,
    };

    static ei_register_info ei[] = {
        { &ei_btmesh_not_decoded_yet,{ "btmesh.not_decoded_yet", PI_PROTOCOL, PI_NOTE, "Not decoded yet", EXPFILL } },
        { &ei_btmesh_unknown_payload,{ "btmesh.unknown_payload", PI_PROTOCOL, PI_ERROR, "Unknown Payload", EXPFILL } },
    };

    expert_module_t* expert_btmesh;

    module_t *btmesh_module;

    /* UAT Net Key and App Key definitions */
    static uat_field_t btmesh_uat_flds[] = {
        UAT_FLD_CSTRING(uat_btmesh_records, network_key_string, "Network Key", "Network Key"),
        UAT_FLD_CSTRING(uat_btmesh_records, application_key_string, "Application Key", "Application Key"),
        UAT_FLD_CSTRING(uat_btmesh_records, ivindex_string, "IVindex", "IVindex"),
        UAT_END_FIELDS
    };

    /* UAT Device Key definition */
    static uat_field_t btmesh_dev_key_uat_flds[] = {
        UAT_FLD_CSTRING(uat_btmesh_dev_key_records, device_key_string, "Device Key", "Device Key"),
        UAT_FLD_CSTRING(uat_btmesh_dev_key_records, src_string, "SRC Address", "SRC Address"),
        UAT_END_FIELDS
    };

    /* UAT Label UUID definition */
    static uat_field_t btmesh_label_uuid_uat_flds[] = {
        UAT_FLD_CSTRING(uat_btmesh_label_uuid_records, label_uuid_string, "Label UUID", "Label UUID"),
        UAT_END_FIELDS
    };

    proto_btmesh = proto_register_protocol("Bluetooth Mesh", "BT Mesh", "btmesh");

    proto_register_field_array(proto_btmesh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btmesh = expert_register_protocol(proto_btmesh);
    expert_register_field_array(expert_btmesh, ei, array_length(ei));

    btmesh_module = prefs_register_protocol_subtree("Bluetooth", proto_btmesh, NULL);

    prefs_register_static_text_preference(btmesh_module, "version",
            "Bluetooth Mesh Profile v1.0",
            "Version of protocol supported by this dissector.");

    btmesh_uat = uat_new("BTMesh Network and Application keys",
        sizeof(uat_btmesh_record_t),    /* record size */
        "btmesh_nw_keys",               /* filename */
        true,                           /* from_profile */
        &uat_btmesh_records,            /* data_ptr */
        &num_btmesh_uat,                /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
        NULL,                           /* help */
        uat_btmesh_record_copy_cb,      /* copy callback */
        uat_btmesh_record_update_cb,    /* update callback */
        uat_btmesh_record_free_cb,      /* free callback */
        NULL,                           /* post update callback */
        NULL,                           /* reset callback */
        btmesh_uat_flds);               /* UAT field definitions */

    prefs_register_uat_preference(btmesh_module,
        "mesh_keys_table",
        "Mesh Keys",
        "Configured Mesh Keys",
        btmesh_uat);

    btmesh_dev_key_uat = uat_new("BTMesh Device keys",
        sizeof(uat_btmesh_dev_key_record_t),  /* record size */
        "btmesh_dev_keys",                    /* filename */
        true,                                 /* from_profile */
        &uat_btmesh_dev_key_records,          /* data_ptr */
        &num_btmesh_dev_key_uat,              /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,               /* affects dissection of packets, but not set of named fields */
        NULL,                                 /* help */
        uat_btmesh_dev_key_record_copy_cb,    /* copy callback */
        uat_btmesh_dev_key_record_update_cb,  /* update callback */
        uat_btmesh_dev_key_record_free_cb,    /* free callback */
        NULL,                                 /* post update callback */
        NULL,                                 /* reset callback */
        btmesh_dev_key_uat_flds);             /* UAT field definitions */

    prefs_register_uat_preference(btmesh_module,
        "mesh_dev_key_table",
        "Device Keys",
        "Configured Mesh Device Keys",
        btmesh_dev_key_uat);

    btmesh_label_uuid_uat = uat_new("BTMesh Label UUIDs",
        sizeof(uat_btmesh_label_uuid_record_t),  /* record size */
        "btmesh_label_uuids",                    /* filename */
        true,                                    /* from_profile */
        &uat_btmesh_label_uuid_records,          /* data_ptr */
        &num_btmesh_label_uuid_uat,              /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,                  /* affects dissection of packets, but not set of named fields */
        NULL,                                    /* help */
        uat_btmesh_label_uuid_record_copy_cb,    /* copy callback */
        uat_btmesh_label_uuid_record_update_cb,  /* update callback */
        uat_btmesh_label_uuid_record_free_cb,    /* free callback */
        NULL,                                    /* post update callback */
        NULL,                                    /* reset callback */
        btmesh_label_uuid_uat_flds);             /* UAT field definitions */

    prefs_register_uat_preference(btmesh_module,
        "mesh_label_uuid_table",
        "Label UUIDs",
        "Configured Mesh Label UUIDs",
        btmesh_label_uuid_uat);

    btmesh_model_vendor_dissector_table  = register_dissector_table("btmesh.model.vendor",  "BT Mesh model vendor", proto_btmesh, FT_UINT16, BASE_DEC);

    register_dissector("btmesh.msg", dissect_btmesh_msg, proto_btmesh);

    reassembly_table_register(&upper_transport_reassembly_table, &upper_transport_reassembly_table_functions);
}

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
