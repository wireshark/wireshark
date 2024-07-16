/* packet-gvcp.c
 * Routines for AIA GigE Vision (TM) Control Protocol dissection
 * Copyright 2012, AIA <www.visiononline.org> All rights reserved
 *
 * GigE Vision (TM): GigE Vision a standard developed under the sponsorship of the AIA for
 * the benefit of the machine vision industry. GVCP stands for GigE Vision (TM) Control
 * Protocol.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>

#define GVCP_MIN_PACKET_SIZE          ( 8 )
#define GVCP_MAX_STREAM_CHANNEL_COUNT ( 512 )

/*
   header fields to show the relations between
   request and response as well as the response time
*/
static int hf_gvcp_response_in;
static int hf_gvcp_response_to;

/*
   structure to hold info to remember between the requests and responses
*/
typedef struct _gvcp_transaction_t {
	uint32_t req_frame;
	uint32_t rep_frame;
	wmem_array_t *addr_list;
	uint32_t addr_count;
} gvcp_transaction_t;

wmem_array_t* gvcp_trans_array;

/*
   structure to hold persistent info for each conversation
*/
typedef struct _gvcp_conv_info_t {
	wmem_map_t *pdus;
	uint32_t extended_bootstrap_address[GVCP_MAX_STREAM_CHANNEL_COUNT];
} gvcp_conv_info_t;

/*
Bootstrap registers addresses
*/

#define GVCP_VERSION (0x00000000)
#define GVCP_DEVICE_MODE (0x00000004)
#define GVCP_DEVICE_MAC_HIGH_0 (0x00000008)
#define GVCP_DEVICE_MAC_LOW_0 (0x0000000C)
#define GVCP_SUPPORTED_IP_CONFIGURATION_0 (0x00000010)
#define GVCP_CURIPCFG_0 (0x00000014)
#define GVCP_CURRENT_IP_ADDRESS_0 (0x00000024)
#define GVCP_CURRENT_SUBNET_MASK_0 (0x00000034)
#define GVCP_CURRENT_DEFAULT_GATEWAY_0 (0x00000044)
#define GVCP_MANUFACTURER_NAME (0x00000048)
#define GVCP_MODEL_NAME (0x00000068)
#define GVCP_DEVICE_VERSION (0x00000088)
#define GVCP_MANUFACTURER_INFO (0x000000A8)
#define GVCP_SERIAL_NUMBER (0x000000d8)
#define GVCP_USER_DEFINED_NAME (0x000000E8)
#define GVCP_FIRST_URL (0x00000200)
#define GVCP_SECOND_URL (0x00000400)
#define GVCP_NUMBER_OF_NETWORK_INTERFACES (0x00000600)
#define GVCP_PERSISTENT_IP_ADDRESS_0 (0x0000064C)
#define GVCP_PERSISTENT_SUBNET_MASK_0 (0x0000065C)
#define GVCP_PERSISTENT_DEFAULT_GATEWAY_0 (0x0000066C)
#define GVCP_LINK_SPEED_0 (0x00000670)
#define GVCP_DEVICE_MAC_HIGH_1 (0x00000680)
#define GVCP_DEVICE_MAC_LOW_1 (0x00000684)
#define GVCP_SUPPORTED_IP_CONFIGURATION_1 (0x00000688)
#define GVCP_CURIPCFG_1 (0x0000068C)
#define GVCP_CURRENT_IP_ADDRESS_1  (0x0000069C)
#define GVCP_CURRENT_SUBNET_MASK_1 (0x000006AC)
#define GVCP_CURRENT_DEFAULT_GATEWAY_1 (0x000006BC)
#define GVCP_PERSISTENT_IP_ADDRESS_1 (0x000006CC)
#define GVCP_PERSISTENT_SUBNET_MASK_1 (0x000006DC)
#define GVCP_PERSISTENT_DEFAULT_GATEWAY_1 (0x000006EC)
#define GVCP_LINK_SPEED_1 (0x000006F0)
#define GVCP_DEVICE_MAC_HIGH_2 (0x00000700)
#define GVCP_DEVICE_MAC_LOW_2 (0x00000704)
#define GVCP_SUPPORTED_IP_CONFIGURATION_2 (0x00000708)
#define GVCP_CURIPCFG_2 (0x0000070C)
#define GVCP_CURRENT_IP_ADDRESS_2 (0x0000071C)
#define GVCP_CURRENT_SUBNET_MASK_2 (0x0000072C)
#define GVCP_CURRENT_DEFAULT_GATEWAY_2 (0x0000073C)
#define GVCP_PERSISTENT_IP_ADDRESS_2 (0x0000074C)
#define GVCP_PERSISTENT_SUBNET_MASK_2 (0x0000075C)
#define GVCP_PERSISTENT_DEFAULT_GATEWAY_2 (0x0000076C)
#define GVCP_LINK_SPEED_2 (0x00000770)
#define GVCP_DEVICE_MAC_HIGH_3 (0x00000780)
#define GVCP_DEVICE_MAC_LOW_3 (0x00000784)
#define GVCP_SUPPORTED_IP_CONFIGURATION_3 (0x00000788)
#define GVCP_CURIPCFG_3 (0x0000078C)
#define GVCP_CURRENT_IP_ADDRESS_3 (0x0000079C)
#define GVCP_CURRENT_SUBNET_MASK_3 (0x000007AC)
#define GVCP_CURRENT_DEFAULT_GATEWAY_3 (0x000007BC)
#define GVCP_PERSISTENT_IP_ADDRESS_3 (0x000007CC)
#define GVCP_PERSISTENT_SUBNET_MASK_3 (0x000007DC)
#define GVCP_PERSISTENT_DEFAULT_GATEWAY_3 (0x000007EC)
#define GVCP_LINK_SPEED_3 (0x000007F0)
#define GVCP_NUMBER_OF_MESSAGE_CHANNELS (0x00000900)
#define GVCP_NUMBER_OF_STREAM_CHANNELS (0x00000904)
#define GVCP_NUMBER_OF_ACTION_SIGNALS (0x00000908)
#define GVCP_ACTION_DEVICE_KEY (0x0000090C)
#define GVCP_NUMBER_OF_ACTIVE_LINKS (0x00000910)
#define GVCP_SC_CAPS (0x0000092C)
#define GVCP_MESSAGE_CHANNEL_CAPS (0x00000930)
#define GVCP_CAPABILITY (0x00000934)
#define GVCP_HEARTBEAT_TIMEOUT (0x00000938)
#define GVCP_TIMESTAMP_TICK_FREQUENCY_HIGH (0x0000093C)
#define GVCP_TIMESTAMP_TICK_FREQUENCY_LOW (0x00000940)
#define GVCP_TIMESTAMP_CONTROL (0x00000944)
#define GVCP_TIMESTAMP_VALUE_HIGH (0x00000948)
#define GVCP_TIMESTAMP_VALUE_LOW (0x0000094C)
#define GVCP_DISCOVERY_ACK_DELAY (0x00000950)
#define GVCP_CONFIGURATION (0x00000954)
#define GVCP_PENDING_TIMEOUT (0x00000958)
#define GVCP_CONTROL_SWITCHOVER_KEY (0x0000095C)
#define GVCP_GVSCP_CONFIGURATION (0x00000960)
#define GVCP_PHYSICAL_LINK_CAPABILITY (0x00000964)
#define GVCP_PHYSICAL_LINK_CONFIGURATION (0x00000968)
#define GVCP_IEEE_1588_STATUS (0x0000096C)
#define GVCP_SCHEDULED_ACTION_COMMAND_QUEUE_SIZE (0x00000970)
#define GVCP_IEEE_1588_EXTENDED_CAPABILITY (0x00000974)
#define GVCP_IEEE_1588_SUPPORTED_PROFILES (0x00000978)
#define GVCP_IEEE_1588_SELECTED_PROFILE (0x0000097C)
#define GVCP_CCP (0x00000A00)
#define GVCP_PRIMARY_APPLICATION_PORT (0x00000A04)
#define GVCP_PRIMARY_APPLICATION_IP_ADDRESS (0x00000A14)
#define GVCP_MC_DESTINATION_PORT (0x00000B00)
#define GVCP_MC_DESTINATION_ADDRESS (0x00000B10)
#define GVCP_MC_TIMEOUT (0x00000B14)
#define GVCP_MC_RETRY_COUNT (0x00000B18)
#define GVCP_MC_SOURCE_PORT (0x00000B1C)
#define GVCP_MC_CONFIGURATION (0x00000B20) /* GEV 2.2 */
#define GVCP_MANIFEST_TABLE (0x00009000)

#define GVCP_SC_DESTINATION_PORT(I)           (0x0d00+(0x40*I))
#define GVCP_SC_PACKET_SIZE(I)                (0x0d04+(0x40*I))
#define GVCP_SC_PACKET_DELAY(I)               (0x0d08+(0x40*I))
#define GVCP_SC_DESTINATION_ADDRESS(I)        (0x0d18+(0x40*I))
#define GVCP_SC_SOURCE_PORT(I)                (0x0d1C+(0x40*I))
#define GVCP_SC_CAPABILITY(I)                 (0x0d20+(0x40*I))
#define GVCP_SC_CONFIGURATION(I)              (0x0d24+(0x40*I))
#define GVCP_SC_ZONE(I)                       (0x0d28+(0x40*I))
#define GVCP_SC_ZONE_DIRECTION(I)             (0x0d2C+(0x40*I))
#define GVCP_SC_MAX_PACKET_COUNT(I)           (0x0d30+(0x40*I)) /* GEV 2.2 */
#define GVCP_SC_MAX_BLOCK_SIZE_HIGH(I)        (0x0d34+(0x40*I)) /* GEV 2.2 */
#define GVCP_SC_MAX_BLOCK_SIZE_LOW(I)         (0x0d38+(0x40*I)) /* GEV 2.2 */
#define GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(I) (0x0d3C+(0x40*I)) /* GEV 2.2 */

/* Real address: GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(I) + the values defined here */
#define GVCP_SC_GENDC_DESCRIPTOR_ADDRESS         ( 0x0000 ) /* GEV 2.2 */
#define GVCP_SC_GENDC_DESCRIPTOR_SIZE            ( 0x0004 ) /* GEV 2.2 */
#define GVCP_SC_GENDC_FLOW_MAPPING_TABLE_ADDRESS ( 0x0008 ) /* GEV 2.2 */
#define GVCP_SC_GENDC_FLOW_MAPPING_TABLE_SIZE    ( 0x000C ) /* GEV 2.2 */
#define GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS_LAST  ( 0x000C )

#define GVCP_ACTION_GROUP_KEY(I)  (0x9800+(0x10*I))
#define GVCP_ACTION_GROUP_MASK(I) (0x9804+(0x10*I))


/*
Command and acknowledge IDs
*/

#define GVCP_DISCOVERY_CMD (0x0002)
#define GVCP_DISCOVERY_ACK (0x0003)
#define GVCP_FORCEIP_CMD (0x0004)
#define GVCP_FORCEIP_ACK (0x0005)
#define GVCP_PACKETRESEND_CMD (0x0040)
#define GVCP_PACKETRESEND_ACK (0x0041)
#define GVCP_READREG_CMD (0x0080)
#define GVCP_READREG_ACK (0x0081)
#define GVCP_WRITEREG_CMD (0x0082)
#define GVCP_WRITEREG_ACK (0x0083)
#define GVCP_READMEM_CMD (0x0084)
#define GVCP_READMEM_ACK (0x0085)
#define GVCP_WRITEMEM_CMD (0x0086)
#define GVCP_WRITEMEM_ACK (0x0087)
#define GVCP_PENDING_ACK (0x0089)
#define GVCP_EVENT_CMD (0x00C0)
#define GVCP_EVENT_ACK (0x00C1)
#define GVCP_EVENTDATA_CMD (0x00C2)
#define GVCP_EVENTDATA_ACK (0x00C3)
#define GVCP_ACTION_CMD (0x0100)
#define GVCP_ACTION_ACK (0x0101)


/*
GVCP statuses
*/

#define GEV_STATUS_SUCCESS (0x0000)
#define GEV_STATUS_PACKET_RESEND (0x0100)
#define GEV_STATUS_NOT_IMPLEMENTED (0x8001)
#define GEV_STATUS_INVALID_PARAMETER (0x8002)
#define GEV_STATUS_INVALID_ADDRESS (0x8003)
#define GEV_STATUS_WRITE_PROTECT (0x8004)
#define GEV_STATUS_BAD_ALIGNMENT (0x8005)
#define GEV_STATUS_ACCESS_DENIED (0x8006)
#define GEV_STATUS_BUSY (0x8007)
#define GEV_STATUS_LOCAL_PROBLEM (0x8008)  /* deprecated */
#define GEV_STATUS_MSG_MISMATCH (0x8009) /* deprecated */
#define GEV_STATUS_INVALID_PROTOCOL (0x800A) /* deprecated */
#define GEV_STATUS_NO_MSG (0x800B) /* deprecated */
#define GEV_STATUS_PACKET_UNAVAILABLE (0x800C)
#define GEV_STATUS_DATA_OVERRUN (0x800D)
#define GEV_STATUS_INVALID_HEADER (0x800E)
#define GEV_STATUS_WRONG_CONFIG (0x800F) /* deprecated */
#define GEV_STATUS_PACKET_NOT_YET_AVAILABLE (0x8010)
#define GEV_STATUS_PACKET_AND_PREV_REMOVED_FROM_MEMORY (0x8011)
#define GEV_STATUS_PACKET_REMOVED_FROM_MEMORY (0x8012)
#define GEV_STATUS_NO_REF_TIME (0x8013) /* GEV 2.0 */
#define GEV_STATUS_PACKET_TEMPORARILY_UNAVAILABLE (0x8014) /* GEV 2.0 */
#define GEV_STATUS_OVERFLOW (0x8015) /* GEV 2.0 */
#define GEV_STATUS_ACTION_LATE (0x8016) /* GEV 2.0 */
#define GEV_STATUS_LEADER_TRAILER_OVERFLOW (0x8017) /* GEV 2.1 */
#define GEV_STATUS_ERROR (0x8FFF)


/*
Device modes
*/

#define GEV_DEVICEMODE_TRANSMITTER (0x00 )
#define GEV_DEVICEMODE_RECEIVER (0x01)
#define GEV_DEVICEMODE_TRANSCEIVER (0x02)
#define GEV_DEVICEMODE_PERIPHERAL (0x03)


/*
Event IDs
*/

#define GEV_EVENT_TRIGGER (0x0002) /* deprecated */
#define GEV_EVENT_START_OF_EXPOSURE (0x0003) /* deprecated */
#define GEV_EVENT_END_OF_EXPOSURE (0x0004) /* deprecated */
#define GEV_EVENT_START_OF_TRANSFER (0x0005) /* deprecated */
#define GEV_EVENT_END_OF_TRANSFER (0x0006) /* deprecated */
#define GEV_EVENT_PRIMARY_APP_SWITCH (0x0007)
#define GEV_EVENT_EVENT_LINK_SPEED_CHANGE (0x0008)
#define GEV_EVENT_ACTION_LATE (0x0009)
#define GEV_EVENT_ERROR_001 (0x8001)


/*
Link configurations
*/

#define GEV_LINKCONFIG_SINGLELINK (0x00)
#define GEV_LINKCONFIG_MULTIPLELINKS (0x01)
#define GEV_LINKCONFIG_STATICLAG (0x02)
#define GEV_LINKCONFIG_DYNAMICLAG (0x03)


void proto_register_gvcp(void);
void proto_reg_handoff_gvcp(void);

/* Define the gvcp proto */
static int proto_gvcp;
static int global_gvcp_port = 3956;

static int hf_gvcp_custom_register_addr;
static int hf_gvcp_custom_memory_addr;

/*
\brief IDs used for bootstrap dissection
*/

static int hf_gvcp_message_key_code;
static int hf_gvcp_flag;
static int hf_gvcp_acknowledge_required_flag;
static int hf_gvcp_allow_broadcast_acknowledge_flag;
static int hf_gvcp_command;
static int hf_gvcp_length;
static int hf_gvcp_request_id;
static int hf_gvcp_status;
static int hf_gvcp_acknowledge;
static int hf_gvcp_spec_version_major;
static int hf_gvcp_spec_version_minor;
static int hf_gvcp_devicemodediscovery;
static int hf_gvcp_device_mac_address;
static int hf_gvcp_ip_config_persistent_ip;
static int hf_gvcp_ip_config_dhcp;
static int hf_gvcp_ip_config_lla;
static int hf_gvcp_current_IP;
static int hf_gvcp_current_subnet_mask;
static int hf_gvcp_current_default_gateway;
static int hf_gvcp_manufacturer_name;
static int hf_gvcp_model_name;
static int hf_gvcp_device_version;
static int hf_gvcp_manufacturer_specific_info;
static int hf_gvcp_serial_number;
static int hf_gvcp_user_defined_name;
static int hf_gvcp_first_xml_device_description_file;
static int hf_gvcp_second_xml_device_description_file;
static int hf_gvcp_readregcmd_bootstrap_register;
static int hf_gvcp_writeregcmd_bootstrap_register;
static int hf_gvcp_writeregcmd_data;
static int hf_gvcp_writeregcmd_data_index;
static int hf_gvcp_readmemcmd_address;
static int hf_gvcp_readmemcmd_bootstrap_register;
static int hf_gvcp_readmemcmd_count;
static int hf_gvcp_writememcmd_data;
static int hf_gvcp_writememcmd_data_index;
static int hf_gvcp_forceip_mac_address;
static int hf_gvcp_forceip_static_IP;
static int hf_gvcp_forceip_static_subnet_mask;
static int hf_gvcp_forceip_static_default_gateway;
static int hf_gvcp_resendcmd_stream_channel_index;
static int hf_gvcp_resendcmd_block_id;
static int hf_gvcp_resendcmd_first_packet_id;
static int hf_gvcp_resendcmd_last_packet_id;
static int hf_gvcp_eventcmd_id;
static int hf_gvcp_eventcmd_error_id;
static int hf_gvcp_eventcmd_extid_length;
static int hf_gvcp_eventcmd_device_specific_id;
static int hf_gvcp_eventcmd_stream_channel_index;
static int hf_gvcp_eventcmd_block_id;
static int hf_gvcp_eventcmd_timestamp;
static int hf_gvcp_eventcmd_data;
static int hf_gvcp_actioncmd_device_key;
static int hf_gvcp_actioncmd_group_key;
static int hf_gvcp_actioncmd_group_mask;
static int hf_gvcp_time_to_completion;
static int hf_gvcp_devicemode_endianness;
static int hf_gvcp_devicemode_deviceclass;
static int hf_gvcp_devicemode_characterset;
static int hf_gvcp_machigh;
static int hf_gvcp_maclow;
static int hf_gvcp_persistent_ip;
static int hf_gvcp_persistent_subnet;
static int hf_gvcp_persistent_gateway;
static int hf_gvcp_link_speed;
static int hf_gvcp_number_message_channels;
static int hf_gvcp_number_stream_channels;
static int hf_gvcp_number_action_signals;
static int hf_gvcp_capability_user_defined;
static int hf_gvcp_capability_serial_number;
static int hf_gvcp_capability_heartbeat_disable;
static int hf_gvcp_capability_link_speed;
static int hf_gvcp_capability_extended_status_code_v1_1;
static int hf_gvcp_capability_ccp_application_portip;
static int hf_gvcp_capability_manifest_table;
static int hf_gvcp_capability_test_data;
static int hf_gvcp_capability_discovery_ACK_delay;
static int hf_gvcp_capability_writable_discovery_ACK_delay;
static int hf_gvcp_capability_primary_application_switchover;
static int hf_gvcp_capability_unconditional_action_command;
static int hf_gvcp_capability_pending;
static int hf_gvcp_capability_evendata;
static int hf_gvcp_capability_event;
static int hf_gvcp_capability_packetresend;
static int hf_gvcp_capability_writemem;
static int hf_gvcp_capability_concatenation;
static int hf_gvcp_heartbeat;
static int hf_gvcp_high_timestamp_frequency;
static int hf_gvcp_low_timestamp_frequency;
static int hf_gvcp_high_timestamp_value;
static int hf_gvcp_low_timestamp_value;
static int hf_gvcp_discovery_ACK_delay;
static int hf_gvcp_configuration_pending_ack_enable;
static int hf_gvcp_configuration_heartbeat_disable;
static int hf_gvcp_pending_timeout_max_execution;
static int hf_gvcp_control_switchover_key_register;
static int hf_gvcp_control_switchover_key;
static int hf_gvcp_control_switchover_en;
static int hf_gvcp_control_access;
static int hf_gvcp_exclusive_access;
static int hf_gvcp_primary_application_host_port;
static int hf_gvcp_primary_application_ip_address;
static int hf_gvcp_network_interface_index;
static int hf_gvcp_host_port;
static int hf_gvcp_channel_destination_ip;
static int hf_gvcp_message_channel_transmission_timeout;
static int hf_gvcp_message_channel_retry_count;
static int hf_gvcp_message_channel_source_port;
static int hf_gvcp_sc_host_port;
static int hf_gvcp_sc_ni_index;
static int hf_gvcp_sc_direction;
static int hf_gvcp_sc_fire_test_packet;
static int hf_gvcp_sc_do_not_fragment;
static int hf_gvcp_sc_pixel_endianness;
static int hf_gvcp_sc_packet_size;
static int hf_gvcp_sc_packet_delay;
static int hf_gvcp_sc_destination_ip;
static int hf_gvcp_sc_source_port;
static int hf_gvcp_sc_big_little_endian_supported;
static int hf_gvcp_sc_ip_reassembly_supported;
static int hf_gvcp_sc_unconditional_streaming_supported;
static int hf_gvcp_sc_extended_chunk_data_supported;
static int hf_gvcp_sc_unconditional_streaming_enabled;
static int hf_gvcp_configuration_extended_status_codes_enable_v1_1;
static int hf_gvcp_sc_extended_chunk_data_enabled;
static int hf_gvcp_action_group_key;
static int hf_gvcp_action_group_mask;
static int hf_gvcp_timestamp_control_latch;
static int hf_gvcp_timestamp_control_reset;
static int hf_gvcp_payloaddata;
static int hf_gvcp_number_interfaces;
static int hf_gvcp_supportedipconfig;
static int hf_gvcp_currentipconfig;
static int hf_gvcp_spec_version;

/* Added for 2.0 support */
static int hf_gvcp_devicemode_current_link_configuration_v2_0;
static int hf_gvcp_ip_config_can_handle_pause_frames_v2_0;
static int hf_gvcp_ip_config_can_generate_pause_frames_v2_0;
static int hf_gvcp_number_of_active_links_v2_0;
static int hf_gvcp_sccaps_scspx_register_supported;
static int hf_gvcp_sccaps_legacy_16bit_blockid_supported_v2_0;
static int hf_gvcp_mcsp_supported;
static int hf_gvcp_capability_1588_v2_0;
static int hf_gvcp_capability_extended_status_code_v2_0;
static int hf_gvcp_capability_scheduled_action_command_v2_0;
static int hf_gvcp_capability_action_command;
static int hf_gvcp_configuration_1588_enable_v2_0;
static int hf_gvcp_configuration_extended_status_codes_enable_v2_0;
static int hf_gvcp_configuration_unconditional_action_command_enable_v2_0;
static int hf_gvcp_gvsp_configuration_64bit_blockid_enable_v2_0;
static int hf_gvcp_link_dlag_v2_0;
static int hf_gvcp_link_slag_v2_0;
static int hf_gvcp_link_ml_v2_0;
static int hf_gvcp_link_sl_v2_0;
static int hf_gvcp_ieee1588_clock_status_v2_0;
static int hf_gvcp_scheduled_action_command_queue_size_v2_0;
static int hf_gvcp_sc_multizone_supported_v2_0;
static int hf_gvcp_sc_packet_resend_destination_option_supported_v2_0;
static int hf_gvcp_sc_packet_resend_all_in_transmission_supported_v2_0;
static int hf_gvcp_sc_packet_resend_destination_option_enabled_v2_0;
static int hf_gvcp_sc_packet_resend_all_in_transmission_enabled_v2_0;
static int hf_gvcp_sc_additional_zones_v2_0;
static int hf_gvcp_sc_zone0_direction_v2_0;
static int hf_gvcp_sc_zone1_direction_v2_0;
static int hf_gvcp_sc_zone2_direction_v2_0;
static int hf_gvcp_sc_zone3_direction_v2_0;
static int hf_gvcp_sc_zone4_direction_v2_0;
static int hf_gvcp_sc_zone5_direction_v2_0;
static int hf_gvcp_sc_zone6_direction_v2_0;
static int hf_gvcp_sc_zone7_direction_v2_0;
static int hf_gvcp_sc_zone8_direction_v2_0;
static int hf_gvcp_sc_zone9_direction_v2_0;
static int hf_gvcp_sc_zone10_direction_v2_0;
static int hf_gvcp_sc_zone11_direction_v2_0;
static int hf_gvcp_sc_zone12_direction_v2_0;
static int hf_gvcp_sc_zone13_direction_v2_0;
static int hf_gvcp_sc_zone14_direction_v2_0;
static int hf_gvcp_sc_zone15_direction_v2_0;
static int hf_gvcp_sc_zone16_direction_v2_0;
static int hf_gvcp_sc_zone17_direction_v2_0;
static int hf_gvcp_sc_zone18_direction_v2_0;
static int hf_gvcp_sc_zone19_direction_v2_0;
static int hf_gvcp_sc_zone20_direction_v2_0;
static int hf_gvcp_sc_zone21_direction_v2_0;
static int hf_gvcp_sc_zone22_direction_v2_0;
static int hf_gvcp_sc_zone23_direction_v2_0;
static int hf_gvcp_sc_zone24_direction_v2_0;
static int hf_gvcp_sc_zone25_direction_v2_0;
static int hf_gvcp_sc_zone26_direction_v2_0;
static int hf_gvcp_sc_zone27_direction_v2_0;
static int hf_gvcp_sc_zone28_direction_v2_0;
static int hf_gvcp_sc_zone29_direction_v2_0;
static int hf_gvcp_sc_zone30_direction_v2_0;
static int hf_gvcp_sc_zone31_direction_v2_0;
static int hf_gvcp_scheduledactioncommand_flag_v2_0;
static int hf_gvcp_64bitid_flag_v2_0;
static int hf_gvcp_resendcmd_extended_block_id_v2_0;
static int hf_gvcp_resendcmd_extended_first_packet_id_v2_0;
static int hf_gvcp_resendcmd_extended_last_packet_id_v2_0;
static int hf_gvcp_actioncmd_time_v2_0;
static int hf_gvcp_eventcmd_block_id_64bit_v2_0;

/* Added for 2.1 support */
static int hf_gvcp_selected_ieee1588_profile_v2_1;
static int hf_gvcp_capability_ieee1588_extended_capabilities_v2_1;
static int hf_gvcp_ieee1588_profile_registers_present_v2_1;
static int hf_gvcp_ieee1588_ptp_profile_supported_v2_1;
static int hf_gvcp_ieee1588_802dot1as_profile_supported_v2_1;
static int hf_gvcp_sc_multi_part_supported_v2_1;
static int hf_gvcp_sc_large_leader_trailer_supported_v2_1;
static int hf_gvcp_sc_multi_part_enabled_v2_1;
static int hf_gvcp_sc_large_leader_trailer_enabled_v2_1;

/* Added for 2.2 support */
static int hf_gvcp_sccaps_scmbsx_supported_v2_2;
static int hf_gvcp_sccaps_scebax_supported_v2_2;
static int hf_gvcp_mccfg_supported_v2_2;
static int hf_gvcp_mcec_supported_v2_2;
static int hf_gvcp_mcec_enabled_v2_2;
static int hf_gvcp_sc_scmpcx_supported_v2_2;
static int hf_gvcp_sc_gendc_supported_v2_2;
static int hf_gvcp_sc_gendc_enabled_v2_2;
static int hf_gvcp_sc_max_packet_count_v2_2;
static int hf_gvcp_sc_max_block_size_high_v2_2;
static int hf_gvcp_sc_max_block_size_low_v2_2;
static int hf_gvcp_sc_extended_registers_address_v2_2;
static int hf_gvcp_sc_gendc_descriptor_address_v2_2;
static int hf_gvcp_sc_gendc_descriptor_size_v2_2;
static int hf_gvcp_sc_gendc_flow_mapping_table_address_v2_2;
static int hf_gvcp_sc_gendc_flow_mapping_table_size_v2_2;
static int hf_gvcp_readregcmd_extended_bootstrap_register;
static int hf_gvcp_writeregcmd_extended_bootstrap_register;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_gvcp_custom_register_value;
static int hf_gvcp_custom_read_register_addr;
static int hf_gvcp_readmemcmd_data_read;
static int hf_gvcp_custom_read_register_value;
static int hf_gvcp_manifest_table;
static int hf_gvcp_reserved_bit;

/*Define the tree for gvcp*/
static int ett_gvcp;
static int ett_gvcp_cmd;
static int ett_gvcp_flags;
static int ett_gvcp_ack;
static int ett_gvcp_payload_cmd;
static int ett_gvcp_payload_ack;
static int ett_gvcp_payload_cmd_subtree;
static int ett_gvcp_payload_ack_subtree;
static int ett_gvcp_bootstrap_fields;

static dissector_handle_t gvcp_handle;
static dissector_handle_t gvsp_handle;

/*Device Mode*/
static const value_string devicemodenames_class[] = {
	{ GEV_DEVICEMODE_TRANSMITTER, "Transmitter" },
	{ GEV_DEVICEMODE_RECEIVER, "Receiver" },
	{ GEV_DEVICEMODE_TRANSCEIVER, "Transceiver" },
	{ GEV_DEVICEMODE_PERIPHERAL, "Peripheral" },
	{ 0, NULL },
};

/*Current Link Configuration*/
static const value_string linkconfiguration_class[] = {
	{ GEV_LINKCONFIG_SINGLELINK, "Single Link" },
	{ GEV_LINKCONFIG_MULTIPLELINKS, "Multiple Links" },
	{ GEV_LINKCONFIG_STATICLAG, "Static LAG" },
	{ GEV_LINKCONFIG_DYNAMICLAG, "Dynamic LAG" },
	{ 0, NULL },
};

static const value_string devicemodenames_characterset[] = {
	{ 0x02, "ASCII" },
	{ 0x01, "UTF-8 Character Set" },
	{ 0x00, "Reserved" },
	{ 0, NULL },
};

static const value_string commandnames[] = {
	{ GVCP_DISCOVERY_CMD, "DISCOVERY_CMD" },
	{ GVCP_FORCEIP_CMD, "FORCEIP_CMD" },
	{ GVCP_PACKETRESEND_CMD, "PACKETRESEND_CMD" },
	{ GVCP_READREG_CMD, "READREG_CMD" },
	{ GVCP_WRITEREG_CMD, "WRITEREG_CMD" },
	{ GVCP_READMEM_CMD, "READMEM_CMD" },
	{ GVCP_WRITEMEM_CMD, "WRITEMEM_CMD" },
	{ GVCP_EVENT_CMD, "EVENT_CMD" },
	{ GVCP_EVENTDATA_CMD, "EVENTDATA_CMD" },
	{ GVCP_ACTION_CMD, "ACTION_CMD" },
	{ 0, NULL }
};

static const value_string acknowledgenames[] = {
	{ GVCP_DISCOVERY_ACK, "DISCOVERY_ACK" },
	{ GVCP_FORCEIP_ACK, "FORCEIP_ACK" },
	{ GVCP_PACKETRESEND_ACK, "PACKETRESEND_ACK" },
	{ GVCP_READREG_ACK, "READREG_ACK" },
	{ GVCP_WRITEREG_ACK, "WRITEREG_ACK" },
	{ GVCP_READMEM_ACK, "READMEM_ACK" },
	{ GVCP_WRITEMEM_ACK, "WRITEMEM_ACK" },
	{ GVCP_PENDING_ACK, "PENDING_ACK" },
	{ GVCP_EVENT_ACK, "EVENT_ACK" },
	{ GVCP_EVENTDATA_ACK, "EVENTDATA_ACK" },
	{ GVCP_ACTION_ACK, "ACTION_ACK" },
	{ 0, NULL },
};

static const value_string eventidnames[] = {
	{ GEV_EVENT_TRIGGER, "GEV_EVENT_TRIGGER (deprecated)" },
	{ GEV_EVENT_START_OF_EXPOSURE, "GEV_EVENT_START_OF_EXPOSURE (deprecated)" },
	{ GEV_EVENT_END_OF_EXPOSURE, "GEV_EVENT_END_OF_EXPOSURE (deprecated)" },
	{ GEV_EVENT_START_OF_TRANSFER, "GEV_EVENT_START_OF_TRANSFER (deprecated)" },
	{ GEV_EVENT_END_OF_TRANSFER, "GEV_EVENT_END_OF_TRANSFER (deprecated)" },
	{ GEV_EVENT_PRIMARY_APP_SWITCH, "GEV_EVENT_PRIMARY_APP_SWITCH" },
	{ GEV_EVENT_EVENT_LINK_SPEED_CHANGE, "GEV_EVENT_EVENT_LINK_SPEED_CHANGE" },
	{ GEV_EVENT_ACTION_LATE, "GEV_EVENT_ACTION_LATE" },
	{ GEV_EVENT_ERROR_001, "GEV_EVENT_ERROR_001" },
	{ 0, NULL },
};

static const value_string statusnames[] = {
	{ GEV_STATUS_SUCCESS, "GEV_STATUS_SUCCESS" },
	{ GEV_STATUS_PACKET_RESEND, "GEV_STATUS_PACKET_RESEND" },
	{ GEV_STATUS_NOT_IMPLEMENTED, "GEV_STATUS_NOT_IMPLEMENTED" },
	{ GEV_STATUS_INVALID_PARAMETER, "GEV_STATUS_INVALID_PARAMETER" },
	{ GEV_STATUS_INVALID_ADDRESS, "GEV_STATUS_INVALID_ADDRESS" },
	{ GEV_STATUS_WRITE_PROTECT, "GEV_STATUS_WRITE_PROTECT" },
	{ GEV_STATUS_BAD_ALIGNMENT, "GEV_STATUS_BAD_ALIGNMENT" },
	{ GEV_STATUS_ACCESS_DENIED, "GEV_STATUS_ACCESS_DENIED" },
	{ GEV_STATUS_BUSY, "GEV_STATUS_BUSY" },
	{ GEV_STATUS_LOCAL_PROBLEM, "GEV_STATUS_LOCAL_PROBLEM (deprecated)" },
	{ GEV_STATUS_MSG_MISMATCH, "GEV_STATUS_MSG_MISMATCH (deprecated)" },
	{ GEV_STATUS_INVALID_PROTOCOL, "GEV_STATUS_INVALID_PROTOCOL (deprecated)" },
	{ GEV_STATUS_NO_MSG, "GEV_STATUS_NO_MSG (deprecated)" },
	{ GEV_STATUS_PACKET_UNAVAILABLE, "GEV_STATUS_PACKET_UNAVAILABLE" },
	{ GEV_STATUS_DATA_OVERRUN, "GEV_STATUS_DATA_OVERRUN" },
	{ GEV_STATUS_INVALID_HEADER, "GEV_STATUS_INVALID_HEADER" },
	{ GEV_STATUS_WRONG_CONFIG, "GEV_STATUS_WRONG_CONFIG (deprecated)" },
	{ GEV_STATUS_PACKET_NOT_YET_AVAILABLE, "GEV_STATUS_PACKET_NOT_YET_AVAILABLE" },
	{ GEV_STATUS_PACKET_AND_PREV_REMOVED_FROM_MEMORY, "GEV_STATUS_PACKET_AND_PREV_REMOVED_FROM_MEMORY" },
	{ GEV_STATUS_PACKET_REMOVED_FROM_MEMORY, "GEV_STATUS_PACKET_REMOVED_FROM_MEMORY" },
	{ GEV_STATUS_NO_REF_TIME, "GEV_STATUS_NO_REF_TIME" },
	{ GEV_STATUS_PACKET_TEMPORARILY_UNAVAILABLE, "GEV_STATUS_PACKET_TEMPORARILY_UNAVAILABLE" },
	{ GEV_STATUS_OVERFLOW, "GEV_STATUS_OVERFLOW" },
	{ GEV_STATUS_ACTION_LATE, "GEV_STATUS_ACTION_LATE" },
	{ GEV_STATUS_LEADER_TRAILER_OVERFLOW, "GEV_STATUS_LEADER_TRAILER_OVERFLOW" },
	{ GEV_STATUS_ERROR, "GEV_STATUS_ERROR" },
	{ 0, NULL },
};

static const value_string statusnames_short[] = {
	{ GEV_STATUS_SUCCESS, "" },
	{ GEV_STATUS_PACKET_RESEND, "(Packet Resend) " },
	{ GEV_STATUS_NOT_IMPLEMENTED, "(Not Implemented) " },
	{ GEV_STATUS_INVALID_PARAMETER, "(Invalid Parameter) " },
	{ GEV_STATUS_INVALID_ADDRESS, "(Invalid Address) " },
	{ GEV_STATUS_WRITE_PROTECT, "(Write Protect) " },
	{ GEV_STATUS_BAD_ALIGNMENT, "(Bad Alignment) " },
	{ GEV_STATUS_ACCESS_DENIED, "(Access Denied) " },
	{ GEV_STATUS_BUSY, "(Busy) " },
	{ GEV_STATUS_LOCAL_PROBLEM, "(Local Problem) " },
	{ GEV_STATUS_MSG_MISMATCH, "(Message Mismatch) " },
	{ GEV_STATUS_INVALID_PROTOCOL, "(Invalid Protocol) " },
	{ GEV_STATUS_NO_MSG, "(No Message) " },
	{ GEV_STATUS_PACKET_UNAVAILABLE, "(Packet Unavailable) " },
	{ GEV_STATUS_DATA_OVERRUN, "(Data Overrun) " },
	{ GEV_STATUS_INVALID_HEADER, "(Invalid Header) " },
	{ GEV_STATUS_WRONG_CONFIG, "(Wrong Configuration) " },
	{ GEV_STATUS_PACKET_NOT_YET_AVAILABLE, "(Packet not yet available) " },
	{ GEV_STATUS_PACKET_AND_PREV_REMOVED_FROM_MEMORY, "(Packet and previous removed from memory) " },
	{ GEV_STATUS_PACKET_REMOVED_FROM_MEMORY, "(Packet removed from memory) " },
	{ GEV_STATUS_NO_REF_TIME, "(No reference time)" },
	{ GEV_STATUS_PACKET_TEMPORARILY_UNAVAILABLE, "(Packet temp. unavailable)" },
	{ GEV_STATUS_OVERFLOW, "(overflow)" },
	{ GEV_STATUS_ACTION_LATE, "(Action late)" },
	{ GEV_STATUS_LEADER_TRAILER_OVERFLOW, "(Leader/Trailer overflow)" },
	{ GEV_STATUS_ERROR, "(Error) " },
	{ 0, NULL },
};

static const true_false_string directionnames = {
	"Receiver",
	"Transmitter"
};

static const true_false_string zonedirectionnames = {
	"Bottom-Up",
	"Top-Down"
};

/*
brief Register name to address mappings
*/

static const value_string bootstrapregisternames[] = {
	{ GVCP_VERSION, "[Version]" },
	{ GVCP_DEVICE_MODE, "[Device Mode]" },
	{ GVCP_DEVICE_MAC_HIGH_0, "[Device MAC address High (Net #0)]" },
	{ GVCP_DEVICE_MAC_LOW_0, "[Device MAC address Low (Net #0)]" },
	{ GVCP_SUPPORTED_IP_CONFIGURATION_0, "[Supported IP Configuration (Net #0)]" },
	{ GVCP_CURIPCFG_0, "[Current IP Configuration (Net #0)]" },
	{ GVCP_CURRENT_IP_ADDRESS_0, "[Current IP Address (Net #0)]" },
	{ GVCP_CURRENT_SUBNET_MASK_0, "[Current Subnet Mask (Net #0)]" },
	{ GVCP_CURRENT_DEFAULT_GATEWAY_0, "[Current Default Gateway (Net #0)]" },
	{ GVCP_MANUFACTURER_NAME, "[Manufacturer Name]" },
	{ GVCP_MODEL_NAME, "[Model Name]" },
	{ GVCP_DEVICE_VERSION, "[Device Version]" },
	{ GVCP_MANUFACTURER_INFO, "[Manufacturer Specific Information]" },
	{ GVCP_SERIAL_NUMBER, "[Serial Number]" },
	{ GVCP_USER_DEFINED_NAME, "[User-defined Name]" },
	{ GVCP_FIRST_URL, "[First Choice of URL for XML device description file]" },
	{ GVCP_SECOND_URL, "[Second Choice of URL for XML device description file]" },
	{ GVCP_NUMBER_OF_NETWORK_INTERFACES, "[Number of network interfaces]" },
	{ GVCP_PERSISTENT_IP_ADDRESS_0, "[Persistent IP address (Net #0)]" },
	{ GVCP_PERSISTENT_SUBNET_MASK_0, "[Persistent subnet mask (Net #0)]" },
	{ GVCP_PERSISTENT_DEFAULT_GATEWAY_0, "[Persistent default gateway (Net# 0)]" },
	{ GVCP_LINK_SPEED_0, "[Link Speed (Net #0)]" },
	{ GVCP_DEVICE_MAC_HIGH_1, "[Device MAC address High (Net #1)]" },
	{ GVCP_DEVICE_MAC_LOW_1, "[Device MAC address Low (Net #1)]" },
	{ GVCP_SUPPORTED_IP_CONFIGURATION_1, "[Supported IP Configuration (Net #1)]" },
	{ GVCP_CURIPCFG_1, "[Current IP Configuration (Net #1)]" },
	{ GVCP_CURRENT_IP_ADDRESS_1, "[Current IP Address (Net #1)]" },
	{ GVCP_CURRENT_SUBNET_MASK_1, "[Current Subnet Mask (Net #1)]" },
	{ GVCP_CURRENT_DEFAULT_GATEWAY_1, "[Current Default Gateway (Net #1)]" },
	{ GVCP_PERSISTENT_IP_ADDRESS_1, "[Persistent IP address (Net #1)]" },
	{ GVCP_PERSISTENT_SUBNET_MASK_1, "[Persistent subnet mask (Net#1)]" },
	{ GVCP_PERSISTENT_DEFAULT_GATEWAY_1, "[Persistent default gateway (Net #1)]" },
	{ GVCP_LINK_SPEED_1, "[Link Speed (Net #1)]" },
	{ GVCP_DEVICE_MAC_HIGH_2, "[Device MAC address High (Net #2)]" },
	{ GVCP_DEVICE_MAC_LOW_2, "[Device MAC address Low (Net #2)]" },
	{ GVCP_SUPPORTED_IP_CONFIGURATION_2, "[Supported IP Configuration (Net #2)]" },
	{ GVCP_CURIPCFG_2, "[Current IP Configuration (Net #2)]" },
	{ GVCP_CURRENT_IP_ADDRESS_2, "[Current IP Address (Net #2)]" },
	{ GVCP_CURRENT_SUBNET_MASK_2, "[Current Subnet Mask (Net #2)]" },
	{ GVCP_CURRENT_DEFAULT_GATEWAY_2, "[Current Default Gateway (Net #2)]" },
	{ GVCP_PERSISTENT_IP_ADDRESS_2, "[Persistent IP address (Net #2)]" },
	{ GVCP_PERSISTENT_SUBNET_MASK_2, "[Persistent subnet mask (Net #2)]" },
	{ GVCP_PERSISTENT_DEFAULT_GATEWAY_2, "[Persistent default gateway (Net #2)]" },
	{ GVCP_LINK_SPEED_2, "[Link Speed (Net #2)]" },
	{ GVCP_DEVICE_MAC_HIGH_3, "[Device MAC address High (Net #3)]" },
	{ GVCP_DEVICE_MAC_LOW_3, "[Device MAC address Low (Net #3)]" },
	{ GVCP_SUPPORTED_IP_CONFIGURATION_3, "[Supported IP Configuration (Net #3)]" },
	{ GVCP_CURIPCFG_3, "[Current IP Configuration (Net #3)]" },
	{ GVCP_CURRENT_IP_ADDRESS_3, "[Current IP Address (Net #3)]" },
	{ GVCP_CURRENT_SUBNET_MASK_3, "[Current Subnet Mask (Net #3)]" },
	{ GVCP_CURRENT_DEFAULT_GATEWAY_3, "[Current Default Gateway (Net #3)]" },
	{ GVCP_PERSISTENT_IP_ADDRESS_3, "[Persistent IP address (Net #3)]" },
	{ GVCP_PERSISTENT_SUBNET_MASK_3, "[Persistent subnet mask (Net #3)]" },
	{ GVCP_PERSISTENT_DEFAULT_GATEWAY_3, "[Persistent default gateway (Net #3)]" },
	{ GVCP_LINK_SPEED_3, "[Link Speed (Net #3)]" },
	{ GVCP_NUMBER_OF_MESSAGE_CHANNELS, "[Number of Message Channels]" },
	{ GVCP_NUMBER_OF_STREAM_CHANNELS, "[Number of Stream Channels]" },
	{ GVCP_NUMBER_OF_ACTION_SIGNALS, "[Number of Action Signals]" },
	{ GVCP_ACTION_DEVICE_KEY, "[Action Device Key]" },
	{ GVCP_SC_CAPS, "[Stream channels Capability]" },
	{ GVCP_MESSAGE_CHANNEL_CAPS, "[Message channel Capability]" },
	{ GVCP_CAPABILITY, "[GVCP Capability]" },
	{ GVCP_HEARTBEAT_TIMEOUT, "[Heartbeat timeout]" },
	{ GVCP_TIMESTAMP_TICK_FREQUENCY_HIGH, "[Timestamp tick frequency - High]" },
	{ GVCP_TIMESTAMP_TICK_FREQUENCY_LOW, "[Timestamp tick frequency - Low]" },
	{ GVCP_TIMESTAMP_CONTROL, "[Timestamp control]" },
	{ GVCP_TIMESTAMP_VALUE_HIGH, "[Timestamp value (latched) - High]" },
	{ GVCP_TIMESTAMP_VALUE_LOW, "[Timestamp value (latched) - Low]" },
	{ GVCP_DISCOVERY_ACK_DELAY, "[Discovery ACK delay]" },
	{ GVCP_CONFIGURATION, "[GVCP Configuration]" },
	{ GVCP_PENDING_TIMEOUT, "[Pending Timeout]" },
	{ GVCP_CONTROL_SWITCHOVER_KEY, "[Control switchover key]" },
	{ GVCP_GVSCP_CONFIGURATION, "[GVSP Configuration]" },
	{ GVCP_PHYSICAL_LINK_CAPABILITY, "[Physical link capability]" },
	{ GVCP_PHYSICAL_LINK_CONFIGURATION, "[Physical link configuration]" },
	{ GVCP_IEEE_1588_STATUS, "[IEEE1588 status]" },
	{ GVCP_SCHEDULED_ACTION_COMMAND_QUEUE_SIZE, "[Scheduled action command queue size]" },
	{ GVCP_IEEE_1588_EXTENDED_CAPABILITY, "[IEEE1588 extended capabilities]" },
	{ GVCP_IEEE_1588_SUPPORTED_PROFILES, "[IEEE1588 supported profiles]" },
	{ GVCP_IEEE_1588_SELECTED_PROFILE, "[IEEE1588 selected profile]" },
	{ GVCP_CCP, "[CCP (Control Channel Privilege)]" },
	{ GVCP_PRIMARY_APPLICATION_PORT, "[Primary Application Port]" },
	{ GVCP_PRIMARY_APPLICATION_IP_ADDRESS, "[Primary Application IP address]" },
	{ GVCP_MC_DESTINATION_PORT, "[MCP (Message Channel Port)]" },
	{ GVCP_MC_DESTINATION_ADDRESS, "[MCDA (Message Channel Destination Address)]" },
	{ GVCP_MC_TIMEOUT, "[MCTT (Message Channel Transmission Timeout in ms)]" },
	{ GVCP_MC_RETRY_COUNT, "[MCRC (Message Channel Retry Count)]" },
	{ GVCP_MC_SOURCE_PORT, "[MCSP (Message Channel Source Port)]" },
	{ GVCP_MC_CONFIGURATION, "[MCCFG (Message Channel Configuration)]" }, /* GEV 2.2 */
	{ GVCP_SC_DESTINATION_PORT(0), "[SCP0 (Stream Channel #0 Port)]" },
	{ GVCP_SC_PACKET_SIZE(0), "[SCPS0 (Stream Channel #0 Packet Size)]" },
	{ GVCP_SC_PACKET_DELAY(0), "[SCPD0 (Stream Channel #0 Packet Delay)]" },
	{ GVCP_SC_DESTINATION_ADDRESS(0), "[SCDA0 (Stream Channel #0 Destination Address)]" },
	{ GVCP_SC_SOURCE_PORT(0), "[SCSP0 (Stream Channel #0 Source Port)]" },
	{ GVCP_SC_CAPABILITY(0), "[SCC0 (Stream Channel #0 Capability)]" },
	{ GVCP_SC_CONFIGURATION(0), "[SCCONF0 (Stream Channel #0 Configuration)]" },
	{ GVCP_SC_ZONE(0), "[SCZ0 (Stream Channel Zone #0)]" },
	{ GVCP_SC_ZONE_DIRECTION(0), "[SCZD0 (Stream Channel Zone Direction #0)]" },
	{ GVCP_SC_MAX_PACKET_COUNT(0), "[SCMPC0 (Stream Channel Max Packet Count #0)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_HIGH(0), "[SCMBSL0 (Stream Channel Max Block Size (High) #0)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_LOW(0), "[SCMBSH0 (Stream Channel Max Block Size (Low) #0)]" },
	{ GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(0), "SCEBA0 (Stream Channel Extended Bootstrap Address #0)]" },
	{ GVCP_SC_DESTINATION_PORT(1), "[SCP1 (Stream Channel #1 Port)]" },
	{ GVCP_SC_PACKET_SIZE(1), "[SCPS1 (Stream Channel #1 Packet Size)]" },
	{ GVCP_SC_PACKET_DELAY(1), "[SCPD1 (Stream Channel #1 Packet Delay)]" },
	{ GVCP_SC_DESTINATION_ADDRESS(1), "[SCDA1 (Stream Channel #1 Destination Address)]" },
	{ GVCP_SC_SOURCE_PORT(1), "[SCSP1 (Stream Channel #1 Source Port)]" },
	{ GVCP_SC_CAPABILITY(1), "[SCC1 (Stream Channel #1 Capability)]" },
	{ GVCP_SC_CONFIGURATION(1), "[SCCONF1 (Stream Channel #1 Configuration)]" },
	{ GVCP_SC_ZONE(1), "[SCZ1 (Stream Channel Zone #1)]" },
	{ GVCP_SC_ZONE_DIRECTION(1), "[SCZD1 (Stream Channel Zone Direction #1)]" },
	{ GVCP_SC_MAX_PACKET_COUNT(1), "[SCMPC1 (Stream Channel Max Packet Count #1)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_HIGH(1), "[SCMBSL1 (Stream Channel Max Block Size (High) #1)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_LOW(1), "[SCMBSH1 (Stream Channel Max Block Size (Low) #1)]" },
	{ GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(1), "SCEBA1 (Stream Channel Extended Bootstrap Address #1)]" },
	{ GVCP_SC_DESTINATION_PORT(2), "[SCP2 (Stream Channel #2 Port)]" },
	{ GVCP_SC_PACKET_SIZE(2), "[SCPS2 (Stream Channel #2 Packet Size)]" },
	{ GVCP_SC_PACKET_DELAY(2), "[SCPD2 (Stream Channel #2 Packet Delay)]" },
	{ GVCP_SC_DESTINATION_ADDRESS(2), "[SCDA2 (Stream Channel #2 Destination Address)]" },
	{ GVCP_SC_SOURCE_PORT(2), "[SCSP2 (Stream Channel #2 Source Port)]" },
	{ GVCP_SC_CAPABILITY(2), "[SCC2 (Stream Channel #2 Capability)]" },
	{ GVCP_SC_CONFIGURATION(2), "[SCCONF2 (Stream Channel #2 Configuration)]" },
	{ GVCP_SC_ZONE(2), "[SCZ2 (Stream Channel Zone #2)]" },
	{ GVCP_SC_ZONE_DIRECTION(2), "[SCZD2 (Stream Channel Zone Direction #2)]" },
	{ GVCP_SC_MAX_PACKET_COUNT(2), "[SCMPC2 (Stream Channel Max Packet Count #2)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_HIGH(2), "[SCMBSL2 (Stream Channel Max Block Size (High) #2)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_LOW(2), "[SCMBSH2 (Stream Channel Max Block Size (Low) #2)]" },
	{ GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(2), "SCEBA2 (Stream Channel Extended Bootstrap Address #2)]" },
	{ GVCP_SC_DESTINATION_PORT(3), "[SCP3 (Stream Channel #3 Port)]" },
	{ GVCP_SC_PACKET_SIZE(3), "[SCPS3 (Stream Channel #3 Packet Size)]" },
	{ GVCP_SC_PACKET_DELAY(3), "[SCPD3 (Stream Channel #3 Packet Delay)]" },
	{ GVCP_SC_DESTINATION_ADDRESS(3), "[SCDA3 (Stream Channel #3 Destination Address)]" },
	{ GVCP_SC_SOURCE_PORT(3), "[SCSP3 (Stream Channel #3 Source Port)]" },
	{ GVCP_SC_CAPABILITY(3), "[SCC3 (Stream Channel #3 Capability)]" },
	{ GVCP_SC_CONFIGURATION(3), "[SCCONF3 (Stream Channel #3 Configuration)]" },
	{ GVCP_SC_ZONE(3), "[SCZ3 (Stream Channel Zone #3)]" },
	{ GVCP_SC_ZONE_DIRECTION(3), "[SCZD3 (Stream Channel Zone Direction #3)]" },
	{ GVCP_SC_MAX_PACKET_COUNT(3), "[SCMPC3 (Stream Channel Max Packet Count #3)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_HIGH(3), "[SCMBSL3 (Stream Channel Max Block Size (High) #3)]" },
	{ GVCP_SC_MAX_BLOCK_SIZE_LOW(3), "[SCMBSH3 (Stream Channel Max Block Size (Low) #3)]" },
	{ GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(3), "SCEBA3 (Stream Channel Extended Bootstrap Address #3)]" },
	{ GVCP_MANIFEST_TABLE, "[Manifest Table]" },
	{ GVCP_ACTION_GROUP_KEY(0), "[Action Group Key #0]" },
	{ GVCP_ACTION_GROUP_MASK(0), "[Action Group Mask #0]" },
	{ GVCP_ACTION_GROUP_KEY(1), "[Action Group Key #1]" },
	{ GVCP_ACTION_GROUP_MASK(1), "[Action Group Mask #1]" },
	{ GVCP_ACTION_GROUP_KEY(2), "[Action Group Key #2]" },
	{ GVCP_ACTION_GROUP_MASK(2), "[Action Group Mask #2]" },
	{ GVCP_ACTION_GROUP_KEY(3), "[Action Group Key #3]" },
	{ GVCP_ACTION_GROUP_MASK(3), "[Action Group Mask #3]" },
	{ GVCP_ACTION_GROUP_KEY(4), "[Action Group Key #4]" },
	{ GVCP_ACTION_GROUP_MASK(4), "[Action Group Mask #4]" },
	{ GVCP_ACTION_GROUP_KEY(5), "[Action Group Key #5]" },
	{ GVCP_ACTION_GROUP_MASK(5), "[Action Group Mask #5]" },
	{ GVCP_ACTION_GROUP_KEY(6), "[Action Group Key #6]" },
	{ GVCP_ACTION_GROUP_MASK(6), "[Action Group Mask #6]" },
	{ GVCP_ACTION_GROUP_KEY(7), "[Action Group Key #7]" },
	{ GVCP_ACTION_GROUP_MASK(7), "[Action Group Mask #7]" },
	{ GVCP_ACTION_GROUP_KEY(8), "[Action Group Key #8]" },
	{ GVCP_ACTION_GROUP_MASK(8), "[Action Group Mask #8]" },
	{ GVCP_ACTION_GROUP_KEY(9), "[Action Group Key #9]" },
	{ GVCP_ACTION_GROUP_MASK(9), "[Action Group Mask #9]" },
	{ 0, NULL },
};


/*
brief Extended Register name to address mappings
*/

/* GEV 2.2 */
static const value_string extendedbootstrapregisternames[] = {
	{ GVCP_SC_GENDC_DESCRIPTOR_ADDRESS, "[SCGDAx (GenDC Descriptor Address)]" },
	{ GVCP_SC_GENDC_DESCRIPTOR_SIZE, "[SCGDSx (GenDC Descriptor Size)]" },
	{ GVCP_SC_GENDC_FLOW_MAPPING_TABLE_ADDRESS, "[SCGFTAx (GenDC Flow Mapping Table Address)]" },
	{ GVCP_SC_GENDC_FLOW_MAPPING_TABLE_SIZE, "[SCGFTSx (GenDC Flow Mapping Table Size)]" },
	{ 0, NULL },
};


/*
\brief Check is the current register access is into one of the extended stream channel registers
*/

static bool is_extended_bootstrap_address(gvcp_conv_info_t *gvcp_info, uint32_t addr, uint32_t* extended_bootstrap_address_offset)
{
	int stream_channel_count = 0;
	for (stream_channel_count = 0; stream_channel_count < GVCP_MAX_STREAM_CHANNEL_COUNT; stream_channel_count++)
	{
		if ((gvcp_info->extended_bootstrap_address[stream_channel_count] != 0) &&
			(addr >= gvcp_info->extended_bootstrap_address[stream_channel_count]) &&
			(addr <= (gvcp_info->extended_bootstrap_address[stream_channel_count] + GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS_LAST)))
		{
			if (extended_bootstrap_address_offset)
			{
				*extended_bootstrap_address_offset = gvcp_info->extended_bootstrap_address[stream_channel_count];
			}
			return true;
		}
	}
	return false;
}


/*
\brief Returns a register name based on its address
*/

static const char* get_register_name_from_address(uint32_t addr, wmem_allocator_t *scope, gvcp_conv_info_t *gvcp_info, bool* is_custom_register)
{
	const char* address_string = NULL;

	if (is_custom_register != NULL)
	{
		*is_custom_register = false;
	}

	address_string = try_val_to_str(addr, bootstrapregisternames);
	if (!address_string)
	{
		uint32_t extended_bootstrap_address_offset = 0;
		if (is_extended_bootstrap_address(gvcp_info, addr, &extended_bootstrap_address_offset))
		{
			address_string = try_val_to_str(addr - extended_bootstrap_address_offset, extendedbootstrapregisternames);
		}

		if (!address_string)
		{
			address_string = wmem_strdup_printf(scope, "[Addr:0x%08X]", addr);
			if (is_custom_register != NULL)
			{
				*is_custom_register = true;
			}
		}
	}

	return address_string;
}


/*
\brief Attempts to dissect a bootstrap register
*/

static int dissect_register(uint32_t addr, proto_tree *branch, tvbuff_t *tvb, int offset, int length)
{
	switch (addr)
	{
	case GVCP_VERSION:
		proto_tree_add_item(branch, hf_gvcp_spec_version_major, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_spec_version_minor, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_DEVICE_MODE:
		proto_tree_add_item(branch, hf_gvcp_devicemode_endianness, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_devicemode_deviceclass, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_devicemode_current_link_configuration_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_devicemode_characterset, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_DEVICE_MAC_HIGH_0:
	case GVCP_DEVICE_MAC_HIGH_1:
	case GVCP_DEVICE_MAC_HIGH_2:
	case GVCP_DEVICE_MAC_HIGH_3:
		proto_tree_add_item(branch, hf_gvcp_machigh, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_DEVICE_MAC_LOW_0:
	case GVCP_DEVICE_MAC_LOW_1:
	case GVCP_DEVICE_MAC_LOW_2:
	case GVCP_DEVICE_MAC_LOW_3:
		proto_tree_add_item(branch, hf_gvcp_maclow, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SUPPORTED_IP_CONFIGURATION_0:
	case GVCP_SUPPORTED_IP_CONFIGURATION_1:
	case GVCP_SUPPORTED_IP_CONFIGURATION_2:
	case GVCP_SUPPORTED_IP_CONFIGURATION_3:
		proto_tree_add_item(branch, hf_gvcp_ip_config_can_handle_pause_frames_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_can_generate_pause_frames_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_lla, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_dhcp, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_persistent_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CURIPCFG_0:
	case GVCP_CURIPCFG_1:
	case GVCP_CURIPCFG_2:
	case GVCP_CURIPCFG_3:
		proto_tree_add_item(branch, hf_gvcp_ip_config_can_handle_pause_frames_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_can_generate_pause_frames_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_lla, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_dhcp, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ip_config_persistent_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CURRENT_IP_ADDRESS_0:
	case GVCP_CURRENT_IP_ADDRESS_1:
	case GVCP_CURRENT_IP_ADDRESS_2:
	case GVCP_CURRENT_IP_ADDRESS_3:
		proto_tree_add_item(branch, hf_gvcp_current_IP, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CURRENT_SUBNET_MASK_0:
	case GVCP_CURRENT_SUBNET_MASK_1:
	case GVCP_CURRENT_SUBNET_MASK_2:
	case GVCP_CURRENT_SUBNET_MASK_3:
		proto_tree_add_item(branch, hf_gvcp_current_subnet_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CURRENT_DEFAULT_GATEWAY_0:
	case GVCP_CURRENT_DEFAULT_GATEWAY_1:
	case GVCP_CURRENT_DEFAULT_GATEWAY_2:
	case GVCP_CURRENT_DEFAULT_GATEWAY_3:
		proto_tree_add_item(branch, hf_gvcp_current_default_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MANUFACTURER_NAME:
		proto_tree_add_item(branch, hf_gvcp_reserved_bit, tvb, 0, length, ENC_NA); /*? */
		break;

	case GVCP_MODEL_NAME:
		proto_tree_add_item(branch, hf_gvcp_reserved_bit, tvb, 0, length, ENC_NA); /*? */
		break;

	case GVCP_DEVICE_VERSION:
		proto_tree_add_item(branch, hf_gvcp_reserved_bit, tvb, 0, length, ENC_NA); /*? */
		break;

	case GVCP_MANUFACTURER_INFO:
		proto_tree_add_item(branch, hf_gvcp_reserved_bit, tvb, 0, length, ENC_NA); /*? */
		break;

	case GVCP_SERIAL_NUMBER:
		proto_tree_add_item(branch, hf_gvcp_reserved_bit, tvb, 0, length, ENC_NA); /*? */
		break;

	case GVCP_USER_DEFINED_NAME:
		proto_tree_add_item(branch, hf_gvcp_user_defined_name, tvb, offset, 4, ENC_ASCII); /*? */
		break;

	case GVCP_FIRST_URL:
		proto_tree_add_item(branch, hf_gvcp_reserved_bit, tvb, 0, length, ENC_NA); /*? */
		break;

	case GVCP_SECOND_URL:
		proto_tree_add_item(branch, hf_gvcp_reserved_bit, tvb, 0, length, ENC_NA); /*? */
		break;

	case GVCP_NUMBER_OF_NETWORK_INTERFACES:
		proto_tree_add_item(branch, hf_gvcp_number_interfaces, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PERSISTENT_IP_ADDRESS_0:
	case GVCP_PERSISTENT_IP_ADDRESS_1:
	case GVCP_PERSISTENT_IP_ADDRESS_2:
	case GVCP_PERSISTENT_IP_ADDRESS_3:
		proto_tree_add_item(branch, hf_gvcp_persistent_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PERSISTENT_SUBNET_MASK_0:
	case GVCP_PERSISTENT_SUBNET_MASK_1:
	case GVCP_PERSISTENT_SUBNET_MASK_2:
	case GVCP_PERSISTENT_SUBNET_MASK_3:
		proto_tree_add_item(branch, hf_gvcp_persistent_subnet, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PERSISTENT_DEFAULT_GATEWAY_0:
	case GVCP_PERSISTENT_DEFAULT_GATEWAY_1:
	case GVCP_PERSISTENT_DEFAULT_GATEWAY_2:
	case GVCP_PERSISTENT_DEFAULT_GATEWAY_3:
		proto_tree_add_item(branch, hf_gvcp_persistent_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_LINK_SPEED_0:
	case GVCP_LINK_SPEED_1:
	case GVCP_LINK_SPEED_2:
	case GVCP_LINK_SPEED_3:
		proto_tree_add_item(branch, hf_gvcp_link_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_NUMBER_OF_MESSAGE_CHANNELS:
		proto_tree_add_item(branch, hf_gvcp_number_message_channels, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_NUMBER_OF_STREAM_CHANNELS:
		proto_tree_add_item(branch, hf_gvcp_number_stream_channels, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_NUMBER_OF_ACTION_SIGNALS:
		proto_tree_add_item(branch, hf_gvcp_number_action_signals, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_ACTION_DEVICE_KEY:
		proto_tree_add_item(branch, hf_gvcp_writeregcmd_data, tvb, offset, 4, ENC_BIG_ENDIAN); /*? */
		break;

	case GVCP_NUMBER_OF_ACTIVE_LINKS:
		proto_tree_add_item(branch, hf_gvcp_number_of_active_links_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_CAPS:
		proto_tree_add_item(branch, hf_gvcp_sccaps_scspx_register_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sccaps_legacy_16bit_blockid_supported_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sccaps_scmbsx_supported_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sccaps_scebax_supported_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MESSAGE_CHANNEL_CAPS:
		proto_tree_add_item(branch, hf_gvcp_mcsp_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_mccfg_supported_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_mcec_supported_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CAPABILITY:
		proto_tree_add_item(branch, hf_gvcp_capability_user_defined, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_serial_number, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_heartbeat_disable, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_link_speed, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_ccp_application_portip, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_manifest_table, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_test_data, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_discovery_ACK_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_writable_discovery_ACK_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_extended_status_code_v1_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_primary_application_switchover, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_unconditional_action_command, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_1588_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_extended_status_code_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_scheduled_action_command_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_ieee1588_extended_capabilities_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_action_command, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_pending, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_evendata, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_event, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_packetresend, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_writemem, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_capability_concatenation, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_HEARTBEAT_TIMEOUT:
		proto_tree_add_item(branch, hf_gvcp_heartbeat, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_TIMESTAMP_TICK_FREQUENCY_HIGH:
		proto_tree_add_item(branch, hf_gvcp_high_timestamp_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_TIMESTAMP_TICK_FREQUENCY_LOW:
		proto_tree_add_item(branch, hf_gvcp_low_timestamp_frequency, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_TIMESTAMP_CONTROL:
		proto_tree_add_item(branch, hf_gvcp_timestamp_control_latch, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_timestamp_control_reset, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_TIMESTAMP_VALUE_HIGH:
		proto_tree_add_item(branch, hf_gvcp_high_timestamp_value, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_TIMESTAMP_VALUE_LOW:
		proto_tree_add_item(branch, hf_gvcp_low_timestamp_value, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_DISCOVERY_ACK_DELAY:
		proto_tree_add_item(branch, hf_gvcp_discovery_ACK_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CONFIGURATION:
		proto_tree_add_item(branch, hf_gvcp_configuration_1588_enable_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_configuration_extended_status_codes_enable_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_configuration_unconditional_action_command_enable_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_configuration_extended_status_codes_enable_v1_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_configuration_pending_ack_enable, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_configuration_heartbeat_disable, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PENDING_TIMEOUT:
		proto_tree_add_item(branch, hf_gvcp_pending_timeout_max_execution, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CONTROL_SWITCHOVER_KEY:
		proto_tree_add_item(branch, hf_gvcp_control_switchover_key_register, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_GVSCP_CONFIGURATION:
		proto_tree_add_item(branch, hf_gvcp_gvsp_configuration_64bit_blockid_enable_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PHYSICAL_LINK_CAPABILITY:
		proto_tree_add_item(branch, hf_gvcp_link_dlag_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_link_slag_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_link_ml_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_link_sl_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PHYSICAL_LINK_CONFIGURATION:
		proto_tree_add_item(branch, hf_gvcp_link_dlag_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_link_slag_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_link_ml_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_link_sl_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_IEEE_1588_STATUS:
		proto_tree_add_item(branch, hf_gvcp_ieee1588_clock_status_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SCHEDULED_ACTION_COMMAND_QUEUE_SIZE:
		proto_tree_add_item(branch, hf_gvcp_scheduled_action_command_queue_size_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_IEEE_1588_EXTENDED_CAPABILITY:
		proto_tree_add_item(branch, hf_gvcp_ieee1588_profile_registers_present_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_IEEE_1588_SUPPORTED_PROFILES:
		proto_tree_add_item(branch, hf_gvcp_ieee1588_ptp_profile_supported_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_ieee1588_802dot1as_profile_supported_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_IEEE_1588_SELECTED_PROFILE:
		proto_tree_add_item(branch, hf_gvcp_selected_ieee1588_profile_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_CCP:
		proto_tree_add_item(branch, hf_gvcp_control_switchover_key, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_control_switchover_en, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_control_access, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_exclusive_access, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PRIMARY_APPLICATION_PORT:
		proto_tree_add_item(branch, hf_gvcp_primary_application_host_port, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_PRIMARY_APPLICATION_IP_ADDRESS:
		proto_tree_add_item(branch, hf_gvcp_primary_application_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MC_DESTINATION_PORT:
		proto_tree_add_item(branch, hf_gvcp_network_interface_index, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_host_port, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MC_DESTINATION_ADDRESS:
		proto_tree_add_item(branch, hf_gvcp_channel_destination_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MC_TIMEOUT:
		proto_tree_add_item(branch, hf_gvcp_message_channel_transmission_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MC_RETRY_COUNT:
		proto_tree_add_item(branch, hf_gvcp_message_channel_retry_count, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MC_SOURCE_PORT:
		proto_tree_add_item(branch, hf_gvcp_message_channel_source_port, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_MC_CONFIGURATION:
		proto_tree_add_item(branch, hf_gvcp_mcec_enabled_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_DESTINATION_PORT(0):
	case GVCP_SC_DESTINATION_PORT(1):
	case GVCP_SC_DESTINATION_PORT(2):
	case GVCP_SC_DESTINATION_PORT(3):
		proto_tree_add_item(branch, hf_gvcp_sc_direction, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_ni_index, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_host_port, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_PACKET_SIZE(0):
	case GVCP_SC_PACKET_SIZE(1):
	case GVCP_SC_PACKET_SIZE(2):
	case GVCP_SC_PACKET_SIZE(3):
		proto_tree_add_item(branch, hf_gvcp_sc_fire_test_packet, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_do_not_fragment, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_pixel_endianness, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_packet_size, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_PACKET_DELAY(0):
	case GVCP_SC_PACKET_DELAY(1):
	case GVCP_SC_PACKET_DELAY(2):
	case GVCP_SC_PACKET_DELAY(3):
		proto_tree_add_item(branch, hf_gvcp_sc_packet_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_DESTINATION_ADDRESS(0):
	case GVCP_SC_DESTINATION_ADDRESS(1):
	case GVCP_SC_DESTINATION_ADDRESS(2):
	case GVCP_SC_DESTINATION_ADDRESS(3):
		{
			uint32_t value = 0;
			value = tvb_get_letohl(tvb, offset);
			proto_tree_add_ipv4(branch, hf_gvcp_sc_destination_ip, tvb, offset, 4, value);
		}
		break;

	case GVCP_SC_SOURCE_PORT(0):
	case GVCP_SC_SOURCE_PORT(1):
	case GVCP_SC_SOURCE_PORT(2):
	case GVCP_SC_SOURCE_PORT(3):
		proto_tree_add_item(branch, hf_gvcp_sc_source_port, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_CAPABILITY(0):
	case GVCP_SC_CAPABILITY(1):
	case GVCP_SC_CAPABILITY(2):
	case GVCP_SC_CAPABILITY(3):
		proto_tree_add_item(branch, hf_gvcp_sc_big_little_endian_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_ip_reassembly_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_scmpcx_supported_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_gendc_supported_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_multi_part_supported_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_large_leader_trailer_supported_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_multizone_supported_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_packet_resend_destination_option_supported_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_packet_resend_all_in_transmission_supported_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_unconditional_streaming_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_extended_chunk_data_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_CONFIGURATION(0):
	case GVCP_SC_CONFIGURATION(1):
	case GVCP_SC_CONFIGURATION(2):
	case GVCP_SC_CONFIGURATION(3):
		proto_tree_add_item(branch, hf_gvcp_sc_gendc_enabled_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_multi_part_enabled_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_large_leader_trailer_enabled_v2_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_packet_resend_destination_option_enabled_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_packet_resend_all_in_transmission_enabled_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_unconditional_streaming_enabled, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_extended_chunk_data_enabled, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_ZONE(0):
	case GVCP_SC_ZONE(1):
	case GVCP_SC_ZONE(2):
	case GVCP_SC_ZONE(3):
		proto_tree_add_item(branch, hf_gvcp_sc_additional_zones_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_ZONE_DIRECTION(0):
	case GVCP_SC_ZONE_DIRECTION(1):
	case GVCP_SC_ZONE_DIRECTION(2):
	case GVCP_SC_ZONE_DIRECTION(3):
		proto_tree_add_item(branch, hf_gvcp_sc_zone0_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone1_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone2_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone3_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone4_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone5_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone6_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone7_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone8_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone9_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone10_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone11_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone12_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone13_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone14_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone15_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone16_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone17_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone18_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone19_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone20_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone21_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone22_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone23_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone24_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone25_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone26_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone27_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone28_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone29_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone30_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(branch, hf_gvcp_sc_zone31_direction_v2_0, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_MAX_PACKET_COUNT(0):
	case GVCP_SC_MAX_PACKET_COUNT(1):
	case GVCP_SC_MAX_PACKET_COUNT(2):
	case GVCP_SC_MAX_PACKET_COUNT(3):
		proto_tree_add_item(branch, hf_gvcp_sc_max_packet_count_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_MAX_BLOCK_SIZE_HIGH(0):
	case GVCP_SC_MAX_BLOCK_SIZE_HIGH(1):
	case GVCP_SC_MAX_BLOCK_SIZE_HIGH(2):
	case GVCP_SC_MAX_BLOCK_SIZE_HIGH(3):
		proto_tree_add_item(branch, hf_gvcp_sc_max_block_size_high_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_MAX_BLOCK_SIZE_LOW(0):
	case GVCP_SC_MAX_BLOCK_SIZE_LOW(1):
	case GVCP_SC_MAX_BLOCK_SIZE_LOW(2):
	case GVCP_SC_MAX_BLOCK_SIZE_LOW(3):
		proto_tree_add_item(branch, hf_gvcp_sc_max_block_size_low_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(0):
	case GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(1):
	case GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(2):
	case GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(3):
		proto_tree_add_item(branch, hf_gvcp_sc_extended_registers_address_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);

		break;

	case GVCP_MANIFEST_TABLE:
		proto_tree_add_item(branch, hf_gvcp_manifest_table, tvb, 0, length, ENC_NA);
		break;

	case GVCP_ACTION_GROUP_KEY(0):
	case GVCP_ACTION_GROUP_KEY(1):
	case GVCP_ACTION_GROUP_KEY(2):
	case GVCP_ACTION_GROUP_KEY(3):
	case GVCP_ACTION_GROUP_KEY(4):
	case GVCP_ACTION_GROUP_KEY(5):
	case GVCP_ACTION_GROUP_KEY(6):
	case GVCP_ACTION_GROUP_KEY(7):
	case GVCP_ACTION_GROUP_KEY(8):
	case GVCP_ACTION_GROUP_KEY(9):
		proto_tree_add_item(branch, hf_gvcp_action_group_key, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	case GVCP_ACTION_GROUP_MASK(0):
	case GVCP_ACTION_GROUP_MASK(1):
	case GVCP_ACTION_GROUP_MASK(2):
	case GVCP_ACTION_GROUP_MASK(3):
	case GVCP_ACTION_GROUP_MASK(4):
	case GVCP_ACTION_GROUP_MASK(5):
	case GVCP_ACTION_GROUP_MASK(6):
	case GVCP_ACTION_GROUP_MASK(7):
	case GVCP_ACTION_GROUP_MASK(8):
	case GVCP_ACTION_GROUP_MASK(9):
		proto_tree_add_item(branch, hf_gvcp_action_group_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	default:
		return 0;
	}

	return 1;
}

/*
\brief Attempts to dissect an extended bootstrap register
*/

static int dissect_extended_bootstrap_register(uint32_t addr, proto_tree *branch, tvbuff_t *tvb, int offset, int length _U_)
{
	switch (addr)
	{
	case GVCP_SC_GENDC_DESCRIPTOR_ADDRESS:
		proto_tree_add_item(branch, hf_gvcp_sc_gendc_descriptor_address_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case GVCP_SC_GENDC_DESCRIPTOR_SIZE:
		proto_tree_add_item(branch, hf_gvcp_sc_gendc_descriptor_size_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case GVCP_SC_GENDC_FLOW_MAPPING_TABLE_ADDRESS:
		proto_tree_add_item(branch, hf_gvcp_sc_gendc_flow_mapping_table_address_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case GVCP_SC_GENDC_FLOW_MAPPING_TABLE_SIZE:
		proto_tree_add_item(branch, hf_gvcp_sc_gendc_flow_mapping_table_size_v2_2, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;

	default:
		return 0;
	}

	return 1;
}


/* Attempts to dissect a bootstrap register (readmem context) */
static int dissect_register_data(uint32_t addr, proto_tree *branch, tvbuff_t *tvb, int offset, int length)
{
	switch (addr)
	{
	case GVCP_MANUFACTURER_NAME:
		if (length == 32)
		{
			proto_tree_add_item(branch, hf_gvcp_manufacturer_name, tvb, offset, -1, ENC_ASCII);
		}
		break;

	case GVCP_MODEL_NAME:
		if (length == 32)
		{
			proto_tree_add_item(branch, hf_gvcp_model_name, tvb, offset, -1, ENC_ASCII);
		}
		break;

	case GVCP_DEVICE_VERSION:
		if (length == 32)
		{
			proto_tree_add_item(branch, hf_gvcp_device_version, tvb, offset, -1, ENC_ASCII);
		}
		break;

	case GVCP_MANUFACTURER_INFO:
		if (length == 48)
		{
			proto_tree_add_item(branch, hf_gvcp_manufacturer_specific_info, tvb, offset, -1, ENC_ASCII);
		}
		break;

	case GVCP_SERIAL_NUMBER:
		if (length == 16)
		{
			proto_tree_add_item(branch, hf_gvcp_serial_number, tvb, offset, -1, ENC_ASCII);
		}
		break;

	case GVCP_USER_DEFINED_NAME:
		if (length == 16)
		{
			proto_tree_add_item(branch, hf_gvcp_user_defined_name, tvb, offset, -1, ENC_ASCII);
		}
		break;

	case GVCP_FIRST_URL:
		if (length == 512)
		{
			proto_tree_add_item(branch, hf_gvcp_first_xml_device_description_file, tvb, offset, -1, ENC_ASCII);
		}
		break;

	case GVCP_SECOND_URL:
		if (length == 512)
		{
			proto_tree_add_item(branch, hf_gvcp_second_xml_device_description_file, tvb, offset, -1, ENC_ASCII);
		}
		break;

	default:
		return 0;
	}

	return 1;
}


/*
\brief DISSECT: Force IP command
*/

static void dissect_forceip_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo _U_, int startoffset, int length)
{
	const int mac_offset = startoffset + 2;
	const int ip_offset = startoffset + 20;
	const int mask_offset = startoffset + 36;
	const int gateway_offset = startoffset + 52;

	if (gvcp_telegram_tree != NULL)
	{
		gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, startoffset, length,
										ett_gvcp_payload_cmd, NULL, "FORCEIP_CMD Options");

		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_forceip_mac_address, tvb, mac_offset, 6, ENC_NA);
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_forceip_static_IP, tvb, ip_offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_forceip_static_subnet_mask, tvb, mask_offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_forceip_static_default_gateway, tvb, gateway_offset, 4, ENC_BIG_ENDIAN);
	}
}


/*
\brief DISSECT: Packet resend command
*/

static void dissect_packetresend_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, int extendedblockid)
{

	uint64_t block_id = 0;
	uint32_t first_packet = 0;
	uint32_t last_packet = 0;
	int offset = startoffset;

	/* Get block ID to generate summary - supports 16 and 64 bits */
	if (extendedblockid == 0)
	{
		block_id = tvb_get_ntohs(tvb, offset + 2);
	}
	else
	{
		uint64_t highid;
		uint64_t lowid;
		highid = tvb_get_ntohl(tvb, offset + 12);
		lowid = tvb_get_ntohl(tvb, offset + 16);

		block_id = lowid | (highid << 32);
	}

	/* Get first and last packet IDs for summary - supports 24 and 32 bits */
	if (extendedblockid == 0)
	{
		/* in GEV1.2 and prior we use only 24 bit packet IDs */
		first_packet = tvb_get_ntohl(tvb, offset + 4) & 0x00FFFFFF;
		last_packet = tvb_get_ntohl(tvb, offset + 8) & 0x00FFFFFF;
	}
	else
	{
		first_packet = tvb_get_ntohl(tvb, offset + 4);
		last_packet = tvb_get_ntohl(tvb, offset + 8);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, "Block %" PRIu64 ", Packets %d->%d", (int64_t)block_id, first_packet, last_packet);

	if (gvcp_telegram_tree != NULL)
	{
		/* Command header/tree */
		gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, startoffset, length,
												ett_gvcp_payload_cmd, NULL, "PACKETRESEND_CMD Values");

		/* Stream channel */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_resendcmd_stream_channel_index, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* First, last packet IDs - supports 24 and 32 bits */
		if (extendedblockid == 0)
		{
			/* Block ID (16 bits) only if extended block ID disabled */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_resendcmd_block_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
			/* in GEV1.2 and prior we use only 24 bit packet IDs */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_resendcmd_first_packet_id, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_resendcmd_last_packet_id, tvb, offset + 9, 3, ENC_BIG_ENDIAN);
		}
		else
		{
			/* Extended block ID (64 bits) only if enabled (from GVCP header flags) */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_resendcmd_extended_block_id_v2_0, tvb, offset + 12, 8, ENC_BIG_ENDIAN);
			/* Extended packed ID (32 bits) only if enabled */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_resendcmd_extended_first_packet_id_v2_0, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_resendcmd_extended_last_packet_id_v2_0, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
		}
	}
}


/*
\brief DISSECT: Read register command
*/

static void dissect_readreg_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, gvcp_conv_info_t *gvcp_info, gvcp_transaction_t* gvcp_trans)
{
	proto_item *item = NULL;
	uint32_t addr = 0;
	const char* address_string = NULL;
	bool is_custom_register = false;
	int offset = startoffset;
	int i;
	int num_registers = length / 4;

	addr = tvb_get_ntohl(tvb, offset);
	address_string = get_register_name_from_address(addr, pinfo->pool, gvcp_info, &is_custom_register);

	if (num_registers > 1)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "[Multiple Register Read Command]");
	}
	else
	{
		col_append_str(pinfo->cinfo, COL_INFO, address_string);
	}

	if (!pinfo->fd->visited)
	{
		gvcp_trans->addr_list = wmem_array_new(wmem_file_scope(), sizeof(uint32_t));
	}

	/* Subtree Initialization for Payload Data: READREG_CMD */
	if (gvcp_telegram_tree != NULL)
	{
		if (num_registers > 1)
		{
			gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, startoffset, length,
												ett_gvcp_payload_cmd, &item, "READREG_CMD Address List");
		}
	}

	for (i = 0; i < num_registers; i++)
	{
		/* For block read register request, address gets re-initialized here in the for loop */
		addr = tvb_get_ntohl(tvb, offset);

		if (gvcp_trans && (!pinfo->fd->visited))
		{
			wmem_array_append_one(gvcp_trans->addr_list, addr);
		}

		if (gvcp_telegram_tree != NULL)
		{
			if (try_val_to_str(addr, bootstrapregisternames) != NULL)
			{
				/* Use known bootstrap register */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_readregcmd_bootstrap_register, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			else
			{
				uint32_t extended_bootstrap_address_offset = 0;
				if (is_extended_bootstrap_address(gvcp_info, addr, &extended_bootstrap_address_offset))
				{
					dissect_extended_bootstrap_register(addr - extended_bootstrap_address_offset, gvcp_telegram_tree, tvb, offset, 4);
				}
				else
				{
					/* Insert data as generic register */
					item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_custom_register_addr, tvb, offset, 4, ENC_BIG_ENDIAN);

					/* Use generic register name */
					proto_item_append_text(item, " [Unknown Register]");
				}
			}
		}
		offset +=4;
	}
}


/*
\brief DISSECT: Write register command
*/

static void dissect_writereg_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, gvcp_conv_info_t *gvcp_info, gvcp_transaction_t* gvcp_trans)
{
	int offset = startoffset;
	int i;
	proto_item *item = NULL;
	uint32_t addr = 0;
	uint32_t value = 0;
	const char *address_string = NULL;
	bool is_custom_register = false;
	int num_registers = length / 8; /* divide by 8 because we are counting register-value pairs */
	proto_tree *subtree = NULL;

	if (gvcp_trans)
	{
		gvcp_trans->addr_count = num_registers;
	}

	addr = tvb_get_ntohl(tvb, offset);    /* first register address to be read from WRITEREG_CMD */
	value = tvb_get_ntohl(tvb, offset+4);
	address_string = get_register_name_from_address(addr, pinfo->pool, gvcp_info, &is_custom_register);

	/* Automatically learn stream port. Dissect as external GVSP. */
	if ((addr == GVCP_SC_DESTINATION_PORT(0)) ||
		(addr == GVCP_SC_DESTINATION_PORT(1)) ||
		(addr == GVCP_SC_DESTINATION_PORT(2)) ||
		(addr == GVCP_SC_DESTINATION_PORT(3)))
	{
		/* For now we simply (always) add ports. Maybe we should remove when the dissector gets unloaded? */
		dissector_add_uint("udp.port", value, gvsp_handle);
	}

	/* Automatically learn messaging channel port. Dissect as GVCP. */
	if (addr == GVCP_MC_DESTINATION_PORT)
	{
		/* XXX For now we simply (always) add ports. Maybe we should remove when the dissector gets unloaded? */
		dissector_add_uint("udp.port", value, gvcp_handle);
	}

	if (num_registers > 1)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "[Multiple Register Write Command]");
	}
	else
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s Value=0x%08X", address_string, value);
	}

	if (gvcp_telegram_tree != NULL)
	{
		if (num_registers > 1)
		{
			gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, startoffset, length,
									ett_gvcp_payload_cmd, &item, "WRITEREG_CMD Address List");
		}

		for (i = 0; i < num_registers; i++)
		{
			/* For block write register request, address gets re-initialized here in the for loop */
			addr = tvb_get_ntohl(tvb, offset);

			if (try_val_to_str(addr, bootstrapregisternames) != NULL)
			{
				/* Read the WRITEREG_CMD requested register address */
				item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_writeregcmd_bootstrap_register, tvb, offset, 4, ENC_BIG_ENDIAN);
				subtree = proto_item_add_subtree(item, ett_gvcp_payload_cmd_subtree);

				/* Skip 32bit to dissect the value to be written to the specified address */
				offset += 4;

				/* Read the value to be written to the specified register address */
				dissect_register(addr, subtree, tvb, offset, 4);
			}
			else
			{
				uint32_t extended_bootstrap_address_offset = 0;
				if (is_extended_bootstrap_address(gvcp_info, addr, &extended_bootstrap_address_offset))
				{
					/* Read the WRITEREG_CMD requested register address */
					item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_writeregcmd_extended_bootstrap_register, tvb, offset, 4, ENC_BIG_ENDIAN);
					subtree = proto_item_add_subtree(item, ett_gvcp_payload_cmd_subtree);

					/* Skip 32bit to dissect the value to be written to the specified address */
					offset += 4;

					/* Read the value to be written to the specified register address */
					dissect_extended_bootstrap_register(addr - extended_bootstrap_address_offset, subtree, tvb, offset, 4);
				}
				else
				{
					proto_tree* temp_tree = NULL;

					item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_custom_register_addr, tvb, offset, 4, ENC_BIG_ENDIAN);

					offset += 4;
					temp_tree = proto_item_add_subtree(item, ett_gvcp_payload_cmd_subtree);
					proto_tree_add_item(temp_tree, hf_gvcp_custom_register_value, tvb, offset, 4, ENC_BIG_ENDIAN);
				}
			}
			offset += 4;
		}
	}
}


/*
\brief DISSECT: Read memory command
*/

static void dissect_readmem_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, gvcp_conv_info_t *gvcp_info)
{
	uint32_t addr = 0;
	uint16_t count = 0;
	int offset = startoffset;

	addr = tvb_get_ntohl(tvb, offset);
	count = tvb_get_ntohs(tvb, offset + 6);    /* Number of bytes to read from memory */

	col_append_fstr(pinfo->cinfo, COL_INFO, " (0x%08X (%d) bytes)", addr, count);

	if (gvcp_telegram_tree != NULL)
	{
		proto_item *item = NULL;

		if (try_val_to_str(addr, bootstrapregisternames) != NULL)
		{
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_readmemcmd_bootstrap_register, tvb, offset, 4, ENC_BIG_ENDIAN);
		}
		else
		{
			uint32_t extended_bootstrap_address_offset = 0;
			if (is_extended_bootstrap_address(gvcp_info, addr, &extended_bootstrap_address_offset))
			{
				dissect_extended_bootstrap_register(addr - extended_bootstrap_address_offset, gvcp_telegram_tree, tvb, offset, 4);
			}
			else
			{
				item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_custom_memory_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				proto_item_append_text(item, " [Unknown Register]");
			}
		}
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_readmemcmd_count, tvb, (offset + 6), 2, ENC_BIG_ENDIAN);
	}
}


/*
\brief DISSECT: Write memory command
*/

static void dissect_writemem_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, gvcp_conv_info_t *gvcp_info, gvcp_transaction_t* gvcp_trans)
{
	const char* address_string = NULL;
	bool is_custom_register = false;
	uint32_t addr = 0;

	addr = tvb_get_ntohl(tvb, startoffset);
	address_string = get_register_name_from_address(addr, pinfo->pool, gvcp_info, &is_custom_register);

	/* fill in Info column in Wireshark GUI */
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s: %d bytes", address_string, (length - 4));

	if (gvcp_trans && (!pinfo->fd->visited))
	{
		gvcp_trans->addr_list = wmem_array_new(wmem_file_scope(), sizeof(uint32_t));
		wmem_array_append_one(gvcp_trans->addr_list, addr);
	}

	if (gvcp_telegram_tree != NULL)
	{
		unsigned offset;
		unsigned byte_count;
		offset = startoffset + 4;
		byte_count = (length - 4);

		if (gvcp_trans && (gvcp_trans->rep_frame))
		{
			proto_item *item = NULL;
			item = proto_tree_add_uint(gvcp_telegram_tree, hf_gvcp_response_in, tvb, 0, 0, gvcp_trans->rep_frame);
			proto_item_set_generated(item);
		}

		if (try_val_to_str(addr, bootstrapregisternames) != NULL)
		{
			dissect_register_data(addr, gvcp_telegram_tree, tvb, offset, byte_count);
		}
		else
		{
			uint32_t extended_bootstrap_address_offset = 0;
			if (is_extended_bootstrap_address(gvcp_info, addr, &extended_bootstrap_address_offset))
			{
				dissect_extended_bootstrap_register(addr - extended_bootstrap_address_offset, gvcp_telegram_tree, tvb, offset, byte_count);
			}
			else
			{
				/* Generic, unknown value */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_writememcmd_data, tvb, offset, byte_count, ENC_NA);
			}
		}
	}
}


/*
\brief DISSECT: Event command
*/

static void dissect_event_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, int extendedblockids)
{
	int32_t eventid;
	int offset;
	offset = startoffset;

	/* Get event ID */
	eventid = tvb_get_ntohs(tvb, offset + 2);

	/* fill in Info column in Wireshark GUI */
	col_append_fstr(pinfo->cinfo, COL_INFO, "[ID: 0x%04X]", eventid);

	if (gvcp_telegram_tree != NULL)
	{
		int i;
		int event_count = 0;

		/* Compute event count based on data length */
		if (extendedblockids == 0)
		{
			/* No enhanced block id */
			event_count = length / 16;
		}
		else
		{
			/* Enhanced block id adds */
			event_count = length / 24;
		}

		if (event_count > 1)
		{
			gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, offset, length,
												ett_gvcp_payload_cmd, NULL, "EVENT_CMD Event List");
		}


		for (i = 0; i < event_count; i++)
		{
			offset += 2;

			/* Get event ID */
			eventid = tvb_get_ntohs(tvb, offset);

			/* Use range to determine type of event */
			if ((eventid >= 0x0000) && (eventid <= 0x8000))
			{
				/* Standard ID */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			}
			else if ((eventid >= 0x8001) && (eventid <= 0x8FFF))
			{
				/* Error */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_error_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			}
			else if ((eventid >= 0x9000) && (eventid <= 0xFFFF))
			{
				/* Device specific */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_device_specific_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			}
			offset += 2;

			/* Stream channel (possibly) associated with event */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_stream_channel_index, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			if (extendedblockids == 0)
			{
				/* Block id (16 bit) associated with event */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_block_id, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
			else
			{
				offset += 2;
				/* Block id (64 bit) only if reported by gvcp flag */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_block_id_64bit_v2_0, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
			}

			/* Timestamp (64 bit) associated with event */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
		}
	}
}


/*
\brief DISSECT: Event data command
*/

static void dissect_eventdata_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int extendedblockids)
{
	int32_t eventid;
	int offset;
	int data_length = 0;
	offset = startoffset;

	while (tvb_captured_length_remaining(tvb, offset) > 12) /* At least enough bytes for and GEV 1.2 EVENTDATA_CMD with one byte of payload? */
	{
		/* Get event ID */
		eventid = tvb_get_ntohs(tvb, offset + 2);

		/* fill in Info column in Wireshark GUI */
		col_append_fstr(pinfo->cinfo, COL_INFO, "[ID: 0x%04X]", eventid);

		/* If extended ID, then we have event_size here (2.1) */
		if (extendedblockids)
		{
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_extid_length, tvb, offset, 2, ENC_BIG_ENDIAN);
			data_length = tvb_get_ntohs(tvb, offset); // We get the data length here
		}

		/* skip reserved field */
		offset += 2;

		/* Use range to determine type of event */
		if ((eventid >= 0x0000) && (eventid <= 0x8000))
		{
			/* Standard ID */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		}
		else if ((eventid >= 0x8001) && (eventid <= 0x8FFF))
		{
			/* Error */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_error_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		}
		else if ((eventid >= 0x9000) && (eventid <= 0xFFFF))
		{
			/* Device specific */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_device_specific_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		}
		offset += 2;

		/* Stream channel (possibly) associated with event */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_stream_channel_index, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		if (extendedblockids == 0)
		{
			/* Block id (16 bit) associated with event */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_block_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		else
		{
			offset += 2;
			/* Block id (64 bit) only if reported by gvcp flag */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_block_id_64bit_v2_0, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
		}

		/* Timestamp (64 bit) associated with event */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;

		if (extendedblockids)
		{
			if (data_length > 24)
			{
				/* Data */
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_data, tvb, offset, data_length - 24, ENC_NA);
				offset += data_length - 24;
			}
		}
		else
		{
			/* Data */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_eventcmd_data, tvb, offset, -1, ENC_NA);
			return;
		}
	}
}


/*
\brief DISSECT: Action command
*/

static void dissect_action_cmd(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo _U_, int startoffset, int scheduledactioncommand)
{
	if (gvcp_telegram_tree != NULL)
	{
		int offset;
		offset = startoffset;

		/* Device key */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_actioncmd_device_key, tvb, offset, 4, ENC_BIG_ENDIAN);

		/* Group key */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_actioncmd_group_key, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

		/* Group mask */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_actioncmd_group_mask, tvb, offset + 8, 4, ENC_BIG_ENDIAN);

		if (scheduledactioncommand != 0)
		{
			/* 64 bits timestamp (optional) if gvcp header flag is set */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_actioncmd_time_v2_0, tvb, offset + 12, 8, ENC_BIG_ENDIAN);
		}
	}
}


/*
\brief DISSECT: Discovery acknowledge
*/

static void dissect_discovery_ack(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length)
{
	proto_item *item = NULL;
	int offset;
	const uint8_t* string_manufacturer_name = NULL;
	const uint8_t* string_serial_number = NULL;
	int string_length = 0;
	proto_tree *tree = NULL;

	offset = startoffset;
	string_manufacturer_name = tvb_get_stringz_enc(pinfo->pool, tvb, 80, &string_length, ENC_ASCII);
	string_serial_number = tvb_get_stringz_enc(pinfo->pool, tvb, 224, &string_length, ENC_ASCII);

	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s, %s)",string_manufacturer_name, string_serial_number);

	if (gvcp_telegram_tree != NULL)
	{
		gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, offset, length,
										ett_gvcp_payload_cmd, NULL, "DISCOVERY_ACK Payload");

		/* Version */
		item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_spec_version, tvb, offset, 4, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_gvcp_bootstrap_fields);
		dissect_register(GVCP_VERSION, tree, tvb, offset, 4 );

		/* Device mode */
		item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_devicemodediscovery, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_gvcp_bootstrap_fields);
		dissect_register(GVCP_DEVICE_MODE, tree, tvb, offset + 4, 4 );

		/* MAC address */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_device_mac_address, tvb, offset + 10, 6, ENC_NA);

		/* Supported IP configuration */
		item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_supportedipconfig, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_gvcp_bootstrap_fields);
		dissect_register(GVCP_SUPPORTED_IP_CONFIGURATION_0, tree, tvb, offset + 16, 4);

		/* Current IP configuration */
		item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_currentipconfig, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_gvcp_bootstrap_fields);
		dissect_register(GVCP_CURIPCFG_0, tree, tvb, offset + 20, 4);

		/* Current IP address */
		dissect_register(GVCP_CURRENT_IP_ADDRESS_0, gvcp_telegram_tree, tvb, offset + 36, 4);

		/* Current subnet mask */
		dissect_register(GVCP_CURRENT_SUBNET_MASK_0, gvcp_telegram_tree, tvb, offset + 52, 4);

		/* Current default gateway */
		dissect_register(GVCP_CURRENT_DEFAULT_GATEWAY_0, gvcp_telegram_tree, tvb, offset + 68, 4);

		/* Manufacturer name */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_manufacturer_name, tvb, offset + 72, -1, ENC_ASCII);

		/* Model name */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_model_name, tvb, offset + 104, -1, ENC_ASCII);

		/* Device version */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_device_version, tvb, offset + 136, -1, ENC_ASCII);

		/* Manufacturer specific information */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_manufacturer_specific_info, tvb, offset + 168, -1, ENC_ASCII);

		/* Serial number */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_serial_number, tvb, offset + 216, -1, ENC_ASCII);

		/* User defined name */
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_user_defined_name, tvb, offset + 232, -1, ENC_ASCII);
	}
}

/*
\brief DISSECT: Read register acknowledge
*/

static void dissect_readreg_ack(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, gvcp_conv_info_t *gvcp_info, gvcp_transaction_t *gvcp_trans)
{
	unsigned i;
	bool is_custom_register = false;
	const char* address_string = NULL;
	unsigned num_registers;
	int offset;
	bool valid_trans = false;
	unsigned addr_list_size = 0;

	offset = startoffset;
	num_registers = length / 4;

	if (gvcp_trans && gvcp_trans->addr_list)
	{
		valid_trans = true;
		addr_list_size = wmem_array_get_count(gvcp_trans->addr_list);
	}

	if (num_registers > 1)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "[Multiple ReadReg Ack]");
	}
	else
	{
		if (valid_trans)
		{
			if (addr_list_size > 0)
			{
				address_string = get_register_name_from_address(*((uint32_t*)wmem_array_index(gvcp_trans->addr_list, 0)), pinfo->pool, gvcp_info, &is_custom_register);
				col_append_str(pinfo->cinfo, COL_INFO, address_string);
			}

			if (num_registers)
			{
				col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "Value=0x%08X", tvb_get_ntohl(tvb, offset));
			}
		}
	}

	if (gvcp_telegram_tree != NULL)
	{
		/* Subtree initialization for Payload Data: READREG_ACK */
		if (num_registers > 1)
		{
			gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, offset, length,
												ett_gvcp_payload_ack, NULL, "Register Value List");
		}

		for (i = 0; i < num_registers; i++)
		{
			uint32_t curr_register = 0;

			if (valid_trans && i < addr_list_size)
			{
				int stream_channel_count = 0;
				curr_register = *((uint32_t*)wmem_array_index(gvcp_trans->addr_list, i));
				address_string = get_register_name_from_address(curr_register, pinfo->pool, gvcp_info, &is_custom_register);
				for (; stream_channel_count < GVCP_MAX_STREAM_CHANNEL_COUNT; stream_channel_count++)
				{
					if (curr_register == (uint32_t)GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(stream_channel_count))
					{
						gvcp_info->extended_bootstrap_address[stream_channel_count] = tvb_get_ntohl(tvb, offset);
						break;
					}
				}

				if (!is_custom_register) /* bootstrap register */
				{
					uint32_t extended_bootstrap_address_offset = 0;
					if (is_extended_bootstrap_address(gvcp_info, curr_register, &extended_bootstrap_address_offset))
					{
						proto_tree_add_uint_format_value(gvcp_telegram_tree, hf_gvcp_readregcmd_extended_bootstrap_register, tvb, offset, 4, curr_register, "%s (0x%08X)", address_string, curr_register);
						dissect_extended_bootstrap_register(curr_register - extended_bootstrap_address_offset, gvcp_telegram_tree, tvb, offset, length);
					}
					else
					{
						proto_tree_add_uint(gvcp_telegram_tree, hf_gvcp_readregcmd_bootstrap_register, tvb, 0, 4, curr_register);
						dissect_register(curr_register, gvcp_telegram_tree, tvb, offset, length);
					}
				}
				else
				{
					proto_tree_add_uint_format_value(gvcp_telegram_tree, hf_gvcp_custom_read_register_addr, tvb, offset, 4, curr_register, "%s (0x%08X)", address_string, curr_register);
					proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_custom_read_register_value, tvb, offset, 4, ENC_BIG_ENDIAN);
				}
			}
			else
			{
				proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_custom_register_value, tvb, offset, 4, ENC_BIG_ENDIAN);
			}

			offset += 4;
		}
	}
}


/*
\brief DISSECT: Write register acknowledge
*/

static void dissect_writereg_ack(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, gvcp_transaction_t* gvcp_trans)
{
	proto_item *item = NULL;
	uint16_t ack_index = 0;

	if (gvcp_telegram_tree != NULL)
	{
		item = proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_writeregcmd_data_index, tvb, (startoffset + 2), 2, ENC_BIG_ENDIAN);
	}

	ack_index = tvb_get_ntohs(tvb, 10);

	if (gvcp_trans)
	{
		int num_registers = 0;

		num_registers = gvcp_trans->addr_count;
		if (num_registers > 1)
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "[Multiple WriteReg Ack] (%d/%d) %s ", ack_index, num_registers, (ack_index == num_registers ? "(Success)" : "(Failed)"));
		}
		else
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", (ack_index == num_registers ? "(Success)" : "(Failed)"));
		}

		if (gvcp_telegram_tree != NULL)
		{
			proto_item_append_text(item, " %s", (ack_index == num_registers ? "(Success)" : "(Failed)"));
		}
	}
	else
	{
		col_append_str(pinfo->cinfo, COL_INFO, "[Cannot find requesting packet]");
	}
}


/*
\brief DISSECT: Read memory acknowledge
*/

static void dissect_readmem_ack(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, gvcp_conv_info_t *gvcp_info)
{
	if (length > 0)
	{
		uint32_t addr = 0;
		const char *address_string = NULL;
		bool is_custom_register = false;

		addr = tvb_get_ntohl(tvb, startoffset);
		address_string = get_register_name_from_address(addr, pinfo->pool, gvcp_info, &is_custom_register);

		/* Fill in Wireshark GUI Info column */
		col_append_str(pinfo->cinfo, COL_INFO, address_string);

		if (gvcp_telegram_tree != NULL)
		{
			int stream_channel_count = 0;
			unsigned offset;
			unsigned byte_count;
			offset = startoffset + 4;
			byte_count = (length - 4);

			for (stream_channel_count = 0; stream_channel_count < GVCP_MAX_STREAM_CHANNEL_COUNT; stream_channel_count++)
			{
				if (startoffset == GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(stream_channel_count))
				{
					gvcp_info->extended_bootstrap_address[stream_channel_count] = tvb_get_ntohl(tvb, offset);
					break;
				}
			}

			/* Bootstrap register known address */
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_readmemcmd_address, tvb, startoffset, 4, ENC_BIG_ENDIAN);

			if (try_val_to_str(addr, bootstrapregisternames) != NULL)
			{
				dissect_register_data(addr, gvcp_telegram_tree, tvb, offset, byte_count);
			}
			else
			{
				uint32_t extended_bootstrap_address_offset = 0;
				if (is_extended_bootstrap_address(gvcp_info, addr, &extended_bootstrap_address_offset))
				{
					dissect_extended_bootstrap_register(addr - extended_bootstrap_address_offset, gvcp_telegram_tree, tvb, offset, byte_count);
				}
				else
				{
					/* Generic, unknown value */
					proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_readmemcmd_data_read, tvb, offset, byte_count, ENC_NA);
				}
			}
		}
	}
}


/*
\brief DISSECT: Write memory acknowledge
*/

static void dissect_writemem_ack(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo, int startoffset, int length, gvcp_conv_info_t *gvcp_info, gvcp_transaction_t* gvcp_trans)
{
	if (gvcp_trans && gvcp_trans->addr_list)
	{
		if (wmem_array_get_count(gvcp_trans->addr_list) > 0)
		{
			const char *address_string = NULL;
			address_string = get_register_name_from_address((*((uint32_t*)wmem_array_index(gvcp_trans->addr_list, 0))), pinfo->pool, gvcp_info, NULL);
			col_append_str(pinfo->cinfo, COL_INFO, address_string);
		}
	}

	if (gvcp_telegram_tree != NULL)
	{
		if (gvcp_trans && gvcp_trans->req_frame)
		{
			proto_item *item = proto_tree_add_uint(gvcp_telegram_tree, hf_gvcp_response_to, tvb, 0, 0, gvcp_trans->req_frame);
			proto_item_set_generated(item);
		}

		gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, startoffset, length,
												ett_gvcp_payload_cmd, NULL, "Payload Data: WRITEMEM_ACK");
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_writememcmd_data_index, tvb, (startoffset +2), 2, ENC_BIG_ENDIAN);
	}
}


/*
\brief DISSECT: Pending acknowledge
*/

static void dissect_pending_ack(proto_tree *gvcp_telegram_tree, tvbuff_t *tvb, packet_info *pinfo _U_, int startoffset, int length)
{
	if (gvcp_telegram_tree != NULL)
	{
		gvcp_telegram_tree = proto_tree_add_subtree(gvcp_telegram_tree, tvb, startoffset, length,
										ett_gvcp_payload_cmd, NULL, "Payload Data: PENDING_ACK");
		proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_time_to_completion, tvb, (startoffset + 2), 2, ENC_BIG_ENDIAN);
	}
}


/*
\brief Point of entry of all GVCP packet dissection
*/

static int dissect_gvcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = 0;
	proto_tree *gvcp_tree = NULL;
	proto_tree *gvcp_tree_flag = NULL;
	proto_tree *gvcp_telegram_tree = NULL;
	int data_length = 0;
	int command = -1;
	const char* command_string = NULL;
	int flags = -1;
	int extendedblockids = -1;
	int scheduledactioncommand = -1;
	int ack_code = -1;
	const char* ack_string = NULL;
	int request_id = 0;
	char key_code = 0;
	proto_item *ti = NULL;
	proto_item *item = NULL;
	conversation_t *conversation = 0;
	gvcp_conv_info_t *gvcp_info = 0;
	gvcp_transaction_t *gvcp_trans = 0;

	if (tvb_captured_length(tvb) <  GVCP_MIN_PACKET_SIZE)
	{
		return 0;
	}

	/* check for valid key/ack code */
	key_code = (char) tvb_get_guint8(tvb, offset);
	ack_code = tvb_get_ntohs(tvb, offset+2);
	ack_string = try_val_to_str(ack_code, acknowledgenames);

	if ((key_code != 0x42) && !ack_string)
	{
		return 0;
	}

	/* Set the protocol column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GVCP");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Adds "Gigabit-Ethernet Control Protocol" heading to protocol tree */
	/* We will add fields to this using the gvcp_tree pointer */
	ti = proto_tree_add_item(tree, proto_gvcp, tvb, offset, -1, ENC_NA);
	gvcp_tree = proto_item_add_subtree(ti, ett_gvcp);

	/* Is this a command message? */
	if (key_code == 0x42)
	{
		command = tvb_get_ntohs(tvb, offset+2);
		command_string = val_to_str(command, commandnames,"Unknown Command (0x%x)");

		/* Add the Command name string to the Info column */
		col_append_fstr(pinfo->cinfo, COL_INFO, "> %s ", command_string);

		gvcp_tree = proto_tree_add_subtree_format(gvcp_tree, tvb, offset, 8,
								ett_gvcp_cmd, NULL, "Command Header: %s", command_string);

		/* Add the message key code: */
		proto_tree_add_item(gvcp_tree, hf_gvcp_message_key_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		/* Add the flags */
		flags = (char) tvb_get_guint8(tvb, offset);
		item = proto_tree_add_item(gvcp_tree, hf_gvcp_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
		gvcp_tree_flag  = proto_item_add_subtree(item, ett_gvcp_flags);
		if (command == GVCP_ACTION_CMD)
		{
			proto_tree_add_item(gvcp_tree_flag, hf_gvcp_scheduledactioncommand_flag_v2_0, tvb, offset, 1, ENC_BIG_ENDIAN);
			scheduledactioncommand = (flags & 0x80);
		}
		if ((command == GVCP_EVENTDATA_CMD) ||
			(command == GVCP_EVENT_CMD) ||
			(command == GVCP_PACKETRESEND_CMD))
		{
			proto_tree_add_item(gvcp_tree_flag, hf_gvcp_64bitid_flag_v2_0, tvb, offset, 1, ENC_BIG_ENDIAN);
			flags = (char) tvb_get_guint8(tvb, offset );
			extendedblockids = (flags & 0x10);
		}
		if ((command == GVCP_DISCOVERY_CMD) ||
			(command == GVCP_FORCEIP_CMD))
		{
			proto_tree_add_item(gvcp_tree_flag, hf_gvcp_allow_broadcast_acknowledge_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		proto_tree_add_item(gvcp_tree_flag, hf_gvcp_acknowledge_required_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

		offset++;

		/* Add the command */
		proto_tree_add_item(gvcp_tree, hf_gvcp_command, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}
	else /* ... or else it is an acknowledge */
	{
		int status = tvb_get_ntohs(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, "< %s %s",
			ack_string, val_to_str(status, statusnames_short, "Unknown status (0x%04X)"));

		gvcp_tree = proto_tree_add_subtree_format(gvcp_tree, tvb, offset+2, tvb_captured_length(tvb)-2,
												ett_gvcp_ack, NULL, "Acknowledge Header: %s", ack_string);

		/* Add the status: */
		proto_tree_add_item(gvcp_tree, hf_gvcp_status, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Add the acknowledge */
		proto_tree_add_item(gvcp_tree, hf_gvcp_acknowledge, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;
	}

	/* Parse the second part of both the command and the acknowledge header:
	0               15 16            31
	-------- -------- -------- --------
	|     status      |   acknowledge |
	-------- -------- -------- --------
	|     length      |      req_id   |
	-------- -------- -------- --------

	Add the data length
	Number of valid data bytes in this message, not including this header. This
	represents the number of bytes of payload appended after this header */
	proto_tree_add_item(gvcp_tree, hf_gvcp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	data_length = tvb_get_ntohs(tvb, offset);
	offset += 2;

	/* Add the request ID */
	proto_tree_add_item(gvcp_tree, hf_gvcp_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	request_id = tvb_get_ntohs(tvb, offset);
	offset += 2;

	conversation = find_or_create_conversation(pinfo);

	gvcp_info = (gvcp_conv_info_t*)conversation_get_proto_data(conversation, proto_gvcp);
	if (!gvcp_info)
	{
		int stream_channel_count = 0;
		gvcp_info = wmem_new(wmem_file_scope(), gvcp_conv_info_t);
		gvcp_info->pdus = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		for (; stream_channel_count < GVCP_MAX_STREAM_CHANNEL_COUNT; stream_channel_count++)
		{
			gvcp_info->extended_bootstrap_address[stream_channel_count] = 0;
		}
		conversation_add_proto_data(conversation, proto_gvcp, gvcp_info);
	}

	if (!pinfo->fd->visited)
	{
		if (key_code == 0x42)
		{
			/* This is a request */
			gvcp_trans = wmem_new(pinfo->pool, gvcp_transaction_t);
			gvcp_trans->req_frame = pinfo->num;
			gvcp_trans->rep_frame = 0;
			gvcp_trans->addr_list = 0;
			gvcp_trans->addr_count = 0;
		}
		else
		{
			if (ack_string && ( ack_code != GVCP_PENDING_ACK ) )
			{
				/* this is a response, so update trans info with ack's frame number */
				/* get list of transactions for given request id */
				gvcp_trans_array = (wmem_array_t*)wmem_map_lookup(gvcp_info->pdus, GUINT_TO_POINTER(request_id));
				if (gvcp_trans_array)
				{
					int i;
					unsigned array_size = wmem_array_get_count(gvcp_trans_array);
					for (i = array_size-1; i >= 0; i--)
					{
						gvcp_trans = (gvcp_transaction_t*)wmem_array_index(gvcp_trans_array, i);

						if (gvcp_trans && (gvcp_trans->req_frame < pinfo->num))
						{
							if (gvcp_trans->rep_frame != 0)
							{
								gvcp_trans = 0;
							}
							else
							{
								gvcp_trans->rep_frame = pinfo->num;
							}

							break;
						}
						gvcp_trans = 0;
					}
				}
			}
		}
	}
	else
	{
		gvcp_trans = 0;
		gvcp_trans_array = (wmem_array_t*)wmem_map_lookup(gvcp_info->pdus, GUINT_TO_POINTER(request_id));

		if (gvcp_trans_array)
		{
			unsigned i;
			unsigned array_size = wmem_array_get_count(gvcp_trans_array);

			for (i = 0; i < array_size; ++i)
			{
				gvcp_trans = (gvcp_transaction_t*)wmem_array_index(gvcp_trans_array, i);
				if (gvcp_trans && (pinfo->num == gvcp_trans->req_frame || pinfo->num == gvcp_trans->rep_frame))
				{
					break;
				}

				gvcp_trans = 0;
			}
		}
	}

	if (!gvcp_trans)
	{
		gvcp_trans = wmem_new0(pinfo->pool, gvcp_transaction_t);
	}

	/* Add telegram subtree */
	gvcp_telegram_tree = proto_item_add_subtree(gvcp_tree, ett_gvcp);

	/* Is this a command? */
	if (key_code == 0x42)
	{
		if (gvcp_telegram_tree != NULL)
		{
			if (gvcp_trans->rep_frame)
			{
				item = proto_tree_add_uint(gvcp_telegram_tree, hf_gvcp_response_in, tvb, 0, 0, gvcp_trans->rep_frame);
				proto_item_set_generated(item);
			}
		}

		switch (command)
		{
		case GVCP_FORCEIP_CMD:
			dissect_forceip_cmd(gvcp_telegram_tree, tvb, pinfo, offset, data_length);
			break;

		case GVCP_PACKETRESEND_CMD:
			dissect_packetresend_cmd(gvcp_telegram_tree, tvb, pinfo, offset, data_length, extendedblockids);
			break;

		case GVCP_READREG_CMD:
			dissect_readreg_cmd(gvcp_telegram_tree, tvb, pinfo, offset, data_length, gvcp_info, gvcp_trans);
			break;

		case GVCP_WRITEREG_CMD:
			dissect_writereg_cmd(gvcp_telegram_tree, tvb, pinfo, offset, data_length, gvcp_info, gvcp_trans);
			break;

		case GVCP_READMEM_CMD:
			dissect_readmem_cmd(gvcp_telegram_tree, tvb, pinfo, offset, gvcp_info);
			break;

		case GVCP_WRITEMEM_CMD:
			dissect_writemem_cmd(gvcp_telegram_tree, tvb, pinfo, offset, data_length, gvcp_info, gvcp_trans);
			break;

		case GVCP_EVENT_CMD:
			dissect_event_cmd(gvcp_telegram_tree, tvb, pinfo, offset, data_length, extendedblockids);
			break;

		case GVCP_EVENTDATA_CMD:
			dissect_eventdata_cmd(gvcp_telegram_tree, tvb, pinfo, offset, extendedblockids);
			break;

		case GVCP_ACTION_CMD:
			dissect_action_cmd(gvcp_telegram_tree, tvb, pinfo, offset, scheduledactioncommand);
			break;

		case GVCP_DISCOVERY_CMD:
		default:
			break;
		}

		if (!pinfo->fd->visited)
		{
			if (key_code == 0x42)
			{
				gvcp_trans_array = (wmem_array_t*)wmem_map_lookup(gvcp_info->pdus, GUINT_TO_POINTER(request_id));

				if(gvcp_trans_array)
				{
					wmem_array_append(gvcp_trans_array, gvcp_trans, 1);
				}
				else
				{
					gvcp_trans_array = wmem_array_new(wmem_file_scope(), sizeof(gvcp_transaction_t));
					wmem_array_append(gvcp_trans_array, gvcp_trans, 1);
					wmem_map_insert(gvcp_info->pdus, GUINT_TO_POINTER(request_id), (void *)gvcp_trans_array);
				}
			}
		}
	}
	else
	{
		if (gvcp_telegram_tree != NULL)
		{
			if (gvcp_trans->req_frame)
			{
				item = proto_tree_add_uint(gvcp_telegram_tree, hf_gvcp_response_to, tvb, 0, 0, gvcp_trans->req_frame);
				proto_item_set_generated(item);
			}
		}

		switch (ack_code)
		{
		case GVCP_DISCOVERY_ACK:
			dissect_discovery_ack(gvcp_telegram_tree, tvb, pinfo, offset, data_length);
			break;

		case GVCP_READREG_ACK:
			dissect_readreg_ack(gvcp_telegram_tree, tvb, pinfo, offset, data_length, gvcp_info, gvcp_trans);
			break;

		case GVCP_WRITEREG_ACK:
			dissect_writereg_ack(gvcp_telegram_tree, tvb, pinfo, offset, gvcp_trans);
			break;

		case GVCP_READMEM_ACK:
			dissect_readmem_ack(gvcp_telegram_tree, tvb, pinfo, offset, data_length, gvcp_info);
			break;

		case GVCP_WRITEMEM_ACK:
			dissect_writemem_ack(gvcp_telegram_tree, tvb, pinfo, offset, data_length, gvcp_info, gvcp_trans);
			break;

		case GVCP_PENDING_ACK:
			dissect_pending_ack(gvcp_telegram_tree, tvb, pinfo, offset, data_length);
			break;

		case GVCP_FORCEIP_ACK:
			break;
		case GVCP_PACKETRESEND_ACK:
		case GVCP_EVENT_ACK:
		case GVCP_EVENTDATA_ACK:
		case GVCP_ACTION_ACK:
		default:
			proto_tree_add_item(gvcp_telegram_tree, hf_gvcp_payloaddata, tvb, offset, data_length, ENC_NA);
			break;
		}
	}
	return tvb_captured_length(tvb);
}

void proto_register_gvcp(void)
{
	/*
	\brief Structures for register dissection
	*/

	static hf_register_info hf[] =
	{
		/* Common GVCP data */

		{ &hf_gvcp_message_key_code,
		{ "Message Key Code", "gvcp.message_key_code",
		FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_flag,
		{ "Flags", "gvcp.cmd.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_acknowledge_required_flag,
		{ "Acknowledge Required", "gvcp.cmd.flag.acq_required",
		FT_BOOLEAN, 8, NULL, 0x01,
		NULL, HFILL }},

		{ &hf_gvcp_scheduledactioncommand_flag_v2_0,
		{ "Scheduled Action Command", "gvcp.cmd.flag.scheduledactioncommand",
		FT_BOOLEAN, 8, NULL, 0x80,
		NULL, HFILL }},

		{ &hf_gvcp_64bitid_flag_v2_0,
		{ "64 bit ID", "gvcp.cmd.flag.64bitid",
		FT_BOOLEAN, 8, NULL, 0x10,
		NULL, HFILL }},

		{ &hf_gvcp_allow_broadcast_acknowledge_flag,
		{ "Allow Broadcast Acknowledge", "gvcp.cmd.flag.allowbroadcastacq",
		FT_BOOLEAN, 8, NULL, 0x10,
		NULL, HFILL }},

		{ &hf_gvcp_command,
		{ "Command", "gvcp.cmd.command",
		FT_UINT16, BASE_HEX, VALS(commandnames), 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_length,
		{ "Payload Length", "gvcp.cmd.payloadlength",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_request_id,
		{ "Request ID", "gvcp.cmd.req_id",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_payloaddata,
		{ "Payload Data", "gvcp.cmd.payloaddata",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_status,
		{ "Status", "gvcp.cmd.status",
		FT_UINT16, BASE_HEX, VALS(statusnames), 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_acknowledge,
		{ "Acknowledge", "gvcp.ack",
		FT_UINT16, BASE_HEX, VALS(acknowledgenames), 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_devicemodediscovery,
		{ "Device Mode", "gvcp.ack.discovery.devicemode",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		/* Force IP */

		{ &hf_gvcp_forceip_mac_address,
		{ "MAC Address", "gvcp.cmd.forceip.macaddress",
		FT_ETHER, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_forceip_static_IP,
		{ "IP address", "gvcp.cmd.forceip.ip",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_forceip_static_subnet_mask,
		{ "Subnet Mask", "gvcp.cmd.forceip.subnetmask",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_forceip_static_default_gateway,
		{ "Default Gateway", "gvcp.cmd.forceip.defaultgateway",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* Discovery specific */

		{ &hf_gvcp_device_mac_address,
		{ "Device MAC Address", "gvcp.cmd.discovery.devicemacaddress",
		FT_ETHER, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* Read register */
		{ &hf_gvcp_readregcmd_bootstrap_register,
		{ "Bootstrap Register", "gvcp.cmd.readreg.bootstrapregister",
		FT_UINT32, BASE_HEX_DEC, VALS(bootstrapregisternames), 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_readregcmd_extended_bootstrap_register,
		{ "Extended Bootstrap Register", "gvcp.cmd.readreg.extendedbootstrapregister",
		FT_UINT32, BASE_HEX_DEC, VALS(extendedbootstrapregisternames), 0x0,
		NULL, HFILL } },

		/* Write register */

		{ &hf_gvcp_writeregcmd_data,
		{ "DataX", "gvcp.cmd.writereg.data",
		FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_writeregcmd_bootstrap_register,
		{ "Bootstrap Register", "gvcp.cmd.writereg.bootstrapregister",
		FT_UINT32, BASE_HEX_DEC, VALS(bootstrapregisternames), 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_writeregcmd_extended_bootstrap_register,
		{ "Extended Bootstrap Register", "gvcp.cmd.writereg.extendedbootstrapregister",
		FT_UINT32, BASE_HEX_DEC, VALS(extendedbootstrapregisternames), 0x0,
		NULL, HFILL } },

		{ &hf_gvcp_writeregcmd_data_index,
		{ "Data Index", "gvcp.cmd.writereg.dataindex",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		/* Read memory */

		{ &hf_gvcp_readmemcmd_address,
		{ "Register Address", "gvcp.cmd.readmem.address",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_readmemcmd_bootstrap_register,
		{ "Memory Bootstrap Register", "gvcp.cmd.readmem.bootstrapregister",
		FT_UINT32, BASE_HEX_DEC, VALS(bootstrapregisternames), 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_readmemcmd_count,
		{ "Count", "gvcp.cmd.readmem.count",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		/* Write memory */

		{ &hf_gvcp_writememcmd_data,
		{ "DataY", "gvcp.cmd.writemem.data",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_writememcmd_data_index,
		{ "Data Index", "gvcp.cmd.writemem.dataindex",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		/* Resend request */

		{ &hf_gvcp_resendcmd_stream_channel_index,
		{ "Resend Stream Channel Index", "gvcp.cmd.resend.streamchannelindex",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_resendcmd_block_id,
		{ "Resend Block ID 16 bits", "gvcp.cmd.resend.blockid",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_resendcmd_first_packet_id,
		{ "Resend First Packet ID 24 bits", "gvcp.cmd.resend.firstpacketid",
		FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_resendcmd_last_packet_id,
		{ "Resend Last Packet ID 24 bits", "gvcp.cmd.resend.lastpacketid",
		FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_resendcmd_extended_block_id_v2_0,
		{ "Resend Block ID 64 bits", "gvcp.cmd.resend.extendedblockid",
		FT_UINT64, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_resendcmd_extended_first_packet_id_v2_0,
		{ "Resend First Packet ID 32 bits", "gvcp.cmd.resend.firstpacketid",
		FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_resendcmd_extended_last_packet_id_v2_0,
		{ "Resend Last Packet ID 32 bits", "gvcp.cmd.resend.lastpacketid",
		FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		/* Event */

		{ &hf_gvcp_eventcmd_id,
		{ "ID", "gvcp.cmd.event.id",
		FT_UINT16, BASE_HEX_DEC, VALS(eventidnames), 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_eventcmd_error_id,
		{ "Error ID", "gvcp.cmd.event.errorid",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_eventcmd_extid_length,
		{ "Event Size", "gvcp.cmd.event.eventsize",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_eventcmd_device_specific_id,
		{ "Device Specific ID", "gvcp.cmd.event.devicespecificid",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_eventcmd_stream_channel_index,
		{ "Stream Channel Index", "gvcp.cmd.event.streamchannelindex",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_eventcmd_block_id,
		{ "Block ID (16 bit)", "gvcp.cmd.event.blockid",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_eventcmd_timestamp,
		{ "Timestamp", "gvcp.cmd.event.timestamp",
		FT_UINT64, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_eventcmd_block_id_64bit_v2_0,
		{ "Block ID 64 bit", "gvcp.event_timestamp",
		FT_UINT64, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		/* Event data */

		{ &hf_gvcp_eventcmd_data,
		{ "Event Data", "gvcp.cmd.eventdata.data",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* Action */

		{ &hf_gvcp_actioncmd_device_key,
		{ "Action Device Key", "gvcp.cmd.action.devicekey",
		FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_actioncmd_group_key,
		{ "Action Group Key", "gvcp.cmd.action.groupkey",
		FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_gvcp_actioncmd_group_mask,
		{ "Action Group Mask", "gvcp.cmd.action.groupmask",
		FT_UINT32, BASE_HEX_DEC, NULL, 0xFFFFFFFF,
		NULL, HFILL }},

		{ &hf_gvcp_actioncmd_time_v2_0,
		{ "Action Scheduled Time", "gvcp.cmd.action.time",
		FT_UINT64, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		/* Pending acknowledge */

		{ &hf_gvcp_time_to_completion,
		{ "Time to completion", "gvcp.ack.pendingack.timetocompletion",
		FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_VERSION */

		{ &hf_gvcp_spec_version_major,
		{ "Version Major", "gvcp.bootstrap.specversion.major",
		FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
		NULL, HFILL }},

		{ &hf_gvcp_spec_version_minor,
		{ "Version Minor", "gvcp.bootstrap.specversion.minor",
		FT_UINT32, BASE_HEX, NULL, 0x0000FFFF,
		NULL, HFILL }},

		{ &hf_gvcp_spec_version,
		{ "Spec Version", "gvcp.bootstrap.specversion",
		FT_UINT32, BASE_HEX, NULL, 0,
		NULL, HFILL }},

		/* GVCP_devicemode */

		{ &hf_gvcp_devicemode_endianness,
		{ "Endianness", "gvcp.bootstrap.devicemode.endianness",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_devicemode_deviceclass,
		{ "Device Class", "gvcp.bootstrap.devicemode.deviceclass",
		FT_UINT32, BASE_HEX, VALS(devicemodenames_class), 0x70000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_devicemode_current_link_configuration_v2_0,
		{ "Current Link Configuration", "gvcp.bootstrap.devicemode.currentlinkconfiguration",
		FT_UINT32, BASE_HEX, VALS(linkconfiguration_class), 0x03000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_devicemode_characterset,
		{ "Character Set", "gvcp.bootstrap.devicemode.characterset",
		FT_UINT32, BASE_HEX, VALS(devicemodenames_characterset), 0x0000000F,
		NULL, HFILL
		}},

		/* GVCP_MAC_HIGH_0, 1, 2, 3 */

		{ &hf_gvcp_machigh,
		{ "MAC High", "gvcp.bootstrap.machigh",
		FT_UINT32, BASE_HEX, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_MAC_LOW_0, 1, 2, 3 */

		{ &hf_gvcp_maclow,
		{ "MAC Low", "gvcp.bootstrap.maclow",
		FT_UINT32, BASE_HEX, NULL, 0,
		NULL, HFILL
		}},

		/* GVCP_SUPPORTED_IP_CONFIGURATION_0, 1, 2, 3 */
		/* GVCP_CURIPCFG_0, 1, 2, 3 */

		{ &hf_gvcp_ip_config_can_handle_pause_frames_v2_0,
		{ "IP Config Can Handle Pause Frames", "gvcp.bootstrap.ipconfig.canhandlepauseframes",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL }},

		{ &hf_gvcp_ip_config_can_generate_pause_frames_v2_0,
		{ "Can Generate Pause Frames", "gvcp.bootstrap.ipconfig.cangeneratepauseframes",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL }},

		{ &hf_gvcp_ip_config_lla,
		{ "LLA", "gvcp.bootstrap.ipconfig.lla",
		FT_BOOLEAN, 32, NULL, 0x00000004,
		NULL, HFILL }},

		{ &hf_gvcp_ip_config_dhcp,
		{ "DHCP", "gvcp.bootstrap.ipconfig.dhcp",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL }},

		{ &hf_gvcp_ip_config_persistent_ip,
		{ "Persistent IP", "gvcp.bootstrap.ipconfig.persistentip",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL }},

		{ &hf_gvcp_supportedipconfig,
		{ "Supported IP Configuration", "gvcp.bootstrap.supportedipconfig",
		FT_UINT32, BASE_HEX, NULL, 0,
		NULL, HFILL
		}},

		{ &hf_gvcp_currentipconfig,
		{ "Current IP Configuration", "gvcp.bootstrap.currentipconfig",
		FT_UINT32, BASE_HEX, NULL, 0,
		NULL, HFILL
		}},

		/* GVCP_CURRENT_IP_ADDRESS_0, 1, 2, 3 */

		{ &hf_gvcp_current_IP,
		{ "Current IP", "gvcp.bootstrap.currentip",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_CURRENT_SUBNET_MASK_0, 1, 2, 3 */

		{ &hf_gvcp_current_subnet_mask,
		{ "Subnet Mask", "gvcp.bootstrap.currentsubnetmask",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_CURRENT_DEFAULT_GATEWAY_0, 1, 2, 3 */

		{ &hf_gvcp_current_default_gateway,
		{ "Default Gateway", "gvcp.bootstrap.currentdefaultgateway",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_MANUFACTURER_NAME */

		{ &hf_gvcp_manufacturer_name,
		{ "Manufacturer Name", "gvcp.bootstrap.manufacturername",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_MODEL_NAME */

		{ &hf_gvcp_model_name,
		{ "Model Name", "gvcp.bootstrap.modelname",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_DEVICE_VERSION */

		{ &hf_gvcp_device_version,
		{ "Device Version", "gvcp.bootstrap.deviceversion",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_MANUFACTURER_INFO */

		{ &hf_gvcp_manufacturer_specific_info,
		{ "Manufacturer Specific Info", "gvcp.bootstrap.manufacturerspecificinfo",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_SERIAL_NUMBER */

		{ &hf_gvcp_serial_number,
		{ "Serial Number", "gvcp.bootstrap.serialnumber",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_USER_DEFINED_NAME */

		{ &hf_gvcp_user_defined_name,
		{ "User-defined Name", "gvcp.bootstrap.userdefinedname",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_FIRST_URL */

		{ &hf_gvcp_first_xml_device_description_file,
		{ "First URL", "gvcp.bootstrap.firsturl",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_SECOND_URL */

		{ &hf_gvcp_second_xml_device_description_file,
		{ "Second URL", "gvcp.bootstrap.secondurl",
		FT_STRINGZ, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		/* GVCP_NUMBER_OF_NETWORK_INTERFACES */

		{ &hf_gvcp_number_interfaces,
		{ "Number of Network Interfaces", "gvcp.bootstrap.numberofnetworminterfaces",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_PERSISTENT_IP_ADDRESS_0, 1, 2, 3 */

		{ &hf_gvcp_persistent_ip,
		{ "Persistent IP", "gvcp.bootstrap.persistentip",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_PERSISTENT_SUBNET_MASK_0, 1, 2, 3 */

		{ &hf_gvcp_persistent_subnet,
		{ "Persistent Subnet Mask", "gvcp.bootstrap.persistentsubnetmask",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_PERSISTENT_DEFAULT_GATEWAY_0, 1, 2, 3 */

		{ &hf_gvcp_persistent_gateway,
		{ "Persistent GateWay", "gvcp.bootstrap.persistentgateway",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_LINK_SPEED_0, 1, 2, 3 */

		{ &hf_gvcp_link_speed,
		{ "Link Speed (in Mbs)", "gvcp.bootstrap.linkspeed",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_NUMBER_OF_MESSAGE_CHANNELS */

		{ &hf_gvcp_number_message_channels,
		{ "Number of Message Channels", "gvcp.bootstrap.numberofmessagechannels",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_NUMBER_OF_STREAM_CHANNELS */

		{ &hf_gvcp_number_stream_channels,
		{ "Number of Stream Channels", "gvcp.bootstrap.numberofstreamchannels",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_NUMBER_OF_ACTION_SIGNALS */

		{ &hf_gvcp_number_action_signals,
		{ "Number of Action Signals", "gvcp.bootstrap.numberofactionsignals",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_NUMBER_OF_ACTIVE_LINKS */

		{ &hf_gvcp_number_of_active_links_v2_0,
		{ "Number of Active Links", "gvcp.bootstrap.numberofactivelinks",
		FT_UINT32, BASE_DEC, NULL, 0x0000000F,
		NULL, HFILL
		}},

		/* GVCP_IEEE_1588_SELECTED_PROFILE */

		{ &hf_gvcp_selected_ieee1588_profile_v2_1,
		{ "IEEE 1588 Selected Profile", "gvcp.bootstrap.ieee1588selectedprofile",
		FT_UINT32, BASE_DEC, NULL, 0x0000001F,
		NULL, HFILL
		}},

		/* GVCP_SC_CAPS */

		{ &hf_gvcp_sccaps_scspx_register_supported,
		{ "SCSPx Register Supported", "gvcp.bootstrap.sccaps.scspxregistersupported",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sccaps_legacy_16bit_blockid_supported_v2_0,
		{ "16 bit Block ID Supported", "gvcp.bootstrap.sccaps.16bitblockidsupported",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sccaps_scmbsx_supported_v2_2,
		{ "Stream Channel Max. Block Size Supported", "gvcp.bootstrap.sccaps.scmbssupported",
		FT_BOOLEAN, 32, NULL, 0x20000000,
		NULL, HFILL
		} },

		{ &hf_gvcp_sccaps_scebax_supported_v2_2,
		{ "Stream Channel Extended Bootstrap Address Supported", "gvcp.bootstrap.sccaps.scebasupported",
		FT_BOOLEAN, 32, NULL, 0x10000000,
		NULL, HFILL
		} },

		/* GVCP_MESSAGE_CHANNEL_CAPS */

		{ &hf_gvcp_mcsp_supported,
		{ "MCSP Supported", "gvcp.bootstrap.mccaps.mcspsupported",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_mccfg_supported_v2_2,
		{ "MCCFG Supported", "gvcp.bootstrap.mccaps.mccfgsupported",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL
		} },

		{ &hf_gvcp_mcec_supported_v2_2,
		{ "MCEC Supported", "gvcp.bootstrap.mccaps.mcecsupported",
		FT_BOOLEAN, 32, NULL, 0x20000000,
		NULL, HFILL
		} },

		/* GVCP_IEEE_1588_EXTENDED_CAPABILITY */

		{ &hf_gvcp_ieee1588_profile_registers_present_v2_1,
		{ "IEEE 1588 Profile Registers Present", "gvcp.bootstrap.ieee1588extendedcapabilities.profileregisterspresent",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		/* GVCP_IEEE_1588_SUPPORTED_PROFILES */

		{ &hf_gvcp_ieee1588_ptp_profile_supported_v2_1,
		{ "IEEE 1588 PTP Profile Supported", "gvcp.bootstrap.ieee1588supportedprofiles.ptp",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_ieee1588_802dot1as_profile_supported_v2_1,
		{ "IEEE 1588 802.1as Profile Supported", "gvcp.bootstrap.ieee1588supportedprofiles.802dot1as",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL
		}},

		/* GVCP_CAPABILITY */

		{ &hf_gvcp_capability_user_defined,
		{ "User Defined Name Supported", "gvcp.bootstrap.capability.userdefined",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_serial_number,
		{ "Serial Number Supported", "gvcp.bootstrap.capability.serialnumber",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_heartbeat_disable,
		{ "Heartbeat Disable Supported", "gvcp.bootstrap.capability.heartbeatdisabled",
		FT_BOOLEAN, 32, NULL, 0x20000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_link_speed,
		{ "Link Speed Supported", "gvcp.bootstrap.capability.linkspeed",
		FT_BOOLEAN, 32, NULL, 0x10000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_ccp_application_portip,
		{ "CCP Application Port/IP Supported", "gvcp.bootstrap.capability.ccpapplicationportip",
		FT_BOOLEAN, 32, NULL, 0x08000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_manifest_table,
		{ "Manifest Table Supported", "gvcp.bootstrap.capability.manifesttable",
		FT_BOOLEAN, 32, NULL, 0x04000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_test_data,
		{ "Test Data Supported", "gvcp.bootstrap.capability.testdata",
		FT_BOOLEAN, 32, NULL, 0x02000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_discovery_ACK_delay,
		{ "Discovery ACK Delay Supported", "gvcp.bootstrap.capability.discoveryackdelay",
		FT_BOOLEAN, 32, NULL, 0x01000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_writable_discovery_ACK_delay,
		{ "Writable Discovery ACK Delay Supported", "gvcp.bootstrap.capability.writablediscoveryackdelay",
		FT_BOOLEAN, 32, NULL, 0x00800000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_extended_status_code_v1_1,
		{ "Extended Status Code Supported (v1.1)", "gvcp.bootstrap.capability.extendedstatuscodesupportedv1_1",
		FT_BOOLEAN, 32, NULL, 0x00400000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_primary_application_switchover,
		{ "Primary Application Switchover Supported", "gvcp.bootstrap.capability.primaryapplicationswitchover",
		FT_BOOLEAN, 32, NULL, 0x00200000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_unconditional_action_command,
		{ "Unconditional Action Command Supported", "gvcp.bootstrap.capability.unconditionalactioncommand",
		FT_BOOLEAN, 32, NULL, 0x00100000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_1588_v2_0,
		{ "Capability 1588", "gvcp.bootstrap.capability.ieee1588",
		FT_BOOLEAN, 32, NULL, 0x00080000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_extended_status_code_v2_0,
		{ "Status Code", "gvcp.bootstrap.capability.pendingextendedstatuscodev2_0",
		FT_BOOLEAN, 32, NULL, 0x00040000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_scheduled_action_command_v2_0,
		{ "Scheduled Action Command", "gvcp.bootstrap.capability.scheduledactioncommand",
		FT_BOOLEAN, 32, NULL, 0x00020000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_ieee1588_extended_capabilities_v2_1,
		{ "IEEE1588 Extended Capabilities", "gvcp.bootstrap.capability.ieee1588extendedcapabilities",
		FT_BOOLEAN, 32, NULL, 0x00010000,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_action_command,
		{ "Action Command", "gvcp.bootstrap.capability.actioncommand",
		FT_BOOLEAN, 32, NULL, 0x00000040,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_pending,
		{ "Pending ACK Supported", "gvcp.bootstrap.capability.pendingack",
		FT_BOOLEAN, 32, NULL, 0x00000020,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_evendata,
		{ "Event Data Supported", "gvcp.bootstrap.capability.eventdata",
		FT_BOOLEAN, 32, NULL, 0x00000010,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_event,
		{ "Event Signal Supported", "gvcp.bootstrap.capability.eventsignal",
		FT_BOOLEAN, 32, NULL, 0x00000008,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_packetresend,
		{ "Packet Resend CMD Supported", "gvcp.bootstrap.capability.packetresendcmd",
		FT_BOOLEAN, 32, NULL, 0x00000004,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_writemem,
		{ "WRITEMEM Supported", "gvcp.bootstrap.capability.writemem",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_capability_concatenation,
		{ "Concatenation Supported", "gvcp.bootstrap.capability.concatenation",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_HEARTBEAT_TIMEOUT */

		{ &hf_gvcp_heartbeat,
		{ "Heartbeat Timeout (in ms)", "gvcp.bootstrap.heartbeattimeout",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_TIMESTAMP_TICK_FREQUENCY_HIGH */

		{ &hf_gvcp_high_timestamp_frequency,
		{ "Timestamp Tick High Frequency (in Hz)", "gvcp.bootstrap.timestamptickfrequencyhigh",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_TIMESTAMP_TICK_FREQUENCY_LOW */

		{ &hf_gvcp_low_timestamp_frequency,
		{ "Timestamp Tick Low Frequency (in Hz)", "gvcp.bootstrap.timestamptickfrequencylow",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_TIMESTAMP_CONTROL */

		{ &hf_gvcp_timestamp_control_latch,
		{ "Timestamp Control Latch", "gvcp.bootstrap.timestampcontrol.latch",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_timestamp_control_reset,
		{ "Timestamp Control Reset", "gvcp.bootstrap.timestampcontrol.reset",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_TIMESTAMP_VALUE_HIGH */

		{ &hf_gvcp_high_timestamp_value,
		{ "Timestamp Value High", "gvcp.bootstrap.timestampvaluehigh",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_TIMESTAMP_VALUE_LOW */

		{ &hf_gvcp_low_timestamp_value,
		{ "Timestamp Value Low", "gvcp.bootstrap.timestampvaluelow",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_DISCOVERY_ACK_DELAY */

		{ &hf_gvcp_discovery_ACK_delay,
		{ "Discovery ACK Delay (in ms)", "gvcp.bootstrap.discoveryackdelay",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_CONFIGURATION */

		{ &hf_gvcp_configuration_1588_enable_v2_0,
		{ "IEEE 1588 Enable", "gvcp.bootstrap.config.ieee1588enable",
		FT_BOOLEAN, 32, NULL, 0x00080000,
		NULL, HFILL
		}},

		{ &hf_gvcp_configuration_extended_status_codes_enable_v2_0,
		{ "Status Codes v2.0 Enable", "gvcp.bootstrap.config.statuscodesv2_0enable",
		FT_BOOLEAN, 32, NULL, 0x00040000,
		NULL, HFILL
		}},

		{ &hf_gvcp_configuration_unconditional_action_command_enable_v2_0,
		{ "Unconditional Action Command Enable", "gvcp.bootstrap.config.unconditionalactioncommandenable",
		FT_BOOLEAN, 32, NULL, 0x00000008,
		NULL, HFILL
		}},

		{ &hf_gvcp_configuration_extended_status_codes_enable_v1_1,
		{ "Status Codes v1.1 Enable", "gvcp.bootstrap.config.statuscodesv1_1enable",
		FT_BOOLEAN, 32, NULL, 0x00000004,
		NULL, HFILL
		}},

		{ &hf_gvcp_configuration_pending_ack_enable,
		{ "Pending_ACK Enable", "gvcp.bootstrap.config.pendingackenable",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_configuration_heartbeat_disable,
		{ "Heartbeat Disable", "gvcp.bootstrap.config.heartbeatdisable",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_PENDING_TIMEOUT */

		{ &hf_gvcp_pending_timeout_max_execution,
		{ "Pending Timeout (in ms)", "gvcp.bootstrap.pending.timeout",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_CONTROL_SWITCHOVER_KEY */

		{ &hf_gvcp_control_switchover_key_register,
		{ "Control Switchover Key", "gvcp.bootstrap.controlswitchoverkey",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_GVSCP_CONFIGURATION */

		{ &hf_gvcp_gvsp_configuration_64bit_blockid_enable_v2_0,
		{ "GVSP Configuration 64 bit Block ID", "gvcp.bootstrap.gvcspconfig.64bitblockidenable",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL
		}},

		/* GVCP_PHYSICAL_LINK_CAPABILITY, GVCP_PHYSICAL_LINK_CONFIGURATION */

		{ &hf_gvcp_link_dlag_v2_0,
		{ "Link dLAG", "gvcp.bootstrap.link.dlag",
		FT_BOOLEAN, 32, NULL, 0x00000008,
		NULL, HFILL
		}},

		{ &hf_gvcp_link_slag_v2_0,
		{ "Link sLAG", "gvcp.bootstrap.link.slag",
		FT_BOOLEAN, 32, NULL, 0x00000004,
		NULL, HFILL
		}},

		{ &hf_gvcp_link_ml_v2_0,
		{ "Link ML", "gvcp.bootstrap.link.ml",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_link_sl_v2_0,
		{ "Link SL", "gvcp.bootstrap.link.sl",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_IEEE_1588_STATUS */

		{ &hf_gvcp_ieee1588_clock_status_v2_0,
		{ "IEEE 1588 Clock Status", "gvcp.bootstrap.ieee1588.clockstatus",
		FT_UINT32, BASE_HEX, NULL, 0x0000000F,
		NULL, HFILL
		}},

		/* GVCP_SCHEDULED_ACTION_COMMAND_QUEUE_SIZE */

		{ &hf_gvcp_scheduled_action_command_queue_size_v2_0,
		{ "Scheduled Action Command Queue Size", "gvcp.bootstrap.scheduledactioncommandqueuesize",
		FT_UINT32, BASE_DEC, NULL, 0,
		NULL, HFILL
		}},

		/* GVCP_CCP */

		{ &hf_gvcp_control_switchover_key,
		{ "Control Switchover Key", "gvcp.bootstrap.control.switchoverkey",
		FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
		NULL, HFILL
		}},

		{ &hf_gvcp_control_switchover_en,
		{ "Control Switchover Enable", "gvcp.bootstrap.control.switchoverenable",
		FT_BOOLEAN, 32, NULL, 0x00000004,
		NULL, HFILL
		}},

		{ &hf_gvcp_control_access,
		{ "Control Access", "gvcp.bootstrap.control.controlaccess",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_exclusive_access,
		{ "Exclusive Access", "gvcp.bootstrap.control.exclusiveaccess",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_PRIMARY_APPLICATION_PORT */

		{ &hf_gvcp_primary_application_host_port,
		{ "Primary Application Port", "gvcp.bootstrap.primaryapplicationport",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_PRIMARY_APPLICATION_IP_ADDRESS */

		{ &hf_gvcp_primary_application_ip_address,
		{ "Primary Application IP Address", "gvcp.bootstrap.primaryapplicationipaddress",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_MC_DESTINATION_PORT */

		{ &hf_gvcp_network_interface_index,
		{ "Network Interface Index", "gvcp.bootstrap.mcp.networkinterfaceindex",
		FT_UINT32, BASE_DEC, NULL, 0x000F0000,
		NULL, HFILL
		}},

		{ &hf_gvcp_host_port,
		{ "Host Port", "gvcp.bootstrap.mcp.hostport",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_MC_DESTINATION_ADDRESS */

		{ &hf_gvcp_channel_destination_ip,
		{ "Destination IP Address", "gvcp.bootstrap.mcda",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_MC_TIMEOUT */

		{ &hf_gvcp_message_channel_transmission_timeout,
		{ "Transmission Timeout (in ms)", "gvcp.bootstrap.mctt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_MC_RETRY_COUNT */

		{ &hf_gvcp_message_channel_retry_count,
		{ "Retry Count", "gvcp.bootstrap.mcrc",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_MC_SOURCE_PORT */

		{ &hf_gvcp_message_channel_source_port,
		{ "Source Port", "gvcp.bootstrap.mcsp",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_MC_CONFIGURATION */

		{ &hf_gvcp_mcec_enabled_v2_2,
		{ "MCEC Enabled", "gvcp.bootstrap.mcconfig.mcecenabled",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		} },

		/* GVCP_SC_DESTINATION_PORT(0), 1, 2, 3 */

		{ &hf_gvcp_sc_direction,
		{ "Direction", "gvcp.bootstrap.scpx.direction",
		FT_BOOLEAN, 32, TFS(&directionnames), 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_ni_index,
		{ "Network Interface Index", "gvcp.bootstrap.scpx.networkinterfaceindex",
		FT_UINT32, BASE_DEC, NULL, 0x000F0000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_host_port,
		{ "Host Port", "gvcp.bootstrap.scpx.hostport",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_SC_PACKET_SIZE(0), 1, 2, 3 */

		{ &hf_gvcp_sc_fire_test_packet,
		{ "Fire Test Packet", "gvcp.bootstrap.scpsx.firetestpacket",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_do_not_fragment,
		{ "Do Not Fragment", "gvcp.bootstrap.scpsx.donotfragment",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_pixel_endianness,
		{ "Pixel Endianness", "gvcp.bootstrap.scpsx.pixelendianness",
		FT_BOOLEAN, 32, NULL, 0x20000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_packet_size,
		{ "Packet Size", "gvcp.bootstrap.scpsx.packetsize",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_SC_PACKET_DELAY(0), 1, 2, 3 */

		{ &hf_gvcp_sc_packet_delay,
		{ "Packet Delay", "gvcp.bootstrap.scpdx",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_SC_DESTINATION_ADDRESS(0), 1, 2, 3 */

		{ &hf_gvcp_sc_destination_ip,
		{ "Destination Address", "gvcp.bootstrap.scdax",
		FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_SC_SOURCE_PORT(0), 1, 2, 3 */

		{ &hf_gvcp_sc_source_port,
		{ "Source Port", "gvcp.bootstrap.scspx",
		FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
		NULL, HFILL
		}},

		/* GVCP_SC_CAPABILITY(0), 1, 2, 3 */

		{ &hf_gvcp_sc_big_little_endian_supported,
		{ "Big/Little Endian Supported", "gvcp.bootstrap.sccx.biglittleendiansupported",
		FT_BOOLEAN, 32, NULL, 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_ip_reassembly_supported,
		{ "IP Reassembly Supported", "gvcp.bootstrap.sccx.ipreassemblysupported",
		FT_BOOLEAN, 32, NULL, 0x40000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_scmpcx_supported_v2_2,
		{ "Stream Channel Maximum Packet Count Supported", "gvcp.bootstrap.sccx.scmpcxsupported",
		FT_BOOLEAN, 32, NULL, 0x00000100,
		NULL, HFILL
		} },

		{ &hf_gvcp_sc_gendc_supported_v2_2,
		{ "GenDC Supported", "gvcp.bootstrap.sccx.gendcsupported",
		FT_BOOLEAN, 32, NULL, 0x00000080,
		NULL, HFILL
		} },

		{ &hf_gvcp_sc_multi_part_supported_v2_1,
		{ "Multi-part Supported", "gvcp.bootstrap.sccx.multipartsupported",
		FT_BOOLEAN, 32, NULL, 0x00000040,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_large_leader_trailer_supported_v2_1,
		{ "Large Leader/Trailer Supported", "gvcp.bootstrap.sccx.largeleadertrailersupported",
		FT_BOOLEAN, 32, NULL, 0x00000020,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_multizone_supported_v2_0,
		{ "Multi-zone Supported", "gvcp.bootstrap.sccx.multizonesupported",
		FT_BOOLEAN, 32, NULL, 0x00000010,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_packet_resend_destination_option_supported_v2_0,
		{ "Resend Destination Option Supported", "gvcp.bootstrap.sccx.resenddestinationoptionsupported",
		FT_BOOLEAN, 32, NULL, 0x00000008,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_packet_resend_all_in_transmission_supported_v2_0,
		{ "All In Transmission Supported", "gvcp.bootstrap.sccx.allintransmissionsupported",
		FT_BOOLEAN, 32, NULL, 0x00000004,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_unconditional_streaming_supported,
		{ "Unconditional Streaming Supported", "gvcp.bootstrap.sccx.unconditionalstreamingsupported",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_extended_chunk_data_supported,
		{ "Extended Chunk Data Supported", "gvcp.bootstrap.sccx.extendedchunkdatasupported",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_SC_CONFIGURATION(0), 1, 2, 3 */

		{ &hf_gvcp_sc_gendc_enabled_v2_2,
		{ "GenDC Enabled", "gvcp.bootstrap.sccfgx.gendcenabled",
		FT_BOOLEAN, 32, NULL, 0x00000080,
		NULL, HFILL
		} },

		{ &hf_gvcp_sc_multi_part_enabled_v2_1,
		{ "Multi-part Enabled", "gvcp.bootstrap.sccfgx.multipartenabled",
		FT_BOOLEAN, 32, NULL, 0x00000040,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_large_leader_trailer_enabled_v2_1,
		{ "Large Leader/Trailer Enabled", "gvcp.bootstrap.sccfgx.largeleadertrailerenabled",
		FT_BOOLEAN, 32, NULL, 0x00000020,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_packet_resend_destination_option_enabled_v2_0,
		{ "Resend Destination Option Enabled", "gvcp.bootstrap.sccfgx.resenddestinationoptionenabled",
		FT_BOOLEAN, 32, NULL, 0x00000008,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_packet_resend_all_in_transmission_enabled_v2_0,
		{ "All In Transmission Enabled", "gvcp.bootstrap.sccfgx.allintransmissionenabled",
		FT_BOOLEAN, 32, NULL, 0x00000004,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_unconditional_streaming_enabled,
		{ "Unconditional Streaming Enabled", "gvcp.bootstrap.sccfgx.unconditionalstreamingenabled",
		FT_BOOLEAN, 32, NULL, 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_extended_chunk_data_enabled,
		{ "Extended Chunk Data Enabled", "gvcp.bootstrap.sccfgx.extendedchunkdataenabled",
		FT_BOOLEAN, 32, NULL, 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_SC_ZONE(0), 1, 2, 3 */

        { &hf_gvcp_sc_additional_zones_v2_0,
		{ "Additional Zones", "gvcp.bootstrap.sczx.additionalzones",
		FT_UINT32, BASE_DEC, NULL, 0x0000000F,
		NULL, HFILL
		}},

		/* GVCP_SC_ZONE_DIRECTION(0), 1, 2, 3 */

		{ &hf_gvcp_sc_zone0_direction_v2_0,
		{ "Zone 0 Direction", "gvcp.bootstrap.sczdx.zone0direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x80000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone1_direction_v2_0,
		{ "Zone 1 Direction", "gvcp.bootstrap.sczdx.zone1direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x40000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone2_direction_v2_0,
		{ "Zone 2 Direction", "gvcp.bootstrap.sczdx.zone2direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x20000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone3_direction_v2_0,
		{ "Zone 3 Direction", "gvcp.bootstrap.sczdx.zone3direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x10000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone4_direction_v2_0,
		{ "Zone 4 Direction", "gvcp.bootstrap.sczdx.zone4direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x08000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone5_direction_v2_0,
		{ "Zone 5 Direction", "gvcp.bootstrap.sczdx.zone5direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x04000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone6_direction_v2_0,
		{ "Zone 6 Direction", "gvcp.bootstrap.sczdx.zone6direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x02000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone7_direction_v2_0,
		{ "Zone 7 Direction", "gvcp.bootstrap.sczdx.zone7direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x01000000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone8_direction_v2_0,
		{ "Zone 8 Direction", "gvcp.bootstrap.sczdx.zone8direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00800000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone9_direction_v2_0,
		{ "Zone 9 Direction", "gvcp.bootstrap.sczdx.zone9direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00400000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone10_direction_v2_0,
		{ "Zone 10 Direction", "gvcp.bootstrap.sczdx.zone10direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00200000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone11_direction_v2_0,
		{ "Zone 11 Direction", "gvcp.bootstrap.sczdx.zone11direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00100000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone12_direction_v2_0,
		{ "Zone 12 Direction", "gvcp.bootstrap.sczdx.zone12direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00080000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone13_direction_v2_0,
		{ "Zone 13 Direction", "gvcp.bootstrap.sczdx.zone13direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00040000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone14_direction_v2_0,
		{ "Zone 14 Direction", "gvcp.bootstrap.sczdx.zone14direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00020000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone15_direction_v2_0,
		{ "Zone 15 Direction", "gvcp.bootstrap.sczdx.zone15direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00010000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone16_direction_v2_0,
		{ "Zone 16 Direction", "gvcp.bootstrap.sczdx.zone16direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00008000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone17_direction_v2_0,
		{ "Zone 17 Direction", "gvcp.bootstrap.sczdx.zone17direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00004000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone18_direction_v2_0,
		{ "Zone 18 Direction", "gvcp.bootstrap.sczdx.zone18direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00002000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone19_direction_v2_0,
		{ "Zone 19 Direction", "gvcp.bootstrap.sczdx.zone19direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00001000,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone20_direction_v2_0,
		{ "Zone 20 Direction", "gvcp.bootstrap.sczdx.zone20direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000800,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone21_direction_v2_0,
		{ "Zone 21 Direction", "gvcp.bootstrap.sczdx.zone21direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000400,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone22_direction_v2_0,
		{ "Zone 22 Direction", "gvcp.bootstrap.sczdx.zone22direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000200,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone23_direction_v2_0,
		{ "Zone 23 Direction", "gvcp.bootstrap.sczdx.zone23direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000100,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone24_direction_v2_0,
		{ "Zone 24 Direction", "gvcp.bootstrap.sczdx.zone24direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000080,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone25_direction_v2_0,
		{ "Zone 25 Direction", "gvcp.bootstrap.sczdx.zone25direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000040,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone26_direction_v2_0,
		{ "Zone 26 Direction", "gvcp.bootstrap.sczdx.zone26direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000020,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone27_direction_v2_0,
		{ "Zone 27 Direction", "gvcp.bootstrap.sczdx.zone27direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000010,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone28_direction_v2_0,
		{ "Zone 28 Direction", "gvcp.bootstrap.sczdx.zone28direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000008,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone29_direction_v2_0,
		{ "Zone 29 Direction", "gvcp.bootstrap.sczdx.zone29direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000004,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone30_direction_v2_0,
		{ "Zone 30 Direction", "gvcp.bootstrap.sczdx.zone30direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000002,
		NULL, HFILL
		}},

		{ &hf_gvcp_sc_zone31_direction_v2_0,
		{ "Zone 31 Direction", "gvcp.bootstrap.sczdx.zone31direction",
		FT_BOOLEAN, 32, TFS(&zonedirectionnames), 0x00000001,
		NULL, HFILL
		}},

		/* GVCP_SC_MAX_PACKET_COUNT(0), 1, 2, 3 */

		{ &hf_gvcp_sc_max_packet_count_v2_2,
		{ "Max. Packet Count", "gvcp.bootstrap.scmpcx.maxpacketcount",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_SC_MAX_BLOCK_SIZE_HIGH(0), 1, 2, 3 */

		{ &hf_gvcp_sc_max_block_size_high_v2_2,
		{ "Max. Block Size (High)", "gvcp.bootstrap.maxblocksizehigh",
		FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_SC_MAX_BLOCK_SIZE_LOW(0), 1, 2, 3 */

		{ &hf_gvcp_sc_max_block_size_low_v2_2,
		{ "Max. Payload Size (Low)", "gvcp.bootstrap.maxblocksizelow",
		FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_SC_EXTENDED_BOOTSTRAP_ADDRESS(0), 1, 2, 3 */

		{ &hf_gvcp_sc_extended_registers_address_v2_2,
		{ "Stream Channel Extended Bootstrap Address", "gvcp.bootstrap.extendedbootstrapaddress",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_SC_GENDC_DESCRIPTOR_ADDRESS(0), 1, 2, 3 */

		{ &hf_gvcp_sc_gendc_descriptor_address_v2_2,
		{ "Stream Channel GenDC Descriptor Address", "gvcp.bootstrap.gendc.descriptoraddress",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_SC_GENDC_DESCRIPTOR_SIZE(0), 1, 2, 3 */

		{ &hf_gvcp_sc_gendc_descriptor_size_v2_2,
		{ "Stream Channel GenDC Descriptor Size", "gvcp.bootstrap.gedc.descriptorsize",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_SC_GENDC_FLOW_MAPPING_TABLE_ADDRESS(0), 1, 2, 3 */

		{ &hf_gvcp_sc_gendc_flow_mapping_table_address_v2_2,
		{ "Stream Channel GenDC Flow Mapping Table Address", "gvcp.bootstrap.gendc.flowmappingtableaddress",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_SC_GENDC_FLOW_MAPPING_TABLE_SIZE(0), 1, 2, 3 */

		{ &hf_gvcp_sc_gendc_flow_mapping_table_size_v2_2,
		{ "Stream Channel GenDC Flow Mapping Table Size", "gvcp.bootstrap.gendc.flowmappingtablesize",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		} },

		/* GVCP_ACTION_GROUP_KEY(0), 1, 2, 3, 4, 5, 6, 7, 8, 9 */

		{ &hf_gvcp_action_group_key,
		{ "Action Group Key", "gvcp.bootstrap.actiongroupkey",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},

		/* GVCP_ACTION_GROUP_MASK(0), 1, 2, 3, 4, 5, 6, 7, 8, 9 */

		{ &hf_gvcp_action_group_mask,
		{ "Action Group Mask", "gvcp.bootstrap.actiongroupmask",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		}},
/*
		{ &hf_gvcp_latency,
		{ "Latency Value (in us)", "gvcp.bootstrap.latency",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		NULL, HFILL
		}},
*/
		{ &hf_gvcp_custom_register_addr,
		{ "Custom Register Address", "gvcp.bootstrap.custom.register.write",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		}},

		{ &hf_gvcp_custom_memory_addr,
		{ "Custom Memory Address", "gvcp.bootstrap.custom.memory.write",
		FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL
		}},

		/* Request/Response tracking */
		{ &hf_gvcp_response_in,
		{ "Response In", "gvcp.response_in",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		"The response to this GVCP request is in this frame", HFILL
		}},

		{ &hf_gvcp_response_to,
		{ "Request In", "gvcp.response_to",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		"This is a response to the GVCP request in this frame", HFILL
		}},

		/* Generated from convert_proto_tree_add_text.pl */
		{ &hf_gvcp_reserved_bit, { "Reserved Bit", "gvcp.reserved_bit", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gvcp_manifest_table, { "Manifest Table", "gvcp.manifest_table", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gvcp_custom_register_value, { "Value", "gvcp.bootstrap.custom.register.value", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_gvcp_custom_read_register_addr, { "Custom Register Address", "gvcp.bootstrap.custom.register.read", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_gvcp_custom_read_register_value, { "Custom Register Value", "gvcp.bootstrap.custom.register.read_value", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_gvcp_readmemcmd_data_read, { "Data read", "gvcp.cmd.readmem.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_gvcp,
		&ett_gvcp_cmd,
		&ett_gvcp_flags,
		&ett_gvcp_ack,
		&ett_gvcp_payload_cmd,
		&ett_gvcp_payload_ack,
		&ett_gvcp_payload_ack_subtree,
		&ett_gvcp_payload_cmd_subtree,
		&ett_gvcp_bootstrap_fields
	};

	proto_gvcp = proto_register_protocol("GigE Vision Control Protocol", "GVCP", "gvcp");

	gvcp_handle = register_dissector("gvcp", dissect_gvcp, proto_gvcp);

	proto_register_field_array(proto_gvcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* The registration hand-off routing */

void proto_reg_handoff_gvcp(void)
{
	dissector_add_uint("udp.port", global_gvcp_port, gvcp_handle);
	gvsp_handle = find_dissector("gvsp");
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
