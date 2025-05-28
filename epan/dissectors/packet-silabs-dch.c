/* packet-silabs_dch.c
 * Routines for Silicon Labs Debug Channel dissection
 * Copyright 2023, Dhruv Chandwani <dhchandw@silabs.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Silabs Debug Channel is a protocol that is used for PTI (Packet Trace) data
 * to flow from the Silicon Labs chips, via the adapter firmware into the PC of a developer.
 *
 * Packet Trace (PTI) is a functionality of Silicon Labs radio chips, which allows
 * for the information about radio operation to be transferred to the observing
 * hardware via a dedicated PTI pin (or two) on the Silicon Labs Radio Microcontroller.
 *
 * Silabs Debug Channel can also be used for other event-based data transfer, but PTI is the primary use case.
 *
 * Spec - https://github.com/SiliconLabs/java_packet_trace_library/blob/master/doc/debug-channel.md
 */

/* Include files */
#include "config.h"
#include <wireshark.h>
#include <wiretap/wtap.h>
#include <wsutil/bitswap.h>
#include <epan/packet.h> /* Required dissection API header */
#include <epan/expert.h> /* Include only as needed */
#include <epan/prefs.h>  /* Include only as needed */
#include "packet-tls.h"

#define WS_LOG_DOMAIN "silabs_dch"

/* Protocol identifier, populated by registration */
static int proto_silabs_dch;

// Field identifiers, populated by registration.
/* Debug Channel Header */
static int hf_dch_version;
static int hf_dch_timestamp;
static int hf_dch_type;
static int hf_dch_flags;
static int hf_dch_sequence;

/* EFR32 */
static int hf_efr32;
static int hf_efr32_hwstart;
static int hf_efr32_phr;
static int hf_efr32_phr_packetlen;
static int hf_efr32_2bytephr;
static int hf_efr32_4bytephr;
static int hf_efr32_hwend;
static int hf_efr32_rssi;
static int hf_efr32_syncword;
static int hf_efr32_radiocfg;
static int hf_efr32_phyid;
static int hf_efr32_radiocfg_addedbytes;
static int hf_ef32_radiocfg_blephyid;
static int hf_efr32_radiocfg_regionid;
static int hf_efr32_radiocfg_2bytephr;
static int hf_efr32_radiocfg_softmodem;
static int hf_efr32_radiocfg_external;
static int hf_efr32_radiocfg_id;
static int hf_efr32_radioinfo;
static int hf_efr32_radioinfo_antenna;
static int hf_efr32_radioinfo_syncword;
static int hf_efr32_radioinfo_channel;
static int hf_efr32_channel;
static int hf_efr32_status;
static int hf_efr32_status_errorcode;
static int hf_efr32_status_protocolid;
static int hf_efr32_appendedinfocfg;
static int hf_efr32_appendedinfocfg_txrx;
static int hf_efr32_appendedinfocfg_length;
static int hf_efr32_appendedinfocfg_version;

/* Wi-SUN PHY Header */
static int hf_phr_fsk;
static int hf_phr_wisun_fsk_ms;
static int hf_phr_ofdm;

static int hf_phr_fsk_ms;
static int hf_phr_fsk_fcs;
static int hf_phr_fsk_dw;
static int hf_phr_fsk_length;

static int hf_phr_fsk_ms_checksum;
static int hf_phr_fsk_ms_parity;

static int hf_phr_wisun_fsk_ms_reserved;
static int hf_phr_wisun_fsk_ms_phymodeid;

static int hf_phr_ofdm_rate;
static int hf_phr_ofdm_length;
static int hf_phr_ofdm_scrambler;

/* Expert info fields - used for warnings and notes*/
static expert_field ei_silabs_dch_unsupported_type = EI_INIT;
static expert_field ei_silabs_dch_unsupported_protocol = EI_INIT;
static expert_field ei_silabs_dch_invalid_appendedinfolen = EI_INIT;

/* Bit-mask for the EFR32 phr field */
#define EFR32_PHR_PACKETLEN_MASK 0xFF

/* Bit-masks for the EFR32 radio-cfg field */
#define EFR32_RADIOCFG_ADDEDBYTES_MASK 0xF8
#define EFR32_RADIOCFG_BLEPHYID_MASK 0x03
#define EFR32_RADIOCFG_REGIONID_MASK 0x1F
#define EFR32_RADIOCFG_2BYTEPHR_MASK 0x80
#define EFR32_RADIOCFG_SOFTMODEM_MASK 0x40
#define EFR32_RADIOCFG_EXTERNAL_MASK 0x10
#define EFR32_RADIOCFG_ID_MASK 0x07

/* Bit-masks for the EFR32 radio-info field */
#define EFR32_RADIOINFO_ANTENNA_MASK 0x80
#define EFR32_RADIOINFO_SYNCWORD_MASK 0x40
#define EFR32_RADIOINFO_CHANNEL_MASK 0x3F

/* Bit-masks for the EFR32 status field */
#define EFR32_STATUS_ERRORCODE_MASK 0xF0
#define EFR32_STATUS_PROTOCOLID_MASK 0x0F

/* Bit-masks for the EFR32 appended info cfg field */
#define EFR32_APPENDEDINFOCFG_TXRX_MASK 0x40
#define EFR32_APPENDEDINFOCFG_LENGTH_MASK 0x38
#define EFR32_APPENDEDINFOCFG_VERSION_MASK 0x07

/* Bit-masks for Wi-SUN PHY Header */
#define PHR_FSK_MS 0x8000
#define PHR_FSK_FCS 0x1000
#define PHR_FSK_DW 0x0800
#define PHR_FSK_LENGTH 0x07ff

#define PHR_FSK_MS_CHECKSUM 0x001E
#define PHR_FSK_MS_PARITY 0x0001

#define PHR_WISUN_FSK_MS_RESERVED 0x6000
#define PHR_WISUN_FSK_MS_PHYMODEID 0x1FE0

#define PHR_OFDM_RATE 0xF80000
#define PHR_OFDM_LENGTH 0x03FF80
#define PHR_OFDM_SCRAMBLER 0x000018

// --------------------

/* Subtree identifiers, populated by registration */
static int ett_silabs_dch;
static int ett_silabs_efr32;
static int ett_silabs_efr32_radiocfg;
static int ett_silabs_efr32_radioinfo;
static int ett_silabs_efr32_status;
static int ett_silabs_efr32_appendedinfo;
static int ett_silabs_efr32_phr;
static int *ett[] = {
    &ett_silabs_dch,
    &ett_silabs_efr32,
    &ett_silabs_efr32_radiocfg,
    &ett_silabs_efr32_radioinfo,
    &ett_silabs_efr32_status,
    &ett_silabs_efr32_appendedinfo,
    &ett_silabs_efr32_phr,
};

// Structs and other types
typedef struct
{
  const char *title;
  int8_t crcLen;
} ProtocolInfo;

typedef struct
{
  uint8_t length;
  uint8_t version;
  bool hasRssi;
  bool hasSyncword;
  bool hasRadioCfg;
  uint8_t rssiLen;
  uint8_t syncwordLen;
  uint8_t radioCfgLen;
  bool isInvalid;
} Efr32AppendedInfo;

typedef enum
{
  PHR_RAW = 0,
  PHR_SUN_FSK = 6,
  PHR_SUN_OFDM = 7,
  PHR_WISUN_FSK_MS = 18,
} phr_type_t;
// --------------------

/* Silabs Debug Channel Dissector Handle */
static dissector_handle_t silabs_dch_handle;

/* Handoff dissector handles */
static dissector_handle_t ieee802154nofcs_handle;

// Function declarations
/* Prototypes for required functions. */
void proto_reg_handoff_silabs_dch(void);
void proto_register_silabs_dch(void);

/* Dissector functions */
static int dissect_silabs_dch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int dissect_silabs_efr32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_silabs_wisun_phr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t phr_len, uint8_t phy_mode_id, int ota_payload_len, int *crc_len);

/* Helper functions */
static const Efr32AppendedInfo *get_efr32_appended_info(uint8_t appended_info_cfg);
static const ProtocolInfo *get_protocol_info(uint8_t protocol_id);
static int decode_wisun_phr_type(tvbuff_t *tvb, int offset, uint8_t phr_len, uint8_t phy_mode_id, int ota_payload_len);
static int decode_channel_number(tvbuff_t *tvb, proto_tree *tree, int offset, uint8_t radioinfo_channel, uint8_t radiocfg_id, uint8_t protocol_id);
static uint16_t reverse_bits_uint16(uint16_t value);
static uint8_t get_phr_length(uint8_t protocol_id, tvbuff_t *tvb, int last_index, uint8_t radioCfgLen);
static uint8_t get_phy_mode_id(uint8_t protocol_id, tvbuff_t *tvb, int last_index, uint8_t radioCfgLen);
// --------------------

/* Debug channel message types*/
static const value_string silabs_dch_message_types[] = {
    {0x0000, "Time synchronization notice"},
    {0x0001, "Reset notice"},
    {0x0002, "Application printf"},
    {0x0003, "API trace"},
    {0x0004, "Assertion notice"},
    {0x0005, "Core dump"},
    {0x0006, "Phy Rx"},
    {0x0007, "API Rx"},
    {0x0008, "Phy Tx"},
    {0x0009, "API Tx"},
    {0x000A, "Sniffer packet"},
    {0x000B, "Adapter error"},
    {0x000C, "Statistics"},
    {0x000D, "Time sync test"},
    {0x000E, "Radio reboot count"},
    {0x0011, "Virtual UART Tx"},
    {0x0012, "Virtual UART Rx"},
    {0x0020, "2420 Tx packet"},
    {0x0021, "2420 Rx packet"},
    {0x0022, "250 Tx packet"},
    {0x0023, "250 Rx packet"},
    {0x0024, "350 Tx packet"},
    {0x0025, "350 Rx packet"},
    {0x0026, "Pro2+ Tx packet"},
    {0x0027, "Pro2+ Rx packet"},
    {0x0028, "Pro2+ debug packet"},
    {0x0029, "EFR Tx packet"},
    {0x002A, "EFR Rx packet"},
    {0x002B, "EFR additional PTI data"},
    {0x0030, "Flash read request"},
    {0x0031, "Flash read response"},
    {0x0032, "EEPROM read request"},
    {0x0033, "EEPROM read response"},
    {0x0034, "EEPROM write request"},
    {0x0035, "EEPROM write response"},
    {0x0036, "RAM read request"},
    {0x0037, "RAM read response"},
    {0x0038, "RAM write request"},
    {0x0039, "RAM write response"},
    {0x003A, "Info request"},
    {0x003B, "Node information"},
    {0x003C, "EmberZNet serial protocol"},
    {0x003D, "ASH protocol"},
    {0x003E, "DAG trace"},
    {0x003F, "Simulated NCP callback ready"},
    {0x0040, "Simulated wakeup signal to NCP"},
    {0x0041, "Simulated signal to host that NCP is awake"},
    {0x0042, "Ember ZNet stack version"},
    {0x0043, "Ember IP stack version"},
    {0x0044, "Current time information"},
    {0x0045, "Memory use information"},
    {0x0046, "Mustang API message"},
    {0x0047, "Latency"},
    {0x0048, "TMSP"},
    {0x0050, "AEM sample"},
    {0x0051, "AEM counters snapshot"},
    {0x0060, "AEM request"},
    {0x0061, "AEM response"},
    {0x0062, "AEM current packet"},
    {0x0063, "AEM current packet v2"},
    {0x0064, "PC sample packet"},
    {0x0065, "Exception packet"},
    {0x0066, "Logic analyzer data"},
    {0x0070, "CPU usage"},
    {0x0080, "Configuration over SWO"},
    {0xFFFE, "User command"},
    {0xFFFF, "User response"},
    {0, NULL}};

/* Efr32 HW start values*/
static const value_string silabs_efr32_hwstart_values[] = {
    {0xF8, "Rx Start"},
    {0xFC, "Tx Start"},
    {0xF0, "DMP Protocol Switch"},
    {0, NULL}};

/* Efr32 HW end values*/
static const value_string silabs_efr32_hwend_values[] = {
    {0xF9, "Rx Success"},
    {0xFA, "Rx Abort"},
    {0xFD, "Tx Success"},
    {0xFE, "Tx Abort"},
    {0, NULL}};

/* Efr32 protocol id values*/
static const value_string silabs_efr32_status_protcolid_values[] = {
    {0x00, "Custom"},
    {0x01, "EmberPHY (Zigbee/Thread)"},
    {0x02, "Thread on RAIL"},
    {0x03, "BLE"},
    {0x04, "Connect on RAIL"},
    {0x05, "Zigbee on RAIL"},
    {0x06, "Z-Wave on RAIL"},
    {0x07, "Wi-SUN on RAIL"},
    {0x08, "Custom on 802.15.4 built-in PHY"},
    {0x09, "Amazon SideWalk"},
    {0x0A, "Bluetooth Classic"},
    {0, NULL}};

/* Efr32 tx/rx values*/
static const value_string silabs_efr32_appendedinfocfg_txrx_values[] = {
    {0x00, "Tx"},
    {0x01, "Rx"},
    {0, NULL}};

/* Wi-SUN PHR Values*/
static const value_string phr_wisun_phymodeid_values[] = {
    {1, "FSK #1a 50ksym/s mod-index 0.5"},
    {2, "FSK #1b 50ksym/s mod-index 1.0"},
    {3, "FSK #2a 100ksym/s mod-index 0.5"},
    {4, "FSK #2b 100ksym/s mod-index 1.0"},
    {5, "FSK #3 150ksym/s mod-index 0.5"},
    {6, "FSK #4a 200ksym/s mod-index 0.5"},
    {7, "FSK #4b 200ksym/s mod-index 1.0"},
    {8, "FSK #5 300ksym/s mod-index 0.5"},
    {17, "FSK with FEC #1a 50ksym/s mod-index 0.5"},
    {18, "FSK with FEC #1b 50ksym/s mod-index 1.0"},
    {19, "FSK with FEC #2a 100ksym/s mod-index 0.5"},
    {20, "FSK with FEC #2b 100ksym/s mod-index 1.0"},
    {21, "FSK with FEC #3 150ksym/s mod-index 0.5"},
    {22, "FSK with FEC #4a 200ksym/s mod-index 0.5"},
    {23, "FSK with FEC #4b 200ksym/s mod-index 1.0"},
    {24, "FSK with FEC #5 300ksym/s mod-index 0.5"},
    {34, "OFDM Option 1 MCS 2 400kbps"},
    {35, "OFDM Option 1 MCS 3 800kbps"},
    {36, "OFDM Option 1 MCS 4 1200kbps"},
    {37, "OFDM Option 1 MCS 5 1600kbps"},
    {38, "OFDM Option 1 MCS 6 2400kbps"},
    {51, "OFDM Option 2 MCS 3 400kbps"},
    {52, "OFDM Option 2 MCS 4 600kbps"},
    {53, "OFDM Option 2 MCS 5 800kbps"},
    {54, "OFDM Option 2 MCS 6 1200kbps"},
    {68, "OFDM Option 3 MCS 4 300kbps"},
    {69, "OFDM Option 3 MCS 5 400kbps"},
    {70, "OFDM Option 3 MCS 6 600kbps"},
    {84, "OFDM Option 4 MCS 4 150kbps"},
    {85, "OFDM Option 4 MCS 5 200kbps"},
    {86, "OFDM Option 4 MCS 6 300kbps"},
    {0, NULL}};

static const value_string phr_ofdm_rate_values[] = {
    {0, "MCS0"},
    {1, "MCS1"},
    {2, "MCS2"},
    {3, "MCS3"},
    {4, "MCS4"},
    {5, "MCS5"},
    {6, "MCS6"},
    {7, "MCS7"},
    {0, NULL}};

static const value_string phr_ofdm_scrambler_values[] = {
    {0, "000010111"},
    {1, "000011100"},
    {2, "101110111"},
    {3, "101111100"},
    {0, NULL}};

/**
 * Top-level dissector - dissects the debug channel header.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 * @param data data passed (unused)
 * @return offset after dissection
 *
 */
static int dissect_silabs_dch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *dch_root = NULL;
  proto_tree *dch_tree = NULL;
  tvbuff_t *next_tvb;
  int offset = 0;
  uint32_t dch_version, dch_message_type;
  const char *dch_message_type_str;

  // Create the top-level DCH subtree.
  dch_root = proto_tree_add_item(tree, proto_silabs_dch, tvb, offset, -1, ENC_NA);
  dch_tree = proto_item_add_subtree(dch_root, ett_silabs_dch);

  // Decode version, add it to DCH subtree.
  proto_tree_add_item_ret_uint(dch_tree, hf_dch_version, tvb, offset, 2, ENC_LITTLE_ENDIAN, &dch_version);
  offset += 2;

  // Decode timestamp, add it to DCH subtree. Timestamp is 8 bytes in later versions, but only 6 in version 2.
  if (dch_version > 2)
  {
    proto_tree_add_item(dch_tree, hf_dch_timestamp, tvb, offset, 8, ENC_TIME_NSECS | ENC_LITTLE_ENDIAN);
    offset += 8;
  }
  else
  {
    proto_tree_add_item(dch_tree, hf_dch_timestamp, tvb, offset, 6, ENC_TIME_USECS | ENC_LITTLE_ENDIAN);
    offset += 6;
  }

  // Decode message type, add it to DCH subtree. Use the message type descriptions
  // from the array above.
  proto_tree_add_item_ret_uint(dch_tree, hf_dch_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &dch_message_type);
  dch_message_type_str = val_to_str_const(dch_message_type, silabs_dch_message_types, "Unknown");
  offset += 2;
  col_add_fstr(pinfo->cinfo, COL_INFO, "Debug Message Type: %s", dch_message_type_str);

  // Decode flags (if exists) and sequence, honor differences between version 2 and version 3.
  if (dch_version > 2)
  {
    proto_tree_add_item(dch_tree, hf_dch_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(dch_tree, hf_dch_sequence, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
  }
  else
  {
    proto_tree_add_item(dch_tree, hf_dch_sequence, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
  }

  // get debug message payload
  next_tvb = tvb_new_subset_remaining(tvb, offset);

  // Decode dch payload by dch message type
  switch (dch_message_type)
  {
  case 0x02A:
  case 0x029:
    // hand debug message payload to EFR32 dissector
    offset = dissect_silabs_efr32(next_tvb, pinfo, tree);
    break;
  default:
    proto_tree_add_expert_format(dch_tree, pinfo, &ei_silabs_dch_unsupported_type, tvb, offset, -1, "Debug message type - %s not supported yet", dch_message_type_str);
    break;
  }

  return offset;
}

/**
 * Dissector for Efr32 radio info
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 * @return offset after dissection
 *
 */
static int dissect_silabs_efr32(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *efr32_root;
  proto_item *efr32_tree;
  tvbuff_t *next_tvb;
  int offset = 0;

  // create the EFR32 subtree
  efr32_root = proto_tree_add_item(tree, hf_efr32, tvb, offset, -1, ENC_NA);
  efr32_tree = proto_item_add_subtree(efr32_root, ett_silabs_efr32);

  // decode hw start, add to subtree
  proto_tree_add_item(efr32_tree, hf_efr32_hwstart, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  int last_index;
  uint8_t protocol_id;
  uint8_t appended_info_cfg;
  uint8_t status_byte;
  uint8_t phr_len;
  const ProtocolInfo *protocol;
  const Efr32AppendedInfo *appended_info;

  // decode radio appended info details
  last_index = offset + tvb_reported_length_remaining(tvb, offset) - 1;
  appended_info_cfg = tvb_get_uint8(tvb, last_index);
  appended_info = get_efr32_appended_info(appended_info_cfg);

  // check if appended info len is invalid
  if (appended_info->isInvalid)
  {
    proto_tree_add_expert_format(efr32_tree, pinfo, &ei_silabs_dch_invalid_appendedinfolen, tvb, offset, -1, "Invalid Appended Info Length");
    return offset;
  }

  // decode protocol
  status_byte = tvb_get_uint8(tvb, last_index - 1);
  protocol_id = 0x0000000F & status_byte;
  protocol = get_protocol_info(protocol_id);

  // determine OTA Payload -> (PHR + Payload + CRC)
  int crc_len = (protocol->crcLen != -1) ? protocol->crcLen : 2; // Dynamic crc length (indicated by -1) not supported yet, default to 2
  int ota_payload_len = last_index + 1 - offset - appended_info->length - 1;

  // decode PHR Length and PHR
  phr_len = get_phr_length(protocol_id, tvb, last_index, appended_info->radioCfgLen);
  switch (protocol_id)
  {
  case 7:
  { // Further dissect Wi-SUN PHR
    uint8_t phy_mode_id = get_phy_mode_id(protocol_id, tvb, last_index, appended_info->radioCfgLen);
    phr_len = dissect_silabs_wisun_phr(tvb, pinfo, efr32_tree, offset, phr_len, phy_mode_id, ota_payload_len, &crc_len);
    break;
  }
  case 2: // Thread on RAIL
  case 5: // Zigbee on RAIL
  case 8: // Custom on 802.15.4 built-in PHY
  {
    static int *const efr32_phr_fields[] = {
        &hf_efr32_phr_packetlen,
        NULL};

    switch (phr_len)
    {
    case 1:
      proto_tree_add_bitmask(efr32_tree, tvb, offset, hf_efr32_phr, ett_silabs_efr32_phr, efr32_phr_fields, ENC_LITTLE_ENDIAN);
      break;
    case 2:
      proto_tree_add_item(efr32_tree, hf_efr32_2bytephr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      break;
    case 4:
      proto_tree_add_item(efr32_tree, hf_efr32_4bytephr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      break;
    default:
      break;
    }
  }
  }
  // Adjust offset and ota_payload_len after PHR
  offset += phr_len;
  ota_payload_len -= phr_len;
  // Adjust ota_payload_len for crc
  ota_payload_len = (ota_payload_len > 0) ? (ota_payload_len - crc_len) : ota_payload_len;

  // create next tvb for ota payload
  next_tvb = tvb_new_subset_length(tvb, offset, ota_payload_len);

  // hand ota payload to protocol dissector
  if (ota_payload_len > 0)
  {
    switch (protocol_id)
    {
    case 2: // Thread on RAIL
    case 5: // Zigbee on RAIL
    case 7: // Wi-SUN on RAIL
    case 8: // Custom on 802.15.4 built-in PHY
      call_dissector(ieee802154nofcs_handle, next_tvb, pinfo, tree);
      break;
    default:
      proto_tree_add_expert_format(efr32_tree, pinfo, &ei_silabs_dch_unsupported_protocol, tvb, offset, -1, "Protocol - %s not supported yet", protocol->title);
      break;
      // TODO: add support for the following protocols
      // case 1: // EFR32 EmberPHY (Zigbee/Thread)
      // case 3: // BLE
      // case 4: // Connect on RAIL
      // case 6: // Z-Wave on RAIL
      // case 9: // Amazon SideWalk
    }
    offset += ota_payload_len;
  }

  // account for CRC if present
  offset = (ota_payload_len > 0) ? offset + crc_len : offset;

  // decode hw end, add to subtree
  proto_tree_add_item(efr32_tree, hf_efr32_hwend, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  // decode rssi, add to subtree
  if (appended_info->hasRssi)
  {
    int8_t rssi = tvb_get_uint8(tvb, offset);
    rssi = (appended_info->version == 1) ? (rssi - 0x32) : rssi;
    proto_tree_add_int_format_value(efr32_tree, hf_efr32_rssi, tvb, offset, appended_info->rssiLen, rssi, "%d dBm", rssi);
    offset += appended_info->rssiLen;
  }

  // decode syncword, add to subtree
  if (appended_info->hasSyncword)
  {
    proto_tree_add_item(efr32_tree, hf_efr32_syncword, tvb, offset, appended_info->syncwordLen, ENC_LITTLE_ENDIAN);
    offset += appended_info->syncwordLen;
  }

  // decode radio cfg, add to subtree
  static int *const efr32_radiocfg_ble_fields[] = {
      &hf_efr32_radiocfg_addedbytes,
      &hf_ef32_radiocfg_blephyid,
      NULL};
  static int *const efr32_radiocfg_zwave_fields[] = {
      &hf_efr32_radiocfg_regionid,
      NULL};
  static int *const efr32_radiocfg_154_fields[] = {
      &hf_efr32_radiocfg_2bytephr,
      &hf_efr32_radiocfg_softmodem,
      &hf_efr32_radiocfg_external,
      &hf_efr32_radiocfg_id,
      NULL};
  uint8_t radiocfg_id = 0;
  if (appended_info->hasRadioCfg)
  {
    switch (protocol_id)
    {
    case 3: // BLE
      proto_tree_add_bitmask(efr32_tree, tvb, offset, hf_efr32_radiocfg, ett_silabs_efr32_radiocfg, efr32_radiocfg_ble_fields, ENC_LITTLE_ENDIAN);
      break;
    case 6: // Z-Wave on RAIL
      proto_tree_add_bitmask(efr32_tree, tvb, offset, hf_efr32_radiocfg, ett_silabs_efr32_radiocfg, efr32_radiocfg_zwave_fields, ENC_LITTLE_ENDIAN);
      break;
    case 1:
    case 2:
    case 5:
    case 7:
    case 8:
    {
      radiocfg_id = tvb_get_uint8(tvb, offset) & EFR32_RADIOCFG_ID_MASK;
      proto_tree_add_bitmask(efr32_tree, tvb, offset, hf_efr32_radiocfg, ett_silabs_efr32_radiocfg, efr32_radiocfg_154_fields, ENC_LITTLE_ENDIAN);
      break;
    }
    default:
      proto_tree_add_item(efr32_tree, hf_efr32_radiocfg, tvb, offset, appended_info->radioCfgLen, ENC_LITTLE_ENDIAN);
      break;
    }
    offset += 1;
    if (appended_info->radioCfgLen == 2)
    {
      proto_tree_add_item(efr32_tree, hf_efr32_phyid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;
    }
  }

  // decode radio info, add to subtree
  static int *const efr32_radioinfo_fields[] = {
      &hf_efr32_radioinfo_antenna,
      &hf_efr32_radioinfo_syncword,
      &hf_efr32_radioinfo_channel,
      NULL};
  uint8_t radioinfo_channel = tvb_get_uint8(tvb, offset) & EFR32_RADIOINFO_CHANNEL_MASK;
  proto_tree_add_bitmask(efr32_tree, tvb, offset, hf_efr32_radioinfo, ett_silabs_efr32_radioinfo, efr32_radioinfo_fields, ENC_LITTLE_ENDIAN);
  // decode computed channel
  decode_channel_number(tvb, efr32_tree, offset, radioinfo_channel, radiocfg_id, protocol_id);
  offset += 1;

  // decode status, add to subtree
  static int *const efr32_status_fields[] = {
      &hf_efr32_status_errorcode,
      &hf_efr32_status_protocolid,
      NULL};
  proto_tree_add_bitmask(efr32_tree, tvb, offset, hf_efr32_status, ett_silabs_efr32_status, efr32_status_fields, ENC_LITTLE_ENDIAN);
  offset += 1;

  // decode appended info cfg, add to subtree
  static int *const efr32_appendedinfocfg_fields[] = {
      &hf_efr32_appendedinfocfg_txrx,
      &hf_efr32_appendedinfocfg_length,
      &hf_efr32_appendedinfocfg_version,
      NULL};
  proto_tree_add_bitmask(efr32_tree, tvb, offset, hf_efr32_appendedinfocfg, ett_silabs_efr32_appendedinfo, efr32_appendedinfocfg_fields, ENC_LITTLE_ENDIAN);
  offset += 1;

  return offset;
}

/**
 * Dissect Wi-SUN PHY Header
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields
 * @param tree pointer to data tree wireshark uses to display packet.
 * @param offset offset in tvb
 * @param phr_len length of PHY Header
 * @param ota_payload_len length of OTA payload
 * @param crc_len pointer to length of CRC (updated by function)
 * @return offset after dissection
 *
 */
static int dissect_silabs_wisun_phr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t phr_len, uint8_t phy_mode_id, int ota_payload_len, int *crc_len)
{
  // First byte after HW Start can be garbage 0x0b byte
  bool can_be_garbage = (tvb_get_uint8(tvb, offset) == 0x0b);

  // Get PHR Type
  uint8_t garbage_byte_len = 0;
  uint8_t phr_type = decode_wisun_phr_type(tvb, offset, phr_len, phy_mode_id, ota_payload_len);
  // if possible garbage byte is present, try skipping it
  if ((phr_type == PHR_RAW) & can_be_garbage)
  {
    phr_type = decode_wisun_phr_type(tvb, offset + 1, phr_len, phy_mode_id, ota_payload_len - 1);
    if (phr_type != PHR_RAW)
    {
      offset += 1;
      garbage_byte_len = 1;
    }
  }

  // Dissect PHR based of Type
  if (phr_type == PHR_SUN_FSK || phr_type == PHR_WISUN_FSK_MS)
  {

    uint8_t *datax = (uint8_t *)tvb_memdup(pinfo->pool, tvb, offset, 2);
    bitswap_buf_inplace(datax, 2);
    tvbuff_t *reversed_tvb = tvb_new_child_real_data(tvb, datax, 2, 2);
    /* Add the reversed data to the data source list. */
    add_new_data_source(pinfo, reversed_tvb, "decoded_phr");

    if (phr_type == PHR_WISUN_FSK_MS)
    {
      static int *const phr_wisun_fsk_ms_fields[] = {
          &hf_phr_fsk_ms,
          &hf_phr_wisun_fsk_ms_reserved,
          &hf_phr_wisun_fsk_ms_phymodeid,
          &hf_phr_fsk_ms_checksum,
          &hf_phr_fsk_ms_parity,
          NULL};
      proto_tree_add_bitmask(tree, reversed_tvb, 0, hf_phr_wisun_fsk_ms, ett_silabs_efr32_phr, phr_wisun_fsk_ms_fields, ENC_BIG_ENDIAN);
      col_clear(pinfo->cinfo, COL_INFO);
      col_set_str(pinfo->cinfo, COL_INFO, "Wi-SUN FSK Mode Switch PHR");
      *crc_len = 0; // No CRC for Wi-SUN FSK MS since no payload
    }
    else
    {
      static int *const phr_fsk_fields[] = {
          &hf_phr_fsk_ms,
          &hf_phr_fsk_fcs,
          &hf_phr_fsk_dw,
          &hf_phr_fsk_length,
          NULL};
      proto_tree_add_bitmask(tree, reversed_tvb, 0, hf_phr_fsk, ett_silabs_efr32_phr, phr_fsk_fields, ENC_BIG_ENDIAN);
    }
  }
  else if (phr_type == PHR_SUN_OFDM)
  {
    offset += 1;
    *crc_len = 0; // No CRC for OFDM
    uint8_t *datax = (uint8_t *)tvb_memdup(pinfo->pool, tvb, offset, 3);
    bitswap_buf_inplace(datax, 3);
    tvbuff_t *reversed_tvb = tvb_new_child_real_data(tvb, datax, 3, 3);
    /* Add the reversed data to the data source list. */
    add_new_data_source(pinfo, reversed_tvb, "decoded_phr");

    static int *const phr_ofdm_fields[] = {
        &hf_phr_ofdm_rate,
        &hf_phr_ofdm_length,
        &hf_phr_ofdm_scrambler,
        NULL};
    proto_tree_add_bitmask(tree, reversed_tvb, 0, hf_phr_ofdm, ett_silabs_efr32_phr, phr_ofdm_fields, ENC_BIG_ENDIAN);
  }
  else
  {
    proto_tree_add_item(tree, hf_efr32_phr, tvb, offset, phr_len, ENC_LITTLE_ENDIAN);
  }
  return phr_len + garbage_byte_len;
}

/**
 * Get Wi-SUN PHY Header Type
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param offset offset in tvb
 * @param phr_len length of PHY Header
 * @param phy_mode_id PHY Mode ID
 * @param ota_payload_len length of OTA payload
 * @return Wi-SUN PHY Header Type
 *
 */
static int decode_wisun_phr_type(tvbuff_t *tvb, int offset, uint8_t phr_len, uint8_t phy_mode_id, int ota_payload_len)
{
  uint8_t phr_type = PHR_RAW;
  if (phr_len == 2)
  {
    /* If PHR length is 2, PHR is either SUN FSK or WISUN FSK MS based on Mode Switch bit*/
    uint16_t phr = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    if ((phr & 0x01) && (ota_payload_len == phr_len))
    {
      phr_type = PHR_WISUN_FSK_MS;
    }
    if ((ota_payload_len - phr_len) == reverse_bits_uint16(phr & 0xFFE0))
    {
      phr_type = PHR_SUN_FSK;
    }
  }
  if ((phr_len == 4) && (phy_mode_id >= 0x20))
  {
    uint32_t phr = tvb_get_uint24(tvb, offset + 1, ENC_LITTLE_ENDIAN);
    uint16_t frame_length = (uint16_t)((phr & 0x0001FFC0) >> 6);
    frame_length = reverse_bits_uint16(frame_length) >> 5;
    if ((ota_payload_len) == frame_length)
    {
      phr_type = PHR_SUN_OFDM;
    }
  }
  return phr_type;
}

/**
 * Decode and add computed channel number to the tree
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param tree pointer to data tree wireshark uses to display packet.
 * @param offset offset in tvb
 * @param radioinfo_channel channel number from radio info
 * @param radiocfg_id radio configuration id
 * @param protocol_id protocol id
 * @return offset
 */
static int decode_channel_number(tvbuff_t *tvb, proto_tree *tree, int offset, uint8_t radioinfo_channel, uint8_t radiocfg_id, uint8_t protocol_id)
{
  int center_freq;
  int formatted_channel = radioinfo_channel;
  proto_item *channel_item;

  switch (protocol_id)
  {
  case 3: // BLE
    center_freq = 2402 + (radioinfo_channel * 2);
    formatted_channel = radioinfo_channel;
    channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
    proto_item_append_text(channel_item, " (RF channel %d, %d MHz)", radioinfo_channel, center_freq);
    break;

  case 1: // EMBER_PHY
  case 2: // THREAD_ON_RAIL
  case 5: // ZIGBEE_ON_RAIL
  case 4: // CONNECT_ON_RAIL
  case 8: // CUSTOM_ON_802_15_4
    switch (radiocfg_id)
    {
    case 0: // OQPSK 2.4GHz
      center_freq = 2405 + (5 * radioinfo_channel);
      formatted_channel = radioinfo_channel + 11;
      channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
      proto_item_append_text(channel_item, " (15.4 Cp0 channel %d, 2.%03d GHz)", formatted_channel, center_freq % 1000);
      break;

    case 1: // BPSK 868MHz
      channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
      proto_item_append_text(channel_item, " (15.4 Cp0 channel %d, 868.3 MHz)", radioinfo_channel);
      break;

    case 2: // BPSK 915MHz
      center_freq = 906 + (2 * radioinfo_channel);
      channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
      proto_item_append_text(channel_item, " (15.4 Cp0 channel %d, %d MHz)", radioinfo_channel, center_freq);
      break;

    case 5: // GFSK 863MHz GB868
      center_freq = 863250 + (200 * radioinfo_channel);
      if (radioinfo_channel < 27)
      {
        formatted_channel = radioinfo_channel;
        channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
        proto_item_append_text(channel_item, " (15.4 Cp28 channel %d, %d.%03d MHz)", formatted_channel, center_freq / 1000, center_freq % 1000);
      }
      else if (radioinfo_channel < 35)
      {
        formatted_channel = radioinfo_channel - 27;
        channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
        proto_item_append_text(channel_item, " (15.4 Cp29 channel %d, %d.%03d MHz)", formatted_channel, center_freq / 1000, center_freq % 1000);
      }
      else if (radioinfo_channel < 62)
      {
        formatted_channel = radioinfo_channel - 35;
        channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
        proto_item_append_text(channel_item, " (15.4 Cp30 channel %d, %d.%03d MHz)", formatted_channel, center_freq / 1000, center_freq % 1000);
      }
      else
      {
        formatted_channel = 8 + radioinfo_channel - 62;
        channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
        proto_item_append_text(channel_item, " (15.4 Cp29 channel %d, %d.%03d MHz)", formatted_channel, center_freq / 1000, center_freq % 1000);
      }
      break;

    case 6: // GFSK 915MHz GB868
      center_freq = 915350 + (200 * radioinfo_channel);
      channel_item = proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
      proto_item_append_text(channel_item, " (15.4 Cp31 channel %d, %d.%03d MHz)", radioinfo_channel, center_freq / 1000, center_freq % 1000);
      break;

    default:
      proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
      break;
    }
    break;

  case 7: // Wi-SUN
  {
    formatted_channel = (radiocfg_id << 6) + radioinfo_channel;
    proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
    break;
  }

  default:
    proto_tree_add_uint(tree, hf_efr32_channel, tvb, offset, 1, formatted_channel);
    break;
  }

  return offset;
}

/**
 * Get protocol info based on protocol id
 *
 * @param protocol_id protocol id
 * @return pointer to ProtocolInfo struct
 *
 */
static const ProtocolInfo *get_protocol_info(uint8_t protocol_id)
{
  ProtocolInfo *protocol_info = wmem_new(wmem_packet_scope(), ProtocolInfo);

  switch (protocol_id)
  {
  case 0:
    *protocol_info = (ProtocolInfo){"Custom", 2};
    break;
  case 1:
    *protocol_info = (ProtocolInfo){"EFR32 EmberPHY", 2};
    break;
  case 2:
    *protocol_info = (ProtocolInfo){"Thread on RAIL", 2};
    break;
  case 3:
    *protocol_info = (ProtocolInfo){"BLE", 3};
    break;
  case 4:
    *protocol_info = (ProtocolInfo){"Connect on RAIL", 2};
    break;
  case 5:
    *protocol_info = (ProtocolInfo){"ZigBee on RAIL", 2};
    break;
  case 6:
    *protocol_info = (ProtocolInfo){"Z-Wave on RAIL", -1};
    break;
  case 7:
    *protocol_info = (ProtocolInfo){"Wi-SUN", 4};
    break;
  default:
    *protocol_info = (ProtocolInfo){"Unknown", 0};
    break;
  }

  return protocol_info;
}

/**
 * Get appended info details based on appended info cfg
 *
 * @param appended_info_cfg appended info cfg byte
 * @return pointer to Efr32AppendedInfo struct
 *
 */
static const Efr32AppendedInfo *get_efr32_appended_info(uint8_t appended_info_cfg)
{
  Efr32AppendedInfo *appended_info = wmem_new(wmem_packet_scope(), Efr32AppendedInfo);
  memset(appended_info, 0, sizeof(Efr32AppendedInfo)); // Initialize all fields to 0 or false
  bool isRx = (appended_info_cfg & 0x00000040) != 0;
  uint8_t var_len = (appended_info_cfg & 0x00000038) >> 3;
  appended_info->length = var_len + 3;
  appended_info->version = (appended_info_cfg & 0x00000007);
  appended_info->isInvalid = false;
  if (isRx)
  {
    switch (var_len)
    {
    case 1:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = true;
      appended_info->hasRadioCfg = false;
      break;
    case 2:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = true;
      appended_info->hasRadioCfg = true;
      break;
    case 3:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = true;
      appended_info->hasRadioCfg = true;
      break;
    case 5:
      appended_info->hasSyncword = true;
      appended_info->hasRssi = true;
      appended_info->hasRadioCfg = false;
      break;
    case 6:
      appended_info->hasSyncword = true;
      appended_info->hasRssi = true;
      appended_info->hasRadioCfg = true;
      break;
    case 7:
      appended_info->hasSyncword = true;
      appended_info->hasRssi = true;
      appended_info->hasRadioCfg = true;
      break;
    default:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = false;
      appended_info->isInvalid = true;
      break;
    }
  }
  else
  {
    switch (var_len)
    {
    case 0:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = false;
      break;
    case 1:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = true;
      break;
    case 2:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = true;
      break;
    case 4:
      appended_info->hasSyncword = true;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = false;
      break;
    case 5:
      appended_info->hasSyncword = true;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = true;
      break;
    case 6:
      appended_info->hasSyncword = true;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = true;
      break;
    default:
      appended_info->hasSyncword = false;
      appended_info->hasRssi = false;
      appended_info->hasRadioCfg = false;
      appended_info->isInvalid = true;
      break;
    }
  }
  appended_info->rssiLen = appended_info->hasRssi ? 1 : 0;
  appended_info->syncwordLen = appended_info->hasSyncword ? 4 : 0;
  if (appended_info->hasRadioCfg)
  {
    if (isRx)
    {
      appended_info->radioCfgLen = (var_len == 3 || var_len == 7) ? 2 : 1;
    }
    else
    {
      appended_info->radioCfgLen = (var_len == 2 || var_len == 6) ? 2 : 1;
    }
  }

  return appended_info;
}

/**
 * Get PHR Length
 *
 * @param protocol_id protocol id
 * @param tvb pointer to buffer containing raw packet.
 * @param last_index last index of tvb
 * @param radioCfgLen radio cfg length
 * @return PHR length
 *
 */
static uint8_t get_phr_length(uint8_t protocol_id, tvbuff_t *tvb, int last_index, uint8_t radioCfgLen)
{
  uint8_t phr_len = 1;
  if (radioCfgLen > 0)
  {
    switch (protocol_id)
    {
    case 1:
    case 2:
    case 5:
    case 7:
    case 8:
    {
      uint8_t radiocfg_byte = tvb_get_uint8(tvb, last_index - radioCfgLen - 2); // radio cfg byte is either 4th byte or 5th byte from the end (depends on existence of radio cfg ext)
      if (radiocfg_byte & (1 << 6))
      {
        phr_len = 4; // if soft modem is used then PHR is always 4 bytes
      }
      else
      {
        phr_len = (radiocfg_byte & (1 << 7)) ? 2 : 1; // bit 7 indicates 2 byte PHR
      }
    }
    break;
    default:
      phr_len = 1;
    }
  }
  return phr_len;
}

/**
 * Get PHY Mode ID
 *
 * @param protocol_id protocol id
 * @param tvb pointer to buffer containing raw packet.
 * @param last_index last index of tvb
 * @param radioCfgLen radio cfg length
 * @return PHY Mode ID
 *
 */
static uint8_t get_phy_mode_id(uint8_t protocol_id, tvbuff_t *tvb, int last_index, uint8_t radioCfgLen)
{
  uint8_t phy_mode_id = 0;
  // PHY Mode ID is present only in Radio Cfg Ext for 15.4
  if (radioCfgLen == 2)
  {
    switch (protocol_id)
    {
    case 1:
    case 2:
    case 5:
    case 7:
    case 8:
      phy_mode_id = tvb_get_uint8(tvb, last_index - radioCfgLen - 1);
      break;
    default:
      phy_mode_id = 0;
    }
  }
  return phy_mode_id;
}

/**
 * Reverse the bits of a uint16_t value.
 *
 * @param value The uint16_t value to reverse.
 * @return The bit-reversed uint16_t value.
 */
static uint16_t reverse_bits_uint16(uint16_t value)
{
  value = ((value & 0x5555) << 1) | ((value & 0xAAAA) >> 1);
  value = ((value & 0x3333) << 2) | ((value & 0xCCCC) >> 2);
  value = ((value & 0x0F0F) << 4) | ((value & 0xF0F0) >> 4);
  value = (value << 8) | (value >> 8);
  return value;
}

// ********************************

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 *
 */
void proto_register_silabs_dch(void)
{
  static hf_register_info hf[] = {
      /* Debug Channel Header */
      {&hf_dch_version,
       {"Version", "silabs-dch.version", FT_UINT16, BASE_DEC, NULL, 0x0, "Debug Channel Version", HFILL}},
      {&hf_dch_timestamp,
       {"Timestamp", "silabs-dch.timestamp", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "Debug Channel Timestamp", HFILL}},
      {&hf_dch_type,
       {"Type", "silabs-dch.type", FT_UINT16, BASE_HEX, VALS(silabs_dch_message_types), 0x0, "Debug Message Type", HFILL}},
      {&hf_dch_flags,
       {"Flags", "silabs-dch.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "Debug Channel Flags", HFILL}},
      {&hf_dch_sequence,
       {"Sequence", "silabs-dch.seq", FT_UINT16, BASE_DEC, NULL, 0x0, "Debug Channel Sequence", HFILL}},

      /* EFR32 */
      {&hf_efr32,
       {"Silabs EFR32 Radio Info", "silabs-dch.efr32", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
      {&hf_efr32_hwstart,
       {"HW Start", "silabs-dch.hwstart", FT_UINT8, BASE_HEX, VALS(silabs_efr32_hwstart_values), 0x0, "EFR32 HW Start", HFILL}},
      {&hf_efr32_phr,
       {"PHR", "silabs-dch.phr", FT_UINT8, BASE_DEC, NULL, 0x0, "EFR32 PHR", HFILL}},
      {&hf_efr32_phr_packetlen,
       {"Packet Length", "silabs-dch.phr_packetlen", FT_UINT8, BASE_DEC, NULL, EFR32_PHR_PACKETLEN_MASK, "EFR32 PHR Packet Length", HFILL}},
      {&hf_efr32_2bytephr,
       {"2-Byte PHR", "silabs-dch.phr_2bytephr", FT_UINT16, BASE_DEC, NULL, 0x0, "EFR32 PHR 2-Byte", HFILL}},
      {&hf_efr32_4bytephr,
       {"4-Byte PHR", "silabs-dch.phr_4bytephr", FT_UINT32, BASE_DEC, NULL, 0x0, "EFR32 PHR 4-Byte", HFILL}},
      {&hf_efr32_hwend,
       {"HW End", "silabs-dch.hwend", FT_UINT8, BASE_HEX, VALS(silabs_efr32_hwend_values), 0x0, "EFR32 HW End", HFILL}},
      {&hf_efr32_rssi,
       {"RSSI", "silabs-dch.rssi", FT_INT8, BASE_DEC, NULL, 0x0, "EFR32 RSSI", HFILL}},
      {&hf_efr32_syncword,
       {"Syncword", "silabs-dch.syncword", FT_UINT32, BASE_HEX, NULL, 0x0, "EFR32 Syncword", HFILL}},
      {&hf_efr32_radiocfg,
       {"Radio Config", "silabs-dch.radio_cfg", FT_UINT8, BASE_HEX, NULL, 0x0, "EFR32 Radio Config", HFILL}},
      {&hf_efr32_phyid,
       {"Phy ID", "silabs-dch.phy_id", FT_UINT8, BASE_HEX, NULL, 0x0, "EFR32 Phy ID", HFILL}},
      {&hf_efr32_radiocfg_addedbytes,
       {"Added Bytes", "silabs-dch.radio_cfg_addedbytes", FT_UINT8, BASE_HEX, NULL, EFR32_RADIOCFG_ADDEDBYTES_MASK, "EFR32 Radio Config Added Bytes", HFILL}},
      {&hf_ef32_radiocfg_blephyid,
       {"BLE PHY Id", "silabs-dch.radio_cfg_blephyid", FT_UINT8, BASE_HEX, NULL, EFR32_RADIOCFG_BLEPHYID_MASK, "EFR32 Radio Config BLE PHY Id", HFILL}},
      {&hf_efr32_radiocfg_regionid,
       {"Z-Wave Region ID", "silabs-dch.radio_cfg_regionid", FT_UINT8, BASE_HEX, NULL, EFR32_RADIOCFG_REGIONID_MASK, "EFR32 Radio Config Z-Wave Region ID", HFILL}},
      {&hf_efr32_radiocfg_2bytephr,
       {"2-Byte PHR", "silabs-dch.radio_cfg_2bytephr", FT_BOOLEAN, 8, NULL, EFR32_RADIOCFG_2BYTEPHR_MASK, "EFR32 Radio Config 2-Byte PHR", HFILL}},
      {&hf_efr32_radiocfg_softmodem,
       {"Soft Modem", "silabs-dch.radio_cfg_softmodem", FT_BOOLEAN, 8, NULL, EFR32_RADIOCFG_SOFTMODEM_MASK, "EFR32 Radio Config Soft Modem", HFILL}},
      {&hf_efr32_radiocfg_external,
       {"External Radio Config", "silabs-dch.radio_cfg_external", FT_BOOLEAN, 8, NULL, EFR32_RADIOCFG_EXTERNAL_MASK, "EFR32 Radio Config External", HFILL}},
      {&hf_efr32_radiocfg_id,
       {"Radio Config Id", "silabs-dch.radio_cfg_id", FT_UINT8, BASE_HEX, NULL, EFR32_RADIOCFG_ID_MASK, "EFR32 Radio Config ID", HFILL}},
      {&hf_efr32_radioinfo,
       {"Radio Info", "silabs-dch.radio_info", FT_UINT8, BASE_HEX, NULL, 0x0, "EFR32 Radio Info", HFILL}},
      {&hf_efr32_radioinfo_antenna,
       {"Antenna Select", "silabs-dch.radio_info_antenna", FT_UINT8, BASE_HEX, NULL, EFR32_RADIOINFO_ANTENNA_MASK, "EFR32 Radio Info Antenna", HFILL}},
      {&hf_efr32_radioinfo_syncword,
       {"Syncword Select", "silabs-dch.radio_info_syncword", FT_UINT8, BASE_HEX, NULL, EFR32_RADIOINFO_SYNCWORD_MASK, "EFR32 Radio Info Syncword", HFILL}},
      {&hf_efr32_radioinfo_channel,
       {"Radio Info Channel", "silabs-dch.radio_info_channel", FT_UINT8, BASE_DEC, NULL, EFR32_RADIOINFO_CHANNEL_MASK, "EFR32 Radio Info Channel", HFILL}},
      {&hf_efr32_channel,
       {"Channel", "silabs-dch.channel", FT_UINT16, BASE_DEC, NULL, 0x0, "EFR32 Channel", HFILL}},
      {&hf_efr32_status,
       {"Status", "silabs-dch.status", FT_UINT8, BASE_HEX, NULL, 0x0, "EFR32 Status", HFILL}},
      {&hf_efr32_status_errorcode,
       {"Error Code", "silabs-dch.status_errorcode", FT_UINT8, BASE_HEX, NULL, EFR32_STATUS_ERRORCODE_MASK, "EFR32 Status Error Code", HFILL}},
      {&hf_efr32_status_protocolid,
       {"Protocol", "silabs-dch.status_protocolid", FT_UINT8, BASE_HEX, VALS(silabs_efr32_status_protcolid_values), EFR32_STATUS_PROTOCOLID_MASK, "EFR32 Status Protocol ID", HFILL}},
      {&hf_efr32_appendedinfocfg,
       {"Appended Info Config", "silabs-dch.appended_info_cfg", FT_UINT8, BASE_HEX, NULL, 0x0, "EFR32 Appended Info Config", HFILL}},
      {&hf_efr32_appendedinfocfg_txrx,
       {"Tx/Rx", "silabs-dch.appended_info_cfg_txrx", FT_UINT8, BASE_HEX, VALS(silabs_efr32_appendedinfocfg_txrx_values), EFR32_APPENDEDINFOCFG_TXRX_MASK, "EFR32 Appended Info Config Tx/Rx", HFILL}},
      {&hf_efr32_appendedinfocfg_length,
       {"Appended Info Length", "silabs-dch.appended_info_cfg_length", FT_UINT8, BASE_DEC, NULL, EFR32_APPENDEDINFOCFG_LENGTH_MASK, "EFR32 Appended Info Config Length", HFILL}},
      {&hf_efr32_appendedinfocfg_version,
       {"Appended Info Version", "silabs-dch.appended_info_cfg_version", FT_UINT8, BASE_DEC, NULL, EFR32_APPENDEDINFOCFG_VERSION_MASK, "EFR32 Appended Info Config Version", HFILL}},

      /* Wi-SUN PHY Header */
      {&hf_phr_fsk,
       {"FSK PHR", "silabs-dch.phr_fsk", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_phr_wisun_fsk_ms,
       {"Wi-SUN Mode Switch PHR", "silabs-dch.phr_wisun_fsk_ms", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_phr_ofdm,
       {"OFDM PHR", "silabs-dch.phr_ofdm", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_phr_fsk_ms,
       {"MS", "silabs-dch.phr_fsk.ms", FT_BOOLEAN, 16, NULL, PHR_FSK_MS, "PHR SunFSK MS", HFILL}},
      {&hf_phr_fsk_fcs,
       {"FCS Type", "silabs-dch.phr_fsk.fcs", FT_BOOLEAN, 16, NULL, PHR_FSK_FCS, "PHR SunFSK FCS", HFILL}},
      {&hf_phr_fsk_dw,
       {"DW", "silabs-dch.phr_fsk.dw", FT_BOOLEAN, 16, NULL, PHR_FSK_DW, "Data Whitening", HFILL}},
      {&hf_phr_fsk_length,
       {"Frame Length", "silabs-dch.phr_fsk.length", FT_UINT16, BASE_DEC, NULL, PHR_FSK_LENGTH, NULL, HFILL}},
      {&hf_phr_fsk_ms_checksum,
       {"Checksum", "silabs-dch.phr_fsk_ms.checksum", FT_UINT16, BASE_HEX, NULL, PHR_FSK_MS_CHECKSUM, "BCH(15,11) checksum", HFILL}},
      {&hf_phr_fsk_ms_parity,
       {"Parity", "silabs-dch.phr_fsk_ms.parity", FT_UINT16, BASE_HEX, NULL, PHR_FSK_MS_PARITY, "Parity Check bit", HFILL}},
      {&hf_phr_wisun_fsk_ms_reserved,
       {"Reserved", "silabs-dch.phr_wisun_fsk_ms.reserved", FT_UINT16, BASE_HEX, NULL, PHR_WISUN_FSK_MS_RESERVED, NULL, HFILL}},
      {&hf_phr_wisun_fsk_ms_phymodeid,
       {"PhyModeId", "silabs-dch.phr_wisun_fsk_ms.phymodeid", FT_UINT16, BASE_HEX, VALS(phr_wisun_phymodeid_values), PHR_WISUN_FSK_MS_PHYMODEID, "New Wi-SUN PhyModeId", HFILL}},
      {&hf_phr_ofdm_rate,
       {"Rate", "silabs-dch.phr_ofdm.rate", FT_UINT24, BASE_DEC, VALS(phr_ofdm_rate_values), PHR_OFDM_RATE, NULL, HFILL}},
      {&hf_phr_ofdm_length,
       {"Frame length", "silabs-dch.phr_ofdm.length", FT_UINT24, BASE_DEC, NULL, PHR_OFDM_LENGTH, NULL, HFILL}},
      {&hf_phr_ofdm_scrambler,
       {"Scrambling seed", "silabs-dch.phr_ofdm.scrambler", FT_UINT24, BASE_HEX, VALS(phr_ofdm_scrambler_values), PHR_OFDM_SCRAMBLER, NULL, HFILL}},

  };

  static ei_register_info ei[] = {
      {&ei_silabs_dch_unsupported_type,
       {"silabs-dch.unsupported_dch_msg_type", PI_COMMENTS_GROUP, PI_NOTE, "Unsupported Debug Channel Message Type", EXPFILL}},
      {&ei_silabs_dch_unsupported_protocol,
       {"silabs-dch.unsupported_protocol", PI_COMMENTS_GROUP, PI_NOTE, "Unsupported EFR32 Protocol", EXPFILL}},
      {&ei_silabs_dch_invalid_appendedinfolen,
       {"silabs-dch.invalid_appendedinfolen", PI_MALFORMED, PI_ERROR, "Invalid Appended Info Length", EXPFILL}},
  };

  // Register the protocol
  proto_silabs_dch = proto_register_protocol(
      "Silabs Debug Channel",
      "Silabs DCH",
      "silabs-dch");

  // Register field header
  proto_register_field_array(proto_silabs_dch, hf, array_length(hf));

  // Register subtrees
  proto_register_subtree_array(ett, array_length(ett));

  expert_module_t *expert_silabs_dch;
  expert_silabs_dch = expert_register_protocol(proto_silabs_dch);
  expert_register_field_array(expert_silabs_dch, ei, array_length(ei));

  // Register the dissector, obtain a handle.
  silabs_dch_handle = register_dissector(
      "silabs_dch",
      dissect_silabs_dch,
      proto_silabs_dch);
}

/**
 * Register handoff link
 *
 */
void proto_reg_handoff_silabs_dch(void)
{
  ieee802154nofcs_handle = find_dissector("wpan_nofcs");
  // Register top-level handoff, so that the toplevel WTAP will be
  // decoded by the silabs dch dissector.
  dissector_add_uint(
      "wtap_encap",
      WTAP_ENCAP_SILABS_DEBUG_CHANNEL,
      silabs_dch_handle);
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
