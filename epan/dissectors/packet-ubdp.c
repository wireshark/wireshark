/* packet-ubdp.c
 * Routines for the disassembly of the "Ubiquiti Discovery Protocol (UBDP)"
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

#define UB_TLV_TYPE      0
#define UB_TLV_LENGTH    1

#define UB_HW_ADDR       1
#define UB_HW_IP_ADDR    2
#define UB_FIRMWARE_FULL 3
#define UB_USERNAME      6
#define UB_UPTIME        10
#define UB_HOSTNAME      11
#define UB_PRODUCT       12
#define UB_ESSID         13
#define UB_WLAN_MODE     14
#define UB_SYSTEM_ID     16
#define UB_SEQ_NUM       18
#define UB_HW_ADDR_2     19
#define UB_TYPE          20
#define UB_MODEL         21
#define UB_FIRMWARE      22
#define UB_PLATFORM_VERS 27

void proto_register_ubdp(void);
void proto_reg_handoff_ubdp(void);

static int proto_ubdp = -1;

static int hf_ubdp_version = -1;
static int hf_ubdp_command = -1;
static int hf_ubdp_size = -1;
static int hf_ubdp_type = -1;
static int hf_ubdp_len = -1;
static int hf_ubdp_mac = -1;
static int hf_ubdp_ip = -1;
static int hf_ubdp_firmware_full = -1;
static int hf_ubdp_username = -1;
static int hf_ubdp_uptime = -1;
static int hf_ubdp_hostname = -1;
static int hf_ubdp_product = -1;
static int hf_ubdp_ssid = -1;
static int hf_ubdp_wlan_mode = -1;
static int hf_ubdp_system_id = -1;
static int hf_ubdp_seq_num = -1;
static int hf_ubdp_model = -1;
static int hf_ubdp_firmware = -1;
static int hf_ubdp_platform_vers = -1;
static int hf_ubdp_generic = -1;

static gint ett_ubdp = -1;
static gint ett_ubdp_tlv = -1;

static expert_field ei_ubdp_bad_version = EI_INIT;
static expert_field ei_ubdp_unexpected_len = EI_INIT;

static dissector_handle_t ubdp_handle;

/* Format Identifier */
static const value_string type_vals[] = {
    { UB_HW_ADDR, "MAC Address" },
    { UB_HW_IP_ADDR, "MAC and IP Address" },
    { UB_FIRMWARE_FULL, "Firmware Detailed" },
    { UB_USERNAME, "Username" },
    { UB_UPTIME, "Uptime" },
    { UB_HOSTNAME, "Hostname" },
    { UB_PRODUCT, "Product" },
    { UB_ESSID, "ESSID" },
    { UB_WLAN_MODE, "WLAN Mode" },
    { UB_SYSTEM_ID, "System ID" },
    { UB_SEQ_NUM, "Counter" },
    { UB_HW_ADDR_2, "MAC Address" },
    { UB_TYPE, "Model Type" },
    { UB_MODEL, "Model" },
    { UB_FIRMWARE, "Firmware" },
    { UB_PLATFORM_VERS, "Platform Version"},
    { 0, NULL }
};

static const string_string ubiquiti_vals[] = {
    {"UP4",     "UP4: UniFi Phone-X"},
    {"UP5",     "UP5: UniFi Phone"},
    {"UP5c",    "UP5c: UniFi Phone"},
    {"UP5t",    "UP5t: UniFi Phone-Pro"},
    {"UP5tc",   "UP5tc: UniFi Phone-Pro"},
    {"UP7",     "UP7: UniFi Phone-Executive"},
    {"UP7c",    "UP7c: UniFi Phone-Executive"},
    {"N2N",     "N2N: NanoStation M2"},
    {"p2N",     "p2N: PicoStation M2"},
    {"P6E",     "P6E: mFi mPower Pro"},
    {"US8P150", "US8P150: UniFi Switch 8 POE-150W"},
    {"US16P150","US16P150: UniFi Switch 16 POE-150W"},
    {"US24",    "US24: UniFi Switch 24"},
    {"US24P250","US24P250: UniFi Switch 24 POE-250W"},
    {"US24P500","US24P500: UniFi Switch 24 POE-500W"},
    {"US48",    "US48: UniFi Switch 48"},
    {"US48P500","US48P500: UniFi Switch 48 POE-500W"},
    {"US48P750","US48P750: UniFi Switch 48 POE-750W"},
    {"UGW3",    "UGW3: UniFi Security Gateway"},
    {"UGW4",    "UGW4: UniFi Security Gateway-Pro"},
    {"BZ2",     "BZ2: UniFi AP"},
    {"BZ2LR",   "BZ2LR: UniFi AP-LR"},
    {"U2O",     "U2O: UniFi AP-Outdoor"},
    {"U2HSR",   "U2HSR: UniFi AP-Outdoor+"},
    {"U2IW",    "U2IW: UniFi AP-In Wall"},
    {"U5O",     "U5O: UniFi AP-Outdoor 5G"},
    {"U7E",     "U7E: UniFi AP-AC"},
    {"U7Ev2",   "U7Ev2: UniFi AP-AC v2"},
    {"U7EDU",   "U7EDU: UniFi AP-AC-EDU"},
    {"U7HD",    "U7HD: UniFi AP-AC-HD"},
    {"U7LR",    "U7LR: UniFi AP-AC-LR"},
    {"U7LT",    "U7LT: UniFi AP-AC-Lite"},
    {"U7MSH",   "U7MSH: UniFi AP-AC-Mesh"},
    {"U7MP",    "U7MP: UniFi AP-AC-Mesh-Pro"},
    {"U7O",     "U7O: UniFi AP-AC Outdoor"},
    {"U7P",     "U7P: UniFi AP-Pro"},
    {"U7PG2",   "U7PG2: UniFi AP-AC-Pro Gen2"},
    {NULL,       NULL}
};


static int
dissect_ubdp(tvbuff_t *ubdp_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree  *ubdp_tree, *tlv_tree;
    proto_item  *ubdp_item, *tlv_item;
    guint32     ubdp_length;
    guint32     ubdp_type;
    guint32     version;
    gint offset = 0;
    gchar *uValue;
    const gchar *uModel;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBDP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "UBDP");

    ubdp_item = proto_tree_add_item(tree, proto_ubdp, ubdp_tvb, 0, -1, ENC_NA);
    ubdp_tree = proto_item_add_subtree(ubdp_item, ett_ubdp);

    proto_tree_add_item_ret_uint(ubdp_tree, hf_ubdp_version, ubdp_tvb, offset, 1, ENC_BIG_ENDIAN, &version);
    proto_tree_add_item(ubdp_tree, hf_ubdp_command, ubdp_tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ubdp_tree, hf_ubdp_size, ubdp_tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    offset+=4;

    if (version != 1 && version != 2){
      expert_add_info(pinfo, ubdp_item, &ei_ubdp_bad_version);
      return tvb_captured_length(ubdp_tvb);
    }
    while(tvb_reported_length_remaining(ubdp_tvb, offset) != 0){
        tlv_tree = proto_tree_add_subtree(ubdp_tree, ubdp_tvb, offset + UB_TLV_TYPE, -1, ett_ubdp_tlv, &tlv_item, "");
        proto_tree_add_item_ret_uint(tlv_tree, hf_ubdp_type, ubdp_tvb, offset + UB_TLV_TYPE, 1, ENC_BIG_ENDIAN, &ubdp_type);
        proto_item_set_text(tlv_tree, "%s", val_to_str_const(ubdp_type, type_vals, "Unknown type"));
        proto_tree_add_item_ret_uint(tlv_tree, hf_ubdp_len, ubdp_tvb, offset + UB_TLV_LENGTH, 2, ENC_BIG_ENDIAN, &ubdp_length);
        offset += 3;

        switch(ubdp_type){
          case UB_HW_ADDR:
          case UB_HW_ADDR_2:
            if(ubdp_length == 6){
                proto_tree_add_item(tlv_tree, hf_ubdp_mac, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }else{
                expert_add_info(pinfo, tlv_item, &ei_ubdp_unexpected_len);
                proto_tree_add_item(tlv_tree, hf_ubdp_generic, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }
            break;
          case UB_HW_IP_ADDR:
            if(ubdp_length == 10){
              proto_tree_add_item(tlv_tree, hf_ubdp_mac, ubdp_tvb, offset, 6, ENC_NA);
              proto_tree_add_item(tlv_tree, hf_ubdp_ip, ubdp_tvb, offset + 6, 4, ENC_NA);
            }else{
              expert_add_info(pinfo, tlv_item, &ei_ubdp_unexpected_len);
              proto_tree_add_item(tlv_tree, hf_ubdp_generic, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }
            break;
          case UB_FIRMWARE_FULL:
            proto_tree_add_item(tlv_tree, hf_ubdp_firmware_full, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            break;
          case UB_USERNAME:
            proto_tree_add_item(tlv_tree, hf_ubdp_username, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            break;
          case UB_UPTIME:
            if(ubdp_length == 4){
              proto_tree_add_item(tlv_tree, hf_ubdp_uptime, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }else{
              expert_add_info(pinfo, tlv_item, &ei_ubdp_unexpected_len);
              proto_tree_add_item(tlv_tree, hf_ubdp_generic, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }
            break;
          case UB_HOSTNAME:
            proto_tree_add_item(tlv_tree, hf_ubdp_hostname, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            break;
          case UB_PRODUCT:
            uValue = tvb_get_string_enc(pinfo->pool, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            uModel = try_str_to_str(uValue, ubiquiti_vals);
            proto_tree_add_string(tlv_tree, hf_ubdp_product, ubdp_tvb, offset, ubdp_length, uModel ? uModel : uValue);
            break;
          case UB_ESSID:
            proto_tree_add_item(tlv_tree, hf_ubdp_ssid, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            break;
          case UB_WLAN_MODE:
            if(ubdp_length == 1){
              proto_tree_add_item(tlv_tree, hf_ubdp_wlan_mode, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }else{
              expert_add_info(pinfo, tlv_item, &ei_ubdp_unexpected_len);
              proto_tree_add_item(tlv_tree, hf_ubdp_generic, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }
            break;
          case UB_SYSTEM_ID:
            if(ubdp_length == 2){
              proto_tree_add_item(tlv_tree, hf_ubdp_system_id, ubdp_tvb, offset, ubdp_length, ENC_BIG_ENDIAN);
            }else{
              expert_add_info(pinfo, tlv_item, &ei_ubdp_unexpected_len);
              proto_tree_add_item(tlv_tree, hf_ubdp_generic, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }
            break;
          case UB_SEQ_NUM:
            if(ubdp_length == 4){
              proto_tree_add_item(tlv_tree, hf_ubdp_seq_num, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }else{
              expert_add_info(pinfo, tlv_item, &ei_ubdp_unexpected_len);
              proto_tree_add_item(tlv_tree, hf_ubdp_generic, ubdp_tvb, offset, ubdp_length, ENC_NA);
            }
            break;
          case UB_TYPE:
            uValue = tvb_get_string_enc(pinfo->pool, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            uModel = try_str_to_str(uValue, ubiquiti_vals);
            proto_tree_add_string(tlv_tree, hf_ubdp_model, ubdp_tvb, offset, ubdp_length, uModel ? uModel : uValue);
            break;
          case UB_MODEL:
            uValue = tvb_get_string_enc(pinfo->pool, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            uModel = try_str_to_str(uValue, ubiquiti_vals);
            proto_tree_add_string(tlv_tree, hf_ubdp_model, ubdp_tvb, offset, ubdp_length, uModel ? uModel : uValue);
            break;
          case UB_FIRMWARE:
            proto_tree_add_item(tlv_tree, hf_ubdp_firmware, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            break;
          case UB_PLATFORM_VERS:
            proto_tree_add_item(tlv_tree, hf_ubdp_platform_vers, ubdp_tvb, offset, ubdp_length, ENC_ASCII);
            break;
          default:
            proto_tree_add_item(tlv_tree, hf_ubdp_generic, ubdp_tvb, offset, ubdp_length, ENC_NA);
            break;
        }
        proto_item_set_len(tlv_item, ubdp_length + 3);
        offset += ubdp_length;
    }
    return tvb_captured_length(ubdp_tvb);
}

void
proto_register_ubdp(void)
{
    static hf_register_info hf[] = {
        { &hf_ubdp_version, {"Version", "ubdp.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_command, {"Command", "ubdp.command", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_size, {"Data Bytes","ubdp.size",FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_type, {"Type","ubdp.type",FT_UINT8, BASE_DEC, VALS(type_vals), 0x0, NULL, HFILL }},
        { &hf_ubdp_len, {"Length","ubdp.len",FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_mac, {"MAC","ubdp.mac",FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_ip, {"IP","ubdp.ip",FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_firmware_full, {"Firmware Path","ubdp.firmware_full",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_username, {"Username", "ubdp.username", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_uptime, {"Uptime","ubdp.uptime",FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_hostname, {"Hostname","ubdp.hostname",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_product, {"Product","ubdp.product",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_ssid, {"SSID","ubdp.ssid",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_wlan_mode, {"Wireless Mode","ubdp.wlan_mode",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_seq_num, {"Counter","ubdp.seq_num",FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_model, {"Model","ubdp.model",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_system_id, {"System ID","ubdp.system_id",FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_firmware, {"Version","ubdp.firmware",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_platform_vers, {"Platform Version","ubdp.platform_vers",FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ubdp_generic, {"Unknown Field","ubdp.unk",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
      &ett_ubdp,
      &ett_ubdp_tlv
    };

  static ei_register_info ei[] = {
	 { &ei_ubdp_bad_version, { "ubdp.bad-version-detected", PI_PROTOCOL, PI_WARN, "Bad Version Detected", EXPFILL }},
     { &ei_ubdp_unexpected_len, { "ubdp.bad-field-length-detected", PI_PROTOCOL, PI_WARN, "Bad Length Field Detected", EXPFILL }},
  };

    expert_module_t* expert_ubdp;

    proto_ubdp = proto_register_protocol("Ubiquiti Discovery Protocol", "UBDP", "ubdp");

    proto_register_field_array(proto_ubdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ubdp = expert_register_protocol(proto_ubdp);
    expert_register_field_array(expert_ubdp, ei, array_length(ei));

    ubdp_handle = register_dissector("ubdp", dissect_ubdp, proto_ubdp);
}

void
proto_reg_handoff_ubdp(void)
{
    dissector_add_for_decode_as_with_preference("udp.port", ubdp_handle);
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
