/* header_field.h
  * Contains the header_field array 
  * Pulled into separate file due to size 
  * Copyright 2007 Don Newton <dnewton@cypresscom.net>
  *
  * $Id$
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
  * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef UNISTIM_HEADER_FIELD_H
#define UNISTIM_HEADER_FIELD_H

static hf_register_info hf[] = { 
      { &hf_unistim_seq_nu, 
         { "RUDP Seq Num","unistim.num",FT_UINT32, 
            BASE_HEX|BASE_RANGE_STRING, RVALS(sequence_numbers), 0x0, NULL, HFILL} 
      },
      { &hf_unistim_cmd_add,
         { "UNISTIM CMD Address","unistim.add",FT_UINT8, 
            BASE_HEX,VALS(command_address),0x0,NULL,HFILL}
      },
      { &hf_uftp_command,
         { "UFTP CMD","uftp.cmd",FT_UINT8,
            BASE_HEX,VALS(uftp_commands),0x0,NULL,HFILL}
      },
      { &hf_uftp_datablock_size,
         { "UFTP Datablock Size","uftp.blocksize",FT_UINT32,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_uftp_datablock_limit,
         { "UFTP Datablock Limit","uftp.limit",FT_UINT8,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_uftp_filename,
         { "UFTP Filename","uftp.filename",FT_STRINGZ,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_uftp_datablock,
         { "UFTP Data Block","uftp.datablock",FT_BYTES,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_unistim_packet_type,
         { "RUDP Pkt type","unistim.type",FT_UINT8, 
            BASE_DEC, VALS(packet_names),0x0,NULL,HFILL} 
      },
      { &hf_unistim_payload,
         { "UNISTIM Payload","unistim.pay",FT_UINT8, 
            BASE_HEX, VALS(payload_names),0x0,NULL,HFILL}
      },
      { &hf_unistim_len ,
         { "UNISTIM CMD Length","unistim.len",FT_UINT8, 
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_basic_bit_field,
         {"FLAGS","unistim.bit.fields",FT_BOOLEAN,
            8,TFS(&basic_bit_yn),0xff,NULL,HFILL}
      },
      { &hf_basic_switch_cmd ,
         {"Basic Cmd (switch)","unistim.basic.switch",FT_UINT8,
            BASE_HEX,VALS(basic_switch_msgs),0x0,NULL,HFILL}
      },
      { &hf_basic_phone_cmd ,
         {"Basic Cmd (phone)","unistim.basic.phone",FT_UINT8,
            BASE_HEX,VALS(basic_phone_msgs),0x0,NULL,HFILL}
      },
      { &hf_broadcast_switch_cmd ,
         {"Broadcast Cmd (switch)","unistim.broadcast.switch",FT_UINT8,
            BASE_HEX,VALS(broadcast_switch_msgs),0x0,NULL,HFILL}
      },
      { &hf_broadcast_phone_cmd ,
         {"Broadcast Cmd (phone)","unistim.broadcast.phone",FT_UINT8,
            BASE_HEX,VALS(broadcast_phone_msgs),0x0,NULL,HFILL}
      },
      { &hf_audio_switch_cmd ,
         {"Audio Cmd (switch)","unistim.audio.switch",FT_UINT8,
            BASE_HEX,VALS(audio_switch_msgs),0x0,NULL,HFILL}
      },
      { &hf_audio_phone_cmd ,
         {"Audio Cmd (phone)","unistim.audio.phone",FT_UINT8,
            BASE_HEX,VALS(audio_phone_msgs),0x0,NULL,HFILL}
      },
      { &hf_display_switch_cmd ,
         {"Display Cmd (switch)","unistim.display.switch",FT_UINT8,
            BASE_HEX,VALS(display_switch_msgs),0x0,NULL,HFILL}
      },
      { &hf_display_phone_cmd ,
         {"Display Cmd (phone)","unistim.display.phone",FT_UINT8,
            BASE_HEX,VALS(display_phone_msgs),0x0,NULL,HFILL}
      },
      { &hf_key_switch_cmd ,
         {"Key Cmd (switch)","unistim.key.switch",FT_UINT8,
            BASE_HEX,VALS(key_switch_msgs),0x0,NULL,HFILL}
      },
      { &hf_key_phone_cmd ,
         {"Key Cmd (phone)","unistim.key.phone",FT_UINT8,
            BASE_HEX,VALS(key_phone_msgs),0x0,NULL,HFILL}
      },
      { &hf_network_switch_cmd ,
         {"Network Cmd (switch)","unistim.network.switch",FT_UINT8,
            BASE_HEX,VALS(network_switch_msgs),0x0,NULL,HFILL}
      },
      { &hf_network_phone_cmd ,
         {"Network Cmd (phone)","unistim.network.phone",FT_UINT8,
            BASE_HEX,VALS(network_phone_msgs),0x0,NULL,HFILL}
      },
      { &hf_terminal_id,
         {"Terminal ID","unistim.terminal.id",FT_IPv4,
            BASE_HEX,NULL,0x0,NULL,HFILL}
      },
      { &hf_broadcast_year,
         {"Year","unistim.broadcast.year",FT_UINT8,
            BASE_DEC,NULL,0x7f,NULL,HFILL}
      },
      { &hf_broadcast_month,
         {"Month","unistim.broadcast.month",FT_UINT8,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_broadcast_day,
         {"Day","unistim.broadcast.day",FT_UINT8,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_broadcast_hour,
         {"Hour","unistim.broadcast.hour",FT_UINT8,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_broadcast_minute,
         {"Minute","unistim.broadcast.minute",FT_UINT8,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_broadcast_second,
         {"Second","unistim.broadcast.second",FT_UINT8,
            BASE_DEC,NULL,0x0,NULL,HFILL}
      },
      { &hf_net_diag_flag,
         {"Query Network Manager Diagnostic","unistim.query.diagnostic", 
            FT_BOOLEAN,8, NULL,
            QUERY_NETWORK_MANAGER_DIAGNOSTIC, NULL,HFILL}
      },
      { &hf_net_managers_flag,
         {"Query Network Manager Managers","unistim.query.managers",
            FT_BOOLEAN,8, NULL,
            QUERY_NETWORK_MANAGER_MANAGERS, NULL,HFILL}
      },
      { &hf_net_attributes_flag,
         {"Query Network Manager Attributes","unistim.query.attributes",
            FT_BOOLEAN, 8,NULL,
            QUERY_NETWORK_MANAGER_ATTRIBUTES,NULL,HFILL}
      },
      { &hf_net_serv_info_flag,
         {"Query Network Manager Server Info","unistim.query.serverInfo",
            FT_BOOLEAN, 8,NULL,
            QUERY_NETWORK_MANAGER_SERVER_INFO,NULL,HFILL}
      },
      { &hf_net_options_flag,
         {"Query Network Manager Options","unistim.query.options",
            FT_BOOLEAN, 8,NULL,
            QUERY_NETWORK_MANAGER_OPTIONS,NULL,HFILL}
      },
      { &hf_net_sanity_flag,
         {"Query Network Manager Sanity","unistim.query.sanity",
            FT_BOOLEAN, 8,NULL,
            QUERY_NETWORK_MANAGER_SANITY,NULL,HFILL}
      },
      { &hf_net_enable_diag,
         {"Network Manager Enable DIAG","unistim.enable.diag",
            FT_BOOLEAN, 8,NULL,
            NETWORK_MANAGER_ENABLE_DIAG,NULL,HFILL}
      },
      { &hf_net_enable_rudp,
         {"Network Manager Enable RUDP","unistim.enable.network.rel.udp",
            FT_BOOLEAN, 8,NULL,
            NETWORK_MANAGER_ENABLE_RUDP,NULL,HFILL}
      },
      { &hf_net_server_id,
         {"Download Server ID","unistim.download.id",FT_UINT8,
            BASE_HEX, VALS(network_server_id),0x00,NULL,HFILL}
      },
      { &hf_net_server_port,
         {"Download Server Port","unistim.download.port",FT_UINT16,
            BASE_DEC, NULL,0x00,NULL,HFILL}
      },
      { &hf_net_server_action,
         {"Download Server Action","unistim.download.action",FT_UINT8,
            BASE_HEX, VALS(server_action),0x00,NULL,HFILL}
      },
      { &hf_net_server_retry_count,
         {"Download Retry Count","unistim.download.retry",FT_UINT8,
            BASE_DEC, NULL,0x00,NULL,HFILL}
      },
      { &hf_net_server_failover_id,
         {"Download Failover Server ID","unistim.download.failover",FT_UINT8,
            BASE_HEX, VALS(network_server_id),0x00,NULL,HFILL}
      },
      { &hf_net_server_ip_address,
         {"Download Server Address","unistim.download.address",FT_UINT32,
            BASE_HEX, NULL,0x00,NULL,HFILL}
      },
      { &hf_net_server_time_out,
         {"Watchdog Timeout","unistim.watchdog.timeout",FT_UINT16,
            BASE_DEC, NULL,0x00,NULL,HFILL}
      },
      { &hf_net_server_config_element,
         {"Configure Network Element","unistim.config.element",FT_UINT8,
            BASE_HEX, VALS(network_elements),0x00,NULL,HFILL}
      },
      { &hf_net_server_recovery_time_low,
         {"Recovery Procedure Idle Low Boundary","unistim.recovery.low",FT_UINT16,
            BASE_DEC, NULL,0x00,NULL,HFILL}
      },
      { &hf_net_server_recovery_time_high,
         {"Recovery Procedure Idle High Boundary","unistim.recovery.high",FT_UINT16,
            BASE_DEC, NULL,0x00,NULL,HFILL}
      },
      { &hf_net_phone_rx_ovr_flag,
         {"Receive Buffer Overflow","unistim.receive.overflow",
            FT_BOOLEAN, 8,NULL,
            RX_BUFFER_OVERFLOW,NULL,HFILL}
      },
      { &hf_net_phone_tx_ovr_flag,
         {"Transmit Buffer Overflow","unistim.trans.overflow",
            FT_BOOLEAN, 8,NULL,
            TX_BUFFER_OVERFLOW,NULL,HFILL}
      },
      { &hf_net_phone_rx_empty_flag,
         {"Receive Buffer Unexpectedly Empty","unistim.receive.empty",
            FT_BOOLEAN, 8,NULL,
            RX_UNEXPECT_EMPTY,NULL,HFILL}
      },
      { &hf_net_phone_invalid_msg_flag,
         {"Received Invalid MSG","unistim.invalid.msg",
            FT_BOOLEAN, 8,NULL,
            INVALID_MSG,NULL,HFILL}
      },
      { &hf_net_phone_eeprom_insane_flag,
         {"EEProm Insane","unistim.eeprom.insane",
            FT_BOOLEAN, 8,NULL,
            EEPROM_INSANE,NULL,HFILL}
      },
      { &hf_net_phone_eeprom_unsafe_flag,
         {"EEProm Unsafe","unistim.eeprom.unsafe",
            FT_BOOLEAN, 8,NULL,
            EEPROM_UNSAFE,NULL,HFILL}
      },
      { &hf_net_phone_diag,
         {"Diagnostic Command Enabled","unistim.diag.enabled",FT_BOOLEAN,
           8,NULL,NETWORK_MGR_REPORT_DIAG,NULL,HFILL}
      },
      { &hf_net_phone_rudp,
         {"Reliable UDP Active","unistim.rudp.active",FT_BOOLEAN,
           8,NULL,NETWORK_MGR_REPORT_RUDP,NULL,HFILL}
      },
      { &hf_basic_switch_query_flags,
         {"Query Basic Manager","unistim.basic.query",FT_UINT8,
            BASE_HEX, NULL,0x00,"INITIAL PHONE QUERY",HFILL}
      },
      { &hf_basic_switch_query_attr,
         {"Query Basic Manager Attributes","unistim.basic.attrs",FT_BOOLEAN,
           8,NULL,BASIC_QUERY_ATTRIBUTES,"Basic Query Attributes",HFILL}
      },
      { &hf_basic_switch_query_opts,
         {"Query Basic Manager Options","unistim.basic.opts",FT_BOOLEAN,
           8,NULL,BASIC_QUERY_OPTIONS,"Basic Query Options",HFILL}
      },
      { &hf_basic_switch_query_fw,
         {"Query Basic Switch Firmware","unistim.basic.fw",FT_BOOLEAN,
            8,NULL,BASIC_QUERY_FW,"Basic Query Firmware",HFILL}
      },
      { &hf_basic_switch_query_hw_id,
         {"Query Basic Manager Hardware ID","unistim.basic.hwid",FT_BOOLEAN,
           8,NULL,BASIC_QUERY_HW_ID,"Basic Query Hardware ID",HFILL}
      },
      { &hf_basic_switch_query_it_type,
         {"Query Basic Manager Phone Type","unistim.basic.type",FT_BOOLEAN,
           8,NULL,BASIC_QUERY_IT_TYPE,"Basic Query Phone Type",HFILL}
      },
      { &hf_basic_switch_query_prod_eng_code,
         {"Query Basic Manager Prod Eng Code","unistim.basic.code",FT_BOOLEAN,
           8,NULL,BASIC_QUERY_PROD_ENG_CODE,"Basic Query Production Engineering Code",HFILL}
      },
      { &hf_basic_switch_query_gray_mkt_info,
         {"Query Basic Manager Gray Mkt Info","unistim.basic.gray",FT_BOOLEAN,
           8,NULL,BASIC_QUERY_GRAY_MKT_INFO,"Basic Query Gray Market Info",HFILL}
      },
      { &hf_basic_switch_options_secure,
         {"Basic Switch Options Secure Code","unistim.basic.secure",FT_BOOLEAN,
           8,NULL,BASIC_OPTION_SECURE,NULL,HFILL}
      },
      { &hf_basic_switch_element_id,
         {"Basic Element ID","unistim.basic.element.id",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_basic_switch_eeprom_data,
         {"EEProm Data","unistim.basic.eeprom.data",FT_BYTES,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_basic_phone_eeprom_stat_cksum,
         {"Basic Phone EEProm Static Checksum","unistim.static.cksum",FT_UINT8,
            BASE_HEX,NULL,0x0,NULL,HFILL}
      },
      { &hf_basic_phone_eeprom_dynam,
         {"Basic Phone EEProm Dynamic Checksum","unistim.dynam.cksum",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_basic_phone_eeprom_net_config_cksum,
         {"Basic Phone EEProm Net Config Checksum","unistim.netconfig.cksum",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_basic_phone_hw_id,
         {"Basic Phone Hardware ID","unistim.basic.hw.id",FT_BYTES,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_basic_phone_fw_ver,
         {"Basic Phone Firmware Version","unistim.basic.fw.ver",FT_STRING,
            BASE_NONE,NULL,0x00,NULL,HFILL}
      },
      { &hf_key_code,
         {"Key Name","unistim.key.name",FT_UINT8,
            BASE_HEX,VALS(key_names),0x3f,NULL,HFILL}
      },
      { &hf_key_command,
         {"Key Action","unistim.key.action",FT_UINT8,
            BASE_HEX,VALS(key_cmds),0xc0,NULL,HFILL}
      },
      { &hf_icon_id,
         {"Icon ID","unistim.icon.id",FT_UINT8,
            BASE_HEX,NULL, DISPLAY_ICON_ID,NULL,HFILL}
      },
      { &hf_broadcast_icon_state,
         {"Icon State","unistim.icon.state",FT_UINT8,
            BASE_HEX,VALS(bcast_icon_states),0x1f,NULL,HFILL}
      },
      { &hf_broadcast_icon_cadence,
         {"Icon Cadence","unistim.icon.cadence",FT_UINT8,
            BASE_HEX,VALS(bcast_icon_cadence),0xe0,NULL,HFILL}
      },
      { &hf_audio_mgr_attr,
         {"Query Audio Manager Attributes","unistim.audio.attr",FT_BOOLEAN,
            8,NULL,QUERY_AUDIO_MGR_ATTRIBUTES,NULL,HFILL}
      },
      { &hf_audio_mgr_opts,
         {"Query Audio Manager Options","unistim.audio.options",FT_BOOLEAN,
            8,NULL,QUERY_AUDIO_MGR_OPTIONS,NULL,HFILL}
      },
      { &hf_audio_mgr_alert,
         {"Query Audio Manager Alerting","unistim.audio.alerting",FT_BOOLEAN,
            8,NULL,QUERY_AUDIO_MGR_ALERTING ,NULL,HFILL}
      },
      { &hf_audio_mgr_adj_rx_vol,
         {"Query Audio Manager Adjustable Receive Volume","unistim.audio.adj.volume",FT_BOOLEAN,
            8,NULL,QUERY_AUDIO_MGR_ADJ_RX_VOL,NULL,HFILL}
      },
      { &hf_audio_mgr_def_rx_vol,
         {"Query Audio Manager Default Receive Volume","unistim.audio.def.volume",FT_BOOLEAN,
            8,NULL,QUERY_AUDIO_MGR_DEF_RX_VOL,NULL,HFILL}
      },
      { &hf_audio_mgr_handset,
         {"Query Audio Manager Handset","unistim.audio.handset",FT_BOOLEAN,
            8,NULL,QUERY_AUDIO_MGR_HANDSET,NULL,HFILL}
      },
      { &hf_audio_mgr_headset,
         {"Query Audio Manager Headset","unistim.audio.headset",FT_BOOLEAN,
            8,NULL,QUERY_AUDIO_MGR_HEADSET,NULL,HFILL}
      },
      { &hf_audio_default_rx_vol_id,
         {"Audio Manager Default Receive Volume ID","unistim.audio.volume.id",FT_UINT8,
            BASE_HEX,VALS(default_rx_vol_id),0x00,NULL,HFILL}
      },
      { &hf_audio_mgr_opt_max_vol,
         {"Audio Manager Enable Max Tone Volume","unistim.audio.max.tone",FT_BOOLEAN,
            8,TFS(&audio_opts_enable_max_tone_vol),AUDIO_MGR_OPTS_MAX_VOL,NULL,HFILL}
      },
      { &hf_audio_mgr_opt_adj_vol,
         {"Audio Manager Adjust Volume","unistim.audio.opts.adj.vol",FT_BOOLEAN,
            8,TFS(&audio_opts_adjust_volume),AUDIO_MGR_ADJ_VOL,NULL,HFILL}
      },
      { &hf_audio_mgr_opt_aa_rx_vol_rpt,
         {"Audio Manager Auto Adjust Volume RPT","unistim.audio.aa.vol.rpt",FT_BOOLEAN,
            8,TFS(&audio_opts_automatic_adjustable),AUDIO_MGR_AUTO_RX_VOL_RPT,NULL,HFILL}
      },
      { &hf_audio_mgr_opt_hs_on_air,
         {"Audio Manager Handset","unistim.audio.handset",FT_BOOLEAN,
            8,TFS(&audio_opts_hs_on_air_feature),AUDIO_MGR_HS_ON_AIR,NULL,HFILL}
      },
      { &hf_audio_mgr_opt_hd_on_air,
         {"Audio Manager Headset","unistim.audio.headset",FT_BOOLEAN,
            8,TFS(&audio_opts_hd_on_air_feature),AUDIO_MGR_HD_ON_AIR,NULL,HFILL}
      },
      { &hf_audio_mgr_opt_noise_squelch,
         {"Audio Manager Noise Squelch","unistim.audio.squelch",FT_BOOLEAN,
            8,TFS(&noise_sqlch_disable), AUDIO_MGR_NOISE_SQUELCH,NULL,HFILL}
      },
      { &hf_audio_mgr_mute,
         {"Audio Manager Mute","unistim.audio.mute",FT_BOOLEAN,
            8,TFS(&audio_mgr_mute_val),AUDIO_MGR_MUTE,NULL,HFILL}
      },
      { &hf_audio_mgr_tx_rx,
         {"Audio Manager RX or TX","unistim.audio.rx.tx",FT_BOOLEAN,
            8,TFS(&audio_mgr_tx_rx_val),AUDIO_MGR_TX_RX,NULL,HFILL}
      },
      { &hf_audio_mgr_stream_id,
         {"Audio Manager Stream ID","unistim.audio.stream.id",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_mgr_transducer_based_tone_id,
         {"Audio Manager Transducer Based Tone On","unistim.audio.transducer.on",FT_UINT8,
            BASE_HEX,VALS(trans_base_tone_ids),0x07,NULL,HFILL}
      },
      { &hf_audio_mgr_attenuated,
         {"Audio Manager Transducer Tone Attenuated","unistim.audio.attenuated.on",FT_BOOLEAN,
            8,NULL,AUDIO_MGR_ATTENUATED,NULL,HFILL}
      },
      { &hf_audio_mgr_warbler_select,
         {"Warbler Select","unistim.warbler.select",FT_UINT8,
            BASE_HEX,NULL,0x07,NULL,HFILL}
      },
      { &hf_audio_mgr_transducer_routing,
         {"Transducer Routing","unistim.transducer.routing",FT_UINT8,
            BASE_HEX,VALS(transducer_routing_vals),0xf8,NULL,HFILL}
      },
      { &hf_audio_mgr_tone_vol_range,
         {"Tone Volume Range in Steps","unistim.tone.volume.range",FT_UINT8,
            BASE_HEX,NULL,0x0f,NULL,HFILL}
      },
      { &hf_audio_mgr_cadence_select,
         {"Cadence Select","unistim.cadence.select",FT_UINT8,
            BASE_HEX,VALS(cadence_select_vals),0xf0,NULL,HFILL}
      },
      { &hf_audio_special_tone,
         {"Special Tone Select","unistim.special.tone.select",FT_UINT8,
            BASE_HEX,VALS(special_tones_vals),0x00,NULL,HFILL}
      },
      { &hf_audio_tone_level,
         {"Tone Level","unistim.audio.tone.level",FT_UINT8,
            BASE_DEC,NULL,0xf0,NULL,HFILL}
      },
      { &hf_audio_visual_tones,
         {"Enable Visual Tones","unistim.visual.tones",FT_BOOLEAN,
            8,NULL,AUDIO_MGR_VISUAL_TONE,NULL,HFILL}
      },
      { &hf_audio_stream_based_tone_id,
         {"Stream Based Tone ID","unistim.stream.tone.id",FT_UINT8,
            BASE_HEX,VALS(stream_based_tone_vals),0x1f,NULL,HFILL}
      },
      { &hf_audio_stream_based_tone_rx_tx,
         {"Stream Based Tone RX or TX","unistim.stream.based.tone.rx.tx",FT_BOOLEAN,
            8,TFS(&stream_based_tone_rx_tx_yn),AUDIO_STREAM_BASED_TONE_RX_TX,NULL,HFILL}
      },
      { &hf_audio_stream_based_tone_mute,
         {"Stream Based Tone Mute","unistim.stream.tone.mute",FT_BOOLEAN,
            8,TFS(&stream_based_tone_mute_yn),AUDIO_STREAM_BASED_TONE_MUTE,NULL,HFILL}
      },
      { &hf_audio_stream_id,
         {"Stream ID","unistim.audio.stream.id",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_stream_based_volume,
         {"Stream Based Volume ID","unistim.stream.volume.id",FT_UINT8,
            BASE_HEX,VALS(stream_base_vol_level),0x00,NULL,HFILL}
      },
      { &hf_basic_switch_terminal_id,
         {"Terminal ID assigned by Switch","unistim.switch.terminal.id",FT_IPv4,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_basic_it_type,
         {"IT (Phone) Type","unistim.it.type",FT_UINT8,
            BASE_HEX,VALS(it_types),0x00,NULL,HFILL}
      },
      { &hf_basic_prod_eng_code,
         {"Product Engineering Code for phone","unistim.basic.eng.code",FT_STRING,
            BASE_NONE,NULL,0x00,NULL,HFILL}
      },
      { &hf_net_phone_primary_server_id,
         {"Phone Primary Server ID","unistim.net.phone.primary.id",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_net_phone_server_port,
         {"Port Number","unistim.server.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_net_phone_server_action,
         {"Action","unistim.server.action.byte",FT_UINT8,
            BASE_HEX,VALS(action_bytes),0x00,NULL,HFILL}
      },
      { &hf_net_phone_server_retry_count,
         {"Number of times to Retry","unistim.server.retry.count",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_net_phone_server_failover_id,
         {"Failover Server ID","unistim.server.failover.id",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_net_phone_server_ip,
         {"IP address","unistim.server.ip.address",FT_IPv4,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_apb_number,
         {"APB Number","unistim.audio.apb.number",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { & hf_audio_apb_op_code,
         {"APB Operation Code","unistim.audio.apb.op.code",FT_UINT8,
            BASE_HEX,VALS(apb_op_codes),0x00,NULL,HFILL}
      },
      { &hf_audio_apb_param_len,
         {"APB Operation Parameter Length","unistim.apb.param.len",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_apb_data,
         {"APB Operation Data","unistim.apb.operation.data",FT_BYTES,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_write_address_numeric,
         {"Is Address Numeric","unistim.write.address.numeric",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_ADDRESS_NUMERIC_FLAG,NULL,HFILL}
      },
      { &hf_display_write_address_context,
         {"Context Field in the Info Bar","unistim.write.address.context",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_ADDRESS_CONTEXT_FLAG,NULL,HFILL}
      },
      { &hf_display_write_address_line,
         {"Write A Line","unistim.write.address.line",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_ADDRESS_LINE_FLAG ,NULL,HFILL}
      },
      { &hf_display_write_address_soft_key,
         {"Write a SoftKey","unistim.write.address.softkey",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG,NULL,HFILL}
      },
      { &hf_display_write_address_soft_label,
         {"Write A Softkey Label","unistim.write.address.softkey.label",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG,NULL,HFILL}
      },
      { &hf_display_write_address_softkey_id,
         {"Soft Key ID","unistim.write.addres.softkey.id",FT_UINT8,
            BASE_HEX,NULL,DISPLAY_WRITE_ADDRESS_SOFT_KEY_ID,NULL,HFILL}
      },
      { &hf_display_write_address_char_pos,
         {"Character Position or Soft-Label Key ID","unistim.display.write.address.char.pos",FT_UINT8,
            BASE_HEX,NULL,DISPLAY_WRITE_ADDRESS_CHAR_POS,NULL,HFILL}
      },
      { &hf_display_write_address_line_number,
         {"Line Number","unistim.write.address.line.number",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_WRITE_ADDRESS_LINE_NUM,NULL,HFILL}
      },
      { &hf_display_write_cursor_move,
         {"Cursor Move","unistim.display.cursor.move",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_CURSOR_MOVE,NULL,HFILL}
      },
      { &hf_display_write_clear_left,
         {"Clear Left","unistim.display.clear.left",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_CLEAR_LEFT,NULL,HFILL}
      },
      { &hf_display_write_clear_right,
         {"Clear Right","unistim.display.clear.right",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_CLEAR_RIGHT,NULL,HFILL}
      },
      { &hf_display_write_shift_left,
         {"Shift Left","unistim.display.shift.left",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_SHIFT_LEFT,NULL,HFILL}
      },
      { &hf_display_write_shift_right,
         {"Shift Right","unistim.display.shift.right",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_SHIFT_RIGHT,NULL,HFILL}
      },
      { &hf_display_write_highlight,
         {"Highlight","unistim.display.highlight",FT_BOOLEAN,
            8,NULL,DISPLAY_WRITE_HIGHLIGHT,NULL,HFILL}
      },
      { &hf_display_write_tag,
         {"Tag for text","unistim.display.text.tag",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_cursor_move_cmd,
         {"Cursor Movement Command","unistim.cursor.move.cmd",FT_UINT8,
            BASE_HEX,VALS(cursor_move_cmds),DISPLAY_CURSOR_MOVE_CMD,NULL,HFILL}
      },
      { &hf_display_cursor_blink,
         {"Should Cursor Blink","unistim.cursor.blink",FT_BOOLEAN,
            8,NULL,DISPLAY_CURSOR_BLINK,NULL,HFILL}
      },
      { &hf_audio_vocoder_id,
         {"Vocoder Protocol","unistim.vocoder.id",FT_UINT8,
            BASE_HEX,VALS(vocoder_ids),0x00,NULL,HFILL}
      },
      { &hf_audio_vocoder_param,
         {"Vocoder Config Param","unistim.vocoder.config.param",FT_UINT8,
            BASE_HEX,VALS(vocoder_config_params),AUDIO_VOCODER_CONFIG_PARAM,NULL,HFILL}
      },
      { &hf_audio_vocoder_entity,
         {"Vocoder Entity","unistim.vocoder.entity",FT_UINT8,
            BASE_HEX,VALS(config_param_entities),AUDIO_VOCODER_CONFIG_ENTITY,NULL,HFILL}
      },
      { &hf_audio_vocoder_annexa,
         {"Enable Annex A","unistim.enable.annexa",FT_BOOLEAN,
            8,NULL,AUDIO_VOCODER_ANNEXA,NULL,HFILL}
      },
      { &hf_audio_vocoder_annexb,
         {"Enable Annex B","unistim.enable.annexb",FT_BOOLEAN,
            8,NULL,AUDIO_VOCODER_ANNEXB,NULL,HFILL}
      },
      { &hf_audio_sample_rate,
         {"Sample Rate","unistim.audio.sample.rate",FT_UINT8,
            BASE_HEX,VALS(sample_rates),0x00,NULL,HFILL}
      },
      { &hf_audio_rtp_type,
         {"RTP Type","unistim.audio.rtp.type",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_bytes_per_frame,
         {"Bytes Per Frame","unistim.audio.bytes.per.frame",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_rx_stream_id,
         {"Receive Stream Id","unistim.rx.stream.id",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_tx_stream_id,
         {"Transmit Stream Id","unistim.rx.stream.id",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_rx_vocoder_type,
         {"Receive Vocoder Protocol","unistim.vocoder.id",FT_UINT8,
            BASE_HEX,VALS(vocoder_ids),0x00,NULL,HFILL}
      },
      { &hf_tx_vocoder_type,
         {"Transmit Vocoder Protocol","unistim.vocoder.id",FT_UINT8,
            BASE_HEX,VALS(vocoder_ids),0x00,NULL,HFILL}
      },
      { &hf_frames_per_packet,
         {"Frames Per Packet","unistim.vocoder.frames.per.packet",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_tos,
         {"Type of Service","unistim.audio.type.service",FT_UINT8,
            BASE_HEX,VALS(types_of_service),AUDIO_TYPE_OF_SERVICE,NULL,HFILL}
      },
      { &hf_audio_precedence,
         {"Precedence","unistim.audio.precedence",FT_UINT8,
            BASE_HEX,VALS(precedences),AUDIO_PRECENDENCE,NULL,HFILL}
      },
      { &hf_audio_frf_11,
         {"FRF.11 Enable","unistim.audio.frf.11",FT_BOOLEAN,
            8,NULL,AUDIO_FRF_11,NULL,HFILL}
      },
      { &hf_audio_lcl_rtp_port,
         {"Phone RTP Port","unistim.local.rtp.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_lcl_rtcp_port,
         {"Phone RTCP Port","unistim.local.rtcp.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_far_rtp_port,
         {"Distant RTP Port","unistim.far.rtp.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_far_rtcp_port,
         {"Distant RTCP Port","unistim.far.rtcp.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_far_ip_add,
         {"Distant IP Address for RT[C]P","unistim.far.ip.address",FT_IPv4,
            BASE_NONE,NULL,0x00,NULL,HFILL}
      },
      { &hf_rtcp_bucket_id,
         {"RTCP Bucket ID","unistim.rtcp.bucket.id",FT_UINT16,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_key_icon_id,
         {"Icon ID","unistim.key.icon.id",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_clear_numeric,
         {"Numeric Index Field in InfoBar","unistim.display.clear.numeric",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_NUMERIC,NULL,HFILL}
      },
      { &hf_display_clear_context ,
         {"Context Field in InfoBar","unistim.display.clear.context",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_CONTEXT,NULL,HFILL}
      },
      { &hf_display_clear_date ,
         {"Date Field","unistim.display.clear.date",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_DATE,NULL,HFILL}
      },
      { &hf_display_clear_time,
         {"Time Field","unistim.display.clear.time",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_TIME,NULL,HFILL}
      },
      { &hf_display_clear_line,
         {"Line Data","unistim.display.clear.line",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon,
         {"Status Bar Icon","unistim.display.statusbar.icon",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_STATUS_BAR_ICON,NULL,HFILL}
      },
      { &hf_display_clear_softkey,
         {"Soft Key","unistim.display.clear.softkey",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_SOFTKEY,NULL,HFILL}
      },
      { &hf_display_clear_softkey_label ,
         {"Soft Key Label","unistim.display.clear.softkey.label",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_SOFTKEY_LABEL,NULL,HFILL}
      },
      { &hf_display_clear_line_1 ,
         {"Line 1","unistim.display.clear.line1",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_1,NULL,HFILL}
      },
      { &hf_display_clear_line_2 ,
         {"Line 2","unistim.display.clear.line2",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_2,NULL,HFILL}
      },
      { &hf_display_clear_line_3 ,
         {"Line 3","unistim.display.clear.line3",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_3,NULL,HFILL}
      },
      { &hf_display_clear_line_4 ,
         {"Line 4","unistim.display.clear.line4",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_4,NULL,HFILL}
      },
      { &hf_display_clear_line_5 ,
         {"Line 5","unistim.display.clear.line5",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_5,NULL,HFILL}
      },
      { &hf_display_clear_line_6 ,
         {"Line 6","unistim.display.clear.line6",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_6,NULL,HFILL}
      },
      { &hf_display_clear_line_7 ,
         {"Line 7","unistim.display.clear.line7",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_7,NULL,HFILL}
      },
      { &hf_display_clear_line_8 ,
         {"Line 8","unistim.display.clear.line8",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_LINE_8,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_1 ,
         {"Status Bar Icon 1","unistim.display.clear.sbar.icon1",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_1,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_2 ,
         {"Status Bar Icon 2","unistim.display.clear.sbar.icon2",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_2,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_3 ,
         {"Status Bar Icon 3","unistim.display.clear.sbar.icon3",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_3,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_4 ,
         {"Status Bar Icon 4","unistim.display.clear.sbar.icon4",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_4,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_5 ,
         {"Status Bar Icon 5","unistim.display.clear.sbar.icon5",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_5,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_6 ,
         {"Status Bar Icon 6","unistim.display.clear.sbar.icon6",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_6,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_7 ,
         {"Status Bar Icon 7","unistim.display.clear.sbar.icon7",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_7,NULL,HFILL}
      },
      { &hf_display_clear_status_bar_icon_8 ,
         {"Status Bar Icon 8","unistim.display.clear.sbar.icon8",FT_BOOLEAN,
            8,NULL,DISPLAY_STATUS_BAR_ICON_8,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_1 ,
         {"Soft Key 1","unistim.display.clear.soft.key1",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_1,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_2 ,
         {"Soft Key 2","unistim.display.clear.soft.key2",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_2,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_3 ,
         {"Soft Key 3","unistim.display.clear.soft.key3",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_3,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_4 ,
         {"Soft Key 4","unistim.display.clear.soft.key4",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_4,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_5 ,
         {"Soft Key 5","unistim.display.clear.soft.key5",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_5,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_6 ,
         {"Soft Key 6","unistim.display.clear.soft.key6",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_6,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_7 ,
         {"Soft Key 7","unistim.display.clear.soft.key7",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_7,NULL,HFILL}
      },
      { &hf_display_clear_soft_key_8 ,
         {"Soft Key 8","unistim.display.clear.soft.key8",FT_BOOLEAN,
            8,NULL,DISPLAY_SOFT_KEY_8,NULL,HFILL}
      },
      { &hf_display_clear_sk_label_key_id,
         {"Soft Key Label ID","unistim.display.clear.sk.label.id",FT_UINT8,
            BASE_HEX,NULL, DISPLAY_CLEAR_SK_LABEL_KEY_ID,NULL,HFILL}
      },
      { &hf_display_clear_all_slks,
         {"Clear All Soft Key Labels","unistim.display.clear.all.sks",FT_BOOLEAN,
            8,NULL,DISPLAY_CLEAR_ALL_SLKS,NULL,HFILL}
      },
      { &hf_key_led_cadence,
         {"LED Cadence","unistim.key.led.cadence",FT_UINT8,
            BASE_HEX,VALS(led_cadences),KEY_LED_CADENCE,NULL,HFILL}
      },
      { &hf_key_led_id,
         {"LED ID","unistim.key.led.id",FT_UINT8,
            BASE_HEX,VALS(led_ids),KEY_LED_ID,NULL,HFILL}
      },
      { &hf_basic_ether_address,
         {"Phone Ethernet Address","unistim.phone.ether",FT_ETHER,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_rtcp_bucket_id,
         {"RTCP Bucket ID","unistim.audio.rtcp.bucket.id",FT_UINT8,
            BASE_HEX,NULL,AUDIO_RTCP_BUCKET_ID,NULL,HFILL}
      },
      { &hf_audio_clear_bucket,
         {"Clear Bucket Counter","unistim.clear.bucket",FT_BOOLEAN,
            8,NULL,AUDIO_CLEAR_BUCKET,NULL,HFILL}
      },
      { &hf_display_arrow,
         {"Arrow Display Direction","unistim.arrow.direction",FT_UINT8,
            BASE_HEX,VALS(arrow_dirs),0x00,NULL,HFILL}
      },
      { &hf_audio_transducer_pair,
         {"Audio Transducer Pair","unistim.transducer.pairs",FT_UINT8,
            BASE_HEX,VALS(transducer_pairs),AUDIO_TRANSDUCER_PAIR_ID,NULL,HFILL}
      },
      { &hf_audio_rx_enable,
         {"RX Enable","unistim.receive.enable",FT_BOOLEAN,
            8,NULL,AUDIO_RX_ENABLE,NULL,HFILL}
      },
      { &hf_audio_tx_enable,
         {"TX Enable","unistim.transmit.enable",FT_BOOLEAN,
            8,NULL,AUDIO_TX_ENABLE,NULL,HFILL}
      },
      { &hf_audio_sidetone_disable,
         {"Disable Sidetone","unistim.audio.sidetone.disable",FT_BOOLEAN,
            8,NULL,AUDIO_SIDETONE_DISABLE,NULL,HFILL}
      },
      { &hf_audio_destruct_additive,
         {"Destructive/Additive","unistim.destructive.active",FT_BOOLEAN,
            8,TFS(&destruct_additive),AUDIO_DESTRUCT_ADD,NULL,HFILL}
      },
      { &hf_audio_dont_force_active,
         {"Don't Force Active","unistim.dont.force.active",FT_BOOLEAN,
            8,TFS(&dont_force_active),AUDIO_DONT_FORCE_ACTIVE,NULL,HFILL}
      },
      { &hf_display_line_width,
         {"Phone Line Width","unistim.line.width",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_LINE_WIDTH,NULL,HFILL}
      },
      { &hf_display_lines,
         {"Number Of Lines","unistim.number.lines",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_LINES,NULL,HFILL}
      },
      { &hf_display_softkey_width,
         {"Phone Softkey Width","unistim.softkey.width",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_SKEY_WIDTH,NULL,HFILL}
      },
      { &hf_display_softkeys,
         {"Phone Softkeys","unistim.phone.softkeys",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_SKEYS,NULL,HFILL}
      },
      { &hf_display_icon,
         {"Phone Icon Type","unistim.phone.icon.type",FT_UINT8,
            BASE_HEX,VALS(icon_types),DISPLAY_ICON,NULL,HFILL}
      },
      { &hf_display_softlabel_key_width,
         {"Soft-Label Key width","unistim.softlabel.key.width",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_SOFTLABEL_WIDTH,NULL,HFILL}
      },
      { &hf_display_context_width,
         {"Phone Context Width","unistim.context.width",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_CONTEXT_WIDTH,NULL,HFILL}
      },
      { &hf_display_numeric_width,
         {"Phone Numeric Width","unistim.numeric.width",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_NUMERIC_WIDTH,NULL,HFILL}
      },
      { &hf_display_time_width,
         {"Phone Time Width","unistim.time.width",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_TIME_WIDTH,NULL,HFILL}
      },
      { &hf_display_date_width,
         {"Phone Date Width","unistim.date.width",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_DATE_WIDTH,NULL,HFILL}
      },
      { &hf_display_char_dload,
         {"Number of Downloadable Chars","unistim.number.dload.chars",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_CHAR_DLOAD,NULL,HFILL}
      },
      { &hf_display_freeform_icon_dload,
         {"Number of Freeform Icon Downloads","unistim.number.dload.icons",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_FFORM_ICON_DLOAD,NULL,HFILL}
      },
      { &hf_display_icon_type,
         {"Icon Types","unistim.icon.types",FT_UINT8,
            BASE_HEX,NULL,DISPLAY_ICON_TYPE,NULL,HFILL}
      },
      { &hf_display_charsets,
         {"Character Sets","unistim.phone.charsets",FT_UINT8,
            BASE_HEX,NULL,DISPLAY_CHARSET,NULL,HFILL}
      },
      { &hf_display_contrast,
         {"Phone Contrast Level","unistim.phone.contrast.level",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_cursor_numeric,
         {"Numeric Index Field","unistim.field.numeric",FT_BOOLEAN,
            8,NULL,DISPLAY_CURSOR_NUMERIC,NULL,HFILL}
      },
      { &hf_display_cursor_context,
         {"Context Field","unistim.field.context",FT_BOOLEAN,
            8,NULL,DISPLAY_CURSOR_CONTEXT,NULL,HFILL}
      },
      { &hf_display_cursor_line,
         {"Text Line","unistim.field.text.line",FT_BOOLEAN,
            8,NULL,DISPLAY_CURSOR_LINE,NULL,HFILL}
      },
      { &hf_display_cursor_softkey,
         {"Softkey Position","unistim.position.skey",FT_BOOLEAN,
            8,NULL,DISPLAY_CURSOR_SKEY,NULL,HFILL}
      },
      { &hf_display_cursor_softkey_id,
         {"Soft Key Id","unistim.cursor.skey.id",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_CURSOR_SKEY_ID,NULL,HFILL}
      },
      { &hf_display_cursor_char_pos,
         {"Character Position","unistim.phone.char.pos",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_CURSOR_CHAR_POS,NULL,HFILL}
      },
      { &hf_display_cursor_line_number,
         {"Display Line Number","unistim.display.line.number",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_CURSOR_LINE_NUM,NULL,HFILL}
      },
      { &hf_display_hlight_start,
         {"Display Highlight Start Position","unistim.hilite.start.pos",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_hlight_end,
         {"Display Highlight End Position","unistim.hilite.end.pos",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_date_format,
         {"Date Format","unistim.display.date.format",FT_UINT8,
            BASE_HEX,VALS(date_formats),DISPLAY_DATE_FORMAT,NULL,HFILL}
      },
      { &hf_display_time_format,
         {"Time Format","unistim.display.time.format",FT_UINT8,
            BASE_HEX,VALS(time_formats),DISPLAY_TIME_FORMAT,NULL,HFILL}
      },
      { &hf_display_use_time_format,
         {"Use Time Format","unistim.display.use.time.format",FT_BOOLEAN,
            8,NULL,DISPLAY_USE_TIME_FORMAT,NULL,HFILL}
      },
      { &hf_display_use_date_format,
         {"Use Date Format","unistim.display.use.date.format",FT_BOOLEAN,
            8,NULL,DISPLAY_USE_DATE_FORMAT,NULL,HFILL}
      },
      { &hf_display_context_format,
         {"Context Info Bar Format","unistim.display.context.format",FT_UINT8,
            BASE_HEX,VALS(display_formats),DISPLAY_CTX_FORMAT,NULL,HFILL}
      },
      { &hf_display_context_field,
         {"Context Info Bar Field","unistim.display.context.field",FT_UINT8,
            BASE_HEX,VALS(display_format_fields),DISPLAY_CTX_FIELD,NULL,HFILL}
      },
      { &hf_display_char_address,
         {"Display Character Address","unistim.display.char.address",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_layer_number,
         {"Softkey Layer Number","unistim.softkey.layer.num",FT_UINT8,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      },
      { &hf_display_layer_skey_id,
         {"Softkey ID","unistim.layer.softkey.id",FT_UINT8,
            BASE_DEC,NULL,DISPLAY_LAYER_SKEY_ID,NULL,HFILL}
      },
      { &hf_display_layer_all_skeys,
         {"All Softkeys","unistim.layer.all.skeys",FT_BOOLEAN,
            8,NULL,DISPLAY_LAYER_ALL_SKEYS,NULL,HFILL}
      },
      { &hf_display_once_or_cyclic,
         {"Layer Softkey Once/Cyclic","unistim.layer.once.cyclic",FT_BOOLEAN,
            8,TFS(&once_or_cyclic),DISPLAY_ONE_OR_CYCLIC,NULL,HFILL}
      },
      { &hf_display_layer_duration,
         {"Display Duration (20ms steps)","unistim.layer.display.duration",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_key_programmable_keys,
         {"Number of Programmable Keys","unistim.num.prog.keys",FT_UINT8,
            BASE_DEC,NULL,KEY_NUM_PROG_KEYS,NULL,HFILL}
      },
      { &hf_keys_soft_keys,
         {"Number of Soft Keys","unistim.num.soft.keys",FT_UINT8,
            BASE_DEC,NULL,KEY_NUM_SOFT_KEYS,NULL,HFILL}
      },
      { &hf_keys_hd_key,
         {"Headset Key Exists","unistim.exist.hd.key",FT_BOOLEAN,
            8,NULL,KEY_HD_KEY_EXISTS,NULL,HFILL}
      },
      { &hf_keys_mute_key,
         {"Mute Key Exists","unistim.exist.mute.key",FT_BOOLEAN,
            8,NULL,KEY_MUTE_KEY_EXISTS,NULL,HFILL}
      },
      { &hf_keys_quit_key,
         {"Quit Key Exists","unistim.exist.quit.key",FT_BOOLEAN,
            8,NULL,KEY_QUIT_KEY_EXISTS,NULL,HFILL}
      },
      { &hf_keys_copy_key,
         {"Copy Key Exists","unistim.exist.copy.key",FT_BOOLEAN,
            8,NULL,KEY_COPY_KEY_EXISTS,NULL,HFILL}
      },
      { &hf_keys_mwi_key,
         {"Message Waiting Indicator Exists","unistim.exist.mwi.key",FT_BOOLEAN,
            8,NULL,KEY_MWI_EXISTS,NULL,HFILL}
      },
      { &hf_keys_num_nav_keys,
         {"Number of Navigation Keys","unistim.num.nav.keys",FT_UINT8,
            BASE_DEC,VALS(number_nav_keys),KEY_NUM_NAV_KEYS,NULL,HFILL}
      },
      { &hf_keys_num_conspic_keys,
         {"Number Of Conspicuous Keys","unistim.num.conspic.keys",FT_UINT8,
            BASE_DEC,NULL,KEY_NUM_CONSPIC_KEYS,NULL,HFILL}
      },
      { &hf_keys_send_key_rel,
         {"Send Key Release","unistim.key.send.release",FT_BOOLEAN,
            8,TFS(&key_release),KEY_SEND_KEY_RELEASE,NULL,HFILL}
      },
      { &hf_keys_enable_vol,
         {"Enable Volume Control","unistim.key.enable.vol",FT_BOOLEAN,
            8,TFS(&enable_vol),KEY_ENABLE_VOL_KEY,NULL,HFILL}
      },
      { &hf_keys_conspic_prog_key,
         {"Conspicuous and Programmable Keys Same","unistim.conspic.prog.keys",FT_BOOLEAN,
            8,TFS(&conspic_prog),KEY_CONSPIC_PROG_KEY0,NULL,HFILL}
      },
      { &hf_keys_acd_super_control,
         {"ACD Supervisor Control","unistim.acd.super.control",FT_BOOLEAN,
            8,TFS(&acd_supervisor),KEY_ACD_SUP_CONTROL,NULL,HFILL}
      },
      { &hf_keys_local_dial_feedback,
         {"Local Keypad Feedback","unistim.key.feedback",FT_UINT8,
            BASE_HEX,VALS(local_dialpad_feedback),KEY_LOCAL_DIAL_PAD_FEED,NULL,HFILL}
      },
      { &hf_audio_source_descr,
         {"Source Description Item","unistim.source.desc.item",FT_UINT8,
            BASE_HEX,VALS(source_descriptions),AUDIO_SOURCE_DESCRIPTION,NULL,HFILL}
      },
      { &hf_audio_sdes_rtcp_bucket,
         {"RTCP Bucket Id","unistim.sdes.rtcp.bucket",FT_UINT8,
            BASE_HEX,NULL,AUDIO_SDES_RTCP_BUCKET,NULL,HFILL}
      },
      { &hf_audio_desired_jitter,
         {"Desired Jitter","unistim.audio.desired.jitter",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_high_water_mark,
         {"Threshold of audio frames where jitter buffer removes frames","unistim.high.water.mark",FT_UINT8,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      {  &hf_audio_early_packet_resync_thresh,
         {"Threshold in x/8000 sec where packets are too early","unistim.early.packet.thresh",FT_UINT32,
           BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_late_packet_resync_thresh,
         {"Threshold in x/8000 sec where packets are too late","unistim.late.packet.thresh",FT_UINT32,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_resolve_phone_port,
         {"Resolve Phone Port","unistim.resolve.phone.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_far_end_echo_port,
         {"Resolve Far End Port","unistim.resolve.far.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_far_end_ip_address,
         {"Resolve Far End IP","unistim.resolve.far.ip",FT_IPv4,
            BASE_NONE,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_nat_port,
         {"NAT Port","unistim.audio.nat.port",FT_UINT16,
            BASE_DEC,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_nat_ip_address,
         {"NAT IP Address","unistim.audio.nat.ip",FT_IPv4,
            BASE_NONE,NULL,0x00,NULL,HFILL}
      },
      { &hf_audio_direction_code,
         {"Stream Direction Code","unistim.audio.direction.codes",FT_UINT8,
            BASE_HEX,VALS(direction_codes),AUDIO_DIRECTION_CODE,NULL,HFILL}
      },
      { &hf_audio_hf_support,
         {"Handsfree supported","unistim.handsfree.support",FT_BOOLEAN,
            8,NULL,AUDIO_HF_SUPPORT,NULL,HFILL}
      },
      { &hf_audio_opt_rpt_max,
         {"Max Volume","unistim.max.vol",FT_BOOLEAN,
            8,TFS(&opt_rpt_enable_max_tone_vol),AUDIO_ENABLED_MAX_TONE,NULL,HFILL}
      },
      { &hf_audio_opt_rpt_adj_vol,
         {"Volume Adjustments","unistim.audio.volume.adj",FT_BOOLEAN,
            8,TFS(&opt_rpt_adjust_volume),AUDIO_ENABLED_ADJ_VOL,NULL,HFILL}
      },
      { &hf_audio_opt_rpt_auto_adj_vol,
         {"Auto Adjust RX Volume","unistim.auto.adj.rx.vol",FT_BOOLEAN,
            8,TFS(&opt_rpt_automatic_adjustable_rx_volume_report),
            AUDIO_AUTO_ADJ_RX_REP,NULL,HFILL}
      },
      { &hf_audio_opt_rpt_hs_on_air,
         {"HS On Air","unistim.audio.hs.on.air",FT_BOOLEAN,
            8,TFS(&opt_rpths_on_air_feature),AUDIO_HS_ON_AIR_FEATURE,NULL,HFILL}
      },
      { &hf_audio_opt_rpt_hd_on_air,
         {"HD On Air","unistim.audio.hd.on.air",FT_BOOLEAN,
            8,TFS(&opt_rpt_hd_on_air_feature),AUDIO_HD_ON_AIR_FEATURE,NULL,HFILL}
      },
      { &hf_audio_opt_rpt_noise_squelch,
         {"Automatic Squelch","unistim.auto.noise.squelch",FT_BOOLEAN,
            8,TFS(&opt_rpt_noise_sqlch_disable),AUDIO_NOISE_SQUELCH_DIS,NULL,HFILL}
      },
      { &hf_audio_rx_vol_apb_rpt,
         {"APB Volume Report","unistim.apb.volume.rpt",FT_UINT8,
            BASE_HEX,VALS(volume_rpt_apbs),AUDIO_APB_VOL_RPT,NULL,HFILL}
      },
      { &hf_audio_rx_vol_vol_up,
         {"Volume Up","unistim.audio.volume.up",FT_BOOLEAN,
            8,NULL,AUDIO_VOL_UP_RPT,NULL,HFILL}
      },
      { &hf_audio_rx_vol_vol_floor,
         {"RX Volume at Floor","unistim.audio.rx.vol.floor",FT_BOOLEAN,
            8,NULL,AUDIO_VOL_FLR_RPT,NULL,HFILL}
      },
      { &hf_audio_rx_vol_vol_ceiling,
         {"RX Volume at Ceiling","unistim.audio.rx.vol.ceiling",FT_BOOLEAN,
            8,NULL,AUDIO_VOL_CEIL_RPT,NULL,HFILL}
      },
      { &hf_audio_current_adj_vol_id,
         {"Current APB Volume Report","unistim.current.volume.rpt",FT_UINT8,
            BASE_HEX,VALS(volume_rpt_apbs),AUDIO_APB_VOL_RPT,NULL,HFILL}
       },
       { &hf_audio_current_rx_level,
          {"Current RX Volume Level","unistim.current.rx.vol.level",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_current_rx_range,
          {"Current RX Volume Range","unistim.current.rx.vol.range",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_cadence_select,
          {"Alerting Cadence Select","unistim.alert.cad.sel",FT_UINT8,
             BASE_HEX,NULL,AUDIO_ALERT_CADENCE_SEL,NULL,HFILL}
       },
       { &hf_audio_warbler_select,
          {"Alerting Warbler Select","unistim.alert.warb.select",FT_UINT8,
             BASE_HEX,NULL,AUDIO_ALERT_WARBLER_SEL,NULL,HFILL}
       },
       { &hf_audio_open_stream_rpt,
          {"Open Stream Report","unistim.open.audio.stream.rpt",FT_UINT8,
             BASE_HEX,VALS(stream_result),0x00,NULL,HFILL}
       },
       { &hf_audio_sdes_rpt_source_desc,
          {"Report Source Description","unistim.rpt.src.desc",FT_UINT8,
             BASE_HEX,VALS(source_descipts),AUDIO_SDES_INFO_RPT_DESC,NULL,HFILL}
       },
       { &hf_audio_sdes_rpt_buk_id,
          {"Report RTCP Bucket ID","unistim.rpt.rtcp.buk.id",FT_UINT8,
             BASE_HEX,NULL,AUDIO_SDES_INFO_RPT_BUK,NULL,HFILL}
       },
       { &hf_audio_phone_port,
          {"Phone Listen Port","unistim.phone.listen.port",FT_UINT16,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_phone_ip,
          {"Phone Listen Address","unistim.phone.listen.address",FT_IPv4,
             BASE_NONE,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_phone_add_len,
          {"Phone Address Length","unistim.phone.address.len",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_nat_listen_port,
          {"NAT Listen Port","unistim.nat.listen.port",FT_UINT16,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_nat_ip,
          {"NAT Listen Address","unistim.nat.listen.address",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_nat_add_len,
          {"NAT Address Length","unistim.nat.address.len",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_audio_stream_direction_code,
          {"Audio Stream Direction","unistim.audio.stream.direction",FT_UINT8,
             BASE_HEX,VALS(stream_direction_codes),AUDIO_STREAM_DIRECTION,NULL,HFILL}
       },
       { &hf_audio_stream_state,
          {"Audio Stream State","unistim.audio.stream.state",FT_BOOLEAN,
             8,TFS(&stream_states),AUDIO_STREAM_STATE,NULL,HFILL}
       },
       { &hf_audio_transducer_list_length,
          {"Transducer List Length","unistim.trans.list.len",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_net_file_xfer_mode,
          {"File Transfer Mode","unistim.net.file.xfer.mode",FT_UINT8,
             BASE_HEX,VALS(file_xfer_modes),NETWORK_FILE_XFER_MODE,NULL,HFILL}
       },
       { &hf_net_force_download ,
          {"Force Download","unistim.net.force.download",FT_BOOLEAN,
             8,NULL,NETWORK_FORCE_DLOAD,NULL,HFILL}
       },
       { &hf_net_use_file_server_port,
          {"Use Custom Server Port","unistim.net.use.server.port",FT_BOOLEAN,
             8,NULL,NETWORK_USE_FSERV_PORT,NULL,HFILL}
       },
       { &hf_net_use_local_port,
          {"Use Custom Local Port","unistim.net.use.local.port",FT_BOOLEAN,
             8,NULL,NETWORK_USE_LOCAL_PORT,NULL,HFILL}
       },
       { &hf_net_file_server_port,
          {"File Server Port","unistim.net.file.server.port",FT_UINT16,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_net_local_port,
          {"Local XFer Port","unistim.net.local.xfer.port",FT_UINT16,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_net_file_server_address,
          {"File Server IP Address","unistim.net.file.server.address",FT_IPv4,
             BASE_NONE,NULL,0x00,NULL,HFILL}
       },
       { &hf_keys_admin_command,
          {"Admin Command","unistim.key.icon.admin.cmd",FT_UINT8,
             BASE_HEX,VALS(admin_commands),KEY_ADMIN_CMD,NULL,HFILL}
       },
       { &hf_keys_logical_icon_id,
          {"Logical Icon ID","unistim.keys.logical.icon.id",FT_UINT16,
             BASE_HEX,NULL,0x00,NULL,HFILL}
       },
       { &hf_keys_repeat_timer_one,
          {"Key Repeat Timer 1 Value","unistim.keys.repeat.time.one",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_keys_repeat_timer_two,
          {"Key Repeat Timer 2 Value","unistim.keys.repeat.time.two",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_keys_led_id,
          {"Led ID","unistim.keys.led.id",FT_UINT8,
             BASE_HEX,VALS(keys_led_ids),0x00,NULL,HFILL}
       },
       { &hf_keys_phone_icon_id,
          {"Phone Icon ID","unistim.keys.phone.icon.id",FT_UINT8,
             BASE_HEX,NULL,0x00,NULL,HFILL}
       },
       { &hf_keys_cadence_on_time,
          {"Indicator Cadence On Time","unistim.keys.cadence.on.time",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_keys_cadence_off_time,
          {"Indicator Cadence Off Time","unistim.keys.cadence.off.time",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_keys_user_activity_timeout,
          {"User Activity Timeout Value","unistim.keys.user.timeout.value",FT_UINT8,
             BASE_DEC,NULL,0x00,NULL,HFILL}
       },
       { &hf_display_call_timer_mode,
         {"Call Timer Mode","unistim.display.call.timer.mode",FT_BOOLEAN,
           8,TFS(&call_duration_timer_mode),DISPLAY_CALL_TIMER_MODE,NULL,HFILL}
       },
       { &hf_display_call_timer_reset,
         {"Call Timer Reset","unistim.display.call.timer.reset",FT_BOOLEAN,
           8,TFS(&call_duration_timer_reset),DISPLAY_CALL_TIMER_RESET,NULL,HFILL}
       },
       { &hf_display_call_timer_display,
         {"Call Timer Display","unistim.display.call.timer.display",FT_BOOLEAN,
           8,TFS(&call_duration_display_timer),DISPLAY_CALL_TIMER_DISPLAY,NULL,HFILL}
       },
       { &hf_display_call_timer_delay,
         {"Call Timer Delay","unistim.display.call.timer.delay",FT_BOOLEAN,
           8,TFS(&call_duration_timer_delay),DISPLAY_CALL_TIMER_DELAY,NULL,HFILL}
       },
       { &hf_display_call_timer_id,
         {"Call Timer ID","unistim.display.call.timer.id",FT_UINT8,
           BASE_DEC,NULL,DISPLAY_CALL_TIMER_ID,NULL,HFILL}
       },

/****LAST****/   
      { &hf_generic_string,
         {"DATA","unistim.generic.data",FT_STRING,
            BASE_NONE,NULL,0x00,NULL,HFILL}
      },
      { &hf_generic_data,
         {"DATA","unistim.generic.data",FT_BYTES,
            BASE_HEX,NULL,0x00,NULL,HFILL}
      }
};

#endif
