/* packet-acdr.c
 * Routines for acdr packet dissection
 * Copyright 2019, AudioCodes Ltd
 *   @author: Alex Rodikov <alex.rodikov@audiocodes.com>
 *   @author: Beni Bloch <beni.bloch@audiocodes.com>
 *   @author: Orgad Shaneh <orgad.shaneh@audiocodes.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include "packet-acdr.h"

#define ACDR_VERSION_MAJOR 0
#define ACDR_VERSION_MINOR 9
#define PORT_AC_DR 925

// acdr header definitions

//  1 B        6 B           2 B        2B        1 B          1 B           1 B             1 B                     0-14 B
//------------------------------------------------------------------------------------------------------------------------------------------
//Version |  TimeStamp  | Source ID | Dest ID | Reserved  |  Trace Point | Media Type | Payload Header Length |  Payload Header  |   Payload
//------------------------------------------------------------------------------------------------------------------------------------------

// From version #4:

//  1 B        4 B       2 B        4 B        4 B       1 B          1 B           1 B             1 B                     0-14 B
//------------------------------------------------------------------------------------------------------------------------------------------
//Version | TimeStamp | SeqNum | Source ID | Dest ID | Reserved  |  Trace Point | Media Type | Payload Header Length |  Payload Header  |   Payload
//------------------------------------------------------------------------------------------------------------------------------------------

#define MII_HEADER_BYTE_LENGTH 4
#define AC5X_ANALYSIS_PACKET_HEADER 16
#define AC5X_HPI_PACKET_HEADER 4

// ACDR extension header macros:
#define EXT_HEADER_IPV4_ADDRESS_BYTE_COUNT 4
#define EXT_HEADER_IPV6_ADDRESS_BYTE_COUNT 16
#define EXT_HEADER_UDP_PORT_BYTE_COUNT 2
#define EXT_HEADER_IP_TOS_BYTE_COUNT 1
#define EXT_HEADER_C5_CONTROL_FLAFS_COUNT 1

// Signaling Packet Macros:
#define HEADER_FIELD_SIG_OPCODE_BYTE_NO 0
#define HEADER_FIELD_SIG_OPCODE_BYTE_COUNT 2
#define HEADER_FIELD_SIG_TIME_BYTE_NO 2
#define HEADER_FIELD_SIG_TIME_BYTE_COUNT 4
#define HEADER_FIELD_SIG_MESSAGE_BYTE_NO 6


// masks for the former reserved byte (data byte)
// Must be same as in file DebugTarget.h
#define MEDIUM_MASK 0x1
#define IPV6_MASK 0x2
#define FRAGMENTED_MASK 0x4
#define HEADERADDED_MASK 0x8
#define ENCRYPTED_MASK 0x10
#define MTCE_MASK 0x20
#define LI_MASK 0x40

#define FAVORITE_MASK 0x10

void proto_register_acdr(void);
void proto_reg_handoff_acdr(void);

enum Direction
{
    DIR_TX = 0,
    DIR_RX = 1
};

// Array that is used to check missed ACDR packets
#define AC_SEQ_NUM_AR_SIZE 255
struct SeqNumIpSeq
{
    guint ip;
    guint seq;
};

static const value_string acdr_trace_pt_vals[] = {
    {Net2Dsp,          "Network -> Dsp"                              }, //  0
    {Dsp2Net,          "Dsp -> Network"                              }, //  1
    {Dsp2Host,         "Dsp -> Host"                                 }, //  2
    {Host2Dsp,         "Host -> Dsp"                                 }, //  3
    {Net2Host,         "Network -> Host"                             }, //  4
    {Host2Net,         "Host -> Network"                             }, //  5
    {System,           "System"                                      }, //  6
    {Dsp2Dsp,          "Dsp -> Dsp (Media Loopback)"                 }, //  7
    {Net2Net,          "Network -> Network (Mediation)"              }, //  8
    {Dsp2Tdm,          "Dsp -> Tdm"                                  }, //  9
    {Tdm2Dsp,          "Tdm -> Dsp"                                  }, // 10
    {Np2Dsp,           "Network Processor(C5) -> Dsp"                }, // 11
    {Dsp2Np,           "Dsp -> Network Processor(C5)"                }, // 12
    {Host2Np,          "Host -> Network Processor(C5)"               }, // 13
    {Np2Host,          "Network Processor(C5) -> Host"               }, // 14
    {acUnknown,        "Unknown"                                     }, // 15 (Internal Only - not in Wireshark)
    {Net,              "Network Only"                                }, // 16
    {P2P,              "Dsp -> Dsp (P2P)"                            }, // 17
    {DspDecoder,       "Host -> DSP (before DSP Decoder)"            }, // 18
    {DspEncoder,       "Dsp -> Host (before DSP Encoder)"            }, // 19
    {VoipDecoder,      "Media Network Incoming (before Voip Decoder)"}, // 20
    {VoipEncoder,      "Media Voip Outgoing (before Voip Encoder)"   }, // 21
    {NetEncoder,       "Media Network Outgoing (before Net Encoder)" }, // 22
    {P2PDecoder,       "Dsp Internal <- DSP (after Native Decoder)"  }, // 23
    {P2PEncoder,       "Dsp Internal -> DSP (before Native Encoder)" }, // 24
    {Host2Pstn,        "Host -> Pstn"                                }, // 25
    {Pstn2Host,        "Pstn -> Host"                                }, // 26
    {Net2DspPing,      "Srtp Ping: Network -> Dsp"                   }, // 27
    {Dsp2NetPing,      "Srtp Ping: Dsp -> Network"                   }, // 28
    {Src2Dest,         "Src -> Dst"                                  }, // 29 (Internal Only - not in Wireshark)
    {Addr2Addr,        "Addr -> Addr"                                }, // 30 (Internal Only - not in Wireshark)
    {GeneralSystem,    "General System"                              }, // 31 (Internal Only - not in Wireshark)
    {AllMedia,         "All Media"                                   }, // 32 (Internal Only - not in Wireshark)
    {DspIncoming,      "Dsp Internal <- Host (DSP Incoming)"         }, // 33
    {DspOutgoing,      "Dsp Internal -> Host (DSP Outgoing)"         }, // 34
    {AfterSrtpDecoder, "Media Network Incoming (After Srtp Decoder)" }, // 35
    {0,                NULL                                          }
};

static const value_string acdr_media_type_vals[] = {
    {ACDR_DSP_AC49X,        "DSP 49x Packet"     },
    {ACDR_RTP,              "RTP Packet"         },
    {ACDR_RTCP,             "RTCP Packet"        },
    {ACDR_T38,              "T38 Packet"         },
    {ACDR_Event,            "HostEvent"          },
    {ACDR_Info,             "System Info"        },
    {ACDR_VoiceAI,          "Voice AI Packet"    },
    {ACDR_NotUse1,          "Not Use 1"          },
    {ACDR_NotUse2,          "Not Use 2"          },
    {ACDR_NotUse3,          "Not Use 3"          },
    {ACDR_SIP,              "SIP Packet"         },
    {ACDR_MEGACO,           "Megaco Packet"      },
    {ACDR_MGCP,             "MGCP Packet"        },
    {ACDR_TPNCP,            "TPNCP Packet"       },
    {ACDR_Control,          "Control Packet"     },
    {ACDR_PCM,              "PCM"                },
    {ACDR_NP_CONTROL,       "C5 Control packet"  },
    {ACDR_NP_DATA,          "C5 Data packet"     },
    {ACDR_DSP_AC45X,        "DSP 64x Packet"     },
    {ACDR_DSP_AC48X,        "DSP 48x Packet"     },
    {ACDR_HA,               "HA trace"           },
    {ACDR_CAS,              "CAS"                },
    {ACDR_NET_BRICKS,       "Net Bricks trace"   },
    {ACDR_COMMAND,          "TPNCP Command"      },
    {ACDR_VIDEORTP,         "Video RTP"          },
    {ACDR_VIDEORTCP,        "Video RTCP"         },
    {ACDR_PCIIF_COMMAND,    "PCIIF Command"      },
    {ACDR_GWAPPSYSLOG,      "GWApp syslog"       },
    {ACDR_V1501,            "V150.1 - Data relay"},
    {ACDR_DSP_AC5X,         "DSP 5x Packet"      },
    {ACDR_TLS,              "TLS Data"           },
    {ACDR_TLSPeek,          "TLS Peek Date"      },
    {ACDR_DSP_AC5X_MII,     "DSP 5x MII Packet"  },
    {ACDR_NATIVE,           "P2P - NATIVE"       },
    {ACDR_SIGNALING,        "Signaling"          },
    {ACDR_FRAGMENTED,       "Fragmented"         },
    {ACDR_QOE_CDR,          "QOE CDR"            },
    {ACDR_QOE_MDR,          "QOE MDR"            },
    {ACDR_QOE_EVENT,        "QOE Event"          },
    {ACDR_DSP_TDM_PLAYBACK, "DSP Tdm Playback"   },
    {ACDR_DSP_NET_PLAYBACK, "DSP Net Playback"   },
    {ACDR_DSP_DATA_RELAY,   "DSP Data Relay"     },
    {ACDR_DSP_SNIFFER,      "DSP Sniffer"        },
    {ACDR_RTP_AMR,          "RTP AMR"            },
    {ACDR_RTP_EVRC,         "RTP EVRC"           },
    {ACDR_RTP_RFC2198,      "RTP Rfc2198"        },
    {ACDR_RTP_RFC2833,      "RTP Rfc2833"        },
    {ACDR_T38_OVER_RTP,     "T38 over RTP"       },
    {ACDR_RTP_FEC,          "RTP FEC"            },
    {ACDR_RTP_FAX_BYPASS,   "RTP Fax Bypass"     },
    {ACDR_RTP_MODEM_BYPASS, "RTP Modem Bypass"   },
    {ACDR_RTP_NSE,          "RTP NSE"            },
    {ACDR_RTP_NO_OP,        "RTP NoOp"           },
    {ACDR_DTLS,             "DTLS Data"          },
    {0,                NULL                 }
};

static const value_string acdr_media_type_dummy_vals[] = {
    {ACDR_DSP_AC49X,     ""             },
    {ACDR_RTP,           ""             },
    {ACDR_RTCP,          ""             },
    {ACDR_T38,           ""             },
    {ACDR_Event,         ""             },
    {ACDR_Info,          ""             },
    {ACDR_VoiceAI,       ""             },
    {ACDR_NotUse1,       ""             },
    {ACDR_NotUse2,       ""             },
    {ACDR_NotUse3,       ""             },
    {ACDR_SIP,           ""             },
    {ACDR_MEGACO,        ""             },
    {ACDR_MGCP,          ""             },
    {ACDR_TPNCP,         ""             },
    {ACDR_Control,       ""             },
    {ACDR_PCM,           ""             },
    {ACDR_NP_CONTROL,    ""             },
    {ACDR_NP_DATA,       ""             },
    {ACDR_DSP_AC45X,     ""             },
    {ACDR_DSP_AC48X,     ""             },
    {ACDR_HA,            ""             },
    {ACDR_CAS,           ""             },
    {ACDR_NET_BRICKS,    ""             },
    {ACDR_COMMAND,       ""             },
    {ACDR_VIDEORTP,      ""             },
    {ACDR_VIDEORTCP,     ""             },
    {ACDR_PCIIF_COMMAND, ""             },
    {ACDR_GWAPPSYSLOG,   ""             },
    {ACDR_V1501,         ""             },
    {ACDR_DSP_AC5X,      ""             },
    {ACDR_TLS,           ""             },
    {ACDR_TLSPeek,       ""             },
    {ACDR_DSP_AC5X_MII,  "DSP 5x Packet"},
    {0,             NULL           }
};

enum AcdrAc5xProtocolType
{
    ACDR_AC5X_PROTOCOL_TYPE__REGULAR,
    ACDR_AC5X_PROTOCOL_TYPE__TDM_PLAYBACK,
    ACDR_AC5X_PROTOCOL_TYPE__NET_PLAYBACK
};

struct AcdrAc5xPrivateData
{
    guint packet_direction;
    enum AcdrAc5xProtocolType protocol_type;
    guint mii_header_exist;
};

typedef struct AcdrTlsPacketInfo
{
    guint16 source_port;
    guint16 dest_port;
    guint8  application;
} AcdrTlsPacketInfo;


static const value_string hf_acdr_ext_tls_application_vals[] = {
    {0, "UNKNWN"},
    {1, "HTTP"  },
    {2, "TR069" },
    {3, "SIP"   },
    {4, "LDAP"  },
    {5, "XML"   },
    {6, "TCP"   },
    {7, "TELNET"},
    {8, "FTP"   },
    {9, "TPNCP" },
    {0, NULL    },
};

static const value_string hf_acdr_ext_direction_vals[] = {
    {1, "Outgoing"},
    {0, "Incoming"},
    {0, NULL      }
};

static int proto_acdr = -1;
static int proto_ac5xmii = -1;
static int proto_ac5x = -1;
static int proto_ac48x = -1;
static int proto_ac49x = -1;

// Define headers for acdr
static int hf_acdr_seq_num = -1;
static int hf_acdr_timestamp = -1;
static int hf_acdr_sourceid = -1;
static int hf_acdr_destid = -1;
static int hf_acdr_version = -1;
static int hf_acdr_trace_pt = -1;
static int hf_acdr_media_type = -1;
static int hf_acdr_media_type_dsp_ac5x = -1;
static int hf_acdr_pl_offset_type = -1;
static int hf_acdr_header_ext_len_type = -1;
static int hf_acdr_data = -1;
static int hf_acdr_data_mii = -1;
static int hf_acdr_data_ipv6 = -1;
static int hf_acdr_data_fragmented = -1;
static int hf_acdr_data_headeradded = -1;
static int hf_acdr_data_encrypted = -1;
static int hf_acdr_data_mtce = -1;
static int hf_acdr_data_li = -1;

static int hf_acdr_session_id = -1;
static int hf_acdr_session_id_board_id = -1;
static int hf_acdr_session_id_reset_counter = -1;
static int hf_acdr_session_id_session_number = -1;
static int hf_acdr_session_id_long_session_number = -1;

static int hf_acdr_ext_c5_control_favorite = -1;

static int hf_acdr_payload_header = -1;
static int hf_acdr_mii_header = -1;

// header extension
static int hf_acdr_ext_srcudp = -1;
static int hf_acdr_ext_dstudp = -1;
static int hf_acdr_ext_srcip = -1;
static int hf_acdr_ext_srcipv6 = -1;
static int hf_acdr_ext_dstip = -1;
static int hf_acdr_ext_dstipv6 = -1;
static int hf_acdr_ext_protocol = -1;
static int hf_acdr_ext_tls_application = -1;
static int hf_acdr_ext_direction = -1;
static int hf_acdr_ext_iptos = -1;
static int hf_acdr_ext_c5_control_flags = -1;

static int hf_acdr_unknown_packet = -1;
static int hf_acdr_ext_pstn_trace_seq_num = -1;
static int hf_acdr_header_extension = -1;
static int hf_acdr_ext_dsp_core = -1;
static int hf_acdr_ext_dsp_channel = -1;
static int hf_acdr_ext_event_id = -1;
static int hf_acdr_ext_event_source = -1;

// Mii header extension
static int hf_acdr_mii_sequence = -1;
static int hf_acdr_mii_packet_size = -1;
static int hf_acdr_5x_analysis_packet_header = -1;
static int hf_5x_analysis_version = -1;
static int hf_5x_analysis_direction = -1;
static int hf_5x_analysis_sub_version = -1;
static int hf_5x_analysis_device = -1;
static int hf_5x_analysis_sequence = -1;
static int hf_5x_analysis_spare1 = -1;
static int hf_5x_analysis_timestamp = -1;
static int hf_5x_analysis_spare2 = -1;

static int hf_acdr_5x_hpi_packet_header = -1;
static int hf_5x_hpi_sync5 = -1;
static int hf_5x_hpi_udp_checksum = -1;
static int hf_5x_hpi_resource_id = -1;
static int hf_5x_hpi_favorite = -1;
static int hf_5x_hpi_protocol = -1;

static int hf_ac45x_packet = -1;
static int hf_ac48x_packet = -1;
static int hf_ac49x_packet = -1;
static int hf_ac5x_packet = -1;

static int hf_signaling_packet = -1;
static int hf_acdr_signaling_opcode = -1;
static int hf_acdr_signaling_timestamp = -1;


// Define the trees for acdr
static int ett_acdr = -1;
static int ett_extension = -1;
static int ett_ac49x_packet = -1;
static int ett_ac48x_packet = -1;
static int ett_ac45x_packet = -1;
static int ett_ac5x_packet = -1;
static int ett_ac5x_mii_packet = -1;
static int ett_mii_header = -1;
static int ett_signaling_packet = -1;
static int ett_extra_data = -1;
static int ett_c5_cntrl_flags = -1;
static int ett_5x_analysis_packet_header = -1;
static int ett_5x_hpi_packet_header = -1;
static int ett_session_id = -1;

static expert_field ei_acdr_version_not_supported = EI_INIT;

static int proto_rtp;

static dissector_table_t media_type_table;
static dissector_table_t tls_application_table;
static dissector_table_t tls_application_port_table;

static dissector_handle_t acdr_dissector_handle;
static dissector_handle_t rtp_dissector_handle;
static dissector_handle_t udp_stun_dissector_handle = NULL;
static dissector_handle_t rtp_events_handle;
static dissector_handle_t rtp_rfc2198_handle;
static dissector_handle_t amr_handle;
static dissector_handle_t evrc_handle;
static dissector_table_t rtp_dissector_table;
static dissector_handle_t rtcp_dissector_handle;
static dissector_handle_t ip_dissector_handle;
static dissector_handle_t json_dissector_handle;
static dissector_handle_t megaco_dissector_handle;
static dissector_handle_t mgcp_dissector_handle;
static dissector_handle_t sip_dissector_handle;
static dissector_handle_t dsp_49x_dissector_handle;
static dissector_handle_t dsp_48x_dissector_handle;
static dissector_handle_t dsp_45x_dissector_handle;
static dissector_handle_t dsp_5x_dissector_handle;
static dissector_handle_t dsp_5x_MII_dissector_handle;
static dissector_handle_t udp_dissector_handle;
static dissector_handle_t xml_dissector_handle;
static dissector_handle_t lix2x3_dissector_handle;

static void dissect_rtp_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               guint8 media_type, guint16 payload_type);
static int  dissect_signaling_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void create_5x_analysis_packet_header_subtree(proto_tree *tree, tvbuff_t *tvb);
static void create_5x_hpi_packet_header_subtree(proto_tree *tree, tvbuff_t *tvb);

static int
create_full_session_id_subtree(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 ver)
{
    guint64 full_session_id = tvb_get_letoh64(tvb, offset);
    proto_item *packet_item = NULL;
    proto_item *packet_tree = NULL;
    guint64 session_int = 0;
    gint session_id_length;

    // SessionID
    const char *str = "N/A";

    if (full_session_id != 0) {
        const char *session_ext = "";
        guint32 board_id = tvb_get_ntoh24(tvb, offset);
        guint8 reset_counter = tvb_get_guint8(tvb, offset + 3);

        if ((ver & 0xF) == 7)
            session_int = tvb_get_ntohl(tvb, offset + 4);
        else
            session_int = tvb_get_ntoh40(tvb, offset + 4);

        if (session_int != 0)
            session_ext = wmem_strdup_printf(wmem_packet_scope(), ":%" G_GINT64_MODIFIER "u", session_int);
        str = wmem_strdup_printf(wmem_packet_scope(), "%x:%d%s", board_id, reset_counter, session_ext);
    }

    if ((ver & 0xF) == 7) {
        session_id_length = 8;
        packet_item = proto_tree_add_string(tree, hf_acdr_session_id, tvb, offset, session_id_length, str);
    } else {
        session_id_length = 9;
        packet_item = proto_tree_add_string(tree, hf_acdr_session_id, tvb, offset, session_id_length, str);
    }
    if (full_session_id == 0)
        return offset + session_id_length;

    packet_tree = proto_item_add_subtree(packet_item, ett_session_id);

    // SessionID.boardid
    proto_tree_add_item(packet_tree, hf_acdr_session_id_board_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    // SessionID.resetcounter
    proto_tree_add_item(packet_tree, hf_acdr_session_id_reset_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // SessionID.sessionnumber
    if ((ver & 0xF) == 7) {
        proto_tree_add_item(packet_tree, hf_acdr_session_id_session_number, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        proto_tree_add_item(packet_tree, hf_acdr_session_id_long_session_number, tvb,
                            offset, 5, ENC_BIG_ENDIAN);
        offset += 5;
    }

    return offset;
}

static void
create_header_extension_subtree(proto_tree *tree, tvbuff_t *tvb, gint offset, guint8 extension_length,
                                guint32 ver, guint8 media_type, guint8 trace_point, guint8 extra_data,
                                AcdrTlsPacketInfo *tls_packet_info)
{
    proto_tree *extension_tree;
    gboolean ipv6 = ((IPV6_MASK & extra_data) == IPV6_MASK);

    // parse the header extension
    proto_item *ti = proto_tree_add_item(tree, hf_acdr_header_extension, tvb, offset,
                                         extension_length, ENC_NA);

    extension_tree = proto_item_add_subtree(ti, ett_extension);

    if (media_type == ACDR_TLS || media_type == ACDR_TLSPeek) {
        tls_packet_info->source_port = tvb_get_ntohs(tvb, offset);
        tls_packet_info->dest_port = tvb_get_ntohs(tvb, offset + 2);
        tls_packet_info->application = tvb_get_guint8(tvb, offset + 12);
    }

    //further processing only involves adding fields
    if (tree == NULL)
        return;

    switch (trace_point) {
    case DspIncoming:
    case DspOutgoing:

        // Gen5 only - special case of recorded packets from DSP
        proto_tree_add_item(extension_tree, hf_acdr_ext_dsp_core, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(extension_tree, hf_acdr_ext_dsp_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
        return;
    }

    switch (media_type) {
    case ACDR_CAS:
    case ACDR_NET_BRICKS:
        if (extension_length > 0) {
            proto_tree_add_item(extension_tree, hf_acdr_ext_pstn_trace_seq_num, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
        }
        break;
    case ACDR_Event:
        proto_tree_add_item(extension_tree, hf_acdr_ext_event_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(extension_tree, hf_acdr_ext_event_source, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case ACDR_DSP_AC49X:
    case ACDR_DSP_AC48X:
    case ACDR_DSP_AC45X:
    case ACDR_DSP_AC5X:
    case ACDR_DSP_AC5X_MII:
    case ACDR_DSP_SNIFFER:
        proto_tree_add_item(extension_tree, hf_acdr_ext_dsp_core, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(extension_tree, hf_acdr_ext_dsp_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case ACDR_RTP:
    case ACDR_RTP_AMR:
    case ACDR_RTP_EVRC:
    case ACDR_RTP_RFC2198:
    case ACDR_RTP_RFC2833:
    case ACDR_T38_OVER_RTP:
    case ACDR_RTP_FEC:
    case ACDR_RTP_FAX_BYPASS:
    case ACDR_RTP_MODEM_BYPASS:
    case ACDR_RTP_NSE:
    case ACDR_RTP_NO_OP:
    case ACDR_T38:
    case ACDR_RTCP:
    case ACDR_VIDEORTP:
    case ACDR_VIDEORTCP:
    case ACDR_NATIVE:
    case ACDR_DTLS:
    {
        switch (trace_point) {
        case Net2Dsp:
        case Net2Host:
        case DspDecoder:
        case VoipDecoder:
        case Net2DspPing:
        case AfterSrtpDecoder:
            if (((ver & 0xF) >= 3) && ipv6) {
                proto_tree_add_item(extension_tree, hf_acdr_ext_srcipv6, tvb, offset, 16, ENC_NA);
                offset += 16;
            } else {
                proto_tree_add_item(extension_tree, hf_acdr_ext_srcip, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

            // Gen3 only: we put the UDP header in the last 8 bytes of the header extension.
            // So, we have only IP address into the real header extension
            if ((media_type == ACDR_T38) && (trace_point == Net2Dsp) && (extension_length == 4))
                break;

            proto_tree_add_item(extension_tree, hf_acdr_ext_srcudp, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(extension_tree, hf_acdr_ext_dstudp, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(extension_tree, hf_acdr_ext_iptos, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            if ((trace_point == Net2Dsp) && (extension_length == 10)) {
                // Gen3 only: we should add one byte of C5 Control Flags
                // C5 Control Flags

                static int * const c5_cntrl_flags[] = {
                    &hf_acdr_ext_c5_control_favorite,
                    NULL
                };

                proto_tree_add_bitmask(extension_tree, tvb, offset, hf_acdr_ext_c5_control_flags,
                                       ett_c5_cntrl_flags, c5_cntrl_flags, ENC_BIG_ENDIAN);
            }
            break;
        case Dsp2Net:
        case Host2Net:
        case P2P:
        case P2PDecoder:
        case P2PEncoder:
        case NetEncoder:
        case VoipEncoder:
        case DspEncoder:
        case Dsp2NetPing:
            if (((ver & 0xF) >= 3) && ipv6) {
                proto_tree_add_item(extension_tree, hf_acdr_ext_dstipv6, tvb, offset, 16, ENC_NA);
                offset += 16;
            } else {
                proto_tree_add_item(extension_tree, hf_acdr_ext_dstip, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

            // Gen3 only: we put the UDP header in the last 8 bytes of the header extension.
            // So, we have only IP address into the real header extension
            if ((media_type == ACDR_T38) && (trace_point == Dsp2Net) && (extension_length == 4))
                break;

            proto_tree_add_item(extension_tree, hf_acdr_ext_dstudp, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(extension_tree, hf_acdr_ext_srcudp, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(extension_tree, hf_acdr_ext_iptos, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;

        default:
            proto_tree_add_item(extension_tree, hf_acdr_payload_header, tvb, offset,
                                extension_length, ENC_NA);
            break;
        }
        break;
    }

    case ACDR_VoiceAI:
    case ACDR_SIP:
    case ACDR_MEGACO:
    case ACDR_MGCP:
    case ACDR_TPNCP:
    case ACDR_Control:
        if (trace_point == System) {
            proto_tree_add_item(extension_tree, hf_acdr_ext_srcip, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(extension_tree, hf_acdr_ext_dstip, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(extension_tree, hf_acdr_ext_srcudp, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(extension_tree, hf_acdr_ext_dstudp, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(extension_tree, hf_acdr_ext_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(extension_tree, hf_acdr_ext_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        } else {
            proto_tree_add_item(extension_tree, hf_acdr_payload_header, tvb, offset,
                                extension_length, ENC_NA);
        }
        break;
    case ACDR_TLS:
    case ACDR_TLSPeek:
        proto_tree_add_item(extension_tree, hf_acdr_ext_srcudp, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(extension_tree, hf_acdr_ext_dstudp, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(extension_tree, hf_acdr_ext_srcip, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(extension_tree, hf_acdr_ext_dstip, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(extension_tree, hf_acdr_ext_tls_application, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;

    default:

        // Payload Header - only show it if exists
        proto_tree_add_item(extension_tree, hf_acdr_payload_header, tvb, offset, extension_length,
                            ENC_NA);
    }
}

static void
create_mii_header_subtree(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 media_type)
{
    proto_tree *mii_header_tree;

    // parse the header extension
    proto_item *ti = proto_tree_add_item(tree, hf_acdr_mii_header, tvb,
                                         offset, MII_HEADER_BYTE_LENGTH, ENC_NA);

    mii_header_tree = proto_item_add_subtree(ti, ett_mii_header);

    switch (media_type) {
    case ACDR_DSP_AC5X_MII:
    case ACDR_RTP:
    case ACDR_RTP_AMR:
    case ACDR_RTP_EVRC:
    case ACDR_RTP_RFC2198:
    case ACDR_RTP_RFC2833:
    case ACDR_T38_OVER_RTP:
    case ACDR_RTP_FEC:
    case ACDR_RTP_FAX_BYPASS:
    case ACDR_RTP_MODEM_BYPASS:
    case ACDR_RTP_NSE:
    case ACDR_RTP_NO_OP:
    case ACDR_T38:
    case ACDR_RTCP:
    case ACDR_VIDEORTP:
    case ACDR_VIDEORTCP:
    case ACDR_NATIVE:
        proto_tree_add_item(mii_header_tree, hf_acdr_mii_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(mii_header_tree, hf_acdr_mii_packet_size, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    }
}

static void
create_5x_analysis_packet_header_subtree(proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree *ac5x_analysis_packet_header;

    // parse the header extension
    proto_item *ti = proto_tree_add_item(tree, hf_acdr_5x_analysis_packet_header, tvb,
                                         AC5X_ANALYSIS_PACKET_HEADER, -1, ENC_NA);

    ac5x_analysis_packet_header = proto_item_add_subtree(ti, ett_5x_analysis_packet_header);

    if (tree) {
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_version, tvb, 0, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_direction, tvb, 2, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_sub_version, tvb, 2, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_device, tvb, 3, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_sequence, tvb, 4, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_spare1, tvb, 6, 2,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_timestamp, tvb, 8, 4,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(ac5x_analysis_packet_header, hf_5x_analysis_spare2, tvb, 12, 4,
                            ENC_BIG_ENDIAN);
    }
}

static void
create_5x_hpi_packet_header_subtree(proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree *ac5x_hpi_packet_header;

    // parse the header extension
    proto_item *ti = proto_tree_add_item(tree, hf_acdr_5x_hpi_packet_header, tvb, 0,
                                         AC5X_HPI_PACKET_HEADER, ENC_NA);

    ac5x_hpi_packet_header = proto_item_add_subtree(ti, ett_5x_hpi_packet_header);

    if (!tree)
        return;
    proto_tree_add_item(ac5x_hpi_packet_header, hf_5x_hpi_sync5, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ac5x_hpi_packet_header, hf_5x_hpi_udp_checksum, tvb, 0, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(ac5x_hpi_packet_header, hf_5x_hpi_resource_id, tvb, 1, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(ac5x_hpi_packet_header, hf_5x_hpi_favorite, tvb, 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ac5x_hpi_packet_header, hf_5x_hpi_protocol, tvb, 3, 1, ENC_BIG_ENDIAN);
}

static void
acdr_payload_handler(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                     acdr_dissector_data_t *data, const char *proto_name)
{
    if (data->header_added) {
        dissector_handle_t dissector = ip_dissector_handle;
        if (data->media_type == ACDR_DTLS || data->media_type == ACDR_T38)
            dissector = udp_dissector_handle;
        if (dissector)
            call_dissector(dissector, tvb, pinfo, tree);
        else
            call_data_dissector(tvb, pinfo, tree);
        if (proto_name)
            col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name);
        return;
    }
    if (data->li_packet && !data->header_added && lix2x3_dissector_handle)
    {
        if (call_dissector_only(lix2x3_dissector_handle, tvb, pinfo, tree, data))
            return;
    }
    // check registered media types
    if (dissector_try_uint_new(media_type_table, data->media_type, tvb, pinfo, tree, FALSE, data))
        return;
    proto_tree_add_item(tree, hf_acdr_unknown_packet, tvb, 0, 0, ENC_NA);
}

static void
dissect_rtp_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 media_type,
                   guint16 payload_type)
{
    proto_tree *rtp_data_tree;
    dissector_handle_t old_dissector_handle = NULL;

    int bytes_dissected = 0;

    if ((tvb_get_guint8(tvb, 0) & 0xC0) == 0) {
        // RTP Version = 0
        if (tvb_get_ntohl(tvb, 4) == 0x2112a442) {
            // This is STUN RFC 5389 packet
            if (udp_stun_dissector_handle) {
                bytes_dissected = call_dissector(udp_stun_dissector_handle, tvb, pinfo, tree);
                if (bytes_dissected > 0)
                    return;
            }
        }
    }

    if (payload_type != 0) {
        switch (media_type) {
        case ACDR_RTP_AMR:
            if (amr_handle) {
                old_dissector_handle = dissector_get_uint_handle(rtp_dissector_table, payload_type);
                if (old_dissector_handle != amr_handle)
                    dissector_add_uint("rtp.pt", payload_type, amr_handle);
            }
            break;
        case ACDR_RTP_EVRC:
            if (evrc_handle) {
                old_dissector_handle = dissector_get_uint_handle(rtp_dissector_table, payload_type);
                if (old_dissector_handle != evrc_handle)
                    dissector_add_uint("rtp.pt", payload_type, evrc_handle);
            }
            break;
        case ACDR_RTP_RFC2198:
            if (rtp_rfc2198_handle) {
                old_dissector_handle = dissector_get_uint_handle(rtp_dissector_table, payload_type);
                if (old_dissector_handle != rtp_rfc2198_handle)
                    dissector_add_uint("rtp.pt", payload_type, rtp_rfc2198_handle);
            }
            break;
        case ACDR_RTP_RFC2833:
            if (rtp_events_handle) {
                old_dissector_handle = dissector_get_uint_handle(rtp_dissector_table, payload_type);
                if (old_dissector_handle != rtp_events_handle)
                    dissector_add_uint("rtp.pt", payload_type, rtp_events_handle);
            }
            break;
        case ACDR_RTP_FEC:
            if (rtp_rfc2198_handle) {
                old_dissector_handle = dissector_get_uint_handle(rtp_dissector_table, payload_type);
                if (old_dissector_handle != rtp_rfc2198_handle)
                    dissector_add_uint("rtp.pt", payload_type, rtp_rfc2198_handle);
            }
            break;
        }
    }

    call_dissector(rtp_dissector_handle, tvb, pinfo, tree);

    // see that the bottom protocol is indeed RTP and not some other protocol on top RTP
    if (tree && tree->last_child) {
        if (tree->last_child->finfo->hfinfo->id == proto_rtp) {
            // add the length & offset fields to the RTP payload
            rtp_data_tree = tree->last_child->last_child; // the rtp subtree->the payload field

            if (rtp_data_tree) {
                proto_item_set_text(rtp_data_tree, "RTP Data (%d bytes, offset %d)",
                                    rtp_data_tree->finfo->length, rtp_data_tree->finfo->start);
            }
        }
    }

    switch (media_type) {
    case ACDR_RTP_AMR:
        if (old_dissector_handle && (old_dissector_handle != amr_handle))
            dissector_add_uint("rtp.pt", payload_type, old_dissector_handle);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP AMR");
        break;
    case ACDR_RTP_EVRC:
        if (old_dissector_handle && (old_dissector_handle != evrc_handle))
            dissector_add_uint("rtp.pt", payload_type, old_dissector_handle);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP Evrc");
        break;
    case ACDR_RTP_RFC2198:
        if (old_dissector_handle && (old_dissector_handle != rtp_rfc2198_handle))
            dissector_add_uint("rtp.pt", payload_type, old_dissector_handle);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP Rfc2198");
        break;
    case ACDR_RTP_RFC2833:
        if (old_dissector_handle && (old_dissector_handle != rtp_events_handle))
            dissector_add_uint("rtp.pt", payload_type, old_dissector_handle);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP Rfc2833");
        break;
    case ACDR_T38_OVER_RTP:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "T38 over RTP");
        break;
    case ACDR_RTP_FEC:
        if (old_dissector_handle && (old_dissector_handle != rtp_rfc2198_handle))
            dissector_add_uint("rtp.pt", payload_type, old_dissector_handle);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP FEC");
        break;
    case ACDR_RTP_FAX_BYPASS:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP Fax Bypass");
        break;
    case ACDR_RTP_MODEM_BYPASS:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP Modem Bypass");
        break;
    case ACDR_RTP_NSE:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP NSE");
        break;
    case ACDR_RTP_NO_OP:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP NoOp");
        break;
    case ACDR_VIDEORTP:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP Video");
        break;
    }
}

static int
dissect_signaling_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *next_tvb = NULL;
    proto_item *ti = NULL;
    guint32 tmp;
    gint64 timestamp;

    proto_tree_add_item(tree, hf_acdr_signaling_opcode, tvb, HEADER_FIELD_SIG_OPCODE_BYTE_NO,
                        HEADER_FIELD_SIG_OPCODE_BYTE_COUNT, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, hf_acdr_signaling_timestamp, tvb, HEADER_FIELD_SIG_TIME_BYTE_NO,
                             HEADER_FIELD_SIG_TIME_BYTE_COUNT, ENC_NA);

    tmp = tvb_get_ntohl(tvb, HEADER_FIELD_SIG_TIME_BYTE_NO);

    timestamp = (((gint64) tmp) << 16);
    tmp = tvb_get_ntohs(tvb, HEADER_FIELD_SIG_TIME_BYTE_NO + 2);
    timestamp |= tmp;

    proto_item_append_text(ti, " (%f sec)", timestamp / 1000000.0);

    next_tvb = tvb_new_subset_length_caplen(
        tvb, HEADER_FIELD_SIG_MESSAGE_BYTE_NO,
        tvb_reported_length_remaining(tvb, HEADER_FIELD_SIG_OPCODE_BYTE_COUNT +
                                      HEADER_FIELD_SIG_TIME_BYTE_COUNT), -1);

    return call_data_dissector(next_tvb, pinfo, tree);
}

static gint32
add_cid(proto_tree *tree, tvbuff_t *tvb, gint offset, gint cid_byte_length, int hf)
{
    gint32 cid = 0;
    if (cid_byte_length == 2) {
        cid = tvb_get_ntohs(tvb, offset);
    } else {
        cid = tvb_get_ntohl(tvb, offset);
    }
    if (cid_byte_length == 2 && cid == 0xFFFF)
        cid = -1;
    proto_tree_add_int_format_value(tree, hf, tvb, offset, cid_byte_length, cid, "%d", cid);
    return cid;
}

static void
create_acdr_tree(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{
    proto_item *header_ti = NULL;
    proto_item *ti = NULL;
    proto_tree *acdr_tree;
    tvbuff_t *next_tvb = NULL;
    guint32 tmp;
    gint offset = 0;
    gint header_byte_length = 15;
    gint cid_byte_length = 2;
    guint32 sequence_num = 0;
    guint32 version, trace_point, header_extension_len = 0;
    guint8 media_type, extra_data;
    gboolean medium_mii = 0;
    gint64 timestamp;
    int acdr_header_length;
    gboolean header_added;
    gboolean li_packet;
    guint16 payload_type = 0;
    AcdrTlsPacketInfo tls_packet_info = {0xFFFF, 0xFFFF, TLS_APP_UNKNWN};
    const char *proto_name = NULL;

    header_ti = proto_tree_add_item(tree, proto_acdr, tvb, 0, -1, ENC_NA);
    acdr_tree = proto_item_add_subtree(header_ti, ett_acdr);

    // Version
    proto_tree_add_item_ret_uint(acdr_tree, hf_acdr_version, tvb, offset, 1, ENC_BIG_ENDIAN, &version);
    offset++;

    if ((version & 0xF) < 5) {
        header_byte_length = 15;
        cid_byte_length = 2;
    } else if ((version & 0xF) < 7) {
        header_byte_length = 19;
        cid_byte_length = 2;
    } else if ((version & 0xF) == 7) {
        header_byte_length = 23;
        cid_byte_length = 2;
    } else if ((version & 0xF) == 8) {
        header_byte_length = 24;
        cid_byte_length = 2;
    } else {
        header_byte_length = 28;
        cid_byte_length = 4;
    }

    if (((version & 0xF) > ACDR_VERSION_MINOR) || (((version >> 4) & 0xF) != ACDR_VERSION_MAJOR)) {
        // version not supported
        expert_add_info_format(pinfo, header_ti, &ei_acdr_version_not_supported,
                               "ACDR version %d not supported", version);
        return;
    }

    // Timestamp
    if ((version & 0xF) <= 3) {
        ti = proto_tree_add_item(acdr_tree, hf_acdr_timestamp, tvb, offset, 6, ENC_NA);
        tmp = tvb_get_ntohl(tvb, offset);
        timestamp = (((gint64) tmp) << 16);
        tmp = tvb_get_ntohs(tvb, offset + 4);
        timestamp |= tmp;
        offset += 6;
    } else {
        ti = proto_tree_add_item(acdr_tree, hf_acdr_timestamp, tvb, offset, 4, ENC_NA);
        timestamp = tvb_get_ntohl(tvb, offset);
        offset += 4;
    }
    proto_item_append_text(ti, " (%f sec)", timestamp / 1000000.0);

    // Sequence Number
    if ((version & 0xF) >= 4) {
        proto_tree_add_item_ret_uint(acdr_tree, hf_acdr_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN,
                                     &sequence_num);
        offset += 2;
    }

    add_cid(acdr_tree, tvb, offset, cid_byte_length, hf_acdr_sourceid);
    offset += cid_byte_length;
    add_cid(acdr_tree, tvb, offset, cid_byte_length, hf_acdr_destid);
    offset += cid_byte_length;

    // Extra Data
    extra_data = tvb_get_guint8(tvb, offset);
    if ((extra_data == 0) ||

        // Backward Compatible:  in old versions we always set the extra_data with 0xAA value
        ((extra_data == 0xAA) && ((version & 0xF) <= 3))) {
        proto_tree_add_item(acdr_tree, hf_acdr_data, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        static int * const extra_data_bits[] = {
            &hf_acdr_data_li,
            &hf_acdr_data_mtce,
            &hf_acdr_data_encrypted,
            &hf_acdr_data_headeradded,
            &hf_acdr_data_fragmented,
            &hf_acdr_data_ipv6,
            &hf_acdr_data_mii,
            NULL
        };

        proto_tree_add_bitmask(acdr_tree, tvb, offset, hf_acdr_data, ett_extra_data,
                               extra_data_bits, ENC_BIG_ENDIAN);
    }
    offset++;

    if (((version & 0xF) >= 3) && ((MEDIUM_MASK & extra_data) == MEDIUM_MASK))
        medium_mii = 1;

    header_added = ((HEADERADDED_MASK & extra_data) == HEADERADDED_MASK) && (extra_data != 0xAA);
    li_packet = (LI_MASK & extra_data) == LI_MASK;

    // Trace Point Type
    proto_tree_add_item_ret_uint(acdr_tree, hf_acdr_trace_pt, tvb, offset, 1, ENC_BIG_ENDIAN,
                                 &trace_point);
    offset++;

    // Media Type
    media_type = tvb_get_guint8(tvb, offset);
    if ((media_type == ACDR_DSP_AC5X_MII) && (medium_mii == 0))
        proto_tree_add_item(acdr_tree, hf_acdr_media_type_dsp_ac5x, tvb, offset, 1, ENC_BIG_ENDIAN);
    else
        proto_tree_add_item(acdr_tree, hf_acdr_media_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if ((version & 0xF) < 5) {
        // Payload Offset
        proto_tree_add_item(acdr_tree, hf_acdr_pl_offset_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        // Header Extension Length
        proto_tree_add_item_ret_uint(acdr_tree, hf_acdr_header_ext_len_type, tvb, offset, 1,
                                     ENC_BIG_ENDIAN, &header_extension_len);
    }
    offset++;

    // calculate the header length
    acdr_header_length = header_byte_length + header_extension_len;
    if (medium_mii)
        acdr_header_length += MII_HEADER_BYTE_LENGTH;

    if ((version & 0xF) >= 5) {
        if ((version & 0xF) < 7) {
            // Simple SessionID (not include BoardID)
            proto_tree_add_item(acdr_tree, hf_acdr_session_id_session_number, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
        } else {
            // Full SessionID (include also BoardID)
            create_full_session_id_subtree(acdr_tree, tvb, offset, version);
        }
    }

    proto_item_set_len(header_ti, acdr_header_length);
    if (header_added) {
        p_add_proto_data(pinfo->pool, pinfo, proto_acdr, 0, GUINT_TO_POINTER(media_type));
        if (media_type == ACDR_VoiceAI)
            proto_name = "VoiceAI";
        else if (media_type == ACDR_DTLS)
            proto_name = "DTLS data";
    }

    // Header extension
    if (header_extension_len > 0) {
        switch (media_type) {
        case ACDR_T38:
            if (header_added) {
                // Gen3 only: we put the UDP header in the last 8 bytes of the header extension.
                // So, we have only IP address into the real header extension
                if (header_extension_len == 12)
                    header_extension_len = 4;
            }
            break;

        case ACDR_RTP_AMR:
        case ACDR_RTP_EVRC:
        case ACDR_RTP_RFC2198:
        case ACDR_RTP_RFC2833:
        case ACDR_RTP_FEC:
            payload_type = (tvb_get_guint8(tvb, acdr_header_length + 1) & 0x7F);
            break;
        }

        create_header_extension_subtree(acdr_tree, tvb, header_byte_length, header_extension_len,
                                        version, media_type, trace_point, extra_data, &tls_packet_info);
    }

    if (medium_mii)
        create_mii_header_subtree(acdr_tree, tvb, header_byte_length + header_extension_len, media_type);

    // create a new tvbuff for the next dissector
    next_tvb = tvb_new_subset_remaining(tvb, header_byte_length + header_extension_len);

    if ((trace_point == DspIncoming) || (trace_point == DspOutgoing)) {
        // Gen5 only - special case of recorded packets from DSP
        create_5x_analysis_packet_header_subtree(tree, next_tvb);

        next_tvb = tvb_new_subset_remaining(tvb, header_byte_length + header_extension_len +
                                            AC5X_ANALYSIS_PACKET_HEADER);
        create_5x_hpi_packet_header_subtree(tree, next_tvb);

        next_tvb = tvb_new_subset_remaining(tvb, header_byte_length + header_extension_len +
                                            AC5X_ANALYSIS_PACKET_HEADER + AC5X_HPI_PACKET_HEADER);
    }

    acdr_dissector_data_t data;

    data.header_added = header_added;
    data.version = version;
    data.tls_source_port = tls_packet_info.source_port;
    data.tls_dest_port = tls_packet_info.dest_port;
    data.tls_application = tls_packet_info.application;
    data.media_type = media_type;
    data.payload_type = payload_type;
    data.trace_point = trace_point;
    data.medium_mii = medium_mii;
    data.li_packet = li_packet;
    acdr_payload_handler(tree, pinfo, next_tvb, &data, proto_name);
}

static int
dissect_acdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    pinfo->current_proto = "acdr";

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AC DR");
    col_add_fstr(pinfo->cinfo, COL_INFO, "AC DEBUG Packet");

    create_acdr_tree(tree, pinfo, tvb);

    return tvb_captured_length(tvb);
}

static int
dissect_acdr_voiceai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/*
	 * I guess this is just a blob of JSON.
	 *
	 * Do *NOT* pass data to the JSON dissector; it's expecting
	 * an http_message_info_t *, and that's *NOT* what we hand
	 * subdissectors.  Hilarity ensures; see
	 *
	 *    https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16622
	 */
	call_dissector(json_dissector_handle, tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}

static int
dissect_acdr_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;
    int dissected;

    if (acdr_data == NULL)
        return 0;

    if (acdr_data->tls_application == TLS_APP_TCP) {
        dissected = dissector_try_uint(tls_application_port_table, acdr_data->tls_source_port, tvb,
                                       pinfo, tree);
        if (dissected != 0)
            return dissected;

        dissected = dissector_try_uint(tls_application_port_table, acdr_data->tls_dest_port, tvb,
                                       pinfo, tree);
        if (dissected != 0)
            return dissected;
    } else {
        dissected = dissector_try_uint(tls_application_table, acdr_data->tls_application, tvb,
                                       pinfo, tree);
        if (dissected != 0)
            return dissected;
    }

    //dissector wasn't found
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TLS");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "TLS raw data");
    call_data_dissector(tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static int
dissect_acdr_ip_or_other(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data,
                         dissector_handle_t other_dissector_handle)
{
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;

    if (acdr_data == NULL)
        return 0;

    if (acdr_data->header_added && ip_dissector_handle) {
        call_dissector(ip_dissector_handle, tvb, pinfo, tree);
    } else if (other_dissector_handle) {
        call_dissector(other_dissector_handle, tvb, pinfo, tree);
    } else {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_acdr_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_acdr_ip_or_other(tvb, pinfo, tree, data, sip_dissector_handle);
}

static int
dissect_acdr_megaco(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_acdr_ip_or_other(tvb, pinfo, tree, data, megaco_dissector_handle);
}

static int
dissect_acdr_mgcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_acdr_ip_or_other(tvb, pinfo, tree, data, mgcp_dissector_handle);
}

static int
dissect_acdr_rtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;

    if (acdr_data == NULL)
        return 0;

    dissect_rtp_packet(tvb, pinfo, tree, acdr_data->media_type, acdr_data->payload_type);

    return tvb_captured_length(tvb);
}

static int
dissect_acdr_rtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;

    if (acdr_data == NULL)
        return 0;

    int bytes_dissected = 0;
    if ((tvb_get_guint8(tvb, 0) & 0xC0) == 0) {
        // RTCP Version = 0
        if (tvb_get_ntohl(tvb, 4) == 0x2112a442) {
            // This is STUN RFC 5389 packet
            if (udp_stun_dissector_handle) {
                bytes_dissected = call_dissector(udp_stun_dissector_handle, tvb, pinfo, tree);
                if (bytes_dissected > 0)
                    return bytes_dissected;
            }
        }
    }

    if (rtcp_dissector_handle)
        return call_dissector(rtcp_dissector_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static int
dissect_acdr_video_rtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int res = dissect_acdr_rtcp(tvb, pinfo, tree, data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTCP Video");
    return res;
}

static int
dissect_acdr_xml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    const char *name;
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;
    if (acdr_data == NULL)
        return 0;

    name = val_to_str_const(acdr_data->media_type, acdr_media_type_vals, "Unknown");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACDR");
    col_set_str(pinfo->cinfo, COL_INFO, name);

    return call_dissector(xml_dissector_handle, tvb, pinfo, tree);
}

void
proto_register_acdr(void)
{
    static hf_register_info hf[] = {
        { &hf_acdr_unknown_packet,
            { "Unknown packet Type", "acdr.unknown_packet",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_timestamp,
            { "Time Stamp", "acdr.timestamp",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                "timestamp in us resolution", HFILL }
        },
        { &hf_acdr_seq_num,
            { "Sequence Number", "acdr.seq",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_sourceid,
            { "Source ID", "acdr.src_id",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                "source EP ID (CID)", HFILL }
        },
        { &hf_acdr_destid,
            { "Dest ID", "acdr.dst_id",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                "dest EP ID (CID)", HFILL }
        },
        { &hf_acdr_version,
            { "Version", "acdr.ver",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                "DR Protocol version (Major.Minor)", HFILL }
        },
        { &hf_acdr_trace_pt,
            { "Trace Point", "acdr.trace_pt",
                FT_UINT8, BASE_DEC,
                VALS(acdr_trace_pt_vals), 0x0,
                "AC Debug trace point", HFILL }
        },
        { &hf_acdr_media_type,
            { "Media Type", "acdr.media_type",
                FT_UINT8, BASE_DEC,
                VALS(acdr_media_type_vals), 0x0,
                "AC Debug layer 2 packet type", HFILL }
        },
        { &hf_acdr_media_type_dsp_ac5x,
            { "Media Type", "acdr.media_type",
                FT_UINT8, BASE_DEC,
                VALS(acdr_media_type_dummy_vals), 0x0,
                "AC Debug layer 2 packet type", HFILL }
        },
        { &hf_acdr_pl_offset_type,
            { "Payload offset", "acdr.payload_offset",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Offset to packet Payload", HFILL }
        },
        { &hf_acdr_header_ext_len_type,
            { "Header Extension Len", "acdr.header_ext_len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Header extension length", HFILL }
        },
        { &hf_acdr_data,
            { "Extra Data", "acdr.extra_data",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_data_li,
            { "LI", "acdr.extra_data.li",
                FT_UINT8, BASE_HEX,
                NULL, LI_MASK,
                "Packet LI (with X2 or X3 header)", HFILL }
        },
        { &hf_acdr_data_mtce,
            { "Mtce", "acdr.extra_data.mtce",
                FT_UINT8, BASE_HEX,
                NULL, MTCE_MASK,
                "Packet of Mtce", HFILL }
        },
        { &hf_acdr_data_encrypted,
            { "Encrypted", "acdr.extra_data.encrypted",
                FT_UINT8, BASE_HEX,
                NULL, ENCRYPTED_MASK,
                "Packet is Encrypted", HFILL }
        },
        { &hf_acdr_data_headeradded,
            { "header_added", "acdr.extra_data.headeradded",
                FT_UINT8, BASE_HEX,
                NULL, HEADERADDED_MASK,
                "Header Added", HFILL }
        },
        { &hf_acdr_data_fragmented,
            { "Fragmented", "acdr.extra_data.fragmented",
                FT_UINT8, BASE_HEX,
                NULL, FRAGMENTED_MASK,
                "Fragmented Data", HFILL }
        },
        { &hf_acdr_data_ipv6,
            { "IPV6", "acdr.extra_data.ipv6",
                FT_UINT8, BASE_HEX,
                NULL, IPV6_MASK,
                NULL, HFILL }
        },
        { &hf_acdr_data_mii,
            { "MII", "acdr.extra_data.mii",
                FT_UINT8, BASE_HEX,
                NULL, MEDIUM_MASK,
                NULL, HFILL }
        },
        { &hf_acdr_session_id,
            { "Full Session ID", "acdr.full_session_id",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_session_id_board_id,
            { "Board ID", "acdr.board_id",
                FT_UINT24, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_session_id_reset_counter,
            { "Reset Counter", "acdr.reset_counter",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_session_id_session_number,
            { "Session ID", "acdr.session_id",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_session_id_long_session_number,
            { "Session ID", "acdr.long_session_id",
                FT_UINT40, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_payload_header,
            { "Payload Header", "acdr.payload_header",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                "Payload header bytes", HFILL }
        },
        { &hf_acdr_ext_srcudp,
            { "Packet source UDP port", "acdr.ext.src_port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_dstudp,
            { "Packet destination UDP port", "acdr.ext.dst_port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_srcip,
            { "Packet source IP address", "acdr.ext.src_ip",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_srcipv6,
            { "Packet source IPv6 address", "acdr.ext.src_ip_v6",
                FT_IPv6, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_acdr_ext_dstip,
            { "Packet destination IP address", "acdr.ext.dst_ip",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_dstipv6,
            { "Packet destination IPv6 address", "acdr.ext.dst_ip_v6",
                FT_IPv6, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_protocol,
            { "IP protocol type", "acdr.ext.protocol",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                &ipproto_val_ext, 0x0,
                "IP protocol type (as defined by IANA)", HFILL }
        },
        { &hf_acdr_ext_tls_application,
            { "TLS Application", "acdr.ext.application",
                FT_UINT8, BASE_DEC,
                VALS(hf_acdr_ext_tls_application_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_direction,
            { "Packet Direction", "acdr.ext.direction",
                FT_UINT8, BASE_DEC,
                VALS(hf_acdr_ext_direction_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_iptos,
            { "IP type of service", "acdr.ext.iptos",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "IP Type Of Service (IP TOS)", HFILL }
        },
        { &hf_acdr_ext_c5_control_flags,
            { "C5 Control Flags", "acdr.c5_control_flags",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_c5_control_favorite,
            { "Favorite flag", "acdr.c5_control.favorite",
                FT_UINT8, BASE_HEX,
                NULL, FAVORITE_MASK,
                NULL, HFILL }
        },
        { &hf_acdr_ext_pstn_trace_seq_num,
            { "PSTN Trace Seq Num", "acdr.ext.pstn_trace_seq_num",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                "acdr.ext.pstn_trace_seq_num", HFILL }
        },
        { &hf_acdr_header_extension,
            { "Header Extension", "acdr.ext.header_extension",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "acdr.ext.header_extension", HFILL }
        },
        { &hf_acdr_ext_dsp_core,
            { "DSP Core", "acdr.ext.dsp_core",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "DSP core number", HFILL }
        },
        { &hf_acdr_ext_dsp_channel,
            { "DSP Channel", "acdr.ext.dsp_ch",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "DSP Channel number", HFILL }
        },
        { &hf_acdr_ext_event_id,
            { "Event ID", "acdr.ext.event_id",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_ext_event_source,
            { "Event source module", "acdr.ext.event_src",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_mii_header,
            { "MII Header", "acdr.mii_header",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_mii_sequence,
            { "MII sequence number", "acdr.mii_sequence_num",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_mii_packet_size,
            { "MII packet size", "acdr.mii_packet_size",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_5x_analysis_packet_header,
            { "5x Analysis Packet Header", "acdr.5x_analysis_packet_header",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_5x_analysis_version,
            { "Version", "acdr.analysis_version",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                "5x Analysis Version", HFILL }
        },
        { &hf_5x_analysis_direction,
            { "Direction", "acdr.analysis_direction",
                FT_UINT8, BASE_HEX,
                NULL, 0x80,
                "5x Analysis Direction", HFILL }
        },
        { &hf_5x_analysis_sub_version,
            { "SubVersion", "acdr.analysis_subversion",
                FT_UINT8, BASE_DEC,
                NULL, 0x7F,
                "5x Analysis SubVersion", HFILL }
        },
        { &hf_5x_analysis_device,
            { "Device", "acdr.analysis_device",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "5x Analysis Device", HFILL }
        },
        { &hf_5x_analysis_sequence,
            { "Sequence", "acdr.analysis_sequence",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                "5x Analysis Sequence", HFILL }
        },
        { &hf_5x_analysis_spare1,
            { "Spare1", "acdr.analysis_spare1",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                "5x Analysis spare1", HFILL }
        },
        { &hf_5x_analysis_timestamp,
            { "Timestamp", "acdr.analysis_timestamp",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                "5x Analysis Timestamp", HFILL }
        },
        { &hf_5x_analysis_spare2,
            { "Spare2", "acdr.analysis_spare2",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                "5x Analysis Spare2", HFILL }
        },
        { &hf_acdr_5x_hpi_packet_header,
            { "5x HPI Packet Header", "acdr.5x_hpi_packet_header",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                "acdr.5x_hpi_packet_header", HFILL }
        },
        { &hf_5x_hpi_sync5,
            { "Sync5", "acdr.5x.HpiHeader.Sync5",
                FT_UINT8, BASE_HEX,
                NULL, 0xE0,
                "DSP Sync const 0x5", HFILL }
        },
        { &hf_5x_hpi_udp_checksum,
            { "UDP Checksum Included", "acdr.5x.HpiHeader.UdpChecksum",
                FT_UINT8, BASE_HEX,
                NULL, 0x10,
                "5x HpiHeader UdpChecksum", HFILL }
        },
        { &hf_5x_hpi_resource_id,
            { "Resource ID", "acdr.5x.HpiHeader.ResourceId",
                FT_UINT8, BASE_DEC,
                NULL, 0xFF,
                "Resource ID into core", HFILL }
        },
        { &hf_5x_hpi_favorite,
            { "Favorite Stream", "acdr.5x.HpiHeader.Favorite",
                FT_UINT8, BASE_DEC,
                NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_5x_hpi_protocol,
            { "Protocol", "acdr.5x.HpiHeader.Protocol",
                FT_UINT8, BASE_DEC,
                NULL, 0x3F,
                "Protocol Proprietary", HFILL }
        },
        { &hf_signaling_packet,
            { "Signaling Packet", "acdr.signaling_packet",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ac45x_packet,
            { "45x DSP packet", "acdr.45x_dsp_packet",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ac48x_packet,
          { "48x DSP packet", "acdr.48x_dsp_packet",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ac49x_packet,
          { "49x DSP packet", "acdr.49x_dsp_packet",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ac5x_packet,
          { "5x DSP packet", "acdr.5x_dsp_packet",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_acdr_signaling_opcode,
            { "Signaling OpCode", "acdr.signaling_opcode",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_acdr_signaling_timestamp,
            { "Signaling Timestamp", "acdr.signaling_timestamp",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                "Timestamp in us resolution", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_acdr,
        &ett_extension,
        &ett_ac45x_packet,
        &ett_ac48x_packet,
        &ett_ac49x_packet,
        &ett_ac5x_packet,
        &ett_ac5x_mii_packet,
        &ett_mii_header,
        &ett_signaling_packet,
        &ett_extra_data,
        &ett_c5_cntrl_flags,
        &ett_5x_analysis_packet_header,
        &ett_5x_hpi_packet_header,
        &ett_session_id
    };

    static ei_register_info ei[] = {
        { &ei_acdr_version_not_supported, { "acdr.version_not_supported", PI_UNDECODED, PI_WARN, "Version not supported", EXPFILL } },
    };

    expert_module_t *expert_acdr;

    proto_acdr = proto_register_protocol("AUDIOCODES DEBUG RECORDING", "AC DR", "acdr");
    proto_register_field_array(proto_acdr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_acdr = expert_register_protocol(proto_acdr);
    expert_register_field_array(expert_acdr, ei, array_length(ei));

    media_type_table = register_dissector_table("acdr.media_type", "AC DR Media Type", proto_acdr,
                                                FT_UINT32, BASE_HEX);
    tls_application_table = register_dissector_table("acdr.tls_application",
                                                     "AC DR TLS Application Type", proto_acdr,
                                                     FT_UINT32, BASE_HEX);

    //For backwards compatibility
    tls_application_port_table = register_dissector_table("acdr.tls_application_port",
                                                          "AC DR TLS Application Port", proto_acdr,
                                                          FT_UINT32, BASE_HEX);
}

static int
dissect_acdr_dsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data,
                 int hf, int ett, const char *name, dissector_handle_t dissector)
{
    guint packet_direction;
    proto_item *packet_item;
    proto_tree *packet_tree;
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;

    if (!dissector)
        return call_data_dissector(tvb, pinfo, parent_tree);
    packet_item = proto_tree_add_item(parent_tree, hf, tvb, 0, -1, ENC_NA);
    packet_tree = proto_item_add_subtree(packet_item, ett);

    col_clear(pinfo->cinfo, COL_INFO);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, name);

    if (acdr_data->trace_point == Dsp2Host)
        packet_direction = DIR_RX;
    else
        packet_direction = DIR_TX;

    return call_dissector_with_data(dissector, tvb, pinfo, packet_tree, &packet_direction);
}

static int
dissect_acdr_ac45x(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    return dissect_acdr_dsp(tvb, pinfo, parent_tree, data, hf_ac45x_packet, ett_ac45x_packet,
                            "AC45X", dsp_45x_dissector_handle);
}

static int
dissect_acdr_ac48x(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    return dissect_acdr_dsp(tvb, pinfo, parent_tree, data, hf_ac48x_packet, ett_ac48x_packet,
                            "AC48X", dsp_48x_dissector_handle);
}

static int
dissect_acdr_ac49x(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    return dissect_acdr_dsp(tvb, pinfo, parent_tree, data, hf_ac49x_packet, ett_ac49x_packet,
                            "AC49X", dsp_49x_dissector_handle);
}

static int
dissect_acdr_ac5x(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    return dissect_acdr_dsp(tvb, pinfo, parent_tree, data, hf_ac5x_packet, ett_ac5x_packet,
                            "AC5X", dsp_5x_dissector_handle);
}

static int
dissect_acdr_mii(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *packet_item = NULL;
    proto_item *packet_tree = NULL;
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;
    struct AcdrAc5xPrivateData private_data;

    if (!dsp_5x_MII_dissector_handle)
        return call_data_dissector(tvb, pinfo, packet_tree);

    if (acdr_data->media_type == ACDR_DSP_TDM_PLAYBACK) {
        private_data.protocol_type = ACDR_AC5X_PROTOCOL_TYPE__TDM_PLAYBACK;
        private_data.mii_header_exist = 1;
    } else if (acdr_data->media_type == ACDR_DSP_NET_PLAYBACK) {
        private_data.protocol_type = ACDR_AC5X_PROTOCOL_TYPE__NET_PLAYBACK;
        private_data.mii_header_exist = 1;
    } else {
        private_data.protocol_type = ACDR_AC5X_PROTOCOL_TYPE__REGULAR;
        private_data.mii_header_exist = acdr_data->medium_mii;
    }

    packet_item = proto_tree_add_item(tree, proto_ac5xmii, tvb, 0, -1, FALSE);
    packet_tree = proto_item_add_subtree(packet_item, ett_ac5x_mii_packet);

    col_clear(pinfo->cinfo, COL_INFO);
    if (acdr_data->media_type == ACDR_DSP_AC5X_MII) {
        if (acdr_data->medium_mii)
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "AC5x_MII");
        else
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "AC5x");
    } else {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "AC5x_MII");
    }

    if ((acdr_data->trace_point == Dsp2Host) || (acdr_data->trace_point == DspOutgoing))
        private_data.packet_direction = DIR_RX;
    else
        private_data.packet_direction = DIR_TX;

    return call_dissector_with_data(dsp_5x_MII_dissector_handle, tvb, pinfo, packet_tree, &private_data);
}

static int
dissect_acdr_v1501(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "V150.1");
    return call_data_dissector(tvb, pinfo, tree);
}

static int
dissect_acdr_signaling(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    acdr_dissector_data_t *acdr_data = (acdr_dissector_data_t *) data;
    proto_item *packet_item = proto_tree_add_item(tree, hf_signaling_packet, tvb, 0, -1, ENC_NA);
    proto_tree *packet_tree = proto_item_add_subtree(packet_item, ett_signaling_packet);

    int res = dissect_signaling_packet(tvb, pinfo, packet_tree);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Signaling");
    col_clear(pinfo->cinfo, COL_INFO);
    switch (acdr_data->trace_point) {
    case Host2Pstn:
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "HOST --> PSTN");
        break;
    case Pstn2Host:
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "PSTN --> HOST");
        break;
    case DspIncoming:
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "DSP Incoming:  HOST --> PSTN");
        break;
    case DspOutgoing:
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "DSP Outgoing:  PSTN --> HOST");
        break;
    }
    return res;
}

static int
dissect_acdr_fragmented(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Fragmented");
    col_set_str(pinfo->cinfo, COL_INFO, "fragment of previous ACDR packet");
    return call_data_dissector(tvb, pinfo, tree);
}

static int
dissect_acdr_dsp_data_relay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSP Data Relay");
    return call_data_dissector(tvb, pinfo, tree);
}

void
proto_reg_handoff_acdr(void)
{
    dissector_handle_t acdr_mii_dissector_handle;
    dissector_handle_t acdr_rtp_dissector_handle;
    dissector_handle_t acdr_xml_dissector_handle;

    acdr_dissector_handle = create_dissector_handle(dissect_acdr, proto_acdr);

    register_dissector("acdr", dissect_acdr, proto_acdr);

    rtp_dissector_handle = find_dissector("rtp");
    rtp_dissector_table = find_dissector_table("rtp.pt");
    rtp_events_handle = find_dissector("rtpevent");
    rtp_rfc2198_handle = find_dissector("rtp.rfc2198");
    amr_handle = find_dissector("amr");
    evrc_handle = find_dissector("EVRC");
    ip_dissector_handle = find_dissector("ip");
    rtcp_dissector_handle = find_dissector("rtcp");
    json_dissector_handle = find_dissector("json");
    megaco_dissector_handle = find_dissector("megaco");

    mgcp_dissector_handle = find_dissector("mgcp");
    sip_dissector_handle = find_dissector("sip");
    udp_dissector_handle = find_dissector("udp");
    lix2x3_dissector_handle = find_dissector("lix2x3");

    dsp_49x_dissector_handle = find_dissector("ac49x");
    proto_ac49x = proto_get_id_by_filter_name("ac49x");
    dsp_48x_dissector_handle = find_dissector("ac48x");
    proto_ac48x = proto_get_id_by_filter_name("ac48x");
    dsp_45x_dissector_handle = find_dissector("AC45x");
    dsp_5x_dissector_handle = find_dissector("ac5x");
    proto_ac5x = proto_get_id_by_filter_name("ac5x");
    dsp_5x_MII_dissector_handle = find_dissector("ac5xmii");
    proto_ac5xmii = proto_get_id_by_filter_name("ac5xmii");

    proto_rtp = proto_get_id_by_filter_name("rtp");

    udp_stun_dissector_handle = find_dissector("stun-udp");
    xml_dissector_handle = find_dissector("xml");

    acdr_mii_dissector_handle = create_dissector_handle(dissect_acdr_mii, proto_acdr);
    acdr_rtp_dissector_handle = create_dissector_handle(dissect_acdr_rtp, proto_acdr);
    acdr_xml_dissector_handle = create_dissector_handle(dissect_acdr_xml, proto_acdr);

    // register our port number to the underlying TCP/UDP layers so our
    // dissector gets called for the appropriate port
    dissector_add_uint_with_preference("udp.port", PORT_AC_DR, acdr_dissector_handle);
    dissector_add_uint_with_preference("tcp.port", PORT_AC_DR, acdr_dissector_handle);

    // Register "local" media types
    dissector_add_uint("acdr.media_type", ACDR_VoiceAI, create_dissector_handle(dissect_acdr_voiceai, -1));
    dissector_add_uint("acdr.media_type", ACDR_TLS, create_dissector_handle(dissect_acdr_tls, -1));
    dissector_add_uint("acdr.media_type", ACDR_TLSPeek, create_dissector_handle(dissect_acdr_tls, -1));
    dissector_add_uint("acdr.media_type", ACDR_SIP, create_dissector_handle(dissect_acdr_sip, -1));
    dissector_add_uint("acdr.media_type", ACDR_MEGACO, create_dissector_handle(dissect_acdr_megaco, -1));
    dissector_add_uint("acdr.media_type", ACDR_MGCP, create_dissector_handle(dissect_acdr_mgcp, -1));

    dissector_add_uint("acdr.media_type", ACDR_RTP, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_AMR, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_EVRC, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_RFC2198, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_RFC2833, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_T38_OVER_RTP, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_FEC, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_FAX_BYPASS, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_MODEM_BYPASS, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_NSE, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTP_NO_OP, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_PCM, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_NATIVE, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_VIDEORTP, acdr_rtp_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_RTCP, create_dissector_handle(dissect_acdr_rtcp, -1));
    dissector_add_uint("acdr.media_type", ACDR_VIDEORTCP, create_dissector_handle(dissect_acdr_video_rtcp, -1));
    dissector_add_uint("acdr.media_type", ACDR_DSP_AC45X, create_dissector_handle(dissect_acdr_ac45x, proto_acdr));
    dissector_add_uint("acdr.media_type", ACDR_DSP_AC48X, create_dissector_handle(dissect_acdr_ac48x, proto_acdr));
    dissector_add_uint("acdr.media_type", ACDR_DSP_AC49X, create_dissector_handle(dissect_acdr_ac49x, proto_acdr));
    dissector_add_uint("acdr.media_type", ACDR_DSP_AC5X, create_dissector_handle(dissect_acdr_ac5x, proto_acdr));
    dissector_add_uint("acdr.media_type", ACDR_DSP_AC5X_MII, acdr_mii_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_DSP_TDM_PLAYBACK, acdr_mii_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_DSP_NET_PLAYBACK, acdr_mii_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_V1501, create_dissector_handle(dissect_acdr_v1501, -1));
    dissector_add_uint("acdr.media_type", ACDR_SIGNALING, create_dissector_handle(dissect_acdr_signaling, -1));
    dissector_add_uint("acdr.media_type", ACDR_FRAGMENTED, create_dissector_handle(dissect_acdr_fragmented, -1));
    dissector_add_uint("acdr.media_type", ACDR_DSP_DATA_RELAY,
                       create_dissector_handle(dissect_acdr_dsp_data_relay, -1));
    dissector_add_uint("acdr.media_type", ACDR_QOE_CDR, acdr_xml_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_QOE_MDR, acdr_xml_dissector_handle);
    dissector_add_uint("acdr.media_type", ACDR_QOE_EVENT, acdr_xml_dissector_handle);
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
