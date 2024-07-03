/* packet-acdr.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ACDR_H__
#define __PACKET_ACDR_H__

enum acdr_media_types
{
    ACDR_DSP_AC49X = 0,
    ACDR_RTP = 1,
    ACDR_RTCP = 2,
    ACDR_T38 = 3,
    ACDR_Event = 4,
    ACDR_Info = 5,
    ACDR_VoiceAI = 6,
    ACDR_NotUse1 = 7,
    ACDR_NotUse2 = 8,
    ACDR_NotUse3 = 9,
    ACDR_SIP = 10,
    ACDR_MEGACO = 11,
    ACDR_MGCP = 12,
    ACDR_TPNCP = 13,
    ACDR_Control = 14,
    ACDR_PCM = 15,
    ACDR_NP_CONTROL = 16,
    ACDR_NP_DATA = 17,
    ACDR_DSP_AC48X = 18,
    ACDR_DSP_AC45X = 19,
    ACDR_RESERVED_FOR_INTERNAL_USE_20 = 20,
    ACDR_RESERVED_FOR_INTERNAL_USE_21 = 21,
    ACDR_RESERVED_FOR_INTERNAL_USE_22 = 22,
    ACDR_HA = 23,
    ACDR_CAS = 24,
    ACDR_NET_BRICKS = 25,
    ACDR_COMMAND = 26,
    ACDR_VIDEORTP = 27,
    ACDR_VIDEORTCP = 28,
    ACDR_PCIIF_COMMAND = 29,
    ACDR_GWAPPSYSLOG = 30,
    ACDR_V1501 = 31,
    ACDR_DSP_AC5X = 32,
    ACDR_TLS = 33,
    ACDR_TLSPeek = 34,
    ACDR_DSP_AC5X_MII = 35,
    ACDR_NATIVE = 36,
    ACDR_SIGNALING = 37,
    ACDR_FRAGMENTED = 38,
    ACDR_RESERVED_FOR_INTERNAL_USE_39 = 39,
    ACDR_RESERVED_FOR_INTERNAL_USE_40 = 40,
    ACDR_RESERVED_FOR_INTERNAL_USE_41 = 41,
    ACDR_QOE_CDR = 42,
    ACDR_QOE_MDR = 43,
    ACDR_QOE_EVENT = 44,
    ACDR_RESERVED_FOR_INTERNAL_USE_45 = 45,
    ACDR_RESERVED_FOR_INTERNAL_USE_46 = 46,
    ACDR_DSP_TDM_PLAYBACK = 47,
    ACDR_DSP_NET_PLAYBACK = 48,
    ACDR_DSP_DATA_RELAY = 49,
    ACDR_DSP_SNIFFER = 50,
    ACDR_RTP_AMR = 51,
    ACDR_RTP_EVRC = 52,
    ACDR_RTP_RFC2198 = 53,
    ACDR_RTP_RFC2833 = 54,
    ACDR_T38_OVER_RTP = 55,
    ACDR_RTP_FEC = 56,
    ACDR_RTP_FAX_BYPASS = 57,
    ACDR_RTP_MODEM_BYPASS = 58,
    ACDR_RTP_NSE = 59,
    ACDR_RTP_NO_OP = 60,
    ACDR_DTLS = 61,
    ACDR_SSH_SHELL = 62,
    ACDR_SSH_SFTP = 63,
    ACDR_SSH_SCP = 64
};

enum AcdrTlsApplication
{
    TLS_APP_UNKNWN = 0,
    TLS_APP_HTTP = 1,
    TLS_APP_TR069 = 2,
    TLS_APP_SIP = 3,
    TLS_APP_LDAP = 4,
    TLS_APP_XML = 5,
    TLS_APP_TCP = 6, // TLS_APP_TCP value (6) is defined for backward compatible
    TLS_APP_TELNET = 7,
    TLS_APP_FTP = 8,
    TLS_APP_TPNCP = 9
};

// must be in same order as in DebugRecordingAPI.h in TPApp.
enum AcdrTracePoints
{
    Net2Dsp = 0,
    Dsp2Net = 1,
    Dsp2Host = 2,
    Host2Dsp = 3,
    Net2Host = 4,
    Host2Net = 5,
    System = 6,
    Dsp2Dsp = 7,
    Net2Net = 8,
    Dsp2Tdm = 9,
    Tdm2Dsp = 10,
    Np2Dsp = 11,
    Dsp2Np = 12,
    Host2Np = 13,
    Np2Host = 14,
    acUnknown = 15,
    Net = 16,
    P2P = 17,
    DspDecoder = 18,
    DspEncoder = 19,
    VoipDecoder = 20,
    VoipEncoder = 21,
    NetEncoder = 22,
    P2PDecoder = 23,
    P2PEncoder = 24,
    Host2Pstn = 25,
    Pstn2Host = 26,
    Net2DspPing = 27,
    Dsp2NetPing = 28,
    Src2Dest = 29,
    Addr2Addr = 30,
    GeneralSystem = 31,
    AllMedia = 32,
    DspIncoming = 33,
    DspOutgoing = 34,
    AfterSrtpDecoder = 35
};

typedef struct {
    bool header_added;
    uint8_t version;
    uint16_t tls_source_port;
    uint16_t tls_dest_port;
    uint8_t tls_application;
    uint8_t media_type;
    uint16_t payload_type;
    uint8_t trace_point;
    bool medium_mii;
    bool li_packet;
} acdr_dissector_data_t;

#endif /* __PACKET_ACDR_H__ */

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
