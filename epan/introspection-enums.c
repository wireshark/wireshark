/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Generated automatically from make-enums.py. It can be re-created by running
 * "tools/make-enums.py" from the top source directory.
 *
 * It is fine to edit this file by hand. Particularly if a symbol
 * disappears from the API it can just be removed here. There is no
 * requirement to re-run the generator script.
 *
 */
#include <epan/address.h>
#include <epan/ipproto.h>
#include <epan/proto.h>
#include <epan/ftypes/ftypes.h>
#include <epan/stat_groups.h>

#define ENUM(arg) { #arg, arg }

static ws_enum_t const all_enums[] = {
    ENUM(ABSOLUTE_TIME_DOY_UTC),
    ENUM(ABSOLUTE_TIME_LOCAL),
    ENUM(ABSOLUTE_TIME_NTP_UTC),
    ENUM(ABSOLUTE_TIME_UNIX),
    ENUM(ABSOLUTE_TIME_UTC),
    ENUM(AT_AX25),
    ENUM(AT_END_OF_LIST),
    ENUM(AT_ETHER),
    ENUM(AT_EUI64),
    ENUM(AT_FC),
    ENUM(AT_FCWWN),
    ENUM(AT_IB),
    ENUM(AT_ILNP_ILV),
    ENUM(AT_ILNP_L64),
    ENUM(AT_ILNP_NID),
    ENUM(AT_IPX),
    ENUM(AT_IPv4),
    ENUM(AT_IPv6),
    ENUM(AT_MCTP),
    ENUM(AT_NONE),
    ENUM(AT_NUMERIC),
    ENUM(AT_STRINGZ),
    ENUM(AT_VINES),
    ENUM(BASE_ALLOW_ZERO),
    ENUM(BASE_CUSTOM),
    ENUM(BASE_DEC),
    ENUM(BASE_DEC_HEX),
    ENUM(BASE_EXP),
    ENUM(BASE_EXT_STRING),
    ENUM(BASE_HEX),
    ENUM(BASE_HEX_DEC),
    ENUM(BASE_NETMASK),
    ENUM(BASE_NONE),
    ENUM(BASE_NO_DISPLAY_VALUE),
    ENUM(BASE_OCT),
    ENUM(BASE_OUI),
    ENUM(BASE_PROTOCOL_INFO),
    ENUM(BASE_PT_DCCP),
    ENUM(BASE_PT_SCTP),
    ENUM(BASE_PT_TCP),
    ENUM(BASE_PT_UDP),
    ENUM(BASE_RANGE_STRING),
    ENUM(BASE_SHOW_ASCII_PRINTABLE),
    ENUM(BASE_SHOW_UTF_8_PRINTABLE),
    ENUM(BASE_SPECIAL_VALS),
    ENUM(BASE_STR_WSP),
    ENUM(BASE_UNIT_STRING),
    ENUM(BASE_VAL64_STRING),
    ENUM(BMT_NO_APPEND),
    ENUM(BMT_NO_FALSE),
    ENUM(BMT_NO_FLAGS),
    ENUM(BMT_NO_INT),
    ENUM(BMT_NO_TFS),
    ENUM(ENC_3GPP_TS_23_038_7BITS),
    ENUM(ENC_3GPP_TS_23_038_7BITS_PACKED),
    ENUM(ENC_3GPP_TS_23_038_7BITS_UNPACKED),
    ENUM(ENC_ANTI_HOST_ENDIAN),
    ENUM(ENC_APN_STR),
    ENUM(ENC_ASCII),
    ENUM(ENC_ASCII_7BITS),
    ENUM(ENC_BCD_DIGITS_0_9),
    ENUM(ENC_BCD_ODD_NUM_DIG),
    ENUM(ENC_BCD_SKIP_FIRST),
    ENUM(ENC_BIG_ENDIAN),
    ENUM(ENC_BOM),
    ENUM(ENC_CHARENCODING_MASK),
    ENUM(ENC_CP437),
    ENUM(ENC_CP855),
    ENUM(ENC_CP866),
    ENUM(ENC_DECT_STANDARD_4BITS_TBCD),
    ENUM(ENC_DECT_STANDARD_8BITS),
    ENUM(ENC_EBCDIC),
    ENUM(ENC_EBCDIC_CP037),
    ENUM(ENC_EBCDIC_CP500),
    ENUM(ENC_ETSI_TS_102_221_ANNEX_A),
    ENUM(ENC_EUC_KR),
    ENUM(ENC_GB18030),
    ENUM(ENC_HOST_ENDIAN),
    ENUM(ENC_IMF_DATE_TIME),
    ENUM(ENC_ISO_646_BASIC),
    ENUM(ENC_ISO_646_IRV),
    ENUM(ENC_ISO_8601_DATE),
    ENUM(ENC_ISO_8601_DATE_TIME),
    ENUM(ENC_ISO_8601_DATE_TIME_BASIC),
    ENUM(ENC_ISO_8601_TIME),
    ENUM(ENC_ISO_8859_1),
    ENUM(ENC_ISO_8859_10),
    ENUM(ENC_ISO_8859_11),
    ENUM(ENC_ISO_8859_13),
    ENUM(ENC_ISO_8859_14),
    ENUM(ENC_ISO_8859_15),
    ENUM(ENC_ISO_8859_16),
    ENUM(ENC_ISO_8859_2),
    ENUM(ENC_ISO_8859_3),
    ENUM(ENC_ISO_8859_4),
    ENUM(ENC_ISO_8859_5),
    ENUM(ENC_ISO_8859_6),
    ENUM(ENC_ISO_8859_7),
    ENUM(ENC_ISO_8859_8),
    ENUM(ENC_ISO_8859_9),
    ENUM(ENC_KEYPAD_ABC_TBCD),
    ENUM(ENC_KEYPAD_BC_TBCD),
    ENUM(ENC_LITTLE_ENDIAN),
    ENUM(ENC_MAC_ROMAN),
    ENUM(ENC_NA),
    ENUM(ENC_NUM_PREF),
    ENUM(ENC_RFC_1123),
    ENUM(ENC_RFC_822),
    ENUM(ENC_SEP_COLON),
    ENUM(ENC_SEP_DASH),
    ENUM(ENC_SEP_DOT),
    ENUM(ENC_SEP_MASK),
    ENUM(ENC_SEP_NONE),
    ENUM(ENC_SEP_SPACE),
    ENUM(ENC_STRING),
    ENUM(ENC_STR_HEX),
    ENUM(ENC_STR_MASK),
    ENUM(ENC_STR_NUM),
    ENUM(ENC_STR_TIME_MASK),
    ENUM(ENC_T61),
    ENUM(ENC_TIME_CLASSIC_MAC_OS_SECS),
    ENUM(ENC_TIME_MIP6),
    ENUM(ENC_TIME_MP4_FILE_SECS),
    ENUM(ENC_TIME_MSECS),
    ENUM(ENC_TIME_MSEC_NTP),
    ENUM(ENC_TIME_NSECS),
    ENUM(ENC_TIME_NTP),
    ENUM(ENC_TIME_NTP_BASE_ZERO),
    ENUM(ENC_TIME_RFC_3971),
    ENUM(ENC_TIME_RTPS),
    ENUM(ENC_TIME_SECS),
    ENUM(ENC_TIME_SECS_NSECS),
    ENUM(ENC_TIME_SECS_NTP),
    ENUM(ENC_TIME_SECS_USECS),
    ENUM(ENC_TIME_TIMESPEC),
    ENUM(ENC_TIME_TIMEVAL),
    ENUM(ENC_TIME_TOD),
    ENUM(ENC_TIME_USECS),
    ENUM(ENC_TIME_ZBEE_ZCL),
    ENUM(ENC_UCS_2),
    ENUM(ENC_UCS_4),
    ENUM(ENC_UTF_16),
    ENUM(ENC_UTF_8),
    ENUM(ENC_VARINT_MASK),
    ENUM(ENC_VARINT_PROTOBUF),
    ENUM(ENC_VARINT_QUIC),
    ENUM(ENC_VARINT_SDNV),
    ENUM(ENC_VARINT_ZIGZAG),
    ENUM(ENC_WINDOWS_1250),
    ENUM(ENC_WINDOWS_1251),
    ENUM(ENC_WINDOWS_1252),
    ENUM(ENC_ZIGBEE),
    ENUM(FIELD_DISPLAY_E_MASK),
    ENUM(FI_BIG_ENDIAN),
    ENUM(FI_GENERATED),
    ENUM(FI_HIDDEN),
    ENUM(FI_LITTLE_ENDIAN),
    ENUM(FI_URL),
    ENUM(FI_VARINT),
    ENUM(FTREPR_DFILTER),
    ENUM(FTREPR_DISPLAY),
    ENUM(FTREPR_JSON),
    ENUM(FTREPR_RAW),
    ENUM(FT_ABSOLUTE_TIME),
    ENUM(FT_AX25),
    ENUM(FT_AX25_ADDR_LEN),
    ENUM(FT_BADARG),
    ENUM(FT_BOOLEAN),
    ENUM(FT_BYTES),
    ENUM(FT_CHAR),
    ENUM(FT_DOUBLE),
    ENUM(FT_ENUM_SIZE),
    ENUM(FT_ERROR),
    ENUM(FT_ETHER),
    ENUM(FT_ETHER_LEN),
    ENUM(FT_EUI64),
    ENUM(FT_EUI64_LEN),
    ENUM(FT_FALSE),
    ENUM(FT_FCWWN),
    ENUM(FT_FCWWN_LEN),
    ENUM(FT_FLOAT),
    ENUM(FT_FRAMENUM),
    ENUM(FT_FRAMENUM_ACK),
    ENUM(FT_FRAMENUM_DUP_ACK),
    ENUM(FT_FRAMENUM_NONE),
    ENUM(FT_FRAMENUM_NUM_TYPES),
    ENUM(FT_FRAMENUM_REQUEST),
    ENUM(FT_FRAMENUM_RESPONSE),
    ENUM(FT_FRAMENUM_RETRANS_NEXT),
    ENUM(FT_FRAMENUM_RETRANS_PREV),
    ENUM(FT_GUID),
    ENUM(FT_GUID_LEN),
    ENUM(FT_IEEE_11073_FLOAT),
    ENUM(FT_IEEE_11073_SFLOAT),
    ENUM(FT_INT16),
    ENUM(FT_INT24),
    ENUM(FT_INT32),
    ENUM(FT_INT40),
    ENUM(FT_INT48),
    ENUM(FT_INT56),
    ENUM(FT_INT64),
    ENUM(FT_INT8),
    ENUM(FT_IPXNET),
    ENUM(FT_IPXNET_LEN),
    ENUM(FT_IPv4),
    ENUM(FT_IPv4_LEN),
    ENUM(FT_IPv6),
    ENUM(FT_IPv6_LEN),
    ENUM(FT_NONE),
    ENUM(FT_NUM_TYPES),
    ENUM(FT_OID),
    ENUM(FT_OK),
    ENUM(FT_OVERFLOW),
    ENUM(FT_PROTOCOL),
    ENUM(FT_RELATIVE_TIME),
    ENUM(FT_REL_OID),
    ENUM(FT_SCALAR),
    ENUM(FT_STRING),
    ENUM(FT_STRINGZ),
    ENUM(FT_STRINGZPAD),
    ENUM(FT_STRINGZTRUNC),
    ENUM(FT_SYSTEM_ID),
    ENUM(FT_TRUE),
    ENUM(FT_UINT16),
    ENUM(FT_UINT24),
    ENUM(FT_UINT32),
    ENUM(FT_UINT40),
    ENUM(FT_UINT48),
    ENUM(FT_UINT56),
    ENUM(FT_UINT64),
    ENUM(FT_UINT8),
    ENUM(FT_UINT_BYTES),
    ENUM(FT_UINT_STRING),
    ENUM(FT_UNDERFLOW),
    ENUM(FT_VARINT_MAX_LEN),
    ENUM(FT_VINES),
    ENUM(FT_VINES_ADDR_LEN),
    ENUM(HF_REF_TYPE_DIRECT),
    ENUM(HF_REF_TYPE_INDIRECT),
    ENUM(HF_REF_TYPE_NONE),
    ENUM(HF_REF_TYPE_PRINT),
    ENUM(IP_PROTO_3PC),
    ENUM(IP_PROTO_AGGFRAG),
    ENUM(IP_PROTO_AH),
    ENUM(IP_PROTO_AN),
    ENUM(IP_PROTO_ARGUS),
    ENUM(IP_PROTO_ARIS),
    ENUM(IP_PROTO_AX25),
    ENUM(IP_PROTO_AX4000),
    ENUM(IP_PROTO_BBN_RCC),
    ENUM(IP_PROTO_BIT_EMU),
    ENUM(IP_PROTO_BNA),
    ENUM(IP_PROTO_BRSATMON),
    ENUM(IP_PROTO_BULK),
    ENUM(IP_PROTO_CBT),
    ENUM(IP_PROTO_CHAOS),
    ENUM(IP_PROTO_CMTP),
    ENUM(IP_PROTO_COMPAQ),
    ENUM(IP_PROTO_CPHB),
    ENUM(IP_PROTO_CPNX),
    ENUM(IP_PROTO_CRTP),
    ENUM(IP_PROTO_CRUDP),
    ENUM(IP_PROTO_DCCP),
    ENUM(IP_PROTO_DCNMEAS),
    ENUM(IP_PROTO_DDP),
    ENUM(IP_PROTO_DDX),
    ENUM(IP_PROTO_DGP),
    ENUM(IP_PROTO_DSR),
    ENUM(IP_PROTO_DSTOPTS),
    ENUM(IP_PROTO_EGP),
    ENUM(IP_PROTO_EIGRP),
    ENUM(IP_PROTO_EMCON),
    ENUM(IP_PROTO_ENCAP),
    ENUM(IP_PROTO_ESP),
    ENUM(IP_PROTO_ETHERIP),
    ENUM(IP_PROTO_ETHERNET),
    ENUM(IP_PROTO_FC),
    ENUM(IP_PROTO_FIRE),
    ENUM(IP_PROTO_FRAGMENT),
    ENUM(IP_PROTO_GGP),
    ENUM(IP_PROTO_GMTP),
    ENUM(IP_PROTO_GRE),
    ENUM(IP_PROTO_HIP),
    ENUM(IP_PROTO_HMP),
    ENUM(IP_PROTO_HOMA),
    ENUM(IP_PROTO_HOPOPTS),
    ENUM(IP_PROTO_IATP),
    ENUM(IP_PROTO_ICMP),
    ENUM(IP_PROTO_ICMPV6),
    ENUM(IP_PROTO_IDP),
    ENUM(IP_PROTO_IDPR),
    ENUM(IP_PROTO_IDRP),
    ENUM(IP_PROTO_IFMP),
    ENUM(IP_PROTO_IGMP),
    ENUM(IP_PROTO_IGP),
    ENUM(IP_PROTO_IGRP),
    ENUM(IP_PROTO_IL),
    ENUM(IP_PROTO_INSLP),
    ENUM(IP_PROTO_IPCOMP),
    ENUM(IP_PROTO_IPCV),
    ENUM(IP_PROTO_IPINIP),
    ENUM(IP_PROTO_IPIP),
    ENUM(IP_PROTO_IPLT),
    ENUM(IP_PROTO_IPPC),
    ENUM(IP_PROTO_IPV4),
    ENUM(IP_PROTO_IPV6),
    ENUM(IP_PROTO_IPX),
    ENUM(IP_PROTO_IRT),
    ENUM(IP_PROTO_ISIS),
    ENUM(IP_PROTO_ISOIP),
    ENUM(IP_PROTO_KRYPTOLAN),
    ENUM(IP_PROTO_L2TP),
    ENUM(IP_PROTO_LARP),
    ENUM(IP_PROTO_LEAF1),
    ENUM(IP_PROTO_LEAF2),
    ENUM(IP_PROTO_MANET),
    ENUM(IP_PROTO_MERIT),
    ENUM(IP_PROTO_MFE_NSP),
    ENUM(IP_PROTO_MICP),
    ENUM(IP_PROTO_MIPV6),
    ENUM(IP_PROTO_MIPV6_OLD),
    ENUM(IP_PROTO_MOBILE),
    ENUM(IP_PROTO_MPLS_IN_IP),
    ENUM(IP_PROTO_MTP),
    ENUM(IP_PROTO_MUX),
    ENUM(IP_PROTO_NARP),
    ENUM(IP_PROTO_NCS_HEARTBEAT),
    ENUM(IP_PROTO_NONE),
    ENUM(IP_PROTO_NSFNETIGP),
    ENUM(IP_PROTO_NSH),
    ENUM(IP_PROTO_NVPII),
    ENUM(IP_PROTO_OSPF),
    ENUM(IP_PROTO_PGM),
    ENUM(IP_PROTO_PIM),
    ENUM(IP_PROTO_PIPE),
    ENUM(IP_PROTO_PNNI),
    ENUM(IP_PROTO_PRM),
    ENUM(IP_PROTO_PTP),
    ENUM(IP_PROTO_PUP),
    ENUM(IP_PROTO_PVP),
    ENUM(IP_PROTO_QNX),
    ENUM(IP_PROTO_RDP),
    ENUM(IP_PROTO_ROHC),
    ENUM(IP_PROTO_ROUTING),
    ENUM(IP_PROTO_RSVP),
    ENUM(IP_PROTO_RSVPE2EI),
    ENUM(IP_PROTO_RVD),
    ENUM(IP_PROTO_SATEXPAK),
    ENUM(IP_PROTO_SATMON),
    ENUM(IP_PROTO_SCCCP),
    ENUM(IP_PROTO_SCPS),
    ENUM(IP_PROTO_SCTP),
    ENUM(IP_PROTO_SDRP),
    ENUM(IP_PROTO_SHIM6),
    ENUM(IP_PROTO_SKIP),
    ENUM(IP_PROTO_SM),
    ENUM(IP_PROTO_SMP),
    ENUM(IP_PROTO_SNP),
    ENUM(IP_PROTO_SPRITE),
    ENUM(IP_PROTO_SPS),
    ENUM(IP_PROTO_SRP),
    ENUM(IP_PROTO_SSCOPMCE),
    ENUM(IP_PROTO_STP),
    ENUM(IP_PROTO_STREAM),
    ENUM(IP_PROTO_SUNND),
    ENUM(IP_PROTO_SVMTP),
    ENUM(IP_PROTO_SWIPE),
    ENUM(IP_PROTO_TCF),
    ENUM(IP_PROTO_TCP),
    ENUM(IP_PROTO_TLSP),
    ENUM(IP_PROTO_TP),
    ENUM(IP_PROTO_TPPP),
    ENUM(IP_PROTO_TRUNK1),
    ENUM(IP_PROTO_TRUNK2),
    ENUM(IP_PROTO_TTP),
    ENUM(IP_PROTO_UDP),
    ENUM(IP_PROTO_UDPLITE),
    ENUM(IP_PROTO_UTI),
    ENUM(IP_PROTO_VINES),
    ENUM(IP_PROTO_VISA),
    ENUM(IP_PROTO_VMTP),
    ENUM(IP_PROTO_VRRP),
    ENUM(IP_PROTO_WBEXPAK),
    ENUM(IP_PROTO_WBMON),
    ENUM(IP_PROTO_WESP),
    ENUM(IP_PROTO_WSN),
    ENUM(IP_PROTO_XNET),
    ENUM(IP_PROTO_XTP),
    ENUM(ITEM_LABEL_LENGTH),
    ENUM(PI_ASSUMPTION),
    ENUM(PI_CHAT),
    ENUM(PI_CHECKSUM),
    ENUM(PI_COMMENT),
    ENUM(PI_COMMENTS_GROUP),
    ENUM(PI_DEBUG),
    ENUM(PI_DECRYPTION),
    ENUM(PI_DEPRECATED),
    ENUM(PI_DISSECTOR_BUG),
    ENUM(PI_ERROR),
    ENUM(PI_GROUP_MASK),
    ENUM(PI_INTERFACE),
    ENUM(PI_MALFORMED),
    ENUM(PI_NOTE),
    ENUM(PI_PROTOCOL),
    ENUM(PI_REASSEMBLE),
    ENUM(PI_RECEIVE),
    ENUM(PI_REQUEST_CODE),
    ENUM(PI_RESPONSE_CODE),
    ENUM(PI_SECURITY),
    ENUM(PI_SEQUENCE),
    ENUM(PI_SEVERITY_MASK),
    ENUM(PI_UNDECODED),
    ENUM(PI_WARN),
    ENUM(PROTO_CHECKSUM_E_BAD),
    ENUM(PROTO_CHECKSUM_E_GOOD),
    ENUM(PROTO_CHECKSUM_E_ILLEGAL),
    ENUM(PROTO_CHECKSUM_E_NOT_PRESENT),
    ENUM(PROTO_CHECKSUM_E_UNVERIFIED),
    ENUM(PROTO_CHECKSUM_GENERATED),
    ENUM(PROTO_CHECKSUM_IN_CKSUM),
    ENUM(PROTO_CHECKSUM_NOT_PRESENT),
    ENUM(PROTO_CHECKSUM_NO_FLAGS),
    ENUM(PROTO_CHECKSUM_VERIFY),
    ENUM(PROTO_CHECKSUM_ZERO),
    ENUM(PT_BLUETOOTH),
    ENUM(PT_DCCP),
    ENUM(PT_DDP),
    ENUM(PT_I2C),
    ENUM(PT_IBQP),
    ENUM(PT_IDP),
    ENUM(PT_IPX),
    ENUM(PT_IWARP_MPA),
    ENUM(PT_MCTP),
    ENUM(PT_NONE),
    ENUM(PT_SCTP),
    ENUM(PT_TCP),
    ENUM(PT_UDP),
    ENUM(PT_USB),
    ENUM(REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER),
    ENUM(REGISTER_LOG_ANALYZE_GROUP_UNSORTED),
    ENUM(REGISTER_LOG_STAT_GROUP_UNSORTED),
    ENUM(REGISTER_PACKET_ANALYZE_GROUP_UNSORTED),
    ENUM(REGISTER_PACKET_STAT_GROUP_UNSORTED),
    ENUM(REGISTER_STAT_GROUP_CONVERSATION_LIST),
    ENUM(REGISTER_STAT_GROUP_ENDPOINT_LIST),
    ENUM(REGISTER_STAT_GROUP_GENERIC),
    ENUM(REGISTER_STAT_GROUP_RESPONSE_TIME),
    ENUM(REGISTER_STAT_GROUP_RSERPOOL),
    ENUM(REGISTER_TELEPHONY_GROUP_3GPP_UU),
    ENUM(REGISTER_TELEPHONY_GROUP_ANSI),
    ENUM(REGISTER_TELEPHONY_GROUP_GSM),
    ENUM(REGISTER_TELEPHONY_GROUP_MTP3),
    ENUM(REGISTER_TELEPHONY_GROUP_SCTP),
    ENUM(REGISTER_TELEPHONY_GROUP_UNSORTED),
    ENUM(REGISTER_TOOLS_GROUP_UNSORTED),
    ENUM(SEP_COLON),
    ENUM(SEP_DASH),
    ENUM(SEP_DOT),
    ENUM(SEP_SPACE),
    ENUM(ST_FORMAT_CSV),
    ENUM(ST_FORMAT_PLAIN),
    ENUM(ST_FORMAT_XML),
    ENUM(ST_FORMAT_YAML),
    { NULL, 0 },
};
