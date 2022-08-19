/* packet-ieee80211.h
 * Routines for Wireless LAN (IEEE 802.11) dissection
 *
 * Copyright 2000, Axis Communications AB
 * Inquiries/bugreports should be sent to Johan.Jorgensen@axis.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
  gboolean association_has_mobility_domain_element;
  gboolean has_ft_akm_suite;
  gboolean has_non_ft_akm_suite;
  gboolean has_fils_session;
  guint32 last_akm_suite;
  guint16 owe_group;
  proto_node *rsn_first_ft_akm_suite;
  proto_node *rsn_first_non_ft_akm_suite;
  guint8 ampe_frame;
} association_sanity_check_t;

typedef struct {
  guint16 discovered_key_mic_len; /* Discovered from the first EAPOL frame */
  gboolean last_akm_suite_set;    /* Have we set this? */
  guint32 last_akm_suite;
  guint16 owe_group;
} ieee80211_conversation_data_t;

typedef struct {
  gboolean last_akm_suite_set;
  guint32 last_akm_suite;
  guint16 owe_group;
} ieee80211_packet_data_t;

typedef struct ieee80211_tagged_field_data
{
  int ftype;
  association_sanity_check_t* sanity_check;
  gboolean isDMG;
  proto_item* item_tag;
  proto_item* item_tag_length;
} ieee80211_tagged_field_data_t;

int add_tagged_field(packet_info *pinfo, proto_tree *tree,
                            tvbuff_t *tvb, int offset, int ftype,
                            const guint8 *valid_element_ids,
                            guint valid_element_ids_count,
                            association_sanity_check_t *association_sanity_check);

int add_tagged_field_with_validation(packet_info *pinfo, proto_tree *tree,
                                      tvbuff_t *tvb, int offset, int ftype,
                                      const guint8 *element_ids,
                                      guint element_ids_count,
                                      gboolean elements_ids_assume_invalid,
                                      const guint8 *ext_element_ids,
                                      guint ext_element_ids_count,
                                      gboolean ext_element_ids_assume_invalid,
                                      association_sanity_check_t *association_sanity_check);

int dissect_wifi_dpp_config_proto(packet_info *pinfo, proto_tree *query,
                                  tvbuff_t *tvb, int offset);
#define MAX_SSID_LEN    32
#define MAX_PROTECT_LEN 10

/*
 * Table of data rates, indexed by MCS index, bandwidth (0 for 20, 1 for 40),
 * amd guard interval (0 for long, 1 for short).
 */
#define MAX_MCS_INDEX 76

WS_DLL_PUBLIC const guint16 ieee80211_ht_Dbps[MAX_MCS_INDEX+1];
float ieee80211_htrate(int mcs_index, gboolean bandwidth, gboolean short_gi);

WS_DLL_PUBLIC value_string_ext ieee80211_supported_rates_vals_ext;

WS_DLL_PUBLIC
gboolean is_broadcast_bssid(const address *bssid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*
 * Extract the protocol version from the frame control field
 */
#define FCF_PROT_VERSION(x)  ((x) & 0x3)

#define PV0 0x0
#define PV1 0x1
#define PC2 0x2
#define PV3 0x3

/*
 * Extract the frame type from the frame control field.
 */
#define FCF_FRAME_TYPE(x)    (((x) & 0xC) >> 2)
#define FCF_PV1_TYPE(x)      (((x) >> 2) & 0x7)

/*
 * Extract the frame subtype from the frame control field.
 */
#define FCF_FRAME_SUBTYPE(x) (((x) & 0xF0) >> 4)
#define FCF_PV1_SUBTYPE(x)   (((x) >> 5) & 0x7)

/*
 * Extract the control frame extension from the frame control field.
 */
#define FCF_FRAME_EXTENSION(x) (((x) & 0xF00) >> 8)

/*
 * Checks if the frame is control frame extension.
 */
#define IS_FRAME_EXTENSION(x) ((FCF_FRAME_TYPE(x) == 0x1 && FCF_FRAME_SUBTYPE(x) == 0x6) ? 1 : 0)

/*
 * Convert the frame type and subtype from the frame control field into
 * one of the MGT_, CTRL_, or DATA_ values.
 * Now includes extension subtype in case present.
 */
#define COMPOSE_FRAME_TYPE(x) ((FCF_FRAME_TYPE(x) == 0x1 && FCF_FRAME_SUBTYPE(x) == 0x6) ? (((x & 0x0C)<< 6) + ((x) & 0xF0) + FCF_FRAME_EXTENSION(x)) : (((x & 0x0C)<< 2)+FCF_FRAME_SUBTYPE(x)))  /* Create key to (sub)type */

/*
 * The subtype field of a data frame is, in effect, composed of 4 flag
 * bits - CF-Ack, CF-Poll, Null (means the frame doesn't actually have
 * any data), and QoS.
 */
#define DATA_FRAME_IS_CF_ACK(x)  ((x) & 0x01)
#define DATA_FRAME_IS_CF_POLL(x) ((x) & 0x02)
#define DATA_FRAME_IS_NULL(x)    ((x) & 0x04)
#define DATA_FRAME_IS_QOS(x)     ((x) & 0x08)

/*
 * Extract the flags from the frame control field.
 * Now includes subset of flags when the subtype is control frame extension.
 */
#define FCF_FLAGS(x)           ((FCF_FRAME_TYPE(x) == 0x1 && FCF_FRAME_SUBTYPE(x) == 0x6) ? (((x) & 0xF000) >> 12) : (((x) & 0xFF00) >> 8))

/*
 * Bits from the flags field.
 */
#define FLAG_TO_DS            0x01
#define FLAG_FROM_DS          0x02
#define FLAG_MORE_FRAGMENTS   0x04
#define FLAG_RETRY            0x08
#define FLAG_POWER_MGT        0x10
#define FLAG_MORE_DATA        0x20
#define FLAG_PROTECTED        0x40
#define FLAG_ORDER            0x80    /* overloaded for "has HT control" */

/*
 * Test bits in the flags field.
 */
/*
 * XXX - Only HAVE_FRAGMENTS, IS_PROTECTED, and HAS_HT_CONTROL
 * are in use.  Should the rest be removed?
 */
#define IS_TO_DS(x)            ((x) & FLAG_TO_DS)
#define IS_FROM_DS(x)          ((x) & FLAG_FROM_DS)
#define HAVE_FRAGMENTS(x)      ((x) & FLAG_MORE_FRAGMENTS)
#define IS_RETRY(x)            ((x) & FLAG_RETRY)
#define POWER_MGT_STATUS(x)    ((x) & FLAG_POWER_MGT)
#define HAS_MORE_DATA(x)       ((x) & FLAG_MORE_DATA)
#define IS_PROTECTED(x)        ((x) & FLAG_PROTECTED)
#define IS_STRICTLY_ORDERED(x) ((x) & FLAG_ORDER)      /* for non-QoS data frames */
#define HAS_HT_CONTROL(x)      ((x) & FLAG_ORDER)      /* for management and QoS data frames */

/*
 * Extract subfields from the flags field.
 */
#define FLAGS_DS_STATUS(x)          ((x) & (FLAG_FROM_DS|FLAG_TO_DS))

/*
 * Extract an indication of the types of addresses in a data frame from
 * the frame control field.
 */
#define FCF_ADDR_SELECTOR(x) ((x) & ((FLAG_TO_DS|FLAG_FROM_DS) << 8))

#define DATA_ADDR_T1         0
#define DATA_ADDR_T2         (FLAG_FROM_DS << 8)
#define DATA_ADDR_T3         (FLAG_TO_DS << 8)
#define DATA_ADDR_T4         ((FLAG_TO_DS|FLAG_FROM_DS) << 8)

/*
 * COMPOSE_FRAME_TYPE() values for management frames.
 */
#define MGT_ASSOC_REQ          0x00  /* association request        */
#define MGT_ASSOC_RESP         0x01  /* association response       */
#define MGT_REASSOC_REQ        0x02  /* reassociation request      */
#define MGT_REASSOC_RESP       0x03  /* reassociation response     */
#define MGT_PROBE_REQ          0x04  /* Probe request              */
#define MGT_PROBE_RESP         0x05  /* Probe response             */
#define MGT_MEASUREMENT_PILOT  0x06  /* Measurement Pilot          */
#define MGT_BEACON             0x08  /* Beacon frame               */
#define MGT_ATIM               0x09  /* ATIM                       */
#define MGT_DISASS             0x0A  /* Disassociation             */
#define MGT_AUTHENTICATION     0x0B  /* Authentication             */
#define MGT_DEAUTHENTICATION   0x0C  /* Deauthentication           */
#define MGT_ACTION             0x0D  /* Action                     */
#define MGT_ACTION_NO_ACK      0x0E  /* Action No Ack              */
#define MGT_ARUBA_WLAN         0x0F  /* Aruba WLAN Specific        */

/*
 * COMPOSE_FRAME_TYPE() values for control frames.
 * 0x160 - 0x16A are for control frame extension where type = 1 and subtype =6.
 */
#define CTRL_TRIGGER           0x12  /* HE Trigger                     */
#define CTRL_TACK              0x13  /* S1G TWT Ack                    */
#define CTRL_BEAMFORM_RPT_POLL 0x14  /* Beamforming Report             */
#define CTRL_VHT_NDP_ANNC      0x15  /* VHT NDP Announcement           */
#define CTRL_POLL              0x162  /* Poll                          */
#define CTRL_SPR               0x163  /* Service Period Request        */
#define CTRL_GRANT             0x164  /* Grant                         */
#define CTRL_DMG_CTS           0x165  /* DMG Clear to Send             */
#define CTRL_DMG_DTS           0x166  /* DMG Denial to Send            */
#define CTRL_GRANT_ACK         0x167  /* Grant Acknowledgment          */
#define CTRL_SSW               0x168  /* Sector Sweep                  */
#define CTRL_SSW_FEEDBACK      0x169  /* Sector Sweep Feedback         */
#define CTRL_SSW_ACK           0x16A  /* Sector Sweep Acknowledgment   */
#define CTRL_CONTROL_WRAPPER   0x17  /* Control Wrapper                */
#define CTRL_BLOCK_ACK_REQ     0x18  /* Block ack Request              */
#define CTRL_BLOCK_ACK         0x19  /* Block ack                      */
#define CTRL_PS_POLL           0x1A  /* power-save poll                */
#define CTRL_RTS               0x1B  /* request to send                */
#define CTRL_CTS               0x1C  /* clear to send                  */
#define CTRL_ACKNOWLEDGEMENT   0x1D  /* acknowledgement                */
#define CTRL_CFP_END           0x1E  /* contention-free period end     */
#define CTRL_CFP_ENDACK        0x1F  /* contention-free period end/ack */

/*
 * COMPOSE_FRAME_TYPE() values for data frames.
 */
#define DATA                        0x20  /* Data                       */
#define DATA_CF_ACK                 0x21  /* Data + CF-Ack              */
#define DATA_CF_POLL                0x22  /* Data + CF-Poll             */
#define DATA_CF_ACK_POLL            0x23  /* Data + CF-Ack + CF-Poll    */
#define DATA_NULL_FUNCTION          0x24  /* Null function (no data)    */
#define DATA_CF_ACK_NOD             0x25  /* CF-Ack (no data)           */
#define DATA_CF_POLL_NOD            0x26  /* CF-Poll (No data)          */
#define DATA_CF_ACK_POLL_NOD        0x27  /* CF-Ack + CF-Poll (no data) */

#define DATA_QOS_DATA               0x28  /* QoS Data                   */
#define DATA_QOS_DATA_CF_ACK        0x29  /* QoS Data + CF-Ack        */
#define DATA_QOS_DATA_CF_POLL       0x2A  /* QoS Data + CF-Poll      */
#define DATA_QOS_DATA_CF_ACK_POLL   0x2B  /* QoS Data + CF-Ack + CF-Poll    */
#define DATA_QOS_NULL               0x2C  /* QoS Null        */
#define DATA_QOS_CF_POLL_NOD        0x2E  /* QoS CF-Poll (No Data)      */
#define DATA_QOS_CF_ACK_POLL_NOD    0x2F  /* QoS CF-Ack + CF-Poll (No Data) */

/*
 * COMPOSE_FRAME_TYPE() values for extension frames.
 */
#define EXTENSION_DMG_BEACON         0x30  /* Extension DMG beacon */
#define EXTENSION_S1G_BEACON         0x31  /* Extension S1G beacon */

/*
 * PV1 frame types
 */
#define PV1_QOS_DATA_1MAC            0x00  /* QoS data, one SID, one MAC     */
#define PV1_MANAGEMENT               0x01  /* PV1 Management frame           */
#define PV1_CONTROL                  0x02  /* PV1 Control frame              */
#define PV1_QOS_DATA_2MAC            0x03  /* QoS data, two MAC addresses    */

/*
 * PV1 frame subtypes
 */
#define PV1_CONTROL_STACK             0x00   /* Control STACK */
#define PV1_CONTROL_BAT               0x01   /* Control BAT   */

#define PV1_MANAGEMENT_ACTION         0x00
#define PV1_MANAGEMENT_ACTION_NO_ACK  0x01
#define PV1_MANAGEMENT_PROBE_RESPONSE 0x02
#define PV1_MANAGEMENT_RESOURCE_ALLOC 0x03

/*
 * PV1 SID constants
 */
#define SID_AID_MASK                  0x1FFF
#define SID_A3_PRESENT                0x2000
#define SID_A4_PRESENT                0x4000
#define SID_A_MSDU                    0x8000

#define TBTT_INFO(x)          (((x) & 0x3) >> 0)
#define TBTT_INFO_COUNT(x)    (((x) & (0xf<<4)) >> 4)
#define TBTT_INFO_LENGTH(x)   (((x) & (0xff<<8)) >> 8)

typedef struct _wlan_stats {
  guint8 channel;
  guint8 ssid_len;
  guchar ssid[MAX_SSID_LEN];
  gchar protection[MAX_PROTECT_LEN];
  gboolean fc_retry;
} wlan_stats_t;

typedef struct _wlan_hdr {
  address bssid;
  address src;
  address dst;
  guint16 type;
  struct _wlan_stats stats;
} wlan_hdr_t;

#define WLANCAP_MAGIC_COOKIE_BASE 0x80211000
#define WLANCAP_MAGIC_COOKIE_V1 0x80211001
#define WLANCAP_MAGIC_COOKIE_V2 0x80211002

/* UAT entry structure. */
typedef struct {
  guint8    key;
  gchar    *string;
} uat_wep_key_record_t;

#define ADV_PROTO_ID_ANQP      0
#define ANV_PROTO_ID_MIH_IS    1
#define ADV_PROTO_ID_MIH_CESCD 2
#define ADV_PROTO_ID_EAS       3
#define ADV_PROTO_ID_RLQP       4
#define ADV_PROTO_ID_VS        221

typedef struct anqp_info_dissector_data {
  gboolean request;
  int idx;
} anqp_info_dissector_data_t;

/* WFA vendor specific element subtypes */
#define WFA_SUBTYPE_SUBSCRIPTION_REMEDIATION   0
#define WFA_SUBTYPE_DEAUTHENTICATION_IMMINENT  1
#define WFA_SUBTYPE_P2P                        9
#define WFA_SUBTYPE_WIFI_DISPLAY               10
#define WFA_SUBTYPE_HS20_INDICATION            16
#define WFA_SUBTYPE_OSEN                       18
#define WFA_SUBTYPE_NAN_IE                     19
#define WFA_SUBTYPE_MBO_OCE                    22
#define WFA_SUBTYPE_WIFI_60G                   23
#define WFA_SUBTYPE_NAN_ACTION                 24
#define WFA_SUBTYPE_DPP                        26
#define WFA_SUBTYPE_IEEE1905_MULTI_AP          27 /* ox1B */
#define WFA_SUBTYPE_OWE_TRANSITION_MODE        28
#define WFA_SUBTYPE_TRANSITION_DISABLE_KDE     32
#define WFA_SUBTYPE_QOS_MGMT                   33 /* 0x21 */

/* WFA Public Action Types */
#define WFA_SUBTYPE_ACTION_QOS_MGMT          0x1A

/* WFA vendor specific ANQP subtypes */
#define WFA_ANQP_SUBTYPE_HS20                  17
#define WFA_ANQP_SUBTYPE_MBO                   18

/* WFA WNM notification request subtypes */
#define WFA_WNM_SUBTYPE_NON_PREF_CHAN_REPORT   2
#define WFA_WNM_SUBTYPE_CELL_DATA_CAPABILITIES 3

/* Information Element tags */
#define TAG_SSID                       0
#define TAG_SUPP_RATES                 1
#define TAG_FH_PARAMETER               2
#define TAG_DS_PARAMETER               3
#define TAG_CF_PARAMETER               4
#define TAG_TIM                        5
#define TAG_IBSS_PARAMETER             6
#define TAG_COUNTRY_INFO               7
#define TAG_FH_HOPPING_PARAMETER       8
#define TAG_FH_HOPPING_TABLE           9
#define TAG_REQUEST                   10
#define TAG_QBSS_LOAD                 11
#define TAG_EDCA_PARAM_SET            12
#define TAG_TSPEC                     13
#define TAG_TCLAS                     14
#define TAG_SCHEDULE                  15
#define TAG_CHALLENGE_TEXT            16

#define TAG_POWER_CONSTRAINT          32
#define TAG_POWER_CAPABILITY          33
#define TAG_TPC_REQUEST               34
#define TAG_TPC_REPORT                35
#define TAG_SUPPORTED_CHANNELS        36
#define TAG_CHANNEL_SWITCH_ANN        37
#define TAG_MEASURE_REQ               38
#define TAG_MEASURE_REP               39
#define TAG_QUIET                     40
#define TAG_IBSS_DFS                  41
#define TAG_ERP_INFO                  42
#define TAG_TS_DELAY                  43
#define TAG_TCLAS_PROCESS             44
#define TAG_HT_CAPABILITY             45 /* IEEE Stc 802.11n/D2.0 */
#define TAG_QOS_CAPABILITY            46
#define TAG_ERP_INFO_OLD              47 /* IEEE Std 802.11g/D4.0 */
#define TAG_RSN_IE                    48
/* Reserved 49 */
#define TAG_EXT_SUPP_RATES            50
#define TAG_AP_CHANNEL_REPORT         51
#define TAG_NEIGHBOR_REPORT           52
#define TAG_RCPI                      53
#define TAG_MOBILITY_DOMAIN           54  /* IEEE Std 802.11r-2008 */
#define TAG_FAST_BSS_TRANSITION       55  /* IEEE Std 802.11r-2008 */
#define TAG_TIMEOUT_INTERVAL          56  /* IEEE Std 802.11r-2008 */
#define TAG_RIC_DATA                  57  /* IEEE Std 802.11r-2008 */
#define TAG_DSE_REG_LOCATION          58
#define TAG_SUPPORTED_OPERATING_CLASSES             59 /* IEEE Std 802.11w-2009 */
#define TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT    60 /* IEEE Std 802.11w-2009 */
#define TAG_HT_INFO                   61  /* IEEE Stc 802.11n/D2.0 */
#define TAG_SECONDARY_CHANNEL_OFFSET  62  /* IEEE Stc 802.11n/D1.10/D2.0 */
#define TAG_BSS_AVG_ACCESS_DELAY      63
#define TAG_ANTENNA                   64
#define TAG_RSNI                      65
#define TAG_MEASURE_PILOT_TRANS       66
#define TAG_BSS_AVB_ADM_CAPACITY      67
#define TAG_IE_68_CONFLICT            68  /* Conflict: WAPI Vs. IEEE */
#define TAG_WAPI_PARAM_SET            68
#define TAG_BSS_AC_ACCESS_DELAY       68
#define TAG_TIME_ADV                  69  /* IEEE Std 802.11p-2010 */
#define TAG_RM_ENABLED_CAPABILITY     70
#define TAG_MULTIPLE_BSSID            71
#define TAG_20_40_BSS_CO_EX           72  /* IEEE P802.11n/D6.0 */
#define TAG_20_40_BSS_INTOL_CH_REP    73  /* IEEE P802.11n/D6.0 */
#define TAG_OVERLAP_BSS_SCAN_PAR      74  /* IEEE P802.11n/D6.0 */
#define TAG_RIC_DESCRIPTOR            75  /* IEEE Std 802.11r-2008 */
#define TAG_MMIE                      76  /* IEEE Std 802.11w-2009 */
#define TAG_EVENT_REQUEST             78
#define TAG_EVENT_REPORT              79
#define TAG_DIAGNOSTIC_REQUEST        80
#define TAG_DIAGNOSTIC_REPORT         81
#define TAG_LOCATION_PARAMETERS       82
#define TAG_NO_BSSID_CAPABILITY       83
#define TAG_SSID_LIST                 84
#define TAG_MULTIPLE_BSSID_INDEX      85
#define TAG_FMS_DESCRIPTOR            86
#define TAG_FMS_REQUEST               87
#define TAG_FMS_RESPONSE              88
#define TAG_QOS_TRAFFIC_CAPABILITY    89
#define TAG_BSS_MAX_IDLE_PERIOD       90
#define TAG_TFS_REQUEST               91
#define TAG_TFS_RESPONSE              92
#define TAG_WNM_SLEEP_MODE            93
#define TAG_TIM_BROADCAST_REQUEST     94
#define TAG_TIM_BROADCAST_RESPONSE    95
#define TAG_COLLOCATED_INTER_REPORT   96
#define TAG_CHANNEL_USAGE             97
#define TAG_TIME_ZONE                 98  /* IEEE Std 802.11v-2011 */
#define TAG_DMS_REQUEST               99
#define TAG_DMS_RESPONSE             100
#define TAG_LINK_IDENTIFIER          101  /* IEEE Std 802.11z-2010 */
#define TAG_WAKEUP_SCHEDULE          102  /* IEEE Std 802.11z-2010 */
#define TAG_CHANNEL_SWITCH_TIMING    104  /* IEEE Std 802.11z-2010 */
#define TAG_PTI_CONTROL              105  /* IEEE Std 802.11z-2010 */
#define TAG_PU_BUFFER_STATUS         106  /* IEEE Std 802.11z-2010 */
#define TAG_INTERWORKING             107  /* IEEE Std 802.11u-2011 */
#define TAG_ADVERTISEMENT_PROTOCOL   108  /* IEEE Std 802.11u-2011 */
#define TAG_EXPIDITED_BANDWIDTH_REQ  109  /* IEEE Std 802.11u-2011 */
#define TAG_QOS_MAP_SET              110  /* IEEE Std 802.11u-2011 */
#define TAG_ROAMING_CONSORTIUM       111  /* IEEE Std 802.11u-2011 */
#define TAG_EMERGENCY_ALERT_ID       112  /* IEEE Std 802.11u-2011 */
#define TAG_MESH_CONFIGURATION       113  /* IEEE Std 802.11s-2011 */
#define TAG_MESH_ID                  114  /* IEEE Std 802.11s-2011 */
#define TAG_MESH_LINK_METRIC_REPORT  115
#define TAG_CONGESTION_NOTIFICATION  116
#define TAG_MESH_PEERING_MGMT        117  /* IEEE Std 802.11s-2011 */
#define TAG_MESH_CHANNEL_SWITCH      118
#define TAG_MESH_AWAKE_WINDOW        119  /* IEEE Std 802.11s-2011 */
#define TAG_BEACON_TIMING            120
#define TAG_MCCAOP_SETUP_REQUEST     121
#define TAG_MCCAOP_SETUP_REPLY       122
#define TAG_MCCAOP_ADVERTISEMENT     123
#define TAG_MCCAOP_TEARDOWN          124
#define TAG_GANN                     125
#define TAG_RANN                     126  /* IEEE Std 802.11s-2011 */
#define TAG_EXTENDED_CAPABILITIES    127  /* IEEE Stc 802.11n/D1.10/D2.0 */
#define TAG_AGERE_PROPRIETARY        128
#define TAG_MESH_PREQ                130  /* IEEE Std 802.11s-2011 */
#define TAG_MESH_PREP                131  /* IEEE Std 802.11s-2011 */
#define TAG_MESH_PERR                132  /* IEEE Std 802.11s-2011 */
#define TAG_CISCO_CCX1_CKIP          133  /* Cisco Compatible eXtensions v1 */
#define TAG_CISCO_CCX2               136  /* Cisco Compatible eXtensions v2 */
#define TAG_PXU                      137
#define TAG_PXUC                     138
#define TAG_AUTH_MESH_PEERING_EXCH   139
#define TAG_MIC                      140
#define TAG_DESTINATION_URI          141
#define TAG_U_APSD_COEX              142
#define TAG_WAKEUP_SCHEDULE_AD       143  /* IEEE Std 802.11ad */
#define TAG_EXTENDED_SCHEDULE        144  /* IEEE Std 802.11ad */
#define TAG_STA_AVAILABILITY         145  /* IEEE Std 802.11ad */
#define TAG_DMG_TSPEC                146  /* IEEE Std 802.11ad */
#define TAG_NEXT_DMG_ATI             147  /* IEEE Std 802.11ad */
#define TAG_DMG_CAPABILITIES         148  /* IEEE Std 802.11ad */
#define TAG_CISCO_CCX3               149  /* Cisco Compatible eXtensions v3 */
#define TAG_CISCO_VENDOR_SPECIFIC    150  /* Cisco Compatible eXtensions */
#define TAG_DMG_OPERATION            151  /* IEEE Std 802.11ad */
#define TAG_DMG_BSS_PARAMETER_CHANGE 152  /* IEEE Std 802.11ad */
#define TAG_DMG_BEAM_REFINEMENT      153  /* IEEE Std 802.11ad */
#define TAG_CHANNEL_MEASURMENT_FB    154  /* IEEE Std 802.11ad */
#define TAG_AWAKE_WINDOW             157  /* IEEE Std 802.11ad */
#define TAG_MULTI_BAND               158  /* IEEE Std 802.11ad */
#define TAG_ADDBA_EXT                159  /* IEEE Std 802.11ad */
#define TAG_NEXTPCP_LIST             160  /* IEEE Std 802.11ad */
#define TAG_PCP_HANDOVER             161  /* IEEE Std 802.11ad */
#define TAG_DMG_LINK_MARGIN          162  /* IEEE Std 802.11ad */
#define TAG_SWITCHING_STREAM         163  /* IEEE Std 802.11ad */
#define TAG_SESSION_TRANSMISSION     164  /* IEEE Std 802.11ad */
#define TAG_DYN_TONE_PAIR_REP        165  /* IEEE Std 802.11ad */
#define TAG_CLUSTER_REP              166  /* IEEE Std 802.11ad */
#define TAG_RELAY_CAPABILITIES       167  /* IEEE Std 802.11ad */
#define TAG_RELAY_TRANSFER_PARAM     168  /* IEEE Std 802.11ad */
#define TAG_BEAMLINK_MAINTENANCE     169  /* IEEE Std 802.11ad */
#define TAG_MULTIPLE_MAC_SUBLAYERS   170  /* IEEE Std 802.11ad */
#define TAG_U_PID                    171  /* IEEE Std 802.11ad */
#define TAG_DMG_LINK_ADAPTION_ACK    172  /* IEEE Std 802.11ad */
#define TAG_SYMBOL_PROPRIETARY       173
#define TAG_MCCAOP_ADVERTISEMENT_OV  174
#define TAG_QUIET_PERIOD_REQ         175  /* IEEE Std 802.11ad */
#define TAG_QUIET_PERIOD_RES         177  /* IEEE Std 802.11ad */
#define TAG_ECAPC_POLICY             182  /* IEEE Std 802.11ad */
#define TAG_CLUSTER_TIME_OFFSET      183  /* IEEE Std 802.11ad */
#define TAG_INTRA_ACCESS_CAT_PRIO    184
#define TAG_SCS_DESCRIPTOR           185  /* IEEE Std 802.11   */
#define TAG_ANTENNA_SECTOR_ID        190  /* IEEE Std 802.11ad */
#define TAG_VHT_CAPABILITY           191  /* IEEE Std 802.11ac/D3.1 */
#define TAG_VHT_OPERATION            192  /* IEEE Std 802.11ac/D3.1 */
#define TAG_EXT_BSS_LOAD             193  /* IEEE Std 802.11ac */
#define TAG_WIDE_BW_CHANNEL_SWITCH   194  /* IEEE Std 802.11ac */
#define TAG_TX_PWR_ENVELOPE          195  /* IEEE Std 802.11-2020 */
#define TAG_CHANNEL_SWITCH_WRAPPER   196  /* IEEE Std 802.11ac */
#define TAG_OPERATING_MODE_NOTIFICATION 199  /* IEEE Std 802.11ac */
#define TAG_REDUCED_NEIGHBOR_REPORT  201
#define TAG_FINE_TIME_MEASUREMENT_PARAM 206  /* IEEE Std 802.11-REVmd/D2.0 */
#define TAG_S1G_OPEN_LOOP_LINK_MARGIN_INDEX 207 /* IEEE Std 802.11ah */
#define TAG_RPS                      208  /* IEEE Stf 802.11ah */
#define TAG_PAGE_SLICE               209  /* IEEE Stf 802.11ah */
#define TAG_AID_REQUEST              210  /* IEEE Stf 802.11ah */
#define TAG_AID_RESPONSE             211  /* IEEE Stf 802.11ah */
#define TAG_S1G_SECTOR_OPERATION     212  /* IEEE Stf 802.11ah */
#define TAG_S1G_BEACON_COMPATIBILITY 213  /* IEEE Stf 802.11ah */
#define TAG_SHORT_BEACON_INTERVAL    214  /* IEEE Stf 802.11ah */
#define TAG_CHANGE_SEQUENCE          215  /* IEEE Stf 802.11ah */
#define TAG_TWT                      216  /* IEEE Std 802.11ah */
#define TAG_S1G_CAPABILITIES         217  /* IEEE Stf 802.11ah */
#define TAG_SUBCHANNEL_SELECTIVE_TRANSMISSION 220  /* IEEE Stf 802.11ah */
#define TAG_VENDOR_SPECIFIC_IE       221
#define TAG_AUTHENTICATION_CONTROL   222  /* IEEE Stf 802.11ah */
#define TAG_TSF_TIMER_ACCURACY       223  /* IEEE Stf 802.11ah */
#define TAG_S1G_RELAY                224  /* IEEE Stf 802.11ah */
#define TAG_REACHABLE_ADDRESS        225  /* IEEE Stf 802.11ah */
#define TAG_S1G_RELAY_DISCOVERY      226  /* IEEE Stf 802.11ah */
#define TAG_AID_ANNOUNCEMENT         228  /* IEEE Stf 802.11ah */
#define TAG_PV1_PROBE_RESPONSE_OPTION 229  /* IEEE Stf 802.11ah */
#define TAG_EL_OPERATION             230  /* IEEE Stf 802.11ah */
#define TAG_SECTORIZED_GROUP_ID_LIST 231  /* IEEE Stf 802.11ah */
#define TAG_S1G_OPERATION            232  /* IEEE Stf 802.11ah */
#define TAG_HEADER_COMPRESSION       233  /* IEEE Stf 802.11ah */
#define TAG_SST_OPERATION            234  /* IEEE Stf 802.11ah */
#define TAG_MAD                      235  /* IEEE Stf 802.11ah */
#define TAG_S1G_RELAY_ACTIVATION     236  /* IEEE Stf 802.11ah */
#define TAG_CAG_NUMBER               237  /* IEEE Std 802.11ai */
#define TAG_AP_CSN                   239  /* IEEE Std 802.11ai */
#define TAG_FILS_INDICATION          240  /* IEEE Std 802.11ai */
#define TAG_DIFF_INITIAL_LINK_SETUP  241  /* IEEE Std 802.11ai */
#define TAG_FRAGMENT                 242  /* IEEE Std 802.11ai */
#define TAG_RSNX                     244
#define TAG_ELEMENT_ID_EXTENSION     255  /* IEEE Std 802.11ai */

extern const value_string ie_tag_num_vals[];

guint
add_ff_action(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
              association_sanity_check_t *association_sanity_check );

guint
add_ff_action_public_fields(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                            int offset, guint8 code);

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
