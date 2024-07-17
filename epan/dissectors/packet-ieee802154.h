/* packet-ieee802154.h
 *
 * IEEE 802.15.4 Dissectors for Wireshark
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2007 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_IEEE802154_H
#define PACKET_IEEE802154_H

/* Protocol Abbreviation */
#define IEEE802154_PROTOABBREV_WPAN         "wpan"
#define IEEE802154_PROTOABBREV_WPAN_BEACON  "wpan.beacon"
/* PANID dissector list is for Decode-As and stateful dissection only. */
#define IEEE802154_PROTOABBREV_WPAN_PANID   "wpan.panid"

/* Dissector tables */
#define IEEE802154_HEADER_IE_DTABLE         "wpan.header_ie"
#define IEEE802154_PAYLOAD_IE_DTABLE        "wpan.payload_ie"
#define IEEE802154_MLME_IE_DTABLE           "wpan.mlme_ie"
#define IEEE802154_CMD_VENDOR_DTABLE        "wpan.cmd.vendor"

/*  Packet Overhead from MAC header + footer (excluding addressing) */
#define IEEE802154_MAX_FRAME_LEN            127
#define IEEE802154_FCS_LEN                  2

/*  Command Frame Identifier Types Definitions */
#define IEEE802154_CMD_ASSOC_REQ                0x01
#define IEEE802154_CMD_ASSOC_RSP                0x02
#define IEEE802154_CMD_DISASSOC_NOTIFY          0x03
#define IEEE802154_CMD_DATA_RQ                  0x04
#define IEEE802154_CMD_PANID_CONFLICT           0x05
#define IEEE802154_CMD_ORPHAN_NOTIFY            0x06
#define IEEE802154_CMD_BEACON_REQ               0x07
#define IEEE802154_CMD_COORD_REALIGN            0x08
#define IEEE802154_CMD_GTS_REQ                  0x09
#define IEEE802154_CMD_TRLE_MGMT_REQ            0x0a
#define IEEE802154_CMD_TRLE_MGMT_RSP            0x0b
/* 0x0c-0x12 reserved in IEEE802.15.4-2015 */
#define IEEE802154_CMD_DSME_ASSOC_REQ           0x13
#define IEEE802154_CMD_DSME_ASSOC_RSP           0x14
#define IEEE802154_CMD_DSME_GTS_REQ             0x15
#define IEEE802154_CMD_DSME_GTS_RSP             0x16
#define IEEE802154_CMD_DSME_GTS_NOTIFY          0x17
#define IEEE802154_CMD_DSME_INFO_REQ            0x18
#define IEEE802154_CMD_DSME_INFO_RSP            0x19
#define IEEE802154_CMD_DSME_BEACON_ALLOC_NOTIFY 0x1a
#define IEEE802154_CMD_DSME_BEACON_COLL_NOTIFY  0x1b
#define IEEE802154_CMD_DSME_LINK_REPORT         0x1c
/* 0x1d-0x1f reserved in IEEE802.15.4-2015 */
#define IEEE802154_CMD_RIT_DATA_REQ             0x20
#define IEEE802154_CMD_DBS_REQ                  0x21
#define IEEE802154_CMD_DBS_RSP                  0x22
#define IEEE802154_CMD_RIT_DATA_RSP             0x23
#define IEEE802154_CMD_VENDOR_SPECIFIC          0x24
/* 0x25-0xff reserved in IEEE802.15.4-2015 */

/*  Definitions for Association Response Command */
#define IEEE802154_CMD_ASRSP_AS_SUCCESS         0x00
#define IEEE802154_CMD_ASRSP_PAN_FULL           0x01
#define IEEE802154_CMD_ASRSP_PAN_DENIED         0x02

/*  Bit Masks for Capability Information Field
    Included in Association Req. command    */
#define IEEE802154_CMD_CINFO_ALT_PAN_COORD  0x01
#define IEEE802154_CMD_CINFO_DEVICE_TYPE    0x02
#define IEEE802154_CMD_CINFO_POWER_SRC      0x04
#define IEEE802154_CMD_CINFO_IDLE_RX        0x08
#define IEEE802154_CMD_CINFO_SEC_CAPABLE    0x40
#define IEEE802154_CMD_CINFO_ALLOC_ADDR     0x80

#define IEEE802154_CMD_GTS_REQ_LEN          0x0F
#define IEEE802154_CMD_GTS_REQ_DIR          0x10
#define IEEE802154_CMD_GTS_REQ_TYPE         0x20

/*  Bit masks & shifts for various beacon fields */
#define IEEE802154_BEACON_ORDER_MASK        0x000F
#define IEEE802154_SUPERFRAME_ORDER_MASK    0x00F0
#define IEEE802154_SUPERFRAME_CAP_MASK      0x0F00
#define IEEE802154_BATT_EXTENSION_MASK      0x1000
#define IEEE802154_SUPERFRAME_COORD_MASK    0x4000
#define IEEE802154_ASSOC_PERMIT_MASK        0x8000
#define IEEE802154_SUPERFRAME_ORDER_SHIFT   4
#define IEEE802154_SUPERFRAME_CAP_SHIFT     8

#define IEEE802154_GTS_COUNT_MASK           0x07
#define IEEE802154_GTS_PERMIT_MASK          0x80
#define IEEE802154_GTS_DIRECTION_SLOT(i)    (0x01<<(i))
#define IEEE802154_GTS_MAX_SLOTS            7
#define IEEE802154_GTS_DIRECTION_SLOT1      0x01
#define IEEE802154_GTS_DIRECTION_SLOT2      0x02
#define IEEE802154_GTS_DIRECTION_SLOT3      0x04
#define IEEE802154_GTS_DIRECTION_SLOT4      0x08
#define IEEE802154_GTS_DIRECTION_SLOT5      0x10
#define IEEE802154_GTS_DIRECTION_SLOT6      0x20
#define IEEE802154_GTS_DIRECTION_SLOT7      0x40
#define IEEE802154_GTS_SLOT_MASK            0x0F
#define IEEE802154_GTS_LENGTH_MASK          0xF0
#define IEEE802154_GTS_LENGTH_SHIFT         4

#define IEEE802154_PENDADDR_SHORT_MASK      0x07
#define IEEE802154_PENDADDR_LONG_MASK       0x70
#define IEEE802154_PENDADDR_LONG_SHIFT      4

#define IEEE802154_SUPERFRAME_DURATION      (IEEE802154_BASE_SLOT_DURATION * IEEE802154_SUPERFRAME_SLOTS)
#define IEEE802154_BASE_SLOT_DURATION       60
#define IEEE802154_SUPERFRAME_SLOTS         16

/*  Bit-masks for the FCF */
#define IEEE802154_FCF_TYPE_MASK            0x0007  /* Frame Type Mask */
#define IEEE802154_FCF_SEC_EN               0x0008
#define IEEE802154_FCF_FRAME_PND            0x0010
#define IEEE802154_FCF_ACK_REQ              0x0020
#define IEEE802154_FCF_PAN_ID_COMPRESSION   0x0040  /* known as Intra PAN prior to IEEE 802.15.4-2006 */
#define IEEE802154_FCF_SEQNO_SUPPRESSION    0x0100
#define IEEE802154_FCF_IE_PRESENT           0x0200
#define IEEE802154_FCF_DADDR_MASK           0x0C00  /* destination addressing mask */
#define IEEE802154_FCF_VERSION              0x3000
#define IEEE802154_FCF_SADDR_MASK           0xC000  /* source addressing mask */

/* Bit-masks for the Multipurpose FCF */
#define IEEE802154_MPF_FCF_TYPE_MASK           0x0007
#define IEEE802154_MPF_FCF_LONG_FC             0x0008
#define IEEE802154_MPF_FCF_DADDR_MASK          0x0030
#define IEEE802154_MPF_FCF_SADDR_MASK          0x00C0
#define IEEE802154_MPF_FCF_PAN_ID_PRESENT      0x0100
#define IEEE802154_MPF_FCF_SEC_EN              0x0200
#define IEEE802154_MPF_FCF_SEQNO_SUPPRESSION   0x0400
#define IEEE802154_MPF_FCF_FRAME_PND           0x0800
#define IEEE802154_MPF_FCF_VERSION             0x3000
#define IEEE802154_MPF_FCF_ACK_REQ             0x4000
#define IEEE802154_MPF_FCF_IE_PRESENT          0x8000

/* Frame Type Definitions */
#define IEEE802154_FCF_BEACON                  0x0  /* Beacon Frame */
#define IEEE802154_FCF_DATA                    0x1  /* Data Frame */
#define IEEE802154_FCF_ACK                     0x2  /* Acknowlegement Frame */
#define IEEE802154_FCF_CMD                     0x3  /* MAC Command Frame */
#define IEEE802154_FCF_RESERVED                0x4  /* reserved */
#define IEEE802154_FCF_MULTIPURPOSE            0x5  /* Multipurpose */
#define IEEE802154_FCF_FRAGMENT                0x6  /* Fragment or Frak */
#define IEEE802154_FCF_EXTENDED                0x7  /* Extended */

/* Frame version definitions. */
#define IEEE802154_VERSION_2003                0x0
#define IEEE802154_VERSION_2006                0x1
#define IEEE802154_VERSION_2015                0x2
#define IEEE802154_VERSION_RESERVED            0x3

/* Address Mode Definitions */
#define IEEE802154_FCF_ADDR_NONE               0x0
#define IEEE802154_FCF_ADDR_RESERVED           0x1
#define IEEE802154_FCF_ADDR_SHORT              0x2
#define IEEE802154_FCF_ADDR_EXT                0x3

/* Header IE Fields */
#define IEEE802154_HEADER_IE_TYPE_MASK      0x8000
#define IEEE802154_HEADER_IE_ID_MASK        0x7F80
#define IEEE802154_HEADER_IE_LENGTH_MASK    0x007F

/* Payload IE Fields */
#define IEEE802154_PAYLOAD_IE_TYPE_MASK     0x8000
#define IEEE802154_PAYLOAD_IE_ID_MASK       0x7800
#define IEEE802154_PAYLOAD_IE_LENGTH_MASK   0x07FF

/* Payload (Nested) Sub IE Fields */
#define IEEE802154_PSIE_TYPE_MASK           0x8000
#define IEEE802154_PSIE_ID_MASK_SHORT       0x7F00
#define IEEE802154_PSIE_LENGTH_MASK_SHORT   0x00FF
#define IEEE802154_PSIE_ID_MASK_LONG        0x7800
#define IEEE802154_PSIE_LENGTH_MASK_LONG    0x07FF

/* Enhanced Beacon Filter IE */
#define IEEE802154_MLME_PSIE_EB_FLT_PJOIN     0x01
#define IEEE802154_MLME_PSIE_EB_FLT_LQI       0x02
#define IEEE802154_MLME_PSIE_EB_FLT_PERCENT   0x04
#define IEEE802154_MLME_PSIE_EB_FLT_ATTR_LEN  0x18

/* Vendor OUIs */

/*  Bit-masks for TI CC24xx end-of-packet metadata */
#define IEEE802154_CC24xx_CRC_OK            0x8000 /* 1 if CRC OK, 0 if not */
#define IEEE802154_CC24xx_CORRELATION       0x7F00 /* Some LQI stuff */
#define IEEE802154_CC24xx_RSSI              0x00FF /* Raw RSSI */

/*  Special IEEE802.15.4 Addresses */
#define IEEE802154_NO_ADDR16                0xFFFE
#define IEEE802154_BCAST_ADDR               0xFFFF
#define IEEE802154_BCAST_PAN                0xFFFF

/*  Bit mask for PHY length field */
#define IEEE802154_PHY_LENGTH_MASK          0x7F

/* Auxiliary Security Header */
#define IEEE802154_AUX_SEC_LEVEL_MASK                 0x07  /* Security Level */
#define IEEE802154_AUX_KEY_ID_MODE_MASK               0x18  /* Key Identifier Mode */
#define IEEE802154_AUX_KEY_ID_MODE_SHIFT              3
#define IEEE802154_AUX_FRAME_COUNTER_SUPPRESSION_MASK 0x20  /* 802.15.4-2015 */
#define IEEE802154_AUX_ASN_IN_NONCE_MASK              0x40  /* 802.15.4-2015 */
/* Note: 802.15.4-2015 specifies bits 6-7 as reserved, but 6 is used for ASN */
#define IEEE802154_AUX_CTRL_RESERVED_MASK             0x80  /* Reserved */

/* Thread-specific well-known key support */
#define IEEE802154_THR_WELL_KNOWN_KEY_INDEX 0xff
#define IEEE802154_THR_WELL_KNOWN_KEY_SRC   0xffffffff
#define IEEE802154_THR_WELL_KNOWN_EXT_ADDR  0x3506feb823d48712ULL

/* 802.15.4e LE-multipurpose Wake-up frame length */
#define IEEE802154E_LE_WUF_LEN              12

typedef enum {
    SECURITY_LEVEL_NONE = 0x00,
    SECURITY_LEVEL_MIC_32 = 0x01,
    SECURITY_LEVEL_MIC_64 = 0x02,
    SECURITY_LEVEL_MIC_128 = 0x03,
    SECURITY_LEVEL_ENC = 0x04,
    SECURITY_LEVEL_ENC_MIC_32 = 0x05,
    SECURITY_LEVEL_ENC_MIC_64 = 0x06,
    SECURITY_LEVEL_ENC_MIC_128 = 0x07
} ieee802154_security_level;

typedef enum {
    KEY_ID_MODE_IMPLICIT = 0x00,
    KEY_ID_MODE_KEY_INDEX = 0x01,
    KEY_ID_MODE_KEY_EXPLICIT_4 = 0x02,
    KEY_ID_MODE_KEY_EXPLICIT_8 = 0x03
} ieee802154_key_id_mode;

typedef enum {
    KEY_HASH_NONE = 0x00,
    KEY_HASH_ZIP = 0x01,
    KEY_HASH_THREAD = 0x02
} ieee802154_key_hash;

/* Header IE Element ID */
#define IEEE802154_HEADER_IE_VENDOR_SPECIFIC 0x00
/* Reserved 0x01-0x19 */
#define IEEE802154_HEADER_IE_CSL            0x1a
#define IEEE802154_HEADER_IE_RIT            0x1b
#define IEEE802154_HEADER_IE_DSME_PAN       0x1c
#define IEEE802154_HEADER_IE_RENDEZVOUS     0x1d
#define IEEE802154_HEADER_IE_TIME_CORR      0x1e
/* Reserved 0x1f-0x20 */
#define IEEE802154_HEADER_IE_EXT_DSME_PAN   0x21
#define IEEE802154_HEADER_IE_FSCD           0x22
#define IEEE802154_HEADER_IE_SMPL_SUPER_FRM 0x23
#define IEEE802154_HEADER_IE_SMPL_GTS       0x24
#define IEEE802154_HEADER_IE_LECIM          0x25
#define IEEE802154_HEADER_IE_TRLE           0x26
#define IEEE802154_HEADER_IE_RCC_CAP        0x27
#define IEEE802154_HEADER_IE_RCCN           0x28
#define IEEE802154_HEADER_IE_GLOBAL_TIME    0x29
#define IEEE802154_HEADER_IE_WISUN          0x2a
#define IEEE802154_HEADER_IE_DA_IE          0x2b
/* Reserved 0x2c-0x7d */
#define IEEE802154_HEADER_IE_HT1            0x7e
#define IEEE802154_HEADER_IE_HT2            0x7f

/* Thread vendor ID */
#define IEEE802154_HEADER_IE_THREAD         0x9b

/* Reserved 0x80-0xff */

/* Payload IE Group ID */
#define IEEE802154_PAYLOAD_IE_ESDU           0x0 /* Encapsulated Service Data Unit */
#define IEEE802154_PAYLOAD_IE_MLME           0x1 /* Media Access Control (MAC) subLayer Management Entity */
#define IEEE802154_PAYLOAD_IE_VENDOR         0x2 /* Vendor Specific */
#define IEEE802154_PAYLOAD_IE_MPX            0x3 /* MPX IE (802.15.9) */
#define IEEE802154_PAYLOAD_IE_WISUN          0x4 /* Wi-SUN IE */
#define IEEE802154_PAYLOAD_IE_IETF           0x5 /* IETF IE, RFC 8137 */
/* Reserved 0x6-0xe */
#define IEEE802154_PAYLOAD_IE_TERMINATION    0xf

/* Payload IE (Nested) Sub ID */
/* Payload IE (Nested) Sub ID - long format */
/* 0x0 - 0x7 Reserved */
/* 0x0 - 0x8 Vendor Specific */
#define IEEE802154_MLME_SUBIE_CHANNEL_HOPPING            0x9
/* 0xa - 0xf Reserved */
/* 0x10 - 0x19 Short Format Reserved */
#define IEEE802154_MLME_SUBIE_TSCH_SYNCH                 0x1A
#define IEEE802154_MLME_SUBIE_TSCH_SLOTFR_LINK           0x1B
#define IEEE802154_MLME_SUBIE_TSCH_TIMESLOT              0x1C
#define IEEE802154_MLME_SUBIE_HOPPING_TIMING             0x1D
#define IEEE802154_MLME_SUBIE_ENHANCED_BEACON_FILTER     0x1E
#define IEEE802154_MLME_SUBIE_MAC_METRICS                0x1F
#define IEEE802154_MLME_SUBIE_ALL_MAC_METRICS            0x20
#define IEEE802154_MLME_SUBIE_COEXISTENCE_SPEC           0x21
#define IEEE802154_MLME_SUBIE_SUN_DEVICE_CAPABILITIES    0x22
#define IEEE802154_MLME_SUBIE_SUN_FSK_GEN_PHY            0x23
#define IEEE802154_MLME_SUBIE_MODE_SWITCH_PARAMETER      0x24
#define IEEE802154_MLME_SUBIE_PHY_PARAMETER_CHANGE       0x25
#define IEEE802154_MLME_SUBIE_O_QPSK_PHY_MODE            0x26
#define IEEE802154_MLME_SUBIE_PCA_ALLOCATION             0x27
#define IEEE802154_MLME_SUBIE_DSSS_OPER_MODE             0x28
#define IEEE802154_MLME_SUBIE_FSK_OPER_MODE              0x29
#define IEEE802154_MLME_SUBIE_TVWS_PHY_OPE_MODE          0x2B
#define IEEE802154_MLME_SUBIE_TVWS_DEVICE_CAPAB          0x2C
#define IEEE802154_MLME_SUBIE_TVWS_DEVICE_CATEG          0x2D
#define IEEE802154_MLME_SUBIE_TVWS_DEVICE_IDENTIF        0x2E
#define IEEE802154_MLME_SUBIE_TVWS_DEVICE_LOCATION       0x2F
#define IEEE802154_MLME_SUBIE_TVWS_CH_INFOR_QUERY        0x30
#define IEEE802154_MLME_SUBIE_TVWS_CH_INFOR_SOURCE       0x31
#define IEEE802154_MLME_SUBIE_CTM                        0x32
#define IEEE802154_MLME_SUBIE_TIMESTAMP                  0x33
#define IEEE802154_MLME_SUBIE_TIMESTAMP_DIFF             0x34
#define IEEE802154_MLME_SUBIE_TMCP_SPECIFICATION         0x35
#define IEEE802154_MLME_SUBIE_RCC_PHY_OPER_MODE          0x36
/* 0x37-0x7f Reserved */

/* IETF IE - Sub IE */
#define IEEE802154_IETF_SUBIE_6TOP_DRAFT                 0xC9 /* not formally assigned yet */
#define IEEE802154_IETF_SUBIE_6TOP                       0x01 /* not formally assigned yet */

/* IEEE 802.15.4 cipher block size. */
#define IEEE802154_CIPHER_SIZE                16

/* IEEE 802.15 CID */
#define IEEE80215_CID       0xBA55ECULL

/* Macro to compute the MIC length. */
#define IEEE802154_MIC_LENGTH(_level_) ((0x2 << ((_level_) & 0x3)) & ~0x3)
/* Macro to check for payload encryption. */
#define IEEE802154_IS_ENCRYPTED(_level_) ((_level_) & 0x4)

/*SIXTOP Bit-mask*/
#define IETF_6TOP_VERSION                0x0F
#define IETF_6TOP_TYPE                   0x30
#define IETF_6TOP_FLAGS_RESERVED         0xC0
#define IETF_6TOP_SEQNUM                 0xFF

/* SIXTOP CMD and RC identifiers */
#define IETF_6TOP_CMD_ADD              0x01
#define IETF_6TOP_CMD_DELETE           0x02
#define IETF_6TOP_CMD_RELOCATE         0x03
#define IETF_6TOP_CMD_COUNT            0x04
#define IETF_6TOP_CMD_LIST             0x05
#define IETF_6TOP_CMD_SIGNAL           0x06
#define IETF_6TOP_CMD_CLEAR            0x07
#define IETF_6TOP_RC_SUCCESS           0x00
#define IETF_6TOP_RC_EOL               0x01
#define IETF_6TOP_RC_ERR               0x02
#define IETF_6TOP_RC_RESET             0x03
#define IETF_6TOP_RC_ERR_VERSION       0x04
#define IETF_6TOP_RC_ERR_SFID          0x05
#define IETF_6TOP_RC_ERR_SEQNUM        0x06
#define IETF_6TOP_RC_ERR_CELLLIST      0x07
#define IETF_6TOP_RC_ERR_BUSY          0x08
#define IETF_6TOP_RC_ERR_LOCKED        0x09

/* SIXTOP Message Types */
#define IETF_6TOP_TYPE_REQUEST         0x00
#define IETF_6TOP_TYPE_RESPONSE        0x01
#define IETF_6TOP_TYPE_CONFIRMATION    0x02
#define IETF_6TOP_TYPE_RESERVED        0x03

/* SIXTOP Cell Options */
#define IETF_6TOP_CELL_OPTION_TX       0x01
#define IETF_6TOP_CELL_OPTION_RX       0x02
#define IETF_6TOP_CELL_OPTION_SHARED   0x04
#define IETF_6TOP_CELL_OPTION_RESERVED 0xF8

/* IEEE 802.15.9 MPX IE */
#define IEEE802159_MPX_TRANSFER_TYPE_MASK      0x07
#define IEEE802159_MPX_TRANSACTION_ID_MASK     0xf8
#define IEEE802159_MPX_TRANSACTION_ID_SHIFT    0x03
/* IEEE 802.15.9 Table 19 */
#define IEEE802159_MPX_FULL_FRAME                 0
#define IEEE802159_MPX_FULL_FRAME_NO_MUXID        1
#define IEEE802159_MPX_NON_LAST_FRAGMENT          2
#define IEEE802159_MPX_LAST_FRAGMENT              4
#define IEEE802159_MPX_ABORT                      6
/* IEEE 802.15.9 Table 20 */
#define IEEE802159_MPX_MULTIPLEX_ID_KMP           1
#define IEEE802159_MPX_MULTIPLEX_ID_WISUN         2
/* IEEE 802.15.9 Table 21 */
#define IEEE802159_MPX_KMP_ID_IEEE8021X           1
#define IEEE802159_MPX_KMP_ID_HIP                 2
#define IEEE802159_MPX_KMP_ID_IKEV2               3
#define IEEE802159_MPX_KMP_ID_PANA                4
#define IEEE802159_MPX_KMP_ID_DRAGONFLY           5
#define IEEE802159_MPX_KMP_ID_IEEE80211_4WH       6
#define IEEE802159_MPX_KMP_ID_IEEE80211_GKH       7
#define IEEE802159_MPX_KMP_ID_ETSI_TS_102_887_2   8
#define IEEE802159_MPX_KMP_ID_VENDOR_SPECIFIC   255
/* Wi-SUN MPX Sub-ID values. */
#define IEEE802159_MPX_WISUN_SUBID_MHDS           0
#define IEEE802159_MPX_WISUN_SUBID_6LOWPAN        1
#define IEEE802159_MPX_WISUN_SUBID_SECURITY       2

/*  Structure containing information regarding all necessary packet fields. */
typedef struct {
    /* Frame control field. */
    int32_t     version;
    int32_t     frame_type;
    int32_t     dst_addr_mode;
    int32_t     src_addr_mode;
    bool        security_enable;
    bool        frame_pending;
    bool        ack_request;
    bool        pan_id_compression;
    bool        seqno_suppression;
    bool        ie_present;

    /* Fields exclusive to the 802.15.4-2015 multipurpose frame control field */
    bool        long_frame_control;
    bool        pan_id_present;

    uint8_t     seqno;
    /* Determined during processing of Header IE*/
    bool        payload_ie_present;
    /* Addressing Info. */
    bool        dst_pan_present;
    bool        src_pan_present;
    uint16_t    dst_pan;
    uint16_t    src_pan;
    uint16_t    dst16;
    uint64_t    dst64;
    uint16_t    src16;
    uint64_t    src64;

    /* Security Info. */
    ieee802154_security_level   security_level;
    ieee802154_key_id_mode      key_id_mode;
    bool        frame_counter_suppression; /* 802.15.4-2015 */
    uint32_t    frame_counter;
    uint8_t     key_sequence_counter;    /* Only for 802.15.4-2003 security suite with encryption */
    uint64_t    asn;

    union {
        uint32_t addr32;
        uint64_t addr64;
    } key_source;
    uint8_t     key_index;

    /* Command ID (only if frame_type == 0x3) */
    uint8_t     command_id;
    GHashTable *short_table;
} ieee802154_packet;

/* Structure for two-way mapping table */
typedef struct {
    GHashTable *long_table;
    GHashTable *short_table;
} ieee802154_map_tab_t;

/* Key used by the short address hash table. */
typedef struct {
    uint16_t    pan;
    uint16_t    addr;
} ieee802154_short_addr;

/* Key used by the long address hash table. */
typedef struct {
    uint64_t    addr;
} ieee802154_long_addr;

/* A mapping record for a frame, pointed to by hash table */
typedef struct {
    const char *proto; /* name of protocol that created this record */
    unsigned    start_fnum;
    unsigned    end_fnum;
    uint64_t    addr64;
    /*uint32_t  frame_counter;   TODO for frame counter sequence checks. */
} ieee802154_map_rec;

#define IEEE802154_USER_MAPPING 0

typedef struct {
    uint16_t            src_pan;
    uint16_t            src16;
    uint16_t            dst16;
    ieee802154_map_rec *map_rec;
    void               *packet;
} ieee802154_hints_t;

typedef enum {
    DECRYPT_PACKET_SUCCEEDED,
    DECRYPT_NOT_ENCRYPTED,
    DECRYPT_FRAME_COUNTER_SUPPRESSION_UNSUPPORTED,
    DECRYPT_PACKET_TOO_SMALL,
    DECRYPT_PACKET_NO_EXT_SRC_ADDR,
    DECRYPT_PACKET_NO_KEY,
    DECRYPT_PACKET_DECRYPT_FAILED,
    DECRYPT_PACKET_MIC_CHECK_FAILED
} ieee802154_decrypt_status;

/* UAT key structure. */
typedef struct {
    char *pref_key;
    unsigned  key_index;
    ieee802154_key_hash hash_type;
    uint8_t key[IEEE802154_CIPHER_SIZE];
    uint8_t mle_key[IEEE802154_CIPHER_SIZE];
} ieee802154_key_t;

/* */
void dissect_ieee802154_superframe      (tvbuff_t *, packet_info *, proto_tree *, unsigned *);
void dissect_ieee802154_gtsinfo         (tvbuff_t *, packet_info *, proto_tree *, unsigned *);
void dissect_ieee802154_pendaddr        (tvbuff_t *, packet_info *, proto_tree *, unsigned *);
void dissect_ieee802154_aux_sec_header_and_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet, unsigned *offset);
void ccm_init_block(char *block, bool adata, int M, uint64_t addr, uint32_t frame_counter, uint8_t level, int ctr_val, const char *generic_nonce);
bool ccm_ctr_encrypt(const char *key, const char *iv, char *mic, char *data, int length);
bool ccm_cbc_mac(const char *key, const char *iv, const char *a, int a_len, const char *m, int m_len, char *mic);

proto_tree *ieee802154_create_hie_tree(tvbuff_t *tvb, proto_tree *tree, int hf, int ett);
proto_tree *ieee802154_create_pie_tree(tvbuff_t *tvb, proto_tree *tree, int hf, int ett);


/** Even if the FCF Security Enabled flag is set, there is no auxiliary security header present (used by Wi-SUN Netricity) */
#define IEEE802154_DISSECT_HEADER_OPTION_NO_AUX_SEC_HDR  (1 << 1)
/**
 * Dissect the IEEE 802.15.4 header starting from the FCF up to and including the Header IEs (the non-encrypted part)
 * @param tvb the IEEE 802.15.4 frame
 * @param pinfo packet info of the currently processed packet
 * @param tree current protocol tree
 * @param options bitmask of IEEE802154_DISSECT_HEADER_OPTION_XX flags
 * @param[out] created_header_tree will be set to the tree created for the header
 * @param[out] parsed_info will be set to the (wmem allocated) IEEE 802.15.4 packet information
 * @return the MHR length or 0 if an error occurred
 */
unsigned ieee802154_dissect_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned options, proto_tree **created_header_tree, ieee802154_packet **parsed_info);

/**
 * Decrypt the IEEE 802.15.4 payload starting from the Payload IEs
 *
 * If the packet is not encrypted, just return the payload.
 * @param tvb the IEEE 802.15.4 frame
 * @param mhr_len the size of the IEEE 802.15.4 header (MHR)
 * @param pinfo packet info of the currently processed packet
 * @param ieee802154_tree the tree for the IEEE 802.15.4 header/protocol
 * @param packet the IEEE 802.15.4 packet information
 * @return the plaintext payload or NULL if decryption failed
 */
tvbuff_t* ieee802154_decrypt_payload(tvbuff_t *tvb, unsigned mhr_len, packet_info *pinfo, proto_tree *ieee802154_tree, ieee802154_packet *packet);

/**
 * Dissect the IEEE 802.15.4 Payload IEs (if present)
 * @param tvb the (decrypted) IEEE 802.15.4 payload
 * @param pinfo packet info of the currently processed packet
 * @param ieee802154_tree the tree for the IEEE 802.15.4 header/protocol
 * @param packet the IEEE 802.15.4 packet information
 * @return the number of bytes dissected
 */
unsigned ieee802154_dissect_payload_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ieee802154_tree, ieee802154_packet *packet);

/**
 * Dissect the IEEE 802.15.4 frame payload (after the Payload IEs)
 * @param tvb the (decrypted) IEEE 802.15.4 frame payload (after the Payload IEs)
 * @param pinfo packet info of the currently processed packet
 * @param ieee802154_tree the tree for the IEEE 802.15.4 header/protocol
 * @param packet the IEEE 802.15.4 packet information
 * @param fcs_ok set to false if the FCS verification failed, which is used to suppress some further processing
 * @return the number of bytes dissected
 */
unsigned ieee802154_dissect_frame_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ieee802154_tree, ieee802154_packet *packet, bool fcs_ok);


/* Results for the decryption */
typedef struct {
    /* Set by decrypt_ieee802154_payload */
    unsigned char *key;  // not valid after return of decrypt_ieee802154_payload
    unsigned key_number;
    /* Set by the ieee802154_decrypt_func */
    unsigned char* rx_mic;
    unsigned* rx_mic_length;
    unsigned aux_offset;
    unsigned aux_length;
    ieee802154_decrypt_status* status;
} ieee802154_decrypt_info_t;

/** Fill key and alt_key based on the provided information from the frame and an IEEE 802.15.4 preference table entry
 * and return the number of keys set (0: none, 1: just key, 2: key and alt_key) */
typedef unsigned (*ieee802154_set_key_func) (ieee802154_packet *packet, unsigned char *key, unsigned char *alt_key, ieee802154_key_t *uat_key);
/** Decrypt the payload with the provided information */
typedef tvbuff_t* (*ieee802154_decrypt_func) (tvbuff_t *, unsigned, packet_info *, ieee802154_packet *, ieee802154_decrypt_info_t*);
/** Loop over the keys specified in the IEEE 802.15.4 preferences, try to use them with the specified set_key_func
 * and try to decrypt with the specified decrypt_func
 */
tvbuff_t *decrypt_ieee802154_payload(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *key_tree, ieee802154_packet *packet,
                                     ieee802154_decrypt_info_t *decrypt_info, ieee802154_set_key_func set_key_func, ieee802154_decrypt_func decrypt_func);


extern void register_ieee802154_mac_key_hash_handler(unsigned hash_identifier, ieee802154_set_key_func key_func);

/* Short to Extended Address Prototypes */
extern ieee802154_map_rec *ieee802154_addr_update(ieee802154_map_tab_t *, uint16_t, uint16_t, uint64_t,
        const char *, unsigned);
extern unsigned ieee802154_short_addr_hash(const void *);
extern unsigned ieee802154_long_addr_hash(const void *key);
extern gboolean ieee802154_short_addr_equal(const void *, const void *);
extern gboolean ieee802154_long_addr_equal(const void *a, const void *b);

extern bool ieee802154_short_addr_invalidate(uint16_t, uint16_t, unsigned);
extern bool ieee802154_long_addr_invalidate(uint64_t, unsigned);

extern ieee802154_map_tab_t ieee802154_map;

extern const value_string ieee802154_mpx_kmp_id_vals[];
extern const value_string zboss_page_names[];

extern unsigned ieee802154_fcs_len;

#endif /* PACKET_IEEE802154_H */
