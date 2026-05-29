/** @file
 *
 * Binary Log File (BLF) file format from Vector Informatik decoder
 * for the Wiretap library.
 *
 * Copyright (c) 2021-2025 by Dr. Lars Völker <lars.voelker@technica-engineering.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * The following was used as a reference for the file format:
  *     https://bitbucket.org/tobylorenz/vector_blf
  * The repo above includes multiple examples files as well.
  */

#ifndef __W_BLF_H__
#define __W_BLF_H__

#include "wtap.h"

/**
 * @brief Opens a BLF file.
 *
 * This function attempts to open and read the header of a BLF file, determining if it is a valid BLF file.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where any error codes will be stored.
 * @param err_info Pointer to a char pointer where any error messages will be stored.
 * @return A value indicating whether the file is a valid BLF file, not a mine, or if there was an error opening the file.
 */
wtap_open_return_val blf_open(wtap *wth, int *err, char **err_info);

/*
 * A BLF file is of the form:
 *
 *    BLF File Header
 *    Sequence of BLF objects
 *
 * A BLF object is of the form:
 *
 *    BLF Block Header
 *    Object header (object type dependent, may be empty)
 *    Object contents
 *
 * As per
 *
 *    https://gitlab.com/wireshark/wireshark/-/issues/19896#note_1967971057
 *
 * the sequence may have one (or more?) metadata objects at the beginning.
 * After those, if present, there are zero or more LOG_CONTAINER objects,
 * containing data for all subsequent objects.  An object may be split
 * between LOG_CONTAINER objects, as per
 *
 *    https://gitlab.com/wireshark/wireshark/-/issues/19377#note_1651998569
 *
 * A LOG_CONTAINER object's contents are of the form:
 *
 *    Log container header
 *    Data for contained objects.
 *
 * The data in a LOG_CONTAINER object may be compressed using zlib.
 */

#define BLF_HEADER_TYPE_DEFAULT                   1
#define BLF_HEADER_TYPE_2                         2
#define BLF_HEADER_TYPE_3                         3


#define BLF_COMPRESSION_NONE                      0
#define BLF_COMPRESSION_ZLIB                      2

#define BLF_TIMESTAMP_RESOLUTION_10US             1
#define BLF_TIMESTAMP_RESOLUTION_1NS              2

/**
 * @brief Represents a date and time value as used in BLF file headers.
 */
typedef struct blf_date {
    uint16_t year;      /**< Full calendar year (e.g. 2024). */
    uint16_t month;     /**< Month of the year: 1 = January … 12 = December. */
    uint16_t dayofweek; /**< Day of the week: 0 = Sunday … 6 = Saturday. */
    uint16_t day;       /**< Day of the month: 1–31. */
    uint16_t hour;      /**< Hour of the day in 24-hour format: 0–23. */
    uint16_t mins;      /**< Minutes: 0–59. */
    uint16_t sec;       /**< Seconds: 0–59. */
    uint16_t ms;        /**< Milliseconds: 0–999. */
} blf_date_t;


/**
 * @brief Top-level file header for a BLF (Binary Logging Format) capture file.
 */
typedef struct blf_fileheader {
    uint8_t    magic[4];              /**< File magic number; must be "LOGG". */
    uint32_t   header_length;         /**< Total length in bytes of this file header. */
    uint32_t   api_version;           /**< BLF API version, decimal encoded. */
    uint8_t    application;           /**< Numeric identifier of the application that created this file. */
    uint8_t    compression_level;     /**< Compression level applied to log container data. */
    uint8_t    application_major;     /**< Major version number of the creating application. */
    uint8_t    application_minor;     /**< Minor version number of the creating application. */
    uint64_t   len_compressed;        /**< Total size of the file data before decompression, in bytes. */
    uint64_t   len_uncompressed;      /**< Total size of the file data after decompression, in bytes. */
    uint32_t   obj_count;             /**< Total number of objects stored in this file. */
    uint32_t   application_build;     /**< Build number of the creating application. */
    blf_date_t start_date;            /**< Date and time of the first recorded event. */
    blf_date_t end_date;              /**< Date and time of the last recorded event. */
    uint32_t   restore_point_offset;  /**< File offset to the restore point used for crash recovery. */
    uint8_t    padding[];             /**< Padding bytes to align the header to the required boundary. */
} blf_fileheader_t;


/**
 * @brief Common block header preceding every object in a BLF file.
 */
typedef struct blf_blockheader {
    uint8_t  magic[4];       /**< Block magic number; must be "LOBJ". */
    uint16_t header_length;  /**< Length in bytes of this header, starting from @p magic. */
    uint16_t header_type;    /**< Header format variant identifier. */
    uint32_t object_length;  /**< Total length in bytes of the object including this header. */
    uint32_t object_type;    /**< Object type identifier indicating the payload format. */
} blf_blockheader_t;


/**
 * @brief Header for a BLF log container object, which wraps a block of compressed or uncompressed log data.
 */
typedef struct blf_logcontainerheader {
    uint16_t compression_method; /**< Compression method applied to the container payload: 0 = uncompressed, 2 = zlib. */
    uint16_t res1;               /**< Reserved; must be zero. */
    uint32_t res2;               /**< Reserved; must be zero. */
    uint32_t uncompressed_size;  /**< Size in bytes of the payload after decompression. */
    uint32_t res4;               /**< Reserved; must be zero. */
} blf_logcontainerheader_t;


/**
 * @brief Standard log object header (type 1) carrying a single timestamp.
 */
typedef struct blf_logobjectheader {
    uint32_t flags;            /**< Object flags bitmask controlling timestamp and other behavior. */
    uint16_t client_index;     /**< Index identifying the client that generated this object. */
    uint16_t object_version;   /**< Version of the object format. */
    uint64_t object_timestamp; /**< Timestamp of this object in nanoseconds relative to the measurement start. */
} blf_logobjectheader_t;


#define BLF_TS_STATUS_ORIG_TS_VALID  0x01 /**< The original timestamp field contains a valid value. */
#define BLF_TS_STATUS_SW_TS          0x02 /**< Timestamp was generated in software rather than hardware. */
#define BLF_TS_STATUS_PROTO_SPECIFIC 0x10 /**< Timestamp interpretation is protocol-specific. */


/**
 * @brief Extended log object header (type 2) carrying both an object timestamp and an original hardware timestamp.
 */
typedef struct blf_logobjectheader2 {
    uint32_t flags;              /**< Object flags bitmask controlling timestamp and other behavior. */
    uint8_t  timestamp_status;   /**< Bitmask of BLF_TS_STATUS_* flags describing the validity and source of the timestamps. */
    uint8_t  res1;               /**< Reserved; must be zero. */
    uint16_t object_version;     /**< Version of the object format. */
    uint64_t object_timestamp;   /**< Primary object timestamp in nanoseconds relative to the measurement start. */
    uint64_t original_timestamp; /**< Original hardware timestamp in nanoseconds; valid only when BLF_TS_STATUS_ORIG_TS_VALID is set. */
} blf_logobjectheader2_t;


/**
 * @brief Compact log object header (type 3) carrying a static size field and a single timestamp.
 */
typedef struct blf_logobjectheader3 {
    uint32_t flags;            /**< Object flags bitmask controlling timestamp and other behavior. */
    uint16_t static_size;      /**< Size in bytes of the static (non-variable) portion of the object payload. */
    uint16_t object_version;   /**< Version of the object format. */
    uint64_t object_timestamp; /**< Timestamp of this object in nanoseconds relative to the measurement start. */
} blf_logobjectheader3_t;


#define BLF_DIR_RX    0 /**< Frame was received. */
#define BLF_DIR_TX    1 /**< Frame was transmitted. */
#define BLF_DIR_TX_RQ 2 /**< Frame transmission was requested but not yet confirmed. */


/**
 * @brief Header for a BLF Ethernet frame object (legacy format).
 */
typedef struct blf_ethernetframeheader {
    uint8_t  src_addr[6];    /**< Source MAC address of the Ethernet frame. */
    uint16_t channel;        /**< Logical channel number on which this frame was captured. */
    uint8_t  dst_addr[6];    /**< Destination MAC address of the Ethernet frame. */
    uint16_t direction;      /**< Transfer direction: one of BLF_DIR_RX, BLF_DIR_TX, or BLF_DIR_TX_RQ. */
    uint16_t ethtype;        /**< EtherType field identifying the encapsulated protocol. */
    uint16_t tpid;           /**< Tag Protocol Identifier for VLAN-tagged frames (802.1Q TPID). */
    uint16_t tci;            /**< Tag Control Information for VLAN-tagged frames (PCP, DEI, VID). */
    uint16_t payloadlength;  /**< Length in bytes of the Ethernet payload. */
    uint64_t res;            /**< Reserved; must be zero. */
} blf_ethernetframeheader_t;

/**
 * @brief Extended header for a BLF Ethernet frame object with additional hardware metadata.
 */
typedef struct blf_ethernetframeheader_ex {
    uint16_t struct_length;   /**< Total length in bytes of this header structure. */
    uint16_t flags;           /**< Bitmask of BLF_ETHERNET_EX_* flags indicating which optional fields are valid. */
    uint16_t channel;         /**< Logical channel number on which this frame was captured. */
    uint16_t hw_channel;      /**< Hardware channel number; valid only when BLF_ETHERNET_EX_HARDWARECHANNEL is set. */
    uint64_t frame_duration;  /**< Duration of the frame on the wire in nanoseconds; valid only when BLF_ETHERNET_EX_FRAMEDURATION is set. */
    uint32_t frame_checksum;  /**< Ethernet FCS (CRC-32) of the frame. */
    uint16_t direction;       /**< Transfer direction: one of BLF_DIR_RX, BLF_DIR_TX, or BLF_DIR_TX_RQ. */
    uint16_t frame_length;    /**< Total length in bytes of the captured Ethernet frame. */
    uint32_t frame_handle;    /**< Hardware-assigned frame handle; valid only when BLF_ETHERNET_EX_FRAMEHANDLE is set. */
    uint32_t error;           /**< Error flags reported by the hardware for this frame. */
} blf_ethernetframeheader_ex_t;

#define BLF_ETHERNET_EX_RES             0x0001 /**< Reserved flag. */
#define BLF_ETHERNET_EX_HARDWARECHANNEL 0x0002 /**< The @p hw_channel field contains a valid hardware channel number. */
#define BLF_ETHERNET_EX_FRAMEDURATION   0x0004 /**< The @p frame_duration field contains a valid value. */
#define BLF_ETHERNET_EX_FRAMEHANDLE     0x0008 /**< The @p frame_handle field contains a valid value. */

/**
 * @brief Header for a BLF Ethernet receive-error event carrying raw frame bytes and error metadata.
 */
typedef struct blf_ethernet_rxerror {
    uint16_t struct_length;  /**< Total length in bytes of this header structure. */
    uint16_t channel;        /**< Logical channel number on which the error was observed. */
    uint16_t direction;      /**< Transfer direction: one of BLF_DIR_RX, BLF_DIR_TX, or BLF_DIR_TX_RQ. */
    uint16_t hw_channel;     /**< Hardware channel number on which the error was observed. */
    uint32_t frame_checksum; /**< Ethernet FCS (CRC-32) of the erroneous frame. */
    uint16_t frame_length;   /**< Number of valid raw Ethernet data bytes captured for this error event. */
    uint32_t error;          /**< Error flags reported by the hardware describing the nature of the receive error. */
} blf_ethernet_rxerror_t;


/**
 * @brief Header for a BLF WLAN frame object.
 */
typedef struct blf_wlanframeheader {
    uint16_t channel;         /**< Logical channel number on which this frame was captured. */
    uint16_t flags;           /**< WLAN-specific flags for this frame. */
    uint8_t  direction;       /**< Transfer direction: one of BLF_DIR_RX, BLF_DIR_TX, or BLF_DIR_TX_RQ. */
    uint8_t  radio_channel;   /**< RF channel number on which this frame was transmitted or received. */
    uint16_t signal_strength; /**< Received signal strength in dBm. */
    uint16_t signal_quality;  /**< Received signal quality indicator. */
    uint16_t frame_length;    /**< Total length in bytes of the captured WLAN frame. */
    uint32_t res;             /**< Reserved; must be zero. */
} blf_wlanframeheader_t;


#define BLF_CANMESSAGE_FLAG_TX   0x01 /**< Frame was transmitted (TX direction). */
#define BLF_CANMESSAGE_FLAG_NERR 0x20 /**< No error (NERR) line was active during transmission. */
#define BLF_CANMESSAGE_FLAG_WU   0x40 /**< Frame triggered a bus wake-up. */
#define BLF_CANMESSAGE_FLAG_RTR  0x80 /**< Frame is a Remote Transmission Request (RTR). */


/**
 * @brief Header for a BLF CAN message or CAN message2 object.
 */
typedef struct blf_canmessage {
    uint16_t channel; /**< Logical CAN channel number on which this message was captured. */
    uint8_t  flags;   /**< Bitmask of BLF_CANMESSAGE_FLAG_* values describing message properties. */
    uint8_t  dlc;     /**< Data Length Code indicating the number of data bytes in the payload (0–8). */
    uint32_t id;      /**< CAN message identifier; bit 31 set indicates a 29-bit extended ID. */
} blf_canmessage_t;


/**
 * @brief Trailer appended to a BLF CAN message2 object with timing and bit-count metadata.
 */
typedef struct blf_canmessage2_trailer {
    uint32_t frameLength_in_ns; /**< Duration of the CAN frame on the bus in nanoseconds. */
    uint8_t  bitCount;          /**< Total number of bits in the CAN frame including stuffing bits. */
    uint8_t  reserved1;         /**< Reserved; must be zero. */
    uint16_t reserved2;         /**< Reserved; must be zero. */
} blf_canmessage2_trailer_t;


#define BLF_CANFDMESSAGE_CANFDFLAG_EDL 0x01 /**< Extended Data Length: 0 = Classical CAN, 1 = CAN FD. */
#define BLF_CANFDMESSAGE_CANFDFLAG_BRS 0x02 /**< Bit Rate Switch: data phase transmitted at a higher bit rate. */
#define BLF_CANFDMESSAGE_CANFDFLAG_ESI 0x04 /**< Error State Indicator: transmitting node is in passive error state. */

/**
 * @brief Header for a BLF CAN FD message object.
 */
typedef struct blf_canfdmessage {
    uint16_t channel;                  /**< Logical CAN channel number on which this message was captured. */
    uint8_t  flags;                    /**< Bitmask of BLF_CANMESSAGE_FLAG_* values describing message properties. */
    uint8_t  dlc;                      /**< Data Length Code indicating the encoded payload size (0–15 for CAN FD). */
    uint32_t id;                       /**< CAN message identifier; bit 31 set indicates a 29-bit extended ID. */
    uint32_t frameLength_in_ns;        /**< Duration of the CAN FD frame on the bus in nanoseconds. */
    uint8_t  arbitration_bit_count;    /**< Number of bits in the arbitration phase of the frame. */
    uint8_t  canfdflags;               /**< Bitmask of BLF_CANFDMESSAGE_CANFDFLAG_* values (EDL, BRS, ESI). */
    uint8_t  validDataBytes;           /**< Number of valid data bytes in the payload following this header. */
    uint8_t  reservedCanFdMessage1;    /**< Reserved; must be zero. */
    uint32_t reservedCanFdMessage2;    /**< Reserved; must be zero. */
    /* Payload data bytes follow this header. */
    /* uint32_t reservedCanFdMessage3 follows the payload. */
} blf_canfdmessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanFdMessage64.h */

#define BLF_CANFDMESSAGE64_FLAG_NERR                0x000004
#define BLF_CANFDMESSAGE64_FLAG_HIGH_VOLT_WAKE_UP   0x000008
#define BLF_CANFDMESSAGE64_FLAG_REMOTE_FRAME        0x000010
#define BLF_CANFDMESSAGE64_FLAG_TX_ACK              0x000040
#define BLF_CANFDMESSAGE64_FLAG_TX_REQ              0x000080
#define BLF_CANFDMESSAGE64_FLAG_SRR                 0x000200
#define BLF_CANFDMESSAGE64_FLAG_R0                  0x000400
#define BLF_CANFDMESSAGE64_FLAG_R1                  0x000800
/* EDL 0: CAN, 1: CAN-FD*/
#define BLF_CANFDMESSAGE64_FLAG_EDL                 0x001000
#define BLF_CANFDMESSAGE64_FLAG_BRS                 0x002000
#define BLF_CANFDMESSAGE64_FLAG_ESI                 0x004000
#define BLF_CANFDMESSAGE64_FLAG_BURST               0x020000

/**
 * @brief Header for a BLF CAN FD message object with extended 64-bit channel and timing metadata.
 */
typedef struct blf_canfdmessage64 {
    uint8_t  channel;              /**< Logical CAN channel number on which this message was captured. */
    uint8_t  dlc;                  /**< Data Length Code indicating the encoded payload size (0–15 for CAN FD). */
    uint8_t  validDataBytes;       /**< Number of valid data bytes in the payload following this header. */
    uint8_t  txCount;              /**< Number of transmission attempts made for this frame. */
    uint32_t id;                   /**< CAN message identifier; bit 31 set indicates a 29-bit extended ID. */
    uint32_t frameLength_in_ns;    /**< Total duration of the CAN FD frame on the bus in nanoseconds. */
    uint32_t flags;                /**< Bitmask of BLF_CANMESSAGE_FLAG_* and BLF_CANFDMESSAGE_CANFDFLAG_* values. */
    uint32_t btrCfgArb;            /**< Bit timing register configuration for the arbitration phase. */
    uint32_t btrCfgData;           /**< Bit timing register configuration for the data phase. */
    uint32_t timeOffsetBrsNs;      /**< Time offset in nanoseconds from the start of the frame to the BRS bit. */
    uint32_t timeOffsetCrcDelNs;   /**< Time offset in nanoseconds from the start of the frame to the CRC delimiter bit. */
    uint16_t bitCount;             /**< Total number of bits in the frame including stuffing bits. */
    uint8_t  dir;                  /**< Transfer direction: one of BLF_DIR_RX, BLF_DIR_TX, or BLF_DIR_TX_RQ. */
    uint8_t  extDataOffset;        /**< Byte offset from the start of this struct to any extended data appended after the payload. */
    uint32_t crc;                  /**< CRC value of the CAN FD frame as transmitted on the bus. */
} blf_canfdmessage64_t;


/**
 * @brief Header for a BLF CAN error frame object recording a bus error event.
 */
typedef struct blf_canerror {
    uint16_t channel; /**< Logical CAN channel number on which the error was observed. */
    uint16_t length;  /**< Length in bytes of the erroneous frame data. */
} blf_canerror_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanErrorFrameExt.h */

#define BLF_CANERROREXT_FLAG_SJA                   0x01
#define BLF_CANERROREXT_FLAG_CANCORE               0x02
#define BLF_CANERROREXT_EXTECC_TX                  0x1000
#define BLF_CANERROREXT_EXTECC_NOT_ACK             0x2000
#define BLF_CANERROREXT_ECC_MEANING_BIT_ERROR      0x0
#define BLF_CANERROREXT_ECC_MEANING_FORM_ERROR     0x1
#define BLF_CANERROREXT_ECC_MEANING_STUFF_ERROR    0x2
#define BLF_CANERROREXT_ECC_MEANING_OTHER_ERROR    0x3
#define BLF_CANERROREXT_ECC_MEANING_CRC_ERROR      0x4
#define BLF_CANERROREXT_ECC_MEANING_ACKDEL_ERROR   0x5
#define BLF_CANERROREXT_ECC_MEANING_OTHER_ERROR2   0x6
#define BLF_CANERROREXT_ECC_MEANING_NACK_ERROR     0x7
#define BLF_CANERROREXT_ECC_MEANING_OVERLOAD       0x8
#define BLF_CANERROREXT_ECC_FDF_BIT_ERROR          0x9

/**
 * @brief Extended header for a BLF CAN error frame object with full error diagnostic metadata.
 */
typedef struct blf_canerrorext {
    uint16_t channel;           /**< Logical CAN channel number on which the error was observed. */
    uint16_t length;            /**< Length in bytes of the erroneous frame data. */
    uint32_t flags;             /**< Bitmask of flags describing the properties and context of the error frame. */
    uint8_t  ecc;               /**< Error Capture Code register value identifying the error type and location. */
    uint8_t  position;          /**< Bit position within the frame at which the error was detected. */
    uint8_t  dlc;               /**< Data Length Code of the erroneous frame (0–8). */
    uint8_t  reserved1;         /**< Reserved; must be zero. */
    uint32_t frameLength_in_ns; /**< Duration of the erroneous frame on the bus in nanoseconds. */
    uint32_t id;                /**< CAN message identifier of the erroneous frame; bit 31 set indicates a 29-bit extended ID. */
    uint16_t errorCodeExt;      /**< Extended error code providing additional detail about the error condition. */
    uint16_t reserved2;         /**< Reserved; must be zero. */
} blf_canerrorext_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanFdErrorFrame64.h */

#define BLF_CANERROR64_FLAG_FDF 0x01
#define BLF_CANERROR65_FLAG_BRS 0x02
#define BLF_CANERROR65_FLAG_ESI 0x04

/**
 * @brief Extended header for a BLF CAN FD error frame object with full diagnostic and timing metadata.
 */
typedef struct blf_canfderror64 {
    uint8_t  channel;              /**< Logical CAN channel number on which the error was observed. */
    uint8_t  dlc;                  /**< Data Length Code of the erroneous frame (0–15 for CAN FD). */
    uint8_t  validDataBytes;       /**< Number of valid data bytes captured from the erroneous frame payload. */
    uint8_t  ecc;                  /**< Error Capture Code register value identifying the error type and location. */
    uint16_t flags;                /**< Bitmask of flags describing the properties and context of this error frame. */
    uint16_t errorCodeExt;         /**< Extended error code providing additional detail about the error condition. */
    uint16_t extFlags;             /**< Additional extended flags with supplementary error state information. */
    uint8_t  extDataOffset;        /**< Byte offset from the start of this struct to any extended data appended after the payload. */
    uint8_t  reserved1;            /**< Reserved; must be zero. */
    uint32_t id;                   /**< CAN message identifier of the erroneous frame; bit 31 set indicates a 29-bit extended ID. */
    uint32_t frameLength_in_ns;    /**< Total duration of the erroneous CAN FD frame on the bus in nanoseconds. */
    uint32_t btrCfgArb;            /**< Bit timing register configuration for the arbitration phase. */
    uint32_t btrCfgData;           /**< Bit timing register configuration for the data phase. */
    uint32_t timeOffsetBrsNs;      /**< Time offset in nanoseconds from the start of the frame to the BRS bit. */
    uint32_t timeOffsetCrcDelNs;   /**< Time offset in nanoseconds from the start of the frame to the CRC delimiter bit. */
    uint32_t crc;                  /**< CRC value of the erroneous CAN FD frame as observed on the bus. */
    uint16_t errorPosition;        /**< Bit position within the frame at which the error was detected. */
    uint16_t reserved2;            /**< Reserved; must be zero. */
} blf_canfderror64_t;


/* CAN-XL */

#define BLF_CANXLCHANNELFRAME_FLAG_REMOTE_FRAME 0x10
#define BLF_CANXLCHANNELFRAME_FLAG_SRR          0x200
#define BLF_CANXLCHANNELFRAME_FLAG_FDF          0x1000
#define BLF_CANXLCHANNELFRAME_FLAG_BRS          0x2000
#define BLF_CANXLCHANNELFRAME_FLAG_ESI          0x4000
#define BLF_CANXLCHANNELFRAME_FLAG_XLF          0x400000
#define BLF_CANXLCHANNELFRAME_FLAG_RRS          0x800000
#define BLF_CANXLCHANNELFRAME_FLAG_SEC          0x1000000

/**
 * @brief Header for a BLF CAN XL channel frame object with full timing, arbitration, and CRC metadata.
 */
typedef struct blf_canxlchannelframe {
    uint8_t  channel;                             /**< Logical CAN channel number on which this frame was captured. */
    uint8_t  tx_count;                            /**< Number of transmission attempts made for this frame. */
    uint8_t  dir;                                 /**< Transfer direction: one of BLF_DIR_RX, BLF_DIR_TX, or BLF_DIR_TX_RQ. */
    uint8_t  res1;                                /**< Reserved; must be zero. */
    uint32_t frameLength_in_ns;                   /**< Total duration of the CAN XL frame on the bus in nanoseconds. */

    uint16_t bitCount;                            /**< Total number of bits in the frame including stuffing bits. */
    uint16_t res2;                                /**< Reserved; must be zero. */
    uint32_t frameIdentifier;                     /**< CAN XL frame identifier field. */

    uint8_t  serviceDataUnitType;                 /**< Service Data Unit (SDU) type identifying the higher-layer protocol carried in this frame. */
    uint8_t  res3;                                /**< Reserved; must be zero. */
    uint16_t dlc;                                 /**< Data Length Code indicating the number of payload bytes (0–2048 for CAN XL). */
    uint16_t dataLength;                          /**< Actual number of payload data bytes present in this frame. */
    uint16_t stuffBitCount;                       /**< Number of stuff bits inserted into the frame during encoding. */

    uint16_t prefaceCRC;                          /**< CRC value covering the CAN XL preface field. */
    uint8_t  virtualControllerAreaNetChannelID;   /**< Virtual CAN (VCAN) channel identifier associated with this frame. */
    uint8_t  res4;                                /**< Reserved; must be zero. */
    uint32_t acceptanceField;                     /**< Acceptance field value used for frame filtering. */

    uint8_t  stuffCount;                          /**< Rolling counter of stuff bits used for stuff-bit error detection. */
    uint8_t  res5;                                /**< Reserved; must be zero. */
    uint16_t res6;                                /**< Reserved; must be zero. */
    uint32_t crc;                                 /**< CRC value of the CAN XL frame as transmitted on the bus. */

    uint32_t timeOffsetBrsNs;                     /**< Time offset in nanoseconds from the start of the frame to the BRS bit. */
    uint32_t timeOffsetCrcDelNs;                  /**< Time offset in nanoseconds from the start of the frame to the CRC delimiter bit. */

    uint32_t flags;                               /**< Bitmask of flags describing the properties and state of this frame. */
    uint32_t reserved;                            /**< Reserved; must be zero. */

    uint64_t arbitrationDataBitTimingConfig;      /**< Bit timing configuration register for the arbitration phase data segment. */
    uint64_t arbitrationDataHwChannelSettings;    /**< Hardware channel settings for the arbitration phase data segment. */
    uint64_t fdPhaseBitTimingConfig;              /**< Bit timing configuration register for the CAN FD phase. */
    uint64_t fdPhaseHwChannelSettings;            /**< Hardware channel settings for the CAN FD phase. */
    uint64_t xlPhaseBitTimingConfig;              /**< Bit timing configuration register for the CAN XL phase. */
    uint64_t xlPhaseHwChannelSettings;            /**< Hardware channel settings for the CAN XL phase. */
} blf_canxlchannelframe_t;

/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayData.h */

#define BLF_FLEXRAYDATA_FRAME                       0x01
#define BLF_FLEXRAYDATA_CHANNEL_B                   0x80

/**
 * @brief Header for a BLF FlexRay data object capturing a single FlexRay frame.
 */
typedef struct blf_flexraydata {
    uint16_t channel;                   /**< Logical FlexRay channel number on which this frame was captured. */
    uint8_t  mux;                       /**< Multiplexer identifier indicating the frame's slot and cycle assignment. */
    uint8_t  len;                       /**< Length in bytes of the FlexRay frame payload. */
    uint16_t messageId;                 /**< FlexRay message identifier associated with this frame. */
    uint16_t crc;                       /**< CRC value of the FlexRay frame header as transmitted on the bus. */
    uint8_t  dir;                       /**< Transfer direction: one of BLF_DIR_RX, BLF_DIR_TX, or BLF_DIR_TX_RQ. */
    uint8_t  reservedFlexRayData1;      /**< Reserved; must be zero. */
    uint16_t reservedFlexRayData2;      /**< Reserved; must be zero. */
} blf_flexraydata_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayV6Message.h */

#define BLF_FLEXRAYMESSAGE_DIR_RX                   0x01
#define BLF_FLEXRAYMESSAGE_DIR_TX                   0x02
#define BLF_FLEXRAYMESSAGE_DIR_TX_REQ               0x04

#define BLF_FLEXRAYMESSAGE_STATE_PPI                0x01
#define BLF_FLEXRAYMESSAGE_STATE_SFI                0x02
#define BLF_FLEXRAYMESSAGE_STATE_RES_BIT2           0x04
#define BLF_FLEXRAYMESSAGE_STATE_NFI                0x08
#define BLF_FLEXRAYMESSAGE_STATE_STFI               0x10
#define BLF_FLEXRAYMESSAGE_STATE_FORMAT             0xe0

#define BLF_FLEXRAYMESSAGE_HEADER_BIT_NM            0x01
#define BLF_FLEXRAYMESSAGE_HEADER_BIT_SYNC          0x02
#define BLF_FLEXRAYMESSAGE_HEADER_BIT_RES           0x04

#define BLF_DLT_FLEXRAY_STFI                        0x08
#define BLF_DLT_FLEXRAY_SFI                         0x10
#define BLF_DLT_FLEXRAY_NFI                         0x20
#define BLF_DLT_FLEXRAY_PPI                         0x40

/**
 * @brief Header for a BLF FlexRay V6 message object with FPGA timing and frame state metadata.
 */
typedef struct blf_flexraymessage {
    uint16_t channel;                          /**< Logical FlexRay channel number on which this frame was captured. */
    uint8_t  dir;                              /**< Transfer direction: 0 = RX, 1 = TX, 2 = TX Request, 3 = internal, 4 = internal. */
    uint8_t  lowTime;                          /**< Low-phase duration measurement used for bus timing analysis. */
    uint32_t fpgaTick;                         /**< FPGA tick counter value at the time this frame was captured. */
    uint32_t fpgaTickOverflow;                 /**< Number of times the FPGA tick counter has overflowed. */
    uint32_t clientIndexFlexRayV6Message;      /**< Index identifying the client that recorded this FlexRay V6 message. */
    uint32_t clusterTime;                      /**< FlexRay cluster time at which this frame was captured, in FlexRay ticks. */
    uint16_t frameId;                          /**< FlexRay frame identifier (slot ID) of this frame. */
    uint16_t headerCrc;                        /**< CRC value of the FlexRay frame header as transmitted on the bus. */
    uint16_t frameState;                       /**< State flags describing the reception status and validity of this frame. */
    uint8_t  length;                           /**< Length in bytes of the FlexRay frame payload. */
    uint8_t  cycle;                            /**< FlexRay communication cycle counter value at the time of capture. */
    uint8_t  headerBitMask;                    /**< Bitmask of FlexRay header flags (e.g. startup, sync, null frame indicators). */
    uint8_t  reservedFlexRayV6Message1;        /**< Reserved; must be zero. */
    uint16_t reservedFlexRayV6Message2;        /**< Reserved; must be zero. */
} blf_flexraymessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayVFrReceiveMsg.h */

#define BLF_FLEXRAYRCVMSG_DIR_RX                  0x01
#define BLF_FLEXRAYRCVMSG_DIR_TX                  0x02
#define BLF_FLEXRAYRCVMSG_DIR_TX_REQ              0x04

#define BLF_FLEXRAYRCVMSG_CHANNELMASK_RES         0x00
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_A           0x01
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_B           0x02
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_AB          0x03

#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_NULL_FRAME    0x00000001
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_VALID_DATA    0x00000002
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_SYNC          0x00000004
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_STARTUP       0x00000008
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_PAYLOAD_PREAM 0x00000010
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_RES_20        0x00000020
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_ERROR         0x00000040
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_RES_80        0x00000080

/**
 * @brief Header for a BLF FlexRay received message object with dual-channel CRC and cluster metadata.
 */
typedef struct blf_flexrayrcvmessage {
    uint16_t channel;             /**< Logical FlexRay channel number on which this frame was captured. */
    uint16_t version;             /**< Version of the FlexRay received message format. */
    uint16_t channelMask;         /**< Physical channel mask: 0 = reserved, 1 = channel A, 2 = channel B, 3 = A+B. */
    uint16_t dir;                 /**< Transfer direction: 0 = RX, 1 = TX, 2 = TX Request, 3 = internal, 4 = internal; high byte reserved. */
    uint32_t clientIndex;         /**< Index identifying the client that recorded this message. */
    uint32_t clusterNo;           /**< FlexRay cluster number from which this frame originated. */
    uint16_t frameId;             /**< FlexRay frame identifier (slot ID) of this frame. */
    uint16_t headerCrc1;          /**< Header CRC computed for channel A. */
    uint16_t headerCrc2;          /**< Header CRC computed for channel B. */
    uint16_t payloadLength;       /**< Nominal payload length of the frame in 16-bit words as defined by the static segment configuration. */
    uint16_t payloadLengthValid;  /**< Number of payload bytes actually captured and valid in the payload buffer. */
    uint16_t cycle;               /**< FlexRay communication cycle counter at the time of capture; high byte reserved. */
    uint32_t tag;                 /**< Application-defined tag associated with this message. */
    uint32_t data;                /**< Application-defined data word associated with this message. */
    uint32_t frameFlags;          /**< Bitmask of FlexRay frame flags (e.g. startup, sync, null frame, payload preamble). */
    uint32_t appParameter;        /**< Application-specific parameter associated with this message. */
    /* If this is an extended message, skip 40 bytes before the payload. */
    /* Payload bytes follow. */
    /* uint16_t res3 — reserved, follows payload. */
    /* uint32_t res4 — reserved, follows res3. */
} blf_flexrayrcvmessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayVFrReceiveMsgEx.h */

/* defines see above BLF_FLEXRAYRCVMSG_* */

/**
 * @brief Extended header for a BLF FlexRay received message object with frame CRC, duration, and PDU offset metadata.
 */
typedef struct blf_flexrayrcvmessageex {
    uint16_t channel;             /**< Logical FlexRay channel number on which this frame was captured. */
    uint16_t version;             /**< Version of the FlexRay extended received message format. */
    uint16_t channelMask;         /**< Physical channel mask: 0 = reserved, 1 = channel A, 2 = channel B, 3 = A+B. */
    uint16_t dir;                 /**< Transfer direction: 0 = RX, 1 = TX, 2 = TX Request, 3 = internal, 4 = internal. */
    uint32_t clientIndex;         /**< Index identifying the client that recorded this message. */
    uint32_t clusterNo;           /**< FlexRay cluster number from which this frame originated. */
    uint16_t frameId;             /**< FlexRay frame identifier (slot ID) of this frame. */
    uint16_t headerCrc1;          /**< Header CRC computed for channel A. */
    uint16_t headerCrc2;          /**< Header CRC computed for channel B. */
    uint16_t payloadLength;       /**< Nominal payload length in 16-bit words as defined by the static segment configuration. */
    uint16_t payloadLengthValid;  /**< Number of payload bytes actually captured and valid in the payload buffer. */
    uint16_t cycle;               /**< FlexRay communication cycle counter at the time of capture. */
    uint32_t tag;                 /**< Application-defined tag associated with this message. */
    uint32_t data;                /**< Application-defined data word associated with this message. */
    uint32_t frameFlags;          /**< Bitmask of FlexRay frame flags (e.g. startup, sync, null frame, payload preamble). */
    uint32_t appParameter;        /**< Application-specific parameter associated with this message. */
    uint32_t frameCRC;            /**< CRC value of the complete FlexRay frame as transmitted on the bus. */
    uint32_t frameLengthInNs;     /**< Total duration of the FlexRay frame on the bus in nanoseconds. */
    uint16_t frameId1;            /**< Secondary frame identifier used for additional frame correlation. */
    uint16_t pduOffset;           /**< Byte offset to the start of the PDU within the frame payload. */
    uint16_t blfLogMask;          /**< Bitmask controlling which elements of this frame are logged. */
    uint16_t res1;                /**< Reserved; must be zero. */
    uint32_t res2;                /**< Reserved; must be zero. */
    uint32_t res3;                /**< Reserved; must be zero. */
    uint32_t res4;                /**< Reserved; must be zero. */
    uint32_t res5;                /**< Reserved; must be zero. */
    uint32_t res6;                /**< Reserved; must be zero. */
    uint32_t res7;                /**< Reserved; must be zero. */
    /* Payload bytes follow this header. */
} blf_flexrayrcvmessageex_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/LinMessage.h */

/**
 * @brief Header for a BLF LIN message object (legacy format) carrying up to 8 data bytes.
 */
typedef struct blf_linmessage {
    uint16_t channel;                      /**< Logical LIN channel number on which this message was captured. */
    uint8_t  id;                           /**< LIN frame identifier (0–63). */
    uint8_t  dlc;                          /**< Data Length Code indicating the number of data bytes (0–8). */
    uint8_t  data[8];                      /**< Payload data bytes of the LIN frame. */
    uint8_t  fsmId;                        /**< Identifier of the finite state machine instance that processed this frame. */
    uint8_t  fsmState;                     /**< State of the finite state machine at the time this frame was processed. */
    uint8_t  headerTime;                   /**< Duration of the LIN header in bit times. */
    uint8_t  fullTime;                     /**< Total duration of the complete LIN frame in bit times. */
    uint16_t crc;                          /**< Checksum of the LIN frame (classic or enhanced). */
    uint8_t  dir;                          /**< Transfer direction: 0 = RX, 1 = TX Receipt, 2 = TX Request. */
    uint8_t  res1;                         /**< Reserved; must be zero. */
    /* uint32_t res2 — optional trailing reserved field; may be absent. */
} blf_linmessage_t;


/**
 * @brief Header for a BLF LIN receive error event object (legacy format).
 */
typedef struct blf_linrcverror {
    uint16_t channel;                      /**< Logical LIN channel number on which the error was observed. */
    uint8_t  id;                           /**< LIN frame identifier (0–63) of the frame that produced the error. */
    uint8_t  dlc;                          /**< Data Length Code of the frame at the time of the error. */
    uint8_t  fsmId;                        /**< Identifier of the finite state machine instance that processed this frame. */
    uint8_t  fsmState;                     /**< State of the finite state machine at the time the error occurred. */
    uint8_t  headerTime;                   /**< Duration of the LIN header in bit times. */
    uint8_t  fullTime;                     /**< Total duration of the LIN frame up to the error in bit times. */
    uint8_t  stateReason;                  /**< Reason code describing why the receive error state was entered. */
    uint8_t  offendingByte;                /**< Value of the byte that caused the receive error, if applicable. */
    uint8_t  shortError;                   /**< Non-zero if a short (dominant) error was detected on the bus. */
    uint8_t  timeoutDuringDlcDetection;    /**< Non-zero if a timeout occurred while detecting the DLC. */
} blf_linrcverror_t;


/**
 * @brief Header for a BLF LIN send error event object (legacy format).
 */
typedef struct blf_linsenderror {
    uint16_t channel;    /**< Logical LIN channel number on which the send error was observed. */
    uint8_t  id;         /**< LIN frame identifier (0–63) of the frame that failed to send. */
    uint8_t  dlc;        /**< Data Length Code of the frame that failed to send. */
    uint8_t  fsmId;      /**< Identifier of the finite state machine instance that processed this frame. */
    uint8_t  fsmState;   /**< State of the finite state machine at the time the send error occurred. */
    uint8_t  headerTime; /**< Duration of the LIN header in bit times. */
    uint8_t  fullTime;   /**< Total duration of the LIN frame up to the error in bit times. */
} blf_linsenderror_t;


/**
 * @brief Header for a BLF LIN wake-up event object (legacy format).
 */
typedef struct blf_linwakeupevent {
    uint16_t channel;  /**< Logical LIN channel number on which the wake-up was detected. */
    uint8_t  signal;   /**< Wake-up signal value as observed on the bus. */
    uint8_t  external; /**< Non-zero if the wake-up was triggered by an external source. */
} blf_linwakeupevent_t;


/**
 * @brief Base event header for BLF LIN bus events, carrying start-of-frame timing and baud rate.
 */
typedef struct blf_linbusevent {
    uint64_t sof;            /**< Start-of-frame timestamp in nanoseconds relative to the measurement start. */
    uint32_t eventBaudrate;  /**< Baud rate in bits per second measured for this LIN bus event. */
    uint16_t channel;        /**< Logical LIN channel number on which this event was observed. */
    uint8_t  res1[2];        /**< Reserved; must be zero. */
} blf_linbusevent_t;


/**
 * @brief BLF LIN sync field event, extending the base bus event with break and delimiter lengths.
 */
typedef struct blf_linsynchfieldevent {
    blf_linbusevent_t linBusEvent;      /**< Base LIN bus event header with SOF timestamp and baud rate. */
    uint64_t          synchBreakLength; /**< Duration of the LIN sync break field in nanoseconds. */
    uint64_t          synchDelLength;   /**< Duration of the LIN sync delimiter field in nanoseconds. */
} blf_linsynchfieldevent_t;


/**
 * @brief BLF LIN message descriptor, extending the sync field event with frame identification and protocol metadata.
 */
typedef struct blf_linmessagedescriptor {
    blf_linsynchfieldevent_t linSynchFieldEvent;    /**< Sync field event carrying SOF, baud rate, and sync field timings. */
    uint16_t                 supplierId;            /**< LIN 2.0+ supplier identifier associated with this frame's node. */
    uint16_t                 messageId;             /**< LIN 2.0: message identifier; LIN 2.1: position index as specified in the LDF. */
    uint8_t                  configuredNodeAddress; /**< LIN 2.0+ configured node address (NAD) for the slave that owns this frame. */
    uint8_t                  id;                    /**< LIN frame identifier (0–63). */
    uint8_t                  dlc;                   /**< Data Length Code indicating the number of data bytes (0–8). */
    uint8_t                  checksumModel;         /**< Checksum model used: 0 = classic, 1 = enhanced. */
} blf_linmessagedescriptor_t;


/**
 * @brief BLF LIN data byte timestamp event, extending the message descriptor with per-byte arrival timestamps.
 */
typedef struct blf_lindatabytetimestampevent {
    blf_linmessagedescriptor_t linMessageDescriptor;    /**< Message descriptor carrying sync field, frame ID, and protocol metadata. */
    uint64_t databyteTimestamps[9];                     /**< Per-byte arrival timestamps in nanoseconds: index 0 = last header byte, indices 1–8 = data bytes 1–8. */
} blf_lindatabytetimestampevent_t;


/**
 * @brief Header for a BLF LIN message object (version 2) with extended timing and event-triggered frame metadata.
 */
typedef struct blf_linmessage2 {
    blf_lindatabytetimestampevent_t linDataByteTimestampEvent; /**< Data byte timestamp event carrying sync, descriptor, and per-byte timestamps. */
    uint8_t                         data[8];                   /**< Payload data bytes of the LIN frame. */
    uint16_t                        crc;                       /**< Checksum of the LIN frame (classic or enhanced). */
    uint8_t                         dir;                       /**< Transfer direction: 0 = RX, 1 = TX Receipt, 2 = TX Request. */
    uint8_t                         simulated;                 /**< Frame origin: 0 = real frame captured on bus, 1 = simulated frame. */
    uint8_t                         isEtf;                     /**< Event-triggered frame flag: 0 = standard frame, 1 = event-triggered frame. */
    uint8_t                         eftAssocIndex;             /**< Index of the associated unconditional frame within the event-triggered frame schedule. */
    uint8_t                         eftAssocEftId;             /**< Frame identifier of the associated event-triggered frame. */
    uint8_t                         fsmId;                     /**< Finite state machine instance identifier (obsolete). */
    uint8_t                         fsmState;                  /**< Finite state machine state at time of capture (obsolete). */
    uint8_t                         res1[3];                   /**< Reserved; must be zero. */
    /* Optional trailing fields omitted; their absence does not affect parsing:
       uint32_t respBaudrate;
       double   exactHeaderBaudrate;
       uint32_t earlyStopBitOffset;
       uint32_t earlyStopBitOffsetResponse; */
} blf_linmessage2_t;


/**
 * @brief Header for a BLF LIN CRC error event object (version 2).
 */
typedef struct blf_lincrcerror2 {
    blf_lindatabytetimestampevent_t linDataByteTimestampEvent; /**< Data byte timestamp event carrying sync, descriptor, and per-byte timestamps. */
    uint8_t                         data[8];                   /**< Payload data bytes received before the CRC error was detected. */
    uint16_t                        crc;                       /**< Erroneous checksum value received on the bus. */
    uint8_t                         dir;                       /**< Transfer direction: 0 = RX, 1 = TX Receipt, 2 = TX Request. */
    uint8_t                         fsmId;                     /**< Finite state machine instance identifier (obsolete). */
    uint8_t                         fsmState;                  /**< Finite state machine state at time of capture (obsolete). */
    uint8_t                         simulated;                 /**< Frame origin: 0 = real frame captured on bus, 1 = simulated frame. */
    uint8_t                         res1[2];                   /**< Reserved; must be zero. */
    /* Optional trailing fields omitted; their absence does not affect parsing:
       uint32_t respBaudrate;
       uint8_t  res2[4];
       double   exactHeaderBaudrate;
       uint32_t earlyStopBitOffset;
       uint32_t earlyStopBitOffsetResponse; */
} blf_lincrcerror2_t;


/**
 * @brief Header for a BLF LIN receive error event object (version 2).
 */
typedef struct blf_linrcverror2 {
    blf_lindatabytetimestampevent_t linDataByteTimestampEvent; /**< Data byte timestamp event carrying sync, descriptor, and per-byte timestamps. */
    uint8_t                         data[8];                   /**< Payload bytes captured before the receive error occurred. */
    uint8_t                         fsmId;                     /**< Finite state machine instance identifier (obsolete). */
    uint8_t                         fsmState;                  /**< Finite state machine state at time of capture (obsolete). */
    uint8_t                         stateReason;               /**< Reason code describing why the receive error state was entered. */
    uint8_t                         offendingByte;             /**< Value of the byte that caused the receive error, if applicable. */
    uint8_t                         shortError;                /**< Non-zero if a short (dominant) error was detected on the bus. */
    uint8_t                         timeoutDuringDlcDetection; /**< Non-zero if a timeout occurred while detecting the DLC. */
    uint8_t                         isEtf;                     /**< Non-zero if the error occurred within an event-triggered frame. */
    uint8_t                         hasDataBytes;              /**< Non-zero if valid data bytes were captured before the error. */
    /* Optional trailing fields omitted; their absence does not affect parsing:
       uint32_t respBaudrate;
       uint8_t  res[4];
       double   exactHeaderBaudrate;
       uint32_t earlyStopBitOffset;
       uint32_t earlyStopBitOffsetResponse; */
} blf_linrcverror2_t;


/**
 * @brief Header for a BLF LIN send error event object (version 2).
 */
typedef struct blf_linsenderror2 {
    blf_linmessagedescriptor_t linMessageDescriptor; /**< Message descriptor carrying sync field, frame ID, and protocol metadata. */
    uint64_t                   eoh;                  /**< End-of-header timestamp in nanoseconds relative to the measurement start. */
    uint8_t                    isEtf;                /**< Non-zero if the send error occurred within an event-triggered frame. */
    uint8_t                    fsmId;                /**< Finite state machine instance identifier (obsolete). */
    uint8_t                    fsmState;             /**< Finite state machine state at time of the send error (obsolete). */
    uint8_t                    res1;                 /**< Reserved; must be zero. */
    /* Optional trailing fields omitted; their absence does not affect parsing:
       uint8_t  res2[4];
       double   exactHeaderBaudrate;
       uint32_t earlyStopBitOffset; */
} blf_linsenderror2_t;


/**
 * @brief Header for a BLF LIN wake-up event object (version 2) with length validation.
 */
typedef struct blf_linwakeupevent2 {
    blf_linbusevent_t linBusEvent; /**< Base LIN bus event header with SOF timestamp and baud rate. */
    uint8_t           lengthInfo;  /**< Wake-up pulse length validity: 0 = OK, 1 = too short, 2 = too long. */
    uint8_t           signal;      /**< Wake-up signal value as observed on the bus. */
    uint8_t           external;    /**< Non-zero if the wake-up was triggered by an external source. */
    uint8_t           res;         /**< Reserved; must be zero. */
} blf_linwakeupevent2_t;


/**
 * @brief Header for a BLF LIN sleep mode event object recording a bus sleep or wake transition.
 */
typedef struct blf_linsleepmodeevent {
    uint16_t channel; /**< Logical LIN channel number on which the sleep mode event was observed. */
    uint8_t  reason;  /**< Reason code describing what caused the sleep mode transition. */
    uint8_t  flags;   /**< Bitmask of flags providing additional context about the sleep mode event. */
} blf_linsleepmodeevent_t;

#define BLF_LIN_WU_SLEEP_REASON_START_STATE         0   /* Initial state of the interface */
#define BLF_LIN_SLEEP_REASON_GO_TO_SLEEP_FRAME      1
#define BLF_LIN_SLEEP_REASON_BUS_IDLE_TIMEOUT       2
#define BLF_LIN_SLEEP_REASON_SILENT_SLEEPMODE_CMD   3   /* Command to shorten bus idle timeout */
#define BLF_LIN_WU_REASON_EXTERNAL_WAKEUP_SIG       9
#define BLF_LIN_WU_REASON_INTERNAL_WAKEUP_SIG       10
#define BLF_LIN_WU_REASON_BUS_TRAFFIC               11
#define BLF_LIN_NO_SLEEP_REASON_BUS_TRAFFIC         18  /* LIN hardware does not go into Sleep mode in spite of request to do so */


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/AppText.h */

/**
 * @brief Header for a BLF application text object carrying an embedded variable-length string.
 */
typedef struct blf_apptext {
    uint32_t source;             /**< Identifier of the source or subsystem that generated this text entry. */
    uint32_t reservedAppText1;   /**< Reserved; must be zero. */
    uint32_t textLength;         /**< Length in bytes of the text string that follows this header. */
    uint32_t reservedAppText2;   /**< Reserved; must be zero. */
} blf_apptext_t;

#define BLF_APPTEXT_COMMENT     0x00000000
#define BLF_APPTEXT_CHANNEL     0x00000001
#define BLF_APPTEXT_METADATA    0x00000002
#define BLF_APPTEXT_ATTACHMENT  0x00000003
#define BLF_APPTEXT_TRACELINE   0x00000004
#define BLF_APPTEXT_CONT        0x000000FE
#define BLF_APPTEXT_FAILED      0x000000FF

#define BLF_APPTEXT_XML_GENERAL     0x01
#define BLF_APPTEXT_XML_CHANNELS    0x02
#define BLF_APPTEXT_XML_IDENTITY    0x03

#define BLF_APPTEXT_TAG_DISS_ETHSTATUS      "blf-ethernetstatus-obj"
#define BLF_APPTEXT_TAG_DISS_ETHPHYSTATUS   "blf-ethernetphystate-obj"
#define BLF_APPTEXT_TAG_DISS_DEFAULT        "data-text-lines"
#define BLF_APPTEXT_COL_PROT_TEXT           "BLF App text"
#define BLF_APPTEXT_COL_INFO_TEXT           "Metadata"
#define BLF_APPTEXT_COL_INFO_TEXT_GENERAL   "Metadata: General"
#define BLF_APPTEXT_COL_INFO_TEXT_CHANNELS  "Metadata: Channels"
#define BLF_APPTEXT_COL_INFO_TEXT_IDENTITY  "Metadata: Identity"

#define BLF_BUSTYPE_CAN 1
#define BLF_BUSTYPE_LIN 5
#define BLF_BUSTYPE_MOST 6
#define BLF_BUSTYPE_FLEXRAY 7
#define BLF_BUSTYPE_J1708 9
#define BLF_BUSTYPE_ETHERNET 11
#define BLF_BUSTYPE_WLAN 13
#define BLF_BUSTYPE_AFDX 14

/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/EthernetStatus.h */
/**
 * @brief Header for a BLF Ethernet status object reporting the physical link state and configuration of an Ethernet channel.
 */
typedef struct blf_ethernet_status {
    uint16_t channel;         /**< Logical Ethernet channel number to which this status event applies. */
    uint16_t flags;           /**< Bitmask of flags indicating which optional fields in this record are valid. */
    uint8_t  linkStatus;      /**< Current physical link status (e.g. link up, link down). */
    uint8_t  ethernetPhy;     /**< Ethernet PHY type in use on this channel. */
    uint8_t  duplex;          /**< Duplex mode: half-duplex or full-duplex. */
    uint8_t  mdi;             /**< MDI/MDI-X configuration of the physical connector. */
    uint8_t  connector;       /**< Physical connector type used on this channel. */
    uint8_t  clockMode;       /**< Ethernet clock mode (e.g. master or slave for IEEE 802.3). */
    uint8_t  pairs;           /**< Number of wire pairs active on this link. */
    uint8_t  hardwareChannel;  /**< Hardware channel index corresponding to this logical channel. */
    uint32_t bitrate;         /**< Negotiated link bit rate in bits per second. */
    /* Version 1 and later append the following optional field:
       uint64_t linkUpDuration;  // Duration the link has been continuously up, in nanoseconds. */
} blf_ethernet_status_t;

#define BLF_ETH_STATUS_LINKSTATUS       0x0001
#define BLF_ETH_STATUS_BITRATE          0x0002
#define BLF_ETH_STATUS_ETHERNETPHY      0x0004
#define BLF_ETH_STATUS_DUPLEX           0x0008
#define BLF_ETH_STATUS_MDITYPE          0x0010
#define BLF_ETH_STATUS_CONNECTOR        0x0020
#define BLF_ETH_STATUS_CLOCKMODE        0x0040
#define BLF_ETH_STATUS_BRPAIR           0x0080
#define BLF_ETH_STATUS_HARDWARECHANNEL  0x0100
#define BLF_ETH_STATUS_LINKUPDURATION   0x0200

/**
 * @brief Header for a BLF Ethernet PHY state event object reporting a physical layer state transition.
 */
typedef struct blf_ethernet_phystate {
    uint16_t channel;         /**< Logical Ethernet channel number to which this PHY state event applies. */
    uint16_t flags;           /**< Bitmask of flags indicating which optional fields in this record are valid. */
    uint8_t  phyState;        /**< Current PHY state (e.g. idle, initializing, link ready). */
    uint8_t  phyEvent;        /**< PHY event that triggered this state change (e.g. link up, link down, error). */
    uint8_t  hardwareChannel; /**< Hardware channel index corresponding to this logical channel. */
    uint8_t  res1;            /**< Reserved; must be zero. */
} blf_ethernet_phystate_t;

#define BLF_PHY_STATE_PHYSTATE          0x0001
#define BLF_PHY_STATE_PHYEVENT          0x0002
#define BLF_PHY_STATE_HARDWARECHANNEL   0x0004


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/ObjectHeaderBase.h */

#define BLF_OBJTYPE_UNKNOWN                       0
#define BLF_OBJTYPE_CAN_MESSAGE                   1
#define BLF_OBJTYPE_CAN_ERROR                     2
#define BLF_OBJTYPE_CAN_OVERLOAD                  3
#define BLF_OBJTYPE_CAN_STATISTIC                 4
#define BLF_OBJTYPE_APP_TRIGGER                   5
#define BLF_OBJTYPE_ENV_INTEGER                   6
#define BLF_OBJTYPE_ENV_DOUBLE                    7
#define BLF_OBJTYPE_ENV_STRING                    8
#define BLF_OBJTYPE_ENV_DATA                      9
#define BLF_OBJTYPE_LOG_CONTAINER                10
#define BLF_OBJTYPE_LIN_MESSAGE                  11
#define BLF_OBJTYPE_LIN_CRC_ERROR                12
#define BLF_OBJTYPE_LIN_DLC_INFO                 13
#define BLF_OBJTYPE_LIN_RCV_ERROR                14
#define BLF_OBJTYPE_LIN_SND_ERROR                15
#define BLF_OBJTYPE_LIN_SLV_TIMEOUT              16
#define BLF_OBJTYPE_LIN_SCHED_MODCH              17
#define BLF_OBJTYPE_LIN_SYN_ERROR                18
#define BLF_OBJTYPE_LIN_BAUDRATE                 19
#define BLF_OBJTYPE_LIN_SLEEP                    20
#define BLF_OBJTYPE_LIN_WAKEUP                   21
#define BLF_OBJTYPE_MOST_SPY                     22
#define BLF_OBJTYPE_MOST_CTRL                    23
#define BLF_OBJTYPE_MOST_LIGHTLOCK               24
#define BLF_OBJTYPE_MOST_STATISTIC               25

#define BLF_OBJTYPE_FLEXRAY_DATA                 29
#define BLF_OBJTYPE_FLEXRAY_SYNC                 30
#define BLF_OBJTYPE_CAN_DRIVER_ERROR             31
#define BLF_OBJTYPE_MOST_PKT                     32
#define BLF_OBJTYPE_MOST_PKT2                    33
#define BLF_OBJTYPE_MOST_HWMODE                  34
#define BLF_OBJTYPE_MOST_REG                     35
#define BLF_OBJTYPE_MOST_GENREG                  36
#define BLF_OBJTYPE_MOST_NETSTATE                37
#define BLF_OBJTYPE_MOST_DATALOST                38
#define BLF_OBJTYPE_MOST_TRIGGER                 39
#define BLF_OBJTYPE_FLEXRAY_CYCLE                40
#define BLF_OBJTYPE_FLEXRAY_MESSAGE              41
#define BLF_OBJTYPE_LIN_CHECKSUM_INFO            42
#define BLF_OBJTYPE_LIN_SPIKE_EVENT              43
#define BLF_OBJTYPE_CAN_DRIVER_SYNC              44
#define BLF_OBJTYPE_FLEXRAY_STATUS               45
#define BLF_OBJTYPE_GPS_EVENT                    46
#define BLF_OBJTYPE_FLEXRAY_ERROR                47
#define BLF_OBJTYPE_FLEXRAY_STATUS2              48
#define BLF_OBJTYPE_FLEXRAY_STARTCYCLE           49
#define BLF_OBJTYPE_FLEXRAY_RCVMESSAGE           50
#define BLF_OBJTYPE_REALTIMECLOCK                51

#define BLF_OBJTYPE_LIN_STATISTIC                54
#define BLF_OBJTYPE_J1708_MESSAGE                55
#define BLF_OBJTYPE_J1708_VIRTUAL_MSG            56
#define BLF_OBJTYPE_LIN_MESSAGE2                 57
#define BLF_OBJTYPE_LIN_SND_ERROR2               58
#define BLF_OBJTYPE_LIN_SYN_ERROR2               59
#define BLF_OBJTYPE_LIN_CRC_ERROR2               60
#define BLF_OBJTYPE_LIN_RCV_ERROR2               61
#define BLF_OBJTYPE_LIN_WAKEUP2                  62
#define BLF_OBJTYPE_LIN_SPIKE_EVENT2             63
#define BLF_OBJTYPE_LIN_LONG_DOM_SIG             64
#define BLF_OBJTYPE_APP_TEXT                     65
#define BLF_OBJTYPE_FLEXRAY_RCVMESSAGE_EX        66
#define BLF_OBJTYPE_MOST_STATISTICEX             67
#define BLF_OBJTYPE_MOST_TXLIGHT                 68
#define BLF_OBJTYPE_MOST_ALLOCTAB                69
#define BLF_OBJTYPE_MOST_STRESS                  70
#define BLF_OBJTYPE_ETHERNET_FRAME               71
#define BLF_OBJTYPE_SYS_VARIABLE                 72
#define BLF_OBJTYPE_CAN_ERROR_EXT                73
#define BLF_OBJTYPE_CAN_DRIVER_ERROR_EXT         74
#define BLF_OBJTYPE_LIN_LONG_DOM_SIG2            75
#define BLF_OBJTYPE_MOST_150_MESSAGE             76
#define BLF_OBJTYPE_MOST_150_PKT                 77
#define BLF_OBJTYPE_MOST_ETHERNET_PKT            78
#define BLF_OBJTYPE_MOST_150_MESSAGE_FRAGMENT    79
#define BLF_OBJTYPE_MOST_150_PKT_FRAGMENT        80
#define BLF_OBJTYPE_MOST_ETHERNET_PKT_FRAGMENT   81
#define BLF_OBJTYPE_MOST_SYSTEM_EVENT            82
#define BLF_OBJTYPE_MOST_150_ALLOCTAB            83
#define BLF_OBJTYPE_MOST_50_MESSAGE              84
#define BLF_OBJTYPE_MOST_50_PKT                  85
#define BLF_OBJTYPE_CAN_MESSAGE2                 86
#define BLF_OBJTYPE_LIN_UNEXPECTED_WAKEUP        87
#define BLF_OBJTYPE_LIN_SHORT_OR_SLOW_RESPONSE   88
#define BLF_OBJTYPE_LIN_DISTURBANCE_EVENT        89
#define BLF_OBJTYPE_SERIAL_EVENT                 90
#define BLF_OBJTYPE_OVERRUN_ERROR                91
#define BLF_OBJTYPE_EVENT_COMMENT                92
#define BLF_OBJTYPE_WLAN_FRAME                   93
#define BLF_OBJTYPE_WLAN_STATISTIC               94
#define BLF_OBJTYPE_MOST_ECL                     95
#define BLF_OBJTYPE_GLOBAL_MARKER                96
#define BLF_OBJTYPE_AFDX_FRAME                   97
#define BLF_OBJTYPE_AFDX_STATISTIC               98
#define BLF_OBJTYPE_KLINE_STATUSEVENT            99
#define BLF_OBJTYPE_CAN_FD_MESSAGE              100
#define BLF_OBJTYPE_CAN_FD_MESSAGE_64           101
#define BLF_OBJTYPE_ETHERNET_RX_ERROR           102
#define BLF_OBJTYPE_ETHERNET_STATUS             103
#define BLF_OBJTYPE_CAN_FD_ERROR_64             104

#define BLF_OBJTYPE_AFDX_STATUS                 106
#define BLF_OBJTYPE_AFDX_BUS_STATISTIC          107

#define BLF_OBJTYPE_AFDX_ERROR_EVENT            109
#define BLF_OBJTYPE_A429_ERROR                  110
#define BLF_OBJTYPE_A429_STATUS                 111
#define BLF_OBJTYPE_A429_BUS_STATISTIC          112
#define BLF_OBJTYPE_A429_MESSAGE                113
#define BLF_OBJTYPE_ETHERNET_STATISTIC          114
#define BLF_OBJTYPE_RESERVED5                   115
#define BLF_OBJTYPE_RESERVED6                   116
#define BLF_OBJTYPE_RESERVED7                   117
#define BLF_OBJTYPE_TEST_STRUCTURE              118
#define BLF_OBJTYPE_DIAG_REQUEST_INTERPRETATION 119
#define BLF_OBJTYPE_ETHERNET_FRAME_EX           120
#define BLF_OBJTYPE_ETHERNET_FRAME_FORWARDED    121
#define BLF_OBJTYPE_ETHERNET_ERROR_EX           122
#define BLF_OBJTYPE_ETHERNET_ERROR_FORWARDED    123
#define BLF_OBJTYPE_FUNCTION_BUS                124
#define BLF_OBJTYPE_DATA_LOST_BEGIN             125
#define BLF_OBJTYPE_DATA_LOST_END               126
#define BLF_OBJTYPE_WATER_MARK_EVENT            127
#define BLF_OBJTYPE_TRIGGER_CONDITION           128
#define BLF_OBJTYPE_CAN_SETTING_CHANGED         129
#define BLF_OBJTYPE_DISTRIBUTED_OBJECT_MEMBER   130
#define BLF_OBJTYPE_ATTRIBUTE_EVENT             131
#define BLF_OBJTYPE_DISTRIBUTED_OBJECT_CHANGE   132
#define BLF_OBJTYPE_ETHERNET_PHY_STATE          133
#define BLF_OBJTYPE_MACSEC_STATUS               134

#define BLF_OBJTYPE_10BASET1S_STATUS            136
#define BLF_OBJTYPE_10BASET1S_STATISTIC         137
#define BLF_OBJTYPE_TUNNEL_PROTO_DECODER_EVENT  138
#define BLF_OBJTYPE_CAN_XL_CHANNEL_FRAME        139
#define BLF_OBJTYPE_CAN_XL_CHANNEL_ERRORFRAME   140


#endif

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
