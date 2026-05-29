/** @file
                          observer.h  -  description
                             -------------------
    begin                : Wed Oct 29 2003
    copyright            : (C) 2003 by root
    email                : scotte[AT}netinst.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *  SPDX-License-Identifier: GPL-2.0-or-later                              *
 *                                                                         *
 ***************************************************************************/

#ifndef __NETWORK_INSTRUMENTS_H__
#define __NETWORK_INSTRUMENTS_H__

#include "wtap.h"

/**
 * @brief Opens a capture file using the observer format.
 *
 * This function attempts to open and read the header of a capture file in the observer format.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where any error code will be stored if an error occurs.
 * @param err_info Pointer to a char pointer where any error message will be stored if an error occurs.
 * @return A value indicating whether the file was successfully opened or not.
 */
wtap_open_return_val observer_open(wtap *wth, int *err, char **err_info);

/**
 * @brief Top-level file header for a Network Instruments Observer capture file.
 *
 * As of v15, @p observer_version was shortened by one byte to introduce
 * @p offset_to_first_packet_high_byte, extending the addressable range for
 * the first-packet offset to 16 MB. Files predating v15 will always have
 * @p offset_to_first_packet_high_byte set to 0.
 */
typedef struct capture_file_header
{
    char    observer_version[31];                /**< Null-terminated version string of the Observer software that created this file; maximum 30 characters. */
    uint8_t offset_to_first_packet_high_byte;    /**< High byte of the offset to the first packet, extending the range to 256 × 0x10000 = 16 MB; always 0 in files predating v15. */
    uint16_t offset_to_first_packet;             /**< Low 16 bits of the byte offset from the start of the file to the first packet record. */
    char    probe_instance;                      /**< Identifier of the probe instance that captured this file. */
    uint8_t number_of_information_elements;      /**< Number of TLV information elements appended to this header. */
} capture_file_header;

/** @brief Converts @p offset_to_first_packet in a @ref capture_file_header from little-endian to host byte order in place. */
#define CAPTURE_FILE_HEADER_FROM_LE_IN_PLACE(_capture_file_header) \
    _capture_file_header.offset_to_first_packet = GUINT16_FROM_LE((_capture_file_header).offset_to_first_packet)

/** @brief Converts @p offset_to_first_packet in a @ref capture_file_header from host byte order to little-endian in place. */
#define CAPTURE_FILE_HEADER_TO_LE_IN_PLACE(_capture_file_header) \
    _capture_file_header.offset_to_first_packet = GUINT16_TO_LE((_capture_file_header).offset_to_first_packet)

/**
 * @brief TLV (Type-Length-Value) header used for information elements appended to the Observer capture file header.
 */
typedef struct tlv_header
{
    uint16_t type;   /**< Type identifier indicating the kind of information carried in this TLV element. */
    uint16_t length; /**< Total length in bytes of this TLV element, including this header. */
} tlv_header;

/** @brief Converts all fields of a @ref tlv_header from little-endian to host byte order in place. */
#define TLV_HEADER_FROM_LE_IN_PLACE(_tlv_header) \
    (_tlv_header).type   = GUINT16_FROM_LE((_tlv_header).type); \
    (_tlv_header).length = GUINT16_FROM_LE((_tlv_header).length)

/** @brief Converts all fields of a @ref tlv_header from host byte order to little-endian in place. */
#define TLV_HEADER_TO_LE_IN_PLACE(_tlv_header) \
    (_tlv_header).type   = GUINT16_TO_LE((_tlv_header).type); \
    (_tlv_header).length = GUINT16_TO_LE((_tlv_header).length)

/*
 * TLV type values.
 *
 * Do TLVs without the 0x0100 bit set show up in packets, and
 * do TLVs with that set show up in the file header, or are
 * there two separate types of TLV?
 *
 * ALIAS_LIST contains an ASCII string (null-terminated, but
 * we can't trust that, of course) that is the pathname of
 * a file containing the alias list.  Not much use to us.
 *
 * COMMENT contains an ASCII string (null-terminated, but
 * we can't trust that, of course); in all the captures
 * I've seen, it appears to be a note about the file added
 * by Observer, not by a user.  It appears to end with 0x0a
 * 0x2e, i.e. '\n' '.'.
 *
 * REMOTE_PROBE contains, in all the captures I've seen, an
 * ASCII string (null-terminated, but we cna't trust that,
 * of course) of the form "Remote Probe [hex string]".  THe
 * hex string has 8 characters, i.e. 4 octets.
 *
 * The Observer document indicates that the types of expert information
 * packets are:
 *
 *    Network Load (markers used by Expert Time Interval and What If
 *    analysis modes)
 *
 *    Start/Stop Packet Capture marker frames (with time stamps when
 *    captures start and stop)
 *
 *    Wireless Channel Change (markers showing what channel was being
 *    currently listened to)
 *
 * That information appears to be contained in TLVs.
 */
#define INFORMATION_TYPE_ALIAS_LIST         0x0001
#define INFORMATION_TYPE_COMMENT            0x0002 /* ASCII text */
#define INFORMATION_TYPE_TIME_INFO          0x0004
#define INFORMATION_TYPE_REMOTE_PROBE       0x0005
#define INFORMATION_TYPE_NETWORK_LOAD       0x0100
#define INFORMATION_TYPE_WIRELESS           0x0101
#define INFORMATION_TYPE_CAPTURE_START_STOP 0x0104

/*
 * See in Fibre Channel captures; not seen elsewhere.
 *
 * It has 4 bytes of data in all captures I've seen.
 */
/*                                          0x0106 */

/**
 * @brief TLV payload carrying the timestamp reference timezone for an Observer capture file.
 */
typedef struct tlv_time_info {
    uint32_t time_format; /**< Timezone of the timestamps in this capture: TIME_INFO_LOCAL or TIME_INFO_GMT. */
} tlv_time_info;

#define TIME_INFO_LOCAL 0 /**< Timestamps in the capture file are in local time. */
#define TIME_INFO_GMT   1 /**< Timestamps in the capture file are in GMT. */

/** @brief Converts all fields of a @ref tlv_time_info from little-endian to host byte order in place. */
#define TLV_TIME_INFO_FROM_LE_IN_PLACE(_tlv_time_info) \
    (_tlv_time_info).time_format = GUINT32_FROM_LE((_tlv_time_info).time_format)

/** @brief Converts all fields of a @ref tlv_time_info from host byte order to little-endian in place. */
#define TLV_TIME_INFO_TO_LE_IN_PLACE(_tlv_time_info) \
    (_tlv_time_info).time_format = GUINT32_TO_LE((_tlv_time_info).time_format)


/**
 * @brief TLV payload carrying a network load snapshot sampled at the time of capture.
 *
 * The purpose of @p unknown1, @p unknown2, @p unknown3, and @p unknown4 is undetermined;
 * they may represent broadcast counts, multicast counts, or error counters. All have
 * been observed as zero in known captures.
 */
typedef struct tlv_network_load
{
    uint32_t utilization;        /**< Network utilization expressed in tenths of a percent (e.g. 10 = 1.0%). */
    uint32_t unknown1;           /**< Purpose unknown; observed as zero in all known captures. */
    uint32_t unknown2;           /**< Purpose unknown; observed as zero in all known captures. */
    uint32_t packets_per_second; /**< Number of packets per second observed on the network at time of capture. */
    uint32_t unknown3;           /**< Purpose unknown; observed as zero in all known captures. */
    uint32_t bytes_per_second;   /**< Number of bytes per second observed on the network at time of capture. */
    uint32_t unknown4;           /**< Purpose unknown; observed as zero in all known captures. */
} tlv_network_load;

/** @brief Converts all fields of a @ref tlv_network_load from little-endian to host byte order in place. */
#define TLV_NETWORK_LOAD_FROM_LE_IN_PLACE(_tlv_network_load) \
    (_tlv_network_load).utilization        = GUINT32_FROM_LE((_tlv_network_load).utilization); \
    (_tlv_network_load).unknown1           = GUINT32_FROM_LE((_tlv_network_load).unknown1); \
    (_tlv_network_load).unknown2           = GUINT32_FROM_LE((_tlv_network_load).unknown2); \
    (_tlv_network_load).packets_per_second = GUINT32_FROM_LE((_tlv_network_load).packets_per_second); \
    (_tlv_network_load).unknown3           = GUINT32_FROM_LE((_tlv_network_load).unknown3); \
    (_tlv_network_load).bytes_per_second   = GUINT32_FROM_LE((_tlv_network_load).bytes_per_second); \
    (_tlv_network_load).unknown4           = GUINT32_FROM_LE((_tlv_network_load).unknown4)

/** @brief Converts all fields of a @ref tlv_network_load from host byte order to little-endian in place. */
#define TLV_NETWORK_LOAD_TO_LE_IN_PLACE(_tlv_network_load) \
    (_tlv_network_load).utilization        = GUINT32_TO_LE((_tlv_network_load).utilization); \
    (_tlv_network_load).unknown1           = GUINT32_TO_LE((_tlv_network_load).unknown1); \
    (_tlv_network_load).unknown2           = GUINT32_TO_LE((_tlv_network_load).unknown2); \
    (_tlv_network_load).packets_per_second = GUINT32_TO_LE((_tlv_network_load).packets_per_second); \
    (_tlv_network_load).unknown3           = GUINT32_TO_LE((_tlv_network_load).unknown3); \
    (_tlv_network_load).bytes_per_second   = GUINT32_TO_LE((_tlv_network_load).bytes_per_second); \
    (_tlv_network_load).unknown4           = GUINT32_TO_LE((_tlv_network_load).unknown4)


/**
 * @brief TLV payload carrying wireless signal and channel quality metrics for a captured packet.
 *
 * @p quality takes observed values of 15, 20–27, 50–54, 208, and 213.
 * @p conditions takes observed values of 0x00, 0x02, and 0x90.
 * @p reserved takes observed values of 0x00 or 0x80; the 0x80 value
 * co-occurs with @p conditions = 0x90.
 */
typedef struct tlv_wireless_info {
    uint8_t quality;         /**< Wireless signal quality indicator; interpretation is vendor-specific. */
    uint8_t signalStrength;  /**< Raw received signal strength value reported by the wireless hardware. */
    uint8_t rate;            /**< Wireless data rate at which this packet was received. */
    uint8_t frequency;       /**< RF channel frequency on which this packet was captured. */
    uint8_t qualityPercent;  /**< Wireless signal quality expressed as a percentage (0–100). */
    uint8_t strengthPercent; /**< Received signal strength expressed as a percentage (0–100). */
    uint8_t conditions;      /**< Bitmask of wireless conditions flags (e.g. WIRELESS_WEP_SUCCESS). */
    uint8_t reserved;        /**< Reserved; observed as 0x80 when @p conditions is 0x90, otherwise 0x00. */
} tlv_wireless_info;

#define WIRELESS_WEP_SUCCESS 0x80 /**< WEP decryption of this packet succeeded. */

/**
 * @brief TLV payload recording a capture start or stop event in the Observer capture file.
 */
typedef struct tlv_capture_start_stop
{
    uint32_t start_stop; /**< Event type: START_STOP_TYPE_START when capture began, START_STOP_TYPE_STOP when capture ended. */
} tlv_capture_start_stop;

#define START_STOP_TYPE_STOP  0 /**< Capture stop event. */
#define START_STOP_TYPE_START 1 /**< Capture start event. */

/**
 * @brief Per-packet record header in a Network Instruments Observer capture file.
 */
typedef struct packet_entry_header
{
    uint32_t packet_magic;                  /**< Magic number identifying the start of a valid packet record. */
    uint32_t network_speed;                 /**< Speed of the network in bits per second at the time of capture. */
    uint16_t captured_size;                 /**< Number of bytes of the packet actually saved in the file. */
    uint16_t network_size;                  /**< Original on-wire size of the packet in bytes. */
    uint16_t offset_to_frame;              /**< Byte offset from the start of this header to the first byte of frame data. */
    uint16_t offset_to_next_packet;        /**< Byte offset from the start of this header to the start of the next packet record. */
    uint8_t  network_type;                  /**< Network type identifier indicating the link-layer medium (e.g. Ethernet, WLAN). */
    uint8_t  flags;                         /**< Bitmask of packet flags describing capture conditions for this packet. */
    uint8_t  number_of_information_elements;/**< Number of TLV information elements appended to this header. */
    uint8_t  packet_type;                   /**< Packet type classification (e.g. unicast, broadcast, multicast). */
    uint16_t errors;                        /**< Bitmask of error flags reported for this packet by the capture hardware. */
    uint16_t reserved;                      /**< Reserved; must be zero. */
    uint64_t packet_number;                 /**< Sequential packet number assigned by the capture software. */
    uint64_t original_packet_number;        /**< Original packet number from the source capture, used when merging or filtering. */
    uint64_t nano_seconds_since_2000;       /**< Packet arrival timestamp in nanoseconds since January 1, 2000 00:00:00 UTC. */
} packet_entry_header;

#define PACKET_ENTRY_HEADER_FROM_LE_IN_PLACE(_packet_entry_header) \
    (_packet_entry_header).packet_magic            = GUINT32_FROM_LE((_packet_entry_header).packet_magic); \
    (_packet_entry_header).network_speed           = GUINT32_FROM_LE((_packet_entry_header).network_speed); \
    (_packet_entry_header).captured_size           = GUINT16_FROM_LE((_packet_entry_header).captured_size); \
    (_packet_entry_header).network_size            = GUINT16_FROM_LE((_packet_entry_header).network_size); \
    (_packet_entry_header).offset_to_frame         = GUINT16_FROM_LE((_packet_entry_header).offset_to_frame); \
    (_packet_entry_header).offset_to_next_packet   = GUINT16_FROM_LE((_packet_entry_header).offset_to_next_packet); \
    (_packet_entry_header).errors                  = GUINT16_FROM_LE((_packet_entry_header).errors); \
    (_packet_entry_header).reserved                = GUINT16_FROM_LE((_packet_entry_header).reserved); \
    (_packet_entry_header).packet_number           = GUINT64_FROM_LE((_packet_entry_header).packet_number); \
    (_packet_entry_header).original_packet_number  = GUINT64_FROM_LE((_packet_entry_header).original_packet_number); \
    (_packet_entry_header).nano_seconds_since_2000 = GUINT64_FROM_LE((_packet_entry_header).nano_seconds_since_2000)

#define PACKET_ENTRY_HEADER_TO_LE_IN_PLACE(_packet_entry_header) \
    (_packet_entry_header).packet_magic            = GUINT32_TO_LE((_packet_entry_header).packet_magic); \
    (_packet_entry_header).network_speed           = GUINT32_TO_LE((_packet_entry_header).network_speed); \
    (_packet_entry_header).captured_size           = GUINT16_TO_LE((_packet_entry_header).captured_size); \
    (_packet_entry_header).network_size            = GUINT16_TO_LE((_packet_entry_header).network_size); \
    (_packet_entry_header).offset_to_frame         = GUINT16_TO_LE((_packet_entry_header).offset_to_frame); \
    (_packet_entry_header).offset_to_next_packet   = GUINT16_TO_LE((_packet_entry_header).offset_to_next_packet); \
    (_packet_entry_header).errors                  = GUINT16_TO_LE((_packet_entry_header).errors); \
    (_packet_entry_header).reserved                = GUINT16_TO_LE((_packet_entry_header).reserved); \
    (_packet_entry_header).packet_number           = GUINT64_TO_LE((_packet_entry_header).packet_number); \
    (_packet_entry_header).original_packet_number  = GUINT64_TO_LE((_packet_entry_header).original_packet_number); \
    (_packet_entry_header).nano_seconds_since_2000 = GUINT64_TO_LE((_packet_entry_header).nano_seconds_since_2000)

/*
 * Network type values.
 */
#define OBSERVER_UNDEFINED       0xFF
#define OBSERVER_ETHERNET        0x00
#define OBSERVER_TOKENRING       0x01
#define OBSERVER_FIBRE_CHANNEL   0x08
#define OBSERVER_WIRELESS_802_11 0x09

/*
 * Packet type values.
 */
#define PACKET_TYPE_DATA_PACKET               0
#define PACKET_TYPE_EXPERT_INFORMATION_PACKET 1

#endif
