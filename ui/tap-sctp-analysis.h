/** @file
 *
 * Copyright 2004-2013, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_SCTP_ANALYSIS_H__
#define __TAP_SCTP_ANALYSIS_H__

#include <stdbool.h>
#include <epan/dissectors/packet-sctp.h>
#include <epan/address.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CHUNK_TYPE_LENGTH	      1
#define CHUNK_FLAGS_LENGTH	      1
#define CHUNK_LENGTH_LENGTH	      2

#define CHUNK_HEADER_OFFSET	      0
#define CHUNK_TYPE_OFFSET	      CHUNK_HEADER_OFFSET
#define CHUNK_FLAGS_OFFSET	      (CHUNK_TYPE_OFFSET + CHUNK_TYPE_LENGTH)
#define CHUNK_LENGTH_OFFSET	      (CHUNK_FLAGS_OFFSET + CHUNK_FLAGS_LENGTH)
#define CHUNK_VALUE_OFFSET	      (CHUNK_LENGTH_OFFSET + CHUNK_LENGTH_LENGTH)

#define INIT_CHUNK_INITIATE_TAG_LENGTH		     4
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH	     4
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH 2
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH  2


#define INIT_CHUNK_INITIATE_TAG_OFFSET		     CHUNK_VALUE_OFFSET
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET	     (INIT_CHUNK_INITIATE_TAG_OFFSET + \
						      INIT_CHUNK_INITIATE_TAG_LENGTH )
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET (INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET + \
						      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH )
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET  (INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET + \
						      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH )
#define INIT_CHUNK_INITIAL_TSN_OFFSET		     (INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET + \
						      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH )

#define DATA_CHUNK_TSN_LENGTH	      4
#define DATA_CHUNK_TSN_OFFSET	      (CHUNK_VALUE_OFFSET + 0)
#define DATA_CHUNK_STREAM_ID_OFFSET   (DATA_CHUNK_TSN_OFFSET + DATA_CHUNK_TSN_LENGTH)
#define DATA_CHUNK_STREAM_ID_LENGTH   2
#define DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH 2
#define DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH 4
#define I_DATA_CHUNK_RESERVED_LENGTH 2
#define I_DATA_CHUNK_MID_LENGTH 4
#define I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH 4
#define I_DATA_CHUNK_FSN_LENGTH 4
#define I_DATA_CHUNK_RESERVED_OFFSET  (DATA_CHUNK_STREAM_ID_OFFSET + \
                                       DATA_CHUNK_STREAM_ID_LENGTH)
#define I_DATA_CHUNK_MID_OFFSET       (I_DATA_CHUNK_RESERVED_OFFSET + \
                                       I_DATA_CHUNK_RESERVED_LENGTH)
#define I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET (I_DATA_CHUNK_MID_OFFSET + \
                                                 I_DATA_CHUNK_MID_LENGTH)
#define I_DATA_CHUNK_FSN_OFFSET       (I_DATA_CHUNK_MID_OFFSET + \
                                       I_DATA_CHUNK_MID_LENGTH)
#define I_DATA_CHUNK_PAYLOAD_OFFSET   (I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_OFFSET + \
                                       I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define DATA_CHUNK_HEADER_LENGTH      (CHUNK_HEADER_LENGTH + \
				       DATA_CHUNK_TSN_LENGTH + \
				       DATA_CHUNK_STREAM_ID_LENGTH + \
				       DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH + \
				       DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define I_DATA_CHUNK_HEADER_LENGTH    (CHUNK_HEADER_LENGTH + \
                                       DATA_CHUNK_TSN_LENGTH + \
                                       DATA_CHUNK_STREAM_ID_LENGTH + \
                                       I_DATA_CHUNK_RESERVED_LENGTH + \
                                       I_DATA_CHUNK_MID_LENGTH +\
                                       I_DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define MAX_ADDRESS_LEN		       47

#define SCTP_ABORT_CHUNK_T_BIT	      0x01

#define PARAMETER_TYPE_LENGTH		 2
#define PARAMETER_LENGTH_LENGTH		 2
#define PARAMETER_HEADER_LENGTH		 (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET		 0
#define PARAMETER_TYPE_OFFSET		 PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET		 (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET		 (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4ADDRESS_PARAMETER_ID	     0x0005
#define IPV6ADDRESS_PARAMETER_ID	     0x0006

#define SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH	4
#define SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET (CHUNK_VALUE_OFFSET + 0)
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH 4
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET (SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + \
						 SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH)

#define INIT_CHUNK_INITIAL_TSN_LENGTH		     4
#define INIT_CHUNK_FIXED_PARAMETERS_LENGTH	     (INIT_CHUNK_INITIATE_TAG_LENGTH + \
						      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH + \
						      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH + \
						      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH + \
						      INIT_CHUNK_INITIAL_TSN_LENGTH)
#define CHUNK_HEADER_LENGTH	      (CHUNK_TYPE_LENGTH + \
				       CHUNK_FLAGS_LENGTH + \
				       CHUNK_LENGTH_LENGTH)
#define INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET  (INIT_CHUNK_INITIAL_TSN_OFFSET + \
						      INIT_CHUNK_INITIAL_TSN_LENGTH )

/* The below value is 255 */
#define NUM_CHUNKS  0x100

/* This variable is used as an index into arrays
 * which store the cumulative information corresponding
 * all chunks with Chunk Type greater > 16
 * The value for the below variable is 17
 */
#define OTHER_CHUNKS_INDEX	0xfe

/* VNB */
/* This variable stores the maximum chunk type value
 * that can be associated with a sctp chunk.
 */
#define MAX_SCTP_CHUNK_TYPE 256

/**
 * @brief Represents a group of TSNs transmitted in a single SCTP packet.
 */
typedef struct _tsn {
    uint32_t     frame_number;  /**< Wireshark frame number of the packet containing these TSNs. */
    uint32_t     secs;          /**< Absolute timestamp seconds component. */
    uint32_t     usecs;         /**< Absolute timestamp microseconds component. */
    address      src;           /**< Source address of the packet. */
    address      dst;           /**< Destination address of the packet. */
    uint32_t     first_tsn;     /**< Lowest TSN number present in this packet. */
    GList       *tsns;          /**< List of individual TSN entries carried in this packet. */
} tsn_t;


/**
 * @brief Transient per-packet info collected during SCTP dissection before a full association record exists.
 */
typedef struct _sctp_tmp_info {
    uint16_t assoc_id;           /**< Temporary association identifier assigned during dissection. */
    uint16_t direction;          /**< Packet direction relative to the association endpoints. */
    address  src;                /**< Source address of the SCTP packet. */
    address  dst;                /**< Destination address of the SCTP packet. */
    uint16_t port1;              /**< Source port number. */
    uint16_t port2;              /**< Destination port number. */
    uint32_t verification_tag1;  /**< Verification tag for endpoint 1. */
    uint32_t verification_tag2;  /**< Verification tag for endpoint 2. */
    uint32_t initiate_tag;       /**< Initiate tag extracted from the INIT or INIT-ACK chunk. */
    uint32_t n_tvbs;             /**< Number of tvbuffs referenced by this packet. */
} sctp_tmp_info_t;


/**
 * @brief Records verification tags and initial TSNs from an INIT/INIT-ACK collision.
 */
typedef struct _sctp_init_collision {
    uint32_t init_vtag;        /**< Initiate tag carried in the INIT chunk. */
    uint32_t initack_vtag;     /**< Initiate tag carried in the INIT-ACK chunk. */
    uint32_t init_min_tsn;     /**< Initial TSN carried in the INIT chunk. */
    uint32_t initack_min_tsn;  /**< Initial TSN carried in the INIT-ACK chunk. */
    bool     init:1;           /**< True if an INIT chunk has been observed for this collision. */
    bool     initack:1;        /**< True if an INIT-ACK chunk has been observed for this collision. */
} sctp_init_collision_t;


/**
 * @brief A sortable summary record for a single TSN, used when ordering TSNs for graph rendering.
 */
struct tsn_sort {
    uint32_t tsnumber;    /**< Transmission Sequence Number value. */
    uint32_t secs;        /**< Timestamp seconds component of the packet carrying this TSN. */
    uint32_t usecs;       /**< Timestamp microseconds component of the packet carrying this TSN. */
    uint32_t offset;      /**< Byte offset of this TSN's data within the stream. */
    uint32_t length;      /**< Length of the data chunk associated with this TSN in bytes. */
    uint32_t framenumber; /**< Wireshark frame number of the packet carrying this TSN. */
};

/**
 * @brief Tracks per-address chunk counts for one direction of an SCTP association.
 */
typedef struct _sctp_addr_chunk {
    uint32_t  direction;                         /**< Direction this record applies to (endpoint 1 or 2). */
    address   addr;                              /**< The peer address this record tracks. */
    /* The array is initialized to MAX_SCTP_CHUNK_TYPE
     * so that there is no memory overwrite
     * when accessed using sctp chunk type as index.
     */
    uint32_t  addr_count[MAX_SCTP_CHUNK_TYPE];   /**< Per-chunk-type packet count for this address, indexed by SCTP chunk type. */
} sctp_addr_chunk;

/**
 * @brief Complete statistics and metadata record for a single SCTP association.
 */
typedef struct _sctp_assoc_info {
    uint16_t  assoc_id;                          /**< Unique identifier for this association within the capture. */
    address   src;                               /**< Source address of the association's first observed packet. */
    address   dst;                               /**< Destination address of the association's first observed packet. */
    uint16_t  port1;                             /**< Port number of endpoint 1. */
    uint16_t  port2;                             /**< Port number of endpoint 2. */
    uint32_t  verification_tag1;                 /**< Verification tag used by endpoint 1. */
    uint32_t  verification_tag2;                 /**< Verification tag used by endpoint 2. */
    uint32_t  initiate_tag;                      /**< Initiate tag from the INIT chunk that opened this association. */
    uint32_t  n_tvbs;                            /**< Total number of tvbuffs referenced across all packets. */
    GList    *addr1;                             /**< List of additional addresses advertised by endpoint 1. */
    GList    *addr2;                             /**< List of additional addresses advertised by endpoint 2. */
    uint16_t  instream1;                         /**< Number of inbound streams requested by endpoint 1. */
    uint16_t  outstream1;                        /**< Number of outbound streams requested by endpoint 1. */
    uint16_t  instream2;                         /**< Number of inbound streams requested by endpoint 2. */
    uint16_t  outstream2;                        /**< Number of outbound streams requested by endpoint 2. */
    uint32_t  n_adler32_calculated;              /**< Number of packets for which an Adler-32 checksum was calculated. */
    uint32_t  n_adler32_correct;                 /**< Number of packets whose Adler-32 checksum was correct. */
    uint32_t  n_crc32c_calculated;               /**< Number of packets for which a CRC-32c checksum was calculated. */
    uint32_t  n_crc32c_correct;                  /**< Number of packets whose CRC-32c checksum was correct. */
    char      checksum_type[8];                  /**< String identifying the checksum algorithm in use (e.g., "CRC32C"). */
    uint32_t  n_checksum_errors;                 /**< Number of packets with checksum errors. */
    uint32_t  n_bundling_errors;                 /**< Number of chunk bundling errors detected. */
    uint32_t  n_padding_errors;                  /**< Number of chunk padding errors detected. */
    uint32_t  n_length_errors;                   /**< Number of chunk length field errors detected. */
    uint32_t  n_value_errors;                    /**< Number of chunk value field errors detected. */
    uint32_t  n_data_chunks;                     /**< Total number of DATA chunks across both endpoints. */
    uint32_t  n_forward_chunks;                  /**< Total number of FORWARD-TSN chunks across both endpoints. */
    uint32_t  n_forward_chunks_ep1;              /**< Number of FORWARD-TSN chunks sent by endpoint 1. */
    uint32_t  n_forward_chunks_ep2;              /**< Number of FORWARD-TSN chunks sent by endpoint 2. */
    uint32_t  n_data_bytes;                      /**< Total payload bytes across all DATA chunks. */
    uint32_t  n_packets;                         /**< Total number of SCTP packets in the association. */
    uint32_t  n_data_chunks_ep1;                 /**< Number of DATA chunks sent by endpoint 1. */
    uint32_t  n_data_bytes_ep1;                  /**< Payload bytes in DATA chunks sent by endpoint 1. */
    uint32_t  n_data_chunks_ep2;                 /**< Number of DATA chunks sent by endpoint 2. */
    uint32_t  n_data_bytes_ep2;                  /**< Payload bytes in DATA chunks sent by endpoint 2. */
    uint32_t  n_sack_chunks_ep1;                 /**< Number of SACK chunks sent by endpoint 1. */
    uint32_t  n_sack_chunks_ep2;                 /**< Number of SACK chunks sent by endpoint 2. */
    uint32_t  n_array_tsn1;                      /**< Number of TSN entries recorded for endpoint 1. */
    uint32_t  n_array_tsn2;                      /**< Number of TSN entries recorded for endpoint 2. */
    uint32_t  max_window1;                       /**< Maximum advertised receiver window (rwnd) seen from endpoint 1. */
    uint32_t  max_window2;                       /**< Maximum advertised receiver window (rwnd) seen from endpoint 2. */
    uint32_t  arwnd1;                            /**< Current advertised receiver window for endpoint 1. */
    uint32_t  arwnd2;                            /**< Current advertised receiver window for endpoint 2. */
    bool      init:1;                            /**< True if an INIT chunk has been observed for this association. */
    bool      initack:1;                         /**< True if an INIT-ACK chunk has been observed for this association. */
    bool      firstdata:1;                       /**< True if the first DATA chunk has been observed. */
    bool      init_collision:1;                  /**< True if an INIT collision (simultaneous open) was detected. */
    uint16_t  initack_dir;                       /**< Direction from which the INIT-ACK was received. */
    uint16_t  direction;                         /**< Current packet direction relative to the association endpoints. */
    uint32_t  min_secs;                          /**< Seconds component of the earliest packet timestamp. */
    uint32_t  min_usecs;                         /**< Microseconds component of the earliest packet timestamp. */
    uint32_t  max_secs;                          /**< Seconds component of the latest packet timestamp. */
    uint32_t  max_usecs;                         /**< Microseconds component of the latest packet timestamp. */
    uint32_t  min_tsn1;                          /**< Lowest TSN observed from endpoint 1. */
    uint32_t  min_tsn2;                          /**< Lowest TSN observed from endpoint 2. */
    uint32_t  max_tsn1;                          /**< Highest TSN observed from endpoint 1. */
    uint32_t  max_tsn2;                          /**< Highest TSN observed from endpoint 2. */
    uint32_t  max_bytes1;                        /**< Maximum bytes in flight observed from endpoint 1. */
    uint32_t  max_bytes2;                        /**< Maximum bytes in flight observed from endpoint 2. */
    sctp_init_collision_t *dir1;                 /**< INIT collision record for the direction towards endpoint 1, or NULL. */
    sctp_init_collision_t *dir2;                 /**< INIT collision record for the direction towards endpoint 2, or NULL. */
    GSList   *min_max;                           /**< List of min/max byte-in-flight samples for graph rendering. */
    GList    *frame_numbers;                     /**< List of all frame numbers belonging to this association. */
    GList    *tsn1;                              /**< Chronological list of @ref tsn_t records from endpoint 1. */
    GPtrArray *sort_tsn1;                        /**< Pointer array of @ref tsn_sort records from endpoint 1, sorted by TSN. */
    GPtrArray *sort_sack1;                       /**< Pointer array of SACK sort records from endpoint 1, sorted by TSN. */
    GList    *sack1;                             /**< Chronological list of SACK records from endpoint 1. */
    GList    *tsn2;                              /**< Chronological list of @ref tsn_t records from endpoint 2. */
    GPtrArray *sort_tsn2;                        /**< Pointer array of @ref tsn_sort records from endpoint 2, sorted by TSN. */
    GPtrArray *sort_sack2;                       /**< Pointer array of SACK sort records from endpoint 2, sorted by TSN. */
    GList    *sack2;                             /**< Chronological list of SACK records from endpoint 2. */
    bool      check_address;                     /**< True if address validation should be performed for this association. */
    GList    *error_info_list;                   /**< List of @ref sctp_error_info_t records describing detected errors. */
    /* The array is initialized to MAX_SCTP_CHUNK_TYPE
     * so that there is no memory overwrite
     * when accessed using sctp chunk type as index.
     */
    uint32_t  chunk_count[MAX_SCTP_CHUNK_TYPE];      /**< Total chunk count indexed by SCTP chunk type. */
    uint32_t  ep1_chunk_count[MAX_SCTP_CHUNK_TYPE];  /**< Per-chunk-type count for chunks sent by endpoint 1. */
    uint32_t  ep2_chunk_count[MAX_SCTP_CHUNK_TYPE];  /**< Per-chunk-type count for chunks sent by endpoint 2. */
    GList    *addr_chunk_count;                  /**< List of @ref sctp_addr_chunk records with per-address chunk counts. */
} sctp_assoc_info_t;

/**
 * @brief Describes a single protocol error detected within an SCTP chunk.
 */
typedef struct _sctp_error_info {
    uint32_t     frame_number;    /**< Frame number of the packet in which the error was detected. */
    char         chunk_info[200]; /**< Human-readable string describing the chunk context of the error. */
    const char  *info_text;       /**< Pointer to a static string with a detailed error description. */
} sctp_error_info_t;

/**
 * @brief Top-level container holding information about all SCTP associations found in a capture.
 */
typedef struct _sctp_allassocs_info {
    uint32_t  sum_tvbs;           /**< Total number of tvbuffs across all associations. */
    GList    *assoc_info_list;    /**< List of @ref sctp_assoc_info_t records, one per detected association. */
    bool      is_registered;      /**< True if the SCTP tap listener is currently registered. */
    GList    *children;           /**< List of child UI widgets or windows associated with this tap. */
} sctp_allassocs_info_t;



/**
 * @brief Registers a tap listener for SCTP statistics.
 *
 * This function registers a tap listener for SCTP statistics, allowing for the collection and display of SCTP-related data in Wireshark.
 */
void register_tap_listener_sctp_stat(void);

/**
 * @brief Gets the SCTP statistics information.
 * @return Pointer to the SCTP statistics information.
 */
const sctp_allassocs_info_t* sctp_stat_get_info(void);

/**
 * @brief Scans the SCTP statistics.
 */
void sctp_stat_scan(void);

/**
 * @brief Removes the SCTP statistics tap listener.
 */
void remove_tap_listener_sctp_stat(void);

/**
 * @brief Retrieves SCTP association information based on the given association ID.
 *
 * @param assoc_id The ID of the SCTP association to retrieve information for.
 * @return Pointer to the SCTP association information, or NULL if not found.
 */
const sctp_assoc_info_t* get_sctp_assoc_info(uint16_t assoc_id);

/**
 * @brief Retrieves information about the currently selected SCTP association.
 *
 * This function returns a pointer to the sctp_assoc_info_t structure representing
 * the SCTP association that is currently selected in the user interface.
 *
 * @return Pointer to the selected SCTP association info, or NULL if none is selected.
 */
const sctp_assoc_info_t* get_selected_assoc(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_SCTP_ANALYSIS_H__ */
