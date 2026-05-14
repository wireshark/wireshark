/** @file
 *
 * Declarations of our own routines for writing pcap and pcapng files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <wsutil/file_compressed.h>

/* Writing pcap files */

/**
 * @brief Writes a pcap file header to the specified output stream.
 *
 * Write the file header to a dump file.
 * Returns true on success, false on failure.
 * Sets "*err" to an error code, or 0 for a short write, on failure
 *
 * @param pfile The output stream to which the header will be written.
 * @param linktype The data link type of the packets that will be captured.
 * @param snaplen The snapshot length for each packet.
 * @param ts_nsecs Indicates whether the timestamp should have nanosecond resolution.
 * @param bytes_written Pointer to a variable where the number of bytes written will be stored.
 * @param err Pointer to an integer where any error code will be stored.
 * @return true on success, false on failure.
 */
extern bool
libpcap_write_file_header(ws_cwstream* pfile, int linktype, int snaplen,
                          bool ts_nsecs, uint64_t *bytes_written, int *err);

/**
 * @brief Writes a packet to a pcap file.
 *
 * Write a record for a packet to a dump file.
 * Returns true on success, false on failure
 *
 * @param pfile The output stream for the pcap file.
 * @param sec The timestamp seconds of the packet.
 * @param usec The timestamp microseconds of the packet.
 * @param caplen The captured length of the packet.
 * @param len The original length of the packet.
 * @param pd The data of the packet.
 * @param bytes_written Pointer to store the number of bytes written.
 * @param err Pointer to store any error code.
 * @return true if the packet was successfully written, false otherwise.
 */
extern bool
libpcap_write_packet(ws_cwstream* pfile,
                     time_t sec, uint32_t usec,
                     uint32_t caplen, uint32_t len,
                     const uint8_t *pd,
                     uint64_t *bytes_written, int *err);

/* Writing pcapng files */

/**
 * @brief Write a pre-formatted pcapng block to the output stream.
 *
 * Checks if the data and length are aligned to 4 bytes, and if the block_total_length field is consistent at both ends of the block.
 *
 * @param pfile The output stream to write the block to.
 * @param data The data to be written as a pcapng block.
 * @param block_total_length The length of the data.
 * @param bytes_written Pointer to store the number of bytes written.
 * @param err Pointer to store any error encountered during writing.
 * @return true if the block was successfully written, false otherwise.
 */
extern bool
pcapng_write_block(ws_cwstream* pfile,
                   const uint8_t *data,
                   uint32_t block_total_length,
                   uint64_t *bytes_written,
                   int *err);

/**
 * @brief Write a section header block (SHB)
 */
extern bool
pcapng_write_section_header_block(ws_cwstream* pfile,  /**< Write information */
                                  GPtrArray *comments,  /**< Comments on the section, Option 1 opt_comment
                                                         * UTF-8 strings containing comments that areassociated to the current block.
                                                         */
                                  const char *hw,       /**< HW, Option 2 shb_hardware
                                                         * An UTF-8 string containing the description of the hardware  used to create this section.
                                                         */
                                  const char *os,       /**< Operating system name, Option 3 shb_os
                                                         * An UTF-8 string containing the name of the operating system used to create this section.
                                                         */
                                  const char *appname,  /**< Application name, Option 4 shb_userappl
                                                         * An UTF-8 string containing the name of the application  used to create this section.
                                                         */
                                  uint64_t section_length, /**< Length of section */
                                  uint64_t *bytes_written, /**< Number of written bytes */
                                  int *err /**< Error type */
                                  );

/**
 * @brief Writes an Interface Description Block (IDB) to a pcapng file.
 *
 * This function writes an IDB to the specified pcapng file stream, containing information about the network interface.
 *
 * @param pfile The pcapng file stream to write to.
 * @param comment A comment string for the IDB (optional).
 * @param name The name of the network interface.
 * @param descr A description of the network interface.
 * @param filter A display filter for the interface.
 * @param os The operating system on which the interface is running.
 * @param hardware The hardware description of the interface.
 * @param link_type The link type of the interface (e.g., Ethernet, Wi-Fi).
 * @param snap_len The snapshot length for packet capture.
 * @return true if the IDB was successfully written, false otherwise.
 */
extern bool
pcapng_write_interface_description_block(ws_cwstream* pfile,
                                         const char *comment,  /* OPT_COMMENT           1 */
                                         const char *name,     /* IDB_NAME              2 */
                                         const char *descr,    /* IDB_DESCRIPTION       3 */
                                         const char *filter,   /* IDB_FILTER           11 */
                                         const char *os,       /* IDB_OS               12 */
                                         const char *hardware, /* IDB_HARDWARE         15 */
                                         int link_type,
                                         int snap_len,
                                         uint64_t *bytes_written,
                                         uint64_t if_speed,     /* IDB_IF_SPEED          8 */
                                         uint8_t tsresol,       /* IDB_TSRESOL           9 */
                                         int *err);

/**
 * @brief Writes an Interface Statistics Block to a pcapng file.
 *
 * @param pfile The write context for the pcapng file.
 * @param interface_id The ID of the network interface.
 * @param bytes_written Pointer to store the number of bytes written.
 * @param comment Optional comment string (OPT_COMMENT).
 * @param isb_starttime Start time of the statistics block in 100-nanosecond intervals since January 1, 1601 (ISB_STARTTIME).
 * @param isb_endtime End time of the statistics block in 100-nanosecond intervals since January 1, 1601 (ISB_ENDTIME).
 * @param isb_ifrecv Number of packets received by the interface (ISB_IFRECV).
 * @param isb_ifdrop Number of packets dropped by the interface (ISB_IFDROP).
 * @param err Pointer to store any error code.
 * @return true if successful, false otherwise.
 */
extern bool
pcapng_write_interface_statistics_block(ws_cwstream* pfile,
                                        uint32_t interface_id,
                                        uint64_t *bytes_written,
                                        const char *comment,   /* OPT_COMMENT           1 */
                                        uint64_t isb_starttime, /* ISB_STARTTIME         2 */
                                        uint64_t isb_endtime,   /* ISB_ENDTIME           3 */
                                        uint64_t isb_ifrecv,    /* ISB_IFRECV            4 */
                                        uint64_t isb_ifdrop,    /* ISB_IFDROP            5 */
                                        int *err);

/**
 * @brief Writes an Enhanced Packet Block (EPB) to a pcapng file.
 *
 * @param pfile Pointer to the write context.
 * @param comment Optional comment for the packet.
 * @param sec Seconds part of the timestamp.
 * @param usec Microseconds part of the timestamp.
 * @param caplen Length of the captured data.
 * @param len Total length of the packet.
 * @param interface_id ID of the network interface on which the packet was received.
 * @param ts_mul Timestamp multiplier.
 * @param pd Pointer to the captured data.
 * @param flags Flags for the packet.
 * @param bytes_written Pointer to store the number of bytes written.
 * @return true if successful, false otherwise.
 */
extern bool
pcapng_write_enhanced_packet_block(ws_cwstream* pfile,
                                   const char *comment,
                                   time_t sec, uint32_t usec,
                                   uint32_t caplen, uint32_t len,
                                   uint32_t interface_id,
                                   unsigned ts_mul,
                                   const uint8_t *pd,
                                   uint32_t flags,
                                   uint64_t *bytes_written,
                                   int *err);
