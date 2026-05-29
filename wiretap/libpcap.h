/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_LIBPCAP_H__
#define __W_LIBPCAP_H__

#include <wiretap/wtap.h>

/* Magic numbers in "libpcap" files.

   "libpcap" file records are written in the byte order of the host that
   writes them, and the reader is expected to fix this up.

   PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
   is a byte-swapped version of that.

   PCAP_MODIFIED_MAGIC is for Alexey Kuznetsov's modified "libpcap"
   format, as generated on Linux systems that have a "libpcap" with
   his patches, at

	http://ftp.sunet.se/pub/os/Linux/ip-routing/lbl-tools/

   applied; PCAP_SWAPPED_MODIFIED_MAGIC is the byte-swapped version.

   PCAP_IXIAMODIFIED_MAGIC is used by IXIA's lcap file format. It adds
   a length field at the end of the file header (size of all records).
   PCAP_SWAPPED_IXIAMODIFIED_MAGIC is the byte-swapped version.

   PCAP_NSEC_MAGIC is for Ulf Lamping's modified "libpcap" format,
   which uses the same common file format as PCAP_MAGIC, but the
   timestamps are saved in nanosecond resolution instead of microseconds.
   PCAP_SWAPPED_NSEC_MAGIC is a byte-swapped version of that. */
#define	PCAP_MAGIC			0xa1b2c3d4
#define	PCAP_SWAPPED_MAGIC		0xd4c3b2a1
#define	PCAP_MODIFIED_MAGIC		0xa1b2cd34
#define	PCAP_SWAPPED_MODIFIED_MAGIC	0x34cdb2a1
#define PCAP_IXIAHW_MAGIC		0x1c0001ac
#define PCAP_SWAPPED_IXIAHW_MAGIC	0xac01001c
#define PCAP_IXIASW_MAGIC		0x1c0001ab
#define PCAP_SWAPPED_IXIASW_MAGIC	0xab01001c
#define	PCAP_NSEC_MAGIC			0xa1b23c4d
#define	PCAP_SWAPPED_NSEC_MAGIC		0x4d3cb2a1

/**
 * @brief File header for a libpcap capture file, immediately following the magic number.
 */
struct pcap_hdr {
    uint16_t version_major; /**< Major version number of the libpcap file format. */
    uint16_t version_minor; /**< Minor version number of the libpcap file format. */
    int32_t  thiszone;      /**< Offset in seconds between GMT and the local timezone used for timestamps; typically 0. */
    uint32_t sigfigs;       /**< Accuracy of the timestamps in the file; typically 0. */
    uint32_t snaplen;       /**< Maximum number of octets captured per packet; packets longer than this are truncated. */
    uint32_t network;       /**< Data link type of the captured packets, as a LINKTYPE_* value. */
};

/**
 * @brief Per-packet record header in a standard libpcap capture file.
 */
struct pcaprec_hdr {
    uint32_t ts_sec;   /**< Timestamp seconds component of the packet arrival time. */
    uint32_t ts_usec;  /**< Timestamp sub-second component: microseconds for standard pcap, nanoseconds for PCAP_NSEC_MAGIC files. */
    uint32_t incl_len; /**< Number of octets of the packet actually saved in the file. */
    uint32_t orig_len; /**< Original on-wire length of the packet in octets before any truncation. */
};

/**
 * @brief Per-packet record header for Alexey Kuznetsov's modified libpcap format, extending the standard header with interface and protocol metadata.
 */
struct pcaprec_modified_hdr {
    struct pcaprec_hdr hdr; /**< Standard libpcap record header with timestamps and lengths. */
    uint32_t ifindex;       /**< Index of the capture interface in the capturing machine's interface list on which this packet arrived. */
    uint16_t protocol;      /**< Ethernet protocol type (EtherType) of the captured packet. */
    uint8_t  pkt_type;      /**< Packet type indicator (e.g. broadcast, multicast, unicast to host). */
    uint8_t  pad;           /**< Padding byte to align the header to a 4-byte boundary. */
};

/**
 * @brief Per-packet record header for the ss990915 incarnation of Alexey's modified libpcap format, as found in SuSE Linux 6.3.
 */
struct pcaprec_ss990915_hdr {
    struct pcaprec_hdr hdr; /**< Standard libpcap record header with timestamps and lengths. */
    uint32_t ifindex;       /**< Index of the capture interface in the capturing machine's interface list on which this packet arrived. */
    uint16_t protocol;      /**< Ethernet protocol type (EtherType) of the captured packet. */
    uint8_t  pkt_type;      /**< Packet type indicator (e.g. broadcast, multicast, unicast to host). */
    uint8_t  cpu1;          /**< First SMP CPU identifier; possibly used for SMP debugging. */
    uint8_t  cpu2;          /**< Second SMP CPU identifier; possibly used for SMP debugging. */
    uint8_t  pad[3];        /**< Padding bytes to align the header to a 4-byte boundary. */
};

/**
 * @brief Per-packet record header for the Nokia-variant libpcap format, as used on some Nokia firewall devices.
 */
struct pcaprec_nokia_hdr {
    struct pcaprec_hdr hdr; /**< Standard libpcap record header with timestamps and lengths. */
    uint8_t stuff[4];       /**< Device-specific metadata of unknown purpose appended by Nokia firmware. */
};

/**
 * @brief Opens a capture file using libpcap format.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Pointer to an integer that will hold any error code if an error occurs.
 * @param err_info Pointer to a char pointer that will hold any error information if an error occurs.
 * @return wtap_open_return_val The result of the open operation, indicating success or failure.
 */
wtap_open_return_val libpcap_open(wtap *wth, int *err, char **err_info);

#endif
