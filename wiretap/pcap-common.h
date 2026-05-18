/** @file
 *
 * Declarations for code common to pcap and pcapng file formats
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for pcapng file format
 * Copyright (c) 2007 by Ulf Lamping <ulf.lamping@web.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_PCAP_COMMON_H__
#define __W_PCAP_COMMON_H__

#include "wtap.h"

/**
 * @brief Get the maximum snapshot length for a given capture encapsulation type.
 *
 * @param wtap_encap The capture encapsulation type.
 * @return unsigned The maximum snapshot length for the specified encapsulation type.
 */
extern unsigned wtap_max_snaplen_for_encap(int wtap_encap);

/**
 * @brief Reads and processes the pseudo-header for a pcap packet record.
 *
 * @param fh          File handle positioned immediately after the pcap
 *                    record header, at the start of any pseudo-header data.
 * @param is_nokia    @c true if the file is a Nokia-variant pcap file,
 *                    which uses a different pseudo-header layout.
 * @param wtap_encap  Wiretap encapsulation type for this packet, used to
 *                    select the correct pseudo-header format to read.
 * @param packet_size Total captured packet size in bytes including any
 *                    pseudo-header; used for bounds checking.
 * @param rec         wtap record structure whose pseudo-header fields are
 *                    populated by this function.
 * @param err         Set to a Wiretap or UNIX errno error code on failure.
 * @param err_info    Set to a newly allocated error detail string on failure;
 *                    the caller is responsible for freeing it.
 * @return            Number of pseudo-header bytes consumed on success;
 *                    -1 on failure, with @p err and @p err_info set.
 */
extern int pcap_process_pseudo_header(FILE_T fh, bool is_nokia,
    int wtap_encap, unsigned packet_size, wtap_rec *rec,
    int *err, char **err_info);

/**
 * @brief Performs post-read fixups on a pcap packet record.
 *
 * @param is_nokia     @c true if the file is a Nokia-variant pcap file,
 *                     which requires Nokia-specific fixups.
 * @param wtap_encap   Wiretap encapsulation type for this packet, used to
 *                     determine which fields require post-processing.
 * @param rec          wtap record structure to fix up in-place.
 * @param bytes_swapped @c true if the pcap file was written by a host with
 *                     the opposite byte order, requiring byte-swapping of
 *                     multi-byte pseudo-header fields.
 * @param fcs_len      Frame Check Sequence length in bytes as recorded in
 *                     the pcap file header; -1 if unknown.
 */
extern void pcap_read_post_process(bool is_nokia, int wtap_encap,
    wtap_rec *rec, bool bytes_swapped, int fcs_len);

/**
 * @brief Retrieves the size of the pseudo-header for a given encapsulation type and pseudo-header.
 *
 * @param encap The encapsulation type.
 * @param pseudo_header Pointer to the pseudo-header union.
 * @return The size of the pseudo-header, or 0 if not applicable.
 */
extern unsigned pcap_get_phdr_size(int encap,
    const union wtap_pseudo_header *pseudo_header);

/**
 * @brief Writes a packet header to a dump file.
 *
 * @param wdh Pointer to the wtap_dumper structure.
 * @param wtap_encap The encapsulation type of the packet.
 * @param pseudo_header Pointer to the pseudo-header of the packet.
 * @param err Pointer to an integer where any error code will be stored.
 * @return true if the header was successfully written, false otherwise.
 */
extern bool pcap_write_phdr(wtap_dumper *wdh, int wtap_encap,
    const union wtap_pseudo_header *pseudo_header, int *err);

#endif
