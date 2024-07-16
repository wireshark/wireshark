/* packet-erf.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ERF_H__
#define __PACKET_ERF_H__

/** Gets the ERF extension header of the specified type,
 *
 * Afterindex may be NULL, or set to a int initialized to -1 and the function
 * re-called in a loop to iterate through extension headers of hdrtype type.
 *
 * Note: pinfo is assumed to be a pointer to an ERF pinfo.
 *
 * @param pinfo Packet info of ERF record to get extension header of.
 * @param hdrtype Type code of extension header. More headers bit is ignored.
 * @param afterinstance Pointer to header index to begin searching at,
 * exclusive.
 * Updated with index of extension header found. If NULL or initialized to -1
 * begin searching at the first extension header.
 *
 * @returns Pointer to extension header or NULL.
 * */
uint64_t* erf_get_ehdr(packet_info *pinfo, uint8_t hdrtype, int* afterinstance);
#endif /* packet-erf.h */
