/* pcapng.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __W_PCAPNG_H__
#define __W_PCAPNG_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

/* Option codes: 16-bit field */
#define OPT_EOFOPT           0x0000
#define OPT_COMMENT          0x0001 /**< NULL if not available */

/* Section Header block (SHB) */
#define OPT_SHB_HARDWARE     0x0002 /**< NULL if not available
                                     *     UTF-8 string containing the description of the
                                     *     hardware used to create this section.
                                     */
#define OPT_SHB_OS           0x0003 /**< NULL if not available, UTF-8 string containing the
                                     *     name of the operating system used to create this section.
                                     */
#define OPT_SHB_USERAPPL     0x0004 /**< NULL if not available, UTF-8 string containing the
                                     *     name of the application used to create this section.
                                     */

/* Interface Description block (IDB) */
#define OPT_IDB_NAME         0x0002 /**< NULL if not available, A UTF-8 string containing the name
                                     *     of the device used to capture data.
                                     *     "eth0" / "\Device\NPF_{AD1CE675-96D0-47C5-ADD0-2504B9126B68}"
                                     */
#define OPT_IDB_DESCR        0x0003 /**< NULL if not available, A UTF-8 string containing the description
                                     *     of the device used to capture data.
                                     *     "Broadcom NetXtreme" / "First Ethernet Interface"
                                     */
#define OPT_IDB_IP4ADDR      0x0004 /**< XXX: if_IPv4addr Interface network address and netmask.
                                     *     This option can be repeated multiple times within the same Interface Description Block
                                     *     when multiple IPv4 addresses are assigned to the interface.
                                     *     192 168 1 1 255 255 255 0
                                     */
#define OPT_IDB_IP6ADDR      0x0005 /* XXX: if_IPv6addr Interface network address and prefix length (stored in the last byte).
                                     *     This option can be repeated multiple times within the same Interface
                                     *     Description Block when multiple IPv6 addresses are assigned to the interface.
                                     *     2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is written (in hex) as
                                     *     "20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44 40"*/
#define OPT_IDB_MACADDR      0x0006 /* XXX: if_MACaddr  Interface Hardware MAC address (48 bits).                             */
#define OPT_IDB_EUIADDR      0x0007 /* XXX: if_EUIaddr  Interface Hardware EUI address (64 bits)                              */
#define OPT_IDB_SPEED        0x0008 /**< 0xFFFFFFFF if unknown
                                     *     Interface speed (in bps). 100000000 for 100Mbps
                                     */
#define OPT_IDB_TSRESOL      0x0009 /**< Resolution of timestamps. If the Most Significant Bit is equal to zero,
                                     *     the remaining bits indicates the resolution of the timestamp as as a
                                     *     negative power of 10 (e.g. 6 means microsecond resolution, timestamps
                                     *     are the number of microseconds since 1/1/1970). If the Most Significant Bit
                                     *     is equal to one, the remaining bits indicates the resolution has a
                                     *     negative power of 2 (e.g. 10 means 1/1024 of second).
                                     *     If this option is not present, a resolution of 10^-6 is assumed
                                     *     (i.e. timestamps have the same resolution of the standard 'libpcap' timestamps).
                                     */
#define OPT_IDB_TZONE        0x000A /* XXX: if_tzone    Time zone for GMT support (TODO: specify better). */
#define OPT_IDB_FILTER       0x000B /**< The filter (e.g. "capture only TCP traffic") used to capture traffic.
                                     *     The first byte of the Option Data keeps a code of the filter used
                                     *     (e.g. if this is a libpcap string, or BPF bytecode, and more).
                                     *     More details about this format will be presented in Appendix XXX (TODO).
                                     *     (TODO: better use different options for different fields?
                                     *     e.g. if_filter_pcap, if_filter_bpf, ...) 00 "tcp port 23 and host 10.0.0.5"
                                     */
#define OPT_IDB_OS           0x000C /**< NULL if not available, A UTF-8 string containing the name of the operating system of the
                                     *     machine in which this interface is installed.
                                     *     This can be different from the same information that can be
                                     *     contained by the Section Header Block
                                     *     (Section 3.1 (Section Header Block (mandatory))) because
                                     *     the capture can have been done on a remote machine.
                                     *     "Windows XP SP2" / "openSUSE 10.2"
                                     */
#define OPT_IDB_FCSLEN       0x000D /**< An integer value that specified the length of the
                                     *     Frame Check Sequence (in bits) for this interface.
                                     *     For link layers whose FCS length can change during time,
                                     *     the Packet Block Flags Word can be used (see Appendix A (Packet Block Flags Word))
                                     */
#define OPT_IDB_TSOFFSET     0x000E /**< XXX: A 64 bits integer value that specifies an offset (in seconds)
                                     *                     that must be added to the timestamp of each packet to obtain
                                     *                     the absolute timestamp of a packet. If the option is missing,
                                     *                     the timestamps stored in the packet must be considered absolute
                                     *                     timestamps. The time zone of the offset can be specified with the
                                     *                     option if_tzone. TODO: won't a if_tsoffset_low for fractional
                                     *                     second offsets be useful for highly syncronized capture systems?
                                     */

#define OPT_ISB_STARTTIME    0x0002
#define OPT_ISB_ENDTIME      0x0003
#define OPT_ISB_IFRECV       0x0004
#define OPT_ISB_IFDROP       0x0005
#define OPT_ISB_FILTERACCEPT 0x0006
#define OPT_ISB_OSDROP       0x0007
#define OPT_ISB_USRDELIV     0x0008

wtap_open_return_val pcapng_open(wtap *wth, int *err, gchar **err_info);
gboolean pcapng_dump_open(wtap_dumper *wdh, int *err);
int pcapng_dump_can_write_encap(int encap);

#endif
