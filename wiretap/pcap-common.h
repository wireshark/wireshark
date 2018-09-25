/* pcap-common.h
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

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

extern guint wtap_max_snaplen_for_encap(int wtap_encap);

extern int pcap_process_pseudo_header(FILE_T fh, int file_type, int wtap_encap,
    guint packet_size, wtap_rec *rec, int *err, gchar **err_info);

extern void pcap_read_post_process(int file_type, int wtap_encap,
    wtap_rec *rec, guint8 *pd, gboolean bytes_swapped, int fcs_len);

extern int pcap_get_phdr_size(int encap,
    const union wtap_pseudo_header *pseudo_header);

extern gboolean pcap_write_phdr(wtap_dumper *wdh, int wtap_encap,
    const union wtap_pseudo_header *pseudo_header, int *err);

#endif
