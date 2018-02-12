/* packet-tftp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TFTP_H__
#define __PACKET_TFTP_H__

#include <epan/packet.h>

/* When export file data, store list of separate blocks */
typedef struct file_block_t {
  void *data;
  guint length;
} file_block_t;

#endif /* __PACKET_TFTP_H__ */
