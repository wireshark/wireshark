/** @file
 *
 * Copyright (c) 2003 Endace Technology Ltd, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This software and documentation has been developed by Endace Technology Ltd.
 * along with the DAG PCI network capture cards. For further information please
 * visit https://www.endace.com/.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __W_ERF_H__
#define __W_ERF_H__

#include <glib.h>
#include <wiretap/wtap.h>
#include "ws_symbol_export.h"

#define ERF_POPULATE_SUCCESS 1
#define ERF_POPULATE_ALREADY_POPULATED 0
#define ERF_POPULATE_FAILED -1

#define ERF_MAX_INTERFACES 8

/*
 * Private data for ERF files and LINKTYPE_ERF packets in pcap and pcapng.
 */
struct erf_private {
  GHashTable* if_map;
  GHashTable* anchor_map;
  uint64_t implicit_host_id;
  uint64_t capture_gentime;
  uint64_t host_gentime;
};

#define MIN_RECORDS_FOR_ERF_CHECK 3
#define RECORDS_FOR_ERF_CHECK 20
#define FCS_BITS	32
/*Configurable through ERF_HOST_ID environment variable */
#define ERF_WS_DEFAULT_HOST_ID 0

wtap_open_return_val erf_open(wtap *wth, int *err, char **err_info);

#endif /* __W_ERF_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
