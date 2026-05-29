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

#include <wiretap/wtap.h>

#define ERF_POPULATE_SUCCESS 1
#define ERF_POPULATE_ALREADY_POPULATED 0
#define ERF_POPULATE_FAILED -1

#define ERF_MAX_INTERFACES 8

/**
 * @brief Private state maintained for ERF capture files and LINKTYPE_ERF packets in pcap/pcapng.
 */
struct erf_private {
    GHashTable *if_map;            /**< Hash table mapping ERF interface IDs to wtap_interface_info records. */
    GHashTable *anchor_map;        /**< Hash table mapping ERF anchor IDs to associated metadata records. */
    uint64_t    implicit_host_id;  /**< Host ID inferred implicitly when no explicit Host ID extension header is present. */
    uint64_t    capture_gentime;   /**< Generation timestamp of the capture-level metadata, in ERF time format. */
    uint64_t    host_gentime;      /**< Generation timestamp of the host-level metadata, in ERF time format. */
};

#define MIN_RECORDS_FOR_ERF_CHECK 3
#define RECORDS_FOR_ERF_CHECK 20
#define FCS_BITS	32
/*Configurable through ERF_HOST_ID environment variable */
#define ERF_WS_DEFAULT_HOST_ID 0

/**
 * @brief Open an ERF file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
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
