/** @file
 *
 * Ericsson eNode-B raw log file format decoder for the Wiretap library.
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_ERI_ENB_LOG_H__
#define __W_ERI_ENB_LOG_H__

#include "wtap.h"

/**
 * @brief Open an Ericsson eNode-B log file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
wtap_open_return_val eri_enb_log_open(wtap *wth, int *err, char **err_info);

#endif /* __W_ERI_ENB_LOG_H__*/
