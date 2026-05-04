/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __SYSTEMD_JOURNAL_H__
#define __SYSTEMD_JOURNAL_H__

#include "wtap.h"

/** @brief Open a systemd journal file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return A value indicating the result of the operation.
 */
wtap_open_return_val systemd_journal_open(wtap *wth, int *err, char **err_info);

#endif // __SYSTEMD_JOURNAL_H__
