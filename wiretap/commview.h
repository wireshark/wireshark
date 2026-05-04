/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __COMMVIEW_H__
#define __COMMVIEW_H__

#include "wtap.h"

/**
 * @brief Open a CommView NCF file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val The result of the open operation.
 */
wtap_open_return_val commview_ncf_open(wtap *wth, int *err, char **err_info);

/**
 * @brief Open a CommView NCX file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val The result of the open operation.
 */
wtap_open_return_val commview_ncfx_open(wtap *wth, int *err, char **err_info);

#endif /* __COMMVIEW_H__ */

