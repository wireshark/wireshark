/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DAINTREE_SNA_H__
#define __DAINTREE_SNA_H__

#include "wtap.h"

/**
 * @brief Open a Daintree SNA file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return The result of opening the file.
 */
wtap_open_return_val daintree_sna_open(wtap *wth, int *err, char **err_info _U_);

#endif /* __DAINTREE_SNA_H__ */

