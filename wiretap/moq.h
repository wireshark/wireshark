/* moq.h
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "wtap.h"
wtap_open_return_val moq_open(wtap *wth, int *err, char **err_info);
void register_moq(void);
