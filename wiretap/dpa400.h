/** @file
 *
 * Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DPA400_H__
#define __DPA400_H__

#include "wtap.h"

/**
 * @brief Open a DPA400 file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val dpa400_open(wtap *wth, int *err, char **err_info);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
