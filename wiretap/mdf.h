/** @file
 *
 * ASAM MDF (Measurement Data Format, MF4) file format reader for the
 * Wiretap library.
 *
 * Copyright (c) 2022-2026 by Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_MDF_H__
#define __W_MDF_H__

#include "wtap.h"

/**
 * @brief Opens an MDF file.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where any error codes will be stored.
 * @param err_info Pointer to a char pointer where any error messages will be stored.
 * @return A value indicating whether the file is an MDF file, not an MDF file, or if there was an error opening the file.
 */
wtap_open_return_val mdf_open(wtap *wth, int *err, char **err_info);

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
