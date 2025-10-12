/** @file
 *
 * Definitions for the Wireshark Memory Manager Hash Map Internals
 * Copyright 2014, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_MAP_INT_H__
#define __WMEM_MAP_INT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize internal hashing parameters for the wmem subsystem.
 *
 * Generates random values used to seed the hashing mechanism, including a random odd
 * multiplier and a preseed value. These values help randomize hash behavior to reduce
 * collision risks and improve distribution.
 *
 * This function should be called once during initialization before any hashing operations.
 */
WS_DLL_LOCAL
void
wmem_init_hashing(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_MAP_INT_H__ */

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
