/** @file
 *
 * Initialization of UI "helper" components
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_INIT_H__
#define __UI_INIT_H__

#include <wsutil/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Initialize the UI "helper" components */
extern void ui_init(void);

/* Cleanup the UI "helper" components */
extern void ui_cleanup(void);

/**
 * @brief Fetch the current UI memory scope.
 *
 * Allocated memory is freed when ui_cleanup() is called, which is normally at program exit.
 */
extern wmem_allocator_t* wmem_ui_scope(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_INIT_H__ */
