/** @file
 *
 * Routine to fetch the last directory in which a file was opened;
 * its implementation is GUI-dependent, but the API isn't
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_LAST_OPEN_DIR_H__
#define __UI_LAST_OPEN_DIR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Get the latest opened directory.
 *
 * @return the dirname
 */
extern char *get_last_open_dir(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_LAST_OPEN_DIR_H__ */
