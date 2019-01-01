/* export_object_ui.h
 * Common routines for tracking & saving objects found in streams of data
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EXPORT_OBJECT_UI_H__
#define __EXPORT_OBJECT_UI_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <epan/export_object.h>

/* Common between protocols */

void eo_save_entry(const gchar *save_as_filename, export_object_entry_t *entry);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EXPORT_OBJECT_UI_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
