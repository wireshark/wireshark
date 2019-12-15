/* tap-exportobject.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_EXPORT_OBJECT_H__
#define __TAP_EXPORT_OBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void eo_list_object_types(void);

/* will be called by main each time a --export-objects option is found */
gboolean eo_tap_opt_add(const char *optarg);

void start_exportobjects(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_EXPORT_OBJECT_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
