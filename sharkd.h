/* sharkd.h
 *
 * Copyright (C) 2016 Jakub Zawadzki
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __SHARKD_H
#define __SHARKD_H

#include <file.h>
#include <globals.h>

/* sharkd.c */
cf_status_t sharkd_cf_open(const char *fname, unsigned int type, gboolean is_tempfile, int *err);
int sharkd_load_cap_file(void);
int sharkd_retap(void);
int sharkd_filter(const char *dftext, guint8 **result);
int sharkd_dissect_columns(int framenum, column_info *cinfo, gboolean dissect_color);
int sharkd_dissect_request(unsigned int framenum, void (*cb)(epan_dissect_t *, proto_tree *, struct epan_column_info *, const GSList *, void *), int dissect_bytes, int dissect_columns, int dissect_tree, void *data);
const char *sharkd_version(void);

/* sharkd_daemon.c */
int sharkd_init(int argc, char **argv);
int sharkd_loop(void);

/* sharkd_session.c */
int sharkd_session_main(void);

#endif /* __SHARKD_H */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
