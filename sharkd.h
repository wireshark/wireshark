/* sharkd.h
 *
 * Copyright (C) 2016 Jakub Zawadzki
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SHARKD_H
#define __SHARKD_H

#include <file.h>

#define SHARKD_DISSECT_FLAG_NULL       0x00u
#define SHARKD_DISSECT_FLAG_BYTES      0x01u
#define SHARKD_DISSECT_FLAG_COLUMNS    0x02u
#define SHARKD_DISSECT_FLAG_PROTO_TREE 0x04u
#define SHARKD_DISSECT_FLAG_COLOR      0x08u

typedef void (*sharkd_dissect_func_t)(epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data);

/* sharkd.c */
cf_status_t sharkd_cf_open(const char *fname, unsigned int type, gboolean is_tempfile, int *err);
int sharkd_load_cap_file(void);
int sharkd_retap(void);
int sharkd_filter(const char *dftext, guint8 **result);
frame_data *sharkd_get_frame(guint32 framenum);
int sharkd_dissect_columns(frame_data *fdata, guint32 frame_ref_num, guint32 prev_dis_num, column_info *cinfo, gboolean dissect_color);
int sharkd_dissect_request(guint32 framenum, guint32 frame_ref_num, guint32 prev_dis_num, sharkd_dissect_func_t cb, guint32 dissect_flags, void *data);
const char *sharkd_get_user_comment(const frame_data *fd);
int sharkd_set_user_comment(frame_data *fd, const gchar *new_comment);
const char *sharkd_version(void);

/* sharkd_daemon.c */
int sharkd_init(int argc, char **argv);
int sharkd_loop(void);

/* sharkd_session.c */
int sharkd_session_main(void);

#endif /* __SHARKD_H */

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
