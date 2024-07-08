/** @file
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
#include <wiretap/wtap_opttypes.h>

#define SHARKD_DISSECT_FLAG_NULL       0x00u
#define SHARKD_DISSECT_FLAG_BYTES      0x01u
#define SHARKD_DISSECT_FLAG_COLUMNS    0x02u
#define SHARKD_DISSECT_FLAG_PROTO_TREE 0x04u
#define SHARKD_DISSECT_FLAG_COLOR      0x08u

#define SHARKD_MODE_CLASSIC_CONSOLE    1
#define SHARKD_MODE_CLASSIC_DAEMON     2
#define SHARKD_MODE_GOLD_CONSOLE       3
#define SHARKD_MODE_GOLD_DAEMON        4

typedef void (*sharkd_dissect_func_t)(epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data);

/* sharkd.c */
cf_status_t sharkd_cf_open(const char *fname, unsigned int type, bool is_tempfile, int *err);
int sharkd_load_cap_file(void);
int sharkd_retap(void);
int sharkd_filter(const char *dftext, uint8_t **result);
frame_data *sharkd_get_frame(uint32_t framenum);
enum dissect_request_status {
  DISSECT_REQUEST_SUCCESS,
  DISSECT_REQUEST_NO_SUCH_FRAME,
  DISSECT_REQUEST_READ_ERROR
};
enum dissect_request_status
sharkd_dissect_request(uint32_t framenum, uint32_t frame_ref_num,
                       uint32_t prev_dis_num, wtap_rec *rec, Buffer *buf,
                       column_info *cinfo, uint32_t dissect_flags,
                       sharkd_dissect_func_t cb, void *data,
                       int *err, char **err_info);
wtap_block_t sharkd_get_modified_block(const frame_data *fd);
wtap_block_t sharkd_get_packet_block(const frame_data *fd);
int sharkd_set_modified_block(frame_data *fd, wtap_block_t new_block);
const char *sharkd_version(void);

/* sharkd_daemon.c */
int sharkd_init(int argc, char **argv);
int sharkd_loop(int argc _U_, char* argv[] _U_);

/* sharkd_session.c */
int sharkd_session_main(int mode_setting);

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
