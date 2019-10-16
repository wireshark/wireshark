/* file_dialog.h
 * Common file dialog definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILE_DIALOG_H__
#define __FILE_DIALOG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
  SAVE,
  SAVE_WITHOUT_COMMENTS,
  SAVE_IN_ANOTHER_FORMAT,
  CANCELLED
} check_savability_t;

typedef enum {
    export_type_text = 1,
    export_type_ps,
    export_type_csv,
    export_type_psml,
    export_type_pdml,
    export_type_carrays,
    export_type_json
} export_type_e;

typedef struct {
    gboolean have_times;  /* TRUE if we have start and stop times */
    double start_time;    /* seconds, with nsec resolution */
    double stop_time;     /* seconds, with nsec resolution */
    guint32 records;      /* total number of records */
    guint32 data_records; /* number of data records */
} ws_file_preview_stats;

typedef enum {
    PREVIEW_SUCCEEDED,
    PREVIEW_TIMED_OUT,
    PREVIEW_READ_ERROR
} ws_file_preview_stats_status;

extern ws_file_preview_stats_status
get_stats_for_preview(wtap *wth, ws_file_preview_stats *stats,
                      int *err, gchar **err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_DIALOG_H__ */

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
