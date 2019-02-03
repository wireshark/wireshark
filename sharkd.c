/* sharkd.c
 *
 * Daemon variant of Wireshark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan.h>

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <version_info.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include <epan/decode_as.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#include "ui/util.h"
#include "ui/ws_ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/filter_files.h"
#include "ui/tap_export_pdu.h"
#include "ui/failure_message.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/uat-int.h>
#include <epan/secrets.h>

#include <wsutil/codecs.h>

#include "log.h"

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include "sharkd.h"

#define INIT_FAILED 1
#define EPAN_INIT_FAIL 2

capture_file cfile;

static guint32 cum_bytes;
static frame_data ref_frame;

static void failure_warning_message(const char *msg_format, va_list ap);
static void open_failure_message(const char *filename, int err,
    gboolean for_writing);
static void read_failure_message(const char *filename, int err);
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);

static void
print_current_user(void) {
  gchar *cur_user, *cur_group;

  if (started_with_special_privs()) {
    cur_user = get_cur_username();
    cur_group = get_cur_groupname();
    fprintf(stderr, "Running as user \"%s\" and group \"%s\".",
      cur_user, cur_group);
    g_free(cur_user);
    g_free(cur_group);
    if (running_with_special_privs()) {
      fprintf(stderr, " This could be dangerous.");
    }
    fprintf(stderr, "\n");
  }
}

int
main(int argc, char *argv[])
{
  char                *init_progfile_dir_error;

  char                *err_msg = NULL;
  e_prefs             *prefs_p;
  int                  ret = EXIT_SUCCESS;

  cmdarg_err_init(failure_warning_message, failure_message_cont);

  /*
   * Get credential information for later use, and drop privileges
   * before doing anything else.
   * Let the user know if anything happened.
   */
  init_process_policies();
  relinquish_special_privs_perm();
  print_current_user();

  /*
   * Attempt to get the pathname of the executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0]);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr, "sharkd: Can't get pathname of sharkd program: %s.\n",
            init_progfile_dir_error);
  }

  /* Initialize the version information. */
  ws_init_version_info("Sharkd (Wireshark)", NULL,
                       epan_get_compiled_version_info,
                       epan_get_runtime_version_info);

  if (sharkd_init(argc, argv) < 0)
  {
    printf("cannot initialize sharkd\n");
    ret = INIT_FAILED;
    goto clean_exit;
  }

  init_report_message(failure_warning_message, failure_warning_message,
                      open_failure_message, read_failure_message,
                      write_failure_message);

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

  wtap_init(TRUE);

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  if (!epan_init(NULL, NULL, TRUE)) {
    ret = EPAN_INIT_FAIL;
    goto clean_exit;
  }

  codecs_init();

  /* Load libwireshark settings from the current profile. */
  prefs_p = epan_load_settings();

  read_filter_list(CFILTER_LIST);

  if (!color_filters_init(&err_msg, NULL)) {
     fprintf(stderr, "%s\n", err_msg);
     g_free(err_msg);
  }

  cap_file_init(&cfile);

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that their preferences have changed. */
  prefs_apply_all();

  /* Build the column format array */
  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

#ifdef HAVE_MAXMINDDB
  /* mmdbresolve is started from mmdb_resolve_start(), which is called from epan_load_settings via: read_prefs -> (...) uat_load_all -> maxmind_db_post_update_cb.
   * Need to stop it, otherwise all sharkd will have same mmdbresolve process, including pipe descriptors to read and write. */
  uat_clear(uat_get_table_by_name("MaxMind Database Paths"));
#endif

  ret = sharkd_loop();
clean_exit:
  col_cleanup(&cfile.cinfo);
  free_filter_lists();
  codecs_cleanup();
  wtap_cleanup();
  free_progdirs();
  return ret;
}

static const nstime_t *
sharkd_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;

  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;

  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;

  if (prov->frames) {
     frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static epan_t *
sharkd_epan_new(capture_file *cf)
{
  static const struct packet_provider_funcs funcs = {
    sharkd_get_frame_ts,
    cap_file_provider_get_interface_name,
    cap_file_provider_get_interface_description,
    cap_file_provider_get_user_comment
  };

  return epan_new(&cf->provider, &funcs);
}

static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt,
               gint64 offset, wtap_rec *rec, Buffer *buf)
{
  frame_data     fdlocal;
  gboolean       passed;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  /* The frame number of this packet, if we add it to the set of frames,
     would be one more than the count of frames in the file so far. */
  frame_data_init(&fdlocal, cf->count + 1, rec, offset, cum_bytes);

  /* If we're going to print packet information, or we're going to
     run a read filter, or display filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt) {
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name)
      /* Grab any resolved addresses */
      host_name_lookup_process();

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf->rfcode)
      epan_dissect_prime_with_dfilter(edt, cf->rfcode);

    if (cf->dfcode)
      epan_dissect_prime_with_dfilter(edt, cf->dfcode);

    /* This is the first and only pass, so prime the epan_dissect_t
       with the hfids postdissectors want on the first pass. */
    prime_epan_dissect_with_postdissector_wanted_hfids(edt);

    frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                                  &cf->provider.ref, cf->provider.prev_dis);
    if (cf->provider.ref == &fdlocal) {
      ref_frame = fdlocal;
      cf->provider.ref = &ref_frame;
    }

    epan_dissect_run(edt, cf->cd_t, rec,
                     frame_tvbuff_new_buffer(&cf->provider, &fdlocal, buf),
                     &fdlocal, NULL);

    /* Run the read filter if we have one. */
    if (cf->rfcode)
      passed = dfilter_apply_edt(cf->rfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cf->provider.prev_cap = cf->provider.prev_dis = frame_data_sequence_add(cf->provider.frames, &fdlocal);

    /* If we're not doing dissection then there won't be any dependent frames.
     * More importantly, edt.pi.dependent_frames won't be initialized because
     * epan hasn't been initialized.
     * if we *are* doing dissection, then mark the dependent frames, but only
     * if a display filter was given and it matches this packet.
     */
    if (edt && cf->dfcode) {
      if (dfilter_apply_edt(cf->dfcode, edt)) {
        g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->provider.frames);
      }
    }

    cf->count++;
  } else {
    /* if we don't add it to the frame_data_sequence, clean it up right now
     * to avoid leaks */
    frame_data_destroy(&fdlocal);
  }

  if (edt)
    epan_dissect_reset(edt);

  return passed;
}


static int
load_cap_file(capture_file *cf, int max_packet_count, gint64 max_byte_count)
{
  int          err;
  gchar       *err_info = NULL;
  gint64       data_offset;
  wtap_rec     rec;
  Buffer       buf;
  epan_dissect_t *edt = NULL;

  {
    /* Allocate a frame_data_sequence for all the frames. */
    cf->provider.frames = new_frame_data_sequence();

    {
      gboolean create_proto_tree;

      /*
       * Determine whether we need to create a protocol tree.
       * We do if:
       *
       *    we're going to apply a read filter;
       *
       *    we're going to apply a display filter;
       *
       *    a postdissector wants field values or protocols
       *    on the first pass.
       */
      create_proto_tree =
        (cf->rfcode != NULL || cf->dfcode != NULL || postdissectors_want_hfids());

      /* We're not going to display the protocol tree on this pass,
         so it's not going to be "visible". */
      edt = epan_dissect_new(cf->epan, create_proto_tree, FALSE);
    }

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    while (wtap_read(cf->provider.wth, &rec, &buf, &err, &err_info, &data_offset)) {
      if (process_packet(cf, edt, data_offset, &rec, &buf)) {
        /* Stop reading if we have the maximum number of packets;
         * When the -c option has not been used, max_packet_count
         * starts at 0, which practically means, never stop reading.
         * (unless we roll over max_packet_count ?)
         */
        if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
          err = 0; /* This is not an error */
          break;
        }
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    /* Close the sequential I/O side, to free up memory it requires. */
    wtap_sequential_close(cf->provider.wth);

    /* Allow the protocol dissectors to free up memory that they
     * don't need after the sequential run-through of the packets. */
    postseq_cleanup_all_protocols();

    cf->provider.prev_dis = NULL;
    cf->provider.prev_cap = NULL;
  }

  if (err != 0) {
    cfile_read_failure_message("sharkd", cf->filename, err, err_info);
  }

  return err;
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  wtap  *wth;
  gchar *err_info;

  wth = wtap_open_offline(fname, type, err, &err_info, TRUE);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Fill in the information for this file. */

  cf->provider.wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t      = wtap_file_type_subtype(cf->provider.wth);
  cf->open_type = type;
  cf->count     = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->provider.wth);
  nstime_set_zero(&cf->elapsed_time);
  cf->provider.ref = NULL;
  cf->provider.prev_dis = NULL;
  cf->provider.prev_cap = NULL;

  /* Create new epan session for dissection. */
  epan_free(cf->epan);
  cf->epan = sharkd_epan_new(cf);

  cf->state = FILE_READ_IN_PROGRESS;

  wtap_set_cb_new_ipv4(cf->provider.wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->provider.wth, (wtap_new_ipv6_callback_t) add_ipv6_name);
  wtap_set_cb_new_secrets(cf->provider.wth, secrets_wtap_callback);

  return CF_OK;

fail:
  cfile_open_failure_message("sharkd", fname, *err, err_info);
  return CF_ERROR;
}

/*
 * General errors and warnings are reported with an console message
 * in sharkd.
 */
static void
failure_warning_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "sharkd: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Open/create errors are reported with an console message in sharkd.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
  fprintf(stderr, "sharkd: ");
  fprintf(stderr, file_open_error_message(err, for_writing), filename);
  fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in sharkd.
 */
static void
read_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Write errors are reported with an console message in sharkd.
 */
static void
write_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while writing to the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
failure_message_cont(const char *msg_format, va_list ap)
{
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

cf_status_t
sharkd_cf_open(const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  return cf_open(&cfile, fname, type, is_tempfile, err);
}

int
sharkd_load_cap_file(void)
{
  return load_cap_file(&cfile, 0, 0);
}

frame_data *
sharkd_get_frame(guint32 framenum)
{
  return frame_data_sequence_find(cfile.provider.frames, framenum);
}

int
sharkd_dissect_request(guint32 framenum, guint32 frame_ref_num, guint32 prev_dis_num, sharkd_dissect_func_t cb, guint32 dissect_flags, void *data)
{
  frame_data *fdata;
  column_info *cinfo = (dissect_flags & SHARKD_DISSECT_FLAG_COLUMNS) ? &cfile.cinfo : NULL;
  epan_dissect_t edt;
  gboolean create_proto_tree;
  wtap_rec rec; /* Record metadata */
  Buffer buf;   /* Record data */

  int err;
  char *err_info = NULL;

  fdata = sharkd_get_frame(framenum);
  if (fdata == NULL)
    return -1;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);

  if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info)) {
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    return -1; /* error reading the record */
  }

  create_proto_tree = ((dissect_flags & SHARKD_DISSECT_FLAG_PROTO_TREE) ||
                      ((dissect_flags & SHARKD_DISSECT_FLAG_COLOR) && color_filters_used()) ||
                      (cinfo && have_custom_cols(cinfo)));
  epan_dissect_init(&edt, cfile.epan, create_proto_tree, (dissect_flags & SHARKD_DISSECT_FLAG_PROTO_TREE));

  if (dissect_flags & SHARKD_DISSECT_FLAG_COLOR) {
    color_filters_prime_edt(&edt);
    fdata->need_colorize = 1;
  }

  if (cinfo)
    col_custom_prime_edt(&edt, cinfo);

  /*
   * XXX - need to catch an OutOfMemoryError exception and
   * attempt to recover from it.
   */
  fdata->ref_time = (framenum == frame_ref_num);
  fdata->frame_ref_num = frame_ref_num;
  fdata->prev_dis_num = prev_dis_num;
  epan_dissect_run(&edt, cfile.cd_t, &rec,
                   frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                   fdata, cinfo);

  if (cinfo) {
    /* "Stringify" non frame_data vals */
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE/* fill_fd_columns */);
  }

  cb(&edt, (dissect_flags & SHARKD_DISSECT_FLAG_PROTO_TREE) ? edt.tree : NULL,
     cinfo, (dissect_flags & SHARKD_DISSECT_FLAG_BYTES) ? edt.pi.data_src : NULL,
     data);

  epan_dissect_cleanup(&edt);
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  return 0;
}

/* based on packet_list_dissect_and_cache_record */
int
sharkd_dissect_columns(frame_data *fdata, guint32 frame_ref_num, guint32 prev_dis_num, column_info *cinfo, gboolean dissect_color)
{
  epan_dissect_t edt;
  gboolean create_proto_tree;
  wtap_rec rec; /* Record metadata */
  Buffer buf;   /* Record data */

  int err;
  char *err_info = NULL;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);

  if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info)) {
    col_fill_in_error(cinfo, fdata, FALSE, FALSE /* fill_fd_columns */);
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    return -1; /* error reading the record */
  }

  create_proto_tree = (dissect_color && color_filters_used()) || (cinfo && have_custom_cols(cinfo));

  epan_dissect_init(&edt, cfile.epan, create_proto_tree, FALSE /* proto_tree_visible */);

  if (dissect_color) {
    color_filters_prime_edt(&edt);
    fdata->need_colorize = 1;
  }

  if (cinfo)
    col_custom_prime_edt(&edt, cinfo);

  /*
   * XXX - need to catch an OutOfMemoryError exception and
   * attempt to recover from it.
   */
  fdata->ref_time = (fdata->num == frame_ref_num);
  fdata->frame_ref_num = frame_ref_num;
  fdata->prev_dis_num = prev_dis_num;
  epan_dissect_run(&edt, cfile.cd_t, &rec,
                   frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                   fdata, cinfo);

  if (cinfo) {
    /* "Stringify" non frame_data vals */
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE/* fill_fd_columns */);
  }

  epan_dissect_cleanup(&edt);
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  return 0;
}

int
sharkd_retap(void)
{
  guint32          framenum;
  frame_data      *fdata;
  Buffer           buf;
  wtap_rec         rec;
  int err;
  char *err_info = NULL;

  guint         tap_flags;
  gboolean      create_proto_tree;
  epan_dissect_t edt;
  column_info   *cinfo;

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  /* If any tap listeners require the columns, construct them. */
  cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cfile.cinfo : NULL;

  /*
   * Determine whether we need to create a protocol tree.
   * We do if:
   *
   *    one of the tap listeners is going to apply a filter;
   *
   *    one of the tap listeners requires a protocol tree.
   */
  create_proto_tree =
    (have_filtering_tap_listeners() || (tap_flags & TL_REQUIRES_PROTO_TREE));

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  epan_dissect_init(&edt, cfile.epan, create_proto_tree, FALSE);

  reset_tap_listeners();

  for (framenum = 1; framenum <= cfile.count; framenum++) {
    fdata = sharkd_get_frame(framenum);

    if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info))
      break;

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = framenum - 1;
    epan_dissect_run_with_taps(&edt, cfile.cd_t, &rec,
                               frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                               fdata, cinfo);
    epan_dissect_reset(&edt);
  }

  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);

  draw_tap_listeners(TRUE);

  return 0;
}

int
sharkd_filter(const char *dftext, guint8 **result)
{
  dfilter_t  *dfcode = NULL;

  guint32 framenum, prev_dis_num = 0;
  guint32 frames_count;
  Buffer buf;
  wtap_rec rec;
  int err;
  char *err_info = NULL;

  guint8 *result_bits;
  guint8  passed_bits;

  epan_dissect_t edt;

  if (!dfilter_compile(dftext, &dfcode, &err_info)) {
    g_free(err_info);
    return -1;
  }

  /* if dfilter_compile() success, but (dfcode == NULL) all frames are matching */
  if (dfcode == NULL) {
    *result = NULL;
    return 0;
  }

  frames_count = cfile.count;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  epan_dissect_init(&edt, cfile.epan, TRUE, FALSE);

  passed_bits = 0;
  result_bits = (guint8 *) g_malloc(2 + (frames_count / 8));

  for (framenum = 1; framenum <= frames_count; framenum++) {
    frame_data *fdata = sharkd_get_frame(framenum);

    if ((framenum & 7) == 0) {
      result_bits[(framenum / 8) - 1] = passed_bits;
      passed_bits = 0;
    }

    if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info))
      break;

    /* frame_data_set_before_dissect */
    epan_dissect_prime_with_dfilter(&edt, dfcode);

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = prev_dis_num;
    epan_dissect_run(&edt, cfile.cd_t, &rec,
                     frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                     fdata, NULL);

    if (dfilter_apply_edt(dfcode, &edt)) {
      passed_bits |= (1 << (framenum % 8));
      prev_dis_num = framenum;
    }

    /* if passed or ref -> frame_data_set_after_dissect */

    epan_dissect_reset(&edt);
  }

  if ((framenum & 7) == 0)
      framenum--;
  result_bits[framenum / 8] = passed_bits;

  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);

  dfilter_free(dfcode);

  *result = result_bits;

  return framenum;
}

const char *
sharkd_get_user_comment(const frame_data *fd)
{
  return cap_file_provider_get_user_comment(&cfile.provider, fd);
}

int
sharkd_set_user_comment(frame_data *fd, const gchar *new_comment)
{
  cap_file_provider_set_user_comment(&cfile.provider, fd, new_comment);
  return 0;
}

#include "version.h"
const char *sharkd_version(void)
{
  /* based on get_ws_vcs_version_info(), but shorter */
#ifdef VCSVERSION
  return VCSVERSION;
#else
  return VERSION;
#endif
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
