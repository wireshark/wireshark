/* sharkd.c
 *
 * Daemon variant of Wireshark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include <epan/epan-int.h>
#include <epan/epan.h>

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <ws_version_info.h>
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
#include "ui/ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/filter_files.h"
#include "ui/tap_export_pdu.h"
#include "ui/failure_message.h"
#include "register.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>

#include <codecs/codecs.h>

#include "log.h"

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include "sharkd.h"

#define INIT_FAILED 1
#define EPAN_INIT_FAIL 2

static guint32 cum_bytes;
static const frame_data *ref;
static frame_data ref_frame;
static frame_data *prev_dis;
static frame_data *prev_cap;

static void failure_warning_message(const char *msg_format, va_list ap);
static void open_failure_message(const char *filename, int err,
    gboolean for_writing);
static void read_failure_message(const char *filename, int err);
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);

capture_file cfile;

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
  GString             *comp_info_str;
  GString             *runtime_info_str;
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
  init_progfile_dir_error = init_progfile_dir(argv[0], main);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr, "sharkd: Can't get pathname of sharkd program: %s.\n",
            init_progfile_dir_error);
  }

  /* Get the compile-time version information string */
  comp_info_str = get_compiled_version_info(NULL, epan_get_compiled_version_info);

  /* Get the run-time version information string */
  runtime_info_str = get_runtime_version_info(epan_get_runtime_version_info);

  /* Add it to the information to be reported on a crash. */
  ws_add_crash_info("Sharkd (Wireshark) %s\n"
         "\n"
         "%s"
         "\n"
         "%s",
      get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);
  g_string_free(comp_info_str, TRUE);
  g_string_free(runtime_info_str, TRUE);

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

  wtap_init();

#ifdef HAVE_PLUGINS
  /* Register all the plugin types we have. */
  epan_register_plugin_types(); /* Types known to libwireshark */

  /* Scan for plugins.  This does *not* call their registration routines;
     that's done later. */
  scan_plugins(REPORT_LOAD_FAILURE);

  /* Register all libwiretap plugin modules. */
  register_all_wiretap_modules();
#endif

  register_all_codecs();

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  if (!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL,
                 NULL)) {
    ret = EPAN_INIT_FAIL;
    goto clean_exit;
  }

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

  ret = sharkd_loop();
clean_exit:
  col_cleanup(&cfile.cinfo);
  free_filter_lists();
  wtap_cleanup();
  free_progdirs();
#ifdef HAVE_PLUGINS
  plugins_cleanup();
#endif
  return ret;
}

static const nstime_t *
sharkd_get_frame_ts(void *data, guint32 frame_num)
{
  capture_file *cf = (capture_file *) data;

  if (ref && ref->num == frame_num)
    return &ref->abs_ts;

  if (prev_dis && prev_dis->num == frame_num)
    return &prev_dis->abs_ts;

  if (prev_cap && prev_cap->num == frame_num)
    return &prev_cap->abs_ts;

  if (cf->frames) {
     frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static epan_t *
sharkd_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = sharkd_get_frame_ts;
  epan->get_interface_name = cap_file_get_interface_name;
  epan->get_interface_description = cap_file_get_interface_description;
  epan->get_user_comment = NULL;

  return epan;
}

static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt,
               gint64 offset, struct wtap_pkthdr *whdr,
               const guchar *pd)
{
  frame_data     fdlocal;
  guint32        framenum;
  gboolean       passed;

  /* The frame number of this packet is one more than the count of
     frames in this packet. */
  framenum = cf->count + 1;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  frame_data_init(&fdlocal, framenum, whdr, offset, cum_bytes);

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
                                  &ref, prev_dis);
    if (ref == &fdlocal) {
      ref_frame = fdlocal;
      ref = &ref_frame;
    }

    epan_dissect_run(edt, cf->cd_t, whdr, frame_tvbuff_new(&fdlocal, pd), &fdlocal, NULL);

    /* Run the read filter if we have one. */
    if (cf->rfcode)
      passed = dfilter_apply_edt(cf->rfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    prev_cap = prev_dis = frame_data_sequence_add(cf->frames, &fdlocal);

    /* If we're not doing dissection then there won't be any dependent frames.
     * More importantly, edt.pi.dependent_frames won't be initialized because
     * epan hasn't been initialized.
     * if we *are* doing dissection, then mark the dependent frames, but only
     * if a display filter was given and it matches this packet.
     */
    if (edt && cf->dfcode) {
      if (dfilter_apply_edt(cf->dfcode, edt)) {
        g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->frames);
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
  epan_dissect_t *edt = NULL;

  {
    /* Allocate a frame_data_sequence for all the frames. */
    cf->frames = new_frame_data_sequence();

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

    while (wtap_read(cf->wth, &err, &err_info, &data_offset)) {
      if (process_packet(cf, edt, data_offset, wtap_phdr(cf->wth),
                         wtap_buf_ptr(cf->wth))) {
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

    /* Close the sequential I/O side, to free up memory it requires. */
    wtap_sequential_close(cf->wth);

    /* Allow the protocol dissectors to free up memory that they
     * don't need after the sequential run-through of the packets. */
    postseq_cleanup_all_protocols();

    prev_dis = NULL;
    prev_cap = NULL;
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

  /* Create new epan session for dissection. */
  epan_free(cf->epan);
  cf->epan = sharkd_epan_new(cf);

  cf->wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t      = wtap_file_type_subtype(cf->wth);
  cf->open_type = type;
  cf->count     = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->wth);
  nstime_set_zero(&cf->elapsed_time);
  ref = NULL;
  prev_dis = NULL;
  prev_cap = NULL;

  cf->state = FILE_READ_IN_PROGRESS;

  wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);

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

int
sharkd_dissect_request(unsigned int framenum, void (*cb)(packet_info *, proto_tree *, struct epan_column_info *, const GSList *, void *), int dissect_bytes, int dissect_columns, int dissect_tree, void *data)
{
  frame_data *fdata;
  column_info *cinfo = (dissect_columns) ? &cfile.cinfo : NULL;
  epan_dissect_t edt;
  gboolean create_proto_tree;
  struct wtap_pkthdr phdr; /* Packet header */
  Buffer buf; /* Packet data */

  int err;
  char *err_info = NULL;

  fdata = frame_data_sequence_find(cfile.frames, framenum);
  if (fdata == NULL)
    return -1;

  wtap_phdr_init(&phdr);
  ws_buffer_init(&buf, 1500);

  if (!wtap_seek_read(cfile.wth, fdata->file_off, &phdr, &buf, &err, &err_info)) {
    ws_buffer_free(&buf);
    return -1; /* error reading the record */
  }

  create_proto_tree = (dissect_tree) || (cinfo && have_custom_cols(cinfo));
  epan_dissect_init(&edt, cfile.epan, create_proto_tree, dissect_tree);

  if (cinfo)
    col_custom_prime_edt(&edt, cinfo);

  /*
   * XXX - need to catch an OutOfMemoryError exception and
   * attempt to recover from it.
   */
  epan_dissect_run(&edt, cfile.cd_t, &phdr, frame_tvbuff_new_buffer(fdata, &buf), fdata, cinfo);

  if (cinfo) {
    /* "Stringify" non frame_data vals */
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE/* fill_fd_columns */);
  }

  cb(&edt.pi, dissect_tree ? edt.tree : NULL, cinfo, dissect_bytes ? edt.pi.data_src : NULL, data);

  epan_dissect_cleanup(&edt);
  wtap_phdr_cleanup(&phdr);
  ws_buffer_free(&buf);
  return 0;
}

/* based on packet_list_dissect_and_cache_record */
int
sharkd_dissect_columns(int framenum, column_info *cinfo, gboolean dissect_color)
{
  frame_data *fdata;
  epan_dissect_t edt;
  gboolean create_proto_tree;
  struct wtap_pkthdr phdr; /* Packet header */
  Buffer buf; /* Packet data */

  int err;
  char *err_info = NULL;

  fdata = frame_data_sequence_find(cfile.frames, framenum);
  if (fdata == NULL) {
    col_fill_in_error(cinfo, fdata, FALSE, TRUE/* fill_fd_columns */);
    return -1; /* error reading the record */
  }

  wtap_phdr_init(&phdr);
  ws_buffer_init(&buf, 1500);

  if (!wtap_seek_read(cfile.wth, fdata->file_off, &phdr, &buf, &err, &err_info)) {
    col_fill_in_error(cinfo, fdata, FALSE, FALSE /* fill_fd_columns */);
    ws_buffer_free(&buf);
    return -1; /* error reading the record */
  }

  create_proto_tree = (dissect_color && color_filters_used()) || (cinfo && have_custom_cols(cinfo));

  epan_dissect_init(&edt, cfile.epan, create_proto_tree, FALSE /* proto_tree_visible */);

  if (dissect_color) {
    color_filters_prime_edt(&edt);
    fdata->flags.need_colorize = 1;
  }

  if (cinfo)
    col_custom_prime_edt(&edt, cinfo);

  /*
   * XXX - need to catch an OutOfMemoryError exception and
   * attempt to recover from it.
   */
  epan_dissect_run(&edt, cfile.cd_t, &phdr, frame_tvbuff_new_buffer(fdata, &buf), fdata, cinfo);

  if (cinfo) {
    /* "Stringify" non frame_data vals */
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE/* fill_fd_columns */);
  }

  epan_dissect_cleanup(&edt);
  wtap_phdr_cleanup(&phdr);
  ws_buffer_free(&buf);
  return 0;
}

int
sharkd_retap(void)
{
  guint32          framenum;
  frame_data      *fdata;
  Buffer           buf;
  struct wtap_pkthdr phdr;
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

  wtap_phdr_init(&phdr);
  ws_buffer_init(&buf, 1500);
  epan_dissect_init(&edt, cfile.epan, create_proto_tree, FALSE);

  reset_tap_listeners();

  for (framenum = 1; framenum <= cfile.count; framenum++) {
    fdata = frame_data_sequence_find(cfile.frames, framenum);

    if (!wtap_seek_read(cfile.wth, fdata->file_off, &phdr, &buf, &err, &err_info))
      break;

    epan_dissect_run_with_taps(&edt, cfile.cd_t, &phdr, frame_tvbuff_new(fdata, ws_buffer_start_ptr(&buf)), fdata, cinfo);
    epan_dissect_reset(&edt);
  }

  wtap_phdr_cleanup(&phdr);
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);

  draw_tap_listeners(TRUE);

  return 0;
}

int
sharkd_filter(const char *dftext, guint8 **result)
{
  dfilter_t  *dfcode = NULL;

  guint32 framenum;
  guint32 frames_count;
  Buffer buf;
  struct wtap_pkthdr phdr;
  int err;
  char *err_info = NULL;

  guint8 *result_bits;
  guint8  passed_bits;

  epan_dissect_t edt;

  if (!dfilter_compile(dftext, &dfcode, &err_info)) {
    g_free(err_info);
    return -1;
  }

  frames_count = cfile.count;

  wtap_phdr_init(&phdr);
  ws_buffer_init(&buf, 1500);
  epan_dissect_init(&edt, cfile.epan, TRUE, FALSE);

  passed_bits = 0;
  result_bits = (guint8 *) g_malloc(2 + (frames_count / 8));

  for (framenum = 1; framenum <= frames_count; framenum++) {
    frame_data *fdata = frame_data_sequence_find(cfile.frames, framenum);

    if ((framenum & 7) == 0) {
      result_bits[(framenum / 8) - 1] = passed_bits;
      passed_bits = 0;
    }

    if (!wtap_seek_read(cfile.wth, fdata->file_off, &phdr, &buf, &err, &err_info))
      break;

    /* frame_data_set_before_dissect */
    epan_dissect_prime_with_dfilter(&edt, dfcode);

    epan_dissect_run(&edt, cfile.cd_t, &phdr, frame_tvbuff_new_buffer(fdata, &buf), fdata, NULL);

    if (dfilter_apply_edt(dfcode, &edt))
      passed_bits |= (1 << (framenum % 8));

    /* if passed or ref -> frame_data_set_after_dissect */

    epan_dissect_reset(&edt);
  }

  if ((framenum & 7) == 0)
      framenum--;
  result_bits[framenum / 8] = passed_bits;

  wtap_phdr_cleanup(&phdr);
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);

  dfilter_free(dfcode);

  *result = result_bits;

  return framenum;
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
