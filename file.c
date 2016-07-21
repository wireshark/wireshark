/* file.c
 * File I/O routines
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

#include <time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <wsutil/tempfile.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <ws_version_info.h>

#include <wiretap/merge.h>

#include <epan/exceptions.h>
#include <epan/epan-int.h>
#include <epan/epan.h>
#include <epan/column.h>
#include <epan/packet.h>
#include <epan/column-utils.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/timestamp.h>
#include <epan/dfilter/dfilter-macro.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/color_filters.h>

#include "cfile.h"
#include "file.h"
#include "fileset.h"
#include "frame_tvbuff.h"

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/main_statusbar.h"
#include "ui/progress_dlg.h"
#include "ui/ui_util.h"

/* Needed for addrinfo */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#ifdef _WIN32
# include <ws2tcpip.h>
#endif

#ifdef HAVE_LIBPCAP
gboolean auto_scroll_live; /* GTK+ only? */
#endif

static int read_packet(capture_file *cf, dfilter_t *dfcode, epan_dissect_t *edt,
    column_info *cinfo, gint64 offset);

static void rescan_packets(capture_file *cf, const char *action, const char *action_item, gboolean redissect);

typedef enum {
  MR_NOTMATCHED,
  MR_MATCHED,
  MR_ERROR
} match_result;
static match_result match_protocol_tree(capture_file *cf, frame_data *fdata,
    void *criterion);
static void match_subtree_text(proto_node *node, gpointer data);
static match_result match_summary_line(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_narrow_and_wide(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_narrow(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_wide(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_binary(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_regex(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_dfilter(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_marked(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_time_reference(capture_file *cf, frame_data *fdata,
    void *criterion);
static gboolean find_packet(capture_file *cf,
    match_result (*match_function)(capture_file *, frame_data *, void *),
    void *criterion, search_direction dir);

static const char *cf_get_user_packet_comment(capture_file *cf, const frame_data *fd);

static void cf_open_failure_alert_box(const char *filename, int err,
                      gchar *err_info, gboolean for_writing,
                      int file_type);
static void cf_rename_failure_alert_box(const char *filename, int err);
static void cf_close_failure_alert_box(const char *filename, int err);
static void ref_time_packets(capture_file *cf);

/* Seconds spent processing packets between pushing UI updates. */
#define PROGBAR_UPDATE_INTERVAL 0.150

/* Show the progress bar after this many seconds. */
#define PROGBAR_SHOW_DELAY 0.5

/*
 * We could probably use g_signal_...() instead of the callbacks below but that
 * would require linking our CLI programs to libgobject and creating an object
 * instance for the signals.
 */
typedef struct {
  cf_callback_t cb_fct;
  gpointer      user_data;
} cf_callback_data_t;

static GList *cf_callbacks = NULL;

static void
cf_callback_invoke(int event, gpointer data)
{
  cf_callback_data_t *cb;
  GList              *cb_item = cf_callbacks;

  /* there should be at least one interested */
  g_assert(cb_item != NULL);

  while (cb_item != NULL) {
    cb = (cf_callback_data_t *)cb_item->data;
    cb->cb_fct(event, data, cb->user_data);
    cb_item = g_list_next(cb_item);
  }
}


void
cf_callback_add(cf_callback_t func, gpointer user_data)
{
  cf_callback_data_t *cb;

  cb = g_new(cf_callback_data_t,1);
  cb->cb_fct = func;
  cb->user_data = user_data;

  cf_callbacks = g_list_prepend(cf_callbacks, cb);
}

void
cf_callback_remove(cf_callback_t func, gpointer user_data)
{
  cf_callback_data_t *cb;
  GList              *cb_item = cf_callbacks;

  while (cb_item != NULL) {
    cb = (cf_callback_data_t *)cb_item->data;
    if (cb->cb_fct == func && cb->user_data == user_data) {
      cf_callbacks = g_list_remove(cf_callbacks, cb);
      g_free(cb);
      return;
    }
    cb_item = g_list_next(cb_item);
  }

  g_assert_not_reached();
}

void
cf_timestamp_auto_precision(capture_file *cf)
{
  int i;

  /* don't try to get the file's precision if none is opened */
  if (cf->state == FILE_CLOSED) {
    return;
  }

  /* Set the column widths of those columns that show the time in
     "command-line-specified" format. */
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    if (col_has_time_fmt(&cf->cinfo, i)) {
      packet_list_resize_column(i);
    }
  }
}

gulong
cf_get_computed_elapsed(capture_file *cf)
{
  return cf->computed_elapsed;
}

/*
 * GLIB_CHECK_VERSION(2,28,0) adds g_get_real_time which could minimize or
 * replace this
 */
static void compute_elapsed(capture_file *cf, GTimeVal *start_time)
{
  gdouble  delta_time;
  GTimeVal time_now;

  g_get_current_time(&time_now);

  delta_time = (time_now.tv_sec - start_time->tv_sec) * 1e6 +
    time_now.tv_usec - start_time->tv_usec;

  cf->computed_elapsed = (gulong) (delta_time / 1000); /* ms */
}

static const nstime_t *
ws_get_frame_ts(void *data, guint32 frame_num)
{
  capture_file *cf = (capture_file *) data;

  if (cf->prev_dis && cf->prev_dis->num == frame_num)
    return &cf->prev_dis->abs_ts;

  if (cf->prev_cap && cf->prev_cap->num == frame_num)
    return &cf->prev_cap->abs_ts;

  if (cf->frames) {
    frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

    return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static const char *
ws_get_user_comment(void *data, const frame_data *fd)
{
  capture_file *cf = (capture_file *) data;

  return cf_get_user_packet_comment(cf, fd);
}

static epan_t *
ws_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = ws_get_frame_ts;
  epan->get_interface_name = cap_file_get_interface_name;
  epan->get_user_comment = ws_get_user_comment;

  return epan;
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  wtap  *wth;
  gchar *err_info;

  wth = wtap_open_offline(fname, type, err, &err_info, TRUE);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Close whatever capture file we had open,
     and fill in the information for this file. */
  cf_close(cf);

  /* Initialize the packet header. */
  wtap_phdr_init(&cf->phdr);

  /* XXX - we really want to initialize this after we've read all
     the packets, so we know how much we'll ultimately need. */
  ws_buffer_init(&cf->buf, 1500);

  /* Create new epan session for dissection.
   * (The old one was freed in cf_close().)
   */
  cf->epan = ws_epan_new(cf);

  /* We're about to start reading the file. */
  cf->state = FILE_READ_IN_PROGRESS;

  cf->wth = wth;
  cf->f_datalen = 0;

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->computed_elapsed = 0;

  cf->cd_t        = wtap_file_type_subtype(cf->wth);
  cf->open_type   = type;
  cf->linktypes = g_array_sized_new(FALSE, FALSE, (guint) sizeof(int), 1);
  cf->count     = 0;
  cf->packet_comment_count = 0;
  cf->displayed_count = 0;
  cf->marked_count = 0;
  cf->ignored_count = 0;
  cf->ref_time_count = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->wth);
  if (cf->snap == 0) {
    /* Snapshot length not known. */
    cf->has_snap = FALSE;
    cf->snap = WTAP_MAX_PACKET_SIZE;
  } else
    cf->has_snap = TRUE;

  /* Allocate a frame_data_sequence for the frames in this file */
  cf->frames = new_frame_data_sequence();

  nstime_set_zero(&cf->elapsed_time);
  cf->ref = NULL;
  cf->prev_dis = NULL;
  cf->prev_cap = NULL;
  cf->cum_bytes = 0;

  packet_list_queue_draw();
  cf_callback_invoke(cf_cb_file_opened, cf);

  if (cf->cd_t == WTAP_FILE_TYPE_SUBTYPE_BER) {
    /* tell the BER dissector the file name */
    ber_set_filename(cf->filename);
  }

  wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);

  return CF_OK;

fail:
  cf_open_failure_alert_box(fname, *err, err_info, FALSE, 0);
  return CF_ERROR;
}

/*
 * Add an encapsulation type to cf->linktypes.
 */
static void
cf_add_encapsulation_type(capture_file *cf, int encap)
{
  guint i;

  for (i = 0; i < cf->linktypes->len; i++) {
    if (g_array_index(cf->linktypes, gint, i) == encap)
      return; /* it's already there */
  }
  /* It's not already there - add it. */
  g_array_append_val(cf->linktypes, encap);
}

/* Reset everything to a pristine state */
void
cf_close(capture_file *cf)
{
  cf->stop_flag = FALSE;
  if (cf->state == FILE_CLOSED)
    return; /* Nothing to do */

  /* Die if we're in the middle of reading a file. */
  g_assert(cf->state != FILE_READ_IN_PROGRESS);

  cf_callback_invoke(cf_cb_file_closing, cf);

  /* close things, if not already closed before */
  color_filters_cleanup();

  if (cf->wth) {
    wtap_close(cf->wth);
    cf->wth = NULL;
  }
  /* We have no file open... */
  if (cf->filename != NULL) {
    /* If it's a temporary file, remove it. */
    if (cf->is_tempfile)
      ws_unlink(cf->filename);
    g_free(cf->filename);
    cf->filename = NULL;
  }
  /* ...which means we have no changes to that file to save. */
  cf->unsaved_changes = FALSE;

  /* no open_routine type */
  cf->open_type = WTAP_TYPE_AUTO;

  /* Clean up the packet header. */
  wtap_phdr_cleanup(&cf->phdr);

  /* Free up the packet buffer. */
  ws_buffer_free(&cf->buf);

  dfilter_free(cf->rfcode);
  cf->rfcode = NULL;
  if (cf->frames != NULL) {
    free_frame_data_sequence(cf->frames);
    cf->frames = NULL;
  }
#ifdef WANT_PACKET_EDITOR
  if (cf->edited_frames) {
    g_tree_destroy(cf->edited_frames);
    cf->edited_frames = NULL;
  }
#endif
  if (cf->frames_user_comments) {
    g_tree_destroy(cf->frames_user_comments);
    cf->frames_user_comments = NULL;
  }
  cf_unselect_packet(cf);   /* nothing to select */
  cf->first_displayed = 0;
  cf->last_displayed = 0;

  /* No frames, no frame selected, no field in that frame selected. */
  cf->count = 0;
  cf->current_frame = 0;
  cf->current_row = 0;
  cf->finfo_selected = NULL;

  /* No frame link-layer types, either. */
  if (cf->linktypes != NULL) {
    g_array_free(cf->linktypes, TRUE);
    cf->linktypes = NULL;
  }

  /* Clear the packet list. */
  packet_list_freeze();
  packet_list_clear();
  packet_list_thaw();

  cf->f_datalen = 0;
  nstime_set_zero(&cf->elapsed_time);

  reset_tap_listeners();

  epan_free(cf->epan);
  cf->epan = NULL;

  /* We have no file open. */
  cf->state = FILE_CLOSED;

  cf_callback_invoke(cf_cb_file_closed, cf);
}

/*
 * TRUE if the progress dialog doesn't exist and it looks like we'll
 * take > 2s to load, FALSE otherwise.
 */
static inline gboolean
progress_is_slow(progdlg_t *progdlg, GTimer *prog_timer, gint64 size, gint64 pos)
{
  double elapsed;

  if (progdlg) return FALSE;
  elapsed = g_timer_elapsed(prog_timer, NULL);
  if ((elapsed / 2 > PROGBAR_SHOW_DELAY && (size / pos) > 2) /* It looks like we're going to be slow. */
      || elapsed > PROGBAR_SHOW_DELAY) { /* We are indeed slow. */
    return TRUE;
  }
  return FALSE;
}

static float
calc_progbar_val(capture_file *cf, gint64 size, gint64 file_pos, gchar *status_str, gulong status_size)
{
  float progbar_val;

  progbar_val = (gfloat) file_pos / (gfloat) size;
  if (progbar_val > 1.0) {

    /*  The file probably grew while we were reading it.
     *  Update file size, and try again.
     */
    size = wtap_file_size(cf->wth, NULL);

    if (size >= 0)
      progbar_val = (gfloat) file_pos / (gfloat) size;

    /*  If it's still > 1, either "wtap_file_size()" failed (in which
     *  case there's not much we can do about it), or the file
     *  *shrank* (in which case there's not much we can do about
     *  it); just clip the progress value at 1.0.
     */
    if (progbar_val > 1.0f)
      progbar_val = 1.0f;
  }

  g_snprintf(status_str, status_size,
             "%" G_GINT64_MODIFIER "dKB of %" G_GINT64_MODIFIER "dKB",
             file_pos / 1024, size / 1024);

  return progbar_val;
}

cf_read_status_t
cf_read(capture_file *cf, gboolean reloading)
{
  int                  err = 0;
  gchar               *err_info = NULL;
  gchar               *name_ptr;
  progdlg_t           *volatile progbar = NULL;
  GTimer              *prog_timer = g_timer_new();
  GTimeVal             start_time;
  epan_dissect_t       edt;
  dfilter_t           *dfcode;
  volatile gboolean    create_proto_tree;
  guint                tap_flags;
  gboolean             compiled;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode, NULL);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();
  create_proto_tree =
    (dfcode != NULL || have_filtering_tap_listeners() || (tap_flags & TL_REQUIRES_PROTO_TREE));

  reset_tap_listeners();

  name_ptr = g_filename_display_basename(cf->filename);

  if (reloading)
    cf_callback_invoke(cf_cb_file_reload_started, cf);
  else
    cf_callback_invoke(cf_cb_file_read_started, cf);

  /* Record whether the file is compressed.
     XXX - do we know this at open time? */
  cf->iscompressed = wtap_iscompressed(cf->wth);

  /* The packet list window will be empty until the file is completly loaded */
  packet_list_freeze();

  cf->stop_flag = FALSE;
  g_get_current_time(&start_time);

  epan_dissect_init(&edt, cf->epan, create_proto_tree, FALSE);

  TRY {
    int     count             = 0;

    gint64  size;
    gint64  file_pos;
    gint64  data_offset;

    float   progbar_val;
    gchar   status_str[100];

    column_info *cinfo;

    cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cf->cinfo : NULL;

    /* Find the size of the file. */
    size = wtap_file_size(cf->wth, NULL);

    g_timer_start(prog_timer);

    while ((wtap_read(cf->wth, &err, &err_info, &data_offset))) {
      if (size >= 0) {
        count++;
        file_pos = wtap_read_so_far(cf->wth);

        /* Create the progress bar if necessary. */
        if (progress_is_slow(progbar, prog_timer, size, file_pos)) {
          progbar_val = calc_progbar_val(cf, size, file_pos, status_str, sizeof(status_str));
          if (reloading)
            progbar = delayed_create_progress_dlg(cf->window, "Reloading", name_ptr,
                TRUE, &cf->stop_flag, &start_time, progbar_val);
          else
            progbar = delayed_create_progress_dlg(cf->window, "Loading", name_ptr,
                TRUE, &cf->stop_flag, &start_time, progbar_val);
        }

        /*
         * Update the progress bar, but do it only after
         * PROGBAR_UPDATE_INTERVAL has elapsed. Calling update_progress_dlg
         * and packets_bar_update will likely trigger UI paint events, which
         * might take a while depending on the platform and display. Reset
         * our timer *after* painting.
         */
        if (progbar && g_timer_elapsed(prog_timer, NULL) > PROGBAR_UPDATE_INTERVAL) {
          progbar_val = calc_progbar_val(cf, size, file_pos, status_str, sizeof(status_str));
          /* update the packet bar content on the first run or frequently on very large files */
          update_progress_dlg(progbar, progbar_val, status_str);
          packets_bar_update();
          g_timer_start(prog_timer);
        }
      }

      if (cf->stop_flag) {
        /* Well, the user decided to abort the read. He/She will be warned and
           it might be enough for him/her to work with the already loaded
           packets.
           This is especially true for very large capture files, where you don't
           want to wait loading the whole file (which may last minutes or even
           hours even on fast machines) just to see that it was the wrong file. */
        break;
      }
      read_packet(cf, dfcode, &edt, cinfo, data_offset);
    }
  }
  CATCH(OutOfMemoryError) {
    simple_message_box(ESD_TYPE_ERROR, NULL,
                   "More information and workarounds can be found at\n"
                   "https://wiki.wireshark.org/KnownBugs/OutOfMemory",
                   "Sorry, but Wireshark has run out of memory and has to terminate now.");
#if 0
    /* Could we close the current capture and free up memory from that? */
#else
    /* we have to terminate, as we cannot recover from the memory error */
    exit(1);
#endif
  }
  ENDTRY;

  /* Free the display name */
  g_free(name_ptr);

  /* Cleanup and release all dfilter resources */
  if (dfcode != NULL) {
    dfilter_free(dfcode);
  }

  epan_dissect_cleanup(&edt);

  /* We're done reading the file; destroy the progress bar if it was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);
  g_timer_destroy(prog_timer);

  /* We're done reading sequentially through the file. */
  cf->state = FILE_READ_DONE;

  /* Close the sequential I/O side, to free up memory it requires. */
  wtap_sequential_close(cf->wth);

  /* Allow the protocol dissectors to free up memory that they
   * don't need after the sequential run-through of the packets. */
  postseq_cleanup_all_protocols();

  /* compute the time it took to load the file */
  compute_elapsed(cf, &start_time);

  /* Set the file encapsulation type now; we don't know what it is until
     we've looked at all the packets, as we don't know until then whether
     there's more than one type (and thus whether it's
     WTAP_ENCAP_PER_PACKET). */
  cf->lnk_t = wtap_file_encap(cf->wth);

  cf->current_frame = frame_data_sequence_find(cf->frames, cf->first_displayed);
  cf->current_row = 0;

  packet_list_thaw();
  if (reloading)
    cf_callback_invoke(cf_cb_file_reload_finished, cf);
  else
    cf_callback_invoke(cf_cb_file_read_finished, cf);

  /* If we have any displayed packets to select, select the first of those
     packets by making the first row the selected row. */
  if (cf->first_displayed != 0) {
    packet_list_select_first_row();
  }

  if (cf->stop_flag) {
    simple_message_box(ESD_TYPE_WARN, NULL,
                  "The remaining packets in the file were discarded.\n"
                  "\n"
                  "As a lot of packets from the original file will be missing,\n"
                  "remember to be careful when saving the current content to a file.\n",
                  "File loading was cancelled.");
    return CF_READ_ERROR;
  }

  if (err != 0) {
    /* Put up a message box noting that the read failed somewhere along
       the line.  Don't throw out the stuff we managed to read, though,
       if any. */
    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
      simple_error_message_box(
                 "The capture file contains record data that Wireshark doesn't support.\n(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_SHORT_READ:
      simple_error_message_box(
                 "The capture file appears to have been cut short"
                 " in the middle of a packet.");
      break;

    case WTAP_ERR_BAD_FILE:
      simple_error_message_box(
                 "The capture file appears to be damaged or corrupt.\n(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_DECOMPRESS:
      simple_error_message_box(
                 "The compressed capture file appears to be damaged or corrupt.\n(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    default:
      simple_error_message_box(
                 "An error occurred while reading the"
                 " capture file: %s.", wtap_strerror(err));
      break;
    }
    return CF_READ_ERROR;
  } else
    return CF_READ_OK;
}

#ifdef HAVE_LIBPCAP
cf_read_status_t
cf_continue_tail(capture_file *cf, volatile int to_read, int *err)
{
  gchar            *err_info;
  volatile int      newly_displayed_packets = 0;
  dfilter_t        *dfcode;
  epan_dissect_t    edt;
  gboolean          create_proto_tree;
  guint             tap_flags;
  gboolean          compiled;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode, NULL);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();
  create_proto_tree =
    (dfcode != NULL || have_filtering_tap_listeners() || (tap_flags & TL_REQUIRES_PROTO_TREE));

  *err = 0;

  packet_list_check_end();
  /* Don't freeze/thaw the list when doing live capture */
  /*packet_list_freeze();*/

  /*g_log(NULL, G_LOG_LEVEL_MESSAGE, "cf_continue_tail: %u new: %u", cf->count, to_read);*/

  epan_dissect_init(&edt, cf->epan, create_proto_tree, FALSE);

  TRY {
    gint64 data_offset = 0;
    column_info *cinfo;

    cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cf->cinfo : NULL;

    while (to_read != 0) {
      wtap_cleareof(cf->wth);
      if (!wtap_read(cf->wth, err, &err_info, &data_offset)) {
        break;
      }
      if (cf->state == FILE_READ_ABORTED) {
        /* Well, the user decided to exit Wireshark.  Break out of the
           loop, and let the code below (which is called even if there
           aren't any packets left to read) exit. */
        break;
      }
      if (read_packet(cf, dfcode, &edt, (column_info *) cinfo, data_offset) != -1) {
        newly_displayed_packets++;
      }
      to_read--;
    }
  }
  CATCH(OutOfMemoryError) {
    simple_message_box(ESD_TYPE_ERROR, NULL,
                   "More information and workarounds can be found at\n"
                   "https://wiki.wireshark.org/KnownBugs/OutOfMemory",
                   "Sorry, but Wireshark has run out of memory and has to terminate now.");
#if 0
    /* Could we close the current capture and free up memory from that? */
    return CF_READ_ABORTED;
#else
    /* we have to terminate, as we cannot recover from the memory error */
    exit(1);
#endif
  }
  ENDTRY;

  /* Update the file encapsulation; it might have changed based on the
     packets we've read. */
  cf->lnk_t = wtap_file_encap(cf->wth);

  /* Cleanup and release all dfilter resources */
  if (dfcode != NULL) {
    dfilter_free(dfcode);
  }

  epan_dissect_cleanup(&edt);

  /*g_log(NULL, G_LOG_LEVEL_MESSAGE, "cf_continue_tail: count %u state: %u err: %u",
    cf->count, cf->state, *err);*/

  /* Don't freeze/thaw the list when doing live capture */
  /*packet_list_thaw();*/
  /* With the new packet list the first packet
   * isn't automatically selected.
   */
  if (!cf->current_frame)
    packet_list_select_first_row();

  /* moving to the end of the packet list - if the user requested so and
     we have some new packets. */
  if (newly_displayed_packets && auto_scroll_live && cf->count != 0)
      packet_list_moveto_end();

  if (cf->state == FILE_READ_ABORTED) {
    /* Well, the user decided to exit Wireshark.  Return CF_READ_ABORTED
       so that our caller can kill off the capture child process;
       this will cause an EOF on the pipe from the child, so
       "cf_finish_tail()" will be called, and it will clean up
       and exit. */
    return CF_READ_ABORTED;
  } else if (*err != 0) {
    /* We got an error reading the capture file.
       XXX - pop up a dialog box instead? */
    if (err_info != NULL) {
      g_warning("Error \"%s\" while reading \"%s\" (\"%s\")",
                wtap_strerror(*err), cf->filename, err_info);
      g_free(err_info);
    } else {
      g_warning("Error \"%s\" while reading \"%s\"",
                wtap_strerror(*err), cf->filename);
    }
    return CF_READ_ERROR;
  } else
    return CF_READ_OK;
}

void
cf_fake_continue_tail(capture_file *cf) {
  cf->state = FILE_READ_DONE;
}

cf_read_status_t
cf_finish_tail(capture_file *cf, int *err)
{
  gchar     *err_info;
  gint64     data_offset;
  dfilter_t *dfcode;
  column_info *cinfo;
  epan_dissect_t edt;
  gboolean   create_proto_tree;
  guint      tap_flags;
  gboolean   compiled;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode, NULL);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();
  cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cf->cinfo : NULL;
  create_proto_tree =
    (dfcode != NULL || have_filtering_tap_listeners() || (tap_flags & TL_REQUIRES_PROTO_TREE));

  if (cf->wth == NULL) {
    cf_close(cf);
    return CF_READ_ERROR;
  }

  packet_list_check_end();
  /* Don't freeze/thaw the list when doing live capture */
  /*packet_list_freeze();*/

  epan_dissect_init(&edt, cf->epan, create_proto_tree, FALSE);

  while ((wtap_read(cf->wth, err, &err_info, &data_offset))) {
    if (cf->state == FILE_READ_ABORTED) {
      /* Well, the user decided to abort the read.  Break out of the
         loop, and let the code below (which is called even if there
         aren't any packets left to read) exit. */
      break;
    }
    read_packet(cf, dfcode, &edt, cinfo, data_offset);
  }

  /* Cleanup and release all dfilter resources */
  if (dfcode != NULL) {
    dfilter_free(dfcode);
  }

  epan_dissect_cleanup(&edt);

  /* Don't freeze/thaw the list when doing live capture */
  /*packet_list_thaw();*/

  if (cf->state == FILE_READ_ABORTED) {
    /* Well, the user decided to abort the read.  We're only called
       when the child capture process closes the pipe to us (meaning
       it's probably exited), so we can just close the capture
       file; we return CF_READ_ABORTED so our caller can do whatever
       is appropriate when that happens. */
    cf_close(cf);
    return CF_READ_ABORTED;
  }

  if (auto_scroll_live && cf->count != 0)
    packet_list_moveto_end();

  /* We're done reading sequentially through the file. */
  cf->state = FILE_READ_DONE;

  /* We're done reading sequentially through the file; close the
     sequential I/O side, to free up memory it requires. */
  wtap_sequential_close(cf->wth);

  /* Allow the protocol dissectors to free up memory that they
   * don't need after the sequential run-through of the packets. */
  postseq_cleanup_all_protocols();

  /* Update the file encapsulation; it might have changed based on the
     packets we've read. */
  cf->lnk_t = wtap_file_encap(cf->wth);

  /* Update the details in the file-set dialog, as the capture file
   * has likely grown since we first stat-ed it */
  fileset_update_file(cf->filename);

  if (*err != 0) {
    /* We got an error reading the capture file.
       XXX - pop up a dialog box? */
    if (err_info != NULL) {
      g_warning("Error \"%s\" while reading \"%s\" (\"%s\")",
                wtap_strerror(*err), cf->filename, err_info);
      g_free(err_info);
    } else {
      g_warning("Error \"%s\" while reading \"%s\"",
                wtap_strerror(*err), cf->filename);
    }
    return CF_READ_ERROR;
  } else {
    return CF_READ_OK;
  }
}
#endif /* HAVE_LIBPCAP */

gchar *
cf_get_display_name(capture_file *cf)
{
  gchar *displayname;

  /* Return a name to use in displays */
  if (!cf->is_tempfile) {
    /* Get the last component of the file name, and use that. */
    if (cf->filename) {
      displayname = g_filename_display_basename(cf->filename);
    } else {
      displayname=g_strdup("(No file)");
    }
  } else {
    /* The file we read is a temporary file from a live capture or
       a merge operation; we don't mention its name, but, if it's
       from a capture, give the source of the capture. */
    if (cf->source) {
      displayname = g_strdup(cf->source);
    } else {
      displayname = g_strdup("(Untitled)");
    }
  }
  return displayname;
}

void cf_set_tempfile_source(capture_file *cf, gchar *source) {
  if (cf->source) {
    g_free(cf->source);
  }

  if (source) {
    cf->source = g_strdup(source);
  } else {
    cf->source = g_strdup("");
  }
}

const gchar *cf_get_tempfile_source(capture_file *cf) {
  if (!cf->source) {
    return "";
  }

  return cf->source;
}

/* XXX - use a macro instead? */
int
cf_get_packet_count(capture_file *cf)
{
  return cf->count;
}

/* XXX - use a macro instead? */
gboolean
cf_is_tempfile(capture_file *cf)
{
  return cf->is_tempfile;
}

void cf_set_tempfile(capture_file *cf, gboolean is_tempfile)
{
  cf->is_tempfile = is_tempfile;
}


/* XXX - use a macro instead? */
void cf_set_drops_known(capture_file *cf, gboolean drops_known)
{
  cf->drops_known = drops_known;
}

/* XXX - use a macro instead? */
void cf_set_drops(capture_file *cf, guint32 drops)
{
  cf->drops = drops;
}

/* XXX - use a macro instead? */
gboolean cf_get_drops_known(capture_file *cf)
{
  return cf->drops_known;
}

/* XXX - use a macro instead? */
guint32 cf_get_drops(capture_file *cf)
{
  return cf->drops;
}

void cf_set_rfcode(capture_file *cf, dfilter_t *rfcode)
{
  cf->rfcode = rfcode;
}

static int
add_packet_to_packet_list(frame_data *fdata, capture_file *cf,
    epan_dissect_t *edt, dfilter_t *dfcode, column_info *cinfo,
    struct wtap_pkthdr *phdr, const guint8 *buf, gboolean add_to_packet_list)
{
  gint            row               = -1;

  frame_data_set_before_dissect(fdata, &cf->elapsed_time,
                                &cf->ref, cf->prev_dis);
  cf->prev_cap = fdata;

  if (dfcode != NULL) {
      epan_dissect_prime_dfilter(edt, dfcode);
  }
#if 0
  /* Prepare coloring rules, this ensures that display filter rules containing
   * frame.color_rule references are still processed.
   * TODO: actually detect that situation or maybe apply other optimizations? */
  if (edt->tree && color_filters_used()) {
    color_filters_prime_edt(edt);
    fdata->flags.need_colorize = 1;
  }
#endif

  /* Dissect the frame. */
  epan_dissect_run_with_taps(edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, buf), fdata, cinfo);

  /* If we don't have a display filter, set "passed_dfilter" to 1. */
  if (dfcode != NULL) {
    fdata->flags.passed_dfilter = dfilter_apply_edt(dfcode, edt) ? 1 : 0;

    if (fdata->flags.passed_dfilter) {
      /* This frame passed the display filter but it may depend on other
       * (potentially not displayed) frames.  Find those frames and mark them
       * as depended upon.
       */
      g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->frames);
    }
  } else
    fdata->flags.passed_dfilter = 1;

  if (fdata->flags.passed_dfilter || fdata->flags.ref_time)
    cf->displayed_count++;

  if (add_to_packet_list) {
    /* We fill the needed columns from new_packet_list */
      row = packet_list_append(cinfo, fdata);
  }

  if (fdata->flags.passed_dfilter || fdata->flags.ref_time)
  {
    frame_data_set_after_dissect(fdata, &cf->cum_bytes);
    cf->prev_dis = fdata;

    /* If we haven't yet seen the first frame, this is it.

       XXX - we must do this before we add the row to the display,
       as, if the display's GtkCList's selection mode is
       GTK_SELECTION_BROWSE, when the first entry is added to it,
       "cf_select_packet()" will be called, and it will fetch the row
       data for the 0th row, and will get a null pointer rather than
       "fdata", as "gtk_clist_append()" won't yet have returned and
       thus "gtk_clist_set_row_data()" won't yet have been called.

       We thus need to leave behind bread crumbs so that
       "cf_select_packet()" can find this frame.  See the comment
       in "cf_select_packet()". */
    if (cf->first_displayed == 0)
      cf->first_displayed = fdata->num;

    /* This is the last frame we've seen so far. */
    cf->last_displayed = fdata->num;
  }

  epan_dissect_reset(edt);
  return row;
}

/* read in a new packet */
/* returns the row of the new packet in the packet list or -1 if not displayed */
static int
read_packet(capture_file *cf, dfilter_t *dfcode, epan_dissect_t *edt,
            column_info *cinfo, gint64 offset)
{
  struct wtap_pkthdr *phdr = wtap_phdr(cf->wth);
  const guint8 *buf = wtap_buf_ptr(cf->wth);
  frame_data    fdlocal;
  guint32       framenum;
  frame_data   *fdata;
  gboolean      passed;
  int           row = -1;

  /* Add this packet's link-layer encapsulation type to cf->linktypes, if
     it's not already there.
     XXX - yes, this is O(N), so if every packet had a different
     link-layer encapsulation type, it'd be O(N^2) to read the file, but
     there are probably going to be a small number of encapsulation types
     in a file. */
  cf_add_encapsulation_type(cf, phdr->pkt_encap);

  /* The frame number of this packet is one more than the count of
     frames in the file so far. */
  framenum = cf->count + 1;

  frame_data_init(&fdlocal, framenum, phdr, offset, cf->cum_bytes);

  passed = TRUE;
  if (cf->rfcode) {
    epan_dissect_t rf_edt;

    epan_dissect_init(&rf_edt, cf->epan, TRUE, FALSE);
    epan_dissect_prime_dfilter(&rf_edt, cf->rfcode);
    epan_dissect_run(&rf_edt, cf->cd_t, phdr, frame_tvbuff_new(&fdlocal, buf), &fdlocal, NULL);
    passed = dfilter_apply_edt(cf->rfcode, &rf_edt);
    epan_dissect_cleanup(&rf_edt);
  }

  if (passed) {
    /* This does a shallow copy of fdlocal, which is good enough. */
    fdata = frame_data_sequence_add(cf->frames, &fdlocal);

    cf->count++;
    if (phdr->opt_comment != NULL)
      cf->packet_comment_count++;
    cf->f_datalen = offset + fdlocal.cap_len;

    if (!cf->redissecting) {
      row = add_packet_to_packet_list(fdata, cf, edt, dfcode,
                                      cinfo, phdr, buf, TRUE);
    }
  }

  return row;
}


typedef struct _callback_data_t {
  gint64           f_len;
  GTimeVal         start_time;
  progdlg_t       *progbar;
  GTimer          *prog_timer;
  gboolean         stop_flag;
} callback_data_t;


static gboolean
merge_callback(merge_event event, int num _U_,
               const merge_in_file_t in_files[], const guint in_file_count,
               void *data)
{
  guint i;
  callback_data_t *cb_data = (callback_data_t*) data;

  g_assert(cb_data != NULL);

  switch (event) {

    case MERGE_EVENT_INPUT_FILES_OPENED:
      /* do nothing */
      break;

    case MERGE_EVENT_FRAME_TYPE_SELECTED:
      /* do nothing */
      break;

    case MERGE_EVENT_READY_TO_MERGE:
      /* Get the sum of the sizes of all the files. */
      for (i = 0; i < in_file_count; i++)
        cb_data->f_len += in_files[i].size;

      cb_data->prog_timer = g_timer_new();
      g_timer_start(cb_data->prog_timer);

      g_get_current_time(&cb_data->start_time);
      break;

    case MERGE_EVENT_PACKET_WAS_READ:
      {
        gint64 data_offset = 0;

        /* Get the sum of the data offsets in all of the files. */
        data_offset = 0;
        for (i = 0; i < in_file_count; i++)
          data_offset += in_files[i].data_offset;

        /* Create the progress bar if necessary.
           We check on every iteration of the loop, so that it takes no
           longer than the standard time to create it (otherwise, for a
           large file, we might take considerably longer than that standard
           time in order to get to the next progress bar step). */
        if (cb_data->progbar == NULL) {
          cb_data->progbar = delayed_create_progress_dlg(NULL, "Merging", "files",
            FALSE, &cb_data->stop_flag, &cb_data->start_time, 0.0f);
        }

        /*
         * Update the progress bar, but do it only after
         * PROGBAR_UPDATE_INTERVAL has elapsed. Calling update_progress_dlg
         * and packets_bar_update will likely trigger UI paint events, which
         * might take a while depending on the platform and display. Reset
         * our timer *after* painting.
         */
        if (g_timer_elapsed(cb_data->prog_timer, NULL) > PROGBAR_UPDATE_INTERVAL) {
            float  progbar_val;
            gint64 file_pos = 0;
            /* Get the sum of the seek positions in all of the files. */
            for (i = 0; i < in_file_count; i++)
              file_pos += wtap_read_so_far(in_files[i].wth);

            progbar_val = (gfloat) file_pos / (gfloat) cb_data->f_len;
            if (progbar_val > 1.0f) {
              /* Some file probably grew while we were reading it.
                 That "shouldn't happen", so we'll just clip the progress
                 value at 1.0. */
              progbar_val = 1.0f;
            }

            if (cb_data->progbar != NULL) {
              gchar status_str[100];
              g_snprintf(status_str, sizeof(status_str),
                         "%" G_GINT64_MODIFIER "dKB of %" G_GINT64_MODIFIER "dKB",
                         file_pos / 1024, cb_data->f_len / 1024);
              update_progress_dlg(cb_data->progbar, progbar_val, status_str);
            }
            g_timer_start(cb_data->prog_timer);
        }
      }
      break;

    case MERGE_EVENT_DONE:
      /* We're done merging the files; destroy the progress bar if it was created. */
      if (cb_data->progbar != NULL)
        destroy_progress_dlg(cb_data->progbar);
      g_timer_destroy(cb_data->prog_timer);
      break;
  }

  return cb_data->stop_flag;
}



cf_status_t
cf_merge_files(char **out_filenamep, int in_file_count,
               char *const *in_filenames, int file_type, gboolean do_append)
{
  char                      *out_filename;
  char                      *tmpname;
  int                        out_fd;
  int                        err      = 0;
  gchar                     *err_info = NULL;
  guint                      err_fileno;
  merge_result               status;
  merge_progress_callback_t  cb;


  if (*out_filenamep != NULL) {
    out_filename = *out_filenamep;
    out_fd = ws_open(out_filename, O_CREAT|O_TRUNC|O_BINARY, 0600);
    if (out_fd == -1)
      err = errno;
  } else {
    out_fd = create_tempfile(&tmpname, "wireshark", NULL);
    if (out_fd == -1)
      err = errno;
    out_filename = g_strdup(tmpname);
    *out_filenamep = out_filename;
  }
  if (out_fd == -1) {
    cf_open_failure_alert_box(out_filename, err, NULL, TRUE, file_type);
    return CF_ERROR;
  }

  /* prepare our callback routine */
  cb.callback_func = merge_callback;
  cb.data = g_malloc0(sizeof(callback_data_t));

  /* merge the files */
  status = merge_files(out_fd, out_filename, file_type,
                       (const char *const *) in_filenames, in_file_count,
                       do_append, IDB_MERGE_MODE_ALL_SAME, 0 /* snaplen */,
                       "Wireshark", &cb, &err, &err_info, &err_fileno);

  g_free(cb.data);

  switch (status) {
    case MERGE_OK:
      break;

    case MERGE_USER_ABORTED:
      /* this isn't really an error, though we will return CF_ERROR later */
      break;

    case MERGE_ERR_CANT_OPEN_INFILE:
      cf_open_failure_alert_box(in_filenames[err_fileno], err, err_info,
                                FALSE, 0);
      ws_close(out_fd);
      break;

    case MERGE_ERR_CANT_OPEN_OUTFILE:
      cf_open_failure_alert_box(out_filename, err, err_info, TRUE,
                                file_type);
      ws_close(out_fd);
      break;

    case MERGE_ERR_CANT_READ_INFILE:      /* fall through */
    case MERGE_ERR_BAD_PHDR_INTERFACE_ID:
    case MERGE_ERR_CANT_WRITE_OUTFILE:
    case MERGE_ERR_CANT_CLOSE_OUTFILE:
    default:
      simple_error_message_box("%s", err_info ? err_info : "unknown error");
      break;
  }

  g_free(err_info);
  /* for general case, no need to close out_fd: file handle associated to this file
     descriptor was already closed by the call to wtap_dump_close() in merge_files() */

  if (status != MERGE_OK) {
    /* Callers aren't expected to treat an error or an explicit abort
       differently - we put up error dialogs ourselves, so they don't
       have to. */
    return CF_ERROR;
  } else
    return CF_OK;
}

cf_status_t
cf_filter_packets(capture_file *cf, gchar *dftext, gboolean force)
{
  const char *filter_new = dftext ? dftext : "";
  const char *filter_old = cf->dfilter ? cf->dfilter : "";
  dfilter_t  *dfcode;
  gchar      *err_msg;
  GTimeVal    start_time;

  /* if new filter equals old one, do nothing unless told to do so */
  if (!force && strcmp(filter_new, filter_old) == 0) {
    return CF_OK;
  }

  dfcode=NULL;

  if (dftext == NULL) {
    /* The new filter is an empty filter (i.e., display all packets).
     * so leave dfcode==NULL
     */
  } else {
    /*
     * We have a filter; make a copy of it (as we'll be saving it),
     * and try to compile it.
     */
    dftext = g_strdup(dftext);
    if (!dfilter_compile(dftext, &dfcode, &err_msg)) {
      /* The attempt failed; report an error. */
      simple_message_box(ESD_TYPE_ERROR, NULL,
          "See the help for a description of the display filter syntax.",
          "\"%s\" isn't a valid display filter: %s",
          dftext, err_msg);
      g_free(err_msg);
      g_free(dftext);
      return CF_ERROR;
    }

    /* Was it empty? */
    if (dfcode == NULL) {
      /* Yes - free the filter text, and set it to null. */
      g_free(dftext);
      dftext = NULL;
    }
  }

  /* We have a valid filter.  Replace the current filter. */
  g_free(cf->dfilter);
  cf->dfilter = dftext;
  g_get_current_time(&start_time);


  /* Now rescan the packet list, applying the new filter, but not
     throwing away information constructed on a previous pass. */
  if (cf->state != FILE_CLOSED) {
    if (dftext == NULL) {
      rescan_packets(cf, "Resetting", "Filter", FALSE);
    } else {
      rescan_packets(cf, "Filtering", dftext, FALSE);
    }
  }

  /* Cleanup and release all dfilter resources */
  dfilter_free(dfcode);

  return CF_OK;
}

void
cf_reftime_packets(capture_file *cf)
{
  ref_time_packets(cf);
}

void
cf_redissect_packets(capture_file *cf)
{
  if (cf->state != FILE_CLOSED) {
    rescan_packets(cf, "Reprocessing", "all packets", TRUE);
  }
}

gboolean
cf_read_record_r(capture_file *cf, const frame_data *fdata,
                 struct wtap_pkthdr *phdr, Buffer *buf)
{
  int    err;
  gchar *err_info;
  gchar *display_basename;

#ifdef WANT_PACKET_EDITOR
  /* if fdata->file_off == -1 it means packet was edited, and we must find data inside edited_frames tree */
  if (G_UNLIKELY(fdata->file_off == -1)) {
    const modified_frame_data *frame = (const modified_frame_data *) g_tree_lookup(cf->edited_frames, GINT_TO_POINTER(fdata->num));

    if (!frame) {
      simple_error_message_box("fdata->file_off == -1, but can't find modified frame.");
      return FALSE;
    }

    *phdr = frame->phdr;
    ws_buffer_assure_space(buf, frame->phdr.caplen);
    memcpy(ws_buffer_start_ptr(buf), frame->pd, frame->phdr.caplen);
    return TRUE;
  }
#endif

  if (!wtap_seek_read(cf->wth, fdata->file_off, phdr, buf, &err, &err_info)) {
    display_basename = g_filename_display_basename(cf->filename);
    switch (err) {

    case WTAP_ERR_BAD_FILE:
      simple_error_message_box("An error occurred while reading from the file \"%s\": %s.\n(%s)",
                 display_basename, wtap_strerror(err),
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    default:
      simple_error_message_box(
                 "An error occurred while reading from the file \"%s\": %s.",
                 display_basename, wtap_strerror(err));
      break;
    }
    g_free(display_basename);
    return FALSE;
  }
  return TRUE;
}

gboolean
cf_read_record(capture_file *cf, frame_data *fdata)
{
  return cf_read_record_r(cf, fdata, &cf->phdr, &cf->buf);
}

/* Rescan the list of packets, reconstructing the CList.

   "action" describes why we're doing this; it's used in the progress
   dialog box.

   "action_item" describes what we're doing; it's used in the progress
   dialog box.

   "redissect" is TRUE if we need to make the dissectors reconstruct
   any state information they have (because a preference that affects
   some dissector has changed, meaning some dissector might construct
   its state differently from the way it was constructed the last time). */
static void
rescan_packets(capture_file *cf, const char *action, const char *action_item, gboolean redissect)
{
  /* Rescan packets new packet list */
  guint32     framenum;
  frame_data *fdata;
  progdlg_t  *progbar = NULL;
  GTimer     *prog_timer = g_timer_new();
  int         count;
  frame_data *selected_frame, *preceding_frame, *following_frame, *prev_frame;
  int         selected_frame_num, preceding_frame_num, following_frame_num, prev_frame_num;
  gboolean    selected_frame_seen;
  float       progbar_val;
  GTimeVal    start_time;
  gchar       status_str[100];
  epan_dissect_t  edt;
  dfilter_t  *dfcode;
  column_info *cinfo;
  gboolean    create_proto_tree;
  guint       tap_flags;
  gboolean    add_to_packet_list = FALSE;
  gboolean    compiled;
  guint32     frames_count;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode, NULL);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();
  cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cf->cinfo : NULL;
  create_proto_tree =
    (dfcode != NULL || have_filtering_tap_listeners() || (tap_flags & TL_REQUIRES_PROTO_TREE));

  reset_tap_listeners();
  /* Which frame, if any, is the currently selected frame?
     XXX - should the selected frame or the focus frame be the "current"
     frame, that frame being the one from which "Find Frame" searches
     start? */
  selected_frame = cf->current_frame;

  /* Mark frame num as not found */
  selected_frame_num = -1;

  /* Freeze the packet list while we redo it, so we don't get any
     screen updates while it happens. */
  packet_list_freeze();

  if (redissect) {
    /* We need to re-initialize all the state information that protocols
       keep, because some preference that controls a dissector has changed,
       which might cause the state information to be constructed differently
       by that dissector. */

    /* We might receive new packets while redissecting, and we don't
       want to dissect those before their time. */
    cf->redissecting = TRUE;

    /* 'reset' dissection session */
    epan_free(cf->epan);
    if (cf->edt && cf->edt->pi.fd) {
      /* All pointers in "per frame proto data" for the currently selected
         packet are allocated in wmem_file_scope() and deallocated in epan_free().
         Free them here to avoid unintended usage in packet_list_clear(). */
      frame_data_destroy(cf->edt->pi.fd);
    }
    cf->epan = ws_epan_new(cf);
    cf->cinfo.epan = cf->epan;

    /* A new Lua tap listener may be registered in lua_prime_all_fields()
       called via epan_new() / init_dissection() when reloading Lua plugins. */
    if (!create_proto_tree && have_filtering_tap_listeners()) {
      create_proto_tree = TRUE;
    }

    /* We need to redissect the packets so we have to discard our old
     * packet list store. */
    packet_list_clear();
    add_to_packet_list = TRUE;
  }

  /* We don't yet know which will be the first and last frames displayed. */
  cf->first_displayed = 0;
  cf->last_displayed = 0;

  /* We currently don't display any packets */
  cf->displayed_count = 0;

  /* Iterate through the list of frames.  Call a routine for each frame
     to check whether it should be displayed and, if so, add it to
     the display list. */
  cf->ref = NULL;
  cf->prev_dis = NULL;
  cf->prev_cap = NULL;
  cf->cum_bytes = 0;

  cf_callback_invoke(cf_cb_file_rescan_started, cf);

  g_timer_start(prog_timer);
  /* Count of packets at which we've looked. */
  count = 0;
  /* Progress so far. */
  progbar_val = 0.0f;

  cf->stop_flag = FALSE;
  g_get_current_time(&start_time);

  /* no previous row yet */
  prev_frame_num = -1;
  prev_frame = NULL;

  preceding_frame_num = -1;
  preceding_frame = NULL;
  following_frame_num = -1;
  following_frame = NULL;

  selected_frame_seen = FALSE;

  frames_count = cf->count;

  epan_dissect_init(&edt, cf->epan, create_proto_tree, FALSE);

  for (framenum = 1; framenum <= frames_count; framenum++) {
    fdata = frame_data_sequence_find(cf->frames, framenum);

    /* Create the progress bar if necessary.
       We check on every iteration of the loop, so that it takes no
       longer than the standard time to create it (otherwise, for a
       large file, we might take considerably longer than that standard
       time in order to get to the next progress bar step). */
    if (progbar == NULL)
      progbar = delayed_create_progress_dlg(cf->window, action, action_item, TRUE,
                                            &cf->stop_flag,
                                            &start_time,
                                            progbar_val);

    /*
     * Update the progress bar, but do it only after PROGBAR_UPDATE_INTERVAL
     * has elapsed. Calling update_progress_dlg and packets_bar_update will
     * likely trigger UI paint events, which might take a while depending on
     * the platform and display. Reset our timer *after* painting.
     */
    if (g_timer_elapsed(prog_timer, NULL) > PROGBAR_UPDATE_INTERVAL) {
      /* let's not divide by zero. I should never be started
       * with count == 0, so let's assert that
       */
      g_assert(cf->count > 0);
      progbar_val = (gfloat) count / frames_count;

      if (progbar != NULL) {
        g_snprintf(status_str, sizeof(status_str),
                  "%4u of %u frames", count, frames_count);
        update_progress_dlg(progbar, progbar_val, status_str);
      }

      g_timer_start(prog_timer);
    }

    if (cf->stop_flag) {
      /* Well, the user decided to abort the filtering.  Just stop.

         XXX - go back to the previous filter?  Users probably just
         want not to wait for a filtering operation to finish;
         unless we cancel by having no filter, reverting to the
         previous filter will probably be even more expensive than
         continuing the filtering, as it involves going back to the
         beginning and filtering, and even with no filter we currently
         have to re-generate the entire clist, which is also expensive.

         I'm not sure what Network Monitor does, but it doesn't appear
         to give you an unfiltered display if you cancel. */
      break;
    }

    count++;

    if (redissect) {
      /* Since all state for the frame was destroyed, mark the frame
       * as not visited, free the GSList referring to the state
       * data (the per-frame data itself was freed by
       * "init_dissection()"), and null out the GSList pointer. */
      frame_data_reset(fdata);
      frames_count = cf->count;
    }

    /* Frame dependencies from the previous dissection/filtering are no longer valid. */
    fdata->flags.dependent_of_displayed = 0;

    if (!cf_read_record(cf, fdata))
      break; /* error reading the frame */

    /* If the previous frame is displayed, and we haven't yet seen the
       selected frame, remember that frame - it's the closest one we've
       yet seen before the selected frame. */
    if (prev_frame_num != -1 && !selected_frame_seen && prev_frame->flags.passed_dfilter) {
      preceding_frame_num = prev_frame_num;
      preceding_frame = prev_frame;
    }

    add_packet_to_packet_list(fdata, cf, &edt, dfcode,
                                    cinfo, &cf->phdr,
                                    ws_buffer_start_ptr(&cf->buf),
                                    add_to_packet_list);

    /* If this frame is displayed, and this is the first frame we've
       seen displayed after the selected frame, remember this frame -
       it's the closest one we've yet seen at or after the selected
       frame. */
    if (fdata->flags.passed_dfilter && selected_frame_seen && following_frame_num == -1) {
      following_frame_num = fdata->num;
      following_frame = fdata;
    }
    if (fdata == selected_frame) {
      selected_frame_seen = TRUE;
      if (fdata->flags.passed_dfilter)
          selected_frame_num = fdata->num;
    }

    /* Remember this frame - it'll be the previous frame
       on the next pass through the loop. */
    prev_frame_num = fdata->num;
    prev_frame = fdata;
  }

  epan_dissect_cleanup(&edt);

  /* We are done redissecting the packet list. */
  cf->redissecting = FALSE;

  if (redissect) {
      frames_count = cf->count;
    /* Clear out what remains of the visited flags and per-frame data
       pointers.

       XXX - that may cause various forms of bogosity when dissecting
       these frames, as they won't have been seen by this sequential
       pass, but the only alternative I see is to keep scanning them
       even though the user requested that the scan stop, and that
       would leave the user stuck with an Wireshark grinding on
       until it finishes.  Should we just stick them with that? */
    for (; framenum <= frames_count; framenum++) {
      fdata = frame_data_sequence_find(cf->frames, framenum);
      frame_data_reset(fdata);
    }
  }

  /* We're done filtering the packets; destroy the progress bar if it
     was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);
  g_timer_destroy(prog_timer);

  /* Unfreeze the packet list. */
  if (!add_to_packet_list)
    packet_list_recreate_visible_rows();

  /* Compute the time it took to filter the file */
  compute_elapsed(cf, &start_time);

  packet_list_thaw();

  cf_callback_invoke(cf_cb_file_rescan_finished, cf);

  if (selected_frame_num == -1) {
    /* The selected frame didn't pass the filter. */
    if (selected_frame == NULL) {
      /* That's because there *was* no selected frame.  Make the first
         displayed frame the current frame. */
      selected_frame_num = 0;
    } else {
      /* Find the nearest displayed frame to the selected frame (whether
         it's before or after that frame) and make that the current frame.
         If the next and previous displayed frames are equidistant from the
         selected frame, choose the next one. */
      g_assert(following_frame == NULL ||
               following_frame->num >= selected_frame->num);
      g_assert(preceding_frame == NULL ||
               preceding_frame->num <= selected_frame->num);
      if (following_frame == NULL) {
        /* No frame after the selected frame passed the filter, so we
           have to select the last displayed frame before the selected
           frame. */
        selected_frame_num = preceding_frame_num;
        selected_frame = preceding_frame;
      } else if (preceding_frame == NULL) {
        /* No frame before the selected frame passed the filter, so we
           have to select the first displayed frame after the selected
           frame. */
        selected_frame_num = following_frame_num;
        selected_frame = following_frame;
      } else {
        /* Frames before and after the selected frame passed the filter, so
           we'll select the previous frame */
        selected_frame_num = preceding_frame_num;
        selected_frame = preceding_frame;
      }
    }
  }

  if (selected_frame_num == -1) {
    /* There are no frames displayed at all. */
    cf_unselect_packet(cf);
  } else {
    /* Either the frame that was selected passed the filter, or we've
       found the nearest displayed frame to that frame.  Select it, make
       it the focus row, and make it visible. */
    /* Set to invalid to force update of packet list and packet details */
    cf->current_row = -1;
    if (selected_frame_num == 0) {
      packet_list_select_first_row();
    }else{
      if (!packet_list_select_row_from_data(selected_frame)) {
        /* We didn't find a row corresponding to this frame.
           This means that the frame isn't being displayed currently,
           so we can't select it. */
        simple_message_box(ESD_TYPE_INFO, NULL,
                           "The capture file is probably not fully dissected.",
                           "End of capture exceeded.");
      }
    }
  }

  /* Cleanup and release all dfilter resources */
  dfilter_free(dfcode);
}


/*
 * Scan through all frame data and recalculate the ref time
 * without rereading the file.
 * XXX - do we need a progres bar or is this fast enough?
 */
static void
ref_time_packets(capture_file *cf)
{
  guint32     framenum;
  frame_data *fdata;
  nstime_t rel_ts;

  cf->ref = NULL;
  cf->prev_dis = NULL;
  cf->cum_bytes = 0;

  for (framenum = 1; framenum <= cf->count; framenum++) {
    fdata = frame_data_sequence_find(cf->frames, framenum);

    /* just add some value here until we know if it is being displayed or not */
    fdata->cum_bytes = cf->cum_bytes + fdata->pkt_len;

    /*
     *Timestamps
     */

    /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
    if (cf->ref == NULL)
        cf->ref = fdata;
      /* if this frames is marked as a reference time frame, reset
        firstsec and firstusec to this frame */
    if (fdata->flags.ref_time)
        cf->ref = fdata;

    /* If we don't have the time stamp of the previous displayed packet,
     it's because this is the first displayed packet.  Save the time
     stamp of this packet as the time stamp of the previous displayed
     packet. */
    if (cf->prev_dis == NULL) {
        cf->prev_dis = fdata;
    }

    /* Get the time elapsed between the first packet and this packet. */
    fdata->frame_ref_num = (fdata != cf->ref) ? cf->ref->num : 0;
    nstime_delta(&rel_ts, &fdata->abs_ts, &cf->ref->abs_ts);

    /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
    if ((gint32)cf->elapsed_time.secs < rel_ts.secs
        || ((gint32)cf->elapsed_time.secs == rel_ts.secs && (gint32)cf->elapsed_time.nsecs < rel_ts.nsecs)) {
        cf->elapsed_time = rel_ts;
    }

    /* If this frame is displayed, get the time elapsed between the
     previous displayed packet and this packet. */
    if ( fdata->flags.passed_dfilter ) {
        fdata->prev_dis_num = cf->prev_dis->num;
        cf->prev_dis = fdata;
    }

    /*
     * Byte counts
     */
    if ( (fdata->flags.passed_dfilter) || (fdata->flags.ref_time) ) {
        /* This frame either passed the display filter list or is marked as
        a time reference frame.  All time reference frames are displayed
        even if they don't pass the display filter */
        if (fdata->flags.ref_time) {
            /* if this was a TIME REF frame we should reset the cum_bytes field */
            cf->cum_bytes = fdata->pkt_len;
            fdata->cum_bytes = cf->cum_bytes;
        } else {
            /* increase cum_bytes with this packets length */
            cf->cum_bytes += fdata->pkt_len;
        }
    }
  }
}

typedef enum {
  PSP_FINISHED,
  PSP_STOPPED,
  PSP_FAILED
} psp_return_t;

static psp_return_t
process_specified_records(capture_file *cf, packet_range_t *range,
    const char *string1, const char *string2, gboolean terminate_is_stop,
    gboolean (*callback)(capture_file *, frame_data *,
                         struct wtap_pkthdr *, const guint8 *, void *),
    void *callback_args,
    gboolean show_progress_bar)
{
  guint32          framenum;
  frame_data      *fdata;
  Buffer           buf;
  psp_return_t     ret     = PSP_FINISHED;

  progdlg_t       *progbar = NULL;
  GTimer          *prog_timer = g_timer_new();
  int              progbar_count;
  float            progbar_val;
  GTimeVal         progbar_start_time;
  gchar            progbar_status_str[100];
  range_process_e  process_this;
  struct wtap_pkthdr phdr;

  wtap_phdr_init(&phdr);
  ws_buffer_init(&buf, 1500);

  g_timer_start(prog_timer);
  /* Count of packets at which we've looked. */
  progbar_count = 0;
  /* Progress so far. */
  progbar_val = 0.0f;

  cf->stop_flag = FALSE;
  g_get_current_time(&progbar_start_time);

  if (range != NULL)
    packet_range_process_init(range);

  /* Iterate through all the packets, printing the packets that
     were selected by the current display filter.  */
  for (framenum = 1; framenum <= cf->count; framenum++) {
    fdata = frame_data_sequence_find(cf->frames, framenum);

    /* Create the progress bar if necessary.
       We check on every iteration of the loop, so that it takes no
       longer than the standard time to create it (otherwise, for a
       large file, we might take considerably longer than that standard
       time in order to get to the next progress bar step). */
    if (show_progress_bar && progbar == NULL)
      progbar = delayed_create_progress_dlg(cf->window, string1, string2,
                                            terminate_is_stop,
                                            &cf->stop_flag,
                                            &progbar_start_time,
                                            progbar_val);

    /*
     * Update the progress bar, but do it only after PROGBAR_UPDATE_INTERVAL
     * has elapsed. Calling update_progress_dlg and packets_bar_update will
     * likely trigger UI paint events, which might take a while depending on
     * the platform and display. Reset our timer *after* painting.
     */
    if (progbar && g_timer_elapsed(prog_timer, NULL) > PROGBAR_UPDATE_INTERVAL) {
      /* let's not divide by zero. I should never be started
       * with count == 0, so let's assert that
       */
      g_assert(cf->count > 0);
      progbar_val = (gfloat) progbar_count / cf->count;

      g_snprintf(progbar_status_str, sizeof(progbar_status_str),
                  "%4u of %u packets", progbar_count, cf->count);
      update_progress_dlg(progbar, progbar_val, progbar_status_str);

      g_timer_start(prog_timer);
    }

    if (cf->stop_flag) {
      /* Well, the user decided to abort the operation.  Just stop,
         and arrange to return PSP_STOPPED to our caller, so they know
         it was stopped explicitly. */
      ret = PSP_STOPPED;
      break;
    }

    progbar_count++;

    if (range != NULL) {
      /* do we have to process this packet? */
      process_this = packet_range_process_packet(range, fdata);
      if (process_this == range_process_next) {
        /* this packet uninteresting, continue with next one */
        continue;
      } else if (process_this == range_processing_finished) {
        /* all interesting packets processed, stop the loop */
        break;
      }
    }

    /* Get the packet */
    if (!cf_read_record_r(cf, fdata, &phdr, &buf)) {
      /* Attempt to get the packet failed. */
      ret = PSP_FAILED;
      break;
    }
    /* Process the packet */
    if (!callback(cf, fdata, &phdr, ws_buffer_start_ptr(&buf), callback_args)) {
      /* Callback failed.  We assume it reported the error appropriately. */
      ret = PSP_FAILED;
      break;
    }
  }

  /* We're done printing the packets; destroy the progress bar if
     it was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);
  g_timer_destroy(prog_timer);

  wtap_phdr_cleanup(&phdr);
  ws_buffer_free(&buf);

  return ret;
}

typedef struct {
  epan_dissect_t edt;
  column_info *cinfo;
} retap_callback_args_t;

static gboolean
retap_packet(capture_file *cf, frame_data *fdata,
             struct wtap_pkthdr *phdr, const guint8 *pd,
             void *argsp)
{
  retap_callback_args_t *args = (retap_callback_args_t *)argsp;

  epan_dissect_run_with_taps(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, args->cinfo);
  epan_dissect_reset(&args->edt);

  return TRUE;
}

cf_read_status_t
cf_retap_packets(capture_file *cf)
{
  packet_range_t        range;
  retap_callback_args_t callback_args;
  gboolean              construct_protocol_tree;
  gboolean              filtering_tap_listeners;
  guint                 tap_flags;
  psp_return_t          ret;

  /* Presumably the user closed the capture file. */
  if (cf == NULL) {
    return CF_READ_ABORTED;
  }

  cf_callback_invoke(cf_cb_file_retap_started, cf);

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  tap_flags = union_of_tap_listener_flags();

  /* If any tap listeners have filters, or require the protocol tree,
     construct the protocol tree. */
  construct_protocol_tree = filtering_tap_listeners ||
                            (tap_flags & TL_REQUIRES_PROTO_TREE);

  /* If any tap listeners require the columns, construct them. */
  callback_args.cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cf->cinfo : NULL;

  /* Reset the tap listeners. */
  reset_tap_listeners();

  epan_dissect_init(&callback_args.edt, cf->epan, construct_protocol_tree, FALSE);

  /* Iterate through the list of packets, dissecting all packets and
     re-running the taps. */
  packet_range_init(&range, cf);
  packet_range_process_init(&range);

  ret = process_specified_records(cf, &range, "Recalculating statistics on",
                                  "all packets", TRUE, retap_packet,
                                  &callback_args, TRUE);

  epan_dissect_cleanup(&callback_args.edt);

  cf_callback_invoke(cf_cb_file_retap_finished, cf);

  switch (ret) {
  case PSP_FINISHED:
    /* Completed successfully. */
    return CF_READ_OK;

  case PSP_STOPPED:
    /* Well, the user decided to abort the refiltering.
       Return CF_READ_ABORTED so our caller knows they did that. */
    return CF_READ_ABORTED;

  case PSP_FAILED:
    /* Error while retapping. */
    return CF_READ_ERROR;
  }

  g_assert_not_reached();
  return CF_READ_OK;
}

typedef struct {
  print_args_t *print_args;
  gboolean      print_header_line;
  char         *header_line_buf;
  int           header_line_buf_len;
  gboolean      print_formfeed;
  gboolean      print_separator;
  char         *line_buf;
  int           line_buf_len;
  gint         *col_widths;
  int           num_visible_cols;
  gint         *visible_cols;
  epan_dissect_t edt;
} print_callback_args_t;

static gboolean
print_packet(capture_file *cf, frame_data *fdata,
             struct wtap_pkthdr *phdr, const guint8 *pd,
             void *argsp)
{
  print_callback_args_t *args = (print_callback_args_t *)argsp;
  int             i;
  char           *cp;
  int             line_len;
  int             column_len;
  int             cp_off;
  char            bookmark_name[9+10+1];  /* "__frameNNNNNNNNNN__\0" */
  char            bookmark_title[6+10+1]; /* "Frame NNNNNNNNNN__\0"  */
  col_item_t*     col_item;

  /* Fill in the column information if we're printing the summary
     information. */
  if (args->print_args->print_summary) {
    col_custom_prime_edt(&args->edt, &cf->cinfo);
    epan_dissect_run(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, &cf->cinfo);
    epan_dissect_fill_in_columns(&args->edt, FALSE, TRUE);
  } else
    epan_dissect_run(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, NULL);

  if (args->print_formfeed) {
    if (!new_page(args->print_args->stream))
      goto fail;
  } else {
      if (args->print_separator) {
        if (!print_line(args->print_args->stream, 0, ""))
          goto fail;
      }
  }

  /*
   * We generate bookmarks, if the output format supports them.
   * The name is "__frameN__".
   */
  g_snprintf(bookmark_name, sizeof bookmark_name, "__frame%u__", fdata->num);

  if (args->print_args->print_summary) {
    if (!args->print_args->print_col_headings)
        args->print_header_line = FALSE;
    if (args->print_header_line) {
      if (!print_line(args->print_args->stream, 0, args->header_line_buf))
        goto fail;
      args->print_header_line = FALSE;  /* we might not need to print any more */
    }
    cp = &args->line_buf[0];
    line_len = 0;
    for (i = 0; i < args->num_visible_cols; i++) {
      col_item = &cf->cinfo.columns[args->visible_cols[i]];
      /* Find the length of the string for this column. */
      column_len = (int) strlen(col_item->col_data);
      if (args->col_widths[i] > column_len)
         column_len = args->col_widths[i];

      /* Make sure there's room in the line buffer for the column; if not,
         double its length. */
      line_len += column_len + 1;   /* "+1" for space */
      if (line_len > args->line_buf_len) {
        cp_off = (int) (cp - args->line_buf);
        args->line_buf_len = 2 * line_len;
        args->line_buf = (char *)g_realloc(args->line_buf, args->line_buf_len + 1);
        cp = args->line_buf + cp_off;
      }

      /* Right-justify the packet number column. */
      if (col_item->col_fmt == COL_NUMBER)
        g_snprintf(cp, column_len+1, "%*s", args->col_widths[i], col_item->col_data);
      else
        g_snprintf(cp, column_len+1, "%-*s", args->col_widths[i], col_item->col_data);
      cp += column_len;
      if (i != args->num_visible_cols - 1)
        *cp++ = ' ';
    }
    *cp = '\0';

    /*
     * Generate a bookmark, using the summary line as the title.
     */
    if (!print_bookmark(args->print_args->stream, bookmark_name,
                        args->line_buf))
      goto fail;

    if (!print_line(args->print_args->stream, 0, args->line_buf))
      goto fail;
  } else {
    /*
     * Generate a bookmark, using "Frame N" as the title, as we're not
     * printing the summary line.
     */
    g_snprintf(bookmark_title, sizeof bookmark_title, "Frame %u", fdata->num);
    if (!print_bookmark(args->print_args->stream, bookmark_name,
                        bookmark_title))
      goto fail;
  } /* if (print_summary) */

  if (args->print_args->print_dissections != print_dissections_none) {
    if (args->print_args->print_summary) {
      /* Separate the summary line from the tree with a blank line. */
      if (!print_line(args->print_args->stream, 0, ""))
        goto fail;
    }

    /* Print the information in that tree. */
    if (!proto_tree_print(args->print_args, &args->edt, NULL, args->print_args->stream))
      goto fail;

    /* Print a blank line if we print anything after this (aka more than one packet). */
    args->print_separator = TRUE;

    /* Print a header line if we print any more packet summaries */
    if (args->print_args->print_col_headings)
        args->print_header_line = TRUE;
  }

  if (args->print_args->print_hex) {
    if (args->print_args->print_summary || (args->print_args->print_dissections != print_dissections_none)) {
      if (!print_line(args->print_args->stream, 0, ""))
        goto fail;
    }
    /* Print the full packet data as hex. */
    if (!print_hex_data(args->print_args->stream, &args->edt))
      goto fail;

    /* Print a blank line if we print anything after this (aka more than one packet). */
    args->print_separator = TRUE;

    /* Print a header line if we print any more packet summaries */
    if (args->print_args->print_col_headings)
        args->print_header_line = TRUE;
  } /* if (args->print_args->print_dissections != print_dissections_none) */

  epan_dissect_reset(&args->edt);

  /* do we want to have a formfeed between each packet from now on? */
  if (args->print_args->print_formfeed) {
    args->print_formfeed = TRUE;
  }

  return TRUE;

fail:
  epan_dissect_reset(&args->edt);
  return FALSE;
}

cf_print_status_t
cf_print_packets(capture_file *cf, print_args_t *print_args,
                 gboolean show_progress_bar)
{
  print_callback_args_t callback_args;
  gint          data_width;
  char         *cp;
  int           i, cp_off, column_len, line_len;
  int           num_visible_col = 0, last_visible_col = 0, visible_col_count;
  psp_return_t  ret;
  GList        *clp;
  fmt_data     *cfmt;
  gboolean      proto_tree_needed;

  callback_args.print_args = print_args;
  callback_args.print_header_line = print_args->print_col_headings;
  callback_args.header_line_buf = NULL;
  callback_args.header_line_buf_len = 256;
  callback_args.print_formfeed = FALSE;
  callback_args.print_separator = FALSE;
  callback_args.line_buf = NULL;
  callback_args.line_buf_len = 256;
  callback_args.col_widths = NULL;
  callback_args.num_visible_cols = 0;
  callback_args.visible_cols = NULL;

  if (!print_preamble(print_args->stream, cf->filename, get_ws_vcs_version_info())) {
    destroy_print_stream(print_args->stream);
    return CF_PRINT_WRITE_ERROR;
  }

  if (print_args->print_summary) {
    /* We're printing packet summaries.  Allocate the header line buffer
       and get the column widths. */
    callback_args.header_line_buf = (char *)g_malloc(callback_args.header_line_buf_len + 1);

    /* Find the number of visible columns and the last visible column */
    for (i = 0; i < prefs.num_cols; i++) {

        clp = g_list_nth(prefs.col_list, i);
        if (clp == NULL) /* Sanity check, Invalid column requested */
            continue;

        cfmt = (fmt_data *) clp->data;
        if (cfmt->visible) {
            num_visible_col++;
            last_visible_col = i;
        }
    }

    /* Find the widths for each of the columns - maximum of the
       width of the title and the width of the data - and construct
       a buffer with a line containing the column titles. */
    callback_args.num_visible_cols = num_visible_col;
    callback_args.col_widths = (gint *) g_malloc(sizeof(gint) * num_visible_col);
    callback_args.visible_cols = (gint *) g_malloc(sizeof(gint) * num_visible_col);
    cp = &callback_args.header_line_buf[0];
    line_len = 0;
    visible_col_count = 0;
    for (i = 0; i < cf->cinfo.num_cols; i++) {

      clp = g_list_nth(prefs.col_list, i);
      if (clp == NULL) /* Sanity check, Invalid column requested */
          continue;

      cfmt = (fmt_data *) clp->data;
      if (cfmt->visible == FALSE)
          continue;

      /* Save the order of visible columns */
      callback_args.visible_cols[visible_col_count] = i;

      /* Don't pad the last column. */
      if (i == last_visible_col)
        callback_args.col_widths[visible_col_count] = 0;
      else {
        callback_args.col_widths[visible_col_count] = (gint) strlen(cf->cinfo.columns[i].col_title);
        data_width = get_column_char_width(get_column_format(i));
        if (data_width > callback_args.col_widths[visible_col_count])
          callback_args.col_widths[visible_col_count] = data_width;
      }

      /* Find the length of the string for this column. */
      column_len = (int) strlen(cf->cinfo.columns[i].col_title);
      if (callback_args.col_widths[i] > column_len)
        column_len = callback_args.col_widths[visible_col_count];

      /* Make sure there's room in the line buffer for the column; if not,
         double its length. */
      line_len += column_len + 1;   /* "+1" for space */
      if (line_len > callback_args.header_line_buf_len) {
        cp_off = (int) (cp - callback_args.header_line_buf);
        callback_args.header_line_buf_len = 2 * line_len;
        callback_args.header_line_buf = (char *)g_realloc(callback_args.header_line_buf,
                                                  callback_args.header_line_buf_len + 1);
        cp = callback_args.header_line_buf + cp_off;
      }

      /* Right-justify the packet number column. */
/*      if (cf->cinfo.col_fmt[i] == COL_NUMBER)
        g_snprintf(cp, column_len+1, "%*s", callback_args.col_widths[visible_col_count], cf->cinfo.columns[i].col_title);
      else*/
      g_snprintf(cp, column_len+1, "%-*s", callback_args.col_widths[visible_col_count], cf->cinfo.columns[i].col_title);
      cp += column_len;
      if (i != cf->cinfo.num_cols - 1)
        *cp++ = ' ';

      visible_col_count++;
    }
    *cp = '\0';

    /* Now start out the main line buffer with the same length as the
       header line buffer. */
    callback_args.line_buf_len = callback_args.header_line_buf_len;
    callback_args.line_buf = (char *)g_malloc(callback_args.line_buf_len + 1);
  } /* if (print_summary) */

  /* Create the protocol tree, and make it visible, if we're printing
     the dissection or the hex data.
     XXX - do we need it if we're just printing the hex data? */
  proto_tree_needed =
      callback_args.print_args->print_dissections != print_dissections_none ||
      callback_args.print_args->print_hex ||
      have_custom_cols(&cf->cinfo) || have_field_extractors();
  epan_dissect_init(&callback_args.edt, cf->epan, proto_tree_needed, proto_tree_needed);

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_records(cf, &print_args->range, "Printing",
                                  "selected packets", TRUE, print_packet,
                                  &callback_args, show_progress_bar);
  epan_dissect_cleanup(&callback_args.edt);
  g_free(callback_args.header_line_buf);
  g_free(callback_args.line_buf);
  g_free(callback_args.col_widths);
  g_free(callback_args.visible_cols);

  switch (ret) {

  case PSP_FINISHED:
    /* Completed successfully. */
    break;

  case PSP_STOPPED:
    /* Well, the user decided to abort the printing.

       XXX - note that what got generated before they did that
       will get printed if we're piping to a print program; we'd
       have to write to a file and then hand that to the print
       program to make it actually not print anything. */
    break;

  case PSP_FAILED:
    /* Error while printing.

       XXX - note that what got generated before they did that
       will get printed if we're piping to a print program; we'd
       have to write to a file and then hand that to the print
       program to make it actually not print anything. */
    destroy_print_stream(print_args->stream);
    return CF_PRINT_WRITE_ERROR;
  }

  if (!print_finale(print_args->stream)) {
    destroy_print_stream(print_args->stream);
    return CF_PRINT_WRITE_ERROR;
  }

  if (!destroy_print_stream(print_args->stream))
    return CF_PRINT_WRITE_ERROR;

  return CF_PRINT_OK;
}

typedef struct {
  FILE *fh;
  epan_dissect_t edt;
  print_args_t *print_args;
} write_packet_callback_args_t;

static gboolean
write_pdml_packet(capture_file *cf, frame_data *fdata,
                  struct wtap_pkthdr *phdr, const guint8 *pd,
          void *argsp)
{
  write_packet_callback_args_t *args = (write_packet_callback_args_t *)argsp;

  /* Create the protocol tree, but don't fill in the column information. */
  epan_dissect_run(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, NULL);

  /* Write out the information in that tree. */
  write_pdml_proto_tree(NULL, NULL, &args->edt, args->fh);

  epan_dissect_reset(&args->edt);

  return !ferror(args->fh);
}

cf_print_status_t
cf_write_pdml_packets(capture_file *cf, print_args_t *print_args)
{
  write_packet_callback_args_t callback_args;
  FILE         *fh;
  psp_return_t  ret;

  fh = ws_fopen(print_args->file, "w");
  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_pdml_preamble(fh, cf->filename);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  callback_args.fh = fh;
  callback_args.print_args = print_args;
  epan_dissect_init(&callback_args.edt, cf->epan, TRUE, TRUE);

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_records(cf, &print_args->range, "Writing PDML",
                                  "selected packets", TRUE,
                                  write_pdml_packet, &callback_args, TRUE);

  epan_dissect_cleanup(&callback_args.edt);

  switch (ret) {

  case PSP_FINISHED:
    /* Completed successfully. */
    break;

  case PSP_STOPPED:
    /* Well, the user decided to abort the printing. */
    break;

  case PSP_FAILED:
    /* Error while printing. */
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  write_pdml_finale(fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* XXX - check for an error */
  fclose(fh);

  return CF_PRINT_OK;
}

static gboolean
write_psml_packet(capture_file *cf, frame_data *fdata,
                  struct wtap_pkthdr *phdr, const guint8 *pd,
          void *argsp)
{
  write_packet_callback_args_t *args = (write_packet_callback_args_t *)argsp;

  /* Fill in the column information */
  col_custom_prime_edt(&args->edt, &cf->cinfo);
  epan_dissect_run(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, &cf->cinfo);
  epan_dissect_fill_in_columns(&args->edt, FALSE, TRUE);

  /* Write out the column information. */
  write_psml_columns(&args->edt, args->fh);

  epan_dissect_reset(&args->edt);

  return !ferror(args->fh);
}

cf_print_status_t
cf_write_psml_packets(capture_file *cf, print_args_t *print_args)
{
  write_packet_callback_args_t callback_args;
  FILE         *fh;
  psp_return_t  ret;

  gboolean proto_tree_needed;

  fh = ws_fopen(print_args->file, "w");
  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_psml_preamble(&cf->cinfo, fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  callback_args.fh = fh;
  callback_args.print_args = print_args;

  /* Fill in the column information, only create the protocol tree
     if having custom columns or field extractors. */
  proto_tree_needed = have_custom_cols(&cf->cinfo) || have_field_extractors();
  epan_dissect_init(&callback_args.edt, cf->epan, proto_tree_needed, proto_tree_needed);

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_records(cf, &print_args->range, "Writing PSML",
                                  "selected packets", TRUE,
                                  write_psml_packet, &callback_args, TRUE);

  epan_dissect_cleanup(&callback_args.edt);

  switch (ret) {

  case PSP_FINISHED:
    /* Completed successfully. */
    break;

  case PSP_STOPPED:
    /* Well, the user decided to abort the printing. */
    break;

  case PSP_FAILED:
    /* Error while printing. */
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  write_psml_finale(fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* XXX - check for an error */
  fclose(fh);

  return CF_PRINT_OK;
}

static gboolean
write_csv_packet(capture_file *cf, frame_data *fdata,
                 struct wtap_pkthdr *phdr, const guint8 *pd,
                 void *argsp)
{
  write_packet_callback_args_t *args = (write_packet_callback_args_t *)argsp;

  /* Fill in the column information */
  col_custom_prime_edt(&args->edt, &cf->cinfo);
  epan_dissect_run(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, &cf->cinfo);
  epan_dissect_fill_in_columns(&args->edt, FALSE, TRUE);

  /* Write out the column information. */
  write_csv_columns(&args->edt, args->fh);

  epan_dissect_reset(&args->edt);

  return !ferror(args->fh);
}

cf_print_status_t
cf_write_csv_packets(capture_file *cf, print_args_t *print_args)
{
  write_packet_callback_args_t callback_args;
  gboolean        proto_tree_needed;
  FILE         *fh;
  psp_return_t  ret;

  fh = ws_fopen(print_args->file, "w");
  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_csv_column_titles(&cf->cinfo, fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  callback_args.fh = fh;
  callback_args.print_args = print_args;

  /* only create the protocol tree if having custom columns or field extractors. */
  proto_tree_needed = have_custom_cols(&cf->cinfo) || have_field_extractors();
  epan_dissect_init(&callback_args.edt, cf->epan, proto_tree_needed, proto_tree_needed);

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_records(cf, &print_args->range, "Writing CSV",
                                  "selected packets", TRUE,
                                  write_csv_packet, &callback_args, TRUE);

  epan_dissect_cleanup(&callback_args.edt);

  switch (ret) {

  case PSP_FINISHED:
    /* Completed successfully. */
    break;

  case PSP_STOPPED:
    /* Well, the user decided to abort the printing. */
    break;

  case PSP_FAILED:
    /* Error while printing. */
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* XXX - check for an error */
  fclose(fh);

  return CF_PRINT_OK;
}

static gboolean
carrays_write_packet(capture_file *cf, frame_data *fdata,
             struct wtap_pkthdr *phdr,
             const guint8 *pd, void *argsp)
{
  write_packet_callback_args_t *args = (write_packet_callback_args_t *)argsp;

  epan_dissect_run(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, NULL);
  write_carrays_hex_data(fdata->num, args->fh, &args->edt);
  epan_dissect_reset(&args->edt);

  return !ferror(args->fh);
}

cf_print_status_t
cf_write_carrays_packets(capture_file *cf, print_args_t *print_args)
{
  write_packet_callback_args_t callback_args;
  FILE         *fh;
  psp_return_t  ret;

  fh = ws_fopen(print_args->file, "w");

  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  callback_args.fh = fh;
  callback_args.print_args = print_args;
  epan_dissect_init(&callback_args.edt, cf->epan, TRUE, TRUE);

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_records(cf, &print_args->range,
                                  "Writing C Arrays",
                                  "selected packets", TRUE,
                                  carrays_write_packet, &callback_args, TRUE);

  epan_dissect_cleanup(&callback_args.edt);

  switch (ret) {
  case PSP_FINISHED:
    /* Completed successfully. */
    break;
  case PSP_STOPPED:
    /* Well, the user decided to abort the printing. */
    break;
  case PSP_FAILED:
    /* Error while printing. */
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  fclose(fh);
  return CF_PRINT_OK;
}

static gboolean
write_json_packet(capture_file *cf, frame_data *fdata,
                  struct wtap_pkthdr *phdr, const guint8 *pd,
          void *argsp)
{
  write_packet_callback_args_t *args = (write_packet_callback_args_t *)argsp;

  /* Create the protocol tree, but don't fill in the column information. */
  epan_dissect_run(&args->edt, cf->cd_t, phdr, frame_tvbuff_new(fdata, pd), fdata, NULL);

  /* Write out the information in that tree. */
  write_json_proto_tree(NULL, args->print_args, NULL, &args->edt, args->fh);

  epan_dissect_reset(&args->edt);

  return !ferror(args->fh);
}

cf_print_status_t
cf_write_json_packets(capture_file *cf, print_args_t *print_args)
{
  write_packet_callback_args_t callback_args;
  FILE         *fh;
  psp_return_t  ret;

  fh = ws_fopen(print_args->file, "w");
  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_json_preamble(fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  callback_args.fh = fh;
  callback_args.print_args = print_args;
  epan_dissect_init(&callback_args.edt, cf->epan, TRUE, TRUE);

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_records(cf, &print_args->range, "Writing PDML",
                                  "selected packets", TRUE,
                                  write_json_packet, &callback_args, TRUE);

  epan_dissect_cleanup(&callback_args.edt);

  switch (ret) {

  case PSP_FINISHED:
    /* Completed successfully. */
    break;

  case PSP_STOPPED:
    /* Well, the user decided to abort the printing. */
    break;

  case PSP_FAILED:
    /* Error while printing. */
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  write_json_finale(fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* XXX - check for an error */
  fclose(fh);

  return CF_PRINT_OK;
}

gboolean
cf_find_packet_protocol_tree(capture_file *cf, const char *string,
                             search_direction dir)
{
  match_data mdata;

  mdata.string = string;
  mdata.string_len = strlen(string);
  return find_packet(cf, match_protocol_tree, &mdata, dir);
}

gboolean
cf_find_string_protocol_tree(capture_file *cf, proto_tree *tree,  match_data *mdata)
{
  mdata->frame_matched = FALSE;
  mdata->string = convert_string_case(cf->sfilter, cf->case_type);
  mdata->string_len = strlen(mdata->string);
  mdata->cf = cf;
  /* Iterate through all the nodes looking for matching text */
  proto_tree_children_foreach(tree, match_subtree_text, mdata);
  return mdata->frame_matched ? MR_MATCHED : MR_NOTMATCHED;
}

static match_result
match_protocol_tree(capture_file *cf, frame_data *fdata, void *criterion)
{
  match_data     *mdata = (match_data *)criterion;
  epan_dissect_t  edt;

  /* Load the frame's data. */
  if (!cf_read_record(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  /* Construct the protocol tree, including the displayed text */
  epan_dissect_init(&edt, cf->epan, TRUE, TRUE);
  /* We don't need the column information */
  epan_dissect_run(&edt, cf->cd_t, &cf->phdr, frame_tvbuff_new_buffer(fdata, &cf->buf), fdata, NULL);

  /* Iterate through all the nodes, seeing if they have text that matches. */
  mdata->cf = cf;
  mdata->frame_matched = FALSE;
  proto_tree_children_foreach(edt.tree, match_subtree_text, mdata);
  epan_dissect_cleanup(&edt);
  return mdata->frame_matched ? MR_MATCHED : MR_NOTMATCHED;
}

static void
match_subtree_text(proto_node *node, gpointer data)
{
  match_data   *mdata      = (match_data *) data;
  const gchar  *string     = mdata->string;
  size_t        string_len = mdata->string_len;
  capture_file *cf         = mdata->cf;
  field_info   *fi         = PNODE_FINFO(node);
  gchar         label_str[ITEM_LABEL_LENGTH];
  gchar        *label_ptr;
  size_t        label_len;
  guint32       i;
  guint8        c_char;
  size_t        c_match    = 0;

  /* dissection with an invisible proto tree? */
  g_assert(fi);

  if (mdata->frame_matched) {
    /* We already had a match; don't bother doing any more work. */
    return;
  }

  /* Don't match invisible entries. */
  if (PROTO_ITEM_IS_HIDDEN(node))
    return;

  /* was a free format label produced? */
  if (fi->rep) {
    label_ptr = fi->rep->representation;
  } else {
    /* no, make a generic label */
    label_ptr = label_str;
    proto_item_fill_label(fi, label_str);
  }

  if (cf->regex) {
    if (g_regex_match(cf->regex, label_ptr, (GRegexMatchFlags) 0, NULL)) {
      mdata->frame_matched = TRUE;
      mdata->finfo = fi;
      return;
    }
  } else {
    /* Does that label match? */
    label_len = strlen(label_ptr);
    for (i = 0; i < label_len; i++) {
      c_char = label_ptr[i];
      if (cf->case_type)
        c_char = g_ascii_toupper(c_char);
      if (c_char == string[c_match]) {
        c_match++;
        if (c_match == string_len) {
          /* No need to look further; we have a match */
          mdata->frame_matched = TRUE;
          mdata->finfo = fi;
          return;
        }
      } else
        c_match = 0;
    }
  }

  /* Recurse into the subtree, if it exists */
  if (node->first_child != NULL)
    proto_tree_children_foreach(node, match_subtree_text, mdata);
}

gboolean
cf_find_packet_summary_line(capture_file *cf, const char *string,
                            search_direction dir)
{
  match_data mdata;

  mdata.string = string;
  mdata.string_len = strlen(string);
  return find_packet(cf, match_summary_line, &mdata, dir);
}

static match_result
match_summary_line(capture_file *cf, frame_data *fdata, void *criterion)
{
  match_data     *mdata      = (match_data *)criterion;
  const gchar    *string     = mdata->string;
  size_t          string_len = mdata->string_len;
  epan_dissect_t  edt;
  const char     *info_column;
  size_t          info_column_len;
  match_result    result     = MR_NOTMATCHED;
  gint            colx;
  guint32         i;
  guint8          c_char;
  size_t          c_match    = 0;

  /* Load the frame's data. */
  if (!cf_read_record(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  /* Don't bother constructing the protocol tree */
  epan_dissect_init(&edt, cf->epan, FALSE, FALSE);
  /* Get the column information */
  epan_dissect_run(&edt, cf->cd_t, &cf->phdr, frame_tvbuff_new_buffer(fdata, &cf->buf), fdata,
                   &cf->cinfo);

  /* Find the Info column */
  for (colx = 0; colx < cf->cinfo.num_cols; colx++) {
    if (cf->cinfo.columns[colx].fmt_matx[COL_INFO]) {
      /* Found it.  See if we match. */
      info_column = edt.pi.cinfo->columns[colx].col_data;
      info_column_len = strlen(info_column);
      if (cf->regex) {
        if (g_regex_match(cf->regex, info_column, (GRegexMatchFlags) 0, NULL)) {
          result = MR_MATCHED;
          break;
        }
      } else {
        for (i = 0; i < info_column_len; i++) {
          c_char = info_column[i];
          if (cf->case_type)
            c_char = g_ascii_toupper(c_char);
          if (c_char == string[c_match]) {
            c_match++;
            if (c_match == string_len) {
              result = MR_MATCHED;
              break;
            }
          } else
            c_match = 0;
        }
      }
      break;
    }
  }
  epan_dissect_cleanup(&edt);
  return result;
}

typedef struct {
    const guint8 *data;
    size_t        data_len;
} cbs_t;    /* "Counted byte string" */


/*
 * The current match_* routines only support ASCII case insensitivity and don't
 * convert UTF-8 inputs to UTF-16 for matching.
 *
 * We could modify them to use the GLib Unicode routines or the International
 * Components for Unicode library but it's not apparent that we could do so
 * without consuming a lot more CPU and memory or that searching would be
 * significantly better.
 */

gboolean
cf_find_packet_data(capture_file *cf, const guint8 *string, size_t string_size,
                    search_direction dir)
{
  cbs_t info;

  info.data = string;
  info.data_len = string_size;

  /* Regex, String or hex search? */
  if (cf->regex) {
    /* Regular Expression search */
    return find_packet(cf, match_regex, NULL, dir);
  } else if (cf->string) {
    /* String search - what type of string? */
    switch (cf->scs_type) {

    case SCS_NARROW_AND_WIDE:
      return find_packet(cf, match_narrow_and_wide, &info, dir);

    case SCS_NARROW:
      return find_packet(cf, match_narrow, &info, dir);

    case SCS_WIDE:
      return find_packet(cf, match_wide, &info, dir);

    default:
      g_assert_not_reached();
      return FALSE;
    }
  } else
    return find_packet(cf, match_binary, &info, dir);
}

static match_result
match_narrow_and_wide(capture_file *cf, frame_data *fdata, void *criterion)
{
  cbs_t        *info       = (cbs_t *)criterion;
  const guint8 *ascii_text = info->data;
  size_t        textlen    = info->data_len;
  match_result  result;
  guint32       buf_len;
  guint8       *pd;
  guint32       i;
  guint8        c_char;
  size_t        c_match    = 0;

  /* Load the frame's data. */
  if (!cf_read_record(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->cap_len;
  pd = ws_buffer_start_ptr(&cf->buf);
  i = 0;
  while (i < buf_len) {
    c_char = pd[i];
    if (cf->case_type)
      c_char = g_ascii_toupper(c_char);
    if (c_char != '\0') {
      if (c_char == ascii_text[c_match]) {
        c_match += 1;
        if (c_match == textlen) {
          result = MR_MATCHED;
          cf->search_pos = i; /* Save the position of the last character
                                 for highlighting the field. */
          cf->search_len = (guint32)textlen;
          break;
        }
      }
      else {
        g_assert(i>=c_match);
        i -= (guint32)c_match;
        c_match = 0;
      }
    }
    i += 1;
  }
  return result;
}

static match_result
match_narrow(capture_file *cf, frame_data *fdata, void *criterion)
{
  guint8       *pd;
  cbs_t        *info       = (cbs_t *)criterion;
  const guint8 *ascii_text = info->data;
  size_t        textlen    = info->data_len;
  match_result  result;
  guint32       buf_len;
  guint32       i;
  guint8        c_char;
  size_t        c_match    = 0;

  /* Load the frame's data. */
  if (!cf_read_record(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->cap_len;
  pd = ws_buffer_start_ptr(&cf->buf);
  i = 0;
  while (i < buf_len) {
    c_char = pd[i];
    if (cf->case_type)
      c_char = g_ascii_toupper(c_char);
    if (c_char == ascii_text[c_match]) {
      c_match += 1;
      if (c_match == textlen) {
        result = MR_MATCHED;
        cf->search_pos = i; /* Save the position of the last character
                               for highlighting the field. */
        cf->search_len = (guint32)textlen;
        break;
      }
    }
    else {
      g_assert(i>=c_match);
      i -= (guint32)c_match;
      c_match = 0;
    }
    i += 1;
  }

  return result;
}

static match_result
match_wide(capture_file *cf, frame_data *fdata, void *criterion)
{
  cbs_t        *info       = (cbs_t *)criterion;
  const guint8 *ascii_text = info->data;
  size_t        textlen    = info->data_len;
  match_result  result;
  guint32       buf_len;
  guint8       *pd;
  guint32       i;
  guint8        c_char;
  size_t        c_match    = 0;

  /* Load the frame's data. */
  if (!cf_read_record(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->cap_len;
  pd = ws_buffer_start_ptr(&cf->buf);
  i = 0;
  while (i < buf_len) {
    c_char = pd[i];
    if (cf->case_type)
      c_char = g_ascii_toupper(c_char);
    if (c_char == ascii_text[c_match]) {
      c_match += 1;
      if (c_match == textlen) {
        result = MR_MATCHED;
        cf->search_pos = i; /* Save the position of the last character
                               for highlighting the field. */
        cf->search_len = (guint32)textlen;
        break;
      }
      i += 1;
    }
    else {
      g_assert(i>=(c_match*2));
      i -= (guint32)c_match*2;
      c_match = 0;
    }
    i += 1;
  }
  return result;
}

static match_result
match_binary(capture_file *cf, frame_data *fdata, void *criterion)
{
  cbs_t        *info        = (cbs_t *)criterion;
  const guint8 *binary_data = info->data;
  size_t        datalen     = info->data_len;
  match_result  result;
  guint32       buf_len;
  guint8       *pd;
  guint32       i;
  size_t        c_match     = 0;

  /* Load the frame's data. */
  if (!cf_read_record(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->cap_len;
  pd = ws_buffer_start_ptr(&cf->buf);
  i = 0;
  while (i < buf_len) {
    if (pd[i] == binary_data[c_match]) {
      c_match += 1;
      if (c_match == datalen) {
        result = MR_MATCHED;
        cf->search_pos = i; /* Save the position of the last character
                               for highlighting the field. */
        cf->search_len = (guint32)datalen;
        break;
      }
    }
    else {
      g_assert(i>=c_match);
      i -= (guint32)c_match;
      c_match = 0;
    }
    i += 1;
  }
  return result;
}

static match_result
match_regex(capture_file *cf, frame_data *fdata, void *criterion _U_)
{
    match_result  result = MR_NOTMATCHED;
    GMatchInfo   *match_info = NULL;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    if (g_regex_match_full(cf->regex, ws_buffer_start_ptr(&cf->buf), fdata->cap_len,
                           0, (GRegexMatchFlags) 0, &match_info, NULL))
    {
        gint start_pos = 0, end_pos = 0;
        g_match_info_fetch_pos (match_info, 0, &start_pos, &end_pos);
        cf->search_pos = end_pos - 1;
        cf->search_len = end_pos - start_pos;
        result = MR_MATCHED;
    }
    return result;
}

gboolean
cf_find_packet_dfilter(capture_file *cf, dfilter_t *sfcode,
                       search_direction dir)
{
  return find_packet(cf, match_dfilter, sfcode, dir);
}

gboolean
cf_find_packet_dfilter_string(capture_file *cf, const char *filter,
                              search_direction dir)
{
  dfilter_t *sfcode;
  gboolean   result;

  if (!dfilter_compile(filter, &sfcode, NULL)) {
     /*
      * XXX - this shouldn't happen, as the filter string is machine
      * generated
      */
    return FALSE;
  }
  if (sfcode == NULL) {
    /*
     * XXX - this shouldn't happen, as the filter string is machine
     * generated.
     */
    return FALSE;
  }
  result = find_packet(cf, match_dfilter, sfcode, dir);
  dfilter_free(sfcode);
  return result;
}

static match_result
match_dfilter(capture_file *cf, frame_data *fdata, void *criterion)
{
  dfilter_t      *sfcode = (dfilter_t *)criterion;
  epan_dissect_t  edt;
  match_result    result;

  /* Load the frame's data. */
  if (!cf_read_record(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  epan_dissect_init(&edt, cf->epan, TRUE, FALSE);
  epan_dissect_prime_dfilter(&edt, sfcode);
  epan_dissect_run(&edt, cf->cd_t, &cf->phdr, frame_tvbuff_new_buffer(fdata, &cf->buf), fdata, NULL);
  result = dfilter_apply_edt(sfcode, &edt) ? MR_MATCHED : MR_NOTMATCHED;
  epan_dissect_cleanup(&edt);
  return result;
}

gboolean
cf_find_packet_marked(capture_file *cf, search_direction dir)
{
  return find_packet(cf, match_marked, NULL, dir);
}

static match_result
match_marked(capture_file *cf _U_, frame_data *fdata, void *criterion _U_)
{
  return fdata->flags.marked ? MR_MATCHED : MR_NOTMATCHED;
}

gboolean
cf_find_packet_time_reference(capture_file *cf, search_direction dir)
{
  return find_packet(cf, match_time_reference, NULL, dir);
}

static match_result
match_time_reference(capture_file *cf _U_, frame_data *fdata, void *criterion _U_)
{
  return fdata->flags.ref_time ? MR_MATCHED : MR_NOTMATCHED;
}

static gboolean
find_packet(capture_file *cf,
            match_result (*match_function)(capture_file *, frame_data *, void *),
            void *criterion, search_direction dir)
{
  frame_data  *start_fd;
  guint32      framenum;
  frame_data  *fdata;
  frame_data  *new_fd = NULL;
  progdlg_t   *progbar = NULL;
  GTimer      *prog_timer = g_timer_new();
  int          count;
  gboolean     found;
  float        progbar_val;
  GTimeVal     start_time;
  gchar        status_str[100];
  const char  *title;
  match_result result;

  start_fd = cf->current_frame;
  if (start_fd != NULL)  {
    /* Iterate through the list of packets, starting at the packet we've
       picked, calling a routine to run the filter on the packet, see if
       it matches, and stop if so.  */
    count = 0;
    framenum = start_fd->num;

    g_timer_start(prog_timer);
    /* Progress so far. */
    progbar_val = 0.0f;

    cf->stop_flag = FALSE;
    g_get_current_time(&start_time);

    title = cf->sfilter?cf->sfilter:"";
    for (;;) {
      /* Create the progress bar if necessary.
         We check on every iteration of the loop, so that it takes no
         longer than the standard time to create it (otherwise, for a
         large file, we might take considerably longer than that standard
         time in order to get to the next progress bar step). */
      if (progbar == NULL)
         progbar = delayed_create_progress_dlg(cf->window, "Searching", title,
           FALSE, &cf->stop_flag, &start_time, progbar_val);

      /*
       * Update the progress bar, but do it only after PROGBAR_UPDATE_INTERVAL
       * has elapsed. Calling update_progress_dlg and packets_bar_update will
       * likely trigger UI paint events, which might take a while depending on
       * the platform and display. Reset our timer *after* painting.
       */
      if (g_timer_elapsed(prog_timer, NULL) > PROGBAR_UPDATE_INTERVAL) {
        /* let's not divide by zero. I should never be started
         * with count == 0, so let's assert that
         */
        g_assert(cf->count > 0);

        progbar_val = (gfloat) count / cf->count;

        g_snprintf(status_str, sizeof(status_str),
                    "%4u of %u packets", count, cf->count);
        update_progress_dlg(progbar, progbar_val, status_str);

        g_timer_start(prog_timer);
      }

      if (cf->stop_flag) {
        /* Well, the user decided to abort the search.  Go back to the
           frame where we started. */
        new_fd = start_fd;
        break;
      }

      /* Go past the current frame. */
      if (dir == SD_BACKWARD) {
        /* Go on to the previous frame. */
        if (framenum == 1) {
          /*
           * XXX - other apps have a bit more of a detailed message
           * for this, and instead of offering "OK" and "Cancel",
           * they offer things such as "Continue" and "Cancel";
           * we need an API for popping up alert boxes with
           * {Verb} and "Cancel".
           */

          if (prefs.gui_find_wrap)
          {
              statusbar_push_temporary_msg("Search reached the beginning. Continuing at end.");
              framenum = cf->count;     /* wrap around */
          }
          else
          {
              statusbar_push_temporary_msg("Search reached the beginning.");
              framenum = start_fd->num; /* stay on previous packet */
          }
        } else
          framenum--;
      } else {
        /* Go on to the next frame. */
        if (framenum == cf->count) {
          if (prefs.gui_find_wrap)
          {
              statusbar_push_temporary_msg("Search reached the end. Continuing at beginning.");
              framenum = 1;             /* wrap around */
          }
          else
          {
              statusbar_push_temporary_msg("Search reached the end.");
              framenum = start_fd->num; /* stay on previous packet */
          }
        } else
          framenum++;
      }
      fdata = frame_data_sequence_find(cf->frames, framenum);

      count++;

      /* Is this packet in the display? */
      if (fdata->flags.passed_dfilter) {
        /* Yes.  Does it match the search criterion? */
        result = (*match_function)(cf, fdata, criterion);
        if (result == MR_ERROR) {
          /* Error; our caller has reported the error.  Go back to the frame
             where we started. */
          new_fd = start_fd;
          break;
        } else if (result == MR_MATCHED) {
          /* Yes.  Go to the new frame. */
          new_fd = fdata;
          break;
        }
      }

      if (fdata == start_fd) {
        /* We're back to the frame we were on originally, and that frame
           doesn't match the search filter.  The search failed. */
        break;
      }
    }

    /* We're done scanning the packets; destroy the progress bar if it
       was created. */
    if (progbar != NULL)
      destroy_progress_dlg(progbar);
    g_timer_destroy(prog_timer);
  }

  if (new_fd != NULL) {
    /* Find and select */
    cf->search_in_progress = TRUE;
    found = packet_list_select_row_from_data(new_fd);
    cf->search_in_progress = FALSE;
    cf->search_pos = 0; /* Reset the position */
    cf->search_len = 0; /* Reset length */
    if (!found) {
      /* We didn't find a row corresponding to this frame.
         This means that the frame isn't being displayed currently,
         so we can't select it. */
      simple_message_box(ESD_TYPE_INFO, NULL,
                         "The capture file is probably not fully dissected.",
                         "End of capture exceeded.");
      return FALSE;
    }
    return TRUE;    /* success */
  } else
    return FALSE;   /* failure */
}

gboolean
cf_goto_frame(capture_file *cf, guint fnumber)
{
  frame_data *fdata;

  if (cf == NULL || cf->frames == NULL) {
    /* we don't have a loaded capture file - fix for bugs 11810 & 11989 */
    statusbar_push_temporary_msg("There is no file loaded");
    return FALSE;   /* we failed to go to that packet */
  }

  fdata = frame_data_sequence_find(cf->frames, fnumber);

  if (fdata == NULL) {
    /* we didn't find a packet with that packet number */
    statusbar_push_temporary_msg("There is no packet number %u.", fnumber);
    return FALSE;   /* we failed to go to that packet */
  }
  if (!fdata->flags.passed_dfilter) {
    /* that packet currently isn't displayed */
    /* XXX - add it to the set of displayed packets? */
    statusbar_push_temporary_msg("Packet number %u isn't displayed.", fnumber);
    return FALSE;   /* we failed to go to that packet */
  }

  if (!packet_list_select_row_from_data(fdata)) {
    /* We didn't find a row corresponding to this frame.
       This means that the frame isn't being displayed currently,
       so we can't select it. */
    simple_message_box(ESD_TYPE_INFO, NULL,
                       "The capture file is probably not fully dissected.",
                       "End of capture exceeded.");
    return FALSE;
  }
  return TRUE;  /* we got to that packet */
}

gboolean
cf_goto_top_frame(void)
{
  /* Find and select */
  packet_list_select_first_row();
  return TRUE;  /* we got to that packet */
}

gboolean
cf_goto_bottom_frame(void)
{
  /* Find and select */
  packet_list_select_last_row();
  return TRUE;  /* we got to that packet */
}

/*
 * Go to frame specified by currently selected protocol tree item.
 */
gboolean
cf_goto_framenum(capture_file *cf)
{
  header_field_info *hfinfo;
  guint32            framenum;

  if (cf->finfo_selected) {
    hfinfo = cf->finfo_selected->hfinfo;
    g_assert(hfinfo);
    if (hfinfo->type == FT_FRAMENUM) {
      framenum = fvalue_get_uinteger(&cf->finfo_selected->value);
      if (framenum != 0)
        return cf_goto_frame(cf, framenum);
      }
  }

  return FALSE;
}

/* Select the packet on a given row. */
void
cf_select_packet(capture_file *cf, int row)
{
  epan_dissect_t *old_edt;
  frame_data     *fdata;

  /* Get the frame data struct pointer for this frame */
  fdata = packet_list_get_row_data(row);

  if (fdata == NULL) {
    /* XXX - if a GtkCList's selection mode is GTK_SELECTION_BROWSE, when
       the first entry is added to it by "real_insert_row()", that row
       is selected (see "real_insert_row()", in "ui/gtk/gtkclist.c", in both
       our version and the vanilla GTK+ version).

       This means that a "select-row" signal is emitted; this causes
       "packet_list_select_cb()" to be called, which causes "cf_select_packet()"
       to be called.

       "cf_select_packet()" fetches, above, the data associated with the
       row that was selected; however, as "gtk_clist_append()", which
       called "real_insert_row()", hasn't yet returned, we haven't yet
       associated any data with that row, so we get back a null pointer.

       We can't assume that there's only one frame in the frame list,
       either, as we may be filtering the display.

       We therefore assume that, if "row" is 0, i.e. the first row
       is being selected, and "cf->first_displayed" equals
       "cf->last_displayed", i.e. there's only one frame being
       displayed, that frame is the frame we want.

       This means we have to set "cf->first_displayed" and
       "cf->last_displayed" before adding the row to the
       GtkCList; see the comment in "add_packet_to_packet_list()". */

       if (row == 0 && cf->first_displayed == cf->last_displayed)
         fdata = frame_data_sequence_find(cf->frames, cf->first_displayed);
  }

  /* If fdata _still_ isn't set simply give up. */
  if (fdata == NULL) {
    return;
  }

  /* Get the data in that frame. */
  if (!cf_read_record (cf, fdata)) {
    return;
  }

  /* Record that this frame is the current frame. */
  cf->current_frame = fdata;
  cf->current_row = row;

  old_edt = cf->edt;
  /* Create the logical protocol tree. */
  /* We don't need the columns here. */
  cf->edt = epan_dissect_new(cf->epan, TRUE, TRUE);

  tap_build_interesting(cf->edt);
  epan_dissect_run(cf->edt, cf->cd_t, &cf->phdr, frame_tvbuff_new_buffer(cf->current_frame, &cf->buf),
                   cf->current_frame, NULL);

  dfilter_macro_build_ftv_cache(cf->edt->tree);

  cf_callback_invoke(cf_cb_packet_selected, cf);

  if (old_edt != NULL)
    epan_dissect_free(old_edt);

}

/* Unselect the selected packet, if any. */
void
cf_unselect_packet(capture_file *cf)
{
  epan_dissect_t *old_edt = cf->edt;

  cf->edt = NULL;

  /* No packet is selected. */
  cf->current_frame = NULL;
  cf->current_row = 0;

  cf_callback_invoke(cf_cb_packet_unselected, cf);

  /* No protocol tree means no selected field. */
  cf_unselect_field(cf);

  /* Destroy the epan_dissect_t for the unselected packet. */
  if (old_edt != NULL)
    epan_dissect_free(old_edt);
}

/* Unset the selected protocol tree field, if any. */
void
cf_unselect_field(capture_file *cf)
{
  cf->finfo_selected = NULL;

  cf_callback_invoke(cf_cb_field_unselected, cf);
}

/*
 * Mark a particular frame.
 */
void
cf_mark_frame(capture_file *cf, frame_data *frame)
{
  if (! frame->flags.marked) {
    frame->flags.marked = TRUE;
    if (cf->count > cf->marked_count)
      cf->marked_count++;
  }
}

/*
 * Unmark a particular frame.
 */
void
cf_unmark_frame(capture_file *cf, frame_data *frame)
{
  if (frame->flags.marked) {
    frame->flags.marked = FALSE;
    if (cf->marked_count > 0)
      cf->marked_count--;
  }
}

/*
 * Ignore a particular frame.
 */
void
cf_ignore_frame(capture_file *cf, frame_data *frame)
{
  if (! frame->flags.ignored) {
    frame->flags.ignored = TRUE;
    if (cf->count > cf->ignored_count)
      cf->ignored_count++;
  }
}

/*
 * Un-ignore a particular frame.
 */
void
cf_unignore_frame(capture_file *cf, frame_data *frame)
{
  if (frame->flags.ignored) {
    frame->flags.ignored = FALSE;
    if (cf->ignored_count > 0)
      cf->ignored_count--;
  }
}

/*
 * Read the comment in SHB block
 */

const gchar *
cf_read_shb_comment(capture_file *cf)
{
  wtap_block_t shb_inf;
  char *shb_comment;

  /* Get the SHB. */
  /* XXX - support multiple SHBs */
  shb_inf = wtap_file_get_shb(cf->wth);

  /* Get the first comment from the SHB. */
  /* XXX - support multiple comments */
  if (wtap_block_get_nth_string_option_value(shb_inf, OPT_COMMENT, 0, &shb_comment) != WTAP_OPTTYPE_SUCCESS)
    return NULL;
  return shb_comment;
}

void
cf_update_capture_comment(capture_file *cf, gchar *comment)
{
  wtap_block_t shb_inf;
  gchar *shb_comment;

  /* Get the SHB. */
  /* XXX - support multiple SHBs */
  shb_inf = wtap_file_get_shb(cf->wth);

  /* Get the first comment from the SHB. */
  /* XXX - support multiple comments */
  if (wtap_block_get_nth_string_option_value(shb_inf, OPT_COMMENT, 0, &shb_comment) != WTAP_OPTTYPE_SUCCESS) {
    /* There's no comment - add one. */
    wtap_block_add_string_option(shb_inf, OPT_COMMENT, comment, strlen(comment));
  } else {
    /* See if the comment has changed or not */
    if (strcmp(shb_comment, comment) == 0) {
      g_free(comment);
      return;
    }

    /* The comment has changed, let's update it */
    wtap_block_set_nth_string_option_value(shb_inf, OPT_COMMENT, 0, comment, strlen(comment));
  }
  /* Mark the file as having unsaved changes */
  cf->unsaved_changes = TRUE;
}

static const char *
cf_get_user_packet_comment(capture_file *cf, const frame_data *fd)
{
  if (cf->frames_user_comments)
     return (const char *)g_tree_lookup(cf->frames_user_comments, fd);

  /* g_warning? */
  return NULL;
}

char *
cf_get_comment(capture_file *cf, const frame_data *fd)
{
  char *comment;

  /* fetch user comment */
  if (fd->flags.has_user_comment)
    return g_strdup(cf_get_user_packet_comment(cf, fd));

  /* fetch phdr comment */
  if (fd->flags.has_phdr_comment) {
    struct wtap_pkthdr phdr; /* Packet header */
    Buffer buf; /* Packet data */

    wtap_phdr_init(&phdr);
    ws_buffer_init(&buf, 1500);

    if (!cf_read_record_r(cf, fd, &phdr, &buf))
      { /* XXX, what we can do here? */ }

    comment = phdr.opt_comment;
    wtap_phdr_cleanup(&phdr);
    ws_buffer_free(&buf);
    return comment;
  }
  return NULL;
}

static int
frame_cmp(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
  const frame_data *fdata1 = (const frame_data *) a;
  const frame_data *fdata2 = (const frame_data *) b;

  return (fdata1->num < fdata2->num) ? -1 :
    (fdata1->num > fdata2->num) ? 1 :
    0;
}

gboolean
cf_set_user_packet_comment(capture_file *cf, frame_data *fd, const gchar *new_comment)
{
  char *pkt_comment = cf_get_comment(cf, fd);

  /* Check if the comment has changed */
  if (!g_strcmp0(pkt_comment, new_comment)) {
    g_free(pkt_comment);
    return FALSE;
  }
  g_free(pkt_comment);

  if (pkt_comment)
    cf->packet_comment_count--;

  if (new_comment)
    cf->packet_comment_count++;

  fd->flags.has_user_comment = TRUE;

  if (!cf->frames_user_comments)
    cf->frames_user_comments = g_tree_new_full(frame_cmp, NULL, NULL, g_free);

  /* insert new packet comment */
  g_tree_replace(cf->frames_user_comments, fd, g_strdup(new_comment));

  expert_update_comment_count(cf->packet_comment_count);

  /* OK, we have unsaved changes. */
  cf->unsaved_changes = TRUE;
  return TRUE;
}

/*
 * What types of comments does this capture file have?
 */
guint32
cf_comment_types(capture_file *cf)
{
  guint32 comment_types = 0;

  if (cf_read_shb_comment(cf) != NULL)
    comment_types |= WTAP_COMMENT_PER_SECTION;
  if (cf->packet_comment_count != 0)
    comment_types |= WTAP_COMMENT_PER_PACKET;
  return comment_types;
}

/*
 * Add a resolved address to this file's list of resolved addresses.
 */
gboolean
cf_add_ip_name_from_string(capture_file *cf, const char *addr, const char *name)
{
  /*
   * XXX - support multiple resolved address lists, and add to the one
   * attached to this file?
   */
  if (!add_ip_name_from_string(addr, name))
    return FALSE;

  /* OK, we have unsaved changes. */
  cf->unsaved_changes = TRUE;
  return TRUE;
}

#ifdef WANT_PACKET_EDITOR
static gint
g_direct_compare_func(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
  if (a > b)
    return 1;
  else if (a < b)
    return -1;
  else
    return 0;
}

static void
modified_frame_data_free(gpointer data)
{
  modified_frame_data *mfd = (modified_frame_data *)data;

  g_free(mfd->pd);
  g_free(mfd);
}

/*
 * Give a frame new, edited data.
 */
void
cf_set_frame_edited(capture_file *cf, frame_data *fd,
                    struct wtap_pkthdr *phdr, guint8 *pd)
{
  modified_frame_data *mfd = (modified_frame_data *)g_malloc(sizeof(modified_frame_data));

  mfd->phdr = *phdr;
  mfd->pd = pd;

  if (cf->edited_frames == NULL)
    cf->edited_frames = g_tree_new_full(g_direct_compare_func, NULL, NULL,
                                        modified_frame_data_free);
  g_tree_insert(cf->edited_frames, GINT_TO_POINTER(fd->num), mfd);
  fd->file_off = -1;

  /* Mark the file as having unsaved changes */
  cf->unsaved_changes = TRUE;
}
#endif

typedef struct {
  wtap_dumper *pdh;
  const char  *fname;
  int          file_type;
} save_callback_args_t;

/*
 * Save a capture to a file, in a particular format, saving either
 * all packets, all currently-displayed packets, or all marked packets.
 *
 * Returns TRUE if it succeeds, FALSE otherwise; if it fails, it pops
 * up a message box for the failure.
 */
static gboolean
save_record(capture_file *cf, frame_data *fdata,
            struct wtap_pkthdr *phdr, const guint8 *pd,
            void *argsp)
{
  save_callback_args_t *args = (save_callback_args_t *)argsp;
  struct wtap_pkthdr    hdr;
  int           err;
  gchar        *err_info;
  gchar        *display_basename;
  const char   *pkt_comment;

  if (fdata->flags.has_user_comment)
    pkt_comment = cf_get_user_packet_comment(cf, fdata);
  else
    pkt_comment = phdr->opt_comment;

  /* init the wtap header for saving */
  /* TODO: reuse phdr */
  /* XXX - these are the only flags that correspond to data that we have
     in the frame_data structure and that matter on a per-packet basis.

     For WTAP_HAS_CAP_LEN, either the file format has separate "captured"
     and "on the wire" lengths, or it doesn't.

     For WTAP_HAS_DROP_COUNT, Wiretap doesn't actually supply the value
     to its callers.

     For WTAP_HAS_PACK_FLAGS, we currently don't save the FCS length
     from the packet flags. */
  hdr.rec_type = phdr->rec_type;
  hdr.presence_flags = 0;
  if (fdata->flags.has_ts)
    hdr.presence_flags |= WTAP_HAS_TS;
  if (phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
    hdr.presence_flags |= WTAP_HAS_INTERFACE_ID;
  if (phdr->presence_flags & WTAP_HAS_PACK_FLAGS)
    hdr.presence_flags |= WTAP_HAS_PACK_FLAGS;
  hdr.ts           = phdr->ts;
  hdr.caplen       = phdr->caplen;
  hdr.len          = phdr->len;
  hdr.pkt_encap    = phdr->pkt_encap;
  /* pcapng */
  hdr.interface_id = phdr->interface_id;   /* identifier of the interface. */
  /* options */
  hdr.pack_flags   = phdr->pack_flags;
  hdr.opt_comment  = g_strdup(pkt_comment);

  /* pseudo */
  hdr.pseudo_header = phdr->pseudo_header;
#if 0
  hdr.drop_count   =
  hdr.pack_flags   =     /* XXX - 0 for now (any value for "we don't have it"?) */
#endif
  /* and save the packet */
  if (!wtap_dump(args->pdh, &hdr, pd, &err, &err_info)) {
    if (err < 0) {
      /* Wiretap error. */
      switch (err) {

      case WTAP_ERR_UNWRITABLE_ENCAP:
        /*
         * This is a problem with the particular frame we're writing and
         * the file type and subtype we're writing; note that, and report
         * the frame number and file type/subtype.
         */
        simple_error_message_box(
                      "Frame %u has a network type that can't be saved in a \"%s\" file.",
                      fdata->num, wtap_file_type_subtype_string(args->file_type));
        break;

      case WTAP_ERR_PACKET_TOO_LARGE:
        /*
         * This is a problem with the particular frame we're writing and
         * the file type and subtype we're writing; note that, and report
         * the frame number and file type/subtype.
         */
        simple_error_message_box(
                      "Frame %u is larger than Wireshark supports in a \"%s\" file.",
                      fdata->num, wtap_file_type_subtype_string(args->file_type));
        break;

      case WTAP_ERR_UNWRITABLE_REC_TYPE:
        /*
         * This is a problem with the particular record we're writing and
         * the file type and subtype we're writing; note that, and report
         * the record number and file type/subtype.
         */
        simple_error_message_box(
                      "Record %u has a record type that can't be saved in a \"%s\" file.",
                      fdata->num, wtap_file_type_subtype_string(args->file_type));
        break;

      case WTAP_ERR_UNWRITABLE_REC_DATA:
        /*
         * This is a problem with the particular frame we're writing and
         * the file type and subtype we're writing; note that, and report
         * the frame number and file type/subtype.
         */
        simple_error_message_box(
                      "Record %u has data that can't be saved in a \"%s\" file.\n(%s)",
                      fdata->num, wtap_file_type_subtype_string(args->file_type),
                      err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

      default:
        display_basename = g_filename_display_basename(args->fname);
        simple_error_message_box(
                      "An error occurred while writing to the file \"%s\": %s.",
                      display_basename, wtap_strerror(err));
        g_free(display_basename);
        break;
      }
    } else {
      /* OS error. */
      write_failure_alert_box(args->fname, err);
    }
    return FALSE;
  }

  g_free(hdr.opt_comment);
  return TRUE;
}

/*
 * Can this capture file be written out in any format using Wiretap
 * rather than by copying the raw data?
 */
gboolean
cf_can_write_with_wiretap(capture_file *cf)
{
  /* We don't care whether we support the comments in this file or not;
     if we can't, we'll offer the user the option of discarding the
     comments. */
  return wtap_dump_can_write(cf->linktypes, 0);
}

/*
 * Should we let the user do a save?
 *
 * We should if:
 *
 *  the file has unsaved changes, and we can save it in some
 *  format through Wiretap
 *
 * or
 *
 *  the file is a temporary file and has no unsaved changes (so
 *  that "saving" it just means copying it).
 *
 * XXX - we shouldn't allow files to be edited if they can't be saved,
 * so cf->unsaved_changes should be true only if the file can be saved.
 *
 * We don't care whether we support the comments in this file or not;
 * if we can't, we'll offer the user the option of discarding the
 * comments.
 */
gboolean
cf_can_save(capture_file *cf)
{
  if (cf->unsaved_changes && wtap_dump_can_write(cf->linktypes, 0)) {
    /* Saved changes, and we can write it out with Wiretap. */
    return TRUE;
  }

  if (cf->is_tempfile && !cf->unsaved_changes) {
    /*
     * Temporary file with no unsaved changes, so we can just do a
     * raw binary copy.
     */
    return TRUE;
  }

  /* Nothing to save. */
  return FALSE;
}

/*
 * Should we let the user do a "save as"?
 *
 * That's true if:
 *
 *  we can save it in some format through Wiretap
 *
 * or
 *
 *  the file is a temporary file and has no unsaved changes (so
 *  that "saving" it just means copying it).
 *
 * XXX - we shouldn't allow files to be edited if they can't be saved,
 * so cf->unsaved_changes should be true only if the file can be saved.
 *
 * We don't care whether we support the comments in this file or not;
 * if we can't, we'll offer the user the option of discarding the
 * comments.
 */
gboolean
cf_can_save_as(capture_file *cf)
{
  if (wtap_dump_can_write(cf->linktypes, 0)) {
    /* We can write it out with Wiretap. */
    return TRUE;
  }

  if (cf->is_tempfile && !cf->unsaved_changes) {
    /*
     * Temporary file with no unsaved changes, so we can just do a
     * raw binary copy.
     */
    return TRUE;
  }

  /* Nothing to save. */
  return FALSE;
}

/*
 * Does this file have unsaved data?
 */
gboolean
cf_has_unsaved_data(capture_file *cf)
{
  /*
   * If this is a temporary file, or a file with unsaved changes, it
   * has unsaved data.
   */
  return (cf->is_tempfile && cf->count>0) || cf->unsaved_changes;
}

/*
 * Quick scan to find packet offsets.
 */
static cf_read_status_t
rescan_file(capture_file *cf, const char *fname, gboolean is_tempfile, int *err)
{
  const struct wtap_pkthdr *phdr;
  gchar               *err_info;
  gchar               *name_ptr;
  gint64               data_offset;
  progdlg_t           *progbar        = NULL;
  GTimer              *prog_timer = g_timer_new();
  gint64               size;
  float                progbar_val;
  GTimeVal             start_time;
  gchar                status_str[100];
  guint32              framenum;
  frame_data          *fdata;
  int                  count          = 0;

  /* Close the old handle. */
  wtap_close(cf->wth);

  /* Open the new file. */
  /* XXX: this will go through all open_routines for a matching one. But right
     now rescan_file() is only used when a file is being saved to a different
     format than the original, and the user is not given a choice of which
     reader to use (only which format to save it in), so doing this makes
     sense for now. */
  cf->wth = wtap_open_offline(fname, WTAP_TYPE_AUTO, err, &err_info, TRUE);
  if (cf->wth == NULL) {
    cf_open_failure_alert_box(fname, *err, err_info, FALSE, 0);
    return CF_READ_ERROR;
  }

  /* We're scanning a file whose contents should be the same as what
     we had before, so we don't discard dissection state etc.. */
  cf->f_datalen = 0;

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t        = wtap_file_type_subtype(cf->wth);
  cf->linktypes = g_array_sized_new(FALSE, FALSE, (guint) sizeof(int), 1);

  cf->snap      = wtap_snapshot_length(cf->wth);
  if (cf->snap == 0) {
    /* Snapshot length not known. */
    cf->has_snap = FALSE;
    cf->snap = WTAP_MAX_PACKET_SIZE;
  } else
    cf->has_snap = TRUE;

  name_ptr = g_filename_display_basename(cf->filename);

  cf_callback_invoke(cf_cb_file_rescan_started, cf);

  /* Record whether the file is compressed.
     XXX - do we know this at open time? */
  cf->iscompressed = wtap_iscompressed(cf->wth);

  /* Find the size of the file. */
  size = wtap_file_size(cf->wth, NULL);

  g_timer_start(prog_timer);

  cf->stop_flag = FALSE;
  g_get_current_time(&start_time);

  framenum = 0;
  phdr = wtap_phdr(cf->wth);
  while ((wtap_read(cf->wth, err, &err_info, &data_offset))) {
    framenum++;
    fdata = frame_data_sequence_find(cf->frames, framenum);
    fdata->file_off = data_offset;
    if (size >= 0) {
      count++;
      cf->f_datalen = wtap_read_so_far(cf->wth);

      /* Create the progress bar if necessary. */
      if (progress_is_slow(progbar, prog_timer, size, cf->f_datalen)) {
        progbar_val = calc_progbar_val(cf, size, cf->f_datalen, status_str, sizeof(status_str));
        progbar = delayed_create_progress_dlg(cf->window, "Rescanning", name_ptr,
                                              TRUE, &cf->stop_flag, &start_time, progbar_val);
      }

      /*
       * Update the progress bar, but do it only after PROGBAR_UPDATE_INTERVAL
       * has elapsed. Calling update_progress_dlg and packets_bar_update will
       * likely trigger UI paint events, which might take a while depending on
       * the platform and display. Reset our timer *after* painting.
       */
      if (progbar && g_timer_elapsed(prog_timer, NULL) > PROGBAR_UPDATE_INTERVAL) {
        progbar_val = calc_progbar_val(cf, size, cf->f_datalen, status_str, sizeof(status_str));
        /* update the packet bar content on the first run or frequently on very large files */
        update_progress_dlg(progbar, progbar_val, status_str);
        packets_bar_update();
        g_timer_start(prog_timer);
      }
    }

    if (cf->stop_flag) {
      /* Well, the user decided to abort the rescan.  Sadly, as this
         isn't a reread, recovering is difficult, so we'll just
         close the current capture. */
      break;
    }

    /* Add this packet's link-layer encapsulation type to cf->linktypes, if
       it's not already there.
       XXX - yes, this is O(N), so if every packet had a different
       link-layer encapsulation type, it'd be O(N^2) to read the file, but
       there are probably going to be a small number of encapsulation types
       in a file. */
    cf_add_encapsulation_type(cf, phdr->pkt_encap);
  }

  /* Free the display name */
  g_free(name_ptr);

  /* We're done reading the file; destroy the progress bar if it was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);
  g_timer_destroy(prog_timer);

  /* We're done reading sequentially through the file. */
  cf->state = FILE_READ_DONE;

  /* Close the sequential I/O side, to free up memory it requires. */
  wtap_sequential_close(cf->wth);

  /* compute the time it took to load the file */
  compute_elapsed(cf, &start_time);

  /* Set the file encapsulation type now; we don't know what it is until
     we've looked at all the packets, as we don't know until then whether
     there's more than one type (and thus whether it's
     WTAP_ENCAP_PER_PACKET). */
  cf->lnk_t = wtap_file_encap(cf->wth);

  cf_callback_invoke(cf_cb_file_rescan_finished, cf);

  if (cf->stop_flag) {
    /* Our caller will give up at this point. */
    return CF_READ_ABORTED;
  }

  if (*err != 0) {
    /* Put up a message box noting that the read failed somewhere along
       the line.  Don't throw out the stuff we managed to read, though,
       if any. */
    switch (*err) {

    case WTAP_ERR_UNSUPPORTED:
      simple_error_message_box(
                 "The capture file contains record data that Wireshark doesn't support.\n(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_SHORT_READ:
      simple_error_message_box(
                 "The capture file appears to have been cut short"
                 " in the middle of a packet.");
      break;

    case WTAP_ERR_BAD_FILE:
      simple_error_message_box(
                 "The capture file appears to be damaged or corrupt.\n(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_DECOMPRESS:
      simple_error_message_box(
                 "The compressed capture file appears to be damaged or corrupt.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    default:
      simple_error_message_box(
                 "An error occurred while reading the"
                 " capture file: %s.", wtap_strerror(*err));
      break;
    }
    return CF_READ_ERROR;
  } else
    return CF_READ_OK;
}

cf_write_status_t
cf_save_records(capture_file *cf, const char *fname, guint save_format,
                gboolean compressed, gboolean discard_comments,
                gboolean dont_reopen)
{
  gchar           *err_info;
  gchar           *fname_new = NULL;
  wtap_dumper     *pdh;
  frame_data      *fdata;
  addrinfo_lists_t *addr_lists;
  guint            framenum;
  int              err;
#ifdef _WIN32
  gchar           *display_basename;
#endif
  enum {
     SAVE_WITH_MOVE,
     SAVE_WITH_COPY,
     SAVE_WITH_WTAP
  }                    how_to_save;
  save_callback_args_t callback_args;

  cf_callback_invoke(cf_cb_file_save_started, (gpointer)fname);

  addr_lists = get_addrinfo_list();

  if (save_format == cf->cd_t && compressed == cf->iscompressed
      && !discard_comments && !cf->unsaved_changes
      && !(addr_lists && wtap_dump_has_name_resolution(save_format))) {
    /* We're saving in the format it's already in, and we're
       not discarding comments, and there are no changes we have
       in memory that aren't saved to the file, and we have no name
       resolution blocks to write, so we can just move or copy the raw data. */

    if (cf->is_tempfile) {
      /* The file being saved is a temporary file from a live
         capture, so it doesn't need to stay around under that name;
         first, try renaming the capture buffer file to the new name.
         This acts as a "safe save", in that, if the file already
         exists, the existing file will be removed only if the rename
         succeeds.

         Sadly, on Windows, as we have the current capture file
         open, even MoveFileEx() with MOVEFILE_REPLACE_EXISTING
         (to cause the rename to remove an existing target), as
         done by ws_stdio_rename() (ws_rename() is #defined to
         be ws_stdio_rename() on Windows) will fail.

         According to the MSDN documentation for CreateFile(), if,
         when we open a capture file, we were to directly do a CreateFile(),
         opening with FILE_SHARE_DELETE|FILE_SHARE_READ, and then
         convert it to a file descriptor with _open_osfhandle(),
         that would allow the file to be renamed out from under us.

         However, that doesn't work in practice.  Perhaps the problem
         is that the process doing the rename is the process that
         has the file open. */
#ifndef _WIN32
      if (ws_rename(cf->filename, fname) == 0) {
        /* That succeeded - there's no need to copy the source file. */
        how_to_save = SAVE_WITH_MOVE;
      } else {
        if (errno == EXDEV) {
          /* They're on different file systems, so we have to copy the
             file. */
          how_to_save = SAVE_WITH_COPY;
        } else {
          /* The rename failed, but not because they're on different
             file systems - put up an error message.  (Or should we
             just punt and try to copy?  The only reason why I'd
             expect the rename to fail and the copy to succeed would
             be if we didn't have permission to remove the file from
             the temporary directory, and that might be fixable - but
             is it worth requiring the user to go off and fix it?) */
          cf_rename_failure_alert_box(fname, errno);
          goto fail;
        }
      }
#else
      how_to_save = SAVE_WITH_COPY;
#endif
    } else {
      /* It's a permanent file, so we should copy it, and not remove the
         original. */
      how_to_save = SAVE_WITH_COPY;
    }

    if (how_to_save == SAVE_WITH_COPY) {
      /* Copy the file, if we haven't moved it.  If we're overwriting
         an existing file, we do it with a "safe save", by writing
         to a new file and, if the write succeeds, renaming the
         new file on top of the old file. */
      if (file_exists(fname)) {
        fname_new = g_strdup_printf("%s~", fname);
        if (!copy_file_binary_mode(cf->filename, fname_new))
          goto fail;
      } else {
        if (!copy_file_binary_mode(cf->filename, fname))
          goto fail;
      }
    }
  } else {
    /* Either we're saving in a different format or we're saving changes,
       such as added, modified, or removed comments, that haven't yet
       been written to the underlying file; we can't do that by copying
       or moving the capture file, we have to do it by writing the packets
       out in Wiretap. */

    GArray                      *shb_hdrs = NULL;
    wtapng_iface_descriptions_t *idb_inf = NULL;
    GArray                      *nrb_hdrs = NULL;
    int encap;

    /* XXX: what free's this shb_hdr? */
    shb_hdrs = wtap_file_get_shb_for_new_file(cf->wth);
    idb_inf = wtap_file_get_idb_info(cf->wth);
    nrb_hdrs = wtap_file_get_nrb_for_new_file(cf->wth);

    /* Determine what file encapsulation type we should use. */
    encap = wtap_dump_file_encap_type(cf->linktypes);

    if (file_exists(fname)) {
      /* We're overwriting an existing file; write out to a new file,
         and, if that succeeds, rename the new file on top of the
         old file.  That makes this a "safe save", so that we don't
         lose the old file if we have a problem writing out the new
         file.  (If the existing file is the current capture file,
         we *HAVE* to do that, otherwise we're overwriting the file
         from which we're reading the packets that we're writing!) */
      fname_new = g_strdup_printf("%s~", fname);
      pdh = wtap_dump_open_ng(fname_new, save_format, encap, cf->snap,
                              compressed, shb_hdrs, idb_inf, nrb_hdrs, &err);
    } else {
      pdh = wtap_dump_open_ng(fname, save_format, encap, cf->snap,
                              compressed, shb_hdrs, idb_inf, nrb_hdrs, &err);
    }
    g_free(idb_inf);
    idb_inf = NULL;

    if (pdh == NULL) {
      cf_open_failure_alert_box(fname, err, NULL, TRUE, save_format);
      goto fail;
    }

    /* Add address resolution */
    wtap_dump_set_addrinfo_list(pdh, addr_lists);

    /* Iterate through the list of packets, processing all the packets. */
    callback_args.pdh = pdh;
    callback_args.fname = fname;
    callback_args.file_type = save_format;
    switch (process_specified_records(cf, NULL, "Saving", "packets",
                                      TRUE, save_record, &callback_args, TRUE)) {

    case PSP_FINISHED:
      /* Completed successfully. */
      break;

    case PSP_STOPPED:
      /* The user decided to abort the saving.
         If we're writing to a temporary file, remove it.
         XXX - should we do so even if we're not writing to a
         temporary file? */
      wtap_dump_close(pdh, &err);
      if (fname_new != NULL)
        ws_unlink(fname_new);
      cf_callback_invoke(cf_cb_file_save_stopped, NULL);
      return CF_WRITE_ABORTED;

    case PSP_FAILED:
      /* Error while saving.
         If we're writing to a temporary file, remove it. */
      if (fname_new != NULL)
        ws_unlink(fname_new);
      wtap_dump_close(pdh, &err);
      goto fail;
    }

    if (!wtap_dump_close(pdh, &err)) {
      cf_close_failure_alert_box(fname, err);
      goto fail;
    }

    how_to_save = SAVE_WITH_WTAP;
  }

  if (fname_new != NULL) {
    /* We wrote out to fname_new, and should rename it on top of
       fname.  fname_new is now closed, so that should be possible even
       on Windows.  However, on Windows, we first need to close whatever
       file descriptors we have open for fname. */
#ifdef _WIN32
    wtap_fdclose(cf->wth);
#endif
    /* Now do the rename. */
    if (ws_rename(fname_new, fname) == -1) {
      /* Well, the rename failed. */
      cf_rename_failure_alert_box(fname, errno);
#ifdef _WIN32
      /* Attempt to reopen the random file descriptor using the
         current file's filename.  (At this point, the sequential
         file descriptor is closed.) */
      if (!wtap_fdreopen(cf->wth, cf->filename, &err)) {
        /* Oh, well, we're screwed. */
        display_basename = g_filename_display_basename(cf->filename);
        simple_error_message_box(
                      file_open_error_message(err, FALSE), display_basename);
        g_free(display_basename);
      }
#endif
      goto fail;
    }
  }

  cf_callback_invoke(cf_cb_file_save_finished, NULL);
  cf->unsaved_changes = FALSE;

  if (!dont_reopen) {
    switch (how_to_save) {

    case SAVE_WITH_MOVE:
      /* We just moved the file, so the wtap structure refers to the
         new file, and all the information other than the filename
         and the "is temporary" status applies to the new file; just
         update that. */
      g_free(cf->filename);
      cf->filename = g_strdup(fname);
      cf->is_tempfile = FALSE;
      cf_callback_invoke(cf_cb_file_fast_save_finished, cf);
      break;

    case SAVE_WITH_COPY:
      /* We just copied the file, s all the information other than
         the wtap structure, the filename, and the "is temporary"
         status applies to the new file; just update that. */
      wtap_close(cf->wth);
      /* Although we're just "copying" and then opening the copy, it will
         try all open_routine readers to open the copy, so we need to
         reset the cfile's open_type. */
      cf->open_type = WTAP_TYPE_AUTO;
      cf->wth = wtap_open_offline(fname, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
      if (cf->wth == NULL) {
        cf_open_failure_alert_box(fname, err, err_info, FALSE, 0);
        cf_close(cf);
      } else {
        g_free(cf->filename);
        cf->filename = g_strdup(fname);
        cf->is_tempfile = FALSE;
      }
      cf_callback_invoke(cf_cb_file_fast_save_finished, cf);
      break;

    case SAVE_WITH_WTAP:
      /* Open and read the file we saved to.

         XXX - this is somewhat of a waste; we already have the
         packets, all this gets us is updated file type information
         (which we could just stuff into "cf"), and having the new
         file be the one we have opened and from which we're reading
         the data, and it means we have to spend time opening and
         reading the file, which could be a significant amount of
         time if the file is large.

         If the capture-file-writing code were to return the
         seek offset of each packet it writes, we could save that
         in the frame_data structure for the frame, and just open
         the file without reading it again...

         ...as long as, for gzipped files, the process of writing
         out the file *also* generates the information needed to
         support fast random access to the compressed file. */
      /* rescan_file will cause us to try all open_routines, so
         reset cfile's open_type */
      cf->open_type = WTAP_TYPE_AUTO;
      if (rescan_file(cf, fname, FALSE, &err) != CF_READ_OK) {
        /* The rescan failed; just close the file.  Either
           a dialog was popped up for the failure, so the
           user knows what happened, or they stopped the
           rescan, in which case they know what happened. */
        cf_close(cf);
      }
      break;
    }

    /* If we were told to discard the comments, do so. */
    if (discard_comments) {
      /* Remove SHB comment, if any. */
      wtap_write_shb_comment(cf->wth, NULL);

      /* remove all user comments */
      for (framenum = 1; framenum <= cf->count; framenum++) {
        fdata = frame_data_sequence_find(cf->frames, framenum);

        fdata->flags.has_phdr_comment = FALSE;
        fdata->flags.has_user_comment = FALSE;
      }

      if (cf->frames_user_comments) {
        g_tree_destroy(cf->frames_user_comments);
        cf->frames_user_comments = NULL;
      }

      cf->packet_comment_count = 0;
    }
  }
  return CF_WRITE_OK;

fail:
  if (fname_new != NULL) {
    /* We were trying to write to a temporary file; get rid of it if it
       exists.  (We don't care whether this fails, as, if it fails,
       there's not much we can do about it.  I guess if it failed for
       a reason other than "it doesn't exist", we could report an
       error, so the user knows there's a junk file that they might
       want to clean up.) */
    ws_unlink(fname_new);
    g_free(fname_new);
  }
  cf_callback_invoke(cf_cb_file_save_failed, NULL);
  return CF_WRITE_ERROR;
}

cf_write_status_t
cf_export_specified_packets(capture_file *cf, const char *fname,
                            packet_range_t *range, guint save_format,
                            gboolean compressed)
{
  gchar                       *fname_new = NULL;
  int                          err;
  wtap_dumper                 *pdh;
  save_callback_args_t         callback_args;
  GArray                      *shb_hdrs = NULL;
  wtapng_iface_descriptions_t *idb_inf = NULL;
  GArray                      *nrb_hdrs = NULL;
  int                          encap;

  cf_callback_invoke(cf_cb_file_export_specified_packets_started, (gpointer)fname);

  packet_range_process_init(range);

  /* We're writing out specified packets from the specified capture
     file to another file.  Even if all captured packets are to be
     written, don't special-case the operation - read each packet
     and then write it out if it's one of the specified ones. */

  /* XXX: what free's this shb_hdr? */
  shb_hdrs = wtap_file_get_shb_for_new_file(cf->wth);
  idb_inf = wtap_file_get_idb_info(cf->wth);
  nrb_hdrs = wtap_file_get_nrb_for_new_file(cf->wth);

  /* Determine what file encapsulation type we should use. */
  encap = wtap_dump_file_encap_type(cf->linktypes);

  if (file_exists(fname)) {
    /* We're overwriting an existing file; write out to a new file,
       and, if that succeeds, rename the new file on top of the
       old file.  That makes this a "safe save", so that we don't
       lose the old file if we have a problem writing out the new
       file.  (If the existing file is the current capture file,
       we *HAVE* to do that, otherwise we're overwriting the file
       from which we're reading the packets that we're writing!) */
    fname_new = g_strdup_printf("%s~", fname);
    pdh = wtap_dump_open_ng(fname_new, save_format, encap, cf->snap,
                            compressed, shb_hdrs, idb_inf, nrb_hdrs, &err);
  } else {
    pdh = wtap_dump_open_ng(fname, save_format, encap, cf->snap,
                            compressed, shb_hdrs, idb_inf, nrb_hdrs, &err);
  }
  g_free(idb_inf);
  idb_inf = NULL;

  if (pdh == NULL) {
    cf_open_failure_alert_box(fname, err, NULL, TRUE, save_format);
    goto fail;
  }

  /* Add address resolution */
  wtap_dump_set_addrinfo_list(pdh, get_addrinfo_list());

  /* Iterate through the list of packets, processing the packets we were
     told to process.

     XXX - we've already called "packet_range_process_init(range)", but
     "process_specified_records()" will do it again.  Fortunately,
     that's harmless in this case, as we haven't done anything to
     "range" since we initialized it. */
  callback_args.pdh = pdh;
  callback_args.fname = fname;
  callback_args.file_type = save_format;
  switch (process_specified_records(cf, range, "Writing", "specified records",
                                    TRUE, save_record, &callback_args, TRUE)) {

  case PSP_FINISHED:
    /* Completed successfully. */
    break;

  case PSP_STOPPED:
      /* The user decided to abort the saving.
         If we're writing to a temporary file, remove it.
         XXX - should we do so even if we're not writing to a
         temporary file? */
      wtap_dump_close(pdh, &err);
      if (fname_new != NULL)
        ws_unlink(fname_new);
      cf_callback_invoke(cf_cb_file_export_specified_packets_stopped, NULL);
      return CF_WRITE_ABORTED;
    break;

  case PSP_FAILED:
    /* Error while saving.
       If we're writing to a temporary file, remove it. */
    if (fname_new != NULL)
      ws_unlink(fname_new);
    wtap_dump_close(pdh, &err);
    goto fail;
  }

  if (!wtap_dump_close(pdh, &err)) {
    cf_close_failure_alert_box(fname, err);
    goto fail;
  }

  if (fname_new != NULL) {
    /* We wrote out to fname_new, and should rename it on top of
       fname; fname is now closed, so that should be possible even
       on Windows.  Do the rename. */
    if (ws_rename(fname_new, fname) == -1) {
      /* Well, the rename failed. */
      cf_rename_failure_alert_box(fname, errno);
      goto fail;
    }
  }

  cf_callback_invoke(cf_cb_file_export_specified_packets_finished, NULL);
  return CF_WRITE_OK;

fail:
  if (fname_new != NULL) {
    /* We were trying to write to a temporary file; get rid of it if it
       exists.  (We don't care whether this fails, as, if it fails,
       there's not much we can do about it.  I guess if it failed for
       a reason other than "it doesn't exist", we could report an
       error, so the user knows there's a junk file that they might
       want to clean up.) */
    ws_unlink(fname_new);
    g_free(fname_new);
  }
  cf_callback_invoke(cf_cb_file_export_specified_packets_failed, NULL);
  return CF_WRITE_ERROR;
}

static void
cf_open_failure_alert_box(const char *filename, int err, gchar *err_info,
                          gboolean for_writing, int file_type)
{
  gchar *display_basename;

  if (err < 0) {
    /* Wiretap error. */
    display_basename = g_filename_display_basename(filename);
    switch (err) {

    case WTAP_ERR_NOT_REGULAR_FILE:
      simple_error_message_box(
            "The file \"%s\" is a \"special file\" or socket or other non-regular file.",
            display_basename);
      break;

    case WTAP_ERR_RANDOM_OPEN_PIPE:
      /* Seen only when opening a capture file for reading. */
      simple_error_message_box(
            "The file \"%s\" is a pipe or FIFO; Wireshark can't read pipe or FIFO files.\n"
            "To capture from a pipe or FIFO use wireshark -i -",
            display_basename);
      break;

    case WTAP_ERR_FILE_UNKNOWN_FORMAT:
      /* Seen only when opening a capture file for reading. */
      simple_error_message_box(
            "The file \"%s\" isn't a capture file in a format Wireshark understands.",
            display_basename);
      break;

    case WTAP_ERR_UNSUPPORTED:
      /* Seen only when opening a capture file for reading. */
      simple_error_message_box(
            "The file \"%s\" contains record data that Wireshark doesn't support.\n"
            "(%s)",
            display_basename,
            err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_CANT_WRITE_TO_PIPE:
      /* Seen only when opening a capture file for writing. */
      simple_error_message_box(
            "The file \"%s\" is a pipe, and %s capture files can't be "
            "written to a pipe.",
            display_basename, wtap_file_type_subtype_string(file_type));
      break;

    case WTAP_ERR_UNWRITABLE_FILE_TYPE:
      /* Seen only when opening a capture file for writing. */
      simple_error_message_box(
            "Wireshark doesn't support writing capture files in that format.");
      break;

    case WTAP_ERR_UNWRITABLE_ENCAP:
      /* Seen only when opening a capture file for writing. */
      simple_error_message_box("Wireshark can't save this capture in that format.");
      break;

    case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
      if (for_writing) {
        simple_error_message_box(
              "Wireshark can't save this capture in that format.");
      } else {
        simple_error_message_box(
              "The file \"%s\" is a capture for a network type that Wireshark doesn't support.",
              display_basename);
      }
      break;

    case WTAP_ERR_BAD_FILE:
      /* Seen only when opening a capture file for reading. */
      simple_error_message_box(
            "The file \"%s\" appears to be damaged or corrupt.\n"
            "(%s)",
            display_basename,
            err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_CANT_OPEN:
      if (for_writing) {
        simple_error_message_box(
              "The file \"%s\" could not be created for some unknown reason.",
              display_basename);
      } else {
        simple_error_message_box(
              "The file \"%s\" could not be opened for some unknown reason.",
              display_basename);
      }
      break;

    case WTAP_ERR_SHORT_READ:
      simple_error_message_box(
            "The file \"%s\" appears to have been cut short"
            " in the middle of a packet or other data.",
            display_basename);
      break;

    case WTAP_ERR_SHORT_WRITE:
      simple_error_message_box(
            "A full header couldn't be written to the file \"%s\".",
            display_basename);
      break;

    case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
      simple_error_message_box(
            "This file type cannot be written as a compressed file.");
      break;

    case WTAP_ERR_DECOMPRESS:
      simple_error_message_box(
            "The compressed file \"%s\" appears to be damaged or corrupt.\n"
            "(%s)", display_basename,
            err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    default:
      simple_error_message_box(
            "The file \"%s\" could not be %s: %s.",
            display_basename,
            for_writing ? "created" : "opened",
            wtap_strerror(err));
      break;
    }
    g_free(display_basename);
  } else {
    /* OS error. */
    open_failure_alert_box(filename, err, for_writing);
  }
}

/*
 * XXX - whether we mention the source pathname, the target pathname,
 * or both depends on the error and on what we find if we look for
 * one or both of them.
 */
static void
cf_rename_failure_alert_box(const char *filename, int err)
{
  gchar *display_basename;

  display_basename = g_filename_display_basename(filename);
  switch (err) {

  case ENOENT:
    /* XXX - should check whether the source exists and, if not,
       report it as the problem and, if so, report the destination
       as the problem. */
    simple_error_message_box("The path to the file \"%s\" doesn't exist.",
                             display_basename);
    break;

  case EACCES:
    /* XXX - if we're doing a rename after a safe save, we should
       probably say something else. */
    simple_error_message_box("You don't have permission to move the capture file to \"%s\".",
                             display_basename);
    break;

  default:
    /* XXX - this should probably mention both the source and destination
       pathnames. */
    simple_error_message_box("The file \"%s\" could not be moved: %s.",
                             display_basename, wtap_strerror(err));
    break;
  }
  g_free(display_basename);
}

/* Check for write errors - if the file is being written to an NFS server,
   a write error may not show up until the file is closed, as NFS clients
   might not send writes to the server until the "write()" call finishes,
   so that the write may fail on the server but the "write()" may succeed. */
static void
cf_close_failure_alert_box(const char *filename, int err)
{
  gchar *display_basename;

  if (err < 0) {
    /* Wiretap error. */
    display_basename = g_filename_display_basename(filename);
    switch (err) {

    case WTAP_ERR_CANT_CLOSE:
      simple_error_message_box(
            "The file \"%s\" couldn't be closed for some unknown reason.",
            display_basename);
      break;

    case WTAP_ERR_SHORT_WRITE:
      simple_error_message_box(
            "Not all the packets could be written to the file \"%s\".",
                    display_basename);
      break;

    default:
      simple_error_message_box(
            "An error occurred while closing the file \"%s\": %s.",
            display_basename, wtap_strerror(err));
      break;
    }
    g_free(display_basename);
  } else {
    /* OS error.
       We assume that a close error from the OS is really a write error. */
    write_failure_alert_box(filename, err);
  }
}

/* Reload the current capture file. */
void
cf_reload(capture_file *cf) {
  gchar    *filename;
  gboolean  is_tempfile;
  int       err;

  /* If the file could be opened, "cf_open()" calls "cf_close()"
     to get rid of state for the old capture file before filling in state
     for the new capture file.  "cf_close()" will remove the file if
     it's a temporary file; we don't want that to happen (for one thing,
     it'd prevent subsequent reopens from working).  Remember whether it's
     a temporary file, mark it as not being a temporary file, and then
     reopen it as the type of file it was.

     Also, "cf_close()" will free "cf->filename", so we must make
     a copy of it first. */
  filename = g_strdup(cf->filename);
  is_tempfile = cf->is_tempfile;
  cf->is_tempfile = FALSE;
  if (cf_open(cf, filename, cf->open_type, is_tempfile, &err) == CF_OK) {
    switch (cf_read(cf, TRUE)) {

    case CF_READ_OK:
    case CF_READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file. */
      break;

    case CF_READ_ABORTED:
      /* The user bailed out of re-reading the capture file; the
         capture file has been closed - just free the capture file name
         string and return (without changing the last containing
         directory). */
      g_free(filename);
      return;
    }
  } else {
    /* The open failed, so "cf->is_tempfile" wasn't set to "is_tempfile".
       Instead, the file was left open, so we should restore "cf->is_tempfile"
       ourselves.

       XXX - change the menu?  Presumably "cf_open()" will do that;
       make sure it does! */
    cf->is_tempfile = is_tempfile;
  }
  /* "cf_open()" made a copy of the file name we handed it, so
     we should free up our copy. */
  g_free(filename);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
