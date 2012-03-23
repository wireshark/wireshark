/* file.c
 * File I/O routines
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <epan/epan.h>
#include <epan/filesystem.h>

#include "color.h"
#include "color_filters.h"
#include "cfile.h"
#include <epan/column.h>
#include <epan/packet.h>
#include <epan/column-utils.h>
#include "packet-range.h"
#include "print.h"
#include "file.h"
#include "fileset.h"
#include "tempfile.h"
#include "merge.h"

#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-data.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/timestamp.h>
#include <epan/dfilter/dfilter-macro.h>
#include <wsutil/file_util.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/main_statusbar.h"
#include "ui/progress_dlg.h"
#include "ui/ui_util.h"

#ifdef HAVE_LIBPCAP
gboolean auto_scroll_live;
#endif

static guint32 cum_bytes;
static nstime_t first_ts;
static nstime_t prev_dis_ts;
static nstime_t prev_cap_ts;

static gulong computed_elapsed;

static void cf_reset_state(capture_file *cf);

static int read_packet(capture_file *cf, dfilter_t *dfcode,
    gboolean filtering_tap_listeners, guint tap_flags, gint64 offset);

static void rescan_packets(capture_file *cf, const char *action, const char *action_item,
    gboolean refilter, gboolean redissect);

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
static match_result match_ascii_and_unicode(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_ascii(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_unicode(capture_file *cf, frame_data *fdata,
    void *criterion);
static match_result match_binary(capture_file *cf, frame_data *fdata,
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

static void cf_open_failure_alert_box(const char *filename, int err,
                      gchar *err_info, gboolean for_writing,
                      int file_type);
static const char *file_rename_error_message(int err);
static void cf_close_failure_alert_box(const char *filename, int err);
static void ref_time_packets(capture_file *cf);
/* Update the progress bar this many times when reading a file. */
#define N_PROGBAR_UPDATES   100
/* We read around 200k/100ms don't update the progress bar more often than that */
#define MIN_QUANTUM         200000
#define MIN_NUMBER_OF_PACKET 1500

/*
 * We could probably use g_signal_...() instead of the callbacks below but that
 * would require linking our CLI programs to libgobject and creating an object
 * instance for the signals.
 */
typedef struct {
  cf_callback_t cb_fct;
  gpointer user_data;
} cf_callback_data_t;

static GList *cf_callbacks = NULL;

static void
cf_callback_invoke(int event, gpointer data)
{
  cf_callback_data_t *cb;
  GList *cb_item = cf_callbacks;

  /* there should be at least one interested */
  g_assert(cb_item != NULL);

  while(cb_item != NULL) {
    cb = cb_item->data;
    cb->cb_fct(event, data, cb->user_data);
    cb_item = g_list_next(cb_item);
  }
}


void
cf_callback_add(cf_callback_t func, gpointer user_data)
{
  cf_callback_data_t *cb;

  cb = g_malloc(sizeof(cf_callback_data_t));
  cb->cb_fct = func;
  cb->user_data = user_data;

  cf_callbacks = g_list_append(cf_callbacks, cb);
}

void
cf_callback_remove(cf_callback_t func)
{
  cf_callback_data_t *cb;
  GList *cb_item = cf_callbacks;

  while(cb_item != NULL) {
    cb = cb_item->data;
    if(cb->cb_fct == func) {
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
  int prec = timestamp_get_precision();


  /* don't try to get the file's precision if none is opened */
  if(cf->state == FILE_CLOSED) {
    return;
  }

  /* if we are in auto mode, set precision of current file */
  if(prec == TS_PREC_AUTO ||
     prec == TS_PREC_AUTO_SEC ||
     prec == TS_PREC_AUTO_DSEC ||
     prec == TS_PREC_AUTO_CSEC ||
     prec == TS_PREC_AUTO_MSEC ||
     prec == TS_PREC_AUTO_USEC ||
     prec == TS_PREC_AUTO_NSEC)
  {
    switch(wtap_file_tsprecision(cf->wth)) {
    case(WTAP_FILE_TSPREC_SEC):
      timestamp_set_precision(TS_PREC_AUTO_SEC);
      break;
    case(WTAP_FILE_TSPREC_DSEC):
      timestamp_set_precision(TS_PREC_AUTO_DSEC);
      break;
    case(WTAP_FILE_TSPREC_CSEC):
      timestamp_set_precision(TS_PREC_AUTO_CSEC);
      break;
    case(WTAP_FILE_TSPREC_MSEC):
      timestamp_set_precision(TS_PREC_AUTO_MSEC);
      break;
    case(WTAP_FILE_TSPREC_USEC):
      timestamp_set_precision(TS_PREC_AUTO_USEC);
      break;
    case(WTAP_FILE_TSPREC_NSEC):
      timestamp_set_precision(TS_PREC_AUTO_NSEC);
      break;
    default:
      g_assert_not_reached();
    }
  }
  /* Set the column widths of those columns that show the time in
     "command-line-specified" format. */
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    if (col_has_time_fmt(&cf->cinfo, i)) {
      new_packet_list_resize_column(i);
    }
  }
}

gulong
cf_get_computed_elapsed(void)
{
  return computed_elapsed;
}

static void reset_elapsed(void)
{
  computed_elapsed = 0;
}

static void compute_elapsed(GTimeVal *start_time)
{
  gdouble    delta_time;
  GTimeVal   time_now;

  g_get_current_time(&time_now);

  delta_time = (time_now.tv_sec - start_time->tv_sec) * 1e6 +
    time_now.tv_usec - start_time->tv_usec;

  computed_elapsed = (gulong) (delta_time / 1000); /* ms*/
}

cf_status_t
cf_open(capture_file *cf, const char *fname, gboolean is_tempfile, int *err)
{
  wtap       *wth;
  gchar       *err_info;

  wth = wtap_open_offline(fname, err, &err_info, TRUE);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Close whatever capture file we had open,
     and fill in the information for this file. */
  cf_close(cf);

  /* Cleanup all data structures used for dissection. */
  cleanup_dissection();
  /* Initialize all data structures used for dissection. */
  init_dissection();

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

  /* If it's a temporary capture buffer file, mark it as not saved. */
  cf->user_saved = !is_tempfile;

  reset_elapsed();

  cf->cd_t        = wtap_file_type(cf->wth);
  cf->count     = 0;
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
  nstime_set_unset(&first_ts);
  nstime_set_unset(&prev_dis_ts);
  nstime_set_unset(&prev_cap_ts);
  cum_bytes = 0;

  /* Adjust timestamp precision if auto is selected, col width will be adjusted */
  cf_timestamp_auto_precision(cf);
  /* XXX needed ? */
  new_packet_list_queue_draw();
  fileset_file_opened(fname);

  if(cf->cd_t == WTAP_FILE_BER) {
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
 * Reset the state for the currently closed file, but don't do the
 * UI callbacks; this is for use in "cf_open()", where we don't
 * want the UI to go from "file open" to "file closed" back to
 * "file open", we want it to go from "old file open" to "new file
 * open and being read".
 *
 * XXX - currently, cf_open() calls cf_close(), rather than
 * cf_reset_state().
 */
static void
cf_reset_state(capture_file *cf)
{
  /* Die if we're in the middle of reading a file. */
  g_assert(cf->state != FILE_READ_IN_PROGRESS);

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
  /* ...which means we have nothing to save. */
  cf->user_saved = FALSE;

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
  cf_unselect_packet(cf);   /* nothing to select */
  cf->first_displayed = 0;
  cf->last_displayed = 0;

  /* No frames, no frame selected, no field in that frame selected. */
  cf->count = 0;
  cf->current_frame = 0;
  cf->current_row = 0;
  cf->finfo_selected = NULL;

  /* Clear the packet list. */
  new_packet_list_freeze();
  new_packet_list_clear();
  new_packet_list_thaw();

  cf->f_datalen = 0;
  nstime_set_zero(&cf->elapsed_time);

  reset_tap_listeners();

  /* We have no file open. */
  cf->state = FILE_CLOSED;

  fileset_file_closed();
}

/* Reset everything to a pristine state */
void
cf_close(capture_file *cf)
{
  if(cf->state != FILE_CLOSED) {
    cf_callback_invoke(cf_cb_file_closing, cf);

  /* close things, if not already closed before */
    color_filters_cleanup();
    cf_reset_state(cf);
    cleanup_dissection();

    cf_callback_invoke(cf_cb_file_closed, cf);
  }
}

/* an out of memory exception occured, wait for a user button press to exit */
static void outofmemory_cb(gpointer dialog _U_, gint btn _U_, gpointer data _U_)
{
    main_window_exit();
}

static float
calc_progbar_val(capture_file *cf, gint64 size, gint64 file_pos, gchar *status_str, gulong status_size)
{
  float   progbar_val;

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
cf_read(capture_file *cf, gboolean from_save)
{
  int         err;
  gchar       *err_info;
  const gchar *name_ptr;
  const char  *errmsg;
  char         errmsg_errno[1024+1];
  gint64       data_offset;
  gint64       file_pos;
  progdlg_t *volatile progbar = NULL;
  gboolean     stop_flag;
  volatile gint64 size;
  volatile float progbar_val;
  GTimeVal     start_time;
  gchar        status_str[100];
  volatile gint64 progbar_nextstep;
  volatile gint64 progbar_quantum;
  dfilter_t   *dfcode;
  gboolean    filtering_tap_listeners;
  guint       tap_flags;
  volatile int count = 0;
#ifdef HAVE_LIBPCAP
  volatile int displayed_once = 0;
#endif
  gboolean compiled;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  reset_tap_listeners();

  name_ptr = get_basename(cf->filename);

  if (from_save == FALSE)
    cf_callback_invoke(cf_cb_file_read_started, cf);
  else
    cf_callback_invoke(cf_cb_file_save_started, (gpointer)name_ptr);

  /* Find the size of the file. */
  size = wtap_file_size(cf->wth, NULL);

  /* Update the progress bar when it gets to this value. */
  progbar_nextstep = 0;
  /* When we reach the value that triggers a progress bar update,
     bump that value by this amount. */
  if (size >= 0){
    progbar_quantum = size/N_PROGBAR_UPDATES;
    if (progbar_quantum < MIN_QUANTUM)
      progbar_quantum = MIN_QUANTUM;
  }else
    progbar_quantum = 0;
  /* Progress so far. */
  progbar_val = 0.0f;

  /* The packet list window will be empty untill the file is completly loaded */
  new_packet_list_freeze();

  stop_flag = FALSE;
  g_get_current_time(&start_time);

  while ((wtap_read(cf->wth, &err, &err_info, &data_offset))) {
    if (size >= 0) {
      count++;
      file_pos = wtap_read_so_far(cf->wth);

      /* Create the progress bar if necessary.
       * Check whether it should be created or not every MIN_NUMBER_OF_PACKET
       */
      if ((progbar == NULL) && !(count % MIN_NUMBER_OF_PACKET)){
        progbar_val = calc_progbar_val(cf, size, file_pos, status_str, sizeof(status_str));
        if (from_save == FALSE)
          progbar = delayed_create_progress_dlg("Loading", name_ptr,
                                                TRUE, &stop_flag, &start_time, progbar_val);
        else
          progbar = delayed_create_progress_dlg("Saving", name_ptr,
                                                TRUE, &stop_flag, &start_time, progbar_val);
      }

      /* Update the progress bar, but do it only N_PROGBAR_UPDATES times;
         when we update it, we have to run the GTK+ main loop to get it
         to repaint what's pending, and doing so may involve an "ioctl()"
         to see if there's any pending input from an X server, and doing
         that for every packet can be costly, especially on a big file. */
      if (file_pos >= progbar_nextstep) {
        if (progbar != NULL) {
          progbar_val = calc_progbar_val(cf, size, file_pos, status_str, sizeof(status_str));
          /* update the packet bar content on the first run or frequently on very large files */
#ifdef HAVE_LIBPCAP
          if (progbar_quantum > 500000 || displayed_once == 0) {
            if ((auto_scroll_live || displayed_once == 0 || cf->displayed_count < 1000) && cf->count != 0) {
              displayed_once = 1;
              packets_bar_update();
            }
          }
#endif /* HAVE_LIBPCAP */
          update_progress_dlg(progbar, progbar_val, status_str);
        }
        progbar_nextstep += progbar_quantum;
      }
    }

    if (stop_flag) {
      /* Well, the user decided to abort the read. He/She will be warned and
         it might be enough for him/her to work with the already loaded
         packets.
         This is especially true for very large capture files, where you don't
         want to wait loading the whole file (which may last minutes or even
         hours even on fast machines) just to see that it was the wrong file. */
      break;
    }
    TRY {
      read_packet(cf, dfcode, filtering_tap_listeners, tap_flags, data_offset);
    }
    CATCH(OutOfMemoryError) {
      gpointer dialog;

      dialog = simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                             "%sOut Of Memory!%s\n"
                             "\n"
                             "Sorry, but Wireshark has to terminate now!\n"
                             "\n"
                             "Some infos / workarounds can be found at:\n"
                             "http://wiki.wireshark.org/KnownBugs/OutOfMemory",
                             simple_dialog_primary_start(), simple_dialog_primary_end());
      /* we have to terminate, as we cannot recover from the memory error */
      simple_dialog_set_cb(dialog, outofmemory_cb, NULL);
      while(1) {
        main_window_update();
        /* XXX - how to avoid a busy wait? */
        /* Sleep(100); */
      };
      break;
    }
    ENDTRY;
  }

  /* Cleanup and release all dfilter resources */
  if (dfcode != NULL){
    dfilter_free(dfcode);
  }

  /* We're done reading the file; destroy the progress bar if it was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);

  /* We're done reading sequentially through the file. */
  cf->state = FILE_READ_DONE;

  /* Close the sequential I/O side, to free up memory it requires. */
  wtap_sequential_close(cf->wth);

  /* Allow the protocol dissectors to free up memory that they
   * don't need after the sequential run-through of the packets. */
  postseq_cleanup_all_protocols();

  /* compute the time it took to load the file */
  compute_elapsed(&start_time);

  /* Set the file encapsulation type now; we don't know what it is until
     we've looked at all the packets, as we don't know until then whether
     there's more than one type (and thus whether it's
     WTAP_ENCAP_PER_PACKET). */
  cf->lnk_t = wtap_file_encap(cf->wth);

  cf->current_frame = frame_data_sequence_find(cf->frames, cf->first_displayed);
  cf->current_row = 0;

  new_packet_list_thaw();
  if (from_save == FALSE)
    cf_callback_invoke(cf_cb_file_read_finished, cf);
  else
    cf_callback_invoke(cf_cb_file_save_finished, cf);

  /* If we have any displayed packets to select, select the first of those
     packets by making the first row the selected row. */
  if (cf->first_displayed != 0){
    new_packet_list_select_first_row();
  }

  if(stop_flag) {
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                  "%sFile loading was cancelled!%s\n"
                  "\n"
                  "The remaining packets in the file were discarded.\n"
                  "\n"
                  "As a lot of packets from the original file will be missing,\n"
                  "remember to be careful when saving the current content to a file.\n",
                  simple_dialog_primary_start(), simple_dialog_primary_end());
    return CF_READ_ERROR;
  }

  if (err != 0) {
    /* Put up a message box noting that the read failed somewhere along
       the line.  Don't throw out the stuff we managed to read, though,
       if any. */
    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The capture file contains record data that TShark doesn't support.\n(%s)",
                 err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_UNSUPPORTED_ENCAP:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The capture file has a packet with a network type that Wireshark doesn't support.\n(%s)",
                 err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_CANT_READ:
      errmsg = "An attempt to read from the capture file failed for"
        " some unknown reason.";
      break;

    case WTAP_ERR_SHORT_READ:
      errmsg = "The capture file appears to have been cut short"
        " in the middle of a packet.";
      break;

    case WTAP_ERR_BAD_FILE:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The capture file appears to be damaged or corrupt.\n(%s)",
                 err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_DECOMPRESS:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The compressed capture file appears to be damaged or corrupt.\n"
                 "(%s)", err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    default:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "An error occurred while reading the"
                 " capture file: %s.", wtap_strerror(err));
      errmsg = errmsg_errno;
      break;
    }
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", errmsg);
    return CF_READ_ERROR;
  } else
    return CF_READ_OK;
}

#ifdef HAVE_LIBPCAP
cf_status_t
cf_start_tail(capture_file *cf, const char *fname, gboolean is_tempfile, int *err)
{
  cf_status_t cf_status;

  cf_status = cf_open(cf, fname, is_tempfile, err);
  return cf_status;
}

cf_read_status_t
cf_continue_tail(capture_file *cf, volatile int to_read, int *err)
{
  gint64 data_offset = 0;
  gchar *err_info;
  volatile int newly_displayed_packets = 0;
  dfilter_t   *dfcode;
  gboolean filtering_tap_listeners;
  guint tap_flags;
  gboolean compiled;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  *err = 0;

  new_packet_list_check_end();
  /* Don't freeze/thaw the list when doing live capture */
  /*new_packet_list_freeze();*/

  /*g_log(NULL, G_LOG_LEVEL_MESSAGE, "cf_continue_tail: %u new: %u", cf->count, to_read);*/

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
    TRY{
      if (read_packet(cf, dfcode, filtering_tap_listeners, tap_flags,
                      data_offset) != -1) {
        newly_displayed_packets++;
      }
    }
    CATCH(OutOfMemoryError) {
      gpointer dialog;

      dialog = simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                             "%sOut Of Memory!%s\n"
                             "\n"
                             "Sorry, but Wireshark has to terminate now!\n"
                             "\n"
                             "The capture file is not lost, it can be found at:\n"
                             "%s\n"
                             "\n"
                             "Some infos / workarounds can be found at:\n"
                             "http://wiki.wireshark.org/KnownBugs/OutOfMemory",
                             simple_dialog_primary_start(), simple_dialog_primary_end(), cf->filename);
      /* we have to terminate, as we cannot recover from the memory error */
      simple_dialog_set_cb(dialog, outofmemory_cb, NULL);
      while(1) {
        main_window_update();
        /* XXX - how to avoid a busy wait? */
        /* Sleep(100); */
      };
      /* Don't freeze/thaw the list when doing live capture */
      /*new_packet_list_thaw();*/
      return CF_READ_ABORTED;
    }
    ENDTRY;
    to_read--;
  }

  /* Cleanup and release all dfilter resources */
  if (dfcode != NULL){
    dfilter_free(dfcode);
  }

  /*g_log(NULL, G_LOG_LEVEL_MESSAGE, "cf_continue_tail: count %u state: %u err: %u",
    cf->count, cf->state, *err);*/

  /* Don't freeze/thaw the list when doing live capture */
  /*new_packet_list_thaw();*/
  /* With the new packet list the first packet
   * isn't automatically selected.
   */
  if(!cf->current_frame)
    new_packet_list_select_first_row();

  /* moving to the end of the packet list - if the user requested so and
     we have some new packets. */
  if (newly_displayed_packets && auto_scroll_live && cf->count != 0)
      new_packet_list_moveto_end();

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
    g_warning("Error \"%s\" while reading: \"%s\"\n",
        wtap_strerror(*err), cf->filename);

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
  gchar *err_info;
  gint64 data_offset;
  dfilter_t   *dfcode;
  gboolean filtering_tap_listeners;
  guint tap_flags;
  gboolean compiled;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  if(cf->wth == NULL) {
    cf_close(cf);
    return CF_READ_ERROR;
  }

  new_packet_list_check_end();
  /* Don't freeze/thaw the list when doing live capture */
  /*new_packet_list_freeze();*/

  while ((wtap_read(cf->wth, err, &err_info, &data_offset))) {
    if (cf->state == FILE_READ_ABORTED) {
      /* Well, the user decided to abort the read.  Break out of the
         loop, and let the code below (which is called even if there
     aren't any packets left to read) exit. */
      break;
    }
    read_packet(cf, dfcode, filtering_tap_listeners, tap_flags, data_offset);
  }

  /* Cleanup and release all dfilter resources */
  if (dfcode != NULL){
    dfilter_free(dfcode);
  }

  /* Don't freeze/thaw the list when doing live capture */
  /*new_packet_list_thaw();*/

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
    new_packet_list_moveto_end();

  /* We're done reading sequentially through the file. */
  cf->state = FILE_READ_DONE;

  /* We're done reading sequentially through the file; close the
     sequential I/O side, to free up memory it requires. */
  wtap_sequential_close(cf->wth);

  /* Allow the protocol dissectors to free up memory that they
   * don't need after the sequential run-through of the packets. */
  postseq_cleanup_all_protocols();

  /* Set the file encapsulation type now; we don't know what it is until
     we've looked at all the packets, as we don't know until then whether
     there's more than one type (and thus whether it's
     WTAP_ENCAP_PER_PACKET). */
  cf->lnk_t = wtap_file_encap(cf->wth);

  if (*err != 0) {
    /* We got an error reading the capture file.
       XXX - pop up a dialog box? */
    return CF_READ_ERROR;
  } else {
    return CF_READ_OK;
  }
}
#endif /* HAVE_LIBPCAP */

const gchar *
cf_get_display_name(capture_file *cf)
{
  const gchar *displayname;

  /* Return a name to use in displays */
  if (!cf->is_tempfile) {
    /* Get the last component of the file name, and use that. */
    if (cf->filename){
      displayname = get_basename(cf->filename);
    } else {
      displayname="(No file)";
    }
  } else {
    /* The file we read is a temporary file from a live capture;
       we don't mention its name. */
    if (cf->source) {
      displayname = cf->source;
    } else {
      displayname = "(Untitled)";
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
void
cf_set_packet_count(capture_file *cf, int packet_count)
{
  cf->count = packet_count;
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

static void
find_and_mark_frame_depended_upon(gpointer data, gpointer user_data)
{
  frame_data *dependent_fd;
  guint32 dependent_frame = GPOINTER_TO_UINT(data);
  capture_file *cf = (capture_file *)user_data;

  dependent_fd = frame_data_sequence_find(cf->frames, dependent_frame);
  dependent_fd->flags.dependent_of_displayed = 1;
}

static int
add_packet_to_packet_list(frame_data *fdata, capture_file *cf,
    dfilter_t *dfcode, gboolean filtering_tap_listeners,
    guint tap_flags,
    union wtap_pseudo_header *pseudo_header, const guchar *buf,
    gboolean refilter,
    gboolean add_to_packet_list)
{
  gboolean  create_proto_tree = FALSE;
  epan_dissect_t edt;
  column_info *cinfo;
  gint row = -1;

  cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cf->cinfo : NULL;

  frame_data_set_before_dissect(fdata, &cf->elapsed_time,
                                &first_ts, &prev_dis_ts, &prev_cap_ts);

  /* If either
    + we have a display filter and are re-applying it;
    + we have tap listeners with filters;
    + we have tap listeners that require a protocol tree;

     allocate a protocol tree root node, so that we'll construct
     a protocol tree against which a filter expression can be
     evaluated. */
  if ((dfcode != NULL && refilter) ||
      filtering_tap_listeners || (tap_flags & TL_REQUIRES_PROTO_TREE))
      create_proto_tree = TRUE;

  /* Dissect the frame. */
  epan_dissect_init(&edt, create_proto_tree, FALSE);

  if (dfcode != NULL && refilter) {
      epan_dissect_prime_dfilter(&edt, dfcode);
  }

  tap_queue_init(&edt);
  epan_dissect_run(&edt, pseudo_header, buf, fdata, cinfo);
  tap_push_tapped_queue(&edt);

  /* If we have a display filter, apply it if we're refiltering, otherwise
     leave the "passed_dfilter" flag alone.

     If we don't have a display filter, set "passed_dfilter" to 1. */
  if (dfcode != NULL) {
    if (refilter) {
      fdata->flags.passed_dfilter = dfilter_apply_edt(dfcode, &edt) ? 1 : 0;

    /* This frame passed the display filter but it may depend on other
     * (potentially not displayed) frames.  Find those frames and mark them
     * as depended upon.
     */
      g_slist_foreach(edt.pi.dependent_frames, find_and_mark_frame_depended_upon, cf);
    }
  } else
    fdata->flags.passed_dfilter = 1;

  /* We're done with this list */
  g_slist_free(edt.pi.dependent_frames);

  if(fdata->flags.passed_dfilter || fdata->flags.ref_time)
    cf->displayed_count++;

  if (add_to_packet_list) {
    /* We fill the needed columns from new_packet_list */
      row = new_packet_list_append(cinfo, fdata, &edt.pi);
  }

  if(fdata->flags.passed_dfilter || fdata->flags.ref_time)
  {
    frame_data_set_after_dissect(fdata, &cum_bytes, &prev_dis_ts);

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

  epan_dissect_cleanup(&edt);
  return row;
}

/* read in a new packet */
/* returns the row of the new packet in the packet list or -1 if not displayed */
static int
read_packet(capture_file *cf, dfilter_t *dfcode,
            gboolean filtering_tap_listeners, guint tap_flags, gint64 offset)
{
  const struct wtap_pkthdr *phdr = wtap_phdr(cf->wth);
  union wtap_pseudo_header *pseudo_header = wtap_pseudoheader(cf->wth);
  const guchar *buf = wtap_buf_ptr(cf->wth);
  frame_data    fdlocal;
  guint32       framenum;
  frame_data   *fdata;
  int           passed;
  int           row = -1;

  /* The frame number of this packet is one more than the count of
     frames in this packet. */
  framenum = cf->count + 1;

  frame_data_init(&fdlocal, framenum, phdr, offset, cum_bytes);

  passed = TRUE;
  if (cf->rfcode) {
    epan_dissect_t edt;
    epan_dissect_init(&edt, TRUE, FALSE);
    epan_dissect_prime_dfilter(&edt, cf->rfcode);
    epan_dissect_run(&edt, pseudo_header, buf, &fdlocal, NULL);
    passed = dfilter_apply_edt(cf->rfcode, &edt);
    epan_dissect_cleanup(&edt);
  }

  if (passed) {
    /* This does a shallow copy of fdlocal, which is good enough. */
    fdata = frame_data_sequence_add(cf->frames, &fdlocal);

    cf->count++;
    cf->f_datalen = offset + fdlocal.cap_len;

    if (!cf->redissecting) {
      row = add_packet_to_packet_list(fdata, cf, dfcode,
                                      filtering_tap_listeners, tap_flags,
                                      pseudo_header, buf, TRUE, TRUE);
    }
  }

  return row;
}

cf_status_t
cf_merge_files(char **out_filenamep, int in_file_count,
               char *const *in_filenames, int file_type, gboolean do_append)
{
  merge_in_file_t  *in_files, *in_file;
  char             *out_filename;
  char             *tmpname;
  int               out_fd;
  wtap_dumper      *pdh;
  int               open_err, read_err, write_err, close_err;
  gchar            *err_info;
  int               err_fileno;
  int               i;
  char              errmsg_errno[1024+1];
  const char       *errmsg;
  gboolean          got_read_error = FALSE, got_write_error = FALSE;
  gint64            data_offset;
  progdlg_t        *progbar = NULL;
  gboolean          stop_flag;
  gint64            f_len, file_pos;
  float             progbar_val;
  GTimeVal          start_time;
  gchar             status_str[100];
  gint64            progbar_nextstep;
  gint64            progbar_quantum;

  /* open the input files */
  if (!merge_open_in_files(in_file_count, in_filenames, &in_files,
                           &open_err, &err_info, &err_fileno)) {
    g_free(in_files);
    cf_open_failure_alert_box(in_filenames[err_fileno], open_err, err_info,
                              FALSE, 0);
    return CF_ERROR;
  }

  if (*out_filenamep != NULL) {
    out_filename = *out_filenamep;
    out_fd = ws_open(out_filename, O_CREAT|O_TRUNC|O_BINARY, 0600);
    if (out_fd == -1)
      open_err = errno;
  } else {
    out_fd = create_tempfile(&tmpname, "wireshark");
    if (out_fd == -1)
      open_err = errno;
    out_filename = g_strdup(tmpname);
    *out_filenamep = out_filename;
  }
  if (out_fd == -1) {
    err_info = NULL;
    merge_close_in_files(in_file_count, in_files);
    g_free(in_files);
    cf_open_failure_alert_box(out_filename, open_err, NULL, TRUE, file_type);
    return CF_ERROR;
  }

  pdh = wtap_dump_fdopen(out_fd, file_type,
      merge_select_frame_type(in_file_count, in_files),
      merge_max_snapshot_length(in_file_count, in_files),
      FALSE /* compressed */, &open_err);
  if (pdh == NULL) {
    ws_close(out_fd);
    merge_close_in_files(in_file_count, in_files);
    g_free(in_files);
    cf_open_failure_alert_box(out_filename, open_err, err_info, TRUE,
                              file_type);
    return CF_ERROR;
  }

  /* Get the sum of the sizes of all the files. */
  f_len = 0;
  for (i = 0; i < in_file_count; i++)
    f_len += in_files[i].size;

  /* Update the progress bar when it gets to this value. */
  progbar_nextstep = 0;
  /* When we reach the value that triggers a progress bar update,
     bump that value by this amount. */
  progbar_quantum = f_len/N_PROGBAR_UPDATES;
  /* Progress so far. */
  progbar_val = 0.0f;

  stop_flag = FALSE;
  g_get_current_time(&start_time);

  /* do the merge (or append) */
  for (;;) {
    if (do_append)
      in_file = merge_append_read_packet(in_file_count, in_files, &read_err,
                                         &err_info);
    else
      in_file = merge_read_packet(in_file_count, in_files, &read_err,
                                  &err_info);
    if (in_file == NULL) {
      /* EOF */
      break;
    }

    if (read_err != 0) {
      /* I/O error reading from in_file */
      got_read_error = TRUE;
      break;
    }

    /* Get the sum of the data offsets in all of the files. */
    data_offset = 0;
    for (i = 0; i < in_file_count; i++)
      data_offset += in_files[i].data_offset;

    /* Create the progress bar if necessary.
       We check on every iteration of the loop, so that it takes no
       longer than the standard time to create it (otherwise, for a
       large file, we might take considerably longer than that standard
       time in order to get to the next progress bar step). */
    if (progbar == NULL) {
      progbar = delayed_create_progress_dlg("Merging", "files",
        FALSE, &stop_flag, &start_time, progbar_val);
    }

    /* Update the progress bar, but do it only N_PROGBAR_UPDATES times;
       when we update it, we have to run the GTK+ main loop to get it
       to repaint what's pending, and doing so may involve an "ioctl()"
       to see if there's any pending input from an X server, and doing
       that for every packet can be costly, especially on a big file. */
    if (data_offset >= progbar_nextstep) {
        /* Get the sum of the seek positions in all of the files. */
        file_pos = 0;
        for (i = 0; i < in_file_count; i++)
          file_pos += wtap_read_so_far(in_files[i].wth);
        progbar_val = (gfloat) file_pos / (gfloat) f_len;
        if (progbar_val > 1.0f) {
          /* Some file probably grew while we were reading it.
             That "shouldn't happen", so we'll just clip the progress
             value at 1.0. */
          progbar_val = 1.0f;
        }
        if (progbar != NULL) {
          g_snprintf(status_str, sizeof(status_str),
                     "%" G_GINT64_MODIFIER "dKB of %" G_GINT64_MODIFIER "dKB",
                     file_pos / 1024, f_len / 1024);
          update_progress_dlg(progbar, progbar_val, status_str);
        }
        progbar_nextstep += progbar_quantum;
    }

    if (stop_flag) {
      /* Well, the user decided to abort the merge. */
      break;
    }

    if (!wtap_dump(pdh, wtap_phdr(in_file->wth), wtap_pseudoheader(in_file->wth),
         wtap_buf_ptr(in_file->wth), &write_err)) {
      got_write_error = TRUE;
      break;
    }
  }

  /* We're done merging the files; destroy the progress bar if it was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);

  merge_close_in_files(in_file_count, in_files);
  if (!got_read_error && !got_write_error) {
    if (!wtap_dump_close(pdh, &write_err))
      got_write_error = TRUE;
  } else
    wtap_dump_close(pdh, &close_err);

  if (got_read_error) {
    /*
     * Find the file on which we got the error, and report the error.
     */
    for (i = 0; i < in_file_count; i++) {
      if (in_files[i].state == GOT_ERROR) {
        /* Put up a message box noting that a read failed somewhere along
           the line. */
        switch (read_err) {

        case WTAP_ERR_UNSUPPORTED_ENCAP:
          g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                     "The capture file %%s has a packet with a network type that Wireshark doesn't support.\n(%s)",
                     err_info);
          g_free(err_info);
          errmsg = errmsg_errno;
          break;

        case WTAP_ERR_CANT_READ:
          errmsg = "An attempt to read from the capture file %s failed for"
                   " some unknown reason.";
          break;

        case WTAP_ERR_SHORT_READ:
          errmsg = "The capture file %s appears to have been cut short"
                   " in the middle of a packet.";
          break;

        case WTAP_ERR_BAD_FILE:
          g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                     "The capture file %%s appears to be damaged or corrupt.\n(%s)",
                     err_info);
          g_free(err_info);
          errmsg = errmsg_errno;
          break;

        case WTAP_ERR_DECOMPRESS:
          g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                     "The compressed capture file %%s appears to be damaged or corrupt.\n"
                     "(%s)", err_info);
          g_free(err_info);
          errmsg = errmsg_errno;
          break;

        default:
          g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                     "An error occurred while reading the"
                     " capture file %%s: %s.", wtap_strerror(read_err));
          errmsg = errmsg_errno;
          break;
        }
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, errmsg, in_files[i].filename);
      }
    }
  }

  if (got_write_error) {
    /* Put up an alert box for the write error. */
    if (write_err < 0) {
      /* Wiretap error. */
      switch (write_err) {

      case WTAP_ERR_UNSUPPORTED_ENCAP:
        /*
         * This is a problem with the particular frame we're writing;
         * note that, and give the frame number.
         */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Frame %u of \"%s\" has a network type that can't be saved in a \"%s\" file.",
                      in_file->packet_num, in_file->filename,
                      wtap_file_type_string(file_type));
        break;

      default:
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "An error occurred while writing to the file \"%s\": %s.",
                      out_filename, wtap_strerror(write_err));
        break;
      }
    } else {
      /* OS error. */
      write_failure_alert_box(out_filename, write_err);
    }
  }

  if (got_read_error || got_write_error || stop_flag) {
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
  dfilter_t   *dfcode;
  GTimeVal     start_time;

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
    if (!dfilter_compile(dftext, &dfcode)) {
      /* The attempt failed; report an error. */
      gchar *safe_dftext = simple_dialog_format_message(dftext);
      gchar *safe_dfilter_error_msg = simple_dialog_format_message(
      dfilter_error_msg);
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
          "%s%s%s\n"
          "\n"
          "The following display filter isn't a valid display filter:\n%s\n"
          "See the help for a description of the display filter syntax.",
          simple_dialog_primary_start(), safe_dfilter_error_msg,
          simple_dialog_primary_end(), safe_dftext);
      g_free(safe_dfilter_error_msg);
      g_free(safe_dftext);
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
  if (dftext == NULL) {
    rescan_packets(cf, "Resetting", "Filter", TRUE, FALSE);
  } else {
    rescan_packets(cf, "Filtering", dftext, TRUE, FALSE);
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
  rescan_packets(cf, "Reprocessing", "all packets", TRUE, TRUE);
}

gboolean
cf_read_frame_r(capture_file *cf, frame_data *fdata,
                union wtap_pseudo_header *pseudo_header, guint8 *pd)
{
  int err;
  gchar *err_info;
  char errmsg_errno[1024+1];

#ifdef WANT_PACKET_EDITOR
  /* if fdata->file_off == -1 it means packet was edited, and we must find data inside edited_frames tree */
  if (G_UNLIKELY(fdata->file_off == -1)) {
    const modified_frame_data *frame = (const modified_frame_data *) g_tree_lookup(cf->edited_frames, GINT_TO_POINTER(fdata->num));

    if (!frame) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "fdata->file_off == -1, but can't find modified frame!");
      return FALSE;
    }

    *pseudo_header = frame->ph;
    memcpy(pd, frame->pd, fdata->cap_len);
    return TRUE;
  }
#endif

  if (!wtap_seek_read(cf->wth, fdata->file_off, pseudo_header, pd,
                      fdata->cap_len, &err, &err_info)) {
    switch (err) {

    case WTAP_ERR_UNSUPPORTED_ENCAP:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" has a packet with a network type that Wireshark doesn't support.\n(%s)",
                 err_info);
      g_free(err_info);
      break;

    case WTAP_ERR_BAD_FILE:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "An error occurred while reading from the file \"%%s\": %s.\n(%s)",
                 wtap_strerror(err), err_info);
      g_free(err_info);
      break;

    default:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "An error occurred while reading from the file \"%%s\": %s.",
                 wtap_strerror(err));
      break;
    }
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, errmsg_errno, cf->filename);
    return FALSE;
  }
  return TRUE;
}

gboolean
cf_read_frame(capture_file *cf, frame_data *fdata)
{
  return cf_read_frame_r(cf, fdata, &cf->pseudo_header, cf->pd);
}

/* Rescan the list of packets, reconstructing the CList.

   "action" describes why we're doing this; it's used in the progress
   dialog box.

   "action_item" describes what we're doing; it's used in the progress
   dialog box.

   "refilter" is TRUE if we need to re-evaluate the filter expression.

   "redissect" is TRUE if we need to make the dissectors reconstruct
   any state information they have (because a preference that affects
   some dissector has changed, meaning some dissector might construct
   its state differently from the way it was constructed the last time). */
static void
rescan_packets(capture_file *cf, const char *action, const char *action_item,
        gboolean refilter, gboolean redissect)
{
  /* Rescan packets new packet list */
  guint32     framenum;
  frame_data *fdata;
  progdlg_t  *progbar = NULL;
  gboolean    stop_flag;
  int         count;
  frame_data *selected_frame, *preceding_frame, *following_frame, *prev_frame;
  int         selected_frame_num, preceding_frame_num, following_frame_num, prev_frame_num;
  gboolean    selected_frame_seen;
  float       progbar_val;
  GTimeVal    start_time;
  gchar       status_str[100];
  int         progbar_nextstep;
  int         progbar_quantum;
  dfilter_t   *dfcode;
  gboolean    filtering_tap_listeners;
  guint       tap_flags;
  gboolean    add_to_packet_list = FALSE;
  gboolean compiled;

  /* Compile the current display filter.
   * We assume this will not fail since cf->dfilter is only set in
   * cf_filter IFF the filter was valid.
   */
  compiled = dfilter_compile(cf->dfilter, &dfcode);
  g_assert(!cf->dfilter || (compiled && dfcode));

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

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
  new_packet_list_freeze();

  if (redissect) {
    /* We need to re-initialize all the state information that protocols
       keep, because some preference that controls a dissector has changed,
       which might cause the state information to be constructed differently
       by that dissector. */

    /* We might receive new packets while redissecting, and we don't
       want to dissect those before their time. */
    cf->redissecting = TRUE;

    /* Cleanup all data structures used for dissection. */
    cleanup_dissection();
    /* Initialize all data structures used for dissection. */
    init_dissection();

    /* We need to redissect the packets so we have to discard our old
     * packet list store. */
    new_packet_list_clear();
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
  nstime_set_unset(&first_ts);
  nstime_set_unset(&prev_dis_ts);
  nstime_set_unset(&prev_cap_ts);
  cum_bytes = 0;

  /* Update the progress bar when it gets to this value. */
  progbar_nextstep = 0;
  /* When we reach the value that triggers a progress bar update,
     bump that value by this amount. */
  progbar_quantum = cf->count/N_PROGBAR_UPDATES;
  /* Count of packets at which we've looked. */
  count = 0;
  /* Progress so far. */
  progbar_val = 0.0f;

  stop_flag = FALSE;
  g_get_current_time(&start_time);

  /* no previous row yet */
  prev_frame_num = -1;
  prev_frame = NULL;

  preceding_frame_num = -1;
  preceding_frame = NULL;
  following_frame_num = -1;
  following_frame = NULL;

  selected_frame_seen = FALSE;

  for (framenum = 1; framenum <= cf->count; framenum++) {
    fdata = frame_data_sequence_find(cf->frames, framenum);

    /* Create the progress bar if necessary.
       We check on every iteration of the loop, so that it takes no
       longer than the standard time to create it (otherwise, for a
       large file, we might take considerably longer than that standard
       time in order to get to the next progress bar step). */
    if (progbar == NULL)
      progbar = delayed_create_progress_dlg(action, action_item, TRUE,
                                            &stop_flag, &start_time,
                                            progbar_val);

    /* Update the progress bar, but do it only N_PROGBAR_UPDATES times;
       when we update it, we have to run the GTK+ main loop to get it
       to repaint what's pending, and doing so may involve an "ioctl()"
       to see if there's any pending input from an X server, and doing
       that for every packet can be costly, especially on a big file. */
    if (count >= progbar_nextstep) {
      /* let's not divide by zero. I should never be started
       * with count == 0, so let's assert that
       */
      g_assert(cf->count > 0);
      progbar_val = (gfloat) count / cf->count;

      if (progbar != NULL) {
        g_snprintf(status_str, sizeof(status_str),
                  "%4u of %u frames", count, cf->count);
        update_progress_dlg(progbar, progbar_val, status_str);
      }

      progbar_nextstep += progbar_quantum;
    }

    if (stop_flag) {
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
      fdata->flags.visited = 0;
      frame_data_cleanup(fdata);
    }

    if (!cf_read_frame(cf, fdata))
      break; /* error reading the frame */

    /* If the previous frame is displayed, and we haven't yet seen the
       selected frame, remember that frame - it's the closest one we've
       yet seen before the selected frame. */
    if (prev_frame_num != -1 && !selected_frame_seen && prev_frame->flags.passed_dfilter) {
      preceding_frame_num = prev_frame_num;
      preceding_frame = prev_frame;
    }
    add_packet_to_packet_list(fdata, cf, dfcode, filtering_tap_listeners,
                                    tap_flags, &cf->pseudo_header, cf->pd,
                                    refilter,
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

  /* We are done redissecting the packet list. */
  cf->redissecting = FALSE;

  if (redissect) {
    /* Clear out what remains of the visited flags and per-frame data
       pointers.

       XXX - that may cause various forms of bogosity when dissecting
       these frames, as they won't have been seen by this sequential
       pass, but the only alternative I see is to keep scanning them
       even though the user requested that the scan stop, and that
       would leave the user stuck with an Wireshark grinding on
       until it finishes.  Should we just stick them with that? */
    for (; framenum <= cf->count; framenum++) {
      fdata = frame_data_sequence_find(cf->frames, framenum);
      fdata->flags.visited = 0;
      frame_data_cleanup(fdata);
    }
  }

  /* We're done filtering the packets; destroy the progress bar if it
     was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);

  /* Unfreeze the packet list. */
  if (!add_to_packet_list)
    new_packet_list_recreate_visible_rows();

  /* Compute the time it took to filter the file */
  compute_elapsed(&start_time);

  new_packet_list_thaw();

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
      new_packet_list_select_first_row();
    }else{
      if (!new_packet_list_select_row_from_data(selected_frame)) {
        /* We didn't find a row corresponding to this frame.
           This means that the frame isn't being displayed currently,
           so we can't select it. */
        simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
                      "%sEnd of capture exceeded!%s\n\n"
                      "The capture file is probably not fully dissected.",
                      simple_dialog_primary_start(), simple_dialog_primary_end());
      }
    }
  }

  /* Cleanup and release all dfilter resources */
  dfilter_free(dfcode);
}


/*
 * Scan trough all frame data and recalculate the ref time
 * without rereading the file.
 * XXX - do we need a progres bar or is this fast enough?
 */
static void
ref_time_packets(capture_file *cf)
{
  guint32 framenum;
  frame_data *fdata;

  nstime_set_unset(&first_ts);
  nstime_set_unset(&prev_dis_ts);
  cum_bytes = 0;

  for (framenum = 1; framenum <= cf->count; framenum++) {
    fdata = frame_data_sequence_find(cf->frames, framenum);

    /* just add some value here until we know if it is being displayed or not */
    fdata->cum_bytes = cum_bytes + fdata->pkt_len;

    /*
     *Timestamps
     */

    /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
    if (nstime_is_unset(&first_ts)) {
        first_ts  = fdata->abs_ts;
    }
      /* if this frames is marked as a reference time frame, reset
        firstsec and firstusec to this frame */
    if(fdata->flags.ref_time){
        first_ts = fdata->abs_ts;
    }

    /* If we don't have the time stamp of the previous displayed packet,
     it's because this is the first displayed packet.  Save the time
     stamp of this packet as the time stamp of the previous displayed
     packet. */
    if (nstime_is_unset(&prev_dis_ts)) {
        prev_dis_ts = fdata->abs_ts;
    }

    /* Get the time elapsed between the first packet and this packet. */
    nstime_delta(&fdata->rel_ts, &fdata->abs_ts, &first_ts);

    /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
    if ((gint32)cf->elapsed_time.secs < fdata->rel_ts.secs
        || ((gint32)cf->elapsed_time.secs == fdata->rel_ts.secs && (gint32)cf->elapsed_time.nsecs < fdata->rel_ts.nsecs)) {
        cf->elapsed_time = fdata->rel_ts;
    }

    /* If this frame is displayed, get the time elapsed between the
     previous displayed packet and this packet. */
    if( fdata->flags.passed_dfilter ) {
        nstime_delta(&fdata->del_dis_ts, &fdata->abs_ts, &prev_dis_ts);
        prev_dis_ts = fdata->abs_ts;
    }

    /*
     * Byte counts
     */
    if( (fdata->flags.passed_dfilter) || (fdata->flags.ref_time) ){
        /* This frame either passed the display filter list or is marked as
        a time reference frame.  All time reference frames are displayed
        even if they dont pass the display filter */
        if(fdata->flags.ref_time){
            /* if this was a TIME REF frame we should reset the cum_bytes field */
            cum_bytes = fdata->pkt_len;
            fdata->cum_bytes =  cum_bytes;
        } else {
            /* increase cum_bytes with this packets length */
            cum_bytes += fdata->pkt_len;
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
process_specified_packets(capture_file *cf, packet_range_t *range,
    const char *string1, const char *string2, gboolean terminate_is_stop,
    gboolean (*callback)(capture_file *, frame_data *,
                         union wtap_pseudo_header *, const guint8 *, void *),
    void *callback_args)
{
  guint32 framenum;
  frame_data *fdata;
  union wtap_pseudo_header pseudo_header;
  guint8      pd[WTAP_MAX_PACKET_SIZE+1];
  psp_return_t ret = PSP_FINISHED;

  progdlg_t  *progbar = NULL;
  int         progbar_count;
  float       progbar_val;
  gboolean    progbar_stop_flag;
  GTimeVal    progbar_start_time;
  gchar       progbar_status_str[100];
  int         progbar_nextstep;
  int         progbar_quantum;
  range_process_e process_this;

  /* Update the progress bar when it gets to this value. */
  progbar_nextstep = 0;
  /* When we reach the value that triggers a progress bar update,
     bump that value by this amount. */
  progbar_quantum = cf->count/N_PROGBAR_UPDATES;
  /* Count of packets at which we've looked. */
  progbar_count = 0;
  /* Progress so far. */
  progbar_val = 0.0f;

  progbar_stop_flag = FALSE;
  g_get_current_time(&progbar_start_time);

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
    if (progbar == NULL)
      progbar = delayed_create_progress_dlg(string1, string2,
                                            terminate_is_stop,
                                            &progbar_stop_flag,
                                            &progbar_start_time,
                                            progbar_val);

    /* Update the progress bar, but do it only N_PROGBAR_UPDATES times;
       when we update it, we have to run the GTK+ main loop to get it
       to repaint what's pending, and doing so may involve an "ioctl()"
       to see if there's any pending input from an X server, and doing
       that for every packet can be costly, especially on a big file. */
    if (progbar_count >= progbar_nextstep) {
      /* let's not divide by zero. I should never be started
       * with count == 0, so let's assert that
       */
      g_assert(cf->count > 0);
      progbar_val = (gfloat) progbar_count / cf->count;

      if (progbar != NULL) {
        g_snprintf(progbar_status_str, sizeof(progbar_status_str),
                   "%4u of %u packets", progbar_count, cf->count);
        update_progress_dlg(progbar, progbar_val, progbar_status_str);
      }

      progbar_nextstep += progbar_quantum;
    }

    if (progbar_stop_flag) {
      /* Well, the user decided to abort the operation.  Just stop,
         and arrange to return PSP_STOPPED to our caller, so they know
         it was stopped explicitly. */
      ret = PSP_STOPPED;
      break;
    }

    progbar_count++;

    /* do we have to process this packet? */
    process_this = packet_range_process_packet(range, fdata);
    if (process_this == range_process_next) {
        /* this packet uninteresting, continue with next one */
        continue;
    } else if (process_this == range_processing_finished) {
        /* all interesting packets processed, stop the loop */
        break;
    }

    /* Get the packet */
    if (!cf_read_frame_r(cf, fdata, &pseudo_header, pd)) {
      /* Attempt to get the packet failed. */
      ret = PSP_FAILED;
      break;
    }
    /* Process the packet */
    if (!callback(cf, fdata, &pseudo_header, pd, callback_args)) {
      /* Callback failed.  We assume it reported the error appropriately. */
      ret = PSP_FAILED;
      break;
    }
  }

  /* We're done printing the packets; destroy the progress bar if
     it was created. */
  if (progbar != NULL)
    destroy_progress_dlg(progbar);

  return ret;
}

typedef struct {
  gboolean construct_protocol_tree;
  column_info *cinfo;
} retap_callback_args_t;

static gboolean
retap_packet(capture_file *cf _U_, frame_data *fdata,
             union wtap_pseudo_header *pseudo_header, const guint8 *pd,
             void *argsp)
{
  retap_callback_args_t *args = argsp;
  epan_dissect_t edt;

  epan_dissect_init(&edt, args->construct_protocol_tree, FALSE);
  tap_queue_init(&edt);
  epan_dissect_run(&edt, pseudo_header, pd, fdata, args->cinfo);
  tap_push_tapped_queue(&edt);
  epan_dissect_cleanup(&edt);

  return TRUE;
}

cf_read_status_t
cf_retap_packets(capture_file *cf)
{
  packet_range_t range;
  retap_callback_args_t callback_args;
  gboolean filtering_tap_listeners;
  guint tap_flags;

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  tap_flags = union_of_tap_listener_flags();

  /* If any tap listeners have filters, or require the protocol tree,
     construct the protocol tree. */
  callback_args.construct_protocol_tree = filtering_tap_listeners ||
                                          (tap_flags & TL_REQUIRES_PROTO_TREE);

  /* If any tap listeners require the columns, construct them. */
  callback_args.cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cf->cinfo : NULL;

  /* Reset the tap listeners. */
  reset_tap_listeners();

  /* Iterate through the list of packets, dissecting all packets and
     re-running the taps. */
  packet_range_init(&range);
  packet_range_process_init(&range);
  switch (process_specified_packets(cf, &range, "Recalculating statistics on",
                                    "all packets", TRUE, retap_packet,
                                    &callback_args)) {
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
} print_callback_args_t;

static gboolean
print_packet(capture_file *cf, frame_data *fdata,
             union wtap_pseudo_header *pseudo_header, const guint8 *pd,
             void *argsp)
{
  print_callback_args_t *args = argsp;
  epan_dissect_t edt;
  int             i;
  char           *cp;
  int             line_len;
  int             column_len;
  int             cp_off;
  gboolean        proto_tree_needed;
  char            bookmark_name[9+10+1];    /* "__frameNNNNNNNNNN__\0" */
  char            bookmark_title[6+10+1];   /* "Frame NNNNNNNNNN__\0" */

  /* Create the protocol tree, and make it visible, if we're printing
     the dissection or the hex data.
     XXX - do we need it if we're just printing the hex data? */
  proto_tree_needed =
      args->print_args->print_dissections != print_dissections_none || args->print_args->print_hex || have_custom_cols(&cf->cinfo);
  epan_dissect_init(&edt, proto_tree_needed, proto_tree_needed);

  /* Fill in the column information if we're printing the summary
     information. */
  if (args->print_args->print_summary) {
    col_custom_prime_edt(&edt, &cf->cinfo);
    epan_dissect_run(&edt, pseudo_header, pd, fdata, &cf->cinfo);
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE);
  } else
    epan_dissect_run(&edt, pseudo_header, pd, fdata, NULL);

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
    if (args->print_header_line) {
      if (!print_line(args->print_args->stream, 0, args->header_line_buf))
        goto fail;
      args->print_header_line = FALSE;  /* we might not need to print any more */
    }
    cp = &args->line_buf[0];
    line_len = 0;
    for (i = 0; i < cf->cinfo.num_cols; i++) {
      /* Find the length of the string for this column. */
      column_len = (int) strlen(cf->cinfo.col_data[i]);
      if (args->col_widths[i] > column_len)
         column_len = args->col_widths[i];

      /* Make sure there's room in the line buffer for the column; if not,
         double its length. */
      line_len += column_len + 1;   /* "+1" for space */
      if (line_len > args->line_buf_len) {
        cp_off = (int) (cp - args->line_buf);
        args->line_buf_len = 2 * line_len;
        args->line_buf = g_realloc(args->line_buf, args->line_buf_len + 1);
        cp = args->line_buf + cp_off;
      }

      /* Right-justify the packet number column. */
      if (cf->cinfo.col_fmt[i] == COL_NUMBER)
        g_snprintf(cp, column_len+1, "%*s", args->col_widths[i], cf->cinfo.col_data[i]);
      else
        g_snprintf(cp, column_len+1, "%-*s", args->col_widths[i], cf->cinfo.col_data[i]);
      cp += column_len;
      if (i != cf->cinfo.num_cols - 1)
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
    if (!proto_tree_print(args->print_args, &edt, args->print_args->stream))
      goto fail;

    /* Print a blank line if we print anything after this (aka more than one packet). */
    args->print_separator = TRUE;

    /* Print a header line if we print any more packet summaries */
    args->print_header_line = TRUE;
  }

  if (args->print_args->print_hex) {
    /* Print the full packet data as hex. */
    if (!print_hex_data(args->print_args->stream, &edt))
      goto fail;

    /* Print a blank line if we print anything after this (aka more than one packet). */
    args->print_separator = TRUE;

    /* Print a header line if we print any more packet summaries */
    args->print_header_line = TRUE;
  } /* if (args->print_args->print_dissections != print_dissections_none) */

  epan_dissect_cleanup(&edt);

  /* do we want to have a formfeed between each packet from now on? */
  if(args->print_args->print_formfeed) {
    args->print_formfeed = TRUE;
  }

  return TRUE;

fail:
  epan_dissect_cleanup(&edt);
  return FALSE;
}

cf_print_status_t
cf_print_packets(capture_file *cf, print_args_t *print_args)
{
  int         i;
  print_callback_args_t callback_args;
  gint        data_width;
  char        *cp;
  int         cp_off;
  int         column_len;
  int         line_len;
  psp_return_t ret;

  callback_args.print_args = print_args;
  callback_args.print_header_line = TRUE;
  callback_args.header_line_buf = NULL;
  callback_args.header_line_buf_len = 256;
  callback_args.print_formfeed = FALSE;
  callback_args.print_separator = FALSE;
  callback_args.line_buf = NULL;
  callback_args.line_buf_len = 256;
  callback_args.col_widths = NULL;

  if (!print_preamble(print_args->stream, cf->filename)) {
    destroy_print_stream(print_args->stream);
    return CF_PRINT_WRITE_ERROR;
  }

  if (print_args->print_summary) {
    /* We're printing packet summaries.  Allocate the header line buffer
       and get the column widths. */
    callback_args.header_line_buf = g_malloc(callback_args.header_line_buf_len + 1);

    /* Find the widths for each of the columns - maximum of the
       width of the title and the width of the data - and construct
       a buffer with a line containing the column titles. */
    callback_args.col_widths = (gint *) g_malloc(sizeof(gint) * cf->cinfo.num_cols);
    cp = &callback_args.header_line_buf[0];
    line_len = 0;
    for (i = 0; i < cf->cinfo.num_cols; i++) {
      /* Don't pad the last column. */
      if (i == cf->cinfo.num_cols - 1)
        callback_args.col_widths[i] = 0;
      else {
        callback_args.col_widths[i] = (gint) strlen(cf->cinfo.col_title[i]);
        data_width = get_column_char_width(get_column_format(i));
        if (data_width > callback_args.col_widths[i])
          callback_args.col_widths[i] = data_width;
      }

      /* Find the length of the string for this column. */
      column_len = (int) strlen(cf->cinfo.col_title[i]);
      if (callback_args.col_widths[i] > column_len)
        column_len = callback_args.col_widths[i];

      /* Make sure there's room in the line buffer for the column; if not,
         double its length. */
      line_len += column_len + 1;   /* "+1" for space */
      if (line_len > callback_args.header_line_buf_len) {
        cp_off = (int) (cp - callback_args.header_line_buf);
        callback_args.header_line_buf_len = 2 * line_len;
        callback_args.header_line_buf = g_realloc(callback_args.header_line_buf,
                                                  callback_args.header_line_buf_len + 1);
        cp = callback_args.header_line_buf + cp_off;
      }

      /* Right-justify the packet number column. */
/*      if (cf->cinfo.col_fmt[i] == COL_NUMBER)
        g_snprintf(cp, column_len+1, "%*s", callback_args.col_widths[i], cf->cinfo.col_title[i]);
      else*/
      g_snprintf(cp, column_len+1, "%-*s", callback_args.col_widths[i], cf->cinfo.col_title[i]);
      cp += column_len;
      if (i != cf->cinfo.num_cols - 1)
        *cp++ = ' ';
    }
    *cp = '\0';

    /* Now start out the main line buffer with the same length as the
       header line buffer. */
    callback_args.line_buf_len = callback_args.header_line_buf_len;
    callback_args.line_buf = g_malloc(callback_args.line_buf_len + 1);
  } /* if (print_summary) */

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_packets(cf, &print_args->range, "Printing",
                                  "selected packets", TRUE, print_packet,
                                  &callback_args);

  g_free(callback_args.header_line_buf);
  g_free(callback_args.line_buf);
  g_free(callback_args.col_widths);

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

static gboolean
write_pdml_packet(capture_file *cf _U_, frame_data *fdata,
                  union wtap_pseudo_header *pseudo_header, const guint8 *pd,
          void *argsp)
{
  FILE *fh = argsp;
  epan_dissect_t edt;

  /* Create the protocol tree, but don't fill in the column information. */
  epan_dissect_init(&edt, TRUE, TRUE);
  epan_dissect_run(&edt, pseudo_header, pd, fdata, NULL);

  /* Write out the information in that tree. */
  proto_tree_write_pdml(&edt, fh);

  epan_dissect_cleanup(&edt);

  return !ferror(fh);
}

cf_print_status_t
cf_write_pdml_packets(capture_file *cf, print_args_t *print_args)
{
  FILE        *fh;
  psp_return_t ret;

  fh = ws_fopen(print_args->file, "w");
  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_pdml_preamble(fh, cf->filename);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_packets(cf, &print_args->range, "Writing PDML",
                                  "selected packets", TRUE,
                                  write_pdml_packet, fh);

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
                  union wtap_pseudo_header *pseudo_header, const guint8 *pd,
          void *argsp)
{
  FILE *fh = argsp;
  epan_dissect_t edt;
  gboolean proto_tree_needed;

  /* Fill in the column information, only create the protocol tree
     if having custom columns. */
  proto_tree_needed = have_custom_cols(&cf->cinfo);
  epan_dissect_init(&edt, proto_tree_needed, proto_tree_needed);
  col_custom_prime_edt(&edt, &cf->cinfo);
  epan_dissect_run(&edt, pseudo_header, pd, fdata, &cf->cinfo);
  epan_dissect_fill_in_columns(&edt, FALSE, TRUE);

  /* Write out the information in that tree. */
  proto_tree_write_psml(&edt, fh);

  epan_dissect_cleanup(&edt);

  return !ferror(fh);
}

cf_print_status_t
cf_write_psml_packets(capture_file *cf, print_args_t *print_args)
{
  FILE        *fh;
  psp_return_t ret;

  fh = ws_fopen(print_args->file, "w");
  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_psml_preamble(fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_packets(cf, &print_args->range, "Writing PSML",
                                  "selected packets", TRUE,
                                  write_psml_packet, fh);

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
                 union wtap_pseudo_header *pseudo_header, const guint8 *pd,
                 void *argsp)
{
  FILE *fh = argsp;
  epan_dissect_t edt;
  gboolean proto_tree_needed;

  /* Fill in the column information, only create the protocol tree
     if having custom columns. */
  proto_tree_needed = have_custom_cols(&cf->cinfo);
  epan_dissect_init(&edt, proto_tree_needed, proto_tree_needed);
  col_custom_prime_edt(&edt, &cf->cinfo);
  epan_dissect_run(&edt, pseudo_header, pd, fdata, &cf->cinfo);
  epan_dissect_fill_in_columns(&edt, FALSE, TRUE);

  /* Write out the information in that tree. */
  proto_tree_write_csv(&edt, fh);

  epan_dissect_cleanup(&edt);

  return !ferror(fh);
}

cf_print_status_t
cf_write_csv_packets(capture_file *cf, print_args_t *print_args)
{
  FILE        *fh;
  psp_return_t ret;

  fh = ws_fopen(print_args->file, "w");
  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_csv_preamble(fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_packets(cf, &print_args->range, "Writing CSV",
                                  "selected packets", TRUE,
                                  write_csv_packet, fh);

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

  write_csv_finale(fh);
  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* XXX - check for an error */
  fclose(fh);

  return CF_PRINT_OK;
}

static gboolean
write_carrays_packet(capture_file *cf _U_, frame_data *fdata,
             union wtap_pseudo_header *pseudo_header,
             const guint8 *pd, void *argsp)
{
  FILE *fh = argsp;
  epan_dissect_t edt;

  epan_dissect_init(&edt, TRUE, TRUE);
  epan_dissect_run(&edt, pseudo_header, pd, fdata, NULL);
  proto_tree_write_carrays(fdata->num, fh, &edt);
  epan_dissect_cleanup(&edt);

  return !ferror(fh);
}

cf_print_status_t
cf_write_carrays_packets(capture_file *cf, print_args_t *print_args)
{
  FILE        *fh;
  psp_return_t ret;

  fh = ws_fopen(print_args->file, "w");

  if (fh == NULL)
    return CF_PRINT_OPEN_ERROR; /* attempt to open destination failed */

  write_carrays_preamble(fh);

  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  /* Iterate through the list of packets, printing the packets we were
     told to print. */
  ret = process_specified_packets(cf, &print_args->range,
                  "Writing C Arrays",
                  "selected packets", TRUE,
                                  write_carrays_packet, fh);
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

  write_carrays_finale(fh);

  if (ferror(fh)) {
    fclose(fh);
    return CF_PRINT_WRITE_ERROR;
  }

  fclose(fh);
  return CF_PRINT_OK;
}

gboolean
cf_find_packet_protocol_tree(capture_file *cf, const char *string,
                             search_direction dir)
{
  match_data        mdata;

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
  match_data        *mdata = criterion;
  epan_dissect_t    edt;

  /* Load the frame's data. */
  if (!cf_read_frame(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  /* Construct the protocol tree, including the displayed text */
  epan_dissect_init(&edt, TRUE, TRUE);
  /* We don't need the column information */
  epan_dissect_run(&edt, &cf->pseudo_header, cf->pd, fdata, NULL);

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
  match_data    *mdata = (match_data*) data;
  const gchar   *string = mdata->string;
  size_t        string_len = mdata->string_len;
  capture_file  *cf = mdata->cf;
  field_info    *fi = PNODE_FINFO(node);
  gchar         label_str[ITEM_LABEL_LENGTH];
  gchar         *label_ptr;
  size_t        label_len;
  guint32       i;
  guint8        c_char;
  size_t        c_match = 0;

  g_assert(fi && "dissection with an invisible proto tree?");

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

  /* Does that label match? */
  label_len = strlen(label_ptr);
  for (i = 0; i < label_len; i++) {
    c_char = label_ptr[i];
    if (cf->case_type)
      c_char = toupper(c_char);
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

  /* Recurse into the subtree, if it exists */
  if (node->first_child != NULL)
    proto_tree_children_foreach(node, match_subtree_text, mdata);
}

gboolean
cf_find_packet_summary_line(capture_file *cf, const char *string,
                            search_direction dir)
{
  match_data        mdata;

  mdata.string = string;
  mdata.string_len = strlen(string);
  return find_packet(cf, match_summary_line, &mdata, dir);
}

static match_result
match_summary_line(capture_file *cf, frame_data *fdata, void *criterion)
{
  match_data        *mdata = criterion;
  const gchar       *string = mdata->string;
  size_t            string_len = mdata->string_len;
  epan_dissect_t    edt;
  const char        *info_column;
  size_t            info_column_len;
  match_result      result = MR_NOTMATCHED;
  gint              colx;
  guint32           i;
  guint8            c_char;
  size_t            c_match = 0;

  /* Load the frame's data. */
  if (!cf_read_frame(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  /* Don't bother constructing the protocol tree */
  epan_dissect_init(&edt, FALSE, FALSE);
  /* Get the column information */
  epan_dissect_run(&edt, &cf->pseudo_header, cf->pd, fdata, &cf->cinfo);

  /* Find the Info column */
  for (colx = 0; colx < cf->cinfo.num_cols; colx++) {
    if (cf->cinfo.fmt_matx[colx][COL_INFO]) {
      /* Found it.  See if we match. */
      info_column = edt.pi.cinfo->col_data[colx];
      info_column_len = strlen(info_column);
      for (i = 0; i < info_column_len; i++) {
        c_char = info_column[i];
        if (cf->case_type)
          c_char = toupper(c_char);
        if (c_char == string[c_match]) {
          c_match++;
          if (c_match == string_len) {
            result = MR_MATCHED;
            break;
          }
        } else
          c_match = 0;
      }
      break;
    }
  }
  epan_dissect_cleanup(&edt);
  return result;
}

typedef struct {
    const guint8 *data;
    size_t data_len;
} cbs_t;    /* "Counted byte string" */

gboolean
cf_find_packet_data(capture_file *cf, const guint8 *string, size_t string_size,
                    search_direction dir)
{
  cbs_t info;

  info.data = string;
  info.data_len = string_size;

  /* String or hex search? */
  if (cf->string) {
    /* String search - what type of string? */
    switch (cf->scs_type) {

    case SCS_ASCII_AND_UNICODE:
      return find_packet(cf, match_ascii_and_unicode, &info, dir);

    case SCS_ASCII:
      return find_packet(cf, match_ascii, &info, dir);

    case SCS_UNICODE:
      return find_packet(cf, match_unicode, &info, dir);

    default:
      g_assert_not_reached();
      return FALSE;
    }
  } else
    return find_packet(cf, match_binary, &info, dir);
}

static match_result
match_ascii_and_unicode(capture_file *cf, frame_data *fdata, void *criterion)
{
  cbs_t        *info = criterion;
  const guint8 *ascii_text = info->data;
  size_t       textlen = info->data_len;
  match_result result;
  guint32      buf_len;
  guint32      i;
  guint8       c_char;
  size_t       c_match = 0;

  /* Load the frame's data. */
  if (!cf_read_frame(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->pkt_len;
  i = 0;
  while (i < buf_len) {
    c_char = cf->pd[i];
    if (cf->case_type)
      c_char = toupper(c_char);
    if (c_char != '\0') {
      if (c_char == ascii_text[c_match]) {
        c_match += 1;
        if (c_match == textlen) {
          result = MR_MATCHED;
          cf->search_pos = i; /* Save the position of the last character
                                 for highlighting the field. */
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
match_ascii(capture_file *cf, frame_data *fdata, void *criterion)
{
  cbs_t        *info = criterion;
  const guint8 *ascii_text = info->data;
  size_t       textlen = info->data_len;
  match_result result;
  guint32      buf_len;
  guint32      i;
  guint8       c_char;
  size_t       c_match = 0;

  /* Load the frame's data. */
  if (!cf_read_frame(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->pkt_len;
  i = 0;
  while (i < buf_len) {
    c_char = cf->pd[i];
    if (cf->case_type)
      c_char = toupper(c_char);
    if (c_char == ascii_text[c_match]) {
      c_match += 1;
      if (c_match == textlen) {
        result = MR_MATCHED;
        cf->search_pos = i; /* Save the position of the last character
                               for highlighting the field. */
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
match_unicode(capture_file *cf, frame_data *fdata, void *criterion)
{
  cbs_t        *info = criterion;
  const guint8 *ascii_text = info->data;
  size_t       textlen = info->data_len;
  match_result result;
  guint32      buf_len;
  guint32      i;
  guint8       c_char;
  size_t       c_match = 0;

  /* Load the frame's data. */
  if (!cf_read_frame(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->pkt_len;
  i = 0;
  while (i < buf_len) {
    c_char = cf->pd[i];
    if (cf->case_type)
      c_char = toupper(c_char);
    if (c_char == ascii_text[c_match]) {
      c_match += 1;
      if (c_match == textlen) {
        result = MR_MATCHED;
        cf->search_pos = i; /* Save the position of the last character
                               for highlighting the field. */
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
  cbs_t        *info = criterion;
  const guint8 *binary_data = info->data;
  size_t       datalen = info->data_len;
  match_result result;
  guint32      buf_len;
  guint32      i;
  size_t       c_match = 0;

  /* Load the frame's data. */
  if (!cf_read_frame(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  result = MR_NOTMATCHED;
  buf_len = fdata->pkt_len;
  i = 0;
  while (i < buf_len) {
    if (cf->pd[i] == binary_data[c_match]) {
      c_match += 1;
      if (c_match == datalen) {
        result = MR_MATCHED;
        cf->search_pos = i; /* Save the position of the last character
                               for highlighting the field. */
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
  gboolean result;

  if (!dfilter_compile(filter, &sfcode)) {
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
  dfilter_t      *sfcode = criterion;
  epan_dissect_t edt;
  match_result   result;

  /* Load the frame's data. */
  if (!cf_read_frame(cf, fdata)) {
    /* Attempt to get the packet failed. */
    return MR_ERROR;
  }

  epan_dissect_init(&edt, TRUE, FALSE);
  epan_dissect_prime_dfilter(&edt, sfcode);
  epan_dissect_run(&edt, &cf->pseudo_header, cf->pd, fdata, NULL);
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
  gboolean     stop_flag;
  int          count;
  gboolean     found;
  float        progbar_val;
  GTimeVal     start_time;
  gchar        status_str[100];
  int          progbar_nextstep;
  int          progbar_quantum;
  const char  *title;
  match_result result;

  start_fd = cf->current_frame;
  if (start_fd != NULL)  {
    /* Iterate through the list of packets, starting at the packet we've
       picked, calling a routine to run the filter on the packet, see if
       it matches, and stop if so.  */
    count = 0;
    framenum = start_fd->num;

    /* Update the progress bar when it gets to this value. */
    progbar_nextstep = 0;
    /* When we reach the value that triggers a progress bar update,
       bump that value by this amount. */
    progbar_quantum = cf->count/N_PROGBAR_UPDATES;
    /* Progress so far. */
    progbar_val = 0.0f;

    stop_flag = FALSE;
    g_get_current_time(&start_time);

    title = cf->sfilter?cf->sfilter:"";
    for (;;) {
      /* Create the progress bar if necessary.
         We check on every iteration of the loop, so that it takes no
         longer than the standard time to create it (otherwise, for a
         large file, we might take considerably longer than that standard
         time in order to get to the next progress bar step). */
      if (progbar == NULL)
         progbar = delayed_create_progress_dlg("Searching", title,
           FALSE, &stop_flag, &start_time, progbar_val);

      /* Update the progress bar, but do it only N_PROGBAR_UPDATES times;
         when we update it, we have to run the GTK+ main loop to get it
         to repaint what's pending, and doing so may involve an "ioctl()"
         to see if there's any pending input from an X server, and doing
         that for every packet can be costly, especially on a big file. */
      if (count >= progbar_nextstep) {
        /* let's not divide by zero. I should never be started
         * with count == 0, so let's assert that
         */
        g_assert(cf->count > 0);

        progbar_val = (gfloat) count / cf->count;

        if (progbar != NULL) {
          g_snprintf(status_str, sizeof(status_str),
                     "%4u of %u packets", count, cf->count);
          update_progress_dlg(progbar, progbar_val, status_str);
        }

        progbar_nextstep += progbar_quantum;
      }

      if (stop_flag) {
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
  }

  if (new_fd != NULL) {
    /* Find and select */
    cf->search_in_progress = TRUE;
    found = new_packet_list_select_row_from_data(new_fd);
    cf->search_in_progress = FALSE;
    cf->search_pos = 0; /* Reset the position */
    if (!found) {
      /* We didn't find a row corresponding to this frame.
         This means that the frame isn't being displayed currently,
         so we can't select it. */
      simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
                    "%sEnd of capture exceeded!%s\n\n"
                    "The capture file is probably not fully dissected.",
                    simple_dialog_primary_start(), simple_dialog_primary_end());
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

  if (!new_packet_list_select_row_from_data(fdata)) {
    /* We didn't find a row corresponding to this frame.
       This means that the frame isn't being displayed currently,
       so we can't select it. */
    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
                  "%sEnd of capture exceeded!%s\n\n"
                  "The capture file is probably not fully dissected.",
                  simple_dialog_primary_start(), simple_dialog_primary_end());
    return FALSE;
  }
  return TRUE;  /* we got to that packet */
}

gboolean
cf_goto_top_frame(void)
{
  /* Find and select */
  new_packet_list_select_first_row();
  return TRUE;  /* we got to that packet */
}

gboolean
cf_goto_bottom_frame(void)
{
  /* Find and select */
  new_packet_list_select_last_row();
  return TRUE;  /* we got to that packet */
}

/*
 * Go to frame specified by currently selected protocol tree item.
 */
gboolean
cf_goto_framenum(capture_file *cf)
{
  header_field_info       *hfinfo;
  guint32                 framenum;

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
  frame_data *fdata;

  /* Get the frame data struct pointer for this frame */
  fdata = new_packet_list_get_row_data(row);

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
  if (!cf_read_frame (cf, fdata)) {
    return;
  }

  /* Record that this frame is the current frame. */
  cf->current_frame = fdata;
  cf->current_row = row;

  /* Create the logical protocol tree. */
  if (cf->edt != NULL)
    epan_dissect_free(cf->edt);

  /* We don't need the columns here. */
  cf->edt = epan_dissect_new(TRUE, TRUE);

  tap_build_interesting(cf->edt);
  epan_dissect_run(cf->edt, &cf->pseudo_header, cf->pd, cf->current_frame,
          NULL);

  dfilter_macro_build_ftv_cache(cf->edt->tree);

  cf_callback_invoke(cf_cb_packet_selected, cf);
}

/* Unselect the selected packet, if any. */
void
cf_unselect_packet(capture_file *cf)
{
  /* Destroy the epan_dissect_t for the unselected packet. */
  if (cf->edt != NULL) {
    epan_dissect_free(cf->edt);
    cf->edt = NULL;
  }

  /* No packet is selected. */
  cf->current_frame = NULL;
  cf->current_row = 0;

  cf_callback_invoke(cf_cb_packet_unselected, cf);

  /* No protocol tree means no selected field. */
  cf_unselect_field(cf);
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

const gchar* 
cf_read_shb_comment(capture_file *cf)
{
  wtapng_section_t *shb_inf;
  const gchar *temp_str;

  /* Get info from SHB */
  shb_inf = wtap_file_get_shb_info(cf->wth);
  if(shb_inf == NULL)
        return NULL;
  temp_str = shb_inf->opt_comment;
  g_free(shb_inf);

  return temp_str;

}

void
cf_update_capture_comment(capture_file *cf, gchar *comment)
{
  wtapng_section_t *shb_inf;

  /* Get info from SHB */
  shb_inf = wtap_file_get_shb_info(cf->wth);

  /* See if the comment has changed or not */
  if (shb_inf && shb_inf->opt_comment) {
    if (strcmp(shb_inf->opt_comment, comment) == 0) {
      g_free(comment);
      return;
    }
  }

  /* The comment has changed, let's update it */
  wtap_write_shb_comment(cf->wth, comment);
  /* Mark the file as unsaved */
  cf->user_saved = FALSE;
}

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
save_packet(capture_file *cf _U_, frame_data *fdata,
            union wtap_pseudo_header *pseudo_header, const guint8 *pd,
            void *argsp)
{
  save_callback_args_t *args = argsp;
  struct wtap_pkthdr hdr;
  int           err;

  /* init the wtap header for saving */
  hdr.ts.secs      = fdata->abs_ts.secs;
  hdr.ts.nsecs     = fdata->abs_ts.nsecs;
  hdr.caplen       = fdata->cap_len;
  hdr.len          = fdata->pkt_len;
  hdr.pkt_encap    = fdata->lnk_t;
  /* pcapng */
  hdr.interface_id = fdata->interface_id;   /* identifier of the interface. */
  /* options */
  hdr.opt_comment  = fdata->opt_comment; /* NULL if not available */
#if 0
  hdr.drop_count   =
  hdr.pack_flags   =     /* XXX - 0 for now (any value for "we don't have it"?) */
#endif
  /* and save the packet */
  if (!wtap_dump(args->pdh, &hdr, pseudo_header, pd, &err)) {
    if (err < 0) {
      /* Wiretap error. */
      switch (err) {

      case WTAP_ERR_UNSUPPORTED_ENCAP:
        /*
         * This is a problem with the particular frame we're writing;
         * note that, and give the frame number.
         */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Frame %u has a network type that can't be saved in a \"%s\" file.",
                      fdata->num, wtap_file_type_string(args->file_type));
        break;

      default:
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "An error occurred while writing to the file \"%s\": %s.",
                      args->fname, wtap_strerror(err));
        break;
      }
    } else {
      /* OS error. */
      write_failure_alert_box(args->fname, err);
    }
    return FALSE;
  }
  return TRUE;
}

/*
 * Can this capture file be saved in any format except by copying the raw data?
 */
gboolean
cf_can_save_as(capture_file *cf)
{
  int ft;

  for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
    /* To save a file with Wiretap, Wiretap has to handle that format,
       and its code to handle that format must be able to write a file
       with this file's encapsulation type. */
    if (wtap_dump_can_open(ft) && wtap_dump_can_write_encap(ft, cf->lnk_t)) {
      /* OK, we can write it out in this type. */
      return TRUE;
    }
  }

  /* No, we couldn't save it in any format. */
  return FALSE;
}

cf_status_t
cf_save(capture_file *cf, const char *fname, packet_range_t *range, guint save_format, gboolean compressed)
{
  gchar        *from_filename;
  int           err;
  gboolean      do_copy;
  wtap_dumper  *pdh;
  save_callback_args_t callback_args;

  cf_callback_invoke(cf_cb_file_save_started, (gpointer)fname);

  /* don't write over an existing file. */
  /* this should've been already checked by our caller, just to be sure... */
  if (file_exists(fname)) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "%sCapture file: \"%s\" already exists!%s\n\n"
      "Please choose a different filename.",
      simple_dialog_primary_start(), fname, simple_dialog_primary_end());
    goto fail;
  }

  packet_range_process_init(range);

  if (packet_range_process_all(range) && save_format == cf->cd_t) {
    /* We're not filtering packets, and we're saving it in the format
       it's already in, so we can just move or copy the raw data. */

    if (cf->is_tempfile) {
      /* The file being saved is a temporary file from a live
         capture, so it doesn't need to stay around under that name;
         first, try renaming the capture buffer file to the new name. */
#ifndef _WIN32
      if (ws_rename(cf->filename, fname) == 0) {
        /* That succeeded - there's no need to copy the source file. */
        from_filename = NULL;
    do_copy = FALSE;
      } else {
        if (errno == EXDEV) {
          /* They're on different file systems, so we have to copy the
             file. */
          do_copy = TRUE;
          from_filename = cf->filename;
        } else {
          /* The rename failed, but not because they're on different
             file systems - put up an error message.  (Or should we
             just punt and try to copy?  The only reason why I'd
             expect the rename to fail and the copy to succeed would
             be if we didn't have permission to remove the file from
             the temporary directory, and that might be fixable - but
             is it worth requiring the user to go off and fix it?) */
          simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                        file_rename_error_message(errno), fname);
          goto fail;
        }
      }
#else
      do_copy = TRUE;
      from_filename = cf->filename;
#endif
    } else {
      /* It's a permanent file, so we should copy it, and not remove the
         original. */
      do_copy = TRUE;
      from_filename = cf->filename;
    }

    if (do_copy) {
      /* Copy the file, if we haven't moved it. */
      if (!copy_file_binary_mode(from_filename, fname))
        goto fail;
    }
  } else {
    /* Either we're filtering packets, or we're saving in a different
       format; we can't do that by copying or moving the capture file,
       we have to do it by writing the packets out in Wiretap. */

    wtapng_section_t *shb_hdr = NULL;
    wtapng_iface_descriptions_t *idb_inf = NULL;

    shb_hdr = wtap_file_get_shb_info(cf->wth);
    idb_inf = wtap_file_get_idb_info(cf->wth);

    pdh = wtap_dump_open_ng(fname, save_format, cf->lnk_t, cf->snap,
        compressed, shb_hdr, idb_inf, &err);
    g_free(idb_inf);
    idb_inf = NULL;

    if (pdh == NULL) {
      cf_open_failure_alert_box(fname, err, NULL, TRUE, save_format);
      goto fail;
    }

    /* Add address resolution */
    wtap_dump_set_addrinfo_list(pdh, get_addrinfo_list());

    /* XXX - we let the user save a subset of the packets.

       If we do that, should we make that file the current file?  If so,
       it means we can no longer get at the other packets.  What does
       NetMon do? */

    /* Iterate through the list of packets, processing the packets we were
       told to process.

       XXX - we've already called "packet_range_process_init(range)", but
       "process_specified_packets()" will do it again.  Fortunately,
       that's harmless in this case, as we haven't done anything to
       "range" since we initialized it. */
    callback_args.pdh = pdh;
    callback_args.fname = fname;
    callback_args.file_type = save_format;
    switch (process_specified_packets(cf, range, "Saving", "selected packets",
                                      TRUE, save_packet, &callback_args)) {

    case PSP_FINISHED:
      /* Completed successfully. */
      break;

    case PSP_STOPPED:
      /* The user decided to abort the saving.
         XXX - remove the output file? */
      break;

    case PSP_FAILED:
      /* Error while saving. */
      wtap_dump_close(pdh, &err);
      goto fail;
    }

    if (!wtap_dump_close(pdh, &err)) {
      cf_close_failure_alert_box(fname, err);
      goto fail;
    }
  }

  cf_callback_invoke(cf_cb_file_save_finished, NULL);

  if (packet_range_process_all(range)) {
    /* We saved the entire capture, not just some packets from it.
       Open and read the file we saved it to.

       XXX - this is somewhat of a waste; we already have the
       packets, all this gets us is updated file type information
       (which we could just stuff into "cf"), and having the new
       file be the one we have opened and from which we're reading
       the data, and it means we have to spend time opening and
       reading the file, which could be a significant amount of
       time if the file is large. */
    cf->user_saved = TRUE;

    if ((cf_open(cf, fname, FALSE, &err)) == CF_OK) {
      /* XXX - report errors if this fails?
         What should we return if it fails or is aborted? */

      switch (cf_read(cf, TRUE)) {

      case CF_READ_OK:
      case CF_READ_ERROR:
        /* Just because we got an error, that doesn't mean we were unable
           to read any of the file; we handle what we could get from the
           file. */
        break;

      case CF_READ_ABORTED:
        /* The user bailed out of re-reading the capture file; the
           capture file has been closed - just return (without
           changing any menu settings; "cf_close()" set them
           correctly for the "no capture file open" state). */
        break;
      }
      cf_callback_invoke(cf_cb_file_save_reload_finished, cf);
    }
  }
  return CF_OK;

fail:
  cf_callback_invoke(cf_cb_file_save_failed, NULL);
  return CF_ERROR;
}

static void
cf_open_failure_alert_box(const char *filename, int err, gchar *err_info,
                          gboolean for_writing, int file_type)
{
  if (err < 0) {
    /* Wiretap error. */
    switch (err) {

    case WTAP_ERR_NOT_REGULAR_FILE:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" is a \"special file\" or socket or other non-regular file.",
            filename);
      break;

    case WTAP_ERR_RANDOM_OPEN_PIPE:
      /* Seen only when opening a capture file for reading. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" is a pipe or FIFO; Wireshark can't read pipe or FIFO files.",
            filename);
      break;

    case WTAP_ERR_FILE_UNKNOWN_FORMAT:
      /* Seen only when opening a capture file for reading. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" isn't a capture file in a format Wireshark understands.",
            filename);
      break;

    case WTAP_ERR_UNSUPPORTED:
      /* Seen only when opening a capture file for reading. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" isn't a capture file in a format Wireshark understands.\n"
            "(%s)",
            filename, err_info);
      g_free(err_info);
      break;

    case WTAP_ERR_CANT_WRITE_TO_PIPE:
      /* Seen only when opening a capture file for writing. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" is a pipe, and %s capture files can't be "
            "written to a pipe.",
            filename, wtap_file_type_string(file_type));
      break;

    case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
      /* Seen only when opening a capture file for writing. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Wireshark doesn't support writing capture files in that format.");
      break;

    case WTAP_ERR_UNSUPPORTED_ENCAP:
      if (for_writing) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
              "Wireshark can't save this capture in that format.");
      } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
              "The file \"%s\" is a capture for a network type that Wireshark doesn't support.\n"
              "(%s)",
              filename, err_info);
        g_free(err_info);
      }
      break;

    case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
      if (for_writing) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
              "Wireshark can't save this capture in that format.");
      } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
              "The file \"%s\" is a capture for a network type that Wireshark doesn't support.",
              filename);
      }
      break;

    case WTAP_ERR_BAD_FILE:
      /* Seen only when opening a capture file for reading. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" appears to be damaged or corrupt.\n"
            "(%s)",
            filename, err_info);
      g_free(err_info);
      break;

    case WTAP_ERR_CANT_OPEN:
      if (for_writing) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
              "The file \"%s\" could not be created for some unknown reason.",
              filename);
      } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
              "The file \"%s\" could not be opened for some unknown reason.",
              filename);
      }
      break;

    case WTAP_ERR_SHORT_READ:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" appears to have been cut short"
            " in the middle of a packet or other data.",
            filename);
      break;

    case WTAP_ERR_SHORT_WRITE:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "A full header couldn't be written to the file \"%s\".",
            filename);
      break;

    case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "This file type cannot be written as a compressed file.");
      break;

    case WTAP_ERR_DECOMPRESS:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The compressed file \"%s\" appears to be damaged or corrupt.\n"
            "(%s)", filename, err_info);
      g_free(err_info);
      break;

    default:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" could not be %s: %s.",
            filename,
            for_writing ? "created" : "opened",
            wtap_strerror(err));
      break;
    }
  } else {
    /* OS error. */
    open_failure_alert_box(filename, err, for_writing);
  }
}

static const char *
file_rename_error_message(int err)
{
  const char *errmsg;
  static char errmsg_errno[1024+1];

  switch (err) {

  case ENOENT:
    errmsg = "The path to the file \"%s\" doesn't exist.";
    break;

  case EACCES:
    errmsg = "You don't have permission to move the capture file to \"%s\".";
    break;

  default:
    g_snprintf(errmsg_errno, sizeof(errmsg_errno),
            "The file \"%%s\" could not be moved: %s.",
                wtap_strerror(err));
    errmsg = errmsg_errno;
    break;
  }
  return errmsg;
}

/* Check for write errors - if the file is being written to an NFS server,
   a write error may not show up until the file is closed, as NFS clients
   might not send writes to the server until the "write()" call finishes,
   so that the write may fail on the server but the "write()" may succeed. */
static void
cf_close_failure_alert_box(const char *filename, int err)
{
  if (err < 0) {
    /* Wiretap error. */
    switch (err) {

    case WTAP_ERR_CANT_CLOSE:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The file \"%s\" couldn't be closed for some unknown reason.",
            filename);
      break;

    case WTAP_ERR_SHORT_WRITE:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Not all the packets could be written to the file \"%s\".",
                    filename);
      break;

    default:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "An error occurred while closing the file \"%s\": %s.",
            filename, wtap_strerror(err));
      break;
    }
  } else {
    /* OS error.
       We assume that a close error from the OS is really a write error. */
    write_failure_alert_box(filename, err);
  }
}

/* Reload the current capture file. */
void
cf_reload(capture_file *cf) {
  gchar *filename;
  gboolean is_tempfile;
  int err;

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
  if (cf_open(cf, filename, is_tempfile, &err) == CF_OK) {
    switch (cf_read(cf, FALSE)) {

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
