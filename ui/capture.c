/* capture.c
 * Routines for packet capture
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

#include "config.h"

#ifdef HAVE_LIBPCAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/dfilter/dfilter.h>
#include "file.h"
#include "ui/capture.h"
#include "caputils/capture_ifinfo.h"
#include <capchild/capture_sync.h>
#include "capture_info.h"
#include "ui/capture_ui_utils.h"
#include "ui/util.h"
#include "caputils/capture-pcap-util.h"
#include <epan/prefs.h>

#ifdef _WIN32
#include "caputils/capture-wpcap.h"
#endif

#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include "wsutil/file_util.h"
#include "wsutil/str_util.h"
#include "log.h"

typedef struct if_stat_cache_item_s {
    char *name;
    struct pcap_stat ps;
} if_stat_cache_item_t;

struct if_stat_cache_s {
    int stat_fd;
    ws_process_id fork_child;
    GList *cache_list;  /* List of if_stat_chache_entry_t */
};

/* this callback mechanism should possibly be replaced by the g_signal_...() stuff (if I only would know how :-) */
typedef struct {
    capture_callback_t cb_fct;
    gpointer user_data;
} capture_callback_data_t;

static GList *capture_callbacks = NULL;

static void
capture_callback_invoke(int event, capture_session *cap_session)
{
  capture_callback_data_t *cb;
  GList *cb_item = capture_callbacks;

  /* there should be at least one interested */
  g_assert(cb_item != NULL);

  while(cb_item != NULL) {
    cb = (capture_callback_data_t *)cb_item->data;
    cb->cb_fct(event, cap_session, cb->user_data);
    cb_item = g_list_next(cb_item);
  }
}


void
capture_callback_add(capture_callback_t func, gpointer user_data)
{
  capture_callback_data_t *cb;

  cb = (capture_callback_data_t *)g_malloc(sizeof(capture_callback_data_t));
  cb->cb_fct = func;
  cb->user_data = user_data;

  capture_callbacks = g_list_append(capture_callbacks, cb);
}

void
capture_callback_remove(capture_callback_t func, gpointer user_data)
{
  capture_callback_data_t *cb;
  GList *cb_item = capture_callbacks;

  while(cb_item != NULL) {
    cb = (capture_callback_data_t *)cb_item->data;
    if(cb->cb_fct == func && cb->user_data == user_data) {
      capture_callbacks = g_list_remove(capture_callbacks, cb);
      g_free(cb);
      return;
    }
    cb_item = g_list_next(cb_item);
  }

  g_assert_not_reached();
}

/**
 * Start a capture.
 *
 * @return TRUE if the capture starts successfully, FALSE otherwise.
 */
gboolean
capture_start(capture_options *capture_opts, capture_session *cap_session, info_data_t* cap_data, void(*update_cb)(void))
{
  gboolean ret;
  GString *source;

  cap_session->state = CAPTURE_PREPARING;
  cap_session->count = 0;
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Start ...");
  source = get_iface_list_string(capture_opts, IFLIST_SHOW_FILTER);
  cf_set_tempfile_source((capture_file *)cap_session->cf, source->str);
  g_string_free(source, TRUE);
  /* try to start the capture child process */
  ret = sync_pipe_start(capture_opts, cap_session, cap_data, update_cb);
  if(!ret) {
      if(capture_opts->save_file != NULL) {
          g_free(capture_opts->save_file);
          capture_opts->save_file = NULL;
      }

      g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Start failed.");
      cap_session->state = CAPTURE_STOPPED;
  } else {
      /* the capture child might not respond shortly after bringing it up */
      /* (for example: it will block if no input arrives from an input capture pipe (e.g. mkfifo)) */

      /* to prevent problems, bring the main GUI into "capture mode" right after a successful */
      /* spawn/exec of the capture child, without waiting for any response from it */
      capture_callback_invoke(capture_cb_capture_prepared, cap_session);

      if(capture_opts->show_info)
        capture_info_open(cap_session, cap_data);
  }

  return ret;
}


void
capture_stop(capture_session *cap_session)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Stop ...");

  capture_callback_invoke(capture_cb_capture_stopping, cap_session);

  /* stop the capture child gracefully */
  sync_pipe_stop(cap_session);
}


void
capture_restart(capture_session *cap_session)
{
    capture_options *capture_opts = cap_session->capture_opts;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Restart");

    capture_opts->restart = TRUE;
    capture_stop(cap_session);
}


void
capture_kill_child(capture_session *cap_session)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_INFO, "Capture Kill");

  /* kill the capture child */
  sync_pipe_kill(cap_session->fork_child);
}

/* We've succeeded in doing a (non real-time) capture; try to read it into a new capture file */
static gboolean
capture_input_read_all(capture_session *cap_session, gboolean is_tempfile,
                       gboolean drops_known, guint32 drops)
{
  capture_options *capture_opts = cap_session->capture_opts;
  int err;

  /* Capture succeeded; attempt to open the capture file. */
  if (cf_open((capture_file *)cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err) != CF_OK) {
    /* We're not doing a capture any more, so we don't have a save file. */
    return FALSE;
  }

  /* Set the read filter to NULL. */
  /* XXX - this is odd here; try to put it somewhere where it fits better */
  cf_set_rfcode((capture_file *)cap_session->cf, NULL);

  /* Get the packet-drop statistics.

     XXX - there are currently no packet-drop statistics stored
     in libpcap captures, and that's what we're reading.

     At some point, we will add support in Wiretap to return
     packet-drop statistics for capture file formats that store it,
     and will make "cf_read()" get those statistics from Wiretap.
     We clear the statistics (marking them as "not known") in
     "cf_open()", and "cf_read()" will only fetch them and mark
     them as known if Wiretap supplies them, so if we get the
     statistics now, after calling "cf_open()" but before calling
     "cf_read()", the values we store will be used by "cf_read()".

     If a future libpcap capture file format stores the statistics,
     we'll put them into the capture file that we write, and will
     thus not have to set them here - "cf_read()" will get them from
     the file and use them. */
  if (drops_known) {
    cf_set_drops_known((capture_file *)cap_session->cf, TRUE);

    /* XXX - on some systems, libpcap doesn't bother filling in
       "ps_ifdrop" - it doesn't even set it to zero - so we don't
       bother looking at it.

       Ideally, libpcap would have an interface that gave us
       several statistics - perhaps including various interface
       error statistics - and would tell us which of them it
       supplies, allowing us to display only the ones it does. */
    cf_set_drops((capture_file *)cap_session->cf, drops);
  }

  /* read in the packet data */
  switch (cf_read((capture_file *)cap_session->cf, FALSE)) {

  case CF_READ_OK:
  case CF_READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file. */
    break;

  case CF_READ_ABORTED:
    /* User wants to quit program. Exit by leaving the main loop,
       so that any quit functions we registered get called. */
    main_window_nested_quit();
    return FALSE;
  }

  /* if we didn't capture even a single packet, close the file again */
  if(cap_session->count == 0 && !capture_opts->restart) {
    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
"%sNo packets captured.%s\n"
"\n"
"As no data was captured, closing the %scapture file.\n"
"\n"
"\n"
"Help about capturing can be found at\n"
"\n"
"       https://wiki.wireshark.org/CaptureSetup"
#ifdef _WIN32
"\n\n"
"Wireless (Wi-Fi/WLAN):\n"
"Try to switch off promiscuous mode in the Capture Options"
#endif
"",
    simple_dialog_primary_start(), simple_dialog_primary_end(),
    (cf_is_tempfile((capture_file *)cap_session->cf)) ? "temporary " : "");
    cf_close((capture_file *)cap_session->cf);
  }
  return TRUE;
}


/* capture child tells us we have a new (or the first) capture file */
gboolean
capture_input_new_file(capture_session *cap_session, gchar *new_file)
{
  capture_options *capture_opts = cap_session->capture_opts;
  gboolean is_tempfile;
  int  err;

  if(cap_session->state == CAPTURE_PREPARING) {
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture started");
  }
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "File: \"%s\"", new_file);

  g_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

  /* free the old filename */
  if(capture_opts->save_file != NULL) {
    /* we start a new capture file, close the old one (if we had one before). */
    /* (we can only have an open capture file in real_time_mode!) */
    if( ((capture_file *) cap_session->cf)->state != FILE_CLOSED) {
        if(capture_opts->real_time_mode) {
            capture_callback_invoke(capture_cb_capture_update_finished, cap_session);
            cf_finish_tail((capture_file *)cap_session->cf, &err);
            cf_close((capture_file *)cap_session->cf);
        } else {
            capture_callback_invoke(capture_cb_capture_fixed_finished, cap_session);
        }
    }
    g_free(capture_opts->save_file);
    is_tempfile = FALSE;
    cf_set_tempfile((capture_file *)cap_session->cf, FALSE);
  } else {
    /* we didn't have a save_file before; must be a tempfile */
    is_tempfile = TRUE;
    cf_set_tempfile((capture_file *)cap_session->cf, TRUE);
  }

  /* save the new filename */
  capture_opts->save_file = g_strdup(new_file);

  /* if we are in real-time mode, open the new file now */
  if(capture_opts->real_time_mode) {
    /* Attempt to open the capture file and set up to read from it. */
    switch(cf_open((capture_file *)cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err)) {
    case CF_OK:
      break;
    case CF_ERROR:
      /* Don't unlink (delete) the save file - leave it around,
         for debugging purposes. */
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      return FALSE;
    }
  } else {
    capture_callback_invoke(capture_cb_capture_prepared, cap_session);
  }

  if(capture_opts->show_info) {
    if (!capture_info_new_file(new_file, cap_session->cap_data_info))
      return FALSE;
  }

  if(capture_opts->real_time_mode) {
    capture_callback_invoke(capture_cb_capture_update_started, cap_session);
  } else {
    capture_callback_invoke(capture_cb_capture_fixed_started, cap_session);
  }
  cap_session->state = CAPTURE_RUNNING;

  return TRUE;
}


/* capture child tells us we have new packets to read */
void
capture_input_new_packets(capture_session *cap_session, int to_read)
{
  capture_options *capture_opts = cap_session->capture_opts;
  int  err;

  g_assert(capture_opts->save_file);

  if(capture_opts->real_time_mode) {
    /* Read from the capture file the number of records the child told us it added. */
    switch (cf_continue_tail((capture_file *)cap_session->cf, to_read, &err)) {

    case CF_READ_OK:
    case CF_READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file.

         XXX - abort on a read error? */
         capture_callback_invoke(capture_cb_capture_update_continue, cap_session);
      break;

    case CF_READ_ABORTED:
      /* Kill the child capture process; the user wants to exit, and we
         shouldn't just leave it running. */
      capture_kill_child(cap_session);
      break;
    }
  } else {
    cf_fake_continue_tail((capture_file *)cap_session->cf);

    capture_callback_invoke(capture_cb_capture_fixed_continue, cap_session);
  }

  /* update the main window so we get events (e.g. from the stop toolbar button) */
  /* This causes a hang on Windows (see bug 7305). Do we need this on any platform? */
#ifndef _WIN32
  main_window_update();
#endif

  if(capture_opts->show_info)
    capture_info_new_packets(to_read, cap_session->cap_data_info);
}


/* Capture child told us how many dropped packets it counted.
 */
void
capture_input_drops(capture_session *cap_session, guint32 dropped)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_INFO, "%u packet%s dropped", dropped, plurality(dropped, "", "s"));

  g_assert(cap_session->state == CAPTURE_RUNNING);

  cf_set_drops_known((capture_file *)cap_session->cf, TRUE);
  cf_set_drops((capture_file *)cap_session->cf, dropped);
}


/* Capture child told us that an error has occurred while starting/running
   the capture.
   The buffer we're handed has *two* null-terminated strings in it - a
   primary message and a secondary message, one right after the other.
   The secondary message might be a null string.
 */
void
capture_input_error_message(capture_session *cap_session, char *error_msg,
                            char *secondary_error_msg)
{
  gchar *safe_error_msg;
  gchar *safe_secondary_error_msg;

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Error message from child: \"%s\", \"%s\"",
        error_msg, secondary_error_msg);

  g_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

  safe_error_msg = simple_dialog_format_message(error_msg);
  if (*secondary_error_msg != '\0') {
    /* We have both primary and secondary messages. */
    safe_secondary_error_msg = simple_dialog_format_message(secondary_error_msg);
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s%s%s\n\n%s",
                  simple_dialog_primary_start(), safe_error_msg,
                  simple_dialog_primary_end(), safe_secondary_error_msg);
    g_free(safe_secondary_error_msg);
  } else {
    /* We have only a primary message. */
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s%s%s",
                  simple_dialog_primary_start(), safe_error_msg,
                  simple_dialog_primary_end());
  }
  g_free(safe_error_msg);

  /* the capture child will close the sync_pipe if required, nothing to do for now */
}

/* Capture child told us that an error has occurred while parsing a
   capture filter when starting/running the capture.
 */
void
capture_input_cfilter_error_message(capture_session *cap_session, guint i,
                                    char *error_message)
{
  capture_options *capture_opts = cap_session->capture_opts;
  dfilter_t *rfcode = NULL;
  gchar *safe_cfilter;
  gchar *safe_descr;
  gchar *safe_cfilter_error_msg;
  interface_options interface_opts;

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture filter error message from child: \"%s\"", error_message);

  g_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);
  g_assert(i < capture_opts->ifaces->len);

  interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
  safe_cfilter = simple_dialog_format_message(interface_opts.cfilter);
  safe_descr = simple_dialog_format_message(interface_opts.descr);
  safe_cfilter_error_msg = simple_dialog_format_message(error_message);
  /* Did the user try a display filter? */
  if (dfilter_compile(interface_opts.cfilter, &rfcode, NULL) && rfcode != NULL) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "%sInvalid capture filter \"%s\" for interface %s.%s\n"
      "\n"
      "That string looks like a valid display filter; however, it isn't a valid\n"
      "capture filter (%s).\n"
      "\n"
      "Note that display filters and capture filters don't have the same syntax,\n"
      "so you can't use most display filter expressions as capture filters.\n"
      "\n"
      "See the User's Guide for a description of the capture filter syntax.",
      simple_dialog_primary_start(), safe_cfilter, safe_descr,
      simple_dialog_primary_end(), safe_cfilter_error_msg);
      dfilter_free(rfcode);
  } else {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "%sInvalid capture filter \"%s\" for interface %s.%s\n"
      "\n"
      "That string isn't a valid capture filter (%s).\n"
      "See the User's Guide for a description of the capture filter syntax.",
      simple_dialog_primary_start(), safe_cfilter, safe_descr,
      simple_dialog_primary_end(), safe_cfilter_error_msg);
  }
  g_free(safe_cfilter_error_msg);
  g_free(safe_descr);
  g_free(safe_cfilter);

  /* the capture child will close the sync_pipe if required, nothing to do for now */
}

/* capture child closed its side of the pipe, do the required cleanup */
void
capture_input_closed(capture_session *cap_session, gchar *msg)
{
  capture_options *capture_opts = cap_session->capture_opts;
  int  err;

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture stopped.");
  g_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

  if (msg != NULL)
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", msg);

  if(cap_session->state == CAPTURE_PREPARING) {
    /* We didn't start a capture; note that the attempt to start it
       failed. */
    capture_callback_invoke(capture_cb_capture_failed, cap_session);
  } else {
    /* We started a capture; process what's left of the capture file if
       we were in "update list of packets in real time" mode, or process
       all of it if we weren't. */
    if(capture_opts->real_time_mode) {
      cf_read_status_t status;

      /* Read what remains of the capture file. */
      status = cf_finish_tail((capture_file *)cap_session->cf, &err);

      /* Tell the GUI we are not doing a capture any more.
         Must be done after the cf_finish_tail(), so file lengths are
         correctly displayed */
      capture_callback_invoke(capture_cb_capture_update_finished, cap_session);

      /* Finish the capture. */
      switch (status) {

      case CF_READ_OK:
        if (cap_session->count == 0 && !capture_opts->restart) {
          simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
            "%sNo packets captured.%s\n"
            "\n"
            "As no data was captured, closing the %scapture file.\n"
            "\n"
            "\n"
            "Help about capturing can be found at\n"
            "\n"
            "       https://wiki.wireshark.org/CaptureSetup"
#ifdef _WIN32
            "\n\n"
            "Wireless (Wi-Fi/WLAN):\n"
            "Try to switch off promiscuous mode in the Capture Options."
#endif
            "",
            simple_dialog_primary_start(), simple_dialog_primary_end(),
            cf_is_tempfile((capture_file *)cap_session->cf) ? "temporary " : "");
          cf_close((capture_file *)cap_session->cf);
        }
        break;
      case CF_READ_ERROR:
        /* Just because we got an error, that doesn't mean we were unable
           to read any of the file; we handle what we could get from the
           file. */
        break;

      case CF_READ_ABORTED:
        /* Exit by leaving the main loop, so that any quit functions
           we registered get called. */
        main_window_quit();
        break;
      }
    } else {
      /* first of all, we are not doing a capture any more */
      capture_callback_invoke(capture_cb_capture_fixed_finished, cap_session);

      /* this is a normal mode capture and if no error happened, read in the capture file data */
      if(capture_opts->save_file != NULL) {
        capture_input_read_all(cap_session, cf_is_tempfile((capture_file *)cap_session->cf),
          cf_get_drops_known((capture_file *)cap_session->cf), cf_get_drops((capture_file *)cap_session->cf));
      }
    }
  }

  if(capture_opts->show_info)
    capture_info_close(cap_session->cap_data_info);

  cap_session->state = CAPTURE_STOPPED;

  /* if we couldn't open a capture file, there's nothing more for us to do */
  if(capture_opts->save_file == NULL) {
    cf_close((capture_file *)cap_session->cf);
    return;
  }

  /* does the user wants to restart the current capture? */
  if(capture_opts->restart) {
    capture_opts->restart = FALSE;

    ws_unlink(capture_opts->save_file);

    /* If we have a ring buffer, the original save file has been overwritten
       with the "ring filename".  Restore it before starting again */
    if ((capture_opts->multi_files_on) && (capture_opts->orig_save_file != NULL)) {
      g_free(capture_opts->save_file);
      capture_opts->save_file = g_strdup(capture_opts->orig_save_file);
    }

    /* if it was a tempfile, throw away the old filename (so it will become a tempfile again) */
    if(cf_is_tempfile((capture_file *)cap_session->cf)) {
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
    }

    /* ... and start the capture again */
    if (capture_opts->ifaces->len == 0) {
      collect_ifaces(capture_opts);
    }

    /* close the currently loaded capture file */
    cf_close((capture_file *)cap_session->cf);

    capture_start(capture_opts, cap_session, cap_session->cap_data_info, NULL); /*XXX is this NULL ok or we need an update_cb???*/
  } else {
    /* We're not doing a capture any more, so we don't have a save file. */
    g_free(capture_opts->save_file);
    capture_opts->save_file = NULL;
  }
}

if_stat_cache_t *
capture_stat_start(capture_options *capture_opts) {
  int stat_fd;
  ws_process_id fork_child;
  gchar *msg;
  if_stat_cache_t *sc = NULL;
  if_stat_cache_item_t *sc_item;
  guint i;
  interface_t device;

  /* Fire up dumpcap. */
  /*
   * XXX - on systems with BPF, the number of BPF devices limits the
   * number of devices on which you can capture simultaneously.
   *
   * This means that
   *
   *    1) this might fail if you run out of BPF devices
   *
   * and
   *
   *    2) opening every interface could leave too few BPF devices
   *       for *other* programs.
   *
   * It also means the system could end up getting a lot of traffic
   * that it has to pass through the networking stack and capture
   * mechanism, so opening all the devices and presenting packet
   * counts might not always be a good idea.
   */
  if (sync_interface_stats_open(&stat_fd, &fork_child, &msg, NULL) == 0) {
    sc = (if_stat_cache_t *)g_malloc(sizeof(if_stat_cache_t));
    sc->stat_fd = stat_fd;
    sc->fork_child = fork_child;
    sc->cache_list = NULL;

    /* Initialize the cache */
    for (i = 0; i < capture_opts->all_ifaces->len; i++) {
      device = g_array_index(capture_opts->all_ifaces, interface_t, i);
      if (device.type != IF_PIPE) {
        sc_item = (if_stat_cache_item_t *)g_malloc0(sizeof(if_stat_cache_item_t));
        sc_item->name = g_strdup(device.if_info.name);
        sc->cache_list = g_list_append(sc->cache_list, sc_item);
      }
    }
  } else {
    g_free(msg); /* XXX: should we display this to the user ? */
  }
  return sc;
}

#define MAX_STAT_LINE_LEN 500

static void
capture_stat_cache_update(if_stat_cache_t *sc) {
  gchar stat_line[MAX_STAT_LINE_LEN] = "";
  gchar **stat_parts;
  GList *sc_entry;
  if_stat_cache_item_t *sc_item;

  if (!sc)
    return;

  while (sync_pipe_gets_nonblock(sc->stat_fd, stat_line, MAX_STAT_LINE_LEN) > 0) {
    g_strstrip(stat_line);
    stat_parts = g_strsplit(stat_line, "\t", 3);
    if (stat_parts[0] == NULL || stat_parts[1] == NULL ||
      stat_parts[2] == NULL) {
      g_strfreev(stat_parts);
      continue;
    }
    for (sc_entry = sc->cache_list; sc_entry != NULL; sc_entry = g_list_next(sc_entry)) {
      sc_item = (if_stat_cache_item_t *)sc_entry->data;
      if (strcmp(sc_item->name, stat_parts[0]) == 0) {
        sc_item->ps.ps_recv = (u_int) strtoul(stat_parts[1], NULL, 10);
        sc_item->ps.ps_drop = (u_int) strtoul(stat_parts[2], NULL, 10);
      }
    }
  g_strfreev(stat_parts);
  }
}

gboolean
capture_stats(if_stat_cache_t *sc, char *ifname, struct pcap_stat *ps) {
  GList *sc_entry;
  if_stat_cache_item_t *sc_item;

  if (!sc || !ifname || !ps) {
    return FALSE;
  }

  capture_stat_cache_update(sc);
  for (sc_entry = sc->cache_list; sc_entry != NULL; sc_entry = g_list_next(sc_entry)) {
    sc_item = (if_stat_cache_item_t *)sc_entry->data;
    if (strcmp(sc_item->name, ifname) == 0) {
      memcpy(ps, &sc_item->ps, sizeof(struct pcap_stat));
      return TRUE;
    }
  }
  return FALSE;
}

void
capture_stat_stop(if_stat_cache_t *sc) {
  GList *sc_entry;
  if_stat_cache_item_t *sc_item;
  int ret;
  gchar *msg;

  if (!sc)
    return;

  ret = sync_interface_stats_close(&sc->stat_fd, &sc->fork_child, &msg);
  if (ret == -1) {
    /* XXX - report failure? */
    g_free(msg);
  }

  for (sc_entry = sc->cache_list; sc_entry != NULL; sc_entry = g_list_next(sc_entry)) {
    sc_item = (if_stat_cache_item_t *)sc_entry->data;
    g_free(sc_item->name);
    g_free(sc_item);
  }
  g_list_free(sc->cache_list);
  g_free(sc);
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
