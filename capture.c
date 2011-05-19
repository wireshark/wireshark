/* capture.c
 * Routines for packet capture
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

#ifdef HAVE_LIBPCAP

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/dfilter/dfilter.h>
#include "file.h"
#include "capture.h"
#include "capture_ifinfo.h"
#include "capture_sync.h"
#include "capture_info.h"
#include "capture_ui_utils.h"
#include "util.h"
#include "capture-pcap-util.h"
#include "simple_dialog.h"
#include <epan/prefs.h>

#ifdef _WIN32
#include "capture-wpcap.h"
#endif
#include "ui_util.h"
#include "wsutil/file_util.h"
#include "log.h"

typedef struct if_stat_cache_item_s {
    char *name;
    struct pcap_stat ps;
} if_stat_cache_item_t;

struct if_stat_cache_s {
    int stat_fd;
    int fork_child;
    GList *cache_list;  /* List of if_stat_chache_entry_t */
};

/* this callback mechanism should possibly be replaced by the g_signal_...() stuff (if I only would know how :-) */
typedef struct {
    capture_callback_t cb_fct;
    gpointer user_data;
} capture_callback_data_t;

static GList *capture_callbacks = NULL;

static void
capture_callback_invoke(int event, capture_options *capture_opts)
{
    capture_callback_data_t *cb;
    GList *cb_item = capture_callbacks;

    /* there should be at least one interested */
    g_assert(cb_item != NULL);

    while(cb_item != NULL) {
        cb = cb_item->data;
        cb->cb_fct(event, capture_opts, cb->user_data);
        cb_item = g_list_next(cb_item);
    }
}


void
capture_callback_add(capture_callback_t func, gpointer user_data)
{
    capture_callback_data_t *cb;

    cb = g_malloc(sizeof(capture_callback_data_t));
    cb->cb_fct = func;
    cb->user_data = user_data;

    capture_callbacks = g_list_append(capture_callbacks, cb);
}

void
capture_callback_remove(capture_callback_t func)
{
    capture_callback_data_t *cb;
    GList *cb_item = capture_callbacks;

    while(cb_item != NULL) {
        cb = cb_item->data;
        if(cb->cb_fct == func) {
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
capture_start(capture_options *capture_opts)
{
  gboolean ret;
  guint i;
  GString *source = g_string_new("");

  if (capture_opts->state != CAPTURE_STOPPED)
    return FALSE;
  capture_opts->state = CAPTURE_PREPARING;

  /* close the currently loaded capture file */
  cf_close(capture_opts->cf);

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Start ...");

#ifdef _WIN32
  if (capture_opts->ifaces->len < 2) {
#else
  if (capture_opts->ifaces->len < 4) {
#endif
    for (i = 0; i < capture_opts->ifaces->len; i++) {
      interface_options interface_opts;

      interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
      if (i > 0) {
          if (capture_opts->ifaces->len > 2) {
              g_string_append_printf(source, ",");
          }
          g_string_append_printf(source, " ");
          if (i == capture_opts->ifaces->len - 1) {
              g_string_append_printf(source, "and ");
          }
      }
      g_string_append_printf(source, "%s", get_iface_description_for_interface(capture_opts, i));
      if ((interface_opts.cfilter != NULL) &&
          (strlen(interface_opts.cfilter) > 0)) {
        g_string_append_printf(source, " (%s)", interface_opts.cfilter);
      }
    }
  } else {
    g_string_append_printf(source, "%u interfaces", capture_opts->ifaces->len);
  }
  cf_set_tempfile_source(capture_opts->cf, source->str);
  g_string_free(source, TRUE);

  /* try to start the capture child process */
  ret = sync_pipe_start(capture_opts);
  if(!ret) {
      if(capture_opts->save_file != NULL) {
          g_free(capture_opts->save_file);
          capture_opts->save_file = NULL;
      }

      g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Start failed!");
      capture_opts->state = CAPTURE_STOPPED;
  } else {
      /* the capture child might not respond shortly after bringing it up */
      /* (for example: it will block if no input arrives from an input capture pipe (e.g. mkfifo)) */

      /* to prevent problems, bring the main GUI into "capture mode" right after a successful */
      /* spawn/exec of the capture child, without waiting for any response from it */
      capture_callback_invoke(capture_cb_capture_prepared, capture_opts);

      if(capture_opts->show_info)
        capture_info_open(capture_opts);
  }

  return ret;
}


void
capture_stop(capture_options *capture_opts)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Stop ...");

  capture_callback_invoke(capture_cb_capture_stopping, capture_opts);

  /* stop the capture child gracefully */
  sync_pipe_stop(capture_opts);
}


void
capture_restart(capture_options *capture_opts)
{
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Restart");

    capture_opts->restart = TRUE;
    capture_stop(capture_opts);
}


void
capture_kill_child(capture_options *capture_opts)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_INFO, "Capture Kill");

  /* kill the capture child */
  sync_pipe_kill(capture_opts->fork_child);
}



/* We've succeeded in doing a (non real-time) capture; try to read it into a new capture file */
static gboolean
capture_input_read_all(capture_options *capture_opts, gboolean is_tempfile, gboolean drops_known,
guint32 drops)
{
  int err;

  /* Capture succeeded; attempt to open the capture file. */
  if (cf_open(capture_opts->cf, capture_opts->save_file, is_tempfile, &err) != CF_OK) {
    /* We're not doing a capture any more, so we don't have a save file. */
    return FALSE;
  }
  
  /* Set the read filter to NULL. */
  /* XXX - this is odd here; try to put it somewhere where it fits better */
  cf_set_rfcode(capture_opts->cf, NULL);

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
    cf_set_drops_known(capture_opts->cf, TRUE);

    /* XXX - on some systems, libpcap doesn't bother filling in
       "ps_ifdrop" - it doesn't even set it to zero - so we don't
       bother looking at it.

       Ideally, libpcap would have an interface that gave us
       several statistics - perhaps including various interface
       error statistics - and would tell us which of them it
       supplies, allowing us to display only the ones it does. */
    cf_set_drops(capture_opts->cf, drops);
  }

  /* read in the packet data */
  switch (cf_read(capture_opts->cf, FALSE)) {

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
  if(cf_get_packet_count(capture_opts->cf) == 0 && !capture_opts->restart) {
    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
"%sNo packets captured!%s\n"
"\n"
"As no data was captured, closing the %scapture file!\n"
"\n"
"\n"
"Help about capturing can be found at:\n"
"\n"
"       http://wiki.wireshark.org/CaptureSetup"
#ifdef _WIN32
"\n\n"
"Wireless (Wi-Fi/WLAN):\n"
"Try to switch off promiscuous mode in the Capture Options!"
#endif
"",
    simple_dialog_primary_start(), simple_dialog_primary_end(),
    (cf_is_tempfile(capture_opts->cf)) ? "temporary " : "");
    cf_close(capture_opts->cf);
  }
  return TRUE;
}


/* capture child tells us we have a new (or the first) capture file */
gboolean
capture_input_new_file(capture_options *capture_opts, gchar *new_file)
{
  gboolean is_tempfile;
  int  err;

  if(capture_opts->state == CAPTURE_PREPARING) {
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture started!");
  }
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "File: \"%s\"", new_file);

  g_assert(capture_opts->state == CAPTURE_PREPARING || capture_opts->state == CAPTURE_RUNNING);

  /* free the old filename */
  if(capture_opts->save_file != NULL) {
    /* we start a new capture file, close the old one (if we had one before). */
    /* (we can only have an open capture file in real_time_mode!) */
    if( ((capture_file *) capture_opts->cf)->state != FILE_CLOSED) {
        capture_callback_invoke(capture_cb_capture_update_finished, capture_opts);
        cf_finish_tail(capture_opts->cf, &err);
        cf_close(capture_opts->cf);
    }
    g_free(capture_opts->save_file);
    is_tempfile = FALSE;
    cf_set_tempfile(capture_opts->cf, FALSE);
  } else {
    /* we didn't have a save_file before; must be a tempfile */
    is_tempfile = TRUE;
    cf_set_tempfile(capture_opts->cf, TRUE);
  }

  /* save the new filename */
  capture_opts->save_file = g_strdup(new_file);

  /* if we are in real-time mode, open the new file now */
  if(capture_opts->real_time_mode) {
    /* Attempt to open the capture file and set up to read from it. */
    switch(cf_start_tail(capture_opts->cf, capture_opts->save_file, is_tempfile, &err)) {
    case CF_OK:
      break;
    case CF_ERROR:
      /* Don't unlink (delete) the save file - leave it around,
         for debugging purposes. */
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      return FALSE;
    }
  }

  if(capture_opts->show_info) {
    if (!capture_info_new_file(new_file))
      return FALSE;
  }

  if(capture_opts->real_time_mode) {
    capture_callback_invoke(capture_cb_capture_update_started, capture_opts);
  } else {
    capture_callback_invoke(capture_cb_capture_fixed_started, capture_opts);
  }
  capture_opts->state = CAPTURE_RUNNING;

  return TRUE;
}


/* capture child tells us we have new packets to read */
void
capture_input_new_packets(capture_options *capture_opts, int to_read)
{
  int  err;


  g_assert(capture_opts->save_file);

  if(capture_opts->real_time_mode) {
    /* Read from the capture file the number of records the child told us it added. */
    switch (cf_continue_tail(capture_opts->cf, to_read, &err)) {

    case CF_READ_OK:
    case CF_READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file.

         XXX - abort on a read error? */
         capture_callback_invoke(capture_cb_capture_update_continue, capture_opts);
      break;

    case CF_READ_ABORTED:
      /* Kill the child capture process; the user wants to exit, and we
         shouldn't just leave it running. */
      capture_kill_child(capture_opts);
      break;
    }
  } else {
    /* increase the capture file packet counter by the number of incoming packets */
    cf_set_packet_count(capture_opts->cf,
        cf_get_packet_count(capture_opts->cf) + to_read);
    cf_fake_continue_tail(capture_opts->cf);

    capture_callback_invoke(capture_cb_capture_fixed_continue, capture_opts);
  }

  /* update the main window so we get events (e.g. from the stop toolbar button) */
  main_window_update();

  if(capture_opts->show_info)
    capture_info_new_packets(to_read);
}


/* Capture child told us how many dropped packets it counted.
 */
void
capture_input_drops(capture_options *capture_opts, guint32 dropped)
{
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_INFO, "%u packet%s dropped", dropped, plurality(dropped, "", "s"));

  g_assert(capture_opts->state == CAPTURE_RUNNING);

  cf_set_drops_known(capture_opts->cf, TRUE);
  cf_set_drops(capture_opts->cf, dropped);
}


/* Capture child told us that an error has occurred while starting/running
   the capture.
   The buffer we're handed has *two* null-terminated strings in it - a
   primary message and a secondary message, one right after the other.
   The secondary message might be a null string.
 */
void
capture_input_error_message(capture_options *capture_opts, char *error_msg, char *secondary_error_msg)
{
  gchar *safe_error_msg;
  gchar *safe_secondary_error_msg;

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Error message from child: \"%s\", \"%s\"",
        error_msg, secondary_error_msg);

  g_assert(capture_opts->state == CAPTURE_PREPARING || capture_opts->state == CAPTURE_RUNNING);

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
capture_input_cfilter_error_message(capture_options *capture_opts, char *error_message)
{
  dfilter_t   *rfcode = NULL;
  gchar *safe_cfilter = simple_dialog_format_message(capture_opts->cfilter);
  gchar *safe_cfilter_error_msg = simple_dialog_format_message(error_message);

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture filter error message from child: \"%s\"", error_message);

  g_assert(capture_opts->state == CAPTURE_PREPARING || capture_opts->state == CAPTURE_RUNNING);

  /* Did the user try a display filter? */
  if (dfilter_compile(capture_opts->cfilter, &rfcode) && rfcode != NULL) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "%sInvalid capture filter: \"%s\"!%s\n"
      "\n"
      "That string looks like a valid display filter; however, it isn't a valid\n"
      "capture filter (%s).\n"
      "\n"
      "Note that display filters and capture filters don't have the same syntax,\n"
      "so you can't use most display filter expressions as capture filters.\n"
      "\n"
      "See the User's Guide for a description of the capture filter syntax.",
      simple_dialog_primary_start(), safe_cfilter,
      simple_dialog_primary_end(), safe_cfilter_error_msg);
      dfilter_free(rfcode);
  } else {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "%sInvalid capture filter: \"%s\"!%s\n"
      "\n"
      "That string isn't a valid capture filter (%s).\n"
      "See the User's Guide for a description of the capture filter syntax.",
      simple_dialog_primary_start(), safe_cfilter,
      simple_dialog_primary_end(), safe_cfilter_error_msg);
  }
  g_free(safe_cfilter_error_msg);
  g_free(safe_cfilter);

  /* the capture child will close the sync_pipe if required, nothing to do for now */
}


/* capture child closed its side of the pipe, do the required cleanup */
void
capture_input_closed(capture_options *capture_opts, gchar *msg)
{
    int  err;
    int  packet_count_save;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture stopped!");
    g_assert(capture_opts->state == CAPTURE_PREPARING || capture_opts->state == CAPTURE_RUNNING);

    if (msg != NULL)
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", msg);

    /* if we didn't start the capture, do a fake start. */
    /* (happens if we got an error message - we won't get a filename then). */
    if(capture_opts->state == CAPTURE_PREPARING) {
        if(capture_opts->real_time_mode) {
            capture_callback_invoke(capture_cb_capture_update_started, capture_opts);
        } else {
            capture_callback_invoke(capture_cb_capture_fixed_started, capture_opts);
        }
    }

    if(capture_opts->real_time_mode) {
        cf_read_status_t status;

        /* Read what remains of the capture file. */
        status = cf_finish_tail(capture_opts->cf, &err);

        /* XXX: If -Q (quit-after-cap) then cf->count clr'd below so save it first */
        packet_count_save = cf_get_packet_count(capture_opts->cf);
        /* Tell the GUI we are not doing a capture any more.
           Must be done after the cf_finish_tail(), so file lengths are 
           correctly displayed */
        capture_callback_invoke(capture_cb_capture_update_finished, capture_opts);

        /* Finish the capture. */
        switch (status) {

        case CF_READ_OK:
            if ((packet_count_save == 0) && !capture_opts->restart) {
                simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
"%sNo packets captured!%s\n"
"\n"
"As no data was captured, closing the %scapture file!\n"
"\n"
"\n"
"Help about capturing can be found at:\n"
"\n"
"       http://wiki.wireshark.org/CaptureSetup"
#ifdef _WIN32
"\n\n"
"Wireless (Wi-Fi/WLAN):\n"
"Try to switch off promiscuous mode in the Capture Options!"
#endif
"",
              simple_dialog_primary_start(), simple_dialog_primary_end(),
              cf_is_tempfile(capture_opts->cf) ? "temporary " : "");
              cf_close(capture_opts->cf);
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
        capture_callback_invoke(capture_cb_capture_fixed_finished, capture_opts);

        /* this is a normal mode capture and if no error happened, read in the capture file data */
        if(capture_opts->save_file != NULL) {
            capture_input_read_all(capture_opts, cf_is_tempfile(capture_opts->cf),
                cf_get_drops_known(capture_opts->cf), cf_get_drops(capture_opts->cf));
        }
    }

    if(capture_opts->show_info)
      capture_info_close();

    capture_opts->state = CAPTURE_STOPPED;

    /* if we couldn't open a capture file, there's nothing more for us to do */
    if(capture_opts->save_file == NULL) {
        cf_close(capture_opts->cf);
        return;
    }

    /* does the user wants to restart the current capture? */
    if(capture_opts->restart) {
        capture_opts->restart = FALSE;

        ws_unlink(capture_opts->save_file);

        /* if it was a tempfile, throw away the old filename (so it will become a tempfile again) */
        if(cf_is_tempfile(capture_opts->cf)) {
            g_free(capture_opts->save_file);
            capture_opts->save_file = NULL;
        }

        /* ... and start the capture again */
        capture_start(capture_opts);
    } else {
        /* We're not doing a capture any more, so we don't have a save file. */
        g_free(capture_opts->save_file);
        capture_opts->save_file = NULL;
    }
}

if_stat_cache_t *
capture_stat_start(GList *if_list) {
    int stat_fd, fork_child;
    gchar *msg;
    if_stat_cache_t *sc = NULL;
    GList *if_entry;
    if_info_t *if_info;
    if_stat_cache_item_t *sc_item;

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
     if (sync_interface_stats_open(&stat_fd, &fork_child, &msg) == 0) {
        sc = g_malloc(sizeof(if_stat_cache_t));
        sc->stat_fd = stat_fd;
        sc->fork_child = fork_child;
        sc->cache_list = NULL;

        /* Initialize the cache */
        for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
            if_info = if_entry->data;
            sc_item = g_malloc0(sizeof(if_stat_cache_item_t));
            sc_item->name = g_strdup(if_info->name);
            sc->cache_list = g_list_append(sc->cache_list, sc_item);
        }
    }
    return sc;
}

#define MAX_STAT_LINE_LEN 500

static void
capture_stat_cache_update(if_stat_cache_t *sc) {
    gchar stat_line[MAX_STAT_LINE_LEN];
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
            sc_item = sc_entry->data;
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
        sc_item = sc_entry->data;
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
        sc_item = sc_entry->data;
        g_free(sc_item->name);
        g_free(sc_item);
    }
    g_free(sc);
}

#endif /* HAVE_LIBPCAP */
