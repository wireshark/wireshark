/* capture_sync.c
 * Synchronisation between Ethereal capture parent and child instances
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <pcap.h>

#include <glib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifndef _WIN32
/*
 * Define various POSIX macros (and, in the case of WCOREDUMP, non-POSIX
 * macros) on UNIX systems that don't have them.
 */
#ifndef WIFEXITED
# define WIFEXITED(status)	(((status) & 0177) == 0)
#endif
#ifndef WIFSTOPPED
# define WIFSTOPPED(status)	(((status) & 0177) == 0177)
#endif
#ifndef WIFSIGNALED
# define WIFSIGNALED(status)	(!WIFSTOPPED(status) && !WIFEXITED(status))
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(status)	((status) >> 8)
#endif
#ifndef WTERMSIG
# define WTERMSIG(status)	((status) & 0177)
#endif
#ifndef WCOREDUMP
# define WCOREDUMP(status)	((status) & 0200)
#endif
#ifndef WSTOPSIG
# define WSTOPSIG(status)	((status) >> 8)
#endif
#endif /* _WIN32 */

#include <epan/packet.h>
#include <epan/prefs.h>

#include "globals.h"
#include "file.h"
#include <epan/filesystem.h>

#include "capture.h"
#include "capture_sync.h"
#include "simple_dialog.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif
#include "ui_util.h"
#include "file_util.h"
#include "log.h"

#ifdef _WIN32
#include <process.h>    /* For spawning child process */
#endif


#ifndef _WIN32
static const char *sync_pipe_signame(int);
#endif


static gboolean sync_pipe_input_cb(gint source, gpointer user_data);
static void sync_pipe_wait_for_child(capture_options *capture_opts);

/*
 * Maximum length of sync pipe message data.  Must be < 2^24, as the
 * message length is 3 bytes.
 * XXX - this must be large enough to handle a Really Big Filter
 * Expression, as the error message for an incorrect filter expression
 * is a bit larger than the filter expression.
 */
#define SP_MAX_MSG_LEN	4096


 /* write a message to the recipient pipe in the standard format 
   (3 digit message length (excluding length and indicator field), 
   1 byte message indicator and the rest is the message) */
static void
pipe_write_block(int pipe, char indicator, int len, const char *msg)
{
    guchar header[3+1]; /* indicator + 3-byte len */
    int ret;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "write %d enter", pipe);

    g_assert(indicator < '0' || indicator > '9');
    g_assert(len <= SP_MAX_MSG_LEN);

    /* write header (indicator + 3-byte len) */
    header[0] = indicator;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8) & 0xFF;
    header[3] = (len >> 0) & 0xFF;

    ret = write(pipe, header, sizeof header);
    if(ret == -1) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_WARNING,
              "write %d header: error %s", pipe, strerror(errno));
        return;
    }

    /* write value (if we have one) */
    if(len) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "write %d indicator: %c value len: %u msg: %s", pipe, indicator,
              len, msg);
        ret = write(pipe, msg, len);
        if(ret == -1) {
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_WARNING,
                  "write %d value: error %s", pipe, strerror(errno));
            return;
        }
    } else {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "write %d indicator: %c no value", pipe, indicator);
    }

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "write %d leave", pipe);
}


#ifndef _WIN32
void
sync_pipe_errmsg_to_parent(const char *errmsg)
{
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "sync_pipe_errmsg_to_parent: %s", errmsg);

    pipe_write_block(1, SP_ERROR_MSG, strlen(errmsg)+1, errmsg);
}
#endif


#ifdef _WIN32
static void
signal_pipe_capquit_to_child(capture_options *capture_opts)
{

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "signal_pipe_capquit_to_child");

    pipe_write_block(capture_opts->signal_pipe_write_fd, SP_QUIT, 0, NULL);
}
#endif



/* read a message from the sending pipe in the standard format 
   (1-byte message indicator, 3-byte message length (excluding length
   and indicator field), and the rest is the message) */
static int
pipe_read_block(int pipe, char *indicator, int len, char *msg) {
    int required;
    int newly;
    guchar header[4];
    int offset;


    /* read header (indicator and 3-byte length) */
    required = 4;
    offset = 0;
    while(required) {
        newly = read(pipe, &header[offset], required);
        if (newly == 0) {
            /* EOF */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "read %d header empty (capture closed)", pipe);
            return newly;
        }
        if (newly < 0) {
            /* error */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "read %d header error: %s", pipe, strerror(errno));
            return newly;
        }

        required -= newly;
        offset += newly;
    }

    /* convert header values */
    *indicator = header[0];
    required = header[1]<<16 | header[2]<<8 | header[3];

    /* only indicator with no value? */
    if(required == 0) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
              "read %d indicator: %c empty value", pipe, *indicator);
        return 4;
    }

    if(required > len) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
              "read %d length error, required %d > len %d, indicator: %u",
              pipe, required, len, *indicator);
        return -1;
    }
    len = required;

    /* read value */
    offset = 0;
    while(required) {
        newly = read(pipe, &msg[offset], required);
        if (newly == -1) {
            /* error */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "read %d value error: %s, indicator: %u", pipe,
                  strerror(errno), *indicator);
            return newly;
        }

        required -= newly;
        offset += newly;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
          "read %d ok indicator: %c len: %u msg: %s", pipe, *indicator,
          len, msg);
    return len + 4;
}



/* Add a string pointer to a NULL-terminated array of string pointers. */
static const char **
sync_pipe_add_arg(const char **args, int *argc, const char *arg)
{
  /* Grow the array; "*argc" currently contains the number of string
     pointers, *not* counting the NULL pointer at the end, so we have
     to add 2 in order to get the new size of the array, including the
     new pointer and the terminating NULL pointer. */
  args = g_realloc( (gpointer) args, (*argc + 2) * sizeof (char *));

  /* Stuff the pointer into the penultimate element of the array, which
     is the one at the index specified by "*argc". */
  args[*argc] = arg;

  /* Now bump the count. */
  (*argc)++;

  /* We overwrite the NULL pointer; put it back right after the
     element we added. */
  args[*argc] = NULL;

  return args;
}



#define ARGV_NUMBER_LEN 24

gboolean
sync_pipe_start(capture_options *capture_opts) {
    char ssnap[ARGV_NUMBER_LEN];
    char scount[ARGV_NUMBER_LEN];
    char sfilesize[ARGV_NUMBER_LEN];
    char sfile_duration[ARGV_NUMBER_LEN];
    char sring_num_files[ARGV_NUMBER_LEN];
    char sautostop_files[ARGV_NUMBER_LEN];
    char sautostop_filesize[ARGV_NUMBER_LEN];
    char sautostop_duration[ARGV_NUMBER_LEN];
#ifdef _WIN32
    char buffer_size[ARGV_NUMBER_LEN];
    char *filterstring;
    char *savefilestring;
    HANDLE sync_pipe_read;                  /* pipe used to send messages from child to parent */
    HANDLE sync_pipe_write;                 /* pipe used to send messages from child to parent */
    HANDLE signal_pipe_read;                /* pipe used to send messages from parent to child (currently only stop) */
    HANDLE signal_pipe_write;               /* pipe used to send messages from parent to child (currently only stop) */
    GString *args = g_string_sized_new(200);
    SECURITY_ATTRIBUTES sa; 
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    int i;
#else
    char errmsg[1024+1];
    int sync_pipe[2];                       /* pipe used to send messages from child to parent */
    enum PIPES { PIPE_READ, PIPE_WRITE };   /* Constants 0 and 1 for PIPE_READ and PIPE_WRITE */
#endif
    int sync_pipe_read_fd;
    char *exename;
    int argc;
    const char **argv;


    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_start");
    capture_opts_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, capture_opts);

    capture_opts->fork_child = -1;

    /* Allocate the string pointer array with enough space for the
       terminating NULL pointer. */
    argc = 0;
    argv = g_malloc(sizeof (char *));
    *argv = NULL;

    argv = sync_pipe_add_arg(argv, &argc, "-i");
    argv = sync_pipe_add_arg(argv, &argc, capture_opts->iface);

    if (capture_opts->has_snaplen) {
      argv = sync_pipe_add_arg(argv, &argc, "-s");
      g_snprintf(ssnap, ARGV_NUMBER_LEN, "%d",capture_opts->snaplen);
      argv = sync_pipe_add_arg(argv, &argc, ssnap);
    }

    if (capture_opts->linktype != -1) {
      argv = sync_pipe_add_arg(argv, &argc, "-y");
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
      g_snprintf(ssnap, ARGV_NUMBER_LEN, "%s",pcap_datalink_val_to_name(capture_opts->linktype));
#else
      /* XXX - just treat it as a number */
      g_snprintf(ssnap, ARGV_NUMBER_LEN, "%d",capture_opts->linktype);
#endif
      argv = sync_pipe_add_arg(argv, &argc, ssnap);
    }

    if(capture_opts->multi_files_on) {
      if (capture_opts->has_autostop_filesize) {
        argv = sync_pipe_add_arg(argv, &argc, "-b");
        g_snprintf(sfilesize, ARGV_NUMBER_LEN, "filesize:%d",capture_opts->autostop_filesize);
        argv = sync_pipe_add_arg(argv, &argc, sfilesize);
      }

      if (capture_opts->has_file_duration) {
        argv = sync_pipe_add_arg(argv, &argc, "-b");
        g_snprintf(sfile_duration, ARGV_NUMBER_LEN, "duration:%d",capture_opts->file_duration);
        argv = sync_pipe_add_arg(argv, &argc, sfile_duration);
      }

      if (capture_opts->has_ring_num_files) {
        argv = sync_pipe_add_arg(argv, &argc, "-b");
        g_snprintf(sring_num_files, ARGV_NUMBER_LEN, "files:%d",capture_opts->ring_num_files);
        argv = sync_pipe_add_arg(argv, &argc, sring_num_files);
      }

      if (capture_opts->has_autostop_files) {
        argv = sync_pipe_add_arg(argv, &argc, "-a");
        g_snprintf(sautostop_files, ARGV_NUMBER_LEN, "files:%d",capture_opts->autostop_files);
        argv = sync_pipe_add_arg(argv, &argc, sautostop_files);
      }
    } else {
        if (capture_opts->has_autostop_filesize) {
          argv = sync_pipe_add_arg(argv, &argc, "-a");
          g_snprintf(sautostop_filesize, ARGV_NUMBER_LEN, "filesize:%d",capture_opts->autostop_filesize);
          argv = sync_pipe_add_arg(argv, &argc, sautostop_filesize);
        }
    }

    if (capture_opts->has_autostop_packets) {
      argv = sync_pipe_add_arg(argv, &argc, "-c");
      g_snprintf(scount, ARGV_NUMBER_LEN, "%d",capture_opts->autostop_packets);
      argv = sync_pipe_add_arg(argv, &argc, scount);
    }

    if (capture_opts->has_autostop_duration) {
      argv = sync_pipe_add_arg(argv, &argc, "-a");
      g_snprintf(sautostop_duration, ARGV_NUMBER_LEN, "duration:%d",capture_opts->autostop_duration);
      argv = sync_pipe_add_arg(argv, &argc, sautostop_duration);
    }

    if (!capture_opts->promisc_mode)
      argv = sync_pipe_add_arg(argv, &argc, "-p");

    /* dumpcap should be running in capture child mode (hidden feature) */
#ifndef DEBUG_CHILD
    argv = sync_pipe_add_arg(argv, &argc, "-Z");
#endif

    /* take ethereal's absolute program path and replace ethereal with dumpcap */
    exename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "dumpcap",
                              get_progfile_dir());

#ifdef _WIN32
    argv = sync_pipe_add_arg(argv, &argc, "-B");
    g_snprintf(buffer_size, ARGV_NUMBER_LEN, "%d",capture_opts->buffer_size);
    argv = sync_pipe_add_arg(argv, &argc, buffer_size);

    /* Convert filter string to a quote delimited string and pass to child */
    filterstring = NULL;
    if (capture_opts->cfilter != NULL && strlen(capture_opts->cfilter) != 0) {
      argv = sync_pipe_add_arg(argv, &argc, "-f");
      filterstring = g_strdup_printf("\"%s\"", capture_opts->cfilter);
      argv = sync_pipe_add_arg(argv, &argc, filterstring);
    }

    /* Convert save file name to a quote delimited string and pass to child */
    savefilestring = NULL;
    if(capture_opts->save_file) {
      argv = sync_pipe_add_arg(argv, &argc, "-w");
      savefilestring = g_strdup_printf("\"%s\"", capture_opts->save_file);
      argv = sync_pipe_add_arg(argv, &argc, savefilestring);
    }

    /* init SECURITY_ATTRIBUTES */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
    sa.bInheritHandle = TRUE; 
    sa.lpSecurityDescriptor = NULL; 

    /* Create a pipe for the child process */
    /* (inrease this value if you have trouble while fast capture file switches) */
    if (! CreatePipe(&sync_pipe_read, &sync_pipe_write, &sa, 5120)) {
      /* Couldn't create the pipe between parent and child. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't create sync pipe: %s",
                        strerror(errno));
      g_free( (gpointer) argv);
      return FALSE;
    }

    /* Create a pipe for the parent process */
    if (! CreatePipe(&signal_pipe_read, &signal_pipe_write, &sa, 512)) {
      /* Couldn't create the signal pipe between parent and child. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't create signal pipe: %s",
                        strerror(errno));
      CloseHandle(sync_pipe_read);
      CloseHandle(sync_pipe_write);
      g_free( (gpointer) argv);
      return FALSE;
    }

    /* init STARTUPINFO */
    memset(&si, 0, sizeof(si));
    si.cb           = sizeof(si);
#ifdef DEBUG_CHILD
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow  = SW_SHOW;
#else
    si.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.wShowWindow  = SW_HIDE;  /* this hides the console window */
    si.hStdInput = signal_pipe_read;
    si.hStdOutput = sync_pipe_write;
    si.hStdError = sync_pipe_write;
#endif

    g_string_append(args, exename);

    /* convert args array into a single string */
    /* XXX - could change sync_pipe_add_arg() instead */
    /* there is a drawback here: the length is internally limited to 1024 bytes */
    for(i=0; argv[i] != 0; i++) {
        g_string_append_c(args, ' ');
        g_string_append(args, argv[i]);
    }

    /* call dumpcap */
    if(!CreateProcess(NULL, args->str, NULL, NULL, TRUE,
                      CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        g_error("couldn't open dumpcap.exe!");
    }
    capture_opts->fork_child = (int) pi.hProcess;
    g_string_free(args, TRUE);

    /* associate the operating system filehandle to a C run-time file handle */
    /* (good file handle infos at: http://www.flounder.com/handles.htm) */
    sync_pipe_read_fd = _open_osfhandle( (long) sync_pipe_read, _O_BINARY);

    /* associate the operating system filehandle to a C run-time file handle */
    capture_opts->signal_pipe_write_fd = _open_osfhandle( (long) signal_pipe_write, _O_BINARY);

    if (filterstring) {
      g_free(filterstring);
    }
    if(savefilestring) {
      g_free(savefilestring);
    }

    /* child own's the read side now, close our handle */
    CloseHandle(signal_pipe_read);
#else /* _WIN32 */
    if (pipe(sync_pipe) < 0) {
      /* Couldn't create the pipe between parent and child. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't create sync pipe: %s",
			strerror(errno));
      g_free(argv);
      return FALSE;
    }

    if (capture_opts->cfilter != NULL && capture_opts->cfilter != 0) {
      argv = sync_pipe_add_arg(argv, &argc, "-f");
      argv = sync_pipe_add_arg(argv, &argc, capture_opts->cfilter);
    }

    if(capture_opts->save_file) {
      argv = sync_pipe_add_arg(argv, &argc, "-w");
      argv = sync_pipe_add_arg(argv, &argc, capture_opts->save_file);
    }

    if ((capture_opts->fork_child = fork()) == 0) {
      /*
       * Child process - run Ethereal with the right arguments to make
       * it just pop up the live capture dialog box and capture with
       * the specified capture parameters, writing to the specified file.
       *
       * args: -i interface specification
       * -w file to write
       * -c count to capture
       * -s snaplen
       * -m / -b fonts
       * -f "filter expression"
       */
      eth_close(1);
      dup(sync_pipe[PIPE_WRITE]);
      eth_close(sync_pipe[PIPE_READ]);
      execvp(exename, argv);
      g_snprintf(errmsg, sizeof errmsg, "Couldn't run %s in child process: %s",
		exename, strerror(errno));
      sync_pipe_errmsg_to_parent(errmsg);

      /* Exit with "_exit()", so that we don't close the connection
         to the X server (and cause stuff buffered up by our parent but
	 not yet sent to be sent, as that stuff should only be sent by
	 our parent). */
      _exit(2);
    }

    sync_pipe_read_fd = sync_pipe[PIPE_READ];
#endif

    g_free(exename);

    /* Parent process - read messages from the child process over the
       sync pipe. */
    g_free( (gpointer) argv);	/* free up arg array */

    /* Close the write side of the pipe, so that only the child has it
       open, and thus it completely closes, and thus returns to us
       an EOF indication, if the child closes it (either deliberately
       or by exiting abnormally). */
#ifdef _WIN32
    CloseHandle(sync_pipe_write);
#else
    eth_close(sync_pipe[PIPE_WRITE]);
#endif

    if (capture_opts->fork_child == -1) {
      /* We couldn't even create the child process. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Couldn't create child process: %s", strerror(errno));
      eth_close(sync_pipe_read_fd);
#ifdef _WIN32
      eth_close(capture_opts->signal_pipe_write_fd);
#endif
      return FALSE;
    }

    /* we might wait for a moment till child is ready, so update screen now */
    main_window_update();

    /* We were able to set up to read the capture file;
       arrange that our callback be called whenever it's possible
       to read from the sync pipe, so that it's called when
       the child process wants to tell us something. */

    /* we have a running capture, now wait for the real capture filename */
    pipe_input_set_handler(sync_pipe_read_fd, (gpointer) capture_opts, 
        &capture_opts->fork_child, sync_pipe_input_cb);

    return TRUE;
}

/* There's stuff to read from the sync pipe, meaning the child has sent
   us a message, or the sync pipe has closed, meaning the child has
   closed it (perhaps because it exited). */
static gboolean 
sync_pipe_input_cb(gint source, gpointer user_data)
{
  capture_options *capture_opts = (capture_options *)user_data;
  char buffer[SP_MAX_MSG_LEN+1];
  int  nread;
  char indicator;


  nread = pipe_read_block(source, &indicator, SP_MAX_MSG_LEN, buffer);
  if(nread <= 0) {
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_input_cb: child has closed sync_pipe");

    /* The child has closed the sync pipe, meaning it's not going to be
       capturing any more packets.  Pick up its exit status, and
       complain if it did anything other than exit with status 0. */
    sync_pipe_wait_for_child(capture_opts);

#ifdef _WIN32
    eth_close(capture_opts->signal_pipe_write_fd);
#endif
    capture_input_closed(capture_opts);
    return FALSE;
  }

  switch(indicator) {
  case SP_FILE:
      if(!capture_input_new_file(capture_opts, buffer)) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_input_cb: file failed, closing capture");

        /* We weren't able to open the new capture file; user has been
           alerted. Close the sync pipe. */
        eth_close(source);

        /* the child has send us a filename which we couldn't open.
           this probably means, the child is creating files faster than we can handle it.
           this should only be the case for very fast file switches
           we can't do much more than telling the child to stop
           (this is the "emergency brake" if user e.g. wants to switch files every second) */
        sync_pipe_stop(capture_opts);
      }
      break;
  case SP_PACKET_COUNT:
    nread = atoi(buffer);
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_input_cb: new packets %u", nread);
    capture_input_new_packets(capture_opts, nread);
    break;
  case SP_ERROR_MSG:
    capture_input_error_message(capture_opts, buffer);
    /* the capture child will close the sync_pipe, nothing to do for now */
    break;
  case SP_DROPS:
    capture_input_drops(capture_opts, atoi(buffer));
    break;
  default:
      g_assert_not_reached();
  }

  return TRUE;
}



/* the child process is going down, wait until it's completely terminated */
static void
sync_pipe_wait_for_child(capture_options *capture_opts)
{
  int  wstatus;


  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_wait_for_child: wait till child closed");
  g_assert(capture_opts->fork_child != -1);

#ifdef _WIN32
  /* XXX - analyze the wait status and display more information
     in the dialog box?
     XXX - set "fork_child" to -1 if we find it exited? */
  if (_cwait(&wstatus, capture_opts->fork_child, _WAIT_CHILD) == -1) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Child capture process stopped unexpectedly");
  }
#else
  if (wait(&wstatus) != -1) {
    if (WIFEXITED(wstatus)) {
      /* The child exited; display its exit status, if it seems uncommon (0=ok, 1=error) */
      /* the child will inform us about errors through the sync_pipe, which will popup */
      /* an error message, so don't popup another one */

      /* XXX - if there are situations where the child won't send us such an error message, */
      /* this should be fixed in the child and not here! */
      if (WEXITSTATUS(wstatus) != 0 && WEXITSTATUS(wstatus) != 1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		      "Child capture process exited: exit status %d",
		      WEXITSTATUS(wstatus));
      }
    } else if (WIFSTOPPED(wstatus)) {
      /* It stopped, rather than exiting.  "Should not happen." */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Child capture process stopped: %s",
		    sync_pipe_signame(WSTOPSIG(wstatus)));
    } else if (WIFSIGNALED(wstatus)) {
      /* It died with a signal. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Child capture process died: %s%s",
		    sync_pipe_signame(WTERMSIG(wstatus)),
		    WCOREDUMP(wstatus) ? " - core dumped" : "");
    } else {
      /* What?  It had to either have exited, or stopped, or died with
         a signal; what happened here? */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Child capture process died: wait status %#o", wstatus);
    }
  }

  /* No more child process. */
  capture_opts->fork_child = -1;
#endif

  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_wait_for_child: capture child closed");
}


#ifndef _WIN32
/* convert signal to corresponding name */
static const char *
sync_pipe_signame(int sig)
{
  const char *sigmsg;
  static char sigmsg_buf[6+1+3+1];

  switch (sig) {

  case SIGHUP:
    sigmsg = "Hangup";
    break;

  case SIGINT:
    sigmsg = "Interrupted";
    break;

  case SIGQUIT:
    sigmsg = "Quit";
    break;

  case SIGILL:
    sigmsg = "Illegal instruction";
    break;

  case SIGTRAP:
    sigmsg = "Trace trap";
    break;

  case SIGABRT:
    sigmsg = "Abort";
    break;

  case SIGFPE:
    sigmsg = "Arithmetic exception";
    break;

  case SIGKILL:
    sigmsg = "Killed";
    break;

  case SIGBUS:
    sigmsg = "Bus error";
    break;

  case SIGSEGV:
    sigmsg = "Segmentation violation";
    break;

  /* http://metalab.unc.edu/pub/Linux/docs/HOWTO/GCC-HOWTO
     Linux is POSIX compliant.  These are not POSIX-defined signals ---
     ISO/IEC 9945-1:1990 (IEEE Std 1003.1-1990), paragraph B.3.3.1.1 sez:

	``The signals SIGBUS, SIGEMT, SIGIOT, SIGTRAP, and SIGSYS
	were omitted from POSIX.1 because their behavior is
	implementation dependent and could not be adequately catego-
	rized.  Conforming implementations may deliver these sig-
	nals, but must document the circumstances under which they
	are delivered and note any restrictions concerning their
	delivery.''

     So we only check for SIGSYS on those systems that happen to
     implement them (a system can be POSIX-compliant and implement
     them, it's just that POSIX doesn't *require* a POSIX-compliant
     system to implement them).
   */

#ifdef SIGSYS
  case SIGSYS:
    sigmsg = "Bad system call";
    break;
#endif

  case SIGPIPE:
    sigmsg = "Broken pipe";
    break;

  case SIGALRM:
    sigmsg = "Alarm clock";
    break;

  case SIGTERM:
    sigmsg = "Terminated";
    break;

  default:
	/* XXX - returning a static buffer is ok in the context we use it here */
    g_snprintf(sigmsg_buf, sizeof sigmsg_buf, "Signal %d", sig);
    sigmsg = sigmsg_buf;
    break;
  }
  return sigmsg;
}
#endif


/* user wants to stop the capture run */
void
sync_pipe_stop(capture_options *capture_opts)
{
  /* XXX - in which cases this will be 0? */
  if (capture_opts->fork_child != -1 && capture_opts->fork_child != 0) {
#ifndef _WIN32
    /* send the SIGUSR1 signal to close the capture child gracefully. */
    kill(capture_opts->fork_child, SIGUSR1);
#else
    /* Win32 doesn't have the kill() system call, use the special signal pipe 
       instead to close the capture child gracefully. */
    signal_pipe_capquit_to_child(capture_opts);
#endif
  }
}


/* Ethereal has to exit, force the capture child to close */
void
sync_pipe_kill(capture_options *capture_opts)
{
  /* XXX - in which cases this will be 0? */
  if (capture_opts->fork_child != -1 && capture_opts->fork_child != 0) {
#ifndef _WIN32
      kill(capture_opts->fork_child, SIGTERM);	/* SIGTERM so it can clean up if necessary */
#else
      /* XXX: this is not the preferred method of closing a process!
       * the clean way would be getting the process id of the child process,
       * then getting window handle hWnd of that process (using EnumChildWindows),
       * and then do a SendMessage(hWnd, WM_CLOSE, 0, 0) 
       *
       * Unfortunately, I don't know how to get the process id from the
       * handle.  OpenProcess will get an handle (not a window handle)
       * from the process ID; it will not get a window handle from the
       * process ID.  (How could it?  A process can have more than one
       * window.)
       *
       * Hint: GenerateConsoleCtrlEvent() will only work if both processes are 
       * running in the same console; that's not necessarily the case for
       * us, as we might not be running in a console.
       * And this also will require to have the process id.
       */
      TerminateProcess((HANDLE) (capture_opts->fork_child), 0);
#endif
  }
}

#endif /* HAVE_LIBPCAP */
