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

#include <glib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>

#ifdef _WIN32
#include <fcntl.h>
#include "epan/strutil.h"
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#include "capture-pcap-util.h"

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

#include "sync_pipe.h"

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



/* Append an arg (realloc) to an argc/argv array */
/* (add a string pointer to a NULL-terminated array of string pointers) */
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



#ifdef _WIN32
/* Quote the argument element if necessary, so that it will get
 * reconstructed correctly in the C runtime startup code.  Note that
 * the unquoting algorithm in the C runtime is really weird, and
 * rather different than what Unix shells do. See stdargv.c in the C
 * runtime sources (in the Platform SDK, in src/crt).
 *
 * Stolen from GLib's protect_argv(), an internal routine that quotes
 * string in an argument list so that they arguments will be handled
 * correctly in the command-line string passed to CreateProcess()
 * if that string is constructed by gluing those strings together.
 */
static gchar *
protect_arg (const gchar *argv)
{
    gchar *new_arg;
    const gchar *p = argv;
    gchar *q;
    gint len = 0;
    gboolean need_dblquotes = FALSE;

    while (*p) {
        if (*p == ' ' || *p == '\t')
            need_dblquotes = TRUE;
        else if (*p == '"')
            len++;
        else if (*p == '\\') {
            const gchar *pp = p;

            while (*pp && *pp == '\\')
                pp++;
            if (*pp == '"')
                len++;
	}
        len++;
        p++;
    }

    q = new_arg = g_malloc (len + need_dblquotes*2 + 1);
    p = argv;

    if (need_dblquotes)
        *q++ = '"';

    while (*p) {
        if (*p == '"')
            *q++ = '\\';
        else if (*p == '\\') {
            const gchar *pp = p;

            while (*pp && *pp == '\\')
                pp++;
            if (*pp == '"')
                *q++ = '\\';
	}
	*q++ = *p;
	p++;
    }

    if (need_dblquotes)
        *q++ = '"';
    *q++ = '\0';

    return new_arg;
}
#endif



#define ARGV_NUMBER_LEN 24

/* a new capture run: start a new dumpcap task and hand over parameters through command line */
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
    HANDLE sync_pipe_read;                  /* pipe used to send messages from child to parent */
    HANDLE sync_pipe_write;                 /* pipe used to send messages from child to parent */
    HANDLE signal_pipe_read;                /* pipe used to send messages from parent to child (currently only stop) */
    HANDLE signal_pipe_write;               /* pipe used to send messages from parent to child (currently only stop) */
    GString *args = g_string_sized_new(200);
    gchar *quoted_arg;
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
    const char *progfile_dir;
    char *exename;
    int argc;
    const char **argv;


    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_start");
    capture_opts_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, capture_opts);

    capture_opts->fork_child = -1;

    progfile_dir = get_progfile_dir();
    if (progfile_dir == NULL) {
      /* We don't know where to find dumpcap. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "We don't know where to find dumpcap.");
      return FALSE;
    }

    /* Allocate the string pointer array with enough space for the
       terminating NULL pointer. */
    argc = 0;
    argv = g_malloc(sizeof (char *));
    *argv = NULL;

    /* take ethereal's absolute program path and replace "ethereal" with "dumpcap" */
    exename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "dumpcap", progfile_dir);

    /* Make that the first argument in the argument list (argv[0]). */
    argv = sync_pipe_add_arg(argv, &argc, exename);

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
      g_snprintf(ssnap, ARGV_NUMBER_LEN, "%s",linktype_val_to_name(capture_opts->linktype));
#else
      /* we can't get the type name, just treat it as a number */
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

#ifdef _WIN32
    argv = sync_pipe_add_arg(argv, &argc, "-B");
    g_snprintf(buffer_size, ARGV_NUMBER_LEN, "%d",capture_opts->buffer_size);
    argv = sync_pipe_add_arg(argv, &argc, buffer_size);
#endif

    if (capture_opts->cfilter != NULL && strlen(capture_opts->cfilter) != 0) {
      argv = sync_pipe_add_arg(argv, &argc, "-f");
      argv = sync_pipe_add_arg(argv, &argc, capture_opts->cfilter);
    }

    if(capture_opts->save_file) {
      argv = sync_pipe_add_arg(argv, &argc, "-w");
      argv = sync_pipe_add_arg(argv, &argc, capture_opts->save_file);
    }

#ifdef _WIN32
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
    /*si.hStdError = (HANDLE) _get_osfhandle(2);*/
#endif

    /* convert args array into a single string */
    /* XXX - could change sync_pipe_add_arg() instead */
    /* there is a drawback here: the length is internally limited to 1024 bytes */
    for(i=0; argv[i] != 0; i++) {
        if(i != 0) g_string_append_c(args, ' ');    /* don't prepend a space before the path!!! */
        quoted_arg = protect_arg(argv[i]);
        g_string_append(args, quoted_arg);
        g_free(quoted_arg);
    }

    /* call dumpcap */
    if(!CreateProcess(NULL, utf_8to16(args->str), NULL, NULL, TRUE,
                      CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Couldn't run %s in child process: error %u",
                    args->str, GetLastError());
      CloseHandle(sync_pipe_read);
      CloseHandle(sync_pipe_write);
      g_free( (gpointer) argv);
      return FALSE;
    }
    capture_opts->fork_child = (int) pi.hProcess;
    g_string_free(args, TRUE);

    /* associate the operating system filehandle to a C run-time file handle */
    /* (good file handle infos at: http://www.flounder.com/handles.htm) */
    sync_pipe_read_fd = _open_osfhandle( (long) sync_pipe_read, _O_BINARY);

    /* associate the operating system filehandle to a C run-time file handle */
    capture_opts->signal_pipe_write_fd = _open_osfhandle( (long) signal_pipe_write, _O_BINARY);

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

    if ((capture_opts->fork_child = fork()) == 0) {
      /*
       * Child process - run Ethereal with the right arguments to make
       * it just pop up the live capture dialog box and capture with
       * the specified capture parameters, writing to the specified file.
       */
      eth_close(1);
      dup(sync_pipe[PIPE_WRITE]);
      eth_close(sync_pipe[PIPE_READ]);
      execv(exename, argv);
      g_snprintf(errmsg, sizeof errmsg, "Couldn't run %s in child process: %s",
		exename, strerror(errno));
      sync_pipe_errmsg_to_parent(errmsg, "");

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



/* read a number of bytes from a pipe */
/* (blocks until enough bytes read or an error occurs) */
static int
pipe_read_bytes(int pipe, char *bytes, int required) {
    int newly;
    int offset = 0;


    while(required) {
        newly = read(pipe, &bytes[offset], required);
        if (newly == 0) {
            /* EOF */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "read from pipe %d: EOF (capture closed?)", pipe);
            return offset;
        }
        if (newly < 0) {
            /* error */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "read from pipe %d: error(%u): %s", pipe, errno, strerror(errno));
            return newly;
        }

        required -= newly;
        offset += newly;
    }

    return offset;
}

/* convert header values (indicator and 4-byte length) */
static void
pipe_convert_header(const guchar *header, int header_len, char *indicator, int *block_len) {    

    g_assert(header_len == 4);

    /* convert header values */
    *indicator = header[0];
    *block_len = header[1]<<16 | header[2]<<8 | header[3];
}

/* read a message from the sending pipe in the standard format
   (1-byte message indicator, 3-byte message length (excluding length
   and indicator field), and the rest is the message) */
static int
pipe_read_block(int pipe, char *indicator, int len, char *msg) {
    int required;
    int newly;
    guchar header[4];


    /* read header (indicator and 3-byte length) */
    newly = pipe_read_bytes(pipe, header, 4);
    if(newly != 4) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
              "read %d failed to read header: %u", pipe, newly);
        return -1;
    }

    /* convert header values */
    pipe_convert_header(header, 4, indicator, &required);

    /* only indicator with no value? */
    if(required == 0) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
              "read %d indicator: %c empty value", pipe, *indicator);
        return 4;
    }

    /* does the data fit into the given buffer? */
    if(required > len) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
              "read %d length error, required %d > len %d, indicator: %u",
              pipe, required, len, *indicator);

        /* we have a problem here, try to read some more bytes from the pipe to debug where the problem really is */
        memcpy(msg, header, sizeof(header));
        newly = read(pipe, &msg[sizeof(header)], len-sizeof(header));
        g_warning("Unknown message from dumpcap, try to show it as a string: %s", msg);
        return -1;
    }
    len = required;

    /* read the actual block data */
    newly = pipe_read_bytes(pipe, msg, required);
    if(newly != required) {
        g_warning("Unknown message from dumpcap, try to show it as a string: %s", msg);
        return -1;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
          "read %d ok indicator: %c len: %u msg: %s", pipe, *indicator,
          len, msg);
    return newly + 4;
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
  int  primary_len;
  char * primary_msg;
  int  secondary_len;
  char * secondary_msg;


  nread = pipe_read_block(source, &indicator, SP_MAX_MSG_LEN, buffer);
  if(nread <= 0) {
    if (nread == 0)
      g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
            "sync_pipe_input_cb: child has closed sync_pipe");
    else
      g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
            "sync_pipe_input_cb: error reading from sync pipe");

    /* The child has closed the sync pipe, meaning it's not going to be
       capturing any more packets.  Pick up its exit status, and
       complain if it did anything other than exit with status 0.

       We don't have to worry about killing the child, if the sync pipe 
       returned an error. Usually this error is caused as the child killed itself 
       while going down. Even in the rare cases that this isn't the case, 
       the child will get an error when writing to the broken pipe the next time, 
       cleaning itself up then. */
    sync_pipe_wait_for_child(capture_opts);

#ifdef _WIN32
    eth_close(capture_opts->signal_pipe_write_fd);
#endif
    capture_input_closed(capture_opts);
    return FALSE;
  }

  /* we got a valid message block from the child, process it */
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
    /* convert primary message */
    pipe_convert_header(buffer, 4, &indicator, &primary_len);
    primary_msg = buffer+4;
    /* convert secondary message */
    pipe_convert_header(primary_msg + primary_len, 4, &indicator, &secondary_len);
    secondary_msg = primary_msg + primary_len + 4;
    /* message output */
    capture_input_error_message(capture_opts, primary_msg, secondary_msg);
    /* the capture child will close the sync_pipe, nothing to do for now */
    /* (an error message doesn't mean we have to stop capturing) */
    break;
  case SP_BAD_FILTER:
    capture_input_cfilter_error_message(capture_opts, buffer);
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
  if (_cwait(&wstatus, capture_opts->fork_child, _WAIT_CHILD) == -1) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Child capture process stopped unexpectedly (errno:%u)", errno);
  }
#else
  if (wait(&wstatus) != -1) {
    if (WIFEXITED(wstatus)) {
      /* The child exited; display its exit status, if it seems uncommon (0=ok, 1=error) */
      /* the child will inform us about errors through the sync_pipe, which will popup */
      /* an error message, so don't popup another one */

      /* If there are situations where the child won't send us such an error message, */
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
#endif

  /* No more child process. */
  capture_opts->fork_child = -1;

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
	/* Returning a static buffer is ok in the context we use it here */
    g_snprintf(sigmsg_buf, sizeof sigmsg_buf, "Signal %d", sig);
    sigmsg = sigmsg_buf;
    break;
  }
  return sigmsg;
}
#endif


#ifdef _WIN32
/* tell the child through the signal pipe that we want to quit the capture */
static void
signal_pipe_capquit_to_child(capture_options *capture_opts)
{
    const char quit_msg[] = "QUIT";
    int ret;


    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "signal_pipe_capquit_to_child");

    /* it doesn't matter *what* we send here, the first byte will stop the capture */
    /* simply sending a "QUIT" string */
    /*pipe_write_block(capture_opts->signal_pipe_write_fd, SP_QUIT, quit_msg);*/
    ret = write(capture_opts->signal_pipe_write_fd, quit_msg, sizeof quit_msg);
    if(ret == -1) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_WARNING,
              "signal_pipe_capquit_to_child: %d header: error %s", capture_opts->signal_pipe_write_fd, strerror(errno));
    }
}
#endif


/* user wants to stop the capture run */
void
sync_pipe_stop(capture_options *capture_opts)
{
  if (capture_opts->fork_child != -1) {
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
  if (capture_opts->fork_child != -1) {
#ifndef _WIN32
      kill(capture_opts->fork_child, SIGTERM);	/* SIGTERM so it can clean up if necessary */
#else
      /* Remark: This is not the preferred method of closing a process!
       * the clean way would be getting the process id of the child process,
       * then getting window handle hWnd of that process (using EnumChildWindows),
       * and then do a SendMessage(hWnd, WM_CLOSE, 0, 0)
       *
       * Unfortunately, I don't know how to get the process id from the
       * handle.  OpenProcess will get an handle (not a window handle)
       * from the process ID; it will not get a window handle from the
       * process ID.  (How could it?  A process can have more than one
       * window.  For that matter, a process might have *no* windows,
       * as a process running dumpcap, the normal child process program,
       * probably does.)
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
