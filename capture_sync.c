/* capture_sync.c
 * Synchronisation between Wireshark capture parent and child instances
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

#include <glib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <signal.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
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
#include <epan/report_err.h>

#include "capture.h"
#include "capture_sync.h"

#include "sync_pipe.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif
#include "ui_util.h"
#include <wsutil/file_util.h>
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

/* Initialize an argument list and add dumpcap to it. */
static const char **
init_pipe_args(int *argc) {
    const char **argv;
    const char *progfile_dir;
    char *exename;

    progfile_dir = get_progfile_dir();
    if (progfile_dir == NULL) {
      return NULL;
    }

    /* Allocate the string pointer array with enough space for the
       terminating NULL pointer. */
    *argc = 0;
    argv = g_malloc(sizeof (char *));
    *argv = NULL;

    /* take Wireshark's absolute program path and replace "Wireshark" with "dumpcap" */
    exename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "dumpcap", progfile_dir);

    /* Make that the first argument in the argument list (argv[0]). */
    argv = sync_pipe_add_arg(argv, argc, exename);

    return argv;
}

#define ARGV_NUMBER_LEN 24
/* a new capture run: start a new dumpcap task and hand over parameters through command line */
gboolean
sync_pipe_start(capture_options *capture_opts) {
    char ssnap[ARGV_NUMBER_LEN];
    char sdlt[ARGV_NUMBER_LEN];
    char scount[ARGV_NUMBER_LEN];
    char sfilesize[ARGV_NUMBER_LEN];
    char sfile_duration[ARGV_NUMBER_LEN];
    char sring_num_files[ARGV_NUMBER_LEN];
    char sautostop_files[ARGV_NUMBER_LEN];
    char sautostop_filesize[ARGV_NUMBER_LEN];
    char sautostop_duration[ARGV_NUMBER_LEN];
#ifdef HAVE_PCAP_REMOTE
    char sauth[256];
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    char ssampling[ARGV_NUMBER_LEN];
#endif
#ifdef _WIN32
    char buffer_size[ARGV_NUMBER_LEN];
    HANDLE sync_pipe_read;                  /* pipe used to send messages from child to parent */
    HANDLE sync_pipe_write;                 /* pipe used to send messages from child to parent */
    HANDLE signal_pipe;                     /* named pipe used to send messages from parent to child (currently only stop) */
    GString *args = g_string_sized_new(200);
    gchar *quoted_arg;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    int i;
    char control_id[ARGV_NUMBER_LEN];
    gchar *signal_pipe_name;
#else
    char errmsg[1024+1];
    int sync_pipe[2];                       /* pipe used to send messages from child to parent */
    enum PIPES { PIPE_READ, PIPE_WRITE };   /* Constants 0 and 1 for PIPE_READ and PIPE_WRITE */
#endif
    int sync_pipe_read_fd;
    int argc;
    const char **argv;


    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_start");
    capture_opts_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, capture_opts);

    capture_opts->fork_child = -1;

    argv = init_pipe_args(&argc);
    if (!argv) {
        /* We don't know where to find dumpcap. */
        report_failure("We don't know where to find dumpcap.");
        return FALSE;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "argv[0]: %s", argv[0]);

    argv = sync_pipe_add_arg(argv, &argc, "-i");
    argv = sync_pipe_add_arg(argv, &argc, capture_opts->iface);

    if (capture_opts->has_snaplen) {
      argv = sync_pipe_add_arg(argv, &argc, "-s");
      g_snprintf(ssnap, ARGV_NUMBER_LEN, "%d",capture_opts->snaplen);
      argv = sync_pipe_add_arg(argv, &argc, ssnap);
    }

    if (capture_opts->linktype != -1) {
      argv = sync_pipe_add_arg(argv, &argc, "-y");
      g_snprintf(sdlt, ARGV_NUMBER_LEN, "%s",linktype_val_to_name(capture_opts->linktype));
      argv = sync_pipe_add_arg(argv, &argc, sdlt);
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
    if (capture_opts->use_pcapng)
      argv = sync_pipe_add_arg(argv, &argc, "-n");
#ifdef HAVE_PCAP_REMOTE
    if (capture_opts->datatx_udp)
      argv = sync_pipe_add_arg(argv, &argc, "-u");

    if (!capture_opts->nocap_rpcap)
      argv = sync_pipe_add_arg(argv, &argc, "-r");

    if (capture_opts->auth_type == CAPTURE_AUTH_PWD)
    {
        argv = sync_pipe_add_arg(argv, &argc, "-A");
        g_snprintf(sauth, sizeof(sauth), "%s:%s", capture_opts->auth_username,
                   capture_opts->auth_password);
        argv = sync_pipe_add_arg(argv, &argc, sauth);
    }
#endif
#ifdef HAVE_PCAP_SETSAMPLING
    if (capture_opts->sampling_method != CAPTURE_SAMP_NONE)
    {
        argv = sync_pipe_add_arg(argv, &argc, "-m");
        g_snprintf(ssampling, ARGV_NUMBER_LEN, "%s:%d",
             capture_opts->sampling_method == CAPTURE_SAMP_BY_COUNT ? "count" :
             capture_opts->sampling_method == CAPTURE_SAMP_BY_TIMER ? "timer" :
             "undef",
             capture_opts->sampling_param);
        argv = sync_pipe_add_arg(argv, &argc, ssampling);
    }
#endif

    /* dumpcap should be running in capture child mode (hidden feature) */
#ifndef DEBUG_CHILD
    argv = sync_pipe_add_arg(argv, &argc, "-Z");
#ifdef _WIN32
    g_snprintf(control_id, ARGV_NUMBER_LEN, "%d", GetCurrentProcessId());
    argv = sync_pipe_add_arg(argv, &argc, control_id);
#else
    argv = sync_pipe_add_arg(argv, &argc, SIGNAL_PIPE_CTRL_ID_NONE);
#endif
#endif

#ifdef _WIN32
    argv = sync_pipe_add_arg(argv, &argc, "-B");
#ifdef HAVE_PCAP_REMOTE
    if (capture_opts->src_type == CAPTURE_IFREMOTE)
      /* No buffer size when using remote interfaces */
      g_snprintf(buffer_size, ARGV_NUMBER_LEN, "%d", 1);
    else
#endif
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
    /* (increase this value if you have trouble while fast capture file switches) */
    if (! CreatePipe(&sync_pipe_read, &sync_pipe_write, &sa, 5120)) {
      /* Couldn't create the pipe between parent and child. */
      report_failure("Couldn't create sync pipe: %s", strerror(errno));
      g_free( (gpointer) argv[0]);
      g_free( (gpointer) argv);
      return FALSE;
    }

    /* Create the signal pipe */
    signal_pipe_name = g_strdup_printf(SIGNAL_PIPE_FORMAT, control_id);
    signal_pipe = CreateNamedPipe(utf_8to16(signal_pipe_name),
      PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 65535, 65535, 0, NULL);
    g_free(signal_pipe_name);

    if (signal_pipe == INVALID_HANDLE_VALUE) {
      /* Couldn't create the signal pipe between parent and child. */
      report_failure("Couldn't create signal pipe: %s", strerror(errno));
      g_free( (gpointer) argv[0]);
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
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
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
      report_failure("Couldn't run %s in child process: error %u",
                     args->str, GetLastError());
      CloseHandle(sync_pipe_read);
      CloseHandle(sync_pipe_write);
      g_free( (gpointer) argv[0]);
      g_free( (gpointer) argv);
      return FALSE;
    }
    capture_opts->fork_child = (int) pi.hProcess;
    g_string_free(args, TRUE);

    /* associate the operating system filehandle to a C run-time file handle */
    /* (good file handle infos at: http://www.flounder.com/handles.htm) */
    sync_pipe_read_fd = _open_osfhandle( (long) sync_pipe_read, _O_BINARY);

    /* associate the operating system filehandle to a C run-time file handle */
    capture_opts->signal_pipe_write_fd = _open_osfhandle( (long) signal_pipe, _O_BINARY);

#else /* _WIN32 */
    if (pipe(sync_pipe) < 0) {
      /* Couldn't create the pipe between parent and child. */
      report_failure("Couldn't create sync pipe: %s", strerror(errno));
      g_free( (gpointer) argv[0]);
      g_free(argv);
      return FALSE;
    }

    if ((capture_opts->fork_child = fork()) == 0) {
      /*
       * Child process - run dumpcap with the right arguments to make
       * it just capture with the specified capture parameters
       */
      dup2(sync_pipe[PIPE_WRITE], 2);
      ws_close(sync_pipe[PIPE_READ]);
      execv(argv[0], (gpointer)argv);
      g_snprintf(errmsg, sizeof errmsg, "Couldn't run %s in child process: %s",
		argv[0], strerror(errno));
      sync_pipe_errmsg_to_parent(2, errmsg, "");

      /* Exit with "_exit()", so that we don't close the connection
         to the X server (and cause stuff buffered up by our parent but
	 not yet sent to be sent, as that stuff should only be sent by
	 our parent).  We've sent an error message to the parent, so
	 we exit with an exit status of 1 (any exit status other than
	 0 or 1 will cause an additional message to report that exit
	 status, over and above the error message we sent to the parent). */
      _exit(1);
    }

    sync_pipe_read_fd = sync_pipe[PIPE_READ];
#endif

    g_free( (gpointer) argv[0]);  /* exename */

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
    ws_close(sync_pipe[PIPE_WRITE]);
#endif

    if (capture_opts->fork_child == -1) {
      /* We couldn't even create the child process. */
      report_failure("Couldn't create child process: %s", strerror(errno));
      ws_close(sync_pipe_read_fd);
#ifdef _WIN32
      ws_close(capture_opts->signal_pipe_write_fd);
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

/*
 * Open dumpcap with the supplied arguments.  On success, msg points to
 * a buffer containing the dumpcap output and returns 0.  read_fd and
 * fork_child point to the pipe's file descriptor and child PID/handle,
 * respectively.  On failure, msg points to the error message returned by
 * dumpcap, and returns dumpcap's exit value.  In either case, msg must be
 * freed with g_free().
 */
/* XXX - This duplicates a lot of code in sync_pipe_start() */
#define PIPE_BUF_SIZE 5120
static int
sync_pipe_open_command(const char** argv, int *read_fd, int *fork_child, gchar **msg) {
#ifdef _WIN32
    HANDLE sync_pipe_read;                  /* pipe used to send messages from child to parent */
    HANDLE sync_pipe_write;                 /* pipe used to send messages from parent to child */
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

    *fork_child = -1;
    *read_fd = -1;
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_run_command");

    if (!msg) {
        /* We can't return anything */
#ifdef _WIN32
        g_string_free(args, TRUE);
#endif
        return -1;
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
        *msg = g_strdup_printf("Couldn't create sync pipe: %s", strerror(errno));
        g_free( (gpointer) argv[0]);
        g_free( (gpointer) argv);
        return CANT_RUN_DUMPCAP;
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
    si.hStdInput = NULL;
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
        *msg = g_strdup_printf("Couldn't run %s in child process: error %u",
                        args->str, GetLastError());
        CloseHandle(sync_pipe_read);
        CloseHandle(sync_pipe_write);
        g_free( (gpointer) argv[0]);
        g_free( (gpointer) argv);
        return CANT_RUN_DUMPCAP;
    }
    *fork_child = (int) pi.hProcess;
    g_string_free(args, TRUE);

    /* associate the operating system filehandle to a C run-time file handle */
    /* (good file handle infos at: http://www.flounder.com/handles.htm) */
    *read_fd = _open_osfhandle( (long) sync_pipe_read, _O_BINARY);

#else /* _WIN32 */
    if (pipe(sync_pipe) < 0) {
        /* Couldn't create the pipe between parent and child. */
        *msg = g_strdup_printf("Couldn't create sync pipe: %s", strerror(errno));
        g_free( (gpointer) argv[0]);
        g_free(argv);
        return CANT_RUN_DUMPCAP;
    }

    if ((*fork_child = fork()) == 0) {
        /*
         * Child process - run dumpcap with the right arguments to make
         * it just capture with the specified capture parameters
         */
        dup2(sync_pipe[PIPE_WRITE], 1);
        ws_close(sync_pipe[PIPE_READ]);
        execv(argv[0], (gpointer)argv);
        g_snprintf(errmsg, sizeof errmsg, "Couldn't run %s in child process: %s",
		   argv[0], strerror(errno));
        sync_pipe_errmsg_to_parent(1, errmsg, "");

        /* Exit with "_exit()", so that we don't close the connection
           to the X server (and cause stuff buffered up by our parent but
           not yet sent to be sent, as that stuff should only be sent by
           our parent).  We've sent an error message to the parent, so
           we exit with an exit status of 1 (any exit status other than
           0 or 1 will cause an additional message to report that exit
           status, over and above the error message we sent to the parent). */
        _exit(1);
    }

    *read_fd = sync_pipe[PIPE_READ];
#endif

    g_free( (gpointer) argv[0]);  /* exename */

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
    ws_close(sync_pipe[PIPE_WRITE]);
#endif

    if (*fork_child == -1) {
        /* We couldn't even create the child process. */
        *msg = g_strdup_printf("Couldn't create child process: %s", strerror(errno));
        ws_close(*read_fd);
        return CANT_RUN_DUMPCAP;
    }

    /* we might wait for a moment till child is ready, so update screen now */
    main_window_update();
    return 0;
}

static int
#ifdef _WIN32
sync_pipe_close_command(int *read_fd, int *fork_child, gchar **msg) {
#else
sync_pipe_close_command(int *read_fd, gchar **msg) {
#endif
    int fork_child_status;

    ws_close(*read_fd);

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_pipe_close_command: wait till child closed");

#ifdef _WIN32
    /* XXX - Should we signal the child somehow? */
    sync_pipe_kill(*fork_child);
    if (_cwait(&fork_child_status, *fork_child, _WAIT_CHILD) == -1) {
        *msg = g_strdup_printf("Child capture process stopped unexpectedly "
            "(errno:%u)", errno);
        return CANT_RUN_DUMPCAP;
    }
#else
    if (wait(&fork_child_status) != -1) {
        if (WIFEXITED(fork_child_status)) {
            /* The child exited. */
            fork_child_status = WEXITSTATUS(fork_child_status);
        } else {
            if (WIFSTOPPED(fork_child_status)) {
                /* It stopped, rather than exiting.  "Should not happen." */
                *msg = g_strdup_printf("Child capture process stopped: %s",
                    sync_pipe_signame(WSTOPSIG(fork_child_status)));
            } else if (WIFSIGNALED(fork_child_status)) {
                /* It died with a signal. */
                *msg = g_strdup_printf("Child capture process died: %s%s",
		    sync_pipe_signame(WTERMSIG(fork_child_status)),
		    WCOREDUMP(fork_child_status) ? " - core dumped" : "");
            } else {
                /* What?  It had to either have exited, or stopped, or died with
                   a signal; what happened here? */
                *msg = g_strdup_printf("Child capture process died: wait status %#o",
                    fork_child_status);
            }
            return CANT_RUN_DUMPCAP;
        }
    } else {
      *msg = g_strdup_printf("Child capture process stopped unexpectedly "
        "(errno:%u)", errno);
      return CANT_RUN_DUMPCAP;
    }
#endif
    return 0;
}

/*
 * Run dumpcap with the supplied arguments.  On success, msg points to
 * a buffer containing the dumpcap output and returns 0.  On failure, msg
 * points to the error message returned by dumpcap, and returns dumpcap's
 * exit value.  In either case, msg must be freed with g_free().
 */
/* XXX - This duplicates a lot of code in sync_pipe_start() */
#define PIPE_BUF_SIZE 5120
static int
sync_pipe_run_command(const char** argv, gchar **msg) {
    int sync_pipe_read_fd, fork_child, ret;
    gchar buf[PIPE_BUF_SIZE+1];
    GString *msg_buf = NULL;
    int count;

    ret = sync_pipe_open_command(argv, &sync_pipe_read_fd, &fork_child, msg);

    if (ret)
	return ret;

    /* We were able to set up to read dumpcap's output.  Do so and
       return its exit value. */
    msg_buf = g_string_new("");
    while ((count = ws_read(sync_pipe_read_fd, buf, PIPE_BUF_SIZE)) > 0) {
        buf[count] = '\0';
        g_string_append(msg_buf, buf);
    }

#ifdef _WIN32
    ret = sync_pipe_close_command(&sync_pipe_read_fd, &fork_child, msg);
#else
    ret = sync_pipe_close_command(&sync_pipe_read_fd, msg);
#endif

    if (ret) {
	g_string_free(msg_buf, TRUE);
	return ret;
    }

    *msg = msg_buf->str;
    g_string_free(msg_buf, FALSE);
    return 0;
}

/*
 * Get an interface list using dumpcap.  On success, msg points to
 * a buffer containing the dumpcap output and returns 0.  On failure, msg
 * points to the error message returned by dumpcap, and returns dumpcap's
 * exit value.  In either case, msg must be freed with g_free().
 */
int
sync_interface_list_open(gchar **msg) {
    int argc;
    const char **argv;

    if (!msg) {
        /* We can't return anything */
        return -1;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_interface_list_open");

    argv = init_pipe_args(&argc);

    if (!argv) {
        *msg = g_strdup_printf("We don't know where to find dumpcap.");
        return CANT_RUN_DUMPCAP;
    }

    /* Ask for the interface list */
    argv = sync_pipe_add_arg(argv, &argc, "-D");
    argv = sync_pipe_add_arg(argv, &argc, "-M");

#if 0
    /* dumpcap should be running in capture child mode (hidden feature)                   */
    /* XXX: Actually: don't run dumpcap in capture_child_mode.                            */
    /*     Instead run dumpcap in 'normal' mode so that dumpcap err msgs are sent to      */
    /*     stderr in normal format and are then sent to whereever our stderr goes.        */
    /*     Note: Using 'dumpcap -D -M -Z' (capture_child mode) changes only the format of */
    /*           dumpcap err msgs. That is: dumpcap in capture_child mode outputs err     */
    /*           msgs to stderr in a special type/len/string format which would then      */
    /*           currently be sent as is to stderr resulting in garbled output.           */
    /*     ToDo: Revise this code to be similar to sync_pipe_start so that 'dumpcap -Z'   */
    /*     special format error messages to stderr are captured and returned to caller    */
    /*     (eg: so can be processed and displayed in a pop-up box).                       */
#ifndef DEBUG_CHILD
    argv = sync_pipe_add_arg(argv, &argc, "-Z");
    argv = sync_pipe_add_arg(argv, &argc, SIGNAL_PIPE_CTRL_ID_NONE);
#endif
#endif

    return sync_pipe_run_command(argv, msg);
}

/*
 * Get an linktype list using dumpcap.  On success, msg points to
 * a buffer containing the dumpcap output and returns 0.  On failure, msg
 * points to the error message returned by dumpcap, and returns dumpcap's
 * exit value.  In either case, msg must be freed with g_free().
 */
int
sync_linktype_list_open(const gchar *ifname, gchar **msg) {
    int argc;
    const char **argv;

    if (!msg) {
        /* We can't return anything */
        return -1;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_linktype_list_open");

    argv = init_pipe_args(&argc);

    if (!argv) {
        *msg = g_strdup_printf("We don't know where to find dumpcap.");
        return CANT_RUN_DUMPCAP;
    }

    /* Ask for the linktype list */
    argv = sync_pipe_add_arg(argv, &argc, "-i");
    argv = sync_pipe_add_arg(argv, &argc, ifname);
    argv = sync_pipe_add_arg(argv, &argc, "-L");
    argv = sync_pipe_add_arg(argv, &argc, "-M");

#if 0
    /* dumpcap should be running in capture child mode (hidden feature)                   */
    /* XXX: Actually: don't run dumpcap in capture_child_mode.                            */
    /*     Instead run dumpcap in 'normal' mode so that dumpcap err msgs are sent to      */
    /*     stderr in normal format and are then sent to whereever our stderr goes.        */
    /*     Note: Using 'dumpcap -L -M -Z' (capture_child mode) changes only the format of */
    /*           dumpcap err msgs. That is: dumpcap in capture_child mode outputs err     */
    /*           msgs to stderr in a special type/len/string format which would then      */
    /*           currently be sent as is to stderr resulting in garbled output.           */
    /*     ToDo: Revise this code to be similar to sync_pipe_start so that 'dumpcap -Z'   */
    /*     special format error messages to stderr are captured and returned to caller    */
    /*     (eg: so can be processed and displayed in a pop-up box).                       */
#ifndef DEBUG_CHILD
    argv = sync_pipe_add_arg(argv, &argc, "-Z");
    argv = sync_pipe_add_arg(argv, &argc, SIGNAL_PIPE_CTRL_ID_NONE);
#endif
#endif
    return sync_pipe_run_command(argv, msg);
}

/*
 * Start getting interface statistics using dumpcap.  On success, read_fd
 * contains the file descriptor for the pipe's stdout, msg is unchanged,
 * and zero is returned.  On failure, msg will point to an error message
 * that must be g_free()d and a nonzero error value will be returned.
 */
int
sync_interface_stats_open(int *read_fd, int *fork_child, gchar **msg) {
    int argc;
    const char **argv;

    if (!msg) {
        /* We can't return anything */
        return -1;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "sync_interface_stats_open");

    argv = init_pipe_args(&argc);

    if (!argv) {
        *msg = g_strdup_printf("We don't know where to find dumpcap.");
        return CANT_RUN_DUMPCAP;
    }

    /* Ask for the interface statistics */
    argv = sync_pipe_add_arg(argv, &argc, "-S");
    argv = sync_pipe_add_arg(argv, &argc, "-M");

#if 0
    /* dumpcap should be running in capture child mode (hidden feature)                   */
    /* XXX: Actually: don't run dumpcap in capture_child_mode.                            */
    /*     Instead run dumpcap in 'normal' mode so that dumpcap err msgs are sent to      */
    /*     stderr in normal format and are then sent to whereever our stderr goes.        */
    /*     Note: Using 'dumpcap -S -M -Z' (capture_child mode) changes only the format of */
    /*           dumpcap err msgs. That is: dumpcap in capture_child mode outputs err     */
    /*           msgs to stderr in a special type/len/string format which would then      */
    /*           currently be sent as is to stderr resulting in garbled output.           */
    /*     ToDo: Revise this code to be similar to sync_pipe_start so that 'dumpcap -Z'   */
    /*     special format error messages to stderr are captured and returned to caller    */
    /*     (eg: so can be processed and displayed in a pop-up box).                       */
#ifndef DEBUG_CHILD
    argv = sync_pipe_add_arg(argv, &argc, "-Z");
    argv = sync_pipe_add_arg(argv, &argc, SIGNAL_PIPE_CTRL_ID_NONE);
#endif
#endif
    return sync_pipe_open_command(argv, read_fd, fork_child, msg);
}

/* Close down the stats process */
int
sync_interface_stats_close(int *read_fd, int *fork_child
#ifndef _WIN32
_U_
#endif
, gchar **msg) {
#ifdef _WIN32
    return sync_pipe_close_command(read_fd, fork_child, msg);
#else
    return sync_pipe_close_command(read_fd, msg);
#endif
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

static gboolean pipe_data_available(int pipe) {
#ifdef _WIN32 /* PeekNamedPipe */
    HANDLE hPipe = (HANDLE) _get_osfhandle(pipe);
    DWORD bytes_avail;

    if (hPipe == INVALID_HANDLE_VALUE)
        return FALSE;

    if (! PeekNamedPipe(hPipe, NULL, 0, NULL, &bytes_avail, NULL))
        return FALSE;

    if (bytes_avail > 0)
        return TRUE;
    return FALSE;
#else /* select */
    fd_set rfds;
    struct timeval timeout;

    FD_ZERO(&rfds);
    FD_SET(pipe, &rfds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if (select(pipe+1, &rfds, NULL, NULL, &timeout) > 0)
        return TRUE;

    return FALSE;
#endif
}

/* Read a line from a pipe, similar to fgets */
int
sync_pipe_gets_nonblock(int pipe_fd, char *bytes, int max) {
    int newly;
    int offset = -1;

    while(offset < max - 1) {
        offset++;
        if (! pipe_data_available(pipe_fd))
            break;
        newly = read(pipe_fd, &bytes[offset], 1);
        if (newly == 0) {
            /* EOF - not necessarily an error */
            break;
        } else if (newly < 0) {
            /* error */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                  "read from pipe %d: error(%u): %s", pipe_fd, errno, strerror(errno));
            return newly;
        } else if (bytes[offset] == '\n') {
            break;
        }
    }

    if (offset >= 0)
        bytes[offset] = '\0';

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

    /* XXX If message is "2part", the msg probably won't be sent to debug log correctly */
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
    ws_close(capture_opts->signal_pipe_write_fd);
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
      ws_close(source);

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
    capture_input_drops(capture_opts, (guint32)strtoul(buffer, NULL, 10));
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
    report_failure("Child capture process stopped unexpectedly (errno:%u)",
                   errno);
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
        report_failure("Child capture process exited: exit status %d",
		       WEXITSTATUS(wstatus));
      }
    } else if (WIFSTOPPED(wstatus)) {
      /* It stopped, rather than exiting.  "Should not happen." */
      report_failure("Child capture process stopped: %s",
		     sync_pipe_signame(WSTOPSIG(wstatus)));
    } else if (WIFSIGNALED(wstatus)) {
      /* It died with a signal. */
      report_failure("Child capture process died: %s%s",
		     sync_pipe_signame(WTERMSIG(wstatus)),
		     WCOREDUMP(wstatus) ? " - core dumped" : "");
    } else {
      /* What?  It had to either have exited, or stopped, or died with
         a signal; what happened here? */
      report_failure("Child capture process died: wait status %#o", wstatus);
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
#ifdef _WIN32
  int count;
  DWORD childstatus;
  gboolean terminate = TRUE;
#endif

  if (capture_opts->fork_child != -1) {
#ifndef _WIN32
    /* send the SIGINT signal to close the capture child gracefully. */
    int sts = kill(capture_opts->fork_child, SIGINT);
    if (sts != 0) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_WARNING,
              "Sending SIGINT to child failed: %s\n", strerror(errno));
    }
#else
#define STOP_SLEEP_TIME 500 /* ms */
#define STOP_CHECK_TIME 50
    /* First, use the special signal pipe to try to close the capture child
     * gracefully.
     */
    signal_pipe_capquit_to_child(capture_opts);

    /* Next, wait for the process to exit on its own */
    for (count = 0; count < STOP_SLEEP_TIME / STOP_CHECK_TIME; count++) {
      if (GetExitCodeProcess((HANDLE) capture_opts->fork_child, &childstatus) &&
              childstatus != STILL_ACTIVE) {
        terminate = FALSE;
        break;
      }
      Sleep(STOP_CHECK_TIME);
    }

    /* Force the issue. */
    if (terminate) {
      g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_WARNING,
            "sync_pipe_stop: forcing child to exit");
      sync_pipe_kill(capture_opts->fork_child);
    }
#endif
  }
}


/* Wireshark has to exit, force the capture child to close */
void
sync_pipe_kill(int fork_child)
{
    if (fork_child != -1) {
#ifndef _WIN32
        int sts = kill(fork_child, SIGTERM);	/* SIGTERM so it can clean up if necessary */
        if (sts != 0) {
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_WARNING,
                  "Sending SIGTERM to child failed: %s\n", strerror(errno));
        }
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
        TerminateProcess((HANDLE) (fork_child), 0);
#endif
    }
}

#endif /* HAVE_LIBPCAP */
