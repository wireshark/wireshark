/* extcap-base.c
 * Base function for extcaps
 *
 * Copyright 2015, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_EXTCAP

#include "extcap-base.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include <wsutil/file_util.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#include <wsutil/win32-utils.h>
#endif

#include <capture/sync_pipe.h>

#include "ws_attributes.h"

enum extcap_options {
    EXTCAP_BASE_OPTIONS_ENUM
};

typedef struct _extcap_interface
{
    char * interface;
    char * description;

    uint16_t dlt;
    char * dltname;
    char * dltdescription;
} extcap_interface;

typedef struct _extcap_option {
    char * optname;
    char * optdesc;
} extcap_option_t;

static FILE *custom_log;

/* used to inform to extcap application that end of application is requested */
bool extcap_end_application;
/* graceful shutdown callback, can be null */
static void (*extcap_graceful_shutdown_cb)(void);
/* toolbar control callback, can be null */
static extcap_toolbar_control_cb_t extcap_toolbar_control_cb;

static void extcap_init_log_file(const char *filename);

/* Called from signals */
#ifdef _WIN32
static BOOL WINAPI
extcap_exit_from_loop(DWORD dwCtrlType _U_)
#else
static void extcap_exit_from_loop(int signo _U_)
#endif /* _WIN32 */
{
    ws_debug("Exiting from main loop by signal");
    extcap_end_application = true;
    if (extcap_graceful_shutdown_cb != NULL) {
       extcap_graceful_shutdown_cb();
    }
#ifdef _WIN32
    return true;
#endif /* _WIN32 */
}

void extcap_base_register_interface(extcap_parameters * extcap, const char * interface, const char * ifdescription, uint16_t dlt, const char * dltdescription )
{
    extcap_base_register_interface_ext(extcap, interface, ifdescription, dlt, NULL, dltdescription );
}

void extcap_base_register_interface_ext(extcap_parameters * extcap,
        const char * interface, const char * ifdescription,
        uint16_t dlt, const char * dltname, const char * dltdescription )
{
    extcap_interface * iface;

    if (interface == NULL)
    return;

    iface = g_new0(extcap_interface, 1);

    iface->interface = g_strdup(interface);
    iface->description = g_strdup(ifdescription);
    iface->dlt = dlt;
    iface->dltname = g_strdup(dltname);
    iface->dltdescription = g_strdup(dltdescription);

    extcap->interfaces = g_list_append(extcap->interfaces, (void *) iface);
}

bool extcap_base_register_graceful_shutdown_cb(extcap_parameters * extcap _U_, void (*callback)(void))
{
#ifndef _WIN32
    struct sigaction sig_handler = { .sa_handler = extcap_exit_from_loop };
#endif

    extcap_end_application = false;
    extcap_graceful_shutdown_cb = callback;
#ifdef _WIN32
    /* This signal can be triggered if extcap is ran manually from a command prompt,
     * but cannot be triggered by wireshark. On Windows, wireshark will therefore terminate
     * the program when the user clicks "stop". Use postkill_cb to try and cleanup afterwards
     * if needed.
     */
    if (!SetConsoleCtrlHandler(extcap_exit_from_loop, true)) {
            ws_warning("Can't set console handler");
            return false;
    }
#else
    /* Catch signals to be able to cleanup config later */
    if (sigaction(SIGINT, &sig_handler, NULL)) {
            ws_warning("Can't set SIGINT signal handler");
            return false;
    }
    if (sigaction(SIGTERM, &sig_handler, NULL)) {
            ws_warning("Can't set SIGTERM signal handler");
            return false;
    }
    if (sigaction(SIGPIPE, &sig_handler, NULL)) {
            ws_warning("Can't set SIGPIPE signal handler");
            return false;
    }
#endif /* _WIN32 */

    return true;
}

bool extcap_base_register_cleanup_postkill_cb(extcap_parameters* extcap, void (*callback)(void))
{
    extcap->cleanup_postkill_cb = callback;
    return true;
}

bool extcap_base_register_toolbar_control_cb(extcap_parameters * extcap _U_, extcap_toolbar_control_cb_t callback)
{
    extcap_toolbar_control_cb = callback;
    return true;
}

void extcap_base_set_util_info(extcap_parameters * extcap, const char * exename, const char * major,
    const char * minor, const char * release, const char * helppage)
{
    extcap->exename = g_path_get_basename(exename);

    ws_assert(major);
    if (!minor)
        ws_assert(!release);

    extcap->version = ws_strdup_printf("%s%s%s%s%s",
        major,
        minor ? "." : "",
        minor ? minor : "",
        release ? "." : "",
        release ? release : "");
    extcap->helppage = g_strdup(helppage);
}

void extcap_base_set_compiled_with(extcap_parameters * extcap, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    extcap->compiled_with = ws_strdup_vprintf(fmt, ap);
    va_end(ap);
}

void extcap_base_set_running_with(extcap_parameters * extcap, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    extcap->running_with = ws_strdup_vprintf(fmt, ap);
    va_end(ap);
}

static void
extcap_log_writer(const char *domain, enum ws_log_level level,
    const char *file, long line, const char *func,
    const char *fatal_msg _U_, ws_log_manifest_t *mft,
    const char *user_format, va_list user_ap,
    void *user_data)
{
    extcap_parameters *extcap_conf = (extcap_parameters*)user_data;

    if (extcap_conf && extcap_conf->control_out && extcap_conf->control_out_fd != -1) {
        /* Format the log message as what the sync pipe expects:
         * The numeric level, followed by a colon, and then the
         * string matching the standard log string. */
        GString *msg = g_string_new(NULL);
        g_string_append_printf(msg, "%u:", level);
        if (file != NULL) {
            g_string_append_printf(msg, "%s", file);
            if (line >= 0) {
                g_string_append_printf(msg, ":%ld", line);
            }
            g_string_append(msg, " -- ");
        }
        if (func != NULL) {
            g_string_append_printf(msg, "%s(): ", func);
        }
        g_string_append_vprintf(msg, user_format, user_ap);

        /* If it's possible to write more than PIPE_BUF, we should acquire
         * a mutex just in case here. */
        sync_pipe_write_string_msg(extcap_conf->control_out_fd, SP_LOG_MSG, msg->str);
        g_string_free(msg, TRUE);
    } else {
        ws_log_console_writer(domain, level, file, line, func, mft, user_format, user_ap);
    }
}

void extcap_log_init(extcap_parameters *extcap_conf)
{
    ws_log_init(NULL, "Extcap Debug Console");
    ws_log_set_writer_with_data(extcap_log_writer, extcap_conf, NULL);
    ws_noisy("Extcap log initialization finished");
}

static int
open_control_in(const char *pipename)
{
    int fd = -1;
#ifndef _WIN32
    fd = ws_open(pipename, O_RDONLY, 0000 /* no creation so don't matter */);
    if (fd == -1) {
        ws_warning("couldn't open %s (%i)", g_strerror(errno), errno);
    }
#else
    if (!win32_is_pipe_name(pipename)) {
        return -1;
    }
    /* Wait for the pipe to appear */
    HANDLE hPipe;
    while (1) {
        hPipe = CreateFile(utf_8to16(pipename), GENERIC_READ, 0, NULL,
                OPEN_EXISTING, 0, NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            fd = _open_osfhandle((intptr_t)hPipe, O_RDONLY | O_BINARY);
            break;
        }

        if (GetLastError() != ERROR_PIPE_BUSY) {
            ws_warning("Error on control in pipe open: %s",
                win32strerror(GetLastError()));
            break;
        }

        if (!WaitNamedPipe(utf_8to16(pipename), 30 * 1000)) {
            ws_warning("Control in pipe open timed out: %s",
                win32strerror(GetLastError()));
            break;
        }
    }
#endif
    return fd;
}

void *
control_in_reader_thread(void *user_data) {
    char *pipename = (char*)user_data;
    ssize_t bytes_read;
    char indicator;
    char *buffer = g_malloc(SP_MAX_MSG_LEN);
    char *primary_msg;
    GIOChannel *control_io;

    int fd = open_control_in(pipename);
    if (fd == -1) {
        ws_warning("Couldn't open control in pipe/FIFO %s", pipename);
        g_free(pipename);
        g_free(buffer);
        return NULL;
    }
    g_free(pipename);
#ifdef _WIN32
    control_io = g_io_channel_win32_new_fd(fd);
#else
    control_io = g_io_channel_unix_new(fd);
#endif
    g_io_channel_set_encoding(control_io, NULL, NULL);
    g_io_channel_set_buffered(control_io, false);
    g_io_channel_set_close_on_unref(control_io, true);

    while ((bytes_read = sync_pipe_read_block(control_io, &indicator, SP_MAX_MSG_LEN,
        buffer, &primary_msg)) >= 4) {
        // bytes_read includes the header and should always be at least 4 on
        // synchronous reads

        ws_debug("Got a %c message with length %zu", indicator, (size_t)bytes_read);
        switch (indicator) {
        // Add other callbacks?
        case SP_QUIT:
            extcap_end_application = true;
            if (extcap_graceful_shutdown_cb) {
                extcap_graceful_shutdown_cb();
            } else {
                // XXX - Are there extcaps that gracefully shutdown when
                // extcap_end_application is set to true but do not register
                // a graceful shutdown callback?
                //_Exit(0);
            }
            break;
        case SP_TOOLBAR_CTRL:
            if (extcap_toolbar_control_cb && bytes_read >= 6) {
                extcap_toolbar_control_cb(buffer[0], buffer[1], g_bytes_new(&buffer[2], bytes_read - 6));
            }
        default:
            continue;
        }
    }

    ws_debug("control in thread exiting");
    g_io_channel_unref(control_io);
    g_free(buffer);
    return NULL;
}

uint8_t extcap_base_parse_options(extcap_parameters * extcap, int result, char * optargument)
{
    uint8_t ret = 1;
    enum ws_log_level level;

    switch (result) {
        case EXTCAP_OPT_LOG_LEVEL:
            level = ws_log_set_level_str(optargument);
            if (level == LOG_LEVEL_NONE) {
                /* Invalid log level string. */
                ret = 0;
            }
            extcap->debug = level;
            break;
        case EXTCAP_OPT_LOG_FILE:
            extcap_init_log_file(optargument);
            break;
        case EXTCAP_OPT_LIST_INTERFACES:
            extcap->do_list_interfaces = 1;
            break;
        case EXTCAP_OPT_CLEANUP_POSTKILL:
            extcap->do_cleanup_postkill = 1;
            break;
        case EXTCAP_OPT_VERSION:
            extcap->ws_version = g_strdup(optargument);
            extcap->do_version = 1;
            break;
        case EXTCAP_OPT_LIST_DLTS:
            extcap->do_list_dlts = 1;
            break;
        case EXTCAP_OPT_INTERFACE:
            extcap->interface = g_strdup(optargument);
            break;
        case EXTCAP_OPT_CONFIG:
            extcap->show_config = 1;
            break;
        case EXTCAP_OPT_CONFIG_OPTION_NAME:
            extcap->show_config_option = 1;
            extcap->config_option_name = g_strdup(optargument);
            break;
        case EXTCAP_OPT_CONFIG_OPTION_VALUE:
            extcap->show_config_option = 1;
            extcap->config_option_value = g_strdup(optargument);
            break;
        case EXTCAP_OPT_CAPTURE:
            extcap->capture = 1;
            break;
        case EXTCAP_OPT_CAPTURE_FILTER:
            extcap->capture_filter = g_strdup(optargument);
            break;
        case EXTCAP_OPT_FIFO:
            extcap->fifo = g_strdup(optargument);
            break;
        case EXTCAP_OPT_CONTROL_OUT:
            extcap->control_out_fd = ws_open(optargument, O_WRONLY, 0000 /* no creation so don't matter */);
            if (extcap->control_out_fd != -1) {
                extcap->control_out = g_strdup(optargument);
            }
            break;
        case EXTCAP_OPT_CONTROL_IN:
            if (extcap->control_in_tid == NULL) {
                extcap->control_in_tid = g_thread_new("Control in reader", control_in_reader_thread, g_strdup(optargument));
            }
            break;
        default:
            ret = 0;
    }

    return ret;
}

static void extcap_iface_print(void * data, void * userdata _U_)
{
    extcap_interface * iface = (extcap_interface *)data;

    printf("interface {value=%s}", iface->interface);
    if (iface->description != NULL)
        printf ("{display=%s}\n", iface->description);
    else
        printf ("\n");
}

static int extcap_iface_compare(const void *   a, const void *   b)
{
    const extcap_interface * iface_a = (const extcap_interface *)a;

    return (g_strcmp0(iface_a->interface, (const char *) b));
}

static void extcap_print_version(extcap_parameters * extcap)
{
    printf("extcap {version=%s}", extcap->version != NULL ? extcap->version : "unknown");
    if (extcap->helppage != NULL)
        printf("{help=%s}", extcap->helppage);
    printf("\n");
}

static int extcap_iface_listall(extcap_parameters * extcap, uint8_t list_ifs)
{
    if (list_ifs) {
        if (g_list_length(extcap->interfaces) > 0) {
            extcap_print_version(extcap);
            g_list_foreach(extcap->interfaces, extcap_iface_print, extcap);
        }
    } else if (extcap->do_version) {
        extcap_print_version(extcap);
    } else {
        GList * element = NULL;
        extcap_interface * iface = NULL;
        if ((element = g_list_find_custom(extcap->interfaces, extcap->interface, extcap_iface_compare)) == NULL)
            return 0;

        iface = (extcap_interface *) element->data;
        printf("dlt {number=%u}{name=%s}", iface->dlt, iface->dltname != NULL ? iface->dltname : iface->interface);
        if (iface->description != NULL)
            printf ("{display=%s}\n", iface->dltdescription);
        else
            printf ("\n");
    }

    return 1;
}

uint8_t extcap_base_handle_interface(extcap_parameters * extcap)
{
    /* A fifo must be provided for capture */
    if (extcap->capture && (extcap->fifo == NULL || strlen(extcap->fifo) == 0)) {
        extcap->capture = 0;
        ws_error("Extcap Error: No FIFO pipe provided");
        return 0;
    }

    if (extcap->do_cleanup_postkill) {
        if (extcap->cleanup_postkill_cb != NULL)
            extcap->cleanup_postkill_cb();
        return 1;
    } else if (extcap->do_list_interfaces) {
        return extcap_iface_listall(extcap, 1);
    } else if (extcap->do_version || extcap->do_list_dlts) {
        return extcap_iface_listall(extcap, 0);
    }

    return 0;
}

static void extcap_iface_free(void * data)
{
    extcap_interface * iface = (extcap_interface *)data;
    g_free(iface->interface);
    g_free(iface->description);
    g_free(iface->dltname);
    g_free(iface->dltdescription);
    g_free(iface);
}

static void extcap_help_option_free(void * option)
{
    extcap_option_t* o = (extcap_option_t*)option;
    g_free(o->optname);
    g_free(o->optdesc);
    g_free(o);
}

void extcap_base_cleanup(extcap_parameters ** extcap)
{
    g_list_free_full((*extcap)->interfaces, extcap_iface_free);
    g_free((*extcap)->exename);
    g_free((*extcap)->fifo);
    g_free((*extcap)->control_in);
    g_free((*extcap)->control_out);
    if ((*extcap)->control_out_fd != -1) {
        ws_close((*extcap)->control_out_fd);
    }
    g_free((*extcap)->interface);
    g_free((*extcap)->capture_filter);
    g_free((*extcap)->version);
    g_free((*extcap)->compiled_with);
    g_free((*extcap)->running_with);
    g_free((*extcap)->helppage);
    g_free((*extcap)->help_header);
    g_free((*extcap)->ws_version);
    g_list_free_full((*extcap)->help_options, extcap_help_option_free);
    g_free(*extcap);
    *extcap = NULL;
}

static void extcap_print_option(void * option, void * user_data _U_)
{
    extcap_option_t* o = (extcap_option_t*)option;
    printf("\t%s: %s\n", o->optname, o->optdesc);
}

void extcap_version_print(extcap_parameters * extcap)
{
    printf("%s version %s\n", extcap->exename, extcap->version);
    if (extcap->compiled_with != NULL)
        printf("Compiled with %s\n", extcap->compiled_with);
    if (extcap->running_with != NULL)
        printf("Running with %s\n", extcap->running_with);
}

void extcap_help_print(extcap_parameters * extcap)
{
    printf("\nWireshark - %s v%s\n\n", extcap->exename, extcap->version);
    printf("Usage:\n");
    printf("%s", extcap->help_header);
    printf("\n");
    printf("Options:\n");
    g_list_foreach(extcap->help_options, extcap_print_option, NULL);
    printf("\n");
}

void extcap_help_add_option(extcap_parameters * extcap, const char * help_option_name, const char * help_option_desc)
{
    extcap_option_t* o = g_new0(extcap_option_t, 1);
    o->optname = g_strdup(help_option_name);
    o->optdesc = g_strdup(help_option_desc);

    extcap->help_options = g_list_append(extcap->help_options, o);
}

void extcap_help_add_header(extcap_parameters * extcap, char * help_header)
{
    extcap->help_header = g_strdup(help_header);
    extcap_help_add_option(extcap, "--extcap-interfaces", "list the extcap Interfaces");
    extcap_help_add_option(extcap, "--extcap-dlts", "list the DLTs");
    extcap_help_add_option(extcap, "--extcap-interface <iface>", "specify the extcap interface");
    extcap_help_add_option(extcap, "--extcap-config", "list the additional configuration for an interface");
    extcap_help_add_option(extcap, "--capture", "run the capture");
    extcap_help_add_option(extcap, "--extcap-capture-filter <filter>", "the capture filter");
    extcap_help_add_option(extcap, "--fifo <file>", "dump data to file or fifo");
    extcap_help_add_option(extcap, "--extcap-control-in <file>", "FIFO used to receive control messages");
    extcap_help_add_option(extcap, "--extcap-control-out <file>", "FIFO used to send control messages");
    extcap_help_add_option(extcap, "--extcap-version", "print tool version");
    extcap_help_add_option(extcap, "--log-level", "Set the log level");
    extcap_help_add_option(extcap, "--log-file", "Set a log file to log messages in addition to the console");
    if (extcap->cleanup_postkill_cb != NULL)
    {
        extcap_help_add_option(extcap, "--extcap-cleanup-postkill", "Perform a post-mortem cleanup if the process was killed.");
    }
}

static void extcap_init_log_file(const char* filename)
{
    if (!filename || strlen(filename) == 0)
        ws_error("Missing log file name");
    custom_log = fopen(filename, "w");
    if (!custom_log)
        ws_error("Can't open custom log file: %s (%s)", filename, strerror(errno));
    ws_log_add_custom_file(custom_log);
}

void extcap_config_debug(unsigned* count)
{
    printf("arg {number=%u}{call=--log-level}{display=Set the log level}"
    "{type=selector}{tooltip=Set the log level}{required=false}"
    "{group=Debug}\n", *count);
    printf("value {arg=%u}{value=message}{display=Message}{default=true}\n", *count);
    printf("value {arg=%u}{value=info}{display=Info}\n", *count);
    printf("value {arg=%u}{value=debug}{display=Debug}\n", *count);
    printf("value {arg=%u}{value=noisy}{display=Noisy}\n", *count);
    (*count)++;
    printf("arg {number=%u}{call=--log-file}{display=Use a file for logging}"
    "{type=fileselect}{tooltip=Set a file where log messages are written}{required=false}"
    "{group=Debug}\n", (*count)++);
}

void extcap_cmdline_debug(char** ar, const unsigned n)
{
    GString* cmdline = g_string_new("cmdline: ");
    unsigned i;
    for (i = 0; i < n; i++)
        g_string_append_printf(cmdline, "%s ", ar[i]);
    ws_debug("%s", cmdline->str);
    g_string_free(cmdline, TRUE);
}

/*
 * Report errors and warnings through ws_warning().
 *
 * Unfortunately, ws_warning() may be a macro, so we do it by calling
 * ws_logv() with the appropriate arguments.
 */
void
extcap_log_cmdarg_err(const char *msg_format, va_list ap)
{
    ws_logv(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_WARNING, msg_format, ap);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
