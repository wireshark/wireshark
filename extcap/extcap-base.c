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

static FILE *custom_log = NULL;

/* used to inform to extcap application that end of application is requested */
gboolean extcap_end_application = FALSE;
/* graceful shutdown callback, can be null */
void (*extcap_graceful_shutdown_cb)(void) = NULL;

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
    extcap_end_application = TRUE;
    if (extcap_graceful_shutdown_cb != NULL) {
       extcap_graceful_shutdown_cb();
    }
#ifdef _WIN32
    return TRUE;
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

    extcap->interfaces = g_list_append(extcap->interfaces, (gpointer) iface);
}

gboolean extcap_base_register_graceful_shutdown_cb(extcap_parameters * extcap _U_, void (*callback)(void))
{
#ifndef _WIN32
    struct sigaction sig_handler = { .sa_handler = extcap_exit_from_loop };
#endif

    extcap_end_application = FALSE;
    extcap_graceful_shutdown_cb = callback;
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(extcap_exit_from_loop, TRUE)) {
            ws_warning("Can't set console handler");
            return FALSE;
    }
#else
    /* Catch signals to be able to cleanup config later */
    if (sigaction(SIGINT, &sig_handler, NULL)) {
            ws_warning("Can't set SIGINT signal handler");
            return FALSE;
    }
    if (sigaction(SIGTERM, &sig_handler, NULL)) {
            ws_warning("Can't set SIGTERM signal handler");
            return FALSE;
    }
    if (sigaction(SIGPIPE, &sig_handler, NULL)) {
            ws_warning("Can't set SIGPIPE signal handler");
            return FALSE;
    }
#endif /* _WIN32 */

    return TRUE;
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

void extcap_log_init(const char *progname)
{
    ws_log_init(progname, NULL);
    /* extcaps cannot write debug information to parent on stderr. */
    ws_log_console_writer_set_use_stdout(TRUE);
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
            else if (level <= LOG_LEVEL_DEBUG) {
                extcap->debug = TRUE;
            }
            break;
        case EXTCAP_OPT_LOG_FILE:
            extcap_init_log_file(optargument);
            break;
        case EXTCAP_OPT_LIST_INTERFACES:
            extcap->do_list_interfaces = 1;
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
        case EXTCAP_OPT_CAPTURE:
            extcap->capture = 1;
            break;
        case EXTCAP_OPT_CAPTURE_FILTER:
            extcap->capture_filter = g_strdup(optargument);
            break;
        case EXTCAP_OPT_FIFO:
            extcap->fifo = g_strdup(optargument);
            break;
        default:
            ret = 0;
    }

    return ret;
}

static void extcap_iface_print(gpointer data, gpointer userdata _U_)
{
    extcap_interface * iface = (extcap_interface *)data;

    printf("interface {value=%s}", iface->interface);
    if (iface->description != NULL)
        printf ("{display=%s}\n", iface->description);
    else
        printf ("\n");
}

static gint extcap_iface_compare(gconstpointer  a, gconstpointer  b)
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

static gint extcap_iface_listall(extcap_parameters * extcap, uint8_t list_ifs)
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
    if (extcap->capture && (extcap->fifo == NULL || strlen(extcap->fifo) <= 0)) {
        extcap->capture = 0;
        ws_error("Extcap Error: No FIFO pipe provided");
        return 0;
    }

    if (extcap->do_list_interfaces) {
        return extcap_iface_listall(extcap, 1);
    } else if (extcap->do_version || extcap->do_list_dlts) {
        return extcap_iface_listall(extcap, 0);
    }

    return 0;
}

static void extcap_iface_free(gpointer data)
{
    extcap_interface * iface = (extcap_interface *)data;
    g_free(iface->interface);
    g_free(iface->description);
    g_free(iface->dltname);
    g_free(iface->dltdescription);
    g_free(iface);
}

static void extcap_help_option_free(gpointer option)
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
    g_free((*extcap)->interface);
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

static void extcap_print_option(gpointer option, gpointer user_data _U_)
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
    extcap_help_add_option(extcap, "--extcap-version", "print tool version");
    extcap_help_add_option(extcap, "--log-level", "Set the log level");
    extcap_help_add_option(extcap, "--log-file", "Set a log file to log messages in addition to the console");
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
