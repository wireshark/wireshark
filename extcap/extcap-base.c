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

#include "extcap-base.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_GETOPT_H
    #include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
    #include "wsutil/wsgetopt.h"
#endif
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

FILE* custom_log = NULL;

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

void extcap_base_set_util_info(extcap_parameters * extcap, const char * exename, const char * major,
    const char * minor, const char * release, const char * helppage)
{
    extcap->exename = g_path_get_basename(exename);

    g_assert(major);
    if (!minor)
        g_assert(!release);

    extcap->version = g_strdup_printf("%s%s%s%s%s",
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
    extcap->compiled_with = g_strdup_vprintf(fmt, ap);
    va_end(ap);
}

void extcap_base_set_running_with(extcap_parameters * extcap, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    extcap->running_with = g_strdup_vprintf(fmt, ap);
    va_end(ap);
}

static void extcap_custom_log(const gchar *log_domain,
             GLogLevelFlags log_level,
             const gchar *message,
             gpointer user_data)
{
    if (log_level & G_LOG_LEVEL_DEBUG) {
        if (!custom_log)
            return;
        fprintf(custom_log, "%s\n", message);
        fflush(custom_log);
    } else {
        g_log_default_handler(log_domain, log_level, message, user_data);
    }
}

uint8_t extcap_base_parse_options(extcap_parameters * extcap, int result, char * optargument)
{
    uint8_t ret = 1;

    switch (result) {
        case EXTCAP_OPT_DEBUG:
#ifdef _WIN32
            _putenv_s("G_MESSAGES_DEBUG", "all");
#else
            setenv("G_MESSAGES_DEBUG", "all", 1);
#endif
            extcap->debug = TRUE;
            break;
        case EXTCAP_OPT_DEBUG_FILE:
            extcap_init_custom_log(optargument);
            g_log_set_default_handler(extcap_custom_log, NULL);
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
        g_error("Extcap Error: No FIFO pipe provided");
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
    extcap_help_add_option(extcap, "--debug", "print additional messages");
    extcap_help_add_option(extcap, "--debug-file", "print debug messages to file");
}

void extcap_init_custom_log(const char* filename)
{
    if (!filename || strlen(filename) == 0)
        return;
    custom_log = fopen(filename, "w");
    if (!custom_log)
        g_error("Can't open custom log file: %s (%s)", filename, strerror(errno));
}

void extcap_config_debug(unsigned* count)
{
    printf("arg {number=%u}{call=--debug}{display=Run in debug mode}"
    "{type=boolflag}{default=false}{tooltip=Print debug messages}{required=false}"
    "{group=Debug}\n", (*count)++);
    printf("arg {number=%u}{call=--debug-file}{display=Use a file for debug}"
    "{type=string}{tooltip=Set a file where the debug messages are written}{required=false}"
    "{group=Debug}\n", (*count)++);
}

void extcap_cmdline_debug(char** ar, const unsigned n)
{
    GString* cmdline = g_string_new("cmdline: ");
    unsigned i;
    for (i = 0; i < n; i++)
        g_string_append_printf(cmdline, "%s ", ar[i]);
    g_debug("%s", cmdline->str);
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
