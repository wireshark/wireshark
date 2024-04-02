/* util.c
 * Utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#include "epan/address.h"
#include "epan/addr_resolv.h"
#include "epan/prefs.h"
#include "epan/strutil.h"

#include <wsutil/filesystem.h>

#include "ui/util.h"

/*
 * Collect command-line arguments as a string consisting of the arguments,
 * separated by spaces.
 */
char *
get_args_as_string(int argc, char **argv, int optindex)
{
    int len;
    int i;
    char *argstring;

    /*
     * Find out how long the string will be.
     */
    len = 0;
    for (i = optindex; i < argc; i++) {
        len += (int) strlen(argv[i]);
        len++;    /* space, or '\0' if this is the last argument */
    }

    /*
     * If no arguments, return empty string
     */
    if (len == 0)
        return g_strdup("");

    /*
     * Allocate the buffer for the string.
     */
    argstring = (char *)g_malloc(len);

    /*
     * Now construct the string.
     */
    argstring[0] = '\0';
    i = optindex;
    for (;;) {
        (void) g_strlcat(argstring, argv[i], len);
        i++;
        if (i == argc)
            break;
        (void) g_strlcat(argstring, " ", len);
    }
    return argstring;
}

/* Compute the difference between two seconds/microseconds time stamps. */
void
compute_timestamp_diff(int *diffsec, int *diffusec,
    uint32_t sec1, uint32_t usec1, uint32_t sec2, uint32_t usec2)
{
  if (sec1 == sec2) {
    /* The seconds part of the first time is the same as the seconds
       part of the second time, so if the microseconds part of the first
       time is less than the microseconds part of the second time, the
       first time is before the second time.  The microseconds part of
       the delta should just be the difference between the microseconds
       part of the first time and the microseconds part of the second
       time; don't adjust the seconds part of the delta, as it's OK if
       the microseconds part is negative. */

    *diffsec = sec1 - sec2;
    *diffusec = usec1 - usec2;
  } else if (sec1 <= sec2) {
    /* The seconds part of the first time is less than the seconds part
       of the second time, so the first time is before the second time.

       Both the "seconds" and "microseconds" value of the delta
       should have the same sign, so if the difference between the
       microseconds values would be *positive*, subtract 1,000,000
       from it, and add one to the seconds value. */
    *diffsec = sec1 - sec2;
    if (usec2 >= usec1) {
      *diffusec = usec1 - usec2;
    } else {
      *diffusec = (usec1 - 1000000) - usec2;
      (*diffsec)++;
    }
  } else {
    /* Oh, good, we're not caught in a chronosynclastic infindibulum. */
    *diffsec = sec1 - sec2;
    if (usec2 <= usec1) {
      *diffusec = usec1 - usec2;
    } else {
      *diffusec = (usec1 + 1000000) - usec2;
      (*diffsec)--;
    }
  }
}

/* Remove any %<interface_name> from an IP address. */
static char *sanitize_filter_ip(char *hostname) {
    char *end;
    char *ret;

    ret = g_strdup(hostname);
    if (!ret)
        return NULL;

    end = strchr(ret, '%');
    if (end)
        *end = '\0';
    return ret;
}

/* Try to figure out if we're remotely connected, e.g. via ssh or
   Terminal Server, and create a capture filter that matches aspects of the
   connection.  We match the following environment variables:

   SSH_CONNECTION (ssh): <remote IP> <remote port> <local IP> <local port>
   SSH_CLIENT (ssh): <remote IP> <remote port> <local port>
   REMOTEHOST (tcsh, others?): <remote name>
   DISPLAY (x11): [remote name]:<display num>
   SESSIONNAME (terminal server): <remote name>
 */

const char *get_conn_cfilter(void) {
    static GString *filter_str = NULL;
    char *env, **tokens;
    char *lastp, *lastc, *p;
    char *pprotocol = NULL;
    char *phostname = NULL;
    size_t hostlen;
    char *remip, *locip;

    if (filter_str == NULL) {
        filter_str = g_string_new("");
    }
    if ((env = getenv("SSH_CONNECTION")) != NULL) {
        tokens = g_strsplit(env, " ", 4);
        if (g_strv_length(tokens) == 4) {
            remip = sanitize_filter_ip(tokens[0]);
            locip = sanitize_filter_ip(tokens[2]);
            g_string_printf(filter_str, "not (tcp port %s and host %s "
                             "and tcp port %s and host %s)", tokens[1], remip,
                tokens[3], locip);
            g_free(remip);
            g_free(locip);
        }
        g_strfreev(tokens);
    } else if ((env = getenv("SSH_CLIENT")) != NULL) {
        tokens = g_strsplit(env, " ", 3);
        if (g_strv_length(tokens) == 3) {
            remip = sanitize_filter_ip(tokens[2]);
            g_string_printf(filter_str, "not (tcp port %s and host %s "
                "and tcp port %s)", tokens[1], tokens[0], remip);
            g_free(remip);
        }
        g_strfreev(tokens);
    } else if ((env = getenv("REMOTEHOST")) != NULL) {
        /* FreeBSD 7.0 sets REMOTEHOST to an empty string */
        if (g_ascii_strcasecmp(env, "localhost") == 0 ||
            strcmp(env, "127.0.0.1") == 0 ||
            strcmp(env, "") == 0) {
            return "";
        }
        remip = sanitize_filter_ip(env);
        g_string_printf(filter_str, "not host %s", remip);
        g_free(remip);
    } else if ((env = getenv("DISPLAY")) != NULL) {
        /*
         * This mirrors what _X11TransConnectDisplay() does.
         * Note that, on some systems, the hostname can
         * begin with "/", which means that it's a pathname
         * of a UNIX domain socket to connect to.
         *
         * The comments mirror those in _X11TransConnectDisplay(),
         * too. :-)
         *
         * Display names may be of the following format:
         *
         *    [protocol./] [hostname] : [:] displaynumber [.screennumber]
         *
         * A string with exactly two colons separating hostname
         * from the display indicates a DECnet style name.  Colons
         * in the hostname may occur if an IPv6 numeric address
         * is used as the hostname.  An IPv6 numeric address may
         * also end in a double colon, so three colons in a row
         * indicates an IPv6 address ending in :: followed by
         * :display.  To make it easier for people to read, an
         * IPv6 numeric address hostname may be surrounded by []
         * in a similar fashion to the IPv6 numeric address URL
         * syntax defined by IETF RFC 2732.
         *
         * If no hostname and no protocol is specified, the string
         * is interpreted as the most efficient local connection
         * to a server on the same machine.  This is usually:
         *
         *    o shared memory
         *    o local stream
         *    o UNIX domain socket
         *    o TCP to local host.
         */

        p = env;

        /*
         * Step 0, find the protocol.  This is delimited by
         * the optional slash ('/').
         */
        for (lastp = p; *p != '\0' && *p != ':' && *p != '/'; p++)
            ;
        if (*p == '\0')
            return "";    /* must have a colon */

        if (p != lastp && *p != ':') {    /* protocol given? */
            /* Yes */
            pprotocol = p;

            /* Is it TCP? */
            if (p - lastp != 3 || g_ascii_strncasecmp(lastp, "tcp", 3) != 0)
                return "";    /* not TCP */
            p++;            /* skip the '/' */
        } else
            p = env;        /* reset the pointer in
                           case no protocol was given */

        /*
         * Step 1, find the hostname.  This is delimited either by
         * one colon, or two colons in the case of DECnet (DECnet
         * Phase V allows a single colon in the hostname).  (See
         * note above regarding IPv6 numeric addresses with
         * triple colons or [] brackets.)
         */
        lastp = p;
        lastc = NULL;
        for (; *p != '\0'; p++)
            if (*p == ':')
                lastc = p;

        if (lastc == NULL)
            return "";        /* must have a colon */

        if ((lastp != lastc) && (*(lastc - 1) == ':')
            && (((lastc - 1) == lastp) || (*(lastc - 2) != ':'))) {
                /* DECnet display specified */
                return "";
        } else
            hostlen = lastc - lastp;

        if (hostlen == 0)
            return "";    /* no hostname supplied */

        phostname = (char *)g_malloc(hostlen + 1);
        memcpy(phostname, lastp, hostlen);
        phostname[hostlen] = '\0';

        if (pprotocol == NULL) {
            /*
             * No protocol was explicitly specified, so it
             * could be a local connection over a transport
             * that we won't see.
             *
             * Does the host name refer to the local host?
             * If so, the connection would probably be a
             * local connection.
             *
             * XXX - compare against our host name?
             * _X11TransConnectDisplay() does.
             */
            if (g_ascii_strcasecmp(phostname, "localhost") == 0 ||
                strcmp(phostname, "127.0.0.1") == 0) {
                    g_free(phostname);
                return "";
            }

            /*
             * A host name of "unix" (case-sensitive) also
             * causes a local connection.
             */
            if (strcmp(phostname, "unix") == 0) {
                    g_free(phostname);
                return "";
            }

            /*
             * Does the host name begin with "/"?  If so,
             * it's presumed to be the pathname of a
             * UNIX domain socket.
             */
            if (phostname[0] == '/') {
                g_free(phostname);
                return "";
            }
        }

        g_string_printf(filter_str, "not host %s", phostname);
        g_free(phostname);
#ifdef _WIN32
    } else if (GetSystemMetrics(SM_REMOTESESSION)) {
        /* We have a remote session: https://docs.microsoft.com/en-us/windows/win32/termserv/detecting-the-terminal-services-environment */
        g_string_printf(filter_str, "not port 3389");
#endif /* _WIN32 */
    } else {
        return "";
    }
    return filter_str->str;
}

bool display_is_remote(void)
{
    static bool remote_display_checked;
    static bool is_remote;

    if (!remote_display_checked) {
        is_remote = (strlen(get_conn_cfilter()) > 0);
    }
    return is_remote;
}

// MUST be UTF-8
static char *last_open_dir;

const char *
get_last_open_dir(void)
{
    return last_open_dir;
}

void
set_last_open_dir(const char *dirname)
{
    size_t len;
    char *new_last_open_dir;

    if (dirname && dirname[0]) {
        len = strlen(dirname);
        if (dirname[len-1] == G_DIR_SEPARATOR) {
            new_last_open_dir = g_strconcat(dirname, (char *)NULL);
        }
        else {
            new_last_open_dir = g_strconcat(dirname,
                                            G_DIR_SEPARATOR_S, (char *)NULL);
        }
    } else {
        new_last_open_dir = NULL;
    }

    g_free(last_open_dir);
    last_open_dir = new_last_open_dir;
}

const char *
get_open_dialog_initial_dir(void)
{
    const char *initial_dir;

    switch (prefs.gui_fileopen_style) {

    case FO_STYLE_LAST_OPENED:
        /* The user has specified that we should start out in the last directory
           we looked in.

           If we have a "last directory in which a file was opened", use that.

           If not, use the user's personal data file directory. */
        /* This is now the default behaviour in file_selection_new() */
        initial_dir = get_last_open_dir();
        if (initial_dir == NULL)
            initial_dir = get_persdatafile_dir();
        break;

    case FO_STYLE_SPECIFIED:
        /* The user has specified that we should always start out in a
           specified directory; if they've specified that directory,
           start out by showing the files in that dir, otherwise use
           the user's personal data file directory. */
        if (prefs.gui_fileopen_dir[0] != '\0')
            initial_dir = prefs.gui_fileopen_dir;
        else
            initial_dir = get_persdatafile_dir();
        break;

    default:
        ws_assert_not_reached();
        initial_dir = NULL;
        break;
    }
    return initial_dir;
}
