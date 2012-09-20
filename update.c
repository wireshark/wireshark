/* update.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <glib.h>
#include <string.h>
#include <stdio.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/filesystem.h>

#include "simple_dialog.h"
#include "version_info.h"

#ifdef HAVE_LIBPCAP
#include "capture-pcap-util.h"
#endif

#include <wsutil/file_util.h>

#include <wininet.h>
#include "nio-ie5.h"


/* update information about a single component */
typedef struct update_info_s {
    char *prefix;                   /* prefix of the update file keys */
    gboolean needs_update;          /* does this component need an update */
    char *version_installed;        /* the version currently installed */

    char *title;                    /* the component title (name) */
    char *description;              /* description of the component */
    char *version_recommended;      /* the version recommended */
    char *url;                      /* the URL for an update */
    char *md5;                      /* md5 checksum for that update */
    char *size;                     /* size of that update */
} update_info_t;


/* download a complete file from the internet */
int
download_file(const char *url, const char *filename) {
    netio_ie5_t * conn;
    char buf[100];
    int chunk_len;
    int fd;
    int stream_len;
    int ret = 0;


    /* open output file */
    fd = ws_open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if(fd == -1) {
        g_warning("Couldn't open output file %s!", filename);
        return -1;
    }

    /* connect to url */
    conn = netio_ie5_connect (url);
    if (conn == NULL) {
        ws_close(fd);
        g_warning("Couldn't connect to %s!", url);
        return -1;
    }

    do {
		/* XXX - maybe add a progress bar here */

        /* read some bytes from the url */
        chunk_len = netio_ie5_read (conn, buf, sizeof(buf));

        /* write bytes to the output file */
        stream_len = ws_write( fd, buf, chunk_len);
        if(stream_len != chunk_len) {
            g_warning("output failed: stream_len %u != chunk_len %u", stream_len, chunk_len);
            ret = -1;
            break;
        }
    } while(chunk_len > 0);

    netio_ie5_disconnect(conn);

    ws_close(fd);

    return ret;
}

update_info_t *
update_info_new(void)
{
    return g_malloc0(sizeof(update_info_t));
}

void
update_info_delete(update_info_t *update_info)
{
    g_free(update_info->prefix);
    g_free(update_info->version_installed);
    g_free(update_info->title);
    g_free(update_info->description);
    g_free(update_info->version_recommended);
    g_free(update_info->url);
    g_free(update_info->md5);
    g_free(update_info->size);

    g_free(update_info);
}

/* check a single key value pair */
static void
update_pref_check(gchar *pref_name, gchar *value, char *check_prefix, char *check_name, char **check_value)
{
    GString *check = g_string_new(check_prefix);

    g_string_append(check, check_name);

    if(strcmp(pref_name, check->str) == 0) {
        if(*check_value)
            /* there shouldn't be a duplicate entry in the update file */
            g_warning("Duplicate of %s: current %s former %s", pref_name, value, *check_value);
        else
            *check_value = g_strdup(value);
    }

    g_string_free(check, TRUE);
}

/* a new key value pair from the update file */
static prefs_set_pref_e
update_pref(gchar *pref_name, gchar *value, void *private_data)
{
    update_info_t *update_info = private_data;

    update_pref_check(pref_name, value, update_info->prefix, "title",       &update_info->title);
    update_pref_check(pref_name, value, update_info->prefix, "description", &update_info->description);
    update_pref_check(pref_name, value, update_info->prefix, "version",     &update_info->version_recommended);
    update_pref_check(pref_name, value, update_info->prefix, "update.url",  &update_info->url);
    update_pref_check(pref_name, value, update_info->prefix, "update.md5",  &update_info->md5);
    update_pref_check(pref_name, value, update_info->prefix, "update.size",  &update_info->size);

    return PREFS_SET_OK;
}

/* display an update_info */
static void
update_info_display(update_info_t *update_info)
{
    GString *overview;


    overview = g_string_new("");

    if(update_info->title) {
        g_string_append_printf(overview, "%s%s%s",
            simple_dialog_primary_start(), update_info->title, simple_dialog_primary_end());
    } else {
        g_string_append_printf(overview, "%sComponent%s",
            simple_dialog_primary_start(), simple_dialog_primary_end());
    }

    g_string_append(overview, "\n\n");

    if(update_info->description)
        g_string_append_printf(overview, "%s\n\n", update_info->description);

    g_string_append_printf(overview, "Installed: %s\n", update_info->version_installed);

    if(update_info->version_recommended)
        g_string_append_printf(overview, "Recommended: %s\n", update_info->version_recommended);
    else
        g_string_append(overview, "Recommenced: unknown\n");

    if(update_info->version_recommended && update_info->url)
        g_string_append_printf(overview, "From: %s\n", update_info->url);

    if(update_info->size)
        g_string_append_printf(overview, "Size: %s", update_info->size);

    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, overview->str);

    g_string_free(overview, TRUE);

}

/* check the version of the wireshark program */
static update_info_t *
update_check_wireshark(const char *local_file)
{
    FILE *pf;
    update_info_t *update_info = update_info_new();


    update_info->version_installed = g_strdup(VERSION);
    update_info->prefix = "wireshark.setup.";

    pf = ws_fopen(local_file, "r");
    if(pf != NULL) {
        /* read in update_info of Wireshark */
        read_prefs_file(local_file, pf, update_pref, update_info);
        fclose(pf);

        /* check if Wireshark needs an update */
        if(update_info->version_installed && update_info->version_recommended &&
            strcmp(update_info->version_installed, update_info->version_recommended) != 0)
        {
            update_info->needs_update = TRUE;
        }
    } else {
        g_warning("Could not open %s", local_file);
    }

    return update_info;
}

/* check the version of winpcap */
static update_info_t *
update_check_winpcap(const char *local_file)
{
    FILE *pf;
    update_info_t * update_info = update_info_new();
    GString *pcap_version_tmp;
    char *pcap_version = NULL;
    char *pcap_vstart;
    char *pcap_vend;


    update_info->prefix = "winpcap.";

    pf = ws_fopen(local_file, "r");
    if(pf != NULL) {
        /* read in update_info of WinPcap */
        read_prefs_file(local_file, pf, update_pref, update_info);
        fclose(pf);

        /* get WinPcap version */
        /* XXX - what's the "approved" method to get the WinPcap version? */
        pcap_version_tmp = g_string_new("");
        get_runtime_pcap_version(pcap_version_tmp);

        /* cut out real version from "combined" version string */
        pcap_vstart = strstr(pcap_version_tmp->str, "with WinPcap version ");
        if(pcap_vstart != NULL) {
            pcap_vstart += sizeof("with WinPcap version");
            pcap_vend = strstr(pcap_vstart, " ");
            if(pcap_vend != NULL) {
                pcap_vend[0] = 0;
                pcap_version = g_strdup(pcap_vstart);
            }
        }

        update_info->version_installed = g_strdup(pcap_version);

        if(pcap_version && update_info->version_recommended &&
            strcmp(pcap_version, update_info->version_recommended) != 0)
        {
            update_info->needs_update = TRUE;
        }
    } else {
        g_warning("Could not open %s", local_file);
    }

    g_string_free(pcap_version_tmp, TRUE);
    g_free(pcap_version);

    return update_info;
}


/* check for all updates */
void
update_check(gboolean interactive)
{
    char *local_file;
    const char *url_file = "http://127.0.0.1/wsupdate";	/* XXX - build the URL depending on platform, versions, ... */
    update_info_t *update_info_wireshark;
    update_info_t *update_info_winpcap;


    /* build update file name */
    /* XXX - using the personal path, use temp dir instead? */
    local_file = get_persconffile_path("wsupdate", FALSE, TRUE /*for_writing*/);
    if(local_file == NULL) {
        g_warning("Couldn't create output path!");
        return;
    }

    /* download update file */
    if(download_file(url_file, local_file) == -1) {
        g_warning("Couldn't download update file: %s", local_file);
        g_free(local_file);
        return;
    }

    /* check wireshark */
    update_info_wireshark = update_check_wireshark(local_file);

    /* check winpcap */
    update_info_winpcap = update_check_winpcap(local_file);

    /* display results */
    if(update_info_wireshark->needs_update || update_info_winpcap->needs_update) {
        if(update_info_wireshark->needs_update)
            update_info_display(update_info_wireshark);
        if(update_info_winpcap->needs_update)
            update_info_display(update_info_winpcap);
    } else {
        if(interactive) {
            simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "No updates available");
        }
    }

    /* cleanup */
    update_info_delete(update_info_wireshark);
    update_info_delete(update_info_winpcap);

    g_free(local_file);
}

