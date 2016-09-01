/* traffic_table_ui.c
 * Copied from gtk/conversations_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
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

#include <glib.h>

#include "traffic_table_ui.h"
#include <wsutil/utf8_entities.h>

#ifdef HAVE_GEOIP
#include <GeoIP.h>
#include "epan/address.h"
#include "epan/addr_resolv.h"
#include "epan/geoip_db.h"
#include "epan/strutil.h"
#include "wsutil/pint.h"
#include "wsutil/str_util.h"

#include "epan/packet_info.h"
#include "epan/conversation_table.h"

#include <errno.h>
#include <stdio.h>
#include "wsutil/filesystem.h"
#include "wsutil/file_util.h"
#include "wsutil/tempfile.h"
#endif

const char *conv_column_titles[CONV_NUM_COLUMNS] = {
    "Address A",
    "Port A",
    "Address B",
    "Port B",
    "Packets",
    "Bytes",
    "Packets A " UTF8_RIGHTWARDS_ARROW " B",
    "Bytes A " UTF8_RIGHTWARDS_ARROW " B",
    "Packets B " UTF8_RIGHTWARDS_ARROW " A",
    "Bytes B " UTF8_RIGHTWARDS_ARROW " A",
    "Rel Start",
    "Duration",
    "Bits/s A " UTF8_RIGHTWARDS_ARROW " B",
    "Bits/s B " UTF8_RIGHTWARDS_ARROW " A"
};

const char *conv_conn_a_title = "Connection A";
const char *conv_conn_b_title = "Connection B";
const char *conv_abs_start_title = "Abs Start";

const char *endp_column_titles[ENDP_NUM_COLUMNS] = {
    "Address",
    "Port",
    "Packets",
    "Bytes",
    "Packets A " UTF8_RIGHTWARDS_ARROW " B",
    "Bytes A " UTF8_RIGHTWARDS_ARROW " B",
    "Packets B " UTF8_RIGHTWARDS_ARROW " A",
    "Bytes B " UTF8_RIGHTWARDS_ARROW " A"
};

const char *endp_conn_title = "Connection";

#ifdef HAVE_GEOIP
#define MAX_TPL_LINE_LEN 4096
gchar *
create_endpoint_geoip_map(const GArray *endp_array, gchar **err_str) {
    char *tpl_filename, *tpl_line;
    FILE *tpl_file, *out_file;
    char *map_path;
    gchar *map_filename = NULL;
    guint i;
    GString *tpl_entry;
    gchar *esc_entry;
    int db_lon, db_lat, db_country4, db_country6, db_city4, db_city6, db_asn4, db_asn6;
    guint cur_db;
    const char *map_endpoint_opener = "{\n";

    db_lon = db_lat = db_country4 = db_country6 = db_city4 = db_city6 = db_asn4 = db_asn6 = -1;

    /* Create a location map HTML file from a template */
    /* XXX - add error handling */
    tpl_filename = get_datafile_path("ipmap.html");
    tpl_file = ws_fopen(tpl_filename, "r");
    if(tpl_file == NULL) {
        if (err_str) {
            GString *err_descr = g_string_new("");
            g_string_printf(err_descr, file_open_error_message(errno, FALSE), tpl_filename);
            *err_str = g_string_free(err_descr, FALSE);
        }
        g_free(tpl_filename);
        return NULL;
    }
    g_free(tpl_filename);

#if 1
    /* We should probably create a file with a temporary name and a .html extension instead */
    if (! create_tempdir(&map_path, "Wireshark IP Map ")) {
        if (err_str) {
            GString *err_descr = g_string_new("");
            g_string_printf(err_descr, "Could not create temporary directory\n%s",
                            map_path);
            *err_str = g_string_free(err_descr, FALSE);
        }
        fclose(tpl_file);
        return NULL;
    }
#else
    /* Debugging only */
    map_path = "/tmp";
#endif

    map_filename = g_strdup_printf("%s%cipmap.html", map_path, G_DIR_SEPARATOR);
    out_file = ws_fopen(map_filename, "w");
    if(out_file == NULL) {
        if (err_str) {
            GString *err_descr = g_string_new("");
            g_string_printf(err_descr, file_open_error_message(errno, FALSE), map_filename);
            *err_str = g_string_free(err_descr, FALSE);
        }
        g_free(map_filename);
        fclose(tpl_file);
        return NULL;
    }

    tpl_line = (char *)g_malloc(MAX_TPL_LINE_LEN);

    while (fgets(tpl_line, MAX_TPL_LINE_LEN, tpl_file) != NULL) {
        fputs(tpl_line, out_file);
        /* MUST match ipmap.html */
        if (strstr(tpl_line, "// Start endpoint list")) {
            break;
        }
    }

    for (cur_db = 0; cur_db < geoip_db_num_dbs(); cur_db++) {
        switch (geoip_db_type(cur_db)) {
        case WS_LON_FAKE_EDITION:
            db_lon = cur_db;
            break;
        case WS_LAT_FAKE_EDITION:
            db_lat = cur_db;
            break;
        case GEOIP_COUNTRY_EDITION:
            db_country4 = cur_db;
            break;
        case GEOIP_COUNTRY_EDITION_V6:
            db_country6 = cur_db;
            break;
        case GEOIP_CITY_EDITION_REV0:
        case GEOIP_CITY_EDITION_REV1:
            db_city4 = cur_db;
            break;
        case GEOIP_CITY_EDITION_REV0_V6:
        case GEOIP_CITY_EDITION_REV1_V6:
            db_city6 = cur_db;
            break;
        }
    }

    if(db_lon < 0 || db_lat < 0) {
        if (err_str) {
            *err_str = g_strdup("Unable to open GeoIP database");
        }
        /* We can't write the map file, so close it and get rid of it */
        fclose(out_file);
        ws_unlink(map_filename);
        g_free(map_filename);
        fclose(tpl_file);
        return NULL;
    }

    /* Fill in our map data */
    tpl_entry = g_string_new("");

    for (i = 0; i < endp_array->len; i++) {
        char *lat = NULL, *lon = NULL, *country = NULL, *city = NULL, *asn = NULL;
        hostlist_talker_t *endp_item = &g_array_index(endp_array, hostlist_talker_t, i);

        if (endp_item->myaddress.type == AT_IPv4) {
            lon = geoip_db_lookup_ipv4(db_lon, pntoh32(endp_item->myaddress.data), NULL);
            lat = geoip_db_lookup_ipv4(db_lat, pntoh32(endp_item->myaddress.data), NULL);
            country = geoip_db_lookup_ipv4(db_country4, pntoh32(endp_item->myaddress.data), "-");
            city = geoip_db_lookup_ipv4(db_city4, pntoh32(endp_item->myaddress.data), "-");
            asn = geoip_db_lookup_ipv4(db_asn4, pntoh32(endp_item->myaddress.data), "-");
        } else if (endp_item->myaddress.type == AT_IPv6) {
            const struct e_in6_addr *addr = (const struct e_in6_addr *) endp_item->myaddress.data;
            lon = geoip_db_lookup_ipv6(db_lon, *addr, NULL);
            lat = geoip_db_lookup_ipv6(db_lat, *addr, NULL);
            country = geoip_db_lookup_ipv6(db_country6, *addr, "-");
            city = geoip_db_lookup_ipv6(db_city6, *addr, "-");
            asn = geoip_db_lookup_ipv6(db_asn6, *addr, "-");
        } else {
            continue;
        }

        /*
        {
          'type': 'Feature', 'geometry': { 'type': 'Point', 'coordinates': [-122.583889, 37.898889] },
          'properties': { 'title': 'host.example.com', 'description': 'AS: AS12345 Ewok Holdings, Inc.<br/>Country: US<br/>City: Muir Woods, CA<br/>Packets: 6<br/>Bytes: 980' }
        },
         */

        if (lon && lat) {
            char* addr_str;

            g_string_printf(tpl_entry, "%s", map_endpoint_opener);

            /* Longitude + latitude */
            g_string_append_printf(tpl_entry, "    'type': 'Feature', 'geometry': { 'type': 'Point', 'coordinates': [%s, %s] },\n", lon, lat);

            /* Address */
            addr_str = address_to_display(NULL, &endp_item->myaddress);
            g_string_append_printf(tpl_entry, "    'properties': { 'title': '%s', ", addr_str);
            wmem_free(NULL, addr_str);

            /* Description */

            /* City */
            esc_entry = string_replace(city, "'", "&#39;");
            g_string_append_printf(tpl_entry, "'description': '<div class=\"geoip_property\">City: %s</div>", esc_entry);
            g_free(esc_entry);

            /* Country */
            esc_entry = string_replace(country, "'", "&#39;");
            g_string_append_printf(tpl_entry, "<div class=\"geoip_property\">Country: %s</div>", esc_entry);
            g_free(esc_entry);

            /* Packets */
            esc_entry = format_size(endp_item->tx_frames + endp_item->rx_frames,
                                    (format_size_flags_e)(format_size_unit_none|format_size_prefix_si));
            g_string_append_printf(tpl_entry, "<div class=\"geoip_property\">Packets: %s</div>", esc_entry);
            g_free(esc_entry);

            /* Bytes */
            esc_entry = format_size(endp_item->tx_bytes + endp_item->rx_bytes,
                                    (format_size_flags_e)(format_size_unit_none|format_size_prefix_si));
            g_string_append_printf(tpl_entry, "<div class=\"geoip_property\">Bytes: %s</div>", esc_entry);
            g_free(esc_entry);

            /* ASN */
            esc_entry = string_replace(asn, "'", "&#39;");
            g_string_append_printf(tpl_entry, "<div class=\"geoip_property\">AS Number: %s</div>", esc_entry);
            g_free(esc_entry);

            /* XXX - We could add specific icons, e.g. depending on the amount of packets or bytes */
            g_string_append(tpl_entry, "' }\n");
            g_string_append(tpl_entry, "}");

            fputs(tpl_entry->str, out_file);
            map_endpoint_opener = ",\n{\n";
        }

        wmem_free(NULL, lat);
        wmem_free(NULL, lon);
        wmem_free(NULL, country);
        wmem_free(NULL, city);
        wmem_free(NULL, asn);

        /* XXX Display an error if we we have no entries */
    }

    while (fgets(tpl_line, MAX_TPL_LINE_LEN, tpl_file) != NULL) {
        fputs(tpl_line, out_file);
    }
    g_free(tpl_line);

    fclose(tpl_file);
    fclose(out_file);

    return map_filename;


}
#endif

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
