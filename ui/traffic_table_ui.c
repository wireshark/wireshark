/* traffic_table_ui.c
 * Helper routines common to conversation/endpoint tables.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <glib.h>

#include "traffic_table_ui.h"
#include <wsutil/utf8_entities.h>

#ifdef HAVE_MAXMINDDB
#include <errno.h>

#include "wsutil/filesystem.h"
#include "wsutil/file_util.h"
#include "wsutil/json_dumper.h"
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

const char *endp_column_titles[ENDP_NUM_GEO_COLUMNS] = {
    "Address",
    "Port",
    "Packets",
    "Bytes",
    "Tx Packets",
    "Tx Bytes",
    "Rx Packets",
    "Rx Bytes",
    "Country",
    "City",
    "AS Number",
    "AS Organization"
};

const char *endp_conn_title = "Connection";

#ifdef HAVE_MAXMINDDB
gboolean
write_endpoint_geoip_map(FILE *fp, gboolean json_only, hostlist_talker_t *const *hosts, gchar **err_str)
{
    if (!json_only) {
        char *base_html_path = get_datafile_path("ipmap.html");
        FILE *base_html_fp = ws_fopen(base_html_path, "rb");
        if (!base_html_fp) {
            *err_str = g_strdup_printf("Could not open base file %s for reading: %s",
                    base_html_path, g_strerror(errno));
            g_free(base_html_path);
            return FALSE;
        }
        g_free(base_html_path);

        /* Copy ipmap.html to map file. */
        size_t n;
        char buf[4096];
        while ((n = fread(buf, 1, sizeof(buf), base_html_fp)) != 0) {
            if (fwrite(buf, 1, n, fp) != n) {
                *err_str = g_strdup_printf("Failed to write to map file: %s", g_strerror(errno));
                fclose(base_html_fp);
                return FALSE;
            }
        }
        if (ferror(base_html_fp)) {
            *err_str = g_strdup_printf("Failed to read base file: %s", g_strerror(errno));
            fclose(base_html_fp);
            return FALSE;
        }
        fclose(base_html_fp);

        fputs("<script id=\"ipmap-data\" type=\"application/json\">\n", fp);
    }

    /*
     * Writes a feature for each resolved address, the output will look like:
     *  {
     *    "type": "FeatureCollection",
     *    "features": [
     *      {
     *        "type": "Feature",
     *        "geometry": {
     *          "type": "Point",
     *          "coordinates": [ -97.821999, 37.750999 ]
     *        },
     *        "properties": {
     *          "ip": "8.8.4.4",
     *          "autonomous_system_number": 15169,
     *          "autonomous_system_organization": "Google LLC",
     *          "city": "(omitted, but key is shown for documentation reasons)",
     *          "country": "United States",
     *          "radius": 1000,
     *          "packets": 1,
     *          "bytes": 1543
     *        }
     *      }
     *    ]
     *  }
     */
    json_dumper dumper = {
        .output_file = fp,
        .flags = JSON_DUMPER_FLAGS_PRETTY_PRINT
    };
    json_dumper_begin_object(&dumper);
    json_dumper_set_member_name(&dumper, "type");
    json_dumper_value_string(&dumper, "FeatureCollection");
    json_dumper_set_member_name(&dumper, "features");
    json_dumper_begin_array(&dumper);

    /* Append map data. */
    size_t count = 0;
    const hostlist_talker_t *host;
    for (hostlist_talker_t *const *iter = hosts; (host = *iter) != NULL; ++iter) {
        char addr[WS_INET6_ADDRSTRLEN];
        const mmdb_lookup_t *result = NULL;
        if (host->myaddress.type == AT_IPv4) {
            const ws_in4_addr *ip4 = (const ws_in4_addr *)host->myaddress.data;
            result = maxmind_db_lookup_ipv4(ip4);
            ws_inet_ntop4(ip4, addr, sizeof(addr));
        } else if (host->myaddress.type == AT_IPv6) {
            const ws_in6_addr *ip6 = (const ws_in6_addr *)host->myaddress.data;
            result = maxmind_db_lookup_ipv6(ip6);
            ws_inet_ntop6(ip6, addr, sizeof(addr));
        }
        if (!maxmind_db_has_coords(result)) {
            // result could be NULL if the caller did not trigger a lookup
            // before. result->found could be FALSE if no MMDB entry exists.
            continue;
        }

        ++count;
        json_dumper_begin_object(&dumper);

        json_dumper_set_member_name(&dumper, "type");
        json_dumper_value_string(&dumper, "Feature");

        json_dumper_set_member_name(&dumper, "geometry");
        {
            json_dumper_begin_object(&dumper);
            json_dumper_set_member_name(&dumper, "type");
            json_dumper_value_string(&dumper, "Point");
            json_dumper_set_member_name(&dumper, "coordinates");
            json_dumper_begin_array(&dumper);
            json_dumper_value_double(&dumper, result->longitude);
            json_dumper_value_double(&dumper, result->latitude);
            json_dumper_end_array(&dumper);     // end coordinates
        }
        json_dumper_end_object(&dumper);    // end geometry

        json_dumper_set_member_name(&dumper, "properties");
        json_dumper_begin_object(&dumper);
        {
            json_dumper_set_member_name(&dumper, "ip");
            json_dumper_value_string(&dumper, addr);
            if (result->as_number && result->as_org) {
                json_dumper_set_member_name(&dumper, "autonomous_system_number");
                json_dumper_value_anyf(&dumper, "%u", result->as_number);
                json_dumper_set_member_name(&dumper, "autonomous_system_organization");
                json_dumper_value_string(&dumper, result->as_org);
            }
            if (result->city) {
                json_dumper_set_member_name(&dumper, "city");
                json_dumper_value_string(&dumper, result->city);
            }
            if (result->country) {
                json_dumper_set_member_name(&dumper, "country");
                json_dumper_value_string(&dumper, result->country);
            }
            if (result->accuracy) {
                json_dumper_set_member_name(&dumper, "radius");
                json_dumper_value_anyf(&dumper, "%u", result->accuracy);
            }
            json_dumper_set_member_name(&dumper, "packets");
            json_dumper_value_anyf(&dumper, "%" G_GUINT64_FORMAT, host->rx_frames + host->tx_frames);
            json_dumper_set_member_name(&dumper, "bytes");
            json_dumper_value_anyf(&dumper, "%" G_GUINT64_FORMAT, host->rx_bytes + host->tx_bytes);
        }
        json_dumper_end_object(&dumper);    // end properties

        json_dumper_end_object(&dumper);
    }

    json_dumper_end_array(&dumper);     // end features
    json_dumper_end_object(&dumper);
    json_dumper_finish(&dumper);
    if (!json_only) {
        fputs("</script>\n", fp);
    }

    if (count == 0) {
        *err_str = g_strdup("No endpoints available to map");
        return FALSE;
    }

    return TRUE;
}
#endif

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
