/* geoip_db.c
 * GeoIP database support
 *
 * Copyright 2008, Gerald Combs <gerald@wireshark.org>
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

/* To do:
 * We currently return a single string for each database. Some databases,
 * e.g. GeoIPCity, can return other info such as area codes.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#ifdef HAVE_GEOIP
#include "GeoIP.h"
#include "GeoIPCity.h"

#include "geoip_db.h"
#include "uat.h"
#include "prefs.h"
#include "report_err.h"
#include "value_string.h"
#include <wsutil/file_util.h>

/* This needs to match NUM_GEOIP_COLS in hostlist_table.h */
#define MAX_GEOIP_DBS 13

/* Column names for each database type */
value_string geoip_type_name_vals[] = {
    { GEOIP_COUNTRY_EDITION,        "Country" },
    { GEOIP_REGION_EDITION_REV0,    "Region" },
    { GEOIP_CITY_EDITION_REV0,      "City"},
    { GEOIP_ORG_EDITION,            "Organization" },
    { GEOIP_ISP_EDITION,            "ISP" },
    { GEOIP_CITY_EDITION_REV1,      "City" },
    { GEOIP_REGION_EDITION_REV1,    "Region" },
    { GEOIP_PROXY_EDITION,          "Proxy" },
    { GEOIP_ASNUM_EDITION,          "AS Number" },
    { GEOIP_NETSPEED_EDITION,       "Speed" },
    { GEOIP_DOMAIN_EDITION,         "Domain" },
#ifdef HAVE_GEOIP_V6
    { GEOIP_COUNTRY_EDITION_V6,     "Country" },
/* This is the closest thing to a version that GeoIP.h seems to provide. */
#if NUM_DB_TYPES > 31 /* 1.4.7 */
    { GEOIP_CITY_EDITION_REV0_V6,   "City"},
    { GEOIP_CITY_EDITION_REV1_V6,   "City"},
    { GEOIP_ASNUM_EDITION_V6,       "AS Number" },
    { GEOIP_ISP_EDITION_V6,         "ISP" },
    { GEOIP_ORG_EDITION_V6,         "Organization" },
    { GEOIP_DOMAIN_EDITION_V6,      "Domain" },
#endif /* NUM_DB_TYPES > 31 */
#if NUM_DB_TYPES > 32 /* 1.4.8 */
    { GEOIP_NETSPEED_EDITION_REV1_V6, "Speed" },
#endif /* NUM_DB_TYPES > 32 */
#endif /* HAVE_GEOIP_V6 */
    { WS_LAT_FAKE_EDITION,          "Latitude" },   /* fake database */
    { WS_LON_FAKE_EDITION,          "Longitude" },  /* fake database */
    { 0, NULL }
};

static GArray *geoip_dat_arr = NULL;

/* UAT definitions. Copied from oids.c */
typedef struct _geoip_db_path_t {
    char* path;
} geoip_db_path_t;

static geoip_db_path_t *geoip_db_paths = NULL;
static guint num_geoip_db_paths = 0;
static uat_t *geoip_db_paths_uat = NULL;
UAT_DIRECTORYNAME_CB_DEF(geoip_mod, path, geoip_db_path_t)


/**
 * Scan a directory for GeoIP databases and load them
 */
static void
geoip_dat_scan_dir(const char *dirname) {
    WS_DIR *dir;
    WS_DIRENT *file;
    const char *name;
    char *datname;
    GeoIP *gi;

    if ((dir = ws_dir_open(dirname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            name = ws_dir_get_name(file);
            if (g_str_has_prefix(file, "Geo") && g_str_has_suffix(file, ".dat")) {
                datname = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", dirname, name);
                gi = GeoIP_open(datname, GEOIP_MEMORY_CACHE);
                if (gi) {
                    g_array_append_val(geoip_dat_arr, gi);
                }
                g_free(datname);
            }
        }
        ws_dir_close (dir);
    }
}

/* UAT callbacks */
static void* geoip_db_path_copy_cb(void* dest, const void* orig, size_t len _U_) {
    const geoip_db_path_t *m = orig;
    geoip_db_path_t *d = dest;

    d->path = g_strdup(m->path);

    return d;
}

static void geoip_db_path_free_cb(void* p) {
    geoip_db_path_t *m = p;
    g_free(m->path);
}

/**
 * Initialize GeoIP lookups
 */
void
geoip_db_init(void) {
    guint i;
    static uat_field_t geoip_db_paths_fields[] = {
        UAT_FLD_DIRECTORYNAME(geoip_mod, path, "GeoIP Database Directory", "The GeoIP database directory path"),
        UAT_END_FIELDS
    };
    char* geoip_load_error = NULL;

    geoip_dat_arr = g_array_new(FALSE, FALSE, sizeof(GeoIP *));

    geoip_db_paths_uat = uat_new("GeoIP Database Paths",
            sizeof(geoip_db_path_t),
            "geoip_db_paths",
            FALSE,
            (void*)&geoip_db_paths,
            &num_geoip_db_paths,
            UAT_CAT_GENERAL,
            "ChGeoIPDbPaths",
            geoip_db_path_copy_cb,
            NULL,
            geoip_db_path_free_cb,
                        NULL,
            geoip_db_paths_fields);

    uat_load(geoip_db_paths_uat, &geoip_load_error);

    if (geoip_load_error) {
        report_failure("Error loading GeoIP database path table: %s", geoip_load_error);
        return;
    }

    for (i = 0; i < num_geoip_db_paths; i++) {
        if (geoip_db_paths[i].path) {
            geoip_dat_scan_dir(geoip_db_paths[i].path);
        }
    }

    /* add fake databases for latitude and longitude (using "City" in reality) */
    {
        GeoIP *gi_lat;
        GeoIP *gi_lon;

        gi_lat = g_malloc(sizeof (GeoIP));
        gi_lat->databaseType = WS_LAT_FAKE_EDITION;
        g_array_append_val(geoip_dat_arr, gi_lat);
        gi_lon = g_malloc(sizeof (GeoIP));
        gi_lon->databaseType = WS_LON_FAKE_EDITION;
        g_array_append_val(geoip_dat_arr, gi_lon);
    }
}

guint
geoip_db_num_dbs(void) {
    return geoip_dat_arr->len;
}

const gchar *
geoip_db_name(guint dbnum) {
    GeoIP *gi;

    gi = g_array_index(geoip_dat_arr, GeoIP *, dbnum);
    if (gi) {
        return (val_to_str(gi->databaseType, geoip_type_name_vals, "Unknown database"));
    }
    return "Invalid database";
}

int
geoip_db_type(guint dbnum) {
    GeoIP *gi;

    gi = g_array_index(geoip_dat_arr, GeoIP *, dbnum);
    if (gi) {
        return (gi->databaseType);
    }
    return -1;
}

static int
geoip_db_lookup_latlon4(guint32 addr, float *lat, float *lon) {
    GeoIP *gi;
    GeoIPRecord *gir;
    guint i;

    for (i = 0; i < geoip_db_num_dbs(); i++) {
        gi = g_array_index(geoip_dat_arr, GeoIP *, i);
        if (gi) {
            switch (gi->databaseType) {
                case GEOIP_CITY_EDITION_REV0:
                case GEOIP_CITY_EDITION_REV1:
                    gir = GeoIP_record_by_ipnum(gi, addr);
                    if(gir) {
                        *lat = gir->latitude;
                        *lon = gir->longitude;
                        return 0;
                    }
                    return -1;
                    /*break;*/

                default:
                    break;
            }
        }
    }
    return -1;
}

#define VAL_STR_LEN 100

/*
 * GeoIP 1.4.3 and later provide GeoIP_set_charset(), but in versions
 * 1.4.3 to 1.4.6 that only applies to the City databases. I.e., it's
 * possible to produce invalid UTF-8 sequences even if GeoIP_set_charset()
 * is used.
 */
static void
iso_8859_1_to_utf_8(char *val) {
    char *utf8_val;

    utf8_val = g_convert(val, VAL_STR_LEN, "UTF-8", "ISO-8859-1", NULL, NULL, NULL);
    if (utf8_val) {
        g_strlcpy(val, utf8_val, VAL_STR_LEN);
        g_free(utf8_val);
    }

}

const char *
geoip_db_lookup_ipv4(guint dbnum, guint32 addr, char *not_found) {
    GeoIP *gi;
    GeoIPRecord *gir;
    const char *raw_val, *ret = not_found;
    static char val[VAL_STR_LEN];

    gi = g_array_index(geoip_dat_arr, GeoIP *, dbnum);
    if (gi) {
        switch (gi->databaseType) {
            case GEOIP_COUNTRY_EDITION:
                raw_val = GeoIP_country_name_by_ipnum(gi, addr);
                if (raw_val) {
                    g_snprintf(val, VAL_STR_LEN, "%s", raw_val);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                }
                break;

            case GEOIP_CITY_EDITION_REV0:
            case GEOIP_CITY_EDITION_REV1:
                gir = GeoIP_record_by_ipnum(gi, addr);
                if (gir && gir->city && gir->region) {
                    g_snprintf(val, VAL_STR_LEN, "%s, %s", gir->city, gir->region);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                } else if (gir && gir->city) {
                    g_snprintf(val, VAL_STR_LEN, "%s", gir->city);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                }
                break;

            case GEOIP_ORG_EDITION:
            case GEOIP_ISP_EDITION:
            case GEOIP_ASNUM_EDITION:
                raw_val = GeoIP_name_by_ipnum(gi, addr);
                if (raw_val) {
                    g_snprintf(val, VAL_STR_LEN, "%s", raw_val);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                }
                break;

            case WS_LAT_FAKE_EDITION:
            {
                float lat;
                float lon;
                char *c;
                if(geoip_db_lookup_latlon4(addr, &lat, &lon) == 0) {
                    g_snprintf(val, VAL_STR_LEN, "%f", lat);
                    c = strchr(val, ',');
                    if (c != NULL) *c = '.';
                    ret = val;
                }
            }
                break;

            case WS_LON_FAKE_EDITION:
            {
                float lat;
                float lon;
                char *c;
                if(geoip_db_lookup_latlon4(addr, &lat, &lon) == 0) {
                    g_snprintf(val, VAL_STR_LEN, "%f", lon);
                    c = strchr(val, ',');
                    if (c != NULL) *c = '.';
                    ret = val;
                }
            }
                break;

            default:
                break;
        }
    }
    if (ret) {
        return ret;
    }
    return not_found;
}

#ifdef HAVE_GEOIP_V6

static int
#if NUM_DB_TYPES > 31 /* 1.4.7 */
geoip_db_lookup_latlon6(geoipv6_t addr, float *lat, float *lon) {
    GeoIP *gi;
    GeoIPRecord *gir;
    guint i;

    for (i = 0; i < geoip_db_num_dbs(); i++) {
        gi = g_array_index(geoip_dat_arr, GeoIP *, i);
        if (gi) {
            switch (gi->databaseType) {
                case GEOIP_CITY_EDITION_REV0_V6:
                case GEOIP_CITY_EDITION_REV1_V6:
                    gir = GeoIP_record_by_ipnum_v6(gi, addr);
                    if(gir) {
                        *lat = gir->latitude;
                        *lon = gir->longitude;
                        return 0;
                    }
                    return -1;
                    /*break;*/

                default:
                    break;
            }
        }
    }
    return -1;
}
#else /* NUM_DB_TYPES */
geoip_db_lookup_latlon6(geoipv6_t addr _U_, float *lat _U_, float *lon _U_) {
    return -1;
}
#endif /* NUM_DB_TYPES */

const char *
geoip_db_lookup_ipv6(guint dbnum, struct e_in6_addr addr, char *not_found) {
    GeoIP *gi;
    geoipv6_t gaddr;
    const char *raw_val, *ret = not_found;
    static char val[VAL_STR_LEN];
#if NUM_DB_TYPES > 31
    GeoIPRecord *gir;
#endif

    memcpy(&gaddr, &addr, sizeof(addr));

    gi = g_array_index(geoip_dat_arr, GeoIP *, dbnum);
    if (gi) {
        switch (gi->databaseType) {
            case GEOIP_COUNTRY_EDITION_V6:
                raw_val = GeoIP_country_name_by_ipnum_v6(gi, gaddr);
                if (raw_val) {
                    g_snprintf(val, VAL_STR_LEN, "%s", raw_val);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                }
                break;

#if NUM_DB_TYPES > 31
            case GEOIP_CITY_EDITION_REV0_V6:
            case GEOIP_CITY_EDITION_REV1_V6:
                gir = GeoIP_record_by_ipnum_v6(gi, gaddr);
                if (gir && gir->city && gir->region) {
                    g_snprintf(val, VAL_STR_LEN, "%s, %s", gir->city, gir->region);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                } else if (gir && gir->city) {
                    g_snprintf(val, VAL_STR_LEN, "%s", gir->city);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                }
                break;

            case GEOIP_ORG_EDITION_V6:
            case GEOIP_ISP_EDITION_V6:
            case GEOIP_ASNUM_EDITION_V6:
                raw_val = GeoIP_name_by_ipnum_v6(gi, gaddr);
                if (raw_val) {
                    g_snprintf(val, VAL_STR_LEN, "%s", raw_val);
                    iso_8859_1_to_utf_8(val);
                    ret = val;
                }
                break;
#endif /* NUM_DB_TYPES */

            case WS_LAT_FAKE_EDITION:
            {
                float lat;
                float lon;
                char *c;
                if(geoip_db_lookup_latlon6(gaddr, &lat, &lon) == 0) {
                    g_snprintf(val, VAL_STR_LEN, "%f", lat);
                    c = strchr(val, ',');
                    if (c != NULL) *c = '.';
                    ret = val;
                }
            }
                break;

            case WS_LON_FAKE_EDITION:
            {
                float lat;
                float lon;
                char *c;
                if(geoip_db_lookup_latlon6(gaddr, &lat, &lon) == 0) {
                    g_snprintf(val, VAL_STR_LEN, "%f", lon);
                    c = strchr(val, ',');
                    if (c != NULL) *c = '.';
                    ret = val;
                }
            }
                break;

            default:
                break;
        }
    }
    if (ret) {
        return ret;
    }
    return not_found;
}

#else /* HAVE_GEOIP_V6 */

const char *
geoip_db_lookup_ipv6(guint dbnum _U_, struct e_in6_addr addr _U_, char *not_found) {
    return not_found;
}

#endif /* HAVE_GEOIP_V6 */

gchar *
geoip_db_get_paths(void) {
    GString* path_str = NULL;
    gchar *path_ret;
    char path_separator;
    guint i;

    path_str = g_string_new("");
#ifdef _WIN32
    path_separator = ';';
#else
    path_separator = ':';
#endif

    for (i = 0; i < num_geoip_db_paths; i++) {
        if (geoip_db_paths[i].path) {
            g_string_append_printf(path_str, "%s%c", geoip_db_paths[i].path, path_separator);
        }
    }

    g_string_truncate(path_str, path_str->len-1);
    path_ret = path_str->str;
    g_string_free(path_str, FALSE);

    return path_ret;
}

#else /* HAVE_GEOIP */
void
geoip_db_init(void) {}

guint
geoip_db_num_dbs(void) {
    return 0;
}

const gchar *
geoip_db_name(guint dbnum _U_) {
    return "Unsupported";
}

int
geoip_db_type(guint dbnum _U_) {
    return -1;
}

const char *
geoip_db_lookup_ipv4(guint dbnum _U_, guint32 addr _U_, char *not_found) {
    return not_found;
}

const char *
geoip_db_lookup_ipv6(guint dbnum _U_, guint32 addr _U_, char *not_found) {
    return not_found;
}

gchar *
geoip_db_get_paths(void) {
    return "";
}

#endif /* HAVE_GEOIP */

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
