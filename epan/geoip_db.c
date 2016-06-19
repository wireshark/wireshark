/* geoip_db.c
 * GeoIP database support
 *
 * Copyright 2008, Gerald Combs <gerald@wireshark.org>
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

/* To do:
 * We currently return a single string for each database. Some databases,
 * e.g. GeoIPCity, can return other info such as area codes.
 */

#include "config.h"

#include <glib.h>

#include <epan/wmem/wmem.h>

#ifdef HAVE_GEOIP
#include <GeoIP.h>
#include <GeoIPCity.h>

#include <epan/geoip_db.h>
#include <epan/uat.h>
#include <epan/prefs.h>
#include <epan/value_string.h>

#include <wsutil/report_err.h>
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
    const geoip_db_path_t *m = (const geoip_db_path_t *)orig;
    geoip_db_path_t *d = (geoip_db_path_t *)dest;

    d->path = g_strdup(m->path);

    return d;
}

static void geoip_db_path_free_cb(void* p) {
    geoip_db_path_t *m = (geoip_db_path_t *)p;
    g_free(m->path);
}

/* called every time the user presses "Apply" or "OK in the list of
 * GeoIP directories, and also once on startup */
static void geoip_db_post_update_cb(void) {
    GeoIP *gi;
    guint i;

    /* If we have old data, clear out the whole thing
     * and start again. TODO: Just update the ones that
     * have changed for efficiency's sake. */
    if (geoip_dat_arr) {
        /* skip the last two, as they are fake */
        for (i = 0; i < geoip_db_num_dbs() - 2; i++) {
            gi = g_array_index(geoip_dat_arr, GeoIP *, i);
            if (gi) {
                GeoIP_delete(gi);
            }
        }
        /* don't use GeoIP_delete() on the two fake
         * databases as they weren't created by GeoIP_new()
         * or GeoIP_open() */
        gi = g_array_index(geoip_dat_arr, GeoIP *, i);
        if (gi) {
            g_free(gi);
        }
        gi = g_array_index(geoip_dat_arr, GeoIP *, i+1);
        if (gi) {
            g_free(gi);
        }
        /* finally, free the array itself */
        g_array_free(geoip_dat_arr, TRUE);
    }

    /* allocate the array */
    geoip_dat_arr = g_array_new(FALSE, FALSE, sizeof(GeoIP *));

    /* Walk all the directories */
    for (i = 0; i < num_geoip_db_paths; i++) {
        if (geoip_db_paths[i].path) {
            geoip_dat_scan_dir(geoip_db_paths[i].path);
        }
    }

    /* add fake databases for latitude and longitude
     * (using "City" in reality) */

    /* latitude */
    gi = (GeoIP *)g_malloc(sizeof (GeoIP));
    gi->databaseType = WS_LAT_FAKE_EDITION;
    g_array_append_val(geoip_dat_arr, gi);

    /* longitude */
    gi = (GeoIP *)g_malloc(sizeof (GeoIP));
    gi->databaseType = WS_LON_FAKE_EDITION;
    g_array_append_val(geoip_dat_arr, gi);
}

/**
 * Initialize GeoIP lookups
 */
void
geoip_db_pref_init(module_t *nameres)
{
    static uat_field_t geoip_db_paths_fields[] = {
        UAT_FLD_DIRECTORYNAME(geoip_mod, path, "GeoIP Database Directory", "The GeoIP database directory path"),
        UAT_END_FIELDS
    };

    geoip_db_paths_uat = uat_new("GeoIP Database Paths",
            sizeof(geoip_db_path_t),
            "geoip_db_paths",
            FALSE,
            (void**)&geoip_db_paths,
            &num_geoip_db_paths,
            /* affects dissection of packets (as the GeoIP database is
               used when dissecting), but not set of named fields */
            UAT_AFFECTS_DISSECTION,
            "ChGeoIPDbPaths",
            geoip_db_path_copy_cb,
            NULL,
            geoip_db_path_free_cb,
            geoip_db_post_update_cb,
            geoip_db_paths_fields);

    prefs_register_uat_preference(nameres,
            "geoip_db_paths",
            "GeoIP database directories",
                "Search paths for GeoIP address mapping databases.\n"
                "Wireshark will look in each directory for files beginning\n"
                "with \"Geo\" and ending with \".dat\".",
            geoip_db_paths_uat);
}

guint
geoip_db_num_dbs(void) {
    return (geoip_dat_arr == NULL) ? 0 : geoip_dat_arr->len;
}

const gchar *
geoip_db_name(guint dbnum) {
    GeoIP *gi;

    gi = g_array_index(geoip_dat_arr, GeoIP *, dbnum);
    if (gi) {
        return (val_to_str_const(gi->databaseType, geoip_type_name_vals, "Unknown database"));
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

/*
 * GeoIP 1.4.3 and later provide GeoIP_set_charset(), but in versions
 * 1.4.3 to 1.4.6 that only applies to the City databases. I.e., it's
 * possible to produce invalid UTF-8 sequences even if GeoIP_set_charset()
 * is used.
 */

/* Ensure that a given db value is UTF-8 */
static char *
db_val_to_utf_8(const char *val, GeoIP *gi) {

    if (GeoIP_charset(gi) == GEOIP_CHARSET_ISO_8859_1) {
        char *utf8_val;
        utf8_val = g_convert(val, -1, "UTF-8", "ISO-8859-1", NULL, NULL, NULL);
        if (utf8_val) {
            char *ret_val = wmem_strdup(NULL, utf8_val);
            g_free(utf8_val);
            return ret_val;
        }
    }
    return wmem_strdup(NULL, val);
}

char *
geoip_db_lookup_ipv4(guint dbnum, guint32 addr, const char *not_found) {
    GeoIP *gi;
    GeoIPRecord *gir;
    const char *raw_val;
    char *val, *ret = NULL;

    if (dbnum > geoip_db_num_dbs()) {
        if (not_found == NULL)
            return NULL;

        return wmem_strdup(NULL, not_found);
    }
    gi = g_array_index(geoip_dat_arr, GeoIP *, dbnum);
    if (gi) {
        switch (gi->databaseType) {
            case GEOIP_COUNTRY_EDITION:
                raw_val = GeoIP_country_name_by_ipnum(gi, addr);
                if (raw_val) {
                    ret = db_val_to_utf_8(raw_val, gi);
                }
                break;

            case GEOIP_CITY_EDITION_REV0:
            case GEOIP_CITY_EDITION_REV1:
                gir = GeoIP_record_by_ipnum(gi, addr);
                if (gir && gir->city && gir->region) {
                    val = wmem_strdup_printf(NULL, "%s, %s", gir->city, gir->region);
                    ret = db_val_to_utf_8(val, gi);
                    wmem_free(NULL, val);
                } else if (gir && gir->city) {
                    ret = db_val_to_utf_8(gir->city, gi);
                }
                break;

            case GEOIP_ORG_EDITION:
            case GEOIP_ISP_EDITION:
            case GEOIP_ASNUM_EDITION:
                raw_val = GeoIP_name_by_ipnum(gi, addr);
                if (raw_val) {
                    ret = db_val_to_utf_8(raw_val, gi);
                }
                break;

            case WS_LAT_FAKE_EDITION:
            {
                float lat;
                float lon;
                char *c;
                if(geoip_db_lookup_latlon4(addr, &lat, &lon) == 0) {
                    val = wmem_strdup_printf(NULL, "%f", lat);
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
                    val = wmem_strdup_printf(NULL, "%f", lon);
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

    if (ret == NULL) {
        if (not_found == NULL)
            return NULL;

        return wmem_strdup(NULL, not_found);
    }

    return ret;
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

char *
geoip_db_lookup_ipv6(guint dbnum, struct e_in6_addr addr, const char *not_found) {
    GeoIP *gi;
    geoipv6_t gaddr;
    const char *raw_val;
    char *val, *ret = NULL;
#if NUM_DB_TYPES > 31
    GeoIPRecord *gir;
#endif
    if (dbnum > geoip_db_num_dbs()) {
        if (not_found == NULL)
            return NULL;

        return wmem_strdup(NULL, not_found);
    }

    memcpy(&gaddr, &addr, sizeof(addr));

    gi = g_array_index(geoip_dat_arr, GeoIP *, dbnum);
    if (gi) {
        switch (gi->databaseType) {
            case GEOIP_COUNTRY_EDITION_V6:
                raw_val = GeoIP_country_name_by_ipnum_v6(gi, gaddr);
                if (raw_val) {
                    ret = db_val_to_utf_8(raw_val, gi);
                }
                break;

#if NUM_DB_TYPES > 31
            case GEOIP_CITY_EDITION_REV0_V6:
            case GEOIP_CITY_EDITION_REV1_V6:
                gir = GeoIP_record_by_ipnum_v6(gi, gaddr);
                if (gir && gir->city && gir->region) {
                    val = wmem_strdup_printf(NULL, "%s, %s", gir->city, gir->region);
                    ret = db_val_to_utf_8(val, gi);
                    wmem_free(NULL, val);
                } else if (gir && gir->city) {
                    ret = db_val_to_utf_8(gir->city, gi);
                }
                break;

            case GEOIP_ORG_EDITION_V6:
            case GEOIP_ISP_EDITION_V6:
            case GEOIP_ASNUM_EDITION_V6:
                raw_val = GeoIP_name_by_ipnum_v6(gi, gaddr);
                if (raw_val) {
                    ret = db_val_to_utf_8(raw_val, gi);
                }
                break;
#endif /* NUM_DB_TYPES */

            case WS_LAT_FAKE_EDITION:
            {
                float lat;
                float lon;
                char *c;
                if(geoip_db_lookup_latlon6(gaddr, &lat, &lon) == 0) {
                    val = wmem_strdup_printf(NULL, "%f", lat);
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
                    val = wmem_strdup_printf(NULL, "%f", lon);
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

    if (ret == NULL) {
        if (not_found == NULL)
            return NULL;

        return wmem_strdup(NULL, not_found);
    }

    return ret;
}

#else /* HAVE_GEOIP_V6 */

char *
geoip_db_lookup_ipv6(guint dbnum _U_, struct e_in6_addr addr _U_, const char *not_found) {
    if (not_found == NULL)
        return NULL;

    return wmem_strdup(NULL, not_found);
}

#endif /* HAVE_GEOIP_V6 */

gchar *
geoip_db_get_paths(void) {
    GString* path_str = NULL;
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

    return g_string_free(path_str, FALSE);
}

#else /* HAVE_GEOIP */
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

char *
geoip_db_lookup_ipv4(guint dbnum _U_, guint32 addr _U_, const char *not_found) {
    if (not_found == NULL)
        return NULL;

    return (char *)wmem_strdup(NULL, not_found);
}

char *
geoip_db_lookup_ipv6(guint dbnum _U_, guint32 addr _U_, const char *not_found) {
    if (not_found == NULL)
        return NULL;

    return (char *)wmem_strdup(NULL, not_found);
}

gchar *
geoip_db_get_paths(void) {
    return g_strdup("");
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
