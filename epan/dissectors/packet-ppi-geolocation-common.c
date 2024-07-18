/* packet-ppi-geolocation-common.c
 * Routines for PPI-GEOLOCATION  dissection
 * Copyright 2010, Harris Corp, jellch@harris.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include "packet-ppi-geolocation-common.h"

/*
 * input: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 * output: a signed floating point value between -180.0000000 and + 180.0000000, inclusive)
 */
double ppi_fixed3_7_to_gdouble(guint32 in) {
    gint32 remapped_in = in - (180 * 10000000);
    double ret = (double) ((double) remapped_in / 10000000);
    return ret;
}
/*
 * input: a native 32 bit unsigned value between 0 and 999999999
 * output: a positive floating point value between 000.0000000 and 999.9999999
 */

double ppi_fixed3_6_to_gdouble(guint32 in) {
    double ret = (double) in  / 1000000.0;
    return ret;

}
/*
 * input: a native 32 bit unsigned value between 0 and 3600000000
 * output: a signed floating point value between -180000.0000 and +180000.0000
 */
double ppi_fixed6_4_to_gdouble(guint32 in) {
    gint32 remapped_in = in - (180000 * 10000);
    double ret = (double) ((double) remapped_in / 10000);
    return ret;
}

double ppi_ns_counter_to_gdouble(guint32 in) {
    double ret;
    ret = (double) in / 1000000000;
    return ret;
}

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
