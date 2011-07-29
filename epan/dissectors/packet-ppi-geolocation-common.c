/* packet-ppi-geolocation-common.c
 * Routines for PPI-GEOLOCATION  dissection
 * Copyright 2010, Harris Corp, jellch@harris.com
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>
#include "packet-ppi-geolocation-common.h"

/*
 * input: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 * output: a signed floating point value betwen -180.0000000 and + 180.0000000, inclusive)
 */
gdouble ppi_fixed3_7_to_gdouble(guint32 in) {
    gint32 remapped_in = in - (180 * 10000000);
    gdouble ret = (gdouble) ((gdouble) remapped_in / 10000000);
    return ret;
}
/*
 * input: a native 32 bit unsigned value between 0 and 999999999
 * output: a positive floating point value between 000.0000000 and 999.9999999
 */

gdouble ppi_fixed3_6_to_gdouble(guint32 in) {
    gdouble ret = (gdouble) in  / 1000000.0;
    return ret;

}
/*
 * input: a native 32 bit unsigned value between 0 and 3600000000
 * output: a signed floating point value between -180000.0000 and +180000.0000
 */
gdouble ppi_fixed6_4_to_gdouble(guint32 in) {
    gint32 remapped_in = in - (180000 * 10000);
    gdouble ret = (gdouble) ((gdouble) remapped_in / 10000);
    return ret;
}

gdouble ppi_ns_counter_to_gdouble(guint32 in) {
    gdouble ret;
    ret = (gdouble) in / 1000000000;
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
 * ex: set shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */
