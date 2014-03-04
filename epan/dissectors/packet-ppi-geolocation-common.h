/* packet-ppi-geolocation-common.h
 * Routines for PPI-GEOLOCATION  dissection
 * Copyright 2010, Harris Corp, jellch@harris.com
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

#ifndef __PPI_GEOLOCATION_COMMON_H
#define __PPI_GEOLOCATION_COMMON_H

/*
 * Declarations from shared PPI-GEOLOCATION functions.
 *
 */

/*
 * these constants are offsets into base_geotag header, which is bitwise-compatible
 * with a radiotap header
 */
#define PPI_GEOBASE_MIN_HEADER_LEN  8   /* minimum header length */
#define PPI_GEOBASE_VERSION_OFFSET  0   /* offset of version field */
#define PPI_GEOBASE_LENGTH_OFFSET   2   /* offset of length field */
#define PPI_GEOBASE_PRESENT_OFFSET  4   /* offset of "present" field */
/*
 * These BITNO macros were accquired from the radiotap parser. maybe we can share them
 * eventually
 */
#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)  (1 << n)



/*
 * Floating point numbers are stored on disk in a handful of fixed-point formats (fixedX_Y)
 * designed to preserve the appropriate amount of precision vs range. These functions convert
 * the fixedX_Y fixed point values into 'native' gdoubles for displaying.
 * Documentation on these formats can be found in the PPI-GEOLOCATION specification
 */
gdouble ppi_fixed3_7_to_gdouble(guint32 in);
gdouble ppi_fixed3_6_to_gdouble(guint32 in);
gdouble ppi_fixed6_4_to_gdouble(guint32 in);
/*
 * Some values are encoded as 32-bit unsigned nano-second counters.
 * Usually we want to display these values as doubles.
 */
gdouble ppi_ns_counter_to_gdouble(guint32 in);


typedef enum {
    PPI_GEOLOCATION_HARRIS   =  0x00485253 /* 00SRH */
} ppi_geolocation_appstr_num;


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


