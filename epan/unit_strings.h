/* unit_strings.h
 * Units to append to field values
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UNIT_STRINGS_H__
#define __UNIT_STRINGS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Units to append to field values
 */

/** For BASE_UNIT_STRING, the display format for adding units */
typedef struct unit_name_string {
    char *singular;     /**< name to use for 1 unit */
    char *plural;       /**< name to use for < 1 or > 1 units */
} unit_name_string;

/** Returns the unit string appropriate for the 32 bit value.
 *
 * From the given unit_name_string return the appropriate string pointer
 * @param[in] value The value for which to get the appropriate string
 * @param[in] units The unit_name_string containing the relevant strings
 * @return          Pointer to the appropriate string
 */
WS_DLL_PUBLIC const char* unit_name_string_get_value(guint32 value, const unit_name_string* units);

/** Returns the unit string appropriate for the 64 bit value.
 *
 * From the given unit_name_string return the appropriate string pointer
 * @param[in] value The value for which to get the appropriate string
 * @param[in] units The unit_name_string containing the relevant strings
 * @return          Pointer to the appropriate string
 */
WS_DLL_PUBLIC const char* unit_name_string_get_value64(guint64 value, const unit_name_string* units);

/** Returns the unit string appropriate for the double value.
 *
 * From the given unit_name_string return the appropriate string pointer
 * @param[in] value The value for which to get the appropriate string
 * @param[in] units The unit_name_string containing the relevant strings
 * @return          Pointer to the appropriate string
 */
WS_DLL_PUBLIC const char* unit_name_string_get_double(double value, const unit_name_string* units);

/*
 * A default set of unit strings that dissectors can use for
 * header fields.
 */
WS_DLL_PUBLIC const unit_name_string units_foot_feet;
WS_DLL_PUBLIC const unit_name_string units_bit_bits;
WS_DLL_PUBLIC const unit_name_string units_byte_bytes;
WS_DLL_PUBLIC const unit_name_string units_byte_bytespsecond;
WS_DLL_PUBLIC const unit_name_string units_octet_octets;
WS_DLL_PUBLIC const unit_name_string units_word_words;
WS_DLL_PUBLIC const unit_name_string units_tick_ticks;
WS_DLL_PUBLIC const unit_name_string units_meters;
WS_DLL_PUBLIC const unit_name_string units_meter_meters;
WS_DLL_PUBLIC const unit_name_string units_week_weeks;
WS_DLL_PUBLIC const unit_name_string units_day_days;
WS_DLL_PUBLIC const unit_name_string units_hour_hours;
WS_DLL_PUBLIC const unit_name_string units_hours;
WS_DLL_PUBLIC const unit_name_string units_minute_minutes;
WS_DLL_PUBLIC const unit_name_string units_minutes;
WS_DLL_PUBLIC const unit_name_string units_second_seconds; // full unit name "second[s?]"
WS_DLL_PUBLIC const unit_name_string units_seconds;        //only seconds abbreviation "s"
WS_DLL_PUBLIC const unit_name_string units_millisecond_milliseconds; // full unit name "millisecond[s?]"
WS_DLL_PUBLIC const unit_name_string units_milliseconds;        //only seconds abbreviation "ms"
WS_DLL_PUBLIC const unit_name_string units_microsecond_microseconds; // full unit name "microsecond[s?]"
WS_DLL_PUBLIC const unit_name_string units_microseconds;        //only seconds abbreviation "us"
WS_DLL_PUBLIC const unit_name_string units_nanosecond_nanoseconds; // full unit name "nanosecond[s?]"
WS_DLL_PUBLIC const unit_name_string units_nanoseconds; //only seconds abbreviation "ns"
WS_DLL_PUBLIC const unit_name_string units_nanometers;
WS_DLL_PUBLIC const unit_name_string units_degree_degrees;
WS_DLL_PUBLIC const unit_name_string units_degree_celsius;
WS_DLL_PUBLIC const unit_name_string units_degree_bearing;
WS_DLL_PUBLIC const unit_name_string units_centibels;
WS_DLL_PUBLIC const unit_name_string units_decibels;
WS_DLL_PUBLIC const unit_name_string units_dbm;
WS_DLL_PUBLIC const unit_name_string units_dbi;
WS_DLL_PUBLIC const unit_name_string units_mbm;
WS_DLL_PUBLIC const unit_name_string units_percent;
WS_DLL_PUBLIC const unit_name_string units_khz;
WS_DLL_PUBLIC const unit_name_string units_ghz;
WS_DLL_PUBLIC const unit_name_string units_mhz;
WS_DLL_PUBLIC const unit_name_string units_hz;
WS_DLL_PUBLIC const unit_name_string units_hz_s;
WS_DLL_PUBLIC const unit_name_string units_kbit;
WS_DLL_PUBLIC const unit_name_string units_kbps;
WS_DLL_PUBLIC const unit_name_string units_kibps;
WS_DLL_PUBLIC const unit_name_string units_pkts;
WS_DLL_PUBLIC const unit_name_string units_pkts_per_sec;
WS_DLL_PUBLIC const unit_name_string units_km;
WS_DLL_PUBLIC const unit_name_string units_kmh;
WS_DLL_PUBLIC const unit_name_string units_milliamps;
WS_DLL_PUBLIC const unit_name_string units_microwatts;
WS_DLL_PUBLIC const unit_name_string units_volt;
WS_DLL_PUBLIC const unit_name_string units_grams_per_second;
WS_DLL_PUBLIC const unit_name_string units_meter_sec;
WS_DLL_PUBLIC const unit_name_string units_meter_sec_squared;
WS_DLL_PUBLIC const unit_name_string units_bit_sec;
WS_DLL_PUBLIC const unit_name_string units_segment_remaining;
WS_DLL_PUBLIC const unit_name_string units_frame_frames;
WS_DLL_PUBLIC const unit_name_string units_revolutions_per_minute;
WS_DLL_PUBLIC const unit_name_string units_kilopascal;
WS_DLL_PUBLIC const unit_name_string units_newton_metre;
WS_DLL_PUBLIC const unit_name_string units_liter_per_hour;
WS_DLL_PUBLIC const unit_name_string units_amp;
WS_DLL_PUBLIC const unit_name_string units_watthour;
WS_DLL_PUBLIC const unit_name_string units_watt;
WS_DLL_PUBLIC const unit_name_string units_bpm;
WS_DLL_PUBLIC const unit_name_string units_calorie;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UNIT_STRINGS_H__ */

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
