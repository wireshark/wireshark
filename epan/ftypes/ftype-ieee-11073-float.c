/* FLOATs as specified by ISO/IEEE Std. 11073-20601-2014
 *
 * Personal Health Devices Transcoding White Paper v1.5
 * https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=272346
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ftypes-int.h>
#include <inttypes.h>
#include <stdio.h>
#include <math.h>
#include <float.h>

#include "strutil.h"

#define DOUBLE_REPR_LENGTH  27

#define SFLOAT_VALUE_INFINITY_PLUS   0x07FE
#define SFLOAT_VALUE_NAN             0x07FF
#define SFLOAT_VALUE_NRES            0x0800
#define SFLOAT_VALUE_RFU             0x0801
#define SFLOAT_VALUE_INFINITY_MINUS  0x0802

#define FLOAT_VALUE_INFINITY_PLUS    0x007FFFFE
#define FLOAT_VALUE_NAN              0x007FFFFF
#define FLOAT_VALUE_NRES             0x00800000
#define FLOAT_VALUE_RFU              0x00800001
#define FLOAT_VALUE_INFINITY_MINUS   0x00800002

static void
sfloat_ieee_11073_fvalue_new(fvalue_t *fv)
{
    fv->value.sfloat_ieee_11073 = 0x0000;
}

static bool
sfloat_ieee_11073_val_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg _U_)
{
    const char    *i_char = s;
    char           c;
    uint8_t        mantissa_sign = 0;
    uint32_t       mantissa = 0;
    int8_t         exponent = 0;
    bool           fraction_mode = false;
    const uint16_t mantissa_max = 0x07FF;

    c = *i_char;

    if (c== '\0')
        return false;

    if (c == '.')
        return false;

    if (c == '-' && s[1] == '.')
        return false;

    if (c == '-' && (s[1] == 'I' || s[1] == 'i')) {
        if (!g_ascii_strcasecmp(s, "-INFINITY")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_INFINITY_MINUS;
            return true;
        }

        return false;
    } else if (c == 'R' || c == 'r') {
        if (!g_ascii_strcasecmp(s, "RFU")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_RFU;
            return true;
        }

        return false;
    } else if (c == 'N' || c == 'n') {
        if (!g_ascii_strcasecmp(s, "NRes")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_NRES;
            return true;
        }

        if (!g_ascii_strcasecmp(s, "NaN")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_NAN;
            return true;
        }

        return false;
    } else if (c == '+') {
        if (!g_ascii_strcasecmp(s, "+INFINITY")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_INFINITY_PLUS;
            return true;
        }

        return false;
    }

    if (c == '-') {
        if (s[1] == '\0')
            return false;

        mantissa_sign = 1;
        i_char += 1;
    }

    while (*i_char == '0') {
        i_char += 1;
    }

    c = *i_char;

    do {
        if (c == '0') {
            if (mantissa * 10 >  (uint32_t) mantissa_max + mantissa_sign) {
                exponent += 1;
                if (exponent > 7)
                    return false;
            } else {
                mantissa *= 10;
            }
        } else if (c == '1') {
            mantissa *= 10;
            mantissa += 1;
        } else if (c == '2') {
            mantissa *= 10;
            mantissa += 2;
        } else if (c == '3') {
            mantissa *= 10;
            mantissa += 3;
        } else if (c == '4') {
            mantissa *= 10;
            mantissa += 4;
        } else if (c == '5') {
            mantissa *= 10;
            mantissa += 5;
        } else if (c == '6') {
            mantissa *= 10;
            mantissa += 6;
        } else if (c == '7') {
            mantissa *= 10;
            mantissa += 7;
        } else if (c == '8') {
            mantissa *= 10;
            mantissa += 8;
        } else if (c == '9') {
            mantissa *= 10;
            mantissa += 9;
        } else if (c == '.') {
            if (fraction_mode)
                return false;
            fraction_mode = true;
            i_char += 1;

            while (*i_char == '0') {
                i_char += 1;
                if (mantissa * 10 <= (uint32_t) mantissa_max + mantissa_sign) {
                    mantissa *= 10;
                    if (exponent > -8 - 4) /* -8 is min exponent; 4 is mantissa size */
                         exponent -= 1;
                }
            }

            i_char -= 1;
        } else if (c != '\0') {
            /* NOTE: Maybe 5e-10, 5e3 notation should be also supported */
            return false;
        }

        if (mantissa > (uint32_t) mantissa_max + mantissa_sign)
            return false;

        if (c != '.' && fraction_mode)
            exponent -= 1;

        i_char += 1;
    } while ((c = *i_char));

    if (mantissa_sign) {
        mantissa = ~(mantissa - 1);
        mantissa &= 0x0FFF;
    }

    /* Transform to normal form */

    if (mantissa == 0)
        exponent = 0;

    while (mantissa > 0 && mantissa % 10 == 0 && exponent < 7) {
        mantissa /= 10;
        exponent += 1;
    }

    if (exponent < -8)
        return false;

    fv->value.sfloat_ieee_11073 = ((exponent & 0x0F) << 12) | mantissa;

    return true;
}

static bool
sfloat_ieee_11073_val_from_uinteger64(fvalue_t *fv, const char *s, uint64_t value _U_, char **err_msg)
{
    return sfloat_ieee_11073_val_from_literal(fv, s, FALSE, err_msg);
}

static bool
sfloat_ieee_11073_val_from_sinteger64(fvalue_t *fv, const char *s, int64_t value _U_, char **err_msg)
{
    return sfloat_ieee_11073_val_from_literal(fv, s, FALSE, err_msg);
}

static bool
sfloat_ieee_11073_val_from_double(fvalue_t *fv, const char *s, double value _U_, char **err_msg)
{
    return sfloat_ieee_11073_val_from_literal(fv, s, FALSE, err_msg);
}

static char *
sfloat_ieee_11073_val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
    int8_t   exponent;
    uint16_t mantissa;
    uint16_t mantissa_sign;
    uint32_t offset = 0;
    char     mantissa_buf[5];
    char    *mantissa_str;
    uint8_t  mantissa_digits;

    /* Predefined: +INFINITY, -INFINITY, RFU, NRes, NaN */
    if (fv->value.sfloat_ieee_11073 >= 0x07FE && fv->value.sfloat_ieee_11073 <= 0x0802) {
        char *s = NULL;

        switch (fv->value.sfloat_ieee_11073) {
        case SFLOAT_VALUE_INFINITY_PLUS:
            s = "+INFINITY";
            break;
        case SFLOAT_VALUE_NAN:
            s = "NaN";
            break;
        case SFLOAT_VALUE_NRES:
            s = "NRes";
            break;
        case SFLOAT_VALUE_RFU:
            s = "RFU";
            break;
        case SFLOAT_VALUE_INFINITY_MINUS:
            s = "-INFINITY";
            break;
        }
        return wmem_strdup(scope, s);
    }

    /* Longest Signed Float Number:    -0.00002048  (11 characters without NULL) */
    /* Longest Signed Float Number     -0.00000001 */
    /* Longest Signed Nonfloat Number: -20480000000 (12 characters without NULL) */
    char buf[13];

    exponent = fv->value.sfloat_ieee_11073 >> 12;
    if (exponent & 0x8)
        exponent |= 0xF0; /* It is signed (4bits), so make it signed in int8_t */
    mantissa = fv->value.sfloat_ieee_11073 & 0x07FF;
    mantissa_sign = (fv->value.sfloat_ieee_11073 & 0x0800);
    if (mantissa_sign)
        mantissa = -((int16_t)mantissa | 0xF800);

    if (mantissa == 0) {
        return wmem_strdup(scope, "0");
    }

    if (mantissa_sign) {
        buf[0] = '-';
        offset += 1;
    }

    mantissa_digits = snprintf(mantissa_buf, sizeof(mantissa_buf), "%"PRIu16, mantissa);
    mantissa_str = mantissa_buf;

    if (exponent == 0) {
        memcpy(buf + offset, mantissa_str, mantissa_digits);
        offset += mantissa_digits;
    } else if (exponent > 0) {
        memcpy(buf + offset, mantissa_str, mantissa_digits);
        offset += mantissa_digits;

        memset(buf + offset, '0', exponent);
        offset += exponent;
    } else /* if (exponent < 0)*/ {
        if (-exponent < mantissa_digits) {
            memcpy(buf + offset, mantissa_str, mantissa_digits + exponent);
            offset += mantissa_digits + exponent;

            buf[offset] = '.';
            offset += 1;

            memcpy(buf + offset, mantissa_str + mantissa_digits + exponent, -exponent);
            offset += -exponent;
        } else {
            buf[offset] = '0';
            offset += 1;

            buf[offset] = '.';
            offset += 1;

            if (-exponent - mantissa_digits > 0) {
                memset(buf + offset, '0', -exponent - mantissa_digits);
                offset += -exponent - mantissa_digits;
            }

            memcpy(buf + offset, mantissa_str, mantissa_digits);
            offset += mantissa_digits;
        }
    }

    buf[offset] = '\0';
    return wmem_strdup(scope, buf);
}

static void
sfloat_ieee_11073_value_set(fvalue_t *fv, uint32_t value)
{
    fv->value.sfloat_ieee_11073 = (uint16_t) value;
}

static uint32_t
sfloat_ieee_11073_value_get(fvalue_t *fv)
{
    return (uint32_t) fv->value.sfloat_ieee_11073;
}

static uint16_t sfloat_to_normal_form(uint16_t value)
{
    int8_t   exponent;
    uint16_t mantissa;
    uint8_t  mantissa_sign;

    if (value >= 0x07FE && value <= 0x0802) /* Save special values */
        return value;

    mantissa = value & 0x07FF;
    if (value & 0x0800) {
        mantissa = -((int16_t)mantissa | 0xF800);
        mantissa_sign = 1;
    } else {
        mantissa_sign = 0;
    }

    exponent = value >> 12;

    if (exponent & 0x08) {
        exponent |= 0xF0;
    }

    while ((!(mantissa % 10)) && mantissa != 0) {
        mantissa /= 10;

        if (exponent == 7)
            break;

        exponent += 1;
    }

    return ((((exponent & 0x80) ? 0x8 : 0x0 ) | (exponent & 0x7)) << 12) | (mantissa_sign << 11) | mantissa;
}

static bool
sfloat_ieee_11073_cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
    return sfloat_to_normal_form(a->value.sfloat_ieee_11073) == sfloat_to_normal_form(b->value.sfloat_ieee_11073);
}

static bool
sfloat_ieee_11073_cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
    uint16_t a_norm;
    uint16_t b_norm;
    int16_t  a_norm_mantissa;
    int16_t  b_norm_mantissa;
    int8_t   a_norm_exponent;
    int8_t   b_norm_exponent;

    a_norm = sfloat_to_normal_form(a->value.sfloat_ieee_11073);
    b_norm = sfloat_to_normal_form(b->value.sfloat_ieee_11073);

    if (a_norm == b_norm)
        return false;

    switch (a_norm) {
    case SFLOAT_VALUE_NAN:
    case SFLOAT_VALUE_NRES:
    case SFLOAT_VALUE_RFU:
    case SFLOAT_VALUE_INFINITY_PLUS:
        return false;
    case SFLOAT_VALUE_INFINITY_MINUS:
        switch (b_norm) {
        case SFLOAT_VALUE_NAN:
        case SFLOAT_VALUE_NRES:
        case SFLOAT_VALUE_RFU:
        case SFLOAT_VALUE_INFINITY_MINUS: /* Dead, informative case */
            return false;
        case SFLOAT_VALUE_INFINITY_PLUS:
        default:
            return true;
        }
    }

    a_norm_mantissa = a_norm & 0x0FFF;
    b_norm_mantissa = b_norm & 0x0FFF;
    if (a_norm & 0x0800)
        a_norm_mantissa |= 0xFFFFF000;

    if (b_norm & 0x0800)
        b_norm_mantissa |= 0xFFFFF000;

    a_norm_exponent = a_norm >> 12;
    b_norm_exponent = b_norm >> 12;

    if (a_norm_exponent & 0x08) {
        a_norm_exponent |= 0xF0;
    }

    if (b_norm_exponent & 0x08) {
        b_norm_exponent |= 0xF0;
    }

    if (a_norm_mantissa == b_norm_mantissa && a_norm_exponent < b_norm_exponent)
        return true;

    if (a_norm_exponent == b_norm_exponent && a_norm_mantissa < b_norm_mantissa)
        return true;

    if (a_norm_exponent < b_norm_exponent) {
        uint8_t exponent_difference;

        exponent_difference = b_norm_exponent - a_norm_exponent;

        if (exponent_difference >= 4)
            return true;

        while (exponent_difference--) {
            b_norm_mantissa *= 10;
        }
    } else {
        uint8_t exponent_difference;

        exponent_difference = a_norm_exponent - b_norm_exponent;

        if (exponent_difference >= 4)
            return false;

        while (exponent_difference--) {
            a_norm_mantissa *= 10;
        }
    }

    if (a_norm_mantissa < b_norm_mantissa)
        return true;

    return false;
}

static enum ft_result
sfloat_ieee_11073_cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
    if (sfloat_ieee_11073_cmp_lt(a, b))
        *cmp = -1;
    else
        *cmp = sfloat_ieee_11073_cmp_eq(a, b) ? 0 : 1;

    return FT_OK;
}

static bool
sfloat_ieee_11073_is_zero(const fvalue_t *a)
{
    return a->value.sfloat_ieee_11073 == 0;
}

static unsigned
sfloat_ieee_11073_hash(const fvalue_t *fv)
{
    int64_t value = fv->value.sfloat_ieee_11073;
    return g_int64_hash(&value);
}

/*============================================================================*/

static void
float_ieee_11073_fvalue_new(fvalue_t *fv)
{
    fv->value.float_ieee_11073 = 0x0000;
}

static bool
float_ieee_11073_val_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg _U_)
{
    const char *i_char = s;
    char          c;
    uint8_t       mantissa_sign = 0;
    uint32_t      mantissa = 0;
    int16_t       exponent = 0;
    bool          fraction_mode = false;
    const uint32_t mantissa_max = 0x007FFFFF;

    c = *i_char;

    if (c== '\0')
        return false;

    if (c == '.')
        return false;

    if (c == '-' && s[1] == '.')
        return false;

    if (c == '-' && (s[1] == 'I' || s[1] == 'i')) {
        if (!g_ascii_strcasecmp(s, "-INFINITY")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_INFINITY_MINUS;
            return true;
        }

        return false;
    } else if (c == 'R' || c == 'r') {
        if (!g_ascii_strcasecmp(s, "RFU")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_RFU;
            return true;
        }

        return false;
    } else if (c == 'N' || c == 'n') {
        if (!g_ascii_strcasecmp(s, "NRes")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_NRES;
            return true;
        }

        if (!g_ascii_strcasecmp(s, "NaN")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_NAN;
            return true;
        }

        return false;
    } else if (c == '+') {
        if (!g_ascii_strcasecmp(s, "+INFINITY")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_INFINITY_PLUS;
            return true;
        }

        return false;
    }

    if (c == '-') {
        if (s[1] == '\0')
            return false;

        mantissa_sign = 1;
        i_char += 1;
    }

    while (*i_char == '0') {
        i_char += 1;
    }

    c = *i_char;

    do {
        if (c == '0') {
            if (mantissa * 10 > mantissa_sign + mantissa_max) {
                exponent += 1;
                if (exponent <= 127)
                    return false;
            } else {
                mantissa *= 10;
            }
        } else if (c == '1') {
            mantissa *= 10;
            mantissa += 1;
        } else if (c == '2') {
            mantissa *= 10;
            mantissa += 2;
        } else if (c == '3') {
            mantissa *= 10;
            mantissa += 3;
        } else if (c == '4') {
            mantissa *= 10;
            mantissa += 4;
        } else if (c == '5') {
            mantissa *= 10;
            mantissa += 5;
        } else if (c == '6') {
            mantissa *= 10;
            mantissa += 6;
        } else if (c == '7') {
            mantissa *= 10;
            mantissa += 7;
        } else if (c == '8') {
            mantissa *= 10;
            mantissa += 8;
        } else if (c == '9') {
            mantissa *= 10;
            mantissa += 9;
        } else if (c == '.') {
            if (fraction_mode)
                return false;
            fraction_mode = true;
            i_char += 1;

            while (*i_char == '0') {
                i_char += 1;
                if (mantissa * 10 <= mantissa_max + mantissa_sign) {
                    mantissa *= 10;
                    if (exponent > -128 - 7) /* -8 is min exponent; 4 is mantissa size */
                         exponent -= 1;
                }
            }

            i_char -= 1;
        } else if (c != '\0') {
            /* NOTE: Maybe 5e-10, 5e3 notation should be also supported */
            return false;
        }

        if (mantissa > mantissa_max + mantissa_sign)
            return false;

        if (c != '.' && fraction_mode)
            exponent -= 1;

        i_char += 1;
    } while ((c = *i_char));

    if (mantissa_sign) {
        mantissa = ~(mantissa - 1);
        mantissa &= 0x00FFFFFF;
    }

    /* Transform to normal form */

    if (mantissa == 0)
        exponent = 0;

    while (mantissa > 0 && mantissa % 10 == 0 && exponent < 127) {
        mantissa /= 10;
        exponent += 1;
    }

    if (exponent < -128)
        return false;

    fv->value.float_ieee_11073 = ((exponent & 0xFF) << 24) | mantissa;

    return true;
}

static bool
float_ieee_11073_val_from_uinteger64(fvalue_t *fv, const char *s, uint64_t value _U_, char **err_msg)
{
    return float_ieee_11073_val_from_literal(fv, s, FALSE, err_msg);
}

static bool
float_ieee_11073_val_from_sinteger64(fvalue_t *fv, const char *s, int64_t value _U_, char **err_msg)
{
    return float_ieee_11073_val_from_literal(fv, s, FALSE, err_msg);
}

static bool
float_ieee_11073_val_from_double(fvalue_t *fv, const char *s, double value _U_, char **err_msg)
{
    return float_ieee_11073_val_from_literal(fv, s, FALSE, err_msg);
}

static char *
float_ieee_11073_val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
    int8_t   exponent;
    uint32_t mantissa;
    uint32_t mantissa_sign;
    uint32_t offset = 0;
    char     mantissa_buf[8];
    char    *mantissa_str;
    uint8_t  mantissa_digits;

    /* Predefined: +INFINITY, -INFINITY, RFU, NRes, NaN */
    if (fv->value.float_ieee_11073 >= 0x007FFFFE && fv->value.float_ieee_11073 <= 0x00800002) {
        char *s = NULL;
        switch (fv->value.float_ieee_11073) {
        case FLOAT_VALUE_INFINITY_PLUS:
            s = "+INFINITY";
            break;
        case FLOAT_VALUE_NAN:
            s = "NaN";
            break;
        case FLOAT_VALUE_NRES:
            s = "NRes";
            break;
        case FLOAT_VALUE_RFU:
            s = "RFU";
            break;
        case FLOAT_VALUE_INFINITY_MINUS:
            s = "-INFINITY";
            break;
        }
        return wmem_strdup(scope, s);
    }

    /* Longest Signed Nonfloat Number: -8388608*(10^-128) (1 character for sign, 7 for mantisa digits, 127 zeros, 1 character for NULL) */
    char buf[136];

    exponent = fv->value.float_ieee_11073 >> 24;

    mantissa = fv->value.float_ieee_11073 & 0x007FFFFF;
    mantissa_sign = (fv->value.float_ieee_11073 & 0x00800000);
    if (mantissa_sign)
        mantissa = (uint32_t)(-((int32_t)(mantissa | 0xFF000000)));

    if (mantissa == 0) {
        return wmem_strdup(scope, "0");
    }

    if (mantissa_sign) {
        buf[0] = '-';
        offset += 1;
    }

    mantissa_digits = snprintf(mantissa_buf, sizeof(mantissa_buf), "%"PRIu32, mantissa);
    mantissa_str = mantissa_buf;

    if (exponent == 0) {
        memcpy(buf + offset, mantissa_str, mantissa_digits);
        offset += mantissa_digits;
    } else if (exponent > 0) {
        memcpy(buf + offset, mantissa_str, mantissa_digits);
        offset += mantissa_digits;

        memset(buf + offset, '0', exponent);
        offset += exponent;
    } else /* if (exponent < 0)*/ {
        if (-exponent < mantissa_digits) {
            memcpy(buf + offset, mantissa_str, mantissa_digits + exponent);
            offset += mantissa_digits + exponent;

            buf[offset] = '.';
            offset += 1;

            memcpy(buf + offset, mantissa_str + mantissa_digits + exponent, -exponent);
            offset += -exponent;
        } else {
            buf[offset] = '0';
            offset += 1;

            buf[offset] = '.';
            offset += 1;

            if (-exponent - mantissa_digits > 0) {
                memset(buf + offset, '0', -exponent - mantissa_digits);
                offset += -exponent - mantissa_digits;
            }

            memcpy(buf + offset, mantissa_str, mantissa_digits);
            offset += mantissa_digits;
        }
    }

    buf[offset] = '\0';
    return wmem_strdup(scope, buf);
}

static void
float_ieee_11073_value_set(fvalue_t *fv, uint32_t value)
{
    fv->value.float_ieee_11073 = value;
}

static uint32_t
float_ieee_11073_value_get(fvalue_t *fv)
{
    return fv->value.float_ieee_11073;
}

static uint32_t float_to_normal_form(uint32_t value)
{
    int8_t   exponent;
    uint16_t mantissa;
    uint8_t  mantissa_sign;

    if (value >= 0x007FFFFE && value <= 0x00800002) /* Save special values */
        return value;

    mantissa = value & 0x907FFFFF;
    if (value & 0x00800000) {
        mantissa = (uint32_t)(-((int32_t)(mantissa | 0xFF000000)));
        mantissa_sign = 1;
    } else {
        mantissa_sign = 0;
    }

    exponent = value >> 24;

    while ((!(mantissa % 10)) && mantissa != 0) {
        mantissa /= 10;

        if (exponent == 127)
            break;

        exponent += 1;
    }

    return (exponent << 24) | (mantissa_sign << 23) | mantissa;
}

static bool
float_ieee_11073_cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
    return float_to_normal_form(a->value.float_ieee_11073) == float_to_normal_form(b->value.float_ieee_11073);
}

static bool
float_ieee_11073_cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
    uint32_t a_norm;
    uint32_t b_norm;
    int32_t a_norm_mantissa;
    int32_t b_norm_mantissa;
    int8_t  a_norm_exponent;
    int8_t  b_norm_exponent;

    a_norm = float_to_normal_form(a->value.float_ieee_11073);
    b_norm = float_to_normal_form(b->value.float_ieee_11073);

    if (a_norm == b_norm)
        return false;

    switch (a_norm) {
    case FLOAT_VALUE_NAN:
    case FLOAT_VALUE_NRES:
    case FLOAT_VALUE_RFU:
    case FLOAT_VALUE_INFINITY_PLUS:
        return false;
    case FLOAT_VALUE_INFINITY_MINUS:
        switch (b_norm) {
        case FLOAT_VALUE_NAN:
        case FLOAT_VALUE_NRES:
        case FLOAT_VALUE_RFU:
        case FLOAT_VALUE_INFINITY_MINUS: /* Dead, informative case */
            return false;
        case FLOAT_VALUE_INFINITY_PLUS:
        default:
            return true;
        }
    }

    a_norm_mantissa = a_norm & 0x00FFFFFF;
    b_norm_mantissa = b_norm & 0x00FFFFFF;
    if (a_norm & 0x00800000)
        a_norm_mantissa |= 0xFF000000;

    if (b_norm & 0x00800000)
        b_norm_mantissa |= 0xFF000000;

    a_norm_exponent = a_norm >> 24;
    b_norm_exponent = b_norm >> 24;

    if (a_norm_mantissa == b_norm_mantissa && a_norm_exponent < b_norm_exponent)
        return true;

    if (a_norm_exponent == b_norm_exponent && a_norm_mantissa < b_norm_mantissa)
        return true;

    if (a_norm_exponent < b_norm_exponent) {
        uint8_t exponent_difference;

        exponent_difference = b_norm_exponent - a_norm_exponent;

        if (exponent_difference >= 7)
            return true;

        while (exponent_difference--) {
            b_norm_mantissa *= 10;
        }
    } else {
        uint8_t exponent_difference;

        exponent_difference = a_norm_exponent - b_norm_exponent;

        if (exponent_difference >= 7)
            return false;

        while (exponent_difference--) {
            a_norm_mantissa *= 10;
        }
    }

    if (a_norm_mantissa < b_norm_mantissa)
        return true;

    return false;
}

static enum ft_result
float_ieee_11073_cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
    if (float_ieee_11073_cmp_lt(a, b))
        *cmp = -1;
    else
        *cmp = float_ieee_11073_cmp_eq(a, b) ? 0 : 1;

    return FT_OK;
}

static bool
float_ieee_11073_is_zero(const fvalue_t *a)
{
    return a->value.float_ieee_11073 == 0;
}

static unsigned
float_ieee_11073_hash(const fvalue_t *fv)
{
    int64_t value = fv->value.float_ieee_11073;
    return g_int64_hash(&value);
}

/*============================================================================*/

void
ftype_register_ieee_11073_float(void)
{
/*
Size: 16bits = 2 octets

Exponent: 4 bits  (signed integer - 2's complement)
Mantissa: 12 bits (signed integer - 2's complement)
Base: 10

x = M * (10 ^ E)

Exponent range: from -8 to 7
Mantissa range: from -2048 to 2047  (4 digits)

Special values:
    + INFINITY [exponent 0, mantissa +(2^11 -2) = 0x07FE]
    NaN (Not a Number) [exponent 0, mantissa +(2^11 -1) = 0x07FF]
    NRes (Not at this Resolution) [exponent 0, mantissa -(2^11) = 0x0800]
    Reserved for future use [exponent 0, mantissa -(2^11 -1) = 0x0801]
    - INFINITY [exponent 0, mantissa -(2^11 -2) = 0x0802]

Note:
be carefour when comparing: 1e == 10e-1 == 10e-2 == ... (solution: compare only if the lowest mantissa % 10 != 0)

Example: 114 is 0x0072

*/
    static const ftype_t sfloat_type = {
        FT_IEEE_11073_SFLOAT,                 /* ftype */
        2,                                    /* wire_size */

        sfloat_ieee_11073_fvalue_new,         /* new_value */
        NULL,                                 /* copy_value */
        NULL,                                 /* free_value */
        sfloat_ieee_11073_val_from_literal,   /* val_from_literal */
        NULL,                                 /* val_from_string */
        NULL,                                 /* val_from_charconst */
        sfloat_ieee_11073_val_from_uinteger64, /* val_from_uinteger64 */
        sfloat_ieee_11073_val_from_sinteger64, /* val_from_sinteger64 */
        sfloat_ieee_11073_val_from_double,    /* val_from_double */
        sfloat_ieee_11073_val_to_repr,        /* val_to_string_repr */

        NULL,                                 /* val_to_uinteger64 */
        NULL,                                 /* val_to_sinteger64 */
        NULL,                                 /* val_to_double */

        { .set_value_uinteger = sfloat_ieee_11073_value_set }, /* union set_value */
        { .get_value_uinteger = sfloat_ieee_11073_value_get }, /* union get_value */

        sfloat_ieee_11073_cmp_order,
        NULL,                                 /* cmp_contains */
        NULL,                                 /* cmp_matches */

        sfloat_ieee_11073_hash,               /* hash */
        sfloat_ieee_11073_is_zero,            /* is_zero */
        NULL,                                 /* is_negative */
        NULL,                                 /* len */
        NULL,                                 /* slice */
        NULL,                                 /* bitwise_and */
        NULL,                                 /* unary_minus */
        NULL,                                 /* add */
        NULL,                                 /* subtract */
        NULL,                                 /* multiply */
        NULL,                                 /* divide */
        NULL,                                 /* modulo */
    };

/*
Size: 32bits = 4 octets

Exponent: 1 octet  (signed integer - 2's complement)
Mantissa: 3 octets (signed integer - 2's complement)
Base: 10

x = M * (10 ^ E)

Exponent range: from -128 to 127
Mantissa range: from -8388608 to 8388607  (7 digits)

Special values:
    + INFINITY [exponent 0, mantissa +(2^23 -2) = 0x007FFFFE]
    NaN (Not a Number) [exponent 0, mantissa +(2^23 -1) = 0x007FFFFF]
    NRes (Not at this Resolution) [exponent 0, mantissa -(2^23) = 0x00800000]
    Reserved for future use [exponent 0, mantissa -(2^23-1) = 0x00800001]
    - INFINITY [exponent 0, mantissa -(2^23 -2) = 0x00800002]

Note:
be carefour when comparing: 1e == 10e-1 == 10e-2 == ... (solution: compare only if the lowest mantissa % 10 != 0)

Example: 36.4 is 0xFF00016C

*/

    static const ftype_t float_type = {
        FT_IEEE_11073_FLOAT,                  /* ftype */
        4,                                    /* wire_size */

        float_ieee_11073_fvalue_new,         /* new_value */
        NULL,                                /* copy_value */
        NULL,                                /* free_value */
        float_ieee_11073_val_from_literal,   /* val_from_literal */
        NULL,                                /* val_from_string */
        NULL,                                /* val_from_charconst */
        float_ieee_11073_val_from_uinteger64, /* val_from_uinteger64 */
        float_ieee_11073_val_from_sinteger64, /* val_from_sinteger64 */
        float_ieee_11073_val_from_double,    /* val_from_double */
        float_ieee_11073_val_to_repr,        /* val_to_string_repr */

        NULL,                                 /* val_to_uinteger64 */
        NULL,                                 /* val_to_sinteger64 */
        NULL,                                 /* val_to_double */

        { .set_value_uinteger = float_ieee_11073_value_set }, /* union set_value */
        { .get_value_uinteger = float_ieee_11073_value_get }, /* union get_value */

        float_ieee_11073_cmp_order,
        NULL,                                /* cmp_contains */
        NULL,                                /* cmp_matches */

        float_ieee_11073_hash,               /* hash */
        float_ieee_11073_is_zero,            /* is_zero */
        NULL,                                /* is_negative */
        NULL,                                /* len */
        NULL,                                /* slice */
        NULL,                                /* bitwise_and */
        NULL,                                /* unary_minus */
        NULL,                                /* add */
        NULL,                                /* subtract */
        NULL,                                /* multiply */
        NULL,                                /* divide */
        NULL,                                /* modulo */
    };

    ftype_register(FT_IEEE_11073_SFLOAT, &sfloat_type);
    ftype_register(FT_IEEE_11073_FLOAT, &float_type);
}

void
ftype_register_pseudofields_ieee_11073_float(int proto)
{
    static int hf_ft_ieee_11073_sfloat;
    static int hf_ft_ieee_11073_float;

    static hf_register_info hf_ftypes[] = {
        { &hf_ft_ieee_11073_sfloat,
            { "FT_IEEE_11073_SFLOAT", "_ws.ftypes.ieee_11073_sfloat",
                FT_IEEE_11073_SFLOAT, BASE_NONE, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_ft_ieee_11073_float,
                { "FT_IEEE_11073_FLOAT", "_ws.ftypes.ieee_11073_float",
                    FT_IEEE_11073_FLOAT, BASE_NONE, NULL, 0x00,
                    NULL, HFILL }
            },
    };

    proto_register_field_array(proto, hf_ftypes, array_length(hf_ftypes));
}

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
