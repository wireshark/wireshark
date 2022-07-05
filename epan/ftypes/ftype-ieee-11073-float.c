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
#include <errno.h>
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

static gboolean
sfloat_ieee_11073_val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg _U_)
{
    const char *i_char = s;
    char          c;
    guint8        mantissa_sign = 0;
    guint32       mantissa = 0;
    gint8         exponent = 0;
    gboolean      fraction_mode = FALSE;
    const guint16 mantissa_max = 0x07FF;

    c = *i_char;

    if (c== '\0')
        return FALSE;

    if (c == '.')
        return FALSE;

    if (c == '-' && s[1] == '.')
        return FALSE;

    if (c == '-' && (s[1] == 'I' || s[1] == 'i')) {
        if (!g_ascii_strcasecmp(s, "-INFINITY")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_INFINITY_MINUS;
            return TRUE;
        }

        return FALSE;
    } else if (c == 'R' || c == 'r') {
        if (!g_ascii_strcasecmp(s, "RFU")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_RFU;
            return TRUE;
        }

        return FALSE;
    } else if (c == 'N' || c == 'n') {
        if (!g_ascii_strcasecmp(s, "NRes")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_NRES;
            return TRUE;
        }

        if (!g_ascii_strcasecmp(s, "NaN")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_NAN;
            return TRUE;
        }

        return FALSE;
    } else if (c == '+') {
        if (!g_ascii_strcasecmp(s, "+INFINITY")) {
            fv->value.sfloat_ieee_11073 = SFLOAT_VALUE_INFINITY_PLUS;
            return TRUE;
        }

        return FALSE;
    }

    if (c == '-') {
        if (s[1] == '\0')
            return FALSE;

        mantissa_sign = 1;
        i_char += 1;
    }

    while (*i_char == '0') {
        i_char += 1;
    }

    c = *i_char;

    do {
        if (c == '0') {
            if (mantissa * 10 >  (guint32) mantissa_max + mantissa_sign) {
                exponent += 1;
                if (exponent > 7)
                    return FALSE;
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
                return FALSE;
            fraction_mode = TRUE;
            i_char += 1;

            while (*i_char == '0') {
                i_char += 1;
                if (mantissa * 10 <= (guint32) mantissa_max + mantissa_sign) {
                    mantissa *= 10;
                    if (exponent > -8 - 4) /* -8 is min exponent; 4 is mantissa size */
                         exponent -= 1;
                }
            }

            i_char -= 1;
        } else if (c != '\0') {
            /* NOTE: Maybe 5e-10, 5e3 notation should be also supported */
            return FALSE;
        }

        if (mantissa > (guint32) mantissa_max + mantissa_sign)
            return FALSE;

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
        return FALSE;

    fv->value.sfloat_ieee_11073 = ((exponent & 0x0F) << 12) | mantissa;

    return TRUE;
}

static char *
sfloat_ieee_11073_val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
    gint8    exponent;
    uint16_t mantissa;
    guint16  mantissa_sign;
    guint32  offset = 0;
    char     mantissa_buf[5];
    char    *mantissa_str;
    guint8   mantissa_digits;

    /* Predefinied: +INFINITY, -INFINITY, RFU, NRes, NaN */
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
        exponent |= 0xF0; /* It is signed (4bits), so make it signed in gint8 */
    mantissa = fv->value.sfloat_ieee_11073 & 0x07FF;
    mantissa_sign = (fv->value.sfloat_ieee_11073 & 0x0800);
    if (mantissa_sign)
        mantissa = -((gint16)mantissa | 0xF800);

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
sfloat_ieee_11073_value_set(fvalue_t *fv, guint32 value)
{
    fv->value.sfloat_ieee_11073 = (guint16) value;
}

static guint32
sfloat_ieee_11073_value_get(fvalue_t *fv)
{
    return (guint32) fv->value.sfloat_ieee_11073;
}

static guint16 sfloat_to_normal_form(guint16 value)
{
    gint8    exponent;
    guint16  mantissa;
    guint8   mantissa_sign;

    if (value >= 0x07FE && value <= 0x0802) /* Save special values */
        return value;

    mantissa = value & 0x07FF;
    if (value & 0x0800) {
        mantissa = -((gint16)mantissa | 0xF800);
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

static gboolean
sfloat_ieee_11073_cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
    return sfloat_to_normal_form(a->value.sfloat_ieee_11073) == sfloat_to_normal_form(b->value.sfloat_ieee_11073);
}

static gboolean
sfloat_ieee_11073_cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
    guint16 a_norm;
    guint16 b_norm;
    gint16  a_norm_mantissa;
    gint16  b_norm_mantissa;
    gint8   a_norm_exponent;
    gint8   b_norm_exponent;

    a_norm = sfloat_to_normal_form(a->value.sfloat_ieee_11073);
    b_norm = sfloat_to_normal_form(b->value.sfloat_ieee_11073);

    if (a_norm == b_norm)
        return FALSE;

    switch (a_norm) {
    case SFLOAT_VALUE_NAN:
    case SFLOAT_VALUE_NRES:
    case SFLOAT_VALUE_RFU:
    case SFLOAT_VALUE_INFINITY_PLUS:
        return FALSE;
    case SFLOAT_VALUE_INFINITY_MINUS:
        switch (b_norm) {
        case SFLOAT_VALUE_NAN:
        case SFLOAT_VALUE_NRES:
        case SFLOAT_VALUE_RFU:
        case SFLOAT_VALUE_INFINITY_MINUS: /* Dead, informative case */
            return FALSE;
        case SFLOAT_VALUE_INFINITY_PLUS:
        default:
            return TRUE;
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
        return TRUE;

    if (a_norm_exponent == b_norm_exponent && a_norm_mantissa < b_norm_mantissa)
        return TRUE;

    if (a_norm_exponent < b_norm_exponent) {
        guint8  exponent_difference;

        exponent_difference = b_norm_exponent - a_norm_exponent;

        if (exponent_difference >= 4)
            return TRUE;

        while (exponent_difference--) {
            b_norm_mantissa *= 10;
        }
    } else {
        guint8  exponent_difference;

        exponent_difference = a_norm_exponent - b_norm_exponent;

        if (exponent_difference >= 4)
            return FALSE;

        while (exponent_difference--) {
            a_norm_mantissa *= 10;
        }
    }

    if (a_norm_mantissa < b_norm_mantissa)
        return TRUE;

    return FALSE;
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

static gboolean
sfloat_ieee_11073_is_zero(const fvalue_t *a)
{
    return a->value.sfloat_ieee_11073 == 0;
}

/*============================================================================*/

static void
float_ieee_11073_fvalue_new(fvalue_t *fv)
{
    fv->value.float_ieee_11073 = 0x0000;
}

static gboolean
float_ieee_11073_val_from_literal(fvalue_t *fv, const char *s, gboolean allow_partial_value _U_, gchar **err_msg _U_)
{
    const char *i_char = s;
    char          c;
    guint8        mantissa_sign = 0;
    guint32       mantissa = 0;
    gint16        exponent = 0;
    gboolean      fraction_mode = FALSE;
    const guint32 mantissa_max = 0x007FFFFF;

    c = *i_char;

    if (c== '\0')
        return FALSE;

    if (c == '.')
        return FALSE;

    if (c == '-' && s[1] == '.')
        return FALSE;

    if (c == '-' && (s[1] == 'I' || s[1] == 'i')) {
        if (!g_ascii_strcasecmp(s, "-INFINITY")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_INFINITY_MINUS;
            return TRUE;
        }

        return FALSE;
    } else if (c == 'R' || c == 'r') {
        if (!g_ascii_strcasecmp(s, "RFU")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_RFU;
            return TRUE;
        }

        return FALSE;
    } else if (c == 'N' || c == 'n') {
        if (!g_ascii_strcasecmp(s, "NRes")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_NRES;
            return TRUE;
        }

        if (!g_ascii_strcasecmp(s, "NaN")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_NAN;
            return TRUE;
        }

        return FALSE;
    } else if (c == '+') {
        if (!g_ascii_strcasecmp(s, "+INFINITY")) {
            fv->value.float_ieee_11073 = FLOAT_VALUE_INFINITY_PLUS;
            return TRUE;
        }

        return FALSE;
    }

    if (c == '-') {
        if (s[1] == '\0')
            return FALSE;

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
                    return FALSE;
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
                return FALSE;
            fraction_mode = TRUE;
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
            return FALSE;
        }

        if (mantissa > mantissa_max + mantissa_sign)
            return FALSE;

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
        return FALSE;

    fv->value.float_ieee_11073 = ((exponent & 0xFF) << 24) | mantissa;

    return TRUE;
}

static char *
float_ieee_11073_val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
    gint8    exponent;
    uint32_t mantissa;
    guint32  mantissa_sign;
    guint32  offset = 0;
    char     mantissa_buf[8];
    char    *mantissa_str;
    guint8   mantissa_digits;

    /* Predefinied: +INFINITY, -INFINITY, RFU, NRes, NaN */
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
        mantissa = (guint32)(-((gint32)(mantissa | 0xFF000000)));

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
float_ieee_11073_value_set(fvalue_t *fv, guint32 value)
{
    fv->value.float_ieee_11073 = value;
}

static guint32
float_ieee_11073_value_get(fvalue_t *fv)
{
    return fv->value.float_ieee_11073;
}

static guint32 float_to_normal_form(guint32 value)
{
    gint8    exponent;
    guint16  mantissa;
    guint8   mantissa_sign;

    if (value >= 0x007FFFFE && value <= 0x00800002) /* Save special values */
        return value;

    mantissa = value & 0x907FFFFF;
    if (value & 0x00800000) {
        mantissa = (guint32)(-((gint32)(mantissa | 0xFF000000)));
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

static gboolean
float_ieee_11073_cmp_eq(const fvalue_t *a, const fvalue_t *b)
{
    return float_to_normal_form(a->value.float_ieee_11073) == float_to_normal_form(b->value.float_ieee_11073);
}

static gboolean
float_ieee_11073_cmp_lt(const fvalue_t *a, const fvalue_t *b)
{
    guint32 a_norm;
    guint32 b_norm;
    gint32  a_norm_mantissa;
    gint32  b_norm_mantissa;
    gint8   a_norm_exponent;
    gint8   b_norm_exponent;

    a_norm = float_to_normal_form(a->value.float_ieee_11073);
    b_norm = float_to_normal_form(b->value.float_ieee_11073);

    if (a_norm == b_norm)
        return FALSE;

    switch (a_norm) {
    case FLOAT_VALUE_NAN:
    case FLOAT_VALUE_NRES:
    case FLOAT_VALUE_RFU:
    case FLOAT_VALUE_INFINITY_PLUS:
        return FALSE;
    case FLOAT_VALUE_INFINITY_MINUS:
        switch (b_norm) {
        case FLOAT_VALUE_NAN:
        case FLOAT_VALUE_NRES:
        case FLOAT_VALUE_RFU:
        case FLOAT_VALUE_INFINITY_MINUS: /* Dead, informative case */
            return FALSE;
        case FLOAT_VALUE_INFINITY_PLUS:
        default:
            return TRUE;
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
        return TRUE;

    if (a_norm_exponent == b_norm_exponent && a_norm_mantissa < b_norm_mantissa)
        return TRUE;

    if (a_norm_exponent < b_norm_exponent) {
        guint8  exponent_difference;

        exponent_difference = b_norm_exponent - a_norm_exponent;

        if (exponent_difference >= 7)
            return TRUE;

        while (exponent_difference--) {
            b_norm_mantissa *= 10;
        }
    } else {
        guint8  exponent_difference;

        exponent_difference = a_norm_exponent - b_norm_exponent;

        if (exponent_difference >= 7)
            return FALSE;

        while (exponent_difference--) {
            a_norm_mantissa *= 10;
        }
    }

    if (a_norm_mantissa < b_norm_mantissa)
        return TRUE;

    return FALSE;
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

static gboolean
float_ieee_11073_is_zero(const fvalue_t *a)
{
    return a->value.float_ieee_11073 == 0;
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
    static ftype_t sfloat_type = {
        FT_IEEE_11073_SFLOAT,                 /* ftype */
        "FT_IEEE_11073_SFLOAT",               /* name */
        "IEEE-11073 floating point (16-bit)", /* pretty_name */
        2,                                    /* wire_size */

        sfloat_ieee_11073_fvalue_new,         /* new_value */
        NULL,                                 /* copy_value */
        NULL,                                 /* free_value */
        sfloat_ieee_11073_val_from_literal,   /* val_from_literal */
        NULL,                                 /* val_from_string */
        NULL,                                 /* val_from_charconst */
        sfloat_ieee_11073_val_to_repr,        /* val_to_string_repr */

        NULL,                                 /* val_to_uinteger64 */
        NULL,                                 /* val_to_sinteger64 */

        { .set_value_uinteger = sfloat_ieee_11073_value_set }, /* union set_value */
        { .get_value_uinteger = sfloat_ieee_11073_value_get }, /* union get_value */

        sfloat_ieee_11073_cmp_order,
        NULL,                                 /* cmp_contains */
        NULL,                                 /* cmp_matches */

        sfloat_ieee_11073_is_zero,           /* is_zero */
        NULL,                                /* is_negative */
        NULL,                                /* len */
        NULL,                                /* slice */
        NULL,                                /* bitwise_and */
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

    static ftype_t float_type = {
        FT_IEEE_11073_FLOAT,                  /* ftype */
        "FT_IEEE_11073_FLOAT",                /* name */
        "IEEE-11073 Floating point (32-bit)", /* pretty_name */
        4,                                    /* wire_size */

        float_ieee_11073_fvalue_new,         /* new_value */
        NULL,                                /* copy_value */
        NULL,                                /* free_value */
        float_ieee_11073_val_from_literal,   /* val_from_literal */
        NULL,                                /* val_from_string */
        NULL,                                /* val_from_charconst */
        float_ieee_11073_val_to_repr,        /* val_to_string_repr */

        NULL,                                 /* val_to_uinteger64 */
        NULL,                                 /* val_to_sinteger64 */

        { .set_value_uinteger = float_ieee_11073_value_set }, /* union set_value */
        { .get_value_uinteger = float_ieee_11073_value_get }, /* union get_value */

        float_ieee_11073_cmp_order,
        NULL,                                /* cmp_contains */
        NULL,                                /* cmp_matches */

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
