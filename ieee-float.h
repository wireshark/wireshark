/**********************************************************************
 *
 * ieee_float.h
 *
 * Implements simple stuff to convert from IEEE float types
 * to 32-bit longs
 *
 * (C) Ashok Narayanan, 2000
 *
 * $Id: ieee-float.h,v 1.1 2000/03/09 18:31:50 ashokn Exp $
 *
 * For license details, see the COPYING file with this distribution
 *
 **********************************************************************/

#ifndef IEEE_FLOAT_H
#define IEEE_FLOAT_H

/* Stuff for IEEE float handling */

#define IEEE_NUMBER_WIDTH	32	/* bits in number */
#define IEEE_EXP_WIDTH		8	/* bits in exponent */
#define IEEE_MANTISSA_WIDTH	23	/* IEEE_NUMBER_WIDTH - 1 - IEEE_EXP_WIDTH */

#define IEEE_SIGN_MASK		0x80000000
#define IEEE_EXPONENT_MASK	0x7F800000
#define IEEE_MANTISSA_MASK	0x007FFFFF
#define IEEE_INFINITY		IEEE_EXPONENT_MASK

#define IEEE_IMPLIED_BIT (1 << IEEE_MANTISSA_WIDTH)
#define IEEE_INFINITE ((1 << IEEE_EXP_WIDTH) - 1)
#define IEEE_BIAS ((1 << (IEEE_EXP_WIDTH - 1)) - 1)

#define MINUS_INFINITY (signed)0x80000000L
#define PLUS_INFINITY  0x7FFFFFFF

static inline int ieee_float_is_zero (long number)
{
    return(!(number & ~IEEE_SIGN_MASK));
}

/*
 * simple conversion: ieee floating point to long
 */
static long pieee_to_long (const void *p)
{
    long number;
    long sign;
    long exponent;
    long mantissa;

    number = pntohl(p);
    sign = number & IEEE_SIGN_MASK;
    exponent = number & IEEE_EXPONENT_MASK;
    mantissa = number & IEEE_MANTISSA_MASK;

    if (ieee_float_is_zero(number)) {
	/* number is zero, unnormalized, or not-a-number */
	return 0;
    }
    if (IEEE_INFINITY == exponent) {
	/* number is positive or negative infinity, or a special value */
	return (sign? MINUS_INFINITY: PLUS_INFINITY);
    }

    exponent = (exponent >> IEEE_MANTISSA_WIDTH) - IEEE_BIAS;
    if (exponent < 0) {
	/* number is between zero and one */
	return 0;
    }

    mantissa |= IEEE_IMPLIED_BIT;
    if (exponent <= IEEE_MANTISSA_WIDTH)
	mantissa >>= IEEE_MANTISSA_WIDTH - exponent;
    else
	mantissa <<= exponent - IEEE_MANTISSA_WIDTH;

    if (sign)
	return -mantissa;
    else
	return mantissa;
}

#endif
