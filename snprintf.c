
/*
   Unix snprintf implementation.
   Version 1.2
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   It can be redistribute also under the terms of GNU Library General
   Public Lincense.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
   Revision History:

   1.2:
      * put the program under LGPL.
   1.1:
      *  added changes from Miles Bader
      *  corrected a bug with %f
      *  added support for %#g
      *  added more comments :-)
   1.0:
      *  supporting must ANSI syntaxic_sugars
   0.0:
      *  suppot %s %c %d

 THANKS(for the patches and ideas):
     Miles Bader
     Cyrille Rustom
     Jacek Slabocewiz
     Mike Parker(mouse)

*/
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "snprintf-imp.h"
#include "snprintf.h"

/*
 * Find the nth power of 10
 */
PRIVATE double
#ifdef __STDC__
pow_10(int n)
#else
pow_10(n)
int n;
#endif
{ 
  int i;
  double P;

  if (n < 0)
    for (i = 1, P = 1., n = -n ; i <= n ; i++) {P *= .1;}
  else
    for (i = 1, P = 1. ; i <= n ; i++) {P *= 10.0;}
  return P;
}

/*
 * Find the integral part of the log in base 10 
 * Note: this not a real log10()
         I just need and approximation(integerpart) of x in:
          10^x ~= r
 * log_10(200) = 2;
 * log_10(250) = 2;
 */
PRIVATE int
#ifdef __STDC__
log_10(double r)
#else
log_10(r)
double r;
#endif
{ 
  int i = 0;
  double result = 1.;

  if (r < 0.)
    r = -r;

  if (r == 0.0)
     return(0);
  if (r < 1.) {
    while (result >= r) {result *= .1; i++;}
    return (-i);
  } else {
    while (result <= r) {result *= 10.; i++;}
    return (i - 1);
  }
}

/*
 * This function return the fraction part of a double
 * and set in ip the integral part.
 * In many ways it resemble the modf() found on most Un*x
 */
PRIVATE double
#ifdef __STDC__
integral(double real, double * ip)
#else
integral(real, ip)
double real;
double * ip;
#endif
{ 
  int j;
  double i, s, p;
  double real_integral = 0.;

/* take care of the obvious */
/* equal to zero ? */
  if (real == 0.) {
    *ip = 0.;
    return (0.);
  }

/* negative number ? */
  if (real < 0.)
    real = -real;

/* a fraction ? */
  if ( real < 1.) {
    *ip = 0.;
    return real;
  }
/* the real work :-) */
  for (j = log_10(real); j >= 0; j--) {
    p = pow_10(j);
    s = (real - real_integral)/p;
    i = 0.;
    while (i + 1. <= s) {i++;}
    real_integral += i*p;
  }
  *ip = real_integral;
  return (real - real_integral);
}

#define PRECISION 1.e-6
/* 
 * return an ascii representation of the integral part of the number
 * and set fract to be an ascii representation of the fraction part
 * the container for the fraction and the integral part or staticly
 * declare with fix size 
 */
PRIVATE char *
#ifdef __STDC__
numtoa(double number, int base, int precision, char ** fract)
#else
numtoa(number, base, precision, fract)
double number;
int base;
int precision;
char ** fract;
#endif
{
  register int i, j;
  double ip, fp; /* integer and fraction part */
  double fraction;
  int digits = MAX_INT - 1;
  static char integral_part[MAX_INT];
  static char fraction_part[MAX_FRACT];
  double sign;
  int ch;

/* taking care of the obvious case: 0.0 */
  if (number == 0.) { 
    integral_part[0] = '0';
    integral_part[1] = '\0';
    fraction_part[0] = '0';
    fraction_part[1] = '\0';
    return integral_part;
  }

/* for negative numbers */
  if ((sign = number) < 0.) {
    number = -number;
    digits--; /* sign consume one digit */
  } 

  fraction = integral(number, &ip);
  number = ip;
/* do the integral part */
  if ( ip == 0.) {
    integral_part[0] = '0';
    i = 1;
  } else {
    for ( i = 0; i < digits && number != 0.; ++i) {
      number /= base;
      fp = integral(number, &ip);
      ch = (int)((fp + PRECISION)*base); /* force to round */
      integral_part[i] = (ch <= 9) ? ch + '0' : ch + 'a' - 10;
      if (! isxdigit((unsigned char)integral_part[i])) /* bail out overflow !! */
        break; 
      number = ip;
     }
  }
     
/* Oh No !! out of bound, ho well fill it up ! */
  if (number != 0.)
    for (i = 0; i < digits; ++i)
      integral_part[i] = '9';

/* put the sign ? */
  if (sign < 0.)
    integral_part[i++] = '-';

  integral_part[i] = '\0';

/* reverse every thing */
  for ( i--, j = 0; j < i; j++, i--)
    SWAP_INT(integral_part[i], integral_part[j]);  

/* the fractionnal part */
  for (i=0, fp=fraction; precision > 0 && i < MAX_FRACT ; i++, precision--	) {
    fraction_part[i] = (int)((fp + PRECISION)*10. + '0');
    if (! isdigit((unsigned char)fraction_part[i])) /* underflow ? */
      break;
    fp = (fp*10.0) - (double)(long)((fp + PRECISION)*10.);
  }
  fraction_part[i] = '\0';

  if (fract != (char **)0)
    *fract = fraction_part;

  return integral_part;

}

/* for %d and friends, it puts in holder
 * the representation with the right padding
 */
PRIVATE void
#ifdef __STDC__
decimal(struct DATA *p, double d)
#else
decimal(p, d)
struct DATA *p;
double d;
#endif
{
  char *tmp;

  tmp = itoa(d);
  p->width -= strlen(tmp);
  PAD_RIGHT(p);
  PUT_PLUS(d, p);
  PUT_SPACE(d, p);
  while (*tmp) { /* the integral */
    PUT_CHAR(*tmp, p);
    tmp++;
  }
  PAD_LEFT(p);
}

/* for %o octal representation */
PRIVATE void
#ifdef __STDC__
octal(struct DATA *p, double d)
#else
octal(p, d)
struct DATA *p;
double d;
#endif
{
  char *tmp;

  tmp = otoa(d);
  p->width -= strlen(tmp);
  if (p->square == FOUND) /* had prefix '0' for octal */
    PUT_CHAR('0', p);
  PAD_RIGHT(p);
  while (*tmp) { /* octal */
    PUT_CHAR(*tmp, p);
    tmp++;
  }
  PAD_LEFT(p);
}

/* for %x %X hexadecimal representation */
PRIVATE void
#ifdef __STDC__
hexa(struct DATA *p, double d)
#else
hexa(p, d)
struct DATA *p;
double d;
#endif
{
  char *tmp;

  tmp = htoa(d);
  p->width -= strlen(tmp);
  if (p->square == FOUND) { /* prefix '0x' for hexa */
    PUT_CHAR('0', p); PUT_CHAR(*p->pf, p);
  }
  PAD_RIGHT(p);
  while (*tmp) { /* hexa */
    PUT_CHAR((*p->pf == 'X' ? toupper(*tmp) : *tmp), p);
    tmp++;
  }
  PAD_LEFT(p);
}

/* %s strings */
PRIVATE void
#ifdef __STDC__
strings(struct DATA *p, char *tmp)
#else
strings(p, tmp)
struct DATA *p;
char *tmp;
#endif
{
  int i;

  i = strlen(tmp);
  if (p->precision != NOT_FOUND) /* the smallest number */
    i = (i < p->precision ? i : p->precision);
  p->width -= i;
  PAD_RIGHT(p);
  while (i-- > 0) { /* put the sting */
    PUT_CHAR(*tmp, p);
    tmp++;
  }
  PAD_LEFT(p);
}

/* %f or %g  floating point representation */
PRIVATE void
#ifdef __STDC__
floating(struct DATA *p, double d)
#else
floating(p, d)
struct DATA *p;
double d;
#endif
{
  char *tmp, *tmp2;
  int i;

  DEF_PREC(p);
  d = ROUND(d, p);
  tmp = dtoa(d, p->precision, &tmp2);
  /* calculate the padding. 1 for the dot */
  p->width = p->width -
            ((d > 0. && p->justify == RIGHT) ? 1:0) -
            ((p->space == FOUND) ? 1:0) -
            strlen(tmp) - p->precision - 1;
  PAD_RIGHT(p);  
  PUT_PLUS(d, p);
  PUT_SPACE(d, p);
  while (*tmp) { /* the integral */
    PUT_CHAR(*tmp, p);
    tmp++;
  }
  if (p->precision != 0 || p->square == FOUND)
    PUT_CHAR('.', p);  /* put the '.' */
  if (*p->pf == 'g' || *p->pf == 'G') /* smash the trailing zeros */
    for (i = strlen(tmp2) - 1; i >= 0 && tmp2[i] == '0'; i--)
       tmp2[i] = '\0'; 
  for (; *tmp2; tmp2++)
    PUT_CHAR(*tmp2, p); /* the fraction */
  
  PAD_LEFT(p);
} 

/* %e %E %g exponent representation */
PRIVATE void
#ifdef __STDC__
exponent(struct DATA *p, double d)
#else
exponent(p, d)
struct DATA *p;
double d;
#endif
{
  char *tmp, *tmp2;
  int j, i;

  DEF_PREC(p);
  j = log_10(d);
  d = d / pow_10(j);  /* get the Mantissa */
  d = ROUND(d, p);                  
  tmp = dtoa(d, p->precision, &tmp2);
  /* 1 for unit, 1 for the '.', 1 for 'e|E',
   * 1 for '+|-', 3 for 'exp' */
  /* calculate how much padding need */
  p->width = p->width - 
             ((d > 0. && p->justify == RIGHT) ? 1:0) -
             ((p->space == FOUND) ? 1:0) - p->precision - 7;
  PAD_RIGHT(p);
  PUT_PLUS(d, p);
  PUT_SPACE(d, p);
  while (*tmp) {/* the integral */
    PUT_CHAR(*tmp, p);
    tmp++;
  }
  if (p->precision != 0 || p->square == FOUND)
    PUT_CHAR('.', p);  /* the '.' */
  if (*p->pf == 'g' || *p->pf == 'G') /* smash the trailing zeros */
    for (i = strlen(tmp2) - 1; i >= 0 && tmp2[i] == '0'; i--)
       tmp2[i] = '\0'; 
  for (; *tmp2; tmp2++)
    PUT_CHAR(*tmp2, p); /* the fraction */

  if (*p->pf == 'g' || *p->pf == 'e') { /* the exponent put the 'e|E' */
     PUT_CHAR('e', p);
   } else
     PUT_CHAR('E', p);
   if (j > 0) {  /* the sign of the exp */
     PUT_CHAR('+', p);
   } else {
     PUT_CHAR('-', p);
     j = -j;
   }
   tmp = itoa((double)j);
   if (j < 9) {  /* need to pad the exponent with 0 '000' */
     PUT_CHAR('0', p); PUT_CHAR('0', p);
   } else if (j < 99)
     PUT_CHAR('0', p);
   while (*tmp) { /* the exponent */
     PUT_CHAR(*tmp, p);
     tmp++;
   }
   PAD_LEFT(p);
}

/* initialize the conversion specifiers */
PRIVATE void
#ifdef __STDC__
conv_flag(char * s, struct DATA * p)
#else
conv_flag(s, p)
char * s;
struct DATA * p;
#endif
{
  char number[MAX_FIELD/2];
  int i;

  p->precision = p->width = NOT_FOUND;
  p->star_w = p->star_p = NOT_FOUND;
  p->square = p->space = NOT_FOUND;
  p->a_long = p->justify = NOT_FOUND;
  p->pad = ' ';

  for(;s && *s ;s++) {
    switch(*s) {
      case ' ': p->space = FOUND; break;
      case '#': p->square = FOUND; break;
      case '*': if (p->width == NOT_FOUND)
                  p->width = p->star_w = FOUND;
                else
                  p->precision = p->star_p = FOUND;
                break;
      case '+': p->justify = RIGHT; break;
      case '-': p->justify = LEFT; break;
      case '.': if (p->width == NOT_FOUND)
                  p->width = 0;
                break;
      case '0': p->pad = '0'; break;
      case '1': case '2': case '3':
      case '4': case '5': case '6':
      case '7': case '8': case '9':     /* gob all the digits */
        for (i = 0; isdigit((unsigned char)*s); i++, s++) 
          if (i < MAX_FIELD/2 - 1)
            number[i] = *s;
        number[i] = '\0';
        if (p->width == NOT_FOUND)
          p->width = atoi(number);
        else
          p->precision = atoi(number);
        s--;   /* went to far go back */
        break;
    }
  }
}

PUBLIC int
#ifdef __STDC__
vsnprintf(char *string, size_t length, const char * format, va_list args)
#else
vsnprintf(string, length, format, args)
char *string;
size_t length;
char * format;
va_list args;
#endif
{
  struct DATA data;
  char conv_field[MAX_FIELD];
  double d; /* temporary holder */
  int state;
  int i;

  data.length = length - 1; /* leave room for '\0' */
  data.holder = string;
  data.pf = format;
  data.counter = 0;


/* sanity check, the string must be > 1 */
  if (length < 1)
    return -1;


  for (; *data.pf && (data.counter < data.length); data.pf++) {
    if ( *data.pf == '%' ) { /* we got a magic % cookie */
      conv_flag((char *)0, &data); /* initialise format flags */
      for (state = 1; *data.pf && state;) {
        switch (*(++data.pf)) {
          case '\0': /* a NULL here ? ? bail out */
            *data.holder = '\0';
            return data.counter;
            break;
          case 'f':  /* float, double */
            STAR_ARGS(&data);
            d = va_arg(args, double);
            floating(&data, d);  
            state = 0;
            break;
          case 'g': 
          case 'G':
            STAR_ARGS(&data);
            DEF_PREC(&data);
            d = va_arg(args, double);
            i = log_10(d);
            /*
             * for '%g|%G' ANSI: use f if exponent
             * is in the range or [-4,p] exclusively
             * else use %e|%E
             */
            if (-4 < i && i < data.precision)
              floating(&data, d);
            else
              exponent(&data, d);
            state = 0;
            break;
          case 'e':
          case 'E':  /* Exponent double */
            STAR_ARGS(&data);
            d = va_arg(args, double);
            exponent(&data, d);
            state = 0;
            break;
          case 'u':  /* unsigned decimal */
            STAR_ARGS(&data);
            if (data.a_long == FOUND)
              d = va_arg(args, unsigned long);
            else
              d = va_arg(args, unsigned int);
            decimal(&data, d);
            state = 0;
            break;
          case 'd':  /* decimal */
          case 'i':  /* "integer" (signed decimal) */
            STAR_ARGS(&data);
            if (data.a_long == FOUND)
              d = va_arg(args, long);
            else
              d = va_arg(args, int);
            decimal(&data, d);
            state = 0;
            break;
          case 'o':  /* octal */
            STAR_ARGS(&data);
            if (data.a_long == FOUND)
              d = va_arg(args, unsigned long);
            else
              d = va_arg(args, unsigned int);
            octal(&data, d);
            state = 0;
            break;
          case 'x': 
          case 'X':  /* hexadecimal */
            STAR_ARGS(&data);
            if (data.a_long == FOUND)
              d = va_arg(args, unsigned long);
            else
              d = va_arg(args, unsigned int);
            hexa(&data, d);
            state = 0;
            break;
          case 'c': /* character */
            d = va_arg(args, int);
            PUT_CHAR(d, &data);
            state = 0;
            break;
          case 's':  /* string */
            STAR_ARGS(&data);
            strings(&data, va_arg(args, char *));
            state = 0;
            break;
          case 'n':
             *(va_arg(args, int *)) = data.counter; /* what's the count ? */
             state = 0;
             break;
          case 'l':
            data.a_long = FOUND;
            break;
          case 'h':
            break;
          case '%':  /* nothing just % */
            PUT_CHAR('%', &data);
            state = 0;
            break;
          case '#': case ' ': case '+': case '*':
          case '-': case '.': case '0': case '1': 
          case '2': case '3': case '4': case '5':
          case '6': case '7': case '8': case '9':
           /* initialize width and precision */
            for (i = 0; isflag((unsigned char)*data.pf); i++, data.pf++) 
              if (i < MAX_FIELD - 1)
                conv_field[i] = *data.pf;
            conv_field[i] = '\0';
            conv_flag(conv_field, &data);
            data.pf--;   /* went to far go back */
            break;
          default:
            /* is this an error ? maybe bail out */
            state = 0;
            break;
        } /* end switch */
      } /* end of for state */
    } else { /* not % */
      PUT_CHAR(*data.pf, &data);  /* add the char the string */
    }
  }

  *data.holder = '\0'; /* the end ye ! */

  return data.counter;
}

#ifndef HAVE_SNPRINTF

PUBLIC int
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
snprintf(char *string, size_t length, const char * format, ...)
#else
snprintf(string, length, format, va_alist)
char *string;
size_t length;
char * format;
va_dcl
#endif
{
  int rval;
  va_list args;

#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
  va_start(args, format);
#else
  va_start(args);
#endif

  rval = vsnprintf (string, length, format, args);

  va_end(args);

  return rval;
}

#endif /* HAVE_SNPRINTF */


#ifdef DRIVER

#include <stdio.h>

/* set of small tests for snprintf() */
void main()
{
  char holder[100];
  int i;

/*
  printf("Suite of test for snprintf:\n");
  printf("a_format\n");
  printf("printf() format\n");
  printf("snprintf() format\n\n");
*/
/* Checking the field widths */

  printf("/%%d/, 336\n");
  snprintf(holder, sizeof holder, "/%d/\n", 336);
  printf("/%d/\n", 336);
  printf("%s\n", holder);

  printf("/%%2d/, 336\n");
  snprintf(holder, sizeof holder, "/%2d/\n", 336);
  printf("/%2d/\n", 336);
  printf("%s\n", holder);

  printf("/%%10d/, 336\n");
  snprintf(holder, sizeof holder, "/%10d/\n", 336);
  printf("/%10d/\n", 336);
  printf("%s\n", holder);

  printf("/%%-10d/, 336\n");
  snprintf(holder, sizeof holder, "/%-10d/\n", 336);
  printf("/%-10d/\n", 336);
  printf("%s\n", holder);


/* floating points */

  printf("/%%f/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%f/\n", 1234.56);
  printf("/%f/\n", 1234.56);
  printf("%s\n", holder);

  printf("/%%e/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%e/\n", 1234.56);
  printf("/%e/\n", 1234.56);
  printf("%s\n", holder);

  printf("/%%4.2f/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%4.2f/\n", 1234.56);
  printf("/%4.2f/\n", 1234.56);
  printf("%s\n", holder);

  printf("/%%3.1f/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%3.1f/\n", 1234.56);
  printf("/%3.1f/\n", 1234.56);
  printf("%s\n", holder);

  printf("/%%10.3f/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%10.3f/\n", 1234.56);
  printf("/%10.3f/\n", 1234.56);
  printf("%s\n", holder);

  printf("/%%10.3e/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%10.3e/\n", 1234.56);
  printf("/%10.3e/\n", 1234.56);
  printf("%s\n", holder);

  printf("/%%+4.2f/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%+4.2f/\n", 1234.56);
  printf("/%+4.2f/\n", 1234.56);
  printf("%s\n", holder);

  printf("/%%010.2f/, 1234.56\n");
  snprintf(holder, sizeof holder, "/%010.2f/\n", 1234.56);
  printf("/%010.2f/\n", 1234.56);
  printf("%s\n", holder);

#define BLURB "Outstanding acting !"
/* strings precisions */

  printf("/%%2s/, \"%s\"\n", BLURB);
  snprintf(holder, sizeof holder, "/%2s/\n", BLURB);
  printf("/%2s/\n", BLURB);
  printf("%s\n", holder);

  printf("/%%22s/ %s\n", BLURB);
  snprintf(holder, sizeof holder, "/%22s/\n", BLURB);
  printf("/%22s/\n", BLURB);
  printf("%s\n", holder);

  printf("/%%22.5s/ %s\n", BLURB);
  snprintf(holder, sizeof holder, "/%22.5s/\n", BLURB);
  printf("/%22.5s/\n", BLURB);
  printf("%s\n", holder);

  printf("/%%-22.5s/ %s\n", BLURB);
  snprintf(holder, sizeof holder, "/%-22.5s/\n", BLURB);
  printf("/%-22.5s/\n", BLURB);
  printf("%s\n", holder);

/* see some flags */

  printf("%%x %%X %%#x, 31, 31, 31\n");
  snprintf(holder, sizeof holder, "%x %X %#x\n", 31, 31, 31);
  printf("%x %X %#x\n", 31, 31, 31);
  printf("%s\n", holder);

  printf("**%%d**%% d**%% d**, 42, 42, -42\n");
  snprintf(holder, sizeof holder, "**%d**% d**% d**\n", 42, 42, -42);
  printf("**%d**% d**% d**\n", 42, 42, -42);
  printf("%s\n", holder);

/* other flags */

  printf("/%%g/, 31.4\n");
  snprintf(holder, sizeof holder, "/%g/\n", 31.4);
  printf("/%g/\n", 31.4);
  printf("%s\n", holder);

  printf("/%%.6g/, 31.4\n");
  snprintf(holder, sizeof holder, "/%.6g/\n", 31.4);
  printf("/%.6g/\n", 31.4);
  printf("%s\n", holder);

  printf("/%%.1G/, 31.4\n");
  snprintf(holder, sizeof holder, "/%.1G/\n", 31.4);
  printf("/%.1G/\n", 31.4);
  printf("%s\n", holder);

  printf("abc%%n\n");
  printf("abc%n", &i); printf("%d\n", i);
  snprintf(holder, sizeof holder, "abc%n", &i);
  printf("%s", holder); printf("%d\n\n", i);
  
  printf("%%*.*s --> 10.10\n");
  snprintf(holder, sizeof holder, "%*.*s\n", 10, 10, BLURB);
  printf("%*.*s\n", 10, 10, BLURB);
  printf("%s\n", holder);

  printf("%%%%%%%%\n");
  snprintf(holder, sizeof holder, "%%%%\n");
  printf("%%%%\n");
  printf("%s\n", holder);

#define BIG "Hello this is a too big string for the buffer"
/*  printf("A buffer to small of 10, trying to put this:\n");*/
  printf("<%%>, %s\n", BIG); 
  i = snprintf(holder, 10, "%s\n", BIG);
  printf("<%s>\n", BIG);
  printf("<%s>\n", holder);
}
#endif
