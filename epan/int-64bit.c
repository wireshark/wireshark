/* int-64bit.c
 * Routines for handling of 64-bit integers
 * 2001 Ronnie Sahlberg
 *
 * $Id: int-64bit.c,v 1.1 2001/11/22 03:07:06 hagbard Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "int-64bit.h"

/* all functions take the 64bit integer parameter as a 
   pointer to a 64bit integer in network order.
   that is ptr[0] is the most significant byte and
   ptr[7] is the least significant byte.
*/   

#define U64STRLEN	21


/* this must be signed. if it is not clear why, please dont
   modify the functions in this file. it will break.
*/
static const signed char u64val[64][U64STRLEN] =
{
/* 1  */	{ 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 2  */	{ 2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 3  */	{ 4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 4  */	{ 8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 5  */	{ 6,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 6  */	{ 2,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 7  */	{ 4,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 8  */	{ 8,2,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 9  */	{ 6,5,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 10 */	{ 2,1,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 11 */	{ 4,2,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 12 */	{ 8,4,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 13 */	{ 6,9,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 14 */	{ 2,9,1,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 15 */	{ 4,8,3,6,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 16 */	{ 8,6,7,2,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 17 */	{ 6,3,5,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 18 */	{ 2,7,0,1,3,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 19 */	{ 4,4,1,2,6,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 20 */	{ 8,8,2,4,2,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 21 */	{ 6,7,5,8,4,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 22 */	{ 2,5,1,7,9,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 23 */	{ 4,0,3,4,9,1,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 24 */	{ 8,0,6,8,8,3,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 25 */	{ 6,1,2,7,7,7,6,1,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 26 */	{ 2,3,4,4,5,5,3,3,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 27 */	{ 4,6,8,8,0,1,7,6,0,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 28 */	{ 8,2,7,7,1,2,4,3,1,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 29 */	{ 6,5,4,5,3,4,8,6,2,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 30 */	{ 2,1,9,0,7,8,6,3,5,0,0,0,0,0,0,0,0,0,0,0,0 },
/* 31 */	{ 4,2,8,1,4,7,3,7,0,1,0,0,0,0,0,0,0,0,0,0,0 },
/* 32 */	{ 8,4,6,3,8,4,7,4,1,2,0,0,0,0,0,0,0,0,0,0,0 },
/* 33 */	{ 6,9,2,7,6,9,4,9,2,4,0,0,0,0,0,0,0,0,0,0,0 },
/* 34 */	{ 2,9,5,4,3,9,9,8,5,8,0,0,0,0,0,0,0,0,0,0,0 },
/* 35 */	{ 4,8,1,9,6,8,9,7,1,7,1,0,0,0,0,0,0,0,0,0,0 },
/* 36 */	{ 8,6,3,8,3,7,9,5,3,4,3,0,0,0,0,0,0,0,0,0,0 },
/* 37 */	{ 6,3,7,6,7,4,9,1,7,8,6,0,0,0,0,0,0,0,0,0,0 },
/* 38 */	{ 2,7,4,3,5,9,8,3,4,7,3,1,0,0,0,0,0,0,0,0,0 },
/* 39 */	{ 4,4,9,6,0,9,7,7,8,4,7,2,0,0,0,0,0,0,0,0,0 },
/* 40 */	{ 8,8,8,3,1,8,5,5,7,9,4,5,0,0,0,0,0,0,0,0,0 },
/* 41 */	{ 6,7,7,7,2,6,1,1,5,9,9,0,1,0,0,0,0,0,0,0,0 },
/* 42 */	{ 2,5,5,5,5,2,3,2,0,9,9,1,2,0,0,0,0,0,0,0,0 },
/* 43 */	{ 4,0,1,1,1,5,6,4,0,8,9,3,4,0,0,0,0,0,0,0,0 },
/* 44 */	{ 8,0,2,2,2,0,3,9,0,6,9,7,8,0,0,0,0,0,0,0,0 },
/* 45 */	{ 6,1,4,4,4,0,6,8,1,2,9,5,7,1,0,0,0,0,0,0,0 },
/* 46 */	{ 2,3,8,8,8,0,2,7,3,4,8,1,5,3,0,0,0,0,0,0,0 },
/* 47 */	{ 4,6,6,7,7,1,4,4,7,8,6,3,0,7,0,0,0,0,0,0,0 },
/* 48 */	{ 8,2,3,5,5,3,8,8,4,7,3,7,0,4,1,0,0,0,0,0,0 },
/* 49 */	{ 6,5,6,0,1,7,6,7,9,4,7,4,1,8,2,0,0,0,0,0,0 },
/* 50 */	{ 2,1,3,1,2,4,3,5,9,9,4,9,2,6,5,0,0,0,0,0,0 },
/* 51 */	{ 4,2,6,2,4,8,6,0,9,9,9,8,5,2,1,1,0,0,0,0,0 },
/* 52 */	{ 8,4,2,5,8,6,3,1,8,9,9,7,1,5,2,2,0,0,0,0,0 },
/* 53 */	{ 6,9,4,0,7,3,7,2,6,9,9,5,3,0,5,4,0,0,0,0,0 },
/* 54 */	{ 2,9,9,0,4,7,4,5,2,9,9,1,7,0,0,9,0,0,0,0,0 },
/* 55 */	{ 4,8,9,1,8,4,9,0,5,8,9,3,4,1,0,8,1,0,0,0,0 },
/* 56 */	{ 8,6,9,3,6,9,8,1,0,7,9,7,8,2,0,6,3,0,0,0,0 },
/* 57 */	{ 6,3,9,7,2,9,7,3,0,4,9,5,7,5,0,2,7,0,0,0,0 },
/* 58 */	{ 2,7,8,5,5,8,5,7,0,8,8,1,5,1,1,4,4,1,0,0,0 },
/* 59 */	{ 4,4,7,1,1,7,1,5,1,6,7,3,0,3,2,8,8,2,0,0,0 },
/* 60 */	{ 8,8,4,3,2,4,3,0,3,2,5,7,0,6,4,6,7,5,0,0,0 },
/* 61 */	{ 6,7,9,6,4,8,6,0,6,4,0,5,1,2,9,2,5,1,1,0,0 },
/* 62 */	{ 2,5,9,3,9,6,3,1,2,9,0,0,3,4,8,5,0,3,2,0,0 },
/* 63 */	{ 4,0,9,7,8,3,7,2,4,8,1,0,6,8,6,1,1,6,4,0,0 },
/* 64 */	{ 8,0,8,5,7,7,4,5,8,6,3,0,2,7,3,3,2,2,9,0,0 }
};


/* convert an unsigned  64 bit integer into a string
   it is important that this function is efficient 
   since it will be used for every 64bit integer in
   any capture.
   It is much less important that the inverse: atou64
   be efficient since it is only called when  
   diplayfilters are entered.

   "neg" should be 1 if the number should have a "-" put in
   front of it.
*/
static char *
n64toa(const unsigned char *u64ptr, int neg)
{
	unsigned char acc[U64STRLEN]; /* accumulator */
	int i,j,k,pos;
	static char str[U64STRLEN+1]; /* 1 extra for the sign */

	/* clear out the accumulator */
	for(i=0;i<U64STRLEN-1;i++){
		acc[i]=0;
	}

	pos=0;
	/* loop over the 8 bytes of the 64bit integer,
	   lsb to msb */
	for(i=7;i>=0;i--){
		/* optimize, most of these bytes will be 0 ?*/
		if(u64ptr[i]==0){
			pos+=8;
		} else {
			for(j=0;j<8;j++,pos++){
				if(u64ptr[i]&(1<<j)){
					for(k=0;k<U64STRLEN-1;k++){
						acc[k]+=u64val[pos][k];
					}
				}
			}
		}
		/* we must handle carries inside this loop
		   since othevise the signed char in acc will
		   owerflow/wrap, but we dont need to do it
		   for every iteration. its enough if we
		   do it halfway through and at the end 
		   and we will prevent any overflow.
		*/
		if((i%4)==0){
			/* handle carries */
			for(j=0;j<U64STRLEN-1;j++){
				if(acc[j]>9){
					int x;
					x=acc[j]/10; 
					acc[j+1]+=x;
					acc[j]-=x*10;
				}
			}
		}
	}

	/* convert to a string */
	str[U64STRLEN-1+neg]=0;
	for(i=0;i<U64STRLEN-1;i++){
		str[U64STRLEN-2-i+neg]='0'+acc[i];
	}

	/* skip the initial zeros */
	for(i=0;i<U64STRLEN-2;i++){
		if(str[i+neg]>'0'){
			break;
		}
	}

	/* insert the sign */
	if (neg)
		str[i] = '-';

	return str+i;
}

/*
 * Convert an unsigned 64-bit integer into a string, in decimal.
 */
char *
u64toa(const unsigned char *u64ptr)
{
	/*
	 * Just use "n64toa()".
	 */
	return n64toa(u64ptr, 0);
}

/*
 * Convert a signed 64-bit integer into a string, in decimal.
 */
char *
i64toa(const unsigned char *i64ptr)
{
	unsigned char neg[8];
	int i;
	int carry;
	int byte;

	/*
	 * The bytes of the integer go from msb to lsb, so the
	 * msb is "i64ptr[0]".
	 *
	 * The sign bit, therefore, is "i64ptr[0] & 0x80".
	 */
	if (i64ptr[0] & 0x80) {
		/*
		 * It's negative - compute the absolute value,
		 * by taking the two's complement; take the
		 * one's complement of the low-order byte, add
		 * 1, take the one's complement of the next byte
		 * up, add the carry from the previous addition,
		 * etc.
		 *
		 * If it's the maximum negative value, which is
		 * 0x8000000000000000, this will turn it back
		 * into 0x8000000000000000, which "n64toa()"
		 * will handle correctly, reporting the absolute
		 * value of the maximum negative value;
		 * thus, we don't have to worry about it.
		 */
		carry = 1;
		for (i = 7; i >= 0; i--) {
			byte = ((unsigned char)~i64ptr[i]) + carry;
			neg[i] = byte;
			if (byte & 0x100)
				carry = 1;
			else
				carry = 0;
		}

		/*
		 * Use "n64toa()" on the negative, and tell it to insert
		 * a "-".
		 */
		return n64toa(neg, 1);
	} else {
		/*
		 * It's positive, so just use "n64toa()".
		 */
		return n64toa(i64ptr, 0);
	}
}

/* like memcmp but compares in reverse */
static int
revcmp(const signed char *s1, const signed char *s2, int len)
{
	int i;

	for(i=U64STRLEN-1;i>=0;i--){
		if(s1[i]==s2[i]){
			continue;
		}
		if(s1[i]>s2[i]){
			return 1;
		} else {
			return -1;
		}
	}
	return 0;
}

/*
 * Convert a string to an unsigned 64-bit integer.
 */
unsigned char *
atou64(const char *u64str, unsigned char *u64int)
{
	signed char res[U64STRLEN]; /* residual */
	int i,j,len;
	const char *strp;

	if(!u64str){
		return NULL;
	}

	/* if it is a hex string */
	if( (u64str[0]=='0')
	&&  (u64str[1]=='x') ){
		return htou64(u64str, u64int);
	}

	/* verify that the string is ok */
	for(strp=u64str;*strp;strp++){
		if((*strp>='0')&&(*strp<='9')){
			continue;
		}
		return NULL;
	}

	/* clear the result vector */
	for(i=0;i<8;i++){
		u64int[i]=0;
	}

	/* clear the residual string and copy the
	   original to it (subtracting '0')
	*/ 
	for(i=0;i<U64STRLEN;i++){
		res[i]=0;
	}
	while(*u64str=='0'){ /* skip initial blanks */
		u64str++;
	}
	len=strlen(u64str)-1;
	for(i=0;len>=0;i++,len--){
		res[i]=u64str[len]-'0';
	}

	/* go through all bits and subtract their 
	   value */
	for(i=63;i>=0;i--){
		if(revcmp(u64val[i], res, U64STRLEN)<=0){
			u64int[7-(i>>3)]|=(1<<(i&0x07));
			for(j=0;j<U64STRLEN;j++){
				res[j]-=u64val[i][j];
				/*underflow*/
				if(res[j]<0){
					res[j]+=10;
					res[j+1]-=1;
				}
			}
		}
	}

	return u64int;
}

/*
 * Convert a string to a signed 64-bit integer.
 */
unsigned char *
atoi64(const char *i64str, unsigned char *i64int)
{
	int i;
	int carry;
	int byte;

	if(!i64str){
		return NULL;
	}

	/*
	 * Does it begin with a minus sign?
	 */
	if (i64str[0] == '-') {
		/*
		 * Yes - convert the rest of the string to a number...
		 */
		if (atou64(&i64str[1], i64int) == NULL) {
			/*
			 * We failed.
			 */
			return NULL;
		}

		/*
		 * ...and then take its negative.
		 */
		carry = 1;
		for (i = 7; i >= 0; i--) {
			byte = ((unsigned char)~i64int[i]) + carry;
			i64int[i] = byte;
			if (byte & 0x100)
				carry = 1;
			else
				carry = 0;
		}
		return i64int;
	} else {
		/*
		 * No - just let "atou64()" handle it.
		 */
		return atou64(i64str, i64int);
	}
}

/*
 * Convert an unsigned 64-bit integer to a string, in hex.
 */
char *
u64toh(const unsigned char *u64ptr)
{
	static char str[19], *strp;
	static char ntoh[] = {'0','1','2','3','4','5','6','7',
		'8','9','a','b','c','d','e','f'};
	int i;

	str[0]='0';
	str[1]='x';
	strp=str+2;
	for(i=0;i<8;i++){
		*strp++ = ntoh[u64ptr[i]>>4];
		*strp++ = ntoh[u64ptr[i]&0x0f];
	}
	*strp=0;

	return str;
}

static unsigned int
ntoh(unsigned char h)
{
	if((h>='0')&&(h<='9')){
		return h-'0';
	}

	if((h>='A')&&(h<='F')){
		return h+10-'A';
	}
 
	if((h>='a')&&(h<='f')){
		return h+10-'a';
	}

	return 0;
}

/*
 * Convert a hex string to an unsigned 64-bit integer.
 */
unsigned char *
htou64(const char *u64str, unsigned char *u64int)
{
	int i,len;
	char str[16];
	const char *strp;

	if(!u64str){
		return NULL;
	}

	/* verify that the string is ok */
	if( (u64str[0]!='0')
	||  (u64str[1]!='x') ){
		return NULL;
	}

	for(strp=u64str+2;*strp;strp++){
		if((*strp>='0')&&(*strp<='9')){
			continue;
		}
		if((*strp>='A')&&(*strp<='F')){
			continue;
		}
		if((*strp>='a')&&(*strp<='f')){
			continue;
		}
		return NULL;
	}

	/* clear the result vector */
	for(i=0;i<8;i++){
		u64int[i]=0;
	}

	/* get len of input string */
	for(len=0,strp=u64str+2;len<16;len++,strp++){
		if((*strp>='0')&&(*strp<='9')){
			continue;
		}
		if((*strp>='A')&&(*strp<='F')){
			continue;
		}
		if((*strp>='a')&&(*strp<='f')){
			continue;
		}
		break;
	}
	for(i=0;i<16;i++){
		str[i]='0';
	}
	for(i=0;i<len;i++){
		str[15-i]=u64str[len+1-i];
	}
	

	for(i=0;i<8;i++){
		u64int[i]=(ntoh(str[i*2])<<4)
			| ntoh(str[1+i*2]);
	}

	return u64int;
}

#ifdef TEST_DEBUG
#include <stdio.h>

int main(void)
{
	char i998877665544331[8] =
	    {0x0, 0x23, 0x7c, 0xbd, 0x4c, 0x49, 0xd5, 0x6f};
	char iminus9988776655443311[8] =
	    {0xff, 0xdc, 0x83, 0x42, 0xb3, 0xb6, 0x2a, 0x91};
	char i9223372036854775807[8] =
	    {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	char iminus1[8] =
	    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	char iminus9223372036854775808[8] =
	    {0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	char u9223372036854775808[8] =
	    {0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	char u18446744073709551615[8] =
	    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	char u0xaabbccdd00112233[8] =
	    {0xaa, 0xbb, 0xcc, 0xdd, 0x0, 0x11, 0x22, 0x33};
	char t[8];

	printf("%s (9988776655443311)\n",i64toa(i998877665544331));
	printf("%s (-9988776655443311)\n",i64toa(iminus9988776655443311));
	printf("%s (9223372036854775807)\n",i64toa(i9223372036854775807));
	printf("%s (-1)\n",i64toa(iminus1));
	printf("%s (-9223372036854775808)\n",i64toa(iminus9223372036854775808));

	printf("%s (9988776655443311)\n",u64toa(i998877665544331));
	printf("%s (9223372036854775807)\n",u64toa(i9223372036854775807));
	printf("%s (9223372036854775808)\n",u64toa(u9223372036854775808));
	printf("%s (18446744073709551615)\n",u64toa(u18446744073709551615));

	printf("%s (0xaabbccdd00112233)\n",u64toh(u0xaabbccdd00112233));

	printf("%s (55443311)\n",i64toa(atoi64("55443311",t)));
	printf("%s (-55443311)\n",i64toa(atoi64("-55443311",t)));
	printf("%s (9988776655443311)\n",i64toa(atoi64("9988776655443311",t)));
	printf("%s (-9988776655443311)\n",i64toa(atoi64("-9988776655443311",t)));
	printf("%s (9223372036854775807)\n",i64toa(atoi64("9223372036854775807",t)));
	printf("%s (-1)\n",i64toa(atoi64("-1",t)));
	printf("%s (-9223372036854775808)\n",i64toa(atoi64("-9223372036854775808",t)));

	printf("%s (55443311)\n",u64toa(atou64("55443311",t)));
	printf("%s (0x55443311)\n",u64toh(htou64("0x55443311",t)));
	return 0;
}
#endif
