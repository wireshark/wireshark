/* int-64bit.c
 * Routines for handling of 64-bit integers
 * 2001 Ronnie Sahlberg
 *
 * $Id: int-64bit.c,v 1.3 2001/10/30 08:39:02 guy Exp $
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
*/
char *
u64toa(const unsigned char *u64ptr)
{
	unsigned char acc[U64STRLEN]; /* accumulator */
	int i,j,k,pos;
	static char str[U64STRLEN];

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
	str[U64STRLEN-1]=0;
	for(i=0;i<U64STRLEN-1;i++){
		str[U64STRLEN-2-i]='0'+acc[i];
	}

	/* skip the initial zeros */
	for(i=0;i<U64STRLEN-2;i++){
		if(str[i]>'0'){
			break;
		}
	}

	return str+i;
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
int main(void)
{
	char i[8] = {0,0,0,0,0x55,0x44,0x33,0x11};
	char t[8];

	printf("%s\n",u64toa(i));
	printf("%s\n",u64toa(atou64("55443311",t)));
	printf("%s\n",u64toh(i));
	printf("%s\n",u64toh(htou64("0x55443311",t)));
	return 0;
}
#endif
