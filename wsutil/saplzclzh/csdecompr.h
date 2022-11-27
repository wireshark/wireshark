/*@(#)cslzh.h		20.7	SAP	97/11/11


    ========== licence begin  GPL
    Copyright (c) 1994-2005 SAP AG

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; If not, see <https://www.gnu.org/licenses/>.
    ========== licence end




*/
/*
 * Source Code Taken and Adapted from
 * ftp://ftp.sap.com/pub/maxdb/current/7.6.00/maxdb-source-7_6_00_37.zip
 * sys/src/pa/XXXCsObject...
 * sys/src/pa/XXXxxxclzc/h.cpp
 *
 * Changes to the source in ftp.sap.com:
 * Dont use a static CSHU and CSC structure for status handle, but
 * transport it locally to be thread safe. Therefore many function
 * signatures were changed and many csc. (to csc->) places, however
 * the functionality from ftp.sap.com is the same.
 */
/*
 *     SAP AG Walldorf
 *     Systeme, Anwendungen und Produkte in der Datenverarbeitung
 *
 *     (C) Copyright (c) 1994-2005 SAP AG
 */

/*--------------------------------------------------------------------*/
/*                                                                    */
/*      Definitions for LZH Algorithm                                 */
/*      Lempel-Ziv-Huffman                                            */
/*--------------------------------------------------------------------*/

#ifndef CSDECOMPR_H      /* cannot be included twice .................*/
#define CSDECOMPR_H

#include "hpa101saptype.h"


/*--------------------------------------------------------------------*/
/* Flags for CsCompr and CsDecompr                                    */
/*--------------------------------------------------------------------*/
#define CS_LZH_VERSION          1

#define CS_LZH1                 (1 << 4)
#define CS_LZH2                 (2 << 4)
#define CS_LZH3                 (3 << 4)
#define CS_LZH4                 (4 << 4)
#define CS_LZH5                 (5 << 4)
#define CS_LZH6                 (6 << 4)
#define CS_LZH7                 (7 << 4)
#define CS_LZH8                 (8 << 4)
#define CS_LZH9                 (9 << 4)


/* call flags for compression ........................................*/
#define CS_NORMAL_COMPRESS      0x0    /* normal .....................*/
#define CS_INIT_COMPRESS        0x1    /* first call CsCompr..........*/
#define CS_INIT_DECOMPRESS      0x1    /* first call CsDeCompr........*/

#define CS_LZC                  0x0    /* use lzc ....................*/
#define CS_LZH                  0x2    /* use lzh ....................*/
#define CS_GRAPHIC_DATA         0x8    /* not supported now ..........*/

/* Header info in compressed file ....................................*/
#define CS_ALGORITHM_LZC        (SAP_BYTE) 1
#define CS_ALGORITHM_LZH        (SAP_BYTE) 2

#define CS_HEAD_SIZE             8     /* size of common header ......*/

/*--------------------------------------------------------------------*/
/* Error & Return Codes for CsCompr and CsDecompr                     */
/*--------------------------------------------------------------------*/
#define CS_END_INBUFFER          3     /* End of input buffer ........*/
#define CS_END_OUTBUFFER         2     /* End of output buffer .......*/
#define CS_END_OF_STREAM         1     /* End of data ................*/
#define CS_OK                    0

#define CS_IEND_OF_STREAM       -1     /* End of data (internal) .....*/
#define CS_IEND_OUTBUFFER       -2     /* End of output buffer .......*/
#define CS_IEND_INBUFFER        -3     /* End of input buffer ........*/

#define CS_ERROR               -10     /* First Error Code ...........*/
#define CS_E_OUT_BUFFER_LEN    -10     /* Invalid output length ......*/
#define CS_E_IN_BUFFER_LEN     -11     /* Invalid input length .......*/
#define CS_E_NOSAVINGS         -12
#define CS_E_INVALID_SUMLEN    -13     /* Invalid len of stream ......*/
#define CS_E_IN_EQU_OUT        -14     /* inbuf == outbuf ............*/
#define CS_E_INVALID_ADDR      -15     /* inbuf == NULL,outbuf == NULL*/
#define CS_E_FATAL             -19     /* Internal Error ! ...........*/
#define CS_E_BOTH_ZERO         -20     /* inlen = outlen = 0 .........*/
#define CS_E_UNKNOWN_ALG       -21     /* unknown algorithm ..........*/
#define CS_E_UNKNOWN_TYPE      -22

/* for decompress */
#define CS_E_FILENOTCOMPRESSED -50     /* Input not compressed .......*/
#define CS_E_MAXBITS_TOO_BIG   -51     /* maxbits to large ...........*/
#define CS_E_BAD_HUF_TREE      -52     /* bad hufman tree   ..........*/
#define CS_E_NO_STACKMEM       -53     /* no stack memory in decomp ..*/
#define CS_E_INVALIDCODE       -54     /* invalid code ...............*/
#define CS_E_BADLENGTH         -55     /* bad lengths ................*/

#define CS_E_STACK_OVERFLOW    -60     /* stack overflow in decomp    */
#define CS_E_STACK_UNDERFLOW   -61     /* stack underflow in decomp   */

/* only Windows */
#define CS_NOT_INITIALIZED     -71     /* storage not allocated ......*/

/* definition of byte arrays
 * corresponding to their primitive
 * data type
 */
typedef unsigned char BYTEARRAY_2[2]; /* unsigned short     */
typedef unsigned char BYTEARRAY_4[4]; /* unsigned integer   */
typedef unsigned char BYTEARRAY_8[8]; /* unsigned long long */


#define REGISTER register
/* The minimum and maximum match lengths .............................*/
#define MIN_MATCH  3
#define MAX_MATCH  258

/* Minimum amount of lookahead, except at the end of the input file ..*/
#define MIN_LOOKAHEAD (MAX_MATCH+MIN_MATCH+1)

/* In order to simplify the code, particularly on 16 bit machines, match
 * distances are limited to MAX_DIST instead of WSIZE. ...............*/
#define MAX_DIST  (WSIZE-MIN_LOOKAHEAD)

#define NONSENSE_LENBITS 2

#define EODATA (-1)

/* Maximum window size = 32K (must be a power of 2) ..................*/
#define WSIZE  ((unsigned) 0x4000)             /* 16K */

#define CS_HASH_BITS  14

#define CS_HASH_SIZE (unsigned)(1 << CS_HASH_BITS)

#define CS_LIT_BUFSIZE  (unsigned) 0x4000      /* 16K */
#define CS_DIST_BUFSIZE  CS_LIT_BUFSIZE

#define HASH_MASK (CS_HASH_SIZE-1)
#define WMASK     (WSIZE-1)

/* Configuration parameters ..........................................*/
/* speed options for the general purpose bit flag */
#define FAST_PA107 4
#define SLOW_PA107 0

/* Matches of length 3 are discarded if their distance exceeds TOO_FAR*/
#ifndef TOO_FAR
#define TOO_FAR 4096
#endif

/* Types centralized here for easy modification ......................*/
typedef SAP_BYTE   uch;      /* unsigned 8-bit value  ................*/
typedef SAP_USHORT ush;      /* unsigned 16-bit value ................*/
typedef SAP_UINT   ulg;      /* unsigned 32-bit value ................*/

/*
 *     SAP AG Walldorf
 *     Systeme, Anwendungen und Produkte in der Datenverarbeitung
 *
 *     (C) Copyright (c) 1992-2005 SAP AG - 1994
 */

/*--------------------------------------------------------------------*/
/*                                                                    */
/*      Definitions for LZC Algorithm                                 */
/*                                                                    */
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* Macros (internal)                                                  */
/*--------------------------------------------------------------------*/
                                     /* for 16 Bit OS ................*/
#if defined ( OS_16 )
#define LARGE_ARRAY far
#else
#define LARGE_ARRAY
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef CS_BITS
#define CS_BITS        13      /* max. number of bits (default) ......*/
#endif

/* If a new version is added, change CS_VERSION
 */

#define CS_VERSION     (BYTE_TYP) 1

#define CS_ALGORITHM   (BYTE_TYP) 1    /* never change this ..........*/


#define FIRST          257     /* first free entry ...................*/
#define CLEAR          256     /* table clear output code ............*/
                               /* ratio check interval ...............*/
#define CHECK_GAP      4096  /* 10000 */

/* Defines for 8. byte of header .....................................*/
#define BIT_MASK       0x1f
#define BLOCK_MASK     0x80

/* Masks 0x40 and 0x20 are free. */

#define INIT_CS_BITS 9         /* initial number of bits/code ........*/
#define MAX_CS_BITS 16         /* max. number of bits/code ...........*/

#if CS_BITS <= INIT_CS_BITS    /* CS_BITS at least INIT_CS_BITS + 1 ..*/
#undef CS_BITS
#define CS_BITS (INIT_CS_BITS + 1)
#endif

#if CS_BITS >  MAX_CS_BITS     /* CS_BITS at most MAX_CS_BITS ........*/
#undef CS_BITS
#define CS_BITS MAX_CS_BITS
#endif

/*--------------------------------------------------------------------*/
/* TYPES  (depending on CS_BITS)                                      */
/*--------------------------------------------------------------------*/

typedef SAP_BYTE        BYTE_TYP;

#if CS_BITS > 15
typedef long int        CODE_INT;
#else
typedef int             CODE_INT;
#endif

typedef long int        COUNT_INT;
typedef unsigned short  CODE_ENTRY;

/*--------------------------------------------------------------------*/
/* Size of the hash table depending on CS_BITS .......................*/
/*--------------------------------------------------------------------*/

#if CS_BITS == 16
#define HSIZE  69001U          /* 95% occupancy  65536/69001 .........*/
#define CSIZE  69001U
#endif
#if CS_BITS == 15
#define HSIZE  35023U          /* 94% occupancy  32768/35023 .........*/
#define CSIZE  69001U
#endif
#if CS_BITS == 14
#define HSIZE  18013U          /* 91% occupancy  16384/18013 .........*/
#define CSIZE  35023U
#endif
#if CS_BITS == 13
#define HSIZE  9001U           /* 91% occupancy   8192/9001  .........*/
#define CSIZE  18013U
#endif
#if CS_BITS <= 12
#define HSIZE  5003U           /* 80% occupancy   4096/5003  .........*/
#define CSIZE  9001U
#endif

/*--------------------------------------------------------------------*/
/* Access Macros for code and hash tables ............................*/
/*--------------------------------------------------------------------*/

#define MAXCODE(n_bits)  (((CODE_INT) 1 << (n_bits)) - 1)
#define HTABOF(i)        csc->htab[i]
#define CODETABOF(i)     csc->codetab[i]

/*
 * To save much memory, we overlay the table used by CsCompr () with
 * those used by CsDecompr ().  The TAB_PREFIX table is the same size
 * and type as the codetab. The TAB_SUFFIX table needs 2^BITS
 * characters.  We get this from the beginning of htab.
 * The output stack uses the rest of htab, and contains characters.
 * There is plenty of room for any possible stack (stack used to
 * be 8000 characters).
 */

#define TAB_PREFIXOF(i) csc->Prefixtab[i]
#define TAB_SUFFIXOF(i) csc->Suffixtab[i]

/* following definition gives a compiler warning on HP 64 bit (2001-05-15)
   Maybe this will work again some time later.

#define DE_STACK  &TAB_SUFFIXOF((CODE_INT)1<<(CS_BITS+1))

   Definition beneath works on HP, too, but requires an extra global var.
*/

extern CODE_INT DE_STACK_OFFSET;
#define DE_STACK  &TAB_SUFFIXOF(DE_STACK_OFFSET)

/* Clear Hash Table ..................................................*/
#define CL_HASH(size) \
  memset (csc->htab, 0xff, (size) * sizeof (COUNT_INT));


#ifdef USE_MEMCPY           /* use memcpy to transfer bytes ..........*/

#define BYTES_OUT(dst,src,len)              \
    memcpy (dst,src,len); dst += len;

#define BYTES_IN(to,from,len)              \
    memcpy (to,from,len); from += len;

#else                       /* native copy ...........................*/

#define BYTES_OUT(dst,src,len)              \
    {                                       \
      register int i_i = len;               \
      register BYTE_TYP *bufp = src;        \
      while (i_i-- > 0) *dst++ = *bufp++;   \
    }

#define BYTES_IN(to,from,len)               \
    {                                       \
      register int i_i = len;               \
      register BYTE_TYP *bufp = to;         \
      while (i_i-- > 0) *bufp++ = *from++;  \
    }

#endif    /* USE_MEMCPY   */

#define EOBCODE    15
#define LITCODE    16
#define INVALIDCODE 99
/* number of length codes, not counting the special END_BLOCK code */
#define LENGTH_CODES 29
#define D_CODES   30                /* number of distance codes */

#define NONSENSE_LENBITS 2
#define LBITS 9
#define DBITS 6

/* If BMAX needs to be larger than 16, then h and x[] should be ULONG */
#define BMAX 16    /* maximum bit length of any code (16 for explode) */
#define N_MAX 288  /* maximum number of codes in any set .............*/


#define DUMPBITS(n) { cshu->bb >>= (n); cshu->bk -= (n); }

#define NEEDBITS(n)                                             \
{                                                               \
  while (cshu->bk < (n))                                               \
  {                                                             \
    if (cshu->MemInoffset < cshu->MemInsize)                                \
    {                                                           \
      cshu->bytebuf = (unsigned short) cshu->MemInbuffer[(cshu->MemInoffset)++];    \
      bitcount = 8;                                             \
    }                                                           \
    else bitcount = 0;                                          \
    if (!bitcount) break;                                       \
    cshu->bb |= (cshu->bytebuf) << cshu->bk;                                          \
    cshu->bk += 8;                                                     \
  }                                                             \
}

struct HUFT
{
  unsigned char e;                /* number of extra bits or operation .........*/
  unsigned char b;                /* number of bits in this code or subcode ....*/
  union
  {
    unsigned short n;   /* literal, length base, or distance base ....*/
    struct HUFT *t;     /* pointer to next level of table ............*/
  } v;
};

typedef struct HUFT HUFTREE;
#define DE_STACK_SIZE 0x1000

#define BUF_SIZE1 (sizeof(COUNT_INT) * HSIZE > 2*WSIZE ? \
                   sizeof(COUNT_INT) * HSIZE : 2*WSIZE)

#ifdef SAPonWINDOWS
#define DUMMY_SIZE 32768U
#else

#define DUMMY_SIZE (sizeof(HUFTREE) > 8 ? \
                    sizeof(HUFTREE) * 0x1E00 : 0xF000)
#endif

#define BUF_SIZE2 (sizeof(CODE_ENTRY) * CSIZE > DUMMY_SIZE ? \
                   sizeof(CODE_ENTRY) * CSIZE : DUMMY_SIZE)


typedef struct CSHU
{
 SAP_BYTE *OutPtr;
 SAP_UINT SumOut;

 SAP_BYTE *MemOutbuffer;
 SAP_BYTE *MemInbuffer;
 unsigned MemOutoffset;
 unsigned MemOutsize;
 unsigned MemInoffset;
 unsigned MemInsize;
 unsigned BytesPending, SlideOffset;
 unsigned wp;

 SAP_UINT bb;                         /* bit buffer ............*/
 unsigned bk;                         /* bits in bit buffer ....*/

 SAP_UINT bytebuf;
 unsigned AllocStackSize;

 HUFTREE *htp;     /* pointer to table entry */
 unsigned save_n, save_d, save_e;

 int lastblockflag;                /* last block flag ....................*/
 int staterun;            /* state of last run ..................*/
 int NonSenseflag;
 SAP_INT OrgLen;
 unsigned blocktype;         /* block type */

 HUFTREE *tlitlen;      /* literal/length code table */
 HUFTREE *tdistcode;    /* distance code table */
 int blitlen;           /* lookup bits for tl */
 int bdistlen;          /* lookup bits for td */

 int dd_ii;
 unsigned dd_jj;
 unsigned dd_lastlen;     /* last length */
 unsigned dd_maskbit;     /* mask for bit lengths table */
 unsigned dd_nolen;       /* number of lengths to get */
 HUFTREE *dd_tl;          /* literal/length code table */
 HUFTREE *dd_td;          /* distance code table */
 int      dd_bl;          /* lookup bits for tl */
 int      dd_bd;          /* lookup bits for td */
 unsigned dd_nb;          /* number of bit length codes */
 unsigned dd_nl;          /* number of literal/length codes */
 unsigned dd_nd;          /* number of distance codes */
 unsigned dd_ll[286+30];  /* literal/length and distance lengths */
 SAP_BYTE Slide[(BUF_SIZE1)];
 HUFTREE InterBuf[DE_STACK_SIZE];
} CSHU;

typedef struct CSC
{
 int n_bits;                 /* number of bits/code ............*/
 int maxbits;                /* user settable max # bits/code ..*/
 CODE_INT maxcode;           /* maximum code, given n_bits .....*/

                                   /* storage for GETCODE / PUTCODE ..*/
 BYTE_TYP buf1[MAX_CS_BITS];

 int cs_offset;
 int csc_offset;
 int put_n_bytes;

 BYTE_TYP *outptr;
 BYTE_TYP *end_outbuf;

                                   /* should never be generated ......*/
 CODE_INT maxmaxcode; /* = (CODE_INT)1 << CS_BITS; */

 COUNT_INT LARGE_ARRAY htab [HSIZE];      /* hash table ........*/
 CODE_ENTRY LARGE_ARRAY codetab [CSIZE];  /* code table ........*/
 CODE_ENTRY Prefixtab[(BUF_SIZE1)/4]; /* = (CODE_ENTRY *) &CsDeWindowBuf[0]; */
 BYTE_TYP Suffixtab[(BUF_SIZE2)/4]; /* = (BYTE_TYP *) &CsDeInterBuf[0]; */
 CODE_INT hsize; /* = HSIZE; */     /* for dynamic table sizing .......*/


 CODE_INT  free_ent;            /* first unused entry ..........*/
 long int  bytes_out;           /* length of compressed output .*/
 long int  rest_len;            /* rest bytes to decompress ....*/
 int       block_compress;      /* block compression ...........*/
 int       clear_flg;           /* clear hash table ............*/
 long int  ratio;               /* compression ratio ...........*/
 COUNT_INT checkpoint;          /* ratio check point for compr. */

/* states for get_code ...............................................*/
 int get_size, get_r_bits;

 BYTE_TYP * in_ptr;             /* global input ptr ............*/
 BYTE_TYP * end_inbuf;          /* end of input buffer .........*/
 BYTE_TYP *stack_end;

 int hshift;
 CODE_INT ent;
 int sflush;
 long org_len;
 long in_count_sum;


 BYTE_TYP *sstackp; /* = (BYTE_TYP *) 0; */
 long dorg_len;
 CODE_INT scode, soldcode, sincode, sfinchar;
 int restart;

} CSC;

typedef struct CSHDL
{
   union {
	   CSC csc;
	   CSHU cshu;
   } handle;

} CSHDL;

int CsDecompr (CSHDL    * hdl,           /* handle           */
               SAP_BYTE * inbuf,         /* ptr input .......*/
               SAP_INT    inlen,         /* len of input ....*/
               SAP_BYTE * outbuf,        /* ptr output ......*/
               SAP_INT    outlen,        /* len output ......*/
               SAP_INT    option,        /* decompr. option  */
               SAP_INT *  bytes_read,    /* bytes read ......*/
               SAP_INT *  bytes_decompressed); /* bytes decompr.  */

int CsDecomprLZC (CSC      * csc,
                  SAP_BYTE * inbuf,
                  SAP_INT    inlen,
                  SAP_BYTE * outbuf,
                  SAP_INT    outlen,
                  SAP_INT    option,
                  SAP_INT *  bytes_read,
                  SAP_INT *  bytes_written);

int CsDecomprLZH (CSHU     * cshu,
                  SAP_BYTE * inp,
                  SAP_INT    inlen,
                  SAP_BYTE * outp,
                  SAP_INT    outlen,
                  SAP_INT    option,
                  SAP_INT *  bytes_read,
                  SAP_INT *  bytes_decompressed);

#endif   /* CSDECOMPR_H */
