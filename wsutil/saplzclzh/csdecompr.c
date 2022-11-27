/*@(#)cslzh.c		20.7	SAP	97/11/11


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
/* Adapter defines                                                    */
/*--------------------------------------------------------------------*/
#ifdef SAPwithUNICODE
#undef SAPwithUNICODE
#undef UNICODE
#undef _UNICODE
#endif

/*--------------------------------------------------------------------*/
/* system includes (OS-dependent)                                     */
/*--------------------------------------------------------------------*/
#ifdef _WIN32
#ifndef WIN32_MEAN_AND_LEAN
#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#endif
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>

/*--------------------------------------------------------------------*/
/* SAP includes                                                       */
/*--------------------------------------------------------------------*/
#include "csdecompr.h"

static SAP_BYTE CsMagicHead[] = { "\037\235" };  /* 1F 9D */
static unsigned short mask_bits[] =
{
 0x0000, 0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
 0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff
};

static unsigned border[] =
{    /* Order of the bit length code lengths */
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

static int cplens[] =
       {       /* Copy lengths for literal codes 257..285 */
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0
       };
        /* note: see note #13 above about the 258 in this list. */

static int CPLENS_LEN = sizeof(cplens)/sizeof(int);

static int cpdist[] =
       {       /* Copy offsets for distance codes 0..29 */
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577
       };

static int CsExtraLenBits[LENGTH_CODES+2] /* extra bits for each length code */
   = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,99,99};
static int *cplext = &CsExtraLenBits[0];

static int CsExtraDistBits[D_CODES] /* extra bits for each distance code */
= {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
static int * cpdext = &CsExtraDistBits[0];


SAP_INT CsGetAlgorithm (const SAP_BYTE * data)
/*--------------------------------------------------------------------*/
/* Get Algorithm number of compressed data                            */
/*--------------------------------------------------------------------*/
{
   return ((int) (data[4] & (unsigned char)0x0F));
}

SAP_INT CsGetLen (SAP_BYTE * data)
/*--------------------------------------------------------------------*/
/* Get the length of the original data stream                         */
/*                                                                    */
/*   Returns CS_E_FILENOT_COMPRESSED if the magic number is           */
/*                                      different from magic header   */
/*                                   else                             */
/*           Length of org. data stream                               */
/*--------------------------------------------------------------------*/
{
  SAP_INT len;
                                      /* file not compressed !!! .....*/
  if ((CsMagicHead[0] != data[5]) ||
      (CsMagicHead[1] != data[6]))
  {
    return ((SAP_INT)CS_E_FILENOTCOMPRESSED);
  }

  len = (SAP_INT)data[0]         +    /* read length from first buf ..*/
        ((SAP_INT)data[1] << 8)  +
        ((SAP_INT)data[2] << 16) +
        ((SAP_INT)data[3] << 24);

  return len;
}
void NoBits (CSHU *cshu)
/*--------------------------------------------------------------------*/
/*                                                                    */
/*--------------------------------------------------------------------*/
{
  unsigned   x;         /* number of bits in bit buffer ............*/
  int bitcount = 1;       /* bitcount ................................*/

  NEEDBITS(NONSENSE_LENBITS)
  x = (unsigned) (cshu->bb & ((1 << NONSENSE_LENBITS) - 1));
  DUMPBITS(NONSENSE_LENBITS)

  if (x)
  {
    NEEDBITS(x)
    DUMPBITS(x)
  }
}

HUFTREE * AllocHufTree (CSHU *cshu, unsigned size)
{
  HUFTREE * p;

  p = cshu->InterBuf + cshu->AllocStackSize;

  cshu->AllocStackSize += size; /* * sizeof(HUFTREE); */
  /* InterBuf is at least 0x1000 in size (5.9.96 ab) .................*/
  if (cshu->AllocStackSize >= DE_STACK_SIZE) return (HUFTREE *) 0;

  return p;
}

static int BuildHufTree (CSHU *cshu,
             unsigned * b,  /* code lengths in bits (all assumed <= BMAX) */
             unsigned   n,  /* number of codes (assumed <= N_MAX) */
             unsigned   s,  /* number of simple-valued codes (0..s-1) */
             int      * d,  /* list of base values for non-simple codes */
             int      * e,  /* list of extra bits for non-simple codes */
             int        ll, /* length of lists d and e */
             HUFTREE  **t,  /* result: starting table */
             int      * m)  /* maximum lookup bits, returns actual */

/* Given a list of code lengths and a maximum table size, make a set of
   tables to decode that set of codes.  Return zero on success, one if
   the given code set is incomplete (the tables are still built in this
   case), two if the input is invalid (all zero length codes or an
   oversubscribed set of lengths), and three if not enough memory. */
{
  unsigned a = 0;                   /* counter for codes of length k */
  unsigned c[BMAX+1] = {0};         /* bit length count table */
  unsigned f = 0;                   /* i repeats in table every f entries */
  int g = 0;                        /* maximum code length */
  int h = 0;                        /* table level */
  REGISTER unsigned i = 0;          /* counter, current code */
  REGISTER unsigned j = 0;          /* counter */
  REGISTER int k = 0;               /* number of bits in current code */
  int l = 0;                        /* bits per table (returned in m) */
  REGISTER unsigned *p = NULL;      /* pointer into c[], b[], or v[] */
  REGISTER HUFTREE *q = NULL;       /* points to current table */
  HUFTREE  r = {0};                 /* table entry for struct assignment */
  HUFTREE *u[BMAX] = {NULL};        /* table stack */
  unsigned v[N_MAX] = {0};          /* values in order of bit length */
  REGISTER int w = 0;               /* bits before this table == (l * h) */
  unsigned x[BMAX+1] = {0};         /* bit offsets, then code stack */
  unsigned *xp = NULL;              /* pointer into x */
  int y = 0;                        /* number of dummy codes added */
  unsigned z = 0;                   /* number of entries in current table */

  if(!cshu ||!b || !m )
    return CS_E_BAD_HUF_TREE;

  /* Generate counts for each bit length .............................*/
  p = b;
  for(i = 0; i < n; i++)
  {
      if(*p > BMAX)                 /* make sure that all entries <= BMAX .......*/
        return CS_E_BAD_HUF_TREE;
    c[*p++]++;
  }

  if (c[0] == n)                 /* bad input--all zero length codes .*/
    return CS_E_BAD_HUF_TREE;

  /* Find minimum and maximum length, bound *m by those ..............*/
  l = *m;
  for (j = 1; j <= BMAX; j++)
    if (c[j]) break;

  k = j;                        /* minimum code length ...............*/
  if ((unsigned)l < j) l = j;

  for (i = BMAX; i; i--)
    if (c[i]) break;

  g = i;                        /* maximum code length ...............*/
  if (( unsigned)l > i) l = i;
  *m = l;

  /* Adjust last length count to fill out codes, if needed ...........*/
  for (y = 1 << j; j < i; j++, y <<= 1)
    if ((y -= c[j]) < 0)
      return CS_E_BAD_HUF_TREE;  /* bad input: more codes than bits ..*/

  if ((y -= c[i]) < 0) return CS_E_BAD_HUF_TREE;

  c[i] += y;

  /* Generate starting offsets into the value table for each length ..*/
  x[1] = j = 0;
  p = c + 1;  xp = x + 2;
  while (--i)              /* note that i == g from above ............*/
  {
    *xp++ = (j += *p++);
  }

  /* Make a table of values in order of bit lengths ..................*/
  p = b;
  for(i = 0; i < n; i++)
  {
    if ((j = *p++) != 0) v[x[j]++] = i;
  }

  /* Generate the Huffman codes and for each, make the table entries */
  x[0] = i = 0;                 /* first Huffman code is zero */
  p = v;                        /* grab values in bit order */
  h = -1;                       /* no tables yet--level -1 */
  w = -l;                       /* bits decoded == (l * h) */

  /* go through the bit lengths (k already is bits in shortest code) */
  for (; k <= g; k++)
  {
    a = c[k];
    while (a--)
    {
      /* here i is the Huffman code of length k bits for value *p */
      /* make tables up to required level */
      while (k > w + l)
      {
        h++;
        w += l;                 /* previous table always l bits */

        /* compute minimum size table less than or equal to l bits */
        z = (z = g - w) > (unsigned)l ? (unsigned)l : z; /* upper limit on table size */
        j = k - w;
        f = 1 << j;
        if (f > a + 1)    /* try a k-w bit table */
        {                       /* too few codes for k-w bit table */
          f -= a + 1;           /* deduct codes from patterns left */
          xp = c + k;
          while (++j < z)       /* try smaller tables up to z bits */
          {
            if ((f <<= 1) <= *++xp)
              break;            /* enough codes to use up j bits */
            f -= *xp;           /* else deduct codes from patterns */
          }
        }
        z = 1 << j;             /* table entries for j-bit table */

        /* allocate and link in new table ............................*/
        q = AllocHufTree (cshu, z+1);

        if (q == (HUFTREE *) 0)
        {
          return CS_E_NO_STACKMEM;       /* not enough memory ........*/
        }
        if(!t)
            return CS_E_BAD_HUF_TREE;
        *t = q + 1;
        *(t = &(q->v.t)) = (HUFTREE *)NULL;
        u[h] = ++q;                      /* table starts after link ..*/

        /* connect to last table, if there is one ................... */
        if (h)
        {
          x[h] = i;                    /* save pattern for backing up */
          r.b = (unsigned char)l;           /* bits to dump before this .. */
          r.e = (unsigned char)(16 + j);      /* bits in this table .......*/
          r.v.t = q;                     /* pointer to this table ....*/
          j = i >> (w - l);              /* (get around Turbo C bug) .*/
          u[h-1][j] = r;                 /* connect to last table ....*/
        }
      }

      /* set up table entry in r .....................................*/
      r.b = (unsigned char)(k - w);
      if (p >= v + n)
      {
        r.e = INVALIDCODE;             /* out of values--invalid code */
      }
      else if (*p < s)
      {                         /* 256 is end-of-block code */
        r.e = (unsigned char)(*p < 256 ? LITCODE : EOBCODE);
        r.v.n = (unsigned short) *p;  /* simple code is just the value*/
        p++;
      }
      else
      {
        if (!e || !d || (*p - s >=(unsigned)ll) )
            return CS_E_BAD_HUF_TREE;
        r.e = (unsigned char) e[*p - s]; /*non-simple,look up in lists*/
        r.v.n = (unsigned short) d[*p - s];
        p++;
      }

      /* fill code-like entries with r ...............................*/
      f = 1 << (k - w);
      for (j = i >> w; j < z; j += f)
        q[j] = r;

      /* backwards increment the k-bit code i ........................*/
      for (j = 1 << (k - 1); i & j; j >>= 1)
        i ^= j;
      i ^= j;

      /* backup over finished tables .................................*/
      while ((i & ((1 << w) - 1)) != x[h])
      {
        h--;                    /* don't need to update q ............*/
        w -= l;
      }
    }
  }

  /* Return true (1) if we were given an incomplete table ............*/
  return y != 0 && n != 1;
}


int FlushOut (CSHU *cshu, unsigned w)          /* number of bytes to flush */
/*--------------------------------------------------------------------*/
/* Do the equivalent of OUTB for the bytes Slide[0..w-1]. ............*/
/*--------------------------------------------------------------------*/
{
  unsigned n;
  const unsigned char *p;

  p = cshu->Slide + cshu->SlideOffset;
  if (w)
  {                                     /* try to fill up buffer .....*/
    if (cshu->MemOutoffset + (int)w <= cshu->MemOutsize)
    {
      memcpy (cshu->OutPtr, p, w);
      cshu->OutPtr       += w;
      cshu->BytesPending  = 0;
      cshu->MemOutoffset += w;
      cshu->SumOut       += w;
      cshu->SlideOffset   = 0;
    }
    else
    {
      n = (unsigned) (cshu->MemOutsize - cshu->MemOutoffset);
      memcpy (cshu->OutPtr, p, n);
      cshu->BytesPending  = (int)w - (int)n;
      cshu->MemOutoffset += n;
      cshu->SumOut       += n;
      cshu->SlideOffset  += n;

      return CS_END_OUTBUFFER;
    }
  }
  return 0;
}

int DecompCodes ( CSHU *cshu,
              int     *state,     /* state of last run ...............*/
              HUFTREE *tl,        /* literal/length decoder tables */
              HUFTREE *td,        /* distance decoder tables */
              int      bl,        /* number of bits decoded by tl[] */
              int      bd)        /* number of bits decoded by td[] */

/* inflate (decompress) the codes in a deflated (compressed) block.
   Return an error code or zero if it all goes ok. ...................*/
{
  REGISTER unsigned e;   /* table entry flag/number of extra bits */
  unsigned n, d;         /* length and index for copy */
  unsigned w;            /* current window position */
  unsigned ml, md;       /* masks for bl and bd bits */
  REGISTER int bitcount;
  int rc;

  /* make local copies of globals ....................................*/
  bitcount = 1;
  w = cshu->wp;                       /* initialize window position */

  /* precompute masks for speed ......................................*/
  ml = mask_bits[bl];
  md = mask_bits[bd];

  switch (*state)    /* depending on state in last run ...............*/
  {
    case 2:
      n = cshu->save_n;
      d = cshu->save_d;
      e = cshu->save_e;
      *state = 0;

      goto STATE_2;

    case 20:
      *state = 0;
      break;

    case 21:
      *state = 0;
      e = cshu->save_e;
      goto STATE_21;

    case 22:
      *state = 0;
      e = cshu->save_e;
      goto STATE_22;

    case 23:
      n = cshu->save_n;
      e = cshu->save_e;
      *state = 0;
      goto STATE_23;

    case 24:
      e = cshu->save_e;
      n = cshu->save_n;
      *state = 0;
      goto STATE_24;

    case 25:
      n = cshu->save_n;
      e = cshu->save_e;
      *state = 0;
      goto STATE_25;

    default: break;
  }

  *state = 0;

  for (;;)
  {
    NEEDBITS((unsigned)bl)
    if (bitcount == 0)
    {
      *state = 20;
      cshu->wp = w;

      return CS_END_INBUFFER;
    }

    if ((e = (cshu->htp = tl + ((unsigned)cshu->bb & ml))->e) > LITCODE)
    {
      do
      {
        if (e == INVALIDCODE) return CS_E_INVALIDCODE;

        DUMPBITS(cshu->htp->b)
        e -= LITCODE;

      STATE_21:
        NEEDBITS(e)
        if (bitcount == 0)
        {
          cshu->wp = w;
          cshu->save_e = e;
          *state = 21;

          return CS_END_INBUFFER;
        }
      }
      while ((e = (cshu->htp = cshu->htp->v.t + ((unsigned)cshu->bb & mask_bits[e]))->e) > LITCODE);
    }

    DUMPBITS(cshu->htp->b)

    if (e == LITCODE)           /* then it's a literal ...............*/
    {
      cshu->Slide[w++] = (unsigned char)cshu->htp->v.n;
      if (w == WSIZE)
      {
        if ((rc = FlushOut (cshu,w)) != 0)
        {
          cshu->wp = 0;

          *state = 1;
          return rc;
        }
        w = 0;
      }
    }
    else                        /* it's an EOB or a length ...........*/
    {
      /* exit if end of block ........................................*/
      if (e == EOBCODE)
      {
        break;
      }

      /* get length of block to copy .................................*/
    STATE_22:
      NEEDBITS(e)
      if (bitcount == 0)
      {
        cshu->wp = w;
        cshu->save_e = e;
        *state = 22;
        return CS_END_INBUFFER;
      }
      n = cshu->htp->v.n + ((unsigned)cshu->bb & mask_bits[e]);
      DUMPBITS(e);

      /* decode distance of block to copy ............................*/
    STATE_23:
      NEEDBITS((unsigned)bd)
      if (bitcount == 0)
      {
        cshu->wp = w;
        cshu->save_n = n;
        cshu->save_e = e;
        *state = 23;
        return CS_END_INBUFFER;
      }

      if ((e = (cshu->htp = td + ((unsigned)cshu->bb & md))->e) > LITCODE)
      {
        do
        {
          if (e == INVALIDCODE) return CS_E_INVALIDCODE;

          DUMPBITS(cshu->htp->b)
          e -= LITCODE;
        STATE_24:
          NEEDBITS(e)
          if (bitcount == 0)
          {
            cshu->wp = w;
            cshu->save_e = e;
            cshu->save_n = n;
            *state = 24;
            return CS_END_INBUFFER;
          }
        }
        while ((e = (cshu->htp = cshu->htp->v.t + ((unsigned)cshu->bb & mask_bits[e]))->e) > LITCODE);
      }

      DUMPBITS(cshu->htp->b)

    STATE_25:
      NEEDBITS(e)
      if (bitcount == 0)
      {
        cshu->wp = w;

        cshu->save_e = e;
        cshu->save_n = n;
        *state = 25;
        return CS_END_INBUFFER;
      }

      d = w - cshu->htp->v.n - ((unsigned)cshu->bb & mask_bits[e]);
      DUMPBITS(e)

      /* do the copy .................................................*/
      do
      {
        n -= (e = (e = WSIZE - ((d &= WSIZE-1) > w ? d : w)) > n ? n : e);

        if (w - d >= e)    /* (this test assumes unsigned comparison) */
        {
          memcpy (cshu->Slide + w, cshu->Slide + d, e);
          w += e;
          d += e;
        }
        else                /* do it slow to avoid memcpy() overlap ..*/
        {
          do
          {
            cshu->Slide[w++] = cshu->Slide[d++];
          } while (--e);
        }

        if (w == WSIZE)
        {
          if ((rc = FlushOut (cshu,w)) != 0)
          {
            cshu->wp = 0;

            cshu->save_n = n;
            cshu->save_d = d;
            cshu->save_e = e;
            *state = 2;
            return rc;
          }
        STATE_2:
          w = 0;
        }
      } while (n);
    }
  }

  cshu->wp = w;                       /* restore global window pointer .....*/

  return 0;
}

int
DecompFixed (CSHU *cshu, int *state)
/*--------------------------------------------------------------------*/
/* Decompress an fixed Huffman codes block.                           */
/*--------------------------------------------------------------------*/
{
  int i, rc;               /* temporary variable */
  unsigned l[288];         /* length list for BuildHufTree */

  if (*state == 0)
  {
    /* set up literal table, make a complete, but wrong code set .....*/
    for (i = 0; i < 144; i++) l[i] = 8;
    for (; i < 256; i++) l[i] = 9;
    for (; i < 280; i++) l[i] = 7;
    for (; i < 288; i++) l[i] = 8;

    cshu->blitlen = 7;
    rc = BuildHufTree (cshu, l, 288, 257, cplens, cplext, CPLENS_LEN, &(cshu->tlitlen), &(cshu->blitlen));
    if (rc)
    {
      cshu->AllocStackSize = 0;
      return rc;
    }

    /* set up distance table .........................................*/
    for (i = 0; i < 30; i++) l[i] = 5; /* make an incomplete code set */

    cshu->bdistlen = 5;
    if ((rc = BuildHufTree (cshu, l, 30, 0, cpdist, cpdext, CPLENS_LEN, &(cshu->tdistcode), &(cshu->bdistlen))) < 0)
    {
      cshu->AllocStackSize = 0;
      return rc;
    }
  }

  /* decompress until an end-of-block code ...........................*/
  if ((rc = DecompCodes (cshu, state, cshu->tlitlen, cshu->tdistcode, cshu->blitlen, cshu->bdistlen)) != 0)
    return rc;

  /* free the decoding tables, return ................................*/
  cshu->AllocStackSize = 0;

  return 0;
}


int DecompDynamic (CSHU *cshu, int *state)
/*--------------------------------------------------------------------*/
/* Decompress an dynamic Huffman Code block.                          */
/*--------------------------------------------------------------------*/
{
  unsigned j;

  REGISTER int bitcount;
  int rc;

  bitcount = 1;

  switch (*state)
  {
    case 0:
    case 5:
      NEEDBITS(5)
      if (bitcount == 0)
      {
        *state = 5;
        return CS_END_INBUFFER;
      }
                                    /* number of literal/length codes */
      cshu->dd_nl = 257 + ((unsigned)cshu->bb & 0x1f);
      DUMPBITS(5)

    case 6:
      NEEDBITS(5)
      if (bitcount == 0)
      {
        *state = 6;
        return CS_END_INBUFFER;
      }

      cshu->dd_nd = 1 + ((unsigned)cshu->bb & 0x1f);  /* number of distance codes ....*/
      DUMPBITS(5)

    case 7:
      NEEDBITS(4)
      if (bitcount == 0)
      {
        *state = 7;
        return CS_END_INBUFFER;
      }

      cshu->dd_nb = 4 + ((unsigned)cshu->bb & 0xf);   /* number of bit length codes ..*/
      DUMPBITS(4)

      if (cshu->dd_nl > 286 || cshu->dd_nd > 30)
        return CS_E_BADLENGTH;        /* bad lengths .................*/

      *state = 0;
      break;

    case 8:
      j = cshu->dd_jj;
      *state = 0;
      goto STATE_8;

    case 9:
      *state = 0;
      goto STATE_9;

    case 10:
      *state = 0;
      goto STATE_10;

    case 11:
      *state = 0;
      goto STATE_11;

    case 12:
      *state = 0;
      goto STATE_12;

    default: break;
  }

  if (*state == 0)
  {
    cshu->dd_jj = 0;
    for (j = cshu->dd_jj; j < cshu->dd_nb; j++)  /* read in bit-length-code lengths ....*/
    {
    STATE_8:
      NEEDBITS(3)
      if (bitcount == 0)
      {
        cshu->dd_jj = j;
        *state = 8;
        return CS_END_INBUFFER;
      }

      cshu->dd_ll[border[j]] = (unsigned)cshu->bb & 7;
      DUMPBITS(3)
    }

    for (; j < 19; j++) cshu->dd_ll[border[j]] = 0;

    /* build decoding table for trees--single level, 7 bit lookup ....*/
    cshu->dd_bl = 7;
    if ((rc = BuildHufTree (cshu, cshu->dd_ll, 19, 19, NULL, NULL, CPLENS_LEN, &(cshu->dd_tl), &(cshu->dd_bl))) != 0)
    {
      cshu->AllocStackSize = 0;
      return rc;                   /* incomplete code set ............*/
    }

    cshu->dd_nolen = cshu->dd_nl + cshu->dd_nd;
    cshu->dd_maskbit = mask_bits[cshu->dd_bl];
    cshu->dd_ii = cshu->dd_lastlen = 0;
                    /* read in literal and distance code lengths .....*/
    while ((unsigned)cshu->dd_ii < cshu->dd_nolen)
    {
    STATE_9:
      NEEDBITS((unsigned)cshu->dd_bl)
      if (bitcount == 0)
      {
        *state = 9;
        return CS_END_INBUFFER;
      }

      j = (cshu->dd_td = cshu->dd_tl + ((unsigned)cshu->bb & cshu->dd_maskbit))->b;
      DUMPBITS(j)
      j = cshu->dd_td->v.n;
      if (j < 16)                 /* length of code in bits (0..15) ..*/
        cshu->dd_ll[cshu->dd_ii++] = cshu->dd_lastlen = j;          /* save last length in l ...........*/
      else if (j == 16)           /* repeat last length 3 to 6 times .*/
      {
      STATE_10:
        NEEDBITS(2)
        if (bitcount == 0)
        {
          *state = 10;
          return CS_END_INBUFFER;
        }
        j = 3 + ((unsigned)cshu->bb & 3);
        DUMPBITS(2)
        if ((unsigned)cshu->dd_ii + j > cshu->dd_nolen) return CS_E_INVALIDCODE;
        while (j--) cshu->dd_ll[cshu->dd_ii++] = cshu->dd_lastlen;
      }
      else if (j == 17)           /* 3 to 10 zero length codes .......*/
      {
      STATE_11:
        NEEDBITS(3)
        if (bitcount == 0)
        {
          *state = 11;
          return CS_END_INBUFFER;
        }

        j = 3 + ((unsigned)cshu->bb & 7);
        DUMPBITS(3)
        if ((unsigned)cshu->dd_ii + j > cshu->dd_nolen) return CS_E_INVALIDCODE;
        while (j--) cshu->dd_ll[cshu->dd_ii++] = 0;
        cshu->dd_lastlen = 0;
      }
      else                    /* j == 18: 11 to 138 zero length codes */
      {
      STATE_12:
        NEEDBITS(7)
        if (bitcount == 0)
        {
          *state = 12;
          return CS_END_INBUFFER;
        }

        j = 11 + ((unsigned)cshu->bb & 0x7f);
        DUMPBITS(7)
        if ((unsigned)cshu->dd_ii + j > cshu->dd_nolen) return CS_E_INVALIDCODE;
        while (j--) cshu->dd_ll[cshu->dd_ii++] = 0;
        cshu->dd_lastlen = 0;
      }
    }

    /* build the decoding tables for literal/length and distance codes*/
    cshu->dd_bl = LBITS;
    if ((rc = BuildHufTree (cshu, cshu->dd_ll, cshu->dd_nl, 257, cplens, cplext, CPLENS_LEN, &(cshu->dd_tl), &(cshu->dd_bl))) !=0)
    {
      cshu->AllocStackSize = 0;
      return rc;                   /* incomplete code set ............*/
    }

    cshu->dd_bd = DBITS;
    rc = BuildHufTree (cshu, cshu->dd_ll + cshu->dd_nl, cshu->dd_nd, 0, cpdist, cpdext, CPLENS_LEN, &(cshu->dd_td), &(cshu->dd_bd));
    if (rc)
    {
      cshu->AllocStackSize = 0;
      return rc;      /* incomplete code set or no stack .............*/
    }
  }

  /* decompress until an end-of-block code ...........................*/
  if ((rc = DecompCodes (cshu, state, cshu->dd_tl, cshu->dd_td, cshu->dd_bl, cshu->dd_bd)) != 0)
    return rc;

  /* free the decoding tables, return ................................*/
  cshu->AllocStackSize = 0;
  return 0;
}

int
DecompBlock (CSHU *cshu, int *state, int *e) /* state, last block flag */
/*--------------------------------------------------------------------*/
/* Decompress a block of codes                                        */
/*--------------------------------------------------------------------*/
{
  REGISTER int bitcount;       /* bitcount ...........................*/

  bitcount = 1;

  switch (*state)
  {
    case 0:
    case 3:
                /* read in last block bit ............................*/
      NEEDBITS(1)
      if (bitcount == 0)
      {
        *state = 3;
        return CS_END_INBUFFER;
      }

      *e = (int)cshu->bb & 1;
      DUMPBITS(1)

    case 4:     /* read in block type ................................*/
      NEEDBITS(2)
      if (bitcount == 0)
      {
        *state = 4;
        return CS_END_INBUFFER;
      }

      cshu->blocktype = (unsigned)cshu->bb & 3;
      DUMPBITS(2)

      *state = 0;
      break;

    default: break;
  }

  switch (cshu->blocktype)   /* inflate that block type ............................*/
  {
    case 2:  return DecompDynamic (cshu,state);
    case 1:  return DecompFixed (cshu,state);
    default: return CS_E_UNKNOWN_TYPE;
  }
}

int CsDecomprLZH (CSHU     * cshu,
                  SAP_BYTE * inp,                 /* ptr input .......*/
                  SAP_INT    inlen,               /* len of input ....*/
                  SAP_BYTE * outp,                /* ptr output ......*/
                  SAP_INT    outlen,              /* len output ......*/
                  SAP_INT    option,              /* decompr. option  */
                  SAP_INT *  bytes_read,          /* bytes read ......*/
                  SAP_INT *  bytes_decompressed)  /* bytes decompr.   */
/*--------------------------------------------------------------------*/
/* Lempel-Ziv-Huffman                                                 */
/*--------------------------------------------------------------------*/
{
  int rc;

  cshu->MemOutbuffer = outp;
  cshu->MemOutoffset = 0;
  cshu->MemOutsize   = (unsigned) outlen;

  cshu->OutPtr       = outp;

  cshu->MemInbuffer  = inp;
  cshu->MemInoffset  = 0;
  cshu->MemInsize    = (unsigned) inlen;

  if (inlen == 0 && outlen == 0) return CS_E_BOTH_ZERO;

  if (option & CS_INIT_DECOMPRESS)
  {
    cshu->BytesPending   = 0;           /* bytes to flush in next run ......*/
    cshu->SlideOffset    = 0;           /* offset in window ................*/
    cshu->AllocStackSize = 0;           /* stack counter for trees .........*/
    cshu->staterun       = 0;           /* state of uncompress .............*/
    cshu->lastblockflag  = 0;           /* last block flag (1 = last block) */

    if (inlen < CS_HEAD_SIZE) return CS_E_IN_BUFFER_LEN;

    cshu->OrgLen = CsGetLen (inp);
    if (cshu->OrgLen < 0)
      return CS_E_FILENOTCOMPRESSED;   /* Input not compressed .......*/

    cshu->SumOut = 0;
    cshu->MemInoffset = CS_HEAD_SIZE;

    /* initialize window, bit buffer .................................*/
    cshu->wp = 0;
    cshu->bk = 0;
    cshu->bb = 0;
    cshu->save_e = cshu->save_n = cshu->save_d = 0;
    cshu->NonSenseflag = 0;
    if (inlen == CS_HEAD_SIZE) return CS_END_INBUFFER;
  }

  if (cshu->NonSenseflag == 0)
  {
    NoBits (cshu);
    cshu->NonSenseflag = 1;
  }

  if (cshu->staterun == 1 || cshu->staterun == 2)   /* end of outbuffer in last run ....*/
  {
    rc = FlushOut (cshu,cshu->BytesPending);
    if (rc || ((SAP_INT)cshu->SumOut >= cshu->OrgLen))
    {
      *bytes_read         = cshu->MemInoffset;
      *bytes_decompressed = cshu->MemOutoffset;

      if (rc) return rc;
      *bytes_read = inlen;
      return CS_END_OF_STREAM;
    }
  }

  do                           /* decompress until the last block ....*/
  {
    rc = DecompBlock (cshu, &(cshu->staterun), &(cshu->lastblockflag));
    if (rc) break;
  } while (!(cshu->lastblockflag));

  if ((rc == 0) && (cshu->staterun == 0) && (cshu->lastblockflag))
  {
    rc = FlushOut (cshu, cshu->wp);        /* flush out Slide ....................*/
    if (rc) cshu->staterun = 2;
  }
                               /* set output params ..................*/
  *bytes_read         = cshu->MemInoffset;
  *bytes_decompressed = cshu->MemOutoffset;

  if (rc) return rc;
  *bytes_read = inlen;
  return CS_END_OF_STREAM;     /* all done ...........................*/
}

/* Macros for STACK CHECK in CsDecomp */
#ifdef CS_STACK_CHECK

/*
#define STACK_OVERFLOW_CHECK(p) ((p) >= ((BYTE_TYP *)&CsDeInterBuf[csbufsize2 / 4 - 1]))
*/
#define STACK_OVERFLOW_CHECK(p) ((p) >= (csc->stack_end))

#define STACK_UNDERFLOW_CHECK(p) ((p) < (DE_STACK))

#define OVERFLOW_CHECK 	                 \
      if (STACK_OVERFLOW_CHECK(stackp))  \
	  {                                  \
        return CS_E_STACK_OVERFLOW;      \
	  }

#define UNDERFLOW_CHECK                  \
	  if (STACK_UNDERFLOW_CHECK(stackp))  \
	  {                                  \
        return CS_E_STACK_UNDERFLOW;     \
	  }

#else

#define OVERFLOW_CHECK
#define UNDERFLOW_CHECK

#endif

CODE_INT DE_STACK_OFFSET = 1<<(CS_BITS+1);

CODE_INT GetCode (struct CSC *csc)
/*--------------------------------------------------------------------*/
/* Read the next code from input stream                               */
/*--------------------------------------------------------------------*/
/* Returns: code on default                                           */
/*          CS_IEND_INBUFFER on end of input buffer                   */
/*                                                                    */
/*--------------------------------------------------------------------*/
{
  register CODE_INT code;

  register int r_off, bits;
  register BYTE_TYP *bp = csc->buf1;
  /* 2 ** i - 1 (i=0..8) ...............................................*/
  static BYTE_TYP rmask[9] =
       {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};
  for (;;)
  {
    if (csc->get_r_bits > 0)   /* does not fit in last run .....*/
    {
      csc->get_r_bits = (SAP_INT) MIN (csc->get_r_bits, csc->end_inbuf - csc->in_ptr);
      csc->get_r_bits = MAX (0, csc->get_r_bits);
      BYTES_IN (csc->buf1 + csc->get_size, csc->in_ptr, csc->get_r_bits)
      csc->get_size += csc->get_r_bits;
      csc->get_r_bits = 0;
      csc->get_size = (csc->get_size << 3) - (csc->n_bits - 1);
      csc->csc_offset = 0;
    }
    else
    if (csc->clear_flg > 0 || csc->csc_offset >= csc->get_size || csc->free_ent > csc->maxcode)
    {
     /*
      * If the next entry will be too big for the current code
      * get_size, then we must increase the get_size.
      * This implies reading a new buffer full, too.
      */

      if (csc->free_ent > csc->maxcode)
      {
        (csc->n_bits)++;
        if (csc->n_bits == csc->maxbits)
          csc->maxcode = csc->maxmaxcode;   /* won't get any bigger now .....*/
        else
          csc->maxcode = MAXCODE(csc->n_bits);
      }

      if (csc->clear_flg > 0)
      {
        csc->maxcode = MAXCODE (csc->n_bits = INIT_CS_BITS);
        csc->clear_flg = 0;
      }

      csc->get_size = (SAP_INT) (csc->end_inbuf - csc->in_ptr);
      if (csc->get_size < csc->n_bits)        /* does not fit in buffer .....*/
      {
        if (csc->get_size <= 0)
        {
          code = CS_IEND_INBUFFER;  /* end of stream ..............*/
          break;
        }
        if (csc->get_r_bits < 0)         /* initial !!! ................*/
          csc->get_r_bits = 0;
        else                        /* end of input buffer ........*/
        {
          BYTES_IN (csc->buf1, csc->in_ptr, csc->get_size)
          csc->get_r_bits = csc->n_bits - csc->get_size;
          csc->csc_offset = 0;
          code = CS_IEND_INBUFFER;
          break;
        }
      }
      else                               /* min (n_bits, get_size) .*/
        csc->get_size = csc->n_bits;

      BYTES_IN (csc->buf1, csc->in_ptr, csc->get_size)
      csc->csc_offset = 0;

      /* Round get_size down to integral number of codes ...........*/
      csc->get_size = (csc->get_size << 3) - (csc->n_bits - 1);
    }

    /* Do all the terrible bit staff ...............................*/
    r_off = csc->csc_offset;
    bits = csc->n_bits;

    bp += (r_off >> 3);
    r_off &= 7;

    /* Get first part (low order bits) .............................*/
    code = (int)*bp >> r_off;
    bp++;
    r_off = 8 - r_off;
    bits -= r_off;

    /* Get any 8 bit parts in the middle (<=1 for up to 16 bits)    */
    if (bits >= 8)
    {
      code |= (int) *bp << r_off;
      bp++;
      r_off += 8;
      bits -= 8;
    }

    /* high order bits .............................................*/
    code |= ((int)*bp & rmask[bits]) << r_off;
    csc->csc_offset += csc->n_bits;
    break;
  }

  return code;
}

int CsDecomprLZC (CSC      * csc,
                  SAP_BYTE * inbuf,
                  SAP_INT    inlen,
                  SAP_BYTE * outbuf,
                  SAP_INT    outlen,
                  SAP_INT    option,
                  SAP_INT *  bytes_read,
                  SAP_INT *  bytes_written)
{
/*--------------------------------------------------------------------*/
/* LZC decompress                                                     */
/*                                                                    */
/* Adaptive Dictionary Compression                                    */
/*   Lempel-Zip-Welch-Thomas                                          */
/*                                                                    */
/* Input:                                                             */
/* -----                                                              */
/*        inbuf             Pointer to input memory                   */
/*        inlen             Length of input memory                    */
/*        outbuf            Pointer to output area                    */
/*        outlen            Length of output area                     */
/*        option            Compress option:                          */
/*                             CS_INIT_COMPRESS      initial          */
/*                             CS_NORMAL_COMPRESS                     */
/*                                                                    */
/* Output:                                                            */
/* ------                                                             */
/*        bytes_read        Bytes read from input buffer              */
/*        bytes_written     Bytes decompressed to output buffer       */
/*                                                                    */
/* Internal Functions:                                                */
/* ------------------                                                 */
/*       GetCode               Get a code from input buffer           */
/*                                                                    */
/* Return Code:                                                       */
/* -----------                                                        */
/*        CS_END_OF_STREAM     End of input stream reached            */
/*        CS_END_INBUFFER      End of input buffer reached            */
/*        CS_END_OUTBUFFER     End of output buffer reached           */
/*                                                                    */
/*        CS_E_OUT_BUFFER_LEN  Output buffer length to short          */
/*        CS_E_IN_BUFFER_LEN   Input buffer length to short           */
/*        CS_E_MAXBITS_TOO_BIG No internal memory to decompress       */
/*        CS_E_INVALID_LEN     inlen < 0 or outlen < CS_BITS          */
/*        CS_E_FILENOTCOMPRESSED Input is not compressed              */
/*        CS_E_IN_EQU_OUT      Same addr for input and output buffer  */
/*        CS_E_INVALID_ADDR    Invalid addr for input or output buffer*/
/*        CS_E_FATAL           Internal (should never happen)         */
/*                                                                    */
/*--------------------------------------------------------------------*/
{
  register BYTE_TYP *stackp;
  register CODE_INT code, oldcode = 0, incode, finchar = 0;
  register SAP_INT rest_lenr;

/*
  static BYTE_TYP *sstackp = (BYTE_TYP *) 0;

  static long dorg_len;
  static CODE_INT scode, soldcode, sincode, sfinchar;
  static int restart;
*/
#ifdef SAPonWINDOWS
  Suffixtab = (BYTE_TYP *) CsDeInterBuf;

  Prefixtab = (CODE_ENTRY *) CsDeWindowBuf;
#endif

  *bytes_read    = 0;                    /* init output parameters ...*/
  *bytes_written = 0;

  /* Check input parameters ..........................................*/
  if (inlen < 0)                         /* invalid len of inbuf .....*/
    return CS_E_IN_BUFFER_LEN;
                                         /* invalid addr .............*/
  if (inbuf == (BYTE_TYP *) 0 || outbuf == (BYTE_TYP *) 0)
    return CS_E_INVALID_ADDR;

  if (inbuf == outbuf)                   /* inbuf == outbuf: invalid !*/
    return CS_E_IN_EQU_OUT;

  csc->end_inbuf  = inbuf + inlen;            /* set start & end ptrs .....*/
  csc->end_outbuf = outbuf + outlen;
  csc->outptr     = outbuf;
  rest_lenr  = (SAP_INT)csc->rest_len;        /* push to register .........*/

  if (option & CS_INIT_DECOMPRESS)       /* only initial .............*/
  {
    csc->sstackp = (BYTE_TYP *) 0;
    csc->restart    =  0;
    csc->csc_offset =  0;
    csc->get_size   =  0;
    csc->get_r_bits = -1;
/*    csc->stack_end = &(csc->Suffixtab[csbufsize2 - 1]); */

    if (inlen < CS_HEAD_SIZE)         /* input buffer too small ......*/
      return CS_E_IN_BUFFER_LEN;

    csc->dorg_len = CsGetLen (inbuf);       /* get sum length               */

    if (csc->dorg_len < 0)                  /* and check if file is compr. .*/
      return (CS_E_FILENOTCOMPRESSED);

    csc->maxbits        = inbuf[7];        /* get max. bits ...............*/
    csc->block_compress = csc->maxbits & BLOCK_MASK;
    csc->maxbits       &= BIT_MASK;
    csc->maxmaxcode     = (CODE_INT) 1 << csc->maxbits;
    csc->maxcode        = MAXCODE(csc->n_bits = INIT_CS_BITS);

    if (csc->maxbits > CS_BITS + 1)     /* not enough memory to decompress */
      return CS_E_MAXBITS_TOO_BIG;

    /* get version and algorithm .....................................*/
    /* not supported at the moment ...................................*/

    for (code = 255; code >= 0; code--)    /* init. code table .......*/
    {
      TAB_PREFIXOF(code) = 0;
      TAB_SUFFIXOF(code) = (BYTE_TYP) code;
    }

    csc->free_ent = ((csc->block_compress) ? FIRST : 256);   /* first entry ....*/

    csc->in_ptr    = inbuf + CS_HEAD_SIZE; /* skip header .................*/
    csc->rest_len  = csc->dorg_len;              /* save sum length .............*/
    rest_lenr = (SAP_INT)csc->rest_len;
    stackp    = DE_STACK;             /* init. stack ptr .............*/

    if (outlen == 0)                  /* End of output buffer ........*/
    {
      code = CS_END_OUTBUFFER;
      goto ende;
    }

    if (csc->in_ptr >= csc->end_inbuf)          /* End of input buffer .........*/
    {
      code = CS_END_INBUFFER;
      goto ende;
    }
  }
  else                                /* not initial .................*/
  {
    csc->in_ptr  = inbuf;
    stackp  = csc->sstackp;                /* restore states ..............*/
    finchar = csc->sfinchar;
    oldcode = csc->soldcode;

    if (outlen <= 0)                  /* min. size for outbuffer .....*/
      return CS_E_OUT_BUFFER_LEN;

    if (rest_lenr <= 0)               /* end of input ................*/
    {
      code = CS_END_OF_STREAM;
      goto ende;
    }

    if (csc->restart)  /* output buffer to small in last run ..............*/
    {
      /* restore machine state .......................................*/
      code    = csc->scode;
      incode  = csc->sincode;
      csc->restart = 0;
      goto contin;
    }
  }

  if (csc->get_r_bits == -1)               /* init. decoding ..............*/
  {
    finchar = oldcode = (CODE_INT) GetCode (csc);
    csc->get_r_bits = 0;                   /* not redundant !!! ...........*/

    if (outlen == 0)                  /* must have some space ........*/
    {
      code = CS_END_OUTBUFFER;
      goto ende;
    }

    *csc->outptr++ = (BYTE_TYP) finchar;
    if (--rest_lenr <= 0)             /* End of stream ...............*/
    {
      code = CS_END_OF_STREAM;
      goto ende;
    }
  }

  for (;;)                            /* until not end of inbuf ......*/
  {
    code = GetCode (csc);
    if (code < 0) break;

    if ((code == CLEAR) && csc->block_compress)
    {
      /* clear code table ............................................*/
      memset (csc->Prefixtab, '\0', sizeof (CODE_ENTRY) << 8);
      csc->clear_flg = 1;
      csc->free_ent = FIRST - 1;

      if ((code = GetCode (csc)) < 0)
        break;
    }

    incode = code;

    /* Special case for ababa string .................................*/
    if (code >= csc->free_ent)
    {
      *stackp++ = (BYTE_TYP) finchar;
      OVERFLOW_CHECK
      code = oldcode;
    }

    /* Generate output characters in reverse order ...................*/
    while (code >= 256)
    {
      /* Check for end of stack */
      if (stackp >= (DE_STACK + DE_STACK_OFFSET)){
          return (CS_E_STACK_OVERFLOW);
      }
      *stackp++ = TAB_SUFFIXOF(code);
      OVERFLOW_CHECK
      code = TAB_PREFIXOF(code);
    }

    finchar = TAB_SUFFIXOF(code);
    *stackp++ = (BYTE_TYP) finchar;
    OVERFLOW_CHECK

contin:
    /* and put them out in forward order .............................*/
    for (;;)
    {
      if (csc->outptr >= csc->end_outbuf)        /* End of outbuffer ...........*/
      {
        csc->scode    = code;
        csc->sincode  = incode;
        csc->restart  = 1;
        code     = CS_END_OUTBUFFER;
        goto ende;
      }

      *csc->outptr++ = *--stackp;

      if (--rest_lenr <= 0)            /* End of Stream ..............*/
      {
        code = CS_END_OF_STREAM;
        goto ende;
      }

      if (stackp == DE_STACK) break;   /* End of Stack ...............*/
    }  /* end for (;;) ...............................................*/

    /* Generate the new entry ........................................*/
    if ((code = csc->free_ent) < csc->maxmaxcode)
    {
      TAB_PREFIXOF(code) = (CODE_ENTRY)oldcode;
      TAB_SUFFIXOF(code) = (BYTE_TYP) finchar;
      csc->free_ent = code + 1;
    }

    /* Remember previous code ........................................*/
    oldcode = incode;

  }  /* end for (;;) .................................................*/

ende:
  csc->sstackp  = stackp;               /* save state of the compressor ...*/
  csc->soldcode = oldcode;
  csc->sfinchar = finchar;
  csc->rest_len = rest_lenr;
                                   /* set output parameters ..........*/
  *bytes_written = (SAP_INT) (csc->outptr - outbuf);
  *bytes_read    = (SAP_INT) (csc->in_ptr - inbuf);

  if (code == CS_IEND_INBUFFER) return CS_END_INBUFFER;
  else
    return code;
}
}

int CsDecompr (CSHDL    * hdl,           /* handle           */
               SAP_BYTE * inbuf,         /* ptr input .......*/
               SAP_INT    inlen,         /* len of input ....*/
               SAP_BYTE * outbuf,        /* ptr output ......*/
               SAP_INT    outlen,        /* len output ......*/
               SAP_INT    option,        /* decompr. option  */
               SAP_INT *  bytes_read,    /* bytes read ......*/
               SAP_INT *  bytes_decompressed) /* bytes decompr.  */
/*--------------------------------------------------------------------*/
/*     Decompress                                                     */
/*                                                                    */
/* Adaptive Dictionary Compression                                    */
/*   Lempel-Zip                                                       */
/*                                                                    */
/* Input:                                                             */
/* -----                                                              */
/*        inbuf             Pointer to input memory                   */
/*        inlen             Length of input memory                    */
/*        outbuf            Pointer to output area                    */
/*        outlen            Length of output area                     */
/*        option            DeCompress option:                        */
/*                             CS_INIT_DECOMPRESS      initial        */
/*                             CS_NORMAL_COMPRESS                     */
/*                                                                    */
/* Output:                                                            */
/* ------                                                             */
/*        bytes_read        Bytes read from input buffer              */
/*        bytes_written     Bytes decompressed to output buffer       */
/*                                                                    */
/* Return Code:                                                       */
/* -----------                                                        */
/*        CS_END_OF_STREAM     End of input stream reached            */
/*        CS_END_INBUFFER      End of input buffer reached            */
/*        CS_END_OUTBUFFER     End of output buffer reached           */
/*                                                                    */
/*        CS_E_OUT_BUFFER_LEN  Output buffer length to short          */
/*        CS_E_IN_BUFFER_LEN   Input buffer length to short           */
/*        CS_E_MAXBITS_TOO_BIG No internal memory to decompress       */
/*        CS_E_INVALID_LEN     inlen < 0 or outlen < CS_BITS          */
/*        CS_E_FILENOTCOMPRESSED Input is not compressed              */
/*        CS_E_IN_EQU_OUT      Same addr for input and output buffer  */
/*        CS_E_INVALID_ADDR    Invalid addr for input or output buffer*/
/*        CS_E_FATAL           Internal (should never happen)         */
/*                                                                    */
/*--------------------------------------------------------------------*/
{

  if (option & CS_INIT_DECOMPRESS)
  {
    if (inlen < CS_HEAD_SIZE) return CS_E_IN_BUFFER_LEN;
  }

  switch (CsGetAlgorithm (inbuf))
  {
    case CS_ALGORITHM_LZC:
      return CsDecomprLZC (&hdl->handle.csc, inbuf, inlen, outbuf, outlen,
                           option, bytes_read, bytes_decompressed);
    case CS_ALGORITHM_LZH:
      return CsDecomprLZH (&hdl->handle.cshu, inbuf, inlen, outbuf, outlen,
                           option, bytes_read, bytes_decompressed);

    default: return CS_E_UNKNOWN_ALG;
  }
}
