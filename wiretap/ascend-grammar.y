/*
   Example 'wandsess' output data:
   
RECV-iguana:241:(task: B02614C0, time: 1975432.85) 49 octets @ 8003BD94
  [0000]: FF 03 00 3D C0 06 CA 22 2F 45 00 00 28 6A 3B 40 
  [0010]: 00 3F 03 D7 37 CE 41 62 12 CF 00 FB 08 20 27 00 
  [0020]: 50 E4 08 DD D7 7C 4C 71 92 50 10 7D 78 67 C8 00 
  [0030]: 00 
XMIT-iguana:241:(task: B04E12C0, time: 1975432.85) 53 octets @ 8009EB16
  [0000]: FF 03 00 3D C0 09 1E 31 21 45 00 00 2C 2D BD 40 
  [0010]: 00 7A 06 D8 B1 CF 00 FB 08 CE 41 62 12 00 50 20 
  [0020]: 29 7C 4C 71 9C 9A 6A 93 A4 60 12 22 38 3F 10 00 
  [0030]: 00 02 04 05 B4 
 */

%{
 
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap.h"
#include "buffer.h"
#include "ascend.h"

#define NFH_PATH "/dev/null"

extern void ascend_init_lexer(FILE *fh, FILE *nfh);
extern int at_eof;

int yyparse(void);
void yyerror(char *);

int bcur = 0, bcount;
guint32 secs, usecs, caplen, wirelen;
ascend_pkthdr header;
char *pkt_data;
FILE *nfh = NULL;

%}
 
%union {
gchar  *s;
guint32 d;
char    b;
}

%token <s> USERNAME HEXNUM KEYWORD COUNTER
%token <d> PREFIX SESSNUM TASKNUM TIMEVAL OCTETS
%token <b> BYTE

%type <s> username hexnum dataln datagroup
%type <d> prefix sessnum tasknum timeval octets
%type <b> byte bytegroup

%%

data_packet:
  | header datagroup
;

prefix: PREFIX;

username: USERNAME;

sessnum: SESSNUM;

tasknum: TASKNUM;

timeval: TIMEVAL;

octets: OCTETS;

hexnum: HEXNUM;

/*        1        2       3       4       5       6       7       8       9      10     11 */
header: prefix username sessnum KEYWORD tasknum KEYWORD timeval timeval octets KEYWORD HEXNUM {
  wirelen = $9;
  caplen = ($9 < ASCEND_MAX_PKT_LEN) ? $9 : ASCEND_MAX_PKT_LEN;
  if (bcount > 0 && bcount <= caplen)
    caplen = bcount;
  else
  secs = $7;
  usecs = $8;
  /* header.user is set in ascend-scanner.l */
  header.type = $1;
  header.sess = $3;
  header.task = $5;
  
  bcur = 0;
}
;
 
byte: BYTE {
  if (bcur < caplen) {
    pkt_data[bcur + ASCEND_PKTHDR_OFFSET] = $1;
    bcur++;
  }

  if (bcur >= caplen) {
    header.secs = secs;
    header.usecs = usecs;
    header.caplen = caplen;
    header.len = wirelen;
    memcpy(pkt_data, &header, ASCEND_PKTHDR_OFFSET);
    YYACCEPT;
  }
} 
;

/* There must be a better way to do this... */
bytegroup: byte
  | byte byte
  | byte byte byte
  | byte byte byte byte
  | byte byte byte byte byte
  | byte byte byte byte byte byte
  | byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte byte byte byte
;

dataln: COUNTER bytegroup;

datagroup: dataln
  | dataln dataln
  | dataln dataln dataln
  | dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln dataln dataln dataln
;

%%

void
init_parse_ascend()
{
  bcur = 0;
  at_eof = 0;
  
  /* In order to keep flex from printing a lot of newlines while reading
     the capture data, we open up /dev/null and point yyout at the null
     file handle. */
  if (! nfh) {
    nfh = fopen(NFH_PATH, "r");
  }
}

/* Parse the capture file.  Return the offset of the next packet, or zero
   if there is none. */
int
parse_ascend(FILE *fh, void *pd, int len)
{
  /* yydebug = 1; */
 
  ascend_init_lexer(fh, nfh);
  pkt_data = pd;
  bcount = len;
  
  /* Skip errors until we get something parsed. */
  if (yyparse())
    return 0;
  else
    return 1;
}

void
yyerror (char *s)
{
  /* fprintf (stderr, "%s\n", s); */
}
