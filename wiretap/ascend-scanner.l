%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap.h"
#include "ascend.h"
#include "ascend-grammar.h"

struct ascend_phdr *pseudo_header;

int at_eof;
int mul, scratch;
%}

/* %option debug */
%option nostdinit

D [0-9]
H [A-Fa-f0-9]

XPFX XMIT-
RPFX RECV-
EPFX "ETHER "

%s sc_user
%s sc_sess
%s sc_task
%s sc_time_s
%s sc_time_u
%s sc_octets
%s sc_counter
%s sc_byte

%%

<INITIAL,sc_byte>{EPFX} {
  BEGIN(sc_user);
  ascendlval.d = ASCEND_PFX_ETHER;
  return PREFIX;
}

<INITIAL,sc_byte>{XPFX} {
  BEGIN(sc_user);
  ascendlval.d = ASCEND_PFX_PPP_X;
  return PREFIX;
}

<INITIAL,sc_byte>{RPFX} {
  BEGIN(sc_user);
  ascendlval.d = ASCEND_PFX_PPP_R;
  return PREFIX;
}

<sc_user>[^:]+ {
  BEGIN(sc_sess);
  if (pseudo_header != NULL) {
    strncpy(pseudo_header->user, ascendtext, ASCEND_MAX_STR_LEN);
    pseudo_header->user[ASCEND_MAX_STR_LEN - 1] = '\0';
  }
  return USERNAME;
}

<sc_sess>{D}+ {
  BEGIN(sc_task);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return SESSNUM;
}

<sc_task>{H}+ {
  BEGIN(sc_time_s);
  ascendlval.d = strtoul(ascendtext, NULL, 16);
  return TASKNUM;
}

<sc_time_s>{D}+ {
  BEGIN(sc_time_u);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return TIMEVAL;
}

<sc_time_u>{D}+ {
  BEGIN(sc_octets);
  /* We have the fractional portion of the time.  We want it converted
     to microseconds. */
  mul = 1000000;
  ascendlval.d = strtol(ascendtext, NULL, 10);
  for (scratch = ascendlval.d; scratch > 0; scratch /= 10)
    mul /= 10;
  ascendlval.d *= mul;
  return TIMEVAL;
}

<sc_octets>{D}+ {
  BEGIN(sc_counter);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return OCTETS;
}

<sc_counter,sc_byte>"["{H}{4}"]:" {
  BEGIN(sc_byte);
  return COUNTER;
}

<sc_byte>{H}{2} {
  ascendlval.b = strtol(ascendtext, NULL, 16);
  return BYTE;
}

{H}+ { return HEXNUM; }

task:|time:|octets { return KEYWORD; }

<<EOF>> { at_eof++; yyterminate(); }

. ;

%%

int ascendwrap() { return 1; };

void ascend_init_lexer(FILE *fh, FILE *nfh)
{
  yyin = fh;
  yyout = nfh;
  yyrestart(fh);
  BEGIN(INITIAL);
}
