%{
#include <glib.h>
#include "rt-tokdefs.h"
guint8* parse_bytes(char *text);
enum nibble_t { high, low };
static char *in_buffer;

/* from libpcap */
#ifdef FLEX_SCANNER
#define YY_NO_UNPUT
#undef YY_INPUT
#define YY_INPUT(buf, result, max)\
 {\
	char *src = in_buffer;\
	int i;\
\
	if (*src == 0)\
		result = YY_NULL;\
	else {\
		for (i = 0; *src && i < max; ++i)\
			buf[i] = *src++;\
		in_buffer += i;\
		result = i;\
	}\
 }
#else
#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)
#endif


%}

N	([0-9]+|(0X|0x)[0-9A-Fa-f]+)
B	[0-9A-Fa-f][0-9A-Fa-f]?([-:.]?[0-9A-Fa-f][0-9A-Fa-f]?)*
W	[A-Za-z_]
quoted	\"[^"\n]*["\n]

%%

[\n\t ]+	/* eat whitespace */

{quoted} {
	wtap_lval.s = g_string_new(wtap_text + 1);
	g_string_truncate(wtap_lval.s, strlen(wtap_text) - 2);
	return QUOTED;
}

";"		return ';';
","		return ',';
"("		return '(';
")"		return ')';
"@"		return '@';

/* ct-compile: lex tokens */

eq				return EQ;
ne				return NE;

{B}	{
	wtap_lval.b = parse_bytes(wtap_text);
	return BYTES;
}

{N} {
	wtap_lval.d = atoi(wtap_text);
	return NUMBER;
}

{W}+	{
	wtap_lval.s = g_string_new(wtap_text);
	return TEXT;
	}

%%

guint8*
parse_bytes(char *text)
{
	guint8		buffer[256];
	guint8		index = 0;
	char		*cp;
	char		character;
	guint8		byte_val=0;
	gchar		*dup_ptr;
	enum nibble_t	nibble = high;

	for (cp = text; (*cp != '\x0') && index < 256; cp++) {
		character = *cp;

		if (nibble == high) {
			/* assumes ASCII, not EBCDIC */
			if (character >= '0' && character <= '9') {
					byte_val = (character - '0') << 4;
			}
			else if (character >= 'A' && character <= 'F') {
					byte_val = (character - 'A' + 10) << 4;
			}
			else if (character >= 'a' && character <= 'f') {
					byte_val = (character - 'a' + 10) << 4;
			}
			else {
				continue;
			}
			nibble = low;
			continue;
		}
		else {
			/* assumes ASCII, not EBCDIC */
			if (character >= '0' && character <= '9') {
					byte_val += (character - '0');
			}
			else if (character >= 'A' && character <= 'F') {
					byte_val += (character - 'A' + 10);
			}
			else if (character >= 'a' && character <= 'f') {
					byte_val += (character - 'a' + 10);
			}
			else {
				byte_val >>= 4;
			}
			nibble = high;

			buffer[index] = byte_val;
			index++;
		}

	}

	/* did we finish mid-nibble? */
	if (nibble == low) {
		buffer[index] = byte_val >> 4;
		index++;
	}

	dup_ptr = g_malloc(index + 1);
	dup_ptr[0] = index;
	memcpy(dup_ptr + 1, buffer, index);
	return dup_ptr;
}


void wtap_error(char *string)
{
	g_error("%s\n",string);
	exit(0);
}

void
wtap_lex_init(char *buf)
{
	in_buffer = buf;
}

int
yywrap()
{
	return 1;
}

