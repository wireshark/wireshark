/* $Id: lemonflex-tail.inc,v 1.1 2001/02/01 20:21:25 gram Exp $ */

/* This file is #include'd at the bottom of a Lex/Flex scanner
for use with the Lemon parser. You must have #define'd:

MODNAME		module name for creating function names:

Prototypes:

void	MODNAME_scanner_text(char *text);
void	MODNAME_scanner_cleanup(void);
int	MODNAME_wrap(void);
*/

#include <cppmagic.h>

#define TEXT_FUNC	CONCAT(MODNAME,_scanner_text)
#define FILE_FUNC	CONCAT(MODNAME,_scanner_file)
#define CLEANUP_FUNC	CONCAT(MODNAME,_scanner_cleanup)
#define WRAP_FUNC	CONCAT(MODNAME,_wrap)


/* Resets scanner and assigns the char* argument
 * as the text to scan
 */
void
TEXT_FUNC (const char *text)
{
	yy_scan_string(text);
}

void
FILE_FUNC (FILE* fh)
{
	YY_BUFFER_STATE new_buffer;

	new_buffer = yy_create_buffer(fh, YY_BUF_SIZE);
	yy_switch_to_buffer(new_buffer);
}

void
CLEANUP_FUNC (void)
{
	BEGIN(INITIAL);
	yy_delete_buffer(YY_CURRENT_BUFFER);
}

/* Flex has an option '%option noyywrap' so that I don't have to
 * provide this yywrap function, but in order to maintain portability,
 * I'll just use this yywrap() function.
 */
int
WRAP_FUNC ()
{
	return 1; /* stop at EOF, instead of looking for next file */
}



