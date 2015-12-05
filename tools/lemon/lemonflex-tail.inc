
/* This file is #include'd at the bottom of a Lex/Flex scanner
for use with the Lemon parser. You must have #define'd:

MODNAME		module name for creating function names:

Prototypes:
*/
void	CONCAT(MODNAME,_scanner_text(char *text));
void	CONCAT(MODNAME,_scanner_file(FILE *fh));
void	CONCAT(MODNAME,_scanner_cleanup(void));
#ifndef YY_SKIP_YYWRAP
int	CONCAT(MODNAME,_wrap(void));
#endif

#include <cppmagic.h>

#define TEXT_FUNC	CONCAT(MODNAME,_scanner_text)
#define FILE_FUNC	CONCAT(MODNAME,_scanner_file)
#define CLEANUP_FUNC	CONCAT(MODNAME,_scanner_cleanup)
#ifndef YY_SKIP_YYWRAP
#define WRAP_FUNC	CONCAT(MODNAME,_wrap)
#endif

/* flex 2.5.31 no longer #defines these as yy_* if used with -P. */
#ifndef yy_scan_string
#define yy_scan_string		CONCAT(FLEX_YY_PREFIX, _scan_string)
#endif

#ifndef yy_create_buffer
#define yy_create_buffer	CONCAT(FLEX_YY_PREFIX, _create_buffer)
#endif

#ifndef yy_switch_to_buffer
#define yy_switch_to_buffer	CONCAT(FLEX_YY_PREFIX, _switch_to_buffer)
#endif

#ifndef yy_delete_buffer
#define yy_delete_buffer	CONCAT(FLEX_YY_PREFIX, _delete_buffer)
#endif

/* Resets scanner and assigns the char* argument
 * as the text to scan
 */
void
TEXT_FUNC (char *text)
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

#ifndef YY_SKIP_YYWRAP
/* Flex has an option '%option noyywrap' so that I don't have to
 * provide this yywrap function, but in order to maintain portability,
 * I'll just use this yywrap() function if that option wasn't used.
 */
int
WRAP_FUNC (void)
{
	return 1; /* stop at EOF, instead of looking for next file */
}
#endif
