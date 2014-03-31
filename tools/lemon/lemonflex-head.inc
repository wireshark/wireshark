
/* This file is #include'd at the top of a Lex/Flex scanner
for use with the Lemon parser. You must have #define'd:

LVAL		name of lval variable
LVAL_TYPE	type of lval variable
LVAL_INIT_VAL	Initial value of lval variable

*/

/* Flex has a few routines which help us get the scanner to read
 * from a string rather than from a file. POSIX lex only provides
 * for reading from a file; any method of reading from a string
 * is inherently non-portable.  Besides reading from a string,
 * we have to worry about resetting the scanner after a bad
 * parse; this too is non-portable. Combine the reset with
 * a string input, and you have major non-portability. I'll provide
 * the routines for flex here. If you really want to modify the
 * scanner and use a non-flex lex implementation, you may
 * add more ifdef's below.
 */


/* If we don't need yyunput, use this macro to get it out of the
 * generated C file, avoiding a compiler warning about its lack of use */
#define YY_NO_UNPUT 1


/* Yup, I'm using a non-standard type for lval, unlike usual lex/yacc implementations.
 * I can do so because I'm *not* using yacc, I'm using Lemon, where I have
 * more control of the interaction between scanner and parser. */
LVAL_TYPE	LVAL = LVAL_INIT_VAL;

