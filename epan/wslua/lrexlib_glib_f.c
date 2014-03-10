/* lrexlib_glib_f.c - GLib regular expression library */

/*
This file, written by Hadriel Kaplan, is in the Public Domain, or
under the MIT license if your country does not allow Public Domain.

Copyright (c) 2014 Hadriel Kaplan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <glib.h>
#include "lua.h"
#include "lauxlib.h"
#include "lrexlib.h"

#define VERSION_GLIB (GLIB_MAJOR_VERSION*100 + GLIB_MINOR_VERSION)

static flag_pair gregex_compile_flags[] = {
  { "MAJOR",                         GLIB_MAJOR_VERSION },
  { "MINOR",                         GLIB_MINOR_VERSION },
  { "MICRO",                         GLIB_MICRO_VERSION },
/*-----------------------  Compile flags  -----------------------------------*/
  { "CASELESS",                      G_REGEX_CASELESS },
  { "MULTILINE",                     G_REGEX_MULTILINE },
  { "DOTALL",                        G_REGEX_DOTALL },
  { "EXTENDED",                      G_REGEX_EXTENDED },
  { "ANCHORED",                      G_REGEX_ANCHORED },
  { "DOLLAR_ENDONLY",                G_REGEX_DOLLAR_ENDONLY },
  { "UNGREEDY",                      G_REGEX_UNGREEDY },
  { "NO_AUTO_CAPTURE",               G_REGEX_NO_AUTO_CAPTURE },
  { "OPTIMIZE",                      G_REGEX_OPTIMIZE },
  { "DUPNAMES",                      G_REGEX_DUPNAMES },
  { "NEWLINE_CR",                    G_REGEX_NEWLINE_CR },
  { "NEWLINE_LF",                    G_REGEX_NEWLINE_LF },
  { "NEWLINE_CRLF",                  G_REGEX_NEWLINE_CRLF },
#if VERSION_GLIB >= 234
  { "FIRSTLINE",                     G_REGEX_FIRSTLINE },
  { "NEWLINE_ANYCRLF",               G_REGEX_NEWLINE_ANYCRLF },
  { "BSR_ANYCRLF",                   G_REGEX_BSR_ANYCRLF },
  { "JAVASCRIPT_COMPAT",             G_REGEX_JAVASCRIPT_COMPAT },
#endif
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

/*-----------------------  Match flags  -------------------------------------*/
static flag_pair gregex_match_flags[] = {
  { "ANCHORED",                      G_REGEX_MATCH_ANCHORED },
  { "NOTBOL",                        G_REGEX_MATCH_NOTBOL },
  { "NOTEOL",                        G_REGEX_MATCH_NOTEOL },
  { "NOTEMPTY",                      G_REGEX_MATCH_NOTEMPTY },
  { "PARTIAL",                       G_REGEX_MATCH_PARTIAL },
  { "NEWLINE_CR",                    G_REGEX_MATCH_NEWLINE_CR },
  { "NEWLINE_LF",                    G_REGEX_MATCH_NEWLINE_LF },
  { "NEWLINE_CRLF",                  G_REGEX_MATCH_NEWLINE_CRLF },
  { "NEWLINE_ANY",                   G_REGEX_MATCH_NEWLINE_ANY },
#if VERSION_GLIB >= 234
  { "NEWLINE_ANYCRLF",               G_REGEX_MATCH_NEWLINE_ANYCRLF },
  { "BSR_ANYCRLF",                   G_REGEX_MATCH_BSR_ANYCRLF },
  { "BSR_ANY",                       G_REGEX_MATCH_BSR_ANY },
  { "PARTIAL_SOFT",                  G_REGEX_MATCH_PARTIAL_SOFT },
  { "PARTIAL_HARD",                  G_REGEX_MATCH_PARTIAL_HARD },
  { "NOTEMPTY_ATSTART",              G_REGEX_MATCH_NOTEMPTY_ATSTART },
#endif
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

flag_pair gregex_error_flags[] = {
  { "COMPILE",                                G_REGEX_ERROR_COMPILE },
  { "OPTIMIZE",                               G_REGEX_ERROR_OPTIMIZE },
  { "REPLACE",                                G_REGEX_ERROR_REPLACE },
  { "MATCH",                                  G_REGEX_ERROR_MATCH },
  { "INTERNAL",                               G_REGEX_ERROR_INTERNAL },
  { "STRAY_BACKSLASH",                        G_REGEX_ERROR_STRAY_BACKSLASH },
  { "MISSING_CONTROL_CHAR",                   G_REGEX_ERROR_MISSING_CONTROL_CHAR },
  { "UNRECOGNIZED_ESCAPE",                    G_REGEX_ERROR_UNRECOGNIZED_ESCAPE },
  { "QUANTIFIERS_OUT_OF_ORDER",               G_REGEX_ERROR_QUANTIFIERS_OUT_OF_ORDER },
  { "QUANTIFIER_TOO_BIG",                     G_REGEX_ERROR_QUANTIFIER_TOO_BIG },
  { "UNTERMINATED_CHARACTER_CLASS",           G_REGEX_ERROR_UNTERMINATED_CHARACTER_CLASS },
  { "INVALID_ESCAPE_IN_CHARACTER_CLASS",      G_REGEX_ERROR_INVALID_ESCAPE_IN_CHARACTER_CLASS },
  { "RANGE_OUT_OF_ORDER",                     G_REGEX_ERROR_RANGE_OUT_OF_ORDER },
  { "NOTHING_TO_REPEAT",                      G_REGEX_ERROR_NOTHING_TO_REPEAT },
  { "UNRECOGNIZED_CHARACTER",                 G_REGEX_ERROR_UNRECOGNIZED_CHARACTER },
  { "POSIX_NAMED_CLASS_OUTSIDE_CLASS",        G_REGEX_ERROR_POSIX_NAMED_CLASS_OUTSIDE_CLASS },
  { "UNMATCHED_PARENTHESIS",                  G_REGEX_ERROR_UNMATCHED_PARENTHESIS },
  { "INEXISTENT_SUBPATTERN_REFERENCE",        G_REGEX_ERROR_INEXISTENT_SUBPATTERN_REFERENCE },
  { "UNTERMINATED_COMMENT",                   G_REGEX_ERROR_UNTERMINATED_COMMENT },
  { "EXPRESSION_TOO_LARGE",                   G_REGEX_ERROR_EXPRESSION_TOO_LARGE },
  { "MEMORY_ERROR",                           G_REGEX_ERROR_MEMORY_ERROR },
  { "VARIABLE_LENGTH_LOOKBEHIND",             G_REGEX_ERROR_VARIABLE_LENGTH_LOOKBEHIND },
  { "MALFORMED_CONDITION",                    G_REGEX_ERROR_MALFORMED_CONDITION },
  { "TOO_MANY_CONDITIONAL_BRANCHES",          G_REGEX_ERROR_TOO_MANY_CONDITIONAL_BRANCHES },
  { "ASSERTION_EXPECTED",                     G_REGEX_ERROR_ASSERTION_EXPECTED },
  { "UNKNOWN_POSIX_CLASS_NAME",               G_REGEX_ERROR_UNKNOWN_POSIX_CLASS_NAME },
  { "POSIX_COLLATING_ELEMENTS_NOT_SUPPORTED", G_REGEX_ERROR_POSIX_COLLATING_ELEMENTS_NOT_SUPPORTED },
  { "HEX_CODE_TOO_LARGE",                     G_REGEX_ERROR_HEX_CODE_TOO_LARGE },
  { "INVALID_CONDITION",                      G_REGEX_ERROR_INVALID_CONDITION },
  { "SINGLE_BYTE_MATCH_IN_LOOKBEHIND",        G_REGEX_ERROR_SINGLE_BYTE_MATCH_IN_LOOKBEHIND },
  { "INFINITE_LOOP",                          G_REGEX_ERROR_INFINITE_LOOP },
  { "MISSING_SUBPATTERN_NAME_TERMINATOR",     G_REGEX_ERROR_MISSING_SUBPATTERN_NAME_TERMINATOR },
  { "DUPLICATE_SUBPATTERN_NAME",              G_REGEX_ERROR_DUPLICATE_SUBPATTERN_NAME },
  { "MALFORMED_PROPERTY",                     G_REGEX_ERROR_MALFORMED_PROPERTY },
  { "UNKNOWN_PROPERTY",                       G_REGEX_ERROR_UNKNOWN_PROPERTY },
  { "SUBPATTERN_NAME_TOO_LONG",               G_REGEX_ERROR_SUBPATTERN_NAME_TOO_LONG },
  { "TOO_MANY_SUBPATTERNS",                   G_REGEX_ERROR_TOO_MANY_SUBPATTERNS },
  { "INVALID_OCTAL_VALUE",                    G_REGEX_ERROR_INVALID_OCTAL_VALUE },
  { "TOO_MANY_BRANCHES_IN_DEFINE",            G_REGEX_ERROR_TOO_MANY_BRANCHES_IN_DEFINE },
  { "INCONSISTENT_NEWLINE_OPTIONS",           G_REGEX_ERROR_INCONSISTENT_NEWLINE_OPTIONS },
  { "MISSING_BACK_REFERENCE",                 G_REGEX_ERROR_MISSING_BACK_REFERENCE },
#if VERSION_GLIB >= 234
  { "INVALID_RELATIVE_REFERENCE",             G_REGEX_ERROR_INVALID_RELATIVE_REFERENCE },
  { "BACKTRACKING_CONTROL_VERB_ARGUMENT_FORBIDDEN",G_REGEX_ERROR_BACKTRACKING_CONTROL_VERB_ARGUMENT_FORBIDDEN },
  { "UNKNOWN_BACKTRACKING_CONTROL_VERB",      G_REGEX_ERROR_UNKNOWN_BACKTRACKING_CONTROL_VERB },
  { "NUMBER_TOO_BIG",                         G_REGEX_ERROR_NUMBER_TOO_BIG },
  { "MISSING_SUBPATTERN_NAME",                G_REGEX_ERROR_MISSING_SUBPATTERN_NAME },
  { "MISSING_DIGIT",                          G_REGEX_ERROR_MISSING_DIGIT },
  { "INVALID_DATA_CHARACTER",                 G_REGEX_ERROR_INVALID_DATA_CHARACTER },
  { "EXTRA_SUBPATTERN_NAME",                  G_REGEX_ERROR_EXTRA_SUBPATTERN_NAME },
  { "BACKTRACKING_CONTROL_VERB_ARGUMENT_REQUIRED",G_REGEX_ERROR_BACKTRACKING_CONTROL_VERB_ARGUMENT_REQUIRED },
  { "INVALID_CONTROL_CHAR",                   G_REGEX_ERROR_INVALID_CONTROL_CHAR },
  { "MISSING_NAME",                           G_REGEX_ERROR_MISSING_NAME },
  { "NOT_SUPPORTED_IN_CLASS",                 G_REGEX_ERROR_NOT_SUPPORTED_IN_CLASS },
  { "TOO_MANY_FORWARD_REFERENCES",            G_REGEX_ERROR_TOO_MANY_FORWARD_REFERENCES },
  { "NAME_TOO_LONG",                          G_REGEX_ERROR_NAME_TOO_LONG },
  { "CHARACTER_VALUE_TOO_LARGE",              G_REGEX_ERROR_CHARACTER_VALUE_TOO_LARGE },
#endif
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

int Gregex_get_compile_flags (lua_State *L) {
  const flag_pair* fps[] = { gregex_compile_flags, NULL };
  return get_flags (L, fps);
}

int Gregex_get_match_flags (lua_State *L) {
  const flag_pair* fps[] = { gregex_match_flags, NULL };
  return get_flags (L, fps);
}

int Gregex_get_flags (lua_State *L) {
  const flag_pair* fps[] = { gregex_compile_flags, gregex_match_flags, gregex_error_flags, NULL };
  return get_flags (L, fps);
}
