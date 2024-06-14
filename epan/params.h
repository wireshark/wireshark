/** @file
 *
 * Definitions for parameter handling routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PARAMS_H__
#define __PARAMS_H__

/*
 * Definition of a value for an enumerated type.
 *
 * "name" is the name one would use on the command line for the value.
 * "description" is the description of the value, used in combo boxes/
 * option menus.
 * "value" is the value.
 */
typedef struct {
	const char	*name;
	const char	*description;
	int		value;
} enum_val_t;

/* -----  Public enum_val_t "Helper" macros ----- */
/*
 * Reuse the macro format of the list of value strings (that is used by value_string.h
 * for generating definitions of enum and/or value strings array) to generating
 * enum_val_t array. For example, there is a macro of a value strings list like:
 *
 *      #define foo_VALUE_STRING_LIST(XXX) \
 *         XXX( FOO_A, 1, "aaa" ) \
 *         XXX( FOO_B, 3, "bbb" )
 *
 * The code VS_LIST_TO_ENUM_VAL_T_ARRAY_STATIC(foo, foo_ev); will define a static enum_val_t array:
 *
 *      static const enum_val_t foo_ev[] = {
 *          { "aaa", "aaa", 1 },
 *          { "bbb", "bbb", 3 },
 *          { NULL, NULL, 0 }
 *      };
 *
 * The code VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DEF(foo, foo_ev); will define a global enum_val_t array:
 *
 *      const enum_val_t foo_ev[] = {
 *          { "aaa", "aaa", 1 },
 *          { "bbb", "bbb", 3 },
 *          { NULL, NULL, 0 }
 *      };
 *
 * The code VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DCL(foo_ev); will declare a extern enum_val_t array:
 *
 *      extern const enum_val_t foo_ev[];
 */
#define VS_LIST_TO_ENUM_VAL_T_ARRAY_STATIC(    array_name, new_array_name) static _EV_ARRAY_XXX(array_name, new_array_name, _VALUE_STRING_LIST, _EV_ARRAY_ENTRY_FROM_VS)
#define VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DEF(array_name, new_array_name) _EV_ARRAY_XXX(array_name, new_array_name, _VALUE_STRING_LIST, _EV_ARRAY_ENTRY_FROM_VS)
#define VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DCL(new_array_name) extern const enum_val_t new_array_name[]

/*
 * Provide the capability to define a list of enum_val_t(s) once and
 * then to expand the list as an enum and/or as a enum_val_t array.:
 *
 *      #define foo2_ENUM_VAL_T_LIST(XXX) \
 *         XXX( FOO_A, 1, "aaa", "The description of aaa" ) \
 *         XXX( FOO_B, 3, "bbb", "The description of bbb" )
 *
 * The code ENUM_VAL_T_ENUM(foo2); will define an enumeration type:
 *
 *      enum {
 *          FOO_A = 1,
 *          FOO_B = 3,
 *          _foo_ENUM_DUMMY = 0
 *      };
 * Note, you can use code "typedef ENUM_VAL_T_ENUM(foo2) enum_foo_t;" to define a
 * named enumeration.
 *
 * The code ENUM_VAL_T_ARRAY_STATIC(foo2); will define a static enum_val_t array:
 *
 *      static const enum_val_t foo2[] = {
 *          { "aaa", "The description of aaa", 1 },
 *          { "bbb", "The description of bbb", 3 },
 *          { NULL, NULL, 0 }
 *      };
 *
 * The code ENUM_VAL_T_ARRAY_GLOBAL_DEF(foo2); will define a global enum_val_t array:
 *
 *      const enum_val_t foo2[] = {
 *          { "aaa", "The description of aaa", 1 },
 *          { "bbb", "The description of bbb", 3 },
 *          { NULL, NULL, 0 }
 *      };
 *
 * The code VS_LIST_TO_ENUM_VAL_T_ARRAY_GLOBAL_DCL(foo2); will declare a extern enum_val_t array:
 *
 *      extern const enum_val_t foo2[];
 */
#define ENUM_VAL_T_ENUM(array_name)  _EV_ENUM_XXX(array_name, _ENUM_VAL_T_LIST, _EV_ENUM_ENTRY)
#define ENUM_VAL_T_ARRAY_STATIC(    array_name) static _EV_ARRAY_XXX(array_name, array_name, _ENUM_VAL_T_LIST, _EV_ARRAY_ENTRY)
#define ENUM_VAL_T_ARRAY_GLOBAL_DEF(array_name) _EV_ARRAY_XXX(array_name, array_name, _ENUM_VAL_T_LIST, _EV_ARRAY_ENTRY)
#define ENUM_VAL_T_ARRAY_GLOBAL_DCL(array_name) extern const enum_val_t array_name[]

/*
 * Reuse the format of enum_val list to create value_string array:
 *
 * The code ENUM_VAL_T_TO_VS_ARRAY_STATIC(foo2, foo2_vs); will define a static value_string array from an enum_val list:
 *
 *      static const value_string foo2_vs[] = {
 *          { 1, "aaa" },
 *          { 3, "bbb" },
 *          { 0, NULL }
 *      };
 *
 * The code ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DEF(foo2, foo2_vs); will define a global value_string array from an enum_val list:
 *
 *      const value_string foo2_vs[] = {
 *          { 1, "aaa" },
 *          { 3, "bbb" },
 *          { 0, NULL }
 *      };
 *
 * The code ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DCL(foo2_vs); will declare a extern value_string array from an enum_val list:
 *
 *      extern const value_string foo2_vs[];
 *
 * The macros ENUM_VAL_T_TO_VS_ARRAY_STATIC2, ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DEF2 and ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DCL2
 * are similar to ENUM_VAL_T_TO_VS_ARRAY_STATIC, ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DEF and ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DCL
 * except that ENUM_VAL_T_TO_VS_ARRAY_XXX(s) uses the 'name' field of enum_val list as the 'string' field of value_string,
 * and ENUM_VAL_T_TO_VS_ARRAY_XXX2(s) uses the 'enum_name' field.
 *
 * Similarly, The macros ENUM_VAL_T_TO_VS_ARRAY_XXX3(s) uses the 'description' field of enum_val list as the 'string'
 * field of value_string.
 */
#define ENUM_VAL_T_TO_VS_ARRAY_STATIC(    array_name, new_array_name) static _EV_TO_VS_ARRAY_XXX(array_name, new_array_name, _ENUM_VAL_T_LIST, _VS_ARRAY_ENTRY_FROM_EV)
#define ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DEF(array_name, new_array_name) _EV_TO_VS_ARRAY_XXX(array_name, new_array_name, _ENUM_VAL_T_LIST, _VS_ARRAY_ENTRY_FROM_EV)
#define ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DCL(new_array_name) extern const value_string new_array_name[]

#define ENUM_VAL_T_TO_VS_ARRAY_STATIC2(    array_name, new_array_name) static _EV_TO_VS_ARRAY_XXX(array_name, new_array_name, _ENUM_VAL_T_LIST, _VS_ARRAY_ENTRY_FROM_EV2)
#define ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DEF2(array_name, new_array_name) _EV_TO_VS_ARRAY_XXX(array_name, new_array_name, _ENUM_VAL_T_LIST, _VS_ARRAY_ENTRY_FROM_EV2)
#define ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DCL2(new_array_name) extern const value_string new_array_name[]

#define ENUM_VAL_T_TO_VS_ARRAY_STATIC3(    array_name, new_array_name) static _EV_TO_VS_ARRAY_XXX(array_name, new_array_name, _ENUM_VAL_T_LIST, _VS_ARRAY_ENTRY_FROM_EV3)
#define ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DEF3(array_name, new_array_name) _EV_TO_VS_ARRAY_XXX(array_name, new_array_name, _ENUM_VAL_T_LIST, _VS_ARRAY_ENTRY_FROM_EV3)
#define ENUM_VAL_T_TO_VS_ARRAY_GLOBAL_DCL3(new_array_name) extern const value_string new_array_name[]

/* -- Private macros -- */
#define _EV_ARRAY_XXX(array_name, new_array_name, array_suffix, macro)  \
    const enum_val_t new_array_name[] = { \
    array_name##array_suffix(macro) \
    { NULL, NULL, 0 } \
}

#define _EV_ARRAY_ENTRY(enum_name, value, name, description) { name, description, value },
#define _EV_ARRAY_ENTRY_FROM_VS(enum_name, value, string) { string, string, value },

#define _EV_ENUM_XXX(array_name, array_suffix, macro) \
enum { \
    array_name##array_suffix(macro) \
    _##array_name##_ENUM_DUMMY = 0 \
}

#define _EV_ENUM_ENTRY(enum_name, value, name, description) enum_name = value,

#define _EV_TO_VS_ARRAY_XXX(array_name, new_array_name, array_suffix, macro)  \
    const value_string new_array_name[] = { \
    array_name##array_suffix(macro) \
    { 0, NULL } \
}
#define _VS_ARRAY_ENTRY_FROM_EV(enum_name, value, name, description) { value, name }
#define _VS_ARRAY_ENTRY_FROM_EV2(enum_name, value, name, description) { value, #enum_name }
#define _VS_ARRAY_ENTRY_FROM_EV3(enum_name, value, name, description) { value, description }

#endif /* params.h */

