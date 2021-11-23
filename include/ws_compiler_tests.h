/* ws_compiler_tests.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_COMPILER_TESTS_H__
#define __WS_COMPILER_TESTS_H__

/*
 * This was introduced by Clang:
 *
 *     http://clang.llvm.org/docs/LanguageExtensions.html#has-attribute
 *
 * in some version (which version?); it has been picked up by GCC 5.0.
 */
#ifndef __has_attribute
  /*
   * It's a macro, so you can check whether it's defined to check
   * whether it's supported.
   *
   * If it's not, define it to always return 0, so that we move on to
   * the fallback checks.
   */
  #define __has_attribute(x) 0
#endif

/*
 * Note that the C90 spec's "6.8.1 Conditional inclusion" and the
 * C99 spec's and C11 spec's "6.10.1 Conditional inclusion" say:
 *
 *    Prior to evaluation, macro invocations in the list of preprocessing
 *    tokens that will become the controlling constant expression are
 *    replaced (except for those macro names modified by the defined unary
 *    operator), just as in normal text.  If the token "defined" is
 *    generated as a result of this replacement process or use of the
 *    "defined" unary operator does not match one of the two specified
 *    forms prior to macro replacement, the behavior is undefined.
 *
 * so you shouldn't use defined() in a #define that's used in #if or
 * #elif.  Some versions of Clang, for example, will warn about this.
 *
 * Instead, we check whether the pre-defined macros for particular
 * compilers are defined and, if not, define the "is this version XXX
 * or a later version of this compiler" macros as 0.
 */

/*
 * Check whether this is GCC major.minor or a later release, or some
 * compiler that claims to be "just like GCC" of that version or a
 * later release.
 */

#if !defined(__GNUC__)
  #define WS_IS_AT_LEAST_GNUC_VERSION(major, minor) 0
#else
  #define WS_IS_AT_LEAST_GNUC_VERSION(major, minor) \
	(__GNUC__ > (major) || \
	 (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#endif

/*
 * Check whether this is Clang major.minor or a later release.
 */

#if !defined(__clang__)
  #define WS_IS_AT_LEAST_CLANG_VERSION(major, minor) 0
#else
  #define WS_IS_AT_LEAST_CLANG_VERSION(major, minor) \
	(__clang_major__ > (major) || \
	 (__clang_major__ == (major) && __clang_minor__ >= (minor)))
#endif

/*
 * Check whether this is Sun C/SunPro C/Oracle Studio major.minor
 * or a later release.
 *
 * The version number in __SUNPRO_C is encoded in hex BCD, with the
 * uppermost hex digit being the major version number, the next
 * one or two hex digits being the minor version number, and
 * the last digit being the patch version.
 *
 * It represents the *compiler* version, not the product version;
 * see
 *
 *    https://sourceforge.net/p/predef/wiki/Compilers/
 *
 * for a partial mapping, which we assume continues for later
 * 12.x product releases.
 */

#if !defined(__SUNPRO_C)
  #define WS_IS_AT_LEAST_SUNC_VERSION(major, minor) 0
#else
  #define WS_SUNPRO_VERSION_TO_BCD(major, minor) \
	(((minor) >= 10) ? \
	    (((major) << 12) | (((minor)/10) << 8) | (((minor)%10) << 4)) : \
	    (((major) << 8) | ((minor) << 4)))
  #define WS_IS_AT_LEAST_SUNC_VERSION(major, minor) \
	(__SUNPRO_C >= WS_SUNPRO_VERSION_TO_BCD((major), (minor)))
#endif

/*
 * Check whether this is IBM XL C major.minor or a later release.
 *
 * The version number in __xlC__ has the major version in the
 * upper 8 bits and the minor version in the lower 8 bits.
 */

#if !defined(__xlC__)
  #define WS_IS_AT_LEAST_XL_C_VERSION(major, minor) 0
#else
  #define WS_IS_AT_LEAST_XL_C_VERSION(major, minor) \
	(__xlC__ >= (((major) << 8) | (minor)))
#endif

/*
 * Check whether this is HP aC++/HP C major.minor or a later release.
 *
 * The version number in __HP_aCC is encoded in zero-padded decimal BCD,
 * with the "A." stripped off, the uppermost two decimal digits being
 * the major version number, the next two decimal digits being the minor
 * version number, and the last two decimal digits being the patch version.
 * (Strip off the A., remove the . between the major and minor version
 * number, and add two digits of patch.)
 */

#if !defined(__HP_aCC)
  #define WS_IS_AT_LEAST_HP_C_VERSION(major, minor) 0
#else
  #define WS_IS_AT_LEAST_HP_C_VERSION(major, minor) \
	(__HP_aCC >= ((major)*10000 + (minor)*100))
#endif

#endif /* __WS_COMPILER_TESTS_H__ */
