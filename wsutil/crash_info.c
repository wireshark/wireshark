/* crash_info.c
 * Routines to try to provide more useful information in crash dumps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include "crash_info.h"

#ifdef __APPLE__
/*
 * Copyright 2005-2012 Apple Inc. All rights reserved.
 *
 * IMPORTANT:  This Apple software is supplied to you by Apple Computer,
 * Inc. ("Apple") in consideration of your agreement to the following
 * terms, and your use, installation, modification or redistribution of
 * this Apple software constitutes acceptance of these terms.  If you do
 * not agree with these terms, please do not use, install, modify or
 * redistribute this Apple software.
 *
 * In consideration of your agreement to abide by the following terms, and
 * subject to these terms, Apple grants you a personal, non-exclusive
 * license, under Apple's copyrights in this original Apple software (the
 * "Apple Software"), to use, reproduce, modify and redistribute the Apple
 * Software, with or without modifications, in source and/or binary forms;
 * provided that if you redistribute the Apple Software in its entirety and
 * without modifications, you must retain this notice and the following
 * text and disclaimers in all such redistributions of the Apple Software.
 * Neither the name, trademarks, service marks or logos of Apple Computer,
 * Inc. may be used to endorse or promote products derived from the Apple
 * Software without specific prior written permission from Apple.  Except
 * as expressly stated in this notice, no other rights or licenses, express
 * or implied, are granted by Apple herein, including but not limited to
 * any patent rights that may be infringed by your derivative works or by
 * other works in which the Apple Software may be incorporated.
 *
 * The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
 * MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
 * OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.
 *
 * IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
 * MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
 * AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
 * STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/*
 * This used to be the way to add an application-specific string to
 * crash dumps; see
 *
 *	http://www.allocinit.net/blog/2008/01/04/application-specific-information-in-leopard-crash-reports/
 *
 * It still appears to work as of OS X 10.8 (Mountain Lion).
 */
__private_extern__ char *__crashreporter_info__ = NULL;

#if 0
/*
 * And this appears to be the new way to do it, as of Lion.
 * However, if we do both, we get the message twice, so we're
 * not doing this one, for now.
 *
 * This code was lifted from SVN trunk CUPS.
 */
#define _crc_make_getter(attr, type) (type)(gCRAnnotations.attr)
#define _crc_make_setter(attr, arg) (gCRAnnotations.attr = (uint64_t)(unsigned long)(arg))
#define CRASH_REPORTER_CLIENT_HIDDEN __attribute__((visibility("hidden")))
#define CRASHREPORTER_ANNOTATIONS_VERSION 4
#define CRASHREPORTER_ANNOTATIONS_SECTION "__crash_info"

/*
 * Yes, these are all 64-bit, even on 32-bit platforms.
 *
 * version is presumably the version of this structure.
 *
 * message and message2 are reported, one after the other,
 * under "Application Specific Information".
 *
 * signature_string is reported under "Application Specific
 * Signatures".
 *
 * backtrace is reported under "Application Specific Backtrace".
 *
 * Dunno which versions are supported by which versions of OS X.
 */
struct crashreporter_annotations_t {
	uint64_t version;		/* unsigned long */
	uint64_t message;		/* char * */
	uint64_t signature_string;	/* char * */
	uint64_t backtrace;		/* char * */
	uint64_t message2;		/* char * */
	uint64_t thread;		/* uint64_t */
	uint64_t dialog_mode;		/* unsigned int */
};

CRASH_REPORTER_CLIENT_HIDDEN
struct crashreporter_annotations_t gCRAnnotations
	__attribute__((section("__DATA," CRASHREPORTER_ANNOTATIONS_SECTION))) = {
	CRASHREPORTER_ANNOTATIONS_VERSION,	/* version */
	0,					/* message */
	0,					/* signature_string */
	0,					/* backtrace */
	0,					/* message2 */
	0,					/* thread */
	0					/* dialog_mode */
};

#define CRSetCrashLogMessage(m) _crc_make_setter(message, m)
#endif /* 0 */

void
ws_add_crash_info(const char *fmt, ...)
{
	va_list ap;
	char *m, *old_info, *new_info;

	va_start(ap, fmt);
	m = g_strdup_vprintf(fmt, ap);
	va_end(ap);
	if (__crashreporter_info__ == NULL)
		__crashreporter_info__ = m;
	else {
		old_info = __crashreporter_info__;
		new_info = g_strdup_printf("%s\n%s", old_info, m);
		g_free(m);
		__crashreporter_info__ = new_info;
		g_free(old_info);
	}
}

#else /* __APPLE__ */
/*
 * Perhaps Google Breakpad (http://code.google.com/p/google-breakpad/) or
 * other options listed at
 * http://stackoverflow.com/questions/7631908/library-for-logging-call-stack-at-runtime-windows-linux
 * ?
 */
void
ws_add_crash_info(const char *fmt _U_, ...)
{
}
#endif /* __APPLE__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
