/* keytab_krb5_ctx.h
 * Declare krb5_context structure used with keytab file.
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * We declare this here, rather than in epan/read_keytab_file.h, so that
 * callers of routines declared in epan/read_keytab_file.h that don't
 * need this structure don't need to include krb5.h.
 *
 * Do *not* attempt to put this back in epan/read_keytab_file.h without
 * adding an include of krb5.h in epan/read_keytab_file.h; there is *no*
 * guarantee that the krb5_context is a typedef for struct _krb5_context;
 * on NetBSD 10, it's a typedef for struct krb5_context_data, and that
 * causes compilation errors. To tweak a line from Henry Spencer, "If you
 * lie to the development environment, it will get its revenge."
 */

#ifdef HAVE_KERBEROS

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)

#include <krb5.h>

extern krb5_context keytab_krb5_ctx;

#endif /* defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS) */

#endif /* HAVE_KERBEROS */

#ifdef __cplusplus
}
#endif /* __cplusplus */
