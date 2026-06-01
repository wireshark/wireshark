/* display_filter_validator.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/display_filter_validator.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>

DisplayFilterValidator::DisplayFilterValidator(QObject *parent) :
    FilterValidator(parent)
{
}

QValidator::State DisplayFilterValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);
    detail_ = Detail();

    const QString filter = input;
    if (filter.isEmpty())
        return QValidator::Acceptable;

    dfilter_t *dfp = NULL;
    df_error_t *df_err = NULL;
    if (dfilter_compile_full(filter.toUtf8().constData(), &dfp, &df_err,
                             DF_EXPAND_MACROS | DF_OPTIMIZE, "Qt")) {
        // Valid. Surface warnings and deprecated tokens as Deprecated (amber) by
        // returning Acceptable with a non-empty deprecatedToken, mirroring the
        // old checkDisplayFilter().
        GSList *warn;
        GPtrArray *depr = NULL;
        if (dfp != NULL && (warn = dfilter_get_warnings(dfp)) != NULL) {
            // Only report the first warning, as the old code did.
            detail_.errMsg = QString(static_cast<char *>(warn->data));
            detail_.deprecatedToken = detail_.errMsg;
        } else if (dfp != NULL && (depr = dfilter_deprecated_tokens(dfp)) != NULL) {
            // Only report the first deprecated token, as the old code did.
            QString token(static_cast<const char *>(g_ptr_array_index(depr, 0)));
            char *token_str = qstring_strdup(token.section('.', 0, 0));
            header_field_info *hfi = proto_registrar_get_byalias(token_str);
            if (hfi)
                detail_.errMsg = tr("\"%1\" is deprecated in favour of \"%2\". "
                                    "See Help section 6.4.8 for details.")
                                     .arg(token_str).arg(hfi->abbrev);
            else
                detail_.errMsg = QString::fromUtf8(token_str);
            detail_.deprecatedToken = token;
            g_free(token_str);
        }
        dfilter_free(dfp);
        return QValidator::Acceptable;
    }

    // Compile failed. An unexpected end means the expression is incomplete but
    // not (yet) wrong, so report Intermediate rather than flashing red.
    QValidator::State result = QValidator::Invalid;
    if (df_err) {
        if (df_err->code == DF_ERROR_UNEXPECTED_END) {
            result = QValidator::Intermediate;
        } else {
            detail_.errMsg = QString::fromUtf8(df_err->msg);
            detail_.errPos = static_cast<int>(df_err->loc.col_start);
            detail_.errLen = static_cast<int>(df_err->loc.col_len);
        }
        df_error_free(&df_err);
    }
    return result;
}
