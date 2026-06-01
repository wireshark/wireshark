/* display_filter_completer.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/display_filter_completer.h>

#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>
#include <epan/dfilter/dfunctions.h>

#include <QStringListModel>

#include <cstring>

// Characters that make up a single display-filter field token (protocol and
// field abbreviations); carried over from the old DisplayFilterEdit.
static const QString fld_abbrev_chars_ =
    "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

DisplayFilterCompleter::DisplayFilterCompleter(QObject *parent) :
    FilterCompleter(parent),
    fields_(new QStringListModel(this))
{
    setTokenChars(fld_abbrev_chars_);
}

QStringList DisplayFilterCompleter::splitPath(const QString &path) const
{
    const QStringList parts = FilterCompleter::splitPath(path);
    const QString token = parts.isEmpty() ? QString() : parts.first();
    // Everything before the token is the preamble used for the grammaticality
    // check (is a field even allowed at this position?).
    const QString preamble = path.left(path.length() - token.length()).trimmed();
    rebuildFields(token, preamble);
    return parts;
}

void DisplayFilterCompleter::rebuildFields(const QString &field_word, const QString &preamble) const
{
    QStringList field_list;

    if (field_word.isEmpty()) {
        fields_->setStringList(field_list);
        return;
    }

    // Only offer fields when one is grammatical at the cursor. An empty preamble
    // can always start a filter; otherwise compile the preamble and accept a
    // field only when the parser stopped because it expected an identifier.
    bool accepts_field = true;
    if (!preamble.isEmpty()) {
        df_error_t *df_err = NULL;
        dfilter_t *test_df = NULL;
        if (dfilter_compile_full(preamble.toUtf8().constData(), &test_df, &df_err,
                                 DF_EXPAND_MACROS, "Qt")) {
            // A field is not grammatical after a complete, valid filter.
            accepts_field = false;
        } else {
            accepts_field = (df_err->code == DF_ERROR_UNEXPECTED_END);
        }
        dfilter_free(test_df);
        df_error_free(&df_err);
    }

    if (accepts_field) {
        void *proto_cookie;
        // Some protocol names (e.g. _ws.expert) contain periods.
        const int field_dots = static_cast<int>(field_word.count('.'));
        for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
             proto_id = proto_get_next_protocol(&proto_cookie)) {
            protocol_t *protocol = find_protocol_by_id(proto_id);
            if (!proto_is_protocol_enabled(protocol))
                continue;

            const QString pfname = proto_get_protocol_filter_name(proto_id);
            field_list << pfname;

            // Only descend into fields once we are past the protocol name and
            // only for the current protocol.
            if (field_dots > pfname.count('.')) {
                void *field_cookie;
                const QByteArray fw_ba = field_word.toUtf8();
                const char *fw_utf8 = fw_ba.constData();
                size_t fw_len = strlen(fw_utf8);
                for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie);
                     hfinfo; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
                    if (hfinfo->same_name_prev_id != -1)
                        continue; // ignore duplicate names
                    if (!g_ascii_strncasecmp(fw_utf8, hfinfo->abbrev, fw_len)) {
                        if (strlen(hfinfo->abbrev) != fw_len)
                            field_list << hfinfo->abbrev;
                    }
                }
            }
        }

        // Display-filter functions are grammatically the same as fields.
        GPtrArray *func_list = df_func_name_list();
        for (unsigned i = 0; i < func_list->len; i++) {
            field_list << QString::fromUtf8(static_cast<const char *>(func_list->pdata[i])).append("(");
        }
        g_ptr_array_unref(func_list);

        field_list.sort();
    }

    fields_->setStringList(field_list);
}
