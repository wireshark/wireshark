/* field_filter_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <epan/dfilter/dfilter.h>

#include <filter_files.h>

#include <wsutil/utf8_entities.h>

#include "field_filter_edit.h"
#include "filter_dialog.h"
#include "stock_icon_tool_button.h"
#include "syntax_line_edit.h"

#include <QAction>
#include <QAbstractItemView>
#include <QComboBox>
#include <QCompleter>
#include <QEvent>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QStringListModel>

#include <wsutil/utf8_entities.h>

// To do:
// - Get rid of shortcuts and replace them with "n most recently applied filters"?
// - We need simplified (button- and dropdown-free) versions for use in dialogs and field-only checking.
// - Add a separator or otherwise distinguish between recent items and fields
//   in the completion dropdown.


#ifdef __APPLE__
#define DEFAULT_MODIFIER UTF8_PLACE_OF_INTEREST_SIGN
#else
#define DEFAULT_MODIFIER "Ctrl-"
#endif

// proto.c:fld_abbrev_chars
static const QString fld_abbrev_chars_ = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

FieldFilterEdit::FieldFilterEdit(QWidget *parent) :
    SyntaxLineEdit(parent),
    save_action_(NULL),
    remove_action_(NULL)
{
    setAccessibleName(tr("Display filter entry"));

    completion_model_ = new QStringListModel(this);
    setCompleter(new QCompleter(completion_model_, this));
    setCompletionTokenChars(fld_abbrev_chars_);

    setDefaultPlaceholderText();

    //   DFCombo
    //     Bookmark
    //     DisplayFilterEdit
    //     Clear button
    //     Apply (right arrow)
    //     Combo drop-down

    connect(this, SIGNAL(textChanged(const QString&)), this, SLOT(checkFilter(const QString&)));
//        connect(this, SIGNAL(returnPressed()), this, SLOT(applyDisplayFilter()));
}

void FieldFilterEdit::setDefaultPlaceholderText()
{
    placeholder_text_ = QString(tr("Enter a field %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);

#if QT_VERSION >= QT_VERSION_CHECK(4, 7, 0)
    setPlaceholderText(placeholder_text_);
#endif
}

void FieldFilterEdit::paintEvent(QPaintEvent *evt) {
    SyntaxLineEdit::paintEvent(evt);


#if QT_VERSION < QT_VERSION_CHECK(4, 7, 0)
    // http://wiki.forum.nokia.com/index.php/Custom_QLineEdit
    if (text().isEmpty() && ! this->hasFocus()) {
        QPainter p(this);
        QFont f = font();
        f.setItalic(true);
        p.setFont(f);

        QColor color(palette().color(foregroundRole()));
        color.setAlphaF(0.5);
        p.setPen(color);

        QStyleOptionFrame opt;
        initStyleOption(&opt);
        QRect cr = style()->subElementRect(QStyle::SE_LineEditContents, &opt, this);
        cr.setLeft(cr.left() + 2);
        cr.setRight(cr.right() - 2);

        p.drawText(cr, Qt::AlignLeft|Qt::AlignVCenter, placeholder_text_);
    }
    // else check filter syntax and set the background accordingly
    // XXX - Should we add little warning/error icons as well?
#endif // QT < 4.7
}

void FieldFilterEdit::focusOutEvent(QFocusEvent *event)
{
    if (syntaxState() == Valid)
        emit popFilterSyntaxStatus();
    SyntaxLineEdit::focusOutEvent(event);
}

bool FieldFilterEdit::checkFilter()
{
    checkFilter(text());

    return syntaxState() != Invalid;
}

void FieldFilterEdit::checkFilter(const QString& filter_text)
{
    popFilterSyntaxStatus();
    checkDisplayFilter(filter_text);

    switch (syntaxState()) {
    case Deprecated:
    {
        emit pushFilterSyntaxWarning(syntaxErrorMessage());
        break;
    }
    case Invalid:
    {
        QString invalidMsg(tr("Invalid filter: "));
        invalidMsg.append(syntaxErrorMessage());
        emit pushFilterSyntaxStatus(invalidMsg);
        break;
    }
    default:
        break;
    }
}

// GTK+ behavior:
// - Operates on words (proto.c:fld_abbrev_chars).
// - Popup appears when you enter or remove text.

// Our behavior:
// - Operates on words (fld_abbrev_chars_).
// - Popup appears when you enter or remove text.
// - Popup appears when you move the cursor.
// - Popup does not appear when text is selected.
// - Recent and saved display filters in popup when editing first word.

// ui/gtk/filter_autocomplete.c:build_autocompletion_list
void FieldFilterEdit::buildCompletionList(const QString &field_word)
{
    // Push a hint about the current field.
    if (syntaxState() == Valid) {
        emit popFilterSyntaxStatus();

        header_field_info *hfinfo = proto_registrar_get_byname(field_word.toUtf8().constData());
        if (hfinfo) {
            QString cursor_field_msg = QString("%1: %2")
                    .arg(hfinfo->name)
                    .arg(ftype_pretty_name(hfinfo->type));
            emit pushFilterSyntaxStatus(cursor_field_msg);
        }
    }

    if (field_word.length() < 1) {
        completion_model_->setStringList(QStringList());
        return;
    }

    void *proto_cookie;
    QStringList field_list;
    int field_dots = field_word.count('.'); // Some protocol names (_ws.expert) contain periods.
    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1; proto_id = proto_get_next_protocol(&proto_cookie)) {
        protocol_t *protocol = find_protocol_by_id(proto_id);
        if (!proto_is_protocol_enabled(protocol)) continue;

        // Don't complete the current word.
        const QString pfname = proto_get_protocol_filter_name(proto_id);
        if (field_word.compare(pfname)) field_list << pfname;

        // Add fields only if we're past the protocol name and only for the
        // current protocol.
        if (field_dots > pfname.count('.')) {
            void *field_cookie;
            const QByteArray fw_ba = field_word.toUtf8(); // or toLatin1 or toStdString?
            const char *fw_utf8 = fw_ba.constData();
            gsize fw_len = (gsize) strlen(fw_utf8);
            for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
                if (hfinfo->same_name_prev_id != -1) continue; // Ignore duplicate names.

                if (!g_ascii_strncasecmp(fw_utf8, hfinfo->abbrev, fw_len)) {
                    if ((gsize) strlen(hfinfo->abbrev) != fw_len) field_list << hfinfo->abbrev;
                }
            }
        }
    }
    field_list.sort();

    completion_model_->setStringList(field_list);
    completer()->setCompletionPrefix(field_word);
}

void FieldFilterEdit::clearFilter()
{
    clear();
    QString new_filter;
    emit filterPackets(new_filter, true);
}

void FieldFilterEdit::applyDisplayFilter()
{
    if (syntaxState() == Invalid) {
        return;
    }

    QString new_filter = text();
    emit filterPackets(new_filter, true);
}

void FieldFilterEdit::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            setDefaultPlaceholderText();
            break;
        default:
            break;
        }
    }
    SyntaxLineEdit::changeEvent(event);
}

void FieldFilterEdit::showFilters()
{
    FilterDialog display_filter_dlg(window(), FilterDialog::DisplayFilter);
    display_filter_dlg.exec();
}

void FieldFilterEdit::prepareFilter()
{
    QAction *pa = qobject_cast<QAction*>(sender());
    if (!pa || pa->data().toString().isEmpty()) return;

    setText(pa->data().toString());
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
