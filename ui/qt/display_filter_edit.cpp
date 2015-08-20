/* display_filter_edit.cpp
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

#include <ui/filters.h>

#include "ui/utf8_entities.h"

#include "display_filter_edit.h"
#include "syntax_line_edit.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QCompleter>
#include <QEvent>
#include <QPainter>
#include <QStringListModel>
#include <QStyleOptionFrame>
#include <QToolButton>

#include "ui/utf8_entities.h"

// To do:
// - Implement the bookmark button.
// - Add @2x icons or find a nice set of license-compatible glyph icons and use them instead.
// - We need simplified (button- and dropdown-free) versions for use in dialogs and field-only checking.
// - Move bookmark and apply buttons to the toolbar a la Firefox, Chrome & Safari?
// - Use native buttons on OS X?
// - Add a separator or otherwise distinguish between recent items and fields
//   in the completion dropdown.

#if defined(Q_OS_MAC) && 0
// http://developer.apple.com/library/mac/#documentation/Cocoa/Reference/ApplicationKit/Classes/NSImage_Class/Reference/Reference.html
// http://www.virtualbox.org/svn/vbox/trunk/src/VBox/Frontends/VirtualBox/src/platform/darwin/UICocoaSpecialControls.mm

class UIMiniCancelButton: public QAbstractButton
{
    Q_OBJECT;

public:
    UIMiniCancelButton(QWidget *pParent = 0);

    void setText(const QString &strText) { m_pButton->setText(strText); }
    void setToolTip(const QString &strTip) { m_pButton->setToolTip(strTip); }
    void removeBorder() {}

protected:
    void paintEvent(QPaintEvent * /* pEvent */) {}
    void resizeEvent(QResizeEvent *pEvent);

private:
    UICocoaButton *m_pButton;
};

UIMiniCancelButton::UIMiniCancelButton(QWidget *pParent /* = 0 */)
  : QAbstractButton(pParent)
{
    setShortcut(QKeySequence(Qt::Key_Escape));
    m_pButton = new UICocoaButton(UICocoaButton::CancelButton, this);
    connect(m_pButton, SIGNAL(clicked()),
            this, SIGNAL(clicked()));
    setFixedSize(m_pButton->size());
}

#endif

#ifdef __APPLE__
#define DEFAULT_MODIFIER UTF8_PLACE_OF_INTEREST_SIGN
#else
#define DEFAULT_MODIFIER "Ctrl-"
#endif

// proto.c:fld_abbrev_chars
static const QString fld_abbrev_chars_ = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

DisplayFilterEdit::DisplayFilterEdit(QWidget *parent, bool plain) :
    SyntaxLineEdit(parent),
    plain_(plain),
    bookmark_button_(NULL),
    clear_button_(NULL),
    apply_button_(NULL)
{
    setAccessibleName(tr("Display filter entry"));

    completion_model_ = new QStringListModel(this);
    setCompleter(new QCompleter(completion_model_, this));
    setCompletionTokenChars(fld_abbrev_chars_);

    if (plain_) {
        placeholder_text_ = QString(tr("Enter a display filter %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);
    } else {
        placeholder_text_ = QString(tr("Apply a display filter %1 <%2/>")).arg(UTF8_HORIZONTAL_ELLIPSIS)
    .arg(DEFAULT_MODIFIER);
    }
#if QT_VERSION >= QT_VERSION_CHECK(4, 7, 0)
    setPlaceholderText(placeholder_text_);
#endif

    //   DFCombo
    //     Bookmark (star)
    //     DispalyFilterEdit
    //     Clear button
    //     Apply (right arrow) + Cancel (x) + Reload (arrowed circle)
    //     Combo drop-down

    if (!plain_) {
        bookmark_button_ = new QToolButton(this);
        bookmark_button_->setEnabled(false);
        bookmark_button_->setCursor(Qt::ArrowCursor);
        bookmark_button_->setStyleSheet(QString(
                "QToolButton { /* all types of tool button */"
                "  border 0 0 0 0;"
#ifdef Q_OS_MAC
                "  border-right: %1px solid gray;"
#else
                "  border-right: %1px solid palette(shadow);"
#endif
                "  border-top-left-radius: 3px;"
                "  border-bottom-left-radius: 3px;"
                "  padding-left: 1px;"
                "  image: url(:/dfilter/dfilter_bookmark_normal.png) center;"
                "}"

                "QToolButton:hover {"
                "  image: url(:/dfilter/dfilter_bookmark_hover.png) center;"
                "}"
                "QToolButton:pressed {"
                "  image: url(:/dfilter/dfilter_bookmark_pressed.png) center;"
                "}"
                "QToolButton:disabled {"
                "  image: url(:/dfilter/dfilter_bookmark_disabled.png) center;"
                "}"
                ).arg(plain_ ? 0 : 1)
                );
#ifndef QT_NO_TOOLTIP
        bookmark_button_->setToolTip(tr("Bookmark this filter string"));
#endif // QT_NO_TOOLTIP
        connect(bookmark_button_, SIGNAL(clicked()), this, SLOT(bookmarkClicked()));
    }

    if (!plain_) {
        clear_button_ = new QToolButton(this);
        clear_button_->setCursor(Qt::ArrowCursor);
        clear_button_->setStyleSheet(
                "QToolButton {"
                "  image: url(:/dfilter/dfilter_erase_normal.png) center;"
                "  border: none;"
                "  width: 16px;"
                "}"
                "QToolButton:hover {"
                "  image: url(:/dfilter/dfilter_erase_active.png) center;"
                "}"
                "QToolButton:pressed {"
                "  image: url(:/dfilter/dfilter_erase_selected.png) center;"
                "}"
                );
#ifndef QT_NO_TOOLTIP
        clear_button_->setToolTip(tr("Clear the filter string and update the display"));
#endif // QT_NO_TOOLTIP
        clear_button_->hide();
        connect(clear_button_, SIGNAL(clicked()), this, SLOT(clearFilter()));
    }

    connect(this, SIGNAL(textChanged(const QString&)), this, SLOT(checkFilter(const QString&)));

    if (!plain_) {
        apply_button_ = new QToolButton(this);
        apply_button_->setCursor(Qt::ArrowCursor);
        apply_button_->setEnabled(false);
        apply_button_->setStyleSheet(
                "QToolButton { /* all types of tool button */"
                "  border 0 0 0 0;"
                "  border-top-right-radius: 3px;"
                "  border-bottom-right-radius: 3px;"
                "  padding-right: 1px;"
                "  image: url(:/dfilter/dfilter_apply_normal.png) center;"
                "}"

                "QToolButton:hover {"
                "  image: url(:/dfilter/dfilter_apply_hover.png) center;"
                "}"
                "QToolButton:pressed {"
                "  image: url(:/dfilter/dfilter_apply_pressed.png) center;"
                "}"
                "QToolButton:disabled {"
                "  image: url(:/dfilter/dfilter_apply_disabled.png) center;"
                "}"
                );
#ifndef QT_NO_TOOLTIP
        apply_button_->setToolTip(tr("Apply this filter string to the display"));
#endif // QT_NO_TOOLTIP
        connect(apply_button_, SIGNAL(clicked()), this, SLOT(applyDisplayFilter()));
        connect(this, SIGNAL(returnPressed()), this, SLOT(applyDisplayFilter()));
    }

    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize bksz;
    if (bookmark_button_) {
        bksz = bookmark_button_->sizeHint();
    }
    QSize cbsz;
    if (clear_button_) {
        cbsz = clear_button_->sizeHint();
    }
    QSize apsz;
    if (apply_button_) {
        apsz = apply_button_->sizeHint();
    }
    setStyleSheet(QString(
            "DisplayFilterEdit {"
            "  padding-left: %1px;"
            "  margin-left: %2px;"
            "  margin-right: %3px;"
            "}"
            )
            .arg(frameWidth + 1)
            .arg(bksz.width())
            .arg(cbsz.width() + apsz.width() + frameWidth + 1)
                  );
}

#if QT_VERSION < QT_VERSION_CHECK(4, 7, 0)
void DisplayFilterEdit::paintEvent(QPaintEvent *evt) {
    SyntaxLineEdit::paintEvent(evt);

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
}
#endif // QT < 4.7

void DisplayFilterEdit::resizeEvent(QResizeEvent *)
{
    QSize cbsz;
    if (clear_button_) {
        cbsz = clear_button_->sizeHint();
    }
    QSize apsz;
    if (apply_button_) {
        apsz = apply_button_->sizeHint();
    } else {
        apsz.setHeight(0); apsz.setWidth(0);
    }
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    if (clear_button_) {
        clear_button_->move(contentsRect().right() - frameWidth - cbsz.width() - apsz.width(),
                            contentsRect().top());
        clear_button_->setMaximumHeight(contentsRect().height());
    }
    if (apply_button_) {
        apply_button_->move(contentsRect().right() - frameWidth - apsz.width(),
                            contentsRect().top());
        apply_button_->setMaximumHeight(contentsRect().height());
    }
    if (bookmark_button_) {
        bookmark_button_->setMaximumHeight(contentsRect().height());
    }
}

void DisplayFilterEdit::focusOutEvent(QFocusEvent *event)
{
    if (syntaxState() == Valid)
        emit popFilterSyntaxStatus();
    SyntaxLineEdit::focusOutEvent(event);
}

bool DisplayFilterEdit::checkFilter()
{
    checkFilter(text());

    return syntaxState() != Invalid;
}

void DisplayFilterEdit::checkFilter(const QString& text)
{
    if (clear_button_) {
        clear_button_->setVisible(!text.isEmpty());
    }

    popFilterSyntaxStatus();
    checkDisplayFilter(text);

    switch (syntaxState()) {
    case Deprecated:
    {
        /*
         * We're being lazy and only printing the first "problem" token.
         * Would it be better to print all of them?
         */
        QString deprecatedMsg(tr("\"%1\" may have unexpected results (see the User's Guide)")
                .arg(deprecatedToken()));
        emit pushFilterSyntaxWarning(deprecatedMsg);
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

    if (bookmark_button_) {
        bookmark_button_->setEnabled(syntaxState() == Valid || syntaxState() == Deprecated);
    }
    if (apply_button_) {
        apply_button_->setEnabled(syntaxState() != Invalid);
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
void DisplayFilterEdit::buildCompletionList(const QString &field_word)
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

    // Grab matching display filters from our parent combo and from the
    // saved display filters file. Skip ones that look like single fields
    // and assume they will be added below.
    QStringList complex_list;
    QComboBox *df_combo = qobject_cast<QComboBox *>(parent());
    if (df_combo) {
        for (int i = 0; i < df_combo->count() ; i++) {
            QString recent_filter = df_combo->itemText(i);

            if (isComplexFilter(recent_filter)) {
                complex_list << recent_filter;
            }
        }
    }
    for (const GList *df_item = get_filter_list_first(DFILTER_LIST); df_item; df_item = g_list_next(df_item)) {
        const filter_def *df_def = (filter_def *) df_item->data;
        if (!df_def || !df_def->strval) continue;
        QString saved_filter = df_def->strval;

        if (isComplexFilter(saved_filter) && !complex_list.contains(saved_filter)) {
            complex_list << saved_filter;
        }
    }
    completion_model_->setStringList(complex_list);
    completer()->setCompletionPrefix(field_word);

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

    completion_model_->setStringList(complex_list + field_list);
    completer()->setCompletionPrefix(field_word);
}

void DisplayFilterEdit::bookmarkClicked()
{
    emit addBookmark(text());
}

void DisplayFilterEdit::clearFilter()
{
    clear();
    QString new_filter;
    emit filterPackets(new_filter, true);
}

void DisplayFilterEdit::applyDisplayFilter()
{
    if (syntaxState() == Invalid) {
        return;
    }

    QString new_filter = text();
    emit filterPackets(new_filter, true);
}

void DisplayFilterEdit::displayFilterSuccess(bool success)
{
    apply_button_->setEnabled(!success);
}

void DisplayFilterEdit::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            if (plain_) {
                placeholder_text_ = QString(tr("Enter a display filter %1")).
                    arg(UTF8_HORIZONTAL_ELLIPSIS);
            } else {
                placeholder_text_ = QString(tr("Apply a display filter %1 <%2/>"))
                    .arg(UTF8_HORIZONTAL_ELLIPSIS).arg(DEFAULT_MODIFIER);
            }
#if QT_VERSION >= QT_VERSION_CHECK(4, 7, 0)
            setPlaceholderText(placeholder_text_);
#endif
            break;
        default:
            break;
        }
    }
    SyntaxLineEdit::changeEvent(event);
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
