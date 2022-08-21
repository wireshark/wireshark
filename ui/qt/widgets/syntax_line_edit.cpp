/* syntax_line_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>
#include <epan/column.h>

#include <wsutil/utf8_entities.h>

#include <ui/qt/widgets/syntax_line_edit.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/stock_icon.h>

#include <QAbstractItemView>
#include <QApplication>
#include <QCompleter>
#include <QKeyEvent>
#include <QPainter>
#include <QScrollBar>
#include <QStringListModel>
#include <QStyleOptionFrame>
#include <limits>

const int max_completion_items_ = 20;

SyntaxLineEdit::SyntaxLineEdit(QWidget *parent) :
    QLineEdit(parent),
    completer_(NULL),
    completion_model_(NULL),
    completion_enabled_(false)
{
    setSyntaxState();
    setMaxLength(std::numeric_limits<quint32>::max());
}

// Override setCompleter so that we don't clobber the filter text on activate.
void SyntaxLineEdit::setCompleter(QCompleter *c)
{
    if (completer_)
        QObject::disconnect(completer_, 0, this, 0);

    completer_ = c;

    if (!completer_)
        return;

    completer_->setWidget(this);
    completer_->setCompletionMode(QCompleter::PopupCompletion);
    completer_->setCaseSensitivity(Qt::CaseInsensitive);
    // Completion items are not guaranteed to be sorted (recent filters +
    // fields), so no setModelSorting.
    completer_->setMaxVisibleItems(max_completion_items_);
    QObject::connect(completer_, static_cast<void (QCompleter::*)(const QString &)>(&QCompleter::activated),
                     this, &SyntaxLineEdit::insertFieldCompletion);

    // Auto-completion is turned on.
    completion_enabled_ = true;
}

void SyntaxLineEdit::allowCompletion(bool enabled)
{
    completion_enabled_ = enabled;
}

void SyntaxLineEdit::setSyntaxState(SyntaxState state) {
    syntax_state_ = state;

    // XXX Should we drop the background colors here in favor of ::paintEvent below?
    QColor valid_bg = ColorUtils::fromColorT(&prefs.gui_text_valid);
    QColor valid_fg = ColorUtils::contrastingTextColor(valid_bg);
    QColor invalid_bg = ColorUtils::fromColorT(&prefs.gui_text_invalid);
    QColor invalid_fg = ColorUtils::contrastingTextColor(invalid_bg);
    QColor deprecated_bg = ColorUtils::fromColorT(&prefs.gui_text_deprecated);
    QColor deprecated_fg = ColorUtils::contrastingTextColor(deprecated_bg);

    // Try to matche QLineEdit's placeholder text color (which sets the
    // alpha channel to 50%, which doesn't work in style sheets).
    // Setting the foreground color lets us avoid yet another background
    // color preference and should hopefully make things easier to
    // distinguish for color blind folk.
    QColor busy_fg = ColorUtils::alphaBlend(QApplication::palette().text(), QApplication::palette().base(), 0.5);

    state_style_sheet_ = QString(
            "SyntaxLineEdit[syntaxState=\"%1\"] {"
            "  color: %2;"
            "  background-color: %3;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%4\"] {"
            "  color: %5;"
            "  background-color: %6;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%7\"] {"
            "  color: %8;"
            "  background-color: %9;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%10\"] {"
            "  color: %11;"
            "  background-color: %12;"
            "}"
            )

            // CSS selector, foreground, background
            .arg(Valid)
            .arg(valid_fg.name())
            .arg(valid_bg.name())

            .arg(Invalid)
            .arg(invalid_fg.name())
            .arg(invalid_bg.name())

            .arg(Deprecated)
            .arg(deprecated_fg.name())
            .arg(deprecated_bg.name())

            .arg(Busy)
            .arg(busy_fg.name())
            .arg(palette().base().color().name())
            ;
    setStyleSheet(style_sheet_);
}

QString SyntaxLineEdit::syntaxErrorMessage()
{
    return syntax_error_message_;
}

QString SyntaxLineEdit::syntaxErrorMessageFull()
{
    return syntax_error_message_full_;
}

QString SyntaxLineEdit::createSyntaxErrorMessageFull(
                                const QString &filter, const QString &err_msg,
                                qsizetype loc_start, size_t loc_length)
{
    QString msg = tr("Invalid filter: %1").arg(err_msg);

    if (loc_start >= 0 && loc_length >= 1) {
        // Add underlined location
        msg = QString("<p>%1<pre>  %2\n  %3^%4</pre></p>")
            .arg(msg)
            .arg(filter)
            .arg(QString(' ').repeated(loc_start))
            .arg(QString('~').repeated(loc_length - 1));
    }
    return msg;
}

QString SyntaxLineEdit::styleSheet() const {
    return style_sheet_;
}

void SyntaxLineEdit::setStyleSheet(const QString &style_sheet) {
    style_sheet_ = style_sheet;
    QLineEdit::setStyleSheet(style_sheet_ + state_style_sheet_);
}

void SyntaxLineEdit::insertFilter(const QString &filter)
{
    QString padded_filter = filter;

    if (hasSelectedText()) {
        backspace();
    }

    int pos = cursorPosition();
    if (pos > 0 && !text().at(pos - 1).isSpace()) {
        padded_filter.prepend(" ");
    }
    if (pos < text().length() - 1 && !text().at(pos + 1).isSpace()) {
        padded_filter.append(" ");
    }
    insert(padded_filter);
}

bool SyntaxLineEdit::checkDisplayFilter(QString filter)
{
    if (!completion_enabled_) {
        return false;
    }

    if (filter.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return true;
    }

    dfilter_t *dfp = NULL;
    gchar *err_msg;
    dfilter_loc_t loc;
    if (dfilter_compile2(filter.toUtf8().constData(), &dfp, &err_msg, &loc)) {
        GPtrArray *depr = NULL;
        if (dfp) {
            depr = dfilter_deprecated_tokens(dfp);
        }
        if (depr) {
            // You keep using that word. I do not think it means what you think it means.
            // Possible alternatives: ::Troubled, or ::Problematic maybe?
            setSyntaxState(SyntaxLineEdit::Deprecated);
            /*
             * We're being lazy and only printing the first "problem" token.
             * Would it be better to print all of them?
             */
            QString token((const char *)g_ptr_array_index(depr, 0));
            gchar *token_str = qstring_strdup(token.section('.', 0, 0));
            header_field_info *hfi = proto_registrar_get_byalias(token_str);
            if (hfi)
                syntax_error_message_ = tr("\"%1\" is deprecated in favour of \"%2\". "
                                           "See Help section 6.4.8 for details.").arg(token_str).arg(hfi->abbrev);
            else
                // The token_str is the message.
                syntax_error_message_ = tr("%1").arg(token_str);
            g_free(token_str);
        } else {
            setSyntaxState(SyntaxLineEdit::Valid);
        }
    } else {
        setSyntaxState(SyntaxLineEdit::Invalid);
        syntax_error_message_ = QString::fromUtf8(err_msg);
        syntax_error_message_full_ = createSyntaxErrorMessageFull(filter, syntax_error_message_, loc.col_start, loc.col_len);
        g_free(err_msg);
    }
    dfilter_free(dfp);

    return true;
}

void SyntaxLineEdit::checkFieldName(QString field)
{
    if (field.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    char invalid_char = proto_check_field_name(field.toUtf8().constData());
    if (invalid_char) {
        setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        checkDisplayFilter(field);
    }
}

void SyntaxLineEdit::checkCustomColumn(QString fields)
{
    if (fields.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    gchar **splitted_fields = g_regex_split_simple(COL_CUSTOM_PRIME_REGEX,
                fields.toUtf8().constData(), G_REGEX_ANCHORED, G_REGEX_MATCH_ANCHORED);

    for (guint i = 0; i < g_strv_length(splitted_fields); i++) {
        if (splitted_fields[i] && *splitted_fields[i]) {
            if (proto_check_field_name(splitted_fields[i]) != 0) {
                setSyntaxState(SyntaxLineEdit::Invalid);
                g_strfreev(splitted_fields);
                return;
            }
        }
    }
    g_strfreev(splitted_fields);

    checkDisplayFilter(fields);
}

void SyntaxLineEdit::checkInteger(QString number)
{
    if (number.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    bool ok;
    text().toInt(&ok);
    if (ok) {
        setSyntaxState(SyntaxLineEdit::Valid);
    } else {
        setSyntaxState(SyntaxLineEdit::Invalid);
    }
}

bool SyntaxLineEdit::isComplexFilter(const QString &filter)
{
    bool is_complex = false;
    for (int i = 0; i < filter.length(); i++) {
        if (!token_chars_.contains(filter.at(i))) {
            is_complex = true;
            break;
        }
    }
    // Don't complete the current filter.
    if (is_complex && filter.startsWith(text()) && filter.compare(text())) {
        return true;
    }
    return false;
}

bool SyntaxLineEdit::event(QEvent *event)
{
    if (event->type() == QEvent::ShortcutOverride) {
        // You can't set time display formats while the display filter edit
        // has focus.

        // Keep shortcuts in the main window from stealing keyPressEvents
        // with Ctrl+Alt modifiers from us. This is a problem for many AltGr
        // combinations since they are delivered with Ctrl+Alt modifiers
        // instead of Qt::Key_AltGr and they tend to match the time display
        // format shortcuts.

        // Uncommenting the qDebug line below prints the following here:
        //
        // US Keyboard:
        // Ctrl+o: 79 QFlags<Qt::KeyboardModifiers>(ControlModifier) "\u000F"
        // Ctrl+Alt+2: 50 QFlags<Qt::KeyboardModifiers>(ControlModifier|AltModifier) "2"
        //
        // Swedish (Sweden) Keyboard:
        // Ctrl+o: 79 QFlags<Qt::KeyboardModifiers>(ControlModifier) "\u000F"
        // Ctrl+Alt+2: 64 QFlags<Qt::KeyboardModifiers>(ControlModifier|AltModifier) "@"
        // AltGr+{: 123 QFlags<Qt::KeyboardModifiers>(ControlModifier|AltModifier) "{"

        QKeyEvent* key_event = static_cast<QKeyEvent*>(event);
        // qDebug() << "=so" << key_event->key() << key_event->modifiers() << key_event->text();

        if (key_event->modifiers() == Qt::KeyboardModifiers(Qt::ControlModifier|Qt::AltModifier)) {
            event->accept();
            return true;
        }
    }
    return QLineEdit::event(event);
}

void SyntaxLineEdit::completionKeyPressEvent(QKeyEvent *event)
{
    // Forward to the completer if needed...
    if (completer_ && completer_->popup()->isVisible()) {
        switch (event->key()) {
        case Qt::Key_Enter:
        case Qt::Key_Return:
            break;
        case Qt::Key_Tab:
            focusNextChild();
            break;
        case Qt::Key_Escape:
        case Qt::Key_Backtab:
            event->ignore();
            return;
        default:
            break;
        }
    }

    // ...otherwise process the key ourselves.
    SyntaxLineEdit::keyPressEvent(event);

    if (!completion_enabled_ || !completer_ || !completion_model_ || !prefs.gui_autocomplete_filter) return;

    // Do nothing on bare shift.
    if ((event->modifiers() & Qt::ShiftModifier) && event->text().isEmpty()) return;

    if (event->modifiers() & (Qt::ControlModifier | Qt::AltModifier | Qt::MetaModifier)) {
        completer_->popup()->hide();
        return;
    }

    QPoint token_coords(getTokenUnderCursor());

    QString token_word = text().mid(token_coords.x(), token_coords.y());
    buildCompletionList(token_word);

    if (completion_model_->stringList().length() < 1) {
        completer_->popup()->hide();
        return;
    }

    QRect cr = cursorRect();
    cr.setWidth(completer_->popup()->sizeHintForColumn(0)
                + completer_->popup()->verticalScrollBar()->sizeHint().width());
    completer_->complete(cr);
}

void SyntaxLineEdit::completionFocusInEvent(QFocusEvent *event)
{
    if (completer_)
        completer_->setWidget(this);
    SyntaxLineEdit::focusInEvent(event);
}

void SyntaxLineEdit::focusOutEvent(QFocusEvent *event)
{
    if (completer_ && completer_->popup()->isVisible() && event->reason() == Qt::PopupFocusReason) {
        // Pretend we still have focus so that we'll draw our cursor.
        // If cursorRect() were more precise we could just draw the cursor
        // during a paintEvent.
        return;
    }
    QLineEdit::focusOutEvent(event);
}

// Add indicator icons for syntax states in order to make things more clear for
// color blind people.
void SyntaxLineEdit::paintEvent(QPaintEvent *event)
{
    QStyleOptionFrame opt;
    initStyleOption(&opt);
    QRect cr = style()->subElementRect(QStyle::SE_LineEditContents, &opt, this);
    QPainter painter(this);

    // In my (gcc) testing here, if I add "background: yellow;" to the DisplayFilterCombo
    // stylesheet, when building with Qt 5.15.2 the combobox background is yellow and the
    // text entry area (between the bookmark and apply button) is drawn in the correct
    // base color (white for light mode and black for dark mode), and the correct syntax
    // color otherwise. When building with Qt 6.2.4 and 6.3.1, the combobox background is
    // yellow and the text entry area is always yellow, i.e. QLineEdit isn't painting its
    // background for some reason.
    //
    // It's not clear if this is a bug or just how things work under Qt6. Either way, it's
    // easy to work around.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    // Must match CaptureFilterEdit and DisplayFilterEdit stylesheets.
    int pad = style()->pixelMetric(QStyle::PM_DefaultFrameWidth) + 1;
    QRect full_cr = cr.adjusted(-pad, 0, 0, 0);
    QBrush bg;

    switch (syntax_state_) {
    case Valid:
        bg = ColorUtils::fromColorT(&prefs.gui_text_valid);
        break;
    case Invalid:
        bg = ColorUtils::fromColorT(&prefs.gui_text_invalid);
        break;
    case Deprecated:
        bg = ColorUtils::fromColorT(&prefs.gui_text_deprecated);
        break;
    default:
        bg = palette().base();
        break;
    }

    painter.fillRect(full_cr, bg);
#endif

    QLineEdit::paintEvent(event);

    QString si_name;

    switch (syntax_state_) {
    case Invalid:
        si_name = "x-filter-invalid";
        break;
    case Deprecated:
        si_name = "x-filter-deprecated";
        break;
    default:
        return;
    }

    QRect sir = QRect(0, 0, 14, 14); // QIcon::paint scales, which is not what we want.
    int textWidth = fontMetrics().boundingRect(text()).width();
    // Qt always adds a margin of 6px between the border and text, see
    // QLineEditPrivate::effectiveLeftTextMargin and
    // QLineEditPrivate::sideWidgetParameters.
    int margin = 2 * 6 + 1;

    if (cr.width() - margin - textWidth < sir.width() || cr.height() < sir.height()) {
        // No space to draw
        return;
    }

    QIcon state_icon = StockIcon(si_name);
    if (state_icon.isNull()) {
        return;
    }

    int si_off = (cr.height() - sir.height()) / 2;
    sir.moveTop(si_off);
    sir.moveRight(cr.right() - si_off);
    painter.save();
    painter.setOpacity(0.25);
    state_icon.paint(&painter, sir);
    painter.restore();
}

void SyntaxLineEdit::insertFieldCompletion(const QString &completion_text)
{
    if (!completer_) return;

    QPoint field_coords(getTokenUnderCursor());

    // Insert only if we have a matching field or if the entry is empty
    if (field_coords.y() < 1 && !text().isEmpty()) {
        completer_->popup()->hide();
        return;
    }

    QString new_text = text().replace(field_coords.x(), field_coords.y(), completion_text);
    setText(new_text);
    setCursorPosition(field_coords.x() + static_cast<int>(completion_text.length()));
    emit textEdited(new_text);
}

QPoint SyntaxLineEdit::getTokenUnderCursor()
{
    if (selectionStart() >= 0) return (QPoint(0,0));

    int pos = cursorPosition();
    int start = pos;
    int len = 0;

    while (start > 0 && token_chars_.contains(text().at(start -1))) {
        start--;
        len++;
    }
    while (pos < text().length() && token_chars_.contains(text().at(pos))) {
        pos++;
        len++;
    }

    return QPoint(start, len);
}
