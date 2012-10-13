/* display_filter_edit.cpp
 *
 * $Id$
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

#include "globals.h"

#include <glib.h>

#include <epan/proto.h>

#include "display_filter_edit.h"
#include "syntax_line_edit.h"

#include "ui/utf8_entities.h"

// platform
//   osx
//   win
//   default

#if defined(Q_WS_MAC) && 0
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
#define DEFAULT_MODIFIER QChar(0x2318) // PLACE OF INTEREST SIGN
#else
#define DEFAULT_MODIFIER "Ctrl-"
#endif

// XXX - We need simplified (button- and dropdown-free) versions for use in dialogs and field-only checking.

DisplayFilterEdit::DisplayFilterEdit(QWidget *parent, bool plain) :
    SyntaxLineEdit(parent),
    plain_(plain),
    field_name_only_(false)
{
    setAccessibleName(tr("Display filter entry"));

    if (plain_) {
        empty_filter_message_ = QString(tr("Enter a display filter %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);
    } else {
        empty_filter_message_ = QString(tr("Apply a display filter %1 <%2/>")).arg(UTF8_HORIZONTAL_ELLIPSIS)
    .arg(DEFAULT_MODIFIER);
    }

    //   DFCombo
    //     Bookmark (star)
    //     DispalyFilterEdit
    //     Clear button
    //     Apply (right arrow) + Cancel (x) + Reload (arrowed circle)
    //     Down Arrow

    // XXX - Move bookmark and apply buttons to the toolbar a la Firefox, Chrome & Safari?
    // XXX - Use native buttons on OS X?

    bookmark_button_ = new QToolButton(this);
    bookmark_button_->setCursor(Qt::ArrowCursor);
    bookmark_button_->setStyleSheet(QString(
            "QToolButton { /* all types of tool button */"
            "  border 0 0 0 0;"
            "  border-right: %1px solid gray;"
            "  border-top-left-radius: 3px;"
            "  border-bottom-left-radius: 3px;"
            "  padding-left: 1px;"
            "  image: url(:/dfilter/dfilter_bookmark_normal.png);"
//            "  background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,"
//            "                                      stop: 0 #f6f7fa, stop: 1 #dadbde);"
            "}"

            "QToolButton:hover {"
            "  image: url(:/dfilter/dfilter_bookmark_hover.png);"
            "}"
            "QToolButton:pressed {"
            "  image: url(:/dfilter/dfilter_bookmark_pressed.png);"
            "}"

//            "QToolButton:pressed {"
//            "    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,"
//            "                                      stop: 0 #dadbde, stop: 1 #f6f7fa);"
//            "}"

            ).arg(plain_ ? 0 : 1)
            );
    connect(bookmark_button_, SIGNAL(clicked()), this, SLOT(showDisplayFilterDialog()));

    clear_button_ = new QToolButton(this);
    clear_button_->setCursor(Qt::ArrowCursor);
    clear_button_->setStyleSheet(
            "QToolButton {"
            "  image: url(:/dfilter/dfilter_erase_normal.png);"
            "  border: none;"
            "  width: 16px;"
            "}"
            "QToolButton:hover {"
            "  image: url(:/dfilter/dfilter_erase_active.png);"
            "}"
            "QToolButton:pressed {"
            "  image: url(:/dfilter/dfilter_erase_selected.png);"
            "}"
            );
    clear_button_->hide();
    connect(clear_button_, SIGNAL(clicked()), this, SLOT(clear()));
    connect(this, SIGNAL(textChanged(const QString&)), this, SLOT(checkFilter(const QString&)));

    apply_button_ = NULL;
    if (!plain_) {
        apply_button_ = new QToolButton(this);
        apply_button_->setCursor(Qt::ArrowCursor);
        apply_button_->setStyleSheet(
                "QToolButton { /* all types of tool button */"
                "  border 0 0 0 0;"
                "  border-top-right-radius: 3px;"
                "  border-bottom-right-radius: 3px;"
                "  padding-right: 1px;"
                "  image: url(:/dfilter/dfilter_apply_normal.png);"
                "}"

                "QToolButton:hover {"
                "  image: url(:/dfilter/dfilter_apply_hover.png);"
                "}"
                "QToolButton:pressed {"
                "  image: url(:/dfilter/dfilter_apply_pressed.png);"
                "}"
                );
        connect(apply_button_, SIGNAL(clicked()), this, SLOT(applyDisplayFilter()));
        connect(this, SIGNAL(returnPressed()), this, SLOT(applyDisplayFilter()));
    }

    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize bksz = bookmark_button_->sizeHint();
    QSize cbsz = clear_button_->sizeHint();
    QSize apsz;
    if (apply_button_) {
        apsz = apply_button_->sizeHint();
    } else {
        apsz.setHeight(0); apsz.setWidth(0);
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

        p.drawText(cr, Qt::AlignLeft|Qt::AlignVCenter, empty_filter_message_);
    }
    // else check filter syntax and set the background accordingly
    // XXX - Should we add little warning/error icons as well?
}

void DisplayFilterEdit::resizeEvent(QResizeEvent *)
{
    QSize cbsz = clear_button_->sizeHint();
    QSize apsz;
    if (apply_button_) {
        apsz = apply_button_->sizeHint();
    } else {
        apsz.setHeight(0); apsz.setWidth(0);
    }
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    clear_button_->move(rect().right() - frameWidth - cbsz.width() - apsz.width(),
                      (rect().bottom() + 1 - cbsz.height())/2);
    if (apply_button_) {
        apply_button_->move(rect().right() - frameWidth - apsz.width(),
                          (rect().bottom() + 1 - apsz.height())/2);
    }
}

void DisplayFilterEdit::checkFilter(const QString& text)
{
    dfilter_t *dfp;
    guchar c;

    clear_button_->setVisible(!text.isEmpty());

    popFilterSyntaxStatus();

    if (field_name_only_ && (c = proto_check_field_name(text.toUtf8().constData()))) {
        setSyntaxState(Invalid);
        emit pushFilterSyntaxStatus(QString().sprintf("Illegal character in field name: '%c'", c));
    } else if (dfilter_compile(text.toUtf8().constData(), &dfp)) {
        GPtrArray *depr = NULL;
        if (dfp != NULL) {
            depr = dfilter_deprecated_tokens(dfp);
        }
        if (text.length() < 1) {
            setSyntaxState(Empty);
        } else if (depr) {
            /* You keep using that word. I do not think it means what you think it means. */
            setSyntaxState(Deprecated);
            /*
             * We're being lazy and only printing the first "problem" token.
             * Would it be better to print all of them?
             */
            emit pushFilterSyntaxWarning(QString().sprintf("\"%s\" may have unexpected results (see the User's Guide)",
                                                          (const char *) g_ptr_array_index(depr, 0)));
        } else {
            setSyntaxState(Valid);
        }
        dfilter_free(dfp);
    } else {
        setSyntaxState(Invalid);
        QString invalidMsg(tr("Invalid filter"));
        if (dfilter_error_msg) {
            invalidMsg.append(QString().sprintf(": %s", dfilter_error_msg));
        }
        emit pushFilterSyntaxStatus(invalidMsg);
    }

    if (apply_button_) {
        apply_button_->setEnabled(SyntaxState() == Empty || syntaxState() == Valid);
    }
}

void DisplayFilterEdit::showDisplayFilterDialog()
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: implement display filter dialog for \"%s\"", this->text().toUtf8().constData());
}

void DisplayFilterEdit::applyDisplayFilter()
{
    QString    dfString(text());
    gchar *dftext = NULL;
    cf_status_t cf_status;

    if (syntaxState() != Valid && syntaxState() != Empty) {
        return;
    }

    if (dfString.length() > 0)
        dftext = g_strdup(dfString.toUtf8().constData());
    cf_status = cf_filter_packets(&cfile, dftext, FALSE);
    g_free(dftext);

    if (cf_status == CF_OK) {
        if (apply_button_) {
            apply_button_->setEnabled(false);
        }
        if (dfString.length() < 1) {
//            gtk_widget_set_sensitive (g_object_get_data (G_OBJECT(filter_cm), E_DFILTER_CLEAR_KEY), FALSE);
//            gtk_widget_set_sensitive (g_object_get_data (G_OBJECT(filter_cm), E_DFILTER_SAVE_KEY), FALSE);
        }
    }

    if (cf_status == CF_OK && dfString.length() > 0) {
//        int index;

        g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: add \"%s\" to recent display filters", this->text().toUtf8().constData());

//        if(!dfilter_entry_match(filter_cm,s, &index)){
//            gtk_combo_box_text_prepend_text(GTK_COMBO_BOX_TEXT(filter_cm), s);
//            index++;
//        }
//        while ((guint)index >= prefs.gui_recent_df_entries_max){
//            gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(filter_cm), index);
//            index--;
//        }
    }
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
