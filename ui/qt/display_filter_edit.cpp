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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "config.h"

#include "globals.h"

#include <glib.h>

#include <epan/proto.h>

#include "display_filter_edit.h"

#include "ui/gtk/utf8_entities.h"

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

DisplayFilterEdit::DisplayFilterEdit(QWidget *parent) :
    QLineEdit(parent)
{
    fieldNameOnly = false;
    m_syntaxState = Empty;
    emptyFilterMessage = QString::fromUtf8("Apply a display filter" UTF8_HORIZONTAL_ELLIPSIS " <%1/>").arg(DEFAULT_MODIFIER);

    setAccessibleName("Dispaly filter entry");

    //   DFCombo
    //     Bookmark (star)
    //     DispalyFilterEdit
    //     Clear button
    //     Apply (right arrow) + Cancel (x) + Reload (arrowed circle)
    //     Down Arrow

    // XXX - Move bookmark and apply buttons to the toolbar a la Firefox, Chrome & Safari?
    // XXX - Use native buttons on OS X?

    bookmarkButton = new QToolButton(this);
    bookmarkButton->setCursor(Qt::ArrowCursor);
    bookmarkButton->setStyleSheet(
            "QToolButton { /* all types of tool button */"
            "  border 0 0 0 0;"
            "  border-right: 1px solid gray;"
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

            );
    connect(bookmarkButton, SIGNAL(clicked()), this, SLOT(showDisplayFilterDialog()));

    clearButton = new QToolButton(this);
    clearButton->setCursor(Qt::ArrowCursor);
    clearButton->setStyleSheet(
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
    clearButton->hide();
    connect(clearButton, SIGNAL(clicked()), this, SLOT(clear()));
    connect(this, SIGNAL(textChanged(const QString&)), this, SLOT(checkFilter(const QString&)));

    applyButton = new QToolButton(this);
    applyButton->setCursor(Qt::ArrowCursor);
    applyButton->setStyleSheet(
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
    connect(applyButton, SIGNAL(clicked()), this, SLOT(applyDisplayFilter()));
    connect(this, SIGNAL(returnPressed()), this, SLOT(applyDisplayFilter()));

    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize bksz = bookmarkButton->sizeHint();
    QSize cbsz = clearButton->sizeHint();
    QSize apsz = applyButton->sizeHint();
    syntaxStyleSheet = QString(
            "DisplayFilterEdit {"
            "  padding-left: %1px;"
            "  margin-left: %2px;"
            "  margin-right: %3px;"
            "  background: transparent;"
            "}"

            // Should the backgrounds fade away on the right?
            // Tango "Scarlet Red"
            "DisplayFilterEdit[syntaxState=\"%4\"] {"
            "  color: white;"
            "  background-color: rgba(239, 41, 41, 128);"
            "}"

            // Tango "Butter"
            "DisplayFilterEdit[syntaxState=\"%5\"] {"
            "  color: black;"
            "  background-color: rgba(252, 233, 79, 128);"
            "}"

            // Tango "Chameleon
            "DisplayFilterEdit[syntaxState=\"%6\"] {"
            "  color: black;"
            "  background-color: rgba(138, 226, 52, 128);"
            "}"
            )
            .arg(frameWidth + 1)
            .arg(bksz.width())
            .arg(cbsz.width() + apsz.width() + frameWidth + 1)
            .arg(Invalid)
            .arg(Deprecated)
            .arg(Valid);
    setStyleSheet(syntaxStyleSheet);
}

void DisplayFilterEdit::paintEvent(QPaintEvent *evt) {
    QLineEdit::paintEvent(evt);

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

        p.drawText(cr, Qt::AlignLeft|Qt::AlignVCenter, emptyFilterMessage);
    }
    // else check filter syntax and set the background accordingly
    // XXX - Should we add little warning/error icons as well?
}

void DisplayFilterEdit::resizeEvent(QResizeEvent *)
{
    QSize cbsz = clearButton->sizeHint();
    QSize apsz = applyButton->sizeHint();
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    clearButton->move(rect().right() - frameWidth - cbsz.width() - apsz.width(),
                      (rect().bottom() + 1 - cbsz.height())/2);
    applyButton->move(rect().right() - frameWidth - apsz.width(),
                      (rect().bottom() + 1 - apsz.height())/2);
}

void DisplayFilterEdit::checkFilter(const QString& text)
{
    dfilter_t *dfp;
    GPtrArray *depr = NULL;
    guchar c;

    clearButton->setVisible(!text.isEmpty());

    popFilterSyntaxStatus();

    if (fieldNameOnly && (c = proto_check_field_name(text.toUtf8().constData()))) {
        m_syntaxState = Invalid;
        emit pushFilterSyntaxStatus(QString().sprintf("Illegal character in field name: '%c'", c));
    } else if (dfilter_compile(text.toUtf8().constData(), &dfp)) {
        if (dfp != NULL) {
            depr = dfilter_deprecated_tokens(dfp);
        }
        if (text.length() < 1) {
            m_syntaxState = Empty;
        } else if (depr) {
            /* You keep using that word. I do not think it means what you think it means. */
            m_syntaxState = Deprecated;
            /*
             * We're being lazy and only printing the first "problem" token.
             * Would it be better to print all of them?
             */
            emit pushFilterSyntaxWarning(QString().sprintf("\"%s\" may have unexpected results (see the User's Guide)",
                                                          (const char *) g_ptr_array_index(depr, 0)));
        } else {
            m_syntaxState = Valid;
        }
        dfilter_free(dfp);
    } else {
        m_syntaxState = Invalid;
        QString invalidMsg("Invalid filter");
        if (dfilter_error_msg) {
            invalidMsg.append(QString().sprintf(": %s", dfilter_error_msg));
        }
        emit pushFilterSyntaxStatus(invalidMsg);
    }

    setStyleSheet(syntaxStyleSheet);
    applyButton->setEnabled(m_syntaxState == Empty || m_syntaxState == Valid);

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

    if (m_syntaxState != Valid && m_syntaxState != Empty) {
        return;
    }

    if (dfString.length() > 0)
        dftext = g_strdup(dfString.toUtf8().constData());
    cf_status = cf_filter_packets(&cfile, dftext, FALSE);
    g_free(dftext);

    if (cf_status == CF_OK) {
        applyButton->setEnabled(false);
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
