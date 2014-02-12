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

#include "display_filter_edit.h"
#include "syntax_line_edit.h"

#include <QPainter>
#include <QStyleOptionFrame>

#include "ui/utf8_entities.h"

// platform
//   osx
//   win
//   default

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
#define DEFAULT_MODIFIER QChar(0x2318) // PLACE OF INTEREST SIGN
#else
#define DEFAULT_MODIFIER "Ctrl-"
#endif

// XXX - We need simplified (button- and dropdown-free) versions for use in dialogs and field-only checking.

DisplayFilterEdit::DisplayFilterEdit(QWidget *parent, bool plain) :
    SyntaxLineEdit(parent),
    plain_(plain),
    apply_button_(NULL)

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
    //     Combo drop-down

    // XXX - Move bookmark and apply buttons to the toolbar a la Firefox, Chrome & Safari?
    // XXX - Use native buttons on OS X?

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
    clear_button_->move(contentsRect().right() - frameWidth - cbsz.width() - apsz.width(),
                        contentsRect().top());
    clear_button_->setMaximumHeight(contentsRect().height());
    if (apply_button_) {
        apply_button_->move(contentsRect().right() - frameWidth - apsz.width(),
                            contentsRect().top());
        apply_button_->setMaximumHeight(contentsRect().height());
    }
    bookmark_button_->setMaximumHeight(contentsRect().height());
}

void DisplayFilterEdit::checkFilter(const QString& text)
{
    clear_button_->setVisible(!text.isEmpty());

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
        QString invalidMsg(tr("Invalid filter"));
        if (dfilter_error_msg) {
            invalidMsg.append(QString().sprintf(": %s", dfilter_error_msg));
        }
        emit pushFilterSyntaxStatus(invalidMsg);
        break;
    }
    default:
        break;
    }

    bookmark_button_->setEnabled(syntaxState() == Valid || syntaxState() == Deprecated);
    if (apply_button_) {
        apply_button_->setEnabled(SyntaxState() != Invalid);
    }
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
    if (syntaxState() != Valid && syntaxState() != Empty) {
        return;
    }

    QString new_filter = text();
    emit filterPackets(new_filter, true);
}

void DisplayFilterEdit::displayFilterSuccess(bool success)
{
    apply_button_->setEnabled(!success);
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
