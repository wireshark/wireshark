/* capture_filter_edit.cpp
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

#include <epan/proto.h>

#include "capture_opts.h"
#include "ui/capture_globals.h"

#include "capture_filter_edit.h"
#include "wireshark_application.h"

#include <QPainter>
#include <QStyleOptionFrame>

#include "ui/utf8_entities.h"
#include "qt_ui_utils.h"

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


// XXX - We need simplified (button- and dropdown-free) versions for use in dialogs and field-only checking.

CaptureFilterEdit::CaptureFilterEdit(QWidget *parent, bool plain) :
    SyntaxLineEdit(parent),
    plain_(plain),
    field_name_only_(false),
    apply_button_(NULL)
{
    setAccessibleName(tr("Capture filter entry"));

    empty_filter_message_ = QString(tr("Enter a capture filter %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);

    //   DFCombo
    //     Bookmark (star)
    //     DispalyFilterEdit
    //     Clear button
    //     Apply (right arrow) + Cancel (x) + Reload (arrowed circle)
    //     Combo drop-down

    // XXX - Move bookmark and apply buttons to the toolbar a la Firefox, Chrome & Safari?
    // XXX - Use native buttons on OS X?

    bookmark_button_ = new QToolButton(this);
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
    clear_button_->hide();
    connect(clear_button_, SIGNAL(clicked()), this, SLOT(clear()));
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
        connect(apply_button_, SIGNAL(clicked()), this, SLOT(applyCaptureFilter()));
        connect(this, SIGNAL(returnPressed()), this, SLOT(applyCaptureFilter()));
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
            "CaptureFilterEdit {"
            "  padding-left: %1px;"
            "  margin-left: %2px;"
            "  margin-right: %3px;"
            "}"
            )
            .arg(frameWidth + 1)
            .arg(bksz.width())
            .arg(cbsz.width() + apsz.width() + frameWidth + 1)
            );

    QThread *syntax_thread = new QThread;
    syntax_worker_ = new CaptureFilterSyntaxWorker;
    syntax_worker_->moveToThread(syntax_thread);
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(initCaptureFilter()));
    connect(syntax_thread, SIGNAL(started()), syntax_worker_, SLOT(start()));
    connect(syntax_thread, SIGNAL(started()), this, SLOT(checkFilter()));
    connect(syntax_worker_, SIGNAL(syntaxResult(QString,bool,QString)),
            this, SLOT(setFilterSyntaxState(QString,bool,QString)));
    connect(syntax_thread, SIGNAL(finished()), syntax_worker_, SLOT(deleteLater()));
    syntax_thread->start();
}

void CaptureFilterEdit::paintEvent(QPaintEvent *evt) {
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

void CaptureFilterEdit::resizeEvent(QResizeEvent *)
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

void CaptureFilterEdit::checkFilter(const QString& text)
{
    setSyntaxState(Empty);
    popFilterSyntaxStatus();
    bool empty = text.isEmpty();

    bookmark_button_->setEnabled(false);
    if (apply_button_) {
        apply_button_->setEnabled(false);
    }

    if (empty) {
        clear_button_->setVisible(false);
        setFilterSyntaxState(text, true, QString());
    } else {
        clear_button_->setVisible(true);
        syntax_worker_->checkFilter(text);
    }
}

void CaptureFilterEdit::checkFilter()
{
    checkFilter(text());
}

void CaptureFilterEdit::initCaptureFilter()
{
#ifdef HAVE_LIBPCAP
    setText(global_capture_opts.default_options.cfilter);
#endif // HAVE_LIBPCAP
}

void CaptureFilterEdit::setFilterSyntaxState(QString filter, bool valid, QString err_msg)
{
    if (filter.compare(text()) == 0) { // The user hasn't changed the filter
        if (valid) {
            setSyntaxState(text().isEmpty() ? Empty : Valid);
        } else {
            setSyntaxState(Invalid);
            emit pushFilterSyntaxStatus(err_msg);
        }
    }

#ifdef HAVE_LIBPCAP
    if (syntaxState() != Invalid) {
        bookmark_button_->setEnabled(true);
        if (apply_button_) {
            apply_button_->setEnabled(true);
        }
        valid = true;
        g_free(global_capture_opts.default_options.cfilter);
        if (filter.isEmpty()) {
            global_capture_opts.default_options.cfilter = NULL;
        } else {
            global_capture_opts.default_options.cfilter = qstring_strdup(filter);
        }

        if (global_capture_opts.num_selected > 0) {
            interface_t device;

            for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
                device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
                if (!device.selected) {
                    continue;
                }
//                if (device.active_dlt == -1) {
//                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The link type of interface %s was not specified.", device.name);
//                    continue;  /* Programming error: somehow managed to select an "unsupported" entry */
//                }
                g_array_remove_index(global_capture_opts.all_ifaces, i);
                device.cfilter = qstring_strdup(filter);
                g_array_insert_val(global_capture_opts.all_ifaces, i, device);
//                update_filter_string(device.name, filter_text);
            }
        }
    }
#endif // HAVE_LIBPCAP

    emit captureFilterSyntaxChanged(valid);
}

void CaptureFilterEdit::bookmarkClicked()
{
    emit addBookmark(text());
}

void CaptureFilterEdit::applyCaptureFilter()
{
    if (syntaxState() == Invalid) {
        return;
    }

    emit startCapture();
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
