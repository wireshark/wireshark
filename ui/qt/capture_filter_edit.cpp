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

#include <ui/capture_globals.h>
#include <ui/filters.h>
#include <wsutil/utf8_entities.h>

#include "capture_filter_edit.h"
#include "capture_filter_syntax_worker.h"
#include "stock_icon_tool_button.h"
#include "wireshark_application.h"

#include <QComboBox>
#include <QCompleter>
#include <QPainter>
#include <QStringListModel>
#include <QStyleOptionFrame>

#include "qt_ui_utils.h"

// To do:
// - This duplicates some DisplayFilterEdit code.
// - We need simplified (button- and dropdown-free) versions for use in dialogs and field-only checking.


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

static const QString libpcap_primitive_chars_ = "-0123456789abcdefghijklmnopqrstuvwxyz";

// grep '^[a-z].*return [A-Z].*;$' scanner.l | awk '{gsub(/\|/, "\n") ; print "    << \"" $1 "\""}' | sort
// Remove "and" and "or".
static const QStringList libpcap_primitives_ = QStringList()
        << "aarp" << "action" << "address1" << "address2" << "address3" << "address4"
        << "ah" << "arp" << "atalk" << "bcc" << "broadcast" << "byte" << "carp"
        << "clnp" << "connectmsg" << "csnp" << "decnet" << "direction" << "dpc"
        << "dst" << "es-is" << "esis" << "esp" << "fddi" << "fisu" << "gateway"
        << "greater" << "hdpc" << "hfisu" << "hlssu" << "hmsu" << "hopc" << "host"
        << "hsio" << "hsls" << "icmp" << "icmp6" << "igmp" << "igrp" << "iih" << "ilmic"
        << "inbound" << "ip" << "ip6" << "ipx" << "is-is" << "isis" << "iso" << "l1"
        << "l2" << "lane" << "lat" << "len" << "less" << "link" << "llc" << "lsp"
        << "lssu" << "lsu" << "mask" << "metac" << "metaconnect" << "mopdl" << "moprc"
        << "mpls" << "msu" << "multicast" << "net" << "netbeui" << "oam" << "oamf4"
        << "oamf4ec" << "oamf4sc" << "on" << "opc" << "outbound" << "pim"
        << "port" << "portrange" << "pppoed" << "pppoes" << "proto" << "psnp" << "ra"
        << "radio" << "rarp" << "reason" << "rnr" << "rset" << "sc" << "sca" << "sctp"
        << "sio" << "sls" << "snp" << "src" << "srnr" << "stp" << "subtype" << "ta"
        << "tcp" << "type" << "udp" << "vci" << "vlan" << "vpi" << "vrrp"
        ;

CaptureFilterEdit::CaptureFilterEdit(QWidget *parent, bool plain) :
    SyntaxLineEdit(parent),
    plain_(plain),
    field_name_only_(false),
    bookmark_button_(NULL),
    clear_button_(NULL),
    apply_button_(NULL)
{
    setAccessibleName(tr("Capture filter entry"));

    completion_model_ = new QStringListModel(this);
    setCompleter(new QCompleter(completion_model_, this));
    setCompletionTokenChars(libpcap_primitive_chars_);

    placeholder_text_ = QString(tr("Enter a capture filter %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);
#if QT_VERSION >= QT_VERSION_CHECK(4, 7, 0)
    setPlaceholderText(placeholder_text_);
#endif

    // These are fully implemented in DisplayFilterEdit but not here.

    if (!plain_) {
        bookmark_button_ = new StockIconToolButton(this, "x-filter-bookmark");
        bookmark_button_->setCursor(Qt::ArrowCursor);
        bookmark_button_->setPopupMode(QToolButton::InstantPopup);
        bookmark_button_->setToolTip(tr("Manage saved bookmarks."));
        bookmark_button_->setIconSize(QSize(14, 14));
        bookmark_button_->setStyleSheet(
                    "QToolButton {"
                    "  border: none;"
                    "  background: transparent;" // Disables platform style on Windows.
                    "  padding: 0 0 0 0;"
                    "}"
                    "QToolButton::menu-indicator { image: none; }"
            );
        connect(bookmark_button_, SIGNAL(clicked()), this, SLOT(bookmarkClicked()));
    }

    if (!plain_) {
        clear_button_ = new StockIconToolButton(this, "x-filter-clear");
        clear_button_->setCursor(Qt::ArrowCursor);
        clear_button_->setToolTip(QString());
        clear_button_->setIconSize(QSize(14, 14));
        clear_button_->setStyleSheet(
                "QToolButton {"
                "  border: none;"
                "  background: transparent;" // Disables platform style on Windows.
                "  padding: 0 0 0 0;"
                "  margin-left: 1px;"
                "}"
                );
        connect(clear_button_, SIGNAL(clicked()), this, SLOT(clear()));
    }

    connect(this, SIGNAL(textChanged(const QString&)), this, SLOT(checkFilter(const QString&)));

    if (!plain_) {
        apply_button_ = new StockIconToolButton(this, "x-filter-apply");
        apply_button_->setCursor(Qt::ArrowCursor);
        apply_button_->setEnabled(false);
        apply_button_->setToolTip(tr("Apply this filter string to the display."));
        apply_button_->setIconSize(QSize(24, 14));
        apply_button_->setStyleSheet(
                "QToolButton {"
                "  border: none;"
                "  background: transparent;" // Disables platform style on Windows.
                "  padding: 0 0 0 0;"
                "}"
                );
        connect(apply_button_, SIGNAL(clicked()), this, SLOT(applyCaptureFilter()));
        connect(this, SIGNAL(returnPressed()), this, SLOT(applyCaptureFilter()));
    }

    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize bksz;
    if (bookmark_button_) bksz = bookmark_button_->sizeHint();
    QSize cbsz;
    if (clear_button_) cbsz = clear_button_->sizeHint();
    QSize apsz;
    if (apply_button_) apsz = apply_button_->sizeHint();

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

    checkFilter();
}

#if QT_VERSION < QT_VERSION_CHECK(4, 7, 0)
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

        p.drawText(cr, Qt::AlignLeft|Qt::AlignVCenter, placeholder_text_);
    }
    // else check filter syntax and set the background accordingly
    // XXX - Should we add little warning/error icons as well?
}
#endif // QT < 4.7

void CaptureFilterEdit::resizeEvent(QResizeEvent *)
{
    QSize cbsz;
    if (clear_button_) cbsz = clear_button_->sizeHint();
    QSize apsz;
    if (apply_button_) apsz = apply_button_->sizeHint();

    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    if (clear_button_) {
        clear_button_->move(contentsRect().right() - frameWidth - cbsz.width() - apsz.width(),
                            contentsRect().top());
        clear_button_->setMinimumHeight(contentsRect().height());
        clear_button_->setMaximumHeight(contentsRect().height());
    }
    if (apply_button_) {
        apply_button_->move(contentsRect().right() - frameWidth - apsz.width(),
                            contentsRect().top());
        apply_button_->setMinimumHeight(contentsRect().height());
        apply_button_->setMaximumHeight(contentsRect().height());
    }
    if (bookmark_button_) {
        bookmark_button_->setMinimumHeight(contentsRect().height());
        bookmark_button_->setMaximumHeight(contentsRect().height());
    }
}

void CaptureFilterEdit::checkFilter(const QString& text)
{
    setSyntaxState(Empty);
    popFilterSyntaxStatus();
    bool empty = text.isEmpty();

    if (bookmark_button_) {
        bookmark_button_->setEnabled(false);
    }

    if (apply_button_) {
        apply_button_->setEnabled(false);
    }

    if (clear_button_) {
        clear_button_->setVisible(!empty);
    }

    if (empty) {
        setFilterSyntaxState(text, true, QString());
    } else {
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
        if (bookmark_button_) {
            bookmark_button_->setEnabled(true);
        }
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

void CaptureFilterEdit::buildCompletionList(const QString &primitive_word)
{
    if (primitive_word.length() < 1) {
        completion_model_->setStringList(QStringList());
        return;
    }

    // Grab matching capture filters from our parent combo and from the
    // saved capture filters file. Skip ones that look like single fields
    // and assume they will be added below.
    QStringList complex_list;
    QComboBox *cf_combo = qobject_cast<QComboBox *>(parent());
    if (cf_combo) {
        for (int i = 0; i < cf_combo->count() ; i++) {
            QString recent_filter = cf_combo->itemText(i);

            if (isComplexFilter(recent_filter)) {
                complex_list << recent_filter;
            }
        }
    }
    for (const GList *cf_item = get_filter_list_first(CFILTER_LIST); cf_item; cf_item = g_list_next(cf_item)) {
        const filter_def *cf_def = (filter_def *) cf_item->data;
        if (!cf_def || !cf_def->strval) continue;
        QString saved_filter = cf_def->strval;

        if (isComplexFilter(saved_filter) && !complex_list.contains(saved_filter)) {
            complex_list << saved_filter;
        }
    }

    // libpcap has a small number of primitives so we just add the whole list
    // sans the current word.
    QStringList primitive_list = libpcap_primitives_;
    primitive_list.removeAll(primitive_word);

    completion_model_->setStringList(complex_list + primitive_list);
    completer()->setCompletionPrefix(primitive_word);
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
