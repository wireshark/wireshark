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
#include <filter_files.h>
#include <wsutil/utf8_entities.h>

#include "capture_filter_edit.h"
#include "capture_filter_syntax_worker.h"
#include "filter_dialog.h"
#include "stock_icon_tool_button.h"
#include "wireshark_application.h"

#include <QComboBox>
#include <QCompleter>
#include <QMenu>
#include <QMessageBox>
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
    enable_save_action_(false),
    save_action_(NULL),
    remove_action_(NULL),
    bookmark_button_(NULL),
    clear_button_(NULL),
    apply_button_(NULL)
{
    setAccessibleName(tr("Capture filter entry"));

    completion_model_ = new QStringListModel(this);
    setCompleter(new QCompleter(completion_model_, this));
    setCompletionTokenChars(libpcap_primitive_chars_);

    setConflict(false);

    if (!plain_) {
        bookmark_button_ = new StockIconToolButton(this, "x-capture-filter-bookmark");
        bookmark_button_->setCursor(Qt::ArrowCursor);
        bookmark_button_->setMenu(new QMenu());
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
        connect(clear_button_, SIGNAL(clicked()), this, SLOT(clearFilter()));
    }

    connect(this, SIGNAL(textChanged(const QString&)), this, SLOT(checkFilter(const QString&)));

#if 0
    // Disable the apply button for now
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
    }
#endif
    connect(this, SIGNAL(returnPressed()), this, SLOT(applyCaptureFilter()));

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

    QComboBox *cf_combo = qobject_cast<QComboBox *>(parent);
    if (cf_combo) {
        connect(cf_combo, SIGNAL(activated(QString)), this, SIGNAL(textEdited(QString)));
    }

    QThread *syntax_thread = new QThread;
    syntax_worker_ = new CaptureFilterSyntaxWorker;
    syntax_worker_->moveToThread(syntax_thread);
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(updateBookmarkMenu()));
    connect(wsApp, SIGNAL(captureFilterListChanged()), this, SLOT(updateBookmarkMenu()));
    connect(syntax_thread, SIGNAL(started()), syntax_worker_, SLOT(start()));
    connect(syntax_thread, SIGNAL(started()), this, SLOT(checkFilter()));
    connect(syntax_worker_, SIGNAL(syntaxResult(QString,int,QString)),
            this, SLOT(setFilterSyntaxState(QString,int,QString)));
    connect(syntax_thread, SIGNAL(finished()), syntax_worker_, SLOT(deleteLater()));
    syntax_thread->start();
    updateBookmarkMenu();
}

void CaptureFilterEdit::paintEvent(QPaintEvent *evt) {
    SyntaxLineEdit::paintEvent(evt);

    if (bookmark_button_) {
        // Draw the right border by hand. We could try to do this in the
        // style sheet but it's a pain.
#ifdef Q_OS_MAC
        QColor divider_color = Qt::gray;
#else
        QColor divider_color = palette().shadow().color();
#endif
        QPainter painter(this);
        painter.setPen(divider_color);
        QRect cr = contentsRect();
        QSize bksz = bookmark_button_->size();
        painter.drawLine(bksz.width(), cr.top(), bksz.width(), cr.bottom());
    }

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

void CaptureFilterEdit::setConflict(bool conflict)
{
    if (conflict) {
        //: This is a very long concept that needs to fit into a short space.
        placeholder_text_ = tr("Multiple filters selected. Override them here or leave this blank to preserve them.");
        setToolTip(tr("<p>The interfaces you have selected have different capture filters."
                      " Typing a filter here will override them. Doing nothing will"
                      " preserve them.</p>"));
    } else {
        placeholder_text_ = QString(tr("Enter a capture filter %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);
        setToolTip(QString());
    }
#if QT_VERSION >= QT_VERSION_CHECK(4, 7, 0)
    setPlaceholderText(placeholder_text_);
#endif
}

// XXX Make this private along with setConflict.
QPair<const QString, bool> CaptureFilterEdit::getSelectedFilter()
{
    QString user_filter;
    bool filter_conflict = false;
#ifdef HAVE_LIBPCAP
    int selected_devices = 0;

    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device.selected) {
            selected_devices++;
            if (selected_devices == 1) {
                user_filter = device.cfilter;
            } else {
                if (user_filter.compare(device.cfilter)) {
                    filter_conflict = true;
                }
            }
        }
    }
#endif // HAVE_LIBPCAP
    return QPair<const QString, bool>(user_filter, filter_conflict);
}

void CaptureFilterEdit::checkFilter(const QString& filter)
{
    setSyntaxState(Busy);
    popFilterSyntaxStatus();
    bool empty = filter.isEmpty();

    setConflict(false);
    if (bookmark_button_) {
        bool match = false;

        for (GList *cf_item = get_filter_list_first(CFILTER_LIST); cf_item; cf_item = g_list_next(cf_item)) {
            if (!cf_item->data) continue;
            filter_def *cf_def = (filter_def *) cf_item->data;
            if (!cf_def->name || !cf_def->strval) continue;

            if (filter.compare(cf_def->strval) == 0) {
                match = true;
            }
        }

        if (match) {
            bookmark_button_->setStockIcon("x-filter-matching-bookmark");
            if (remove_action_) {
                remove_action_->setData(text());
                remove_action_->setVisible(true);
            }
        } else {
            bookmark_button_->setStockIcon("x-capture-filter-bookmark");
            if (remove_action_) {
                remove_action_->setVisible(false);
            }
        }

        enable_save_action_ = (!match && !filter.isEmpty());
        if (save_action_) {
            save_action_->setEnabled(false);
        }
    }

    if (apply_button_) {
        apply_button_->setEnabled(false);
    }

    if (clear_button_) {
        clear_button_->setVisible(!empty);
    }

    if (empty) {
        setFilterSyntaxState(filter, Empty, QString());
    } else {
        syntax_worker_->checkFilter(filter);
    }
}

void CaptureFilterEdit::checkFilter()
{
    checkFilter(text());
}

void CaptureFilterEdit::updateBookmarkMenu()
{
    if (!bookmark_button_)
        return;

    QMenu *bb_menu = bookmark_button_->menu();
    bb_menu->clear();

    save_action_ = bb_menu->addAction(tr("Save this filter"));
    connect(save_action_, SIGNAL(triggered(bool)), this, SLOT(saveFilter()));
    remove_action_ = bb_menu->addAction(tr("Remove this filter"));
    connect(remove_action_, SIGNAL(triggered(bool)), this, SLOT(removeFilter()));
    QAction *manage_action = bb_menu->addAction(tr("Manage Capture Filters"));
    connect(manage_action, SIGNAL(triggered(bool)), this, SLOT(showFilters()));
    bb_menu->addSeparator();

    for (GList *cf_item = get_filter_list_first(CFILTER_LIST); cf_item; cf_item = g_list_next(cf_item)) {
        if (!cf_item->data) continue;
        filter_def *cf_def = (filter_def *) cf_item->data;
        if (!cf_def->name || !cf_def->strval) continue;

        int one_em = bb_menu->fontMetrics().height();
        QString prep_text = QString("%1: %2").arg(cf_def->name).arg(cf_def->strval);
        prep_text = bb_menu->fontMetrics().elidedText(prep_text, Qt::ElideRight, one_em * 40);

        QAction *prep_action = bb_menu->addAction(prep_text);
        prep_action->setData(cf_def->strval);
        connect(prep_action, SIGNAL(triggered(bool)), this, SLOT(prepareFilter()));
    }

    checkFilter();
}

void CaptureFilterEdit::setFilterSyntaxState(QString filter, int state, QString err_msg)
{
    if (filter.compare(text()) == 0) { // The user hasn't changed the filter
        setSyntaxState((SyntaxState)state);
        if (!err_msg.isEmpty()) {
            emit pushFilterSyntaxStatus(err_msg);
        }
    }

    bool valid = (state != Invalid);

    if (valid) {
        if (save_action_) {
            save_action_->setEnabled(enable_save_action_);
        }
        if (apply_button_) {
            apply_button_->setEnabled(true);
        }
    }

    emit captureFilterSyntaxChanged(valid);
}

void CaptureFilterEdit::bookmarkClicked()
{
    emit addBookmark(text());
}

void CaptureFilterEdit::clearFilter()
{
    clear();
    emit textEdited(text());
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

void CaptureFilterEdit::saveFilter()
{
    FilterDialog capture_filter_dlg(window(), FilterDialog::CaptureFilter, text());
    capture_filter_dlg.exec();
}

void CaptureFilterEdit::removeFilter()
{
    QAction *ra = qobject_cast<QAction*>(sender());
    if (!ra || ra->data().toString().isEmpty()) return;

    QString remove_filter = ra->data().toString();

    for (GList *cf_item = get_filter_list_first(CFILTER_LIST); cf_item; cf_item = g_list_next(cf_item)) {
        if (!cf_item->data) continue;
        filter_def *cf_def = (filter_def *) cf_item->data;
        if (!cf_def->name || !cf_def->strval) continue;

        if (remove_filter.compare(cf_def->strval) == 0) {
            remove_from_filter_list(CFILTER_LIST, cf_item);
        }
    }

    char *f_path;
    int f_save_errno;

    save_filter_list(CFILTER_LIST, &f_path, &f_save_errno);
    if (f_path != NULL) {
        // We had an error saving the filter.
        QString warning_title = tr("Unable to save capture filter settings.");
        QString warning_msg = tr("Could not save to your capture filter file\n\"%1\": %2.").arg(f_path).arg(g_strerror(f_save_errno));

        QMessageBox::warning(this, warning_title, warning_msg, QMessageBox::Ok);
        g_free(f_path);
    }

    updateBookmarkMenu();
}

void CaptureFilterEdit::showFilters()
{
    FilterDialog capture_filter_dlg(window(), FilterDialog::CaptureFilter);
    capture_filter_dlg.exec();
}

void CaptureFilterEdit::prepareFilter()
{
    QAction *pa = qobject_cast<QAction*>(sender());
    if (!pa || pa->data().toString().isEmpty()) return;

    QString filter(pa->data().toString());
    setText(filter);
    emit textEdited(filter);
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
