/* print_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "print_dialog.h"
#include <ui_print_dialog.h>

#include <wsutil/utf8_entities.h>

#ifdef Q_OS_WIN
#include <windows.h>
#include "ui/packet_range.h"
#include "ui/win32/file_dlg_win32.h"
#endif

#include <QPrintDialog>
#include <QPageSetupDialog>
#include <QPainter>
#include <QPaintEngine>
#include <QKeyEvent>
#include <QMessageBox>

#include "wireshark_application.h"

extern "C" {

// Page element callbacks

static gboolean
print_preamble_pd(print_stream_t *self, gchar *, const char *)
{
    if (!self) return FALSE;
    PrintDialog *print_dlg = static_cast<PrintDialog *>(self->data);
    if (!print_dlg) return FALSE;

    return print_dlg->printHeader();
}

static gboolean
print_line_pd(print_stream_t *self, int indent, const char *line)
{
    if (!self) return FALSE;
    PrintDialog *print_dlg = static_cast<PrintDialog *>(self->data);
    if (!print_dlg) return FALSE;

    return print_dlg->printLine(indent, line);
}

static gboolean
new_page_pd(print_stream_t *self)
{
    if (!self) return FALSE;
    PrintDialog *print_dlg = static_cast<PrintDialog *>(self->data);
    if (!print_dlg) return FALSE;

    return print_dlg->printHeader();
}

} // extern "C"

PrintDialog::PrintDialog(QWidget *parent, capture_file *cf, QString selRange) :
    QDialog(parent),
    pd_ui_(new Ui::PrintDialog),
    cur_printer_(NULL),
    cur_painter_(NULL),
    preview_(new QPrintPreviewWidget(&printer_)),
    print_bt_(new QPushButton(tr("&Print" UTF8_HORIZONTAL_ELLIPSIS))),
    cap_file_(cf),
    page_pos_(0),
    in_preview_(FALSE)
{
    Q_ASSERT(cf);

    pd_ui_->setupUi(this);
    setWindowTitle(wsApp->windowTitleString(tr("Print")));

    pd_ui_->previewLayout->insertWidget(0, preview_, Qt::AlignTop);

    preview_->setMinimumWidth(preview_->height() / 2);
    preview_->setToolTip(pd_ui_->zoomLabel->toolTip());

    // XXX Make these configurable
    header_font_.setFamily("Times");
    header_font_.setPointSizeF(header_font_.pointSizeF() * 0.8);
    packet_font_ = wsApp->monospaceFont();
    packet_font_.setPointSizeF(packet_font_.pointSizeF() * 0.8);

    memset(&print_args_, 0, sizeof(print_args_));
    memset(&stream_ops_, 0, sizeof(stream_ops_));

    /* Init the export range */
    packet_range_init(&print_args_.range, cap_file_);
    /* Default to displayed packets */
    print_args_.range.process_filtered = TRUE;

    stream_ops_.print_preamble = print_preamble_pd;
    stream_ops_.print_line     = print_line_pd;
    stream_ops_.new_page       = new_page_pd;

    stream_.data = this;
    stream_.ops = &stream_ops_;
    print_args_.stream = &stream_;

    gchar *display_basename = g_filename_display_basename(cap_file_->filename);
    printer_.setDocName(display_basename);
    g_free(display_basename);

    pd_ui_->rangeGroupBox->initRange(&print_args_.range, selRange);

    pd_ui_->buttonBox->addButton(print_bt_, QDialogButtonBox::ActionRole);
    pd_ui_->buttonBox->addButton(tr("Page &Setup" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ResetRole);
    print_bt_->setDefault(true);

    connect(preview_, SIGNAL(paintRequested(QPrinter*)), this, SLOT(paintPreview(QPrinter*)));
    connect(pd_ui_->rangeGroupBox, SIGNAL(rangeChanged()),
            this, SLOT(checkValidity()));
    connect(pd_ui_->formatGroupBox, SIGNAL(formatChanged()),
            this, SLOT(checkValidity()));
    connect(pd_ui_->formFeedCheckBox, SIGNAL(toggled(bool)),
            preview_, SLOT(updatePreview()));

    checkValidity();
}

PrintDialog::~PrintDialog()
{
    packet_range_cleanup(&print_args_.range);
    delete pd_ui_;
}

gboolean PrintDialog::printHeader()
{
    if (!cap_file_ || !cap_file_->filename || !cur_printer_ || !cur_painter_) return FALSE;
    int page_top = cur_printer_->pageRect().top();

    if (page_pos_ > page_top) {
        if (in_preview_) {
            // When generating a preview, only generate the first page;
            // if we're past the first page, stop the printing process.
            return FALSE;
        }
        // Second and subsequent pages only
        cur_printer_->newPage();
        page_pos_ = page_top;
    }

    QString banner = QString(tr("%1 %2 total packets, %3 shown"))
            .arg(cap_file_->filename)
            .arg(cap_file_->count)
            .arg(cap_file_->displayed_count);
    cur_painter_->setFont(header_font_);
    cur_painter_->drawText(0, page_top, banner);
    page_pos_ += cur_painter_->fontMetrics().height();
    cur_painter_->setFont(packet_font_);
    return TRUE;
}

gboolean PrintDialog::printLine(int indent, const char *line)
{
    QRect out_rect;
    QString out_line;

    if (!line || !cur_printer_ || !cur_painter_) return FALSE;

    /* Prepare the tabs for printing, depending on tree level */
    out_line.fill(' ', indent * 4);
    out_line += line;

    out_rect = cur_painter_->boundingRect(cur_printer_->pageRect(), Qt::TextWordWrap, out_line);

    if (cur_printer_->pageRect().height() < page_pos_ + out_rect.height()) {
        //
        // We're past the end of the page, so this line will be on
        // the next page.
        //
        if (in_preview_) {
            // When generating a preview, only generate the first page;
            // if we're past the first page, stop the printing process.
            return FALSE;
        }
        if (*line == '\0') {
            // This is an empty line, so it's a separator; no need to
            // waste space printing it at the top of a page, as the
            // page break suffices as a separator.
            return TRUE;
        }
        printHeader();
    }

    out_rect.translate(0, page_pos_);
    cur_painter_->drawText(out_rect, Qt::TextWordWrap, out_line);
    page_pos_ += out_rect.height();
    return TRUE;
}

// Protected

void PrintDialog::keyPressEvent(QKeyEvent *event)
{
    // XXX - This differs from the main window but matches other applications (e.g. Mozilla and Safari)
    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
        preview_->zoomOut();
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
        preview_->zoomIn();
        break;
    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
        // fitInView doesn't grow (at least in Qt 4.8.2) so make sure it shrinks.
        preview_->setUpdatesEnabled(false);
        preview_->setZoomFactor(1.0);
        preview_->fitInView();
        preview_->setUpdatesEnabled(true);
        break;
    }

    QDialog::keyPressEvent(event);
}

// Private

void PrintDialog::printPackets(QPrinter *printer, bool in_preview)
{
    QPainter painter;

    if (!printer) return;

    page_pos_ = printer->pageRect().top();
    in_preview_ = in_preview;

    /* Fill in our print args */

    print_args_.format              = PR_FMT_TEXT;
    print_args_.print_summary       = pd_ui_->formatGroupBox->summaryEnabled();
    print_args_.print_col_headings  = pd_ui_->formatGroupBox->includeColumnHeadingsEnabled();
    print_args_.print_hex           = pd_ui_->formatGroupBox->bytesEnabled();
    print_args_.print_formfeed      = pd_ui_->formFeedCheckBox->isChecked();

    print_args_.print_dissections = print_dissections_none;
    if (pd_ui_->formatGroupBox->detailsEnabled()) {
        if (pd_ui_->formatGroupBox->allCollapsedEnabled())
            print_args_.print_dissections = print_dissections_collapsed;
        else if (pd_ui_->formatGroupBox->asDisplayedEnabled())
            print_args_.print_dissections = print_dissections_as_displayed;
        else if (pd_ui_->formatGroupBox->allExpandedEnabled())
            print_args_.print_dissections = print_dissections_expanded;
    }

    // This should be identical to printer_. However, the QPrintPreviewWidget docs
    // tell us to draw on the printer handed to us by the paintRequested() signal.
    cur_printer_ = printer;
    cur_painter_ = &painter;
    if (!painter.begin(printer)) {
        QMessageBox::warning(this, tr("Print Error"),
                             QString(tr("Unable to print to %1.")).arg(printer_.printerName()),
                             QMessageBox::Ok);
        close();
    }
    // Don't show a progress bar if we're previewing; if it takes a
    // significant amount of time to generate a preview of the first
    // page, We Have A Real Problem
    cf_print_packets(cap_file_, &print_args_, in_preview ? FALSE : TRUE);
    cur_printer_ = NULL;
    cur_painter_ = NULL;
    painter.end();
}

void PrintDialog::paintPreview(QPrinter *printer)
{
    printPackets(printer, true);
}

void PrintDialog::checkValidity()
{
    bool enable = true;

    if (!pd_ui_->rangeGroupBox->isValid()) enable = false;

    if (!pd_ui_->formatGroupBox->summaryEnabled() &&
        !pd_ui_->formatGroupBox->detailsEnabled() &&
        !pd_ui_->formatGroupBox->bytesEnabled())
    {
        enable = false;
    }

    print_bt_->setEnabled(enable);
    preview_->updatePreview();
}

void PrintDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_PRINT_DIALOG);
}

void PrintDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    QPrintDialog *print_dlg;
    QPageSetupDialog *ps_dlg;
#ifdef Q_OS_WIN
        HANDLE da_ctx;
#endif

    switch (pd_ui_->buttonBox->buttonRole(button)) {
    case QDialogButtonBox::ActionRole:
        int result;
#ifdef Q_OS_WIN
        da_ctx = set_thread_per_monitor_v2_awareness();
#endif
        print_dlg = new QPrintDialog(&printer_, this);
        result = print_dlg->exec();
#ifdef Q_OS_WIN
        revert_thread_per_monitor_v2_awareness(da_ctx);
#endif
        if (result == QDialog::Accepted) {
            printPackets(&printer_, false);
            done(result);
        }
        break;
    case QDialogButtonBox::ResetRole:
#ifdef Q_OS_WIN
        da_ctx = set_thread_per_monitor_v2_awareness();
#endif
        ps_dlg = new QPageSetupDialog(&printer_, this);
        ps_dlg->exec();
#ifdef Q_OS_WIN
        revert_thread_per_monitor_v2_awareness(da_ctx);
#endif
        preview_->updatePreview();
        break;
    default: // Help, Cancel
        break;
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
