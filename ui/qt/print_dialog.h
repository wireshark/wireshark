/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PRINT_DIALOG_H
#define PRINT_DIALOG_H

#include <config.h>

#include "file.h"

#include <QDialog>
#include <QPrinter>
#include <QPrintPreviewWidget>
#include <QPushButton>

namespace Ui {
    class PrintDialog;
}

/**
 * @brief Dialog that provides packet print and print-preview functionality
 *        for a live or saved capture file.
 */
class PrintDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Print dialog.
     * @param parent   Optional parent widget.
     * @param cf       Capture file whose packets are to be printed; may be @c NULL.
     * @param selRange Optional string describing a pre-selected packet range to print.
     */
    explicit PrintDialog(QWidget *parent = 0, capture_file *cf = NULL, QString selRange = QString());

    /**
     * @brief Destroys the Print dialog and releases all associated resources.
     */
    ~PrintDialog();

    /**
     * @brief Prints the page header for the current print job.
     * @return @c true on success; @c false if the header could not be rendered.
     */
    bool printHeader();

    /**
     * @brief Prints a single line of packet data at the given indentation level.
     * @param indent Number of indentation levels to apply before the line text.
     * @param line   NUL-terminated string containing the line text to render.
     * @return @c true on success; @c false if the line could not be rendered.
     */
    bool printLine(int indent, const char *line);

protected:
    /**
     * @brief Intercepts key press events, e.g. to suppress closing the dialog on Enter.
     * @param event The key event to handle.
     */
    virtual void keyPressEvent(QKeyEvent *event) override;

private:
    Ui::PrintDialog *pd_ui_; /**< Qt Designer-generated UI object for this dialog. */

    QPrinter              printer_;     /**< Configured printer instance used for actual printing. */
    QPrinter             *cur_printer_; /**< Pointer to the printer currently in use (real or preview). */
    QPainter             *cur_painter_; /**< Painter used to render content onto cur_printer_. */
    QPrintPreviewWidget  *preview_;     /**< Embedded print-preview widget shown in the dialog. */
    QPushButton          *print_bt_;    /**< "Print" button; enabled only when settings are valid. */
    QFont                 header_font_; /**< Font used for page header text. */
    QFont                 packet_font_; /**< Font used for packet body text. */

public:
    capture_file *cap_file_; /**< Capture file being printed; publicly accessible for print stream callbacks. */

private:
    print_args_t       print_args_;  /**< Wireshark print arguments (range, format, options). */
    print_stream_ops_t stream_ops_;  /**< Vtable of print stream operations bound to this dialog. */
    print_stream_t     stream_;      /**< Active print stream used by the Wireshark print engine. */
    int                page_pos_;    /**< Current vertical position (in device units) on the active page. */
    bool               in_preview_;  /**< @c true while rendering into the preview widget rather than a real printer. */

    /**
     * @brief Iterates over the selected packets and renders them to @p printer.
     * @param printer    Target printer; uses @c printer_ when @c NULL.
     * @param in_preview @c true when rendering for the on-screen preview rather than a real print job.
     */
    void printPackets(QPrinter *printer = NULL, bool in_preview = false);

private slots:
    /**
     * @brief Slot invoked by the QPrintPreviewWidget to render pages for the preview.
     * @param printer The printer provided by the preview widget for rendering.
     */
    void paintPreview(QPrinter *printer);

    /**
     * @brief Validates the current dialog settings and enables or disables the
     *        Print button accordingly.
     */
    void checkValidity();

    /** @brief Opens the context-sensitive help page for the Print dialog. */
    void on_buttonBox_helpRequested();

    /**
     * @brief Dispatches button-box actions (Print, Cancel, etc.).
     * @param button The button that was activated.
     */
    void on_buttonBox_clicked(QAbstractButton *button);
};


#endif // PRINT_DIALOG_H
