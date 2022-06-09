/* mtp3_summary_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mtp3_summary_dialog.h"
#include <ui_mtp3_summary_dialog.h>

#include "config.h"

#include <glib.h>

#include <epan/tap.h>

#include <epan/dissectors/packet-mtp3.h>

#include "wsutil/utf8_entities.h"

#include "ui/capture_globals.h"
#include "ui/simple_dialog.h"
#include "ui/summary.h"

#include <ui/qt/utils/qt_ui_utils.h>

#include <QTextStream>

typedef struct _mtp3_stat_si_code_t {
    int			num_msus;
    int			size;
} mtp3_stat_si_code_t;

typedef struct _mtp3_stat_t {
    mtp3_addr_pc_t		addr_opc;
    mtp3_addr_pc_t		addr_dpc;
    mtp3_stat_si_code_t		mtp3_si_code[MTP3_NUM_SI_CODE];
} mtp3_stat_t;

#define	MTP3_MAX_NUM_OPC_DPC	50

static mtp3_stat_t mtp3_stat[MTP3_MAX_NUM_OPC_DPC];
static size_t mtp3_num_used;

Mtp3SummaryDialog::Mtp3SummaryDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui(new Ui::Mtp3SummaryDialog)
{
    ui->setupUi(this);

    setWindowSubtitle(tr("MTP3 Summary"));
    updateWidgets();
}

Mtp3SummaryDialog::~Mtp3SummaryDialog()
{
    delete ui;
}

QString Mtp3SummaryDialog::summaryToHtml()
{
    summary_tally summary;
    memset(&summary, 0, sizeof(summary_tally));

    QString section_tmpl;
    QString table_begin, table_end;
    QString table_row_begin, table_ul_row_begin, table_row_end;
    QString table_vheader_tmpl, table_hheader15_tmpl, table_hheader25_tmpl;
    QString table_data_tmpl;

    section_tmpl = "<p><strong>%1</strong></p>\n";
    table_begin = "<p><table>\n";
    table_end = "</table></p>\n";
    table_row_begin = "<tr>\n";
    table_ul_row_begin = "<tr style=\"border-bottom: 1px solid gray;\">\n";
    table_row_end = "</tr>\n";
    table_vheader_tmpl = "<td width=\"50%\">%1:</td>"; // <th align="left"> looked odd
    table_hheader15_tmpl = "<td width=\"15%\"><u>%1</u></td>";
    table_hheader25_tmpl = "<td width=\"25%\"><u>%1</u></td>";
    table_data_tmpl = "<td>%1</td>";

    if (cap_file_.isValid()) {
        /* initial computations */
        summary_fill_in(cap_file_.capFile(), &summary);
#ifdef HAVE_LIBPCAP
        summary_fill_in_capture(cap_file_.capFile(), &global_capture_opts, &summary);
#endif
    }

    QString summary_str;
    QTextStream out(&summary_str);

    // File Section
    out << section_tmpl.arg(tr("File"));
    out << table_begin;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Name"))
        << table_data_tmpl.arg(summary.filename)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Length"))
        << table_data_tmpl.arg(file_size_to_qstring(summary.file_length))
        << table_row_end;

    QString format_str = wtap_file_type_subtype_description(summary.file_type);
    const char *compression_type_description = wtap_compression_type_description(summary.compression_type);
    if (compression_type_description != NULL) {
        format_str += QString(" (%1)").arg(compression_type_description);
    }
    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Format"))
        << table_data_tmpl.arg(format_str)
        << table_row_end;

    if (summary.snap != 0) {
        out << table_row_begin
            << table_vheader_tmpl.arg(tr("Snapshot length"))
            << table_data_tmpl.arg(summary.snap)
            << table_row_end;
    }

    out << table_end;

    // Data Section
    out << section_tmpl.arg(tr("Data"));
    out << table_begin;

    if (summary.packet_count_ts == summary.packet_count &&
            summary.packet_count >= 1)
    {
        // start time
        out << table_row_begin
            << table_vheader_tmpl.arg(tr("First packet"))
            << table_data_tmpl.arg(time_t_to_qstring((time_t)summary.start_time))
            << table_row_end;

        // stop time
        out << table_row_begin
            << table_vheader_tmpl.arg(tr("Last packet"))
            << table_data_tmpl.arg(time_t_to_qstring((time_t)summary.stop_time))
            << table_row_end;

        // elapsed seconds (capture duration)
        if (summary.packet_count_ts > 1)
        {
            /* elapsed seconds */
            QString elapsed_str;
            unsigned int elapsed_time = (unsigned int)summary.elapsed_time;
            if (elapsed_time/86400)
            {
                elapsed_str = QString("%1 days ").arg(elapsed_time / 86400);
            }

            elapsed_str += QString("%1:%2:%3")
                    .arg(elapsed_time % 86400 / 3600, 2, 10, QChar('0'))
                    .arg(elapsed_time % 3600 / 60, 2, 10, QChar('0'))
                    .arg(elapsed_time % 60, 2, 10, QChar('0'));
            out << table_row_begin
                << table_vheader_tmpl.arg(tr("Elapsed"))
                << table_data_tmpl.arg(elapsed_str)
                << table_row_end;
        }
    }

    // count
    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Packets"))
        << table_data_tmpl.arg(summary.packet_count)
        << table_row_end;

    out << table_end;

    QString n_a = UTF8_EM_DASH;
    int total_msus = 0;
    int total_bytes = 0;
    double seconds = summary.stop_time - summary.start_time;

    // SI Section
    out << section_tmpl.arg(tr("Service Indicator (SI) Totals"));
    out << table_begin;

    out << table_row_begin
        << table_hheader25_tmpl.arg(tr("SI"))
        << table_hheader15_tmpl.arg(tr("MSUs"))
        << table_hheader15_tmpl.arg(tr("MSUs/s"))
        << table_hheader15_tmpl.arg(tr("Bytes"))
        << table_hheader15_tmpl.arg(tr("Bytes/MSU"))
        << table_hheader15_tmpl.arg(tr("Bytes/s"))
        << table_row_end;

    for (size_t ws_si_code = 0; ws_si_code < MTP3_NUM_SI_CODE; ws_si_code++) {
        int si_msus = 0;
        int si_bytes = 0;
        QString msus_s_str = n_a;
        QString bytes_msu_str = n_a;
        QString bytes_s_str = n_a;

        for (size_t stat_idx = 0; stat_idx < mtp3_num_used; stat_idx++) {
            si_msus += mtp3_stat[stat_idx].mtp3_si_code[ws_si_code].num_msus;
            si_bytes += mtp3_stat[stat_idx].mtp3_si_code[ws_si_code].size;
        }
        total_msus += si_msus;
        total_bytes += si_bytes;

        if (seconds > 0) {
            msus_s_str = QString("%1").arg(si_msus / seconds, 1, 'f', 1);
            bytes_s_str = QString("%1").arg(si_bytes / seconds, 1, 'f', 1);
        }

        if (si_msus > 0) {
            bytes_msu_str = QString("%1").arg((double) si_bytes / si_msus, 1, 'f', 1);
        }

        out << table_row_begin
            << table_data_tmpl.arg(mtp3_service_indicator_code_short_vals[ws_si_code].strptr)
            << table_data_tmpl.arg(si_msus)
            << table_data_tmpl.arg(msus_s_str)
            << table_data_tmpl.arg(si_bytes)
            << table_data_tmpl.arg(bytes_msu_str)
            << table_data_tmpl.arg(bytes_s_str)
            << table_row_end;
    }

    out << table_end;

    // Totals Section

    QString total_msus_s_str = n_a;
    QString total_bytes_msu_str = n_a;
    QString total_bytes_s_str = n_a;

    if (seconds > 0) {
        total_msus_s_str = QString("%1").arg(total_msus / seconds, 1, 'f', 1);
        total_bytes_s_str = QString("%1").arg(total_bytes / seconds, 1, 'f', 1);
    }
    if (total_msus > 0) {
        total_bytes_msu_str = QString("%1").arg((double) total_bytes / total_msus, 1, 'f', 1);
    }

    out << section_tmpl.arg(tr("Totals"));
    out << table_begin;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total MSUs"))
        << table_data_tmpl.arg(total_msus)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("MSUs/s"))
        << table_data_tmpl.arg(total_msus_s_str)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total Bytes"))
        << table_data_tmpl.arg(total_bytes)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average Bytes/MSU"))
        << table_data_tmpl.arg(total_bytes_msu_str)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average Bytes/s"))
        << table_data_tmpl.arg(total_bytes_s_str)
        << table_row_end;

    out << table_end;

    return summary_str;
}

void Mtp3SummaryDialog::updateWidgets()
{
    ui->summaryTextEdit->setHtml(summaryToHtml());

    WiresharkDialog::updateWidgets();
}

extern "C" {

void register_tap_listener_qt_mtp3_summary(void);

static void
mtp3_summary_reset(
    void        *tapdata)
{
    mtp3_stat_t     (*stat_p)[MTP3_MAX_NUM_OPC_DPC] = (mtp3_stat_t(*)[MTP3_MAX_NUM_OPC_DPC])tapdata;

    mtp3_num_used = 0;
    memset(stat_p, 0, MTP3_MAX_NUM_OPC_DPC * sizeof(mtp3_stat_t));
}


static tap_packet_status
mtp3_summary_packet(
    void            *tapdata,
    packet_info     *,
    epan_dissect_t  *,
    const void      *data,
    tap_flags_t)
{
    mtp3_stat_t           (*stat_p)[MTP3_MAX_NUM_OPC_DPC] = (mtp3_stat_t(*)[MTP3_MAX_NUM_OPC_DPC])tapdata;
    const mtp3_tap_rec_t  *data_p = (const mtp3_tap_rec_t *)data;
    size_t                 i;

    if (data_p->mtp3_si_code >= MTP3_NUM_SI_CODE)
    {
        /*
         * we thought this si_code was not used ?
         * is MTP3_NUM_SI_CODE out of date ?
         * XXX - if this is an error, report it and return TAP_PACKET_FAILED.
         */
        return(TAP_PACKET_DONT_REDRAW);
    }

    /*
     * look for opc/dpc pair
     */
    i = 0;
    while (i < mtp3_num_used)
    {
        if (memcmp(&data_p->addr_opc, &(*stat_p)[i].addr_opc, sizeof(mtp3_addr_pc_t)) == 0)
        {
            if (memcmp(&data_p->addr_dpc, &(*stat_p)[i].addr_dpc, sizeof(mtp3_addr_pc_t)) == 0)
            {
                break;
            }
        }

        i++;
    }

    if (i == mtp3_num_used)
    {
        if (mtp3_num_used == MTP3_MAX_NUM_OPC_DPC)
        {
            /*
             * too many
             * XXX - report an error and return TAP_PACKET_FAILED?
             */
            return(TAP_PACKET_DONT_REDRAW);
        }

        mtp3_num_used++;
    }

    (*stat_p)[i].addr_opc = data_p->addr_opc;
    (*stat_p)[i].addr_dpc = data_p->addr_dpc;
    (*stat_p)[i].mtp3_si_code[data_p->mtp3_si_code].num_msus++;
    (*stat_p)[i].mtp3_si_code[data_p->mtp3_si_code].size += data_p->size;

    return(TAP_PACKET_REDRAW);
}

void
register_tap_listener_qt_mtp3_summary(void)
{
    GString     *err_p;

    memset((void *) &mtp3_stat, 0, sizeof(mtp3_stat));

    err_p =
    register_tap_listener("mtp3", &mtp3_stat, NULL, 0,
        mtp3_summary_reset,
        mtp3_summary_packet,
        NULL,
        NULL);

    if (err_p != NULL)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_p->str);
        g_string_free(err_p, TRUE);

        exit(1);
    }
}

} // extern "C"
