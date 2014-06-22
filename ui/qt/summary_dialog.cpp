/* summary_dialog.cpp
 *
 * GSoC 2013 - QtShark
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

#include "summary_dialog.h"
#include "ui_summary_dialog.h"

#include "wireshark_application.h"

#include <wsutil/ws_version_info.h>

#include <QtGui>
#include <QPushButton>

SummaryDialog::SummaryDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SummaryDialog)
{
    ui->setupUi(this);

    ui->tbDisplay->horizontalHeader()->setVisible(true);

    /* set column widths */
    ui->tbInterfaces->setColumnWidth(0, 305);
    ui->tbInterfaces->setColumnWidth(1, 110);
    ui->tbInterfaces->setColumnWidth(2, 90);
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tbInterfaces->horizontalHeader()->setResizeMode(3, QHeaderView::Stretch);
#else
    ui->tbInterfaces->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
#endif
    ui->tbInterfaces->setColumnWidth(4, 160);

    ui->tbDisplay->setColumnWidth(0, 265);
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tbDisplay->horizontalHeader()->setResizeMode(1, QHeaderView::Stretch);
    ui->tbDisplay->horizontalHeader()->setResizeMode(2, QHeaderView::Stretch);
    ui->tbDisplay->horizontalHeader()->setResizeMode(3, QHeaderView::Stretch);
#else
    ui->tbDisplay->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tbDisplay->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->tbDisplay->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
#endif
    this->setFixedSize(this->size());

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(SaveComment()));
    connect(ui->buttonBox, SIGNAL(helpRequested()), this, SLOT(HelpButton()));

    bRefresh = ui->buttonBox->addButton(tr("Refresh"), QDialogButtonBox::ActionRole);
    connect(bRefresh, SIGNAL(clicked()), this, SLOT(RefreshData()));

    bCopyComment = ui->buttonBox->addButton(tr("Copy To Clipboard"), QDialogButtonBox::ActionRole);
    connect(bCopyComment, SIGNAL(clicked()), this, SLOT(CopyComment()));
}

/*
 *            Slots
 **/

void SummaryDialog::RefreshData()
{
    UpdateValues();
}

void SummaryDialog::SaveComment()
{
    if (cfile.filename != NULL)
    {
        if (wtap_dump_can_write(cfile.linktypes, WTAP_COMMENT_PER_SECTION))
        {
            gchar *str = g_strdup((gchar*)ui->teCFComments->toPlainText().toStdString().c_str());
            cf_update_capture_comment(&cfile, str);
            emit captureCommentChanged();
        }
    }
}

void SummaryDialog::HelpButton()
{
    wsApp->helpTopicAction(HELP_STATS_SUMMARY_DIALOG);
}

void SummaryDialog::CopyComment()
{
    QClipboard *clipboard = QApplication::clipboard();

    clipboard->setText(SummaryToString());
}

void SummaryDialog::on_tabWidget_currentChanged(int index)
{
    // if we are showing the comment summary tab, we update it with new values
    if (index == 2)
    {
        UpdateValues();
        ui->pteCommentSummary->clear();
        ui->pteCommentSummary->insertPlainText(SummaryToString());
    }
}


/**/

QString SummaryDialog::SummaryToString()
{
    UpdateValues();

    QString summaryStr;
    QTextStream out(&summaryStr);

    out << tr("Summary created by Wireshark %1\n\n").arg(get_ws_vcs_version_info());

    // File Section
    out << tr("File: \n");
    out << "\t" << tr("Name:\t\t%1\n").arg(summary_.filename);
    out << "\t" << tr("Length:\t\t%1 bytes\n").arg(summary_.file_length);
    out << "\t" << tr("Format:\t\t%1%2\n")
           .arg(wtap_file_type_subtype_string(summary_.file_type))
           .arg(summary_.iscompressed? tr(" (gzip compressed)") : "");
    out << "\t" << tr("Encapsulation:\t\t%1\n").arg(ui->lEncapsulation->text());

    out << "\n\n";

    // Time Section
    out << tr("Time:\n");
    if (summary_.packet_count_ts == summary_.packet_count &&
            summary_.packet_count >= 1)
    {

        // start time
        out << "\t" << tr("First packet:\t\t%1\n").arg(ui->lFirstPacket->text());

        // stop time
        out << "\t" << tr("Last packet:\t\t%1\n").arg(ui->lLastPacket->text());

        // elapsed seconds (capture duration)
        if (summary_.packet_count_ts >= 2) {
            out << "\t" << tr("Elapsed:\t\t%1\n").arg(ui->lElapsed->text());
        }

    }
    out << "\n\n";

    // Capture Section
    out << tr("Capture:\n");

//    // capture HW
//    if (summary_.shb_hardware){
//        out << INDENT << tr("Capture HW: %1\n").arg(ui_->captureHWLabel->text());
//    }
    // capture OS
    if (summary_.shb_os)
    {
        out << "\t" << tr("OS:\t%1\n").arg(ui->lOS->text());
    }
    // capture application
    if (summary_.shb_user_appl)
    {
        out << "\t" << tr("Capture application:\t%1\n").arg(ui->lCaptureApp->text());
    }

    out << "\n";

    // capture interfaces info
    for (int i = 0; i < ui->tbInterfaces->rowCount(); i++)
    {
        out << "\t" << ui->tbInterfaces->item(i,0)->text() << "\n";
        out << "\t" << "\t" << tr("Dropped packets:\t%1\n")
               .arg(ui->tbInterfaces->item(i,1)->text());
        out << "\t" << "\t" << tr("Capture filter:\t\t%1\n")
               .arg(ui->tbInterfaces->item(i,2)->text());
        out << "\t" << "\t" << tr("Link type:\t\t%1\n")
               .arg(ui->tbInterfaces->item(i,3)->text());
        out << "\t" << "\t" << tr("Packet size limit:\t%1\n")
               .arg(ui->tbInterfaces->item(i,4)->text());
    }

    out << "\n\n";

    // Statistics Section
    out << tr("Statistics:\n");
    for (int i = 0; i < ui->tbDisplay->rowCount(); i++)
    {
        out << "\t" << tr("%1:\t%2")
               .arg(ui->tbDisplay->item(i,0)->text())
               .arg(ui->tbDisplay->item(i,1)->text());
        out << "\n";
    }

    out << "\n\n";

    //Capture Comments Section - reads from GUI buffer
    if(ui->teCFComments->isEnabled()
            && (!ui->teCFComments->toPlainText().isEmpty()))
    {
        out << tr("Capture File Comments:\n");
        out << ui->teCFComments->toPlainText() << endl;
    }

    return summaryStr;
}

QString SummaryDialog::TimeToString(time_t ti_time)
{
    struct tm *ti_tm;
    QString str;

    ti_tm = localtime(&ti_time);
    if (ti_tm == NULL)
    {
        str = tr("Not representable");
    }
    else
    {
        str = str.sprintf("%04d-%02d-%02d %02d:%02d:%02d",
                          ti_tm->tm_year + 1900,
                          ti_tm->tm_mon + 1,
                          ti_tm->tm_mday,
                          ti_tm->tm_hour,
                          ti_tm->tm_min,
                          ti_tm->tm_sec);
    }
    return str;
}



void SummaryDialog::UpdateValues()
{
    QString output;
    iface_options iface;

    uint i;

    double        seconds = 0.0;
    double        disp_seconds = 0.0;
    double        marked_seconds = 0.0;


    memset(&summary_, 0, sizeof(summary_tally));


    /* initial computations */
    summary_fill_in(&cfile, &summary_);
#ifdef HAVE_LIBPCAP
    summary_fill_in_capture(&cfile, &global_capture_opts, &summary_);
#endif

    seconds = summary_.stop_time - summary_.start_time;
    disp_seconds = summary_.filtered_stop - summary_.filtered_start;
    marked_seconds = summary_.marked_stop - summary_.marked_start;


    /*
     *  File groupbox
     * */

    /* setting the filename */
    ui->lFilename->setText(summary_.filename);

    /* setting the length of the file */
    ui->lLength->setText(QString(tr("%1 bytes (%2 Mbytes)")).arg((ulong)summary_.file_length).arg((float)summary_.file_length/1048576));

    /* format */
    ui->lFormat->setText(QString("%1%2").arg(wtap_file_type_subtype_string(summary_.file_type), summary_.iscompressed? tr(" (gzip compressed)") : ""));

    /* encapsulation */
    if (summary_.file_encap_type == WTAP_ENCAP_PER_PACKET)
    {
        for (i = 0; i < summary_.packet_encap_types->len; i++)
        {
            output = QString(wtap_encap_string(g_array_index(summary_.packet_encap_types, int, i)));
        }
    }
    else
    {
        output = QString(wtap_encap_string(summary_.file_encap_type));
    }

    ui->lEncapsulation->setText(output);

    /*
     *  Time groupbox
     * */

    /* First packet and Last packet */

    ui->lFirstPacket->setText(TimeToString((time_t)summary_.start_time));
    ui->lLastPacket->setText(TimeToString((time_t)summary_.stop_time));

    /*
         * We must have at least two time-stamped packets for the elapsed time
         * to be valid.
         */
    if (summary_.packet_count_ts >= 2)
    {
        /* elapsed seconds */
        uint elapsed_time = (unsigned int)summary_.elapsed_time;
        if(elapsed_time/86400)
        {
            output = output.sprintf("%02u days %02u:%02u:%02u", elapsed_time/86400,
                                elapsed_time%86400/3600,
                                elapsed_time%3600/60,
                                elapsed_time%60);
        }
        else
        {
            output = output.sprintf("%02u:%02u:%02u", elapsed_time%86400/3600,
                                elapsed_time%3600/60,
                                elapsed_time%60);
        }
        ui->lElapsed->setText(output);
    }

    /*============
     *  Capture groupbox
     *============ */

    if (summary_.shb_os)
    {
        ui->lOS->setText(summary_.shb_os);
    }

    if (summary_.shb_user_appl)
    {
        ui->lCaptureApp->setText(summary_.shb_user_appl);
    }

    if (wtap_dump_can_write(cfile.linktypes, WTAP_COMMENT_PER_SECTION))
    {
        ui->teCFComments->setText(summary_.opt_comment);
    }

    /*============
     *  Interfaces table
     *============ */

    ui->tbInterfaces->setRowCount(0);

    for (i = 0; i < summary_.ifaces->len; i++)
    {
        ui->tbInterfaces->setRowCount(ui->tbInterfaces->rowCount() + 1);
        iface = g_array_index(summary_.ifaces, iface_options, i);

        /* interface */
        if (iface.descr)
        {
            output = QString(iface.descr);
        }

        else if (iface.name)
        {
            output = QString(iface.name);
        }

        else
        {
            output = QString(tr("unknown"));
        }

        ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, 0, new QTableWidgetItem(output));



        /* Dropped count */
        if (iface.drops_known)
        {
            output = QString("%1 (%2 %)").arg(iface.drops).arg(QString::number(
                     /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
                     summary_.packet_count ?(100.0 * (gint64)iface.drops)/summary_.packet_count : 0.0f, 'g', 3));
        }
        else
        {
            output = QString(tr("Unknown"));
        }
        ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, 1, new QTableWidgetItem(output));



        /* Capture filter */
        if (iface.cfilter && iface.cfilter[0] != '\0')
        {
            output = output.sprintf("%s", iface.cfilter);
        }
        else
        {
            if (iface.name)
            {
                output = QString(tr("none"));
            }
            else
            {
                output = QString(tr("unknown"));
            }
        }
        ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, 2, new QTableWidgetItem(output));

        ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, 3, new QTableWidgetItem(wtap_encap_string(iface.encap_type)));

        output = output.sprintf(tr("%u bytes").toStdString().c_str(), iface.snap);
        ui->tbInterfaces->setItem(ui->tbInterfaces->rowCount()-1, 4, new QTableWidgetItem(output));

    }

    /*============
     *  Display table
     *============ */

    /* Display filter */
    if (summary_.dfilter)
    {

        output = QString(summary_.dfilter);
    }
    else
    {
        output = QString(tr("none"));
    }

    ui->lDisplayFilter->setText(output);


    /* Ignored packets */
    output = output.sprintf("%i (%.3f%%)", summary_.ignored_count,
                        summary_.packet_count ? (100.0 * summary_.ignored_count)/summary_.packet_count : 0.0);

    ui->lIgnoredPackets->setText(output);



    /* filling the display table*/
    ui->tbDisplay->setRowCount(0);



    /*
     *            Packet count
     **/

    ui->tbDisplay->setRowCount(ui->tbDisplay->rowCount() + 1);
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 0, new QTableWidgetItem(tr("Packets")));

    output = output.sprintf("%i", summary_.packet_count);
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 1, new QTableWidgetItem(output));

    if (summary_.dfilter)
    {
        output = output.sprintf("%i (%.3f%%)", summary_.filtered_count,
                            summary_.packet_count ?
                                (100.0 * summary_.filtered_count)/summary_.packet_count : 0.0);

    }
    else
    {
        output = output.sprintf("%i (100.000%%)", summary_.packet_count);
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 2, new QTableWidgetItem(output));


    output = output.sprintf("%i (%.3f%%)", summary_.marked_count,
                        summary_.packet_count ?
                            (100.0 * summary_.marked_count)/summary_.packet_count : 0.0);
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 3, new QTableWidgetItem(output));

    /*
     *            Time between first and last
     **/
    ui->tbDisplay->setRowCount(ui->tbDisplay->rowCount() + 1);

    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 0, new QTableWidgetItem(tr("Between first and last packet")));
    if (seconds > 0)
    {
        output = output.sprintf(tr("%.3f sec").toStdString().c_str(), seconds);

    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 1, new QTableWidgetItem(output));

    /* Displayed packet count */
    if (summary_.dfilter && disp_seconds > 0)
    {
        output = output.sprintf(tr("%.3f sec").toStdString().c_str(), disp_seconds);
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 2, new QTableWidgetItem(output));

    /* Marked packet count */
    if (summary_.marked_count && marked_seconds > 0)
    {
        output = output.sprintf(tr("%.3f sec").toStdString().c_str(), marked_seconds);
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 3, new QTableWidgetItem(output));



    /*
     *           Average packets per second
     **/

    ui->tbDisplay->setRowCount(ui->tbDisplay->rowCount() + 1);

    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 0, new QTableWidgetItem(tr("Avg. packets/sec")));
    if (seconds > 0)
    {
        output = output.sprintf("%.3f", summary_.packet_count/seconds);

    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 1, new QTableWidgetItem(output));

    /* Displayed packet count/sec */
    if (summary_.dfilter && disp_seconds > 0)
    {
        output = output.sprintf("%.3f", summary_.filtered_count/disp_seconds);
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 2, new QTableWidgetItem(output));

    /* Marked packet count/sec */
    if (summary_.marked_count && marked_seconds > 0)
    {
        output = output.sprintf("%.3f", summary_.marked_count/marked_seconds);
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 3, new QTableWidgetItem(output));


    /*
     *          Average packet size
     **/

    ui->tbDisplay->setRowCount(ui->tbDisplay->rowCount() + 1);

    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 0, new QTableWidgetItem(tr("Avg. packet size")));
    if (summary_.packet_count > 1)
    {
        output = output.sprintf(tr("%" G_GUINT64_FORMAT " bytes").toStdString().c_str(),
                            (guint64) ((double)summary_.bytes/summary_.packet_count + 0.5));

    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 1, new QTableWidgetItem(output));


    if (summary_.dfilter && summary_.filtered_count > 1)
    {
        output = output.sprintf(tr("%" G_GUINT64_FORMAT " bytes").toStdString().c_str(),
                            (guint64) ((double)summary_.filtered_bytes/summary_.filtered_count + 0.5));
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 2, new QTableWidgetItem(output));


    if (summary_.marked_count > 1)
    {
        output = output.sprintf(tr("%" G_GUINT64_FORMAT " bytes").toStdString().c_str(),
                            (guint64) ((double)summary_.marked_bytes/summary_.marked_count + 0.5));
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 3, new QTableWidgetItem(output));


    /*
     *          Byte count
     **/


    ui->tbDisplay->setRowCount(ui->tbDisplay->rowCount() + 1);
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 0, new QTableWidgetItem(tr("Bytes")));


    output = QString("%1").arg(summary_.bytes);

    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 1, new QTableWidgetItem(output));

    if (summary_.dfilter)
    {
        output = QString("%1 (%2%)").arg(summary_.filtered_bytes).arg(QString::number(
                 /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
                 summary_.bytes ?(100.0 * (gint64)summary_.filtered_bytes)/summary_.bytes : 0.0f, 'g', 3));

    }
    else
    {
        output = QString("%1 (100.000%)").arg(summary_.bytes);
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 2, new QTableWidgetItem(output));


    if (summary_.marked_count)
    {
        output = QString("%1 (%2%)").arg(summary_.marked_bytes).arg(QString::number(
                 /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
                 summary_.bytes ?(100.0 * (gint64)summary_.marked_bytes)/summary_.bytes : 0.0f, 'g', 3));
    }
    else
    {
        output = QString("0 (0.000%)");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 3, new QTableWidgetItem(output));




    /*
     *           Bytes per second
     **/

    ui->tbDisplay->setRowCount(ui->tbDisplay->rowCount() + 1);

    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 0, new QTableWidgetItem(tr("Avg. bytes/sec")));
    if (seconds > 0)
    {
        /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
        output = output.sprintf("%.3f", ((gint64) summary_.bytes)/seconds);

    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 1, new QTableWidgetItem(output));

    /* Displayed packet count/sec */
    if (summary_.dfilter && disp_seconds > 0)
    {
        /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
        output = output.sprintf("%.3f", ((gint64) summary_.filtered_bytes)/disp_seconds);
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 2, new QTableWidgetItem(output));

    /* Marked packet count/sec */
    if (summary_.marked_count && marked_seconds > 0)
    {
        /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
        output = output.sprintf("%.3f", ((gint64) summary_.marked_bytes)/marked_seconds);
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 3, new QTableWidgetItem(output));


    /*
     *           MBits per second
     **/

    ui->tbDisplay->setRowCount(ui->tbDisplay->rowCount() + 1);

    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 0, new QTableWidgetItem(tr("Avg. MBit/sec")));
    if (seconds > 0)
    {
        /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
        output = output.sprintf("%.3f", ((gint64) summary_.bytes) * 8.0 / (seconds * 1000.0 * 1000.0));

    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 1, new QTableWidgetItem(output));

    /* Displayed packet count/sec */
    if (summary_.dfilter && disp_seconds > 0)
    {
        /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
        output = output.sprintf("%.3f", ((gint64) summary_.filtered_bytes) * 8.0 / (disp_seconds * 1000.0 * 1000.0));
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 2, new QTableWidgetItem(output));

    /* Marked packet count/sec */
    if (summary_.marked_count && marked_seconds > 0)
    {
        /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
        output = output.sprintf("%.3f", ((gint64) ((gint64) summary_.marked_bytes) * 8.0 / (marked_seconds * 1000.0 * 1000.0)));
    }
    else
    {
        output = QString("N/A");
    }
    ui->tbDisplay->setItem(ui->tbDisplay->rowCount()-1, 3, new QTableWidgetItem(output));


}

SummaryDialog::~SummaryDialog()
{
    delete ui;
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
