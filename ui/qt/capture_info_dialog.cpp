/* capture_info_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "ui/capture_info.h"

#include "epan/capture_dissectors.h"
#include "epan/proto.h"

#include "ui/capture.h"

#include "capture_info_dialog.h"
#include "ui_capture_info_dialog.h"

#include "wireshark_application.h"

#include "ui/qt/models/sparkline_delegate.h"

#include "utils/qt_ui_utils.h"

#include <QMainWindow>
#include <QPushButton>

// The GTK+ version of this dialog showed a list of protocols and a simple bar graph
// (progress bars) showing their portion of the total number of packets. We show a
// a time series for each protocol using a sparkline. If we wanted to show bar graphs
// instead we could do so using QProgressBars or using PercentBarDelegates.

extern "C" {

// Callbacks defined in ui/capture_info.h.

/* create the capture info dialog */
/* will keep pointers to the fields in the counts parameter */
void capture_info_ui_create(
capture_info    *cinfo,
capture_session *cap_session)
{
    // cinfo->ui should have three values:
    // - The main window, set in MainWindow::startCapture.
    // - This dialog, set below.
    // - NULL, set in our destructor.

    if (!cinfo || !cinfo->ui) return;
    if (!cap_session) return;
    QMainWindow *main_window = qobject_cast<QMainWindow *>((QObject *)cinfo->ui);
    if (!main_window) return;

    // ...and we take it over from here.
    CaptureInfoDialog *ci_dlg = new CaptureInfoDialog(cinfo, cap_session, main_window);
    cinfo->ui = ci_dlg;
    ci_dlg->show();
}

/* update the capture info dialog */
/* As this function is a bit time critical while capturing, */
/* prepare everything possible in the capture_info_ui_create() function above! */
void capture_info_ui_update(
capture_info    *cinfo)
{
    CaptureInfoDialog *ci_dlg = qobject_cast<CaptureInfoDialog *>((QObject *)cinfo->ui);
    if (!ci_dlg) return;
    ci_dlg->updateInfo();
}

/* destroy the capture info dialog again */
void capture_info_ui_destroy(
capture_info    *cinfo)
{
    CaptureInfoDialog *ci_dlg = qobject_cast<CaptureInfoDialog *>((QObject *)cinfo->ui);
    if (!ci_dlg) return;
    delete ci_dlg;
}

} // extern "C"

CaptureInfoDialog::CaptureInfoDialog(struct _capture_info *cap_info, struct _capture_session *cap_session, QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::CaptureInfoDialog),
    cap_info_(cap_info),
    cap_session_(cap_session)
{
    ui->setupUi(this);
    loadGeometry();
    setWindowTitle(wsApp->windowTitleString(tr("Capture Information")));

    QPushButton *button = ui->buttonBox->button(QDialogButtonBox::Abort);
    button->setText(tr("Stop Capture"));
    connect(button, &QPushButton::clicked, this, &CaptureInfoDialog::stopCapture);

    ci_model_ = new CaptureInfoModel(cap_info, this);
    ui->treeView->setModel(ci_model_);

    ui->treeView->setItemDelegateForColumn(1, new SparkLineDelegate(this));

    duration_.start();
}

CaptureInfoDialog::~CaptureInfoDialog()
{
    delete ui;
    cap_info_->ui = NULL;
}

void CaptureInfoDialog::updateInfo()
{
    int secs = int(duration_.elapsed() / 1000);
    QString duration = tr("%1 packets, %2:%3:%4")
            .arg(cap_info_->counts->total)
            .arg(secs / 3600, 2, 10, QChar('0'))
            .arg(secs % 3600 / 60, 2, 10, QChar('0'))
            .arg(secs % 60, 2, 10, QChar('0'));
    ui->infoLabel->setText(duration);

    ci_model_->updateInfo();
    ui->treeView->resizeColumnToContents(0);
}

void CaptureInfoDialog::stopCapture()
{
#ifdef HAVE_LIBPCAP
    capture_stop(cap_session_); // ...or we could connect to MainWindow::stopCapture.
#endif // HAVE_LIBPCAP
}

CaptureInfoModel::CaptureInfoModel(struct _capture_info *cap_info, QObject *parent) :
    QAbstractTableModel(parent),
    cap_info_(cap_info),
    samples_(0),
    last_other_(0)
{
}

void CaptureInfoModel::updateInfo()
{
    if (!cap_info_) return;

    GHashTableIter iter;
    gpointer key, value;

    samples_++;
    other_points_.append(cap_info_->counts->other - last_other_);
    last_other_ = cap_info_->counts->other;

    g_hash_table_iter_init (&iter, cap_info_->counts->counts_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        int proto_id = GPOINTER_TO_INT(key);
        int cur_count = (int) capture_dissector_get_count(cap_info_->counts, proto_id);
        if (!points_.contains(proto_id)) {
            emit beginInsertRows(QModelIndex(), rowCount(), rowCount());
            QVector<int> zeroes = QVector<int>(samples_, 0);
            points_[proto_id] = zeroes.toList();
            last_count_[proto_id] = 0;
            emit endInsertRows();
        } else {
            points_[proto_id].append(cur_count - last_count_[proto_id]);
            last_count_[proto_id] = cur_count;
        }
    }
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
}

int CaptureInfoModel::rowCount(const QModelIndex &) const
{
    if (!cap_info_) return 0;
    return points_.keys().size() + 1;
}

int CaptureInfoModel::columnCount(const QModelIndex &) const
{
    return 2;
}

QVariant CaptureInfoModel::data(const QModelIndex &index, int role) const
{
    QList<int> proto_ids = points_.keys();
    int row = index.row();

    if (role == Qt::DisplayRole && index.column() == 0) {
        if (row < proto_ids.size()) {
            int proto_id = proto_ids.at(row);
            return QString(proto_get_protocol_short_name(find_protocol_by_id(proto_id)));
        } else {
            return tr("Other");
        }
    } else if (role == Qt::UserRole && index.column() == 1) {
        if (row < proto_ids.size()) {
            int proto_id = proto_ids.at(row);
            return QVariant::fromValue(points_[proto_id]);
        } else {
            return QVariant::fromValue(other_points_);
        }
    }
    return QVariant();
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
