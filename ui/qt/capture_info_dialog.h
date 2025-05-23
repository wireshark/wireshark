/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_INFO_DIALOG_H
#define CAPTURE_INFO_DIALOG_H

#include "geometry_state_dialog.h"

#include <QAbstractTableModel>
#include <QElapsedTimer>

struct _capture_info;
struct _capture_session;

namespace Ui {
class CaptureInfoDialog;
}

class CaptureInfoModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit CaptureInfoModel(struct _capture_info *cap_info, QObject * parent = Q_NULLPTR);
    virtual ~CaptureInfoModel() {}
    void updateInfo();

    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
//    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

private:
    struct _capture_info *cap_info_;
    int samples_;
    // The SparkLineDelegate expects to plot ints. The delta between packet
    // counts in two intervals should fit in an int, even if the totals don't.
    QMap<int, uint64_t> last_count_;
    QMap<int, QList<int> > points_;
    uint64_t last_other_;
    QList<int> other_points_;
};

class CaptureInfoDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit CaptureInfoDialog(struct _capture_info *cap_info, struct _capture_session *cap_session, QWidget *parent = 0);
    ~CaptureInfoDialog();
    void updateInfo(void);

signals:

public slots:

private slots:
    void stopCapture();

private:
    Ui::CaptureInfoDialog *ui;
    struct _capture_info *cap_info_;
    struct _capture_session *cap_session_;
    CaptureInfoModel *ci_model_;
    QElapsedTimer duration_;
};

#endif // CAPTURE_INFO_DIALOG_H
