/* capture_info_dialog.h
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
    QMap<int, int> last_count_;
    QMap<int, QList<int> > points_;
    int last_other_;
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
