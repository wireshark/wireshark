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

/**
 * @brief A table model for displaying active capture information and statistics.
 */
class CaptureInfoModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CaptureInfoModel.
     * @param cap_info Pointer to the capture information structure.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit CaptureInfoModel(struct _capture_info *cap_info, QObject * parent = Q_NULLPTR);

    /**
     * @brief Destroys the CaptureInfoModel.
     */
    virtual ~CaptureInfoModel() {}

    /**
     * @brief Updates the model with the latest capture information.
     */
    void updateInfo();

    /**
     * @brief Returns the number of rows under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows in the model.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Returns the number of columns under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns in the model.
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Retrieves data from the model for the given index and role.
     * @param index The model index to retrieve data for.
     * @param role The role for which the data is requested (defaults to Qt::DisplayRole).
     * @return The data associated with the index and role.
     */
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
//    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

private:
    /** Pointer to the underlying capture information. */
    struct _capture_info *cap_info_;

    /** The number of samples collected. */
    int samples_;

    // The SparkLineDelegate expects to plot ints. The delta between packet
    // counts in two intervals should fit in an int, even if the totals don't.
    /** The last recorded packet count per interface/type. */
    QMap<int, uint64_t> last_count_;

    /** Data points for plotting statistics. */
    QMap<int, QList<int> > points_;

    /** The last recorded count for other packets. */
    uint64_t last_other_;

    /** Data points for plotting other packets. */
    QList<int> other_points_;
};

/**
 * @brief A dialog displaying real-time information and statistics during a capture.
 */
class CaptureInfoDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CaptureInfoDialog.
     * @param cap_info Pointer to the capture information structure.
     * @param cap_session Pointer to the active capture session.
     * @param parent The parent widget, defaults to 0.
     */
    explicit CaptureInfoDialog(struct _capture_info *cap_info, struct _capture_session *cap_session, QWidget *parent = 0);

    /**
     * @brief Destroys the CaptureInfoDialog.
     */
    ~CaptureInfoDialog();

    /**
     * @brief Updates the dialog with the latest capture information.
     */
    void updateInfo(void);

signals:

public slots:

private slots:
    /**
     * @brief Slot triggered to stop the active capture.
     */
    void stopCapture();

private:
    /** Pointer to the generated UI elements. */
    Ui::CaptureInfoDialog *ui;

    /** Pointer to the underlying capture information. */
    struct _capture_info *cap_info_;

    /** Pointer to the active capture session. */
    struct _capture_session *cap_session_;

    /** Pointer to the table model providing capture statistics. */
    CaptureInfoModel *ci_model_;

    /** Timer tracking the duration of the capture. */
    QElapsedTimer duration_;
};

#endif // CAPTURE_INFO_DIALOG_H
