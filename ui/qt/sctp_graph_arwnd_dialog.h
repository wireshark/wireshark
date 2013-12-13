#ifndef SCTP_GRAPH_ARWND_DIALOG_H
#define SCTP_GRAPH_ARWND_DIALOG_H

#include "config.h"
#include "qcustomplot.h"
#include <glib.h>

#include <file.h>
#include <math.h>
#include <epan/dissectors/packet-sctp.h>
#include "epan/packet.h"

#include "ui/tap-sctp-analysis.h"

#include <QDialog>
#include <QObject>
#include <QMessageBox>

namespace Ui {
class SCTPGraphArwndDialog;
}


class SCTPGraphArwndDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCTPGraphArwndDialog(QWidget *parent = 0, sctp_assoc_info_t *assoc = NULL, capture_file *cf = NULL, int dir = 0);
    ~SCTPGraphArwndDialog();

public slots:
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    void on_pushButton_4_clicked();

    void graphClicked(QCPAbstractPlottable* plottable, QMouseEvent* event);

    void on_saveButton_clicked();

private:
    Ui::SCTPGraphArwndDialog *ui;
    sctp_assoc_info_t     *selected_assoc;
    capture_file *cap_file_;
    int frame_num;
    int direction;
    int startArwnd;
    QVector<double> xa, ya;
    QVector<guint32> fa;
 //   QVector<QString> typeStrings;

    void drawGraph();
    void drawArwndGraph();
};

#endif // SCTP_GRAPH_DIALOG_H
