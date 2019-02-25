/********************************************************************************
** Form generated from reading UI file 'rtp_stream_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_RTP_STREAM_DIALOG_H
#define UI_RTP_STREAM_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_RtpStreamDialog
{
public:
    QAction *actionFindReverse;
    QAction *actionMarkPackets;
    QAction *actionSelectNone;
    QAction *actionGoToSetup;
    QAction *actionPrepareFilter;
    QAction *actionExportAsRtpDump;
    QAction *actionAnalyze;
    QAction *actionCopyAsCsv;
    QAction *actionCopyAsYaml;
    QVBoxLayout *verticalLayout;
    QTreeWidget *streamTreeWidget;
    QLabel *hintLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *RtpStreamDialog)
    {
        if (RtpStreamDialog->objectName().isEmpty())
            RtpStreamDialog->setObjectName(QString::fromUtf8("RtpStreamDialog"));
        RtpStreamDialog->resize(600, 460);
        actionFindReverse = new QAction(RtpStreamDialog);
        actionFindReverse->setObjectName(QString::fromUtf8("actionFindReverse"));
        actionMarkPackets = new QAction(RtpStreamDialog);
        actionMarkPackets->setObjectName(QString::fromUtf8("actionMarkPackets"));
        actionSelectNone = new QAction(RtpStreamDialog);
        actionSelectNone->setObjectName(QString::fromUtf8("actionSelectNone"));
        actionGoToSetup = new QAction(RtpStreamDialog);
        actionGoToSetup->setObjectName(QString::fromUtf8("actionGoToSetup"));
        actionPrepareFilter = new QAction(RtpStreamDialog);
        actionPrepareFilter->setObjectName(QString::fromUtf8("actionPrepareFilter"));
        actionExportAsRtpDump = new QAction(RtpStreamDialog);
        actionExportAsRtpDump->setObjectName(QString::fromUtf8("actionExportAsRtpDump"));
        actionAnalyze = new QAction(RtpStreamDialog);
        actionAnalyze->setObjectName(QString::fromUtf8("actionAnalyze"));
        actionCopyAsCsv = new QAction(RtpStreamDialog);
        actionCopyAsCsv->setObjectName(QString::fromUtf8("actionCopyAsCsv"));
        actionCopyAsYaml = new QAction(RtpStreamDialog);
        actionCopyAsYaml->setObjectName(QString::fromUtf8("actionCopyAsYaml"));
        verticalLayout = new QVBoxLayout(RtpStreamDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        streamTreeWidget = new QTreeWidget(RtpStreamDialog);
        streamTreeWidget->setObjectName(QString::fromUtf8("streamTreeWidget"));
        streamTreeWidget->setSelectionMode(QAbstractItemView::MultiSelection);
        streamTreeWidget->setTextElideMode(Qt::ElideMiddle);
        streamTreeWidget->setRootIsDecorated(false);
        streamTreeWidget->setUniformRowHeights(true);
        streamTreeWidget->setItemsExpandable(false);
        streamTreeWidget->setSortingEnabled(true);
        streamTreeWidget->setExpandsOnDoubleClick(false);
        streamTreeWidget->header()->setDefaultSectionSize(50);

        verticalLayout->addWidget(streamTreeWidget);

        hintLabel = new QLabel(RtpStreamDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        verticalLayout->addWidget(hintLabel);

        buttonBox = new QDialogButtonBox(RtpStreamDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(RtpStreamDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), RtpStreamDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), RtpStreamDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(RtpStreamDialog);
    } // setupUi

    void retranslateUi(QDialog *RtpStreamDialog)
    {
        RtpStreamDialog->setWindowTitle(QApplication::translate("RtpStreamDialog", "Dialog", nullptr));
        actionFindReverse->setText(QApplication::translate("RtpStreamDialog", "Find Reverse", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFindReverse->setToolTip(QApplication::translate("RtpStreamDialog", "Find the reverse stream matching the selected forward stream.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionFindReverse->setShortcut(QApplication::translate("RtpStreamDialog", "R", nullptr));
#endif // QT_NO_SHORTCUT
        actionMarkPackets->setText(QApplication::translate("RtpStreamDialog", "Mark Packets", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMarkPackets->setToolTip(QApplication::translate("RtpStreamDialog", "Mark the packets of the selected stream(s).", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMarkPackets->setShortcut(QApplication::translate("RtpStreamDialog", "M", nullptr));
#endif // QT_NO_SHORTCUT
        actionSelectNone->setText(QApplication::translate("RtpStreamDialog", "Select None", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSelectNone->setToolTip(QApplication::translate("RtpStreamDialog", "Undo stream selection.", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoToSetup->setText(QApplication::translate("RtpStreamDialog", "Go To Setup", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToSetup->setToolTip(QApplication::translate("RtpStreamDialog", "Go to the setup packet for this stream.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToSetup->setShortcut(QApplication::translate("RtpStreamDialog", "G", nullptr));
#endif // QT_NO_SHORTCUT
        actionPrepareFilter->setText(QApplication::translate("RtpStreamDialog", "Prepare Filter", nullptr));
#ifndef QT_NO_TOOLTIP
        actionPrepareFilter->setToolTip(QApplication::translate("RtpStreamDialog", "Prepare a filter matching the selected stream(s).", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionPrepareFilter->setShortcut(QApplication::translate("RtpStreamDialog", "P", nullptr));
#endif // QT_NO_SHORTCUT
        actionExportAsRtpDump->setText(QApplication::translate("RtpStreamDialog", "Export As RTPDump", nullptr));
#ifndef QT_NO_TOOLTIP
        actionExportAsRtpDump->setToolTip(QApplication::translate("RtpStreamDialog", "Export the stream payload as rtpdump", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionExportAsRtpDump->setShortcut(QApplication::translate("RtpStreamDialog", "E", nullptr));
#endif // QT_NO_SHORTCUT
        actionAnalyze->setText(QApplication::translate("RtpStreamDialog", "Analyze", nullptr));
#ifndef QT_NO_TOOLTIP
        actionAnalyze->setToolTip(QApplication::translate("RtpStreamDialog", "Open the analysis window for the selected stream(s)", nullptr));
#endif // QT_NO_TOOLTIP
        actionCopyAsCsv->setText(QApplication::translate("RtpStreamDialog", "Copy as CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsCsv->setToolTip(QApplication::translate("RtpStreamDialog", "Copy stream list as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionCopyAsYaml->setText(QApplication::translate("RtpStreamDialog", "Copy as YAML", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsYaml->setToolTip(QApplication::translate("RtpStreamDialog", "Copy stream list as YAML.", nullptr));
#endif // QT_NO_TOOLTIP
        QTreeWidgetItem *___qtreewidgetitem = streamTreeWidget->headerItem();
        ___qtreewidgetitem->setText(11, QApplication::translate("RtpStreamDialog", "Status", nullptr));
        ___qtreewidgetitem->setText(10, QApplication::translate("RtpStreamDialog", "Mean Jitter", nullptr));
        ___qtreewidgetitem->setText(9, QApplication::translate("RtpStreamDialog", "Max Jitter", nullptr));
        ___qtreewidgetitem->setText(8, QApplication::translate("RtpStreamDialog", "Max Delta (ms)", nullptr));
        ___qtreewidgetitem->setText(7, QApplication::translate("RtpStreamDialog", "Lost", nullptr));
        ___qtreewidgetitem->setText(6, QApplication::translate("RtpStreamDialog", "Packets", nullptr));
        ___qtreewidgetitem->setText(5, QApplication::translate("RtpStreamDialog", "Payload", nullptr));
        ___qtreewidgetitem->setText(4, QApplication::translate("RtpStreamDialog", "SSRC", nullptr));
        ___qtreewidgetitem->setText(3, QApplication::translate("RtpStreamDialog", "Destination Port", nullptr));
        ___qtreewidgetitem->setText(2, QApplication::translate("RtpStreamDialog", "Destination Address", nullptr));
        ___qtreewidgetitem->setText(1, QApplication::translate("RtpStreamDialog", "Source Port", nullptr));
        ___qtreewidgetitem->setText(0, QApplication::translate("RtpStreamDialog", "Source Address", nullptr));
        hintLabel->setText(QApplication::translate("RtpStreamDialog", "<small><i>A hint.</i></small>", nullptr));
    } // retranslateUi

};

namespace Ui {
    class RtpStreamDialog: public Ui_RtpStreamDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_RTP_STREAM_DIALOG_H
