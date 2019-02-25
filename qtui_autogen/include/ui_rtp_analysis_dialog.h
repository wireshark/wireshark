/********************************************************************************
** Form generated from reading UI file 'rtp_analysis_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_RTP_ANALYSIS_DIALOG_H
#define UI_RTP_ANALYSIS_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include "progress_frame.h"
#include "widgets/qcustomplot.h"

QT_BEGIN_NAMESPACE

class Ui_RtpAnalysisDialog
{
public:
    QAction *actionSaveAudioUnsync;
    QAction *actionSaveForwardAudioUnsync;
    QAction *actionSaveReverseAudioUnsync;
    QAction *actionSaveCsv;
    QAction *actionSaveForwardCsv;
    QAction *actionSaveReverseCsv;
    QAction *actionSaveGraph;
    QAction *actionGoToPacket;
    QAction *actionNextProblem;
    QAction *actionSaveAudioSyncStream;
    QAction *actionSaveForwardAudioSyncStream;
    QAction *actionSaveReverseAudioSyncStream;
    QAction *actionSaveAudioSyncFile;
    QAction *actionSaveForwardAudioSyncFile;
    QAction *actionSaveReverseAudioSyncFile;
    QVBoxLayout *verticalLayout_3;
    QHBoxLayout *horizontalLayout;
    QVBoxLayout *verticalLayout;
    QLabel *statisticsLabel;
    QSpacerItem *verticalSpacer;
    QTabWidget *tabWidget;
    QTreeWidget *forwardTreeWidget;
    QTreeWidget *reverseTreeWidget;
    QWidget *graphTab;
    QVBoxLayout *verticalLayout_2;
    QCustomPlot *streamGraph;
    QHBoxLayout *forwardHorizontalLayout;
    QCheckBox *fJitterCheckBox;
    QSpacerItem *horizontalSpacer_3;
    QCheckBox *fDiffCheckBox;
    QSpacerItem *horizontalSpacer_5;
    QCheckBox *fDeltaCheckBox;
    QSpacerItem *horizontalSpacer;
    QHBoxLayout *reverseHorizontalLayout;
    QCheckBox *rJitterCheckBox;
    QSpacerItem *horizontalSpacer_4;
    QCheckBox *rDiffCheckBox;
    QSpacerItem *horizontalSpacer_6;
    QCheckBox *rDeltaCheckBox;
    QSpacerItem *horizontalSpacer_2;
    QHBoxLayout *horizontalLayout_2;
    QLabel *hintLabel;
    ProgressFrame *progressFrame;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *RtpAnalysisDialog)
    {
        if (RtpAnalysisDialog->objectName().isEmpty())
            RtpAnalysisDialog->setObjectName(QString::fromUtf8("RtpAnalysisDialog"));
        RtpAnalysisDialog->resize(650, 475);
        actionSaveAudioUnsync = new QAction(RtpAnalysisDialog);
        actionSaveAudioUnsync->setObjectName(QString::fromUtf8("actionSaveAudioUnsync"));
        actionSaveForwardAudioUnsync = new QAction(RtpAnalysisDialog);
        actionSaveForwardAudioUnsync->setObjectName(QString::fromUtf8("actionSaveForwardAudioUnsync"));
        actionSaveReverseAudioUnsync = new QAction(RtpAnalysisDialog);
        actionSaveReverseAudioUnsync->setObjectName(QString::fromUtf8("actionSaveReverseAudioUnsync"));
        actionSaveCsv = new QAction(RtpAnalysisDialog);
        actionSaveCsv->setObjectName(QString::fromUtf8("actionSaveCsv"));
        actionSaveForwardCsv = new QAction(RtpAnalysisDialog);
        actionSaveForwardCsv->setObjectName(QString::fromUtf8("actionSaveForwardCsv"));
        actionSaveReverseCsv = new QAction(RtpAnalysisDialog);
        actionSaveReverseCsv->setObjectName(QString::fromUtf8("actionSaveReverseCsv"));
        actionSaveGraph = new QAction(RtpAnalysisDialog);
        actionSaveGraph->setObjectName(QString::fromUtf8("actionSaveGraph"));
        actionGoToPacket = new QAction(RtpAnalysisDialog);
        actionGoToPacket->setObjectName(QString::fromUtf8("actionGoToPacket"));
        actionNextProblem = new QAction(RtpAnalysisDialog);
        actionNextProblem->setObjectName(QString::fromUtf8("actionNextProblem"));
        actionSaveAudioSyncStream = new QAction(RtpAnalysisDialog);
        actionSaveAudioSyncStream->setObjectName(QString::fromUtf8("actionSaveAudioSyncStream"));
        actionSaveForwardAudioSyncStream = new QAction(RtpAnalysisDialog);
        actionSaveForwardAudioSyncStream->setObjectName(QString::fromUtf8("actionSaveForwardAudioSyncStream"));
        actionSaveReverseAudioSyncStream = new QAction(RtpAnalysisDialog);
        actionSaveReverseAudioSyncStream->setObjectName(QString::fromUtf8("actionSaveReverseAudioSyncStream"));
        actionSaveAudioSyncFile = new QAction(RtpAnalysisDialog);
        actionSaveAudioSyncFile->setObjectName(QString::fromUtf8("actionSaveAudioSyncFile"));
        actionSaveForwardAudioSyncFile = new QAction(RtpAnalysisDialog);
        actionSaveForwardAudioSyncFile->setObjectName(QString::fromUtf8("actionSaveForwardAudioSyncFile"));
        actionSaveReverseAudioSyncFile = new QAction(RtpAnalysisDialog);
        actionSaveReverseAudioSyncFile->setObjectName(QString::fromUtf8("actionSaveReverseAudioSyncFile"));
        verticalLayout_3 = new QVBoxLayout(RtpAnalysisDialog);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        statisticsLabel = new QLabel(RtpAnalysisDialog);
        statisticsLabel->setObjectName(QString::fromUtf8("statisticsLabel"));
        statisticsLabel->setTextFormat(Qt::RichText);
        statisticsLabel->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        verticalLayout->addWidget(statisticsLabel);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);


        horizontalLayout->addLayout(verticalLayout);

        tabWidget = new QTabWidget(RtpAnalysisDialog);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        forwardTreeWidget = new QTreeWidget();
        forwardTreeWidget->setObjectName(QString::fromUtf8("forwardTreeWidget"));
        forwardTreeWidget->setRootIsDecorated(false);
        forwardTreeWidget->setUniformRowHeights(true);
        forwardTreeWidget->setItemsExpandable(false);
        forwardTreeWidget->setSortingEnabled(true);
        forwardTreeWidget->setExpandsOnDoubleClick(false);
        tabWidget->addTab(forwardTreeWidget, QString());
        reverseTreeWidget = new QTreeWidget();
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        reverseTreeWidget->setHeaderItem(__qtreewidgetitem);
        reverseTreeWidget->setObjectName(QString::fromUtf8("reverseTreeWidget"));
        reverseTreeWidget->setRootIsDecorated(false);
        reverseTreeWidget->setUniformRowHeights(true);
        reverseTreeWidget->setItemsExpandable(false);
        reverseTreeWidget->setSortingEnabled(true);
        tabWidget->addTab(reverseTreeWidget, QString());
        graphTab = new QWidget();
        graphTab->setObjectName(QString::fromUtf8("graphTab"));
        verticalLayout_2 = new QVBoxLayout(graphTab);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        streamGraph = new QCustomPlot(graphTab);
        streamGraph->setObjectName(QString::fromUtf8("streamGraph"));

        verticalLayout_2->addWidget(streamGraph);

        forwardHorizontalLayout = new QHBoxLayout();
        forwardHorizontalLayout->setObjectName(QString::fromUtf8("forwardHorizontalLayout"));
        fJitterCheckBox = new QCheckBox(graphTab);
        fJitterCheckBox->setObjectName(QString::fromUtf8("fJitterCheckBox"));

        forwardHorizontalLayout->addWidget(fJitterCheckBox);

        horizontalSpacer_3 = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        forwardHorizontalLayout->addItem(horizontalSpacer_3);

        fDiffCheckBox = new QCheckBox(graphTab);
        fDiffCheckBox->setObjectName(QString::fromUtf8("fDiffCheckBox"));

        forwardHorizontalLayout->addWidget(fDiffCheckBox);

        horizontalSpacer_5 = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        forwardHorizontalLayout->addItem(horizontalSpacer_5);

        fDeltaCheckBox = new QCheckBox(graphTab);
        fDeltaCheckBox->setObjectName(QString::fromUtf8("fDeltaCheckBox"));

        forwardHorizontalLayout->addWidget(fDeltaCheckBox);

        horizontalSpacer = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        forwardHorizontalLayout->addItem(horizontalSpacer);

        forwardHorizontalLayout->setStretch(5, 1);

        verticalLayout_2->addLayout(forwardHorizontalLayout);

        reverseHorizontalLayout = new QHBoxLayout();
        reverseHorizontalLayout->setObjectName(QString::fromUtf8("reverseHorizontalLayout"));
        rJitterCheckBox = new QCheckBox(graphTab);
        rJitterCheckBox->setObjectName(QString::fromUtf8("rJitterCheckBox"));

        reverseHorizontalLayout->addWidget(rJitterCheckBox);

        horizontalSpacer_4 = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        reverseHorizontalLayout->addItem(horizontalSpacer_4);

        rDiffCheckBox = new QCheckBox(graphTab);
        rDiffCheckBox->setObjectName(QString::fromUtf8("rDiffCheckBox"));

        reverseHorizontalLayout->addWidget(rDiffCheckBox);

        horizontalSpacer_6 = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        reverseHorizontalLayout->addItem(horizontalSpacer_6);

        rDeltaCheckBox = new QCheckBox(graphTab);
        rDeltaCheckBox->setObjectName(QString::fromUtf8("rDeltaCheckBox"));

        reverseHorizontalLayout->addWidget(rDeltaCheckBox);

        horizontalSpacer_2 = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        reverseHorizontalLayout->addItem(horizontalSpacer_2);

        reverseHorizontalLayout->setStretch(5, 1);

        verticalLayout_2->addLayout(reverseHorizontalLayout);

        verticalLayout_2->setStretch(0, 1);
        tabWidget->addTab(graphTab, QString());

        horizontalLayout->addWidget(tabWidget);


        verticalLayout_3->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        hintLabel = new QLabel(RtpAnalysisDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        horizontalLayout_2->addWidget(hintLabel);

        progressFrame = new ProgressFrame(RtpAnalysisDialog);
        progressFrame->setObjectName(QString::fromUtf8("progressFrame"));
        progressFrame->setFrameShape(QFrame::NoFrame);
        progressFrame->setFrameShadow(QFrame::Plain);

        horizontalLayout_2->addWidget(progressFrame);

        horizontalLayout_2->setStretch(0, 1);

        verticalLayout_3->addLayout(horizontalLayout_2);

        buttonBox = new QDialogButtonBox(RtpAnalysisDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help|QDialogButtonBox::Save);

        verticalLayout_3->addWidget(buttonBox);


        retranslateUi(RtpAnalysisDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), RtpAnalysisDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), RtpAnalysisDialog, SLOT(reject()));

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(RtpAnalysisDialog);
    } // setupUi

    void retranslateUi(QDialog *RtpAnalysisDialog)
    {
        RtpAnalysisDialog->setWindowTitle(QApplication::translate("RtpAnalysisDialog", "Dialog", nullptr));
        actionSaveAudioUnsync->setText(QApplication::translate("RtpAnalysisDialog", "Unsynchronized Forward and Reverse Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveAudioUnsync->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the unsynchronized audio data for both channels.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveForwardAudioUnsync->setText(QApplication::translate("RtpAnalysisDialog", "Unsynchronized Forward Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveForwardAudioUnsync->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the unsynchronized forward stream audio data.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveReverseAudioUnsync->setText(QApplication::translate("RtpAnalysisDialog", "Unsynchronized Reverse Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveReverseAudioUnsync->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the unsynchronized reverse stream audio data.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveCsv->setText(QApplication::translate("RtpAnalysisDialog", "CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveCsv->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save both tables as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveForwardCsv->setText(QApplication::translate("RtpAnalysisDialog", "Forward Stream CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveForwardCsv->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the forward table as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveReverseCsv->setText(QApplication::translate("RtpAnalysisDialog", "Reverse Stream CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveReverseCsv->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the reverse table as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveGraph->setText(QApplication::translate("RtpAnalysisDialog", "Save Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveGraph->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the graph image.", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoToPacket->setText(QApplication::translate("RtpAnalysisDialog", "Go to Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPacket->setToolTip(QApplication::translate("RtpAnalysisDialog", "Select the corresponding packet in the packet list.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToPacket->setShortcut(QApplication::translate("RtpAnalysisDialog", "G", nullptr));
#endif // QT_NO_SHORTCUT
        actionNextProblem->setText(QApplication::translate("RtpAnalysisDialog", "Next Problem Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionNextProblem->setToolTip(QApplication::translate("RtpAnalysisDialog", "Go to the next problem packet", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionNextProblem->setShortcut(QApplication::translate("RtpAnalysisDialog", "N", nullptr));
#endif // QT_NO_SHORTCUT
        actionSaveAudioSyncStream->setText(QApplication::translate("RtpAnalysisDialog", "Stream Synchronized Forward and Reverse Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveAudioSyncStream->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the audio data for both channels synchronized to start of earlier stream.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveForwardAudioSyncStream->setText(QApplication::translate("RtpAnalysisDialog", "Stream Synchronized Forward Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveForwardAudioSyncStream->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the forward stream audio data synchronized to start of earlier stream.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveReverseAudioSyncStream->setText(QApplication::translate("RtpAnalysisDialog", "Stream Synchronized Reverse Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveReverseAudioSyncStream->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the reverse stream audio data synchronized to start of earlier stream.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveAudioSyncFile->setText(QApplication::translate("RtpAnalysisDialog", "File Synchronized Forward and Reverse Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveAudioSyncFile->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the audio data for both channels synchronized to start of file.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveForwardAudioSyncFile->setText(QApplication::translate("RtpAnalysisDialog", "File Synchronized Forward Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveForwardAudioSyncFile->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the forward stream audio data synchronized to start of file.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveReverseAudioSyncFile->setText(QApplication::translate("RtpAnalysisDialog", "File Synchronized Reverse Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveReverseAudioSyncFile->setToolTip(QApplication::translate("RtpAnalysisDialog", "Save the reverse stream audio data synchronized to start of file.", nullptr));
#endif // QT_NO_TOOLTIP
        statisticsLabel->setText(QApplication::translate("RtpAnalysisDialog", "<html><head/><body><p><span style=\" font-size:medium; font-weight:600;\">Forward</span></p><p><span style=\" font-size:medium; font-weight:600;\">Reverse</span></p></body></html>", nullptr));
        QTreeWidgetItem *___qtreewidgetitem = forwardTreeWidget->headerItem();
        ___qtreewidgetitem->setText(7, QApplication::translate("RtpAnalysisDialog", "Status", nullptr));
        ___qtreewidgetitem->setText(6, QApplication::translate("RtpAnalysisDialog", "Marker", nullptr));
        ___qtreewidgetitem->setText(5, QApplication::translate("RtpAnalysisDialog", "Bandwidth", nullptr));
        ___qtreewidgetitem->setText(4, QApplication::translate("RtpAnalysisDialog", "Skew", nullptr));
        ___qtreewidgetitem->setText(3, QApplication::translate("RtpAnalysisDialog", "Jitter (ms)", nullptr));
        ___qtreewidgetitem->setText(2, QApplication::translate("RtpAnalysisDialog", "Delta (ms)", nullptr));
        ___qtreewidgetitem->setText(1, QApplication::translate("RtpAnalysisDialog", "Sequence", nullptr));
        ___qtreewidgetitem->setText(0, QApplication::translate("RtpAnalysisDialog", "Packet", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(forwardTreeWidget), QApplication::translate("RtpAnalysisDialog", "Forward", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(reverseTreeWidget), QApplication::translate("RtpAnalysisDialog", "Reverse", nullptr));
#ifndef QT_NO_TOOLTIP
        fJitterCheckBox->setToolTip(QApplication::translate("RtpAnalysisDialog", "<html><head/><body><p>Show or hide forward jitter values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        fJitterCheckBox->setText(QApplication::translate("RtpAnalysisDialog", "Forward Jitter", nullptr));
#ifndef QT_NO_TOOLTIP
        fDiffCheckBox->setToolTip(QApplication::translate("RtpAnalysisDialog", "<html><head/><body><p>Show or hide forward difference values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        fDiffCheckBox->setText(QApplication::translate("RtpAnalysisDialog", "Forward Difference", nullptr));
#ifndef QT_NO_TOOLTIP
        fDeltaCheckBox->setToolTip(QApplication::translate("RtpAnalysisDialog", "<html><head/><body><p>Show or hide forward delta values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        fDeltaCheckBox->setText(QApplication::translate("RtpAnalysisDialog", "Forward Delta", nullptr));
#ifndef QT_NO_TOOLTIP
        rJitterCheckBox->setToolTip(QApplication::translate("RtpAnalysisDialog", "<html><head/><body><p>Show or hide reverse jitter values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        rJitterCheckBox->setText(QApplication::translate("RtpAnalysisDialog", "Reverse Jitter", nullptr));
#ifndef QT_NO_TOOLTIP
        rDiffCheckBox->setToolTip(QApplication::translate("RtpAnalysisDialog", "<html><head/><body><p>Show or hide reverse difference values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        rDiffCheckBox->setText(QApplication::translate("RtpAnalysisDialog", "Reverse Difference", nullptr));
#ifndef QT_NO_TOOLTIP
        rDeltaCheckBox->setToolTip(QApplication::translate("RtpAnalysisDialog", "<html><head/><body><p>Show or hide reverse delta values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        rDeltaCheckBox->setText(QApplication::translate("RtpAnalysisDialog", "Reverse Delta", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(graphTab), QApplication::translate("RtpAnalysisDialog", "Graph", nullptr));
        hintLabel->setText(QApplication::translate("RtpAnalysisDialog", "<small><i>A hint.</i></small>", nullptr));
    } // retranslateUi

};

namespace Ui {
    class RtpAnalysisDialog: public Ui_RtpAnalysisDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_RTP_ANALYSIS_DIALOG_H
