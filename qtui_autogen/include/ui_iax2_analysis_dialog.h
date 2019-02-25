/********************************************************************************
** Form generated from reading UI file 'iax2_analysis_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_IAX2_ANALYSIS_DIALOG_H
#define UI_IAX2_ANALYSIS_DIALOG_H

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

class Ui_Iax2AnalysisDialog
{
public:
    QAction *actionSaveAudio;
    QAction *actionSaveForwardAudio;
    QAction *actionSaveReverseAudio;
    QAction *actionSaveCsv;
    QAction *actionSaveForwardCsv;
    QAction *actionSaveReverseCsv;
    QAction *actionSaveGraph;
    QAction *actionGoToPacket;
    QAction *actionNextProblem;
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
    QSpacerItem *horizontalSpacer;
    QHBoxLayout *reverseHorizontalLayout;
    QCheckBox *rJitterCheckBox;
    QSpacerItem *horizontalSpacer_4;
    QCheckBox *rDiffCheckBox;
    QSpacerItem *horizontalSpacer_2;
    QHBoxLayout *horizontalLayout_2;
    QLabel *hintLabel;
    ProgressFrame *progressFrame;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Iax2AnalysisDialog)
    {
        if (Iax2AnalysisDialog->objectName().isEmpty())
            Iax2AnalysisDialog->setObjectName(QString::fromUtf8("Iax2AnalysisDialog"));
        Iax2AnalysisDialog->resize(650, 475);
        actionSaveAudio = new QAction(Iax2AnalysisDialog);
        actionSaveAudio->setObjectName(QString::fromUtf8("actionSaveAudio"));
        actionSaveForwardAudio = new QAction(Iax2AnalysisDialog);
        actionSaveForwardAudio->setObjectName(QString::fromUtf8("actionSaveForwardAudio"));
        actionSaveReverseAudio = new QAction(Iax2AnalysisDialog);
        actionSaveReverseAudio->setObjectName(QString::fromUtf8("actionSaveReverseAudio"));
        actionSaveCsv = new QAction(Iax2AnalysisDialog);
        actionSaveCsv->setObjectName(QString::fromUtf8("actionSaveCsv"));
        actionSaveForwardCsv = new QAction(Iax2AnalysisDialog);
        actionSaveForwardCsv->setObjectName(QString::fromUtf8("actionSaveForwardCsv"));
        actionSaveReverseCsv = new QAction(Iax2AnalysisDialog);
        actionSaveReverseCsv->setObjectName(QString::fromUtf8("actionSaveReverseCsv"));
        actionSaveGraph = new QAction(Iax2AnalysisDialog);
        actionSaveGraph->setObjectName(QString::fromUtf8("actionSaveGraph"));
        actionGoToPacket = new QAction(Iax2AnalysisDialog);
        actionGoToPacket->setObjectName(QString::fromUtf8("actionGoToPacket"));
        actionNextProblem = new QAction(Iax2AnalysisDialog);
        actionNextProblem->setObjectName(QString::fromUtf8("actionNextProblem"));
        verticalLayout_3 = new QVBoxLayout(Iax2AnalysisDialog);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        statisticsLabel = new QLabel(Iax2AnalysisDialog);
        statisticsLabel->setObjectName(QString::fromUtf8("statisticsLabel"));
        statisticsLabel->setTextFormat(Qt::RichText);
        statisticsLabel->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        verticalLayout->addWidget(statisticsLabel);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout->addItem(verticalSpacer);


        horizontalLayout->addLayout(verticalLayout);

        tabWidget = new QTabWidget(Iax2AnalysisDialog);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        forwardTreeWidget = new QTreeWidget();
        forwardTreeWidget->setObjectName(QString::fromUtf8("forwardTreeWidget"));
        forwardTreeWidget->setRootIsDecorated(false);
        forwardTreeWidget->setItemsExpandable(false);
        forwardTreeWidget->setExpandsOnDoubleClick(false);
        tabWidget->addTab(forwardTreeWidget, QString());
        reverseTreeWidget = new QTreeWidget();
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        reverseTreeWidget->setHeaderItem(__qtreewidgetitem);
        reverseTreeWidget->setObjectName(QString::fromUtf8("reverseTreeWidget"));
        reverseTreeWidget->setRootIsDecorated(false);
        reverseTreeWidget->setItemsExpandable(false);
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

        horizontalSpacer = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        forwardHorizontalLayout->addItem(horizontalSpacer);

        forwardHorizontalLayout->setStretch(3, 1);

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

        horizontalSpacer_2 = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        reverseHorizontalLayout->addItem(horizontalSpacer_2);

        reverseHorizontalLayout->setStretch(3, 1);

        verticalLayout_2->addLayout(reverseHorizontalLayout);

        verticalLayout_2->setStretch(0, 1);
        tabWidget->addTab(graphTab, QString());

        horizontalLayout->addWidget(tabWidget);


        verticalLayout_3->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        hintLabel = new QLabel(Iax2AnalysisDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        horizontalLayout_2->addWidget(hintLabel);

        progressFrame = new ProgressFrame(Iax2AnalysisDialog);
        progressFrame->setObjectName(QString::fromUtf8("progressFrame"));
        progressFrame->setFrameShape(QFrame::NoFrame);
        progressFrame->setFrameShadow(QFrame::Plain);

        horizontalLayout_2->addWidget(progressFrame);

        horizontalLayout_2->setStretch(0, 1);

        verticalLayout_3->addLayout(horizontalLayout_2);

        buttonBox = new QDialogButtonBox(Iax2AnalysisDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help|QDialogButtonBox::Save);

        verticalLayout_3->addWidget(buttonBox);


        retranslateUi(Iax2AnalysisDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Iax2AnalysisDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Iax2AnalysisDialog, SLOT(reject()));

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(Iax2AnalysisDialog);
    } // setupUi

    void retranslateUi(QDialog *Iax2AnalysisDialog)
    {
        Iax2AnalysisDialog->setWindowTitle(QApplication::translate("Iax2AnalysisDialog", "Dialog", nullptr));
        actionSaveAudio->setText(QApplication::translate("Iax2AnalysisDialog", "Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveAudio->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Save the audio data for both channels.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveForwardAudio->setText(QApplication::translate("Iax2AnalysisDialog", "Forward Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveForwardAudio->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Save the forward stream audio data.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveReverseAudio->setText(QApplication::translate("Iax2AnalysisDialog", "Reverse Stream Audio", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveReverseAudio->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Save the reverse stream audio data.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveCsv->setText(QApplication::translate("Iax2AnalysisDialog", "CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveCsv->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Save both tables as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveForwardCsv->setText(QApplication::translate("Iax2AnalysisDialog", "Forward Stream CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveForwardCsv->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Save the forward table as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveReverseCsv->setText(QApplication::translate("Iax2AnalysisDialog", "Reverse Stream CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveReverseCsv->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Save the reverse table as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionSaveGraph->setText(QApplication::translate("Iax2AnalysisDialog", "Save Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSaveGraph->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Save the graph image.", nullptr));
#endif // QT_NO_TOOLTIP
        actionGoToPacket->setText(QApplication::translate("Iax2AnalysisDialog", "Go to Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPacket->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Select the corresponding packet in the packet list.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToPacket->setShortcut(QApplication::translate("Iax2AnalysisDialog", "G", nullptr));
#endif // QT_NO_SHORTCUT
        actionNextProblem->setText(QApplication::translate("Iax2AnalysisDialog", "Next Problem Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionNextProblem->setToolTip(QApplication::translate("Iax2AnalysisDialog", "Go to the next problem packet", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionNextProblem->setShortcut(QApplication::translate("Iax2AnalysisDialog", "N", nullptr));
#endif // QT_NO_SHORTCUT
        statisticsLabel->setText(QApplication::translate("Iax2AnalysisDialog", "<html><head/><body><p><span style=\" font-size:medium; font-weight:600;\">Forward</span></p><p><span style=\" font-size:medium; font-weight:600;\">Reverse</span></p></body></html>", nullptr));
        QTreeWidgetItem *___qtreewidgetitem = forwardTreeWidget->headerItem();
        ___qtreewidgetitem->setText(5, QApplication::translate("Iax2AnalysisDialog", "Length", nullptr));
        ___qtreewidgetitem->setText(4, QApplication::translate("Iax2AnalysisDialog", "Status", nullptr));
        ___qtreewidgetitem->setText(3, QApplication::translate("Iax2AnalysisDialog", "Bandwidth", nullptr));
        ___qtreewidgetitem->setText(2, QApplication::translate("Iax2AnalysisDialog", "Jitter (ms)", nullptr));
        ___qtreewidgetitem->setText(1, QApplication::translate("Iax2AnalysisDialog", "Delta (ms)", nullptr));
        ___qtreewidgetitem->setText(0, QApplication::translate("Iax2AnalysisDialog", "Packet", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(forwardTreeWidget), QApplication::translate("Iax2AnalysisDialog", "Forward", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(reverseTreeWidget), QApplication::translate("Iax2AnalysisDialog", "Reverse", nullptr));
#ifndef QT_NO_TOOLTIP
        fJitterCheckBox->setToolTip(QApplication::translate("Iax2AnalysisDialog", "<html><head/><body><p>Show or hide forward jitter values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        fJitterCheckBox->setText(QApplication::translate("Iax2AnalysisDialog", "Forward Jitter", nullptr));
#ifndef QT_NO_TOOLTIP
        fDiffCheckBox->setToolTip(QApplication::translate("Iax2AnalysisDialog", "<html><head/><body><p>Show or hide forward difference values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        fDiffCheckBox->setText(QApplication::translate("Iax2AnalysisDialog", "Forward Difference", nullptr));
#ifndef QT_NO_TOOLTIP
        rJitterCheckBox->setToolTip(QApplication::translate("Iax2AnalysisDialog", "<html><head/><body><p>Show or hide reverse jitter values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        rJitterCheckBox->setText(QApplication::translate("Iax2AnalysisDialog", "Reverse Jitter", nullptr));
#ifndef QT_NO_TOOLTIP
        rDiffCheckBox->setToolTip(QApplication::translate("Iax2AnalysisDialog", "<html><head/><body><p>Show or hide reverse difference values.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        rDiffCheckBox->setText(QApplication::translate("Iax2AnalysisDialog", "Reverse Difference", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(graphTab), QApplication::translate("Iax2AnalysisDialog", "Graph", nullptr));
        hintLabel->setText(QApplication::translate("Iax2AnalysisDialog", "<small><i>A hint.</i></small>", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Iax2AnalysisDialog: public Ui_Iax2AnalysisDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_IAX2_ANALYSIS_DIALOG_H
