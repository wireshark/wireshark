/********************************************************************************
** Form generated from reading UI file 'sctp_all_assocs_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SCTP_ALL_ASSOCS_DIALOG_H
#define UI_SCTP_ALL_ASSOCS_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_SCTPAllAssocsDialog
{
public:
    QAction *actionReset;
    QAction *actionZoomIn;
    QAction *actionZoomOut;
    QAction *actionMoveUp10;
    QAction *actionMoveLeft10;
    QAction *actionMoveRight10;
    QAction *actionMoveDown10;
    QAction *actionMoveUp1;
    QAction *actionMoveLeft1;
    QAction *actionMoveRight1;
    QAction *actionMoveDown1;
    QAction *actionNextStream;
    QAction *actionPreviousStream;
    QAction *actionSwitchDirection;
    QAction *actionGoToPacket;
    QAction *actionDragZoom;
    QAction *actionToggleSequenceNumbers;
    QAction *actionToggleTimeOrigin;
    QAction *actionCrosshairs;
    QAction *actionRoundTripTime;
    QAction *actionThroughput;
    QAction *actionStevens;
    QAction *actionWindowScaling;
    QAction *actionTcptrace;
    QVBoxLayout *verticalLayout;
    QTableWidget *assocList;
    QHBoxLayout *horizontalLayout;
    QHBoxLayout *horizontalLayout_2;
    QPushButton *setFilterButton;
    QPushButton *analyseButton;
    QSpacerItem *horizontalSpacer_2;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *SCTPAllAssocsDialog)
    {
        if (SCTPAllAssocsDialog->objectName().isEmpty())
            SCTPAllAssocsDialog->setObjectName(QString::fromUtf8("SCTPAllAssocsDialog"));
        SCTPAllAssocsDialog->resize(685, 300);
        actionReset = new QAction(SCTPAllAssocsDialog);
        actionReset->setObjectName(QString::fromUtf8("actionReset"));
        actionZoomIn = new QAction(SCTPAllAssocsDialog);
        actionZoomIn->setObjectName(QString::fromUtf8("actionZoomIn"));
        actionZoomOut = new QAction(SCTPAllAssocsDialog);
        actionZoomOut->setObjectName(QString::fromUtf8("actionZoomOut"));
        actionMoveUp10 = new QAction(SCTPAllAssocsDialog);
        actionMoveUp10->setObjectName(QString::fromUtf8("actionMoveUp10"));
        actionMoveLeft10 = new QAction(SCTPAllAssocsDialog);
        actionMoveLeft10->setObjectName(QString::fromUtf8("actionMoveLeft10"));
        actionMoveRight10 = new QAction(SCTPAllAssocsDialog);
        actionMoveRight10->setObjectName(QString::fromUtf8("actionMoveRight10"));
        actionMoveDown10 = new QAction(SCTPAllAssocsDialog);
        actionMoveDown10->setObjectName(QString::fromUtf8("actionMoveDown10"));
        actionMoveUp1 = new QAction(SCTPAllAssocsDialog);
        actionMoveUp1->setObjectName(QString::fromUtf8("actionMoveUp1"));
        actionMoveLeft1 = new QAction(SCTPAllAssocsDialog);
        actionMoveLeft1->setObjectName(QString::fromUtf8("actionMoveLeft1"));
        actionMoveRight1 = new QAction(SCTPAllAssocsDialog);
        actionMoveRight1->setObjectName(QString::fromUtf8("actionMoveRight1"));
        actionMoveDown1 = new QAction(SCTPAllAssocsDialog);
        actionMoveDown1->setObjectName(QString::fromUtf8("actionMoveDown1"));
        actionNextStream = new QAction(SCTPAllAssocsDialog);
        actionNextStream->setObjectName(QString::fromUtf8("actionNextStream"));
        actionPreviousStream = new QAction(SCTPAllAssocsDialog);
        actionPreviousStream->setObjectName(QString::fromUtf8("actionPreviousStream"));
        actionSwitchDirection = new QAction(SCTPAllAssocsDialog);
        actionSwitchDirection->setObjectName(QString::fromUtf8("actionSwitchDirection"));
        actionGoToPacket = new QAction(SCTPAllAssocsDialog);
        actionGoToPacket->setObjectName(QString::fromUtf8("actionGoToPacket"));
        actionDragZoom = new QAction(SCTPAllAssocsDialog);
        actionDragZoom->setObjectName(QString::fromUtf8("actionDragZoom"));
        actionToggleSequenceNumbers = new QAction(SCTPAllAssocsDialog);
        actionToggleSequenceNumbers->setObjectName(QString::fromUtf8("actionToggleSequenceNumbers"));
        actionToggleTimeOrigin = new QAction(SCTPAllAssocsDialog);
        actionToggleTimeOrigin->setObjectName(QString::fromUtf8("actionToggleTimeOrigin"));
        actionCrosshairs = new QAction(SCTPAllAssocsDialog);
        actionCrosshairs->setObjectName(QString::fromUtf8("actionCrosshairs"));
        actionRoundTripTime = new QAction(SCTPAllAssocsDialog);
        actionRoundTripTime->setObjectName(QString::fromUtf8("actionRoundTripTime"));
        actionThroughput = new QAction(SCTPAllAssocsDialog);
        actionThroughput->setObjectName(QString::fromUtf8("actionThroughput"));
        actionStevens = new QAction(SCTPAllAssocsDialog);
        actionStevens->setObjectName(QString::fromUtf8("actionStevens"));
        actionWindowScaling = new QAction(SCTPAllAssocsDialog);
        actionWindowScaling->setObjectName(QString::fromUtf8("actionWindowScaling"));
        actionTcptrace = new QAction(SCTPAllAssocsDialog);
        actionTcptrace->setObjectName(QString::fromUtf8("actionTcptrace"));
        verticalLayout = new QVBoxLayout(SCTPAllAssocsDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        assocList = new QTableWidget(SCTPAllAssocsDialog);
        if (assocList->columnCount() < 6)
            assocList->setColumnCount(6);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        assocList->setHorizontalHeaderItem(0, __qtablewidgetitem);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        assocList->setHorizontalHeaderItem(1, __qtablewidgetitem1);
        QTableWidgetItem *__qtablewidgetitem2 = new QTableWidgetItem();
        assocList->setHorizontalHeaderItem(2, __qtablewidgetitem2);
        QTableWidgetItem *__qtablewidgetitem3 = new QTableWidgetItem();
        assocList->setHorizontalHeaderItem(3, __qtablewidgetitem3);
        QTableWidgetItem *__qtablewidgetitem4 = new QTableWidgetItem();
        assocList->setHorizontalHeaderItem(4, __qtablewidgetitem4);
        QTableWidgetItem *__qtablewidgetitem5 = new QTableWidgetItem();
        assocList->setHorizontalHeaderItem(5, __qtablewidgetitem5);
        if (assocList->rowCount() < 2)
            assocList->setRowCount(2);
        assocList->setObjectName(QString::fromUtf8("assocList"));
        assocList->setEditTriggers(QAbstractItemView::NoEditTriggers);
        assocList->setProperty("showDropIndicator", QVariant(false));
        assocList->setDragDropOverwriteMode(false);
        assocList->setAlternatingRowColors(true);
        assocList->setSelectionMode(QAbstractItemView::SingleSelection);
        assocList->setSelectionBehavior(QAbstractItemView::SelectRows);
        assocList->setSortingEnabled(true);
        assocList->setWordWrap(false);
        assocList->setRowCount(2);
        assocList->setColumnCount(6);
        assocList->horizontalHeader()->setDefaultSectionSize(120);
        assocList->horizontalHeader()->setMinimumSectionSize(50);
        assocList->horizontalHeader()->setStretchLastSection(true);

        verticalLayout->addWidget(assocList);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));

        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        setFilterButton = new QPushButton(SCTPAllAssocsDialog);
        setFilterButton->setObjectName(QString::fromUtf8("setFilterButton"));
        setFilterButton->setEnabled(false);
        setFilterButton->setFocusPolicy(Qt::ClickFocus);

        horizontalLayout_2->addWidget(setFilterButton);

        analyseButton = new QPushButton(SCTPAllAssocsDialog);
        analyseButton->setObjectName(QString::fromUtf8("analyseButton"));
        analyseButton->setEnabled(false);
        analyseButton->setFocusPolicy(Qt::ClickFocus);

        horizontalLayout_2->addWidget(analyseButton);

        horizontalSpacer_2 = new QSpacerItem(10, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);

        buttonBox = new QDialogButtonBox(SCTPAllAssocsDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        horizontalLayout_2->addWidget(buttonBox);


        verticalLayout->addLayout(horizontalLayout_2);


        retranslateUi(SCTPAllAssocsDialog);
        QObject::connect(buttonBox, SIGNAL(clicked(QAbstractButton*)), SCTPAllAssocsDialog, SLOT(close()));

        QMetaObject::connectSlotsByName(SCTPAllAssocsDialog);
    } // setupUi

    void retranslateUi(QDialog *SCTPAllAssocsDialog)
    {
        SCTPAllAssocsDialog->setWindowTitle(QApplication::translate("SCTPAllAssocsDialog", "Wireshark - SCTP Associations", nullptr));
        actionReset->setText(QApplication::translate("SCTPAllAssocsDialog", "Reset Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionReset->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Reset the graph to its initial state.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionReset->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "0", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomIn->setText(QApplication::translate("SCTPAllAssocsDialog", "Zoom In", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomIn->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Zoom In", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomIn->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "+", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOut->setText(QApplication::translate("SCTPAllAssocsDialog", "Zoom Out", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOut->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Zoom Out", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOut->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "-", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp10->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Up 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp10->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Up 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp10->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft10->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Left 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft10->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Left 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft10->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight10->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Right 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight10->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Right 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight10->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown10->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Down 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown10->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Down 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown10->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp1->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Up 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp1->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Up 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp1->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Shift+Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft1->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Left 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft1->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Left 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft1->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Shift+Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight1->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Right 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight1->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Right 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight1->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Shift+Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown1->setText(QApplication::translate("SCTPAllAssocsDialog", "Move Down 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown1->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Move Down 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown1->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Shift+Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionNextStream->setText(QApplication::translate("SCTPAllAssocsDialog", "Next Stream", nullptr));
#ifndef QT_NO_TOOLTIP
        actionNextStream->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Go to the next stream in the capture", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionNextStream->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "PgUp", nullptr));
#endif // QT_NO_SHORTCUT
        actionPreviousStream->setText(QApplication::translate("SCTPAllAssocsDialog", "Previous Stream", nullptr));
#ifndef QT_NO_TOOLTIP
        actionPreviousStream->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Go to the previous stream in the capture", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionPreviousStream->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "PgDown", nullptr));
#endif // QT_NO_SHORTCUT
        actionSwitchDirection->setText(QApplication::translate("SCTPAllAssocsDialog", "Switch Direction", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSwitchDirection->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Switch direction (swap TCP endpoints)", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionSwitchDirection->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "D", nullptr));
#endif // QT_NO_SHORTCUT
        actionGoToPacket->setText(QApplication::translate("SCTPAllAssocsDialog", "Go To Packet Under Cursor", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPacket->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Go to packet currently under the cursor", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToPacket->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "G", nullptr));
#endif // QT_NO_SHORTCUT
        actionDragZoom->setText(QApplication::translate("SCTPAllAssocsDialog", "Drag / Zoom", nullptr));
#ifndef QT_NO_TOOLTIP
        actionDragZoom->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Toggle mouse drag / zoom behavior", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionDragZoom->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Z", nullptr));
#endif // QT_NO_SHORTCUT
        actionToggleSequenceNumbers->setText(QApplication::translate("SCTPAllAssocsDialog", "Relative / Absolute Sequence Numbers", nullptr));
#ifndef QT_NO_TOOLTIP
        actionToggleSequenceNumbers->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Toggle relative / absolute sequence numbers", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionToggleSequenceNumbers->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "S", nullptr));
#endif // QT_NO_SHORTCUT
        actionToggleTimeOrigin->setText(QApplication::translate("SCTPAllAssocsDialog", "Capture / Session Time Origin", nullptr));
#ifndef QT_NO_TOOLTIP
        actionToggleTimeOrigin->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Toggle capture / session time origin", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionToggleTimeOrigin->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "T", nullptr));
#endif // QT_NO_SHORTCUT
        actionCrosshairs->setText(QApplication::translate("SCTPAllAssocsDialog", "Crosshairs", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCrosshairs->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Toggle crosshairs", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionCrosshairs->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "Space", nullptr));
#endif // QT_NO_SHORTCUT
        actionRoundTripTime->setText(QApplication::translate("SCTPAllAssocsDialog", "Round Trip Time", nullptr));
#ifndef QT_NO_TOOLTIP
        actionRoundTripTime->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Switch to the Round Trip Time graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionRoundTripTime->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "1", nullptr));
#endif // QT_NO_SHORTCUT
        actionThroughput->setText(QApplication::translate("SCTPAllAssocsDialog", "Throughput", nullptr));
#ifndef QT_NO_TOOLTIP
        actionThroughput->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Switch to the Throughput graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionThroughput->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "2", nullptr));
#endif // QT_NO_SHORTCUT
        actionStevens->setText(QApplication::translate("SCTPAllAssocsDialog", "Time / Sequence (Stevens)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStevens->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Switch to the Stevens-style Time / Sequence graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionStevens->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "3", nullptr));
#endif // QT_NO_SHORTCUT
        actionWindowScaling->setText(QApplication::translate("SCTPAllAssocsDialog", "Window Scaling", nullptr));
#ifndef QT_NO_TOOLTIP
        actionWindowScaling->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Switch to the Window Scaling graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionWindowScaling->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "5", nullptr));
#endif // QT_NO_SHORTCUT
        actionTcptrace->setText(QApplication::translate("SCTPAllAssocsDialog", "Time / Sequence (tcptrace)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTcptrace->setToolTip(QApplication::translate("SCTPAllAssocsDialog", "Switch to the tcptrace-style Time / Sequence graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionTcptrace->setShortcut(QApplication::translate("SCTPAllAssocsDialog", "4", nullptr));
#endif // QT_NO_SHORTCUT
        QTableWidgetItem *___qtablewidgetitem = assocList->horizontalHeaderItem(0);
        ___qtablewidgetitem->setText(QApplication::translate("SCTPAllAssocsDialog", "ID", nullptr));
        QTableWidgetItem *___qtablewidgetitem1 = assocList->horizontalHeaderItem(1);
        ___qtablewidgetitem1->setText(QApplication::translate("SCTPAllAssocsDialog", "Port 1", nullptr));
        QTableWidgetItem *___qtablewidgetitem2 = assocList->horizontalHeaderItem(2);
        ___qtablewidgetitem2->setText(QApplication::translate("SCTPAllAssocsDialog", "Port 2", nullptr));
        QTableWidgetItem *___qtablewidgetitem3 = assocList->horizontalHeaderItem(3);
        ___qtablewidgetitem3->setText(QApplication::translate("SCTPAllAssocsDialog", "Number of Packets", nullptr));
        QTableWidgetItem *___qtablewidgetitem4 = assocList->horizontalHeaderItem(4);
        ___qtablewidgetitem4->setText(QApplication::translate("SCTPAllAssocsDialog", "Number of DATA Chunks", nullptr));
        QTableWidgetItem *___qtablewidgetitem5 = assocList->horizontalHeaderItem(5);
        ___qtablewidgetitem5->setText(QApplication::translate("SCTPAllAssocsDialog", "Number of Bytes", nullptr));
        setFilterButton->setText(QApplication::translate("SCTPAllAssocsDialog", "Filter Selected Association", nullptr));
        analyseButton->setText(QApplication::translate("SCTPAllAssocsDialog", "Analyze", nullptr));
    } // retranslateUi

};

namespace Ui {
    class SCTPAllAssocsDialog: public Ui_SCTPAllAssocsDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SCTP_ALL_ASSOCS_DIALOG_H
