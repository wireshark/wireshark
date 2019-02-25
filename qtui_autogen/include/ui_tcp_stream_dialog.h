/********************************************************************************
** Form generated from reading UI file 'tcp_stream_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TCP_STREAM_DIALOG_H
#define UI_TCP_STREAM_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QVBoxLayout>
#include "widgets/qcustomplot.h"

QT_BEGIN_NAMESPACE

class Ui_TCPStreamDialog
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
    QAction *actionZoomInX;
    QAction *actionZoomOutX;
    QAction *actionZoomInY;
    QAction *actionZoomOutY;
    QVBoxLayout *verticalLayout;
    QCustomPlot *streamPlot;
    QLabel *hintLabel;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QComboBox *graphTypeComboBox;
    QSpacerItem *horizontalSpacer_1a;
    QLabel *maWindowSizeLabel;
    QDoubleSpinBox *maWindowSizeSpinBox;
    QCheckBox *selectSACKsCheckBox;
    QSpacerItem *horizontalSpacer_1b;
    QLabel *streamNumberLabel;
    QSpinBox *streamNumberSpinBox;
    QPushButton *otherDirectionButton;
    QHBoxLayout *horizontalLayout_2;
    QLabel *mouseLabel;
    QRadioButton *dragRadioButton;
    QRadioButton *zoomRadioButton;
    QSpacerItem *horizontalSpacer_2a;
    QCheckBox *bySeqNumberCheckBox;
    QCheckBox *showSegLengthCheckBox;
    QCheckBox *showThroughputCheckBox;
    QCheckBox *showGoodputCheckBox;
    QCheckBox *showRcvWinCheckBox;
    QCheckBox *showBytesOutCheckBox;
    QSpacerItem *horizontalSpacer_2b;
    QPushButton *resetButton;
    QDialogButtonBox *buttonBox;
    QButtonGroup *mouseButtonGroup;

    void setupUi(QDialog *TCPStreamDialog)
    {
        if (TCPStreamDialog->objectName().isEmpty())
            TCPStreamDialog->setObjectName(QString::fromUtf8("TCPStreamDialog"));
        TCPStreamDialog->resize(850, 640);
        actionReset = new QAction(TCPStreamDialog);
        actionReset->setObjectName(QString::fromUtf8("actionReset"));
        actionZoomIn = new QAction(TCPStreamDialog);
        actionZoomIn->setObjectName(QString::fromUtf8("actionZoomIn"));
        actionZoomOut = new QAction(TCPStreamDialog);
        actionZoomOut->setObjectName(QString::fromUtf8("actionZoomOut"));
        actionMoveUp10 = new QAction(TCPStreamDialog);
        actionMoveUp10->setObjectName(QString::fromUtf8("actionMoveUp10"));
        actionMoveLeft10 = new QAction(TCPStreamDialog);
        actionMoveLeft10->setObjectName(QString::fromUtf8("actionMoveLeft10"));
        actionMoveRight10 = new QAction(TCPStreamDialog);
        actionMoveRight10->setObjectName(QString::fromUtf8("actionMoveRight10"));
        actionMoveDown10 = new QAction(TCPStreamDialog);
        actionMoveDown10->setObjectName(QString::fromUtf8("actionMoveDown10"));
        actionMoveUp1 = new QAction(TCPStreamDialog);
        actionMoveUp1->setObjectName(QString::fromUtf8("actionMoveUp1"));
        actionMoveLeft1 = new QAction(TCPStreamDialog);
        actionMoveLeft1->setObjectName(QString::fromUtf8("actionMoveLeft1"));
        actionMoveRight1 = new QAction(TCPStreamDialog);
        actionMoveRight1->setObjectName(QString::fromUtf8("actionMoveRight1"));
        actionMoveDown1 = new QAction(TCPStreamDialog);
        actionMoveDown1->setObjectName(QString::fromUtf8("actionMoveDown1"));
        actionNextStream = new QAction(TCPStreamDialog);
        actionNextStream->setObjectName(QString::fromUtf8("actionNextStream"));
        actionPreviousStream = new QAction(TCPStreamDialog);
        actionPreviousStream->setObjectName(QString::fromUtf8("actionPreviousStream"));
        actionSwitchDirection = new QAction(TCPStreamDialog);
        actionSwitchDirection->setObjectName(QString::fromUtf8("actionSwitchDirection"));
        actionGoToPacket = new QAction(TCPStreamDialog);
        actionGoToPacket->setObjectName(QString::fromUtf8("actionGoToPacket"));
        actionDragZoom = new QAction(TCPStreamDialog);
        actionDragZoom->setObjectName(QString::fromUtf8("actionDragZoom"));
        actionToggleSequenceNumbers = new QAction(TCPStreamDialog);
        actionToggleSequenceNumbers->setObjectName(QString::fromUtf8("actionToggleSequenceNumbers"));
        actionToggleTimeOrigin = new QAction(TCPStreamDialog);
        actionToggleTimeOrigin->setObjectName(QString::fromUtf8("actionToggleTimeOrigin"));
        actionCrosshairs = new QAction(TCPStreamDialog);
        actionCrosshairs->setObjectName(QString::fromUtf8("actionCrosshairs"));
        actionRoundTripTime = new QAction(TCPStreamDialog);
        actionRoundTripTime->setObjectName(QString::fromUtf8("actionRoundTripTime"));
        actionThroughput = new QAction(TCPStreamDialog);
        actionThroughput->setObjectName(QString::fromUtf8("actionThroughput"));
        actionStevens = new QAction(TCPStreamDialog);
        actionStevens->setObjectName(QString::fromUtf8("actionStevens"));
        actionWindowScaling = new QAction(TCPStreamDialog);
        actionWindowScaling->setObjectName(QString::fromUtf8("actionWindowScaling"));
        actionTcptrace = new QAction(TCPStreamDialog);
        actionTcptrace->setObjectName(QString::fromUtf8("actionTcptrace"));
        actionZoomInX = new QAction(TCPStreamDialog);
        actionZoomInX->setObjectName(QString::fromUtf8("actionZoomInX"));
        actionZoomOutX = new QAction(TCPStreamDialog);
        actionZoomOutX->setObjectName(QString::fromUtf8("actionZoomOutX"));
        actionZoomInY = new QAction(TCPStreamDialog);
        actionZoomInY->setObjectName(QString::fromUtf8("actionZoomInY"));
        actionZoomOutY = new QAction(TCPStreamDialog);
        actionZoomOutY->setObjectName(QString::fromUtf8("actionZoomOutY"));
        verticalLayout = new QVBoxLayout(TCPStreamDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        streamPlot = new QCustomPlot(TCPStreamDialog);
        streamPlot->setObjectName(QString::fromUtf8("streamPlot"));
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(1);
        sizePolicy.setHeightForWidth(streamPlot->sizePolicy().hasHeightForWidth());
        streamPlot->setSizePolicy(sizePolicy);
        streamPlot->setFocusPolicy(Qt::TabFocus);

        verticalLayout->addWidget(streamPlot);

        hintLabel = new QLabel(TCPStreamDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        verticalLayout->addWidget(hintLabel);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(TCPStreamDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        graphTypeComboBox = new QComboBox(TCPStreamDialog);
        graphTypeComboBox->setObjectName(QString::fromUtf8("graphTypeComboBox"));
        graphTypeComboBox->setFrame(false);
        graphTypeComboBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout->addWidget(graphTypeComboBox);

        horizontalSpacer_1a = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_1a);

        maWindowSizeLabel = new QLabel(TCPStreamDialog);
        maWindowSizeLabel->setObjectName(QString::fromUtf8("maWindowSizeLabel"));

        horizontalLayout->addWidget(maWindowSizeLabel);

        maWindowSizeSpinBox = new QDoubleSpinBox(TCPStreamDialog);
        maWindowSizeSpinBox->setObjectName(QString::fromUtf8("maWindowSizeSpinBox"));

        horizontalLayout->addWidget(maWindowSizeSpinBox);

        selectSACKsCheckBox = new QCheckBox(TCPStreamDialog);
        selectSACKsCheckBox->setObjectName(QString::fromUtf8("selectSACKsCheckBox"));
        selectSACKsCheckBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout->addWidget(selectSACKsCheckBox);

        horizontalSpacer_1b = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_1b);

        streamNumberLabel = new QLabel(TCPStreamDialog);
        streamNumberLabel->setObjectName(QString::fromUtf8("streamNumberLabel"));

        horizontalLayout->addWidget(streamNumberLabel);

        streamNumberSpinBox = new QSpinBox(TCPStreamDialog);
        streamNumberSpinBox->setObjectName(QString::fromUtf8("streamNumberSpinBox"));

        horizontalLayout->addWidget(streamNumberSpinBox);

        otherDirectionButton = new QPushButton(TCPStreamDialog);
        otherDirectionButton->setObjectName(QString::fromUtf8("otherDirectionButton"));

        horizontalLayout->addWidget(otherDirectionButton);


        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        mouseLabel = new QLabel(TCPStreamDialog);
        mouseLabel->setObjectName(QString::fromUtf8("mouseLabel"));

        horizontalLayout_2->addWidget(mouseLabel);

        dragRadioButton = new QRadioButton(TCPStreamDialog);
        mouseButtonGroup = new QButtonGroup(TCPStreamDialog);
        mouseButtonGroup->setObjectName(QString::fromUtf8("mouseButtonGroup"));
        mouseButtonGroup->addButton(dragRadioButton);
        dragRadioButton->setObjectName(QString::fromUtf8("dragRadioButton"));
        dragRadioButton->setCheckable(true);
        dragRadioButton->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(dragRadioButton);

        zoomRadioButton = new QRadioButton(TCPStreamDialog);
        mouseButtonGroup->addButton(zoomRadioButton);
        zoomRadioButton->setObjectName(QString::fromUtf8("zoomRadioButton"));
        zoomRadioButton->setCheckable(true);
        zoomRadioButton->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(zoomRadioButton);

        horizontalSpacer_2a = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2a);

        bySeqNumberCheckBox = new QCheckBox(TCPStreamDialog);
        bySeqNumberCheckBox->setObjectName(QString::fromUtf8("bySeqNumberCheckBox"));
        bySeqNumberCheckBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(bySeqNumberCheckBox);

        showSegLengthCheckBox = new QCheckBox(TCPStreamDialog);
        showSegLengthCheckBox->setObjectName(QString::fromUtf8("showSegLengthCheckBox"));
        showSegLengthCheckBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(showSegLengthCheckBox);

        showThroughputCheckBox = new QCheckBox(TCPStreamDialog);
        showThroughputCheckBox->setObjectName(QString::fromUtf8("showThroughputCheckBox"));
        showThroughputCheckBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(showThroughputCheckBox);

        showGoodputCheckBox = new QCheckBox(TCPStreamDialog);
        showGoodputCheckBox->setObjectName(QString::fromUtf8("showGoodputCheckBox"));
        showGoodputCheckBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(showGoodputCheckBox);

        showRcvWinCheckBox = new QCheckBox(TCPStreamDialog);
        showRcvWinCheckBox->setObjectName(QString::fromUtf8("showRcvWinCheckBox"));
        showRcvWinCheckBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(showRcvWinCheckBox);

        showBytesOutCheckBox = new QCheckBox(TCPStreamDialog);
        showBytesOutCheckBox->setObjectName(QString::fromUtf8("showBytesOutCheckBox"));
        showBytesOutCheckBox->setFocusPolicy(Qt::TabFocus);

        horizontalLayout_2->addWidget(showBytesOutCheckBox);

        horizontalSpacer_2b = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2b);

        resetButton = new QPushButton(TCPStreamDialog);
        resetButton->setObjectName(QString::fromUtf8("resetButton"));

        horizontalLayout_2->addWidget(resetButton);


        verticalLayout->addLayout(horizontalLayout_2);

        buttonBox = new QDialogButtonBox(TCPStreamDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help|QDialogButtonBox::Save);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(TCPStreamDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), TCPStreamDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), TCPStreamDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(TCPStreamDialog);
    } // setupUi

    void retranslateUi(QDialog *TCPStreamDialog)
    {
        TCPStreamDialog->setWindowTitle(QApplication::translate("TCPStreamDialog", "Dialog", nullptr));
        actionReset->setText(QApplication::translate("TCPStreamDialog", "Reset Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionReset->setToolTip(QApplication::translate("TCPStreamDialog", "Reset the graph to its initial state.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionReset->setShortcut(QApplication::translate("TCPStreamDialog", "0", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomIn->setText(QApplication::translate("TCPStreamDialog", "Zoom In", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomIn->setToolTip(QApplication::translate("TCPStreamDialog", "Zoom In", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomIn->setShortcut(QApplication::translate("TCPStreamDialog", "+", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOut->setText(QApplication::translate("TCPStreamDialog", "Zoom Out", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOut->setToolTip(QApplication::translate("TCPStreamDialog", "Zoom Out", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOut->setShortcut(QApplication::translate("TCPStreamDialog", "-", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp10->setText(QApplication::translate("TCPStreamDialog", "Move Up 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp10->setToolTip(QApplication::translate("TCPStreamDialog", "Move Up 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp10->setShortcut(QApplication::translate("TCPStreamDialog", "Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft10->setText(QApplication::translate("TCPStreamDialog", "Move Left 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft10->setToolTip(QApplication::translate("TCPStreamDialog", "Move Left 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft10->setShortcut(QApplication::translate("TCPStreamDialog", "Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight10->setText(QApplication::translate("TCPStreamDialog", "Move Right 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight10->setToolTip(QApplication::translate("TCPStreamDialog", "Move Right 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight10->setShortcut(QApplication::translate("TCPStreamDialog", "Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown10->setText(QApplication::translate("TCPStreamDialog", "Move Down 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown10->setToolTip(QApplication::translate("TCPStreamDialog", "Move Down 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown10->setShortcut(QApplication::translate("TCPStreamDialog", "Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp1->setText(QApplication::translate("TCPStreamDialog", "Move Up 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp1->setToolTip(QApplication::translate("TCPStreamDialog", "Move Up 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp1->setShortcut(QApplication::translate("TCPStreamDialog", "Shift+Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft1->setText(QApplication::translate("TCPStreamDialog", "Move Left 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft1->setToolTip(QApplication::translate("TCPStreamDialog", "Move Left 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft1->setShortcut(QApplication::translate("TCPStreamDialog", "Shift+Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight1->setText(QApplication::translate("TCPStreamDialog", "Move Right 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight1->setToolTip(QApplication::translate("TCPStreamDialog", "Move Right 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight1->setShortcut(QApplication::translate("TCPStreamDialog", "Shift+Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown1->setText(QApplication::translate("TCPStreamDialog", "Move Down 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown1->setToolTip(QApplication::translate("TCPStreamDialog", "Move Down 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown1->setShortcut(QApplication::translate("TCPStreamDialog", "Shift+Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionNextStream->setText(QApplication::translate("TCPStreamDialog", "Next Stream", nullptr));
#ifndef QT_NO_TOOLTIP
        actionNextStream->setToolTip(QApplication::translate("TCPStreamDialog", "Go to the next stream in the capture", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionNextStream->setShortcut(QApplication::translate("TCPStreamDialog", "PgUp", nullptr));
#endif // QT_NO_SHORTCUT
        actionPreviousStream->setText(QApplication::translate("TCPStreamDialog", "Previous Stream", nullptr));
#ifndef QT_NO_TOOLTIP
        actionPreviousStream->setToolTip(QApplication::translate("TCPStreamDialog", "Go to the previous stream in the capture", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionPreviousStream->setShortcut(QApplication::translate("TCPStreamDialog", "PgDown", nullptr));
#endif // QT_NO_SHORTCUT
        actionSwitchDirection->setText(QApplication::translate("TCPStreamDialog", "Switch Direction", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSwitchDirection->setToolTip(QApplication::translate("TCPStreamDialog", "Switch direction (swap TCP endpoints)", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionSwitchDirection->setShortcut(QApplication::translate("TCPStreamDialog", "D", nullptr));
#endif // QT_NO_SHORTCUT
        actionGoToPacket->setText(QApplication::translate("TCPStreamDialog", "Go To Packet Under Cursor", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPacket->setToolTip(QApplication::translate("TCPStreamDialog", "Go to packet currently under the cursor", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToPacket->setShortcut(QApplication::translate("TCPStreamDialog", "G", nullptr));
#endif // QT_NO_SHORTCUT
        actionDragZoom->setText(QApplication::translate("TCPStreamDialog", "Drag / Zoom", nullptr));
#ifndef QT_NO_TOOLTIP
        actionDragZoom->setToolTip(QApplication::translate("TCPStreamDialog", "Toggle mouse drag / zoom behavior", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionDragZoom->setShortcut(QApplication::translate("TCPStreamDialog", "Z", nullptr));
#endif // QT_NO_SHORTCUT
        actionToggleSequenceNumbers->setText(QApplication::translate("TCPStreamDialog", "Relative / Absolute Sequence Numbers", nullptr));
#ifndef QT_NO_TOOLTIP
        actionToggleSequenceNumbers->setToolTip(QApplication::translate("TCPStreamDialog", "Toggle relative / absolute sequence numbers", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionToggleSequenceNumbers->setShortcut(QApplication::translate("TCPStreamDialog", "S", nullptr));
#endif // QT_NO_SHORTCUT
        actionToggleTimeOrigin->setText(QApplication::translate("TCPStreamDialog", "Capture / Session Time Origin", nullptr));
#ifndef QT_NO_TOOLTIP
        actionToggleTimeOrigin->setToolTip(QApplication::translate("TCPStreamDialog", "Toggle capture / session time origin", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionToggleTimeOrigin->setShortcut(QApplication::translate("TCPStreamDialog", "T", nullptr));
#endif // QT_NO_SHORTCUT
        actionCrosshairs->setText(QApplication::translate("TCPStreamDialog", "Crosshairs", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCrosshairs->setToolTip(QApplication::translate("TCPStreamDialog", "Toggle crosshairs", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionCrosshairs->setShortcut(QApplication::translate("TCPStreamDialog", "Space", nullptr));
#endif // QT_NO_SHORTCUT
        actionRoundTripTime->setText(QApplication::translate("TCPStreamDialog", "Round Trip Time", nullptr));
#ifndef QT_NO_TOOLTIP
        actionRoundTripTime->setToolTip(QApplication::translate("TCPStreamDialog", "Switch to the Round Trip Time graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionRoundTripTime->setShortcut(QApplication::translate("TCPStreamDialog", "1", nullptr));
#endif // QT_NO_SHORTCUT
        actionThroughput->setText(QApplication::translate("TCPStreamDialog", "Throughput", nullptr));
#ifndef QT_NO_TOOLTIP
        actionThroughput->setToolTip(QApplication::translate("TCPStreamDialog", "Switch to the Throughput graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionThroughput->setShortcut(QApplication::translate("TCPStreamDialog", "2", nullptr));
#endif // QT_NO_SHORTCUT
        actionStevens->setText(QApplication::translate("TCPStreamDialog", "Time / Sequence (Stevens)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionStevens->setToolTip(QApplication::translate("TCPStreamDialog", "Switch to the Stevens-style Time / Sequence graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionStevens->setShortcut(QApplication::translate("TCPStreamDialog", "3", nullptr));
#endif // QT_NO_SHORTCUT
        actionWindowScaling->setText(QApplication::translate("TCPStreamDialog", "Window Scaling", nullptr));
#ifndef QT_NO_TOOLTIP
        actionWindowScaling->setToolTip(QApplication::translate("TCPStreamDialog", "Switch to the Window Scaling graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionWindowScaling->setShortcut(QApplication::translate("TCPStreamDialog", "5", nullptr));
#endif // QT_NO_SHORTCUT
        actionTcptrace->setText(QApplication::translate("TCPStreamDialog", "Time / Sequence (tcptrace)", nullptr));
#ifndef QT_NO_TOOLTIP
        actionTcptrace->setToolTip(QApplication::translate("TCPStreamDialog", "Switch to the tcptrace-style Time / Sequence graph", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionTcptrace->setShortcut(QApplication::translate("TCPStreamDialog", "4", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomInX->setText(QApplication::translate("TCPStreamDialog", "Zoom In X Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomInX->setToolTip(QApplication::translate("TCPStreamDialog", "Zoom In X Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomInX->setShortcut(QApplication::translate("TCPStreamDialog", "X", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOutX->setText(QApplication::translate("TCPStreamDialog", "Zoom Out X Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOutX->setToolTip(QApplication::translate("TCPStreamDialog", "Zoom Out X Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOutX->setShortcut(QApplication::translate("TCPStreamDialog", "Shift+X", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomInY->setText(QApplication::translate("TCPStreamDialog", "Zoom In Y Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomInY->setToolTip(QApplication::translate("TCPStreamDialog", "Zoom In Y Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomInY->setShortcut(QApplication::translate("TCPStreamDialog", "Y", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOutY->setText(QApplication::translate("TCPStreamDialog", "Zoom Out Y Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOutY->setToolTip(QApplication::translate("TCPStreamDialog", "Zoom Out Y Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOutY->setShortcut(QApplication::translate("TCPStreamDialog", "Shift+Y", nullptr));
#endif // QT_NO_SHORTCUT
#ifndef QT_NO_TOOLTIP
        hintLabel->setToolTip(QApplication::translate("TCPStreamDialog", "<html><head/><body>\n"
"\n"
"<h3>Valuable and amazing time-saving keyboard shortcuts</h3>\n"
"<table><tbody>\n"
"\n"
"<tr><th>+</th><td>Zoom in</td></th>\n"
"<tr><th>-</th><td>Zoom out</td></th>\n"
"<tr><th>x</th><td>Zoom in X axis</td></th>\n"
"<tr><th>X</th><td>Zoom out X axis</td></th>\n"
"<tr><th>y</th><td>Zoom in Y axis</td></th>\n"
"<tr><th>Y</th><td>Zoom out Y axis</td></th>\n"
"<tr><th>0</th><td>Reset graph to its initial state</td></th>\n"
"\n"
"<tr><th>\342\206\222</th><td>Move right 10 pixels</td></th>\n"
"<tr><th>\342\206\220</th><td>Move left 10 pixels</td></th>\n"
"<tr><th>\342\206\221</th><td>Move up 10 pixels</td></th>\n"
"<tr><th>\342\206\223</th><td>Move down 10 pixels</td></th>\n"
"<tr><th><i>Shift+</i>\342\206\222</th><td>Move right 1 pixel</td></th>\n"
"<tr><th><i>Shift+</i>\342\206\220</th><td>Move left 1 pixel</td></th>\n"
"<tr><th><i>Shift+</i>\342\206\221</th><td>Move up 1 pixel</td></th>\n"
"<tr><th><i>Shift+</i>\342\206\223</th><td>Move down 1 pixel</td></th>\n"
"\n"
"<tr><th><i>Pg U"
                        "p</i></th><td>Next stream</td></th>\n"
"<tr><th><i>Pg Dn</i></th><td>Previous stream</td></th>\n"
"<tr><th>d</th><td>Switch direction (swap TCP endpoints)</td></th>\n"
"<tr><th>g</th><td>Go to packet under cursor</td></th>\n"
"\n"
"<tr><th>z</th><td>Toggle mouse drag / zoom</td></th>\n"
"<tr><th>s</th><td>Toggle relative / absolute sequence numbers</td></th>\n"
"<tr><th>t</th><td>Toggle capture / session time origin</td></th>\n"
"<tr><th>Space</th><td>Toggle crosshairs</td></th>\n"
"\n"
"<tr><th>1</th><td>Round Trip Time graph</td></th>\n"
"<tr><th>2</th><td>Throughput graph</td></th>\n"
"<tr><th>3</th><td>Stevens-style Time / Sequence graph</td></th>\n"
"<tr><th>4</th><td>tcptrace-style Time / Sequence graph</td></th>\n"
"<tr><th>5</th><td>Window Scaling graph</td></th>\n"
"\n"
"</tbody></table>\n"
"</body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        hintLabel->setText(QApplication::translate("TCPStreamDialog", "<small><i>Mouse over for shortcuts</i></small>", nullptr));
        label->setText(QApplication::translate("TCPStreamDialog", "Type", nullptr));
        maWindowSizeLabel->setText(QApplication::translate("TCPStreamDialog", "MA Window (s)", nullptr));
#ifndef QT_NO_TOOLTIP
        selectSACKsCheckBox->setToolTip(QApplication::translate("TCPStreamDialog", "Allow SACK segments as well as data packets to be selected by clicking on the graph", nullptr));
#endif // QT_NO_TOOLTIP
        selectSACKsCheckBox->setText(QApplication::translate("TCPStreamDialog", "Select SACKs", nullptr));
        streamNumberLabel->setText(QApplication::translate("TCPStreamDialog", "Stream", nullptr));
#ifndef QT_NO_TOOLTIP
        otherDirectionButton->setToolTip(QApplication::translate("TCPStreamDialog", "<html><head/><body><p>Switch the direction of the connection (view the opposite flow).</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        otherDirectionButton->setText(QApplication::translate("TCPStreamDialog", "Switch Direction", nullptr));
        mouseLabel->setText(QApplication::translate("TCPStreamDialog", "Mouse", nullptr));
#ifndef QT_NO_TOOLTIP
        dragRadioButton->setToolTip(QApplication::translate("TCPStreamDialog", "Drag using the mouse button.", nullptr));
#endif // QT_NO_TOOLTIP
        dragRadioButton->setText(QApplication::translate("TCPStreamDialog", "drags", nullptr));
#ifndef QT_NO_TOOLTIP
        zoomRadioButton->setToolTip(QApplication::translate("TCPStreamDialog", "Select using the mouse button.", nullptr));
#endif // QT_NO_TOOLTIP
        zoomRadioButton->setText(QApplication::translate("TCPStreamDialog", "zooms", nullptr));
#ifndef QT_NO_TOOLTIP
        bySeqNumberCheckBox->setToolTip(QApplication::translate("TCPStreamDialog", "Display Round Trip Time vs Sequence Number", nullptr));
#endif // QT_NO_TOOLTIP
        bySeqNumberCheckBox->setText(QApplication::translate("TCPStreamDialog", "RTT By Sequence Number", nullptr));
#ifndef QT_NO_TOOLTIP
        showSegLengthCheckBox->setToolTip(QApplication::translate("TCPStreamDialog", "Display graph of Segment Length vs Time", nullptr));
#endif // QT_NO_TOOLTIP
        showSegLengthCheckBox->setText(QApplication::translate("TCPStreamDialog", "Segment Length", nullptr));
#ifndef QT_NO_TOOLTIP
        showThroughputCheckBox->setToolTip(QApplication::translate("TCPStreamDialog", "Display graph of Mean Transmitted Bytes vs Time", nullptr));
#endif // QT_NO_TOOLTIP
        showThroughputCheckBox->setText(QApplication::translate("TCPStreamDialog", "Throughput", nullptr));
#ifndef QT_NO_TOOLTIP
        showGoodputCheckBox->setToolTip(QApplication::translate("TCPStreamDialog", "Display graph of Mean ACKed Bytes vs Time", nullptr));
#endif // QT_NO_TOOLTIP
        showGoodputCheckBox->setText(QApplication::translate("TCPStreamDialog", "Goodput", nullptr));
#ifndef QT_NO_TOOLTIP
        showRcvWinCheckBox->setToolTip(QApplication::translate("TCPStreamDialog", "Display graph of Receive Window Size vs Time", nullptr));
#endif // QT_NO_TOOLTIP
        showRcvWinCheckBox->setText(QApplication::translate("TCPStreamDialog", "Rcv Win", nullptr));
#ifndef QT_NO_TOOLTIP
        showBytesOutCheckBox->setToolTip(QApplication::translate("TCPStreamDialog", "Display graph of Outstanding Bytes vs Time", nullptr));
#endif // QT_NO_TOOLTIP
        showBytesOutCheckBox->setText(QApplication::translate("TCPStreamDialog", "Bytes Out", nullptr));
#ifndef QT_NO_TOOLTIP
        resetButton->setToolTip(QApplication::translate("TCPStreamDialog", "<html><head/><body><p>Reset the graph to its initial state.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        resetButton->setText(QApplication::translate("TCPStreamDialog", "Reset", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TCPStreamDialog: public Ui_TCPStreamDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TCP_STREAM_DIALOG_H
