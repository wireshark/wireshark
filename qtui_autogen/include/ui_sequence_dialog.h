/********************************************************************************
** Form generated from reading UI file 'sequence_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SEQUENCE_DIALOG_H
#define UI_SEQUENCE_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"
#include "widgets/qcustomplot.h"

QT_BEGIN_NAMESPACE

class Ui_SequenceDialog
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
    QAction *actionGoToPacket;
    QAction *actionFlowAny;
    QAction *actionFlowTcp;
    QAction *actionGoToNextPacket;
    QAction *actionGoToPreviousPacket;
    QVBoxLayout *verticalLayout_2;
    QGridLayout *gridLayout;
    QCustomPlot *sequencePlot;
    QScrollBar *verticalScrollBar;
    QScrollBar *horizontalScrollBar;
    QFrame *frame;
    ElidedLabel *hintLabel;
    QFrame *controlFrame;
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout_2;
    QCheckBox *displayFilterCheckBox;
    QSpacerItem *horizontalSpacer;
    QLabel *flowLabel;
    QComboBox *flowComboBox;
    QSpacerItem *horizontalSpacer_2;
    QLabel *label_3;
    QComboBox *addressComboBox;
    QHBoxLayout *horizontalLayout;
    QSpacerItem *horizontalSpacer_3;
    QPushButton *resetButton;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *SequenceDialog)
    {
        if (SequenceDialog->objectName().isEmpty())
            SequenceDialog->setObjectName(QString::fromUtf8("SequenceDialog"));
        SequenceDialog->resize(679, 568);
        actionReset = new QAction(SequenceDialog);
        actionReset->setObjectName(QString::fromUtf8("actionReset"));
        actionZoomIn = new QAction(SequenceDialog);
        actionZoomIn->setObjectName(QString::fromUtf8("actionZoomIn"));
        actionZoomOut = new QAction(SequenceDialog);
        actionZoomOut->setObjectName(QString::fromUtf8("actionZoomOut"));
        actionMoveUp10 = new QAction(SequenceDialog);
        actionMoveUp10->setObjectName(QString::fromUtf8("actionMoveUp10"));
        actionMoveLeft10 = new QAction(SequenceDialog);
        actionMoveLeft10->setObjectName(QString::fromUtf8("actionMoveLeft10"));
        actionMoveRight10 = new QAction(SequenceDialog);
        actionMoveRight10->setObjectName(QString::fromUtf8("actionMoveRight10"));
        actionMoveDown10 = new QAction(SequenceDialog);
        actionMoveDown10->setObjectName(QString::fromUtf8("actionMoveDown10"));
        actionMoveUp1 = new QAction(SequenceDialog);
        actionMoveUp1->setObjectName(QString::fromUtf8("actionMoveUp1"));
        actionMoveLeft1 = new QAction(SequenceDialog);
        actionMoveLeft1->setObjectName(QString::fromUtf8("actionMoveLeft1"));
        actionMoveRight1 = new QAction(SequenceDialog);
        actionMoveRight1->setObjectName(QString::fromUtf8("actionMoveRight1"));
        actionMoveDown1 = new QAction(SequenceDialog);
        actionMoveDown1->setObjectName(QString::fromUtf8("actionMoveDown1"));
        actionGoToPacket = new QAction(SequenceDialog);
        actionGoToPacket->setObjectName(QString::fromUtf8("actionGoToPacket"));
        actionFlowAny = new QAction(SequenceDialog);
        actionFlowAny->setObjectName(QString::fromUtf8("actionFlowAny"));
        actionFlowTcp = new QAction(SequenceDialog);
        actionFlowTcp->setObjectName(QString::fromUtf8("actionFlowTcp"));
        actionGoToNextPacket = new QAction(SequenceDialog);
        actionGoToNextPacket->setObjectName(QString::fromUtf8("actionGoToNextPacket"));
        actionGoToPreviousPacket = new QAction(SequenceDialog);
        actionGoToPreviousPacket->setObjectName(QString::fromUtf8("actionGoToPreviousPacket"));
        verticalLayout_2 = new QVBoxLayout(SequenceDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        sequencePlot = new QCustomPlot(SequenceDialog);
        sequencePlot->setObjectName(QString::fromUtf8("sequencePlot"));
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(1);
        sizePolicy.setHeightForWidth(sequencePlot->sizePolicy().hasHeightForWidth());
        sequencePlot->setSizePolicy(sizePolicy);

        gridLayout->addWidget(sequencePlot, 0, 0, 1, 1);

        verticalScrollBar = new QScrollBar(SequenceDialog);
        verticalScrollBar->setObjectName(QString::fromUtf8("verticalScrollBar"));
        verticalScrollBar->setOrientation(Qt::Vertical);

        gridLayout->addWidget(verticalScrollBar, 0, 1, 1, 1);

        horizontalScrollBar = new QScrollBar(SequenceDialog);
        horizontalScrollBar->setObjectName(QString::fromUtf8("horizontalScrollBar"));
        horizontalScrollBar->setOrientation(Qt::Horizontal);

        gridLayout->addWidget(horizontalScrollBar, 1, 0, 1, 1);

        frame = new QFrame(SequenceDialog);
        frame->setObjectName(QString::fromUtf8("frame"));

        gridLayout->addWidget(frame, 1, 1, 1, 1);


        verticalLayout_2->addLayout(gridLayout);

        hintLabel = new ElidedLabel(SequenceDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));

        verticalLayout_2->addWidget(hintLabel);

        controlFrame = new QFrame(SequenceDialog);
        controlFrame->setObjectName(QString::fromUtf8("controlFrame"));
        controlFrame->setFrameShape(QFrame::NoFrame);
        controlFrame->setFrameShadow(QFrame::Plain);
        controlFrame->setLineWidth(0);
        verticalLayout = new QVBoxLayout(controlFrame);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        displayFilterCheckBox = new QCheckBox(controlFrame);
        displayFilterCheckBox->setObjectName(QString::fromUtf8("displayFilterCheckBox"));

        horizontalLayout_2->addWidget(displayFilterCheckBox);

        horizontalSpacer = new QSpacerItem(13, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        flowLabel = new QLabel(controlFrame);
        flowLabel->setObjectName(QString::fromUtf8("flowLabel"));

        horizontalLayout_2->addWidget(flowLabel);

        flowComboBox = new QComboBox(controlFrame);
        flowComboBox->setObjectName(QString::fromUtf8("flowComboBox"));

        horizontalLayout_2->addWidget(flowComboBox);

        horizontalSpacer_2 = new QSpacerItem(13, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);

        label_3 = new QLabel(controlFrame);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        horizontalLayout_2->addWidget(label_3);

        addressComboBox = new QComboBox(controlFrame);
        addressComboBox->addItem(QString());
        addressComboBox->addItem(QString());
        addressComboBox->setObjectName(QString::fromUtf8("addressComboBox"));

        horizontalLayout_2->addWidget(addressComboBox);


        verticalLayout->addLayout(horizontalLayout_2);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        resetButton = new QPushButton(controlFrame);
        resetButton->setObjectName(QString::fromUtf8("resetButton"));

        horizontalLayout->addWidget(resetButton);


        verticalLayout->addLayout(horizontalLayout);


        verticalLayout_2->addWidget(controlFrame);

        buttonBox = new QDialogButtonBox(SequenceDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help|QDialogButtonBox::Save);

        verticalLayout_2->addWidget(buttonBox);

        verticalLayout_2->setStretch(0, 1);

        retranslateUi(SequenceDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), SequenceDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), SequenceDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(SequenceDialog);
    } // setupUi

    void retranslateUi(QDialog *SequenceDialog)
    {
        actionReset->setText(QApplication::translate("SequenceDialog", "Reset Diagram", nullptr));
#ifndef QT_NO_TOOLTIP
        actionReset->setToolTip(QApplication::translate("SequenceDialog", "Reset the diagram to its initial state.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionReset->setShortcut(QApplication::translate("SequenceDialog", "0", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomIn->setText(QApplication::translate("SequenceDialog", "Zoom In", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomIn->setToolTip(QApplication::translate("SequenceDialog", "Zoom In", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomIn->setShortcut(QApplication::translate("SequenceDialog", "+", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOut->setText(QApplication::translate("SequenceDialog", "Zoom Out", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOut->setToolTip(QApplication::translate("SequenceDialog", "Zoom Out", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOut->setShortcut(QApplication::translate("SequenceDialog", "-", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp10->setText(QApplication::translate("SequenceDialog", "Move Up 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp10->setToolTip(QApplication::translate("SequenceDialog", "Move Up 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp10->setShortcut(QApplication::translate("SequenceDialog", "Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft10->setText(QApplication::translate("SequenceDialog", "Move Left 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft10->setToolTip(QApplication::translate("SequenceDialog", "Move Left 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft10->setShortcut(QApplication::translate("SequenceDialog", "Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight10->setText(QApplication::translate("SequenceDialog", "Move Right 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight10->setToolTip(QApplication::translate("SequenceDialog", "Move Right 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight10->setShortcut(QApplication::translate("SequenceDialog", "Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown10->setText(QApplication::translate("SequenceDialog", "Move Down 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown10->setToolTip(QApplication::translate("SequenceDialog", "Move Down 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown10->setShortcut(QApplication::translate("SequenceDialog", "Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp1->setText(QApplication::translate("SequenceDialog", "Move Up 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp1->setToolTip(QApplication::translate("SequenceDialog", "Move Up 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp1->setShortcut(QApplication::translate("SequenceDialog", "Shift+Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft1->setText(QApplication::translate("SequenceDialog", "Move Left 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft1->setToolTip(QApplication::translate("SequenceDialog", "Move Left 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft1->setShortcut(QApplication::translate("SequenceDialog", "Shift+Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight1->setText(QApplication::translate("SequenceDialog", "Move Right 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight1->setToolTip(QApplication::translate("SequenceDialog", "Move Right 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight1->setShortcut(QApplication::translate("SequenceDialog", "Shift+Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown1->setText(QApplication::translate("SequenceDialog", "Move Down 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown1->setToolTip(QApplication::translate("SequenceDialog", "Move Down 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown1->setShortcut(QApplication::translate("SequenceDialog", "Shift+Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionGoToPacket->setText(QApplication::translate("SequenceDialog", "Go To Packet Under Cursor", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPacket->setToolTip(QApplication::translate("SequenceDialog", "Go to packet currently under the cursor", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToPacket->setShortcut(QApplication::translate("SequenceDialog", "G", nullptr));
#endif // QT_NO_SHORTCUT
        actionFlowAny->setText(QApplication::translate("SequenceDialog", "All Flows", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFlowAny->setToolTip(QApplication::translate("SequenceDialog", "Show flows for all packets", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionFlowAny->setShortcut(QApplication::translate("SequenceDialog", "1", nullptr));
#endif // QT_NO_SHORTCUT
        actionFlowTcp->setText(QApplication::translate("SequenceDialog", "TCP Flows", nullptr));
#ifndef QT_NO_TOOLTIP
        actionFlowTcp->setToolTip(QApplication::translate("SequenceDialog", "Show only TCP flow information", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionFlowTcp->setShortcut(QApplication::translate("SequenceDialog", "1", nullptr));
#endif // QT_NO_SHORTCUT
        actionGoToNextPacket->setText(QApplication::translate("SequenceDialog", "Go To Next Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToNextPacket->setToolTip(QApplication::translate("SequenceDialog", "Go to the next packet", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToNextPacket->setShortcut(QApplication::translate("SequenceDialog", "N", nullptr));
#endif // QT_NO_SHORTCUT
        actionGoToPreviousPacket->setText(QApplication::translate("SequenceDialog", "Go To Previous Packet", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPreviousPacket->setToolTip(QApplication::translate("SequenceDialog", "Go to the previous packet", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToPreviousPacket->setShortcut(QApplication::translate("SequenceDialog", "P", nullptr));
#endif // QT_NO_SHORTCUT
#ifndef QT_NO_TOOLTIP
        hintLabel->setToolTip(QApplication::translate("SequenceDialog", "<html><head/><body>\n"
"\n"
"<h3>Valuable and amazing time-saving keyboard shortcuts</h3>\n"
"<table><tbody>\n"
"\n"
"<tr><th>+</th><td>Zoom in</td></th>\n"
"<tr><th>-</th><td>Zoom out</td></th>\n"
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
"<tr><th>g</th><td>Go to packet under cursor</td></th>\n"
"<tr><th>n</th><td>Go to the next packet</td></th>\n"
"<tr><th>p</th><td>Go to the previous packet</td></th>\n"
"\n"
"</tbody></table>\n"
"</body></"
                        "html>", nullptr));
#endif // QT_NO_TOOLTIP
        hintLabel->setText(QApplication::translate("SequenceDialog", "<small><i>A hint</i></small>", nullptr));
#ifndef QT_NO_TOOLTIP
        displayFilterCheckBox->setToolTip(QApplication::translate("SequenceDialog", "<html><head/><body><p>Only show flows matching the current display filter</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        displayFilterCheckBox->setText(QApplication::translate("SequenceDialog", "Limit to display filter", nullptr));
        flowLabel->setText(QApplication::translate("SequenceDialog", "Flow type:", nullptr));
        label_3->setText(QApplication::translate("SequenceDialog", "Addresses:", nullptr));
        addressComboBox->setItemText(0, QApplication::translate("SequenceDialog", "Any", nullptr));
        addressComboBox->setItemText(1, QApplication::translate("SequenceDialog", "Network", nullptr));

        resetButton->setText(QApplication::translate("SequenceDialog", "Reset", nullptr));
        Q_UNUSED(SequenceDialog);
    } // retranslateUi

};

namespace Ui {
    class SequenceDialog: public Ui_SequenceDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SEQUENCE_DIALOG_H
