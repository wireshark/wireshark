/********************************************************************************
** Form generated from reading UI file 'io_graph_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_IO_GRAPH_DIALOG_H
#define UI_IO_GRAPH_DIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"
#include "widgets/qcustomplot.h"
#include "widgets/tabnav_tree_view.h"

QT_BEGIN_NAMESPACE

class Ui_IOGraphDialog
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
    QAction *actionDragZoom;
    QAction *actionToggleTimeOrigin;
    QAction *actionCrosshairs;
    QAction *actionZoomInX;
    QAction *actionZoomOutX;
    QAction *actionZoomInY;
    QAction *actionZoomOutY;
    QVBoxLayout *verticalLayout;
    QCustomPlot *ioPlot;
    ElidedLabel *hintLabel;
    TabnavTreeView *graphUat;
    QHBoxLayout *horizontalLayout;
    QToolButton *newToolButton;
    QToolButton *deleteToolButton;
    QToolButton *copyToolButton;
    QToolButton *clearToolButton;
    QSpacerItem *horizontalSpacer_4;
    QLabel *mouseLabel;
    QRadioButton *dragRadioButton;
    QRadioButton *zoomRadioButton;
    QSpacerItem *horizontalSpacer_3;
    QLabel *label_2;
    QComboBox *intervalComboBox;
    QSpacerItem *horizontalSpacer_2;
    QCheckBox *todCheckBox;
    QSpacerItem *horizontalSpacer_5;
    QCheckBox *logCheckBox;
    QSpacerItem *horizontalSpacer;
    QPushButton *resetButton;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *IOGraphDialog)
    {
        if (IOGraphDialog->objectName().isEmpty())
            IOGraphDialog->setObjectName(QString::fromUtf8("IOGraphDialog"));
        IOGraphDialog->resize(850, 640);
        actionReset = new QAction(IOGraphDialog);
        actionReset->setObjectName(QString::fromUtf8("actionReset"));
        actionZoomIn = new QAction(IOGraphDialog);
        actionZoomIn->setObjectName(QString::fromUtf8("actionZoomIn"));
        actionZoomOut = new QAction(IOGraphDialog);
        actionZoomOut->setObjectName(QString::fromUtf8("actionZoomOut"));
        actionMoveUp10 = new QAction(IOGraphDialog);
        actionMoveUp10->setObjectName(QString::fromUtf8("actionMoveUp10"));
        actionMoveLeft10 = new QAction(IOGraphDialog);
        actionMoveLeft10->setObjectName(QString::fromUtf8("actionMoveLeft10"));
        actionMoveRight10 = new QAction(IOGraphDialog);
        actionMoveRight10->setObjectName(QString::fromUtf8("actionMoveRight10"));
        actionMoveDown10 = new QAction(IOGraphDialog);
        actionMoveDown10->setObjectName(QString::fromUtf8("actionMoveDown10"));
        actionMoveUp1 = new QAction(IOGraphDialog);
        actionMoveUp1->setObjectName(QString::fromUtf8("actionMoveUp1"));
        actionMoveLeft1 = new QAction(IOGraphDialog);
        actionMoveLeft1->setObjectName(QString::fromUtf8("actionMoveLeft1"));
        actionMoveRight1 = new QAction(IOGraphDialog);
        actionMoveRight1->setObjectName(QString::fromUtf8("actionMoveRight1"));
        actionMoveDown1 = new QAction(IOGraphDialog);
        actionMoveDown1->setObjectName(QString::fromUtf8("actionMoveDown1"));
        actionGoToPacket = new QAction(IOGraphDialog);
        actionGoToPacket->setObjectName(QString::fromUtf8("actionGoToPacket"));
        actionDragZoom = new QAction(IOGraphDialog);
        actionDragZoom->setObjectName(QString::fromUtf8("actionDragZoom"));
        actionToggleTimeOrigin = new QAction(IOGraphDialog);
        actionToggleTimeOrigin->setObjectName(QString::fromUtf8("actionToggleTimeOrigin"));
        actionCrosshairs = new QAction(IOGraphDialog);
        actionCrosshairs->setObjectName(QString::fromUtf8("actionCrosshairs"));
        actionZoomInX = new QAction(IOGraphDialog);
        actionZoomInX->setObjectName(QString::fromUtf8("actionZoomInX"));
        actionZoomOutX = new QAction(IOGraphDialog);
        actionZoomOutX->setObjectName(QString::fromUtf8("actionZoomOutX"));
        actionZoomInY = new QAction(IOGraphDialog);
        actionZoomInY->setObjectName(QString::fromUtf8("actionZoomInY"));
        actionZoomOutY = new QAction(IOGraphDialog);
        actionZoomOutY->setObjectName(QString::fromUtf8("actionZoomOutY"));
        verticalLayout = new QVBoxLayout(IOGraphDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        ioPlot = new QCustomPlot(IOGraphDialog);
        ioPlot->setObjectName(QString::fromUtf8("ioPlot"));
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(4);
        sizePolicy.setHeightForWidth(ioPlot->sizePolicy().hasHeightForWidth());
        ioPlot->setSizePolicy(sizePolicy);

        verticalLayout->addWidget(ioPlot);

        hintLabel = new ElidedLabel(IOGraphDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));

        verticalLayout->addWidget(hintLabel);

        graphUat = new TabnavTreeView(IOGraphDialog);
        graphUat->setObjectName(QString::fromUtf8("graphUat"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(1);
        sizePolicy1.setHeightForWidth(graphUat->sizePolicy().hasHeightForWidth());
        graphUat->setSizePolicy(sizePolicy1);

        verticalLayout->addWidget(graphUat);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        newToolButton = new QToolButton(IOGraphDialog);
        newToolButton->setObjectName(QString::fromUtf8("newToolButton"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/stock/plus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        newToolButton->setIcon(icon);

        horizontalLayout->addWidget(newToolButton);

        deleteToolButton = new QToolButton(IOGraphDialog);
        deleteToolButton->setObjectName(QString::fromUtf8("deleteToolButton"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/stock/minus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        deleteToolButton->setIcon(icon1);

        horizontalLayout->addWidget(deleteToolButton);

        copyToolButton = new QToolButton(IOGraphDialog);
        copyToolButton->setObjectName(QString::fromUtf8("copyToolButton"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/stock/copy-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        copyToolButton->setIcon(icon2);

        horizontalLayout->addWidget(copyToolButton);

        clearToolButton = new QToolButton(IOGraphDialog);
        clearToolButton->setObjectName(QString::fromUtf8("clearToolButton"));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/stock/delete_list.png"), QSize(), QIcon::Normal, QIcon::Off);
        clearToolButton->setIcon(icon3);
        clearToolButton->setEnabled(false);

        horizontalLayout->addWidget(clearToolButton);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_4);

        mouseLabel = new QLabel(IOGraphDialog);
        mouseLabel->setObjectName(QString::fromUtf8("mouseLabel"));

        horizontalLayout->addWidget(mouseLabel);

        dragRadioButton = new QRadioButton(IOGraphDialog);
        dragRadioButton->setObjectName(QString::fromUtf8("dragRadioButton"));
        dragRadioButton->setCheckable(true);

        horizontalLayout->addWidget(dragRadioButton);

        zoomRadioButton = new QRadioButton(IOGraphDialog);
        zoomRadioButton->setObjectName(QString::fromUtf8("zoomRadioButton"));
        zoomRadioButton->setCheckable(true);

        horizontalLayout->addWidget(zoomRadioButton);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        label_2 = new QLabel(IOGraphDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        horizontalLayout->addWidget(label_2);

        intervalComboBox = new QComboBox(IOGraphDialog);
        intervalComboBox->setObjectName(QString::fromUtf8("intervalComboBox"));

        horizontalLayout->addWidget(intervalComboBox);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        todCheckBox = new QCheckBox(IOGraphDialog);
        todCheckBox->setObjectName(QString::fromUtf8("todCheckBox"));

        horizontalLayout->addWidget(todCheckBox);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_5);

        logCheckBox = new QCheckBox(IOGraphDialog);
        logCheckBox->setObjectName(QString::fromUtf8("logCheckBox"));

        horizontalLayout->addWidget(logCheckBox);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        resetButton = new QPushButton(IOGraphDialog);
        resetButton->setObjectName(QString::fromUtf8("resetButton"));

        horizontalLayout->addWidget(resetButton);


        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(IOGraphDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help|QDialogButtonBox::Save);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(IOGraphDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), IOGraphDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), IOGraphDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(IOGraphDialog);
    } // setupUi

    void retranslateUi(QDialog *IOGraphDialog)
    {
        IOGraphDialog->setWindowTitle(QApplication::translate("IOGraphDialog", "Dialog", nullptr));
        actionReset->setText(QApplication::translate("IOGraphDialog", "Reset Graph", nullptr));
#ifndef QT_NO_TOOLTIP
        actionReset->setToolTip(QApplication::translate("IOGraphDialog", "Reset the graph to its initial state.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionReset->setShortcut(QApplication::translate("IOGraphDialog", "0", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomIn->setText(QApplication::translate("IOGraphDialog", "Zoom In", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomIn->setToolTip(QApplication::translate("IOGraphDialog", "Zoom In", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomIn->setShortcut(QApplication::translate("IOGraphDialog", "+", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOut->setText(QApplication::translate("IOGraphDialog", "Zoom Out", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOut->setToolTip(QApplication::translate("IOGraphDialog", "Zoom Out", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOut->setShortcut(QApplication::translate("IOGraphDialog", "-", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp10->setText(QApplication::translate("IOGraphDialog", "Move Up 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp10->setToolTip(QApplication::translate("IOGraphDialog", "Move Up 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp10->setShortcut(QApplication::translate("IOGraphDialog", "Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft10->setText(QApplication::translate("IOGraphDialog", "Move Left 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft10->setToolTip(QApplication::translate("IOGraphDialog", "Move Left 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft10->setShortcut(QApplication::translate("IOGraphDialog", "Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight10->setText(QApplication::translate("IOGraphDialog", "Move Right 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight10->setToolTip(QApplication::translate("IOGraphDialog", "Move Right 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight10->setShortcut(QApplication::translate("IOGraphDialog", "Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown10->setText(QApplication::translate("IOGraphDialog", "Move Down 10 Pixels", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown10->setToolTip(QApplication::translate("IOGraphDialog", "Move Down 10 Pixels", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown10->setShortcut(QApplication::translate("IOGraphDialog", "Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveUp1->setText(QApplication::translate("IOGraphDialog", "Move Up 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveUp1->setToolTip(QApplication::translate("IOGraphDialog", "Move Up 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveUp1->setShortcut(QApplication::translate("IOGraphDialog", "Shift+Up", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveLeft1->setText(QApplication::translate("IOGraphDialog", "Move Left 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveLeft1->setToolTip(QApplication::translate("IOGraphDialog", "Move Left 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveLeft1->setShortcut(QApplication::translate("IOGraphDialog", "Shift+Left", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveRight1->setText(QApplication::translate("IOGraphDialog", "Move Right 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveRight1->setToolTip(QApplication::translate("IOGraphDialog", "Move Right 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveRight1->setShortcut(QApplication::translate("IOGraphDialog", "Shift+Right", nullptr));
#endif // QT_NO_SHORTCUT
        actionMoveDown1->setText(QApplication::translate("IOGraphDialog", "Move Down 1 Pixel", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMoveDown1->setToolTip(QApplication::translate("IOGraphDialog", "Move down 1 Pixel", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMoveDown1->setShortcut(QApplication::translate("IOGraphDialog", "Shift+Down", nullptr));
#endif // QT_NO_SHORTCUT
        actionGoToPacket->setText(QApplication::translate("IOGraphDialog", "Go To Packet Under Cursor", nullptr));
#ifndef QT_NO_TOOLTIP
        actionGoToPacket->setToolTip(QApplication::translate("IOGraphDialog", "Go to packet currently under the cursor", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionGoToPacket->setShortcut(QApplication::translate("IOGraphDialog", "G", nullptr));
#endif // QT_NO_SHORTCUT
        actionDragZoom->setText(QApplication::translate("IOGraphDialog", "Drag / Zoom", nullptr));
#ifndef QT_NO_TOOLTIP
        actionDragZoom->setToolTip(QApplication::translate("IOGraphDialog", "Toggle mouse drag / zoom behavior", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionDragZoom->setShortcut(QApplication::translate("IOGraphDialog", "Z", nullptr));
#endif // QT_NO_SHORTCUT
        actionToggleTimeOrigin->setText(QApplication::translate("IOGraphDialog", "Capture / Session Time Origin", nullptr));
#ifndef QT_NO_TOOLTIP
        actionToggleTimeOrigin->setToolTip(QApplication::translate("IOGraphDialog", "Toggle capture / session time origin", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionToggleTimeOrigin->setShortcut(QApplication::translate("IOGraphDialog", "T", nullptr));
#endif // QT_NO_SHORTCUT
        actionCrosshairs->setText(QApplication::translate("IOGraphDialog", "Crosshairs", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCrosshairs->setToolTip(QApplication::translate("IOGraphDialog", "Toggle crosshairs", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionCrosshairs->setShortcut(QApplication::translate("IOGraphDialog", "Space", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomInX->setText(QApplication::translate("IOGraphDialog", "Zoom In X Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomInX->setToolTip(QApplication::translate("IOGraphDialog", "Zoom In X Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomInX->setShortcut(QApplication::translate("IOGraphDialog", "X", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOutX->setText(QApplication::translate("IOGraphDialog", "Zoom Out X Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOutX->setToolTip(QApplication::translate("IOGraphDialog", "Zoom Out X Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOutX->setShortcut(QApplication::translate("IOGraphDialog", "Shift+X", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomInY->setText(QApplication::translate("IOGraphDialog", "Zoom In Y Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomInY->setToolTip(QApplication::translate("IOGraphDialog", "Zoom In Y Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomInY->setShortcut(QApplication::translate("IOGraphDialog", "Y", nullptr));
#endif // QT_NO_SHORTCUT
        actionZoomOutY->setText(QApplication::translate("IOGraphDialog", "Zoom Out Y Axis", nullptr));
#ifndef QT_NO_TOOLTIP
        actionZoomOutY->setToolTip(QApplication::translate("IOGraphDialog", "Zoom Out Y Axis", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionZoomOutY->setShortcut(QApplication::translate("IOGraphDialog", "Shift+Y", nullptr));
#endif // QT_NO_SHORTCUT
#ifndef QT_NO_TOOLTIP
        hintLabel->setToolTip(QApplication::translate("IOGraphDialog", "<html><head/><body>\n"
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
"<tr><th>g</th><"
                        "td>Go to packet under cursor</td></th>\n"
"\n"
"<tr><th>z</th><td>Toggle mouse drag / zoom</td></th>\n"
"<tr><th>t</th><td>Toggle capture / session time origin</td></th>\n"
"<tr><th>Space</th><td>Toggle crosshairs</td></th>\n"
"\n"
"</tbody></table>\n"
"</body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        hintLabel->setText(QString());
#ifndef QT_NO_TOOLTIP
        newToolButton->setToolTip(QApplication::translate("IOGraphDialog", "Add a new graph.", nullptr));
#endif // QT_NO_TOOLTIP
        newToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        deleteToolButton->setToolTip(QApplication::translate("IOGraphDialog", "Remove this graph.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        copyToolButton->setToolTip(QApplication::translate("IOGraphDialog", "Duplicate this graph.", nullptr));
#endif // QT_NO_TOOLTIP
        copyToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        clearToolButton->setToolTip(QApplication::translate("IOGraphDialog", "Clear all graphs.", nullptr));
#endif // QT_NO_TOOLTIP
        mouseLabel->setText(QApplication::translate("IOGraphDialog", "Mouse", nullptr));
#ifndef QT_NO_TOOLTIP
        dragRadioButton->setToolTip(QApplication::translate("IOGraphDialog", "Drag using the mouse button.", nullptr));
#endif // QT_NO_TOOLTIP
        dragRadioButton->setText(QApplication::translate("IOGraphDialog", "drags", nullptr));
#ifndef QT_NO_TOOLTIP
        zoomRadioButton->setToolTip(QApplication::translate("IOGraphDialog", "Select using the mouse button.", nullptr));
#endif // QT_NO_TOOLTIP
        zoomRadioButton->setText(QApplication::translate("IOGraphDialog", "zooms", nullptr));
        label_2->setText(QApplication::translate("IOGraphDialog", "Interval", nullptr));
        todCheckBox->setText(QApplication::translate("IOGraphDialog", "Time of day", nullptr));
        logCheckBox->setText(QApplication::translate("IOGraphDialog", "Log scale", nullptr));
        resetButton->setText(QApplication::translate("IOGraphDialog", "Reset", nullptr));
    } // retranslateUi

};

namespace Ui {
    class IOGraphDialog: public Ui_IOGraphDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_IO_GRAPH_DIALOG_H
