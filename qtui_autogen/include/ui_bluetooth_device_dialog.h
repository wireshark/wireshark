/********************************************************************************
** Form generated from reading UI file 'bluetooth_device_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_BLUETOOTH_DEVICE_DIALOG_H
#define UI_BLUETOOTH_DEVICE_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_BluetoothDeviceDialog
{
public:
    QAction *actionCopy_Cell;
    QAction *actionCopy_Rows;
    QAction *actionCopy_All;
    QAction *actionSave_as_image;
    QAction *actionMark_Unmark_Row;
    QAction *actionMark_Unmark_Cell;
    QVBoxLayout *verticalLayout;
    QTableWidget *tableWidget;
    QLabel *hintLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *BluetoothDeviceDialog)
    {
        if (BluetoothDeviceDialog->objectName().isEmpty())
            BluetoothDeviceDialog->setObjectName(QString::fromUtf8("BluetoothDeviceDialog"));
        BluetoothDeviceDialog->resize(544, 679);
        BluetoothDeviceDialog->setBaseSize(QSize(0, 0));
        BluetoothDeviceDialog->setContextMenuPolicy(Qt::CustomContextMenu);
        actionCopy_Cell = new QAction(BluetoothDeviceDialog);
        actionCopy_Cell->setObjectName(QString::fromUtf8("actionCopy_Cell"));
        actionCopy_Rows = new QAction(BluetoothDeviceDialog);
        actionCopy_Rows->setObjectName(QString::fromUtf8("actionCopy_Rows"));
        actionCopy_All = new QAction(BluetoothDeviceDialog);
        actionCopy_All->setObjectName(QString::fromUtf8("actionCopy_All"));
        actionSave_as_image = new QAction(BluetoothDeviceDialog);
        actionSave_as_image->setObjectName(QString::fromUtf8("actionSave_as_image"));
        actionMark_Unmark_Row = new QAction(BluetoothDeviceDialog);
        actionMark_Unmark_Row->setObjectName(QString::fromUtf8("actionMark_Unmark_Row"));
        actionMark_Unmark_Cell = new QAction(BluetoothDeviceDialog);
        actionMark_Unmark_Cell->setObjectName(QString::fromUtf8("actionMark_Unmark_Cell"));
        verticalLayout = new QVBoxLayout(BluetoothDeviceDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        tableWidget = new QTableWidget(BluetoothDeviceDialog);
        if (tableWidget->columnCount() < 2)
            tableWidget->setColumnCount(2);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(0, __qtablewidgetitem);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        tableWidget->setHorizontalHeaderItem(1, __qtablewidgetitem1);
        if (tableWidget->rowCount() < 22)
            tableWidget->setRowCount(22);
        QTableWidgetItem *__qtablewidgetitem2 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(0, __qtablewidgetitem2);
        QTableWidgetItem *__qtablewidgetitem3 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(1, __qtablewidgetitem3);
        QTableWidgetItem *__qtablewidgetitem4 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(2, __qtablewidgetitem4);
        QTableWidgetItem *__qtablewidgetitem5 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(3, __qtablewidgetitem5);
        QTableWidgetItem *__qtablewidgetitem6 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(4, __qtablewidgetitem6);
        QTableWidgetItem *__qtablewidgetitem7 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(5, __qtablewidgetitem7);
        QTableWidgetItem *__qtablewidgetitem8 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(6, __qtablewidgetitem8);
        QTableWidgetItem *__qtablewidgetitem9 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(7, __qtablewidgetitem9);
        QTableWidgetItem *__qtablewidgetitem10 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(8, __qtablewidgetitem10);
        QTableWidgetItem *__qtablewidgetitem11 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(9, __qtablewidgetitem11);
        QTableWidgetItem *__qtablewidgetitem12 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(10, __qtablewidgetitem12);
        QTableWidgetItem *__qtablewidgetitem13 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(11, __qtablewidgetitem13);
        QTableWidgetItem *__qtablewidgetitem14 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(12, __qtablewidgetitem14);
        QTableWidgetItem *__qtablewidgetitem15 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(13, __qtablewidgetitem15);
        QTableWidgetItem *__qtablewidgetitem16 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(14, __qtablewidgetitem16);
        QTableWidgetItem *__qtablewidgetitem17 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(15, __qtablewidgetitem17);
        QTableWidgetItem *__qtablewidgetitem18 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(16, __qtablewidgetitem18);
        QTableWidgetItem *__qtablewidgetitem19 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(17, __qtablewidgetitem19);
        QTableWidgetItem *__qtablewidgetitem20 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(18, __qtablewidgetitem20);
        QTableWidgetItem *__qtablewidgetitem21 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(19, __qtablewidgetitem21);
        QTableWidgetItem *__qtablewidgetitem22 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(20, __qtablewidgetitem22);
        QTableWidgetItem *__qtablewidgetitem23 = new QTableWidgetItem();
        tableWidget->setVerticalHeaderItem(21, __qtablewidgetitem23);
        QTableWidgetItem *__qtablewidgetitem24 = new QTableWidgetItem();
        tableWidget->setItem(0, 1, __qtablewidgetitem24);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        tableWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setDragDropOverwriteMode(false);
        tableWidget->setAlternatingRowColors(true);
        tableWidget->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        tableWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        tableWidget->setShowGrid(true);
        tableWidget->setGridStyle(Qt::SolidLine);
        tableWidget->setSortingEnabled(false);
        tableWidget->horizontalHeader()->setDefaultSectionSize(100);
        tableWidget->horizontalHeader()->setHighlightSections(true);
        tableWidget->horizontalHeader()->setProperty("showSortIndicator", QVariant(false));
        tableWidget->horizontalHeader()->setStretchLastSection(false);
        tableWidget->verticalHeader()->setCascadingSectionResizes(false);
        tableWidget->verticalHeader()->setStretchLastSection(false);

        verticalLayout->addWidget(tableWidget);

        hintLabel = new QLabel(BluetoothDeviceDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));

        verticalLayout->addWidget(hintLabel);

        buttonBox = new QDialogButtonBox(BluetoothDeviceDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(BluetoothDeviceDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), BluetoothDeviceDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), BluetoothDeviceDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(BluetoothDeviceDialog);
    } // setupUi

    void retranslateUi(QDialog *BluetoothDeviceDialog)
    {
        BluetoothDeviceDialog->setWindowTitle(QApplication::translate("BluetoothDeviceDialog", "Bluetooth Device", nullptr));
        actionCopy_Cell->setText(QApplication::translate("BluetoothDeviceDialog", "Copy Cell", nullptr));
        actionCopy_Rows->setText(QApplication::translate("BluetoothDeviceDialog", "Copy Rows", nullptr));
        actionCopy_All->setText(QApplication::translate("BluetoothDeviceDialog", "Copy All", nullptr));
        actionSave_as_image->setText(QApplication::translate("BluetoothDeviceDialog", "Save as image", nullptr));
        actionMark_Unmark_Row->setText(QApplication::translate("BluetoothDeviceDialog", "Mark/Unmark Row", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMark_Unmark_Row->setToolTip(QApplication::translate("BluetoothDeviceDialog", "Mark/Unmark Row", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMark_Unmark_Row->setShortcut(QApplication::translate("BluetoothDeviceDialog", "CtrlM", nullptr));
#endif // QT_NO_SHORTCUT
        actionMark_Unmark_Cell->setText(QApplication::translate("BluetoothDeviceDialog", "Mark/Unmark Cell", nullptr));
        QTableWidgetItem *___qtablewidgetitem = tableWidget->horizontalHeaderItem(0);
        ___qtablewidgetitem->setText(QApplication::translate("BluetoothDeviceDialog", "Value", nullptr));
        QTableWidgetItem *___qtablewidgetitem1 = tableWidget->horizontalHeaderItem(1);
        ___qtablewidgetitem1->setText(QApplication::translate("BluetoothDeviceDialog", "Changes", nullptr));
        QTableWidgetItem *___qtablewidgetitem2 = tableWidget->verticalHeaderItem(0);
        ___qtablewidgetitem2->setText(QApplication::translate("BluetoothDeviceDialog", "BD_ADDR", nullptr));
        QTableWidgetItem *___qtablewidgetitem3 = tableWidget->verticalHeaderItem(1);
        ___qtablewidgetitem3->setText(QApplication::translate("BluetoothDeviceDialog", "OUI", nullptr));
        QTableWidgetItem *___qtablewidgetitem4 = tableWidget->verticalHeaderItem(2);
        ___qtablewidgetitem4->setText(QApplication::translate("BluetoothDeviceDialog", "Name", nullptr));
        QTableWidgetItem *___qtablewidgetitem5 = tableWidget->verticalHeaderItem(3);
        ___qtablewidgetitem5->setText(QApplication::translate("BluetoothDeviceDialog", "Class of Device", nullptr));
        QTableWidgetItem *___qtablewidgetitem6 = tableWidget->verticalHeaderItem(4);
        ___qtablewidgetitem6->setText(QApplication::translate("BluetoothDeviceDialog", "LMP Version", nullptr));
        QTableWidgetItem *___qtablewidgetitem7 = tableWidget->verticalHeaderItem(5);
        ___qtablewidgetitem7->setText(QApplication::translate("BluetoothDeviceDialog", "LMP Subverion", nullptr));
        QTableWidgetItem *___qtablewidgetitem8 = tableWidget->verticalHeaderItem(6);
        ___qtablewidgetitem8->setText(QApplication::translate("BluetoothDeviceDialog", "Manufacturer", nullptr));
        QTableWidgetItem *___qtablewidgetitem9 = tableWidget->verticalHeaderItem(7);
        ___qtablewidgetitem9->setText(QApplication::translate("BluetoothDeviceDialog", "HCI Version", nullptr));
        QTableWidgetItem *___qtablewidgetitem10 = tableWidget->verticalHeaderItem(8);
        ___qtablewidgetitem10->setText(QApplication::translate("BluetoothDeviceDialog", "HCI Revision", nullptr));
        QTableWidgetItem *___qtablewidgetitem11 = tableWidget->verticalHeaderItem(9);
        ___qtablewidgetitem11->setText(QApplication::translate("BluetoothDeviceDialog", "Scan", nullptr));
        QTableWidgetItem *___qtablewidgetitem12 = tableWidget->verticalHeaderItem(10);
        ___qtablewidgetitem12->setText(QApplication::translate("BluetoothDeviceDialog", "Authentication", nullptr));
        QTableWidgetItem *___qtablewidgetitem13 = tableWidget->verticalHeaderItem(11);
        ___qtablewidgetitem13->setText(QApplication::translate("BluetoothDeviceDialog", "Encryption", nullptr));
        QTableWidgetItem *___qtablewidgetitem14 = tableWidget->verticalHeaderItem(12);
        ___qtablewidgetitem14->setText(QApplication::translate("BluetoothDeviceDialog", "ACL MTU", nullptr));
        QTableWidgetItem *___qtablewidgetitem15 = tableWidget->verticalHeaderItem(13);
        ___qtablewidgetitem15->setText(QApplication::translate("BluetoothDeviceDialog", "ACL Total Packets", nullptr));
        QTableWidgetItem *___qtablewidgetitem16 = tableWidget->verticalHeaderItem(14);
        ___qtablewidgetitem16->setText(QApplication::translate("BluetoothDeviceDialog", "SCO MTU", nullptr));
        QTableWidgetItem *___qtablewidgetitem17 = tableWidget->verticalHeaderItem(15);
        ___qtablewidgetitem17->setText(QApplication::translate("BluetoothDeviceDialog", "SCO Total Packets", nullptr));
        QTableWidgetItem *___qtablewidgetitem18 = tableWidget->verticalHeaderItem(16);
        ___qtablewidgetitem18->setText(QApplication::translate("BluetoothDeviceDialog", "LE ACL MTU", nullptr));
        QTableWidgetItem *___qtablewidgetitem19 = tableWidget->verticalHeaderItem(17);
        ___qtablewidgetitem19->setText(QApplication::translate("BluetoothDeviceDialog", "LE ACL Total Packets", nullptr));
        QTableWidgetItem *___qtablewidgetitem20 = tableWidget->verticalHeaderItem(18);
        ___qtablewidgetitem20->setText(QApplication::translate("BluetoothDeviceDialog", "Inquiry Mode", nullptr));
        QTableWidgetItem *___qtablewidgetitem21 = tableWidget->verticalHeaderItem(19);
        ___qtablewidgetitem21->setText(QApplication::translate("BluetoothDeviceDialog", "Page Timeout", nullptr));
        QTableWidgetItem *___qtablewidgetitem22 = tableWidget->verticalHeaderItem(20);
        ___qtablewidgetitem22->setText(QApplication::translate("BluetoothDeviceDialog", "Simple Pairing Mode", nullptr));
        QTableWidgetItem *___qtablewidgetitem23 = tableWidget->verticalHeaderItem(21);
        ___qtablewidgetitem23->setText(QApplication::translate("BluetoothDeviceDialog", "Voice Setting", nullptr));

        const bool __sortingEnabled = tableWidget->isSortingEnabled();
        tableWidget->setSortingEnabled(false);
        tableWidget->setSortingEnabled(__sortingEnabled);

        hintLabel->setText(QApplication::translate("BluetoothDeviceDialog", "%1 changes", nullptr));
    } // retranslateUi

};

namespace Ui {
    class BluetoothDeviceDialog: public Ui_BluetoothDeviceDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_BLUETOOTH_DEVICE_DIALOG_H
