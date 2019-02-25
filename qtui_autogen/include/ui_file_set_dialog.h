/********************************************************************************
** Form generated from reading UI file 'file_set_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_FILE_SET_DIALOG_H
#define UI_FILE_SET_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeView>
#include "widgets/elided_label.h"

QT_BEGIN_NAMESPACE

class Ui_FileSetDialog
{
public:
    QGridLayout *gridLayout;
    QFormLayout *formLayout;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    ElidedLabel *directoryLabel;
    QDialogButtonBox *buttonBox;
    QTreeView *fileSetTree;

    void setupUi(QDialog *FileSetDialog)
    {
        if (FileSetDialog->objectName().isEmpty())
            FileSetDialog->setObjectName(QString::fromUtf8("FileSetDialog"));
        FileSetDialog->resize(750, 450);
        FileSetDialog->setSizeGripEnabled(true);
        gridLayout = new QGridLayout(FileSetDialog);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        formLayout = new QFormLayout();
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        formLayout->setFieldGrowthPolicy(QFormLayout::FieldsStayAtSizeHint);
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(FileSetDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        directoryLabel = new ElidedLabel(FileSetDialog);
        directoryLabel->setObjectName(QString::fromUtf8("directoryLabel"));
        QSizePolicy sizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(directoryLabel->sizePolicy().hasHeightForWidth());
        directoryLabel->setSizePolicy(sizePolicy);
        directoryLabel->setOpenExternalLinks(true);
        directoryLabel->setTextInteractionFlags(Qt::LinksAccessibleByKeyboard|Qt::LinksAccessibleByMouse|Qt::TextBrowserInteraction|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        horizontalLayout->addWidget(directoryLabel);


        formLayout->setLayout(1, QFormLayout::SpanningRole, horizontalLayout);

        buttonBox = new QDialogButtonBox(FileSetDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        formLayout->setWidget(2, QFormLayout::SpanningRole, buttonBox);

        fileSetTree = new QTreeView(FileSetDialog);
        fileSetTree->setObjectName(QString::fromUtf8("fileSetTree"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(1);
        sizePolicy1.setHeightForWidth(fileSetTree->sizePolicy().hasHeightForWidth());
        fileSetTree->setSizePolicy(sizePolicy1);
        fileSetTree->setTextElideMode(Qt::ElideLeft);
        fileSetTree->setRootIsDecorated(false);
        fileSetTree->setUniformRowHeights(true);
        fileSetTree->setItemsExpandable(false);
        fileSetTree->setExpandsOnDoubleClick(false);

        formLayout->setWidget(0, QFormLayout::SpanningRole, fileSetTree);


        gridLayout->addLayout(formLayout, 0, 0, 1, 1);


        retranslateUi(FileSetDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), FileSetDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), FileSetDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(FileSetDialog);
    } // setupUi

    void retranslateUi(QDialog *FileSetDialog)
    {
        FileSetDialog->setWindowTitle(QApplication::translate("FileSetDialog", "Dialog", nullptr));
        label->setText(QApplication::translate("FileSetDialog", "Directory:", nullptr));
        directoryLabel->setText(QString());
    } // retranslateUi

};

namespace Ui {
    class FileSetDialog: public Ui_FileSetDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_FILE_SET_DIALOG_H
