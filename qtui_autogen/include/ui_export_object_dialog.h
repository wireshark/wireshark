/********************************************************************************
** Form generated from reading UI file 'export_object_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_EXPORT_OBJECT_DIALOG_H
#define UI_EXPORT_OBJECT_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include "widgets/export_objects_view.h"

QT_BEGIN_NAMESPACE

class Ui_ExportObjectDialog
{
public:
    QVBoxLayout *verticalLayout;
    ExportObjectsTreeView *objectTree;
    QFrame *progressFrame;
    QHBoxLayout *horizontalLayout;
    QLabel *progressLabel;
    QProgressBar *progressBar;
    QSpacerItem *horizontalSpacer;
    QHBoxLayout *filterLayout;
    QLabel *label;
    QLineEdit *filterLine;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ExportObjectDialog)
    {
        if (ExportObjectDialog->objectName().isEmpty())
            ExportObjectDialog->setObjectName(QString::fromUtf8("ExportObjectDialog"));
        ExportObjectDialog->resize(750, 520);
        ExportObjectDialog->setSizeGripEnabled(true);
        verticalLayout = new QVBoxLayout(ExportObjectDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        objectTree = new ExportObjectsTreeView(ExportObjectDialog);
        objectTree->setObjectName(QString::fromUtf8("objectTree"));
        objectTree->setSortingEnabled(true);
        objectTree->setRootIsDecorated(false);
        objectTree->setUniformRowHeights(true);
        objectTree->setItemsExpandable(false);
        objectTree->setExpandsOnDoubleClick(false);

        verticalLayout->addWidget(objectTree);

        progressFrame = new QFrame(ExportObjectDialog);
        progressFrame->setObjectName(QString::fromUtf8("progressFrame"));
        progressFrame->setEnabled(true);
        progressFrame->setFrameShape(QFrame::NoFrame);
        progressFrame->setFrameShadow(QFrame::Plain);
        progressFrame->setLineWidth(0);
        horizontalLayout = new QHBoxLayout(progressFrame);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setContentsMargins(-1, 0, -1, 0);
        progressLabel = new QLabel(progressFrame);
        progressLabel->setObjectName(QString::fromUtf8("progressLabel"));

        horizontalLayout->addWidget(progressLabel);

        progressBar = new QProgressBar(progressFrame);
        progressBar->setObjectName(QString::fromUtf8("progressBar"));
        progressBar->setStyleSheet(QString::fromUtf8("QProgressBar { width: 10em; }"));
        progressBar->setMaximum(0);
        progressBar->setValue(-1);
        progressBar->setTextVisible(false);

        horizontalLayout->addWidget(progressBar);

        horizontalSpacer = new QSpacerItem(387, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        horizontalLayout->setStretch(2, 1);

        verticalLayout->addWidget(progressFrame);

        filterLayout = new QHBoxLayout();
        filterLayout->setObjectName(QString::fromUtf8("filterLayout"));
        label = new QLabel(ExportObjectDialog);
        label->setObjectName(QString::fromUtf8("label"));

        filterLayout->addWidget(label, 0, Qt::AlignLeft);

        filterLine = new QLineEdit(ExportObjectDialog);
        filterLine->setObjectName(QString::fromUtf8("filterLine"));

        filterLayout->addWidget(filterLine);


        verticalLayout->addLayout(filterLayout);

        buttonBox = new QDialogButtonBox(ExportObjectDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help|QDialogButtonBox::Save|QDialogButtonBox::SaveAll);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(ExportObjectDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), ExportObjectDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), ExportObjectDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(ExportObjectDialog);
    } // setupUi

    void retranslateUi(QDialog *ExportObjectDialog)
    {
        ExportObjectDialog->setWindowTitle(QApplication::translate("ExportObjectDialog", "Dialog", nullptr));
        progressLabel->setText(QApplication::translate("ExportObjectDialog", "Searching for objects", nullptr));
        label->setText(QApplication::translate("ExportObjectDialog", "Text Filter:", nullptr));
#ifndef QT_NO_TOOLTIP
        filterLine->setToolTip(QApplication::translate("ExportObjectDialog", "Only display entries containing this string", nullptr));
#endif // QT_NO_TOOLTIP
    } // retranslateUi

};

namespace Ui {
    class ExportObjectDialog: public Ui_ExportObjectDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_EXPORT_OBJECT_DIALOG_H
