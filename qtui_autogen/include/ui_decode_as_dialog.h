/********************************************************************************
** Form generated from reading UI file 'decode_as_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DECODE_AS_DIALOG_H
#define UI_DECODE_AS_DIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"
#include "widgets/tabnav_tree_view.h"

QT_BEGIN_NAMESPACE

class Ui_DecodeAsDialog
{
public:
    QVBoxLayout *verticalLayout_2;
    TabnavTreeView *decodeAsTreeView;
    QHBoxLayout *horizontalLayout;
    QToolButton *newToolButton;
    QToolButton *deleteToolButton;
    QToolButton *copyToolButton;
    QToolButton *clearToolButton;
    QSpacerItem *horizontalSpacer;
    ElidedLabel *pathLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *DecodeAsDialog)
    {
        if (DecodeAsDialog->objectName().isEmpty())
            DecodeAsDialog->setObjectName(QString::fromUtf8("DecodeAsDialog"));
        DecodeAsDialog->resize(750, 460);
        verticalLayout_2 = new QVBoxLayout(DecodeAsDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        decodeAsTreeView = new TabnavTreeView(DecodeAsDialog);
        decodeAsTreeView->setObjectName(QString::fromUtf8("decodeAsTreeView"));
        decodeAsTreeView->setIndentation(0);

        verticalLayout_2->addWidget(decodeAsTreeView);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        newToolButton = new QToolButton(DecodeAsDialog);
        newToolButton->setObjectName(QString::fromUtf8("newToolButton"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/stock/plus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        newToolButton->setIcon(icon);

        horizontalLayout->addWidget(newToolButton);

        deleteToolButton = new QToolButton(DecodeAsDialog);
        deleteToolButton->setObjectName(QString::fromUtf8("deleteToolButton"));
        deleteToolButton->setEnabled(false);
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/stock/minus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        deleteToolButton->setIcon(icon1);

        horizontalLayout->addWidget(deleteToolButton);

        copyToolButton = new QToolButton(DecodeAsDialog);
        copyToolButton->setObjectName(QString::fromUtf8("copyToolButton"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/stock/copy-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        copyToolButton->setIcon(icon2);

        horizontalLayout->addWidget(copyToolButton);

        clearToolButton = new QToolButton(DecodeAsDialog);
        clearToolButton->setObjectName(QString::fromUtf8("clearToolButton"));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/stock/delete_list.png"), QSize(), QIcon::Normal, QIcon::Off);
        clearToolButton->setIcon(icon3);
        clearToolButton->setEnabled(false);

        horizontalLayout->addWidget(clearToolButton);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        pathLabel = new ElidedLabel(DecodeAsDialog);
        pathLabel->setObjectName(QString::fromUtf8("pathLabel"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(pathLabel->sizePolicy().hasHeightForWidth());
        pathLabel->setSizePolicy(sizePolicy);
        pathLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        pathLabel->setOpenExternalLinks(true);

        horizontalLayout->addWidget(pathLabel);

        horizontalLayout->setStretch(5, 1);

        verticalLayout_2->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(DecodeAsDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok|QDialogButtonBox::Save);

        verticalLayout_2->addWidget(buttonBox);


        retranslateUi(DecodeAsDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), DecodeAsDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), DecodeAsDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(DecodeAsDialog);
    } // setupUi

    void retranslateUi(QDialog *DecodeAsDialog)
    {
#ifndef QT_NO_TOOLTIP
        newToolButton->setToolTip(QApplication::translate("DecodeAsDialog", "Change the dissection behavior for a protocol.", nullptr));
#endif // QT_NO_TOOLTIP
        newToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        deleteToolButton->setToolTip(QApplication::translate("DecodeAsDialog", "Remove this dissection behavior.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        copyToolButton->setToolTip(QApplication::translate("DecodeAsDialog", "Copy this dissection behavior.", nullptr));
#endif // QT_NO_TOOLTIP
        copyToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        clearToolButton->setToolTip(QApplication::translate("DecodeAsDialog", "Clear all dissection behaviors.", nullptr));
#endif // QT_NO_TOOLTIP
        pathLabel->setText(QString());
        Q_UNUSED(DecodeAsDialog);
    } // retranslateUi

};

namespace Ui {
    class DecodeAsDialog: public Ui_DecodeAsDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DECODE_AS_DIALOG_H
