#include "transactiondescdialog.h"
#include "ui_transactiondescdialog.h"

#include "transactiontablemodel.h"

#include <QModelIndex>

TransactionDescDialog::TransactionDescDialog(const QModelIndex &idx, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TransactionDescDialog)
{
    ui->setupUi(this);
    QString desc = idx.data(TransactionTableModel::LongDescriptionRole).toString();
    ui->detailText->setHtml(desc);
    ui->buttonBox->setStyleSheet("background-color:rgb(255,233,142); color:black;border-style:outset; border-width:2px; border-color:darkgrey; border-radius:10px; padding:2px 10px 2px 10px");

    ui->detailText->setStyleSheet("QToolTip {background-color:rgb(255,233,142); color:black; border: 2px solid grey; padding:2px 10px 2px 10px} QMenu{padding: 2px 10px 2px 10px;background-color:rgb(235,227,181);border:2px solid grey}");
}
TransactionDescDialog::~TransactionDescDialog()
{
    delete ui;
}
