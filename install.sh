#!/bin/bash

apt-get install mysql_server mariadb
pip install pycrypto pymysql

echo "create or replace user python@localhost identified by 'CuloMadonna19@__'; grant all privileges on *.* to python@localhost;" | mysql
echo "create database Passwords" | mysql -u python --password=CuloMadonna19@__
