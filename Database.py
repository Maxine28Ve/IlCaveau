#!/usr/bin/python3
import pymysql
import hashlib
import warnings
from AESCipher import AESCipher

class Database:

    def __init__(self):
        self.db = pymysql.connect("localhost","python", "somepassword", "Passwords" )
        cursor = self.db.cursor()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sql = """CREATE TABLE IF NOT EXISTS passwords (
                        id INT AUTO_INCREMENT NOT NULL,
                        service VARCHAR(128),
                        username VARCHAR(128),
                        password VARCHAR(128),
                        PRIMARY KEY(id)
                    )"""

            cursor.execute(sql)
            sql = """CREATE TABLE IF NOT EXISTS masterpassword (
                        sha_id VARCHAR(128) NOT NULL,
                        masterpassword_hash VARCHAR(128),
                        PRIMARY KEY(sha_id)
                    )"""
            cursor.execute(sql)
        sql = """ SELECT masterpassword_hash FROM masterpassword """
        cursor.execute(sql)
        if(cursor.fetchone() == None):
            print("First start detected.")
            pwd = input("Insert a password: ")
            sql = """ INSERT INTO masterpassword (sha_id, masterpassword_hash)
            VALUES ("{}", "{}")""".format(self.__get_hash(pwd), self.__get_hash(pwd))
            print(sql)
            try:
                cursor.execute(sql)
                self.db.commit()
            except:
                print("Smth wrong")
                self.db.rollback()
            sql = """ SELECT masterpassword_hash FROM masterpassword """
            cursor.execute(sql)
            print(cursor.fetchall())

    def insert(self, service="", username="", password=""):
        """ Insert a new entry to the table """
        # we create a string from which we will generate a hash to uniquely
        # identify a table row
        sql = """ INSERT INTO passwords (service, username, password)
                VALUES ("{}", "{}", "{}")
                """.format(service, username, password)
        cursor = self.db.cursor()
        try:
            cursor.execute(sql)
            self.db.commit()
            ret = 0
        except:
            self.db.rollback()
            ret = 1
        return ret

    def load_entries(self):
        """ Retrieves the whole passwords table as a list. Such list is the one
            returned by cursor.fetchall()
        """
        sql = """SELECT service, username, password FROM passwords"""
        cursor = self.db.cursor()
        cursor.execute(sql)
        return cursor.fetchall()

    def update(self, list):
        sql = """ DELETE FROM passwords; """
        cursor = self.db.cursor()
        try:
            cursor.execute(sql)
            self.db.commit()
        except:
            self.db.rollback()
            return 1

        for item in list:
            ret = self.insert(item[0], item[1], item[2])
            if(ret == 1):
                print("AYYYYYYYYY NOPE")

    def update_masterpassword(self, new_masterpassword):
        cursor = self.db.cursor()
        new_masterpassword_hash = self.__get_hash(new_masterpassword)
        sql = """ DROP TABLE masterpassword """

        try:
            cursor.execute(sql)
            self.db.commit()
        except:
            self.db.rollback()

        sql = """CREATE TABLE IF NOT EXISTS masterpassword (
            sha_id VARCHAR(128) NOT NULL,
            masterpassword_hash VARCHAR(128),
            PRIMARY KEY(sha_id)
        )"""
        try:
            cursor.execute(sql)
            self.db.commit()
        except:
            self.db.rollback()
        sql = """ INSERT INTO masterpassword (sha_id, masterpassword_hash) VALUES
                ("{}", "{}")
        """.format(new_masterpassword_hash, new_masterpassword_hash)
        try:
            cursor.execute(sql)
            self.db.commit()
        except:
            self.db.rollback()

    def get_masterpassword(self):
        cursor = self.db.cursor()
        sql = """ SELECT masterpassword_hash FROM masterpassword """
        cursor.execute(sql)
        return cursor.fetchone()

    def quit(self):
        """ Close the connetion to the mysql database """
        self.db.close()

    def __get_hash(self, string):
        return hashlib.sha256(string.encode('utf-8')).hexdigest()
