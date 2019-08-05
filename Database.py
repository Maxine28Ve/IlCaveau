#!/usr/bin/python3
import pymysql
import hashlib

class Database:

    def __init__(self):
        self.db = pymysql.connect("localhost","python", "CuloMadonna19@__", "Passwords" )
        cursor = self.db.cursor()
        sql = """CREATE TABLE IF NOT EXISTS passwords (
                    sha_id VARCHAR(64) NOT NULL,
                    service VARCHAR(128),
                    username VARCHAR(128),
                    password VARCHAR(128),
                    PRIMARY KEY(sha_id)
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
        sha_id = self.__get_sha_id(service, username, password)
        sql = """ INSERT INTO passwords (sha_id, service, username, password)
                VALUES ("{}", "{}", "{}", "{}")
                """.format(sha_id, service, username, password)
        cursor = self.db.cursor()
        try:
            cursor.execute(sql)
            self.db.commit()
        except:
            self.db.rollback()

    def delete(self, list):
        """ Delete rows from the passwords table previously selected by the user
            from a list
        """
        cursor = self.db.cursor()
        # do this for each selected tuple
        for password_list in list:

            # get the hash of the combined tuple's 3 attributes ( service, username, password)
            string = ""
            for item in password_list:
                string += item
            sha_id = hashlib.sha256(string.encode('utf-8')).hexdigest()

            sql = """ DELETE FROM passwords WHERE sha_id = "{}"; """.format()
            try:
                cursor.execute(sql)
                self.db.commit()
            except:
                self.db.rollback()

    def load_entries(self):
        """ Retrieves the whole passwords table as a list. Such list is the one
            returned by cursor.fetchall()
        """
        sql = """SELECT service, username, password FROM passwords"""
        cursor = self.db.cursor()
        cursor.execute(sql)
        return cursor.fetchall()

    def update(self, service, username, password, newservice, newusername, newpassword):
        cursor = self.db.cursor()

        sha_id = self.__get_sha_id(service, username, password)
        sql = """ SELECT service, username, password FROM passwords
                WHERE sha_id = "{}" """.format(sha_id)
        cursor.execute(sql)
        result = cursor.fetchall()
        row_service = new_service if service != "" else result[0][0]
        row_username = new_username if username != "" else result[0][1]
        row_password = new_password if password != "" else result[0][2]

        sql = """ UPDATE passwords SET service = "{}", username = "{}", password = "{}"
                WHERE sha_id = "{}"
        """.format(row_service, row_username, row_password, sha_id)
        try:
            cursor.execute(sql)
            self.db.commit()
        except:
            self.db.rollback()

    def update_passwords(self, list):
        cursor = self.db.cursor()
        service = ""
        username = ""
        password = ""
        for tuple in list:
            service = tuple[0]
            username = tuple[1]
            password = tuple[2]
            sha_id = self.__get_sha_id(service, username, password)

            sql = """ UPDATE passwords SET password = "{}"
                    WHERE sha_id = "{}"
            """.format(password, sha_id)
            try:
                cursor.execute(sql)
                self.db.commit()
            except:
                self.db.rollback()

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

    def __get_sha_id(self, service, username, password):
        string = service + username + password
        return hashlib.sha256(string.encode('utf-8')).hexdigest()

    def __get_hash(self, string):
        return hashlib.sha256(string.encode('utf-8')).hexdigest()
