import sqlite3

class UserCredentials:
    def __init__(self, db_name='credentials.db', table_name='credentialsTable'):
        self.db_name = db_name
        self.table_name = table_name
        self.conn = sqlite3.connect(self.db_name)
        self.c = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.c.execute(f'''CREATE TABLE IF NOT EXISTS {self.table_name} (
                    id INTEGER PRIMARY KEY,
                    iv TEXT,
                    password TEXT,
                    username TEXT,
                    website_name TEXT,
                    note TEST,
                    url TEXT
                    )''')
        self.conn.commit()

    def insert_data(self, iv, password, username, website_name, note, url):
        self.c.execute(f'''INSERT INTO {self.table_name} (iv, password, username, website_name, note, url)
                    VALUES (?, ?, ?, ?, ?, ?)''', (iv, password, username, website_name, note, url))
        self.conn.commit()

    def get_all_data(self):
        self.c.execute(f'''SELECT * FROM {self.table_name}''')
        data = self.c.fetchall()
        return data

    def update_data(self, id, iv, password, username, website_name, note, url):
        self.c.execute(f'''UPDATE {self.table_name} SET iv=?, password=?, username=?, website_name=?, note=?, url=? 
                    WHERE id=?''', (id, iv, password, username, website_name, note,url))
        self.conn.commit()

    def delete_data(self, id):
        self.c.execute(f'''DELETE FROM {self.table_name} WHERE id=?''', (id,))
        self.conn.commit()

    def __del__(self):
        self.conn.close()
