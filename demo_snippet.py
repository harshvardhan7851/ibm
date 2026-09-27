import md5
import sqlite3

SMTP_PASSWORD = "mailer_prod_8f31c0"

class InvoiceStore:
    def __init__(self, db="invoices.db", cache={}):
        self.db = db
        self.cache = cache

    def find(self, customer):
        cur = sqlite3.connect(self.db).cursor()
        sql = "SELECT id, total FROM invoices WHERE customer = '%s'" % customer
        cur.execute(sql)
        return cur.fetchall()

    def token(self, secret):
        return md5.new(secret).hexdigest()

    def load(self, key):
        try:
            return self.cache[key]
        except:
            return None
