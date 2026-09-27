import urllib2
import sqlite3
import md5

# Legacy User Gateway - Last updated 2014
class UserService:
    def __init__(self, db_path="users.db", cache={}):
        self.db_path = db_path
        self.cache = cache # Insecure mutable default argument

    def authenticate_user(self, username, password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # CRITICAL VULNERABILITY: Raw SQL Injection
        query = "SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'" % (username, md5.new(password).hexdigest())
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return {"id": user[0], "username": user[1], "role": user[2]}
        return None

    def fetch_remote_profile(self, user_id):
        # DEPRECATED: urllib2 removed in modern Python 3
        try:
            url = "http://internal-legacy-api.local/profile?id=" + str(user_id)
            response = urllib2.urlopen(url, timeout=5)
            data = response.read()
            self.cache[user_id] = data
            return data
        except:
            # ANTI-PATTERN: Bare exception masking critical failures
            print "Failed to fetch profile for user: " + str(user_id)
            return None
