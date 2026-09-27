"""
Example legacy sources.
=======================

These are *inputs only*.

The previous version of this file also carried hand-written ``modernized_code``
and ``tests`` for each entry, and the pipeline returned them verbatim whenever a
``preset_id`` was supplied. That made the demo look flawless while ignoring
whatever the user had actually typed. The golden outputs are gone: every example
now goes through the same scan → plan → synthesise → verify path as any pasted
snippet.

``expected_rule_ids`` records which rules each example is meant to trigger. The
test suite asserts on it, so a rule regression shows up as a failing test rather
than a quietly emptier report.
"""

from __future__ import annotations

from typing import Any, Dict

EXAMPLES: Dict[str, Dict[str, Any]] = {
    "python_legacy_service": {
        "id": "python_legacy_service",
        "name": "Python 2 user service",
        "language": "python",
        "filename": "legacy_user_service.py",
        "category": "Security & deprecation",
        "description": (
            "Python 2 era service: SQL built by string formatting, MD5 password "
            "hashing, urllib2, a mutable default argument, a bare except and a "
            "print statement. Does not even parse on Python 3."
        ),
        "expected_rule_ids": [
            "PY-SEC-001",
            "PY-SEC-002",
            "PY-SEC-003",
            "PY-DEP-001",
            "PY-DEP-002",
            "PY-QUAL-001",
            "PY-QUAL-002",
        ],
        "original_code": '''import urllib2
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
''',
    },
    "java_concurrency_monolith": {
        "id": "java_concurrency_monolith",
        "name": "Java 8 batch processor",
        "language": "java",
        "filename": "OrderBatchProcessor.java",
        "category": "Concurrency & JDBC",
        "description": (
            "Java 8 batch job: a shared SimpleDateFormat field, one platform "
            "thread per order, SQL assembled by concatenation, a leaked JDBC "
            "connection and printStackTrace error handling."
        ),
        "expected_rule_ids": [
            "JAVA-SEC-001",
            "JAVA-SEC-002",
            "JAVA-DEP-001",
            "JAVA-QUAL-001",
            "JAVA-QUAL-002",
        ],
        "original_code": '''package com.enterprise.legacy;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

// Legacy Batch Processor written for Java 7/8
public class OrderBatchProcessor {
    private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); // BUG: Not thread-safe!

    public void processOrders(List<String> orderIds) {
        for (final String orderId : orderIds) {
            // ANTI-PATTERN: Unbounded thread spawning
            new Thread(new Runnable() {
                public void run() {
                    try {
                        Connection conn = DriverManager.getConnection("jdbc:legacy:db");
                        Statement stmt = conn.createStatement();
                        String dateStr = dateFormat.format(new Date());

                        stmt.executeUpdate("UPDATE orders SET processed_at = '" + dateStr + "' WHERE id = " + orderId);

                        // LEAK: Missing conn.close() / stmt.close() in finally block
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }
}
''',
    },
    "node_callback_hell": {
        "id": "node_callback_hell",
        "name": "Node.js upload handler",
        "language": "javascript",
        "filename": "uploadHandler.js",
        "category": "Async & cryptography",
        "description": (
            "Express handler using the deprecated crypto.createCipher (MD5 key "
            "derivation, no IV) and two levels of error-first callbacks with no "
            "structured error path."
        ),
        "expected_rule_ids": ["JS-SEC-001", "JS-DEP-001"],
        "original_code": '''const crypto = require('crypto');
const fs = require('fs');

// Legacy Express Route Handler
function handleUserUpload(req, res) {
    const rawData = req.body.payload;

    // VULNERABILITY: createCipher is deprecated and uses weak key derivation
    const cipher = crypto.createCipher('aes-128-cbc', 'legacy-app-secret');
    let encrypted = cipher.update(rawData, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    fs.writeFile('./temp_vault.bin', encrypted, function(err) {
        if (err) {
            res.status(500).send("Disk error");
        } else {
            fs.readFile('./temp_vault.bin', function(readErr, data) {
                if (readErr) {
                    res.status(500).send("Read error");
                } else {
                    res.json({ status: "success", bytes: data.length });
                }
            });
        }
    });
}
module.exports = { handleUserUpload };
''',
    },
    "php_legacy_admin": {
        "id": "php_legacy_admin",
        "name": "PHP 5 admin lookup",
        "language": "php",
        "filename": "admin_lookup.php",
        "category": "Injection & credentials",
        "description": (
            "PHP 5 script using the removed mysql_* extension, a request "
            "superglobal spliced straight into SQL, md5 password hashing and a "
            "shell call built from a variable."
        ),
        "expected_rule_ids": ["PHP-SEC-001", "PHP-SEC-002", "PHP-SEC-003", "PHP-DEP-001"],
        "original_code": '''<?php
// Legacy admin tooling - PHP 5.x
$link = mysql_connect("localhost", "root", "root");
mysql_select_db("app", $link);

$username = $_GET['user'];
$result = mysql_query("SELECT id, email, role FROM users WHERE username = '" . $username . "'");
$row = mysql_fetch_assoc($result);

$hashed = md5($_POST['password']);
if ($row && $hashed === $row['password_hash']) {
    $logfile = $_GET['log'];
    // Dumps the requested log straight through a shell
    system("cat /var/log/app/" . $logfile);
    echo "Welcome " . $row['email'];
} else {
    echo "Access denied";
}
''',
    },
    "typescript_unsafe_api": {
        "id": "typescript_unsafe_api",
        "name": "TypeScript API route",
        "language": "typescript",
        "filename": "userRoute.ts",
        "category": "Injection & type safety",
        "description": (
            "TypeScript route that builds SQL with a template literal, evaluates "
            "a filter expression with eval(), leans on `any`, and leaves a promise "
            "chain without a rejection handler."
        ),
        "expected_rule_ids": [
            "JS-SEC-002",
            "JS-SEC-003",
            "JS-QUAL-001",
            "JS-QUAL-002",
            "TS-QUAL-001",
        ],
        "original_code": '''import { Router } from 'express';
import { db } from './db';

const router = Router();

router.get('/users/:id', (req: any, res: any) => {
  const id = req.params.id;

  // Template literal straight into SQL
  db.query(`SELECT id, email, role FROM users WHERE id = ${id}`)
    .then((rows: any) => {
      var filter = req.query.filter;
      // Arbitrary expression evaluated against the result set
      const matched = rows.filter((r: any) => eval(filter));
      res.json({ users: matched });
    });
});

export default router;
''',
    },
}

#: Backwards-compatible alias for the previous module-level name.
PRESETS = EXAMPLES


def example_summaries() -> list[Dict[str, Any]]:
    """Metadata plus source, for /api/examples. No golden outputs to leak."""
    return [
        {
            "id": example["id"],
            "name": example["name"],
            "language": example["language"],
            "filename": example["filename"],
            "category": example["category"],
            "description": example["description"],
            "original_code": example["original_code"],
        }
        for example in EXAMPLES.values()
    ]
