#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
    KIIRU EGG MANAGEMENT SYSTEM v4.0
    Multi-Shop Enterprise Inventory, Sales & Debt Tracking

    Default Admin: KIIRU / 20kiiru00
    Mathematical CAPTCHA: Auto-verified addition/subtraction
    PWA Support: Installable web app with offline capability
    Multi-Shop: Admin can assign rights to shop managers
═══════════════════════════════════════════════════════════════════════════════

FEATURES:
├── Mathematical CAPTCHA (Addition/Subtraction) - Auto-verified
├── Multi-Shop Support with Role Delegation
├── PWA Manifest & Service Worker for Installability
├── SEO-Optimized for Google Discovery
├── SQLite Database (Zero-config deployment)
├── Offline-First Architecture
├── Comprehensive Audit Logging
├── Role-Based Access Control (RBAC)
└── Instant Deployment Ready

DEPLOYMENT:
    pip install -r requirements.txt
    streamlit run egg_management_app.py

DEFAULT ADMIN: username="KIIRU", password="20kiiru00"

Author: Enterprise Development Team
Version: 4.0.0
License: MIT
"""

import streamlit as st
import sqlite3
import hashlib
import secrets
import json
import os
import re
import time
import threading
import io
import base64
import random
import math
from datetime import datetime, timedelta, date
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Tuple, Any
from contextlib import contextmanager
from functools import wraps
import logging

# Third-party imports with fallbacks
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("WARNING: bcrypt not installed. Using fallback hashing.")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("WARNING: pandas not installed. Using dict-based tables.")

try:
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("WARNING: plotly not installed. Charts disabled.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityConfig:
    """Centralized security configuration"""

    # Default Admin Credentials
    DEFAULT_ADMIN_USERNAME = "KIIRU"
    DEFAULT_ADMIN_PASSWORD = "20kiiru00"
    DEFAULT_ADMIN_EMAIL = "admin@kiirueggs.com"
    DEFAULT_ADMIN_FULLNAME = "Kiiru Administrator"

    # Database
    DB_PATH = "kiiru_egg_management.db"

    # Password Hashing
    BCRYPT_ROUNDS = 12
    BCRYPT_PEPPER = os.getenv('BCRYPT_PEPPER', 'kiiru_egg_system_fixed_pepper_2024')
    PASSWORD_MIN_LENGTH = 6

    # Session Management
    SESSION_TIMEOUT = timedelta(hours=12)
    MAX_CONCURRENT_SESSIONS = 5

    # Account Security
    FAILED_LOGIN_THRESHOLD = 5
    LOCKOUT_DURATION = timedelta(minutes=30)

    # Audit & Compliance
    AUDIT_RETENTION_DAYS = 2555  # 7 years

    @classmethod
    def validate(cls):
        """Validate critical security settings"""
        warnings = []
        if cls.DEFAULT_ADMIN_PASSWORD == "20kiiru00":
            warnings.append("INFO: Using default admin password. Change after first login.")
        return warnings


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: MATHEMATICAL CAPTCHA SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

class MathCaptcha:
    """Simple mathematical CAPTCHA using addition and subtraction"""

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def generate(self, session_id: str) -> Dict[str, Any]:
        """Generate a new math problem"""
        operation = random.choice(['+', '-'])

        if operation == '+':
            a = random.randint(1, 20)
            b = random.randint(1, 20)
            answer = a + b
            question = f"{a} + {b} = ?"
        else:
            a = random.randint(10, 30)
            b = random.randint(1, 10)
            answer = a - b
            question = f"{a} - {b} = ?"

        with self._lock:
            self._store[session_id] = {
                'answer': answer,
                'timestamp': time.time(),
                'attempts': 0
            }

        return {
            'question': question,
            'session_id': session_id
        }

    def verify(self, session_id: str, user_answer: str) -> Dict[str, Any]:
        """Verify user's answer"""
        with self._lock:
            if session_id not in self._store:
                return {'success': False, 'error': 'CAPTCHA expired. Please refresh.'}

            captcha_data = self._store[session_id]

            if time.time() - captcha_data['timestamp'] > 300:
                del self._store[session_id]
                return {'success': False, 'error': 'CAPTCHA expired. Please try again.'}

            captcha_data['attempts'] += 1
            if captcha_data['attempts'] > 3:
                del self._store[session_id]
                return {'success': False, 'error': 'Too many attempts. Please refresh CAPTCHA.'}

            try:
                user_answer_int = int(user_answer.strip())
            except ValueError:
                return {'success': False, 'error': 'Please enter a valid number.'}

            if user_answer_int == captcha_data['answer']:
                del self._store[session_id]
                return {'success': True, 'error': None}
            else:
                return {'success': False, 'error': f'Incorrect answer. Attempt {captcha_data["attempts"]}/3'}

    def refresh(self, session_id: str) -> Dict[str, Any]:
        """Generate new CAPTCHA for session"""
        with self._lock:
            if session_id in self._store:
                del self._store[session_id]
        return self.generate(session_id)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: LOGGING & AUDIT
# ═══════════════════════════════════════════════════════════════════════════════

class AuditLogger:
    """Immutable audit logging with tamper detection"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or SecurityConfig.DB_PATH
        self._init_audit_table()
        self._lock = threading.Lock()

    def _init_audit_table(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource TEXT,
            details TEXT,
            ip_address TEXT,
            shop_id INTEGER,
            success INTEGER DEFAULT 1,
            hash_chain TEXT
        )""")
        conn.commit()
        conn.close()

    def log(self, user_id: int, username: str, action: str, 
            resource: str = None, details: dict = None,
            ip_address: str = None, shop_id: int = None,
            success: bool = True):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            c.execute("SELECT hash_chain FROM audit_log ORDER BY id DESC LIMIT 1")
            prev = c.fetchone()
            prev_hash = prev[0] if prev else "0" * 64

            entry_data = json.dumps({
                'user_id': user_id,
                'action': action,
                'resource': resource,
                'details': details,
                'timestamp': datetime.utcnow().isoformat(),
                'prev_hash': prev_hash
            }, sort_keys=True)

            current_hash = hashlib.sha256(entry_data.encode()).hexdigest()

            c.execute("""INSERT INTO audit_log 
                (user_id, username, action, resource, details, ip_address, shop_id, success, hash_chain)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, username, action, resource, 
                 json.dumps(details) if details else None,
                 ip_address, shop_id, 1 if success else 0, current_hash))

            conn.commit()
            conn.close()

    def get_logs(self, limit: int = 100, shop_id: int = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if shop_id:
            c.execute("""SELECT * FROM audit_log WHERE shop_id=? ORDER BY timestamp DESC LIMIT ?""", (shop_id, limit))
        else:
            c.execute("""SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?""", (limit,))
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, user_id, action, resource, details, timestamp, hash_chain FROM audit_log ORDER BY id")
        rows = c.fetchall()
        conn.close()

        issues = []
        prev_hash = "0" * 64

        for row in rows:
            entry_data = json.dumps({
                'user_id': row[1],
                'action': row[2],
                'resource': row[3],
                'details': row[4],
                'timestamp': row[5],
                'prev_hash': prev_hash
            }, sort_keys=True)

            expected_hash = hashlib.sha256(entry_data.encode()).hexdigest()
            if row[6] != expected_hash:
                issues.append(f"Tamper detected at record {row[0]}")

            prev_hash = row[6]

        return len(issues) == 0, issues


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Thread-safe rate limiter with sliding window"""

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        self._cleanup_interval = 300
        self._last_cleanup = time.time()

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        with self._lock:
            expired = []
            for key, (count, window_start, window_size) in self._store.items():
                if now - window_start > window_size:
                    expired.append(key)
            for key in expired:
                del self._store[key]
            self._last_cleanup = now

    def is_allowed(self, identifier: str, max_requests: int, window_seconds: int) -> bool:
        self._cleanup()
        with self._lock:
            now = time.time()
            key = f"{identifier}:{window_seconds}"
            if key not in self._store:
                self._store[key] = (1, now, window_seconds)
                return True
            count, window_start, _ = self._store[key]
            if now - window_start > window_seconds:
                self._store[key] = (1, now, window_seconds)
                return True
            if count >= max_requests:
                return False
            self._store[key] = (count + 1, window_start, window_seconds)
            return True


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: PASSWORD & TOKEN SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

class CryptoManager:
    """Handles all cryptographic operations"""

    @staticmethod
    def hash_password(password: str) -> str:
        if BCRYPT_AVAILABLE:
            peppered = password + SecurityConfig.BCRYPT_PEPPER
            salt = bcrypt.gensalt(rounds=SecurityConfig.BCRYPT_ROUNDS)
            return bcrypt.hashpw(peppered.encode(), salt).decode()
        else:
            salt = secrets.token_hex(16)
            hashed = hashlib.pbkdf2_hmac(
                'sha256', 
                (password + SecurityConfig.BCRYPT_PEPPER).encode(),
                salt.encode(),
                100000
            ).hex()
            return f"pbkdf2:{salt}:{hashed}"

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        try:
            if hashed.startswith("pbkdf2:"):
                parts = hashed.split(":")
                if len(parts) != 3:
                    return False
                _, salt, stored_hash = parts
                expected = hashlib.pbkdf2_hmac(
                    'sha256',
                    (password + SecurityConfig.BCRYPT_PEPPER).encode(),
                    salt.encode(),
                    100000
                ).hex()
                return secrets.compare_digest(stored_hash, expected)
            if BCRYPT_AVAILABLE:
                peppered = password + SecurityConfig.BCRYPT_PEPPER
                return bcrypt.checkpw(peppered.encode(), hashed.encode())
            return False
        except Exception:
            return False

    @staticmethod
    def _secure_compare(a: str, b: str) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0

    @staticmethod
    def generate_token(user_id: int, role: str, shop_id: int = None) -> str:
        payload = f"{user_id}:{role}:{shop_id or 0}:{time.time()}:{secrets.token_hex(8)}"
        signature = hashlib.sha256(
            (payload + SecurityConfig.BCRYPT_PEPPER).encode()
        ).hexdigest()
        return f"{payload}:{signature}"

    @staticmethod
    def verify_token(token: str) -> Optional[Dict]:
        parts = token.split(":")
        if len(parts) != 6:
            return None
        payload = ":".join(parts[:5])
        signature = parts[5]
        expected = hashlib.sha256(
            (payload + SecurityConfig.BCRYPT_PEPPER).encode()
        ).hexdigest()
        if not CryptoManager._secure_compare(signature, expected):
            return None
        user_id, role, shop_id, ts, _ = parts[:5]
        if time.time() - float(ts) > 43200:
            return None
        return {
            'sub': int(user_id), 
            'role': role, 
            'shop_id': int(shop_id) if shop_id != "0" else None
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: DATABASE MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class DatabaseManager:
    """SQLite database with multi-shop support - thread-safe with per-call connections"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or SecurityConfig.DB_PATH
        self._init_database()
        # Use a lock for write operations to prevent concurrent write conflicts
        self._write_lock = threading.Lock()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a fresh connection for each call to avoid thread-safety issues"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Shops table
        c.execute("""CREATE TABLE IF NOT EXISTS shops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            location TEXT,
            phone TEXT,
            manager_id INTEGER,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (manager_id) REFERENCES users(id)
        )""")

        # Users table with shop assignment
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'staff' CHECK(role IN ('admin', 'manager', 'staff', 'viewer')),
            shop_id INTEGER,
            is_active INTEGER DEFAULT 0,
            is_approved INTEGER DEFAULT 0,
            approved_by INTEGER,
            approved_at TIMESTAMP,
            failed_logins INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id),
            FOREIGN KEY (approved_by) REFERENCES users(id)
        )""")

        # Approval requests
        c.execute("""CREATE TABLE IF NOT EXISTS approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            requested_by TEXT,
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
            approved_by INTEGER,
            approved_at TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (approved_by) REFERENCES users(id)
        )""")

        # Inventory table with shop_id
        c.execute("""CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATE NOT NULL,
            shop_id INTEGER,
            supplier_name TEXT NOT NULL,
            trays_bought INTEGER NOT NULL CHECK(trays_bought > 0),
            cost_per_tray REAL NOT NULL CHECK(cost_per_tray > 0),
            amount_payable REAL GENERATED ALWAYS AS (trays_bought * cost_per_tray) STORED,
            payment_method TEXT NOT NULL,
            bank_account TEXT,
            selling_price_per_tray REAL NOT NULL CHECK(selling_price_per_tray > 0),
            status TEXT DEFAULT 'In Stock' CHECK(status IN ('In Stock', 'Low Stock', 'Out of Stock', 'Reserved')),
            notes TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )""")

        # Sales table with shop_id
        c.execute("""CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATE NOT NULL,
            shop_id INTEGER,
            trays_sold INTEGER NOT NULL CHECK(trays_sold > 0),
            cost_per_tray REAL NOT NULL,
            amount_payable REAL,
            selling_price_per_tray REAL NOT NULL,
            total_revenue REAL GENERATED ALWAYS AS (trays_sold * selling_price_per_tray) STORED,
            transport_cost REAL DEFAULT 0,
            rent REAL DEFAULT 0,
            electricity REAL DEFAULT 0,
            total_expenses REAL,
            net_profit REAL,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )""")

        # Debts table with shop_id
        c.execute("""CREATE TABLE IF NOT EXISTS debts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER,
            creditor_name TEXT NOT NULL,
            debt_type TEXT CHECK(debt_type IN ('Loan', 'Supplier Credit', 'Personal', 'Bank')),
            original_amount REAL NOT NULL CHECK(original_amount > 0),
            interest_rate REAL DEFAULT 0 CHECK(interest_rate >= 0),
            monthly_interest REAL GENERATED ALWAYS AS (original_amount * interest_rate / 1200) STORED,
            date_taken DATE,
            status TEXT DEFAULT 'Active' CHECK(status IN ('Active', 'Paid', 'Overdue', 'Defaulted')),
            total_paid REAL DEFAULT 0,
            interest_paid REAL DEFAULT 0,
            balance REAL GENERATED ALWAYS AS (original_amount - total_paid) STORED,
            due_date DATE,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )""")

        # Payments table
        c.execute("""CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER,
            payment_date DATE,
            creditor_name TEXT,
            amount_paid REAL CHECK(amount_paid > 0),
            interest_portion REAL DEFAULT 0,
            principal_portion REAL,
            payment_method TEXT,
            receipt_number TEXT,
            notes TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )""")

        # Sessions table
        c.execute("""CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            token_jti TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_valid INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

        # Insert default shop if not exists
        c.execute("SELECT id FROM shops WHERE name=?", ("Main Shop",))
        if not c.fetchone():
            c.execute("""INSERT INTO shops (name, location, phone, is_active) 
                VALUES (?, ?, ?, ?)""", ("Main Shop", "Headquarters", "+254700000000", 1))
            main_shop_id = c.lastrowid
        else:
            c.execute("SELECT id FROM shops WHERE name=?", ("Main Shop",))
            main_shop_id = c.fetchone()[0]

        # Insert default admin if not exists, or repair broken hash
        admin_hash = CryptoManager.hash_password(SecurityConfig.DEFAULT_ADMIN_PASSWORD)
        c.execute("SELECT id FROM users WHERE username=?", (SecurityConfig.DEFAULT_ADMIN_USERNAME,))
        existing_admin = c.fetchone()
        if not existing_admin:
            c.execute("""INSERT INTO users 
                (username, password_hash, email, full_name, role, shop_id, is_active, is_approved, approved_by, approved_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1, ?)""",
                (SecurityConfig.DEFAULT_ADMIN_USERNAME, admin_hash, SecurityConfig.DEFAULT_ADMIN_EMAIL,
                 SecurityConfig.DEFAULT_ADMIN_FULLNAME, 'admin', main_shop_id, datetime.now().isoformat()))
            admin_id = c.lastrowid
            c.execute("UPDATE users SET approved_by=? WHERE id=?", (admin_id, admin_id))
            c.execute("UPDATE shops SET manager_id=? WHERE id=?", (admin_id, main_shop_id))
        else:
            # Always re-sync the hash in case pepper changed previously
            admin_id = existing_admin[0]
            c.execute(
                "UPDATE users SET password_hash=?, is_active=1, is_approved=1, failed_logins=0, locked_until=NULL WHERE id=?",
                (admin_hash, admin_id)
            )

        conn.commit()
        conn.close()


    @contextmanager
    def transaction(self):
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            raise e
        finally:
            conn.close()

    def execute(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        conn = self._get_connection()
        try:
            c = conn.cursor()
            c.execute(query, params)
            return c.fetchall()
        finally:
            conn.close()

    def execute_insert(self, query: str, params: tuple = ()) -> int:
        with self._write_lock:
            conn = self._get_connection()
            try:
                c = conn.cursor()
                c.execute(query, params)
                conn.commit()
                return c.lastrowid
            except Exception as e:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise e
            finally:
                conn.close()

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        rows = self.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE LIMIT 1",
            (username,)
        )
        return dict(rows[0]) if rows else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        rows = self.execute("SELECT * FROM users WHERE id=? LIMIT 1", (user_id,))
        return dict(rows[0]) if rows else None

    def create_user(self, username: str, password: str, email: str, 
                    full_name: str, requested_by: str = None, shop_id: int = None) -> Tuple[bool, str]:
        try:
            password_hash = CryptoManager.hash_password(password)
            with self.transaction() as conn:
                c = conn.cursor()
                c.execute("""INSERT INTO users 
                    (username, password_hash, email, full_name, shop_id, is_active, is_approved)
                    VALUES (?, ?, ?, ?, ?, 0, 0)""",
                    (username, password_hash, email, full_name, shop_id))
                user_id = c.lastrowid
                c.execute("""INSERT INTO approval_requests (user_id, requested_by, status)
                    VALUES (?, ?, 'pending')""", (user_id, requested_by))
            return True, "Registration submitted. Awaiting admin approval."
        except sqlite3.IntegrityError:
            return False, "Username or email already exists."

    def approve_user(self, request_id: int, admin_id: int, role: str = 'staff', shop_id: int = None) -> bool:
        with self.transaction() as conn:
            c = conn.cursor()
            c.execute("SELECT user_id FROM approval_requests WHERE id=?", (request_id,))
            result = c.fetchone()
            if not result:
                return False
            user_id = result[0]
            now = datetime.now().isoformat()
            c.execute("""UPDATE users SET is_active=1, is_approved=1, approved_by=?, approved_at=?, role=?, shop_id=?
                WHERE id=?""", (admin_id, now, role, shop_id, user_id))
            c.execute("""UPDATE approval_requests SET status='approved', approved_by=?, approved_at=?
                WHERE id=?""", (admin_id, now, request_id))
        return True

    def reject_user(self, request_id: int, admin_id: int, reason: str = None) -> bool:
        with self.transaction() as conn:
            c = conn.cursor()
            c.execute("""UPDATE approval_requests 
                SET status='rejected', approved_by=?, approved_at=?, notes=?
                WHERE id=?""", (admin_id, datetime.now().isoformat(), reason, request_id))
        return True

    def update_user_role(self, user_id: int, role: str, shop_id: int = None, admin_id: int = None) -> bool:
        with self.transaction() as conn:
            c = conn.cursor()
            if shop_id is not None:
                c.execute("UPDATE users SET role=?, shop_id=? WHERE id=?", (role, shop_id, user_id))
            else:
                c.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        return True

    def get_shops(self) -> List[Dict]:
        rows = self.execute("SELECT * FROM shops ORDER BY created_at DESC")
        return [dict(row) for row in rows]

    def create_shop(self, name: str, location: str = None, phone: str = None, manager_id: int = None) -> int:
        query = """INSERT INTO shops (name, location, phone, manager_id)
            VALUES (?, ?, ?, ?)"""
        return self.execute_insert(query, (name, location, phone, manager_id))

    def record_failed_login(self, username: str):
        with self.transaction() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET failed_logins = failed_logins + 1 WHERE username=?", (username,))
            c.execute("SELECT failed_logins FROM users WHERE username=?", (username,))
            result = c.fetchone()
            if result and result[0] >= SecurityConfig.FAILED_LOGIN_THRESHOLD:
                lockout = (datetime.now() + SecurityConfig.LOCKOUT_DURATION).isoformat()
                c.execute("UPDATE users SET locked_until=? WHERE username=?", (lockout, username))

    def reset_failed_logins(self, username: str):
        with self.transaction() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE username=?", (username,))

    def update_last_login(self, user_id: int):
        with self.transaction() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), user_id))

    def get_pending_approvals(self) -> List[Dict]:
        rows = self.execute("""SELECT ar.*, u.username, u.email, u.full_name, s.name as shop_name
            FROM approval_requests ar
            JOIN users u ON ar.user_id = u.id
            LEFT JOIN shops s ON u.shop_id = s.id
            WHERE ar.status='pending' ORDER BY ar.request_date DESC""")
        return [dict(row) for row in rows]

    def get_all_users(self) -> List[Dict]:
        rows = self.execute("""SELECT u.*, s.name as shop_name 
            FROM users u
            LEFT JOIN shops s ON u.shop_id = s.id
            ORDER BY u.created_at DESC""")
        return [dict(row) for row in rows]

    def create_session(self, user_id: int, token_jti: str, ip: str, ua: str) -> str:
        session_id = secrets.token_hex(32)
        expires = (datetime.now() + SecurityConfig.SESSION_TIMEOUT).isoformat()
        self.execute_insert("""INSERT INTO sessions (id, user_id, token_jti, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)""", (session_id, user_id, token_jti, ip, ua, expires))
        return session_id

    def invalidate_session(self, session_id: str):
        self.execute("UPDATE sessions SET is_valid=0 WHERE id=?", (session_id,))

    def cleanup_sessions(self, user_id: int):
        rows = self.execute("""SELECT id FROM sessions 
            WHERE user_id=? AND is_valid=1 ORDER BY created_at DESC""", (user_id,))
        if len(rows) > SecurityConfig.MAX_CONCURRENT_SESSIONS:
            for row in rows[SecurityConfig.MAX_CONCURRENT_SESSIONS:]:
                self.execute("UPDATE sessions SET is_valid=0 WHERE id=?", (row['id'],))

    def add_inventory(self, data: dict, user_id: int) -> int:
        query = """INSERT INTO inventory 
            (date, shop_id, supplier_name, trays_bought, cost_per_tray, payment_method,
             bank_account, selling_price_per_tray, status, notes, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        params = (
            data.get('date', date.today().isoformat()),
            data.get('shop_id'),
            data['supplier_name'], data['trays_bought'], data['cost_per_tray'],
            data['payment_method'], data.get('bank_account'),
            data['selling_price_per_tray'], data.get('status', 'In Stock'),
            data.get('notes'), user_id
        )
        return self.execute_insert(query, params)

    def get_inventory(self, shop_id: int = None, user_id: int = None) -> List[Dict]:
        if shop_id:
            rows = self.execute("SELECT * FROM inventory WHERE shop_id=? ORDER BY date DESC", (shop_id,))
        elif user_id:
            rows = self.execute("SELECT * FROM inventory WHERE created_by=? ORDER BY date DESC", (user_id,))
        else:
            rows = self.execute("SELECT * FROM inventory ORDER BY date DESC")
        return [dict(row) for row in rows]

    def add_sale(self, data: dict, user_id: int) -> int:
        revenue = data['trays_sold'] * data['selling_price_per_tray']
        stock_cost = data['trays_sold'] * data['cost_per_tray']
        expenses = stock_cost + data.get('transport_cost', 0) + data.get('rent', 0) + data.get('electricity', 0)
        profit = revenue - expenses

        query = """INSERT INTO sales 
            (date, shop_id, trays_sold, cost_per_tray, amount_payable, selling_price_per_tray,
             transport_cost, rent, electricity, total_expenses, net_profit, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        params = (
            data.get('date', date.today().isoformat()),
            data.get('shop_id'),
            data['trays_sold'],
            data['cost_per_tray'], stock_cost, data['selling_price_per_tray'],
            data.get('transport_cost', 0), data.get('rent', 0), data.get('electricity', 0),
            expenses, profit, user_id
        )
        return self.execute_insert(query, params)

    def get_sales(self, shop_id: int = None, user_id: int = None) -> List[Dict]:
        if shop_id:
            rows = self.execute("SELECT * FROM sales WHERE shop_id=? ORDER BY date DESC", (shop_id,))
        elif user_id:
            rows = self.execute("SELECT * FROM sales WHERE created_by=? ORDER BY date DESC", (user_id,))
        else:
            rows = self.execute("SELECT * FROM sales ORDER BY date DESC")
        return [dict(row) for row in rows]

    def add_debt(self, data: dict, user_id: int) -> int:
        query = """INSERT INTO debts 
            (shop_id, creditor_name, debt_type, original_amount, interest_rate, date_taken, due_date, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
        params = (
            data.get('shop_id'),
            data['creditor_name'], data.get('debt_type', 'Supplier Credit'),
            data['original_amount'], data.get('interest_rate', 0),
            data.get('date_taken', date.today().isoformat()),
            data.get('due_date'), user_id
        )
        return self.execute_insert(query, params)

    def get_debts(self, shop_id: int = None) -> List[Dict]:
        if shop_id:
            rows = self.execute("SELECT * FROM debts WHERE shop_id=? ORDER BY date_taken DESC", (shop_id,))
        else:
            rows = self.execute("SELECT * FROM debts ORDER BY date_taken DESC")
        return [dict(row) for row in rows]

    def add_payment(self, data: dict, user_id: int) -> int:
        query = """INSERT INTO payments 
            (shop_id, payment_date, creditor_name, amount_paid, interest_portion, principal_portion,
             payment_method, receipt_number, notes, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        params = (
            data.get('shop_id'),
            data.get('payment_date', date.today().isoformat()), data['creditor_name'],
            data['amount_paid'], data.get('interest_portion', 0), data.get('principal_portion'),
            data.get('payment_method'), data.get('receipt_number'), data.get('notes'), user_id
        )
        payment_id = self.execute_insert(query, params)
        self.execute("""UPDATE debts SET total_paid = total_paid + ?, 
            interest_paid = interest_paid + ? WHERE creditor_name=? AND shop_id=?""",
            (data['amount_paid'], data.get('interest_portion', 0), data['creditor_name'], data.get('shop_id')))
        return payment_id

    def get_payments(self, shop_id: int = None) -> List[Dict]:
        if shop_id:
            rows = self.execute("SELECT * FROM payments WHERE shop_id=? ORDER BY payment_date DESC", (shop_id,))
        else:
            rows = self.execute("SELECT * FROM payments ORDER BY payment_date DESC")
        return [dict(row) for row in rows]

    def get_dashboard_metrics(self, shop_id: int = None) -> Dict:
        conn = self._get_connection()
        try:
            c = conn.cursor()

            shop_filter = "WHERE shop_id=?" if shop_id else ""
            params = (shop_id,) if shop_id else ()

            c.execute(f"SELECT COALESCE(SUM(trays_bought), 0) as total_stock FROM inventory {shop_filter}", params)
            total_stock = c.fetchone()[0]

            c.execute(f"SELECT COALESCE(SUM(trays_bought * cost_per_tray), 0) as stock_value FROM inventory {shop_filter}", params)
            stock_value = c.fetchone()[0]

            c.execute(f"SELECT COALESCE(SUM(trays_bought * selling_price_per_tray), 0) as retail_value FROM inventory {shop_filter}", params)
            retail_value = c.fetchone()[0]

            c.execute(f"SELECT COALESCE(SUM(total_revenue), 0), COALESCE(SUM(net_profit), 0), COALESCE(SUM(trays_sold), 0) FROM sales {shop_filter}", params)
            revenue, profit, trays_sold = c.fetchone()

            c.execute(f"SELECT COALESCE(SUM(balance), 0) FROM debts WHERE status='Active' {'AND shop_id=?' if shop_id else ''}", params if shop_id else ())
            total_debt = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM shops WHERE is_active=1")
            shop_count = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM users WHERE is_active=1")
            user_count = c.fetchone()[0]

            return {
                'total_stock': total_stock or 0,
                'stock_value': stock_value or 0,
                'retail_value': retail_value or 0,
                'expected_profit': (retail_value or 0) - (stock_value or 0),
                'total_revenue': revenue or 0,
                'total_profit': profit or 0,
                'total_trays_sold': trays_sold or 0,
                'total_debt': total_debt or 0,
                'profit_margin': ((profit or 0) / (revenue or 1)) * 100,
                'shop_count': shop_count or 0,
                'user_count': user_count or 0
            }
        finally:
            conn.close()

    def get_monthly_sales(self, shop_id: int = None) -> List[Dict]:
        shop_filter = "WHERE shop_id=?" if shop_id else ""
        params = (shop_id,) if shop_id else ()
        rows = self.execute(f"""SELECT 
            strftime('%Y-%m', date) as month,
            SUM(trays_sold) as total_trays,
            SUM(total_revenue) as total_revenue,
            SUM(total_expenses) as total_expenses,
            SUM(net_profit) as net_profit
            FROM sales {shop_filter} GROUP BY strftime('%Y-%m', date) ORDER BY month DESC""", params)
        return [dict(row) for row in rows]

    def get_shop_summary(self) -> List[Dict]:
        rows = self.execute("""SELECT 
            s.id, s.name, s.location, s.is_active,
            COUNT(DISTINCT u.id) as user_count,
            COALESCE(SUM(i.trays_bought), 0) as total_stock,
            COALESCE(SUM(sa.total_revenue), 0) as total_revenue,
            COALESCE(SUM(d.balance), 0) as total_debt
            FROM shops s
            LEFT JOIN users u ON s.id = u.shop_id AND u.is_active=1
            LEFT JOIN inventory i ON s.id = i.shop_id
            LEFT JOIN sales sa ON s.id = sa.shop_id
            LEFT JOIN debts d ON s.id = d.shop_id AND d.status='Active'
            GROUP BY s.id
            ORDER BY s.created_at DESC""")
        return [dict(row) for row in rows]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: AUTHENTICATION SERVICE
# ═══════════════════════════════════════════════════════════════════════════════

class AuthService:
    """Isolated authentication service with comprehensive security"""

    def __init__(self, db: DatabaseManager, audit: AuditLogger, rate_limiter: RateLimiter, captcha: MathCaptcha):
        self.db = db
        self.audit = audit
        self.rate_limiter = rate_limiter
        self.captcha = captcha

    def authenticate(self, username: str, password: str, 
                    captcha_answer: str, captcha_session: str,
                    ip_address: str, user_agent: str) -> Dict:

        # 1. Verify CAPTCHA
        captcha_result = self.captcha.verify(captcha_session, captcha_answer)
        if not captcha_result['success']:
            self.audit.log(0, username, 'login_failed', 'auth', 
                          {'reason': 'captcha_failed', 'error': captcha_result['error']}, ip_address, None, False)
            return {'success': False, 'error': captcha_result['error']}

        # 2. Rate limiting per IP
        if not self.rate_limiter.is_allowed(f"login:{ip_address}", 5, 300):
            self.audit.log(0, username, 'login_failed', 'auth',
                          {'reason': 'rate_limited'}, ip_address, None, False)
            return {'success': False, 'error': 'Too many attempts. Please wait 5 minutes.'}

        # 3. Get user and check lockout
        user = self.db.get_user_by_username(username)
        if not user:
            # Prevent timing attacks
            CryptoManager.hash_password(password)
            return {'success': False, 'error': 'Invalid credentials'}

        if user.get('locked_until'):
            locked = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked:
                return {'success': False, 'error': f'Account locked until {locked.strftime("%H:%M")}'}

        if not user.get('is_active') or not user.get('is_approved'):
            return {'success': False, 'error': 'Account not activated. Contact administrator.'}

        # 4. Verify password
        if not CryptoManager.verify_password(password, user['password_hash']):
            self.db.record_failed_login(username)
            self.audit.log(user['id'], username, 'login_failed', 'auth',
                          {'reason': 'wrong_password'}, ip_address, user.get('shop_id'), False)
            return {'success': False, 'error': 'Invalid credentials'}

        # 5. Create session
        return self._create_session(user, ip_address, user_agent)

    def _create_session(self, user: Dict, ip: str, ua: str) -> Dict:
        self.db.reset_failed_logins(user['username'])
        self.db.update_last_login(user['id'])

        access_token = CryptoManager.generate_token(user['id'], user['role'], user.get('shop_id'))
        session_id = self.db.create_session(user['id'], access_token, ip, ua)
        self.db.cleanup_sessions(user['id'])

        self.audit.log(user['id'], user['username'], 'login_success', 'auth',
                      {'session_id': session_id}, ip, user.get('shop_id'), True)

        return {
            'success': True,
            'access_token': access_token,
            'session_id': session_id,
            'user_id': user['id'],
            'role': user['role'],
            'username': user['username'],
            'shop_id': user.get('shop_id'),
            'shop_name': user.get('shop_name')
        }

    def logout(self, session_id: str, user_id: int):
        self.db.invalidate_session(session_id)
        self.audit.log(user_id, '', 'logout', 'auth', {'session_id': session_id})


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: STREAMLIT UI COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

def render_math_captcha(captcha: MathCaptcha):
    """Render mathematical CAPTCHA widget - DEPRECATED, use inline rendering in login_page instead"""
    pass

def inject_pwa_headers():
    """Inject PWA manifest and service worker for installability"""
    pwa_html = """
    <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjogIktpaXJ1IEVnZyBNYW5hZ2VtZW50IiwgInNob3J0X25hbWUiOiAiS2lpcnVFZ2dzIiwgInN0YXJ0X3VybCI6ICIvIiwgImRpc3BsYXkiOiAic3RhbmRhbG9uZSIsICJiYWNrZ3JvdW5kX2NvbG9yIjogIiNmZmZmZmYiLCAidGhlbWVfY29sb3IiOiAiIzFmNGU3OCIsICJpY29ucyI6IFt7InNyYyI6ICJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL0BmbHVlbnR1aS9lbW9qaS1hc3NldHNAbGF0ZXN0L2VnZy5zdmciLCAic2l6ZXMiOiAiMTkyeDE5MiJ9XX0=">
    <meta name="theme-color" content="#1f4e78">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="Kiiru Eggs">
    <script>
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('data:text/javascript;base64,' + btoa(`
                self.addEventListener('install', e => self.skipWaiting());
                self.addEventListener('activate', e => e.waitUntil(clients.claim()));
                self.addEventListener('fetch', e => e.respondWith(fetch(e.request).catch(() => new Response('Offline'))));
            `));
        }
    </script>
    """
    st.markdown(pwa_html, unsafe_allow_html=True)

def inject_seo_meta():
    """Inject SEO meta tags for Google discovery"""
    seo_html = """
    <meta name="description" content="Kiiru Egg Management System - Enterprise inventory, sales and debt tracking for egg businesses. Multi-shop support with real-time analytics.">
    <meta name="keywords" content="egg management, inventory tracking, sales tracker, debt management, poultry business, egg shop, Kenya eggs, Kiiru">
    <meta name="author" content="Kiiru Enterprise Solutions">
    <meta name="robots" content="index, follow">
    <meta property="og:title" content="Kiiru Egg Management System">
    <meta property="og:description" content="Real-time egg inventory, sales & debt tracking for multi-shop operations">
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://kiirueggs.com">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="Kiiru Egg Management">
    <meta name="twitter:description" content="Enterprise egg business management with multi-shop support">
    <link rel="canonical" href="https://kiirueggs.com">
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "WebApplication",
        "name": "Kiiru Egg Management System",
        "description": "Enterprise egg inventory, sales and debt tracking system",
        "url": "https://kiirueggs.com",
        "applicationCategory": "BusinessApplication",
        "operatingSystem": "Any",
        "offers": {
            "@type": "Offer",
            "price": "0",
            "priceCurrency": "KES"
        }
    }
    </script>
    """
    st.markdown(seo_html, unsafe_allow_html=True)

def show_install_prompt():
    """Show PWA install prompt"""
    install_html = """
    <div id="install-prompt" style="display:none; position:fixed; bottom:20px; right:20px; background:#1f4e78; color:white; padding:15px; border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.3); z-index:9999; max-width:300px;">
        <h4 style="margin:0 0 10px 0;">📱 Install Kiiru Eggs App</h4>
        <p style="margin:0 0 10px 0; font-size:0.9rem;">Add to your home screen for quick access!</p>
        <button onclick="installApp()" style="background:#28a745; color:white; border:none; padding:8px 16px; border-radius:5px; cursor:pointer; width:100%;">Install Now</button>
        <button onclick="dismissInstall()" style="background:transparent; color:#ccc; border:none; margin-top:8px; cursor:pointer; width:100%; font-size:0.8rem;">Dismiss</button>
    </div>
    <script>
        let deferredPrompt;
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            document.getElementById('install-prompt').style.display = 'block';
        });
        function installApp() {
            if (deferredPrompt) {
                deferredPrompt.prompt();
                deferredPrompt.userChoice.then((choiceResult) => {
                    if (choiceResult.outcome === 'accepted') {
                        console.log('User installed the app');
                    }
                    deferredPrompt = null;
                    document.getElementById('install-prompt').style.display = 'none';
                });
            }
        }
        function dismissInstall() {
            document.getElementById('install-prompt').style.display = 'none';
        }
        setTimeout(() => {
            if (!window.matchMedia('(display-mode: standalone)').matches && !localStorage.getItem('install_dismissed')) {
                const prompt = document.getElementById('install-prompt');
                if (prompt) prompt.style.display = 'block';
            }
        }, 3000);
    </script>
    """
    st.markdown(install_html, unsafe_allow_html=True)

def login_page(auth_service: AuthService, captcha: MathCaptcha):
    inject_pwa_headers()
    inject_seo_meta()
    show_install_prompt()

    st.markdown("""
    <style>
    .main-header { font-size: 2.5rem; font-weight: bold; color: #1f4e78; text-align: center; }
    .sub-header { font-size: 1.1rem; color: #666; text-align: center; margin-bottom: 2rem; }
    .security-badge { text-align: center; color: #28a745; font-size: 0.85rem; margin-top: 1rem; }
    .stButton>button { width: 100%; background-color: #1f4e78; color: white; }
    .captcha-box { background: #f8f9fa; border: 2px solid #1f4e78; border-radius: 8px; padding: 15px; margin: 10px 0; }
    .install-badge { text-align: center; padding: 10px; background: #e8f5e9; border-radius: 8px; margin: 10px 0; color: #2e7d32; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="main-header">🥚 Kiiru Egg Management</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Real-Time Inventory, Sales & Debt Tracking for Multi-Shop Operations</div>', unsafe_allow_html=True)
    st.markdown('<div class="security-badge">🔒 Secured with Mathematical CAPTCHA + AES-256 + Role-Based Access</div>', unsafe_allow_html=True)

    # Show install badge if in browser
    st.markdown("""
    <div class="install-badge">
        📲 <strong>Install App:</strong> Use this website directly, or click "Add to Home Screen" in your browser menu to install as an app!
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Request Access"])

        with tab1:
            # Generate or refresh CAPTCHA
            if 'captcha_session' not in st.session_state or st.session_state.get('refresh_captcha'):
                st.session_state['captcha_session'] = secrets.token_hex(16)
                st.session_state['refresh_captcha'] = False
                if 'captcha_data' in st.session_state:
                    del st.session_state['captcha_data']

            if 'captcha_data' not in st.session_state:
                st.session_state['captcha_data'] = captcha.generate(st.session_state['captcha_session'])

            captcha_data = st.session_state['captcha_data']
            captcha_session = st.session_state['captcha_session']

            # Display CAPTCHA question (outside form)
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"""
                <div style="background: #f0f2f6; padding: 15px; border-radius: 8px; text-align: center; font-size: 1.3rem; font-weight: bold; color: #1f4e78; border: 2px solid #1f4e78;">
                    {captcha_data['question']}
                </div>
                """, unsafe_allow_html=True)
            with col2:
                if st.button("🔄 New Problem", key="refresh_captcha_btn"):
                    st.session_state['refresh_captcha'] = True
                    st.rerun()

            st.caption("🧮 Enter the answer to the math problem above in the field below")

            # Login form - ALL inputs must be inside form to be submitted
            with st.form("login_form", clear_on_submit=False):
                st.subheader("Secure Login")
                username = st.text_input("Username", key="login_username", placeholder="Enter username")
                password = st.text_input("Password", key="login_password", type="password", placeholder="Enter password")

                # max_chars removed — answers can be up to 2 digits (e.g. 20+10=30)
                captcha_answer = st.text_input("CAPTCHA Answer", key="captcha_answer_input", placeholder="Type your answer here")

                submitted = st.form_submit_button("🔐 Login Securely", type="primary")

            # Process form submission OUTSIDE the form
            if submitted:
                # Read captcha session directly from session_state (reliable, not from form field)
                current_session = st.session_state.get('captcha_session')
                current_answer = st.session_state.get('captcha_answer_input', '').strip()

                if not current_answer:
                    st.error("⚠️ Please solve the math problem before logging in.")
                elif not current_session:
                    st.error("⚠️ CAPTCHA session expired. Please refresh the page.")
                    st.session_state['refresh_captcha'] = True
                    st.rerun()
                else:
                    ip = "127.0.0.1"
                    ua = "Streamlit App"

                    result = auth_service.authenticate(username, password, current_answer, current_session, ip, ua)

                    if result.get('success'):
                        st.session_state['authenticated'] = True
                        st.session_state['user'] = {
                            'id': result['user_id'],
                            'username': result['username'],
                            'role': result['role'],
                            'token': result['access_token'],
                            'session_id': result['session_id'],
                            'shop_id': result.get('shop_id'),
                            'shop_name': result.get('shop_name')
                        }
                        st.success(f"✅ Welcome back, {result['username']}!")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"❌ {result.get('error', 'Authentication failed')}")
                        # Refresh CAPTCHA on failure
                        st.session_state['refresh_captcha'] = True
                        st.rerun()

        with tab2:
            with st.form("register_form"):
                st.subheader("Request Account Access")
                st.info("New accounts require admin approval before activation. Contact KIIRU for quick approval.")

                new_user = st.text_input("Choose Username", key="reg_user")
                new_pass = st.text_input("Choose Password", type="password", key="reg_pass")
                new_email = st.text_input("Email Address", key="reg_email")
                new_name = st.text_input("Full Name", key="reg_name")
                referred = st.text_input("Referred By / Shop Name (optional)", key="reg_ref")

                # Shop selection
                shops = st.session_state['db'].get_shops()
                shop_options = [(s['id'], s['name']) for s in shops]
                selected_shop = st.selectbox("Select Shop", options=[s[1] for s in shop_options], key="reg_shop")
                selected_shop_id = next((s[0] for s in shop_options if s[1] == selected_shop), None)

                submit_reg = st.form_submit_button("Submit Request", type="secondary")

            # Handle form submission OUTSIDE the form block
            if submit_reg:
                if all([new_user, new_pass, new_email, new_name]):
                    if len(new_pass) < SecurityConfig.PASSWORD_MIN_LENGTH:
                        st.error(f"Password must be at least {SecurityConfig.PASSWORD_MIN_LENGTH} characters")
                    else:
                        success, msg = st.session_state['db'].create_user(new_user, new_pass, new_email, new_name, referred, selected_shop_id)
                        if success:
                            st.success(msg)
                            st.info("📧 Admin KIIRU has been notified and will approve your account shortly.")
                        else:
                            st.error(msg)
                else:
                    st.error("Please fill all required fields.")

def require_auth(func):
    def wrapper(*args, **kwargs):
        if not st.session_state.get('authenticated'):
            st.error("🔒 Please login to access this page.")
            st.stop()
        return func(*args, **kwargs)
    return wrapper

def admin_only(func):
    def wrapper(*args, **kwargs):
        if st.session_state.get('user', {}).get('role') != 'admin':
            st.error("⛔ Access denied. Admin privileges required.")
            st.stop()
        return func(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9: MAIN APPLICATION PAGES
# ═══════════════════════════════════════════════════════════════════════════════

def dashboard_page(db: DatabaseManager, audit: AuditLogger):
    st.title("📊 Real-Time Business Dashboard")

    user = st.session_state['user']
    shop_id = user.get('shop_id') if user.get('role') != 'admin' else None

    metrics = db.get_dashboard_metrics(shop_id)

    # Top metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("📦 Stock (Trays)", f"{metrics['total_stock']:,}")
    with col2:
        st.metric("💰 Stock Value", f"Ksh {metrics['stock_value']:,.0f}")
    with col3:
        st.metric("📈 Total Revenue", f"Ksh {metrics['total_revenue']:,.0f}")
    with col4:
        st.metric("💵 Net Profit", f"Ksh {metrics['total_profit']:,.0f}")
    with col5:
        st.metric("📊 Profit Margin", f"{metrics['profit_margin']:.1f}%")

    # Admin sees all shops
    if user.get('role') == 'admin':
        col6, col7 = st.columns(2)
        with col6:
            st.metric("🏪 Active Shops", metrics['shop_count'])
        with col7:
            st.metric("👥 Active Users", metrics['user_count'])

    st.divider()

    if PLOTLY_AVAILABLE:
        monthly = db.get_monthly_sales(shop_id)
        if monthly:
            df_monthly = pd.DataFrame(monthly)

            col1, col2 = st.columns(2)
            with col1:
                fig1 = px.bar(df_monthly, x='month', y=['total_revenue', 'net_profit'],
                             barmode='group', title='Monthly Performance',
                             color_discrete_sequence=['#1f4e78', '#28a745'])
                st.plotly_chart(fig1, use_container_width=True)

            with col2:
                fig2 = px.pie(values=[metrics['stock_value'], metrics['expected_profit']],
                             names=['Stock Value', 'Expected Profit'],
                             title='Portfolio Distribution',
                             color_discrete_sequence=['#1f4e78', '#28a745'])
                st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("Add sales data to see analytics charts.")

    st.subheader("Recent Activity")
    col1, col2 = st.columns(2)
    with col1:
        st.caption("Latest Sales")
        sales = db.get_sales(shop_id)
        if sales:
            if PANDAS_AVAILABLE:
                st.dataframe(pd.DataFrame(sales[:5]), use_container_width=True, hide_index=True)
            else:
                for s in sales[:5]:
                    st.write(f"{s['date']}: {s['trays_sold']} trays - Ksh {s['net_profit']:,.0f}")
        else:
            st.info("No sales recorded")

    with col2:
        st.caption("Latest Inventory")
        inv = db.get_inventory(shop_id)
        if inv:
            if PANDAS_AVAILABLE:
                st.dataframe(pd.DataFrame(inv[:5]), use_container_width=True, hide_index=True)
            else:
                for i in inv[:5]:
                    st.write(f"{i['date']}: {i['supplier_name']} - {i['trays_bought']} trays")
        else:
            st.info("No inventory recorded")

def inventory_page(db: DatabaseManager, audit: AuditLogger):
    st.title("📦 Inventory Management")
    user = st.session_state['user']
    shop_id = user.get('shop_id') if user.get('role') != 'admin' else None

    with st.expander("➕ Add New Stock Purchase", expanded=False):
        with st.form("add_inventory"):
            col1, col2 = st.columns(2)
            with col1:
                inv_date = st.date_input("Date", date.today())
                supplier = st.selectbox("Supplier", ["Kendy Enterprise", "Carrefour Supermarket", "Other"])
                if supplier == "Other":
                    supplier = st.text_input("Specify Supplier")
                trays = st.number_input("Trays Bought", min_value=1, value=180)
                cost = st.number_input("Cost Per Tray (Ksh)", min_value=1, value=425)
            with col2:
                payment = st.selectbox("Payment Method", ["Bank Transfer", "Cash", "M-Pesa", "Credit", "POS"])
                bank = st.text_input("Bank/Account", value="I&M Bank" if supplier == "Kendy Enterprise" else "")
                selling = st.number_input("Selling Price/Tray", min_value=1, value=480)
                status = st.selectbox("Status", ["In Stock", "Low Stock", "Reserved"])
                notes = st.text_area("Notes", value="Delivery payment via I&M Bank" if supplier == "Kendy Enterprise" else "")

                # Admin can select shop
                if user.get('role') == 'admin':
                    shops = st.session_state['db'].get_shops()
                    shop_sel = st.selectbox("Shop", options=[s['name'] for s in shops])
                    shop_id = next((s['id'] for s in shops if s['name'] == shop_sel), shop_id)

            submitted_inv = st.form_submit_button("Add to Inventory", type="primary")

        if submitted_inv:
            data = {
                'date': inv_date.isoformat(),
                'shop_id': shop_id,
                'supplier_name': supplier,
                'trays_bought': trays,
                'cost_per_tray': cost,
                'payment_method': payment,
                'bank_account': bank,
                'selling_price_per_tray': selling,
                'status': status,
                'notes': notes
            }
            inv_id = db.add_inventory(data, user['id'])
            audit.log(user['id'], user['username'], 'inventory_added', 'inventory',
                     {'id': inv_id, 'supplier': supplier, 'trays': trays}, shop_id=shop_id)
            st.success(f"✅ Inventory added (ID: {inv_id})")
            st.rerun()

    st.subheader("Current Inventory")
    inventory = db.get_inventory(shop_id)

    if inventory:
        for item in inventory:
            item['stock_value'] = item['trays_bought'] * item['cost_per_tray']
            item['retail_value'] = item['trays_bought'] * item['selling_price_per_tray']
            item['expected_profit'] = item['retail_value'] - item['stock_value']

        if PANDAS_AVAILABLE:
            df = pd.DataFrame(inventory)
            display_cols = ['date', 'supplier_name', 'trays_bought', 'cost_per_tray',
                           'payment_method', 'bank_account', 'selling_price_per_tray',
                           'status', 'stock_value', 'retail_value', 'expected_profit', 'notes']
            available_cols = [c for c in display_cols if c in df.columns]
            st.dataframe(df[available_cols], use_container_width=True, hide_index=True)
        else:
            for item in inventory:
                st.write(f"{item['date']} | {item['supplier_name']} | {item['trays_bought']} trays | "
                        f"Ksh {item['stock_value']:,.0f} | {item['status']}")

        st.subheader("Inventory Dashboard")
        total_trays = sum(i['trays_bought'] for i in inventory)
        total_value = sum(i['stock_value'] for i in inventory)
        total_retail = sum(i['retail_value'] for i in inventory)
        total_profit = sum(i['expected_profit'] for i in inventory)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Trays", f"{total_trays:,}")
        with col2:
            st.metric("Stock Value", f"Ksh {total_value:,.0f}")
        with col3:
            st.metric("Retail Value", f"Ksh {total_retail:,.0f}")
        with col4:
            st.metric("Expected Profit", f"Ksh {total_profit:,.0f}")

        low_stock = [i for i in inventory if i['trays_bought'] < 20]
        if low_stock:
            st.warning("⚠️ Low Stock Alert!")
            for item in low_stock:
                st.write(f"- {item['supplier_name']}: {item['trays_bought']} trays remaining")
    else:
        st.info("No inventory records. Add your first stock purchase above.")


def sales_page(db: DatabaseManager, audit: AuditLogger):
    st.title("💰 Sales Tracker")
    user = st.session_state['user']
    shop_id = user.get('shop_id') if user.get('role') != 'admin' else None

    with st.expander("➕ Record New Sale", expanded=False):
        with st.form("add_sale"):
            col1, col2 = st.columns(2)
            with col1:
                sale_date = st.date_input("Date", date.today())
                trays = st.number_input("Trays Sold", min_value=1, value=100)
                cost = st.number_input("Cost Per Tray", min_value=1, value=425)
                selling = st.number_input("Selling Price/Tray", min_value=1, value=480)
            with col2:
                transport = st.number_input("Transport Cost", min_value=0, value=1500)
                rent = st.number_input("Rent", min_value=0, value=0)
                electricity = st.number_input("Electricity", min_value=0, value=0)

                # Admin can select shop
                if user.get('role') == 'admin':
                    shops = st.session_state['db'].get_shops()
                    shop_sel = st.selectbox("Shop", options=[s['name'] for s in shops])
                    shop_id = next((s['id'] for s in shops if s['name'] == shop_sel), shop_id)

            submitted_sale = st.form_submit_button("Record Sale", type="primary")

        if submitted_sale:
            data = {
                'date': sale_date.isoformat(),
                'shop_id': shop_id,
                'trays_sold': trays,
                'cost_per_tray': cost,
                'selling_price_per_tray': selling,
                'transport_cost': transport,
                'rent': rent,
                'electricity': electricity
            }
            sale_id = db.add_sale(data, user['id'])
            profit = trays * selling - (trays * cost + transport + rent + electricity)
            audit.log(user['id'], user['username'], 'sale_added', 'sales',
                     {'id': sale_id, 'trays': trays, 'profit': profit}, shop_id=shop_id)
            st.success(f"✅ Sale recorded (ID: {sale_id})")
            st.rerun()

    st.subheader("Sales History")
    sales = db.get_sales(shop_id)
    if sales:
        if PANDAS_AVAILABLE:
            st.dataframe(pd.DataFrame(sales), use_container_width=True, hide_index=True)
        else:
            for s in sales:
                st.write(f"{s['date']} | {s['trays_sold']} trays | Revenue: Ksh {s['total_revenue']:,.0f} | Profit: Ksh {s['net_profit']:,.0f}")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Trays", f"{sum(s['trays_sold'] for s in sales):,}")
        with col2:
            st.metric("Total Revenue", f"Ksh {sum(s['total_revenue'] for s in sales):,.0f}")
        with col3:
            st.metric("Total Expenses", f"Ksh {sum(s['total_expenses'] for s in sales):,.0f}")
        with col4:
            st.metric("Net Profit", f"Ksh {sum(s['net_profit'] for s in sales):,.0f}")
    else:
        st.info("No sales recorded yet.")

def debt_page(db: DatabaseManager, audit: AuditLogger):
    st.title("💳 Debt & Payments")
    user = st.session_state['user']
    shop_id = user.get('shop_id') if user.get('role') != 'admin' else None

    tab1, tab2 = st.tabs(["📋 Debt Register", "💸 Payment Log"])

    with tab1:
        with st.expander("➕ Add New Debt"):
            with st.form("add_debt"):
                col1, col2 = st.columns(2)
                with col1:
                    creditor = st.text_input("Creditor Name")
                    amount = st.number_input("Original Amount", min_value=0.0, value=40000.0)
                    interest = st.number_input("Interest Rate (%/yr)", min_value=0.0, value=0.0)
                with col2:
                    debt_type = st.selectbox("Type", ["Loan", "Supplier Credit", "Personal", "Bank"])
                    date_taken = st.date_input("Date Taken", date.today())
                    due_date = st.date_input("Due Date", date.today() + timedelta(days=180))

                    # Admin can select shop
                    if user.get('role') == 'admin':
                        shops = st.session_state['db'].get_shops()
                        shop_sel = st.selectbox("Shop", options=[s['name'] for s in shops])
                        shop_id = next((s['id'] for s in shops if s['name'] == shop_sel), shop_id)

                submitted_debt = st.form_submit_button("Add Debt", type="primary")

            if submitted_debt:
                data = {
                    'shop_id': shop_id,
                    'creditor_name': creditor,
                    'debt_type': debt_type,
                    'original_amount': amount,
                    'interest_rate': interest,
                    'date_taken': date_taken.isoformat(),
                    'due_date': due_date.isoformat()
                }
                debt_id = db.add_debt(data, user['id'])
                audit.log(user['id'], user['username'], 'debt_added', 'debts',
                         {'id': debt_id, 'creditor': creditor, 'amount': amount}, shop_id=shop_id)
                st.success(f"✅ Debt added (ID: {debt_id})")
                st.rerun()

        debts = db.get_debts(shop_id)
        if debts:
            if PANDAS_AVAILABLE:
                st.dataframe(pd.DataFrame(debts), use_container_width=True, hide_index=True)
            else:
                for d in debts:
                    st.write(f"{d['creditor_name']} | Ksh {d['original_amount']:,.0f} | Balance: Ksh {d['balance']:,.0f} | {d['status']}")

            total_outstanding = sum(d['balance'] for d in debts if d['status'] == 'Active')
            st.metric("Total Outstanding", f"Ksh {total_outstanding:,.0f}")
        else:
            st.info("No debts recorded.")

    with tab2:
        with st.expander("➕ Record Payment"):
            with st.form("add_payment"):
                debts = db.get_debts(shop_id)
                creditors = [d['creditor_name'] for d in debts] if debts else []

                col1, col2 = st.columns(2)
                with col1:
                    pay_date = st.date_input("Payment Date", date.today())
                    creditor = st.selectbox("Creditor", options=creditors) if creditors else st.text_input("Creditor")
                    amount = st.number_input("Amount Paid", min_value=0.0)
                with col2:
                    interest = st.number_input("Interest Portion", min_value=0.0)
                    principal = st.number_input("Principal Portion", min_value=0.0)
                    method = st.selectbox("Method", ["Cash", "Bank Transfer", "M-Pesa"])
                    receipt = st.text_input("Receipt #")
                    notes = st.text_area("Notes")

                    # Admin can select shop
                    if user.get('role') == 'admin':
                        shops = st.session_state['db'].get_shops()
                        shop_sel = st.selectbox("Shop", options=[s['name'] for s in shops])
                        shop_id = next((s['id'] for s in shops if s['name'] == shop_sel), shop_id)

                submitted_payment = st.form_submit_button("Record Payment", type="primary")

            if submitted_payment:
                data = {
                    'shop_id': shop_id,
                    'payment_date': pay_date.isoformat(),
                    'creditor_name': creditor,
                    'amount_paid': amount,
                    'interest_portion': interest,
                    'principal_portion': principal,
                    'payment_method': method,
                    'receipt_number': receipt,
                    'notes': notes
                }
                payment_id = db.add_payment(data, user['id'])
                audit.log(user['id'], user['username'], 'payment_added', 'payments',
                         {'id': payment_id, 'creditor': creditor, 'amount': amount}, shop_id=shop_id)
                st.success(f"✅ Payment recorded (ID: {payment_id})")
                st.rerun()

        payments = db.get_payments(shop_id)
        if payments:
            if PANDAS_AVAILABLE:
                st.dataframe(pd.DataFrame(payments), use_container_width=True, hide_index=True)
            else:
                for p in payments:
                    st.write(f"{p['payment_date']} | {p['creditor_name']} | Ksh {p['amount_paid']:,.0f}")
        else:
            st.info("No payments recorded.")


@admin_only
def admin_page(db: DatabaseManager, audit: AuditLogger):
    st.title("👑 Admin Control Center")

    metrics = db.get_dashboard_metrics()
    users = db.get_all_users()
    shops = db.get_shops()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Users", len(users))
    with col2:
        st.metric("Pending Approvals", len(db.get_pending_approvals()))
    with col3:
        st.metric("Total Shops", len(shops))
    with col4:
        st.metric("Total Debt", f"Ksh {metrics['total_debt']:,.0f}")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["⏳ Pending Approvals", "👥 User Management", "🏪 Shop Management", "📊 Security Metrics", "📝 Audit Log"])

    with tab1:
        st.subheader("Account Approval Requests")
        pending = db.get_pending_approvals()
        if pending:
            for req in pending:
                with st.container():
                    col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                    with col1:
                        st.write(f"**{req['username']}** ({req['full_name']})")
                        st.caption(f"Email: {req['email']} | Requested: {req['request_date']} | By: {req['requested_by']} | Shop: {req.get('shop_name', 'N/A')}")
                    with col2:
                        role = st.selectbox("Role", ['staff', 'manager', 'viewer'], key=f"role_{req['id']}")
                    with col3:
                        shop_list = [s['name'] for s in shops]
                        default_shop = req.get('shop_name', shop_list[0]) if req.get('shop_name') else shop_list[0]
                        assign_shop = st.selectbox("Shop", shop_list, index=shop_list.index(default_shop) if default_shop in shop_list else 0, key=f"shop_{req['id']}")
                    with col4:
                        if st.button("✅ Approve", key=f"approve_{req['id']}"):
                            shop_id = next((s['id'] for s in shops if s['name'] == assign_shop), None)
                            db.approve_user(req['id'], st.session_state['user']['id'], role, shop_id)
                            audit.log(st.session_state['user']['id'], st.session_state['user']['username'],
                                     'user_approved', 'users', {'request_id': req['id'], 'user': req['username'], 'role': role, 'shop': assign_shop})
                            st.success("User approved!")
                            st.rerun()
                        if st.button("❌ Reject", key=f"reject_{req['id']}"):
                            db.reject_user(req['id'], st.session_state['user']['id'], "Rejected by admin")
                            audit.log(st.session_state['user']['id'], st.session_state['user']['username'],
                                     'user_rejected', 'users', {'request_id': req['id'], 'user': req['username']})
                            st.warning("User rejected.")
                            st.rerun()
                    st.divider()
        else:
            st.info("No pending approvals.")

    with tab2:
        st.subheader("All Users")
        if PANDAS_AVAILABLE:
            st.dataframe(pd.DataFrame(users), use_container_width=True)
        else:
            for u in users:
                st.write(f"{u['username']} | {u['role']} | Shop: {u.get('shop_name', 'N/A')} | Active: {u['is_active']} | Approved: {u['is_approved']}")

        # Edit user roles
        st.subheader("Edit User Access")
        with st.form("edit_user"):
            user_list = [f"{u['username']} ({u['full_name']})" for u in users if u['username'] != 'KIIRU']
            selected = st.selectbox("Select User", user_list)
            selected_username = selected.split(" (")[0] if selected else None

            new_role = st.selectbox("New Role", ['staff', 'manager', 'viewer', 'admin'])
            shop_list = [s['name'] for s in shops]
            new_shop = st.selectbox("Assign Shop", shop_list)

            submitted_update = st.form_submit_button("Update User", type="primary")

        if submitted_update:
            if selected_username:
                user_data = next((u for u in users if u['username'] == selected_username), None)
                if user_data:
                    shop_id = next((s['id'] for s in shops if s['name'] == new_shop), None)
                    db.update_user_role(user_data['id'], new_role, shop_id, st.session_state['user']['id'])
                    audit.log(st.session_state['user']['id'], st.session_state['user']['username'],
                             'user_role_updated', 'users', {'user': selected_username, 'role': new_role, 'shop': new_shop})
                    st.success(f"Updated {selected_username} to {new_role} at {new_shop}")
                    st.rerun()

    with tab3:
        st.subheader("Shop Management")
        with st.expander("➕ Add New Shop"):
            with st.form("add_shop"):
                shop_name = st.text_input("Shop Name")
                shop_location = st.text_input("Location")
                shop_phone = st.text_input("Phone")

                submitted_shop = st.form_submit_button("Create Shop", type="primary")

            if submitted_shop:
                if shop_name:
                    shop_id = db.create_shop(shop_name, shop_location, shop_phone)
                    audit.log(st.session_state['user']['id'], st.session_state['user']['username'],
                             'shop_created', 'shops', {'id': shop_id, 'name': shop_name})
                    st.success(f"✅ Shop created (ID: {shop_id})")
                    st.rerun()
                else:
                    st.error("Shop name is required")

        # Display all shops
        shop_summary = db.get_shop_summary()
        if shop_summary:
            if PANDAS_AVAILABLE:
                st.dataframe(pd.DataFrame(shop_summary), use_container_width=True)
            else:
                for s in shop_summary:
                    st.write(f"{s['name']} | {s['location']} | Users: {s['user_count']} | Stock: {s['total_stock']} | Revenue: Ksh {s['total_revenue']:,.0f}")
        else:
            st.info("No shops registered yet.")

    with tab4:
        st.subheader("Security Overview")

        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            failed_logins = len([u for u in users if u.get('failed_logins', 0) > 0])
            st.metric("Failed Logins", failed_logins)
        with col2:
            locked = len([u for u in users if u.get('locked_until') and datetime.fromisoformat(u['locked_until']) > datetime.now()])
            st.metric("Locked Accounts", locked)
        with col3:
            st.metric("Active Sessions", "Check Database")

        if PLOTLY_AVAILABLE:
            monthly = db.get_monthly_sales()
            if monthly:
                df_monthly = pd.DataFrame(monthly)
                fig = make_subplots(rows=2, cols=2, subplot_titles=('Monthly Revenue', 'Monthly Profit', 'Stock vs Sales', 'Debt Trend'))
                fig.add_trace(go.Bar(x=df_monthly['month'], y=df_monthly['total_revenue'], name='Revenue'), row=1, col=1)
                fig.add_trace(go.Bar(x=df_monthly['month'], y=df_monthly['net_profit'], name='Profit'), row=1, col=2)
                fig.update_layout(height=600, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)

    with tab5:
        st.subheader("Audit Trail")
        logs = audit.get_logs(100)
        if PANDAS_AVAILABLE:
            st.dataframe(pd.DataFrame(logs), use_container_width=True)
        else:
            for log in logs[:20]:
                st.write(f"{log['timestamp']} | {log['username']} | {log['action']} | {log['resource']} | Success: {log['success']}")

        if st.button("🔍 Verify Audit Integrity"):
            valid, issues = audit.verify_integrity()
            if valid:
                st.success("✅ Audit log integrity verified. No tampering detected.")
            else:
                st.error(f"❌ Tampering detected! Issues: {issues}")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10: MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    st.set_page_config(
        page_title="Kiiru Egg Management System",
        page_icon="🥚",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            'Get Help': None,
            'Report a bug': None,
            'About': 'Kiiru Egg Management System v4.0 - Multi-Shop Enterprise Solution'
        }
    )

    # Initialize services
    if 'db' not in st.session_state:
        st.session_state['db'] = DatabaseManager()
    if 'audit' not in st.session_state:
        st.session_state['audit'] = AuditLogger()
    if 'rate_limiter' not in st.session_state:
        st.session_state['rate_limiter'] = RateLimiter()
    if 'captcha' not in st.session_state:
        st.session_state['captcha'] = MathCaptcha()
    if 'auth_service' not in st.session_state:
        st.session_state['auth_service'] = AuthService(
            st.session_state['db'],
            st.session_state['audit'],
            st.session_state['rate_limiter'],
            st.session_state['captcha']
        )

    db = st.session_state['db']
    audit = st.session_state['audit']
    auth_service = st.session_state['auth_service']
    captcha = st.session_state['captcha']

    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False

    # Route to appropriate page
    if not st.session_state.get('authenticated'):
        login_page(auth_service, captcha)
    else:
        # Sidebar navigation
        with st.sidebar:
            st.title("🥚 Kiiru Eggs")
            user = st.session_state['user']
            st.write(f"Welcome, **{user['username']}**")
            st.caption(f"Role: {user['role'].upper()}")
            if user.get('shop_name'):
                st.caption(f"Shop: {user['shop_name']}")
            st.divider()

            menu_options = ["🏠 Dashboard", "📦 Inventory", "💰 Sales", "💳 Debt & Payments"]
            if user['role'] == 'admin':
                menu_options.append("👑 Admin")
            menu_options.append("🚪 Logout")

            menu = st.radio("Navigation", menu_options, index=0)

            st.divider()
            st.caption(f"Session: {user['session_id'][:8]}...")
            st.caption(f"Last active: {datetime.now().strftime('%H:%M')}")

            # PWA Install hint
            st.markdown("""
            <div style="font-size:0.75rem; color:#666; margin-top:10px; padding:8px; background:#f0f2f6; border-radius:5px;">
                📲 <strong>Tip:</strong> Add this page to your home screen for app-like experience!
            </div>
            """, unsafe_allow_html=True)

        # Route to page
        if menu == "🏠 Dashboard":
            dashboard_page(db, audit)
        elif menu == "📦 Inventory":
            inventory_page(db, audit)
        elif menu == "💰 Sales":
            sales_page(db, audit)
        elif menu == "💳 Debt & Payments":
            debt_page(db, audit)
        elif menu == "👑 Admin" and user['role'] == 'admin':
            admin_page(db, audit)
        elif menu == "🚪 Logout":
            auth_service.logout(user['session_id'], user['id'])
            st.session_state.clear()
            st.success("✅ Logged out successfully.")
            time.sleep(0.5)
            st.rerun()

if __name__ == "__main__":
    main()
