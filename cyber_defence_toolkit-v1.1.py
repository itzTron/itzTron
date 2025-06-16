#!/usr/bin/env python3
import os
import sys
import sqlite3
import hashlib
import zipfile
import tempfile
import smtplib
import random
import string
from datetime import datetime
import platform
import shutil
import getpass
import socket
import geoip2.database
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from typing import Optional, List, Dict, Tuple

# Constants
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256
IV_SIZE = 16
ITERATIONS = 100000
DB_NAME = "cyber_defence.db"
BACKUP_DIR = "encrypted_backups"
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
SMTP_CONFIG = {
    "server": "smtp.gmail.com",
    "port": 587,
    "email": "your.email@example.com",
    "password": "your_app_password"
}

# Color Codes
COLORS = {
    "HEADER": "\033[95m",
    "OKBLUE": "\033[94m",
    "OKGREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m"
}

class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                master_hash TEXT NOT NULL,
                master_salt TEXT NOT NULL,
                password_hint TEXT,
                otp_secret TEXT,
                otp_expiry TEXT
            )
        ''')
        
        # Encrypted files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                encrypted_path TEXT NOT NULL,
                backup_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                encryption_date TEXT NOT NULL,
                password_hint TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        # File access logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                access_time TEXT NOT NULL,
                user TEXT NOT NULL,
                ip_address TEXT,
                location TEXT,
                action TEXT NOT NULL
            )
        ''')
        
        # File integrity records
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_integrity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                md5_hash TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                check_date TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        # Password vault
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                password TEXT NOT NULL,
                strength TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        self.conn.commit()

class SecurityManager:
    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Secure password hashing with PBKDF2"""
        if salt is None:
            salt = get_random_bytes(SALT_SIZE)
        key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
        return key, salt
    
    @staticmethod
    def generate_otp(length: int = 6) -> str:
        """Generate a random OTP"""
        return ''.join(random.choices(string.digits, k=length))
    
    @staticmethod
    def send_email(to_email: str, subject: str, body: str) -> bool:
        """Send email with OTP"""
        try:
            with smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"]) as server:
                server.starttls()
                server.login(SMTP_CONFIG["email"], SMTP_CONFIG["password"])
                message = f"Subject: {subject}\n\n{body}"
                server.sendmail(SMTP_CONFIG["email"], to_email, message)
            return True
        except Exception as e:
            print(f"{COLORS['FAIL']}Error sending email: {e}{COLORS['ENDC']}")
            return False

class FileEncryptor:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.ensure_backup_dir()
    
    def ensure_backup_dir(self):
        """Create backup directory if not exists"""
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
    
    def encrypt_file(self, file_path: str, password: str, user_id: int, hint: str = None) -> bool:
        """Encrypt file with AES-256-CBC"""
        try:
            if not os.path.exists(file_path):
                print(f"{COLORS['FAIL']}Error: File not found{COLORS['ENDC']}")
                return False
            
            # Generate crypto materials
            salt = get_random_bytes(SALT_SIZE)
            iv = get_random_bytes(IV_SIZE)
            key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
            
            # Read and pad file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            pad_len = AES.block_size - (len(plaintext) % AES.block_size)
            plaintext += bytes([pad_len]) * pad_len
            
            # Encrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(plaintext)
            
            # Create backup
            backup_path = os.path.join(BACKUP_DIR, f"{os.path.basename(file_path)}.bak")
            shutil.copy2(file_path, backup_path)
            
            # Save encrypted file
            encrypted_path = f"{file_path}.enc"
            with open(encrypted_path, 'wb') as f:
                f.write(salt + iv + ciphertext)
            
            # Calculate hash
            file_hash = hashlib.sha256(plaintext).hexdigest()
            
            # Store in database
            cursor = self.db.conn.cursor()
            cursor.execute('''
                INSERT INTO encrypted_files 
                (user_id, original_path, encrypted_path, backup_path, file_hash, encryption_date, password_hint)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, file_path, encrypted_path, backup_path, file_hash, datetime.now().isoformat(), hint))
            self.db.conn.commit()
            
            # Cleanup
            os.remove(file_path)
            
            print(f"{COLORS['OKGREEN']}File encrypted successfully!{COLORS['ENDC']}")
            print(f"Encrypted file: {encrypted_path}")
            print(f"Backup created: {backup_path}")
            return True
        except Exception as e:
            print(f"{COLORS['FAIL']}Error during encryption: {e}{COLORS['ENDC']}")
            return False
    
    def decrypt_file(self, encrypted_path: str, password: str, user_id: int) -> bool:
        """Decrypt file encrypted by this tool"""
        try:
            if not os.path.exists(encrypted_path):
                print(f"{COLORS['FAIL']}Error: File not found{COLORS['ENDC']}")
                return False
            
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                data = f.read()
            
            # Extract crypto materials
            salt = data[:SALT_SIZE]
            iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
            ciphertext = data[SALT_SIZE+IV_SIZE:]
            
            # Derive key and decrypt
            key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            
            # Remove padding
            pad_len = plaintext[-1]
            plaintext = plaintext[:-pad_len]
            
            # Get original path from database
            cursor = self.db.conn.cursor()
            cursor.execute('''
                SELECT original_path FROM encrypted_files 
                WHERE encrypted_path = ? AND user_id = ?
            ''', (encrypted_path, user_id))
            result = cursor.fetchone()
            
            if result:
                original_path = result[0]
            else:
                original_path = encrypted_path[:-4] if encrypted_path.endswith('.enc') else f"{encrypted_path}.decrypted"
            
            # Write decrypted file
            with open(original_path, 'wb') as f:
                f.write(plaintext)
            
            print(f"{COLORS['OKGREEN']}File decrypted successfully!{COLORS['ENDC']}")
            print(f"Restored to: {original_path}")
            return True
        except Exception as e:
            print(f"{COLORS['FAIL']}Error during decryption: {e}{COLORS['ENDC']}")
            return False

class FileLogChecker:
    def __init__(self, db: DatabaseManager):
        self.db = db
        try:
            self.geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except:
            self.geoip_reader = None
    
    def log_access(self, file_path: str, action: str, user: Optional[str] = None):
        try:
            user = user or getpass.getuser()
            ip = socket.gethostbyname(socket.gethostname())
            location = "Unknown"
            
            if self.geoip_reader:
                try:
                    response = self.geoip_reader.city(ip)
                    location = f"{response.city.name}, {response.country.name}"
                except:
                    pass
            
            cursor = self.db.conn.cursor()
            cursor.execute('''
                INSERT INTO file_access_logs 
                (file_path, access_time, user, ip_address, location, action)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                file_path,
                datetime.now().isoformat(),
                user,
                ip,
                location,
                action
            ))
            self.db.conn.commit()
            return True
        except Exception as e:
            print(f"Error logging access: {e}")
            return False
    
    def show_logs(self, file_path: Optional[str] = None):
        cursor = self.db.conn.cursor()
        
        if file_path:
            cursor.execute('''
                SELECT * FROM file_access_logs WHERE file_path = ? ORDER BY access_time DESC
            ''', (file_path,))
        else:
            cursor.execute('''
                SELECT * FROM file_access_logs ORDER BY access_time DESC
            ''')
        
        logs = cursor.fetchall()
        
        if not logs:
            print("\n[-] No access logs found")
            return
        
        print("\n[+] File Access Logs:")
        print("=" * 100)
        for log in logs:
            print(f"File: {log[1]}")
            print(f"Time: {log[2]}")
            print(f"User: {log[3]}")
            print(f"IP: {log[4]}")
            print(f"Location: {log[5]}")
            print(f"Action: {log[6]}")
            print("-" * 100)

class FileIntegrityChecker:
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def calculate_hashes(self, file_path: str) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 hashes"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
        
        return md5.hexdigest(), sha256.hexdigest()
    
    def check_file(self, file_path: str, user_id: int) -> bool:
        """Check and record file integrity"""
        try:
            if not os.path.exists(file_path):
                print(f"{COLORS['FAIL']}Error: File not found{COLORS['ENDC']}")
                return False
            
            md5_hash, sha256_hash = self.calculate_hashes(file_path)
            
            cursor = self.db.conn.cursor()
            cursor.execute('''
                INSERT INTO file_integrity 
                (file_path, md5_hash, sha256_hash, check_date, user_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                file_path,
                md5_hash,
                sha256_hash,
                datetime.now().isoformat(),
                user_id
            ))
            self.db.conn.commit()
            
            print(f"\n{COLORS['OKGREEN']}File integrity check completed:{COLORS['ENDC']}")
            print(f"File: {file_path}")
            print(f"MD5: {md5_hash}")
            print(f"SHA256: {sha256_hash}")
            return True
        except Exception as e:
            print(f"{COLORS['FAIL']}Error checking file: {e}{COLORS['ENDC']}")
            return False
    
    def verify_file(self, file_path: str, user_id: int) -> bool:
        """Verify against stored hashes"""
        try:
            if not os.path.exists(file_path):
                print(f"{COLORS['FAIL']}Error: File not found{COLORS['ENDC']}")
                return False
            
            current_md5, current_sha256 = self.calculate_hashes(file_path)
            
            cursor = self.db.conn.cursor()
            cursor.execute('''
                SELECT md5_hash, sha256_hash FROM file_integrity 
                WHERE file_path = ? AND user_id = ?
                ORDER BY check_date DESC LIMIT 1
            ''', (file_path, user_id))
            result = cursor.fetchone()
            
            if not result:
                print(f"{COLORS['WARNING']}No previous record found for this file{COLORS['ENDC']}")
                return False
            
            stored_md5, stored_sha256 = result
            
            if current_md5 == stored_md5 and current_sha256 == stored_sha256:
                print(f"{COLORS['OKGREEN']}File integrity verified!{COLORS['ENDC']}")
                print("Hashes match the last recorded values")
                return True
            else:
                print(f"{COLORS['FAIL']}WARNING: File has been modified!{COLORS['ENDC']}")
                print(f"Stored MD5: {stored_md5}")
                print(f"Current MD5: {current_md5}")
                print(f"Stored SHA256: {stored_sha256}")
                print(f"Current SHA256: {current_sha256}")
                return False
        except Exception as e:
            print(f"{COLORS['FAIL']}Error verifying file: {e}{COLORS['ENDC']}")
            return False

class PasswordManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def generate_password(self, length: int = 16) -> str:
        """Generate a strong random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = ''.join(random.choices(chars, k=length))
            # Check password complexity requirements
            has_lower = any(c.islower() for c in password)
            has_upper = any(c.isupper() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*" for c in password)
            if has_lower and has_upper and has_digit and has_special:
                return password

    def check_strength(self, password: str) -> str:
        """Evaluate password strength"""
        score = 0
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*" for c in password): score += 1
        
        if score <= 2: return "Very Weak"
        if score <= 3: return "Weak"
        if score <= 4: return "Moderate"
        if score <= 5: return "Strong"
        return "Very Strong"
    
    def save_password(self, purpose: str, password: str, user_id: int):
        """Store password in vault"""
        strength = self.check_strength(password)
        cursor = self.db.conn.cursor()
        cursor.execute('''
            INSERT INTO password_vault 
            (user_id, purpose, password, strength, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            user_id,
            purpose,
            password,
            strength,
            datetime.now().isoformat()
        ))
        self.db.conn.commit()
        print(f"{COLORS['OKGREEN']}Password saved successfully!{COLORS['ENDC']}")

class CyberDefenceToolkit:
    def __init__(self):
        self.db = DatabaseManager()
        self.encryptor = FileEncryptor(self.db)
        self.log_checker = FileLogChecker(self.db)
        self.integrity_checker = FileIntegrityChecker(self.db)
        self.password_manager = PasswordManager(self.db)
        self.current_user = None
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_header(self, title: str):
        """Display colorful header"""
        self.clear_screen()
        print(f"\n{COLORS['HEADER']}{'='*60}{COLORS['ENDC']}")
        print(f"{COLORS['HEADER']}{title.center(60)}{COLORS['ENDC']}")
        print(f"{COLORS['HEADER']}{'='*60}{COLORS['ENDC']}\n")
    
    def register_user(self):
        """User registration flow"""
        self.display_header("REGISTER NEW USER")
        
        username = input(f"{COLORS['OKBLUE']}Choose a username: {COLORS['ENDC']}").strip()
        email = input(f"{COLORS['OKBLUE']}Enter your email: {COLORS['ENDC']}").strip()
        
        # Validate inputs
        if not username or not email:
            print(f"{COLORS['FAIL']}Username and email are required!{COLORS['ENDC']}")
            return False
        
        # Check if username/email exists
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            print(f"{COLORS['FAIL']}Username or email already registered!{COLORS['ENDC']}")
            return False
        
        # Get password
        while True:
            password = getpass.getpass(f"{COLORS['OKBLUE']}Create master password: {COLORS['ENDC']}")
            if not password:
                print(f"{COLORS['FAIL']}Password cannot be empty!{COLORS['ENDC']}")
                continue
            
            confirm = getpass.getpass(f"{COLORS['OKBLUE']}Confirm password: {COLORS['ENDC']}")
            if password != confirm:
                print(f"{COLORS['FAIL']}Passwords don't match!{COLORS['ENDC']}")
                continue
            break
        
        hint = input(f"{COLORS['OKBLUE']}Password hint (optional): {COLORS['ENDC']}").strip() or None
        
        # Hash and store password
        password_hash, salt = SecurityManager.hash_password(password)
        
        cursor.execute('''
            INSERT INTO users 
            (username, email, master_hash, master_salt, password_hint)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, salt, hint))
        self.db.conn.commit()
        
        print(f"\n{COLORS['OKGREEN']}Registration successful!{COLORS['ENDC']}")
        return True
    
    def login(self):
        """User login flow"""
        self.display_header("LOGIN")
        
        username = input(f"{COLORS['OKBLUE']}Username: {COLORS['ENDC']}").strip()
        password = getpass.getpass(f"{COLORS['OKBLUE']}Password: {COLORS['ENDC']}")
        
        if not username or not password:
            print(f"{COLORS['FAIL']}Username and password are required!{COLORS['ENDC']}")
            return False
        
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT id, master_hash, master_salt FROM users WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()
        
        if not result:
            print(f"{COLORS['FAIL']}User not found!{COLORS['ENDC']}")
            return False
        
        user_id, stored_hash, salt = result
        entered_hash, _ = SecurityManager.hash_password(password, salt)
        
        if entered_hash == stored_hash:
            print(f"\n{COLORS['OKGREEN']}Login successful!{COLORS['ENDC']}")
            self.current_user = {"id": user_id, "username": username}
            return True
        else:
            print(f"\n{COLORS['FAIL']}Invalid password!{COLORS['ENDC']}")
            return False
    
    def reset_password(self):
        """Password reset flow with email OTP"""
        self.display_header("PASSWORD RECOVERY")
        
        email = input(f"{COLORS['OKBLUE']}Enter your registered email: {COLORS['ENDC']}").strip()
        if not email:
            print(f"{COLORS['FAIL']}Email is required!{COLORS['ENDC']}")
            return
        
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT id, password_hint FROM users WHERE email = ?
        ''', (email,))
        result = cursor.fetchone()
        
        if not result:
            print(f"{COLORS['FAIL']}Email not found!{COLORS['ENDC']}")
            return
        
        user_id, hint = result
        if hint:
            print(f"\n{COLORS['WARNING']}Password hint: {hint}{COLORS['ENDC']}")
        
        # Generate and send OTP
        otp = SecurityManager.generate_otp()
        if not SecurityManager.send_email(email, "Your Password Reset OTP", f"Your OTP is: {otp}"):
            print(f"{COLORS['FAIL']}Failed to send OTP!{COLORS['ENDC']}")
            return
        
        # Store OTP in database
        cursor.execute('''
            UPDATE users SET otp_secret = ?, otp_expiry = ?
            WHERE id = ?
        ''', (
            otp,
            (datetime.now() + timedelta(minutes=10)).isoformat(),
            user_id
        ))
        self.db.conn.commit()
        
        print(f"\n{COLORS['OKGREEN']}OTP sent to your email!{COLORS['ENDC']}")
        
        # Verify OTP
        entered_otp = input(f"{COLORS['OKBLUE']}Enter OTP: {COLORS['ENDC']}").strip()
        
        cursor.execute('''
            SELECT otp_secret, otp_expiry FROM users WHERE id = ?
        ''', (user_id,))
        result = cursor.fetchone()
        
        if not result or result[0] != entered_otp:
            print(f"{COLORS['FAIL']}Invalid OTP!{COLORS['ENDC']}")
            return
        
        if datetime.now() > datetime.fromisoformat(result[1]):
            print(f"{COLORS['FAIL']}OTP expired!{COLORS['ENDC']}")
            return
        
        # Set new password
        while True:
            new_password = getpass.getpass(f"{COLORS['OKBLUE']}Enter new password: {COLORS['ENDC']}")
            if not new_password:
                print(f"{COLORS['FAIL']}Password cannot be empty!{COLORS['ENDC']}")
                continue
            
            confirm = getpass.getpass(f"{COLORS['OKBLUE']}Confirm new password: {COLORS['ENDC']}")
            if new_password != confirm:
                print(f"{COLORS['FAIL']}Passwords don't match!{COLORS['ENDC']}")
                continue
            break
        
        # Update password
        new_hash, new_salt = SecurityManager.hash_password(new_password)
        cursor.execute('''
            UPDATE users 
            SET master_hash = ?, master_salt = ?, otp_secret = NULL, otp_expiry = NULL
            WHERE id = ?
        ''', (new_hash, new_salt, user_id))
        self.db.conn.commit()
        
        print(f"\n{COLORS['OKGREEN']}Password reset successfully!{COLORS['ENDC']}")
        return True
    
    def file_encryptor_menu(self):
        """File encryption/decryption menu"""
        while True:
            self.display_header("FILE ENCRYPTOR")
            print(f"{COLORS['OKBLUE']}1. Encrypt File{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}2. Decrypt File{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}3. List Encrypted Files{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}4. Back to Main Menu{COLORS['ENDC']}")
            
            choice = input(f"\n{COLORS['HEADER']}Select option: {COLORS['ENDC']}").strip()
            
            if choice == "1":
                file_path = input(f"{COLORS['OKBLUE']}Enter file path to encrypt: {COLORS['ENDC']}").strip()
                password = getpass.getpass(f"{COLORS['OKBLUE']}Enter encryption password: {COLORS['ENDC']}")
                hint = input(f"{COLORS['OKBLUE']}Password hint (optional): {COLORS['ENDC']}").strip() or None
                self.encryptor.encrypt_file(file_path, password, self.current_user["id"], hint)
            
            elif choice == "2":
                file_path = input(f"{COLORS['OKBLUE']}Enter encrypted file path: {COLORS['ENDC']}").strip()
                password = getpass.getpass(f"{COLORS['OKBLUE']}Enter decryption password: {COLORS['ENDC']}")
                self.encryptor.decrypt_file(file_path, password, self.current_user["id"])
            
            elif choice == "3":
                cursor = self.db.conn.cursor()
                cursor.execute('''
                    SELECT original_path, encrypted_path, encryption_date, password_hint 
                    FROM encrypted_files WHERE user_id = ?
                ''', (self.current_user["id"],))
                files = cursor.fetchall()
                
                if not files:
                    print(f"{COLORS['WARNING']}No encrypted files found{COLORS['ENDC']}")
                else:
                    print(f"\n{COLORS['HEADER']}{'Your Encrypted Files':^60}{COLORS['ENDC']}")
                    for file in files:
                        print(f"\n{COLORS['OKBLUE']}Original:{COLORS['ENDC']} {file[0]}")
                        print(f"{COLORS['OKBLUE']}Encrypted:{COLORS['ENDC']} {file[1]}")
                        print(f"{COLORS['OKBLUE']}Date:{COLORS['ENDC']} {file[2]}")
                        print(f"{COLORS['OKBLUE']}Hint:{COLORS['ENDC']} {file[3] or 'None'}")
                        print("-" * 60)
            
            elif choice == "4":
                break
            
            input(f"\n{COLORS['OKBLUE']}Press Enter to continue...{COLORS['ENDC']}")
    
    def file_log_checker_menu(self):
        """File access log menu"""
        while True:
            self.display_header("FILE LOG CHECKER")
            print(f"{COLORS['OKBLUE']}1. View All Access Logs{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}2. View Logs for Specific File{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}3. Back to Main Menu{COLORS['ENDC']}")
            
            choice = input(f"\n{COLORS['HEADER']}Select option: {COLORS['ENDC']}").strip()
            
            if choice == "1":
                self.log_checker.show_logs()
            
            elif choice == "2":
                file_path = input(f"{COLORS['OKBLUE']}Enter file path: {COLORS['ENDC']}").strip()
                self.log_checker.show_logs(file_path)
            
            elif choice == "3":
                break
            
            input(f"\n{COLORS['OKBLUE']}Press Enter to continue...{COLORS['ENDC']}")
    
    def file_integrity_menu(self):
        """File integrity check menu"""
        while True:
            self.display_header("FILE INTEGRITY CHECKER")
            print(f"{COLORS['OKBLUE']}1. Check File Integrity{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}2. Verify Against Stored Hash{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}3. View Integrity History{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}4. Back to Main Menu{COLORS['ENDC']}")
            
            choice = input(f"\n{COLORS['HEADER']}Select option: {COLORS['ENDC']}").strip()
            
            if choice == "1":
                file_path = input(f"{COLORS['OKBLUE']}Enter file path to check: {COLORS['ENDC']}").strip()
                self.integrity_checker.check_file(file_path, self.current_user["id"])
            
            elif choice == "2":
                file_path = input(f"{COLORS['OKBLUE']}Enter file path to verify: {COLORS['ENDC']}").strip()
                self.integrity_checker.verify_file(file_path, self.current_user["id"])
            
            elif choice == "3":
                cursor = self.db.conn.cursor()
                cursor.execute('''
                    SELECT file_path, md5_hash, sha256_hash, check_date 
                    FROM file_integrity WHERE user_id = ?
                    ORDER BY check_date DESC
                ''', (self.current_user["id"],))
                records = cursor.fetchall()
                
                if not records:
                    print(f"{COLORS['WARNING']}No integrity records found{COLORS['ENDC']}")
                else:
                    print(f"\n{COLORS['HEADER']}{'Integrity Check History':^80}{COLORS['ENDC']}")
                    for rec in records:
                        print(f"\n{COLORS['OKBLUE']}File:{COLORS['ENDC']} {rec[0]}")
                        print(f"{COLORS['OKBLUE']}Date:{COLORS['ENDC']} {rec[3]}")
                        print(f"{COLORS['OKBLUE']}MD5:{COLORS['ENDC']} {rec[1]}")
                        print(f"{COLORS['OKBLUE']}SHA256:{COLORS['ENDC']} {rec[2]}")
                        print("-" * 80)
            
            elif choice == "4":
                break
            
            input(f"\n{COLORS['OKBLUE']}Press Enter to continue...{COLORS['ENDC']}")
    
    def password_manager_menu(self):
        """Password generator and strength checker menu"""
        while True:
            self.display_header("PASSWORD MANAGER")
            print(f"{COLORS['OKBLUE']}1. Generate Strong Password{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}2. Check Password Strength{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}3. View Saved Passwords{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}4. Back to Main Menu{COLORS['ENDC']}")
            
            choice = input(f"\n{COLORS['HEADER']}Select option: {COLORS['ENDC']}").strip()
            
            if choice == "1":
                length = input(f"{COLORS['OKBLUE']}Enter password length (default 16): {COLORS['ENDC']}").strip()
                try:
                    length = int(length) if length else 16
                    password = self.password_manager.generate_password(length)
                    print(f"\n{COLORS['OKGREEN']}Generated Password:{COLORS['ENDC']} {password}")
                    
                    save = input(f"{COLORS['OKBLUE']}Save to vault? (y/n): {COLORS['ENDC']}").lower()
                    if save == 'y':
                        purpose = input(f"{COLORS['OKBLUE']}Enter purpose: {COLORS['ENDC']}").strip()
                        if purpose:
                            self.password_manager.save_password(purpose, password, self.current_user["id"])
                except ValueError:
                    print(f"{COLORS['FAIL']}Invalid length!{COLORS['ENDC']}")
            
            elif choice == "2":
                password = getpass.getpass(f"{COLORS['OKBLUE']}Enter password to check: {COLORS['ENDC']}")
                strength = self.password_manager.check_strength(password)
                print(f"\n{COLORS['OKGREEN']}Password Strength:{COLORS['ENDC']} {strength}")
            
            elif choice == "3":
                master_pw = getpass.getpass(f"{COLORS['OKBLUE']}Enter master password: {COLORS['ENDC']}")
                
                # Verify master password
                cursor = self.db.conn.cursor()
                cursor.execute('''
                    SELECT master_hash, master_salt FROM users WHERE id = ?
                ''', (self.current_user["id"],))
                result = cursor.fetchone()
                
                if not result:
                    print(f"{COLORS['FAIL']}Error verifying password!{COLORS['ENDC']}")
                    continue
                
                stored_hash, salt = result
                entered_hash, _ = SecurityManager.hash_password(master_pw, salt)
                
                if entered_hash != stored_hash:
                    print(f"{COLORS['FAIL']}Incorrect master password!{COLORS['ENDC']}")
                    continue
                
                # Show passwords
                cursor.execute('''
                    SELECT purpose, password, strength, created_at 
                    FROM password_vault WHERE user_id = ?
                    ORDER BY created_at DESC
                ''', (self.current_user["id"],))
                passwords = cursor.fetchall()
                
                if not passwords:
                    print(f"{COLORS['WARNING']}No saved passwords found{COLORS['ENDC']}")
                else:
                    print(f"\n{COLORS['HEADER']}{'Your Saved Passwords':^80}{COLORS['ENDC']}")
                    for pw in passwords:
                        print(f"\n{COLORS['OKBLUE']}Purpose:{COLORS['ENDC']} {pw[0]}")
                        print(f"{COLORS['OKBLUE']}Password:{COLORS['ENDC']} {pw[1]}")
                        print(f"{COLORS['OKBLUE']}Strength:{COLORS['ENDC']} {pw[2]}")
                        print(f"{COLORS['OKBLUE']}Created:{COLORS['ENDC']} {pw[3]}")
                        print("-" * 80)
            
            elif choice == "4":
                break
            
            input(f"\n{COLORS['OKBLUE']}Press Enter to continue...{COLORS['ENDC']}")
    
    def main_menu(self):
        """Main application menu"""
        while True:
            self.display_header("CYBER-DEFENCE TOOLKIT")
            print(f"{COLORS['OKBLUE']}1. File Encryptor{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}2. File Log Checker{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}3. File Integrity Checker{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}4. Password Manager{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}5. Change Master Password{COLORS['ENDC']}")
            print(f"{COLORS['OKBLUE']}6. Logout{COLORS['ENDC']}")
            
            choice = input(f"\n{COLORS['HEADER']}Select tool (1-6): {COLORS['ENDC']}").strip()
            
            if choice == "1":
                self.file_encryptor_menu()
            elif choice == "2":
                self.file_log_checker_menu()
            elif choice == "3":
                self.file_integrity_menu()
            elif choice == "4":
                self.password_manager_menu()
            elif choice == "5":
                self.change_password()
            elif choice == "6":
                self.current_user = None
                break
            else:
                print(f"{COLORS['FAIL']}Invalid choice!{COLORS['ENDC']}")
    
    def change_password(self):
        """Change master password"""
        self.display_header("CHANGE MASTER PASSWORD")
        
        current = getpass.getpass(f"{COLORS['OKBLUE']}Current password: {COLORS['ENDC']}")
        
        # Verify current password
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT master_hash, master_salt FROM users WHERE id = ?
        ''', (self.current_user["id"],))
        result = cursor.fetchone()
        
        if not result:
            print(f"{COLORS['FAIL']}Error verifying password!{COLORS['ENDC']}")
            return
        
        stored_hash, salt = result
        entered_hash, _ = SecurityManager.hash_password(current, salt)
        
        if entered_hash != stored_hash:
            print(f"{COLORS['FAIL']}Incorrect current password!{COLORS['ENDC']}")
            return
        
        # Get new password
        while True:
            new_pw = getpass.getpass(f"{COLORS['OKBLUE']}New password: {COLORS['ENDC']}")
            if not new_pw:
                print(f"{COLORS['FAIL']}Password cannot be empty!{COLORS['ENDC']}")
                continue
            
            confirm = getpass.getpass(f"{COLORS['OKBLUE']}Confirm new password: {COLORS['ENDC']}")
            if new_pw != confirm:
                print(f"{COLORS['FAIL']}Passwords don't match!{COLORS['ENDC']}")
                continue
            break
        
        # Update password
        new_hash, new_salt = SecurityManager.hash_password(new_pw)
        cursor.execute('''
            UPDATE users 
            SET master_hash = ?, master_salt = ?
            WHERE id = ?
        ''', (new_hash, new_salt, self.current_user["id"]))
        self.db.conn.commit()
        
        print(f"\n{COLORS['OKGREEN']}Password changed successfully!{COLORS['ENDC']}")
    
    def run(self):
        """Main application loop"""
        while True:
            self.clear_screen()
            self.display_header("CYBER-DEFENCE TOOLKIT")
            
            if not self.current_user:
                print(f"{COLORS['OKBLUE']}1. Register{COLORS['ENDC']}")
                print(f"{COLORS['OKBLUE']}2. Login{COLORS['ENDC']}")
                print(f"{COLORS['OKBLUE']}3. Forgot Password{COLORS['ENDC']}")
                print(f"{COLORS['OKBLUE']}4. Exit{COLORS['ENDC']}")
                
                choice = input(f"\n{COLORS['HEADER']}Select option (1-4): {COLORS['ENDC']}").strip()
                
                if choice == "1":
                    self.register_user()
                elif choice == "2":
                    if self.login():
                        self.main_menu()
                elif choice == "3":
                    self.reset_password()
                elif choice == "4":
                    print(f"\n{COLORS['OKGREEN']}Goodbye!{COLORS['ENDC']}")
                    break
                else:
                    print(f"{COLORS['FAIL']}Invalid choice!{COLORS['ENDC']}")
            else:
                self.main_menu()
            
            input(f"\n{COLORS['OKBLUE']}Press Enter to continue...{COLORS['ENDC']}")

if __name__ == "__main__":
    try:
        toolkit = CyberDefenceToolkit()
        toolkit.run()
    except KeyboardInterrupt:
        print(f"\n{COLORS['FAIL']}Program interrupted by user{COLORS['ENDC']}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{COLORS['FAIL']}Critical error: {e}{COLORS['ENDC']}")
        sys.exit(1)