import uuid
import logging
import sys
import sqlite3
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
                             QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox,
                             QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
                             QSpinBox, QDoubleSpinBox, QDateEdit, QHeaderView, QInputDialog)
from PyQt5.QtCore import Qt, QDate
from PyQt5.QtGui import QFont, QPixmap, QIcon
import hashlib
import secrets
import string
from datetime import datetime
import os

AUTHORIZED_DEVICE_ID = '0x54e1ad90c41e'

def get_device_id():
    return hex(uuid.getnode())

def check_device_id():
    if get_device_id() != AUTHORIZED_DEVICE_ID:
        app = QApplication([])
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("Unauthorized Machine")
        msg.setInformativeText("This system is licensed to a specific machine only.")
        msg.setWindowTitle("Access Denied")
        msg.exec_()
        sys.exit()

check_device_id()


class SecureDatabase:
    def __init__(self, db_name='construction_inventory.db'):
        # Create application directory if it doesn't exist
        self.app_data_dir = os.path.join(os.path.expanduser('~'), '.construction_inventory')
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)

        self.db_path = os.path.join(self.app_data_dir, db_name)
        self.connection = sqlite3.connect(self.db_path)
        self.cursor = self.connection.cursor()

        # Enable foreign key constraints
        self.cursor.execute("PRAGMA foreign_keys = ON")

        # Set WAL mode for better concurrency
        self.cursor.execute("PRAGMA journal_mode = WAL")

        # Secure the database with encryption key
        self.setup_database()

    def setup_database(self):
        # Create all tables with proper constraints
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('Admin', 'Manager', 'Sales')),
                full_name TEXT NOT NULL,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                must_change_password BOOLEAN DEFAULT 1
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS suppliers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                contact_person TEXT,
                phone TEXT,
                email TEXT,
                address TEXT,
                tax_id TEXT,
                payment_terms TEXT
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                client_name TEXT NOT NULL,
                address TEXT,
                start_date TEXT,
                end_date TEXT,
                status TEXT CHECK(status IN ('Planning', 'Active', 'On Hold', 'Completed', 'Cancelled')),
                notes TEXT
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS materials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                unit TEXT NOT NULL,
                supplier_id INTEGER,
                cost_price REAL NOT NULL,
                min_stock_level INTEGER DEFAULT 10,
                barcode TEXT UNIQUE,
                FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                material_id INTEGER NOT NULL,
                warehouse TEXT NOT NULL,
                quantity REAL NOT NULL,
                last_updated TEXT NOT NULL,
                PRIMARY KEY (material_id, warehouse),
                FOREIGN KEY (material_id) REFERENCES materials(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                material_id INTEGER NOT NULL,
                warehouse TEXT NOT NULL,
                quantity_change REAL NOT NULL,
                transaction_type TEXT NOT NULL CHECK(transaction_type IN ('Purchase', 'Sale', 'Adjustment', 'Transfer')),
                reference_id INTEGER,
                transaction_date TEXT NOT NULL,
                recorded_by INTEGER NOT NULL,
                notes TEXT,
                FOREIGN KEY (material_id) REFERENCES materials(id),
                FOREIGN KEY (recorded_by) REFERENCES users(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS project_pricing (
                material_id INTEGER NOT NULL,
                project_id INTEGER NOT NULL,
                sale_price REAL NOT NULL,
                PRIMARY KEY (material_id, project_id),
                FOREIGN KEY (material_id) REFERENCES materials(id),
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                sale_date TEXT NOT NULL,
                total_amount REAL NOT NULL,
                discount REAL DEFAULT 0,
                tax_amount REAL DEFAULT 0,
                payment_status TEXT CHECK(payment_status IN ('Pending', 'Partial', 'Paid')),
                recorded_by INTEGER NOT NULL,
                notes TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (recorded_by) REFERENCES users(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sale_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sale_id INTEGER NOT NULL,
                material_id INTEGER NOT NULL,
                quantity REAL NOT NULL,
                unit_price REAL NOT NULL,
                total_price REAL NOT NULL,
                warehouse TEXT NOT NULL,
                FOREIGN KEY (sale_id) REFERENCES sales(id),
                FOREIGN KEY (material_id) REFERENCES materials(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                supplier_id INTEGER NOT NULL,
                purchase_date TEXT NOT NULL,
                total_amount REAL NOT NULL,
                delivery_date TEXT,
                status TEXT CHECK(status IN ('Ordered', 'Received', 'Cancelled')),
                recorded_by INTEGER NOT NULL,
                notes TEXT,
                FOREIGN KEY (supplier_id) REFERENCES suppliers(id),
                FOREIGN KEY (recorded_by) REFERENCES users(id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS purchase_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                purchase_id INTEGER NOT NULL,
                material_id INTEGER NOT NULL,
                quantity REAL NOT NULL,
                unit_price REAL NOT NULL,
                total_price REAL NOT NULL,
                warehouse TEXT NOT NULL,
                FOREIGN KEY (purchase_id) REFERENCES purchases(id),
                FOREIGN KEY (material_id) REFERENCES materials(id)
            )
        ''')

        # Create default admin if not exists
        self.cursor.execute("SELECT * FROM users WHERE username='admin'")
        if not self.cursor.fetchone():
            salt = self.generate_salt()
            password = "Admin@123"  # Default password that must be changed
            hashed_password = self.hash_password(password, salt)

            self.cursor.execute('''
                INSERT INTO users (username, password_hash, salt, role, full_name, must_change_password)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', hashed_password, salt, 'Admin', 'System Administrator', 1))

        self.connection.commit()

    @staticmethod
    def generate_salt(length=16):
        """Generate a random salt for password hashing"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def hash_password(password, salt):
        """Hash password with salt using PBKDF2_HMAC"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

    def verify_password(self, username, password):
        """Verify user password"""
        self.cursor.execute('''
            SELECT password_hash, salt, locked_until FROM users 
            WHERE username=?
        ''', (username,))

        result = self.cursor.fetchone()
        if not result:
            return False, "User not found"

        stored_hash, salt, locked_until = result

        # Check if account is locked
        if locked_until and datetime.now() < datetime.fromisoformat(locked_until):
            return False, f"Account locked until {locked_until}"

        # Verify password
        input_hash = self.hash_password(password, salt)
        if secrets.compare_digest(input_hash, stored_hash):
            return True, "Success"
        return False, "Invalid password"

    def close(self):
        """Close database connection"""
        self.connection.close()


class LoginWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Construction Inventory Management - Login")
        self.setFixedSize(600, 500)
        self.setWindowIcon(QIcon("construction_icon.png"))

        # Initialize secure database
        self.db = SecureDatabase()

        self.init_ui()
        self.setup_styles()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)

        # Logo and title
        logo_label = QLabel()
        pixmap = QPixmap("construction_logo.png")
        if not pixmap.isNull():
            logo_label.setPixmap(pixmap.scaled(200, 200, Qt.KeepAspectRatio))
        logo_label.setAlignment(Qt.AlignCenter)

        title = QLabel("Construction Inventory Management")
        title.setFont(QFont('Arial', 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #1a5276;")

        # Login form
        form_layout = QVBoxLayout()
        form_layout.setSpacing(15)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.setMinimumWidth(300)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)

        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.authenticate)
        login_btn.setMinimumHeight(40)

        form_layout.addWidget(QLabel("Username:"))
        form_layout.addWidget(self.username)
        form_layout.addWidget(QLabel("Password:"))
        form_layout.addWidget(self.password)
        form_layout.addWidget(login_btn)

        # Add widgets to main layout
        layout.addWidget(logo_label)
        layout.addWidget(title)
        layout.addLayout(form_layout)

        self.setLayout(layout)

    def setup_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #f8f9fa;
                font-family: Arial;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QLabel {
                font-size: 14px;
            }
        """)

    def authenticate(self):
        username = self.username.text().strip()
        password = self.password.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password are required!")
            return

        # Verify credentials
        valid, message = self.db.verify_password(username, password)

        if not valid:
            QMessageBox.warning(self, "Login Failed", message)

            # Track failed attempts
            self.db.cursor.execute('''
                UPDATE users 
                SET failed_attempts = failed_attempts + 1 
                WHERE username=?
            ''', (username,))

            # Lock account after 3 failed attempts for 15 minutes
            self.db.cursor.execute('''
                SELECT failed_attempts FROM users WHERE username=?
            ''', (username,))
            attempts = self.db.cursor.fetchone()[0]

            if attempts >= 3:
                lock_time = datetime.now().replace(minute=datetime.now().minute + 15).isoformat()
                self.db.cursor.execute('''
                    UPDATE users 
                    SET locked_until=? 
                    WHERE username=?
                ''', (lock_time, username))
                QMessageBox.warning(self, "Account Locked",
                                    "Too many failed attempts. Account locked for 15 minutes.")

            self.db.connection.commit()
            return

        # Reset failed attempts on successful login
        self.db.cursor.execute('''
            UPDATE users 
            SET failed_attempts=0, locked_until=NULL, last_login=?
            WHERE username=?
        ''', (datetime.now().isoformat(), username))
        self.db.connection.commit()

        # Check if password needs to be changed
        self.db.cursor.execute('''
            SELECT must_change_password FROM users WHERE username=?
        ''', (username,))
        must_change = self.db.cursor.fetchone()[0]

        if must_change:
            self.change_password(username)
            return

        # Get user details
        self.db.cursor.execute('''
            SELECT id, username, role, full_name FROM users WHERE username=?
        ''', (username,))
        user = self.db.cursor.fetchone()

        # Proceed to main application
        self.hide()
        self.main_window = MainWindow(user, self.db)
        self.main_window.show()

    def change_password(self, username):
        new_password, ok = QInputDialog.getText(
            self,
            "Change Password",
            "Your password must be changed. Enter a new password (min 8 chars, 1 uppercase, 1 digit):",
            QLineEdit.Password
        )

        if ok and new_password:
            # Validate password strength
            if len(new_password) < 8 or not any(c.isupper() for c in new_password) or not any(
                    c.isdigit() for c in new_password):
                QMessageBox.warning(self, "Weak Password",
                                    "Password must be at least 8 characters with 1 uppercase letter and 1 digit.")
                self.change_password(username)
                return

            # Update password
            salt = self.db.generate_salt()
            hashed_password = self.db.hash_password(new_password, salt)

            self.db.cursor.execute('''
                UPDATE users 
                SET password_hash=?, salt=?, must_change_password=0 
                WHERE username=?
            ''', (hashed_password, salt, username))
            self.db.connection.commit()

            QMessageBox.information(self, "Success", "Password changed successfully!")

            # Get user details
            self.db.cursor.execute('''
                SELECT id, username, role, full_name FROM users WHERE username=?
            ''', (username,))
            user = self.db.cursor.fetchone()

            # Proceed to main application
            self.hide()
            self.main_window = MainWindow(user, self.db)
            self.main_window.show()

    def closeEvent(self, event):
        self.db.close()
        event.accept()


class MainWindow(QMainWindow):
    def __init__(self, user, db):
        super().__init__()
        self.user = {
            'id': user[0],
            'username': user[1],
            'role': user[2],
            'full_name': user[3]
        }
        self.db = db

        self.setWindowTitle(f"Construction Inventory Management - {self.user['role']}")
        self.setMinimumSize(1200, 800)
        self.setWindowIcon(QIcon("construction_icon.png"))

        self.init_ui()
        self.setup_styles()

    def init_ui(self):
        self.tabs = QTabWidget()

        # Dashboard Tab
        self.dashboard_tab = QWidget()
        self.init_dashboard()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")

        # Inventory Tab
        self.inventory_tab = QWidget()
        self.init_inventory()
        self.tabs.addTab(self.inventory_tab, "Inventory")

        # Projects Tab
        self.projects_tab = QWidget()
        self.init_projects()
        self.tabs.addTab(self.projects_tab, "Projects")

        # Sales Tab
        self.sales_tab = QWidget()
        self.init_sales()
        self.tabs.addTab(self.sales_tab, "Sales")

        # Purchases Tab
        self.purchases_tab = QWidget()
        self.init_purchases()
        self.tabs.addTab(self.purchases_tab, "Purchases")

        # Suppliers Tab
        self.suppliers_tab = QWidget()
        self.init_suppliers()
        self.tabs.addTab(self.suppliers_tab, "Suppliers")

        # Reports Tab
        self.reports_tab = QWidget()
        self.init_reports()
        self.tabs.addTab(self.reports_tab, "Reports")

        # User Management Tab (only for admin/manager)
        if self.user['role'] in ('Admin', 'Manager'):
            self.users_tab = QWidget()
            self.init_users()
            self.tabs.addTab(self.users_tab, "User Management")

        self.setCentralWidget(self.tabs)

        # Status Bar
        self.statusBar().showMessage(f"Logged in as: {self.user['full_name']} ({self.user['role']})")

    def setup_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                padding: 10px;
            }
            QTabBar::tab {
                background: #e0e0e0;
                border: 1px solid #ddd;
                padding: 8px 12px;
            }
            QTabBar::tab:selected {
                background: #3498db;
                color: white;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #ddd;
                font-size: 14px;
            }
            QHeaderView::section {
                background-color: #3498db;
                color: white;
                padding: 5px;
                border: none;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateEdit {
                padding: 6px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
            }
            QLabel {
                font-size: 14px;
            }
        """)

    def init_dashboard(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Summary Cards
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(15)

        # Materials Summary
        materials_card = QWidget()
        materials_card.setObjectName("summaryCard")
        materials_layout = QVBoxLayout()
        materials_title = QLabel("Total Materials")
        materials_title.setFont(QFont('Arial', 12, QFont.Bold))
        self.materials_count = QLabel("0")
        self.materials_count.setFont(QFont('Arial', 24, QFont.Bold))
        materials_layout.addWidget(materials_title)
        materials_layout.addWidget(self.materials_count)
        materials_card.setLayout(materials_layout)

        # Low Stock Summary
        low_stock_card = QWidget()
        low_stock_card.setObjectName("summaryCard")
        low_stock_layout = QVBoxLayout()
        low_stock_title = QLabel("Low Stock Items")
        low_stock_title.setFont(QFont('Arial', 12, QFont.Bold))
        self.low_stock_count = QLabel("0")
        self.low_stock_count.setFont(QFont('Arial', 24, QFont.Bold))
        low_stock_layout.addWidget(low_stock_title)
        low_stock_layout.addWidget(self.low_stock_count)
        low_stock_card.setLayout(low_stock_layout)

        # Sales Summary
        sales_card = QWidget()
        sales_card.setObjectName("summaryCard")
        sales_layout = QVBoxLayout()
        sales_title = QLabel("Today's Sales")
        sales_title.setFont(QFont('Arial', 12, QFont.Bold))
        self.sales_amount = QLabel("$0.00")
        self.sales_amount.setFont(QFont('Arial', 24, QFont.Bold))
        sales_layout.addWidget(sales_title)
        sales_layout.addWidget(self.sales_amount)
        sales_card.setLayout(sales_layout)

        # Inventory Value Summary
        inventory_value_card = QWidget()
        inventory_value_card.setObjectName("summaryCard")
        inventory_value_layout = QVBoxLayout()
        inventory_value_title = QLabel("Inventory Value")
        inventory_value_title.setFont(QFont('Arial', 12, QFont.Bold))
        self.inventory_value = QLabel("$0.00")
        self.inventory_value.setFont(QFont('Arial', 24, QFont.Bold))
        inventory_value_layout.addWidget(inventory_value_title)
        inventory_value_layout.addWidget(self.inventory_value)
        inventory_value_card.setLayout(inventory_value_layout)

        summary_layout.addWidget(materials_card)
        summary_layout.addWidget(low_stock_card)
        summary_layout.addWidget(sales_card)
        summary_layout.addWidget(inventory_value_card)

        # Recent Activity
        recent_activity_label = QLabel("Recent Activity")
        recent_activity_label.setFont(QFont('Arial', 14, QFont.Bold))

        self.activity_table = QTableWidget()
        self.activity_table.setColumnCount(6)
        self.activity_table.setHorizontalHeaderLabels(["Date", "Type", "Material", "Quantity", "Warehouse", "User"])
        self.activity_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addLayout(summary_layout)
        layout.addSpacing(20)
        layout.addWidget(recent_activity_label)
        layout.addWidget(self.activity_table)

        self.dashboard_tab.setLayout(layout)

        # Load dashboard data
        self.load_dashboard_data()

    def load_dashboard_data(self):
        # Total materials count
        self.db.cursor.execute("SELECT COUNT(*) FROM materials")
        self.materials_count.setText(str(self.db.cursor.fetchone()[0]))

        # Low stock count
        self.db.cursor.execute('''
            SELECT COUNT(*) 
            FROM materials m
            JOIN inventory i ON m.id = i.material_id
            WHERE i.quantity <= m.min_stock_level
        ''')
        self.low_stock_count.setText(str(self.db.cursor.fetchone()[0]))

        # Today's sales total
        today = datetime.now().strftime("%Y-%m-%d")
        self.db.cursor.execute("SELECT SUM(total_amount) FROM sales WHERE sale_date LIKE ?", (f"{today}%",))
        total_sales = self.db.cursor.fetchone()[0]
        self.sales_amount.setText(f"${total_sales:,.2f}" if total_sales else "$0.00")

        # Inventory value
        self.db.cursor.execute('''
            SELECT SUM(m.cost_price * i.quantity)
            FROM materials m
            JOIN inventory i ON m.id = i.material_id
        ''')
        inv_value = self.db.cursor.fetchone()[0]
        self.inventory_value.setText(f"${inv_value:,.2f}" if inv_value else "$0.00")

        # Recent activity
        self.db.cursor.execute('''
            SELECT t.transaction_date, t.transaction_type, m.name, t.quantity_change, 
                   t.warehouse, u.full_name
            FROM inventory_transactions t
            JOIN materials m ON t.material_id = m.id
            JOIN users u ON t.recorded_by = u.id
            ORDER BY t.transaction_date DESC
            LIMIT 20
        ''')
        activities = self.db.cursor.fetchall()

        self.activity_table.setRowCount(len(activities))
        for row_idx, row_data in enumerate(activities):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.activity_table.setItem(row_idx, col_idx, item)

    def init_inventory(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Search and filter controls
        controls_layout = QHBoxLayout()

        self.search_material = QLineEdit()
        self.search_material.setPlaceholderText("Search materials...")
        self.search_material.textChanged.connect(self.load_materials)

        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.db.cursor.execute("SELECT DISTINCT category FROM materials ORDER BY category")
        categories = self.db.cursor.fetchall()
        for category in categories:
            self.category_filter.addItem(category[0])
        self.category_filter.currentIndexChanged.connect(self.load_materials)

        self.warehouse_filter = QComboBox()
        self.warehouse_filter.addItem("All Warehouses")
        self.db.cursor.execute("SELECT DISTINCT warehouse FROM inventory ORDER BY warehouse")
        warehouses = self.db.cursor.fetchall()
        for warehouse in warehouses:
            self.warehouse_filter.addItem(warehouse[0])
        self.warehouse_filter.currentIndexChanged.connect(self.load_materials)

        add_material_btn = QPushButton("Add Material")
        add_material_btn.clicked.connect(self.show_add_material_dialog)

        controls_layout.addWidget(self.search_material)
        controls_layout.addWidget(QLabel("Category:"))
        controls_layout.addWidget(self.category_filter)
        controls_layout.addWidget(QLabel("Warehouse:"))
        controls_layout.addWidget(self.warehouse_filter)
        controls_layout.addWidget(add_material_btn)

        # Inventory table
        self.inventory_table = QTableWidget()
        self.inventory_table.setColumnCount(8)
        self.inventory_table.setHorizontalHeaderLabels([
            "ID", "Name", "Category", "Unit", "Cost Price", "Quantity", "Warehouse", "Actions"
        ])
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addLayout(controls_layout)
        layout.addWidget(self.inventory_table)

        self.inventory_tab.setLayout(layout)

        # Load inventory data
        self.load_materials()

    def load_materials(self):
        search_term = f"%{self.search_material.text()}%"
        category = self.category_filter.currentText() if self.category_filter.currentIndex() > 0 else "%"
        warehouse = self.warehouse_filter.currentText() if self.warehouse_filter.currentIndex() > 0 else "%"

        self.db.cursor.execute('''
            SELECT m.id, m.name, m.category, m.unit, m.cost_price, 
                   COALESCE(i.quantity, 0) as quantity, 
                   COALESCE(i.warehouse, 'N/A') as warehouse
            FROM materials m
            LEFT JOIN inventory i ON m.id = i.material_id
            WHERE (m.name LIKE ? OR m.category LIKE ?)
            AND m.category LIKE ?
            AND (i.warehouse LIKE ? OR i.warehouse IS NULL)
            ORDER BY m.name
        ''', (search_term, search_term, category, warehouse))

        materials = self.db.cursor.fetchall()

        self.inventory_table.setRowCount(len(materials))
        for row_idx, row_data in enumerate(materials):
            for col_idx, col_data in enumerate(row_data[:7]):  # Skip the last column (warehouse)
                item = QTableWidgetItem(str(col_data))
                self.inventory_table.setItem(row_idx, col_idx, item)

                # Format numeric columns
                if col_idx == 4:  # Cost price
                    item.setText(f"${float(col_data):,.2f}")
                elif col_idx == 5:  # Quantity
                    item.setText(str(int(col_data)) if col_data.is_integer() else str(col_data))

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            view_btn = QPushButton("View")
            view_btn.setProperty('row', row_idx)
            view_btn.clicked.connect(self.view_material_details)

            edit_btn = QPushButton("Edit")
            edit_btn.setProperty('row', row_idx)
            edit_btn.clicked.connect(self.edit_material)

            delete_btn = QPushButton("Delete")
            delete_btn.setProperty('row', row_idx)
            delete_btn.clicked.connect(self.delete_material)

            adjust_btn = QPushButton("Adjust")
            adjust_btn.setProperty('row', row_idx)
            adjust_btn.clicked.connect(self.adjust_inventory)

            actions_layout.addWidget(view_btn)
            actions_layout.addWidget(edit_btn)
            actions_layout.addWidget(delete_btn)
            actions_layout.addWidget(adjust_btn)
            actions_widget.setLayout(actions_layout)

            self.inventory_table.setCellWidget(row_idx, 7, actions_widget)

            # Highlight low stock items
            min_stock = self.get_min_stock_level(row_data[0])
            if row_data[5] <= min_stock:  # quantity <= min_stock_level
                for col in range(7):
                    item = self.inventory_table.item(row_idx, col)
                    if item:
                        item.setBackground(Qt.yellow if row_data[5] > 0 else Qt.red)
                        if row_data[5] == 0:
                            item.setForeground(Qt.white)

    def get_min_stock_level(self, material_id):
        self.db.cursor.execute("SELECT min_stock_level FROM materials WHERE id=?", (material_id,))
        return self.db.cursor.fetchone()[0]

    def show_add_material_dialog(self):
        self.material_dialog = QWidget()
        self.material_dialog.setWindowTitle("Add New Material")
        self.material_dialog.setFixedSize(500, 500)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Form fields
        self.material_name = QLineEdit()
        self.material_name.setPlaceholderText("Material Name")

        self.material_category = QComboBox()
        self.material_category.setEditable(True)
        self.db.cursor.execute("SELECT DISTINCT category FROM materials ORDER BY category")
        categories = [row[0] for row in self.db.cursor.fetchall()]
        self.material_category.addItems(categories)

        self.material_description = QLineEdit()
        self.material_description.setPlaceholderText("Description (optional)")

        self.material_unit = QComboBox()
        self.material_unit.addItems(["Each", "Box", "Pallet", "Kg", "Lb", "Meter", "Foot", "Liter", "Gallon"])
        self.material_unit.setEditable(True)

        self.material_supplier = QComboBox()
        self.material_supplier.addItem("None", None)
        self.db.cursor.execute("SELECT id, name FROM suppliers ORDER BY name")
        suppliers = self.db.cursor.fetchall()
        for supplier in suppliers:
            self.material_supplier.addItem(supplier[1], supplier[0])

        self.material_cost = QDoubleSpinBox()
        self.material_cost.setPrefix("$ ")
        self.material_cost.setMaximum(99999.99)
        self.material_cost.setValue(0.0)

        self.min_stock_level = QSpinBox()
        self.min_stock_level.setMinimum(0)
        self.min_stock_level.setMaximum(9999)
        self.min_stock_level.setValue(10)

        self.initial_quantity = QDoubleSpinBox()
        self.initial_quantity.setMinimum(0)
        self.initial_quantity.setMaximum(99999)
        self.initial_quantity.setValue(0)

        self.initial_warehouse = QLineEdit()
        self.initial_warehouse.setPlaceholderText("Main Warehouse")

        save_btn = QPushButton("Save Material")
        save_btn.clicked.connect(self.save_material)

        # Add fields to layout
        layout.addWidget(QLabel("Material Name:"))
        layout.addWidget(self.material_name)
        layout.addWidget(QLabel("Category:"))
        layout.addWidget(self.material_category)
        layout.addWidget(QLabel("Description:"))
        layout.addWidget(self.material_description)
        layout.addWidget(QLabel("Unit of Measure:"))
        layout.addWidget(self.material_unit)
        layout.addWidget(QLabel("Supplier:"))
        layout.addWidget(self.material_supplier)
        layout.addWidget(QLabel("Cost Price:"))
        layout.addWidget(self.material_cost)
        layout.addWidget(QLabel("Minimum Stock Level:"))
        layout.addWidget(self.min_stock_level)
        layout.addWidget(QLabel("Initial Quantity:"))
        layout.addWidget(self.initial_quantity)
        layout.addWidget(QLabel("Initial Warehouse:"))
        layout.addWidget(self.initial_warehouse)
        layout.addWidget(save_btn)

        self.material_dialog.setLayout(layout)
        self.material_dialog.show()

    def save_material(self):
        name = self.material_name.text().strip()
        category = self.material_category.currentText().strip()
        description = self.material_description.text().strip()
        unit = self.material_unit.currentText().strip()
        supplier_id = self.material_supplier.currentData()
        cost_price = self.material_cost.value()
        min_stock = self.min_stock_level.value()
        initial_qty = self.initial_quantity.value()
        warehouse = self.initial_warehouse.text().strip() or "Main Warehouse"

        if not name:
            QMessageBox.warning(self.material_dialog, "Error", "Material name is required!")
            return

        if not category:
            QMessageBox.warning(self.material_dialog, "Error", "Category is required!")
            return

        try:
            # Start transaction
            self.db.cursor.execute("BEGIN TRANSACTION")

            # Insert material
            self.db.cursor.execute('''
                INSERT INTO materials (name, category, description, unit, supplier_id, cost_price, min_stock_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (name, category, description, unit, supplier_id, cost_price, min_stock))

            material_id = self.db.cursor.lastrowid

            # Add initial inventory if quantity > 0
            if initial_qty > 0:
                self.db.cursor.execute('''
                    INSERT OR REPLACE INTO inventory (material_id, warehouse, quantity, last_updated)
                    VALUES (?, ?, ?, ?)
                ''', (material_id, warehouse, initial_qty, datetime.now().isoformat()))

                # Record inventory transaction
                self.db.cursor.execute('''
                    INSERT INTO inventory_transactions (
                        material_id, warehouse, quantity_change, transaction_type, 
                        transaction_date, recorded_by, notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    material_id, warehouse, initial_qty, 'Adjustment',
                    datetime.now().isoformat(), self.user['id'],
                    f"Initial inventory entry"
                ))

            self.db.connection.commit()

            QMessageBox.information(self.material_dialog, "Success", "Material added successfully!")
            self.material_dialog.close()
            self.load_materials()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            self.db.connection.rollback()
            QMessageBox.critical(self.material_dialog, "Database Error", f"Failed to save material: {str(e)}")

    def view_material_details(self):
        btn = self.sender()
        row = btn.property('row')
        material_id = int(self.inventory_table.item(row, 0).text())

        self.db.cursor.execute('''
            SELECT m.*, s.name as supplier_name
            FROM materials m
            LEFT JOIN suppliers s ON m.supplier_id = s.id
            WHERE m.id=?
        ''', (material_id,))
        material = self.db.cursor.fetchone()

        self.db.cursor.execute('''
            SELECT warehouse, quantity, last_updated
            FROM inventory
            WHERE material_id=?
            ORDER BY warehouse
        ''', (material_id,))
        inventory = self.db.cursor.fetchall()

        self.db.cursor.execute('''
            SELECT p.name, pp.sale_price
            FROM project_pricing pp
            JOIN projects p ON pp.project_id = p.id
            WHERE pp.material_id=?
            ORDER BY p.name
        ''', (material_id,))
        pricing = self.db.cursor.fetchall()

        # Create details dialog
        details_dialog = QWidget()
        details_dialog.setWindowTitle(f"Material Details - {material[1]}")
        details_dialog.setMinimumSize(600, 500)

        layout = QVBoxLayout()

        # Basic info
        info_group = QWidget()
        info_layout = QVBoxLayout()

        info_layout.addWidget(QLabel(f"<h2>{material[1]}</h2>"))
        info_layout.addWidget(QLabel(f"<b>Category:</b> {material[2]}"))
        info_layout.addWidget(QLabel(f"<b>Description:</b> {material[3] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Unit:</b> {material[4]}"))
        info_layout.addWidget(QLabel(f"<b>Supplier:</b> {material[8] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Cost Price:</b> ${material[5]:,.2f}"))
        info_layout.addWidget(QLabel(f"<b>Min Stock Level:</b> {material[6]}"))

        info_group.setLayout(info_layout)

        # Inventory tabs
        tabs = QTabWidget()

        # Inventory by warehouse
        inventory_tab = QWidget()
        inventory_layout = QVBoxLayout()

        inventory_table = QTableWidget()
        inventory_table.setColumnCount(3)
        inventory_table.setHorizontalHeaderLabels(["Warehouse", "Quantity", "Last Updated"])
        inventory_table.setRowCount(len(inventory))

        for row_idx, row_data in enumerate(inventory):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                inventory_table.setItem(row_idx, col_idx, item)

        inventory_layout.addWidget(inventory_table)
        inventory_tab.setLayout(inventory_layout)
        tabs.addTab(inventory_tab, "Inventory")

        # Project pricing
        pricing_tab = QWidget()
        pricing_layout = QVBoxLayout()

        pricing_table = QTableWidget()
        pricing_table.setColumnCount(2)
        pricing_table.setHorizontalHeaderLabels(["Project", "Sale Price"])
        pricing_table.setRowCount(len(pricing))

        for row_idx, row_data in enumerate(pricing):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                pricing_table.setItem(row_idx, col_idx, item)
                if col_idx == 1:  # Price column
                    item.setText(f"${float(col_data):,.2f}")

        pricing_layout.addWidget(pricing_table)

        # Add pricing form
        if self.user['role'] in ('Admin', 'Manager'):
            pricing_form = QWidget()
            form_layout = QHBoxLayout()

            self.pricing_project = QComboBox()
            self.db.cursor.execute("SELECT id, name FROM projects ORDER BY name")
            projects = self.db.cursor.fetchall()
            for project in projects:
                self.pricing_project.addItem(project[1], project[0])

            self.pricing_price = QDoubleSpinBox()
            self.pricing_price.setPrefix("$ ")
            self.pricing_price.setMaximum(99999.99)

            add_pricing_btn = QPushButton("Add Pricing")
            add_pricing_btn.clicked.connect(lambda: self.add_project_pricing(material_id))

            form_layout.addWidget(QLabel("Project:"))
            form_layout.addWidget(self.pricing_project)
            form_layout.addWidget(QLabel("Price:"))
            form_layout.addWidget(self.pricing_price)
            form_layout.addWidget(add_pricing_btn)

            pricing_form.setLayout(form_layout)
            pricing_layout.addWidget(pricing_form)

        pricing_tab.setLayout(pricing_layout)
        tabs.addTab(pricing_tab, "Project Pricing")

        # Transaction history
        history_tab = QWidget()
        history_layout = QVBoxLayout()

        self.db.cursor.execute('''
            SELECT t.transaction_date, t.transaction_type, t.quantity_change, 
                   t.warehouse, u.full_name, t.notes
            FROM inventory_transactions t
            JOIN users u ON t.recorded_by = u.id
            WHERE t.material_id=?
            ORDER BY t.transaction_date DESC
            LIMIT 50
        ''', (material_id,))
        transactions = self.db.cursor.fetchall()

        history_table = QTableWidget()
        history_table.setColumnCount(6)
        history_table.setHorizontalHeaderLabels(["Date", "Type", "Qty Change", "Warehouse", "User", "Notes"])
        history_table.setRowCount(len(transactions))

        for row_idx, row_data in enumerate(transactions):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                history_table.setItem(row_idx, col_idx, item)

        history_layout.addWidget(history_table)
        history_tab.setLayout(history_layout)
        tabs.addTab(history_tab, "History")

        layout.addWidget(info_group)
        layout.addWidget(tabs)

        details_dialog.setLayout(layout)
        details_dialog.exec_()

    def add_project_pricing(self, material_id):
        project_id = self.pricing_project.currentData()
        price = self.pricing_price.value()

        if not project_id or price <= 0:
            QMessageBox.warning(self, "Error", "Please select a project and enter a valid price!")
            return

        try:
            self.db.cursor.execute('''
                INSERT OR REPLACE INTO project_pricing (material_id, project_id, sale_price)
                VALUES (?, ?, ?)
            ''', (material_id, project_id, price))
            self.db.connection.commit()

            QMessageBox.information(self, "Success", "Project pricing updated successfully!")

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to update pricing: {str(e)}")

    def edit_material(self):
        btn = self.sender()
        row = btn.property('row')
        material_id = int(self.inventory_table.item(row, 0).text())

        self.db.cursor.execute("SELECT * FROM materials WHERE id=?", (material_id,))
        material = self.db.cursor.fetchone()

        self.edit_material_dialog = QWidget()
        self.edit_material_dialog.setWindowTitle("Edit Material")
        self.edit_material_dialog.setFixedSize(500, 400)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.edit_material_id = material_id
        self.edit_material_name = QLineEdit(material[1])

        self.edit_material_category = QComboBox()
        self.edit_material_category.setEditable(True)
        self.db.cursor.execute("SELECT DISTINCT category FROM materials ORDER BY category")
        categories = [row[0] for row in self.db.cursor.fetchall()]
        self.edit_material_category.addItems(categories)
        self.edit_material_category.setCurrentText(material[2])

        self.edit_material_description = QLineEdit(material[3] if material[3] else "")

        self.edit_material_unit = QComboBox()
        self.edit_material_unit.setEditable(True)
        self.edit_material_unit.addItems(["Each", "Box", "Pallet", "Kg", "Lb", "Meter", "Foot", "Liter", "Gallon"])
        self.edit_material_unit.setCurrentText(material[4])

        self.edit_material_supplier = QComboBox()
        self.edit_material_supplier.addItem("None", None)
        self.db.cursor.execute("SELECT id, name FROM suppliers ORDER BY name")
        suppliers = self.db.cursor.fetchall()
        for supplier in suppliers:
            self.edit_material_supplier.addItem(supplier[1], supplier[0])
            if supplier[0] == material[5]:  # Current supplier
                self.edit_material_supplier.setCurrentIndex(self.edit_material_supplier.count() - 1)

        self.edit_material_cost = QDoubleSpinBox()
        self.edit_material_cost.setPrefix("$ ")
        self.edit_material_cost.setMaximum(99999.99)
        self.edit_material_cost.setValue(material[6])

        self.edit_min_stock_level = QSpinBox()
        self.edit_min_stock_level.setMinimum(0)
        self.edit_min_stock_level.setMaximum(9999)
        self.edit_min_stock_level.setValue(material[7])

        update_btn = QPushButton("Update Material")
        update_btn.clicked.connect(self.update_material)

        layout.addWidget(QLabel("Material Name:"))
        layout.addWidget(self.edit_material_name)
        layout.addWidget(QLabel("Category:"))
        layout.addWidget(self.edit_material_category)
        layout.addWidget(QLabel("Description:"))
        layout.addWidget(self.edit_material_description)
        layout.addWidget(QLabel("Unit of Measure:"))
        layout.addWidget(self.edit_material_unit)
        layout.addWidget(QLabel("Supplier:"))
        layout.addWidget(self.edit_material_supplier)
        layout.addWidget(QLabel("Cost Price:"))
        layout.addWidget(self.edit_material_cost)
        layout.addWidget(QLabel("Minimum Stock Level:"))
        layout.addWidget(self.edit_min_stock_level)
        layout.addWidget(update_btn)

        self.edit_material_dialog.setLayout(layout)
        self.edit_material_dialog.show()

    def update_material(self):
        material_id = self.edit_material_id
        name = self.edit_material_name.text().strip()
        category = self.edit_material_category.currentText().strip()
        description = self.edit_material_description.text().strip()
        unit = self.edit_material_unit.currentText().strip()
        supplier_id = self.edit_material_supplier.currentData()
        cost_price = self.edit_material_cost.value()
        min_stock = self.edit_min_stock_level.value()

        if not name:
            QMessageBox.warning(self.edit_material_dialog, "Error", "Material name is required!")
            return

        try:
            self.db.cursor.execute('''
                UPDATE materials 
                SET name=?, category=?, description=?, unit=?, supplier_id=?, cost_price=?, min_stock_level=?
                WHERE id=?
            ''', (name, category, description, unit, supplier_id, cost_price, min_stock, material_id))
            self.db.connection.commit()

            QMessageBox.information(self.edit_material_dialog, "Success", "Material updated successfully!")
            self.edit_material_dialog.close()
            self.load_materials()

        except sqlite3.Error as e:
            QMessageBox.critical(self.edit_material_dialog, "Database Error", f"Failed to update material: {str(e)}")

    def delete_material(self):
        btn = self.sender()
        row = btn.property('row')
        material_id = int(self.inventory_table.item(row, 0).text())

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete material ID {material_id}? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            try:
                # Check if material is referenced in any transactions
                self.db.cursor.execute("SELECT COUNT(*) FROM inventory_transactions WHERE material_id=?",
                                       (material_id,))
                if self.db.cursor.fetchone()[0] > 0:
                    QMessageBox.warning(self, "Cannot Delete",
                                        "This material has transaction history and cannot be deleted.")
                    return

                self.db.cursor.execute("DELETE FROM materials WHERE id=?", (material_id,))
                self.db.connection.commit()

                QMessageBox.information(self, "Success", "Material deleted successfully!")
                self.load_materials()
                self.load_dashboard_data()

            except sqlite3.Error as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete material: {str(e)}")

    def adjust_inventory(self):
        btn = self.sender()
        row = btn.property('row')
        material_id = int(self.inventory_table.item(row, 0).text())
        material_name = self.inventory_table.item(row, 1).text()

        self.db.cursor.execute('''
            SELECT warehouse, quantity FROM inventory WHERE material_id=?
        ''', (material_id,))
        current_inventory = self.db.cursor.fetchall()

        self.adjust_dialog = QWidget()
        self.adjust_dialog.setWindowTitle(f"Adjust Inventory - {material_name}")
        self.adjust_dialog.setFixedSize(400, 300)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.adjust_material_id = material_id

        # Warehouse selection
        self.adjust_warehouse = QComboBox()
        for warehouse, qty in current_inventory:
            self.adjust_warehouse.addItem(f"{warehouse} (Current: {qty})", warehouse)

        # Allow new warehouse if not in list
        self.adjust_warehouse.setEditable(True)
        self.adjust_warehouse.addItem("Add New Warehouse...", None)

        # Adjustment type
        self.adjust_type = QComboBox()
        self.adjust_type.addItems(["Add Stock", "Remove Stock", "Set Exact Quantity"])

        # Adjustment quantity
        self.adjust_quantity = QDoubleSpinBox()
        self.adjust_quantity.setMinimum(0)
        self.adjust_quantity.setMaximum(99999)
        self.adjust_quantity.setValue(0)

        # Notes
        self.adjust_notes = QLineEdit()
        self.adjust_notes.setPlaceholderText("Reason for adjustment (required)")

        adjust_btn = QPushButton("Apply Adjustment")
        adjust_btn.clicked.connect(self.apply_inventory_adjustment)

        layout.addWidget(QLabel("Warehouse:"))
        layout.addWidget(self.adjust_warehouse)
        layout.addWidget(QLabel("Adjustment Type:"))
        layout.addWidget(self.adjust_type)
        layout.addWidget(QLabel("Quantity:"))
        layout.addWidget(self.adjust_quantity)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.adjust_notes)
        layout.addWidget(adjust_btn)

        self.adjust_dialog.setLayout(layout)
        self.adjust_dialog.show()

    def apply_inventory_adjustment(self):
        material_id = self.adjust_material_id
        warehouse = self.adjust_warehouse.currentText().split(" (Current:")[0].strip()
        adjust_type = self.adjust_type.currentIndex()
        quantity = self.adjust_quantity.value()
        notes = self.adjust_notes.text().strip()

        if not notes:
            QMessageBox.warning(self.adjust_dialog, "Error", "Please enter a reason for this adjustment!")
            return

        if quantity <= 0:
            QMessageBox.warning(self.adjust_dialog, "Error", "Quantity must be greater than zero!")
            return

        try:
            # Start transaction
            self.db.cursor.execute("BEGIN TRANSACTION")

            # Get current quantity
            self.db.cursor.execute('''
                SELECT quantity FROM inventory 
                WHERE material_id=? AND warehouse=?
            ''', (material_id, warehouse))
            result = self.db.cursor.fetchone()
            current_qty = result[0] if result else 0

            # Calculate new quantity based on adjustment type
            if adjust_type == 0:  # Add stock
                new_qty = current_qty + quantity
                trans_type = "Adjustment"
                trans_qty = quantity
            elif adjust_type == 1:  # Remove stock
                if quantity > current_qty:
                    QMessageBox.warning(self.adjust_dialog, "Error",
                                        f"Cannot remove more than current quantity ({current_qty})!")
                    self.db.connection.rollback()
                    return
                new_qty = current_qty - quantity
                trans_type = "Adjustment"
                trans_qty = -quantity
            else:  # Set exact quantity
                new_qty = quantity
                trans_type = "Adjustment"
                trans_qty = new_qty - current_qty

            # Update inventory
            self.db.cursor.execute('''
                INSERT OR REPLACE INTO inventory (material_id, warehouse, quantity, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (material_id, warehouse, new_qty, datetime.now().isoformat()))

            # Record transaction
            self.db.cursor.execute('''
                INSERT INTO inventory_transactions (
                    material_id, warehouse, quantity_change, transaction_type,
                    transaction_date, recorded_by, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                material_id, warehouse, trans_qty, trans_type,
                datetime.now().isoformat(), self.user['id'], notes
            ))

            self.db.connection.commit()

            QMessageBox.information(self.adjust_dialog, "Success", "Inventory adjusted successfully!")
            self.adjust_dialog.close()
            self.load_materials()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            self.db.connection.rollback()
            QMessageBox.critical(self.adjust_dialog, "Database Error", f"Failed to adjust inventory: {str(e)}")

    def init_projects(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Search and filter controls
        controls_layout = QHBoxLayout()

        self.search_project = QLineEdit()
        self.search_project.setPlaceholderText("Search projects...")
        self.search_project.textChanged.connect(self.load_projects)

        self.status_filter = QComboBox()
        self.status_filter.addItem("All Statuses")
        self.status_filter.addItems(["Planning", "Active", "On Hold", "Completed", "Cancelled"])
        self.status_filter.currentIndexChanged.connect(self.load_projects)

        add_project_btn = QPushButton("Add Project")
        add_project_btn.clicked.connect(self.show_add_project_dialog)

        controls_layout.addWidget(self.search_project)
        controls_layout.addWidget(QLabel("Status:"))
        controls_layout.addWidget(self.status_filter)
        controls_layout.addWidget(add_project_btn)

        # Projects table
        self.projects_table = QTableWidget()
        self.projects_table.setColumnCount(7)
        self.projects_table.setHorizontalHeaderLabels([
            "ID", "Name", "Client", "Start Date", "End Date", "Status", "Actions"
        ])
        self.projects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addLayout(controls_layout)
        layout.addWidget(self.projects_table)

        self.projects_tab.setLayout(layout)

        # Load projects
        self.load_projects()

    def load_projects(self):
        search_term = f"%{self.search_project.text()}%"
        status = self.status_filter.currentText() if self.status_filter.currentIndex() > 0 else "%"

        self.db.cursor.execute('''
            SELECT id, name, client_name, start_date, end_date, status
            FROM projects
            WHERE (name LIKE ? OR client_name LIKE ?)
            AND status LIKE ?
            ORDER BY status, name
        ''', (search_term, search_term, status))

        projects = self.db.cursor.fetchall()

        self.projects_table.setRowCount(len(projects))
        for row_idx, row_data in enumerate(projects):
            for col_idx, col_data in enumerate(row_data[:6]):  # Skip actions column
                item = QTableWidgetItem(str(col_data) if col_data else "N/A")
                self.projects_table.setItem(row_idx, col_idx, item)

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            view_btn = QPushButton("View")
            view_btn.setProperty('row', row_idx)
            view_btn.clicked.connect(self.view_project_details)

            edit_btn = QPushButton("Edit")
            edit_btn.setProperty('row', row_idx)
            edit_btn.clicked.connect(self.edit_project)

            delete_btn = QPushButton("Delete")
            delete_btn.setProperty('row', row_idx)
            delete_btn.clicked.connect(self.delete_project)

            actions_layout.addWidget(view_btn)
            actions_layout.addWidget(edit_btn)
            actions_layout.addWidget(delete_btn)
            actions_widget.setLayout(actions_layout)

            self.projects_table.setCellWidget(row_idx, 6, actions_widget)

            # Color coding by status
            status_item = self.projects_table.item(row_idx, 5)
            if status_item.text() == "Active":
                status_item.setBackground(Qt.green)
                status_item.setForeground(Qt.white)
            elif status_item.text() == "On Hold":
                status_item.setBackground(Qt.yellow)
            elif status_item.text() == "Completed":
                status_item.setBackground(Qt.blue)
                status_item.setForeground(Qt.white)
            elif status_item.text() == "Cancelled":
                status_item.setBackground(Qt.red)
                status_item.setForeground(Qt.white)

    def show_add_project_dialog(self):
        self.project_dialog = QWidget()
        self.project_dialog.setWindowTitle("Add New Project")
        self.project_dialog.setFixedSize(500, 400)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.project_name = QLineEdit()
        self.project_name.setPlaceholderText("Project Name")

        self.client_name = QLineEdit()
        self.client_name.setPlaceholderText("Client Name")

        self.project_address = QLineEdit()
        self.project_address.setPlaceholderText("Project Address (optional)")

        self.start_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate())
        self.start_date.setCalendarPopup(True)

        self.end_date = QDateEdit()
        self.end_date.setDate(QDate.currentDate().addMonths(1))
        self.end_date.setCalendarPopup(True)

        self.project_status = QComboBox()
        self.project_status.addItems(["Planning", "Active", "On Hold", "Completed", "Cancelled"])

        self.project_notes = QLineEdit()
        self.project_notes.setPlaceholderText("Notes (optional)")

        save_btn = QPushButton("Save Project")
        save_btn.clicked.connect(self.save_project)

        layout.addWidget(QLabel("Project Name:"))
        layout.addWidget(self.project_name)
        layout.addWidget(QLabel("Client Name:"))
        layout.addWidget(self.client_name)
        layout.addWidget(QLabel("Project Address:"))
        layout.addWidget(self.project_address)
        layout.addWidget(QLabel("Start Date:"))
        layout.addWidget(self.start_date)
        layout.addWidget(QLabel("End Date:"))
        layout.addWidget(self.end_date)
        layout.addWidget(QLabel("Status:"))
        layout.addWidget(self.project_status)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.project_notes)
        layout.addWidget(save_btn)

        self.project_dialog.setLayout(layout)
        self.project_dialog.show()

    def save_project(self):
        name = self.project_name.text().strip()
        client = self.client_name.text().strip()
        address = self.project_address.text().strip()
        start_date = self.start_date.date().toString("yyyy-MM-dd")
        end_date = self.end_date.date().toString("yyyy-MM-dd")
        status = self.project_status.currentText()
        notes = self.project_notes.text().strip()

        if not name or not client:
            QMessageBox.warning(self.project_dialog, "Error", "Project name and client name are required!")
            return

        try:
            self.db.cursor.execute('''
                INSERT INTO projects (name, client_name, address, start_date, end_date, status, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (name, client, address, start_date, end_date, status, notes))
            self.db.connection.commit()

            QMessageBox.information(self.project_dialog, "Success", "Project added successfully!")
            self.project_dialog.close()
            self.load_projects()

        except sqlite3.Error as e:
            QMessageBox.critical(self.project_dialog, "Database Error", f"Failed to save project: {str(e)}")

    def view_project_details(self):
        btn = self.sender()
        row = btn.property('row')
        project_id = int(self.projects_table.item(row, 0).text())

        self.db.cursor.execute("SELECT * FROM projects WHERE id=?", (project_id,))
        project = self.db.cursor.fetchone()

        self.db.cursor.execute('''
            SELECT s.id, s.sale_date, s.total_amount, s.payment_status, u.full_name
            FROM sales s
            JOIN users u ON s.recorded_by = u.id
            WHERE s.project_id=?
            ORDER BY s.sale_date DESC
        ''', (project_id,))
        sales = self.db.cursor.fetchall()

        self.db.cursor.execute('''
            SELECT m.name, pp.sale_price
            FROM project_pricing pp
            JOIN materials m ON pp.material_id = m.id
            WHERE pp.project_id=?
            ORDER BY m.name
        ''', (project_id,))
        materials = self.db.cursor.fetchall()

        # Create details dialog
        details_dialog = QWidget()
        details_dialog.setWindowTitle(f"Project Details - {project[1]}")
        details_dialog.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        # Basic info
        info_group = QWidget()
        info_layout = QVBoxLayout()

        info_layout.addWidget(QLabel(f"<h2>{project[1]}</h2>"))
        info_layout.addWidget(QLabel(f"<b>Client:</b> {project[2]}"))
        info_layout.addWidget(QLabel(f"<b>Address:</b> {project[3] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Dates:</b> {project[4]} to {project[5]}"))
        info_layout.addWidget(QLabel(f"<b>Status:</b> {project[6]}"))
        info_layout.addWidget(QLabel(f"<b>Notes:</b> {project[7] or 'N/A'}"))

        info_group.setLayout(info_layout)

        # Project tabs
        tabs = QTabWidget()

        # Sales tab
        sales_tab = QWidget()
        sales_layout = QVBoxLayout()

        sales_table = QTableWidget()
        sales_table.setColumnCount(5)
        sales_table.setHorizontalHeaderLabels(["ID", "Date", "Amount", "Status", "Recorded By"])
        sales_table.setRowCount(len(sales))

        for row_idx, row_data in enumerate(sales):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                sales_table.setItem(row_idx, col_idx, item)
                if col_idx == 2:  # Amount column
                    item.setText(f"${float(col_data):,.2f}")

        sales_layout.addWidget(sales_table)

        # Add new sale button
        if project[6] != "Completed" and project[6] != "Cancelled":
            new_sale_btn = QPushButton("New Sale")
            new_sale_btn.clicked.connect(lambda: self.create_project_sale(project_id))
            sales_layout.addWidget(new_sale_btn)

        sales_tab.setLayout(sales_layout)
        tabs.addTab(sales_tab, "Sales")

        # Materials tab
        materials_tab = QWidget()
        materials_layout = QVBoxLayout()

        materials_table = QTableWidget()
        materials_table.setColumnCount(2)
        materials_table.setHorizontalHeaderLabels(["Material", "Price"])
        materials_table.setRowCount(len(materials))

        for row_idx, row_data in enumerate(materials):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                materials_table.setItem(row_idx, col_idx, item)
                if col_idx == 1:  # Price column
                    item.setText(f"${float(col_data):,.2f}")

        materials_layout.addWidget(materials_table)

        # Add material pricing button
        if self.user['role'] in ('Admin', 'Manager') and project[6] != "Completed" and project[6] != "Cancelled":
            add_material_btn = QPushButton("Add Material Pricing")
            add_material_btn.clicked.connect(lambda: self.add_project_material_pricing(project_id))
            materials_layout.addWidget(add_material_btn)

        materials_tab.setLayout(materials_layout)
        tabs.addTab(materials_tab, "Materials")

        layout.addWidget(info_group)
        layout.addWidget(tabs)

        details_dialog.setLayout(layout)
        details_dialog.exec_()

    def create_project_sale(self, project_id):
        self.db.cursor.execute("SELECT name FROM projects WHERE id=?", (project_id,))
        project_name = self.db.cursor.fetchone()[0]

        self.sale_dialog = QWidget()
        self.sale_dialog.setWindowTitle(f"New Sale - {project_name}")
        self.sale_dialog.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        # Sale items table
        self.sale_items_table = QTableWidget()
        self.sale_items_table.setColumnCount(6)
        self.sale_items_table.setHorizontalHeaderLabels([
            "Material", "Warehouse", "Quantity", "Unit Price", "Total", "Actions"
        ])
        self.sale_items_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Add item controls
        add_item_layout = QHBoxLayout()

        self.sale_material = QComboBox()
        self.load_materials_for_sale(project_id)

        self.sale_warehouse = QComboBox()
        self.db.cursor.execute("SELECT DISTINCT warehouse FROM inventory ORDER BY warehouse")
        warehouses = self.db.cursor.fetchall()
        for warehouse in warehouses:
            self.sale_warehouse.addItem(warehouse[0])

        self.sale_quantity = QDoubleSpinBox()
        self.sale_quantity.setMinimum(0.01)
        self.sale_quantity.setMaximum(99999)
        self.sale_quantity.setValue(1)

        self.sale_unit_price = QDoubleSpinBox()
        self.sale_unit_price.setPrefix("$ ")
        self.sale_unit_price.setMaximum(99999.99)
        self.sale_unit_price.setValue(0)

        add_item_btn = QPushButton("Add Item")
        add_item_btn.clicked.connect(self.add_sale_item)

        add_item_layout.addWidget(QLabel("Material:"))
        add_item_layout.addWidget(self.sale_material)
        add_item_layout.addWidget(QLabel("Warehouse:"))
        add_item_layout.addWidget(self.sale_warehouse)
        add_item_layout.addWidget(QLabel("Quantity:"))
        add_item_layout.addWidget(self.sale_quantity)
        add_item_layout.addWidget(QLabel("Unit Price:"))
        add_item_layout.addWidget(self.sale_unit_price)
        add_item_layout.addWidget(add_item_btn)

        # Sale summary
        self.sale_summary = QLabel("Total: $0.00")
        self.sale_summary.setFont(QFont('Arial', 12, QFont.Bold))

        # Payment details
        payment_layout = QHBoxLayout()

        self.payment_status = QComboBox()
        self.payment_status.addItems(["Pending", "Partial", "Paid"])

        self.discount = QDoubleSpinBox()
        self.discount.setPrefix("$ ")
        self.discount.setMaximum(99999.99)
        self.discount.setValue(0)

        self.tax_amount = QDoubleSpinBox()
        self.tax_amount.setPrefix("$ ")
        self.tax_amount.setMaximum(99999.99)
        self.tax_amount.setValue(0)

        self.sale_notes = QLineEdit()
        self.sale_notes.setPlaceholderText("Sale notes (optional)")

        payment_layout.addWidget(QLabel("Payment Status:"))
        payment_layout.addWidget(self.payment_status)
        payment_layout.addWidget(QLabel("Discount:"))
        payment_layout.addWidget(self.discount)
        payment_layout.addWidget(QLabel("Tax:"))
        payment_layout.addWidget(self.tax_amount)

        # Save button
        save_sale_btn = QPushButton("Record Sale")
        save_sale_btn.clicked.connect(lambda: self.save_project_sale(project_id))

        layout.addWidget(self.sale_items_table)
        layout.addLayout(add_item_layout)
        layout.addWidget(self.sale_summary)
        layout.addLayout(payment_layout)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.sale_notes)
        layout.addWidget(save_sale_btn)

        self.sale_dialog.setLayout(layout)
        self.sale_dialog.show()

    def load_materials_for_sale(self, project_id):
        self.sale_material.clear()
        self.sale_material_map = {}  # material_id: (name, price)

        self.db.cursor.execute('''
            SELECT m.id, m.name, pp.sale_price, m.unit
            FROM project_pricing pp
            JOIN materials m ON pp.material_id = m.id
            WHERE pp.project_id=?
            ORDER BY m.name
        ''', (project_id,))

        materials = self.db.cursor.fetchall()
        for material in materials:
            self.sale_material.addItem(f"{material[1]} ({material[3]})", material[0])
            self.sale_material_map[material[0]] = (material[1], material[2])

        # Connect price update when material selection changes
        self.sale_material.currentIndexChanged.connect(self.update_sale_price)

    def update_sale_price(self):
        material_id = self.sale_material.currentData()
        if material_id in self.sale_material_map:
            _, price = self.sale_material_map[material_id]
            self.sale_unit_price.setValue(price)

    def add_sale_item(self):
        material_id = self.sale_material.currentData()
        material_name, unit_price = self.sale_material_map.get(material_id, ("", 0))
        warehouse = self.sale_warehouse.currentText()
        quantity = self.sale_quantity.value()
        price = self.sale_unit_price.value()
        total = quantity * price

        if not material_id or quantity <= 0:
            QMessageBox.warning(self.sale_dialog, "Error", "Please select a material and enter a valid quantity!")
            return

        # Check inventory availability
        self.db.cursor.execute('''
            SELECT quantity FROM inventory 
            WHERE material_id=? AND warehouse=?
        ''', (material_id, warehouse))
        result = self.db.cursor.fetchone()

        if not result or result[0] < quantity:
            QMessageBox.warning(self.sale_dialog, "Insufficient Stock",
                                f"Not enough stock in {warehouse} warehouse!")
            return

        # Add to sale items table
        row = self.sale_items_table.rowCount()
        self.sale_items_table.insertRow(row)

        self.sale_items_table.setItem(row, 0, QTableWidgetItem(material_name))
        self.sale_items_table.setItem(row, 1, QTableWidgetItem(warehouse))
        self.sale_items_table.setItem(row, 2, QTableWidgetItem(str(quantity)))
        self.sale_items_table.setItem(row, 3, QTableWidgetItem(f"${price:,.2f}"))
        self.sale_items_table.setItem(row, 4, QTableWidgetItem(f"${total:,.2f}"))

        # Add remove button
        remove_btn = QPushButton("Remove")
        remove_btn.setProperty('row', row)
        remove_btn.clicked.connect(self.remove_sale_item)

        cell_widget = QWidget()
        layout = QHBoxLayout()
        layout.addWidget(remove_btn)
        layout.setContentsMargins(0, 0, 0, 0)
        cell_widget.setLayout(layout)

        self.sale_items_table.setCellWidget(row, 5, cell_widget)

        # Update total
        self.update_sale_total()

    def remove_sale_item(self):
        btn = self.sender()
        row = btn.property('row')
        self.sale_items_table.removeRow(row)

        # Update row properties for remaining buttons
        for r in range(row, self.sale_items_table.rowCount()):
            btn = self.sale_items_table.cellWidget(r, 5).findChild(QPushButton)
            btn.setProperty('row', r)

        self.update_sale_total()

    def update_sale_total(self):
        total = 0
        for row in range(self.sale_items_table.rowCount()):
            total_text = self.sale_items_table.item(row, 4).text().replace("$", "").replace(",", "")
            total += float(total_text)

        self.sale_summary.setText(f"Total: ${total:,.2f}")

    def save_project_sale(self, project_id):
        if self.sale_items_table.rowCount() == 0:
            QMessageBox.warning(self.sale_dialog, "Error", "Please add at least one item to the sale!")
            return

        # Calculate totals
        subtotal = 0
        for row in range(self.sale_items_table.rowCount()):
            total_text = self.sale_items_table.item(row, 4).text().replace("$", "").replace(",", "")
            subtotal += float(total_text)

        discount = self.discount.value()
        tax = self.tax_amount.value()
        total = subtotal - discount + tax
        payment_status = self.payment_status.currentText()
        notes = self.sale_notes.text().strip()

        try:
            # Start transaction
            self.db.cursor.execute("BEGIN TRANSACTION")

            # Create sale record
            self.db.cursor.execute('''
                INSERT INTO sales (
                    project_id, sale_date, total_amount, discount, tax_amount, 
                    payment_status, recorded_by, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                project_id, datetime.now().isoformat(), total, discount, tax,
                payment_status, self.user['id'], notes
            ))

            sale_id = self.db.cursor.lastrowid

            # Add sale items and update inventory
            for row in range(self.sale_items_table.rowCount()):
                material_name = self.sale_items_table.item(row, 0).text()
                warehouse = self.sale_items_table.item(row, 1).text()
                quantity = float(self.sale_items_table.item(row, 2).text())
                unit_price = float(self.sale_items_table.item(row, 3).text().replace("$", "").replace(",", ""))

                # Get material ID
                self.db.cursor.execute('''
                    SELECT id FROM materials WHERE name=?
                ''', (material_name,))
                material_id = self.db.cursor.fetchone()[0]

                # Add sale item
                self.db.cursor.execute('''
                    INSERT INTO sale_items (
                        sale_id, material_id, quantity, unit_price, total_price, warehouse
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (sale_id, material_id, quantity, unit_price, quantity * unit_price, warehouse))

                # Update inventory
                self.db.cursor.execute('''
                    UPDATE inventory 
                    SET quantity = quantity - ?, last_updated = ?
                    WHERE material_id = ? AND warehouse = ?
                ''', (quantity, datetime.now().isoformat(), material_id, warehouse))

                # Record inventory transaction
                self.db.cursor.execute('''
                    INSERT INTO inventory_transactions (
                        material_id, warehouse, quantity_change, transaction_type,
                        reference_id, transaction_date, recorded_by, notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    material_id, warehouse, -quantity, 'Sale',
                    sale_id, datetime.now().isoformat(), self.user['id'],
                    f"Sale #{sale_id}"
                ))

            self.db.connection.commit()

            QMessageBox.information(self.sale_dialog, "Success", "Sale recorded successfully!")
            self.sale_dialog.close()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            self.db.connection.rollback()
            QMessageBox.critical(self.sale_dialog, "Database Error", f"Failed to record sale: {str(e)}")

    def add_project_material_pricing(self, project_id):
        self.db.cursor.execute("SELECT name FROM projects WHERE id=?", (project_id,))
        project_name = self.db.cursor.fetchone()[0]

        self.pricing_dialog = QWidget()
        self.pricing_dialog.setWindowTitle(f"Add Material Pricing - {project_name}")
        self.pricing_dialog.setFixedSize(500, 300)

        layout = QVBoxLayout()

        # Material selection
        self.pricing_material = QComboBox()
        self.db.cursor.execute('''
            SELECT m.id, m.name 
            FROM materials m
            LEFT JOIN project_pricing pp ON m.id = pp.material_id AND pp.project_id=?
            WHERE pp.material_id IS NULL
            ORDER BY m.name
        ''', (project_id,))
        materials = self.db.cursor.fetchall()
        for material in materials:
            self.pricing_material.addItem(material[1], material[0])

        # Price input
        self.pricing_price = QDoubleSpinBox()
        self.pricing_price.setPrefix("$ ")
        self.pricing_price.setMaximum(99999.99)
        self.pricing_price.setValue(0)

        # Save button
        save_btn = QPushButton("Save Pricing")
        save_btn.clicked.connect(lambda: self.save_project_material_pricing(project_id))

        layout.addWidget(QLabel("Material:"))
        layout.addWidget(self.pricing_material)
        layout.addWidget(QLabel("Price:"))
        layout.addWidget(self.pricing_price)
        layout.addWidget(save_btn)

        self.pricing_dialog.setLayout(layout)
        self.pricing_dialog.show()

    def save_project_material_pricing(self, project_id):
        material_id = self.pricing_material.currentData()
        price = self.pricing_price.value()

        if not material_id or price <= 0:
            QMessageBox.warning(self.pricing_dialog, "Error", "Please select a material and enter a valid price!")
            return

        try:
            self.db.cursor.execute('''
                INSERT INTO project_pricing (material_id, project_id, sale_price)
                VALUES (?, ?, ?)
            ''', (material_id, project_id, price))
            self.db.connection.commit()

            QMessageBox.information(self.pricing_dialog, "Success", "Material pricing added successfully!")
            self.pricing_dialog.close()

        except sqlite3.Error as e:
            QMessageBox.critical(self.pricing_dialog, "Database Error", f"Failed to save pricing: {str(e)}")

    def edit_project(self):
        btn = self.sender()
        row = btn.property('row')
        project_id = int(self.projects_table.item(row, 0).text())

        self.db.cursor.execute("SELECT * FROM projects WHERE id=?", (project_id,))
        project = self.db.cursor.fetchone()

        self.edit_project_dialog = QWidget()
        self.edit_project_dialog.setWindowTitle("Edit Project")
        self.edit_project_dialog.setFixedSize(500, 400)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.edit_project_id = project_id
        self.edit_project_name = QLineEdit(project[1])
        self.edit_client_name = QLineEdit(project[2])
        self.edit_project_address = QLineEdit(project[3] if project[3] else "")

        self.edit_start_date = QDateEdit()
        self.edit_start_date.setCalendarPopup(True)
        self.edit_start_date.setDate(QDate.fromString(project[4], "yyyy-MM-dd"))

        self.edit_end_date = QDateEdit()
        self.edit_end_date.setCalendarPopup(True)
        self.edit_end_date.setDate(QDate.fromString(project[5], "yyyy-MM-dd"))

        self.edit_project_status = QComboBox()
        self.edit_project_status.addItems(["Planning", "Active", "On Hold", "Completed", "Cancelled"])
        self.edit_project_status.setCurrentText(project[6])

        self.edit_project_notes = QLineEdit(project[7] if project[7] else "")

        update_btn = QPushButton("Update Project")
        update_btn.clicked.connect(self.update_project)

        layout.addWidget(QLabel("Project Name:"))
        layout.addWidget(self.edit_project_name)
        layout.addWidget(QLabel("Client Name:"))
        layout.addWidget(self.edit_client_name)
        layout.addWidget(QLabel("Project Address:"))
        layout.addWidget(self.edit_project_address)
        layout.addWidget(QLabel("Start Date:"))
        layout.addWidget(self.edit_start_date)
        layout.addWidget(QLabel("End Date:"))
        layout.addWidget(self.edit_end_date)
        layout.addWidget(QLabel("Status:"))
        layout.addWidget(self.edit_project_status)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.edit_project_notes)
        layout.addWidget(update_btn)

        self.edit_project_dialog.setLayout(layout)
        self.edit_project_dialog.show()

    def update_project(self):
        project_id = self.edit_project_id
        name = self.edit_project_name.text().strip()
        client = self.edit_client_name.text().strip()
        address = self.edit_project_address.text().strip()
        start_date = self.edit_start_date.date().toString("yyyy-MM-dd")
        end_date = self.edit_end_date.date().toString("yyyy-MM-dd")
        status = self.edit_project_status.currentText()
        notes = self.edit_project_notes.text().strip()

        if not name or not client:
            QMessageBox.warning(self.edit_project_dialog, "Error", "Project name and client name are required!")
            return

        try:
            self.db.cursor.execute('''
                UPDATE projects 
                SET name=?, client_name=?, address=?, start_date=?, end_date=?, status=?, notes=?
                WHERE id=?
            ''', (name, client, address, start_date, end_date, status, notes, project_id))
            self.db.connection.commit()

            QMessageBox.information(self.edit_project_dialog, "Success", "Project updated successfully!")
            self.edit_project_dialog.close()
            self.load_projects()

        except sqlite3.Error as e:
            QMessageBox.critical(self.edit_project_dialog, "Database Error", f"Failed to update project: {str(e)}")

    def delete_project(self):
        btn = self.sender()
        row = btn.property('row')
        project_id = int(self.projects_table.item(row, 0).text())

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete project ID {project_id}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            try:
                # Check if project has any sales
                self.db.cursor.execute("SELECT COUNT(*) FROM sales WHERE project_id=?", (project_id,))
                if self.db.cursor.fetchone()[0] > 0:
                    QMessageBox.warning(self, "Cannot Delete",
                                        "This project has sales records and cannot be deleted.")
                    return

                self.db.cursor.execute("DELETE FROM projects WHERE id=?", (project_id,))
                self.db.cursor.execute("DELETE FROM project_pricing WHERE project_id=?", (project_id,))
                self.db.connection.commit()

                QMessageBox.information(self, "Success", "Project deleted successfully!")
                self.load_projects()

            except sqlite3.Error as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete project: {str(e)}")

    def init_sales(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Date filter
        filter_layout = QHBoxLayout()

        self.sales_date_from = QDateEdit()
        self.sales_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.sales_date_from.setCalendarPopup(True)

        self.sales_date_to = QDateEdit()
        self.sales_date_to.setDate(QDate.currentDate())
        self.sales_date_to.setCalendarPopup(True)

        self.sales_status_filter = QComboBox()
        self.sales_status_filter.addItem("All Statuses")
        self.sales_status_filter.addItems(["Pending", "Partial", "Paid"])

        filter_btn = QPushButton("Filter")
        filter_btn.clicked.connect(self.load_sales)

        filter_layout.addWidget(QLabel("From:"))
        filter_layout.addWidget(self.sales_date_from)
        filter_layout.addWidget(QLabel("To:"))
        filter_layout.addWidget(self.sales_date_to)
        filter_layout.addWidget(QLabel("Status:"))
        filter_layout.addWidget(self.sales_status_filter)
        filter_layout.addWidget(filter_btn)

        # Sales table
        self.sales_table = QTableWidget()
        self.sales_table.setColumnCount(7)
        self.sales_table.setHorizontalHeaderLabels([
            "ID", "Date", "Project", "Amount", "Status", "Recorded By", "Actions"
        ])
        self.sales_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addLayout(filter_layout)
        layout.addWidget(self.sales_table)

        self.sales_tab.setLayout(layout)

        # Load sales data
        self.load_sales()

    def load_sales(self):
        date_from = self.sales_date_from.date().toString("yyyy-MM-dd")
        date_to = self.sales_date_to.date().addDays(1).toString("yyyy-MM-dd")  # Include end date
        status = self.sales_status_filter.currentText() if self.sales_status_filter.currentIndex() > 0 else "%"

        self.db.cursor.execute('''
            SELECT s.id, s.sale_date, p.name, s.total_amount, s.payment_status, u.full_name
            FROM sales s
            JOIN projects p ON s.project_id = p.id
            JOIN users u ON s.recorded_by = u.id
            WHERE s.sale_date BETWEEN ? AND ?
            AND s.payment_status LIKE ?
            ORDER BY s.sale_date DESC
        ''', (date_from, date_to, status))

        sales = self.db.cursor.fetchall()

        self.sales_table.setRowCount(len(sales))
        for row_idx, row_data in enumerate(sales):
            for col_idx, col_data in enumerate(row_data[:6]):  # Skip actions column
                item = QTableWidgetItem(str(col_data))
                self.sales_table.setItem(row_idx, col_idx, item)

                # Format numeric columns
                if col_idx == 3:  # Amount column
                    item.setText(f"${float(col_data):,.2f}")

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            view_btn = QPushButton("View")
            view_btn.setProperty('row', row_idx)
            view_btn.clicked.connect(self.view_sale_details)

            # Only allow editing for recent sales and if user is admin/manager
            if (datetime.now() - datetime.strptime(row_data[1], "%Y-%m-%d %H:%M:%S")).days < 7 and \
                    self.user['role'] in ('Admin', 'Manager'):
                edit_btn = QPushButton("Edit")
                edit_btn.setProperty('row', row_idx)
                edit_btn.clicked.connect(self.edit_sale)
                actions_layout.addWidget(edit_btn)

            actions_layout.addWidget(view_btn)
            actions_widget.setLayout(actions_layout)

            self.sales_table.setCellWidget(row_idx, 6, actions_widget)

            # Color coding by status
            status_item = self.sales_table.item(row_idx, 4)
            if status_item.text() == "Pending":
                status_item.setBackground(Qt.yellow)
            elif status_item.text() == "Partial":
                status_item.setBackground(Qt.blue)
                status_item.setForeground(Qt.white)
            elif status_item.text() == "Paid":
                status_item.setBackground(Qt.green)
                status_item.setForeground(Qt.white)

    def view_sale_details(self):
        btn = self.sender()
        row = btn.property('row')
        sale_id = int(self.sales_table.item(row, 0).text())

        self.db.cursor.execute('''
            SELECT s.*, p.name as project_name, u.full_name as recorded_by
            FROM sales s
            JOIN projects p ON s.project_id = p.id
            JOIN users u ON s.recorded_by = u.id
            WHERE s.id=?
        ''', (sale_id,))
        sale = self.db.cursor.fetchone()

        self.db.cursor.execute('''
            SELECT si.id, m.name, si.quantity, si.unit_price, si.total_price, si.warehouse
            FROM sale_items si
            JOIN materials m ON si.material_id = m.id
            WHERE si.sale_id=?
            ORDER BY m.name
        ''', (sale_id,))
        items = self.db.cursor.fetchall()

        # Create details dialog
        details_dialog = QWidget()
        details_dialog.setWindowTitle(f"Sale Details - #{sale_id}")
        details_dialog.setMinimumSize(600, 500)

        layout = QVBoxLayout()

        # Sale info
        info_group = QWidget()
        info_layout = QVBoxLayout()

        info_layout.addWidget(QLabel(f"<h2>Sale #{sale_id}</h2>"))
        info_layout.addWidget(QLabel(f"<b>Project:</b> {sale[9]}"))
        info_layout.addWidget(QLabel(f"<b>Date:</b> {sale[2]}"))
        info_layout.addWidget(QLabel(f"<b>Recorded By:</b> {sale[10]}"))
        info_layout.addWidget(QLabel(f"<b>Status:</b> {sale[6]}"))
        info_layout.addWidget(QLabel(f"<b>Subtotal:</b> ${sale[3] + sale[4] - sale[5]:,.2f}"))
        info_layout.addWidget(QLabel(f"<b>Discount:</b> ${sale[4]:,.2f}"))
        info_layout.addWidget(QLabel(f"<b>Tax:</b> ${sale[5]:,.2f}"))
        info_layout.addWidget(QLabel(f"<b>Total:</b> ${sale[3]:,.2f}"))
        info_layout.addWidget(QLabel(f"<b>Notes:</b> {sale[8] or 'N/A'}"))

        info_group.setLayout(info_layout)

        # Items table
        items_table = QTableWidget()
        items_table.setColumnCount(5)
        items_table.setHorizontalHeaderLabels(["Material", "Quantity", "Unit Price", "Total", "Warehouse"])
        items_table.setRowCount(len(items))

        for row_idx, row_data in enumerate(items):
            for col_idx, col_data in enumerate(row_data[1:]):  # Skip ID
                item = QTableWidgetItem(str(col_data))
                items_table.setItem(row_idx, col_idx, item)

                # Format numeric columns
                if col_idx in (2, 3):  # Price columns
                    item.setText(f"${float(col_data):,.2f}")

        layout.addWidget(info_group)
        layout.addWidget(QLabel("<b>Items:</b>"))
        layout.addWidget(items_table)

        details_dialog.setLayout(layout)
        details_dialog.exec_()

    def edit_sale(self):
        btn = self.sender()
        row = btn.property('row')
        sale_id = int(self.sales_table.item(row, 0).text())

        self.db.cursor.execute('''
            SELECT s.*, p.name as project_name
            FROM sales s
            JOIN projects p ON s.project_id = p.id
            WHERE s.id=?
        ''', (sale_id,))
        sale = self.db.cursor.fetchone()

        self.db.cursor.execute('''
            SELECT si.id, m.id as material_id, m.name, si.quantity, si.unit_price, si.total_price, si.warehouse
            FROM sale_items si
            JOIN materials m ON si.material_id = m.id
            WHERE si.sale_id=?
            ORDER BY m.name
        ''', (sale_id,))
        items = self.db.cursor.fetchall()

        self.edit_sale_dialog = QWidget()
        self.edit_sale_dialog.setWindowTitle(f"Edit Sale - #{sale_id}")
        self.edit_sale_dialog.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        # Sale items table
        self.edit_sale_items_table = QTableWidget()
        self.edit_sale_items_table.setColumnCount(6)
        self.edit_sale_items_table.setHorizontalHeaderLabels([
            "Material", "Warehouse", "Quantity", "Unit Price", "Total", "Actions"
        ])
        self.edit_sale_items_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Add existing items to table
        for item in items:
            row = self.edit_sale_items_table.rowCount()
            self.edit_sale_items_table.insertRow(row)

            self.edit_sale_items_table.setItem(row, 0, QTableWidgetItem(item[2]))  # Material name
            self.edit_sale_items_table.setItem(row, 1, QTableWidgetItem(item[6]))  # Warehouse
            self.edit_sale_items_table.setItem(row, 2, QTableWidgetItem(str(item[3])))  # Quantity
            self.edit_sale_items_table.setItem(row, 3, QTableWidgetItem(f"${item[4]:,.2f}"))  # Unit price
            self.edit_sale_items_table.setItem(row, 4, QTableWidgetItem(f"${item[5]:,.2f}"))  # Total

            # Add remove button
            remove_btn = QPushButton("Remove")
            remove_btn.setProperty('row', row)
            remove_btn.setProperty('item_id', item[0])  # Store sale item ID
            remove_btn.clicked.connect(self.remove_edit_sale_item)

            cell_widget = QWidget()
            btn_layout = QHBoxLayout()
            btn_layout.addWidget(remove_btn)
            btn_layout.setContentsMargins(0, 0, 0, 0)
            cell_widget.setLayout(btn_layout)

            self.edit_sale_items_table.setCellWidget(row, 5, cell_widget)

        # Add item controls
        add_item_layout = QHBoxLayout()

        self.edit_sale_material = QComboBox()
        self.load_materials_for_sale(sale[1])  # project_id

        self.edit_sale_warehouse = QComboBox()
        self.db.cursor.execute("SELECT DISTINCT warehouse FROM inventory ORDER BY warehouse")
        warehouses = self.db.cursor.fetchall()
        for warehouse in warehouses:
            self.edit_sale_warehouse.addItem(warehouse[0])

        self.edit_sale_quantity = QDoubleSpinBox()
        self.edit_sale_quantity.setMinimum(0.01)
        self.edit_sale_quantity.setMaximum(99999)
        self.edit_sale_quantity.setValue(1)

        self.edit_sale_unit_price = QDoubleSpinBox()
        self.edit_sale_unit_price.setPrefix("$ ")
        self.edit_sale_unit_price.setMaximum(99999.99)
        self.edit_sale_unit_price.setValue(0)

        add_item_btn = QPushButton("Add Item")
        add_item_btn.clicked.connect(self.add_edit_sale_item)

        add_item_layout.addWidget(QLabel("Material:"))
        add_item_layout.addWidget(self.edit_sale_material)
        add_item_layout.addWidget(QLabel("Warehouse:"))
        add_item_layout.addWidget(self.edit_sale_warehouse)
        add_item_layout.addWidget(QLabel("Quantity:"))
        add_item_layout.addWidget(self.edit_sale_quantity)
        add_item_layout.addWidget(QLabel("Unit Price:"))
        add_item_layout.addWidget(self.edit_sale_unit_price)
        add_item_layout.addWidget(add_item_btn)

        # Sale summary
        self.edit_sale_summary = QLabel(f"Total: ${sale[3]:,.2f}")
        self.edit_sale_summary.setFont(QFont('Arial', 12, QFont.Bold))

        # Payment details
        payment_layout = QHBoxLayout()

        self.edit_payment_status = QComboBox()
        self.edit_payment_status.addItems(["Pending", "Partial", "Paid"])
        self.edit_payment_status.setCurrentText(sale[6])

        self.edit_discount = QDoubleSpinBox()
        self.edit_discount.setPrefix("$ ")
        self.edit_discount.setMaximum(99999.99)
        self.edit_discount.setValue(sale[4])

        self.edit_tax_amount = QDoubleSpinBox()
        self.edit_tax_amount.setPrefix("$ ")
        self.edit_tax_amount.setMaximum(99999.99)
        self.edit_tax_amount.setValue(sale[5])

        self.edit_sale_notes = QLineEdit(sale[8] if sale[8] else "")

        payment_layout.addWidget(QLabel("Payment Status:"))
        payment_layout.addWidget(self.edit_payment_status)
        payment_layout.addWidget(QLabel("Discount:"))
        payment_layout.addWidget(self.edit_discount)
        payment_layout.addWidget(QLabel("Tax:"))
        payment_layout.addWidget(self.edit_tax_amount)

        # Save button
        save_btn = QPushButton("Update Sale")
        save_btn.clicked.connect(lambda: self.update_sale(sale_id, sale[1]))  # sale_id, project_id

        layout.addWidget(self.edit_sale_items_table)
        layout.addLayout(add_item_layout)
        layout.addWidget(self.edit_sale_summary)
        layout.addLayout(payment_layout)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.edit_sale_notes)
        layout.addWidget(save_btn)

        self.edit_sale_dialog.setLayout(layout)
        self.edit_sale_dialog.show()

        # Connect price update when material selection changes
        self.edit_sale_material.currentIndexChanged.connect(self.update_edit_sale_price)

    def update_edit_sale_price(self):
        material_id = self.edit_sale_material.currentData()
        if material_id in self.sale_material_map:
            _, price = self.sale_material_map[material_id]
            self.edit_sale_unit_price.setValue(price)

    def add_edit_sale_item(self):
        material_id = self.edit_sale_material.currentData()
        material_name, unit_price = self.sale_material_map.get(material_id, ("", 0))
        warehouse = self.edit_sale_warehouse.currentText()
        quantity = self.edit_sale_quantity.value()
        price = self.edit_sale_unit_price.value()
        total = quantity * price

        if not material_id or quantity <= 0:
            QMessageBox.warning(self.edit_sale_dialog, "Error", "Please select a material and enter a valid quantity!")
            return

        # Check inventory availability
        self.db.cursor.execute('''
            SELECT quantity FROM inventory 
            WHERE material_id=? AND warehouse=?
        ''', (material_id, warehouse))
        result = self.db.cursor.fetchone()

        if not result or result[0] < quantity:
            QMessageBox.warning(self.edit_sale_dialog, "Insufficient Stock",
                                f"Not enough stock in {warehouse} warehouse!")
            return

        # Add to sale items table
        row = self.edit_sale_items_table.rowCount()
        self.edit_sale_items_table.insertRow(row)

        self.edit_sale_items_table.setItem(row, 0, QTableWidgetItem(material_name))
        self.edit_sale_items_table.setItem(row, 1, QTableWidgetItem(warehouse))
        self.edit_sale_items_table.setItem(row, 2, QTableWidgetItem(str(quantity)))
        self.edit_sale_items_table.setItem(row, 3, QTableWidgetItem(f"${price:,.2f}"))
        self.edit_sale_items_table.setItem(row, 4, QTableWidgetItem(f"${total:,.2f}"))

        # Add remove button with negative item_id to indicate new item
        remove_btn = QPushButton("Remove")
        remove_btn.setProperty('row', row)
        remove_btn.setProperty('item_id', -1)  # -1 indicates new item
        remove_btn.clicked.connect(self.remove_edit_sale_item)

        cell_widget = QWidget()
        layout = QHBoxLayout()
        layout.addWidget(remove_btn)
        layout.setContentsMargins(0, 0, 0, 0)
        cell_widget.setLayout(layout)

        self.edit_sale_items_table.setCellWidget(row, 5, cell_widget)

        # Update total
        self.update_edit_sale_total()

    def remove_edit_sale_item(self):
        btn = self.sender()
        row = btn.property('row')
        item_id = btn.property('item_id')

        # If item_id is positive, it's an existing item that needs to be marked for deletion
        if item_id > 0:
            if not hasattr(self, 'items_to_delete'):
                self.items_to_delete = []
            self.items_to_delete.append(item_id)

        self.edit_sale_items_table.removeRow(row)

        # Update row properties for remaining buttons
        for r in range(row, self.edit_sale_items_table.rowCount()):
            btn = self.edit_sale_items_table.cellWidget(r, 5).findChild(QPushButton)
            btn.setProperty('row', r)

        self.update_edit_sale_total()

    def update_edit_sale_total(self):
        total = 0
        for row in range(self.edit_sale_items_table.rowCount()):
            total_text = self.edit_sale_items_table.item(row, 4).text().replace("$", "").replace(",", "")
            total += float(total_text)

        self.edit_sale_summary.setText(f"Total: ${total:,.2f}")

    def update_sale(self, sale_id, project_id):
        if self.edit_sale_items_table.rowCount() == 0:
            QMessageBox.warning(self.edit_sale_dialog, "Error", "Sale must have at least one item!")
            return

        # Calculate totals
        subtotal = 0
        for row in range(self.edit_sale_items_table.rowCount()):
            total_text = self.edit_sale_items_table.item(row, 4).text().replace("$", "").replace(",", "")
            subtotal += float(total_text)

        discount = self.edit_discount.value()
        tax = self.edit_tax_amount.value()
        total = subtotal - discount + tax
        payment_status = self.edit_payment_status.currentText()
        notes = self.edit_sale_notes.text().strip()

        try:
            # Start transaction
            self.db.cursor.execute("BEGIN TRANSACTION")

            # Update sale record
            self.db.cursor.execute('''
                UPDATE sales 
                SET total_amount=?, discount=?, tax_amount=?, payment_status=?, notes=?
                WHERE id=?
            ''', (total, discount, tax, payment_status, notes, sale_id))

            # Process items marked for deletion
            if hasattr(self, 'items_to_delete'):
                for item_id in self.items_to_delete:
                    # Get item details to restore inventory
                    self.db.cursor.execute('''
                        SELECT material_id, quantity, warehouse 
                        FROM sale_items 
                        WHERE id=?
                    ''', (item_id,))
                    item = self.db.cursor.fetchone()

                    if item:
                        # Restore inventory
                        self.db.cursor.execute('''
                            UPDATE inventory 
                            SET quantity = quantity + ?, last_updated = ?
                            WHERE material_id = ? AND warehouse = ?
                        ''', (item[1], datetime.now().isoformat(), item[0], item[2]))

                        # Record inventory transaction
                        self.db.cursor.execute('''
                            INSERT INTO inventory_transactions (
                                material_id, warehouse, quantity_change, transaction_type,
                                reference_id, transaction_date, recorded_by, notes
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            item[0], item[2], item[1], 'Adjustment',
                            sale_id, datetime.now().isoformat(), self.user['id'],
                            f"Sale #{sale_id} item removal"
                        ))

                    # Delete sale item
                    self.db.cursor.execute('''
                        DELETE FROM sale_items WHERE id=?
                    ''', (item_id,))

                del self.items_to_delete

            # Process updated items
            for row in range(self.edit_sale_items_table.rowCount()):
                material_name = self.edit_sale_items_table.item(row, 0).text()
                warehouse = self.edit_sale_items_table.item(row, 1).text()
                quantity = float(self.edit_sale_items_table.item(row, 2).text())
                unit_price = float(self.edit_sale_items_table.item(row, 3).text().replace("$", "").replace(",", ""))

                # Get material ID
                self.db.cursor.execute('''
                    SELECT id FROM materials WHERE name=?
                ''', (material_name,))
                material_id = self.db.cursor.fetchone()[0]

                # Get the button to check if this is a new or existing item
                btn = self.edit_sale_items_table.cellWidget(row, 5).findChild(QPushButton)
                item_id = btn.property('item_id')

                if item_id == -1:  # New item
                    # Add sale item
                    self.db.cursor.execute('''
                        INSERT INTO sale_items (
                            sale_id, material_id, quantity, unit_price, total_price, warehouse
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (sale_id, material_id, quantity, unit_price, quantity * unit_price, warehouse))

                    # Update inventory
                    self.db.cursor.execute('''
                        UPDATE inventory 
                        SET quantity = quantity - ?, last_updated = ?
                        WHERE material_id = ? AND warehouse = ?
                    ''', (quantity, datetime.now().isoformat(), material_id, warehouse))

                    # Record inventory transaction
                    self.db.cursor.execute('''
                        INSERT INTO inventory_transactions (
                            material_id, warehouse, quantity_change, transaction_type,
                            reference_id, transaction_date, recorded_by, notes
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        material_id, warehouse, -quantity, 'Sale',
                        sale_id, datetime.now().isoformat(), self.user['id'],
                        f"Sale #{sale_id}"
                    ))
                else:  # Existing item - need to update quantity difference
                    # Get original quantity
                    self.db.cursor.execute('''
                        SELECT quantity FROM sale_items WHERE id=?
                    ''', (item_id,))
                    original_qty = self.db.cursor.fetchone()[0]

                    qty_diff = quantity - original_qty

                    if qty_diff != 0:
                        # Update sale item
                        self.db.cursor.execute('''
                            UPDATE sale_items 
                            SET quantity=?, unit_price=?, total_price=?
                            WHERE id=?
                        ''', (quantity, unit_price, quantity * unit_price, item_id))

                        # Update inventory
                        self.db.cursor.execute('''
                            UPDATE inventory 
                            SET quantity = quantity - ?, last_updated = ?
                            WHERE material_id = ? AND warehouse = ?
                        ''', (qty_diff, datetime.now().isoformat(), material_id, warehouse))

                        # Record inventory transaction
                        self.db.cursor.execute('''
                            INSERT INTO inventory_transactions (
                                material_id, warehouse, quantity_change, transaction_type,
                                reference_id, transaction_date, recorded_by, notes
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            material_id, warehouse, -qty_diff, 'Adjustment',
                            sale_id, datetime.now().isoformat(), self.user['id'],
                            f"Sale #{sale_id} quantity adjustment"
                        ))

            self.db.connection.commit()

            QMessageBox.information(self.edit_sale_dialog, "Success", "Sale updated successfully!")
            self.edit_sale_dialog.close()
            self.load_sales()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            self.db.connection.rollback()
            QMessageBox.critical(self.edit_sale_dialog, "Database Error", f"Failed to update sale: {str(e)}")

    def init_purchases(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Date filter
        filter_layout = QHBoxLayout()

        self.purchases_date_from = QDateEdit()
        self.purchases_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.purchases_date_from.setCalendarPopup(True)

        self.purchases_date_to = QDateEdit()
        self.purchases_date_to.setDate(QDate.currentDate())
        self.purchases_date_to.setCalendarPopup(True)

        self.purchases_status_filter = QComboBox()
        self.purchases_status_filter.addItem("All Statuses")
        self.purchases_status_filter.addItems(["Ordered", "Received", "Cancelled"])

        filter_btn = QPushButton("Filter")
        filter_btn.clicked.connect(self.load_purchases)

        add_purchase_btn = QPushButton("New Purchase")
        add_purchase_btn.clicked.connect(self.show_add_purchase_dialog)

        filter_layout.addWidget(QLabel("From:"))
        filter_layout.addWidget(self.purchases_date_from)
        filter_layout.addWidget(QLabel("To:"))
        filter_layout.addWidget(self.purchases_date_to)
        filter_layout.addWidget(QLabel("Status:"))
        filter_layout.addWidget(self.purchases_status_filter)
        filter_layout.addWidget(filter_btn)
        filter_layout.addWidget(add_purchase_btn)

        # Purchases table
        self.purchases_table = QTableWidget()
        self.purchases_table.setColumnCount(7)
        self.purchases_table.setHorizontalHeaderLabels([
            "ID", "Date", "Supplier", "Amount", "Status", "Delivery Date", "Actions"
        ])
        self.purchases_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addLayout(filter_layout)
        layout.addWidget(self.purchases_table)

        self.purchases_tab.setLayout(layout)

        # Load purchases data
        self.load_purchases()

    def load_purchases(self):
        date_from = self.purchases_date_from.date().toString("yyyy-MM-dd")
        date_to = self.purchases_date_to.date().addDays(1).toString("yyyy-MM-dd")  # Include end date
        status = self.purchases_status_filter.currentText() if self.purchases_status_filter.currentIndex() > 0 else "%"

        self.db.cursor.execute('''
            SELECT p.id, p.purchase_date, s.name, p.total_amount, p.status, p.delivery_date
            FROM purchases p
            JOIN suppliers s ON p.supplier_id = s.id
            WHERE p.purchase_date BETWEEN ? AND ?
            AND p.status LIKE ?
            ORDER BY p.purchase_date DESC
        ''', (date_from, date_to, status))

        purchases = self.db.cursor.fetchall()

        self.purchases_table.setRowCount(len(purchases))
        for row_idx, row_data in enumerate(purchases):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data) if col_data else "N/A")
                self.purchases_table.setItem(row_idx, col_idx, item)

                # Format numeric columns
                if col_idx == 3:  # Amount column
                    item.setText(f"${float(col_data):,.2f}")

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            view_btn = QPushButton("View")
            view_btn.setProperty('row', row_idx)
            view_btn.clicked.connect(self.view_purchase_details)

            # Only allow editing for "Ordered" purchases
            if row_data[4] == "Ordered" and self.user['role'] in ('Admin', 'Manager'):
                edit_btn = QPushButton("Edit")
                edit_btn.setProperty('row', row_idx)
                edit_btn.clicked.connect(self.edit_purchase)
                actions_layout.addWidget(edit_btn)

            actions_layout.addWidget(view_btn)
            actions_widget.setLayout(actions_layout)

            self.purchases_table.setCellWidget(row_idx, 6, actions_widget)

            # Color coding by status
            status_item = self.purchases_table.item(row_idx, 4)
            if status_item.text() == "Ordered":
                status_item.setBackground(Qt.yellow)
            elif status_item.text() == "Received":
                status_item.setBackground(Qt.green)
                status_item.setForeground(Qt.white)
            elif status_item.text() == "Cancelled":
                status_item.setBackground(Qt.red)
                status_item.setForeground(Qt.white)

    def show_add_purchase_dialog(self):
        self.purchase_dialog = QWidget()
        self.purchase_dialog.setWindowTitle("New Purchase Order")
        self.purchase_dialog.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        # Supplier selection
        supplier_layout = QHBoxLayout()

        self.purchase_supplier = QComboBox()
        self.db.cursor.execute("SELECT id, name FROM suppliers ORDER BY name")
        suppliers = self.db.cursor.fetchall()
        for supplier in suppliers:
            self.purchase_supplier.addItem(supplier[1], supplier[0])

        supplier_layout.addWidget(QLabel("Supplier:"))
        supplier_layout.addWidget(self.purchase_supplier)

        # Purchase items table
        self.purchase_items_table = QTableWidget()
        self.purchase_items_table.setColumnCount(6)
        self.purchase_items_table.setHorizontalHeaderLabels([
            "Material", "Quantity", "Unit Price", "Total", "Warehouse", "Actions"
        ])
        self.purchase_items_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Add item controls
        add_item_layout = QHBoxLayout()

        self.purchase_material = QComboBox()
        self.db.cursor.execute("SELECT id, name, unit FROM materials ORDER BY name")
        materials = self.db.cursor.fetchall()
        for material in materials:
            self.purchase_material.addItem(f"{material[1]} ({material[2]})", material[0])

        self.purchase_quantity = QDoubleSpinBox()
        self.purchase_quantity.setMinimum(0.01)
        self.purchase_quantity.setMaximum(99999)
        self.purchase_quantity.setValue(1)

        self.purchase_unit_price = QDoubleSpinBox()
        self.purchase_unit_price.setPrefix("$ ")
        self.purchase_unit_price.setMaximum(99999.99)
        self.purchase_unit_price.setValue(0)

        self.purchase_warehouse = QLineEdit()
        self.purchase_warehouse.setPlaceholderText("Main Warehouse")

        add_item_btn = QPushButton("Add Item")
        add_item_btn.clicked.connect(self.add_purchase_item)

        add_item_layout.addWidget(QLabel("Material:"))
        add_item_layout.addWidget(self.purchase_material)
        add_item_layout.addWidget(QLabel("Quantity:"))
        add_item_layout.addWidget(self.purchase_quantity)
        add_item_layout.addWidget(QLabel("Unit Price:"))
        add_item_layout.addWidget(self.purchase_unit_price)
        add_item_layout.addWidget(QLabel("Warehouse:"))
        add_item_layout.addWidget(self.purchase_warehouse)
        add_item_layout.addWidget(add_item_btn)

        # Purchase summary
        self.purchase_summary = QLabel("Total: $0.00")
        self.purchase_summary.setFont(QFont('Arial', 12, QFont.Bold))

        # Delivery details
        delivery_layout = QHBoxLayout()

        self.delivery_date = QDateEdit()
        self.delivery_date.setDate(QDate.currentDate().addDays(7))
        self.delivery_date.setCalendarPopup(True)

        self.purchase_status = QComboBox()
        self.purchase_status.addItems(["Ordered", "Received"])

        self.purchase_notes = QLineEdit()
        self.purchase_notes.setPlaceholderText("Purchase notes (optional)")

        delivery_layout.addWidget(QLabel("Expected Delivery:"))
        delivery_layout.addWidget(self.delivery_date)
        delivery_layout.addWidget(QLabel("Status:"))
        delivery_layout.addWidget(self.purchase_status)

        # Save button
        save_btn = QPushButton("Save Purchase Order")
        save_btn.clicked.connect(self.save_purchase)

        layout.addLayout(supplier_layout)
        layout.addWidget(self.purchase_items_table)
        layout.addLayout(add_item_layout)
        layout.addWidget(self.purchase_summary)
        layout.addLayout(delivery_layout)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.purchase_notes)
        layout.addWidget(save_btn)

        self.purchase_dialog.setLayout(layout)
        self.purchase_dialog.show()

    def add_purchase_item(self):
        material_id = self.purchase_material.currentData()
        material_text = self.purchase_material.currentText()
        quantity = self.purchase_quantity.value()
        unit_price = self.purchase_unit_price.value()
        total = quantity * unit_price
        warehouse = self.purchase_warehouse.text().strip() or "Main Warehouse"

        if not material_id or quantity <= 0:
            QMessageBox.warning(self.purchase_dialog, "Error", "Please select a material and enter a valid quantity!")
            return

        # Add to purchase items table
        row = self.purchase_items_table.rowCount()
        self.purchase_items_table.insertRow(row)

        self.purchase_items_table.setItem(row, 0, QTableWidgetItem(material_text))
        self.purchase_items_table.setItem(row, 1, QTableWidgetItem(str(quantity)))
        self.purchase_items_table.setItem(row, 2, QTableWidgetItem(f"${unit_price:,.2f}"))
        self.purchase_items_table.setItem(row, 3, QTableWidgetItem(f"${total:,.2f}"))
        self.purchase_items_table.setItem(row, 4, QTableWidgetItem(warehouse))

        # Add remove button
        remove_btn = QPushButton("Remove")
        remove_btn.setProperty('row', row)
        remove_btn.clicked.connect(self.remove_purchase_item)

        cell_widget = QWidget()
        layout = QHBoxLayout()
        layout.addWidget(remove_btn)
        layout.setContentsMargins(0, 0, 0, 0)
        cell_widget.setLayout(layout)

        self.purchase_items_table.setCellWidget(row, 5, cell_widget)

        # Update total
        self.update_purchase_total()

    def remove_purchase_item(self):
        btn = self.sender()
        row = btn.property('row')
        self.purchase_items_table.removeRow(row)

        # Update row properties for remaining buttons
        for r in range(row, self.purchase_items_table.rowCount()):
            btn = self.purchase_items_table.cellWidget(r, 5).findChild(QPushButton)
            btn.setProperty('row', r)

        self.update_purchase_total()

    def update_purchase_total(self):
        total = 0
        for row in range(self.purchase_items_table.rowCount()):
            total_text = self.purchase_items_table.item(row, 3).text().replace("$", "").replace(",", "")
            total += float(total_text)

        self.purchase_summary.setText(f"Total: ${total:,.2f}")

    def save_purchase(self):
        if self.purchase_items_table.rowCount() == 0:
            QMessageBox.warning(self.purchase_dialog, "Error", "Please add at least one item to the purchase!")
            return

        supplier_id = self.purchase_supplier.currentData()
        total = 0
        for row in range(self.purchase_items_table.rowCount()):
            total_text = self.purchase_items_table.item(row, 3).text().replace("$", "").replace(",", "")
            total += float(total_text)

        delivery_date = self.delivery_date.date().toString("yyyy-MM-dd")
        status = self.purchase_status.currentText()
        notes = self.purchase_notes.text().strip()

        try:
            # Start transaction
            self.db.cursor.execute("BEGIN TRANSACTION")

            # Create purchase record
            self.db.cursor.execute('''
                INSERT INTO purchases (
                    supplier_id, purchase_date, total_amount, delivery_date, 
                    status, recorded_by, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                supplier_id, datetime.now().isoformat(), total, delivery_date,
                status, self.user['id'], notes
            ))

            purchase_id = self.db.cursor.lastrowid

            # Add purchase items
            for row in range(self.purchase_items_table.rowCount()):
                material_text = self.purchase_items_table.item(row, 0).text()
                material_id = self.purchase_material.findData(material_text.split(" (")[0])
                quantity = float(self.purchase_items_table.item(row, 1).text())
                unit_price = float(self.purchase_items_table.item(row, 2).text().replace("$", "").replace(",", ""))
                warehouse = self.purchase_items_table.item(row, 4).text()

                # Add purchase item
                self.db.cursor.execute('''
                    INSERT INTO purchase_items (
                        purchase_id, material_id, quantity, unit_price, total_price, warehouse
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (purchase_id, material_id, quantity, unit_price, quantity * unit_price, warehouse))

                # If status is "Received", update inventory
                if status == "Received":
                    # Update inventory
                    self.db.cursor.execute('''
                        INSERT OR REPLACE INTO inventory (material_id, warehouse, quantity, last_updated)
                        VALUES (?, ?, COALESCE((SELECT quantity FROM inventory WHERE material_id=? AND warehouse=?), 0) + ?, ?)
                    ''', (material_id, warehouse, material_id, warehouse, quantity, datetime.now().isoformat()))

                    # Record inventory transaction
                    self.db.cursor.execute('''
                        INSERT INTO inventory_transactions (
                            material_id, warehouse, quantity_change, transaction_type,
                            reference_id, transaction_date, recorded_by, notes
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        material_id, warehouse, quantity, 'Purchase',
                        purchase_id, datetime.now().isoformat(), self.user['id'],
                        f"Purchase #{purchase_id}"
                    ))

            self.db.connection.commit()

            QMessageBox.information(self.purchase_dialog, "Success", "Purchase order saved successfully!")
            self.purchase_dialog.close()
            self.load_purchases()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            self.db.connection.rollback()
            QMessageBox.critical(self.purchase_dialog, "Database Error", f"Failed to save purchase: {str(e)}")

    def view_purchase_details(self):
        btn = self.sender()
        row = btn.property('row')
        purchase_id = int(self.purchases_table.item(row, 0).text())

        self.db.cursor.execute('''
            SELECT p.*, s.name as supplier_name, u.full_name as recorded_by
            FROM purchases p
            JOIN suppliers s ON p.supplier_id = s.id
            JOIN users u ON p.recorded_by = u.id
            WHERE p.id=?
        ''', (purchase_id,))
        purchase = self.db.cursor.fetchone()

        self.db.cursor.execute('''
            SELECT pi.id, m.name, pi.quantity, pi.unit_price, pi.total_price, pi.warehouse
            FROM purchase_items pi
            JOIN materials m ON pi.material_id = m.id
            WHERE pi.purchase_id=?
            ORDER BY m.name
        ''', (purchase_id,))
        items = self.db.cursor.fetchall()

        # Create details dialog
        details_dialog = QWidget()
        details_dialog.setWindowTitle(f"Purchase Details - #{purchase_id}")
        details_dialog.setMinimumSize(600, 500)

        layout = QVBoxLayout()

        # Purchase info
        info_group = QWidget()
        info_layout = QVBoxLayout()

        info_layout.addWidget(QLabel(f"<h2>Purchase #{purchase_id}</h2>"))
        info_layout.addWidget(QLabel(f"<b>Supplier:</b> {purchase[8]}"))
        info_layout.addWidget(QLabel(f"<b>Date:</b> {purchase[2]}"))
        info_layout.addWidget(QLabel(f"<b>Recorded By:</b> {purchase[9]}"))
        info_layout.addWidget(QLabel(f"<b>Status:</b> {purchase[5]}"))
        info_layout.addWidget(QLabel(f"<b>Delivery Date:</b> {purchase[4] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Total:</b> ${purchase[3]:,.2f}"))
        info_layout.addWidget(QLabel(f"<b>Notes:</b> {purchase[7] or 'N/A'}"))

        info_group.setLayout(info_layout)

        # Items table
        items_table = QTableWidget()
        items_table.setColumnCount(5)
        items_table.setHorizontalHeaderLabels(["Material", "Quantity", "Unit Price", "Total", "Warehouse"])
        items_table.setRowCount(len(items))

        for row_idx, row_data in enumerate(items):
            for col_idx, col_data in enumerate(row_data[1:]):  # Skip ID
                item = QTableWidgetItem(str(col_data))
                items_table.setItem(row_idx, col_idx, item)

                # Format numeric columns
                if col_idx in (2, 3):  # Price columns
                    item.setText(f"${float(col_data):,.2f}")

        layout.addWidget(info_group)
        layout.addWidget(QLabel("<b>Items:</b>"))
        layout.addWidget(items_table)

        # Add receive button if status is "Ordered"
        if purchase[5] == "Ordered" and self.user['role'] in ('Admin', 'Manager'):
            receive_btn = QPushButton("Mark as Received")
            receive_btn.clicked.connect(lambda: self.receive_purchase(purchase_id))
            layout.addWidget(receive_btn)

        details_dialog.setLayout(layout)
        details_dialog.exec_()

    def receive_purchase(self, purchase_id):
        confirm = QMessageBox.question(
            self,
            "Confirm Receipt",
            "Are you sure you want to mark this purchase as received? This will update inventory.",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            try:
                # Start transaction
                self.db.cursor.execute("BEGIN TRANSACTION")

                # Get all purchase items
                self.db.cursor.execute('''
                    SELECT material_id, quantity, warehouse 
                    FROM purchase_items 
                    WHERE purchase_id=?
                ''', (purchase_id,))
                items = self.db.cursor.fetchall()

                # Update inventory for each item
                for material_id, quantity, warehouse in items:
                    # Update inventory
                    self.db.cursor.execute('''
                        INSERT OR REPLACE INTO inventory (material_id, warehouse, quantity, last_updated)
                        VALUES (?, ?, COALESCE((SELECT quantity FROM inventory WHERE material_id=? AND warehouse=?), 0) + ?, ?)
                    ''', (material_id, warehouse, material_id, warehouse, quantity, datetime.now().isoformat()))

                    # Record inventory transaction
                    self.db.cursor.execute('''
                        INSERT INTO inventory_transactions (
                            material_id, warehouse, quantity_change, transaction_type,
                            reference_id, transaction_date, recorded_by, notes
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        material_id, warehouse, quantity, 'Purchase',
                        purchase_id, datetime.now().isoformat(), self.user['id'],
                        f"Purchase #{purchase_id} receipt"
                    ))

                # Update purchase status
                self.db.cursor.execute('''
                    UPDATE purchases 
                    SET status='Received', delivery_date=?
                    WHERE id=?
                ''', (datetime.now().isoformat(), purchase_id))

                self.db.connection.commit()

                QMessageBox.information(self, "Success", "Purchase marked as received successfully!")
                self.load_purchases()
                self.load_dashboard_data()

            except sqlite3.Error as e:
                self.db.connection.rollback()
                QMessageBox.critical(self, "Database Error", f"Failed to receive purchase: {str(e)}")

    def edit_purchase(self):
        btn = self.sender()
        row = btn.property('row')
        purchase_id = int(self.purchases_table.item(row, 0).text())

        self.db.cursor.execute('''
            SELECT p.*, s.name as supplier_name
            FROM purchases p
            JOIN suppliers s ON p.supplier_id = s.id
            WHERE p.id=?
        ''', (purchase_id,))
        purchase = self.db.cursor.fetchone()

        self.db.cursor.execute('''
            SELECT pi.id, m.id as material_id, m.name, m.unit, pi.quantity, pi.unit_price, pi.total_price, pi.warehouse
            FROM purchase_items pi
            JOIN materials m ON pi.material_id = m.id
            WHERE pi.purchase_id=?
            ORDER BY m.name
        ''', (purchase_id,))
        items = self.db.cursor.fetchall()

        self.edit_purchase_dialog = QWidget()
        self.edit_purchase_dialog.setWindowTitle(f"Edit Purchase - #{purchase_id}")
        self.edit_purchase_dialog.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        # Supplier selection
        supplier_layout = QHBoxLayout()

        self.edit_purchase_supplier = QComboBox()
        self.db.cursor.execute("SELECT id, name FROM suppliers ORDER BY name")
        suppliers = self.db.cursor.fetchall()
        for supplier in suppliers:
            self.edit_purchase_supplier.addItem(supplier[1], supplier[0])
            if supplier[0] == purchase[1]:  # Current supplier
                self.edit_purchase_supplier.setCurrentIndex(self.edit_purchase_supplier.count() - 1)

        supplier_layout.addWidget(QLabel("Supplier:"))
        supplier_layout.addWidget(self.edit_purchase_supplier)

        # Purchase items table
        self.edit_purchase_items_table = QTableWidget()
        self.edit_purchase_items_table.setColumnCount(6)
        self.edit_purchase_items_table.setHorizontalHeaderLabels([
            "Material", "Quantity", "Unit Price", "Total", "Warehouse", "Actions"
        ])
        self.edit_purchase_items_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Add existing items to table
        for item in items:
            row = self.edit_purchase_items_table.rowCount()
            self.edit_purchase_items_table.insertRow(row)

            self.edit_purchase_items_table.setItem(row, 0, QTableWidgetItem(f"{item[2]} ({item[3]})"))  # Material
            self.edit_purchase_items_table.setItem(row, 1, QTableWidgetItem(str(item[4])))  # Quantity
            self.edit_purchase_items_table.setItem(row, 2, QTableWidgetItem(f"${item[5]:,.2f}"))  # Unit price
            self.edit_purchase_items_table.setItem(row, 3, QTableWidgetItem(f"${item[6]:,.2f}"))  # Total
            self.edit_purchase_items_table.setItem(row, 4, QTableWidgetItem(item[7]))  # Warehouse

            # Add remove button
            remove_btn = QPushButton("Remove")
            remove_btn.setProperty('row', row)
            remove_btn.setProperty('item_id', item[0])  # Store purchase item ID
            remove_btn.clicked.connect(self.remove_edit_purchase_item)

            cell_widget = QWidget()
            btn_layout = QHBoxLayout()
            btn_layout.addWidget(remove_btn)
            btn_layout.setContentsMargins(0, 0, 0, 0)
            cell_widget.setLayout(btn_layout)

            self.edit_purchase_items_table.setCellWidget(row, 5, cell_widget)

        # Add item controls
        add_item_layout = QHBoxLayout()

        self.edit_purchase_material = QComboBox()
        self.db.cursor.execute("SELECT id, name, unit FROM materials ORDER BY name")
        materials = self.db.cursor.fetchall()
        for material in materials:
            self.edit_purchase_material.addItem(f"{material[1]} ({material[2]})", material[0])

        self.edit_purchase_quantity = QDoubleSpinBox()
        self.edit_purchase_quantity.setMinimum(0.01)
        self.edit_purchase_quantity.setMaximum(99999)
        self.edit_purchase_quantity.setValue(1)

        self.edit_purchase_unit_price = QDoubleSpinBox()
        self.edit_purchase_unit_price.setPrefix("$ ")
        self.edit_purchase_unit_price.setMaximum(99999.99)
        self.edit_purchase_unit_price.setValue(0)

        self.edit_purchase_warehouse = QLineEdit()
        self.edit_purchase_warehouse.setPlaceholderText("Main Warehouse")

        add_item_btn = QPushButton("Add Item")
        add_item_btn.clicked.connect(self.add_edit_purchase_item)

        add_item_layout.addWidget(QLabel("Material:"))
        add_item_layout.addWidget(self.edit_purchase_material)
        add_item_layout.addWidget(QLabel("Quantity:"))
        add_item_layout.addWidget(self.edit_purchase_quantity)
        add_item_layout.addWidget(QLabel("Unit Price:"))
        add_item_layout.addWidget(self.edit_purchase_unit_price)
        add_item_layout.addWidget(QLabel("Warehouse:"))
        add_item_layout.addWidget(self.edit_purchase_warehouse)
        add_item_layout.addWidget(add_item_btn)

        # Purchase summary
        self.edit_purchase_summary = QLabel(f"Total: ${purchase[3]:,.2f}")
        self.edit_purchase_summary.setFont(QFont('Arial', 12, QFont.Bold))

        # Delivery details
        delivery_layout = QHBoxLayout()

        self.edit_delivery_date = QDateEdit()
        if purchase[4]:
            self.edit_delivery_date.setDate(QDate.fromString(purchase[4], "yyyy-MM-dd"))
        else:
            self.edit_delivery_date.setDate(QDate.currentDate().addDays(7))
        self.edit_delivery_date.setCalendarPopup(True)

        self.edit_purchase_status = QComboBox()
        self.edit_purchase_status.addItems(["Ordered", "Received"])
        self.edit_purchase_status.setCurrentText(purchase[5])

        self.edit_purchase_notes = QLineEdit(purchase[7] if purchase[7] else "")

        delivery_layout.addWidget(QLabel("Expected Delivery:"))
        delivery_layout.addWidget(self.edit_delivery_date)
        delivery_layout.addWidget(QLabel("Status:"))
        delivery_layout.addWidget(self.edit_purchase_status)

        # Save button
        save_btn = QPushButton("Update Purchase Order")
        save_btn.clicked.connect(lambda: self.update_purchase(purchase_id))

        layout.addLayout(supplier_layout)
        layout.addWidget(self.edit_purchase_items_table)
        layout.addLayout(add_item_layout)
        layout.addWidget(self.edit_purchase_summary)
        layout.addLayout(delivery_layout)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.edit_purchase_notes)
        layout.addWidget(save_btn)

        self.edit_purchase_dialog.setLayout(layout)
        self.edit_purchase_dialog.show()

    def add_edit_purchase_item(self):
        material_id = self.edit_purchase_material.currentData()
        material_text = self.edit_purchase_material.currentText()
        quantity = self.edit_purchase_quantity.value()
        unit_price = self.edit_purchase_unit_price.value()
        total = quantity * unit_price
        warehouse = self.edit_purchase_warehouse.text().strip() or "Main Warehouse"

        if not material_id or quantity <= 0:
            QMessageBox.warning(self.edit_purchase_dialog, "Error",
                                "Please select a material and enter a valid quantity!")
            return

        # Add to purchase items table
        row = self.edit_purchase_items_table.rowCount()
        self.edit_purchase_items_table.insertRow(row)

        self.edit_purchase_items_table.setItem(row, 0, QTableWidgetItem(material_text))
        self.edit_purchase_items_table.setItem(row, 1, QTableWidgetItem(str(quantity)))
        self.edit_purchase_items_table.setItem(row, 2, QTableWidgetItem(f"${unit_price:,.2f}"))
        self.edit_purchase_items_table.setItem(row, 3, QTableWidgetItem(f"${total:,.2f}"))
        self.edit_purchase_items_table.setItem(row, 4, QTableWidgetItem(warehouse))

        # Add remove button with negative item_id to indicate new item
        remove_btn = QPushButton("Remove")
        remove_btn.setProperty('row', row)
        remove_btn.setProperty('item_id', -1)  # -1 indicates new item
        remove_btn.clicked.connect(self.remove_edit_purchase_item)

        cell_widget = QWidget()
        layout = QHBoxLayout()
        layout.addWidget(remove_btn)
        layout.setContentsMargins(0, 0, 0, 0)
        cell_widget.setLayout(layout)

        self.edit_purchase_items_table.setCellWidget(row, 5, cell_widget)

        # Update total
        self.update_edit_purchase_total()

    def remove_edit_purchase_item(self):
        btn = self.sender()
        row = btn.property('row')
        item_id = btn.property('item_id')

        # If item_id is positive, it's an existing item that needs to be marked for deletion
        if item_id > 0:
            if not hasattr(self, 'purchase_items_to_delete'):
                self.purchase_items_to_delete = []
            self.purchase_items_to_delete.append(item_id)

        self.edit_purchase_items_table.removeRow(row)

        # Update row properties for remaining buttons
        for r in range(row, self.edit_purchase_items_table.rowCount()):
            btn = self.edit_purchase_items_table.cellWidget(r, 5).findChild(QPushButton)
            btn.setProperty('row', r)

        self.update_edit_purchase_total()

    def update_edit_purchase_total(self):
        total = 0
        for row in range(self.edit_purchase_items_table.rowCount()):
            total_text = self.edit_purchase_items_table.item(row, 3).text().replace("$", "").replace(",", "")
            total += float(total_text)

        self.edit_purchase_summary.setText(f"Total: ${total:,.2f}")

    def update_purchase(self, purchase_id):
        if self.edit_purchase_items_table.rowCount() == 0:
            QMessageBox.warning(self.edit_purchase_dialog, "Error", "Purchase must have at least one item!")
            return

        supplier_id = self.edit_purchase_supplier.currentData()
        total = 0
        for row in range(self.edit_purchase_items_table.rowCount()):
            total_text = self.edit_purchase_items_table.item(row, 3).text().replace("$", "").replace(",", "")
            total += float(total_text)

        delivery_date = self.edit_delivery_date.date().toString("yyyy-MM-dd")
        status = self.edit_purchase_status.currentText()
        notes = self.edit_purchase_notes.text().strip()

        try:
            # Start transaction
            self.db.cursor.execute("BEGIN TRANSACTION")

            # Update purchase record
            self.db.cursor.execute('''
                UPDATE purchases 
                SET supplier_id=?, total_amount=?, delivery_date=?, status=?, notes=?
                WHERE id=?
            ''', (supplier_id, total, delivery_date, status, notes, purchase_id))

            # Process items marked for deletion
            if hasattr(self, 'purchase_items_to_delete'):
                for item_id in self.purchase_items_to_delete:
                    # Delete purchase item
                    self.db.cursor.execute('''
                        DELETE FROM purchase_items WHERE id=?
                    ''', (item_id,))

                del self.purchase_items_to_delete

            # Process updated items
            for row in range(self.edit_purchase_items_table.rowCount()):
                material_text = self.edit_purchase_items_table.item(row, 0).text()
                material_id = self.edit_purchase_material.findData(material_text.split(" (")[0])
                quantity = float(self.edit_purchase_items_table.item(row, 1).text())
                unit_price = float(self.edit_purchase_items_table.item(row, 2).text().replace("$", "").replace(",", ""))
                warehouse = self.edit_purchase_items_table.item(row, 4).text()

                # Get the button to check if this is a new or existing item
                btn = self.edit_purchase_items_table.cellWidget(row, 5).findChild(QPushButton)
                item_id = btn.property('item_id')

                if item_id == -1:  # New item
                    # Add purchase item
                    self.db.cursor.execute('''
                        INSERT INTO purchase_items (
                            purchase_id, material_id, quantity, unit_price, total_price, warehouse
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (purchase_id, material_id, quantity, unit_price, quantity * unit_price, warehouse))
                else:  # Existing item
                    # Update purchase item
                    self.db.cursor.execute('''
                        UPDATE purchase_items 
                        SET quantity=?, unit_price=?, total_price=?, warehouse=?
                        WHERE id=?
                    ''', (quantity, unit_price, quantity * unit_price, warehouse, item_id))

            self.db.connection.commit()

            QMessageBox.information(self.edit_purchase_dialog, "Success", "Purchase updated successfully!")
            self.edit_purchase_dialog.close()
            self.load_purchases()

        except sqlite3.Error as e:
            self.db.connection.rollback()
            QMessageBox.critical(self.edit_purchase_dialog, "Database Error", f"Failed to update purchase: {str(e)}")

    def init_suppliers(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Search and filter controls
        controls_layout = QHBoxLayout()

        self.search_supplier = QLineEdit()
        self.search_supplier.setPlaceholderText("Search suppliers...")
        self.search_supplier.textChanged.connect(self.load_suppliers)

        add_supplier_btn = QPushButton("Add Supplier")
        add_supplier_btn.clicked.connect(self.show_add_supplier_dialog)

        controls_layout.addWidget(self.search_supplier)
        controls_layout.addWidget(add_supplier_btn)

        # Suppliers table
        self.suppliers_table = QTableWidget()
        self.suppliers_table.setColumnCount(8)
        self.suppliers_table.setHorizontalHeaderLabels([
            "ID", "Name", "Contact", "Phone", "Email", "Address", "Tax ID", "Actions"
        ])
        self.suppliers_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addLayout(controls_layout)
        layout.addWidget(self.suppliers_table)

        self.suppliers_tab.setLayout(layout)

        # Load suppliers
        self.load_suppliers()

    def load_suppliers(self):
        search_term = f"%{self.search_supplier.text()}%"

        self.db.cursor.execute('''
            SELECT id, name, contact_person, phone, email, address, tax_id
            FROM suppliers
            WHERE name LIKE ? OR contact_person LIKE ? OR phone LIKE ? OR email LIKE ?
            ORDER BY name
        ''', (search_term, search_term, search_term, search_term))

        suppliers = self.db.cursor.fetchall()

        self.suppliers_table.setRowCount(len(suppliers))
        for row_idx, row_data in enumerate(suppliers):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data) if col_data else "N/A")
                self.suppliers_table.setItem(row_idx, col_idx, item)

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            view_btn = QPushButton("View")
            view_btn.setProperty('row', row_idx)
            view_btn.clicked.connect(self.view_supplier_details)

            edit_btn = QPushButton("Edit")
            edit_btn.setProperty('row', row_idx)
            edit_btn.clicked.connect(self.edit_supplier)

            delete_btn = QPushButton("Delete")
            delete_btn.setProperty('row', row_idx)
            delete_btn.clicked.connect(self.delete_supplier)

            actions_layout.addWidget(view_btn)
            actions_layout.addWidget(edit_btn)
            actions_layout.addWidget(delete_btn)
            actions_widget.setLayout(actions_layout)

            self.suppliers_table.setCellWidget(row_idx, 7, actions_widget)

    def show_add_supplier_dialog(self):
        self.supplier_dialog = QWidget()
        self.supplier_dialog.setWindowTitle("Add New Supplier")
        self.supplier_dialog.setFixedSize(500, 400)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.supplier_name = QLineEdit()
        self.supplier_name.setPlaceholderText("Supplier Name")

        self.supplier_contact = QLineEdit()
        self.supplier_contact.setPlaceholderText("Contact Person")

        self.supplier_phone = QLineEdit()
        self.supplier_phone.setPlaceholderText("Phone Number")

        self.supplier_email = QLineEdit()
        self.supplier_email.setPlaceholderText("Email Address")

        self.supplier_address = QLineEdit()
        self.supplier_address.setPlaceholderText("Physical Address")

        self.supplier_tax_id = QLineEdit()
        self.supplier_tax_id.setPlaceholderText("Tax ID")

        self.supplier_payment_terms = QLineEdit()
        self.supplier_payment_terms.setPlaceholderText("Payment Terms (e.g., Net 30)")

        save_btn = QPushButton("Save Supplier")
        save_btn.clicked.connect(self.save_supplier)

        layout.addWidget(QLabel("Supplier Name:"))
        layout.addWidget(self.supplier_name)
        layout.addWidget(QLabel("Contact Person:"))
        layout.addWidget(self.supplier_contact)
        layout.addWidget(QLabel("Phone Number:"))
        layout.addWidget(self.supplier_phone)
        layout.addWidget(QLabel("Email Address:"))
        layout.addWidget(self.supplier_email)
        layout.addWidget(QLabel("Physical Address:"))
        layout.addWidget(self.supplier_address)
        layout.addWidget(QLabel("Tax ID:"))
        layout.addWidget(self.supplier_tax_id)
        layout.addWidget(QLabel("Payment Terms:"))
        layout.addWidget(self.supplier_payment_terms)
        layout.addWidget(save_btn)

        self.supplier_dialog.setLayout(layout)
        self.supplier_dialog.show()

    def save_supplier(self):
        name = self.supplier_name.text().strip()
        contact = self.supplier_contact.text().strip()
        phone = self.supplier_phone.text().strip()
        email = self.supplier_email.text().strip()
        address = self.supplier_address.text().strip()
        tax_id = self.supplier_tax_id.text().strip()
        payment_terms = self.supplier_payment_terms.text().strip()

        if not name:
            QMessageBox.warning(self.supplier_dialog, "Error", "Supplier name is required!")
            return

        try:
            self.db.cursor.execute('''
                INSERT INTO suppliers (
                    name, contact_person, phone, email, address, tax_id, payment_terms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (name, contact, phone, email, address, tax_id, payment_terms))
            self.db.connection.commit()

            QMessageBox.information(self.supplier_dialog, "Success", "Supplier added successfully!")
            self.supplier_dialog.close()
            self.load_suppliers()

        except sqlite3.Error as e:
            QMessageBox.critical(self.supplier_dialog, "Database Error", f"Failed to save supplier: {str(e)}")

    def view_supplier_details(self):
        btn = self.sender()
        row = btn.property('row')
        supplier_id = int(self.suppliers_table.item(row, 0).text())

        self.db.cursor.execute("SELECT * FROM suppliers WHERE id=?", (supplier_id,))
        supplier = self.db.cursor.fetchone()

        self.db.cursor.execute('''
            SELECT p.id, p.purchase_date, p.total_amount, p.status
            FROM purchases p
            WHERE p.supplier_id=?
            ORDER BY p.purchase_date DESC
            LIMIT 10
        ''', (supplier_id,))
        purchases = self.db.cursor.fetchall()

        # Create details dialog
        details_dialog = QWidget()
        details_dialog.setWindowTitle(f"Supplier Details - {supplier[1]}")
        details_dialog.setMinimumSize(600, 500)

        layout = QVBoxLayout()

        # Basic info
        info_group = QWidget()
        info_layout = QVBoxLayout()

        info_layout.addWidget(QLabel(f"<h2>{supplier[1]}</h2>"))
        info_layout.addWidget(QLabel(f"<b>Contact:</b> {supplier[2] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Phone:</b> {supplier[3] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Email:</b> {supplier[4] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Address:</b> {supplier[5] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Tax ID:</b> {supplier[6] or 'N/A'}"))
        info_layout.addWidget(QLabel(f"<b>Payment Terms:</b> {supplier[7] or 'N/A'}"))

        info_group.setLayout(info_layout)

        # Recent purchases
        purchases_label = QLabel("<b>Recent Purchases:</b>")

        purchases_table = QTableWidget()
        purchases_table.setColumnCount(4)
        purchases_table.setHorizontalHeaderLabels(["ID", "Date", "Amount", "Status"])
        purchases_table.setRowCount(len(purchases))

        for row_idx, row_data in enumerate(purchases):
            for col_idx, col_data in enumerate(row_data[1:]):  # Skip supplier_id
                item = QTableWidgetItem(str(col_data))
                purchases_table.setItem(row_idx, col_idx, item)

                # Format numeric columns
                if col_idx == 1:  # Amount column
                    item.setText(f"${float(col_data):,.2f}")

                # Color coding by status
                if col_idx == 2:  # Status column
                    if col_data == "Ordered":
                        item.setBackground(Qt.yellow)
                    elif col_data == "Received":
                        item.setBackground(Qt.green)
                        item.setForeground(Qt.white)
                    elif col_data == "Cancelled":
                        item.setBackground(Qt.red)
                        item.setForeground(Qt.white)

        layout.addWidget(info_group)
        layout.addWidget(purchases_label)
        layout.addWidget(purchases_table)

        details_dialog.setLayout(layout)
        details_dialog.exec_()

    def edit_supplier(self):
        btn = self.sender()
        row = btn.property('row')
        supplier_id = int(self.suppliers_table.item(row, 0).text())

        self.db.cursor.execute("SELECT * FROM suppliers WHERE id=?", (supplier_id,))
        supplier = self.db.cursor.fetchone()

        self.edit_supplier_dialog = QWidget()
        self.edit_supplier_dialog.setWindowTitle("Edit Supplier")
        self.edit_supplier_dialog.setFixedSize(500, 400)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.edit_supplier_id = supplier_id
        self.edit_supplier_name = QLineEdit(supplier[1])
        self.edit_supplier_contact = QLineEdit(supplier[2] if supplier[2] else "")
        self.edit_supplier_phone = QLineEdit(supplier[3] if supplier[3] else "")
        self.edit_supplier_email = QLineEdit(supplier[4] if supplier[4] else "")
        self.edit_supplier_address = QLineEdit(supplier[5] if supplier[5] else "")
        self.edit_supplier_tax_id = QLineEdit(supplier[6] if supplier[6] else "")
        self.edit_supplier_payment_terms = QLineEdit(supplier[7] if supplier[7] else "")

        update_btn = QPushButton("Update Supplier")
        update_btn.clicked.connect(self.update_supplier)

        layout.addWidget(QLabel("Supplier Name:"))
        layout.addWidget(self.edit_supplier_name)
        layout.addWidget(QLabel("Contact Person:"))
        layout.addWidget(self.edit_supplier_contact)
        layout.addWidget(QLabel("Phone Number:"))
        layout.addWidget(self.edit_supplier_phone)
        layout.addWidget(QLabel("Email Address:"))
        layout.addWidget(self.edit_supplier_email)
        layout.addWidget(QLabel("Physical Address:"))
        layout.addWidget(self.edit_supplier_address)
        layout.addWidget(QLabel("Tax ID:"))
        layout.addWidget(self.edit_supplier_tax_id)
        layout.addWidget(QLabel("Payment Terms:"))
        layout.addWidget(self.edit_supplier_payment_terms)
        layout.addWidget(update_btn)

        self.edit_supplier_dialog.setLayout(layout)
        self.edit_supplier_dialog.show()

    def update_supplier(self):
        supplier_id = self.edit_supplier_id
        name = self.edit_supplier_name.text().strip()
        contact = self.edit_supplier_contact.text().strip()
        phone = self.edit_supplier_phone.text().strip()
        email = self.edit_supplier_email.text().strip()
        address = self.edit_supplier_address.text().strip()
        tax_id = self.edit_supplier_tax_id.text().strip()
        payment_terms = self.edit_supplier_payment_terms.text().strip()

        if not name:
            QMessageBox.warning(self.edit_supplier_dialog, "Error", "Supplier name is required!")
            return

        try:
            self.db.cursor.execute('''
                UPDATE suppliers 
                SET name=?, contact_person=?, phone=?, email=?, address=?, tax_id=?, payment_terms=?
                WHERE id=?
            ''', (name, contact, phone, email, address, tax_id, payment_terms, supplier_id))
            self.db.connection.commit()

            QMessageBox.information(self.edit_supplier_dialog, "Success", "Supplier updated successfully!")
            self.edit_supplier_dialog.close()
            self.load_suppliers()

        except sqlite3.Error as e:
            QMessageBox.critical(self.edit_supplier_dialog, "Database Error", f"Failed to update supplier: {str(e)}")

    def delete_supplier(self):
        btn = self.sender()
        row = btn.property('row')
        supplier_id = int(self.suppliers_table.item(row, 0).text())

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete supplier ID {supplier_id}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            try:
                # Check if supplier has any purchases
                self.db.cursor.execute("SELECT COUNT(*) FROM purchases WHERE supplier_id=?", (supplier_id,))
                if self.db.cursor.fetchone()[0] > 0:
                    QMessageBox.warning(self, "Cannot Delete",
                                        "This supplier has purchase records and cannot be deleted.")
                    return

                self.db.cursor.execute("DELETE FROM suppliers WHERE id=?", (supplier_id,))
                self.db.connection.commit()

                QMessageBox.information(self, "Success", "Supplier deleted successfully!")
                self.load_suppliers()

            except sqlite3.Error as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete supplier: {str(e)}")

    def init_reports(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Report type selection
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Inventory Status",
            "Sales Summary",
            "Purchase Summary",
            "Financial Summary",
            "Low Stock Report",
            "Project Materials"
        ])
        self.report_type.currentIndexChanged.connect(self.generate_report)

        # Date range for reports
        date_layout = QHBoxLayout()

        self.report_date_from = QDateEdit()
        self.report_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.report_date_from.setCalendarPopup(True)

        self.report_date_to = QDateEdit()
        self.report_date_to.setDate(QDate.currentDate())
        self.report_date_to.setCalendarPopup(True)

        date_layout.addWidget(QLabel("From:"))
        date_layout.addWidget(self.report_date_from)
        date_layout.addWidget(QLabel("To:"))
        date_layout.addWidget(self.report_date_to)

        # Additional filters
        self.report_project_filter = QComboBox()
        self.report_project_filter.addItem("All Projects")
        self.db.cursor.execute("SELECT id, name FROM projects ORDER BY name")
        projects = self.db.cursor.fetchall()
        for project in projects:
            self.report_project_filter.addItem(project[1], project[0])

        self.report_supplier_filter = QComboBox()
        self.report_supplier_filter.addItem("All Suppliers")
        self.db.cursor.execute("SELECT id, name FROM suppliers ORDER BY name")
        suppliers = self.db.cursor.fetchall()
        for supplier in suppliers:
            self.report_supplier_filter.addItem(supplier[1], supplier[0])

        self.report_warehouse_filter = QComboBox()
        self.report_warehouse_filter.addItem("All Warehouses")
        self.db.cursor.execute("SELECT DISTINCT warehouse FROM inventory ORDER BY warehouse")
        warehouses = self.db.cursor.fetchall()
        for warehouse in warehouses:
            self.report_warehouse_filter.addItem(warehouse[0])

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Project:"))
        filter_layout.addWidget(self.report_project_filter)
        filter_layout.addWidget(QLabel("Supplier:"))
        filter_layout.addWidget(self.report_supplier_filter)
        filter_layout.addWidget(QLabel("Warehouse:"))
        filter_layout.addWidget(self.report_warehouse_filter)

        # Generate button
        generate_btn = QPushButton("Generate Report")
        generate_btn.clicked.connect(self.generate_report)

        # Export button
        export_btn = QPushButton("Export to CSV")
        export_btn.clicked.connect(self.export_report)

        # Report table
        self.report_table = QTableWidget()
        self.report_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Summary labels
        self.report_summary = QLabel()
        self.report_summary.setFont(QFont('Arial', 12))

        layout.addWidget(QLabel("Report Type:"))
        layout.addWidget(self.report_type)
        layout.addLayout(date_layout)
        layout.addLayout(filter_layout)
        layout.addWidget(generate_btn)
        layout.addWidget(export_btn)
        layout.addWidget(self.report_summary)
        layout.addWidget(self.report_table)

        self.reports_tab.setLayout(layout)

        # Generate initial report
        self.generate_report()

    def generate_report(self):
        report_type = self.report_type.currentText()
        date_from = self.report_date_from.date().toString("yyyy-MM-dd")
        date_to = self.report_date_to.date().addDays(1).toString("yyyy-MM-dd")  # Include end date
        project_id = self.report_project_filter.currentData() if self.report_project_filter.currentIndex() > 0 else None
        supplier_id = self.report_supplier_filter.currentData() if self.report_supplier_filter.currentIndex() > 0 else None
        warehouse = self.report_warehouse_filter.currentText() if self.report_warehouse_filter.currentIndex() > 0 else "%"

        if report_type == "Inventory Status":
            self.db.cursor.execute('''
                SELECT m.id, m.name, m.category, m.unit, m.cost_price, 
                       COALESCE(i.quantity, 0) as quantity, 
                       COALESCE(i.warehouse, 'N/A') as warehouse,
                       m.min_stock_level
                FROM materials m
                LEFT JOIN inventory i ON m.id = i.material_id
                WHERE (i.warehouse LIKE ? OR i.warehouse IS NULL)
                AND (m.supplier_id = ? OR ? IS NULL)
                ORDER BY m.name, i.warehouse
            ''', (warehouse, supplier_id, supplier_id))

            inventory = self.db.cursor.fetchall()

            self.report_table.setColumnCount(8)
            self.report_table.setHorizontalHeaderLabels([
                "ID", "Name", "Category", "Unit", "Cost", "Quantity", "Warehouse", "Min Stock"
            ])
            self.report_table.setRowCount(len(inventory))

            total_value = 0
            low_stock_count = 0

            for row_idx, row_data in enumerate(inventory):
                for col_idx, col_data in enumerate(row_data):
                    item = QTableWidgetItem(str(col_data))
                    self.report_table.setItem(row_idx, col_idx, item)

                    # Format numeric columns
                    if col_idx == 4:  # Cost
                        item.setText(f"${float(col_data):,.2f}")
                        total_value += float(col_data) * float(row_data[5])  # cost * quantity

                    # Highlight low stock items
                    if col_idx == 5 and float(col_data) <= float(row_data[7]):  # quantity <= min_stock_level
                        item.setBackground(Qt.yellow if float(col_data) > 0 else Qt.red)
                        if float(col_data) == 0:
                            item.setForeground(Qt.white)
                        low_stock_count += 1

            self.report_summary.setText(
                f"Total Inventory Value: ${total_value:,.2f} | "
                f"Total Items: {len(inventory)} | "
                f"Low Stock Items: {low_stock_count}"
            )

        elif report_type == "Sales Summary":
            self.db.cursor.execute('''
                SELECT s.id, s.sale_date, p.name as project, 
                       SUM(si.quantity) as total_quantity, 
                       s.total_amount, u.full_name as seller
                FROM sales s
                JOIN sale_items si ON s.id = si.sale_id
                JOIN projects p ON s.project_id = p.id
                JOIN users u ON s.recorded_by = u.id
                WHERE s.sale_date BETWEEN ? AND ?
                AND (s.project_id = ? OR ? IS NULL)
                GROUP BY s.id
                ORDER BY s.sale_date DESC
            ''', (date_from, date_to, project_id, project_id))

            sales = self.db.cursor.fetchall()

            self.report_table.setColumnCount(6)
            self.report_table.setHorizontalHeaderLabels([
                "ID", "Date", "Project", "Total Quantity", "Amount", "Seller"
            ])
            self.report_table.setRowCount(len(sales))

            total_sales = 0
            total_quantity = 0

            for row_idx, row_data in enumerate(sales):
                for col_idx, col_data in enumerate(row_data):
                    item = QTableWidgetItem(str(col_data))
                    self.report_table.setItem(row_idx, col_idx, item)

                    # Format numeric columns
                    if col_idx == 4:  # Amount
                        item.setText(f"${float(col_data):,.2f}")
                        total_sales += float(col_data)
                    elif col_idx == 3:  # Quantity
                        total_quantity += float(col_data)

            self.report_summary.setText(
                f"Total Sales: ${total_sales:,.2f} | "
                f"Total Quantity Sold: {total_quantity} | "
                f"Number of Sales: {len(sales)}"
            )

        elif report_type == "Purchase Summary":
            self.db.cursor.execute('''
                SELECT p.id, p.purchase_date, s.name as supplier, 
                       SUM(pi.quantity) as total_quantity, 
                       p.total_amount, p.status
                FROM purchases p
                JOIN purchase_items pi ON p.id = pi.purchase_id
                JOIN suppliers s ON p.supplier_id = s.id
                WHERE p.purchase_date BETWEEN ? AND ?
                AND (p.supplier_id = ? OR ? IS NULL)
                GROUP BY p.id
                ORDER BY p.purchase_date DESC
            ''', (date_from, date_to, supplier_id, supplier_id))

            purchases = self.db.cursor.fetchall()

            self.report_table.setColumnCount(6)
            self.report_table.setHorizontalHeaderLabels([
                "ID", "Date", "Supplier", "Total Quantity", "Amount", "Status"
            ])
            self.report_table.setRowCount(len(purchases))

            total_purchases = 0
            total_quantity = 0

            for row_idx, row_data in enumerate(purchases):
                for col_idx, col_data in enumerate(row_data):
                    item = QTableWidgetItem(str(col_data))
                    self.report_table.setItem(row_idx, col_idx, item)

                    # Format numeric columns
                    if col_idx == 4:  # Amount
                        item.setText(f"${float(col_data):,.2f}")
                        total_purchases += float(col_data)
                    elif col_idx == 3:  # Quantity
                        total_quantity += float(col_data)

                    # Color coding by status
                    if col_idx == 5:  # Status column
                        if col_data == "Ordered":
                            item.setBackground(Qt.yellow)
                        elif col_data == "Received":
                            item.setBackground(Qt.green)
                            item.setForeground(Qt.white)
                        elif col_data == "Cancelled":
                            item.setBackground(Qt.red)
                            item.setForeground(Qt.white)

            self.report_summary.setText(
                f"Total Purchases: ${total_purchases:,.2f} | "
                f"Total Quantity Purchased: {total_quantity} | "
                f"Number of Orders: {len(purchases)}"
            )

        elif report_type == "Financial Summary":
            # Sales total
            self.db.cursor.execute('''
                SELECT SUM(total_amount), COUNT(*)
                FROM sales
                WHERE sale_date BETWEEN ? AND ?
                AND (project_id = ? OR ? IS NULL)
            ''', (date_from, date_to, project_id, project_id))
            sales_result = self.db.cursor.fetchone()
            sales_total = sales_result[0] if sales_result[0] else 0
            sales_count = sales_result[1] if sales_result[1] else 0

            # Purchases total
            self.db.cursor.execute('''
                SELECT SUM(total_amount), COUNT(*)
                FROM purchases
                WHERE purchase_date BETWEEN ? AND ?
                AND (supplier_id = ? OR ? IS NULL)
                AND status != 'Cancelled'
            ''', (date_from, date_to, supplier_id, supplier_id))
            purchases_result = self.db.cursor.fetchone()
            purchases_total = purchases_result[0] if purchases_result[0] else 0
            purchases_count = purchases_result[1] if purchases_result[1] else 0

            # Expenses (simplified - in a real app you might have a separate expenses table)
            expenses_total = 0  # Placeholder

            # Net profit
            net_profit = sales_total - purchases_total - expenses_total

            # Create summary table
            self.report_table.setColumnCount(2)
            self.report_table.setHorizontalHeaderLabels(["Category", "Amount"])
            self.report_table.setRowCount(4)

            self.report_table.setItem(0, 0, QTableWidgetItem("Total Sales"))
            self.report_table.setItem(0, 1, QTableWidgetItem(f"${sales_total:,.2f}"))

            self.report_table.setItem(1, 0, QTableWidgetItem("Total Purchases"))
            self.report_table.setItem(1, 1, QTableWidgetItem(f"${purchases_total:,.2f}"))

            self.report_table.setItem(2, 0, QTableWidgetItem("Total Expenses"))
            self.report_table.setItem(2, 1, QTableWidgetItem(f"${expenses_total:,.2f}"))

            self.report_table.setItem(3, 0, QTableWidgetItem("Net Profit"))
            self.report_table.setItem(3, 1, QTableWidgetItem(f"${net_profit:,.2f}"))

            # Color coding
            if net_profit >= 0:
                self.report_table.item(3, 1).setForeground(Qt.darkGreen)
            else:
                self.report_table.item(3, 1).setForeground(Qt.red)

            self.report_summary.setText(
                f"Period: {date_from} to {self.report_date_to.date().toString('yyyy-MM-dd')} | "
                f"Sales: {sales_count} | Purchases: {purchases_count}"
            )

        elif report_type == "Low Stock Report":
            self.db.cursor.execute('''
                SELECT m.id, m.name, m.category, m.unit, 
                       COALESCE(i.quantity, 0) as quantity, 
                       COALESCE(i.warehouse, 'N/A') as warehouse,
                       m.min_stock_level, m.cost_price,
                       s.name as supplier
                FROM materials m
                LEFT JOIN inventory i ON m.id = i.material_id
                LEFT JOIN suppliers s ON m.supplier_id = s.id
                WHERE (i.quantity <= m.min_stock_level OR i.quantity IS NULL)
                AND (i.warehouse LIKE ? OR i.warehouse IS NULL)
                AND (m.supplier_id = ? OR ? IS NULL)
                ORDER BY (i.quantity / m.min_stock_level) ASC, m.name
            ''', (warehouse, supplier_id, supplier_id))

            low_stock = self.db.cursor.fetchall()

            self.report_table.setColumnCount(9)
            self.report_table.setHorizontalHeaderLabels([
                "ID", "Name", "Category", "Unit", "Quantity", "Warehouse", "Min Stock", "Cost", "Supplier"
            ])
            self.report_table.setRowCount(len(low_stock))

            critical_count = 0
            warning_count = 0

            for row_idx, row_data in enumerate(low_stock):
                for col_idx, col_data in enumerate(row_data):
                    item = QTableWidgetItem(str(col_data))
                    self.report_table.setItem(row_idx, col_idx, item)

                    # Format numeric columns
                    if col_idx == 7:  # Cost
                        item.setText(f"${float(col_data):,.2f}")

                    # Highlight critical items (less than 50% of min stock)
                    if col_idx == 4:  # Quantity
                        min_stock = float(row_data[6])
                        if float(col_data) < min_stock * 0.5:
                            item.setBackground(Qt.red)
                            item.setForeground(Qt.white)
                            critical_count += 1
                        elif float(col_data) <= min_stock:
                            item.setBackground(Qt.yellow)
                            warning_count += 1

            self.report_summary.setText(
                f"Critical Items: {critical_count} | "
                f"Warning Items: {warning_count} | "
                f"Total Low Stock Items: {len(low_stock)}"
            )

        elif report_type == "Project Materials":
            if not project_id:
                QMessageBox.warning(self, "Error", "Please select a project for this report!")
                return

            self.db.cursor.execute('''
                SELECT m.id, m.name, m.unit, pp.sale_price, 
                       COALESCE(SUM(si.quantity), 0) as sold_quantity,
                       COALESCE(SUM(si.total_price), 0) as total_sales
                FROM project_pricing pp
                JOIN materials m ON pp.material_id = m.id
                LEFT JOIN sale_items si ON pp.material_id = si.material_id
                LEFT JOIN sales s ON si.sale_id = s.id AND s.project_id = pp.project_id
                WHERE pp.project_id = ?
                GROUP BY pp.material_id
                ORDER BY m.name
            ''', (project_id,))

            materials = self.db.cursor.fetchall()

            self.report_table.setColumnCount(6)
            self.report_table.setHorizontalHeaderLabels([
                "ID", "Material", "Unit", "Price", "Quantity Sold", "Total Sales"
            ])
            self.report_table.setRowCount(len(materials))

            total_sales = 0
            total_quantity = 0

            for row_idx, row_data in enumerate(materials):
                for col_idx, col_data in enumerate(row_data):
                    item = QTableWidgetItem(str(col_data))
                    self.report_table.setItem(row_idx, col_idx, item)

                    # Format numeric columns
                    if col_idx == 3:  # Price
                        item.setText(f"${float(col_data):,.2f}")
                    elif col_idx == 5:  # Total sales
                        item.setText(f"${float(col_data):,.2f}")
                        total_sales += float(col_data)
                    elif col_idx == 4:  # Quantity
                        total_quantity += float(col_data)

            self.report_summary.setText(
                f"Total Sales: ${total_sales:,.2f} | "
                f"Total Quantity Sold: {total_quantity} | "
                f"Materials: {len(materials)}"
            )

    def export_report(self):
        report_type = self.report_type.currentText()
        if self.report_table.rowCount() == 0:
            QMessageBox.warning(self, "Error", "No data to export!")
            return

        # Get save file path
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            f"{report_type.replace(' ', '_')}_{QDate.currentDate().toString('yyyyMMdd')}.csv",
            "CSV Files (*.csv)"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as file:
                import csv
                writer = csv.writer(file)

                # Write headers
                headers = []
                for col in range(self.report_table.columnCount()):
                    headers.append(self.report_table.horizontalHeaderItem(col).text())
                writer.writerow(headers)

                # Write data
                for row in range(self.report_table.rowCount()):
                    row_data = []
                    for col in range(self.report_table.columnCount()):
                        item = self.report_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)

                # Add summary if available
                if self.report_summary.text():
                    writer.writerow([])
                    writer.writerow([self.report_summary.text()])

            QMessageBox.information(self, "Success", f"Report exported successfully to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def init_users(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Add user form
        form_layout = QHBoxLayout()

        self.new_username = QLineEdit()
        self.new_username.setPlaceholderText("Username")

        self.new_password = QLineEdit()
        self.new_password.setPlaceholderText("Password")
        self.new_password.setEchoMode(QLineEdit.Password)

        self.new_fullname = QLineEdit()
        self.new_fullname.setPlaceholderText("Full Name")

        self.new_role = QComboBox()
        self.new_role.addItems(["Admin", "Manager", "Sales"])

        add_user_btn = QPushButton("Add User")
        add_user_btn.clicked.connect(self.add_user)

        form_layout.addWidget(self.new_username)
        form_layout.addWidget(self.new_password)
        form_layout.addWidget(self.new_fullname)
        form_layout.addWidget(self.new_role)
        form_layout.addWidget(add_user_btn)

        # Users table
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(6)
        self.users_table.setHorizontalHeaderLabels([
            "ID", "Username", "Full Name", "Role", "Last Login", "Actions"
        ])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addLayout(form_layout)
        layout.addWidget(self.users_table)

        self.users_tab.setLayout(layout)

        # Load users
        self.load_users()

    def load_users(self):
        self.db.cursor.execute('''
            SELECT id, username, full_name, role, last_login
            FROM users
            ORDER BY role, username
        ''')
        users = self.db.cursor.fetchall()

        self.users_table.setRowCount(len(users))
        for row_idx, row_data in enumerate(users):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data) if col_data else "Never")
                self.users_table.setItem(row_idx, col_idx, item)

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            reset_btn = QPushButton("Reset Password")
            reset_btn.setProperty('row', row_idx)
            reset_btn.clicked.connect(self.reset_password)

            edit_btn = QPushButton("Edit")
            edit_btn.setProperty('row', row_idx)
            edit_btn.clicked.connect(self.edit_user)

            delete_btn = QPushButton("Delete")
            delete_btn.setProperty('row', row_idx)
            delete_btn.clicked.connect(self.delete_user)

            actions_layout.addWidget(reset_btn)
            actions_layout.addWidget(edit_btn)
            actions_layout.addWidget(delete_btn)
            actions_widget.setLayout(actions_layout)

            self.users_table.setCellWidget(row_idx, 5, actions_widget)

            # Disable delete for current user and admin
            if row_data[0] == self.user['id'] or row_data[3] == "Admin":
                delete_btn.setEnabled(False)
                if row_data[0] == self.user['id']:
                    reset_btn.setEnabled(False)

    def add_user(self):
        username = self.new_username.text().strip()
        password = self.new_password.text()
        full_name = self.new_fullname.text().strip()
        role = self.new_role.currentText()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password are required!")
            return

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            QMessageBox.warning(self, "Weak Password",
                                "Password must be at least 8 characters with 1 uppercase letter and 1 digit!")
            return

        salt = self.db.generate_salt()
        hashed_password = self.db.hash_password(password, salt)

        try:
            self.db.cursor.execute('''
                INSERT INTO users (username, password_hash, salt, role, full_name, must_change_password)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, hashed_password, salt, role, full_name, 0))
            self.db.connection.commit()

            QMessageBox.information(self, "Success", "User added successfully!")
            self.new_username.clear()
            self.new_password.clear()
            self.new_fullname.clear()
            self.load_users()

        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Error", "Username already exists!")

    def reset_password(self):
        btn = self.sender()
        row = btn.property('row')
        user_id = int(self.users_table.item(row, 0).text())
        username = self.users_table.item(row, 1).text()

        new_password, ok = QInputDialog.getText(
            self,
            "Reset Password",
            f"Enter new password for {username} (min 8 chars, 1 uppercase, 1 digit):",
            QLineEdit.Password
        )

        if ok and new_password:
            if len(new_password) < 8 or not any(c.isupper() for c in new_password) or not any(
                    c.isdigit() for c in new_password):
                QMessageBox.warning(self, "Weak Password",
                                    "Password must be at least 8 characters with 1 uppercase letter and 1 digit!")
                return

            salt = self.db.generate_salt()
            hashed_password = self.db.hash_password(new_password, salt)

            self.db.cursor.execute('''
                UPDATE users 
                SET password_hash=?, salt=?, must_change_password=1 
                WHERE id=?
            ''', (hashed_password, salt, user_id))
            self.db.connection.commit()

            QMessageBox.information(self, "Success", "Password reset successfully!")

    def edit_user(self):
        btn = self.sender()
        row = btn.property('row')
        user_id = int(self.users_table.item(row, 0).text())

        self.db.cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = self.db.cursor.fetchone()

        self.edit_user_dialog = QWidget()
        self.edit_user_dialog.setWindowTitle("Edit User")
        self.edit_user_dialog.setFixedSize(400, 300)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        self.edit_user_id = user_id
        self.edit_username = QLineEdit(user[1])
        self.edit_username.setEnabled(False)  # Don't allow changing username

        self.edit_fullname = QLineEdit(user[4])

        self.edit_role = QComboBox()
        self.edit_role.addItems(["Admin", "Manager", "Sales"])
        self.edit_role.setCurrentText(user[3])

        # Disable role change for admin users (except for current admin)
        if user[3] == "Admin" and user_id != self.user['id']:
            self.edit_role.setEnabled(False)

        update_btn = QPushButton("Update User")
        update_btn.clicked.connect(self.update_user)

        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.edit_username)
        layout.addWidget(QLabel("Full Name:"))
        layout.addWidget(self.edit_fullname)
        layout.addWidget(QLabel("Role:"))
        layout.addWidget(self.edit_role)
        layout.addWidget(update_btn)

        self.edit_user_dialog.setLayout(layout)
        self.edit_user_dialog.show()

    def update_user(self):
        user_id = self.edit_user_id
        full_name = self.edit_fullname.text().strip()
        role = self.edit_role.currentText()

        if not full_name:
            QMessageBox.warning(self.edit_user_dialog, "Error", "Full name is required!")
            return

        try:
            self.db.cursor.execute('''
                UPDATE users 
                SET full_name=?, role=?
                WHERE id=?
            ''', (full_name, role, user_id))
            self.db.connection.commit()

            QMessageBox.information(self.edit_user_dialog, "Success", "User updated successfully!")
            self.edit_user_dialog.close()
            self.load_users()

        except sqlite3.Error as e:
            QMessageBox.critical(self.edit_user_dialog, "Database Error", f"Failed to update user: {str(e)}")

    def delete_user(self):
        btn = self.sender()
        row = btn.property('row')
        user_id = int(self.users_table.item(row, 0).text())
        username = self.users_table.item(row, 1).text()

        if user_id == self.user['id']:
            QMessageBox.warning(self, "Error", "You cannot delete your own account!")
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete user {username}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            try:
                # Check if user has any recorded transactions
                self.db.cursor.execute('''
                    SELECT COUNT(*) FROM (
                        SELECT recorded_by FROM sales WHERE recorded_by=?
                        UNION ALL
                        SELECT recorded_by FROM purchases WHERE recorded_by=?
                        UNION ALL
                        SELECT recorded_by FROM inventory_transactions WHERE recorded_by=?
                    )
                ''', (user_id, user_id, user_id))

                if self.db.cursor.fetchone()[0] > 0:
                    QMessageBox.warning(self, "Cannot Delete",
                                        "This user has recorded transactions and cannot be deleted.")
                    return

                self.db.cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
                self.db.connection.commit()

                QMessageBox.information(self, "Success", "User deleted successfully!")
                self.load_users()

            except sqlite3.Error as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete user: {str(e)}")

    def closeEvent(self, event):
        confirm = QMessageBox.question(
            self,
            "Confirm Exit",
            "Are you sure you want to exit the application?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.db.close()
            event.accept()
        else:
            event.ignore()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle('Fusion')

    # Create application directory if it doesn't exist
    app_data_dir = os.path.join(os.path.expanduser('~'), '.construction_inventory')
    if not os.path.exists(app_data_dir):
        os.makedirs(app_data_dir)

    # Set up logging
    log_file = os.path.join(app_data_dir, 'app.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    try:
        login = LoginWindow()
        login.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error(f"Application error: {str(e)}", exc_info=True)
        QMessageBox.critical(None, "Fatal Error", f"An unexpected error occurred:\n{str(e)}\n\nSee logs for details.")