import uuid
import sys
import sqlite3
import os
import hashlib
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
                             QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox,
                             QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
                             QSpinBox, QDoubleSpinBox, QDateEdit, QHeaderView, QInputDialog)
from PyQt5.QtCore import Qt, QDate
from PyQt5.QtGui import QFont, QPixmap, QColor

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

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("durasea Inventory Management")
        self.setFixedSize(800, 600)
        self.setStyleSheet("background-color: #f5f5f5;")

        self.db_connection = sqlite3.connect('construction_inventory.db')
        self.create_tables()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Logo and title
        logo_layout = QHBoxLayout()
        logo_label = QLabel()
        if os.path.exists("icon.png"):
            pixmap = QPixmap("icon.png").scaled(150, 150, Qt.KeepAspectRatio)
            logo_label.setPixmap(pixmap)
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch()

        title = QLabel("Construction Inventory Management")
        title.setFont(QFont('Arial', 24, QFont.Bold))
        title.setStyleSheet("color: #1a5276;")
        title.setAlignment(Qt.AlignCenter)

        # Login form
        form_widget = QWidget()
        form_widget.setStyleSheet("""
            background-color: white;
            border-radius: 10px;
            padding: 30px;
        """)
        form_layout = QVBoxLayout(form_widget)

        form_title = QLabel("Login to Your Account")
        form_title.setFont(QFont('Arial', 16, QFont.Bold))
        form_title.setStyleSheet("color: #1a5276; margin-bottom: 20px;")
        form_title.setAlignment(Qt.AlignCenter)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-bottom: 15px;
            }
        """)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-bottom: 15px;
            }
        """)

        self.role_input = QComboBox()
        self.role_input.addItems(["Admin", "Manager", "Warehouse", "Sales"])
        self.role_input.setStyleSheet("""
            QComboBox {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-bottom: 15px;
            }
        """)

        login_btn = QPushButton("Login")
        login_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        login_btn.clicked.connect(self.authenticate)

        form_layout.addWidget(form_title)
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(self.password_input)
        form_layout.addWidget(self.role_input)
        form_layout.addWidget(login_btn)

        # Main layout
        layout.addLayout(logo_layout)
        layout.addSpacing(20)
        layout.addWidget(title)
        layout.addSpacing(40)
        layout.addWidget(form_widget)
        layout.addStretch()

        self.setLayout(layout)

    def create_tables(self):
        cursor = self.db_connection.cursor()

        # Users table with enhanced security
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0,
                account_locked INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Projects table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                client TEXT NOT NULL,
                address TEXT,
                start_date TEXT,
                end_date TEXT,
                status TEXT DEFAULT 'Active',
                budget REAL,
                notes TEXT
            )
        ''')

        # Materials table with enhanced fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS materials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                supplier TEXT NOT NULL,
                supplier_code TEXT,
                unit TEXT NOT NULL,
                cost_price REAL NOT NULL,
                base_sale_price REAL NOT NULL,
                quantity_in_stock INTEGER NOT NULL,
                min_stock_level INTEGER DEFAULT 10,
                location TEXT,
                last_updated TEXT,
                notes TEXT
            )
        ''')

        # Project-specific pricing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS project_pricing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                material_id INTEGER NOT NULL,
                sale_price REAL NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (material_id) REFERENCES materials(id),
                UNIQUE(project_id, material_id)
            )
        ''')

        # Warehouse transactions (in/out)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS warehouse_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                material_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,  -- 'IN' or 'OUT'
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                total_value REAL NOT NULL,
                transaction_date TEXT NOT NULL,
                project_id INTEGER,
                notes TEXT,
                recorded_by INTEGER NOT NULL,
                FOREIGN KEY (material_id) REFERENCES materials(id),
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (recorded_by) REFERENCES users(id)
            )
        ''')

        # Sales table with project reference
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                material_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                total_price REAL NOT NULL,
                sale_date TEXT NOT NULL,
                seller_id INTEGER NOT NULL,
                notes TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (material_id) REFERENCES materials(id),
                FOREIGN KEY (seller_id) REFERENCES users(id)
            )
        ''')

        # Expenses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                amount REAL NOT NULL,
                expense_date TEXT NOT NULL,
                category TEXT NOT NULL,
                project_id INTEGER,
                recorded_by INTEGER NOT NULL,
                receipt_number TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (recorded_by) REFERENCES users(id)
            )
        ''')

        # Audit log for security
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                table_affected TEXT,
                record_id INTEGER,
                notes TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # Create default admin if not exists (with secure password hashing)
        cursor.execute("SELECT * FROM users WHERE username='admin'")
        if not cursor.fetchone():
            salt = os.urandom(32).hex()
            password = 'Admin@123'  # Strong default password
            hashed_password = self._hash_password(password, salt)

            cursor.execute('''
                INSERT INTO users (username, password, salt, role, full_name)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', hashed_password, salt, 'Admin', 'System Administrator'))

        self.db_connection.commit()

    def _hash_password(self, password, salt):
        """Hash the password with the salt using PBKDF2-HMAC-SHA256"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()

    def authenticate(self):
        username = self.username_input.text()
        password = self.password_input.text()
        role = self.role_input.currentText()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password are required!")
            return

        cursor = self.db_connection.cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()

            if not user:
                QMessageBox.warning(self, "Error", "Invalid username or password!")
                return

            # Check if account is locked
            if user[8] == 1:  # account_locked column
                QMessageBox.warning(self, "Error", "Account is locked. Please contact administrator.")
                return

            # Verify password
            salt = user[3]  # salt column
            hashed_password = user[2]  # password column
            input_hash = self._hash_password(password, salt)

            if input_hash == hashed_password:
                # Check role
                if user[4] != role:  # role column
                    QMessageBox.warning(self, "Error", f"User is not authorized as {role}!")
                    return

                # Reset failed attempts and update last login
                cursor.execute('''
                    UPDATE users 
                    SET failed_attempts=0, last_login=?
                    WHERE id=?
                ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user[0]))
                self.db_connection.commit()

                # Log the successful login
                self._log_activity(user[0], "LOGIN", "users", user[0], "Successful login")

                # Open main window
                self.main_window = MainWindow(user, self.db_connection)
                self.main_window.show()
                self.hide()
            else:
                # Increment failed attempts
                cursor.execute('''
                    UPDATE users 
                    SET failed_attempts=failed_attempts+1 
                    WHERE id=?
                ''', (user[0],))
                self.db_connection.commit()

                # Check if account should be locked
                cursor.execute("SELECT failed_attempts FROM users WHERE id=?", (user[0],))
                attempts = cursor.fetchone()[0]

                if attempts >= 5:
                    cursor.execute('''
                        UPDATE users 
                        SET account_locked=1 
                        WHERE id=?
                    ''', (user[0],))
                    self.db_connection.commit()
                    QMessageBox.warning(self, "Error",
                                        "Account locked due to too many failed attempts. Contact administrator.")
                else:
                    QMessageBox.warning(self, "Error",
                                      f"Invalid username or password! {5-attempts} attempts remaining.")

                # Log the failed login attempt
                self._log_activity(user[0], "LOGIN_FAILED", "users", user[0], "Failed login attempt")

        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def _log_activity(self, user_id, action, table=None, record_id=None, notes=None):
        """Log user activity for security auditing"""
        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO audit_log (user_id, action, table_affected, record_id, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action, table, record_id, notes))
            self.db_connection.commit()
        except sqlite3.Error as e:
            print(f"Error logging activity: {e}")
            self.db_connection.rollback()

    def closeEvent(self, event):
        self.db_connection.close()
        event.accept()


class MainWindow(QMainWindow):
    def __init__(self, user, db_connection):
        super().__init__()
        self.user = user
        self.user_id = user[0]
        self.user_role = user[4]
        self.db_connection = db_connection

        self.setWindowTitle(f"Construction Inventory Management - {self.user_role}")
        self.setMinimumSize(1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 5px;
                background: white;
            }
            QTabBar::tab {
                padding: 13px 15px;
                background: #e0e0e0;
                border: 1px solid #ddd;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: white;
                border-bottom: 2px solid #f39c12;
                font-weight: bold;
            }
        """)

        self.init_ui()

    def init_ui(self):
        self.tabs = QTabWidget()

        # Dashboard Tab
        self.dashboard_tab = QWidget()
        self.init_dashboard()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")

        # Projects Tab
        self.projects_tab = QWidget()
        self.init_projects()
        self.tabs.addTab(self.projects_tab, "Projects")

        # Inventory Tab
        self.inventory_tab = QWidget()
        self.init_inventory()
        self.tabs.addTab(self.inventory_tab, "Inventory")

        # Warehouse Tab
        self.warehouse_tab = QWidget()
        self.init_warehouse()
        self.tabs.addTab(self.warehouse_tab, "Warehouse")

        # Sales Tab
        self.sales_tab = QWidget()
        self.init_sales()
        self.tabs.addTab(self.sales_tab, "Sales")

        # Expenses Tab
        self.expenses_tab = QWidget()
        self.init_expenses()
        self.tabs.addTab(self.expenses_tab, "Expenses")

        # Reports Tab
        self.reports_tab = QWidget()
        self.init_reports()
        self.tabs.addTab(self.reports_tab, "Reports")

        # User Management Tab (only for admin)
        if self.user_role == "Admin":
            self.users_tab = QWidget()
            self.init_users()
            self.tabs.addTab(self.users_tab, "User Management")

        self.setCentralWidget(self.tabs)

        # Status Bar
        status_bar = self.statusBar()
        status_bar.setStyleSheet("background-color: #1a5276; color: white;")
        status_bar.showMessage(f"Logged in as: {self.user[5] if self.user[5] else self.user[1]} ({self.user_role})")

    def init_dashboard(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Summary Cards
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(15)

        # Materials Summary
        materials_card = QWidget()
        materials_card.setStyleSheet("""
            background-color: white;
            border-radius: 10px;
            padding: 15px;
            border-left: 5px solid #3498db;
        """)
        materials_layout = QVBoxLayout(materials_card)
        materials_title = QLabel("Total Materials")
        materials_title.setFont(QFont('Arial', 12, QFont.Bold))
        materials_title.setStyleSheet("color: #3498db;")
        self.materials_count = QLabel("0")
        self.materials_count.setFont(QFont('Arial', 24, QFont.Bold))
        materials_layout.addWidget(materials_title)
        materials_layout.addWidget(self.materials_count)
        materials_layout.addWidget(QLabel("Items in inventory"))
        materials_card.setLayout(materials_layout)

        # Low Stock Summary
        low_stock_card = QWidget()
        low_stock_card.setStyleSheet("""
            background-color: white;
            border-radius: 10px;
            padding: 15px;
            border-left: 5px solid #e74c3c;
        """)
        low_stock_layout = QVBoxLayout(low_stock_card)
        low_stock_title = QLabel("Low Stock Items")
        low_stock_title.setFont(QFont('Arial', 12, QFont.Bold))
        low_stock_title.setStyleSheet("color: #e74c3c;")
        self.low_stock_count = QLabel("0")
        self.low_stock_count.setFont(QFont('Arial', 24, QFont.Bold))
        low_stock_layout.addWidget(low_stock_title)
        low_stock_layout.addWidget(self.low_stock_count)
        low_stock_layout.addWidget(QLabel("Need replenishment"))
        low_stock_card.setLayout(low_stock_layout)

        # Sales Summary
        sales_card = QWidget()
        sales_card.setStyleSheet("""
            background-color: white;
            border-radius: 10px;
            padding: 15px;
            border-left: 5px solid #2ecc71;
        """)
        sales_layout = QVBoxLayout(sales_card)
        sales_title = QLabel("Today's Sales")
        sales_title.setFont(QFont('Arial', 12, QFont.Bold))
        sales_title.setStyleSheet("color: #2ecc71;")
        self.sales_amount = QLabel("$0.00")
        self.sales_amount.setFont(QFont('Arial', 24, QFont.Bold))
        sales_layout.addWidget(sales_title)
        sales_layout.addWidget(self.sales_amount)
        sales_layout.addWidget(QLabel("Total revenue"))
        sales_card.setLayout(sales_layout)

        # Inventory Value Summary
        inventory_value_card = QWidget()
        inventory_value_card.setStyleSheet("""
            background-color: white;
            border-radius: 10px;
            padding: 15px;
            border-left: 5px solid #f39c12;
        """)
        inventory_value_layout = QVBoxLayout(inventory_value_card)
        inventory_value_title = QLabel("Inventory Value")
        inventory_value_title.setFont(QFont('Arial', 12, QFont.Bold))
        inventory_value_title.setStyleSheet("color: #f39c12;")
        self.inventory_value = QLabel("$0.00")
        self.inventory_value.setFont(QFont('Arial', 24, QFont.Bold))
        inventory_value_layout.addWidget(inventory_value_title)
        inventory_value_layout.addWidget(self.inventory_value)
        inventory_value_layout.addWidget(QLabel("Current stock value"))
        inventory_value_card.setLayout(inventory_value_layout)

        summary_layout.addWidget(materials_card)
        summary_layout.addWidget(low_stock_card)
        summary_layout.addWidget(sales_card)
        summary_layout.addWidget(inventory_value_card)

        # Recent Activity Tables
        recent_activity_layout = QHBoxLayout()
        recent_activity_layout.setSpacing(15)

        # Recent Sales
        recent_sales_group = QWidget()
        recent_sales_group.setStyleSheet("background-color: white; border-radius: 10px; padding: 15px;")
        recent_sales_layout = QVBoxLayout(recent_sales_group)

        recent_sales_label = QLabel("Recent Sales")
        recent_sales_label.setFont(QFont('Arial', 14, QFont.Bold))
        recent_sales_label.setStyleSheet("margin-bottom: 10px;")

        self.recent_sales_table = QTableWidget()
        self.recent_sales_table.setColumnCount(6)
        self.recent_sales_table.setHorizontalHeaderLabels(["ID", "Project", "Material", "Qty", "Amount", "Date"])
        self.recent_sales_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.recent_sales_table.setEditTriggers(QTableWidget.NoEditTriggers)

        recent_sales_layout.addWidget(recent_sales_label)
        recent_sales_layout.addWidget(self.recent_sales_table)

        # Recent Warehouse Activity
        recent_warehouse_group = QWidget()
        recent_warehouse_group.setStyleSheet("background-color: white; border-radius: 10px; padding: 15px;")
        recent_warehouse_layout = QVBoxLayout(recent_warehouse_group)

        recent_warehouse_label = QLabel("Recent Warehouse Activity")
        recent_warehouse_label.setFont(QFont('Arial', 14, QFont.Bold))
        recent_warehouse_label.setStyleSheet("margin-bottom: 10px;")

        self.recent_warehouse_table = QTableWidget()
        self.recent_warehouse_table.setColumnCount(6)
        self.recent_warehouse_table.setHorizontalHeaderLabels(["ID", "Material", "Type", "Qty", "Project", "Date"])
        self.recent_warehouse_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.recent_warehouse_table.setEditTriggers(QTableWidget.NoEditTriggers)

        recent_warehouse_layout.addWidget(recent_warehouse_label)
        recent_warehouse_layout.addWidget(self.recent_warehouse_table)

        recent_activity_layout.addWidget(recent_sales_group)
        recent_activity_layout.addWidget(recent_warehouse_group)

        layout.addLayout(summary_layout)
        layout.addLayout(recent_activity_layout)

        self.dashboard_tab.setLayout(layout)

        # Load dashboard data
        self.load_dashboard_data()

    def load_dashboard_data(self):
        cursor = self.db_connection.cursor()

        # Total materials count
        cursor.execute("SELECT COUNT(*) FROM materials")
        self.materials_count.setText(str(cursor.fetchone()[0]))

        # Low stock count
        cursor.execute("SELECT COUNT(*) FROM materials WHERE quantity_in_stock <= min_stock_level")
        self.low_stock_count.setText(str(cursor.fetchone()[0]))

        # Today's sales total
        today = datetime.now().strftime("%Y-%m-%d")
        cursor.execute("SELECT SUM(total_price) FROM sales WHERE date(sale_date) = ?", (today,))
        total_sales = cursor.fetchone()[0]
        self.sales_amount.setText(f"${total_sales:,.2f}" if total_sales else "$0.00")

        # Inventory value
        cursor.execute("SELECT SUM(cost_price * quantity_in_stock) FROM materials")
        inventory_value = cursor.fetchone()[0]
        self.inventory_value.setText(f"${inventory_value:,.2f}" if inventory_value else "$0.00")

        # Recent sales (last 10)
        cursor.execute('''
            SELECT s.id, p.name, m.name, s.quantity, s.total_price, s.sale_date 
            FROM sales s 
            JOIN projects p ON s.project_id = p.id
            JOIN materials m ON s.material_id = m.id
            ORDER BY s.sale_date DESC LIMIT 10
        ''')
        recent_sales = cursor.fetchall()

        self.recent_sales_table.setRowCount(len(recent_sales))
        for row_idx, row_data in enumerate(recent_sales):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.recent_sales_table.setItem(row_idx, col_idx, item)

        # Recent warehouse activity (last 10)
        cursor.execute('''
            SELECT wt.id, m.name, wt.transaction_type, wt.quantity, 
                   COALESCE(p.name, 'N/A'), wt.transaction_date
            FROM warehouse_transactions wt
            JOIN materials m ON wt.material_id = m.id
            LEFT JOIN projects p ON wt.project_id = p.id
            ORDER BY wt.transaction_date DESC LIMIT 10
        ''')
        recent_warehouse = cursor.fetchall()

        self.recent_warehouse_table.setRowCount(len(recent_warehouse))
        for row_idx, row_data in enumerate(recent_warehouse):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.recent_warehouse_table.setItem(row_idx, col_idx, item)

    def init_projects(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Top controls
        controls_layout = QHBoxLayout()

        self.search_project = QLineEdit()
        self.search_project.setPlaceholderText("Search projects...")
        self.search_project.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        """)
        self.search_project.textChanged.connect(self.load_projects)

        add_project_btn = QPushButton("Add Project")
        add_project_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                padding: 10px 15px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        add_project_btn.clicked.connect(self.show_add_project_dialog)

        controls_layout.addWidget(self.search_project)
        controls_layout.addWidget(add_project_btn)

        # Projects table
        self.projects_table = QTableWidget()
        self.projects_table.setColumnCount(8)
        self.projects_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Client", "Start Date", "End Date", "Status", "Budget", "Actions"])
        self.projects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.projects_table.setEditTriggers(QTableWidget.NoEditTriggers)

        layout.addLayout(controls_layout)
        layout.addWidget(self.projects_table)

        self.projects_tab.setLayout(layout)

        # Load projects
        self.load_projects()

    def load_projects(self):
        search_term = f"%{self.search_project.text()}%"
        cursor = self.db_connection.cursor()
        cursor.execute('''
            SELECT id, name, client, start_date, end_date, status, budget
            FROM projects 
            WHERE name LIKE ? OR client LIKE ? OR status LIKE ?
            ORDER BY status, start_date DESC
        ''', (search_term, search_term, search_term))
        projects = cursor.fetchall()

        self.projects_table.setRowCount(len(projects))
        for row_idx, row_data in enumerate(projects):
            for col_idx, col_data in enumerate(row_data[:7]):  # Skip notes for display
                item = QTableWidgetItem(str(col_data) if col_data is not None else "")
                self.projects_table.setItem(row_idx, col_idx, item)

                # Color coding for status
                if col_idx == 5:  # Status column
                    if col_data == "Active":
                        item.setForeground(Qt.darkGreen)
                    elif col_data == "Completed":
                        item.setForeground(Qt.darkBlue)
                    elif col_data == "On Hold":
                        item.setForeground(Qt.darkYellow)
                    elif col_data == "Cancelled":
                        item.setForeground(Qt.red)

                # Format budget as currency
                if col_idx == 6 and col_data is not None:  # Budget column
                    item.setText(f"${float(col_data):,.2f}")

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            edit_btn = QPushButton("Edit")
            edit_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    padding: 7px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
            edit_btn.clicked.connect(lambda _, row=row_idx: self.edit_project(row))

            pricing_btn = QPushButton("Pricing")
            pricing_btn.setStyleSheet("""
                QPushButton {
                    background-color: #2ecc71;
                    color: white;
                    padding: 8px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #27ae60;
                }
            """)
            pricing_btn.clicked.connect(lambda _, row=row_idx: self.manage_project_pricing(row))

            delete_btn = QPushButton("Delete")
            delete_btn.setStyleSheet("""
                QPushButton {
                    background-color: #e74c3c;
                    color: white;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #c0392b;
                }
            """)
            delete_btn.clicked.connect(lambda _, row=row_idx: self.delete_project(row))

            actions_layout.addWidget(edit_btn)
            actions_layout.addWidget(pricing_btn)
            actions_layout.addWidget(delete_btn)
            actions_widget.setLayout(actions_layout)

            self.projects_table.setCellWidget(row_idx, 7, actions_widget)

    def show_add_project_dialog(self):
        self.project_dialog = QWidget()
        self.project_dialog.setWindowTitle("Add New Project")
        self.project_dialog.setFixedSize(500, 500)
        self.project_dialog.setStyleSheet("background-color: white; padding: 20px;")

        layout = QVBoxLayout()

        self.project_name = QLineEdit()
        self.project_name.setPlaceholderText("Project Name")

        self.project_client = QLineEdit()
        self.project_client.setPlaceholderText("Client Name")

        self.project_address = QLineEdit()
        self.project_address.setPlaceholderText("Project Address")

        # Date widgets
        date_layout = QHBoxLayout()
        self.project_start_date = QDateEdit()
        self.project_start_date.setDate(QDate.currentDate())
        self.project_start_date.setCalendarPopup(True)
        self.project_end_date = QDateEdit()
        self.project_end_date.setDate(QDate.currentDate().addMonths(3))
        self.project_end_date.setCalendarPopup(True)
        date_layout.addWidget(QLabel("Start Date:"))
        date_layout.addWidget(self.project_start_date)
        date_layout.addWidget(QLabel("End Date:"))
        date_layout.addWidget(self.project_end_date)

        self.project_status = QComboBox()
        self.project_status.addItems(["Active", "On Hold", "Completed", "Cancelled"])

        self.project_budget = QDoubleSpinBox()
        self.project_budget.setPrefix("$ ")
        self.project_budget.setMaximum(99999999.99)

        self.project_notes = QLineEdit()
        self.project_notes.setPlaceholderText("Notes (optional)")

        save_btn = QPushButton("Save Project")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        save_btn.clicked.connect(self.save_project)

        # Style all inputs consistently
        for widget in [self.project_name, self.project_client, self.project_address,
                       self.project_notes]:
            widget.setStyleSheet("""
                QLineEdit {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        self.project_status.setStyleSheet("""
            QComboBox {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-bottom: 15px;
            }
        """)

        self.project_budget.setStyleSheet("""
            QDoubleSpinBox {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-bottom: 15px;
            }
        """)

        layout.addWidget(QLabel("Project Name:"))
        layout.addWidget(self.project_name)
        layout.addWidget(QLabel("Client:"))
        layout.addWidget(self.project_client)
        layout.addWidget(QLabel("Address:"))
        layout.addWidget(self.project_address)
        layout.addLayout(date_layout)
        layout.addWidget(QLabel("Status:"))
        layout.addWidget(self.project_status)
        layout.addWidget(QLabel("Budget:"))
        layout.addWidget(self.project_budget)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.project_notes)
        layout.addWidget(save_btn)

        self.project_dialog.setLayout(layout)
        self.project_dialog.show()

    def save_project(self):
        name = self.project_name.text()
        client = self.project_client.text()
        address = self.project_address.text()
        start_date = self.project_start_date.date().toString("yyyy-MM-dd")
        end_date = self.project_end_date.date().toString("yyyy-MM-dd")
        status = self.project_status.currentText()
        budget = self.project_budget.value()
        notes = self.project_notes.text()

        if not name or not client:
            QMessageBox.warning(self.project_dialog, "Error", "Project name and client are required!")
            return

        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO projects (name, client, address, start_date, end_date, status, budget, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, client, address, start_date, end_date, status, budget, notes))
            self.db_connection.commit()

            # Log the activity
            self._log_activity(self.user_id, "CREATE", "projects", cursor.lastrowid, f"Added project {name}")

            QMessageBox.information(self.project_dialog, "Success", "Project added successfully!")
            self.project_dialog.close()
            self.load_projects()
        except sqlite3.Error as e:
            QMessageBox.warning(self.project_dialog, "Error", f"Database error: {str(e)}")

    def edit_project(self, row):
        project_id = int(self.projects_table.item(row, 0).text())

        cursor = self.db_connection.cursor()
        cursor.execute("SELECT * FROM projects WHERE id=?", (project_id,))
        project = cursor.fetchone()

        self.edit_project_dialog = QWidget()
        self.edit_project_dialog.setWindowTitle("Edit Project")
        self.edit_project_dialog.setFixedSize(500, 500)
        self.edit_project_dialog.setStyleSheet("background-color: white; padding: 20px;")

        layout = QVBoxLayout()

        self.edit_project_id = project_id
        self.edit_project_name = QLineEdit(project[1])
        self.edit_project_client = QLineEdit(project[2])
        self.edit_project_address = QLineEdit(project[3] if project[3] else "")

        # Date widgets
        date_layout = QHBoxLayout()
        self.edit_project_start_date = QDateEdit()
        self.edit_project_start_date.setDate(QDate.fromString(project[4], "yyyy-MM-dd"))
        self.edit_project_start_date.setCalendarPopup(True)
        self.edit_project_end_date = QDateEdit()
        self.edit_project_end_date.setDate(
            QDate.fromString(project[5], "yyyy-MM-dd") if project[5] else QDate.currentDate())
        self.edit_project_end_date.setCalendarPopup(True)
        date_layout.addWidget(QLabel("Start Date:"))
        date_layout.addWidget(self.edit_project_start_date)
        date_layout.addWidget(QLabel("End Date:"))
        date_layout.addWidget(self.edit_project_end_date)

        self.edit_project_status = QComboBox()
        self.edit_project_status.addItems(["Active", "On Hold", "Completed", "Cancelled"])
        self.edit_project_status.setCurrentText(project[6])

        self.edit_project_budget = QDoubleSpinBox()
        self.edit_project_budget.setPrefix("$ ")
        self.edit_project_budget.setMaximum(99999999.99)
        self.edit_project_budget.setValue(project[7] if project[7] else 0)

        self.edit_project_notes = QLineEdit(project[8] if project[8] else "")
        self.edit_project_notes.setPlaceholderText("Notes (optional)")

        update_btn = QPushButton("Update Project")
        update_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        update_btn.clicked.connect(self.update_project)

        # Style all inputs consistently
        for widget in [self.edit_project_name, self.edit_project_client, self.edit_project_address,
                       self.edit_project_notes]:
            widget.setStyleSheet("""
                QLineEdit {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        self.edit_project_status.setStyleSheet("""
            QComboBox {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-bottom: 15px;
            }
        """)

        self.edit_project_budget.setStyleSheet("""
            QDoubleSpinBox {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-bottom: 15px;
            }
        """)

        layout.addWidget(QLabel("Project Name:"))
        layout.addWidget(self.edit_project_name)
        layout.addWidget(QLabel("Client:"))
        layout.addWidget(self.edit_project_client)
        layout.addWidget(QLabel("Address:"))
        layout.addWidget(self.edit_project_address)
        layout.addLayout(date_layout)
        layout.addWidget(QLabel("Status:"))
        layout.addWidget(self.edit_project_status)
        layout.addWidget(QLabel("Budget:"))
        layout.addWidget(self.edit_project_budget)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.edit_project_notes)
        layout.addWidget(update_btn)

        self.edit_project_dialog.setLayout(layout)
        self.edit_project_dialog.show()

    def update_project(self):
        project_id = self.edit_project_id
        name = self.edit_project_name.text()
        client = self.edit_project_client.text()
        address = self.edit_project_address.text()
        start_date = self.edit_project_start_date.date().toString("yyyy-MM-dd")
        end_date = self.edit_project_end_date.date().toString("yyyy-MM-dd")
        status = self.edit_project_status.currentText()
        budget = self.edit_project_budget.value()
        notes = self.edit_project_notes.text()

        if not name or not client:
            QMessageBox.warning(self.edit_project_dialog, "Error", "Project name and client are required!")
            return

        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                UPDATE projects 
                SET name=?, client=?, address=?, start_date=?, end_date=?, status=?, budget=?, notes=?
                WHERE id=?
            ''', (name, client, address, start_date, end_date, status, budget, notes, project_id))
            self.db_connection.commit()

            # Log the activity
            self._log_activity(self.user_id, "UPDATE", "projects", project_id, f"Updated project {name}")

            QMessageBox.information(self.edit_project_dialog, "Success", "Project updated successfully!")
            self.edit_project_dialog.close()
            self.load_projects()
        except sqlite3.Error as e:
            QMessageBox.warning(self.edit_project_dialog, "Error", f"Database error: {str(e)}")

    def delete_project(self, row):
        project_id = int(self.projects_table.item(row, 0).text())
        project_name = self.projects_table.item(row, 1).text()

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete project '{project_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            cursor = self.db_connection.cursor()
            try:
                cursor.execute("DELETE FROM projects WHERE id=?", (project_id,))
                self.db_connection.commit()

                # Log the activity
                self._log_activity(self.user_id, "DELETE", "projects", project_id, f"Deleted project {project_name}")

                QMessageBox.information(self, "Success", "Project deleted successfully!")
                self.load_projects()
            except sqlite3.Error as e:
                QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def manage_project_pricing(self, row):
        project_id = int(self.projects_table.item(row, 0).text())
        project_name = self.projects_table.item(row, 1).text()

        self.pricing_dialog = QWidget()
        self.pricing_dialog.setWindowTitle(f"Pricing for {project_name}")
        self.pricing_dialog.setMinimumSize(800, 600)
        self.pricing_dialog.setStyleSheet("background-color: white; padding: 20px;")

        layout = QVBoxLayout()

        # Project info
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel(f"<b>Project:</b> {project_name}"))
        info_layout.addWidget(QLabel(f"<b>Client:</b> {self.projects_table.item(row, 2).text()}"))
        info_layout.addStretch()

        # Materials selection and pricing
        form_layout = QHBoxLayout()

        self.pricing_material = QComboBox()
        self.load_materials_for_pricing()

        self.pricing_base_price = QDoubleSpinBox()
        self.pricing_base_price.setPrefix("$ ")
        self.pricing_base_price.setMaximum(99999.99)
        self.pricing_base_price.setReadOnly(True)

        self.pricing_sale_price = QDoubleSpinBox()
        self.pricing_sale_price.setPrefix("$ ")
        self.pricing_sale_price.setMaximum(99999.99)

        add_pricing_btn = QPushButton("Set Price")
        add_pricing_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        add_pricing_btn.clicked.connect(lambda: self.set_project_price(project_id))

        form_layout.addWidget(QLabel("Material:"))
        form_layout.addWidget(self.pricing_material)
        form_layout.addWidget(QLabel("Base Price:"))
        form_layout.addWidget(self.pricing_base_price)
        form_layout.addWidget(QLabel("Sale Price:"))
        form_layout.addWidget(self.pricing_sale_price)
        form_layout.addWidget(add_pricing_btn)

        # Pricing table
        self.pricing_table = QTableWidget()
        self.pricing_table.setColumnCount(5)
        self.pricing_table.setHorizontalHeaderLabels(["Material", "Category", "Base Price", "Sale Price", "Actions"])
        self.pricing_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.pricing_table.setEditTriggers(QTableWidget.NoEditTriggers)

        layout.addLayout(info_layout)
        layout.addLayout(form_layout)
        layout.addWidget(self.pricing_table)

        self.pricing_dialog.setLayout(layout)
        self.pricing_dialog.show()

        # Load existing pricing
        self.load_project_pricing(project_id)

        # Connect material selection change to update base price
        self.pricing_material.currentIndexChanged.connect(self.update_pricing_base_price)

    def load_materials_for_pricing(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT id, name, category, base_sale_price FROM materials ORDER BY name")
        materials = cursor.fetchall()

        self.pricing_material.clear()
        self.pricing_material_map = {}

        for material in materials:
            self.pricing_material_map[material[0]] = material[3]  # Store material_id: base_price
            self.pricing_material.addItem(f"{material[1]} ({material[2]})", material[0])

    def update_pricing_base_price(self):
        material_id = self.pricing_material.currentData()
        if material_id in self.pricing_material_map:
            self.pricing_base_price.setValue(self.pricing_material_map[material_id])
            self.pricing_sale_price.setValue(self.pricing_material_map[material_id])

    def load_project_pricing(self, project_id):
        cursor = self.db_connection.cursor()
        cursor.execute('''
            SELECT pp.id, m.name, m.category, m.base_sale_price, pp.sale_price
            FROM project_pricing pp
            JOIN materials m ON pp.material_id = m.id
            WHERE pp.project_id = ?
            ORDER BY m.name
        ''', (project_id,))
        pricing_data = cursor.fetchall()

        self.pricing_table.setRowCount(len(pricing_data))
        for row_idx, row_data in enumerate(pricing_data):
            for col_idx, col_data in enumerate(row_data[1:]):  # Skip the pp.id
                item = QTableWidgetItem(str(col_data))
                self.pricing_table.setItem(row_idx, col_idx, item)

                # Format prices as currency
                if col_idx in [2, 3]:  # Base Price and Sale Price columns
                    item.setText(f"${float(col_data):,.2f}")

                    # Highlight if sale price is different from base price
                    if col_idx == 3 and row_data[3] != row_data[4]:
                        if row_data[4] > row_data[3]:
                            item.setForeground(Qt.darkGreen)
                        else:
                            item.setForeground(Qt.darkRed)

            # Add action button
            delete_btn = QPushButton("Remove")
            delete_btn.setStyleSheet("""
                QPushButton {
                    background-color: #e74c3c;
                    color: white;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #c0392b;
                }
            """)
            delete_btn.clicked.connect(lambda _, pid=row_data[0]: self.remove_project_price(pid, project_id))

            self.pricing_table.setCellWidget(row_idx, 4, delete_btn)

    def set_project_price(self, project_id):
        material_id = self.pricing_material.currentData()
        sale_price = self.pricing_sale_price.value()

        if not material_id:
            QMessageBox.warning(self.pricing_dialog, "Error", "Please select a material!")
            return

        cursor = self.db_connection.cursor()
        try:
            # Check if pricing already exists for this project+material
            cursor.execute('''
                SELECT id FROM project_pricing 
                WHERE project_id=? AND material_id=?
            ''', (project_id, material_id))

            existing = cursor.fetchone()

            if existing:
                # Update existing pricing
                cursor.execute('''
                    UPDATE project_pricing 
                    SET sale_price=?
                    WHERE id=?
                ''', (sale_price, existing[0]))
                action = "updated"
            else:
                # Insert new pricing
                cursor.execute('''
                    INSERT INTO project_pricing (project_id, material_id, sale_price)
                    VALUES (?, ?, ?)
                ''', (project_id, material_id, sale_price))
                action = "added"

            self.db_connection.commit()

            # Log the activity
            cursor.execute("SELECT name FROM materials WHERE id=?", (material_id,))
            material_name = cursor.fetchone()[0]
            self._log_activity(self.user_id, "UPDATE" if existing else "CREATE",
                              "project_pricing", cursor.lastrowid,
                              f"{action} price {sale_price} for {material_name}")

            QMessageBox.information(self.pricing_dialog, "Success",
                                   f"Price {action} successfully!")
            self.load_project_pricing(project_id)
        except sqlite3.Error as e:
            QMessageBox.warning(self.pricing_dialog, "Error", f"Database error: {str(e)}")

    def remove_project_price(self, pricing_id, project_id):
        confirm = QMessageBox.question(
            self.pricing_dialog,
            "Confirm Remove",
            "Are you sure you want to remove this pricing?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            cursor = self.db_connection.cursor()
            try:
                # Get material name for logging
                cursor.execute('''
                    SELECT m.name FROM project_pricing pp
                    JOIN materials m ON pp.material_id = m.id
                    WHERE pp.id=?
                ''', (pricing_id,))
                material_name = cursor.fetchone()[0]

                cursor.execute("DELETE FROM project_pricing WHERE id=?", (pricing_id,))
                self.db_connection.commit()

                # Log the activity
                self._log_activity(self.user_id, "DELETE", "project_pricing",
                                  pricing_id, f"Removed pricing for {material_name}")

                QMessageBox.information(self.pricing_dialog, "Success",
                                       "Pricing removed successfully!")
                self.load_project_pricing(project_id)
            except sqlite3.Error as e:
                QMessageBox.warning(self.pricing_dialog, "Error", f"Database error: {str(e)}")

    def init_inventory(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Top controls
        controls_layout = QHBoxLayout()

        self.search_material = QLineEdit()
        self.search_material.setPlaceholderText("Search materials...")
        self.search_material.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        """)
        self.search_material.textChanged.connect(self.load_materials)

        add_material_btn = QPushButton("Add Material")
        add_material_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                padding: 10px 15px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        add_material_btn.clicked.connect(self.show_add_material_dialog)

        controls_layout.addWidget(self.search_material)
        controls_layout.addWidget(add_material_btn)

        # Materials table
        self.materials_table = QTableWidget()
        self.materials_table.setColumnCount(10)
        self.materials_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Category", "Supplier", "Unit", "Cost", "Base Price", "In Stock", "Min Stock", "Actions"])
        self.materials_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.materials_table.setEditTriggers(QTableWidget.NoEditTriggers)

        layout.addLayout(controls_layout)
        layout.addWidget(self.materials_table)

        self.inventory_tab.setLayout(layout)

        # Load materials
        self.load_materials()

    def load_materials(self):
        search_term = f"%{self.search_material.text()}%"
        cursor = self.db_connection.cursor()
        cursor.execute('''
            SELECT id, name, category, supplier, unit, cost_price, base_sale_price, 
                   quantity_in_stock, min_stock_level
            FROM materials 
            WHERE name LIKE ? OR category LIKE ? OR supplier LIKE ?
            ORDER BY name
        ''', (search_term, search_term, search_term))
        materials = cursor.fetchall()

        self.materials_table.setRowCount(len(materials))
        for row_idx, row_data in enumerate(materials):
            for col_idx, col_data in enumerate(row_data[:9]):  # Skip notes, location for display
                item = QTableWidgetItem(str(col_data))
                self.materials_table.setItem(row_idx, col_idx, item)

                # Format prices as currency
                if col_idx in [5, 6]:  # Cost and Base Price columns
                    item.setText(f"${float(col_data):,.2f}")

                # Highlight low stock items
                if col_idx == 7 and row_data[7] <= row_data[8]:  # quantity <= min_stock_level
                    if row_data[7] <= row_data[8] * 0.5:  # Critical low stock
                        item.setBackground(Qt.red)
                        item.setForeground(Qt.white)
                    else:
                        item.setBackground(Qt.yellow)

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            edit_btn = QPushButton("Edit")
            edit_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
            edit_btn.clicked.connect(lambda _, row=row_idx: self.edit_material(row))

            delete_btn = QPushButton("Delete")
            delete_btn.setStyleSheet("""
                QPushButton {
                    background-color: #e74c3c;
                    color: white;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #c0392b;
                }
            """)
            delete_btn.clicked.connect(lambda _, row=row_idx: self.delete_material(row))

            actions_layout.addWidget(edit_btn)
            actions_layout.addWidget(delete_btn)
            actions_widget.setLayout(actions_layout)

            self.materials_table.setCellWidget(row_idx, 9, actions_widget)

    def show_add_material_dialog(self):
        self.material_dialog = QWidget()
        self.material_dialog.setWindowTitle("Add New Material")
        self.material_dialog.setFixedSize(500, 600)
        self.material_dialog.setStyleSheet("background-color: white; padding: 20px;")

        layout = QVBoxLayout()

        self.material_name = QLineEdit()
        self.material_name.setPlaceholderText("Material Name")

        self.material_category = QComboBox()
        self.material_category.addItems([
            "Cement & Concrete", "Steel & Rebar", "Bricks & Blocks",
            "Aggregates", "Wood & Timber", "Plumbing", "Electrical",
            "Finishes", "Hardware", "Other"
        ])

        self.material_supplier = QLineEdit()
        self.material_supplier.setPlaceholderText("Supplier (e.g., Dr.Fixit)")

        self.material_supplier_code = QLineEdit()
        self.material_supplier_code.setPlaceholderText("Supplier Code (optional)")

        self.material_unit = QComboBox()
        self.material_unit.addItems([
            "kg", "ton", "piece", "box", "bag", "roll", "sheet",
            "liter", "gallon", "meter", "sq.m", "cu.m", "set"
        ])

        self.material_cost_price = QDoubleSpinBox()
        self.material_cost_price.setPrefix("$ ")
        self.material_cost_price.setMaximum(99999.99)

        self.material_base_price = QDoubleSpinBox()
        self.material_base_price.setPrefix("$ ")
        self.material_base_price.setMaximum(99999.99)

        self.material_quantity = QSpinBox()
        self.material_quantity.setMinimum(0)
        self.material_quantity.setMaximum(999999)

        self.material_min_stock = QSpinBox()
        self.material_min_stock.setMinimum(1)
        self.material_min_stock.setMaximum(999999)
        self.material_min_stock.setValue(10)

        self.material_location = QLineEdit()
        self.material_location.setPlaceholderText("Warehouse Location (optional)")

        self.material_notes = QLineEdit()
        self.material_notes.setPlaceholderText("Notes (optional)")

        save_btn = QPushButton("Save Material")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        save_btn.clicked.connect(self.save_material)

        # Style all inputs consistently
        for widget in [self.material_name, self.material_supplier,
                       self.material_supplier_code, self.material_location,
                       self.material_notes]:
            widget.setStyleSheet("""
                QLineEdit {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        for widget in [self.material_category, self.material_unit]:
            widget.setStyleSheet("""
                QComboBox {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        for widget in [self.material_cost_price, self.material_base_price,
                       self.material_quantity, self.material_min_stock]:
            widget.setStyleSheet("""
                QSpinBox, QDoubleSpinBox {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        layout.addWidget(QLabel("Material Name:"))
        layout.addWidget(self.material_name)
        layout.addWidget(QLabel("Category:"))
        layout.addWidget(self.material_category)
        layout.addWidget(QLabel("Supplier:"))
        layout.addWidget(self.material_supplier)
        layout.addWidget(QLabel("Supplier Code:"))
        layout.addWidget(self.material_supplier_code)
        layout.addWidget(QLabel("Unit:"))
        layout.addWidget(self.material_unit)
        layout.addWidget(QLabel("Cost Price:"))
        layout.addWidget(self.material_cost_price)
        layout.addWidget(QLabel("Base Sale Price:"))
        layout.addWidget(self.material_base_price)
        layout.addWidget(QLabel("Initial Quantity:"))
        layout.addWidget(self.material_quantity)
        layout.addWidget(QLabel("Minimum Stock Level:"))
        layout.addWidget(self.material_min_stock)
        layout.addWidget(QLabel("Location:"))
        layout.addWidget(self.material_location)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.material_notes)
        layout.addWidget(save_btn)

        self.material_dialog.setLayout(layout)
        self.material_dialog.show()

    def save_material(self):
        name = self.material_name.text()
        category = self.material_category.currentText()
        supplier = self.material_supplier.text()
        supplier_code = self.material_supplier_code.text()
        unit = self.material_unit.currentText()
        cost_price = self.material_cost_price.value()
        base_price = self.material_base_price.value()
        quantity = self.material_quantity.value()
        min_stock = self.material_min_stock.value()
        location = self.material_location.text()
        notes = self.material_notes.text()

        if not name or not supplier:
            QMessageBox.warning(self.material_dialog, "Error", "Material name and supplier are required!")
            return

        if base_price < cost_price:
            confirm = QMessageBox.question(
                self.material_dialog,
                "Confirm Price",
                "Sale price is lower than cost price. Are you sure?",
                QMessageBox.Yes | QMessageBox.No
            )
            if confirm == QMessageBox.No:
                return

        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO materials (
                    name, category, supplier, supplier_code, unit, 
                    cost_price, base_sale_price, quantity_in_stock, 
                    min_stock_level, location, notes, last_updated
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                name, category, supplier, supplier_code, unit,
                cost_price, base_price, quantity, min_stock,
                location, notes, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            self.db_connection.commit()

            # Log the activity
            self._log_activity(self.user_id, "CREATE", "materials", cursor.lastrowid, f"Added material {name}")

            QMessageBox.information(self.material_dialog, "Success", "Material added successfully!")
            self.material_dialog.close()
            self.load_materials()
            self.load_dashboard_data()  # Refresh dashboard counts
        except sqlite3.Error as e:
            QMessageBox.warning(self.material_dialog, "Error", f"Database error: {str(e)}")

    def edit_material(self, row):
        material_id = int(self.materials_table.item(row, 0).text())

        cursor = self.db_connection.cursor()
        cursor.execute("SELECT * FROM materials WHERE id=?", (material_id,))
        material = cursor.fetchone()

        self.edit_material_dialog = QWidget()
        self.edit_material_dialog.setWindowTitle("Edit Material")
        self.edit_material_dialog.setFixedSize(500, 600)
        self.edit_material_dialog.setStyleSheet("background-color: white; padding: 20px;")

        layout = QVBoxLayout()

        self.edit_material_id = material_id
        self.edit_material_name = QLineEdit(material[1])
        self.edit_material_category = QComboBox()
        self.edit_material_category.addItems([
            "Cement & Concrete", "Steel & Rebar", "Bricks & Blocks",
            "Aggregates", "Wood & Timber", "Plumbing", "Electrical",
            "Finishes", "Hardware", "Other"
        ])
        self.edit_material_category.setCurrentText(material[2])

        self.edit_material_supplier = QLineEdit(material[3])
        self.edit_material_supplier_code = QLineEdit(material[4] if material[4] else "")
        self.edit_material_unit = QComboBox()
        self.edit_material_unit.addItems([
            "kg", "ton", "piece", "box", "bag", "roll", "sheet",
            "liter", "gallon", "meter", "sq.m", "cu.m", "set"
        ])
        self.edit_material_unit.setCurrentText(material[5])

        self.edit_material_cost_price = QDoubleSpinBox()
        self.edit_material_cost_price.setPrefix("$ ")
        self.edit_material_cost_price.setMaximum(99999.99)
        self.edit_material_cost_price.setValue(material[6])

        self.edit_material_base_price = QDoubleSpinBox()
        self.edit_material_base_price.setPrefix("$ ")
        self.edit_material_base_price.setMaximum(99999.99)
        self.edit_material_base_price.setValue(material[7])

        self.edit_material_quantity = QSpinBox()
        self.edit_material_quantity.setMinimum(0)
        self.edit_material_quantity.setMaximum(999999)
        self.edit_material_quantity.setValue(material[8])

        self.edit_material_min_stock = QSpinBox()
        self.edit_material_min_stock.setMinimum(1)
        self.edit_material_min_stock.setMaximum(999999)
        self.edit_material_min_stock.setValue(material[9])

        self.edit_material_location = QLineEdit(material[10] if material[10] else "")
        self.edit_material_notes = QLineEdit(material[11] if material[11] else "")

        update_btn = QPushButton("Update Material")
        update_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        update_btn.clicked.connect(self.update_material)

        # Style all inputs consistently
        for widget in [self.edit_material_name, self.edit_material_supplier,
                       self.edit_material_supplier_code, self.edit_material_location,
                       self.edit_material_notes]:
            widget.setStyleSheet("""
                QLineEdit {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        for widget in [self.edit_material_category, self.edit_material_unit]:
            widget.setStyleSheet("""
                QComboBox {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        for widget in [self.edit_material_cost_price, self.edit_material_base_price,
                       self.edit_material_quantity, self.edit_material_min_stock]:
            widget.setStyleSheet("""
                QSpinBox, QDoubleSpinBox {
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-bottom: 15px;
                }
            """)

        layout.addWidget(QLabel("Material Name:"))
        layout.addWidget(self.edit_material_name)
        layout.addWidget(QLabel("Category:"))
        layout.addWidget(self.edit_material_category)
        layout.addWidget(QLabel("Supplier:"))
        layout.addWidget(self.edit_material_supplier)
        layout.addWidget(QLabel("Supplier Code:"))
        layout.addWidget(self.edit_material_supplier_code)
        layout.addWidget(QLabel("Unit:"))
        layout.addWidget(self.edit_material_unit)
        layout.addWidget(QLabel("Cost Price:"))
        layout.addWidget(self.edit_material_cost_price)
        layout.addWidget(QLabel("Base Sale Price:"))
        layout.addWidget(self.edit_material_base_price)
        layout.addWidget(QLabel("Quantity:"))
        layout.addWidget(self.edit_material_quantity)
        layout.addWidget(QLabel("Minimum Stock Level:"))
        layout.addWidget(self.edit_material_min_stock)
        layout.addWidget(QLabel("Location:"))
        layout.addWidget(self.edit_material_location)
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.edit_material_notes)
        layout.addWidget(update_btn)

        self.edit_material_dialog.setLayout(layout)
        self.edit_material_dialog.show()

    def update_material(self):
        material_id = self.edit_material_id
        name = self.edit_material_name.text()
        category = self.edit_material_category.currentText()
        supplier = self.edit_material_supplier.text()
        supplier_code = self.edit_material_supplier_code.text()
        unit = self.edit_material_unit.currentText()
        cost_price = self.edit_material_cost_price.value()
        base_price = self.edit_material_base_price.value()
        quantity = self.edit_material_quantity.value()
        min_stock = self.edit_material_min_stock.value()
        location = self.edit_material_location.text()
        notes = self.edit_material_notes.text()

        if not name or not supplier:
            QMessageBox.warning(self.edit_material_dialog, "Error", "Material name and supplier are required!")
            return

        if base_price < cost_price:
            confirm = QMessageBox.question(
                self.edit_material_dialog,
                "Confirm Price",
                "Sale price is lower than cost price. Are you sure?",
                QMessageBox.Yes | QMessageBox.No
            )
            if confirm == QMessageBox.No:
                return

        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                UPDATE materials 
                SET name=?, category=?, supplier=?, supplier_code=?, unit=?, 
                    cost_price=?, base_sale_price=?, quantity_in_stock=?, 
                    min_stock_level=?, location=?, notes=?, last_updated=?
                WHERE id=?
            ''', (
                name, category, supplier, supplier_code, unit,
                cost_price, base_price, quantity, min_stock,
                location, notes, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                material_id
            ))
            self.db_connection.commit()

            # Log the activity
            self._log_activity(self.user_id, "UPDATE", "materials", material_id, f"Updated material {name}")

            QMessageBox.information(self.edit_material_dialog, "Success", "Material updated successfully!")
            self.edit_material_dialog.close()
            self.load_materials()
            self.load_dashboard_data()  # Refresh dashboard counts
        except sqlite3.Error as e:
            QMessageBox.warning(self.edit_material_dialog, "Error", f"Database error: {str(e)}")

    def delete_material(self, row):
        material_id = int(self.materials_table.item(row, 0).text())
        material_name = self.materials_table.item(row, 1).text()

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete material '{material_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            cursor = self.db_connection.cursor()
            try:
                # Check if material is referenced in sales or warehouse transactions
                cursor.execute("SELECT COUNT(*) FROM sales WHERE material_id=?", (material_id,))
                sales_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM warehouse_transactions WHERE material_id=?", (material_id,))
                transactions_count = cursor.fetchone()[0]

                if sales_count > 0 or transactions_count > 0:
                    QMessageBox.warning(self, "Error",
                                       "Cannot delete material with existing sales or warehouse transactions!")
                    return

                cursor.execute("DELETE FROM materials WHERE id=?", (material_id,))
                cursor.execute("DELETE FROM project_pricing WHERE material_id=?", (material_id,))
                self.db_connection.commit()

                # Log the activity
                self._log_activity(self.user_id, "DELETE", "materials", material_id,
                                   f"Deleted material {material_name}")

                QMessageBox.information(self, "Success", "Material deleted successfully!")
                self.load_materials()
                self.load_dashboard_data()  # Refresh dashboard counts
            except sqlite3.Error as e:
                QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def init_warehouse(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Transaction type selector
        self.warehouse_transaction_type = QComboBox()
        self.warehouse_transaction_type.addItems(["IN - Receiving", "OUT - Issuance"])
        self.warehouse_transaction_type.currentIndexChanged.connect(self.update_warehouse_form)

        # Transaction form
        self.warehouse_form = QWidget()
        self.warehouse_form.setStyleSheet("""
            background-color: white;
            border-radius: 10px;
            padding: 20px;
        """)
        warehouse_form_layout = QVBoxLayout(self.warehouse_form)

        # Form fields will be populated by update_warehouse_form()
        self.warehouse_fields_layout = QVBoxLayout()
        warehouse_form_layout.addLayout(self.warehouse_fields_layout)

        record_btn = QPushButton("Record Transaction")
        record_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        record_btn.clicked.connect(self.record_warehouse_transaction)
        warehouse_form_layout.addWidget(record_btn)

        # Transactions table
        self.warehouse_table = QTableWidget()
        self.warehouse_table.setColumnCount(8)
        self.warehouse_table.setHorizontalHeaderLabels(
            ["ID", "Date", "Type", "Material", "Qty", "Unit Price", "Total", "Project"])
        self.warehouse_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.warehouse_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Date filter
        filter_layout = QHBoxLayout()

        self.warehouse_date_from = QDateEdit()
        self.warehouse_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.warehouse_date_from.setCalendarPopup(True)

        self.warehouse_date_to = QDateEdit()
        self.warehouse_date_to.setDate(QDate.currentDate())
        self.warehouse_date_to.setCalendarPopup(True)

        filter_btn = QPushButton("Filter")
        filter_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        filter_btn.clicked.connect(self.load_warehouse_transactions)

        filter_layout.addWidget(QLabel("From:"))
        filter_layout.addWidget(self.warehouse_date_from)
        filter_layout.addWidget(QLabel("To:"))
        filter_layout.addWidget(self.warehouse_date_to)
        filter_layout.addWidget(filter_btn)

        layout.addWidget(QLabel("Transaction Type:"))
        layout.addWidget(self.warehouse_transaction_type)
        layout.addWidget(self.warehouse_form)
        layout.addLayout(filter_layout)
        layout.addWidget(self.warehouse_table)

        self.warehouse_tab.setLayout(layout)

        # Initialize the form and load transactions
        self.update_warehouse_form()
        self.load_warehouse_transactions()

    def update_warehouse_form(self):
        # Clear existing fields
        while self.warehouse_fields_layout.count():
            child = self.warehouse_fields_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        transaction_type = self.warehouse_transaction_type.currentText()

        # Common fields
        self.warehouse_material = QComboBox()
        self.load_materials_for_warehouse()

        self.warehouse_quantity = QDoubleSpinBox()
        self.warehouse_quantity.setMinimum(0.01)
        self.warehouse_quantity.setMaximum(999999.99)
        self.warehouse_quantity.setValue(1.0)

        self.warehouse_unit_price = QDoubleSpinBox()
        self.warehouse_unit_price.setPrefix("$ ")
        self.warehouse_unit_price.setMinimum(0.01)
        self.warehouse_unit_price.setMaximum(999999.99)

        self.warehouse_project = QComboBox()
        self.load_projects_for_warehouse()

        self.warehouse_notes = QLineEdit()
        self.warehouse_notes.setPlaceholderText("Notes (optional)")

        # For IN transactions - supplier info
        if "IN" in transaction_type:
            self.warehouse_supplier = QLineEdit()
            self.warehouse_supplier.setPlaceholderText("Supplier (e.g., Dr.Fixit)")

            self.warehouse_delivery_ref = QLineEdit()
            self.warehouse_delivery_ref.setPlaceholderText("Delivery Reference (optional)")

        # Add fields to layout
        self.warehouse_fields_layout.addWidget(QLabel("Material:"))
        self.warehouse_fields_layout.addWidget(self.warehouse_material)
        self.warehouse_fields_layout.addWidget(QLabel("Quantity:"))
        self.warehouse_fields_layout.addWidget(self.warehouse_quantity)
        self.warehouse_fields_layout.addWidget(QLabel("Unit Price:"))
        self.warehouse_fields_layout.addWidget(self.warehouse_unit_price)
        self.warehouse_fields_layout.addWidget(QLabel("Project:"))
        self.warehouse_fields_layout.addWidget(self.warehouse_project)

        if "IN" in transaction_type:
            self.warehouse_fields_layout.addWidget(QLabel("Supplier:"))
            self.warehouse_fields_layout.addWidget(self.warehouse_supplier)
            self.warehouse_fields_layout.addWidget(QLabel("Delivery Reference:"))
            self.warehouse_fields_layout.addWidget(self.warehouse_delivery_ref)

        self.warehouse_fields_layout.addWidget(QLabel("Notes:"))
        self.warehouse_fields_layout.addWidget(self.warehouse_notes)

        # Connect material selection to update unit price
        self.warehouse_material.currentIndexChanged.connect(self.update_warehouse_unit_price)

    def load_materials_for_warehouse(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT id, name, unit, cost_price FROM materials ORDER BY name")
        materials = cursor.fetchall()

        self.warehouse_material.clear()
        self.warehouse_material_map = {}

        for material in materials:
            self.warehouse_material_map[material[0]] = (material[2], material[3])  # Store unit and cost_price
            self.warehouse_material.addItem(f"{material[1]} ({material[2]})", material[0])

    def load_projects_for_warehouse(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT id, name FROM projects WHERE status='Active' ORDER BY name")
        projects = cursor.fetchall()

        self.warehouse_project.clear()
        self.warehouse_project.addItem("N/A - General Inventory", None)

        for project in projects:
            self.warehouse_project.addItem(project[1], project[0])

    def update_warehouse_unit_price(self):
        material_id = self.warehouse_material.currentData()
        if material_id in self.warehouse_material_map:
            unit, cost_price = self.warehouse_material_map[material_id]
            self.warehouse_unit_price.setValue(cost_price)

    def record_warehouse_transaction(self):
        transaction_type = "IN" if "IN" in self.warehouse_transaction_type.currentText() else "OUT"
        material_id = self.warehouse_material.currentData()
        quantity = self.warehouse_quantity.value()
        unit_price = self.warehouse_unit_price.value()
        total_value = quantity * unit_price
        project_id = self.warehouse_project.currentData()
        notes = self.warehouse_notes.text()
        transaction_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "IN" in transaction_type:
            supplier = self.warehouse_supplier.text()
            delivery_ref = self.warehouse_delivery_ref.text()
            if supplier:
                notes = f"Supplier: {supplier}\nDelivery Ref: {delivery_ref}\n{notes}"
            else:
                QMessageBox.warning(self, "Error", "Supplier is required for receiving!")
                return

        if not material_id:
            QMessageBox.warning(self, "Error", "Please select a material!")
            return

        cursor = self.db_connection.cursor()
        try:
            # Record the transaction
            cursor.execute('''
                INSERT INTO warehouse_transactions (
                    material_id, transaction_type, quantity, unit_price, 
                    total_value, transaction_date, project_id, notes, recorded_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                material_id, transaction_type, quantity, unit_price,
                total_value, transaction_date, project_id, notes, self.user_id
            ))

            # Update material quantity
            if transaction_type == "IN":
                cursor.execute('''
                    UPDATE materials 
                    SET quantity_in_stock = quantity_in_stock + ?, 
                        last_updated = ?
                    WHERE id = ?
                ''', (quantity, transaction_date, material_id))
            else:  # OUT
                # Check stock availability
                cursor.execute("SELECT quantity_in_stock FROM materials WHERE id=?", (material_id,))
                current_stock = cursor.fetchone()[0]

                if quantity > current_stock:
                    QMessageBox.warning(self, "Error", f"Not enough stock! Only {current_stock} available.")
                    return

                cursor.execute('''
                    UPDATE materials 
                    SET quantity_in_stock = quantity_in_stock - ?, 
                        last_updated = ?
                    WHERE id = ?
                ''', (quantity, transaction_date, material_id))

            self.db_connection.commit()

            # Log the activity
            cursor.execute("SELECT name FROM materials WHERE id=?", (material_id,))
            material_name = cursor.fetchone()[0]
            self._log_activity(self.user_id, "CREATE", "warehouse_transactions",
                              cursor.lastrowid, f"Recorded {transaction_type} transaction for {material_name}")

            QMessageBox.information(self, "Success", "Transaction recorded successfully!")
            self.load_warehouse_transactions()
            self.load_materials()  # Refresh inventory
            self.load_dashboard_data()  # Refresh dashboard

            # Clear form
            self.warehouse_notes.clear()
            if "IN" in transaction_type:
                self.warehouse_supplier.clear()
                self.warehouse_delivery_ref.clear()

        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def load_warehouse_transactions(self):
        date_from = self.warehouse_date_from.date().toString("yyyy-MM-dd")
        date_to = self.warehouse_date_to.date().addDays(1).toString("yyyy-MM-dd")  # Include the end date

        cursor = self.db_connection.cursor()
        cursor.execute('''
            SELECT wt.id, wt.transaction_date, wt.transaction_type, 
                   m.name, wt.quantity, wt.unit_price, wt.total_value,
                   COALESCE(p.name, 'N/A')
            FROM warehouse_transactions wt
            JOIN materials m ON wt.material_id = m.id
            LEFT JOIN projects p ON wt.project_id = p.id
            WHERE wt.transaction_date BETWEEN ? AND ?
            ORDER BY wt.transaction_date DESC
        ''', (date_from, date_to))
        transactions = cursor.fetchall()

        self.warehouse_table.setRowCount(len(transactions))
        for row_idx, row_data in enumerate(transactions):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.warehouse_table.setItem(row_idx, col_idx, item)

                # Format prices as currency
                if col_idx in [5, 6]:  # unit_price and total_value columns
                    item.setText(f"${float(col_data):,.2f}")

                # Color code transaction types
                if col_idx == 2:  # transaction_type column
                    if col_data == "IN":
                        item.setForeground(Qt.darkGreen)
                    else:
                        item.setForeground(Qt.darkRed)

    def init_sales(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Sale form
        form_layout = QVBoxLayout()
        form_layout.setSpacing(10)

        # Project selection
        self.sale_project = QComboBox()
        self.load_projects_for_sale()

        # Material selection and pricing
        material_layout = QHBoxLayout()
        self.sale_material = QComboBox()
        self.load_materials_for_sale()

        self.sale_base_price = QDoubleSpinBox()
        self.sale_base_price.setPrefix("$ ")
        self.sale_base_price.setMaximum(99999.99)
        self.sale_base_price.setReadOnly(True)

        self.sale_project_price = QDoubleSpinBox()
        self.sale_project_price.setPrefix("$ ")
        self.sale_project_price.setMaximum(99999.99)
        self.sale_project_price.setReadOnly(True)

        material_layout.addWidget(QLabel("Material:"))
        material_layout.addWidget(self.sale_material)
        material_layout.addWidget(QLabel("Base Price:"))
        material_layout.addWidget(self.sale_base_price)
        material_layout.addWidget(QLabel("Project Price:"))
        material_layout.addWidget(self.sale_project_price)

        # Quantity and total
        quantity_layout = QHBoxLayout()
        self.sale_quantity = QDoubleSpinBox()
        self.sale_quantity.setMinimum(0.01)
        self.sale_quantity.setMaximum(999999.99)
        self.sale_quantity.setValue(1.0)

        self.sale_total = QDoubleSpinBox()
        self.sale_total.setPrefix("$ ")
        self.sale_total.setMaximum(9999999.99)
        self.sale_total.setReadOnly(True)

        quantity_layout.addWidget(QLabel("Quantity:"))
        quantity_layout.addWidget(self.sale_quantity)
        quantity_layout.addWidget(QLabel("Total:"))
        quantity_layout.addWidget(self.sale_total)

        self.sale_notes = QLineEdit()
        self.sale_notes.setPlaceholderText("Notes (optional)")

        record_sale_btn = QPushButton("Record Sale")
        record_sale_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        record_sale_btn.clicked.connect(self.record_sale)

        form_layout.addWidget(QLabel("Project:"))
        form_layout.addWidget(self.sale_project)
        form_layout.addLayout(material_layout)
        form_layout.addLayout(quantity_layout)
        form_layout.addWidget(QLabel("Notes:"))
        form_layout.addWidget(self.sale_notes)
        form_layout.addWidget(record_sale_btn)

        # Sales table
        self.sales_table = QTableWidget()
        self.sales_table.setColumnCount(8)
        self.sales_table.setHorizontalHeaderLabels(
            ["ID", "Date", "Project", "Material", "Qty", "Unit Price", "Total", "Seller"])
        self.sales_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.sales_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Date filter
        filter_layout = QHBoxLayout()

        self.sales_date_from = QDateEdit()
        self.sales_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.sales_date_from.setCalendarPopup(True)

        self.sales_date_to = QDateEdit()
        self.sales_date_to.setDate(QDate.currentDate())
        self.sales_date_to.setCalendarPopup(True)

        filter_btn = QPushButton("Filter")
        filter_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        filter_btn.clicked.connect(self.load_sales)

        filter_layout.addWidget(QLabel("From:"))
        filter_layout.addWidget(self.sales_date_from)
        filter_layout.addWidget(QLabel("To:"))
        filter_layout.addWidget(self.sales_date_to)
        filter_layout.addWidget(filter_btn)

        layout.addLayout(form_layout)
        layout.addLayout(filter_layout)
        layout.addWidget(self.sales_table)

        self.sales_tab.setLayout(layout)

        # Connect signals for dynamic updates
        self.sale_project.currentIndexChanged.connect(self.update_sale_materials)
        self.sale_material.currentIndexChanged.connect(self.update_sale_prices)
        self.sale_quantity.valueChanged.connect(self.update_sale_total)

        # Load initial sales data
        self.load_sales()

    def load_projects_for_sale(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT id, name FROM projects WHERE status='Active' ORDER BY name")
        projects = cursor.fetchall()

        self.sale_project.clear()
        for project in projects:
            self.sale_project.addItem(project[1], project[0])

    def load_materials_for_sale(self):
        # This will be populated based on project selection
        self.sale_material.clear()

    def update_sale_materials(self):
        project_id = self.sale_project.currentData()
        if not project_id:
            return

        cursor = self.db_connection.cursor()

        # Get materials with project-specific pricing or base pricing
        cursor.execute('''
            SELECT m.id, m.name, m.unit, 
                   COALESCE(pp.sale_price, m.base_sale_price) as sale_price,
                   m.quantity_in_stock
            FROM materials m
            LEFT JOIN project_pricing pp ON m.id = pp.material_id AND pp.project_id = ?
            WHERE m.quantity_in_stock > 0
            ORDER BY m.name
        ''', (project_id,))

        materials = cursor.fetchall()

        self.sale_material.clear()
        self.sale_material_map = {}

        for material in materials:
            self.sale_material_map[material[0]] = (material[2], material[3], material[4])  # unit, sale_price, quantity
            self.sale_material.addItem(f"{material[1]} ({material[2]})", material[0])

    def update_sale_prices(self):
        material_id = self.sale_material.currentData()
        project_id = self.sale_project.currentData()

        if material_id in self.sale_material_map:
            unit, sale_price, quantity = self.sale_material_map[material_id]

            # Get base price
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT base_sale_price FROM materials WHERE id=?", (material_id,))
            base_price = cursor.fetchone()[0]

            self.sale_base_price.setValue(base_price)
            self.sale_project_price.setValue(sale_price)

            # Update total based on current quantity
            self.update_sale_total()

    def update_sale_total(self):
        material_id = self.sale_material.currentData()
        if material_id in self.sale_material_map:
            unit, sale_price, quantity = self.sale_material_map[material_id]
            total = self.sale_quantity.value() * sale_price
            self.sale_total.setValue(total)

    def record_sale(self):
        project_id = self.sale_project.currentData()
        material_id = self.sale_material.currentData()
        quantity = self.sale_quantity.value()
        unit_price = self.sale_project_price.value()
        total_price = self.sale_total.value()
        notes = self.sale_notes.text()
        sale_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not project_id or not material_id:
            QMessageBox.warning(self, "Error", "Project and material are required!")
            return

        # Check stock availability
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT quantity_in_stock FROM materials WHERE id=?", (material_id,))
        current_stock = cursor.fetchone()[0]

        if quantity > current_stock:
            QMessageBox.warning(self, "Error", f"Not enough stock! Only {current_stock} available.")
            return

        try:
            # Record the sale
            cursor.execute('''
                INSERT INTO sales (
                    project_id, material_id, quantity, unit_price, 
                    total_price, sale_date, seller_id, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                project_id, material_id, quantity, unit_price,
                total_price, sale_date, self.user_id, notes
            ))

            # Update material quantity
            cursor.execute('''
                UPDATE materials 
                SET quantity_in_stock = quantity_in_stock - ?, 
                    last_updated = ?
                WHERE id = ?
            ''', (quantity, sale_date, material_id))

            self.db_connection.commit()

            # Log the activity
            cursor.execute("SELECT name FROM materials WHERE id=?", (material_id,))
            material_name = cursor.fetchone()[0]
            cursor.execute("SELECT name FROM projects WHERE id=?", (project_id,))
            project_name = cursor.fetchone()[0]
            self._log_activity(self.user_id, "CREATE", "sales",
                              cursor.lastrowid, f"Recorded sale of {material_name} for project {project_name}")

            QMessageBox.information(self, "Success", "Sale recorded successfully!")
            self.load_sales()
            self.load_materials()  # Refresh inventory
            self.load_dashboard_data()  # Refresh dashboard

            # Clear form
            self.sale_quantity.setValue(1.0)
            self.sale_notes.clear()
            self.update_sale_materials()  # Refresh material list

        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def load_sales(self):
        date_from = self.sales_date_from.date().toString("yyyy-MM-dd")
        date_to = self.sales_date_to.date().addDays(1).toString("yyyy-MM-dd")  # Include the end date

        cursor = self.db_connection.cursor()
        cursor.execute('''
            SELECT s.id, s.sale_date, p.name, m.name, s.quantity, 
                   s.unit_price, s.total_price, u.full_name
            FROM sales s
            JOIN projects p ON s.project_id = p.id
            JOIN materials m ON s.material_id = m.id
            JOIN users u ON s.seller_id = u.id
            WHERE s.sale_date BETWEEN ? AND ?
            ORDER BY s.sale_date DESC
        ''', (date_from, date_to))
        sales = cursor.fetchall()

        self.sales_table.setRowCount(len(sales))
        for row_idx, row_data in enumerate(sales):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.sales_table.setItem(row_idx, col_idx, item)

                # Format prices as currency
                if col_idx in [5, 6]:  # unit_price and total_price columns
                    item.setText(f"${float(col_data):,.2f}")

    def init_expenses(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Expense form
        form_layout = QVBoxLayout()
        form_layout.setSpacing(10)

        self.expense_project = QComboBox()
        self.load_projects_for_expense()

        self.expense_description = QLineEdit()
        self.expense_description.setPlaceholderText("Description")

        self.expense_amount = QDoubleSpinBox()
        self.expense_amount.setPrefix("$ ")
        self.expense_amount.setMaximum(999999.99)

        self.expense_category = QComboBox()
        self.expense_category.addItems([
            "Labor", "Equipment", "Materials", "Subcontractor",
            "Permits", "Utilities", "Transport", "Other"
        ])

        self.expense_receipt = QLineEdit()
        self.expense_receipt.setPlaceholderText("Receipt Number (optional)")

        self.expense_notes = QLineEdit()
        self.expense_notes.setPlaceholderText("Notes (optional)")

        record_expense_btn = QPushButton("Record Expense")
        record_expense_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        record_expense_btn.clicked.connect(self.record_expense)

        form_layout.addWidget(QLabel("Project:"))
        form_layout.addWidget(self.expense_project)
        form_layout.addWidget(QLabel("Description:"))
        form_layout.addWidget(self.expense_description)
        form_layout.addWidget(QLabel("Amount:"))
        form_layout.addWidget(self.expense_amount)
        form_layout.addWidget(QLabel("Category:"))
        form_layout.addWidget(self.expense_category)
        form_layout.addWidget(QLabel("Receipt Number:"))
        form_layout.addWidget(self.expense_receipt)
        form_layout.addWidget(QLabel("Notes:"))
        form_layout.addWidget(self.expense_notes)
        form_layout.addWidget(record_expense_btn)

        # Expenses table
        self.expenses_table = QTableWidget()
        self.expenses_table.setColumnCount(7)
        self.expenses_table.setHorizontalHeaderLabels(
            ["ID", "Date", "Project", "Description", "Amount", "Category", "Receipt"])
        self.expenses_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.expenses_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Date filter
        filter_layout = QHBoxLayout()

        self.expenses_date_from = QDateEdit()
        self.expenses_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.expenses_date_from.setCalendarPopup(True)

        self.expenses_date_to = QDateEdit()
        self.expenses_date_to.setDate(QDate.currentDate())
        self.expenses_date_to.setCalendarPopup(True)

        filter_btn = QPushButton("Filter")
        filter_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        filter_btn.clicked.connect(self.load_expenses)

        filter_layout.addWidget(QLabel("From:"))
        filter_layout.addWidget(self.expenses_date_from)
        filter_layout.addWidget(QLabel("To:"))
        filter_layout.addWidget(self.expenses_date_to)
        filter_layout.addWidget(filter_btn)

        layout.addLayout(form_layout)
        layout.addLayout(filter_layout)
        layout.addWidget(self.expenses_table)

        self.expenses_tab.setLayout(layout)

        # Load initial expenses data
        self.load_expenses()

    def load_projects_for_expense(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT id, name FROM projects ORDER BY name")
        projects = cursor.fetchall()

        self.expense_project.clear()
        self.expense_project.addItem("N/A - General Expense", None)

        for project in projects:
            self.expense_project.addItem(project[1], project[0])

    def record_expense(self):
        project_id = self.expense_project.currentData()
        description = self.expense_description.text()
        amount = self.expense_amount.value()
        category = self.expense_category.currentText()
        receipt = self.expense_receipt.text()
        notes = self.expense_notes.text()
        expense_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not description:
            QMessageBox.warning(self, "Error", "Description is required!")
            return

        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO expenses (
                    description, amount, expense_date, category, 
                    project_id, recorded_by, receipt_number, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                description, amount, expense_date, category,
                project_id, self.user_id, receipt, notes
            ))
            self.db_connection.commit()

            # Log the activity
            project_name = "General" if project_id is None else self.expense_project.currentText()
            self._log_activity(self.user_id, "CREATE", "expenses",
                              cursor.lastrowid, f"Recorded expense for {project_name}: {description}")

            QMessageBox.information(self, "Success", "Expense recorded successfully!")
            self.load_expenses()
            self.load_dashboard_data()

            # Clear form
            self.expense_description.clear()
            self.expense_amount.setValue(0)
            self.expense_receipt.clear()
            self.expense_notes.clear()

        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def load_expenses(self):
        date_from = self.expenses_date_from.date().toString("yyyy-MM-dd")
        date_to = self.expenses_date_to.date().addDays(1).toString("yyyy-MM-dd")  # Include the end date

        cursor = self.db_connection.cursor()
        cursor.execute('''
            SELECT e.id, e.expense_date, COALESCE(p.name, 'N/A'), 
                   e.description, e.amount, e.category, e.receipt_number
            FROM expenses e
            LEFT JOIN projects p ON e.project_id = p.id
            WHERE e.expense_date BETWEEN ? AND ?
            ORDER BY e.expense_date DESC
        ''', (date_from, date_to))
        expenses = cursor.fetchall()

        self.expenses_table.setRowCount(len(expenses))
        for row_idx, row_data in enumerate(expenses):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.expenses_table.setItem(row_idx, col_idx, item)

                # Format amount as currency
                if col_idx == 4:  # amount column
                    item.setText(f"${float(col_data):,.2f}")

    def init_reports(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Report type selection
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Inventory Status",
            "Sales Summary",
            "Project Financials",
            "Expense Analysis",
            "Low Stock Report",
            "Warehouse Activity"
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

        generate_btn = QPushButton("Generate Report")
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 10px 15px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        generate_btn.clicked.connect(self.generate_report)

        date_layout.addWidget(QLabel("From:"))
        date_layout.addWidget(self.report_date_from)
        date_layout.addWidget(QLabel("To:"))
        date_layout.addWidget(self.report_date_to)
        date_layout.addWidget(generate_btn)

        # Project filter (for some reports)
        self.report_project = QComboBox()
        self.load_projects_for_report()
        self.report_project.setVisible(False)  # Only show for certain reports

        # Summary labels
        self.report_summary = QLabel()
        self.report_summary.setFont(QFont('Arial', 12))
        self.report_summary.setStyleSheet("background-color: white; padding: 10px; border-radius: 5px;")

        # Report table
        self.report_table = QTableWidget()
        self.report_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.report_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Export button
        export_btn = QPushButton("Export to CSV")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                padding: 10px 15px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        export_btn.clicked.connect(self.export_report)

        layout.addWidget(QLabel("Report Type:"))
        layout.addWidget(self.report_type)
        layout.addLayout(date_layout)
        layout.addWidget(self.report_project)
        layout.addWidget(self.report_summary)
        layout.addWidget(self.report_table)
        layout.addWidget(export_btn)

        self.reports_tab.setLayout(layout)

        # Generate initial report
        self.generate_report()

    def load_projects_for_report(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT id, name FROM projects ORDER BY name")
        projects = cursor.fetchall()

        self.report_project.clear()
        self.report_project.addItem("All Projects", None)

        for project in projects:
            self.report_project.addItem(project[1], project[0])

    def generate_report(self):
        report_type = self.report_type.currentText()
        date_from = self.report_date_from.date().toString("yyyy-MM-dd")
        date_to = self.report_date_to.date().addDays(1).toString("yyyy-MM-dd")  # Include the end date
        project_id = self.report_project.currentData() if self.report_project.isVisible() else None

        cursor = self.db_connection.cursor()

        # Show/hide project filter based on report type
        self.report_project.setVisible(report_type in ["Project Financials", "Sales Summary"])

        if report_type == "Inventory Status":
            cursor.execute('''
                SELECT id, name, category, supplier, quantity_in_stock, 
                       min_stock_level, unit, cost_price, base_sale_price
                FROM materials
                ORDER BY (quantity_in_stock / min_stock_level) ASC
            ''')

            inventory_data = cursor.fetchall()

            self.report_table.setColumnCount(9)
            self.report_table.setHorizontalHeaderLabels([
                "ID", "Name", "Category", "Supplier", "In Stock",
                "Min Stock", "Unit", "Cost", "Sale Price"
            ])
            self.report_table.setRowCount(len(inventory_data))

            total_value = 0
            low_stock_count = 0
            critical_count = 0

            for row_idx, row_data in enumerate(inventory_data):
                for col_idx, col_data in enumerate(row_data):
                    item = QTableWidgetItem(str(col_data))
                    self.report_table.setItem(row_idx, col_idx, item)

                    # Format prices as currency
                    if col_idx in [7, 8]:  # cost_price and base_sale_price columns
                        item.setText(f"${float(col_data):,.2f}")

                    # Calculate inventory value
                    if col_idx == 4 and col_idx == 7:  # quantity and cost_price
                        total_value += row_data[4] * row_data[7]

                    # Highlight stock levels
                    if col_idx == 4:  # quantity_in_stock column
                        min_stock = row_data[5]
                        if row_data[4] <= min_stock:
                            low_stock_count += 1
                            if row_data[4] <= min_stock * 0.5:  # Critical low stock
                                critical_count += 1
                                item.setBackground(Qt.red)
                                item.setForeground(Qt.white)
                            else:
                                item.setBackground(Qt.yellow)

            self.report_summary.setText(
                f"Total Inventory Value: ${total_value:,.2f} | "
                f"Low Stock Items: {low_stock_count} | "
                f"Critical Items: {critical_count}"
            )

        elif report_type == "Sales Summary":
            query = '''
                SELECT s.id, s.sale_date, p.name, m.name, s.quantity, 
                       s.unit_price, s.total_price, u.full_name
                FROM sales s
                JOIN projects p ON s.project_id = p.id
                JOIN materials m ON s.material_id = m.id
                JOIN users u ON s.seller_id = u.id
                WHERE s.sale_date BETWEEN ? AND ?
                {project_filter}
                ORDER BY s.sale_date DESC
            '''.format(
                project_filter="AND s.project_id=?" if project_id else ""
            )

            params = [date_from, date_to]
            if project_id:
                params.append(project_id)

            cursor.execute(query, params)
            sales_data = cursor.fetchall()

            self.report_table.setColumnCount(8)
            self.report_table.setHorizontalHeaderLabels([
                "ID", "Date", "Project", "Material", "Qty",
                "Unit Price", "Total", "Seller"
            ])
            self.report_table.setRowCount(len(sales_data))

            total_sales = 0
            for row_idx, row_data in enumerate(sales_data):
                for col_idx, col_data in enumerate(row_data):
                    item = QTableWidgetItem(str(col_data))
                    self.report_table.setItem(row_idx, col_idx, item)

                    # Format prices as currency
                    if col_idx in [5, 6]:  # unit_price and total_price columns
                        item.setText(f"${float(col_data):,.2f}")
                        if col_idx == 6:
                            total_sales += float(col_data)

            # Get sales by category if no project filter
            category_sales = ""
            if not project_id:
                cursor.execute('''
                    SELECT m.category, SUM(s.total_price)
                    FROM sales s
                    JOIN materials m ON s.material_id = m.id
                    WHERE s.sale_date BETWEEN ? AND ?
                    GROUP BY m.category
                    ORDER BY SUM(s.total_price) DESC
                ''', (date_from, date_to))

                category_data = cursor.fetchall()
                category_sales = " | Category Breakdown: " + ", ".join(
                    f"{cat[0]}: ${cat[1]:,.2f}" for cat in category_data
                )

            self.report_summary.setText(
                f"Total Sales: ${total_sales:,.2f} | "
                f"Transactions: {len(sales_data)}"
                f"{category_sales}"
            )

        elif report_type == "Project Financials":
            if project_id:
                # Detailed report for a specific project
                cursor.execute('''
                    SELECT p.name, p.client, p.start_date, p.end_date, p.status, p.budget
                    FROM projects p
                    WHERE p.id = ?
                ''', (project_id,))
                project_info = cursor.fetchone()

                # Get project sales
                cursor.execute('''
                    SELECT SUM(s.total_price)
                    FROM sales s
                    WHERE s.project_id = ? AND s.sale_date BETWEEN ? AND ?
                ''', (project_id, date_from, date_to))
                project_sales = cursor.fetchone()[0] or 0

                # Get project expenses
                cursor.execute('''
                    SELECT SUM(e.amount)
                    FROM expenses e
                    WHERE e.project_id = ? AND e.expense_date BETWEEN ? AND ?
                ''', (project_id, date_from, date_to))
                project_expenses = cursor.fetchone()[0] or 0

                # Get material usage
                cursor.execute('''
                    SELECT m.name, SUM(wt.quantity), m.unit, SUM(wt.total_value)
                    FROM warehouse_transactions wt
                    JOIN materials m ON wt.material_id = m.id
                    WHERE wt.project_id = ? AND wt.transaction_type = 'OUT' 
                    AND wt.transaction_date BETWEEN ? AND ?
                    GROUP BY m.name, m.unit
                    ORDER BY SUM(wt.total_value) DESC
                ''', (project_id, date_from, date_to))
                material_usage = cursor.fetchall()

                # Create summary table
                self.report_table.setColumnCount(2)
                self.report_table.setHorizontalHeaderLabels(["Category", "Amount"])
                self.report_table.setRowCount(6 + len(material_usage))

                # Project info
                self.report_table.setItem(0, 0, QTableWidgetItem("Project Name"))
                self.report_table.setItem(0, 1, QTableWidgetItem(project_info[0]))
                self.report_table.setItem(1, 0, QTableWidgetItem("Client"))
                self.report_table.setItem(1, 1, QTableWidgetItem(project_info[1]))
                self.report_table.setItem(2, 0, QTableWidgetItem("Status"))
                self.report_table.setItem(2, 1, QTableWidgetItem(project_info[4]))
                self.report_table.setItem(3, 0, QTableWidgetItem("Budget"))
                self.report_table.setItem(3, 1, QTableWidgetItem(
                    f"${float(project_info[5]):,.2f}" if project_info[5] else "$0.00"))

                # Financial summary
                self.report_table.setItem(4, 0, QTableWidgetItem("Total Sales"))
                self.report_table.setItem(4, 1, QTableWidgetItem(f"${project_sales:,.2f}"))
                self.report_table.setItem(5, 0, QTableWidgetItem("Total Expenses"))
                self.report_table.setItem(5, 1, QTableWidgetItem(f"${project_expenses:,.2f}"))
                self.report_table.setItem(6, 0, QTableWidgetItem("Net Profit"))
                net_profit = project_sales - project_expenses
                net_item = QTableWidgetItem(f"${net_profit:,.2f}")
                self.report_table.setItem(6, 1, net_item)
                if net_profit >= 0:
                    net_item.setForeground(Qt.darkGreen)
                else:
                    net_item.setForeground(Qt.red)

                # Material usage
                for i, (name, qty, unit, value) in enumerate(material_usage):
                    self.report_table.setItem(7 + i, 0, QTableWidgetItem(f"Material Used: {name}"))
                    self.report_table.setItem(7 + i, 1, QTableWidgetItem(f"{qty} {unit} (${value:,.2f})"))

                self.report_summary.setText(
                    f"Project: {project_info[0]} | "
                    f"Period: {date_from} to {self.report_date_to.date().toString('yyyy-MM-dd')}"
                )
            else:
                # Summary for all projects
                cursor.execute('''
                    SELECT p.id, p.name, p.status, p.budget,
                           COALESCE(SUM(s.total_price), 0) as sales,
                           COALESCE(SUM(e.amount), 0) as expenses
                    FROM projects p
                    LEFT JOIN sales s ON p.id = s.project_id 
                        AND s.sale_date BETWEEN ? AND ?
                    LEFT JOIN expenses e ON p.id = e.project_id 
                        AND e.expense_date BETWEEN ? AND ?
                    GROUP BY p.id, p.name, p.status, p.budget
                    ORDER BY p.status, p.name
                ''', (date_from, date_to, date_from, date_to))

                projects_data = cursor.fetchall()

                self.report_table.setColumnCount(7)
                self.report_table.setHorizontalHeaderLabels([
                    "ID", "Project", "Status", "Budget", "Sales",
                    "Expenses", "Profit"
                ])
                self.report_table.setRowCount(len(projects_data))

                total_budget = 0
                total_sales = 0
                total_expenses = 0

                for row_idx, row_data in enumerate(projects_data):
                    for col_idx, col_data in enumerate(row_data[:6]):  # Exclude calculated profit
                        item = QTableWidgetItem(str(col_data))
                        self.report_table.setItem(row_idx, col_idx, item)

                        # Format currency values
                        if col_idx in [3, 4, 5]:  # budget, sales, expenses columns
                            item.setText(f"${float(col_data):,.2f}")
                            if col_idx == 3:
                                total_budget += float(col_data)
                            elif col_idx == 4:
                                total_sales += float(col_data)
                            elif col_idx == 5:
                                total_expenses += float(col_data)

                        # Color code status
                        if col_idx == 2:  # status column
                            if col_data == "Active":
                                item.setForeground(Qt.darkGreen)
                            elif col_data == "Completed":
                                item.setForeground(Qt.darkBlue)
                            elif col_data == "On Hold":
                                item.setForeground(Qt.darkYellow)
                            elif col_data == "Cancelled":
                                item.setForeground(Qt.red)

                    # Calculate and display profit
                    profit = row_data[4] - row_data[5]
                    profit_item = QTableWidgetItem(f"${profit:,.2f}")
                    self.report_table.setItem(row_idx, 6, profit_item)
                    if profit >= 0:
                        profit_item.setForeground(Qt.darkGreen)
                    else:
                        profit_item.setForeground(Qt.red)

                total_profit = total_sales - total_expenses
                self.report_summary.setText(
                    f"Total Budget: ${total_budget:,.2f} | "
                    f"Total Sales: ${total_sales:,.2f} | "
                    f"Total Expenses: ${total_expenses:,.2f} | "
                    f"Total Profit: ${total_profit:,.2f}"
                )

    def export_report(self):
        from PyQt5.QtWidgets import QFileDialog
        import csv

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "", "CSV Files (*.csv)"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                header = []
                for col in range(self.report_table.columnCount()):
                    header.append(self.report_table.horizontalHeaderItem(col).text())
                writer.writerow(header)

                # Write data
                for row in range(self.report_table.rowCount()):
                    row_data = []
                    for col in range(self.report_table.columnCount()):
                        item = self.report_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)

            QMessageBox.information(self, "Success", "Report exported successfully!")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to export report: {str(e)}")

    def init_users(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Add user form
        form_layout = QHBoxLayout()

        self.new_username = QLineEdit()
        self.new_username.setPlaceholderText("Username")
        self.new_username.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        """)

        self.new_password = QLineEdit()
        self.new_password.setPlaceholderText("Password")
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        """)

        self.new_fullname = QLineEdit()
        self.new_fullname.setPlaceholderText("Full Name")
        self.new_fullname.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        """)

        self.new_role = QComboBox()
        self.new_role.addItems(["Admin", "Manager", "Warehouse", "Sales"])
        self.new_role.setStyleSheet("""
            QComboBox {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
        """)

        add_user_btn = QPushButton("Add User")
        add_user_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                padding: 10px 15px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        add_user_btn.clicked.connect(self.add_user)

        form_layout.addWidget(self.new_username)
        form_layout.addWidget(self.new_password)
        form_layout.addWidget(self.new_fullname)
        form_layout.addWidget(self.new_role)
        form_layout.addWidget(add_user_btn)

        # Users table
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(6)
        self.users_table.setHorizontalHeaderLabels(["ID", "Username", "Full Name", "Role", "Last Login", "Actions"])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.users_table.setEditTriggers(QTableWidget.NoEditTriggers)

        layout.addLayout(form_layout)
        layout.addWidget(self.users_table)

        self.users_tab.setLayout(layout)

        # Load users
        self.load_users()

    def load_users(self):
        cursor = self.db_connection.cursor()
        cursor.execute("""
            SELECT id, username, full_name, role, last_login 
            FROM users 
            ORDER BY role, username
        """)
        users = cursor.fetchall()

        self.users_table.setRowCount(len(users))
        for row_idx, row_data in enumerate(users):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data) if col_data is not None else "Never")
                self.users_table.setItem(row_idx, col_idx, item)

                # Color code roles
                if col_idx == 3:  # role column
                    if col_data == "Admin":
                        item.setForeground(Qt.darkRed)
                    elif col_data == "Manager":
                        item.setForeground(Qt.darkBlue)
                    elif col_data == "Warehouse":
                        item.setForeground(Qt.darkGreen)

            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)

            reset_btn = QPushButton("Reset Password")
            reset_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
            reset_btn.clicked.connect(lambda _, row=row_idx: self.reset_password(row))

            delete_btn = QPushButton("Delete")
            delete_btn.setStyleSheet("""
                QPushButton {
                    background-color: #e74c3c;
                    color: white;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #c0392b;
                }
            """)
            delete_btn.clicked.connect(lambda _, row=row_idx: self.delete_user(row))

            actions_layout.addWidget(reset_btn)
            actions_layout.addWidget(delete_btn)
            actions_widget.setLayout(actions_layout)

            self.users_table.setCellWidget(row_idx, 5, actions_widget)

            # Disable delete for current user and admin
            if row_data[0] == self.user_id or row_data[3] == "Admin":
                delete_btn.setEnabled(False)

    def add_user(self):
        username = self.new_username.text()
        password = self.new_password.text()
        full_name = self.new_fullname.text()
        role = self.new_role.currentText()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password are required!")
            return

        if len(password) < 8:
            QMessageBox.warning(self, "Error", "Password must be at least 8 characters long!")
            return

        # Generate salt and hash password
        salt = os.urandom(32).hex()
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()

        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password, salt, role, full_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hashed_password, salt, role, full_name))
            self.db_connection.commit()

            # Log the activity
            self._log_activity(self.user_id, "CREATE", "users", cursor.lastrowid, f"Added user {username}")

            QMessageBox.information(self, "Success", "User added successfully!")
            self.new_username.clear()
            self.new_password.clear()
            self.new_fullname.clear()
            self.load_users()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Error", "Username already exists!")
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def reset_password(self, row):
        user_id = int(self.users_table.item(row, 0).text())
        username = self.users_table.item(row, 1).text()

        if user_id == self.user_id:
            QMessageBox.warning(self, "Error",
                               "You cannot reset your own password here. Use the login screen's forgot password feature.")
            return

        new_password, ok = QInputDialog.getText(
            self,
            "Reset Password",
            f"Enter new password for {username}:",
            QLineEdit.Password
        )

        if ok and new_password:
            if len(new_password) < 8:
                QMessageBox.warning(self, "Error", "Password must be at least 8 characters long!")
                return

            # Generate new salt and hash password
            salt = os.urandom(32).hex()
            hashed_password = hashlib.pbkdf2_hmac('sha256', new_password.encode(), bytes.fromhex(salt), 100000).hex()

            cursor = self.db_connection.cursor()
            try:
                cursor.execute('''
                    UPDATE users 
                    SET password=?, salt=?, failed_attempts=0, account_locked=0 
                    WHERE id=?
                ''', (hashed_password, salt, user_id))
                self.db_connection.commit()

                # Log the activity
                self._log_activity(self.user_id, "UPDATE", "users", user_id, f"Reset password for {username}")

                QMessageBox.information(self, "Success", "Password reset successfully!")
            except sqlite3.Error as e:
                QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def delete_user(self, row):
        user_id = int(self.users_table.item(row, 0).text())
        username = self.users_table.item(row, 1).text()
        role = self.users_table.item(row, 3).text()

        if user_id == self.user_id:
            QMessageBox.warning(self, "Error", "You cannot delete your own account!")
            return

        if role == "Admin":
            QMessageBox.warning(self, "Error", "Admin users cannot be deleted!")
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete user {username}?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            cursor = self.db_connection.cursor()
            try:
                cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
                self.db_connection.commit()

                # Log the activity
                self._log_activity(self.user_id, "DELETE", "users", user_id, f"Deleted user {username}")

                QMessageBox.information(self, "Success", "User deleted successfully!")
                self.load_users()
            except sqlite3.Error as e:
                QMessageBox.warning(self, "Error", f"Database error: {str(e)}")

    def _log_activity(self, user_id, action, table=None, record_id=None, description=None):
        """Log user activity for security auditing"""
        cursor = self.db_connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO audit_log (user_id, action, table_affected, record_id, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action, table, record_id, description))
            self.db_connection.commit()
        except sqlite3.Error as e:
            print(f"Error logging activity: {e}")
            self.db_connection.rollback()

    def closeEvent(self, event):
        # Confirm before closing
        confirm = QMessageBox.question(
            self,
            "Confirm Exit",
            "Are you sure you want to exit the application?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            self.db_connection.close()
            event.accept()
        else:
            event.ignore()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle('Fusion')

    palette = app.palette()
    palette.setColor(palette.Window, QColor(245, 245, 245))
    palette.setColor(palette.WindowText, Qt.black)
    palette.setColor(palette.Base, QColor(255, 255, 255))
    palette.setColor(palette.AlternateBase, QColor(240, 240, 240))
    palette.setColor(palette.ToolTipBase, Qt.white)
    palette.setColor(palette.ToolTipText, Qt.black)
    palette.setColor(palette.Text, Qt.black)
    palette.setColor(palette.Button, QColor(240, 240, 240))
    palette.setColor(palette.ButtonText, Qt.black)
    palette.setColor(palette.BrightText, Qt.red)
    palette.setColor(palette.Highlight, QColor(243, 156, 18))
    palette.setColor(palette.HighlightedText, Qt.white)
    app.setPalette(palette)

    login = LoginWindow()
    login.show()

    sys.exit(app.exec_())