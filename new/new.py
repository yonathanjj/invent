import uuid
import sys
import sqlite3
import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QDateEdit, QMessageBox, QStackedWidget, QFormLayout, QDoubleSpinBox,
    QSpinBox, QTextEdit, QGroupBox, QScrollArea, QTabWidget, QHeaderView,
    QDialog, QFileDialog
)
from PyQt5.QtCore import Qt, QDate, QSize
from PyQt5.QtGui import QFont, QColor, QPixmap, QIcon


AUTHORIZED_DEVICE_ID = '0x54e1ad90c41e'

def get_device_id():
    return hex(uuid.getnode())

if get_device_id() != AUTHORIZED_DEVICE_ID:
    print("Unauthorized device.")
    sys.exit()


# Constants
DATABASE_NAME = 'construction_inventory.db'
PBKDF2_ITERATIONS = 100000

# Color Scheme
PRIMARY_COLOR = "#2c3691"
SECONDARY_COLOR = "#fbc210"
BACKGROUND_COLOR = "#f5f5f5"
TEXT_COLOR = "#333333"
ERROR_COLOR = "#d9534f"


class DatabaseManager:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.initialize_database()

    def initialize_database(self):
        """Initialize the database with all required tables"""
        try:
            self.conn = sqlite3.connect(DATABASE_NAME)
            self.cursor = self.conn.cursor()

            # Create tables if they don't exist
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_locked INTEGER DEFAULT 0,
                    failed_attempts INTEGER DEFAULT 0,
                    last_login TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    client TEXT NOT NULL,
                    address TEXT,
                    start_date TEXT,
                    end_date TEXT,
                    status TEXT DEFAULT 'Active',
                    budget REAL,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS materials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT,
                    supplier TEXT,
                    unit_type TEXT,
                    cost_price REAL NOT NULL,
                    sale_price REAL NOT NULL,
                    current_stock REAL DEFAULT 0,
                    min_stock_level REAL DEFAULT 0,
                    location TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS project_pricing (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    material_id INTEGER NOT NULL,
                    custom_price REAL NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_id) REFERENCES projects(id),
                    FOREIGN KEY (material_id) REFERENCES materials(id),
                    UNIQUE(project_id, material_id)
                )
            ''')

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS warehouse_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_type TEXT NOT NULL,
                    material_id INTEGER NOT NULL,
                    quantity REAL NOT NULL,
                    unit_price REAL NOT NULL,
                    project_id INTEGER,
                    supplier_info TEXT,
                    notes TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (material_id) REFERENCES materials(id),
                    FOREIGN KEY (project_id) REFERENCES projects(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS sales (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    material_id INTEGER NOT NULL,
                    quantity REAL NOT NULL,
                    unit_price REAL NOT NULL,
                    total_price REAL NOT NULL,
                    notes TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_id) REFERENCES projects(id),
                    FOREIGN KEY (material_id) REFERENCES materials(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS expenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    amount REAL NOT NULL,
                    category TEXT,
                    receipt_number TEXT,
                    notes TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_id) REFERENCES projects(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action_type TEXT NOT NULL,
                    table_affected TEXT,
                    record_id INTEGER,
                    description TEXT,
                    ip_address TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            self.conn.commit()

            # Create default admin user if not exists
            self.cursor.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
            if self.cursor.fetchone()[0] == 0:
                salt = os.urandom(32).hex()
                password_hash = self.hash_password('Admin@123', salt)
                self.cursor.execute('''
                    INSERT INTO users (username, password_hash, salt, full_name, role)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('admin', password_hash, salt, 'Administrator', 'Admin'))
                self.conn.commit()

        except sqlite3.Error as e:
            QMessageBox.critical(None, "Database Error", f"Failed to initialize database: {str(e)}")
            sys.exit(1)

    def hash_password(self, password, salt):
        """Hash password using PBKDF2-HMAC-SHA256"""
        import hashlib
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), PBKDF2_ITERATIONS).hex()

    def log_audit(self, user_id, action_type, table_affected=None, record_id=None, description=None):
        """Log an audit trail entry"""
        try:
            self.cursor.execute('''
                INSERT INTO audit_log (user_id, action_type, table_affected, record_id, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action_type, table_affected, record_id, description))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Failed to log audit trail: {str(e)}")

    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()


class LoginWindow(QWidget):
    def __init__(self, db_manager, on_success):
        super().__init__()
        self.db_manager = db_manager
        self.on_success = on_success
        self.setWindowTitle("Construction Inventory Management - Login")
        self.setFixedSize(500, 500)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)

        # Logo
        logo_label = QLabel()
        logo_pixmap = QPixmap("icon.png").scaled(150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)

        # Title
        title = QLabel("Construction Inventory Management")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont('Arial', 16, QFont.Bold))
        title.setStyleSheet(f"color: {PRIMARY_COLOR};")
        layout.addWidget(title)

        # Form
        form_layout = QFormLayout()
        form_layout.setSpacing(15)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px;")
        form_layout.addRow("Username:", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px;")
        form_layout.addRow("Password:", self.password_input)

        self.role_combo = QComboBox()
        self.role_combo.addItems(["Admin", "Manager", "Warehouse", "Viewer"])
        self.role_combo.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px;")
        form_layout.addRow("Role:", self.role_combo)

        layout.addLayout(form_layout)

        # Login button
        login_btn = QPushButton("Login")
        login_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 10px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        login_btn.clicked.connect(self.handle_login)
        layout.addWidget(login_btn)

        # Status label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet(f"color: {ERROR_COLOR};")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        role = self.role_combo.currentText()

        if not username or not password:
            self.status_label.setText("Username and password are required")
            return

        try:
            # Check if account is locked
            self.db_manager.cursor.execute("SELECT is_locked FROM users WHERE username=?", (username,))
            result = self.db_manager.cursor.fetchone()

            if result and result[0] == 1:
                self.status_label.setText("Account is locked. Contact administrator.")
                return

            # Verify credentials
            self.db_manager.cursor.execute("SELECT id, password_hash, salt, role FROM users WHERE username=?",
                                           (username,))
            result = self.db_manager.cursor.fetchone()

            if not result:
                self.status_label.setText("Invalid username or password")
                self.record_failed_attempt(username)
                return

            user_id, stored_hash, salt, user_role = result

            # Verify role
            if role != user_role:
                self.status_label.setText(f"User is not a {role}")
                self.record_failed_attempt(username)
                return

            # Verify password
            input_hash = self.db_manager.hash_password(password, salt)
            if input_hash != stored_hash:
                self.status_label.setText("Invalid username or password")
                self.record_failed_attempt(username)
                return

            # Login successful
            self.db_manager.cursor.execute(
                "UPDATE users SET failed_attempts=0, last_login=CURRENT_TIMESTAMP WHERE id=?", (user_id,))
            self.db_manager.conn.commit()

            # Log audit trail
            self.db_manager.log_audit(user_id, "LOGIN", description="User logged in")

            self.on_success(user_id, username, user_role)

        except sqlite3.Error as e:
            self.status_label.setText("Database error during login")
            print(f"Database error: {str(e)}")

    def record_failed_attempt(self, username):
        """Record a failed login attempt and lock account if needed"""
        try:
            self.db_manager.cursor.execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE username=?",
                                           (username,))
            self.db_manager.cursor.execute("SELECT failed_attempts FROM users WHERE username=?", (username,))
            attempts = self.db_manager.cursor.fetchone()[0]

            if attempts >= 5:
                self.db_manager.cursor.execute("UPDATE users SET is_locked=1 WHERE username=?", (username,))
                self.db_manager.log_audit(None, "ACCOUNT_LOCK",
                                          description=f"Account {username} locked due to failed attempts")

            self.db_manager.conn.commit()
        except sqlite3.Error as e:
            print(f"Failed to record login attempt: {str(e)}")


class MainWindow(QMainWindow):
    def __init__(self, db_manager, user_id, username, role):
        super().__init__()
        self.db_manager = db_manager
        self.user_id = user_id
        self.username = username
        self.role = role
        self.setWindowTitle(f"Construction Inventory Management - {username} ({role})")
        self.setMinimumSize(1024, 768)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        self.setup_ui()

    def setup_ui(self):
        # Main layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        welcome_label = QLabel(f"Welcome, {self.username} ({self.role})")
        welcome_label.setFont(QFont('Arial', 12, QFont.Bold))
        welcome_label.setStyleSheet(f"color: {PRIMARY_COLOR};")
        header.addWidget(welcome_label, alignment=Qt.AlignLeft)

        logout_btn = QPushButton("Logout")
        logout_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ERROR_COLOR};
                color: white;
                padding: 5px 10px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #c9302c;
            }}
        """)
        logout_btn.clicked.connect(self.logout)
        header.addWidget(logout_btn, alignment=Qt.AlignRight)

        main_layout.addLayout(header)

        # Tab widget for different modules
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                padding: 8px 15px;
                background: #f1f1f1;
                border: 1px solid #ddd;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #fff;
                border-color: #ddd;
                border-bottom-color: #fff;
            }
            QTabBar::tab:hover {
                background: #e9e9e9;
            }
        """)

        # Dashboard tab
        self.dashboard_tab = QWidget()
        self.setup_dashboard()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")

        # Projects tab
        if self.role in ['Admin', 'Manager']:
            self.projects_tab = QWidget()
            self.setup_projects()
            self.tabs.addTab(self.projects_tab, "Projects")

        # Inventory tab
        if self.role in ['Admin', 'Manager', 'Warehouse']:
            self.inventory_tab = QWidget()
            self.setup_inventory()
            self.tabs.addTab(self.inventory_tab, "Inventory")

        # Warehouse tab
        if self.role in ['Admin', 'Warehouse']:
            self.warehouse_tab = QWidget()
            self.setup_warehouse()
            self.tabs.addTab(self.warehouse_tab, "Warehouse")

        # Sales tab
        if self.role in ['Admin', 'Manager']:
            self.sales_tab = QWidget()
            self.setup_sales()
            self.tabs.addTab(self.sales_tab, "Sales")

        # Expenses tab
        if self.role in ['Admin', 'Manager']:
            self.expenses_tab = QWidget()
            self.setup_expenses()
            self.tabs.addTab(self.expenses_tab, "Expenses")

        # Reports tab
        if self.role in ['Admin', 'Manager', 'Viewer']:
            self.reports_tab = QWidget()
            self.setup_reports()
            self.tabs.addTab(self.reports_tab, "Reports")

        # User management tab (admin only)
        if self.role == 'Admin':
            self.users_tab = QWidget()
            self.setup_users()
            self.tabs.addTab(self.users_tab, "User Management")

        main_layout.addWidget(self.tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Load initial data
        self.load_dashboard_data()
        if hasattr(self, 'projects_tab'):
            self.load_projects_data()
        if hasattr(self, 'inventory_tab'):
            self.load_inventory_data()

    def setup_dashboard(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Summary cards
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(15)

        def create_summary_card(title, value, color):
            card = QGroupBox(title)
            card.setStyleSheet("""
                QGroupBox {
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 3px;
                }
            """)
            card_layout = QVBoxLayout()

            value_label = QLabel(value)
            value_label.setFont(QFont('Arial', 24, QFont.Bold))
            value_label.setAlignment(Qt.AlignCenter)
            value_label.setStyleSheet(f"color: {color};")
            card_layout.addWidget(value_label)

            card.setLayout(card_layout)
            return card

        # Total materials card
        self.total_materials_label = QLabel("0")
        total_materials_card = create_summary_card("Total Materials", "0", PRIMARY_COLOR)
        summary_layout.addWidget(total_materials_card)

        # Low stock card
        self.low_stock_label = QLabel("0")
        low_stock_card = create_summary_card("Low Stock Items", "0", ERROR_COLOR)
        summary_layout.addWidget(low_stock_card)

        # Today's sales card
        self.sales_label = QLabel("$0.00")
        sales_card = create_summary_card("Today's Sales", "$0.00", SECONDARY_COLOR)
        summary_layout.addWidget(sales_card)

        # Inventory value card
        self.value_label = QLabel("$0.00")
        value_card = create_summary_card("Inventory Value", "$0.00", PRIMARY_COLOR)
        summary_layout.addWidget(value_card)

        layout.addLayout(summary_layout)

        # Recent activity tables
        tabs = QTabWidget()

        # Recent sales table
        recent_sales_tab = QWidget()
        recent_sales_layout = QVBoxLayout()
        self.recent_sales_table = QTableWidget()
        self.recent_sales_table.setColumnCount(5)
        self.recent_sales_table.setHorizontalHeaderLabels(["Date", "Project", "Material", "Qty", "Amount"])
        self.recent_sales_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.recent_sales_table)
        recent_sales_layout.addWidget(self.recent_sales_table)
        recent_sales_tab.setLayout(recent_sales_layout)
        tabs.addTab(recent_sales_tab, "Recent Sales")

        # Recent warehouse activity
        warehouse_activity_tab = QWidget()
        warehouse_activity_layout = QVBoxLayout()
        self.warehouse_activity_table = QTableWidget()
        self.warehouse_activity_table.setColumnCount(6)
        self.warehouse_activity_table.setHorizontalHeaderLabels(["Date", "Type", "Material", "Qty", "Project", "User"])
        self.warehouse_activity_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.warehouse_activity_table)
        warehouse_activity_layout.addWidget(self.warehouse_activity_table)
        warehouse_activity_tab.setLayout(warehouse_activity_layout)
        tabs.addTab(warehouse_activity_tab, "Warehouse Activity")

        layout.addWidget(tabs)
        self.dashboard_tab.setLayout(layout)

    def style_table(self, table):
        """Apply consistent styling to tables"""
        table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #ddd;
                background-color: white;
            }
            QHeaderView::section {
                background-color: #f1f1f1;
                padding: 5px;
                border: 1px solid #ddd;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)

    def setup_projects(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Project management controls
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)

        self.project_search = QLineEdit()
        self.project_search.setPlaceholderText("Search projects...")
        self.project_search.textChanged.connect(self.load_projects_data)
        self.project_search.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        controls_layout.addWidget(self.project_search)

        add_project_btn = QPushButton("Add New Project")
        add_project_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 5px 10px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        add_project_btn.clicked.connect(self.show_add_project_dialog)
        controls_layout.addWidget(add_project_btn)

        layout.addLayout(controls_layout)

        # Projects table
        self.projects_table = QTableWidget()
        self.projects_table.setColumnCount(8)
        self.projects_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Client", "Status", "Start Date", "End Date", "Budget", "Actions"])
        self.projects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.projects_table)

        layout.addWidget(self.projects_table)
        self.projects_tab.setLayout(layout)

    def setup_inventory(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Inventory management controls
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)

        self.inventory_search = QLineEdit()
        self.inventory_search.setPlaceholderText("Search inventory...")
        self.inventory_search.textChanged.connect(self.load_inventory_data)
        self.inventory_search.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        controls_layout.addWidget(self.inventory_search)

        category_filter = QComboBox()
        category_filter.addItem("All Categories")
        category_filter.addItems(["Building Materials", "Tools", "Electrical", "Plumbing", "Safety Equipment"])
        category_filter.currentIndexChanged.connect(self.load_inventory_data)
        category_filter.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        controls_layout.addWidget(category_filter)

        add_material_btn = QPushButton("Add New Material")
        add_material_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 5px 10px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        add_material_btn.clicked.connect(self.show_add_material_dialog)
        controls_layout.addWidget(add_material_btn)

        layout.addLayout(controls_layout)

        # Inventory table
        self.inventory_table = QTableWidget()
        self.inventory_table.setColumnCount(10)
        self.inventory_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Category", "Supplier", "Stock", "Unit", "Cost", "Price", "Value", "Actions"])
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.inventory_table)

        layout.addWidget(self.inventory_table)
        self.inventory_tab.setLayout(layout)

    def setup_warehouse(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Transaction form
        form_group = QGroupBox("Warehouse Transaction")
        form_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
        form_layout = QFormLayout()
        form_layout.setSpacing(10)

        self.transaction_type = QComboBox()
        self.transaction_type.addItems(["IN", "OUT"])
        self.transaction_type.currentTextChanged.connect(self.update_warehouse_form)
        self.transaction_type.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Transaction Type:", self.transaction_type)

        self.warehouse_material = QComboBox()
        self.warehouse_material.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Material:", self.warehouse_material)

        self.transaction_qty = QDoubleSpinBox()
        self.transaction_qty.setMinimum(0.01)
        self.transaction_qty.setMaximum(999999)
        self.transaction_qty.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Quantity:", self.transaction_qty)

        self.transaction_price = QDoubleSpinBox()
        self.transaction_price.setMinimum(0.01)
        self.transaction_price.setMaximum(999999)
        self.transaction_price.setPrefix("$ ")
        self.transaction_price.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Unit Price:", self.transaction_price)

        self.warehouse_project = QComboBox()
        self.warehouse_project.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Project (for OUT):", self.warehouse_project)

        self.supplier_info = QLineEdit()
        self.supplier_info.setPlaceholderText("Supplier name and details")
        self.supplier_info.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Supplier Info (for IN):", self.supplier_info)

        self.transaction_notes = QTextEdit()
        self.transaction_notes.setMaximumHeight(80)
        self.transaction_notes.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Notes:", self.transaction_notes)

        submit_btn = QPushButton("Submit Transaction")
        submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        submit_btn.clicked.connect(self.submit_warehouse_transaction)
        form_layout.addRow(submit_btn)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        # Recent transactions
        recent_group = QGroupBox("Recent Transactions")
        recent_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
        recent_layout = QVBoxLayout()

        self.warehouse_transactions_table = QTableWidget()
        self.warehouse_transactions_table.setColumnCount(8)
        self.warehouse_transactions_table.setHorizontalHeaderLabels(
            ["Date", "Type", "Material", "Qty", "Price", "Project", "User", "Notes"])
        self.warehouse_transactions_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.warehouse_transactions_table)

        recent_layout.addWidget(self.warehouse_transactions_table)
        recent_group.setLayout(recent_layout)
        layout.addWidget(recent_group)

        self.warehouse_tab.setLayout(layout)

        # Load initial data
        self.load_warehouse_form_data()
        self.load_warehouse_transactions()

    def update_warehouse_form(self, transaction_type):
        """Update form fields based on transaction type"""
        if transaction_type == "IN":
            self.warehouse_project.setEnabled(False)
            self.supplier_info.setEnabled(True)
        else:
            self.warehouse_project.setEnabled(True)
            self.supplier_info.setEnabled(False)

    def setup_sales(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Sales form
        form_group = QGroupBox("Record Sale")
        form_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
        form_layout = QFormLayout()
        form_layout.setSpacing(10)

        self.sale_project = QComboBox()
        self.sale_project.currentIndexChanged.connect(self.update_sale_materials)
        self.sale_project.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Project:", self.sale_project)

        self.sale_material = QComboBox()
        self.sale_material.currentIndexChanged.connect(self.update_sale_price)
        self.sale_material.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Material:", self.sale_material)

        self.sale_qty = QDoubleSpinBox()
        self.sale_qty.setMinimum(0.01)
        self.sale_qty.setMaximum(999999)
        self.sale_qty.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        self.sale_qty.valueChanged.connect(self.update_sale_total)
        form_layout.addRow("Quantity:", self.sale_qty)

        self.sale_price = QDoubleSpinBox()
        self.sale_price.setMinimum(0.01)
        self.sale_price.setMaximum(999999)
        self.sale_price.setPrefix("$ ")
        self.sale_price.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        self.sale_price.valueChanged.connect(self.update_sale_total)
        form_layout.addRow("Unit Price:", self.sale_price)

        self.sale_total = QLabel("$0.00")
        self.sale_total.setFont(QFont('Arial', 12, QFont.Bold))
        self.sale_total.setStyleSheet(f"color: {PRIMARY_COLOR};")
        form_layout.addRow("Total:", self.sale_total)

        self.sale_notes = QTextEdit()
        self.sale_notes.setMaximumHeight(80)
        self.sale_notes.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Notes:", self.sale_notes)

        submit_btn = QPushButton("Record Sale")
        submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        submit_btn.clicked.connect(self.submit_sale)
        form_layout.addRow(submit_btn)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        # Recent sales
        recent_group = QGroupBox("Recent Sales")
        recent_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
        recent_layout = QVBoxLayout()

        self.sales_history_table = QTableWidget()
        self.sales_history_table.setColumnCount(7)
        self.sales_history_table.setHorizontalHeaderLabels(
            ["Date", "Project", "Material", "Qty", "Price", "Total", "Notes"])
        self.sales_history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.sales_history_table)

        recent_layout.addWidget(self.sales_history_table)
        recent_group.setLayout(recent_layout)
        layout.addWidget(recent_group)

        self.sales_tab.setLayout(layout)

        # Load initial data
        self.load_sales_form_data()
        self.load_sales_history()

    def update_sale_materials(self):
        """Update materials combo based on selected project"""
        project_id = self.sale_project.currentData()
        if not project_id:
            return

        try:
            self.sale_material.clear()

            # Get all materials with their standard prices and any project-specific prices
            self.db_manager.cursor.execute('''
                SELECT m.id, m.name, 
                       COALESCE(pp.custom_price, m.sale_price) as price,
                       m.current_stock
                FROM materials m
                LEFT JOIN project_pricing pp ON pp.material_id = m.id AND pp.project_id = ?
                WHERE m.current_stock > 0
                ORDER BY m.name
            ''', (project_id,))

            materials = self.db_manager.cursor.fetchall()
            for material in materials:
                self.sale_material.addItem(f"{material[1]} (Stock: {material[3]}, Price: ${material[2]:.2f})",
                                           (material[0], material[2]))

            if materials:
                self.sale_price.setValue(materials[0][2])
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load materials: {str(e)}")

    def update_sale_price(self):
        """Update price when material selection changes"""
        material_data = self.sale_material.currentData()
        if material_data:
            material_id, price = material_data
            self.sale_price.setValue(price)

    def setup_expenses(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Expense form
        form_group = QGroupBox("Record Expense")
        form_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
        form_layout = QFormLayout()
        form_layout.setSpacing(10)

        self.expense_project = QComboBox()
        self.expense_project.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Project:", self.expense_project)

        self.expense_desc = QLineEdit()
        self.expense_desc.setPlaceholderText("Description of expense")
        self.expense_desc.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Description:", self.expense_desc)

        self.expense_amount = QDoubleSpinBox()
        self.expense_amount.setMinimum(0.01)
        self.expense_amount.setMaximum(999999)
        self.expense_amount.setPrefix("$ ")
        self.expense_amount.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Amount:", self.expense_amount)

        self.expense_category = QComboBox()
        self.expense_category.addItems(["Labor", "Materials", "Equipment", "Subcontractor", "Permits", "Other"])
        self.expense_category.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Category:", self.expense_category)

        self.expense_receipt = QLineEdit()
        self.expense_receipt.setPlaceholderText("Receipt number (if available)")
        self.expense_receipt.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Receipt #:", self.expense_receipt)

        self.expense_notes = QTextEdit()
        self.expense_notes.setMaximumHeight(80)
        self.expense_notes.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        form_layout.addRow("Notes:", self.expense_notes)

        submit_btn = QPushButton("Record Expense")
        submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        submit_btn.clicked.connect(self.submit_expense)
        form_layout.addRow(submit_btn)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        # Recent expenses
        recent_group = QGroupBox("Recent Expenses")
        recent_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
        recent_layout = QVBoxLayout()

        self.expenses_history_table = QTableWidget()
        self.expenses_history_table.setColumnCount(7)
        self.expenses_history_table.setHorizontalHeaderLabels(
            ["Date", "Project", "Description", "Amount", "Category", "Receipt", "Notes"])
        self.expenses_history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.expenses_history_table)

        recent_layout.addWidget(self.expenses_history_table)
        recent_group.setLayout(recent_layout)
        layout.addWidget(recent_group)

        self.expenses_tab.setLayout(layout)

        # Load initial data
        self.load_expenses_form_data()
        self.load_expenses_history()

    def setup_reports(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Report selection
        report_controls = QHBoxLayout()
        report_controls.setSpacing(10)

        self.report_type = QComboBox()
        self.report_type.addItems([
            "Inventory Status",
            "Sales Summary",
            "Project Financials",
            "Expense Analysis",
            "Low Stock Report",
            "Warehouse Activity"
        ])
        self.report_type.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        report_controls.addWidget(self.report_type)

        date_layout = QHBoxLayout()
        date_layout.setSpacing(5)
        date_layout.addWidget(QLabel("From:"))
        self.report_from_date = QDateEdit()
        self.report_from_date.setDate(QDate.currentDate().addMonths(-1))
        self.report_from_date.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        date_layout.addWidget(self.report_from_date)

        date_layout.addWidget(QLabel("To:"))
        self.report_to_date = QDateEdit()
        self.report_to_date.setDate(QDate.currentDate())
        self.report_to_date.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        date_layout.addWidget(self.report_to_date)

        report_controls.addLayout(date_layout)

        project_layout = QHBoxLayout()
        project_layout.setSpacing(5)
        project_layout.addWidget(QLabel("Project:"))
        self.report_project = QComboBox()
        self.report_project.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        project_layout.addWidget(self.report_project)
        report_controls.addLayout(project_layout)

        generate_btn = QPushButton("Generate Report")
        generate_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 5px 10px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        generate_btn.clicked.connect(self.generate_report)
        report_controls.addWidget(generate_btn)

        export_btn = QPushButton("Export to CSV")
        export_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {SECONDARY_COLOR};
                color: black;
                padding: 5px 10px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #fccf40;
            }}
        """)
        export_btn.clicked.connect(self.export_report)
        report_controls.addWidget(export_btn)

        layout.addLayout(report_controls)

        # Report results
        self.report_table = QTableWidget()
        self.report_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.report_table)
        layout.addWidget(self.report_table)

        self.reports_tab.setLayout(layout)

        # Load initial data
        self.load_reports_form_data()

    def setup_users(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # User management controls
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)

        self.user_search = QLineEdit()
        self.user_search.setPlaceholderText("Search users...")
        self.user_search.textChanged.connect(self.load_users_data)
        self.user_search.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        controls_layout.addWidget(self.user_search)

        add_user_btn = QPushButton("Add New User")
        add_user_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 5px 10px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        add_user_btn.clicked.connect(self.show_add_user_dialog)
        controls_layout.addWidget(add_user_btn)

        layout.addLayout(controls_layout)

        # Users table
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(6)
        self.users_table.setHorizontalHeaderLabels(["ID", "Username", "Full Name", "Role", "Status", "Actions"])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.style_table(self.users_table)

        layout.addWidget(self.users_table)
        self.users_tab.setLayout(layout)

        # Load initial data
        self.load_users_data()

    def load_dashboard_data(self):
        """Load data for the dashboard"""
        try:
            # Total materials count
            self.db_manager.cursor.execute("SELECT COUNT(*) FROM materials")
            total_materials = self.db_manager.cursor.fetchone()[0]
            self.total_materials_label.setText(str(total_materials))

            # Low stock items
            self.db_manager.cursor.execute(
                "SELECT COUNT(*) FROM materials WHERE current_stock <= min_stock_level AND min_stock_level > 0")
            low_stock = self.db_manager.cursor.fetchone()[0]
            self.low_stock_label.setText(str(low_stock))

            # Today's sales
            today = datetime.now().strftime("%Y-%m-%d")
            self.db_manager.cursor.execute("SELECT SUM(total_price) FROM sales WHERE date(created_at) = ?", (today,))
            sales_total = self.db_manager.cursor.fetchone()[0] or 0
            self.sales_label.setText(f"${sales_total:,.2f}")

            # Inventory value
            self.db_manager.cursor.execute("SELECT SUM(cost_price * current_stock) FROM materials")
            inventory_value = self.db_manager.cursor.fetchone()[0] or 0
            self.value_label.setText(f"${inventory_value:,.2f}")

            # Recent sales (last 10)
            self.db_manager.cursor.execute('''
                SELECT s.created_at, p.name, m.name, s.quantity, s.total_price 
                FROM sales s
                JOIN projects p ON s.project_id = p.id
                JOIN materials m ON s.material_id = m.id
                ORDER BY s.created_at DESC
                LIMIT 10
            ''')
            recent_sales = self.db_manager.cursor.fetchall()

            self.recent_sales_table.setRowCount(len(recent_sales))
            for row_idx, row in enumerate(recent_sales):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))
                    if col_idx == 4:  # Format currency
                        item.setText(f"${float(value):,.2f}")
                    self.recent_sales_table.setItem(row_idx, col_idx, item)

            # Recent warehouse activity
            self.db_manager.cursor.execute('''
                SELECT wt.created_at, wt.transaction_type, m.name, wt.quantity, 
                       COALESCE(p.name, 'N/A'), u.username, wt.notes
                FROM warehouse_transactions wt
                JOIN materials m ON wt.material_id = m.id
                LEFT JOIN projects p ON wt.project_id = p.id
                JOIN users u ON wt.user_id = u.id
                ORDER BY wt.created_at DESC
                LIMIT 10
            ''')
            recent_activity = self.db_manager.cursor.fetchall()

            self.warehouse_activity_table.setRowCount(len(recent_activity))
            for row_idx, row in enumerate(recent_activity):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))
                    self.warehouse_activity_table.setItem(row_idx, col_idx, item)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load dashboard data: {str(e)}")

    def load_projects_data(self):
        """Load projects data into the table"""
        try:
            search_term = f"%{self.project_search.text()}%"
            self.db_manager.cursor.execute('''
                SELECT id, name, client, status, start_date, end_date, budget 
                FROM projects 
                WHERE name LIKE ? OR client LIKE ?
                ORDER BY status, start_date DESC
            ''', (search_term, search_term))
            projects = self.db_manager.cursor.fetchall()

            self.projects_table.setRowCount(len(projects))
            for row_idx, row in enumerate(projects):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))

                    # Format dates and currency
                    if col_idx in [4, 5] and value:  # Dates
                        item.setText(datetime.strptime(value, "%Y-%m-%d").strftime("%m/%d/%Y"))
                    elif col_idx == 6:  # Budget
                        item.setText(f"${float(value):,.2f}" if value else "$0.00")

                    # Color by status
                    if col_idx == 3:  # Status column
                        if value == "Active":
                            item.setBackground(QColor(220, 255, 220))
                        elif value == "On Hold":
                            item.setBackground(QColor(255, 255, 200))
                        elif value == "Completed":
                            item.setBackground(QColor(220, 220, 255))
                        elif value == "Cancelled":
                            item.setBackground(QColor(255, 220, 220))

                    self.projects_table.setItem(row_idx, col_idx, item)

                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout()
                actions_layout.setContentsMargins(0, 0, 0, 0)
                actions_layout.setSpacing(5)

                edit_btn = QPushButton("Edit")
                edit_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {SECONDARY_COLOR};
                        color: black;
                        padding: 3px 5px;
                        border: none;
                        border-radius: 3px;
                    }}
                    QPushButton:hover {{
                        background-color: #fccf40;
                    }}
                """)
                edit_btn.clicked.connect(lambda _, r=row[0]: self.edit_project(r))
                actions_layout.addWidget(edit_btn)

                delete_btn = QPushButton("Delete")
                delete_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {ERROR_COLOR};
                        color: white;
                        padding: 3px 5px;
                        border: none;
                        border-radius: 3px;
                    }}
                    QPushButton:hover {{
                        background-color: #c9302c;
                    }}
                """)
                delete_btn.clicked.connect(lambda _, r=row[0]: self.delete_project(r))
                actions_layout.addWidget(delete_btn)

                actions_widget.setLayout(actions_layout)
                self.projects_table.setCellWidget(row_idx, 7, actions_widget)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load projects: {str(e)}")

    def load_inventory_data(self):
        """Load inventory data into the table"""
        try:
            search_term = f"%{self.inventory_search.text()}%"
            self.db_manager.cursor.execute('''
                SELECT id, name, category, supplier, current_stock, unit_type, cost_price, sale_price
                FROM materials 
                WHERE name LIKE ? OR supplier LIKE ? OR category LIKE ?
                ORDER BY name
            ''', (search_term, search_term, search_term))
            materials = self.db_manager.cursor.fetchall()

            self.inventory_table.setRowCount(len(materials))
            for row_idx, row in enumerate(materials):
                inventory_value = row[4] * row[6]  # stock * cost

                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))

                    # Format numbers
                    if col_idx in [6, 7]:  # Prices
                        item.setText(f"${float(value):,.2f}")
                    elif col_idx == 4:  # Stock
                        item.setText(f"{float(value):,.2f}")

                    # Highlight low stock
                    self.db_manager.cursor.execute("SELECT min_stock_level FROM materials WHERE id=?", (row[0],))
                    min_stock = self.db_manager.cursor.fetchone()[0]
                    if min_stock and value == row[4] and float(value) <= min_stock:
                        item.setBackground(QColor(255, 200, 200))

                    self.inventory_table.setItem(row_idx, col_idx, item)

                # Add value column
                value_item = QTableWidgetItem(f"${inventory_value:,.2f}")
                self.inventory_table.setItem(row_idx, 8, value_item)

                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout()
                actions_layout.setContentsMargins(0, 0, 0, 0)
                actions_layout.setSpacing(5)

                edit_btn = QPushButton("Edit")
                edit_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {SECONDARY_COLOR};
                        color: black;
                        padding: 3px 5px;
                        border: none;
                        border-radius: 3px;
                    }}
                    QPushButton:hover {{
                        background-color: #fccf40;
                    }}
                """)
                edit_btn.clicked.connect(lambda _, r=row[0]: self.edit_material(r))
                actions_layout.addWidget(edit_btn)

                delete_btn = QPushButton("Delete")
                delete_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {ERROR_COLOR};
                        color: white;
                        padding: 3px 5px;
                        border: none;
                        border-radius: 3px;
                    }}
                    QPushButton:hover {{
                        background-color: #c9302c;
                    }}
                """)
                delete_btn.clicked.connect(lambda _, r=row[0]: self.delete_material(r))
                actions_layout.addWidget(delete_btn)

                actions_widget.setLayout(actions_layout)
                self.inventory_table.setCellWidget(row_idx, 9, actions_widget)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load inventory: {str(e)}")

    def load_warehouse_form_data(self):
        """Load data needed for warehouse form"""
        try:
            # Load materials
            self.warehouse_material.clear()
            self.db_manager.cursor.execute("SELECT id, name FROM materials ORDER BY name")
            materials = self.db_manager.cursor.fetchall()
            for material in materials:
                self.warehouse_material.addItem(material[1], material[0])

            # Load projects
            self.warehouse_project.clear()
            self.db_manager.cursor.execute("SELECT id, name FROM projects WHERE status='Active' ORDER BY name")
            projects = self.db_manager.cursor.fetchall()
            for project in projects:
                self.warehouse_project.addItem(project[1], project[0])

            # Set default price
            if materials:
                self.db_manager.cursor.execute("SELECT cost_price FROM materials WHERE id=?", (materials[0][0],))
                cost_price = self.db_manager.cursor.fetchone()[0]
                self.transaction_price.setValue(cost_price)

            # Update form based on initial transaction type
            self.update_warehouse_form(self.transaction_type.currentText())

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load form data: {str(e)}")

    def load_warehouse_transactions(self):
        """Load recent warehouse transactions"""
        try:
            self.db_manager.cursor.execute('''
                SELECT wt.created_at, wt.transaction_type, m.name, wt.quantity, 
                       wt.unit_price, COALESCE(p.name, 'N/A'), u.username, wt.notes
                FROM warehouse_transactions wt
                JOIN materials m ON wt.material_id = m.id
                LEFT JOIN projects p ON wt.project_id = p.id
                JOIN users u ON wt.user_id = u.id
                ORDER BY wt.created_at DESC
                LIMIT 50
            ''')
            transactions = self.db_manager.cursor.fetchall()

            self.warehouse_transactions_table.setRowCount(len(transactions))
            for row_idx, row in enumerate(transactions):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))

                    # Format numbers
                    if col_idx == 4:  # Unit price
                        item.setText(f"${float(value):,.2f}")
                    elif col_idx == 3:  # Quantity
                        item.setText(f"{float(value):,.2f}")

                    # Color by transaction type
                    if col_idx == 1:  # Transaction type
                        if value == "IN":
                            item.setBackground(QColor(220, 255, 220))
                        else:
                            item.setBackground(QColor(255, 220, 220))

                    self.warehouse_transactions_table.setItem(row_idx, col_idx, item)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load transactions: {str(e)}")

    def load_sales_form_data(self):
        """Load data needed for sales form"""
        try:
            # Load projects
            self.sale_project.clear()
            self.db_manager.cursor.execute("SELECT id, name FROM projects WHERE status='Active' ORDER BY name")
            projects = self.db_manager.cursor.fetchall()
            for project in projects:
                self.sale_project.addItem(project[1], project[0])

            # Load materials for first project if available
            if projects:
                self.update_sale_materials()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load form data: {str(e)}")

    def load_sales_history(self):
        """Load recent sales history"""
        try:
            self.db_manager.cursor.execute('''
                SELECT s.created_at, p.name, m.name, s.quantity, s.unit_price, s.total_price, s.notes
                FROM sales s
                JOIN projects p ON s.project_id = p.id
                JOIN materials m ON s.material_id = m.id
                ORDER BY s.created_at DESC
                LIMIT 50
            ''')
            sales = self.db_manager.cursor.fetchall()

            self.sales_history_table.setRowCount(len(sales))
            for row_idx, row in enumerate(sales):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))

                    # Format numbers
                    if col_idx in [3, 4, 5]:  # Quantity and prices
                        if col_idx == 3:  # Quantity
                            item.setText(f"{float(value):,.2f}")
                        else:  # Prices
                            item.setText(f"${float(value):,.2f}")

                    self.sales_history_table.setItem(row_idx, col_idx, item)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load sales history: {str(e)}")

    def load_expenses_form_data(self):
        """Load data needed for expenses form"""
        try:
            # Load projects
            self.expense_project.clear()
            self.db_manager.cursor.execute("SELECT id, name FROM projects ORDER BY name")
            projects = self.db_manager.cursor.fetchall()
            for project in projects:
                self.expense_project.addItem(project[1], project[0])

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load form data: {str(e)}")

    def load_expenses_history(self):
        """Load recent expenses history"""
        try:
            self.db_manager.cursor.execute('''
                SELECT e.created_at, p.name, e.description, e.amount, e.category, e.receipt_number, e.notes
                FROM expenses e
                JOIN projects p ON e.project_id = p.id
                ORDER BY e.created_at DESC
                LIMIT 50
            ''')
            expenses = self.db_manager.cursor.fetchall()

            self.expenses_history_table.setRowCount(len(expenses))
            for row_idx, row in enumerate(expenses):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))

                    # Format amount
                    if col_idx == 3:  # Amount
                        item.setText(f"${float(value):,.2f}")

                    self.expenses_history_table.setItem(row_idx, col_idx, item)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load expenses history: {str(e)}")

    def load_reports_form_data(self):
        """Load data needed for reports form"""
        try:
            # Load projects
            self.report_project.clear()
            self.report_project.addItem("All Projects")
            self.db_manager.cursor.execute("SELECT id, name FROM projects ORDER BY name")
            projects = self.db_manager.cursor.fetchall()
            for project in projects:
                self.report_project.addItem(project[1], project[0])

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load form data: {str(e)}")

    def load_users_data(self):
        """Load users data into the table"""
        try:
            search_term = f"%{self.user_search.text()}%"
            self.db_manager.cursor.execute('''
                SELECT id, username, full_name, role, is_locked 
                FROM users 
                WHERE username LIKE ? OR full_name LIKE ?
                ORDER BY role, username
            ''', (search_term, search_term))
            users = self.db_manager.cursor.fetchall()

            self.users_table.setRowCount(len(users))
            for row_idx, row in enumerate(users):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(str(value))

                    # Format status
                    if col_idx == 4:  # Locked status
                        item.setText("Locked" if value == 1 else "Active")
                        if value == 1:
                            item.setBackground(QColor(255, 200, 200))

                    self.users_table.setItem(row_idx, col_idx, item)

                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout()
                actions_layout.setContentsMargins(0, 0, 0, 0)
                actions_layout.setSpacing(5)

                edit_btn = QPushButton("Edit")
                edit_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {SECONDARY_COLOR};
                        color: black;
                        padding: 3px 5px;
                        border: none;
                        border-radius: 3px;
                    }}
                    QPushButton:hover {{
                        background-color: #fccf40;
                    }}
                """)
                edit_btn.clicked.connect(lambda _, r=row[0]: self.edit_user(r))
                actions_layout.addWidget(edit_btn)

                reset_btn = QPushButton("Reset PW")
                reset_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #5bc0de;
                        color: white;
                        padding: 3px 5px;
                        border: none;
                        border-radius: 3px;
                    }}
                    QPushButton:hover {{
                        background-color: #46b8da;
                    }}
                """)
                reset_btn.clicked.connect(lambda _, r=row[0]: self.reset_user_password(r))
                actions_layout.addWidget(reset_btn)

                toggle_btn = QPushButton("Toggle Lock")
                toggle_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #f0ad4e;
                        color: white;
                        padding: 3px 5px;
                        border: none;
                        border-radius: 3px;
                    }}
                    QPushButton:hover {{
                        background-color: #eea236;
                    }}
                """)
                toggle_btn.clicked.connect(lambda _, r=row[0]: self.toggle_user_lock(r))
                actions_layout.addWidget(toggle_btn)

                # Don't allow deleting the admin user
                if row[1] != "admin":
                    delete_btn = QPushButton("Delete")
                    delete_btn.setStyleSheet(f"""
                        QPushButton {{
                            background-color: {ERROR_COLOR};
                            color: white;
                            padding: 3px 5px;
                            border: none;
                            border-radius: 3px;
                        }}
                        QPushButton:hover {{
                            background-color: #c9302c;
                        }}
                    """)
                    delete_btn.clicked.connect(lambda _, r=row[0]: self.delete_user(r))
                    actions_layout.addWidget(delete_btn)

                actions_widget.setLayout(actions_layout)
                self.users_table.setCellWidget(row_idx, 5, actions_widget)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load users: {str(e)}")

    def show_add_project_dialog(self):
        """Show dialog to add a new project"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Project")
        dialog.setMinimumWidth(500)

        layout = QFormLayout()
        layout.setSpacing(15)

        # Form fields
        name_input = QLineEdit()
        name_input.setPlaceholderText("Project name")
        name_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Name*:", name_input)

        client_input = QLineEdit()
        client_input.setPlaceholderText("Client name")
        client_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Client*:", client_input)

        address_input = QTextEdit()
        address_input.setMaximumHeight(80)
        address_input.setPlaceholderText("Project address")
        address_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Address:", address_input)

        dates_layout = QHBoxLayout()
        dates_layout.setSpacing(10)
        start_date = QDateEdit()
        start_date.setDate(QDate.currentDate())
        start_date.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        dates_layout.addWidget(QLabel("Start Date:"))
        dates_layout.addWidget(start_date)

        end_date = QDateEdit()
        end_date.setDate(QDate.currentDate().addMonths(3))
        end_date.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        dates_layout.addWidget(QLabel("End Date:"))
        dates_layout.addWidget(end_date)
        layout.addRow(dates_layout)

        status_combo = QComboBox()
        status_combo.addItems(["Active", "On Hold", "Completed", "Cancelled"])
        status_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Status:", status_combo)

        budget_input = QDoubleSpinBox()
        budget_input.setMinimum(0)
        budget_input.setMaximum(999999999)
        budget_input.setPrefix("$ ")
        budget_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Budget:", budget_input)

        notes_input = QTextEdit()
        notes_input.setMaximumHeight(100)
        notes_input.setPlaceholderText("Project notes")
        notes_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Notes:", notes_input)

        # Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        submit_btn = QPushButton("Add Project")
        submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        submit_btn.clicked.connect(lambda: self.add_project(
            name_input.text().strip(),
            client_input.text().strip(),
            address_input.toPlainText().strip(),
            start_date.date().toString("yyyy-MM-dd"),
            end_date.date().toString("yyyy-MM-dd"),
            status_combo.currentText(),
            budget_input.value(),
            notes_input.toPlainText().strip(),
            dialog
        ))
        buttons_layout.addWidget(submit_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ERROR_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #c9302c;
            }}
        """)
        cancel_btn.clicked.connect(dialog.reject)
        buttons_layout.addWidget(cancel_btn)

        layout.addRow(buttons_layout)

        dialog.setLayout(layout)
        dialog.exec_()

    def add_project(self, name, client, address, start_date, end_date, status, budget, notes, dialog):
        """Add a new project to the database"""
        if not name or not client:
            QMessageBox.warning(self, "Validation Error", "Name and client are required fields")
            return

        try:
            self.db_manager.cursor.execute('''
                INSERT INTO projects (name, client, address, start_date, end_date, status, budget, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, client, address, start_date, end_date, status, budget, notes))
            self.db_manager.conn.commit()

            # Log audit trail
            project_id = self.db_manager.cursor.lastrowid
            self.db_manager.log_audit(self.user_id, "CREATE", "projects", project_id, f"Added project {name}")

            QMessageBox.information(self, "Success", "Project added successfully")
            self.load_projects_data()
            dialog.accept()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to add project: {str(e)}")

    def edit_project(self, project_id):
        """Edit an existing project"""
        try:
            self.db_manager.cursor.execute('''
                SELECT name, client, address, start_date, end_date, status, budget, notes 
                FROM projects WHERE id=?
            ''', (project_id,))
            project = self.db_manager.cursor.fetchone()

            if not project:
                QMessageBox.warning(self, "Not Found", "Project not found")
                return

            dialog = QDialog(self)
            dialog.setWindowTitle("Edit Project")
            dialog.setMinimumWidth(500)

            layout = QFormLayout()
            layout.setSpacing(15)

            # Form fields with existing data
            name_input = QLineEdit(project[0])
            name_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Name*:", name_input)

            client_input = QLineEdit(project[1])
            client_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Client*:", client_input)

            address_input = QTextEdit(project[2])
            address_input.setMaximumHeight(80)
            address_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Address:", address_input)

            dates_layout = QHBoxLayout()
            dates_layout.setSpacing(10)
            start_date = QDateEdit(QDate.fromString(project[3], "yyyy-MM-dd"))
            start_date.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            dates_layout.addWidget(QLabel("Start Date:"))
            dates_layout.addWidget(start_date)

            end_date = QDateEdit(QDate.fromString(project[4], "yyyy-MM-dd"))
            end_date.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            dates_layout.addWidget(QLabel("End Date:"))
            dates_layout.addWidget(end_date)
            layout.addRow(dates_layout)

            status_combo = QComboBox()
            status_combo.addItems(["Active", "On Hold", "Completed", "Cancelled"])
            status_combo.setCurrentText(project[5])
            status_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Status:", status_combo)

            budget_input = QDoubleSpinBox()
            budget_input.setValue(project[6])
            budget_input.setPrefix("$ ")
            budget_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Budget:", budget_input)

            notes_input = QTextEdit(project[7])
            notes_input.setMaximumHeight(100)
            notes_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Notes:", notes_input)

            # Buttons
            buttons_layout = QHBoxLayout()
            buttons_layout.setSpacing(10)
            update_btn = QPushButton("Update Project")
            update_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {PRIMARY_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #3a479e;
                }}
            """)
            update_btn.clicked.connect(lambda: self.update_project(
                project_id,
                name_input.text().strip(),
                client_input.text().strip(),
                address_input.toPlainText().strip(),
                start_date.date().toString("yyyy-MM-dd"),
                end_date.date().toString("yyyy-MM-dd"),
                status_combo.currentText(),
                budget_input.value(),
                notes_input.toPlainText().strip(),
                dialog
            ))
            buttons_layout.addWidget(update_btn)

            cancel_btn = QPushButton("Cancel")
            cancel_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ERROR_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #c9302c;
                }}
            """)
            cancel_btn.clicked.connect(dialog.reject)
            buttons_layout.addWidget(cancel_btn)

            layout.addRow(buttons_layout)

            dialog.setLayout(layout)
            dialog.exec_()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load project: {str(e)}")

    def update_project(self, project_id, name, client, address, start_date, end_date, status, budget, notes, dialog):
        """Update project in database"""
        if not name or not client:
            QMessageBox.warning(self, "Validation Error", "Name and client are required fields")
            return

        try:
            self.db_manager.cursor.execute('''
                UPDATE projects 
                SET name=?, client=?, address=?, start_date=?, end_date=?, status=?, budget=?, notes=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            ''', (name, client, address, start_date, end_date, status, budget, notes, project_id))
            self.db_manager.conn.commit()

            # Log audit trail
            self.db_manager.log_audit(self.user_id, "UPDATE", "projects", project_id, f"Updated project {name}")

            QMessageBox.information(self, "Success", "Project updated successfully")
            self.load_projects_data()
            dialog.accept()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to update project: {str(e)}")

    def delete_project(self, project_id):
        """Delete a project after confirmation"""
        try:
            # Check if project has associated records
            self.db_manager.cursor.execute("SELECT COUNT(*) FROM sales WHERE project_id=?", (project_id,))
            sales_count = self.db_manager.cursor.fetchone()[0]

            self.db_manager.cursor.execute("SELECT COUNT(*) FROM expenses WHERE project_id=?", (project_id,))
            expenses_count = self.db_manager.cursor.fetchone()[0]

            self.db_manager.cursor.execute("SELECT COUNT(*) FROM warehouse_transactions WHERE project_id=?",
                                           (project_id,))
            transactions_count = self.db_manager.cursor.fetchone()[0]

            if sales_count > 0 or expenses_count > 0 or transactions_count > 0:
                QMessageBox.warning(self, "Cannot Delete",
                                    "This project has associated records (sales, expenses, or transactions) and cannot be deleted.")
                return

            # Get project name for audit log
            self.db_manager.cursor.execute("SELECT name FROM projects WHERE id=?", (project_id,))
            project_name = self.db_manager.cursor.fetchone()[0]

            # Confirm deletion
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                f"Are you sure you want to delete project '{project_name}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.db_manager.cursor.execute("DELETE FROM projects WHERE id=?", (project_id,))
                self.db_manager.conn.commit()

                # Log audit trail
                self.db_manager.log_audit(self.user_id, "DELETE", "projects", project_id,
                                          f"Deleted project {project_name}")

                QMessageBox.information(self, "Success", "Project deleted successfully")
                self.load_projects_data()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to delete project: {str(e)}")

    def show_add_material_dialog(self):
        """Show dialog to add a new material"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Material")
        dialog.setMinimumWidth(500)

        layout = QFormLayout()
        layout.setSpacing(15)

        # Form fields
        name_input = QLineEdit()
        name_input.setPlaceholderText("Material name")
        name_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Name*:", name_input)

        category_combo = QComboBox()
        category_combo.addItems(["", "Building Materials", "Tools", "Electrical", "Plumbing", "Safety Equipment"])
        category_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Category:", category_combo)

        supplier_input = QLineEdit()
        supplier_input.setPlaceholderText("Supplier name")
        supplier_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Supplier*:", supplier_input)

        unit_combo = QComboBox()
        unit_combo.addItems(["Each", "Box", "Pallet", "Pound", "Ton", "Gallon", "Liter", "Foot", "Meter"])
        unit_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Unit Type:", unit_combo)

        cost_input = QDoubleSpinBox()
        cost_input.setMinimum(0.01)
        cost_input.setMaximum(999999)
        cost_input.setPrefix("$ ")
        cost_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Cost Price*:", cost_input)

        sale_input = QDoubleSpinBox()
        sale_input.setMinimum(0.01)
        sale_input.setMaximum(999999)
        sale_input.setPrefix("$ ")
        sale_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Sale Price*:", sale_input)

        stock_input = QDoubleSpinBox()
        stock_input.setMinimum(0)
        stock_input.setMaximum(999999)
        stock_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Initial Stock:", stock_input)

        min_stock_input = QDoubleSpinBox()
        min_stock_input.setMinimum(0)
        min_stock_input.setMaximum(999999)
        min_stock_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Min Stock Level:", min_stock_input)

        location_input = QLineEdit()
        location_input.setPlaceholderText("Warehouse location")
        location_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Location:", location_input)

        notes_input = QTextEdit()
        notes_input.setMaximumHeight(100)
        notes_input.setPlaceholderText("Material notes")
        notes_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Notes:", notes_input)

        # Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        submit_btn = QPushButton("Add Material")
        submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        submit_btn.clicked.connect(lambda: self.add_material(
            name_input.text().strip(),
            category_combo.currentText(),
            supplier_input.text().strip(),
            unit_combo.currentText(),
            cost_input.value(),
            sale_input.value(),
            stock_input.value(),
            min_stock_input.value(),
            location_input.text().strip(),
            notes_input.toPlainText().strip(),
            dialog
        ))
        buttons_layout.addWidget(submit_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ERROR_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #c9302c;
            }}
        """)
        cancel_btn.clicked.connect(dialog.reject)
        buttons_layout.addWidget(cancel_btn)

        layout.addRow(buttons_layout)

        dialog.setLayout(layout)
        dialog.exec_()

    def add_material(self, name, category, supplier, unit, cost, sale, stock, min_stock, location, notes, dialog):
        """Add a new material to the database"""
        if not name or not supplier:
            QMessageBox.warning(self, "Validation Error", "Name and supplier are required fields")
            return

        if sale < cost:
            reply = QMessageBox.question(
                self, 'Confirm Sale Price',
                "Sale price is less than cost price. Are you sure?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                return

        try:
            self.db_manager.cursor.execute('''
                INSERT INTO materials (name, category, supplier, unit_type, cost_price, sale_price, current_stock, min_stock_level, location, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, category, supplier, unit, cost, sale, stock, min_stock, location, notes))
            self.db_manager.conn.commit()

            # Log audit trail
            material_id = self.db_manager.cursor.lastrowid
            self.db_manager.log_audit(self.user_id, "CREATE", "materials", material_id, f"Added material {name}")

            QMessageBox.information(self, "Success", "Material added successfully")
            self.load_inventory_data()
            dialog.accept()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to add material: {str(e)}")

    def edit_material(self, material_id):
        """Edit an existing material"""
        try:
            self.db_manager.cursor.execute('''
                SELECT name, category, supplier, unit_type, cost_price, sale_price, current_stock, min_stock_level, location, notes 
                FROM materials WHERE id=?
            ''', (material_id,))
            material = self.db_manager.cursor.fetchone()

            if not material:
                QMessageBox.warning(self, "Not Found", "Material not found")
                return

            dialog = QDialog(self)
            dialog.setWindowTitle("Edit Material")
            dialog.setMinimumWidth(500)

            layout = QFormLayout()
            layout.setSpacing(15)

            # Form fields with existing data
            name_input = QLineEdit(material[0])
            name_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Name*:", name_input)

            category_combo = QComboBox()
            category_combo.addItems(["", "Building Materials", "Tools", "Electrical", "Plumbing", "Safety Equipment"])
            category_combo.setCurrentText(material[1] if material[1] else "")
            category_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Category:", category_combo)

            supplier_input = QLineEdit(material[2])
            supplier_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Supplier*:", supplier_input)

            unit_combo = QComboBox()
            unit_combo.addItems(["Each", "Box", "Pallet", "Pound", "Ton", "Gallon", "Liter", "Foot", "Meter"])
            unit_combo.setCurrentText(material[3])
            unit_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Unit Type:", unit_combo)

            cost_input = QDoubleSpinBox()
            cost_input.setValue(material[4])
            cost_input.setPrefix("$ ")
            cost_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Cost Price*:", cost_input)

            sale_input = QDoubleSpinBox()
            sale_input.setValue(material[5])
            sale_input.setPrefix("$ ")
            sale_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Sale Price*:", sale_input)

            stock_input = QDoubleSpinBox()
            stock_input.setValue(material[6])
            stock_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Current Stock:", stock_input)

            min_stock_input = QDoubleSpinBox()
            min_stock_input.setValue(material[7])
            min_stock_input.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Min Stock Level:", min_stock_input)

            location_input = QLineEdit(material[8])
            location_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Location:", location_input)

            notes_input = QTextEdit(material[9])
            notes_input.setMaximumHeight(100)
            notes_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Notes:", notes_input)

            # Buttons
            buttons_layout = QHBoxLayout()
            buttons_layout.setSpacing(10)
            update_btn = QPushButton("Update Material")
            update_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {PRIMARY_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #3a479e;
                }}
            """)
            update_btn.clicked.connect(lambda: self.update_material(
                material_id,
                name_input.text().strip(),
                category_combo.currentText(),
                supplier_input.text().strip(),
                unit_combo.currentText(),
                cost_input.value(),
                sale_input.value(),
                stock_input.value(),
                min_stock_input.value(),
                location_input.text().strip(),
                notes_input.toPlainText().strip(),
                dialog
            ))
            buttons_layout.addWidget(update_btn)

            cancel_btn = QPushButton("Cancel")
            cancel_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ERROR_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #c9302c;
                }}
            """)
            cancel_btn.clicked.connect(dialog.reject)
            buttons_layout.addWidget(cancel_btn)

            layout.addRow(buttons_layout)

            dialog.setLayout(layout)
            dialog.exec_()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load material: {str(e)}")

    def update_material(self, material_id, name, category, supplier, unit, cost, sale, stock, min_stock, location,
                        notes, dialog):
        """Update material in database"""
        if not name or not supplier:
            QMessageBox.warning(self, "Validation Error", "Name and supplier are required fields")
            return

        if sale < cost:
            reply = QMessageBox.question(
                self, 'Confirm Sale Price',
                "Sale price is less than cost price. Are you sure?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                return

        try:
            self.db_manager.cursor.execute('''
                UPDATE materials 
                SET name=?, category=?, supplier=?, unit_type=?, cost_price=?, sale_price=?, 
                    current_stock=?, min_stock_level=?, location=?, notes=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            ''', (name, category, supplier, unit, cost, sale, stock, min_stock, location, notes, material_id))
            self.db_manager.conn.commit()

            # Log audit trail
            self.db_manager.log_audit(self.user_id, "UPDATE", "materials", material_id, f"Updated material {name}")

            QMessageBox.information(self, "Success", "Material updated successfully")
            self.load_inventory_data()
            dialog.accept()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to update material: {str(e)}")

    def delete_material(self, material_id):
        """Delete a material after confirmation"""
        try:
            # Check if material has associated records
            self.db_manager.cursor.execute("SELECT COUNT(*) FROM sales WHERE material_id=?", (material_id,))
            sales_count = self.db_manager.cursor.fetchone()[0]

            self.db_manager.cursor.execute("SELECT COUNT(*) FROM warehouse_transactions WHERE material_id=?",
                                           (material_id,))
            transactions_count = self.db_manager.cursor.fetchone()[0]

            if sales_count > 0 or transactions_count > 0:
                QMessageBox.warning(self, "Cannot Delete",
                                    "This material has associated records (sales or transactions) and cannot be deleted.")
                return

            # Get material name for audit log
            self.db_manager.cursor.execute("SELECT name FROM materials WHERE id=?", (material_id,))
            material_name = self.db_manager.cursor.fetchone()[0]

            # Confirm deletion
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                f"Are you sure you want to delete material '{material_name}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.db_manager.cursor.execute("DELETE FROM materials WHERE id=?", (material_id,))
                self.db_manager.conn.commit()

                # Log audit trail
                self.db_manager.log_audit(self.user_id, "DELETE", "materials", material_id,
                                          f"Deleted material {material_name}")

                QMessageBox.information(self, "Success", "Material deleted successfully")
                self.load_inventory_data()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to delete material: {str(e)}")

    def submit_warehouse_transaction(self):
        """Submit a warehouse transaction (IN or OUT)"""
        material_id = self.warehouse_material.currentData()
        if not material_id:
            QMessageBox.warning(self, "Validation Error", "Please select a material")
            return

        quantity = self.transaction_qty.value()
        if quantity <= 0:
            QMessageBox.warning(self, "Validation Error", "Quantity must be positive")
            return

        unit_price = self.transaction_price.value()
        if unit_price <= 0:
            QMessageBox.warning(self, "Validation Error", "Unit price must be positive")
            return

        transaction_type = self.transaction_type.currentText()
        project_id = self.warehouse_project.currentData() if transaction_type == "OUT" else None
        supplier_info = self.supplier_info.text().strip() if transaction_type == "IN" else None
        notes = self.transaction_notes.toPlainText().strip()

        if transaction_type == "IN" and not supplier_info:
            QMessageBox.warning(self, "Validation Error", "Supplier info is required for IN transactions")
            return

        try:
            # Start transaction
            self.db_manager.conn.execute("BEGIN TRANSACTION")

            # Insert transaction record
            self.db_manager.cursor.execute('''
                INSERT INTO warehouse_transactions 
                (transaction_type, material_id, quantity, unit_price, project_id, supplier_info, notes, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (transaction_type, material_id, quantity, unit_price, project_id, supplier_info, notes, self.user_id))

            # Update material stock
            if transaction_type == "IN":
                self.db_manager.cursor.execute('''
                    UPDATE materials SET current_stock = current_stock + ? 
                    WHERE id=?
                ''', (quantity, material_id))
            else:  # OUT
                # Check stock availability
                self.db_manager.cursor.execute("SELECT current_stock FROM materials WHERE id=?", (material_id,))
                current_stock = self.db_manager.cursor.fetchone()[0]

                if current_stock < quantity:
                    QMessageBox.warning(self, "Insufficient Stock",
                                        f"Not enough stock available (current: {current_stock}, requested: {quantity})")
                    self.db_manager.conn.rollback()
                    return

                self.db_manager.cursor.execute('''
                    UPDATE materials SET current_stock = current_stock - ? 
                    WHERE id=?
                ''', (quantity, material_id))

            # Commit transaction
            self.db_manager.conn.commit()

            # Log audit trail
            transaction_id = self.db_manager.cursor.lastrowid
            self.db_manager.log_audit(self.user_id, "CREATE", "warehouse_transactions", transaction_id,
                                      f"{transaction_type} transaction for material ID {material_id}")

            QMessageBox.information(self, "Success", "Transaction recorded successfully")

            # Reset form
            self.transaction_qty.setValue(0.01)
            self.transaction_notes.clear()
            if transaction_type == "IN":
                self.supplier_info.clear()

            # Refresh data
            self.load_warehouse_transactions()
            self.load_inventory_data()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            self.db_manager.conn.rollback()
            QMessageBox.critical(self, "Database Error", f"Failed to record transaction: {str(e)}")

    def update_sale_total(self):
        """Update the total sale price based on quantity and unit price"""
        quantity = self.sale_qty.value()
        unit_price = self.sale_price.value()
        total = quantity * unit_price
        self.sale_total.setText(f"${total:,.2f}")

    def submit_sale(self):
        """Record a material sale"""
        project_id = self.sale_project.currentData()
        if not project_id:
            QMessageBox.warning(self, "Validation Error", "Please select a project")
            return

        material_data = self.sale_material.currentData()
        if not material_data:
            QMessageBox.warning(self, "Validation Error", "Please select a material")
            return

        material_id, default_price = material_data
        quantity = self.sale_qty.value()
        if quantity <= 0:
            QMessageBox.warning(self, "Validation Error", "Quantity must be positive")
            return

        unit_price = self.sale_price.value()
        if unit_price <= 0:
            QMessageBox.warning(self, "Validation Error", "Unit price must be positive")
            return

        total_price = quantity * unit_price
        notes = self.sale_notes.toPlainText().strip()

        try:
            # Start transaction
            self.db_manager.conn.execute("BEGIN TRANSACTION")

            # Check stock availability
            self.db_manager.cursor.execute("SELECT current_stock FROM materials WHERE id=?", (material_id,))
            current_stock = self.db_manager.cursor.fetchone()[0]

            if current_stock < quantity:
                QMessageBox.warning(self, "Insufficient Stock",
                                    f"Not enough stock available (current: {current_stock}, requested: {quantity})")
                self.db_manager.conn.rollback()
                return

            # Record sale
            self.db_manager.cursor.execute('''
                INSERT INTO sales 
                (project_id, material_id, quantity, unit_price, total_price, notes, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (project_id, material_id, quantity, unit_price, total_price, notes, self.user_id))

            # Update material stock
            self.db_manager.cursor.execute('''
                UPDATE materials SET current_stock = current_stock - ? 
                WHERE id=?
            ''', (quantity, material_id))

            # Commit transaction
            self.db_manager.conn.commit()

            # Log audit trail
            sale_id = self.db_manager.cursor.lastrowid
            self.db_manager.log_audit(self.user_id, "CREATE", "sales", sale_id,
                                      f"Sale of material ID {material_id} to project ID {project_id}")

            QMessageBox.information(self, "Success", "Sale recorded successfully")

            # Reset form
            self.sale_qty.setValue(0.01)
            self.sale_notes.clear()

            # Refresh data
            self.load_sales_history()
            self.load_inventory_data()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            self.db_manager.conn.rollback()
            QMessageBox.critical(self, "Database Error", f"Failed to record sale: {str(e)}")

    def submit_expense(self):
        """Record a project expense"""
        project_id = self.expense_project.currentData()
        if not project_id:
            QMessageBox.warning(self, "Validation Error", "Please select a project")
            return

        description = self.expense_desc.text().strip()
        if not description:
            QMessageBox.warning(self, "Validation Error", "Description is required")
            return

        amount = self.expense_amount.value()
        if amount <= 0:
            QMessageBox.warning(self, "Validation Error", "Amount must be positive")
            return

        category = self.expense_category.currentText()
        receipt = self.expense_receipt.text().strip()
        notes = self.expense_notes.toPlainText().strip()

        try:
            # Record expense
            self.db_manager.cursor.execute('''
                INSERT INTO expenses 
                (project_id, description, amount, category, receipt_number, notes, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (project_id, description, amount, category, receipt, notes, self.user_id))
            self.db_manager.conn.commit()

            # Log audit trail
            expense_id = self.db_manager.cursor.lastrowid
            self.db_manager.log_audit(self.user_id, "CREATE", "expenses", expense_id,
                                      f"Expense for project ID {project_id}: {description}")

            QMessageBox.information(self, "Success", "Expense recorded successfully")

            # Reset form
            self.expense_desc.clear()
            self.expense_amount.setValue(0.01)
            self.expense_notes.clear()

            # Refresh data
            self.load_expenses_history()
            self.load_dashboard_data()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to record expense: {str(e)}")

    def generate_report(self):
        """Generate a report based on selected criteria"""
        report_type = self.report_type.currentText()
        from_date = self.report_from_date.date().toString("yyyy-MM-dd")
        to_date = self.report_to_date.date().toString("yyyy-MM-dd")
        project_id = self.report_project.currentData() if self.report_project.currentIndex() > 0 else None

        try:
            if report_type == "Inventory Status":
                self.generate_inventory_report()
            elif report_type == "Sales Summary":
                self.generate_sales_report(from_date, to_date, project_id)
            elif report_type == "Project Financials":
                self.generate_project_financials_report(project_id)
            elif report_type == "Expense Analysis":
                self.generate_expense_report(from_date, to_date, project_id)
            elif report_type == "Low Stock Report":
                self.generate_low_stock_report()
            elif report_type == "Warehouse Activity":
                self.generate_warehouse_activity_report(from_date, to_date, project_id)

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to generate report: {str(e)}")

    def generate_inventory_report(self):
        """Generate inventory status report"""
        self.db_manager.cursor.execute('''
            SELECT id, name, category, supplier, current_stock, unit_type, cost_price, sale_price
            FROM materials 
            ORDER BY name
        ''')
        inventory = self.db_manager.cursor.fetchall()

        self.report_table.setColumnCount(8)
        self.report_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Category", "Supplier", "Stock", "Unit", "Cost", "Price"]
        )

        self.report_table.setRowCount(len(inventory))
        for row_idx, row in enumerate(inventory):
            for col_idx, value in enumerate(row):
                item = QTableWidgetItem(str(value))

                # Format numbers
                if col_idx in [6, 7]:  # Prices
                    item.setText(f"${float(value):,.2f}")
                elif col_idx == 4:  # Stock
                    item.setText(f"{float(value):,.2f}")

                self.report_table.setItem(row_idx, col_idx, item)

    def generate_sales_report(self, from_date, to_date, project_id):
        """Generate sales summary report"""
        query = '''
            SELECT s.created_at, p.name, m.name, s.quantity, s.unit_price, s.total_price
            FROM sales s
            JOIN projects p ON s.project_id = p.id
            JOIN materials m ON s.material_id = m.id
            WHERE date(s.created_at) BETWEEN ? AND ?
        '''
        params = [from_date, to_date]

        if project_id:
            query += " AND s.project_id = ?"
            params.append(project_id)

        query += " ORDER BY s.created_at"

        self.db_manager.cursor.execute(query, params)
        sales = self.db_manager.cursor.fetchall()

        self.report_table.setColumnCount(6)
        self.report_table.setHorizontalHeaderLabels(
            ["Date", "Project", "Material", "Qty", "Unit Price", "Total"]
        )

        self.report_table.setRowCount(len(sales))
        for row_idx, row in enumerate(sales):
            for col_idx, value in enumerate(row):
                item = QTableWidgetItem(str(value))

                # Format numbers
                if col_idx == 3:  # Quantity
                    item.setText(f"{float(value):,.2f}")
                elif col_idx in [4, 5]:  # Prices
                    item.setText(f"${float(value):,.2f}")

                self.report_table.setItem(row_idx, col_idx, item)

    def generate_project_financials_report(self, project_id):
        """Generate project financials report"""
        if not project_id:
            QMessageBox.warning(self, "Selection Required", "Please select a specific project for this report")
            return

        # Project details
        self.db_manager.cursor.execute('''
            SELECT name, client, start_date, end_date, status, budget
            FROM projects WHERE id=?
        ''', (project_id,))
        project = self.db_manager.cursor.fetchone()

        # Sales total
        self.db_manager.cursor.execute('''
            SELECT COALESCE(SUM(total_price), 0) FROM sales WHERE project_id=?
        ''', (project_id,))
        sales_total = self.db_manager.cursor.fetchone()[0]

        # Expenses total
        self.db_manager.cursor.execute('''
            SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE project_id=?
        ''', (project_id,))
        expenses_total = self.db_manager.cursor.fetchone()[0]

        # Create report
        self.report_table.setColumnCount(2)
        self.report_table.setHorizontalHeaderLabels(["Field", "Value"])

        self.report_table.setRowCount(8)

        # Project info
        self.report_table.setItem(0, 0, QTableWidgetItem("Project Name"))
        self.report_table.setItem(0, 1, QTableWidgetItem(project[0]))

        self.report_table.setItem(1, 0, QTableWidgetItem("Client"))
        self.report_table.setItem(1, 1, QTableWidgetItem(project[1]))

        self.report_table.setItem(2, 0, QTableWidgetItem("Dates"))
        dates = f"{project[2]} to {project[3]}" if project[2] and project[3] else "N/A"
        self.report_table.setItem(2, 1, QTableWidgetItem(dates))

        self.report_table.setItem(3, 0, QTableWidgetItem("Status"))
        self.report_table.setItem(3, 1, QTableWidgetItem(project[4]))

        # Financials
        self.report_table.setItem(4, 0, QTableWidgetItem("Budget"))
        self.report_table.setItem(4, 1, QTableWidgetItem(f"${float(project[5]):,.2f}" if project[5] else "$0.00"))

        self.report_table.setItem(5, 0, QTableWidgetItem("Sales Total"))
        self.report_table.setItem(5, 1, QTableWidgetItem(f"${sales_total:,.2f}"))

        self.report_table.setItem(6, 0, QTableWidgetItem("Expenses Total"))
        self.report_table.setItem(6, 1, QTableWidgetItem(f"${expenses_total:,.2f}"))

        profit = sales_total - expenses_total
        self.report_table.setItem(7, 0, QTableWidgetItem("Profit/Loss"))
        profit_item = QTableWidgetItem(f"${profit:,.2f}")
        profit_item.setBackground(QColor(220, 255, 220) if profit >= 0 else QColor(255, 220, 220))
        self.report_table.setItem(7, 1, profit_item)

    def generate_expense_report(self, from_date, to_date, project_id):
        """Generate expense analysis report"""
        query = '''
            SELECT e.created_at, p.name, e.description, e.amount, e.category, e.receipt_number
            FROM expenses e
            JOIN projects p ON e.project_id = p.id
            WHERE date(e.created_at) BETWEEN ? AND ?
        '''
        params = [from_date, to_date]

        if project_id:
            query += " AND e.project_id = ?"
            params.append(project_id)

        query += " ORDER BY e.created_at"

        self.db_manager.cursor.execute(query, params)
        expenses = self.db_manager.cursor.fetchall()

        self.report_table.setColumnCount(6)
        self.report_table.setHorizontalHeaderLabels(
            ["Date", "Project", "Description", "Amount", "Category", "Receipt"]
        )

        self.report_table.setRowCount(len(expenses))
        for row_idx, row in enumerate(expenses):
            for col_idx, value in enumerate(row):
                item = QTableWidgetItem(str(value))

                # Format amount
                if col_idx == 3:  # Amount
                    item.setText(f"${float(value):,.2f}")

                self.report_table.setItem(row_idx, col_idx, item)

    def generate_low_stock_report(self):
        """Generate low stock report"""
        self.db_manager.cursor.execute('''
            SELECT id, name, category, current_stock, min_stock_level, unit_type, supplier
            FROM materials 
            WHERE current_stock <= min_stock_level AND min_stock_level > 0
            ORDER BY current_stock/min_stock_level
        ''')
        low_stock = self.db_manager.cursor.fetchall()

        self.report_table.setColumnCount(7)
        self.report_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Category", "Current", "Min", "Unit", "Supplier"]
        )

        self.report_table.setRowCount(len(low_stock))
        for row_idx, row in enumerate(low_stock):
            for col_idx, value in enumerate(row):
                item = QTableWidgetItem(str(value))

                # Format stock levels
                if col_idx in [3, 4]:  # Stock levels
                    item.setText(f"{float(value):,.2f}")

                # Highlight critical items
                if col_idx == 3 and float(value) <= 0:
                    item.setBackground(QColor(255, 200, 200))

                self.report_table.setItem(row_idx, col_idx, item)

    def generate_warehouse_activity_report(self, from_date, to_date, project_id):
        """Generate warehouse activity report"""
        query = '''
            SELECT wt.created_at, wt.transaction_type, m.name, wt.quantity, 
                   wt.unit_price, COALESCE(p.name, 'N/A'), u.username
            FROM warehouse_transactions wt
            JOIN materials m ON wt.material_id = m.id
            LEFT JOIN projects p ON wt.project_id = p.id
            JOIN users u ON wt.user_id = u.id
            WHERE date(wt.created_at) BETWEEN ? AND ?
        '''
        params = [from_date, to_date]

        if project_id:
            query += " AND wt.project_id = ?"
            params.append(project_id)

        query += " ORDER BY wt.created_at"

        self.db_manager.cursor.execute(query, params)
        transactions = self.db_manager.cursor.fetchall()

        self.report_table.setColumnCount(7)
        self.report_table.setHorizontalHeaderLabels(
            ["Date", "Type", "Material", "Qty", "Price", "Project", "User"]
        )

        self.report_table.setRowCount(len(transactions))
        for row_idx, row in enumerate(transactions):
            for col_idx, value in enumerate(row):
                item = QTableWidgetItem(str(value))

                # Format numbers
                if col_idx == 3:  # Quantity
                    item.setText(f"{float(value):,.2f}")
                elif col_idx == 4:  # Price
                    item.setText(f"${float(value):,.2f}")

                # Color by transaction type
                if col_idx == 1:  # Transaction type
                    if value == "IN":
                        item.setBackground(QColor(220, 255, 220))
                    else:
                        item.setBackground(QColor(255, 220, 220))

                self.report_table.setItem(row_idx, col_idx, item)

    def export_report(self):
        """Export current report to CSV"""
        if self.report_table.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "There is no report data to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "", "CSV Files (*.csv);;All Files (*)"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w') as f:
                # Write headers
                headers = []
                for col in range(self.report_table.columnCount()):
                    headers.append(self.report_table.horizontalHeaderItem(col).text())
                f.write(','.join(headers) + '\n')

                # Write data
                for row in range(self.report_table.rowCount()):
                    row_data = []
                    for col in range(self.report_table.columnCount()):
                        item = self.report_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    f.write(','.join(row_data) + '\n')

            QMessageBox.information(self, "Success", "Report exported successfully")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def show_add_user_dialog(self):
        """Show dialog to add a new user"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New User")
        dialog.setMinimumWidth(400)

        layout = QFormLayout()
        layout.setSpacing(15)

        # Form fields
        username_input = QLineEdit()
        username_input.setPlaceholderText("Username")
        username_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Username*:", username_input)

        password_input = QLineEdit()
        password_input.setPlaceholderText("Password")
        password_input.setEchoMode(QLineEdit.Password)
        password_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Password*:", password_input)

        fullname_input = QLineEdit()
        fullname_input.setPlaceholderText("Full name")
        fullname_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Full Name*:", fullname_input)

        role_combo = QComboBox()
        role_combo.addItems(["Admin", "Manager", "Warehouse", "Viewer"])
        role_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
        layout.addRow("Role*:", role_combo)

        # Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        submit_btn = QPushButton("Add User")
        submit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #3a479e;
            }}
        """)
        submit_btn.clicked.connect(lambda: self.add_user(
            username_input.text().strip(),
            password_input.text().strip(),
            fullname_input.text().strip(),
            role_combo.currentText(),
            dialog
        ))
        buttons_layout.addWidget(submit_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ERROR_COLOR};
                color: white;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #c9302c;
            }}
        """)
        cancel_btn.clicked.connect(dialog.reject)
        buttons_layout.addWidget(cancel_btn)

        layout.addRow(buttons_layout)

        dialog.setLayout(layout)
        dialog.exec_()

    def add_user(self, username, password, full_name, role, dialog):
        """Add a new user to the database"""
        if not username or not password or not full_name:
            QMessageBox.warning(self, "Validation Error", "All fields are required")
            return

        if len(password) < 8:
            QMessageBox.warning(self, "Validation Error", "Password must be at least 8 characters")
            return

        try:
            # Check if username exists
            self.db_manager.cursor.execute("SELECT COUNT(*) FROM users WHERE username=?", (username,))
            if self.db_manager.cursor.fetchone()[0] > 0:
                QMessageBox.warning(self, "Validation Error", "Username already exists")
                return

            # Hash password
            salt = os.urandom(32).hex()
            password_hash = self.db_manager.hash_password(password, salt)

            # Insert user
            self.db_manager.cursor.execute('''
                INSERT INTO users (username, password_hash, salt, full_name, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, salt, full_name, role))
            self.db_manager.conn.commit()

            # Log audit trail
            user_id = self.db_manager.cursor.lastrowid
            self.db_manager.log_audit(self.user_id, "CREATE", "users", user_id, f"Added user {username}")

            QMessageBox.information(self, "Success", "User added successfully")
            self.load_users_data()
            dialog.accept()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to add user: {str(e)}")

    def edit_user(self, user_id):
        """Edit an existing user"""
        try:
            self.db_manager.cursor.execute('''
                SELECT username, full_name, role 
                FROM users WHERE id=?
            ''', (user_id,))
            user = self.db_manager.cursor.fetchone()

            if not user:
                QMessageBox.warning(self, "Not Found", "User not found")
                return

            dialog = QDialog(self)
            dialog.setWindowTitle("Edit User")
            dialog.setMinimumWidth(400)

            layout = QFormLayout()
            layout.setSpacing(15)

            # Form fields with existing data
            username_input = QLineEdit(user[0])
            username_input.setReadOnly(True)  # Don't allow changing username
            username_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Username:", username_input)

            fullname_input = QLineEdit(user[1])
            fullname_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Full Name*:", fullname_input)

            role_combo = QComboBox()
            role_combo.addItems(["Admin", "Manager", "Warehouse", "Viewer"])
            role_combo.setCurrentText(user[2])
            role_combo.setStyleSheet("padding: 5px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Role*:", role_combo)

            # Buttons
            buttons_layout = QHBoxLayout()
            buttons_layout.setSpacing(10)
            update_btn = QPushButton("Update User")
            update_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {PRIMARY_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #3a479e;
                }}
            """)
            update_btn.clicked.connect(lambda: self.update_user(
                user_id,
                fullname_input.text().strip(),
                role_combo.currentText(),
                dialog
            ))
            buttons_layout.addWidget(update_btn)

            cancel_btn = QPushButton("Cancel")
            cancel_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ERROR_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #c9302c;
                }}
            """)
            cancel_btn.clicked.connect(dialog.reject)
            buttons_layout.addWidget(cancel_btn)

            layout.addRow(buttons_layout)

            dialog.setLayout(layout)
            dialog.exec_()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load user: {str(e)}")

    def update_user(self, user_id, full_name, role, dialog):
        """Update user in database"""
        if not full_name:
            QMessageBox.warning(self, "Validation Error", "Full name is required")
            return

        try:
            self.db_manager.cursor.execute('''
                UPDATE users 
                SET full_name=?, role=?
                WHERE id=?
            ''', (full_name, role, user_id))
            self.db_manager.conn.commit()

            # Log audit trail
            self.db_manager.log_audit(self.user_id, "UPDATE", "users", user_id, f"Updated user ID {user_id}")

            QMessageBox.information(self, "Success", "User updated successfully")
            self.load_users_data()
            dialog.accept()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to update user: {str(e)}")

    def reset_user_password(self, user_id):
        """Reset a user's password"""
        try:
            # Get username for confirmation
            self.db_manager.cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
            username = self.db_manager.cursor.fetchone()[0]

            # Confirm reset
            reply = QMessageBox.question(
                self, 'Confirm Reset',
                f"Are you sure you want to reset password for user '{username}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.No:
                return

            # Show dialog to enter new password
            dialog = QDialog(self)
            dialog.setWindowTitle("Reset Password")
            dialog.setMinimumWidth(300)

            layout = QFormLayout()
            layout.setSpacing(15)

            password_input = QLineEdit()
            password_input.setPlaceholderText("New password")
            password_input.setEchoMode(QLineEdit.Password)
            password_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("New Password*:", password_input)

            confirm_input = QLineEdit()
            confirm_input.setPlaceholderText("Confirm password")
            confirm_input.setEchoMode(QLineEdit.Password)
            confirm_input.setStyleSheet("padding: 8px; border: 1px solid #ddd; border-radius: 4px;")
            layout.addRow("Confirm Password*:", confirm_input)

            # Buttons
            buttons_layout = QHBoxLayout()
            buttons_layout.setSpacing(10)
            submit_btn = QPushButton("Reset Password")
            submit_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {PRIMARY_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #3a479e;
                }}
            """)
            submit_btn.clicked.connect(lambda: self.do_password_reset(
                user_id,
                password_input.text().strip(),
                confirm_input.text().strip(),
                dialog
            ))
            buttons_layout.addWidget(submit_btn)

            cancel_btn = QPushButton("Cancel")
            cancel_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ERROR_COLOR};
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: #c9302c;
                }}
            """)
            cancel_btn.clicked.connect(dialog.reject)
            buttons_layout.addWidget(cancel_btn)

            layout.addRow(buttons_layout)
            dialog.setLayout(layout)
            dialog.exec_()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to reset password: {str(e)}")

    def do_password_reset(self, user_id, password, confirm, dialog):
        """Perform the password reset"""
        if not password or not confirm:
            QMessageBox.warning(self, "Validation Error", "Both password fields are required")
            return

        if password != confirm:
            QMessageBox.warning(self, "Validation Error", "Passwords do not match")
            return

        if len(password) < 8:
            QMessageBox.warning(self, "Validation Error", "Password must be at least 8 characters")
            return

        try:
            # Hash new password
            salt = os.urandom(32).hex()
            password_hash = self.db_manager.hash_password(password, salt)

            # Update password
            self.db_manager.cursor.execute('''
                UPDATE users 
                SET password_hash=?, salt=?, is_locked=0, failed_attempts=0
                WHERE id=?
            ''', (password_hash, salt, user_id))
            self.db_manager.conn.commit()

            # Log audit trail
            self.db_manager.log_audit(self.user_id, "UPDATE", "users", user_id, "Password reset")

            QMessageBox.information(self, "Success", "Password reset successfully")
            dialog.accept()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to reset password: {str(e)}")

    def toggle_user_lock(self, user_id):
        """Toggle user lock status"""
        try:
            # Get current status
            self.db_manager.cursor.execute("SELECT username, is_locked FROM users WHERE id=?", (user_id,))
            username, is_locked = self.db_manager.cursor.fetchone()

            new_status = 0 if is_locked else 1
            status_text = "lock" if new_status == 1 else "unlock"

            # Confirm action
            reply = QMessageBox.question(
                self, 'Confirm Action',
                f"Are you sure you want to {status_text} user '{username}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.No:
                return

            # Update status
            self.db_manager.cursor.execute('''
                UPDATE users 
                SET is_locked=?
                WHERE id=?
            ''', (new_status, user_id))
            self.db_manager.conn.commit()

            # Log audit trail
            self.db_manager.log_audit(self.user_id, "UPDATE", "users", user_id,
                                      f"User account {status_text}ed")

            QMessageBox.information(self, "Success", f"User account {status_text}ed successfully")
            self.load_users_data()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to toggle lock status: {str(e)}")

    def delete_user(self, user_id):
        """Delete a user after confirmation"""
        try:
            # Get user details
            self.db_manager.cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
            username = self.db_manager.cursor.fetchone()[0]

            if username == "admin":
                QMessageBox.warning(self, "Cannot Delete", "The admin user cannot be deleted")
                return

            # Confirm deletion
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                f"Are you sure you want to delete user '{username}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.db_manager.cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
                self.db_manager.conn.commit()

                # Log audit trail
                self.db_manager.log_audit(self.user_id, "DELETE", "users", user_id, f"Deleted user {username}")

                QMessageBox.information(self, "Success", "User deleted successfully")
                self.load_users_data()

        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to delete user: {str(e)}")

    def logout(self):
        """Log out the current user"""
        # Log audit trail
        self.db_manager.log_audit(self.user_id, "LOGOUT", description="User logged out")

        # Close the main window which will return to login
        self.close()


class ConstructionInventoryApp(QApplication):
    def __init__(self, sys_argv):
        super().__init__(sys_argv)
        self.setWindowIcon(QIcon('icon.png'))
        self.db_manager = DatabaseManager()

        # Show login window
        self.login_window = LoginWindow(self.db_manager, self.on_login_success)
        self.login_window.show()

        self.main_window = None

    def on_login_success(self, user_id, username, role):
        """Handle successful login"""
        self.login_window.close()
        self.main_window = MainWindow(self.db_manager, user_id, username, role)
        self.main_window.show()

    def close(self):
        """Clean up on application close"""
        if self.db_manager:
            self.db_manager.close()
        super().close()


if __name__ == "__main__":
    app = ConstructionInventoryApp(sys.argv)
    sys.exit(app.exec_())