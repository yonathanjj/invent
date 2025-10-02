# Construction Inventory Management System

This repository contains a desktop application for managing construction inventory, built with Python, PyQt5, and SQLite. The system is designed to track materials, manage projects, and handle sales and purchases with a focus on security and usability.

There are two main versions of the application in this repository:
-   `erp2.py`: The primary, feature-rich version.
-   `erp.py`: An earlier, simpler version.

## Features (`erp2.py`)

The main application (`erp2.py`) provides a comprehensive set of features for construction inventory management:

-   **Secure Authentication**:
    -   User login with password hashing and salting.
    -   Role-based access control (Admin, Manager, Sales).
    -   Account lockout mechanism after multiple failed login attempts.
    -   Forced password changes on first login for enhanced security.
-   **Dashboard**:
    -   At-a-glance summary of total materials, low-stock items, today's sales, and total inventory value.
    -   A table of recent inventory transactions.
-   **Inventory Management**:
    -   Add, edit, and delete materials with details like category, supplier, and unit of measure.
    -   Track inventory levels across multiple warehouses.
    -   Set minimum stock levels and view low-stock alerts.
    -   Adjust inventory quantities with detailed transaction logging.
-   **Project Management**:
    -   Create and manage projects with client information, start/end dates, and status.
    -   Assign material pricing specific to each project.
-   **Sales and Purchases**:
    -   Record sales transactions with detailed item information.
    -   Create and manage purchase orders from suppliers.
    -   Track the status of sales (Pending, Partial, Paid) and purchases (Ordered, Received, Cancelled).
-   **Supplier Management**:
    -   Maintain a database of suppliers with contact and payment information.
-   **Reporting**:
    -   Generate detailed reports for inventory status, sales, purchases, and project financials.
    -   Export reports to CSV for further analysis.
-   **User Management** (Admin/Manager only):
    -   Add, edit, and delete users.
    -   Reset user passwords.

## Setup and Installation

To run the application, you need to have Python and PyQt5 installed.

1.  **Prerequisites**:
    *   Python 3.x
    *   PyQt5

2.  **Installation**:
    You can install the required library using pip:
    ```bash
    pip install PyQt5
    ```

3.  **Running the Application**:
    To start the application, run the `erp2.py` script:
    ```bash
    python erp2.py
    ```
    The default login credentials are:
    -   **Username**: `admin`
    -   **Password**: `Admin@123`

    You will be required to change the password upon your first login.

## Other Files

-   `erp.py`: An earlier version of the application with a more basic UI and fewer features. It serves as a prototype for the more advanced `erp2.py`.
-   `get_device_id.py`: A utility script that uses Tkinter to display the machine's unique device ID. This ID is used in both `erp.py` and `erp2.py` for a hardcoded device authorization check.
-   `onlyi.py`: An empty and unused file.
-   `shop_management.db`: A SQLite database file, likely used by one of the application versions.
-   `erp.iml`: An IDE-specific project file (IntelliJ).
-   `get_device_id.spec`: A spec file for PyInstaller, used to package the `get_device_id.py` script into an executable.

## Database

The application uses a SQLite database (`construction_inventory.db`) to store all its data. The database file is automatically created in a hidden directory in the user's home folder (`~/.construction_inventory/`) when `erp2.py` is run for the first time.