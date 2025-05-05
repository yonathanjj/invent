
import uuid
import tkinter as tk
from tkinter import messagebox

def get_device_id():
    return hex(uuid.getnode())

# Create simple GUI
root = tk.Tk()
root.withdraw()  # Hide main window

device_id = get_device_id()
messagebox.showinfo("Device ID", f"Your Device ID is:\n{device_id}")
