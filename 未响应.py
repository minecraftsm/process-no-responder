import tkinter as tk
from tkinter import messagebox
import win32api
import win32con
import ctypes
import psutil

# Windows API constants and functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
OpenThread = kernel32.OpenThread
SuspendThread = kernel32.SuspendThread
CloseHandle = kernel32.CloseHandle
TH32CS_SNAPTHREAD = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ThreadID", ctypes.c_ulong),
        ("th32OwnerProcessID", ctypes.c_ulong),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
    ]


def enumerate_threads(pid):
    thread_list = []
    h_thread_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if h_thread_snap == -1:
        return []

    te32 = THREADENTRY32()
    te32.dwSize = ctypes.sizeof(THREADENTRY32)

    if not kernel32.Thread32First(h_thread_snap, ctypes.byref(te32)):
        kernel32.CloseHandle(h_thread_snap)
        return []

    while True:
        if te32.th32OwnerProcessID == pid:
            thread_list.append(te32.th32ThreadID)
        if not kernel32.Thread32Next(h_thread_snap, ctypes.byref(te32)):
            break

    kernel32.CloseHandle(h_thread_snap)
    return thread_list


def suspend_process(pid):
    try:
        threads = enumerate_threads(pid)
        for thread_id in threads:
            thread_handle = OpenThread(THREAD_SUSPEND_RESUME, False, thread_id)
            if thread_handle:
                SuspendThread(thread_handle)
                CloseHandle(thread_handle)
        return True, f"Process with PID {pid} has been suspended."
    except Exception as e:
        return False, f"Failed to suspend process: {e}"


def find_pid_by_name(process_name):
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            if proc.info['name'].lower() == process_name.lower():
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None


def on_submit():
    process_name = entry.get()
    if not process_name:
        messagebox.showerror("Error", "Please enter a process name.")
        return

    pid = find_pid_by_name(process_name)
    if pid:
        success, message = suspend_process(pid)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)
    else:
        messagebox.showerror("Error", f"Process {process_name} not found")


# Create the main window
root = tk.Tk()
root.title("Suspend Process")
root.geometry("400x200")  # Set the window size to be twice as large

# Create and place the input label and entry
tk.Label(root, text="Enter process name:").pack(pady=20)
entry = tk.Entry(root, width=50)  # Increase the width of the entry field
entry.pack(pady=10)

# Create and place the submit button
tk.Button(root, text="Suspend", command=on_submit, width=20).pack(pady=20)  # Increase the width of the button

# Run the application
root.mainloop()
