import tkinter as tk
from tkinter import ttk, messagebox

import sv_ttk
import platform
import base64

from installer_utils import get_data_path
from utils import WindowsCredentialLocker, LinuxCredentialLocker, generate_password, DataManager

class InstructionsPage(ttk.Frame):
    def __init__(self, root: tk.Tk) -> None:
        super().__init__(root)

        ttk.Label(self, text="Setup", font=("arial", 25)).pack(pady=10)
        ttk.Label(self, text="Now you just need to configure your email, password length and password.", font=("arial", 15)).pack(pady=10)
        ttk.Label(self, text="If you ended up here randomly something went wrong and you shouldn't continue. Go to the password recovery page on my Github.", font=("arial", 10)).pack(pady=10)

class CredentialsPage(ttk.Frame):
    def __init__(self, root: tk.Tk, show_page: object) -> None:
        super().__init__(root)

        self.show_page = show_page

        password_length_frame = ttk.Frame(self)
        password_length_frame.pack(pady=10)

        self.password_length = tk.IntVar(value=15)

        ttk.Scale(self, orient="horizontal", from_=6, to=40, variable=self.password_length, length=200, command=self.update_label).pack()

        self.length_label = ttk.Label(password_length_frame, text=f"Password Length: {self.password_length.get()}", font=("arial", 15))
        self.length_label.pack(side=tk.LEFT)

        email_frame = ttk.Frame(self)
        email_frame.pack(pady=10)
        ttk.Label(email_frame, text="              Email:  ", font=("arial", 15)).pack(side=tk.LEFT)

        self.email_entry = ttk.Entry(email_frame, width=30)
        self.email_entry.pack(side=tk.LEFT)

    def update_label(self, *args) -> None:
        self.length_label.configure(text=f"Password Length: {self.password_length.get()}")

    def verify(self) -> None:
        password_length = self.password_length.get()
        email = self.email_entry.get().strip()

        if email == "":
            if not messagebox.askokcancel("Blank Email", "The email field is blank. This means you won't have autofill email when entering passwords. Are you sure you wish to continue?"):
                return

        master_password = generate_password(password_length=30)

        system = platform.system()

        if system == "Windows":
            WindowsCredentialLocker.store_master_password(DataManager.CRED_MANAGER_TARGET_NAME, master_password)
        elif system == "Linux":
            LinuxCredentialLocker.store_master_password(DataManager.CRED_MANAGER_TARGET_NAME, master_password)

        data_path = get_data_path()

        with open(f"{data_path}/config.txt", 'w') as f:
            f.write(f"{email}\n{password_length}")

        DataManager().init()
        DataManager().set_device_salt()

        with open(f"{data_path}/passwords.json", 'w') as f:
            f.write(base64.b64encode(DataManager().encrypt_data(b"{}")[12:]).decode())

        self.show_page(2)

class FinishPage(ttk.Frame):
    def __init__(self, root: tk.Tk) -> None:
        super().__init__(root)

        ttk.Label(self, text="Setup Complete!", font=("arial", 25)).pack(pady=10)
        ttk.Label(self, text="You can now start using Whisper. It will launch automatically when you close this.", font=("arial", 15)).pack(pady=10)

class Installer:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("800x300")
        self.root.title("Whisper - Setup")
        self.root.iconbitmap("whisper.ico")
        
        sv_ttk.set_theme("dark")

        self.current_page = 0

        self.buttons_frame = ttk.Frame(self.root)
        self.buttons_frame.pack(side=tk.BOTTOM, anchor="e", padx=10, pady=10)

        self.back_btn = ttk.Button(self.buttons_frame, text="Back", command=lambda: self.show_page(self.current_page - 1))
        self.back_btn.pack(side=tk.LEFT) 

        self.next_btn = ttk.Button(self.buttons_frame, text="Next", command=lambda: self.show_page(self.current_page + 1))
        self.next_btn.pack(side=tk.LEFT) 

        self.instructions_page = InstructionsPage(self.root)
        self.credentials_page = CredentialsPage(self.root, self.show_page)
        self.finish_page = FinishPage(self.root)

        self.show_page(0)

    def show_page(self, page_index: int) -> None:
        self.instructions_page.pack_forget()
        self.credentials_page.pack_forget()
        self.finish_page.pack_forget()

        self.back_btn.pack_forget()
        self.next_btn.pack_forget()

        self.root.focus()

        if page_index == 0:
            self.instructions_page.pack()

            self.next_btn.pack(side=tk.LEFT)

        elif page_index == 1:
            self.credentials_page.pack()
            
            self.next_btn.pack(side=tk.LEFT)
            self.next_btn.configure(command=self.credentials_page.verify)

        elif page_index == 2:
            self.finish_page.pack()

            self.next_btn.pack(side=tk.LEFT)
            self.next_btn.configure(text="Finish", command=self.root.destroy)

        elif page_index == 3: self.root.destroy()

def runwizard() -> None:
    installer = Installer()
    installer.root.mainloop()