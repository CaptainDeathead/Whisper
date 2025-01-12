import tkinter as tk
import sv_ttk

from tkinter import ttk, messagebox

from utils import generate_password, DataManager

class PasswordInfoPopup:
    def __init__(self, parent_root: tk.Tk, app_name: str, passwords_dict: dict, collect_password_update: object) -> None:
        self.parent_root = parent_root
        self.app_name = app_name
        self.passwords_dict = passwords_dict
        self.collect_password_update = collect_password_update

        self.delete = False
        self.apply = False
        self.done = False

        self.root = tk.Toplevel(self.parent_root)
        self.root.geometry("400x400")
        self.root.title(f"Whisper - '{app_name}' Info")
        self.root.iconbitmap("whisper.ico")
        self.root.focus()

        sv_ttk.set_theme("dark")

        self.original_email = self.passwords_dict[self.app_name]["email"]
        self.original_password = self.passwords_dict[self.app_name]["password"]

        ttk.Label(self.root, text="Password Info", font=("arial", 30)).pack(pady=10)
        ttk.Label(self.root, text=f"Site / App: {self.app_name}", font=("arial", 20)).pack(pady=10)

        email_frame = ttk.Frame(self.root)
        email_frame.pack(pady=10)
        ttk.Label(email_frame, text="       Email:  ", font=("arial", 15)).pack(side=tk.LEFT)

        self.email_entry = ttk.Entry(email_frame, width=30)
        self.email_entry.insert(1, passwords_dict[app_name]["email"])
        self.email_entry.pack(side=tk.LEFT)

        password_frame = ttk.Frame(self.root)
        password_frame.pack(pady=10)
        ttk.Label(password_frame, text="Password:  ", font=("arial", 15)).pack(side=tk.LEFT)

        self.password_entry = ttk.Entry(password_frame, width=30)
        self.password_entry.insert(1, passwords_dict[app_name]["password"])
        self.password_entry.pack(side=tk.LEFT)

        ttk.Button(self.root, text="Regenerate password", command=self.generate_new_password).pack(pady=5)

        ttk.Button(self.root, text="Delete", command=self.delete_password).pack(pady=20)

        end_buttons_frame = ttk.Frame(self.root)
        end_buttons_frame.pack(anchor="e", pady=10)

        ttk.Button(end_buttons_frame, text="Cancel", command=self.on_close).pack(side=tk.LEFT)
        ttk.Button(end_buttons_frame, text="Apply", command=self.apply_changes).pack(side=tk.LEFT, padx=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def exit(self) -> None:
        self.root.destroy()

        if self.delete:
            result = {"delete": "yep"}
        elif self.apply:
            result = self.passwords_dict[self.app_name]
        else:
            result = {}

        self.collect_password_update(self.app_name, result)
    
    def on_close(self) -> None:
        if self.email_entry.get().strip() != self.original_email or self.password_entry.get().strip() != self.original_password:
            if not messagebox.askyesno("Confirm Exit", "Are you sure you want to cancel? All changes will be reverted."):
                self.root.focus()
                return
        
        self.exit()

    def generate_new_password(self) -> None:
        new_password = generate_password(DataManager().PASSWORD_LENGTH)

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(1, new_password)

    def delete_password(self) -> None:
        self.delete = messagebox.askyesno("Delete password", "Are you sure? This will permanently remove this password from the database!")

        if self.delete:
            self.exit()
        else:
            self.root.focus()

    def apply_changes(self) -> None:
        self.apply = messagebox.askokcancel("Apply", "Are you sure? This will overwrite the existing email / password!")

        if self.apply:
            if self.password_entry.get().strip() == "":
                messagebox.showerror("Error", "The password cannot be blank! (Password reverted)")
                
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(1, self.passwords_dict[self.app_name]["password"])
                return

            self.passwords_dict[self.app_name]["email"] = self.email_entry.get().strip()
            self.passwords_dict[self.app_name]["password"] = self.password_entry.get().strip()

            self.exit()

    def main(self) -> None:
        self.root.mainloop()