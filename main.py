import tkinter as tk
import sv_ttk
import json
import csv
import base64

from tkinter import ttk, messagebox, filedialog
from pathlib import Path

from installer import runwizard
from password_info_popup import PasswordInfoPopup
from utils import generate_password, DataManager

class PasswordManager:
    def __init__(self) -> None:
        self.data_manager = DataManager()

        try: self.data_manager.init()
        except:
            runwizard()

        self.root = tk.Tk()
        self.root.geometry("550x750")
        self.root.title("Whisper - Password Manager")
        self.root.iconbitmap("whisper.ico")

        sv_ttk.set_theme("dark")

        self.passwords_dict = {}
        self.load_passwords()

        ttk.Label(self.root, text="Whisper", font=("arial", 50)).pack()
        ttk.Label(self.root, text="Add passwords:", font=("arial", 20)).pack(pady=10)
        
        app_name_frame = ttk.Frame(self.root)
        app_name_frame.pack(pady=5)
        ttk.Label(app_name_frame, text="Site / App:  ", font=("arial")).pack(side=tk.LEFT)

        self.app_name_entry = ttk.Entry(app_name_frame, width=30)
        self.app_name_entry.pack(side=tk.LEFT)

        email_frame = ttk.Frame(self.root)
        email_frame.pack(pady=5)
        ttk.Label(email_frame, text="       Email:  ", font=("arial")).pack(side=tk.LEFT)

        self.email_entry = ttk.Entry(email_frame, width=30)
        self.email_entry.insert(1, self.data_manager.AUTOFILL_EMAIL)
        self.email_entry.pack(side=tk.LEFT)

        password_frame = ttk.Frame(self.root)
        password_frame.pack(pady=5)
        ttk.Label(password_frame, text="Password:  ", font=("arial")).pack(side=tk.LEFT)

        self.password_entry = ttk.Entry(password_frame, width=30)
        self.password_entry.pack(side=tk.LEFT)

        new_password_buttons_frame = ttk.Frame(self.root)
        new_password_buttons_frame.pack(pady=10)

        self.add_btn = ttk.Button(new_password_buttons_frame, text="Add", command=self.add_password)
        self.add_btn.pack(side=tk.LEFT, padx=5)

        self.regen_btn = ttk.Button(new_password_buttons_frame, text="Regenerate", command=self.generate_new_password)
        self.regen_btn.pack(side=tk.LEFT, padx=5)

        ttk.Label(self.root, text="Find passwords:", font=("arial", 20)).pack(pady=10)

        search_app_name_frame = ttk.Frame(self.root)
        search_app_name_frame.pack(pady=5)
        ttk.Label(search_app_name_frame, text="Search:  ", font=("arial")).pack(side=tk.LEFT)

        self.search_query = tk.StringVar()
        self.search_query.trace_add("write", self.on_search_entry_changed)

        self.search_entry = ttk.Entry(search_app_name_frame, textvariable=self.search_query)
        self.search_entry.pack(side=tk.LEFT)

        self.password_list_canvas = tk.Canvas(self.root)

        self.password_list_outer_frame = ttk.Frame(self.root, width=500, height=500)
        self.password_canvas = tk.Canvas(self.password_list_outer_frame)
        self.password_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        self.password_list_scrollbar = ttk.Scrollbar(self.password_list_outer_frame, orient="vertical", command=self.password_canvas.yview)
        self.password_list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.password_canvas.configure(yscrollcommand=self.password_list_scrollbar.set)
        self.password_canvas.bind(
            "<Configure>", lambda e: self.password_canvas.configure(scrollregion=self.password_canvas.bbox("all"))
        )

        self.password_list_frame = ttk.Frame(self.password_canvas, width=500, height=500)
        self.password_list_frame.pack(pady=15)
        self.password_buttons = []

        self.password_canvas.create_window((0, 0), window=self.password_list_frame, anchor="nw")
        self.password_list_outer_frame.pack(pady=15)

        self.generate_new_password()
        self.populate_passwords_textbox()

        csv_frame = ttk.Frame(self.root)
        csv_frame.pack(pady=5)

        ttk.Button(csv_frame, text="Import csv file", command=self.import_csv_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(csv_frame, text="Export csv file", command=self.export_csv_file).pack(side=tk.LEFT, padx=5)

    def showok(self, text: str) -> None:
        messagebox.showinfo("Success!", text)
    
    def showerr(self, text: str) -> None:
        messagebox.showerror("Error!", text)

    def load_passwords(self) -> None:
        with open(self.data_manager.PASSWORDS_PATH, "r") as f:
            raw_json_encrypted_b64 = f.read()

        raw_json_encrypted = base64.b64decode(raw_json_encrypted_b64)
        raw_json = self.data_manager.decrypt_data(raw_json_encrypted)

        self.passwords_dict = json.loads(raw_json.decode())

    def save_passwords(self) -> None:
        raw_json = json.dumps(self.passwords_dict)
        raw_json_encrypted = self.data_manager.encrypt_data(raw_json.encode())[12:]

        with open(self.data_manager.PASSWORDS_PATH, "w") as f:
            f.write(base64.b64encode(raw_json_encrypted).decode())

    def generate_new_password(self) -> None:
        new_password = generate_password(self.data_manager.PASSWORD_LENGTH)

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(1, new_password)

    def add_password(self) -> None:
        name = self.app_name_entry.get().strip()
        email = self.email_entry.get().strip()
        pwd = self.password_entry.get().strip()

        if name == "" or pwd == "":
            self.showerr("Name or password field is empty!")
            return

        self.app_name_entry.delete(0, tk.END)
        self.generate_new_password()

        if name in self.passwords_dict:
            self.showerr("Name already exists!")
            return

        self.passwords_dict[name] = {"email": email, "password": pwd}
        self.save_passwords()

        self.showok("Password saved.")

        self.populate_passwords_textbox()

    def collect_password_update(self, name: str, result: dict) -> None:
        if result.get("delete") is not None:
            del self.passwords_dict[name]
            self.showok(f"{name} successfully deleted!")

            self.populate_passwords_textbox()
        else:
            self.passwords_dict[name].update(result)
            
            if result != {}:
                messagebox.showinfo("Success", f"The email / password for {name} successfully updated.")

        self.save_passwords()

    def view_password_info(self, name: str) -> None:
        password_info_popup = PasswordInfoPopup(self.root, name, self.passwords_dict, self.collect_password_update)
        password_info_popup.main()

    def filter_passwords_dict(self) -> list[str]:
        query = self.search_entry.get().strip()
        password_names = []

        for app_name in self.passwords_dict:
            if query in app_name.strip().lower():
                password_names.append(app_name)

        return password_names

    def populate_passwords_textbox(self) -> None:
        for button in self.password_buttons:
            button.destroy()

        self.password_buttons = []

        for name in self.filter_passwords_dict():
            self.password_buttons.append(ttk.Button(self.password_list_frame, text=f"{name}", width=45, command=lambda name=name: self.view_password_info(name)))
            self.password_buttons[-1].pack()

        self.password_list_frame.update_idletasks()
        self.password_canvas.config(scrollregion=self.password_canvas.bbox("all"))

    def on_search_entry_changed(self, *args) -> None:
        self.populate_passwords_textbox()

    def import_csv_file(self) -> None:
        f = filedialog.askopenfile(filetypes=[("CSV files", "*.csv")])
        if f is None: return

        reader = csv.DictReader(f)

        for row in reader:
            self.passwords_dict[row['name']] = {"email": row.get('email', row.get('username', '')), "password": row['password']}

        self.populate_passwords_textbox()
        self.save_passwords()
        self.showok("CSV file imported successfully!")

    def export_csv_file(self) -> None:
        downloads_folder = str(Path.home() / "Downloads")

        with open(f"{downloads_folder}/passwords.csv", "w") as f:
            writer = csv.DictWriter(f, ["name", "email", "password"])
            writer.writeheader()

            for name, value in self.passwords_dict.items():
                data = {"name": name, "email": value["email"], "password": value["password"]}
                writer.writerow(data)

        self.showok("Passwords exported as 'passwords.csv' in your downloads folder.\nPlease keep them safe!")

    def main(self) -> None:
        self.root.mainloop()

if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.main()