import tkinter as tk
import sv_ttk
import json
import csv
import secrets
import string

from tkinter import ttk, messagebox, filedialog

class PasswordManager:
    PASSWORDS_PATH = "./passwords.json"
    PASSWORD_LENGTH = 15

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("550x700")
        self.root.title("Whisper - Password Manager")

        sv_ttk.set_theme("dark")

        self.passwords_dict = {}
        self.load_passwords()

        ttk.Label(self.root, text="Whisper", font=("arial", 50)).pack()
        ttk.Label(self.root, text="Add passwords:", font=("arial", 20)).pack(pady=10)
        
        app_name_frame = ttk.Frame(self.root)
        app_name_frame.pack(pady=5)
        ttk.Label(app_name_frame, text="Site / App:  ", font=("arial")).pack(side=tk.LEFT)

        self.app_name_entry = ttk.Entry(app_name_frame)
        self.app_name_entry.pack(side=tk.LEFT)

        password_frame = ttk.Frame(self.root)
        password_frame.pack(pady=5)
        ttk.Label(password_frame, text="Password:  ", font=("arial")).pack(side=tk.LEFT)

        self.password_entry = ttk.Entry(password_frame)
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

        self.passwords_textbox = tk.Text(
            self.root,
            width=50,
            height=14,
            bg="#2e2e2e",
            fg="#ffffff",
            font=("arial"),
            relief="flat",
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.passwords_textbox.pack(pady=15)

        self.generate_new_password()
        self.populate_passwords_textbox()

        ttk.Button(self.root, text="Import csv file", command=self.import_csv_file).pack(pady=5)

    def showok(self, text: str) -> None:
        messagebox.showinfo("Success!", text)
    
    def showerr(self, text: str) -> None:
        messagebox.showerror("Error!", text)

    def load_passwords(self) -> None:
        with open(self.PASSWORDS_PATH, "r") as f:
            raw_json = f.read()

        self.passwords_dict = json.loads(raw_json)

    def save_passwords(self) -> None:
        with open(self.PASSWORDS_PATH, "w") as f:
            f.write(json.dumps(self.passwords_dict))

    def generate_new_password(self) -> None:
        new_password = ""

        characters = string.ascii_letters + string.digits * 2 + string.punctuation
        characters = characters.replace('"', '').replace("'", "").replace("&", "").replace("<", "").replace(">", "").replace("\\", "") # Remove commonly discarded characters by websites because injection

        for _ in range(self.PASSWORD_LENGTH):
            new_password += secrets.choice(characters)

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(1, new_password)

    def add_password(self) -> None:
        name = self.app_name_entry.get().strip()
        pwd = self.password_entry.get().strip()

        if name == "" or pwd == "":
            self.showerr("Name or password field is empty!")
            return

        self.app_name_entry.delete(0, tk.END)
        self.generate_new_password()

        if name in self.passwords_dict:
            add_anyway = self.showerr("Name already exists!")
            if not add_anyway: return

        self.passwords_dict[name] = pwd
        self.save_passwords()

        self.showok("Password saved.")

        self.populate_passwords_textbox()

    def stringify_passwords_dict(self) -> str:
        query = self.search_entry.get().strip()
        passwords_str = ""

        for app_name in self.passwords_dict:
            if query in app_name.strip().lower():
                passwords_str += f"{app_name} - {self.passwords_dict[app_name]}\n"

        return passwords_str

    def populate_passwords_textbox(self) -> None:
        passwords_str = self.stringify_passwords_dict()

        self.passwords_textbox.config(state=tk.NORMAL)
        self.passwords_textbox.delete("1.0", tk.END)
        self.passwords_textbox.insert("1.0", passwords_str)
        self.passwords_textbox.config(state=tk.DISABLED)

    def on_search_entry_changed(self, *args) -> None:
        self.populate_passwords_textbox()

    def import_csv_file(self) -> None:
        f = filedialog.askopenfile(filetypes=[("CSV files", "*.csv")])
        if f is None: return

        reader = csv.DictReader(f)

        for row in reader:
            self.passwords_dict[row['name']] = row['password']

        self.populate_passwords_textbox()
        self.save_passwords()
        self.showok("CSV file imported successfully!")

    def main(self) -> None:
        self.root.mainloop()

if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.main()