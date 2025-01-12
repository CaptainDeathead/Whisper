import string
import secrets
import os
import platform

from tkinter import messagebox

class DataManager:
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(DataManager, cls).__new__(cls)

        return cls.instance

    def init(self) -> None:
        self.DATA_PATH = get_data_path()

        self.PASSWORDS_PATH = f"{self.DATA_PATH}/passwords.json"
        self.CONFIG_PATH = f"{self.DATA_PATH}/config.txt"

        with open(self.CONFIG_PATH, "r") as cfg:
            contents = cfg.read().splitlines()

        self.AUTOFILL_EMAIL = contents[0]
        self.PASSWORD_LENGTH = int(contents[1])

def get_data_path():
    system = platform.system()

    if system == "Windows":
        appdata_path = os.getenv("LOCALAPPDATA")

        os.makedirs(f"{appdata_path}/Plazma-Whisper", exist_ok=True)
        
        if appdata_path:
            full_path = f"{appdata_path}/Plazma-Whisper"

            if os.path.isdir(full_path):
                return full_path
            else:
                error = "Appdata path not created during setup! Reinstalling the application with full permissions should fix the problem."
                messagebox.showerror("ERROR - Reinstall", error)
                raise EnvironmentError(error)
        else:
            error = "LOCALAPPDATA environement variable not found! Try reinstalling with full permissions."
            messagebox.showerror("ERROR - Reinstall", error)
            raise EnvironmentError(error)

    elif system == "Linux":
        appdata_path = os.path.expanduser("~/.config")
        full_path = f"{appdata_path}/Plazma-Whisper"
        
        os.chdir(appdata_path)
        os.makedirs("Plazma-Whisper", exist_ok=True)

        if os.path.isdir(full_path):
            return full_path
        else:
            error = f"Data path not created during setup ({appdata_path})! Reinstalling the application with full permissions should fix the problem."
            messagebox.showerror("ERROR - Reinstall", error)
            raise EnvironmentError(error)

    else:
        error = f"Unsupported operating system: {system}!"
        messagebox.showerror("ERROR - Bad luck", error)
        raise EnvironmentError(error)

def generate_password(password_length: int) -> str:
    new_password = ""

    characters = string.ascii_letters + string.digits * 2 + string.punctuation
    characters = characters.replace('"', '').replace("'", "").replace("&", "").replace("<", "").replace(">", "").replace("\\", "") # Remove commonly discarded characters by websites because injection

    for _ in range(password_length):
        new_password += secrets.choice(characters)

    return new_password