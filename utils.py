import string
import secrets
import os
import platform
import sys
import ctypes
import hashlib
import base64

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ctypes import wintypes
import keyring

from tkinter import messagebox, simpledialog
from time import time

class WindowsCredentialLocker:
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", wintypes.LPVOID),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]
        
    @staticmethod
    def get_current_windows_filetime() -> int:
        current_time = int(time() * 10000000) + 116444736000000000
        filetime = wintypes.FILETIME(current_time & 0xFFFFFFFF, (current_time >> 32) & 0xFFFFFFFF)
        return filetime

    @staticmethod
    def store_master_password(target_name: str, password: str) -> None:
        cred = WindowsCredentialLocker.CREDENTIAL()
        cred.Flags = 0
        cred.Type = WindowsCredentialLocker.CRED_TYPE_GENERIC
        cred.TargetName = target_name
        cred.CredentialBlob = ctypes.cast(ctypes.create_string_buffer(password.encode()), ctypes.POINTER(ctypes.c_char))
        cred.CredentialBlobSize = len(password)
        cred.Persist = WindowsCredentialLocker.CRED_PERSIST_LOCAL_MACHINE
        cred.Comment = None
        cred.LastWritten = WindowsCredentialLocker.get_current_windows_filetime()
        cred.AttributeCount = 0
        cred.Attributes = None
        cred.TargetAlias = None
        cred.UserName = None

        if not ctypes.windll.advapi32.CredWriteW(ctypes.byref(cred), 0):
            raise ctypes.WinError()

    @staticmethod
    def retrieve_master_password(target_name: str) -> str:
        pcred = ctypes.POINTER(WindowsCredentialLocker.CREDENTIAL)()
        if not ctypes.windll.advapi32.CredReadW(target_name, WindowsCredentialLocker.CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
            raise ctypes.WinError()
        
        cred = pcred.contents
        password = ctypes.wstring_at(cred.CredentialBlob, cred.CredentialBlobSize // 2)  # Convert bytes to string
        ctypes.windll.advapi32.CredFree(pcred)
        return password

class LinuxCredentialLocker:
    @staticmethod
    def store_master_password(service_name: str, password: str) -> None:
        keyring.set_password(service_name, "master_password", password)
    
    @staticmethod
    def retrieve_master_password(service_name: str) -> str:
        password = keyring.get_password(service_name, "master_password")

        if password is None:
            raise ValueError(f"No password found for service '{service_name}'")
        
        return password

class DataManager:
    CRED_MANAGER_TARGET_NAME = "plazma_whisper"

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

    def check_debugger_attached(self) -> None:
        system = platform.system()

        if system == "Windows":
            if ctypes.windll.kernel32.IsDebuggerPresent() != 0:
                error = "SOMEONE IS HOOKED TO THE PASSWORD MANAGER! Your passwords should be safe as we've caught them early, but please check all running processes and uninstall any suspicious apps."
                messagebox.showerror("FATAL ERROR - Debugger Present", error)
                sys.exit(1)

        elif system == "Linux":
            with open("/proc/self/status") as f:
                for line in f:
                    if "TracerPid" in line:
                        if int(line.split()[1]) > 0:
                            error = "SOMEONE IS HOOKED TO THE PASSWORD MANAGER! Your passwords should be safe as we've caught them early, but please check all running processes and uninstall any suspicious apps."
                            messagebox.showerror("FATAL ERROR - Debugger Present", error)
                            sys.exit(1)

    def get_device_salt(self, *args) -> bytes:
        system = platform.system()

        if system == "Windows":
            return WindowsCredentialLocker.retrieve_master_password('plazma_whisper_salt').encode()
        elif system == "Linux":
            return LinuxCredentialLocker.retrieve_master_password('plazma_whisper_salt').encode()

    def set_device_salt(self) -> None:
        # Return a unique hash device-specific
        salt = base64.b64encode(os.urandom(16)).decode()
        
        system = platform.system()
        
        if system == "Windows":
            WindowsCredentialLocker.store_master_password('plazma_whisper_salt', salt)
        elif system == "Linux":
            LinuxCredentialLocker.store_master_password('plazma_whisper_salt', salt)

    def get_master_password(self) -> str:
        system = platform.system()

        if system == "Windows":
            return WindowsCredentialLocker.retrieve_master_password(self.CRED_MANAGER_TARGET_NAME)
        elif system == "Linux":
            return LinuxCredentialLocker.retrieve_master_password(self.CRED_MANAGER_TARGET_NAME)

    def get_master_key(self) -> str:
        master_password = self.get_master_password()
        kdf = Scrypt(
            salt=self.get_device_salt(),
            length=32, # 32 bytes for AES-256
            n=2**14, # Work factor
            r=8, # Block size
            p=1 # Parallelism (1 core)
        )

        encryption_key = kdf.derive(master_password.encode())

        return encryption_key

    def encrypt_data(self, data: bytes) -> bytes:
        iv = os.urandom(12) # Generate random initialization vector

        with open(f"{self.DATA_PATH}/iv.txt", "w") as f:
            f.write(base64.b64encode(iv).decode())

        aesgcm = AESGCM(self.get_master_key())
        encrypted_data = aesgcm.encrypt(iv, data, None)
        return iv + encrypted_data # Store the IV with the encrypted data
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        with open(f"{self.DATA_PATH}/iv.txt", "r") as f:
            iv_b64 = f.read()

        iv = base64.b64decode(iv_b64)

        ciphertext = encrypted_data
        aesgcm = AESGCM(self.get_master_key())

        return aesgcm.decrypt(iv, ciphertext, None)

def get_data_path():
    system = platform.system()

    if system == "Windows":
        appdata_path = os.getenv("LOCALAPPDATA")
        
        if appdata_path:
            full_path = f"{appdata_path}/Plazma-Whisper"

            if os.path.isdir(full_path):
                return full_path
            else:
                error = "AppData path not created during setup! Reinstalling the application with full permissions should fix the problem."
                messagebox.showerror("ERROR - Reinstall", error)
                raise EnvironmentError(error)
        else:
            error = "LOCALAPPDATA environement variable not found! Try reinstalling with full permissions."
            messagebox.showerror("ERROR - Reinstall", error)
            raise EnvironmentError(error)

    elif system == "Linux":
        appdata_path = os.path.expanduser("~/.config")
        full_path = f"{appdata_path}/Plazma-Whisper"

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