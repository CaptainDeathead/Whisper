from tkinter import messagebox, simpledialog
from installer_utils import get_data_path

def runwizard() -> None:
    messagebox.showinfo("Congratulations!", "Thank you for installing Whisper! Now you just need to enter your email and configure a couple of things. (The email is just used for autofill to make it easier to add apps / sites)")

    email = simpledialog.askstring("Email (Optional)", "Email:")
    if email is None: email = ""

    password_length = simpledialog.askinteger("Password Length (Required)", "Desired password length (Between 8 - 40):", initialvalue=15, minvalue=8, maxvalue=40)
    if password_length is None: password_length = 15

    data_path = get_data_path()

    with open(f"{data_path}/passwords.json", 'w') as f:
        f.write("{}")

    with open(f"{data_path}/config.txt", 'w') as f:
        f.write(f"{email}\n{password_length}")

    messagebox.showinfo("Success!", "Whisper is all setup and ready to go!")