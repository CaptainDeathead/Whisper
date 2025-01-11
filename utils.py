import string
import secrets

def generate_password(password_length: int) -> str:
    new_password = ""

    characters = string.ascii_letters + string.digits * 2 + string.punctuation
    characters = characters.replace('"', '').replace("'", "").replace("&", "").replace("<", "").replace(">", "").replace("\\", "") # Remove commonly discarded characters by websites because injection

    for _ in range(password_length):
        new_password += secrets.choice(characters)

    return new_password