import base64
import os
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

func = input('Lock a vault(L) or unlock a vault(U)?(l/u): ').lower()
if func == 'l':
    while True:
        password_prov = getpass()
        confirm_password = getpass('Confirm password: ')
        if password_prov == confirm_password:
            break
        else:
            print('Passwords do not match!')
            
    password = password_prov.encode()
    salt = b'nG\xc8\xb0\x84q\x00\x9a\xb8\xa9CT\x915\xa4\xa1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend = default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    filepath = input('Input .txt unencrypted vault filepath: ').encode('unicode-escape').decode().replace('////','//')
    with open(filepath, 'rb') as f:
        data=f.read()
        f.close()
    os.remove(filepath)
    f = Fernet(key)
    encrypted = f.encrypt(data)
    with open('vault_encrypted', 'wb') as f:
        f.write(encrypted)
if func == 'u':
    filepath = input('Input encrypted vault filepath: ').encode('unicode-escape').decode().replace('////','//')
    password_prov = getpass()
    password = password_prov.encode()
    salt = b'nG\xc8\xb0\x84q\x00\x9a\xb8\xa9CT\x915\xa4\xa1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend = default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    with open(filepath, 'rb') as f:
        data=f.read()
        f.close()
    f = Fernet(key)
    try:
        decrypted = f.decrypt(data)
        vault = decrypted.decode()
        print(vault)
    except:
        print('Wrong password! Vault could not be decrypted!')
