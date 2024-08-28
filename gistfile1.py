from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import json
import getpass

class PasswordManager:
    def __init__(self):
        self.master_password = None
        self.passwords = {}
        self.key = None

    def generate_key(self):
        # Use PBKDF2 to derive a key from the master password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt_value',  # Change this in a real application
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.master_password.encode())
        return key

    def encrypt_data(self, data):
        # Use Fernet symmetric encryption for data
        cipher = Fernet(self.key)
        encrypted_data = cipher.encrypt(data.encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        cipher = Fernet(self.key)
        decrypted_data = cipher.decrypt(encrypted_data).decode()
        return decrypted_data

    def load_passwords(self):
        try:
            with open('passwords.json', 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = self.decrypt_data(encrypted_data)
                self.passwords = json.loads(decrypted_data)
        except (FileNotFoundError, json.JSONDecodeError):
            self.passwords = {}

    def save_passwords(self):
        data = json.dumps(self.passwords)
        encrypted_data = self.encrypt_data(data)
        with open('passwords.json', 'wb') as file:
            file.write(encrypted_data)

    def set_master_password(self):
        master_password = getpass.getpass("Set your master password: ")
        self.master_password = master_password
        self.key = self.generate_key()

    def add_password(self, website, username, password):
        self.passwords[website] = {'username': username, 'password': password}
        self.save_passwords()

    def get_password(self, website):
        return self.passwords.get(website, None)

if __name__ == "__main__":
    password_manager = PasswordManager()

    # Set or load master password
    password_manager.set_master_password()

    # Load existing passwords
    password_manager.load_passwords()

    # Example: Add a password
    password_manager.add_password('example.com', 'user123', 'securepassword')

    # Example: Get a password
    result = password_manager.get_password('example.com')
    if result:
        print(f"Username: {result['username']}, Password: {result['password']}")
    else:
        print("Password not found.")


## Update 22/08/24
# Includes compatibility with multiple Operating Systems
# Encryption Improvements
# PBKDF2 to derive a key from the MP
# Fernet Symmetric Encryption

# CO-OP COLAB (GITHUB)

# JAVASCRIPT IMPLEMENTATION (THROUGH XCODE COLABORATOR)

# WITH ARRAYS
public static boolean occursExactlyOnce(int[] data, int key) {
   int count = 0;
   boolean found = false;
   for(int i=0; i < data.length; i++) {
      if(data[i] == key) { //if found
         if(found) { //if found before
            return false; //this is the second time
         }
         else { //if not found before
            found = true; //now it's found
         }
      }
   }
   return found == true; //ensure found once
}

# WITH ArrayLists
 public static boolean occursExactlyOnce(ArrayList<Integer> list, int key) {
   if(list.indexOf(key) >= 0)) { //if found
      if(list.indexOf(key) == list.lastIndexOf(key) { //if first and last occurrence is the same
    return true;
      }
   }
   return false; //in ALL other cases
}

#Creating An ArrayList Object
ArrayList<E> name = new ArrayList<E>();

#or

ArrayList<E> name = new ArrayList<>();



#SQL
create table sender (
senderID char(4) primary key,
SenderName varchar(30),
senderDOB date,
SenderEmail varchat(50),
senderAdress varchar(100));

create table Delivery (
deliveryID int,
DeliveryAdress varchar(100),
deliveryWeight float;
DeliveryCost float,
deliveryStatus varchat(10),


