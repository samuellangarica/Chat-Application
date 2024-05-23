import socket
import tkinter as tk
from tkinter import messagebox

SERVER_IP = '10.7.1.45' 
SERVER_PORT = 5004
BUFFER_SIZE = 1024
CIPHER_KEY = 3  # Displacement key for Caesar cipher

class ClientConnection:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = None

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
            print(f"Connected to server at {self.server_ip}:{self.server_port}")
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def disconnect(self):
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None
            print("Disconnected from server")

    def send_request(self, request):
        if not self.client_socket:
            self.connect()
        
        try:
            encrypted_message = caesar_cipher(request, CIPHER_KEY)
            self.client_socket.sendall(encrypted_message.encode('utf-8'))
            encrypted_response = self.client_socket.recv(BUFFER_SIZE).decode('utf-8')
            decrypted_response = caesar_decipher(encrypted_response, CIPHER_KEY)
            return decrypted_response
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.disconnect()
            return None

def caesar_cipher(text, key):
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + key) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + key) % 26 + ord('A')))
        else:
            result.append(char)  # Non-alphabetic characters remain unchanged
    return ''.join(result)

def caesar_decipher(text, key):
    return caesar_cipher(text, 26 - key)  # Reverse the key for decryption

def handle_auth():
    global username
    username = auth_username_entry.get()
    password = auth_password_entry.get()
    request = f"Auth\n{username}\n{password}"
    response = connection.send_request(request)
    auth_response_label.config(text=response)
    if "successful" in response:
        show_authenticated_ui()

def handle_signup():
    username = signup_username_entry.get()
    password = signup_password_entry.get()
    request = f"Signup\n{username}\n{password}"
    response = connection.send_request(request)
    signup_response_label.config(text=response)
    if "successful" in response:
        show_authenticated_ui()

def handle_send_message_to_group():
    global username
    group_name = group_message_group_name_entry.get()
    message = group_message_entry.get("1.0", tk.END).strip()
    request = f"send_message_to_group\n{username}\n{group_name}\n{message}"
    response = connection.send_request(request)
    group_message_response_label.config(text=response)

def handle_create_group():
    global username
    group_name = group_name_entry.get()
    request = f"create_group\n{username}\n{group_name}"
    response = connection.send_request(request)
    group_response_label.config(text=response)

def show_authenticated_ui():
    login_signup_frame.pack_forget()
    authenticated_frame.pack(pady=10, fill=tk.X)

app = tk.Tk()
app.title("Client Application")

# Initialize the connection
connection = ClientConnection(SERVER_IP, SERVER_PORT)
connection.connect()

# Login or Signup UI
login_signup_frame = tk.Frame(app, padx=5, pady=5)
login_signup_frame.pack(pady=10, fill=tk.X)

# Authentication UI
auth_frame = tk.Frame(login_signup_frame)
auth_frame.pack(padx=10, pady=10, fill=tk.X)

auth_title_label = tk.Label(auth_frame, text="Authentication Service")
auth_title_label.grid(row=0, column=0, columnspan=2)

auth_username_label = tk.Label(auth_frame, text="Username:")
auth_username_label.grid(row=1, column=0)
auth_username_entry = tk.Entry(auth_frame)
auth_username_entry.grid(row=1, column=1)

auth_password_label = tk.Label(auth_frame, text="Password:")
auth_password_label.grid(row=2, column=0)
auth_password_entry = tk.Entry(auth_frame, show="*")
auth_password_entry.grid(row=2, column=1)

auth_button = tk.Button(auth_frame, text="Authenticate", command=handle_auth)
auth_button.grid(row=3, column=0, columnspan=2)

auth_response_label = tk.Label(auth_frame, text="")
auth_response_label.grid(row=4, column=0, columnspan=2)

# Signup UI
signup_frame = tk.Frame(login_signup_frame)
signup_frame.pack(padx=10, pady=10, fill=tk.X)

signup_title_label = tk.Label(signup_frame, text="Signup Service")
signup_title_label.grid(row=0, column=0, columnspan=2)

signup_username_label = tk.Label(signup_frame, text="Username:")
signup_username_label.grid(row=1, column=0)
signup_username_entry = tk.Entry(signup_frame)
signup_username_entry.grid(row=1, column=1)

signup_password_label = tk.Label(signup_frame, text="Password:")
signup_password_label.grid(row=2, column=0)
signup_password_entry = tk.Entry(signup_frame, show="*")
signup_password_entry.grid(row=2, column=1)

signup_button = tk.Button(signup_frame, text="Signup", command=handle_signup)
signup_button.grid(row=3, column=0, columnspan=2)

signup_response_label = tk.Label(signup_frame, text="")
signup_response_label.grid(row=4, column=0, columnspan=2)

# Authenticated UI
authenticated_frame = tk.Frame(app, padx=5, pady=5)

# Create Group Service UI
group_frame_wrapper = tk.Frame(authenticated_frame, padx=5, pady=5)
group_frame_wrapper.pack(pady=10, fill=tk.X)

group_frame = tk.Frame(group_frame_wrapper)
group_frame.pack(padx=10, pady=10, fill=tk.X)

group_title_label = tk.Label(group_frame, text="Create Group Service")
group_title_label.grid(row=0, column=0, columnspan=2)

group_name_label = tk.Label(group_frame, text="Group Name:")
group_name_label.grid(row=1, column=0)
group_name_entry = tk.Entry(group_frame)
group_name_entry.grid(row=1, column=1)

group_button = tk.Button(group_frame, text="Create Group", command=handle_create_group)
group_button.grid(row=2, column=0, columnspan=2)

group_response_label = tk.Label(group_frame, text="")
group_response_label.grid(row=3, column=0, columnspan=2)

# Send Message to Group Service UI
group_message_frame_wrapper = tk.Frame(authenticated_frame, padx=5, pady=5)
group_message_frame_wrapper.pack(pady=10, fill=tk.X)

group_message_frame = tk.Frame(group_message_frame_wrapper)
group_message_frame.pack(padx=10, pady=10, fill=tk.X)

group_message_title_label = tk.Label(group_message_frame, text="Send Message to Group Service")
group_message_title_label.grid(row=0, column=0, columnspan=2)

group_message_group_name_label = tk.Label(group_message_frame, text="Group Name:")
group_message_group_name_label.grid(row=1, column=0)
group_message_group_name_entry = tk.Entry(group_message_frame)
group_message_group_name_entry.grid(row=1, column=1)

group_message_label = tk.Label(group_message_frame, text="Message:")
group_message_label.grid(row=2, column=0)
group_message_entry = tk.Text(group_message_frame, height=5, width=30)
group_message_entry.grid(row=2, column=1)

group_message_button = tk.Button(group_message_frame, text="Send Message to Group", command=handle_send_message_to_group)
group_message_button.grid(row=3, column=0, columnspan=2)

group_message_response_label = tk.Label(group_message_frame, text="")
group_message_response_label.grid(row=4, column=0, columnspan=2)

# Clean up connection on exit
def on_closing():
    connection.disconnect()
    app.destroy()

app.protocol("WM_DELETE_WINDOW", on_closing)
app.mainloop()
