import socket
import tkinter as tk
from tkinter import messagebox

SERVER_IP = '192.168.4.175'  # Replace with your server's IP address
SERVER_PORT = 5004
BUFFER_SIZE = 1024
CIPHER_KEY = 3  # Basic displacement key for the Caesar cipher

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

def handle_send_message():
    global username
    message = message_entry.get("1.0", tk.END).strip()
    request = f"send_message\n{username}\n{message}"
    response = connection.send_request(request)
    message_response_label.config(text=response)

def handle_create_group():
    global username
    group_name = group_name_entry.get()
    request = f"create_group\n{username}\n{group_name}"
    response = connection.send_request(request)
    group_response_label.config(text=response)

app = tk.Tk()
app.title("Client Application")

# Initialize the connection
connection = ClientConnection(SERVER_IP, SERVER_PORT)
connection.connect()

# Authentication Service UI
auth_frame_wrapper = tk.Frame(app, bg="blue", padx=5, pady=5)
auth_frame_wrapper.pack(pady=10, fill=tk.X)

auth_frame = tk.Frame(auth_frame_wrapper, bg="white")
auth_frame.pack(padx=10, pady=10, fill=tk.X)

auth_title_label = tk.Label(auth_frame, text="Authentication Service", bg="white")
auth_title_label.grid(row=0, column=0, columnspan=2)

auth_username_label = tk.Label(auth_frame, text="Username:", bg="white")
auth_username_label.grid(row=1, column=0)
auth_username_entry = tk.Entry(auth_frame)
auth_username_entry.grid(row=1, column=1)

auth_password_label = tk.Label(auth_frame, text="Password:", bg="white")
auth_password_label.grid(row=2, column=0)
auth_password_entry = tk.Entry(auth_frame, show="*")
auth_password_entry.grid(row=2, column=1)

auth_button = tk.Button(auth_frame, text="Authenticate", command=handle_auth)
auth_button.grid(row=3, column=0, columnspan=2)

auth_response_label = tk.Label(auth_frame, text="", bg="white")
auth_response_label.grid(row=4, column=0, columnspan=2)

# Send Message Service UI
message_frame_wrapper = tk.Frame(app, bg="blue", padx=5, pady=5)
message_frame_wrapper.pack(pady=10, fill=tk.X)

message_frame = tk.Frame(message_frame_wrapper, bg="white")
message_frame.pack(padx=10, pady=10, fill=tk.X)

message_title_label = tk.Label(message_frame, text="Send Message Service", bg="white")
message_title_label.grid(row=0, column=0, columnspan=2)

message_label = tk.Label(message_frame, text="Message:", bg="white")
message_label.grid(row=1, column=0)
message_entry = tk.Text(message_frame, height=5, width=30)
message_entry.grid(row=1, column=1)

message_button = tk.Button(message_frame, text="Send Message", command=handle_send_message)
message_button.grid(row=2, column=0, columnspan=2)

message_response_label = tk.Label(message_frame, text="", bg="white")
message_response_label.grid(row=3, column=0, columnspan=2)

# Create Group Service UI
group_frame_wrapper = tk.Frame(app, bg="blue", padx=5, pady=5)
group_frame_wrapper.pack(pady=10, fill=tk.X)

group_frame = tk.Frame(group_frame_wrapper, bg="white")
group_frame.pack(padx=10, pady=10, fill=tk.X)

group_title_label = tk.Label(group_frame, text="Create Group Service", bg="white")
group_title_label.grid(row=0, column=0, columnspan=2)

group_name_label = tk.Label(group_frame, text="Group Name:", bg="white")
group_name_label.grid(row=1, column=0)
group_name_entry = tk.Entry(group_frame)
group_name_entry.grid(row=1, column=1)

group_button = tk.Button(group_frame, text="Create Group", command=handle_create_group)
group_button.grid(row=2, column=0, columnspan=2)

group_response_label = tk.Label(group_frame, text="", bg="white")
group_response_label.grid(row=3, column=0, columnspan=2)

# Clean up connection on exit
def on_closing():
    connection.disconnect()
    app.destroy()

app.protocol("WM_DELETE_WINDOW", on_closing)
app.mainloop()
