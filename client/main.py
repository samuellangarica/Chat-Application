import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog

SERVER_IP = '192.168.47.173'
SERVER_PORT = 5004
BUFFER_SIZE = 1024
CIPHER_KEY = 3  # Displacement key for Caesar cipher
BROADCAST_PORT = 5005

group_messages = {}

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


def handle_get_user_group_names():
    global username
    request = f"get_user_group_names\n{username}"
    response = connection.send_request(request)

    # Clear the listbox and update with new group names
    group_listbox.delete(0, tk.END)
    group_names = response.strip().split('\n')
    for group_name in group_names:
        group_listbox.insert(tk.END, group_name)
        group_listbox.itemconfig(tk.END, {'fg': 'black'})  # Initialize group items with default color


def handle_create_group():
    global username
    group_name = simpledialog.askstring("Create Group", "Enter group name:")
    if group_name:
        request = f"create_group\n{username}\n{group_name}"
        response = connection.send_request(request)
        messagebox.showinfo("Create Group", response)
        if "successfully" in response:
            handle_get_user_group_names()


def on_group_select(event):
    # Get the selected group name
    selected_group = group_listbox.get(group_listbox.curselection())
    
    # Change the selected group color back to the original (black)
    group_index = group_listbox.curselection()[0]
    group_listbox.itemconfig(group_index, {'fg': 'black'})

    # Update the current group label
    current_group_label.config(text=selected_group)

    # Request messages from the selected group
    request = f"get_messages_from_group\n{selected_group}"
    response = connection.send_request(request)

    # Update the group messages dictionary
    group_messages[selected_group] = response.strip()

    # Update the chat display with the new messages
    update_message_display(selected_group)


def handle_send_message():
    global username
    selected_group = group_listbox.get(tk.ACTIVE)
    if not selected_group:
        messagebox.showerror("Error", "No group selected")
        return

    message = message_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Message field is empty")
        return

    request = f"send_message_to_group\n{username}\n{selected_group}\n{message}"
    response = connection.send_request(request)
    message_entry.delete("1.0", tk.END)  # Clear the message entry field


def update_message_display(group_name):
    messages = group_messages.get(group_name, "")
    message_display.config(state=tk.NORMAL)
    message_display.delete(1.0, tk.END)
    message_display.insert(tk.END, messages)
    message_display.config(state=tk.DISABLED)

def show_add_user_dialog():
    selected_group = group_listbox.get(tk.ACTIVE)
    if not selected_group:
        messagebox.showerror("Error", "No group selected")
        return

    def add_user():
        username_to_add = username_entry.get()
        if not username_to_add:
            messagebox.showerror("Error", "Username field is empty")
            return

        request = f"add_user_to_group\n{selected_group}\n{username_to_add}"
        response = connection.send_request(request)
        messagebox.showinfo("Add User to Group", response)
        add_user_window.destroy()

    add_user_window = tk.Toplevel(app)
    add_user_window.title("Add User to Group")

    tk.Label(add_user_window, text="Username to add:").pack(pady=5)
    username_entry = tk.Entry(add_user_window)
    username_entry.pack(pady=5)

    tk.Button(add_user_window, text="Add User", command=add_user).pack(pady=5)

def show_delete_user_dialog():
    selected_group = group_listbox.get(tk.ACTIVE)
    if not selected_group:
        messagebox.showerror("Error", "No group selected")
        return

    def delete_user():
        username_to_delete = username_entry.get()
        if not username_to_delete:
            messagebox.showerror("Error", "Username field is empty")
            return

        request = f"delete_user\n{selected_group}\n{username_to_delete}"
        response = connection.send_request(request)
        messagebox.showinfo("Delete User from Group", response)
        delete_user_window.destroy()

    delete_user_window = tk.Toplevel(app)
    delete_user_window.title("Delete User from Group")

    tk.Label(delete_user_window, text="Username to delete:").pack(pady=5)
    username_entry = tk.Entry(delete_user_window)
    username_entry.pack(pady=5)

    tk.Button(delete_user_window, text="Delete User", command=delete_user).pack(pady=5)

def handle_delete_group():
    selected_group = group_listbox.get(tk.ACTIVE)
    if not selected_group:
        messagebox.showerror("Error", "No group selected")
        return

    request = f"delete_group\n{selected_group}"
    response = connection.send_request(request)
    messagebox.showinfo("Delete Group", response)
    if "successfully" in response:
        handle_get_user_group_names()

def listen_for_broadcast():
    udp_socket = socket.socket(socket.AF_INET, SOCK_DGRAM)
    udp_socket.bind(('', BROADCAST_PORT))

    while True:
        data, addr = udp_socket.recvfrom(BUFFER_SIZE * 10)
        message = data.decode('utf-8')

        if message == "update":
            handle_get_user_group_names()
        else:
            group_name, group_messages_content = message.split('\n', 1)
            group_messages[group_name] = group_messages_content.strip()
            
            # Change the color of the group name to red when a message is received
            group_index = group_listbox.get(0, tk.END).index(group_name)
            group_listbox.itemconfig(group_index, {'fg': 'red'})
            
            if group_listbox.get(tk.ACTIVE) == group_name:
                update_message_display(group_name)


def show_authenticated_ui():
    login_signup_frame.pack_forget()
    main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    handle_get_user_group_names()
    threading.Thread(target=listen_for_broadcast, daemon=True).start()


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

# Main UI after authentication
main_frame = tk.Frame(app, padx=5, pady=5)

# Left column: Group list
left_frame = tk.Frame(main_frame, padx=5, pady=5)
left_frame.pack(side=tk.LEFT, fill=tk.Y)

create_group_button = tk.Button(left_frame, text="Create Group", command=handle_create_group)
create_group_button.pack(fill=tk.X)

group_listbox = tk.Listbox(left_frame, selectmode=tk.SINGLE)
group_listbox.pack(side=tk.LEFT, fill=tk.Y, expand=True)
group_listbox.bind('<<ListboxSelect>>', on_group_select)

# Right column: Group messages
right_frame = tk.Frame(main_frame, padx=5, pady=5)
right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

group_header_frame = tk.Frame(right_frame)
group_header_frame.pack(fill=tk.X)

current_group_label = tk.Label(group_header_frame, text="Select a group", font=("Arial", 16))
current_group_label.pack(side=tk.LEFT)

add_user_button = tk.Button(group_header_frame, text="Add User", command=show_add_user_dialog)
add_user_button.pack(side=tk.LEFT, padx=10)

delete_user_button = tk.Button(group_header_frame, text="Delete User", command=show_delete_user_dialog)
delete_user_button.pack(side=tk.LEFT, padx=10)

delete_group_button = tk.Button(group_header_frame, text="Delete Group", command=handle_delete_group)
delete_group_button.pack(side=tk.LEFT, padx=10)

message_display = scrolledtext.ScrolledText(right_frame, state=tk.DISABLED, wrap=tk.WORD)
message_display.pack(padx=10, pady=10, fill=tk.BOTH,expand=True)

message_entry_frame = tk.Frame(right_frame)
message_entry_frame.pack(fill=tk.X, pady=5)

message_entry = tk.Text(message_entry_frame, height=5, width=50)
message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

send_button = tk.Button(message_entry_frame, text="Send", command=handle_send_message)
send_button.pack(side=tk.LEFT, padx=5)

# Clean up connection on exit
def on_closing():
    connection.disconnect()
    app.destroy()


app.protocol("WM_DELETE_WINDOW", on_closing)
app.mainloop()
