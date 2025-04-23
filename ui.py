import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import os

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")

        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Poppins', 10))
        self.style.configure('TButton', font=('Poppins', 10))
        self.style.configure('TEntry', font=('Poppins', 10))

        # Sample data
        self.passwords = [
            {"app": "Netflix", "username": "test", "password": "test123", "email": "test@gmail.com"},
            {"app": "Netflix", "username": "user2", "password": "pass123", "email": "user2@gmail.com"}
        ]

        # Create all frames
        self.create_login_form()
        self.create_register_form()
        self.create_recovery_form()
        self.create_dashboard()
        self.create_edit_profile_form()
        self.create_add_password_form()
        self.create_edit_password_form()
        
        self.show_form("login")

    def create_login_form(self):
        self.login_frame = ttk.Frame(self.root)

        ttk.Label(self.login_frame, text="Login", font=('Poppins', 16, 'bold')).pack(pady=10)

        ttk.Label(self.login_frame, text="Username/Email:").pack(pady=(5, 0))
        self.login_email = ttk.Entry(self.login_frame)
        self.login_email.pack(pady=5, padx=20, fill=tk.X)

        ttk.Label(self.login_frame, text="Password:").pack(pady=(5, 0))
        self.login_password = ttk.Entry(self.login_frame, show="*")
        self.login_password.pack(pady=5, padx=20, fill=tk.X)

        ttk.Button(self.login_frame, text="Login", command=self.login).pack(pady=10)

        link_frame = ttk.Frame(self.login_frame)
        link_frame.pack(pady=5)
        ttk.Label(link_frame, text="Don't have an account?").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(link_frame, text="Register", command=lambda: self.show_form("register"), style='Link.TButton').pack(side=tk.LEFT)

        forgot_frame = ttk.Frame(self.login_frame)
        forgot_frame.pack(pady=20)
        ttk.Label(forgot_frame, text="Forgot Password?").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(forgot_frame, text="Recover Account", command=lambda: self.show_form("recover"), style='Link.TButton').pack(side=tk.LEFT)

    def create_register_form(self):
        self.register_frame = ttk.Frame(self.root)

        ttk.Label(self.register_frame, text="Register", font=('Poppins', 16, 'bold')).pack(pady=10)

        ttk.Label(self.register_frame, text="Name:").pack(pady=(5, 0))
        self.register_name = ttk.Entry(self.register_frame)
        self.register_name.pack(pady=5, padx=20, fill=tk.X)

        ttk.Label(self.register_frame, text="Recovery Email:").pack(pady=(5, 0))
        self.register_email = ttk.Entry(self.register_frame)
        self.register_email.pack(pady=5, padx=20, fill=tk.X)

        ttk.Label(self.register_frame, text="Password:").pack(pady=(5, 0))
        self.register_password = ttk.Entry(self.register_frame, show="*")
        self.register_password.pack(pady=5, padx=20, fill=tk.X)

        ttk.Button(self.register_frame, text="Register", command=self.register).pack(pady=10)

        login_link_frame = ttk.Frame(self.register_frame)
        login_link_frame.pack(pady=5)
        ttk.Label(login_link_frame, text="Already have an account?").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(login_link_frame, text="Login", command=lambda: self.show_form("login"), style='Link.TButton').pack(side=tk.LEFT)

    def create_recovery_form(self):
        self.recover_frame = ttk.Frame(self.root)

        ttk.Label(self.recover_frame, text="Account Recovery", font=('Poppins', 16, 'bold')).pack(pady=10)

        ttk.Label(self.recover_frame, text="Recovery Email:").pack(pady=(5, 0))
        self.recovery_email = ttk.Entry(self.recover_frame)
        self.recovery_email.pack(pady=5, padx=20, fill=tk.X)

        ttk.Button(self.recover_frame, text="Send", command=self.recover_account).pack(pady=10)

        back_btn = ttk.Button(self.recover_frame, text="Go Back", command=lambda: self.show_form("login"))
        back_btn.pack(pady=5)

    def create_dashboard(self):
        self.dashboard_frame = ttk.Frame(self.root)
        
        # Header with navigation buttons
        header_frame = ttk.Frame(self.dashboard_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(header_frame, text="Edit Profile", command=lambda: self.show_form("edit_profile")).pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(header_frame)
        self.search_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(header_frame, text="Search", command=self.search_passwords).pack(side=tk.LEFT, padx=5)
        ttk.Button(header_frame, text="Log Out", command=self.logout).pack(side=tk.RIGHT, padx=5)
        
        # Main content area with saved passwords
        content_frame = ttk.Frame(self.dashboard_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview to display saved passwords
        self.tree = ttk.Treeview(content_frame, columns=('Website/App', 'Username', 'Email'), show='headings')
        self.tree.heading('Website/App', text='Website/App')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Email', text='Email')
        self.tree.column('Website/App', width=150)
        self.tree.column('Username', width=150)
        self.tree.column('Email', width=200)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Add sample data
        self.refresh_password_list()
        
        # Add and Delete buttons
        button_frame = ttk.Frame(self.dashboard_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Add New", command=lambda: self.show_form("add_password")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit Selected", command=self.edit_selected_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_password).pack(side=tk.LEFT, padx=5)

    def create_edit_profile_form(self):
        self.edit_profile_frame = ttk.Frame(self.root)
        
        ttk.Label(self.edit_profile_frame, text="Edit Profile", font=('Poppins', 16, 'bold')).pack(pady=10)
        
        ttk.Label(self.edit_profile_frame, text="Username:").pack(pady=(5, 0))
        self.edit_username = ttk.Entry(self.edit_profile_frame)
        self.edit_username.pack(pady=5, padx=20, fill=tk.X)
        
        ttk.Label(self.edit_profile_frame, text="Password:").pack(pady=(5, 0))
        self.edit_password = ttk.Entry(self.edit_profile_frame, show="*")
        self.edit_password.pack(pady=5, padx=20, fill=tk.X)
        
        ttk.Label(self.edit_profile_frame, text="Recovery Email:").pack(pady=(5, 0))
        self.edit_recovery_email = ttk.Entry(self.edit_profile_frame)
        self.edit_recovery_email.pack(pady=5, padx=20, fill=tk.X)
        
        ttk.Label(self.edit_profile_frame, text="PIN:").pack(pady=(5, 0))
        self.edit_pin = ttk.Entry(self.edit_profile_frame, show="*")
        self.edit_pin.pack(pady=5, padx=20, fill=tk.X)
        
        button_frame = ttk.Frame(self.edit_profile_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Request New PIN", command=self.request_new_pin).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=lambda: self.show_form("dashboard")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Apply", command=self.save_profile_changes).pack(side=tk.LEFT, padx=5)

    def create_add_password_form(self):
        self.add_password_frame = ttk.Frame(self.root)
        
        ttk.Label(self.add_password_frame, text="Add New Password", font=('Poppins', 16, 'bold')).pack(pady=10)
        
        # App Name and Logo
        app_frame = ttk.Frame(self.add_password_frame)
        app_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(app_frame, text="App Name:").pack(side=tk.LEFT)
        self.add_app_name = ttk.Entry(app_frame)
        self.add_app_name.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.logo_label = ttk.Label(app_frame, text="Logo")
        self.logo_label.pack(side=tk.RIGHT, padx=10)
        
        # Username
        ttk.Label(self.add_password_frame, text="Username:").pack(pady=(5, 0))
        self.add_username = ttk.Entry(self.add_password_frame)
        self.add_username.pack(pady=5, padx=20, fill=tk.X)
        
        # Password
        ttk.Label(self.add_password_frame, text="Password:").pack(pady=(5, 0))
        self.add_password = ttk.Entry(self.add_password_frame, show="*")
        self.add_password.pack(pady=5, padx=20, fill=tk.X)
        
        # Email
        ttk.Label(self.add_password_frame, text="Email:").pack(pady=(5, 0))
        self.add_email = ttk.Entry(self.add_password_frame)
        self.add_email.pack(pady=5, padx=20, fill=tk.X)
        
        # Buttons
        button_frame = ttk.Frame(self.add_password_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Cancel", command=lambda: self.show_form("dashboard")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add", command=self.save_new_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Log Out", command=self.logout).pack(side=tk.RIGHT, padx=5)

    def create_edit_password_form(self):
        self.edit_password_frame = ttk.Frame(self.root)
        
        ttk.Label(self.edit_password_frame, text="Edit Password", font=('Poppins', 16, 'bold')).pack(pady=10)
        
        # App Name and Logo
        app_frame = ttk.Frame(self.edit_password_frame)
        app_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Label(app_frame, text="App Name:").pack(side=tk.LEFT)
        self.edit_app_name = ttk.Entry(app_frame)
        self.edit_app_name.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.edit_logo_label = ttk.Label(app_frame, text="Logo")
        self.edit_logo_label.pack(side=tk.RIGHT, padx=10)
        
        # Username
        ttk.Label(self.edit_password_frame, text="Username:").pack(pady=(5, 0))
        self.edit_password_username = ttk.Entry(self.edit_password_frame)
        self.edit_password_username.pack(pady=5, padx=20, fill=tk.X)
        
        # Password
        ttk.Label(self.edit_password_frame, text="Password:").pack(pady=(5, 0))
        self.edit_password_password = ttk.Entry(self.edit_password_frame, show="*")
        self.edit_password_password.pack(pady=5, padx=20, fill=tk.X)
        
        # Email
        ttk.Label(self.edit_password_frame, text="Email:").pack(pady=(5, 0))
        self.edit_password_email = ttk.Entry(self.edit_password_frame)
        self.edit_password_email.pack(pady=5, padx=20, fill=tk.X)
        
        # Buttons
        button_frame = ttk.Frame(self.edit_password_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Cancel", command=lambda: self.show_form("dashboard")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Apply", command=self.save_edited_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Log Out", command=self.logout).pack(side=tk.RIGHT, padx=5)

    def show_form(self, form_name):
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.recover_frame.pack_forget()
        self.dashboard_frame.pack_forget()
        self.edit_profile_frame.pack_forget()
        self.add_password_frame.pack_forget()
        self.edit_password_frame.pack_forget()

        if form_name == "login":
            self.login_frame.pack(fill=tk.BOTH, expand=True)
        elif form_name == "register":
            self.register_frame.pack(fill=tk.BOTH, expand=True)
        elif form_name == "recover":
            self.recover_frame.pack(fill=tk.BOTH, expand=True)
        elif form_name == "dashboard":
            self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
        elif form_name == "edit_profile":
            self.edit_profile_frame.pack(fill=tk.BOTH, expand=True)
        elif form_name == "add_password":
            self.add_password_frame.pack(fill=tk.BOTH, expand=True)
        elif form_name == "edit_password":
            self.edit_password_frame.pack(fill=tk.BOTH, expand=True)

    def login(self):
        email = self.login_email.get()
        password = self.login_password.get()

        if email and password:
            self.show_form("dashboard")
        else:
            messagebox.showerror("Error", "Please fill in all fields")

    def register(self):
        name = self.register_name.get()
        email = self.register_email.get()
        password = self.register_password.get()

        if all([name, email, password]):
            messagebox.showinfo("Register", "Registration successful! Please login.")
            self.show_form("login")
        else:
            messagebox.showerror("Error", "Please fill in all fields")

    def recover_account(self):
        email = self.recovery_email.get()
        if email:
            messagebox.showinfo("Recover", f"Recovery instructions sent to:\n{email}")
            self.show_form("login")
        else:
            messagebox.showerror("Error", "Please enter your recovery email")

    def logout(self):
        self.show_form("login")

    def search_passwords(self):
        search_term = self.search_entry.get().lower()
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if any(search_term in str(value).lower() for value in values):
                self.tree.selection_set(item)
                self.tree.focus(item)
                self.tree.see(item)
                break

    def refresh_password_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for pwd in self.passwords:
            self.tree.insert('', tk.END, values=(pwd['app'], pwd['username'], pwd['email']))

    def request_new_pin(self):
        messagebox.showinfo("PIN Request", "A new PIN has been sent to your recovery email")

    def save_profile_changes(self):
        messagebox.showinfo("Success", "Profile changes saved")
        self.show_form("dashboard")

    def save_new_password(self):
        app = self.add_app_name.get()
        username = self.add_username.get()
        password = self.add_password.get()
        email = self.add_email.get()
        
        if all([app, username, password, email]):
            self.passwords.append({
                "app": app,
                "username": username,
                "password": password,
                "email": email
            })
            self.refresh_password_list()
            messagebox.showinfo("Success", "Password added successfully")
            self.show_form("dashboard")
        else:
            messagebox.showerror("Error", "Please fill in all fields")

    def edit_selected_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select an item to edit")
            return
        
        item = selected_item[0]
        values = self.tree.item(item, 'values')
        
        # Find the password in our list
        for pwd in self.passwords:
            if pwd['app'] == values[0] and pwd['username'] == values[1] and pwd['email'] == values[2]:
                self.editing_password = pwd
                break
        
        # Populate the edit form
        self.edit_app_name.delete(0, tk.END)
        self.edit_app_name.insert(0, self.editing_password['app'])
        
        self.edit_password_username.delete(0, tk.END)
        self.edit_password_username.insert(0, self.editing_password['username'])
        
        self.edit_password_password.delete(0, tk.END)
        self.edit_password_password.insert(0, self.editing_password['password'])
        
        self.edit_password_email.delete(0, tk.END)
        self.edit_password_email.insert(0, self.editing_password['email'])
        
        self.show_form("edit_password")

    def save_edited_password(self):
        self.editing_password['app'] = self.edit_app_name.get()
        self.editing_password['username'] = self.edit_password_username.get()
        self.editing_password['password'] = self.edit_password_password.get()
        self.editing_password['email'] = self.edit_password_email.get()
        
        self.refresh_password_list()
        messagebox.showinfo("Success", "Password updated successfully")
        self.show_form("dashboard")

    def delete_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select an item to delete")
            return
        
        item = selected_item[0]
        values = self.tree.item(item, 'values')
        
        # Remove from our list
        for i, pwd in enumerate(self.passwords):
            if pwd['app'] == values[0] and pwd['username'] == values[1] and pwd['email'] == values[2]:
                del self.passwords[i]
                break
        
        self.refresh_password_list()
        messagebox.showinfo("Success", "Password deleted successfully")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()