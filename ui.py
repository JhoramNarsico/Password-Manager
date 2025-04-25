import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import os
import re

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("900x650")
        self.root.configure(bg="#f5f7fa")
        
        # Set theme colors
        self.primary_color = "#4a6fa5"
        self.secondary_color = "#166088"
        self.accent_color = "#4fc3f7"
        self.bg_color = "#f5f7fa"
        self.text_color = "#333333"
        self.error_color = "#e74c3c"
        self.success_color = "#2ecc71"
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, 
                           font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), 
                           foreground=self.secondary_color)
        self.style.configure('TButton', font=('Segoe UI', 10), borderwidth=1)
        self.style.configure('Primary.TButton', foreground='white', background=self.primary_color,
                           borderwidth=0, padding=6)
        self.style.configure('Secondary.TButton', foreground='white', background=self.secondary_color,
                           borderwidth=0, padding=6)
        self.style.configure('Accent.TButton', foreground='white', background=self.accent_color,
                           borderwidth=0, padding=6)
        self.style.map('Primary.TButton', 
                      background=[('active', self.secondary_color), ('pressed', self.secondary_color)])
        self.style.map('Secondary.TButton', 
                      background=[('active', self.primary_color), ('pressed', self.primary_color)])
        self.style.configure('TEntry', fieldbackground='white', bordercolor=self.primary_color,
                           lightcolor=self.primary_color, darkcolor=self.primary_color,
                           padding=5, relief='flat')
        self.style.configure('Treeview', background='white', fieldbackground='white', 
                           foreground=self.text_color, rowheight=25)
        self.style.configure('Treeview.Heading', background=self.primary_color, 
                           foreground='white', font=('Segoe UI', 10, 'bold'))
        self.style.map('Treeview', background=[('selected', self.accent_color)])
        
        # Sample data (to be replaced with MySQL database)
        self.passwords = [
            {"app": "Netflix", "username": "test", "password": "test123", "email": "test@gmail.com"},
            {"app": "Amazon", "username": "user2", "password": "pass123", "email": "user2@gmail.com"},
            {"app": "GitHub", "username": "dev1", "password": "github456", "email": "dev@example.com"}
        ]
        
        # Store current user (for database integration)
        self.current_user = None

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
        self.login_frame = ttk.Frame(self.root, style='TFrame')
        header_frame = ttk.Frame(self.login_frame, style='TFrame')
        header_frame.pack(pady=(40, 20))
        ttk.Label(header_frame, text="🔒", font=('Segoe UI', 24)).pack()
        ttk.Label(header_frame, text="Welcome Back", style='Title.TLabel').pack(pady=5)
        ttk.Label(header_frame, text="Login to access your passwords", font=('Segoe UI', 10)).pack()

        form_frame = ttk.Frame(self.login_frame, style='TFrame')
        form_frame.pack(pady=10, padx=40, fill=tk.X)
        ttk.Label(form_frame, text="Username/Email:").pack(pady=(10, 0), anchor=tk.W)
        self.login_email = ttk.Entry(form_frame, style='TEntry')
        self.login_email.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Password:").pack(pady=(10, 0), anchor=tk.W)
        self.login_password = ttk.Entry(form_frame, show="•", style='TEntry')
        self.login_password.pack(pady=5, fill=tk.X)

        ttk.Button(self.login_frame, text="Login", style='Primary.TButton', 
                  command=self.login).pack(pady=20, ipadx=20)

        link_frame = ttk.Frame(self.login_frame, style='TFrame')
        link_frame.pack(pady=10)
        ttk.Label(link_frame, text="Don't have an account?").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(link_frame, text="Register", command=lambda: self.show_form("register"), 
                  style='Secondary.TButton').pack(side=tk.LEFT)

        forgot_frame = ttk.Frame(self.login_frame, style='TFrame')
        forgot_frame.pack(pady=10)
        ttk.Label(forgot_frame, text="Forgot Password?").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(forgot_frame, text="Recover Account", command=lambda: self.show_form("recover"), 
                  style='Secondary.TButton').pack(side=tk.LEFT)

    def create_register_form(self):
        self.register_frame = ttk.Frame(self.root, style='TFrame')
        header_frame = ttk.Frame(self.register_frame, style='TFrame')
        header_frame.pack(pady=(40, 20))
        ttk.Label(header_frame, text="👤", font=('Segoe UI', 24)).pack()
        ttk.Label(header_frame, text="Create Account", style='Title.TLabel').pack(pady=5)
        ttk.Label(header_frame, text="Register for a new account", font=('Segoe UI', 10)).pack()

        form_frame = ttk.Frame(self.register_frame, style='TFrame')
        form_frame.pack(pady=10, padx=40, fill=tk.X)
        ttk.Label(form_frame, text="Name:").pack(pady=(10, 0), anchor=tk.W)
        self.register_name = ttk.Entry(form_frame, style='TEntry')
        self.register_name.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Recovery Email:").pack(pady=(10, 0), anchor=tk.W)
        self.register_email = ttk.Entry(form_frame, style='TEntry')
        self.register_email.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Password:").pack(pady=(10, 0), anchor=tk.W)
        self.register_password = ttk.Entry(form_frame, show="•", style='TEntry')
        self.register_password.pack(pady=5, fill=tk.X)

        ttk.Button(self.register_frame, text="Register", style='Primary.TButton', 
                  command=self.register).pack(pady=20, ipadx=20)

        login_link_frame = ttk.Frame(self.register_frame, style='TFrame')
        login_link_frame.pack(pady=10)
        ttk.Label(login_link_frame, text="Already have an account?").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(login_link_frame, text="Login", command=lambda: self.show_form("login"), 
                  style='Secondary.TButton').pack(side=tk.LEFT)

    def create_recovery_form(self):
        self.recover_frame = ttk.Frame(self.root, style='TFrame')
        header_frame = ttk.Frame(self.recover_frame, style='TFrame')
        header_frame.pack(pady=(40, 20))
        ttk.Label(header_frame, text="🔑", font=('Segoe UI', 24)).pack()
        ttk.Label(header_frame, text="Account Recovery", style='Title.TLabel').pack(pady=5)
        ttk.Label(header_frame, text="Enter your recovery email", font=('Segoe UI', 10)).pack()

        form_frame = ttk.Frame(self.recover_frame, style='TFrame')
        form_frame.pack(pady=20, padx=40, fill=tk.X)
        ttk.Label(form_frame, text="Recovery Email:").pack(pady=(10, 0), anchor=tk.W)
        self.recovery_email = ttk.Entry(form_frame, style='TEntry')
        self.recovery_email.pack(pady=5, fill=tk.X)

        button_frame = ttk.Frame(self.recover_frame, style='TFrame')
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Send Recovery Email", style='Primary.TButton', 
                  command=self.recover_account).pack(side=tk.LEFT, padx=5, ipadx=10)
        ttk.Button(button_frame, text="Back to Login", style='Secondary.TButton', 
                  command=lambda: self.show_form("login")).pack(side=tk.LEFT, padx=5)

    def create_dashboard(self):
        self.dashboard_frame = ttk.Frame(self.root, style='TFrame')
        header_frame = ttk.Frame(self.dashboard_frame, style='TFrame')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        ttk.Button(header_frame, text="Edit Profile", style='Secondary.TButton',
                  command=lambda: self.show_form("edit_profile")).pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(header_frame, style='TEntry')
        self.search_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(header_frame, text="Search", style='Secondary.TButton',
                  command=self.search_passwords).pack(side=tk.LEFT, padx=5)
        ttk.Button(header_frame, text="Log Out", style='Secondary.TButton',
                  command=self.logout).pack(side=tk.RIGHT, padx=5)

        title_frame = ttk.Frame(self.dashboard_frame, style='TFrame')
        title_frame.pack(pady=(10, 20))
        ttk.Label(title_frame, text="🔐 Your Passwords", style='Title.TLabel').pack()

        content_frame = ttk.Frame(self.dashboard_frame, style='TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        tree_frame = ttk.Frame(content_frame, style='TFrame')
        tree_frame.pack(fill=tk.BOTH, expand=True)
        scroll_y = ttk.Scrollbar(tree_frame)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree = ttk.Treeview(tree_frame, columns=('Website/App', 'Username', 'Email'), 
                                show='headings', yscrollcommand=scroll_y.set)
        scroll_y.config(command=self.tree.yview)
        self.tree.heading('Website/App', text='Website/App')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Email', text='Email')
        self.tree.column('Website/App', width=200, anchor=tk.W)
        self.tree.column('Username', width=150, anchor=tk.W)
        self.tree.column('Email', width=250, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.refresh_password_list()

        button_frame = ttk.Frame(self.dashboard_frame, style='TFrame')
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        ttk.Button(button_frame, text="Add New", style='Primary.TButton',
                  command=lambda: self.show_form("add_password")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit Selected", style='Secondary.TButton',
                  command=self.edit_selected_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Selected", style='Secondary.TButton',
                  command=self.delete_password).pack(side=tk.LEFT, padx=5)

    def create_edit_profile_form(self):
        self.edit_profile_frame = ttk.Frame(self.root, style='TFrame')
        header_frame = ttk.Frame(self.edit_profile_frame, style='TFrame')
        header_frame.pack(pady=(20, 10))
        ttk.Label(header_frame, text="⚙️ Edit Profile", style='Title.TLabel').pack()

        form_frame = ttk.Frame(self.edit_profile_frame, style='TFrame')
        form_frame.pack(pady=10, padx=40, fill=tk.X)
        ttk.Label(form_frame, text="Username:").pack(pady=(10, 0), anchor=tk.W)
        self.edit_username = ttk.Entry(form_frame, style='TEntry')
        self.edit_username.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Password:").pack(pady=(10, 0), anchor=tk.W)
        self.edit_password = ttk.Entry(form_frame, show="•", style='TEntry')
        self.edit_password.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Recovery Email:").pack(pady=(10, 0), anchor=tk.W)
        self.edit_recovery_email = ttk.Entry(form_frame, style='TEntry')
        self.edit_recovery_email.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="PIN:").pack(pady=(10, 0), anchor=tk.W)
        self.edit_pin = ttk.Entry(form_frame, show="•", style='TEntry')
        self.edit_pin.pack(pady=5, fill=tk.X)

        button_frame = ttk.Frame(self.edit_profile_frame, style='TFrame')
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Request New PIN", style='Secondary.TButton',
                  command=self.request_new_pin).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", style='Secondary.TButton',
                  command=lambda: self.show_form("dashboard")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Apply Changes", style='Primary.TButton',
                  command=self.save_profile_changes).pack(side=tk.LEFT, padx=5)

    def create_add_password_form(self):
        self.add_password_frame = ttk.Frame(self.root, style='TFrame')
        header_frame = ttk.Frame(self.add_password_frame, style='TFrame')
        header_frame.pack(pady=(20, 10))
        ttk.Label(header_frame, text="➕ Add New Password", style='Title.TLabel').pack()

        form_frame = ttk.Frame(self.add_password_frame, style='TFrame')
        form_frame.pack(pady=10, padx=40, fill=tk.X)
        app_frame = ttk.Frame(form_frame, style='TFrame')
        app_frame.pack(fill=tk.X, pady=5)
        ttk.Label(app_frame, text="App Name:").pack(side=tk.LEFT)
        self.add_app_name = ttk.Entry(app_frame, style='TEntry')
        self.add_app_name.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.logo_label = ttk.Label(app_frame, text="🌐", font=('Segoe UI', 14))
        self.logo_label.pack(side=tk.RIGHT, padx=10)

        ttk.Label(form_frame, text="Username:").pack(pady=(10, 0), anchor=tk.W)
        self.add_username = ttk.Entry(form_frame, style='TEntry')
        self.add_username.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Password:").pack(pady=(10, 0), anchor=tk.W)
        self.add_password = ttk.Entry(form_frame, show="•", style='TEntry')
        self.add_password.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Email:").pack(pady=(10, 0), anchor=tk.W)
        self.add_email = ttk.Entry(form_frame, style='TEntry')
        self.add_email.pack(pady=5, fill=tk.X)

        button_frame = ttk.Frame(self.add_password_frame, style='TFrame')
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Cancel", style='Secondary.TButton',
                  command=lambda: self.show_form("dashboard")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add Password", style='Primary.TButton',
                  command=self.save_new_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Log Out", style='Secondary.TButton',
                  command=self.logout).pack(side=tk.RIGHT, padx=5)

    def create_edit_password_form(self):
        self.edit_password_frame = ttk.Frame(self.root, style='TFrame')
        header_frame = ttk.Frame(self.edit_password_frame, style='TFrame')
        header_frame.pack(pady=(20, 10))
        ttk.Label(header_frame, text="✏️ Edit Password", style='Title.TLabel').pack()

        form_frame = ttk.Frame(self.edit_password_frame, style='TFrame')
        form_frame.pack(pady=10, padx=40, fill=tk.X)
        app_frame = ttk.Frame(form_frame, style='TFrame')
        app_frame.pack(fill=tk.X, pady=5)
        ttk.Label(app_frame, text="App Name:").pack(side=tk.LEFT)
        self.edit_app_name = ttk.Entry(app_frame, style='TEntry')
        self.edit_app_name.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.edit_logo_label = ttk.Label(app_frame, text="🌐", font=('Segoe UI', 14))
        self.edit_logo_label.pack(side=tk.RIGHT, padx=10)

        ttk.Label(form_frame, text="Username:").pack(pady=(10, 0), anchor=tk.W)
        self.edit_password_username = ttk.Entry(form_frame, style='TEntry')
        self.edit_password_username.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Password:").pack(pady=(10, 0), anchor=tk.W)
        self.edit_password_password = ttk.Entry(form_frame, show="•", style='TEntry')
        self.edit_password_password.pack(pady=5, fill=tk.X)
        ttk.Label(form_frame, text="Email:").pack(pady=(10, 0), anchor=tk.W)
        self.edit_password_email = ttk.Entry(form_frame, style='TEntry')
        self.edit_password_email.pack(pady=5, fill=tk.X)

        button_frame = ttk.Frame(self.edit_password_frame, style='TFrame')
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Cancel", style='Secondary.TButton',
                  command=lambda: self.show_form("dashboard")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Changes", style='Primary.TButton',
                  command=self.save_edited_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Log Out", style='Secondary.TButton',
                  command=self.logout).pack(side=tk.RIGHT, padx=5)

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

    def validate_email(self, email):
        """Validate email format."""
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    def login(self):
        email = self.login_email.get().strip()
        password = self.login_password.get().strip()

        if not email or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return

        # TODO: Replace with MySQL query
        # Example: SELECT * FROM users WHERE email = ? AND password = ?
        # If user exists, set self.current_user = {'id': user_id, 'email': email, ...}
        self.current_user = {'email': email}  # Placeholder
        self.show_form("dashboard")
        self.login_email.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        messagebox.showinfo("Success", "Logged in successfully")

    def register(self):
        name = self.register_name.get().strip()
        email = self.register_email.get().strip()
        password = self.register_password.get().strip()

        if not all([name, email, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return

        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return

        # TODO: Replace with MySQL query
        # Example: INSERT INTO users (name, email, password) VALUES (?, ?, ?)
        self.current_user = {'name': name, 'email': email}  # Placeholder
        messagebox.showinfo("Success", "Registration successful! Please login.")
        self.show_form("login")
        self.register_name.delete(0, tk.END)
        self.register_email.delete(0, tk.END)
        self.register_password.delete(0, tk.END)

    def recover_account(self):
        email = self.recovery_email.get().strip()
        
        if not email:
            messagebox.showerror("Error", "Please enter your recovery email")
            return
        
        if not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return

        # TODO: Replace with MySQL query to verify email and send recovery email
        # Example: SELECT * FROM users WHERE email = ?
        messagebox.showinfo("Success", f"Recovery instructions sent to:\n{email}")
        self.show_form("login")
        self.recovery_email.delete(0, tk.END)

    def logout(self):
        self.current_user = None
        self.passwords = []  # Clear in-memory data
        self.refresh_password_list()
        self.show_form("login")
        messagebox.showinfo("Success", "Logged out successfully")

    def search_passwords(self):
        search_term = self.search_entry.get().strip().lower()
        if not search_term:
            self.refresh_password_list()
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for pwd in self.passwords:
            if any(search_term in str(value).lower() for value in pwd.values()):
                self.tree.insert('', tk.END, values=(pwd['app'], pwd['username'], pwd['email']))

    def refresh_password_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # TODO: Replace with MySQL query
        # Example: SELECT app, username, email FROM passwords WHERE user_id = ?
        for pwd in self.passwords:
            self.tree.insert('', tk.END, values=(pwd['app'], pwd['username'], pwd['email']))

    def request_new_pin(self):
        if not self.current_user:
            messagebox.showerror("Error", "Please log in to request a new PIN")
            return
        
        # TODO: Replace with MySQL query to update PIN and send email
        # Example: UPDATE users SET pin = ? WHERE email = ?
        messagebox.showinfo("Success", "A new PIN has been sent to your recovery email")
        self.edit_pin.delete(0, tk.END)

    def save_profile_changes(self):
        username = self.edit_username.get().strip()
        password = self.edit_password.get().strip()
        email = self.edit_recovery_email.get().strip()
        pin = self.edit_pin.get().strip()

        if not any([username, password, email, pin]):
            messagebox.showerror("Error", "No changes provided")
            return
        
        if email and not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return
        
        if password and len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return

        # TODO: Replace with MySQL query
        # Example: UPDATE users SET username = ?, password = ?, email = ?, pin = ? WHERE user_id = ?
        if username:
            self.current_user['name'] = username
        if email:
            self.current_user['email'] = email
        messagebox.showinfo("Success", "Profile changes saved")
        self.show_form("dashboard")
        self.edit_username.delete(0, tk.END)
        self.edit_password.delete(0, tk.END)
        self.edit_recovery_email.delete(0, tk.END)
        self.edit_pin.delete(0, tk.END)

    def save_new_password(self):
        app = self.add_app_name.get().strip()
        username = self.add_username.get().strip()
        password = self.add_password.get().strip()
        email = self.add_email.get().strip()
        
        if not all([app, username, password, email]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return

        # TODO: Replace with MySQL query
        # Example: INSERT INTO passwords (user_id, app, username, password, email) VALUES (?, ?, ?, ?, ?)
        new_password = {
            "app": app,
            "username": username,
            "password": password,
            "email": email
        }
        self.passwords.append(new_password)
        self.refresh_password_list()
        messagebox.showinfo("Success", "Password added successfully")
        self.show_form("dashboard")
        self.add_app_name.delete(0, tk.END)
        self.add_username.delete(0, tk.END)
        self.add_password.delete(0, tk.END)
        self.add_email.delete(0, tk.END)

    def edit_selected_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select an item to edit")
            return
        
        item = selected_item[0]
        values = self.tree.item(item, 'values')
        
        for pwd in self.passwords:
            if pwd['app'] == values[0] and pwd['username'] == values[1] and pwd['email'] == values[2]:
                self.editing_password = pwd
                break
        
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
        app = self.edit_app_name.get().strip()
        username = self.edit_password_username.get().strip()
        password = self.edit_password_password.get().strip()
        email = self.edit_password_email.get().strip()
        
        if not all([app, username, password, email]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return

        # TODO: Replace with MySQL query
        # Example: UPDATE passwords SET app = ?, username = ?, password = ?, email = ? WHERE id = ?
        self.editing_password['app'] = app
        self.editing_password['username'] = username
        self.editing_password['password'] = password
        self.editing_password['email'] = email
        self.refresh_password_list()
        messagebox.showinfo("Success", "Password updated successfully")
        self.show_form("dashboard")
        self.edit_app_name.delete(0, tk.END)
        self.edit_password_username.delete(0, tk.END)
        self.edit_password_password.delete(0, tk.END)
        self.edit_password_email.delete(0, tk.END)

    def delete_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select an item to delete")
            return
        
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this password?"):
            return
        
        item = selected_item[0]
        values = self.tree.item(item, 'values')
        
        # TODO: Replace with MySQL query
        # Example: DELETE FROM passwords WHERE id = ?
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